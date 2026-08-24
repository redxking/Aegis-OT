"""Coordinator for the capability-separated deterministic-local control path."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from threading import RLock
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopResult,
    CapabilityClosedLoopStatus,
    CapabilityExecutionPermit,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from .capability_observer import ObserverProcessInfo
from .capability_plant import PlantProcessInfo
from .capability_plc import PlcProcessInfo
from .evidence import EvidenceChain
from .gateway import AegisGateway
from .models import Decision, DecisionOutcome
from .physical_control import (
    Clock,
    ExecutionPermitIssuer,
    PermitIssuanceError,
    TrustedCommandTranslator,
    physical_state_to_gateway_state,
    utc_now,
)
from .physical_models import (
    CandidateAssessment,
    CommandStatus,
    PhysicalControlCommand,
)


class ObservationPort(Protocol):
    def resolve(
        self,
        *,
        observation_id: str,
        envelope_digest: str,
    ) -> SignedObservationEnvelope: ...

    def capture_post(
        self,
        *,
        correlation_id: str,
        challenge_nonce: str,
        previous_envelope_digest: str,
        permit_id: str,
        command_digest: str,
        plc_acknowledgment_digest: str,
    ) -> SignedObservationEnvelope: ...


class CandidatePort(Protocol):
    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment: ...


class VirtualPlcPort(Protocol):
    def execute(
        self,
        *,
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        pre_observation: SignedObservationEnvelope,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> PlcCommandAcknowledgment: ...


class CapabilityPermitIssuer:
    """Extend a verified M3 permit with signed observation-reference bindings."""

    def __init__(
        self,
        base_issuer: ExecutionPermitIssuer,
        private_key: Ed25519PrivateKey,
        target_plc: PlcProcessInfo,
    ) -> None:
        if base_issuer.private_key is not private_key:
            raise ValueError("base and capability permits must use the same configured signer")
        self.base_issuer = base_issuer
        self.private_key = private_key
        self.target_plc = target_plc

    def rotate_target(self, target_plc: PlcProcessInfo) -> None:
        self.target_plc = target_plc

    def issue(
        self,
        *,
        request: CapabilityActionRequest,
        pre_observation: SignedObservationEnvelope,
        decision: Decision,
        command: PhysicalControlCommand,
        assessment: CandidateAssessment,
    ) -> CapabilityExecutionPermit:
        snapshot = pre_observation.snapshot
        if (
            request.observation_id != pre_observation.observation_id
            or request.observation_envelope_digest != pre_observation.envelope_digest
            or request.observation_challenge_nonce != pre_observation.challenge_nonce
        ):
            raise PermitIssuanceError("request_observation_binding_mismatch")
        if (
            assessment.pre_state.state_version != snapshot.state_version
            or assessment.pre_state.state_digest != snapshot.state_digest
            or assessment.pre_state.observation_digest != snapshot.observation_digest
            or assessment.pre_state.topology_digest != snapshot.topology_digest
            or assessment.pre_state.model_digest != snapshot.model_digest
        ):
            raise PermitIssuanceError("candidate_signed_observation_mismatch")
        base = self.base_issuer.issue(
            proposal=request.proposal,
            decision=decision,
            command=command,
            assessment=assessment,
        )
        return CapabilityExecutionPermit(
            base_permit=base,
            request_digest=request.digest,
            observation_id=pre_observation.observation_id,
            observation_envelope_digest=pre_observation.envelope_digest,
            observer_id=pre_observation.observer_id,
            observer_key_id=pre_observation.observer_key_id,
            observer_boot_epoch=pre_observation.observer_boot_epoch,
            target_plc_id=self.target_plc.plc_id,
            target_plc_key_id=self.target_plc.key_id,
            target_plc_boot_epoch=self.target_plc.boot_epoch,
            signing_key_id=base.signing_key_id,
        ).signed(self.private_key)


class SignedObservationVerifier:
    """Stateful trust-anchor, freshness, boot, challenge, and sequence verifier."""

    def __init__(
        self,
        *,
        observer_info: ObserverProcessInfo,
        plant_info: PlantProcessInfo,
        maximum_age: timedelta = timedelta(seconds=5),
    ) -> None:
        if maximum_age <= timedelta(0):
            raise ValueError("maximum observation age must be positive")
        self.observer_info = observer_info
        self.plant_info = plant_info
        self.maximum_age = maximum_age
        self._last_sequence = 0
        self._accepted_challenges: set[str] = set()

    def _common_reasons(
        self,
        observation: SignedObservationEnvelope,
        *,
        evaluated_at: datetime,
    ) -> list[str]:
        reasons: list[str] = []
        if observation.observer_id != self.observer_info.observer_id:
            reasons.append("observation_source_mismatch")
        if observation.observer_key_id != self.observer_info.key_id:
            reasons.append("observation_key_mismatch")
        if observation.observer_boot_epoch != self.observer_info.boot_epoch:
            reasons.append("observation_boot_mismatch")
        if not observation.verify(self.observer_info.public_key):
            reasons.append("observation_signature_invalid")
        if observation.snapshot.observation_source_id != self.plant_info.observation_source_id:
            reasons.append("plant_observation_source_mismatch")
        if observation.snapshot.model_digest != self.plant_info.model_digest:
            reasons.append("plant_model_digest_mismatch")
        if observation.snapshot.simulator_version != self.plant_info.simulator_version:
            reasons.append("plant_simulator_version_mismatch")
        if not observation.snapshot.verify_digest():
            reasons.append("observation_state_digest_invalid")
        age = evaluated_at - observation.captured_at
        if age < timedelta(0):
            reasons.append("observation_from_future")
        elif age > self.maximum_age:
            reasons.append("observation_stale")
        if observation.observer_sequence <= self._last_sequence:
            reasons.append("observation_sequence_regressed")
        if observation.challenge_nonce in self._accepted_challenges:
            reasons.append("observation_challenge_replayed")
        return reasons

    def verify_pre(
        self,
        observation: SignedObservationEnvelope,
        request: CapabilityActionRequest,
        *,
        evaluated_at: datetime,
    ) -> tuple[str, ...]:
        reasons = self._common_reasons(observation, evaluated_at=evaluated_at)
        proposal = request.proposal
        if observation.phase is not ObservationPhase.PRE_AUTHORIZATION:
            reasons.append("observation_phase_mismatch")
        if observation.observation_id != request.observation_id:
            reasons.append("observation_id_mismatch")
        if observation.envelope_digest != request.observation_envelope_digest:
            reasons.append("observation_envelope_digest_mismatch")
        if observation.challenge_nonce != request.observation_challenge_nonce:
            reasons.append("observation_challenge_mismatch")
        if observation.correlation_id != request.correlation_id:
            reasons.append("observation_correlation_mismatch")
        if proposal.observed_state_version != observation.snapshot.state_version:
            reasons.append("proposal_observation_version_mismatch")
        if proposal.observed_at != observation.snapshot.observed_at:
            reasons.append("proposal_observation_time_mismatch")
        if not reasons:
            self._accept(observation)
        return tuple(reasons)

    def verify_post(
        self,
        observation: SignedObservationEnvelope,
        *,
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        acknowledgment: PlcCommandAcknowledgment,
        challenge_nonce: str,
        evaluated_at: datetime,
    ) -> tuple[str, ...]:
        reasons = self._common_reasons(observation, evaluated_at=evaluated_at)
        base = permit.base_permit
        if observation.phase is not ObservationPhase.POST_DISPATCH:
            reasons.append("post_observation_phase_mismatch")
        if observation.correlation_id != request.correlation_id:
            reasons.append("post_observation_correlation_mismatch")
        if observation.challenge_nonce != challenge_nonce:
            reasons.append("post_observation_challenge_mismatch")
        if observation.permit_id != base.permit_id:
            reasons.append("post_observation_permit_mismatch")
        if observation.command_digest != base.command_digest:
            reasons.append("post_observation_command_mismatch")
        if observation.plc_acknowledgment_digest != acknowledgment.digest:
            reasons.append("post_observation_acknowledgment_mismatch")
        if observation.previous_envelope_digest != permit.observation_envelope_digest:
            reasons.append("post_observation_previous_envelope_mismatch")
        if observation.captured_at < acknowledgment.acknowledged_at:
            reasons.append("post_observation_precedes_acknowledgment")
        if not reasons:
            self._accept(observation)
        return tuple(reasons)

    def _accept(self, observation: SignedObservationEnvelope) -> None:
        self._last_sequence = observation.observer_sequence
        self._accepted_challenges.add(observation.challenge_nonce)


class CapabilityClosedLoopController:
    """Authorize, simulate, dispatch once, and require dual-signed completion evidence."""

    def __init__(
        self,
        *,
        gateway: AegisGateway,
        observer: ObservationPort,
        simulator: CandidatePort,
        plc: VirtualPlcPort,
        translator: TrustedCommandTranslator,
        permit_issuer: CapabilityPermitIssuer,
        observation_verifier: SignedObservationVerifier,
        plc_info: PlcProcessInfo,
        plc_public_key: Ed25519PublicKey,
        evidence: EvidenceChain,
        clock: Clock = utc_now,
    ) -> None:
        if gateway.evidence is not evidence:
            raise ValueError("gateway and capability controller must share one evidence chain")
        self.gateway = gateway
        self.observer = observer
        self.simulator = simulator
        self.plc = plc
        self.translator = translator
        self.permit_issuer = permit_issuer
        self.observation_verifier = observation_verifier
        self.plc_info = plc_info
        self.plc_public_key = plc_public_key
        self.evidence = evidence
        self.clock = clock
        self._execution_lock = RLock()

    def _record(
        self,
        *,
        status: CapabilityClosedLoopStatus,
        reasons: tuple[str, ...],
        request: CapabilityActionRequest,
        dispatch_attempts: int,
        pre_observation: SignedObservationEnvelope | None = None,
        decision: Decision | None = None,
        command: PhysicalControlCommand | None = None,
        assessment: CandidateAssessment | None = None,
        permit: CapabilityExecutionPermit | None = None,
        acknowledgment: PlcCommandAcknowledgment | None = None,
        post_observation: SignedObservationEnvelope | None = None,
        last_observation: SignedObservationEnvelope | None = None,
    ) -> CapabilityClosedLoopResult:
        record = self.evidence.append(
            proposal_id=request.proposal.proposal_id,
            decision_id=(
                decision.decision_id if decision is not None else f"not-issued:{request.request_id}"
            ),
            payload={
                "event_type": "capability_closed_loop_disposition",
                "coordination_backend": "deterministic-local-v1",
                "status": status.value,
                "reasons": list(reasons),
                "dispatch_attempts": dispatch_attempts,
                "automatic_retry_count": 0,
                "request": request.model_dump(mode="json"),
                "pre_observation": (
                    pre_observation.model_dump(mode="json") if pre_observation else None
                ),
                "decision": decision.model_dump(mode="json") if decision else None,
                "command": command.model_dump(mode="json") if command else None,
                "assessment": assessment.model_dump(mode="json") if assessment else None,
                "permit": permit.model_dump(mode="json") if permit else None,
                "acknowledgment": (
                    acknowledgment.model_dump(mode="json") if acknowledgment else None
                ),
                "post_observation": (
                    post_observation.model_dump(mode="json") if post_observation else None
                ),
                "last_observation": (
                    last_observation.model_dump(mode="json") if last_observation else None
                ),
            },
        )
        return CapabilityClosedLoopResult(
            status=status,
            reasons=reasons,
            request=request,
            pre_observation=pre_observation,
            decision=decision,
            command=command,
            assessment=assessment,
            permit=permit,
            acknowledgment=acknowledgment,
            post_observation=post_observation,
            last_observation=last_observation,
            dispatch_attempts=dispatch_attempts,
            execution_evidence_hash=record.record_hash,
        )

    def execute(self, request: CapabilityActionRequest) -> CapabilityClosedLoopResult:
        with self._execution_lock:
            return self._execute_locked(request)

    def _execute_locked(self, request: CapabilityActionRequest) -> CapabilityClosedLoopResult:
        try:
            observed = self.observer.resolve(
                observation_id=request.observation_id,
                envelope_digest=request.observation_envelope_digest,
            )
        except Exception as exc:
            return self._record(
                status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
                reasons=("pre_observation_unavailable", type(exc).__name__),
                request=request,
                dispatch_attempts=0,
            )
        evaluated_at = self.clock()
        observation_reasons = self.observation_verifier.verify_pre(
            observed,
            request,
            evaluated_at=evaluated_at,
        )
        if observation_reasons:
            return self._record(
                status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
                reasons=observation_reasons,
                request=request,
                dispatch_attempts=0,
                last_observation=observed,
            )
        try:
            gateway_state = physical_state_to_gateway_state(observed.snapshot)
        except Exception as exc:
            return self._record(
                status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
                reasons=("gateway_state_conversion_failed", type(exc).__name__),
                request=request,
                dispatch_attempts=0,
                pre_observation=observed,
                last_observation=observed,
            )
        try:
            decision = self.gateway.decide(request.proposal, gateway_state, evaluated_at)
        except Exception as exc:
            return self._record(
                status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
                reasons=("authorization_decision_unavailable", type(exc).__name__),
                request=request,
                dispatch_attempts=0,
                pre_observation=observed,
                last_observation=observed,
            )
        if decision.outcome is not DecisionOutcome.PERMIT:
            return self._record(
                status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
                reasons=decision.reasons,
                request=request,
                dispatch_attempts=0,
                pre_observation=observed,
                decision=decision,
                last_observation=observed,
            )
        try:
            command = self.translator.translate(request.proposal)
        except Exception as exc:
            return self._record(
                status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
                reasons=("command_translation_failed", type(exc).__name__),
                request=request,
                dispatch_attempts=0,
                pre_observation=observed,
                decision=decision,
                last_observation=observed,
            )
        try:
            assessment = self.simulator.simulate_candidate(command)
        except Exception as exc:
            return self._record(
                status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
                reasons=("candidate_simulation_unavailable", type(exc).__name__),
                request=request,
                dispatch_attempts=0,
                pre_observation=observed,
                decision=decision,
                command=command,
                last_observation=observed,
            )
        snapshot = observed.snapshot
        candidate_matches = (
            assessment.command_digest == command.digest
            and assessment.pre_state.state_version == snapshot.state_version
            and assessment.pre_state.state_digest == snapshot.state_digest
            and assessment.pre_state.observation_digest == snapshot.observation_digest
            and assessment.pre_state.topology_digest == snapshot.topology_digest
            and assessment.pre_state.model_digest == snapshot.model_digest
        )
        if not assessment.safe or not candidate_matches:
            reasons = assessment.reasons if not assessment.safe else ("candidate_binding_mismatch",)
            return self._record(
                status=CapabilityClosedLoopStatus.CANDIDATE_REJECTED,
                reasons=reasons,
                request=request,
                dispatch_attempts=0,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
                last_observation=observed,
            )
        try:
            permit = self.permit_issuer.issue(
                request=request,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
            )
        except Exception as exc:
            return self._record(
                status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
                reasons=("permit_issuance_failed", type(exc).__name__),
                request=request,
                dispatch_attempts=0,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
                last_observation=observed,
            )
        try:
            acknowledgment = self.plc.execute(
                request=request,
                permit=permit,
                pre_observation=observed,
                decision=decision,
                assessment=assessment,
            )
        except Exception as exc:
            return self._record(
                status=CapabilityClosedLoopStatus.UNKNOWN_EFFECT,
                reasons=("plc_dispatch_outcome_unavailable", type(exc).__name__),
                request=request,
                dispatch_attempts=1,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                last_observation=observed,
            )
        acknowledgment_valid = acknowledgment.verify_for_transaction(
            self.plc_public_key,
            request=request,
            permit=permit,
            pre_observation=observed,
            expected_plc_id=self.plc_info.plc_id,
            expected_plc_key_id=self.plc_info.key_id,
            expected_plc_boot_epoch=self.plc_info.boot_epoch,
        )
        if not acknowledgment_valid:
            return self._record(
                status=CapabilityClosedLoopStatus.UNKNOWN_EFFECT,
                reasons=("plc_acknowledgment_invalid",),
                request=request,
                dispatch_attempts=1,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                acknowledgment=acknowledgment,
                last_observation=observed,
            )
        if acknowledgment.status is CommandStatus.REJECTED:
            status = (
                CapabilityClosedLoopStatus.CANDIDATE_REJECTED
                if acknowledgment.reason == "candidate_attestation_mismatch"
                else CapabilityClosedLoopStatus.PLC_REJECTED
            )
            return self._record(
                status=status,
                reasons=(acknowledgment.reason,),
                request=request,
                dispatch_attempts=1,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                acknowledgment=acknowledgment,
                last_observation=observed,
            )
        if acknowledgment.status is CommandStatus.UNKNOWN_EFFECT:
            return self._record(
                status=CapabilityClosedLoopStatus.UNKNOWN_EFFECT,
                reasons=(acknowledgment.reason,),
                request=request,
                dispatch_attempts=1,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                acknowledgment=acknowledgment,
                last_observation=observed,
            )
        challenge_nonce = secrets.token_urlsafe(24)
        try:
            post = self.observer.capture_post(
                correlation_id=request.correlation_id,
                challenge_nonce=challenge_nonce,
                previous_envelope_digest=observed.envelope_digest,
                permit_id=permit.base_permit.permit_id,
                command_digest=permit.base_permit.command_digest,
                plc_acknowledgment_digest=acknowledgment.digest,
            )
        except Exception as exc:
            return self._record(
                status=CapabilityClosedLoopStatus.UNKNOWN_EFFECT,
                reasons=("post_observation_unavailable", type(exc).__name__),
                request=request,
                dispatch_attempts=1,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                acknowledgment=acknowledgment,
                last_observation=observed,
            )
        post_reasons = self.observation_verifier.verify_post(
            post,
            request=request,
            permit=permit,
            acknowledgment=acknowledgment,
            challenge_nonce=challenge_nonce,
            evaluated_at=self.clock(),
        )
        if post_reasons:
            return self._record(
                status=CapabilityClosedLoopStatus.UNKNOWN_EFFECT,
                reasons=("post_observation_invalid", *post_reasons),
                request=request,
                dispatch_attempts=1,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                acknowledgment=acknowledgment,
                last_observation=post,
            )
        post_matches = (
            post.snapshot.state_digest == acknowledgment.post_state_digest
            and post.snapshot.state_version == acknowledgment.post_state_version
            and post.snapshot.topology_digest == acknowledgment.post_topology_digest
            and post.snapshot.state_digest == permit.base_permit.expected_post_state_digest
            and post.snapshot.state_version == permit.base_permit.expected_post_state_version
            and post.snapshot.topology_digest == permit.base_permit.expected_post_topology_digest
        )
        if not post_matches:
            return self._record(
                status=CapabilityClosedLoopStatus.OBSERVATION_DIVERGED,
                reasons=("signed_post_observation_contradiction",),
                request=request,
                dispatch_attempts=1,
                pre_observation=observed,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                acknowledgment=acknowledgment,
                post_observation=post,
                last_observation=post,
            )
        return self._record(
            status=CapabilityClosedLoopStatus.COMPLETED,
            reasons=("plc_acknowledgment_and_signed_post_observation_match",),
            request=request,
            dispatch_attempts=1,
            pre_observation=observed,
            decision=decision,
            command=command,
            assessment=assessment,
            permit=permit,
            acknowledgment=acknowledgment,
            post_observation=post,
            last_observation=post,
        )
