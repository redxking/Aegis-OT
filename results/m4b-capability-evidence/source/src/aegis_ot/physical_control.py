"""Permit issuance, virtual-device enforcement, and M3 closed-loop orchestration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Literal, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from .evidence import EvidenceChain
from .gateway import AegisGateway
from .models import ActionProposal, Decision, DecisionOutcome, Operation, SystemState
from .pandapower_plant import (
    DEFAULT_RESOURCE_BINDINGS,
    PhysicalSimulationError,
    ResourceBinding,
)
from .physical_models import (
    CandidateAssessment,
    ClosedLoopResult,
    ClosedLoopStatus,
    CommandAcknowledgment,
    CommandStatus,
    ExecutionPermit,
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    proposal_digest,
)


class StateCandidateSource(Protocol):
    def capture_state(self) -> PhysicalStateSnapshot: ...

    def read_state(self) -> PhysicalStateSnapshot: ...

    def simulate_candidate(
        self,
        command: PhysicalControlCommand,
    ) -> CandidateAssessment: ...


class TransactionalPhysicalPlant(StateCandidateSource, Protocol):
    def apply_authorized_command(
        self,
        command: PhysicalControlCommand,
        *,
        expected_pre_state_version: int | None = None,
        expected_pre_state_digest: str | None = None,
        expected_pre_observation_digest: str | None = None,
        expected_post_state_digest: str | None = None,
        expected_post_topology_digest: str | None = None,
    ) -> PhysicalStateSnapshot: ...


class ControlDevice(Protocol):
    device_id: str
    acknowledgment_key_id: str

    def execute(
        self,
        permit: ExecutionPermit,
        *,
        proposal: ActionProposal,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> CommandAcknowledgment: ...


Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


class CommandTranslationError(ValueError):
    """Raised when an agent proposal has no exact, bounded actuator mapping."""


class PermitIssuanceError(ValueError):
    """Raised when any authorization or candidate-state binding is incomplete."""


class ControlDispatchUnknownEffect(RuntimeError):
    """The control request may have crossed the dispatch boundary without verified effect."""


class TrustedCommandTranslator:
    """Maps resources to fixed model indices; agent consequence estimates are not actuator truth."""

    def __init__(self, resource_bindings: dict[str, ResourceBinding] | None = None) -> None:
        self.resource_bindings = dict(resource_bindings or DEFAULT_RESOURCE_BINDINGS)

    def translate(self, proposal: ActionProposal) -> PhysicalControlCommand:
        binding = self.resource_bindings.get(proposal.resource)
        if binding is None:
            raise CommandTranslationError("resource_not_mapped")
        unit: Literal["boolean", "MW"]
        if proposal.operation in {Operation.ISOLATE_ASSET, Operation.RESTORE_ASSET}:
            if binding.command_type is not PhysicalCommandType.SET_LINE_SERVICE:
                raise CommandTranslationError("operation_resource_type_mismatch")
            setpoint = 0.0 if proposal.operation is Operation.ISOLATE_ASSET else 1.0
            unit = "boolean"
        elif proposal.operation is Operation.DISPATCH_BATTERY:
            if binding.command_type is not PhysicalCommandType.SET_BATTERY_INJECTION:
                raise CommandTranslationError("operation_resource_type_mismatch")
            if "mw" not in proposal.parameters:
                raise CommandTranslationError("battery_setpoint_missing")
            setpoint = float(proposal.parameters["mw"])
            unit = "MW"
        else:
            raise CommandTranslationError("operation_not_supported_by_physical_adapter")
        if not binding.minimum_setpoint <= setpoint <= binding.maximum_setpoint:
            raise CommandTranslationError("setpoint_out_of_bounds")
        return PhysicalControlCommand(
            proposal_id=proposal.proposal_id,
            operation=proposal.operation,
            resource=proposal.resource,
            command_type=binding.command_type,
            target=binding.target,
            target_index=binding.target_index,
            setpoint=setpoint,
            unit=unit,
        )


class ExecutionPermitIssuer:
    """Signs a short-lived permit only after every gateway and candidate check passes."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        signing_key_id: str,
        audience: str,
        evidence: EvidenceChain,
        time_to_live: timedelta = timedelta(seconds=2),
        clock: Clock = utc_now,
    ) -> None:
        if time_to_live <= timedelta(0):
            raise ValueError("permit time_to_live must be positive")
        self.private_key = private_key
        self.signing_key_id = signing_key_id
        self.audience = audience
        self.evidence = evidence
        self.time_to_live = time_to_live
        self.clock = clock

    def issue(
        self,
        *,
        proposal: ActionProposal,
        decision: Decision,
        command: PhysicalControlCommand,
        assessment: CandidateAssessment,
    ) -> ExecutionPermit:
        issued_at = self.clock()
        try:
            proposal = ActionProposal.model_validate(proposal.model_dump(mode="python"))
            decision = Decision.model_validate(decision.model_dump(mode="python"))
            command = PhysicalControlCommand.model_validate(command.model_dump(mode="python"))
            assessment = CandidateAssessment.model_validate(assessment.model_dump(mode="python"))
        except ValidationError as exc:
            raise PermitIssuanceError("authorization_artifact_not_structurally_valid") from exc
        if decision.outcome is not DecisionOutcome.PERMIT:
            raise PermitIssuanceError("decision_not_permit")
        if decision.proposal_id != proposal.proposal_id:
            raise PermitIssuanceError("proposal_decision_mismatch")
        if command.proposal_id != proposal.proposal_id:
            raise PermitIssuanceError("proposal_command_mismatch")
        if not assessment.safe:
            raise PermitIssuanceError("candidate_not_safe")
        if assessment.command_digest != command.digest:
            raise PermitIssuanceError("candidate_command_mismatch")
        if decision.state_version != assessment.pre_state.state_version:
            raise PermitIssuanceError("decision_state_version_mismatch")
        if not assessment.pre_state.verify_digest():
            raise PermitIssuanceError("candidate_pre_state_digest_invalid")
        if decision.evidence_record_hash is None:
            raise PermitIssuanceError("decision_evidence_missing")
        if not self.evidence.verify():
            raise PermitIssuanceError("decision_evidence_chain_invalid")
        evidence_record = next(
            (
                record
                for record in self.evidence.records
                if record.record_hash == decision.evidence_record_hash
            ),
            None,
        )
        if evidence_record is None:
            raise PermitIssuanceError("decision_evidence_not_found")
        if (
            evidence_record.proposal_id != proposal.proposal_id
            or evidence_record.decision_id != decision.decision_id
            or evidence_record.payload.get("proposal") != proposal.model_dump(mode="json")
            or evidence_record.payload.get("state")
            != physical_state_to_gateway_state(assessment.pre_state).model_dump(mode="json")
        ):
            raise PermitIssuanceError("decision_evidence_binding_mismatch")
        recorded_decision = evidence_record.payload.get("decision")
        expected_recorded_decision = decision.model_copy(
            update={"evidence_record_hash": None}
        ).model_dump(mode="json")
        if recorded_decision != expected_recorded_decision:
            raise PermitIssuanceError("decision_evidence_binding_mismatch")
        permit = ExecutionPermit(
            decision_id=decision.decision_id,
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal_digest(proposal),
            command=command,
            command_digest=command.digest,
            assessment_digest=assessment.digest,
            state_version=assessment.pre_state.state_version,
            state_digest=assessment.pre_state.state_digest,
            observation_digest=assessment.pre_state.observation_digest,
            topology_digest=assessment.pre_state.topology_digest,
            model_digest=assessment.pre_state.model_digest,
            expected_post_state_version=assessment.post_state.state_version,
            expected_post_state_digest=assessment.post_state.state_digest,
            expected_post_topology_digest=assessment.post_state.topology_digest,
            evidence_record_hash=decision.evidence_record_hash,
            policy_version=decision.policy_version,
            safety_version=decision.safety_version,
            audience=self.audience,
            issued_at=issued_at,
            expires_at=issued_at + self.time_to_live,
            signing_key_id=self.signing_key_id,
        )
        return permit.signed(self.private_key)


class PermitAwareVirtualControlDevice:
    """Development virtual control-device boundary with one-time permit enforcement.

    This is an in-process enforcement emulator.  It is not OpenPLC, a physical PLC,
    or evidence of deployed network isolation; the separate PyModbus process is the
    next M3 boundary increment.
    """

    def __init__(
        self,
        plant: TransactionalPhysicalPlant,
        *,
        device_id: str,
        permit_audience: str,
        permit_public_keys: dict[str, Ed25519PublicKey],
        acknowledgment_private_key: Ed25519PrivateKey,
        acknowledgment_key_id: str,
        clock: Clock = utc_now,
    ) -> None:
        self.plant = plant
        self.device_id = device_id
        self.permit_audience = permit_audience
        self.permit_public_keys = dict(permit_public_keys)
        self.acknowledgment_private_key = acknowledgment_private_key
        self.acknowledgment_key_id = acknowledgment_key_id
        self.clock = clock
        self._consumed_permits: set[str] = set()
        self._consumed_nonces: set[str] = set()
        self._consumed_commands: set[str] = set()
        self._scan_counter = 0
        self._lock = RLock()

    @staticmethod
    def _actuator_setpoint(
        state: PhysicalStateSnapshot,
        command: PhysicalControlCommand,
    ) -> float:
        if command.command_type is PhysicalCommandType.SET_LINE_SERVICE:
            return 0.0 if command.resource in state.isolated_resources else 1.0
        return state.battery_injection_mw.get(command.resource, 0.0)

    def _acknowledge(
        self,
        permit: ExecutionPermit,
        *,
        status: CommandStatus,
        reason: str,
        acknowledged_at: datetime,
        pre_state: PhysicalStateSnapshot,
        post_state: PhysicalStateSnapshot | None = None,
    ) -> CommandAcknowledgment:
        acknowledgment = CommandAcknowledgment(
            permit_id=permit.permit_id,
            permit_nonce=permit.permit_nonce,
            command_id=permit.command.command_id,
            command_digest=permit.command_digest,
            assessment_digest=permit.assessment_digest,
            proposal_id=permit.proposal_id,
            decision_id=permit.decision_id,
            device_id=self.device_id,
            device_scan=self._scan_counter,
            status=status,
            reason=reason,
            acknowledged_at=acknowledged_at,
            pre_state_digest=pre_state.state_digest,
            post_state_digest=post_state.state_digest if post_state is not None else None,
            post_state_version=post_state.state_version if post_state is not None else None,
            pre_actuator_setpoint=self._actuator_setpoint(pre_state, permit.command),
            post_actuator_setpoint=(
                self._actuator_setpoint(post_state, permit.command)
                if post_state is not None
                else (
                    self._actuator_setpoint(pre_state, permit.command)
                    if status is CommandStatus.REJECTED
                    else None
                )
            ),
            simulation_time_s=(
                post_state.simulation_time_s
                if post_state is not None
                else pre_state.simulation_time_s
            ),
            signing_key_id=self.acknowledgment_key_id,
        )
        return acknowledgment.signed(self.acknowledgment_private_key)

    def execute(
        self,
        permit: ExecutionPermit,
        *,
        proposal: ActionProposal,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> CommandAcknowledgment:
        with self._lock:
            return self._execute_locked(
                permit,
                proposal=proposal,
                decision=decision,
                assessment=assessment,
            )

    def _execute_locked(
        self,
        permit: ExecutionPermit,
        *,
        proposal: ActionProposal,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> CommandAcknowledgment:
        evaluated_at = self.clock()
        self._scan_counter += 1
        pre_state = self.plant.read_state()
        public_key = self.permit_public_keys.get(permit.signing_key_id)
        checks: tuple[tuple[bool, str], ...] = (
            (permit.audience == self.permit_audience, "permit_wrong_audience"),
            (public_key is not None, "permit_unknown_signing_key"),
            (
                public_key is not None and permit.verify(public_key),
                "permit_signature_invalid",
            ),
            (evaluated_at >= permit.issued_at, "permit_not_yet_valid"),
            (evaluated_at < permit.expires_at, "permit_expired"),
            (permit.proposal_id == proposal.proposal_id, "permit_proposal_id_mismatch"),
            (
                permit.proposal_digest == proposal_digest(proposal),
                "permit_proposal_digest_mismatch",
            ),
            (permit.decision_id == decision.decision_id, "permit_decision_id_mismatch"),
            (decision.outcome is DecisionOutcome.PERMIT, "decision_not_permit"),
            (decision.proposal_id == proposal.proposal_id, "decision_proposal_mismatch"),
            (
                decision.evidence_record_hash == permit.evidence_record_hash,
                "decision_evidence_mismatch",
            ),
            (permit.policy_version == decision.policy_version, "decision_policy_version_mismatch"),
            (permit.safety_version == decision.safety_version, "decision_safety_version_mismatch"),
            (permit.state_version == decision.state_version, "decision_state_version_mismatch"),
            (permit.command_digest == permit.command.digest, "permit_command_digest_mismatch"),
            (permit.assessment_digest == assessment.digest, "permit_assessment_digest_mismatch"),
            (assessment.safe, "candidate_not_safe"),
            (
                assessment.command_digest == permit.command_digest,
                "candidate_command_digest_mismatch",
            ),
            (
                assessment.pre_state.state_digest == permit.state_digest,
                "candidate_state_digest_mismatch",
            ),
            (permit.permit_id not in self._consumed_permits, "permit_replayed"),
            (permit.permit_nonce not in self._consumed_nonces, "permit_nonce_replayed"),
            (permit.command.command_id not in self._consumed_commands, "command_replayed"),
            (pre_state.verify_digest(), "current_state_digest_invalid"),
            (permit.model_digest == pre_state.model_digest, "model_digest_changed"),
            (permit.topology_digest == pre_state.topology_digest, "topology_digest_changed"),
            (permit.state_version == pre_state.state_version, "state_version_changed"),
            (permit.state_digest == pre_state.state_digest, "state_digest_changed"),
            (
                permit.observation_digest == pre_state.observation_digest,
                "observation_envelope_changed",
            ),
        )
        for passed, reason in checks:
            if not passed:
                return self._acknowledge(
                    permit,
                    status=CommandStatus.REJECTED,
                    reason=reason,
                    acknowledged_at=evaluated_at,
                    pre_state=pre_state,
                )

        fresh_assessment = self.plant.simulate_candidate(permit.command)
        if (
            not fresh_assessment.safe
            or fresh_assessment.pre_state.state_digest != assessment.pre_state.state_digest
            or fresh_assessment.post_state.state_digest != assessment.post_state.state_digest
            or fresh_assessment.command_digest != assessment.command_digest
        ):
            return self._acknowledge(
                permit,
                status=CommandStatus.REJECTED,
                reason="candidate_attestation_mismatch",
                acknowledged_at=self.clock(),
                pre_state=pre_state,
            )
        commit_time = self.clock()
        if commit_time >= permit.expires_at:
            return self._acknowledge(
                permit,
                status=CommandStatus.REJECTED,
                reason="permit_expired_before_dispatch",
                acknowledged_at=commit_time,
                pre_state=pre_state,
            )

        # Reserve before dispatch.  No automatic retry is permitted after this point.
        self._consumed_permits.add(permit.permit_id)
        self._consumed_nonces.add(permit.permit_nonce)
        self._consumed_commands.add(permit.command.command_id)
        try:
            post_state = self.plant.apply_authorized_command(
                permit.command,
                expected_pre_state_version=permit.state_version,
                expected_pre_state_digest=permit.state_digest,
                expected_pre_observation_digest=permit.observation_digest,
                expected_post_state_digest=permit.expected_post_state_digest,
                expected_post_topology_digest=permit.expected_post_topology_digest,
            )
        except PhysicalSimulationError as exc:
            return self._acknowledge(
                permit,
                status=CommandStatus.REJECTED,
                reason=str(exc),
                acknowledged_at=self.clock(),
                pre_state=pre_state,
            )
        except Exception:
            return self._acknowledge(
                permit,
                status=CommandStatus.UNKNOWN_EFFECT,
                reason="unclassified_dispatch_failure",
                acknowledged_at=self.clock(),
                pre_state=pre_state,
            )
        if (
            post_state.state_digest != permit.expected_post_state_digest
            or post_state.state_version != permit.expected_post_state_version
            or post_state.topology_digest != permit.expected_post_topology_digest
            or post_state.unsafe_state
        ):
            return self._acknowledge(
                permit,
                status=CommandStatus.UNKNOWN_EFFECT,
                reason="post_dispatch_candidate_divergence",
                acknowledged_at=self.clock(),
                pre_state=pre_state,
            )
        return self._acknowledge(
            permit,
            status=CommandStatus.APPLIED,
            reason="command_applied_and_read_back",
            acknowledged_at=self.clock(),
            pre_state=pre_state,
            post_state=post_state,
        )


def physical_state_to_gateway_state(state: PhysicalStateSnapshot) -> SystemState:
    """Project independently measured plant state into the existing gateway contract."""

    if (
        not state.converged
        or state.minimum_voltage_pu is None
        or state.maximum_voltage_pu is None
        or state.maximum_line_loading_pct is None
    ):
        raise PhysicalSimulationError("physical_state_not_usable_for_authorization")
    return SystemState(
        version=state.state_version,
        observed_at=state.observed_at,
        critical_load_served_pct=state.priority_load_served_pct,
        minimum_voltage_pu=state.minimum_voltage_pu,
        maximum_voltage_pu=state.maximum_voltage_pu,
        maximum_line_loading_pct=state.maximum_line_loading_pct,
        isolated_assets=frozenset(state.isolated_resources),
        battery_dispatch_mw=state.battery_injection_mw.get("battery-1", 0.0),
    )


class PhysicalClosedLoopController:
    """Correlate gateway decision, candidate simulation, permit, device action, and readback."""

    def __init__(
        self,
        *,
        gateway: AegisGateway,
        plant: StateCandidateSource,
        translator: TrustedCommandTranslator,
        permit_issuer: ExecutionPermitIssuer,
        control_device: ControlDevice,
        evidence: EvidenceChain,
        acknowledgment_public_key: Ed25519PublicKey,
        clock: Clock = utc_now,
    ) -> None:
        if gateway.evidence is not evidence:
            raise ValueError("gateway and controller must share one evidence chain")
        self.gateway = gateway
        self.plant = plant
        self.translator = translator
        self.permit_issuer = permit_issuer
        self.control_device = control_device
        self.evidence = evidence
        self.acknowledgment_public_key = acknowledgment_public_key
        self.clock = clock

    def _record(
        self,
        *,
        status: ClosedLoopStatus,
        reasons: tuple[str, ...],
        proposal: ActionProposal,
        pre_state: PhysicalStateSnapshot,
        decision: Decision,
        post_state: PhysicalStateSnapshot | None,
        last_observed_state: PhysicalStateSnapshot | None = None,
        command: PhysicalControlCommand | None = None,
        assessment: CandidateAssessment | None = None,
        permit: ExecutionPermit | None = None,
        acknowledgment: CommandAcknowledgment | None = None,
    ) -> ClosedLoopResult:
        last_observed = last_observed_state or post_state or pre_state
        record = self.evidence.append(
            proposal_id=proposal.proposal_id,
            decision_id=decision.decision_id,
            payload={
                "event_type": "physical_closed_loop_disposition",
                "status": status.value,
                "reasons": list(reasons),
                "proposal_digest": proposal_digest(proposal),
                "pre_state": pre_state.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
                "command": command.model_dump(mode="json") if command else None,
                "assessment": assessment.model_dump(mode="json") if assessment else None,
                "permit": permit.model_dump(mode="json") if permit else None,
                "acknowledgment": (
                    acknowledgment.model_dump(mode="json") if acknowledgment else None
                ),
                "post_state": post_state.model_dump(mode="json") if post_state else None,
                "last_observed_state": last_observed.model_dump(mode="json"),
            },
        )
        return ClosedLoopResult(
            status=status,
            reasons=reasons,
            proposal=proposal,
            pre_state=pre_state,
            decision=decision,
            command=command,
            assessment=assessment,
            permit=permit,
            acknowledgment=acknowledgment,
            post_state=post_state,
            last_observed_state=last_observed,
            execution_evidence_hash=record.record_hash,
        )

    def execute(self, proposal: ActionProposal) -> ClosedLoopResult:
        evaluated_at = self.clock()
        capture_state = getattr(self.plant, "capture_state", self.plant.read_state)
        pre_state = capture_state()
        try:
            gateway_state = physical_state_to_gateway_state(pre_state)
        except PhysicalSimulationError as exc:
            # The current gateway API requires a valid state.  Surface this as a hard failure rather
            # than constructing a fabricated authorization decision.
            raise PhysicalSimulationError("authorization_state_unavailable") from exc
        decision = self.gateway.decide(proposal, gateway_state, evaluated_at)
        if decision.outcome is not DecisionOutcome.PERMIT:
            return self._record(
                status=ClosedLoopStatus.NOT_DISPATCHED,
                reasons=decision.reasons,
                proposal=proposal,
                pre_state=pre_state,
                decision=decision,
                post_state=pre_state,
            )
        try:
            command = self.translator.translate(proposal)
        except CommandTranslationError as exc:
            return self._record(
                status=ClosedLoopStatus.NOT_DISPATCHED,
                reasons=(str(exc),),
                proposal=proposal,
                pre_state=pre_state,
                decision=decision,
                post_state=pre_state,
            )
        assessment = self.plant.simulate_candidate(command)
        if not assessment.safe:
            return self._record(
                status=ClosedLoopStatus.CANDIDATE_REJECTED,
                reasons=assessment.reasons,
                proposal=proposal,
                pre_state=pre_state,
                decision=decision,
                command=command,
                assessment=assessment,
                post_state=pre_state,
            )
        permit = self.permit_issuer.issue(
            proposal=proposal,
            decision=decision,
            command=command,
            assessment=assessment,
        )
        try:
            acknowledgment = self.control_device.execute(
                permit,
                proposal=proposal,
                decision=decision,
                assessment=assessment,
            )
        except Exception as exc:
            return self._record(
                status=ClosedLoopStatus.UNKNOWN_EFFECT,
                reasons=("control_dispatch_outcome_unavailable", type(exc).__name__),
                proposal=proposal,
                pre_state=pre_state,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                post_state=None,
            )
        try:
            post_state = self.plant.read_state()
        except Exception as exc:
            return self._record(
                status=ClosedLoopStatus.UNKNOWN_EFFECT,
                reasons=("post_dispatch_readback_unavailable", type(exc).__name__),
                proposal=proposal,
                pre_state=pre_state,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                acknowledgment=acknowledgment,
                post_state=None,
            )
        acknowledgment_valid = acknowledgment.verify_for_transaction(
            self.acknowledgment_public_key,
            permit=permit,
            pre_state=pre_state,
            readback_state=post_state,
            expected_device_id=self.control_device.device_id,
            expected_key_id=self.control_device.acknowledgment_key_id,
        )
        readback_matches = (
            acknowledgment.post_state_digest == post_state.state_digest
            and acknowledgment.post_state_version == post_state.state_version
        )
        if (
            acknowledgment.status is CommandStatus.APPLIED
            and acknowledgment_valid
            and readback_matches
        ):
            return self._record(
                status=ClosedLoopStatus.COMPLETED,
                reasons=("command_applied_acknowledged_and_read_back",),
                proposal=proposal,
                pre_state=pre_state,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                acknowledgment=acknowledgment,
                post_state=post_state,
            )
        if acknowledgment.status is CommandStatus.REJECTED and acknowledgment_valid:
            return self._record(
                status=ClosedLoopStatus.DEVICE_REJECTED,
                reasons=(acknowledgment.reason,),
                proposal=proposal,
                pre_state=pre_state,
                decision=decision,
                command=command,
                assessment=assessment,
                permit=permit,
                acknowledgment=acknowledgment,
                post_state=post_state,
            )
        reasons = ["execution_effect_not_established", acknowledgment.reason]
        if not acknowledgment_valid:
            reasons.append("acknowledgment_signature_invalid")
        if acknowledgment.status is CommandStatus.APPLIED and not readback_matches:
            reasons.append("acknowledgment_readback_mismatch")
        return self._record(
            status=ClosedLoopStatus.UNKNOWN_EFFECT,
            reasons=tuple(reasons),
            proposal=proposal,
            pre_state=pre_state,
            decision=decision,
            command=command,
            assessment=assessment,
            permit=permit,
            acknowledgment=acknowledgment,
            post_state=None,
            last_observed_state=post_state,
        )
