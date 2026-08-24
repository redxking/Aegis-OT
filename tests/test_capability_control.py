from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Literal

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import aegis_ot.capability_control as capability_control_module
from aegis_ot.capability_control import (
    CapabilityClosedLoopController,
    CapabilityPermitIssuer,
    SignedObservationVerifier,
)
from aegis_ot.capability_ipc import (
    IpcOutcomeUnknownError,
    IpcTransportError,
)
from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopStatus,
    CapabilityExecutionPermit,
    DispatchPhase,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from aegis_ot.capability_observer import ObserverProcessInfo, ObserverServiceError
from aegis_ot.capability_plant import PlantProcessInfo
from aegis_ot.capability_plc import PlcProcessInfo
from aegis_ot.crypto import generate_keypair
from aegis_ot.evidence import EvidenceChain
from aegis_ot.factory import build_local_lab
from aegis_ot.models import ActionProposal, Decision, DecisionOutcome, Operation
from aegis_ot.pandapower_plant import PandapowerCigreMVPlant
from aegis_ot.physical_control import (
    ExecutionPermitIssuer,
    PermitIssuanceError,
    TrustedCommandTranslator,
)
from aegis_ot.physical_models import (
    CandidateAssessment,
    CommandStatus,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
)
from aegis_ot.safety import SafetyKernel, SafetyLimits

NOW = datetime(2026, 8, 24, 16, 0, tzinfo=UTC)
PLANT_BOOT = "plant-boot-epoch-0001"
OBSERVER_ID = "observer:controller-test"
OBSERVER_KEY_ID = "observer-key-controller-test"
OBSERVER_BOOT = "observer-boot-epoch-0001"
PLC_ID = "plc:controller-test"
PLC_KEY_ID = "plc-key-controller-test"
PLC_BOOT = "plc-boot-epoch-0000001"
PERMIT_KEY_ID = "permit-key-controller-test"

PostMode = Literal["valid", "missing", "lost", "invalid_challenge", "contradiction"]
PlcMode = Literal[
    "applied",
    "invalid_ack",
    "lost_response",
    "cas_version_changed",
    "cas_inconsistent",
    "unknown_effect",
]


def _raw_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _redigest_state(
    state: PhysicalStateSnapshot,
    **updates: object,
) -> PhysicalStateSnapshot:
    changed = state.model_copy(
        update=updates | {"state_digest": "0" * 64, "observation_digest": "0" * 64}
    )
    changed = changed.model_copy(
        update={"state_digest": canonical_digest(changed.digest_material())}
    )
    return changed.model_copy(
        update={"observation_digest": canonical_digest(changed.observation_material())}
    )


def _proposal(state: PhysicalStateSnapshot, *, suffix: str) -> ActionProposal:
    return ActionProposal(
        proposal_id=f"capability-controller-{suffix}",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=state.state_version,
        observed_at=state.observed_at,
        submitted_at=state.observed_at,
        nonce=f"capability-controller-{suffix}-nonce-0001",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


@dataclass(frozen=True)
class BaseCase:
    pre_state: PhysicalStateSnapshot
    candidate_post_state: PhysicalStateSnapshot
    observed_post_state: PhysicalStateSnapshot
    cas_version_state: PhysicalStateSnapshot
    permit_private: Ed25519PrivateKey
    permit_public: Ed25519PublicKey
    observer_private: Ed25519PrivateKey
    observer_public: Ed25519PublicKey
    foreign_observer_private: Ed25519PrivateKey
    plc_private: Ed25519PrivateKey
    plc_public: Ed25519PublicKey
    plant_info: PlantProcessInfo
    observer_info: ObserverProcessInfo
    plc_info: PlcProcessInfo


@pytest.fixture(scope="module")
def base_case() -> BaseCase:
    plant = PandapowerCigreMVPlant(
        observed_at=NOW,
        observation_source_id="controller-test-plant-source",
    )
    pre_state = plant.read_state()
    seed_proposal = _proposal(pre_state, suffix="seed")
    seed_command = TrustedCommandTranslator().translate(seed_proposal)
    candidate = plant.simulate_candidate(seed_command)
    observed_post = _redigest_state(
        candidate.post_state,
        observed_at=NOW,
        observation_sequence=pre_state.observation_sequence + 1,
    )
    cas_version_state = _redigest_state(
        pre_state,
        state_version=pre_state.state_version + 1,
        simulation_time_s=pre_state.simulation_time_s + 1.0,
        observation_sequence=pre_state.observation_sequence + 1,
    )
    permit_private, permit_public = generate_keypair()
    observer_private, observer_public = generate_keypair()
    foreign_observer_private, _ = generate_keypair()
    plc_private, plc_public = generate_keypair()
    plant_info = PlantProcessInfo(
        pid=101,
        boot_epoch=PLANT_BOOT,
        backend="deterministic-local-v1",
        model_digest=pre_state.model_digest,
        simulator_version=pre_state.simulator_version,
        observation_source_id=pre_state.observation_source_id,
        capabilities={},
    )
    observer_info = ObserverProcessInfo(
        pid=102,
        observer_id=OBSERVER_ID,
        boot_epoch=OBSERVER_BOOT,
        key_id=OBSERVER_KEY_ID,
        public_key_bytes=_raw_key(observer_public),
        plant_boot_epoch=PLANT_BOOT,
        capabilities={},
    )
    plc_info = PlcProcessInfo(
        pid=103,
        plc_id=PLC_ID,
        boot_epoch=PLC_BOOT,
        key_id=PLC_KEY_ID,
        public_key_bytes=_raw_key(plc_public),
        permit_key_id=PERMIT_KEY_ID,
        plant_boot_epoch=PLANT_BOOT,
        observer_boot_epoch=OBSERVER_BOOT,
        capabilities={},
    )
    return BaseCase(
        pre_state=pre_state,
        candidate_post_state=candidate.post_state,
        observed_post_state=observed_post,
        cas_version_state=cas_version_state,
        permit_private=permit_private,
        permit_public=permit_public,
        observer_private=observer_private,
        observer_public=observer_public,
        foreign_observer_private=foreign_observer_private,
        plc_private=plc_private,
        plc_public=plc_public,
        plant_info=plant_info,
        observer_info=observer_info,
        plc_info=plc_info,
    )


def _pre_observation(
    base: BaseCase,
    *,
    observer_key_id: str = OBSERVER_KEY_ID,
    observer_boot_epoch: str = OBSERVER_BOOT,
    private_key: Ed25519PrivateKey | None = None,
) -> SignedObservationEnvelope:
    return SignedObservationEnvelope.issue(
        snapshot=base.pre_state,
        correlation_id="controller-correlation-0001",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="controller-pre-challenge-0001",
        observer_id=OBSERVER_ID,
        observer_key_id=observer_key_id,
        observer_boot_epoch=observer_boot_epoch,
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=private_key or base.observer_private,
    )


class FakeObserver:
    def __init__(
        self,
        base: BaseCase,
        pre_observation: SignedObservationEnvelope,
        *,
        post_mode: PostMode,
    ) -> None:
        self.base = base
        self.pre_observation = pre_observation
        self.post_mode = post_mode
        self.resolve_calls = 0
        self.post_calls = 0

    def resolve(
        self,
        *,
        observation_id: str,
        envelope_digest: str,
    ) -> SignedObservationEnvelope:
        self.resolve_calls += 1
        if (
            observation_id != self.pre_observation.observation_id
            or envelope_digest != self.pre_observation.envelope_digest
        ):
            raise ObserverServiceError("observation_not_found")
        return self.pre_observation

    def capture_post(
        self,
        *,
        correlation_id: str,
        challenge_nonce: str,
        previous_envelope_digest: str,
        permit_id: str,
        command_digest: str,
        plc_acknowledgment_digest: str,
    ) -> SignedObservationEnvelope:
        self.post_calls += 1
        if previous_envelope_digest != self.pre_observation.envelope_digest:
            raise ObserverServiceError("post predecessor mismatch")
        if self.post_mode == "missing":
            raise ObserverServiceError("post observation missing")
        if self.post_mode == "lost":
            raise IpcTransportError("post observation response lost")
        selected_challenge = (
            f"{challenge_nonce}-wrong"
            if self.post_mode == "invalid_challenge"
            else challenge_nonce
        )
        snapshot = (
            self.pre_observation.snapshot
            if self.post_mode == "contradiction"
            else self.base.observed_post_state
        )
        return SignedObservationEnvelope.issue(
            snapshot=snapshot,
            correlation_id=correlation_id,
            phase=ObservationPhase.POST_DISPATCH,
            challenge_nonce=selected_challenge,
            observer_id=self.pre_observation.observer_id,
            observer_key_id=self.pre_observation.observer_key_id,
            observer_boot_epoch=self.pre_observation.observer_boot_epoch,
            observer_sequence=self.pre_observation.observer_sequence + 1,
            previous_envelope_digest=self.pre_observation.envelope_digest,
            permit_id=permit_id,
            command_digest=command_digest,
            plc_acknowledgment_digest=plc_acknowledgment_digest,
            private_key=self.base.observer_private,
        )


class FakeSimulator:
    def __init__(
        self,
        base: BaseCase,
        *,
        candidate_pre_state: PhysicalStateSnapshot | None,
    ) -> None:
        self.base = base
        self.candidate_pre_state = candidate_pre_state
        self.calls = 0

    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
        self.calls += 1
        return CandidateAssessment(
            command_digest=command.digest,
            pre_state=self.candidate_pre_state or self.base.pre_state,
            post_state=self.base.candidate_post_state,
            safe=True,
            reasons=(),
        )


class FakePlc:
    def __init__(self, base: BaseCase, *, mode: PlcMode) -> None:
        self.base = base
        self.mode = mode
        self.calls = 0

    def execute(
        self,
        *,
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        pre_observation: SignedObservationEnvelope,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> PlcCommandAcknowledgment:
        self.calls += 1
        if self.mode == "lost_response":
            raise IpcOutcomeUnknownError("simulated response loss after one dispatch")

        command = permit.base_permit.command
        pre_state = pre_observation.snapshot
        status = CommandStatus.APPLIED
        phase = DispatchPhase.COMMITTED
        reason = "command_applied_and_plc_read_back"
        post_state = assessment.post_state
        if self.mode in {"cas_version_changed", "cas_inconsistent"}:
            status = CommandStatus.REJECTED
            phase = DispatchPhase.PRE_DISPATCH
            reason = "precommit_state_version_changed"
            post_state = None
            if self.mode == "cas_version_changed":
                pre_state = self.base.cas_version_state
        elif self.mode == "unknown_effect":
            status = CommandStatus.UNKNOWN_EFFECT
            phase = DispatchPhase.EFFECT_UNKNOWN
            reason = "dispatch_crossed_boundary_but_readback_unavailable"
            post_state = None

        pre_setpoint = 0.0 if command.resource in pre_state.isolated_resources else 1.0
        acknowledgment = PlcCommandAcknowledgment(
            request_digest=request.digest,
            permit_digest=permit.digest,
            observation_envelope_digest=pre_observation.envelope_digest,
            permit_id=permit.base_permit.permit_id,
            permit_nonce=permit.base_permit.permit_nonce,
            command_id=command.command_id,
            command_digest=permit.base_permit.command_digest,
            assessment_digest=permit.base_permit.assessment_digest,
            proposal_id=request.proposal.proposal_id,
            decision_id=decision.decision_id,
            plc_id=self.base.plc_info.plc_id,
            plc_key_id=self.base.plc_info.key_id,
            plc_boot_epoch=self.base.plc_info.boot_epoch,
            plc_scan=1,
            status=status,
            dispatch_phase=phase,
            reason=reason,
            acknowledged_at=NOW,
            pre_state=pre_state,
            pre_state_digest=pre_state.state_digest,
            pre_state_version=pre_state.state_version,
            post_state_digest=post_state.state_digest if post_state is not None else None,
            post_state_version=post_state.state_version if post_state is not None else None,
            post_topology_digest=post_state.topology_digest if post_state is not None else None,
            pre_actuator_setpoint=pre_setpoint,
            post_actuator_setpoint=(
                command.setpoint
                if post_state is not None
                else (None if status is CommandStatus.UNKNOWN_EFFECT else pre_setpoint)
            ),
            simulation_time_s=(
                post_state.simulation_time_s
                if post_state is not None
                else pre_state.simulation_time_s
            ),
        ).signed(self.base.plc_private)
        if self.mode == "invalid_ack":
            return acknowledgment.model_copy(update={"signature": "AAAA"})
        return acknowledgment


@dataclass
class Harness:
    controller: CapabilityClosedLoopController
    request: CapabilityActionRequest
    observer: FakeObserver
    simulator: FakeSimulator
    plc: FakePlc


def _harness(
    base: BaseCase,
    *,
    pre_observation: SignedObservationEnvelope | None = None,
    evaluated_at: datetime = NOW,
    candidate_pre_state: PhysicalStateSnapshot | None = None,
    plc_mode: PlcMode = "applied",
    post_mode: PostMode = "valid",
) -> Harness:
    selected_pre = pre_observation or _pre_observation(base)
    proposal = _proposal(selected_pre.snapshot, suffix="under-test")
    request = CapabilityActionRequest(
        correlation_id=selected_pre.correlation_id,
        proposal=proposal,
        observation_id=selected_pre.observation_id,
        observation_envelope_digest=selected_pre.envelope_digest,
        observation_challenge_nonce=selected_pre.challenge_nonce,
    )
    authorization = build_local_lab(NOW)
    authorization.gateway.safety = SafetyKernel(
        SafetyLimits(minimum_voltage_pu=0.90, maximum_voltage_pu=1.10),
        version="controller-test-safety-v1",
    )
    observer = FakeObserver(base, selected_pre, post_mode=post_mode)
    simulator = FakeSimulator(base, candidate_pre_state=candidate_pre_state)
    plc = FakePlc(base, mode=plc_mode)
    base_issuer = ExecutionPermitIssuer(
        base.permit_private,
        signing_key_id=PERMIT_KEY_ID,
        audience=base.plc_info.plc_id,
        evidence=authorization.gateway.evidence,
        clock=lambda: evaluated_at,
    )
    permit_issuer = CapabilityPermitIssuer(
        base_issuer,
        base.permit_private,
        base.plc_info,
    )
    controller = CapabilityClosedLoopController(
        gateway=authorization.gateway,
        observer=observer,
        simulator=simulator,
        plc=plc,
        translator=TrustedCommandTranslator(),
        permit_issuer=permit_issuer,
        observation_verifier=SignedObservationVerifier(
            observer_info=base.observer_info,
            plant_info=base.plant_info,
        ),
        plc_info=base.plc_info,
        plc_public_key=base.plc_public,
        evidence=authorization.gateway.evidence,
        clock=lambda: evaluated_at,
    )
    return Harness(
        controller=controller,
        request=request,
        observer=observer,
        simulator=simulator,
        plc=plc,
    )


@pytest.mark.parametrize(
    ("variant", "expected_reason"),
    [
        ("stale", "observation_stale"),
        ("tampered", "observation_signature_invalid"),
        ("wrong_boot", "observation_boot_mismatch"),
        ("wrong_key", "observation_key_mismatch"),
    ],
)
def test_untrusted_pre_observations_fail_before_simulation_or_dispatch(
    base_case: BaseCase,
    variant: str,
    expected_reason: str,
) -> None:
    pre = _pre_observation(base_case)
    evaluated_at = NOW
    if variant == "stale":
        evaluated_at = NOW + timedelta(seconds=6)
    elif variant == "tampered":
        pre = pre.model_copy(update={"signature": "AAAA"})
    elif variant == "wrong_boot":
        pre = _pre_observation(
            base_case,
            observer_boot_epoch="observer-wrong-boot-0001",
        )
    elif variant == "wrong_key":
        pre = _pre_observation(
            base_case,
            observer_key_id="observer-wrong-key",
            private_key=base_case.foreign_observer_private,
        )

    harness = _harness(base_case, pre_observation=pre, evaluated_at=evaluated_at)
    result = harness.controller.execute(harness.request)

    assert result.status is CapabilityClosedLoopStatus.NOT_DISPATCHED
    assert expected_reason in result.reasons
    assert result.dispatch_attempts == 0
    assert result.automatic_retry_count == 0
    assert result.permit is None
    assert result.acknowledgment is None
    assert harness.observer.resolve_calls == 1
    assert harness.observer.post_calls == 0
    assert harness.simulator.calls == 0
    assert harness.plc.calls == 0
    assert harness.controller.evidence.verify()


def test_candidate_observation_binding_mismatch_blocks_permit_and_dispatch(
    base_case: BaseCase,
) -> None:
    substituted_pre = _redigest_state(
        base_case.pre_state,
        observation_source_id="substituted-candidate-source",
    )
    harness = _harness(base_case, candidate_pre_state=substituted_pre)

    result = harness.controller.execute(harness.request)

    assert result.status is CapabilityClosedLoopStatus.CANDIDATE_REJECTED
    assert result.reasons == ("candidate_binding_mismatch",)
    assert result.permit is None
    assert result.dispatch_attempts == 0
    assert result.automatic_retry_count == 0
    assert harness.simulator.calls == 1
    assert harness.plc.calls == 0
    assert harness.observer.post_calls == 0


def test_invalid_plc_acknowledgment_is_unknown_and_never_promoted_to_completion(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case, plc_mode="invalid_ack")

    result = harness.controller.execute(harness.request)

    assert result.status is CapabilityClosedLoopStatus.UNKNOWN_EFFECT
    assert result.reasons == ("plc_acknowledgment_invalid",)
    assert result.acknowledgment is not None
    assert not result.acknowledgment.verify(base_case.plc_public)
    assert result.post_observation is None
    assert result.dispatch_attempts == 1
    assert result.automatic_retry_count == 0
    assert harness.plc.calls == 1
    assert harness.observer.post_calls == 0


def test_lost_plc_response_has_at_most_one_dispatch_and_no_automatic_retry(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case, plc_mode="lost_response")

    result = harness.controller.execute(harness.request)

    assert result.status is CapabilityClosedLoopStatus.UNKNOWN_EFFECT
    assert result.reasons == ("plc_dispatch_outcome_unavailable", "IpcOutcomeUnknownError")
    assert result.acknowledgment is None
    assert result.post_observation is None
    assert result.dispatch_attempts == 1
    assert result.automatic_retry_count == 0
    assert harness.plc.calls == 1
    assert harness.observer.post_calls == 0


@pytest.mark.parametrize(
    ("post_mode", "error_type"),
    [("missing", "ObserverServiceError"), ("lost", "IpcTransportError")],
)
def test_missing_or_lost_post_observation_is_unknown_without_redispatch(
    base_case: BaseCase,
    post_mode: PostMode,
    error_type: str,
) -> None:
    harness = _harness(base_case, post_mode=post_mode)

    result = harness.controller.execute(harness.request)

    assert result.status is CapabilityClosedLoopStatus.UNKNOWN_EFFECT
    assert result.reasons == ("post_observation_unavailable", error_type)
    assert result.acknowledgment is not None
    assert result.acknowledgment.verify(base_case.plc_public)
    assert result.post_observation is None
    assert result.dispatch_attempts == 1
    assert result.automatic_retry_count == 0
    assert harness.plc.calls == 1
    assert harness.observer.post_calls == 1


def test_invalid_signed_post_observation_is_unknown_not_divergence(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case, post_mode="invalid_challenge")

    result = harness.controller.execute(harness.request)

    assert result.status is CapabilityClosedLoopStatus.UNKNOWN_EFFECT
    assert result.reasons == (
        "post_observation_invalid",
        "post_observation_challenge_mismatch",
    )
    assert result.post_observation is None
    assert result.last_observation is not None
    assert result.last_observation.verify(base_case.observer_public)
    assert result.dispatch_attempts == 1
    assert result.automatic_retry_count == 0
    assert harness.plc.calls == harness.observer.post_calls == 1


def test_validly_signed_post_contradiction_is_explicit_observation_divergence(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case, post_mode="contradiction")

    result = harness.controller.execute(harness.request)

    assert result.status is CapabilityClosedLoopStatus.OBSERVATION_DIVERGED
    assert result.reasons == ("signed_post_observation_contradiction",)
    assert result.acknowledgment is not None
    assert result.post_observation is not None
    assert result.post_observation.verify(base_case.observer_public)
    assert (
        result.post_observation.snapshot.state_digest
        != result.acknowledgment.post_state_digest
    )
    assert result.dispatch_attempts == 1
    assert result.automatic_retry_count == 0
    assert harness.plc.calls == harness.observer.post_calls == 1


@pytest.mark.parametrize(
    ("plc_mode", "expected_status", "expected_reason"),
    [
        (
            "cas_version_changed",
            CapabilityClosedLoopStatus.PLC_REJECTED,
            "precommit_state_version_changed",
        ),
        (
            "cas_inconsistent",
            CapabilityClosedLoopStatus.UNKNOWN_EFFECT,
            "plc_acknowledgment_invalid",
        ),
    ],
)
def test_cas_rejection_requires_the_reason_specific_signed_state_boundary(
    base_case: BaseCase,
    plc_mode: PlcMode,
    expected_status: CapabilityClosedLoopStatus,
    expected_reason: str,
) -> None:
    harness = _harness(base_case, plc_mode=plc_mode)

    result = harness.controller.execute(harness.request)

    assert result.status is expected_status
    assert result.reasons == (expected_reason,)
    assert result.acknowledgment is not None
    assert result.acknowledgment.verify(base_case.plc_public)
    assert result.post_observation is None
    assert result.dispatch_attempts == 1
    assert result.automatic_retry_count == 0
    assert harness.plc.calls == 1
    assert harness.observer.post_calls == 0


def test_capability_permit_issuer_enforces_one_signer_and_rotates_target(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case)
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.COMPLETED
    assert result.pre_observation is not None
    assert result.decision is not None
    assert result.command is not None
    assert result.assessment is not None

    foreign_private, _ = generate_keypair()
    with pytest.raises(ValueError, match="same configured signer"):
        CapabilityPermitIssuer(
            harness.controller.permit_issuer.base_issuer,
            foreign_private,
            base_case.plc_info,
        )

    replacement = replace(
        base_case.plc_info,
        pid=104,
        key_id="plc-key-controller-replacement",
        boot_epoch="plc-boot-replacement-0001",
    )
    issuer = harness.controller.permit_issuer
    issuer.rotate_target(replacement)
    rotated = issuer.issue(
        request=harness.request,
        pre_observation=result.pre_observation,
        decision=result.decision,
        command=result.command,
        assessment=result.assessment,
    )
    assert rotated.target_plc_id == replacement.plc_id
    assert rotated.target_plc_key_id == replacement.key_id
    assert rotated.target_plc_boot_epoch == replacement.boot_epoch


def test_capability_permit_issuer_rejects_reference_and_candidate_substitution(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case)
    result = harness.controller.execute(harness.request)
    assert result.pre_observation is not None
    assert result.decision is not None
    assert result.command is not None
    assert result.assessment is not None
    issuer = harness.controller.permit_issuer

    substituted_request = harness.request.model_copy(
        update={"observation_id": "substituted-observation-id"}
    )
    with pytest.raises(PermitIssuanceError, match="request_observation_binding_mismatch"):
        issuer.issue(
            request=substituted_request,
            pre_observation=result.pre_observation,
            decision=result.decision,
            command=result.command,
            assessment=result.assessment,
        )

    substituted_pre = _redigest_state(
        result.assessment.pre_state,
        observation_source_id="candidate-substitution-source",
    )
    substituted_assessment = result.assessment.model_copy(
        update={"pre_state": substituted_pre}
    )
    with pytest.raises(PermitIssuanceError, match="candidate_signed_observation_mismatch"):
        issuer.issue(
            request=harness.request,
            pre_observation=result.pre_observation,
            decision=result.decision,
            command=result.command,
            assessment=substituted_assessment,
        )


def test_observation_verifier_rejects_nonpositive_freshness_window(
    base_case: BaseCase,
) -> None:
    for maximum_age in (timedelta(0), timedelta(microseconds=-1)):
        with pytest.raises(ValueError, match="must be positive"):
            SignedObservationVerifier(
                observer_info=base_case.observer_info,
                plant_info=base_case.plant_info,
                maximum_age=maximum_age,
            )


def test_observation_verifier_reports_all_common_trust_and_replay_failures(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case)
    verifier = SignedObservationVerifier(
        observer_info=base_case.observer_info,
        plant_info=base_case.plant_info,
    )
    valid = harness.observer.pre_observation
    assert verifier.verify_pre(valid, harness.request, evaluated_at=NOW) == ()

    invalid_snapshot = valid.snapshot.model_copy(
        update={
            "observation_source_id": "wrong-plant-source",
            "model_digest": "f" * 64,
            "simulator_version": "wrong-simulator-version",
            "state_digest": "0" * 64,
        }
    )
    invalid = valid.model_copy(
        update={
            "observer_id": "observer:substituted",
            "observer_key_id": "observer-key-substituted",
            "observer_boot_epoch": "observer-boot-substituted",
            "snapshot": invalid_snapshot,
        }
    )
    reasons = verifier.verify_pre(
        invalid,
        harness.request,
        evaluated_at=NOW - timedelta(microseconds=1),
    )
    assert {
        "observation_source_mismatch",
        "observation_key_mismatch",
        "observation_boot_mismatch",
        "observation_signature_invalid",
        "plant_observation_source_mismatch",
        "plant_model_digest_mismatch",
        "plant_simulator_version_mismatch",
        "observation_state_digest_invalid",
        "observation_from_future",
        "observation_sequence_regressed",
        "observation_challenge_replayed",
    } <= set(reasons)


def test_pre_observation_verifier_reports_every_transaction_binding_mismatch(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case)
    valid = harness.observer.pre_observation
    substituted = valid.model_copy(
        update={
            "phase": ObservationPhase.POST_DISPATCH,
            "observation_id": "substituted-observation-id",
            "envelope_digest": "f" * 64,
            "challenge_nonce": "substituted-challenge-0001",
            "correlation_id": "substituted-correlation-id",
        }
    )
    substituted_proposal = harness.request.proposal.model_copy(
        update={
            "observed_state_version": valid.snapshot.state_version + 1,
            "observed_at": valid.snapshot.observed_at + timedelta(microseconds=1),
        }
    )
    substituted_request = harness.request.model_copy(
        update={"proposal": substituted_proposal}
    )
    verifier = SignedObservationVerifier(
        observer_info=base_case.observer_info,
        plant_info=base_case.plant_info,
    )
    reasons = verifier.verify_pre(substituted, substituted_request, evaluated_at=NOW)
    assert {
        "observation_phase_mismatch",
        "observation_id_mismatch",
        "observation_envelope_digest_mismatch",
        "observation_challenge_mismatch",
        "observation_correlation_mismatch",
        "proposal_observation_version_mismatch",
        "proposal_observation_time_mismatch",
    } <= set(reasons)


def test_post_observation_verifier_reports_every_transaction_binding_mismatch(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case)
    result = harness.controller.execute(harness.request)
    assert result.permit is not None
    assert result.acknowledgment is not None
    assert result.post_observation is not None
    valid = result.post_observation
    substituted = valid.model_copy(
        update={
            "phase": ObservationPhase.PRE_AUTHORIZATION,
            "correlation_id": "substituted-correlation-id",
            "permit_id": "substituted-permit-id",
            "command_digest": "1" * 64,
            "plc_acknowledgment_digest": "2" * 64,
            "previous_envelope_digest": "3" * 64,
            "captured_at": result.acknowledgment.acknowledged_at
            - timedelta(microseconds=1),
        }
    )
    verifier = SignedObservationVerifier(
        observer_info=base_case.observer_info,
        plant_info=base_case.plant_info,
    )
    reasons = verifier.verify_post(
        substituted,
        request=harness.request,
        permit=result.permit,
        acknowledgment=result.acknowledgment,
        challenge_nonce=valid.challenge_nonce,
        evaluated_at=NOW,
    )
    assert {
        "post_observation_phase_mismatch",
        "post_observation_correlation_mismatch",
        "post_observation_permit_mismatch",
        "post_observation_command_mismatch",
        "post_observation_acknowledgment_mismatch",
        "post_observation_previous_envelope_mismatch",
        "post_observation_precedes_acknowledgment",
    } <= set(reasons)


def test_controller_requires_the_gateway_evidence_chain_identity(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case)
    existing = harness.controller
    with pytest.raises(ValueError, match="share one evidence chain"):
        CapabilityClosedLoopController(
            gateway=existing.gateway,
            observer=existing.observer,
            simulator=existing.simulator,
            plc=existing.plc,
            translator=existing.translator,
            permit_issuer=existing.permit_issuer,
            observation_verifier=existing.observation_verifier,
            plc_info=existing.plc_info,
            plc_public_key=existing.plc_public_key,
            evidence=EvidenceChain(),
            clock=lambda: NOW,
        )


def test_controller_fails_closed_when_pre_observation_resolution_raises(
    base_case: BaseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(base_case)

    def unavailable(**_: str) -> SignedObservationEnvelope:
        raise ObserverServiceError("observer unavailable")

    monkeypatch.setattr(harness.observer, "resolve", unavailable)
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.NOT_DISPATCHED
    assert result.reasons == ("pre_observation_unavailable", "ObserverServiceError")
    assert result.dispatch_attempts == 0
    assert harness.simulator.calls == harness.plc.calls == 0


def test_controller_fails_closed_when_gateway_state_conversion_raises(
    base_case: BaseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(base_case)

    def conversion_failed(_: PhysicalStateSnapshot) -> None:
        raise ValueError("state conversion unavailable")

    monkeypatch.setattr(
        capability_control_module,
        "physical_state_to_gateway_state",
        conversion_failed,
    )
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.NOT_DISPATCHED
    assert result.reasons == ("gateway_state_conversion_failed", "ValueError")
    assert result.pre_observation is not None
    assert result.dispatch_attempts == 0
    assert harness.simulator.calls == harness.plc.calls == 0


def test_controller_fails_closed_when_authorization_service_raises(
    base_case: BaseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(base_case)

    def decision_unavailable(*_: object, **__: object) -> Decision:
        raise RuntimeError("authorization unavailable")

    monkeypatch.setattr(harness.controller.gateway, "decide", decision_unavailable)
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.NOT_DISPATCHED
    assert result.reasons == ("authorization_decision_unavailable", "RuntimeError")
    assert result.dispatch_attempts == 0
    assert harness.simulator.calls == harness.plc.calls == 0


def test_controller_preserves_a_nonpermit_gateway_disposition(
    base_case: BaseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(base_case)

    def deny(*_: object, **__: object) -> Decision:
        return Decision(
            proposal_id=harness.request.proposal.proposal_id,
            outcome=DecisionOutcome.DENY,
            reasons=("policy_denied",),
            decided_at=NOW,
            policy_version="controller-test-policy-v1",
            safety_version="controller-test-safety-v1",
            state_version=base_case.pre_state.state_version,
        )

    monkeypatch.setattr(harness.controller.gateway, "decide", deny)
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.NOT_DISPATCHED
    assert result.reasons == ("policy_denied",)
    assert result.decision is not None
    assert result.dispatch_attempts == 0
    assert harness.simulator.calls == harness.plc.calls == 0


def test_controller_fails_closed_when_command_translation_raises(
    base_case: BaseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(base_case)

    def translation_failed(_: ActionProposal) -> PhysicalControlCommand:
        raise ValueError("translation unavailable")

    monkeypatch.setattr(harness.controller.translator, "translate", translation_failed)
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.NOT_DISPATCHED
    assert result.reasons == ("command_translation_failed", "ValueError")
    assert result.decision is not None
    assert result.dispatch_attempts == 0
    assert harness.simulator.calls == harness.plc.calls == 0


def test_controller_fails_closed_when_candidate_simulation_raises(
    base_case: BaseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(base_case)

    def simulation_failed(_: PhysicalControlCommand) -> CandidateAssessment:
        raise RuntimeError("simulation unavailable")

    monkeypatch.setattr(harness.simulator, "simulate_candidate", simulation_failed)
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.NOT_DISPATCHED
    assert result.reasons == ("candidate_simulation_unavailable", "RuntimeError")
    assert result.command is not None
    assert result.dispatch_attempts == 0
    assert harness.plc.calls == 0


def test_controller_preserves_unsafe_candidate_reasons_without_dispatch(
    base_case: BaseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(base_case)

    def unsafe(command: PhysicalControlCommand) -> CandidateAssessment:
        unsafe_post = _redigest_state(
            base_case.candidate_post_state,
            unsafe_state=True,
        )
        return CandidateAssessment(
            command_digest=command.digest,
            pre_state=base_case.pre_state,
            post_state=unsafe_post,
            safe=False,
            reasons=("voltage_limit_exceeded",),
        )

    monkeypatch.setattr(harness.simulator, "simulate_candidate", unsafe)
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.CANDIDATE_REJECTED
    assert result.reasons == ("voltage_limit_exceeded",)
    assert result.permit is None
    assert result.dispatch_attempts == 0
    assert harness.plc.calls == 0


def test_controller_fails_closed_when_permit_issuance_raises(
    base_case: BaseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(base_case)

    def issuance_failed(**_: object) -> CapabilityExecutionPermit:
        raise RuntimeError("permit issuer unavailable")

    monkeypatch.setattr(harness.controller.permit_issuer, "issue", issuance_failed)
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.NOT_DISPATCHED
    assert result.reasons == ("permit_issuance_failed", "RuntimeError")
    assert result.assessment is not None
    assert result.dispatch_attempts == 0
    assert harness.plc.calls == 0


def test_plc_signed_unknown_effect_is_terminal_without_post_capture(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case, plc_mode="unknown_effect")
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.UNKNOWN_EFFECT
    assert result.reasons == ("dispatch_crossed_boundary_but_readback_unavailable",)
    assert result.acknowledgment is not None
    assert result.acknowledgment.status is CommandStatus.UNKNOWN_EFFECT
    assert result.acknowledgment.verify(base_case.plc_public)
    assert result.dispatch_attempts == 1
    assert harness.plc.calls == 1
    assert harness.observer.post_calls == 0


def test_matching_plc_and_observer_evidence_completes_exactly_once(
    base_case: BaseCase,
) -> None:
    harness = _harness(base_case)
    result = harness.controller.execute(harness.request)
    assert result.status is CapabilityClosedLoopStatus.COMPLETED
    assert result.reasons == (
        "plc_acknowledgment_and_signed_post_observation_match",
    )
    assert result.acknowledgment is not None
    assert result.post_observation is not None
    assert result.post_observation.snapshot.state_digest == (
        result.acknowledgment.post_state_digest
    )
    assert result.dispatch_attempts == 1
    assert harness.plc.calls == harness.observer.post_calls == 1
