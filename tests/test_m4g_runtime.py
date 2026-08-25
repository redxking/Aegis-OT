from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityExecutionPermit,
    DispatchPhase,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from aegis_ot.capability_observer import ObserverProcessInfo
from aegis_ot.capability_plc import (
    CapabilityVirtualPlc,
    OrderlyRestartReplayReservations,
)
from aegis_ot.crypto import generate_keypair
from aegis_ot.models import ActionProposal, Decision, Operation
from aegis_ot.pandapower_plant import PhysicalSimulationError
from aegis_ot.physical_control import (
    TrustedCommandTranslator,
    physical_state_to_gateway_state,
)
from aegis_ot.physical_factory import build_physical_local_lab
from aegis_ot.physical_models import (
    CandidateAssessment,
    CommandStatus,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
)
from aegis_ot.segmented_capability_models import (
    OT_CAPABILITY_AUDIENCE,
    PHYSICAL_PLANT_AUDIENCE,
    PlantApplyPayload,
    PlantCallerRole,
    PlantCapturePayload,
    PlantFailureResponsePayload,
    PlantOperation,
    PlantReadPayload,
    PlantResponseStatus,
    SegmentedCapabilityDispatch,
    SignedPlantCall,
    SignedSegmentedCapabilityDispatch,
)
from aegis_ot.segmented_capability_runtime import (
    CapabilityAdmissionRejected,
    CapabilityGatewayRuntime,
    CapabilityObserverRuntime,
    CapabilityOtRuntime,
    CapabilityPlantRuntime,
    CapabilityRuntimeUnavailable,
    ObservationCaptureRequest,
    ObservationResolveRequest,
    PostObservationCaptureRequest,
    TrustedPlantCaller,
    create_ot_app,
    create_plant_app,
)
from aegis_ot.segmented_capability_transport import (
    PlantHealthMetadata,
    TransportFailureBody,
)
from aegis_ot.transport_replay import DurableTransportReplayLedger

NOW = datetime(2026, 8, 25, 18, 0, tzinfo=UTC)
PLANT_KEY_ID = "m4g-runtime-plant-key-0001"
OBSERVER_KEY_ID = "m4g-runtime-observer-key-0001"
CANDIDATE_KEY_ID = "m4g-runtime-candidate-key-0001"
OT_KEY_ID = "m4g-runtime-ot-key-0001"
GATEWAY_KEY_ID = "m4g-runtime-gateway-key-0001"
PLANT_BOOT = "m4g-runtime-plant-boot-0001"
NEW_PLANT_BOOT = "m4g-runtime-plant-boot-0002"
OBSERVER_BOOT = "m4g-runtime-observer-boot-0001"
OT_BOOT = "m4g-runtime-ot-boot-0001"
PLC_ID = "virtual-control-device:m4g-runtime"


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    return base64.urlsafe_b64encode(
        private_key.public_key().public_bytes_raw()
    ).decode("ascii")


@dataclass(frozen=True)
class RuntimeArtifacts:
    gateway_private: Ed25519PrivateKey
    plant_private: Ed25519PrivateKey
    observer_private: Ed25519PrivateKey
    candidate_private: Ed25519PrivateKey
    ot_private: Ed25519PrivateKey
    permit_private: Ed25519PrivateKey
    permit_key_id: str
    pre_state: PhysicalStateSnapshot
    command: PhysicalControlCommand
    assessment: CandidateAssessment
    request: CapabilityActionRequest
    pre_observation: SignedObservationEnvelope
    decision: Decision
    permit: CapabilityExecutionPermit
    dispatch: SegmentedCapabilityDispatch
    envelope: SignedSegmentedCapabilityDispatch
    acknowledgment: PlcCommandAcknowledgment


@pytest.fixture(scope="module")
def artifacts() -> RuntimeArtifacts:
    lab = build_physical_local_lab(NOW)
    pre_state = lab.plant.read_state()
    proposal = ActionProposal(
        proposal_id="m4g-runtime-proposal-0001",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=pre_state.state_version,
        observed_at=pre_state.observed_at,
        submitted_at=pre_state.observed_at,
        nonce="m4g-runtime-proposal-nonce-0001",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )
    decision = lab.authorization.gateway.decide(
        proposal,
        physical_state_to_gateway_state(pre_state),
        NOW,
    )
    command = TrustedCommandTranslator().translate(proposal)
    assessment = lab.plant.simulate_candidate(command)
    base_permit = lab.controller.permit_issuer.issue(
        proposal=proposal,
        decision=decision,
        command=command,
        assessment=assessment,
    )
    permit_private = lab.controller.permit_issuer.private_key
    base_permit = base_permit.model_copy(
        update={"audience": PLC_ID, "signature": ""}
    ).signed(permit_private)
    gateway_private, _ = generate_keypair()
    plant_private, _ = generate_keypair()
    observer_private, _ = generate_keypair()
    candidate_private, _ = generate_keypair()
    ot_private, _ = generate_keypair()
    pre_observation = SignedObservationEnvelope.issue(
        snapshot=pre_state,
        correlation_id="m4g-runtime-correlation-0001",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="m4g-runtime-observation-challenge-0001",
        observer_id="observer:m4g-runtime",
        observer_key_id=OBSERVER_KEY_ID,
        observer_boot_epoch=OBSERVER_BOOT,
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=observer_private,
    )
    request = CapabilityActionRequest(
        request_id="m4g-runtime-request-0001",
        correlation_id=pre_observation.correlation_id,
        proposal=proposal,
        observation_id=pre_observation.observation_id,
        observation_envelope_digest=pre_observation.envelope_digest,
        observation_challenge_nonce=pre_observation.challenge_nonce,
    )
    permit = CapabilityExecutionPermit(
        base_permit=base_permit,
        request_digest=request.digest,
        observation_id=pre_observation.observation_id,
        observation_envelope_digest=pre_observation.envelope_digest,
        observer_id=pre_observation.observer_id,
        observer_key_id=pre_observation.observer_key_id,
        observer_boot_epoch=pre_observation.observer_boot_epoch,
        target_plc_id=PLC_ID,
        target_plc_key_id=OT_KEY_ID,
        target_plc_boot_epoch=OT_BOOT,
        signing_key_id=base_permit.signing_key_id,
    ).signed(permit_private)
    dispatch = SegmentedCapabilityDispatch(
        request=request,
        pre_observation=pre_observation,
        decision=decision,
        assessment=assessment,
        permit=permit,
    )
    envelope = SignedSegmentedCapabilityDispatch.issue(
        dispatch=dispatch,
        gateway_key_id=GATEWAY_KEY_ID,
        transport_nonce="m4g-runtime-transport-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        private_key=gateway_private,
        audience=OT_CAPABILITY_AUDIENCE,
    )
    post_state = assessment.post_state
    acknowledgment = PlcCommandAcknowledgment(
        request_digest=request.digest,
        permit_digest=permit.digest,
        observation_envelope_digest=pre_observation.envelope_digest,
        permit_id=base_permit.permit_id,
        permit_nonce=base_permit.permit_nonce,
        command_id=command.command_id,
        command_digest=command.digest,
        assessment_digest=assessment.digest,
        proposal_id=proposal.proposal_id,
        decision_id=decision.decision_id,
        plc_id=PLC_ID,
        plc_key_id=OT_KEY_ID,
        plc_boot_epoch=OT_BOOT,
        plc_scan=1,
        status=CommandStatus.APPLIED,
        dispatch_phase=DispatchPhase.COMMITTED,
        reason="command_applied_and_read_back",
        acknowledged_at=NOW,
        pre_state=pre_state,
        pre_state_digest=pre_state.state_digest,
        pre_state_version=pre_state.state_version,
        post_state_digest=post_state.state_digest,
        post_state_version=post_state.state_version,
        post_topology_digest=post_state.topology_digest,
        pre_actuator_setpoint=1.0,
        post_actuator_setpoint=command.setpoint,
        simulation_time_s=post_state.simulation_time_s,
    ).signed(ot_private)
    return RuntimeArtifacts(
        gateway_private=gateway_private,
        plant_private=plant_private,
        observer_private=observer_private,
        candidate_private=candidate_private,
        ot_private=ot_private,
        permit_private=permit_private,
        permit_key_id=base_permit.signing_key_id,
        pre_state=pre_state,
        command=command,
        assessment=assessment,
        request=request,
        pre_observation=pre_observation,
        decision=decision,
        permit=permit,
        dispatch=dispatch,
        envelope=envelope,
        acknowledgment=acknowledgment,
    )


class FakePlant:
    def __init__(self, artifacts: RuntimeArtifacts) -> None:
        self.model_digest = artifacts.pre_state.model_digest
        self.simulator_version = artifacts.pre_state.simulator_version
        self.state = artifacts.pre_state
        self.assessment = artifacts.assessment
        self.capture_calls = 0
        self.simulation_calls = 0
        self.apply_calls = 0

    def read_state(self) -> PhysicalStateSnapshot:
        return self.state

    def capture_state(self) -> PhysicalStateSnapshot:
        self.capture_calls += 1
        return self.state

    def simulate_candidate(
        self,
        command: PhysicalControlCommand,
    ) -> CandidateAssessment:
        assert command.digest == self.assessment.command_digest
        self.simulation_calls += 1
        return self.assessment

    def apply_authorized_command(
        self,
        command: PhysicalControlCommand,
        *,
        expected_pre_state_version: int,
        expected_pre_state_digest: str,
        expected_pre_observation_digest: str,
        expected_post_state_digest: str,
        expected_post_topology_digest: str,
        effect_deadline: datetime,
        effect_clock: Any,
    ) -> PhysicalStateSnapshot:
        assert command.digest == self.assessment.command_digest
        assert expected_pre_state_version == self.state.state_version
        assert expected_pre_state_digest == self.state.state_digest
        assert expected_pre_observation_digest == self.state.observation_digest
        assert expected_post_state_digest == self.assessment.post_state.state_digest
        assert expected_post_topology_digest == self.assessment.post_state.topology_digest
        if effect_clock() >= effect_deadline:
            raise PhysicalSimulationError("authorization_expired_before_effect")
        self.apply_calls += 1
        self.state = self.assessment.post_state
        return self.state


def _trusted_callers(
    artifacts: RuntimeArtifacts,
) -> dict[PlantCallerRole, TrustedPlantCaller]:
    return {
        PlantCallerRole.OBSERVER: TrustedPlantCaller(
            OBSERVER_KEY_ID,
            artifacts.observer_private.public_key(),
        ),
        PlantCallerRole.CANDIDATE: TrustedPlantCaller(
            CANDIDATE_KEY_ID,
            artifacts.candidate_private.public_key(),
        ),
        PlantCallerRole.PLC: TrustedPlantCaller(
            OT_KEY_ID,
            artifacts.ot_private.public_key(),
        ),
    }


def _plant_runtime(
    artifacts: RuntimeArtifacts,
    plant: FakePlant,
    *,
    boot_epoch: str = PLANT_BOOT,
    clock: Any = None,
) -> CapabilityPlantRuntime:
    return CapabilityPlantRuntime(
        plant=cast(Any, plant),
        private_key=artifacts.plant_private,
        key_id=PLANT_KEY_ID,
        trusted_callers=_trusted_callers(artifacts),
        boot_epoch=boot_epoch,
        clock=clock or (lambda: NOW),
    )


def _plant_call(
    *,
    role: PlantCallerRole,
    operation: PlantOperation,
    payload: PlantCapturePayload | PlantReadPayload | PlantApplyPayload,
    caller_key_id: str,
    target_plant_key_id: str,
    target_plant_boot_epoch: str,
    nonce: str,
    private_key: Ed25519PrivateKey,
) -> SignedPlantCall:
    return SignedPlantCall.issue(
        role=role,
        operation=operation,
        payload=payload,
        caller_key_id=caller_key_id,
        target_plant_key_id=target_plant_key_id,
        target_plant_boot_epoch=target_plant_boot_epoch,
        call_nonce=nonce,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        private_key=private_key,
        audience=PHYSICAL_PLANT_AUDIENCE,
    )


def _capture_payload() -> PlantCapturePayload:
    return PlantCapturePayload(
        correlation_id="m4g-runtime-plant-correlation",
        challenge_nonce="m4g-runtime-plant-challenge-0001",
    )


def _apply_payload(artifacts: RuntimeArtifacts) -> PlantApplyPayload:
    base = artifacts.permit.base_permit
    return PlantApplyPayload(
        command=artifacts.command,
        expected_pre_state_version=base.state_version,
        expected_pre_state_digest=base.state_digest,
        expected_pre_observation_digest=base.observation_digest,
        expected_post_state_digest=base.expected_post_state_digest,
        expected_post_topology_digest=base.expected_post_topology_digest,
        authorization_expires_at=base.expires_at,
    )


def test_plant_authenticates_role_key_and_target_before_nonce_reservation(
    artifacts: RuntimeArtifacts,
) -> None:
    plant = FakePlant(artifacts)
    runtime = _plant_runtime(artifacts, plant)
    nonce = "m4g-runtime-shared-auth-nonce-0001"
    invalid_calls = (
        _plant_call(
            role=PlantCallerRole.PLC,
            operation=PlantOperation.READ,
            payload=PlantReadPayload(correlation_id="role-key-spoof"),
            caller_key_id=OT_KEY_ID,
            target_plant_key_id=PLANT_KEY_ID,
            target_plant_boot_epoch=PLANT_BOOT,
            nonce=nonce,
            private_key=artifacts.observer_private,
        ),
        _plant_call(
            role=PlantCallerRole.OBSERVER,
            operation=PlantOperation.CAPTURE,
            payload=_capture_payload(),
            caller_key_id="wrong-observer-key-id",
            target_plant_key_id=PLANT_KEY_ID,
            target_plant_boot_epoch=PLANT_BOOT,
            nonce=nonce,
            private_key=artifacts.observer_private,
        ),
        _plant_call(
            role=PlantCallerRole.OBSERVER,
            operation=PlantOperation.CAPTURE,
            payload=_capture_payload(),
            caller_key_id=OBSERVER_KEY_ID,
            target_plant_key_id="wrong-plant-key-id",
            target_plant_boot_epoch=PLANT_BOOT,
            nonce=nonce,
            private_key=artifacts.observer_private,
        ),
        _plant_call(
            role=PlantCallerRole.OBSERVER,
            operation=PlantOperation.CAPTURE,
            payload=_capture_payload(),
            caller_key_id=OBSERVER_KEY_ID,
            target_plant_key_id=PLANT_KEY_ID,
            target_plant_boot_epoch="old-plant-boot-epoch-0000",
            nonce=nonce,
            private_key=artifacts.observer_private,
        ),
    )

    for call in invalid_calls:
        with pytest.raises(CapabilityAdmissionRejected, match="authentication"):
            runtime.execute(call)
        assert runtime.health().call_reservations == 0
        assert plant.capture_calls == 0
        assert plant.apply_calls == 0

    valid = _plant_call(
        role=PlantCallerRole.OBSERVER,
        operation=PlantOperation.CAPTURE,
        payload=_capture_payload(),
        caller_key_id=OBSERVER_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce=nonce,
        private_key=artifacts.observer_private,
    )
    status, response = runtime.execute(valid)

    assert status == 200
    assert response.verify_for_call(
        artifacts.plant_private.public_key(),
        call=valid,
        expected_plant_boot_epoch=PLANT_BOOT,
        expected_plant_key_id=PLANT_KEY_ID,
    )
    assert runtime.health().call_reservations == 1
    assert plant.capture_calls == 1


def test_plant_exact_apply_replay_returns_exact_cached_terminal_response(
    artifacts: RuntimeArtifacts,
) -> None:
    plant = FakePlant(artifacts)
    runtime = _plant_runtime(artifacts, plant)
    call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=_apply_payload(artifacts),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4g-runtime-plant-apply-nonce-0001",
        private_key=artifacts.ot_private,
    )

    first_status, first = runtime.execute(call)
    replay_status, replay = runtime.execute(call)

    assert first_status == 200
    assert first.status is PlantResponseStatus.OK
    assert replay_status == 200
    assert replay == first
    assert replay.status is PlantResponseStatus.OK
    assert replay.verify_for_call(
        artifacts.plant_private.public_key(),
        call=call,
        expected_plant_boot_epoch=PLANT_BOOT,
        expected_plant_key_id=PLANT_KEY_ID,
    )
    assert plant.apply_calls == 1
    assert runtime.health().apply_requests == 1
    assert runtime.health().commit_count == 1
    assert runtime.health().call_reservations == 1


def test_plant_unknown_first_outcome_cannot_be_replayed_as_known_no_effect(
    artifacts: RuntimeArtifacts,
) -> None:
    class ExplodingPlant(FakePlant):
        def apply_authorized_command(self, *args: Any, **kwargs: Any) -> PhysicalStateSnapshot:
            raise RuntimeError("simulated connection loss after admission")

    plant = ExplodingPlant(artifacts)
    runtime = _plant_runtime(artifacts, plant)
    call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=_apply_payload(artifacts),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4g-runtime-indeterminate-apply-nonce-0001",
        private_key=artifacts.ot_private,
    )

    with pytest.raises(RuntimeError, match="simulated connection loss"):
        runtime.execute(call)
    with pytest.raises(CapabilityRuntimeUnavailable, match="outcome_indeterminate"):
        runtime.execute(call)

    assert runtime.health().apply_requests == 1
    assert runtime.health().commit_count == 0
    assert runtime.health().call_reservations == 1


def test_plant_rechecks_authorization_at_atomic_effect_boundary(
    artifacts: RuntimeArtifacts,
) -> None:
    plant = FakePlant(artifacts)
    expired = artifacts.permit.base_permit.expires_at + timedelta(milliseconds=1)
    clock_values = iter((NOW, NOW, expired, expired))
    runtime = _plant_runtime(
        artifacts,
        plant,
        clock=lambda: next(clock_values),
    )
    call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=_apply_payload(artifacts),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4g-runtime-effect-deadline-nonce-0001",
        private_key=artifacts.ot_private,
    )

    status, response = runtime.execute(call)

    assert status == 409
    assert response.status is PlantResponseStatus.REJECTED
    assert isinstance(response.payload, PlantFailureResponsePayload)
    assert response.payload.reason == "authorization_expired_before_effect"
    assert plant.apply_calls == 0
    assert runtime.health().commit_count == 0


def test_plant_rejects_reused_key_material_even_with_distinct_ids(
    artifacts: RuntimeArtifacts,
) -> None:
    callers = _trusted_callers(artifacts)
    callers[PlantCallerRole.CANDIDATE] = TrustedPlantCaller(
        CANDIDATE_KEY_ID,
        artifacts.observer_private.public_key(),
    )

    with pytest.raises(ValueError, match="key material must be distinct"):
        CapabilityPlantRuntime(
            plant=cast(Any, FakePlant(artifacts)),
            private_key=artifacts.plant_private,
            key_id=PLANT_KEY_ID,
            trusted_callers=callers,
            boot_epoch=PLANT_BOOT,
            clock=lambda: NOW,
        )


def test_restarted_plant_rejects_old_target_boot_before_reservation(
    artifacts: RuntimeArtifacts,
) -> None:
    nonce = "m4g-runtime-restart-call-nonce-0001"
    old_call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=_apply_payload(artifacts),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce=nonce,
        private_key=artifacts.ot_private,
    )
    restarted_plant = FakePlant(artifacts)
    restarted = _plant_runtime(
        artifacts,
        restarted_plant,
        boot_epoch=NEW_PLANT_BOOT,
    )

    with pytest.raises(CapabilityAdmissionRejected, match="authentication"):
        restarted.execute(old_call)
    assert restarted.health().call_reservations == 0
    assert restarted_plant.apply_calls == 0

    current_call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=_apply_payload(artifacts),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=NEW_PLANT_BOOT,
        nonce=nonce,
        private_key=artifacts.ot_private,
    )
    status, _ = restarted.execute(current_call)

    assert status == 200
    assert restarted_plant.apply_calls == 1
    assert restarted.health().call_reservations == 1


class FakeObserverPlant:
    def __init__(self, snapshot: PhysicalStateSnapshot) -> None:
        self.snapshot = snapshot
        self.calls: list[tuple[str, str]] = []

    def capture_bound_state(
        self,
        *,
        correlation_id: str,
        challenge_nonce: str,
    ) -> PhysicalStateSnapshot:
        self.calls.append((correlation_id, challenge_nonce))
        return self.snapshot


def _plant_health(
    artifacts: RuntimeArtifacts,
    *,
    boot_epoch: str = PLANT_BOOT,
) -> PlantHealthMetadata:
    return _plant_runtime(
        artifacts,
        FakePlant(artifacts),
        boot_epoch=boot_epoch,
    ).health()


def test_observer_cache_resolution_and_transaction_predecessor_are_exact(
    artifacts: RuntimeArtifacts,
) -> None:
    plant = FakeObserverPlant(artifacts.pre_state)
    runtime = CapabilityObserverRuntime(
        plant=cast(Any, plant),
        plant_info=_plant_health(artifacts),
        private_key=artifacts.observer_private,
        key_id=OBSERVER_KEY_ID,
        observer_id="observer:m4g-runtime",
        boot_epoch=OBSERVER_BOOT,
        cache_capacity=4,
    )
    pre_request = ObservationCaptureRequest(
        correlation_id="m4g-runtime-observer-transaction",
        challenge_nonce="m4g-runtime-observer-pre-nonce-0001",
    )
    pre = runtime.capture_pre(pre_request)
    plant_calls_after_pre = len(plant.calls)

    resolved = runtime.resolve(
        ObservationResolveRequest(
            observation_id=pre.observation_id,
            envelope_digest=pre.envelope_digest,
        )
    )
    assert resolved == pre
    assert len(plant.calls) == plant_calls_after_pre

    for wrong in (
        ObservationResolveRequest(
            observation_id=pre.observation_id,
            envelope_digest="0" * 64,
        ),
        ObservationResolveRequest(
            observation_id="unknown-observation-id",
            envelope_digest=pre.envelope_digest,
        ),
    ):
        with pytest.raises(CapabilityAdmissionRejected, match="not_found"):
            runtime.resolve(wrong)
    assert len(plant.calls) == plant_calls_after_pre

    invalid_post = PostObservationCaptureRequest(
        correlation_id="different-transaction",
        challenge_nonce="m4g-runtime-observer-post-nonce-0001",
        previous_envelope_digest=pre.envelope_digest,
        permit_id="m4g-runtime-permit-0001",
        command_digest=artifacts.command.digest,
        plc_acknowledgment_digest=artifacts.acknowledgment.digest,
    )
    with pytest.raises(CapabilityAdmissionRejected, match="predecessor"):
        runtime.capture_post(invalid_post)
    assert len(plant.calls) == plant_calls_after_pre
    assert runtime.health().cached_observations == 1

    valid_post = invalid_post.model_copy(
        update={"correlation_id": pre.correlation_id}
    )
    post = runtime.capture_post(valid_post)

    assert post.phase is ObservationPhase.POST_DISPATCH
    assert post.previous_envelope_digest == pre.envelope_digest
    assert post.correlation_id == pre.correlation_id
    assert post.observer_sequence == pre.observer_sequence + 1
    assert len(plant.calls) == plant_calls_after_pre + 1
    assert runtime.health().cached_observations == 2
    assert runtime.health().capture_count == 2


class FakeDevice:
    def __init__(self, artifacts: RuntimeArtifacts) -> None:
        self.acknowledgment_key_id = OT_KEY_ID
        self.plc_id = PLC_ID
        self.boot_epoch = OT_BOOT
        self.acknowledgment_private_key = artifacts.ot_private
        self.scan_counter = 0
        self.calls = 0
        self.acknowledgment = artifacts.acknowledgment

    def execute(self, **_: Any) -> PlcCommandAcknowledgment:
        self.calls += 1
        self.scan_counter += 1
        return self.acknowledgment


def _observer_info(artifacts: RuntimeArtifacts) -> ObserverProcessInfo:
    return ObserverProcessInfo(
        pid=101,
        observer_id=artifacts.pre_observation.observer_id,
        boot_epoch=OBSERVER_BOOT,
        key_id=OBSERVER_KEY_ID,
        public_key_bytes=artifacts.observer_private.public_key().public_bytes_raw(),
        plant_boot_epoch=PLANT_BOOT,
        capabilities={"gateway": ("resolve", "capture_post")},
    )


def test_virtual_plc_carries_permit_deadline_to_effect_capable_plant(
    artifacts: RuntimeArtifacts,
    tmp_path: Path,
) -> None:
    class DeadlinePlant:
        def __init__(self) -> None:
            self.deadline: datetime | None = None

        def read_state(self) -> PhysicalStateSnapshot:
            return artifacts.pre_state

        def simulate_candidate(
            self,
            command: PhysicalControlCommand,
        ) -> CandidateAssessment:
            assert command.digest == artifacts.command.digest
            return artifacts.assessment

        def apply_authorized_command(self, *_: Any, **__: Any) -> PhysicalStateSnapshot:
            raise AssertionError("non-deadline apply path must not be used")

        def apply_authorized_command_with_deadline(
            self,
            command: PhysicalControlCommand,
            **kwargs: Any,
        ) -> PhysicalStateSnapshot:
            assert command.digest == artifacts.command.digest
            self.deadline = cast(datetime, kwargs["authorization_expires_at"])
            return artifacts.assessment.post_state

    plant = DeadlinePlant()
    replay = OrderlyRestartReplayReservations(
        tmp_path / "semantic-replay.json",
        initialize=True,
    )
    device = CapabilityVirtualPlc(
        cast(Any, plant),
        plc_id=PLC_ID,
        boot_epoch=OT_BOOT,
        permit_key_id=artifacts.permit_key_id,
        permit_public_key=artifacts.permit_private.public_key(),
        observer_info=_observer_info(artifacts),
        acknowledgment_private_key=artifacts.ot_private,
        acknowledgment_key_id=OT_KEY_ID,
        replay=replay,
        clock=lambda: NOW,
    )

    acknowledgment = device.execute(
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        decision=artifacts.decision,
        assessment=artifacts.assessment,
    )

    assert acknowledgment.status is CommandStatus.APPLIED
    assert plant.deadline == artifacts.permit.base_permit.expires_at


def test_virtual_plc_rechecks_expiry_after_durable_replay_reservation(
    artifacts: RuntimeArtifacts,
    tmp_path: Path,
) -> None:
    class NoApplyPlant:
        apply_calls = 0

        def read_state(self) -> PhysicalStateSnapshot:
            return artifacts.pre_state

        def simulate_candidate(
            self,
            command: PhysicalControlCommand,
        ) -> CandidateAssessment:
            assert command.digest == artifacts.command.digest
            return artifacts.assessment

        def apply_authorized_command(self, *_: Any, **__: Any) -> PhysicalStateSnapshot:
            self.apply_calls += 1
            return artifacts.assessment.post_state

    plant = NoApplyPlant()
    replay = OrderlyRestartReplayReservations(
        tmp_path / "semantic-replay.json",
        initialize=True,
    )
    clock_values = iter(
        (
            NOW,
            NOW,
            artifacts.permit.base_permit.expires_at,
        )
    )
    device = CapabilityVirtualPlc(
        cast(Any, plant),
        plc_id=PLC_ID,
        boot_epoch=OT_BOOT,
        permit_key_id=artifacts.permit_key_id,
        permit_public_key=artifacts.permit_private.public_key(),
        observer_info=_observer_info(artifacts),
        acknowledgment_private_key=artifacts.ot_private,
        acknowledgment_key_id=OT_KEY_ID,
        replay=replay,
        clock=lambda: next(clock_values),
    )

    acknowledgment = device.execute(
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        decision=artifacts.decision,
        assessment=artifacts.assessment,
    )

    assert acknowledgment.status is CommandStatus.REJECTED
    assert acknowledgment.dispatch_phase is DispatchPhase.PRE_DISPATCH
    assert acknowledgment.reason == "permit_expired_after_replay_reservation"
    assert replay.reservation_count == 1
    assert plant.apply_calls == 0


def _ot_runtime(
    artifacts: RuntimeArtifacts,
    tmp_path: Path,
) -> tuple[CapabilityOtRuntime, FakeDevice, DurableTransportReplayLedger]:
    tmp_path.chmod(0o700)
    transport = DurableTransportReplayLedger(
        tmp_path / "transport-replay.json",
        audience=OT_CAPABILITY_AUDIENCE,
        gateway_key_id=GATEWAY_KEY_ID,
        gateway_public_key_sha256=hashlib.sha256(
            artifacts.gateway_private.public_key().public_bytes_raw()
        ).hexdigest(),
        initialize=True,
    )
    semantic = OrderlyRestartReplayReservations(
        tmp_path / "semantic-replay.json",
        initialize=True,
    )
    device = FakeDevice(artifacts)
    runtime = CapabilityOtRuntime(
        device=cast(Any, device),
        transport_replay=transport,
        gateway_public_key=artifacts.gateway_private.public_key(),
        gateway_key_id=GATEWAY_KEY_ID,
        observer_info=_observer_info(artifacts),
        permit_public_key=artifacts.permit_private.public_key(),
        permit_key_id=artifacts.permit_key_id,
        private_key=artifacts.ot_private,
        key_id=OT_KEY_ID,
        plc_id=PLC_ID,
        boot_epoch=OT_BOOT,
        plant_info=_plant_health(artifacts),
        semantic_replay=semantic,
        clock=lambda: NOW,
    )
    return runtime, device, transport


def _signed_dispatch(
    artifacts: RuntimeArtifacts,
    dispatch: SegmentedCapabilityDispatch,
    *,
    nonce: str,
) -> SignedSegmentedCapabilityDispatch:
    return SignedSegmentedCapabilityDispatch.issue(
        dispatch=dispatch,
        gateway_key_id=GATEWAY_KEY_ID,
        transport_nonce=nonce,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        private_key=artifacts.gateway_private,
        audience=OT_CAPABILITY_AUDIENCE,
    )


@pytest.mark.parametrize("invalid_layer", ["outer", "observer", "permit"])
def test_ot_invalid_outer_or_inner_auth_does_not_reserve_or_poison_nonce(
    artifacts: RuntimeArtifacts,
    tmp_path: Path,
    invalid_layer: str,
) -> None:
    runtime, device, replay = _ot_runtime(artifacts, tmp_path)
    nonce = f"m4g-runtime-{invalid_layer}-nonce-0001"
    if invalid_layer == "outer":
        invalid = _signed_dispatch(artifacts, artifacts.dispatch, nonce=nonce).model_copy(
            update={"signature": "tampered-signature"}
        )
    elif invalid_layer == "observer":
        invalid_observation = artifacts.pre_observation.model_copy(
            update={"signature": "tampered-observer-signature"}
        )
        invalid_dispatch = artifacts.dispatch.model_copy(
            update={"pre_observation": invalid_observation}
        )
        invalid = _signed_dispatch(artifacts, invalid_dispatch, nonce=nonce)
    else:
        invalid_permit = artifacts.permit.model_copy(
            update={"signature": "tampered-permit-signature"}
        )
        invalid_dispatch = artifacts.dispatch.model_copy(
            update={"permit": invalid_permit}
        )
        invalid = _signed_dispatch(artifacts, invalid_dispatch, nonce=nonce)

    with pytest.raises(CapabilityAdmissionRejected, match="authentication"):
        runtime.execute(invalid)
    assert replay.reservation_count == 0
    assert device.calls == 0
    assert runtime.health().execute_requests == 0

    valid = _signed_dispatch(artifacts, artifacts.dispatch, nonce=nonce)
    response = runtime.execute(valid)

    assert response.request_sha256 == valid.digest
    assert replay.reservation_count == 1
    assert device.calls == 1


def test_ot_exact_outer_replay_never_invokes_device_twice(
    artifacts: RuntimeArtifacts,
    tmp_path: Path,
) -> None:
    runtime, device, replay = _ot_runtime(artifacts, tmp_path)

    response = runtime.execute(artifacts.envelope)
    with pytest.raises(CapabilityAdmissionRejected, match="transport_request_replayed"):
        runtime.execute(artifacts.envelope)

    assert response.request_sha256 == artifacts.envelope.digest
    assert response.verify_for_request(
        artifacts.ot_private.public_key(),
        request=artifacts.envelope,
        expected_ot_key_id=OT_KEY_ID,
    )
    assert device.calls == 1
    assert runtime.health().execute_requests == 1
    assert replay.reservation_count == 1


def test_gateway_serializes_capture_flood_behind_active_action(
    artifacts: RuntimeArtifacts,
) -> None:
    entered = Event()
    release = Event()
    capture_started = Event()
    captured = Event()
    action_errors: list[Exception] = []

    class BlockingController:
        def execute(self, _: CapabilityActionRequest) -> object:
            entered.set()
            assert release.wait(timeout=2)
            return object()

    class RecordingObserver:
        def capture_pre(self, **_: str) -> SignedObservationEnvelope:
            captured.set()
            return artifacts.pre_observation

    runtime = CapabilityGatewayRuntime(
        authorization=cast(Any, object()),
        controller=cast(Any, BlockingController()),
        observer=cast(Any, RecordingObserver()),
        discovery=cast(Any, object()),
        gateway_key_id=GATEWAY_KEY_ID,
    )

    def run_action() -> None:
        try:
            runtime.execute(artifacts.request)
        except RuntimeError as exc:  # expected invalid sentinel result
            action_errors.append(exc)

    def run_capture() -> None:
        capture_started.set()
        runtime.capture_pre(
            ObservationCaptureRequest(
                correlation_id="m4g-runtime-concurrent-capture",
                challenge_nonce="m4g-runtime-concurrent-challenge-0001",
            )
        )

    action_thread = Thread(target=run_action)
    capture_thread = Thread(target=run_capture)
    action_thread.start()
    assert entered.wait(timeout=2)
    capture_thread.start()
    assert capture_started.wait(timeout=2)
    assert not captured.wait(timeout=0.05)

    release.set()
    action_thread.join(timeout=2)
    capture_thread.join(timeout=2)

    assert captured.is_set()
    assert not action_thread.is_alive()
    assert not capture_thread.is_alive()
    assert len(action_errors) == 1
    assert isinstance(action_errors[0], RuntimeError)


class ExplodingRuntime:
    def execute(self, _: Any) -> None:
        raise RuntimeError("sensitive backend detail")


def test_consequential_app_5xx_is_closed_ambiguous_failure_shape(
    artifacts: RuntimeArtifacts,
) -> None:
    plant_call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=_apply_payload(artifacts),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4g-runtime-app-failure-nonce-0001",
        private_key=artifacts.ot_private,
    )
    cases = (
        (
            create_plant_app(lambda: cast(Any, ExplodingRuntime())),
            "/v1/plant/call",
            plant_call,
            "plant_outcome_unavailable",
        ),
        (
            create_ot_app(lambda: cast(Any, ExplodingRuntime())),
            "/v1/capability/execute",
            artifacts.envelope,
            "ot_outcome_unavailable",
        ),
    )

    for app, path, payload, expected_reason in cases:
        response = TestClient(app).post(
            path,
            content=payload.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        body = TransportFailureBody.model_validate_json(response.content)

        assert response.status_code == 503
        assert body.status == "error"
        assert body.reason == expected_reason
        assert set(body.model_dump()) == {"schema_version", "status", "reason"}
        assert "sensitive" not in response.text
