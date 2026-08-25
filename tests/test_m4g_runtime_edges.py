from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_m4g_runtime import (
    CANDIDATE_KEY_ID,
    GATEWAY_KEY_ID,
    NOW,
    OBSERVER_BOOT,
    OBSERVER_KEY_ID,
    OT_BOOT,
    OT_KEY_ID,
    PLANT_BOOT,
    PLANT_KEY_ID,
    PLC_ID,
    FakeDevice,
    FakeObserverPlant,
    FakePlant,
    RuntimeArtifacts,
    _apply_payload,
    _observer_info,
    _plant_call,
    _plant_health,
    _plant_runtime,
    _trusted_callers,
)
from test_m4g_runtime import (
    artifacts as _runtime_artifacts_fixture,
)

import aegis_ot.segmented_capability_runtime as runtime_module
from aegis_ot.capability_models import (
    CapabilityClosedLoopStatus,
    ObservationPhase,
    SignedObservationEnvelope,
)
from aegis_ot.capability_plc import OrderlyRestartReplayReservations
from aegis_ot.evidence import EvidenceChain
from aegis_ot.pandapower_plant import PhysicalSimulationError
from aegis_ot.segmented_capability_models import (
    OT_CAPABILITY_AUDIENCE,
    PHYSICAL_PLANT_AUDIENCE,
    PlantCallerRole,
    PlantExchange,
    PlantFailureResponsePayload,
    PlantOperation,
    PlantReadPayload,
    PlantResponseStatus,
    PlantSimulatePayload,
    PlantSimulationResponsePayload,
    SegmentedCapabilityClosedLoopResult,
    SignedPlantCall,
    SignedPlantResponse,
    SignedSegmentedCapabilityResponse,
)
from aegis_ot.segmented_capability_runtime import (
    CandidateSimulationRequest,
    CapabilityAdmissionRejected,
    CapabilityCandidateRuntime,
    CapabilityGatewayRuntime,
    CapabilityObserverRuntime,
    CapabilityOtRuntime,
    CapabilityPlantRuntime,
    CapabilityRuntimeUnavailable,
    ObservationCaptureRequest,
    ObservationResolveRequest,
    PostObservationCaptureRequest,
    SegmentedCapabilityController,
    TrustedPlantCaller,
    create_candidate_app,
    create_gateway_app,
    create_observer_app,
    create_ot_app,
    create_plant_app,
)
from aegis_ot.segmented_capability_transport import (
    CandidateHealthMetadata,
    ObserverHealthMetadata,
    OtHealthMetadata,
    SegmentedCapabilityDiscovery,
    TransportFailureBody,
)
from aegis_ot.transport_replay import (
    DurableTransportReplayLedger,
    TransportReplayLedgerError,
)


@pytest.fixture(scope="module")
def artifacts() -> RuntimeArtifacts:
    factory = cast(
        Callable[[], RuntimeArtifacts],
        _runtime_artifacts_fixture.__wrapped__,
    )
    return factory()


def _b64_public(private_key: Ed25519PrivateKey) -> str:
    return base64.urlsafe_b64encode(
        private_key.public_key().public_bytes_raw()
    ).decode("ascii")


def _health_bundle(artifacts: RuntimeArtifacts) -> SegmentedCapabilityDiscovery:
    plant = _plant_health(artifacts)
    observer = ObserverHealthMetadata(
        pid=1101,
        observer_id=artifacts.pre_observation.observer_id,
        boot_epoch=OBSERVER_BOOT,
        key_id=OBSERVER_KEY_ID,
        public_key_b64=_b64_public(artifacts.observer_private),
        plant_boot_epoch=plant.boot_epoch,
        plant_model_digest=plant.model_digest,
        capture_count=0,
        resolve_count=0,
        cached_observations=0,
    )
    candidate = CandidateHealthMetadata(
        pid=1102,
        boot_epoch="m4g-runtime-candidate-boot-0001",
        key_id=CANDIDATE_KEY_ID,
        public_key_b64=_b64_public(artifacts.candidate_private),
        plant_boot_epoch=plant.boot_epoch,
        plant_model_digest=plant.model_digest,
        simulation_count=0,
    )
    ot = OtHealthMetadata(
        pid=1103,
        plc_id=PLC_ID,
        boot_epoch=OT_BOOT,
        key_id=OT_KEY_ID,
        public_key_b64=_b64_public(artifacts.ot_private),
        gateway_key_id=GATEWAY_KEY_ID,
        gateway_public_key_b64=_b64_public(artifacts.gateway_private),
        permit_key_id=artifacts.permit_key_id,
        permit_public_key_b64=_b64_public(artifacts.permit_private),
        plant_boot_epoch=plant.boot_epoch,
        plant_model_digest=plant.model_digest,
        plant=plant,
        observer_boot_epoch=observer.boot_epoch,
        transport_replay_reservations=0,
        semantic_replay_reservations=0,
        execute_requests=0,
        scan_counter=0,
    )
    return SegmentedCapabilityDiscovery(
        plant=plant,
        observer=observer,
        candidate=candidate,
        ot=ot,
    )


def _candidate_exchange(artifacts: RuntimeArtifacts) -> PlantExchange:
    call = SignedPlantCall.issue(
        role=PlantCallerRole.CANDIDATE,
        operation=PlantOperation.SIMULATE,
        payload=PlantSimulatePayload(command=artifacts.command),
        caller_key_id=CANDIDATE_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        call_nonce="m4g-runtime-edge-candidate-call-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        private_key=artifacts.candidate_private,
        audience=PHYSICAL_PLANT_AUDIENCE,
    )
    response = SignedPlantResponse.issue(
        call=call,
        status=PlantResponseStatus.OK,
        payload=PlantSimulationResponsePayload(assessment=artifacts.assessment),
        plant_boot_epoch=PLANT_BOOT,
        plant_key_id=PLANT_KEY_ID,
        signed_at=NOW,
        private_key=artifacts.plant_private,
    )
    return PlantExchange(call=call, response=response)


def _candidate_rejected_result(
    artifacts: RuntimeArtifacts,
) -> SegmentedCapabilityClosedLoopResult:
    controller = object.__new__(SegmentedCapabilityController)
    controller.simulator = cast(Any, SimpleNamespace(last_exchange=_candidate_exchange(artifacts)))
    controller.evidence = EvidenceChain()
    result = controller._record(
        status=CapabilityClosedLoopStatus.CANDIDATE_REJECTED,
        reasons=("candidate_rejected_by_test_boundary",),
        request=artifacts.request,
        dispatch_attempts=0,
        pre_observation=artifacts.pre_observation,
        decision=artifacts.decision,
        command=artifacts.command,
        assessment=artifacts.assessment,
    )
    return cast(SegmentedCapabilityClosedLoopResult, result)


def _valid_ot_runtime(
    artifacts: RuntimeArtifacts,
    *,
    device: Any | None = None,
    transport: Any | None = None,
    semantic: Any | None = None,
) -> CapabilityOtRuntime:
    count_state = SimpleNamespace(reservation_count=0)
    return CapabilityOtRuntime(
        device=cast(Any, device or FakeDevice(artifacts)),
        transport_replay=cast(Any, transport or count_state),
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
        semantic_replay=cast(Any, semantic or count_state),
        clock=lambda: NOW,
    )


def _write_key_pair(
    directory: Path,
    name: str,
    private_key: Ed25519PrivateKey,
) -> tuple[Path, Path]:
    private_path = directory / f"{name}.private.raw"
    public_path = directory / f"{name}.public.raw"
    private_path.write_bytes(private_key.private_bytes_raw())
    public_path.write_bytes(private_key.public_key().public_bytes_raw())
    return private_path, public_path


def _configure_runtime_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> dict[str, Path]:
    monkeypatch.setenv("AEGIS_WORKLOAD_IDENTITY_MODE", "disabled")
    roles = {
        "PLANT": (PLANT_KEY_ID, artifacts.plant_private),
        "OBSERVER": (OBSERVER_KEY_ID, artifacts.observer_private),
        "CANDIDATE": (CANDIDATE_KEY_ID, artifacts.candidate_private),
        "OT": (OT_KEY_ID, artifacts.ot_private),
        "GATEWAY": (GATEWAY_KEY_ID, artifacts.gateway_private),
        "PERMIT": (artifacts.permit_key_id, artifacts.permit_private),
    }
    paths: dict[str, Path] = {}
    for role, (key_id, private_key) in roles.items():
        private_path, public_path = _write_key_pair(tmp_path, role.lower(), private_key)
        monkeypatch.setenv(f"AEGIS_{role}_KEY_ID", key_id)
        monkeypatch.setenv(f"AEGIS_{role}_PRIVATE_KEY_FILE", str(private_path))
        monkeypatch.setenv(f"AEGIS_{role}_PUBLIC_KEY_FILE", str(public_path))
        paths[f"{role}_PRIVATE"] = private_path
        paths[f"{role}_PUBLIC"] = public_path

    for role in ("PLANT", "OBSERVER", "CANDIDATE", "OT"):
        monkeypatch.setenv(f"AEGIS_{role}_URL", f"http://{role.lower()}:8080")
    semantic_path = tmp_path / "semantic-replay.json"
    transport_path = tmp_path / "transport-replay.json"
    monkeypatch.setenv("AEGIS_SEMANTIC_REPLAY_LEDGER_FILE", str(semantic_path))
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_LEDGER_FILE", str(transport_path))
    paths["SEMANTIC"] = semantic_path
    paths["TRANSPORT"] = transport_path
    return paths


def _failure_body(response: Any) -> TransportFailureBody:
    return TransportFailureBody.model_validate_json(response.content)


def test_runtime_constructors_reject_collapsed_trust_roles(
    artifacts: RuntimeArtifacts,
) -> None:
    plant = cast(Any, FakePlant(artifacts))
    callers = _trusted_callers(artifacts)
    missing = dict(callers)
    missing.pop(PlantCallerRole.CANDIDATE)
    with pytest.raises(ValueError, match="define observer, candidate, and PLC"):
        CapabilityPlantRuntime(
            plant=plant,
            private_key=artifacts.plant_private,
            key_id=PLANT_KEY_ID,
            trusted_callers=missing,
        )

    duplicate_ids = dict(callers)
    duplicate_ids[PlantCallerRole.CANDIDATE] = TrustedPlantCaller(
        OBSERVER_KEY_ID,
        artifacts.candidate_private.public_key(),
    )
    with pytest.raises(ValueError, match="key IDs must be distinct"):
        CapabilityPlantRuntime(
            plant=plant,
            private_key=artifacts.plant_private,
            key_id=PLANT_KEY_ID,
            trusted_callers=duplicate_ids,
        )

    plant_info = _plant_health(artifacts)
    observer_plant = cast(Any, FakeObserverPlant(artifacts.pre_state))
    with pytest.raises(ValueError, match="cache capacity"):
        CapabilityObserverRuntime(
            plant=observer_plant,
            plant_info=plant_info,
            private_key=artifacts.observer_private,
            key_id=OBSERVER_KEY_ID,
            cache_capacity=0,
        )
    with pytest.raises(ValueError, match="observer and plant"):
        CapabilityObserverRuntime(
            plant=observer_plant,
            plant_info=plant_info,
            private_key=artifacts.plant_private,
            key_id=OBSERVER_KEY_ID,
        )
    with pytest.raises(ValueError, match="candidate and plant"):
        CapabilityCandidateRuntime(
            plant=cast(Any, object()),
            plant_info=plant_info,
            private_key=artifacts.candidate_private,
            key_id=PLANT_KEY_ID,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("device_identity", "identity does not match"),
        ("device_boot", "boot epoch does not match"),
        ("device_key", "response key does not match"),
        ("duplicate_id", "key IDs must be distinct"),
        ("duplicate_material", "key material must be distinct"),
    ),
)
def test_ot_constructor_refuses_identity_and_key_role_collapse(
    artifacts: RuntimeArtifacts,
    mutation: str,
    message: str,
) -> None:
    device = FakeDevice(artifacts)
    gateway_public = artifacts.gateway_private.public_key()
    gateway_key_id = GATEWAY_KEY_ID
    if mutation == "device_identity":
        device.plc_id = "different-plc"
    elif mutation == "device_boot":
        device.boot_epoch = "different-ot-boot-0001"
    elif mutation == "device_key":
        device.acknowledgment_private_key = Ed25519PrivateKey.generate()
    elif mutation == "duplicate_id":
        gateway_key_id = OT_KEY_ID
    else:
        gateway_public = artifacts.ot_private.public_key()

    with pytest.raises(ValueError, match=message):
        CapabilityOtRuntime(
            device=cast(Any, device),
            transport_replay=cast(Any, SimpleNamespace(reservation_count=0)),
            gateway_public_key=gateway_public,
            gateway_key_id=gateway_key_id,
            observer_info=_observer_info(artifacts),
            permit_public_key=artifacts.permit_private.public_key(),
            permit_key_id=artifacts.permit_key_id,
            private_key=artifacts.ot_private,
            key_id=OT_KEY_ID,
            plc_id=PLC_ID,
            boot_epoch=OT_BOOT,
            plant_info=_plant_health(artifacts),
            semantic_replay=cast(Any, SimpleNamespace(reservation_count=0)),
        )


def test_plant_read_simulate_expiry_and_signed_physics_rejection(
    artifacts: RuntimeArtifacts,
) -> None:
    plant = FakePlant(artifacts)
    runtime = _plant_runtime(artifacts, plant)
    read = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.READ,
        payload=PlantReadPayload(correlation_id="m4g-edge-read"),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4g-runtime-edge-read-nonce-0001",
        private_key=artifacts.ot_private,
    )
    simulate = SignedPlantCall.issue(
        role=PlantCallerRole.CANDIDATE,
        operation=PlantOperation.SIMULATE,
        payload=PlantSimulatePayload(command=artifacts.command),
        caller_key_id=CANDIDATE_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        call_nonce="m4g-runtime-edge-simulate-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        private_key=artifacts.candidate_private,
    )

    read_status, read_response = runtime.execute(read)
    simulate_status, simulate_response = runtime.execute(simulate)

    assert read_status == simulate_status == 200
    assert read_response.operation is PlantOperation.READ
    assert isinstance(simulate_response.payload, PlantSimulationResponsePayload)
    assert simulate_response.payload.assessment == artifacts.assessment
    assert plant.simulation_calls == 1

    clock_values = iter((NOW, NOW + timedelta(seconds=11)))
    expiring_runtime = _plant_runtime(
        artifacts,
        FakePlant(artifacts),
        clock=lambda: next(clock_values),
    )
    with pytest.raises(CapabilityRuntimeUnavailable, match="expired_before_effect"):
        expiring_runtime.execute(
            SignedPlantCall.issue(
                role=PlantCallerRole.PLC,
                operation=PlantOperation.READ,
                payload=PlantReadPayload(correlation_id="m4g-edge-expired-read"),
                caller_key_id=OT_KEY_ID,
                target_plant_key_id=PLANT_KEY_ID,
                target_plant_boot_epoch=PLANT_BOOT,
                call_nonce="m4g-runtime-edge-expired-nonce-0001",
                issued_at=NOW,
                expires_at=NOW + timedelta(seconds=10),
                private_key=artifacts.ot_private,
            )
        )

    class RejectingSimulationPlant(FakePlant):
        def simulate_candidate(self, command: Any) -> Any:
            raise PhysicalSimulationError("candidate violates physical invariant")

    rejecting_runtime = _plant_runtime(
        artifacts,
        RejectingSimulationPlant(artifacts),
    )
    rejecting_call = SignedPlantCall.issue(
        role=PlantCallerRole.CANDIDATE,
        operation=PlantOperation.SIMULATE,
        payload=PlantSimulatePayload(command=artifacts.command),
        caller_key_id=CANDIDATE_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        call_nonce="m4g-runtime-edge-rejected-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        private_key=artifacts.candidate_private,
    )
    status, rejection = rejecting_runtime.execute(rejecting_call)
    assert status == 409
    assert rejection.status is PlantResponseStatus.REJECTED
    assert "physical invariant" in rejection.payload.reason


def test_plant_signs_known_rejection_when_authorization_expires_at_boundary(
    artifacts: RuntimeArtifacts,
) -> None:
    runtime = _plant_runtime(artifacts, FakePlant(artifacts))
    expired_payload = _apply_payload(artifacts).model_copy(
        update={"authorization_expires_at": NOW}
    )
    call = SignedPlantCall.issue(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=expired_payload,
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        call_nonce="m4g-runtime-edge-authorization-expired-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        private_key=artifacts.ot_private,
    )

    status, response = runtime.execute(call)

    assert status == 409
    assert response.status is PlantResponseStatus.REJECTED
    assert response.payload.reason == "authorization_expired_before_effect"
    assert response.verify_for_call(
        artifacts.plant_private.public_key(),
        call=call,
        expected_plant_boot_epoch=PLANT_BOOT,
        expected_plant_key_id=PLANT_KEY_ID,
    )
    assert runtime.health().apply_requests == 1
    assert runtime.health().commit_count == 0


def test_observer_bounded_cache_evicts_old_entries_without_remote_resolve(
    artifacts: RuntimeArtifacts,
) -> None:
    plant = FakeObserverPlant(artifacts.pre_state)
    runtime = CapabilityObserverRuntime(
        plant=cast(Any, plant),
        plant_info=_plant_health(artifacts),
        private_key=artifacts.observer_private,
        key_id=OBSERVER_KEY_ID,
        observer_id=artifacts.pre_observation.observer_id,
        boot_epoch=OBSERVER_BOOT,
        cache_capacity=1,
    )
    first = runtime.capture_pre(
        ObservationCaptureRequest(
            correlation_id="m4g-edge-cache-first",
            challenge_nonce="m4g-edge-cache-first-nonce-0001",
        )
    )
    second = runtime.capture_pre(
        ObservationCaptureRequest(
            correlation_id="m4g-edge-cache-second",
            challenge_nonce="m4g-edge-cache-second-nonce-0001",
        )
    )

    with pytest.raises(CapabilityAdmissionRejected, match="not_found"):
        runtime.resolve(
            ObservationResolveRequest(
                observation_id=first.observation_id,
                envelope_digest=first.envelope_digest,
            )
        )
    assert runtime.resolve(
        ObservationResolveRequest(
            observation_id=second.observation_id,
            envelope_digest=second.envelope_digest,
        )
    ) == second
    health = runtime.health()
    assert health.capture_count == 2
    assert health.resolve_count == 2
    assert health.cached_observations == 1
    assert len(plant.calls) == 2


def test_candidate_runtime_preserves_exchange_and_counts_success_only(
    artifacts: RuntimeArtifacts,
) -> None:
    exchange = _candidate_exchange(artifacts)

    class CandidatePlant:
        def __init__(self) -> None:
            self.calls = 0

        def simulate_exchange(self, command: Any) -> PlantExchange:
            assert command == artifacts.command
            self.calls += 1
            return exchange

    plant = CandidatePlant()
    runtime = CapabilityCandidateRuntime(
        plant=cast(Any, plant),
        plant_info=_plant_health(artifacts),
        private_key=artifacts.candidate_private,
        key_id=CANDIDATE_KEY_ID,
        boot_epoch="m4g-runtime-candidate-boot-0001",
    )

    assert runtime.health().simulation_count == 0
    assert runtime.simulate(
        CandidateSimulationRequest(command=artifacts.command)
    ) == exchange
    assert runtime.health().simulation_count == 1
    assert plant.calls == 1


def test_ot_replay_state_and_semantic_failures_remain_closed(
    artifacts: RuntimeArtifacts,
) -> None:
    class BrokenCount:
        @property
        def reservation_count(self) -> int:
            raise TransportReplayLedgerError("corrupt replay state detail")

    health_runtime = _valid_ot_runtime(artifacts, transport=BrokenCount())
    with pytest.raises(CapabilityRuntimeUnavailable, match="replay state is unavailable"):
        health_runtime.health()

    class BrokenReserve:
        reservation_count = 0

        def reserve(self, *_: Any) -> bool:
            raise TransportReplayLedgerError("disk error detail")

    reserve_device = FakeDevice(artifacts)
    reserve_runtime = _valid_ot_runtime(
        artifacts,
        device=reserve_device,
        transport=BrokenReserve(),
    )
    with pytest.raises(CapabilityRuntimeUnavailable, match="transport replay state"):
        reserve_runtime.execute(artifacts.envelope)
    assert reserve_device.calls == 0
    assert reserve_runtime.execute_requests == 0

    class AcceptingReplay:
        reservation_count = 0

        def reserve(self, *_: Any) -> bool:
            return True

    semantic_device = FakeDevice(artifacts)

    def fail_semantic(**_: Any) -> Any:
        raise ValueError("semantic ledger writer unavailable")

    semantic_device.execute = fail_semantic
    semantic_runtime = _valid_ot_runtime(
        artifacts,
        device=semantic_device,
        transport=AcceptingReplay(),
    )
    with pytest.raises(CapabilityRuntimeUnavailable, match="semantic replay state"):
        semantic_runtime.execute(artifacts.envelope)
    assert semantic_runtime.execute_requests == 1


def test_controller_retains_only_the_exact_signed_candidate_exchange(
    artifacts: RuntimeArtifacts,
) -> None:
    controller = object.__new__(SegmentedCapabilityController)
    exchange = _candidate_exchange(artifacts)
    controller.simulator = cast(Any, SimpleNamespace(last_exchange=exchange))
    controller.evidence = EvidenceChain()

    result = controller._record(
        status=CapabilityClosedLoopStatus.CANDIDATE_REJECTED,
        reasons=("candidate_rejected_by_test_boundary",),
        request=artifacts.request,
        dispatch_attempts=0,
        pre_observation=artifacts.pre_observation,
        decision=artifacts.decision,
        command=artifacts.command,
        assessment=artifacts.assessment,
    )

    segmented = cast(SegmentedCapabilityClosedLoopResult, result)
    assert segmented.candidate_exchange == exchange
    assert controller.evidence.records[0].payload["candidate_exchange"] == (
        exchange.model_dump(mode="json")
    )

    mismatched = artifacts.assessment.model_copy(
        update={"assessment_id": "different-assessment-id"}
    )
    with pytest.raises(ValueError, match="exact candidate exchange"):
        controller._record(
            status=CapabilityClosedLoopStatus.CANDIDATE_REJECTED,
            reasons=("mismatched_candidate_exchange",),
            request=artifacts.request,
            dispatch_attempts=0,
            assessment=mismatched,
        )


def test_gateway_runtime_exposes_only_pinned_health_and_typed_results(
    artifacts: RuntimeArtifacts,
) -> None:
    discovery = _health_bundle(artifacts)
    result = _candidate_rejected_result(artifacts)

    class Observer:
        def capture_pre(self, **kwargs: str) -> SignedObservationEnvelope:
            assert kwargs == {
                "correlation_id": "m4g-edge-gateway-correlation",
                "challenge_nonce": "m4g-edge-gateway-challenge-0001",
            }
            return artifacts.pre_observation

    runtime = CapabilityGatewayRuntime(
        authorization=cast(
            Any,
            SimpleNamespace(gateway=SimpleNamespace(evidence=EvidenceChain())),
        ),
        controller=cast(Any, SimpleNamespace(execute=lambda _: result)),
        observer=cast(Any, Observer()),
        discovery=discovery,
        gateway_key_id=GATEWAY_KEY_ID,
    )

    captured = runtime.capture_pre(
        ObservationCaptureRequest(
            correlation_id="m4g-edge-gateway-correlation",
            challenge_nonce="m4g-edge-gateway-challenge-0001",
        )
    )
    assert captured == artifacts.pre_observation
    assert runtime.execute(artifacts.request) == result
    health = runtime.health()
    assert health["status"] == "ready"
    assert health["plant_boot_epoch"] == PLANT_BOOT
    assert health["observer_boot_epoch"] == OBSERVER_BOOT
    assert health["ot_boot_epoch"] == OT_BOOT
    assert health["evidence_records"] == 0


def test_lazy_provider_retries_failed_initialization_and_then_caches() -> None:
    sentinel = object()
    attempts = 0

    def factory() -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise CapabilityRuntimeUnavailable("dependency not ready")
        return sentinel

    provider = runtime_module._LazyProvider(factory)
    with pytest.raises(CapabilityRuntimeUnavailable, match="not ready"):
        provider()
    assert provider() is sentinel
    assert provider() is sentinel
    assert attempts == 2


def test_environment_key_loading_and_pin_failures_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    private_path, public_path = _write_key_pair(tmp_path, "exact", key)
    assert runtime_module._load_private_key(str(private_path)).private_bytes_raw() == (
        key.private_bytes_raw()
    )
    assert runtime_module._load_public_key(str(public_path)).public_bytes_raw() == (
        key.public_key().public_bytes_raw()
    )

    with pytest.raises(CapabilityRuntimeUnavailable, match="unavailable"):
        runtime_module._read_exact_key(str(tmp_path / "missing.raw"))
    short = tmp_path / "short.raw"
    short.write_bytes(b"short")
    with pytest.raises(CapabilityRuntimeUnavailable, match="exactly 32"):
        runtime_module._read_exact_key(str(short))

    monkeypatch.delenv("AEGIS_EDGE_REQUIRED", raising=False)
    with pytest.raises(CapabilityRuntimeUnavailable, match="AEGIS_EDGE_REQUIRED"):
        runtime_module._expected_environment("AEGIS_EDGE_REQUIRED")
    monkeypatch.setenv("AEGIS_EDGE_REQUIRED", "configured")
    assert runtime_module._expected_environment("AEGIS_EDGE_REQUIRED") == "configured"

    with pytest.raises(CapabilityRuntimeUnavailable, match="trust pin"):
        runtime_module._require_pin(
            label="observer",
            actual_key_id="actual",
            actual_public_key=key.public_key(),
            expected_key_id="expected",
            expected_public_key=key.public_key(),
        )


def test_build_helpers_wire_one_consistent_pinned_capability_stack(
    artifacts: RuntimeArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    paths = _configure_runtime_environment(monkeypatch, tmp_path, artifacts)

    plant_runtime = runtime_module._build_plant_runtime()
    plant_health = plant_runtime.health()
    assert plant_health.key_id == PLANT_KEY_ID
    assert plant_health.call_reservations == 0

    monkeypatch.setattr(runtime_module, "fetch_plant_health", lambda _: plant_health)
    observer_runtime = runtime_module._build_observer_runtime()
    observer_health = observer_runtime.health()
    candidate_runtime = runtime_module._build_candidate_runtime()
    candidate_health = candidate_runtime.health()
    assert observer_health.plant_boot_epoch == plant_health.boot_epoch
    assert candidate_health.plant_model_digest == plant_health.model_digest

    monkeypatch.setattr(
        runtime_module,
        "fetch_observer_health",
        lambda _: observer_health,
    )
    semantic = OrderlyRestartReplayReservations(paths["SEMANTIC"], initialize=True)
    semantic.close()
    transport = DurableTransportReplayLedger(
        paths["TRANSPORT"],
        audience=OT_CAPABILITY_AUDIENCE,
        gateway_key_id=GATEWAY_KEY_ID,
        gateway_public_key_sha256=hashlib.sha256(
            artifacts.gateway_private.public_key().public_bytes_raw()
        ).hexdigest(),
        initialize=True,
    )
    transport.close()

    ot_runtime = runtime_module._build_ot_runtime()
    try:
        ot_health = ot_runtime.health()
        assert ot_health.plant == plant_health
        assert ot_health.observer_boot_epoch == observer_health.boot_epoch

        discovery = SegmentedCapabilityDiscovery(
            plant=plant_health,
            observer=observer_health,
            candidate=candidate_health,
            ot=ot_health,
        )
        monkeypatch.setattr(
            runtime_module,
            "discover_segmented_capabilities_via_ot",
            lambda **_: discovery,
        )
        gateway_runtime = runtime_module._build_gateway_runtime()
        gateway_health = gateway_runtime.health()
        assert gateway_health["status"] == "ready"
        assert gateway_health["gateway_key_id"] == GATEWAY_KEY_ID
        assert gateway_runtime.discovery == discovery
        assert gateway_runtime.controller.simulator.plant == discovery.plant
    finally:
        ot_runtime.transport_replay.close()
        ot_runtime.semantic_replay.close()


def test_ot_and_gateway_builders_fail_closed_on_discovery_key_mismatch(
    artifacts: RuntimeArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_runtime_environment(monkeypatch, tmp_path, artifacts)
    discovery = _health_bundle(artifacts)
    inconsistent_observer = discovery.observer.model_copy(
        update={"plant_boot_epoch": "different-plant-boot-0001"}
    )
    monkeypatch.setattr(runtime_module, "fetch_plant_health", lambda _: discovery.plant)
    monkeypatch.setattr(
        runtime_module,
        "fetch_observer_health",
        lambda _: inconsistent_observer,
    )
    with pytest.raises(CapabilityRuntimeUnavailable, match="inconsistent"):
        runtime_module._build_ot_runtime()

    monkeypatch.setattr(
        runtime_module,
        "discover_segmented_capabilities_via_ot",
        lambda **_: discovery,
    )
    monkeypatch.setenv("AEGIS_PERMIT_KEY_ID", "different-permit-key-id")
    with pytest.raises(CapabilityRuntimeUnavailable, match="permit key ID"):
        runtime_module._build_gateway_runtime()


def test_gateway_builder_requires_private_keys_to_match_ot_pins(
    artifacts: RuntimeArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _configure_runtime_environment(monkeypatch, tmp_path, artifacts)
    discovery = _health_bundle(artifacts)
    monkeypatch.setattr(
        runtime_module,
        "discover_segmented_capabilities_via_ot",
        lambda **_: discovery,
    )
    rogue = Ed25519PrivateKey.generate()
    rogue_private, _ = _write_key_pair(tmp_path, "rogue", rogue)

    monkeypatch.setenv("AEGIS_GATEWAY_PRIVATE_KEY_FILE", str(rogue_private))
    with pytest.raises(CapabilityRuntimeUnavailable, match="gateway private key"):
        runtime_module._build_gateway_runtime()

    monkeypatch.setenv("AEGIS_GATEWAY_PRIVATE_KEY_FILE", str(paths["GATEWAY_PRIVATE"]))
    monkeypatch.setenv("AEGIS_PERMIT_PRIVATE_KEY_FILE", str(rogue_private))
    with pytest.raises(CapabilityRuntimeUnavailable, match="permit private key"):
        runtime_module._build_gateway_runtime()


class _RouteRuntime:
    def __init__(self, health: Any = None, **results: Any) -> None:
        self.health_result = health
        self.results = results

    def health(self) -> Any:
        return self.health_result

    def _result(self, name: str) -> Any:
        value = self.results[name]
        if isinstance(value, Exception):
            raise value
        return value

    def execute(self, _: Any) -> Any:
        return self._result("execute")

    def capture_pre(self, _: Any) -> Any:
        return self._result("capture_pre")

    def resolve(self, _: Any) -> Any:
        return self._result("resolve")

    def capture_post(self, _: Any) -> Any:
        return self._result("capture_post")

    def simulate(self, _: Any) -> Any:
        return self._result("simulate")


def test_all_public_health_routes_return_metadata_or_sanitized_unavailability(
    artifacts: RuntimeArtifacts,
) -> None:
    discovery = _health_bundle(artifacts)
    gateway_health = {
        "schema_version": "m4g-gateway-health-v1",
        "status": "ready",
        "role": "segmented-gateway",
    }
    healthy_apps: tuple[tuple[FastAPI, str], ...] = (
        (create_plant_app(lambda: cast(Any, _RouteRuntime(discovery.plant))), "plant"),
        (
            create_observer_app(lambda: cast(Any, _RouteRuntime(discovery.observer))),
            "observer",
        ),
        (
            create_candidate_app(lambda: cast(Any, _RouteRuntime(discovery.candidate))),
            "candidate",
        ),
        (create_ot_app(lambda: cast(Any, _RouteRuntime(discovery.ot))), "ot-adapter"),
        (
            create_gateway_app(lambda: cast(Any, _RouteRuntime(gateway_health))),
            "segmented-gateway",
        ),
    )
    for app, expected_role in healthy_apps:
        response = TestClient(app).get("/health")
        assert response.status_code == 200
        assert response.json()["role"] == expected_role

    def unavailable() -> Any:
        raise RuntimeError("sensitive health failure")

    for app in (
        create_plant_app(unavailable),
        create_observer_app(unavailable),
        create_candidate_app(unavailable),
        create_ot_app(unavailable),
        create_gateway_app(unavailable),
    ):
        response = TestClient(app).get("/health")
        body = _failure_body(response)
        assert response.status_code == 503
        assert body.status == "error"
        assert "sensitive" not in response.text


def test_public_post_routes_return_complete_typed_successes(
    artifacts: RuntimeArtifacts,
) -> None:
    discovery = _health_bundle(artifacts)
    exchange = _candidate_exchange(artifacts)
    signed_ot_response = SignedSegmentedCapabilityResponse.issue(
        request=artifacts.envelope,
        acknowledgment=artifacts.acknowledgment,
        ot_key_id=OT_KEY_ID,
        signed_at=NOW,
        private_key=artifacts.ot_private,
    )
    result = _candidate_rejected_result(artifacts)

    plant_runtime = _plant_runtime(artifacts, FakePlant(artifacts))
    plant_call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.READ,
        payload=PlantReadPayload(correlation_id="m4g-edge-route-read"),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4g-runtime-edge-route-read-nonce-0001",
        private_key=artifacts.ot_private,
    )
    plant_response = TestClient(create_plant_app(lambda: plant_runtime)).post(
        "/v1/plant/call",
        content=plant_call.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert plant_response.status_code == 200
    assert SignedPlantResponse.model_validate_json(plant_response.content).operation is (
        PlantOperation.READ
    )

    observer_runtime = CapabilityObserverRuntime(
        plant=cast(Any, FakeObserverPlant(artifacts.pre_state)),
        plant_info=discovery.plant,
        private_key=artifacts.observer_private,
        key_id=OBSERVER_KEY_ID,
        observer_id=artifacts.pre_observation.observer_id,
        boot_epoch=OBSERVER_BOOT,
        cache_capacity=3,
    )
    observer_client = TestClient(create_observer_app(lambda: observer_runtime))
    capture_request = ObservationCaptureRequest(
        correlation_id="m4g-edge-route-observation",
        challenge_nonce="m4g-edge-route-observation-nonce-0001",
    )
    pre_response = observer_client.post(
        "/v1/observations/pre",
        content=capture_request.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert pre_response.status_code == 200
    pre = SignedObservationEnvelope.model_validate_json(pre_response.content)
    resolve_response = observer_client.post(
        "/v1/observations/resolve",
        content=ObservationResolveRequest(
            observation_id=pre.observation_id,
            envelope_digest=pre.envelope_digest,
        ).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert SignedObservationEnvelope.model_validate_json(resolve_response.content) == pre
    post_response = observer_client.post(
        "/v1/observations/post",
        content=PostObservationCaptureRequest(
            correlation_id=pre.correlation_id,
            challenge_nonce="m4g-edge-route-post-nonce-0001",
            previous_envelope_digest=pre.envelope_digest,
            permit_id=artifacts.permit.base_permit.permit_id,
            command_digest=artifacts.command.digest,
            plc_acknowledgment_digest=artifacts.acknowledgment.digest,
        ).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert (
        SignedObservationEnvelope.model_validate_json(post_response.content).phase
        is ObservationPhase.POST_DISPATCH
    )

    candidate_response = TestClient(
        create_candidate_app(
            lambda: cast(
                Any,
                _RouteRuntime(discovery.candidate, simulate=exchange),
            )
        )
    ).post(
        "/v1/candidates/simulate",
        content=CandidateSimulationRequest(command=artifacts.command).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert PlantExchange.model_validate_json(candidate_response.content) == exchange

    ot_response = TestClient(
        create_ot_app(
            lambda: cast(Any, _RouteRuntime(discovery.ot, execute=signed_ot_response))
        )
    ).post(
        "/v1/capability/execute",
        content=artifacts.envelope.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert (
        SignedSegmentedCapabilityResponse.model_validate_json(ot_response.content)
        == signed_ot_response
    )

    gateway_runtime = _RouteRuntime(
        {"status": "ready"},
        capture_pre=artifacts.pre_observation,
        execute=result,
    )
    gateway_client = TestClient(create_gateway_app(lambda: cast(Any, gateway_runtime)))
    gateway_capture = gateway_client.post(
        "/v1/observations/pre",
        content=ObservationCaptureRequest(
            correlation_id="m4g-edge-gateway-route",
            challenge_nonce="m4g-edge-gateway-route-nonce-0001",
        ).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert SignedObservationEnvelope.model_validate_json(gateway_capture.content) == (
        artifacts.pre_observation
    )
    gateway_action = gateway_client.post(
        "/v1/capability/actions",
        content=artifacts.request.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert SegmentedCapabilityClosedLoopResult.model_validate_json(
        gateway_action.content
    ) == result


def test_plant_route_preserves_signed_known_rejection(
    artifacts: RuntimeArtifacts,
) -> None:
    call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.READ,
        payload=PlantReadPayload(correlation_id="m4g-edge-route-known-rejection"),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4g-runtime-edge-route-known-rejection-0001",
        private_key=artifacts.ot_private,
    )
    rejection = SignedPlantResponse.issue(
        call=call,
        status=PlantResponseStatus.REJECTED,
        payload=PlantFailureResponsePayload(
            status=PlantResponseStatus.REJECTED,
            reason="known_no_effect_rejection",
        ),
        plant_boot_epoch=PLANT_BOOT,
        plant_key_id=PLANT_KEY_ID,
        signed_at=NOW,
        private_key=artifacts.plant_private,
    )
    route_runtime = _RouteRuntime(execute=(409, rejection))

    response = TestClient(
        create_plant_app(lambda: cast(Any, route_runtime))
    ).post(
        "/v1/plant/call",
        content=call.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 409
    returned = SignedPlantResponse.model_validate_json(response.content)
    assert returned == rejection
    assert returned.verify_for_call(
        artifacts.plant_private.public_key(),
        call=call,
        expected_plant_boot_epoch=PLANT_BOOT,
        expected_plant_key_id=PLANT_KEY_ID,
    )


@pytest.mark.parametrize(
    ("app_factory", "path"),
    (
        (create_plant_app, "/v1/plant/call"),
        (create_observer_app, "/v1/observations/pre"),
        (create_observer_app, "/v1/observations/resolve"),
        (create_observer_app, "/v1/observations/post"),
        (create_candidate_app, "/v1/candidates/simulate"),
        (create_ot_app, "/v1/capability/execute"),
        (create_gateway_app, "/v1/observations/pre"),
        (create_gateway_app, "/v1/capability/actions"),
    ),
)
def test_public_post_routes_reject_non_strict_json_before_runtime(
    app_factory: Callable[[Callable[[], Any]], FastAPI],
    path: str,
) -> None:
    invoked = False

    def provider() -> Any:
        nonlocal invoked
        invoked = True
        return object()

    response = TestClient(app_factory(provider)).post(
        path,
        content=b'{"duplicate":1,"duplicate":2}',
        headers={"Content-Type": "application/json"},
    )
    body = _failure_body(response)
    assert response.status_code == 400
    assert body.status == "rejected"
    assert body.reason == "duplicate_json_key"
    assert not invoked


@pytest.mark.parametrize(
    ("app", "path", "payload", "expected_status"),
    (
        (
            create_plant_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        execute=CapabilityAdmissionRejected("plant auth detail")
                    ),
                )
            ),
            "/v1/plant/call",
            "plant",
            403,
        ),
        (
            create_observer_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        capture_pre=CapabilityAdmissionRejected("pre rejected"),
                        resolve=CapabilityAdmissionRejected("resolve rejected"),
                        capture_post=CapabilityAdmissionRejected("post rejected"),
                    ),
                )
            ),
            "/v1/observations/pre",
            "pre",
            409,
        ),
        (
            create_observer_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        capture_pre=CapabilityAdmissionRejected("pre rejected"),
                        resolve=CapabilityAdmissionRejected("resolve rejected"),
                        capture_post=CapabilityAdmissionRejected("post rejected"),
                    ),
                )
            ),
            "/v1/observations/resolve",
            "resolve",
            404,
        ),
        (
            create_observer_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        capture_pre=CapabilityAdmissionRejected("pre rejected"),
                        resolve=CapabilityAdmissionRejected("resolve rejected"),
                        capture_post=CapabilityAdmissionRejected("post rejected"),
                    ),
                )
            ),
            "/v1/observations/post",
            "post",
            409,
        ),
        (
            create_candidate_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        simulate=CapabilityAdmissionRejected("candidate rejected")
                    ),
                )
            ),
            "/v1/candidates/simulate",
            "candidate",
            409,
        ),
        (
            create_ot_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        execute=CapabilityAdmissionRejected("transport_request_replayed")
                    ),
                )
            ),
            "/v1/capability/execute",
            "ot",
            409,
        ),
        (
            create_ot_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        execute=CapabilityAdmissionRejected("authentication rejected")
                    ),
                )
            ),
            "/v1/capability/execute",
            "ot-auth",
            403,
        ),
        (
            create_gateway_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        capture_pre=CapabilityAdmissionRejected("capture rejected")
                    ),
                )
            ),
            "/v1/observations/pre",
            "gateway-pre",
            409,
        ),
    ),
)
def test_public_post_routes_map_admission_rejections_without_leaking(
    app: FastAPI,
    path: str,
    payload: str,
    expected_status: int,
    artifacts: RuntimeArtifacts,
) -> None:
    if payload == "plant":
        body_model: Any = _plant_call(
            role=PlantCallerRole.PLC,
            operation=PlantOperation.READ,
            payload=PlantReadPayload(correlation_id="m4g-edge-route-admission"),
            caller_key_id=OT_KEY_ID,
            target_plant_key_id=PLANT_KEY_ID,
            target_plant_boot_epoch=PLANT_BOOT,
            nonce="m4g-runtime-edge-admission-nonce-0001",
            private_key=artifacts.ot_private,
        )
    elif payload == "pre" or payload == "gateway-pre":
        body_model = ObservationCaptureRequest(
            correlation_id="m4g-edge-route-admission",
            challenge_nonce="m4g-edge-route-admission-nonce-0001",
        )
    elif payload == "resolve":
        body_model = ObservationResolveRequest(
            observation_id=artifacts.pre_observation.observation_id,
            envelope_digest=artifacts.pre_observation.envelope_digest,
        )
    elif payload == "post":
        body_model = PostObservationCaptureRequest(
            correlation_id=artifacts.pre_observation.correlation_id,
            challenge_nonce="m4g-edge-route-admission-post-0001",
            previous_envelope_digest=artifacts.pre_observation.envelope_digest,
            permit_id=artifacts.permit.base_permit.permit_id,
            command_digest=artifacts.command.digest,
            plc_acknowledgment_digest=artifacts.acknowledgment.digest,
        )
    elif payload == "candidate":
        body_model = CandidateSimulationRequest(command=artifacts.command)
    else:
        body_model = artifacts.envelope

    response = TestClient(app).post(
        path,
        content=body_model.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    failure = _failure_body(response)
    assert response.status_code == expected_status
    assert failure.status == "rejected"


def test_public_nonconsequential_failures_are_sanitized(
    artifacts: RuntimeArtifacts,
) -> None:
    discovery = _health_bundle(artifacts)
    cases: tuple[tuple[FastAPI, str, Any, str], ...] = (
        (
            create_observer_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(capture_pre=RuntimeError("sensitive observer detail")),
                )
            ),
            "/v1/observations/pre",
            ObservationCaptureRequest(
                correlation_id="m4g-edge-error-pre",
                challenge_nonce="m4g-edge-error-pre-nonce-0001",
            ),
            "observation_unavailable",
        ),
        (
            create_observer_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(resolve=RuntimeError("sensitive resolve detail")),
                )
            ),
            "/v1/observations/resolve",
            ObservationResolveRequest(
                observation_id=artifacts.pre_observation.observation_id,
                envelope_digest=artifacts.pre_observation.envelope_digest,
            ),
            "observation_unavailable",
        ),
        (
            create_observer_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        capture_post=RuntimeError("sensitive post detail")
                    ),
                )
            ),
            "/v1/observations/post",
            PostObservationCaptureRequest(
                correlation_id=artifacts.pre_observation.correlation_id,
                challenge_nonce="m4g-edge-error-post-nonce-0001",
                previous_envelope_digest=artifacts.pre_observation.envelope_digest,
                permit_id=artifacts.permit.base_permit.permit_id,
                command_digest=artifacts.command.digest,
                plc_acknowledgment_digest=artifacts.acknowledgment.digest,
            ),
            "observation_unavailable",
        ),
        (
            create_candidate_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(simulate=RuntimeError("sensitive candidate detail")),
                )
            ),
            "/v1/candidates/simulate",
            CandidateSimulationRequest(command=artifacts.command),
            "candidate_simulation_unavailable",
        ),
        (
            create_gateway_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(
                        capture_pre=RuntimeError("sensitive gateway capture detail")
                    ),
                )
            ),
            "/v1/observations/pre",
            ObservationCaptureRequest(
                correlation_id="m4g-edge-error-gateway-pre",
                challenge_nonce="m4g-edge-error-gateway-pre-0001",
            ),
            "observation_unavailable",
        ),
        (
            create_gateway_app(
                lambda: cast(
                    Any,
                    _RouteRuntime(execute=RuntimeError("sensitive gateway detail")),
                )
            ),
            "/v1/capability/actions",
            artifacts.request,
            "gateway_runtime_unavailable",
        ),
    )
    assert discovery.plant.status == "ready"
    for app, path, request, expected_reason in cases:
        response = TestClient(app).post(
            path,
            content=request.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        failure = _failure_body(response)
        assert response.status_code == 503
        assert failure.status == "error"
        assert failure.reason == expected_reason
        assert "sensitive" not in response.text
