from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ValidationError

from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityExecutionPermit,
    DispatchPhase,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from aegis_ot.crypto import generate_keypair, sign_bytes
from aegis_ot.models import ActionProposal, Decision, Operation
from aegis_ot.physical_control import TrustedCommandTranslator, physical_state_to_gateway_state
from aegis_ot.physical_factory import build_physical_local_lab
from aegis_ot.physical_models import (
    CandidateAssessment,
    CommandStatus,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
)
from aegis_ot.segmented_capability_models import (
    PHYSICAL_PLANT_AUDIENCE,
    PlantApplyPayload,
    PlantCallerRole,
    PlantCapturePayload,
    PlantExchange,
    PlantFailureResponsePayload,
    PlantOperation,
    PlantResponseStatus,
    PlantSimulatePayload,
    PlantSimulationResponsePayload,
    PlantStateResponsePayload,
    SignedPlantCall,
    SignedPlantResponse,
    SignedSegmentedCapabilityDispatch,
    SignedSegmentedCapabilityResponse,
)
from aegis_ot.segmented_capability_transport import (
    MAX_JSON_BYTES,
    CandidateHealthMetadata,
    CapabilityTransportProtocolError,
    CapabilityTransportRejected,
    CapabilityTransportUnavailable,
    ConsequentialTransportOutcomeUnknown,
    HttpExchangeResponse,
    ObserverHealthMetadata,
    OtHealthMetadata,
    PlantHealthMetadata,
    RemoteCandidatePlantClient,
    RemoteCandidatePort,
    RemoteObservationPort,
    RemoteObserverPlantClient,
    RemotePhysicalRejection,
    RemotePlcPlantClient,
    RemoteVirtualPlcPort,
    SegmentedCapabilityDiscovery,
    TransportFailureBody,
    discover_segmented_capabilities,
)

NOW = datetime(2026, 8, 25, 16, 0, tzinfo=UTC)
GATEWAY_KEY_ID = "m4g-gateway-key-0001"
PLANT_KEY_ID = "m4g-plant-key-0001"
CANDIDATE_KEY_ID = "m4g-candidate-key-0001"
OBSERVER_KEY_ID = "m4g-observer-key-0001"
OT_KEY_ID = "m4g-ot-key-0001"
PLANT_BOOT = "m4g-plant-boot-epoch-0001"
OBSERVER_BOOT = "m4g-observer-boot-epoch-0001"
OT_BOOT = "m4g-ot-boot-epoch-0001"
PLC_ID = "plc:m4g-ot-adapter"


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import base64

    return base64.urlsafe_b64encode(raw).decode("ascii")


def _json_response(
    value: BaseModel,
    *,
    status_code: int = 200,
    content_type: str = "application/json",
) -> HttpExchangeResponse:
    return HttpExchangeResponse(
        status_code=status_code,
        content_type=content_type,
        body=value.model_dump_json().encode("utf-8"),
    )


class StubExchange:
    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: Any,
        timeout_seconds: float,
    ) -> HttpExchangeResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "body": body,
                "headers": headers,
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.handler(method, url, body)


@dataclass(frozen=True)
class Artifacts:
    gateway_private: Ed25519PrivateKey
    plant_private: Ed25519PrivateKey
    candidate_private: Ed25519PrivateKey
    observer_private: Ed25519PrivateKey
    ot_private: Ed25519PrivateKey
    pre_state: PhysicalStateSnapshot
    command: PhysicalControlCommand
    assessment: CandidateAssessment
    request: CapabilityActionRequest
    decision: Decision
    permit: CapabilityExecutionPermit
    pre_observation: SignedObservationEnvelope
    acknowledgment: PlcCommandAcknowledgment
    post_observation: SignedObservationEnvelope
    plant_health: PlantHealthMetadata
    observer_health: ObserverHealthMetadata
    candidate_health: CandidateHealthMetadata
    ot_health: OtHealthMetadata


@pytest.fixture(scope="module")
def artifacts() -> Artifacts:
    lab = build_physical_local_lab(NOW)
    pre_state = lab.plant.read_state()
    proposal = ActionProposal(
        proposal_id="m4g-transport-proposal-0001",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=pre_state.state_version,
        observed_at=pre_state.observed_at,
        submitted_at=pre_state.observed_at,
        nonce="m4g-transport-proposal-nonce-0001",
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
    candidate_private, _ = generate_keypair()
    observer_private, _ = generate_keypair()
    ot_private, _ = generate_keypair()
    pre_observation = SignedObservationEnvelope.issue(
        snapshot=pre_state,
        correlation_id="m4g-correlation-0001",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="m4g-pre-observation-challenge-0001",
        observer_id="observer:m4g-segmented",
        observer_key_id=OBSERVER_KEY_ID,
        observer_boot_epoch=OBSERVER_BOOT,
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=observer_private,
    )
    request = CapabilityActionRequest(
        request_id="m4g-capability-request-0001",
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
    post_observation = SignedObservationEnvelope.issue(
        snapshot=post_state,
        correlation_id=request.correlation_id,
        phase=ObservationPhase.POST_DISPATCH,
        challenge_nonce="m4g-post-observation-challenge-0001",
        observer_id=pre_observation.observer_id,
        observer_key_id=pre_observation.observer_key_id,
        observer_boot_epoch=pre_observation.observer_boot_epoch,
        observer_sequence=2,
        previous_envelope_digest=pre_observation.envelope_digest,
        permit_id=base_permit.permit_id,
        command_digest=command.digest,
        plc_acknowledgment_digest=acknowledgment.digest,
        private_key=observer_private,
    )
    plant_health = PlantHealthMetadata(
        pid=101,
        boot_epoch=PLANT_BOOT,
        key_id=PLANT_KEY_ID,
        public_key_b64=_public_key_b64(plant_private),
        backend="pandapower-cigre-mv",
        model_digest=pre_state.model_digest,
        simulator_version=pre_state.simulator_version,
        observation_source_id=pre_state.observation_source_id,
        state_version=pre_state.state_version,
        state_digest=pre_state.state_digest,
        apply_requests=0,
        commit_count=0,
        call_reservations=0,
    )
    observer_health = ObserverHealthMetadata(
        pid=102,
        observer_id=pre_observation.observer_id,
        boot_epoch=OBSERVER_BOOT,
        key_id=OBSERVER_KEY_ID,
        public_key_b64=_public_key_b64(observer_private),
        plant_boot_epoch=PLANT_BOOT,
        plant_model_digest=pre_state.model_digest,
        capture_count=2,
        resolve_count=0,
        cached_observations=2,
    )
    candidate_health = CandidateHealthMetadata(
        pid=103,
        boot_epoch="m4g-candidate-boot-epoch-0001",
        key_id=CANDIDATE_KEY_ID,
        public_key_b64=_public_key_b64(candidate_private),
        plant_boot_epoch=PLANT_BOOT,
        plant_model_digest=pre_state.model_digest,
        simulation_count=1,
    )
    ot_health = OtHealthMetadata(
        pid=104,
        plc_id=PLC_ID,
        boot_epoch=OT_BOOT,
        key_id=OT_KEY_ID,
        public_key_b64=_public_key_b64(ot_private),
        gateway_key_id=GATEWAY_KEY_ID,
        gateway_public_key_b64=_public_key_b64(gateway_private),
        permit_key_id=permit.signing_key_id,
        permit_public_key_b64=_public_key_b64(permit_private),
        plant_boot_epoch=PLANT_BOOT,
        plant_model_digest=pre_state.model_digest,
        observer_boot_epoch=OBSERVER_BOOT,
        transport_replay_reservations=0,
        semantic_replay_reservations=0,
        execute_requests=1,
        scan_counter=1,
    )
    return Artifacts(
        gateway_private=gateway_private,
        plant_private=plant_private,
        candidate_private=candidate_private,
        observer_private=observer_private,
        ot_private=ot_private,
        pre_state=pre_state,
        command=command,
        assessment=assessment,
        request=request,
        decision=decision,
        permit=permit,
        pre_observation=pre_observation,
        acknowledgment=acknowledgment,
        post_observation=post_observation,
        plant_health=plant_health,
        observer_health=observer_health,
        candidate_health=candidate_health,
        ot_health=ot_health,
    )


def _plant_exchange(
    artifacts: Artifacts,
    call: SignedPlantCall,
    *,
    plant_private: Ed25519PrivateKey | None = None,
    status: PlantResponseStatus = PlantResponseStatus.OK,
) -> PlantExchange:
    if status is not PlantResponseStatus.OK:
        payload: Any = PlantFailureResponsePayload(
            status=status,
            reason="known_remote_rejection",
        )
    elif call.operation is PlantOperation.SIMULATE:
        payload = PlantSimulationResponsePayload(assessment=artifacts.assessment)
    elif call.operation is PlantOperation.APPLY:
        payload = PlantStateResponsePayload(snapshot=artifacts.assessment.post_state)
    else:
        payload = PlantStateResponsePayload(snapshot=artifacts.pre_state)
    response = SignedPlantResponse.issue(
        call=call,
        status=status,
        payload=payload,
        plant_boot_epoch=PLANT_BOOT,
        plant_key_id=PLANT_KEY_ID,
        signed_at=NOW,
        private_key=plant_private or artifacts.plant_private,
    )
    return PlantExchange(call=call, response=response)


def _candidate_exchange(
    artifacts: Artifacts,
    *,
    candidate_private: Ed25519PrivateKey | None = None,
    plant_private: Ed25519PrivateKey | None = None,
) -> PlantExchange:
    call = SignedPlantCall.issue(
        role=PlantCallerRole.CANDIDATE,
        operation=PlantOperation.SIMULATE,
        payload=PlantSimulatePayload(command=artifacts.command),
        caller_key_id=CANDIDATE_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        call_nonce="m4g-candidate-call-nonce-0001",
        issued_at=NOW,
        expires_at=NOW.replace(second=30),
        private_key=candidate_private or artifacts.candidate_private,
        audience=PHYSICAL_PLANT_AUDIENCE,
    )
    return _plant_exchange(artifacts, call, plant_private=plant_private)


def test_discovery_is_closed_consistent_and_allows_dynamic_counters(
    artifacts: Artifacts,
) -> None:
    health_by_host: dict[str, BaseModel] = {
        "plant": artifacts.plant_health,
        "observer": artifacts.observer_health,
        "candidate": artifacts.candidate_health,
        "ot": artifacts.ot_health,
    }

    def handler(method: str, url: str, body: bytes | None) -> HttpExchangeResponse:
        assert method == "GET" and body is None
        host = url.split("//", maxsplit=1)[1].split("/", maxsplit=1)[0]
        return _json_response(health_by_host[host])

    discovery = discover_segmented_capabilities(
        plant_url="http://plant",
        observer_url="http://observer",
        candidate_url="http://candidate",
        ot_url="http://ot",
        gateway_key_id=GATEWAY_KEY_ID,
        exchange=StubExchange(handler),
    )
    assert isinstance(discovery, SegmentedCapabilityDiscovery)

    dynamic_observer = artifacts.observer_health.model_copy(
        update={"capture_count": 99, "resolve_count": 98}
    )
    port = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(
            lambda *_: _json_response(dynamic_observer)
        ),
    )
    assert port.health().capture_count == 99

    wrong = artifacts.candidate_health.model_copy(
        update={"plant_boot_epoch": "different-plant-boot-epoch"}
    )
    with pytest.raises(ValidationError, match="different plant boot"):
        SegmentedCapabilityDiscovery(
            plant=artifacts.plant_health,
            observer=artifacts.observer_health,
            candidate=wrong,
            ot=artifacts.ot_health,
        )

    reused_candidate = CandidateHealthMetadata(
        **{
            **artifacts.candidate_health.model_dump(mode="python"),
            "public_key_b64": artifacts.observer_health.public_key_b64,
        }
    )
    with pytest.raises(ValidationError, match="key material must be distinct"):
        SegmentedCapabilityDiscovery(
            plant=artifacts.plant_health,
            observer=artifacts.observer_health,
            candidate=reused_candidate,
            ot=artifacts.ot_health,
        )


def test_remote_observation_validates_identity_signature_and_bindings(
    artifacts: Artifacts,
) -> None:
    responses = [
        artifacts.pre_observation,
        artifacts.pre_observation,
        artifacts.post_observation,
    ]
    stub = StubExchange(lambda *_: _json_response(responses.pop(0)))
    port = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=stub,
    )
    assert port.resolve(
        observation_id=artifacts.pre_observation.observation_id,
        envelope_digest=artifacts.pre_observation.envelope_digest,
    ) == artifacts.pre_observation
    assert port.capture_pre(
        correlation_id=artifacts.pre_observation.correlation_id,
        challenge_nonce=artifacts.pre_observation.challenge_nonce,
    ) == artifacts.pre_observation
    assert port.capture_post(
        correlation_id=artifacts.request.correlation_id,
        challenge_nonce=artifacts.post_observation.challenge_nonce,
        previous_envelope_digest=artifacts.pre_observation.envelope_digest,
        permit_id=artifacts.permit.base_permit.permit_id,
        command_digest=artifacts.command.digest,
        plc_acknowledgment_digest=artifacts.acknowledgment.digest,
    ) == artifacts.post_observation

    tampered = artifacts.pre_observation.model_copy(update={"signature": "tampered"})
    bad_port = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(lambda *_: _json_response(tampered)),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="signature"):
        bad_port.resolve(
            observation_id=artifacts.pre_observation.observation_id,
            envelope_digest=artifacts.pre_observation.envelope_digest,
        )

    bound_port = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(
            lambda *_: _json_response(artifacts.pre_observation)
        ),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="binding"):
        bound_port.capture_pre(
            correlation_id="different-correlation",
            challenge_nonce=artifacts.pre_observation.challenge_nonce,
        )


@pytest.mark.parametrize("wrong_side", ["candidate", "plant"])
def test_candidate_port_requires_both_signatures(
    artifacts: Artifacts,
    wrong_side: str,
) -> None:
    wrong_private, _ = generate_keypair()
    exchange = _candidate_exchange(
        artifacts,
        candidate_private=wrong_private if wrong_side == "candidate" else None,
        plant_private=wrong_private if wrong_side == "plant" else None,
    )
    port = RemoteCandidatePort(
        "http://candidate",
        candidate=artifacts.candidate_health,
        plant=artifacts.plant_health,
        clock=lambda: NOW,
        exchange=StubExchange(lambda *_: _json_response(exchange)),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="signature|identity"):
        port.simulate_candidate(artifacts.command)


def test_candidate_port_accepts_exact_full_plant_exchange(artifacts: Artifacts) -> None:
    exchange = _candidate_exchange(artifacts)
    port = RemoteCandidatePort(
        "http://candidate",
        candidate=artifacts.candidate_health,
        plant=artifacts.plant_health,
        clock=lambda: NOW,
        exchange=StubExchange(lambda *_: _json_response(exchange)),
    )
    assert port.simulate_candidate(artifacts.command) == artifacts.assessment


def test_remote_virtual_plc_signs_once_and_verifies_ot_and_ack(
    artifacts: Artifacts,
) -> None:
    def handler(method: str, url: str, body: bytes | None) -> HttpExchangeResponse:
        assert method == "POST" and url.endswith("/v1/capability/execute")
        assert body is not None
        signed = SignedSegmentedCapabilityDispatch.model_validate_json(body)
        assert signed.verify_for_admission(
            artifacts.gateway_private.public_key(),
            expected_audience=signed.audience,
            expected_gateway_key_id=GATEWAY_KEY_ID,
            evaluated_at=NOW,
        )
        response = SignedSegmentedCapabilityResponse.issue(
            request=signed,
            acknowledgment=artifacts.acknowledgment,
            ot_key_id=OT_KEY_ID,
            signed_at=NOW,
            private_key=artifacts.ot_private,
        )
        return _json_response(response)

    stub = StubExchange(handler)
    port = RemoteVirtualPlcPort(
        "http://ot",
        ot=artifacts.ot_health,
        gateway_key_id=GATEWAY_KEY_ID,
        gateway_private_key=artifacts.gateway_private,
        clock=lambda: NOW,
        nonce_factory=lambda: "m4g-gateway-transport-nonce-0001",
        exchange=stub,
    )
    result = port.execute(
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        decision=artifacts.decision,
        assessment=artifacts.assessment,
    )
    assert result == artifacts.acknowledgment
    assert len(stub.calls) == 1


def test_remote_virtual_plc_rejects_wrong_ot_binding(artifacts: Artifacts) -> None:
    def handler(method: str, url: str, body: bytes | None) -> HttpExchangeResponse:
        assert body is not None
        request = SignedSegmentedCapabilityDispatch.model_validate_json(body)
        response = SignedSegmentedCapabilityResponse.issue(
            request=request,
            acknowledgment=artifacts.acknowledgment,
            ot_key_id=OT_KEY_ID,
            signed_at=NOW,
            private_key=artifacts.ot_private,
        )
        changed = response.model_copy(update={"request_sha256": "0" * 64, "signature": ""})
        changed = changed.model_copy(
            update={
                "signature": sign_bytes(
                    artifacts.ot_private,
                    changed.signing_payload(),
                )
            }
        )
        return _json_response(changed)

    port = RemoteVirtualPlcPort(
        "http://ot",
        ot=artifacts.ot_health,
        gateway_key_id=GATEWAY_KEY_ID,
        gateway_private_key=artifacts.gateway_private,
        clock=lambda: NOW,
        exchange=StubExchange(handler),
    )
    with pytest.raises(ConsequentialTransportOutcomeUnknown, match="binding"):
        port.execute(
            request=artifacts.request,
            permit=artifacts.permit,
            pre_observation=artifacts.pre_observation,
            decision=artifacts.decision,
            assessment=artifacts.assessment,
        )


def _plant_handler(
    artifacts: Artifacts,
    calls: list[SignedPlantCall],
    *,
    apply_status: PlantResponseStatus = PlantResponseStatus.OK,
    http_status: int = 200,
) -> Any:
    def handler(method: str, url: str, body: bytes | None) -> HttpExchangeResponse:
        assert method == "POST" and url.endswith("/v1/plant/call") and body is not None
        call = SignedPlantCall.model_validate_json(body)
        calls.append(call)
        status = apply_status if call.operation is PlantOperation.APPLY else PlantResponseStatus.OK
        exchange = _plant_exchange(artifacts, call, status=status)
        return _json_response(exchange.response, status_code=http_status)

    return handler


def test_role_signed_plant_clients_use_exact_calls_and_bound_capture(
    artifacts: Artifacts,
) -> None:
    calls: list[SignedPlantCall] = []
    stub = StubExchange(_plant_handler(artifacts, calls))
    observer = RemoteObserverPlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        observer=artifacts.observer_health,
        caller_private_key=artifacts.observer_private,
        clock=lambda: NOW,
        exchange=stub,
    )
    candidate = RemoteCandidatePlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        candidate=artifacts.candidate_health,
        caller_private_key=artifacts.candidate_private,
        clock=lambda: NOW,
        exchange=stub,
    )
    plc = RemotePlcPlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        ot=artifacts.ot_health,
        caller_private_key=artifacts.ot_private,
        clock=lambda: NOW,
        exchange=stub,
    )

    assert observer.capture_bound_state(
        correlation_id="gateway-observation-correlation",
        challenge_nonce="gateway-observation-challenge-0001",
    ) == artifacts.pre_state
    candidate_exchange = candidate.simulate_exchange(artifacts.command)
    assert (
        cast(PlantSimulationResponsePayload, candidate_exchange.response.payload).assessment
        == artifacts.assessment
    )
    assert plc.read_state() == artifacts.pre_state
    assert plc.simulate_candidate(artifacts.command) == artifacts.assessment
    assert plc.apply_authorized_command(
        artifacts.command,
        expected_pre_state_version=artifacts.pre_state.state_version,
        expected_pre_state_digest=artifacts.pre_state.state_digest,
        expected_pre_observation_digest=artifacts.pre_state.observation_digest,
        expected_post_state_digest=artifacts.assessment.post_state.state_digest,
        expected_post_topology_digest=artifacts.assessment.post_state.topology_digest,
        authorization_expires_at=artifacts.permit.base_permit.expires_at,
    ) == artifacts.assessment.post_state

    capture = calls[0]
    assert capture.role is PlantCallerRole.OBSERVER
    assert isinstance(capture.payload, PlantCapturePayload)
    assert capture.payload.correlation_id == "gateway-observation-correlation"
    assert capture.payload.challenge_nonce == "gateway-observation-challenge-0001"
    assert calls[1].role is PlantCallerRole.CANDIDATE
    assert [call.role for call in calls[2:]] == [
        PlantCallerRole.PLC,
        PlantCallerRole.PLC,
        PlantCallerRole.PLC,
    ]
    assert isinstance(calls[-1].payload, PlantApplyPayload)
    assert (
        calls[-1].payload.authorization_expires_at
        == artifacts.permit.base_permit.expires_at
    )


def test_apply_distinguishes_signed_4xx_rejection_from_ambiguous_failure(
    artifacts: Artifacts,
) -> None:
    rejected_calls: list[SignedPlantCall] = []
    rejected_stub = StubExchange(
        _plant_handler(
            artifacts,
            rejected_calls,
            apply_status=PlantResponseStatus.REJECTED,
            http_status=409,
        )
    )
    rejected = RemotePlcPlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        ot=artifacts.ot_health,
        caller_private_key=artifacts.ot_private,
        clock=lambda: NOW,
        exchange=rejected_stub,
    )
    kwargs = {
        "expected_pre_state_version": artifacts.pre_state.state_version,
        "expected_pre_state_digest": artifacts.pre_state.state_digest,
        "expected_pre_observation_digest": artifacts.pre_state.observation_digest,
        "expected_post_state_digest": artifacts.assessment.post_state.state_digest,
        "expected_post_topology_digest": artifacts.assessment.post_state.topology_digest,
        "authorization_expires_at": artifacts.permit.base_permit.expires_at,
    }
    with pytest.raises(RemotePhysicalRejection, match="known_remote_rejection"):
        rejected.apply_authorized_command(artifacts.command, **kwargs)
    assert len(rejected_stub.calls) == 1

    failure = TransportFailureBody(status="error", reason="plant unavailable")
    ambiguous_stub = StubExchange(lambda *_: _json_response(failure, status_code=503))
    ambiguous = RemotePlcPlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        ot=artifacts.ot_health,
        caller_private_key=artifacts.ot_private,
        clock=lambda: NOW,
        exchange=ambiguous_stub,
    )
    with pytest.raises(ConsequentialTransportOutcomeUnknown, match="server failure"):
        ambiguous.apply_authorized_command(artifacts.command, **kwargs)
    assert len(ambiguous_stub.calls) == 1

    def unavailable(*_: Any) -> HttpExchangeResponse:
        raise CapabilityTransportUnavailable("connection lost")

    network_stub = StubExchange(unavailable)
    network = RemotePlcPlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        ot=artifacts.ot_health,
        caller_private_key=artifacts.ot_private,
        clock=lambda: NOW,
        exchange=network_stub,
    )
    with pytest.raises(ConsequentialTransportOutcomeUnknown, match="unavailable"):
        network.apply_authorized_command(artifacts.command, **kwargs)
    assert len(network_stub.calls) == 1


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (
            HttpExchangeResponse(
                status_code=200,
                content_type="application/json",
                body=b'{"x":1,"x":2}',
            ),
            CapabilityTransportProtocolError,
        ),
        (
            HttpExchangeResponse(
                status_code=200,
                content_type="text/plain",
                body=b"{}",
            ),
            CapabilityTransportProtocolError,
        ),
        (
            HttpExchangeResponse(
                status_code=200,
                content_type="application/json",
                body=b"{" + b" " * MAX_JSON_BYTES + b"}",
            ),
            CapabilityTransportProtocolError,
        ),
        (
            _json_response(
                TransportFailureBody(status="rejected", reason="not admitted"),
                status_code=422,
            ),
            CapabilityTransportRejected,
        ),
        (
            _json_response(
                TransportFailureBody(status="error", reason="offline"),
                status_code=503,
            ),
            CapabilityTransportUnavailable,
        ),
    ],
)
def test_strict_json_size_content_and_status_fail_closed(
    artifacts: Artifacts,
    response: HttpExchangeResponse,
    error: type[Exception],
) -> None:
    port = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(lambda *_: response),
    )
    with pytest.raises(error):
        port.resolve(
            observation_id=artifacts.pre_observation.observation_id,
            envelope_digest=artifacts.pre_observation.envelope_digest,
        )


def test_transport_models_reject_extra_health_identity_fields(artifacts: Artifacts) -> None:
    value = artifacts.plant_health.model_dump(mode="json")
    value["claimed_identity"] = "untyped"
    with pytest.raises(ValidationError, match="Extra inputs"):
        PlantHealthMetadata.model_validate(value)
