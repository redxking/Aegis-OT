from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopStatus,
    CapabilityExecutionPermit,
    DispatchPhase,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from aegis_ot.crypto import generate_keypair, sign_bytes
from aegis_ot.models import ActionProposal, Operation
from aegis_ot.physical_control import TrustedCommandTranslator, physical_state_to_gateway_state
from aegis_ot.physical_factory import build_physical_local_lab
from aegis_ot.physical_models import CommandStatus, PhysicalControlCommand, canonical_digest
from aegis_ot.segmented_capability_models import (
    MAX_SIGNED_CALL_TTL,
    OT_CAPABILITY_AUDIENCE,
    PHYSICAL_PLANT_AUDIENCE,
    PlantApplyPayload,
    PlantCallerRole,
    PlantCapturePayload,
    PlantExchange,
    PlantFailureResponsePayload,
    PlantOperation,
    PlantReadPayload,
    PlantResponseStatus,
    PlantSimulatePayload,
    PlantSimulationResponsePayload,
    PlantStateResponsePayload,
    SegmentedCapabilityClosedLoopResult,
    SegmentedCapabilityDispatch,
    SignedPlantCall,
    SignedPlantResponse,
    SignedSegmentedCapabilityDispatch,
    SignedSegmentedCapabilityResponse,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
GATEWAY_KEY_ID = "m4g-gateway-key-1"
OT_KEY_ID = "m4g-ot-key-1"
PLC_KEY_ID = "m4g-plc-artifact-key-1"
PLC_BOOT_EPOCH = "m4g-plc-boot-epoch-0001"
PLANT_KEY_ID = "m4g-plant-key-1"
PLANT_BOOT_EPOCH = "m4g-plant-boot-epoch-0001"


@dataclass(frozen=True)
class ContractArtifacts:
    gateway_private: Ed25519PrivateKey
    gateway_public: Ed25519PublicKey
    ot_private: Ed25519PrivateKey
    ot_public: Ed25519PublicKey
    permit_public: Ed25519PublicKey
    observer_public: Ed25519PublicKey
    plc_private: Ed25519PrivateKey
    plc_public: Ed25519PublicKey
    plant_private: Ed25519PrivateKey
    plant_public: Ed25519PublicKey
    command: PhysicalControlCommand
    dispatch: SegmentedCapabilityDispatch
    envelope: SignedSegmentedCapabilityDispatch
    acknowledgment: PlcCommandAcknowledgment
    response: SignedSegmentedCapabilityResponse


@pytest.fixture(scope="module")
def artifacts() -> ContractArtifacts:
    lab = build_physical_local_lab(NOW)
    pre_state = lab.plant.read_state()
    proposal = ActionProposal(
        proposal_id="m4g-proposal-1",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=pre_state.state_version,
        observed_at=pre_state.observed_at,
        submitted_at=pre_state.observed_at,
        nonce="m4g-proposal-transport-nonce-0001",
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
    observer_private, observer_public = generate_keypair()
    plc_private, plc_public = generate_keypair()
    gateway_private, gateway_public = generate_keypair()
    ot_private, ot_public = generate_keypair()
    plant_private, plant_public = generate_keypair()

    pre_observation = SignedObservationEnvelope.issue(
        snapshot=pre_state,
        correlation_id="m4g-correlation-1",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="m4g-observation-challenge-0001",
        observer_id="observer:m4g",
        observer_key_id="m4g-observer-key-1",
        observer_boot_epoch="m4g-observer-boot-epoch-0001",
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=observer_private,
    )
    request = CapabilityActionRequest(
        request_id="m4g-request-1",
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
        target_plc_id=base_permit.audience,
        target_plc_key_id=PLC_KEY_ID,
        target_plc_boot_epoch=PLC_BOOT_EPOCH,
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
        transport_nonce="m4g-dispatch-transport-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        private_key=gateway_private,
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
        plc_id=permit.target_plc_id,
        plc_key_id=PLC_KEY_ID,
        plc_boot_epoch=PLC_BOOT_EPOCH,
        plc_scan=1,
        status=CommandStatus.APPLIED,
        dispatch_phase=DispatchPhase.COMMITTED,
        reason="command_applied_and_plc_read_back",
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
    ).signed(plc_private)
    response = SignedSegmentedCapabilityResponse.issue(
        request=envelope,
        acknowledgment=acknowledgment,
        ot_key_id=OT_KEY_ID,
        signed_at=NOW + timedelta(seconds=1),
        private_key=ot_private,
    )
    return ContractArtifacts(
        gateway_private=gateway_private,
        gateway_public=gateway_public,
        ot_private=ot_private,
        ot_public=ot_public,
        permit_public=lab.permit_public_key,
        observer_public=observer_public,
        plc_private=plc_private,
        plc_public=plc_public,
        plant_private=plant_private,
        plant_public=plant_public,
        command=command,
        dispatch=dispatch,
        envelope=envelope,
        acknowledgment=acknowledgment,
        response=response,
    )


def test_full_dispatch_and_signed_envelope_round_trip_with_exact_hashes(
    artifacts: ContractArtifacts,
) -> None:
    envelope = artifacts.envelope
    decoded = SignedSegmentedCapabilityDispatch.model_validate_json(
        envelope.model_dump_json()
    )

    assert decoded == envelope
    assert decoded.dispatch.bindings_match()
    assert decoded.dispatch_sha256 == decoded.dispatch.digest
    assert decoded.dispatch.digest == canonical_digest(decoded.dispatch)
    assert decoded.digest == canonical_digest(decoded)
    assert decoded.verify_for_admission(
        artifacts.gateway_public,
        expected_audience=OT_CAPABILITY_AUDIENCE,
        expected_gateway_key_id=GATEWAY_KEY_ID,
        evaluated_at=NOW,
    )


def test_dispatch_signature_and_hash_bind_every_inner_artifact(
    artifacts: ContractArtifacts,
) -> None:
    wrong_key = Ed25519PrivateKey.generate().public_key()
    assert not artifacts.envelope.verify(wrong_key)

    changed_decision = artifacts.dispatch.decision.model_copy(
        update={"policy_version": "substituted-policy"}
    )
    changed_dispatch = artifacts.dispatch.model_copy(update={"decision": changed_decision})
    tampered = artifacts.envelope.model_copy(update={"dispatch": changed_dispatch})
    assert not tampered.verify(artifacts.gateway_public)

    serialized = artifacts.envelope.model_dump(mode="json")
    serialized["dispatch"]["decision"]["policy_version"] = "substituted-policy"
    with pytest.raises(ValidationError, match="bindings|hash"):
        SignedSegmentedCapabilityDispatch.model_validate(serialized)

    wrong_audience = artifacts.envelope.model_copy(update={"audience": "wrong-audience"})
    assert not wrong_audience.verify(artifacts.gateway_public)
    assert not artifacts.envelope.verify_for_admission(
        artifacts.gateway_public,
        expected_audience="wrong-audience",
        expected_gateway_key_id=GATEWAY_KEY_ID,
        evaluated_at=NOW,
    )


def test_complete_ot_admission_rejects_valid_outer_wrapper_with_invalid_inner_signers(
    artifacts: ContractArtifacts,
) -> None:
    admission = {
        "expected_audience": OT_CAPABILITY_AUDIENCE,
        "expected_gateway_key_id": GATEWAY_KEY_ID,
        "observer_public_key": artifacts.observer_public,
        "expected_observer_id": artifacts.dispatch.pre_observation.observer_id,
        "expected_observer_key_id": artifacts.dispatch.pre_observation.observer_key_id,
        "expected_observer_boot_epoch": (
            artifacts.dispatch.pre_observation.observer_boot_epoch
        ),
        "permit_public_key": artifacts.permit_public,
        "expected_permit_key_id": artifacts.dispatch.permit.signing_key_id,
        "expected_plc_id": artifacts.dispatch.permit.target_plc_id,
        "expected_plc_key_id": artifacts.dispatch.permit.target_plc_key_id,
        "expected_plc_boot_epoch": artifacts.dispatch.permit.target_plc_boot_epoch,
        "evaluated_at": NOW,
    }
    assert artifacts.envelope.verify_complete_for_ot(
        artifacts.gateway_public,
        **admission,
    )

    invalid_observation = artifacts.dispatch.pre_observation.model_copy(
        update={"signature": ""}
    )
    invalid_dispatch = artifacts.dispatch.model_copy(
        update={"pre_observation": invalid_observation}
    )
    outer_resigned = SignedSegmentedCapabilityDispatch.issue(
        dispatch=invalid_dispatch,
        gateway_key_id=GATEWAY_KEY_ID,
        transport_nonce="m4g-invalid-observer-outer-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        private_key=artifacts.gateway_private,
    )
    assert outer_resigned.verify_for_admission(
        artifacts.gateway_public,
        expected_audience=OT_CAPABILITY_AUDIENCE,
        expected_gateway_key_id=GATEWAY_KEY_ID,
        evaluated_at=NOW,
    )
    assert not outer_resigned.verify_complete_for_ot(
        artifacts.gateway_public,
        **admission,
    )

    invalid_permit = artifacts.dispatch.permit.model_copy(update={"signature": ""})
    invalid_dispatch = artifacts.dispatch.model_copy(update={"permit": invalid_permit})
    outer_resigned = SignedSegmentedCapabilityDispatch.issue(
        dispatch=invalid_dispatch,
        gateway_key_id=GATEWAY_KEY_ID,
        transport_nonce="m4g-invalid-permit-outer-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        private_key=artifacts.gateway_private,
    )
    assert not outer_resigned.verify_complete_for_ot(
        artifacts.gateway_public,
        **admission,
    )


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "match"),
    [
        (NOW.replace(tzinfo=None), NOW + timedelta(seconds=1), "timezone-aware"),
        (NOW, NOW, "follow issuance"),
        (
            NOW,
            NOW + MAX_SIGNED_CALL_TTL + timedelta(microseconds=1),
            "registered maximum",
        ),
    ],
)
def test_dispatch_envelope_rejects_invalid_time_windows(
    artifacts: ContractArtifacts,
    issued_at: datetime,
    expires_at: datetime,
    match: str,
) -> None:
    with pytest.raises(ValidationError, match=match):
        SignedSegmentedCapabilityDispatch.issue(
            dispatch=artifacts.dispatch,
            gateway_key_id=GATEWAY_KEY_ID,
            transport_nonce="m4g-invalid-window-nonce-0001",
            issued_at=issued_at,
            expires_at=expires_at,
            private_key=artifacts.gateway_private,
        )

    assert not artifacts.envelope.verify_for_admission(
        artifacts.gateway_public,
        expected_audience=OT_CAPABILITY_AUDIENCE,
        expected_gateway_key_id=GATEWAY_KEY_ID,
        evaluated_at=artifacts.envelope.expires_at,
    )
    assert not artifacts.envelope.verify_for_admission(
        artifacts.gateway_public,
        expected_audience=OT_CAPABILITY_AUDIENCE,
        expected_gateway_key_id=GATEWAY_KEY_ID,
        evaluated_at=NOW.replace(tzinfo=None),
    )


def test_dispatch_rejects_cross_artifact_substitution_and_naive_decision_time(
    artifacts: ContractArtifacts,
) -> None:
    substitutions: tuple[dict[str, Any], ...] = (
        {
            "request": artifacts.dispatch.request.model_copy(
                update={"observation_envelope_digest": "1" * 64}
            )
        },
        {
            "assessment": artifacts.dispatch.assessment.model_copy(
                update={"command_digest": "2" * 64}
            )
        },
        {
            "permit": artifacts.dispatch.permit.model_copy(
                update={"request_digest": "3" * 64}
            )
        },
        {
            "decision": artifacts.dispatch.decision.model_copy(
                update={"decided_at": NOW.replace(tzinfo=None)}
            )
        },
    )
    for update in substitutions:
        with pytest.raises(ValidationError, match="bindings"):
            SegmentedCapabilityDispatch(
                request=update.get("request", artifacts.dispatch.request),
                pre_observation=artifacts.dispatch.pre_observation,
                decision=update.get("decision", artifacts.dispatch.decision),
                assessment=update.get("assessment", artifacts.dispatch.assessment),
                permit=update.get("permit", artifacts.dispatch.permit),
            )


def test_signed_ot_response_round_trip_and_exact_request_binding(
    artifacts: ContractArtifacts,
) -> None:
    response = SignedSegmentedCapabilityResponse.model_validate_json(
        artifacts.response.model_dump_json()
    )
    assert response == artifacts.response
    assert response.request_sha256 == artifacts.envelope.digest
    assert response.digest == canonical_digest(response)
    assert response.verify_for_request(
        artifacts.ot_public,
        request=artifacts.envelope,
        expected_ot_key_id=OT_KEY_ID,
    )
    assert response.verify_complete_for_request(
        artifacts.ot_public,
        request=artifacts.envelope,
        expected_ot_key_id=OT_KEY_ID,
        plc_public_key=artifacts.plc_public,
        expected_plc_id=artifacts.acknowledgment.plc_id,
        expected_plc_key_id=artifacts.acknowledgment.plc_key_id,
        expected_plc_boot_epoch=artifacts.acknowledgment.plc_boot_epoch,
        evaluated_at=NOW + timedelta(seconds=1),
    )
    assert not response.verify_for_request(
        artifacts.gateway_public,
        request=artifacts.envelope,
        expected_ot_key_id=OT_KEY_ID,
    )

    changed_ack = artifacts.acknowledgment.model_copy(update={"request_digest": "4" * 64})
    changed_response = response.model_copy(update={"acknowledgment": changed_ack})
    assert not changed_response.verify_for_request(
        artifacts.ot_public,
        request=artifacts.envelope,
        expected_ot_key_id=OT_KEY_ID,
    )
    with pytest.raises(ValueError, match="not bound"):
        SignedSegmentedCapabilityResponse.issue(
            request=artifacts.envelope,
            acknowledgment=changed_ack,
            ot_key_id=OT_KEY_ID,
            signed_at=NOW,
            private_key=artifacts.ot_private,
        )

    altered_time = response.model_copy(update={"signed_at": NOW + timedelta(seconds=2)})
    assert not altered_time.verify(artifacts.ot_public)


def test_complete_ot_response_verification_rejects_resigned_invalid_ack_and_chronology(
    artifacts: ContractArtifacts,
) -> None:
    invalid_ack = artifacts.acknowledgment.model_copy(update={"signature": ""})
    outer = artifacts.response.model_copy(
        update={"acknowledgment": invalid_ack, "signature": ""}
    )
    outer = outer.model_copy(
        update={"signature": sign_bytes(artifacts.ot_private, outer.signing_payload())}
    )
    assert outer.verify_for_request(
        artifacts.ot_public,
        request=artifacts.envelope,
        expected_ot_key_id=OT_KEY_ID,
    )
    assert not outer.verify_complete_for_request(
        artifacts.ot_public,
        request=artifacts.envelope,
        expected_ot_key_id=OT_KEY_ID,
        plc_public_key=artifacts.plc_public,
        expected_plc_id=artifacts.acknowledgment.plc_id,
        expected_plc_key_id=artifacts.acknowledgment.plc_key_id,
        expected_plc_boot_epoch=artifacts.acknowledgment.plc_boot_epoch,
        evaluated_at=NOW + timedelta(seconds=1),
    )

    future_ack = artifacts.acknowledgment.model_copy(
        update={"acknowledged_at": NOW + timedelta(seconds=2), "signature": ""}
    )
    future_ack = future_ack.model_copy(
        update={"signature": sign_bytes(artifacts.plc_private, future_ack.signing_payload())}
    )
    with pytest.raises(ValueError, match="chronology"):
        SignedSegmentedCapabilityResponse.issue(
            request=artifacts.envelope,
            acknowledgment=future_ack,
            ot_key_id=OT_KEY_ID,
            signed_at=NOW + timedelta(seconds=1),
            private_key=artifacts.ot_private,
        )

    future_response = SignedSegmentedCapabilityResponse.issue(
        request=artifacts.envelope,
        acknowledgment=artifacts.acknowledgment,
        ot_key_id=OT_KEY_ID,
        signed_at=NOW + timedelta(seconds=10),
        private_key=artifacts.ot_private,
    )
    assert not future_response.verify_complete_for_request(
        artifacts.ot_public,
        request=artifacts.envelope,
        expected_ot_key_id=OT_KEY_ID,
        plc_public_key=artifacts.plc_public,
        expected_plc_id=artifacts.acknowledgment.plc_id,
        expected_plc_key_id=artifacts.acknowledgment.plc_key_id,
        expected_plc_boot_epoch=artifacts.acknowledgment.plc_boot_epoch,
        evaluated_at=NOW + timedelta(seconds=1),
    )


def test_segmented_closed_loop_result_has_distinct_backend_and_inherited_shape(
    artifacts: ContractArtifacts,
) -> None:
    result = SegmentedCapabilityClosedLoopResult(
        status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
        reasons=("authorization_rejected",),
        request=artifacts.dispatch.request,
        dispatch_attempts=0,
        execution_evidence_hash=canonical_digest({"terminal": "not-dispatched"}),
    )
    decoded = SegmentedCapabilityClosedLoopResult.model_validate_json(
        result.model_dump_json()
    )

    assert decoded == result
    assert decoded.schema_version == "segmented-capability-closed-loop-result-v1"
    assert decoded.coordination_backend == "segmented-compose-http-v1"

    with pytest.raises(ValidationError, match="not-dispatched"):
        SegmentedCapabilityClosedLoopResult(
            status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
            reasons=("invalid_terminal_shape",),
            request=artifacts.dispatch.request,
            permit=artifacts.dispatch.permit,
            dispatch_attempts=1,
            execution_evidence_hash=canonical_digest({"terminal": "invalid"}),
        )

    with pytest.raises(ValidationError):
        SegmentedCapabilityClosedLoopResult.model_validate(
            {
                **result.model_dump(mode="python"),
                "coordination_backend": "deterministic-local-v1",
            }
        )


def _plant_payloads(
    artifacts: ContractArtifacts,
) -> tuple[
    tuple[
        PlantCallerRole,
        PlantOperation,
        PlantCapturePayload
        | PlantReadPayload
        | PlantSimulatePayload
        | PlantApplyPayload,
    ],
    ...,
]:
    dispatch = artifacts.dispatch
    base = dispatch.permit.base_permit
    return (
        (
            PlantCallerRole.OBSERVER,
            PlantOperation.CAPTURE,
            PlantCapturePayload(
                correlation_id=dispatch.request.correlation_id,
                challenge_nonce="m4g-plant-capture-challenge-0001",
            ),
        ),
        (
            PlantCallerRole.PLC,
            PlantOperation.READ,
            PlantReadPayload(correlation_id=dispatch.request.correlation_id),
        ),
        (
            PlantCallerRole.CANDIDATE,
            PlantOperation.SIMULATE,
            PlantSimulatePayload(command=base.command),
        ),
        (
            PlantCallerRole.PLC,
            PlantOperation.READ,
            PlantReadPayload(correlation_id="m4g-plc-precommit-read"),
        ),
        (
            PlantCallerRole.PLC,
            PlantOperation.SIMULATE,
            PlantSimulatePayload(command=base.command),
        ),
        (
            PlantCallerRole.PLC,
            PlantOperation.APPLY,
            PlantApplyPayload(
                command=base.command,
                expected_pre_state_version=base.state_version,
                expected_pre_state_digest=base.state_digest,
                expected_pre_observation_digest=base.observation_digest,
                expected_post_state_digest=base.expected_post_state_digest,
                expected_post_topology_digest=base.expected_post_topology_digest,
                authorization_expires_at=base.expires_at,
            ),
        ),
    )


def test_all_registered_plant_role_operations_sign_round_trip_and_hash(
    artifacts: ContractArtifacts,
) -> None:
    caller_private, caller_public = generate_keypair()
    for index, (role, operation, payload) in enumerate(_plant_payloads(artifacts)):
        call = SignedPlantCall.issue(
            role=role,
            operation=operation,
            payload=payload,
            caller_key_id=f"m4g-{role.value}-key",
            target_plant_key_id=PLANT_KEY_ID,
            target_plant_boot_epoch=PLANT_BOOT_EPOCH,
            call_nonce=f"m4g-plant-call-nonce-{index:04d}",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=5),
            private_key=caller_private,
        )
        decoded = SignedPlantCall.model_validate_json(call.model_dump_json())
        assert decoded == call
        assert decoded.payload_sha256 == canonical_digest(payload)
        assert decoded.digest == canonical_digest(decoded)
        assert decoded.verify_for_plant(
            caller_public,
            expected_role=role,
            expected_caller_key_id=f"m4g-{role.value}-key",
            expected_audience=PHYSICAL_PLANT_AUDIENCE,
            expected_plant_key_id=PLANT_KEY_ID,
            expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
            evaluated_at=NOW,
        )


def test_signed_plant_success_responses_cover_each_operation_and_exact_call(
    artifacts: ContractArtifacts,
) -> None:
    caller_private, _ = generate_keypair()
    pre_state = artifacts.dispatch.pre_observation.snapshot
    assessment = artifacts.dispatch.assessment
    for index, (role, operation, payload) in enumerate(_plant_payloads(artifacts)):
        call = SignedPlantCall.issue(
            role=role,
            operation=operation,
            payload=payload,
            caller_key_id=f"m4g-{role.value}-response-key",
            target_plant_key_id=PLANT_KEY_ID,
            target_plant_boot_epoch=PLANT_BOOT_EPOCH,
            call_nonce=f"m4g-response-call-nonce-{index:04d}",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=5),
            private_key=caller_private,
        )
        if operation is PlantOperation.SIMULATE:
            response_payload: (
                PlantStateResponsePayload | PlantSimulationResponsePayload
            ) = PlantSimulationResponsePayload(assessment=assessment)
        elif operation is PlantOperation.APPLY:
            response_payload = PlantStateResponsePayload(snapshot=assessment.post_state)
        else:
            response_payload = PlantStateResponsePayload(snapshot=pre_state)
        response = SignedPlantResponse.issue(
            call=call,
            status=PlantResponseStatus.OK,
            payload=response_payload,
            plant_boot_epoch=PLANT_BOOT_EPOCH,
            plant_key_id=PLANT_KEY_ID,
            signed_at=NOW + timedelta(seconds=1),
            private_key=artifacts.plant_private,
        )
        decoded = SignedPlantResponse.model_validate_json(response.model_dump_json())

        assert decoded == response
        assert decoded.call_sha256 == call.digest
        assert decoded.digest == canonical_digest(decoded)
        assert decoded.verify_for_call(
            artifacts.plant_public,
            call=call,
            expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
            expected_plant_key_id=PLANT_KEY_ID,
        )


def test_signed_plant_negative_responses_are_closed_and_bound(
    artifacts: ContractArtifacts,
) -> None:
    caller_private, _ = generate_keypair()
    call = SignedPlantCall.issue(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.READ,
        payload=PlantReadPayload(correlation_id="m4g-negative-read"),
        caller_key_id="m4g-negative-plc-key",
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT_EPOCH,
        call_nonce="m4g-negative-call-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        private_key=caller_private,
    )
    for status in (PlantResponseStatus.REJECTED, PlantResponseStatus.ERROR):
        payload = PlantFailureResponsePayload(
            status=status,
            reason=f"bounded_{status.value}_reason",
        )
        response = SignedPlantResponse.issue(
            call=call,
            status=status,
            payload=payload,
            plant_boot_epoch=PLANT_BOOT_EPOCH,
            plant_key_id=PLANT_KEY_ID,
            signed_at=NOW + timedelta(seconds=1),
            private_key=artifacts.plant_private,
        )

        assert SignedPlantResponse.model_validate_json(response.model_dump_json()) == response
        assert response.verify_for_call(
            artifacts.plant_public,
            call=call,
            expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
            expected_plant_key_id=PLANT_KEY_ID,
        )


def test_candidate_exchange_verifies_candidate_and_plant_signatures(
    artifacts: ContractArtifacts,
) -> None:
    candidate_private, candidate_public = generate_keypair()
    call = SignedPlantCall.issue(
        role=PlantCallerRole.CANDIDATE,
        operation=PlantOperation.SIMULATE,
        payload=PlantSimulatePayload(command=artifacts.command),
        caller_key_id="m4g-candidate-key-1",
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT_EPOCH,
        call_nonce="m4g-candidate-call-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        private_key=candidate_private,
    )
    response = SignedPlantResponse.issue(
        call=call,
        status=PlantResponseStatus.OK,
        payload=PlantSimulationResponsePayload(
            assessment=artifacts.dispatch.assessment
        ),
        plant_boot_epoch=PLANT_BOOT_EPOCH,
        plant_key_id=PLANT_KEY_ID,
        signed_at=NOW + timedelta(seconds=1),
        private_key=artifacts.plant_private,
    )
    exchange = PlantExchange(call=call, response=response)
    decoded = PlantExchange.model_validate_json(exchange.model_dump_json())

    assert decoded == exchange
    assert decoded.digest == canonical_digest(decoded)
    assert decoded.verify(
        candidate_public,
        artifacts.plant_public,
        expected_role=PlantCallerRole.CANDIDATE,
        expected_caller_key_id="m4g-candidate-key-1",
        expected_audience=PHYSICAL_PLANT_AUDIENCE,
        expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
        expected_plant_key_id=PLANT_KEY_ID,
        evaluated_at=NOW,
    )
    assert not decoded.verify(
        artifacts.gateway_public,
        artifacts.plant_public,
        expected_role=PlantCallerRole.CANDIDATE,
        expected_caller_key_id="m4g-candidate-key-1",
        expected_audience=PHYSICAL_PLANT_AUDIENCE,
        expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
        expected_plant_key_id=PLANT_KEY_ID,
        evaluated_at=NOW,
    )

    retained = SegmentedCapabilityClosedLoopResult(
        status=CapabilityClosedLoopStatus.CANDIDATE_REJECTED,
        reasons=("candidate_binding_mismatch",),
        request=artifacts.dispatch.request,
        pre_observation=artifacts.dispatch.pre_observation,
        decision=artifacts.dispatch.decision,
        command=artifacts.command,
        assessment=artifacts.dispatch.assessment,
        candidate_exchange=decoded,
        dispatch_attempts=0,
        execution_evidence_hash=canonical_digest({"retained": decoded.digest}),
    )
    assert SegmentedCapabilityClosedLoopResult.model_validate_json(
        retained.model_dump_json()
    ).candidate_exchange == decoded
    with pytest.raises(ValidationError, match="plant response is not bound"):
        SegmentedCapabilityClosedLoopResult(
            **{
                **retained.model_dump(mode="python"),
                "candidate_exchange": decoded.model_copy(
                    update={
                        "response": decoded.response.model_copy(
                            update={
                                "payload": PlantSimulationResponsePayload(
                                    assessment=artifacts.dispatch.assessment.model_copy(
                                        update={"command_digest": "7" * 64}
                                    )
                                )
                            }
                        )
                    }
                ),
            }
        )


@pytest.mark.parametrize(
    ("role", "operation", "payload"),
    [
        (
            PlantCallerRole.OBSERVER,
            PlantOperation.READ,
            PlantReadPayload(correlation_id="forbidden-observer-read"),
        ),
        (
            PlantCallerRole.CANDIDATE,
            PlantOperation.APPLY,
            PlantReadPayload(correlation_id="forbidden-candidate-apply"),
        ),
        (
            PlantCallerRole.PLC,
            PlantOperation.CAPTURE,
            PlantCapturePayload(
                correlation_id="forbidden-plc-capture",
                challenge_nonce="forbidden-plc-capture-nonce",
            ),
        ),
        (
            PlantCallerRole.PLC,
            PlantOperation.READ,
            PlantCapturePayload(
                correlation_id="wrong-payload-for-read",
                challenge_nonce="wrong-payload-for-read-nonce",
            ),
        ),
    ],
)
def test_plant_calls_reject_wrong_role_operation_and_payload(
    role: PlantCallerRole,
    operation: PlantOperation,
    payload: PlantCapturePayload | PlantReadPayload,
) -> None:
    with pytest.raises(ValidationError, match="not authorized"):
        SignedPlantCall.issue(
            role=role,
            operation=operation,
            payload=payload,
            caller_key_id="m4g-forbidden-caller-key",
            target_plant_key_id=PLANT_KEY_ID,
            target_plant_boot_epoch=PLANT_BOOT_EPOCH,
            call_nonce="m4g-forbidden-call-nonce-0001",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=5),
            private_key=Ed25519PrivateKey.generate(),
        )


def test_plant_call_signature_rejects_payload_role_and_audience_tamper(
    artifacts: ContractArtifacts,
) -> None:
    caller_private, caller_public = generate_keypair()
    payload = PlantReadPayload(correlation_id="m4g-plant-read-correlation")
    call = SignedPlantCall.issue(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.READ,
        payload=payload,
        caller_key_id="m4g-plc-caller-key",
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT_EPOCH,
        call_nonce="m4g-plant-read-call-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        private_key=caller_private,
    )
    changed_payload = payload.model_copy(update={"correlation_id": "altered-correlation"})
    assert not call.model_copy(update={"payload": changed_payload}).verify(caller_public)
    assert not call.model_copy(update={"role": PlantCallerRole.OBSERVER}).verify(
        caller_public
    )
    assert not call.model_copy(update={"audience": "wrong-plant"}).verify(caller_public)
    assert not call.verify_for_plant(
        caller_public,
        expected_role=PlantCallerRole.PLC,
        expected_caller_key_id="m4g-plc-caller-key",
        expected_audience="wrong-plant",
        expected_plant_key_id=PLANT_KEY_ID,
        expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
        evaluated_at=NOW,
    )
    assert not call.verify_for_plant(
        caller_public,
        expected_role=PlantCallerRole.PLC,
        expected_caller_key_id="m4g-plc-caller-key",
        expected_audience=PHYSICAL_PLANT_AUDIENCE,
        expected_plant_key_id=PLANT_KEY_ID,
        expected_plant_boot_epoch="replacement-plant-boot-epoch-0002",
        evaluated_at=NOW,
    )
    assert not call.model_copy(
        update={"target_plant_boot_epoch": "replacement-plant-boot-epoch-0002"}
    ).verify(caller_public)

    changed_hash = call.model_dump(mode="json")
    changed_hash["payload"]["correlation_id"] = "altered-correlation"
    with pytest.raises(ValidationError, match="hash"):
        SignedPlantCall.model_validate_json(json.dumps(changed_hash))


def test_plant_response_rejects_tamper_wrong_identity_and_call_substitution(
    artifacts: ContractArtifacts,
) -> None:
    caller_private, _ = generate_keypair()
    call = SignedPlantCall.issue(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.READ,
        payload=PlantReadPayload(correlation_id="m4g-bound-read"),
        caller_key_id="m4g-bound-plc-key",
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT_EPOCH,
        call_nonce="m4g-bound-read-call-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        private_key=caller_private,
    )
    response = SignedPlantResponse.issue(
        call=call,
        status=PlantResponseStatus.OK,
        payload=PlantStateResponsePayload(
            snapshot=artifacts.dispatch.pre_observation.snapshot
        ),
        plant_boot_epoch=PLANT_BOOT_EPOCH,
        plant_key_id=PLANT_KEY_ID,
        signed_at=NOW + timedelta(seconds=1),
        private_key=artifacts.plant_private,
    )
    wrong_public = Ed25519PrivateKey.generate().public_key()

    assert not response.verify(wrong_public)
    assert not response.verify_for_call(
        artifacts.plant_public,
        call=call,
        expected_plant_boot_epoch="wrong-plant-boot-epoch",
        expected_plant_key_id=PLANT_KEY_ID,
    )
    assert not response.verify_for_call(
        artifacts.plant_public,
        call=call,
        expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
        expected_plant_key_id="wrong-plant-key",
    )

    changed_call = call.model_copy(
        update={
            "payload": PlantReadPayload(correlation_id="substituted-read"),
            "payload_sha256": canonical_digest(
                PlantReadPayload(correlation_id="substituted-read")
            ),
        }
    )
    assert not response.verify_for_call(
        artifacts.plant_public,
        call=changed_call,
        expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
        expected_plant_key_id=PLANT_KEY_ID,
    )
    with pytest.raises(ValidationError, match="exact signed call"):
        PlantExchange(call=changed_call, response=response)

    changed_payload = PlantStateResponsePayload(
        snapshot=artifacts.dispatch.assessment.post_state
    )
    assert not response.model_copy(update={"payload": changed_payload}).verify(
        artifacts.plant_public
    )
    assert not response.model_copy(update={"call_sha256": "5" * 64}).verify_for_call(
        artifacts.plant_public,
        call=call,
        expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
        expected_plant_key_id=PLANT_KEY_ID,
    )

    before_call = SignedPlantResponse.issue(
        call=call,
        status=PlantResponseStatus.ERROR,
        payload=PlantFailureResponsePayload(
            status=PlantResponseStatus.ERROR,
            reason="clock_precedes_call",
        ),
        plant_boot_epoch=PLANT_BOOT_EPOCH,
        plant_key_id=PLANT_KEY_ID,
        signed_at=NOW - timedelta(microseconds=1),
        private_key=artifacts.plant_private,
    )
    assert not before_call.verify_for_call(
        artifacts.plant_public,
        call=call,
        expected_plant_boot_epoch=PLANT_BOOT_EPOCH,
        expected_plant_key_id=PLANT_KEY_ID,
    )
    with pytest.raises(ValidationError, match="exact signed call"):
        PlantExchange(call=call, response=before_call)


def test_plant_response_rejects_wrong_typed_payload_status_time_and_semantics(
    artifacts: ContractArtifacts,
) -> None:
    caller_private, _ = generate_keypair()
    simulate_call = SignedPlantCall.issue(
        role=PlantCallerRole.CANDIDATE,
        operation=PlantOperation.SIMULATE,
        payload=PlantSimulatePayload(command=artifacts.command),
        caller_key_id="m4g-candidate-shape-key",
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT_EPOCH,
        call_nonce="m4g-candidate-shape-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        private_key=caller_private,
    )
    with pytest.raises(ValidationError, match="operation and status"):
        SignedPlantResponse.issue(
            call=simulate_call,
            status=PlantResponseStatus.OK,
            payload=PlantStateResponsePayload(
                snapshot=artifacts.dispatch.pre_observation.snapshot
            ),
            plant_boot_epoch=PLANT_BOOT_EPOCH,
            plant_key_id=PLANT_KEY_ID,
            signed_at=NOW,
            private_key=artifacts.plant_private,
        )

    wrong_assessment = artifacts.dispatch.assessment.model_copy(
        update={"command_digest": "6" * 64}
    )
    with pytest.raises(ValueError, match="signed call"):
        SignedPlantResponse.issue(
            call=simulate_call,
            status=PlantResponseStatus.OK,
            payload=PlantSimulationResponsePayload(assessment=wrong_assessment),
            plant_boot_epoch=PLANT_BOOT_EPOCH,
            plant_key_id=PLANT_KEY_ID,
            signed_at=NOW,
            private_key=artifacts.plant_private,
        )

    with pytest.raises(ValidationError, match="operation and status"):
        SignedPlantResponse.issue(
            call=simulate_call,
            status=PlantResponseStatus.REJECTED,
            payload=PlantFailureResponsePayload(
                status=PlantResponseStatus.ERROR,
                reason="mismatched_status",
            ),
            plant_boot_epoch=PLANT_BOOT_EPOCH,
            plant_key_id=PLANT_KEY_ID,
            signed_at=NOW,
            private_key=artifacts.plant_private,
        )

    with pytest.raises(ValidationError, match="timezone-aware"):
        SignedPlantResponse.issue(
            call=simulate_call,
            status=PlantResponseStatus.ERROR,
            payload=PlantFailureResponsePayload(
                status=PlantResponseStatus.ERROR,
                reason="naive_time",
            ),
            plant_boot_epoch=PLANT_BOOT_EPOCH,
            plant_key_id=PLANT_KEY_ID,
            signed_at=NOW.replace(tzinfo=None),
            private_key=artifacts.plant_private,
        )


def test_plant_calls_reject_invalid_windows_extra_fields_strict_numbers_and_nan(
    artifacts: ContractArtifacts,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = PlantReadPayload(correlation_id="m4g-plant-read-window")
    with pytest.raises(ValidationError, match="registered maximum"):
        SignedPlantCall.issue(
            role=PlantCallerRole.PLC,
            operation=PlantOperation.READ,
            payload=payload,
            caller_key_id="m4g-plc-caller-key",
            target_plant_key_id=PLANT_KEY_ID,
            target_plant_boot_epoch=PLANT_BOOT_EPOCH,
            call_nonce="m4g-plant-window-call-nonce-0001",
            issued_at=NOW,
            expires_at=NOW + MAX_SIGNED_CALL_TTL + timedelta(seconds=1),
            private_key=private_key,
        )

    with pytest.raises(ValidationError, match="Extra inputs"):
        PlantReadPayload.model_validate(
            {
                "schema_version": "m4g-plant-read-v1",
                "correlation_id": "m4g-read-extra",
                "extra": "rejected",
            }
        )

    with pytest.raises(ValidationError, match="Extra inputs"):
        PlantSimulatePayload.model_validate(
            {
                "schema_version": "m4g-plant-simulate-v1",
                "request_digest": artifacts.dispatch.request.digest,
                "command": artifacts.command,
            }
        )

    apply_payload = _plant_payloads(artifacts)[-1][2]
    assert isinstance(apply_payload, PlantApplyPayload)
    apply_data = apply_payload.model_dump(mode="python")
    with pytest.raises(ValidationError, match="Extra inputs"):
        PlantApplyPayload.model_validate(
            {
                **apply_data,
                "request_digest": artifacts.dispatch.request.digest,
                "permit_digest": artifacts.dispatch.permit.digest,
            }
        )
    apply_data["expected_pre_state_version"] = 1.0
    with pytest.raises(ValidationError):
        PlantApplyPayload.model_validate(apply_data)

    command_data = artifacts.command.model_dump(mode="json")
    command_data["setpoint"] = float("nan")
    simulate_data = {
        "schema_version": "m4g-plant-simulate-v1",
        "command": command_data,
    }
    with pytest.raises(ValidationError):
        PlantSimulatePayload.model_validate_json(
            json.dumps(simulate_data, separators=(",", ":"), allow_nan=True)
        )

    with pytest.raises(ValidationError):
        SignedPlantCall.model_validate(
            {
                "schema_version": "m4g-signed-plant-call-v1",
                "role": "gateway",
                "operation": PlantOperation.SIMULATE,
                "payload": PlantSimulatePayload(command=artifacts.command),
                "payload_sha256": canonical_digest(
                    PlantSimulatePayload(command=artifacts.command)
                ),
                "audience": PHYSICAL_PLANT_AUDIENCE,
                "caller_key_id": "m4g-obsolete-gateway-key",
                "call_nonce": "m4g-obsolete-gateway-nonce-0001",
                "issued_at": NOW,
                "expires_at": NOW + timedelta(seconds=5),
                "signature": "",
            }
        )
