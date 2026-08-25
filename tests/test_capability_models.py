from __future__ import annotations

import json
import multiprocessing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ValidationError

from aegis_ot.capability_ipc import (
    MAX_FRAME_BYTES,
    IpcOutcomeUnknownError,
    IpcProtocolError,
    IpcRequestFrame,
    IpcResponseFrame,
    IpcTransportError,
    JsonPipeClient,
    decode_frame,
    encode_frame,
)
from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopResult,
    CapabilityClosedLoopStatus,
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
from aegis_ot.physical_control import TrustedCommandTranslator, physical_state_to_gateway_state
from aegis_ot.physical_factory import build_physical_local_lab
from aegis_ot.physical_models import (
    CandidateAssessment,
    CommandStatus,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
)
from aegis_ot.replay_lock_probe import probe_semantic_writer

NOW = datetime(2026, 8, 24, 16, 0, tzinfo=UTC)
OBSERVER_CHALLENGE = "observer-pre-challenge-0001"
POST_CHALLENGE = "observer-post-challenge-0001"
PLC_ID = "plc:deterministic-local"
PLC_KEY_ID = "plc-key-1"
PLC_BOOT_EPOCH = "plc-boot-epoch-0000001"


def test_replay_ledger_rejects_noncanonical_and_unsafe_files(tmp_path: Path) -> None:
    path = tmp_path / "replay.json"
    valid = {
        "command_ids": [],
        "permit_ids": [],
        "permit_nonces": [],
        "request_digests": [],
    }
    hostile_values = (
        {**valid, "unexpected": []},
        {**valid, "permit_ids": ["duplicate", "duplicate"]},
    )
    for value in hostile_values:
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(ValueError, match="unexpected|invalid reservation"):
            OrderlyRestartReplayReservations(path)

    path.write_text(
        '{"command_ids":[],"permit_ids":[],"permit_ids":[],"permit_nonces":[],'
        '"request_digests":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate key"):
        OrderlyRestartReplayReservations(path)


def test_replay_ledger_persists_canonical_mode_and_survives_reload(tmp_path: Path) -> None:
    path = tmp_path / "replay.json"
    ledger = OrderlyRestartReplayReservations(path, initialize=True)
    ledger.reserve(
        request_digest="1" * 64,
        permit_id="permit-1",
        permit_nonce="permit-nonce-1",
        command_id="command-1",
    )

    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "command_ids": ["command-1"],
        "permit_ids": ["permit-1"],
        "permit_nonces": ["permit-nonce-1"],
        "request_digests": ["1" * 64],
    }
    ledger.close()
    reloaded = OrderlyRestartReplayReservations(path)
    assert reloaded.replay_reason(
        request_digest="1" * 64,
        permit_id="permit-1",
        permit_nonce="permit-nonce-1",
        command_id="command-1",
    ) == "transaction_replayed"
    reloaded.close()


def test_initialized_replay_ledger_missing_state_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "replay.json"
    with OrderlyRestartReplayReservations(path, initialize=True) as ledger:
        writer_lock_path = ledger.writer_lock_path

    path.unlink()

    assert writer_lock_path.is_file()
    with pytest.raises(ValueError, match="missing or unavailable"):
        OrderlyRestartReplayReservations(path)


def test_semantic_replay_writer_lock_rejects_a_second_process_until_close(
    tmp_path: Path,
) -> None:
    path = tmp_path / "replay.json"
    ledger = OrderlyRestartReplayReservations(path, initialize=True)
    context = multiprocessing.get_context("spawn")

    blocked_reader, blocked_writer = context.Pipe(duplex=False)
    blocked = context.Process(
        target=probe_semantic_writer,
        args=(str(path), blocked_writer),
    )
    blocked.start()
    blocked_writer.close()
    assert blocked_reader.poll(10)
    assert blocked_reader.recv() == (
        "error",
        "PLC replay writer lock is already held or unavailable",
    )
    blocked_reader.close()
    blocked.join(10)
    assert blocked.exitcode == 0

    ledger.close()
    acquired_reader, acquired_writer = context.Pipe(duplex=False)
    acquired = context.Process(
        target=probe_semantic_writer,
        args=(str(path), acquired_writer),
    )
    acquired.start()
    acquired_writer.close()
    assert acquired_reader.poll(10)
    assert acquired_reader.recv() == ("acquired", "")
    acquired_reader.close()
    acquired.join(10)
    assert acquired.exitcode == 0


@dataclass(frozen=True)
class CapabilityArtifacts:
    permit_private_key: Ed25519PrivateKey
    permit_public_key: Ed25519PublicKey
    observer_private_key: Ed25519PrivateKey
    observer_public_key: Ed25519PublicKey
    plc_private_key: Ed25519PrivateKey
    plc_public_key: Ed25519PublicKey
    pre_state: PhysicalStateSnapshot
    proposal: ActionProposal
    decision: Decision
    command: PhysicalControlCommand
    assessment: CandidateAssessment
    pre_observation: SignedObservationEnvelope
    request: CapabilityActionRequest
    permit: CapabilityExecutionPermit
    acknowledgment: PlcCommandAcknowledgment
    post_observation: SignedObservationEnvelope
    completed_result: CapabilityClosedLoopResult


class _ObservationRacePlant:
    def __init__(
        self,
        pre_state: PhysicalStateSnapshot,
        changed_state: PhysicalStateSnapshot,
        assessment: CandidateAssessment,
    ) -> None:
        self.pre_state = pre_state
        self.changed_state = changed_state
        self.assessment = assessment
        self.apply_attempted = False
        self.apply_kwargs: dict[str, Any] = {}

    def read_state(self) -> PhysicalStateSnapshot:
        return self.changed_state if self.apply_attempted else self.pre_state

    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
        assert command.digest == self.assessment.command_digest
        return self.assessment

    def apply_authorized_command(
        self,
        command: PhysicalControlCommand,
        **kwargs: Any,
    ) -> PhysicalStateSnapshot:
        assert command.digest == self.assessment.command_digest
        self.apply_kwargs = dict(kwargs)
        self.apply_attempted = True
        raise PhysicalSimulationError("precommit_observation_changed")


@pytest.fixture(scope="module")
def artifacts() -> CapabilityArtifacts:
    lab = build_physical_local_lab(NOW)
    pre_state = lab.plant.read_state()
    proposal = ActionProposal(
        proposal_id="capability-model-proposal",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=pre_state.state_version,
        observed_at=pre_state.observed_at,
        submitted_at=pre_state.observed_at,
        nonce="capability-model-proposal-nonce-0001",
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
    permit_private_key = lab.controller.permit_issuer.private_key
    observer_private_key, observer_public_key = generate_keypair()
    plc_private_key, plc_public_key = generate_keypair()
    pre_observation = SignedObservationEnvelope.issue(
        snapshot=pre_state,
        correlation_id="capability-correlation-1",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce=OBSERVER_CHALLENGE,
        observer_id="observer:deterministic-local",
        observer_key_id="observer-key-1",
        observer_boot_epoch="observer-boot-epoch-0001",
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=observer_private_key,
    )
    request = CapabilityActionRequest(
        request_id="capability-request-1",
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
        target_plc_key_id=PLC_KEY_ID,
        target_plc_boot_epoch=PLC_BOOT_EPOCH,
        signing_key_id=base_permit.signing_key_id,
    ).signed(permit_private_key)
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
        plc_key_id=PLC_KEY_ID,
        plc_boot_epoch=PLC_BOOT_EPOCH,
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
    ).signed(plc_private_key)
    post_observation = SignedObservationEnvelope.issue(
        snapshot=post_state,
        correlation_id=request.correlation_id,
        phase=ObservationPhase.POST_DISPATCH,
        challenge_nonce=POST_CHALLENGE,
        observer_id=pre_observation.observer_id,
        observer_key_id=pre_observation.observer_key_id,
        observer_boot_epoch=pre_observation.observer_boot_epoch,
        observer_sequence=2,
        previous_envelope_digest=pre_observation.envelope_digest,
        permit_id=base_permit.permit_id,
        command_digest=command.digest,
        plc_acknowledgment_digest=acknowledgment.digest,
        private_key=observer_private_key,
    )
    completed_result = CapabilityClosedLoopResult(
        status=CapabilityClosedLoopStatus.COMPLETED,
        reasons=("command_applied_acknowledged_and_separately_observer_captured",),
        request=request,
        pre_observation=pre_observation,
        decision=decision,
        command=command,
        assessment=assessment,
        permit=permit,
        acknowledgment=acknowledgment,
        post_observation=post_observation,
        last_observation=post_observation,
        dispatch_attempts=1,
        execution_evidence_hash="a" * 64,
    )
    return CapabilityArtifacts(
        permit_private_key=permit_private_key,
        permit_public_key=lab.permit_public_key,
        observer_private_key=observer_private_key,
        observer_public_key=observer_public_key,
        plc_private_key=plc_private_key,
        plc_public_key=plc_public_key,
        pre_state=pre_state,
        proposal=proposal,
        decision=decision,
        command=command,
        assessment=assessment,
        pre_observation=pre_observation,
        request=request,
        permit=permit,
        acknowledgment=acknowledgment,
        post_observation=post_observation,
        completed_result=completed_result,
    )


def _model_data(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="python")


def _nonapplied_acknowledgment(
    artifacts: CapabilityArtifacts,
    *,
    status: CommandStatus,
    dispatch_phase: DispatchPhase,
    reason: str,
    acknowledged_at: datetime = NOW,
    pre_state: PhysicalStateSnapshot | None = None,
    plc_id: str = PLC_ID,
    plc_key_id: str = PLC_KEY_ID,
    plc_boot_epoch: str = PLC_BOOT_EPOCH,
    private_key: Ed25519PrivateKey | None = None,
) -> PlcCommandAcknowledgment:
    selected_pre_state = pre_state or artifacts.pre_state
    pre_setpoint = (
        0.0
        if artifacts.command.resource in selected_pre_state.isolated_resources
        else 1.0
    )
    data = _model_data(artifacts.acknowledgment)
    data.update(
        {
            "status": status,
            "dispatch_phase": dispatch_phase,
            "reason": reason,
            "acknowledged_at": acknowledged_at,
            "pre_state": selected_pre_state,
            "pre_state_digest": selected_pre_state.state_digest,
            "pre_state_version": selected_pre_state.state_version,
            "post_state_digest": None,
            "post_state_version": None,
            "post_topology_digest": None,
            "pre_actuator_setpoint": pre_setpoint,
            "post_actuator_setpoint": (
                pre_setpoint if status is CommandStatus.REJECTED else None
            ),
            "simulation_time_s": selected_pre_state.simulation_time_s,
            "plc_id": plc_id,
            "plc_key_id": plc_key_id,
            "plc_boot_epoch": plc_boot_epoch,
            "signature": "",
        }
    )
    return PlcCommandAcknowledgment.model_validate(data).signed(
        private_key or artifacts.plc_private_key
    )


def _rejected_acknowledgment(artifacts: CapabilityArtifacts) -> PlcCommandAcknowledgment:
    return _nonapplied_acknowledgment(
        artifacts,
        status=CommandStatus.REJECTED,
        dispatch_phase=DispatchPhase.KNOWN_NO_EFFECT,
        reason="compare_and_swap_rejected",
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


def _contradictory_post_observation(
    artifacts: CapabilityArtifacts,
    *,
    previous_envelope_digest: str | None = None,
) -> SignedObservationEnvelope:
    return SignedObservationEnvelope.issue(
        snapshot=artifacts.pre_state,
        correlation_id=artifacts.request.correlation_id,
        phase=ObservationPhase.POST_DISPATCH,
        challenge_nonce="observer-post-contradiction-0001",
        observer_id=artifacts.pre_observation.observer_id,
        observer_key_id=artifacts.pre_observation.observer_key_id,
        observer_boot_epoch=artifacts.pre_observation.observer_boot_epoch,
        observer_sequence=3,
        previous_envelope_digest=(
            previous_envelope_digest or artifacts.pre_observation.envelope_digest
        ),
        permit_id=artifacts.permit.base_permit.permit_id,
        command_digest=artifacts.command.digest,
        plc_acknowledgment_digest=artifacts.acknowledgment.digest,
        private_key=artifacts.observer_private_key,
    )


def test_ipc_request_and_response_frames_round_trip_as_canonical_json() -> None:
    first = IpcRequestFrame(
        request_id="ipc-request-1",
        operation="observe",
        payload={"b": 2, "a": 1},
        payload_digest=canonical_digest({"a": 1, "b": 2}),
    )
    reordered = IpcRequestFrame(
        request_id=first.request_id,
        operation=first.operation,
        payload={"a": 1, "b": 2},
        payload_digest=first.payload_digest,
    )
    encoded = encode_frame(first)
    assert encoded == encode_frame(reordered)
    assert decode_frame(encoded, IpcRequestFrame) == first

    response = IpcResponseFrame.create(
        first,
        status="ok",
        payload={"state": "ready"},
        error_code=None,
        server_boot_epoch="server-boot-epoch-0001",
        response_counter=1,
    )
    assert decode_frame(encode_frame(response), IpcResponseFrame) == response


def test_ipc_frames_reject_noncanonical_tampered_and_oversized_data() -> None:
    frame = IpcRequestFrame.create("observe", {"state": "ready"})
    noncanonical = json.dumps(frame.model_dump(mode="json"), indent=2).encode("utf-8")
    with pytest.raises(IpcProtocolError, match="canonical JSON form"):
        decode_frame(noncanonical, IpcRequestFrame)

    tampered = frame.model_dump(mode="json")
    tampered["payload"]["state"] = "changed"
    tampered_bytes = json.dumps(
        tampered,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    with pytest.raises(IpcProtocolError, match="structural validation"):
        decode_frame(tampered_bytes, IpcRequestFrame)

    oversized = IpcRequestFrame.create("observe", {"blob": "x" * MAX_FRAME_BYTES})
    with pytest.raises(IpcProtocolError, match="bounded payload size"):
        encode_frame(oversized)
    with pytest.raises(IpcProtocolError, match="bounded payload size"):
        decode_frame(b"x" * (MAX_FRAME_BYTES + 1), IpcRequestFrame)


def test_ipc_identifiers_and_pathological_json_numbers_are_bounded() -> None:
    with pytest.raises(ValidationError):
        IpcRequestFrame.create("x" * 65, {})
    oversized_request_id = {
        "schema_version": "capability-ipc-request-v1",
        "request_id": "x" * 129,
        "operation": "health",
        "payload": {},
        "payload_digest": canonical_digest({}),
    }
    with pytest.raises(ValidationError):
        IpcRequestFrame.model_validate(oversized_request_id)

    pathological_integer = (
        b'{"schema_version":"capability-ipc-request-v1","request_id":"request-1",'
        b'"operation":"health","payload":{"value":'
        + (b"9" * 5_000)
        + b'},"payload_digest":"'
        + (b"0" * 64)
        + b'"}'
    )
    with pytest.raises(IpcProtocolError, match="not canonical JSON data"):
        decode_frame(pathological_integer, IpcRequestFrame)


@pytest.mark.parametrize(
    ("consequential", "expected_error"),
    [(False, IpcTransportError), (True, IpcOutcomeUnknownError)],
)
def test_ipc_timeout_closes_the_ambiguous_channel(
    consequential: bool,
    expected_error: type[Exception],
) -> None:
    client_connection, peer_connection = multiprocessing.Pipe(duplex=True)
    client = JsonPipeClient(
        client_connection,
        expected_boot_epoch="server-boot-epoch-0001",
        timeout_seconds=0.01,
    )
    try:
        with pytest.raises(expected_error, match="timed out"):
            client.request("execute", {}, consequential=consequential)
        with pytest.raises(IpcTransportError, match="closed"):
            client.request("execute", {}, consequential=consequential)
    finally:
        client.close()
        peer_connection.close()


@pytest.mark.parametrize(
    ("status", "error_code"),
    [("ok", "unexpected_error"), ("rejected", None), ("error", None)],
)
def test_ipc_response_status_and_error_code_must_agree(
    status: Literal["ok", "rejected", "error"],
    error_code: str | None,
) -> None:
    request = IpcRequestFrame.create("health", {})
    with pytest.raises(ValidationError):
        IpcResponseFrame.create(
            request,
            status=status,
            payload={},
            error_code=error_code,
            server_boot_epoch="server-boot-epoch-0001",
            response_counter=1,
        )


def test_signed_observations_bind_pre_post_phase_challenges_and_direct_link(
    artifacts: CapabilityArtifacts,
) -> None:
    pre = artifacts.pre_observation
    post = artifacts.post_observation
    assert pre.verify(artifacts.observer_public_key)
    assert post.verify(artifacts.observer_public_key)
    assert pre.phase is ObservationPhase.PRE_AUTHORIZATION
    assert pre.permit_id is pre.command_digest is pre.plc_acknowledgment_digest is None
    assert post.phase is ObservationPhase.POST_DISPATCH
    assert post.challenge_nonce == POST_CHALLENGE
    assert post.previous_envelope_digest == pre.envelope_digest
    assert post.permit_id == artifacts.permit.base_permit.permit_id
    assert post.command_digest == artifacts.command.digest
    assert post.plc_acknowledgment_digest == artifacts.acknowledgment.digest
    assert post.envelope_digest != pre.envelope_digest

    different_challenge = SignedObservationEnvelope.issue(
        snapshot=artifacts.pre_state,
        correlation_id=pre.correlation_id,
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="observer-pre-challenge-0002",
        observer_id=pre.observer_id,
        observer_key_id=pre.observer_key_id,
        observer_boot_epoch=pre.observer_boot_epoch,
        observer_sequence=pre.observer_sequence,
        previous_envelope_digest=None,
        private_key=artifacts.observer_private_key,
    )
    assert different_challenge.envelope_digest != pre.envelope_digest
    assert different_challenge.signature != pre.signature


def test_observation_phase_shape_is_fail_closed(artifacts: CapabilityArtifacts) -> None:
    pre = artifacts.pre_observation
    with pytest.raises(ValidationError, match="cannot assert dispatch bindings"):
        SignedObservationEnvelope.issue(
            snapshot=artifacts.pre_state,
            correlation_id=pre.correlation_id,
            phase=ObservationPhase.PRE_AUTHORIZATION,
            challenge_nonce=pre.challenge_nonce,
            observer_id=pre.observer_id,
            observer_key_id=pre.observer_key_id,
            observer_boot_epoch=pre.observer_boot_epoch,
            observer_sequence=3,
            previous_envelope_digest=pre.envelope_digest,
            permit_id=artifacts.permit.base_permit.permit_id,
            command_digest=artifacts.command.digest,
            plc_acknowledgment_digest=artifacts.acknowledgment.digest,
            private_key=artifacts.observer_private_key,
        )

    for missing in ("permit_id", "command_digest", "plc_acknowledgment_digest"):
        bindings: dict[str, str | None] = {
            "permit_id": artifacts.permit.base_permit.permit_id,
            "command_digest": artifacts.command.digest,
            "plc_acknowledgment_digest": artifacts.acknowledgment.digest,
        }
        bindings[missing] = None
        with pytest.raises(ValidationError, match="requires permit, command, and ACK bindings"):
            SignedObservationEnvelope.issue(
                snapshot=artifacts.assessment.post_state,
                correlation_id=pre.correlation_id,
                phase=ObservationPhase.POST_DISPATCH,
                challenge_nonce=POST_CHALLENGE,
                observer_id=pre.observer_id,
                observer_key_id=pre.observer_key_id,
                observer_boot_epoch=pre.observer_boot_epoch,
                observer_sequence=3,
                previous_envelope_digest=pre.envelope_digest,
                permit_id=bindings["permit_id"],
                command_digest=bindings["command_digest"],
                plc_acknowledgment_digest=bindings["plc_acknowledgment_digest"],
                private_key=artifacts.observer_private_key,
            )

    with pytest.raises(ValidationError, match="transaction predecessor"):
        SignedObservationEnvelope.issue(
            snapshot=artifacts.assessment.post_state,
            correlation_id=pre.correlation_id,
            phase=ObservationPhase.POST_DISPATCH,
            challenge_nonce=POST_CHALLENGE,
            observer_id=pre.observer_id,
            observer_key_id=pre.observer_key_id,
            observer_boot_epoch=pre.observer_boot_epoch,
            observer_sequence=3,
            previous_envelope_digest=None,
            permit_id=artifacts.permit.base_permit.permit_id,
            command_digest=artifacts.command.digest,
            plc_acknowledgment_digest=artifacts.acknowledgment.digest,
            private_key=artifacts.observer_private_key,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("correlation_id", "different-correlation"),
        ("phase", ObservationPhase.POST_DISPATCH),
        ("challenge_nonce", "different-challenge-0001"),
        ("observer_id", "observer:substituted"),
        ("observer_key_id", "observer-key-substituted"),
        ("observer_boot_epoch", "observer-boot-substitute"),
        ("observer_sequence", 99),
        ("captured_at", NOW + timedelta(seconds=1)),
        ("logical_time_s", 1.0),
        ("permit_id", "substituted-permit"),
        ("command_digest", "b" * 64),
        ("plc_acknowledgment_digest", "c" * 64),
        ("previous_envelope_digest", "d" * 64),
        ("envelope_digest", "e" * 64),
        ("signature", "invalid-signature"),
    ],
)
def test_observation_signature_binds_every_envelope_field(
    artifacts: CapabilityArtifacts,
    field: str,
    replacement: Any,
) -> None:
    tampered = artifacts.pre_observation.model_copy(update={field: replacement})
    assert not tampered.verify(artifacts.observer_public_key)


def test_observation_signature_binds_the_complete_physical_snapshot(
    artifacts: CapabilityArtifacts,
) -> None:
    substituted = artifacts.pre_observation.model_copy(
        update={"snapshot": artifacts.assessment.post_state}
    )
    assert artifacts.assessment.post_state.verify_digest()
    assert not substituted.verify(artifacts.observer_public_key)


def test_role_key_substitution_does_not_cross_verify(
    artifacts: CapabilityArtifacts,
) -> None:
    assert not artifacts.pre_observation.verify(artifacts.plc_public_key)
    assert not artifacts.acknowledgment.verify(artifacts.observer_public_key)
    assert not artifacts.permit.verify(artifacts.observer_public_key)
    assert not artifacts.permit.verify(artifacts.plc_public_key)

    substituted = SignedObservationEnvelope.issue(
        snapshot=artifacts.pre_state,
        correlation_id=artifacts.pre_observation.correlation_id,
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce=artifacts.pre_observation.challenge_nonce,
        observer_id=artifacts.pre_observation.observer_id,
        observer_key_id=artifacts.pre_observation.observer_key_id,
        observer_boot_epoch=artifacts.pre_observation.observer_boot_epoch,
        observer_sequence=artifacts.pre_observation.observer_sequence,
        previous_envelope_digest=None,
        private_key=artifacts.plc_private_key,
    )
    assert substituted.verify(artifacts.plc_public_key)
    assert not substituted.verify(artifacts.observer_public_key)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("request_digest", "1" * 64),
        ("observation_id", "different-observation"),
        ("observation_envelope_digest", "2" * 64),
        ("observer_id", "observer:different"),
        ("observer_key_id", "observer-key-different"),
        ("observer_boot_epoch", "observer-boot-different"),
        ("target_plc_id", "plc:different"),
        ("target_plc_key_id", "plc-key-different"),
        ("target_plc_boot_epoch", "plc-boot-different"),
        ("signing_key_id", "permit-key-different"),
    ],
)
def test_capability_permit_signature_binds_every_outer_field(
    artifacts: CapabilityArtifacts,
    field: str,
    replacement: str,
) -> None:
    assert artifacts.permit.verify(artifacts.permit_public_key)
    tampered = artifacts.permit.model_copy(update={field: replacement})
    assert not tampered.verify(artifacts.permit_public_key)


def test_capability_permit_requires_a_valid_base_permit_and_matching_signer(
    artifacts: CapabilityArtifacts,
) -> None:
    tampered_base = artifacts.permit.base_permit.model_copy(update={"state_digest": "f" * 64})
    resigned_outer = artifacts.permit.model_copy(
        update={"base_permit": tampered_base, "signature": ""}
    ).signed(artifacts.permit_private_key)
    assert not resigned_outer.verify(artifacts.permit_public_key)

    data = _model_data(artifacts.permit)
    data["signing_key_id"] = "different-signer"
    with pytest.raises(ValidationError, match="signer does not match"):
        CapabilityExecutionPermit.model_validate(data)


def test_applied_plc_acknowledgment_verifies_the_complete_transaction(
    artifacts: CapabilityArtifacts,
) -> None:
    acknowledgment = artifacts.acknowledgment
    assert acknowledgment.verify(artifacts.plc_public_key)
    assert acknowledgment.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=acknowledgment.plc_id,
        expected_plc_key_id=acknowledgment.plc_key_id,
        expected_plc_boot_epoch=acknowledgment.plc_boot_epoch,
    )
    for field, replacement in (
        ("request_digest", "1" * 64),
        ("permit_digest", "2" * 64),
        ("observation_envelope_digest", "3" * 64),
        ("permit_id", "different-permit"),
        ("command_digest", "4" * 64),
        ("plc_id", "plc:different"),
        ("plc_key_id", "plc-key-different"),
        ("plc_boot_epoch", "plc-boot-epoch-different"),
    ):
        tampered = acknowledgment.model_copy(update={field: replacement})
        assert not tampered.verify_for_transaction(
            artifacts.plc_public_key,
            request=artifacts.request,
            permit=artifacts.permit,
            pre_observation=artifacts.pre_observation,
            expected_plc_id=acknowledgment.plc_id,
            expected_plc_key_id=acknowledgment.plc_key_id,
            expected_plc_boot_epoch=acknowledgment.plc_boot_epoch,
        )


@pytest.mark.parametrize(
    ("status", "dispatch_phase", "reason"),
    [
        (
            CommandStatus.REJECTED,
            DispatchPhase.KNOWN_NO_EFFECT,
            "compare_and_swap_rejected",
        ),
        (
            CommandStatus.UNKNOWN_EFFECT,
            DispatchPhase.EFFECT_UNKNOWN,
            "unclassified_dispatch_failure",
        ),
    ],
)
def test_nonapplied_acknowledgment_rejects_whole_valid_prestate_substitution(
    artifacts: CapabilityArtifacts,
    status: CommandStatus,
    dispatch_phase: DispatchPhase,
    reason: str,
) -> None:
    valid = _nonapplied_acknowledgment(
        artifacts,
        status=status,
        dispatch_phase=dispatch_phase,
        reason=reason,
    )
    assert valid.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=PLC_KEY_ID,
        expected_plc_boot_epoch=PLC_BOOT_EPOCH,
    )

    substituted = _nonapplied_acknowledgment(
        artifacts,
        status=status,
        dispatch_phase=dispatch_phase,
        reason=reason,
        pre_state=artifacts.assessment.post_state,
    )
    assert substituted.pre_state.verify_digest()
    assert substituted.pre_state_digest == substituted.pre_state.state_digest
    assert not substituted.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=PLC_KEY_ID,
        expected_plc_boot_epoch=PLC_BOOT_EPOCH,
    )


def test_rejected_acknowledgment_accepts_only_a_reason_consistent_cas_state(
    artifacts: CapabilityArtifacts,
) -> None:
    changed_state = artifacts.assessment.post_state
    topology_rejection = _nonapplied_acknowledgment(
        artifacts,
        status=CommandStatus.REJECTED,
        dispatch_phase=DispatchPhase.PRE_DISPATCH,
        reason="topology_digest_changed",
        pre_state=changed_state,
    )
    assert topology_rejection.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=PLC_KEY_ID,
        expected_plc_boot_epoch=PLC_BOOT_EPOCH,
    )

    inconsistent_reason = _nonapplied_acknowledgment(
        artifacts,
        status=CommandStatus.REJECTED,
        dispatch_phase=DispatchPhase.PRE_DISPATCH,
        reason="precommit_state_version_changed",
        pre_state=changed_state,
    )
    assert not inconsistent_reason.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=PLC_KEY_ID,
        expected_plc_boot_epoch=PLC_BOOT_EPOCH,
    )


def test_plc_reports_atomic_observation_cas_as_verified_known_no_effect(
    artifacts: CapabilityArtifacts,
    tmp_path: Path,
) -> None:
    changed_provisional = artifacts.pre_state.model_copy(
        update={
            "observation_sequence": artifacts.pre_state.observation_sequence + 1,
            "observation_digest": "0" * 64,
        }
    )
    changed_state = changed_provisional.model_copy(
        update={
            "observation_digest": canonical_digest(
                changed_provisional.observation_material()
            )
        }
    )
    assert changed_state.verify_digest()
    plant = _ObservationRacePlant(
        artifacts.pre_state,
        changed_state,
        artifacts.assessment,
    )
    observer_public_raw = artifacts.observer_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    observer_info = ObserverProcessInfo(
        pid=101,
        observer_id=artifacts.pre_observation.observer_id,
        boot_epoch=artifacts.pre_observation.observer_boot_epoch,
        key_id=artifacts.pre_observation.observer_key_id,
        public_key_bytes=observer_public_raw,
        plant_boot_epoch="plant-boot-epoch-0001",
        capabilities={},
    )
    targeted_base_permit = artifacts.permit.base_permit.model_copy(
        update={"audience": PLC_ID, "signature": ""}
    ).signed(artifacts.permit_private_key)
    targeted_permit = artifacts.permit.model_copy(
        update={"base_permit": targeted_base_permit, "signature": ""}
    ).signed(artifacts.permit_private_key)
    plc = CapabilityVirtualPlc(
        plant=plant,  # type: ignore[arg-type]
        plc_id=PLC_ID,
        boot_epoch=PLC_BOOT_EPOCH,
        permit_key_id=targeted_permit.signing_key_id,
        permit_public_key=artifacts.permit_public_key,
        observer_info=observer_info,
        acknowledgment_private_key=artifacts.plc_private_key,
        acknowledgment_key_id=PLC_KEY_ID,
        replay=OrderlyRestartReplayReservations(
            tmp_path / "replay.json",
            initialize=True,
        ),
        clock=lambda: NOW,
    )

    acknowledgment = plc.execute(
        request=artifacts.request,
        permit=targeted_permit,
        pre_observation=artifacts.pre_observation,
        decision=artifacts.decision,
        assessment=artifacts.assessment,
    )

    assert acknowledgment.status is CommandStatus.REJECTED
    assert acknowledgment.dispatch_phase is DispatchPhase.KNOWN_NO_EFFECT
    assert acknowledgment.reason == "precommit_observation_changed"
    assert acknowledgment.pre_state == changed_state
    assert (
        plant.apply_kwargs["expected_pre_observation_digest"]
        == artifacts.pre_state.observation_digest
    )
    assert acknowledgment.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=targeted_permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=PLC_KEY_ID,
        expected_plc_boot_epoch=PLC_BOOT_EPOCH,
    )


@pytest.mark.parametrize(
    ("reason", "acknowledged_at", "expected"),
    [
        ("compare_and_swap_rejected", NOW, True),
        ("compare_and_swap_rejected", NOW - timedelta(microseconds=1), False),
        ("compare_and_swap_rejected", NOW + timedelta(seconds=2), False),
        ("permit_not_yet_valid", NOW - timedelta(microseconds=1), True),
        ("permit_not_yet_valid", NOW, False),
        ("permit_expired", NOW + timedelta(seconds=2), True),
        ("permit_expired", NOW + timedelta(seconds=1), False),
        ("permit_expired_before_dispatch", NOW + timedelta(seconds=2), True),
        ("permit_expired_after_replay_reservation", NOW + timedelta(seconds=2), True),
        ("transaction_replayed", NOW + timedelta(days=1), True),
    ],
)
def test_rejected_acknowledgment_time_matches_its_permit_reason(
    artifacts: CapabilityArtifacts,
    reason: str,
    acknowledged_at: datetime,
    expected: bool,
) -> None:
    acknowledgment = _nonapplied_acknowledgment(
        artifacts,
        status=CommandStatus.REJECTED,
        dispatch_phase=DispatchPhase.PRE_DISPATCH,
        reason=reason,
        acknowledged_at=acknowledged_at,
    )
    assert (
        acknowledgment.verify_for_transaction(
            artifacts.plc_public_key,
            request=artifacts.request,
            permit=artifacts.permit,
            pre_observation=artifacts.pre_observation,
            expected_plc_id=PLC_ID,
            expected_plc_key_id=PLC_KEY_ID,
            expected_plc_boot_epoch=PLC_BOOT_EPOCH,
        )
        is expected
    )


def test_unknown_acknowledgment_requires_time_at_or_after_permit_issuance(
    artifacts: CapabilityArtifacts,
) -> None:
    for acknowledged_at, expected in (
        (NOW - timedelta(microseconds=1), False),
        (NOW, True),
        (NOW + timedelta(days=1), True),
    ):
        acknowledgment = _nonapplied_acknowledgment(
            artifacts,
            status=CommandStatus.UNKNOWN_EFFECT,
            dispatch_phase=DispatchPhase.EFFECT_UNKNOWN,
            reason="unclassified_dispatch_failure",
            acknowledged_at=acknowledged_at,
        )
        assert (
            acknowledgment.verify_for_transaction(
                artifacts.plc_public_key,
                request=artifacts.request,
                permit=artifacts.permit,
                pre_observation=artifacts.pre_observation,
                expected_plc_id=PLC_ID,
                expected_plc_key_id=PLC_KEY_ID,
                expected_plc_boot_epoch=PLC_BOOT_EPOCH,
            )
            is expected
        )


@pytest.mark.parametrize(
    "reason",
    (
        "transaction_replayed",
        "permit_replayed",
        "permit_nonce_replayed",
        "command_replayed",
    ),
)
def test_restart_replay_rejection_allows_only_the_prior_target_instance(
    artifacts: CapabilityArtifacts,
    reason: str,
) -> None:
    restarted_private_key, restarted_public_key = generate_keypair()
    restarted_key_id = "plc-key-after-restart"
    restarted_boot_epoch = "plc-boot-after-restart"
    replayed = _nonapplied_acknowledgment(
        artifacts,
        status=CommandStatus.REJECTED,
        dispatch_phase=DispatchPhase.PRE_DISPATCH,
        reason=reason,
        acknowledged_at=NOW + timedelta(seconds=3),
        pre_state=artifacts.assessment.post_state,
        plc_key_id=restarted_key_id,
        plc_boot_epoch=restarted_boot_epoch,
        private_key=restarted_private_key,
    )
    assert replayed.verify_for_transaction(
        restarted_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=restarted_key_id,
        expected_plc_boot_epoch=restarted_boot_epoch,
    )


@pytest.mark.parametrize(
    ("status", "dispatch_phase", "reason"),
    [
        (
            CommandStatus.REJECTED,
            DispatchPhase.PRE_DISPATCH,
            "candidate_attestation_mismatch",
        ),
        (
            CommandStatus.REJECTED,
            DispatchPhase.PRE_DISPATCH,
            "transaction_replay",
        ),
        (
            CommandStatus.REJECTED,
            DispatchPhase.KNOWN_NO_EFFECT,
            "transaction_replayed",
        ),
        (
            CommandStatus.UNKNOWN_EFFECT,
            DispatchPhase.EFFECT_UNKNOWN,
            "transaction_replayed",
        ),
    ],
)
def test_target_instance_exception_is_not_available_to_non_replay_dispositions(
    artifacts: CapabilityArtifacts,
    status: CommandStatus,
    dispatch_phase: DispatchPhase,
    reason: str,
) -> None:
    restarted_private_key, restarted_public_key = generate_keypair()
    acknowledgment = _nonapplied_acknowledgment(
        artifacts,
        status=status,
        dispatch_phase=dispatch_phase,
        reason=reason,
        plc_key_id="plc-key-after-restart",
        plc_boot_epoch="plc-boot-after-restart",
        private_key=restarted_private_key,
    )
    assert not acknowledgment.verify_for_transaction(
        restarted_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=acknowledgment.plc_key_id,
        expected_plc_boot_epoch=acknowledgment.plc_boot_epoch,
    )


def test_restart_replay_exception_never_relaxes_target_plc_identity(
    artifacts: CapabilityArtifacts,
) -> None:
    restarted_private_key, restarted_public_key = generate_keypair()
    acknowledgment = _nonapplied_acknowledgment(
        artifacts,
        status=CommandStatus.REJECTED,
        dispatch_phase=DispatchPhase.PRE_DISPATCH,
        reason="transaction_replayed",
        plc_id="plc:different",
        plc_key_id="plc-key-after-restart",
        plc_boot_epoch="plc-boot-after-restart",
        private_key=restarted_private_key,
    )
    assert not acknowledgment.verify_for_transaction(
        restarted_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=acknowledgment.plc_id,
        expected_plc_key_id=acknowledgment.plc_key_id,
        expected_plc_boot_epoch=acknowledgment.plc_boot_epoch,
    )


def test_applied_acknowledgment_requires_the_exact_permit_target_instance(
    artifacts: CapabilityArtifacts,
) -> None:
    restarted_private_key, restarted_public_key = generate_keypair()
    restarted = artifacts.acknowledgment.model_copy(
        update={
            "plc_key_id": "plc-key-after-restart",
            "plc_boot_epoch": "plc-boot-after-restart",
            "signature": "",
        }
    ).signed(restarted_private_key)
    assert not restarted.verify_for_transaction(
        restarted_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=restarted.plc_key_id,
        expected_plc_boot_epoch=restarted.plc_boot_epoch,
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"status": CommandStatus.APPLIED, "dispatch_phase": DispatchPhase.PRE_DISPATCH},
        {"status": CommandStatus.APPLIED, "post_state_digest": None},
        {"status": CommandStatus.REJECTED, "dispatch_phase": DispatchPhase.COMMITTED},
        {"status": CommandStatus.REJECTED, "post_state_digest": "1" * 64},
        {"status": CommandStatus.REJECTED, "post_actuator_setpoint": 0.0},
        {"status": CommandStatus.UNKNOWN_EFFECT, "dispatch_phase": DispatchPhase.COMMITTED},
        {"status": CommandStatus.UNKNOWN_EFFECT, "post_state_version": 1},
    ],
)
def test_plc_acknowledgment_status_and_dispatch_phase_are_consistent(
    artifacts: CapabilityArtifacts,
    updates: dict[str, Any],
) -> None:
    data = _model_data(artifacts.acknowledgment)
    data.update(updates)
    with pytest.raises(ValidationError):
        PlcCommandAcknowledgment.model_validate(data)


def test_closed_loop_completed_result_requires_the_complete_dual_evidence_path(
    artifacts: CapabilityArtifacts,
) -> None:
    assert artifacts.completed_result.status is CapabilityClosedLoopStatus.COMPLETED
    required_fields = (
        "pre_observation",
        "decision",
        "command",
        "assessment",
        "permit",
        "acknowledgment",
        "post_observation",
    )
    for field in required_fields:
        data = _model_data(artifacts.completed_result)
        data[field] = None
        with pytest.raises(ValidationError):
            CapabilityClosedLoopResult.model_validate(data)

    data = _model_data(artifacts.completed_result)
    data["dispatch_attempts"] = 0
    with pytest.raises(ValidationError):
        CapabilityClosedLoopResult.model_validate(data)


def test_closed_loop_terminal_shapes_reject_inconsistent_certainty(
    artifacts: CapabilityArtifacts,
) -> None:
    rejected_ack = _rejected_acknowledgment(artifacts)

    invalid_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {
                "status": CapabilityClosedLoopStatus.COMPLETED,
                "acknowledgment": rejected_ack,
            },
            "applied PLC acknowledgment",
        ),
        (
            {
                "status": CapabilityClosedLoopStatus.COMPLETED,
                "post_observation": artifacts.pre_observation,
            },
            "exact post-observation bindings",
        ),
        (
            {
                "status": CapabilityClosedLoopStatus.PLC_REJECTED,
                "acknowledgment": artifacts.acknowledgment,
            },
            "signed rejected acknowledgment",
        ),
        (
            {
                "status": CapabilityClosedLoopStatus.OBSERVATION_DIVERGED,
                "post_observation": None,
            },
            "both signed evidence artifacts",
        ),
        (
            {
                "status": CapabilityClosedLoopStatus.UNKNOWN_EFFECT,
                "post_observation": artifacts.post_observation,
            },
            "cannot assert a verified post-observation",
        ),
        (
            {"permit": None, "dispatch_attempts": 1},
            "without a permit",
        ),
        (
            {"status": CapabilityClosedLoopStatus.NOT_DISPATCHED},
            "cannot retain dispatch artifacts",
        ),
        (
            {"status": CapabilityClosedLoopStatus.CANDIDATE_REJECTED},
            "cannot retain a post observation",
        ),
        (
            {"dispatch_attempts": 0},
            "acknowledgment requires one dispatch attempt",
        ),
    )
    for updates, message in invalid_cases:
        data = _model_data(artifacts.completed_result)
        data.update(updates)
        with pytest.raises(ValidationError, match=message):
            CapabilityClosedLoopResult.model_validate(data)


def test_closed_loop_noncompleted_terminal_shapes_accept_only_their_evidence(
    artifacts: CapabilityArtifacts,
) -> None:
    rejected_ack = _rejected_acknowledgment(artifacts)
    rejected_data = _model_data(artifacts.completed_result)
    rejected_data.update(
        {
            "status": CapabilityClosedLoopStatus.PLC_REJECTED,
            "reasons": ("compare_and_swap_rejected",),
            "acknowledgment": rejected_ack,
            "post_observation": None,
            "last_observation": artifacts.pre_observation,
        }
    )
    rejected = CapabilityClosedLoopResult.model_validate(rejected_data)
    assert rejected.status is CapabilityClosedLoopStatus.PLC_REJECTED

    unknown_data = _model_data(artifacts.completed_result)
    unknown_data.update(
        {
            "status": CapabilityClosedLoopStatus.UNKNOWN_EFFECT,
            "reasons": ("post_observation_unavailable",),
            "post_observation": None,
            "last_observation": artifacts.pre_observation,
        }
    )
    unknown = CapabilityClosedLoopResult.model_validate(unknown_data)
    assert unknown.status is CapabilityClosedLoopStatus.UNKNOWN_EFFECT

    contradictory_post = SignedObservationEnvelope.issue(
        snapshot=artifacts.pre_state,
        correlation_id=artifacts.request.correlation_id,
        phase=ObservationPhase.POST_DISPATCH,
        challenge_nonce="observer-post-contradiction-0001",
        observer_id=artifacts.pre_observation.observer_id,
        observer_key_id=artifacts.pre_observation.observer_key_id,
        observer_boot_epoch=artifacts.pre_observation.observer_boot_epoch,
        observer_sequence=3,
        previous_envelope_digest=artifacts.pre_observation.envelope_digest,
        permit_id=artifacts.permit.base_permit.permit_id,
        command_digest=artifacts.command.digest,
        plc_acknowledgment_digest=artifacts.acknowledgment.digest,
        private_key=artifacts.observer_private_key,
    )
    divergent_data = _model_data(artifacts.completed_result)
    divergent_data.update(
        {
            "status": CapabilityClosedLoopStatus.OBSERVATION_DIVERGED,
            "reasons": ("signed_post_observation_contradiction",),
            "post_observation": contradictory_post,
            "last_observation": contradictory_post,
        }
    )
    divergent = CapabilityClosedLoopResult.model_validate(divergent_data)
    assert divergent.status is CapabilityClosedLoopStatus.OBSERVATION_DIVERGED


def test_observation_envelope_rejects_invalid_time_state_and_digest_bindings(
    artifacts: CapabilityArtifacts,
) -> None:
    valid = artifacts.pre_observation

    naive_time = _model_data(valid)
    naive_time["captured_at"] = NOW.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="timezone-aware"):
        SignedObservationEnvelope.model_validate(naive_time)

    invalid_snapshot = valid.snapshot.model_copy(update={"state_digest": "0" * 64})
    invalid_state = _model_data(valid)
    invalid_state["snapshot"] = invalid_snapshot
    with pytest.raises(ValidationError, match="invalid physical-state digest"):
        SignedObservationEnvelope.model_validate(invalid_state)

    capture_mismatch = _model_data(valid)
    capture_mismatch["captured_at"] = NOW + timedelta(microseconds=1)
    with pytest.raises(ValidationError, match="capture time must match"):
        SignedObservationEnvelope.model_validate(capture_mismatch)

    logical_mismatch = _model_data(valid)
    logical_mismatch["logical_time_s"] = valid.logical_time_s + 1.0
    with pytest.raises(ValidationError, match="logical time must match"):
        SignedObservationEnvelope.model_validate(logical_mismatch)

    digest_mismatch = _model_data(valid)
    digest_mismatch["envelope_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="envelope digest is inconsistent"):
        SignedObservationEnvelope.model_validate(digest_mismatch)

    with pytest.raises(ValueError, match="logical_time_s must be finite"):
        SignedObservationEnvelope.require_finite_logical_time(float("inf"))


def test_plc_acknowledgment_rejects_invalid_time_state_and_numeric_bindings(
    artifacts: CapabilityArtifacts,
) -> None:
    valid = artifacts.acknowledgment

    naive_time = _model_data(valid)
    naive_time["acknowledged_at"] = NOW.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="timezone-aware"):
        PlcCommandAcknowledgment.model_validate(naive_time)

    invalid_pre = valid.pre_state.model_copy(update={"state_digest": "0" * 64})
    invalid_state = _model_data(valid)
    invalid_state["pre_state"] = invalid_pre
    with pytest.raises(ValidationError, match="invalid pre-state"):
        PlcCommandAcknowledgment.model_validate(invalid_state)

    inconsistent_pre = _model_data(valid)
    inconsistent_pre["pre_state_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="pre-state fields are inconsistent"):
        PlcCommandAcknowledgment.model_validate(inconsistent_pre)

    with pytest.raises(ValueError, match="setpoints must be finite"):
        PlcCommandAcknowledgment.require_finite_setpoint(float("nan"))


@pytest.mark.parametrize(
    "post_field",
    (
        "post_state_digest",
        "post_state_version",
        "post_topology_digest",
        "post_actuator_setpoint",
    ),
)
def test_applied_acknowledgment_requires_each_post_state_field(
    artifacts: CapabilityArtifacts,
    post_field: str,
) -> None:
    data = _model_data(artifacts.acknowledgment)
    data[post_field] = None
    with pytest.raises(ValidationError, match="complete post-state evidence"):
        PlcCommandAcknowledgment.model_validate(data)


@pytest.mark.parametrize(
    "post_field",
    ("post_state_digest", "post_state_version", "post_topology_digest"),
)
def test_rejected_acknowledgment_cannot_assert_any_post_state_field(
    artifacts: CapabilityArtifacts,
    post_field: str,
) -> None:
    data = _model_data(artifacts.acknowledgment)
    data.update(
        {
            "status": CommandStatus.REJECTED,
            "dispatch_phase": DispatchPhase.PRE_DISPATCH,
            "post_state_digest": None,
            "post_state_version": None,
            "post_topology_digest": None,
            "post_actuator_setpoint": artifacts.acknowledgment.pre_actuator_setpoint,
        }
    )
    data[post_field] = (
        artifacts.acknowledgment.post_state_version
        if post_field == "post_state_version"
        else "f" * 64
    )
    with pytest.raises(ValidationError, match="cannot assert a post-state"):
        PlcCommandAcknowledgment.model_validate(data)


def test_rejected_acknowledgment_requires_unchanged_actuator_evidence(
    artifacts: CapabilityArtifacts,
) -> None:
    data = _model_data(artifacts.acknowledgment)
    data.update(
        {
            "status": CommandStatus.REJECTED,
            "dispatch_phase": DispatchPhase.KNOWN_NO_EFFECT,
            "post_state_digest": None,
            "post_state_version": None,
            "post_topology_digest": None,
            "post_actuator_setpoint": (
                artifacts.acknowledgment.pre_actuator_setpoint + 1.0
            ),
        }
    )
    with pytest.raises(ValidationError, match="unchanged actuator"):
        PlcCommandAcknowledgment.model_validate(data)


@pytest.mark.parametrize(
    ("post_field", "value"),
    [
        ("post_state_digest", "f" * 64),
        ("post_state_version", 1),
        ("post_topology_digest", "e" * 64),
        ("post_actuator_setpoint", 0.0),
    ],
)
def test_unknown_effect_acknowledgment_cannot_assert_post_dispatch_state(
    artifacts: CapabilityArtifacts,
    post_field: str,
    value: str | int | float,
) -> None:
    data = _model_data(artifacts.acknowledgment)
    data.update(
        {
            "status": CommandStatus.UNKNOWN_EFFECT,
            "dispatch_phase": DispatchPhase.EFFECT_UNKNOWN,
            "post_state_digest": None,
            "post_state_version": None,
            "post_topology_digest": None,
            "post_actuator_setpoint": None,
        }
    )
    data[post_field] = value
    with pytest.raises(ValidationError, match="cannot assert post-dispatch state"):
        PlcCommandAcknowledgment.model_validate(data)


def test_transaction_verification_rechecks_signed_prestate_setpoint(
    artifacts: CapabilityArtifacts,
) -> None:
    substituted = artifacts.acknowledgment.model_copy(
        update={"pre_actuator_setpoint": 999.0, "signature": ""}
    ).signed(artifacts.plc_private_key)
    assert substituted.verify(artifacts.plc_public_key)
    assert not substituted.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=PLC_KEY_ID,
        expected_plc_boot_epoch=PLC_BOOT_EPOCH,
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("permit_nonce", "substituted-permit-nonce-0001"),
        ("command_id", "substituted-command-id"),
        ("assessment_digest", "4" * 64),
        ("proposal_id", "substituted-proposal-id"),
        ("decision_id", "substituted-decision-id"),
    ],
)
def test_transaction_verification_rejects_remaining_identifier_substitutions(
    artifacts: CapabilityArtifacts,
    field: str,
    replacement: str,
) -> None:
    substituted = artifacts.acknowledgment.model_copy(
        update={field: replacement, "signature": ""}
    ).signed(artifacts.plc_private_key)
    assert not substituted.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=PLC_KEY_ID,
        expected_plc_boot_epoch=PLC_BOOT_EPOCH,
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"acknowledged_at": NOW - timedelta(microseconds=1)},
        {"acknowledged_at": NOW + timedelta(seconds=2)},
        {"post_state_digest": "1" * 64},
        {"post_state_version": 99},
        {"post_topology_digest": "2" * 64},
        {"post_actuator_setpoint": 1.0},
    ],
)
def test_applied_transaction_verification_rejects_effect_binding_substitutions(
    artifacts: CapabilityArtifacts,
    updates: dict[str, Any],
) -> None:
    substituted = artifacts.acknowledgment.model_copy(
        update=updates | {"signature": ""}
    ).signed(artifacts.plc_private_key)
    assert not substituted.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=PLC_KEY_ID,
        expected_plc_boot_epoch=PLC_BOOT_EPOCH,
    )


@pytest.mark.parametrize(
    "reason",
    (
        "model_digest_changed",
        "precommit_state_digest_changed",
        "precommit_observation_changed",
    ),
)
def test_each_atomic_cas_reason_requires_its_specific_changed_state(
    artifacts: CapabilityArtifacts,
    reason: str,
) -> None:
    if reason == "model_digest_changed":
        changed = _redigest_state(artifacts.pre_state, model_digest="f" * 64)
    elif reason == "precommit_state_digest_changed":
        changed = _redigest_state(
            artifacts.pre_state,
            simulation_time_s=artifacts.pre_state.simulation_time_s + 0.5,
        )
    else:
        provisional = artifacts.pre_state.model_copy(
            update={
                "observation_sequence": artifacts.pre_state.observation_sequence + 1,
                "observation_digest": "0" * 64,
            }
        )
        changed = provisional.model_copy(
            update={
                "observation_digest": canonical_digest(provisional.observation_material())
            }
        )
    assert changed.verify_digest()
    acknowledgment = _nonapplied_acknowledgment(
        artifacts,
        status=CommandStatus.REJECTED,
        dispatch_phase=DispatchPhase.PRE_DISPATCH,
        reason=reason,
        pre_state=changed,
    )
    assert acknowledgment.verify_for_transaction(
        artifacts.plc_public_key,
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        expected_plc_id=PLC_ID,
        expected_plc_key_id=PLC_KEY_ID,
        expected_plc_boot_epoch=PLC_BOOT_EPOCH,
    )


@pytest.mark.parametrize(
    "missing_field",
    ("pre_observation", "permit", "acknowledgment", "post_observation"),
)
def test_post_binding_helper_fails_closed_for_each_missing_artifact(
    artifacts: CapabilityArtifacts,
    missing_field: str,
) -> None:
    incomplete = artifacts.completed_result.model_copy(update={missing_field: None})
    assert not incomplete._post_bindings_match()


@pytest.mark.parametrize(
    "missing_field",
    ("permit", "acknowledgment", "post_observation"),
)
def test_post_state_helper_fails_closed_for_each_missing_artifact(
    artifacts: CapabilityArtifacts,
    missing_field: str,
) -> None:
    incomplete = artifacts.completed_result.model_copy(update={missing_field: None})
    assert not incomplete._post_state_matches_expected()


def test_candidate_rejection_shapes_distinguish_pre_and_post_dispatch(
    artifacts: CapabilityArtifacts,
) -> None:
    pre_dispatch = _model_data(artifacts.completed_result)
    pre_dispatch.update(
        {
            "status": CapabilityClosedLoopStatus.CANDIDATE_REJECTED,
            "reasons": ("candidate_binding_mismatch",),
            "acknowledgment": None,
            "post_observation": None,
            "dispatch_attempts": 0,
        }
    )
    with pytest.raises(ValidationError, match="cannot retain PLC artifacts"):
        CapabilityClosedLoopResult.model_validate(pre_dispatch)

    post_dispatch = _model_data(artifacts.completed_result)
    post_dispatch.update(
        {
            "status": CapabilityClosedLoopStatus.CANDIDATE_REJECTED,
            "reasons": ("candidate_attestation_mismatch",),
            "post_observation": None,
        }
    )
    with pytest.raises(ValidationError, match="signed rejected ACK"):
        CapabilityClosedLoopResult.model_validate(post_dispatch)


@pytest.mark.parametrize(
    "artifact_field",
    ("pre_observation", "permit", "acknowledgment", "post_observation"),
)
def test_completed_result_requires_each_present_signature(
    artifacts: CapabilityArtifacts,
    artifact_field: str,
) -> None:
    data = _model_data(artifacts.completed_result)
    data[artifact_field]["signature"] = ""
    with pytest.raises(ValidationError, match="present evidence signatures"):
        CapabilityClosedLoopResult.model_validate(data)


def test_completed_result_rejects_bound_but_contradictory_post_state(
    artifacts: CapabilityArtifacts,
) -> None:
    contradictory = _contradictory_post_observation(artifacts)
    data = _model_data(artifacts.completed_result)
    data.update(
        {
            "post_observation": contradictory,
            "last_observation": contradictory,
        }
    )
    with pytest.raises(ValidationError, match="must match the PLC acknowledgment"):
        CapabilityClosedLoopResult.model_validate(data)


def test_observation_divergence_requires_signatures_bindings_and_contradiction(
    artifacts: CapabilityArtifacts,
) -> None:
    contradictory = _contradictory_post_observation(artifacts)
    base = _model_data(artifacts.completed_result)
    base.update(
        {
            "status": CapabilityClosedLoopStatus.OBSERVATION_DIVERGED,
            "reasons": ("signed_post_observation_contradiction",),
            "post_observation": contradictory,
            "last_observation": contradictory,
        }
    )

    missing_signature = dict(base)
    missing_signature["post_observation"] = contradictory.model_copy(
        update={"signature": ""}
    )
    with pytest.raises(ValidationError, match="present evidence signatures"):
        CapabilityClosedLoopResult.model_validate(missing_signature)

    wrong_predecessor = _contradictory_post_observation(
        artifacts,
        previous_envelope_digest="f" * 64,
    )
    wrong_binding = dict(base)
    wrong_binding["post_observation"] = wrong_predecessor
    with pytest.raises(ValidationError, match="exact post-observation bindings"):
        CapabilityClosedLoopResult.model_validate(wrong_binding)

    not_contradictory = _model_data(artifacts.completed_result)
    not_contradictory.update(
        {
            "status": CapabilityClosedLoopStatus.OBSERVATION_DIVERGED,
            "reasons": ("signed_post_observation_contradiction",),
        }
    )
    with pytest.raises(ValidationError, match="requires a signed state contradiction"):
        CapabilityClosedLoopResult.model_validate(not_contradictory)


def test_unknown_effect_requires_a_consequential_dispatch_attempt(
    artifacts: CapabilityArtifacts,
) -> None:
    data = _model_data(artifacts.completed_result)
    data.update(
        {
            "status": CapabilityClosedLoopStatus.UNKNOWN_EFFECT,
            "reasons": ("outcome_unavailable",),
            "permit": None,
            "acknowledgment": None,
            "post_observation": None,
            "dispatch_attempts": 0,
        }
    )
    with pytest.raises(ValidationError, match="one consequential dispatch attempt"):
        CapabilityClosedLoopResult.model_validate(data)
