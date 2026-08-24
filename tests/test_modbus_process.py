from __future__ import annotations

import os
from dataclasses import replace

import pytest
from pymodbus.client import ModbusTcpClient

from aegis_ot.modbus_device import (
    ModbusPhysicalDeviceClient,
    start_modbus_device_process,
)
from aegis_ot.modbus_wire import (
    DEVICE_ID,
    REQUEST_PAYLOAD_START,
    RESPONSE_HEADER_REGISTERS,
    RESPONSE_HEADER_START,
    WRITE_CHUNK_REGISTERS,
    ControlWord,
    RequestHeader,
    ResponseHeader,
    WireOperation,
    WireRequest,
    WireStatus,
    bytes_to_registers,
    canonical_json_bytes,
    sha256_hex,
)
from aegis_ot.models import ActionProposal, DecisionOutcome, Operation
from aegis_ot.physical_control import physical_state_to_gateway_state
from aegis_ot.physical_modbus_factory import ModbusPhysicalLab, start_modbus_physical_lab
from aegis_ot.physical_models import ClosedLoopStatus, CommandStatus, PhysicalStateSnapshot


def remote_proposal(
    state: PhysicalStateSnapshot,
    *,
    actor_id: str = "agent:operator-1",
    proposal_id: str = "modbus-proposal-1",
    nonce: str = "modbus-proposal-nonce-0001",
) -> ActionProposal:
    return ActionProposal(
        proposal_id=proposal_id,
        actor_id=actor_id,
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=state.state_version,
        observed_at=state.observed_at,
        submitted_at=state.observed_at,
        nonce=nonce,
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


@pytest.fixture
def modbus_lab(now) -> ModbusPhysicalLab:
    lab = start_modbus_physical_lab(now)
    try:
        yield lab
    finally:
        lab.close()


def prepare_remote_permit(lab: ModbusPhysicalLab, now):  # noqa: ANN001, ANN201
    pre = lab.client.read_state()
    proposal = remote_proposal(pre)
    decision = lab.authorization.gateway.decide(
        proposal,
        physical_state_to_gateway_state(pre),
        now,
    )
    command = lab.controller.translator.translate(proposal)
    assessment = lab.client.simulate_candidate(command)
    permit = lab.controller.permit_issuer.issue(
        proposal=proposal,
        decision=decision,
        command=command,
        assessment=assessment,
    )
    return pre, proposal, decision, assessment, permit


def test_modbus_device_is_separate_process_with_signed_health(modbus_lab) -> None:
    assert modbus_lab.info.pid != os.getpid()
    health = modbus_lab.client.health()
    assert health["status"] == "ready"
    assert health["model_digest"] == modbus_lab.info.model_digest
    assert health["device_id"] == modbus_lab.info.device_id
    assert health["boot_epoch"] == modbus_lab.info.boot_epoch


def test_modbus_nominal_closed_loop_has_one_device_effect_and_fresh_readback(modbus_lab) -> None:
    pre = modbus_lab.client.read_state()
    result = modbus_lab.controller.execute(remote_proposal(pre))
    assert result.status is ClosedLoopStatus.COMPLETED
    assert result.decision.outcome is DecisionOutcome.PERMIT
    assert result.acknowledgment is not None
    assert result.acknowledgment.status is CommandStatus.APPLIED
    assert result.acknowledgment.device_scan == 1
    assert result.acknowledgment.pre_actuator_setpoint == 1.0
    assert result.acknowledgment.post_actuator_setpoint == 0.0
    assert result.post_state.state_version == 1
    assert result.post_state.isolated_resources == ("feeder-1",)
    assert modbus_lab.authorization.gateway.evidence.verify()


def test_modbus_denied_proposal_never_sends_execution_or_changes_state(modbus_lab) -> None:
    pre = modbus_lab.client.read_state()
    result = modbus_lab.controller.execute(remote_proposal(pre, actor_id="agent:unknown"))
    post = modbus_lab.client.read_state()
    assert result.status is ClosedLoopStatus.NOT_DISPATCHED
    assert result.permit is None
    assert result.acknowledgment is None
    assert post.state_digest == pre.state_digest


def test_modbus_device_rejects_tampered_permit_and_replay(modbus_lab, now) -> None:
    pre, proposal, decision, assessment, permit = prepare_remote_permit(modbus_lab, now)
    tampered = permit.model_copy(update={"audience": "different-device"})
    rejected = modbus_lab.client.execute(
        tampered,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    assert rejected.status is CommandStatus.REJECTED
    assert rejected.reason == "permit_wrong_audience"
    assert rejected.pre_actuator_setpoint == rejected.post_actuator_setpoint

    applied = modbus_lab.client.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    replayed = modbus_lab.client.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    assert applied.status is CommandStatus.APPLIED
    assert applied.pre_state_digest == pre.state_digest
    assert replayed.status is CommandStatus.REJECTED
    assert replayed.reason == "permit_replayed"
    assert modbus_lab.client.read_state().state_version == 1


def test_modbus_raw_writes_cannot_mutate_response_or_commit_without_staging(modbus_lab) -> None:
    client = ModbusTcpClient(modbus_lab.info.host, port=modbus_lab.info.port, retries=0)
    assert client.connect()
    try:
        response_write = client.write_register(
            RESPONSE_HEADER_START,
            7,
            device_id=DEVICE_ID,
        )
        direct_commit = client.write_register(0, int(ControlWord.COMMIT), device_id=DEVICE_ID)
        assert response_write.isError()
        assert response_write.exception_code == 2
        assert direct_commit.isError()
    finally:
        client.close()


def test_permit_from_prior_boot_is_rejected_when_keys_are_retained(modbus_lab, now) -> None:
    _, proposal, decision, assessment, permit = prepare_remote_permit(modbus_lab, now)
    first_boot = modbus_lab.info.boot_epoch
    second_process = start_modbus_device_process(
        modbus_lab.permit_public_key,
        fixed_now=now,
    )
    try:
        second_client = ModbusPhysicalDeviceClient(second_process.info)
        try:
            acknowledgment = second_client.execute(
                permit,
                proposal=proposal,
                decision=decision,
                assessment=assessment,
            )
            assert second_process.info.boot_epoch != first_boot
            assert acknowledgment.status is CommandStatus.REJECTED
            assert acknowledgment.reason == "permit_wrong_audience"
            assert second_client.read_state().state_version == 0
        finally:
            second_client.close()
    finally:
        second_process.stop()


def test_two_clients_cannot_replace_staging_or_reexecute_a_committed_mailbox(
    modbus_lab,
    now,
) -> None:
    _, proposal, decision, assessment, permit = prepare_remote_permit(modbus_lab, now)
    request = WireRequest(
        transaction_id=9001,
        operation=WireOperation.EXECUTE,
        payload={
            "permit": permit.model_dump(mode="json"),
            "proposal": proposal.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "assessment": assessment.model_dump(mode="json"),
        },
    )
    payload = canonical_json_bytes(request)
    payload_registers = bytes_to_registers(payload)
    header = RequestHeader(
        control=ControlWord.BEGIN,
        operation=WireOperation.EXECUTE,
        transaction_id=request.transaction_id,
        payload_byte_length=len(payload),
        payload_register_count=len(payload_registers),
        payload_digest=sha256_hex(payload),
    )
    competing = replace(header, transaction_id=9002)
    first = ModbusTcpClient(modbus_lab.info.host, port=modbus_lab.info.port, retries=0)
    second = ModbusTcpClient(modbus_lab.info.host, port=modbus_lab.info.port, retries=0)
    assert first.connect()
    assert second.connect()
    try:
        assert not first.write_registers(
            0,
            header.to_registers(),
            device_id=DEVICE_ID,
        ).isError()
        for offset in range(0, len(payload_registers), WRITE_CHUNK_REGISTERS):
            assert not first.write_registers(
                REQUEST_PAYLOAD_START + offset,
                payload_registers[offset : offset + WRITE_CHUNK_REGISTERS],
                device_id=DEVICE_ID,
            ).isError()

        busy = second.write_registers(
            0,
            competing.to_registers(),
            device_id=DEVICE_ID,
        )
        assert busy.isError()
        assert busy.exception_code == 6

        assert not second.write_register(
            0,
            int(ControlWord.COMMIT),
            device_id=DEVICE_ID,
        ).isError()
        terminal_before = first.read_holding_registers(
            RESPONSE_HEADER_START,
            count=RESPONSE_HEADER_REGISTERS,
            device_id=DEVICE_ID,
        ).registers
        response = ResponseHeader.from_registers(terminal_before)
        assert response.transaction_id == request.transaction_id
        assert response.status is WireStatus.COMPLETE
        assert response.state_version_hint == 1

        assert not second.write_register(
            0,
            int(ControlWord.COMMIT),
            device_id=DEVICE_ID,
        ).isError()
        terminal_after = first.read_holding_registers(
            RESPONSE_HEADER_START,
            count=RESPONSE_HEADER_REGISTERS,
            device_id=DEVICE_ID,
        ).registers
        assert terminal_after == terminal_before

        release = replace(header, control=ControlWord.RELEASE)
        assert not first.write_registers(
            0,
            release.to_registers(),
            device_id=DEVICE_ID,
        ).isError()
        assert modbus_lab.client.read_state().state_version == 1
    finally:
        first.close()
        second.close()
