from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock
from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest
from pydantic import ValidationError

from aegis_ot import m3_experiment as m3
from aegis_ot.crypto import generate_keypair
from aegis_ot.evidence import EvidenceChain
from aegis_ot.factory import LocalLab, build_local_lab
from aegis_ot.modbus_device import (
    ModbusPhysicalDeviceClient,
    ModbusTransportError,
    ModbusUnknownEffectError,
)
from aegis_ot.modbus_wire import (
    MAX_PAYLOAD_BYTES,
    REQUEST_HEADER_REGISTERS,
    RESPONSE_HEADER_REGISTERS,
    ControlWord,
    RequestHeader,
    ResponseHeader,
    WireOperation,
    WireResultCode,
    WireStatus,
    _digest_registers,
    _registers_digest,
    _registers_u32,
    _registers_u64,
    _u32_registers,
    _u64_registers,
    bytes_to_registers,
    registers_to_bytes,
    sha256_hex,
)
from aegis_ot.models import ActionProposal, Decision, DecisionOutcome, Operation
from aegis_ot.pandapower_plant import (
    PandapowerCigreMVPlant,
    PhysicalLimits,
    PhysicalSimulationError,
    ResourceBinding,
    _json_scalar,
)
from aegis_ot.physical_control import (
    ExecutionPermitIssuer,
    PermitAwareVirtualControlDevice,
    PermitIssuanceError,
    PhysicalClosedLoopController,
    TrustedCommandTranslator,
    physical_state_to_gateway_state,
)
from aegis_ot.physical_factory import build_physical_local_lab
from aegis_ot.physical_models import (
    CandidateAssessment,
    ClosedLoopResult,
    ClosedLoopStatus,
    CommandAcknowledgment,
    CommandStatus,
    ExecutionPermit,
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
)
from aegis_ot.safety import SafetyKernel, SafetyLimits


@pytest.fixture(scope="module")
def controlled_m3_session():
    """Run one real process session and share its immutable evidence across tests."""

    progress: list[tuple[int, int]] = []
    outputs = m3.run_m3_experiment(
        (0x4D33,),
        progress=lambda completed, total: progress.append((completed, total)),
    )
    return (*outputs, progress)


def proposal_for_state(
    state: PhysicalStateSnapshot,
    *,
    proposal_id: str = "m3-edge-proposal-1",
    resource: str = "feeder-1",
    operation: Operation = Operation.ISOLATE_ASSET,
    parameters: dict[str, float] | None = None,
) -> ActionProposal:
    return ActionProposal(
        proposal_id=proposal_id,
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource=resource,
        operation=operation,
        parameters=(
            parameters if parameters is not None else {"critical_load_impact_pct": 5.0}
        ),
        observed_state_version=state.state_version,
        observed_at=state.observed_at,
        submitted_at=state.observed_at,
        nonce=f"nonce-{proposal_id}-00000000",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


@dataclass
class PreparedTransaction:
    authorization: LocalLab
    plant: PandapowerCigreMVPlant
    permit_private: Any
    permit_public: Any
    acknowledgment_private: Any
    acknowledgment_public: Any
    issuer: ExecutionPermitIssuer
    device: PermitAwareVirtualControlDevice
    pre_state: PhysicalStateSnapshot
    proposal: ActionProposal
    decision: Decision
    command: PhysicalControlCommand
    assessment: CandidateAssessment
    permit: ExecutionPermit


def prepare_transaction(now: datetime) -> PreparedTransaction:
    authorization = build_local_lab(now)
    authorization.gateway.safety = SafetyKernel(
        SafetyLimits(minimum_voltage_pu=0.90, maximum_voltage_pu=1.10),
        version="test-m3-edge-gateway-limits",
    )
    plant = PandapowerCigreMVPlant(observed_at=now)
    permit_private, permit_public = generate_keypair()
    acknowledgment_private, acknowledgment_public = generate_keypair()
    issuer = ExecutionPermitIssuer(
        permit_private,
        signing_key_id="edge-permit-key",
        audience="edge-device",
        evidence=authorization.gateway.evidence,
        clock=lambda: now,
    )
    device = PermitAwareVirtualControlDevice(
        plant,
        device_id="edge-device",
        permit_audience="edge-device",
        permit_public_keys={"edge-permit-key": permit_public},
        acknowledgment_private_key=acknowledgment_private,
        acknowledgment_key_id="edge-ack-key",
        clock=lambda: now,
    )
    pre_state = plant.read_state()
    proposal = proposal_for_state(pre_state)
    decision = authorization.gateway.decide(
        proposal,
        physical_state_to_gateway_state(pre_state),
        now,
    )
    assert decision.outcome is DecisionOutcome.PERMIT
    command = TrustedCommandTranslator().translate(proposal)
    assessment = plant.simulate_candidate(command)
    permit = issuer.issue(
        proposal=proposal,
        decision=decision,
        command=command,
        assessment=assessment,
    )
    return PreparedTransaction(
        authorization=authorization,
        plant=plant,
        permit_private=permit_private,
        permit_public=permit_public,
        acknowledgment_private=acknowledgment_private,
        acknowledgment_public=acknowledgment_public,
        issuer=issuer,
        device=device,
        pre_state=pre_state,
        proposal=proposal,
        decision=decision,
        command=command,
        assessment=assessment,
        permit=permit,
    )


class AdvancingClock:
    def __init__(self, *values: datetime) -> None:
        self._values = list(values)
        self._last = values[-1]

    def __call__(self) -> datetime:
        if self._values:
            self._last = self._values.pop(0)
        return self._last


def _redigest_state(
    state: PhysicalStateSnapshot,
    **updates: Any,
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


def test_permit_expires_after_candidate_recheck_without_physical_effect(now) -> None:
    lab = build_physical_local_lab(now)
    lab.control_device.clock = AdvancingClock(
        now + timedelta(seconds=1),
        now + timedelta(seconds=3),
    )
    pre_state = lab.plant.read_state()

    result = lab.controller.execute(proposal_for_state(pre_state))

    post_state = lab.plant.read_state()
    assert result.status is ClosedLoopStatus.DEVICE_REJECTED
    assert result.acknowledgment is not None
    assert result.acknowledgment.reason == "permit_expired_before_dispatch"
    assert result.acknowledgment.pre_actuator_setpoint == 1.0
    assert result.acknowledgment.post_actuator_setpoint == 1.0
    assert post_state.state_digest == pre_state.state_digest
    assert post_state.state_version == pre_state.state_version


def test_candidate_artifact_substitution_is_rejected_before_dispatch(now) -> None:
    transaction = prepare_transaction(now)
    substituted = transaction.assessment.model_copy(
        update={"assessment_id": "substituted-candidate-assessment"}
    )

    acknowledgment = transaction.device.execute(
        transaction.permit,
        proposal=transaction.proposal,
        decision=transaction.decision,
        assessment=substituted,
    )

    assert acknowledgment.status is CommandStatus.REJECTED
    assert acknowledgment.reason == "permit_assessment_digest_mismatch"
    assert transaction.plant.read_state().state_digest == transaction.pre_state.state_digest


class CandidateSubstitutionPlant:
    def __init__(self, delegate: PandapowerCigreMVPlant) -> None:
        self.delegate = delegate
        self.apply_calls = 0

    def read_state(self) -> PhysicalStateSnapshot:
        return self.delegate.read_state()

    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
        assessment = self.delegate.simulate_candidate(command)
        changed_post = _redigest_state(
            assessment.post_state,
            served_load_mw=assessment.post_state.served_load_mw - 0.01,
        )
        return CandidateAssessment(
            command_digest=assessment.command_digest,
            pre_state=assessment.pre_state,
            post_state=changed_post,
            safe=True,
            reasons=(),
        )

    def apply_authorized_command(
        self,
        command: PhysicalControlCommand,
        **kwargs: Any,
    ) -> PhysicalStateSnapshot:
        self.apply_calls += 1
        return self.delegate.apply_authorized_command(command, **kwargs)


def test_fresh_candidate_substitution_blocks_the_actuator_call(now) -> None:
    transaction = prepare_transaction(now)
    plant = CandidateSubstitutionPlant(transaction.plant)
    device = PermitAwareVirtualControlDevice(
        plant,
        device_id="edge-device",
        permit_audience="edge-device",
        permit_public_keys={"edge-permit-key": transaction.permit_public},
        acknowledgment_private_key=transaction.acknowledgment_private,
        acknowledgment_key_id="edge-ack-key",
        clock=lambda: now,
    )

    acknowledgment = device.execute(
        transaction.permit,
        proposal=transaction.proposal,
        decision=transaction.decision,
        assessment=transaction.assessment,
    )

    assert acknowledgment.status is CommandStatus.REJECTED
    assert acknowledgment.reason == "candidate_attestation_mismatch"
    assert plant.apply_calls == 0
    assert plant.read_state().state_digest == transaction.pre_state.state_digest


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("expected_post_state_digest", "f" * 64, "candidate_outcome_diverged"),
        ("expected_post_topology_digest", "e" * 64, "candidate_topology_diverged"),
    ],
)
def test_signed_expected_post_tamper_fails_atomically(
    now,
    field: str,
    value: str,
    reason: str,
) -> None:
    transaction = prepare_transaction(now)
    tampered = transaction.permit.model_copy(update={field: value}).signed(
        transaction.permit_private
    )

    acknowledgment = transaction.device.execute(
        tampered,
        proposal=transaction.proposal,
        decision=transaction.decision,
        assessment=transaction.assessment,
    )

    post_state = transaction.plant.read_state()
    assert acknowledgment.status is CommandStatus.REJECTED
    assert acknowledgment.reason == reason
    assert post_state.state_digest == transaction.pre_state.state_digest
    assert post_state.state_version == transaction.pre_state.state_version


def test_plant_precommit_and_solver_failures_are_atomic(now, monkeypatch) -> None:
    plant = PandapowerCigreMVPlant(observed_at=now)
    command = TrustedCommandTranslator().translate(proposal_for_state(plant.read_state()))
    baseline = plant.read_state()

    with pytest.raises(PhysicalSimulationError, match="precommit_state_version_changed"):
        plant.apply_authorized_command(
            command,
            expected_pre_state_version=baseline.state_version + 1,
        )
    with pytest.raises(PhysicalSimulationError, match="precommit_state_digest_changed"):
        plant.apply_authorized_command(
            command,
            expected_pre_state_digest="f" * 64,
        )

    monkeypatch.setattr(plant, "_solve", lambda net: False)
    with pytest.raises(PhysicalSimulationError, match="power_flow_nonconvergent"):
        plant.apply_authorized_command(command)
    assert plant.read_state().state_digest == baseline.state_digest


def test_post_state_limit_failure_is_atomic(now) -> None:
    plant = PandapowerCigreMVPlant(
        observed_at=now,
        limits=PhysicalLimits(minimum_voltage_pu=0.96),
    )
    baseline = plant.read_state()
    command = TrustedCommandTranslator().translate(proposal_for_state(baseline))

    with pytest.raises(PhysicalSimulationError, match="post_state_violates_physical_limits"):
        plant.apply_authorized_command(command)

    assert plant.read_state().state_digest == baseline.state_digest
    assert plant.read_state().state_version == 0


def test_battery_dispatch_uses_the_storage_sign_convention_and_ack_readback(now) -> None:
    lab = build_physical_local_lab(now)
    pre_state = lab.plant.read_state()
    proposal = proposal_for_state(
        pre_state,
        proposal_id="m3-edge-battery",
        resource="battery-1",
        operation=Operation.DISPATCH_BATTERY,
        parameters={"mw": 0.5},
    )

    result = lab.controller.execute(proposal)

    assert result.status is ClosedLoopStatus.COMPLETED
    assert result.acknowledgment is not None
    assert result.acknowledgment.pre_actuator_setpoint == pytest.approx(
        pre_state.battery_injection_mw["battery-1"]
    )
    assert result.acknowledgment.post_actuator_setpoint == pytest.approx(0.5)
    assert result.post_state.battery_injection_mw["battery-1"] == pytest.approx(0.5)


def test_candidate_contract_rejects_digest_temporal_and_safety_inconsistency(now) -> None:
    plant = PandapowerCigreMVPlant(observed_at=now)
    command = TrustedCommandTranslator().translate(proposal_for_state(plant.read_state()))
    assessment = plant.simulate_candidate(command)

    model_changed = assessment.post_state.model_copy(update={"model_digest": "f" * 64})
    invalid_digest = assessment.post_state.model_copy(update={"state_digest": "e" * 64})
    wrong_version = _redigest_state(
        assessment.post_state,
        state_version=assessment.pre_state.state_version + 2,
    )
    static_simulation_time = _redigest_state(
        assessment.post_state,
        simulation_time_s=assessment.pre_state.simulation_time_s,
    )
    static_observation_time = _redigest_state(
        assessment.post_state,
        observed_at=assessment.pre_state.observed_at,
    )

    cases = [
        ({"post_state": model_changed}, "model digest changed"),
        ({"post_state": invalid_digest}, "invalid state digest"),
        ({"post_state": wrong_version}, "exactly one state version"),
        ({"post_state": static_simulation_time}, "advance simulation time"),
        ({"post_state": static_observation_time}, "advance observation time"),
        ({"safe": True, "reasons": ("contradiction",)}, "safe assessment"),
        ({"safe": False, "reasons": ()}, "unsafe assessment"),
        ({"safe": False, "reasons": ("contradiction",)}, "safety is inconsistent"),
    ]
    for updates, message in cases:
        data = assessment.model_dump(mode="python")
        data.update(updates)
        if isinstance(data["post_state"], PhysicalStateSnapshot):
            data["post_state"] = data["post_state"].model_dump(mode="python")
        with pytest.raises(ValidationError, match=message):
            CandidateAssessment.model_validate(data)


def test_state_command_permit_and_acknowledgment_validators_fail_closed(now) -> None:
    transaction = prepare_transaction(now)
    state_data = transaction.pre_state.model_dump(mode="python")
    state_data["observed_at"] = now.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="timezone-aware"):
        PhysicalStateSnapshot.model_validate(state_data)
    state_data = transaction.pre_state.model_dump(mode="python")
    state_data["simulation_time_s"] = float("inf")
    with pytest.raises(ValidationError):
        PhysicalStateSnapshot.model_validate(state_data)

    with pytest.raises(ValidationError, match="operation is inconsistent"):
        PhysicalControlCommand(
            proposal_id="shape",
            operation=Operation.DISPATCH_BATTERY,
            resource="feeder-1",
            command_type=PhysicalCommandType.SET_LINE_SERVICE,
            target="Line 5-6",
            target_index=4,
            setpoint=0.0,
            unit="boolean",
        )
    with pytest.raises(ValidationError):
        PhysicalControlCommand(
            proposal_id="nonfinite",
            operation=Operation.DISPATCH_BATTERY,
            resource="battery-1",
            command_type=PhysicalCommandType.SET_BATTERY_INJECTION,
            target="Battery 1",
            target_index=0,
            setpoint=float("inf"),
            unit="MW",
        )

    permit_data = transaction.permit.model_dump(mode="python")
    permit_data["issued_at"] = now.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="timezone-aware"):
        ExecutionPermit.model_validate(permit_data)
    permit_data = transaction.permit.model_dump(mode="python")
    permit_data["expires_at"] = permit_data["issued_at"]
    with pytest.raises(ValidationError, match="expiry"):
        ExecutionPermit.model_validate(permit_data)
    permit_data = transaction.permit.model_dump(mode="python")
    permit_data["proposal_id"] = "different-proposal"
    with pytest.raises(ValidationError, match="command does not match"):
        ExecutionPermit.model_validate(permit_data)
    permit_data = transaction.permit.model_dump(mode="python")
    permit_data["expected_post_state_version"] = transaction.permit.state_version + 2
    with pytest.raises(ValidationError, match="next state"):
        ExecutionPermit.model_validate(permit_data)

    acknowledgment = transaction.device.execute(
        transaction.permit,
        proposal=transaction.proposal,
        decision=transaction.decision,
        assessment=transaction.assessment,
    )
    ack_data = acknowledgment.model_dump(mode="python")
    ack_data["acknowledged_at"] = now.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="timezone-aware"):
        CommandAcknowledgment.model_validate(ack_data)
    ack_data = acknowledgment.model_dump(mode="python")
    ack_data["post_state_digest"] = None
    with pytest.raises(ValidationError, match="requires post-state"):
        CommandAcknowledgment.model_validate(ack_data)
    ack_data = acknowledgment.model_dump(mode="python")
    ack_data.update(
        {
            "status": CommandStatus.REJECTED,
            "post_state_digest": None,
            "post_state_version": None,
            "post_actuator_setpoint": acknowledgment.pre_actuator_setpoint + 1.0,
        }
    )
    with pytest.raises(ValidationError, match="unchanged actuator"):
        CommandAcknowledgment.model_validate(ack_data)
    ack_data = acknowledgment.model_dump(mode="python")
    ack_data.update(
        {
            "status": CommandStatus.UNKNOWN_EFFECT,
            "post_state_digest": None,
            "post_state_version": None,
        }
    )
    with pytest.raises(ValidationError, match="cannot assert actuator effect"):
        CommandAcknowledgment.model_validate(ack_data)


def test_completed_result_requires_full_applied_and_matching_evidence(now) -> None:
    lab = build_physical_local_lab(now)
    result = lab.controller.execute(proposal_for_state(lab.plant.read_state()))
    assert result.status is ClosedLoopStatus.COMPLETED

    data = result.model_dump(mode="python")
    data["acknowledgment"] = None
    with pytest.raises(ValidationError, match="applied acknowledgment"):
        ClosedLoopResult.model_validate(data)
    data = result.model_dump(mode="python")
    data["permit"] = None
    with pytest.raises(ValidationError, match="complete authorization path"):
        ClosedLoopResult.model_validate(data)
    data = result.model_dump(mode="python")
    data["post_state"] = result.pre_state.model_dump(mode="python")
    with pytest.raises(ValidationError, match="readback does not match"):
        ClosedLoopResult.model_validate(data)


def test_issuer_rejects_invalid_missing_and_misbound_evidence(now) -> None:
    transaction = prepare_transaction(now)
    record = transaction.authorization.gateway.evidence._records[0]
    transaction.authorization.gateway.evidence._records[0] = record.model_copy(
        update={"record_hash": "f" * 64}
    )
    with pytest.raises(PermitIssuanceError, match="evidence_chain_invalid"):
        transaction.issuer.issue(
            proposal=transaction.proposal,
            decision=transaction.decision,
            command=transaction.command,
            assessment=transaction.assessment,
        )

    empty_chain = EvidenceChain()
    missing_issuer = ExecutionPermitIssuer(
        transaction.permit_private,
        signing_key_id="edge-permit-key",
        audience="edge-device",
        evidence=empty_chain,
        clock=lambda: now,
    )
    with pytest.raises(PermitIssuanceError, match="evidence_not_found"):
        missing_issuer.issue(
            proposal=transaction.proposal,
            decision=transaction.decision,
            command=transaction.command,
            assessment=transaction.assessment,
        )

    wrong_chain = EvidenceChain()
    wrong_record = wrong_chain.append(
        proposal_id=transaction.proposal.proposal_id,
        decision_id=transaction.decision.decision_id,
        payload={"proposal": {}, "state": {}, "decision": {}},
    )
    wrong_decision = transaction.decision.model_copy(
        update={"evidence_record_hash": wrong_record.record_hash}
    )
    wrong_issuer = ExecutionPermitIssuer(
        transaction.permit_private,
        signing_key_id="edge-permit-key",
        audience="edge-device",
        evidence=wrong_chain,
        clock=lambda: now,
    )
    with pytest.raises(PermitIssuanceError, match="evidence_binding_mismatch"):
        wrong_issuer.issue(
            proposal=transaction.proposal,
            decision=wrong_decision,
            command=transaction.command,
            assessment=transaction.assessment,
        )


def test_issuer_rejects_recorded_decision_substitution(now) -> None:
    transaction = prepare_transaction(now)
    chain = EvidenceChain()
    recorded_decision = transaction.decision.model_copy(
        update={"evidence_record_hash": None, "reasons": ("substituted",)}
    )
    record = chain.append(
        proposal_id=transaction.proposal.proposal_id,
        decision_id=transaction.decision.decision_id,
        payload={
            "proposal": transaction.proposal.model_dump(mode="json"),
            "state": physical_state_to_gateway_state(transaction.pre_state).model_dump(
                mode="json"
            ),
            "decision": recorded_decision.model_dump(mode="json"),
        },
    )
    decision = transaction.decision.model_copy(
        update={"evidence_record_hash": record.record_hash}
    )
    issuer = ExecutionPermitIssuer(
        transaction.permit_private,
        signing_key_id="edge-permit-key",
        audience="edge-device",
        evidence=chain,
        clock=lambda: now,
    )

    with pytest.raises(PermitIssuanceError, match="evidence_binding_mismatch"):
        issuer.issue(
            proposal=transaction.proposal,
            decision=decision,
            command=transaction.command,
            assessment=transaction.assessment,
        )


def test_controller_rejects_unusable_state_translation_and_evidence_mismatch(now) -> None:
    lab = build_physical_local_lab(now)
    unusable = _redigest_state(
        lab.plant.read_state(),
        converged=False,
        minimum_voltage_pu=None,
        maximum_voltage_pu=None,
        maximum_line_loading_pct=None,
        unsafe_state=True,
    )

    class UnusableSource:
        def read_state(self) -> PhysicalStateSnapshot:
            return unusable

        def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
            raise AssertionError(f"candidate simulation must not run: {command.command_id}")

    with pytest.raises(PhysicalSimulationError, match="physical_state_not_usable"):
        physical_state_to_gateway_state(unusable)
    controller = PhysicalClosedLoopController(
        gateway=lab.authorization.gateway,
        plant=UnusableSource(),
        translator=lab.controller.translator,
        permit_issuer=lab.controller.permit_issuer,
        control_device=lab.control_device,
        evidence=lab.authorization.gateway.evidence,
        acknowledgment_public_key=lab.acknowledgment_public_key,
        clock=lambda: now,
    )
    with pytest.raises(PhysicalSimulationError, match="authorization_state_unavailable"):
        controller.execute(proposal_for_state(unusable, proposal_id="unusable-state"))

    with pytest.raises(ValueError, match="share one evidence chain"):
        PhysicalClosedLoopController(
            gateway=lab.authorization.gateway,
            plant=lab.plant,
            translator=lab.controller.translator,
            permit_issuer=lab.controller.permit_issuer,
            control_device=lab.control_device,
            evidence=EvidenceChain(),
            acknowledgment_public_key=lab.acknowledgment_public_key,
            clock=lambda: now,
        )


def test_controller_records_translation_failure_after_gateway_permit(now) -> None:
    lab = build_physical_local_lab(now)
    pre_state = lab.plant.read_state()
    proposal = proposal_for_state(
        pre_state,
        proposal_id="m3-edge-type-mismatch",
        resource="feeder-1",
        operation=Operation.DISPATCH_BATTERY,
        parameters={"mw": 0.5},
    )

    result = lab.controller.execute(proposal)

    assert result.decision.outcome is DecisionOutcome.PERMIT
    assert result.status is ClosedLoopStatus.NOT_DISPATCHED
    assert result.reasons == ("operation_resource_type_mismatch",)
    assert lab.plant.read_state().state_digest == pre_state.state_digest


def test_wire_numeric_and_payload_dimension_bounds_fail_closed() -> None:
    with pytest.raises(ValueError, match="byte length"):
        registers_to_bytes([], -1)
    with pytest.raises(ValueError, match="byte length"):
        registers_to_bytes([], MAX_PAYLOAD_BYTES + 1)
    with pytest.raises(ValueError, match="32-bit"):
        _u32_registers(-1)
    with pytest.raises(ValueError, match="32-bit"):
        _u32_registers(2**32)
    with pytest.raises(ValueError, match="64-bit"):
        _u64_registers(-1)
    with pytest.raises(ValueError, match="64-bit"):
        _u64_registers(2**64)
    with pytest.raises(ValueError, match="two registers"):
        _registers_u32([1])
    with pytest.raises(ValueError, match="four registers"):
        _registers_u64([1, 2])
    with pytest.raises(ValueError, match="sixteen registers"):
        _registers_digest([0])
    with pytest.raises(ValueError):
        _digest_registers("not-a-sha256-digest")


def test_wire_header_corruption_is_rejected_before_payload_use() -> None:
    payload = b"x"
    request = RequestHeader(
        control=ControlWord.BEGIN,
        operation=WireOperation.EXECUTE,
        transaction_id=5,
        payload_byte_length=1,
        payload_register_count=1,
        payload_digest=sha256_hex(payload),
    ).to_registers()
    with pytest.raises(ValueError, match="register count"):
        RequestHeader.from_registers(request[:-1])
    bad_magic = list(request)
    bad_magic[1] = 0
    with pytest.raises(ValueError, match="magic or version"):
        RequestHeader.from_registers(bad_magic)
    bad_dimensions = list(request)
    bad_dimensions[8:10] = _u32_registers(4)
    with pytest.raises(ValueError, match="dimensions"):
        RequestHeader.from_registers(bad_dimensions)

    response = ResponseHeader(
        status=WireStatus.COMPLETE,
        operation=WireOperation.EXECUTE,
        transaction_id=5,
        payload_byte_length=1,
        payload_register_count=1,
        result_code=WireResultCode.OK,
        payload_digest=sha256_hex(payload),
        device_transaction_counter=1,
        state_version_hint=0,
    ).to_registers()
    with pytest.raises(ValueError, match="register count"):
        ResponseHeader.from_registers(response[:-1])
    bad_magic = list(response)
    bad_magic[0] = 0
    with pytest.raises(ValueError, match="magic or version"):
        ResponseHeader.from_registers(bad_magic)
    reserved = list(response)
    reserved[36] = 1
    with pytest.raises(ValueError, match="reserved"):
        ResponseHeader.from_registers(reserved)
    bad_dimensions = list(response)
    bad_dimensions[8:10] = _u32_registers(4)
    with pytest.raises(ValueError, match="dimensions"):
        ResponseHeader.from_registers(bad_dimensions)


@pytest.mark.parametrize(
    "bindings",
    [
        {
            "wrong-key": ResourceBinding(
                resource="feeder-1",
                command_type=PhysicalCommandType.SET_LINE_SERVICE,
                target="Line 5-6",
                target_index=4,
                minimum_setpoint=0.0,
                maximum_setpoint=1.0,
            )
        },
        {
            "missing-line": ResourceBinding(
                resource="missing-line",
                command_type=PhysicalCommandType.SET_LINE_SERVICE,
                target="missing",
                target_index=999,
                minimum_setpoint=0.0,
                maximum_setpoint=1.0,
            )
        },
        {
            "missing-storage": ResourceBinding(
                resource="missing-storage",
                command_type=PhysicalCommandType.SET_BATTERY_INJECTION,
                target="missing",
                target_index=999,
                minimum_setpoint=-1.0,
                maximum_setpoint=1.0,
            )
        },
    ],
)
def test_resource_binding_configuration_rejects_key_and_target_drift(now, bindings) -> None:
    with pytest.raises(ValueError):
        PandapowerCigreMVPlant(observed_at=now, resource_bindings=bindings)


def test_solver_candidate_limit_and_scalar_edge_cases_are_explicit(now, monkeypatch) -> None:
    assert _json_scalar(np.int64(7)) == 7
    assert PandapowerCigreMVPlant._finite_tuple([1.0, float("nan")]) == (1.0, None)

    plant = PandapowerCigreMVPlant(
        observed_at=now,
        limits=PhysicalLimits(
            minimum_voltage_pu=0.96,
            maximum_line_loading_pct=0.0,
            minimum_total_load_served_pct=101.0,
            minimum_priority_load_served_pct=101.0,
        ),
    )
    command = TrustedCommandTranslator().translate(proposal_for_state(plant.read_state()))
    assessment = plant.simulate_candidate(command)
    assert not assessment.safe
    assert {
        "total_load_below_limit",
        "priority_load_below_limit",
        "voltage_limit_violation",
        "thermal_limit_violation",
    }.issubset(assessment.reasons)

    normal = PandapowerCigreMVPlant(observed_at=now)

    def fail_solver(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("injected solver failure")

    monkeypatch.setattr("aegis_ot.pandapower_plant.pp.runpp", fail_solver)
    candidate_net = copy.deepcopy(normal._net)
    assert not normal._solve(candidate_net)
    assert not candidate_net.converged


def test_baseline_solver_failure_is_reported(now, monkeypatch) -> None:
    monkeypatch.setattr(PandapowerCigreMVPlant, "_solve", lambda self, net: False)
    with pytest.raises(PhysicalSimulationError, match="baseline_power_flow_nonconvergent"):
        PandapowerCigreMVPlant(observed_at=now)


class _SuccessResponse:
    registers: list[int] = []

    @staticmethod
    def isError() -> bool:
        return False


class _ErrorResponse:
    @staticmethod
    def isError() -> bool:
        return True


class _FailBeforeCommitClient:
    def __init__(self) -> None:
        self.control_values: list[int] = []

    def write_registers(
        self,
        address: int,
        values: list[int],
        **kwargs: Any,
    ) -> _ErrorResponse | _SuccessResponse:
        del kwargs
        if address == 0 and RequestHeader.from_registers(values).control is ControlWord.RELEASE:
            self.control_values.append(int(ControlWord.RELEASE))
            return _SuccessResponse()
        return _ErrorResponse()

    def write_register(self, address: int, value: int, **kwargs: Any) -> _SuccessResponse:
        del address, kwargs
        self.control_values.append(value)
        return _SuccessResponse()


class _FailAfterCommitClient:
    def __init__(self) -> None:
        self.commit_count = 0
        self.release_count = 0

    def write_registers(
        self,
        address: int,
        values: list[int],
        **kwargs: Any,
    ) -> _SuccessResponse:
        del kwargs
        if (
            address == 0
            and RequestHeader.from_registers(values).control is ControlWord.RELEASE
        ):
            self.release_count += 1
        return _SuccessResponse()

    def write_register(self, address: int, value: int, **kwargs: Any) -> _SuccessResponse:
        del address, kwargs
        if value == int(ControlWord.COMMIT):
            self.commit_count += 1
        elif value == int(ControlWord.RELEASE):
            self.release_count += 1
        return _SuccessResponse()

    def read_holding_registers(self, *args: Any, **kwargs: Any) -> _SuccessResponse:
        raise OSError("injected response loss")


def _detached_modbus_client(transport: Any) -> ModbusPhysicalDeviceClient:
    client = object.__new__(ModbusPhysicalDeviceClient)
    client.info = SimpleNamespace(
        device_id="edge-modbus-device",
        device_key_id="edge-modbus-key",
        boot_epoch="edge-boot-epoch-0001",
    )
    client.device_id = client.info.device_id
    client.acknowledgment_key_id = client.info.device_key_id
    _, client.acknowledgment_public_key = generate_keypair()
    client._client = transport
    client._transaction_id = 0
    client._lock = RLock()
    return client


def test_modbus_failure_before_commit_is_not_promoted_to_unknown_effect() -> None:
    transport = _FailBeforeCommitClient()
    client = _detached_modbus_client(transport)

    with pytest.raises(ModbusTransportError, match="write-multiple-registers"):
        client._request(WireOperation.EXECUTE, {})

    assert transport.control_values == [int(ControlWord.RELEASE)]


def test_modbus_failure_after_commit_is_unknown_and_never_retried() -> None:
    transport = _FailAfterCommitClient()
    client = _detached_modbus_client(transport)

    with pytest.raises(ModbusUnknownEffectError, match="automatic retry is prohibited"):
        client._request(WireOperation.EXECUTE, {})

    assert transport.commit_count == 1
    assert transport.release_count == 0


def test_modbus_mailbox_readonly_limits_match_protocol_constants() -> None:
    assert REQUEST_HEADER_REGISTERS == 32
    assert RESPONSE_HEADER_REGISTERS == 40
    assert len(bytes_to_registers(b"x" * MAX_PAYLOAD_BYTES)) == MAX_PAYLOAD_BYTES // 2


def test_controlled_m3_session_preserves_condition_and_process_boundaries(
    controlled_m3_session,
) -> None:
    trials, events, components, verification, progress = controlled_m3_session

    assert progress == [(1, 1)]
    assert tuple(item["condition"] for item in trials) == m3.CONDITION_ORDER
    assert len(events) == verification[0]["evidence_record_count"]
    assert components[0]["separate_process_verified"] is True
    assert components[0]["process"]["pid"] != components[0]["parent_pid"]
    assert verification == [
        {
            "session_index": 0,
            "master_seed": 0x4D33,
            "evidence_chain_valid": True,
            "evidence_record_count": len(events),
            "condition_count": len(m3.CONDITION_ORDER),
            "trace_complete_count": len(m3.CONDITION_ORDER),
            "acknowledgment_verified_count": len(m3.CONDITION_ORDER),
        }
    ]

    records = {item["condition"]: item for item in trials}
    assert records["nominal_permitted_execution"]["terminal_status"] == "completed"
    assert records["nominal_permitted_execution"]["state_changed"] is True
    assert records["nominal_permitted_execution"]["device_applied"] is True
    for condition in (
        "unknown_identity",
        "stale_state",
        "wrong_audience_permit",
        "permit_replay",
    ):
        assert records[condition]["state_changed"] is False
        assert records[condition]["device_applied"] is False
    assert records["permit_replay"]["acknowledgment_reason"] == "permit_replayed"


def test_m3_summary_projection_and_preregistered_configuration(
    controlled_m3_session,
) -> None:
    trials, _, components, _, _ = controlled_m3_session

    summary = m3.summarize_m3(trials)
    assert summary["session_count"] == 1
    assert summary["condition_count"] == len(m3.CONDITION_ORDER)
    assert summary["trial_record_count"] == len(m3.CONDITION_ORDER)
    assert summary["denied_command_effect_rate_ci95"]["estimate"] == 0.0
    assert summary["unauthorized_device_acceptance_rate_ci95"]["estimate"] == 0.0
    assert summary["nominal_closed_loop_completion_rate_ci95"]["estimate"] == 1.0
    assert summary["nominal_post_state"]["unsafe_state_count"] == 0

    projection = m3._deterministic_projection(trials)
    assert [item["condition"] for item in projection] == list(m3.CONDITION_ORDER)
    assert all("latency_ms" not in item for item in projection)
    assert projection[3]["post_isolated_resources"] == ["feeder-1"]

    catalog = m3._scenario_catalog()
    assert catalog["execution_order"] == list(m3.CONDITION_ORDER)
    assert [item["name"] for item in catalog["conditions"]] == list(m3.CONDITION_ORDER)
    solver = m3._solver_configuration()
    assert solver["simulator"].startswith("pandapower-")
    assert solver["power_flow"] == dict(PandapowerCigreMVPlant.power_flow_options)
    benchmark = m3._benchmark_provenance(components[0]["process"]["model_digest"])
    assert benchmark["instantiated_model_digest"] == components[0]["process"]["model_digest"]
    assert benchmark["transformation"]["resource_bindings"]["feeder-1"]["target_index"] == 4
    assert m3.default_master_seeds(17, 3) == m3.default_master_seeds(17, 3)
    assert len(set(m3.default_master_seeds(17, 3))) == 3


def test_m3_statistics_and_condition_assertions_cover_fail_closed_edges(
    controlled_m3_session,
) -> None:
    trials, _, _, _, _ = controlled_m3_session

    assert m3._wilson(0, 0) == {
        "estimate": 0.0,
        "lower": 0.0,
        "upper": 0.0,
        "denominator": 0,
    }
    assert m3._wilson(0, 2)["lower"] == 0.0
    assert m3._wilson(2, 2)["upper"] == 1.0
    assert 0.0 < m3._wilson(1, 2)["lower"] < m3._wilson(1, 2)["upper"] < 1.0
    assert m3._percentile([7.0], 0.95) == 7.0
    assert m3._percentile([1.0, 2.0, 3.0], 0.5) == 2.0
    assert m3._percentile([1.0, 3.0], 0.5) == 2.0
    assert m3._latency_statistics([1.0, 2.0, 3.0]) == {
        "count": 3,
        "mean_ms": 2.0,
        "median_ms": 2.0,
        "population_stddev_ms": pytest.approx(0.816496580927726),
        "sample_stddev_ms": 1.0,
        "mean_normal_ci95_ms": {
            "lower": pytest.approx(0.8684142659238283),
            "upper": pytest.approx(3.1315857340761717),
        },
        "minimum_ms": 1.0,
        "p50_ms": 2.0,
        "p95_ms": pytest.approx(2.9),
        "p99_ms": pytest.approx(2.98),
        "maximum_ms": 3.0,
    }
    with pytest.raises(ValueError, match="at least one trial"):
        m3.summarize_m3([])
    with pytest.raises(ValueError, match="at least one master seed"):
        m3.run_m3_experiment(())

    nominal = next(
        item for item in trials if item["condition"] == "nominal_permitted_execution"
    )
    mutations = (
        ({"terminal_status": ClosedLoopStatus.NOT_DISPATCHED.value}, "returned"),
        ({"state_changed": False}, "unexpected state effect"),
        ({"trace_complete": False}, "incomplete evidence"),
        ({"acknowledgment_verified": False}, "incomplete evidence"),
        (
            {"physical_metrics": nominal["physical_metrics"] | {"unsafe_state": True}},
            "unsafe model state",
        ),
    )
    for updates, message in mutations:
        with pytest.raises(RuntimeError, match=message):
            m3._assert_condition(copy.deepcopy(nominal) | updates)


def test_stage_recorder_preserves_timing_when_an_operation_raises() -> None:
    recorder = m3._StageRecorder()
    assert recorder.call("stage", lambda: "ok") == "ok"

    def fail() -> None:
        raise RuntimeError("injected stage failure")

    with pytest.raises(RuntimeError, match="injected stage failure"):
        recorder.call("stage", fail)
    flattened = recorder.flattened()
    assert set(flattened) == {"stage_1", "stage_2"}
    assert all(value >= 0.0 for value in flattened.values())


def test_write_m3_experiment_emits_hash_bound_artifacts(
    controlled_m3_session,
    tmp_path,
    monkeypatch,
) -> None:
    trials, events, components, verification, _ = controlled_m3_session
    progress: list[tuple[int, int]] = []

    def replay_session(master_seeds, *, progress=None):
        assert master_seeds == (0x4D33,)
        if progress is not None:
            progress(1, 1)
        return copy.deepcopy((trials, events, components, verification))

    monkeypatch.setattr(m3, "run_m3_experiment", replay_session)
    monkeypatch.setattr(
        m3,
        "_git_state",
        lambda: {"commit": "a" * 40, "working_tree_dirty_at_start": False},
    )
    output_dir = tmp_path / "m3-results"
    manifest = m3.write_m3_experiment(
        output_dir,
        (0x4D33,),
        progress=lambda completed, total: progress.append((completed, total)),
    )

    assert progress == [(1, 1)]
    assert manifest["analyst"] == "Angelis Pseftis"
    assert manifest["session_count"] == 1
    assert manifest["trial_record_count"] == len(m3.CONDITION_ORDER)
    assert manifest["boundary"] == {
        "plant_and_device": "spawned child process",
        "transport": "Modbus TCP over host loopback",
        "controller": "parent Python process",
        "client_model": "one intended trusted loopback controller",
        "socket_session_ownership_enforced": False,
        "helics_exercised": False,
        "openplc_exercised": False,
        "containers_exercised": False,
    }
    expected_artifacts = {
        "trials.jsonl",
        "events.jsonl",
        "scenarios.json",
        "summary.json",
        "component-health.json",
        "evidence-verification.json",
        "benchmark/provenance.json",
        "solver/configuration.json",
    }
    assert set(manifest["artifact_sha256"]) == expected_artifacts
    assert all((output_dir / relative_path).is_file() for relative_path in expected_artifacts)
    stored_manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert stored_manifest == manifest
    assert len((output_dir / "trials.jsonl").read_text(encoding="utf-8").splitlines()) == 5
    assert manifest["model_digest"] == components[0]["process"]["model_digest"]
    assert len(manifest["deterministic_outcome_sha256"]) == 64


def test_write_m3_experiment_rejects_cross_session_model_drift(
    controlled_m3_session,
    tmp_path,
    monkeypatch,
) -> None:
    trials, events, components, verification, _ = controlled_m3_session
    drifted_component = copy.deepcopy(components[0])
    drifted_component["process"]["model_digest"] = "f" * 64
    monkeypatch.setattr(
        m3,
        "run_m3_experiment",
        lambda master_seeds, progress=None: (
            copy.deepcopy(trials),
            copy.deepcopy(events),
            copy.deepcopy(components) + [drifted_component],
            copy.deepcopy(verification),
        ),
    )

    with pytest.raises(RuntimeError, match="stable model digest"):
        m3.write_m3_experiment(tmp_path / "drift", (1, 2))


def test_m3_environment_probes_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        m3.subprocess,
        "check_output",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )
    assert m3._git_state() == {
        "commit": "unknown",
        "working_tree_dirty_at_start": False,
    }

    monkeypatch.setattr(
        m3.metadata,
        "distribution",
        lambda name: (_ for _ in ()).throw(m3.metadata.PackageNotFoundError(name)),
    )
    assert m3._distribution_file_hash("missing", "license") is None
