from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from aegis_ot.crypto import generate_keypair
from aegis_ot.factory import build_local_lab
from aegis_ot.models import ActionProposal, DecisionOutcome, Operation
from aegis_ot.pandapower_plant import PandapowerCigreMVPlant, PhysicalLimits
from aegis_ot.physical_control import (
    ExecutionPermitIssuer,
    PermitAwareVirtualControlDevice,
    PermitIssuanceError,
    PhysicalClosedLoopController,
    TrustedCommandTranslator,
    physical_state_to_gateway_state,
)
from aegis_ot.physical_factory import PhysicalLocalLab, build_physical_local_lab
from aegis_ot.physical_models import (
    ClosedLoopStatus,
    CommandStatus,
    ExecutionPermit,
    PhysicalStateSnapshot,
    canonical_digest,
)
from aegis_ot.safety import SafetyKernel, SafetyLimits


def proposal_for_state(
    state: PhysicalStateSnapshot,
    *,
    actor_id: str = "agent:operator-1",
    proposal_id: str = "m3-closed-loop-1",
    nonce: str = "m3-closed-loop-nonce-0001",
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


def prepare_permit(lab: PhysicalLocalLab, now):  # noqa: ANN001, ANN201
    pre_state = lab.plant.read_state()
    proposal = proposal_for_state(pre_state)
    decision = lab.authorization.gateway.decide(
        proposal,
        physical_state_to_gateway_state(pre_state),
        now,
    )
    command = lab.controller.translator.translate(proposal)
    assessment = lab.plant.simulate_candidate(command)
    permit = lab.controller.permit_issuer.issue(
        proposal=proposal,
        decision=decision,
        command=command,
        assessment=assessment,
    )
    return pre_state, proposal, decision, command, assessment, permit


def test_nominal_closed_loop_requires_acknowledgment_and_matching_readback(now) -> None:
    lab = build_physical_local_lab(now)
    pre = lab.plant.read_state()
    result = lab.controller.execute(proposal_for_state(pre))
    assert result.status is ClosedLoopStatus.COMPLETED
    assert result.decision.outcome is DecisionOutcome.PERMIT
    assert result.permit is not None and result.permit.verify(lab.permit_public_key)
    assert result.acknowledgment is not None
    assert result.acknowledgment.status is CommandStatus.APPLIED
    assert result.acknowledgment.verify(lab.acknowledgment_public_key)
    assert result.post_state.state_version == result.pre_state.state_version + 1
    assert result.post_state.state_digest == result.acknowledgment.post_state_digest
    assert result.post_state.isolated_resources == ("feeder-1",)
    assert len(lab.authorization.gateway.evidence.records) == 2
    assert lab.authorization.gateway.evidence.verify()


def test_fresh_observation_envelope_supports_sequential_closed_loop_actions(now) -> None:
    lab = build_physical_local_lab(now)
    first = lab.controller.execute(proposal_for_state(lab.plant.read_state()))
    assert first.status is ClosedLoopStatus.COMPLETED

    second_pre = lab.plant.read_state()
    second_proposal = ActionProposal(
        proposal_id="m3-sequential-battery",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="battery-1",
        operation=Operation.DISPATCH_BATTERY,
        parameters={
            "mw": 0.25,
            "minimum_voltage_delta_pu": 0.0,
            "maximum_voltage_delta_pu": 0.0,
        },
        observed_state_version=second_pre.state_version,
        observed_at=second_pre.observed_at,
        submitted_at=second_pre.observed_at,
        nonce="m3-sequential-battery-nonce-0001",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )
    second = lab.controller.execute(second_proposal)
    assert second.status is ClosedLoopStatus.COMPLETED
    assert second.post_state is not None
    assert second.post_state.state_version == 2
    assert second.post_state.battery_injection_mw["battery-1"] == pytest.approx(0.25)


def test_denied_action_never_reaches_control_device_or_changes_plant(now) -> None:
    lab = build_physical_local_lab(now)
    pre = lab.plant.read_state()
    proposal = proposal_for_state(pre, actor_id="agent:unknown")
    result = lab.controller.execute(proposal)
    post = lab.plant.read_state()
    assert result.status is ClosedLoopStatus.NOT_DISPATCHED
    assert "identity_not_verified" in result.reasons
    assert result.command is None
    assert result.permit is None
    assert result.acknowledgment is None
    assert post.state_version == pre.state_version
    assert post.state_digest == pre.state_digest


def test_candidate_violation_blocks_permit_after_gateway_permit(now) -> None:
    authorization = build_local_lab(now)
    authorization.gateway.safety = SafetyKernel(
        SafetyLimits(minimum_voltage_pu=0.90, maximum_voltage_pu=1.10),
        version="test-m3-gateway-limits",
    )
    plant = PandapowerCigreMVPlant(
        observed_at=now,
        limits=PhysicalLimits(minimum_voltage_pu=0.96),
    )
    permit_private, permit_public = generate_keypair()
    ack_private, ack_public = generate_keypair()
    issuer = ExecutionPermitIssuer(
        permit_private,
        signing_key_id="permit-key",
        audience="device:test",
        evidence=authorization.gateway.evidence,
        clock=lambda: now,
    )
    device = PermitAwareVirtualControlDevice(
        plant,
        device_id="device:test",
        permit_audience="device:test",
        permit_public_keys={"permit-key": permit_public},
        acknowledgment_private_key=ack_private,
        acknowledgment_key_id="ack-key",
        clock=lambda: now,
    )
    controller = PhysicalClosedLoopController(
        gateway=authorization.gateway,
        plant=plant,
        translator=TrustedCommandTranslator(),
        permit_issuer=issuer,
        control_device=device,
        evidence=authorization.gateway.evidence,
        acknowledgment_public_key=ack_public,
        clock=lambda: now,
    )
    proposal = proposal_for_state(plant.read_state())
    result = controller.execute(proposal)
    assert result.decision.outcome is DecisionOutcome.PERMIT
    assert result.status is ClosedLoopStatus.CANDIDATE_REJECTED
    assert result.permit is None
    assert "voltage_limit_violation" in result.reasons
    assert plant.read_state().state_version == 0


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ({"audience": "device:wrong"}, "permit_wrong_audience"),
        ({"state_digest": "f" * 64}, "permit_signature_invalid"),
        ({"proposal_digest": "e" * 64}, "permit_signature_invalid"),
    ],
)
def test_device_rejects_tampered_permit_without_effect(now, mutation, reason) -> None:
    lab = build_physical_local_lab(now)
    pre, proposal, decision, _, assessment, permit = prepare_permit(lab, now)
    tampered = permit.model_copy(update=mutation)
    acknowledgment = lab.control_device.execute(
        tampered,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    post = lab.plant.read_state()
    assert acknowledgment.status is CommandStatus.REJECTED
    assert acknowledgment.reason == reason
    assert acknowledgment.verify(lab.acknowledgment_public_key)
    assert post.state_digest == pre.state_digest


def test_device_rejects_expired_and_unknown_key_permits(now) -> None:
    lab = build_physical_local_lab(now)
    pre, proposal, decision, _, assessment, permit = prepare_permit(lab, now)
    expired_private, expired_public = generate_keypair()
    expired_device = PermitAwareVirtualControlDevice(
        lab.plant,
        device_id="virtual-control-device:m3",
        permit_audience="virtual-control-device:m3",
        permit_public_keys={"m3-permit-key-1": lab.permit_public_key},
        acknowledgment_private_key=expired_private,
        acknowledgment_key_id="expired-test-ack",
        clock=lambda: now + timedelta(seconds=3),
    )
    expired = expired_device.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    unknown_key = permit.model_copy(update={"signing_key_id": "unknown-key"})
    unknown = lab.control_device.execute(
        unknown_key,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    assert expired.reason == "permit_expired"
    assert expired.verify(expired_public)
    assert unknown.reason == "permit_unknown_signing_key"
    assert lab.plant.read_state().state_digest == pre.state_digest


def test_device_replay_has_exactly_one_physical_effect(now) -> None:
    lab = build_physical_local_lab(now)
    _, proposal, decision, _, assessment, permit = prepare_permit(lab, now)
    first = lab.control_device.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    second = lab.control_device.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    assert first.status is CommandStatus.APPLIED
    assert second.status is CommandStatus.REJECTED
    assert second.reason == "permit_replayed"
    assert lab.plant.read_state().state_version == 1


def test_concurrent_same_permit_has_one_effect_and_atomic_replay_reservation(now) -> None:
    lab = build_physical_local_lab(now)
    _, proposal, decision, _, assessment, permit = prepare_permit(lab, now)

    def dispatch(_index):  # noqa: ANN001, ANN202
        return lab.control_device.execute(
            permit,
            proposal=proposal,
            decision=decision,
            assessment=assessment,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        acknowledgments = list(pool.map(dispatch, range(8)))
    assert sum(item.status is CommandStatus.APPLIED for item in acknowledgments) == 1
    assert sum(item.reason == "permit_replayed" for item in acknowledgments) == 7
    assert len({item.device_scan for item in acknowledgments}) == 8
    assert lab.plant.read_state().state_version == 1


def test_concurrent_distinct_permits_on_one_prestate_commit_once(now) -> None:
    lab = build_physical_local_lab(now)
    pre = lab.plant.read_state()
    prepared = []
    for index in range(2):
        proposal = proposal_for_state(
            pre,
            proposal_id=f"concurrent-{index}",
            nonce=f"concurrent-permit-nonce-{index:04d}",
        )
        decision = lab.authorization.gateway.decide(
            proposal,
            physical_state_to_gateway_state(pre),
            now,
        )
        command = lab.controller.translator.translate(proposal)
        assessment = lab.plant.simulate_candidate(command)
        permit = lab.controller.permit_issuer.issue(
            proposal=proposal,
            decision=decision,
            command=command,
            assessment=assessment,
        )
        prepared.append((proposal, decision, assessment, permit))

    def dispatch(item):  # noqa: ANN001, ANN202
        proposal, decision, assessment, permit = item
        return lab.control_device.execute(
            permit,
            proposal=proposal,
            decision=decision,
            assessment=assessment,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        acknowledgments = list(pool.map(dispatch, prepared))
    assert sum(item.status is CommandStatus.APPLIED for item in acknowledgments) == 1
    assert sum(item.status is CommandStatus.REJECTED for item in acknowledgments) == 1
    assert {
        item.reason for item in acknowledgments if item.status is CommandStatus.REJECTED
    } <= {"state_version_changed", "state_digest_changed", "topology_digest_changed"}
    assert lab.plant.read_state().state_version == 1


class StaticPlant:
    def __init__(
        self,
        state: PhysicalStateSnapshot,
        *,
        assessment=None,  # noqa: ANN001
        unexpected_failure: bool = False,
    ) -> None:
        self.state = state
        self.assessment = assessment
        self.unexpected_failure = unexpected_failure

    def read_state(self):  # noqa: ANN201
        return self.state

    def simulate_candidate(self, command):  # noqa: ANN001, ANN201, ARG002
        if self.assessment is None:
            raise RuntimeError("candidate simulation was not configured")
        return self.assessment

    def apply_authorized_command(self, command, **kwargs):  # noqa: ANN001, ANN201, ARG002
        if self.unexpected_failure:
            raise RuntimeError("injected failure after dispatch boundary")
        return self.state


class DivergentPlant(StaticPlant):
    def __init__(
        self,
        state: PhysicalStateSnapshot,
        divergent: PhysicalStateSnapshot,
        assessment,
    ) -> None:  # noqa: ANN001
        super().__init__(state, assessment=assessment)
        self.divergent = divergent

    def apply_authorized_command(self, command, **kwargs):  # noqa: ANN001, ANN201, ARG002
        return self.divergent


def test_same_version_different_state_digest_is_rejected(now) -> None:
    lab = build_physical_local_lab(now)
    pre, proposal, decision, _, assessment, permit = prepare_permit(lab, now)
    changed = pre.model_copy(
        update={
            "battery_injection_mw": {"battery-1": 0.25},
            "state_digest": "0" * 64,
        }
    )
    changed = changed.model_copy(
        update={"state_digest": canonical_digest(changed.digest_material())}
    )
    changed = changed.model_copy(
        update={"observation_digest": canonical_digest(changed.observation_material())}
    )
    ack_private, ack_public = generate_keypair()
    device = PermitAwareVirtualControlDevice(
        StaticPlant(changed),
        device_id="virtual-control-device:m3",
        permit_audience="virtual-control-device:m3",
        permit_public_keys={"m3-permit-key-1": lab.permit_public_key},
        acknowledgment_private_key=ack_private,
        acknowledgment_key_id="test-ack",
        clock=lambda: now,
    )
    acknowledgment = device.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    assert acknowledgment.status is CommandStatus.REJECTED
    assert acknowledgment.reason == "state_digest_changed"
    assert acknowledgment.verify(ack_public)


def test_unexpected_dispatch_failure_is_unknown_effect_and_not_retried(now) -> None:
    lab = build_physical_local_lab(now)
    pre, proposal, decision, _, assessment, permit = prepare_permit(lab, now)
    ack_private, ack_public = generate_keypair()
    device = PermitAwareVirtualControlDevice(
        StaticPlant(pre, assessment=assessment, unexpected_failure=True),
        device_id="virtual-control-device:m3",
        permit_audience="virtual-control-device:m3",
        permit_public_keys={"m3-permit-key-1": lab.permit_public_key},
        acknowledgment_private_key=ack_private,
        acknowledgment_key_id="test-ack",
        clock=lambda: now,
    )
    first = device.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    second = device.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    assert first.status is CommandStatus.UNKNOWN_EFFECT
    assert first.reason == "unclassified_dispatch_failure"
    assert first.verify(ack_public)
    assert second.status is CommandStatus.REJECTED
    assert second.reason == "permit_replayed"


def test_post_dispatch_candidate_divergence_cannot_be_reported_as_applied(now) -> None:
    lab = build_physical_local_lab(now)
    pre, proposal, decision, _, assessment, permit = prepare_permit(lab, now)
    divergent = assessment.post_state.model_copy(
        update={
            "served_load_mw": assessment.post_state.served_load_mw - 0.01,
            "state_digest": "0" * 64,
        }
    )
    divergent = divergent.model_copy(
        update={"state_digest": canonical_digest(divergent.digest_material())}
    )
    ack_private, ack_public = generate_keypair()
    device = PermitAwareVirtualControlDevice(
        DivergentPlant(pre, divergent, assessment),
        device_id="virtual-control-device:m3",
        permit_audience="virtual-control-device:m3",
        permit_public_keys={"m3-permit-key-1": lab.permit_public_key},
        acknowledgment_private_key=ack_private,
        acknowledgment_key_id="test-ack",
        clock=lambda: now,
    )
    acknowledgment = device.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    assert acknowledgment.status is CommandStatus.UNKNOWN_EFFECT
    assert acknowledgment.reason == "post_dispatch_candidate_divergence"
    assert acknowledgment.verify(ack_public)


def test_acknowledgment_transaction_verification_rejects_validly_signed_substitution(now) -> None:
    lab = build_physical_local_lab(now)
    pre, proposal, decision, _, assessment, permit = prepare_permit(lab, now)
    ack_private, ack_public = generate_keypair()
    device = PermitAwareVirtualControlDevice(
        lab.plant,
        device_id="virtual-control-device:m3",
        permit_audience="virtual-control-device:m3",
        permit_public_keys={"m3-permit-key-1": lab.permit_public_key},
        acknowledgment_private_key=ack_private,
        acknowledgment_key_id="test-ack",
        clock=lambda: now,
    )
    acknowledgment = device.execute(
        permit,
        proposal=proposal,
        decision=decision,
        assessment=assessment,
    )
    post = lab.plant.read_state()
    assert acknowledgment.verify_for_transaction(
        ack_public,
        permit=permit,
        pre_state=pre,
        readback_state=post,
        expected_device_id=device.device_id,
        expected_key_id=device.acknowledgment_key_id,
    )
    substituted = acknowledgment.model_copy(update={"permit_id": "stale-other-permit"}).signed(
        ack_private
    )
    assert substituted.verify(ack_public)
    assert not substituted.verify_for_transaction(
        ack_public,
        permit=permit,
        pre_state=pre,
        readback_state=post,
        expected_device_id=device.device_id,
        expected_key_id=device.acknowledgment_key_id,
    )


class TamperingDevice:
    def __init__(self, delegate: PermitAwareVirtualControlDevice) -> None:
        self.delegate = delegate
        self.device_id = delegate.device_id
        self.acknowledgment_key_id = delegate.acknowledgment_key_id

    def execute(  # noqa: ANN201
        self,
        permit,  # noqa: ANN001
        *,
        proposal,  # noqa: ANN001
        decision,  # noqa: ANN001
        assessment,  # noqa: ANN001
    ):
        valid = self.delegate.execute(
            permit,
            proposal=proposal,
            decision=decision,
            assessment=assessment,
        )
        return valid.model_copy(update={"signature": "invalid"})


def test_controller_does_not_report_success_for_invalid_acknowledgment(now) -> None:
    lab = build_physical_local_lab(now)
    lab.controller.control_device = TamperingDevice(lab.control_device)  # type: ignore[assignment]
    proposal = proposal_for_state(lab.plant.read_state())
    result = lab.controller.execute(proposal)
    assert result.status is ClosedLoopStatus.UNKNOWN_EFFECT
    assert "acknowledgment_signature_invalid" in result.reasons


def test_permit_issuer_refuses_incomplete_or_inconsistent_bindings(now) -> None:
    lab = build_physical_local_lab(now)
    _, proposal, decision, command, assessment, _ = prepare_permit(lab, now)
    issuer = lab.controller.permit_issuer
    with pytest.raises(PermitIssuanceError, match="decision_not_permit"):
        issuer.issue(
            proposal=proposal,
            decision=decision.model_copy(update={"outcome": DecisionOutcome.DENY}),
            command=command,
            assessment=assessment,
        )
    with pytest.raises(PermitIssuanceError, match="proposal_decision_mismatch"):
        issuer.issue(
            proposal=proposal,
            decision=decision.model_copy(update={"proposal_id": "different"}),
            command=command,
            assessment=assessment,
        )
    with pytest.raises(PermitIssuanceError, match="decision_evidence_missing"):
        issuer.issue(
            proposal=proposal,
            decision=decision.model_copy(update={"evidence_record_hash": None}),
            command=command,
            assessment=assessment,
        )
    unsafe_plant = PandapowerCigreMVPlant(
        observed_at=now,
        limits=PhysicalLimits(minimum_voltage_pu=0.96),
    )
    unsafe_assessment = unsafe_plant.simulate_candidate(command)
    with pytest.raises(PermitIssuanceError, match="candidate_not_safe"):
        issuer.issue(
            proposal=proposal,
            decision=decision,
            command=command,
            assessment=unsafe_assessment,
        )
    with pytest.raises(PermitIssuanceError, match="candidate_command_mismatch"):
        issuer.issue(
            proposal=proposal,
            decision=decision,
            command=command,
            assessment=assessment.model_copy(update={"command_digest": "a" * 64}),
        )
    with pytest.raises(PermitIssuanceError, match="decision_state_version_mismatch"):
        issuer.issue(
            proposal=proposal,
            decision=decision.model_copy(update={"state_version": 99}),
            command=command,
            assessment=assessment,
        )
    invalid_pre = assessment.pre_state.model_copy(update={"state_digest": "b" * 64})
    with pytest.raises(
        PermitIssuanceError,
        match="authorization_artifact_not_structurally_valid",
    ):
        issuer.issue(
            proposal=proposal,
            decision=decision,
            command=command,
            assessment=assessment.model_copy(update={"pre_state": invalid_pre}),
        )


def test_permit_contract_rejects_inconsistent_command_digest(now) -> None:
    lab = build_physical_local_lab(now)
    _, _, _, _, _, permit = prepare_permit(lab, now)
    data = permit.model_dump(mode="python")
    data["command_digest"] = "c" * 64
    with pytest.raises(ValueError, match="command digest is inconsistent"):
        ExecutionPermit.model_validate(data)
