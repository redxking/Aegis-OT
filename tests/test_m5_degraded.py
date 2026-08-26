from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_ot.capability_models import CapabilityActionRequest
from aegis_ot.evidence import EvidenceChain
from aegis_ot.m5_degraded import (
    ROLE_LOSS_POLICIES,
    DegradedAdmissionOutcome,
    DegradedBehavior,
    DegradedModeAuthorization,
    DegradedModeReversal,
    DegradedOperationGate,
    DegradedRole,
    DegradedRuntimeSnapshot,
    FileDegradedOperationStateStore,
    RoleCondition,
)
from aegis_ot.models import DecisionOutcome, Operation
from aegis_ot.physical_models import canonical_digest
from aegis_ot.segmented_capability_runtime import (
    CapabilityAdmissionRejected,
    CapabilityGatewayRuntime,
)

NOW = datetime(2026, 8, 26, 14, 0, tzinfo=UTC)
AUTHORITY_ID = "m5-degraded-authority"


def _healthy_conditions() -> dict[DegradedRole, RoleCondition]:
    return {role: RoleCondition.HEALTHY for role in DegradedRole}


def _snapshot(
    *,
    role: DegradedRole | None = None,
    communication: bool = False,
    condition: RoleCondition = RoleCondition.UNAVAILABLE,
    unresolved_effect: bool = False,
) -> DegradedRuntimeSnapshot:
    services = _healthy_conditions()
    paths = _healthy_conditions()
    if role is not None:
        (paths if communication else services)[role] = condition
    return DegradedRuntimeSnapshot(
        snapshot_id="degraded-snapshot-20260826-0001",
        captured_at=NOW,
        role_conditions=services,
        communication_conditions=paths,
        unresolved_effect=unresolved_effect,
    )


def _authorization(
    private_key: Ed25519PrivateKey,
    snapshot: DegradedRuntimeSnapshot,
    *,
    role: DegradedRole,
    behavior: DegradedBehavior | None = None,
    allowed_missions: frozenset[str] = frozenset({"microgrid-containment"}),
    allowed_resources: frozenset[str] = frozenset({"feeder-1"}),
    allowed_operations: frozenset[Operation] = frozenset({Operation.ISOLATE_ASSET}),
    maximum_risk_score: float = 65.0,
    sequence: int = 1,
    issued_at: datetime = NOW - timedelta(seconds=1),
    expires_at: datetime = NOW + timedelta(minutes=1),
) -> DegradedModeAuthorization:
    selected_behavior = ROLE_LOSS_POLICIES[role].behavior if behavior is None else behavior
    return DegradedModeAuthorization(
        authorization_id=f"degraded-authorization-{role.value}-{sequence}",
        sequence=sequence,
        authority_id=AUTHORITY_ID,
        mode_name=f"{role.value}-loss-degraded",
        behavior=selected_behavior,
        affected_roles=frozenset({role}),
        allowed_actor_ids=frozenset({"agent:operator-1"}),
        allowed_mission_ids=allowed_missions,
        allowed_resources=allowed_resources,
        allowed_operations=allowed_operations,
        maximum_risk_score=maximum_risk_score,
        snapshot_sha256=snapshot.digest,
        recovery_checkpoint_id=f"recovery-checkpoint-{role.value}",
        nonce=f"degraded-nonce-{role.value}-{sequence:04d}",
        issued_at=issued_at,
        expires_at=expires_at,
    ).signed(private_key)


def _gate(
    private_key: Ed25519PrivateKey,
    snapshot: DegradedRuntimeSnapshot,
    authorization: DegradedModeAuthorization | None,
    *,
    state_store: Any = None,
) -> DegradedOperationGate:
    return DegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=private_key.public_key(),
        snapshot_source=lambda: snapshot,
        authorization_source=lambda: authorization,
        state_store=state_store,
    )


def _reversal(
    private_key: Ed25519PrivateKey,
    authorization: DegradedModeAuthorization,
) -> DegradedModeReversal:
    return DegradedModeReversal(
        reversal_id="degraded-reversal-20260826-0001",
        sequence=1,
        authority_id=AUTHORITY_ID,
        authorization_id=authorization.authorization_id,
        authorization_sha256=authorization.digest,
        recovery_checkpoint_id=authorization.recovery_checkpoint_id,
        reason_code="runtime_dependencies_recovered",
        nonce="degraded-reversal-nonce-0001",
        issued_at=NOW,
    ).signed(private_key)


def test_role_matrix_is_complete_and_only_management_can_preserve_mission() -> None:
    assert set(ROLE_LOSS_POLICIES) == set(DegradedRole)
    assert {
        role
        for role, policy in ROLE_LOSS_POLICIES.items()
        if policy.mission_preserving_eligible
    } == {DegradedRole.MANAGEMENT}
    assert ROLE_LOSS_POLICIES[DegradedRole.IDENTITY].behavior is DegradedBehavior.SAFE_STATE
    assert ROLE_LOSS_POLICIES[DegradedRole.OBSERVER].behavior is DegradedBehavior.HOLD_STATE
    assert ROLE_LOSS_POLICIES[DegradedRole.EVALUATOR].behavior is DegradedBehavior.HOLD_STATE
    assert ROLE_LOSS_POLICIES[DegradedRole.COORDINATION].behavior is DegradedBehavior.HOLD_STATE
    assert ROLE_LOSS_POLICIES[DegradedRole.OT_ADAPTER].behavior is DegradedBehavior.HOLD_STATE


@pytest.mark.parametrize("role", list(DegradedRole))
@pytest.mark.parametrize("communication", [False, True], ids=["service", "path"])
def test_each_role_and_communication_loss_has_a_bounded_non_bypass_behavior(
    role: DegradedRole,
    communication: bool,
    proposal: Any,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=role, communication=communication)
    authorization = _authorization(private_key, snapshot, role=role)

    result = _gate(private_key, snapshot, authorization).evaluate(proposal, now=NOW)

    expected = ROLE_LOSS_POLICIES[role].behavior
    if expected is DegradedBehavior.MISSION_PRESERVING:
        assert result.outcome is DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE
        assert result.may_enter_primary_assurance
    elif expected is DegradedBehavior.HOLD_STATE:
        assert result.outcome is DegradedAdmissionOutcome.HOLD_STATE
        assert not result.may_enter_primary_assurance
    else:
        assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
        assert not result.may_enter_primary_assurance
    assert not result.execution_authorized
    assert result.authorization_sha256 == authorization.digest
    assert result.recovery_checkpoint_id == authorization.recovery_checkpoint_id
    assert len(result.observable_event_sha256) == 64


@pytest.mark.parametrize(
    "mutation",
    ["missing", "forged", "wrong_behavior", "stale_evidence", "expired"],
)
def test_missing_or_invalid_degraded_authority_fails_safe(
    mutation: str,
    proposal: Any,
) -> None:
    pinned_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization: DegradedModeAuthorization | None = _authorization(
        pinned_key,
        snapshot,
        role=DegradedRole.MANAGEMENT,
    )
    if mutation == "missing":
        authorization = None
    elif mutation == "forged":
        authorization = _authorization(
            Ed25519PrivateKey.generate(),
            snapshot,
            role=DegradedRole.MANAGEMENT,
        )
    elif mutation == "wrong_behavior":
        authorization = _authorization(
            pinned_key,
            snapshot,
            role=DegradedRole.MANAGEMENT,
            behavior=DegradedBehavior.HOLD_STATE,
        )
    elif mutation == "stale_evidence":
        authorization = _authorization(
            pinned_key,
            _snapshot(role=DegradedRole.MANAGEMENT, communication=True),
            role=DegradedRole.MANAGEMENT,
        )
    else:
        authorization = _authorization(
            pinned_key,
            snapshot,
            role=DegradedRole.MANAGEMENT,
            issued_at=NOW - timedelta(minutes=2),
            expires_at=NOW - timedelta(minutes=1),
        )

    result = _gate(pinned_key, snapshot, authorization).evaluate(proposal, now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert not result.may_enter_primary_assurance
    assert not result.execution_authorized


@pytest.mark.parametrize(
    "condition",
    [
        RoleCondition.UNAVAILABLE,
        RoleCondition.UNKNOWN,
        RoleCondition.CONFLICTING,
    ],
)
def test_unavailable_unknown_and_conflicting_role_state_cannot_default_allow(
    condition: RoleCondition,
    proposal: Any,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(
        role=DegradedRole.OBSERVER,
        condition=condition,
    )

    result = _gate(private_key, snapshot, None).evaluate(proposal, now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert not result.may_enter_primary_assurance
    assert f"observer_service_{condition.value}" in result.reasons
    assert "degraded_mode_authorization_missing" in result.reasons


def test_mission_preserving_scope_and_pending_effects_are_held(
    proposal: Any,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    out_of_scope = _authorization(
        private_key,
        snapshot,
        role=DegradedRole.MANAGEMENT,
        allowed_resources=frozenset({"feeder-2"}),
    )
    scoped_result = _gate(private_key, snapshot, out_of_scope).evaluate(
        proposal,
        now=NOW,
    )

    unresolved = _snapshot(
        role=DegradedRole.MANAGEMENT,
        unresolved_effect=True,
    )
    unresolved_result = _gate(
        private_key,
        unresolved,
        _authorization(
            private_key,
            unresolved,
            role=DegradedRole.MANAGEMENT,
        ),
    ).evaluate(proposal, now=NOW)

    assert scoped_result.outcome is DegradedAdmissionOutcome.HOLD_STATE
    assert "degraded_resource_out_of_scope" in scoped_result.reasons
    assert unresolved_result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_unresolved_effect_blocks_new_work" in unresolved_result.reasons

    wrong_actor = proposal.model_copy(update={"actor_id": "agent:other"})
    actor_result = _gate(
        private_key,
        snapshot,
        _authorization(
            private_key,
            snapshot,
            role=DegradedRole.MANAGEMENT,
        ),
    ).evaluate(wrong_actor, now=NOW)
    assert actor_result.outcome is DegradedAdmissionOutcome.HOLD_STATE
    assert "degraded_actor_out_of_scope" in actor_result.reasons


def test_degraded_lease_sequence_rollback_fails_safe(proposal: Any) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    current = {
        "authorization": _authorization(
            private_key,
            snapshot,
            role=DegradedRole.MANAGEMENT,
            sequence=2,
        )
    }
    gate = DegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=private_key.public_key(),
        snapshot_source=lambda: snapshot,
        authorization_source=lambda: current["authorization"],
    )

    assert gate.evaluate(proposal, now=NOW).may_enter_primary_assurance
    current["authorization"] = _authorization(
        private_key,
        snapshot,
        role=DegradedRole.MANAGEMENT,
        sequence=1,
    )
    rolled_back = gate.evaluate(proposal, now=NOW)

    assert rolled_back.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_authorization_sequence_not_monotonic" in rolled_back.reasons


def test_file_state_rejects_lease_rollback_after_gate_replacement(
    proposal: Any,
    tmp_path: Any,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    state_dir = tmp_path / "m5-state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    state_path = state_dir / "degraded-state.json"
    current = _authorization(
        private_key,
        snapshot,
        role=DegradedRole.MANAGEMENT,
        sequence=2,
    )
    first = _gate(
        private_key,
        snapshot,
        current,
        state_store=FileDegradedOperationStateStore(
            state_path,
            authority_id=AUTHORITY_ID,
        ),
    )

    assert first.evaluate(proposal, now=NOW).may_enter_primary_assurance
    assert state_path.stat().st_mode & 0o777 == 0o600

    rolled_back = _gate(
        private_key,
        snapshot,
        _authorization(
            private_key,
            snapshot,
            role=DegradedRole.MANAGEMENT,
            sequence=1,
        ),
        state_store=FileDegradedOperationStateStore(
            state_path,
            authority_id=AUTHORITY_ID,
        ),
    ).evaluate(proposal, now=NOW)

    assert rolled_back.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_authorization_sequence_not_monotonic" in rolled_back.reasons


def test_file_state_persists_reversal_and_replay_defense_across_replacement(
    proposal: Any,
    tmp_path: Any,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(
        private_key,
        snapshot,
        role=DegradedRole.MANAGEMENT,
    )
    state_dir = tmp_path / "m5-reversal-state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    state_path = state_dir / "degraded-state.json"
    first = _gate(
        private_key,
        snapshot,
        authorization,
        state_store=FileDegradedOperationStateStore(
            state_path,
            authority_id=AUTHORITY_ID,
        ),
    )
    reversal = _reversal(private_key, authorization)

    assert first.evaluate(proposal, now=NOW).may_enter_primary_assurance
    assert first.apply_reversal(reversal, authorization, now=NOW).applied

    replacement = _gate(
        private_key,
        snapshot,
        authorization,
        state_store=FileDegradedOperationStateStore(
            state_path,
            authority_id=AUTHORITY_ID,
        ),
    )
    denied = replacement.evaluate(proposal, now=NOW)
    replayed = replacement.apply_reversal(reversal, authorization, now=NOW)

    assert denied.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_authorization_revoked" in denied.reasons
    assert not replayed.applied
    assert "degraded_reversal_replayed" in replayed.reasons


def test_tampered_file_state_fails_closed(proposal: Any, tmp_path: Any) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(
        private_key,
        snapshot,
        role=DegradedRole.MANAGEMENT,
    )
    state_dir = tmp_path / "m5-tampered-state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    state_path = state_dir / "degraded-state.json"
    gate = _gate(
        private_key,
        snapshot,
        authorization,
        state_store=FileDegradedOperationStateStore(
            state_path,
            authority_id=AUTHORITY_ID,
        ),
    )
    assert gate.evaluate(proposal, now=NOW).may_enter_primary_assurance
    state_path.chmod(0o644)

    result = gate.evaluate(proposal, now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert result.reasons == ("degraded_operation_state_unavailable",)


def test_degraded_lease_requires_explicit_reversal_after_health_recovers(
    proposal: Any,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    degraded = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(
        private_key,
        degraded,
        role=DegradedRole.MANAGEMENT,
    )
    current: dict[str, Any] = {
        "snapshot": degraded,
        "authorization": authorization,
    }
    gate = DegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=private_key.public_key(),
        snapshot_source=lambda: current["snapshot"],
        authorization_source=lambda: current["authorization"],
    )

    assert gate.evaluate(proposal, now=NOW).may_enter_primary_assurance
    current["snapshot"] = _snapshot()
    recovered = gate.evaluate(proposal, now=NOW)
    reversal = _reversal(private_key, authorization)
    reversal_result = gate.apply_reversal(reversal, authorization, now=NOW)
    reversed_result = gate.evaluate(proposal, now=NOW)

    assert recovered.outcome is DegradedAdmissionOutcome.HOLD_STATE
    assert recovered.reasons == ("degraded_condition_cleared_reversal_required",)
    assert reversal_result.applied
    assert reversal_result.reasons == ("degraded_authorization_revoked",)
    assert reversed_result.outcome is DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE
    assert reversed_result.reasons == (
        "normal_runtime_dependencies_healthy_after_signed_reversal",
    )


def test_removing_accepted_lease_cannot_bypass_signed_reversal(
    proposal: Any,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    degraded = _snapshot(role=DegradedRole.MANAGEMENT)
    current: dict[str, Any] = {
        "snapshot": degraded,
        "authorization": _authorization(
            private_key,
            degraded,
            role=DegradedRole.MANAGEMENT,
        ),
    }
    gate = DegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=private_key.public_key(),
        snapshot_source=lambda: current["snapshot"],
        authorization_source=lambda: current["authorization"],
    )

    assert gate.evaluate(proposal, now=NOW).may_enter_primary_assurance
    current["snapshot"] = _snapshot()
    current["authorization"] = None

    held = gate.evaluate(proposal, now=NOW)

    assert held.outcome is DegradedAdmissionOutcome.HOLD_STATE
    assert held.reasons == ("degraded_condition_cleared_reversal_required",)
    assert not held.may_enter_primary_assurance
    assert not held.execution_authorized


def test_forged_or_replayed_reversal_cannot_revoke_a_lease(proposal: Any) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(
        private_key,
        snapshot,
        role=DegradedRole.MANAGEMENT,
    )
    gate = _gate(private_key, snapshot, authorization)
    forged = _reversal(Ed25519PrivateKey.generate(), authorization)
    valid = _reversal(private_key, authorization)

    forged_result = gate.apply_reversal(forged, authorization, now=NOW)
    accepted = gate.apply_reversal(valid, authorization, now=NOW)
    replayed = gate.apply_reversal(valid, authorization, now=NOW)

    assert not forged_result.applied
    assert "degraded_reversal_signature_invalid" in forged_result.reasons
    assert accepted.applied
    assert not replayed.applied
    assert "degraded_reversal_sequence_not_monotonic" in replayed.reasons
    assert "degraded_reversal_replayed" in replayed.reasons
    assert not gate.evaluate(proposal, now=NOW).may_enter_primary_assurance


class _NeverCalledIdentity:
    version = "must-not-run"

    def verify(self, actor_id: str) -> bool:
        raise AssertionError(f"identity invoked for {actor_id}")


class _NeverCalledDelegation:
    def validate(self, proposal: Any, now: datetime) -> Any:
        raise AssertionError("delegation invoked")


class _NeverCalledPolicy:
    version = "must-not-run"

    def evaluate(self, proposal: Any, state: Any) -> Any:
        raise AssertionError("policy invoked")


class _NeverCalledSafety:
    version = "must-not-run"

    def evaluate(self, proposal: Any, state: Any) -> Any:
        raise AssertionError("safety invoked")


class _NeverCalledReplay:
    def reserve(self, nonce: str, now: datetime) -> bool:
        raise AssertionError("replay invoked")


def test_gateway_denies_degraded_hold_before_primary_authorization(
    lab: Any,
    proposal: Any,
    state: Any,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.OBSERVER)
    lab.gateway.degraded_operation = _gate(
        private_key,
        snapshot,
        _authorization(private_key, snapshot, role=DegradedRole.OBSERVER),
    )
    lab.gateway.identity = _NeverCalledIdentity()
    lab.gateway.delegation = _NeverCalledDelegation()
    lab.gateway.policy = _NeverCalledPolicy()
    lab.gateway.safety = _NeverCalledSafety()
    lab.gateway.replay = _NeverCalledReplay()

    decision = lab.gateway.decide(proposal, state, NOW)

    assert decision.outcome is DecisionOutcome.DENY
    assert "authorized_hold_state" in decision.reasons
    assert decision.evidence_record_hash
    event = lab.gateway.evidence.records[-1].payload
    assert event["event_type"] == "m5_degraded_pre_authorization_denial"
    assert event["predicted_state"] is None
    assert event["degraded_admission"]["execution_authorized"] is False
    assert event["untrusted_proposal_sha256"] == canonical_digest(proposal)
    assert event["trusted_state_sha256"] == canonical_digest(state)
    assert decision.proposal_id == f"untrusted:{canonical_digest(proposal)}"
    assert lab.gateway.evidence.records[-1].proposal_id == decision.proposal_id
    assert "proposal" not in event
    assert "state" not in event


def test_full_capability_gateway_gates_before_workload_and_controller_admission(
    proposal: Any,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.OBSERVER)
    gate = _gate(
        private_key,
        snapshot,
        _authorization(private_key, snapshot, role=DegradedRole.OBSERVER),
    )
    action = CapabilityActionRequest(
        request_id="m5-full-capability-action-0001",
        correlation_id="m5-full-capability-correlation",
        proposal=proposal,
        observation_id="m5-full-capability-observation",
        observation_envelope_digest="a" * 64,
        observation_challenge_nonce="m5-observation-challenge-0001",
    )

    class NeverController:
        calls = 0

        def execute(self, request: Any) -> Any:
            self.calls += 1
            raise AssertionError(f"controller invoked for {request}")

    controller = NeverController()
    evidence = EvidenceChain()
    runtime = CapabilityGatewayRuntime(
        authorization=SimpleNamespace(
            gateway=SimpleNamespace(evidence=evidence),
        ),
        controller=controller,  # type: ignore[arg-type]
        observer=SimpleNamespace(),  # type: ignore[arg-type]
        discovery=SimpleNamespace(),  # type: ignore[arg-type]
        gateway_key_id="m5-gateway-key",
        # A plain request would be rejected for lacking a workload credential,
        # but the M5 hold must run even earlier than that identity decision.
        agent_workload_verifier=object(),  # type: ignore[arg-type]
        agent_workload_subject="spiffe://aegis-ot.test/workload/agent",
        degraded_operation=gate,
        clock=lambda: NOW,
    )

    with pytest.raises(CapabilityAdmissionRejected, match="m5_degraded_hold_state"):
        runtime.execute(action)

    assert controller.calls == 0
    event = evidence.records[-1].payload
    assert event["event_type"] == "m5_degraded_runtime_admission"
    assert event["untrusted_action_sha256"] == action.digest
    assert event["execution_authorized"] is False
    assert "request_id" not in event
    assert "sender_credential" not in event


def test_management_degraded_lease_still_requires_full_gateway_authorization(
    proposal: Any,
    state: Any,
) -> None:
    from aegis_ot.factory import build_local_lab

    lab = build_local_lab(NOW)
    proposal = proposal.model_copy(
        update={"observed_at": NOW, "submitted_at": NOW}
    )
    state = state.model_copy(update={"observed_at": NOW})
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    lab.gateway.degraded_operation = _gate(
        private_key,
        snapshot,
        _authorization(private_key, snapshot, role=DegradedRole.MANAGEMENT),
    )

    permitted = lab.gateway.decide(proposal, state, NOW)
    unauthorized = proposal.model_copy(
        update={"confidence": 0.4, "nonce": "low-confidence-0001"}
    )
    denied = lab.gateway.decide(unauthorized, state, NOW)

    assert permitted.outcome is DecisionOutcome.PERMIT
    assert denied.outcome is DecisionOutcome.DENY
    assert "confidence_below_policy_minimum" in denied.reasons
    evidence = lab.gateway.evidence.records[0].payload["degraded_admission"]
    assert evidence["may_enter_primary_assurance"] is True
    assert evidence["execution_authorized"] is False
