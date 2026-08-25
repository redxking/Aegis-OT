from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from aegis_ot.lab import SimulatedCommandAdapter
from aegis_ot.models import DecisionOutcome
from aegis_ot.policy import ContextualPolicy


def test_safe_authorized_action_is_permitted(lab, proposal, state, now) -> None:
    decision = lab.gateway.decide(proposal, state, now)
    assert decision.outcome is DecisionOutcome.PERMIT
    assert decision.evidence_record_hash


def test_unsafe_transition_is_denied(lab, proposal, state, now) -> None:
    unsafe = proposal.model_copy(update={"parameters": {"critical_load_impact_pct": 30.0}})
    decision = lab.gateway.decide(unsafe, state, now)
    assert decision.outcome is DecisionOutcome.DENY
    assert "critical_load_below_limit" in decision.reasons


def test_unknown_identity_is_denied(lab, proposal, state, now) -> None:
    unknown = proposal.model_copy(update={"actor_id": "agent:unknown"})
    decision = lab.gateway.decide(unknown, state, now)
    assert "identity_not_verified" in decision.reasons


def test_unknown_identity_cannot_poison_authenticated_nonce(lab, proposal, state, now) -> None:
    unknown = proposal.model_copy(update={"actor_id": "agent:unknown"})
    rejected = lab.gateway.decide(unknown, state, now)
    permitted = lab.gateway.decide(proposal, state, now)

    assert "identity_not_verified" in rejected.reasons
    assert "replayed_nonce" not in rejected.reasons
    assert permitted.outcome is DecisionOutcome.PERMIT


def test_stale_state_is_denied(lab, proposal, state, now) -> None:
    decision = lab.gateway.decide(proposal, state, now + timedelta(seconds=6))
    assert "state_not_fresh" in decision.reasons


def test_future_state_and_proposal_observation_mismatch_are_denied(
    lab, proposal, state, now
) -> None:
    future_state = state.model_copy(update={"observed_at": now + timedelta(seconds=1)})
    decision = lab.gateway.decide(proposal, future_state, now)
    assert "state_not_fresh" in decision.reasons
    assert "proposal_observation_mismatch" in decision.reasons


def test_state_version_mismatch_is_denied(lab, proposal, state, now) -> None:
    mismatched = proposal.model_copy(update={"observed_state_version": state.version + 1})
    decision = lab.gateway.decide(mismatched, state, now)
    assert "state_version_mismatch" in decision.reasons


def test_replay_is_denied(lab, proposal, state, now) -> None:
    first = lab.gateway.decide(proposal, state, now)
    second = lab.gateway.decide(proposal, state, now)
    assert first.outcome is DecisionOutcome.PERMIT
    assert second.outcome is DecisionOutcome.DENY
    assert "replayed_nonce" in second.reasons


def test_concurrent_nonce_reservation_permits_once(lab, proposal, state, now) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(lambda _: lab.gateway.decide(proposal, state, now), range(8)))
    assert sum(item.outcome is DecisionOutcome.PERMIT for item in decisions) == 1
    assert sum("replayed_nonce" in item.reasons for item in decisions) == 7


def test_low_confidence_is_denied(lab, proposal, state, now) -> None:
    low_confidence = proposal.model_copy(update={"confidence": 0.4})
    decision = lab.gateway.decide(low_confidence, state, now)
    assert "confidence_below_policy_minimum" in decision.reasons


def test_high_risk_requires_approval(lab, proposal, state, now) -> None:
    # A separate grant would be needed to permit risk >=75; policy still records approval need.
    high_risk = proposal.model_copy(update={"risk_score": 80.0})
    decision = lab.gateway.decide(high_risk, state, now)
    assert "human_approval_required" in decision.reasons
    assert "risk_out_of_scope" in decision.reasons


def test_approval_outcome_and_approved_permit_are_distinct(lab, proposal, state, now) -> None:
    lab.gateway.policy = ContextualPolicy(human_approval_risk_threshold=50.0)
    pending = lab.gateway.decide(proposal, state, now)
    assert pending.outcome is DecisionOutcome.REQUIRE_APPROVAL
    assert pending.reasons == ("human_approval_required",)

    approved = proposal.model_copy(
        update={"human_approval_id": "approval-1", "nonce": "approved-01234567"}
    )
    permitted = lab.gateway.decide(approved, state, now)
    assert permitted.outcome is DecisionOutcome.PERMIT


def test_adapter_rejects_nonpermit(lab, proposal, state, now) -> None:
    unsafe = proposal.model_copy(update={"parameters": {"critical_load_impact_pct": 30.0}})
    decision = lab.gateway.decide(unsafe, state, now)
    execution = SimulatedCommandAdapter().execute(unsafe, decision, state)
    assert not execution.executed
    assert execution.reason == "decision_not_permit"


def test_adapter_blocks_time_of_check_time_of_use_change(lab, proposal, state, now) -> None:
    decision = lab.gateway.decide(proposal, state, now)
    changed_state = state.model_copy(update={"version": state.version + 1})
    execution = SimulatedCommandAdapter().execute(proposal, decision, changed_state)
    assert not execution.executed
    assert execution.reason == "time_of_check_time_of_use_state_change"


def test_adapter_rejects_proposal_decision_mismatch(lab, proposal, state, now) -> None:
    decision = lab.gateway.decide(proposal, state, now)
    different = proposal.model_copy(update={"proposal_id": "proposal-2"})
    execution = SimulatedCommandAdapter().execute(different, decision, state)
    assert not execution.executed
    assert execution.reason == "proposal_decision_mismatch"


def test_adapter_executes_matching_current_permit(lab, proposal, state, now) -> None:
    decision = lab.gateway.decide(proposal, state, now)
    execution = SimulatedCommandAdapter().execute(proposal, decision, state)
    assert execution.executed
    assert execution.resulting_state is not None
    assert execution.resulting_state.version == state.version + 1
