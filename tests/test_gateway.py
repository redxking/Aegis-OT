from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from aegis_ot.lab import SimulatedCommandAdapter
from aegis_ot.models import DecisionOutcome


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


def test_stale_state_is_denied(lab, proposal, state, now) -> None:
    decision = lab.gateway.decide(proposal, state, now + timedelta(seconds=6))
    assert "state_not_fresh" in decision.reasons


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
