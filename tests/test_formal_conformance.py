"""Executable mappings for the implemented subset of TLA+ properties."""

from __future__ import annotations

from datetime import timedelta

from aegis_ot.lab import SimulatedCommandAdapter
from aegis_ot.models import DecisionOutcome
from aegis_ot.policy import ContextualPolicy


def test_no_unauthenticated_execution_conformance(lab, proposal, state, now) -> None:
    unknown = proposal.model_copy(update={"actor_id": "agent:unknown"})
    decision = lab.gateway.decide(unknown, state, now)
    result = SimulatedCommandAdapter().execute(unknown, decision, state)
    assert decision.outcome is DecisionOutcome.DENY
    assert not result.executed


def test_no_delegation_amplification_conformance(lab, proposal, state, now) -> None:
    amplified = proposal.model_copy(update={"risk_score": lab.leaf_grant.risk_limit + 1})
    decision = lab.gateway.decide(amplified, state, now)
    assert decision.outcome is DecisionOutcome.DENY
    assert "risk_out_of_scope" in decision.reasons


def test_no_out_of_scope_execution_conformance(lab, proposal, state, now) -> None:
    outside = proposal.model_copy(update={"resource": "feeder-2"})
    decision = lab.gateway.decide(outside, state, now)
    result = SimulatedCommandAdapter().execute(outside, decision, state)
    assert "resource_out_of_scope" in decision.reasons
    assert not result.executed


def test_no_unsafe_modeled_execution_conformance(lab, proposal, state, now) -> None:
    unsafe = proposal.model_copy(update={"parameters": {"critical_load_impact_pct": 30.0}})
    decision = lab.gateway.decide(unsafe, state, now)
    result = SimulatedCommandAdapter().execute(unsafe, decision, state)
    assert "critical_load_below_limit" in decision.reasons
    assert not result.executed


def test_no_replay_conformance(lab, proposal, state, now) -> None:
    first = lab.gateway.decide(proposal, state, now)
    second = lab.gateway.decide(proposal, state, now)
    assert first.outcome is DecisionOutcome.PERMIT
    assert second.outcome is DecisionOutcome.DENY
    assert "replayed_nonce" in second.reasons


def test_ancestor_revocation_conformance(lab, proposal, state, now) -> None:
    lab.gateway.delegation.revoke(lab.root_grant.grant_id)
    decision = lab.gateway.decide(proposal, state, now)
    assert decision.outcome is DecisionOutcome.DENY
    assert "revoked_grant:grant-root" in decision.reasons


def test_grant_expiry_conformance(lab, proposal, state, now) -> None:
    evaluated_at = now + timedelta(hours=2)
    current_state = state.model_copy(update={"observed_at": evaluated_at})
    current_proposal = proposal.model_copy(update={"observed_at": evaluated_at})
    decision = lab.gateway.decide(current_proposal, current_state, evaluated_at)
    assert decision.outcome is DecisionOutcome.DENY
    assert any(reason.startswith("inactive_grant:") for reason in decision.reasons)


def test_state_freshness_conformance(lab, proposal, state, now) -> None:
    decision = lab.gateway.decide(proposal, state, now + timedelta(seconds=6))
    assert decision.outcome is DecisionOutcome.DENY
    assert "state_not_fresh" in decision.reasons


def test_human_approval_conformance(lab, proposal, state, now) -> None:
    lab.gateway.policy = ContextualPolicy(human_approval_risk_threshold=50.0)
    pending = lab.gateway.decide(proposal, state, now)
    approved = proposal.model_copy(
        update={"human_approval_id": "approval-1", "nonce": "approval-0123456789"}
    )
    permitted = lab.gateway.decide(approved, state, now)
    assert pending.outcome is DecisionOutcome.REQUIRE_APPROVAL
    assert permitted.outcome is DecisionOutcome.PERMIT


def test_toctou_conformance(lab, proposal, state, now) -> None:
    decision = lab.gateway.decide(proposal, state, now)
    changed_state = state.model_copy(update={"version": state.version + 1})
    result = SimulatedCommandAdapter().execute(proposal, decision, changed_state)
    assert not result.executed
    assert result.reason == "time_of_check_time_of_use_state_change"


def test_decision_evidence_conformance(lab, proposal, state, now) -> None:
    permit = lab.gateway.decide(proposal, state, now)
    denied_proposal = proposal.model_copy(
        update={"actor_id": "agent:unknown", "nonce": "denied-0123456789"}
    )
    deny = lab.gateway.decide(denied_proposal, state, now)
    records = lab.gateway.evidence.records
    assert permit.evidence_record_hash == records[0].record_hash
    assert deny.evidence_record_hash == records[1].record_hash
    assert lab.gateway.evidence.verify()
