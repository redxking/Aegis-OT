"""Deterministic supervisory surrogate and authorization-bound command adapter."""

from __future__ import annotations

from datetime import UTC, datetime

from .models import ActionProposal, Decision, DecisionOutcome, ExecutionResult, SystemState
from .safety import SafetyKernel


def nominal_state(*, version: int = 1, observed_at: datetime | None = None) -> SystemState:
    return SystemState(
        version=version,
        observed_at=observed_at or datetime.now(UTC),
        critical_load_served_pct=100.0,
        minimum_voltage_pu=0.99,
        maximum_voltage_pu=1.01,
        maximum_line_loading_pct=72.0,
    )


class SimulatedCommandAdapter:
    """Rejects commands without a matching current gateway permit."""

    def __init__(self, transition_model: SafetyKernel | None = None) -> None:
        self._transition_model = transition_model or SafetyKernel()

    def execute(
        self,
        proposal: ActionProposal,
        decision: Decision,
        current_state: SystemState,
    ) -> ExecutionResult:
        acknowledged_at = datetime.now(UTC)
        if decision.proposal_id != proposal.proposal_id:
            return ExecutionResult(
                proposal_id=proposal.proposal_id,
                decision_id=decision.decision_id,
                executed=False,
                acknowledged_at=acknowledged_at,
                reason="proposal_decision_mismatch",
            )
        if decision.outcome is not DecisionOutcome.PERMIT:
            return ExecutionResult(
                proposal_id=proposal.proposal_id,
                decision_id=decision.decision_id,
                executed=False,
                acknowledged_at=acknowledged_at,
                reason="decision_not_permit",
            )
        if decision.state_version != current_state.version:
            return ExecutionResult(
                proposal_id=proposal.proposal_id,
                decision_id=decision.decision_id,
                executed=False,
                acknowledged_at=acknowledged_at,
                reason="time_of_check_time_of_use_state_change",
            )
        resulting = self._transition_model.evaluate(proposal, current_state).predicted_state
        return ExecutionResult(
            proposal_id=proposal.proposal_id,
            decision_id=decision.decision_id,
            executed=True,
            acknowledged_at=acknowledged_at,
            resulting_state=resulting,
        )
