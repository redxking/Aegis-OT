"""Contextual policy interface and deterministic local reference policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .models import ActionProposal, SystemState


@dataclass(frozen=True)
class PolicyResult:
    permitted: bool
    reasons: tuple[str, ...]
    requires_approval: bool = False


class PolicyEngine(Protocol):
    @property
    def version(self) -> str: ...

    def evaluate(self, proposal: ActionProposal, state: SystemState) -> PolicyResult: ...


@dataclass(frozen=True)
class ContextualPolicy:
    minimum_confidence: float = 0.70
    human_approval_risk_threshold: float = 75.0
    version: str = "local-contextual-v1"

    def evaluate(self, proposal: ActionProposal, state: SystemState) -> PolicyResult:
        reasons: list[str] = []
        if proposal.confidence < self.minimum_confidence:
            reasons.append("confidence_below_policy_minimum")
        if proposal.observed_state_version != state.version:
            reasons.append("state_version_mismatch")
        requires_approval = proposal.risk_score >= self.human_approval_risk_threshold
        if requires_approval and proposal.human_approval_id is None:
            reasons.append("human_approval_required")
        return PolicyResult(
            permitted=not reasons,
            reasons=tuple(reasons),
            requires_approval=requires_approval,
        )
