"""Sole authorization path for consequential simulated actions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .delegation import DelegationValidator
from .evidence import EvidenceChain
from .identity import IdentityVerifier
from .models import ActionProposal, Decision, DecisionOutcome, SystemState
from .policy import PolicyEngine
from .replay import ReplayLedger
from .safety import SafetyKernel


class AegisGateway:
    def __init__(
        self,
        identity: IdentityVerifier,
        delegation: DelegationValidator,
        policy: PolicyEngine,
        safety: SafetyKernel,
        replay: ReplayLedger,
        evidence: EvidenceChain,
        maximum_state_age: timedelta = timedelta(seconds=5),
    ) -> None:
        self.identity = identity
        self.delegation = delegation
        self.policy = policy
        self.safety = safety
        self.replay = replay
        self.evidence = evidence
        self.maximum_state_age = maximum_state_age

    def decide(
        self,
        proposal: ActionProposal,
        state: SystemState,
        now: datetime | None = None,
    ) -> Decision:
        evaluated_at = now or datetime.now(UTC)
        reasons: list[str] = []
        outcome = DecisionOutcome.DENY

        identity_verified = self.identity.verify(proposal.actor_id)
        if not identity_verified:
            reasons.append("identity_not_verified")

        delegation = self.delegation.validate(proposal, evaluated_at)
        reasons.extend(delegation.reasons)

        state_age = evaluated_at - state.observed_at
        if state_age < timedelta(0) or state_age > self.maximum_state_age:
            reasons.append("state_not_fresh")
        if proposal.observed_at != state.observed_at:
            reasons.append("proposal_observation_mismatch")

        policy = self.policy.evaluate(proposal, state)
        reasons.extend(policy.reasons)

        safety = self.safety.evaluate(proposal, state)
        reasons.extend(safety.reasons)

        # An unauthenticated caller must not be able to poison the replay
        # namespace for a later authenticated proposal using the same nonce.
        # Authenticated proposals are reserved even when another assurance
        # check denies them so the authenticated actor cannot replay a changed
        # context under the same identity-bound nonce.
        if identity_verified and not self.replay.reserve(proposal.nonce, evaluated_at):
            reasons.append("replayed_nonce")

        if reasons == ["human_approval_required"]:
            outcome = DecisionOutcome.REQUIRE_APPROVAL
        elif not reasons:
            outcome = DecisionOutcome.PERMIT

        provisional = Decision(
            proposal_id=proposal.proposal_id,
            outcome=outcome,
            reasons=tuple(reasons) if reasons else ("all_checks_passed",),
            policy_version=self.policy.version,
            safety_version=self.safety.version,
            state_version=state.version,
        )
        evidence_record = self.evidence.append(
            proposal_id=proposal.proposal_id,
            decision_id=provisional.decision_id,
            payload={
                "proposal": proposal.model_dump(mode="json"),
                "decision": provisional.model_dump(mode="json"),
                "state": state.model_dump(mode="json"),
                "predicted_state": safety.predicted_state.model_dump(mode="json"),
                "identity_version": self.identity.version,
            },
        )
        return provisional.model_copy(update={"evidence_record_hash": evidence_record.record_hash})
