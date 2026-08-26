"""Sole authorization path for consequential simulated actions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from .delegation import DelegationValidator
from .evidence import EvidenceChain
from .identity import IdentityVerifier
from .m5_degraded import DegradedOperationGate
from .models import ActionProposal, Decision, DecisionOutcome, SystemState
from .physical_models import canonical_digest
from .policy import PolicyEngine
from .replay import ReplayLedger
from .safety import SafetyKernel

if TYPE_CHECKING:
    from .m5_degraded_publication import PublishedDegradedOperationGate


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
        degraded_operation: (
            DegradedOperationGate | PublishedDegradedOperationGate | None
        ) = None,
    ) -> None:
        self.identity = identity
        self.delegation = delegation
        self.policy = policy
        self.safety = safety
        self.replay = replay
        self.evidence = evidence
        self.maximum_state_age = maximum_state_age
        self.degraded_operation = degraded_operation

    def decide(
        self,
        proposal: ActionProposal,
        state: SystemState,
        now: datetime | None = None,
    ) -> Decision:
        evaluated_at = now or datetime.now(UTC)
        reasons: list[str] = []
        outcome = DecisionOutcome.DENY
        degraded_admission: dict[str, object] | None = None

        # This gate is deliberately first. A denied degraded-mode admission
        # must not invoke identity, delegation, policy, safety, or replay and
        # cannot consume a nonce that may later be evaluated in normal mode.
        if self.degraded_operation is not None:
            untrusted_proposal_sha256 = canonical_digest(proposal)
            untrusted_proposal_id = f"untrusted:{untrusted_proposal_sha256}"
            try:
                admission = self.degraded_operation.evaluate(
                    proposal,
                    now=evaluated_at,
                )
            except Exception:
                reasons.append("degraded_admission_unavailable")
            else:
                degraded_admission = admission.model_dump(mode="json")
                if not admission.may_enter_primary_assurance:
                    reasons.extend(admission.reasons)
            if reasons:
                provisional = Decision(
                    proposal_id=untrusted_proposal_id,
                    outcome=DecisionOutcome.DENY,
                    reasons=tuple(reasons),
                    policy_version="not-evaluated:m5-degraded-pre-authorization",
                    safety_version="not-evaluated:m5-degraded-pre-authorization",
                    state_version=state.version,
                )
                evidence_record = self.evidence.append(
                    proposal_id=untrusted_proposal_id,
                    decision_id=provisional.decision_id,
                    payload={
                        "event_type": "m5_degraded_pre_authorization_denial",
                        "untrusted_proposal_sha256": untrusted_proposal_sha256,
                        "decision": provisional.model_dump(mode="json"),
                        "trusted_state_sha256": canonical_digest(state),
                        "predicted_state": None,
                        "degraded_admission": degraded_admission,
                    },
                )
                return provisional.model_copy(
                    update={"evidence_record_hash": evidence_record.record_hash}
                )

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
        evidence_payload: dict[str, object] = {
            "proposal": proposal.model_dump(mode="json"),
            "decision": provisional.model_dump(mode="json"),
            "state": state.model_dump(mode="json"),
            "predicted_state": safety.predicted_state.model_dump(mode="json"),
            "identity_version": self.identity.version,
        }
        if degraded_admission is not None:
            evidence_payload["degraded_admission"] = degraded_admission
        evidence_record = self.evidence.append(
            proposal_id=proposal.proposal_id,
            decision_id=provisional.decision_id,
            payload=evidence_payload,
        )
        return provisional.model_copy(update={"evidence_record_hash": evidence_record.record_hash})
