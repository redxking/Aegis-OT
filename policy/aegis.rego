package aegis.authz

default permit := false

permit if {
  input.identity.verified
  input.delegation.valid
  input.state.fresh
  input.replay.unique
  input.safety.safe
  input.proposal.confidence >= data.limits.minimum_action_confidence
  input.proposal.risk_score < data.limits.human_approval_risk_threshold
}

require_approval if {
  input.identity.verified
  input.delegation.valid
  input.state.fresh
  input.replay.unique
  input.safety.safe
  input.proposal.risk_score >= data.limits.human_approval_risk_threshold
}
