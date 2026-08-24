--------------------------- MODULE AegisAuthorization ---------------------------
EXTENDS Naturals, FiniteSets, TLC

(***************************************************************************)
(* Bounded authorization and execution model for the Aegis-OT gateway.    *)
(* Enforcement switches are TRUE in the intended configuration. A weak    *)
(* configuration sets one switch FALSE for a targeted counterexample.      *)
(***************************************************************************)

CONSTANTS
  Agents, Actions, Grants, Nonces, Scenarios,
  Agent1, Agent2, Action1, Action2, RootGrant, LeafGrant, Nonce1, Nonce2,
  SUnauthenticated, SDelegation, SScope, SUnsafe, SReplay, SRevoked,
  SExpired, SPolicy, SStale, SApproval, SConflict, STOCTOU, SAck,
  SEvidence, SCompromise,
  MaxTime, RevocationBound,
  EnforceAuthentication, EnforceDelegation, EnforceScope, EnforceSafety,
  EnforceReplay, EnforceRevocation, EnforceExpiry, EnforcePolicy,
  EnforceFreshness, EnforceApproval, EnforceConflict, EnforceTOCTOU,
  EnforceAcknowledgment, EnforceQuarantine, WriteDecisionEvidence,
  WriteExecutionEvidence

Never == MaxTime + RevocationBound + 2

ActorOf(a) == IF a = Action1 THEN Agent1 ELSE Agent2
GrantOf(a) == LeafGrant
Ancestors(g) == IF g = LeafGrant THEN {LeafGrant, RootGrant} ELSE {RootGrant}

NonceOf(a, scenario) ==
  IF scenario = SReplay THEN Nonce1
  ELSE IF a = Action1 THEN Nonce1 ELSE Nonce2

Authenticated(a, scenario) ==
  ~((scenario = SUnauthenticated) /\ (a = Action1))

DelegationValid(a, scenario) ==
  ~((scenario = SDelegation) /\ (a = Action1))

WithinScope(a, scenario) ==
  ~((scenario = SScope) /\ (a = Action1))

ModeledSafe(a, scenario) ==
  ~((scenario = SUnsafe) /\ (a = Action1))

PolicyMatches(a, scenario) ==
  ~((scenario = SPolicy) /\ (a = Action1))

ProposalFresh(a, scenario) ==
  ~((scenario = SStale) /\ (a = Action1))

NeedsApproval(a, scenario) == (scenario = SApproval) /\ (a = Action1)

GrantExpiry(a, scenario) ==
  IF (scenario = SExpired) /\ (a = Action1) THEN 1 ELSE MaxTime

Conflicts(a, b, scenario) ==
  (scenario = SConflict) /\ (a /= b)

VARIABLES
  scenario, time, submitted, authorized, denied, dispatched, acknowledged,
  executed, approvals, usedNonces, decisionEvidence, executionEvidence,
  revokedAt, currentFresh, compromised, quarantined,
  executedWhenRevoked, executedWhenExpired, executedWhenStale,
  executedWithoutAck, executedWhileQuarantined

vars ==
  <<scenario, time, submitted, authorized, denied, dispatched, acknowledged,
    executed, approvals, usedNonces, decisionEvidence, executionEvidence,
    revokedAt, currentFresh, compromised, quarantined,
    executedWhenRevoked, executedWhenExpired, executedWhenStale,
    executedWithoutAck, executedWhileQuarantined>>

Init ==
  /\ scenario \in Scenarios
  /\ time = 0
  /\ submitted = {}
  /\ authorized = {}
  /\ denied = {}
  /\ dispatched = {}
  /\ acknowledged = {}
  /\ executed = {}
  /\ approvals = {}
  /\ usedNonces = {}
  /\ decisionEvidence = {}
  /\ executionEvidence = {}
  /\ revokedAt = [g \in Grants |-> Never]
  /\ currentFresh = [a \in Actions |-> TRUE]
  /\ compromised = {}
  /\ quarantined = {}
  /\ executedWhenRevoked = {}
  /\ executedWhenExpired = {}
  /\ executedWhenStale = {}
  /\ executedWithoutAck = {}
  /\ executedWhileQuarantined = {}

EffectiveRevoked(a) ==
  \E g \in Ancestors(GrantOf(a)):
    (revokedAt[g] /= Never) /\ (time > revokedAt[g] + RevocationBound)

HasConflict(a) ==
  \E other \in executed: Conflicts(a, other, scenario)

Submit(a) ==
  /\ a \notin submitted
  /\ submitted' = submitted \cup {a}
  /\ UNCHANGED <<scenario, time, authorized, denied, dispatched, acknowledged,
                  executed, approvals, usedNonces, decisionEvidence,
                  executionEvidence, revokedAt, currentFresh, compromised,
                  quarantined, executedWhenRevoked, executedWhenExpired,
                  executedWhenStale, executedWithoutAck,
                  executedWhileQuarantined>>

Approve(a) ==
  /\ a \in submitted
  /\ NeedsApproval(a, scenario)
  /\ a \notin approvals
  /\ approvals' = approvals \cup {a}
  /\ UNCHANGED <<scenario, time, submitted, authorized, denied, dispatched,
                  acknowledged, executed, usedNonces, decisionEvidence,
                  executionEvidence, revokedAt, currentFresh, compromised,
                  quarantined, executedWhenRevoked, executedWhenExpired,
                  executedWhenStale, executedWithoutAck,
                  executedWhileQuarantined>>

Authorize(a) ==
  /\ a \in submitted
  /\ a \notin authorized \cup denied
  /\ (EnforceAuthentication => Authenticated(a, scenario))
  /\ (EnforceDelegation => DelegationValid(a, scenario))
  /\ (EnforceScope => WithinScope(a, scenario))
  /\ (EnforceSafety => ModeledSafe(a, scenario))
  /\ (EnforceReplay => NonceOf(a, scenario) \notin usedNonces)
  /\ (EnforceRevocation => ~EffectiveRevoked(a))
  /\ (EnforceExpiry => time <= GrantExpiry(a, scenario))
  /\ (EnforcePolicy => PolicyMatches(a, scenario))
  /\ (EnforceFreshness => ProposalFresh(a, scenario))
  /\ (EnforceApproval => (~NeedsApproval(a, scenario) \/ a \in approvals))
  /\ authorized' = authorized \cup {a}
  /\ usedNonces' = usedNonces \cup {NonceOf(a, scenario)}
  /\ decisionEvidence' =
       IF WriteDecisionEvidence THEN decisionEvidence \cup {a}
       ELSE decisionEvidence
  /\ UNCHANGED <<scenario, time, submitted, denied, dispatched, acknowledged,
                  executed, approvals, executionEvidence, revokedAt,
                  currentFresh, compromised, quarantined,
                  executedWhenRevoked, executedWhenExpired,
                  executedWhenStale, executedWithoutAck,
                  executedWhileQuarantined>>

Deny(a) ==
  /\ a \in submitted
  /\ a \notin authorized \cup denied
  /\ denied' = denied \cup {a}
  /\ decisionEvidence' =
       IF WriteDecisionEvidence THEN decisionEvidence \cup {a}
       ELSE decisionEvidence
  /\ UNCHANGED <<scenario, time, submitted, authorized, dispatched,
                  acknowledged, executed, approvals, usedNonces,
                  executionEvidence, revokedAt, currentFresh, compromised,
                  quarantined, executedWhenRevoked, executedWhenExpired,
                  executedWhenStale, executedWithoutAck,
                  executedWhileQuarantined>>

Resolve(a) == Authorize(a) \/ Deny(a)

Dispatch(a) ==
  /\ a \in authorized
  /\ a \notin dispatched
  /\ dispatched' = dispatched \cup {a}
  /\ UNCHANGED <<scenario, time, submitted, authorized, denied, acknowledged,
                  executed, approvals, usedNonces, decisionEvidence,
                  executionEvidence, revokedAt, currentFresh, compromised,
                  quarantined, executedWhenRevoked, executedWhenExpired,
                  executedWhenStale, executedWithoutAck,
                  executedWhileQuarantined>>

Acknowledge(a) ==
  /\ a \in dispatched
  /\ a \notin acknowledged
  /\ acknowledged' = acknowledged \cup {a}
  /\ UNCHANGED <<scenario, time, submitted, authorized, denied, dispatched,
                  executed, approvals, usedNonces, decisionEvidence,
                  executionEvidence, revokedAt, currentFresh, compromised,
                  quarantined, executedWhenRevoked, executedWhenExpired,
                  executedWhenStale, executedWithoutAck,
                  executedWhileQuarantined>>

Execute(a) ==
  /\ a \in dispatched
  /\ a \notin executed
  /\ (EnforceAcknowledgment => a \in acknowledged)
  /\ (EnforceRevocation => ~EffectiveRevoked(a))
  /\ (EnforceExpiry => time <= GrantExpiry(a, scenario))
  /\ (EnforceTOCTOU => currentFresh[a])
  /\ (EnforceConflict => ~HasConflict(a))
  /\ (EnforceQuarantine => ActorOf(a) \notin quarantined)
  /\ executed' = executed \cup {a}
  /\ executionEvidence' =
       IF WriteExecutionEvidence THEN executionEvidence \cup {a}
       ELSE executionEvidence
  /\ executedWhenRevoked' =
       IF EffectiveRevoked(a) THEN executedWhenRevoked \cup {a}
       ELSE executedWhenRevoked
  /\ executedWhenExpired' =
       IF time > GrantExpiry(a, scenario) THEN executedWhenExpired \cup {a}
       ELSE executedWhenExpired
  /\ executedWhenStale' =
       IF ~currentFresh[a] THEN executedWhenStale \cup {a}
       ELSE executedWhenStale
  /\ executedWithoutAck' =
       IF a \notin acknowledged THEN executedWithoutAck \cup {a}
       ELSE executedWithoutAck
  /\ executedWhileQuarantined' =
       IF ActorOf(a) \in quarantined THEN executedWhileQuarantined \cup {a}
       ELSE executedWhileQuarantined
  /\ UNCHANGED <<scenario, time, submitted, authorized, denied, dispatched,
                  acknowledged, approvals, usedNonces, decisionEvidence,
                  revokedAt, currentFresh, compromised, quarantined>>

Revoke(g) ==
  /\ revokedAt[g] = Never
  /\ revokedAt' = [revokedAt EXCEPT ![g] = time]
  /\ UNCHANGED <<scenario, time, submitted, authorized, denied, dispatched,
                  acknowledged, executed, approvals, usedNonces,
                  decisionEvidence, executionEvidence, currentFresh,
                  compromised, quarantined, executedWhenRevoked,
                  executedWhenExpired, executedWhenStale,
                  executedWithoutAck, executedWhileQuarantined>>

InvalidateState(a) ==
  /\ scenario = STOCTOU
  /\ a \in authorized
  /\ currentFresh[a]
  /\ currentFresh' = [currentFresh EXCEPT ![a] = FALSE]
  /\ UNCHANGED <<scenario, time, submitted, authorized, denied, dispatched,
                  acknowledged, executed, approvals, usedNonces,
                  decisionEvidence, executionEvidence, revokedAt, compromised,
                  quarantined, executedWhenRevoked, executedWhenExpired,
                  executedWhenStale, executedWithoutAck,
                  executedWhileQuarantined>>

Compromise(actor) ==
  /\ scenario = SCompromise
  /\ actor \notin compromised
  /\ compromised' = compromised \cup {actor}
  /\ UNCHANGED <<scenario, time, submitted, authorized, denied, dispatched,
                  acknowledged, executed, approvals, usedNonces,
                  decisionEvidence, executionEvidence, revokedAt, currentFresh,
                  quarantined, executedWhenRevoked, executedWhenExpired,
                  executedWhenStale, executedWithoutAck,
                  executedWhileQuarantined>>

Quarantine(actor) ==
  /\ actor \in compromised
  /\ actor \notin quarantined
  /\ quarantined' = quarantined \cup {actor}
  /\ UNCHANGED <<scenario, time, submitted, authorized, denied, dispatched,
                  acknowledged, executed, approvals, usedNonces,
                  decisionEvidence, executionEvidence, revokedAt, currentFresh,
                  compromised, executedWhenRevoked, executedWhenExpired,
                  executedWhenStale, executedWithoutAck,
                  executedWhileQuarantined>>

Tick ==
  /\ time < MaxTime
  /\ time' = time + 1
  /\ UNCHANGED <<scenario, submitted, authorized, denied, dispatched,
                  acknowledged, executed, approvals, usedNonces,
                  decisionEvidence, executionEvidence, revokedAt, currentFresh,
                  compromised, quarantined, executedWhenRevoked,
                  executedWhenExpired, executedWhenStale,
                  executedWithoutAck, executedWhileQuarantined>>

Next ==
  \/ \E a \in Actions: Submit(a)
  \/ \E a \in Actions: Approve(a)
  \/ \E a \in Actions: Resolve(a)
  \/ \E a \in Actions: Dispatch(a)
  \/ \E a \in Actions: Acknowledge(a)
  \/ \E a \in Actions: Execute(a)
  \/ \E a \in Actions: InvalidateState(a)
  \/ \E g \in Grants: Revoke(g)
  \/ \E actor \in Agents: Compromise(actor)
  \/ \E actor \in Agents: Quarantine(actor)
  \/ Tick

TypeOK ==
  /\ scenario \in Scenarios
  /\ time \in 0..MaxTime
  /\ submitted \subseteq Actions
  /\ authorized \subseteq submitted
  /\ denied \subseteq submitted
  /\ dispatched \subseteq authorized
  /\ acknowledged \subseteq dispatched
  /\ executed \subseteq dispatched
  /\ approvals \subseteq Actions
  /\ usedNonces \subseteq Nonces
  /\ decisionEvidence \subseteq Actions
  /\ executionEvidence \subseteq Actions
  /\ revokedAt \in [Grants -> (0..MaxTime \cup {Never})]
  /\ currentFresh \in [Actions -> BOOLEAN]
  /\ compromised \subseteq Agents
  /\ quarantined \subseteq Agents

NoUnauthenticatedExecution ==
  \A a \in executed: Authenticated(a, scenario)

NoDelegationAmplification ==
  \A a \in authorized: DelegationValid(a, scenario)

NoOutOfScopeExecution ==
  \A a \in executed: WithinScope(a, scenario)

NoUnsafeModeledExecution ==
  \A a \in executed: ModeledSafe(a, scenario)

NoReplay ==
  Cardinality({NonceOf(a, scenario) : a \in executed}) = Cardinality(executed)

NoExecutionAfterEffectiveRevocation == executedWhenRevoked = {}
NoExecutionAfterExpiry == executedWhenExpired = {}
PolicyVersionConsistency == \A a \in authorized: PolicyMatches(a, scenario)
FreshProposalRequired == \A a \in authorized: ProposalFresh(a, scenario)
HumanApprovalRequired ==
  \A a \in executed: NeedsApproval(a, scenario) => a \in approvals
NoConflictingExecution ==
  \A a, b \in executed: (a /= b) => ~Conflicts(a, b, scenario)
NoTOCTOUExecution == executedWhenStale = {}
AcknowledgmentRequired == executedWithoutAck = {}
EvidenceCompleteness ==
  /\ authorized \cup denied \subseteq decisionEvidence
  /\ executed \subseteq executionEvidence
NoQuarantinedExecution == executedWhileQuarantined = {}
BoundedAuthorityUnderCompromise ==
  \A a \in executed:
    (ActorOf(a) \in compromised) => WithinScope(a, scenario)

DecisionLiveness ==
  \A a \in Actions: (a \in submitted) ~> (a \in authorized \cup denied)

Spec ==
  /\ Init
  /\ [][Next]_vars
  /\ \A a \in Actions: WF_vars(Resolve(a))

=============================================================================
