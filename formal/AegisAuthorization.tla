--------------------------- MODULE AegisAuthorization ---------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS Agents, Actions, Grants, Nonces, MaxTime, RevocationBound

VARIABLES time, submitted, authorized, executed, denied, revoked, usedNonces,
          evidence, grantOf, actorOf, nonceOf, safe, authenticated, inScope

vars == <<time, submitted, authorized, executed, denied, revoked, usedNonces,
          evidence, grantOf, actorOf, nonceOf, safe, authenticated, inScope>>

Init ==
  /\ time = 0
  /\ submitted = {}
  /\ authorized = {}
  /\ executed = {}
  /\ denied = {}
  /\ revoked = {}
  /\ usedNonces = {}
  /\ evidence = {}
  /\ grantOf \in [Actions -> Grants]
  /\ actorOf \in [Actions -> Agents]
  /\ nonceOf \in [Actions -> Nonces]
  /\ safe \in [Actions -> BOOLEAN]
  /\ authenticated \in [Agents -> BOOLEAN]
  /\ inScope \in [Actions -> BOOLEAN]

Submit(a) ==
  /\ a \notin submitted
  /\ submitted' = submitted \cup {a}
  /\ UNCHANGED <<time, authorized, executed, denied, revoked, usedNonces,
                  evidence, grantOf, actorOf, nonceOf, safe, authenticated, inScope>>

Authorize(a) ==
  /\ a \in submitted
  /\ a \notin authorized \cup denied
  /\ authenticated[actorOf[a]]
  /\ inScope[a]
  /\ safe[a]
  /\ grantOf[a] \notin revoked
  /\ nonceOf[a] \notin usedNonces
  /\ authorized' = authorized \cup {a}
  /\ usedNonces' = usedNonces \cup {nonceOf[a]}
  /\ evidence' = evidence \cup {a}
  /\ UNCHANGED <<time, submitted, executed, denied, revoked, grantOf, actorOf,
                  nonceOf, safe, authenticated, inScope>>

Deny(a) ==
  /\ a \in submitted
  /\ a \notin authorized \cup denied
  /\ denied' = denied \cup {a}
  /\ evidence' = evidence \cup {a}
  /\ UNCHANGED <<time, submitted, authorized, executed, revoked, usedNonces,
                  grantOf, actorOf, nonceOf, safe, authenticated, inScope>>

Execute(a) ==
  /\ a \in authorized
  /\ a \notin executed
  /\ grantOf[a] \notin revoked
  /\ executed' = executed \cup {a}
  /\ UNCHANGED <<time, submitted, authorized, denied, revoked, usedNonces,
                  evidence, grantOf, actorOf, nonceOf, safe, authenticated, inScope>>

Revoke(g) ==
  /\ g \notin revoked
  /\ revoked' = revoked \cup {g}
  /\ UNCHANGED <<time, submitted, authorized, executed, denied, usedNonces,
                  evidence, grantOf, actorOf, nonceOf, safe, authenticated, inScope>>

Tick ==
  /\ time < MaxTime
  /\ time' = time + 1
  /\ UNCHANGED <<submitted, authorized, executed, denied, revoked, usedNonces,
                  evidence, grantOf, actorOf, nonceOf, safe, authenticated, inScope>>

Next ==
  \/ \E a \in Actions: Submit(a)
  \/ \E a \in Actions: Authorize(a)
  \/ \E a \in Actions: Deny(a)
  \/ \E a \in Actions: Execute(a)
  \/ \E g \in Grants: Revoke(g)
  \/ Tick

NoUnauthenticatedExecution == \A a \in executed: authenticated[actorOf[a]]
NoOutOfScopeExecution == \A a \in executed: inScope[a]
NoUnsafeExecution == \A a \in executed: safe[a]
NoReplay == Cardinality({nonceOf[a] : a \in executed}) = Cardinality(executed)
EvidenceCompleteness == \A a \in authorized \cup denied: a \in evidence
NoExecutionUsingRevokedGrant == \A a \in executed: grantOf[a] \notin revoked

Spec == Init /\ [][Next]_vars

=============================================================================
