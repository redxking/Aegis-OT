# Formal-to-runtime conformance map

The TLA+ model and Python implementation provide different evidence. TLC checks
every reachable state in the committed bounded configuration. The Python tests
exercise selected implementation paths. Neither result proves physical-process
safety or deployed-system correctness.

| Formal property | Modeled transition or state | Runtime evidence | Current boundary |
|---|---|---|---|
| `NoUnauthenticatedExecution` | `Authorize`, `Execute` | `test_no_unauthenticated_execution_conformance` | Identity is a local allowlist, not transport-bound workload identity. |
| `NoDelegationAmplification` | `Authorize` | `test_no_delegation_amplification_conformance` and delegation-chain tests | Runtime covers signed resource, operation, risk, time, and depth attenuation. |
| `NoOutOfScopeExecution` | `Authorize`, `Execute` | `test_no_out_of_scope_execution_conformance` | Local adapter only; no PLC boundary. |
| `NoUnsafeModeledExecution` | `Authorize`, `Execute` | `test_no_unsafe_modeled_execution_conformance` | Safety evaluator and transition adapter share a surrogate model. |
| `NoReplay` | `Authorize` | `test_no_replay_conformance` and concurrent nonce tests | In-memory single-process ledger only. |
| `NoExecutionAfterEffectiveRevocation` | `Revoke`, `Execute` | `test_ancestor_revocation_conformance` | Runtime revocation is immediate and local; propagation delay is not measured. |
| `NoExecutionAfterExpiry` | `Authorize`, `Execute` | `test_grant_expiry_conformance` | Adapter does not independently revalidate the grant after a permit. |
| `FreshProposalRequired` | `Authorize` | `test_state_freshness_conformance` | Uses a five-second local-clock bound. |
| `HumanApprovalRequired` | `Approve`, `Authorize` | `test_human_approval_conformance` | Approval identifier authenticity is not yet externally verified. |
| `NoTOCTOUExecution` | `InvalidateState`, `Execute` | `test_toctou_conformance` | Adapter compares state version, not a physical readback. |
| `EvidenceCompleteness` | `Authorize`, `Deny`, `Execute` | `test_decision_evidence_conformance` | Runtime evidence currently covers decisions, not command acknowledgments. |
| `AcknowledgmentRequired` | `Dispatch`, `Acknowledge`, `Execute` | Partial: successful adapter result includes an acknowledgment timestamp | No independently authenticated actuator acknowledgment. |
| `PolicyVersionConsistency` | `Authorize` | Gap | Proposal does not bind an expected policy version. |
| `NoConflictingExecution` | `Execute` | Gap | No resource-level concurrent-action arbiter exists. |
| `NoQuarantinedExecution` | `Quarantine`, `Execute` | Gap | Runtime quarantine state is not implemented. |
| `BoundedAuthorityUnderCompromise` | `Compromise`, `Execute` | Partial: delegation scope remains enforced | Compromise is modeled, not injected into a deployed identity boundary. |
| `DecisionLiveness` | `Submit`, `Resolve` | Gap | No runtime availability or failover liveness evidence. |

The explicit gaps are work items, not passing conformance claims.

## M4a implementation-conformance boundary

M4a adds runtime contracts and tests for a separate plant process, separately
keyed signed-observer process, Python research virtual-PLC process, and a
controller that has observe/simulate/dispatch ports but no plant-apply handle.
Those tests exercise application-level capability denial, signature and binding
validation, pre-observation compare-and-swap, one-dispatch behavior, explicit
unknown-effect handling, direct transaction pre/post linkage, and one orderly
PLC-child replay-reservation transfer.

This is implementation conformance evidence only. The committed TLA+ model was
not extended for M4a and therefore does not model the process topology, IPC
framing, observer or PLC boot epochs, transaction-local observation linkage,
orderly child replacement, or transport ambiguity. No TLC result should be
read as verification of those mechanisms. Conversely, passing M4a runtime tests
do not close the existing formal gaps for liveness, conflicting controllers,
quarantine, deployed identity, hostile-host isolation, or physical-process
safety.
