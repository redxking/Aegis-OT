# M2 Independent-Oracle Experiment Method

Author: Angelis Pseftis  
Evidence boundary: reviewed synthetic scenarios and deterministic local models

## Purpose

M2 tests authorization and modeled consequence controls without using the safety
kernel's predicted state as the reference outcome. The reference oracle receives
the proposal and pre-action state and independently calculates the candidate
state. Its tighter load, voltage, thermal, isolation, and battery guardbands make
boundary disagreements observable.

## Baselines and ablations

| ID | Control path |
|---|---|
| B0_DIRECT | Executes every proposal. |
| B1_IDENTITY | Requires a recognized workload identity. |
| B2_STATIC_POLICY | Adds a static feeder and risk rule. |
| B3_ASSURED | Uses the complete gateway path. |
| B4_CONTEXTUAL_ABAC | Uses identity, contextual policy, observation match, and freshness without delegation or safety. |
| B5_RISK_AWARE | Uses identity, contextual policy, and a risk threshold without delegation, freshness, or safety. |
| B6_SAFETY_NO_DELEGATION | Uses identity, contextual policy, freshness, and kernel safety while omitting delegation. |
| B7_DELEGATION_NO_FRESHNESS | Uses identity, delegation, contextual policy, and kernel safety while omitting freshness. |

The 12-scenario catalog includes nominal, consequence-unsafe, guardband,
identity, resource-scope, freshness, confidence, and risk/approval templates.
Each template defines bounded parameter ranges plus reviewed reference-oracle
and kernel expectations. Trial seeds sample within those ranges, and the runner
fails if a sampled case crosses its declared classification. Each master seed
exercises three shuffled and independently sampled catalog cycles when the
default 36 trials per seed is used.

## Measures

- Physical unsafe-action escape: execution conditional on the reference oracle
  classifying the outcome outside its synthetic operating envelope.
- Unauthorized execution: execution conditional on the reviewed scenario's
  authorization expectation being false.
- False block: non-execution conditional on authorization being expected and the
  reference outcome being acceptable.
- Mission correctness: agreement between execution and the conjunction of the
  authorization expectation and acceptable reference outcome.
- Kernel-oracle disagreement: different safety classifications for the same
  proposal and pre-action state.

Rate estimates include Wilson 95 percent confidence intervals over the balanced
synthetic trial records. They characterize sampling under this designed catalog,
not model-form or field uncertainty. Thirty master seeds are required for the
controlled M2 run. The manifest preserves all seeds,
source and scenario hashes, Git state, host details, raw timing-inclusive hash,
and timing-independent deterministic outcome hash.

## Claim boundary

The reference oracle is independent at the implementation path, arithmetic, and
guardband levels. It is still a rule-based surrogate. These results cannot
establish power-system accuracy, PLC interoperability, deployment isolation,
field safety, or operational effectiveness.
