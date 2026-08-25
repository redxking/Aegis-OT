# Aegis-OT Project Plan

## State as of 2026-08-25

The original package is unavailable. This repository is a clean reconstruction based on the controlled handoff. No earlier implementation, test, experiment, or document artifact is treated as recovered or independently verified.

| Work package | State | Current exit evidence |
|---|---|---|
| WP0 Governance and reproducibility | In progress | Canonical study revision 0.7, revision log, experiment and formal manifests, and reproducible outcome hashes established |
| WP1 Executable assurance kernel | Initial implementation complete | Isolated candidate suite: 478 tests pass with 92.05 percent branch-aware coverage; strict typing, linting, and schema-drift checks are clean |
| WP2 Formal specification | Bounded M1 complete | Intended model: 167,193 generated and 55,512 distinct states, depth 20, no reported violation; 16 weakened cases produced expected counterexamples; runtime gaps remain explicit |
| WP3 Single-host simulation | Bounded M2 complete | 8,640-record, 30-seed, eight-baseline run reproduced by outcome hash; independent physical evaluation remains open |
| WP4 Power-system and OT integration | In progress | The bounded local pandapower/PyModbus gate and M4b capability-separated loop each have accepted 30-session retained runs and same-code local reproductions; M4b adds root-signed evidence and a separate-process topology-consequence evaluator, but not independent sensing, an independent AC solver, HELICS/OpenPLC, segmentation, hardware, or external validation |
| WP5 Multi-VM trust boundaries | Planned | Infrastructure scaffold only |
| WP6 Operate-through-compromise | Planned | Scenario definitions not yet executed |
| WP7 Scale and economics | Planned | No measurements |
| WP8 Independent validation | Planned | No independent review |

## Milestone sequence

1. M0: controlled reconstruction baseline, clean install, tests, experiment manifest, and canonical study revision 0.1.
2. M1: expanded TLA+ model, weakened variants, model-check evidence, and runtime conformance tests.
3. M2: independent outcome oracle, stronger baselines, ablations, and multi-seed statistical analysis.
4. M3: public power-system model and local process/virtual-device command boundary.
5. M4a: capability-separated deterministic-local plant, signed-observer, and
   research virtual-PLC loop; retained evidence and broader WP4 integration
   remain separate gates.
6. M4b: immutable root-signed evidence, capability probes, restart/replay
   evaluation, and a separate-process topology-consequence check for the M4a
   loop under the same-host deterministic-local boundary.
7. M4: SPIFFE/SPIRE identity, OPA service, network isolation, and six-node deployment.
8. M5: operate-through-compromise and degraded-mode evaluation.
9. M6: logical fleet scaling and economic sensitivity model.
10. M7-M8: independent review, replication package, publication, and release.

## Immediate acceptance gates

- A clean editable install succeeds without `PYTHONPATH`.
- Security-critical rejection paths have positive, negative, and property-based tests.
- The committed ActionProposal schema is generated from and checked against the runtime model.
- Every experiment records code state, configuration, host, seeds, and result hashes.
- The outcome oracle is implemented separately from the gateway safety evaluator.
- The canonical DOCX is the only manuscript and identifies Angelis Pseftis as author and editor.
- Synthetic results remain labeled as local measurements under stated assumptions.

## Active M3 increment

Implemented and locally verified:

- Pandapower 3.5.4 CIGRE MV balanced steady-state AC power-flow adapter with
  model, input, topology, and state digests.
- Trusted resource-to-actuator translation and transactional candidate/commit
  behavior.
- Signed, short-lived, single-use execution permits bound to the exact proposal,
  command, decision evidence, model, topology, pre-state, and expected post-state.
- A spawned child process containing the permit-aware PyModbus virtual device
  and physical model, reached only through the tested Modbus TCP loopback path.
- Signed response and command acknowledgments, readback correlation, replay
  protection, stale-state rejection, candidate re-attestation, atomic rollback,
  concurrent compare-and-swap behavior, restart-epoch invalidation, and explicit
  unknown-effect handling.
- Generated public schemas for the M3 trust-boundary messages.
- An isolated candidate suite of 478 passing tests at 92.05 percent branch-aware
  coverage, together with clean ruff, strict mypy, and schema-drift checks. The
  candidate run used committed retained-evidence files while preserving the
  user-modified copies in the primary working tree.
- A retained primary controlled run and separate local reproduction, each
  containing 30 fresh child-process sessions, 150 trials, and 270 chained
  evidence events. Both pass the offline verifier from the matching clean
  checkout and reproduce deterministic outcome hash
  `150b32da0055da6086a8f858f8dab4425d06b5bfd836ba653a10c1f20adf9005`.
- Primary-package observations of 0 modeled effects and 0 unauthorized device
  applications under the registered 120-trial end-to-end non-nominal metric,
  30/30 nominal closed-loop completions, and 0/30 replay effects. The
  unauthorized-application denominator includes 60 gateway no-dispatch trials
  and is not conditional on device dispatch. The fail-fast runner observed 0/150
  unknown effects, and the narrow proposal/decision/terminal-hash trace indicator
  was complete for 150/150 trials. These are fixed-condition conformance checks,
  not field-rate or ambiguity-rate estimates.

Evidence boundary and remaining M3 gates:

- The process boundary is on one host and the protocol is bound to loopback; it
  is not segmented OT networking or multi-VM isolation.
- The device is a PyModbus research virtual device, not OpenPLC or a physical
  PLC.
- The simulator is balanced steady-state power flow, not transient, protection,
  hardware-in-the-loop, or field behavior.
- HELICS coordination, OpenPLC integration, multi-VM deployment, and external
  validation remain uncompleted work.
- The locally reproduced package records the same commit and lock-file hash,
  host metadata, Python version, and selected component versions; it is not
  independent replication. The unsigned
  package manifests establish internal consistency with the recorded checkout,
  not external authenticity, custody, or operational effectiveness.
- Exactly 90 trials per retained package contain signed device acknowledgments.
  The 60 gateway no-dispatch trials per package are recorded as verified/not
  applicable because no device acknowledgment should exist.

WP4 therefore remains in progress. Passing tests establish local implementation
behavior under the tested conditions; they do not satisfy the WP4 exit gate or
establish operational effectiveness.

## Active M4a capability-separation increment

Implemented, retained, and locally reproduced:

- Distinct spawned plant, signed-observer, and Python research virtual-PLC
  processes with distinct PIDs and separate observer/PLC signing keys and boot
  epochs.
- A closed-loop controller with observation, candidate-simulation, and PLC-
  dispatch ports but no plant-apply handle. The trusted local harness separately
  retains lifecycle administration and permit-signing authority.
- Canonical JSON application frames over private process pipes with static
  operation allowlists and generated public schemas.
- A sole plant-apply endpoint created inside the plant supervisor and passed
  directly to the virtual PLC; negative probes exercise unavailable apply
  operations on observer, simulation, telemetry, and coordinator-admin paths.
- Permit and compare-and-swap binding across PLC identity, key, boot epoch,
  model, topology, state version, state digest, pre-observation digest, and
  expected post-state.
- Completion requiring one transaction-valid PLC-signed applied acknowledgment
  plus a fresh separately observer-signed post snapshot directly linked to the
  transaction's pre-observation and matching the authorized state.
- Explicit `not_dispatched`, `candidate_rejected`, `plc_rejected`,
  `unknown_effect`, `observation_diverged`, and `completed` terminal states,
  with at most one dispatch attempt and no automatic retry.
- Replay reservations surviving one orderly PLC-child replacement while the
  local lab remains running.

Acceptance boundary:

- Separation is at the application/process-capability level on one host under
  one OS user, filesystem, and clock domain. It is not a security boundary
  against a hostile coordinator or host.
- The observer and candidate evaluator read the same authoritative deterministic
  plant. The observer is separately keyed and separately processed, but it is
  not an independently operated sensor or an independently validated model.
- Post-observation linkage is transaction-local, not a continuous global chain.
- Replay state is temporary and covers one orderly child replacement only; it
  is not durable across host crash, power loss, tampering, or full-stack restart.
- The smoke output is transient operational status, not a retained manifest,
  signed-artifact package, offline verifier, reproduced experiment, or
  replication result.
- HELICS, OpenPLC and physical-PLC integration, real-time scan semantics,
  segmented or multi-host deployment, hardware-in-the-loop, recovery evaluation,
  concurrent controllers, external validation, and operational effectiveness
  remain open. M4a does not satisfy the WP4 exit gate.

## Active M4b independent-consequence evidence increment

Implemented and locally conformance-tested:

- Closed M4b transaction, component-registration, capability-probe, orderly-
  restart, independent-evaluation, trust-anchor, manifest, and detached-
  signature contracts with generated schemas.
- A solver-neutral topology fixture derived from the registered CIGRE MV model
  and a separately implemented graph/Decimal consequence evaluator that does
  not import the Aegis-OT controller, pandapower, or its numerical stack.
- A file/process bridge that converts a retained M4a transaction into a closed
  independent-evaluation request, executes the separate evaluator process, and
  rejects malformed, unsigned, incorrectly bound, or exit-code-inconsistent
  reports.
- A live same-host lab test in which one completed line-isolation transaction
  crossed that process boundary and returned a signed `agree` report for the
  registered topology consequence.
- A stable pre-report transaction projection for evaluator binding. This
  removes the former circular dependency in which a transaction record could
  hash a report that itself hashed a request claiming to hash the final
  transaction record.
- An immutable, content-addressed package finalizer and offline verifier with an
  external Ed25519 trust anchor, detached manifest signature, exact artifact
  hashes and counts, canonical JSON/JSONL checks, closed schemas, transaction
  correlations, source/fixture/configuration bindings, and separate integrity,
  acceptance, and checkout-match results.
- Two separately finalized 30-session packages from clean detached checkout
  `ad3f3a9c861d53293c1b764226e33c7bcc991234`. Each package contains 90
  transaction records, 120 denied capability probes, 30 signed independent
  evaluations, and 30 orderly-restart replay attempts. Both passed the offline
  verifier with trusted roots, accepted experiment semantics, and matching
  checkout bindings.
- Across each package, 30 nominal transactions completed with exactly one
  dispatch and no automatic retry; 60 identity/freshness cases were not
  dispatched; all 120 capability probes were denied; all 30 replay attempts
  were rejected without a second state effect; and all 30 independent
  topology-connectivity evaluations returned `agree`.
- The two packages have different package IDs and signing keys but the same
  timing-independent deterministic outcome hash
  `02af9e6b29b55fbde8a7de2ba2c45754281f61f9439a182541ca27632d0c0ebf`.
  This is a same-code, same-host local reproduction, not an independent
  replication.
- The clean detached checkout passed 516 tests; ruff, strict mypy across 43
  source files, generated-schema drift, and neutral-topology-fixture drift
  checks were also clean. The single warning is an upstream Starlette/httpx
  deprecation warning and did not affect test outcomes.

Evidence boundary and next hypothesis-critical gate:

- M4b supports only the tested same-host deterministic-local proposition: the
  registered identity and freshness failures were stopped before dispatch,
  unavailable cross-role capabilities remained unavailable, the registered
  nominal command produced one exact modeled effect, orderly replacement did
  not permit replay, and a separately implemented topology-connectivity check
  agreed with the retained post-observation.
- The evaluator does not independently sense the plant and is not an independent
  AC power-flow solver. It checks signed retained observations against a neutral
  topology/load fixture using graph and decimal arithmetic. Agreement therefore
  does not validate the plant model, measurements, voltage or thermal behavior.
- The M4b package itself does not exercise signed contradiction,
  missing-observation, malformed evaluator input, lost-response/unknown-effect,
  concurrent-controller, crash-recovery, or hostile-host conditions. The
  subsequent M4c campaign below covers a bounded subset of these faults but is
  not a replacement for M4b's raw signed package.
- M4b is not external custody, independent replication, segmented or multi-host
  deployment, HELICS/OpenPLC integration, hardware-in-the-loop, field evidence,
  production readiness, operational effectiveness, or WP4 completion.
- The next shortest claim-critical increment after M4c is abrupt process-crash
  consistency for the replay ledger plus missing-post handling at the
  independent-evaluator boundary. After that, identity/policy/control separation
  must move across an actual segmented deployment before the central system
  claim can be tested beyond a single-host process-capability boundary.

## Active M4c fault and adversarial increment

Implemented and locally reproduced in its stronger v3 form from clean detached
checkout `1a282b0467506368bd37246a33da0418c018ecfb`:

- A five-condition live-process campaign, with a fresh capability-separated
  plant, observer, virtual PLC, and controller stack for every condition.
- One nominal control completed with a valid acknowledgment and signed post-
  observation. Three after-dispatch faults—PLC response loss after an actual
  commit, post-observation unavailability after an acknowledged commit, and a
  post-observation altered after signing—each terminated as `unknown_effect`
  with exactly one dispatch and zero automatic retry.
- A fifth condition started the observer in a fixed experiment profile that
  signed the transaction predecessor as the post-state. The envelope was
  structurally valid, correctly signed, and transaction-bound, but contradicted
  the PLC acknowledgment, permit expectation, and actual plant state. The
  controller returned `observation_diverged`; the separate evaluator returned a
  valid signed `contradict` report with served-load, total-load-served, and
  isolated-resource mismatches.
- In all five conditions, a separate follow-up signed capture observed the
  modeled feeder isolation at state version 1. This matters because the three
  fault cases did not mean “no effect”; they meant the controller lacked enough
  trustworthy completion evidence to claim a known outcome.
- The post-signature tamper initially exposed a controller defect: terminal
  result construction attempted to retain an internally inconsistent envelope
  and raised a validation exception. The controller now revalidates rejected
  envelopes, retains only the last known-valid observation, and returns the
  terminal `unknown_effect` result. A regression test covers the failure.
- A separate evaluator process received strict-JSON duplicate-key input,
  returned exit code 2 with a self-verifying signed `input_rejected` report, and
  rejected a post-signature alteration of that report.
- A sixth lifecycle condition closed the complete plant/observer/PLC/controller
  stack, retained an externally owned replay ledger, started a fresh stack with
  new process identities and observer/PLC boot epochs, and submitted the exact
  prior request, permit, observation, decision, and assessment. The new PLC
  returned a validly signed `transaction_replayed` rejection before dispatch;
  the fresh plant state and ledger contents were unchanged.
- The v1 and v2 reports remain retained as historical increments. Two separately
  retained read-only v3 reports both met all six criteria and reproduced
  deterministic projection hash
  `52f2cd25760589041ad4d8391a1ca9ba0669b06c128d6ea8a7fa2a841a0179de`.
- The clean checkout passed 520 tests; ruff, strict mypy across 44 source files,
  schema drift, and topology-fixture drift checks were clean.

Evidence boundary and remaining critical tests:

- M4c is injected-port, same-host deterministic-local fault evidence. The
  retained JSON reports summarize the validated outcomes but do not retain the
  complete raw signed transaction/evidence artifacts or an external package
  trust anchor as M4b does. Git retention provides repository integrity after
  commit; it is not external custody or independent validation.
- The observed `unknown_effect` transitions support fail-closed outcome
  classification and no-retry behavior under the three registered injections.
  The signed contradiction supports explicit divergence classification under
  its registered profile. Five deterministic cases do not estimate failure
  rates, recovery times, or
  behavior under arbitrary faults.
- The replay result establishes persistence across an orderly full-stack
  shutdown and restart when the ledger directory remains available. It does not
  establish atomic durability under process kill during write, OS crash, power
  loss, filesystem corruption, rollback, deletion, or hostile-host tampering.
- Missing independent post-observation, concurrent state transition, process
  crash during dispatch or ledger persistence, hostile coordinator/host,
  segmentation, HELICS/OpenPLC, and hardware conditions remain untested or lack
  retained experimental evidence.

## Read-only public demonstration increment

The local Compose service now publishes a packaged evidence explorer rather
than the mutable research decision API. The explorer presents the retained M2
and M3 records with exact conditional denominators, Wilson intervals, execution
and retention commits, and an explicit current-checkout mismatch. Its builder
recomputes M2 from raw trials, invokes the offline verifier on both retained M3
packages, checks historical Git bindings, and rejects pairwise reproduction
drift across the registered equivalence contract before regenerating the
packaged projection. The mutable decision and
state routes remain available only through a separately launched research
application documented for loopback-only use.

This public-demo increment improves public traceability and removes a default
exposed mutation surface. It did not itself add HELICS, an independently
operated observer, segmented deployment, or external validation, so it does not
advance the WP4 exit gate by itself. The later M4a local process work described
above is not represented as retained public-demo evidence.
