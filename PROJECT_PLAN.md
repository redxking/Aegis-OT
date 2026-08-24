# Aegis-OT Project Plan

## State as of 2026-08-24

The original package is unavailable. This repository is a clean reconstruction based on the controlled handoff. No earlier implementation, test, experiment, or document artifact is treated as recovered or independently verified.

| Work package | State | Current exit evidence |
|---|---|---|
| WP0 Governance and reproducibility | In progress | Canonical study revision 0.6, revision log, experiment and formal manifests, and reproducible outcome hashes established |
| WP1 Executable assurance kernel | Initial implementation complete | Isolated candidate suite: 478 tests pass with 92.05 percent branch-aware coverage; strict typing, linting, and schema-drift checks are clean |
| WP2 Formal specification | Bounded M1 complete | Intended model: 167,193 generated and 55,512 distinct states, depth 20, no reported violation; 16 weakened cases produced expected counterexamples; runtime gaps remain explicit |
| WP3 Single-host simulation | Bounded M2 complete | 8,640-record, 30-seed, eight-baseline run reproduced by outcome hash; independent physical evaluation remains open |
| WP4 Power-system and OT integration | In progress | The bounded local pandapower/PyModbus gate has a verified 30-session result and a local outcome reproduction under matching recorded conditions; M4a adds a locally conformance-tested capability-separated plant/observer/virtual-PLC loop without a retained experiment package; HELICS/OpenPLC, segmented deployment, and external validation are not implemented |
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
6. M4: SPIFFE/SPIRE identity, OPA service, network isolation, and six-node deployment.
7. M5: operate-through-compromise and degraded-mode evaluation.
8. M6: logical fleet scaling and economic sensitivity model.
9. M7-M8: independent review, replication package, publication, and release.

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

Implemented and locally conformance-tested:

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
