# Aegis-OT Project Plan

## State as of 2026-08-24

The original package is unavailable. This repository is a clean reconstruction based on the controlled handoff. No earlier implementation, test, experiment, or document artifact is treated as recovered or independently verified.

| Work package | State | Current exit evidence |
|---|---|---|
| WP0 Governance and reproducibility | In progress | Canonical study revision 0.4, revision log, experiment and formal manifests, and reproducible outcome hashes established |
| WP1 Executable assurance kernel | Initial implementation complete | Current combined local suite: 264 tests pass with 91.57 percent branch-aware coverage; strict typing, linting, and schema-drift checks are clean |
| WP2 Formal specification | Bounded M1 complete | Intended model: 167,193 generated and 55,512 distinct states, depth 20, no reported violation; 16 weakened cases produced expected counterexamples; runtime gaps remain explicit |
| WP3 Single-host simulation | Bounded M2 complete | 8,640-record, 30-seed, eight-baseline run reproduced by outcome hash; independent physical evaluation remains open |
| WP4 Power-system and OT integration | In progress | Local pandapower/PyModbus closed-loop implementation and negative-path coverage are present; the controlled 30-session result is pending, and HELICS/OpenPLC integration is not implemented |
| WP5 Multi-VM trust boundaries | Planned | Infrastructure scaffold only |
| WP6 Operate-through-compromise | Planned | Scenario definitions not yet executed |
| WP7 Scale and economics | Planned | No measurements |
| WP8 Independent validation | Planned | No independent review |

## Milestone sequence

1. M0: controlled reconstruction baseline, clean install, tests, experiment manifest, and canonical study revision 0.1.
2. M1: expanded TLA+ model, weakened variants, model-check evidence, and runtime conformance tests.
3. M2: independent outcome oracle, stronger baselines, ablations, and multi-seed statistical analysis.
4. M3: public power-system model and local process/virtual-device command boundary, followed by HELICS and OpenPLC integration.
5. M4: SPIFFE/SPIRE identity, OPA service, network isolation, and six-node deployment.
6. M5: operate-through-compromise and degraded-mode evaluation.
7. M6: logical fleet scaling and economic sensitivity model.
8. M7-M8: independent review, replication package, publication, and release.

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
- A local suite of 264 passing tests at 91.57 percent branch-aware coverage,
  together with clean ruff, strict mypy, schema-drift, formal, and Compose
  configuration checks.

Evidence boundary and remaining M3 gates:

- The process boundary is on one host and the protocol is bound to loopback; it
  is not segmented OT networking or multi-VM isolation.
- The device is a PyModbus research virtual device, not OpenPLC or a physical
  PLC.
- The simulator is balanced steady-state power flow, not transient, protection,
  hardware-in-the-loop, or field behavior.
- HELICS coordination, OpenPLC integration, multi-VM deployment, and external
  validation remain uncompleted work.
- The controlled 30-session, five-condition-per-session run has not yet been
  executed and retained. It must start from a clean committed revision and
  produce a manifest, raw evidence, hashes, and reproducible summary before M3
  findings are reported.

WP4 therefore remains in progress. Passing tests establish local implementation
behavior under the tested conditions; they do not satisfy the WP4 exit gate or
establish operational effectiveness.
