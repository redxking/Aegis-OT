# Aegis-OT Project Plan

## State as of 2026-08-24

The original package is unavailable. This repository is a clean reconstruction based on the controlled handoff. No earlier implementation, test, experiment, or document artifact is treated as recovered or independently verified.

| Work package | State | Current exit evidence |
|---|---|---|
| WP0 Governance and reproducibility | In progress | Canonical study revision 0.3, revision log, experiment and formal manifests, and raw hashes established |
| WP1 Executable assurance kernel | Initial implementation complete | 73 tests pass; strict typing and linting clean; 95 percent branch-aware coverage; critical gateway, policy, model, replay, and evidence paths at 100 percent |
| WP2 Formal specification | Bounded M1 complete | Intended model: 167,193 generated and 55,512 distinct states, depth 20, no reported violation; 16 weakened cases produced expected counterexamples; runtime gaps remain explicit |
| WP3 Single-host simulation | Surrogate operational | Shared-seed 200-trial smoke run complete; physical independence and multi-seed analysis remain open |
| WP4 Power-system and OT integration | Planned | No closed-loop PLC or power-flow evidence |
| WP5 Multi-VM trust boundaries | Planned | Infrastructure scaffold only |
| WP6 Operate-through-compromise | Planned | Scenario definitions not yet executed |
| WP7 Scale and economics | Planned | No measurements |
| WP8 Independent validation | Planned | No independent review |

## Milestone sequence

1. M0: controlled reconstruction baseline, clean install, tests, experiment manifest, and canonical study revision 0.1.
2. M1: expanded TLA+ model, weakened variants, model-check evidence, and runtime conformance tests.
3. M2: independent outcome oracle, stronger baselines, ablations, and multi-seed statistical analysis.
4. M3: public power-system model, HELICS coordination, and virtual PLC command boundary.
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
