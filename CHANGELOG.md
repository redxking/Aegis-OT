# Changelog

All notable changes are recorded here. Dates describe actual repository activity.

## [Unreleased]

### Added

- Reconstructed repository governance and Python package foundation.
- Explicit evidence boundary separating the lost historical package from current results.
- Initial runtime-assurance interfaces, formal scaffold, and controlled research-document workflow.
- Twenty-six passing tests covering signatures, full-chain delegation, replay concurrency, evidence tampering, safety, API rejection, and experiment reproduction.
- Shared-seed 200-trial synthetic comparison with preserved exploratory-invalid predecessor run.
- Canonical controlled study revision 0.1 with reproducible figures, accessible images and tables, and rendered page QA.
- PyCharm-compatible Compose defaults using verified digest-pinned OPA 1.19.1 and Python 3.13.7 images; corrected the gateway Docker command override behavior.
- Trust-boundary validation rejects non-finite values, unknown or operation-inconsistent parameters, extra fields, invalid voltage ordering, and naive timestamps.
- Reproducible ActionProposal schema generation with CI drift detection.
- Expanded security-focused suite to 62 tests and 95 percent branch-aware coverage, with a 90 percent CI floor.
- Expanded the bounded TLA+ state machine and added reproducible intended and weakened model-check automation.
- Added explicit formal-to-runtime conformance tests and a mapping that preserves unimplemented gaps.
- Replaced the circular experiment oracle path with an independently implemented reference transition model and conservative guardbands.
- Added a 12-scenario reviewed synthetic truth catalog, four stronger comparison/ablation baselines, 30-seed execution support, Wilson intervals, and timing-independent outcome hashes.
- Added the bounded M3 pandapower CIGRE MV plant, trusted command translation,
  short-lived signed execution permits, and a separate-process PyModbus virtual-device
  boundary with signed acknowledgments, replay rejection, readback correlation,
  candidate re-attestation, atomic state commits, and explicit unknown-effect handling.
- Added the five-condition M3 controlled runner, public trust-boundary schemas,
  source/configuration/schema/artifact hashes, retained per-session verification keys,
  descriptive and interval statistics, and a reproducible M3 results figure.
- Added a fail-closed offline M3 evidence verifier covering safe package traversal,
  strict JSON, event-chain and exact payload correlation, state digests, registered
  fixtures, replay relationships, permit and acknowledgment signatures, summaries,
  deterministic outcomes, and current-checkout bindings.
- Retained the clean-checkout 30-session M3 controlled package and a separate
  local outcome reproduction under matching recorded conditions: 150 trials and
  270 chained events per package, all
  verifier checks passing, with matching deterministic outcome SHA-256
  `150b32da0055da6086a8f858f8dab4425d06b5bfd836ba653a10c1f20adf9005`.
- Added the evidence-derived M3 conformance and host-latency figure, including
  explicit fixed-condition, single-host, and non-field-validation boundaries.

### Fixed

- Made M3 figure generation handle gateway-denial and device-rejection records
  that intentionally do not carry a full `end_to_end_ms` field.
