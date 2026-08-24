# Contributing

Contributions must preserve the distinction among formal proof, implementation conformance, local measurement, simulation, inference, and proposed capability.

Before opening a change:

1. Add or update tests for security-relevant behavior.
2. Run `ruff check .` and `pytest` from an installed environment.
3. Update affected schemas, ADRs, experiment manifests, and documentation.
4. Do not alter raw experiment data in place.
5. Do not weaken fail-closed behavior without an ADR and explicit degraded-mode analysis.

All canonical research-document authorship fields remain Angelis Pseftis.
