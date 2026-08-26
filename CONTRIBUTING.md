# Contributing

Contributions must preserve the distinction among formal proof, implementation conformance, local measurement, simulation, inference, and proposed capability.

Before opening a change:

1. Add or update tests for security-relevant behavior.
2. Run `ruff check .` and `pytest` from an installed environment.
3. Update affected schemas, ADRs, experiment manifests, and documentation.
4. Do not alter raw experiment data in place.
5. Do not weaken fail-closed behavior without an ADR and explicit degraded-mode analysis.

Changes to components, interfaces, trust boundaries, Compose overlays, terminal
states, evidence paths, or verification gates must update the maintained
[systems-engineering view set](docs/architecture/diagram-set.md). Regenerate and
check it with:

```bash
.venv/bin/python scripts/build_system_diagrams.py
.venv/bin/python scripts/build_system_diagrams.py --check
```

All canonical research-document authorship fields remain Angelis Pseftis.
