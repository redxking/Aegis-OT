"""Post-decision experimental outcome oracle, separate from the safety kernel."""

from __future__ import annotations

from dataclasses import dataclass

from .models import SystemState


@dataclass(frozen=True)
class OracleResult:
    acceptable: bool
    violations: tuple[str, ...]


class ReferenceOutcomeOracle:
    """A separate rule implementation for experiments, not field validation."""

    version = "reference-oracle-v1"

    def assess(self, candidate: SystemState) -> OracleResult:
        checks = (
            (candidate.critical_load_served_pct >= 80.0, "critical_load"),
            (0.95 <= candidate.minimum_voltage_pu, "undervoltage"),
            (candidate.maximum_voltage_pu <= 1.05, "overvoltage"),
            (candidate.maximum_line_loading_pct <= 100.0, "thermal_loading"),
            (len(candidate.isolated_assets) <= 2, "isolation_count"),
        )
        violations = tuple(name for passed, name in checks if not passed)
        return OracleResult(acceptable=not violations, violations=violations)
