"""Independent reference outcome model for synthetic experiments."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .models import ActionProposal, Operation, SystemState


@dataclass(frozen=True)
class ReferenceLimits:
    """Conservative experimental guardbands, intentionally unlike the kernel limits."""

    minimum_critical_load_served_pct: Decimal = Decimal("82")
    minimum_voltage_pu: Decimal = Decimal("0.96")
    maximum_voltage_pu: Decimal = Decimal("1.04")
    maximum_line_loading_pct: Decimal = Decimal("95")
    maximum_simultaneous_isolations: int = 2
    maximum_absolute_battery_dispatch_mw: Decimal = Decimal("10")


@dataclass(frozen=True)
class OracleResult:
    acceptable: bool
    violations: tuple[str, ...]
    predicted_state: SystemState


class ReferenceOutcomeOracle:
    """Rule-based reference model; independent code, not physical validation."""

    version = "reference-outcome-v2"

    def __init__(self, limits: ReferenceLimits | None = None) -> None:
        self.limits = limits or ReferenceLimits()

    @staticmethod
    def _number(value: object, default: str = "0") -> Decimal:
        return Decimal(str(value if value is not None else default))

    def predict(self, proposal: ActionProposal, state: SystemState) -> SystemState:
        """Compute the candidate state without using the runtime safety kernel."""
        isolated = set(state.isolated_assets)
        load = self._number(state.critical_load_served_pct)
        minimum_voltage = self._number(state.minimum_voltage_pu)
        maximum_voltage = self._number(state.maximum_voltage_pu)
        loading = self._number(state.maximum_line_loading_pct)
        battery = self._number(state.battery_dispatch_mw)

        if proposal.operation is Operation.ISOLATE_ASSET:
            isolated.add(proposal.resource)
            load -= self._number(proposal.parameters.get("critical_load_impact_pct"))
            loading += self._number(proposal.parameters.get("line_loading_delta_pct"))
        elif proposal.operation is Operation.RESTORE_ASSET:
            isolated.discard(proposal.resource)
            load += self._number(proposal.parameters.get("critical_load_restore_pct"))
            loading += self._number(proposal.parameters.get("line_loading_delta_pct"))
        elif proposal.operation is Operation.SHED_LOAD:
            load -= self._number(proposal.parameters.get("critical_load_impact_pct"))
            loading -= self._number(proposal.parameters.get("line_loading_relief_pct"))
        elif proposal.operation is Operation.DISPATCH_BATTERY:
            battery += self._number(proposal.parameters.get("mw"))
            minimum_voltage += self._number(proposal.parameters.get("minimum_voltage_delta_pu"))
            maximum_voltage += self._number(proposal.parameters.get("maximum_voltage_delta_pu"))

        return state.model_copy(
            update={
                "version": state.version + 1,
                "critical_load_served_pct": float(max(Decimal(0), min(Decimal(100), load))),
                "minimum_voltage_pu": float(minimum_voltage),
                "maximum_voltage_pu": float(maximum_voltage),
                "maximum_line_loading_pct": float(max(Decimal(0), loading)),
                "isolated_assets": frozenset(isolated),
                "battery_dispatch_mw": float(battery),
            }
        )

    def assess(self, proposal: ActionProposal, state: SystemState) -> OracleResult:
        candidate = self.predict(proposal, state)
        limits = self.limits
        checks = (
            (
                self._number(candidate.critical_load_served_pct)
                >= limits.minimum_critical_load_served_pct,
                "critical_load_guardband",
            ),
            (
                self._number(candidate.minimum_voltage_pu) >= limits.minimum_voltage_pu,
                "undervoltage_guardband",
            ),
            (
                self._number(candidate.maximum_voltage_pu) <= limits.maximum_voltage_pu,
                "overvoltage_guardband",
            ),
            (
                self._number(candidate.maximum_line_loading_pct) <= limits.maximum_line_loading_pct,
                "thermal_loading_guardband",
            ),
            (
                len(candidate.isolated_assets) <= limits.maximum_simultaneous_isolations,
                "isolation_count",
            ),
            (
                abs(self._number(candidate.battery_dispatch_mw))
                <= limits.maximum_absolute_battery_dispatch_mw,
                "battery_dispatch_guardband",
            ),
        )
        violations = tuple(name for passed, name in checks if not passed)
        return OracleResult(not violations, violations, candidate)
