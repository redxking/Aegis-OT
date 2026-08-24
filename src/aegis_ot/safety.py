"""Independent gateway-side candidate transition evaluator."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ActionProposal, Operation, SystemState


@dataclass(frozen=True)
class SafetyLimits:
    minimum_critical_load_served_pct: float = 80.0
    minimum_voltage_pu: float = 0.95
    maximum_voltage_pu: float = 1.05
    maximum_line_loading_pct: float = 100.0
    maximum_simultaneous_isolations: int = 2


@dataclass(frozen=True)
class SafetyResult:
    safe: bool
    reasons: tuple[str, ...]
    predicted_state: SystemState


class SafetyKernel:
    version = "surrogate-safety-v1"

    def __init__(self, limits: SafetyLimits | None = None, *, version: str | None = None) -> None:
        self.limits = limits or SafetyLimits()
        if version is not None:
            self.version = version

    def evaluate(self, proposal: ActionProposal, state: SystemState) -> SafetyResult:
        predicted = self._transition(proposal, state)
        reasons: list[str] = []
        if predicted.critical_load_served_pct < self.limits.minimum_critical_load_served_pct:
            reasons.append("critical_load_below_limit")
        if predicted.minimum_voltage_pu < self.limits.minimum_voltage_pu:
            reasons.append("voltage_below_limit")
        if predicted.maximum_voltage_pu > self.limits.maximum_voltage_pu:
            reasons.append("voltage_above_limit")
        if predicted.maximum_line_loading_pct > self.limits.maximum_line_loading_pct:
            reasons.append("line_loading_above_limit")
        if len(predicted.isolated_assets) > self.limits.maximum_simultaneous_isolations:
            reasons.append("isolation_limit_exceeded")
        return SafetyResult(safe=not reasons, reasons=tuple(reasons), predicted_state=predicted)

    def _transition(self, proposal: ActionProposal, state: SystemState) -> SystemState:
        isolated = set(state.isolated_assets)
        load = state.critical_load_served_pct
        min_v = state.minimum_voltage_pu
        max_v = state.maximum_voltage_pu
        loading = state.maximum_line_loading_pct
        battery = state.battery_dispatch_mw

        if proposal.operation is Operation.ISOLATE_ASSET:
            isolated.add(proposal.resource)
            impact = float(proposal.parameters.get("critical_load_impact_pct", 0.0))
            load -= impact
            loading += float(proposal.parameters.get("line_loading_delta_pct", 0.0))
        elif proposal.operation is Operation.RESTORE_ASSET:
            isolated.discard(proposal.resource)
            load += float(proposal.parameters.get("critical_load_restore_pct", 0.0))
            loading += float(proposal.parameters.get("line_loading_delta_pct", 0.0))
        elif proposal.operation is Operation.SHED_LOAD:
            load -= float(proposal.parameters.get("critical_load_impact_pct", 0.0))
            loading -= float(proposal.parameters.get("line_loading_relief_pct", 0.0))
        elif proposal.operation is Operation.DISPATCH_BATTERY:
            battery += float(proposal.parameters.get("mw", 0.0))
            min_v += float(proposal.parameters.get("minimum_voltage_delta_pu", 0.0))
            max_v += float(proposal.parameters.get("maximum_voltage_delta_pu", 0.0))

        return state.model_copy(
            update={
                "version": state.version + 1,
                "critical_load_served_pct": max(0.0, min(100.0, load)),
                "minimum_voltage_pu": min_v,
                "maximum_voltage_pu": max_v,
                "maximum_line_loading_pct": max(0.0, loading),
                "isolated_assets": frozenset(isolated),
                "battery_dispatch_mw": battery,
            }
        )
