"""Independent steady-state plant adapter for the packaged CIGRE MV benchmark.

This module intentionally does not import the gateway safety model or the
experimental reference oracle.  It executes an AC power flow over a separate
pandapower network instance and reports the physical-model result.
"""

from __future__ import annotations

import copy
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from types import MappingProxyType
from typing import Any

import pandapower as pp  # type: ignore[import-untyped]
import pandapower.networks as pn  # type: ignore[import-untyped]

from .physical_models import (
    CandidateAssessment,
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
)

CIGRE_MV_SOURCE = "pandapower.networks.create_cigre_network_mv(with_der='all')"
CIGRE_MV_MODEL_ID = "pandapower-cigre-mv-all"
PANDAPOWER_LICENSE = "BSD-3-Clause"


class PhysicalSimulationError(RuntimeError):
    """Raised when a command is invalid or the transactional power flow fails."""


@dataclass(frozen=True)
class PhysicalLimits:
    """Pre-registered supervisory limits for the M3 steady-state model."""

    minimum_voltage_pu: float = 0.90
    maximum_voltage_pu: float = 1.10
    maximum_line_loading_pct: float = 100.0
    minimum_total_load_served_pct: float = 90.0
    minimum_priority_load_served_pct: float = 80.0


@dataclass(frozen=True)
class ResourceBinding:
    resource: str
    command_type: PhysicalCommandType
    target: str
    target_index: int
    minimum_setpoint: float
    maximum_setpoint: float


DEFAULT_RESOURCE_BINDINGS: dict[str, ResourceBinding] = {
    # Line and storage indices are explicit and verified against the packaged model at startup.
    "feeder-1": ResourceBinding(
        resource="feeder-1",
        command_type=PhysicalCommandType.SET_LINE_SERVICE,
        target="Line 5-6",
        target_index=4,
        minimum_setpoint=0.0,
        maximum_setpoint=1.0,
    ),
    "feeder-2": ResourceBinding(
        resource="feeder-2",
        command_type=PhysicalCommandType.SET_LINE_SERVICE,
        target="Line 8-9",
        target_index=6,
        minimum_setpoint=0.0,
        maximum_setpoint=1.0,
    ),
    "battery-1": ResourceBinding(
        resource="battery-1",
        command_type=PhysicalCommandType.SET_BATTERY_INJECTION,
        target="Battery 1",
        target_index=0,
        minimum_setpoint=-1.0,
        maximum_setpoint=1.0,
    ),
}

# These packaged load rows are declared as a synthetic mission-priority subset for M3.
# This is an Aegis-OT transformation, not a claim about the original CIGRE load semantics.
DEFAULT_PRIORITY_LOAD_INDICES = frozenset({12, 13, 16, 17})


def _json_scalar(value: Any) -> str | int | float | bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return None if not math.isfinite(value) else float(value)
    if hasattr(value, "item"):
        return _json_scalar(value.item())
    return str(value)


def _table_records(net: Any, table: str, columns: tuple[str, ...]) -> list[dict[str, Any]]:
    frame = getattr(net, table)
    records: list[dict[str, Any]] = []
    for index, row in frame.sort_index().iterrows():
        record: dict[str, Any] = {"index": int(index)}
        for column in columns:
            record[column] = _json_scalar(row[column])
        records.append(record)
    return records


def _all_table_records(
    net: Any,
    table: str,
    *,
    exclude: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    frame = getattr(net, table)
    columns = sorted((column for column in frame.columns if str(column) not in exclude), key=str)
    records: list[dict[str, Any]] = []
    for index, row in frame.sort_index().iterrows():
        record: dict[str, Any] = {"index": int(index)}
        for column in columns:
            record[str(column)] = _json_scalar(row[column])
        records.append(record)
    return records


class PandapowerCigreMVPlant:
    """Transactional authoritative plant state backed by pandapower 3.5.4."""

    simulator_version = f"pandapower-{pp.__version__}"
    power_flow_options: Mapping[str, Any] = MappingProxyType(
        {
            "algorithm": "nr",
            "calculate_voltage_angles": True,
            "init": "auto",
            "numba": False,
            "tolerance_mva": 1e-8,
            "max_iteration": 20,
        }
    )

    def __init__(
        self,
        *,
        limits: PhysicalLimits | None = None,
        resource_bindings: dict[str, ResourceBinding] | None = None,
        priority_load_indices: frozenset[int] = DEFAULT_PRIORITY_LOAD_INDICES,
        step_seconds: float = 1.0,
        observed_at: datetime | None = None,
        observation_clock: Callable[[], datetime] | None = None,
        observation_source_id: str = "pandapower-cigre-mv-process",
    ) -> None:
        if step_seconds <= 0 or not math.isfinite(step_seconds):
            raise ValueError("step_seconds must be finite and positive")
        self.limits = limits or PhysicalLimits()
        self.resource_bindings: Mapping[str, ResourceBinding] = MappingProxyType(
            dict(resource_bindings or DEFAULT_RESOURCE_BINDINGS)
        )
        self.priority_load_indices = priority_load_indices
        self.step_seconds = float(step_seconds)
        self._net = pn.create_cigre_network_mv(with_der="all")
        self._lock = RLock()
        self._state_version = 0
        self._simulation_time_s = 0.0
        if observed_at is not None and observation_clock is not None:
            raise ValueError("provide observed_at or observation_clock, not both")
        self._observation_clock = observation_clock or (
            (lambda: observed_at) if observed_at is not None else lambda: datetime.now(UTC)
        )
        self._observed_at = self._observation_clock()
        self._observation_sequence = 0
        self._observation_source_id = observation_source_id
        self._validate_configuration()
        self._model_digest = canonical_digest(self._model_material())
        if not self._solve(self._net):
            raise PhysicalSimulationError("baseline_power_flow_nonconvergent")

    @property
    def model_digest(self) -> str:
        return self._model_digest

    def _validate_configuration(self) -> None:
        if not self.priority_load_indices:
            raise ValueError("at least one mission-priority load must be configured")
        missing_loads = sorted(self.priority_load_indices - set(map(int, self._net.load.index)))
        if missing_loads:
            raise ValueError(f"priority load indices are absent: {missing_loads}")
        for resource, binding in self.resource_bindings.items():
            if resource != binding.resource:
                raise ValueError(f"resource binding key mismatch: {resource}")
            if binding.command_type is PhysicalCommandType.SET_LINE_SERVICE:
                if binding.target_index not in self._net.line.index:
                    raise ValueError(f"line target is absent for {resource}")
                actual = str(self._net.line.at[binding.target_index, "name"])
            else:
                if binding.target_index not in self._net.storage.index:
                    raise ValueError(f"storage target is absent for {resource}")
                actual = str(self._net.storage.at[binding.target_index, "name"])
            if actual != binding.target:
                raise ValueError(
                    f"target name mismatch for {resource}: expected {binding.target}, got {actual}"
                )

    def _model_material(self) -> dict[str, Any]:
        return {
            "model_id": CIGRE_MV_MODEL_ID,
            "source": CIGRE_MV_SOURCE,
            "pandapower_version": pp.__version__,
            "license": PANDAPOWER_LICENSE,
            "power_flow_options": dict(self.power_flow_options),
            "limits": self.limits.__dict__,
            "priority_load_indices": sorted(self.priority_load_indices),
            "resource_bindings": {
                key: {
                    "resource": value.resource,
                    "command_type": value.command_type.value,
                    "target": value.target,
                    "target_index": value.target_index,
                    "minimum_setpoint": value.minimum_setpoint,
                    "maximum_setpoint": value.maximum_setpoint,
                }
                for key, value in sorted(self.resource_bindings.items())
            },
            "network": self._static_network_material(self._net),
        }

    @staticmethod
    def _input_table_exclusions() -> dict[str, frozenset[str]]:
        return {
            "bus": frozenset({"in_service"}),
            "line": frozenset({"in_service"}),
            "load": frozenset({"p_mw", "q_mvar", "scaling", "in_service"}),
            "sgen": frozenset({"p_mw", "q_mvar", "scaling", "in_service"}),
            "storage": frozenset({"p_mw", "q_mvar", "scaling", "soc_percent", "in_service"}),
            "switch": frozenset({"closed"}),
            "trafo": frozenset({"tap_pos", "in_service"}),
            "ext_grid": frozenset({"vm_pu", "va_degree", "in_service"}),
            "shunt": frozenset({"step", "in_service"}),
        }

    def _static_network_material(self, net: Any) -> dict[str, Any]:
        exclusions = self._input_table_exclusions()
        tables: dict[str, Any] = {}
        for name in sorted(net.keys()):
            value = net[name]
            if name.startswith("_") or name.startswith("res_") or not hasattr(value, "columns"):
                continue
            tables[name] = {
                "columns": sorted(
                    str(column)
                    for column in value.columns
                    if str(column) not in exclusions.get(name, frozenset())
                ),
                "records": _all_table_records(
                    net,
                    name,
                    exclude=exclusions.get(name, frozenset()),
                ),
            }
        return {
            "sn_mva": _json_scalar(net.sn_mva),
            "f_hz": _json_scalar(net.f_hz),
            "format_version": str(net.format_version),
            "pandapower_network_version": str(net.version),
            "tables": tables,
        }

    def _input_digest(self, net: Any) -> str:
        dynamic_columns = {
            "bus": ("in_service",),
            "line": ("in_service",),
            "load": ("p_mw", "q_mvar", "scaling", "in_service"),
            "sgen": ("p_mw", "q_mvar", "scaling", "in_service"),
            "storage": ("p_mw", "q_mvar", "scaling", "soc_percent", "in_service"),
            "switch": ("closed",),
            "trafo": ("tap_pos", "in_service"),
            "ext_grid": ("vm_pu", "va_degree", "in_service"),
            "shunt": ("step", "in_service"),
        }
        return canonical_digest(
            {
                table: _table_records(net, table, columns)
                for table, columns in dynamic_columns.items()
            }
        )

    def _assert_model_integrity(self) -> None:
        if canonical_digest(self._model_material()) != self._model_digest:
            raise PhysicalSimulationError("model_configuration_changed")

    def _topology_digest(self, net: Any) -> str:
        return canonical_digest(
            {
                "bus": _table_records(net, "bus", ("in_service",)),
                "line": _table_records(
                    net,
                    "line",
                    ("from_bus", "to_bus", "in_service"),
                ),
                "switch": _table_records(
                    net,
                    "switch",
                    ("bus", "element", "et", "closed"),
                ),
                "trafo": _table_records(
                    net,
                    "trafo",
                    ("hv_bus", "lv_bus", "tap_pos", "in_service"),
                ),
                "ext_grid": _table_records(net, "ext_grid", ("bus", "in_service")),
            }
        )

    def _solve(self, net: Any) -> bool:
        try:
            pp.runpp(net, **self.power_flow_options)
        except Exception:  # pandapower exposes several solver-specific failure types
            net.converged = False
        return bool(net.converged)

    @staticmethod
    def _finite_tuple(values: Any) -> tuple[float | None, ...]:
        result: list[float | None] = []
        for value in values:
            numeric = float(value)
            result.append(numeric if math.isfinite(numeric) else None)
        return tuple(result)

    def _snapshot(
        self,
        net: Any,
        *,
        state_version: int,
        simulation_time_s: float,
        observed_at: datetime,
        observation_sequence: int,
        converged: bool,
    ) -> PhysicalStateSnapshot:
        bus_voltage = (
            self._finite_tuple(net.res_bus.vm_pu.tolist())
            if converged
            else tuple(None for _ in net.bus.index)
        )
        line_loading = (
            self._finite_tuple(net.res_line.loading_percent.tolist())
            if converged
            else tuple(None for _ in net.line.index)
        )
        total_demand = 0.0
        served = 0.0
        priority_demand = 0.0
        priority_served = 0.0
        for index, load in net.load.iterrows():
            if not bool(load.in_service):
                continue
            demand = float(load.p_mw)
            total_demand += demand
            if int(index) in self.priority_load_indices:
                priority_demand += demand
            bus_index = int(load.bus)
            bus_is_supplied = converged and bus_voltage[bus_index] is not None
            if bus_is_supplied:
                served += demand
                if int(index) in self.priority_load_indices:
                    priority_served += demand

        unserved = max(0.0, total_demand - served)
        total_served_pct = 100.0 if total_demand == 0 else 100.0 * served / total_demand
        priority_served_pct = (
            100.0 if priority_demand == 0 else 100.0 * priority_served / priority_demand
        )
        finite_voltage = [value for value in bus_voltage if value is not None]
        finite_loading = [value for value in line_loading if value is not None]
        minimum_voltage = min(finite_voltage) if finite_voltage else None
        maximum_voltage = max(finite_voltage) if finite_voltage else None
        maximum_loading = max(finite_loading) if finite_loading else None
        voltage_violations = sum(
            value < self.limits.minimum_voltage_pu or value > self.limits.maximum_voltage_pu
            for value in finite_voltage
        )
        thermal_violations = sum(
            value > self.limits.maximum_line_loading_pct for value in finite_loading
        )
        unsafe = (
            not converged
            or total_served_pct < self.limits.minimum_total_load_served_pct
            or priority_served_pct < self.limits.minimum_priority_load_served_pct
            or voltage_violations > 0
            or thermal_violations > 0
        )
        isolated = tuple(
            sorted(
                resource
                for resource, binding in self.resource_bindings.items()
                if binding.command_type is PhysicalCommandType.SET_LINE_SERVICE
                and not bool(net.line.at[binding.target_index, "in_service"])
            )
        )
        battery_injection = {
            resource: -float(net.storage.at[binding.target_index, "p_mw"])
            for resource, binding in sorted(self.resource_bindings.items())
            if binding.command_type is PhysicalCommandType.SET_BATTERY_INJECTION
        }
        provisional = PhysicalStateSnapshot(
            model_id=CIGRE_MV_MODEL_ID,
            simulator_version=self.simulator_version,
            model_digest=self._model_digest,
            input_digest=self._input_digest(net),
            topology_digest=self._topology_digest(net),
            state_digest="0" * 64,
            observation_digest="0" * 64,
            observation_sequence=observation_sequence,
            observation_source_id=self._observation_source_id,
            observation_clock_domain="UTC",
            state_version=state_version,
            simulation_time_s=simulation_time_s,
            observed_at=observed_at,
            converged=converged,
            total_load_demand_mw=total_demand,
            served_load_mw=served,
            unserved_load_mw=unserved,
            total_load_served_pct=total_served_pct,
            priority_load_demand_mw=priority_demand,
            priority_load_served_mw=priority_served,
            priority_load_served_pct=priority_served_pct,
            minimum_voltage_pu=minimum_voltage,
            maximum_voltage_pu=maximum_voltage,
            maximum_line_loading_pct=maximum_loading,
            voltage_violation_count=voltage_violations,
            thermal_violation_count=thermal_violations,
            unsafe_state=unsafe,
            isolated_resources=isolated,
            battery_injection_mw=battery_injection,
            bus_voltage_pu=bus_voltage,
            line_loading_pct=line_loading,
        )
        with_state_digest = provisional.model_copy(
            update={"state_digest": canonical_digest(provisional.digest_material())}
        )
        return with_state_digest.model_copy(
            update={
                "observation_digest": canonical_digest(with_state_digest.observation_material())
            }
        )

    def read_state(self) -> PhysicalStateSnapshot:
        with self._lock:
            self._assert_model_integrity()
            return self._snapshot(
                self._net,
                state_version=self._state_version,
                simulation_time_s=self._simulation_time_s,
                observed_at=self._observed_at,
                observation_sequence=self._observation_sequence,
                converged=bool(self._net.converged),
            )

    def capture_state(self) -> PhysicalStateSnapshot:
        """Capture a fresh observation envelope without changing physical state."""

        with self._lock:
            self._observed_at = self._observation_clock()
            self._observation_sequence += 1
            return self.read_state()

    def restore_state(
        self,
        snapshot: PhysicalStateSnapshot,
    ) -> PhysicalStateSnapshot:
        """Restore one trusted physical checkpoint onto a fresh model projection.

        Only the physical state is restored.  Observation source, time, and
        sequence belong to this plant instance, so the returned observation
        envelope is deliberately fresh even when the physical state digest is
        identical to the checkpoint.  Every check completes against a
        candidate network before the authoritative in-memory state is swapped.
        """

        with self._lock:
            self._assert_model_integrity()
            if self._state_version != 0 or self._simulation_time_s != 0.0:
                raise PhysicalSimulationError("restore_target_not_fresh")
            if not snapshot.verify_digest():
                raise PhysicalSimulationError("restore_checkpoint_digest_invalid")
            if (
                snapshot.model_id != CIGRE_MV_MODEL_ID
                or snapshot.simulator_version != self.simulator_version
                or snapshot.model_digest != self._model_digest
            ):
                raise PhysicalSimulationError("restore_model_mismatch")
            if not snapshot.converged or snapshot.unsafe_state:
                raise PhysicalSimulationError("restore_checkpoint_not_safe")

            line_bindings = {
                resource: binding
                for resource, binding in self.resource_bindings.items()
                if binding.command_type is PhysicalCommandType.SET_LINE_SERVICE
            }
            isolated_resources = tuple(snapshot.isolated_resources)
            if (
                isolated_resources != tuple(sorted(set(isolated_resources)))
                or not set(isolated_resources).issubset(line_bindings)
            ):
                raise PhysicalSimulationError("restore_line_state_invalid")

            battery_bindings = {
                resource: binding
                for resource, binding in self.resource_bindings.items()
                if binding.command_type is PhysicalCommandType.SET_BATTERY_INJECTION
            }
            if set(snapshot.battery_injection_mw) != set(battery_bindings):
                raise PhysicalSimulationError("restore_storage_state_invalid")
            for resource, injection in snapshot.battery_injection_mw.items():
                binding = battery_bindings[resource]
                if not binding.minimum_setpoint <= injection <= binding.maximum_setpoint:
                    raise PhysicalSimulationError("restore_storage_state_invalid")

            candidate_net = pn.create_cigre_network_mv(with_der="all")
            candidate_model_material = self._model_material()
            candidate_model_material["network"] = self._static_network_material(
                candidate_net
            )
            if canonical_digest(candidate_model_material) != self._model_digest:
                raise PhysicalSimulationError("restore_model_mismatch")

            isolated = set(isolated_resources)
            for resource, binding in line_bindings.items():
                candidate_net.line.at[binding.target_index, "in_service"] = (
                    resource not in isolated
                )
            for resource, binding in battery_bindings.items():
                # pandapower storage uses positive p_mw for charging; Aegis
                # checkpoints use positive values for injection.
                candidate_net.storage.at[binding.target_index, "p_mw"] = (
                    -snapshot.battery_injection_mw[resource]
                )

            if not self._solve(candidate_net):
                raise PhysicalSimulationError("restore_power_flow_nonconvergent")
            restored_at = self._observation_clock()
            restored = self._snapshot(
                candidate_net,
                state_version=snapshot.state_version,
                simulation_time_s=snapshot.simulation_time_s,
                observed_at=restored_at,
                observation_sequence=0,
                converged=True,
            )
            if restored.input_digest != snapshot.input_digest:
                raise PhysicalSimulationError("restore_input_digest_mismatch")
            if restored.topology_digest != snapshot.topology_digest:
                raise PhysicalSimulationError("restore_topology_digest_mismatch")
            if restored.state_digest != snapshot.state_digest:
                raise PhysicalSimulationError("restore_state_digest_mismatch")

            self._net = candidate_net
            self._state_version = snapshot.state_version
            self._simulation_time_s = snapshot.simulation_time_s
            self._observed_at = restored_at
            self._observation_sequence = 0
            return restored

    def _validate_command(self, command: PhysicalControlCommand) -> ResourceBinding:
        binding = self.resource_bindings.get(command.resource)
        if binding is None:
            raise PhysicalSimulationError("resource_not_mapped")
        if (
            command.command_type is not binding.command_type
            or command.target != binding.target
            or command.target_index != binding.target_index
        ):
            raise PhysicalSimulationError("command_target_binding_mismatch")
        if not binding.minimum_setpoint <= command.setpoint <= binding.maximum_setpoint:
            raise PhysicalSimulationError("command_setpoint_out_of_bounds")
        return binding

    def _apply_to_network(self, net: Any, command: PhysicalControlCommand) -> None:
        binding = self._validate_command(command)
        if command.command_type is PhysicalCommandType.SET_LINE_SERVICE:
            net.line.at[binding.target_index, "in_service"] = bool(command.setpoint)
        elif command.command_type is PhysicalCommandType.SET_BATTERY_INJECTION:
            # pandapower storage uses positive p_mw for charging; Aegis uses positive for injection.
            net.storage.at[binding.target_index, "p_mw"] = -command.setpoint
        else:  # pragma: no cover - strict enum and validation make this unreachable
            raise PhysicalSimulationError("unsupported_command_type")

    def simulate_candidate(
        self,
        command: PhysicalControlCommand,
    ) -> CandidateAssessment:
        with self._lock:
            self._assert_model_integrity()
            pre_state = self.read_state()
            candidate_net = copy.deepcopy(self._net)
            self._apply_to_network(candidate_net, command)
            converged = self._solve(candidate_net)
            post_state = self._snapshot(
                candidate_net,
                state_version=self._state_version + 1,
                simulation_time_s=self._simulation_time_s + self.step_seconds,
                observed_at=self._observed_at + timedelta(seconds=self.step_seconds),
                observation_sequence=self._observation_sequence + 1,
                converged=converged,
            )
            reasons: list[str] = []
            if not converged:
                reasons.append("power_flow_nonconvergent")
            if post_state.total_load_served_pct < self.limits.minimum_total_load_served_pct:
                reasons.append("total_load_below_limit")
            if post_state.priority_load_served_pct < self.limits.minimum_priority_load_served_pct:
                reasons.append("priority_load_below_limit")
            if post_state.voltage_violation_count:
                reasons.append("voltage_limit_violation")
            if post_state.thermal_violation_count:
                reasons.append("thermal_limit_violation")
            return CandidateAssessment(
                command_digest=command.digest,
                pre_state=pre_state,
                post_state=post_state,
                safe=not reasons,
                reasons=tuple(reasons),
            )

    def apply_authorized_command(
        self,
        command: PhysicalControlCommand,
        *,
        expected_pre_state_version: int | None = None,
        expected_pre_state_digest: str | None = None,
        expected_pre_observation_digest: str | None = None,
        expected_post_state_digest: str | None = None,
        expected_post_topology_digest: str | None = None,
        effect_deadline: datetime | None = None,
        effect_clock: Callable[[], datetime] | None = None,
    ) -> PhysicalStateSnapshot:
        """Apply atomically: a failed solver leaves the authoritative plant unchanged."""

        if (effect_deadline is None) is not (effect_clock is None):
            raise ValueError("effect deadline and clock must be configured together")
        if effect_deadline is not None and (
            effect_deadline.tzinfo is None or effect_deadline.utcoffset() is None
        ):
            raise ValueError("effect deadline must be timezone-aware")
        with self._lock:
            self._assert_model_integrity()
            current = self.read_state()
            if (
                expected_pre_state_version is not None
                and current.state_version != expected_pre_state_version
            ):
                raise PhysicalSimulationError("precommit_state_version_changed")
            if (
                expected_pre_state_digest is not None
                and current.state_digest != expected_pre_state_digest
            ):
                raise PhysicalSimulationError("precommit_state_digest_changed")
            if (
                expected_pre_observation_digest is not None
                and current.observation_digest != expected_pre_observation_digest
            ):
                raise PhysicalSimulationError("precommit_observation_changed")
            candidate_net = copy.deepcopy(self._net)
            self._apply_to_network(candidate_net, command)
            if not self._solve(candidate_net):
                raise PhysicalSimulationError("power_flow_nonconvergent")
            next_time = self._simulation_time_s + self.step_seconds
            next_version = self._state_version + 1
            next_observed_at = self._observation_clock()
            next_observation_sequence = self._observation_sequence + 1
            snapshot = self._snapshot(
                candidate_net,
                state_version=next_version,
                simulation_time_s=next_time,
                observed_at=next_observed_at,
                observation_sequence=next_observation_sequence,
                converged=True,
            )
            if snapshot.unsafe_state:
                raise PhysicalSimulationError("post_state_violates_physical_limits")
            if (
                expected_post_state_digest is not None
                and snapshot.state_digest != expected_post_state_digest
            ):
                raise PhysicalSimulationError("candidate_outcome_diverged")
            if (
                expected_post_topology_digest is not None
                and snapshot.topology_digest != expected_post_topology_digest
            ):
                raise PhysicalSimulationError("candidate_topology_diverged")
            if (
                effect_deadline is not None
                and effect_clock is not None
                and effect_clock() >= effect_deadline
            ):
                raise PhysicalSimulationError("authorization_expired_before_effect")
            self._net = candidate_net
            self._simulation_time_s = next_time
            self._state_version = next_version
            self._observed_at = next_observed_at
            self._observation_sequence = next_observation_sequence
            return snapshot
