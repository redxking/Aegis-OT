from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aegis_ot.models import Operation
from aegis_ot.oracle import ReferenceOutcomeOracle
from aegis_ot.safety import SafetyKernel


@given(st.floats(min_value=0, max_value=40, allow_nan=False, allow_infinity=False))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_kernel_and_oracle_agree_for_isolation_load_impact(proposal, state, impact) -> None:
    candidate = proposal.model_copy(update={"parameters": {"critical_load_impact_pct": impact}})
    kernel_result = SafetyKernel().evaluate(candidate, state)
    oracle_result = ReferenceOutcomeOracle().assess(kernel_result.predicted_state)
    assert kernel_result.safe == oracle_result.acceptable


def test_isolation_limit_is_enforced(proposal, state) -> None:
    crowded = state.model_copy(update={"isolated_assets": frozenset({"a", "b"})})
    result = SafetyKernel().evaluate(proposal, crowded)
    assert not result.safe
    assert "isolation_limit_exceeded" in result.reasons


@pytest.mark.parametrize(
    ("parameters", "reason"),
    [
        ({"minimum_voltage_delta_pu": -0.05}, "voltage_below_limit"),
        ({"maximum_voltage_delta_pu": 0.05}, "voltage_above_limit"),
    ],
)
def test_battery_voltage_limits_are_enforced(proposal, state, parameters, reason) -> None:
    candidate = proposal.model_copy(
        update={
            "operation": Operation.DISPATCH_BATTERY,
            "resource": "battery-1",
            "parameters": parameters,
        }
    )
    result = SafetyKernel().evaluate(candidate, state)
    assert not result.safe
    assert reason in result.reasons


def test_line_loading_limit_is_enforced(proposal, state) -> None:
    candidate = proposal.model_copy(update={"parameters": {"line_loading_delta_pct": 30.0}})
    result = SafetyKernel().evaluate(candidate, state)
    assert not result.safe
    assert "line_loading_above_limit" in result.reasons


def test_restore_and_shed_transitions_are_modeled(proposal, state) -> None:
    isolated = state.model_copy(
        update={"critical_load_served_pct": 90.0, "isolated_assets": frozenset({"feeder-1"})}
    )
    restore = proposal.model_copy(
        update={
            "operation": Operation.RESTORE_ASSET,
            "parameters": {"critical_load_restore_pct": 5.0},
        }
    )
    restored = SafetyKernel().evaluate(restore, isolated).predicted_state
    assert restored.critical_load_served_pct == 95.0
    assert "feeder-1" not in restored.isolated_assets

    shed = proposal.model_copy(
        update={
            "operation": Operation.SHED_LOAD,
            "parameters": {"critical_load_impact_pct": 5.0, "line_loading_relief_pct": 10.0},
        }
    )
    shed_state = SafetyKernel().evaluate(shed, state).predicted_state
    assert shed_state.critical_load_served_pct == 95.0
    assert shed_state.maximum_line_loading_pct == 62.0
