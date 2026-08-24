from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

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
