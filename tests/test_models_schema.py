from __future__ import annotations

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from aegis_ot.models import ActionProposal, SystemState
from aegis_ot.schema import action_proposal_schema


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), "1", True])
def test_action_parameter_must_be_a_finite_json_number(proposal, value) -> None:
    data = proposal.model_dump()
    data["parameters"] = {"critical_load_impact_pct": value}
    with pytest.raises(ValidationError, match="finite number"):
        ActionProposal.model_validate(data)


@pytest.mark.parametrize("value", [-0.01, 100.01])
def test_percentage_action_parameter_is_bounded(proposal, value: float) -> None:
    data = proposal.model_dump()
    data["parameters"] = {"critical_load_impact_pct": value}
    with pytest.raises(ValidationError, match="between 0 and 100"):
        ActionProposal.model_validate(data)


def test_operation_rejects_unknown_parameter(proposal) -> None:
    data = proposal.model_dump()
    data["parameters"] = {"critical_load_impact_pct": 5.0, "shell_command": 1.0}
    with pytest.raises(ValidationError, match="not valid for isolate_asset"):
        ActionProposal.model_validate(data)


def test_trust_boundary_rejects_extra_fields(proposal) -> None:
    data = proposal.model_dump()
    data["unmodeled_authority"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ActionProposal.model_validate(data)


def test_system_state_rejects_nonfinite_and_inverted_voltage(state) -> None:
    nonfinite = state.model_dump()
    nonfinite["maximum_line_loading_pct"] = float("nan")
    with pytest.raises(ValidationError, match="finite number"):
        SystemState.model_validate(nonfinite)

    inverted = state.model_dump()
    inverted["minimum_voltage_pu"] = 1.06
    inverted["maximum_voltage_pu"] = 1.05
    with pytest.raises(ValidationError, match="must not exceed"):
        SystemState.model_validate(inverted)


def test_state_and_proposal_reject_naive_timestamps(state, proposal) -> None:
    state_data = state.model_dump()
    state_data["observed_at"] = datetime(2026, 8, 24, 16, 0)
    with pytest.raises(ValidationError, match="timezone-aware"):
        SystemState.model_validate(state_data)

    proposal_data = proposal.model_dump()
    proposal_data["submitted_at"] = datetime(2026, 8, 24, 16, 0)
    with pytest.raises(ValidationError, match="timezone-aware"):
        ActionProposal.model_validate(proposal_data)


def test_committed_action_schema_matches_authoritative_model() -> None:
    with open("schemas/action-proposal.schema.json", encoding="utf-8") as schema_file:
        committed = json.load(schema_file)
    assert committed == action_proposal_schema()


def test_schema_has_operation_specific_closed_parameter_sets() -> None:
    schema = action_proposal_schema()
    branches = schema["allOf"]
    assert len(branches) == 4
    assert all(
        branch["then"]["properties"]["parameters"]["additionalProperties"] is False
        for branch in branches
    )
