"""Reproducible JSON Schema exports for public trust-boundary messages."""

from __future__ import annotations

from typing import Any

from .models import (
    OPERATION_PARAMETERS,
    PERCENTAGE_PARAMETERS,
    ActionProposal,
)

ACTION_PROPOSAL_SCHEMA_ID = "https://example.invalid/aegis-ot/action-proposal-v1.schema.json"


def action_proposal_schema() -> dict[str, Any]:
    """Return the authoritative ActionProposal v1 JSON Schema."""
    schema = ActionProposal.model_json_schema(mode="validation")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = ACTION_PROPOSAL_SCHEMA_ID
    schema["title"] = "Aegis-OT ActionProposal v1"

    parameter_branches: list[dict[str, Any]] = []
    for operation, parameter_names in OPERATION_PARAMETERS.items():
        properties = {
            name: {
                "type": "number",
                **({"minimum": 0.0, "maximum": 100.0} if name in PERCENTAGE_PARAMETERS else {}),
            }
            for name in sorted(parameter_names)
        }
        parameter_branches.append(
            {
                "if": {"properties": {"operation": {"const": operation.value}}},
                "then": {
                    "properties": {
                        "parameters": {
                            "type": "object",
                            "properties": properties,
                            "additionalProperties": False,
                        }
                    }
                },
            }
        )
    schema["allOf"] = parameter_branches
    return schema
