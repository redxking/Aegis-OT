"""Typed domain models at Aegis-OT trust boundaries."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Operation(StrEnum):
    ISOLATE_ASSET = "isolate_asset"
    RESTORE_ASSET = "restore_asset"
    SHED_LOAD = "shed_load"
    DISPATCH_BATTERY = "dispatch_battery"


OPERATION_PARAMETERS: dict[Operation, frozenset[str]] = {
    Operation.ISOLATE_ASSET: frozenset(
        {"critical_load_impact_pct", "line_loading_delta_pct"}
    ),
    Operation.RESTORE_ASSET: frozenset(
        {"critical_load_restore_pct", "line_loading_delta_pct"}
    ),
    Operation.SHED_LOAD: frozenset(
        {"critical_load_impact_pct", "line_loading_relief_pct"}
    ),
    Operation.DISPATCH_BATTERY: frozenset(
        {"mw", "minimum_voltage_delta_pu", "maximum_voltage_delta_pu"}
    ),
}
PERCENTAGE_PARAMETERS = frozenset(
    {
        "critical_load_impact_pct",
        "critical_load_restore_pct",
        "line_loading_relief_pct",
    }
)


class DecisionOutcome(StrEnum):
    PERMIT = "permit"
    DENY = "deny"
    MODIFY = "modify"
    DEFER = "defer"
    SIMULATE = "simulate"
    REQUIRE_APPROVAL = "require_approval"
    QUARANTINE = "quarantine"
    REVOKE = "revoke"


class SystemState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    version: int = Field(ge=0)
    observed_at: datetime
    critical_load_served_pct: float = Field(ge=0, le=100)
    minimum_voltage_pu: float = Field(gt=0)
    maximum_voltage_pu: float = Field(gt=0)
    maximum_line_loading_pct: float = Field(ge=0)
    isolated_assets: frozenset[str] = frozenset()
    battery_dispatch_mw: float = 0.0

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def require_ordered_voltage_bounds(self) -> SystemState:
        if self.minimum_voltage_pu > self.maximum_voltage_pu:
            raise ValueError("minimum_voltage_pu must not exceed maximum_voltage_pu")
        return self


class ActionProposal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    proposal_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    actor_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    operation: Operation
    parameters: dict[str, Any] = Field(default_factory=dict)
    observed_state_version: int = Field(ge=0)
    observed_at: datetime
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    nonce: str = Field(min_length=16, max_length=256)
    confidence: float = Field(ge=0, le=1)
    risk_score: float = Field(ge=0, le=100)
    delegation_chain: tuple[str, ...] = Field(min_length=1)
    human_approval_id: str | None = Field(default=None, min_length=1)

    @field_validator("observed_at", "submitted_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def require_operation_parameters(self) -> ActionProposal:
        allowed = OPERATION_PARAMETERS[self.operation]
        unknown = sorted(set(self.parameters) - allowed)
        if unknown:
            raise ValueError(f"parameters are not valid for {self.operation}: {', '.join(unknown)}")

        normalized: dict[str, float] = {}
        for name, raw_value in self.parameters.items():
            if isinstance(raw_value, bool) or not isinstance(raw_value, int | float):
                raise ValueError(f"parameter {name} must be a finite number")
            value = float(raw_value)
            if not math.isfinite(value):
                raise ValueError(f"parameter {name} must be a finite number")
            normalized[name] = value

        for name in PERCENTAGE_PARAMETERS & normalized.keys():
            if not 0.0 <= normalized[name] <= 100.0:
                raise ValueError(f"parameter {name} must be between 0 and 100")
        return self


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    proposal_id: str
    outcome: DecisionOutcome
    reasons: tuple[str, ...]
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    policy_version: str
    safety_version: str
    state_version: int
    evidence_record_hash: str | None = None


class ExecutionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    proposal_id: str
    decision_id: str
    executed: bool
    acknowledged_at: datetime
    resulting_state: SystemState | None = None
    reason: str | None = None
