"""Typed contracts for the M3 physical-simulation and control boundary."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .crypto import sign_bytes, verify_bytes
from .models import ActionProposal, Decision, DecisionOutcome, Operation

SHA256_PATTERN = r"^[0-9a-f]{64}$"


def canonical_digest(value: BaseModel | dict[str, Any]) -> str:
    """Return a stable SHA-256 digest over canonical JSON material."""

    material = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def proposal_digest(proposal: ActionProposal) -> str:
    """Bind every proposal field, including delegation and observation context."""

    return canonical_digest(proposal)


class PhysicalCommandType(StrEnum):
    SET_LINE_SERVICE = "set_line_service"
    SET_BATTERY_INJECTION = "set_battery_injection"


class CommandStatus(StrEnum):
    APPLIED = "applied"
    REJECTED = "rejected"
    UNKNOWN_EFFECT = "unknown_effect"


class ClosedLoopStatus(StrEnum):
    NOT_DISPATCHED = "not_dispatched"
    CANDIDATE_REJECTED = "candidate_rejected"
    DEVICE_REJECTED = "device_rejected"
    COMPLETED = "completed"
    UNKNOWN_EFFECT = "unknown_effect"


class PhysicalStateSnapshot(BaseModel):
    """Authoritative, versioned steady-state result returned by the plant model."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["physical-state-v1"] = "physical-state-v1"
    model_id: str = Field(min_length=1)
    simulator_version: str = Field(min_length=1)
    model_digest: str = Field(pattern=SHA256_PATTERN)
    input_digest: str = Field(pattern=SHA256_PATTERN)
    topology_digest: str = Field(pattern=SHA256_PATTERN)
    state_digest: str = Field(pattern=SHA256_PATTERN)
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    observation_sequence: int = Field(ge=0)
    observation_source_id: str = Field(min_length=1)
    observation_clock_domain: str = Field(min_length=1)
    state_version: int = Field(ge=0)
    simulation_time_s: float = Field(ge=0)
    observed_at: datetime
    converged: bool
    total_load_demand_mw: float = Field(ge=0)
    served_load_mw: float = Field(ge=0)
    unserved_load_mw: float = Field(ge=0)
    total_load_served_pct: float = Field(ge=0, le=100)
    priority_load_demand_mw: float = Field(ge=0)
    priority_load_served_mw: float = Field(ge=0)
    priority_load_served_pct: float = Field(ge=0, le=100)
    minimum_voltage_pu: float | None = Field(default=None, gt=0)
    maximum_voltage_pu: float | None = Field(default=None, gt=0)
    maximum_line_loading_pct: float | None = Field(default=None, ge=0)
    voltage_violation_count: int = Field(ge=0)
    thermal_violation_count: int = Field(ge=0)
    unsafe_state: bool
    isolated_resources: tuple[str, ...] = ()
    battery_injection_mw: dict[str, float] = Field(default_factory=dict)
    bus_voltage_pu: tuple[float | None, ...]
    line_loading_pct: tuple[float | None, ...]

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        return value

    @field_validator("simulation_time_s")
    @classmethod
    def require_finite_simulation_time(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("simulation_time_s must be finite")
        return value

    def digest_material(self) -> dict[str, Any]:
        """Physical-value material, excluding the separately bound observation envelope."""

        return self.model_dump(
            mode="json",
            exclude={
                "state_digest",
                "observation_digest",
                "observation_sequence",
                "observation_source_id",
                "observation_clock_domain",
                "observed_at",
            },
        )

    def observation_material(self) -> dict[str, Any]:
        """Bind value integrity to capture time, source, sequence, and clock domain."""

        return {
            "state_digest": self.state_digest,
            "observed_at": self.observed_at.isoformat(),
            "observation_sequence": self.observation_sequence,
            "observation_source_id": self.observation_source_id,
            "observation_clock_domain": self.observation_clock_domain,
        }

    def verify_digest(self) -> bool:
        return self.state_digest == canonical_digest(
            self.digest_material()
        ) and self.observation_digest == canonical_digest(self.observation_material())


class PhysicalControlCommand(BaseModel):
    """Exact actuator command derived by a trusted resource mapping."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["physical-command-v1"] = "physical-command-v1"
    command_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    proposal_id: str = Field(min_length=1)
    operation: Operation
    resource: str = Field(min_length=1)
    command_type: PhysicalCommandType
    target: str = Field(min_length=1)
    target_index: int = Field(ge=0)
    setpoint: float
    unit: Literal["boolean", "MW"]

    @field_validator("setpoint")
    @classmethod
    def require_finite_setpoint(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("setpoint must be finite")
        return value

    @model_validator(mode="after")
    def require_command_shape(self) -> PhysicalControlCommand:
        if self.command_type is PhysicalCommandType.SET_LINE_SERVICE:
            if self.unit != "boolean" or self.setpoint not in {0.0, 1.0}:
                raise ValueError("line-service commands require a boolean 0 or 1 setpoint")
            if self.operation not in {Operation.ISOLATE_ASSET, Operation.RESTORE_ASSET}:
                raise ValueError("line-service command operation is inconsistent")
        elif self.command_type is PhysicalCommandType.SET_BATTERY_INJECTION:
            if self.unit != "MW" or self.operation is not Operation.DISPATCH_BATTERY:
                raise ValueError("battery commands require dispatch_battery in MW")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class CandidateAssessment(BaseModel):
    """Independent candidate power-flow result used before permit issuance."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["candidate-assessment-v1"] = "candidate-assessment-v1"
    assessment_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    command_digest: str = Field(pattern=SHA256_PATTERN)
    pre_state: PhysicalStateSnapshot
    post_state: PhysicalStateSnapshot
    safe: bool
    reasons: tuple[str, ...]

    @model_validator(mode="after")
    def require_consistent_assessment(self) -> CandidateAssessment:
        if self.pre_state.model_digest != self.post_state.model_digest:
            raise ValueError("candidate assessment model digest changed")
        if not self.pre_state.verify_digest() or not self.post_state.verify_digest():
            raise ValueError("candidate assessment contains an invalid state digest")
        if self.post_state.state_version != self.pre_state.state_version + 1:
            raise ValueError("candidate assessment must advance exactly one state version")
        if self.post_state.simulation_time_s <= self.pre_state.simulation_time_s:
            raise ValueError("candidate assessment must advance simulation time")
        if self.post_state.observed_at <= self.pre_state.observed_at:
            raise ValueError("candidate assessment must advance observation time")
        if self.safe and self.reasons:
            raise ValueError("a safe assessment cannot contain failure reasons")
        if not self.safe and not self.reasons:
            raise ValueError("an unsafe assessment requires at least one reason")
        if self.safe == self.post_state.unsafe_state:
            raise ValueError("candidate safety is inconsistent with the post-state")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class ExecutionPermit(BaseModel):
    """Integrity-protected, one-time authorization for one exact control command."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["execution-permit-v1"] = "execution-permit-v1"
    permit_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    permit_nonce: str = Field(default_factory=lambda: str(uuid4()), min_length=16)
    decision_id: str = Field(min_length=1)
    decision_outcome: Literal[DecisionOutcome.PERMIT] = DecisionOutcome.PERMIT
    proposal_id: str = Field(min_length=1)
    proposal_digest: str = Field(pattern=SHA256_PATTERN)
    command: PhysicalControlCommand
    command_digest: str = Field(pattern=SHA256_PATTERN)
    assessment_digest: str = Field(pattern=SHA256_PATTERN)
    state_version: int = Field(ge=0)
    state_digest: str = Field(pattern=SHA256_PATTERN)
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    topology_digest: str = Field(pattern=SHA256_PATTERN)
    model_digest: str = Field(pattern=SHA256_PATTERN)
    expected_post_state_version: int = Field(ge=1)
    expected_post_state_digest: str = Field(pattern=SHA256_PATTERN)
    expected_post_topology_digest: str = Field(pattern=SHA256_PATTERN)
    evidence_record_hash: str = Field(pattern=SHA256_PATTERN)
    policy_version: str = Field(min_length=1)
    safety_version: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    signing_key_id: str = Field(min_length=1)
    signature: str = ""

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("permit timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def require_consistent_binding(self) -> ExecutionPermit:
        if self.expires_at <= self.issued_at:
            raise ValueError("permit expiry must be after issuance")
        if self.command.proposal_id != self.proposal_id:
            raise ValueError("permit command does not match proposal")
        if self.command.digest != self.command_digest:
            raise ValueError("permit command digest is inconsistent")
        if self.expected_post_state_version != self.state_version + 1:
            raise ValueError("permit post-state version must be the next state")
        return self

    def signing_payload(self) -> bytes:
        material = self.model_dump(mode="json", exclude={"signature"})
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return canonical.encode("utf-8")

    def signed(self, private_key: Ed25519PrivateKey) -> ExecutionPermit:
        signature = sign_bytes(private_key, self.signing_payload())
        return self.model_copy(update={"signature": signature})

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )


class CommandAcknowledgment(BaseModel):
    """Integrity-protected virtual-device disposition and simulator readback."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["command-ack-v1"] = "command-ack-v1"
    acknowledgment_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    permit_id: str = Field(min_length=1)
    permit_nonce: str = Field(min_length=16)
    command_id: str = Field(min_length=1)
    command_digest: str = Field(pattern=SHA256_PATTERN)
    assessment_digest: str = Field(pattern=SHA256_PATTERN)
    proposal_id: str = Field(min_length=1)
    decision_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    device_scan: int = Field(ge=1)
    status: CommandStatus
    reason: str = Field(min_length=1)
    acknowledged_at: datetime
    pre_state_digest: str = Field(pattern=SHA256_PATTERN)
    post_state_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    post_state_version: int | None = Field(default=None, ge=0)
    pre_actuator_setpoint: float
    post_actuator_setpoint: float | None = None
    simulation_time_s: float = Field(ge=0)
    signing_key_id: str = Field(min_length=1)
    signature: str = ""

    @field_validator("acknowledged_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("acknowledged_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def require_status_shape(self) -> CommandAcknowledgment:
        if self.status is CommandStatus.APPLIED:
            if (
                self.post_state_digest is None
                or self.post_state_version is None
                or self.post_actuator_setpoint is None
            ):
                raise ValueError("applied acknowledgment requires post-state readback")
        elif self.post_state_digest is not None or self.post_state_version is not None:
            raise ValueError("non-applied acknowledgment cannot assert a post-state")
        if self.status is CommandStatus.REJECTED:
            if self.post_actuator_setpoint != self.pre_actuator_setpoint:
                raise ValueError("rejected acknowledgment must evidence an unchanged actuator")
        elif (
            self.status is CommandStatus.UNKNOWN_EFFECT and self.post_actuator_setpoint is not None
        ):
            raise ValueError("unknown-effect acknowledgment cannot assert actuator effect")
        return self

    def signing_payload(self) -> bytes:
        material = self.model_dump(mode="json", exclude={"signature"})
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return canonical.encode("utf-8")

    def signed(self, private_key: Ed25519PrivateKey) -> CommandAcknowledgment:
        signature = sign_bytes(private_key, self.signing_payload())
        return self.model_copy(update={"signature": signature})

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )

    def verify_for_transaction(
        self,
        public_key: Ed25519PublicKey,
        *,
        permit: ExecutionPermit,
        pre_state: PhysicalStateSnapshot,
        readback_state: PhysicalStateSnapshot,
        expected_device_id: str,
        expected_key_id: str,
    ) -> bool:
        """Verify signature and every transaction identifier available before dispatch."""

        identifiers_match = (
            self.permit_id == permit.permit_id
            and self.permit_nonce == permit.permit_nonce
            and self.command_id == permit.command.command_id
            and self.command_digest == permit.command_digest
            and self.assessment_digest == permit.assessment_digest
            and self.proposal_id == permit.proposal_id
            and self.decision_id == permit.decision_id
            and self.device_id == expected_device_id
            and self.signing_key_id == expected_key_id
        )
        if not identifiers_match or not self.verify(public_key):
            return False
        states_valid = (
            pre_state.verify_digest()
            and readback_state.verify_digest()
            and pre_state.model_digest == readback_state.model_digest == permit.model_digest
        )
        if not states_valid:
            return False
        if self.status is CommandStatus.APPLIED:
            return (
                permit.issued_at <= self.acknowledged_at < permit.expires_at
                and self.simulation_time_s == readback_state.simulation_time_s
                and self.pre_state_digest == pre_state.state_digest == permit.state_digest
                and pre_state.topology_digest == permit.topology_digest
                and pre_state.observation_digest == permit.observation_digest
                and self.post_state_digest == permit.expected_post_state_digest
                and self.post_state_version == permit.expected_post_state_version
                and readback_state.state_digest == self.post_state_digest
                and readback_state.state_version == self.post_state_version
                and readback_state.topology_digest == permit.expected_post_topology_digest
                and self.pre_actuator_setpoint
                == (
                    0.0
                    if permit.command.command_type is PhysicalCommandType.SET_LINE_SERVICE
                    and permit.command.resource in pre_state.isolated_resources
                    else (
                        1.0
                        if permit.command.command_type is PhysicalCommandType.SET_LINE_SERVICE
                        else pre_state.battery_injection_mw.get(permit.command.resource, 0.0)
                    )
                )
                and self.post_actuator_setpoint == permit.command.setpoint
            )
        if self.status is CommandStatus.REJECTED:
            return (
                self.acknowledged_at >= permit.issued_at
                and self.simulation_time_s == readback_state.simulation_time_s
                and self.pre_state_digest == pre_state.state_digest == readback_state.state_digest
                and pre_state.state_version == readback_state.state_version
                and pre_state.topology_digest == readback_state.topology_digest
            )
        return True


class ClosedLoopResult(BaseModel):
    """Complete correlated disposition for one proposed physical action."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["closed-loop-result-v1"] = "closed-loop-result-v1"
    status: ClosedLoopStatus
    reasons: tuple[str, ...]
    proposal: ActionProposal
    pre_state: PhysicalStateSnapshot
    decision: Decision
    command: PhysicalControlCommand | None = None
    assessment: CandidateAssessment | None = None
    permit: ExecutionPermit | None = None
    acknowledgment: CommandAcknowledgment | None = None
    post_state: PhysicalStateSnapshot | None
    last_observed_state: PhysicalStateSnapshot
    execution_evidence_hash: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_terminal_shape(self) -> ClosedLoopResult:
        if self.status is ClosedLoopStatus.COMPLETED:
            if (
                self.acknowledgment is None
                or self.acknowledgment.status is not CommandStatus.APPLIED
            ):
                raise ValueError("completed result requires an applied acknowledgment")
            if self.permit is None or self.assessment is None or self.command is None:
                raise ValueError("completed result requires the complete authorization path")
            if self.post_state is None:
                raise ValueError("completed result requires a verified post-state")
            if self.post_state.state_digest != self.acknowledgment.post_state_digest:
                raise ValueError("completed result readback does not match acknowledgment")
        if self.status is ClosedLoopStatus.UNKNOWN_EFFECT and self.post_state is not None:
            raise ValueError("unknown-effect result cannot assert a verified post-state")
        return self
