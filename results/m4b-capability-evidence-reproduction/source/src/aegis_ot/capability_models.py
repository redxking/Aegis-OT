"""Typed contracts for the capability-separated deterministic-local control slice.

These contracts are additive to the retained M3 v1 contracts.  They describe the
first bounded WP4 increment; they are not HELICS, OpenPLC, physical-device, or
segmented-deployment evidence.
"""

from __future__ import annotations

import json
import math
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .crypto import sign_bytes, verify_bytes
from .models import ActionProposal, Decision
from .physical_models import (
    SHA256_PATTERN,
    CandidateAssessment,
    CommandStatus,
    ExecutionPermit,
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
)


def _canonical_json(value: BaseModel | dict[str, Any]) -> bytes:
    material = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


class CapabilityClosedLoopStatus(StrEnum):
    """Terminal states that preserve certainty about dispatch and physical effect."""

    NOT_DISPATCHED = "not_dispatched"
    CANDIDATE_REJECTED = "candidate_rejected"
    PLC_REJECTED = "plc_rejected"
    COMPLETED = "completed"
    UNKNOWN_EFFECT = "unknown_effect"
    OBSERVATION_DIVERGED = "observation_diverged"


class DispatchPhase(StrEnum):
    """PLC evidence boundary for one and only one dispatch attempt."""

    PRE_DISPATCH = "pre_dispatch"
    KNOWN_NO_EFFECT = "known_no_effect"
    COMMITTED = "committed"
    EFFECT_UNKNOWN = "effect_unknown"


class ObservationPhase(StrEnum):
    PRE_AUTHORIZATION = "pre_authorization"
    POST_DISPATCH = "post_dispatch"


class SignedObservationEnvelope(BaseModel):
    """Observer-signed state artifact with boot, sequence, time, and correlation binding."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["signed-observation-v1"] = "signed-observation-v1"
    observation_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    correlation_id: str = Field(min_length=1)
    phase: ObservationPhase
    challenge_nonce: str = Field(min_length=16, max_length=256)
    observer_id: str = Field(min_length=1)
    observer_key_id: str = Field(min_length=1)
    observer_boot_epoch: str = Field(min_length=16)
    observer_sequence: int = Field(ge=1)
    captured_at: datetime
    logical_time_s: float = Field(ge=0)
    snapshot: PhysicalStateSnapshot
    permit_id: str | None = Field(default=None, min_length=1)
    command_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    plc_acknowledgment_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    previous_envelope_digest: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
        description=(
            "For a post-dispatch observation, the exact pre-authorization envelope "
            "for the same transaction; it is not a continuous global-chain claim."
        ),
    )
    envelope_digest: str = Field(pattern=SHA256_PATTERN)
    signature: str = ""

    @field_validator("captured_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("captured_at must be timezone-aware")
        return value

    @field_validator("logical_time_s")
    @classmethod
    def require_finite_logical_time(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("logical_time_s must be finite")
        return value

    @model_validator(mode="after")
    def require_consistent_envelope(self) -> SignedObservationEnvelope:
        if not self.snapshot.verify_digest():
            raise ValueError("signed observation contains an invalid physical-state digest")
        if self.captured_at != self.snapshot.observed_at:
            raise ValueError("observer capture time must match the physical observation time")
        if self.logical_time_s != self.snapshot.simulation_time_s:
            raise ValueError("observer logical time must match the physical simulation time")
        post_bindings = (
            self.permit_id,
            self.command_digest,
            self.plc_acknowledgment_digest,
        )
        if self.phase is ObservationPhase.PRE_AUTHORIZATION and any(
            value is not None for value in post_bindings
        ):
            raise ValueError("pre-authorization observation cannot assert dispatch bindings")
        if self.phase is ObservationPhase.POST_DISPATCH and any(
            value is None for value in post_bindings
        ):
            raise ValueError("post-dispatch observation requires permit, command, and ACK bindings")
        if (
            self.phase is ObservationPhase.POST_DISPATCH
            and self.previous_envelope_digest is None
        ):
            raise ValueError("post-dispatch observation requires its transaction predecessor")
        if self.envelope_digest != canonical_digest(self.digest_material()):
            raise ValueError("signed observation envelope digest is inconsistent")
        return self

    def digest_material(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"envelope_digest", "signature"})

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @classmethod
    def issue(
        cls,
        *,
        snapshot: PhysicalStateSnapshot,
        correlation_id: str,
        phase: ObservationPhase,
        challenge_nonce: str,
        observer_id: str,
        observer_key_id: str,
        observer_boot_epoch: str,
        observer_sequence: int,
        previous_envelope_digest: str | None,
        permit_id: str | None = None,
        command_digest: str | None = None,
        plc_acknowledgment_digest: str | None = None,
        private_key: Ed25519PrivateKey,
    ) -> SignedObservationEnvelope:
        material: dict[str, Any] = {
            "schema_version": "signed-observation-v1",
            "observation_id": str(uuid4()),
            "correlation_id": correlation_id,
            "phase": phase,
            "challenge_nonce": challenge_nonce,
            "observer_id": observer_id,
            "observer_key_id": observer_key_id,
            "observer_boot_epoch": observer_boot_epoch,
            "observer_sequence": observer_sequence,
            "captured_at": snapshot.observed_at,
            "logical_time_s": snapshot.simulation_time_s,
            "snapshot": snapshot,
            "permit_id": permit_id,
            "command_digest": command_digest,
            "plc_acknowledgment_digest": plc_acknowledgment_digest,
            "previous_envelope_digest": previous_envelope_digest,
        }
        provisional = cls.model_construct(
            **material,
            envelope_digest="0" * 64,
            signature="",
        )
        envelope = cls.model_validate(
            {
                **provisional.model_dump(mode="python"),
                "envelope_digest": canonical_digest(provisional.digest_material()),
            }
        )
        return envelope.model_copy(
            update={"signature": sign_bytes(private_key, envelope.signing_payload())}
        )

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )


class CapabilityActionRequest(BaseModel):
    """An agent proposal plus a reference to observer-held signed state, never a state body."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["capability-action-request-v1"] = "capability-action-request-v1"
    request_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    correlation_id: str = Field(min_length=1)
    proposal: ActionProposal
    observation_id: str = Field(min_length=1)
    observation_envelope_digest: str = Field(pattern=SHA256_PATTERN)
    observation_challenge_nonce: str = Field(min_length=16, max_length=256)

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class CapabilityExecutionPermit(BaseModel):
    """Signed M3 permit extension binding the action request to the signed observation."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["capability-execution-permit-v1"] = (
        "capability-execution-permit-v1"
    )
    base_permit: ExecutionPermit
    request_digest: str = Field(pattern=SHA256_PATTERN)
    observation_id: str = Field(min_length=1)
    observation_envelope_digest: str = Field(pattern=SHA256_PATTERN)
    observer_id: str = Field(min_length=1)
    observer_key_id: str = Field(min_length=1)
    observer_boot_epoch: str = Field(min_length=16)
    target_plc_id: str = Field(min_length=1)
    target_plc_key_id: str = Field(min_length=1)
    target_plc_boot_epoch: str = Field(min_length=16)
    signing_key_id: str = Field(min_length=1)
    signature: str = ""

    @model_validator(mode="after")
    def require_consistent_signer(self) -> CapabilityExecutionPermit:
        if self.signing_key_id != self.base_permit.signing_key_id:
            raise ValueError("capability permit signer does not match the base permit signer")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    def signed(self, private_key: Ed25519PrivateKey) -> CapabilityExecutionPermit:
        return self.model_copy(
            update={"signature": sign_bytes(private_key, self.signing_payload())}
        )

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return (
            self.base_permit.verify(public_key)
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )


class PlcCommandAcknowledgment(BaseModel):
    """PLC-signed disposition with boot epoch and an explicit dispatch certainty phase."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["plc-command-ack-v1"] = "plc-command-ack-v1"
    acknowledgment_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    request_digest: str = Field(pattern=SHA256_PATTERN)
    permit_digest: str = Field(pattern=SHA256_PATTERN)
    observation_envelope_digest: str = Field(pattern=SHA256_PATTERN)
    permit_id: str = Field(min_length=1)
    permit_nonce: str = Field(min_length=16)
    command_id: str = Field(min_length=1)
    command_digest: str = Field(pattern=SHA256_PATTERN)
    assessment_digest: str = Field(pattern=SHA256_PATTERN)
    proposal_id: str = Field(min_length=1)
    decision_id: str = Field(min_length=1)
    plc_id: str = Field(min_length=1)
    plc_key_id: str = Field(min_length=1)
    plc_boot_epoch: str = Field(min_length=16)
    plc_scan: int = Field(ge=1)
    dispatch_attempt: Literal[1] = 1
    status: CommandStatus
    dispatch_phase: DispatchPhase
    reason: str = Field(min_length=1)
    acknowledged_at: datetime
    pre_state: PhysicalStateSnapshot
    pre_state_digest: str = Field(pattern=SHA256_PATTERN)
    pre_state_version: int = Field(ge=0)
    post_state_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    post_state_version: int | None = Field(default=None, ge=0)
    post_topology_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    pre_actuator_setpoint: float
    post_actuator_setpoint: float | None = None
    simulation_time_s: float = Field(ge=0)
    signature: str = ""

    @field_validator("acknowledged_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("acknowledged_at must be timezone-aware")
        return value

    @field_validator("pre_actuator_setpoint", "post_actuator_setpoint")
    @classmethod
    def require_finite_setpoint(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("acknowledgment actuator setpoints must be finite")
        return value

    @model_validator(mode="after")
    def require_status_shape(self) -> PlcCommandAcknowledgment:
        if not self.pre_state.verify_digest():
            raise ValueError("PLC acknowledgment contains an invalid pre-state")
        if (
            self.pre_state_digest != self.pre_state.state_digest
            or self.pre_state_version != self.pre_state.state_version
        ):
            raise ValueError("PLC acknowledgment pre-state fields are inconsistent")
        if self.status is CommandStatus.APPLIED:
            if self.dispatch_phase is not DispatchPhase.COMMITTED:
                raise ValueError("applied acknowledgment must assert the committed phase")
            if (
                self.post_state_digest is None
                or self.post_state_version is None
                or self.post_topology_digest is None
                or self.post_actuator_setpoint is None
            ):
                raise ValueError("applied acknowledgment requires complete post-state evidence")
        elif self.status is CommandStatus.REJECTED:
            if self.dispatch_phase not in {
                DispatchPhase.PRE_DISPATCH,
                DispatchPhase.KNOWN_NO_EFFECT,
            }:
                raise ValueError("rejected acknowledgment must establish a no-effect phase")
            if (
                self.post_state_digest is not None
                or self.post_state_version is not None
                or self.post_topology_digest is not None
            ):
                raise ValueError("rejected acknowledgment cannot assert a post-state")
            if self.post_actuator_setpoint != self.pre_actuator_setpoint:
                raise ValueError("rejected acknowledgment must evidence an unchanged actuator")
        else:
            if self.dispatch_phase is not DispatchPhase.EFFECT_UNKNOWN:
                raise ValueError("unknown effect must assert the effect-unknown phase")
            if (
                self.post_state_digest is not None
                or self.post_state_version is not None
                or self.post_topology_digest is not None
                or self.post_actuator_setpoint is not None
            ):
                raise ValueError("unknown effect cannot assert post-dispatch state")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    def signed(self, private_key: Ed25519PrivateKey) -> PlcCommandAcknowledgment:
        return self.model_copy(
            update={"signature": sign_bytes(private_key, self.signing_payload())}
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self)

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
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        pre_observation: SignedObservationEnvelope,
        expected_plc_id: str,
        expected_plc_key_id: str,
        expected_plc_boot_epoch: str,
    ) -> bool:
        base = permit.base_permit
        replay_rejection = (
            self.status is CommandStatus.REJECTED
            and self.dispatch_phase is DispatchPhase.PRE_DISPATCH
            and self.reason
            in {
                "transaction_replayed",
                "permit_replayed",
                "permit_nonce_replayed",
                "command_replayed",
            }
        )
        identifiers_match = (
            self.request_digest == request.digest == permit.request_digest
            and self.permit_digest == permit.digest
            and self.observation_envelope_digest
            == pre_observation.envelope_digest
            == permit.observation_envelope_digest
            and self.permit_id == base.permit_id
            and self.permit_nonce == base.permit_nonce
            and self.command_id == base.command.command_id
            and self.command_digest == base.command_digest
            and self.assessment_digest == base.assessment_digest
            and self.proposal_id == base.proposal_id == request.proposal.proposal_id
            and self.decision_id == base.decision_id
            and self.plc_id == expected_plc_id
            and self.plc_key_id == expected_plc_key_id
            and self.plc_boot_epoch == expected_plc_boot_epoch
            and permit.target_plc_id == expected_plc_id
        )
        target_instance_matches = (
            permit.target_plc_key_id == expected_plc_key_id
            and permit.target_plc_boot_epoch == expected_plc_boot_epoch
        )
        if (
            not identifiers_match
            or not self.verify(public_key)
            or (not target_instance_matches and not replay_rejection)
        ):
            return False
        pre_state_valid = (
            self.pre_state.verify_digest()
            and self.pre_state_digest == self.pre_state.state_digest
            and self.pre_state_version == self.pre_state.state_version
            and self.pre_actuator_setpoint
            == (
                0.0
                if base.command.command_type is PhysicalCommandType.SET_LINE_SERVICE
                and base.command.resource in self.pre_state.isolated_resources
                else (
                    1.0
                    if base.command.command_type is PhysicalCommandType.SET_LINE_SERVICE
                    else self.pre_state.battery_injection_mw.get(base.command.resource, 0.0)
                )
            )
        )
        if not pre_state_valid:
            return False
        authorized_pre_state_matches = (
            self.pre_state == pre_observation.snapshot
            and self.pre_state_digest
            == pre_observation.snapshot.state_digest
            == base.state_digest
            and self.pre_state_version
            == pre_observation.snapshot.state_version
            == base.state_version
            and self.pre_state.observation_digest
            == pre_observation.snapshot.observation_digest
            == base.observation_digest
            and self.pre_state.topology_digest
            == pre_observation.snapshot.topology_digest
            == base.topology_digest
            and self.pre_state.model_digest
            == pre_observation.snapshot.model_digest
            == base.model_digest
        )
        cas_reasons = {
            "model_digest_changed",
            "topology_digest_changed",
            "precommit_state_version_changed",
            "precommit_state_digest_changed",
            "precommit_observation_changed",
        }
        cas_rejection = (
            self.status is CommandStatus.REJECTED
            and self.dispatch_phase
            in {DispatchPhase.PRE_DISPATCH, DispatchPhase.KNOWN_NO_EFFECT}
            and (
                (
                    self.reason == "model_digest_changed"
                    and self.pre_state.model_digest != base.model_digest
                )
                or (
                    self.reason == "topology_digest_changed"
                    and self.pre_state.model_digest == base.model_digest
                    and self.pre_state.topology_digest != base.topology_digest
                )
                or (
                    self.reason == "precommit_state_version_changed"
                    and self.pre_state.model_digest == base.model_digest
                    and self.pre_state.topology_digest == base.topology_digest
                    and self.pre_state_version != base.state_version
                )
                or (
                    self.reason == "precommit_state_digest_changed"
                    and self.pre_state.model_digest == base.model_digest
                    and self.pre_state.topology_digest == base.topology_digest
                    and self.pre_state_version == base.state_version
                    and self.pre_state_digest != base.state_digest
                )
                or (
                    self.reason == "precommit_observation_changed"
                    and self.pre_state.model_digest == base.model_digest
                    and self.pre_state.topology_digest == base.topology_digest
                    and self.pre_state_version == base.state_version
                    and self.pre_state_digest == base.state_digest
                    and self.pre_state.observation_digest != base.observation_digest
                )
            )
        )
        if self.status is CommandStatus.APPLIED:
            return (
                base.issued_at <= self.acknowledged_at < base.expires_at
                and authorized_pre_state_matches
                and self.post_state_digest == base.expected_post_state_digest
                and self.post_state_version == base.expected_post_state_version
                and self.post_topology_digest == base.expected_post_topology_digest
                and self.post_actuator_setpoint == base.command.setpoint
            )
        if self.status is CommandStatus.REJECTED:
            if self.reason == "permit_not_yet_valid":
                time_valid = self.acknowledged_at < base.issued_at
            elif self.reason in {"permit_expired", "permit_expired_before_dispatch"}:
                time_valid = self.acknowledged_at >= base.expires_at
            elif replay_rejection:
                time_valid = self.acknowledged_at >= base.issued_at
            else:
                time_valid = base.issued_at <= self.acknowledged_at < base.expires_at
            return (
                time_valid
                and (
                    (authorized_pre_state_matches and self.reason not in cas_reasons)
                    or replay_rejection
                    or cas_rejection
                )
                and self.post_actuator_setpoint == self.pre_actuator_setpoint
            )
        return (
            self.status is CommandStatus.UNKNOWN_EFFECT
            and self.dispatch_phase is DispatchPhase.EFFECT_UNKNOWN
            and self.acknowledged_at >= base.issued_at
            and authorized_pre_state_matches
        )


class CapabilityClosedLoopResult(BaseModel):
    """Correlated terminal result retaining separately keyed signed artifacts.

    Model validation enforces terminal structure, correlations, and signature presence;
    the live controller, not this schema, performs cryptographic and evidence-chain checks.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["capability-closed-loop-result-v1"] = (
        "capability-closed-loop-result-v1"
    )
    coordination_backend: Literal["deterministic-local-v1"] = "deterministic-local-v1"
    status: CapabilityClosedLoopStatus
    reasons: tuple[str, ...] = Field(min_length=1)
    request: CapabilityActionRequest
    pre_observation: SignedObservationEnvelope | None = None
    decision: Decision | None = None
    command: PhysicalControlCommand | None = None
    assessment: CandidateAssessment | None = None
    permit: CapabilityExecutionPermit | None = None
    acknowledgment: PlcCommandAcknowledgment | None = None
    post_observation: SignedObservationEnvelope | None = None
    last_observation: SignedObservationEnvelope | None = None
    dispatch_attempts: int = Field(ge=0, le=1)
    automatic_retry_count: Literal[0] = 0
    execution_evidence_hash: str = Field(pattern=SHA256_PATTERN)

    def _post_bindings_match(self) -> bool:
        if (
            self.pre_observation is None
            or self.permit is None
            or self.acknowledgment is None
            or self.post_observation is None
        ):
            return False
        post = self.post_observation
        base = self.permit.base_permit
        return (
            post.phase is ObservationPhase.POST_DISPATCH
            and post.correlation_id == self.request.correlation_id
            and post.permit_id == base.permit_id
            and post.command_digest == base.command_digest
            and post.plc_acknowledgment_digest == self.acknowledgment.digest
            and post.previous_envelope_digest == self.pre_observation.envelope_digest
            and self.permit.observation_envelope_digest
            == self.pre_observation.envelope_digest
        )

    def _post_state_matches_expected(self) -> bool:
        if (
            self.permit is None
            or self.acknowledgment is None
            or self.post_observation is None
        ):
            return False
        snapshot = self.post_observation.snapshot
        base = self.permit.base_permit
        return (
            snapshot.state_digest
            == self.acknowledgment.post_state_digest
            == base.expected_post_state_digest
            and snapshot.state_version
            == self.acknowledgment.post_state_version
            == base.expected_post_state_version
            and snapshot.topology_digest
            == self.acknowledgment.post_topology_digest
            == base.expected_post_topology_digest
        )

    @model_validator(mode="after")
    def require_terminal_shape(self) -> CapabilityClosedLoopResult:
        if self.permit is None and self.dispatch_attempts != 0:
            raise ValueError("a result without a permit cannot report a dispatch attempt")
        if self.dispatch_attempts == 0 and self.acknowledgment is not None:
            raise ValueError("an acknowledgment requires one dispatch attempt")
        if self.status is CapabilityClosedLoopStatus.NOT_DISPATCHED:
            if (
                self.dispatch_attempts != 0
                or self.permit is not None
                or self.acknowledgment is not None
                or self.post_observation is not None
            ):
                raise ValueError("not-dispatched result cannot retain dispatch artifacts")
        if self.status is CapabilityClosedLoopStatus.CANDIDATE_REJECTED:
            if self.post_observation is not None:
                raise ValueError("candidate-rejected result cannot retain a post observation")
            if self.dispatch_attempts == 0 and (
                self.permit is not None or self.acknowledgment is not None
            ):
                raise ValueError("pre-dispatch candidate rejection cannot retain PLC artifacts")
            if self.dispatch_attempts == 1 and (
                self.permit is None
                or self.acknowledgment is None
                or self.acknowledgment.status is not CommandStatus.REJECTED
                or not self.acknowledgment.signature
            ):
                raise ValueError("PLC candidate rejection requires a signed rejected ACK")
        if self.status is CapabilityClosedLoopStatus.COMPLETED:
            if (
                self.pre_observation is None
                or self.decision is None
                or self.command is None
                or self.assessment is None
                or self.permit is None
                or self.acknowledgment is None
                or self.post_observation is None
                or self.dispatch_attempts != 1
            ):
                raise ValueError("completed result requires the complete dual-evidence path")
            if self.acknowledgment.status is not CommandStatus.APPLIED:
                raise ValueError("completed result requires an applied PLC acknowledgment")
            if (
                not self.pre_observation.signature
                or not self.permit.signature
                or not self.acknowledgment.signature
                or not self.post_observation.signature
            ):
                raise ValueError("completed result requires present evidence signatures")
            if not self._post_bindings_match():
                raise ValueError("completed result requires exact post-observation bindings")
            if not self._post_state_matches_expected():
                raise ValueError("completed observer state must match the PLC acknowledgment")
        if self.status is CapabilityClosedLoopStatus.PLC_REJECTED:
            if (
                self.acknowledgment is None
                or self.acknowledgment.status is not CommandStatus.REJECTED
                or self.permit is None
                or self.dispatch_attempts != 1
                or not self.acknowledgment.signature
                or not self.permit.signature
                or self.post_observation is not None
            ):
                raise ValueError("PLC-rejected result requires a signed rejected acknowledgment")
        if self.status is CapabilityClosedLoopStatus.OBSERVATION_DIVERGED:
            if (
                self.pre_observation is None
                or self.permit is None
                or self.acknowledgment is None
                or self.post_observation is None
                or self.dispatch_attempts != 1
                or self.acknowledgment.status is not CommandStatus.APPLIED
            ):
                raise ValueError("observation divergence requires both signed evidence artifacts")
            if (
                not self.pre_observation.signature
                or not self.permit.signature
                or not self.acknowledgment.signature
                or not self.post_observation.signature
            ):
                raise ValueError("observation divergence requires present evidence signatures")
            if not self._post_bindings_match():
                raise ValueError("observation divergence requires exact post-observation bindings")
            if self._post_state_matches_expected():
                raise ValueError("observation divergence requires a signed state contradiction")
        if (
            self.status is CapabilityClosedLoopStatus.UNKNOWN_EFFECT
            and self.post_observation is not None
        ):
            raise ValueError("unknown effect cannot assert a verified post-observation")
        if self.status is CapabilityClosedLoopStatus.UNKNOWN_EFFECT and (
            self.permit is None or self.dispatch_attempts != 1
        ):
            raise ValueError("unknown effect requires one consequential dispatch attempt")
        return self
