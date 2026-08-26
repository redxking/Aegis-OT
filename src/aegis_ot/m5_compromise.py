"""Fail-closed operate-through-compromise admission and recovery controls.

This M5 module is deliberately a gate in front of the primary Aegis assurance
path.  A successful mission evaluation means only that the request may continue
to identity, delegation, policy, safety, permit, and execution checks.  It is
never an execution permit.

Recovery uses a separate, pinned-authority-signed contract whose operation enum
contains no plant-control operation.  That keeps restoration and quarantine
lifecycle work from becoming an emergency direct-control bypass.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock
from types import MappingProxyType
from typing import Any, Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from .crypto import sign_bytes, verify_bytes

RECOVERY_AUTHORIZATION_DOMAIN = b"aegis-ot:m5:recovery-authorization:v1\x00"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class AssuranceService(StrEnum):
    IDENTITY = "identity"
    POLICY = "policy"
    EVIDENCE = "evidence"
    GATEWAY = "gateway"


class ServiceCondition(StrEnum):
    HEALTHY = "healthy"
    UNAVAILABLE = "unavailable"
    UNTRUSTED = "untrusted"


class TelemetryCondition(StrEnum):
    FRESH = "fresh"
    UNAVAILABLE = "unavailable"
    DELAYED = "delayed"
    REPLAYED = "replayed"
    BIASED = "biased"
    CONTRADICTORY = "contradictory"


class MissionGateOutcome(StrEnum):
    CONTINUE_PRIMARY_ASSURANCE = "continue_primary_assurance"
    DENY = "deny"
    QUARANTINE = "quarantine"


class RecoveryOperation(StrEnum):
    """Administrative recovery steps; intentionally excludes plant control."""

    PUBLISH_REVOCATION = "publish_revocation"
    ROTATE_CREDENTIAL = "rotate_credential"
    RECONCILE_EFFECT = "reconcile_effect"
    RESTORE_ASSURANCE_SERVICE = "restore_assurance_service"
    RELEASE_QUARANTINE = "release_quarantine"


def _canonical_bytes(value: BaseModel | dict[str, Any]) -> bytes:
    material = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        material,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: BaseModel | dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _timezone_aware(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


class CompromiseSnapshot(BaseModel):
    """Trusted local view used to decide whether mission work may continue."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot_id: str = Field(min_length=16, max_length=128)
    captured_at: datetime
    service_conditions: Mapping[AssuranceService, ServiceCondition]
    telemetry_condition: TelemetryCondition
    compromised_principals: frozenset[str] = frozenset()
    revoked_principals: frozenset[str] = frozenset()
    quarantined_principals: frozenset[str] = frozenset()
    unresolved_effect: bool = False

    @field_validator("captured_at")
    @classmethod
    def require_capture_time(cls, value: datetime) -> datetime:
        return _timezone_aware(value, label="compromise snapshot time")

    @field_validator("service_conditions")
    @classmethod
    def freeze_service_conditions(
        cls,
        value: Mapping[AssuranceService, ServiceCondition],
    ) -> Mapping[AssuranceService, ServiceCondition]:
        # Pydantic's frozen models do not recursively freeze dictionaries.  A
        # mutable service map would let evidence change after its digest was
        # authorized, so retain an immutable defensive copy.
        return MappingProxyType(dict(value))

    @field_serializer("service_conditions")
    def serialize_service_conditions(
        self,
        value: Mapping[AssuranceService, ServiceCondition],
    ) -> dict[str, str]:
        return {
            service.value: value[service].value
            for service in AssuranceService
            if service in value
        }

    @field_validator(
        "compromised_principals",
        "revoked_principals",
        "quarantined_principals",
    )
    @classmethod
    def require_canonical_principals(cls, value: frozenset[str]) -> frozenset[str]:
        if any(
            not item
            or item != item.strip()
            or any(char.isspace() for char in item)
            for item in value
        ):
            raise ValueError("compromise principals must be non-empty and contain no whitespace")
        return value

    @field_serializer(
        "compromised_principals",
        "revoked_principals",
        "quarantined_principals",
    )
    def serialize_principals(self, value: frozenset[str]) -> list[str]:
        # Set iteration is hash-seed-dependent.  Sorting keeps the exact
        # evidence digest stable across hosts and interpreter processes.
        return sorted(value)

    @model_validator(mode="after")
    def require_complete_service_view(self) -> Self:
        if set(self.service_conditions) != set(AssuranceService):
            raise ValueError("compromise snapshot must cover every assurance service exactly")
        return self

    @property
    def digest(self) -> str:
        return _sha256(self)


class MissionAdmissionRequest(BaseModel):
    """Principal path for one request, ordered root/supervisor through leaf."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str = Field(min_length=16, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    delegation_principals: tuple[str, ...] = Field(min_length=1, max_length=32)
    requested_at: datetime

    @field_validator("requested_at")
    @classmethod
    def require_request_time(cls, value: datetime) -> datetime:
        return _timezone_aware(value, label="mission request time")

    @model_validator(mode="after")
    def require_closed_principal_path(self) -> Self:
        if self.delegation_principals[-1] != self.actor_id:
            raise ValueError("mission actor must be the delegation path leaf")
        if len(set(self.delegation_principals)) != len(self.delegation_principals):
            raise ValueError("mission delegation path must not repeat a principal")
        if any(
            not item or item != item.strip() or any(char.isspace() for char in item)
            for item in self.delegation_principals
        ):
            raise ValueError("mission delegation principals must contain no whitespace")
        return self


class MissionGateResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome: MissionGateOutcome
    reasons: tuple[str, ...] = Field(min_length=1)
    evaluated_at: datetime
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    may_enter_primary_assurance: bool
    execution_authorized: bool = False

    @model_validator(mode="after")
    def require_non_bypass_result(self) -> Self:
        should_continue = self.outcome is MissionGateOutcome.CONTINUE_PRIMARY_ASSURANCE
        if self.may_enter_primary_assurance is not should_continue:
            raise ValueError("mission gate continuation flag disagrees with its outcome")
        if self.execution_authorized:
            raise ValueError("the M5 compromise gate cannot authorize execution")
        if len(set(self.reasons)) != len(self.reasons):
            raise ValueError("mission gate reasons must be unique")
        return self


def evaluate_mission_admission(
    request: MissionAdmissionRequest,
    snapshot: CompromiseSnapshot,
    *,
    now: datetime | None = None,
    maximum_snapshot_age: timedelta = timedelta(seconds=5),
) -> MissionGateResult:
    """Fail closed while allowing an unrelated healthy branch to continue."""

    evaluated_at = request.requested_at if now is None else _timezone_aware(
        now, label="mission evaluation time"
    )
    if maximum_snapshot_age < timedelta(0):
        raise ValueError("maximum compromise snapshot age must not be negative")
    reasons: list[str] = []
    ancestors = request.delegation_principals[:-1]

    if request.requested_at > evaluated_at:
        reasons.append("mission_request_from_future")
    snapshot_age = evaluated_at - snapshot.captured_at
    if snapshot_age < timedelta(0):
        reasons.append("compromise_snapshot_from_future")
    elif snapshot_age > maximum_snapshot_age:
        reasons.append("compromise_snapshot_stale")

    actor_compromised = request.actor_id in snapshot.compromised_principals
    if actor_compromised:
        reasons.append("actor_compromised")
    if any(item in snapshot.compromised_principals for item in ancestors):
        reasons.append("delegation_ancestor_compromised")
    if request.actor_id in snapshot.revoked_principals:
        reasons.append("actor_revoked")
    if any(item in snapshot.revoked_principals for item in ancestors):
        reasons.append("delegation_ancestor_revoked")
    if request.actor_id in snapshot.quarantined_principals:
        reasons.append("actor_quarantined")
    if any(item in snapshot.quarantined_principals for item in ancestors):
        reasons.append("delegation_ancestor_quarantined")

    for service in AssuranceService:
        condition = snapshot.service_conditions[service]
        if condition is not ServiceCondition.HEALTHY:
            reasons.append(f"{service.value}_{condition.value}")

    if snapshot.telemetry_condition is not TelemetryCondition.FRESH:
        reasons.append(f"telemetry_{snapshot.telemetry_condition.value}")
    if snapshot.unresolved_effect:
        reasons.append("outcome_reconciliation_required")

    if not reasons:
        outcome = MissionGateOutcome.CONTINUE_PRIMARY_ASSURANCE
        reasons.append("continue_to_primary_assurance")
    elif actor_compromised:
        outcome = MissionGateOutcome.QUARANTINE
    else:
        outcome = MissionGateOutcome.DENY
    return MissionGateResult(
        outcome=outcome,
        reasons=tuple(reasons),
        evaluated_at=evaluated_at,
        snapshot_sha256=snapshot.digest,
        may_enter_primary_assurance=(
            outcome is MissionGateOutcome.CONTINUE_PRIMARY_ASSURANCE
        ),
        execution_authorized=False,
    )


class RecoveryAuthorization(BaseModel):
    """One signed, exact-evidence administrative recovery capability."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="aegis-ot-m5-recovery-authorization-v1",
        pattern=r"^aegis-ot-m5-recovery-authorization-v1$",
    )
    authorization_id: str = Field(min_length=16, max_length=128)
    sequence: int = Field(ge=1)
    authority_id: str = Field(min_length=1, max_length=256)
    subject_id: str = Field(min_length=1, max_length=256)
    operation: RecoveryOperation
    target: str = Field(min_length=1, max_length=256)
    evidence_sha256: str = Field(pattern=SHA256_PATTERN)
    reconciliation_complete: bool = False
    nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_authorization_time(cls, value: datetime) -> datetime:
        return _timezone_aware(value, label="recovery authorization time")

    @model_validator(mode="after")
    def require_window_and_identity_text(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("recovery authorization expiry must follow issuance")
        for value in (
            self.authorization_id,
            self.authority_id,
            self.subject_id,
            self.target,
            self.nonce,
        ):
            if value != value.strip() or any(char.isspace() for char in value):
                raise ValueError("recovery authorization identity fields contain whitespace")
        if (
            self.reconciliation_complete
            and self.operation is not RecoveryOperation.RELEASE_QUARANTINE
        ):
            raise ValueError(
                "only a quarantine-release authorization may assert reconciliation"
            )
        return self

    def signing_payload(self) -> bytes:
        unsigned = self.model_dump(mode="json", exclude={"signature"})
        return RECOVERY_AUTHORIZATION_DOMAIN + _canonical_bytes(unsigned)

    def signed(self, private_key: Ed25519PrivateKey) -> RecoveryAuthorization:
        return self.model_copy(
            update={"signature": sign_bytes(private_key, self.signing_payload())}
        )


class RecoveryRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_id: str = Field(min_length=1, max_length=256)
    operation: RecoveryOperation
    target: str = Field(min_length=1, max_length=256)
    evidence_sha256: str = Field(pattern=SHA256_PATTERN)
    reconciliation_complete: bool = False

    @model_validator(mode="after")
    def require_canonical_request(self) -> Self:
        for value in (self.subject_id, self.target):
            if value != value.strip() or any(char.isspace() for char in value):
                raise ValueError("recovery request identity fields contain whitespace")
        if (
            self.reconciliation_complete
            and self.operation is not RecoveryOperation.RELEASE_QUARANTINE
        ):
            raise ValueError("only a quarantine release may assert reconciliation")
        return self


class RecoveryGateResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed: bool
    reasons: tuple[str, ...] = Field(min_length=1)
    evaluated_at: datetime
    authorization_sha256: str = Field(pattern=SHA256_PATTERN)
    plant_control_authorized: bool = False

    @model_validator(mode="after")
    def require_non_control_result(self) -> Self:
        if self.plant_control_authorized:
            raise ValueError("M5 recovery authorization cannot authorize plant control")
        if len(set(self.reasons)) != len(self.reasons):
            raise ValueError("recovery gate reasons must be unique")
        return self


@dataclass
class RecoveryAuthorizationVerifier:
    """Pinned offline authority verifier with monotonic and replay admission."""

    authority_id: str
    authority_public_key: Ed25519PublicKey
    maximum_lifetime_seconds: int = 900
    _highest_sequence: int = field(default=0, init=False, repr=False)
    _accepted_nonces: set[str] = field(default_factory=set, init=False, repr=False)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            not self.authority_id
            or self.authority_id != self.authority_id.strip()
            or any(char.isspace() for char in self.authority_id)
        ):
            raise ValueError("pinned recovery authority ID must contain no whitespace")
        if (
            isinstance(self.maximum_lifetime_seconds, bool)
            or self.maximum_lifetime_seconds <= 0
        ):
            raise ValueError("maximum recovery authorization lifetime must be positive")

    def evaluate(
        self,
        request: RecoveryRequest,
        authorization: RecoveryAuthorization,
        snapshot: CompromiseSnapshot,
        *,
        now: datetime | None = None,
    ) -> RecoveryGateResult:
        evaluated_at = datetime.now(UTC) if now is None else _timezone_aware(
            now, label="recovery evaluation time"
        )
        authorization_digest = _sha256(authorization)
        reasons: list[str] = []
        if (
            authorization.authority_id != self.authority_id
            or not authorization.signature
            or not verify_bytes(
                self.authority_public_key,
                authorization.signing_payload(),
                authorization.signature,
            )
        ):
            reasons.append("recovery_authority_invalid")
        if not authorization.issued_at <= evaluated_at < authorization.expires_at:
            reasons.append("recovery_authorization_inactive")
        lifetime = (authorization.expires_at - authorization.issued_at).total_seconds()
        if lifetime > self.maximum_lifetime_seconds:
            reasons.append("recovery_authorization_lifetime_exceeded")
        if authorization.subject_id != request.subject_id:
            reasons.append("recovery_subject_mismatch")
        if authorization.operation is not request.operation:
            reasons.append("recovery_operation_mismatch")
        if authorization.target != request.target:
            reasons.append("recovery_target_mismatch")
        if authorization.evidence_sha256 != request.evidence_sha256:
            reasons.append("recovery_request_evidence_mismatch")
        if authorization.evidence_sha256 != snapshot.digest:
            reasons.append("recovery_snapshot_evidence_mismatch")
        if authorization.reconciliation_complete is not request.reconciliation_complete:
            reasons.append("recovery_reconciliation_claim_mismatch")

        if request.operation is RecoveryOperation.RELEASE_QUARANTINE:
            if request.target not in snapshot.quarantined_principals:
                reasons.append("recovery_target_not_quarantined")
            if not request.reconciliation_complete or snapshot.unresolved_effect:
                reasons.append("recovery_reconciliation_incomplete")
        elif request.operation is RecoveryOperation.RECONCILE_EFFECT:
            if not snapshot.unresolved_effect:
                reasons.append("recovery_effect_already_resolved")
        elif request.operation is RecoveryOperation.RESTORE_ASSURANCE_SERVICE:
            try:
                service = AssuranceService(request.target)
            except ValueError:
                reasons.append("recovery_service_target_invalid")
            else:
                if snapshot.service_conditions[service] is ServiceCondition.HEALTHY:
                    reasons.append("recovery_service_already_healthy")
        elif request.operation in {
            RecoveryOperation.PUBLISH_REVOCATION,
            RecoveryOperation.ROTATE_CREDENTIAL,
        }:
            affected = (
                snapshot.compromised_principals
                | snapshot.revoked_principals
                | snapshot.quarantined_principals
            )
            if request.target not in affected:
                reasons.append("recovery_identity_target_not_affected")

        with self._lock:
            if authorization.sequence <= self._highest_sequence:
                reasons.append("recovery_authorization_sequence_not_monotonic")
            if authorization.nonce in self._accepted_nonces:
                reasons.append("recovery_authorization_replayed")
            allowed = not reasons
            if allowed:
                self._highest_sequence = authorization.sequence
                self._accepted_nonces.add(authorization.nonce)

        return RecoveryGateResult(
            allowed=allowed,
            reasons=("authorized_recovery_step",) if allowed else tuple(reasons),
            evaluated_at=evaluated_at,
            authorization_sha256=authorization_digest,
            plant_control_authorized=False,
        )
