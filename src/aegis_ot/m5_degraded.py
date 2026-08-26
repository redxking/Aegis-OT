"""Bounded M5 degraded-operation admission ahead of primary authorization.

This module never authorizes a plant effect.  It decides only whether a request
may enter the existing identity, delegation, policy, safety, replay, permit,
coordination, and evidence path.  A separately signed degraded-mode lease can
therefore preserve narrowly scoped mission work when the management path alone
is lost, but it cannot replace a control that protects consequential execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from fcntl import LOCK_EX, LOCK_UN, flock
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any, Protocol, Self

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
from .models import ActionProposal, Operation

DEGRADED_AUTHORIZATION_DOMAIN = b"aegis-ot:m5:degraded-mode-authorization:v1\x00"
DEGRADED_REVERSAL_DOMAIN = b"aegis-ot:m5:degraded-mode-reversal:v1\x00"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_DEGRADED_CONFIGURATION_BYTES = 1024 * 1024
MAX_DEGRADED_STATE_ENTRIES = 10_000


class DegradedRole(StrEnum):
    """Runtime roles and dependencies covered by the M5 compromise matrix."""

    IDENTITY = "identity"
    POLICY = "policy"
    EVIDENCE = "evidence"
    GATEWAY = "gateway"
    OBSERVER = "observer"
    EVALUATOR = "candidate_evaluator"
    COORDINATION = "coordination"
    MANAGEMENT = "management"
    OT_ADAPTER = "ot_adapter"


class RoleCondition(StrEnum):
    HEALTHY = "healthy"
    UNAVAILABLE = "unavailable"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"
    COMPROMISED = "compromised"


class DegradedBehavior(StrEnum):
    """Named response to a role or communications-path loss."""

    SAFE_STATE = "safe_state"
    HOLD_STATE = "hold_state"
    MISSION_PRESERVING = "mission_preserving"


class DegradedAdmissionOutcome(StrEnum):
    CONTINUE_PRIMARY_ASSURANCE = "continue_primary_assurance"
    SAFE_STATE = "safe_state"
    HOLD_STATE = "hold_state"


class RoleLossPolicy(BaseModel):
    """Static, reviewable behavior for losing one required runtime role."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    behavior: DegradedBehavior
    mission_preserving_eligible: bool
    effect: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def require_consistent_eligibility(self) -> Self:
        if self.mission_preserving_eligible is not (
            self.behavior is DegradedBehavior.MISSION_PRESERVING
        ):
            raise ValueError("role-loss behavior and mission-preserving eligibility disagree")
        return self


ROLE_LOSS_POLICIES: Mapping[DegradedRole, RoleLossPolicy] = MappingProxyType(
    {
        DegradedRole.IDENTITY: RoleLossPolicy(
            behavior=DegradedBehavior.SAFE_STATE,
            mission_preserving_eligible=False,
            effect="Reject new consequential work because actor identity cannot be trusted.",
        ),
        DegradedRole.POLICY: RoleLossPolicy(
            behavior=DegradedBehavior.SAFE_STATE,
            mission_preserving_eligible=False,
            effect="Reject new consequential work because authoritative policy is unavailable.",
        ),
        DegradedRole.EVIDENCE: RoleLossPolicy(
            behavior=DegradedBehavior.HOLD_STATE,
            mission_preserving_eligible=False,
            effect="Hold the last known plant state; no new effect may omit evidence generation.",
        ),
        DegradedRole.GATEWAY: RoleLossPolicy(
            behavior=DegradedBehavior.SAFE_STATE,
            mission_preserving_eligible=False,
            effect="Reject new consequential work because the sole authorization path is lost.",
        ),
        DegradedRole.OBSERVER: RoleLossPolicy(
            behavior=DegradedBehavior.HOLD_STATE,
            mission_preserving_eligible=False,
            effect="Hold the last known state; cached observations do not authorize a new effect.",
        ),
        DegradedRole.EVALUATOR: RoleLossPolicy(
            behavior=DegradedBehavior.HOLD_STATE,
            mission_preserving_eligible=False,
            effect="Hold the last known state; candidate evaluation cannot be bypassed.",
        ),
        DegradedRole.COORDINATION: RoleLossPolicy(
            behavior=DegradedBehavior.HOLD_STATE,
            mission_preserving_eligible=False,
            effect="Hold the last known state until pending effects are durably reconciled.",
        ),
        DegradedRole.MANAGEMENT: RoleLossPolicy(
            behavior=DegradedBehavior.MISSION_PRESERVING,
            mission_preserving_eligible=True,
            effect=(
                "Permit only lease-scoped entry to the unchanged primary assurance path; "
                "management loss grants no execution privilege."
            ),
        ),
        DegradedRole.OT_ADAPTER: RoleLossPolicy(
            behavior=DegradedBehavior.HOLD_STATE,
            mission_preserving_eligible=False,
            effect="Hold the last known state; no direct or alternate plant adapter is allowed.",
        ),
    }
)


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


class DegradedRuntimeSnapshot(BaseModel):
    """Trusted, complete health view for services and their communication paths."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot_id: str = Field(min_length=16, max_length=128)
    captured_at: datetime
    role_conditions: Mapping[DegradedRole, RoleCondition]
    communication_conditions: Mapping[DegradedRole, RoleCondition]
    unresolved_effect: bool = False

    @field_validator("captured_at")
    @classmethod
    def require_capture_time(cls, value: datetime) -> datetime:
        return _timezone_aware(value, label="degraded runtime snapshot time")

    @field_validator("role_conditions", "communication_conditions")
    @classmethod
    def freeze_conditions(
        cls,
        value: Mapping[DegradedRole, RoleCondition],
    ) -> Mapping[DegradedRole, RoleCondition]:
        return MappingProxyType(dict(value))

    @field_serializer("role_conditions", "communication_conditions")
    def serialize_conditions(
        self,
        value: Mapping[DegradedRole, RoleCondition],
    ) -> dict[str, str]:
        return {role.value: value[role].value for role in DegradedRole if role in value}

    @model_validator(mode="after")
    def require_complete_role_views(self) -> Self:
        expected = set(DegradedRole)
        if set(self.role_conditions) != expected:
            raise ValueError("degraded snapshot must cover every runtime role exactly")
        if set(self.communication_conditions) != expected:
            raise ValueError(
                "degraded snapshot must cover every runtime communication path exactly"
            )
        return self

    @property
    def affected_roles(self) -> frozenset[DegradedRole]:
        return frozenset(
            role
            for role in DegradedRole
            if self.role_conditions[role] is not RoleCondition.HEALTHY
            or self.communication_conditions[role] is not RoleCondition.HEALTHY
        )

    @property
    def digest(self) -> str:
        return _sha256(self)


class DegradedModeAuthorization(BaseModel):
    """Separate, signed, time- and action-bounded degraded-mode lease."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="aegis-ot-m5-degraded-mode-authorization-v1",
        pattern=r"^aegis-ot-m5-degraded-mode-authorization-v1$",
    )
    authorization_id: str = Field(min_length=16, max_length=128)
    sequence: int = Field(ge=1)
    authority_id: str = Field(min_length=1, max_length=256)
    mode_name: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    behavior: DegradedBehavior
    affected_roles: frozenset[DegradedRole] = Field(min_length=1)
    allowed_actor_ids: frozenset[str] = Field(min_length=1, max_length=128)
    allowed_mission_ids: frozenset[str] = Field(min_length=1, max_length=32)
    allowed_resources: frozenset[str] = Field(min_length=1, max_length=128)
    allowed_operations: frozenset[Operation] = Field(min_length=1)
    maximum_risk_score: float = Field(ge=0, le=100)
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    recovery_checkpoint_id: str = Field(min_length=16, max_length=128)
    nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_authorization_time(cls, value: datetime) -> datetime:
        return _timezone_aware(value, label="degraded authorization time")

    @field_validator(
        "affected_roles",
        "allowed_actor_ids",
        "allowed_mission_ids",
        "allowed_resources",
    )
    @classmethod
    def freeze_bounded_sets(cls, value: frozenset[Any]) -> frozenset[Any]:
        return frozenset(value)

    @field_serializer(
        "affected_roles",
        "allowed_actor_ids",
        "allowed_mission_ids",
        "allowed_resources",
        "allowed_operations",
    )
    def serialize_bounded_sets(self, value: frozenset[Any]) -> list[str]:
        return sorted(str(item) for item in value)

    @model_validator(mode="after")
    def require_bounded_canonical_lease(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("degraded authorization expiry must follow issuance")
        text_values = (
            self.authorization_id,
            self.authority_id,
            self.mode_name,
            self.recovery_checkpoint_id,
            self.nonce,
            *self.allowed_actor_ids,
            *self.allowed_mission_ids,
            *self.allowed_resources,
        )
        if any(
            not value
            or value != value.strip()
            or any(character.isspace() for character in value)
            for value in text_values
        ):
            raise ValueError("degraded authorization scope contains noncanonical text")
        return self

    def signing_payload(self) -> bytes:
        unsigned = self.model_dump(mode="json", exclude={"signature"})
        return DEGRADED_AUTHORIZATION_DOMAIN + _canonical_bytes(unsigned)

    def signed(self, private_key: Ed25519PrivateKey) -> DegradedModeAuthorization:
        return self.model_copy(
            update={"signature": sign_bytes(private_key, self.signing_payload())}
        )

    @property
    def digest(self) -> str:
        return _sha256(self)


class DegradedAdmissionResult(BaseModel):
    """Observable pre-authorization disposition; never an execution permit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome: DegradedAdmissionOutcome
    reasons: tuple[str, ...] = Field(min_length=1)
    evaluated_at: datetime
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    mode_name: str | None = None
    affected_roles: tuple[DegradedRole, ...]
    recovery_checkpoint_id: str | None = None
    may_enter_primary_assurance: bool
    execution_authorized: bool = False
    observable_event_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("evaluated_at")
    @classmethod
    def require_evaluation_time(cls, value: datetime) -> datetime:
        return _timezone_aware(value, label="degraded admission result time")

    @model_validator(mode="after")
    def require_non_bypass_result(self) -> Self:
        continuation = (
            self.outcome is DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE
        )
        if self.may_enter_primary_assurance is not continuation:
            raise ValueError("degraded outcome and primary-assurance flag disagree")
        if self.execution_authorized:
            raise ValueError("degraded admission cannot authorize execution")
        if len(set(self.reasons)) != len(self.reasons):
            raise ValueError("degraded admission reasons must be unique")
        if tuple(sorted(self.affected_roles, key=str)) != self.affected_roles:
            raise ValueError("affected degraded roles must be sorted")
        return self


class DegradedModeReversal(BaseModel):
    """Pinned-authority direction to revoke one exact degraded-mode lease."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="aegis-ot-m5-degraded-mode-reversal-v1",
        pattern=r"^aegis-ot-m5-degraded-mode-reversal-v1$",
    )
    reversal_id: str = Field(min_length=16, max_length=128)
    sequence: int = Field(ge=1)
    authority_id: str = Field(min_length=1, max_length=256)
    authorization_id: str = Field(min_length=16, max_length=128)
    authorization_sha256: str = Field(pattern=SHA256_PATTERN)
    recovery_checkpoint_id: str = Field(min_length=16, max_length=128)
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,127}$")
    nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    signature: str = ""

    @field_validator("issued_at")
    @classmethod
    def require_reversal_time(cls, value: datetime) -> datetime:
        return _timezone_aware(value, label="degraded reversal time")

    @model_validator(mode="after")
    def require_canonical_reversal(self) -> Self:
        values = (
            self.reversal_id,
            self.authority_id,
            self.authorization_id,
            self.recovery_checkpoint_id,
            self.reason_code,
            self.nonce,
        )
        if any(
            value != value.strip() or any(character.isspace() for character in value)
            for value in values
        ):
            raise ValueError("degraded reversal fields contain noncanonical text")
        return self

    def signing_payload(self) -> bytes:
        unsigned = self.model_dump(mode="json", exclude={"signature"})
        return DEGRADED_REVERSAL_DOMAIN + _canonical_bytes(unsigned)

    def signed(self, private_key: Ed25519PrivateKey) -> DegradedModeReversal:
        return self.model_copy(
            update={"signature": sign_bytes(private_key, self.signing_payload())}
        )

    @property
    def digest(self) -> str:
        return _sha256(self)


class DegradedReversalResult(BaseModel):
    """Observable result of applying a signed lease reversal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    applied: bool
    reasons: tuple[str, ...] = Field(min_length=1)
    evaluated_at: datetime
    authorization_sha256: str = Field(pattern=SHA256_PATTERN)
    reversal_sha256: str = Field(pattern=SHA256_PATTERN)
    observable_event_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("evaluated_at")
    @classmethod
    def require_reversal_evaluation_time(cls, value: datetime) -> datetime:
        return _timezone_aware(value, label="degraded reversal result time")

    @model_validator(mode="after")
    def require_unique_reversal_reasons(self) -> Self:
        if len(set(self.reasons)) != len(self.reasons):
            raise ValueError("degraded reversal reasons must be unique")
        return self


SnapshotSource = Callable[[], DegradedRuntimeSnapshot]
AuthorizationSource = Callable[[], DegradedModeAuthorization | None]


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate degraded configuration key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"forbidden degraded configuration constant: {value}")


def _decode_strict_json(raw: bytes) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("degraded configuration UTF-8 BOM is forbidden")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("degraded configuration is not strict UTF-8 JSON") from exc


def _load_strict_json_file(
    path: Path,
    *,
    missing_is_none: bool,
    private: bool = False,
) -> Any:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if missing_is_none:
            return None
        raise
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("degraded configuration must be a regular file")
        if file_stat.st_nlink != 1 or file_stat.st_uid != os.geteuid():
            raise ValueError("degraded configuration ownership is not trusted")
        mode = stat.S_IMODE(file_stat.st_mode)
        if private and mode != 0o600:
            raise ValueError("trusted degraded configuration mode must be 0600")
        if not private and mode & 0o022:
            raise ValueError("degraded configuration must not be group/other writable")
        if not 1 <= file_stat.st_size <= MAX_DEGRADED_CONFIGURATION_BYTES:
            raise ValueError("degraded configuration is outside the size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_DEGRADED_CONFIGURATION_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) != file_stat.st_size or len(raw) > MAX_DEGRADED_CONFIGURATION_BYTES:
        raise ValueError("degraded configuration changed while it was read")
    return _decode_strict_json(raw)


class FileDegradedSnapshotSource:
    """Reload an atomically replaceable trusted role/path snapshot per request."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def __call__(self) -> DegradedRuntimeSnapshot:
        return DegradedRuntimeSnapshot.model_validate(
            _load_strict_json_file(
                self.path,
                missing_is_none=False,
                private=True,
            )
        )


class FileDegradedAuthorizationSource:
    """Reload a public signed lease; file absence means no active lease."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def __call__(self) -> DegradedModeAuthorization | None:
        material = _load_strict_json_file(self.path, missing_is_none=True)
        if material is None:
            return None
        return DegradedModeAuthorization.model_validate(material)


class DegradedOperationState(BaseModel):
    """Monotonic local state that survives degraded-gate process replacement."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="aegis-ot-m5-degraded-operation-state-v1",
        pattern=r"^aegis-ot-m5-degraded-operation-state-v1$",
    )
    authority_id: str = Field(min_length=1, max_length=256)
    highest_authorization_sequence: int = Field(ge=0)
    active_authorization_sha256: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
    )
    highest_reversal_sequence: int = Field(ge=0)
    accepted_reversal_nonce_sha256: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_DEGRADED_STATE_ENTRIES,
    )
    revoked_authorization_sha256: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_DEGRADED_STATE_ENTRIES,
    )

    @field_validator(
        "accepted_reversal_nonce_sha256",
        "revoked_authorization_sha256",
    )
    @classmethod
    def require_sorted_unique_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(len(item) != 64 or any(c not in "0123456789abcdef" for c in item) for item in value):
            raise ValueError("degraded operation state contains a malformed digest")
        if value != tuple(sorted(set(value))):
            raise ValueError("degraded operation state digests must be sorted and unique")
        return value

    @model_validator(mode="after")
    def require_active_authorization_lineage(self) -> Self:
        if (self.highest_authorization_sequence == 0) != (
            self.active_authorization_sha256 is None
        ):
            raise ValueError("degraded authorization sequence and active digest disagree")
        return self

    @classmethod
    def initial(cls, authority_id: str) -> DegradedOperationState:
        return cls(
            authority_id=authority_id,
            highest_authorization_sequence=0,
            highest_reversal_sequence=0,
        )


StateTransition = Callable[[DegradedOperationState], DegradedOperationState]


class DegradedOperationStateStore(Protocol):
    """Atomic persistence seam for monotonic lease and reversal state."""

    def read(self) -> DegradedOperationState: ...

    def update(self, transition: StateTransition) -> DegradedOperationState: ...


class InMemoryDegradedOperationStateStore:
    """Thread-safe process-local state for models and unit-level adapters."""

    def __init__(self, authority_id: str) -> None:
        self._state = DegradedOperationState.initial(authority_id)
        self._lock = RLock()

    def read(self) -> DegradedOperationState:
        with self._lock:
            return self._state

    def update(self, transition: StateTransition) -> DegradedOperationState:
        with self._lock:
            updated = transition(self._state)
            if not isinstance(updated, DegradedOperationState):
                raise TypeError("degraded state transition returned an invalid value")
            if updated.authority_id != self._state.authority_id:
                raise ValueError("degraded state transition changed the authority")
            self._state = updated
            return updated


class FileDegradedOperationStateStore:
    """Crash-durable, process-serialized state for the configured M5 gate."""

    def __init__(self, path: Path, *, authority_id: str) -> None:
        if not path.is_absolute() or not path.name:
            raise ValueError("degraded state path must be an absolute file path")
        self.path = path
        self.authority_id = authority_id

    def _open_parent(self) -> int:
        parent = self.path.parent
        before = os.lstat(parent)
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise ValueError("degraded state parent must be a non-symlink directory")
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077:
            raise ValueError("degraded state parent must be owned privately by the runtime")
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(parent, flags)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            os.close(descriptor)
            raise ValueError("degraded state parent changed during open")
        return descriptor

    def _open_lock(self, parent_fd: int) -> int:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            f".{self.path.name}.lock",
            flags,
            0o600,
            dir_fd=parent_fd,
        )
        lock_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_nlink != 1
            or lock_stat.st_uid != os.geteuid()
            or stat.S_IMODE(lock_stat.st_mode) != 0o600
        ):
            os.close(descriptor)
            raise ValueError("degraded state lock is not a trusted private file")
        return descriptor

    def _read_locked(self, parent_fd: int) -> DegradedOperationState:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path.name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            return DegradedOperationState.initial(self.authority_id)
        try:
            state_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(state_stat.st_mode)
                or state_stat.st_nlink != 1
                or state_stat.st_uid != os.geteuid()
                or stat.S_IMODE(state_stat.st_mode) != 0o600
            ):
                raise ValueError("degraded state is not a trusted private file")
            if not 1 <= state_stat.st_size <= MAX_DEGRADED_CONFIGURATION_BYTES:
                raise ValueError("degraded state is outside the size limit")
            raw = os.read(descriptor, MAX_DEGRADED_CONFIGURATION_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) != state_stat.st_size:
            raise ValueError("degraded state changed while it was read")
        state = DegradedOperationState.model_validate(_decode_strict_json(raw))
        if state.authority_id != self.authority_id:
            raise ValueError("degraded state belongs to a different authority")
        return state

    def _write_locked(
        self,
        parent_fd: int,
        state: DegradedOperationState,
    ) -> None:
        raw = _canonical_bytes(state) + b"\n"
        if len(raw) > MAX_DEGRADED_CONFIGURATION_BYTES:
            raise ValueError("degraded state exceeds the size limit")
        temporary_name = f".{self.path.name}.{secrets.token_hex(12)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise OSError("degraded state write made no progress")
                written += count
            os.fsync(descriptor)
        except Exception:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(descriptor)
        try:
            os.replace(
                temporary_name,
                self.path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
        except Exception:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise

    def _locked(self, transition: StateTransition | None) -> DegradedOperationState:
        parent_fd = self._open_parent()
        lock_fd = -1
        try:
            lock_fd = self._open_lock(parent_fd)
            flock(lock_fd, LOCK_EX)
            current = self._read_locked(parent_fd)
            if transition is None:
                return current
            updated = transition(current)
            if not isinstance(updated, DegradedOperationState):
                raise TypeError("degraded state transition returned an invalid value")
            if updated.authority_id != self.authority_id:
                raise ValueError("degraded state transition changed the authority")
            self._write_locked(parent_fd, updated)
            return updated
        finally:
            if lock_fd >= 0:
                flock(lock_fd, LOCK_UN)
                os.close(lock_fd)
            os.close(parent_fd)

    def read(self) -> DegradedOperationState:
        return self._locked(None)

    def update(self, transition: StateTransition) -> DegradedOperationState:
        return self._locked(transition)


class DegradedOperationGate:
    """Evaluate a degraded lease before any primary gateway assurance service."""

    version = "m5-degraded-pre-authorization-v1"

    def __init__(
        self,
        *,
        authority_id: str,
        authority_public_key: Ed25519PublicKey,
        snapshot_source: SnapshotSource,
        authorization_source: AuthorizationSource,
        state_store: DegradedOperationStateStore | None = None,
        maximum_snapshot_age: timedelta = timedelta(seconds=5),
        maximum_authorization_lifetime: timedelta = timedelta(minutes=5),
    ) -> None:
        if (
            not authority_id
            or authority_id != authority_id.strip()
            or any(character.isspace() for character in authority_id)
        ):
            raise ValueError("degraded authority ID must contain no whitespace")
        if maximum_snapshot_age < timedelta(0):
            raise ValueError("maximum degraded snapshot age must not be negative")
        if maximum_authorization_lifetime <= timedelta(0):
            raise ValueError("maximum degraded authorization lifetime must be positive")
        self.authority_id = authority_id
        self.authority_public_key = authority_public_key
        self.snapshot_source = snapshot_source
        self.authorization_source = authorization_source
        self.maximum_snapshot_age = maximum_snapshot_age
        self.maximum_authorization_lifetime = maximum_authorization_lifetime
        self.state_store = state_store or InMemoryDegradedOperationStateStore(
            authority_id
        )
        self._lock = RLock()

    def apply_reversal(
        self,
        reversal: DegradedModeReversal,
        authorization: DegradedModeAuthorization,
        *,
        now: datetime | None = None,
    ) -> DegradedReversalResult:
        """Revoke one exact lease; this operation cannot alter plant state."""

        evaluated_at = datetime.now(UTC) if now is None else _timezone_aware(
            now, label="degraded reversal evaluation time"
        )
        reasons: list[str] = []
        if reversal.authority_id != self.authority_id:
            reasons.append("degraded_reversal_authority_mismatch")
        if not reversal.signature or not verify_bytes(
            self.authority_public_key,
            reversal.signing_payload(),
            reversal.signature,
        ):
            reasons.append("degraded_reversal_signature_invalid")
        if (
            authorization.authority_id != self.authority_id
            or not authorization.signature
            or not verify_bytes(
                self.authority_public_key,
                authorization.signing_payload(),
                authorization.signature,
            )
        ):
            reasons.append("degraded_reversal_authorization_invalid")
        if reversal.authorization_id != authorization.authorization_id:
            reasons.append("degraded_reversal_authorization_id_mismatch")
        if reversal.authorization_sha256 != authorization.digest:
            reasons.append("degraded_reversal_authorization_digest_mismatch")
        if reversal.recovery_checkpoint_id != authorization.recovery_checkpoint_id:
            reasons.append("degraded_reversal_checkpoint_mismatch")
        reversal_age = evaluated_at - reversal.issued_at
        if reversal_age < timedelta(0):
            reasons.append("degraded_reversal_from_future")
        elif reversal_age > self.maximum_authorization_lifetime:
            reasons.append("degraded_reversal_stale")

        reversal_nonce_sha256 = hashlib.sha256(reversal.nonce.encode("utf-8")).hexdigest()
        applied = False

        def apply_to_state(state: DegradedOperationState) -> DegradedOperationState:
            nonlocal applied
            if state.authority_id != self.authority_id:
                raise ValueError("degraded state belongs to a different authority")
            if reversal.sequence <= state.highest_reversal_sequence:
                reasons.append("degraded_reversal_sequence_not_monotonic")
            if reversal_nonce_sha256 in state.accepted_reversal_nonce_sha256:
                reasons.append("degraded_reversal_replayed")
            if authorization.digest in state.revoked_authorization_sha256:
                reasons.append("degraded_authorization_already_revoked")
            if reasons:
                return state
            if (
                len(state.accepted_reversal_nonce_sha256)
                >= MAX_DEGRADED_STATE_ENTRIES
                or len(state.revoked_authorization_sha256)
                >= MAX_DEGRADED_STATE_ENTRIES
            ):
                reasons.append("degraded_reversal_state_capacity_exceeded")
                return state
            applied = True
            return DegradedOperationState.model_validate(
                {
                    **state.model_dump(mode="json"),
                    "highest_reversal_sequence": reversal.sequence,
                    "accepted_reversal_nonce_sha256": tuple(
                        sorted(
                            (*state.accepted_reversal_nonce_sha256, reversal_nonce_sha256)
                        )
                    ),
                    "revoked_authorization_sha256": tuple(
                        sorted(
                            (*state.revoked_authorization_sha256, authorization.digest)
                        )
                    ),
                }
            )

        try:
            with self._lock:
                self.state_store.update(apply_to_state)
        except Exception:
            applied = False
            reasons.append("degraded_reversal_state_unavailable")

        final_reasons = (
            ("degraded_authorization_revoked",) if applied else tuple(dict.fromkeys(reasons))
        )
        material: dict[str, Any] = {
            "applied": applied,
            "reasons": list(final_reasons),
            "evaluated_at": evaluated_at.isoformat(),
            "authorization_sha256": authorization.digest,
            "reversal_sha256": reversal.digest,
        }
        return DegradedReversalResult(
            **material,
            observable_event_sha256=_sha256(material),
        )

    @staticmethod
    def _effective_behavior(
        affected_roles: frozenset[DegradedRole],
    ) -> DegradedBehavior:
        behaviors = {ROLE_LOSS_POLICIES[role].behavior for role in affected_roles}
        if DegradedBehavior.SAFE_STATE in behaviors:
            return DegradedBehavior.SAFE_STATE
        if DegradedBehavior.HOLD_STATE in behaviors:
            return DegradedBehavior.HOLD_STATE
        return DegradedBehavior.MISSION_PRESERVING

    @staticmethod
    def _condition_reasons(snapshot: DegradedRuntimeSnapshot) -> list[str]:
        reasons: list[str] = []
        for role in DegradedRole:
            service = snapshot.role_conditions[role]
            communication = snapshot.communication_conditions[role]
            if service is not RoleCondition.HEALTHY:
                reasons.append(f"{role.value}_service_{service.value}")
            if communication is not RoleCondition.HEALTHY:
                reasons.append(f"{role.value}_communication_{communication.value}")
        return reasons

    @staticmethod
    def _result(
        *,
        outcome: DegradedAdmissionOutcome,
        reasons: tuple[str, ...],
        evaluated_at: datetime,
        snapshot_sha256: str,
        authorization: DegradedModeAuthorization | None,
        affected_roles: frozenset[DegradedRole],
        may_enter_primary_assurance: bool,
    ) -> DegradedAdmissionResult:
        material: dict[str, Any] = {
            "outcome": outcome.value,
            "reasons": list(reasons),
            "evaluated_at": evaluated_at.isoformat(),
            "snapshot_sha256": snapshot_sha256,
            "authorization_sha256": (
                authorization.digest if authorization is not None else None
            ),
            "mode_name": authorization.mode_name if authorization is not None else None,
            "affected_roles": sorted(role.value for role in affected_roles),
            "recovery_checkpoint_id": (
                authorization.recovery_checkpoint_id
                if authorization is not None
                else None
            ),
            "may_enter_primary_assurance": may_enter_primary_assurance,
            "execution_authorized": False,
        }
        return DegradedAdmissionResult(
            **material,
            observable_event_sha256=_sha256(material),
        )

    def evaluate(
        self,
        proposal: ActionProposal,
        *,
        now: datetime | None = None,
    ) -> DegradedAdmissionResult:
        evaluated_at = datetime.now(UTC) if now is None else _timezone_aware(
            now, label="degraded admission evaluation time"
        )
        try:
            snapshot = self.snapshot_source()
        except Exception:
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=("degraded_snapshot_unavailable",),
                evaluated_at=evaluated_at,
                snapshot_sha256="0" * 64,
                authorization=None,
                affected_roles=frozenset(),
                may_enter_primary_assurance=False,
            )
        if not isinstance(snapshot, DegradedRuntimeSnapshot):
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=("degraded_snapshot_invalid",),
                evaluated_at=evaluated_at,
                snapshot_sha256="0" * 64,
                authorization=None,
                affected_roles=frozenset(),
                may_enter_primary_assurance=False,
            )

        try:
            authorization = self.authorization_source()
        except Exception:
            authorization = None
            authorization_source_unavailable = True
        else:
            authorization_source_unavailable = False
        if authorization is not None and not isinstance(
            authorization, DegradedModeAuthorization
        ):
            authorization = None
            authorization_source_unavailable = True

        try:
            with self._lock:
                operation_state = self.state_store.read()
        except Exception:
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=("degraded_operation_state_unavailable",),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=authorization,
                affected_roles=snapshot.affected_roles,
                may_enter_primary_assurance=False,
            )
        if (
            not isinstance(operation_state, DegradedOperationState)
            or operation_state.authority_id != self.authority_id
        ):
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=("degraded_operation_state_invalid",),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=authorization,
                affected_roles=snapshot.affected_roles,
                may_enter_primary_assurance=False,
            )
        authorization_revoked = (
            authorization is not None
            and authorization.digest in operation_state.revoked_authorization_sha256
        )

        affected = snapshot.affected_roles
        snapshot_age = evaluated_at - snapshot.captured_at
        freshness_reasons: list[str] = []
        if snapshot_age < timedelta(0):
            freshness_reasons.append("degraded_snapshot_from_future")
        elif snapshot_age > self.maximum_snapshot_age:
            freshness_reasons.append("degraded_snapshot_stale")

        if not affected and not freshness_reasons and not snapshot.unresolved_effect:
            if authorization is not None and not authorization_revoked:
                return self._result(
                    outcome=DegradedAdmissionOutcome.HOLD_STATE,
                    reasons=("degraded_condition_cleared_reversal_required",),
                    evaluated_at=evaluated_at,
                    snapshot_sha256=snapshot.digest,
                    authorization=authorization,
                    affected_roles=frozenset(),
                    may_enter_primary_assurance=False,
                )
            normal_reason = (
                "normal_runtime_dependencies_healthy_after_signed_reversal"
                if authorization_revoked
                else "normal_runtime_dependencies_healthy"
            )
            return self._result(
                outcome=DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE,
                reasons=(normal_reason,),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=None,
                affected_roles=frozenset(),
                may_enter_primary_assurance=True,
            )

        reasons = self._condition_reasons(snapshot)
        reasons.extend(freshness_reasons)
        if snapshot.unresolved_effect:
            reasons.append("outcome_reconciliation_required")
        if authorization_source_unavailable:
            reasons.append("degraded_authorization_source_unavailable")
        if authorization is None:
            reasons.append("degraded_mode_authorization_missing")
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=tuple(dict.fromkeys(reasons)),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=None,
                affected_roles=affected,
                may_enter_primary_assurance=False,
            )

        if authorization_revoked:
            reasons.append("degraded_authorization_revoked")
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=tuple(dict.fromkeys(reasons)),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=authorization,
                affected_roles=affected,
                may_enter_primary_assurance=False,
            )

        expected_behavior = self._effective_behavior(affected) if affected else None
        validation_reasons: list[str] = []
        if authorization.authority_id != self.authority_id:
            validation_reasons.append("degraded_authority_mismatch")
        if not authorization.signature or not verify_bytes(
            self.authority_public_key,
            authorization.signing_payload(),
            authorization.signature,
        ):
            validation_reasons.append("degraded_authority_signature_invalid")
        if not authorization.issued_at <= evaluated_at < authorization.expires_at:
            validation_reasons.append("degraded_authorization_inactive")
        if (
            authorization.expires_at - authorization.issued_at
            > self.maximum_authorization_lifetime
        ):
            validation_reasons.append("degraded_authorization_lifetime_exceeded")
        if authorization.snapshot_sha256 != snapshot.digest:
            validation_reasons.append("degraded_snapshot_evidence_mismatch")
        if authorization.affected_roles != affected:
            validation_reasons.append("degraded_role_scope_mismatch")
        if expected_behavior is None or authorization.behavior is not expected_behavior:
            validation_reasons.append("degraded_behavior_mismatch")
        if snapshot.unresolved_effect:
            validation_reasons.append("degraded_unresolved_effect_blocks_new_work")
        validation_reasons.extend(freshness_reasons)
        if validation_reasons:
            reasons.extend(validation_reasons)
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=tuple(dict.fromkeys(reasons)),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=authorization,
                affected_roles=affected,
                may_enter_primary_assurance=False,
            )

        def accept_authorization(
            state: DegradedOperationState,
        ) -> DegradedOperationState:
            if state.authority_id != self.authority_id:
                raise ValueError("degraded state belongs to a different authority")
            if authorization.digest in state.revoked_authorization_sha256:
                reasons.append("degraded_authorization_revoked")
                return state
            if authorization.digest == state.active_authorization_sha256:
                return state
            if authorization.sequence <= state.highest_authorization_sequence:
                reasons.append("degraded_authorization_sequence_not_monotonic")
                return state
            return DegradedOperationState.model_validate(
                {
                    **state.model_dump(mode="json"),
                    "highest_authorization_sequence": authorization.sequence,
                    "active_authorization_sha256": authorization.digest,
                }
            )

        try:
            with self._lock:
                self.state_store.update(accept_authorization)
        except Exception:
            reasons.append("degraded_operation_state_unavailable")
        if any(
            reason
            in {
                "degraded_authorization_sequence_not_monotonic",
                "degraded_authorization_revoked",
                "degraded_operation_state_unavailable",
            }
            for reason in reasons
        ):
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=tuple(dict.fromkeys(reasons)),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=authorization,
                affected_roles=affected,
                may_enter_primary_assurance=False,
            )

        assert expected_behavior is not None
        if expected_behavior is DegradedBehavior.SAFE_STATE:
            reasons.append("authorized_safe_state")
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=tuple(dict.fromkeys(reasons)),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=authorization,
                affected_roles=affected,
                may_enter_primary_assurance=False,
            )
        if expected_behavior is DegradedBehavior.HOLD_STATE:
            reasons.append("authorized_hold_state")
            return self._result(
                outcome=DegradedAdmissionOutcome.HOLD_STATE,
                reasons=tuple(dict.fromkeys(reasons)),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=authorization,
                affected_roles=affected,
                may_enter_primary_assurance=False,
            )

        scope_reasons: list[str] = []
        if proposal.actor_id not in authorization.allowed_actor_ids:
            scope_reasons.append("degraded_actor_out_of_scope")
        if proposal.mission_id not in authorization.allowed_mission_ids:
            scope_reasons.append("degraded_mission_out_of_scope")
        if proposal.resource not in authorization.allowed_resources:
            scope_reasons.append("degraded_resource_out_of_scope")
        if proposal.operation not in authorization.allowed_operations:
            scope_reasons.append("degraded_operation_out_of_scope")
        if proposal.risk_score > authorization.maximum_risk_score:
            scope_reasons.append("degraded_risk_out_of_scope")
        if scope_reasons:
            reasons.extend(scope_reasons)
            return self._result(
                outcome=DegradedAdmissionOutcome.HOLD_STATE,
                reasons=tuple(dict.fromkeys(reasons)),
                evaluated_at=evaluated_at,
                snapshot_sha256=snapshot.digest,
                authorization=authorization,
                affected_roles=affected,
                may_enter_primary_assurance=False,
            )

        reasons.append("authorized_mission_preserving_entry_to_primary_assurance")
        return self._result(
            outcome=DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE,
            reasons=tuple(dict.fromkeys(reasons)),
            evaluated_at=evaluated_at,
            snapshot_sha256=snapshot.digest,
            authorization=authorization,
            affected_roles=affected,
            may_enter_primary_assurance=True,
        )
