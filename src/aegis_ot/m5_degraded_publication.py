"""Continuous, signed M5 degraded-operation publication and admission.

This module is a v2 companion to :mod:`aegis_ot.m5_degraded`.  It deliberately
does not change the v1 wire models or campaign.  An offline Ed25519 authority
signs a publisher credential and a stable, bounded degraded authorization.  A
separate online publisher key can then refresh complete runtime-condition
publications without receiving the offline authority key.  The publication can
only admit work within the independently signed authorization; it never grants
plant-effect authority and the existing primary assurance path still applies.

The durable files in this module protect against rollback and equivocation only
while their dedicated local state directories remain intact.  They are not an
external monotonic anchor and do not resist a hostile host or storage rollback.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import errno
import fcntl
import hashlib
import json
import os
import secrets
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, RLock
from types import MappingProxyType
from typing import Any, Final, Generic, Self, TypeVar

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
from .m5_degraded import (
    ROLE_LOSS_POLICIES,
    DegradedAdmissionOutcome,
    DegradedAdmissionResult,
    DegradedBehavior,
    DegradedModeReversal,
    DegradedRole,
    DegradedRuntimeSnapshot,
    RoleCondition,
)
from .models import ActionProposal, Operation

PUBLISHER_CREDENTIAL_DOMAIN: Final[bytes] = b"aegis-ot:m5:degraded-publisher-credential:v1\x00"
STABLE_AUTHORIZATION_DOMAIN: Final[bytes] = b"aegis-ot:m5:stable-degraded-authorization:v1\x00"
RUNTIME_PUBLICATION_DOMAIN: Final[bytes] = b"aegis-ot:m5:degraded-runtime-publication:v1\x00"
PUBLISHER_STATE_INTEGRITY_DOMAIN: Final[bytes] = b"aegis-ot:m5:degraded-publisher-state:v1\x00"
CONSUMER_STATE_INTEGRITY_DOMAIN: Final[bytes] = b"aegis-ot:m5:degraded-consumer-state:v1\x00"

SHA256_PATTERN: Final[str] = r"^[0-9a-f]{64}$"
GIT_OBJECT_PATTERN: Final[str] = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
MAX_CONFIGURATION_BYTES: Final[int] = 1024 * 1024
MAX_STATE_BYTES: Final[int] = 64 * 1024
MAX_STABLE_AUTHORIZATION_SECONDS: Final[int] = 300
MAX_REVERSAL_AGE_SECONDS: Final[int] = 300
MAX_PUBLICATION_AGE_SECONDS: Final[int] = 30
MAX_STATUS_INPUT_AGE_SECONDS: Final[int] = 300


class DegradedPublicationError(RuntimeError):
    """A publication, trust input, or durable state cannot be trusted."""


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_model_file_bytes(value: BaseModel) -> bytes:
    return _canonical_json_bytes(value.model_dump(mode="json")) + b"\n"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _model_digest(value: BaseModel) -> str:
    return _sha256_bytes(_canonical_json_bytes(value.model_dump(mode="json")))


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _canonical_text(value: str, *, label: str, minimum: int = 1) -> str:
    if (
        not minimum <= len(value) <= 256
        or value != value.strip()
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{label} must be bounded canonical text without whitespace")
    return value


def _key_id(public_key: Ed25519PublicKey) -> str:
    return _sha256_bytes(public_key.public_bytes_raw())


def _public_key_base64(public_key: Ed25519PublicKey) -> str:
    return base64.b64encode(public_key.public_bytes_raw()).decode("ascii")


def _public_key_from_base64(value: str) -> Ed25519PublicKey:
    try:
        encoded = value.encode("ascii")
        material = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("publisher public key is not canonical Base64") from exc
    if len(material) != 32 or base64.b64encode(material).decode("ascii") != value:
        raise ValueError("publisher public key must contain 32 canonical raw bytes")
    return Ed25519PublicKey.from_public_bytes(material)


def degraded_role_policy_sha256() -> str:
    """Return the digest of the complete, ordered v1 role-loss policy matrix."""

    material = {
        role.value: ROLE_LOSS_POLICIES[role].model_dump(mode="json") for role in DegradedRole
    }
    return _sha256_bytes(_canonical_json_bytes(material))


def _effective_behavior(affected_roles: frozenset[DegradedRole]) -> DegradedBehavior:
    behaviors = {ROLE_LOSS_POLICIES[role].behavior for role in affected_roles}
    if DegradedBehavior.SAFE_STATE in behaviors:
        return DegradedBehavior.SAFE_STATE
    if DegradedBehavior.HOLD_STATE in behaviors:
        return DegradedBehavior.HOLD_STATE
    return DegradedBehavior.MISSION_PRESERVING


class DegradedPublisherCredential(BaseModel):
    """Offline-root-signed authority for one online health publisher key."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="aegis-ot-m5-degraded-publisher-credential-v2",
        pattern=r"^aegis-ot-m5-degraded-publisher-credential-v2$",
    )
    credential_id: str = Field(min_length=16, max_length=128)
    authority_id: str = Field(min_length=3, max_length=128)
    authority_key_id: str = Field(pattern=SHA256_PATTERN)
    publisher_id: str = Field(min_length=3, max_length=128)
    publisher_key_id: str = Field(pattern=SHA256_PATTERN)
    publisher_public_key_b64: str = Field(min_length=44, max_length=44)
    health_source_id: str = Field(min_length=3, max_length=128)
    source_git_commit: str = Field(pattern=GIT_OBJECT_PATTERN)
    source_fingerprint_sha256: str = Field(pattern=SHA256_PATTERN)
    issued_at: datetime
    expires_at: datetime
    maximum_publication_age_seconds: int = Field(
        ge=1,
        le=MAX_PUBLICATION_AGE_SECONDS,
    )
    maximum_status_input_age_seconds: int = Field(
        ge=1,
        le=MAX_STATUS_INPUT_AGE_SECONDS,
    )
    signature: str = ""

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_times(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="degraded publisher credential time")

    @model_validator(mode="after")
    def require_closed_credential(self) -> Self:
        for label, value in (
            ("credential ID", self.credential_id),
            ("authority ID", self.authority_id),
            ("publisher ID", self.publisher_id),
            ("health source ID", self.health_source_id),
        ):
            _canonical_text(value, label=label, minimum=3 if label != "credential ID" else 16)
        if self.expires_at <= self.issued_at:
            raise ValueError("publisher credential expiry must follow issuance")
        publisher_key = _public_key_from_base64(self.publisher_public_key_b64)
        if self.publisher_key_id != _key_id(publisher_key):
            raise ValueError("publisher credential key ID does not match its public key")
        if self.publisher_key_id == self.authority_key_id:
            raise ValueError("publisher and offline authority keys must be distinct")
        return self

    @property
    def publisher_public_key(self) -> Ed25519PublicKey:
        return _public_key_from_base64(self.publisher_public_key_b64)

    def signing_payload(self) -> bytes:
        return PUBLISHER_CREDENTIAL_DOMAIN + _canonical_json_bytes(
            self.model_dump(mode="json", exclude={"signature"})
        )

    def signed(self, authority_private_key: Ed25519PrivateKey) -> DegradedPublisherCredential:
        return self.model_copy(
            update={"signature": sign_bytes(authority_private_key, self.signing_payload())}
        )

    def verify(self, authority_public_key: Ed25519PublicKey) -> bool:
        return (
            self.authority_key_id == _key_id(authority_public_key)
            and bool(self.signature)
            and verify_bytes(authority_public_key, self.signing_payload(), self.signature)
        )

    @property
    def digest(self) -> str:
        return _model_digest(self)


class StableDegradedAuthorization(BaseModel):
    """Offline-root-signed, publisher-bound authorization stable across refreshes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="aegis-ot-m5-stable-degraded-authorization-v1",
        pattern=r"^aegis-ot-m5-stable-degraded-authorization-v1$",
    )
    authorization_id: str = Field(min_length=16, max_length=128)
    sequence: int = Field(ge=1)
    authority_id: str = Field(min_length=3, max_length=128)
    authority_key_id: str = Field(pattern=SHA256_PATTERN)
    publisher_credential_sha256: str = Field(pattern=SHA256_PATTERN)
    publisher_key_id: str = Field(pattern=SHA256_PATTERN)
    mode_name: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    behavior: DegradedBehavior
    affected_roles: frozenset[DegradedRole] = Field(min_length=1)
    role_conditions: Mapping[DegradedRole, RoleCondition]
    communication_conditions: Mapping[DegradedRole, RoleCondition]
    allowed_actor_ids: frozenset[str] = Field(min_length=1, max_length=128)
    allowed_mission_ids: frozenset[str] = Field(min_length=1, max_length=32)
    allowed_resources: frozenset[str] = Field(min_length=1, max_length=128)
    allowed_operations: frozenset[Operation] = Field(min_length=1)
    maximum_risk_score: float = Field(ge=0, le=100)
    role_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    recovery_checkpoint_id: str = Field(min_length=16, max_length=128)
    nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_times(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="stable degraded authorization time")

    @field_validator("role_conditions", "communication_conditions")
    @classmethod
    def freeze_conditions(
        cls,
        value: Mapping[DegradedRole, RoleCondition],
    ) -> Mapping[DegradedRole, RoleCondition]:
        return MappingProxyType(dict(value))

    @field_validator(
        "affected_roles",
        "allowed_actor_ids",
        "allowed_mission_ids",
        "allowed_resources",
        "allowed_operations",
    )
    @classmethod
    def freeze_sets(cls, value: frozenset[Any]) -> frozenset[Any]:
        return frozenset(value)

    @field_serializer("role_conditions", "communication_conditions")
    def serialize_conditions(
        self,
        value: Mapping[DegradedRole, RoleCondition],
    ) -> dict[str, str]:
        return {role.value: value[role].value for role in DegradedRole if role in value}

    @field_serializer(
        "affected_roles",
        "allowed_actor_ids",
        "allowed_mission_ids",
        "allowed_resources",
        "allowed_operations",
    )
    def serialize_sets(self, value: frozenset[Any]) -> list[str]:
        return sorted(str(item) for item in value)

    @model_validator(mode="after")
    def require_stable_bounded_policy(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("stable authorization expiry must follow issuance")
        if self.expires_at - self.issued_at > timedelta(seconds=MAX_STABLE_AUTHORIZATION_SECONDS):
            raise ValueError("stable authorization lifetime exceeds policy")
        if set(self.role_conditions) != set(DegradedRole) or set(
            self.communication_conditions
        ) != set(DegradedRole):
            raise ValueError("stable authorization must cover every role and path")
        affected = frozenset(
            role
            for role in DegradedRole
            if self.role_conditions[role] is not RoleCondition.HEALTHY
            or self.communication_conditions[role] is not RoleCondition.HEALTHY
        )
        if affected != self.affected_roles:
            raise ValueError("stable authorization affected roles disagree with conditions")
        if self.behavior is not _effective_behavior(affected):
            raise ValueError("stable authorization behavior disagrees with role policy")
        if self.role_policy_sha256 != degraded_role_policy_sha256():
            raise ValueError("stable authorization role policy digest is not current")
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
        for value in text_values:
            _canonical_text(value, label="stable authorization field")
        return self

    def signing_payload(self) -> bytes:
        return STABLE_AUTHORIZATION_DOMAIN + _canonical_json_bytes(
            self.model_dump(mode="json", exclude={"signature"})
        )

    def signed(self, authority_private_key: Ed25519PrivateKey) -> StableDegradedAuthorization:
        return self.model_copy(
            update={"signature": sign_bytes(authority_private_key, self.signing_payload())}
        )

    def verify(self, authority_public_key: Ed25519PublicKey) -> bool:
        return (
            self.authority_key_id == _key_id(authority_public_key)
            and bool(self.signature)
            and verify_bytes(authority_public_key, self.signing_payload(), self.signature)
        )

    @property
    def digest(self) -> str:
        return _model_digest(self)


class DegradedStatusInput(BaseModel):
    """Complete configured condition template sampled by the online publisher.

    This is an operator/integration assertion. Re-reading and signing it does
    not establish automatic health assessment or live compromise detection.
    Its observation time and expiry are part of the input itself, so repeatedly
    reading an abandoned file cannot manufacture fresh evidence.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="aegis-ot-m5-degraded-status-input-v2",
        pattern=r"^aegis-ot-m5-degraded-status-input-v2$",
    )
    status_input_id: str = Field(min_length=16, max_length=128)
    sequence: int = Field(ge=1)
    source_id: str = Field(min_length=3, max_length=128)
    observed_at: datetime
    expires_at: datetime
    role_conditions: Mapping[DegradedRole, RoleCondition]
    communication_conditions: Mapping[DegradedRole, RoleCondition]
    unresolved_effect: bool = False
    operator_asserted_not_detected: bool = True

    @field_validator("observed_at", "expires_at")
    @classmethod
    def require_times(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="degraded status input time")

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
    def require_complete_assertion(self) -> Self:
        _canonical_text(self.status_input_id, label="status input ID", minimum=16)
        _canonical_text(self.source_id, label="status input source ID", minimum=3)
        if set(self.role_conditions) != set(DegradedRole) or set(
            self.communication_conditions
        ) != set(DegradedRole):
            raise ValueError("status input must cover every role and path")
        if self.expires_at <= self.observed_at:
            raise ValueError("status input expiry must follow its observation")
        if not self.operator_asserted_not_detected:
            raise ValueError("status input must preserve its operator-assertion boundary")
        return self

    @property
    def digest(self) -> str:
        return _model_digest(self)


class DegradedRuntimePublication(BaseModel):
    """One complete, atomically replaceable online-publisher-signed health view."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="aegis-ot-m5-degraded-runtime-publication-v1",
        pattern=r"^aegis-ot-m5-degraded-runtime-publication-v1$",
    )
    publication_id: str = Field(min_length=16, max_length=128)
    sequence: int = Field(ge=1)
    previous_publication_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    publisher_credential_sha256: str = Field(pattern=SHA256_PATTERN)
    publisher_key_id: str = Field(pattern=SHA256_PATTERN)
    health_source_id: str = Field(min_length=3, max_length=128)
    status_input_sha256: str = Field(pattern=SHA256_PATTERN)
    published_at: datetime
    expires_at: datetime
    snapshot: DegradedRuntimeSnapshot
    authorization: StableDegradedAuthorization | None = None
    signature: str = ""

    @field_validator("published_at", "expires_at")
    @classmethod
    def require_publication_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="degraded runtime publication time")

    @model_validator(mode="after")
    def require_closed_publication(self) -> Self:
        _canonical_text(self.publication_id, label="publication ID", minimum=16)
        _canonical_text(self.health_source_id, label="health source ID", minimum=3)
        if self.snapshot.captured_at > self.published_at:
            raise ValueError("runtime snapshot cannot be captured after publication")
        if self.expires_at <= self.published_at:
            raise ValueError("runtime publication expiry must follow publication")
        if self.authorization is not None and (
            self.authorization.publisher_credential_sha256 != self.publisher_credential_sha256
            or self.authorization.publisher_key_id != self.publisher_key_id
        ):
            raise ValueError("runtime authorization is bound to another publisher")
        return self

    def signing_payload(self) -> bytes:
        return RUNTIME_PUBLICATION_DOMAIN + _canonical_json_bytes(
            self.model_dump(mode="json", exclude={"signature"})
        )

    def signed(self, publisher_private_key: Ed25519PrivateKey) -> DegradedRuntimePublication:
        return self.model_copy(
            update={"signature": sign_bytes(publisher_private_key, self.signing_payload())}
        )

    def verify(self, publisher_public_key: Ed25519PublicKey) -> bool:
        return (
            self.publisher_key_id == _key_id(publisher_public_key)
            and bool(self.signature)
            and verify_bytes(publisher_public_key, self.signing_payload(), self.signature)
        )

    @property
    def digest(self) -> str:
        return _model_digest(self)


def _state_integrity(domain: bytes, fields: Mapping[str, Any]) -> str:
    return _sha256_bytes(domain + _canonical_json_bytes(dict(fields)))


class DegradedPublisherState(BaseModel):
    """Crash-durable online publication allocation and commit state."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    schema_version: str = Field(
        default="aegis-ot-m5-degraded-publisher-state-v2",
        pattern=r"^aegis-ot-m5-degraded-publisher-state-v2$",
    )
    authority_key_id: str = Field(pattern=SHA256_PATTERN)
    publisher_credential_sha256: str = Field(pattern=SHA256_PATTERN)
    publisher_key_id: str = Field(pattern=SHA256_PATTERN)
    highest_allocated_sequence: int = Field(ge=0)
    latest_published_sequence: int = Field(ge=0)
    latest_publication_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    highest_status_input_sequence: int = Field(ge=0)
    latest_status_input_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    integrity_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_valid_state(self) -> Self:
        if self.latest_published_sequence > self.highest_allocated_sequence:
            raise ValueError("publisher commit cannot exceed its allocation")
        if (self.latest_published_sequence == 0) != (self.latest_publication_sha256 is None):
            raise ValueError("publisher sequence and digest disagree")
        if (self.highest_status_input_sequence == 0) != (
            self.latest_status_input_sha256 is None
        ):
            raise ValueError("status input sequence and digest disagree")
        if self.integrity_sha256 != _state_integrity(
            PUBLISHER_STATE_INTEGRITY_DOMAIN,
            self.integrity_fields(),
        ):
            raise ValueError("publisher state integrity digest is invalid")
        return self

    def integrity_fields(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"integrity_sha256"})

    @classmethod
    def create(
        cls,
        *,
        authority_key_id: str,
        publisher_credential_sha256: str,
        publisher_key_id: str,
        highest_allocated_sequence: int = 0,
        latest_published_sequence: int = 0,
        latest_publication_sha256: str | None = None,
        highest_status_input_sequence: int = 0,
        latest_status_input_sha256: str | None = None,
    ) -> DegradedPublisherState:
        fields: dict[str, Any] = {
            "schema_version": "aegis-ot-m5-degraded-publisher-state-v2",
            "authority_key_id": authority_key_id,
            "publisher_credential_sha256": publisher_credential_sha256,
            "publisher_key_id": publisher_key_id,
            "highest_allocated_sequence": highest_allocated_sequence,
            "latest_published_sequence": latest_published_sequence,
            "latest_publication_sha256": latest_publication_sha256,
            "highest_status_input_sequence": highest_status_input_sequence,
            "latest_status_input_sha256": latest_status_input_sha256,
        }
        return cls(
            **fields,
            integrity_sha256=_state_integrity(PUBLISHER_STATE_INTEGRITY_DOMAIN, fields),
        )


class DegradedConsumerState(BaseModel):
    """Durable publication floor and exact active-authorization/reversal state."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    schema_version: str = Field(
        default="aegis-ot-m5-degraded-consumer-state-v1",
        pattern=r"^aegis-ot-m5-degraded-consumer-state-v1$",
    )
    authority_id: str = Field(min_length=3, max_length=128)
    authority_key_id: str = Field(pattern=SHA256_PATTERN)
    publisher_credential_sha256: str = Field(pattern=SHA256_PATTERN)
    publisher_key_id: str = Field(pattern=SHA256_PATTERN)
    highest_publication_sequence: int = Field(ge=0)
    highest_publication_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    highest_authorization_sequence: int = Field(ge=0)
    active_authorization_id: str | None = Field(default=None, min_length=16, max_length=128)
    active_authorization_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    active_recovery_checkpoint_id: str | None = Field(
        default=None,
        min_length=16,
        max_length=128,
    )
    highest_reversal_sequence: int = Field(ge=0)
    latest_reversal_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    latest_reversed_authorization_sha256: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
    )
    integrity_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_valid_state(self) -> Self:
        if (self.highest_publication_sequence == 0) != (self.highest_publication_sha256 is None):
            raise ValueError("consumer publication sequence and digest disagree")
        active = (
            self.active_authorization_id,
            self.active_authorization_sha256,
            self.active_recovery_checkpoint_id,
        )
        if any(value is None for value in active) != all(value is None for value in active):
            raise ValueError("consumer active authorization fields must be all present or absent")
        reversed_fields = (
            self.latest_reversal_sha256,
            self.latest_reversed_authorization_sha256,
        )
        if (self.highest_reversal_sequence == 0) != all(value is None for value in reversed_fields):
            raise ValueError("consumer reversal sequence and digest fields disagree")
        if self.highest_reversal_sequence > 0 and any(value is None for value in reversed_fields):
            raise ValueError("consumer reversal digest fields are incomplete")
        if self.integrity_sha256 != _state_integrity(
            CONSUMER_STATE_INTEGRITY_DOMAIN,
            self.integrity_fields(),
        ):
            raise ValueError("consumer state integrity digest is invalid")
        return self

    def integrity_fields(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"integrity_sha256"})

    @classmethod
    def create(
        cls,
        *,
        authority_id: str,
        authority_key_id: str,
        publisher_credential_sha256: str,
        publisher_key_id: str,
        highest_publication_sequence: int = 0,
        highest_publication_sha256: str | None = None,
        highest_authorization_sequence: int = 0,
        active_authorization_id: str | None = None,
        active_authorization_sha256: str | None = None,
        active_recovery_checkpoint_id: str | None = None,
        highest_reversal_sequence: int = 0,
        latest_reversal_sha256: str | None = None,
        latest_reversed_authorization_sha256: str | None = None,
    ) -> DegradedConsumerState:
        fields: dict[str, Any] = {
            "schema_version": "aegis-ot-m5-degraded-consumer-state-v1",
            "authority_id": authority_id,
            "authority_key_id": authority_key_id,
            "publisher_credential_sha256": publisher_credential_sha256,
            "publisher_key_id": publisher_key_id,
            "highest_publication_sequence": highest_publication_sequence,
            "highest_publication_sha256": highest_publication_sha256,
            "highest_authorization_sequence": highest_authorization_sequence,
            "active_authorization_id": active_authorization_id,
            "active_authorization_sha256": active_authorization_sha256,
            "active_recovery_checkpoint_id": active_recovery_checkpoint_id,
            "highest_reversal_sequence": highest_reversal_sequence,
            "latest_reversal_sha256": latest_reversal_sha256,
            "latest_reversed_authorization_sha256": (latest_reversed_authorization_sha256),
        }
        return cls(
            **fields,
            integrity_sha256=_state_integrity(CONSUMER_STATE_INTEGRITY_DOMAIN, fields),
        )

    @classmethod
    def evolve(
        cls,
        state: DegradedConsumerState,
        **updates: Any,
    ) -> DegradedConsumerState:
        fields = state.integrity_fields()
        fields.pop("schema_version", None)
        fields.update(updates)
        return cls.create(**fields)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate degraded publication key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite degraded publication constant is forbidden: {value}")


def _strict_json_loads(material: bytes) -> Any:
    if material.startswith(b"\xef\xbb\xbf"):
        raise ValueError("degraded publication UTF-8 BOM is forbidden")
    try:
        return json.loads(
            material.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("degraded publication is not strict UTF-8 JSON") from exc


def _secure_flags() -> tuple[int, int]:
    try:
        return os.O_NOFOLLOW, os.O_CLOEXEC
    except AttributeError as exc:  # pragma: no cover - required deployment platforms
        raise DegradedPublicationError(
            "degraded publication requires no-follow and close-on-exec support"
        ) from exc


def _open_owned_parent(path: Path, *, expected_uid: int) -> int:
    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise DegradedPublicationError("degraded publication path must be absolute")
    try:
        before = os.lstat(path.parent)
    except OSError as exc:
        raise DegradedPublicationError("degraded publication directory is unavailable") from exc
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != expected_uid
        or stat.S_IMODE(before.st_mode) != 0o700
    ):
        raise DegradedPublicationError(
            "degraded publication directory must be an owner-matching 0700 directory"
        )
    nofollow, cloexec = _secure_flags()
    flags = os.O_RDONLY | nofollow | cloexec | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path.parent, flags)
    except OSError as exc:
        raise DegradedPublicationError(
            "degraded publication directory cannot be opened safely"
        ) from exc
    after = os.fstat(descriptor)
    if (
        (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or not stat.S_ISDIR(after.st_mode)
        or after.st_uid != expected_uid
        or stat.S_IMODE(after.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise DegradedPublicationError("degraded publication directory changed during validation")
    return descriptor


def _validate_private_file(
    descriptor: int,
    *,
    expected_uid: int,
    label: str,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise DegradedPublicationError(f"{label} must be an owner-matching single-link 0600 file")
    return metadata


def _read_canonical_file(
    path: Path,
    *,
    expected_uid: int,
    missing_is_none: bool = False,
    maximum_bytes: int = MAX_CONFIGURATION_BYTES,
) -> bytes | None:
    parent_fd = _open_owned_parent(path, expected_uid=expected_uid)
    descriptor = -1
    nofollow, cloexec = _secure_flags()
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | nofollow | cloexec | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            if missing_is_none:
                return None
            raise DegradedPublicationError(
                f"required degraded publication file is missing: {path}"
            ) from None
        before = _validate_private_file(
            descriptor,
            expected_uid=expected_uid,
            label="degraded publication file",
        )
        if not 1 <= before.st_size <= maximum_bytes:
            raise DegradedPublicationError("degraded publication file is outside its size limit")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        material = b"".join(chunks)
        after = _validate_private_file(
            descriptor,
            expected_uid=expected_uid,
            label="degraded publication file",
        )
        if (
            len(material) != before.st_size
            or len(material) > maximum_bytes
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
        ):
            raise DegradedPublicationError("degraded publication file changed while it was read")
        return material
    except OSError as exc:
        raise DegradedPublicationError("degraded publication file cannot be read") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


ModelT = TypeVar("ModelT", bound=BaseModel)


def _load_canonical_model(
    path: Path,
    model: type[ModelT],
    *,
    expected_uid: int,
    missing_is_none: bool = False,
) -> ModelT | None:
    material = _read_canonical_file(
        path,
        expected_uid=expected_uid,
        missing_is_none=missing_is_none,
    )
    if material is None:
        return None
    try:
        value = model.model_validate(_strict_json_loads(material))
    except (TypeError, ValueError) as exc:
        raise DegradedPublicationError("degraded publication model is invalid") from exc
    if material != _canonical_model_file_bytes(value):
        raise DegradedPublicationError("degraded publication encoding is not canonical")
    return value


class FileDegradedPublicationSource:
    """Load one canonical atomic publication owned by the configured publisher UID."""

    def __init__(self, path: Path, *, expected_uid: int | None = None) -> None:
        self.path = path
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid

    def __call__(self) -> DegradedRuntimePublication:
        value = _load_canonical_model(
            self.path,
            DegradedRuntimePublication,
            expected_uid=self.expected_uid,
        )
        assert value is not None
        return value


class FileDegradedStatusSource:
    """Load one complete operator/integration-supplied condition snapshot."""

    def __init__(self, path: Path, *, expected_uid: int | None = None) -> None:
        self.path = path
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid

    def __call__(self) -> DegradedStatusInput:
        value = _load_canonical_model(
            self.path,
            DegradedStatusInput,
            expected_uid=self.expected_uid,
        )
        assert value is not None
        return value


class FileStableDegradedAuthorizationSource:
    """Load one immutable root-signed stable authorization."""

    def __init__(self, path: Path, *, expected_uid: int | None = None) -> None:
        self.path = path
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid

    def __call__(self) -> StableDegradedAuthorization:
        value = _load_canonical_model(
            self.path,
            StableDegradedAuthorization,
            expected_uid=self.expected_uid,
        )
        assert value is not None
        return value


class FileDegradedReversalSource:
    """Load an optional root-signed exact reversal command."""

    def __init__(self, path: Path, *, expected_uid: int | None = None) -> None:
        self.path = path
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid

    def __call__(self) -> DegradedModeReversal | None:
        return _load_canonical_model(
            self.path,
            DegradedModeReversal,
            expected_uid=self.expected_uid,
            missing_is_none=True,
        )


def load_publisher_credential(
    path: Path,
    *,
    expected_uid: int | None = None,
) -> DegradedPublisherCredential:
    value = _load_canonical_model(
        path,
        DegradedPublisherCredential,
        expected_uid=os.geteuid() if expected_uid is None else expected_uid,
    )
    assert value is not None
    return value


def _write_all(descriptor: int, material: bytes) -> None:
    offset = 0
    while offset < len(material):
        count = os.write(descriptor, material[offset:])
        if count <= 0:
            raise OSError("degraded publication write made no progress")
        offset += count


class AtomicDegradedPublicationSink:
    """Fsync and atomically replace one complete publication file."""

    def __init__(self, path: Path, *, expected_uid: int | None = None) -> None:
        self.path = path
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        parent_fd = _open_owned_parent(path, expected_uid=self.expected_uid)
        os.close(parent_fd)

    def current(self) -> DegradedRuntimePublication | None:
        value = _load_canonical_model(
            self.path,
            DegradedRuntimePublication,
            expected_uid=self.expected_uid,
            missing_is_none=True,
        )
        return value

    def publish(self, publication: DegradedRuntimePublication) -> None:
        material = _canonical_model_file_bytes(publication)
        if len(material) > MAX_CONFIGURATION_BYTES:
            raise DegradedPublicationError("degraded publication exceeds its size limit")
        parent_fd = _open_owned_parent(self.path, expected_uid=self.expected_uid)
        temporary_name = f".{self.path.name}.{secrets.token_hex(12)}.tmp"
        descriptor = -1
        replaced = False
        nofollow, cloexec = _secure_flags()
        try:
            try:
                existing_fd = os.open(
                    self.path.name,
                    os.O_RDONLY | nofollow | cloexec,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                existing_fd = -1
            if existing_fd >= 0:
                try:
                    _validate_private_file(
                        existing_fd,
                        expected_uid=self.expected_uid,
                        label="existing degraded publication",
                    )
                finally:
                    os.close(existing_fd)
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
                0o600,
                dir_fd=parent_fd,
            )
            os.fchmod(descriptor, 0o600)
            _validate_private_file(
                descriptor,
                expected_uid=self.expected_uid,
                label="temporary degraded publication",
            )
            _write_all(descriptor, material)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                self.path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            replaced = True
            os.fsync(parent_fd)
        except OSError as exc:
            raise DegradedPublicationError("degraded publication could not be persisted") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=parent_fd)
            os.close(parent_fd)
        if self.current() != publication:
            raise DegradedPublicationError("degraded publication readback disagrees")


StateModelT = TypeVar("StateModelT", bound=BaseModel)
MutationResultT = TypeVar("MutationResultT")


class _DurableStateFile(Generic[StateModelT]):
    """Stable-lock, canonical, fsync-backed storage for one state model."""

    def __init__(
        self,
        path: Path,
        model: type[StateModelT],
        *,
        lock_timeout_seconds: float = 2.0,
    ) -> None:
        if not 0.0 <= lock_timeout_seconds <= 30.0:
            raise DegradedPublicationError("degraded state lock timeout is outside policy")
        self.path = path
        self.model = model
        self.lock_timeout_seconds = lock_timeout_seconds
        self._thread_lock = RLock()
        self._poisoned = False
        parent_fd = _open_owned_parent(path, expected_uid=os.geteuid())
        try:
            if set(os.listdir(parent_fd)) != {path.name, self.lock_name}:
                raise DegradedPublicationError(
                    "degraded state and stable lock must be the only directory entries"
                )
        finally:
            os.close(parent_fd)

    @property
    def lock_name(self) -> str:
        return f".{self.path.name}.lock"

    @classmethod
    def initialize(cls, path: Path, initial: StateModelT) -> None:
        parent_fd = _open_owned_parent(path, expected_uid=os.geteuid())
        lock_name = f".{path.name}.lock"
        lock_fd = -1
        state_created = False
        nofollow, cloexec = _secure_flags()
        try:
            if os.listdir(parent_fd):
                raise DegradedPublicationError(
                    "degraded state initializer requires an empty dedicated directory"
                )
            lock_fd = os.open(
                lock_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
                0o600,
                dir_fd=parent_fd,
            )
            os.fchmod(lock_fd, 0o600)
            _validate_private_file(
                lock_fd,
                expected_uid=os.geteuid(),
                label="degraded state stable lock",
            )
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            material = _canonical_model_file_bytes(initial)
            descriptor = os.open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
                0o600,
                dir_fd=parent_fd,
            )
            try:
                os.fchmod(descriptor, 0o600)
                _write_all(descriptor, material)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            state_created = True
            os.fsync(lock_fd)
            os.fsync(parent_fd)
        except OSError as exc:
            raise DegradedPublicationError("degraded state could not be initialized") from exc
        finally:
            if lock_fd >= 0:
                with suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            if not state_created:
                with suppress(FileNotFoundError):
                    os.unlink(path.name, dir_fd=parent_fd)
                with suppress(FileNotFoundError):
                    os.unlink(lock_name, dir_fd=parent_fd)
                with suppress(OSError):
                    os.fsync(parent_fd)
            os.close(parent_fd)

    def _open_lock(self, parent_fd: int) -> int:
        nofollow, cloexec = _secure_flags()
        try:
            descriptor = os.open(
                self.lock_name,
                os.O_RDWR | nofollow | cloexec,
                dir_fd=parent_fd,
            )
            _validate_private_file(
                descriptor,
                expected_uid=os.geteuid(),
                label="degraded state stable lock",
            )
            return descriptor
        except Exception as exc:
            if "descriptor" in locals():
                os.close(descriptor)
            if isinstance(exc, DegradedPublicationError):
                raise
            raise DegradedPublicationError("degraded state stable lock is unavailable") from exc

    def _acquire(self, descriptor: int) -> None:
        deadline = time.monotonic() + self.lock_timeout_seconds
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise DegradedPublicationError(
                        "degraded state lock cannot be acquired"
                    ) from exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DegradedPublicationError(
                        "degraded state lock acquisition timed out"
                    ) from exc
                time.sleep(min(0.01, remaining))

    def _read_locked(self, parent_fd: int) -> StateModelT:
        nofollow, cloexec = _secure_flags()
        try:
            descriptor = os.open(
                self.path.name,
                os.O_RDONLY | nofollow | cloexec | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            self._poisoned = True
            raise DegradedPublicationError("degraded state is missing or unavailable") from exc
        try:
            before = _validate_private_file(
                descriptor,
                expected_uid=os.geteuid(),
                label="degraded state",
            )
            if not 1 <= before.st_size <= MAX_STATE_BYTES:
                raise DegradedPublicationError("degraded state is outside its size limit")
            material = os.read(descriptor, MAX_STATE_BYTES + 1)
            after = _validate_private_file(
                descriptor,
                expected_uid=os.geteuid(),
                label="degraded state",
            )
        finally:
            os.close(descriptor)
        if (
            len(material) != before.st_size
            or len(material) > MAX_STATE_BYTES
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
        ):
            self._poisoned = True
            raise DegradedPublicationError("degraded state changed while it was read")
        try:
            state = self.model.model_validate(_strict_json_loads(material))
        except (TypeError, ValueError) as exc:
            self._poisoned = True
            raise DegradedPublicationError("degraded state is invalid") from exc
        if material != _canonical_model_file_bytes(state):
            self._poisoned = True
            raise DegradedPublicationError("degraded state encoding is not canonical")
        return state

    def _write_locked(self, parent_fd: int, state: StateModelT) -> None:
        material = _canonical_model_file_bytes(state)
        if len(material) > MAX_STATE_BYTES:
            raise DegradedPublicationError("degraded state exceeds its size limit")
        nofollow, cloexec = _secure_flags()
        temporary_name = f".{self.path.name}.{secrets.token_hex(12)}.tmp"
        descriptor = -1
        replaced = False
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
                0o600,
                dir_fd=parent_fd,
            )
            os.fchmod(descriptor, 0o600)
            _validate_private_file(
                descriptor,
                expected_uid=os.geteuid(),
                label="temporary degraded state",
            )
            _write_all(descriptor, material)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                self.path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            replaced = True
            os.fsync(parent_fd)
            if self._read_locked(parent_fd) != state:
                raise DegradedPublicationError("degraded state readback disagrees")
        except Exception as exc:
            self._poisoned = True
            if isinstance(exc, DegradedPublicationError):
                raise
            raise DegradedPublicationError("degraded state update failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=parent_fd)

    def mutate(
        self,
        transition: Callable[[StateModelT], tuple[StateModelT, MutationResultT]],
    ) -> MutationResultT:
        with self._thread_lock:
            if self._poisoned:
                raise DegradedPublicationError("degraded state instance is poisoned")
            parent_fd = _open_owned_parent(self.path, expected_uid=os.geteuid())
            lock_fd = -1
            acquired = False
            try:
                if set(os.listdir(parent_fd)) != {self.path.name, self.lock_name}:
                    self._poisoned = True
                    raise DegradedPublicationError("degraded state directory layout changed")
                lock_fd = self._open_lock(parent_fd)
                self._acquire(lock_fd)
                acquired = True
                current = self._read_locked(parent_fd)
                updated, result = transition(current)
                if not isinstance(updated, self.model):
                    raise DegradedPublicationError(
                        "degraded state transition returned the wrong model"
                    )
                if updated != current:
                    self._write_locked(parent_fd, updated)
                return result
            finally:
                if acquired:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        self._poisoned = True
                if lock_fd >= 0:
                    os.close(lock_fd)
                os.close(parent_fd)

    def read(self) -> StateModelT:
        return self.mutate(lambda state: (state, state))


class FileDegradedPublisherStateStore:
    """Durable sequence allocator for the online publisher."""

    def __init__(self, path: Path, *, lock_timeout_seconds: float = 2.0) -> None:
        self.path = path
        self._store = _DurableStateFile(
            path,
            DegradedPublisherState,
            lock_timeout_seconds=lock_timeout_seconds,
        )

    @classmethod
    def initialize(
        cls,
        path: Path,
        *,
        credential: DegradedPublisherCredential,
    ) -> None:
        _DurableStateFile.initialize(
            path,
            DegradedPublisherState.create(
                authority_key_id=credential.authority_key_id,
                publisher_credential_sha256=credential.digest,
                publisher_key_id=credential.publisher_key_id,
            ),
        )

    def read(self) -> DegradedPublisherState:
        return self._store.read()

    @staticmethod
    def _reconciled_state(
        state: DegradedPublisherState,
        current_publication: DegradedRuntimePublication | None,
        *,
        credential: DegradedPublisherCredential,
    ) -> DegradedPublisherState:
        if (
            state.authority_key_id != credential.authority_key_id
            or state.publisher_credential_sha256 != credential.digest
            or state.publisher_key_id != credential.publisher_key_id
        ):
            raise DegradedPublicationError("publisher state does not match its credential")
        if current_publication is None:
            if state.latest_published_sequence != 0:
                raise DegradedPublicationError(
                    "published output is missing after a committed publication"
                )
            return state
        if (
            current_publication.publisher_credential_sha256 != credential.digest
            or current_publication.publisher_key_id != credential.publisher_key_id
            or current_publication.health_source_id != credential.health_source_id
            or not current_publication.verify(credential.publisher_public_key)
        ):
            raise DegradedPublicationError("current publisher output is outside configured trust")
        current_digest = current_publication.digest
        if current_publication.sequence == state.latest_published_sequence:
            if current_digest != state.latest_publication_sha256:
                raise DegradedPublicationError(
                    "current publisher output equivocated at its committed sequence"
                )
            return state
        if not (
            state.latest_published_sequence
            < current_publication.sequence
            <= state.highest_allocated_sequence
        ):
            raise DegradedPublicationError(
                "current publisher output is outside durable allocation state"
            )
        if current_publication.previous_publication_sha256 != state.latest_publication_sha256:
            raise DegradedPublicationError(
                "recovered publisher output has an inconsistent predecessor"
            )
        return DegradedPublisherState.create(
            authority_key_id=state.authority_key_id,
            publisher_credential_sha256=state.publisher_credential_sha256,
            publisher_key_id=state.publisher_key_id,
            highest_allocated_sequence=state.highest_allocated_sequence,
            latest_published_sequence=current_publication.sequence,
            latest_publication_sha256=current_digest,
            highest_status_input_sequence=state.highest_status_input_sequence,
            latest_status_input_sha256=state.latest_status_input_sha256,
        )

    def reconcile_current(
        self,
        current_publication: DegradedRuntimePublication | None,
        *,
        credential: DegradedPublisherCredential,
    ) -> DegradedPublisherState:
        """Adopt an exactly allocated publication after a post-publish crash."""

        def transition(
            state: DegradedPublisherState,
        ) -> tuple[DegradedPublisherState, DegradedPublisherState]:
            reconciled = self._reconciled_state(
                state,
                current_publication,
                credential=credential,
            )
            return reconciled, reconciled

        return self._store.mutate(transition)

    def allocate(
        self,
        current_publication: DegradedRuntimePublication | None,
        *,
        credential: DegradedPublisherCredential,
        status_input: DegradedStatusInput,
    ) -> tuple[int, str | None]:
        def transition(
            state: DegradedPublisherState,
        ) -> tuple[DegradedPublisherState, tuple[int, str | None]]:
            reconciled = self._reconciled_state(
                state,
                current_publication,
                credential=credential,
            )
            if status_input.sequence < reconciled.highest_status_input_sequence:
                raise DegradedPublicationError("status input sequence rolled back")
            if (
                status_input.sequence == reconciled.highest_status_input_sequence
                and status_input.digest != reconciled.latest_status_input_sha256
            ):
                raise DegradedPublicationError("status input equivocated at its sequence")
            allocated = reconciled.highest_allocated_sequence + 1
            updated = DegradedPublisherState.create(
                authority_key_id=reconciled.authority_key_id,
                publisher_credential_sha256=reconciled.publisher_credential_sha256,
                publisher_key_id=reconciled.publisher_key_id,
                highest_allocated_sequence=allocated,
                latest_published_sequence=reconciled.latest_published_sequence,
                latest_publication_sha256=reconciled.latest_publication_sha256,
                highest_status_input_sequence=max(
                    reconciled.highest_status_input_sequence,
                    status_input.sequence,
                ),
                latest_status_input_sha256=(
                    status_input.digest
                    if status_input.sequence > reconciled.highest_status_input_sequence
                    else reconciled.latest_status_input_sha256
                ),
            )
            return updated, (allocated, reconciled.latest_publication_sha256)

        return self._store.mutate(transition)

    def commit(
        self,
        publication: DegradedRuntimePublication,
        *,
        credential: DegradedPublisherCredential,
    ) -> DegradedPublisherState:
        def transition(
            state: DegradedPublisherState,
        ) -> tuple[DegradedPublisherState, DegradedPublisherState]:
            if (
                state.authority_key_id != credential.authority_key_id
                or state.publisher_credential_sha256 != credential.digest
                or state.publisher_key_id != credential.publisher_key_id
                or publication.publisher_credential_sha256 != credential.digest
                or publication.publisher_key_id != credential.publisher_key_id
                or publication.health_source_id != credential.health_source_id
                or not publication.verify(credential.publisher_public_key)
            ):
                raise DegradedPublicationError("publisher commit is outside configured trust")
            if publication.sequence == state.latest_published_sequence:
                if publication.digest != state.latest_publication_sha256:
                    raise DegradedPublicationError(
                        "publisher commit equivocated at its committed sequence"
                    )
                return state, state
            if not (
                state.latest_published_sequence
                < publication.sequence
                <= state.highest_allocated_sequence
            ):
                raise DegradedPublicationError("publisher commit sequence was not allocated")
            if publication.previous_publication_sha256 != state.latest_publication_sha256:
                raise DegradedPublicationError("publisher commit predecessor is inconsistent")
            updated = DegradedPublisherState.create(
                authority_key_id=state.authority_key_id,
                publisher_credential_sha256=state.publisher_credential_sha256,
                publisher_key_id=state.publisher_key_id,
                highest_allocated_sequence=state.highest_allocated_sequence,
                latest_published_sequence=publication.sequence,
                latest_publication_sha256=publication.digest,
                highest_status_input_sequence=state.highest_status_input_sequence,
                latest_status_input_sha256=state.latest_status_input_sha256,
            )
            return updated, updated

        return self._store.mutate(transition)


class FileDegradedConsumerStateStore:
    """Durable consumer floor and active lease/reversal state."""

    def __init__(self, path: Path, *, lock_timeout_seconds: float = 2.0) -> None:
        self.path = path
        self._store = _DurableStateFile(
            path,
            DegradedConsumerState,
            lock_timeout_seconds=lock_timeout_seconds,
        )

    @classmethod
    def initialize(
        cls,
        path: Path,
        *,
        credential: DegradedPublisherCredential,
    ) -> None:
        _DurableStateFile.initialize(
            path,
            DegradedConsumerState.create(
                authority_id=credential.authority_id,
                authority_key_id=credential.authority_key_id,
                publisher_credential_sha256=credential.digest,
                publisher_key_id=credential.publisher_key_id,
            ),
        )

    def read(self) -> DegradedConsumerState:
        return self._store.read()

    def mutate(
        self,
        transition: Callable[
            [DegradedConsumerState],
            tuple[DegradedConsumerState, MutationResultT],
        ],
    ) -> MutationResultT:
        return self._store.mutate(transition)


StatusSource = Callable[[], DegradedStatusInput]
StableAuthorizationSource = Callable[[], StableDegradedAuthorization]
PublicationSource = Callable[[], DegradedRuntimePublication]
ReversalSource = Callable[[], DegradedModeReversal | None]


class DegradedPublicationPublisher:
    """Refresh signed atomic publications with only an online publisher key."""

    def __init__(
        self,
        *,
        authority_public_key: Ed25519PublicKey,
        credential: DegradedPublisherCredential,
        publisher_private_key: Ed25519PrivateKey,
        status_source: StatusSource,
        authorization_source: StableAuthorizationSource,
        sink: AtomicDegradedPublicationSink,
        state_store: FileDegradedPublisherStateStore,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not credential.verify(authority_public_key):
            raise DegradedPublicationError("publisher credential signature is invalid")
        if (
            publisher_private_key.public_key().public_bytes_raw()
            != credential.publisher_public_key.public_bytes_raw()
        ):
            raise DegradedPublicationError(
                "publisher private key does not match its root-signed credential"
            )
        self.authority_public_key = authority_public_key
        self.credential = credential
        self.publisher_private_key = publisher_private_key
        self.status_source = status_source
        self.authorization_source = authorization_source
        self.sink = sink
        self.state_store = state_store
        self.clock = clock

    def _trusted_authorization(
        self,
        authorization: StableDegradedAuthorization,
    ) -> StableDegradedAuthorization:
        if (
            not authorization.verify(self.authority_public_key)
            or authorization.authority_id != self.credential.authority_id
            or authorization.publisher_credential_sha256 != self.credential.digest
            or authorization.publisher_key_id != self.credential.publisher_key_id
        ):
            raise DegradedPublicationError("stable authorization is outside publisher trust")
        return authorization

    def publish_once(self) -> DegradedRuntimePublication:
        now = _aware_utc(self.clock(), label="degraded publication clock")
        if not self.credential.issued_at <= now < self.credential.expires_at:
            raise DegradedPublicationError("publisher credential is not currently active")
        status_input = self.status_source()
        if not isinstance(status_input, DegradedStatusInput):
            raise DegradedPublicationError("status source returned an invalid model")
        if status_input.source_id != self.credential.health_source_id:
            raise DegradedPublicationError("status input source is not credentialed")
        maximum_status_age = timedelta(
            seconds=self.credential.maximum_status_input_age_seconds
        )
        if status_input.observed_at > now:
            raise DegradedPublicationError("status input observation is from the future")
        if now - status_input.observed_at > maximum_status_age:
            raise DegradedPublicationError("status input observation is stale")
        if status_input.expires_at - status_input.observed_at > maximum_status_age:
            raise DegradedPublicationError("status input lifetime exceeds its credential")
        if now >= status_input.expires_at:
            raise DegradedPublicationError("status input observation is expired")
        snapshot = DegradedRuntimeSnapshot(
            snapshot_id=f"m5-degraded-snapshot-{secrets.token_hex(16)}",
            captured_at=status_input.observed_at,
            role_conditions=status_input.role_conditions,
            communication_conditions=status_input.communication_conditions,
            unresolved_effect=status_input.unresolved_effect,
        )
        authorization = self.authorization_source()
        if not isinstance(authorization, StableDegradedAuthorization):
            raise DegradedPublicationError("authorization source returned an invalid model")
        authorization = self._trusted_authorization(
            authorization,
        )
        current = self.sink.current()
        sequence, previous_digest = self.state_store.allocate(
            current,
            credential=self.credential,
            status_input=status_input,
        )
        publication = DegradedRuntimePublication(
            publication_id=f"m5-degraded-publication-{secrets.token_hex(16)}",
            sequence=sequence,
            previous_publication_sha256=previous_digest,
            publisher_credential_sha256=self.credential.digest,
            publisher_key_id=self.credential.publisher_key_id,
            health_source_id=self.credential.health_source_id,
            status_input_sha256=status_input.digest,
            published_at=now,
            expires_at=now + timedelta(seconds=self.credential.maximum_publication_age_seconds),
            snapshot=snapshot,
            authorization=authorization,
        ).signed(self.publisher_private_key)
        self.sink.publish(publication)
        self.state_store.commit(publication, credential=self.credential)
        return publication

    def run(
        self,
        *,
        interval_seconds: float = 1.0,
        stop_event: Event | None = None,
    ) -> None:
        if not 0.05 <= interval_seconds < self.credential.maximum_publication_age_seconds:
            raise DegradedPublicationError(
                "publication interval must be shorter than the credential freshness bound"
            )
        stop = stop_event or Event()
        while not stop.is_set():
            self.publish_once()
            stop.wait(interval_seconds)


class PublishedDegradedOperationGate:
    """Consume signed publications before the unchanged primary assurance path."""

    version = "m5-published-degraded-pre-authorization-v1"

    def __init__(
        self,
        *,
        authority_id: str,
        authority_public_key: Ed25519PublicKey,
        publisher_credential: DegradedPublisherCredential,
        stable_authorization: StableDegradedAuthorization,
        publication_source: PublicationSource,
        state_store: FileDegradedConsumerStateStore,
        reversal_source: ReversalSource | None = None,
        maximum_reversal_age: timedelta = timedelta(seconds=MAX_REVERSAL_AGE_SECONDS),
    ) -> None:
        if authority_id != publisher_credential.authority_id:
            raise DegradedPublicationError("publisher credential authority ID is not configured")
        if not publisher_credential.verify(authority_public_key):
            raise DegradedPublicationError("publisher credential signature is invalid")
        if (
            not stable_authorization.verify(authority_public_key)
            or stable_authorization.authority_id != authority_id
            or stable_authorization.authority_key_id != _key_id(authority_public_key)
            or stable_authorization.publisher_credential_sha256 != publisher_credential.digest
            or stable_authorization.publisher_key_id != publisher_credential.publisher_key_id
        ):
            raise DegradedPublicationError(
                "stable authorization is outside configured publisher trust"
            )
        if maximum_reversal_age <= timedelta(0) or maximum_reversal_age > timedelta(
            seconds=MAX_REVERSAL_AGE_SECONDS
        ):
            raise ValueError("maximum degraded reversal age is outside policy")
        self.authority_id = authority_id
        self.authority_public_key = authority_public_key
        self.publisher_credential = publisher_credential
        self.stable_authorization = stable_authorization
        self.publication_source = publication_source
        self.state_store = state_store
        self.reversal_source = reversal_source
        self.maximum_reversal_age = maximum_reversal_age

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
        reasons: Sequence[str],
        evaluated_at: datetime,
        snapshot: DegradedRuntimeSnapshot | None,
        authorization: StableDegradedAuthorization | None,
        affected_roles: frozenset[DegradedRole],
        may_enter_primary_assurance: bool,
    ) -> DegradedAdmissionResult:
        unique_reasons = tuple(dict.fromkeys(reasons))
        snapshot_sha256 = snapshot.digest if snapshot is not None else "0" * 64
        material: dict[str, Any] = {
            "outcome": outcome.value,
            "reasons": list(unique_reasons),
            "evaluated_at": evaluated_at.isoformat(),
            "snapshot_sha256": snapshot_sha256,
            "authorization_sha256": (authorization.digest if authorization is not None else None),
            "mode_name": authorization.mode_name if authorization is not None else None,
            "affected_roles": sorted(role.value for role in affected_roles),
            "recovery_checkpoint_id": (
                authorization.recovery_checkpoint_id if authorization is not None else None
            ),
            "may_enter_primary_assurance": may_enter_primary_assurance,
            "execution_authorized": False,
        }
        return DegradedAdmissionResult(
            **material,
            observable_event_sha256=_sha256_bytes(_canonical_json_bytes(material)),
        )

    def _publication_reasons(
        self,
        publication: DegradedRuntimePublication,
        *,
        evaluated_at: datetime,
    ) -> list[str]:
        credential = self.publisher_credential
        reasons: list[str] = []
        if not credential.issued_at <= evaluated_at < credential.expires_at:
            reasons.append("degraded_publisher_credential_inactive")
        if (
            publication.publisher_credential_sha256 != credential.digest
            or publication.publisher_key_id != credential.publisher_key_id
            or publication.health_source_id != credential.health_source_id
        ):
            reasons.append("degraded_publication_publisher_mismatch")
        if (
            publication.authorization is None
            or publication.authorization.digest != self.stable_authorization.digest
        ):
            reasons.append("degraded_publication_authorization_mismatch")
        if not publication.verify(credential.publisher_public_key):
            reasons.append("degraded_publication_signature_invalid")
        publication_age = evaluated_at - publication.published_at
        snapshot_age = evaluated_at - publication.snapshot.captured_at
        maximum_age = timedelta(seconds=credential.maximum_publication_age_seconds)
        maximum_status_age = timedelta(seconds=credential.maximum_status_input_age_seconds)
        if publication_age < timedelta(0):
            reasons.append("degraded_publication_from_future")
        elif publication_age > maximum_age:
            reasons.append("degraded_publication_stale")
        if publication.expires_at - publication.published_at > maximum_age:
            reasons.append("degraded_publication_lifetime_exceeded")
        if evaluated_at >= publication.expires_at:
            reasons.append("degraded_publication_expired")
        if snapshot_age < timedelta(0):
            reasons.append("degraded_snapshot_from_future")
        elif snapshot_age > maximum_status_age:
            reasons.append("degraded_snapshot_stale")
        return reasons

    def _authorization_reasons(
        self,
        authorization: StableDegradedAuthorization,
        publication: DegradedRuntimePublication,
        *,
        evaluated_at: datetime,
    ) -> list[str]:
        reasons: list[str] = []
        if (
            authorization.authority_id != self.authority_id
            or authorization.authority_key_id != _key_id(self.authority_public_key)
        ):
            reasons.append("degraded_authority_mismatch")
        if not authorization.verify(self.authority_public_key):
            reasons.append("degraded_authority_signature_invalid")
        if (
            authorization.publisher_credential_sha256 != self.publisher_credential.digest
            or authorization.publisher_key_id != self.publisher_credential.publisher_key_id
        ):
            reasons.append("degraded_authorization_publisher_mismatch")
        if not authorization.issued_at <= evaluated_at < authorization.expires_at:
            reasons.append("degraded_authorization_inactive")
        if dict(publication.snapshot.role_conditions) != dict(
            authorization.role_conditions
        ) or dict(publication.snapshot.communication_conditions) != dict(
            authorization.communication_conditions
        ):
            reasons.append("degraded_condition_authorization_mismatch")
        if publication.snapshot.unresolved_effect:
            reasons.append("degraded_unresolved_effect_blocks_new_work")
        return reasons

    def _consumer_state_reasons(
        self,
        state: DegradedConsumerState,
        publication: DegradedRuntimePublication,
    ) -> list[str]:
        reasons: list[str] = []
        if (
            state.authority_id != self.authority_id
            or state.authority_key_id != _key_id(self.authority_public_key)
            or state.publisher_credential_sha256 != self.publisher_credential.digest
            or state.publisher_key_id != self.publisher_credential.publisher_key_id
        ):
            reasons.append("degraded_consumer_state_trust_mismatch")
            return reasons
        if publication.sequence < state.highest_publication_sequence:
            reasons.append("degraded_publication_sequence_rollback")
        elif publication.sequence == state.highest_publication_sequence:
            if publication.digest != state.highest_publication_sha256:
                reasons.append("degraded_publication_sequence_equivocation")
        elif (
            publication.sequence == state.highest_publication_sequence + 1
            and state.highest_publication_sequence > 0
            and publication.previous_publication_sha256 != state.highest_publication_sha256
        ):
            reasons.append("degraded_publication_predecessor_mismatch")
        return reasons

    def _apply_reversal(
        self,
        state: DegradedConsumerState,
        reversal: DegradedModeReversal | None,
        *,
        evaluated_at: datetime,
    ) -> tuple[DegradedConsumerState, list[str], bool]:
        if reversal is None:
            return state, [], False
        if (
            state.latest_reversal_sha256 == reversal.digest
            and state.latest_reversed_authorization_sha256 == reversal.authorization_sha256
        ):
            return state, [], True
        reasons: list[str] = []
        if reversal.authority_id != self.authority_id:
            reasons.append("degraded_reversal_authority_mismatch")
        if not reversal.signature or not verify_bytes(
            self.authority_public_key,
            reversal.signing_payload(),
            reversal.signature,
        ):
            reasons.append("degraded_reversal_signature_invalid")
        reversal_age = evaluated_at - reversal.issued_at
        if reversal_age < timedelta(0):
            reasons.append("degraded_reversal_from_future")
        elif reversal_age > self.maximum_reversal_age:
            reasons.append("degraded_reversal_stale")
        if reversal.sequence <= state.highest_reversal_sequence:
            reasons.append("degraded_reversal_sequence_not_monotonic")
        if state.active_authorization_sha256 is None:
            reasons.append("degraded_reversal_no_active_authorization")
        else:
            if reversal.authorization_id != state.active_authorization_id:
                reasons.append("degraded_reversal_authorization_id_mismatch")
            if reversal.authorization_sha256 != state.active_authorization_sha256:
                reasons.append("degraded_reversal_authorization_digest_mismatch")
            if reversal.recovery_checkpoint_id != state.active_recovery_checkpoint_id:
                reasons.append("degraded_reversal_checkpoint_mismatch")
        if reasons:
            return state, reasons, False
        updated = DegradedConsumerState.evolve(
            state,
            active_authorization_id=None,
            active_authorization_sha256=None,
            active_recovery_checkpoint_id=None,
            highest_reversal_sequence=reversal.sequence,
            latest_reversal_sha256=reversal.digest,
            latest_reversed_authorization_sha256=reversal.authorization_sha256,
        )
        return updated, [], True

    def readiness(self, *, now: datetime | None = None) -> dict[str, Any]:
        """Consume and revalidate current immutable trust, source, and state.

        A readiness check is a real consumer: it advances a valid publication
        floor, records a valid active authorization, and durably applies an
        exact reversal.  A consumer may miss publisher refreshes, so a direct
        predecessor is required only for the next contiguous sequence.  Gaps
        advance the floor based on the current root-credentialed publisher
        signature; lower sequences and same-sequence equivocation still fail.
        """

        evaluated_at = _aware_utc(
            datetime.now(UTC) if now is None else now,
            label="published degraded readiness time",
        )
        try:
            publication = self.publication_source()
        except Exception as exc:
            raise DegradedPublicationError(
                "degraded publication readiness source is unavailable"
            ) from exc
        if not isinstance(publication, DegradedRuntimePublication):
            raise DegradedPublicationError(
                "degraded publication readiness source returned an invalid model"
            )
        reasons = self._publication_reasons(
            publication,
            evaluated_at=evaluated_at,
        )
        if not self.publisher_credential.verify(self.authority_public_key):
            reasons.append("degraded_publisher_credential_signature_invalid")
        if not self.stable_authorization.verify(self.authority_public_key):
            reasons.append("degraded_authority_signature_invalid")
        try:
            reversal = self.reversal_source() if self.reversal_source is not None else None
        except Exception as exc:
            raise DegradedPublicationError(
                "degraded publication reversal source is unavailable"
            ) from exc
        if reversal is not None and not isinstance(reversal, DegradedModeReversal):
            raise DegradedPublicationError(
                "degraded publication reversal source returned an invalid model"
            )
        authorization = publication.authorization
        authorization_active = False
        if authorization is not None:
            authorization_active = (
                authorization.issued_at <= evaluated_at < authorization.expires_at
            )
        if reasons:
            unique = ",".join(dict.fromkeys(reasons))
            raise DegradedPublicationError(f"degraded publication gate is not ready: {unique}")

        def transition(
            state: DegradedConsumerState,
        ) -> tuple[
            DegradedConsumerState,
            tuple[DegradedConsumerState, tuple[str, ...], bool],
        ]:
            transition_reasons = self._consumer_state_reasons(state, publication)
            if transition_reasons:
                return state, (state, tuple(transition_reasons), False)
            updated = state
            if publication.sequence > state.highest_publication_sequence:
                updated = DegradedConsumerState.evolve(
                    updated,
                    highest_publication_sequence=publication.sequence,
                    highest_publication_sha256=publication.digest,
                )
            if authorization is not None and (
                publication.snapshot.affected_roles or publication.snapshot.unresolved_effect
            ):
                transition_reasons.extend(
                    self._authorization_reasons(
                        authorization,
                        publication,
                        evaluated_at=evaluated_at,
                    )
                )
                if updated.latest_reversed_authorization_sha256 == authorization.digest:
                    transition_reasons.append("degraded_authorization_revoked")
                if authorization.digest != updated.active_authorization_sha256:
                    if updated.active_authorization_sha256 is not None:
                        transition_reasons.append("degraded_active_authorization_reversal_required")
                    elif authorization.sequence <= updated.highest_authorization_sequence:
                        transition_reasons.append("degraded_authorization_sequence_not_monotonic")
                    if not transition_reasons:
                        updated = DegradedConsumerState.evolve(
                            updated,
                            highest_authorization_sequence=authorization.sequence,
                            active_authorization_id=authorization.authorization_id,
                            active_authorization_sha256=authorization.digest,
                            active_recovery_checkpoint_id=(authorization.recovery_checkpoint_id),
                        )
            updated, reversal_reasons, reversal_applied = self._apply_reversal(
                updated,
                reversal,
                evaluated_at=evaluated_at,
            )
            transition_reasons.extend(reversal_reasons)
            return updated, (
                updated,
                tuple(dict.fromkeys(transition_reasons)),
                reversal_applied,
            )

        try:
            state, state_reasons, reversal_applicable = self.state_store.mutate(transition)
        except Exception as exc:
            raise DegradedPublicationError(
                "degraded publication consumer state is unavailable"
            ) from exc
        if state_reasons:
            raise DegradedPublicationError(
                "degraded publication gate is not ready: " + ",".join(state_reasons)
            )
        authorization_active = bool(
            authorization is not None
            and authorization_active
            and state.active_authorization_sha256 == authorization.digest
        )
        return {
            "schema_version": "aegis-ot-m5-degraded-gate-readiness-v1",
            "ready": True,
            "evaluated_at": evaluated_at.isoformat(),
            "publication_sequence": publication.sequence,
            "publication_sha256": publication.digest,
            "publication_expires_at": publication.expires_at.isoformat(),
            "snapshot_sha256": publication.snapshot.digest,
            "status_input_sha256": publication.status_input_sha256,
            "affected_roles": sorted(role.value for role in publication.snapshot.affected_roles),
            "authorization_sha256": self.stable_authorization.digest,
            "authorization_active": authorization_active,
            "durable_publication_floor": state.highest_publication_sequence,
            "active_authorization_sha256": state.active_authorization_sha256,
            "reversal_present": reversal is not None,
            "reversal_applicable": reversal_applicable,
            "execution_authorized": False,
        }

    def evaluate(
        self,
        proposal: ActionProposal,
        *,
        now: datetime | None = None,
    ) -> DegradedAdmissionResult:
        evaluated_at = _aware_utc(
            datetime.now(UTC) if now is None else now,
            label="published degraded admission time",
        )
        try:
            publication = self.publication_source()
        except Exception:
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=("degraded_publication_unavailable",),
                evaluated_at=evaluated_at,
                snapshot=None,
                authorization=None,
                affected_roles=frozenset(),
                may_enter_primary_assurance=False,
            )
        if not isinstance(publication, DegradedRuntimePublication):
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=("degraded_publication_invalid",),
                evaluated_at=evaluated_at,
                snapshot=None,
                authorization=None,
                affected_roles=frozenset(),
                may_enter_primary_assurance=False,
            )
        publication_reasons = self._publication_reasons(
            publication,
            evaluated_at=evaluated_at,
        )
        if publication_reasons:
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=publication_reasons,
                evaluated_at=evaluated_at,
                snapshot=publication.snapshot,
                authorization=publication.authorization,
                affected_roles=publication.snapshot.affected_roles,
                may_enter_primary_assurance=False,
            )
        try:
            reversal = self.reversal_source() if self.reversal_source is not None else None
        except Exception:
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=("degraded_reversal_source_unavailable",),
                evaluated_at=evaluated_at,
                snapshot=publication.snapshot,
                authorization=publication.authorization,
                affected_roles=publication.snapshot.affected_roles,
                may_enter_primary_assurance=False,
            )
        if reversal is not None and not isinstance(reversal, DegradedModeReversal):
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=("degraded_reversal_invalid",),
                evaluated_at=evaluated_at,
                snapshot=publication.snapshot,
                authorization=publication.authorization,
                affected_roles=publication.snapshot.affected_roles,
                may_enter_primary_assurance=False,
            )

        def transition(
            state: DegradedConsumerState,
        ) -> tuple[DegradedConsumerState, DegradedAdmissionResult]:
            trust_matches = (
                state.authority_id == self.authority_id
                and state.authority_key_id == _key_id(self.authority_public_key)
                and state.publisher_credential_sha256 == self.publisher_credential.digest
                and state.publisher_key_id == self.publisher_credential.publisher_key_id
            )
            if not trust_matches:
                return state, self._result(
                    outcome=DegradedAdmissionOutcome.SAFE_STATE,
                    reasons=("degraded_consumer_state_trust_mismatch",),
                    evaluated_at=evaluated_at,
                    snapshot=publication.snapshot,
                    authorization=publication.authorization,
                    affected_roles=publication.snapshot.affected_roles,
                    may_enter_primary_assurance=False,
                )
            if publication.sequence < state.highest_publication_sequence:
                return state, self._result(
                    outcome=DegradedAdmissionOutcome.SAFE_STATE,
                    reasons=("degraded_publication_sequence_rollback",),
                    evaluated_at=evaluated_at,
                    snapshot=publication.snapshot,
                    authorization=publication.authorization,
                    affected_roles=publication.snapshot.affected_roles,
                    may_enter_primary_assurance=False,
                )
            if publication.sequence == state.highest_publication_sequence:
                if publication.digest != state.highest_publication_sha256:
                    return state, self._result(
                        outcome=DegradedAdmissionOutcome.SAFE_STATE,
                        reasons=("degraded_publication_sequence_equivocation",),
                        evaluated_at=evaluated_at,
                        snapshot=publication.snapshot,
                        authorization=publication.authorization,
                        affected_roles=publication.snapshot.affected_roles,
                        may_enter_primary_assurance=False,
                    )
                updated = state
            else:
                if (
                    publication.sequence == state.highest_publication_sequence + 1
                    and state.highest_publication_sequence > 0
                    and publication.previous_publication_sha256 != state.highest_publication_sha256
                ):
                    return state, self._result(
                        outcome=DegradedAdmissionOutcome.SAFE_STATE,
                        reasons=("degraded_publication_predecessor_mismatch",),
                        evaluated_at=evaluated_at,
                        snapshot=publication.snapshot,
                        authorization=publication.authorization,
                        affected_roles=publication.snapshot.affected_roles,
                        may_enter_primary_assurance=False,
                    )
                updated = DegradedConsumerState.evolve(
                    state,
                    highest_publication_sequence=publication.sequence,
                    highest_publication_sha256=publication.digest,
                )

            updated, reversal_reasons, reversal_applied = self._apply_reversal(
                updated,
                reversal,
                evaluated_at=evaluated_at,
            )
            if reversal_reasons:
                return updated, self._result(
                    outcome=DegradedAdmissionOutcome.SAFE_STATE,
                    reasons=reversal_reasons,
                    evaluated_at=evaluated_at,
                    snapshot=publication.snapshot,
                    authorization=publication.authorization,
                    affected_roles=publication.snapshot.affected_roles,
                    may_enter_primary_assurance=False,
                )

            snapshot = publication.snapshot
            affected = snapshot.affected_roles
            authorization = publication.authorization
            if not affected and not snapshot.unresolved_effect:
                if updated.active_authorization_sha256 is not None:
                    return updated, self._result(
                        outcome=DegradedAdmissionOutcome.HOLD_STATE,
                        reasons=("degraded_condition_cleared_reversal_required",),
                        evaluated_at=evaluated_at,
                        snapshot=snapshot,
                        authorization=authorization,
                        affected_roles=frozenset(),
                        may_enter_primary_assurance=False,
                    )
                reason = (
                    "normal_runtime_dependencies_healthy_after_signed_reversal"
                    if reversal_applied or updated.highest_reversal_sequence > 0
                    else "normal_runtime_dependencies_healthy"
                )
                return updated, self._result(
                    outcome=DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE,
                    reasons=(reason,),
                    evaluated_at=evaluated_at,
                    snapshot=snapshot,
                    authorization=None,
                    affected_roles=frozenset(),
                    may_enter_primary_assurance=True,
                )

            reasons = self._condition_reasons(snapshot)
            if snapshot.unresolved_effect:
                reasons.append("outcome_reconciliation_required")
            if authorization is None:
                reasons.append("degraded_mode_authorization_missing")
                return updated, self._result(
                    outcome=DegradedAdmissionOutcome.SAFE_STATE,
                    reasons=reasons,
                    evaluated_at=evaluated_at,
                    snapshot=snapshot,
                    authorization=None,
                    affected_roles=affected,
                    may_enter_primary_assurance=False,
                )
            authorization_reasons = self._authorization_reasons(
                authorization,
                publication,
                evaluated_at=evaluated_at,
            )
            if updated.latest_reversed_authorization_sha256 == authorization.digest:
                authorization_reasons.append("degraded_authorization_revoked")
            if authorization.digest != updated.active_authorization_sha256:
                if updated.active_authorization_sha256 is not None:
                    authorization_reasons.append("degraded_active_authorization_reversal_required")
                elif authorization.sequence <= updated.highest_authorization_sequence:
                    authorization_reasons.append("degraded_authorization_sequence_not_monotonic")
                if not authorization_reasons:
                    updated = DegradedConsumerState.evolve(
                        updated,
                        highest_authorization_sequence=authorization.sequence,
                        active_authorization_id=authorization.authorization_id,
                        active_authorization_sha256=authorization.digest,
                        active_recovery_checkpoint_id=(authorization.recovery_checkpoint_id),
                    )
            if authorization_reasons:
                reasons.extend(authorization_reasons)
                return updated, self._result(
                    outcome=DegradedAdmissionOutcome.SAFE_STATE,
                    reasons=reasons,
                    evaluated_at=evaluated_at,
                    snapshot=snapshot,
                    authorization=authorization,
                    affected_roles=affected,
                    may_enter_primary_assurance=False,
                )

            behavior = authorization.behavior
            if behavior is DegradedBehavior.SAFE_STATE:
                reasons.append("authorized_safe_state")
                return updated, self._result(
                    outcome=DegradedAdmissionOutcome.SAFE_STATE,
                    reasons=reasons,
                    evaluated_at=evaluated_at,
                    snapshot=snapshot,
                    authorization=authorization,
                    affected_roles=affected,
                    may_enter_primary_assurance=False,
                )
            if behavior is DegradedBehavior.HOLD_STATE:
                reasons.append("authorized_hold_state")
                return updated, self._result(
                    outcome=DegradedAdmissionOutcome.HOLD_STATE,
                    reasons=reasons,
                    evaluated_at=evaluated_at,
                    snapshot=snapshot,
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
                return updated, self._result(
                    outcome=DegradedAdmissionOutcome.HOLD_STATE,
                    reasons=reasons,
                    evaluated_at=evaluated_at,
                    snapshot=snapshot,
                    authorization=authorization,
                    affected_roles=affected,
                    may_enter_primary_assurance=False,
                )
            reasons.append("authorized_mission_preserving_entry_to_primary_assurance")
            return updated, self._result(
                outcome=DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE,
                reasons=reasons,
                evaluated_at=evaluated_at,
                snapshot=snapshot,
                authorization=authorization,
                affected_roles=affected,
                may_enter_primary_assurance=True,
            )

        try:
            return self.state_store.mutate(transition)
        except Exception:
            return self._result(
                outcome=DegradedAdmissionOutcome.SAFE_STATE,
                reasons=("degraded_consumer_state_unavailable",),
                evaluated_at=evaluated_at,
                snapshot=publication.snapshot,
                authorization=publication.authorization,
                affected_roles=publication.snapshot.affected_roles,
                may_enter_primary_assurance=False,
            )


def _read_raw_key(path: Path, *, private: bool) -> bytes:
    material = _read_canonical_file(
        path,
        expected_uid=os.geteuid(),
        maximum_bytes=32,
    )
    assert material is not None
    if len(material) != 32:
        label = "private" if private else "public"
        raise DegradedPublicationError(f"{label} Ed25519 key must contain exactly 32 bytes")
    return material


def load_authority_public_key(
    path: Path,
    *,
    expected_uid: int | None = None,
) -> Ed25519PublicKey:
    """Load an exact raw Ed25519 root key through the strict file boundary."""

    material = _read_canonical_file(
        path,
        expected_uid=os.geteuid() if expected_uid is None else expected_uid,
        maximum_bytes=32,
    )
    assert material is not None
    if len(material) != 32:
        raise DegradedPublicationError("public Ed25519 key must contain exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(material)


def _environment_path(name: str) -> Path | None:
    value = os.getenv(name)
    return Path(value) if value else None


def _required_path_argument(
    parser: argparse.ArgumentParser,
    option: str,
    environment: str,
) -> None:
    default = _environment_path(environment)
    parser.add_argument(option, type=Path, default=default, required=default is None)


def _trust_arguments(parser: argparse.ArgumentParser) -> None:
    _required_path_argument(
        parser,
        "--root-public-key-file",
        "AEGIS_M5_ROOT_PUBLIC_KEY_FILE",
    )
    _required_path_argument(
        parser,
        "--publisher-credential-file",
        "AEGIS_M5_PUBLISHER_CREDENTIAL_FILE",
    )


def _publisher_arguments(parser: argparse.ArgumentParser) -> None:
    _trust_arguments(parser)
    _required_path_argument(
        parser,
        "--publisher-private-key-file",
        "AEGIS_M5_PUBLISHER_PRIVATE_KEY_FILE",
    )
    _required_path_argument(
        parser,
        "--status-input-file",
        "AEGIS_M5_STATUS_INPUT_FILE",
    )
    _required_path_argument(
        parser,
        "--publication-file",
        "AEGIS_M5_PUBLICATION_FILE",
    )
    _required_path_argument(
        parser,
        "--publisher-state-file",
        "AEGIS_M5_PUBLISHER_STATE_FILE",
    )
    _required_path_argument(
        parser,
        "--stable-authorization-file",
        "AEGIS_M5_STABLE_AUTHORIZATION_FILE",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    init_state = commands.add_parser(
        "init-state",
        help="initialize one or both dedicated durable state directories",
    )
    _trust_arguments(init_state)
    init_state.add_argument(
        "--publisher-state-file",
        type=Path,
        default=_environment_path("AEGIS_M5_PUBLISHER_STATE_FILE"),
    )
    init_state.add_argument(
        "--consumer-state-file",
        type=Path,
        default=_environment_path("AEGIS_M5_CONSUMER_STATE_FILE"),
    )

    publish_once = commands.add_parser(
        "publish-once",
        help="publish exactly one signed complete status generation",
    )
    _publisher_arguments(publish_once)

    run = commands.add_parser("run", help="continuously refresh signed publications")
    _publisher_arguments(run)
    run.add_argument(
        "--interval-seconds",
        type=float,
        default=float(os.getenv("AEGIS_M5_PUBLISH_INTERVAL_SECONDS", "1.0")),
    )

    check = commands.add_parser(
        "check",
        help="verify current trust, publication freshness, and durable publisher continuity",
    )
    _trust_arguments(check)
    _required_path_argument(
        check,
        "--publication-file",
        "AEGIS_M5_PUBLICATION_FILE",
    )
    _required_path_argument(
        check,
        "--stable-authorization-file",
        "AEGIS_M5_STABLE_AUTHORIZATION_FILE",
    )
    _required_path_argument(
        check,
        "--publisher-state-file",
        "AEGIS_M5_PUBLISHER_STATE_FILE",
    )
    return parser


def _load_cli_trust(
    arguments: argparse.Namespace,
) -> tuple[
    Ed25519PublicKey,
    DegradedPublisherCredential,
]:
    authority_public_key = load_authority_public_key(arguments.root_public_key_file)
    credential = load_publisher_credential(arguments.publisher_credential_file)
    if not credential.verify(authority_public_key):
        raise DegradedPublicationError("publisher credential signature is invalid")
    return authority_public_key, credential


def _cli_publisher(arguments: argparse.Namespace) -> DegradedPublicationPublisher:
    authority_public_key, credential = _load_cli_trust(arguments)
    publisher_private_key = Ed25519PrivateKey.from_private_bytes(
        _read_raw_key(arguments.publisher_private_key_file, private=True)
    )
    authorization_source: StableAuthorizationSource = FileStableDegradedAuthorizationSource(
        arguments.stable_authorization_file
    )
    return DegradedPublicationPublisher(
        authority_public_key=authority_public_key,
        credential=credential,
        publisher_private_key=publisher_private_key,
        status_source=FileDegradedStatusSource(arguments.status_input_file),
        authorization_source=authorization_source,
        sink=AtomicDegradedPublicationSink(arguments.publication_file),
        state_store=FileDegradedPublisherStateStore(arguments.publisher_state_file),
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "init-state":
            _, credential = _load_cli_trust(arguments)
            initialized: list[str] = []
            if arguments.publisher_state_file is not None:
                FileDegradedPublisherStateStore.initialize(
                    arguments.publisher_state_file,
                    credential=credential,
                )
                initialized.append("publisher")
            if arguments.consumer_state_file is not None:
                FileDegradedConsumerStateStore.initialize(
                    arguments.consumer_state_file,
                    credential=credential,
                )
                initialized.append("consumer")
            if not initialized:
                raise DegradedPublicationError(
                    "init-state requires a publisher or consumer state file"
                )
            report: dict[str, Any] = {
                "schema_version": "aegis-ot-m5-degraded-state-initialization-v1",
                "initialized": initialized,
                "authority_id": credential.authority_id,
                "authority_key_id": credential.authority_key_id,
                "publisher_credential_sha256": credential.digest,
                "publisher_key_id": credential.publisher_key_id,
                "private_key_material_printed": False,
            }
        elif arguments.command in {"publish-once", "run"}:
            publisher = _cli_publisher(arguments)
            if arguments.command == "run":
                try:
                    publisher.run(interval_seconds=arguments.interval_seconds)
                except KeyboardInterrupt:
                    pass
                report = {
                    "schema_version": "aegis-ot-m5-degraded-publisher-run-v1",
                    "status": "stopped",
                    "private_key_material_printed": False,
                }
            else:
                publication = publisher.publish_once()
                report = {
                    "schema_version": publication.schema_version,
                    "publication_id": publication.publication_id,
                    "sequence": publication.sequence,
                    "publication_sha256": publication.digest,
                    "published_at": publication.published_at.isoformat(),
                    "authorization_sha256": (
                        publication.authorization.digest
                        if publication.authorization is not None
                        else None
                    ),
                    "execution_authorized": False,
                    "private_key_material_printed": False,
                }
        else:
            authority_public_key, credential = _load_cli_trust(arguments)
            authorization = FileStableDegradedAuthorizationSource(
                arguments.stable_authorization_file
            )()
            publication = FileDegradedPublicationSource(arguments.publication_file)()
            now = datetime.now(UTC)
            maximum_age = timedelta(seconds=credential.maximum_publication_age_seconds)
            maximum_status_age = timedelta(
                seconds=credential.maximum_status_input_age_seconds
            )
            if (
                not publication.verify(credential.publisher_public_key)
                or publication.publisher_credential_sha256 != credential.digest
                or publication.publisher_key_id != credential.publisher_key_id
                or publication.health_source_id != credential.health_source_id
                or not credential.issued_at <= now < credential.expires_at
                or publication.published_at > now
                or now - publication.published_at > maximum_age
                or publication.expires_at - publication.published_at > maximum_age
                or now >= publication.expires_at
                or publication.snapshot.captured_at > now
                or now - publication.snapshot.captured_at > maximum_status_age
            ):
                raise DegradedPublicationError("current degraded publication is not trusted")
            if (
                not authorization.verify(authority_public_key)
                or authorization.authority_id != credential.authority_id
                or authorization.authority_key_id != credential.authority_key_id
                or authorization.publisher_credential_sha256 != credential.digest
                or authorization.publisher_key_id != credential.publisher_key_id
                or publication.authorization is None
                or publication.authorization.digest != authorization.digest
            ):
                raise DegradedPublicationError(
                    "current stable authorization is outside configured trust"
                )
            state = FileDegradedPublisherStateStore(
                arguments.publisher_state_file
            ).reconcile_current(publication, credential=credential)
            if (
                state.latest_published_sequence != publication.sequence
                or state.latest_publication_sha256 != publication.digest
            ):
                raise DegradedPublicationError(
                    "current publication disagrees with durable publisher state"
                )
            report = {
                "schema_version": publication.schema_version,
                "valid": True,
                "sequence": publication.sequence,
                "publication_sha256": publication.digest,
                "publication_expires_at": publication.expires_at.isoformat(),
                "authorization_sha256": authorization.digest,
                "durable_state_continuous": True,
                "execution_authorized": False,
            }
    except (DegradedPublicationError, OSError, TypeError, ValueError) as exc:
        print(f"M5 degraded publication error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
