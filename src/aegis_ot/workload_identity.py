"""Authority-signed workload identity and revocation for the M4g research path.

This module deliberately implements a closed research credential rather than
claiming X.509, SPIFFE, or platform-attested workload identity.  A pinned
Ed25519 authority signs both short-lived workload credentials and a versioned
trust bundle containing the active revocation set.  Verifiers reload the bundle
for each decision and reject in-process sequence rollback.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any, Self

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .crypto import decode_urlsafe_b64, sign_bytes, verify_bytes

CREDENTIAL_SIGNATURE_DOMAIN = b"aegis-ot:m4g:workload-credential:v1\x00"
TRUST_BUNDLE_SIGNATURE_DOMAIN = b"aegis-ot:m4g:workload-trust-bundle:v1\x00"
MAX_IDENTITY_FILE_BYTES = 262_144


class WorkloadIdentityError(RuntimeError):
    """A workload identity artifact or lifecycle decision cannot be trusted."""


class WorkloadIdentityUnavailable(WorkloadIdentityError):
    """Required local identity material is missing, corrupt, or unusable."""


class WorkloadTrustStateUnavailable(WorkloadIdentityUnavailable):
    """The current signed trust-bundle state cannot be established."""


class WorkloadCredentialRejected(WorkloadIdentityError):
    """A presented credential is authenticatable but not admissible."""


class WorkloadRole(StrEnum):
    AGENT = "agent"
    CANDIDATE = "candidate"
    GATEWAY = "gateway"
    OT_ADAPTER = "ot-adapter"
    OBSERVER = "observer"
    POLICY = "policy"
    PLANT = "plant"
    PERMIT_ISSUER = "permit-issuer"
    SIMULATION = "simulation"


def canonical_json_bytes(value: BaseModel | dict[str, Any]) -> bytes:
    material = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_file_bytes(value: BaseModel | dict[str, Any]) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError(f"duplicate JSON key: {key}")
        parsed[key] = value
    return parsed


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _strict_json_loads(material: bytes) -> Any:
    if material.startswith(b"\xef\xbb\xbf"):
        raise ValueError("UTF-8 BOM is forbidden")
    return json.loads(
        material.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def _load_closed_model(path: Path, model: type[BaseModel]) -> BaseModel:
    try:
        material = path.read_bytes()
    except OSError as exc:
        raise WorkloadIdentityError(f"workload identity file is unavailable: {path}") from exc
    if not material or len(material) > MAX_IDENTITY_FILE_BYTES:
        raise WorkloadIdentityError("workload identity file size is invalid")
    try:
        parsed = _strict_json_loads(material)
        value = model.model_validate(parsed)
    except (UnicodeDecodeError, ValueError) as exc:
        raise WorkloadIdentityError("workload identity file is invalid") from exc
    if material != canonical_json_file_bytes(value):
        raise WorkloadIdentityError("workload identity file is not canonical")
    return value


def public_key_base64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import base64

    return base64.urlsafe_b64encode(raw).decode("ascii")


def workload_key_id(public_key: Ed25519PublicKey) -> str:
    """Return the protocol key identifier derived from exact leaf key bytes."""

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()}"


def public_key_from_base64(value: str) -> Ed25519PublicKey:
    try:
        raw = decode_urlsafe_b64(value)
    except ValueError as exc:
        raise ValueError("workload public key encoding is invalid") from exc
    if len(raw) != 32:
        raise ValueError("workload public key must contain exactly 32 raw bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def _validate_identity_text(label: str, value: str) -> str:
    if value != value.strip() or any(character.isspace() for character in value):
        raise ValueError(f"{label} must not contain whitespace")
    return value


class WorkloadCredential(BaseModel):
    """Closed claims signed by the configured research identity authority."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="m4g-workload-credential-v1",
        pattern=r"^m4g-workload-credential-v1$",
    )
    credential_id: str = Field(min_length=16, max_length=128)
    trust_domain: str = Field(min_length=3, max_length=128)
    subject: str = Field(min_length=3, max_length=256)
    role: WorkloadRole
    key_id: str = Field(min_length=3, max_length=128)
    public_key_b64: str = Field(min_length=44, max_length=44)
    authority_key_id: str = Field(min_length=3, max_length=128)
    audiences: tuple[str, ...] = Field(min_length=1, max_length=16)
    issued_at: datetime
    not_before: datetime
    expires_at: datetime

    @field_validator(
        "credential_id",
        "trust_domain",
        "subject",
        "key_id",
        "authority_key_id",
    )
    @classmethod
    def validate_identity_text(cls, value: str, info: Any) -> str:
        return _validate_identity_text(str(info.field_name), value)

    @field_validator("public_key_b64")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        public_key_from_base64(value)
        return value

    @field_validator("issued_at", "not_before", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("workload credential timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("audiences")
    @classmethod
    def require_canonical_audiences(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        checked = tuple(_validate_identity_text("audience", item) for item in value)
        if checked != tuple(sorted(set(checked))):
            raise ValueError("workload credential audiences must be unique and sorted")
        return checked

    @model_validator(mode="after")
    def require_validity_window(self) -> Self:
        if not self.issued_at <= self.not_before < self.expires_at:
            raise ValueError("workload credential validity window is invalid")
        if self.key_id != workload_key_id(self.public_key):
            raise ValueError("workload credential key ID does not match its public key")
        if self.key_id == self.authority_key_id:
            raise ValueError("workload leaf key must differ from the authority key")
        return self

    @property
    def public_key(self) -> Ed25519PublicKey:
        return public_key_from_base64(self.public_key_b64)


class SignedWorkloadCredential(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    credential: WorkloadCredential
    signature: str = Field(min_length=88, max_length=88)

    def signing_payload(self) -> bytes:
        return CREDENTIAL_SIGNATURE_DOMAIN + canonical_json_bytes(self.credential)

    @classmethod
    def issue(
        cls,
        credential: WorkloadCredential,
        authority_private_key: Ed25519PrivateKey,
    ) -> SignedWorkloadCredential:
        unsigned = cls.model_construct(credential=credential, signature="")
        return cls(
            credential=credential,
            signature=sign_bytes(authority_private_key, unsigned.signing_payload()),
        )

    def verify(self, authority_public_key: Ed25519PublicKey) -> bool:
        return verify_bytes(authority_public_key, self.signing_payload(), self.signature)


class WorkloadRevocation(BaseModel):
    """A listed credential is denied immediately, regardless of timestamp."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    credential_id: str = Field(min_length=16, max_length=128)
    revoked_at: datetime
    reason: str = Field(min_length=1, max_length=256)

    @field_validator("revoked_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("workload revocation timestamp must be timezone-aware")
        return value.astimezone(UTC)


class WorkloadTrustBundle(BaseModel):
    """Pinned-authority-signed lifecycle state for one research trust domain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="m4g-workload-trust-bundle-v1",
        pattern=r"^m4g-workload-trust-bundle-v1$",
    )
    bundle_id: str = Field(min_length=16, max_length=128)
    sequence: int = Field(ge=1)
    trust_domain: str = Field(min_length=3, max_length=128)
    authority_key_id: str = Field(min_length=3, max_length=128)
    authority_public_key_b64: str = Field(min_length=44, max_length=44)
    issued_at: datetime
    expires_at: datetime
    revocations: tuple[WorkloadRevocation, ...] = ()
    signature: str = ""

    @field_validator("bundle_id", "trust_domain", "authority_key_id")
    @classmethod
    def validate_identity_text(cls, value: str, info: Any) -> str:
        return _validate_identity_text(str(info.field_name), value)

    @field_validator("authority_public_key_b64")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        public_key_from_base64(value)
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("workload trust-bundle timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_closed_lifecycle(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("workload trust-bundle validity window is invalid")
        if self.authority_key_id != workload_key_id(
            public_key_from_base64(self.authority_public_key_b64)
        ):
            raise ValueError("workload authority key ID does not match its public key")
        identifiers = tuple(item.credential_id for item in self.revocations)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("workload revocations must be unique and sorted")
        return self

    def signing_payload(self) -> bytes:
        return TRUST_BUNDLE_SIGNATURE_DOMAIN + canonical_json_bytes(
            self.model_dump(mode="json", exclude={"signature"})
        )

    def signed(self, authority_private_key: Ed25519PrivateKey) -> WorkloadTrustBundle:
        return self.model_copy(
            update={"signature": sign_bytes(authority_private_key, self.signing_payload())}
        )

    def verify(self, authority_public_key: Ed25519PublicKey) -> bool:
        return bool(self.signature) and verify_bytes(
            authority_public_key,
            self.signing_payload(),
            self.signature,
        )


def load_signed_workload_credential(path: Path) -> SignedWorkloadCredential:
    try:
        value = _load_closed_model(path, SignedWorkloadCredential)
    except WorkloadIdentityError as exc:
        raise WorkloadIdentityUnavailable("workload credential file is unavailable") from exc
    if not isinstance(value, SignedWorkloadCredential):  # pragma: no cover - type narrowing
        raise WorkloadIdentityUnavailable("workload credential type is invalid")
    return value


def load_workload_trust_bundle(path: Path) -> WorkloadTrustBundle:
    try:
        value = _load_closed_model(path, WorkloadTrustBundle)
    except WorkloadIdentityError as exc:
        raise WorkloadTrustStateUnavailable(
            "workload trust-bundle file is unavailable"
        ) from exc
    if not isinstance(value, WorkloadTrustBundle):  # pragma: no cover - type narrowing
        raise WorkloadTrustStateUnavailable("workload trust-bundle type is invalid")
    return value


@dataclass
class WorkloadIdentityVerifier:
    trust_root_public_key: Ed25519PublicKey
    trust_root_key_id: str
    trust_domain: str
    trust_bundle_path: Path
    maximum_credential_lifetime: timedelta = timedelta(hours=24)
    maximum_bundle_lifetime: timedelta = timedelta(hours=24)
    _highest_sequence: int = field(default=0, init=False, repr=False)
    _highest_sequence_digest: str = field(default="", init=False, repr=False)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def _trusted_bundle(self, now: datetime) -> tuple[WorkloadTrustBundle, str]:
        if now.tzinfo is None or now.utcoffset() is None:
            raise WorkloadTrustStateUnavailable(
                "workload verification time must be timezone-aware"
            )
        now = now.astimezone(UTC)
        bundle = load_workload_trust_bundle(self.trust_bundle_path)
        pinned_public = public_key_base64(self.trust_root_public_key)
        if (
            bundle.trust_domain != self.trust_domain
            or bundle.authority_key_id != self.trust_root_key_id
            or bundle.authority_public_key_b64 != pinned_public
            or not bundle.verify(self.trust_root_public_key)
        ):
            raise WorkloadTrustStateUnavailable(
                "workload trust bundle is not rooted in configured trust"
            )
        if bundle.expires_at - bundle.issued_at > self.maximum_bundle_lifetime:
            raise WorkloadTrustStateUnavailable(
                "workload trust bundle lifetime exceeds policy"
            )
        if not bundle.issued_at <= now < bundle.expires_at:
            raise WorkloadTrustStateUnavailable(
                "workload trust bundle is not currently valid"
            )
        bundle_digest = hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()
        with self._lock:
            if bundle.sequence < self._highest_sequence:
                raise WorkloadTrustStateUnavailable(
                    "workload trust bundle sequence rolled back"
                )
            if (
                bundle.sequence == self._highest_sequence
                and self._highest_sequence_digest
                and bundle_digest != self._highest_sequence_digest
            ):
                raise WorkloadTrustStateUnavailable(
                    "workload trust bundle sequence was equivocated"
                )
            self._highest_sequence = bundle.sequence
            self._highest_sequence_digest = bundle_digest
        return bundle, bundle_digest

    def verify_credential_with_receipt(
        self,
        signed: SignedWorkloadCredential,
        *,
        expected_role: WorkloadRole,
        expected_audience: str,
        expected_subject: str | None = None,
        now: datetime | None = None,
    ) -> WorkloadVerificationReceipt:
        """Verify one credential and return non-secret admission provenance."""

        evaluated_at = datetime.now(UTC) if now is None else now
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise WorkloadCredentialRejected(
                "workload verification time must be timezone-aware"
            )
        evaluated_at = evaluated_at.astimezone(UTC)
        bundle, bundle_digest = self._trusted_bundle(evaluated_at)
        credential = signed.credential
        if (
            credential.trust_domain != self.trust_domain
            or credential.authority_key_id != self.trust_root_key_id
            or not signed.verify(self.trust_root_public_key)
        ):
            raise WorkloadCredentialRejected(
                "workload credential issuer or signature is invalid"
            )
        if credential.expires_at - credential.not_before > self.maximum_credential_lifetime:
            raise WorkloadCredentialRejected(
                "workload credential lifetime exceeds policy"
            )
        if not credential.not_before <= evaluated_at < credential.expires_at:
            raise WorkloadCredentialRejected(
                "workload credential is not currently valid"
            )
        if credential.role is not expected_role:
            raise WorkloadCredentialRejected(
                "workload credential role is not authorized"
            )
        if expected_subject is not None and credential.subject != expected_subject:
            raise WorkloadCredentialRejected(
                "workload credential subject is not authorized"
            )
        if expected_audience not in credential.audiences:
            raise WorkloadCredentialRejected(
                "workload credential audience is not authorized"
            )
        if any(
            revoked.credential_id == credential.credential_id
            for revoked in bundle.revocations
        ):
            raise WorkloadCredentialRejected("workload credential is revoked")
        return WorkloadVerificationReceipt(
            public_key=credential.public_key,
            verified_at=evaluated_at,
            credential_id=credential.credential_id,
            trust_domain=credential.trust_domain,
            subject=credential.subject,
            role=credential.role,
            key_id=credential.key_id,
            authority_key_id=credential.authority_key_id,
            trust_bundle_id=bundle.bundle_id,
            trust_bundle_sequence=bundle.sequence,
            trust_bundle_sha256=bundle_digest,
        )

    def verify_credential(
        self,
        signed: SignedWorkloadCredential,
        *,
        expected_role: WorkloadRole,
        expected_audience: str,
        expected_subject: str | None = None,
        now: datetime | None = None,
    ) -> Ed25519PublicKey:
        return self.verify_credential_with_receipt(
            signed,
            expected_role=expected_role,
            expected_audience=expected_audience,
            expected_subject=expected_subject,
            now=now,
        ).public_key


@dataclass(frozen=True)
class WorkloadVerificationReceipt:
    """Non-secret evidence of one successful lifecycle admission decision."""

    public_key: Ed25519PublicKey
    verified_at: datetime
    credential_id: str
    trust_domain: str
    subject: str
    role: WorkloadRole
    key_id: str
    authority_key_id: str
    trust_bundle_id: str
    trust_bundle_sequence: int
    trust_bundle_sha256: str

    def evidence_fields(self) -> dict[str, Any]:
        return {
            "verified_at": self.verified_at.isoformat(),
            "credential_id": self.credential_id,
            "trust_domain": self.trust_domain,
            "subject": self.subject,
            "role": self.role.value,
            "key_id": self.key_id,
            "authority_key_id": self.authority_key_id,
            "trust_bundle_id": self.trust_bundle_id,
            "trust_bundle_sequence": self.trust_bundle_sequence,
            "trust_bundle_sha256": self.trust_bundle_sha256,
        }


@dataclass(frozen=True)
class ResolvedWorkloadIdentity:
    credential: SignedWorkloadCredential
    public_key: Ed25519PublicKey
    verification: WorkloadVerificationReceipt

    @property
    def key_id(self) -> str:
        return self.credential.credential.key_id

    @property
    def subject(self) -> str:
        return self.credential.credential.subject


@dataclass(frozen=True)
class WorkloadCredentialBinding:
    """Reload and authorize one peer credential at each trust decision."""

    verifier: WorkloadIdentityVerifier
    credential_path: Path
    expected_role: WorkloadRole
    expected_audience: str
    expected_subject: str

    def resolve(self, *, now: datetime | None = None) -> ResolvedWorkloadIdentity:
        credential = load_signed_workload_credential(self.credential_path)
        verification = self.verifier.verify_credential_with_receipt(
            credential,
            expected_role=self.expected_role,
            expected_audience=self.expected_audience,
            expected_subject=self.expected_subject,
            now=now,
        )
        return ResolvedWorkloadIdentity(
            credential=credential,
            public_key=verification.public_key,
            verification=verification,
        )


@dataclass(frozen=True)
class WorkloadSigner:
    credential: SignedWorkloadCredential
    private_key: Ed25519PrivateKey

    @classmethod
    def from_files(
        cls,
        credential_path: Path,
        private_key_path: Path,
    ) -> WorkloadSigner:
        credential = load_signed_workload_credential(credential_path)
        try:
            raw_private = private_key_path.read_bytes()
        except OSError as exc:
            raise WorkloadIdentityUnavailable(
                "workload private key is unavailable"
            ) from exc
        if len(raw_private) != 32:
            raise WorkloadIdentityUnavailable(
                "workload private key must contain exactly 32 raw bytes"
            )
        private_key = Ed25519PrivateKey.from_private_bytes(raw_private)
        public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        claimed = credential.credential.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if public != claimed:
            raise WorkloadIdentityUnavailable(
                "workload private key does not match credential"
            )
        return cls(credential=credential, private_key=private_key)
