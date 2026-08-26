"""Rollback-resistant external anchoring contract for M4i coordination.

The existing M4i journals and plant checkpoint detect ordinary single-store
rollback and disagreement.  This module defines the additional, explicit
contract needed to detect a coordinated rollback of all local stores:

* an independently trusted authority signs nonce-bound, short-lived readbacks;
* every writer grant carries a strictly increasing fencing token;
* every local advance records the exact external checkpoint it was based on;
* the authority accepts the next checkpoint only by compare-and-advance; and
* recovery and admission fail closed when readback, freshness, chain, or fence
  state is unavailable or ambiguous.

``InMemoryMonotonicAnchorReference`` is an executable reference model for this
contract.  It is deliberately process-local and establishes neither external
durability nor distributed consensus.  A deployment must implement the
``ExternalCoordinationAnchor`` protocol in a separately administered rollback
domain and must fence the physical writer with the issued token.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from threading import RLock
from typing import Literal, Protocol, Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .coordination_recovery import (
    CoordinationRecoveryReason,
    CoordinationRecoveryResult,
    CoordinationRecoveryStatus,
)
from .crypto import sign_bytes, verify_bytes
from .physical_models import SHA256_PATTERN, canonical_digest
from .workload_identity import workload_key_id

MAX_ANCHOR_READBACK_LIFETIME = timedelta(seconds=60)
MAX_FENCE_GRANT_LIFETIME = timedelta(seconds=60)
_STREAM_PATTERN = r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,255}$"
_KEY_ID_PATTERN = r"^ed25519:[0-9a-f]{64}$"


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
    )


class LocalCoordinationProjection(_FrozenModel):
    """Exact local recovery state and the external fence that authorized it."""

    schema_version: Literal["m4i-local-anchor-projection-v1"] = (
        "m4i-local-anchor-projection-v1"
    )
    gateway_journal_sha256: str = Field(pattern=SHA256_PATTERN)
    ot_journal_sha256: str = Field(pattern=SHA256_PATTERN)
    plant_model_sha256: str = Field(pattern=SHA256_PATTERN)
    plant_state_version: int = Field(ge=0)
    plant_state_sha256: str = Field(pattern=SHA256_PATTERN)
    recovery_status: CoordinationRecoveryStatus
    recovery_reason: CoordinationRecoveryReason
    record_count: int = Field(ge=0)
    applied_effect_count: int = Field(ge=0)
    pending_effect_count: int = Field(ge=0, le=1)
    latest_applied_state_version: int | None = Field(default=None, ge=1)
    latest_applied_state_sha256: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
    )
    writer_fencing_token: int = Field(ge=0)
    based_on_anchor_sequence: int | None = Field(default=None, ge=0)
    based_on_anchor_sha256: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
    )

    @model_validator(mode="after")
    def require_closed_fence_lineage(self) -> Self:
        lineage = (
            self.based_on_anchor_sequence,
            self.based_on_anchor_sha256,
        )
        if self.writer_fencing_token == 0:
            if lineage != (None, None):
                raise ValueError("unfenced baseline cannot claim anchor lineage")
        elif None in lineage:
            raise ValueError("fenced local state requires exact anchor lineage")
        if (self.latest_applied_state_version is None) != (
            self.latest_applied_state_sha256 is None
        ):
            raise ValueError("latest applied state projection must be complete")
        if self.applied_effect_count == 0 and self.latest_applied_state_version is not None:
            raise ValueError("empty applied history cannot claim a latest applied state")
        if self.applied_effect_count > 0 and self.latest_applied_state_version is None:
            raise ValueError("applied history requires a latest applied state")
        if self.record_count < self.applied_effect_count + self.pending_effect_count:
            raise ValueError("record count cannot omit applied or pending effects")
        if self.recovery_status is CoordinationRecoveryStatus.ALIGNED:
            if self.pending_effect_count != 0:
                raise ValueError("aligned local state cannot retain a pending effect")
            if self.plant_state_version == 0:
                if self.recovery_reason is not CoordinationRecoveryReason.ALIGNED_EMPTY_BASELINE:
                    raise ValueError("zero-state alignment requires the empty baseline reason")
            elif self.recovery_reason is not CoordinationRecoveryReason.ALIGNED_APPLIED_CHAIN:
                raise ValueError("nonzero alignment requires the applied-chain reason")
        return self

    @classmethod
    def from_recovery(
        cls,
        recovery: CoordinationRecoveryResult,
        *,
        gateway_journal_sha256: str,
        ot_journal_sha256: str,
        plant_model_sha256: str,
        writer_fencing_token: int,
        based_on_anchor_sequence: int | None = None,
        based_on_anchor_sha256: str | None = None,
    ) -> LocalCoordinationProjection:
        """Bind an already validated M4i recovery result to exact local bytes."""

        return cls(
            gateway_journal_sha256=gateway_journal_sha256,
            ot_journal_sha256=ot_journal_sha256,
            plant_model_sha256=plant_model_sha256,
            plant_state_version=recovery.plant_state_version,
            plant_state_sha256=recovery.plant_state_digest,
            recovery_status=recovery.status,
            recovery_reason=recovery.reason,
            record_count=recovery.record_count,
            applied_effect_count=recovery.applied_effect_count,
            pending_effect_count=recovery.pending_effect_count,
            latest_applied_state_version=recovery.latest_applied_state_version,
            latest_applied_state_sha256=recovery.latest_applied_state_digest,
            writer_fencing_token=writer_fencing_token,
            based_on_anchor_sequence=based_on_anchor_sequence,
            based_on_anchor_sha256=based_on_anchor_sha256,
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class SignedCoordinationAnchor(_FrozenModel):
    """Authority-signed monotonic checkpoint outside the local rollback domain."""

    schema_version: Literal["m4i-signed-coordination-anchor-v1"] = (
        "m4i-signed-coordination-anchor-v1"
    )
    stream_id: str = Field(pattern=_STREAM_PATTERN)
    anchor_sequence: int = Field(ge=0)
    fencing_token: int = Field(ge=0)
    previous_anchor_sha256: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
    )
    projection: LocalCoordinationProjection
    authority_key_id: str = Field(pattern=_KEY_ID_PATTERN)
    issued_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_monotonic_shape(self) -> Self:
        if not _aware(self.issued_at):
            raise ValueError("anchor issuance time must be timezone-aware")
        if self.projection.recovery_status is not CoordinationRecoveryStatus.ALIGNED:
            raise ValueError("only an aligned local recovery state may be anchored")
        if self.anchor_sequence == 0:
            if self.previous_anchor_sha256 is not None or self.fencing_token != 0:
                raise ValueError("genesis anchor must use the unfenced zero lineage")
            if self.projection.writer_fencing_token != 0:
                raise ValueError("genesis projection must be unfenced")
        else:
            if self.previous_anchor_sha256 is None or self.fencing_token < 1:
                raise ValueError("non-genesis anchor requires predecessor and fence")
            if (
                self.projection.writer_fencing_token != self.fencing_token
                or self.projection.based_on_anchor_sequence != self.anchor_sequence - 1
                or self.projection.based_on_anchor_sha256
                != self.previous_anchor_sha256
            ):
                raise ValueError("anchored projection does not bind its writer fence")
        return self

    def signing_payload(self) -> bytes:
        material = self.model_dump(mode="json", exclude={"signature"})
        return _canonical_bytes(material)

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return (
            self.authority_key_id == workload_key_id(public_key)
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )

    @classmethod
    def issue(
        cls,
        *,
        stream_id: str,
        anchor_sequence: int,
        fencing_token: int,
        previous_anchor_sha256: str | None,
        projection: LocalCoordinationProjection,
        authority_private_key: Ed25519PrivateKey,
        issued_at: datetime,
    ) -> SignedCoordinationAnchor:
        provisional = cls(
            stream_id=stream_id,
            anchor_sequence=anchor_sequence,
            fencing_token=fencing_token,
            previous_anchor_sha256=previous_anchor_sha256,
            projection=projection,
            authority_key_id=workload_key_id(authority_private_key.public_key()),
            issued_at=issued_at,
        )
        return provisional.model_copy(
            update={
                "signature": sign_bytes(
                    authority_private_key,
                    provisional.signing_payload(),
                )
            }
        )


class CoordinationAnchorReadback(_FrozenModel):
    """Fresh nonce-bound authority assertion of the current checkpoint and fence."""

    schema_version: Literal["m4i-coordination-anchor-readback-v1"] = (
        "m4i-coordination-anchor-readback-v1"
    )
    request_nonce: str = Field(min_length=16, max_length=256)
    anchor: SignedCoordinationAnchor
    authority_fencing_token: int = Field(ge=0)
    authority_key_id: str = Field(pattern=_KEY_ID_PATTERN)
    read_at: datetime
    expires_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_bounded_readback(self) -> Self:
        if not _aware(self.read_at) or not _aware(self.expires_at):
            raise ValueError("anchor readback times must be timezone-aware")
        if self.expires_at <= self.read_at:
            raise ValueError("anchor readback must expire after issuance")
        if self.expires_at - self.read_at > MAX_ANCHOR_READBACK_LIFETIME:
            raise ValueError("anchor readback lifetime exceeds the closed bound")
        if self.authority_fencing_token < self.anchor.fencing_token:
            raise ValueError("authority fence watermark cannot precede its checkpoint")
        if self.authority_key_id != self.anchor.authority_key_id:
            raise ValueError("readback and checkpoint authorities differ")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_bytes(self.model_dump(mode="json", exclude={"signature"}))

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return (
            self.authority_key_id == workload_key_id(public_key)
            and self.anchor.verify(public_key)
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )

    def valid_at(self, evaluated_at: datetime) -> bool:
        return _aware(evaluated_at) and self.read_at <= evaluated_at < self.expires_at

    @classmethod
    def issue(
        cls,
        *,
        request_nonce: str,
        anchor: SignedCoordinationAnchor,
        authority_fencing_token: int,
        authority_private_key: Ed25519PrivateKey,
        read_at: datetime,
        expires_at: datetime,
    ) -> CoordinationAnchorReadback:
        provisional = cls(
            request_nonce=request_nonce,
            anchor=anchor,
            authority_fencing_token=authority_fencing_token,
            authority_key_id=workload_key_id(authority_private_key.public_key()),
            read_at=read_at,
            expires_at=expires_at,
        )
        return provisional.model_copy(
            update={
                "signature": sign_bytes(
                    authority_private_key,
                    provisional.signing_payload(),
                )
            }
        )


class CoordinationFenceGrant(_FrozenModel):
    """Short-lived authority grant for one physical-writer fencing epoch."""

    schema_version: Literal["m4i-coordination-fence-grant-v1"] = (
        "m4i-coordination-fence-grant-v1"
    )
    stream_id: str = Field(pattern=_STREAM_PATTERN)
    holder_id: str = Field(min_length=1, max_length=256)
    request_nonce: str = Field(min_length=16, max_length=256)
    based_on_anchor_sequence: int = Field(ge=0)
    based_on_anchor_sha256: str = Field(pattern=SHA256_PATTERN)
    fencing_token: int = Field(ge=1)
    authority_key_id: str = Field(pattern=_KEY_ID_PATTERN)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_bounded_grant(self) -> Self:
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("fence grant times must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("fence grant must expire after issuance")
        if self.expires_at - self.issued_at > MAX_FENCE_GRANT_LIFETIME:
            raise ValueError("fence grant lifetime exceeds the closed bound")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_bytes(self.model_dump(mode="json", exclude={"signature"}))

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return (
            self.authority_key_id == workload_key_id(public_key)
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )

    def valid_at(self, evaluated_at: datetime) -> bool:
        return _aware(evaluated_at) and self.issued_at <= evaluated_at < self.expires_at

    @classmethod
    def issue(
        cls,
        *,
        stream_id: str,
        holder_id: str,
        request_nonce: str,
        anchor: SignedCoordinationAnchor,
        fencing_token: int,
        authority_private_key: Ed25519PrivateKey,
        issued_at: datetime,
        expires_at: datetime,
    ) -> CoordinationFenceGrant:
        provisional = cls(
            stream_id=stream_id,
            holder_id=holder_id,
            request_nonce=request_nonce,
            based_on_anchor_sequence=anchor.anchor_sequence,
            based_on_anchor_sha256=anchor.digest,
            fencing_token=fencing_token,
            authority_key_id=workload_key_id(authority_private_key.public_key()),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return provisional.model_copy(
            update={
                "signature": sign_bytes(
                    authority_private_key,
                    provisional.signing_payload(),
                )
            }
        )


class TrustedAnchorFloor(_FrozenModel):
    """Locally retained minimum accepted authority state used to catch equivocation."""

    schema_version: Literal["m4i-trusted-anchor-floor-v1"] = (
        "m4i-trusted-anchor-floor-v1"
    )
    stream_id: str = Field(pattern=_STREAM_PATTERN)
    anchor_sequence: int = Field(ge=0)
    anchor_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_fencing_token: int = Field(ge=0)

    @classmethod
    def from_readback(cls, readback: CoordinationAnchorReadback) -> TrustedAnchorFloor:
        return cls(
            stream_id=readback.anchor.stream_id,
            anchor_sequence=readback.anchor.anchor_sequence,
            anchor_sha256=readback.anchor.digest,
            authority_fencing_token=readback.authority_fencing_token,
        )


class AnchoredRecoveryStatus(StrEnum):
    """Closed disposition for external-anchor readback and admission."""

    ALIGNED = "aligned"
    ADMISSION_READY = "admission_ready"
    RECOVERY_REQUIRED = "recovery_required"
    INCONSISTENT = "inconsistent"
    UNAVAILABLE = "unavailable"


class AnchoredRecoveryReason(StrEnum):
    """Stable reason codes for every external-anchor disposition."""

    ALIGNED_TO_CURRENT_ANCHOR = "aligned_to_current_anchor"
    CURRENT_FENCE_ADMISSION_READY = "current_fence_admission_ready"
    LOCAL_ADVANCE_REQUIRES_ANCHOR = "local_advance_requires_anchor"
    LOCAL_RECOVERY_REQUIRED = "local_recovery_required"
    LOCAL_RECOVERY_FAIL_CLOSED = "local_recovery_fail_closed"
    ANCHOR_UNAVAILABLE = "anchor_unavailable"
    ANCHOR_READBACK_INVALID = "anchor_readback_invalid"
    ANCHOR_READBACK_STALE = "anchor_readback_stale"
    ANCHOR_STREAM_CONFLICT = "anchor_stream_conflict"
    ANCHOR_SEQUENCE_STALE = "anchor_sequence_stale"
    ANCHOR_EQUIVOCATION = "anchor_equivocation"
    ANCHOR_CHAIN_GAP = "anchor_chain_gap"
    ANCHOR_CHAIN_CONFLICT = "anchor_chain_conflict"
    COORDINATED_ROLLBACK_DETECTED = "coordinated_rollback_detected"
    ANCHORED_STATE_CONFLICT = "anchored_state_conflict"
    UNRECOGNIZED_LOCAL_FENCE = "unrecognized_local_fence"
    FENCE_REQUIRED = "fence_required"
    FENCE_INVALID = "fence_invalid"
    FENCE_STALE = "fence_stale"
    FENCE_CONFLICT = "fence_conflict"


class AnchoredRecoveryDecision(_FrozenModel):
    """Deterministic, serializable result of one anchor readback decision."""

    schema_version: Literal["m4i-anchored-recovery-decision-v1"] = (
        "m4i-anchored-recovery-decision-v1"
    )
    status: AnchoredRecoveryStatus
    reason: AnchoredRecoveryReason
    admission_allowed: bool
    anchor_sequence: int | None = Field(default=None, ge=0)
    authority_fencing_token: int | None = Field(default=None, ge=0)
    local_fencing_token: int = Field(ge=0)

    @model_validator(mode="after")
    def require_fail_closed_admission(self) -> Self:
        if self.admission_allowed != (
            self.status is AnchoredRecoveryStatus.ADMISSION_READY
        ):
            raise ValueError("only an admission-ready decision may authorize admission")
        return self

    @property
    def fail_closed(self) -> bool:
        return not self.admission_allowed


class CoordinationAnchorAdmissionPhase(StrEnum):
    """Consequential M4i phases that must cross the configured anchor guard."""

    PREPARE = "prepare"
    COMMIT = "commit"


class BoundCoordinationAnchorAdmissionDecision(_FrozenModel):
    """One recovery decision bound to the exact consequential runtime call.

    The external decision adapter must construct this envelope from the fresh
    readback evaluated for the supplied call.  The admission guard rejects a
    cached or replayed ready decision whose phase, effect, request digest, or
    evaluation instant differs from the current call.
    """

    schema_version: Literal["m4i-bound-anchor-admission-decision-v1"] = (
        "m4i-bound-anchor-admission-decision-v1"
    )
    phase: CoordinationAnchorAdmissionPhase
    effect_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    evaluated_at: datetime
    decision: AnchoredRecoveryDecision

    @model_validator(mode="after")
    def require_aware_evaluation_instant(self) -> Self:
        if not _aware(self.evaluated_at):
            raise ValueError("anchor admission evaluation instant must be timezone-aware")
        return self


class CoordinationAnchorAdmissionError(RuntimeError):
    """External-anchor admission was unavailable or did not authorize execution."""


class CoordinationAnchorDecisionSource(Protocol):
    """Adapter seam that resolves fresh external state for one runtime request."""

    def __call__(
        self,
        *,
        phase: CoordinationAnchorAdmissionPhase,
        effect_id: str,
        request_sha256: str,
        evaluated_at: datetime,
    ) -> BoundCoordinationAnchorAdmissionDecision: ...


class CoordinationAnchorAdmissionPort(Protocol):
    """Narrow fail-closed port consumed by the current M4i OT runtime."""

    def require_admission(
        self,
        *,
        phase: CoordinationAnchorAdmissionPhase,
        effect_id: str,
        request_sha256: str,
        evaluated_at: datetime,
    ) -> AnchoredRecoveryDecision: ...


class FailClosedCoordinationAnchorAdmission:
    """Convert an authority decision source into a strict runtime admission port.

    A deployment adapter supplies the decision source and is responsible for
    fresh external readback, local projection construction, fence retention,
    and bounded I/O.  Exceptions, malformed decisions, and every disposition
    other than ``admission_ready`` deny the prepare or commit before journal
    admission and before the physical writer is invoked.
    """

    def __init__(self, decision_source: CoordinationAnchorDecisionSource) -> None:
        self._decision_source = decision_source

    def require_admission(
        self,
        *,
        phase: CoordinationAnchorAdmissionPhase,
        effect_id: str,
        request_sha256: str,
        evaluated_at: datetime,
    ) -> AnchoredRecoveryDecision:
        try:
            decision = self._decision_source(
                phase=phase,
                effect_id=effect_id,
                request_sha256=request_sha256,
                evaluated_at=evaluated_at,
            )
        except Exception as exc:
            raise CoordinationAnchorAdmissionError(
                f"anchor_{phase.value}_decision_unavailable"
            ) from exc
        if not isinstance(decision, BoundCoordinationAnchorAdmissionDecision):
            raise CoordinationAnchorAdmissionError(
                f"anchor_{phase.value}_decision_invalid"
            )
        if (
            decision.phase is not phase
            or decision.effect_id != effect_id
            or decision.request_sha256 != request_sha256
            or decision.evaluated_at != evaluated_at
        ):
            raise CoordinationAnchorAdmissionError(
                f"anchor_{phase.value}_decision_binding_mismatch"
            )
        recovery = decision.decision
        if (
            recovery.status is not AnchoredRecoveryStatus.ADMISSION_READY
            or not recovery.admission_allowed
        ):
            raise CoordinationAnchorAdmissionError(
                f"anchor_{phase.value}_denied:{recovery.reason.value}"
            )
        return recovery


def _canonical_bytes(value: object) -> bytes:
    import json

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _decision(
    status: AnchoredRecoveryStatus,
    reason: AnchoredRecoveryReason,
    local: LocalCoordinationProjection,
    readback: CoordinationAnchorReadback | None,
) -> AnchoredRecoveryDecision:
    return AnchoredRecoveryDecision(
        status=status,
        reason=reason,
        admission_allowed=status is AnchoredRecoveryStatus.ADMISSION_READY,
        anchor_sequence=(
            None if readback is None else readback.anchor.anchor_sequence
        ),
        authority_fencing_token=(
            None if readback is None else readback.authority_fencing_token
        ),
        local_fencing_token=local.writer_fencing_token,
    )


def _valid_floor(
    readback: CoordinationAnchorReadback,
    floor: TrustedAnchorFloor | None,
) -> AnchoredRecoveryReason | None:
    if floor is None:
        return None
    anchor = readback.anchor
    if floor.stream_id != anchor.stream_id:
        return AnchoredRecoveryReason.ANCHOR_STREAM_CONFLICT
    if anchor.anchor_sequence < floor.anchor_sequence:
        return AnchoredRecoveryReason.ANCHOR_SEQUENCE_STALE
    if readback.authority_fencing_token < floor.authority_fencing_token:
        return AnchoredRecoveryReason.ANCHOR_SEQUENCE_STALE
    if anchor.anchor_sequence == floor.anchor_sequence:
        if anchor.digest != floor.anchor_sha256:
            return AnchoredRecoveryReason.ANCHOR_EQUIVOCATION
        return None
    if anchor.anchor_sequence > floor.anchor_sequence + 1:
        return AnchoredRecoveryReason.ANCHOR_CHAIN_GAP
    if anchor.previous_anchor_sha256 != floor.anchor_sha256:
        return AnchoredRecoveryReason.ANCHOR_CHAIN_CONFLICT
    return None


def _valid_fence(
    *,
    fence: CoordinationFenceGrant | None,
    readback: CoordinationAnchorReadback,
    authority_public_key: Ed25519PublicKey,
    evaluated_at: datetime,
) -> AnchoredRecoveryReason | None:
    if fence is None:
        return AnchoredRecoveryReason.FENCE_REQUIRED
    anchor = readback.anchor
    if not fence.verify(authority_public_key):
        return AnchoredRecoveryReason.FENCE_INVALID
    if not fence.valid_at(evaluated_at):
        return AnchoredRecoveryReason.FENCE_STALE
    if (
        fence.stream_id != anchor.stream_id
        or fence.based_on_anchor_sequence != anchor.anchor_sequence
        or fence.based_on_anchor_sha256 != anchor.digest
    ):
        return AnchoredRecoveryReason.FENCE_CONFLICT
    if (
        fence.fencing_token != readback.authority_fencing_token
        or fence.fencing_token <= anchor.fencing_token
    ):
        return AnchoredRecoveryReason.FENCE_STALE
    return None


def validate_anchored_coordination_recovery(
    local: LocalCoordinationProjection,
    *,
    readback: CoordinationAnchorReadback | None,
    expected_stream_id: str,
    expected_request_nonce: str,
    authority_public_key: Ed25519PublicKey,
    evaluated_at: datetime,
    trusted_floor: TrustedAnchorFloor | None = None,
    fence: CoordinationFenceGrant | None = None,
    require_fence: bool = False,
) -> AnchoredRecoveryDecision:
    """Validate fresh external state before recovery or consequential admission.

    An aligned result authorizes readback only.  Consequential admission is
    authorized solely when ``require_fence`` is true and the supplied grant is
    the authority's current, fresh fence bound to the exact current anchor.
    """

    if local.recovery_status in {
        CoordinationRecoveryStatus.INCONSISTENT,
        CoordinationRecoveryStatus.UNAVAILABLE,
    }:
        return _decision(
            AnchoredRecoveryStatus.INCONSISTENT,
            AnchoredRecoveryReason.LOCAL_RECOVERY_FAIL_CLOSED,
            local,
            readback,
        )
    if readback is None:
        return _decision(
            AnchoredRecoveryStatus.UNAVAILABLE,
            AnchoredRecoveryReason.ANCHOR_UNAVAILABLE,
            local,
            None,
        )
    if readback.anchor.stream_id != expected_stream_id:
        return _decision(
            AnchoredRecoveryStatus.INCONSISTENT,
            AnchoredRecoveryReason.ANCHOR_STREAM_CONFLICT,
            local,
            readback,
        )
    if (
        readback.request_nonce != expected_request_nonce
        or not readback.verify(authority_public_key)
    ):
        return _decision(
            AnchoredRecoveryStatus.UNAVAILABLE,
            AnchoredRecoveryReason.ANCHOR_READBACK_INVALID,
            local,
            readback,
        )
    if not readback.valid_at(evaluated_at):
        return _decision(
            AnchoredRecoveryStatus.UNAVAILABLE,
            AnchoredRecoveryReason.ANCHOR_READBACK_STALE,
            local,
            readback,
        )
    floor_failure = _valid_floor(readback, trusted_floor)
    if floor_failure is not None:
        status = (
            AnchoredRecoveryStatus.UNAVAILABLE
            if floor_failure
            in {
                AnchoredRecoveryReason.ANCHOR_SEQUENCE_STALE,
                AnchoredRecoveryReason.ANCHOR_CHAIN_GAP,
            }
            else AnchoredRecoveryStatus.INCONSISTENT
        )
        return _decision(status, floor_failure, local, readback)

    anchor = readback.anchor
    anchored = anchor.projection
    if local.digest == anchored.digest:
        if not require_fence:
            return _decision(
                AnchoredRecoveryStatus.ALIGNED,
                AnchoredRecoveryReason.ALIGNED_TO_CURRENT_ANCHOR,
                local,
                readback,
            )
        fence_failure = _valid_fence(
            fence=fence,
            readback=readback,
            authority_public_key=authority_public_key,
            evaluated_at=evaluated_at,
        )
        if fence_failure is not None:
            status = (
                AnchoredRecoveryStatus.UNAVAILABLE
                if fence_failure
                in {
                    AnchoredRecoveryReason.FENCE_REQUIRED,
                    AnchoredRecoveryReason.FENCE_INVALID,
                    AnchoredRecoveryReason.FENCE_STALE,
                }
                else AnchoredRecoveryStatus.INCONSISTENT
            )
            return _decision(status, fence_failure, local, readback)
        return _decision(
            AnchoredRecoveryStatus.ADMISSION_READY,
            AnchoredRecoveryReason.CURRENT_FENCE_ADMISSION_READY,
            local,
            readback,
        )

    if (
        local.writer_fencing_token < anchored.writer_fencing_token
        or local.plant_state_version < anchored.plant_state_version
    ):
        return _decision(
            AnchoredRecoveryStatus.INCONSISTENT,
            AnchoredRecoveryReason.COORDINATED_ROLLBACK_DETECTED,
            local,
            readback,
        )
    if local.plant_model_sha256 != anchored.plant_model_sha256 or (
        local.plant_state_version == anchored.plant_state_version
        and local.plant_state_sha256 != anchored.plant_state_sha256
    ):
        return _decision(
            AnchoredRecoveryStatus.INCONSISTENT,
            AnchoredRecoveryReason.ANCHORED_STATE_CONFLICT,
            local,
            readback,
        )
    if local.writer_fencing_token == anchored.writer_fencing_token:
        return _decision(
            AnchoredRecoveryStatus.INCONSISTENT,
            AnchoredRecoveryReason.ANCHORED_STATE_CONFLICT,
            local,
            readback,
        )
    if local.writer_fencing_token != readback.authority_fencing_token:
        return _decision(
            AnchoredRecoveryStatus.INCONSISTENT,
            AnchoredRecoveryReason.UNRECOGNIZED_LOCAL_FENCE,
            local,
            readback,
        )
    if (
        local.based_on_anchor_sequence != anchor.anchor_sequence
        or local.based_on_anchor_sha256 != anchor.digest
    ):
        return _decision(
            AnchoredRecoveryStatus.INCONSISTENT,
            AnchoredRecoveryReason.FENCE_CONFLICT,
            local,
            readback,
        )
    reason = (
        AnchoredRecoveryReason.LOCAL_RECOVERY_REQUIRED
        if local.recovery_status is CoordinationRecoveryStatus.RECOVERY_REQUIRED
        else AnchoredRecoveryReason.LOCAL_ADVANCE_REQUIRES_ANCHOR
    )
    return _decision(
        AnchoredRecoveryStatus.RECOVERY_REQUIRED,
        reason,
        local,
        readback,
    )


class AnchorAuthorityError(RuntimeError):
    """The reference authority rejected an unavailable or conflicting operation."""


class ExternalCoordinationAnchor(Protocol):
    """Deployment boundary for a separately administered monotonic authority."""

    @property
    def public_key(self) -> Ed25519PublicKey: ...

    def readback(
        self,
        *,
        request_nonce: str,
        read_at: datetime,
        lifetime: timedelta = MAX_ANCHOR_READBACK_LIFETIME,
    ) -> CoordinationAnchorReadback: ...

    def acquire_fence(
        self,
        *,
        holder_id: str,
        request_nonce: str,
        expected_anchor_sha256: str,
        issued_at: datetime,
        lifetime: timedelta = MAX_FENCE_GRANT_LIFETIME,
    ) -> CoordinationFenceGrant: ...

    def compare_and_advance(
        self,
        *,
        expected_anchor_sha256: str,
        projection: LocalCoordinationProjection,
        fence: CoordinationFenceGrant,
        advanced_at: datetime,
    ) -> SignedCoordinationAnchor: ...


class InMemoryMonotonicAnchorReference:
    """Executable single-process model of the external authority contract."""

    def __init__(
        self,
        *,
        stream_id: str,
        genesis: LocalCoordinationProjection,
        authority_private_key: Ed25519PrivateKey,
        initialized_at: datetime,
    ) -> None:
        self._private_key = authority_private_key
        self._lock = RLock()
        self._anchor = SignedCoordinationAnchor.issue(
            stream_id=stream_id,
            anchor_sequence=0,
            fencing_token=0,
            previous_anchor_sha256=None,
            projection=genesis,
            authority_private_key=authority_private_key,
            issued_at=initialized_at,
        )
        self._fencing_token = 0

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    @property
    def current_anchor(self) -> SignedCoordinationAnchor:
        with self._lock:
            return self._anchor

    def readback(
        self,
        *,
        request_nonce: str,
        read_at: datetime,
        lifetime: timedelta = MAX_ANCHOR_READBACK_LIFETIME,
    ) -> CoordinationAnchorReadback:
        with self._lock:
            return CoordinationAnchorReadback.issue(
                request_nonce=request_nonce,
                anchor=self._anchor,
                authority_fencing_token=self._fencing_token,
                authority_private_key=self._private_key,
                read_at=read_at,
                expires_at=read_at + lifetime,
            )

    def acquire_fence(
        self,
        *,
        holder_id: str,
        request_nonce: str,
        expected_anchor_sha256: str,
        issued_at: datetime,
        lifetime: timedelta = MAX_FENCE_GRANT_LIFETIME,
    ) -> CoordinationFenceGrant:
        with self._lock:
            if expected_anchor_sha256 != self._anchor.digest:
                raise AnchorAuthorityError("anchor compare failed before fence issuance")
            next_fencing_token = self._fencing_token + 1
            grant = CoordinationFenceGrant.issue(
                stream_id=self._anchor.stream_id,
                holder_id=holder_id,
                request_nonce=request_nonce,
                anchor=self._anchor,
                fencing_token=next_fencing_token,
                authority_private_key=self._private_key,
                issued_at=issued_at,
                expires_at=issued_at + lifetime,
            )
            self._fencing_token = next_fencing_token
            return grant

    def compare_and_advance(
        self,
        *,
        expected_anchor_sha256: str,
        projection: LocalCoordinationProjection,
        fence: CoordinationFenceGrant,
        advanced_at: datetime,
    ) -> SignedCoordinationAnchor:
        with self._lock:
            current = self._anchor
            if expected_anchor_sha256 != current.digest:
                raise AnchorAuthorityError("anchor compare-and-advance used stale state")
            if not _aware(advanced_at) or advanced_at < current.issued_at:
                raise AnchorAuthorityError("anchor advance time was invalid or regressed")
            if (
                not fence.verify(self.public_key)
                or not fence.valid_at(advanced_at)
                or fence.stream_id != current.stream_id
                or fence.based_on_anchor_sequence != current.anchor_sequence
                or fence.based_on_anchor_sha256 != current.digest
                or fence.fencing_token != self._fencing_token
                or fence.fencing_token <= current.fencing_token
            ):
                raise AnchorAuthorityError("anchor compare-and-advance fence was invalid")
            if (
                projection.recovery_status is not CoordinationRecoveryStatus.ALIGNED
                or projection.writer_fencing_token != fence.fencing_token
                or projection.based_on_anchor_sequence != current.anchor_sequence
                or projection.based_on_anchor_sha256 != current.digest
                or projection.plant_model_sha256
                != current.projection.plant_model_sha256
                or projection.plant_state_version
                < current.projection.plant_state_version
                or (
                    projection.plant_state_version
                    == current.projection.plant_state_version
                    and projection.plant_state_sha256
                    != current.projection.plant_state_sha256
                )
            ):
                raise AnchorAuthorityError("candidate anchor projection was not monotonic")
            advanced = SignedCoordinationAnchor.issue(
                stream_id=current.stream_id,
                anchor_sequence=current.anchor_sequence + 1,
                fencing_token=fence.fencing_token,
                previous_anchor_sha256=current.digest,
                projection=projection,
                authority_private_key=self._private_key,
                issued_at=advanced_at,
            )
            self._anchor = advanced
            return advanced
