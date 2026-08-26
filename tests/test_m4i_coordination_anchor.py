from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from aegis_ot.coordination_anchor import (
    AnchorAuthorityError,
    AnchoredRecoveryDecision,
    AnchoredRecoveryReason,
    AnchoredRecoveryStatus,
    CoordinationAnchorReadback,
    CoordinationFenceGrant,
    InMemoryMonotonicAnchorReference,
    LocalCoordinationProjection,
    SignedCoordinationAnchor,
    TrustedAnchorFloor,
    validate_anchored_coordination_recovery,
)
from aegis_ot.coordination_recovery import (
    CoordinationRecoveryReason,
    CoordinationRecoveryResult,
    CoordinationRecoveryStatus,
)

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
STREAM = "aegis-ot:m4i:test-plant"
READ_NONCE = "anchor-readback-nonce-0001"


def _projection(
    version: int,
    *,
    token: int = 0,
    based_on_sequence: int | None = None,
    based_on_sha256: str | None = None,
    journal_marker: str | None = None,
    state_marker: str | None = None,
    status: CoordinationRecoveryStatus = CoordinationRecoveryStatus.ALIGNED,
) -> LocalCoordinationProjection:
    marker = journal_marker or str(version + 1)
    state = state_marker or chr(ord("a") + version)
    if status is CoordinationRecoveryStatus.ALIGNED:
        reason = (
            CoordinationRecoveryReason.ALIGNED_EMPTY_BASELINE
            if version == 0
            else CoordinationRecoveryReason.ALIGNED_APPLIED_CHAIN
        )
        pending = 0
    else:
        reason = CoordinationRecoveryReason.PENDING_EFFECT_AT_PRE_STATE
        pending = 1
    applied = version
    recovery = CoordinationRecoveryResult(
        status=status,
        reason=reason,
        record_count=applied + pending,
        applied_effect_count=applied,
        pending_effect_count=pending,
        plant_state_version=version,
        plant_state_digest=state * 64,
        latest_applied_state_version=version if applied else None,
        latest_applied_state_digest=state * 64 if applied else None,
    )
    return LocalCoordinationProjection.from_recovery(
        recovery,
        gateway_journal_sha256=marker * 64,
        ot_journal_sha256=marker.lower() * 64,
        plant_model_sha256="f" * 64,
        writer_fencing_token=token,
        based_on_anchor_sequence=based_on_sequence,
        based_on_anchor_sha256=based_on_sha256,
    )


@pytest.fixture
def authority() -> InMemoryMonotonicAnchorReference:
    return InMemoryMonotonicAnchorReference(
        stream_id=STREAM,
        genesis=_projection(0),
        authority_private_key=Ed25519PrivateKey.from_private_bytes(b"a" * 32),
        initialized_at=NOW,
    )


def _decision(
    authority: InMemoryMonotonicAnchorReference,
    local: LocalCoordinationProjection,
    readback: CoordinationAnchorReadback | None,
    *,
    when: datetime = NOW + timedelta(seconds=2),
    floor: TrustedAnchorFloor | None = None,
    fence: CoordinationFenceGrant | None = None,
    require_fence: bool = False,
) -> AnchoredRecoveryDecision:
    return validate_anchored_coordination_recovery(
        local,
        readback=readback,
        expected_stream_id=STREAM,
        expected_request_nonce=READ_NONCE,
        authority_public_key=authority.public_key,
        evaluated_at=when,
        trusted_floor=floor,
        fence=fence,
        require_fence=require_fence,
    )


def test_fresh_readback_aligns_but_only_current_fence_allows_admission(
    authority: InMemoryMonotonicAnchorReference,
) -> None:
    local = _projection(0)
    initial = authority.readback(request_nonce=READ_NONCE, read_at=NOW)

    aligned = _decision(authority, local, initial)
    unfenced = _decision(authority, local, initial, require_fence=True)
    grant = authority.acquire_fence(
        holder_id="ot-writer:test",
        request_nonce="fence-request-nonce-0001",
        expected_anchor_sha256=initial.anchor.digest,
        issued_at=NOW + timedelta(seconds=1),
    )
    current = authority.readback(request_nonce=READ_NONCE, read_at=NOW + timedelta(seconds=1))
    admitted = _decision(
        authority,
        local,
        current,
        fence=grant,
        require_fence=True,
    )

    assert aligned.status is AnchoredRecoveryStatus.ALIGNED
    assert aligned.admission_allowed is False
    assert unfenced.reason is AnchoredRecoveryReason.FENCE_REQUIRED
    assert admitted.status is AnchoredRecoveryStatus.ADMISSION_READY
    assert admitted.admission_allowed is True


def test_compare_and_advance_supports_readback_then_detects_coordinated_rollback(
    authority: InMemoryMonotonicAnchorReference,
) -> None:
    initial = authority.readback(request_nonce=READ_NONCE, read_at=NOW)
    floor = TrustedAnchorFloor.from_readback(initial)
    grant = authority.acquire_fence(
        holder_id="ot-writer:test",
        request_nonce="fence-request-nonce-0002",
        expected_anchor_sha256=initial.anchor.digest,
        issued_at=NOW + timedelta(seconds=1),
    )
    advanced_local = _projection(
        1,
        token=grant.fencing_token,
        based_on_sequence=initial.anchor.anchor_sequence,
        based_on_sha256=initial.anchor.digest,
        journal_marker="b",
    )
    before_anchor = authority.readback(
        request_nonce=READ_NONCE,
        read_at=NOW + timedelta(seconds=2),
    )
    recovery = _decision(authority, advanced_local, before_anchor)
    advanced = authority.compare_and_advance(
        expected_anchor_sha256=initial.anchor.digest,
        projection=advanced_local,
        fence=grant,
        advanced_at=NOW + timedelta(seconds=3),
    )
    readback = authority.readback(
        request_nonce=READ_NONCE,
        read_at=NOW + timedelta(seconds=4),
    )

    aligned = _decision(
        authority,
        advanced_local,
        readback,
        floor=floor,
        when=NOW + timedelta(seconds=5),
    )
    rolled_back = _decision(authority, _projection(0), readback, when=NOW + timedelta(seconds=5))

    assert recovery.status is AnchoredRecoveryStatus.RECOVERY_REQUIRED
    assert recovery.reason is AnchoredRecoveryReason.LOCAL_ADVANCE_REQUIRES_ANCHOR
    assert advanced.anchor_sequence == 1
    assert aligned.status is AnchoredRecoveryStatus.ALIGNED
    assert rolled_back.status is AnchoredRecoveryStatus.INCONSISTENT
    assert rolled_back.reason is AnchoredRecoveryReason.COORDINATED_ROLLBACK_DETECTED


def test_both_journals_rollback_at_same_plant_version_is_detected(
    authority: InMemoryMonotonicAnchorReference,
) -> None:
    initial = authority.current_anchor
    first = authority.acquire_fence(
        holder_id="ot-writer:test",
        request_nonce="fence-request-nonce-0003",
        expected_anchor_sha256=initial.digest,
        issued_at=NOW + timedelta(seconds=1),
    )
    journal_advanced = _projection(
        0,
        token=first.fencing_token,
        based_on_sequence=initial.anchor_sequence,
        based_on_sha256=initial.digest,
        journal_marker="c",
    )
    authority.compare_and_advance(
        expected_anchor_sha256=initial.digest,
        projection=journal_advanced,
        fence=first,
        advanced_at=NOW + timedelta(seconds=2),
    )
    readback = authority.readback(
        request_nonce=READ_NONCE,
        read_at=NOW + timedelta(seconds=3),
    )

    decision = _decision(
        authority,
        _projection(0),
        readback,
        when=NOW + timedelta(seconds=4),
    )

    assert decision.reason is AnchoredRecoveryReason.COORDINATED_ROLLBACK_DETECTED
    assert decision.fail_closed


def test_unavailable_stale_tampered_and_wrong_nonce_readback_fail_closed(
    authority: InMemoryMonotonicAnchorReference,
) -> None:
    local = _projection(0)
    readback = authority.readback(request_nonce=READ_NONCE, read_at=NOW)
    tampered = readback.model_copy(
        update={"authority_fencing_token": readback.authority_fencing_token + 1}
    )

    unavailable = _decision(authority, local, None)
    stale = _decision(authority, local, readback, when=NOW + timedelta(minutes=2))
    invalid = _decision(authority, local, tampered)
    wrong_nonce = validate_anchored_coordination_recovery(
        local,
        readback=readback,
        expected_stream_id=STREAM,
        expected_request_nonce="different-readback-nonce",
        authority_public_key=authority.public_key,
        evaluated_at=NOW + timedelta(seconds=2),
    )

    assert unavailable.reason is AnchoredRecoveryReason.ANCHOR_UNAVAILABLE
    assert stale.reason is AnchoredRecoveryReason.ANCHOR_READBACK_STALE
    assert invalid.reason is AnchoredRecoveryReason.ANCHOR_READBACK_INVALID
    assert wrong_nonce.reason is AnchoredRecoveryReason.ANCHOR_READBACK_INVALID
    assert all(item.fail_closed for item in (unavailable, stale, invalid, wrong_nonce))


def test_floor_rejects_stale_equivocating_and_chain_gap_readbacks(
    authority: InMemoryMonotonicAnchorReference,
) -> None:
    initial = authority.readback(request_nonce=READ_NONCE, read_at=NOW)
    floor = TrustedAnchorFloor.from_readback(initial)
    private_key = Ed25519PrivateKey.from_private_bytes(b"a" * 32)
    conflict_projection = _projection(
        0,
        token=1,
        based_on_sequence=0,
        based_on_sha256=initial.anchor.digest,
        journal_marker="d",
    )
    conflict_anchor = SignedCoordinationAnchor.issue(
        stream_id=STREAM,
        anchor_sequence=1,
        fencing_token=1,
        previous_anchor_sha256=initial.anchor.digest,
        projection=conflict_projection,
        authority_private_key=private_key,
        issued_at=NOW + timedelta(seconds=1),
    )
    conflict_readback = CoordinationAnchorReadback.issue(
        request_nonce=READ_NONCE,
        anchor=conflict_anchor,
        authority_fencing_token=1,
        authority_private_key=private_key,
        read_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=30),
    )
    conflict_floor = TrustedAnchorFloor(
        stream_id=STREAM,
        anchor_sequence=1,
        anchor_sha256="e" * 64,
        authority_fencing_token=1,
    )
    equivocation = _decision(
        authority,
        conflict_projection,
        conflict_readback,
        floor=conflict_floor,
    )
    chain_gap_floor = TrustedAnchorFloor(
        stream_id=STREAM,
        anchor_sequence=3,
        anchor_sha256="f" * 64,
        authority_fencing_token=3,
    )
    stale = _decision(authority, _projection(0), initial, floor=chain_gap_floor)

    assert floor.anchor_sequence == 0
    assert equivocation.reason is AnchoredRecoveryReason.ANCHOR_EQUIVOCATION
    assert stale.reason is AnchoredRecoveryReason.ANCHOR_SEQUENCE_STALE


def test_newer_fence_invalidates_prior_holder_and_stale_compare_and_advance(
    authority: InMemoryMonotonicAnchorReference,
) -> None:
    anchor = authority.current_anchor
    stale_grant = authority.acquire_fence(
        holder_id="ot-writer:old",
        request_nonce="fence-request-nonce-0004",
        expected_anchor_sha256=anchor.digest,
        issued_at=NOW + timedelta(seconds=1),
    )
    current_grant = authority.acquire_fence(
        holder_id="ot-writer:new",
        request_nonce="fence-request-nonce-0005",
        expected_anchor_sha256=anchor.digest,
        issued_at=NOW + timedelta(seconds=2),
    )
    readback = authority.readback(
        request_nonce=READ_NONCE,
        read_at=NOW + timedelta(seconds=2),
    )

    rejected = _decision(
        authority,
        _projection(0),
        readback,
        when=NOW + timedelta(seconds=3),
        fence=stale_grant,
        require_fence=True,
    )
    admitted = _decision(
        authority,
        _projection(0),
        readback,
        when=NOW + timedelta(seconds=3),
        fence=current_grant,
        require_fence=True,
    )
    stale_local = _projection(
        1,
        token=stale_grant.fencing_token,
        based_on_sequence=anchor.anchor_sequence,
        based_on_sha256=anchor.digest,
    )
    with pytest.raises(AnchorAuthorityError, match="fence was invalid"):
        authority.compare_and_advance(
            expected_anchor_sha256=anchor.digest,
            projection=stale_local,
            fence=stale_grant,
            advanced_at=NOW + timedelta(seconds=3),
        )

    assert rejected.reason is AnchoredRecoveryReason.FENCE_STALE
    assert admitted.status is AnchoredRecoveryStatus.ADMISSION_READY


def test_reference_authority_rejects_stale_cas_and_nonmonotonic_plant_state(
    authority: InMemoryMonotonicAnchorReference,
) -> None:
    genesis = authority.current_anchor
    grant = authority.acquire_fence(
        holder_id="ot-writer:test",
        request_nonce="fence-request-nonce-0006",
        expected_anchor_sha256=genesis.digest,
        issued_at=NOW + timedelta(seconds=1),
    )
    advanced_local = _projection(
        1,
        token=grant.fencing_token,
        based_on_sequence=0,
        based_on_sha256=genesis.digest,
    )
    authority.compare_and_advance(
        expected_anchor_sha256=genesis.digest,
        projection=advanced_local,
        fence=grant,
        advanced_at=NOW + timedelta(seconds=2),
    )

    with pytest.raises(AnchorAuthorityError, match="stale state"):
        authority.compare_and_advance(
            expected_anchor_sha256=genesis.digest,
            projection=advanced_local,
            fence=grant,
            advanced_at=NOW + timedelta(seconds=3),
        )


def test_anchor_models_reject_unbounded_lifetimes_and_incomplete_lineage() -> None:
    with pytest.raises(ValidationError, match="requires exact anchor lineage"):
        _projection(1, token=1)
    with pytest.raises(ValidationError, match="lifetime exceeds"):
        CoordinationAnchorReadback.issue(
            request_nonce=READ_NONCE,
            anchor=SignedCoordinationAnchor.issue(
                stream_id=STREAM,
                anchor_sequence=0,
                fencing_token=0,
                previous_anchor_sha256=None,
                projection=_projection(0),
                authority_private_key=Ed25519PrivateKey.from_private_bytes(b"a" * 32),
                issued_at=NOW,
            ),
            authority_fencing_token=0,
            authority_private_key=Ed25519PrivateKey.from_private_bytes(b"a" * 32),
            read_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
        )


def test_invalid_grant_does_not_consume_fencing_token(
    authority: InMemoryMonotonicAnchorReference,
) -> None:
    anchor = authority.current_anchor
    with pytest.raises(ValidationError, match="lifetime exceeds"):
        authority.acquire_fence(
            holder_id="ot-writer:test",
            request_nonce="invalid-lifetime-fence-nonce-0001",
            expected_anchor_sha256=anchor.digest,
            issued_at=NOW,
            lifetime=timedelta(minutes=2),
        )

    grant = authority.acquire_fence(
        holder_id="ot-writer:test",
        request_nonce="valid-lifetime-fence-nonce-0001",
        expected_anchor_sha256=anchor.digest,
        issued_at=NOW,
    )

    assert grant.fencing_token == 1
