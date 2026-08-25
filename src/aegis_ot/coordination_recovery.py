"""Pure M4i coordination-to-plant recovery alignment checks.

This module compares already-loaded, trusted coordination records with an
already-loaded durable plant projection.  It performs no I/O and mutates
nothing.  The check detects ordinary single-volume rollback, truncation, and
misalignment; without an external monotonic anchor it cannot detect a
coordinated rollback or hostile-host tampering of both stores.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .capability_models import PlcCommandAcknowledgment
from .coordination_journal import CoordinationJournalRecord
from .coordination_models import CoordinationState, EffectDisposition, SignedEffectOutcome
from .physical_models import CommandStatus

MAX_RECOVERY_RECORDS = 8192
_SHA256 = re.compile(r"[0-9a-f]{64}")


class PlantInfo(Protocol):
    """Minimum durable plant projection needed by the recovery validator."""

    @property
    def model_digest(self) -> str: ...

    @property
    def state_version(self) -> int: ...

    @property
    def state_digest(self) -> str: ...


class CoordinationRecoveryStatus(StrEnum):
    """Closed recovery disposition for later runtime admission wiring."""

    ALIGNED = "aligned"
    RECOVERY_REQUIRED = "recovery_required"
    INCONSISTENT = "inconsistent"
    UNAVAILABLE = "unavailable"


class CoordinationRecoveryReason(StrEnum):
    """Stable, bounded reason codes for every recovery disposition."""

    ALIGNED_EMPTY_BASELINE = "aligned_empty_baseline"
    ALIGNED_APPLIED_CHAIN = "aligned_applied_chain"
    PENDING_EFFECT_AT_PRE_STATE = "pending_effect_at_pre_state"
    PENDING_EFFECT_AT_POST_STATE = "pending_effect_at_post_state"
    PLANT_INFO_INVALID = "plant_info_invalid"
    RECORD_LIMIT_EXCEEDED = "record_limit_exceeded"
    DUPLICATE_EFFECT_RECORD = "duplicate_effect_record"
    MULTIPLE_PENDING_EFFECTS = "multiple_pending_effects"
    JOURNAL_RECORD_INVALID = "journal_record_invalid"
    APPLIED_ACKNOWLEDGMENT_MISSING = "applied_acknowledgment_missing"
    APPLIED_ACKNOWLEDGMENT_INCONSISTENT = "applied_acknowledgment_inconsistent"
    APPLIED_EVIDENCE_INVALID = "applied_evidence_invalid"
    APPLIED_CHAIN_BROKEN = "applied_chain_broken"
    PENDING_CHAIN_BROKEN = "pending_chain_broken"
    PLANT_MODEL_MISMATCH = "plant_model_mismatch"
    BASELINE_STATE_NOT_ZERO = "baseline_state_not_zero"
    PLANT_STATE_ROLLBACK = "plant_state_rollback"
    PLANT_STATE_ADVANCED = "plant_state_advanced"
    PLANT_STATE_DIGEST_MISMATCH = "plant_state_digest_mismatch"
    PENDING_PLANT_STATE_MISMATCH = "pending_plant_state_mismatch"


@dataclass(frozen=True, slots=True)
class CoordinationRecoveryResult:
    """Deterministic summary of coordination and durable-plant alignment."""

    status: CoordinationRecoveryStatus
    reason: CoordinationRecoveryReason
    record_count: int
    applied_effect_count: int
    pending_effect_count: int
    plant_state_version: int
    plant_state_digest: str
    latest_applied_state_version: int | None = None
    latest_applied_state_digest: str | None = None
    pending_effect_id: str | None = None
    pending_expected_post_state_version: int | None = None
    pending_expected_post_state_digest: str | None = None

    @property
    def aligned(self) -> bool:
        return self.status is CoordinationRecoveryStatus.ALIGNED

    @property
    def recovery_required(self) -> bool:
        return self.status is CoordinationRecoveryStatus.RECOVERY_REQUIRED

    @property
    def fail_closed(self) -> bool:
        return self.status in {
            CoordinationRecoveryStatus.INCONSISTENT,
            CoordinationRecoveryStatus.UNAVAILABLE,
        }


@dataclass(frozen=True, slots=True)
class _AppliedLink:
    record: CoordinationJournalRecord
    outcome: SignedEffectOutcome
    acknowledgment: PlcCommandAcknowledgment

    @property
    def pre_version(self) -> int:
        return self.record.effect.authorized_state_version

    @property
    def pre_digest(self) -> str:
        return self.record.effect.authorized_state_sha256

    @property
    def post_version(self) -> int:
        return self.record.effect.expected_post_state_version

    @property
    def post_digest(self) -> str:
        return self.record.effect.expected_post_state_sha256


def _bounded_records(
    records: Iterable[CoordinationJournalRecord],
) -> tuple[CoordinationJournalRecord, ...] | None:
    retained: list[CoordinationJournalRecord] = []
    for record in records:
        if len(retained) >= MAX_RECOVERY_RECORDS:
            return None
        retained.append(record)
    return tuple(retained)


def _valid_plant_info(plant: PlantInfo) -> bool:
    return (
        isinstance(plant.state_version, int)
        and not isinstance(plant.state_version, bool)
        and plant.state_version >= 0
        and isinstance(plant.model_digest, str)
        and _SHA256.fullmatch(plant.model_digest) is not None
        and isinstance(plant.state_digest, str)
        and _SHA256.fullmatch(plant.state_digest) is not None
    )


def _result(
    *,
    status: CoordinationRecoveryStatus,
    reason: CoordinationRecoveryReason,
    records: tuple[CoordinationJournalRecord, ...],
    plant: PlantInfo,
    applied: tuple[_AppliedLink, ...] = (),
    pending: CoordinationJournalRecord | None = None,
) -> CoordinationRecoveryResult:
    latest = applied[-1] if applied else None
    return CoordinationRecoveryResult(
        status=status,
        reason=reason,
        record_count=len(records),
        applied_effect_count=len(applied),
        pending_effect_count=0 if pending is None else 1,
        plant_state_version=plant.state_version,
        plant_state_digest=plant.state_digest,
        latest_applied_state_version=None if latest is None else latest.post_version,
        latest_applied_state_digest=None if latest is None else latest.post_digest,
        pending_effect_id=None if pending is None else pending.effect.effect_id,
        pending_expected_post_state_version=(
            None if pending is None else pending.effect.expected_post_state_version
        ),
        pending_expected_post_state_digest=(
            None if pending is None else pending.effect.expected_post_state_sha256
        ),
    )


def _applied_link(
    record: CoordinationJournalRecord,
) -> tuple[_AppliedLink | None, CoordinationRecoveryReason | None]:
    outcome = record.terminal_outcome
    acknowledgment = None if outcome is None else outcome.acknowledgment
    if outcome is None or acknowledgment is None:
        return None, CoordinationRecoveryReason.APPLIED_ACKNOWLEDGMENT_MISSING
    effect = record.effect
    if (
        outcome.disposition is not EffectDisposition.APPLIED
        or acknowledgment.status is not CommandStatus.APPLIED
        or acknowledgment.post_state_version is None
        or acknowledgment.post_state_digest is None
        or acknowledgment.post_topology_digest is None
        or acknowledgment.pre_state_version != effect.authorized_state_version
        or acknowledgment.pre_state_digest != effect.authorized_state_sha256
        or acknowledgment.pre_state.state_version != effect.authorized_state_version
        or acknowledgment.pre_state.state_digest != effect.authorized_state_sha256
        or acknowledgment.pre_state.observation_digest
        != effect.authorized_observation_sha256
        or acknowledgment.pre_state.topology_digest != effect.authorized_topology_sha256
        or acknowledgment.pre_state.model_digest != effect.authorized_model_sha256
        or acknowledgment.post_state_version != effect.expected_post_state_version
        or acknowledgment.post_state_digest != effect.expected_post_state_sha256
        or acknowledgment.post_topology_digest != effect.expected_post_topology_sha256
    ):
        return None, CoordinationRecoveryReason.APPLIED_ACKNOWLEDGMENT_INCONSISTENT
    return _AppliedLink(record, outcome, acknowledgment), None


def _applied_evidence_valid(link: _AppliedLink) -> bool:
    outcome = link.outcome
    acknowledgment = link.acknowledgment
    acceptance = outcome.acceptance
    if acceptance is None:
        return False
    commit = acceptance.commit_request
    receipt = commit.receipt
    prepare = receipt.prepare_request
    dispatch = prepare.dispatch
    coordinator_public_key = acceptance.coordinator_credential.credential.public_key
    return (
        link.record.effect == outcome.effect == acceptance.effect == commit.effect
        and commit.effect == receipt.effect == prepare.effect
        and link.record.latest_evidence_sha256 == outcome.digest
        and prepare.verify()
        and receipt.verify()
        and commit.verify()
        and acceptance.verify()
        and outcome.verify()
        and acknowledgment.verify_for_transaction(
            coordinator_public_key,
            request=dispatch.request,
            permit=dispatch.permit,
            pre_observation=dispatch.pre_observation,
            expected_plc_id=dispatch.permit.target_plc_id,
            expected_plc_key_id=dispatch.permit.target_plc_key_id,
            expected_plc_boot_epoch=dispatch.permit.target_plc_boot_epoch,
        )
    )


def validate_coordination_recovery(
    records: Iterable[CoordinationJournalRecord],
    plant: PlantInfo,
) -> CoordinationRecoveryResult:
    """Validate bounded journal history against the durable plant projection.

    A single nonterminal effect always requires explicit recovery.  It is
    recoverable only when the plant is at that effect's authorized pre-state
    or exact expected post-state.  All other ambiguity or disagreement fails
    closed without attempting reconciliation or changing either input.
    """

    retained = _bounded_records(records)
    if retained is None:
        return CoordinationRecoveryResult(
            status=CoordinationRecoveryStatus.UNAVAILABLE,
            reason=CoordinationRecoveryReason.RECORD_LIMIT_EXCEEDED,
            record_count=MAX_RECOVERY_RECORDS + 1,
            applied_effect_count=0,
            pending_effect_count=0,
            plant_state_version=plant.state_version,
            plant_state_digest=plant.state_digest,
        )
    if not _valid_plant_info(plant):
        return _result(
            status=CoordinationRecoveryStatus.UNAVAILABLE,
            reason=CoordinationRecoveryReason.PLANT_INFO_INVALID,
            records=retained,
            plant=plant,
        )

    try:
        pending_records = tuple(record for record in retained if not record.state.terminal)
        effect_ids = tuple(record.effect.effect_id for record in retained)
    except (AttributeError, IndexError, TypeError, ValueError):
        return _result(
            status=CoordinationRecoveryStatus.UNAVAILABLE,
            reason=CoordinationRecoveryReason.JOURNAL_RECORD_INVALID,
            records=retained,
            plant=plant,
        )
    if len(pending_records) > 1:
        return _result(
            status=CoordinationRecoveryStatus.UNAVAILABLE,
            reason=CoordinationRecoveryReason.MULTIPLE_PENDING_EFFECTS,
            records=retained,
            plant=plant,
        )
    if len(set(effect_ids)) != len(effect_ids):
        return _result(
            status=CoordinationRecoveryStatus.UNAVAILABLE,
            reason=CoordinationRecoveryReason.DUPLICATE_EFFECT_RECORD,
            records=retained,
            plant=plant,
        )

    applied_links: list[_AppliedLink] = []
    for record in retained:
        if record.state is CoordinationState.APPLIED:
            try:
                link, failure = _applied_link(record)
            except (AttributeError, IndexError, TypeError, ValueError):
                link = None
                failure = CoordinationRecoveryReason.JOURNAL_RECORD_INVALID
            if link is None:
                assert failure is not None
                return _result(
                    status=CoordinationRecoveryStatus.UNAVAILABLE,
                    reason=failure,
                    records=retained,
                    plant=plant,
                    applied=tuple(applied_links),
                    pending=pending_records[0] if pending_records else None,
                )
            applied_links.append(link)

    applied_links.sort(
        key=lambda link: (
            link.pre_version,
            link.post_version,
            link.record.effect.effect_id,
        )
    )
    applied = tuple(applied_links)
    for index, link in enumerate(applied):
        if index == 0:
            chain_matches = link.pre_version == 0
        else:
            prior = applied[index - 1]
            chain_matches = (
                link.pre_version == prior.post_version
                and link.pre_digest == prior.post_digest
            )
        if not chain_matches:
            return _result(
                status=CoordinationRecoveryStatus.UNAVAILABLE,
                reason=CoordinationRecoveryReason.APPLIED_CHAIN_BROKEN,
                records=retained,
                plant=plant,
                applied=applied,
                pending=pending_records[0] if pending_records else None,
            )

    try:
        for record in retained:
            CoordinationJournalRecord.model_validate_json(record.model_dump_json())
    except (AttributeError, TypeError, ValueError):
        return _result(
            status=CoordinationRecoveryStatus.UNAVAILABLE,
            reason=CoordinationRecoveryReason.JOURNAL_RECORD_INVALID,
            records=retained,
            plant=plant,
            applied=applied,
            pending=pending_records[0] if pending_records else None,
        )
    try:
        evidence_valid = all(_applied_evidence_valid(link) for link in applied)
    except (AttributeError, IndexError, TypeError, ValueError):
        evidence_valid = False
    if not evidence_valid:
        return _result(
            status=CoordinationRecoveryStatus.UNAVAILABLE,
            reason=CoordinationRecoveryReason.APPLIED_EVIDENCE_INVALID,
            records=retained,
            plant=plant,
            applied=applied,
            pending=pending_records[0] if pending_records else None,
        )

    pending = pending_records[0] if pending_records else None
    if pending is not None:
        expected_pre_version = 0 if not applied else applied[-1].post_version
        expected_pre_digest = (
            pending.effect.authorized_state_sha256
            if not applied
            else applied[-1].post_digest
        )
        if (
            pending.effect.authorized_state_version != expected_pre_version
            or pending.effect.authorized_state_sha256 != expected_pre_digest
        ):
            return _result(
                status=CoordinationRecoveryStatus.UNAVAILABLE,
                reason=CoordinationRecoveryReason.PENDING_CHAIN_BROKEN,
                records=retained,
                plant=plant,
                applied=applied,
                pending=pending,
            )

    relevant_model_digests = {
        link.record.effect.authorized_model_sha256 for link in applied
    }
    if pending is not None:
        relevant_model_digests.add(pending.effect.authorized_model_sha256)
    if len(relevant_model_digests) > 1 or (
        relevant_model_digests and plant.model_digest not in relevant_model_digests
    ):
        return _result(
            status=CoordinationRecoveryStatus.INCONSISTENT,
            reason=CoordinationRecoveryReason.PLANT_MODEL_MISMATCH,
            records=retained,
            plant=plant,
            applied=applied,
            pending=pending,
        )

    if pending is not None:
        pre_state = (
            pending.effect.authorized_state_version,
            pending.effect.authorized_state_sha256,
        )
        post_state = (
            pending.effect.expected_post_state_version,
            pending.effect.expected_post_state_sha256,
        )
        plant_state = (plant.state_version, plant.state_digest)
        if plant_state == pre_state:
            reason = CoordinationRecoveryReason.PENDING_EFFECT_AT_PRE_STATE
        elif plant_state == post_state:
            reason = CoordinationRecoveryReason.PENDING_EFFECT_AT_POST_STATE
        elif plant.state_version < pre_state[0]:
            return _result(
                status=CoordinationRecoveryStatus.INCONSISTENT,
                reason=CoordinationRecoveryReason.PLANT_STATE_ROLLBACK,
                records=retained,
                plant=plant,
                applied=applied,
                pending=pending,
            )
        elif plant.state_version > post_state[0]:
            return _result(
                status=CoordinationRecoveryStatus.INCONSISTENT,
                reason=CoordinationRecoveryReason.PLANT_STATE_ADVANCED,
                records=retained,
                plant=plant,
                applied=applied,
                pending=pending,
            )
        else:
            return _result(
                status=CoordinationRecoveryStatus.INCONSISTENT,
                reason=CoordinationRecoveryReason.PENDING_PLANT_STATE_MISMATCH,
                records=retained,
                plant=plant,
                applied=applied,
                pending=pending,
            )
        return _result(
            status=CoordinationRecoveryStatus.RECOVERY_REQUIRED,
            reason=reason,
            records=retained,
            plant=plant,
            applied=applied,
            pending=pending,
        )

    if not applied:
        if plant.state_version != 0:
            return _result(
                status=CoordinationRecoveryStatus.INCONSISTENT,
                reason=CoordinationRecoveryReason.BASELINE_STATE_NOT_ZERO,
                records=retained,
                plant=plant,
            )
        return _result(
            status=CoordinationRecoveryStatus.ALIGNED,
            reason=CoordinationRecoveryReason.ALIGNED_EMPTY_BASELINE,
            records=retained,
            plant=plant,
        )

    latest = applied[-1]
    if plant.state_version < latest.post_version:
        reason = CoordinationRecoveryReason.PLANT_STATE_ROLLBACK
    elif plant.state_version > latest.post_version:
        reason = CoordinationRecoveryReason.PLANT_STATE_ADVANCED
    elif plant.state_digest != latest.post_digest:
        reason = CoordinationRecoveryReason.PLANT_STATE_DIGEST_MISMATCH
    else:
        return _result(
            status=CoordinationRecoveryStatus.ALIGNED,
            reason=CoordinationRecoveryReason.ALIGNED_APPLIED_CHAIN,
            records=retained,
            plant=plant,
            applied=applied,
        )
    return _result(
        status=CoordinationRecoveryStatus.INCONSISTENT,
        reason=reason,
        records=retained,
        plant=plant,
        applied=applied,
    )


def validate_coordination_plant_alignment(
    records: Iterable[CoordinationJournalRecord],
    plant: PlantInfo,
) -> CoordinationRecoveryResult:
    """Compatibility name emphasizing the validator's durable alignment role."""

    return validate_coordination_recovery(records, plant)
