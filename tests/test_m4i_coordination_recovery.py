from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from test_m4i_models import (
    NOW,
    M4iArtifacts,
    _acceptance,
    _commit,
    _prepare,
    _receipt,
)
from test_m4i_models import artifacts as m4i_artifacts_fixture

from aegis_ot.coordination_journal import (
    CoordinationAttemptStatus,
    CoordinationJournalRecord,
    CoordinationTransition,
    EffectCommitAttempt,
    EffectPrepareAttempt,
    EffectQueryAttempt,
)
from aegis_ot.coordination_models import (
    CoordinationState,
    EffectDisposition,
    EffectIdentity,
    SignedEffectOutcome,
    SignedEffectQueryRequest,
)
from aegis_ot.coordination_recovery import (
    CoordinationRecoveryReason,
    CoordinationRecoveryStatus,
    validate_coordination_plant_alignment,
    validate_coordination_recovery,
)
from aegis_ot.physical_models import PhysicalStateSnapshot, canonical_digest

_ARTIFACT_FACTORY = cast(Any, m4i_artifacts_fixture).__wrapped__


@pytest.fixture
def artifacts(tmp_path: Path) -> M4iArtifacts:
    return cast(M4iArtifacts, _ARTIFACT_FACTORY(tmp_path))


@dataclass(frozen=True)
class PlantProjection:
    model_digest: str
    state_version: int
    state_digest: str


def _applied_record(artifacts: M4iArtifacts) -> CoordinationJournalRecord:
    prepare = _prepare(artifacts)
    receipt = _receipt(artifacts, prepare)
    commit = _commit(artifacts, receipt)
    acceptance = _acceptance(artifacts, commit)
    outcome = SignedEffectOutcome.issue(
        request=commit,
        disposition=EffectDisposition.APPLIED,
        reason="command_applied_and_checkpointed",
        signer=artifacts.coordinator_signer,
        signed_at=NOW + timedelta(seconds=2),
        acceptance=acceptance,
        acknowledgment=artifacts.acknowledgment,
    )
    prepare_attempt = EffectPrepareAttempt(
        sequence=1,
        request=prepare,
        request_sha256=prepare.digest,
        status=CoordinationAttemptStatus.RESPONSE_RETAINED,
        receipt=receipt,
        retained_at=NOW + timedelta(milliseconds=250),
        updated_at=receipt.prepared_at,
    )
    commit_attempt = EffectCommitAttempt(
        sequence=2,
        request=commit,
        request_sha256=commit.digest,
        status=CoordinationAttemptStatus.RESPONSE_RETAINED,
        acceptance=acceptance,
        outcome=outcome,
        retained_at=commit.issued_at,
        updated_at=outcome.signed_at,
    )
    return CoordinationJournalRecord(
        effect=prepare.effect,
        effect_sha256=prepare.effect.digest,
        transitions=(
            CoordinationTransition(
                sequence=1,
                state=CoordinationState.RECEIVED,
                evidence_sha256=prepare.digest,
                reason="prepare_retained",
                recorded_at=NOW + timedelta(milliseconds=250),
            ),
            CoordinationTransition(
                sequence=2,
                state=CoordinationState.DISPATCH_ARMED,
                evidence_sha256=receipt.digest,
                reason="receipt_retained",
                recorded_at=receipt.prepared_at,
            ),
            CoordinationTransition(
                sequence=3,
                state=CoordinationState.COMMIT_ACCEPTED,
                evidence_sha256=acceptance.digest,
                reason="commit_accepted",
                recorded_at=acceptance.accepted_at,
            ),
            CoordinationTransition(
                sequence=4,
                state=CoordinationState.APPLIED,
                disposition=EffectDisposition.APPLIED,
                evidence_sha256=outcome.digest,
                reason="applied_outcome_retained",
                recorded_at=outcome.signed_at,
            ),
        ),
        attempts=(prepare_attempt, commit_attempt),
    )


def _pending_record(record: CoordinationJournalRecord) -> CoordinationJournalRecord:
    attempts = tuple(
        attempt.model_copy(
            update={
                "status": CoordinationAttemptStatus.REQUEST_RETAINED,
                "outcome": None,
                "updated_at": attempt.acceptance.accepted_at,
            }
        )
        if isinstance(attempt, EffectCommitAttempt) and attempt.acceptance is not None
        else attempt
        for attempt in record.attempts
    )
    pending = record.model_copy(
        update={
            "transitions": record.transitions[:-1],
            "attempts": attempts,
        }
    )
    return CoordinationJournalRecord.model_validate_json(pending.model_dump_json())


def _plant_at_pre(record: CoordinationJournalRecord) -> PlantProjection:
    return PlantProjection(
        model_digest=record.effect.authorized_model_sha256,
        state_version=record.effect.authorized_state_version,
        state_digest=record.effect.authorized_state_sha256,
    )


def _plant_at_post(record: CoordinationJournalRecord) -> PlantProjection:
    return PlantProjection(
        model_digest=record.effect.authorized_model_sha256,
        state_version=record.effect.expected_post_state_version,
        state_digest=record.effect.expected_post_state_sha256,
    )


def _replace_outcome(
    record: CoordinationJournalRecord,
    outcome: SignedEffectOutcome,
) -> CoordinationJournalRecord:
    attempts = tuple(
        attempt.model_copy(update={"outcome": outcome})
        if isinstance(attempt, EffectCommitAttempt)
        else attempt
        for attempt in record.attempts
    )
    return record.model_copy(update={"attempts": attempts})


def _rehash(snapshot: PhysicalStateSnapshot) -> PhysicalStateSnapshot:
    with_state_digest = snapshot.model_copy(
        update={"state_digest": canonical_digest(snapshot.digest_material())}
    )
    return with_state_digest.model_copy(
        update={
            "observation_digest": canonical_digest(
                with_state_digest.observation_material()
            )
        }
    )


def _effect_with_gap(record: CoordinationJournalRecord) -> EffectIdentity:
    acknowledgment = record.terminal_outcome
    assert acknowledgment is not None and acknowledgment.acknowledgment is not None
    pre_state = _rehash(
        acknowledgment.acknowledgment.pre_state.model_copy(
            update={"state_version": 1, "simulation_time_s": 1.0}
        )
    )
    material = record.effect.stable_material()
    material.update(
        {
            "authorized_state_sha256": pre_state.state_digest,
            "authorized_state_version": 1,
            "authorized_observation_sha256": pre_state.observation_digest,
            "expected_post_state_sha256": "e" * 64,
            "expected_post_state_version": 2,
        }
    )
    effect_material = {"schema_version": "m4i-effect-material-v1", **material}
    effect_id = f"sha256:{canonical_digest(effect_material)}"
    identity_fields = dict(material)
    identity_fields.pop("schema_version")
    return EffectIdentity(effect_id=effect_id, **identity_fields)


def _record_with_initial_version_gap(
    record: CoordinationJournalRecord,
) -> CoordinationJournalRecord:
    outcome = record.terminal_outcome
    assert outcome is not None and outcome.acknowledgment is not None
    effect = _effect_with_gap(record)
    pre_state = _rehash(
        outcome.acknowledgment.pre_state.model_copy(
            update={"state_version": 1, "simulation_time_s": 1.0}
        )
    )
    changed_acknowledgment = outcome.acknowledgment.model_copy(
        update={
            "pre_state": pre_state,
            "pre_state_digest": pre_state.state_digest,
            "pre_state_version": 1,
            "post_state_digest": effect.expected_post_state_sha256,
            "post_state_version": effect.expected_post_state_version,
        }
    )
    changed_outcome = outcome.model_copy(
        update={
            "effect": effect,
            "effect_sha256": effect.digest,
            "acknowledgment": changed_acknowledgment,
        }
    )
    changed = _replace_outcome(record, changed_outcome)
    return changed.model_copy(update={"effect": effect, "effect_sha256": effect.digest})


def test_empty_or_no_applied_history_requires_version_zero() -> None:
    baseline = PlantProjection("a" * 64, 0, "b" * 64)

    aligned = validate_coordination_plant_alignment((), baseline)
    advanced = validate_coordination_recovery(
        (),
        PlantProjection(baseline.model_digest, 1, "c" * 64),
    )

    assert aligned.status is CoordinationRecoveryStatus.ALIGNED
    assert aligned.reason is CoordinationRecoveryReason.ALIGNED_EMPTY_BASELINE
    assert aligned.record_count == 0
    assert advanced.status is CoordinationRecoveryStatus.INCONSISTENT
    assert advanced.reason is CoordinationRecoveryReason.BASELINE_STATE_NOT_ZERO


def test_coherent_applied_chain_matches_exact_durable_plant(
    artifacts: M4iArtifacts,
) -> None:
    record = _applied_record(artifacts)

    result = validate_coordination_recovery((record,), _plant_at_post(record))

    assert result.status is CoordinationRecoveryStatus.ALIGNED
    assert result.reason is CoordinationRecoveryReason.ALIGNED_APPLIED_CHAIN
    assert result.applied_effect_count == 1
    assert result.pending_effect_count == 0
    assert result.latest_applied_state_version == record.effect.expected_post_state_version
    assert result.latest_applied_state_digest == record.effect.expected_post_state_sha256
    assert result.aligned
    assert not result.fail_closed


def test_query_bound_applied_history_preserves_terminal_transition_anchor(
    artifacts: M4iArtifacts,
) -> None:
    record = _applied_record(artifacts)
    commit_outcome = record.terminal_outcome
    assert commit_outcome is not None
    assert commit_outcome.acceptance is not None
    query = SignedEffectQueryRequest.issue(
        effect=record.effect,
        signer=artifacts.gateway_signer,
        request_nonce="recovery-query-nonce-0001",
        issued_at=NOW + timedelta(seconds=3),
        expires_at=NOW + timedelta(seconds=30),
    )
    query_outcome = SignedEffectOutcome.issue(
        request=query,
        disposition=EffectDisposition.APPLIED,
        reason="durable_terminal_record",
        signer=artifacts.coordinator_signer,
        signed_at=NOW + timedelta(seconds=4),
        acceptance=commit_outcome.acceptance,
        acknowledgment=commit_outcome.acknowledgment,
    )
    query_attempt = EffectQueryAttempt(
        sequence=3,
        request=query,
        request_sha256=query.digest,
        status=CoordinationAttemptStatus.RESPONSE_RETAINED,
        outcome=query_outcome,
        retained_at=NOW + timedelta(seconds=3),
        updated_at=query_outcome.signed_at,
    )
    queried = CoordinationJournalRecord.model_validate_json(
        record.model_copy(
            update={"attempts": (*record.attempts, query_attempt)}
        ).model_dump_json()
    )

    assert queried.latest_evidence_sha256 == commit_outcome.digest
    assert queried.terminal_outcome == query_outcome
    assert query_outcome.digest != queried.latest_evidence_sha256

    result = validate_coordination_recovery((queried,), _plant_at_post(queried))

    assert result.status is CoordinationRecoveryStatus.ALIGNED
    assert result.reason is CoordinationRecoveryReason.ALIGNED_APPLIED_CHAIN


@pytest.mark.parametrize(
    ("at_post", "reason"),
    (
        (False, CoordinationRecoveryReason.PENDING_EFFECT_AT_PRE_STATE),
        (True, CoordinationRecoveryReason.PENDING_EFFECT_AT_POST_STATE),
    ),
)
def test_one_pending_effect_accepts_only_exact_pre_or_post_state(
    artifacts: M4iArtifacts,
    at_post: bool,
    reason: CoordinationRecoveryReason,
) -> None:
    pending = _pending_record(_applied_record(artifacts))
    plant = _plant_at_post(pending) if at_post else _plant_at_pre(pending)

    result = validate_coordination_recovery((pending,), plant)

    assert result.status is CoordinationRecoveryStatus.RECOVERY_REQUIRED
    assert result.reason is reason
    assert result.pending_effect_count == 1
    assert result.pending_effect_id == pending.effect.effect_id
    assert result.recovery_required


def test_pending_state_mismatch_and_multiple_pending_fail_closed(
    artifacts: M4iArtifacts,
) -> None:
    pending = _pending_record(_applied_record(artifacts))
    mismatched = PlantProjection(
        pending.effect.authorized_model_sha256,
        pending.effect.expected_post_state_version,
        "f" * 64,
    )

    mismatch = validate_coordination_recovery((pending,), mismatched)
    multiple = validate_coordination_recovery((pending, pending), _plant_at_pre(pending))

    assert mismatch.status is CoordinationRecoveryStatus.INCONSISTENT
    assert mismatch.reason is CoordinationRecoveryReason.PENDING_PLANT_STATE_MISMATCH
    assert mismatch.fail_closed
    assert multiple.status is CoordinationRecoveryStatus.UNAVAILABLE
    assert multiple.reason is CoordinationRecoveryReason.MULTIPLE_PENDING_EFFECTS
    assert multiple.fail_closed


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("missing", CoordinationRecoveryReason.APPLIED_ACKNOWLEDGMENT_MISSING),
        (
            "broken",
            CoordinationRecoveryReason.APPLIED_ACKNOWLEDGMENT_INCONSISTENT,
        ),
    ),
)
def test_missing_or_broken_applied_acknowledgment_fails_closed(
    artifacts: M4iArtifacts,
    mutation: str,
    reason: CoordinationRecoveryReason,
) -> None:
    record = _applied_record(artifacts)
    outcome = record.terminal_outcome
    assert outcome is not None and outcome.acknowledgment is not None
    if mutation == "missing":
        changed_outcome = outcome.model_copy(update={"acknowledgment": None})
    else:
        changed_acknowledgment = outcome.acknowledgment.model_copy(
            update={"post_state_digest": "f" * 64}
        )
        changed_outcome = outcome.model_copy(
            update={"acknowledgment": changed_acknowledgment}
        )

    result = validate_coordination_recovery(
        (_replace_outcome(record, changed_outcome),),
        _plant_at_post(record),
    )

    assert result.status is CoordinationRecoveryStatus.UNAVAILABLE
    assert result.reason is reason


def test_nonzero_chain_start_is_rejected_as_broken_history(
    artifacts: M4iArtifacts,
) -> None:
    record = _applied_record(artifacts)
    broken = _record_with_initial_version_gap(record)

    result = validate_coordination_recovery((broken,), _plant_at_post(record))

    assert result.status is CoordinationRecoveryStatus.UNAVAILABLE
    assert result.reason is CoordinationRecoveryReason.APPLIED_CHAIN_BROKEN


@pytest.mark.parametrize(
    ("version_delta", "digest", "reason"),
    (
        (-1, None, CoordinationRecoveryReason.PLANT_STATE_ROLLBACK),
        (1, None, CoordinationRecoveryReason.PLANT_STATE_ADVANCED),
        (0, "f" * 64, CoordinationRecoveryReason.PLANT_STATE_DIGEST_MISMATCH),
    ),
)
def test_applied_history_rejects_plant_rollback_advance_or_digest_mismatch(
    artifacts: M4iArtifacts,
    version_delta: int,
    digest: str | None,
    reason: CoordinationRecoveryReason,
) -> None:
    record = _applied_record(artifacts)
    expected = _plant_at_post(record)
    plant = PlantProjection(
        expected.model_digest,
        expected.state_version + version_delta,
        expected.state_digest if digest is None else digest,
    )

    result = validate_coordination_recovery((record,), plant)

    assert result.status is CoordinationRecoveryStatus.INCONSISTENT
    assert result.reason is reason
    assert result.fail_closed
