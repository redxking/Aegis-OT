from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from test_m4g_runtime import NOW, RuntimeArtifacts
from test_m4i_ot_coordination_runtime import (
    _ARTIFACT_FACTORY,
    _commit_request,
    _harness,
    _prepare_request,
)

from aegis_ot.coordination_anchor import (
    AnchoredRecoveryDecision,
    AnchoredRecoveryReason,
    AnchoredRecoveryStatus,
    BoundCoordinationAnchorAdmissionDecision,
    CoordinationAnchorAdmissionError,
    CoordinationAnchorAdmissionPhase,
    FailClosedCoordinationAnchorAdmission,
)
from aegis_ot.coordination_journal import EffectCommitAttempt
from aegis_ot.coordination_models import CoordinationState
from aegis_ot.segmented_capability_runtime import CapabilityRuntimeUnavailable


@pytest.fixture(scope="module")
def artifacts() -> RuntimeArtifacts:
    return cast(RuntimeArtifacts, _ARTIFACT_FACTORY())


def _decision(
    status: AnchoredRecoveryStatus,
    reason: AnchoredRecoveryReason,
) -> AnchoredRecoveryDecision:
    return AnchoredRecoveryDecision(
        status=status,
        reason=reason,
        admission_allowed=status is AnchoredRecoveryStatus.ADMISSION_READY,
        anchor_sequence=1,
        authority_fencing_token=2,
        local_fencing_token=1,
    )


READY = _decision(
    AnchoredRecoveryStatus.ADMISSION_READY,
    AnchoredRecoveryReason.CURRENT_FENCE_ADMISSION_READY,
)


@dataclass
class SequencedDecisionSource:
    outcomes: list[
        AnchoredRecoveryDecision | BoundCoordinationAnchorAdmissionDecision | Exception
    ]
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __call__(
        self,
        *,
        phase: CoordinationAnchorAdmissionPhase,
        effect_id: str,
        request_sha256: str,
        evaluated_at: datetime,
    ) -> BoundCoordinationAnchorAdmissionDecision:
        self.calls.append(
            {
                "phase": phase,
                "effect_id": effect_id,
                "request_sha256": request_sha256,
                "evaluated_at": evaluated_at,
            }
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if isinstance(outcome, BoundCoordinationAnchorAdmissionDecision):
            return outcome
        return BoundCoordinationAnchorAdmissionDecision(
            phase=phase,
            effect_id=effect_id,
            request_sha256=request_sha256,
            evaluated_at=evaluated_at,
            decision=outcome,
        )


@pytest.mark.parametrize(
    "changed",
    ("phase", "effect_id", "request_sha256", "evaluated_at"),
)
def test_cached_ready_decision_for_a_different_call_is_rejected(changed: str) -> None:
    requested = {
        "phase": CoordinationAnchorAdmissionPhase.PREPARE,
        "effect_id": "sha256:" + "a" * 64,
        "request_sha256": "b" * 64,
        "evaluated_at": NOW,
    }
    bound = dict(requested)
    replacements = {
        "phase": CoordinationAnchorAdmissionPhase.COMMIT,
        "effect_id": "sha256:" + "c" * 64,
        "request_sha256": "d" * 64,
        "evaluated_at": NOW + timedelta(microseconds=1),
    }
    bound[changed] = replacements[changed]
    source = SequencedDecisionSource(
        [BoundCoordinationAnchorAdmissionDecision(**bound, decision=READY)]
    )

    with pytest.raises(
        CoordinationAnchorAdmissionError,
        match="anchor_prepare_decision_binding_mismatch",
    ):
        FailClosedCoordinationAnchorAdmission(source).require_admission(**requested)


@pytest.mark.parametrize(
    ("status", "reason"),
    (
        (
            AnchoredRecoveryStatus.UNAVAILABLE,
            AnchoredRecoveryReason.ANCHOR_UNAVAILABLE,
        ),
        (
            AnchoredRecoveryStatus.UNAVAILABLE,
            AnchoredRecoveryReason.ANCHOR_READBACK_STALE,
        ),
        (
            AnchoredRecoveryStatus.INCONSISTENT,
            AnchoredRecoveryReason.ANCHORED_STATE_CONFLICT,
        ),
    ),
)
def test_prepare_fails_before_journal_admission_when_anchor_is_not_current(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
    status: AnchoredRecoveryStatus,
    reason: AnchoredRecoveryReason,
) -> None:
    source = SequencedDecisionSource([_decision(status, reason)])
    guard = FailClosedCoordinationAnchorAdmission(source)
    harness = _harness(
        tmp_path,
        artifacts,
        anchor_required=True,
        anchor_admission=guard,
    )
    request = _prepare_request(harness)

    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match="effect_coordination_anchor_prepare_unavailable",
    ):
        harness.runtime.prepare_effect(request)

    assert harness.journal.records() == ()
    assert harness.device.calls == 0
    assert source.calls[0]["phase"] is CoordinationAnchorAdmissionPhase.PREPARE
    assert source.calls[0]["effect_id"] == request.effect.effect_id
    assert source.calls[0]["request_sha256"] == request.digest


def test_commit_fails_before_commit_acceptance_and_physical_execution(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    stale = _decision(
        AnchoredRecoveryStatus.UNAVAILABLE,
        AnchoredRecoveryReason.FENCE_STALE,
    )
    source = SequencedDecisionSource([READY, stale])
    harness = _harness(
        tmp_path,
        artifacts,
        anchor_required=True,
        anchor_admission=FailClosedCoordinationAnchorAdmission(source),
    )
    prepare = _prepare_request(harness)
    receipt = harness.runtime.prepare_effect(prepare)
    harness.clock.value = NOW + timedelta(milliseconds=750)
    commit = _commit_request(harness, receipt)

    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match="effect_coordination_anchor_commit_unavailable",
    ):
        harness.runtime.commit_effect(commit)

    record = harness.journal.get(commit.effect)
    assert record is not None
    assert record.state is CoordinationState.DISPATCH_ARMED
    assert not any(isinstance(attempt, EffectCommitAttempt) for attempt in record.attempts)
    assert harness.device.calls == 0
    assert harness.runtime.execute_requests == 0
    assert [call["phase"] for call in source.calls] == [
        CoordinationAnchorAdmissionPhase.PREPARE,
        CoordinationAnchorAdmissionPhase.COMMIT,
    ]


def test_anchor_decision_source_exception_is_fail_closed(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    source = SequencedDecisionSource([OSError("external anchor unavailable")])
    harness = _harness(
        tmp_path,
        artifacts,
        anchor_required=True,
        anchor_admission=FailClosedCoordinationAnchorAdmission(source),
    )

    with pytest.raises(CapabilityRuntimeUnavailable):
        harness.runtime.prepare_effect(_prepare_request(harness))

    assert harness.journal.records() == ()
    assert harness.device.calls == 0
