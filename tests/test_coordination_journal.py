from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from pydantic import ValidationError
from test_m4i_models import (
    NOW,
    M4iArtifacts,
    _commit,
    _prepare,
)
from test_m4i_models import (
    artifacts as m4i_artifacts_fixture,
)

import aegis_ot.coordination_journal as journal_module
from aegis_ot.coordination_journal import (
    CommitAcceptanceIssuer,
    CommitAdmissionStatus,
    CoordinationAttemptStatus,
    CoordinationCollisionError,
    CoordinationJournalError,
    CoordinationJournalRecord,
    DurableEffectCoordinationJournal,
    DurableGatewayCoordinationJournal,
    EffectCommitAttempt,
    EffectPrepareAttempt,
    EffectQueryAttempt,
    IllegalCoordinationTransition,
)
from aegis_ot.coordination_models import (
    CoordinationReceipt,
    CoordinationState,
    DurableCommitAcceptance,
    EffectDisposition,
    SignedEffectCommitRequest,
    SignedEffectOutcome,
    SignedEffectPrepareRequest,
    SignedEffectQueryRequest,
)

_ARTIFACT_FACTORY = cast(
    Callable[[Path], M4iArtifacts],
    cast(Any, m4i_artifacts_fixture).__wrapped__,
)


@pytest.fixture
def artifacts(tmp_path: Path) -> M4iArtifacts:
    return _ARTIFACT_FACTORY(tmp_path)


def _secure_path(tmp_path: Path, name: str = "coordination.json") -> Path:
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    return directory / name


def _receipt(
    artifacts: M4iArtifacts,
    request: SignedEffectPrepareRequest,
    prepared_offset: float = 0.5,
) -> CoordinationReceipt:
    return CoordinationReceipt.issue(
        request=request,
        signer=artifacts.coordinator_signer,
        prepared_at=NOW + timedelta(seconds=prepared_offset),
    )


def _retry_prepare(
    artifacts: M4iArtifacts,
    *,
    sequence: int,
) -> SignedEffectPrepareRequest:
    return SignedEffectPrepareRequest.issue(
        dispatch=artifacts.dispatch,
        signer=artifacts.gateway_signer,
        request_nonce=f"prepare-retry-nonce-{sequence:04d}",
        issued_at=NOW + timedelta(seconds=sequence),
        expires_at=NOW + timedelta(seconds=sequence + 30),
    )


def _query(
    artifacts: M4iArtifacts,
    prepare: SignedEffectPrepareRequest,
    *,
    sequence: int,
) -> SignedEffectQueryRequest:
    issued_at = NOW + timedelta(seconds=sequence)
    return SignedEffectQueryRequest.issue(
        effect=prepare.effect,
        signer=artifacts.gateway_signer,
        request_nonce=f"query-reconcile-nonce-{sequence:04d}",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=30),
    )


def _outcome(
    artifacts: M4iArtifacts,
    request: SignedEffectCommitRequest | SignedEffectQueryRequest,
    acceptance: DurableCommitAcceptance | None,
    *,
    disposition: EffectDisposition,
    signed_offset: float,
) -> SignedEffectOutcome:
    return SignedEffectOutcome.issue(
        request=request,
        disposition=disposition,
        reason=f"signed_{disposition.value}_evidence",
        signer=artifacts.coordinator_signer,
        signed_at=NOW + timedelta(seconds=signed_offset),
        acceptance=acceptance,
        acknowledgment=(
            artifacts.acknowledgment if disposition is EffectDisposition.APPLIED else None
        ),
    )


def _acceptance(
    artifacts: M4iArtifacts,
    request: SignedEffectCommitRequest,
    *,
    accepted_offset: float = 1.25,
) -> DurableCommitAcceptance:
    return DurableCommitAcceptance.issue(
        request=request,
        signer=artifacts.coordinator_signer,
        accepted_at=NOW + timedelta(seconds=accepted_offset),
        transition_sequence=3,
    )


def _issue_acceptance(
    artifacts: M4iArtifacts,
) -> CommitAcceptanceIssuer:
    def issue(
        request: SignedEffectCommitRequest,
        *,
        accepted_at: datetime,
        transition_sequence: Literal[3],
    ) -> DurableCommitAcceptance:
        assert transition_sequence == 3
        return DurableCommitAcceptance.issue(
            request=request,
            signer=artifacts.coordinator_signer,
            accepted_at=accepted_at,
            transition_sequence=3,
        )

    return issue


def _prepare_executor(
    journal: DurableEffectCoordinationJournal,
    artifacts: M4iArtifacts,
    request: SignedEffectPrepareRequest,
    *,
    recorded_offset: float = 0.5,
) -> CoordinationReceipt:
    return journal.prepare_effect(
        request,
        lambda exact_request, when: CoordinationReceipt.issue(
            request=exact_request,
            signer=artifacts.coordinator_signer,
            prepared_at=when,
        ),
        recorded_at=NOW + timedelta(seconds=recorded_offset),
    )


def _prepare_gateway(
    journal: DurableGatewayCoordinationJournal,
    artifacts: M4iArtifacts,
) -> tuple[SignedEffectPrepareRequest, CoordinationReceipt, SignedEffectCommitRequest]:
    prepare = _prepare(artifacts)
    receipt = _receipt(artifacts, prepare)
    commit = _commit(artifacts, receipt)
    journal.begin(prepare, recorded_at=NOW)
    journal.retain_preparation(
        prepare,
        receipt,
        recorded_at=NOW + timedelta(seconds=0.5),
    )
    journal.begin_commit(commit, recorded_at=NOW + timedelta(seconds=1))
    return prepare, receipt, commit


def test_executor_prepare_retains_exact_artifacts_and_is_idempotent(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    path = _secure_path(tmp_path)
    prepare = _prepare(artifacts)
    issued = 0

    def issue_receipt(
        request: SignedEffectPrepareRequest,
        retained_at: Any,
    ) -> CoordinationReceipt:
        nonlocal issued
        issued += 1
        return CoordinationReceipt.issue(
            request=request,
            signer=artifacts.coordinator_signer,
            prepared_at=retained_at,
        )

    with DurableEffectCoordinationJournal(
        path,
        owner_subject="spiffe://aegis-ot.test/workload/ot-adapter",
        initialize=True,
    ) as journal:
        receipt = journal.prepare_effect(
            prepare,
            issue_receipt,
            recorded_at=NOW + timedelta(seconds=0.5),
        )
        assert (
            journal.prepare_effect(
                prepare,
                issue_receipt,
                recorded_at=NOW + timedelta(seconds=0.75),
            )
            == receipt
        )
        assert issued == 1
        record = journal.get(prepare.effect)
        assert record is not None
        assert record.state is CoordinationState.DISPATCH_ARMED
        assert record.latest_receipt == receipt
        assert record.attempts == journal.attempts(prepare.effect)
        assert isinstance(record.attempts[0], EffectPrepareAttempt)
        assert record.attempts[0].request == prepare
        assert record.attempts[0].receipt == receipt
        assert journal.records() == (record,)
        assert journal.pending() == (record,)

        retry = _retry_prepare(artifacts, sequence=1)
        retry_receipt = journal.prepare_effect(
            retry,
            issue_receipt,
            recorded_at=NOW + timedelta(seconds=1.5),
        )
        assert retry.effect == prepare.effect
        assert retry.digest != prepare.digest
        assert retry_receipt.prepare_request == retry
        assert issued == 2
        retried = journal.get(prepare.effect)
        assert retried is not None
        assert len(retried.attempts) == 2
        assert [item.state for item in retried.transitions] == [
            CoordinationState.RECEIVED,
            CoordinationState.DISPATCH_ARMED,
        ]

    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    parsed = json.loads(path.read_bytes())
    assert path.read_bytes() == journal_module._DurableCoordinationJournal._canonical_bytes(parsed)

    with DurableEffectCoordinationJournal(
        path,
        owner_subject="spiffe://aegis-ot.test/workload/ot-adapter",
    ) as reloaded:
        record = reloaded.get(prepare.effect)
        assert record is not None
        assert record.attempts[0].request == prepare
        assert record.attempts[0].receipt == receipt
        assert reloaded.prepare_effect(retry, issue_receipt) == retry_receipt
        assert issued == 2


def test_commit_intent_is_durable_before_new_admission_and_never_reexecutes(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    path = _secure_path(tmp_path)
    prepare = _prepare(artifacts)
    with DurableEffectCoordinationJournal(
        path,
        owner_subject="ot-coordinator",
        initialize=True,
    ) as journal:
        receipt = _prepare_executor(journal, artifacts, prepare)
        commit = _commit(artifacts, receipt)
        issued = 0

        def issue_acceptance(
            exact_request: SignedEffectCommitRequest,
            *,
            accepted_at: datetime,
            transition_sequence: Literal[3],
        ) -> DurableCommitAcceptance:
            nonlocal issued
            issued += 1
            assert exact_request == commit
            assert transition_sequence == 3
            return DurableCommitAcceptance.issue(
                request=exact_request,
                signer=artifacts.coordinator_signer,
                accepted_at=accepted_at,
                transition_sequence=transition_sequence,
            )

        admission = journal.begin_commit(
            commit,
            issue_acceptance,
            recorded_at=NOW + timedelta(seconds=1),
        )
        assert admission.status is CommitAdmissionStatus.NEW
        assert admission.acceptance.accepted_at == NOW + timedelta(seconds=1)
        assert admission.record.state is CoordinationState.COMMIT_ACCEPTED
        assert admission.record.latest_acceptance == admission.acceptance
        assert admission.record.transitions[-1].evidence_sha256 == admission.acceptance.digest
        assert isinstance(admission.record.attempts[-1], EffectCommitAttempt)
        assert admission.record.attempts[-1].request == commit
        assert admission.record.attempts[-1].acceptance == admission.acceptance
        assert journal.pending() == (admission.record,)

        def must_not_reissue(
            exact_request: SignedEffectCommitRequest,
            *,
            accepted_at: datetime,
            transition_sequence: Literal[3],
        ) -> DurableCommitAcceptance:
            del exact_request, accepted_at, transition_sequence
            raise AssertionError("commit retry must not mint another acceptance")

        repeated = journal.begin_commit(
            commit,
            must_not_reissue,
            recorded_at=NOW + timedelta(seconds=2),
        )
        assert issued == 1
        assert repeated.status is CommitAdmissionStatus.INDETERMINATE
        assert repeated.acceptance == admission.acceptance
        assert repeated.record == admission.record

    applied = _outcome(
        artifacts,
        commit,
        admission.acceptance,
        disposition=EffectDisposition.APPLIED,
        signed_offset=4,
    )
    with DurableEffectCoordinationJournal(
        path,
        owner_subject="ot-coordinator",
    ) as reloaded:
        retained = reloaded.get(prepare.effect)
        assert retained is not None
        assert retained.state is CoordinationState.COMMIT_ACCEPTED
        terminal = reloaded.finish_commit(
            commit,
            applied,
            recorded_at=NOW + timedelta(seconds=4),
        )
        assert terminal.state is CoordinationState.APPLIED
        assert terminal.terminal_outcome == applied
        assert reloaded.finish_commit(commit, applied) == terminal
        replay = reloaded.begin_commit(commit, must_not_reissue)
        assert replay.status is CommitAdmissionStatus.TERMINAL
        assert replay.acceptance == admission.acceptance
        assert replay.retained_outcome == applied
        assert reloaded.pending() == ()

        query = _query(artifacts, prepare, sequence=5)
        answers = 0

        def issue_outcome(
            request: SignedEffectQueryRequest,
            record: CoordinationJournalRecord,
            retained_at: Any,
        ) -> SignedEffectOutcome:
            nonlocal answers
            answers += 1
            assert record.state is CoordinationState.APPLIED
            return _outcome(
                artifacts,
                request,
                admission.acceptance,
                disposition=EffectDisposition.APPLIED,
                signed_offset=6,
            )

        answer = reloaded.answer_query(
            query,
            issue_outcome,
            recorded_at=NOW + timedelta(seconds=6),
        )
        assert reloaded.answer_query(query, issue_outcome) == answer
        assert answers == 1
        assert isinstance(reloaded.attempts(prepare.effect)[-1], EffectQueryAttempt)


def test_prepared_effect_query_closes_not_dispatched_without_acceptance(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    path = _secure_path(tmp_path)
    prepare = _prepare(artifacts)
    query = _query(artifacts, prepare, sequence=2)
    issued = 0

    def issue_not_dispatched(
        exact_query: SignedEffectQueryRequest,
        record: CoordinationJournalRecord,
        retained_at: datetime,
    ) -> SignedEffectOutcome:
        nonlocal issued
        issued += 1
        assert record.state is CoordinationState.DISPATCH_ARMED
        assert record.latest_acceptance is None
        return SignedEffectOutcome.issue(
            request=exact_query,
            disposition=EffectDisposition.NOT_DISPATCHED,
            reason="commit_not_retained_by_effect_coordinator",
            signer=artifacts.coordinator_signer,
            signed_at=retained_at,
        )

    with DurableEffectCoordinationJournal(
        path,
        owner_subject="ot-coordinator",
        initialize=True,
    ) as journal:
        _prepare_executor(journal, artifacts, prepare)
        outcome = journal.answer_query(
            query,
            issue_not_dispatched,
            recorded_at=NOW + timedelta(seconds=3),
        )
        assert outcome.disposition is EffectDisposition.NOT_DISPATCHED
        assert outcome.acceptance is None
        assert outcome.acknowledgment is None
        assert journal.answer_query(query, issue_not_dispatched) == outcome
        assert issued == 1
        record = journal.get(prepare.effect)
        assert record is not None
        assert record.state is CoordinationState.NOT_DISPATCHED
        assert record.latest_acceptance is None
        assert [transition.state for transition in record.transitions] == [
            CoordinationState.RECEIVED,
            CoordinationState.DISPATCH_ARMED,
            CoordinationState.NOT_DISPATCHED,
        ]

    with DurableEffectCoordinationJournal(path, owner_subject="ot-coordinator") as reloaded:
        assert reloaded.answer_query(query, issue_not_dispatched) == outcome
        assert issued == 1


def test_gateway_reconciliation_attempts_enumerate_without_unknown_self_transition(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    path = _secure_path(tmp_path)
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ) as journal:
        prepare, _, commit = _prepare_gateway(journal, artifacts)
        premature_query = _query(artifacts, prepare, sequence=2)
        with pytest.raises(IllegalCoordinationTransition, match="ambiguous commit"):
            journal.begin_query(
                premature_query,
                recorded_at=NOW + timedelta(seconds=2),
            )
        unknown = journal.mark_commit_unknown(
            commit,
            reason="commit_response_lost",
            failure_evidence_sha256="5" * 64,
            recorded_at=NOW + timedelta(seconds=2),
        )
        assert unknown.state is CoordinationState.DISPATCH_ARMED
        assert unknown.latest_acceptance is None
        acceptance = _acceptance(artifacts, commit)

        first_query = _query(artifacts, prepare, sequence=3)
        journal.begin_query(first_query, recorded_at=NOW + timedelta(seconds=3))
        journal.fail_query(
            first_query,
            reason="query_transport_timeout",
            failure_evidence_sha256="6" * 64,
            recorded_at=NOW + timedelta(seconds=4),
        )

        second_query = _query(artifacts, prepare, sequence=5)
        journal.begin_query(second_query, recorded_at=NOW + timedelta(seconds=5))
        signed_unknown = _outcome(
            artifacts,
            second_query,
            acceptance,
            disposition=EffectDisposition.UNKNOWN_EFFECT,
            signed_offset=6,
        )
        journal.complete_query(
            second_query,
            signed_unknown,
            recorded_at=NOW + timedelta(seconds=6),
        )

        third_query = _query(artifacts, prepare, sequence=7)
        journal.begin_query(third_query, recorded_at=NOW + timedelta(seconds=7))
        applied = _outcome(
            artifacts,
            third_query,
            acceptance,
            disposition=EffectDisposition.APPLIED,
            signed_offset=8,
        )
        terminal = journal.complete_query(
            third_query,
            applied,
            recorded_at=NOW + timedelta(seconds=8),
        )
        assert terminal.state is CoordinationState.APPLIED
        assert [item.state for item in terminal.transitions] == [
            CoordinationState.RECEIVED,
            CoordinationState.DISPATCH_ARMED,
            CoordinationState.COMMIT_ACCEPTED,
            CoordinationState.UNKNOWN_EFFECT,
            CoordinationState.APPLIED,
        ]
        assert [item.kind for item in terminal.attempts] == [
            "prepare",
            "commit",
            "query",
            "query",
            "query",
        ]
        assert terminal.attempts[2].status is CoordinationAttemptStatus.OUTCOME_UNKNOWN
        assert terminal.attempts[3].outcome == signed_unknown  # type: ignore[union-attr]
        assert terminal.attempts[4].outcome == applied  # type: ignore[union-attr]
        assert terminal.latest_acceptance == acceptance
        assert journal.complete_query(third_query, applied) == terminal

    with DurableGatewayCoordinationJournal(path, owner_subject="gateway") as reloaded:
        retained = reloaded.get(prepare.effect)
        assert retained == terminal
        assert retained is not None
        assert retained.latest_acceptance == acceptance
        assert retained.terminal_outcome == applied


def test_record_rejects_commit_bypass_backdating_and_unbound_terminal_evidence(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    path = _secure_path(tmp_path)
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ) as journal:
        prepare, receipt, commit = _prepare_gateway(journal, artifacts)
        acceptance = _acceptance(artifacts, commit)
        outcome = _outcome(
            artifacts,
            commit,
            acceptance,
            disposition=EffectDisposition.APPLIED,
            signed_offset=4,
        )
        terminal = journal.retain_commit_outcome(
            commit,
            outcome,
            recorded_at=NOW + timedelta(seconds=4),
        )

    raw = terminal.model_dump(mode="python")
    raw["transitions"][-1]["evidence_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="does not bind a retained outcome"):
        CoordinationJournalRecord.model_validate(raw)

    raw = terminal.model_dump(mode="python")
    raw["attempts"][0]["retained_at"] = NOW - timedelta(microseconds=1)
    with pytest.raises(ValidationError, match="cannot predate its signed request"):
        CoordinationJournalRecord.model_validate(raw)

    raw = terminal.model_dump(mode="python")
    raw["attempts"][0]["updated_at"] = NOW
    with pytest.raises(ValidationError, match="cannot predate its receipt"):
        CoordinationJournalRecord.model_validate(raw)

    query = _query(artifacts, prepare, sequence=5)
    query_outcome = _outcome(
        artifacts,
        query,
        acceptance,
        disposition=EffectDisposition.APPLIED,
        signed_offset=6,
    )
    terminal_query = EffectQueryAttempt(
        sequence=2,
        request=query,
        request_sha256=query.digest,
        status=CoordinationAttemptStatus.RESPONSE_RETAINED,
        outcome=query_outcome,
        retained_at=NOW + timedelta(seconds=5),
        updated_at=NOW + timedelta(seconds=6),
    )
    raw = terminal.model_dump(mode="python")
    raw["attempts"] = (terminal.attempts[0], terminal_query)
    raw["transitions"][-1]["evidence_sha256"] = query_outcome.digest
    with pytest.raises(ValidationError, match="exact retained commit acceptance"):
        CoordinationJournalRecord.model_validate(raw)

    raw = terminal.model_dump(mode="python")
    raw["attempts"][1]["updated_at"] = NOW + timedelta(seconds=3)
    with pytest.raises(ValidationError, match="cannot predate its outcome"):
        CoordinationJournalRecord.model_validate(raw)


def test_gateway_rejects_query_outcome_with_unretained_same_effect_receipt(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    path = _secure_path(tmp_path)
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ) as journal:
        prepare, _, commit = _prepare_gateway(journal, artifacts)
        journal.mark_commit_unknown(
            commit,
            reason="commit_response_lost",
            recorded_at=NOW + timedelta(seconds=2),
        )
        unretained_prepare = _retry_prepare(artifacts, sequence=3)
        unretained_receipt = _receipt(
            artifacts,
            unretained_prepare,
            prepared_offset=3.5,
        )
        unretained_commit = SignedEffectCommitRequest.issue(
            receipt=unretained_receipt,
            signer=artifacts.gateway_signer,
            request_nonce="unretained-commit-nonce-0001",
            issued_at=NOW + timedelta(seconds=3.75),
            expires_at=NOW + timedelta(seconds=30),
        )
        unretained_acceptance = _acceptance(
            artifacts,
            unretained_commit,
            accepted_offset=3.875,
        )
        query = _query(artifacts, prepare, sequence=4)
        journal.begin_query(query, recorded_at=NOW + timedelta(seconds=4))
        outcome = _outcome(
            artifacts,
            query,
            unretained_acceptance,
            disposition=EffectDisposition.UNKNOWN_EFFECT,
            signed_offset=5,
        )
        with pytest.raises(CoordinationCollisionError, match="not retained"):
            journal.complete_query(
                query,
                outcome,
                recorded_at=NOW + timedelta(seconds=5),
            )


def test_stored_acceptance_rejects_a_different_valid_acceptance(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    path = _secure_path(tmp_path)
    prepare = _prepare(artifacts)
    with DurableEffectCoordinationJournal(
        path,
        owner_subject="ot-coordinator",
        initialize=True,
    ) as journal:
        receipt = _prepare_executor(journal, artifacts, prepare)
        commit = _commit(artifacts, receipt)
        admission = journal.begin_commit(
            commit,
            _issue_acceptance(artifacts),
            recorded_at=NOW + timedelta(seconds=1),
        )
        different_acceptance = _acceptance(
            artifacts,
            commit,
            accepted_offset=1.25,
        )
        assert different_acceptance != admission.acceptance
        conflicting_outcome = _outcome(
            artifacts,
            commit,
            different_acceptance,
            disposition=EffectDisposition.APPLIED,
            signed_offset=4,
        )
        with pytest.raises(CoordinationCollisionError, match="different durable acceptance"):
            journal.finish_commit(
                commit,
                conflicting_outcome,
                recorded_at=NOW + timedelta(seconds=4),
            )
        retained = journal.get(prepare.effect)
        assert retained == admission.record
        assert retained is not None
        assert retained.latest_acceptance == admission.acceptance


@pytest.mark.parametrize("mutation", ["missing", "corrupt_signature"])
def test_effect_coordinator_rejects_missing_or_corrupt_acceptance_on_reload(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    mutation: str,
) -> None:
    path = _secure_path(tmp_path)
    prepare = _prepare(artifacts)
    with DurableEffectCoordinationJournal(
        path,
        owner_subject="ot-coordinator",
        initialize=True,
    ) as journal:
        receipt = _prepare_executor(journal, artifacts, prepare)
        commit = _commit(artifacts, receipt)
        journal.begin_commit(
            commit,
            _issue_acceptance(artifacts),
            recorded_at=NOW + timedelta(seconds=1),
        )

    parsed = json.loads(path.read_bytes())
    commit_attempt = parsed["entries"][0]["attempts"][-1]
    if mutation == "missing":
        commit_attempt["acceptance"] = None
    else:
        commit_attempt["acceptance"]["signature"] = "A" * 88
    path.write_bytes(journal_module._DurableCoordinationJournal._canonical_bytes(parsed))
    path.chmod(0o600)

    with pytest.raises(CoordinationJournalError, match="invalid record"):
        DurableEffectCoordinationJournal(path, owner_subject="ot-coordinator")


def test_not_dispatched_is_terminal_before_prepare_receipt(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    path = _secure_path(tmp_path)
    prepare = _prepare(artifacts)
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ) as journal:
        journal.begin(prepare, recorded_at=NOW)
        closed = journal.close_not_dispatched(
            prepare.effect,
            reason="local_admission_failed_before_dispatch",
            recorded_at=NOW + timedelta(milliseconds=1),
        )
        assert closed.state is CoordinationState.NOT_DISPATCHED
        assert journal.pending() == ()
        assert (
            journal.close_not_dispatched(
                prepare.effect,
                reason="local_admission_failed_before_dispatch",
            )
            == closed
        )
        with pytest.raises(IllegalCoordinationTransition, match="immutable"):
            journal.begin(_retry_prepare(artifacts, sequence=1))


def test_lifetime_writer_lock_rejects_a_second_writer(tmp_path: Path) -> None:
    path = _secure_path(tmp_path)
    first = DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    )
    try:
        with pytest.raises(CoordinationJournalError, match="already held"):
            DurableGatewayCoordinationJournal(path, owner_subject="gateway")
    finally:
        first.close()
    with DurableGatewayCoordinationJournal(path, owner_subject="gateway") as reopened:
        assert reopened.records() == ()


@pytest.mark.parametrize(
    "mutation",
    ["noncanonical", "duplicate", "corrupt", "nonfinite", "oversize"],
)
def test_journal_rejects_untrusted_encodings(tmp_path: Path, mutation: str) -> None:
    path = _secure_path(tmp_path)
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ):
        pass
    parsed = json.loads(path.read_bytes())
    if mutation == "noncanonical":
        path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    elif mutation == "duplicate":
        path.write_text(
            '{"entries":[],"entries":[],"journal_role":"gateway",'
            '"owner_subject":"gateway","schema_version":"m4i-coordination-journal-v2"}',
            encoding="utf-8",
        )
    elif mutation == "corrupt":
        path.write_bytes(b"{not-json")
    elif mutation == "nonfinite":
        path.write_text(
            '{"entries":[],"journal_role":"gateway","owner_subject":"gateway",'
            '"schema_version":NaN}',
            encoding="utf-8",
        )
    else:
        path.write_bytes(b" " * (DurableGatewayCoordinationJournal.MAX_JOURNAL_BYTES + 1))
    path.chmod(0o600)
    with pytest.raises(CoordinationJournalError):
        DurableGatewayCoordinationJournal(path, owner_subject="gateway")


def test_missing_permissions_role_and_symlink_fail_closed(tmp_path: Path) -> None:
    path = _secure_path(tmp_path)
    with pytest.raises(CoordinationJournalError, match="missing"):
        DurableGatewayCoordinationJournal(path, owner_subject="gateway")

    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ):
        pass
    path.chmod(0o644)
    with pytest.raises(CoordinationJournalError, match="0600"):
        DurableGatewayCoordinationJournal(path, owner_subject="gateway")
    path.chmod(0o600)
    with pytest.raises(CoordinationJournalError, match="identity"):
        DurableEffectCoordinationJournal(path, owner_subject="gateway")

    path.parent.chmod(0o750)
    with pytest.raises(CoordinationJournalError, match="0700"):
        DurableGatewayCoordinationJournal(path, owner_subject="gateway")
    path.parent.chmod(0o700)

    symlink_path = _secure_path(tmp_path, "symlink.json")
    target = symlink_path.parent / "target.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    os.symlink(target, symlink_path)
    with pytest.raises(CoordinationJournalError, match="missing or unavailable"):
        DurableGatewayCoordinationJournal(symlink_path, owner_subject="gateway")


def test_commit_acceptance_issuer_and_fsync_fail_before_new_admission(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepare = _prepare(artifacts)
    issuer_path = _secure_path(tmp_path, "issuer-failure.json")
    with DurableEffectCoordinationJournal(
        issuer_path,
        owner_subject="ot-coordinator",
        initialize=True,
    ) as journal:
        receipt = _prepare_executor(journal, artifacts, prepare)
        commit = _commit(artifacts, receipt)

        def fail_issuer(
            exact_request: SignedEffectCommitRequest,
            *,
            accepted_at: datetime,
            transition_sequence: Literal[3],
        ) -> DurableCommitAcceptance:
            del exact_request, accepted_at, transition_sequence
            raise RuntimeError("injected acceptance issuer failure")

        with pytest.raises(RuntimeError, match="issuer failure"):
            journal.begin_commit(
                commit,
                fail_issuer,
                recorded_at=NOW + timedelta(seconds=1),
            )
        retained = journal.get(prepare.effect)
        assert retained is not None
        assert retained.state is CoordinationState.DISPATCH_ARMED
        assert not any(isinstance(item, EffectCommitAttempt) for item in retained.attempts)

    fsync_path = _secure_path(tmp_path, "acceptance-fsync-failure.json")
    journal = DurableEffectCoordinationJournal(
        fsync_path,
        owner_subject="ot-coordinator",
        initialize=True,
    )
    receipt = _prepare_executor(journal, artifacts, prepare)
    commit = _commit(artifacts, receipt)
    real_fsync = os.fsync
    issued = 0

    def issue_acceptance(
        exact_request: SignedEffectCommitRequest,
        *,
        accepted_at: datetime,
        transition_sequence: Literal[3],
    ) -> DurableCommitAcceptance:
        nonlocal issued
        issued += 1
        return DurableCommitAcceptance.issue(
            request=exact_request,
            signer=artifacts.coordinator_signer,
            accepted_at=accepted_at,
            transition_sequence=transition_sequence,
        )

    def fail_file_fsync(descriptor: int) -> None:
        del descriptor
        raise OSError("injected acceptance fsync failure")

    monkeypatch.setattr(os, "fsync", fail_file_fsync)
    with pytest.raises(CoordinationJournalError, match="update failed"):
        journal.begin_commit(
            commit,
            issue_acceptance,
            recorded_at=NOW + timedelta(seconds=1),
        )
    assert issued == 1
    with pytest.raises(CoordinationJournalError, match="unusable"):
        journal.records()
    journal.close()

    monkeypatch.setattr(os, "fsync", real_fsync)
    with DurableEffectCoordinationJournal(
        fsync_path,
        owner_subject="ot-coordinator",
    ) as reloaded:
        retained = reloaded.get(prepare.effect)
        assert retained is not None
        assert retained.state is CoordinationState.DISPATCH_ARMED
        assert retained.latest_acceptance is None
        assert not any(isinstance(item, EffectCommitAttempt) for item in retained.attempts)


def test_capacity_precedes_issuer_and_uncertain_receipt_write_poison_writer(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepare = _prepare(artifacts)
    capacity_path = _secure_path(tmp_path)
    with DurableEffectCoordinationJournal(
        capacity_path,
        owner_subject="ot-coordinator",
        initialize=True,
    ) as journal:
        monkeypatch.setattr(journal, "MAX_ENTRIES", 0)
        issued = 0

        def must_not_issue(
            request: SignedEffectPrepareRequest,
            retained_at: Any,
        ) -> CoordinationReceipt:
            nonlocal issued
            issued += 1
            return _receipt(artifacts, request)

        with pytest.raises(CoordinationJournalError, match="capacity"):
            journal.prepare_effect(prepare, must_not_issue)
        assert issued == 0
        assert journal.records() == ()

    failure_path = _secure_path(tmp_path, "failure.json")
    journal = DurableEffectCoordinationJournal(
        failure_path,
        owner_subject="ot-coordinator",
        initialize=True,
    )
    real_fsync = os.fsync
    calls = 0

    def fail_directory_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(CoordinationJournalError, match="update failed"):
        _prepare_executor(journal, artifacts, prepare)
    with pytest.raises(CoordinationJournalError, match="unusable"):
        journal.records()
    journal.close()
