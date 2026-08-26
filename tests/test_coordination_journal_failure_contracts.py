from __future__ import annotations

import copy
import json
import os
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from test_coordination_journal import (
    _acceptance,
    _issue_acceptance,
    _outcome,
    _prepare_executor,
    _query,
    _same_action_different_effect,
    _secure_path,
)
from test_m4i_models import NOW, M4iArtifacts, _commit, _prepare, _receipt
from test_m4i_models import artifacts as m4i_artifacts_fixture

import aegis_ot.coordination_journal as journal_module
from aegis_ot.coordination_journal import (
    CommitAdmission,
    CommitAdmissionStatus,
    CoordinationAttemptStatus,
    CoordinationJournalError,
    CoordinationJournalRecord,
    CoordinationTransition,
    DurableEffectCoordinationJournal,
    DurableGatewayCoordinationJournal,
    EffectCommitAttempt,
    EffectPrepareAttempt,
    EffectQueryAttempt,
)
from aegis_ot.coordination_models import (
    CapabilityOutcomePending,
    CapabilityOutcomeResolution,
    CoordinationReceipt,
    CoordinationState,
    DurableCommitAcceptance,
    EffectDisposition,
    EffectIdentity,
    SignedEffectCommitRequest,
    SignedEffectOutcome,
    SignedEffectPrepareRequest,
    SignedEffectQueryRequest,
)
from aegis_ot.workload_identity import WorkloadSigner


@pytest.fixture
def artifacts(tmp_path: Path) -> M4iArtifacts:
    factory = cast(Callable[[Path], M4iArtifacts], cast(Any, m4i_artifacts_fixture).__wrapped__)
    return factory(tmp_path)


@pytest.fixture
def attempt_values(artifacts: M4iArtifacts) -> dict[str, Any]:
    prepare = _prepare(artifacts)
    receipt = _receipt(artifacts, prepare)
    commit = _commit(artifacts, receipt)
    acceptance = _acceptance(artifacts, commit)
    commit_outcome = _outcome(
        artifacts,
        commit,
        acceptance,
        disposition=EffectDisposition.APPLIED,
        signed_offset=4,
    )
    query = _query(artifacts, prepare, sequence=5)
    query_outcome = _outcome(
        artifacts,
        query,
        acceptance,
        disposition=EffectDisposition.APPLIED,
        signed_offset=6,
    )
    prepare_attempt = EffectPrepareAttempt(
        sequence=1,
        request=prepare,
        request_sha256=prepare.digest,
        status=CoordinationAttemptStatus.RESPONSE_RETAINED,
        receipt=receipt,
        retained_at=NOW,
        updated_at=NOW + timedelta(seconds=0.5),
    )
    commit_attempt = EffectCommitAttempt(
        sequence=2,
        request=commit,
        request_sha256=commit.digest,
        status=CoordinationAttemptStatus.RESPONSE_RETAINED,
        acceptance=acceptance,
        outcome=commit_outcome,
        retained_at=NOW + timedelta(seconds=1),
        updated_at=NOW + timedelta(seconds=4),
    )
    query_attempt = EffectQueryAttempt(
        sequence=3,
        request=query,
        request_sha256=query.digest,
        status=CoordinationAttemptStatus.RESPONSE_RETAINED,
        outcome=query_outcome,
        retained_at=NOW + timedelta(seconds=5),
        updated_at=NOW + timedelta(seconds=6),
    )
    return {
        "prepare": prepare_attempt.model_dump(mode="python"),
        "commit": commit_attempt.model_dump(mode="python"),
        "query": query_attempt.model_dump(mode="python"),
    }


def _mutate_attempt(raw: dict[str, Any], mutation: str) -> None:
    if mutation == "naive-retained-at":
        raw["retained_at"] = raw["retained_at"].replace(tzinfo=None)
    elif mutation == "updated-before-retained":
        raw["updated_at"] = raw["retained_at"] - timedelta(microseconds=1)
    elif mutation == "request-digest":
        raw["request_sha256"] = "0" * 64
    elif mutation == "retained-before-request":
        raw["retained_at"] = raw["request"]["issued_at"] - timedelta(microseconds=1)
    elif mutation == "prepare-unknown":
        raw["status"] = CoordinationAttemptStatus.OUTCOME_UNKNOWN
    elif mutation == "prepare-request-with-receipt":
        raw["status"] = CoordinationAttemptStatus.REQUEST_RETAINED
    elif mutation == "prepare-response-without-receipt":
        raw["receipt"] = None
    elif mutation == "prepare-before-receipt":
        raw["updated_at"] = raw["receipt"]["prepared_at"] - timedelta(microseconds=1)
    elif mutation == "commit-response-without-acceptance":
        raw["acceptance"] = None
    elif mutation == "commit-response-with-failure":
        raw["failure_reason"] = "contradictory_failure"
    elif mutation == "commit-before-acceptance":
        raw["updated_at"] = raw["acceptance"]["accepted_at"] - timedelta(microseconds=1)
    elif mutation == "commit-before-outcome":
        raw["updated_at"] = raw["outcome"]["signed_at"] - timedelta(microseconds=1)
    elif mutation == "commit-unknown-with-outcome":
        raw["status"] = CoordinationAttemptStatus.OUTCOME_UNKNOWN
        raw["failure_reason"] = "delivery_failed"
    elif mutation == "commit-unknown-without-failure":
        raw["status"] = CoordinationAttemptStatus.OUTCOME_UNKNOWN
        raw["outcome"] = None
    elif mutation == "commit-request-with-outcome":
        raw["status"] = CoordinationAttemptStatus.REQUEST_RETAINED
        raw["acceptance"] = None
    elif mutation == "query-response-without-outcome":
        raw["outcome"] = None
    elif mutation == "query-response-with-failure":
        raw["failure_reason"] = "contradictory_failure"
    elif mutation == "query-before-outcome":
        raw["updated_at"] = raw["outcome"]["signed_at"] - timedelta(microseconds=1)
    elif mutation == "query-unknown-with-outcome":
        raw["status"] = CoordinationAttemptStatus.OUTCOME_UNKNOWN
        raw["failure_reason"] = "delivery_failed"
    elif mutation == "query-unknown-without-failure":
        raw["status"] = CoordinationAttemptStatus.OUTCOME_UNKNOWN
        raw["outcome"] = None
    elif mutation == "query-request-with-outcome":
        raw["status"] = CoordinationAttemptStatus.REQUEST_RETAINED
    else:
        raise AssertionError(mutation)


@pytest.mark.parametrize(
    ("kind", "mutation", "message"),
    (
        ("prepare", "naive-retained-at", "timezone-aware"),
        ("prepare", "updated-before-retained", "cannot precede retention"),
        ("prepare", "request-digest", "request binding"),
        ("prepare", "retained-before-request", "predate its signed request"),
        ("prepare", "prepare-unknown", "cannot assert an unknown outcome"),
        ("prepare", "prepare-request-with-receipt", "cannot retain a receipt"),
        ("prepare", "prepare-response-without-receipt", "does not bind"),
        ("prepare", "prepare-before-receipt", "cannot predate its receipt"),
        ("commit", "request-digest", "request binding"),
        ("commit", "retained-before-request", "predate its signed request"),
        ("commit", "commit-response-without-acceptance", "does not bind"),
        ("commit", "commit-response-with-failure", "cannot assert delivery failure"),
        ("commit", "commit-before-acceptance", "cannot predate acceptance"),
        ("commit", "commit-before-outcome", "cannot predate its outcome"),
        ("commit", "commit-unknown-with-outcome", "bounded failure evidence"),
        ("commit", "commit-unknown-without-failure", "bounded failure evidence"),
        ("commit", "commit-request-with-outcome", "cannot assert an outcome"),
        ("query", "request-digest", "request binding"),
        ("query", "retained-before-request", "predate its signed request"),
        ("query", "query-response-without-outcome", "does not bind"),
        ("query", "query-response-with-failure", "cannot assert delivery failure"),
        ("query", "query-before-outcome", "cannot predate its outcome"),
        ("query", "query-unknown-with-outcome", "bounded failure evidence"),
        ("query", "query-unknown-without-failure", "bounded failure evidence"),
        ("query", "query-request-with-outcome", "cannot assert an outcome"),
    ),
)
def test_attempt_models_reject_contradictory_durable_history(
    attempt_values: dict[str, Any],
    kind: str,
    mutation: str,
    message: str,
) -> None:
    model = {
        "prepare": EffectPrepareAttempt,
        "commit": EffectCommitAttempt,
        "query": EffectQueryAttempt,
    }[kind]
    raw = copy.deepcopy(attempt_values[kind])
    _mutate_attempt(raw, mutation)

    with pytest.raises(ValidationError, match=message):
        model.model_validate(raw)


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        (
            {
                "sequence": 1,
                "state": CoordinationState.RECEIVED,
                "disposition": EffectDisposition.APPLIED,
                "evidence_sha256": None,
                "reason": "invalid disposition",
                "recorded_at": NOW,
            },
            "disposition is inconsistent",
        ),
        (
            {
                "sequence": 1,
                "state": CoordinationState.RECEIVED,
                "disposition": None,
                "evidence_sha256": None,
                "reason": "naive time",
                "recorded_at": NOW.replace(tzinfo=None),
            },
            "timezone-aware",
        ),
        (
            {
                "sequence": 1,
                "state": CoordinationState.APPLIED,
                "disposition": EffectDisposition.APPLIED,
                "evidence_sha256": None,
                "reason": "missing terminal evidence",
                "recorded_at": NOW,
            },
            "requires exact outcome evidence",
        ),
    ),
)
def test_transition_requires_closed_disposition_time_and_evidence(
    raw: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        CoordinationTransition.model_validate(raw)


@pytest.fixture
def terminal_values(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> dict[str, Any]:
    path = _secure_path(tmp_path, "coverage-terminal.json")
    prepare = _prepare(artifacts)
    with DurableEffectCoordinationJournal(
        path,
        owner_subject="coverage-effect-coordinator",
        initialize=True,
    ) as journal:
        receipt = _prepare_executor(journal, artifacts, prepare)
        commit = _commit(artifacts, receipt)
        admission = journal.begin_commit(
            commit,
            _issue_acceptance(artifacts),
            recorded_at=NOW + timedelta(seconds=1),
        )
        outcome = _outcome(
            artifacts,
            commit,
            admission.acceptance,
            disposition=EffectDisposition.APPLIED,
            signed_offset=4,
        )
        record = journal.finish_commit(
            commit,
            outcome,
            recorded_at=NOW + timedelta(seconds=4),
        )
    return {
        "record": record.model_dump(mode="python"),
        "admission": admission.model_dump(mode="python"),
        "outcome": outcome,
    }


def _mutate_record(raw: dict[str, Any], mutation: str) -> None:
    if mutation == "effect-digest":
        raw["effect_sha256"] = "0" * 64
    elif mutation == "first-state":
        raw["transitions"][0]["state"] = CoordinationState.DISPATCH_ARMED
    elif mutation == "transition-sequence":
        raw["transitions"][1]["sequence"] = 3
    elif mutation == "transition-chronology":
        raw["transitions"][1]["recorded_at"] = NOW - timedelta(microseconds=1)
    elif mutation == "illegal-transition":
        raw["transitions"][1]["state"] = CoordinationState.RECEIVED
    elif mutation == "attempt-sequence":
        raw["attempts"][1]["sequence"] = 3
    elif mutation == "post-commit-without-intent":
        raw["attempts"] = raw["attempts"][:1]
    elif mutation == "post-commit-without-acceptance":
        commit = raw["attempts"][1]
        commit["status"] = CoordinationAttemptStatus.REQUEST_RETAINED
        commit["acceptance"] = None
        commit["outcome"] = None
        raw["transitions"] = raw["transitions"][:3]
    elif mutation == "acceptance-transition-binding":
        raw["transitions"][2]["evidence_sha256"] = "0" * 64
    elif mutation == "terminal-disposition":
        raw["transitions"][-1]["state"] = CoordinationState.REJECTED
        raw["transitions"][-1]["disposition"] = EffectDisposition.REJECTED
    elif mutation == "terminal-evidence":
        raw["transitions"][-1]["evidence_sha256"] = "0" * 64
    elif mutation == "nonterminal-outcome":
        raw["transitions"] = raw["transitions"][:-1]
    else:
        raise AssertionError(mutation)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("effect-digest", "effect hash is inconsistent"),
        ("first-state", "must begin in received state"),
        ("transition-sequence", "transition sequence is not contiguous"),
        ("transition-chronology", "transition chronology is inconsistent"),
        ("illegal-transition", "illegal state transition"),
        ("attempt-sequence", "attempt sequence is not contiguous"),
        ("post-commit-without-intent", "lacks a retained commit intent"),
        ("post-commit-without-acceptance", "lacks durable commit acceptance"),
        ("acceptance-transition-binding", "transition binding is inconsistent"),
        ("terminal-disposition", "lacks one consistent exact outcome"),
        ("terminal-evidence", "does not bind a retained outcome"),
        ("nonterminal-outcome", "cannot retain terminal outcome evidence"),
    ),
)
def test_record_rejects_impossible_state_machine_histories(
    terminal_values: dict[str, Any],
    mutation: str,
    message: str,
) -> None:
    raw = copy.deepcopy(terminal_values["record"])
    _mutate_record(raw, mutation)

    with pytest.raises(ValidationError, match=message):
        CoordinationJournalRecord.model_validate(raw)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("request", "lacks its retained intent"),
        ("acceptance", "does not expose its retained acceptance"),
        ("new-outcome", "new commit admission is inconsistent"),
        ("terminal-without-outcome", "terminal commit admission is inconsistent"),
        ("indeterminate-with-outcome", "indeterminate commit admission is inconsistent"),
    ),
)
def test_commit_admission_cannot_overstate_execution_state(
    terminal_values: dict[str, Any],
    mutation: str,
    message: str,
) -> None:
    raw = copy.deepcopy(terminal_values["admission"])
    outcome = terminal_values["outcome"]
    if mutation == "request":
        raw["request"]["request_nonce"] = "changed-commit-request-nonce-0001"
    elif mutation == "acceptance":
        raw["acceptance"]["accepted_at"] += timedelta(microseconds=1)
    elif mutation == "new-outcome":
        raw["retained_outcome"] = outcome
    elif mutation == "terminal-without-outcome":
        raw["status"] = CommitAdmissionStatus.TERMINAL
    else:
        raw["status"] = CommitAdmissionStatus.INDETERMINATE
        raw["retained_outcome"] = outcome

    with pytest.raises(ValidationError, match=message):
        CommitAdmission.model_validate(raw)


def _canonical_document(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("fields", "unexpected or missing fields"),
        ("schema", "schema is unsupported"),
        ("entries-type", "entry set is invalid"),
        ("entry-shape", "entry shape is invalid"),
    ),
)
def test_journal_rejects_structurally_valid_but_untrusted_documents(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    path = _secure_path(tmp_path, f"{mutation}.json")
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ):
        pass
    document = json.loads(path.read_bytes())
    if mutation == "fields":
        document["untrusted"] = True
    elif mutation == "schema":
        document["schema_version"] = "m4i-coordination-journal-v999"
    elif mutation == "entries-type":
        document["entries"] = {}
    else:
        document["entries"] = ["not-a-record"]
    path.write_bytes(_canonical_document(document))
    path.chmod(0o600)

    with pytest.raises(CoordinationJournalError, match=message):
        DurableGatewayCoordinationJournal(path, owner_subject="gateway")


def test_journal_rejects_duplicate_sorted_identity_and_wrong_role_history(
    tmp_path: Path,
    terminal_values: dict[str, Any],
    artifacts: M4iArtifacts,
) -> None:
    record = CoordinationJournalRecord.model_validate(
        terminal_values["record"]
    ).model_dump(mode="json")
    duplicate_path = _secure_path(tmp_path, "duplicate-effect.json")
    duplicate_path.write_bytes(
        _canonical_document(
            {
                "entries": [record, record],
                "journal_role": "effect_coordinator",
                "owner_subject": "coverage-effect-coordinator",
                "schema_version": "m4i-coordination-journal-v2",
            }
        )
    )
    duplicate_path.chmod(0o600)
    with pytest.raises(CoordinationJournalError, match="not sorted and unique"):
        DurableEffectCoordinationJournal(
            duplicate_path,
            owner_subject="coverage-effect-coordinator",
        )

    gateway_path = _secure_path(tmp_path, "missing-acceptance.json")
    prepare = _prepare(artifacts)
    receipt = _receipt(artifacts, prepare)
    commit = _commit(artifacts, receipt)
    with DurableGatewayCoordinationJournal(
        gateway_path,
        owner_subject="ot-coordinator",
        initialize=True,
    ) as gateway:
        gateway.begin(prepare, recorded_at=NOW)
        gateway.retain_preparation(prepare, receipt, recorded_at=receipt.prepared_at)
        gateway.begin_commit(commit, recorded_at=commit.issued_at)
        gateway_record = gateway.records()[0].model_dump(mode="json")
    gateway_path.write_bytes(
        _canonical_document(
            {
                "entries": [gateway_record],
                "journal_role": "effect_coordinator",
                "owner_subject": "ot-coordinator",
                "schema_version": "m4i-coordination-journal-v2",
            }
        )
    )
    gateway_path.chmod(0o600)
    with pytest.raises(CoordinationJournalError, match="lacks durable acceptance"):
        DurableEffectCoordinationJournal(gateway_path, owner_subject="ot-coordinator")


def test_writer_identity_parent_and_file_shape_fail_closed(tmp_path: Path) -> None:
    missing_parent = tmp_path / "missing" / "journal.json"
    with pytest.raises(CoordinationJournalError, match="directory is unavailable"):
        DurableGatewayCoordinationJournal(missing_parent, owner_subject="gateway")

    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(CoordinationJournalError, match="non-symlink directory"):
        DurableGatewayCoordinationJournal(parent_file / "journal.json", owner_subject="gateway")

    journal_directory = tmp_path / "journal-directory"
    journal_directory.mkdir(mode=0o700)
    with pytest.raises(CoordinationJournalError, match="regular non-symlink file"):
        DurableGatewayCoordinationJournal(journal_directory, owner_subject="gateway")

    path = _secure_path(tmp_path, "lock-state.json")
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ):
        pass
    lock_path = journal_module._LifetimeWriterLock.path_for(path)
    lock_path.chmod(0o644)
    with pytest.raises(CoordinationJournalError, match="lock mode must be 0600"):
        DurableGatewayCoordinationJournal(path, owner_subject="gateway")


def test_writer_lock_rejects_inherited_or_closed_authority(tmp_path: Path) -> None:
    path = _secure_path(tmp_path, "writer-authority.json")
    journal = DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    )
    writer = journal._writer_lock
    assert writer is not None
    writer._owner_pid = os.getpid() + 1
    with pytest.raises(CoordinationJournalError, match="inherited child process"):
        journal.records()
    writer._owner_pid = os.getpid()
    writer.close()
    with pytest.raises(CoordinationJournalError, match="writer lock is closed"):
        journal.records()
    journal.close()


def test_existing_initialization_and_naive_transition_are_rejected(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    path = _secure_path(tmp_path, "initialize-once.json")
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ):
        pass
    with pytest.raises(CoordinationJournalError, match="already exists"):
        DurableGatewayCoordinationJournal(
            path,
            owner_subject="gateway",
            initialize=True,
        )

    with DurableGatewayCoordinationJournal(path, owner_subject="gateway") as journal:
        with pytest.raises(CoordinationJournalError, match="timezone-aware"):
            journal.begin(
                _prepare(artifacts),
                recorded_at=datetime(2026, 8, 25, 15, 0),
            )


def test_read_and_write_uncertainty_poison_the_writer(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_path = _secure_path(tmp_path, "read-failure.json")
    with DurableGatewayCoordinationJournal(
        read_path,
        owner_subject="gateway",
        initialize=True,
    ):
        pass
    real_read = os.read

    def fail_read(descriptor: int, size: int) -> bytes:
        del descriptor, size
        raise OSError("synthetic durable read failure")

    monkeypatch.setattr(journal_module.os, "read", fail_read)
    with pytest.raises(CoordinationJournalError, match="cannot be read"):
        DurableGatewayCoordinationJournal(read_path, owner_subject="gateway")
    monkeypatch.setattr(journal_module.os, "read", real_read)

    write_path = _secure_path(tmp_path, "write-failure.json")
    journal = DurableGatewayCoordinationJournal(
        write_path,
        owner_subject="gateway",
        initialize=True,
    )
    real_write = os.write

    def zero_progress(descriptor: int, material: bytes) -> int:
        del descriptor, material
        return 0

    monkeypatch.setattr(journal_module.os, "write", zero_progress)
    with pytest.raises(CoordinationJournalError, match="update failed"):
        journal.begin(_prepare(artifacts), recorded_at=NOW)
    with pytest.raises(CoordinationJournalError, match="unusable"):
        journal.records()
    monkeypatch.setattr(journal_module.os, "write", real_write)
    journal.close()


def test_capacity_and_lookup_inputs_fail_before_state_change(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _secure_path(tmp_path, "bounded.json")
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject="gateway",
        initialize=True,
    ) as journal:
        monkeypatch.setattr(journal, "MAX_ENTRIES", 0)
        with pytest.raises(CoordinationJournalError, match="at capacity"):
            journal.begin(_prepare(artifacts), recorded_at=NOW)
        with pytest.raises(CoordinationJournalError, match="digest is invalid"):
            journal.find_action("not-a-digest", "actor", "nonce")
        assert journal.records() == ()


@pytest.fixture
def protocol_values(artifacts: M4iArtifacts) -> dict[str, Any]:
    prepare = _prepare(artifacts)
    receipt = _receipt(artifacts, prepare)
    commit = _commit(artifacts, receipt)
    acceptance = _acceptance(artifacts, commit)
    applied = _outcome(
        artifacts,
        commit,
        acceptance,
        disposition=EffectDisposition.APPLIED,
        signed_offset=4,
    )
    query = _query(artifacts, prepare, sequence=5)
    queried_applied = _outcome(
        artifacts,
        query,
        acceptance,
        disposition=EffectDisposition.APPLIED,
        signed_offset=6,
    )
    queried_unknown = _outcome(
        artifacts,
        query,
        acceptance,
        disposition=EffectDisposition.UNKNOWN_EFFECT,
        signed_offset=6,
    )
    resolution = CapabilityOutcomeResolution(
        effect=prepare.effect,
        prior_state=CoordinationState.UNKNOWN_EFFECT,
        disposition=EffectDisposition.APPLIED,
        query=query,
        acceptance=acceptance,
        outcome=queried_applied,
        resolved_at=NOW + timedelta(seconds=7),
    )
    pending = CapabilityOutcomePending(
        effect=prepare.effect,
        prior_state=CoordinationState.UNKNOWN_EFFECT,
        query=query,
        acceptance=acceptance,
        outcome=queried_unknown,
        retained_at=NOW + timedelta(seconds=7),
    )
    other_prepare = _same_action_different_effect(artifacts)
    other_receipt = CoordinationReceipt.issue(
        request=other_prepare,
        signer=artifacts.coordinator_signer,
        prepared_at=NOW + timedelta(seconds=0.5),
    )
    return {
        "effect": prepare.effect,
        "prepare": prepare,
        "receipt": receipt,
        "commit": commit,
        "acceptance": acceptance,
        "applied": applied,
        "query": query,
        "queried_applied": queried_applied,
        "resolution": resolution,
        "pending": pending,
        "other_effect": other_prepare.effect,
        "other_receipt": other_receipt,
    }


def _credential_with_claims(credential: Any, **updates: Any) -> Any:
    return credential.model_copy(
        update={"credential": credential.credential.model_copy(update=updates)}
    )


@pytest.mark.parametrize(
    ("kind", "mutation", "message"),
    (
        ("effect", "whitespace", "outer whitespace"),
        ("effect", "version", "advance exactly one state version"),
        ("prepare", "effect-hash", "effect hash is inconsistent"),
        ("prepare", "identity", "identity does not match"),
        ("prepare", "role", "requires a gateway"),
        ("prepare", "audience", "audience is not authorized"),
        ("receipt", "effect-hash", "effect hash is inconsistent"),
        ("receipt", "prepare-hash", "prepare binding is inconsistent"),
        ("receipt", "naive", "timezone-aware"),
        ("receipt", "window", "outside the prepare window"),
        ("receipt", "role", "requires an OT coordinator"),
        ("receipt", "audience", "audience is not authorized"),
        ("receipt", "credential-time", "not valid at preparation"),
        ("receipt", "target", "not the prepared OT target"),
        ("commit", "receipt-effect", "different effect"),
        ("commit", "receipt-hash", "receipt hash is inconsistent"),
        ("commit", "chronology", "cannot precede preparation"),
        ("acceptance", "effect", "effect binding is inconsistent"),
        ("acceptance", "request-hash", "request hash is inconsistent"),
        ("acceptance", "naive", "timezone-aware"),
        ("acceptance", "window", "outside the commit window"),
        ("acceptance", "preparation", "cannot precede durable preparation"),
        ("acceptance", "role", "requires an OT coordinator"),
        ("acceptance", "audience", "audience is not authorized"),
        ("acceptance", "signer", "differs from the prepared OT target"),
        ("acceptance", "credential-time", "not valid at acceptance"),
        ("outcome", "effect-hash", "outcome hash is inconsistent"),
        ("outcome", "naive", "timezone-aware"),
        ("outcome", "role", "requires an OT coordinator"),
        ("outcome", "audience", "audience is not authorized"),
        ("outcome", "credential-time", "not valid at signing"),
        ("outcome", "not-dispatched-kind", "only valid for a query"),
        ("outcome", "not-dispatched-evidence", "cannot assert dispatch evidence"),
        ("outcome", "acceptance", "requires its exact durable commit acceptance"),
        ("outcome", "acceptance-time", "cannot precede durable commit acceptance"),
        ("outcome", "coordinator", "coordinator differs"),
        ("outcome", "terminal-ack", "requires a matching PLC acknowledgment"),
        ("outcome", "unknown-ack", "cannot retain known-effect evidence"),
        ("outcome", "ack-time", "chronology is inconsistent"),
        ("outcome", "ack-transaction", "transaction is invalid"),
        ("resolution", "naive", "time must be timezone-aware"),
        ("resolution", "binding", "bindings are inconsistent"),
        ("pending", "naive", "time must be timezone-aware"),
        ("pending", "binding", "bindings are inconsistent"),
    ),
)
def test_protocol_models_reject_corrupted_state_claims(
    protocol_values: dict[str, Any],
    kind: str,
    mutation: str,
    message: str,
) -> None:
    model = {
        "effect": EffectIdentity,
        "prepare": SignedEffectPrepareRequest,
        "receipt": CoordinationReceipt,
        "commit": SignedEffectCommitRequest,
        "acceptance": DurableCommitAcceptance,
        "outcome": SignedEffectOutcome,
        "resolution": CapabilityOutcomeResolution,
        "pending": CapabilityOutcomePending,
    }[kind]
    source_name = "applied" if kind == "outcome" else kind
    raw = protocol_values[source_name].model_dump(mode="python")
    receipt = protocol_values["receipt"]
    commit = protocol_values["commit"]
    acceptance = protocol_values["acceptance"]
    applied = protocol_values["applied"]
    if kind == "effect" and mutation == "whitespace":
        raw["target_id"] = f" {raw['target_id']}"
    elif kind == "effect":
        raw["expected_post_state_version"] = raw["authorized_state_version"]
    elif kind == "prepare" and mutation == "effect-hash":
        raw["effect_sha256"] = "0" * 64
    elif kind == "prepare" and mutation == "identity":
        raw["effect"] = protocol_values["other_effect"]
        raw["effect_sha256"] = protocol_values["other_effect"].digest
    elif kind == "prepare" and mutation == "role":
        raw["sender_credential"] = acceptance.coordinator_credential
    elif kind == "prepare":
        raw["audience"] = "aegis-ot:untrusted"
    elif kind == "receipt" and mutation == "effect-hash":
        raw["effect_sha256"] = "0" * 64
    elif kind == "receipt" and mutation == "prepare-hash":
        raw["prepare_request_sha256"] = "0" * 64
    elif kind == "receipt" and mutation == "naive":
        raw["prepared_at"] = receipt.prepared_at.replace(tzinfo=None)
    elif kind == "receipt" and mutation == "window":
        raw["prepared_at"] = receipt.prepare_request.expires_at
    elif kind == "receipt" and mutation == "role":
        raw["coordinator_credential"] = receipt.prepare_request.sender_credential
    elif kind == "receipt" and mutation == "audience":
        raw["audience"] = "aegis-ot:untrusted"
    elif kind == "receipt" and mutation == "credential-time":
        raw["coordinator_credential"] = _credential_with_claims(
            receipt.coordinator_credential,
            not_before=receipt.prepared_at + timedelta(seconds=1),
        )
    elif kind == "receipt":
        raw["coordinator_credential"] = _credential_with_claims(
            receipt.coordinator_credential,
            key_id="sha256:" + "1" * 64,
        )
    elif kind == "commit" and mutation == "receipt-effect":
        raw["receipt"] = protocol_values["other_receipt"]
    elif kind == "commit" and mutation == "receipt-hash":
        raw["receipt_sha256"] = "0" * 64
    elif kind == "commit":
        raw["issued_at"] = receipt.prepared_at - timedelta(microseconds=1)
    elif kind == "acceptance" and mutation == "effect":
        raw["effect"] = protocol_values["other_effect"]
    elif kind == "acceptance" and mutation == "request-hash":
        raw["commit_request_sha256"] = "0" * 64
    elif kind == "acceptance" and mutation == "naive":
        raw["accepted_at"] = acceptance.accepted_at.replace(tzinfo=None)
    elif kind == "acceptance" and mutation == "window":
        raw["accepted_at"] = commit.expires_at
    elif kind == "acceptance" and mutation == "preparation":
        raw["commit_request"] = commit.model_copy(
            update={"issued_at": NOW, "expires_at": NOW + timedelta(seconds=31)}
        )
        raw["accepted_at"] = receipt.prepared_at - timedelta(microseconds=1)
    elif kind == "acceptance" and mutation == "role":
        raw["coordinator_credential"] = commit.sender_credential
    elif kind == "acceptance" and mutation == "audience":
        raw["audience"] = "aegis-ot:untrusted"
    elif kind == "acceptance" and mutation == "signer":
        raw["coordinator_credential"] = _credential_with_claims(
            acceptance.coordinator_credential,
            subject="spiffe://aegis-ot.test/workload/other-ot",
        )
    elif kind == "acceptance":
        raw["coordinator_credential"] = _credential_with_claims(
            acceptance.coordinator_credential,
            not_before=acceptance.accepted_at + timedelta(seconds=1),
        )
    elif kind == "outcome" and mutation == "effect-hash":
        raw["effect_sha256"] = "0" * 64
    elif kind == "outcome" and mutation == "naive":
        raw["signed_at"] = applied.signed_at.replace(tzinfo=None)
    elif kind == "outcome" and mutation == "role":
        raw["coordinator_credential"] = commit.sender_credential
    elif kind == "outcome" and mutation == "audience":
        raw["audience"] = "aegis-ot:untrusted"
    elif kind == "outcome" and mutation == "credential-time":
        raw["coordinator_credential"] = _credential_with_claims(
            applied.coordinator_credential,
            not_before=applied.signed_at + timedelta(seconds=1),
        )
    elif kind == "outcome" and mutation == "not-dispatched-kind":
        raw["disposition"] = EffectDisposition.NOT_DISPATCHED
        raw["acceptance"] = None
        raw["acknowledgment"] = None
    elif kind == "outcome" and mutation == "not-dispatched-evidence":
        raw["request_kind"] = "query"
        raw["disposition"] = EffectDisposition.NOT_DISPATCHED
        raw["acknowledgment"] = None
    elif kind == "outcome" and mutation == "acceptance":
        raw["acceptance"] = None
    elif kind == "outcome" and mutation == "acceptance-time":
        raw["acceptance"] = acceptance.model_copy(
            update={"accepted_at": applied.signed_at + timedelta(seconds=1)}
        )
    elif kind == "outcome" and mutation == "coordinator":
        raw["coordinator_credential"] = _credential_with_claims(
            applied.coordinator_credential,
            subject="spiffe://aegis-ot.test/workload/other-ot",
        )
    elif kind == "outcome" and mutation == "terminal-ack":
        raw["acknowledgment"] = None
    elif kind == "outcome" and mutation == "unknown-ack":
        raw["disposition"] = EffectDisposition.UNKNOWN_EFFECT
    elif kind == "outcome" and mutation == "ack-time":
        raw["acknowledgment"] = applied.acknowledgment.model_copy(
            update={"acknowledged_at": acceptance.accepted_at - timedelta(microseconds=1)}
        )
    elif kind == "outcome" and mutation == "ack-transaction":
        raw["acknowledgment"] = applied.acknowledgment.model_copy(
            update={"signature": "invalid-acknowledgment"}
        )
    elif kind == "resolution" and mutation == "naive":
        raw["resolved_at"] = raw["resolved_at"].replace(tzinfo=None)
    elif kind == "resolution":
        raw["disposition"] = EffectDisposition.REJECTED
    elif kind == "pending" and mutation == "naive":
        raw["retained_at"] = raw["retained_at"].replace(tzinfo=None)
    else:
        raw["effect"] = protocol_values["other_effect"]

    if kind == "acceptance" and mutation == "preparation":
        invalid = acceptance.model_copy(
            update={
                "commit_request": raw["commit_request"],
                "commit_request_sha256": raw["commit_request"].digest,
                "accepted_at": raw["accepted_at"],
            }
        )
        with pytest.raises(ValueError, match=message):
            invalid.require_closed_acceptance()
        return
    if kind == "acceptance" and mutation == "credential-time":
        bad_credential = raw["coordinator_credential"]
        bad_receipt = receipt.model_copy(
            update={"coordinator_credential": bad_credential}
        )
        bad_commit = commit.model_copy(
            update={"receipt": bad_receipt, "receipt_sha256": bad_receipt.digest}
        )
        invalid = acceptance.model_copy(
            update={
                "commit_request": bad_commit,
                "commit_request_sha256": bad_commit.digest,
                "coordinator_credential": bad_credential,
            }
        )
        with pytest.raises(ValueError, match=message):
            invalid.require_closed_acceptance()
        return
    with pytest.raises(ValidationError, match=message):
        model.model_validate(raw)


def test_signer_and_acceptance_factories_reject_broken_signature_chains(
    protocol_values: dict[str, Any],
) -> None:
    prepare = protocol_values["prepare"]
    mismatched = WorkloadSigner(
        credential=prepare.sender_credential,
        private_key=Ed25519PrivateKey.generate(),
    )
    with pytest.raises(ValueError, match="signer does not match"):
        SignedEffectQueryRequest.issue(
            effect=prepare.effect,
            signer=mismatched,
            request_nonce="query-mismatched-signer-0001",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
        )

    commit = protocol_values["commit"].model_copy(update={"signature": "invalid"})
    with pytest.raises(ValueError, match="intact signed request chain"):
        DurableCommitAcceptance.issue(
            request=commit,
            signer=cast(Any, mismatched),
            accepted_at=NOW + timedelta(seconds=2),
        )


def test_protocol_projections_and_time_bounds_remain_explicit(
    protocol_values: dict[str, Any],
    artifacts: M4iArtifacts,
) -> None:
    receipt = protocol_values["receipt"]
    acceptance = protocol_values["acceptance"]
    outcome = protocol_values["applied"]
    resolution = protocol_values["resolution"]
    pending = protocol_values["pending"]
    dispatch = artifacts.dispatch
    common = {
        "expected_gateway_subject": receipt.prepare_request.sender_subject,
        "expected_coordinator_subject": receipt.coordinator_subject,
        "observer_public_key": artifacts.observer_public_key,
        "expected_observer_id": dispatch.pre_observation.observer_id,
        "expected_observer_key_id": dispatch.pre_observation.observer_key_id,
        "expected_observer_boot_epoch": dispatch.pre_observation.observer_boot_epoch,
        "permit_public_key": artifacts.permit_public_key,
        "expected_permit_key_id": dispatch.permit.signing_key_id,
        "expected_plc_id": dispatch.permit.target_plc_id,
        "expected_plc_key_id": dispatch.permit.target_plc_key_id,
        "expected_plc_boot_epoch": dispatch.permit.target_plc_boot_epoch,
    }
    identity_expectations = {
        key: common[key]
        for key in ("expected_gateway_subject", "expected_coordinator_subject")
    }
    assert receipt.plant_subject == receipt.coordinator_subject
    assert receipt.plant_key_id == receipt.coordinator_key_id
    assert outcome.plant_subject == outcome.coordinator_subject
    assert outcome.plant_key_id == outcome.coordinator_key_id
    assert outcome.execution_evidence_sha256 == outcome.acknowledgment.digest
    assert outcome.receipt_sha256 == receipt.digest
    assert resolution.query_request_sha256 == resolution.query.digest
    assert resolution.receipt == receipt
    assert pending.query_request_sha256 == pending.query.digest
    assert pending.receipt == receipt
    assert not receipt.verify_for_request(
        artifacts.verifier,
        request=receipt.prepare_request,
        evaluated_at=NOW,
        maximum_future_skew=timedelta(seconds=-1),
        **identity_expectations,
    )
    assert not receipt.verify_historical_for_request(
        artifacts.verifier,
        request=receipt.prepare_request,
        evaluated_at=NOW.replace(tzinfo=None),
        **identity_expectations,
    )
    assert not acceptance.verify_for_commit(
        artifacts.verifier,
        request=acceptance.commit_request,
        evaluated_at=NOW,
        maximum_future_skew=timedelta(seconds=-1),
        **common,
    )
    assert not outcome.verify_for_request(
        artifacts.verifier,
        request=acceptance.commit_request,
        evaluated_at=NOW.replace(tzinfo=None),
        **common,
    )
    assert not outcome.verify_historical_for_request(
        artifacts.verifier,
        request=acceptance.commit_request,
        evaluated_at=NOW,
        maximum_future_skew=timedelta(seconds=-1),
        **common,
    )
