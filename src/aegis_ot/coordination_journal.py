"""Fail-closed durable journals for M4i effect coordination.

The journal retains exact signed prepare, receipt, commit, query, and outcome
artifacts. Each instance holds one lifetime ``flock`` writer lock and replaces
its single canonical JSON file only after file fsync; a parent-directory fsync
completes each update. This is bounded single-host durability, not consensus,
an external monotonic anchor, or proof that an effect occurred.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Annotated, Any, ClassVar, Literal, Protocol, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .coordination_models import (
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
from .physical_models import SHA256_PATTERN

MAX_TRANSITIONS_PER_EFFECT = 16
MAX_ATTEMPTS_PER_EFFECT = 128


class CoordinationJournalError(RuntimeError):
    """A coordination journal could not be trusted or durably updated."""


class CoordinationCollisionError(CoordinationJournalError):
    """One stable effect ID was presented with conflicting immutable material."""


class IllegalCoordinationTransition(CoordinationJournalError):
    """A requested coordination state transition is not legal."""


class _WriterLockError(RuntimeError):
    pass


class _LifetimeWriterLock:
    """Hold a stable sidecar lock across journal-inode replacement."""

    def __init__(self, journal_path: Path) -> None:
        self.path = self.path_for(journal_path)
        self._descriptor = -1
        self._owner_pid = os.getpid()
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(self.path, flags, 0o600)
            lock_stat = os.fstat(descriptor)
            if not stat.S_ISREG(lock_stat.st_mode):
                raise _WriterLockError(
                    "coordination writer lock must be a regular non-symlink file"
                )
            if stat.S_IMODE(lock_stat.st_mode) != 0o600:
                raise _WriterLockError("coordination writer lock mode must be 0600")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except _WriterLockError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise _WriterLockError(
                "coordination writer lock is already held or unavailable"
            ) from exc
        self._descriptor = descriptor

    @staticmethod
    def path_for(journal_path: Path) -> Path:
        return journal_path.with_name(f".{journal_path.name}.writer.lock")

    def assert_held(self) -> None:
        if self._descriptor < 0:
            raise _WriterLockError("coordination writer lock is closed")
        if self._owner_pid != os.getpid():
            raise _WriterLockError(
                "coordination writer lock cannot be used by an inherited child process"
            )

    def close(self) -> None:
        descriptor = self._descriptor
        if descriptor < 0:
            return
        self._descriptor = -1
        os.close(descriptor)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
    )


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


class CoordinationAttemptStatus(StrEnum):
    """Closed persistence status for one exact protocol delivery attempt."""

    REQUEST_RETAINED = "request_retained"
    RESPONSE_RETAINED = "response_retained"
    OUTCOME_UNKNOWN = "outcome_unknown"


class CoordinationTransition(_FrozenModel):
    """One immutable, ordered state assertion in a journal record."""

    sequence: int = Field(ge=1, le=MAX_TRANSITIONS_PER_EFFECT)
    state: CoordinationState
    disposition: EffectDisposition | None = None
    evidence_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    reason: str = Field(min_length=1, max_length=512)
    recorded_at: datetime

    @model_validator(mode="after")
    def require_closed_transition(self) -> CoordinationTransition:
        if self.disposition is not EffectDisposition.for_state(self.state):
            raise ValueError("coordination transition disposition is inconsistent")
        if not _aware(self.recorded_at):
            raise ValueError("coordination transition time must be timezone-aware")
        if self.state in {CoordinationState.APPLIED, CoordinationState.REJECTED} and (
            self.evidence_sha256 is None
        ):
            raise ValueError("terminal dispatch transition requires exact outcome evidence")
        return self


class _AttemptBase(_FrozenModel):
    sequence: int = Field(ge=1, le=MAX_ATTEMPTS_PER_EFFECT)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    status: CoordinationAttemptStatus
    retained_at: datetime
    updated_at: datetime

    def _validate_times(self) -> None:
        if not _aware(self.retained_at) or not _aware(self.updated_at):
            raise ValueError("coordination attempt times must be timezone-aware")
        if self.updated_at < self.retained_at:
            raise ValueError("coordination attempt update cannot precede retention")


class EffectPrepareAttempt(_AttemptBase):
    """An exact signed prepare request and, once durable, its exact receipt."""

    schema_version: Literal["m4i-effect-prepare-attempt-v1"] = "m4i-effect-prepare-attempt-v1"
    kind: Literal["prepare"] = "prepare"
    request: SignedEffectPrepareRequest
    receipt: CoordinationReceipt | None = None

    @model_validator(mode="after")
    def require_exact_prepare_attempt(self) -> EffectPrepareAttempt:
        self._validate_times()
        if (
            self.request_sha256 != self.request.digest
            or not self.request.signature
            or not self.request.verify()
        ):
            raise ValueError("prepare attempt request binding is inconsistent")
        if self.retained_at < self.request.issued_at:
            raise ValueError("prepare attempt cannot predate its signed request")
        if self.status is CoordinationAttemptStatus.OUTCOME_UNKNOWN:
            raise ValueError("prepare attempts cannot assert an unknown outcome")
        if self.status is CoordinationAttemptStatus.REQUEST_RETAINED:
            if self.receipt is not None:
                raise ValueError("request-only prepare attempt cannot retain a receipt")
        elif (
            self.receipt is None
            or not self.receipt.signature
            or not self.receipt.verify()
            or self.receipt.prepare_request != self.request
            or self.receipt.prepare_request_sha256 != self.request.digest
            or self.receipt.effect != self.request.effect
        ):
            raise ValueError("prepared response does not bind its exact request")
        if self.receipt is not None and self.updated_at < self.receipt.prepared_at:
            raise ValueError("prepare response retention cannot predate its receipt")
        return self


class EffectCommitAttempt(_AttemptBase):
    """A commit intent retained before effect and its exact eventual outcome."""

    schema_version: Literal["m4i-effect-commit-attempt-v1"] = "m4i-effect-commit-attempt-v1"
    kind: Literal["commit"] = "commit"
    request: SignedEffectCommitRequest
    acceptance: DurableCommitAcceptance | None = None
    outcome: SignedEffectOutcome | None = None
    failure_reason: str | None = Field(default=None, min_length=1, max_length=512)
    failure_evidence_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_exact_commit_attempt(self) -> EffectCommitAttempt:
        self._validate_times()
        if (
            self.request_sha256 != self.request.digest
            or not self.request.signature
            or not self.request.verify()
            or not self.request.receipt.verify()
        ):
            raise ValueError("commit attempt request binding is inconsistent")
        if self.retained_at < self.request.issued_at:
            raise ValueError("commit attempt cannot predate its signed request")
        if self.acceptance is not None and (
            not self.acceptance.signature
            or not self.acceptance.verify()
            or self.acceptance.commit_request != self.request
            or self.acceptance.commit_request_sha256 != self.request.digest
            or self.acceptance.effect != self.request.effect
        ):
            raise ValueError("commit acceptance does not bind its exact request")
        if self.acceptance is not None and self.updated_at < self.acceptance.accepted_at:
            raise ValueError("commit acceptance retention cannot predate acceptance")
        if self.status is CoordinationAttemptStatus.RESPONSE_RETAINED:
            if (
                self.outcome is None
                or not self.outcome.signature
                or not self.outcome.verify()
                or self.outcome.request_kind != "commit"
                or self.outcome.request_sha256 != self.request.digest
                or self.outcome.effect != self.request.effect
                or self.outcome.receipt != self.request.receipt
                or self.acceptance is None
                or self.outcome.acceptance != self.acceptance
            ):
                raise ValueError("commit outcome does not bind its exact request")
            if self.failure_reason is not None or self.failure_evidence_sha256 is not None:
                raise ValueError("retained commit response cannot assert delivery failure")
            if self.updated_at < self.outcome.signed_at:
                raise ValueError("commit response retention cannot predate its outcome")
        elif self.status is CoordinationAttemptStatus.OUTCOME_UNKNOWN:
            if self.outcome is not None or self.failure_reason is None:
                raise ValueError("unknown commit attempt requires bounded failure evidence")
        elif (
            self.outcome is not None
            or self.failure_reason is not None
            or self.failure_evidence_sha256 is not None
        ):
            raise ValueError("request-only commit attempt cannot assert an outcome")
        return self


class EffectQueryAttempt(_AttemptBase):
    """One exact reconciliation query, response, or bounded communication failure."""

    schema_version: Literal["m4i-effect-query-attempt-v1"] = "m4i-effect-query-attempt-v1"
    kind: Literal["query"] = "query"
    request: SignedEffectQueryRequest
    outcome: SignedEffectOutcome | None = None
    failure_reason: str | None = Field(default=None, min_length=1, max_length=512)
    failure_evidence_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_exact_query_attempt(self) -> EffectQueryAttempt:
        self._validate_times()
        if (
            self.request_sha256 != self.request.digest
            or not self.request.signature
            or not self.request.verify()
        ):
            raise ValueError("query attempt request binding is inconsistent")
        if self.retained_at < self.request.issued_at:
            raise ValueError("query attempt cannot predate its signed request")
        if self.status is CoordinationAttemptStatus.RESPONSE_RETAINED:
            if (
                self.outcome is None
                or not self.outcome.signature
                or not self.outcome.verify()
                or self.outcome.request_kind != "query"
                or self.outcome.request_sha256 != self.request.digest
                or self.outcome.effect != self.request.effect
            ):
                raise ValueError("query outcome does not bind its exact request")
            if self.failure_reason is not None or self.failure_evidence_sha256 is not None:
                raise ValueError("retained query response cannot assert delivery failure")
            if self.updated_at < self.outcome.signed_at:
                raise ValueError("query response retention cannot predate its outcome")
        elif self.status is CoordinationAttemptStatus.OUTCOME_UNKNOWN:
            if self.outcome is not None or self.failure_reason is None:
                raise ValueError("unknown query attempt requires bounded failure evidence")
        elif (
            self.outcome is not None
            or self.failure_reason is not None
            or self.failure_evidence_sha256 is not None
        ):
            raise ValueError("request-only query attempt cannot assert an outcome")
        return self


CoordinationAttempt = Annotated[
    EffectPrepareAttempt | EffectCommitAttempt | EffectQueryAttempt,
    Field(discriminator="kind"),
]


class CoordinationJournalRecord(_FrozenModel):
    """Exact protocol history and legal state transitions for one stable effect."""

    schema_version: Literal["m4i-coordination-journal-record-v2"] = (
        "m4i-coordination-journal-record-v2"
    )
    effect: EffectIdentity
    effect_sha256: str = Field(pattern=SHA256_PATTERN)
    transitions: tuple[CoordinationTransition, ...] = Field(
        min_length=1,
        max_length=MAX_TRANSITIONS_PER_EFFECT,
    )
    attempts: tuple[CoordinationAttempt, ...] = Field(
        min_length=1,
        max_length=MAX_ATTEMPTS_PER_EFFECT,
    )

    @model_validator(mode="after")
    def require_legal_history(self) -> CoordinationJournalRecord:
        if self.effect_sha256 != self.effect.digest:
            raise ValueError("journal record effect hash is inconsistent")
        if self.transitions[0].state is not CoordinationState.RECEIVED:
            raise ValueError("journal record must begin in received state")
        prior: CoordinationTransition | None = None
        for expected_sequence, transition in enumerate(self.transitions, start=1):
            if transition.sequence != expected_sequence:
                raise ValueError("journal transition sequence is not contiguous")
            if prior is not None:
                if transition.recorded_at < prior.recorded_at:
                    raise ValueError("journal transition chronology is inconsistent")
                if not prior.state.can_transition_to(transition.state):
                    raise ValueError("journal contains an illegal state transition")
            prior = transition

        prior_retained_at: datetime | None = None
        retained_receipts: set[str] = set()
        commit_requests: set[str] = set()
        commit_attempt_count = 0
        retained_acceptances: dict[str, DurableCommitAcceptance] = {}
        not_dispatched_outcome_digests: set[str] = set()
        terminal_dispositions: set[EffectDisposition] = set()
        terminal_outcome_digests: dict[EffectDisposition, set[str]] = {
            EffectDisposition.APPLIED: set(),
            EffectDisposition.REJECTED: set(),
        }
        for expected_sequence, attempt in enumerate(self.attempts, start=1):
            if attempt.sequence != expected_sequence:
                raise ValueError("journal attempt sequence is not contiguous")
            if attempt.request.effect != self.effect:
                raise ValueError("journal attempt refers to a different effect")
            if prior_retained_at is not None and attempt.retained_at < prior_retained_at:
                raise ValueError("journal attempt chronology is inconsistent")
            prior_retained_at = attempt.retained_at
            if isinstance(attempt, EffectPrepareAttempt) and attempt.receipt is not None:
                retained_receipts.add(attempt.receipt.digest)
            if isinstance(attempt, EffectCommitAttempt):
                commit_attempt_count += 1
                commit_requests.add(attempt.request.digest)
                if attempt.request.receipt.digest not in retained_receipts:
                    raise ValueError("commit attempt lacks its retained prepare receipt")
                if attempt.acceptance is not None:
                    retained_acceptances[attempt.request.digest] = attempt.acceptance
            if (
                isinstance(attempt, EffectQueryAttempt)
                and attempt.outcome is not None
                and attempt.outcome.disposition is not EffectDisposition.NOT_DISPATCHED
                and (
                    attempt.outcome.receipt is None
                    or attempt.outcome.receipt.digest not in retained_receipts
                )
            ):
                raise ValueError("query outcome lacks its retained prepare receipt")
            if (
                isinstance(attempt, EffectQueryAttempt)
                and attempt.outcome is not None
                and attempt.outcome.disposition is not EffectDisposition.NOT_DISPATCHED
                and (
                    attempt.outcome.acceptance is None
                    or retained_acceptances.get(attempt.outcome.acceptance.commit_request.digest)
                    != attempt.outcome.acceptance
                )
            ):
                raise ValueError("query outcome lacks its exact retained commit acceptance")
            if (
                isinstance(attempt, (EffectCommitAttempt, EffectQueryAttempt))
                and attempt.outcome is not None
                and attempt.outcome.disposition
                in {EffectDisposition.APPLIED, EffectDisposition.REJECTED}
            ):
                terminal_dispositions.add(attempt.outcome.disposition)
                terminal_outcome_digests[attempt.outcome.disposition].add(attempt.outcome.digest)
            if (
                isinstance(attempt, EffectQueryAttempt)
                and attempt.outcome is not None
                and attempt.outcome.disposition is EffectDisposition.NOT_DISPATCHED
            ):
                not_dispatched_outcome_digests.add(attempt.outcome.digest)

        if not isinstance(self.attempts[0], EffectPrepareAttempt):
            raise ValueError("journal record must begin with a prepare attempt")
        if commit_attempt_count > 1 or len(commit_requests) > 1:
            raise ValueError("journal record retains conflicting commit requests")
        if (
            self.state not in {CoordinationState.RECEIVED, CoordinationState.NOT_DISPATCHED}
            and not retained_receipts
        ):
            raise ValueError("dispatched state lacks an exact prepare receipt")
        post_commit_states = {
            CoordinationState.COMMIT_ACCEPTED,
            CoordinationState.UNKNOWN_EFFECT,
            CoordinationState.APPLIED,
            CoordinationState.REJECTED,
        }
        if any(item.state in post_commit_states for item in self.transitions) and not (
            commit_requests
        ):
            raise ValueError("post-prepare history lacks a retained commit intent")
        has_post_commit_transition = any(
            item.state in post_commit_states for item in self.transitions
        )
        acceptance = self.latest_acceptance
        if has_post_commit_transition and acceptance is None:
            raise ValueError("post-prepare history lacks durable commit acceptance")
        if acceptance is not None:
            transition_index = acceptance.transition_sequence - 1
            if transition_index >= len(self.transitions):
                raise ValueError("commit acceptance transition is missing")
            acceptance_transition = self.transitions[transition_index]
            if (
                acceptance_transition.state is not CoordinationState.COMMIT_ACCEPTED
                or acceptance_transition.evidence_sha256 != acceptance.digest
                or acceptance_transition.recorded_at < acceptance.accepted_at
            ):
                raise ValueError("commit acceptance transition binding is inconsistent")
        if self.state in {CoordinationState.APPLIED, CoordinationState.REJECTED}:
            expected = EffectDisposition(self.state.value)
            if terminal_dispositions != {expected}:
                raise ValueError("terminal state lacks one consistent exact outcome")
            if self.transitions[-1].evidence_sha256 not in terminal_outcome_digests[expected]:
                raise ValueError("terminal transition does not bind a retained outcome")
        elif terminal_dispositions:
            raise ValueError("nonterminal state cannot retain terminal outcome evidence")
        if not_dispatched_outcome_digests:
            if self.state is not CoordinationState.NOT_DISPATCHED:
                raise ValueError("not-dispatched outcome lacks its terminal transition")
            if self.transitions[-1].evidence_sha256 not in not_dispatched_outcome_digests:
                raise ValueError("not-dispatched transition does not bind a retained outcome")
        return self

    @property
    def state(self) -> CoordinationState:
        return self.transitions[-1].state

    @property
    def disposition(self) -> EffectDisposition | None:
        return self.transitions[-1].disposition

    @property
    def latest_evidence_sha256(self) -> str | None:
        return self.transitions[-1].evidence_sha256

    @property
    def latest_receipt(self) -> CoordinationReceipt | None:
        for attempt in reversed(self.attempts):
            if isinstance(attempt, EffectPrepareAttempt) and attempt.receipt is not None:
                return attempt.receipt
        return None

    @property
    def latest_acceptance(self) -> DurableCommitAcceptance | None:
        """Return the one exact acceptance retained with the commit attempt."""

        for attempt in reversed(self.attempts):
            if isinstance(attempt, EffectCommitAttempt) and attempt.acceptance is not None:
                return attempt.acceptance
        return None

    @property
    def terminal_outcome(self) -> SignedEffectOutcome | None:
        for attempt in reversed(self.attempts):
            if (
                isinstance(attempt, (EffectCommitAttempt, EffectQueryAttempt))
                and attempt.outcome is not None
                and attempt.outcome.disposition
                in {EffectDisposition.APPLIED, EffectDisposition.REJECTED}
            ):
                return attempt.outcome
        return None


class CommitAdmissionStatus(StrEnum):
    """Whether a retained commit may execute, is final, or is indeterminate."""

    NEW = "new"
    TERMINAL = "terminal"
    INDETERMINATE = "indeterminate"


class CommitAdmission(_FrozenModel):
    """Result returned only after the exact commit intent is durable."""

    status: CommitAdmissionStatus
    request: SignedEffectCommitRequest
    record: CoordinationJournalRecord
    acceptance: DurableCommitAcceptance
    retained_outcome: SignedEffectOutcome | None = None

    @model_validator(mode="after")
    def require_consistent_admission(self) -> CommitAdmission:
        attempt = next(
            (
                item
                for item in self.record.attempts
                if isinstance(item, EffectCommitAttempt)
                and item.request_sha256 == self.request.digest
            ),
            None,
        )
        if attempt is None:
            raise ValueError("commit admission lacks its retained intent")
        if attempt.acceptance != self.acceptance:
            raise ValueError("commit admission does not expose its retained acceptance")
        if self.status is CommitAdmissionStatus.NEW:
            if (
                attempt.status is not CoordinationAttemptStatus.REQUEST_RETAINED
                or self.record.state is not CoordinationState.COMMIT_ACCEPTED
                or self.retained_outcome is not None
            ):
                raise ValueError("new commit admission is inconsistent")
        elif self.status is CommitAdmissionStatus.TERMINAL:
            if (
                self.retained_outcome is None
                or self.record.terminal_outcome != self.retained_outcome
                or not self.record.state.terminal
            ):
                raise ValueError("terminal commit admission is inconsistent")
        elif self.retained_outcome is not None or self.record.state not in {
            CoordinationState.COMMIT_ACCEPTED,
            CoordinationState.UNKNOWN_EFFECT,
        }:
            raise ValueError("indeterminate commit admission is inconsistent")
        return self


ReceiptIssuer = Callable[
    [SignedEffectPrepareRequest, datetime],
    CoordinationReceipt,
]


class CommitAcceptanceIssuer(Protocol):
    """Issue the exact signed acceptance that transition three will retain."""

    def __call__(
        self,
        request: SignedEffectCommitRequest,
        /,
        *,
        accepted_at: datetime,
        transition_sequence: Literal[3],
    ) -> DurableCommitAcceptance: ...


OutcomeIssuer = Callable[
    [SignedEffectQueryRequest, CoordinationJournalRecord, datetime],
    SignedEffectOutcome,
]


class _DurableCoordinationJournal:
    SCHEMA_VERSION: ClassVar[str] = "m4i-coordination-journal-v2"
    JOURNAL_ROLE: ClassVar[Literal["gateway", "effect_coordinator"]]
    MAX_JOURNAL_BYTES: ClassVar[int] = 8 * 1024 * 1024
    MAX_ENTRIES: ClassVar[int] = 8192
    MAX_ATTEMPTS_PER_EFFECT: ClassVar[int] = MAX_ATTEMPTS_PER_EFFECT

    def __init__(
        self,
        path: Path,
        *,
        owner_subject: str,
        initialize: bool = False,
    ) -> None:
        self.path = path
        self.owner_subject = self._identity("owner subject", owner_subject)
        self._mutex = RLock()
        self._writer_lock: _LifetimeWriterLock | None = None
        self._records: dict[str, CoordinationJournalRecord] = {}
        self._unusable = False
        self._check_parent()
        try:
            self._writer_lock = _LifetimeWriterLock(self.path)
            if initialize:
                if self.path.exists() or self.path.is_symlink():
                    raise CoordinationJournalError(
                        "coordination journal already exists; refusing to initialize"
                    )
                self._persist({})
            self._records = self._load()
        except _WriterLockError as exc:
            self.close()
            raise CoordinationJournalError(str(exc)) from exc
        except Exception:
            self.close()
            raise

    @property
    def writer_lock_path(self) -> Path:
        return _LifetimeWriterLock.path_for(self.path)

    def _assert_writer(self) -> None:
        if self._unusable:
            raise CoordinationJournalError(
                "coordination journal is unusable after an uncertain update"
            )
        writer_lock = self._writer_lock
        if writer_lock is None:
            raise CoordinationJournalError("coordination writer lock is closed")
        try:
            writer_lock.assert_held()
        except _WriterLockError as exc:
            raise CoordinationJournalError(str(exc)) from exc

    def close(self) -> None:
        writer_lock = self._writer_lock
        self._writer_lock = None
        if writer_lock is not None:
            writer_lock.close()

    def __enter__(self) -> Self:
        self._assert_writer()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()

    @staticmethod
    def _identity(label: str, value: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 256 or value != value.strip():
            raise CoordinationJournalError(f"coordination journal {label} is invalid")
        return value

    @staticmethod
    def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise CoordinationJournalError("coordination journal has a duplicate JSON key")
            value[key] = item
        return value

    @staticmethod
    def _reject_json_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant is forbidden: {value}")

    @staticmethod
    def _canonical_bytes(value: dict[str, Any]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    def _check_parent(self) -> None:
        try:
            parent_stat = self.path.parent.stat()
        except OSError as exc:
            raise CoordinationJournalError("coordination journal directory is unavailable") from exc
        if self.path.parent.is_symlink() or not stat.S_ISDIR(parent_stat.st_mode):
            raise CoordinationJournalError(
                "coordination journal directory must be a non-symlink directory"
            )
        if stat.S_IMODE(parent_stat.st_mode) != 0o700:
            raise CoordinationJournalError("coordination journal directory mode must be 0700")

    def _read(self) -> bytes:
        self._assert_writer()
        self._check_parent()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise CoordinationJournalError(
                "coordination journal is missing or unavailable"
            ) from exc
        try:
            journal_stat = os.fstat(descriptor)
            if not stat.S_ISREG(journal_stat.st_mode):
                raise CoordinationJournalError(
                    "coordination journal must be a regular non-symlink file"
                )
            if stat.S_IMODE(journal_stat.st_mode) != 0o600:
                raise CoordinationJournalError("coordination journal mode must be 0600")
            if journal_stat.st_size > self.MAX_JOURNAL_BYTES:
                raise CoordinationJournalError("coordination journal exceeds its size limit")
            chunks: list[bytes] = []
            remaining = self.MAX_JOURNAL_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            material = b"".join(chunks)
            if len(material) > self.MAX_JOURNAL_BYTES:
                raise CoordinationJournalError("coordination journal exceeds its size limit")
            return material
        except OSError as exc:
            raise CoordinationJournalError("coordination journal cannot be read") from exc
        finally:
            os.close(descriptor)

    def _document(
        self,
        records: dict[str, CoordinationJournalRecord],
    ) -> dict[str, Any]:
        return {
            "entries": [
                records[effect_id].model_dump(mode="json") for effect_id in sorted(records)
            ],
            "journal_role": self.JOURNAL_ROLE,
            "owner_subject": self.owner_subject,
            "schema_version": self.SCHEMA_VERSION,
        }

    def _load(self) -> dict[str, CoordinationJournalRecord]:
        material = self._read()
        try:
            parsed = json.loads(
                material.decode("utf-8", errors="strict"),
                object_pairs_hook=self._closed_object,
                parse_constant=self._reject_json_constant,
            )
        except CoordinationJournalError:
            raise
        except (UnicodeError, ValueError) as exc:
            raise CoordinationJournalError("coordination journal is not strict UTF-8 JSON") from exc
        if not isinstance(parsed, dict) or set(parsed) != {
            "schema_version",
            "journal_role",
            "owner_subject",
            "entries",
        }:
            raise CoordinationJournalError("coordination journal has unexpected or missing fields")
        if parsed["schema_version"] != self.SCHEMA_VERSION:
            raise CoordinationJournalError("coordination journal schema is unsupported")
        if (
            parsed["journal_role"] != self.JOURNAL_ROLE
            or parsed["owner_subject"] != self.owner_subject
        ):
            raise CoordinationJournalError(
                "coordination journal identity does not match configuration"
            )
        entries = parsed["entries"]
        if not isinstance(entries, list) or len(entries) > self.MAX_ENTRIES:
            raise CoordinationJournalError("coordination journal entry set is invalid")
        records: dict[str, CoordinationJournalRecord] = {}
        prior_effect_id: str | None = None
        try:
            for raw_entry in entries:
                if not isinstance(raw_entry, dict):
                    raise CoordinationJournalError("coordination journal entry shape is invalid")
                record = CoordinationJournalRecord.model_validate_json(
                    self._canonical_bytes(raw_entry)
                )
                self._validate_role_history(record)
                effect_id = record.effect.effect_id
                if prior_effect_id is not None and effect_id <= prior_effect_id:
                    raise CoordinationJournalError(
                        "coordination journal entries are not sorted and unique"
                    )
                records[effect_id] = record
                prior_effect_id = effect_id
        except CoordinationJournalError:
            raise
        except (TypeError, ValueError) as exc:
            raise CoordinationJournalError(
                "coordination journal contains an invalid record"
            ) from exc
        try:
            canonical = self._canonical_bytes(self._document(records))
        except (TypeError, ValueError) as exc:
            raise CoordinationJournalError(
                "coordination journal contains noncanonical values"
            ) from exc
        if material != canonical:
            raise CoordinationJournalError("coordination journal encoding is not canonical")
        return records

    def _persist(self, records: dict[str, CoordinationJournalRecord]) -> None:
        self._assert_writer()
        self._check_parent()
        if len(records) > self.MAX_ENTRIES:
            raise CoordinationJournalError("coordination journal is at capacity")
        material = self._canonical_bytes(self._document(records))
        if len(material) > self.MAX_JOURNAL_BYTES:
            raise CoordinationJournalError("coordination journal is at capacity")
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        descriptor = -1
        replaced = False
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(material):
                written = os.write(descriptor, material[offset:])
                if written <= 0:
                    raise OSError("coordination journal write made no progress")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self.path)
            replaced = True
            directory_descriptor = os.open(
                self.path.parent,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError as exc:
            self._unusable = True
            raise CoordinationJournalError("coordination journal update failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                with suppress(FileNotFoundError):
                    temporary.unlink()

    @staticmethod
    def _when(recorded_at: datetime | None) -> datetime:
        value = recorded_at or datetime.now(UTC)
        if not _aware(value):
            raise CoordinationJournalError("coordination transition time must be timezone-aware")
        return value

    def _validated_record(
        self,
        record: CoordinationJournalRecord,
    ) -> CoordinationJournalRecord:
        try:
            validated = CoordinationJournalRecord.model_validate_json(record.model_dump_json())
        except ValueError as exc:
            raise CoordinationJournalError("coordination journal record is invalid") from exc
        self._validate_role_history(validated)
        return validated

    def _validate_role_history(self, record: CoordinationJournalRecord) -> None:
        if self.JOURNAL_ROLE != "effect_coordinator":
            return
        if any(
            isinstance(attempt, EffectCommitAttempt) and attempt.acceptance is None
            for attempt in record.attempts
        ):
            raise CoordinationJournalError(
                "effect-coordinator commit history lacks durable acceptance"
            )

    def _lookup(self, effect: EffectIdentity) -> CoordinationJournalRecord | None:
        record = self._records.get(effect.effect_id)
        if record is not None and record.effect != effect:
            raise CoordinationCollisionError(
                "coordination effect ID collides with different immutable material"
            )
        return record

    def get(self, effect: EffectIdentity | str) -> CoordinationJournalRecord | None:
        with self._mutex:
            self._assert_writer()
            if isinstance(effect, EffectIdentity):
                return self._lookup(effect)
            effect_id = self._identity("effect ID", effect)
            return self._records.get(effect_id)

    def records(self) -> tuple[CoordinationJournalRecord, ...]:
        with self._mutex:
            self._assert_writer()
            return tuple(self._records[key] for key in sorted(self._records))

    def pending(self) -> tuple[CoordinationJournalRecord, ...]:
        with self._mutex:
            self._assert_writer()
            return tuple(record for record in self.records() if not record.state.terminal)

    def attempts(
        self,
        effect: EffectIdentity | str,
    ) -> tuple[CoordinationAttempt, ...]:
        record = self.get(effect)
        return () if record is None else record.attempts

    def _store(self, record: CoordinationJournalRecord) -> CoordinationJournalRecord:
        record = self._validated_record(record)
        candidate = dict(self._records)
        candidate[record.effect.effect_id] = record
        self._persist(candidate)
        self._records = candidate
        return record

    def _transition(
        self,
        record: CoordinationJournalRecord,
        *,
        state: CoordinationState,
        evidence_sha256: str | None,
        reason: str,
        recorded_at: datetime,
    ) -> CoordinationJournalRecord:
        if record.state.terminal:
            raise IllegalCoordinationTransition("terminal coordination state is immutable")
        if not record.state.can_transition_to(state):
            raise IllegalCoordinationTransition(
                f"illegal coordination transition {record.state.value}->{state.value}"
            )
        transition = CoordinationTransition(
            sequence=len(record.transitions) + 1,
            state=state,
            disposition=EffectDisposition.for_state(state),
            evidence_sha256=evidence_sha256,
            reason=reason,
            recorded_at=recorded_at,
        )
        return record.model_copy(update={"transitions": (*record.transitions, transition)})

    @staticmethod
    def _prepare_attempt(
        record: CoordinationJournalRecord,
        request: SignedEffectPrepareRequest,
    ) -> EffectPrepareAttempt | None:
        return next(
            (
                item
                for item in record.attempts
                if isinstance(item, EffectPrepareAttempt) and item.request_sha256 == request.digest
            ),
            None,
        )

    @staticmethod
    def _commit_attempt(
        record: CoordinationJournalRecord,
        request: SignedEffectCommitRequest,
    ) -> EffectCommitAttempt | None:
        return next(
            (
                item
                for item in record.attempts
                if isinstance(item, EffectCommitAttempt) and item.request_sha256 == request.digest
            ),
            None,
        )

    @staticmethod
    def _query_attempt(
        record: CoordinationJournalRecord,
        request: SignedEffectQueryRequest,
    ) -> EffectQueryAttempt | None:
        return next(
            (
                item
                for item in record.attempts
                if isinstance(item, EffectQueryAttempt) and item.request_sha256 == request.digest
            ),
            None,
        )

    @staticmethod
    def _replace_attempt(
        record: CoordinationJournalRecord,
        replacement: CoordinationAttempt,
    ) -> CoordinationJournalRecord:
        attempts = tuple(
            replacement if item.sequence == replacement.sequence else item
            for item in record.attempts
        )
        return record.model_copy(update={"attempts": attempts})

    @staticmethod
    def _require_attempt_capacity(record: CoordinationJournalRecord) -> None:
        if len(record.attempts) >= MAX_ATTEMPTS_PER_EFFECT:
            raise CoordinationJournalError(
                "coordination journal effect attempt history is at capacity"
            )

    @staticmethod
    def _validate_receipt(
        request: SignedEffectPrepareRequest,
        receipt: CoordinationReceipt,
    ) -> None:
        if (
            not receipt.signature
            or not request.verify()
            or not receipt.verify()
            or receipt.prepare_request != request
            or receipt.prepare_request_sha256 != request.digest
            or receipt.effect != request.effect
        ):
            raise CoordinationCollisionError(
                "coordination receipt does not bind the exact prepare request"
            )

    @staticmethod
    def _validate_acceptance(
        request: SignedEffectCommitRequest,
        acceptance: DurableCommitAcceptance,
        *,
        accepted_at: datetime | None = None,
    ) -> None:
        if (
            not isinstance(acceptance, DurableCommitAcceptance)
            or not acceptance.signature
            or not request.verify()
            or not request.receipt.verify()
            or not acceptance.verify()
            or acceptance.commit_request != request
            or acceptance.commit_request_sha256 != request.digest
            or acceptance.effect != request.effect
            or (accepted_at is not None and acceptance.accepted_at != accepted_at)
        ):
            raise CoordinationCollisionError(
                "durable commit acceptance does not bind the exact retained request"
            )

    @staticmethod
    def _validate_outcome(
        request: SignedEffectCommitRequest | SignedEffectQueryRequest,
        outcome: SignedEffectOutcome,
    ) -> None:
        expected_kind = "commit" if isinstance(request, SignedEffectCommitRequest) else "query"
        if (
            not outcome.signature
            or not request.verify()
            or not outcome.verify()
            or outcome.request_kind != expected_kind
            or outcome.request_sha256 != request.digest
            or outcome.effect != request.effect
            or (
                isinstance(request, SignedEffectCommitRequest)
                and outcome.receipt != request.receipt
            )
        ):
            raise CoordinationCollisionError("coordination outcome does not bind the exact request")
        if (
            isinstance(request, SignedEffectCommitRequest)
            and outcome.disposition is EffectDisposition.NOT_DISPATCHED
        ):
            raise IllegalCoordinationTransition(
                "a commit response cannot assert that the effect was not dispatched"
            )

    @staticmethod
    def _state_for_outcome(outcome: SignedEffectOutcome) -> CoordinationState:
        if outcome.disposition not in {
            EffectDisposition.NOT_DISPATCHED,
            EffectDisposition.UNKNOWN_EFFECT,
            EffectDisposition.APPLIED,
            EffectDisposition.REJECTED,
        }:
            raise IllegalCoordinationTransition(
                "outcome does not carry a legal post-prepare disposition"
            )
        return CoordinationState(outcome.disposition.value)

    def _begin_commit_record(
        self,
        request: SignedEffectCommitRequest,
        *,
        issue_acceptance: CommitAcceptanceIssuer | None,
        recorded_at: datetime | None,
    ) -> tuple[CoordinationJournalRecord, bool]:
        record = self._lookup(request.effect)
        if record is None:
            raise IllegalCoordinationTransition("cannot commit an unprepared effect")
        existing = self._commit_attempt(record, request)
        if existing is not None:
            return record, False
        if any(isinstance(item, EffectCommitAttempt) for item in record.attempts):
            raise CoordinationCollisionError(
                "coordination effect already retains a different commit request"
            )
        if record.state.terminal:
            raise IllegalCoordinationTransition("terminal coordination state is immutable")
        if record.state is not CoordinationState.DISPATCH_ARMED:
            raise IllegalCoordinationTransition("commit intent requires a durably prepared effect")
        if not any(
            isinstance(item, EffectPrepareAttempt) and item.receipt == request.receipt
            for item in record.attempts
        ):
            raise CoordinationCollisionError(
                "commit request receipt was not retained by this journal"
            )
        self._require_attempt_capacity(record)
        when = self._when(recorded_at)
        acceptance: DurableCommitAcceptance | None = None
        if issue_acceptance is not None:
            acceptance = issue_acceptance(
                request,
                accepted_at=when,
                transition_sequence=3,
            )
            self._validate_acceptance(request, acceptance, accepted_at=when)
        attempt = EffectCommitAttempt(
            sequence=len(record.attempts) + 1,
            request=request,
            request_sha256=request.digest,
            status=CoordinationAttemptStatus.REQUEST_RETAINED,
            acceptance=acceptance,
            retained_at=when,
            updated_at=when,
        )
        updated = record.model_copy(update={"attempts": (*record.attempts, attempt)})
        if acceptance is not None:
            updated = self._transition(
                updated,
                state=CoordinationState.COMMIT_ACCEPTED,
                evidence_sha256=acceptance.digest,
                reason="signed_commit_acceptance_durably_retained",
                recorded_at=when,
            )
        return self._store(updated), True

    def _bind_outcome_acceptance(
        self,
        record: CoordinationJournalRecord,
        outcome: SignedEffectOutcome,
        *,
        recorded_at: datetime,
    ) -> CoordinationJournalRecord:
        acceptance = outcome.acceptance
        if outcome.disposition is EffectDisposition.NOT_DISPATCHED:
            if acceptance is not None or record.latest_acceptance is not None:
                raise CoordinationCollisionError(
                    "not-dispatched outcome conflicts with durable commit acceptance"
                )
            return record
        if acceptance is None:
            raise CoordinationCollisionError("dispatched outcome lacks durable commit acceptance")
        commit_attempt = self._commit_attempt(record, acceptance.commit_request)
        if commit_attempt is None:
            raise CoordinationCollisionError(
                "outcome acceptance was not retained with an exact commit intent"
            )
        self._validate_acceptance(commit_attempt.request, acceptance)
        if recorded_at < acceptance.accepted_at:
            raise CoordinationCollisionError("outcome retention predates durable commit acceptance")
        if commit_attempt.acceptance is not None and commit_attempt.acceptance != acceptance:
            raise CoordinationCollisionError(
                "commit attempt already retains a different durable acceptance"
            )
        if commit_attempt.acceptance is None:
            record = self._replace_attempt(
                record,
                commit_attempt.model_copy(
                    update={
                        "acceptance": acceptance,
                        "updated_at": recorded_at,
                    }
                ),
            )
        if record.state is CoordinationState.DISPATCH_ARMED:
            record = self._transition(
                record,
                state=CoordinationState.COMMIT_ACCEPTED,
                evidence_sha256=acceptance.digest,
                reason="signed_commit_acceptance_durably_retained",
                recorded_at=recorded_at,
            )
        elif record.state not in {
            CoordinationState.COMMIT_ACCEPTED,
            CoordinationState.UNKNOWN_EFFECT,
            CoordinationState.APPLIED,
            CoordinationState.REJECTED,
        }:
            raise IllegalCoordinationTransition(
                "durable commit acceptance cannot bind from this state"
            )
        return record

    def _mark_commit_unknown_record(
        self,
        request: SignedEffectCommitRequest,
        *,
        reason: str,
        failure_evidence_sha256: str | None,
        recorded_at: datetime | None,
    ) -> CoordinationJournalRecord:
        record = self._lookup(request.effect)
        if record is None:
            raise IllegalCoordinationTransition("cannot update an unknown effect")
        attempt = self._commit_attempt(record, request)
        if attempt is None:
            raise IllegalCoordinationTransition("commit intent was not retained")
        if record.state.terminal:
            raise IllegalCoordinationTransition("terminal coordination state is immutable")
        if attempt.status is CoordinationAttemptStatus.RESPONSE_RETAINED:
            raise CoordinationCollisionError("commit already retains a signed outcome")
        if attempt.status is CoordinationAttemptStatus.OUTCOME_UNKNOWN:
            if (
                attempt.failure_reason == reason
                and attempt.failure_evidence_sha256 == failure_evidence_sha256
            ):
                return record
            raise CoordinationCollisionError(
                "commit attempt already retains different failure evidence"
            )
        when = self._when(recorded_at)
        replacement = EffectCommitAttempt(
            sequence=attempt.sequence,
            request=attempt.request,
            request_sha256=attempt.request_sha256,
            status=CoordinationAttemptStatus.OUTCOME_UNKNOWN,
            acceptance=attempt.acceptance,
            failure_reason=reason,
            failure_evidence_sha256=failure_evidence_sha256,
            retained_at=attempt.retained_at,
            updated_at=when,
        )
        updated = self._replace_attempt(record, replacement)
        if updated.state is CoordinationState.COMMIT_ACCEPTED:
            updated = self._transition(
                updated,
                state=CoordinationState.UNKNOWN_EFFECT,
                evidence_sha256=failure_evidence_sha256 or request.digest,
                reason=reason,
                recorded_at=when,
            )
        elif updated.state not in {
            CoordinationState.DISPATCH_ARMED,
            CoordinationState.UNKNOWN_EFFECT,
        }:
            raise IllegalCoordinationTransition("commit cannot become unknown from this state")
        return self._store(updated)

    def _finish_commit_record(
        self,
        request: SignedEffectCommitRequest,
        outcome: SignedEffectOutcome,
        *,
        recorded_at: datetime | None,
    ) -> CoordinationJournalRecord:
        self._validate_outcome(request, outcome)
        record = self._lookup(request.effect)
        if record is None:
            raise IllegalCoordinationTransition("cannot update an unknown effect")
        attempt = self._commit_attempt(record, request)
        if attempt is None:
            raise IllegalCoordinationTransition("commit intent was not retained")
        target = self._state_for_outcome(outcome)
        if attempt.status is CoordinationAttemptStatus.RESPONSE_RETAINED:
            if attempt.outcome == outcome and record.state is target:
                return record
            raise CoordinationCollisionError("commit already retains a different outcome")
        if record.state.terminal:
            raise IllegalCoordinationTransition("terminal coordination state is immutable")
        when = self._when(recorded_at)
        record = self._bind_outcome_acceptance(
            record,
            outcome,
            recorded_at=when,
        )
        bound_attempt = self._commit_attempt(record, request)
        if bound_attempt is None or bound_attempt.acceptance is None:
            raise CoordinationJournalError("commit outcome lost its durable acceptance binding")
        replacement = EffectCommitAttempt(
            sequence=bound_attempt.sequence,
            request=bound_attempt.request,
            request_sha256=bound_attempt.request_sha256,
            status=CoordinationAttemptStatus.RESPONSE_RETAINED,
            acceptance=bound_attempt.acceptance,
            outcome=outcome,
            retained_at=bound_attempt.retained_at,
            updated_at=when,
        )
        updated = self._replace_attempt(record, replacement)
        if updated.state is not target:
            updated = self._transition(
                updated,
                state=target,
                evidence_sha256=outcome.digest,
                reason="signed_commit_outcome_retained",
                recorded_at=when,
            )
        return self._store(updated)

    def _begin_query_record(
        self,
        request: SignedEffectQueryRequest,
        *,
        recorded_at: datetime | None,
        allow_terminal: bool,
    ) -> tuple[CoordinationJournalRecord, EffectQueryAttempt, bool]:
        record = self._lookup(request.effect)
        if record is None:
            raise IllegalCoordinationTransition("cannot query an unrecorded effect")
        existing = self._query_attempt(record, request)
        if existing is not None:
            return record, existing, False
        if record.state.terminal and not allow_terminal:
            raise IllegalCoordinationTransition("terminal coordination state is immutable")
        gateway_ambiguous = self.JOURNAL_ROLE == "gateway" and any(
            isinstance(item, EffectCommitAttempt)
            and item.status is CoordinationAttemptStatus.OUTCOME_UNKNOWN
            for item in record.attempts
        )
        prepared_effect_query = self.JOURNAL_ROLE == "effect_coordinator" or gateway_ambiguous
        if (
            not record.state.terminal
            and record.state is CoordinationState.DISPATCH_ARMED
            and not prepared_effect_query
        ):
            raise IllegalCoordinationTransition(
                "gateway reconciliation requires an ambiguous commit attempt"
            )
        if not record.state.terminal and record.state not in {
            CoordinationState.DISPATCH_ARMED,
            CoordinationState.COMMIT_ACCEPTED,
            CoordinationState.UNKNOWN_EFFECT,
        }:
            raise IllegalCoordinationTransition(
                "reconciliation query requires a prepared or accepted effect"
            )
        self._require_attempt_capacity(record)
        when = self._when(recorded_at)
        attempt = EffectQueryAttempt(
            sequence=len(record.attempts) + 1,
            request=request,
            request_sha256=request.digest,
            status=CoordinationAttemptStatus.REQUEST_RETAINED,
            retained_at=when,
            updated_at=when,
        )
        updated = record.model_copy(update={"attempts": (*record.attempts, attempt)})
        return self._store(updated), attempt, True

    def _complete_query_record(
        self,
        request: SignedEffectQueryRequest,
        outcome: SignedEffectOutcome,
        *,
        recorded_at: datetime | None,
        create: bool,
    ) -> CoordinationJournalRecord:
        self._validate_outcome(request, outcome)
        record = self._lookup(request.effect)
        if record is None:
            raise IllegalCoordinationTransition("cannot update an unrecorded effect")
        if outcome.receipt is not None and not any(
            isinstance(item, EffectPrepareAttempt) and item.receipt == outcome.receipt
            for item in record.attempts
        ):
            raise CoordinationCollisionError(
                "query outcome receipt was not retained by this journal"
            )
        when = self._when(recorded_at)
        attempt = self._query_attempt(record, request)
        if attempt is None:
            if not create:
                raise IllegalCoordinationTransition("query intent was not retained")
            record, attempt, _ = self._begin_query_record(
                request,
                recorded_at=when,
                allow_terminal=True,
            )
        if attempt.status is CoordinationAttemptStatus.RESPONSE_RETAINED:
            if attempt.outcome == outcome:
                return record
            raise CoordinationCollisionError("query already retains a different outcome")
        if attempt.status is CoordinationAttemptStatus.OUTCOME_UNKNOWN:
            raise CoordinationCollisionError(
                "query failure is immutable; issue a new reconciliation query"
            )
        target = self._state_for_outcome(outcome)
        if record.state.terminal and target is not record.state:
            raise IllegalCoordinationTransition("terminal coordination state is immutable")
        record = self._bind_outcome_acceptance(
            record,
            outcome,
            recorded_at=when,
        )
        if target is CoordinationState.NOT_DISPATCHED and record.state not in {
            CoordinationState.DISPATCH_ARMED,
            CoordinationState.NOT_DISPATCHED,
        }:
            raise IllegalCoordinationTransition(
                "not-dispatched query outcome requires an uncommitted prepared effect"
            )
        replacement = EffectQueryAttempt(
            sequence=attempt.sequence,
            request=attempt.request,
            request_sha256=attempt.request_sha256,
            status=CoordinationAttemptStatus.RESPONSE_RETAINED,
            outcome=outcome,
            retained_at=attempt.retained_at,
            updated_at=when,
        )
        updated = self._replace_attempt(record, replacement)
        if not updated.state.terminal and updated.state is not target:
            updated = self._transition(
                updated,
                state=target,
                evidence_sha256=outcome.digest,
                reason="signed_query_outcome_retained",
                recorded_at=when,
            )
        return self._store(updated)

    def _fail_query_record(
        self,
        request: SignedEffectQueryRequest,
        *,
        reason: str,
        failure_evidence_sha256: str | None,
        recorded_at: datetime | None,
    ) -> CoordinationJournalRecord:
        record = self._lookup(request.effect)
        if record is None:
            raise IllegalCoordinationTransition("cannot update an unrecorded effect")
        attempt = self._query_attempt(record, request)
        if attempt is None:
            raise IllegalCoordinationTransition("query intent was not retained")
        if record.state.terminal:
            raise IllegalCoordinationTransition("terminal coordination state is immutable")
        if attempt.status is CoordinationAttemptStatus.RESPONSE_RETAINED:
            raise CoordinationCollisionError("query already retains a signed outcome")
        if attempt.status is CoordinationAttemptStatus.OUTCOME_UNKNOWN:
            if (
                attempt.failure_reason == reason
                and attempt.failure_evidence_sha256 == failure_evidence_sha256
            ):
                return record
            raise CoordinationCollisionError(
                "query attempt already retains different failure evidence"
            )
        when = self._when(recorded_at)
        replacement = EffectQueryAttempt(
            sequence=attempt.sequence,
            request=attempt.request,
            request_sha256=attempt.request_sha256,
            status=CoordinationAttemptStatus.OUTCOME_UNKNOWN,
            failure_reason=reason,
            failure_evidence_sha256=failure_evidence_sha256,
            retained_at=attempt.retained_at,
            updated_at=when,
        )
        updated = self._replace_attempt(record, replacement)
        if updated.state is CoordinationState.COMMIT_ACCEPTED:
            updated = self._transition(
                updated,
                state=CoordinationState.UNKNOWN_EFFECT,
                evidence_sha256=failure_evidence_sha256 or request.digest,
                reason=reason,
                recorded_at=when,
            )
        elif updated.state not in {
            CoordinationState.DISPATCH_ARMED,
            CoordinationState.UNKNOWN_EFFECT,
        }:
            raise IllegalCoordinationTransition("query cannot become unknown from this state")
        return self._store(updated)


class DurableGatewayCoordinationJournal(_DurableCoordinationJournal):
    """Gateway-side exact intent, response, and reconciliation history."""

    JOURNAL_ROLE = "gateway"

    def begin(
        self,
        request: SignedEffectPrepareRequest,
        *,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            record = self._lookup(request.effect)
            if record is not None:
                existing = self._prepare_attempt(record, request)
                if existing is not None:
                    return record
                if record.state.terminal:
                    raise IllegalCoordinationTransition("terminal coordination state is immutable")
                self._require_attempt_capacity(record)
                when = self._when(recorded_at)
                attempt = EffectPrepareAttempt(
                    sequence=len(record.attempts) + 1,
                    request=request,
                    request_sha256=request.digest,
                    status=CoordinationAttemptStatus.REQUEST_RETAINED,
                    retained_at=when,
                    updated_at=when,
                )
                return self._store(
                    record.model_copy(update={"attempts": (*record.attempts, attempt)})
                )
            if len(self._records) >= self.MAX_ENTRIES:
                raise CoordinationJournalError("coordination journal is at capacity")
            when = self._when(recorded_at)
            attempt = EffectPrepareAttempt(
                sequence=1,
                request=request,
                request_sha256=request.digest,
                status=CoordinationAttemptStatus.REQUEST_RETAINED,
                retained_at=when,
                updated_at=when,
            )
            record = CoordinationJournalRecord(
                effect=request.effect,
                effect_sha256=request.effect.digest,
                transitions=(
                    CoordinationTransition(
                        sequence=1,
                        state=CoordinationState.RECEIVED,
                        disposition=None,
                        evidence_sha256=request.digest,
                        reason="prepare_request_durably_retained",
                        recorded_at=when,
                    ),
                ),
                attempts=(attempt,),
            )
            return self._store(record)

    def retain_preparation(
        self,
        request: SignedEffectPrepareRequest,
        receipt: CoordinationReceipt,
        *,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            self._validate_receipt(request, receipt)
            record = self._lookup(request.effect)
            if record is None:
                raise IllegalCoordinationTransition("prepare intent was not retained")
            attempt = self._prepare_attempt(record, request)
            if attempt is None:
                raise IllegalCoordinationTransition("prepare intent was not retained")
            if attempt.receipt is not None:
                if attempt.receipt == receipt:
                    return record
                raise CoordinationCollisionError(
                    "prepare attempt already retains a different receipt"
                )
            if record.state.terminal:
                raise IllegalCoordinationTransition("terminal coordination state is immutable")
            when = self._when(recorded_at or receipt.prepared_at)
            replacement = EffectPrepareAttempt(
                sequence=attempt.sequence,
                request=attempt.request,
                request_sha256=attempt.request_sha256,
                status=CoordinationAttemptStatus.RESPONSE_RETAINED,
                receipt=receipt,
                retained_at=attempt.retained_at,
                updated_at=when,
            )
            updated = self._replace_attempt(record, replacement)
            if updated.state is CoordinationState.RECEIVED:
                updated = self._transition(
                    updated,
                    state=CoordinationState.DISPATCH_ARMED,
                    evidence_sha256=receipt.digest,
                    reason="signed_prepare_receipt_durably_retained",
                    recorded_at=when,
                )
            return self._store(updated)

    def begin_commit(
        self,
        request: SignedEffectCommitRequest,
        *,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        """Retain outbound intent without claiming remote commit acceptance."""

        with self._mutex:
            self._assert_writer()
            record, _ = self._begin_commit_record(
                request,
                issue_acceptance=None,
                recorded_at=recorded_at,
            )
            return record

    def mark_commit_unknown(
        self,
        request: SignedEffectCommitRequest,
        *,
        reason: str,
        failure_evidence_sha256: str | None = None,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            return self._mark_commit_unknown_record(
                request,
                reason=reason,
                failure_evidence_sha256=failure_evidence_sha256,
                recorded_at=recorded_at,
            )

    def retain_commit_outcome(
        self,
        request: SignedEffectCommitRequest,
        outcome: SignedEffectOutcome,
        *,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            return self._finish_commit_record(
                request,
                outcome,
                recorded_at=recorded_at,
            )

    def begin_query(
        self,
        request: SignedEffectQueryRequest,
        *,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            record, _, _ = self._begin_query_record(
                request,
                recorded_at=recorded_at,
                allow_terminal=False,
            )
            return record

    def complete_query(
        self,
        request: SignedEffectQueryRequest,
        outcome: SignedEffectOutcome,
        *,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            return self._complete_query_record(
                request,
                outcome,
                recorded_at=recorded_at,
                create=False,
            )

    def fail_query(
        self,
        request: SignedEffectQueryRequest,
        *,
        reason: str,
        failure_evidence_sha256: str | None = None,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            return self._fail_query_record(
                request,
                reason=reason,
                failure_evidence_sha256=failure_evidence_sha256,
                recorded_at=recorded_at,
            )

    def close_not_dispatched(
        self,
        effect: EffectIdentity,
        *,
        reason: str,
        evidence_sha256: str | None = None,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            record = self._lookup(effect)
            if record is None:
                raise IllegalCoordinationTransition(
                    "cannot close an unrecorded effect as not dispatched"
                )
            if record.state.terminal:
                latest = record.transitions[-1]
                if (
                    latest.state is CoordinationState.NOT_DISPATCHED
                    and latest.reason == reason
                    and latest.evidence_sha256 == evidence_sha256
                ):
                    return record
                raise IllegalCoordinationTransition("terminal coordination state is immutable")
            when = self._when(recorded_at)
            updated = self._transition(
                record,
                state=CoordinationState.NOT_DISPATCHED,
                evidence_sha256=evidence_sha256,
                reason=reason,
                recorded_at=when,
            )
            return self._store(updated)


class DurableEffectCoordinationJournal(_DurableCoordinationJournal):
    """Generic OT effect-coordinator journal and idempotent commit registry."""

    JOURNAL_ROLE = "effect_coordinator"

    def prepare_effect(
        self,
        request: SignedEffectPrepareRequest,
        issue_receipt: ReceiptIssuer,
        *,
        recorded_at: datetime | None = None,
    ) -> CoordinationReceipt:
        """Persist request and receipt atomically before exposing the receipt."""

        with self._mutex:
            self._assert_writer()
            record = self._lookup(request.effect)
            if record is not None:
                existing = self._prepare_attempt(record, request)
                if existing is not None and existing.receipt is not None:
                    return existing.receipt
                if record.state.terminal:
                    raise IllegalCoordinationTransition("terminal coordination state is immutable")
                self._require_attempt_capacity(record)
            elif len(self._records) >= self.MAX_ENTRIES:
                raise CoordinationJournalError("coordination journal is at capacity")

            when = self._when(recorded_at)
            receipt = issue_receipt(request, when)
            self._validate_receipt(request, receipt)
            if record is None:
                attempt = EffectPrepareAttempt(
                    sequence=1,
                    request=request,
                    request_sha256=request.digest,
                    status=CoordinationAttemptStatus.RESPONSE_RETAINED,
                    receipt=receipt,
                    retained_at=when,
                    updated_at=when,
                )
                record = CoordinationJournalRecord(
                    effect=request.effect,
                    effect_sha256=request.effect.digest,
                    transitions=(
                        CoordinationTransition(
                            sequence=1,
                            state=CoordinationState.RECEIVED,
                            disposition=None,
                            evidence_sha256=request.digest,
                            reason="prepare_request_durably_retained",
                            recorded_at=when,
                        ),
                        CoordinationTransition(
                            sequence=2,
                            state=CoordinationState.DISPATCH_ARMED,
                            disposition=None,
                            evidence_sha256=receipt.digest,
                            reason="signed_prepare_receipt_durably_retained",
                            recorded_at=when,
                        ),
                    ),
                    attempts=(attempt,),
                )
            elif (existing := self._prepare_attempt(record, request)) is not None:
                replacement = EffectPrepareAttempt(
                    sequence=existing.sequence,
                    request=existing.request,
                    request_sha256=existing.request_sha256,
                    status=CoordinationAttemptStatus.RESPONSE_RETAINED,
                    receipt=receipt,
                    retained_at=existing.retained_at,
                    updated_at=when,
                )
                record = self._replace_attempt(record, replacement)
                if record.state is CoordinationState.RECEIVED:
                    record = self._transition(
                        record,
                        state=CoordinationState.DISPATCH_ARMED,
                        evidence_sha256=receipt.digest,
                        reason="signed_prepare_receipt_durably_retained",
                        recorded_at=when,
                    )
            else:
                attempt = EffectPrepareAttempt(
                    sequence=len(record.attempts) + 1,
                    request=request,
                    request_sha256=request.digest,
                    status=CoordinationAttemptStatus.RESPONSE_RETAINED,
                    receipt=receipt,
                    retained_at=when,
                    updated_at=when,
                )
                record = record.model_copy(update={"attempts": (*record.attempts, attempt)})
            self._store(record)
            return receipt

    def begin_commit(
        self,
        request: SignedEffectCommitRequest,
        issue_acceptance: CommitAcceptanceIssuer,
        *,
        recorded_at: datetime | None = None,
    ) -> CommitAdmission:
        """Durably retain commit intent before returning ``NEW`` to an executor."""

        with self._mutex:
            self._assert_writer()
            record, created = self._begin_commit_record(
                request,
                issue_acceptance=issue_acceptance,
                recorded_at=recorded_at,
            )
            outcome = record.terminal_outcome
            acceptance = record.latest_acceptance
            if acceptance is None:
                raise CoordinationJournalError(
                    "effect-coordinator commit admission lacks durable acceptance"
                )
            if created:
                status = CommitAdmissionStatus.NEW
            elif outcome is not None:
                status = CommitAdmissionStatus.TERMINAL
            else:
                status = CommitAdmissionStatus.INDETERMINATE
            return CommitAdmission(
                status=status,
                request=request,
                record=record,
                acceptance=acceptance,
                retained_outcome=outcome,
            )

    def finish_commit(
        self,
        request: SignedEffectCommitRequest,
        outcome: SignedEffectOutcome,
        *,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            return self._finish_commit_record(
                request,
                outcome,
                recorded_at=recorded_at,
            )

    def mark_commit_unknown(
        self,
        request: SignedEffectCommitRequest,
        *,
        reason: str,
        failure_evidence_sha256: str | None = None,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            return self._mark_commit_unknown_record(
                request,
                reason=reason,
                failure_evidence_sha256=failure_evidence_sha256,
                recorded_at=recorded_at,
            )

    def retain_query_outcome(
        self,
        request: SignedEffectQueryRequest,
        outcome: SignedEffectOutcome,
        *,
        recorded_at: datetime | None = None,
    ) -> CoordinationJournalRecord:
        with self._mutex:
            self._assert_writer()
            return self._complete_query_record(
                request,
                outcome,
                recorded_at=recorded_at,
                create=True,
            )

    def answer_query(
        self,
        request: SignedEffectQueryRequest,
        issue_outcome: OutcomeIssuer,
        *,
        recorded_at: datetime | None = None,
    ) -> SignedEffectOutcome:
        """Persist an exact query/outcome pair before exposing the signed outcome."""

        with self._mutex:
            self._assert_writer()
            record = self._lookup(request.effect)
            if record is None:
                raise IllegalCoordinationTransition("cannot answer an unrecorded effect")
            existing = self._query_attempt(record, request)
            if existing is not None and existing.outcome is not None:
                return existing.outcome
            when = self._when(recorded_at)
            outcome = issue_outcome(request, record, when)
            self._complete_query_record(
                request,
                outcome,
                recorded_at=when,
                create=True,
            )
            return outcome


# Compatibility names for the unpublished plant-specific draft. The durable
# executor is the OT effect coordinator, not the physical plant service.
DurablePlantCoordinationJournal = DurableEffectCoordinationJournal
GatewayCoordinationJournal = DurableGatewayCoordinationJournal
EffectCoordinationJournal = DurableEffectCoordinationJournal
PlantCoordinationJournal = DurableEffectCoordinationJournal
