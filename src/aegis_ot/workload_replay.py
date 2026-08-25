"""Durable replay reservations bound to a stable workload identity.

The M4f transport ledger is intentionally bound to a specific gateway leaf
key.  Workload credentials introduced by M4g rotate those leaf keys, so this
ledger binds durable replay state to the authority-issued workload subject
instead.  A credential rotation therefore cannot reset replay history, while
changing the trust domain, subject, authority, or audience fails closed.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from contextlib import suppress
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Any, Self
from uuid import uuid4


class WorkloadReplayLedgerError(RuntimeError):
    """The durable workload replay ledger could not be trusted or updated."""


class _WriterLockError(RuntimeError):
    """A ledger's stable, process-exclusive writer lock could not be held."""


class _LifetimeWriterLock:
    """Hold a sidecar ``flock`` across atomic ledger-file replacements."""

    def __init__(self, ledger_path: Path) -> None:
        self.path = self.path_for(ledger_path)
        self._descriptor = -1
        self._owner_pid = os.getpid()
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(self.path, flags, 0o600)
            lock_stat = os.fstat(descriptor)
            if not stat.S_ISREG(lock_stat.st_mode):
                raise _WriterLockError(
                    "workload replay writer lock must be a regular non-symlink file"
                )
            if stat.S_IMODE(lock_stat.st_mode) != 0o600:
                raise _WriterLockError("workload replay writer lock mode must be 0600")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except _WriterLockError:
            if "descriptor" in locals():
                os.close(descriptor)
            raise
        except OSError as exc:
            if "descriptor" in locals():
                os.close(descriptor)
            raise _WriterLockError(
                "workload replay writer lock is already held or unavailable"
            ) from exc
        self._descriptor = descriptor

    @staticmethod
    def path_for(ledger_path: Path) -> Path:
        return ledger_path.with_name(f".{ledger_path.name}.writer.lock")

    def assert_held_by_current_process(self) -> None:
        if self._descriptor < 0:
            raise _WriterLockError("workload replay writer lock is closed")
        if self._owner_pid != os.getpid():
            raise _WriterLockError(
                "workload replay writer lock cannot be used by an inherited child process"
            )

    def close(self) -> None:
        descriptor = self._descriptor
        if descriptor < 0:
            return
        self._descriptor = -1
        os.close(descriptor)


class DurableWorkloadReplayLedger:
    """Strict fsync-backed replay state for one stable workload subject.

    Leaf credential identifiers and public-key hashes are deliberately absent
    from both the constructor and persisted identity.  Replay state therefore
    survives authority-approved leaf rotation for the same workload subject.
    """

    SCHEMA_VERSION = "m4g-workload-replay-ledger-v1"
    MAX_LEDGER_BYTES = 4 * 1024 * 1024
    MAX_RESERVATIONS = 8192
    MIN_NONCE_LENGTH = 16
    MAX_NONCE_LENGTH = 256

    def __init__(
        self,
        path: Path,
        *,
        audience: str,
        trust_domain: str,
        workload_subject: str,
        authority_key_id: str,
        initialize: bool = False,
    ) -> None:
        self.path = path
        self.audience = self._bounded_identity("audience", audience)
        self.trust_domain = self._bounded_identity("trust domain", trust_domain)
        self.workload_subject = self._bounded_identity(
            "workload subject", workload_subject
        )
        self.authority_key_id = self._bounded_identity(
            "authority key ID", authority_key_id
        )
        self._lock = RLock()
        self._writer_lock: _LifetimeWriterLock | None = None
        self._reservations: dict[str, str] = {}
        self._check_parent()
        try:
            self._writer_lock = _LifetimeWriterLock(self.path)
            if initialize:
                if self.path.exists() or self.path.is_symlink():
                    raise WorkloadReplayLedgerError(
                        "workload replay ledger already exists; refusing to initialize"
                    )
                self._persist()
            self._reservations = self._load()
        except _WriterLockError as exc:
            self.close()
            raise WorkloadReplayLedgerError(str(exc)) from exc
        except Exception:
            self.close()
            raise

    @property
    def writer_lock_path(self) -> Path:
        return _LifetimeWriterLock.path_for(self.path)

    def _assert_writer(self) -> None:
        writer_lock = self._writer_lock
        if writer_lock is None:
            raise WorkloadReplayLedgerError("workload replay writer lock is closed")
        try:
            writer_lock.assert_held_by_current_process()
        except _WriterLockError as exc:
            raise WorkloadReplayLedgerError(str(exc)) from exc

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
    def _bounded_identity(label: str, value: str) -> str:
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 256
            or value != value.strip()
        ):
            raise WorkloadReplayLedgerError(f"workload replay {label} is invalid")
        return value

    @staticmethod
    def _digest(value: str) -> str:
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise WorkloadReplayLedgerError("workload replay digest is invalid")
        return value

    @classmethod
    def _nonce(cls, value: str) -> str:
        if (
            not isinstance(value, str)
            or not cls.MIN_NONCE_LENGTH <= len(value) <= cls.MAX_NONCE_LENGTH
        ):
            raise WorkloadReplayLedgerError("workload replay nonce length is invalid")
        return value

    @staticmethod
    def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise WorkloadReplayLedgerError(
                    "workload replay ledger has a duplicate key"
                )
            value[key] = item
        return value

    def _check_parent(self) -> None:
        try:
            parent_stat = self.path.parent.stat()
        except OSError as exc:
            raise WorkloadReplayLedgerError(
                "workload replay directory is unavailable"
            ) from exc
        if self.path.parent.is_symlink() or not stat.S_ISDIR(parent_stat.st_mode):
            raise WorkloadReplayLedgerError(
                "workload replay directory must be a non-symlink directory"
            )
        if stat.S_IMODE(parent_stat.st_mode) & 0o077:
            raise WorkloadReplayLedgerError(
                "workload replay directory must not grant group or other access"
            )

    def _read(self) -> bytes:
        self._assert_writer()
        self._check_parent()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise WorkloadReplayLedgerError(
                "workload replay ledger is missing or unavailable"
            ) from exc
        try:
            ledger_stat = os.fstat(descriptor)
            if not stat.S_ISREG(ledger_stat.st_mode):
                raise WorkloadReplayLedgerError(
                    "workload replay ledger must be a regular non-symlink file"
                )
            if stat.S_IMODE(ledger_stat.st_mode) != 0o600:
                raise WorkloadReplayLedgerError(
                    "workload replay ledger mode must be 0600"
                )
            if ledger_stat.st_size > self.MAX_LEDGER_BYTES:
                raise WorkloadReplayLedgerError(
                    "workload replay ledger exceeds its size limit"
                )
            chunks: list[bytes] = []
            remaining = self.MAX_LEDGER_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            material = b"".join(chunks)
            if len(material) > self.MAX_LEDGER_BYTES:
                raise WorkloadReplayLedgerError(
                    "workload replay ledger exceeds its size limit"
                )
            return material
        except OSError as exc:
            raise WorkloadReplayLedgerError(
                "workload replay ledger cannot be read"
            ) from exc
        finally:
            os.close(descriptor)

    def _document(self, reservations: dict[str, str]) -> dict[str, Any]:
        return {
            "audience": self.audience,
            "authority_key_id": self.authority_key_id,
            "reservations": [
                {"nonce": nonce, "signed_request_sha256": reservations[nonce]}
                for nonce in sorted(reservations)
            ],
            "schema_version": self.SCHEMA_VERSION,
            "trust_domain": self.trust_domain,
            "workload_subject": self.workload_subject,
        }

    @staticmethod
    def _canonical_bytes(value: dict[str, Any]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    def _load(self) -> dict[str, str]:
        material = self._read()
        try:
            text = material.decode("utf-8", errors="strict")
            parsed = json.loads(text, object_pairs_hook=self._closed_object)
        except WorkloadReplayLedgerError:
            raise
        except (UnicodeError, ValueError) as exc:
            raise WorkloadReplayLedgerError(
                "workload replay ledger is not strict UTF-8 JSON"
            ) from exc
        if not isinstance(parsed, dict) or set(parsed) != {
            "schema_version",
            "audience",
            "trust_domain",
            "workload_subject",
            "authority_key_id",
            "reservations",
        }:
            raise WorkloadReplayLedgerError(
                "workload replay ledger has unexpected or missing fields"
            )
        if parsed["schema_version"] != self.SCHEMA_VERSION:
            raise WorkloadReplayLedgerError(
                "workload replay ledger schema is unsupported"
            )
        if (
            parsed["audience"] != self.audience
            or parsed["trust_domain"] != self.trust_domain
            or parsed["workload_subject"] != self.workload_subject
            or parsed["authority_key_id"] != self.authority_key_id
        ):
            raise WorkloadReplayLedgerError(
                "workload replay ledger identity does not match configuration"
            )
        entries = parsed["reservations"]
        if not isinstance(entries, list) or len(entries) > self.MAX_RESERVATIONS:
            raise WorkloadReplayLedgerError(
                "workload replay ledger reservation set is invalid"
            )
        reservations: dict[str, str] = {}
        request_digests: set[str] = set()
        prior_nonce: str | None = None
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "nonce",
                "signed_request_sha256",
            }:
                raise WorkloadReplayLedgerError(
                    "workload replay ledger reservation shape is invalid"
                )
            nonce = self._nonce(entry["nonce"])
            request_digest = self._digest(entry["signed_request_sha256"])
            if prior_nonce is not None and nonce <= prior_nonce:
                raise WorkloadReplayLedgerError(
                    "workload replay ledger reservations are not sorted and unique"
                )
            if request_digest in request_digests:
                raise WorkloadReplayLedgerError(
                    "workload replay ledger request digest is duplicated"
                )
            reservations[nonce] = request_digest
            request_digests.add(request_digest)
            prior_nonce = nonce
        if material != self._canonical_bytes(self._document(reservations)):
            raise WorkloadReplayLedgerError(
                "workload replay ledger encoding is not canonical"
            )
        return reservations

    def _persist(self) -> None:
        self._assert_writer()
        self._check_parent()
        if len(self._reservations) > self.MAX_RESERVATIONS:
            raise WorkloadReplayLedgerError("workload replay ledger is at capacity")
        material = self._canonical_bytes(self._document(self._reservations))
        if len(material) > self.MAX_LEDGER_BYTES:
            raise WorkloadReplayLedgerError("workload replay ledger is at capacity")
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
                    raise OSError("workload replay ledger write made no progress")
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
            raise WorkloadReplayLedgerError(
                "workload replay ledger update failed"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                with suppress(FileNotFoundError):
                    temporary.unlink()

    def contains(self, nonce: str) -> bool:
        checked_nonce = self._nonce(nonce)
        with self._lock:
            self._reservations = self._load()
            return checked_nonce in self._reservations

    def reserve(self, nonce: str, signed_request_sha256: str) -> bool:
        checked_nonce = self._nonce(nonce)
        checked_digest = self._digest(signed_request_sha256)
        with self._lock:
            self._reservations = self._load()
            if checked_nonce in self._reservations:
                return False
            if checked_digest in self._reservations.values():
                return False
            prior = dict(self._reservations)
            self._reservations[checked_nonce] = checked_digest
            try:
                self._persist()
            except Exception:
                self._reservations = prior
                raise
            return True

    @property
    def reservation_count(self) -> int:
        with self._lock:
            self._reservations = self._load()
            return len(self._reservations)

    @property
    def reservations(self) -> dict[str, str]:
        with self._lock:
            self._reservations = self._load()
            return dict(self._reservations)

    @property
    def canonical_sha256(self) -> str:
        with self._lock:
            self._reservations = self._load()
            material = self._canonical_bytes(self._document(self._reservations))
            return hashlib.sha256(material).hexdigest()

    def status(self) -> tuple[int, str]:
        """Return count and digest from one validated ledger snapshot."""

        with self._lock:
            self._reservations = self._load()
            material = self._canonical_bytes(self._document(self._reservations))
            return len(self._reservations), hashlib.sha256(material).hexdigest()
