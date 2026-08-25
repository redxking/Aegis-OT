"""Lightweight durable replay reservations for capability transactions."""

from __future__ import annotations

import json
import os
from contextlib import suppress
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Any, Self
from uuid import uuid4

from .transport_replay import _LifetimeReplayWriterLock, _ReplayWriterLockError


class OrderlyRestartReplayReservations:
    """Single-writer replay reservations persisted by file-and-directory fsync."""

    MAX_LEDGER_BYTES = 4 * 1024 * 1024

    def __init__(self, path: Path, *, initialize: bool = False) -> None:
        self.path = path
        self._lock = RLock()
        self._writer_lock: _LifetimeReplayWriterLock | None = None
        self._state = self._empty()
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise ValueError("PLC replay ledger directory must be a non-symlink directory")
        try:
            self._writer_lock = _LifetimeReplayWriterLock(self.path)
            if initialize:
                if self.path.exists() or self.path.is_symlink():
                    raise ValueError(
                        "PLC replay ledger already exists; refusing to initialize"
                    )
                self._persist()
            self._state = self._load()
        except _ReplayWriterLockError as exc:
            self.close()
            raise ValueError(
                "PLC replay writer lock is already held or unavailable"
            ) from exc
        except Exception:
            self.close()
            raise

    @property
    def writer_lock_path(self) -> Path:
        return _LifetimeReplayWriterLock.path_for(self.path)

    def _assert_writer(self) -> None:
        writer_lock = self._writer_lock
        if writer_lock is None:
            raise ValueError("PLC replay writer lock is closed")
        try:
            writer_lock.assert_held_by_current_process()
        except _ReplayWriterLockError as exc:
            raise ValueError(str(exc)) from exc

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
    def _empty() -> dict[str, set[str]]:
        return {
            "request_digests": set(),
            "permit_ids": set(),
            "permit_nonces": set(),
            "command_ids": set(),
        }

    def _load(self) -> dict[str, set[str]]:
        self._assert_writer()
        if not self.path.exists():
            raise ValueError("PLC replay ledger is missing or unavailable")
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("PLC replay ledger must be a regular non-symlink file")
        if self.path.stat().st_size > self.MAX_LEDGER_BYTES:
            raise ValueError("PLC replay ledger exceeds its size limit")

        def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("PLC replay ledger contains a duplicate key")
                value[key] = item
            return value

        parsed = json.loads(
            self.path.read_text(encoding="utf-8"),
            object_pairs_hook=closed_object,
        )
        if not isinstance(parsed, dict):
            raise ValueError("PLC replay ledger root must be an object")
        expected = self._empty()
        if set(parsed) != set(expected):
            raise ValueError("PLC replay ledger has unexpected or missing fields")
        for key in expected:
            values = parsed.get(key)
            if (
                not isinstance(values, list)
                or not all(isinstance(value, str) and value for value in values)
                or values != sorted(set(values))
            ):
                raise ValueError("PLC replay ledger has an invalid reservation set")
            expected[key] = set(values)
        return expected

    def _persist(self) -> None:
        self._assert_writer()
        temporary = self.path.with_suffix(f".{uuid4().hex}.tmp")
        material = json.dumps(
            {key: sorted(values) for key, values in sorted(self._state.items())},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        replaced = False
        try:
            offset = 0
            while offset < len(material):
                offset += os.write(descriptor, material[offset:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self.path)
            replaced = True
            directory_descriptor = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

    def replay_reason(
        self,
        *,
        request_digest: str,
        permit_id: str,
        permit_nonce: str,
        command_id: str,
    ) -> str | None:
        with self._lock:
            self._state = self._load()
            return self._replay_reason(
                request_digest=request_digest,
                permit_id=permit_id,
                permit_nonce=permit_nonce,
                command_id=command_id,
            )

    def _replay_reason(
        self,
        *,
        request_digest: str,
        permit_id: str,
        permit_nonce: str,
        command_id: str,
    ) -> str | None:
        checks = (
            (request_digest in self._state["request_digests"], "transaction_replayed"),
            (permit_id in self._state["permit_ids"], "permit_replayed"),
            (permit_nonce in self._state["permit_nonces"], "permit_nonce_replayed"),
            (command_id in self._state["command_ids"], "command_replayed"),
        )
        return next((reason for replayed, reason in checks if replayed), None)

    def reserve(
        self,
        *,
        request_digest: str,
        permit_id: str,
        permit_nonce: str,
        command_id: str,
    ) -> None:
        with self._lock:
            self._state = self._load()
            reason = self._replay_reason(
                request_digest=request_digest,
                permit_id=permit_id,
                permit_nonce=permit_nonce,
                command_id=command_id,
            )
            if reason is not None:
                raise ValueError(reason)
            self._state["request_digests"].add(request_digest)
            self._state["permit_ids"].add(permit_id)
            self._state["permit_nonces"].add(permit_nonce)
            self._state["command_ids"].add(command_id)
            self._persist()

    @property
    def reservation_count(self) -> int:
        with self._lock:
            self._state = self._load()
            return len(self._state["request_digests"])
