"""Durable, identity-bound replay reservations for authenticated OT transport."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4


class TransportReplayLedgerError(RuntimeError):
    """The durable transport replay ledger could not be trusted or updated."""


class DurableTransportReplayLedger:
    """Strict fsync-backed replay ledger for exactly one OT-adapter writer."""

    SCHEMA_VERSION = "m4f-transport-replay-ledger-v1"
    MAX_LEDGER_BYTES = 4 * 1024 * 1024
    MAX_RESERVATIONS = 8192
    MIN_NONCE_LENGTH = 16
    MAX_NONCE_LENGTH = 256

    def __init__(
        self,
        path: Path,
        *,
        audience: str,
        gateway_key_id: str,
        gateway_public_key_sha256: str,
        initialize: bool = False,
    ) -> None:
        self.path = path
        self.audience = self._bounded_identity("audience", audience)
        self.gateway_key_id = self._bounded_identity("gateway key ID", gateway_key_id)
        self.gateway_public_key_sha256 = self._digest(gateway_public_key_sha256)
        self._lock = RLock()
        self._reservations: dict[str, str] = {}
        self._check_parent()
        if initialize:
            if self.path.exists() or self.path.is_symlink():
                raise TransportReplayLedgerError(
                    "transport replay ledger already exists; refusing to initialize"
                )
            self._persist()
        self._reservations = self._load()

    @staticmethod
    def _bounded_identity(label: str, value: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 256:
            raise TransportReplayLedgerError(f"transport replay {label} is invalid")
        return value

    @staticmethod
    def _digest(value: str) -> str:
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise TransportReplayLedgerError("transport replay digest is invalid")
        return value

    @classmethod
    def _nonce(cls, value: str) -> str:
        if (
            not isinstance(value, str)
            or not cls.MIN_NONCE_LENGTH <= len(value) <= cls.MAX_NONCE_LENGTH
        ):
            raise TransportReplayLedgerError("transport nonce length is invalid")
        return value

    @staticmethod
    def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise TransportReplayLedgerError("transport replay ledger has a duplicate key")
            value[key] = item
        return value

    def _check_parent(self) -> None:
        try:
            parent_stat = self.path.parent.stat()
        except OSError as exc:
            raise TransportReplayLedgerError(
                "transport replay directory is unavailable"
            ) from exc
        if self.path.parent.is_symlink() or not stat.S_ISDIR(parent_stat.st_mode):
            raise TransportReplayLedgerError(
                "transport replay directory must be a non-symlink directory"
            )
        if stat.S_IMODE(parent_stat.st_mode) & 0o077:
            raise TransportReplayLedgerError(
                "transport replay directory must not grant group or other access"
            )

    def _read(self) -> bytes:
        self._check_parent()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise TransportReplayLedgerError(
                "transport replay ledger is missing or unavailable"
            ) from exc
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise TransportReplayLedgerError(
                    "transport replay ledger must be a regular non-symlink file"
                )
            if stat.S_IMODE(file_stat.st_mode) != 0o600:
                raise TransportReplayLedgerError(
                    "transport replay ledger mode must be 0600"
                )
            if file_stat.st_size > self.MAX_LEDGER_BYTES:
                raise TransportReplayLedgerError(
                    "transport replay ledger exceeds its size limit"
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
                raise TransportReplayLedgerError(
                    "transport replay ledger exceeds its size limit"
                )
            return material
        except OSError as exc:
            raise TransportReplayLedgerError(
                "transport replay ledger cannot be read"
            ) from exc
        finally:
            os.close(descriptor)

    def _document(self, reservations: dict[str, str]) -> dict[str, Any]:
        return {
            "audience": self.audience,
            "gateway_key_id": self.gateway_key_id,
            "gateway_public_key_sha256": self.gateway_public_key_sha256,
            "reservations": [
                {"nonce": nonce, "signed_request_sha256": reservations[nonce]}
                for nonce in sorted(reservations)
            ],
            "schema_version": self.SCHEMA_VERSION,
        }

    @staticmethod
    def _canonical_bytes(value: dict[str, Any]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def _load(self) -> dict[str, str]:
        material = self._read()
        try:
            text = material.decode("utf-8", errors="strict")
            parsed = json.loads(text, object_pairs_hook=self._closed_object)
        except TransportReplayLedgerError:
            raise
        except (UnicodeError, ValueError) as exc:
            raise TransportReplayLedgerError(
                "transport replay ledger is not strict UTF-8 JSON"
            ) from exc
        if not isinstance(parsed, dict) or set(parsed) != {
            "schema_version",
            "audience",
            "gateway_key_id",
            "gateway_public_key_sha256",
            "reservations",
        }:
            raise TransportReplayLedgerError(
                "transport replay ledger has unexpected or missing fields"
            )
        if parsed["schema_version"] != self.SCHEMA_VERSION:
            raise TransportReplayLedgerError("transport replay ledger schema is unsupported")
        if (
            parsed["audience"] != self.audience
            or parsed["gateway_key_id"] != self.gateway_key_id
            or parsed["gateway_public_key_sha256"] != self.gateway_public_key_sha256
        ):
            raise TransportReplayLedgerError(
                "transport replay ledger identity does not match configuration"
            )
        entries = parsed["reservations"]
        if not isinstance(entries, list) or len(entries) > self.MAX_RESERVATIONS:
            raise TransportReplayLedgerError(
                "transport replay ledger reservation set is invalid"
            )
        reservations: dict[str, str] = {}
        prior_nonce: str | None = None
        request_digests: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "nonce",
                "signed_request_sha256",
            }:
                raise TransportReplayLedgerError(
                    "transport replay ledger reservation shape is invalid"
                )
            nonce = self._nonce(entry["nonce"])
            request_digest = self._digest(entry["signed_request_sha256"])
            if prior_nonce is not None and nonce <= prior_nonce:
                raise TransportReplayLedgerError(
                    "transport replay ledger reservations are not sorted and unique"
                )
            if request_digest in request_digests:
                raise TransportReplayLedgerError(
                    "transport replay ledger request digest is duplicated"
                )
            reservations[nonce] = request_digest
            request_digests.add(request_digest)
            prior_nonce = nonce
        if material != self._canonical_bytes(self._document(reservations)):
            raise TransportReplayLedgerError(
                "transport replay ledger encoding is not canonical"
            )
        return reservations

    def _persist(self) -> None:
        self._check_parent()
        if len(self._reservations) > self.MAX_RESERVATIONS:
            raise TransportReplayLedgerError("transport replay ledger is at capacity")
        material = self._canonical_bytes(self._document(self._reservations))
        if len(material) > self.MAX_LEDGER_BYTES:
            raise TransportReplayLedgerError("transport replay ledger is at capacity")
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        descriptor = -1
        replaced = False
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            offset = 0
            while offset < len(material):
                written = os.write(descriptor, material[offset:])
                if written <= 0:
                    raise OSError("transport replay ledger write made no progress")
                offset += written
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
        except OSError as exc:
            raise TransportReplayLedgerError(
                "transport replay ledger update failed"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

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
        """Return a count and digest from the same validated ledger snapshot."""

        with self._lock:
            self._reservations = self._load()
            material = self._canonical_bytes(self._document(self._reservations))
            return len(self._reservations), hashlib.sha256(material).hexdigest()
