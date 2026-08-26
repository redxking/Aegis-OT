"""Crash-durable monotonic state for workload trust-bundle observations.

The checkpoint protects a verifier from accepting an older signed trust bundle
after its process restarts.  It is deliberately local state: it does not claim
to resist rollback of the checkpoint volume by a hostile host.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import secrets
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from threading import RLock
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_STATE_INTEGRITY_DOMAIN = b"aegis-ot:m4g:workload-trust-sequence-state:v1\x00"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_STATE_BYTES = 4096


class WorkloadTrustSequenceStateError(RuntimeError):
    """The local trust-sequence checkpoint cannot be trusted or updated."""


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_json_file_bytes(value: BaseModel) -> bytes:
    return _canonical_json_bytes(value.model_dump(mode="json")) + b"\n"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate trust-sequence state key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite trust-sequence state constant is forbidden: {value}")


def _strict_json_loads(material: bytes) -> Any:
    if material.startswith(b"\xef\xbb\xbf"):
        raise ValueError("trust-sequence state UTF-8 BOM is forbidden")
    return json.loads(
        material.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def _state_integrity_sha256(fields: dict[str, Any]) -> str:
    return hashlib.sha256(
        _STATE_INTEGRITY_DOMAIN + _canonical_json_bytes(fields)
    ).hexdigest()


class WorkloadTrustSequenceState(BaseModel):
    """Closed, self-checking checkpoint for one pinned workload authority."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    schema_version: str = Field(
        default="m4g-workload-trust-sequence-state-v1",
        pattern=r"^m4g-workload-trust-sequence-state-v1$",
    )
    trust_domain: str = Field(min_length=3, max_length=128)
    authority_key_id: str = Field(min_length=3, max_length=128)
    authority_public_key_sha256: str = Field(pattern=_SHA256_PATTERN)
    highest_sequence: int = Field(ge=1)
    highest_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    integrity_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("trust_domain", "authority_key_id")
    @classmethod
    def require_closed_identity(cls, value: str) -> str:
        if value != value.strip() or any(character.isspace() for character in value):
            raise ValueError("trust-sequence state identity must not contain whitespace")
        return value

    @model_validator(mode="after")
    def require_valid_integrity(self) -> Self:
        if self.integrity_sha256 != _state_integrity_sha256(self.integrity_fields()):
            raise ValueError("trust-sequence state integrity digest is invalid")
        return self

    def integrity_fields(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"integrity_sha256"})

    @classmethod
    def create(
        cls,
        *,
        trust_domain: str,
        authority_key_id: str,
        authority_public_key_sha256: str,
        highest_sequence: int,
        highest_bundle_sha256: str,
    ) -> WorkloadTrustSequenceState:
        fields: dict[str, Any] = {
            "schema_version": "m4g-workload-trust-sequence-state-v1",
            "trust_domain": trust_domain,
            "authority_key_id": authority_key_id,
            "authority_public_key_sha256": authority_public_key_sha256,
            "highest_sequence": highest_sequence,
            "highest_bundle_sha256": highest_bundle_sha256,
        }
        return cls(**fields, integrity_sha256=_state_integrity_sha256(fields))


class FileWorkloadTrustSequenceStateStore:
    """Process-serialized, fsync-backed trust-bundle sequence checkpoint.

    The configured parent must already exist as a dedicated, owner-matching
    ``0700`` directory.  An empty directory may bootstrap exactly once.  Once
    initialized, the directory contains only the checkpoint and its stable
    sidecar lock.
    """

    def __init__(
        self,
        path: Path,
        *,
        trust_domain: str,
        authority_key_id: str,
        authority_public_key_sha256: str,
        lock_timeout_seconds: float = 2.0,
    ) -> None:
        if not path.is_absolute() or not path.name or path.name in {".", ".."}:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence state path must be an absolute file path"
            )
        if not 0.0 <= lock_timeout_seconds <= 30.0:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence lock timeout is outside policy"
        )
        self.path = path
        self.trust_domain = self._identity("trust domain", trust_domain, minimum=3)
        self.authority_key_id = self._identity(
            "authority key ID",
            authority_key_id,
            minimum=3,
        )
        self.authority_public_key_sha256 = self._digest(
            "authority public key", authority_public_key_sha256
        )
        self.lock_timeout_seconds = lock_timeout_seconds
        self._thread_lock = RLock()
        self._highest_sequence = 0
        self._highest_bundle_sha256 = ""
        self._poisoned = False

        parent_fd = self._open_parent()
        try:
            self._classify_layout(parent_fd)
        finally:
            os.close(parent_fd)

    @property
    def lock_path(self) -> Path:
        return self.path.with_name(f".{self.path.name}.lock")

    @staticmethod
    def _identity(label: str, value: str, *, minimum: int) -> str:
        if (
            not minimum <= len(value) <= 128
            or value != value.strip()
            or any(character.isspace() for character in value)
        ):
            raise WorkloadTrustSequenceStateError(
                f"workload trust-sequence {label} is invalid"
            )
        return value

    @staticmethod
    def _digest(label: str, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise WorkloadTrustSequenceStateError(
                f"workload trust-sequence {label} digest is invalid"
            )
        return value

    @staticmethod
    def _secure_open_flags() -> tuple[int, int]:
        try:
            return os.O_NOFOLLOW, os.O_CLOEXEC
        except AttributeError as exc:  # pragma: no cover - supported deployment platforms
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence state requires no-follow and close-on-exec support"
            ) from exc

    def _open_parent(self) -> int:
        nofollow, cloexec = self._secure_open_flags()
        try:
            before = os.lstat(self.path.parent)
        except OSError as exc:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence directory is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o700
        ):
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence directory must be an owner-matching 0700 directory"
            )
        flags = os.O_RDONLY | nofollow | cloexec | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(self.path.parent, flags)
        except OSError as exc:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence directory cannot be opened safely"
            ) from exc
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not stat.S_ISDIR(after.st_mode)
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence directory changed during validation"
            )
        return descriptor

    def _entries(self, parent_fd: int) -> set[str]:
        try:
            return set(os.listdir(parent_fd))
        except OSError as exc:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence directory cannot be enumerated"
            ) from exc

    def _classify_layout(self, parent_fd: int) -> bool:
        """Return whether the directory is an unused bootstrap root."""

        entries = self._entries(parent_fd)
        state_present = self.path.name in entries
        lock_present = self.lock_path.name in entries
        if not state_present and not lock_present:
            if entries:
                raise WorkloadTrustSequenceStateError(
                    "workload trust-sequence bootstrap directory contains unexpected entries"
                )
            return True
        if state_present != lock_present:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence checkpoint and stable lock must both exist"
            )
        return False

    def _require_entries(self, parent_fd: int, expected: set[str]) -> None:
        if self._entries(parent_fd) != expected:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence directory contains unexpected entries"
            )

    @staticmethod
    def _validate_private_file(descriptor: int, *, label: str) -> os.stat_result:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise WorkloadTrustSequenceStateError(
                f"workload trust-sequence {label} must be an owner-matching single-link 0600 file"
            )
        return metadata

    def _open_lock(self, parent_fd: int, *, bootstrap: bool) -> int:
        nofollow, cloexec = self._secure_open_flags()
        flags = os.O_RDWR | nofollow | cloexec
        if bootstrap:
            flags |= os.O_CREAT | os.O_EXCL
        try:
            descriptor = os.open(
                self.lock_path.name,
                flags,
                0o600,
                dir_fd=parent_fd,
            )
            self._validate_private_file(descriptor, label="stable lock")
            if bootstrap:
                os.fsync(descriptor)
                os.fsync(parent_fd)
            return descriptor
        except Exception as exc:
            if "descriptor" in locals():
                os.close(descriptor)
            if isinstance(exc, WorkloadTrustSequenceStateError):
                raise
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence stable lock is unavailable"
            ) from exc

    def _acquire_lock(self, descriptor: int) -> None:
        deadline = time.monotonic() + self.lock_timeout_seconds
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise WorkloadTrustSequenceStateError(
                        "workload trust-sequence stable lock cannot be acquired"
                    ) from exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WorkloadTrustSequenceStateError(
                        "workload trust-sequence stable lock acquisition timed out"
                    ) from exc
                time.sleep(min(0.01, remaining))

    def _require_stable_lock(self, parent_fd: int, descriptor: int) -> None:
        held = self._validate_private_file(descriptor, label="stable lock")
        try:
            named = os.stat(
                self.lock_path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence stable lock changed during acquisition"
            ) from exc
        if (
            stat.S_ISLNK(named.st_mode)
            or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence stable lock changed during acquisition"
            )

    def _load_locked(self, parent_fd: int) -> WorkloadTrustSequenceState:
        nofollow, cloexec = self._secure_open_flags()
        try:
            descriptor = os.open(
                self.path.name,
                os.O_RDONLY | nofollow | cloexec | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence checkpoint is missing or unavailable"
            ) from exc
        try:
            before = self._validate_private_file(descriptor, label="checkpoint")
            if not 1 <= before.st_size <= _MAX_STATE_BYTES:
                raise WorkloadTrustSequenceStateError(
                    "workload trust-sequence checkpoint is outside its size limit"
                )
            chunks: list[bytes] = []
            remaining = _MAX_STATE_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 4096))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            material = b"".join(chunks)
            after = self._validate_private_file(descriptor, label="checkpoint")
        except OSError as exc:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence checkpoint cannot be read"
            ) from exc
        finally:
            os.close(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if (
            len(material) != before.st_size
            or len(material) > _MAX_STATE_BYTES
            or before_identity != after_identity
        ):
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence checkpoint changed while it was read"
            )
        try:
            state = WorkloadTrustSequenceState.model_validate(
                _strict_json_loads(material)
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence checkpoint is invalid"
            ) from exc
        if material != _canonical_json_file_bytes(state):
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence checkpoint encoding is not canonical"
            )
        if (
            state.trust_domain != self.trust_domain
            or state.authority_key_id != self.authority_key_id
            or state.authority_public_key_sha256 != self.authority_public_key_sha256
        ):
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence checkpoint does not match configured trust"
            )
        return state

    def _write_locked(
        self,
        parent_fd: int,
        state: WorkloadTrustSequenceState,
    ) -> None:
        material = _canonical_json_file_bytes(state)
        if len(material) > _MAX_STATE_BYTES:
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence checkpoint exceeds its size limit"
            )
        nofollow, cloexec = self._secure_open_flags()
        temporary_name = f".{self.path.name}.{secrets.token_hex(12)}.tmp"
        descriptor = -1
        replaced = False
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
                0o600,
                dir_fd=parent_fd,
            )
            os.fchmod(descriptor, 0o600)
            self._validate_private_file(descriptor, label="temporary checkpoint")
            offset = 0
            while offset < len(material):
                written = os.write(descriptor, material[offset:])
                if written <= 0:
                    raise OSError("trust-sequence checkpoint write made no progress")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                self.path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            replaced = True
            os.fsync(parent_fd)
            readback = self._load_locked(parent_fd)
            if readback != state:
                raise WorkloadTrustSequenceStateError(
                    "workload trust-sequence checkpoint readback disagrees"
                )
        except Exception as exc:
            self._poisoned = True
            if isinstance(exc, WorkloadTrustSequenceStateError):
                raise
            raise WorkloadTrustSequenceStateError(
                "workload trust-sequence checkpoint update failed"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=parent_fd)

    def _candidate_state(
        self,
        *,
        sequence: int,
        bundle_sha256: str,
    ) -> WorkloadTrustSequenceState:
        return WorkloadTrustSequenceState.create(
            trust_domain=self.trust_domain,
            authority_key_id=self.authority_key_id,
            authority_public_key_sha256=self.authority_public_key_sha256,
            highest_sequence=sequence,
            highest_bundle_sha256=bundle_sha256,
        )

    @contextmanager
    def transaction(
        self,
        *,
        sequence: int,
        bundle_sha256: str,
    ) -> Iterator[WorkloadTrustSequenceState]:
        """Persist one valid observation, then hold its lock through admission."""

        checked_digest = self._digest("bundle", bundle_sha256)
        if sequence < 1:
            raise WorkloadTrustSequenceStateError(
                "workload trust-bundle sequence is invalid"
            )
        with self._thread_lock:
            if self._poisoned:
                raise WorkloadTrustSequenceStateError(
                    "workload trust-sequence state instance is poisoned"
                )
            parent_fd = self._open_parent()
            lock_fd = -1
            acquired = False
            try:
                bootstrap = self._classify_layout(parent_fd)
                lock_fd = self._open_lock(parent_fd, bootstrap=bootstrap)
                self._acquire_lock(lock_fd)
                acquired = True
                self._require_stable_lock(parent_fd, lock_fd)
                if bootstrap:
                    self._require_entries(parent_fd, {self.lock_path.name})
                    current: WorkloadTrustSequenceState | None = None
                else:
                    self._require_entries(
                        parent_fd,
                        {self.path.name, self.lock_path.name},
                    )
                    try:
                        current = self._load_locked(parent_fd)
                    except WorkloadTrustSequenceStateError:
                        self._poisoned = True
                        raise

                if current is not None:
                    if sequence < current.highest_sequence:
                        raise WorkloadTrustSequenceStateError(
                            "workload trust bundle sequence rolled back"
                        )
                    if (
                        sequence == current.highest_sequence
                        and checked_digest != current.highest_bundle_sha256
                    ):
                        raise WorkloadTrustSequenceStateError(
                            "workload trust bundle sequence was equivocated"
                        )

                if sequence < self._highest_sequence:
                    raise WorkloadTrustSequenceStateError(
                        "workload trust bundle sequence rolled back in process"
                    )
                if (
                    sequence == self._highest_sequence
                    and self._highest_bundle_sha256
                    and checked_digest != self._highest_bundle_sha256
                ):
                    raise WorkloadTrustSequenceStateError(
                        "workload trust bundle sequence was equivocated in process"
                    )

                if current is None or sequence > current.highest_sequence:
                    current = self._candidate_state(
                        sequence=sequence,
                        bundle_sha256=checked_digest,
                    )
                    self._write_locked(parent_fd, current)
                    self._require_entries(
                        parent_fd,
                        {self.path.name, self.lock_path.name},
                    )

                self._highest_sequence = sequence
                self._highest_bundle_sha256 = checked_digest
                yield current
            finally:
                if acquired:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        self._poisoned = True
                if lock_fd >= 0:
                    os.close(lock_fd)
                os.close(parent_fd)
