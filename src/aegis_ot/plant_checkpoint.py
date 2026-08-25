"""Fail-closed durable checkpoints for the authoritative synthetic plant.

The store provides bounded single-host, single-writer persistence.  It does
not provide an external monotonic anchor, hostile-host rollback resistance,
replication, or consensus.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Any, ClassVar, Self
from uuid import uuid4

from .physical_models import PhysicalStateSnapshot


class PlantCheckpointError(RuntimeError):
    """A plant checkpoint could not be trusted or durably updated."""


class _WriterLockError(RuntimeError):
    """The checkpoint's process-exclusive writer lock is unavailable."""


class _LifetimeWriterLock:
    """Hold one sidecar ``flock`` across atomic checkpoint replacements."""

    def __init__(self, checkpoint_path: Path, *, initialize: bool) -> None:
        self.path = self.path_for(checkpoint_path)
        self._descriptor = -1
        self._owner_pid = os.getpid()
        flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if initialize:
            flags |= os.O_CREAT | os.O_EXCL
        try:
            descriptor = os.open(self.path, flags, 0o600)
            lock_stat = os.fstat(descriptor)
            if not stat.S_ISREG(lock_stat.st_mode):
                raise _WriterLockError(
                    "plant checkpoint writer lock must be a regular non-symlink file"
                )
            if stat.S_IMODE(lock_stat.st_mode) != 0o600:
                raise _WriterLockError("plant checkpoint writer lock mode must be 0600")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except _WriterLockError:
            if "descriptor" in locals():
                os.close(descriptor)
            raise
        except OSError as exc:
            if "descriptor" in locals():
                os.close(descriptor)
            raise _WriterLockError(
                "plant checkpoint writer lock is missing, held, or unavailable"
            ) from exc
        self._descriptor = descriptor

    @staticmethod
    def path_for(checkpoint_path: Path) -> Path:
        return checkpoint_path.with_name(f".{checkpoint_path.name}.writer.lock")

    def assert_held_by_current_process(self) -> None:
        if self._descriptor < 0:
            raise _WriterLockError("plant checkpoint writer lock is closed")
        if self._owner_pid != os.getpid():
            raise _WriterLockError(
                "plant checkpoint writer lock cannot be used by an inherited child process"
            )

    def close(self) -> None:
        descriptor = self._descriptor
        if descriptor < 0:
            return
        self._descriptor = -1
        os.close(descriptor)


class DurablePlantCheckpointStore:
    """Strict latest-state checkpoint for one configured plant identity.

    ``initialize=True`` provisions a canonical empty sentinel.  The runtime
    installs exactly one version-zero baseline and then commits only the next
    monotonically increasing physical state.  Observation envelopes may be
    refreshed after restart, so current-state checks compare the physical
    digest and version rather than boot-local observation metadata.
    """

    SCHEMA_VERSION: ClassVar[str] = "m4i-plant-checkpoint-v1"
    MAX_CHECKPOINT_BYTES: ClassVar[int] = 1024 * 1024

    def __init__(
        self,
        path: Path,
        *,
        plant_key_id: str,
        model_digest: str,
        initialize: bool = False,
    ) -> None:
        self.path = path
        self.plant_key_id = self._identity("plant key ID", plant_key_id)
        self.model_digest = self._digest("model digest", model_digest)
        self._mutex = RLock()
        self._writer_lock: _LifetimeWriterLock | None = None
        self._checkpoint: PhysicalStateSnapshot | None = None
        self._unusable = False
        self._check_parent()
        lock_path = _LifetimeWriterLock.path_for(self.path)
        if initialize and (
            self.path.exists()
            or self.path.is_symlink()
            or lock_path.exists()
            or lock_path.is_symlink()
        ):
            raise PlantCheckpointError(
                "plant checkpoint artifacts already exist; refusing to initialize"
            )
        try:
            self._writer_lock = _LifetimeWriterLock(
                self.path,
                initialize=initialize,
            )
            if initialize:
                if self.path.exists() or self.path.is_symlink():
                    raise PlantCheckpointError(
                        "plant checkpoint already exists; refusing to initialize"
                    )
                self._persist(None)
            self._checkpoint = self._load()
        except _WriterLockError as exc:
            self.close()
            raise PlantCheckpointError(str(exc)) from exc
        except Exception:
            self.close()
            raise

    @property
    def writer_lock_path(self) -> Path:
        return _LifetimeWriterLock.path_for(self.path)

    def _assert_usable(self) -> None:
        if self._unusable:
            raise PlantCheckpointError(
                "plant checkpoint is unusable after an uncertain update"
            )
        writer_lock = self._writer_lock
        if writer_lock is None:
            raise PlantCheckpointError("plant checkpoint writer lock is closed")
        try:
            writer_lock.assert_held_by_current_process()
        except _WriterLockError as exc:
            raise PlantCheckpointError(str(exc)) from exc

    def close(self) -> None:
        writer_lock = self._writer_lock
        self._writer_lock = None
        if writer_lock is not None:
            writer_lock.close()

    def __enter__(self) -> Self:
        self._assert_usable()
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
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 256
            or value != value.strip()
        ):
            raise PlantCheckpointError(f"plant checkpoint {label} is invalid")
        return value

    @staticmethod
    def _digest(label: str, value: str) -> str:
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise PlantCheckpointError(f"plant checkpoint {label} is invalid")
        return value

    @staticmethod
    def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PlantCheckpointError(
                    "plant checkpoint contains a duplicate JSON key"
                )
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

    def _document(
        self,
        checkpoint: PhysicalStateSnapshot | None,
    ) -> dict[str, Any]:
        return {
            "checkpoint": (
                checkpoint.model_dump(mode="json") if checkpoint is not None else None
            ),
            "model_digest": self.model_digest,
            "plant_key_id": self.plant_key_id,
            "schema_version": self.SCHEMA_VERSION,
        }

    def _check_parent(self) -> None:
        try:
            parent_stat = self.path.parent.lstat()
        except OSError as exc:
            raise PlantCheckpointError(
                "plant checkpoint directory is unavailable"
            ) from exc
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
            raise PlantCheckpointError(
                "plant checkpoint directory must be a non-symlink directory"
            )
        if stat.S_IMODE(parent_stat.st_mode) != 0o700:
            raise PlantCheckpointError("plant checkpoint directory mode must be 0700")

    def _read(self) -> bytes:
        self._assert_usable()
        self._check_parent()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os,
            "O_NOFOLLOW",
            0,
        ) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise PlantCheckpointError(
                "plant checkpoint is missing or unavailable"
            ) from exc
        try:
            checkpoint_stat = os.fstat(descriptor)
            if not stat.S_ISREG(checkpoint_stat.st_mode):
                raise PlantCheckpointError(
                    "plant checkpoint must be a regular non-symlink file"
                )
            if stat.S_IMODE(checkpoint_stat.st_mode) != 0o600:
                raise PlantCheckpointError("plant checkpoint mode must be 0600")
            if checkpoint_stat.st_size > self.MAX_CHECKPOINT_BYTES:
                raise PlantCheckpointError("plant checkpoint exceeds its size limit")
            chunks: list[bytes] = []
            remaining = self.MAX_CHECKPOINT_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            material = b"".join(chunks)
            if len(material) > self.MAX_CHECKPOINT_BYTES:
                raise PlantCheckpointError("plant checkpoint exceeds its size limit")
            return material
        except OSError as exc:
            raise PlantCheckpointError("plant checkpoint cannot be read") from exc
        finally:
            os.close(descriptor)

    def _validate_snapshot(
        self,
        snapshot: PhysicalStateSnapshot,
    ) -> PhysicalStateSnapshot:
        try:
            validated = PhysicalStateSnapshot.model_validate_json(
                snapshot.model_dump_json(),
                strict=True,
            )
        except ValueError as exc:
            raise PlantCheckpointError("plant checkpoint snapshot is invalid") from exc
        if validated.model_digest != self.model_digest:
            raise PlantCheckpointError(
                "plant checkpoint snapshot model does not match configuration"
            )
        if not validated.verify_digest():
            raise PlantCheckpointError("plant checkpoint snapshot digest is invalid")
        if not validated.converged or validated.unsafe_state:
            raise PlantCheckpointError("plant checkpoint snapshot is not a safe solved state")
        return validated

    def _load(self) -> PhysicalStateSnapshot | None:
        material = self._read()
        try:
            parsed = json.loads(
                material.decode("utf-8", errors="strict"),
                object_pairs_hook=self._closed_object,
                parse_constant=self._reject_json_constant,
            )
        except PlantCheckpointError:
            raise
        except (UnicodeError, ValueError) as exc:
            raise PlantCheckpointError(
                "plant checkpoint is not strict UTF-8 JSON"
            ) from exc
        expected_fields = {
            "schema_version",
            "plant_key_id",
            "model_digest",
            "checkpoint",
        }
        if not isinstance(parsed, dict) or set(parsed) != expected_fields:
            raise PlantCheckpointError(
                "plant checkpoint has unexpected or missing fields"
            )
        if parsed["schema_version"] != self.SCHEMA_VERSION:
            raise PlantCheckpointError("plant checkpoint schema is unsupported")
        if (
            parsed["plant_key_id"] != self.plant_key_id
            or parsed["model_digest"] != self.model_digest
        ):
            raise PlantCheckpointError(
                "plant checkpoint identity does not match configuration"
            )
        raw_checkpoint = parsed["checkpoint"]
        checkpoint: PhysicalStateSnapshot | None
        if raw_checkpoint is None:
            checkpoint = None
        elif isinstance(raw_checkpoint, dict):
            try:
                checkpoint = PhysicalStateSnapshot.model_validate_json(
                    self._canonical_bytes(raw_checkpoint),
                    strict=True,
                )
            except ValueError as exc:
                raise PlantCheckpointError(
                    "plant checkpoint snapshot is invalid"
                ) from exc
            checkpoint = self._validate_snapshot(checkpoint)
        else:
            raise PlantCheckpointError("plant checkpoint snapshot shape is invalid")
        try:
            canonical = self._canonical_bytes(self._document(checkpoint))
        except (TypeError, ValueError) as exc:
            raise PlantCheckpointError(
                "plant checkpoint contains noncanonical values"
            ) from exc
        if material != canonical:
            raise PlantCheckpointError("plant checkpoint encoding is not canonical")
        return checkpoint

    def _persist(
        self,
        checkpoint: PhysicalStateSnapshot | None,
        *,
        before_replace: Callable[[], None] | None = None,
    ) -> None:
        self._assert_usable()
        self._check_parent()
        material = self._canonical_bytes(self._document(checkpoint))
        if len(material) > self.MAX_CHECKPOINT_BYTES:
            raise PlantCheckpointError("plant checkpoint exceeds its size limit")
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
                    raise OSError("plant checkpoint write made no progress")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            if before_replace is not None:
                before_replace()
            os.replace(temporary, self.path)
            replaced = True
            directory_descriptor = os.open(
                self.path.parent,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError as exc:
            self._unusable = True
            raise PlantCheckpointError("plant checkpoint update failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                with suppress(FileNotFoundError):
                    temporary.unlink()

    @staticmethod
    def _same_physical_state(
        left: PhysicalStateSnapshot,
        right: PhysicalStateSnapshot,
    ) -> bool:
        return (
            left.model_id == right.model_id
            and left.simulator_version == right.simulator_version
            and left.model_digest == right.model_digest
            and left.input_digest == right.input_digest
            and left.topology_digest == right.topology_digest
            and left.state_version == right.state_version
            and left.state_digest == right.state_digest
            and left.simulation_time_s == right.simulation_time_s
        )

    def current(self) -> PhysicalStateSnapshot | None:
        """Read and validate the currently durable physical checkpoint."""

        with self._mutex:
            self._checkpoint = self._load()
            return self._checkpoint

    def verify_current(
        self,
        snapshot: PhysicalStateSnapshot,
    ) -> PhysicalStateSnapshot:
        """Require the supplied live state to match the durable physical state."""

        with self._mutex:
            live = self._validate_snapshot(snapshot)
            stored = self._load()
            if stored is None:
                raise PlantCheckpointError(
                    "plant checkpoint baseline has not been installed"
                )
            if not self._same_physical_state(stored, live):
                raise PlantCheckpointError(
                    "plant checkpoint does not match the current physical state"
                )
            self._checkpoint = stored
            return stored

    def install_baseline(
        self,
        snapshot: PhysicalStateSnapshot,
    ) -> PhysicalStateSnapshot:
        """Install exactly one safe, solved version-zero baseline."""

        with self._mutex:
            baseline = self._validate_snapshot(snapshot)
            if baseline.state_version != 0 or baseline.simulation_time_s != 0.0:
                raise PlantCheckpointError(
                    "plant checkpoint baseline must be the version-zero initial state"
                )
            if self._load() is not None:
                raise PlantCheckpointError(
                    "plant checkpoint baseline is already installed"
                )
            self._persist(baseline)
            try:
                retained = self._load()
            except PlantCheckpointError:
                self._unusable = True
                raise
            if retained != baseline:
                self._unusable = True
                raise PlantCheckpointError(
                    "plant checkpoint baseline could not be verified"
                )
            self._checkpoint = retained
            return baseline

    def commit_next(
        self,
        *,
        current: PhysicalStateSnapshot,
        next_state: PhysicalStateSnapshot,
        effect_deadline: datetime | None = None,
        effect_clock: Callable[[], datetime] | None = None,
    ) -> PhysicalStateSnapshot:
        """Durably replace the current checkpoint with its exact next state."""

        if (effect_deadline is None) is not (effect_clock is None):
            raise PlantCheckpointError(
                "plant checkpoint effect deadline and clock must be configured together"
            )
        if effect_deadline is not None and (
            effect_deadline.tzinfo is None or effect_deadline.utcoffset() is None
        ):
            raise PlantCheckpointError(
                "plant checkpoint effect deadline must be timezone-aware"
            )

        def require_live_deadline() -> None:
            assert effect_deadline is not None
            assert effect_clock is not None
            try:
                evaluated_at = effect_clock()
                if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
                    raise ValueError("effect clock returned a naive datetime")
            except Exception as exc:
                raise PlantCheckpointError(
                    "plant checkpoint effect deadline check failed"
                ) from exc
            if evaluated_at >= effect_deadline:
                raise PlantCheckpointError(
                    "plant checkpoint effect deadline expired before replace"
                )

        with self._mutex:
            expected = self._validate_snapshot(current)
            candidate = self._validate_snapshot(next_state)
            stored = self._load()
            if stored is None:
                raise PlantCheckpointError(
                    "plant checkpoint baseline has not been installed"
                )
            if not self._same_physical_state(stored, expected):
                raise PlantCheckpointError(
                    "plant checkpoint changed before the next state commit"
                )
            if (
                candidate.model_id != stored.model_id
                or candidate.simulator_version != stored.simulator_version
            ):
                raise PlantCheckpointError(
                    "plant checkpoint next state changed the configured model"
                )
            if candidate.state_version != stored.state_version + 1:
                raise PlantCheckpointError(
                    "plant checkpoint next state must advance exactly one version"
                )
            if candidate.simulation_time_s <= stored.simulation_time_s:
                raise PlantCheckpointError(
                    "plant checkpoint next state must advance simulation time"
                )
            self._persist(
                candidate,
                before_replace=(
                    require_live_deadline if effect_deadline is not None else None
                ),
            )
            try:
                retained = self._load()
            except PlantCheckpointError:
                self._unusable = True
                raise
            if retained != candidate:
                self._unusable = True
                raise PlantCheckpointError(
                    "plant checkpoint next state could not be verified"
                )
            self._checkpoint = retained
            return candidate
