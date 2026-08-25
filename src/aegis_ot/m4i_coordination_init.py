"""Provision three isolated M4i state artifacts as one-shot state."""

from __future__ import annotations

import json
import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .coordination_journal import (
    DurableEffectCoordinationJournal,
    DurableGatewayCoordinationJournal,
)
from .pandapower_plant import PandapowerCigreMVPlant
from .plant_checkpoint import DurablePlantCheckpointStore


@dataclass(frozen=True)
class _StateArtifactDefinition:
    label: str
    path: Path
    target_uid: int
    target_gid: int
    kind: str


@dataclass(frozen=True)
class _JournalDefinition(_StateArtifactDefinition):
    owner_subject: str


@dataclass(frozen=True)
class _PlantCheckpointDefinition(_StateArtifactDefinition):
    plant_key_id: str
    model_digest: str


def _required_environment(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"required M4i coordination setting is missing: {name}")
    return value


def _runtime_id(name: str) -> int:
    try:
        value = int(_required_environment(name))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < 0:
        raise RuntimeError(f"{name} must not be negative")
    return value


def _prepare_empty_directory(path: Path, *, label: str) -> None:
    try:
        directory_stat = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} directory is unavailable: {path}") from exc
    if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
        raise RuntimeError(f"{label} path must be a non-symlink directory: {path}")
    try:
        populated = any(path.iterdir())
    except OSError as exc:
        raise RuntimeError(f"{label} directory cannot be inspected: {path}") from exc
    if populated:
        raise RuntimeError(f"{label} directory must be empty before initialization: {path}")
    path.chmod(0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise RuntimeError(f"{label} directory mode was not set to 0700: {path}")


def _assign_runtime_file(
    path: Path,
    *,
    target_uid: int,
    target_gid: int,
    label: str,
) -> None:
    # Set the mode while the root initializer owns the inode. The Compose
    # boundary grants CAP_CHOWN but intentionally does not grant CAP_FOWNER.
    path.chmod(0o600)
    os.chown(path, target_uid, target_gid)
    file_stat = path.stat()
    if file_stat.st_uid != target_uid or file_stat.st_gid != target_gid:
        raise RuntimeError(f"{label} ownership was not assigned to its runtime")
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise RuntimeError(f"{label} mode was not set to 0600")


def _assign_runtime_directory(
    path: Path,
    *,
    target_uid: int,
    target_gid: int,
    label: str,
) -> None:
    path.chmod(0o700)
    os.chown(path, target_uid, target_gid)
    directory_stat = path.stat()
    if directory_stat.st_uid != target_uid or directory_stat.st_gid != target_gid:
        raise RuntimeError(f"{label} directory ownership was not assigned to its runtime")
    if stat.S_IMODE(directory_stat.st_mode) != 0o700:
        raise RuntimeError(f"{label} directory mode was not preserved as 0700")


def _definitions() -> tuple[
    _JournalDefinition,
    _JournalDefinition,
    _PlantCheckpointDefinition,
]:
    gateway = _JournalDefinition(
        label="M4i gateway coordination journal",
        path=Path(_required_environment("AEGIS_GATEWAY_COORDINATION_JOURNAL_FILE")),
        owner_subject=_required_environment("AEGIS_GATEWAY_WORKLOAD_SUBJECT"),
        target_uid=_runtime_id("AEGIS_GATEWAY_RUNTIME_UID"),
        target_gid=_runtime_id("AEGIS_GATEWAY_RUNTIME_GID"),
        kind="gateway",
    )
    ot = _JournalDefinition(
        label="M4i OT coordination journal",
        path=Path(_required_environment("AEGIS_OT_COORDINATION_JOURNAL_FILE")),
        owner_subject=_required_environment("AEGIS_OT_WORKLOAD_SUBJECT"),
        target_uid=_runtime_id("AEGIS_OT_RUNTIME_UID"),
        target_gid=_runtime_id("AEGIS_OT_RUNTIME_GID"),
        kind="effect_coordinator",
    )
    plant_path = Path(_required_environment("AEGIS_PLANT_CHECKPOINT_FILE"))
    plant_key_id = _required_environment("AEGIS_PLANT_KEY_ID")
    plant_runtime_uid = _runtime_id("AEGIS_PLANT_RUNTIME_UID")
    plant_runtime_gid = _runtime_id("AEGIS_PLANT_RUNTIME_GID")
    plant = _PlantCheckpointDefinition(
        label="M4i plant checkpoint",
        path=plant_path,
        plant_key_id=plant_key_id,
        model_digest=PandapowerCigreMVPlant().model_digest,
        target_uid=plant_runtime_uid,
        target_gid=plant_runtime_gid,
        kind="plant_checkpoint",
    )
    return gateway, ot, plant


def _require_isolated_targets(
    definitions: tuple[_StateArtifactDefinition, ...],
) -> None:
    resolved_paths = tuple(definition.path.resolve(strict=False) for definition in definitions)
    if len(set(resolved_paths)) != len(resolved_paths):
        raise RuntimeError("M4i state artifacts must use distinct files")
    resolved_directories = tuple(path.parent for path in resolved_paths)
    if len(set(resolved_directories)) != len(resolved_directories):
        raise RuntimeError("M4i state artifacts must use distinct directories")
    if set(resolved_paths) & set(resolved_directories):
        raise RuntimeError("M4i state artifact files and directories must not overlap")
    for definition in definitions:
        if definition.path.exists() or definition.path.is_symlink():
            raise RuntimeError(f"{definition.label} already exists; refusing to initialize")


def _remove_initialized_artifacts(
    definitions: tuple[_StateArtifactDefinition, ...],
) -> None:
    for definition in definitions:
        # A late failure can occur after the directory was transferred to the
        # runtime account. CAP_CHOWN is sufficient to recover ownership before
        # cleanup even though the initializer intentionally lacks CAP_DAC_OVERRIDE.
        with suppress(OSError):
            os.chown(definition.path.parent, os.geteuid(), os.getegid())
            definition.path.parent.chmod(0o700)
        lock_path = definition.path.with_name(f".{definition.path.name}.writer.lock")
        for path in (definition.path, lock_path):
            with suppress(OSError):
                path.unlink()


def initialize() -> dict[str, str | int]:
    """Create closed, empty gateway, OT, and plant state without secret access."""

    gateway, ot, plant = _definitions()
    definitions: tuple[_StateArtifactDefinition, ...] = (gateway, ot, plant)
    _require_isolated_targets(definitions)
    for definition in definitions:
        _prepare_empty_directory(definition.path.parent, label=definition.label)

    lock_paths: dict[str, Path] = {}
    try:
        with DurableGatewayCoordinationJournal(
            gateway.path,
            owner_subject=gateway.owner_subject,
            initialize=True,
        ) as gateway_journal:
            lock_paths[gateway.kind] = gateway_journal.writer_lock_path
        with DurableEffectCoordinationJournal(
            ot.path,
            owner_subject=ot.owner_subject,
            initialize=True,
        ) as ot_journal:
            lock_paths[ot.kind] = ot_journal.writer_lock_path
        with DurablePlantCheckpointStore(
            plant.path,
            plant_key_id=plant.plant_key_id,
            model_digest=plant.model_digest,
            initialize=True,
        ) as plant_checkpoint:
            lock_paths[plant.kind] = plant_checkpoint.writer_lock_path
        for definition in definitions:
            for path, suffix in (
                (definition.path, "state file"),
                (lock_paths[definition.kind], "writer lock"),
            ):
                _assign_runtime_file(
                    path,
                    target_uid=definition.target_uid,
                    target_gid=definition.target_gid,
                    label=f"{definition.label} {suffix}",
                )
        for definition in definitions:
            _assign_runtime_directory(
                definition.path.parent,
                target_uid=definition.target_uid,
                target_gid=definition.target_gid,
                label=definition.label,
            )
    except Exception:
        _remove_initialized_artifacts(definitions)
        raise

    return {
        "schema_version": "m4i-coordination-volume-initialization-v2",
        "state_artifact_count": 3,
        "gateway_journal_file": str(gateway.path),
        "gateway_journal_role": gateway.kind,
        "gateway_owner_subject": gateway.owner_subject,
        "gateway_runtime_uid": gateway.target_uid,
        "gateway_runtime_gid": gateway.target_gid,
        "ot_journal_file": str(ot.path),
        "ot_journal_role": ot.kind,
        "ot_owner_subject": ot.owner_subject,
        "ot_runtime_uid": ot.target_uid,
        "ot_runtime_gid": ot.target_gid,
        "plant_checkpoint_file": str(plant.path),
        "plant_checkpoint_role": plant.kind,
        "plant_key_id": plant.plant_key_id,
        "plant_model_digest": plant.model_digest,
        "plant_runtime_uid": plant.target_uid,
        "plant_runtime_gid": plant.target_gid,
        "directory_mode": "0700",
        "artifact_mode": "0600",
        "secrets_consumed": 0,
    }


def main() -> None:
    print(json.dumps(initialize(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
