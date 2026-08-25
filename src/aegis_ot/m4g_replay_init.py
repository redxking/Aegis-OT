"""Provision M4g workload-bound transport and semantic replay state once."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .capability_plc import OrderlyRestartReplayReservations
from .segmented_capability_models import OT_CAPABILITY_AUDIENCE
from .workload_identity import workload_key_id
from .workload_replay import DurableWorkloadReplayLedger


def _required_environment(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"required M4g replay setting is missing: {name}")
    return value


def _runtime_identity() -> tuple[int, int]:
    try:
        target_uid = int(os.getenv("AEGIS_RUNTIME_UID", "65532"))
        target_gid = int(os.getenv("AEGIS_RUNTIME_GID", "65532"))
    except ValueError as exc:
        raise RuntimeError("M4g runtime UID and GID must be integers") from exc
    if target_uid < 0 or target_gid < 0:
        raise RuntimeError("M4g runtime UID and GID must not be negative")
    return target_uid, target_gid


def _prepare_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"M4g replay volume path is not a directory: {path}")
    if any(path.iterdir()):
        raise RuntimeError(f"M4g replay volume must be empty before initialization: {path}")
    path.chmod(0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise RuntimeError(f"M4g replay volume mode was not set to 0700: {path}")


def _assign_private_runtime_file(
    path: Path,
    *,
    target_uid: int,
    target_gid: int,
    label: str,
) -> None:
    os.chown(path, target_uid, target_gid)
    file_stat = path.stat()
    if file_stat.st_uid != target_uid or file_stat.st_gid != target_gid:
        raise RuntimeError(f"{label} ownership was not assigned to the runtime")
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise RuntimeError(f"{label} mode was not set to 0600")


def _assign_private_runtime_directory(
    path: Path,
    *,
    target_uid: int,
    target_gid: int,
) -> None:
    os.chown(path, target_uid, target_gid)
    directory_stat = path.stat()
    if directory_stat.st_uid != target_uid or directory_stat.st_gid != target_gid:
        raise RuntimeError(
            "M4g replay volume ownership was not assigned to the runtime"
        )
    if stat.S_IMODE(directory_stat.st_mode) != 0o700:
        raise RuntimeError("M4g replay volume mode was not preserved as 0700")


def _authority_identity() -> tuple[str, str]:
    public_key_path = Path(
        _required_environment("AEGIS_WORKLOAD_TRUST_ROOT_PUBLIC_KEY_FILE")
    )
    try:
        public_key_bytes = public_key_path.read_bytes()
    except OSError as exc:
        raise RuntimeError("M4g workload authority public key is unavailable") from exc
    if len(public_key_bytes) != 32:
        raise RuntimeError(
            "M4g workload authority public key must contain exactly 32 raw bytes"
        )
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError as exc:
        raise RuntimeError("M4g workload authority public key is invalid") from exc

    derived_key_id = workload_key_id(public_key)
    configured_key_id = _required_environment("AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID")
    if configured_key_id != derived_key_id:
        raise RuntimeError(
            "configured workload authority key ID does not match its public key"
        )
    return derived_key_id, hashlib.sha256(public_key_bytes).hexdigest()


def initialize() -> dict[str, str | int]:
    """Initialize both M4g ledgers without authority private-key access."""

    workload_ledger_path = Path(
        _required_environment("AEGIS_WORKLOAD_REPLAY_LEDGER_FILE")
    )
    semantic_ledger_path = Path(
        _required_environment("AEGIS_SEMANTIC_REPLAY_LEDGER_FILE")
    )
    if workload_ledger_path == semantic_ledger_path:
        raise RuntimeError("workload and semantic replay ledgers must use distinct files")
    for label, path in (
        ("workload replay ledger", workload_ledger_path),
        ("semantic replay ledger", semantic_ledger_path),
    ):
        if path.exists() or path.is_symlink():
            raise RuntimeError(f"{label} already exists; refusing to initialize")

    target_uid, target_gid = _runtime_identity()
    trust_domain = _required_environment("AEGIS_WORKLOAD_TRUST_DOMAIN")
    gateway_subject = _required_environment("AEGIS_GATEWAY_WORKLOAD_SUBJECT")
    authority_key_id, authority_public_key_sha256 = _authority_identity()

    prepared_directories: list[Path] = []
    for directory in (workload_ledger_path.parent, semantic_ledger_path.parent):
        if directory not in prepared_directories:
            _prepare_directory(directory)
            prepared_directories.append(directory)

    with DurableWorkloadReplayLedger(
        workload_ledger_path,
        audience=OT_CAPABILITY_AUDIENCE,
        trust_domain=trust_domain,
        workload_subject=gateway_subject,
        authority_key_id=authority_key_id,
        initialize=True,
    ) as workload_ledger:
        workload_reservations = workload_ledger.reservation_count
        workload_writer_lock_path = workload_ledger.writer_lock_path

    with OrderlyRestartReplayReservations(
        semantic_ledger_path,
        initialize=True,
    ) as semantic_ledger:
        semantic_reservations = semantic_ledger.reservation_count
        semantic_writer_lock_path = semantic_ledger.writer_lock_path

    for path, label in (
        (workload_ledger_path, "M4g workload replay ledger"),
        (workload_writer_lock_path, "M4g workload replay writer lock"),
        (semantic_ledger_path, "M4g semantic replay ledger"),
        (semantic_writer_lock_path, "M4g semantic replay writer lock"),
    ):
        _assign_private_runtime_file(
            path,
            target_uid=target_uid,
            target_gid=target_gid,
            label=label,
        )
    for directory in prepared_directories:
        _assign_private_runtime_directory(
            directory,
            target_uid=target_uid,
            target_gid=target_gid,
        )

    return {
        "schema_version": "m4g-replay-volume-initialization-v1",
        "workload_replay_audience": OT_CAPABILITY_AUDIENCE,
        "workload_trust_domain": trust_domain,
        "gateway_workload_subject": gateway_subject,
        "authority_key_id": authority_key_id,
        "authority_public_key_sha256": authority_public_key_sha256,
        "workload_replay_reservations": workload_reservations,
        "semantic_replay_reservations": semantic_reservations,
        "workload_ledger_mode": "0600",
        "semantic_ledger_mode": "0600",
        "directory_mode": "0700",
        "runtime_uid": target_uid,
        "runtime_gid": target_gid,
    }


def main() -> None:
    print(json.dumps(initialize(), sort_keys=True))


if __name__ == "__main__":
    main()
