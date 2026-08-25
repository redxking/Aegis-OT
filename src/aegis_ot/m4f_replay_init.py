"""Provision the identity-bound M4f replay and probe volumes exactly once."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from .capability_plc import OrderlyRestartReplayReservations
from .transport_replay import DurableTransportReplayLedger


def _prepare_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"M4f volume path is not a directory: {path}")
    if any(path.iterdir()):
        raise RuntimeError(f"M4f volume must be empty before initialization: {path}")
    path.chmod(0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise RuntimeError(f"M4f volume mode was not set to 0700: {path}")


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


def initialize() -> dict[str, str | int | bool]:
    ledger_path = Path(
        os.getenv(
            "AEGIS_TRANSPORT_REPLAY_LEDGER_FILE",
            "/var/lib/aegis-ot/transport-replay.json",
        )
    )
    probe_directory = Path(os.getenv("AEGIS_TRANSPORT_PROBE_DIRECTORY", "/probe"))
    public_key_path = Path(os.environ["AEGIS_GATEWAY_PUBLIC_KEY_FILE"])
    gateway_key_id = os.environ["AEGIS_GATEWAY_KEY_ID"]
    transport_audience = os.getenv(
        "AEGIS_TRANSPORT_AUDIENCE",
        "aegis-ot:ot-adapter",
    )
    target_uid = int(os.getenv("AEGIS_RUNTIME_UID", "65532"))
    target_gid = int(os.getenv("AEGIS_RUNTIME_GID", "65532"))
    semantic_ledger_value = os.getenv("AEGIS_SEMANTIC_REPLAY_LEDGER_FILE")
    semantic_ledger_path = (
        Path(semantic_ledger_value) if semantic_ledger_value is not None else None
    )
    if semantic_ledger_path == ledger_path:
        raise RuntimeError("transport and semantic replay ledgers must use distinct files")

    volume_paths = [ledger_path.parent, probe_directory]
    if semantic_ledger_path is not None:
        volume_paths.append(semantic_ledger_path.parent)
    prepared_paths: list[Path] = []
    for volume_path in volume_paths:
        if volume_path not in prepared_paths:
            _prepare_directory(volume_path)
            prepared_paths.append(volume_path)
    public_key = public_key_path.read_bytes()
    if len(public_key) != 32:
        raise RuntimeError("gateway public key must contain exactly 32 raw bytes")
    public_key_sha256 = hashlib.sha256(public_key).hexdigest()
    with DurableTransportReplayLedger(
        ledger_path,
        audience=transport_audience,
        gateway_key_id=gateway_key_id,
        gateway_public_key_sha256=public_key_sha256,
        initialize=True,
    ) as ledger:
        ledger_reservations = ledger.reservation_count
        transport_writer_lock_path = ledger.writer_lock_path

    semantic_ledger_reservations: int | None = None
    semantic_writer_lock_path: Path | None = None
    if semantic_ledger_path is not None:
        with OrderlyRestartReplayReservations(
            semantic_ledger_path,
            initialize=True,
        ) as semantic_ledger:
            semantic_ledger_reservations = semantic_ledger.reservation_count
            semantic_writer_lock_path = semantic_ledger.writer_lock_path

    _assign_private_runtime_file(
        ledger_path,
        target_uid=target_uid,
        target_gid=target_gid,
        label="M4f replay ledger",
    )
    _assign_private_runtime_file(
        transport_writer_lock_path,
        target_uid=target_uid,
        target_gid=target_gid,
        label="M4f replay writer lock",
    )
    if semantic_ledger_path is not None and semantic_writer_lock_path is not None:
        _assign_private_runtime_file(
            semantic_ledger_path,
            target_uid=target_uid,
            target_gid=target_gid,
            label="M4g semantic replay ledger",
        )
        _assign_private_runtime_file(
            semantic_writer_lock_path,
            target_uid=target_uid,
            target_gid=target_gid,
            label="M4g semantic replay writer lock",
        )
    os.chown(probe_directory, target_uid, target_gid)
    probe_stat = probe_directory.stat()
    if probe_stat.st_uid != target_uid or probe_stat.st_gid != target_gid:
        raise RuntimeError("M4f probe volume ownership was not assigned to the runtime")
    ledger_directories = [ledger_path.parent]
    if (
        semantic_ledger_path is not None
        and semantic_ledger_path.parent not in ledger_directories
    ):
        ledger_directories.append(semantic_ledger_path.parent)
    for ledger_directory in ledger_directories:
        os.chown(ledger_directory, target_uid, target_gid)
        ledger_directory_stat = ledger_directory.stat()
        if (
            ledger_directory_stat.st_uid != target_uid
            or ledger_directory_stat.st_gid != target_gid
        ):
            label = (
                "M4f replay volume"
                if ledger_directory == ledger_path.parent
                else "M4g semantic replay volume"
            )
            raise RuntimeError(f"{label} ownership was not assigned to the runtime")
    result: dict[str, str | int | bool] = {
        "schema_version": "m4f-replay-volume-initialization-v1",
        "gateway_key_id": gateway_key_id,
        "gateway_public_key_sha256": public_key_sha256,
        "ledger_reservations": ledger_reservations,
        "ledger_mode": "0600",
        "directory_mode": "0700",
        "runtime_uid": target_uid,
        "runtime_gid": target_gid,
    }
    if semantic_ledger_reservations is not None:
        result.update(
            {
                "semantic_ledger_initialized": True,
                "semantic_ledger_reservations": semantic_ledger_reservations,
                "semantic_ledger_mode": "0600",
            }
        )
    return result


def main() -> None:
    print(json.dumps(initialize(), sort_keys=True))


if __name__ == "__main__":
    main()
