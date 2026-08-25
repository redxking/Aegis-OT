"""Provision the identity-bound M4f replay and probe volumes exactly once."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from .transport_replay import DurableTransportReplayLedger


def _prepare_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"M4f volume path is not a directory: {path}")
    if any(path.iterdir()):
        raise RuntimeError(f"M4f volume must be empty before initialization: {path}")
    path.chmod(0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise RuntimeError(f"M4f volume mode was not set to 0700: {path}")


def initialize() -> dict[str, str | int]:
    ledger_path = Path(
        os.getenv(
            "AEGIS_TRANSPORT_REPLAY_LEDGER_FILE",
            "/var/lib/aegis-ot/transport-replay.json",
        )
    )
    probe_directory = Path(os.getenv("AEGIS_TRANSPORT_PROBE_DIRECTORY", "/probe"))
    public_key_path = Path(os.environ["AEGIS_GATEWAY_PUBLIC_KEY_FILE"])
    gateway_key_id = os.environ["AEGIS_GATEWAY_KEY_ID"]
    target_uid = int(os.getenv("AEGIS_RUNTIME_UID", "65532"))
    target_gid = int(os.getenv("AEGIS_RUNTIME_GID", "65532"))

    _prepare_directory(ledger_path.parent)
    _prepare_directory(probe_directory)
    public_key = public_key_path.read_bytes()
    if len(public_key) != 32:
        raise RuntimeError("gateway public key must contain exactly 32 raw bytes")
    public_key_sha256 = hashlib.sha256(public_key).hexdigest()
    ledger = DurableTransportReplayLedger(
        ledger_path,
        audience="aegis-ot:ot-adapter",
        gateway_key_id=gateway_key_id,
        gateway_public_key_sha256=public_key_sha256,
        initialize=True,
    )
    ledger_reservations = ledger.reservation_count
    os.chown(ledger_path, target_uid, target_gid)
    ledger_stat = ledger_path.stat()
    if ledger_stat.st_uid != target_uid or ledger_stat.st_gid != target_gid:
        raise RuntimeError("M4f replay ledger ownership was not assigned to the runtime")
    if stat.S_IMODE(ledger_stat.st_mode) != 0o600:
        raise RuntimeError("M4f replay ledger mode was not set to 0600")
    os.chown(probe_directory, target_uid, target_gid)
    probe_stat = probe_directory.stat()
    if probe_stat.st_uid != target_uid or probe_stat.st_gid != target_gid:
        raise RuntimeError("M4f probe volume ownership was not assigned to the runtime")
    os.chown(ledger_path.parent, target_uid, target_gid)
    ledger_directory_stat = ledger_path.parent.stat()
    if (
        ledger_directory_stat.st_uid != target_uid
        or ledger_directory_stat.st_gid != target_gid
    ):
        raise RuntimeError("M4f replay volume ownership was not assigned to the runtime")
    return {
        "schema_version": "m4f-replay-volume-initialization-v1",
        "gateway_key_id": gateway_key_id,
        "gateway_public_key_sha256": public_key_sha256,
        "ledger_reservations": ledger_reservations,
        "ledger_mode": "0600",
        "directory_mode": "0700",
        "runtime_uid": target_uid,
        "runtime_gid": target_gid,
    }


def main() -> None:
    print(json.dumps(initialize(), sort_keys=True))


if __name__ == "__main__":
    main()
