from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis_ot.m4g_replay_init as replay_init
from aegis_ot.segmented_capability_models import OT_CAPABILITY_AUDIENCE
from aegis_ot.semantic_replay import OrderlyRestartReplayReservations
from aegis_ot.workload_identity import workload_key_id
from aegis_ot.workload_replay import DurableWorkloadReplayLedger


def _configure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, str, bytes]:
    replay_directory = tmp_path / "replay"
    replay_directory.mkdir()
    workload_path = replay_directory / "workload-replay.json"
    semantic_path = replay_directory / "semantic-replay.json"
    authority = Ed25519PrivateKey.generate()
    authority_public = authority.public_key()
    authority_public_bytes = authority_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    authority_public_path = tmp_path / "authority.public"
    authority_public_path.write_bytes(authority_public_bytes)
    authority_key_id = workload_key_id(authority_public)

    monkeypatch.setenv("AEGIS_WORKLOAD_REPLAY_LEDGER_FILE", str(workload_path))
    monkeypatch.setenv("AEGIS_SEMANTIC_REPLAY_LEDGER_FILE", str(semantic_path))
    monkeypatch.setenv(
        "AEGIS_WORKLOAD_TRUST_ROOT_PUBLIC_KEY_FILE",
        str(authority_public_path),
    )
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID", authority_key_id)
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_DOMAIN", "aegis-ot.test")
    monkeypatch.setenv("AEGIS_GATEWAY_WORKLOAD_SUBJECT", "gateway/control-1")
    monkeypatch.setenv("AEGIS_RUNTIME_UID", str(os.getuid()))
    monkeypatch.setenv("AEGIS_RUNTIME_GID", str(os.getgid()))
    monkeypatch.delenv(
        "AEGIS_WORKLOAD_TRUST_ROOT_PRIVATE_KEY_FILE",
        raising=False,
    )
    return workload_path, semantic_path, authority_key_id, authority_public_bytes


def test_initializer_creates_private_identity_bound_ledgers_without_root_private_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workload_path, semantic_path, authority_key_id, authority_public_bytes = _configure(
        tmp_path,
        monkeypatch,
    )

    result = replay_init.initialize()

    assert result == {
        "schema_version": "m4g-replay-volume-initialization-v1",
        "workload_replay_audience": OT_CAPABILITY_AUDIENCE,
        "workload_trust_domain": "aegis-ot.test",
        "gateway_workload_subject": "gateway/control-1",
        "authority_key_id": authority_key_id,
        "authority_public_key_sha256": authority_key_id.removeprefix("ed25519:"),
        "workload_replay_reservations": 0,
        "semantic_replay_reservations": 0,
        "workload_ledger_mode": "0600",
        "semantic_ledger_mode": "0600",
        "directory_mode": "0700",
        "runtime_uid": os.getuid(),
        "runtime_gid": os.getgid(),
    }
    assert authority_public_bytes.hex() not in json.dumps(result)
    assert "private" not in json.dumps(result).lower()

    with DurableWorkloadReplayLedger(
        workload_path,
        audience=OT_CAPABILITY_AUDIENCE,
        trust_domain="aegis-ot.test",
        workload_subject="gateway/control-1",
        authority_key_id=authority_key_id,
    ) as workload_ledger:
        assert workload_ledger.reservation_count == 0
    with OrderlyRestartReplayReservations(semantic_path) as semantic_ledger:
        assert semantic_ledger.reservation_count == 0

    for path in (
        workload_path,
        workload_path.with_name(f".{workload_path.name}.writer.lock"),
        semantic_path,
        semantic_path.with_name(f".{semantic_path.name}.writer.lock"),
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_uid == os.getuid()
        assert path.stat().st_gid == os.getgid()
    assert stat.S_IMODE(workload_path.parent.stat().st_mode) == 0o700


def test_initializer_uses_lightweight_semantic_replay_module() -> None:
    assert OrderlyRestartReplayReservations.__module__ == "aegis_ot.semantic_replay"


@pytest.mark.parametrize("existing_ledger", ["workload", "semantic"])
def test_initializer_refuses_any_existing_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_ledger: str,
) -> None:
    workload_path, semantic_path, _, _ = _configure(tmp_path, monkeypatch)
    path = workload_path if existing_ledger == "workload" else semantic_path
    path.write_text("existing", encoding="utf-8")

    with pytest.raises(RuntimeError, match="already exists; refusing to initialize"):
        replay_init.initialize()


def test_initializer_rejects_authority_key_id_not_derived_from_public_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID", "ed25519:" + "0" * 64)

    with pytest.raises(RuntimeError, match="does not match its public key"):
        replay_init.initialize()


def test_initializer_rejects_invalid_authority_public_key_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    public_path = tmp_path / "invalid-authority.public"
    public_path.write_bytes(b"short")
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_ROOT_PUBLIC_KEY_FILE", str(public_path))

    with pytest.raises(RuntimeError, match="exactly 32 raw bytes"):
        replay_init.initialize()


def test_initializer_rejects_same_file_for_both_replay_domains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workload_path, _, _, _ = _configure(tmp_path, monkeypatch)
    monkeypatch.setenv("AEGIS_SEMANTIC_REPLAY_LEDGER_FILE", str(workload_path))

    with pytest.raises(RuntimeError, match="must use distinct files"):
        replay_init.initialize()


def test_main_outputs_safe_sorted_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = {
        "schema_version": "m4g-replay-volume-initialization-v1",
        "workload_replay_reservations": 0,
    }
    monkeypatch.setattr(replay_init, "initialize", lambda: expected)

    replay_init.main()

    output = capsys.readouterr().out
    assert output == json.dumps(expected, sort_keys=True) + "\n"
