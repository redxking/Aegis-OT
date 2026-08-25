from __future__ import annotations

import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

import aegis_ot.transport_replay as replay_module
from aegis_ot.transport_replay import (
    DurableTransportReplayLedger,
    TransportReplayLedgerError,
)

AUDIENCE = "aegis-ot:ot-adapter"
KEY_ID = "gateway-test-key"
PUBLIC_KEY_SHA256 = "a" * 64


def _ledger(path: Path, *, initialize: bool = False) -> DurableTransportReplayLedger:
    path.parent.chmod(0o700)
    return DurableTransportReplayLedger(
        path,
        audience=AUDIENCE,
        gateway_key_id=KEY_ID,
        gateway_public_key_sha256=PUBLIC_KEY_SHA256,
        initialize=initialize,
    )


def _write_ledger(path: Path, value: Any) -> None:
    path.parent.chmod(0o700)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    path.chmod(0o600)


def _empty_document() -> dict[str, Any]:
    return {
        "audience": AUDIENCE,
        "gateway_key_id": KEY_ID,
        "gateway_public_key_sha256": PUBLIC_KEY_SHA256,
        "reservations": [],
        "schema_version": "m4f-transport-replay-ledger-v1",
    }


def test_durable_transport_reservation_survives_reconstruction(tmp_path: Path) -> None:
    path = tmp_path / "transport-replay.json"
    nonce = "durable-transport-nonce-0001"
    request_digest = "b" * 64
    ledger = _ledger(path, initialize=True)

    assert ledger.reserve(nonce, request_digest)
    assert not ledger.reserve(nonce, request_digest)
    assert ledger.reservation_count == 1
    reconstructed = _ledger(path)
    assert reconstructed.contains(nonce)
    assert reconstructed.reserve(nonce, request_digest) is False
    assert reconstructed.reservations == {nonce: request_digest}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes() == json.dumps(
        {
            **_empty_document(),
            "reservations": [
                {"nonce": nonce, "signed_request_sha256": request_digest}
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_concurrent_transport_reservation_succeeds_once(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "transport-replay.json", initialize=True)
    nonce = "concurrent-transport-nonce-0001"
    request_digest = "c" * 64
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(lambda _: ledger.reserve(nonce, request_digest), range(8))
        )
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 7
    assert ledger.reservation_count == 1


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: [],
        lambda value: {key: item for key, item in value.items() if key != "audience"},
        lambda value: {**value, "extra": True},
        lambda value: {**value, "schema_version": "wrong"},
        lambda value: {**value, "audience": "wrong"},
        lambda value: {**value, "gateway_key_id": "wrong"},
        lambda value: {**value, "gateway_public_key_sha256": "f" * 64},
        lambda value: {**value, "reservations": {}},
        lambda value: {
            **value,
            "reservations": [{"nonce": "short", "signed_request_sha256": "b" * 64}],
        },
        lambda value: {
            **value,
            "reservations": [
                {"nonce": "nonce-00000000000002", "signed_request_sha256": "b" * 64},
                {"nonce": "nonce-00000000000001", "signed_request_sha256": "c" * 64},
            ],
        },
        lambda value: {
            **value,
            "reservations": [
                {"nonce": "nonce-00000000000001", "signed_request_sha256": "b" * 64},
                {"nonce": "nonce-00000000000002", "signed_request_sha256": "b" * 64},
            ],
        },
    ],
)
def test_loader_rejects_invalid_shapes_and_identity(
    tmp_path: Path,
    mutator: Any,
) -> None:
    path = tmp_path / "transport-replay.json"
    _write_ledger(path, mutator(_empty_document()))
    with pytest.raises(TransportReplayLedgerError):
        _ledger(path)


def test_loader_rejects_duplicate_keys_and_noncanonical_json(tmp_path: Path) -> None:
    path = tmp_path / "transport-replay.json"
    path.write_text(
        '{"audience":"aegis-ot:ot-adapter","audience":"aegis-ot:ot-adapter",'
        '"gateway_key_id":"gateway-test-key",'
        f'"gateway_public_key_sha256":"{PUBLIC_KEY_SHA256}",'
        '"reservations":[],"schema_version":"m4f-transport-replay-ledger-v1"}',
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(TransportReplayLedgerError, match="duplicate key"):
        _ledger(path)

    _write_ledger(path, _empty_document())
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(TransportReplayLedgerError, match="not canonical"):
        _ledger(path)


def test_missing_symlink_mode_and_oversize_fail_closed(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(TransportReplayLedgerError, match="missing or unavailable"):
        _ledger(missing)

    target = tmp_path / "target.json"
    _write_ledger(target, _empty_document())
    link = tmp_path / "transport-replay.json"
    link.symlink_to(target)
    with pytest.raises(TransportReplayLedgerError, match="missing or unavailable"):
        _ledger(link)

    target.chmod(0o644)
    with pytest.raises(TransportReplayLedgerError, match="0600"):
        _ledger(target)

    oversize = tmp_path / "oversize.json"
    oversize.write_bytes(b" " * (DurableTransportReplayLedger.MAX_LEDGER_BYTES + 1))
    oversize.chmod(0o600)
    with pytest.raises(TransportReplayLedgerError, match="size limit"):
        _ledger(oversize)


def test_insecure_or_missing_parent_and_reinitialization_are_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "transport-replay.json"
    _ledger(path, initialize=True)
    with pytest.raises(TransportReplayLedgerError, match="already exists"):
        _ledger(path, initialize=True)

    tmp_path.chmod(0o755)
    with pytest.raises(TransportReplayLedgerError, match="group or other"):
        DurableTransportReplayLedger(
            path,
            audience=AUDIENCE,
            gateway_key_id=KEY_ID,
            gateway_public_key_sha256=PUBLIC_KEY_SHA256,
        )

    absent_parent = tmp_path / "absent" / "ledger.json"
    with pytest.raises(TransportReplayLedgerError, match="directory is unavailable"):
        DurableTransportReplayLedger(
            absent_parent,
            audience=AUDIENCE,
            gateway_key_id=KEY_ID,
            gateway_public_key_sha256=PUBLIC_KEY_SHA256,
        )


def test_failed_pre_replace_update_preserves_prior_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "transport-replay.json"
    ledger = _ledger(path, initialize=True)
    first = "transport-nonce-first-000001"
    second = "transport-nonce-second-00001"
    assert ledger.reserve(first, "b" * 64)
    before = path.read_bytes()

    def fail_replace(source: Path, destination: Path) -> None:
        del source, destination
        raise OSError("injected replace failure")

    monkeypatch.setattr(replay_module.os, "replace", fail_replace)
    with pytest.raises(TransportReplayLedgerError, match="update failed"):
        ledger.reserve(second, "c" * 64)
    assert path.read_bytes() == before
    assert _ledger(path).reservations == {first: "b" * 64}


def test_post_replace_directory_fsync_failure_leaves_valid_new_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "transport-replay.json"
    ledger = _ledger(path, initialize=True)
    first = "transport-nonce-first-000001"
    second = "transport-nonce-second-00001"
    assert ledger.reserve(first, "b" * 64)
    real_fsync = replay_module.os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(replay_module.os, "fsync", fail_directory_fsync)
    with pytest.raises(TransportReplayLedgerError, match="update failed"):
        ledger.reserve(second, "c" * 64)
    assert _ledger(path).reservations == {first: "b" * 64, second: "c" * 64}


def test_capacity_is_checked_before_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "transport-replay.json"
    ledger = _ledger(path, initialize=True)
    first = "transport-nonce-first-000001"
    second = "transport-nonce-second-00001"
    assert ledger.reserve(first, "b" * 64)
    before = path.read_bytes()
    monkeypatch.setattr(ledger, "MAX_RESERVATIONS", 1)
    with pytest.raises(TransportReplayLedgerError, match="at capacity"):
        ledger.reserve(second, "c" * 64)
    assert path.read_bytes() == before


def test_transport_nonce_and_digest_are_bounded(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "transport-replay.json", initialize=True)
    with pytest.raises(TransportReplayLedgerError, match="nonce length"):
        ledger.reserve("short", "b" * 64)
    with pytest.raises(TransportReplayLedgerError, match="nonce length"):
        ledger.reserve("x" * 257, "b" * 64)
    with pytest.raises(TransportReplayLedgerError, match="digest"):
        ledger.reserve("transport-nonce-0001", "not-a-digest")
