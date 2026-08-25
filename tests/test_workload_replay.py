from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest

import aegis_ot.workload_replay as replay_module
from aegis_ot.workload_replay import (
    DurableWorkloadReplayLedger,
    WorkloadReplayLedgerError,
)

AUDIENCE = "aegis-ot:ot-adapter"
TRUST_DOMAIN = "aegis-ot.test"
WORKLOAD_SUBJECT = "spiffe://aegis-ot.test/workload/gateway"
AUTHORITY_KEY_ID = "authority-root-0001"


def _ledger(
    path: Path,
    *,
    audience: str = AUDIENCE,
    trust_domain: str = TRUST_DOMAIN,
    workload_subject: str = WORKLOAD_SUBJECT,
    authority_key_id: str = AUTHORITY_KEY_ID,
    initialize: bool = False,
) -> DurableWorkloadReplayLedger:
    path.parent.chmod(0o700)
    return DurableWorkloadReplayLedger(
        path,
        audience=audience,
        trust_domain=trust_domain,
        workload_subject=workload_subject,
        authority_key_id=authority_key_id,
        initialize=initialize,
    )


def _empty_document() -> dict[str, Any]:
    return {
        "audience": AUDIENCE,
        "authority_key_id": AUTHORITY_KEY_ID,
        "reservations": [],
        "schema_version": "m4g-workload-replay-ledger-v1",
        "trust_domain": TRUST_DOMAIN,
        "workload_subject": WORKLOAD_SUBJECT,
    }


def _write_document(path: Path, value: Any, *, canonical: bool = True) -> None:
    path.parent.chmod(0o700)
    material = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if not canonical:
        material += "\n"
    path.write_text(material, encoding="utf-8")
    path.chmod(0o600)


def test_workload_replay_roundtrip_and_status(tmp_path: Path) -> None:
    path = tmp_path / "workload-replay.json"
    nonce = "workload-request-nonce-0001"
    digest = "a" * 64
    ledger = _ledger(path, initialize=True)

    initial_count, initial_sha256 = ledger.status()
    assert initial_count == 0
    assert len(initial_sha256) == 64
    assert ledger.reserve(nonce, digest)
    assert ledger.contains(nonce)
    count, canonical_sha256 = ledger.status()
    assert count == 1
    assert canonical_sha256 == ledger.canonical_sha256
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    ledger.close()

    reconstructed = _ledger(path)
    assert reconstructed.reservations == {nonce: digest}
    assert reconstructed.status() == (1, canonical_sha256)
    reconstructed.close()


def test_leaf_rotation_does_not_change_stable_ledger_identity(tmp_path: Path) -> None:
    """Leaf key IDs are intentionally not inputs to the workload ledger."""

    path = tmp_path / "workload-replay.json"
    first_leaf_key_id = "gateway-leaf-before-rotation"
    second_leaf_key_id = "gateway-leaf-after-rotation"
    assert first_leaf_key_id != second_leaf_key_id

    first = _ledger(path, initialize=True)
    assert first.reserve("rotation-stable-nonce-0001", "b" * 64)
    first.close()

    after_rotation = _ledger(path)
    assert after_rotation.contains("rotation-stable-nonce-0001")
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert "gateway_key_id" not in persisted
    assert "gateway_public_key_sha256" not in persisted
    assert "leaf_key_id" not in persisted
    assert persisted["workload_subject"] == WORKLOAD_SUBJECT
    after_rotation.close()


@pytest.mark.parametrize(
    ("field", "configured_value"),
    [
        ("audience", "aegis-ot:observer"),
        ("trust_domain", "other.example"),
        ("workload_subject", "spiffe://aegis-ot.test/workload/other"),
        ("authority_key_id", "authority-root-0002"),
    ],
)
def test_identity_mismatch_fails_closed(
    tmp_path: Path,
    field: str,
    configured_value: str,
) -> None:
    path = tmp_path / "workload-replay.json"
    ledger = _ledger(path, initialize=True)
    ledger.close()
    configured = {
        "audience": AUDIENCE,
        "trust_domain": TRUST_DOMAIN,
        "workload_subject": WORKLOAD_SUBJECT,
        "authority_key_id": AUTHORITY_KEY_ID,
    }
    configured[field] = configured_value

    with pytest.raises(WorkloadReplayLedgerError, match="identity does not match"):
        _ledger(path, **configured)


@pytest.mark.parametrize(
    "corruptor",
    [
        lambda value: {**value, "schema_version": "unsupported"},
        lambda value: {**value, "unexpected": True},
        lambda value: {**value, "reservations": {}},
        lambda value: {
            **value,
            "reservations": [
                {"nonce": "workload-nonce-0002", "signed_request_sha256": "c" * 64},
                {"nonce": "workload-nonce-0001", "signed_request_sha256": "d" * 64},
            ],
        },
    ],
)
def test_corrupt_ledger_shape_fails_closed(
    tmp_path: Path,
    corruptor: Any,
) -> None:
    path = tmp_path / "workload-replay.json"
    _write_document(path, corruptor(_empty_document()))

    with pytest.raises(WorkloadReplayLedgerError):
        _ledger(path)


def test_duplicate_keys_and_noncanonical_json_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "workload-replay.json"
    path.write_text(
        '{"audience":"aegis-ot:ot-adapter","audience":"aegis-ot:ot-adapter",'
        '"authority_key_id":"authority-root-0001","reservations":[],'
        '"schema_version":"m4g-workload-replay-ledger-v1",'
        '"trust_domain":"aegis-ot.test",'
        '"workload_subject":"spiffe://aegis-ot.test/workload/gateway"}',
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(WorkloadReplayLedgerError, match="duplicate key"):
        _ledger(path)

    _write_document(path, _empty_document(), canonical=False)
    with pytest.raises(WorkloadReplayLedgerError, match="not canonical"):
        _ledger(path)


def test_nonce_or_request_digest_replay_is_rejected(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "workload-replay.json", initialize=True)
    first_nonce = "workload-replay-nonce-0001"
    second_nonce = "workload-replay-nonce-0002"
    first_digest = "e" * 64

    assert ledger.reserve(first_nonce, first_digest)
    assert ledger.reserve(first_nonce, "f" * 64) is False
    assert ledger.reserve(second_nonce, first_digest) is False
    assert ledger.reservations == {first_nonce: first_digest}
    ledger.close()


def test_private_directory_and_regular_private_file_are_required(tmp_path: Path) -> None:
    path = tmp_path / "workload-replay.json"
    ledger = _ledger(path, initialize=True)
    ledger.close()

    path.chmod(0o644)
    with pytest.raises(WorkloadReplayLedgerError, match="mode must be 0600"):
        _ledger(path)

    path.chmod(0o600)
    tmp_path.chmod(0o755)
    with pytest.raises(WorkloadReplayLedgerError, match="group or other"):
        DurableWorkloadReplayLedger(
            path,
            audience=AUDIENCE,
            trust_domain=TRUST_DOMAIN,
            workload_subject=WORKLOAD_SUBJECT,
            authority_key_id=AUTHORITY_KEY_ID,
        )


def test_capacity_and_failed_replace_preserve_last_durable_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "workload-replay.json"
    ledger = _ledger(path, initialize=True)
    first_nonce = "workload-durable-nonce-0001"
    second_nonce = "workload-durable-nonce-0002"
    assert ledger.reserve(first_nonce, "1" * 64)
    before = path.read_bytes()

    monkeypatch.setattr(ledger, "MAX_RESERVATIONS", 1)
    with pytest.raises(WorkloadReplayLedgerError, match="at capacity"):
        ledger.reserve(second_nonce, "2" * 64)
    assert path.read_bytes() == before

    monkeypatch.setattr(ledger, "MAX_RESERVATIONS", 8192)

    def fail_replace(source: Path, destination: Path) -> None:
        del source, destination
        raise OSError("injected atomic replacement failure")

    monkeypatch.setattr(replay_module.os, "replace", fail_replace)
    with pytest.raises(WorkloadReplayLedgerError, match="update failed"):
        ledger.reserve(second_nonce, "2" * 64)
    assert path.read_bytes() == before
    assert not list(tmp_path.glob("*.tmp"))
    ledger.close()
