from __future__ import annotations

import hashlib
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_ot.lab import nominal_state
from aegis_ot.m4e_transport_probe import _execution_request
from aegis_ot.m4f_replay_init import initialize
from aegis_ot.m4f_transport_probe import _load_exact_request, _write_exact_request
from aegis_ot.segmented_runtime import SignedSegmentedExecutionRequest, _sha256
from aegis_ot.transport_replay import DurableTransportReplayLedger


def test_m4f_volume_initializer_provisions_identity_bound_private_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_directory = tmp_path / "ledger"
    probe_directory = tmp_path / "probe"
    ledger_directory.mkdir()
    probe_directory.mkdir()
    gateway_private = Ed25519PrivateKey.generate()
    gateway_public = gateway_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_path = tmp_path / "gateway.public"
    public_path.write_bytes(gateway_public)
    ledger_path = ledger_directory / "transport-replay.json"
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_LEDGER_FILE", str(ledger_path))
    monkeypatch.setenv("AEGIS_TRANSPORT_PROBE_DIRECTORY", str(probe_directory))
    monkeypatch.setenv("AEGIS_GATEWAY_PUBLIC_KEY_FILE", str(public_path))
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-test-key")
    monkeypatch.setenv("AEGIS_RUNTIME_UID", str(os.getuid()))
    monkeypatch.setenv("AEGIS_RUNTIME_GID", str(os.getgid()))

    result = initialize()

    assert result["ledger_reservations"] == 0
    assert stat.S_IMODE(ledger_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(probe_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(ledger_path.stat().st_mode) == 0o600
    ledger = DurableTransportReplayLedger(
        ledger_path,
        audience="aegis-ot:ot-adapter",
        gateway_key_id="gateway-test-key",
        gateway_public_key_sha256=hashlib.sha256(gateway_public).hexdigest(),
    )
    assert ledger.reservation_count == 0
    with pytest.raises(RuntimeError, match="must be empty"):
        initialize()


def test_exact_signed_request_probe_file_is_canonical_private_and_exclusive(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    gateway_private = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    request = SignedSegmentedExecutionRequest(
        request=_execution_request(nominal_state(observed_at=now)),
        gateway_key_id="gateway-test-key",
        transport_nonce=str(uuid4()),
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
    ).signed(gateway_private)
    path = tmp_path / "exact-signed-request.json"

    _write_exact_request(path, request)

    loaded = _load_exact_request(path)
    assert _sha256(loaded) == _sha256(request)
    assert loaded.verify(gateway_private.public_key())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(RuntimeError, match="already exists"):
        _write_exact_request(path, request)
