from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_ot.capability_plc import OrderlyRestartReplayReservations
from aegis_ot.m4f_replay_init import initialize
from aegis_ot.segmented_capability_models import OT_CAPABILITY_AUDIENCE
from aegis_ot.transport_replay import DurableTransportReplayLedger


def test_replay_initializer_binds_a_configured_m4g_transport_audience(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ledger_directory = tmp_path / "ledger"
    probe_directory = tmp_path / "probe"
    ledger_directory.mkdir()
    probe_directory.mkdir()
    public_bytes = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_path = tmp_path / "gateway.public"
    public_path.write_bytes(public_bytes)
    ledger_path = ledger_directory / "transport-replay.json"
    semantic_ledger_path = ledger_directory / "semantic-replay.json"
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_LEDGER_FILE", str(ledger_path))
    monkeypatch.setenv(
        "AEGIS_SEMANTIC_REPLAY_LEDGER_FILE",
        str(semantic_ledger_path),
    )
    monkeypatch.setenv("AEGIS_TRANSPORT_PROBE_DIRECTORY", str(probe_directory))
    monkeypatch.setenv("AEGIS_GATEWAY_PUBLIC_KEY_FILE", str(public_path))
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "m4g-gateway-key")
    monkeypatch.setenv("AEGIS_TRANSPORT_AUDIENCE", OT_CAPABILITY_AUDIENCE)
    monkeypatch.setenv("AEGIS_RUNTIME_UID", str(os.getuid()))
    monkeypatch.setenv("AEGIS_RUNTIME_GID", str(os.getgid()))

    result = initialize()

    assert result["ledger_reservations"] == 0
    assert result["semantic_ledger_initialized"] is True
    assert result["semantic_ledger_reservations"] == 0
    ledger = DurableTransportReplayLedger(
        ledger_path,
        audience=OT_CAPABILITY_AUDIENCE,
        gateway_key_id="m4g-gateway-key",
        gateway_public_key_sha256=hashlib.sha256(public_bytes).hexdigest(),
    )
    assert ledger.reservation_count == 0
    ledger.close()
    semantic_ledger = OrderlyRestartReplayReservations(semantic_ledger_path)
    assert semantic_ledger.reservation_count == 0
    semantic_ledger.close()
    assert stat.S_IMODE(semantic_ledger_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(
        semantic_ledger_path.with_name(
            f".{semantic_ledger_path.name}.writer.lock"
        ).stat().st_mode
    ) == 0o600
