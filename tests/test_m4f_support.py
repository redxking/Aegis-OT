from __future__ import annotations

import hashlib
import os
import stat
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
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


def test_m4f_pair_removes_both_outputs_when_second_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    m4f_runner = import_module("run_m4f_experiment")
    output = tmp_path / "primary.json"
    reproduction_output = tmp_path / "reproduction.json"
    campaign_result = {
        "semantic_outcome_sha256": "a" * 64,
        "accepted": True,
    }
    writes = 0

    monkeypatch.setattr(m4f_runner, "_assert_source_checkout", lambda: None)
    monkeypatch.setattr(m4f_runner, "_assert_checkout", lambda _commit: None)
    monkeypatch.setattr(
        m4f_runner.m4d,
        "_run",
        lambda *_args, **_kwargs: SimpleNamespace(
            stdout="" if "status" in _args else "f" * 40,
        ),
    )
    monkeypatch.setattr(
        m4f_runner,
        "_campaign",
        lambda _project, _commit: dict(campaign_result),
    )

    def write_then_fail(path: Path, _value: dict[str, object]) -> None:
        nonlocal writes
        writes += 1
        path.write_text("partial\n", encoding="utf-8")
        if writes == 2:
            raise OSError("post-replace fsync failed")

    monkeypatch.setattr(m4f_runner.m4d, "_atomic_write_json", write_then_fail)

    with pytest.raises(OSError, match="post-replace fsync failed"):
        m4f_runner.run_pair(output, reproduction_output, "primary", "reproduction")

    assert not output.exists()
    assert not reproduction_output.exists()


def test_m4f_compose_normalization_is_checkout_location_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    m4f_runner = import_module("run_m4f_experiment")
    checkout_a = tmp_path / "checkout-a"
    checkout_b = tmp_path / "checkout-b"
    key_directory_a = tmp_path / "keys-a"
    key_directory_b = tmp_path / "keys-b"
    project_a = "aegis-ot-m4f-a"
    project_b = "aegis-ot-m4f-b"
    document_a = {
        "name": project_a,
        "services": {
            "ot-adapter": {
                "build": {
                    "context": str(checkout_a),
                    "dockerfile": str(checkout_a / "Dockerfile"),
                },
                "secrets": [str(key_directory_a / "gateway.public")],
                "volume": f"{project_a}_transport_replay",
            }
        },
    }
    document_b = {
        "name": project_b,
        "services": {
            "ot-adapter": {
                "build": {
                    "context": str(checkout_b),
                    "dockerfile": str(checkout_b / "Dockerfile"),
                },
                "secrets": [str(key_directory_b / "gateway.public")],
                "volume": f"{project_b}_transport_replay",
            }
        },
    }

    normalized_a = m4f_runner._normalize(
        document_a,
        key_directory_a,
        project_a,
        checkout_a,
    )
    normalized_b = m4f_runner._normalize(
        document_b,
        key_directory_b,
        project_b,
        checkout_b,
    )

    assert normalized_a == normalized_b
    assert normalized_a["services"]["ot-adapter"]["build"] == {
        "context": "<checkout-root>",
        "dockerfile": "<checkout-root>/Dockerfile",
    }
    assert normalized_a["services"]["ot-adapter"]["secrets"] == [
        "<ephemeral-key-dir>/gateway.public"
    ]


def test_m4f_semantic_difference_reports_the_first_stable_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    m4f_runner = import_module("run_m4f_experiment")

    difference = m4f_runner._first_semantic_difference(
        {"a": [1, {"status": 409}], "b": True},
        {"a": [1, {"status": 503}], "b": True},
    )

    assert difference == ("$.a[1].status", 409, 503)
