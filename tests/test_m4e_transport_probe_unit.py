from __future__ import annotations

import json
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis_ot.m4e_transport_probe as probe
from aegis_ot.lab import SimulatedCommandAdapter, nominal_state
from aegis_ot.segmented_runtime import (
    SignedSegmentedExecutionRequest,
    SignedSegmentedExecutionResponse,
    _sha256,
)


class _Response:
    def __init__(self, payload: bytes, *, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        del args

    def read(self, _size: int) -> bytes:
        return self.payload


def _write_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Ed25519PrivateKey, Ed25519PrivateKey]:
    gateway_private = Ed25519PrivateKey.generate()
    ot_private = Ed25519PrivateKey.generate()
    gateway_path = tmp_path / "gateway.private"
    ot_public_path = tmp_path / "ot.public"
    gateway_path.write_bytes(
        gateway_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    ot_public_path.write_bytes(
        ot_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-test-key")
    monkeypatch.setenv("AEGIS_GATEWAY_PRIVATE_KEY_FILE", str(gateway_path))
    monkeypatch.setenv("AEGIS_OT_PUBLIC_KEY_FILE", str(ot_public_path))
    return gateway_private, ot_private


@pytest.mark.parametrize("accept_campaign", [True, False])
def test_m4e_probe_main_verifies_the_complete_transport_sequence(
    accept_campaign: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, ot_private = _write_keys(tmp_path, monkeypatch)
    state = nominal_state(observed_at=datetime.now(UTC))
    monkeypatch.setattr(probe, "_read_observation", lambda: state)
    exchange_count = 0

    def exchange(_url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal exchange_count
        exchange_count += 1
        if exchange_count == 1:
            return 403, {"detail": "signed gateway request required"}
        if exchange_count == 2:
            return 403, {"detail": "gateway signature rejected"}
        if exchange_count == 3:
            signed_request = SignedSegmentedExecutionRequest.model_validate(payload)
            execution = SimulatedCommandAdapter().execute(
                signed_request.request.proposal,
                signed_request.request.decision,
                state,
            )
            signed_response = SignedSegmentedExecutionResponse(
                request_sha256=_sha256(signed_request),
                execution=execution,
                ot_key_id="m4e-ot-key-v1",
                signed_at=datetime.now(UTC),
            ).signed(ot_private)
            return 200, signed_response.model_dump(mode="json")
        if exchange_count == 4:
            return 409, {"detail": "transport request replayed"}
        assert exchange_count == 5
        if accept_campaign:
            return 403, {"detail": "gateway signature rejected"}
        return 200, {"detail": "unexpected acceptance"}

    monkeypatch.setattr(probe, "_exchange", exchange)

    if accept_campaign:
        probe.main()
    else:
        with pytest.raises(SystemExit) as exc:
            probe.main()
        assert exc.value.code == 1

    output = json.loads(capsys.readouterr().out)
    assert output["accepted"] is accept_campaign
    assert output["valid_key_holder"] == {
        "executed": True,
        "http_status": 200,
        "response_signature_verified": True,
    }
    assert exchange_count == 5


def test_m4e_probe_exchange_bounds_and_validates_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        probe,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b'{"ok":true}', status=201),
    )
    assert probe._exchange("http://ot-adapter/execute", {"x": 1}) == (
        201,
        {"ok": True},
    )

    error = HTTPError(
        "http://ot-adapter/execute",
        403,
        "forbidden",
        hdrs=None,
        fp=BytesIO(b'{"detail":"denied"}'),
    )

    def reject(*_args: object, **_kwargs: object) -> _Response:
        raise error

    monkeypatch.setattr(probe, "urlopen", reject)
    assert probe._exchange("http://ot-adapter/execute", {}) == (
        403,
        {"detail": "denied"},
    )

    monkeypatch.setattr(
        probe,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"x" * 1_048_577),
    )
    with pytest.raises(RuntimeError, match="size bound"):
        probe._exchange("http://ot-adapter/execute", {})

    monkeypatch.setattr(
        probe,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"[]"),
    )
    with pytest.raises(RuntimeError, match="not an object"):
        probe._exchange("http://ot-adapter/execute", {})


def test_m4e_probe_reads_and_validates_observer_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = nominal_state(observed_at=datetime.now(UTC))
    monkeypatch.setattr(
        probe,
        "urlopen",
        lambda *_args, **_kwargs: _Response(json.dumps(state.model_dump(mode="json")).encode()),
    )

    assert probe._read_observation() == state
