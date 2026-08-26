from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_ot.segmented_runtime import segmented_gateway_app

SIGNED_SETTINGS = (
    "AEGIS_M5_ROOT_PUBLIC_KEY_FILE",
    "AEGIS_M5_PUBLISHER_CREDENTIAL_FILE",
    "AEGIS_M5_STABLE_AUTHORIZATION_FILE",
    "AEGIS_M5_PUBLICATION_FILE",
    "AEGIS_M5_CONSUMER_STATE_FILE",
    "AEGIS_M5_REVERSAL_FILE",
)


def _clear_m5(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AEGIS_M5_SIGNED_PUBLICATION_MODE", raising=False)
    for name in SIGNED_SETTINGS:
        monkeypatch.delenv(name, raising=False)


def test_legacy_gateway_refuses_required_signed_publication_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_m5(monkeypatch)
    monkeypatch.setenv("AEGIS_M5_SIGNED_PUBLICATION_MODE", "required")

    with pytest.raises(RuntimeError, match="cannot enforce M5 signed publications"):
        with TestClient(segmented_gateway_app):
            pass


def test_legacy_gateway_refuses_signed_inputs_even_without_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_m5(monkeypatch)
    monkeypatch.setenv(
        "AEGIS_M5_PUBLICATION_FILE",
        str(tmp_path / "publication.json"),
    )

    with pytest.raises(RuntimeError, match="cannot enforce M5 signed publications"):
        with TestClient(segmented_gateway_app):
            pass


def test_legacy_gateway_remains_available_only_when_m5_is_absent_or_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_m5(monkeypatch)
    with TestClient(segmented_gateway_app) as client:
        assert client.get("/health").status_code == 200

    monkeypatch.setenv("AEGIS_M5_SIGNED_PUBLICATION_MODE", "disabled")
    with TestClient(segmented_gateway_app) as client:
        assert client.get("/health").status_code == 200
