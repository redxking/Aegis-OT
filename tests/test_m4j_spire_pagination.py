# ruff: noqa: S105 - all token-shaped values are synthetic protocol fixtures
from __future__ import annotations

import json
import subprocess
from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROLE_ALIAS_ID = "spiffe://aegis-ot.m4g.local/agent/agents"
JOIN_TOKEN_AGENT_ID = (
    "spiffe://aegis-ot.m4g.local/spire/agent/join_token/"
    "123e4567-e89b-42d3-a456-426614174000"
)


@pytest.fixture
def token_revoker(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return import_module("revoke_m4j_spire_join_token")


def _spire_json(document: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=(),
        returncode=0,
        stdout=json.dumps(document, sort_keys=True, separators=(",", ":")),
        stderr="",
    )


@pytest.mark.parametrize(
    ("inventory", "document"),
    [
        ("agent", {"agents": [], "next_page_token": "hidden-agent-page"}),
        ("alias", {"entries": [], "next_page_token": "hidden-alias-page"}),
    ],
)
def test_spire_cleanup_rejects_an_unconsumed_inventory_page(
    token_revoker: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    inventory: str,
    document: dict[str, Any],
) -> None:
    monkeypatch.setattr(token_revoker, "_run_spire", lambda *_args: _spire_json(document))

    with pytest.raises(token_revoker.TokenRevocationError, match="paginated.*incomplete"):
        if inventory == "agent":
            token_revoker._read_exact_agent(JOIN_TOKEN_AGENT_ID)
        else:
            token_revoker._read_alias_entries(ROLE_ALIAS_ID)
