from __future__ import annotations

from importlib import import_module
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def secret_preparer(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return import_module("prepare_m4j_secrets")


def test_secret_package_generation_does_not_require_or_embed_runtime_state_roots(
    secret_preparer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index, name in enumerate(
        (
            "AEGIS_AGENT_TRUST_SEQUENCE_DIRECTORY",
            "AEGIS_GATEWAY_TRUST_SEQUENCE_DIRECTORY",
            "AEGIS_OT_TRUST_SEQUENCE_DIRECTORY",
        ),
        start=1,
    ):
        monkeypatch.setenv(name, str(tmp_path / f"ambient-state-{index}"))
    monkeypatch.setattr(secret_preparer, "_resolve_commit", lambda _reference: "a" * 40)
    output = tmp_path / "m4j-secrets"

    manifest = secret_preparer.create_secret_package(
        output,
        source_reference="HEAD",
        credential_ttl_seconds=600,
    )

    assert manifest["source_git_commit"] == "a" * 40
    assert not any("trust-sequence" in path for path in manifest["files"])
    assert not any("trust-sequence" in path.name for path in output.rglob("*"))
    assert (output / "identity" / "trust-bundle.json").is_file()
