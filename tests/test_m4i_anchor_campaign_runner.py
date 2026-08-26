from __future__ import annotations

import json
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("run_m4i_anchor_campaign")


def _source(runner: Any, marker: str = "a") -> dict[str, Any]:
    files = {relative: marker * 64 for relative in runner.SOURCE_BINDING_FILES}
    return {
        "git_commit": marker * 40,
        "git_tree": marker * 40,
        "source_files_sha256": files,
        "source_fingerprint_sha256": runner._sha256(runner._canonical_bytes(files)),
        "clean_checkout": True,
    }


def test_campaign_closes_all_anchor_and_fencing_gates(runner: Any) -> None:
    scenarios, gates = runner._run_scenarios()

    assert tuple(scenarios) == runner.SCENARIO_NAMES
    assert tuple(gates) == runner.GATE_NAMES
    assert all(gates.values())
    assert scenarios["coordinated_rollback"]["reason"] == (
        "coordinated_rollback_detected"
    )
    assert scenarios["anchor_unavailable"]["status"] == "unavailable"
    assert scenarios["current_fence"]["admission_allowed"] is True
    assert scenarios["pending_recovery"]["admission_allowed"] is False


def test_retained_evidence_round_trip_and_source_binding(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source(runner)
    evidence = runner._build_evidence(source)
    path = runner._write_evidence(tmp_path, evidence)

    offline = runner.verify_evidence(path)
    monkeypatch.setattr(runner, "_source_binding", lambda _root: source)
    exact_source = runner.verify_evidence(path, source_root=tmp_path)

    assert offline["valid"] is True
    assert exact_source["valid"] is True
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_verifier_rejects_semantic_gate_and_source_tampering(
    runner: Any,
    tmp_path: Path,
) -> None:
    evidence = runner._build_evidence(_source(runner))
    evidence["gates"][runner.GATE_NAMES[0]] = False
    path = runner._write_evidence(tmp_path, evidence)

    result = runner.verify_evidence(path)

    assert result["valid"] is False
    assert "one or more acceptance gates are not true" in result["errors"]
    assert "semantic projection digest is invalid" in result["errors"]
    assert "canonical evidence digest is invalid" in result["errors"]


def test_verifier_rejects_duplicate_json_keys(runner: Any, tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"one","schema_version":"two"}', encoding="utf-8")

    with pytest.raises(runner.CampaignError, match="duplicate JSON key"):
        runner.verify_evidence(path)


def test_source_binding_requires_clean_checkout(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "_git", lambda _root, *_args: " M tracked.py")

    with pytest.raises(runner.CampaignError, match="exact clean checkout"):
        runner._source_binding(tmp_path)


def test_verifier_rejects_exact_source_drift(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = runner._build_evidence(_source(runner, "a"))
    path = runner._write_evidence(tmp_path, evidence)
    monkeypatch.setattr(
        runner,
        "_source_binding",
        lambda _root: _source(runner, "b"),
    )

    result = runner.verify_evidence(path, source_root=tmp_path)

    assert result["valid"] is False
    assert "evidence does not bind the supplied exact source" in result["errors"]


def test_verifier_rejects_non_string_source_digest(
    runner: Any,
    tmp_path: Path,
) -> None:
    evidence = runner._build_evidence(_source(runner))
    first = runner.SOURCE_BINDING_FILES[0]
    evidence["source_binding"]["source_files_sha256"][first] = None
    path = runner._write_evidence(tmp_path, evidence)

    result = runner.verify_evidence(path)

    assert result["valid"] is False
    assert "source binding is invalid" in result["errors"]


def test_verifier_rejects_non_object_json(runner: Any, tmp_path: Path) -> None:
    path = tmp_path / "array.json"
    path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")

    with pytest.raises(runner.CampaignError, match="root must be an object"):
        runner.verify_evidence(path)
