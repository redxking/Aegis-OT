from __future__ import annotations

import copy
import json
import stat
import uuid
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest
from test_m8_evidence_traceability import _report, _repository

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return import_module("run_m8_evidence_traceability")


def _binding(runner: Any, repository: Path) -> dict[str, Any]:
    binding: dict[str, Any] = runner._source_binding(repository)
    return binding


def _rehash_traceability(runner: Any, traceability: dict[str, Any]) -> None:
    traceability.pop("content_sha256", None)
    traceability["content_sha256"] = runner._sha256_json(traceability)


def _rehash_report(runner: Any, report: dict[str, Any]) -> None:
    report.pop("integrity", None)
    report["integrity"] = {"canonical_payload_sha256": runner._sha256_json(report)}


def _private_report(
    runner: Any,
    tmp_path: Path,
    value: dict[str, Any] | bytes,
    *,
    suffix: str,
) -> Path:
    directory = tmp_path / f"{runner.OUTPUT_PREFIX}{suffix}"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "evidence.json"
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_plan_is_read_only_and_claims_no_execution_or_acceptance(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("plan mode touched repository evidence")

    monkeypatch.setattr(runner, "_assert_exact_source", forbidden)
    monkeypatch.setattr(runner, "_build_traceability", forbidden)

    plan = runner.build_plan()

    assert plan["schema"] == "aegis-ot-m8-evidence-traceability-plan-v2"
    assert plan["execution_mode"] == "plan_only"
    assert plan["execution_claimed"] is False
    assert plan["package_integrity_accepted"] is False
    assert plan["requirements_contract"] == {
        "tracked": 223,
        "open": 223,
        "accepted": 0,
        "tbrs_open": 35,
        "baseline_status": "proposed_not_approved",
    }
    assert plan["attestation_contract"]["attestation_included"] is False
    assert plan["attestation_contract"]["automatic_requirement_acceptance"] is False
    assert plan["attestation_contract"]["independent_validation_established"] is False


def test_campaign_report_accepts_only_exact_mapping_package_integrity(
    runner: Any,
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    traceability = _report(repository)
    binding = _binding(runner, repository)

    report = runner._build_report(
        binding,
        traceability,
        authoritative_root=repository,
    )

    assert report["package_integrity_accepted"] is True
    assert tuple(report["gates"]) == runner.GATE_NAMES
    assert all(report["gates"].values())
    assert report["system_acceptance"] == {
        "baseline_approved": False,
        "requirements_accepted": 0,
        "requirements_open": 223,
        "tbrs_open": 35,
        "end_state_accepted": False,
        "g7_completed": False,
        "independent_validation_established": False,
        "deployment_established": False,
        "operational_effectiveness_established": False,
    }
    assert "Acceptance means only" in report["acceptance_scope"]
    assert "not baseline approval" in report["acceptance_scope"]
    assert report["traceability"]["external_attestations"] == []


def test_semantic_outcome_is_stable_across_run_metadata(
    runner: Any,
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    traceability = _report(repository)
    binding = _binding(runner, repository)
    first = runner._build_report(
        binding,
        traceability,
        run_id=str(uuid.UUID(int=1)),
        generated_at=datetime(2026, 8, 26, 16, 0, tzinfo=UTC),
        authoritative_root=repository,
    )
    second = runner._build_report(
        binding,
        traceability,
        run_id=str(uuid.UUID(int=2)),
        generated_at=datetime(2026, 8, 26, 17, 0, tzinfo=UTC),
        authoritative_root=repository,
    )

    assert first["run_id"] != second["run_id"]
    assert first["generated_at"] != second["generated_at"]
    assert first["semantic_outcome_sha256"] == second["semantic_outcome_sha256"]
    assert first["integrity"] != second["integrity"]


def test_verifier_rejects_fully_rehashed_false_acceptance(
    runner: Any,
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    traceability = _report(repository)
    binding = _binding(runner, repository)
    report = runner._build_report(
        binding,
        traceability,
        authoritative_root=repository,
    )
    tampered = copy.deepcopy(report)
    tampered_trace = tampered["traceability"]
    tampered_trace["requirements"][0]["disposition"]["finding_status"] = "accepted"
    _rehash_traceability(runner, tampered_trace)
    tampered["gates"] = runner._gates(
        binding,
        tampered_trace,
        rebuilt_exactly=True,
        authoritative_root=repository,
    )
    tampered["package_integrity_accepted"] = all(tampered["gates"].values())
    semantic = runner._semantic_projection(tampered_trace, tampered["gates"])
    tampered["semantic_outcome_sha256"] = runner._sha256_json(semantic)
    _rehash_report(runner, tampered)

    with pytest.raises(runner.m8v2.TraceabilityError, match="not exactly open"):
        runner._verify_payload(
            tampered,
            expected_source_binding=binding,
            expected_traceability=traceability,
            authoritative_root=repository,
        )


def test_runner_gates_and_report_require_exact_repo_rebuild_and_source_blobs(
    runner: Any,
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    traceability = _report(repository)
    binding = _binding(runner, repository)
    forged_traceability = copy.deepcopy(traceability)
    forged_traceability["tbrs"][0]["decision_or_value"] += " Forged."
    _rehash_traceability(runner, forged_traceability)

    gates = runner._gates(
        binding,
        forged_traceability,
        rebuilt_exactly=True,
        authoritative_root=repository,
    )
    assert not any(gates.values())
    with pytest.raises(runner.m8v2.TraceabilityError, match="exact current repository"):
        runner._build_report(
            binding,
            forged_traceability,
            authoritative_root=repository,
        )

    forged_binding = copy.deepcopy(binding)
    forged_binding["source_files"][0]["sha256"] = "0" * 64
    forged_binding["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(forged_binding)
    )
    gates = runner._gates(
        forged_binding,
        traceability,
        rebuilt_exactly=True,
        authoritative_root=repository,
    )
    assert not any(gates.values())
    with pytest.raises(runner.CampaignError, match="exact authoritative repository"):
        runner._build_report(
            forged_binding,
            traceability,
            authoritative_root=repository,
        )


def test_retained_campaign_uses_private_unique_paths_and_offline_rebuild(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository(tmp_path)
    traceability = _report(repository)
    binding = _binding(runner, repository)
    source_reads = 0
    traceability_reads = 0

    def exact_source() -> dict[str, Any]:
        nonlocal source_reads
        source_reads += 1
        return copy.deepcopy(binding)

    def rebuild() -> dict[str, Any]:
        nonlocal traceability_reads
        traceability_reads += 1
        return copy.deepcopy(traceability)

    monkeypatch.setattr(runner, "_assert_exact_source", exact_source)
    monkeypatch.setattr(runner, "_build_traceability", rebuild)
    monkeypatch.setattr(runner, "ROOT", repository)

    first = runner.run_campaign(tmp_path)
    second = runner.run_campaign(tmp_path)

    assert first != second
    assert source_reads >= 8
    assert traceability_reads >= 4
    assert stat.S_IMODE(first.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert first.stat().st_nlink == 1
    verified = runner.verify_evidence(first)
    assert verified["package_integrity_accepted"] is True
    assert verified["requirements_mapped"] == 6
    assert verified["requirements_open"] == 223
    assert verified["requirements_accepted"] == 0
    assert verified["tbrs_open"] == 35
    assert verified["external_attestations"] == 0
    assert verified["independent_validation_established"] is False


def test_offline_verifier_rejects_exact_source_mismatch(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository(tmp_path)
    traceability = _report(repository)
    binding = _binding(runner, repository)
    report = runner._build_report(
        binding,
        traceability,
        authoritative_root=repository,
    )
    path = _private_report(runner, tmp_path, report, suffix="source-mismatch")
    changed = copy.deepcopy(binding)
    changed["git_commit"] = "f" * 40
    changed["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(changed)
    )
    monkeypatch.setattr(runner, "_assert_exact_source", lambda: copy.deepcopy(changed))
    monkeypatch.setattr(runner, "_build_traceability", lambda: copy.deepcopy(traceability))
    monkeypatch.setattr(runner, "ROOT", repository)

    with pytest.raises(runner.CampaignError, match="exact current source"):
        runner.verify_evidence(path)


def test_private_loader_rejects_duplicate_json_keys_permissions_and_extra_files(
    runner: Any,
    tmp_path: Path,
) -> None:
    duplicate = _private_report(
        runner,
        tmp_path,
        b'{"state":"open","state":"accepted"}',
        suffix="duplicate",
    )
    with pytest.raises(runner.CampaignError, match="duplicate JSON key"):
        runner._load_private_report(duplicate)

    wrong_mode = _private_report(runner, tmp_path, b"{}", suffix="wrong-mode")
    wrong_mode.chmod(0o644)
    with pytest.raises(runner.CampaignError, match="unsafe"):
        runner._load_private_report(wrong_mode)

    extra = _private_report(runner, tmp_path, b"{}", suffix="extra")
    (extra.parent / "unexpected").write_text("x", encoding="utf-8")
    with pytest.raises(runner.CampaignError, match="exactly evidence.json"):
        runner._load_private_report(extra)
