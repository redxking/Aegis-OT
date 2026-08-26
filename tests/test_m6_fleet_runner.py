from __future__ import annotations

import copy
import json
import os
import stat
import uuid
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("run_m6_fleet")


def _source_binding(runner: Any) -> dict[str, Any]:
    binding: dict[str, Any] = {
        "git_commit": "a" * 40,
        "git_tree": "b" * 40,
        "clean_checkout": True,
        "source_files": [
            {
                "path": path,
                "bytes": index + 1,
                "sha256": f"{index + 1:x}" * 64,
                "git_blob": f"{index + 5:x}" * 40,
            }
            for index, path in enumerate(runner.SOURCE_PATHS)
        ],
    }
    binding["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(binding)
    )
    return binding


def _rehash_report(runner: Any, report: dict[str, Any]) -> None:
    report.pop("integrity", None)
    report["integrity"] = {"canonical_payload_sha256": runner._sha256_json(report)}


def _private_evidence_path(
    runner: Any,
    tmp_path: Path,
    report: dict[str, Any] | bytes,
    *,
    suffix: str = "fixture",
) -> Path:
    directory = tmp_path / f"{runner.OUTPUT_PREFIX}{suffix}"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "evidence.json"
    if isinstance(report, bytes):
        path.write_bytes(report)
    else:
        path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_plan_is_read_only_fixed_and_never_claims_execution(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("plan must not inspect source or execute the model")

    monkeypatch.setattr(runner, "_assert_clean_source", forbidden)
    monkeypatch.setattr(runner.m6, "run_m6_fleet_study", forbidden)
    before = tuple(tmp_path.iterdir())

    plan = runner.build_plan()

    assert tuple(tmp_path.iterdir()) == before
    assert plan["schema_version"] == "aegis-ot-m6-fleet-plan-v2"
    assert plan["execution_mode"] == "plan_only"
    assert plan["execution_claimed"] is False
    assert plan["scale_contract"] == [10, 100, 1_000, 10_000]
    assert plan["acceptance_gate_names"] == list(runner.ACCEPTANCE_GATE_NAMES)
    assert len(plan["measure_catalog"]) == 12
    assert plan["assumption_contract"]["sensitivity_cases"] == [
        "low",
        "base",
        "high",
    ]
    assert plan["requirements_boundary"] == {
        "modeled_coverage": ["AOT-PERF-007", "AOT-PERF-008"],
        "verification_completion_claimed": False,
        "unresolved_tbrs": [
            "TBR-011",
            "TBR-016",
            "TBR-017",
            "TBR-021",
            "TBR-023",
        ],
        "gate": "G6",
        "gate_accepted": False,
        "gate_disposition": "not_accepted_modeled_coverage_only",
    }


def test_campaign_accepts_every_required_measure_and_assumption_gate(
    runner: Any,
) -> None:
    binding = _source_binding(runner)
    report = runner._build_report(binding)

    assert report["campaign_contract_passed"] is True
    assert "accepted" not in report
    assert tuple(report["acceptance_gates"]) == runner.ACCEPTANCE_GATE_NAMES
    assert all(report["acceptance_gates"].values())
    assert report["requirements_boundary"]["verification_completion_claimed"] is False
    assert report["requirements_boundary"]["gate_accepted"] is False
    assert report["scale_contract"] == [10, 100, 1_000, 10_000]
    assert [item["logical_agents"] for item in report["study"]["scales"]] == [
        10,
        100,
        1_000,
        10_000,
    ]
    runner._verify_report_payload(report, expected_source_binding=binding)


def test_retained_study_contains_complete_measure_and_sensitivity_contract(
    runner: Any,
) -> None:
    report = runner._build_report(_source_binding(runner))
    study = report["study"]

    assert set(study["assumptions"]) == set(runner.REQUIRED_ASSUMPTION_FIELDS)
    assert [item["name"] for item in study["assumptions"]["economic_cases"]] == [
        "low",
        "base",
        "high",
    ]
    assert all(
        set(item) == set(runner.REQUIRED_ECONOMIC_CASE_FIELDS)
        for item in study["assumptions"]["economic_cases"]
    )
    assert all(
        set(scale) == set(runner.REQUIRED_SCALE_FIELDS) for scale in study["scales"]
    )
    assert [item["measure_id"] for item in report["measure_catalog"]] == [
        "logical_fleet_workload",
        "throughput_and_queue_delay",
        "provisional_unapproved_and_conflict_distribution",
        "approval_concurrency_and_replay_state",
        "pending_effects_and_reconciliation",
        "delegation_complexity",
        "revocation_propagation",
        "policy_distribution",
        "evidence_volume_and_retention",
        "operator_span",
        "incident_response_effort",
        "fleet_economics_and_marginal_governance_cost",
    ]
    for scale in study["scales"]:
        for measure in report["measure_catalog"]:
            assert all(
                runner._nested_field_present(scale, path)
                for path in measure["field_paths"]
            )


def test_semantic_hash_is_deterministic_across_run_metadata(runner: Any) -> None:
    binding = _source_binding(runner)
    first = runner._build_report(
        binding,
        run_id=str(uuid.UUID(int=1)),
        generated_at=datetime(2026, 8, 26, 10, 0, tzinfo=UTC),
    )
    second = runner._build_report(
        binding,
        run_id=str(uuid.UUID(int=2)),
        generated_at=datetime(2026, 8, 26, 11, 0, tzinfo=UTC),
    )

    assert first["run_id"] != second["run_id"]
    assert first["generated_at"] != second["generated_at"]
    assert first["study"] == second["study"]
    assert first["study"]["result_sha256"] == second["study"]["result_sha256"]
    assert first["semantic_outcome_sha256"] == second["semantic_outcome_sha256"]
    assert first["integrity"] != second["integrity"]
    assert first["semantic_outcome_sha256"] == (
        "a2d4a51032ef5019357032fc20d0b9e6779b14afc578cccb324830638a70752b"
    )


def test_report_preserves_modeled_measurement_and_effectiveness_boundaries(
    runner: Any,
) -> None:
    report = runner._build_report(_source_binding(runner))
    rendered = json.dumps(report, sort_keys=True).lower()

    assert report["schema_version"] == "aegis-ot-m6-fleet-campaign-v2"
    assert report["study"]["evidence_classification"] == "synthetic_model_output_only"
    assert report["study"]["claim_scope"].endswith("modeled, not measured.")
    assert "no host benchmark" in rendered
    assert "not a vm" in rendered
    assert "not budgets, quotes, forecasts" in rendered
    assert "does not establish deployment" in rendered
    assert "operational effectiveness" in rendered
    assert "independent validation" in rendered
    assert "provisional or unapproved" in rendered
    assert "neither category denotes execution authorization" in rendered
    assert report["requirements_boundary"] == runner.REQUIREMENTS_BOUNDARY
    assert report["requirements_boundary"]["modeled_coverage"] == [
        "AOT-PERF-007",
        "AOT-PERF-008",
    ]
    assert report["requirements_boundary"]["unresolved_tbrs"] == [
        "TBR-011",
        "TBR-016",
        "TBR-017",
        "TBR-021",
        "TBR-023",
    ]
    assert report["requirements_boundary"]["gate_accepted"] is False
    assert "g6 is not accepted" in rendered
    assert report["material_handling"][
        "private_or_sensitive_material_retained"
    ] is False


def test_verifier_rejects_fully_rehashed_model_output_tampering(runner: Any) -> None:
    binding = _source_binding(runner)
    report = runner._build_report(binding)
    tampered = copy.deepcopy(report)
    tampered["study"]["scales"][3]["queue"][
        "modeled_throughput_events_per_second"
    ] = "999999.000000"
    unsigned_study = dict(tampered["study"])
    unsigned_study.pop("result_sha256")
    tampered["study"]["result_sha256"] = runner._sha256_json(unsigned_study)
    gates = runner._acceptance_gates(
        tampered["study"],
        source_bound=True,
        sensitive_material_retained=False,
    )
    tampered["acceptance_gates"] = gates
    tampered["campaign_contract_passed"] = all(gates.values())
    tampered["semantic_outcome_sha256"] = runner._sha256_json(
        runner._semantic_projection(tampered["study"], gates)
    )
    _rehash_report(runner, tampered)

    with pytest.raises(runner.CampaignError, match="does not replay exactly"):
        runner._verify_report_payload(tampered, expected_source_binding=binding)


def test_verifier_rejects_rehashed_sensitivity_input_tampering(runner: Any) -> None:
    binding = _source_binding(runner)
    report = runner._build_report(binding)
    tampered = copy.deepcopy(report)
    tampered["study"]["assumptions"]["economic_cases"][1][
        "operator_labor_usd_per_hour"
    ] = "1.00"
    unsigned_study = dict(tampered["study"])
    unsigned_study.pop("result_sha256")
    tampered["study"]["result_sha256"] = runner._sha256_json(unsigned_study)
    tampered["semantic_outcome_sha256"] = runner._sha256_json(
        runner._semantic_projection(
            tampered["study"], tampered["acceptance_gates"]
        )
    )
    _rehash_report(runner, tampered)

    with pytest.raises(runner.CampaignError, match="does not replay exactly"):
        runner._verify_report_payload(tampered, expected_source_binding=binding)


def test_coordination_gates_reject_internally_inconsistent_modeled_counts(
    runner: Any,
) -> None:
    report = runner._build_report(_source_binding(runner))
    study = copy.deepcopy(report["study"])
    scale = study["scales"][0]
    scale["action_workload"]["provisional_unapproved_action_requests"] += 1

    gates = runner._acceptance_gates(
        study,
        source_bound=True,
        sensitive_material_retained=False,
    )

    assert gates["provisional_unapproved_and_conflict_distribution_retained"] is False
    assert gates["approval_concurrency_and_replay_growth_retained"] is False
    assert gates["pending_effect_and_reconciliation_backlog_retained"] is False


def test_verifier_rejects_rehashed_requirements_boundary_tampering(
    runner: Any,
) -> None:
    binding = _source_binding(runner)
    tampered = runner._build_report(binding)
    tampered["requirements_boundary"]["gate_accepted"] = True
    _rehash_report(runner, tampered)

    with pytest.raises(runner.CampaignError, match="requirements boundary"):
        runner._verify_report_payload(tampered, expected_source_binding=binding)


def test_verifier_rejects_semantic_and_integrity_digest_tampering(runner: Any) -> None:
    binding = _source_binding(runner)
    report = runner._build_report(binding)

    semantic = copy.deepcopy(report)
    semantic["semantic_outcome_sha256"] = "0" * 64
    _rehash_report(runner, semantic)
    with pytest.raises(runner.CampaignError, match="semantic outcome digest"):
        runner._verify_report_payload(semantic, expected_source_binding=binding)

    integrity = copy.deepcopy(report)
    integrity["integrity"]["canonical_payload_sha256"] = "0" * 64
    with pytest.raises(runner.CampaignError, match="canonical payload digest"):
        runner._verify_report_payload(integrity, expected_source_binding=binding)


def test_source_binding_requires_exact_paths_and_fingerprint(runner: Any) -> None:
    binding = _source_binding(runner)
    runner._verify_source_binding_shape(binding)

    missing = copy.deepcopy(binding)
    missing["source_files"].pop()
    missing["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(missing)
    )
    with pytest.raises(runner.CampaignError, match="exact source path set"):
        runner._verify_source_binding_shape(missing)

    bad_fingerprint = copy.deepcopy(binding)
    bad_fingerprint["source_fingerprint_sha256"] = "0" * 64
    with pytest.raises(runner.CampaignError, match="source fingerprint"):
        runner._verify_source_binding_shape(bad_fingerprint)


def test_material_scan_rejects_secret_fields_and_private_pem(runner: Any) -> None:
    report = runner._build_report(_source_binding(runner))

    assert runner._contains_prohibited_material(report) is False
    assert runner._contains_prohibited_material({"api_key": "value"}) is True
    assert runner._contains_prohibited_material(
        {"material": "-----BEGIN PRIVATE KEY-----"}
    ) is True
    assert runner._contains_prohibited_material(
        {"private_or_sensitive_material_retained": True}
    ) is True


def test_retained_run_uses_unique_private_output_and_same_script_verification(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _source_binding(runner)
    monkeypatch.setattr(
        runner, "_assert_clean_source", lambda: copy.deepcopy(binding)
    )

    first = runner.run_campaign(tmp_path)
    second = runner.run_campaign(tmp_path)

    assert first != second
    assert first.parent.parent == tmp_path
    assert first.parent.name.startswith(runner.OUTPUT_PREFIX)
    assert stat.S_IMODE(first.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    verification = runner.verify_evidence(first)
    assert verification["campaign_contract_passed"] is True
    assert "accepted" not in verification
    assert verification["scale_points"] == [10, 100, 1_000, 10_000]
    assert verification["modeled_requirement_coverage"] == [
        "AOT-PERF-007",
        "AOT-PERF-008",
    ]
    assert verification["unresolved_tbrs"] == [
        "TBR-011",
        "TBR-016",
        "TBR-017",
        "TBR-021",
        "TBR-023",
    ]
    assert verification["g6_accepted"] is False
    assert verification["private_or_sensitive_material_retained"] is False
    assert os.path.commonpath((str(first.resolve()), str(runner.ROOT.resolve()))) != str(
        runner.ROOT.resolve()
    )


def test_retained_run_rejects_checkout_and_dirty_source_before_creation(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _source_binding(runner)
    monkeypatch.setattr(
        runner, "_assert_clean_source", lambda: copy.deepcopy(binding)
    )
    with pytest.raises(runner.CampaignError, match="outside the source checkout"):
        runner.run_campaign(runner.ROOT)

    before = tuple(tmp_path.iterdir())

    def dirty() -> dict[str, Any]:
        raise runner.CampaignError("retained M6 execution requires an exact clean checkout")

    monkeypatch.setattr(runner, "_assert_clean_source", dirty)
    with pytest.raises(runner.CampaignError, match="exact clean checkout"):
        runner.run_campaign(tmp_path)
    assert tuple(tmp_path.iterdir()) == before


def test_source_change_during_campaign_removes_owned_partial_output(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = _source_binding(runner)
    changed = copy.deepcopy(initial)
    changed["git_commit"] = "c" * 40
    changed["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(changed)
    )
    calls = 0

    def changing_source() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return copy.deepcopy(initial if calls == 1 else changed)

    monkeypatch.setattr(runner, "_assert_clean_source", changing_source)

    with pytest.raises(runner.CampaignError, match="source changed"):
        runner.run_campaign(tmp_path)
    assert tuple(tmp_path.iterdir()) == ()


def test_loader_rejects_duplicate_keys_symlinks_permissions_and_size(
    runner: Any,
    tmp_path: Path,
) -> None:
    duplicate = _private_evidence_path(
        runner,
        tmp_path,
        b'{"schema_version":"one","schema_version":"two"}',
        suffix="duplicate",
    )
    with pytest.raises(runner.CampaignError, match="duplicate JSON key"):
        runner._load_report(duplicate)

    linked = duplicate.parent / "linked.json"
    linked.symlink_to(duplicate)
    with pytest.raises(runner.CampaignError, match="non-symlink"):
        runner._load_report(linked)

    wrong_name = duplicate.parent / "copy.json"
    wrong_name.write_text("{}", encoding="utf-8")
    wrong_name.chmod(0o600)
    with pytest.raises(runner.CampaignError, match="filename"):
        runner._load_report(wrong_name)

    hard_linked = _private_evidence_path(
        runner, tmp_path, b"{}", suffix="hard-linked"
    )
    os.link(hard_linked, hard_linked.parent / "second-link.json")
    with pytest.raises(runner.CampaignError, match="exactly one hard link"):
        runner._load_report(hard_linked)

    wrong_mode = _private_evidence_path(
        runner, tmp_path, b"{}", suffix="wrong-mode"
    )
    wrong_mode.chmod(0o644)
    with pytest.raises(runner.CampaignError, match="mode 0600"):
        runner._load_report(wrong_mode)

    oversized = _private_evidence_path(
        runner,
        tmp_path,
        b" " * (runner.MAX_EVIDENCE_BYTES + 1),
        suffix="oversized",
    )
    with pytest.raises(runner.CampaignError, match="outside the verifier limit"):
        runner._load_report(oversized)


def test_offline_verifier_requires_the_exact_current_source_binding(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained_binding = _source_binding(runner)
    report = runner._build_report(retained_binding)
    path = _private_evidence_path(runner, tmp_path, report)
    current_binding = copy.deepcopy(retained_binding)
    current_binding["git_commit"] = "c" * 40
    current_binding["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(current_binding)
    )
    monkeypatch.setattr(
        runner, "_assert_clean_source", lambda: copy.deepcopy(current_binding)
    )

    with pytest.raises(runner.CampaignError, match="exact current source"):
        runner.verify_evidence(path)


def test_offline_verifier_detects_source_change_during_recomputation(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = _source_binding(runner)
    report = runner._build_report(initial)
    path = _private_evidence_path(runner, tmp_path, report)
    changed = copy.deepcopy(initial)
    changed["git_tree"] = "c" * 40
    changed["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(changed)
    )
    calls = 0

    def changing_source() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return copy.deepcopy(initial if calls == 1 else changed)

    monkeypatch.setattr(runner, "_assert_clean_source", changing_source)

    with pytest.raises(runner.CampaignError, match="was being verified"):
        runner.verify_evidence(path)


def test_generation_time_must_be_timezone_aware(runner: Any) -> None:
    binding = _source_binding(runner)
    report = runner._build_report(binding)
    tampered = copy.deepcopy(report)
    generated = datetime.fromisoformat(tampered["generated_at"])
    tampered["generated_at"] = (generated + timedelta(seconds=1)).replace(
        tzinfo=None
    ).isoformat()
    _rehash_report(runner, tampered)

    with pytest.raises(runner.CampaignError, match="timezone-aware"):
        runner._verify_report_payload(tampered, expected_source_binding=binding)
