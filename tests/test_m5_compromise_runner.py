from __future__ import annotations

import copy
import json
import os
import stat
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("run_m5_compromise")


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


def test_plan_is_fixed_and_never_claims_execution(runner: Any) -> None:
    plan = runner.build_plan()

    assert plan["schema_version"] == "aegis-ot-m5-compromise-plan-v1"
    assert plan["execution_mode"] == "plan_only"
    assert not plan["execution_claimed"]
    assert [item["category"] for item in plan["scenario_catalog"]] == [
        "compromised_leaf_and_unrelated_branch",
        "supervisor_compromise_and_revocation",
        "assurance_service_failure_and_bounded_recovery",
        "nonfresh_or_untrustworthy_telemetry",
        "quarantine_release_authority_and_reconciliation",
    ]
    assert len(plan["acceptance_gate_names"]) == 15
    assert plan["scenario_catalog_sha256"] == runner._sha256_json(
        runner.SCENARIO_CATALOG
    )


def test_campaign_accepts_all_fixed_hypothesis_critical_gates(runner: Any) -> None:
    report = runner._build_report(_source_binding(runner))

    assert report["accepted"]
    assert tuple(report["acceptance_gates"]) == runner.ACCEPTANCE_GATE_NAMES
    assert all(report["acceptance_gates"].values())
    assert len(report["scenarios"]) == 5
    assert report["key_material"]["private_key_material_retained"] is False
    runner._verify_report_payload(
        report,
        expected_source_binding=_source_binding(runner),
    )


def test_semantic_hash_is_deterministic_across_fresh_ephemeral_keys(
    runner: Any,
) -> None:
    binding = _source_binding(runner)
    first = runner._build_report(binding)
    second = runner._build_report(binding)

    assert first["run_id"] != second["run_id"]
    assert (
        first["key_material"]["authority_public_key_base64"]
        != second["key_material"]["authority_public_key_base64"]
    )
    assert first["semantic_outcome_sha256"] == second["semantic_outcome_sha256"]
    assert first["semantic_outcome_sha256"] == (
        "b1cdf63a7320b10ba775fbaa0e3fda13e303524111bfd4e07299053b1955207c"
    )


def test_branch_and_ancestor_scenarios_preserve_non_execution_boundary(
    runner: Any,
) -> None:
    scenarios = runner._build_report(_source_binding(runner))["scenarios"]
    branch = scenarios[0]
    compromised, unrelated = branch["mission_evaluations"]

    assert compromised["result"]["outcome"] == "quarantine"
    assert compromised["result"]["reasons"] == ["actor_compromised"]
    assert compromised["result"]["may_enter_primary_assurance"] is False
    assert compromised["result"]["execution_authorized"] is False
    assert unrelated["result"]["outcome"] == "continue_primary_assurance"
    assert unrelated["result"]["may_enter_primary_assurance"] is True
    assert unrelated["result"]["execution_authorized"] is False

    supervisors = scenarios[1]["mission_evaluations"]
    assert supervisors[0]["result"]["reasons"] == [
        "delegation_ancestor_compromised"
    ]
    assert supervisors[1]["result"]["reasons"] == ["delegation_ancestor_revoked"]
    assert all(item["result"]["outcome"] == "deny" for item in supervisors)


def test_service_and_telemetry_matrix_is_complete_and_fail_closed(runner: Any) -> None:
    scenarios = runner._build_report(_source_binding(runner))["scenarios"]
    service = scenarios[2]

    assert len(service["mission_evaluations"]) == 8
    assert len(service["recovery_evaluations"]) == 8
    assert {
        tuple(item["result"]["reasons"])
        for item in service["mission_evaluations"]
    } == {
        (f"{service_name}_{condition}",)
        for service_name in ("identity", "policy", "evidence", "gateway")
        for condition in ("unavailable", "untrusted")
    }
    assert all(
        item["result"]["outcome"] == "deny"
        and item["result"]["execution_authorized"] is False
        for item in service["mission_evaluations"]
    )
    assert all(
        item["request"]["operation"] == "restore_assurance_service"
        and item["result"]["allowed"] is True
        and item["result"]["plant_control_authorized"] is False
        for item in service["recovery_evaluations"]
    )

    telemetry = scenarios[3]["mission_evaluations"]
    assert [item["case_id"] for item in telemetry] == [
        "telemetry-delayed",
        "telemetry-replayed",
        "telemetry-biased",
        "telemetry-contradictory",
        "telemetry-unavailable",
    ]
    assert all(item["result"]["outcome"] == "deny" for item in telemetry)


def test_quarantine_release_has_positive_and_strict_negative_controls(
    runner: Any,
) -> None:
    release = runner._build_report(_source_binding(runner))["scenarios"][4]
    records = {
        item["case_id"]: item for item in release["recovery_evaluations"]
    }

    assert records["release-valid-first-use"]["result"][
        "allowed"
    ] is True
    assert records["release-valid-first-use"]["result"][
        "plant_control_authorized"
    ] is False
    assert "recovery_reconciliation_incomplete" in records[
        "release-unresolved-effect"
    ]["result"]["reasons"]
    assert "recovery_reconciliation_incomplete" in records[
        "release-incomplete-reconciliation"
    ]["result"]["reasons"]
    assert "recovery_authority_invalid" in records["release-forged-authority"][
        "result"
    ]["reasons"]
    assert {
        "recovery_request_evidence_mismatch",
        "recovery_snapshot_evidence_mismatch",
    }.issubset(records["release-stale-evidence"]["result"]["reasons"])
    assert {
        "recovery_authorization_sequence_not_monotonic",
        "recovery_authorization_replayed",
    }.issubset(records["release-valid-replay"]["result"]["reasons"])
    assert release["contract_observations"] == {
        "recovery_operations": [
            "publish_revocation",
            "rotate_credential",
            "reconcile_effect",
            "restore_assurance_service",
            "release_quarantine",
        ],
        "plant_control_operation_present": False,
        "plant_adapter_invoked": False,
    }


def test_offline_replay_rejects_semantically_rehashed_result_tampering(
    runner: Any,
) -> None:
    binding = _source_binding(runner)
    report = runner._build_report(binding)
    tampered = copy.deepcopy(report)
    tampered["scenarios"][0]["mission_evaluations"][1]["result"]["reasons"] = [
        "continue_to_primary_assurance",
        "invented_reason",
    ]
    tampered["semantic_outcome_sha256"] = runner._sha256_json(
        runner._semantic_projection(
            tampered["scenarios"], tampered["acceptance_gates"]
        )
    )
    _rehash_report(runner, tampered)

    with pytest.raises(runner.CampaignError, match="does not replay exactly"):
        runner._verify_report_payload(tampered, expected_source_binding=binding)


def test_offline_replay_rejects_rehashed_signature_tampering(runner: Any) -> None:
    binding = _source_binding(runner)
    report = runner._build_report(binding)
    tampered = copy.deepcopy(report)
    authorization = tampered["scenarios"][2]["recovery_evaluations"][0][
        "authorization"
    ]
    authorization["signature"] = "A" * len(authorization["signature"])
    _rehash_report(runner, tampered)

    with pytest.raises(runner.CampaignError, match="does not replay exactly"):
        runner._verify_report_payload(tampered, expected_source_binding=binding)


def test_private_report_contains_no_private_key_field_or_pem(runner: Any) -> None:
    report = runner._build_report(_source_binding(runner))
    encoded = json.dumps(report, sort_keys=True)

    assert "BEGIN PRIVATE KEY" not in encoded
    assert "private_key_material_retained" in encoded
    assert not runner._private_material_flag(report)
    assert all(
        "private" not in key.lower() or key == "private_key_material_retained"
        for key in report["key_material"]
    )


def test_retained_run_uses_unique_private_output_and_self_verifies(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _source_binding(runner)
    monkeypatch.setattr(runner, "_assert_clean_source", lambda: copy.deepcopy(binding))

    first = runner.run_campaign(tmp_path)
    second = runner.run_campaign(tmp_path)

    assert first != second
    assert first.parent.parent == tmp_path
    assert first.parent.name.startswith(runner.OUTPUT_PREFIX)
    assert stat.S_IMODE(first.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert runner.verify_evidence(first)["accepted"] is True
    assert runner.verify_evidence(second)["accepted"] is True
    assert os.path.commonpath((str(first.resolve()), str(runner.ROOT.resolve()))) != str(
        runner.ROOT.resolve()
    )


def test_retained_run_rejects_checkout_output_and_dirty_source_before_creation(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _source_binding(runner)
    monkeypatch.setattr(runner, "_assert_clean_source", lambda: copy.deepcopy(binding))

    with pytest.raises(runner.CampaignError, match="outside the source checkout"):
        runner.run_campaign(runner.ROOT)

    before = tuple(tmp_path.iterdir())

    def dirty() -> dict[str, Any]:
        raise runner.CampaignError("retained M5 execution requires an exact clean checkout")

    monkeypatch.setattr(runner, "_assert_clean_source", dirty)
    with pytest.raises(runner.CampaignError, match="exact clean checkout"):
        runner.run_campaign(tmp_path)
    assert tuple(tmp_path.iterdir()) == before


def test_loader_rejects_duplicate_keys_symlinks_and_oversized_evidence(
    runner: Any,
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"one","schema_version":"two"}')
    with pytest.raises(runner.CampaignError, match="duplicate JSON key"):
        runner._load_report(duplicate)

    linked = tmp_path / "linked.json"
    linked.symlink_to(duplicate)
    with pytest.raises(runner.CampaignError, match="non-symlink"):
        runner._load_report(linked)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (runner.MAX_EVIDENCE_BYTES + 1))
    with pytest.raises(runner.CampaignError, match="outside the verifier limit"):
        runner._load_report(oversized)


def test_source_binding_shape_requires_exact_file_set_and_fingerprint(
    runner: Any,
) -> None:
    binding = _source_binding(runner)
    runner._verify_source_binding_shape(binding)

    missing = copy.deepcopy(binding)
    missing["source_files"].pop()
    missing["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(missing)
    )
    with pytest.raises(runner.CampaignError, match="exact source path set"):
        runner._verify_source_binding_shape(missing)

    bad_digest = copy.deepcopy(binding)
    bad_digest["source_fingerprint_sha256"] = "0" * 64
    with pytest.raises(runner.CampaignError, match="source fingerprint"):
        runner._verify_source_binding_shape(bad_digest)
