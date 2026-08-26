from __future__ import annotations

import copy
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("run_m5_degraded")


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


def _rehash(runner: Any, report: dict[str, Any]) -> None:
    report.pop("integrity", None)
    report["integrity"] = {"canonical_payload_sha256": runner._sha256_json(report)}


def test_v2_plan_is_fixed_and_preserves_formal_claim_boundaries(runner: Any) -> None:
    plan = runner.build_plan()

    assert plan["schema_version"] == "aegis-ot-m5-degraded-operation-plan-v2"
    assert plan["case_count"] == 90
    assert set(plan["roles"]) == {role.value for role in runner.degraded.DegradedRole}
    assert plan["surfaces"] == ["service", "communication"]
    assert plan["conditions"] == [
        "unavailable",
        "unknown",
        "conflicting",
        "untrusted",
        "compromised",
    ]
    assert not plan["execution_claimed"]


def test_v2_campaign_replays_all_roles_and_retains_no_operational_claim(
    runner: Any,
) -> None:
    binding = _source_binding(runner)
    first = runner._build_report(binding)
    second = runner._build_report(binding)

    assert first["accepted"]
    assert all(first["acceptance_gates"].values())
    assert len(first["scenarios"]) == 90
    assert first["semantic_outcome_sha256"] == second["semantic_outcome_sha256"]
    assert first["key_material"]["private_key_material_retained"] is False
    assert all(value is False for value in first["claim_boundaries"].values())
    runner._verify_report_payload(first, expected_source_binding=binding)


def test_v2_offline_replay_rejects_rehashed_admission_tampering(runner: Any) -> None:
    binding = _source_binding(runner)
    tampered = copy.deepcopy(runner._build_report(binding))
    tampered["scenarios"][0]["result"]["execution_authorized"] = True
    tampered["semantic_outcome_sha256"] = runner._sha256_json(
        runner._semantic_projection(tampered)
    )
    _rehash(runner, tampered)

    with pytest.raises(runner.CampaignError, match="scenario material is invalid"):
        runner._verify_report_payload(tampered, expected_source_binding=binding)
