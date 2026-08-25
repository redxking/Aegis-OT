from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_ot.m4c_fault_experiment import run_fault_campaign, write_fault_campaign


def test_live_fault_campaign_fails_closed_without_retry() -> None:
    report = run_fault_campaign(require_clean_checkout=False)

    assert report["experiment_criteria_met"] is True
    cases = {item["condition"]: item for item in report["controller_cases"]}
    assert cases["nominal_control"]["actual_status"] == "completed"
    for name in (
        "plc_response_lost_after_commit",
        "post_observation_unavailable_after_commit",
        "post_observation_tampered_after_signing",
    ):
        assert cases[name]["actual_status"] == "unknown_effect"
        assert cases[name]["dispatch_attempts"] == 1
        assert cases[name]["automatic_retry_count"] == 0
        assert cases[name]["effect_observed_by_followup_signed_capture"] is True
    assert cases["plc_response_lost_after_commit"][
        "hidden_lost_response_acknowledgment_valid"
    ] is True
    assert cases["post_observation_tampered_after_signing"][
        "original_pre_tamper_observation_valid"
    ] is True
    assert cases["post_observation_tampered_after_signing"][
        "tampered_observation_rejected"
    ] is True
    evaluator = report["evaluator_adversarial_checks"]
    assert evaluator["signed_report_status"] == "input_rejected"
    assert evaluator["signed_report_valid"] is True
    assert evaluator["tampered_report_valid"] is False
    assert evaluator["evaluator_process_separate"] is True


def test_fault_campaign_writer_is_exclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = {
        "schema_version": "m4c-fault-campaign-v1",
        "experiment_criteria_met": True,
    }
    monkeypatch.setattr(
        "aegis_ot.m4c_fault_experiment.run_fault_campaign",
        lambda **_: report,
    )
    output = tmp_path / "fault-campaign.json"
    assert write_fault_campaign(output, require_clean_checkout=False) == report
    assert json.loads(output.read_text(encoding="utf-8")) == report
    assert output.stat().st_mode & 0o777 == 0o444
    with pytest.raises(FileExistsError):
        write_fault_campaign(output, require_clean_checkout=False)
