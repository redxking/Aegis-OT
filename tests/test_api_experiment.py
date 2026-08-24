from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Event

from fastapi.testclient import TestClient

import aegis_ot.api as api_module
from aegis_ot.api import control_app, public_app
from aegis_ot.experiment import (
    BASELINES,
    derive_master_seeds,
    load_scenarios,
    run_experiment,
    run_multiseed_experiment,
    write_experiment,
    write_multiseed_experiment,
)


def test_api_health() -> None:
    response = TestClient(public_app).get("/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "synthetic-local"
    assert response.json()["public_demo"] == "/demo"


def test_public_app_does_not_initialize_mutable_control_state(monkeypatch) -> None:
    monkeypatch.setattr(api_module, "_lab", None)
    response = TestClient(public_app).get("/health")

    assert response.status_code == 200
    assert api_module._lab is None


def test_local_control_lab_initializes_once_under_concurrency(monkeypatch) -> None:
    built_lab = api_module.build_local_lab(datetime.now(UTC))
    build_started = Event()
    allow_build_to_finish = Event()
    build_calls = []

    def controlled_build(_now):  # noqa: ANN001, ANN202
        build_calls.append(True)
        build_started.set()
        assert allow_build_to_finish.wait(timeout=2)
        return built_lab

    monkeypatch.setattr(api_module, "_lab", None)
    monkeypatch.setattr(api_module, "build_local_lab", controlled_build)
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(api_module._local_control_lab) for _ in range(8)]
        assert build_started.wait(timeout=2)
        allow_build_to_finish.set()
        results = [future.result(timeout=2) for future in futures]

    assert build_calls == [True]
    assert all(result is built_lab for result in results)


def test_api_rejects_invalid_payload() -> None:
    response = TestClient(control_app).post(
        "/v1/decisions", json={"proposal": {}, "state": {}}
    )
    assert response.status_code == 422


def test_api_rejects_operation_inconsistent_parameters(proposal, state) -> None:
    payload = {
        "proposal": proposal.model_dump(mode="json"),
        "state": state.model_dump(mode="json"),
    }
    payload["proposal"]["parameters"] = {"shell_command": 1.0}
    response = TestClient(control_app).post("/v1/decisions", json=payload)
    assert response.status_code == 422


def test_api_state_and_valid_decision(proposal, state, monkeypatch) -> None:
    evaluated_at = datetime.now(UTC)
    current_lab = api_module.build_local_lab(evaluated_at)
    current_state = state.model_copy(update={"observed_at": evaluated_at})
    current_proposal = proposal.model_copy(
        update={
            "observed_at": evaluated_at,
            "submitted_at": evaluated_at,
        }
    )
    monkeypatch.setattr(api_module, "_lab", current_lab)
    client = TestClient(control_app)
    state_response = client.get("/v1/state")
    assert state_response.status_code == 200
    assert state_response.json()["version"] == 1

    decision_response = client.post(
        "/v1/decisions",
        json={
            "proposal": current_proposal.model_dump(mode="json"),
            "state": current_state.model_dump(mode="json"),
        },
    )
    assert decision_response.status_code == 200
    assert decision_response.json()["outcome"] == "permit"


def test_experiment_is_deterministic_in_outcomes() -> None:
    first, first_summary = run_experiment(10, 20260824)
    second, second_summary = run_experiment(10, 20260824)
    assert [(item.seed, item.scenario, item.executed) for item in first] == [
        (item.seed, item.scenario, item.executed) for item in second
    ]
    for baseline in BASELINES:
        assert (
            first_summary[baseline]["unsafe_action_escape_rate"]
            == second_summary[baseline]["unsafe_action_escape_rate"]
        )


def test_experiment_writes_hashed_manifest(tmp_path) -> None:
    manifest = write_experiment(tmp_path, 3, 7)
    assert (tmp_path / "trials.jsonl").is_file()
    persisted = json.loads((tmp_path / "manifest.json").read_text())
    assert persisted["raw_sha256"] == manifest["raw_sha256"]
    assert persisted["analyst"] == "Angelis Pseftis"


def test_scenario_catalog_is_unique_and_exercised() -> None:
    version, scenarios = load_scenarios()
    results, _ = run_experiment(len(scenarios), 19)
    assert version == "synthetic-microgrid-v2"
    assert len({scenario.name for scenario in scenarios}) == len(scenarios)
    assert {item.scenario for item in results if item.baseline == BASELINES[0]} == {
        scenario.name for scenario in scenarios
    }


def test_multiseed_summary_has_all_baselines_and_bounded_intervals() -> None:
    seeds = derive_master_seeds(7, 3)
    results, summary = run_multiseed_experiment(12, seeds)
    assert len(results) == 3 * 12 * len(BASELINES)
    assert set(summary) == set(BASELINES)
    nominal_impacts = {
        item.parameters["critical_load_impact_pct"]
        for item in results
        if item.baseline == BASELINES[0] and item.scenario == "nominal_isolation"
    }
    assert len(nominal_impacts) > 1
    for baseline in BASELINES:
        interval = summary[baseline]["mission_success_ci95"]
        assert 0.0 <= interval["lower"] <= interval["estimate"] <= interval["upper"] <= 1.0


def test_deterministic_outcome_hash_excludes_host_timing(tmp_path) -> None:
    seeds = derive_master_seeds(11, 2)
    first = write_multiseed_experiment(tmp_path / "first", 12, seeds)
    second = write_multiseed_experiment(tmp_path / "second", 12, seeds)
    assert first["deterministic_outcome_sha256"] == second["deterministic_outcome_sha256"]


def test_manifest_captures_git_state_before_writing(tmp_path, monkeypatch) -> None:
    calls = []

    def git_state():  # noqa: ANN202
        calls.append((tmp_path / "evidence").exists())
        return {"commit": "test-commit", "working_tree_dirty": False}

    monkeypatch.setattr("aegis_ot.experiment._git_state", git_state)
    manifest = write_multiseed_experiment(tmp_path / "evidence", 1, (7,))
    assert calls == [False]
    assert manifest["git_commit"] == "test-commit"
    assert manifest["working_tree_dirty"] is False
