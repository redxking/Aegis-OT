from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient

import aegis_ot.api as api_module
from aegis_ot.api import app
from aegis_ot.experiment import BASELINES, run_experiment, write_experiment


def test_api_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "synthetic-local"


def test_api_rejects_invalid_payload() -> None:
    response = TestClient(app).post("/v1/decisions", json={"proposal": {}, "state": {}})
    assert response.status_code == 422


def test_api_rejects_operation_inconsistent_parameters(proposal, state) -> None:
    payload = {
        "proposal": proposal.model_dump(mode="json"),
        "state": state.model_dump(mode="json"),
    }
    payload["proposal"]["parameters"] = {"shell_command": 1.0}
    response = TestClient(app).post("/v1/decisions", json=payload)
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
    client = TestClient(app)
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
        assert first_summary[baseline]["unsafe_action_escape_rate"] == second_summary[baseline][
            "unsafe_action_escape_rate"
        ]


def test_experiment_writes_hashed_manifest(tmp_path) -> None:
    manifest = write_experiment(tmp_path, 3, 7)
    assert (tmp_path / "trials.jsonl").is_file()
    persisted = json.loads((tmp_path / "manifest.json").read_text())
    assert persisted["raw_sha256"] == manifest["raw_sha256"]
    assert persisted["analyst"] == "Angelis Pseftis"
