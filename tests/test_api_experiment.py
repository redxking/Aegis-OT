from __future__ import annotations

import json

from fastapi.testclient import TestClient

from aegis_ot.api import app
from aegis_ot.experiment import BASELINES, run_experiment, write_experiment


def test_api_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "synthetic-local"


def test_api_rejects_invalid_payload() -> None:
    response = TestClient(app).post("/v1/decisions", json={"proposal": {}, "state": {}})
    assert response.status_code == 422


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
