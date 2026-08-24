from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from aegis_ot import cli

runner = CliRunner()


def test_demo_command_writes_local_artifact(tmp_path: Path) -> None:
    output_dir = tmp_path / "demo"

    result = runner.invoke(cli.app, ["demo", "--output-dir", str(output_dir)])

    assert result.exit_code == 0, result.output
    payload = json.loads((output_dir / "demo.json").read_text(encoding="utf-8"))
    assert payload["evidence_chain_valid"] is True
    assert payload["claim_boundary"] == "synthetic local demonstration only"


def test_experiment_command_uses_requested_seed_configuration(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    captured: dict[str, Any] = {}

    def fake_seeds(seed: int, count: int) -> tuple[int, ...]:
        captured["seed_request"] = (seed, count)
        return (101, 202)

    def fake_write(
        output_dir: Path,
        trials_per_seed: int,
        master_seeds: tuple[int, ...],
    ) -> dict[str, Any]:
        captured["write"] = (output_dir, trials_per_seed, master_seeds)
        return {"summary": {"trial_record_count": 6}}

    monkeypatch.setattr(cli, "derive_master_seeds", fake_seeds)
    monkeypatch.setattr(cli, "write_multiseed_experiment", fake_write)
    output_dir = tmp_path / "m2"

    result = runner.invoke(
        cli.app,
        [
            "experiment",
            "--trials-per-seed",
            "3",
            "--seed-count",
            "2",
            "--seed",
            "99",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured == {
        "seed_request": (99, 2),
        "write": (output_dir, 3, (101, 202)),
    }
    assert json.loads(result.output)["trial_record_count"] == 6


def test_physical_experiment_command_reports_progress(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    output_dir = tmp_path / "m3"
    monkeypatch.setattr(cli, "default_master_seeds", lambda seed, count: (11, 22))

    def fake_write(
        requested_output: Path,
        master_seeds: tuple[int, ...],
        *,
        root_seed: int,
        progress: Any,
    ) -> dict[str, Any]:
        assert requested_output == output_dir
        assert master_seeds == (11, 22)
        assert root_seed == 77
        progress(1, 2)
        progress(2, 2)
        return {"summary": {"session_count": 2}}

    monkeypatch.setattr(cli, "write_m3_experiment", fake_write)

    result = runner.invoke(
        cli.app,
        [
            "physical-experiment",
            "--seed-count",
            "2",
            "--seed",
            "77",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "M3 process sessions complete: 1/2" in result.output
    assert "M3 process sessions complete: 2/2" in result.output
    assert '"session_count": 2' in result.output


def test_verify_physical_evidence_command_returns_success(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        cli,
        "verify_m3_package",
        lambda output_dir: {"valid": True, "errors": [], "checks": {"manifest": True}},
    )

    result = runner.invoke(cli.app, ["verify-physical-evidence"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["valid"] is True


def test_verify_physical_evidence_command_fails_closed(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        cli,
        "verify_m3_package",
        lambda output_dir: {
            "valid": False,
            "errors": ["artifact hash mismatch"],
            "checks": {"artifact_hashes": False},
        },
    )

    result = runner.invoke(cli.app, ["verify-physical-evidence"])

    assert result.exit_code == 1
    assert json.loads(result.output)["valid"] is False
