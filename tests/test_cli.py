from __future__ import annotations

import json
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from aegis_ot import cli
from aegis_ot.capability_models import CapabilityClosedLoopStatus

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


@pytest.mark.parametrize(
    ("status", "expected_exit"),
    [
        (CapabilityClosedLoopStatus.COMPLETED, 0),
        (CapabilityClosedLoopStatus.NOT_DISPATCHED, 1),
    ],
)
def test_capability_smoke_reports_bounded_live_status_and_fails_closed(
    status: CapabilityClosedLoopStatus,
    expected_exit: int,
    monkeypatch: Any,
) -> None:
    observed_at = datetime(2026, 8, 24, tzinfo=UTC)
    result = SimpleNamespace(
        status=status,
        reasons=("test_terminal_reason",),
        dispatch_attempts=1 if status is CapabilityClosedLoopStatus.COMPLETED else 0,
        automatic_retry_count=0,
    )
    def health(role: str) -> dict[str, str]:
        return {"role": role, "status": "ready"}

    lab = SimpleNamespace(
        initial_observation=SimpleNamespace(
            snapshot=SimpleNamespace(state_version=0, observed_at=observed_at)
        ),
        authorization=SimpleNamespace(
            root_grant=SimpleNamespace(grant_id="grant-root"),
            leaf_grant=SimpleNamespace(grant_id="grant-leaf"),
            gateway=SimpleNamespace(evidence=SimpleNamespace(verify=lambda: True)),
        ),
        controller=SimpleNamespace(execute=lambda request: result),
        request_for=lambda proposal, observation: (proposal, observation),
        topology_pids={"coordinator": 1, "plant": 2, "observer": 3, "plc": 4},
        processes=SimpleNamespace(
            plant_admin=SimpleNamespace(health=lambda: health("plant")),
            observer_admin=SimpleNamespace(health=lambda: health("observer")),
            plc_admin=SimpleNamespace(health=lambda: health("plc")),
        ),
    )
    monkeypatch.setattr(
        cli,
        "start_capability_separated_lab",
        lambda now: nullcontext(lab),
    )

    invocation = runner.invoke(cli.app, ["capability-smoke"])

    assert invocation.exit_code == expected_exit, invocation.output
    payload = json.loads(invocation.output)
    assert payload["status"] == status.value
    assert payload["automatic_retry_count"] == 0
    assert payload["evidence_chain_valid"] is True
    assert payload["topology_pids"] == lab.topology_pids
    assert payload["claim_boundary"].startswith("local implementation smoke test only")
