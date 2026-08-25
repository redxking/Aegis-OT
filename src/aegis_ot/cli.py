"""Aegis-OT command-line interface."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer

from .capability_factory import start_capability_separated_lab
from .capability_models import CapabilityClosedLoopStatus
from .experiment import derive_master_seeds, write_multiseed_experiment
from .factory import build_local_lab
from .lab import SimulatedCommandAdapter, nominal_state
from .m3_experiment import (
    MAX_M3_SESSIONS,
    default_master_seeds,
    verify_m3_package,
    write_m3_experiment,
)
from .m4b_package import verify_m4b_package, write_m4b_experiment
from .m4c_fault_experiment import write_fault_campaign
from .models import ActionProposal, Operation

app = typer.Typer(no_args_is_help=True)


@app.command()
def demo(output_dir: Path = Path("results/demo")) -> None:
    now = datetime.now(UTC)
    lab = build_local_lab(now)
    state = nominal_state(observed_at=now)
    proposal = ActionProposal(
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=state.version,
        observed_at=state.observed_at,
        nonce=f"demo-{now.timestamp():.6f}",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=(lab.root_grant.grant_id, lab.leaf_grant.grant_id),
    )
    decision = lab.gateway.decide(proposal, state, now)
    execution = SimulatedCommandAdapter().execute(proposal, decision, state)
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "proposal": proposal.model_dump(mode="json"),
        "decision": decision.model_dump(mode="json"),
        "execution": execution.model_dump(mode="json"),
        "evidence_chain_valid": lab.gateway.evidence.verify(),
        "claim_boundary": "synthetic local demonstration only",
    }
    (output_dir / "demo.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    typer.echo(json.dumps(payload, indent=2))


@app.command("capability-smoke")
def capability_smoke() -> None:
    """Run one bounded same-host capability-separated control transaction."""

    now = datetime.now(UTC)
    with start_capability_separated_lab(now) as lab:
        observation = lab.initial_observation
        proposal = ActionProposal(
            actor_id="agent:operator-1",
            mission_id="microgrid-containment",
            resource="feeder-1",
            operation=Operation.ISOLATE_ASSET,
            parameters={"critical_load_impact_pct": 5.0},
            observed_state_version=observation.snapshot.state_version,
            observed_at=observation.snapshot.observed_at,
            submitted_at=observation.snapshot.observed_at,
            nonce=f"capability-smoke-{now.timestamp():.6f}",
            confidence=0.95,
            risk_score=40.0,
            delegation_chain=(
                lab.authorization.root_grant.grant_id,
                lab.authorization.leaf_grant.grant_id,
            ),
        )
        result = lab.controller.execute(lab.request_for(proposal, observation))
        payload = {
            "schema_version": "capability-smoke-v1",
            "status": result.status.value,
            "reasons": list(result.reasons),
            "topology_pids": lab.topology_pids,
            "dispatch_attempts": result.dispatch_attempts,
            "automatic_retry_count": result.automatic_retry_count,
            "plant": lab.processes.plant_admin.health(),
            "observer": lab.processes.observer_admin.health(),
            "plc": lab.processes.plc_admin.health(),
            "evidence_chain_valid": lab.authorization.gateway.evidence.verify(),
            "claim_boundary": (
                "local implementation smoke test only; not HELICS, OpenPLC, "
                "segmented deployment, hardware, or external validation"
            ),
        }
    typer.echo(json.dumps(payload, indent=2))
    if result.status is not CapabilityClosedLoopStatus.COMPLETED:
        raise typer.Exit(code=1)


@app.command()
def experiment(
    trials_per_seed: int = typer.Option(36, min=1),
    seed_count: int = typer.Option(30, min=1, max=MAX_M3_SESSIONS),
    seed: int = 20260824,
    output_dir: Path = Path("results/m2-independent-oracle"),
) -> None:
    master_seeds = derive_master_seeds(seed, seed_count)
    manifest = write_multiseed_experiment(output_dir, trials_per_seed, master_seeds)
    typer.echo(json.dumps(manifest["summary"], indent=2))


@app.command("physical-experiment")
def physical_experiment(
    seed_count: int = typer.Option(30, min=1),
    seed: int = 20260824,
    output_dir: Path = Path("results/m3-physical-modbus"),
) -> None:
    """Run the bounded M3 pandapower/PyModbus process experiment."""

    master_seeds = default_master_seeds(seed, seed_count)

    def progress(completed: int, total: int) -> None:
        typer.echo(f"M3 process sessions complete: {completed}/{total}")

    manifest = write_m3_experiment(
        output_dir,
        master_seeds,
        root_seed=seed,
        progress=progress,
    )
    typer.echo(json.dumps(manifest["summary"], indent=2))


@app.command("verify-physical-evidence")
def verify_physical_evidence(
    output_dir: Path = Path("results/m3-physical-modbus"),
) -> None:
    """Verify retained M3 package integrity and internal consistency."""

    report = verify_m3_package(output_dir)
    typer.echo(json.dumps(report, indent=2))
    if not report["valid"]:
        raise typer.Exit(code=1)


@app.command("capability-experiment")
def capability_experiment(
    seed_count: int = typer.Option(30, min=1, max=100),
    seed: int = 20260825,
    output_dir: Path = Path("results/m4b-capability-evidence"),
    trust_anchor: Path = Path("results/m4b-capability-evidence.trust-anchor.json"),
    require_clean_checkout: bool = typer.Option(
        True,
        "--require-clean/--allow-dirty",
    ),
) -> None:
    """Run and retain the bounded M4b capability/consequence experiment."""

    def progress(completed: int, total: int) -> None:
        typer.echo(f"M4b process sessions complete: {completed}/{total}")

    write_m4b_experiment(
        output_dir,
        trust_anchor_path=trust_anchor,
        root_seed=seed,
        seed_count=seed_count,
        progress=progress,
        require_clean_checkout=require_clean_checkout,
    )
    report = verify_m4b_package(
        output_dir,
        trust_anchor,
        checkout_root=Path.cwd(),
    )
    typer.echo(json.dumps(report, indent=2))
    if (
        report["package_valid"] is not True
        or report["experiment_accepted"] is not True
        or report["checkout_matches"] is not True
    ):
        raise typer.Exit(code=1)


@app.command("verify-capability-evidence")
def verify_capability_evidence(
    output_dir: Path = Path("results/m4b-capability-evidence"),
    trust_anchor: Path = Path("results/m4b-capability-evidence.trust-anchor.json"),
    checkout_root: Path = Path("."),
    check_checkout: bool = typer.Option(
        True,
        "--check-checkout/--skip-checkout",
    ),
) -> None:
    """Offline-verify M4b integrity, acceptance, and optional checkout binding."""

    report = verify_m4b_package(
        output_dir,
        trust_anchor,
        checkout_root=checkout_root if check_checkout else None,
    )
    typer.echo(json.dumps(report, indent=2))
    failed = (
        report["package_valid"] is not True
        or report["experiment_accepted"] is not True
        or (check_checkout and report["checkout_matches"] is not True)
    )
    if failed:
        raise typer.Exit(code=1)


@app.command("capability-fault-experiment")
def capability_fault_experiment(
    output_path: Path = Path("results/m4c-fault-campaign-v6.json"),
    require_clean_checkout: bool = typer.Option(
        True,
        "--require-clean/--allow-dirty",
    ),
) -> None:
    """Run and retain bounded live-process fault and evaluator-adversarial checks."""

    def progress(completed: int, total: int) -> None:
        typer.echo(f"M4c controller fault cases complete: {completed}/{total}")

    report = write_fault_campaign(
        output_path,
        progress=progress,
        require_clean_checkout=require_clean_checkout,
    )
    typer.echo(json.dumps(report, indent=2))
    if report["experiment_criteria_met"] is not True:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
