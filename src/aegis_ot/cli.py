"""Aegis-OT command-line interface."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer

from .experiment import derive_master_seeds, write_multiseed_experiment
from .factory import build_local_lab
from .lab import SimulatedCommandAdapter, nominal_state
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


@app.command()
def experiment(
    trials_per_seed: int = typer.Option(36, min=1),
    seed_count: int = typer.Option(30, min=1),
    seed: int = 20260824,
    output_dir: Path = Path("results/m2-independent-oracle"),
) -> None:
    master_seeds = derive_master_seeds(seed, seed_count)
    manifest = write_multiseed_experiment(output_dir, trials_per_seed, master_seeds)
    typer.echo(json.dumps(manifest["summary"], indent=2))


if __name__ == "__main__":
    app()
