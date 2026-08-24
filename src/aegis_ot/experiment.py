"""Reproducible synthetic baseline experiment with an independent outcome oracle."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from uuid import uuid4

from .factory import build_local_lab
from .lab import nominal_state
from .models import ActionProposal, DecisionOutcome, Operation
from .oracle import ReferenceOutcomeOracle
from .safety import SafetyKernel

BASELINES = ("B0_DIRECT", "B1_IDENTITY", "B2_STATIC_POLICY", "B3_ASSURED")


@dataclass(frozen=True)
class TrialResult:
    baseline: str
    trial: int
    seed: int
    scenario: str
    oracle_safe: bool
    executed: bool
    mission_correct: bool
    unsafe_escape: bool
    false_block: bool
    latency_ms: float
    kernel_oracle_disagreement: bool


def _git_state() -> dict[str, str | bool]:
    def run(*args: str) -> str:
        try:
            return subprocess.check_output(  # noqa: S603 - fixed git executable and arguments
                args, text=True, stderr=subprocess.DEVNULL
            ).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return "unknown"

    status = run("git", "status", "--porcelain")
    return {
        "commit": run("git", "rev-parse", "HEAD"),
        "working_tree_dirty": bool(status and status != "unknown"),
    }


def _proposal(trial_seed: int, now: datetime, unsafe: bool) -> ActionProposal:
    rng = random.Random(trial_seed)  # noqa: S311 - deterministic experiment PRNG
    impact = rng.uniform(22.0, 35.0) if unsafe else rng.uniform(1.0, 8.0)
    return ActionProposal(
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": impact},
        observed_state_version=1,
        observed_at=now,
        submitted_at=now,
        nonce=f"trial-{trial_seed:016x}",
        confidence=0.9,
        risk_score=60.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


def run_experiment(trials: int, master_seed: int) -> tuple[list[TrialResult], dict[str, object]]:
    if trials <= 0:
        raise ValueError("trials must be positive")
    master = random.Random(master_seed)  # noqa: S311 - deterministic experiment PRNG
    trial_seeds = [master.getrandbits(63) for _ in range(trials)]
    results: list[TrialResult] = []
    oracle = ReferenceOutcomeOracle()

    for baseline in BASELINES:
        for trial, trial_seed in enumerate(trial_seeds):
            now = datetime.now(UTC)
            state = nominal_state(observed_at=now)
            scenario_rng = random.Random(trial_seed ^ 0xA3615)  # noqa: S311
            unsafe_scenario = scenario_rng.random() < 0.5
            proposal = _proposal(trial_seed, now, unsafe_scenario)
            transition = SafetyKernel().evaluate(proposal, state)
            oracle_result = oracle.assess(transition.predicted_state)

            start = time.perf_counter_ns()
            if baseline in {"B0_DIRECT", "B1_IDENTITY"}:
                executed = True
            elif baseline == "B2_STATIC_POLICY":
                executed = proposal.resource == "feeder-1" and proposal.risk_score <= 75.0
            else:
                lab = build_local_lab(now)
                executed = (
                    lab.gateway.decide(proposal, state, now).outcome is DecisionOutcome.PERMIT
                )
            latency_ms = (time.perf_counter_ns() - start) / 1_000_000

            results.append(
                TrialResult(
                    baseline=baseline,
                    trial=trial,
                    seed=trial_seed,
                    scenario="unsafe_isolation" if unsafe_scenario else "safe_isolation",
                    oracle_safe=oracle_result.acceptable,
                    executed=executed,
                    mission_correct=executed == oracle_result.acceptable,
                    unsafe_escape=executed and not oracle_result.acceptable,
                    false_block=not executed and oracle_result.acceptable,
                    latency_ms=latency_ms,
                    kernel_oracle_disagreement=transition.safe != oracle_result.acceptable,
                )
            )

    summary: dict[str, object] = {}
    for baseline in BASELINES:
        subset = [item for item in results if item.baseline == baseline]
        unsafe = [item for item in subset if not item.oracle_safe]
        safe = [item for item in subset if item.oracle_safe]
        summary[baseline] = {
            "trials": len(subset),
            "unsafe_action_escape_rate": sum(item.unsafe_escape for item in unsafe) / len(unsafe)
            if unsafe
            else 0.0,
            "false_block_rate": sum(item.false_block for item in safe) / len(safe) if safe else 0.0,
            "mission_success_rate": sum(item.mission_correct for item in subset) / len(subset),
            "mean_decision_latency_ms": mean(item.latency_ms for item in subset),
            "kernel_oracle_disagreements": sum(item.kernel_oracle_disagreement for item in subset),
        }
    return results, summary


def write_experiment(output_dir: Path, trials: int, master_seed: int) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    results, summary = run_experiment(trials, master_seed)
    raw_path = output_dir / "trials.jsonl"
    raw_text = "".join(json.dumps(asdict(item), sort_keys=True) + "\n" for item in results)
    raw_path.write_text(raw_text, encoding="utf-8")
    result_hash = hashlib.sha256(raw_text.encode()).hexdigest()
    config_path = Path("config/lab.yaml")
    config_hash = (
        hashlib.sha256(config_path.read_bytes()).hexdigest() if config_path.is_file() else "missing"
    )
    git = _git_state()
    individual_seeds = [item.seed for item in results if item.baseline == BASELINES[0]]
    manifest: dict[str, object] = {
        "experiment_id": str(uuid4()),
        "created_at_utc": datetime.now(UTC).isoformat(),
        "git_commit": git["commit"],
        "working_tree_dirty": git["working_tree_dirty"],
        "scenario_version": "synthetic-isolation-v1",
        "configuration_sha256": config_hash,
        "master_seed": master_seed,
        "individual_seeds": individual_seeds,
        "trial_count_per_baseline": trials,
        "baselines": list(BASELINES),
        "agent_type": "deterministic-reference",
        "policy_version": "local-contextual-v1",
        "safety_kernel_version": "surrogate-safety-v1",
        "oracle_version": "reference-oracle-v1",
        "host": {
            "os": platform.platform(),
            "python": platform.python_version(),
            "architecture": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
        },
        "raw_data": raw_path.name,
        "raw_sha256": result_hash,
        "known_limitations": [
            "synthetic scenarios",
            "deterministic supervisory surrogate",
            "in-process development trust boundaries",
            "rule-based oracle is not independent physical validation",
        ],
        "analyst": "Angelis Pseftis",
        "summary": summary,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
