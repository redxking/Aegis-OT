"""Reproducible synthetic experiment with independent outcome evaluation."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import random
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import mean
from typing import Any
from uuid import uuid4

from .factory import LocalLab, build_local_lab
from .lab import nominal_state
from .models import ActionProposal, DecisionOutcome, Operation, SystemState
from .oracle import ReferenceOutcomeOracle
from .safety import SafetyKernel

ROOT = Path(__file__).resolve().parents[2]
SCENARIO_CATALOG = ROOT / "config" / "scenarios-v2.json"
REFERENCE_TIME = datetime(2026, 8, 24, 16, 0, tzinfo=UTC)
BASELINES = (
    "B0_DIRECT",
    "B1_IDENTITY",
    "B2_STATIC_POLICY",
    "B3_ASSURED",
    "B4_CONTEXTUAL_ABAC",
    "B5_RISK_AWARE",
    "B6_SAFETY_NO_DELEGATION",
    "B7_DELEGATION_NO_FRESHNESS",
)


@dataclass(frozen=True)
class ScenarioDefinition:
    name: str
    operation: Operation
    resource: str
    parameters: dict[str, float]
    authorization_expected: bool
    rationale: str
    proposal_updates: dict[str, Any]
    evaluation_delay_seconds: int = 0


@dataclass(frozen=True)
class TrialResult:
    baseline: str
    master_seed: int
    trial: int
    seed: int
    scenario: str
    authorization_expected: bool
    oracle_safe: bool
    oracle_violations: tuple[str, ...]
    kernel_safe: bool
    executed: bool
    mission_correct: bool
    physical_unsafe_escape: bool
    unauthorized_execution: bool
    false_block: bool
    latency_ms: float
    kernel_oracle_disagreement: bool

    @property
    def unsafe_escape(self) -> bool:
        """Compatibility alias for the original experiment vocabulary."""
        return self.physical_unsafe_escape


def load_scenarios(path: Path = SCENARIO_CATALOG) -> tuple[str, tuple[ScenarioDefinition, ...]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    scenarios: list[ScenarioDefinition] = []
    names: set[str] = set()
    for raw in payload["scenarios"]:
        name = str(raw["name"])
        if name in names:
            raise ValueError(f"duplicate scenario name: {name}")
        names.add(name)
        scenarios.append(
            ScenarioDefinition(
                name=name,
                operation=Operation(raw["operation"]),
                resource=str(raw["resource"]),
                parameters={key: float(value) for key, value in raw["parameters"].items()},
                authorization_expected=bool(raw["authorization_expected"]),
                rationale=str(raw["rationale"]),
                proposal_updates=dict(raw.get("proposal_updates", {})),
                evaluation_delay_seconds=int(raw.get("evaluation_delay_seconds", 0)),
            )
        )
    if not scenarios:
        raise ValueError("scenario catalog must not be empty")
    return str(payload["catalog_version"]), tuple(scenarios)


def derive_master_seeds(seed: int, count: int) -> tuple[int, ...]:
    if count <= 0:
        raise ValueError("seed count must be positive")
    generator = random.Random(seed)  # noqa: S311 - deterministic experiment PRNG
    return tuple(generator.getrandbits(63) for _ in range(count))


def _git_state() -> dict[str, str | bool]:
    def run(*args: str) -> str:
        try:
            return subprocess.check_output(  # noqa: S603 - fixed git executable and arguments
                args, text=True, stderr=subprocess.DEVNULL, cwd=ROOT
            ).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return "unknown"

    status = run("git", "status", "--porcelain")
    return {
        "commit": run("git", "rev-parse", "HEAD"),
        "working_tree_dirty": bool(status and status != "unknown"),
    }


def _proposal(
    scenario: ScenarioDefinition, trial_seed: int, observed_at: datetime
) -> ActionProposal:
    values: dict[str, Any] = {
        "proposal_id": f"proposal-{trial_seed:016x}",
        "actor_id": "agent:operator-1",
        "mission_id": "microgrid-containment",
        "resource": scenario.resource,
        "operation": scenario.operation,
        "parameters": scenario.parameters,
        "observed_state_version": 1,
        "observed_at": observed_at,
        "submitted_at": observed_at,
        "nonce": f"trial-{trial_seed:016x}",
        "confidence": 0.9,
        "risk_score": 60.0,
        "delegation_chain": ("grant-root", "grant-leaf"),
    }
    values.update(scenario.proposal_updates)
    return ActionProposal(**values)


def _scenario_sequence(
    scenarios: tuple[ScenarioDefinition, ...], trials: int, master_seed: int
) -> list[ScenarioDefinition]:
    generator = random.Random(master_seed ^ 0xA3615)  # noqa: S311
    sequence: list[ScenarioDefinition] = []
    while len(sequence) < trials:
        cycle = list(scenarios)
        generator.shuffle(cycle)
        sequence.extend(cycle)
    return sequence[:trials]


def _execute_baseline(
    baseline: str,
    proposal: ActionProposal,
    state: SystemState,
    evaluated_at: datetime,
    lab: LocalLab,
    kernel_safe: bool,
) -> bool:
    identity_ok = lab.gateway.identity.verify(proposal.actor_id)
    policy_ok = lab.gateway.policy.evaluate(proposal, state).permitted
    fresh = timedelta(0) <= evaluated_at - state.observed_at <= lab.gateway.maximum_state_age
    observation_matches = proposal.observed_at == state.observed_at
    delegation_ok = lab.gateway.delegation.validate(proposal, evaluated_at).valid

    if baseline == "B0_DIRECT":
        return True
    if baseline == "B1_IDENTITY":
        return identity_ok
    if baseline == "B2_STATIC_POLICY":
        return identity_ok and proposal.resource == "feeder-1" and proposal.risk_score <= 75.0
    if baseline == "B3_ASSURED":
        return lab.gateway.decide(proposal, state, evaluated_at).outcome is DecisionOutcome.PERMIT
    if baseline == "B4_CONTEXTUAL_ABAC":
        return identity_ok and policy_ok and fresh and observation_matches
    if baseline == "B5_RISK_AWARE":
        return identity_ok and policy_ok and proposal.risk_score < 75.0
    if baseline == "B6_SAFETY_NO_DELEGATION":
        return identity_ok and policy_ok and fresh and observation_matches and kernel_safe
    if baseline == "B7_DELEGATION_NO_FRESHNESS":
        return identity_ok and delegation_ok and policy_ok and kernel_safe
    raise ValueError(f"unknown baseline: {baseline}")


def _wilson(successes: int, total: int) -> dict[str, float | int]:
    if total == 0:
        return {"estimate": 0.0, "lower": 0.0, "upper": 0.0, "denominator": 0}
    z = 1.959963984540054
    estimate = successes / total
    denominator = 1 + z**2 / total
    center = (estimate + z**2 / (2 * total)) / denominator
    margin = z * math.sqrt(estimate * (1 - estimate) / total + z**2 / (4 * total**2))
    margin /= denominator
    lower = 0.0 if successes == 0 else max(0.0, center - margin)
    upper = 1.0 if successes == total else min(1.0, center + margin)
    return {
        "estimate": estimate,
        "lower": lower,
        "upper": upper,
        "denominator": total,
    }


def _summarize(results: list[TrialResult]) -> dict[str, object]:
    summary: dict[str, object] = {}
    for baseline in BASELINES:
        subset = [item for item in results if item.baseline == baseline]
        unsafe = [item for item in subset if not item.oracle_safe]
        unauthorized = [item for item in subset if not item.authorization_expected]
        desired = [item for item in subset if item.authorization_expected and item.oracle_safe]
        unsafe_count = sum(item.physical_unsafe_escape for item in unsafe)
        unauthorized_count = sum(item.unauthorized_execution for item in unauthorized)
        false_block_count = sum(item.false_block for item in desired)
        mission_count = sum(item.mission_correct for item in subset)
        summary[baseline] = {
            "trials": len(subset),
            "unsafe_action_escape_rate": unsafe_count / len(unsafe) if unsafe else 0.0,
            "unsafe_action_escape_ci95": _wilson(unsafe_count, len(unsafe)),
            "unauthorized_execution_rate": unauthorized_count / len(unauthorized)
            if unauthorized
            else 0.0,
            "unauthorized_execution_ci95": _wilson(unauthorized_count, len(unauthorized)),
            "false_block_rate": false_block_count / len(desired) if desired else 0.0,
            "false_block_ci95": _wilson(false_block_count, len(desired)),
            "mission_success_rate": mission_count / len(subset),
            "mission_success_ci95": _wilson(mission_count, len(subset)),
            "mean_decision_latency_ms": mean(item.latency_ms for item in subset),
            "kernel_oracle_disagreements": sum(item.kernel_oracle_disagreement for item in subset),
        }
    return summary


def run_multiseed_experiment(
    trials_per_seed: int, master_seeds: tuple[int, ...]
) -> tuple[list[TrialResult], dict[str, object]]:
    if trials_per_seed <= 0:
        raise ValueError("trials_per_seed must be positive")
    if not master_seeds:
        raise ValueError("at least one master seed is required")
    _, scenarios = load_scenarios()
    oracle = ReferenceOutcomeOracle()
    kernel = SafetyKernel()
    results: list[TrialResult] = []

    for master_index, master_seed in enumerate(master_seeds):
        generator = random.Random(master_seed)  # noqa: S311
        trial_seeds = [generator.getrandbits(63) for _ in range(trials_per_seed)]
        selected = _scenario_sequence(scenarios, trials_per_seed, master_seed)
        observed_at = REFERENCE_TIME + timedelta(days=master_index)
        for baseline in BASELINES:
            lab = build_local_lab(observed_at)
            for trial, (trial_seed, scenario) in enumerate(zip(trial_seeds, selected, strict=True)):
                state = nominal_state(observed_at=observed_at)
                proposal = _proposal(scenario, trial_seed, observed_at)
                evaluated_at = observed_at + timedelta(seconds=scenario.evaluation_delay_seconds)
                oracle_result = oracle.assess(proposal, state)
                kernel_result = kernel.evaluate(proposal, state)
                start = time.perf_counter_ns()
                executed = _execute_baseline(
                    baseline, proposal, state, evaluated_at, lab, kernel_result.safe
                )
                latency_ms = (time.perf_counter_ns() - start) / 1_000_000
                desired_execute = scenario.authorization_expected and oracle_result.acceptable
                results.append(
                    TrialResult(
                        baseline=baseline,
                        master_seed=master_seed,
                        trial=trial,
                        seed=trial_seed,
                        scenario=scenario.name,
                        authorization_expected=scenario.authorization_expected,
                        oracle_safe=oracle_result.acceptable,
                        oracle_violations=oracle_result.violations,
                        kernel_safe=kernel_result.safe,
                        executed=executed,
                        mission_correct=executed == desired_execute,
                        physical_unsafe_escape=executed and not oracle_result.acceptable,
                        unauthorized_execution=executed and not scenario.authorization_expected,
                        false_block=not executed and desired_execute,
                        latency_ms=latency_ms,
                        kernel_oracle_disagreement=kernel_result.safe != oracle_result.acceptable,
                    )
                )
    return results, _summarize(results)


def run_experiment(trials: int, master_seed: int) -> tuple[list[TrialResult], dict[str, object]]:
    """Compatibility wrapper for a single master seed."""
    return run_multiseed_experiment(trials, (master_seed,))


def _outcome_payload(item: TrialResult) -> dict[str, object]:
    payload = asdict(item)
    payload.pop("latency_ms")
    return payload


def write_multiseed_experiment(
    output_dir: Path, trials_per_seed: int, master_seeds: tuple[int, ...]
) -> dict[str, object]:
    git = _git_state()
    output_dir.mkdir(parents=True, exist_ok=True)
    results, summary = run_multiseed_experiment(trials_per_seed, master_seeds)
    raw_path = output_dir / "trials.jsonl"
    raw_text = "".join(json.dumps(asdict(item), sort_keys=True) + "\n" for item in results)
    raw_path.write_text(raw_text, encoding="utf-8")
    outcome_text = "".join(
        json.dumps(_outcome_payload(item), sort_keys=True) + "\n" for item in results
    )
    catalog_version, scenarios = load_scenarios()
    source_paths = (
        Path(__file__),
        Path(__file__).with_name("oracle.py"),
        Path(__file__).with_name("safety.py"),
    )
    manifest: dict[str, object] = {
        "experiment_id": str(uuid4()),
        "created_at_utc": datetime.now(UTC).isoformat(),
        "git_commit": git["commit"],
        "working_tree_dirty": git["working_tree_dirty"],
        "scenario_version": catalog_version,
        "scenario_catalog": str(SCENARIO_CATALOG.relative_to(ROOT)),
        "scenario_catalog_sha256": hashlib.sha256(SCENARIO_CATALOG.read_bytes()).hexdigest(),
        "scenario_count": len(scenarios),
        "master_seeds": list(master_seeds),
        "master_seed_count": len(master_seeds),
        "trials_per_seed_per_baseline": trials_per_seed,
        "total_trial_records": len(results),
        "baselines": list(BASELINES),
        "policy_version": "local-contextual-v1",
        "safety_kernel_version": SafetyKernel.version,
        "oracle_version": ReferenceOutcomeOracle.version,
        "source_sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source_paths
        },
        "host": {
            "os": platform.platform(),
            "python": platform.python_version(),
            "architecture": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
        },
        "raw_data": raw_path.name,
        "raw_sha256": hashlib.sha256(raw_text.encode()).hexdigest(),
        "deterministic_outcome_sha256": hashlib.sha256(outcome_text.encode()).hexdigest(),
        "known_limitations": [
            "human-reviewed synthetic scenario truth, not field measurements",
            "independently implemented rule-based oracle, not a physical simulator",
            "deterministic supervisory state transitions",
            "in-process development trust boundaries",
            "latency measurements are host-specific and excluded from the "
            "deterministic outcome hash",
        ],
        "analyst": "Angelis Pseftis",
        "summary": summary,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def write_experiment(output_dir: Path, trials: int, master_seed: int) -> dict[str, object]:
    """Compatibility wrapper for the original single-seed interface."""
    return write_multiseed_experiment(output_dir, trials, (master_seed,))
