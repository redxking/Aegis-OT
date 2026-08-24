"""Build the public-demo projection after validating its retained evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any, Final, Literal

from aegis_ot.m3_experiment import verify_m3_package
from aegis_ot.public_demo import PublicDemoEvidence

ROOT = Path(__file__).resolve().parents[1]
M2_PACKAGE_DIR = ROOT / "results" / "m2-independent-oracle"
M2_MANIFEST_PATH = M2_PACKAGE_DIR / "manifest.json"
M2_TRIALS_PATH = M2_PACKAGE_DIR / "trials.jsonl"
M3_PACKAGE_DIR = ROOT / "results" / "m3-physical-modbus"
M3_REPRODUCTION_PACKAGE_DIR = ROOT / "results" / "m3-physical-modbus-reproduction"
M3_MANIFEST_PATH = M3_PACKAGE_DIR / "manifest.json"
M3_SUMMARY_PATH = M3_PACKAGE_DIR / "summary.json"
M3_REPRODUCTION_MANIFEST_PATH = M3_REPRODUCTION_PACKAGE_DIR / "manifest.json"
OUTPUT_PATH = ROOT / "src" / "aegis_ot" / "web_demo" / "evidence.json"

M2_EXECUTION_COMMIT = "cd20986ac31eb224d6678875e63f8e8a907d1b76"
M2_RETENTION_COMMIT = "bc6130f150b4ebc9ac944433b67aa8dfdee78dfb"
M3_EXECUTION_COMMIT = "168b8bd61a13f70e0871d36e56acbe76a8ebb659"
M3_RETENTION_COMMIT = "0c48c39ae5eb575791e2bf58bfa49a8d61538524"
_git_executable = shutil.which("git")
if _git_executable is None:
    raise RuntimeError("Git is required to bind displayed evidence to recorded commits")
GIT_EXECUTABLE: Final[str] = _git_executable

BASELINE_LABELS = {
    "B0_DIRECT": "Direct access",
    "B1_IDENTITY": "Identity only",
    "B2_STATIC_POLICY": "Static policy",
    "B3_ASSURED": "Assured path",
    "B4_CONTEXTUAL_ABAC": "Contextual ABAC",
    "B5_RISK_AWARE": "Risk-aware policy",
    "B6_SAFETY_NO_DELEGATION": "Safety without delegation",
    "B7_DELEGATION_NO_FRESHNESS": "Delegation without freshness",
}

M2_TRIAL_FIELDS = frozenset(
    {
        "baseline",
        "master_seed",
        "trial",
        "seed",
        "scenario",
        "parameters",
        "authorization_expected",
        "oracle_safe",
        "oracle_violations",
        "kernel_safe",
        "executed",
        "mission_correct",
        "physical_unsafe_escape",
        "unauthorized_execution",
        "false_block",
        "latency_ms",
        "kernel_oracle_disagreement",
    }
)
M2_BOOL_FIELDS = (
    "authorization_expected",
    "oracle_safe",
    "kernel_safe",
    "executed",
    "mission_correct",
    "physical_unsafe_escape",
    "unauthorized_execution",
    "false_block",
    "kernel_oracle_disagreement",
)
M2_SHARED_FIELDS = (
    "seed",
    "scenario",
    "parameters",
    "authorization_expected",
    "oracle_safe",
    "oracle_violations",
    "kernel_safe",
    "kernel_oracle_disagreement",
)

M3_INTERNAL_CHECKS = (
    "manifest",
    "artifact_hashes",
    "record_counts",
    "event_chains",
    "trial_semantics",
    "deterministic_outcome",
    "summary",
    "configuration_bindings",
)
M3CheckoutBindingStatus = Literal["match", "mismatch"]
M3_EQUIVALENCE_FIELDS = (
    "analyst",
    "boundary",
    "component_versions",
    "conditions_per_session",
    "configuration_sha256",
    "deterministic_outcome_sha256",
    "event_record_count",
    "experiment_configuration",
    "experiment_version",
    "git",
    "host",
    "individual_seeds",
    "known_failures",
    "known_limitations",
    "master_seed",
    "master_seed_count",
    "master_seeds",
    "model_digest",
    "outcome_projection_version",
    "raw_data_location",
    "scenario_version",
    "schema_sha256",
    "session_count",
    "source_sha256",
    "trial_record_count",
)

CONDITION_PRESENTATION: dict[str, dict[str, Any]] = {
    "unknown_identity": {
        "label": "Unknown identity",
        "disposition": "Denied by the gateway before dispatch",
        "path": ("deny", *("not_reached" for _ in range(6))),
        "evidence_note": "No permit or device command was issued.",
    },
    "stale_state": {
        "label": "Stale state",
        "disposition": "Denied before dispatch because the observation was stale",
        "path": ("pass", "pass", "deny", *("not_reached" for _ in range(4))),
        "evidence_note": "The denominator records a gateway no-dispatch case.",
    },
    "wrong_audience_permit": {
        "label": "Tampered permit audience",
        "disposition": (
            "Rejected by device audience validation after the permit audience was altered"
        ),
        "path": ("pass", "pass", "pass", "pass", "tampered", "deny", "no_effect"),
        "evidence_note": (
            "The test altered the audience after signing. The device checked audience before "
            "cryptographic signature and returned permit_wrong_audience. The alteration also "
            "invalidated the signature, so a validly signed wrong-audience case was not "
            "exercised."
        ),
    },
    "nominal_permitted_execution": {
        "label": "Nominal permitted execution",
        "disposition": "Applied, acknowledged, and read back",
        "path": ("pass", "pass", "pass", "pass", "pass", "pass", "effect"),
        "evidence_note": "The same fixed command and operating point were repeated 30 times.",
    },
    "permit_replay": {
        "label": "Permit replay",
        "disposition": "Rejected by the virtual device without a second effect",
        "path": ("reused", "reused", "reused", "reused", "reused", "deny", "no_effect"),
        "evidence_note": (
            "The replay reused the nominal permit; earlier authorization was not rerun."
        ),
    },
}


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def _strict_json_loads(material: str | bytes) -> Any:
    return json.loads(material, parse_constant=_reject_nonfinite)


def _load_json(path: Path) -> dict[str, Any]:
    value = _strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise ValueError(f"JSONL artifact is empty or contains blank records: {path}")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        value = _strict_json_loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"JSONL record {line_number} is not an object: {path}")
        records.append(value)
    return records


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*arguments: str) -> bytes:
    completed = subprocess.run(  # noqa: S603 - fixed executable; bounded internal arguments
        [GIT_EXECUTABLE, *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"Git evidence binding failed: {detail or arguments}")
    return completed.stdout


def _git_blob(commit: str, path: str) -> bytes:
    return _git("show", f"{commit}:{path}")


def _git_tree_paths(commit: str, prefix: str) -> set[str]:
    output = _git("ls-tree", "-r", "--name-only", commit, "--", prefix)
    return {line for line in output.decode("utf-8").splitlines() if line}


def _bind_blob_hashes(commit: str, hashes: dict[str, Any]) -> None:
    for path, expected in hashes.items():
        if not isinstance(path, str) or not isinstance(expected, str):
            raise ValueError("recorded Git binding has an invalid type")
        actual = hashlib.sha256(_git_blob(commit, path)).hexdigest()
        if actual != expected:
            raise ValueError(f"recorded Git binding differs for {path}")


def _bind_directory_to_retention_commit(commit: str, directory: Path) -> None:
    prefix = str(directory.relative_to(ROOT))
    recorded = _git_tree_paths(commit, prefix)
    current = {
        str(path.relative_to(ROOT))
        for path in directory.rglob("*")
        if path.is_file()
    }
    if current != recorded:
        raise ValueError(f"retained package path set differs from {commit}: {prefix}")
    for path in sorted(recorded):
        if hashlib.sha256((ROOT / path).read_bytes()).digest() != hashlib.sha256(
            _git_blob(commit, path)
        ).digest():
            raise ValueError(f"retained package bytes differ from {commit}: {path}")


def _wilson(successes: int, denominator: int) -> dict[str, float | int]:
    z = 1.959963984540054
    estimate = successes / denominator
    scale = 1 + z**2 / denominator
    center = (estimate + z**2 / (2 * denominator)) / scale
    margin = z * math.sqrt(
        estimate * (1 - estimate) / denominator + z**2 / (4 * denominator**2)
    )
    margin /= scale
    return {
        "estimate": estimate,
        "lower": 0.0 if successes == 0 else max(0.0, center - margin),
        "upper": 1.0 if successes == denominator else min(1.0, center + margin),
        "denominator": denominator,
    }


def _validate_m2_record(record: dict[str, Any], index: int) -> None:
    if set(record) != M2_TRIAL_FIELDS:
        raise ValueError(f"M2 trial {index} has missing or unknown fields")
    if record["baseline"] not in BASELINE_LABELS:
        raise ValueError(f"M2 trial {index} has an unregistered baseline")
    for field in ("master_seed", "trial", "seed"):
        if type(record[field]) is not int or record[field] < 0:
            raise ValueError(f"M2 trial {index} has invalid {field}")
    for field in M2_BOOL_FIELDS:
        if type(record[field]) is not bool:
            raise ValueError(f"M2 trial {index} has non-boolean {field}")
    if not isinstance(record["scenario"], str) or not record["scenario"]:
        raise ValueError(f"M2 trial {index} has an invalid scenario")
    violations = record["oracle_violations"]
    if not isinstance(violations, list) or any(not isinstance(item, str) for item in violations):
        raise ValueError(f"M2 trial {index} has invalid oracle violations")
    parameters = record["parameters"]
    if not isinstance(parameters, dict) or any(
        not isinstance(key, str)
        or isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        for key, value in parameters.items()
    ):
        raise ValueError(f"M2 trial {index} has invalid parameters")
    latency = record["latency_ms"]
    if (
        isinstance(latency, bool)
        or not isinstance(latency, (int, float))
        or not math.isfinite(latency)
        or latency < 0
    ):
        raise ValueError(f"M2 trial {index} has invalid latency")

    executed = record["executed"]
    desired = record["authorization_expected"] and record["oracle_safe"]
    expected = {
        "physical_unsafe_escape": executed and not record["oracle_safe"],
        "unauthorized_execution": executed and not record["authorization_expected"],
        "false_block": not executed and desired,
        "mission_correct": executed == desired,
        "kernel_oracle_disagreement": record["kernel_safe"] != record["oracle_safe"],
    }
    if any(record[field] is not value for field, value in expected.items()):
        raise ValueError(f"M2 trial {index} has inconsistent derived outcome flags")


def _summarize_m2(records: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for baseline in BASELINE_LABELS:
        subset = [item for item in records if item["baseline"] == baseline]
        unsafe = [item for item in subset if not item["oracle_safe"]]
        unauthorized = [item for item in subset if not item["authorization_expected"]]
        desired = [
            item for item in subset if item["authorization_expected"] and item["oracle_safe"]
        ]
        unsafe_count = sum(item["physical_unsafe_escape"] for item in unsafe)
        unauthorized_count = sum(item["unauthorized_execution"] for item in unauthorized)
        false_block_count = sum(item["false_block"] for item in desired)
        mission_count = sum(item["mission_correct"] for item in subset)
        summary[baseline] = {
            "trials": len(subset),
            "unsafe_action_escape_rate": unsafe_count / len(unsafe),
            "unsafe_action_escape_ci95": _wilson(unsafe_count, len(unsafe)),
            "unauthorized_execution_rate": unauthorized_count / len(unauthorized),
            "unauthorized_execution_ci95": _wilson(
                unauthorized_count, len(unauthorized)
            ),
            "false_block_rate": false_block_count / len(desired),
            "false_block_ci95": _wilson(false_block_count, len(desired)),
            "mission_success_rate": mission_count / len(subset),
            "mission_success_ci95": _wilson(mission_count, len(subset)),
            "mean_decision_latency_ms": mean(item["latency_ms"] for item in subset),
            "kernel_oracle_disagreements": sum(
                item["kernel_oracle_disagreement"] for item in subset
            ),
        }
    return summary


def _validate_m2_package(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if manifest.get("git_commit") != M2_EXECUTION_COMMIT:
        raise ValueError("M2 execution commit differs from the public evidence registration")
    if manifest.get("working_tree_dirty") is not False:
        raise ValueError("M2 execution did not record a clean working tree")
    if manifest.get("baselines") != list(BASELINE_LABELS):
        raise ValueError("M2 baseline order differs from the registered design")
    raw_name = manifest.get("raw_data")
    if raw_name != M2_TRIALS_PATH.name:
        raise ValueError("M2 raw-data path differs from the registered package")
    if _sha256(M2_TRIALS_PATH) != manifest.get("raw_sha256"):
        raise ValueError("M2 raw trial hash differs from the manifest")

    records = _load_jsonl(M2_TRIALS_PATH)
    for index, record in enumerate(records):
        _validate_m2_record(record, index)
    if len(records) != manifest.get("total_trial_records"):
        raise ValueError("M2 raw trial count differs from the manifest")

    seeds = manifest.get("master_seeds")
    trial_count = manifest.get("trials_per_seed_per_baseline")
    if (
        not isinstance(seeds, list)
        or not seeds
        or any(type(seed) is not int for seed in seeds)
        or len(set(seeds)) != len(seeds)
        or len(seeds) != manifest.get("master_seed_count")
        or type(trial_count) is not int
        or trial_count <= 0
    ):
        raise ValueError("M2 seed or trial registration is invalid")
    expected_total = len(BASELINE_LABELS) * len(seeds) * trial_count
    if expected_total != len(records):
        raise ValueError("M2 registered dimensions differ from raw trial count")

    identities = [(item["baseline"], item["master_seed"], item["trial"]) for item in records]
    if len(set(identities)) != len(identities):
        raise ValueError("M2 raw trials contain duplicate identities")
    counts = Counter((item["baseline"], item["master_seed"]) for item in records)
    for baseline in BASELINE_LABELS:
        for seed in seeds:
            subset = [
                item
                for item in records
                if item["baseline"] == baseline and item["master_seed"] == seed
            ]
            if counts[(baseline, seed)] != trial_count or {
                item["trial"] for item in subset
            } != set(range(trial_count)):
                raise ValueError("M2 raw trials do not cover the registered design")

    shared: dict[tuple[int, int], dict[str, Any]] = {}
    for record in records:
        identity = (record["master_seed"], record["trial"])
        projection = {field: record[field] for field in M2_SHARED_FIELDS}
        prior = shared.setdefault(identity, projection)
        if projection != prior:
            raise ValueError("M2 baseline rows disagree on common scenario truth")

    recomputed_summary = _summarize_m2(records)
    if recomputed_summary != manifest.get("summary"):
        raise ValueError("M2 manifest summary differs from raw trials")
    outcome_text = "".join(
        json.dumps(
            {key: value for key, value in record.items() if key != "latency_ms"},
            sort_keys=True,
        )
        + "\n"
        for record in records
    )
    if hashlib.sha256(outcome_text.encode()).hexdigest() != manifest.get(
        "deterministic_outcome_sha256"
    ):
        raise ValueError("M2 deterministic outcome hash differs from raw trials")

    source_hashes = manifest.get("source_sha256")
    if not isinstance(source_hashes, dict) or set(source_hashes) != {
        "src/aegis_ot/experiment.py",
        "src/aegis_ot/oracle.py",
        "src/aegis_ot/safety.py",
    }:
        raise ValueError("M2 source bindings are incomplete")
    _bind_blob_hashes(M2_EXECUTION_COMMIT, source_hashes)
    scenario_path = manifest.get("scenario_catalog")
    scenario_hash = manifest.get("scenario_catalog_sha256")
    if not isinstance(scenario_path, str) or not isinstance(scenario_hash, str):
        raise ValueError("M2 scenario binding is invalid")
    if hashlib.sha256(_git_blob(M2_EXECUTION_COMMIT, scenario_path)).hexdigest() != scenario_hash:
        raise ValueError("M2 scenario catalog differs from its execution commit")
    _bind_directory_to_retention_commit(M2_RETENTION_COMMIT, M2_PACKAGE_DIR)
    return records


def _metric_payload(
    interval: dict[str, Any],
    numerator: int,
    *,
    metric_id: str | None = None,
    label: str | None = None,
    interpretation: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "numerator": numerator,
        "denominator": interval["denominator"],
        "estimate": interval["estimate"],
        "wilson_ci95": {
            "method": "wilson-score",
            "confidence_level": 0.95,
            "lower": interval["lower"],
            "upper": interval["upper"],
        },
    }
    if metric_id is not None:
        payload.update(
            {
                "metric_id": metric_id,
                "label": label,
                "interpretation": interpretation,
            }
        )
    return payload


def _m2_baselines(manifest: dict[str, Any], records: list[dict[str, Any]]) -> tuple[Any, ...]:
    baselines: list[dict[str, Any]] = []
    for baseline, label in BASELINE_LABELS.items():
        subset = [item for item in records if item["baseline"] == baseline]
        unsafe = [item for item in subset if not item["oracle_safe"]]
        unauthorized = [item for item in subset if not item["authorization_expected"]]
        desired = [
            item for item in subset if item["authorization_expected"] and item["oracle_safe"]
        ]
        summary = manifest["summary"][baseline]
        baselines.append(
            {
                "baseline_id": baseline,
                "display_id": baseline.split("_", 1)[0],
                "label": label,
                "trials": len(subset),
                "metrics": {
                    "unsafe_action_escape": _metric_payload(
                        summary["unsafe_action_escape_ci95"],
                        sum(item["physical_unsafe_escape"] for item in unsafe),
                    ),
                    "unauthorized_execution": _metric_payload(
                        summary["unauthorized_execution_ci95"],
                        sum(item["unauthorized_execution"] for item in unauthorized),
                    ),
                    "false_block": _metric_payload(
                        summary["false_block_ci95"],
                        sum(item["false_block"] for item in desired),
                    ),
                    "mission_success": _metric_payload(
                        summary["mission_success_ci95"],
                        sum(item["mission_correct"] for item in subset),
                    ),
                },
                "mean_decision_latency_ms": summary["mean_decision_latency_ms"],
                "kernel_oracle_disagreements": summary["kernel_oracle_disagreements"],
            }
        )
    return tuple(baselines)


def _bind_m3_execution_commit(manifest: dict[str, Any]) -> None:
    git = manifest.get("git")
    if not isinstance(git, dict) or git.get("commit") != M3_EXECUTION_COMMIT:
        raise ValueError("M3 execution commit differs from the public evidence registration")
    if git.get("working_tree_dirty_at_start") is not False:
        raise ValueError("M3 execution did not record a clean working tree")

    source_hashes = manifest.get("source_sha256")
    schema_hashes = manifest.get("schema_sha256")
    configuration_hashes = manifest.get("configuration_sha256")
    if (
        not isinstance(source_hashes, dict)
        or not isinstance(schema_hashes, dict)
        or not isinstance(configuration_hashes, dict)
    ):
        raise ValueError("M3 recorded checkout bindings have invalid shapes")
    expected_sources = {
        path
        for path in _git_tree_paths(M3_EXECUTION_COMMIT, "src/aegis_ot")
        if path.endswith(".py")
    }
    expected_schemas = {
        path
        for path in _git_tree_paths(M3_EXECUTION_COMMIT, "schemas")
        if Path(path).name.startswith("m3-") and path.endswith(".schema.json")
    }
    if set(source_hashes) != expected_sources or set(schema_hashes) != expected_schemas:
        raise ValueError("M3 source or schema bindings are incomplete for the execution commit")
    _bind_blob_hashes(M3_EXECUTION_COMMIT, source_hashes)
    _bind_blob_hashes(M3_EXECUTION_COMMIT, schema_hashes)
    project_hashes = {
        path: configuration_hashes.get(path)
        for path in ("pyproject.toml", "requirements.lock")
    }
    _bind_blob_hashes(M3_EXECUTION_COMMIT, project_hashes)


def _validate_m3_report(
    package: Path,
    manifest: dict[str, Any],
) -> tuple[tuple[str, ...], M3CheckoutBindingStatus]:
    report = verify_m3_package(package)
    checks = report.get("checks")
    if not isinstance(checks, dict) or set(checks) != {
        *M3_INTERNAL_CHECKS,
        "checkout_bindings",
    }:
        raise ValueError(f"M3 verifier returned an unexpected check set: {package}")
    if any(checks.get(name) is not True for name in M3_INTERNAL_CHECKS):
        raise ValueError(f"M3 internal package verification failed: {package}")
    checkout_state = checks.get("checkout_bindings")
    errors = report.get("errors")
    if checkout_state is False:
        if not isinstance(errors, list) or not errors or any(
            not isinstance(error, str) or not error.startswith("checkout_bindings:")
            for error in errors
        ):
            raise ValueError(f"M3 verifier failure is not limited to current checkout: {package}")
        checkout_status: M3CheckoutBindingStatus = "mismatch"
    elif checkout_state is not True or errors:
        raise ValueError(f"M3 verifier returned an inconsistent checkout result: {package}")
    else:
        checkout_status = "match"
    if (
        report.get("session_count") != manifest.get("session_count")
        or report.get("trial_record_count") != manifest.get("trial_record_count")
        or report.get("event_record_count") != manifest.get("event_record_count")
        or report.get("deterministic_outcome_sha256")
        != manifest.get("deterministic_outcome_sha256")
    ):
        raise ValueError(f"M3 verifier result differs from the manifest: {package}")
    _bind_m3_execution_commit(manifest)
    return M3_INTERNAL_CHECKS, checkout_status


def _without_m3_latency(summary: dict[str, Any]) -> dict[str, Any]:
    projected = _strict_json_loads(json.dumps(summary))
    if not isinstance(projected, dict):
        raise ValueError("M3 summary projection is not an object")
    by_condition = projected.get("by_condition")
    if not isinstance(by_condition, dict):
        raise ValueError("M3 summary lacks condition results")
    for values in by_condition.values():
        if not isinstance(values, dict) or "latency" not in values:
            raise ValueError("M3 summary lacks registered latency fields")
        values.pop("latency")
    return projected


def _validate_m3_pair(primary: dict[str, Any], reproduction: dict[str, Any]) -> None:
    if primary.get("experiment_id") == reproduction.get("experiment_id"):
        raise ValueError("M3 primary and reproduction experiment identifiers must differ")
    for field in M3_EQUIVALENCE_FIELDS:
        if primary.get(field) != reproduction.get(field):
            raise ValueError(f"M3 reproduction differs on registered field: {field}")
    primary_completed = datetime.fromisoformat(primary["completed_at_utc"])
    reproduction_started = datetime.fromisoformat(reproduction["started_at_utc"])
    if primary_completed > reproduction_started:
        raise ValueError("M3 reproduction started before the primary run completed")
    if _without_m3_latency(primary["summary"]) != _without_m3_latency(
        reproduction["summary"]
    ):
        raise ValueError("M3 reproduction differs outside host timing")

    shared_artifacts = (
        "benchmark/provenance.json",
        "evidence-verification.json",
        "scenarios.json",
        "solver/configuration.json",
    )
    run_specific_artifacts = ("trials.jsonl", "events.jsonl", "component-health.json")
    for path in shared_artifacts:
        if primary["artifact_sha256"].get(path) != reproduction["artifact_sha256"].get(path):
            raise ValueError(f"M3 reproduction differs on shared artifact: {path}")
    for path in run_specific_artifacts:
        if primary["artifact_sha256"].get(path) == reproduction["artifact_sha256"].get(path):
            raise ValueError(f"M3 reproduction reused a run-specific artifact: {path}")


def _m3_metrics(summary: dict[str, Any], trials: list[dict[str, Any]]) -> tuple[Any, ...]:
    denied = [item for item in trials if item["condition"] != "nominal_permitted_execution"]
    nominal = [item for item in trials if item["condition"] == "nominal_permitted_execution"]
    replay = [item for item in trials if item["condition"] == "permit_replay"]
    return (
        _metric_payload(
            summary["denied_command_effect_rate_ci95"],
            sum(item["state_changed"] for item in denied),
            metric_id="non_nominal_effect",
            label="Non-nominal modeled effects",
            interpretation=(
                "Registered end-to-end metric over 120 fixed non-nominal trials; "
                "60 were denied before device dispatch."
            ),
        ),
        _metric_payload(
            summary["nominal_closed_loop_completion_rate_ci95"],
            sum(item["terminal_status"] == "completed" for item in nominal),
            metric_id="nominal_completion",
            label="Nominal closed-loop completions",
            interpretation="Repeated fixed-condition completion, not a field reliability estimate.",
        ),
        _metric_payload(
            summary["duplicate_replay_effect_rate_ci95"],
            sum(item["state_changed"] for item in replay),
            metric_id="replay_second_effect",
            label="Replay second effects",
            interpretation="Thirty reuses of the already issued nominal permit.",
        ),
        _metric_payload(
            summary["unknown_effect_rate_ci95"],
            sum(item["terminal_status"] == "unknown_effect" for item in trials),
            metric_id="unknown_effect",
            label="Unknown-effect outcomes",
            interpretation=(
                "Fail-fast conformance-completeness check, not an ambiguity-rate estimate."
            ),
        ),
        _metric_payload(
            summary["evidence_trace_completeness_rate_ci95"],
            sum(item["trace_complete"] for item in trials),
            metric_id="trace_complete",
            label="Narrow trace indicator complete",
            interpretation=(
                "Proposal, decision, and terminal hash only; stronger package checks are separate."
            ),
        ),
    )


def build_evidence() -> PublicDemoEvidence:
    m2 = _load_json(M2_MANIFEST_PATH)
    m2_trials = _validate_m2_package(m2)
    m3 = _load_json(M3_MANIFEST_PATH)
    m3_summary = _load_json(M3_SUMMARY_PATH)
    reproduction = _load_json(M3_REPRODUCTION_MANIFEST_PATH)
    primary_checks, primary_checkout_status = _validate_m3_report(M3_PACKAGE_DIR, m3)
    reproduction_checks, reproduction_checkout_status = _validate_m3_report(
        M3_REPRODUCTION_PACKAGE_DIR,
        reproduction,
    )
    _bind_directory_to_retention_commit(M3_RETENTION_COMMIT, M3_PACKAGE_DIR)
    _bind_directory_to_retention_commit(M3_RETENTION_COMMIT, M3_REPRODUCTION_PACKAGE_DIR)
    _validate_m3_pair(m3, reproduction)
    if primary_checkout_status != reproduction_checkout_status:
        raise ValueError("M3 packages disagree on current-checkout binding status")

    if m3["summary"] != m3_summary:
        raise ValueError("M3 manifest and standalone summary disagree")
    if set(m3_summary["by_condition"]) != set(CONDITION_PRESENTATION):
        raise ValueError("M3 condition set differs from the public-demo registration")
    m3_trials = _load_jsonl(M3_PACKAGE_DIR / "trials.jsonl")

    condition_payloads: list[dict[str, Any]] = []
    for condition_id, presentation in CONDITION_PRESENTATION.items():
        condition_summary = m3_summary["by_condition"][condition_id]
        condition_trials = [
            item for item in m3_trials if item["condition"] == condition_id
        ]
        condition_payloads.append(
            {
                "condition_id": condition_id,
                "label": presentation["label"],
                "trials": condition_summary["trials"],
                "disposition": presentation["disposition"],
                "modeled_effects": condition_summary["state_effects"],
                "device_applied": condition_summary["device_applied"],
                "unknown_effects": condition_summary["unknown_effects"],
                "terminal_completions": sum(
                    item["terminal_status"] == "completed" for item in condition_trials
                ),
                "trace_complete": sum(item["trace_complete"] for item in condition_trials),
                "path": presentation["path"],
                "evidence_note": presentation["evidence_note"],
            }
        )
    conditions = tuple(condition_payloads)

    nominal = m3_summary["by_condition"]["nominal_permitted_execution"]
    nominal_state = m3_summary["nominal_post_state"]
    latency = nominal["latency"]["end_to_end_ms"]
    evidence = {
        "schema_version": "public-demo-v2",
        "project": {
            "name": "Aegis-OT",
            "study_title": (
                "Assured Agentic AI for Critical Infrastructure: Identity-Bound Runtime "
                "Authorization and Operate-Through-Compromise Resilience"
            ),
            "mode": "synthetic-local",
            "milestone": "Bounded M3 physical process-boundary evidence retained",
            "overall_status": "Research prototype; WP4 through WP8 remain incomplete.",
            "question": (
                "Can an AI agent be trusted to act on critical infrastructure when the agent, "
                "its credentials, its observations, or part of the surrounding system may be "
                "compromised?"
            ),
            "claim_boundary": (
                "Recorded local synthetic evidence only. This page issues no control commands "
                "and does not establish physical accuracy, field effectiveness, independent "
                "replication, or production readiness."
            ),
        },
        "generated_from": tuple(
            {
                "path": str(path.relative_to(ROOT)),
                "sha256": _sha256(path),
            }
            for path in (
                M2_MANIFEST_PATH,
                M2_TRIALS_PATH,
                M3_MANIFEST_PATH,
                M3_SUMMARY_PATH,
                M3_REPRODUCTION_MANIFEST_PATH,
            )
        ),
        "architecture": (
            {
                "stage_id": "identity",
                "label": "Identity",
                "responsibility": "Authenticate the workload and bind it to an actor.",
            },
            {
                "stage_id": "delegation",
                "label": "Delegation",
                "responsibility": "Validate the complete attenuated grant chain.",
            },
            {
                "stage_id": "policy_state",
                "label": "Policy + state",
                "responsibility": "Evaluate scope, risk, approval, and observation freshness.",
            },
            {
                "stage_id": "safety",
                "label": "Safety",
                "responsibility": "Evaluate the modeled candidate transition.",
            },
            {
                "stage_id": "permit",
                "label": "Signed permit",
                "responsibility": "Bind one command to one decision and expected state change.",
            },
            {
                "stage_id": "device",
                "label": "Virtual device",
                "responsibility": "Revalidate and consume the permit over Modbus loopback.",
            },
            {
                "stage_id": "plant",
                "label": "Plant + readback",
                "responsibility": "Apply the command transactionally and return resulting state.",
            },
        ),
        "m2": {
            "experiment_id": m2["experiment_id"],
            "evidence_commit": m2["git_commit"],
            "retention_commit": M2_RETENTION_COMMIT,
            "recorded_commit_bound": True,
            "trial_records": m2["total_trial_records"],
            "raw_trials_sha256": m2["raw_sha256"],
            "master_seed_count": m2["master_seed_count"],
            "deterministic_outcome_sha256": m2["deterministic_outcome_sha256"],
            "baselines": _m2_baselines(m2, m2_trials),
            "finding": (
                "The assured path prevented authorization-invalid execution in the reviewed "
                "catalog, while a separately implemented reference oracle exposed a 60 percent "
                "conditional unsafe-escape rate caused by guardband differences."
            ),
            "limitation": (
                "M2 uses balanced synthetic scenarios and separately implemented rules, not a "
                "physical simulator or operational incident distribution."
            ),
        },
        "m3": {
            "experiment_id": m3["experiment_id"],
            "reproduction_experiment_id": reproduction["experiment_id"],
            "evidence_commit": m3["git"]["commit"],
            "retention_commit": M3_RETENTION_COMMIT,
            "sessions": m3["session_count"],
            "trial_records": m3["trial_record_count"],
            "evidence_events": m3["event_record_count"],
            "deterministic_outcome_sha256": m3["deterministic_outcome_sha256"],
            "model_digest": m3["model_digest"],
            "verification": {
                "internal_checks": primary_checks,
                "primary_internal_checks_passed": True,
                "reproduction_internal_checks_passed": reproduction_checks == primary_checks,
                "recorded_commit_bound": True,
                "current_checkout_binding_status": primary_checkout_status,
                "boundary": (
                    "Project-controlled internal consistency and recorded-Git provenance only; "
                    "not external custody, authenticity, model validity, or independent "
                    "replication."
                ),
            },
            "conditions": conditions,
            "metrics": _m3_metrics(m3_summary, m3_trials),
            "nominal_state": {
                "minimum_voltage_pu": nominal_state["minimum_voltage_pu"]["mean"],
                "maximum_line_loading_pct": nominal_state["maximum_line_loading_pct"]["mean"],
                "priority_load_served_pct": nominal_state["priority_load_served_pct"]["mean"],
                "host_latency_mean_ms": latency["mean_ms"],
                "host_latency_median_ms": latency["median_ms"],
            },
            "finding": (
                "All 30 nominal commands completed with signed acknowledgment and readback; "
                "the four registered non-nominal conditions produced no modeled effect."
            ),
            "limitation": (
                "One deterministic pandapower model, one operating point, a PyModbus research "
                "virtual device, and one host were used. Candidate, commit, and readback share "
                "the same process and model."
            ),
        },
        "next_gates": (
            "Independently operated measurement or consequence path",
            "HELICS coordination and OpenPLC or justified virtual-PLC integration",
            "Segmented multi-node trust-boundary deployment",
            "Operate-through-compromise experiments",
            "Fleet-scale and economic evaluation",
            "Independent review, replication, and public-release authorization",
        ),
    }
    return PublicDemoEvidence.model_validate(evidence)


def rendered_evidence() -> str:
    evidence = build_evidence()
    return json.dumps(evidence.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if packaged demo data differs from internally verified retained evidence",
    )
    args = parser.parse_args()
    rendered = rendered_evidence()
    if args.check:
        if not OUTPUT_PATH.is_file() or OUTPUT_PATH.read_text(encoding="utf-8") != rendered:
            raise SystemExit("packaged public-demo evidence is stale")
        return
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
