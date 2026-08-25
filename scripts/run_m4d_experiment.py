"""Run and retain the bounded M4d Docker-network experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


class ExperimentError(RuntimeError):
    """The M4d experiment could not establish its evidence contract."""


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(  # noqa: S603 - argv is fixed by this experiment runner
        args,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "COMPOSE_ANSI": "never"},
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ExperimentError(f"command failed ({' '.join(args)}): {detail[-4000:]}")
    return completed


def _json_records(raw: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        if not all(isinstance(value, dict) for value in parsed):
            raise ExperimentError("Docker JSON array contained a non-object record")
        return parsed
    if isinstance(parsed, dict):
        return [parsed]

    records: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ExperimentError("Docker JSON output contained a non-object record")
            records.append(value)
    if not records:
        raise ExperimentError("Docker JSON output was empty")
    return records


def _network_inventory(project_name: str, network_names: list[str]) -> dict[str, list[str]]:
    inventory: dict[str, list[str]] = {}
    for name in network_names:
        raw = _run("docker", "network", "inspect", f"{project_name}_{name}").stdout
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            raise ExperimentError("Docker network inspection returned an unexpected shape")
        containers = values[0].get("Containers", {})
        if not isinstance(containers, dict):
            raise ExperimentError("Docker network container inventory was malformed")
        names = [item.get("Name") for item in containers.values() if isinstance(item, dict)]
        inventory[name] = sorted(str(value) for value in names if isinstance(value, str))
    return inventory


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ExperimentError(f"refusing to overwrite retained evidence: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def _canonical_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def run_experiment(output: Path, project_name: str) -> dict[str, Any]:
    status = _run("git", "status", "--porcelain").stdout
    if status:
        raise ExperimentError("M4d retained evidence requires a clean checkout")
    commit = _run("git", "rev-parse", "HEAD").stdout.strip()
    compose_json = _run("docker", "compose", "config", "--format", "json").stdout
    compose = json.loads(compose_json)
    if not isinstance(compose, dict):
        raise ExperimentError("resolved Compose configuration was not an object")

    compose_prefix = ("docker", "compose", "-p", project_name)
    _run(*compose_prefix, "--profile", "experiment", "build")
    _run(
        *compose_prefix,
        "up",
        "-d",
        "--force-recreate",
        "opa",
        "simulation",
        "observer",
        "ot-adapter",
        "segmented-gateway",
    )
    probe_run = _run(*compose_prefix, "--profile", "experiment", "run", "--rm", "agent-probe")
    probe = json.loads(probe_run.stdout)
    if not isinstance(probe, dict) or probe.get("accepted") is not True:
        raise ExperimentError("agent-network probe did not satisfy its acceptance criteria")

    expected_networks = ["agent", "trust", "control_dmz", "simulation"]
    networks = _network_inventory(project_name, expected_networks)
    images = _json_records(_run(*compose_prefix, "images", "--format", "json").stdout)
    docker_version = json.loads(_run("docker", "version", "--format", "{{json .}}").stdout)
    evidence: dict[str, Any] = {
        "schema_version": "m4d-segmented-experiment-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "analyst": "Angelis Pseftis",
        "git_commit": commit,
        "clean_checkout": True,
        "project_name": project_name,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "docker": docker_version,
        },
        "resolved_compose_sha256": hashlib.sha256(compose_json.encode()).hexdigest(),
        "images": images,
        "network_inventory": networks,
        "probe": probe,
        "acceptance": {
            "agent_direct_observer_unreachable": probe[
                "agent_network_direct_reachability"
            ]["observer"]
            is False,
            "agent_direct_ot_adapter_unreachable": probe[
                "agent_network_direct_reachability"
            ]["ot-adapter"]
            is False,
            "agent_direct_simulation_unreachable": probe[
                "agent_network_direct_reachability"
            ]["simulation"]
            is False,
            "unsafe_action_denied_without_dispatch": (
                probe["unsafe"]["decision"] == "deny"
                and probe["unsafe"]["dispatched"] is False
            ),
            "safe_action_executed_once": (
                probe["safe"]["decision"] == "permit"
                and probe["safe"]["executed"] is True
                and probe["final_state_version"] == probe["initial_state_version"] + 1
            ),
            "exact_replay_denied_without_dispatch": (
                probe["replay"]["decision"] == "deny"
                and probe["replay"]["dispatched"] is False
                and "replayed_nonce" in probe["replay"]["reasons"]
            ),
        },
        "evidence_boundary": [
            "Docker network membership and in-container reachability on one local host",
            "Synthetic supervisory state and command adapter, not pandapower, HELICS, or OpenPLC",
            "Body-level allowlisted actor identity, not SPIFFE or transport workload identity",
            "Unsigned HTTP between trusted services; no hostile-container or hostile-host claim",
            "Local execution by Angelis Pseftis, not independent or external validation",
        ],
    }
    evidence["accepted"] = all(evidence["acceptance"].values())
    semantic_probe = dict(probe)
    semantic_probe.pop("agent_hostname", None)
    evidence["semantic_outcome_sha256"] = _canonical_sha256(
        {
            "git_commit": commit,
            "resolved_compose_sha256": evidence["resolved_compose_sha256"],
            "network_inventory": networks,
            "probe": semantic_probe,
            "acceptance": evidence["acceptance"],
            "accepted": evidence["accepted"],
        }
    )
    if evidence["accepted"] is not True:
        raise ExperimentError("retained M4d acceptance criteria were not all satisfied")
    _atomic_write_json(output, evidence)
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project-name", default="aegis-ot-m4d")
    arguments = parser.parse_args()
    result = run_experiment(arguments.output, arguments.project_name)
    print(json.dumps({"accepted": result["accepted"], "output": str(arguments.output)}))


if __name__ == "__main__":
    main()
