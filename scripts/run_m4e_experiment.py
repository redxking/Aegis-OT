"""Run and retain the bounded M4e authenticated-transport experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import run_m4d_experiment as m4d
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _replace_key_paths(value: Any, key_directory: Path) -> Any:
    if isinstance(value, dict):
        return {key: _replace_key_paths(item, key_directory) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_key_paths(item, key_directory) for item in value]
    if isinstance(value, str) and value.startswith(str(key_directory)):
        return f"<ephemeral-key-dir>/{Path(value).name}"
    return value


def run_experiment(output: Path, project_name: str) -> dict[str, Any]:
    if m4d._run("git", "status", "--porcelain").stdout:
        raise m4d.ExperimentError("M4e retained evidence requires a clean checkout")
    commit = m4d._run("git", "rev-parse", "HEAD").stdout.strip()
    key_directory = Path(tempfile.mkdtemp(prefix="aegis-ot-m4e-keys-"))
    gateway_private = Ed25519PrivateKey.generate()
    ot_private = Ed25519PrivateKey.generate()
    key_material = {
        "AEGIS_GATEWAY_PRIVATE_KEY_FILE": key_directory / "gateway.private",
        "AEGIS_GATEWAY_PUBLIC_KEY_FILE": key_directory / "gateway.public",
        "AEGIS_OT_PRIVATE_KEY_FILE": key_directory / "ot.private",
        "AEGIS_OT_PUBLIC_KEY_FILE": key_directory / "ot.public",
    }
    key_material["AEGIS_GATEWAY_PRIVATE_KEY_FILE"].write_bytes(
        _raw_private(gateway_private)
    )
    key_material["AEGIS_GATEWAY_PUBLIC_KEY_FILE"].write_bytes(
        _raw_public(gateway_private)
    )
    key_material["AEGIS_OT_PRIVATE_KEY_FILE"].write_bytes(_raw_private(ot_private))
    key_material["AEGIS_OT_PUBLIC_KEY_FILE"].write_bytes(_raw_public(ot_private))
    os.chmod(key_material["AEGIS_GATEWAY_PRIVATE_KEY_FILE"], 0o600)
    os.chmod(key_material["AEGIS_OT_PRIVATE_KEY_FILE"], 0o600)

    prior_environment = {name: os.environ.get(name) for name in key_material}
    for name, path in key_material.items():
        os.environ[name] = str(path)
    prefix = (
        "docker",
        "compose",
        "-p",
        project_name,
        "-f",
        "docker-compose.yml",
        "-f",
        "docker-compose.auth.yml",
    )
    services_started = False
    try:
        compose = json.loads(m4d._run(*prefix, "config", "--format", "json").stdout)
        normalized_compose = _replace_key_paths(compose, key_directory)
        normalized_compose_json = json.dumps(
            normalized_compose,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        m4d._run(*prefix, "--profile", "experiment", "build")
        m4d._run(
            *prefix,
            "up",
            "-d",
            "--force-recreate",
            "opa",
            "simulation",
            "observer",
            "ot-adapter",
            "segmented-gateway",
        )
        services_started = True
        agent = json.loads(
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "run",
                "--rm",
                "agent-probe",
            ).stdout
        )
        transport = json.loads(
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "run",
                "--rm",
                "transport-probe",
            ).stdout
        )
        if not isinstance(agent, dict) or not isinstance(transport, dict):
            raise m4d.ExperimentError("M4e probe output was not an object")
        networks = m4d._network_inventory(
            project_name, ["agent", "trust", "control_dmz", "simulation"]
        )
        images = m4d._json_records(m4d._run(*prefix, "images", "--format", "json").stdout)
        acceptance = {
            "signed_agent_campaign_accepted": agent.get("accepted") is True,
            "unsigned_request_rejected": (
                transport.get("unsigned", {}).get("http_status") == 403
            ),
            "forged_signature_rejected": (
                transport.get("forged_signature", {}).get("http_status") == 403
            ),
            "valid_key_holder_executed_once": (
                transport.get("valid_key_holder", {}).get("http_status") == 200
                and transport.get("valid_key_holder", {}).get("executed") is True
                and transport.get("valid_key_holder", {}).get(
                    "response_signature_verified"
                )
                is True
            ),
            "exact_transport_replay_rejected": (
                transport.get("exact_transport_replay", {}).get("http_status") == 409
            ),
            "post_signature_tamper_rejected": (
                transport.get("post_signature_tamper", {}).get("http_status") == 403
            ),
        }
        semantic_agent = dict(agent)
        semantic_agent.pop("agent_hostname", None)
        semantic_material = {
            "git_commit": commit,
            "normalized_compose_sha256": hashlib.sha256(
                normalized_compose_json.encode()
            ).hexdigest(),
            "network_inventory": networks,
            "agent_probe": semantic_agent,
            "transport_probe": transport,
            "acceptance": acceptance,
        }
        evidence: dict[str, Any] = {
            "schema_version": "m4e-authenticated-transport-experiment-v1",
            "generated_at": datetime.now(UTC).isoformat(),
            "analyst": "Angelis Pseftis",
            "git_commit": commit,
            "clean_checkout": True,
            "project_name": project_name,
            "normalized_compose_sha256": semantic_material[
                "normalized_compose_sha256"
            ],
            "ephemeral_public_key_sha256": {
                "gateway": hashlib.sha256(_raw_public(gateway_private)).hexdigest(),
                "ot_adapter": hashlib.sha256(_raw_public(ot_private)).hexdigest(),
            },
            "private_key_material_retained": False,
            "images": images,
            "network_inventory": networks,
            "agent_probe": agent,
            "transport_probe": transport,
            "acceptance": acceptance,
            "accepted": all(acceptance.values()),
            "semantic_outcome_sha256": m4d._canonical_sha256(semantic_material),
            "evidence_boundary": [
                "Ephemeral Ed25519 service keys and Docker secrets, not SPIFFE/SPIRE",
                "Message signatures inside local HTTP, not TLS peer authentication",
                "Controlled key-holder replay injector, not an untrusted peer",
                "Synthetic supervisory state, not pandapower, HELICS, OpenPLC, or hardware",
                "Single local Docker host and local execution, not independent validation",
            ],
        }
        if evidence["accepted"] is not True:
            raise m4d.ExperimentError("M4e acceptance criteria were not all satisfied")
        m4d._atomic_write_json(output, evidence)
        return evidence
    finally:
        if services_started:
            m4d._run(*prefix, "stop", check=False)
        for name, previous in prior_environment.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
        shutil.rmtree(key_directory, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project-name", default="aegis-ot-m4e")
    arguments = parser.parse_args()
    result = run_experiment(arguments.output, arguments.project_name)
    print(json.dumps({"accepted": result["accepted"], "output": str(arguments.output)}))


if __name__ == "__main__":
    main()
