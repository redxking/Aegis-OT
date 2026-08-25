from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
SPIRE_PATH = ROOT / "docker-compose.spire.yml"
SPIRE = yaml.safe_load(SPIRE_PATH.read_text(encoding="utf-8"))

APPLICATION_USERS = {
    "segmented-gateway": "65532:65532",
    "observer": "65532:65533",
    "candidate": "65532:65534",
    "ot-adapter": "65532:65535",
    "simulation": "65532:65536",
}
TLS_SERVERS = {"observer", "candidate", "ot-adapter", "simulation"}
OUTBOUND_MTLS = {"segmented-gateway", "observer", "candidate", "ot-adapter"}
TRUST_DOMAIN = "aegis-ot.m4g.local"


def _service(name: str) -> dict[str, Any]:
    value = SPIRE["services"][name]
    assert isinstance(value, dict)
    return value


def _compose_environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["COMPOSE_PROJECT_NAME"] = "aegis_spire_config_test"
    environment["AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID"] = "ed25519:" + "0" * 64
    environment["AEGIS_OT_WORKLOAD_KEY_ID"] = "ed25519:" + "1" * 64
    for name in (
        "GATEWAY_PRIVATE",
        "GATEWAY_PUBLIC",
        "OT_PRIVATE",
        "OT_PUBLIC",
        "PERMIT_PRIVATE",
        "PERMIT_PUBLIC",
        "OBSERVER_PRIVATE",
        "OBSERVER_PUBLIC",
        "CANDIDATE_PRIVATE",
        "CANDIDATE_PUBLIC",
        "PLANT_PRIVATE",
        "PLANT_PUBLIC",
        "WORKLOAD_AUTHORITY_PRIVATE",
        "WORKLOAD_AUTHORITY_PUBLIC",
        "AGENT_PRIVATE",
        "AGENT_PUBLIC",
    ):
        path = tmp_path / f"{name.lower()}.key"
        path.write_bytes(b"k" * 32)
        environment[f"AEGIS_{name}_KEY_FILE"] = str(path)
    return environment


def _resolved_config(tmp_path: Path) -> dict[str, Any]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")
    assert docker is not None
    version = subprocess.run(  # noqa: S603 - fixed executable and arguments
        [docker, "compose", "version"],
        check=False,
        capture_output=True,
        text=True,
    )
    if version.returncode != 0:
        pytest.skip("Docker Compose is unavailable")

    command = [docker, "compose"]
    for filename in (
        "docker-compose.yml",
        "docker-compose.auth.yml",
        "docker-compose.replay.yml",
        "docker-compose.capability.yml",
        "docker-compose.identity.yml",
        "docker-compose.spire.yml",
    ):
        command.extend(("-f", str(ROOT / filename)))
    command.extend(("--profile", "experiment", "config", "--format", "json"))
    completed = subprocess.run(  # noqa: S603 - fixed Compose config invocation
        command,
        cwd=ROOT,
        env=_compose_environment(tmp_path),
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    configured = json.loads(completed.stdout)
    assert isinstance(configured, dict)
    return configured


def test_spire_overlay_uses_group_selectors_without_losing_runtime_file_access() -> None:
    assert {name: _service(name)["user"] for name in APPLICATION_USERS} == (APPLICATION_USERS)
    assert _service("replay-init")["environment"] == {
        "AEGIS_RUNTIME_UID": "65532",
        "AEGIS_RUNTIME_GID": "65535",
    }

    for name, user in APPLICATION_USERS.items():
        service = _service(name)
        assert "spire-agent-socket:/run/spire/agent/public:ro" in service["volumes"]
        uid, gid = user.split(":", maxsplit=1)
        assert service["environment"]["AEGIS_SPIRE_MTLS_TMPDIR"] == (
            "/run/aegis-spire-mtls"  # noqa: S108
        )
        assert (
            "/tmp:rw,noexec,nosuid,nodev,size=1m,mode=1777"  # noqa: S108
            in service["tmpfs"]
        )
        assert (
            "/run/aegis-spire-mtls:rw,noexec,nosuid,nodev,size=1m,"  # noqa: S108
            f"mode=0700,uid={uid},gid={gid}"
        ) in service["tmpfs"]


def test_spire_overlay_requires_exact_tls_workload_peers() -> None:
    gateway = _service("segmented-gateway")
    assert gateway["entrypoint"][:3] == [
        "python",
        "-m",
        "aegis_ot.spire_workload_identity",
    ]
    assert "command" not in gateway
    assert gateway["environment"]["AEGIS_WORKLOAD_IDENTITY_MODE"] == "required"
    assert all(
        _service(name)["environment"]["AEGIS_SPIRE_MTLS_MODE"] == "required"
        for name in APPLICATION_USERS
    )

    for name in OUTBOUND_MTLS:
        environment = _service(name)["environment"]
        assert environment["AEGIS_SPIRE_MTLS_MODE"] == "required"
        assert environment["AEGIS_SPIFFE_ID"].startswith(f"spiffe://{TRUST_DOMAIN}/workload/")
        peers = json.loads(environment["AEGIS_SPIFFE_PEER_IDS"])
        assert peers
        assert all(peer.startswith(f"spiffe://{TRUST_DOMAIN}/workload/") for peer in peers.values())

    for name in TLS_SERVERS:
        entrypoint = _service(name)["entrypoint"]
        assert entrypoint[:4] == ["python", "-m", "aegis_ot.spire_mtls", "serve"]
        assert "--expected-spiffe-id" in entrypoint
        assert "--allowed-client-spiffe-id" in entrypoint
        assert _service(name)["command"] == []


def test_six_layer_config_preserves_identity_replay_and_network_boundaries(
    tmp_path: Path,
) -> None:
    services = _resolved_config(tmp_path)["services"]

    assert {name: services[name]["user"] for name in APPLICATION_USERS} == (APPLICATION_USERS)
    assert (
        services["segmented-gateway"]["environment"]["AEGIS_WORKLOAD_IDENTITY_MODE"] == "required"
    )
    assert services["ot-adapter"]["environment"]["AEGIS_WORKLOAD_IDENTITY_MODE"] == "required"
    assert all(
        services[name]["environment"]["AEGIS_SPIRE_MTLS_MODE"] == "required"
        for name in APPLICATION_USERS
    )
    assert services["agent-probe"]["environment"]["AEGIS_SPIRE_MTLS_MODE"] == ("disabled")
    assert (
        services["ot-adapter"]["environment"]["AEGIS_WORKLOAD_REPLAY_LEDGER_FILE"]
        == "/var/lib/aegis-ot/workload-replay.json"
    )
    assert (
        services["ot-adapter"]["environment"]["AEGIS_SEMANTIC_REPLAY_LEDGER_FILE"]
        == "/var/lib/aegis-ot/semantic-replay.json"
    )

    assert services["segmented-gateway"]["environment"]["AEGIS_OBSERVER_URL"] == (
        "https://observer:8082"
    )
    assert services["segmented-gateway"]["environment"]["AEGIS_CANDIDATE_URL"] == (
        "https://candidate:8085"
    )
    assert services["segmented-gateway"]["environment"]["AEGIS_OT_URL"] == (
        "https://ot-adapter:8083"
    )
    assert services["ot-adapter"]["environment"]["AEGIS_PLANT_URL"] == ("https://simulation:8084")

    # The agent-facing boundary remains the committed application-signed HTTP
    # protocol; this overlay only adds SPIRE mTLS behind the gateway.
    assert services["agent-probe"]["environment"]["AEGIS_GATEWAY_URL"] == (
        "http://segmented-gateway:8081"
    )
    assert services["segmented-gateway"]["command"][:2] == [
        "uvicorn",
        "aegis_ot.segmented_capability_runtime:capability_gateway_app",
    ]

    gateway_dependencies = services["segmented-gateway"]["depends_on"]
    assert gateway_dependencies["identity-init"]["condition"] == ("service_completed_successfully")
    assert gateway_dependencies["spire-agent"]["condition"] == "service_healthy"
    ot_dependencies = services["ot-adapter"]["depends_on"]
    assert ot_dependencies["identity-init"]["condition"] == ("service_completed_successfully")
    assert ot_dependencies["replay-init"]["condition"] == ("service_completed_successfully")
    assert ot_dependencies["spire-agent"]["condition"] == "service_healthy"

    assert set(services["segmented-gateway"]["networks"]) == {
        "agent",
        "trust",
        "control_dmz",
    }
    assert set(services["observer"]["networks"]) == {
        "control_dmz",
        "simulation",
    }
    assert set(services["ot-adapter"]["networks"]) == {
        "control_dmz",
        "simulation",
    }
    assert services["simulation"]["networks"] == {"simulation": None}
