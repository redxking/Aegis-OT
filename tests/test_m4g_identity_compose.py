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
IDENTITY_PATH = ROOT / "docker-compose.identity.yml"
IDENTITY = yaml.safe_load(IDENTITY_PATH.read_text(encoding="utf-8"))

RUNTIME_IDENTITY_PATH = "/run/aegis-identity"
COMMON_ENVIRONMENT = {
    "AEGIS_WORKLOAD_IDENTITY_MODE",
    "AEGIS_WORKLOAD_TRUST_DOMAIN",
    "AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID",
    "AEGIS_WORKLOAD_TRUST_ROOT_PUBLIC_KEY_FILE",
    "AEGIS_WORKLOAD_TRUST_BUNDLE_FILE",
}


def _service(name: str) -> dict[str, Any]:
    value = IDENTITY["services"][name]
    assert isinstance(value, dict)
    return value


def _secret_names(service: dict[str, Any]) -> set[str]:
    return {
        item if isinstance(item, str) else item["source"]
        for item in service.get("secrets", [])
    }


def test_identity_administration_is_offline_and_confines_authority_private_key() -> None:
    initializer = _service("identity-init")
    assert initializer["command"] == ["python", "-m", "aegis_ot.m4g_identity_init"]
    assert initializer["network_mode"] == "none"
    assert initializer["read_only"] is True
    assert initializer["user"] == "0:0"
    assert initializer["cap_drop"] == ["ALL"]
    assert initializer["cap_add"] == ["CHOWN"]
    assert initializer["restart"] == "no"
    assert initializer["volumes"] == [
        "workload_identity:/var/lib/aegis-ot/identity",
        (
            "workload_trust_sequence_agent:"
            "/var/lib/aegis-ot/trust-sequence-state/agent"
        ),
        (
            "workload_trust_sequence_gateway:"
            "/var/lib/aegis-ot/trust-sequence-state/gateway"
        ),
        "workload_trust_sequence_ot:/var/lib/aegis-ot/trust-sequence-state/ot",
    ]

    expected_environment = {
        "AEGIS_WORKLOAD_IDENTITY_DIRECTORY": "/var/lib/aegis-ot/identity",
        "AEGIS_WORKLOAD_AUTHORITY_PRIVATE_KEY_FILE": (
            "/run/secrets/workload_authority_private"
        ),
        "AEGIS_AGENT_PUBLIC_KEY_FILE": "/run/secrets/agent_public",
        "AEGIS_GATEWAY_PUBLIC_KEY_FILE": "/run/secrets/gateway_public",
        "AEGIS_OT_PUBLIC_KEY_FILE": "/run/secrets/ot_public",
        "AEGIS_AGENT_TRUST_SEQUENCE_DIRECTORY": (
            "/var/lib/aegis-ot/trust-sequence-state/agent"
        ),
        "AEGIS_GATEWAY_TRUST_SEQUENCE_DIRECTORY": (
            "/var/lib/aegis-ot/trust-sequence-state/gateway"
        ),
        "AEGIS_OT_TRUST_SEQUENCE_DIRECTORY": (
            "/var/lib/aegis-ot/trust-sequence-state/ot"
        ),
    }
    for setting, expected in expected_environment.items():
        assert initializer["environment"][setting] == expected
    assert {
        "AEGIS_AGENT_ACTOR_ID",
        "AEGIS_AGENT_WORKLOAD_SUBJECT",
        "AEGIS_GATEWAY_WORKLOAD_SUBJECT",
        "AEGIS_OT_WORKLOAD_SUBJECT",
        "AEGIS_WORKLOAD_TRUST_DOMAIN",
        "AEGIS_RUNTIME_UID",
        "AEGIS_RUNTIME_GID",
    } <= initializer["environment"].keys()

    authority_holders = {
        name
        for name, service in IDENTITY["services"].items()
        if "workload_authority_private" in _secret_names(service)
    }
    assert authority_holders == {"identity-init", "identity-admin"}
    assert _secret_names(initializer) == {
        "workload_authority_private",
        "agent_public",
        "gateway_public",
        "ot_public",
    }
    administrator = _service("identity-admin")
    assert administrator["profiles"] == ["identity-admin"]
    assert administrator["network_mode"] == "none"
    assert administrator["read_only"] is True
    assert administrator["user"] == "65532:65532"
    assert administrator["entrypoint"] == [
        "python",
        "-m",
        "aegis_ot.m4g_identity_admin",
    ]
    assert _secret_names(administrator) == {"workload_authority_private"}
    assert administrator["volumes"] == [
        "workload_identity:/var/lib/aegis-ot/identity"
    ]


@pytest.mark.parametrize(
    ("service_name", "private_secret", "private_setting"),
    [
        (
            "segmented-gateway",
            "gateway_private",
            "AEGIS_GATEWAY_WORKLOAD_PRIVATE_KEY_FILE",
        ),
        ("ot-adapter", "ot_private", "AEGIS_OT_WORKLOAD_PRIVATE_KEY_FILE"),
        ("agent-probe", "agent_private", "AEGIS_AGENT_WORKLOAD_PRIVATE_KEY_FILE"),
    ],
)
def test_consequence_path_runtimes_require_identity_with_one_leaf_private_key(
    service_name: str,
    private_secret: str,
    private_setting: str,
) -> None:
    service = _service(service_name)
    environment = service["environment"]
    assert COMMON_ENVIRONMENT <= environment.keys()
    assert environment["AEGIS_WORKLOAD_IDENTITY_MODE"] == "required"
    assert environment["AEGIS_WORKLOAD_TRUST_ROOT_PUBLIC_KEY_FILE"] == (
        f"{RUNTIME_IDENTITY_PATH}/authority.public"
    )
    assert environment["AEGIS_WORKLOAD_TRUST_BUNDLE_FILE"] == (
        f"{RUNTIME_IDENTITY_PATH}/trust-bundle.json"
    )
    assert _secret_names(service) == {private_secret}
    assert environment[private_setting] == f"/run/secrets/{private_secret}"
    assert environment["AEGIS_WORKLOAD_TRUST_SEQUENCE_STATE_FILE"] == (
        "/var/lib/aegis-ot/trust-sequence/state.json"
    )
    assert service["volumes"].count(
        f"workload_identity:{RUNTIME_IDENTITY_PATH}:ro"
    ) == 1
    assert "workload_authority_private" not in _secret_names(service)
    assert all(
        "AUTHORITY_PRIVATE" not in setting for setting in environment
    )


def test_consequence_path_verifiers_use_isolated_writable_sequence_volumes() -> None:
    expected = {
        "segmented-gateway": "workload_trust_sequence_gateway",
        "ot-adapter": "workload_trust_sequence_ot",
        "agent-probe": "workload_trust_sequence_agent",
    }
    for service_name, volume in expected.items():
        service = _service(service_name)
        assert f"{volume}:/var/lib/aegis-ot/trust-sequence" in service["volumes"]
        assert all(
            not item.startswith(f"{other}:")
            for other in expected.values()
            if other != volume
            for item in service["volumes"]
        )
    assert all(
        "workload_trust_sequence_" not in item
        for item in _service("identity-admin")["volumes"]
    )


def test_runtime_credential_bindings_match_agent_gateway_ot_roles() -> None:
    gateway = _service("segmented-gateway")["environment"]
    ot = _service("ot-adapter")["environment"]
    agent = _service("agent-probe")["environment"]

    assert gateway["AEGIS_GATEWAY_WORKLOAD_CREDENTIAL_FILE"] == (
        f"{RUNTIME_IDENTITY_PATH}/gateway.credential.json"
    )
    assert gateway["AEGIS_OT_WORKLOAD_CREDENTIAL_FILE"] == (
        f"{RUNTIME_IDENTITY_PATH}/ot.credential.json"
    )
    assert ot["AEGIS_GATEWAY_WORKLOAD_CREDENTIAL_FILE"] == (
        f"{RUNTIME_IDENTITY_PATH}/gateway.credential.json"
    )
    assert ot["AEGIS_OT_WORKLOAD_CREDENTIAL_FILE"] == (
        f"{RUNTIME_IDENTITY_PATH}/ot.credential.json"
    )
    assert agent["AEGIS_AGENT_WORKLOAD_CREDENTIAL_FILE"] == (
        f"{RUNTIME_IDENTITY_PATH}/agent.credential.json"
    )
    assert agent["AEGIS_AGENT_WORKLOAD_SUBJECT"] == (
        "${AEGIS_AGENT_WORKLOAD_SUBJECT:-urn:aegis-ot:m4g:workload:agent-probe}"
    )
    assert agent["AEGIS_AGENT_ACTOR_ID"] == (
        "${AEGIS_AGENT_ACTOR_ID:-agent:operator-1}"
    )
    assert gateway["AEGIS_AGENT_ACTOR_ID"] == agent["AEGIS_AGENT_ACTOR_ID"]


def test_workload_replay_initializer_replaces_static_transport_initialization() -> None:
    replay = _service("replay-init")
    ot = _service("ot-adapter")

    assert replay["command"] == ["python", "-m", "aegis_ot.m4g_replay_init"]
    assert replay["environment"]["AEGIS_WORKLOAD_REPLAY_LEDGER_FILE"] == (
        "/var/lib/aegis-ot/workload-replay.json"
    )
    assert replay["environment"]["AEGIS_WORKLOAD_TRUST_ROOT_PUBLIC_KEY_FILE"] == (
        "/run/secrets/workload_authority_public"
    )
    assert _secret_names(replay) == {"workload_authority_public"}
    assert "workload_authority_private" not in _secret_names(replay)
    assert ot["environment"]["AEGIS_WORKLOAD_REPLAY_LEDGER_FILE"] == (
        "/var/lib/aegis-ot/workload-replay.json"
    )
    assert "workload_replay:/var/lib/aegis-ot" in replay["volumes"]
    assert "workload_replay:/var/lib/aegis-ot" in ot["volumes"]
    assert replay["depends_on"]["identity-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert ot["depends_on"]["replay-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert set(IDENTITY["volumes"]) == {
        "workload_identity",
        "workload_replay",
        "workload_trust_sequence_agent",
        "workload_trust_sequence_gateway",
        "workload_trust_sequence_ot",
    }


def test_probe_waits_for_identity_and_gateway_without_control_network_access() -> None:
    probe = _service("agent-probe")
    assert probe["depends_on"] == {
        "identity-init": {"condition": "service_completed_successfully"},
        "segmented-gateway": {"condition": "service_started"},
    }
    assert "networks" not in probe


def _compose_environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["COMPOSE_PROJECT_NAME"] = "aegis_identity_test"
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


def test_five_layer_compose_config_resolves_identity_and_replay_boundaries(
    tmp_path: Path,
) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")
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
    ):
        command.extend(("-f", str(ROOT / filename)))
    command.extend(
        (
            "--profile",
            "experiment",
            "--profile",
            "identity-admin",
            "config",
            "--format",
            "json",
        )
    )
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
    services = configured["services"]

    assert services["identity-init"]["network_mode"] == "none"
    assert services["replay-init"]["command"] == [
        "python",
        "-m",
        "aegis_ot.m4g_replay_init",
    ]
    assert services["segmented-gateway"]["environment"][
        "AEGIS_WORKLOAD_IDENTITY_MODE"
    ] == "required"
    for service_name in ("segmented-gateway", "ot-adapter", "agent-probe"):
        assert services[service_name]["environment"][
            "AEGIS_WORKLOAD_TRUST_SEQUENCE_STATE_FILE"
        ] == "/var/lib/aegis-ot/trust-sequence/state.json"
    assert services["ot-adapter"]["environment"][
        "AEGIS_WORKLOAD_REPLAY_LEDGER_FILE"
    ] == "/var/lib/aegis-ot/workload-replay.json"
    assert services["agent-probe"]["depends_on"]["segmented-gateway"][
        "condition"
    ] == "service_started"
    assert all(
        "workload_authority_private"
        not in {secret["source"] for secret in service.get("secrets", [])}
        for name, service in services.items()
        if name not in {"identity-init", "identity-admin"}
    )
    assert services["identity-admin"]["network_mode"] == "none"
    assert services["simulation"]["environment"]["AEGIS_OT_KEY_ID"] == (
        _compose_environment(tmp_path)["AEGIS_OT_WORKLOAD_KEY_ID"]
    )
