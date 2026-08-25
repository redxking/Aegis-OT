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
CAPABILITY_PATH = ROOT / "docker-compose.capability.yml"
CAPABILITY = yaml.safe_load(CAPABILITY_PATH.read_text(encoding="utf-8"))
COORDINATION_PATH = ROOT / "docker-compose.coordination.yml"
COORDINATION = yaml.safe_load(COORDINATION_PATH.read_text(encoding="utf-8"))

GATEWAY_DIRECTORY = "/var/lib/aegis-ot/gateway-coordination"
OT_DIRECTORY = "/var/lib/aegis-ot/ot-coordination"
PLANT_DIRECTORY = "/var/lib/aegis-ot/plant-checkpoint"
GATEWAY_FILE = f"{GATEWAY_DIRECTORY}/gateway-coordination.json"
OT_FILE = f"{OT_DIRECTORY}/ot-coordination.json"
PLANT_FILE = f"{PLANT_DIRECTORY}/plant-checkpoint.json"


def _service(name: str) -> dict[str, Any]:
    service = COORDINATION["services"][name]
    assert isinstance(service, dict)
    return service


def _capability_service(name: str) -> dict[str, Any]:
    service = CAPABILITY["services"][name]
    assert isinstance(service, dict)
    return service


def _compose_environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["COMPOSE_PROJECT_NAME"] = "aegis_coordination_config_test"
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
        "docker-compose.coordination.yml",
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


def test_coordination_initializer_is_bounded_offline_and_secretless() -> None:
    initializer = _service("coordination-init")
    assert initializer["command"] == ["python", "-m", "aegis_ot.m4i_coordination_init"]
    assert initializer["user"] == "0:0"
    assert initializer["read_only"] is True
    assert initializer["cap_drop"] == ["ALL"]
    assert initializer["cap_add"] == ["CHOWN"]
    assert initializer["restart"] == "no"
    assert initializer["network_mode"] == "none"
    assert initializer["pids_limit"] == 64
    assert initializer["mem_limit"] == "256m"
    assert "secrets" not in initializer
    assert initializer["environment"] == {
        "AEGIS_GATEWAY_COORDINATION_JOURNAL_FILE": GATEWAY_FILE,
        "AEGIS_GATEWAY_WORKLOAD_SUBJECT": (
            "${AEGIS_GATEWAY_WORKLOAD_SUBJECT:-urn:aegis-ot:m4g:workload:gateway}"
        ),
        "AEGIS_GATEWAY_RUNTIME_UID": "65532",
        "AEGIS_GATEWAY_RUNTIME_GID": "65532",
        "AEGIS_OT_COORDINATION_JOURNAL_FILE": OT_FILE,
        "AEGIS_OT_WORKLOAD_SUBJECT": (
            "${AEGIS_OT_WORKLOAD_SUBJECT:-urn:aegis-ot:m4g:workload:ot-adapter}"
        ),
        "AEGIS_OT_RUNTIME_UID": "65532",
        "AEGIS_OT_RUNTIME_GID": "65535",
        "AEGIS_PLANT_CHECKPOINT_FILE": PLANT_FILE,
        "AEGIS_PLANT_KEY_ID": "m4g-plant-key-v1",
        "AEGIS_PLANT_RUNTIME_UID": "65532",
        "AEGIS_PLANT_RUNTIME_GID": "65536",
    }


def test_capability_base_disables_coordination_for_simulation() -> None:
    simulation = _capability_service("simulation")
    assert simulation["environment"]["AEGIS_EFFECT_COORDINATION_MODE"] == "disabled"


def test_coordination_volumes_are_distinct_nested_mounts_with_closed_startup() -> None:
    initializer = _service("coordination-init")
    gateway = _service("segmented-gateway")
    ot = _service("ot-adapter")
    simulation = _service("simulation")

    assert initializer["volumes"] == [
        f"gateway_coordination:{GATEWAY_DIRECTORY}",
        f"ot_coordination:{OT_DIRECTORY}",
        f"plant_checkpoint:{PLANT_DIRECTORY}",
    ]
    assert gateway["volumes"] == [f"gateway_coordination:{GATEWAY_DIRECTORY}"]
    assert ot["volumes"] == [f"ot_coordination:{OT_DIRECTORY}"]
    assert simulation["volumes"] == [f"plant_checkpoint:{PLANT_DIRECTORY}"]
    assert set(COORDINATION["volumes"]) == {
        "gateway_coordination",
        "ot_coordination",
        "plant_checkpoint",
    }
    for service in (initializer, gateway, ot, simulation):
        assert all(
            not mount.endswith(":/var/lib/aegis-ot")
            and "workload_replay" not in mount
            and "workload_identity" not in mount
            for mount in service["volumes"]
        )
    assert gateway["environment"] == {
        "AEGIS_EFFECT_COORDINATION_MODE": "required",
        "AEGIS_GATEWAY_COORDINATION_JOURNAL_FILE": GATEWAY_FILE,
    }
    assert ot["environment"] == {
        "AEGIS_EFFECT_COORDINATION_MODE": "required",
        "AEGIS_OT_COORDINATION_JOURNAL_FILE": OT_FILE,
    }
    assert simulation["environment"] == {
        "AEGIS_EFFECT_COORDINATION_MODE": "required",
        "AEGIS_PLANT_CHECKPOINT_FILE": PLANT_FILE,
    }
    for service in (gateway, ot, simulation):
        assert service["depends_on"] == {
            "coordination-init": {"condition": "service_completed_successfully"}
        }


def test_seven_layer_compose_preserves_replay_and_coordination_mounts(
    tmp_path: Path,
) -> None:
    services = _resolved_config(tmp_path)["services"]
    initializer = services["coordination-init"]
    assert initializer["network_mode"] == "none"
    assert "secrets" not in initializer

    gateway = services["segmented-gateway"]
    ot = services["ot-adapter"]
    simulation = services["simulation"]
    assert gateway["user"] == "65532:65532"
    assert ot["user"] == "65532:65535"
    assert simulation["user"] == "65532:65536"
    assert gateway["environment"]["AEGIS_EFFECT_COORDINATION_MODE"] == "required"
    assert ot["environment"]["AEGIS_EFFECT_COORDINATION_MODE"] == "required"
    assert simulation["environment"]["AEGIS_EFFECT_COORDINATION_MODE"] == "required"
    assert simulation["environment"]["AEGIS_PLANT_CHECKPOINT_FILE"] == PLANT_FILE
    assert gateway["depends_on"]["coordination-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert ot["depends_on"]["coordination-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert simulation["depends_on"]["coordination-init"]["condition"] == (
        "service_completed_successfully"
    )

    gateway_mounts = {item["target"]: item["source"] for item in gateway["volumes"]}
    ot_mounts = {item["target"]: item["source"] for item in ot["volumes"]}
    plant_mounts = {item["target"]: item["source"] for item in simulation["volumes"]}
    assert gateway_mounts[GATEWAY_DIRECTORY] == "gateway_coordination"
    assert ot_mounts[OT_DIRECTORY] == "ot_coordination"
    assert plant_mounts[PLANT_DIRECTORY] == "plant_checkpoint"
    assert ot_mounts["/var/lib/aegis-ot"] == "workload_replay"
    assert (
        len(
            {
                gateway_mounts[GATEWAY_DIRECTORY],
                ot_mounts[OT_DIRECTORY],
                plant_mounts[PLANT_DIRECTORY],
            }
        )
        == 3
    )
    assert initializer["environment"]["AEGIS_PLANT_RUNTIME_UID"] == "65532"
    assert initializer["environment"]["AEGIS_PLANT_RUNTIME_GID"] == "65536"
