from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis_ot.m5_degraded_init as degraded_init
from aegis_ot.m5_degraded import (
    DegradedModeReversal,
    DegradedRole,
    RoleCondition,
)
from aegis_ot.m5_degraded_publication import DegradedStatusInput

ROOT = Path(__file__).resolve().parents[1]
DEGRADED_PATH = ROOT / "docker-compose.degraded.yml"
DEGRADED_TEXT = DEGRADED_PATH.read_text(encoding="utf-8")
DEGRADED = yaml.safe_load(DEGRADED_TEXT)

PUBLICATION_DIRECTORY = "/var/lib/aegis-ot/m5-publication"
PUBLISHER_STATE_DIRECTORY = "/var/lib/aegis-ot/m5-publisher-state"
CONSUMER_STATE_DIRECTORY = "/var/lib/aegis-ot/m5-consumer-state"
REVERSAL_DIRECTORY = "/var/lib/aegis-ot/m5-reversal-inbox"
PUBLISHER_INPUT_DIRECTORY = "/var/lib/aegis-ot/m5-publisher-inputs"
GATEWAY_INPUT_DIRECTORY = "/var/lib/aegis-ot/m5-gateway-inputs"
STATUS_INPUT_DIRECTORY = "/var/lib/aegis-ot/m5-status-input"
PUBLICATION_FILE = f"{PUBLICATION_DIRECTORY}/publication.json"
PUBLISHER_STATE_FILE = f"{PUBLISHER_STATE_DIRECTORY}/state.json"
CONSUMER_STATE_FILE = f"{CONSUMER_STATE_DIRECTORY}/state.json"
REVERSAL_FILE = f"{REVERSAL_DIRECTORY}/reversal.json"


def _canonical_model(value: Any) -> bytes:
    return (
        json.dumps(
            value.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _service(name: str) -> dict[str, Any]:
    service = DEGRADED["services"][name]
    assert isinstance(service, dict)
    return service


def _compose_environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["COMPOSE_PROJECT_NAME"] = "aegis_m5_degraded_config_test"
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
        "M5_ROOT_PUBLIC",
        "M5_PUBLISHER_PRIVATE",
    ):
        path = tmp_path / f"{name.lower()}.key"
        path.write_bytes(b"k" * 32)
        environment[f"AEGIS_{name}_KEY_FILE"] = str(path)
    for name in (
        "M5_PUBLISHER_CREDENTIAL",
        "M5_STABLE_AUTHORIZATION",
        "M5_STATUS_INPUT",
        "M5_REVERSAL_INPUT",
    ):
        path = tmp_path / f"{name.lower()}.json"
        path.write_text("{}\n", encoding="utf-8")
        environment[f"AEGIS_{name}_FILE"] = str(path)
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
        "docker-compose.degraded.yml",
    ):
        command.extend(("-f", str(ROOT / filename)))
    command.extend(
        (
            "--profile",
            "experiment",
            "--profile",
            "m5-maintenance",
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
    assert isinstance(configured, dict)
    return configured


def _configure_initializer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[tuple[Path, Path, Path, Path], tuple[Path, Path, Path]]:
    paths = (
        tmp_path / "publication" / "publication.json",
        tmp_path / "publisher-state" / "state.json",
        tmp_path / "consumer-state" / "state.json",
        tmp_path / "reversal-inbox" / "reversal.json",
    )
    for path in paths:
        path.parent.mkdir()
    input_directories = (
        tmp_path / "publisher-inputs",
        tmp_path / "gateway-inputs",
        tmp_path / "status-input",
    )
    for directory in input_directories:
        directory.mkdir()
    environment: dict[str, str | int | Path] = {
        "AEGIS_M5_PUBLICATION_FILE": paths[0],
        "AEGIS_M5_PUBLISHER_STATE_FILE": paths[1],
        "AEGIS_M5_CONSUMER_STATE_FILE": paths[2],
        "AEGIS_M5_REVERSAL_FILE": paths[3],
        "AEGIS_M5_PUBLISHER_INPUT_DIRECTORY": input_directories[0],
        "AEGIS_M5_GATEWAY_INPUT_DIRECTORY": input_directories[1],
        "AEGIS_M5_STATUS_INPUT_FILE": input_directories[2] / "status-input.json",
        "AEGIS_M5_RUNTIME_UID": os.getuid(),
        "AEGIS_M5_RUNTIME_GID": os.getgid(),
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, str(value))
    return paths, input_directories


def test_initializer_assigns_four_empty_private_volume_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, input_directories = _configure_initializer(tmp_path, monkeypatch)

    def prepare_empty_roots(
        _paths: Any,
        directory_states: tuple[Any, ...],
        *,
        runtime_uid: int,
        runtime_gid: int,
    ) -> None:
        for directory_state in directory_states:
            directory = directory_state.definition.directory
            directory.chmod(0o700)
            os.chown(directory, runtime_uid, runtime_gid)

    monkeypatch.setattr(degraded_init, "_bootstrap", prepare_empty_roots)

    summary = degraded_init.initialize()

    directories = tuple(path.parent for path in paths) + input_directories
    for directory in directories:
        assert list(directory.iterdir()) == []
        directory_stat = directory.stat()
        assert directory_stat.st_uid == os.getuid()
        assert directory_stat.st_gid == os.getgid()
        assert stat.S_IMODE(directory_stat.st_mode) == 0o700
    assert summary == {
        "schema_version": "m5-signed-publication-volume-initialization-v2",
        "directory_count": 7,
        "publication_file": str(paths[0]),
        "publisher_state_file": str(paths[1]),
        "consumer_state_file": str(paths[2]),
        "reversal_file": str(paths[3]),
        "status_input_file": str(input_directories[2] / "status-input.json"),
        "publisher_input_directory": str(input_directories[0]),
        "gateway_input_directory": str(input_directories[1]),
        "runtime_uid": os.getuid(),
        "runtime_gid": os.getgid(),
        "directory_mode": "0700",
        "artifact_mode": "0600",
        "volume_set_state": "bootstrap_prepared",
        "secrets_consumed": 5,
    }

    for index, directory in enumerate(directories):
        (directory / f"runtime-owned-{index}").write_text(
            "runtime-owned-state\n", encoding="utf-8"
        )
    preserved = degraded_init.initialize()
    assert preserved["volume_set_state"] == "runtime_owned_preserved_uninspected"
    assert preserved["secrets_consumed"] == 0
    for index, directory in enumerate(directories):
        assert (directory / f"runtime-owned-{index}").read_text(encoding="utf-8") == (
            "runtime-owned-state\n"
        )


def test_initializer_refuses_shared_populated_or_symlinked_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _ = _configure_initializer(tmp_path, monkeypatch)
    monkeypatch.setenv(
        "AEGIS_M5_CONSUMER_STATE_FILE",
        str(paths[1].parent / "consumer-state.json"),
    )
    with pytest.raises(RuntimeError, match="isolated directories"):
        degraded_init.initialize()

    monkeypatch.setenv("AEGIS_M5_CONSUMER_STATE_FILE", str(paths[2]))
    retained = paths[0].parent / "retained-publication.json"
    retained.write_text("do-not-overwrite\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="must be empty"):
        degraded_init.initialize()
    assert retained.read_text(encoding="utf-8") == "do-not-overwrite\n"

    retained.unlink()
    real_directory = tmp_path / "real-publication"
    real_directory.mkdir()
    symlink_directory = tmp_path / "linked-publication"
    symlink_directory.symlink_to(real_directory, target_is_directory=True)
    monkeypatch.setenv(
        "AEGIS_M5_PUBLICATION_FILE",
        str(symlink_directory / "publication.json"),
    )
    with pytest.raises(RuntimeError, match="non-symlink directory"):
        degraded_init.initialize()


def test_injectors_validate_typed_canonical_models_and_replace_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 26, 18, 0, tzinfo=UTC)
    healthy = {role: RoleCondition.HEALTHY for role in DegradedRole}
    services = dict(healthy)
    services[DegradedRole.OBSERVER] = RoleCondition.UNAVAILABLE
    status_input = DegradedStatusInput(
        status_input_id="m5-status-injector-input-0001",
        source_id="m5-status-source-0001",
        role_conditions=services,
        communication_conditions=healthy,
        unresolved_effect=False,
    )
    key = Ed25519PrivateKey.generate()
    reversal = DegradedModeReversal(
        reversal_id="m5-reversal-injector-direction-0001",
        sequence=1,
        authority_id="m5-operator-authority",
        authorization_id="m5-stable-authorization-0001",
        authorization_sha256="a" * 64,
        recovery_checkpoint_id="m5-recovery-checkpoint-0001",
        reason_code="runtime_dependencies_recovered",
        nonce="m5-reversal-injector-nonce-0001",
        issued_at=now,
    ).signed(key)
    status_source = tmp_path / "status-source.json"
    reversal_source = tmp_path / "reversal-source.json"
    status_source.write_bytes(_canonical_model(status_input))
    reversal_source.write_bytes(_canonical_model(reversal))
    status_directory = tmp_path / "status-target"
    reversal_directory = tmp_path / "reversal-target"
    status_directory.mkdir(mode=0o700)
    reversal_directory.mkdir(mode=0o700)
    status_target = status_directory / "status.json"
    reversal_target = reversal_directory / "reversal.json"
    monkeypatch.setenv("AEGIS_M5_STATUS_INPUT_SOURCE_FILE", str(status_source))
    monkeypatch.setenv("AEGIS_M5_STATUS_INPUT_FILE", str(status_target))
    monkeypatch.setenv("AEGIS_M5_REVERSAL_SOURCE_FILE", str(reversal_source))
    monkeypatch.setenv("AEGIS_M5_REVERSAL_FILE", str(reversal_target))

    status_report = degraded_init.inject_status()
    reversal_report = degraded_init.inject_reversal()

    assert status_report["status_input_sha256"] == status_input.digest
    assert reversal_report["reversal_sha256"] == reversal.digest
    assert status_target.read_bytes() == _canonical_model(status_input)
    assert reversal_target.read_bytes() == _canonical_model(reversal)
    assert stat.S_IMODE(status_target.stat().st_mode) == 0o600
    assert stat.S_IMODE(reversal_target.stat().st_mode) == 0o600

    status_source.write_text(
        json.dumps(status_input.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="not canonical JSON"):
        degraded_init.inject_status()
    assert status_target.read_bytes() == _canonical_model(status_input)


def test_compose_never_provisions_the_offline_root_private_key() -> None:
    assert "ROOT_PRIVATE" not in DEGRADED_TEXT.upper()
    assert "root private" not in DEGRADED_TEXT.lower()
    assert "m5_root_public" in DEGRADED["secrets"]
    assert set(DEGRADED["secrets"]) == {
        "m5_root_public",
        "m5_publisher_credential",
        "m5_publisher_private",
        "m5_stable_authorization",
        "m5_status_input",
        "m5_reversal_input",
    }


def test_initializer_is_root_chown_only_networkless_and_stages_five_inputs() -> None:
    initializer = _service("m5-degraded-init")
    assert initializer["command"] == ["python", "-m", "aegis_ot.m5_degraded_init"]
    assert initializer["user"] == "0:0"
    assert initializer["read_only"] is True
    assert initializer["cap_drop"] == ["ALL"]
    assert initializer["cap_add"] == ["CHOWN"]
    assert initializer["restart"] == "no"
    assert initializer["network_mode"] == "none"
    assert initializer["pids_limit"] == 64
    assert initializer["mem_limit"] == "256m"
    assert initializer["environment"] == {
        "AEGIS_M5_PUBLICATION_FILE": PUBLICATION_FILE,
        "AEGIS_M5_PUBLISHER_STATE_FILE": PUBLISHER_STATE_FILE,
        "AEGIS_M5_CONSUMER_STATE_FILE": CONSUMER_STATE_FILE,
        "AEGIS_M5_REVERSAL_FILE": REVERSAL_FILE,
        "AEGIS_M5_RUNTIME_UID": "65532",
        "AEGIS_M5_RUNTIME_GID": "65532",
        "AEGIS_M5_PUBLISHER_INPUT_DIRECTORY": PUBLISHER_INPUT_DIRECTORY,
        "AEGIS_M5_GATEWAY_INPUT_DIRECTORY": GATEWAY_INPUT_DIRECTORY,
        "AEGIS_M5_STATUS_INPUT_FILE": f"{STATUS_INPUT_DIRECTORY}/status-input.json",
        "AEGIS_M5_ROOT_PUBLIC_KEY_SOURCE_FILE": "/run/secrets/m5_root_public",
        "AEGIS_M5_PUBLISHER_CREDENTIAL_SOURCE_FILE": (
            "/run/secrets/m5_publisher_credential"
        ),
        "AEGIS_M5_PUBLISHER_PRIVATE_KEY_SOURCE_FILE": (
            "/run/secrets/m5_publisher_private"
        ),
        "AEGIS_M5_STABLE_AUTHORIZATION_SOURCE_FILE": (
            "/run/secrets/m5_stable_authorization"
        ),
        "AEGIS_M5_STATUS_INPUT_SOURCE_FILE": "/run/secrets/m5_status_input",
    }
    assert initializer["secrets"] == [
        "m5_root_public",
        "m5_publisher_credential",
        "m5_publisher_private",
        "m5_stable_authorization",
        "m5_status_input",
    ]
    assert initializer["volumes"] == [
        f"m5_publication:{PUBLICATION_DIRECTORY}",
        f"m5_publisher_state:{PUBLISHER_STATE_DIRECTORY}",
        f"m5_consumer_state:{CONSUMER_STATE_DIRECTORY}",
        f"m5_reversal_inbox:{REVERSAL_DIRECTORY}",
        f"m5_publisher_inputs:{PUBLISHER_INPUT_DIRECTORY}",
        f"m5_gateway_inputs:{GATEWAY_INPUT_DIRECTORY}",
        f"m5_status_input:{STATUS_INPUT_DIRECTORY}",
    ]


def test_publisher_is_nonroot_networkless_and_holds_only_the_leaf_private_key() -> None:
    publisher = _service("m5-degraded-publisher")
    assert publisher["command"] == [
        "python",
        "-m",
        "aegis_ot.m5_degraded_publication",
        "run",
    ]
    assert publisher["user"] == "65532:65532"
    assert publisher["read_only"] is True
    assert publisher["cap_drop"] == ["ALL"]
    assert "cap_add" not in publisher
    assert publisher["network_mode"] == "none"
    assert publisher["pids_limit"] == 64
    assert publisher["mem_limit"] == "256m"
    assert publisher["environment"] == {
        "AEGIS_M5_PUBLICATION_FILE": PUBLICATION_FILE,
        "AEGIS_M5_PUBLISHER_STATE_FILE": PUBLISHER_STATE_FILE,
        "AEGIS_M5_ROOT_PUBLIC_KEY_FILE": (
            f"{PUBLISHER_INPUT_DIRECTORY}/operator-authority.public"
        ),
        "AEGIS_M5_PUBLISHER_CREDENTIAL_FILE": (
            f"{PUBLISHER_INPUT_DIRECTORY}/publisher-credential.json"
        ),
        "AEGIS_M5_STABLE_AUTHORIZATION_FILE": (
            f"{PUBLISHER_INPUT_DIRECTORY}/stable-authorization.json"
        ),
        "AEGIS_M5_PUBLISHER_PRIVATE_KEY_FILE": (
            f"{PUBLISHER_INPUT_DIRECTORY}/publisher.private"
        ),
        "AEGIS_M5_STATUS_INPUT_FILE": f"{STATUS_INPUT_DIRECTORY}/status-input.json",
        "AEGIS_M5_PUBLISH_INTERVAL_SECONDS": (
            "${AEGIS_M5_PUBLISH_INTERVAL_SECONDS:-1}"
        ),
    }
    assert "secrets" not in publisher
    private_inputs = [
        value for key, value in publisher["environment"].items() if "PRIVATE" in key
    ]
    assert private_inputs == [f"{PUBLISHER_INPUT_DIRECTORY}/publisher.private"]
    assert publisher["volumes"] == [
        f"m5_publication:{PUBLICATION_DIRECTORY}",
        f"m5_publisher_state:{PUBLISHER_STATE_DIRECTORY}",
        f"m5_publisher_inputs:{PUBLISHER_INPUT_DIRECTORY}:ro",
        f"m5_status_input:{STATUS_INPUT_DIRECTORY}:ro",
    ]
    assert publisher["depends_on"] == {
        "m5-degraded-init": {"condition": "service_completed_successfully"}
    }
    assert publisher["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-m",
        "aegis_ot.m5_degraded_publication",
        "check",
    ]


def test_gateway_requires_healthy_publication_and_has_isolated_consumer_state() -> None:
    gateway = _service("segmented-gateway")
    assert gateway["environment"] == {
        "AEGIS_M5_PUBLICATION_FILE": PUBLICATION_FILE,
        "AEGIS_M5_CONSUMER_STATE_FILE": CONSUMER_STATE_FILE,
        "AEGIS_M5_REVERSAL_FILE": REVERSAL_FILE,
        "AEGIS_M5_ROOT_PUBLIC_KEY_FILE": (
            f"{GATEWAY_INPUT_DIRECTORY}/operator-authority.public"
        ),
        "AEGIS_M5_PUBLISHER_CREDENTIAL_FILE": (
            f"{GATEWAY_INPUT_DIRECTORY}/publisher-credential.json"
        ),
        "AEGIS_M5_STABLE_AUTHORIZATION_FILE": (
            f"{GATEWAY_INPUT_DIRECTORY}/stable-authorization.json"
        ),
        "AEGIS_M5_SIGNED_PUBLICATION_MODE": "required",
    }
    assert "secrets" not in gateway
    assert gateway["volumes"] == [
        f"m5_publication:{PUBLICATION_DIRECTORY}:ro",
        f"m5_consumer_state:{CONSUMER_STATE_DIRECTORY}",
        f"m5_reversal_inbox:{REVERSAL_DIRECTORY}:ro",
        f"m5_gateway_inputs:{GATEWAY_INPUT_DIRECTORY}:ro",
    ]
    assert gateway["depends_on"] == {
        "m5-degraded-init": {"condition": "service_completed_successfully"},
        "m5-degraded-publisher": {"condition": "service_healthy"},
    }
    assert set(DEGRADED["volumes"]) == {
        "m5_publication",
        "m5_publisher_state",
        "m5_consumer_state",
        "m5_reversal_inbox",
        "m5_publisher_inputs",
        "m5_gateway_inputs",
        "m5_status_input",
    }


def test_profiled_injectors_are_nonroot_networkless_and_single_purpose() -> None:
    status_injector = _service("m5-status-injector")
    reversal_injector = _service("m5-reversal-injector")
    expected = (
        (
            status_injector,
            ["python", "-m", "aegis_ot.m5_degraded_init", "inject-status"],
            ["m5_status_input"],
            [f"m5_status_input:{STATUS_INPUT_DIRECTORY}"],
        ),
        (
            reversal_injector,
            ["python", "-m", "aegis_ot.m5_degraded_init", "inject-reversal"],
            ["m5_reversal_input"],
            [f"m5_reversal_inbox:{REVERSAL_DIRECTORY}"],
        ),
    )
    for service, command, secrets, volumes in expected:
        assert service["profiles"] == ["m5-maintenance"]
        assert service["command"] == command
        assert service["user"] == "65532:65532"
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "cap_add" not in service
        assert service["network_mode"] == "none"
        assert service["restart"] == "no"
        assert service["secrets"] == secrets
        assert service["volumes"] == volumes
        assert service["depends_on"] == {
            "m5-degraded-init": {"condition": "service_completed_successfully"}
        }
        assert "m5_publisher_private" not in service["secrets"]


def test_eight_layer_compose_resolves_trusted_m5_boundaries(tmp_path: Path) -> None:
    services = _resolved_config(tmp_path)["services"]
    initializer = services["m5-degraded-init"]
    publisher = services["m5-degraded-publisher"]
    gateway = services["segmented-gateway"]

    assert initializer["network_mode"] == "none"
    assert {item["source"] for item in initializer["secrets"]} == {
        "m5_root_public",
        "m5_publisher_credential",
        "m5_publisher_private",
        "m5_stable_authorization",
        "m5_status_input",
    }
    assert publisher["network_mode"] == "none"
    assert publisher["user"] == "65532:65532"
    assert gateway["user"] == "65532:65532"
    assert gateway["environment"]["AEGIS_M5_SIGNED_PUBLICATION_MODE"] == "required"
    assert gateway["depends_on"]["m5-degraded-publisher"]["condition"] == (
        "service_healthy"
    )

    publisher_mounts = {item["target"]: item for item in publisher["volumes"]}
    gateway_mounts = {item["target"]: item for item in gateway["volumes"]}
    assert set(publisher_mounts) == {
        PUBLICATION_DIRECTORY,
        PUBLISHER_STATE_DIRECTORY,
        PUBLISHER_INPUT_DIRECTORY,
        STATUS_INPUT_DIRECTORY,
    }
    assert publisher_mounts[PUBLICATION_DIRECTORY].get("read_only", False) is False
    assert publisher_mounts[PUBLISHER_STATE_DIRECTORY].get("read_only", False) is False
    assert publisher_mounts[PUBLISHER_INPUT_DIRECTORY]["read_only"] is True
    assert publisher_mounts[STATUS_INPUT_DIRECTORY]["read_only"] is True
    assert gateway_mounts[PUBLICATION_DIRECTORY]["read_only"] is True
    assert gateway_mounts[CONSUMER_STATE_DIRECTORY].get("read_only", False) is False
    assert gateway_mounts[REVERSAL_DIRECTORY]["read_only"] is True
    assert gateway_mounts[GATEWAY_INPUT_DIRECTORY]["read_only"] is True
    assert PUBLISHER_STATE_DIRECTORY not in gateway_mounts

    assert "secrets" not in publisher
    gateway_secrets = {item["source"] for item in gateway["secrets"]}
    assert not {name for name in gateway_secrets if name.startswith("m5_")}
    assert "PRIVATE" not in " ".join(
        key for key in gateway["environment"] if key.startswith("AEGIS_M5_")
    )
