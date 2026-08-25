from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
AUTH = yaml.safe_load((ROOT / "docker-compose.auth.yml").read_text(encoding="utf-8"))
REPLAY = yaml.safe_load((ROOT / "docker-compose.replay.yml").read_text(encoding="utf-8"))
CAPABILITY = yaml.safe_load(
    (ROOT / "docker-compose.capability.yml").read_text(encoding="utf-8")
)

M4G_SERVICES = {
    "segmented-gateway",
    "observer",
    "candidate",
    "ot-adapter",
    "simulation",
    "agent-probe",
}

EXPECTED_COMMANDS = {
    "segmented-gateway": [
        "uvicorn",
        "aegis_ot.segmented_capability_runtime:capability_gateway_app",
        "--host",
        "0.0.0.0",  # noqa: S104 - exact container bind regression check
        "--port",
        "8081",
    ],
    "observer": [
        "uvicorn",
        "aegis_ot.segmented_capability_runtime:capability_observer_app",
        "--host",
        "0.0.0.0",  # noqa: S104 - exact container bind regression check
        "--port",
        "8082",
    ],
    "candidate": [
        "uvicorn",
        "aegis_ot.segmented_capability_runtime:capability_candidate_app",
        "--host",
        "0.0.0.0",  # noqa: S104 - exact container bind regression check
        "--port",
        "8085",
    ],
    "ot-adapter": [
        "uvicorn",
        "aegis_ot.segmented_capability_runtime:capability_ot_app",
        "--host",
        "0.0.0.0",  # noqa: S104 - exact container bind regression check
        "--port",
        "8083",
    ],
    "simulation": [
        "uvicorn",
        "aegis_ot.segmented_capability_runtime:capability_plant_app",
        "--host",
        "0.0.0.0",  # noqa: S104 - exact container bind regression check
        "--port",
        "8084",
    ],
    "agent-probe": ["python", "-m", "aegis_ot.m4g_probe"],
}

EXPECTED_SECRETS = {
    "segmented-gateway": {
        "gateway_private",
        "ot_public",
        "permit_private",
        "observer_public",
        "candidate_public",
        "plant_public",
    },
    "observer": {"observer_private", "plant_public"},
    "candidate": {"candidate_private", "plant_public"},
    "ot-adapter": {
        "gateway_public",
        "ot_private",
        "permit_public",
        "observer_public",
        "plant_public",
    },
    "simulation": {
        "observer_public",
        "candidate_public",
        "ot_public",
        "plant_private",
    },
}

RUNTIME_REQUIRED_ENVIRONMENT = {
    "segmented-gateway": {
        "AEGIS_CANDIDATE_KEY_ID",
        "AEGIS_CANDIDATE_PUBLIC_KEY_FILE",
        "AEGIS_CANDIDATE_URL",
        "AEGIS_GATEWAY_KEY_ID",
        "AEGIS_GATEWAY_PRIVATE_KEY_FILE",
        "AEGIS_OBSERVER_KEY_ID",
        "AEGIS_OBSERVER_PUBLIC_KEY_FILE",
        "AEGIS_OBSERVER_URL",
        "AEGIS_OT_KEY_ID",
        "AEGIS_OT_PUBLIC_KEY_FILE",
        "AEGIS_OT_URL",
        "AEGIS_PERMIT_KEY_ID",
        "AEGIS_PERMIT_PRIVATE_KEY_FILE",
        "AEGIS_PLANT_KEY_ID",
        "AEGIS_PLANT_PUBLIC_KEY_FILE",
    },
    "observer": {
        "AEGIS_OBSERVER_KEY_ID",
        "AEGIS_OBSERVER_PRIVATE_KEY_FILE",
        "AEGIS_PLANT_KEY_ID",
        "AEGIS_PLANT_PUBLIC_KEY_FILE",
        "AEGIS_PLANT_URL",
    },
    "candidate": {
        "AEGIS_CANDIDATE_KEY_ID",
        "AEGIS_CANDIDATE_PRIVATE_KEY_FILE",
        "AEGIS_PLANT_KEY_ID",
        "AEGIS_PLANT_PUBLIC_KEY_FILE",
        "AEGIS_PLANT_URL",
    },
    "ot-adapter": {
        "AEGIS_GATEWAY_KEY_ID",
        "AEGIS_GATEWAY_PUBLIC_KEY_FILE",
        "AEGIS_OBSERVER_KEY_ID",
        "AEGIS_OBSERVER_PUBLIC_KEY_FILE",
        "AEGIS_OBSERVER_URL",
        "AEGIS_OT_KEY_ID",
        "AEGIS_OT_PRIVATE_KEY_FILE",
        "AEGIS_PERMIT_KEY_ID",
        "AEGIS_PERMIT_PUBLIC_KEY_FILE",
        "AEGIS_PLANT_KEY_ID",
        "AEGIS_PLANT_PUBLIC_KEY_FILE",
        "AEGIS_PLANT_URL",
        "AEGIS_SEMANTIC_REPLAY_LEDGER_FILE",
        "AEGIS_TRANSPORT_REPLAY_LEDGER_FILE",
    },
    "simulation": {
        "AEGIS_CANDIDATE_KEY_ID",
        "AEGIS_CANDIDATE_PUBLIC_KEY_FILE",
        "AEGIS_OBSERVER_KEY_ID",
        "AEGIS_OBSERVER_PUBLIC_KEY_FILE",
        "AEGIS_OT_KEY_ID",
        "AEGIS_OT_PUBLIC_KEY_FILE",
        "AEGIS_PLANT_KEY_ID",
        "AEGIS_PLANT_PRIVATE_KEY_FILE",
    },
}

RUNTIME_KEY_SECRETS = {
    "segmented-gateway": {
        "AEGIS_CANDIDATE_PUBLIC_KEY_FILE": "candidate_public",
        "AEGIS_GATEWAY_PRIVATE_KEY_FILE": "gateway_private",
        "AEGIS_OBSERVER_PUBLIC_KEY_FILE": "observer_public",
        "AEGIS_OT_PUBLIC_KEY_FILE": "ot_public",
        "AEGIS_PERMIT_PRIVATE_KEY_FILE": "permit_private",
        "AEGIS_PLANT_PUBLIC_KEY_FILE": "plant_public",
    },
    "observer": {
        "AEGIS_OBSERVER_PRIVATE_KEY_FILE": "observer_private",
        "AEGIS_PLANT_PUBLIC_KEY_FILE": "plant_public",
    },
    "candidate": {
        "AEGIS_CANDIDATE_PRIVATE_KEY_FILE": "candidate_private",
        "AEGIS_PLANT_PUBLIC_KEY_FILE": "plant_public",
    },
    "ot-adapter": {
        "AEGIS_GATEWAY_PUBLIC_KEY_FILE": "gateway_public",
        "AEGIS_OBSERVER_PUBLIC_KEY_FILE": "observer_public",
        "AEGIS_OT_PRIVATE_KEY_FILE": "ot_private",
        "AEGIS_PERMIT_PUBLIC_KEY_FILE": "permit_public",
        "AEGIS_PLANT_PUBLIC_KEY_FILE": "plant_public",
    },
    "simulation": {
        "AEGIS_CANDIDATE_PUBLIC_KEY_FILE": "candidate_public",
        "AEGIS_OBSERVER_PUBLIC_KEY_FILE": "observer_public",
        "AEGIS_OT_PUBLIC_KEY_FILE": "ot_public",
        "AEGIS_PLANT_PRIVATE_KEY_FILE": "plant_private",
    },
}

STACK = (BASE, AUTH, REPLAY, CAPABILITY)


def _service(name: str) -> dict[str, object]:
    value = CAPABILITY["services"][name]
    assert isinstance(value, dict)
    return value


def _effective_environment(name: str) -> dict[str, object]:
    environment: dict[str, object] = {}
    for document in STACK:
        service = document.get("services", {}).get(name, {})
        environment.update(service.get("environment", {}))
    return environment


def test_m4g_commands_select_only_the_capability_apps() -> None:
    assert {
        name: _service(name)["command"] for name in EXPECTED_COMMANDS
    } == EXPECTED_COMMANDS


def test_m4g_builds_are_digest_pinned_and_install_simulation_dependencies() -> None:
    for name in M4G_SERVICES:
        build = _service(name)["build"]
        assert build["context"] == "."
        assert build["args"]["AEGIS_INSTALL_TARGET"] == ".[simulation]"
        assert build["args"]["PYTHON_IMAGE"].startswith(
            "${PYTHON_IMAGE:-python:3.13.7-slim@sha256:"
        )
        assert build["args"]["PYTHON_IMAGE"].endswith("}")

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG AEGIS_INSTALL_TARGET=." in dockerfile
    assert '"${AEGIS_INSTALL_TARGET}" != "."' in dockerfile
    assert '"${AEGIS_INSTALL_TARGET}" != ".[simulation]"' in dockerfile
    assert '"${AEGIS_INSTALL_TARGET}"' in dockerfile


def test_m4g_preserves_the_segmented_network_boundary() -> None:
    services = BASE["services"]
    networks = BASE["networks"]

    assert services["agent-probe"]["networks"] == ["agent"]
    assert set(services["segmented-gateway"]["networks"]) == {
        "agent",
        "trust",
        "control_dmz",
    }
    assert set(services["observer"]["networks"]) == {"control_dmz", "simulation"}
    assert set(services["ot-adapter"]["networks"]) == {"control_dmz", "simulation"}
    assert services["simulation"]["networks"] == ["simulation"]
    assert _service("candidate")["networks"] == ["control_dmz", "simulation"]
    assert all(
        networks[name].get("internal") is True
        for name in ("trust", "control_dmz", "simulation")
    )

    assert services["segmented-gateway"]["ports"] == ["127.0.0.1:8081:8081"]
    for name in M4G_SERVICES - {"segmented-gateway"}:
        overlay = _service(name)
        base = services.get(name, {})
        assert "ports" not in overlay
        assert "ports" not in base


def test_m4g_services_remain_read_only_and_drop_all_capabilities() -> None:
    for name in M4G_SERVICES:
        overlay = _service(name)
        base = BASE["services"].get(name, {})
        assert overlay.get("read_only", base.get("read_only")) is True
        assert overlay.get("cap_drop", base.get("cap_drop")) == ["ALL"]


def test_m4g_secret_distribution_is_exact_and_private_keys_are_not_overdistributed() -> None:
    for name, expected in EXPECTED_SECRETS.items():
        assert set(_service(name)["secrets"]) == expected

    private_holders = {
        secret: {
            name
            for name, assigned in EXPECTED_SECRETS.items()
            if secret in assigned
        }
        for secret in (
            "gateway_private",
            "ot_private",
            "permit_private",
            "observer_private",
            "candidate_private",
            "plant_private",
        )
    }
    assert private_holders == {
        "gateway_private": {"segmented-gateway"},
        "ot_private": {"ot-adapter"},
        "permit_private": {"segmented-gateway"},
        "observer_private": {"observer"},
        "candidate_private": {"candidate"},
        "plant_private": {"simulation"},
    }
    assert "gateway_private" not in EXPECTED_SECRETS["candidate"]


def test_m4g_secret_paths_and_key_ids_are_explicit() -> None:
    expected_paths = {
        "segmented-gateway": {
            "AEGIS_CANDIDATE_PUBLIC_KEY_FILE": "/run/secrets/candidate_public",
            "AEGIS_PERMIT_PRIVATE_KEY_FILE": "/run/secrets/permit_private",
            "AEGIS_OBSERVER_PUBLIC_KEY_FILE": "/run/secrets/observer_public",
            "AEGIS_PLANT_PUBLIC_KEY_FILE": "/run/secrets/plant_public",
        },
        "observer": {
            "AEGIS_OBSERVER_PRIVATE_KEY_FILE": "/run/secrets/observer_private",
            "AEGIS_PLANT_PUBLIC_KEY_FILE": "/run/secrets/plant_public",
        },
        "candidate": {
            "AEGIS_CANDIDATE_PRIVATE_KEY_FILE": "/run/secrets/candidate_private",
            "AEGIS_PLANT_PUBLIC_KEY_FILE": "/run/secrets/plant_public",
        },
        "ot-adapter": {
            "AEGIS_PERMIT_PUBLIC_KEY_FILE": "/run/secrets/permit_public",
            "AEGIS_OBSERVER_PUBLIC_KEY_FILE": "/run/secrets/observer_public",
            "AEGIS_PLANT_PUBLIC_KEY_FILE": "/run/secrets/plant_public",
        },
        "simulation": {
            "AEGIS_CANDIDATE_PUBLIC_KEY_FILE": "/run/secrets/candidate_public",
            "AEGIS_OBSERVER_PUBLIC_KEY_FILE": "/run/secrets/observer_public",
            "AEGIS_OT_PUBLIC_KEY_FILE": "/run/secrets/ot_public",
            "AEGIS_PLANT_PRIVATE_KEY_FILE": "/run/secrets/plant_private",
        },
    }
    for name, paths in expected_paths.items():
        environment = _service(name)["environment"]
        for variable, path in paths.items():
            assert environment[variable] == path

    assert set(CAPABILITY["secrets"]) == {
        "permit_private",
        "permit_public",
        "observer_private",
        "observer_public",
        "candidate_private",
        "candidate_public",
        "plant_private",
        "plant_public",
    }


def test_m4g_runtime_environment_is_complete_after_overlay_merge() -> None:
    for name, required in RUNTIME_REQUIRED_ENVIRONMENT.items():
        environment = _effective_environment(name)
        assert required <= environment.keys(), (
            f"{name} is missing runtime settings: {sorted(required - environment.keys())}"
        )
        assert all(environment[variable] for variable in required)

    assert _effective_environment("ot-adapter")["AEGIS_OBSERVER_URL"] == (
        "http://observer:8082"
    )
    assert set(_service("ot-adapter")["depends_on"]) == {"observer", "simulation"}


def test_m4g_every_runtime_key_file_is_bound_to_an_assigned_secret() -> None:
    for name, bindings in RUNTIME_KEY_SECRETS.items():
        environment = _effective_environment(name)
        configured_key_files = {
            variable for variable in environment if variable.endswith("_KEY_FILE")
        }
        assert configured_key_files == bindings.keys()
        assert set(bindings.values()) == EXPECTED_SECRETS[name]
        for variable, secret in bindings.items():
            assert environment[variable] == f"/run/secrets/{secret}"


def test_m4g_reuses_the_m4f_volume_for_transport_and_semantic_replay() -> None:
    assert REPLAY["services"]["ot-adapter"]["volumes"] == [
        "transport_replay:/var/lib/aegis-ot"
    ]
    assert _service("ot-adapter")["environment"][
        "AEGIS_SEMANTIC_REPLAY_LEDGER_FILE"
    ] == "/var/lib/aegis-ot/semantic-replay.json"
    assert _service("replay-init")["environment"][
        "AEGIS_SEMANTIC_REPLAY_LEDGER_FILE"
    ] == "/var/lib/aegis-ot/semantic-replay.json"
    assert _service("replay-init")["environment"]["AEGIS_TRANSPORT_AUDIENCE"] == (
        "aegis-ot:m4g:ot-adapter"
    )
    assert _service("ot-adapter")["environment"]["AEGIS_TRANSPORT_AUDIENCE"] == (
        "aegis-ot:m4g:ot-adapter"
    )
    assert "volumes" not in _service("simulation")
    assert "depends_on" not in _service("simulation")
    assert set(REPLAY["volumes"]) == {"transport_replay", "transport_probe"}


def test_m4g_overlay_extends_the_authenticated_replay_stack() -> None:
    assert AUTH["services"]["segmented-gateway"]["environment"][
        "AEGIS_AUTHENTICATED_MODE"
    ] == "true"
    assert AUTH["services"]["ot-adapter"]["environment"][
        "AEGIS_AUTHENTICATED_MODE"
    ] == "true"
    assert REPLAY["services"]["ot-adapter"]["environment"][
        "AEGIS_TRANSPORT_REPLAY_MODE"
    ] == "durable"
    assert _service("agent-probe")["command"] == [
        "python",
        "-m",
        "aegis_ot.m4g_probe",
    ]


def test_m4g_legacy_gateway_and_ot_explicitly_disable_effect_coordination() -> None:
    assert _service("segmented-gateway")["environment"][
        "AEGIS_EFFECT_COORDINATION_MODE"
    ] == "disabled"
    assert _service("ot-adapter")["environment"][
        "AEGIS_EFFECT_COORDINATION_MODE"
    ] == "disabled"
