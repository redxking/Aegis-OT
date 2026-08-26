from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT_PATH = ROOT / "infra" / "m4j" / "deployment.yml"
TOPOLOGY_PATH = ROOT / "infra" / "m4j" / "topology.yml"
VALIDATOR = ROOT / "scripts" / "validate_m4j_deployment.py"


def _load(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _canonical_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _run_validator(
    *,
    mode: str,
    deployment: Path = DEPLOYMENT_PATH,
    topology: Path = TOPOLOGY_PATH,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed local validator path
        [
            sys.executable,
            str(VALIDATOR),
            mode,
            "--deployment",
            str(deployment),
            "--topology",
            str(topology),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def _write_yaml(path: Path, value: object) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def test_committed_contract_passes_check_with_canonical_bindings() -> None:
    completed = _run_validator(mode="--check")

    assert completed.returncode == 0, completed.stderr
    match = re.fullmatch(
        r"M4j deployment contract valid canonical_sha256=([0-9a-f]{64}) "
        r"topology_canonical_sha256=([0-9a-f]{64})\n",
        completed.stdout,
    )
    assert match is not None
    assert match.group(1) == _canonical_sha256(_load(DEPLOYMENT_PATH))
    assert match.group(2) == _canonical_sha256(_load(TOPOLOGY_PATH))


def test_json_mode_is_deterministic_and_retains_the_claim_boundary() -> None:
    first = _run_validator(mode="--json")
    second = _run_validator(mode="--json")

    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout
    result = json.loads(first.stdout)
    assert result == {
        "canonical_sha256": _canonical_sha256(_load(DEPLOYMENT_PATH)),
        "claim_boundary": "no_live_deployment_or_multi_host_isolation_evidence",
        "deployment_status": "configuration_only",
        "schema_version": "aegis-ot-m4j-deployment-v2",
        "topology_canonical_sha256": _canonical_sha256(_load(TOPOLOGY_PATH)),
        "implementation_gates": {
            "multi_host_spire_bootstrap": "implemented_live_validation_pending"
        },
        "valid": True,
    }


def test_role_placement_is_closed_and_host_specific() -> None:
    deployment = _load(DEPLOYMENT_PATH)

    assert deployment["roles"] == {
        "management": {
            "hostname": "aegis-management",
            "workloads": ["orchestration", "evidence-retention"],
            "infrastructure_services": ["sshd"],
        },
        "trust": {
            "hostname": "aegis-trust",
            "workloads": [
                "spire-server",
                "spire-bootstrap",
                "spire-agent",
                "policy-relay",
                "opa",
                "observer",
                "candidate",
            ],
            "infrastructure_services": ["sshd"],
        },
        "agents": {
            "hostname": "aegis-agents",
            "workloads": ["agent-probe", "spire-agent"],
            "infrastructure_services": ["sshd"],
        },
        "gateway": {
            "hostname": "aegis-gateway",
            "workloads": ["segmented-gateway", "spire-agent"],
            "infrastructure_services": ["sshd"],
        },
        "ot": {
            "hostname": "aegis-ot",
            "workloads": ["ot-adapter", "spire-agent"],
            "infrastructure_services": ["sshd"],
        },
        "simulation": {
            "hostname": "aegis-simulation",
            "workloads": ["plant", "spire-agent"],
            "infrastructure_services": ["sshd"],
        },
    }


def test_listeners_bind_only_to_their_exact_topology_or_local_endpoints() -> None:
    deployment = _load(DEPLOYMENT_PATH)
    topology = _load(TOPOLOGY_PATH)
    listeners = deployment["listeners"]

    for listener in listeners.values():
        role = listener["role"]
        network = listener["network"]
        if network == "local":
            assert listener["bind_address"] == "127.0.0.1" or listener["bind_address"].startswith(
                "/run/"
            )
        else:
            assert listener["bind_address"] == topology["nodes"][role]["interfaces"][network]
            assert isinstance(listener["port"], int)

    assert not [
        listener
        for listener in listeners.values()
        if listener["role"] == "management" and listener["scope"] in {"application", "identity"}
    ]
    assert listeners["management-sshd"] == {
        "role": "management",
        "service": "sshd",
        "scope": "infrastructure",
        "network": "management",
        "bind_address": "192.168.56.10",
        "transport": "tcp",
        "port": 22,
    }
    assert {
        key: (value["bind_address"], value["port"])
        for key, value in listeners.items()
        if value["scope"] == "application"
    } == {
        "segmented-gateway-api": ("192.168.58.13", 8081),
        "policy-relay-api": ("192.168.59.11", 8181),
        "opa-loopback": ("127.0.0.1", 8182),
        "observer-api": ("192.168.59.11", 8082),
        "candidate-api": ("192.168.59.11", 8085),
        "ot-adapter-api": ("192.168.59.14", 8083),
        "plant-api": ("192.168.60.15", 8084),
    }


def test_peer_edges_deny_agent_bypass_and_bind_spire_enrollment() -> None:
    deployment = _load(DEPLOYMENT_PATH)
    listeners = deployment["listeners"]
    edges = deployment["peer_edges"]
    agent_application_edges = [
        edge
        for edge in edges
        if edge["source_role"] == "agents"
        and listeners[edge["destination_listener"]]["scope"] == "application"
    ]

    assert deployment["policy"]["default_peer_policy"] == "deny"
    assert [edge["destination_listener"] for edge in agent_application_edges] == [
        "segmented-gateway-api"
    ]
    assert not [
        edge
        for edge in agent_application_edges
        if listeners[edge["destination_listener"]]["role"] in {"ot", "simulation"}
    ]
    enrollment_edges = [edge for edge in edges if edge["protocol"] == "spire_node_api"]
    assert {edge["source_role"] for edge in enrollment_edges} == {
        "trust",
        "agents",
        "gateway",
        "ot",
        "simulation",
    }
    assert all(edge["network"] == "trust_enrollment" for edge in enrollment_edges)
    assert all(
        edge["destination_listener"] == "spire-server-enrollment" for edge in enrollment_edges
    )
    assert deployment["roles"]["trust"]["workloads"][-4:] == [
        "policy-relay",
        "opa",
        "observer",
        "candidate",
    ]
    assert deployment["roles"]["gateway"]["workloads"] == [
        "segmented-gateway",
        "spire-agent",
    ]
    assert deployment["roles"]["ot"]["workloads"] == ["ot-adapter", "spire-agent"]
    assert next(
        edge for edge in edges if edge["id"] == "segmented-gateway-to-policy-relay"
    ) == {
        "id": "segmented-gateway-to-policy-relay",
        "source_role": "gateway",
        "source_service": "segmented-gateway",
        "destination_listener": "policy-relay-api",
        "network": "control_dmz",
        "protocol": "https",
        "authentication": "spiffe_mtls",
    }
    assert next(edge for edge in edges if edge["id"] == "policy-relay-to-opa") == {
        "id": "policy-relay-to-opa",
        "source_role": "trust",
        "source_service": "policy-relay",
        "destination_listener": "opa-loopback",
        "network": "local",
        "protocol": "http",
        "authentication": "local_loopback",
    }
    assert listeners["opa-loopback"]["bind_address"] == "127.0.0.1"
    assert not [
        edge
        for edge in edges
        if edge["source_service"] == "opa"
        and edge["destination_listener"] == "trust-spire-workload-api"
    ]
    assert not [
        edge
        for edge in edges
        if edge["source_role"] == "management" and edge["destination_listener"] == "management-sshd"
    ]


def test_external_vagrant_control_source_targets_all_six_ssh_listeners() -> None:
    deployment = _load(DEPLOYMENT_PATH)

    assert deployment["external_control_sources"] == {
        "vagrant-host": {
            "source_type": "external_host",
            "source_address": "192.168.56.1",
            "network": "management",
            "protocol": "ssh",
            "authentication": "ssh_public_key",
            "purpose": "vagrant_control_provisioning_and_evidence",
            "destination_listeners": [
                "management-sshd",
                "trust-sshd",
                "agents-sshd",
                "gateway-sshd",
                "ot-sshd",
                "simulation-sshd",
            ],
        }
    }


def test_multi_host_spire_bootstrap_implementation_retains_live_evidence_gate() -> None:
    deployment = _load(DEPLOYMENT_PATH)

    assert deployment["implementation_gates"] == [
        {
            "gate_id": "multi_host_spire_bootstrap",
            "status": "implemented_live_validation_pending",
            "blocks": "live_multi_host_deployment_evidence",
            "implementation_contracts": [
                "infra/m4j/workloads.yml",
                "infra/ansible/workloads.yml",
                "scripts/deploy_m4j_workloads.py",
                "scripts/reconcile_m4j_spire_entries.py",
                "scripts/revoke_m4j_spire_join_token.py",
            ],
            "implemented_controls": [
                "distinct_node_attestation_identity_per_host",
                "one_time_non_shared_join_material_per_host",
                "exact_workload_registration_parent_binding",
                "bounded_managed_registration_pruning_and_readback",
                "join_token_cleanup_and_absence_verification",
            ],
            "live_evidence_status": "not_run",
            "required_validation": (
                "apply_exact_source_bundle_then_run_signed_two_phase_live_workload_"
                "probe_on_all_six_hosts"
            ),
        }
    ]


@pytest.mark.parametrize(
    "case",
    [
        "unknown_root_field",
        "missing_policy_field",
        "wrong_role_placement",
        "management_application_listener",
        "wrong_listener_address",
        "wrong_listener_port",
        "direct_agent_ot_edge",
        "spire_wrong_network",
        "wrong_external_source",
        "missing_external_destination",
        "management_self_edge",
        "missing_implementation_gate",
    ],
)
def test_validator_fails_closed_on_deployment_drift(tmp_path: Path, case: str) -> None:
    deployment = copy.deepcopy(_load(DEPLOYMENT_PATH))
    if case == "unknown_root_field":
        deployment["unexpected"] = True
    elif case == "missing_policy_field":
        deployment["policy"].pop("default_peer_policy")
    elif case == "wrong_role_placement":
        deployment["roles"]["trust"]["workloads"].remove("opa")
        deployment["roles"]["gateway"]["workloads"].insert(0, "opa")
    elif case == "management_application_listener":
        deployment["listeners"]["management-api"] = {
            "role": "management",
            "service": "orchestration",
            "scope": "application",
            "network": "management",
            "bind_address": "192.168.56.10",
            "transport": "tcp",
            "port": 8080,
        }
    elif case == "wrong_listener_address":
        deployment["listeners"]["segmented-gateway-api"]["bind_address"] = "0.0.0.0"  # noqa: S104 - deliberately unsafe negative fixture
    elif case == "wrong_listener_port":
        deployment["listeners"]["plant-api"]["port"] = 8086
    elif case == "direct_agent_ot_edge":
        deployment["peer_edges"].append(
            {
                "id": "agent-probe-to-ot-adapter",
                "source_role": "agents",
                "source_service": "agent-probe",
                "destination_listener": "ot-adapter-api",
                "network": "control_dmz",
                "protocol": "https",
                "authentication": "spiffe_mtls",
            }
        )
    elif case == "spire_wrong_network":
        deployment["peer_edges"][6]["network"] = "management"
    elif case == "wrong_external_source":
        deployment["external_control_sources"]["vagrant-host"]["source_address"] = "192.168.56.2"
    elif case == "missing_external_destination":
        deployment["external_control_sources"]["vagrant-host"]["destination_listeners"].remove(
            "management-sshd"
        )
    elif case == "management_self_edge":
        deployment["peer_edges"].insert(
            0,
            {
                "id": "management-to-management-ssh",
                "source_role": "management",
                "source_service": "orchestration",
                "destination_listener": "management-sshd",
                "network": "management",
                "protocol": "ssh",
                "authentication": "ssh_public_key",
            },
        )
    elif case == "missing_implementation_gate":
        deployment["implementation_gates"] = []
    else:  # pragma: no cover - parameter list is closed above
        raise AssertionError(f"unhandled case: {case}")

    changed = tmp_path / "deployment.yml"
    _write_yaml(changed, deployment)
    completed = _run_validator(mode="--check", deployment=changed)

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr.startswith("M4j deployment contract invalid:")


@pytest.mark.parametrize("case", ["unknown_field", "address_drift", "unsafe_subnet"])
def test_validator_rejects_topology_drift(tmp_path: Path, case: str) -> None:
    topology = copy.deepcopy(_load(TOPOLOGY_PATH))
    if case == "unknown_field":
        topology["networks"]["agent_lane"]["dns"] = "192.168.58.1"
    elif case == "address_drift":
        topology["nodes"]["gateway"]["interfaces"]["agent_lane"] = "192.168.58.99"
    elif case == "unsafe_subnet":
        topology["networks"]["agent_lane"]["cidr"] = "203.0.113.0/24"
    else:  # pragma: no cover - parameter list is closed above
        raise AssertionError(f"unhandled case: {case}")

    changed = tmp_path / "topology.yml"
    _write_yaml(changed, topology)
    completed = _run_validator(mode="--json", topology=changed)

    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    assert result["valid"] is False
    assert isinstance(result["error"], str) and result["error"]


@pytest.mark.parametrize("document", ["deployment", "topology"])
def test_validator_rejects_duplicate_yaml_keys(tmp_path: Path, document: str) -> None:
    duplicate = tmp_path / f"{document}.yml"
    duplicate.write_text("schema_version: first\nschema_version: second\n", encoding="utf-8")

    completed = _run_validator(
        mode="--check",
        deployment=duplicate if document == "deployment" else DEPLOYMENT_PATH,
        topology=duplicate if document == "topology" else TOPOLOGY_PATH,
    )

    assert completed.returncode == 1
    assert "duplicate YAML mapping key" in completed.stderr


def test_validator_performs_no_mutation_or_network_or_process_actions() -> None:
    deployment_before = DEPLOYMENT_PATH.read_bytes()
    topology_before = TOPOLOGY_PATH.read_bytes()
    deployment_mtime = DEPLOYMENT_PATH.stat().st_mtime_ns
    topology_mtime = TOPOLOGY_PATH.stat().st_mtime_ns
    source = VALIDATOR.read_text(encoding="utf-8")

    completed = _run_validator(mode="--check")

    assert completed.returncode == 0
    assert DEPLOYMENT_PATH.read_bytes() == deployment_before
    assert TOPOLOGY_PATH.read_bytes() == topology_before
    assert DEPLOYMENT_PATH.stat().st_mtime_ns == deployment_mtime
    assert TOPOLOGY_PATH.stat().st_mtime_ns == topology_mtime
    assert "import socket" not in source
    assert "import subprocess" not in source
    assert "import urllib" not in source
    assert ".write_text(" not in source
    assert ".write_bytes(" not in source
