#!/usr/bin/env python3
"""Validate the closed M4j host-role deployment contract without side effects."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn, cast

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEPLOYMENT = ROOT / "infra" / "m4j" / "deployment.yml"
DEFAULT_TOPOLOGY = ROOT / "infra" / "m4j" / "topology.yml"

ROLES = ("management", "trust", "agents", "gateway", "ot", "simulation")
NETWORKS = (
    "management",
    "trust_enrollment",
    "agent_lane",
    "control_dmz",
    "simulation_lane",
)
NETWORK_CONTRACT: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "management": ("host_only", "ssh_control_only", ROLES),
    "trust_enrollment": (
        "virtualbox_internal",
        "workload_identity_enrollment",
        ("trust", "agents", "gateway", "ot", "simulation"),
    ),
    "agent_lane": ("virtualbox_internal", "agent_to_gateway_only", ("agents", "gateway")),
    "control_dmz": (
        "virtualbox_internal",
        "trusted_control_services",
        ("trust", "gateway", "ot"),
    ),
    "simulation_lane": (
        "virtualbox_internal",
        "plant_access_only",
        ("trust", "ot", "simulation"),
    ),
}
PRIVATE_IPV4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


class ContractError(ValueError):
    """Raised when either input fails the closed deployment contract."""


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ContractError("YAML mapping keys must be scalar and hashable") from exc
        if duplicate:
            raise ContractError(f"duplicate YAML mapping key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _fail(message: str) -> NoReturn:
    raise ContractError(message)


def _exact_mapping(
    value: object,
    *,
    label: str,
    fields: Sequence[str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} must be a string-keyed mapping")
    result = cast(dict[str, Any], value)
    actual = set(result)
    expected = set(fields)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        _fail(f"{label} fields differ: missing={missing}, unknown={unknown}")
    return result


def _exact_named_mapping(
    value: object,
    *,
    label: str,
    names: Sequence[str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} must be a string-keyed mapping")
    result = cast(dict[str, Any], value)
    if set(result) != set(names):
        _fail(
            f"{label} names differ: missing={sorted(set(names) - set(result))}, "
            f"unknown={sorted(set(result) - set(names))}"
        )
    if list(result) != list(names):
        _fail(f"{label} order must be {list(names)}")
    return result


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _integer(value: object, *, label: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer >= {minimum}")
    return value


def _boolean(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} must be a boolean")
    return value


def _string_list(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        _fail(f"{label} must be a list of non-empty strings")
    return cast(list[str], value)


def _load_yaml(path: Path, *, label: str) -> dict[str, Any]:
    try:
        if path.stat().st_size > 1_048_576:
            _fail(f"{label} exceeds the 1 MiB input limit")
        loader = _UniqueKeyLoader(path.read_text(encoding="utf-8"))
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ContractError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} root must be a string-keyed mapping")
    return cast(dict[str, Any], value)


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContractError(f"contract cannot be canonically encoded: {exc}") from exc


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_topology(topology: dict[str, Any]) -> None:
    root = _exact_mapping(
        topology,
        label="topology",
        fields=(
            "schema_version",
            "deployment_status",
            "claim_boundary",
            "box",
            "bootstrap_nat",
            "capacity",
            "addressing",
            "networks",
            "nodes",
        ),
    )
    if root["schema_version"] != "aegis-ot-m4j-topology-v1":
        _fail("topology.schema_version is unsupported")
    if root["deployment_status"] != "configuration_only":
        _fail("topology.deployment_status must be configuration_only")
    if root["claim_boundary"] != "no_live_deployment_or_multi_host_isolation_evidence":
        _fail("topology.claim_boundary is unsupported")

    box = _exact_mapping(
        root["box"],
        label="topology.box",
        fields=("name", "version", "provider", "check_update"),
    )
    if box != {
        "name": "generic/ubuntu2204",
        "version": "4.3.12",
        "provider": "virtualbox",
        "check_update": False,
    }:
        _fail("topology.box must retain the pinned M4j VirtualBox image")

    bootstrap_nat = _exact_mapping(
        root["bootstrap_nat"],
        label="topology.bootstrap_nat",
        fields=("enabled", "purpose", "application_bindings_allowed", "guest_ssh_port"),
    )
    if (
        _boolean(bootstrap_nat["enabled"], label="topology.bootstrap_nat.enabled") is not True
        or bootstrap_nat["purpose"] != "vagrant_bootstrap_only"
        or _boolean(
            bootstrap_nat["application_bindings_allowed"],
            label="topology.bootstrap_nat.application_bindings_allowed",
        )
        is not False
        or _integer(
            bootstrap_nat["guest_ssh_port"],
            label="topology.bootstrap_nat.guest_ssh_port",
        )
        != 22
    ):
        _fail("topology.bootstrap_nat must remain bootstrap-only with no application bindings")

    capacity = _exact_mapping(
        root["capacity"],
        label="topology.capacity",
        fields=("max_total_cpus", "max_total_memory_mb", "max_node_cpus", "max_node_memory_mb"),
    )
    max_total_cpus = _integer(capacity["max_total_cpus"], label="capacity.max_total_cpus")
    max_total_memory = _integer(
        capacity["max_total_memory_mb"], label="capacity.max_total_memory_mb"
    )
    max_node_cpus = _integer(capacity["max_node_cpus"], label="capacity.max_node_cpus")
    max_node_memory = _integer(capacity["max_node_memory_mb"], label="capacity.max_node_memory_mb")

    addressing = _exact_mapping(
        root["addressing"],
        label="topology.addressing",
        fields=("ipv4_prefix_length", "first_node_host_offset"),
    )
    prefix_length = _integer(
        addressing["ipv4_prefix_length"], label="addressing.ipv4_prefix_length"
    )
    first_offset = _integer(
        addressing["first_node_host_offset"], label="addressing.first_node_host_offset"
    )
    if prefix_length != 24:
        _fail("topology.addressing.ipv4_prefix_length must be 24")

    raw_networks = _exact_named_mapping(root["networks"], label="topology.networks", names=NETWORKS)
    parsed_networks: dict[str, ipaddress.IPv4Network] = {}
    for name in NETWORKS:
        network = _exact_mapping(
            raw_networks[name],
            label=f"topology.networks.{name}",
            fields=("cidr", "kind", "purpose", "gateway", "internal_name", "members"),
        )
        kind, purpose, members = NETWORK_CONTRACT[name]
        if network["kind"] != kind or network["purpose"] != purpose:
            _fail(f"topology.networks.{name} kind or purpose differs from the closed contract")
        if _string_list(network["members"], label=f"topology.networks.{name}.members") != list(
            members
        ):
            _fail(f"topology.networks.{name}.members differs from the closed contract")
        try:
            parsed = ipaddress.ip_network(
                _string(network["cidr"], label=f"topology.networks.{name}.cidr"), strict=True
            )
        except ValueError as exc:
            raise ContractError(f"topology.networks.{name}.cidr is invalid: {exc}") from exc
        if not isinstance(parsed, ipaddress.IPv4Network) or parsed.prefixlen != prefix_length:
            _fail(f"topology.networks.{name}.cidr must be IPv4 /{prefix_length}")
        ipv4_network = parsed
        if not any(ipv4_network.subnet_of(private) for private in PRIVATE_IPV4):
            _fail(f"topology.networks.{name}.cidr must be RFC1918")
        parsed_networks[name] = ipv4_network
        if name == "management":
            if network["gateway"] != str(ipv4_network.network_address + 1):
                _fail("topology management gateway must be host offset 1")
            if network["internal_name"] is not None:
                _fail("topology management internal_name must be null")
        else:
            if network["gateway"] is not None:
                _fail(f"topology.networks.{name}.gateway must be null")
            expected_internal = f"aegis-m4j-{name.replace('_', '-')}"
            if network["internal_name"] != expected_internal:
                _fail(f"topology.networks.{name}.internal_name must be {expected_internal}")

    for index, left_name in enumerate(NETWORKS):
        for right_name in NETWORKS[index + 1 :]:
            if parsed_networks[left_name].overlaps(parsed_networks[right_name]):
                _fail(f"topology networks overlap: {left_name}, {right_name}")

    raw_nodes = _exact_named_mapping(root["nodes"], label="topology.nodes", names=ROLES)
    configured_addresses: set[ipaddress.IPv4Address] = set()
    total_cpus = 0
    total_memory = 0
    for role_index, role in enumerate(ROLES):
        node = _exact_mapping(
            raw_nodes[role],
            label=f"topology.nodes.{role}",
            fields=("hostname", "cpus", "memory_mb", "interfaces"),
        )
        if node["hostname"] != f"aegis-{role}":
            _fail(f"topology.nodes.{role}.hostname is not canonical")
        cpus = _integer(node["cpus"], label=f"topology.nodes.{role}.cpus")
        memory = _integer(node["memory_mb"], label=f"topology.nodes.{role}.memory_mb")
        if cpus > max_node_cpus or memory > max_node_memory:
            _fail(f"topology.nodes.{role} exceeds per-node capacity")
        total_cpus += cpus
        total_memory += memory
        expected_interfaces = tuple(
            network for network in NETWORKS if role in NETWORK_CONTRACT[network][2]
        )
        interfaces = _exact_named_mapping(
            node["interfaces"],
            label=f"topology.nodes.{role}.interfaces",
            names=expected_interfaces,
        )
        for network_name in expected_interfaces:
            address_text = _string(
                interfaces[network_name],
                label=f"topology.nodes.{role}.interfaces.{network_name}",
            )
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError as exc:
                raise ContractError(
                    f"topology.nodes.{role}.interfaces.{network_name} is invalid: {exc}"
                ) from exc
            expected_address = (
                parsed_networks[network_name].network_address + first_offset + role_index
            )
            if not isinstance(address, ipaddress.IPv4Address):
                _fail(f"topology.nodes.{role}.interfaces.{network_name} must be IPv4")
            if address != expected_address:
                _fail(f"topology.nodes.{role}.interfaces.{network_name} must be {expected_address}")
            if address in configured_addresses:
                _fail(f"topology address is duplicated: {address}")
            configured_addresses.add(address)
    if total_cpus > max_total_cpus or total_memory > max_total_memory:
        _fail("topology nodes exceed aggregate capacity")


def _role_addresses(topology: Mapping[str, Any], role: str) -> Mapping[str, str]:
    nodes = cast(Mapping[str, Any], topology["nodes"])
    node = cast(Mapping[str, Any], nodes[role])
    return cast(Mapping[str, str], node["interfaces"])


def _listener(
    role: str,
    service: str,
    scope: str,
    network: str,
    bind_address: str,
    transport: str,
    port: int | None,
) -> dict[str, Any]:
    return {
        "role": role,
        "service": service,
        "scope": scope,
        "network": network,
        "bind_address": bind_address,
        "transport": transport,
        "port": port,
    }


def _edge(
    edge_id: str,
    source_role: str,
    source_service: str,
    destination_listener: str,
    network: str,
    protocol: str,
    authentication: str,
) -> dict[str, str]:
    return {
        "id": edge_id,
        "source_role": source_role,
        "source_service": source_service,
        "destination_listener": destination_listener,
        "network": network,
        "protocol": protocol,
        "authentication": authentication,
    }


def _expected_deployment(topology: dict[str, Any]) -> dict[str, Any]:
    management = _role_addresses(topology, "management")
    trust = _role_addresses(topology, "trust")
    agents = _role_addresses(topology, "agents")
    gateway = _role_addresses(topology, "gateway")
    ot = _role_addresses(topology, "ot")
    simulation = _role_addresses(topology, "simulation")
    workloads = {
        "management": ["orchestration", "evidence-retention"],
        "trust": ["spire-server", "spire-bootstrap"],
        "agents": ["agent-probe", "spire-agent"],
        "gateway": ["opa", "segmented-gateway", "spire-agent"],
        "ot": ["observer", "candidate", "ot-adapter", "spire-agent"],
        "simulation": ["plant", "spire-agent"],
    }
    roles = {
        role: {
            "hostname": cast(Mapping[str, Any], topology["nodes"])[role]["hostname"],
            "workloads": workloads[role],
            "infrastructure_services": ["sshd"],
        }
        for role in ROLES
    }
    listeners = {
        "management-sshd": _listener(
            "management",
            "sshd",
            "infrastructure",
            "management",
            management["management"],
            "tcp",
            22,
        ),
        "trust-sshd": _listener(
            "trust", "sshd", "infrastructure", "management", trust["management"], "tcp", 22
        ),
        "agents-sshd": _listener(
            "agents", "sshd", "infrastructure", "management", agents["management"], "tcp", 22
        ),
        "gateway-sshd": _listener(
            "gateway", "sshd", "infrastructure", "management", gateway["management"], "tcp", 22
        ),
        "ot-sshd": _listener(
            "ot", "sshd", "infrastructure", "management", ot["management"], "tcp", 22
        ),
        "simulation-sshd": _listener(
            "simulation",
            "sshd",
            "infrastructure",
            "management",
            simulation["management"],
            "tcp",
            22,
        ),
        "spire-server-enrollment": _listener(
            "trust",
            "spire-server",
            "identity",
            "trust_enrollment",
            trust["trust_enrollment"],
            "tcp",
            8081,
        ),
        "spire-server-admin": _listener(
            "trust",
            "spire-server",
            "identity",
            "local",
            "/run/spire/server/private/api.sock",
            "unix",
            None,
        ),
        "agents-spire-workload-api": _listener(
            "agents",
            "spire-agent",
            "identity",
            "local",
            "/run/spire/agent/public/api.sock",
            "unix",
            None,
        ),
        "gateway-spire-workload-api": _listener(
            "gateway",
            "spire-agent",
            "identity",
            "local",
            "/run/spire/agent/public/api.sock",
            "unix",
            None,
        ),
        "ot-spire-workload-api": _listener(
            "ot",
            "spire-agent",
            "identity",
            "local",
            "/run/spire/agent/public/api.sock",
            "unix",
            None,
        ),
        "simulation-spire-workload-api": _listener(
            "simulation",
            "spire-agent",
            "identity",
            "local",
            "/run/spire/agent/public/api.sock",
            "unix",
            None,
        ),
        "segmented-gateway-api": _listener(
            "gateway",
            "segmented-gateway",
            "application",
            "agent_lane",
            gateway["agent_lane"],
            "tcp",
            8081,
        ),
        "opa-api": _listener("gateway", "opa", "application", "local", "127.0.0.1", "tcp", 8181),
        "observer-api": _listener(
            "ot", "observer", "application", "control_dmz", ot["control_dmz"], "tcp", 8082
        ),
        "candidate-api": _listener(
            "ot", "candidate", "application", "control_dmz", ot["control_dmz"], "tcp", 8085
        ),
        "ot-adapter-api": _listener(
            "ot", "ot-adapter", "application", "control_dmz", ot["control_dmz"], "tcp", 8083
        ),
        "plant-api": _listener(
            "simulation",
            "plant",
            "application",
            "simulation_lane",
            simulation["simulation_lane"],
            "tcp",
            8084,
        ),
    }
    edges = [
        _edge(
            "management-to-trust-ssh",
            "management",
            "orchestration",
            "trust-sshd",
            "management",
            "ssh",
            "ssh_public_key",
        ),
        _edge(
            "management-to-agents-ssh",
            "management",
            "orchestration",
            "agents-sshd",
            "management",
            "ssh",
            "ssh_public_key",
        ),
        _edge(
            "management-to-gateway-ssh",
            "management",
            "orchestration",
            "gateway-sshd",
            "management",
            "ssh",
            "ssh_public_key",
        ),
        _edge(
            "management-to-ot-ssh",
            "management",
            "orchestration",
            "ot-sshd",
            "management",
            "ssh",
            "ssh_public_key",
        ),
        _edge(
            "management-to-simulation-ssh",
            "management",
            "orchestration",
            "simulation-sshd",
            "management",
            "ssh",
            "ssh_public_key",
        ),
        _edge(
            "spire-bootstrap-to-server-admin",
            "trust",
            "spire-bootstrap",
            "spire-server-admin",
            "local",
            "spire_admin_api",
            "local_unix_permissions",
        ),
        _edge(
            "agents-spire-agent-to-server",
            "agents",
            "spire-agent",
            "spire-server-enrollment",
            "trust_enrollment",
            "spire_node_api",
            "join_token_bootstrap_then_mtls",
        ),
        _edge(
            "gateway-spire-agent-to-server",
            "gateway",
            "spire-agent",
            "spire-server-enrollment",
            "trust_enrollment",
            "spire_node_api",
            "join_token_bootstrap_then_mtls",
        ),
        _edge(
            "ot-spire-agent-to-server",
            "ot",
            "spire-agent",
            "spire-server-enrollment",
            "trust_enrollment",
            "spire_node_api",
            "join_token_bootstrap_then_mtls",
        ),
        _edge(
            "simulation-spire-agent-to-server",
            "simulation",
            "spire-agent",
            "spire-server-enrollment",
            "trust_enrollment",
            "spire_node_api",
            "join_token_bootstrap_then_mtls",
        ),
        _edge(
            "agent-probe-to-local-spire-agent",
            "agents",
            "agent-probe",
            "agents-spire-workload-api",
            "local",
            "spire_workload_api",
            "unix_peer_credentials",
        ),
        _edge(
            "segmented-gateway-to-local-spire-agent",
            "gateway",
            "segmented-gateway",
            "gateway-spire-workload-api",
            "local",
            "spire_workload_api",
            "unix_peer_credentials",
        ),
        _edge(
            "observer-to-local-spire-agent",
            "ot",
            "observer",
            "ot-spire-workload-api",
            "local",
            "spire_workload_api",
            "unix_peer_credentials",
        ),
        _edge(
            "candidate-to-local-spire-agent",
            "ot",
            "candidate",
            "ot-spire-workload-api",
            "local",
            "spire_workload_api",
            "unix_peer_credentials",
        ),
        _edge(
            "ot-adapter-to-local-spire-agent",
            "ot",
            "ot-adapter",
            "ot-spire-workload-api",
            "local",
            "spire_workload_api",
            "unix_peer_credentials",
        ),
        _edge(
            "plant-to-local-spire-agent",
            "simulation",
            "plant",
            "simulation-spire-workload-api",
            "local",
            "spire_workload_api",
            "unix_peer_credentials",
        ),
        _edge(
            "agent-probe-to-segmented-gateway",
            "agents",
            "agent-probe",
            "segmented-gateway-api",
            "agent_lane",
            "http",
            "signed_workload_capability",
        ),
        _edge(
            "segmented-gateway-to-opa",
            "gateway",
            "segmented-gateway",
            "opa-api",
            "local",
            "http",
            "loopback_only",
        ),
        _edge(
            "segmented-gateway-to-observer",
            "gateway",
            "segmented-gateway",
            "observer-api",
            "control_dmz",
            "https",
            "spiffe_mtls",
        ),
        _edge(
            "segmented-gateway-to-candidate",
            "gateway",
            "segmented-gateway",
            "candidate-api",
            "control_dmz",
            "https",
            "spiffe_mtls",
        ),
        _edge(
            "segmented-gateway-to-ot-adapter",
            "gateway",
            "segmented-gateway",
            "ot-adapter-api",
            "control_dmz",
            "https",
            "spiffe_mtls",
        ),
        _edge(
            "ot-adapter-to-observer",
            "ot",
            "ot-adapter",
            "observer-api",
            "control_dmz",
            "https",
            "spiffe_mtls",
        ),
        _edge(
            "observer-to-plant",
            "ot",
            "observer",
            "plant-api",
            "simulation_lane",
            "https",
            "spiffe_mtls",
        ),
        _edge(
            "candidate-to-plant",
            "ot",
            "candidate",
            "plant-api",
            "simulation_lane",
            "https",
            "spiffe_mtls",
        ),
        _edge(
            "ot-adapter-to-plant",
            "ot",
            "ot-adapter",
            "plant-api",
            "simulation_lane",
            "https",
            "spiffe_mtls",
        ),
    ]
    return {
        "schema_version": "aegis-ot-m4j-deployment-v1",
        "deployment_status": "configuration_only",
        "claim_boundary": "no_live_deployment_or_multi_host_isolation_evidence",
        "topology_binding": {
            "path": "infra/m4j/topology.yml",
            "schema_version": "aegis-ot-m4j-topology-v1",
            "canonical_sha256": _canonical_sha256(topology),
        },
        "policy": {
            "default_peer_policy": "deny",
            "management_purpose": "orchestration_and_evidence_only",
            "management_application_listeners_allowed": False,
            "bootstrap_nat_purpose": "vagrant_bootstrap_only",
            "bootstrap_nat_application_bindings_allowed": False,
            "agent_control_ingress_role": "gateway",
            "direct_agents_to_ot_allowed": False,
            "direct_agents_to_simulation_allowed": False,
            "spire_enrollment_network": "trust_enrollment",
            "spire_workload_api_socket": "/run/spire/agent/public/api.sock",
        },
        "roles": roles,
        "listeners": listeners,
        "external_control_sources": {
            "vagrant-host": {
                "source_type": "external_host",
                "source_address": cast(Mapping[str, Any], topology["networks"])["management"][
                    "gateway"
                ],
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
        },
        "peer_edges": edges,
        "unresolved_gates": [
            {
                "gate_id": "multi_host_spire_bootstrap",
                "status": "unresolved",
                "blocks": "live_multi_host_deployment_evidence",
                "current_limitation": (
                    "current_single_host_bootstrap_uses_one_shared_agent_identity_and_"
                    "shared_bootstrap_material"
                ),
                "required_resolution": (
                    "issue_distinct_node_attestation_identity_and_non_shared_bootstrap_"
                    "material_per_host_then_bind_and_validate_each_workload_registration_parent"
                ),
            }
        ],
    }


def _first_difference(actual: object, expected: object, *, path: str = "deployment") -> str | None:
    if type(actual) is not type(expected):
        return f"{path} has type {type(actual).__name__}; expected {type(expected).__name__}"
    if isinstance(expected, dict):
        actual_mapping = cast(dict[object, object], actual)
        expected_mapping = cast(dict[object, object], expected)
        actual_keys = set(actual_mapping)
        expected_keys = set(expected_mapping)
        if actual_keys != expected_keys:
            return (
                f"{path} fields differ: "
                f"missing={sorted(str(key) for key in expected_keys - actual_keys)}, "
                f"unknown={sorted(str(key) for key in actual_keys - expected_keys)}"
            )
        for key in expected_mapping:
            difference = _first_difference(
                actual_mapping[key], expected_mapping[key], path=f"{path}.{key}"
            )
            if difference is not None:
                return difference
        return None
    if isinstance(expected, list):
        actual_list = cast(list[object], actual)
        expected_list = cast(list[object], expected)
        if len(actual_list) != len(expected_list):
            return f"{path} has {len(actual_list)} items; expected {len(expected_list)}"
        for index, expected_item in enumerate(expected_list):
            difference = _first_difference(
                actual_list[index], expected_item, path=f"{path}[{index}]"
            )
            if difference is not None:
                return difference
        return None
    if actual != expected:
        return f"{path} is {actual!r}; expected {expected!r}"
    return None


def _validate_semantics(deployment: dict[str, Any], topology: dict[str, Any]) -> None:
    roles = cast(dict[str, dict[str, Any]], deployment["roles"])
    listeners = cast(dict[str, dict[str, Any]], deployment["listeners"])
    external_sources = cast(dict[str, dict[str, Any]], deployment["external_control_sources"])
    edges = cast(list[dict[str, str]], deployment["peer_edges"])
    topology_networks = cast(dict[str, dict[str, Any]], topology["networks"])
    topology_nodes = cast(dict[str, dict[str, Any]], topology["nodes"])

    endpoints: set[tuple[str, str, str, int | None]] = set()
    for listener_id, listener in listeners.items():
        role = cast(str, listener["role"])
        service = cast(str, listener["service"])
        scope = cast(str, listener["scope"])
        network = cast(str, listener["network"])
        address = cast(str, listener["bind_address"])
        port = cast(int | None, listener["port"])
        placed = set(cast(list[str], roles[role]["workloads"])) | set(
            cast(list[str], roles[role]["infrastructure_services"])
        )
        if service not in placed:
            _fail(f"listener {listener_id} service is not placed on role {role}")
        if role == "management" and scope in {"application", "identity"}:
            _fail("management cannot expose application or identity listeners")
        if network == "local":
            if listener["transport"] == "unix":
                if port is not None or not address.startswith("/run/"):
                    _fail(f"listener {listener_id} has an invalid Unix endpoint")
            elif address != "127.0.0.1" or port is None:
                _fail(f"listener {listener_id} must use an exact loopback endpoint")
        else:
            if network not in topology_networks:
                _fail(f"listener {listener_id} uses an unknown topology network")
            interfaces = cast(dict[str, str], topology_nodes[role]["interfaces"])
            if network not in interfaces or address != interfaces[network]:
                _fail(f"listener {listener_id} is not bound to its topology interface")
            if port is None:
                _fail(f"listener {listener_id} must name an exact TCP port")
        endpoint = (role, network, address, port)
        if endpoint in endpoints:
            _fail(f"listener {listener_id} duplicates an endpoint")
        endpoints.add(endpoint)

    external = external_sources["vagrant-host"]
    management_network = topology_networks["management"]
    if external["source_address"] != management_network["gateway"]:
        _fail("external Vagrant control source must equal the management gateway")
    try:
        external_address = ipaddress.ip_address(cast(str, external["source_address"]))
        management_subnet = ipaddress.ip_network(cast(str, management_network["cidr"]), strict=True)
    except ValueError as exc:  # pragma: no cover - topology validation precedes this check
        raise ContractError(f"external Vagrant control source is invalid: {exc}") from exc
    if external_address not in management_subnet:
        _fail("external Vagrant control source must be on the management network")
    external_destinations = cast(list[str], external["destination_listeners"])
    if len(external_destinations) != len(ROLES):
        _fail("external Vagrant control must target exactly one SSH listener per role")
    for role, destination_id in zip(ROLES, external_destinations, strict=True):
        destination = listeners[destination_id]
        if destination != _listener(
            role,
            "sshd",
            "infrastructure",
            "management",
            cast(dict[str, str], topology_nodes[role]["interfaces"])["management"],
            "tcp",
            22,
        ):
            _fail(f"external Vagrant control destination is not the exact {role} SSH listener")

    edge_ids: set[str] = set()
    for edge in edges:
        edge_id = edge["id"]
        if edge_id in edge_ids:
            _fail(f"peer edge id is duplicated: {edge_id}")
        edge_ids.add(edge_id)
        source_role = edge["source_role"]
        source_service = edge["source_service"]
        destination = listeners[edge["destination_listener"]]
        network = edge["network"]
        if source_service not in set(cast(list[str], roles[source_role]["workloads"])) | set(
            cast(list[str], roles[source_role]["infrastructure_services"])
        ):
            _fail(f"peer edge {edge_id} source service is not placed on its role")
        if network != destination["network"]:
            _fail(f"peer edge {edge_id} does not match its destination listener network")
        destination_role = cast(str, destination["role"])
        if network == "local":
            if source_role != destination_role:
                _fail(f"peer edge {edge_id} crosses roles over a local endpoint")
        else:
            members = cast(list[str], topology_networks[network]["members"])
            if source_role not in members or destination_role not in members:
                _fail(f"peer edge {edge_id} crosses roles outside topology membership")

    if any(
        edge["source_role"] == "management" and edge["destination_listener"] == "management-sshd"
        for edge in edges
    ):
        _fail("external host control must not be modeled as a management self-edge")

    application_edges = [
        edge for edge in edges if listeners[edge["destination_listener"]]["scope"] == "application"
    ]
    agent_application_edges = [
        edge for edge in application_edges if edge["source_role"] == "agents"
    ]
    if [edge["destination_listener"] for edge in agent_application_edges] != [
        "segmented-gateway-api"
    ]:
        _fail("gateway must be the sole agents-to-control application path")
    if any(
        listeners[edge["destination_listener"]]["role"] in {"ot", "simulation"}
        for edge in agent_application_edges
    ):
        _fail("direct agents-to-OT or agents-to-simulation paths are forbidden")
    if any(
        listener["scope"] != "infrastructure"
        for listener in listeners.values()
        if listener["network"] == "management"
    ):
        _fail("management carries only infrastructure listeners")
    enrollment_edges = [edge for edge in edges if edge["protocol"] == "spire_node_api"]
    if any(edge["network"] != "trust_enrollment" for edge in enrollment_edges):
        _fail("SPIRE enrollment must use trust_enrollment")


def validate(deployment_path: Path, topology_path: Path) -> dict[str, str]:
    """Validate both files and return their canonical SHA-256 bindings."""

    topology = _load_yaml(topology_path, label="topology")
    _validate_topology(topology)
    deployment = _load_yaml(deployment_path, label="deployment")
    expected = _expected_deployment(topology)
    difference = _first_difference(deployment, expected)
    if difference is not None:
        _fail(difference)
    _validate_semantics(deployment, topology)
    return {
        "canonical_sha256": _canonical_sha256(deployment),
        "topology_canonical_sha256": _canonical_sha256(topology),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="validate and print a concise result")
    mode.add_argument("--json", action="store_true", help="validate and print canonical JSON")
    parser.add_argument("--deployment", type=Path, default=DEFAULT_DEPLOYMENT)
    parser.add_argument("--topology", type=Path, default=DEFAULT_TOPOLOGY)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = validate(arguments.deployment, arguments.topology)
    except ContractError as exc:
        if arguments.json:
            print(
                json.dumps(
                    {"error": str(exc), "valid": False}, separators=(",", ":"), sort_keys=True
                )
            )
        else:
            print(f"M4j deployment contract invalid: {exc}", file=sys.stderr)
        return 1

    if arguments.json:
        print(
            json.dumps(
                {
                    **result,
                    "claim_boundary": "no_live_deployment_or_multi_host_isolation_evidence",
                    "deployment_status": "configuration_only",
                    "schema_version": "aegis-ot-m4j-deployment-v1",
                    "unresolved_gates": ["multi_host_spire_bootstrap"],
                    "valid": True,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    else:
        print(
            "M4j deployment contract valid "
            f"canonical_sha256={result['canonical_sha256']} "
            f"topology_canonical_sha256={result['topology_canonical_sha256']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
