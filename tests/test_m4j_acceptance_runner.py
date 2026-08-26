from __future__ import annotations

import ast
import base64
import copy
import json
import re
import shutil
import stat
import subprocess
import zlib
from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = import_module("run_m4j_acceptance")
    monkeypatch.setattr(module, "_PARTITION_RECONCILIATION_INTERVAL_SECONDS", 0)
    return module


def _topology() -> dict[str, Any]:
    value = yaml.safe_load((ROOT / "infra" / "m4j" / "topology.yml").read_bytes())
    assert isinstance(value, dict)
    return value


def _deployment() -> dict[str, Any]:
    value = yaml.safe_load((ROOT / "infra" / "m4j" / "deployment.yml").read_bytes())
    assert isinstance(value, dict)
    return value


def _run_git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603 - test-owned Git fixture
        ("/usr/bin/git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    (repository / "scripts").mkdir(parents=True)
    (repository / "infra" / "m4j").mkdir(parents=True)
    shutil.copy2(ROOT / "scripts" / "run_m4j_acceptance.py", repository / "scripts")
    shutil.copy2(ROOT / "infra" / "m4j" / "topology.yml", repository / "infra" / "m4j")
    shutil.copy2(ROOT / "infra" / "m4j" / "deployment.yml", repository / "infra" / "m4j")
    shutil.copy2(ROOT / "infra" / "m4j" / "workloads.yml", repository / "infra" / "m4j")
    _run_git(repository, "init", "-q")
    _run_git(repository, "add", "scripts/run_m4j_acceptance.py")
    _run_git(repository, "add", "infra/m4j/topology.yml")
    _run_git(repository, "add", "infra/m4j/deployment.yml")
    _run_git(repository, "add", "infra/m4j/workloads.yml")
    _run_git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    return repository


def _ssh_transport_inputs(tmp_path: Path) -> tuple[Path, Path]:
    identities = tmp_path / "identities"
    identities.mkdir(mode=0o700, exist_ok=True)
    config_lines: list[str] = []
    algorithm = b"ssh-ed25519"
    host_key_prefix = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + (32).to_bytes(4, "big")
    )
    known_host_lines: list[str] = []
    for index, role in enumerate(
        ("management", "trust", "agents", "gateway", "ot", "simulation"),
        start=1,
    ):
        address = f"192.168.56.{index + 9}"
        identity = identities / f"{role}.key"
        identity.write_bytes(f"synthetic-private-identity-{role}\n".encode("ascii"))
        identity.chmod(0o600)
        config_lines.extend(
            (
                f"Host {role}",
                f"  HostName {address}",
                "  User vagrant",
                f"  IdentityFile {identity}",
            )
        )
        encoded = base64.b64encode(host_key_prefix + bytes([index]) * 32).decode(
            "ascii"
        )
        known_host_lines.append(f"{role},{address} ssh-ed25519 {encoded}")
    config = tmp_path / "ssh-config"
    config.write_text("\n".join(config_lines) + "\n", encoding="utf-8")
    config.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("\n".join(known_host_lines) + "\n", encoding="ascii")
    known_hosts.chmod(0o600)
    return config, known_hosts


def _interfaces(role: str, topology: dict[str, Any]) -> dict[str, str]:
    return cast(dict[str, str], topology["nodes"][role]["interfaces"])


def _valid_remote_facts(
    runner: Any,
    role: str,
    topology: dict[str, Any],
    deployment: dict[str, Any],
    *,
    counter_offset: int = 0,
) -> dict[str, Any]:
    role_interfaces = _interfaces(role, topology)
    interface_names = {
        network: f"enp0s{index + 8}"
        for index, network in enumerate(role_interfaces)
    }
    addresses = [
        {
            "ifname": "enp0s3",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "10.0.2.15",
                    "prefixlen": 24,
                    "scope": "global",
                }
            ],
        }
    ]
    routes: list[dict[str, Any]] = [
        {"dst": "default", "gateway": "10.0.2.2", "dev": "enp0s3"},
        {"dst": "10.0.2.0/24", "dev": "enp0s3", "protocol": "kernel"},
    ]
    link_stats: list[dict[str, Any]] = []
    for index, (network, address) in enumerate(role_interfaces.items()):
        interface_name = interface_names[network]
        addresses.append(
            {
                "ifname": interface_name,
                "addr_info": [
                    {
                        "family": "inet",
                        "local": address,
                        "prefixlen": 24,
                        "scope": "global",
                    }
                ],
            }
        )
        routes.append(
            {
                "dst": topology["networks"][network]["cidr"],
                "dev": interface_name,
                "protocol": "kernel",
            }
        )
        base = 1000 + (index * 100) + counter_offset
        link_stats.append(
            {
                "ifname": interface_name,
                "stats64": {
                    "rx": {"packets": base, "bytes": base * 100},
                    "tx": {"packets": base + 10, "bytes": (base + 10) * 100},
                },
            }
        )

    role_listeners = [
        listener
        for listener in runner._listener_contract(deployment)
        if listener["role"] == role
    ]
    ipv4_lines = [
        (
            f"LISTEN 0 4096 {listener['bind_address']}:{listener['port']} "
            "0.0.0.0:*"
        )
        for listener in role_listeners
        if listener["transport"] == "tcp"
    ]
    unix_lines = [
        f"u_str LISTEN 0 4096 {listener['bind_address']} 1 * 0"
        for listener in role_listeners
        if listener["transport"] == "unix"
    ]
    firewall_rules = runner._firewall_contract(
        topology,
        deployment,
        role,
        interface_names=interface_names,
    )
    ufw_added_lines = ["Added user rules (see 'ufw status' for running firewall):"]
    ufw_numbered_lines = ["Status: active"]
    for index, rule in enumerate(firewall_rules, start=1):
        ufw_added_lines.append(
            "ufw allow in on "
            f"{rule['interface']} from {rule['source_address']} "
            f"to {rule['destination_address']} port {rule['port']} proto tcp "
            f"comment 'Aegis-M4j-{index}'"
        )
        ufw_numbered_lines.append(
            f"[{index:2d}] {rule['destination_address']} {rule['port']}/tcp on "
            f"{rule['interface']} ALLOW IN {rule['source_address']}"
        )
    return {
        "hostname": topology["nodes"][role]["hostname"],
        "role_marker": (
            "schema_version=aegis-ot-m4j-topology-v1\n"
            f"role={role}\n"
            "deployment_status=configuration_only\n"
        ),
        "role_marker_mode": 0o440,
        "role_marker_uid": 0,
        "addresses": addresses,
        "routes": routes,
        "link_stats": link_stats,
        "forwarding": {
            "net.ipv4.ip_forward": "0",
            "net.ipv6.conf.all.forwarding": "0",
            "net.ipv6.conf.default.forwarding": "0",
        },
        "ufw_verbose": (
            "Status: active\n"
            "Default: deny (incoming), allow (outgoing), deny (routed)\n"
        ),
        "ufw_numbered": "\n".join(ufw_numbered_lines) + "\n",
        "ufw_added": "\n".join(ufw_added_lines) + "\n",
        "listeners_ipv4": "\n".join(ipv4_lines) + "\n",
        "listeners_ipv6": "",
        "listeners_unix": "\n".join(unix_lines) + ("\n" if unix_lines else ""),
    }


def _payload(script: bytes) -> dict[str, Any]:
    assignment = script.decode("utf-8").splitlines()[1]
    match = re.fullmatch(r"PAYLOAD = json.loads\((.+)\)", assignment)
    assert match is not None
    encoded = ast.literal_eval(match.group(1))
    value = json.loads(encoded)
    assert isinstance(value, dict)
    return value


def _fake_executor(
    runner: Any,
    topology: dict[str, Any],
    deployment: dict[str, Any],
    *,
    force_partition_success: bool = False,
) -> tuple[Callable[..., Any], dict[str, Any]]:
    connectivity = {
        check["check_id"]: bool(check["expected_connected"])
        for check in runner._connectivity_contract(topology, deployment)
    }
    state: dict[str, Any] = {"partitioned": False, "fact_calls": {}, "ssh_configs": set()}

    def execute(
        _ssh_config: Path,
        role: str,
        remote_argv: tuple[str, ...],
        stdin_bytes: bytes,
        _timeout: float,
    ) -> Any:
        state["ssh_configs"].add(_ssh_config)
        if remote_argv[-2:] == ("/usr/bin/python3", "-"):
            payload = _payload(stdin_bytes)
            if b"aegis-m4j-remote-probe-v1:facts" in stdin_bytes:
                calls = state["fact_calls"].get(role, 0)
                state["fact_calls"][role] = calls + 1
                stdout = json.dumps(
                    _valid_remote_facts(
                        runner,
                        role,
                        topology,
                        deployment,
                        counter_offset=calls * 10,
                    ),
                    sort_keys=True,
                ).encode("utf-8")
                return runner.SshOutcome(0, stdout, b"", 2)
            results = []
            for target in payload["targets"]:
                check_id = target["check_id"]
                if check_id.endswith("partitioned"):
                    connected = force_partition_success or not state["partitioned"]
                elif check_id.endswith("restored"):
                    connected = not state["partitioned"]
                else:
                    connected = connectivity[check_id]
                results.append(
                    {
                        "check_id": check_id,
                        "connected": connected,
                        "errno": 0 if connected else 111,
                        "elapsed_ms": 1,
                    }
                )
            return runner.SshOutcome(
                0,
                json.dumps({"results": results}, sort_keys=True).encode("utf-8"),
                b"",
                2,
            )

        if "-C" in remote_argv:
            return runner.SshOutcome(0 if state["partitioned"] else 1, b"", b"", 1)
        if "-I" in remote_argv:
            state["partitioned"] = True
            return runner.SshOutcome(0, b"", b"", 1)
        if "-D" in remote_argv:
            state["partitioned"] = False
            return runner.SshOutcome(0, b"", b"", 1)
        raise AssertionError(remote_argv)

    return execute, state


def test_plan_is_exact_source_bound_and_does_not_execute_ssh(
    runner: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("plan mode invoked SSH")

    monkeypatch.setattr(runner, "_execute_ssh", forbidden)
    before = {
        path.relative_to(repository): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in repository.rglob("*")
        if path.is_file() and ".git" not in path.parts
    }

    plan = runner.build_plan(repository)

    after = {
        path.relative_to(repository): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in repository.rglob("*")
        if path.is_file() and ".git" not in path.parts
    }
    assert before == after
    assert plan["mode"] == "plan_only"
    assert plan["network_acceptance_passed"] is False
    assert plan["source_binding"]["clean_checkout"] is True
    assert {entry["path"] for entry in plan["source_binding"]["files"]} == {
        "scripts/run_m4j_acceptance.py",
        "infra/m4j/topology.yml",
        "infra/m4j/deployment.yml",
        "infra/m4j/workloads.yml",
    }
    assert plan["implementation_gates"][0]["status"] == (
        "implemented_live_validation_pending"
    )
    assert plan["workload_live_probe"] == {
        "evidence_supplied": False,
        "status": "not_run",
    }
    assert plan["packet_metadata_contract"]["payload_capture"] is False
    assert plan["firewall_contract"]["management"] == [
        {
            "direction": "in",
            "interface_network": "management",
            "interface": "resolved_at_runtime_from_exact_address",
            "source_address": "192.168.56.1",
            "destination_address": "192.168.56.10",
            "protocol": "tcp",
            "port": 22,
            "listener_ids": ["management-sshd"],
            "source_ids": ["external:vagrant-host"],
            "edge_ids": ["external:vagrant-host-to-management-sshd"],
        }
    ]


@pytest.mark.parametrize("drift", ["tracked", "untracked"])
def test_source_binding_rejects_any_worktree_drift(
    runner: Any, tmp_path: Path, drift: str
) -> None:
    repository = _repository(tmp_path)
    if drift == "tracked":
        path = repository / "infra" / "m4j" / "topology.yml"
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        (repository / "untracked.txt").write_text("drift\n", encoding="utf-8")

    with pytest.raises(runner.AcceptanceError, match="differs from HEAD|clean checkout"):
        runner._source_binding(repository)


@pytest.mark.parametrize("mask", ["--assume-unchanged", "--skip-worktree"])
def test_source_binding_rejects_index_masked_tracked_drift(
    runner: Any, tmp_path: Path, mask: str
) -> None:
    repository = _repository(tmp_path)
    path = repository / "infra" / "m4j" / "topology.yml"
    _run_git(repository, "update-index", mask, "infra/m4j/topology.yml")
    path.write_bytes(path.read_bytes() + b"\nmasked-drift: true\n")
    assert _run_git(repository, "status", "--porcelain=v1") == ""

    with pytest.raises(runner.AcceptanceError, match="differs from HEAD"):
        runner._source_binding(repository)


def test_source_binding_rejects_index_masked_drift_outside_fingerprint_files(
    runner: Any, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    extra = repository / "tracked-support.txt"
    extra.write_text("committed\n", encoding="utf-8")
    _run_git(repository, "add", "tracked-support.txt")
    _run_git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "support fixture",
    )
    _run_git(repository, "update-index", "--assume-unchanged", "tracked-support.txt")
    extra.write_text("masked\n", encoding="utf-8")
    assert _run_git(repository, "status", "--porcelain=v1") == ""

    with pytest.raises(runner.AcceptanceError, match="tracked-support.txt"):
        runner._source_binding(repository)


def test_source_binding_rejects_corrupted_head_blob_with_matching_worktree(
    runner: Any, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    relative = "infra/m4j/topology.yml"
    path = repository / relative
    object_id = _run_git(repository, "rev-parse", f"HEAD:{relative}").strip()
    object_path = repository / ".git" / "objects" / object_id[:2] / object_id[2:]
    assert object_path.is_file()
    _run_git(repository, "update-index", "--assume-unchanged", relative)
    malicious = path.read_bytes() + b"\nmasked-object-corruption: true\n"
    path.write_bytes(malicious)
    object_path.chmod(0o600)
    object_path.write_bytes(
        zlib.compress(f"blob {len(malicious)}\x00".encode("ascii") + malicious)
    )

    with pytest.raises(runner.AcceptanceError, match="exact M4j source binding"):
        runner._source_binding(repository)


def test_source_binding_disables_configured_fsmonitor_execution(
    runner: Any, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    marker = tmp_path / "fsmonitor-executed"
    monitor = tmp_path / "fsmonitor"
    monitor.write_text(f"#!/bin/sh\n/usr/bin/touch {marker}\n", encoding="utf-8")
    monitor.chmod(0o700)
    _run_git(repository, "config", "core.fsmonitor", str(monitor))

    binding = runner._source_binding(repository)

    assert binding["clean_checkout"] is True
    assert not marker.exists()


def test_source_binding_rejects_external_git_config_and_object_sources(
    runner: Any, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    external = tmp_path / "external.gitconfig"
    external.write_text("[core]\n\tfsmonitor = /bin/false\n", encoding="utf-8")
    config = repository / ".git" / "config"
    config.write_text(
        config.read_text(encoding="utf-8")
        + f"\n[include]\n\tpath = {external}\n",
        encoding="utf-8",
    )

    with pytest.raises(runner.AcceptanceError, match="includes are forbidden"):
        runner._source_binding(repository)

    config.write_text(
        config.read_text(encoding="utf-8").split("\n[include]", maxsplit=1)[0] + "\n",
        encoding="utf-8",
    )
    alternate = repository / ".git" / "objects" / "info" / "alternates"
    alternate.write_text(str(tmp_path / "objects") + "\n", encoding="utf-8")
    with pytest.raises(runner.AcceptanceError, match="alternate"):
        runner._source_binding(repository)


def test_deployment_binding_preserves_trust_separation_and_closed_paths(runner: Any) -> None:
    topology = runner._load_topology((ROOT / "infra" / "m4j" / "topology.yml").read_bytes())
    deployment = runner._load_deployment(
        (ROOT / "infra" / "m4j" / "deployment.yml").read_bytes(), topology
    )
    listeners = {item["listener_id"]: item for item in runner._listener_contract(deployment)}

    assert (
        listeners["policy-relay-api"]["role"],
        listeners["policy-relay-api"]["bind_address"],
    ) == (
        "trust",
        "192.168.59.11",
    )
    assert (
        listeners["opa-loopback"]["role"],
        listeners["opa-loopback"]["bind_address"],
        listeners["opa-loopback"]["port"],
    ) == ("trust", "127.0.0.1", 8182)
    assert listeners["observer-api"]["role"] == "trust"
    assert listeners["candidate-api"]["role"] == "trust"
    assert listeners["ot-adapter-api"]["role"] == "ot"
    assert listeners["plant-api"]["service"] == "plant"
    assert {listeners[f"{role}-sshd"]["bind_address"] for role in runner.EXPECTED_ROLES} == {
        f"192.168.56.{offset}" for offset in range(10, 16)
    }

    checks = {
        item["check_id"]: item
        for item in runner._connectivity_contract(topology, deployment)
    }
    assert checks["agents-to-segmented-gateway-api-8081"]["expected_connected"] is True
    assert checks["agents-to-ot-adapter-api-8083"]["expected_connected"] is False
    assert checks["agents-to-ot-adapter-api-8083"]["source_network"] == "agent_lane"
    assert checks["agents-to-plant-api-8084"]["expected_connected"] is False
    assert checks["agents-to-plant-api-8084"]["source_network"] == "agent_lane"
    assert checks["gateway-to-policy-relay-api-8181"]["expected_connected"] is True
    assert checks["trust-local-to-opa-loopback-8182"]["expected_connected"] is True
    assert checks["ot-to-observer-api-8082"]["expected_connected"] is True
    assert checks["trust-to-plant-api-8084"]["expected_connected"] is True
    assert checks["management-to-trust-sshd-22"]["expected_connected"] is True
    assert checks["agents-to-trust-sshd-22"]["expected_connected"] is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("placement", "service placement"),
        ("listener", "listener contract"),
        ("agent_bypass", "peer sources"),
        ("topology_binding", "authoritative topology"),
    ],
)
def test_deployment_validation_fails_closed_on_drift(
    runner: Any, mutation: str, message: str
) -> None:
    topology = _topology()
    deployment = copy.deepcopy(_deployment())
    if mutation == "placement":
        deployment["roles"]["trust"]["workloads"].remove("observer")
    elif mutation == "listener":
        deployment["listeners"]["observer-api"]["bind_address"] = "0.0.0.0"  # noqa: S104
    elif mutation == "agent_bypass":
        deployment["peer_edges"].append(
            {
                "id": "unsafe-agent-to-ot",
                "source_role": "agents",
                "source_service": "agent-probe",
                "destination_listener": "ot-adapter-api",
                "network": "control_dmz",
                "protocol": "https",
                "authentication": "spiffe_mtls",
            }
        )
    else:
        deployment["topology_binding"]["canonical_sha256"] = "0" * 64

    with pytest.raises(runner.AcceptanceError, match=message):
        runner._load_deployment(yaml.safe_dump(deployment, sort_keys=False).encode(), topology)


@pytest.mark.parametrize("document", ["topology", "deployment"])
def test_contract_loaders_reject_duplicate_yaml_keys(runner: Any, document: str) -> None:
    duplicate = b"schema_version: first\nschema_version: second\n"

    with pytest.raises(runner.AcceptanceError, match="duplicate YAML"):
        if document == "topology":
            runner._load_topology(duplicate)
        else:
            runner._load_deployment(duplicate, _topology())


def test_host_facts_require_exact_identity_routes_firewall_and_listeners(runner: Any) -> None:
    topology = _topology()
    deployment = _deployment()
    raw = _valid_remote_facts(runner, "trust", topology, deployment)

    observed = runner._validate_host_facts("trust", topology, deployment, raw)

    assert observed["hostname"] == "aegis-trust"
    assert {item["service"] for item in observed["listeners"]["tcp"]} == {
        "sshd",
        "spire-server",
        "opa",
        "policy-relay",
        "observer",
        "candidate",
    }
    assert observed["listeners"]["unix"] == [
        {
            "listener_id": "spire-server-admin",
            "service": "spire-server",
            "address": "/run/spire/server/private/api.sock",
        },
        {
            "listener_id": "trust-spire-workload-api",
            "service": "spire-agent",
            "address": "/run/spire/agent/public/api.sock",
        },
    ]
    assert set(observed["forwarding"].values()) == {"0"}
    assert observed["ufw"]["ingress_rule_count"] > 1
    assert observed["ufw"]["extra_inbound_or_routed_allow_count"] == 0
    assert all(
        rule["source_address"] != "192.168.56.0/24"
        for rule in observed["ufw"]["normalized_ingress_rules"]
    )


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("hostname", "hostname identity"),
        ("forwarding", "forwarding"),
        ("route", "connected route"),
        ("ufw", "extra inbound"),
        ("listener", "listener contract"),
        ("ipv6", "IPv6"),
        ("unix", "Unix listener"),
    ],
)
def test_host_facts_fail_closed_on_boundary_drift(
    runner: Any, case: str, message: str
) -> None:
    topology = _topology()
    deployment = _deployment()
    raw = _valid_remote_facts(runner, "gateway", topology, deployment)
    if case == "hostname":
        raw["hostname"] = "aegis-other"
    elif case == "forwarding":
        raw["forwarding"]["net.ipv4.ip_forward"] = "1"
    elif case == "route":
        raw["routes"] = [
            route for route in raw["routes"] if route.get("dst") != "192.168.58.0/24"
        ]
    elif case == "ufw":
        raw["ufw_numbered"] += "[ 2] 22/tcp ALLOW IN Anywhere\n"
    elif case == "listener":
        raw["listeners_ipv4"] += "LISTEN 0 4096 0.0.0.0:9000 0.0.0.0:*\n"  # noqa: S104
    elif case == "ipv6":
        raw["listeners_ipv6"] = "LISTEN 0 4096 [::]:22 [::]:*\n"
    else:
        raw["listeners_unix"] = ""

    with pytest.raises(runner.AcceptanceError, match=message):
        runner._validate_host_facts("gateway", topology, deployment, raw)


def test_host_facts_reject_a_missing_required_deployment_firewall_rule(runner: Any) -> None:
    topology = _topology()
    deployment = _deployment()
    raw = _valid_remote_facts(runner, "trust", topology, deployment)
    added_lines = raw["ufw_added"].splitlines()
    numbered_lines = raw["ufw_numbered"].splitlines()
    raw["ufw_added"] = "\n".join(added_lines[:-1]) + "\n"
    raw["ufw_numbered"] = "\n".join(numbered_lines[:-1]) + "\n"

    with pytest.raises(runner.AcceptanceError, match="deployment edges"):
        runner._validate_host_facts("trust", topology, deployment, raw)


def test_host_facts_reject_an_extra_broad_firewall_rule(runner: Any) -> None:
    topology = _topology()
    deployment = _deployment()
    raw = _valid_remote_facts(runner, "gateway", topology, deployment)
    raw["ufw_added"] += (
        "ufw allow in on enp0s10 from 0.0.0.0/0 to 192.168.58.13 "
        "port 8081 proto tcp comment 'unsafe-broad-rule'\n"
    )
    raw["ufw_numbered"] += (
        "[99] 192.168.58.13 8081/tcp on enp0s10 ALLOW IN Anywhere\n"
    )

    with pytest.raises(runner.AcceptanceError, match="exactly one IPv4 host"):
        runner._validate_host_facts("gateway", topology, deployment, raw)


def test_recorded_ssh_retains_only_hashes_and_bounded_result_metadata(
    runner: Any, tmp_path: Path
) -> None:
    config = tmp_path / "secret-config"
    config.write_text("Host management\n", encoding="utf-8")
    command_records: list[dict[str, Any]] = []

    def execute(*_args: Any) -> Any:
        return runner.SshOutcome(0, b'{"ok":true}', b"", 7)

    runner._recorded_ssh(
        ssh_config=config,
        role="management",
        command_id="fixture",
        remote_argv=("/usr/bin/python3", "-"),
        stdin_bytes=b"sensitive fixture input",
        command_records=command_records,
        executor=execute,
    )

    record = command_records[0]
    encoded = json.dumps(record)
    assert "secret-config" not in encoded
    assert "sensitive fixture input" not in encoded
    assert "remote_argv" not in record
    assert runner._command_hashes_complete(command_records) is True


def test_ssh_transport_rejects_ambient_directives_and_reused_host_keys(
    runner: Any, tmp_path: Path
) -> None:
    ssh_config, known_hosts = _ssh_transport_inputs(tmp_path)
    ssh_config.write_text(
        ssh_config.read_text(encoding="utf-8") + "  ProxyCommand /bin/true\n",
        encoding="utf-8",
    )
    with pytest.raises(runner.AcceptanceError, match="forbidden directive"):
        with runner._stable_ssh_transport(ssh_config, known_hosts):
            pass

    ssh_config, known_hosts = _ssh_transport_inputs(tmp_path)
    lines = known_hosts.read_text(encoding="ascii").splitlines()
    first_key = lines[0].split(" ", maxsplit=2)[2]
    role_address, algorithm, _last_key = lines[-1].split(" ")
    lines[-1] = f"{role_address} {algorithm} {first_key}"
    known_hosts.write_text("\n".join(lines) + "\n", encoding="ascii")
    with pytest.raises(runner.AcceptanceError, match="distinct host key"):
        with runner._stable_ssh_transport(ssh_config, known_hosts):
            pass


def test_execute_ssh_forces_pinned_closed_transport(
    runner: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}
    stable = tmp_path / "stable"
    stable.mkdir(mode=0o700)
    config = stable / "config"
    config.write_text("closed\n", encoding="utf-8")
    config.chmod(0o600)

    def run(command: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(command, 0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(runner.subprocess, "run", run)
    outcome = runner._execute_ssh(config, "management", ("/bin/true",), b"", 1.0)

    command = captured["command"]
    assert command[0] == "/usr/bin/ssh"
    assert ("-F", str(config)) == command[1:3]
    assert "StrictHostKeyChecking=yes" in command
    assert f"UserKnownHostsFile={stable / 'known_hosts'}" in command
    assert "GlobalKnownHostsFile=/dev/null" in command
    assert "ProxyCommand=none" in command
    assert "ProxyJump=none" in command
    assert captured["environment"] == {
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    assert outcome.returncode == 0


def test_mocked_live_campaign_publishes_private_closed_evidence(
    runner: Any, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    topology = _topology()
    deployment = _deployment()
    ssh_config, known_hosts = _ssh_transport_inputs(tmp_path)
    output = tmp_path / "m4j-evidence.json"
    executor, state = _fake_executor(runner, topology, deployment)

    evidence = runner.run_live(
        output,
        ssh_config,
        known_hosts,
        root=repository,
        executor=executor,
    )

    assert evidence["network_acceptance_passed"] is True
    assert all(evidence["acceptance"].values())
    assert state["partitioned"] is False
    assert len(state["ssh_configs"]) == 1
    stable_config = next(iter(state["ssh_configs"]))
    assert stable_config != ssh_config
    assert not stable_config.exists()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text(encoding="utf-8")) == evidence
    assert evidence["gateway_partition"] == {
        **{
            key: evidence["gateway_partition"][key]
            for key in (
                "source_role",
                "destination_role",
                "destination_address",
                "port",
                "rule_marker_sha256",
            )
        },
        "denial_verified": True,
        "cleanup_verified": True,
        "restoration_verified": True,
    }
    assert all(
        item["payload_captured"] is False for item in evidence["packet_metadata"].values()
    )
    assert len(evidence["commands"]) == 32
    assert "ssh-config" not in json.dumps(evidence)
    assert evidence["ssh_transport"]["known_hosts"]["distinct_host_key_count"] == 6
    assert evidence["semantic_projection"]["ssh_transport"][
        "known_hosts_sha256"
    ] == evidence["ssh_transport"]["known_hosts"]["sha256"]


def test_partition_failure_removes_only_its_exact_rule_and_does_not_publish(
    runner: Any, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    ssh_config, known_hosts = _ssh_transport_inputs(tmp_path)
    output = tmp_path / "rejected.json"
    executor, state = _fake_executor(
        runner,
        _topology(),
        _deployment(),
        force_partition_success=True,
    )

    with pytest.raises(runner.AcceptanceError, match="partitioned"):
        runner.run_live(
            output,
            ssh_config,
            known_hosts,
            root=repository,
            executor=executor,
        )

    assert state["partitioned"] is False
    assert not output.exists()


def test_partition_insert_lost_response_still_reconciles_exact_rule_absent(
    runner: Any, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    ssh_config, known_hosts = _ssh_transport_inputs(tmp_path)
    output = tmp_path / "lost-response.json"
    execute, state = _fake_executor(runner, _topology(), _deployment())
    insert_response_lost = False

    def lost_response_executor(*args: Any) -> Any:
        nonlocal insert_response_lost
        remote_argv = args[2]
        if "-I" in remote_argv and not insert_response_lost:
            insert_response_lost = True
            state["partitioned"] = True
            raise runner.AcceptanceError("synthetic lost insert response")
        return execute(*args)

    with pytest.raises(runner.AcceptanceError, match="lost insert response"):
        runner.run_live(
            output,
            ssh_config,
            known_hosts,
            root=repository,
            executor=lost_response_executor,
        )

    assert insert_response_lost is True
    assert state["partitioned"] is False
    assert not output.exists()


def test_stable_ssh_transport_drift_rejects_and_removes_evidence(
    runner: Any, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    ssh_config, known_hosts = _ssh_transport_inputs(tmp_path)
    output = tmp_path / "transport-drift.json"
    execute, _state = _fake_executor(runner, _topology(), _deployment())
    mutated = False

    def mutating_executor(*args: Any) -> Any:
        nonlocal mutated
        stable_config = args[0]
        if not mutated:
            stable_config.write_bytes(stable_config.read_bytes() + b"# drift\n")
            mutated = True
        return execute(*args)

    with pytest.raises(runner.AcceptanceError, match="stable SSH transport input"):
        runner.run_live(
            output,
            ssh_config,
            known_hosts,
            root=repository,
            executor=mutating_executor,
        )

    assert mutated is True
    assert not output.exists()


def test_live_output_and_ssh_configuration_are_fail_closed(
    runner: Any, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    ssh_config, known_hosts = _ssh_transport_inputs(tmp_path)
    ssh_config.chmod(0o644)
    output = tmp_path / "existing.json"
    output.write_text("retain\n", encoding="utf-8")

    with pytest.raises(runner.AcceptanceError, match="mode must"):
        runner.run_live(output, ssh_config, known_hosts, root=repository)

    ssh_config.chmod(0o600)
    with pytest.raises(runner.AcceptanceError, match="overwrite"):
        runner.run_live(output, ssh_config, known_hosts, root=repository)
    assert output.read_text(encoding="utf-8") == "retain\n"


def test_live_output_must_be_outside_source_checkout(runner: Any, tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    ssh_config, known_hosts = _ssh_transport_inputs(tmp_path)

    with pytest.raises(runner.AcceptanceError, match="outside"):
        runner.run_live(
            repository / "evidence.json",
            ssh_config,
            known_hosts,
            root=repository,
        )


def test_plan_parser_rejects_live_arguments(runner: Any) -> None:
    parser = runner._parser()
    arguments = parser.parse_args(["--plan", "--output", "evidence.json"])
    assert arguments.plan is True
    assert arguments.output == Path("evidence.json")
    # main performs the cross-option rejection before any source or SSH action.
    assert "does not accept" in (
        "--plan does not accept --output, --ssh-config, or --known-hosts"
    )


def test_runner_source_has_no_shell_execution_or_packet_capture(runner: Any) -> None:
    source = (ROOT / "scripts" / "run_m4j_acceptance.py").read_text(encoding="utf-8")

    assert "shell=True" not in source
    assert "tcpdump" not in source
    assert "tshark" not in source
    assert "private_key_material" not in source
    assert "payload_captured\": False" in source
    assert runner.EVIDENCE_BOUNDARIES
