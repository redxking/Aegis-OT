from __future__ import annotations

import copy
import ipaddress
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VAGRANTFILE = ROOT / "Vagrantfile"
TOPOLOGY_PATH = ROOT / "infra" / "m4j" / "topology.yml"

EXPECTED_ROLES = ["management", "trust", "agents", "gateway", "ot", "simulation"]
EXPECTED_NETWORKS = {
    "management": {
        "cidr": "192.168.56.0/24",
        "kind": "host_only",
        "members": EXPECTED_ROLES,
    },
    "trust_enrollment": {
        "cidr": "192.168.57.0/24",
        "kind": "virtualbox_internal",
        "members": ["trust", "agents", "gateway", "ot", "simulation"],
    },
    "agent_lane": {
        "cidr": "192.168.58.0/24",
        "kind": "virtualbox_internal",
        "members": ["agents", "gateway"],
    },
    "control_dmz": {
        "cidr": "192.168.59.0/24",
        "kind": "virtualbox_internal",
        "members": ["trust", "gateway", "ot"],
    },
    "simulation_lane": {
        "cidr": "192.168.60.0/24",
        "kind": "virtualbox_internal",
        "members": ["trust", "ot", "simulation"],
    },
}

RUBY_VAGRANT_STUB = r"""
class VagrantStub
  def vm
    self
  end

  def method_missing(_name, *_arguments, **_keywords, &block)
    block.call(self) if block
    self
  end

  def respond_to_missing?(*_arguments)
    true
  end
end

module Vagrant
  def self.configure(_version)
    yield VagrantStub.new
  end
end

load ARGV.fetch(0)
"""


def _topology() -> dict[str, Any]:
    value = yaml.safe_load(TOPOLOGY_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _ruby() -> str:
    executable = shutil.which("ruby")
    if executable is None:
        pytest.skip("Ruby is unavailable")
    return executable


def _run_vagrant_loader(tmp_path: Path, topology: object) -> subprocess.CompletedProcess[str]:
    fixture_root = tmp_path / "fixture"
    fixture_topology = fixture_root / "infra" / "m4j" / "topology.yml"
    fixture_topology.parent.mkdir(parents=True)
    shutil.copyfile(VAGRANTFILE, fixture_root / "Vagrantfile")
    fixture_topology.write_text(
        yaml.safe_dump(topology, sort_keys=False),
        encoding="utf-8",
    )
    return subprocess.run(  # noqa: S603 - fixed Ruby validation harness
        [_ruby(), "-e", RUBY_VAGRANT_STUB, str(fixture_root / "Vagrantfile")],
        check=False,
        capture_output=True,
        text=True,
    )


def test_topology_is_the_closed_six_node_contract() -> None:
    topology = _topology()

    assert list(topology) == [
        "schema_version",
        "deployment_status",
        "claim_boundary",
        "box",
        "bootstrap_nat",
        "capacity",
        "addressing",
        "networks",
        "nodes",
    ]
    assert topology["schema_version"] == "aegis-ot-m4j-topology-v1"
    assert topology["deployment_status"] == "configuration_only"
    assert topology["claim_boundary"] == ("no_live_deployment_or_multi_host_isolation_evidence")
    assert topology["box"] == {
        "name": "generic/ubuntu2204",
        "version": "4.3.12",
        "provider": "virtualbox",
        "check_update": False,
    }
    assert topology["bootstrap_nat"] == {
        "enabled": True,
        "purpose": "vagrant_bootstrap_only",
        "application_bindings_allowed": False,
        "guest_ssh_port": 22,
    }
    assert list(topology["nodes"]) == EXPECTED_ROLES
    assert list(topology["networks"]) == list(EXPECTED_NETWORKS)

    for name, expected in EXPECTED_NETWORKS.items():
        network = topology["networks"][name]
        assert network["cidr"] == expected["cidr"]
        assert network["kind"] == expected["kind"]
        assert network["members"] == expected["members"]
        if name == "management":
            assert network["gateway"] == "192.168.56.1"
            assert network["internal_name"] is None
        else:
            assert network["gateway"] is None
            assert network["internal_name"].startswith("aegis-m4j-")


def test_topology_addresses_and_resources_are_static_bounded_and_nonoverlapping() -> None:
    topology = _topology()
    networks = {
        name: ipaddress.ip_network(network["cidr"], strict=True)
        for name, network in topology["networks"].items()
    }
    for index, left in enumerate(networks.values()):
        for right in list(networks.values())[index + 1 :]:
            assert not left.overlaps(right)

    configured_addresses: list[ipaddress.IPv4Address] = []
    first_offset = topology["addressing"]["first_node_host_offset"]
    for role_index, (role, node) in enumerate(topology["nodes"].items()):
        assert node["hostname"] == f"aegis-{role}"
        expected_interfaces = [
            name for name, network in topology["networks"].items() if role in network["members"]
        ]
        assert list(node["interfaces"]) == expected_interfaces
        for network_name, raw_address in node["interfaces"].items():
            address = ipaddress.ip_address(raw_address)
            network = networks[network_name]
            assert address == network.network_address + first_offset + role_index
            assert address not in {network.network_address, network.broadcast_address}
            assert raw_address != topology["networks"][network_name]["gateway"]
            configured_addresses.append(address)

    assert len(configured_addresses) == len(set(configured_addresses))
    capacity = topology["capacity"]
    nodes = topology["nodes"].values()
    assert sum(node["cpus"] for node in nodes) <= capacity["max_total_cpus"]
    assert (
        sum(node["memory_mb"] for node in topology["nodes"].values())
        <= (capacity["max_total_memory_mb"])
    )
    assert all(
        node["cpus"] <= capacity["max_node_cpus"]
        and node["memory_mb"] <= capacity["max_node_memory_mb"]
        for node in topology["nodes"].values()
    )


def test_vagrantfile_loads_only_the_contract_and_exposes_no_application_port() -> None:
    source = VAGRANTFILE.read_text(encoding="utf-8")

    assert 'File.join(__dir__, "infra", "m4j", "topology.yml")' in source
    assert "YAML.safe_load" in source
    assert 'config.vm.synced_folder ".", "/vagrant", disabled: true' in source
    assert 'config.vm.provider box.fetch("provider")' in source
    assert 'config.vm.box_version = box.fetch("version")' in source
    assert 'config.vm.box_check_update = box.fetch("check_update")' in source
    assert "options[:virtualbox__intnet]" in source
    assert "adapter 1 NAT is bootstrap-only; application bindings prohibited" in source
    assert "forwarded_port" not in source
    assert 'node.vm.provision "ansible"' in source
    assert 'ansible.playbook = "infra/ansible/site.yml"' in source
    assert 'ansible.inventory_path = "infra/ansible/inventory.ini"' in source
    assert 'ansible.limit = "#{role},localhost"' in source
    assert 'node.vm.provision "shell"' not in source
    assert "192.168." not in source
    assert "generic/ubuntu2204" not in source


def test_vagrantfile_ruby_syntax_is_valid() -> None:
    completed = subprocess.run(  # noqa: S603 - fixed local syntax check
        [_ruby(), "-c", str(VAGRANTFILE)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "Syntax OK" in completed.stdout


def test_vagrantfile_accepts_the_committed_topology(tmp_path: Path) -> None:
    completed = _run_vagrant_loader(tmp_path, _topology())
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    "case",
    [
        "malformed_root",
        "extra_topology_field",
        "extra_nested_field",
        "missing_role",
        "unknown_network",
        "unknown_member",
        "duplicate_ip",
        "unsafe_subnet",
        "overlapping_subnets",
        "reserved_gateway_address",
        "routed_data_lane",
        "capacity_exceeded",
        "unpinned_box",
        "wrong_provider",
    ],
)
def test_vagrantfile_rejects_invalid_topology(tmp_path: Path, case: str) -> None:
    topology: object = copy.deepcopy(_topology())
    if case == "malformed_root":
        topology = ["not", "a", "mapping"]
    else:
        assert isinstance(topology, dict)
        if case == "extra_topology_field":
            topology["unexpected"] = True
        elif case == "extra_nested_field":
            topology["box"]["checksum"] = "unregistered"
        elif case == "missing_role":
            topology["nodes"].pop("simulation")
        elif case == "unknown_network":
            topology["nodes"]["agents"]["interfaces"]["untrusted"] = "192.168.61.12"
        elif case == "unknown_member":
            topology["networks"]["agent_lane"]["members"].append("intruder")
        elif case == "duplicate_ip":
            topology["nodes"]["trust"]["interfaces"]["management"] = "192.168.56.10"
        elif case == "unsafe_subnet":
            topology["networks"]["trust_enrollment"]["cidr"] = "203.0.113.0/24"
        elif case == "overlapping_subnets":
            topology["networks"]["trust_enrollment"]["cidr"] = "192.168.56.0/24"
        elif case == "reserved_gateway_address":
            topology["nodes"]["management"]["interfaces"]["management"] = "192.168.56.1"
        elif case == "routed_data_lane":
            topology["networks"]["simulation_lane"]["gateway"] = "192.168.60.1"
        elif case == "capacity_exceeded":
            for node in topology["nodes"].values():
                node["cpus"] = 3
        elif case == "unpinned_box":
            topology["box"]["version"] = "latest"
        elif case == "wrong_provider":
            topology["box"]["provider"] = "libvirt"
        else:  # pragma: no cover - parameter list is closed above
            raise AssertionError(f"unhandled invalid-topology case: {case}")

    completed = _run_vagrant_loader(tmp_path / case, topology)
    assert completed.returncode != 0
    assert "M4jTopology::Error" in completed.stderr
