from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ANSIBLE_ROOT = ROOT / "infra" / "ansible"
TOPOLOGY_PATH = ROOT / "infra" / "m4j" / "topology.yml"
VAGRANTFILE = ROOT / "Vagrantfile"
TASKS_PATH = ANSIBLE_ROOT / "roles" / "m4j_base" / "tasks" / "main.yml"
HANDLERS_PATH = ANSIBLE_ROOT / "roles" / "m4j_base" / "handlers" / "main.yml"
FILES_ROOT = ANSIBLE_ROOT / "roles" / "m4j_base" / "files"

EXPECTED_ROLES = ["management", "trust", "agents", "gateway", "ot", "simulation"]
EXPECTED_MANAGEMENT_IPS = {
    role: f"192.168.56.{offset}"
    for role, offset in zip(EXPECTED_ROLES, range(10, 16), strict=True)
}
EXPECTED_PACKAGE_ENV = {
    "ca-certificates": "AEGIS_M4J_PKG_CA_CERTIFICATES",
    "python3": "AEGIS_M4J_PKG_PYTHON3",
    "python3-venv": "AEGIS_M4J_PKG_PYTHON3_VENV",
    "iproute2": "AEGIS_M4J_PKG_IPROUTE2",
    "iptables": "AEGIS_M4J_PKG_IPTABLES",
    "runc": "AEGIS_M4J_PKG_RUNC",
    "containerd": "AEGIS_M4J_PKG_CONTAINERD",
    "ufw": "AEGIS_M4J_PKG_UFW",
    "docker.io": "AEGIS_M4J_PKG_DOCKER_IO",
}

RUBY_VAGRANT_STUB = r"""
class VagrantStub
  attr_accessor :host, :port

  def vm
    self
  end

  def ssh
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
    $m4j_stub = VagrantStub.new
    yield $m4j_stub
  end
end

load ARGV.fetch(0)
puts "management_ssh=#{$m4j_stub.host}:#{$m4j_stub.port}" if $m4j_stub.host
"""


def _yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _tasks() -> list[dict[str, Any]]:
    value = _yaml(TASKS_PATH)
    assert isinstance(value, list)
    return value


def _task(tasks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for task in tasks:
        if task["name"] == name:
            return task
        for section in ("block", "rescue", "always"):
            nested = task.get(section)
            if isinstance(nested, list):
                try:
                    return _task(nested, name)
                except StopIteration:
                    pass
    raise StopIteration(name)


def _inventory() -> tuple[dict[str, list[tuple[str, dict[str, str]]]], dict[str, str]]:
    groups: dict[str, list[tuple[str, dict[str, str]]]] = {}
    all_vars: dict[str, str] = {}
    section = ""
    for raw_line in (ANSIBLE_ROOT / "inventory.ini").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section != "all:vars":
                groups[section] = []
            continue
        if section == "all:vars":
            key, value = line.split("=", maxsplit=1)
            all_vars[key] = value
            continue
        parts = line.split()
        attributes = dict(part.split("=", maxsplit=1) for part in parts[1:])
        groups[section].append((parts[0], attributes))
    return groups, all_vars


def _ruby() -> str:
    executable = shutil.which("ruby")
    if executable is None:
        pytest.skip("Ruby is unavailable")
    return executable


def _run_vagrant_with_marker(
    tmp_path: Path,
    *,
    marker: str | None,
    mode: int = 0o600,
    symlink: bool = False,
) -> subprocess.CompletedProcess[str]:
    fixture_root = tmp_path / "fixture"
    fixture_topology = fixture_root / "infra" / "m4j" / "topology.yml"
    fixture_topology.parent.mkdir(parents=True)
    shutil.copyfile(VAGRANTFILE, fixture_root / "Vagrantfile")
    shutil.copyfile(TOPOLOGY_PATH, fixture_topology)
    if marker is not None:
        marker_path = (
            fixture_root
            / ".vagrant"
            / "machines"
            / "management"
            / "virtualbox"
            / "m4j-management-communicator"
        )
        marker_path.parent.mkdir(parents=True)
        if symlink:
            target = fixture_root / "marker-target"
            target.write_text(marker, encoding="utf-8")
            target.chmod(mode)
            marker_path.symlink_to(target)
        else:
            marker_path.write_text(marker, encoding="utf-8")
            marker_path.chmod(mode)
    return subprocess.run(  # noqa: S603 - fixed Ruby validation harness
        [_ruby(), "-e", RUBY_VAGRANT_STUB, str(fixture_root / "Vagrantfile")],
        check=False,
        capture_output=True,
        text=True,
    )


def test_inventory_is_exactly_the_authoritative_management_plane() -> None:
    topology = _yaml(TOPOLOGY_PATH)
    groups, all_vars = _inventory()

    assert list(groups) == EXPECTED_ROLES
    assert all_vars == {
        "ansible_user": "vagrant",
        "ansible_python_interpreter": "/usr/bin/python3",
    }
    for role in EXPECTED_ROLES:
        authoritative_ip = topology["nodes"][role]["interfaces"]["management"]
        assert authoritative_ip == EXPECTED_MANAGEMENT_IPS[role]
        assert groups[role] == [
            (
                role,
                {
                    "ansible_host": authoritative_ip,
                    "aegis_role": role,
                },
            )
        ]


def test_vagrant_uses_only_the_bounded_ansible_provisioner() -> None:
    source = VAGRANTFILE.read_text(encoding="utf-8")

    assert source.count('node.vm.provision "ansible"') == 1
    assert 'ansible.playbook = "infra/ansible/site.yml"' in source
    assert 'ansible.inventory_path = "infra/ansible/inventory.ini"' in source
    assert 'ansible.limit = "#{role},localhost"' in source
    assert '"m4j_vagrant_machine" => role' in source
    assert 'node.vm.provision "shell"' not in source
    assert "forwarded_port" not in source
    assert '"m4j-management-communicator"' in source
    assert "node.ssh.host = management_address" in source
    assert "node.ssh.port = 22" in source


def test_valid_communicator_marker_switches_vagrant_to_management_ssh(tmp_path: Path) -> None:
    completed = _run_vagrant_with_marker(
        tmp_path,
        marker=(
            "aegis-ot-m4j-management-communicator-v1\n"
            "role=management\n"
            "address=192.168.56.10\n"
        ),
    )
    assert completed.returncode == 0, completed.stderr
    assert "management_ssh=192.168.56.10:22" in completed.stdout


@pytest.mark.parametrize(
    ("marker", "mode", "symlink"),
    [
        ("malformed\n", 0o600, False),
        (
            "aegis-ot-m4j-management-communicator-v1\n"
            "role=management\n"
            "address=192.168.56.10\n",
            0o644,
            False,
        ),
        (
            "aegis-ot-m4j-management-communicator-v1\n"
            "role=management\n"
            "address=192.168.56.10\n",
            0o600,
            True,
        ),
    ],
)
def test_unsafe_communicator_marker_fails_closed(
    tmp_path: Path,
    marker: str,
    mode: int,
    symlink: bool,
) -> None:
    completed = _run_vagrant_with_marker(
        tmp_path,
        marker=marker,
        mode=mode,
        symlink=symlink,
    )
    assert completed.returncode != 0
    assert "M4jTopology::Error" in completed.stderr


def test_playbook_fails_closed_on_topology_inventory_and_pin_drift_before_role() -> None:
    plays = _yaml(ANSIBLE_ROOT / "site.yml")
    assert isinstance(plays, list) and len(plays) == 2
    controller, host = plays

    assert controller["hosts"] == "localhost"
    assert controller["connection"] == "local"
    assert controller["become"] is False
    assert controller["gather_facts"] is False
    assert controller["tasks"][0]["ansible.builtin.include_vars"] == {
        "file": "../m4j/topology.yml",
        "name": "m4j_topology",
    }
    preflight_conditions = controller["tasks"][1]["ansible.builtin.assert"]["that"]
    preflight_text = "\n".join(preflight_conditions)
    assert "configuration_only" in preflight_text
    assert "no_live_deployment_or_multi_host_isolation_evidence" in preflight_text
    assert 'groups["all"]' in preflight_text
    assert "m4j_vagrant_machine in m4j_expected_roles" in preflight_text
    assert "m4j_vagrant_communicator_marker_path ==" in preflight_text
    assert "ansible_version.full == m4j_required_ansible_core_version" in preflight_text
    assert "m4j_required_apt_sources_manifest_sha256" in preflight_text
    assert "m4j_required_package_versions.keys()" in preflight_text

    inventory_check = controller["tasks"][2]
    inventory_conditions = inventory_check["ansible.builtin.assert"]["that"]
    assert inventory_check["loop"] == "{{ m4j_expected_roles }}"
    assert "groups[item] == [item]" in inventory_conditions
    assert "hostvars[item].aegis_role == item" in inventory_conditions
    assert (
        "hostvars[item].ansible_host == m4j_topology.nodes[item].interfaces.management"
        in inventory_conditions
    )
    assert host["hosts"] == "{{ m4j_vagrant_machine }}"
    assert host["become"] is True
    assert host["gather_facts"] is True
    host_conditions = "\n".join(host["pre_tasks"][1]["ansible.builtin.assert"]["that"])
    assert "inventory_hostname == m4j_vagrant_machine" in host_conditions
    assert 'ansible_distribution == "Ubuntu"' in host_conditions
    assert 'ansible_distribution_version == "22.04"' in host_conditions
    assert 'ansible_distribution_release == "jammy"' in host_conditions
    assert host["roles"] == [{"role": "m4j_base"}]


def test_controller_source_text_and_direct_package_inputs_require_exact_pins() -> None:
    variables = _yaml(ANSIBLE_ROOT / "group_vars" / "all.yml")
    assert variables["m4j_expected_roles"] == EXPECTED_ROLES
    assert "AEGIS_M4J_ANSIBLE_CORE_VERSION" in variables[
        "m4j_required_ansible_core_version"
    ]
    assert "AEGIS_M4J_APT_SOURCES_MANIFEST_SHA256" in variables[
        "m4j_required_apt_sources_manifest_sha256"
    ]
    assert variables["m4j_required_package_names"] == list(EXPECTED_PACKAGE_ENV)
    assert set(variables["m4j_required_package_versions"]) == set(EXPECTED_PACKAGE_ENV)
    for package, environment_name in EXPECTED_PACKAGE_ENV.items():
        pin = variables["m4j_required_package_versions"][package]
        assert "lookup('ansible.builtin.env'" in pin
        assert environment_name in pin

    requirements = _yaml(ANSIBLE_ROOT / "requirements.yml")
    assert requirements == {"collections": [], "roles": []}

    tasks = _tasks()
    version_guard = _task(tasks, "Reject malformed exact package-version inputs")
    guard_text = "\n".join(version_guard["ansible.builtin.assert"]["that"])
    assert "item.value == item.value | trim" in guard_text
    assert 'item.value is match("^[0-9][0-9A-Za-z.+:~_-]*$")' in guard_text
    install = _task(tasks, "Install exact base package versions")["ansible.builtin.apt"]
    assert install == {
        "name": "{{ item.key }}={{ item.value }}",
        "state": "present",
        "install_recommends": False,
        "force_apt_get": True,
        "policy_rc_d": 101,
        "fail_on_autoremove": True,
        "allow_unauthenticated": False,
        "allow_downgrade": False,
    }
    hold = _task(tasks, "Hold the exact base packages against implicit upgrades")
    assert hold["ansible.builtin.dpkg_selections"]["selection"] == "hold"
    assert hold["loop"] == "{{ m4j_required_package_names }}"
    mask = _task(tasks, "Mask Docker activation throughout package installation")
    assert mask["ansible.builtin.command"]["argv"] == [
        "/usr/bin/systemctl",
        "mask",
        "docker.service",
        "docker.socket",
    ]
    refresh = _task(tasks, "Refresh the validated Ubuntu package metadata once")
    assert tasks.index(mask) < tasks.index(refresh)

    all_yaml = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(ANSIBLE_ROOT.rglob("*.yml"))
    )
    assert "state: latest" not in all_yaml
    assert "apt_repository" not in all_yaml
    assert "community." not in all_yaml
    assert "ansible.posix" not in all_yaml


def test_service_identity_and_role_directories_are_least_privilege() -> None:
    variables = _yaml(ANSIBLE_ROOT / "group_vars" / "all.yml")
    assert variables["m4j_service_account"] == {
        "name": "aegis",
        "group": "aegis",
        "uid": 65532,
        "gid": 65532,
        "home": "/nonexistent",
        "shell": "/usr/sbin/nologin",
    }

    tasks = _tasks()
    service_user = _task(tasks, "Create the non-login Aegis service account")[
        "ansible.builtin.user"
    ]
    assert service_user["create_home"] is False
    assert service_user["password_lock"] is True
    assert service_user["groups"] == ""
    assert service_user["append"] is False
    assert "docker" not in service_user.values()

    config = _task(tasks, "Create the role-specific read-only configuration directory")[
        "ansible.builtin.file"
    ]
    assert config == {
        "path": "/etc/aegis-ot/{{ aegis_role }}",
        "state": "directory",
        "owner": "root",
        "group": "{{ m4j_service_account.group }}",
        "mode": "0750",
    }
    private = _task(tasks, "Create role-specific private state and evidence directories")
    assert private["loop"] == [
        "/var/lib/aegis-ot/state/{{ aegis_role }}",
        "/var/lib/aegis-ot/evidence/{{ aegis_role }}",
    ]
    assert private["ansible.builtin.file"]["owner"] == "{{ m4j_service_account.name }}"
    assert private["ansible.builtin.file"]["mode"] == "0700"

    marker_path = variables["m4j_vagrant_communicator_marker_path"]
    assert 'm4j_vagrant_machine ~ "/virtualbox/m4j-management-communicator"' in marker_path
    marker = _task(tasks, "Record the validated management communicator path")
    assert marker["ansible.builtin.copy"]["dest"] == (
        "{{ m4j_vagrant_communicator_marker_path }}"
    )
    assert marker["ansible.builtin.copy"]["mode"] == "0600"
    assert marker["delegate_to"] == "localhost"
    assert marker["become"] is False
    final_forwarding = _task(
        tasks,
        "Reject a final effective forwarding control that is not disabled",
    )
    assert tasks.index(final_forwarding) < tasks.index(marker)


def test_forwarding_is_disabled_in_persistent_and_effective_policy() -> None:
    policy = (FILES_ROOT / "99-aegis-ot-forwarding.conf").read_text(encoding="utf-8")
    assert "net.ipv4.ip_forward = 0" in policy
    assert "net.ipv6.conf.all.forwarding = 0" in policy
    assert "net.ipv6.conf.default.forwarding = 0" in policy

    tasks = _tasks()
    apply = _task(tasks, "Apply the forwarding-disabled kernel policy")
    assert apply["ansible.builtin.command"]["argv"] == [
        "/usr/sbin/sysctl",
        "--load",
        "/etc/sysctl.d/99-aegis-ot-forwarding.conf",
    ]
    conflicts = _task(tasks, "Reject conflicting persistent forwarding definitions")
    conflict_text = "\n".join(conflicts["ansible.builtin.assert"]["that"])
    assert "m4j_persistent_forwarding_definitions.stdout_lines | length == 3" in conflict_text
    assert "^/etc/sysctl.d/99-aegis-ot-forwarding[.]conf" in conflict_text
    read = _task(tasks, "Read final effective forwarding controls")
    assert read["loop"] == [
        "net.ipv4.ip_forward",
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
    ]
    verify = _task(tasks, "Reject a final effective forwarding control that is not disabled")
    assert 'unique | list == ["0"]' in verify["ansible.builtin.assert"]["that"][0]


def test_docker_is_unix_only_and_does_not_manage_host_forwarding() -> None:
    daemon = json.loads((FILES_ROOT / "daemon.json").read_text(encoding="utf-8"))
    assert daemon == {
        "bridge": "none",
        "icc": False,
        "ip-forward": False,
        "ip-masq": False,
        "ip6tables": False,
        "iptables": False,
        "live-restore": True,
        "userland-proxy": False,
    }
    service_override = (FILES_ROOT / "docker.service.conf").read_text(encoding="utf-8")
    socket_override = (FILES_ROOT / "docker.socket.conf").read_text(encoding="utf-8")
    assert "-H fd://" in service_override
    assert "--config-file=/etc/docker/daemon.json" in service_override
    assert "tcp://" not in service_override
    assert "ListenStream=/run/docker.sock" in socket_override
    assert "SocketMode=0600" in socket_override
    assert "SocketUser=root" in socket_override
    assert "SocketGroup=root" in socket_override

    handlers = _yaml(HANDLERS_PATH)
    assert [handler["name"] for handler in handlers] == [
        "Stop Docker before applying the restricted activation boundary",
        "Reload systemd for the restricted Docker units",
        "Unmask the restricted Docker units",
        "Restart the restricted local Docker socket",
        "Start Docker through the restricted local socket",
    ]
    assert all(handler["listen"] == "Reconfigure restricted Docker" for handler in handlers)

    verify = _task(_tasks(), "Reject Docker TCP exposure or an unexpected local socket")
    verify_text = "\n".join(verify["ansible.builtin.assert"]["that"])
    assert '"tcp://" not in m4j_docker_exec_start.stdout' in verify_text
    assert '"dockerd" not in m4j_tcp_listeners.stdout' in verify_text
    assert "m4j_docker_default_bridge.rc != 0" in verify_text
    assert '"/run/docker.sock" in m4j_docker_socket_listen.stdout' in verify_text
    assert "m4j_docker_socket.stat.issock" in verify_text
    assert 'm4j_docker_socket.stat.mode == "0600"' in verify_text


def test_ufw_has_one_user_defined_management_ssh_allowance_and_denies_forwarding() -> None:
    tasks = _tasks()
    locate = _task(tasks, "Locate the authoritative management interface")
    assert locate["ansible.builtin.command"]["argv"][-2:] == [
        "to",
        "{{ ansible_host }}/32",
    ]

    convergence = _task(tasks, "Converge UFW with an emergency default-deny recovery path")
    assert convergence["rescue"][-1]["ansible.builtin.fail"]
    defaults = _task(tasks, "Establish default-deny UFW policy")["loop"]
    assert defaults == [
        ["/usr/sbin/ufw", "default", "deny", "incoming"],
        ["/usr/sbin/ufw", "default", "allow", "outgoing"],
        ["/usr/sbin/ufw", "default", "deny", "routed"],
    ]
    allow = _task(
        tasks,
        "Permit SSH only on the management interface address and subnet",
    )["ansible.builtin.command"]["argv"]
    assert allow == [
        "/usr/sbin/ufw",
        "allow",
        "in",
        "on",
        "{{ m4j_management_interface }}",
        "from",
        "{{ m4j_topology.networks.management.cidr }}",
        "to",
        "{{ ansible_host }}",
        "port",
        "22",
        "proto",
        "tcp",
        "comment",
        "Aegis-M4j-management-SSH",
    ]
    enable = _task(
        tasks,
        "Enable UFW after installing the bounded management allowance",
    )
    assert convergence["block"].index(
        _task(tasks, "Permit SSH only on the management interface address and subnet")
    ) < convergence["block"].index(enable)
    emergency_allow = _task(tasks, "Restore management SSH during emergency recovery")
    emergency_enable = _task(
        tasks,
        "Re-enable UFW after restoring emergency management SSH",
    )
    assert convergence["rescue"].index(emergency_allow) < convergence["rescue"].index(
        emergency_enable
    )
    verify = _task(
        tasks,
        "Reject firewall drift or any additional user-defined inbound allowance",
    )
    verify_text = "\n".join(verify["ansible.builtin.assert"]["that"])
    assert 'select("search", "ALLOW IN") | list | length == 1' in verify_text
    assert '"22/tcp on " + m4j_management_interface' in verify_text
    assert "ansible_host in m4j_ufw_rules.stdout" in verify_text
    assert "m4j_topology.networks.management.cidr" in verify_text


def test_all_ansible_yaml_is_well_formed() -> None:
    yaml_paths = sorted(ANSIBLE_ROOT.rglob("*.yml"))
    assert yaml_paths
    for path in yaml_paths:
        assert _yaml(path) is not None
