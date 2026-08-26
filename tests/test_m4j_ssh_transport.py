from __future__ import annotations

import base64
import hashlib
import importlib.util
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("management", "trust", "agents", "gateway", "ot", "simulation")
ADDRESSES = {
    "management": "192.168.56.10",
    "trust": "192.168.56.11",
    "agents": "192.168.56.12",
    "gateway": "192.168.56.13",
    "ot": "192.168.56.14",
    "simulation": "192.168.56.15",
}
SOURCE_COMMIT = "a" * 40


def _git(*arguments: str, text: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(  # noqa: S603 - fixed /usr/bin/git in private test repositories
        ("/usr/bin/git", *arguments),
        check=True,
        capture_output=text,
        text=text,
    )


def _load_script(name: str) -> ModuleType:
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_test_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def transport() -> ModuleType:
    return _load_script("prepare_m4j_ssh_transport")


def _host_key(index: int) -> bytes:
    algorithm = b"ssh-ed25519"
    decoded = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + (32).to_bytes(4, "big")
        + bytes([index]) * 32
    )
    return f"ssh-ed25519 {base64.b64encode(decoded).decode('ascii')}\n".encode("ascii")


def _private_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _marker(role: str, host_key: bytes) -> bytes:
    return (
        "aegis-ot-m4j-management-communicator-v2\n"
        f"role={role}\n"
        f"address={ADDRESSES[role]}\n"
        f"host_key_sha256={hashlib.sha256(host_key).hexdigest()}\n"
    ).encode("ascii")


def _write_private(path: Path, material: bytes) -> None:
    path.write_bytes(material)
    path.chmod(0o600)


def _fixture_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "checkout"
    topology = checkout / "infra" / "m4j" / "topology.yml"
    topology.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "infra" / "m4j" / "topology.yml", topology)
    machines = checkout / ".vagrant" / "machines"
    for index, role in enumerate(ROLES, start=1):
        machine = machines / role / "virtualbox"
        machine.mkdir(parents=True)
        host_key = _host_key(index)
        _write_private(machine / "private_key", _private_key())
        _write_private(machine / "m4j-ssh-host-ed25519.pub", host_key)
        _write_private(machine / "m4j-management-communicator", _marker(role, host_key))
    return checkout


def _output(tmp_path: Path) -> Path:
    parent = tmp_path / "private-output"
    parent.mkdir(mode=0o700)
    return parent / "transport"


def test_prepared_transport_is_accepted_by_deployment_and_acceptance_consumers(
    transport: ModuleType,
    tmp_path: Path,
) -> None:
    checkout = _fixture_checkout(tmp_path)
    output = _output(tmp_path)

    result = transport.prepare_transport(
        output,
        root=checkout,
        source_commit=SOURCE_COMMIT,
    )

    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / "ssh_config").stat().st_mode) == 0o600
    assert stat.S_IMODE((output / "known_hosts").stat().st_mode) == 0o600
    assert result["source_git_commit"] == SOURCE_COMMIT
    assert result["known_hosts"]["distinct_host_key_count"] == 6
    assert result["trust_boundary"] == (
        "local_vagrant_provisioning_channel_not_independent_or_production_host_identity"
    )

    acceptance = _load_script("run_m4j_acceptance")
    config_material, roles, config_evidence = acceptance._parse_ssh_config(
        output / "ssh_config"
    )
    known_hosts_material, known_hosts_evidence = acceptance._validate_known_hosts(
        output / "known_hosts"
    )
    assert config_material == (output / "ssh_config").read_bytes()
    assert tuple(roles) == ROLES
    assert len(set(config_evidence["identity_sha256"].values())) == 6
    assert known_hosts_material == (output / "known_hosts").read_bytes()
    assert known_hosts_evidence["distinct_host_key_count"] == 6

    deployer = _load_script("deploy_m4j_workloads")
    deployed_material, deployed_digest = deployer._validate_known_hosts(
        output / "known_hosts"
    )
    assert deployed_material == known_hosts_material
    assert deployed_digest == known_hosts_evidence["sha256"]


def test_transport_refuses_to_overwrite_an_existing_output(
    transport: ModuleType,
    tmp_path: Path,
) -> None:
    checkout = _fixture_checkout(tmp_path)
    output = _output(tmp_path)
    output.mkdir(mode=0o700)

    with pytest.raises(transport.TransportPreparationError, match="refusing to overwrite"):
        transport.prepare_transport(output, root=checkout, source_commit=SOURCE_COMMIT)


@pytest.mark.parametrize(
    "mutation",
    ["host_symlink", "duplicate_host_key", "stale_marker", "identity_mode", "topology_address"],
)
def test_transport_rejects_vagrant_state_or_topology_drift(
    transport: ModuleType,
    tmp_path: Path,
    mutation: str,
) -> None:
    checkout = _fixture_checkout(tmp_path)
    management = checkout / ".vagrant" / "machines" / "management" / "virtualbox"
    trust = checkout / ".vagrant" / "machines" / "trust" / "virtualbox"
    if mutation == "host_symlink":
        path = management / "m4j-ssh-host-ed25519.pub"
        material = path.read_bytes()
        path.unlink()
        target = checkout / "host-key-target"
        _write_private(target, material)
        path.symlink_to(target)
    elif mutation == "duplicate_host_key":
        material = (management / "m4j-ssh-host-ed25519.pub").read_bytes()
        _write_private(trust / "m4j-ssh-host-ed25519.pub", material)
        _write_private(trust / "m4j-management-communicator", _marker("trust", material))
    elif mutation == "stale_marker":
        _write_private(management / "m4j-management-communicator", b"stale\n")
    elif mutation == "identity_mode":
        (management / "private_key").chmod(0o644)
    else:
        topology_path = checkout / "infra" / "m4j" / "topology.yml"
        topology: dict[str, Any] = yaml.safe_load(topology_path.read_text(encoding="utf-8"))
        topology["nodes"]["management"]["interfaces"]["management"] = "192.168.56.99"
        topology_path.write_text(yaml.safe_dump(topology, sort_keys=False), encoding="utf-8")

    with pytest.raises(transport.TransportPreparationError):
        transport.prepare_transport(
            _output(tmp_path),
            root=checkout,
            source_commit=SOURCE_COMMIT,
        )


def test_provisioning_exports_and_binds_host_keys_without_overwrite() -> None:
    tasks_path = ROOT / "infra" / "ansible" / "roles" / "m4j_base" / "tasks" / "main.yml"
    tasks = yaml.safe_load(tasks_path.read_text(encoding="utf-8"))
    by_name = {task["name"]: task for task in tasks}

    read_guest = by_name[
        "Read the guest Ed25519 SSH host public key through the provisioning channel"
    ]
    assert read_guest["ansible.builtin.slurp"]["src"] == (
        "/etc/ssh/ssh_host_ed25519_key.pub"
    )
    export = by_name["Export the guest SSH host key to a new private controller file"]
    assert export["delegate_to"] == "localhost"
    assert export["become"] is False
    assert export["ansible.builtin.copy"]["mode"] == "0600"
    assert export["ansible.builtin.copy"]["force"] is False
    assert export["ansible.builtin.copy"]["follow"] is False
    marker = by_name["Construct the host-key-bound management communicator marker"]
    assert "aegis-ot-m4j-management-communicator-v2" in marker[
        "ansible.builtin.set_fact"
    ]["m4j_controller_communicator_marker_material"]
    assert "host_key_sha256=" in marker["ansible.builtin.set_fact"][
        "m4j_controller_communicator_marker_material"
    ]

    vagrant = (ROOT / "Vagrantfile").read_text(encoding="utf-8")
    assert 'HOST_KEY_EVIDENCE_NAME = "m4j-ssh-host-ed25519.pub"' in vagrant
    assert "Base64.strict_decode64" in vagrant
    assert "Digest::SHA256.hexdigest(host_key)" in vagrant


def test_transport_source_binding_ignores_replace_refs_and_ambient_git_redirects(
    transport: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    script = checkout / "scripts" / "prepare_m4j_ssh_transport.py"
    script.parent.mkdir(parents=True)
    _git("init", "-q", str(checkout))
    script.write_text("SAFE\n", encoding="ascii")
    _git("-C", str(checkout), "add", "scripts/prepare_m4j_ssh_transport.py")
    commit_args = (
        "-C",
        str(checkout),
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-q",
        "-m",
    )
    _git(*commit_args, "safe")
    safe_commit = _git("-C", str(checkout), "rev-parse", "HEAD", text=True).stdout.strip()
    script.write_text("MALICIOUS\n", encoding="ascii")
    _git("-C", str(checkout), "add", "scripts/prepare_m4j_ssh_transport.py")
    _git(*commit_args, "malicious")
    malicious_commit = _git(
        "-C", str(checkout), "rev-parse", "HEAD", text=True
    ).stdout.strip()
    _git("-C", str(checkout), "reset", "--hard", "-q", safe_commit)
    _git("-C", str(checkout), "replace", safe_commit, malicious_commit)
    _git("-C", str(checkout), "reset", "--hard", "-q", safe_commit)
    assert script.read_text(encoding="ascii") == "MALICIOUS\n"
    redirect = tmp_path / "redirect.git"
    _git("init", "-q", "--bare", str(redirect))
    monkeypatch.setenv("GIT_DIR", str(redirect))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "attacker-config"))
    monkeypatch.setattr(
        transport,
        "SOURCE_BOUND_PATHS",
        ("scripts/prepare_m4j_ssh_transport.py",),
    )

    with pytest.raises(transport.TransportPreparationError, match="differs from HEAD"):
        transport._resolve_clean_head(checkout, "HEAD")
