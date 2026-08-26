from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import sys
import zlib
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_ot import m4g_probe

ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "a" * 40
APPLICATION_IMAGE_ID = "sha256:" + "b" * 64
HOST_PLAN_SHA256 = "c" * 64


def _evidence_key_paths(tmp_path: Path) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "controller-evidence.private"
    public_path = tmp_path / "controller-evidence.public"
    private_path.write_bytes(private_key.private_bytes_raw())
    public_path.write_bytes(private_key.public_key().public_bytes_raw())
    private_path.chmod(0o600)
    public_path.chmod(0o600)
    return private_path, public_path


def _known_hosts_path(tmp_path: Path) -> Path:
    algorithm = b"ssh-ed25519"
    prefix = len(algorithm).to_bytes(4, "big") + algorithm + (32).to_bytes(4, "big")
    lines = []
    for index, (role, address) in enumerate(
        {
            "management": "192.168.56.10",
            "trust": "192.168.56.11",
            "agents": "192.168.56.12",
            "gateway": "192.168.56.13",
            "ot": "192.168.56.14",
            "simulation": "192.168.56.15",
        }.items()
    ):
        encoded = base64.b64encode(prefix + bytes([index + 1]) * 32).decode()
        lines.append(f"{role},{address} ssh-ed25519 {encoded}")
    path = tmp_path / "known_hosts"
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    path.chmod(0o600)
    return path


def _fake_ansible_runtime(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "ansible-playbook"
    path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    path.chmod(0o700)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _load_script(name: str) -> ModuleType:
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_test_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def compiler() -> ModuleType:
    return _load_script("validate_m4j_workloads")


@pytest.fixture(scope="module")
def deployer() -> ModuleType:
    return _load_script("deploy_m4j_workloads")


@pytest.fixture(scope="module")
def reconciler() -> ModuleType:
    return _load_script("reconcile_m4j_spire_entries")


@pytest.fixture(scope="module")
def firewall_reconciler() -> ModuleType:
    return _load_script("reconcile_m4j_ufw_rules")


@pytest.fixture(scope="module")
def token_revoker() -> ModuleType:
    return _load_script("revoke_m4j_spire_join_token")


@pytest.fixture(scope="module")
def probe_runner() -> ModuleType:
    return _load_script("run_m4j_workload_probe")


def _workload_document() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "infra" / "m4j" / "workloads.yml").read_text())


def _write_workload(tmp_path: Path, workload: dict[str, Any]) -> Path:
    path = tmp_path / "workloads.yml"
    path.write_text(yaml.safe_dump(workload, sort_keys=False), encoding="utf-8")
    return path


def _validate_mutation(
    compiler: ModuleType,
    tmp_path: Path,
    workload: dict[str, Any],
) -> None:
    compiler._validate_contract(
        _write_workload(tmp_path, workload),
        compiler.DEFAULT_DEPLOYMENT,
        compiler.DEFAULT_TOPOLOGY,
    )


def test_contract_rejects_duplicate_yaml_keys(
    compiler: ModuleType,
    tmp_path: Path,
) -> None:
    source = (ROOT / "infra" / "m4j" / "workloads.yml").read_text(encoding="utf-8")
    unique = "      AEGIS_PLANT_URL: https://plant.m4j.internal:8084\n"
    assert source.count(unique) == 3
    path = tmp_path / "duplicate.yml"
    path.write_text(source.replace(unique, unique * 2, 1), encoding="utf-8")

    with pytest.raises(compiler.WorkloadContractError, match="duplicate YAML"):
        compiler._validate_contract(
            path,
            compiler.DEFAULT_DEPLOYMENT,
            compiler.DEFAULT_TOPOLOGY,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("secret_files", "../agent.private"),
        ("secret_files", "workload_authority.private"),
        ("identity_files", "../authority.public"),
        ("identity_files", "workload_authority.private"),
    ],
)
def test_contract_rejects_secret_traversal_or_authority_private_delivery(
    compiler: ModuleType,
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    workload = _workload_document()
    workload["services"]["agent-probe"][field].append(value)

    with pytest.raises(compiler.WorkloadContractError, match="input is outside"):
        _validate_mutation(compiler, tmp_path, workload)


@pytest.mark.parametrize("mutation", ["peer_map", "client_allowlist"])
def test_contract_rejects_broadened_spiffe_peer_or_client_mapping(
    compiler: ModuleType,
    tmp_path: Path,
    mutation: str,
) -> None:
    workload = _workload_document()
    if mutation == "peer_map":
        workload["services"]["agent-probe"]["environment"][
            "AEGIS_SPIFFE_PEER_IDS"
        ] = json.dumps(
            {
                "segmented-gateway.m4j.internal": (
                    "spiffe://aegis-ot.m4g.local/workload/gateway"
                ),
                "observer": "spiffe://aegis-ot.m4g.local/workload/observer",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    else:
        workload["services"]["segmented-gateway"]["command"].extend(
            [
                "--allowed-client-spiffe-id",
                "spiffe://aegis-ot.m4g.local/workload/observer",
            ]
        )

    with pytest.raises(compiler.WorkloadContractError, match="SPIRE mTLS"):
        _validate_mutation(compiler, tmp_path, workload)


@pytest.mark.parametrize("service", ["agent-probe", "segmented-gateway"])
@pytest.mark.parametrize("value", [None, "agent:other-operator"])
def test_contract_rejects_missing_or_mismatched_agent_actor_binding(
    compiler: ModuleType,
    tmp_path: Path,
    service: str,
    value: str | None,
) -> None:
    workload = _workload_document()
    environment = workload["services"][service]["environment"]
    if value is None:
        environment.pop("AEGIS_AGENT_ACTOR_ID")
    else:
        environment["AEGIS_AGENT_ACTOR_ID"] = value

    with pytest.raises(compiler.WorkloadContractError, match="SPIRE mTLS"):
        _validate_mutation(compiler, tmp_path, workload)


def test_inventory_is_source_bound_and_ansible_environment_is_closed(
    deployer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert "infra/ansible/inventory.ini" in deployer.SOURCE_BOUND_PATHS
    assert "infra/ansible/ansible.cfg" in deployer.SOURCE_BOUND_PATHS
    assert "infra/ansible/probe.yml" in deployer.SOURCE_BOUND_PATHS
    assert "scripts/build_m4j_bundle.py" in deployer.SOURCE_BOUND_PATHS
    assert "scripts/prepare_m4j_ssh_transport.py" in deployer.SOURCE_BOUND_PATHS
    assert "scripts/run_m4j_workload_probe.py" in deployer.SOURCE_BOUND_PATHS
    assert "scripts/reconcile_m4j_ufw_rules.py" in deployer.SOURCE_BOUND_PATHS
    assert "scripts/revoke_m4j_spire_join_token.py" in deployer.SOURCE_BOUND_PATHS
    playbook = (ROOT / "infra" / "ansible" / "workloads.yml").read_text()
    assert "hostvars[item].ansible_host" in playbook
    assert "groups[item] == [item]" in playbook

    inputs = [tmp_path / name for name in ("bundle", "runtime", "secrets")]
    for path in inputs:
        path.mkdir(mode=0o700)
    monkeypatch.setenv("ANSIBLE_CONFIG", "/unsafe/ansible.cfg")
    monkeypatch.setenv("ANSIBLE_INVENTORY", "/unsafe/inventory")
    monkeypatch.setenv("PYTHONHOME", "/unsafe/python")
    monkeypatch.setenv("PYTHONPATH", "/unsafe/modules")
    monkeypatch.setenv("ANSIBLE_ACTION_PLUGINS", "/unsafe/plugins")
    monkeypatch.setenv("PATH", "/unsafe/path")
    monkeypatch.setattr(deployer, "_require_plan_inputs_unchanged", lambda **_: None)
    runtime, runtime_sha256 = _fake_ansible_runtime(tmp_path)
    monkeypatch.setattr(
        deployer,
        "_validate_ansible_runtime",
        lambda *_args, **_kwargs: runtime,
    )
    captured: dict[str, Any] = {}

    def run(argv: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        captured.update(argv=argv, **kwargs)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(deployer.subprocess, "run", run)
    caller_known_hosts = _known_hosts_path(tmp_path)
    expected_plans = {role: {"role": role} for role in deployer.ROLES}
    with deployer._stable_known_hosts(caller_known_hosts) as (
        stable_known_hosts,
        known_hosts_sha256,
    ), deployer._stable_plan_file(SOURCE_COMMIT, expected_plans) as (
        stable_plan_file,
        stable_plan_file_sha256,
    ):
        assert oct(stable_known_hosts.parent.stat().st_mode & 0o777) == "0o700"
        assert oct(stable_known_hosts.stat().st_mode & 0o777) == "0o600"
        caller_known_hosts.write_text("caller path replaced\n", encoding="ascii")
        caller_known_hosts.chmod(0o600)
        deployer._apply(
            source_commit=SOURCE_COMMIT,
            bundle_directory=inputs[0],
            runtime_image_directory=inputs[1],
            secret_directory=inputs[2],
            expected_plans=expected_plans,
            plan_file=stable_plan_file,
            expected_plan_file_sha256=stable_plan_file_sha256,
            known_hosts_file=stable_known_hosts,
            ansible_playbook=runtime,
            expected_ansible_playbook_sha256=runtime_sha256,
            orchestration_root=ROOT,
            expected_known_hosts_sha256=known_hosts_sha256,
        )
        stable_path = stable_known_hosts
    assert not stable_path.parent.exists()

    environment = captured["env"]
    assert environment["ANSIBLE_CONFIG"] == str(
        ROOT / "infra" / "ansible" / "ansible.cfg"
    )
    assert environment["ANSIBLE_HOST_KEY_CHECKING"] == "True"
    assert environment["ANSIBLE_SSH_COMMON_ARGS"] == (
        "-F /dev/null -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes "
        f"-o UserKnownHostsFile={stable_path} "
        "-o GlobalKnownHostsFile=/dev/null"
    )
    assert environment["ANSIBLE_SSH_EXECUTABLE"] == "/usr/bin/ssh"
    assert environment["PATH"] == "/usr/bin:/bin"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONSAFEPATH"] == "1"
    assert environment["ANSIBLE_INVENTORY_ENABLED"] == "ini"
    assert environment["ANSIBLE_COLLECTIONS_PATH"] != "/unsafe/plugins"
    plugin_paths = {
        value
        for name, value in environment.items()
        if name.startswith("ANSIBLE_") and name.endswith("_PLUGINS")
    }
    assert len(plugin_paths) == 1
    assert "PYTHONHOME" not in environment
    assert "PYTHONPATH" not in environment
    assert "/unsafe" not in "\n".join(environment.values())
    assert environment["AEGIS_M4J_PLAN_FILE"] == str(stable_plan_file.resolve())
    assert environment["AEGIS_M4J_PLAN_FILE_SHA256"] == stable_plan_file_sha256
    assert environment["AEGIS_M4J_HOST_PLAN_SEMANTIC_SHA256"] == hashlib.sha256(
        deployer._canonical_bytes(expected_plans)
    ).hexdigest()
    assert captured["argv"][-2:] == (
        str(ROOT / "infra" / "ansible" / "inventory.ini"),
        str(ROOT / "infra" / "ansible" / "workloads.yml"),
    )


def test_deployer_rejects_host_trust_change_during_apply(
    deployer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = [tmp_path / name for name in ("bundle", "runtime", "secrets")]
    for path in inputs:
        path.mkdir(mode=0o700)
    monkeypatch.setattr(deployer, "_require_plan_inputs_unchanged", lambda **_: None)
    runtime, runtime_sha256 = _fake_ansible_runtime(tmp_path)
    monkeypatch.setattr(
        deployer,
        "_validate_ansible_runtime",
        lambda *_args, **_kwargs: runtime,
    )
    caller_known_hosts = _known_hosts_path(tmp_path)
    expected_plans = {role: {"role": role} for role in deployer.ROLES}
    with deployer._stable_known_hosts(caller_known_hosts) as (
        stable_known_hosts,
        known_hosts_sha256,
    ), deployer._stable_plan_file(SOURCE_COMMIT, expected_plans) as (
        stable_plan_file,
        stable_plan_file_sha256,
    ):
        original_lines = stable_known_hosts.read_text(encoding="ascii").splitlines()
        fields = original_lines[0].split(" ")
        key = bytearray(base64.b64decode(fields[2]))
        key[-1] ^= 0x7F
        original_lines[0] = f"{fields[0]} {fields[1]} {base64.b64encode(key).decode()}"
        changed = "\n".join(original_lines) + "\n"

        def run(_argv: tuple[str, ...], **_kwargs: Any) -> SimpleNamespace:
            stable_known_hosts.write_text(changed, encoding="ascii")
            stable_known_hosts.chmod(0o600)
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(deployer.subprocess, "run", run)
        with pytest.raises(deployer.DeploymentError, match="changed during"):
            deployer._apply(
                source_commit=SOURCE_COMMIT,
                bundle_directory=inputs[0],
                runtime_image_directory=inputs[1],
                secret_directory=inputs[2],
                expected_plans=expected_plans,
                plan_file=stable_plan_file,
                expected_plan_file_sha256=stable_plan_file_sha256,
                known_hosts_file=stable_known_hosts,
                ansible_playbook=runtime,
                expected_ansible_playbook_sha256=runtime_sha256,
                orchestration_root=ROOT,
                expected_known_hosts_sha256=known_hosts_sha256,
            )


def test_deployer_uses_one_immutable_plan_and_rejects_valid_input_swap(
    deployer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = [tmp_path / name for name in ("bundle", "runtime", "secrets")]
    for path in inputs:
        path.mkdir(mode=0o700)
    expected_plans = {role: {"role": role, "generation": 1} for role in deployer.ROLES}
    changed_plans = {role: {"role": role, "generation": 2} for role in deployer.ROLES}
    observed = expected_plans

    def require_unchanged(**kwargs: Any) -> None:
        if deployer._canonical_bytes(observed) != deployer._canonical_bytes(
            kwargs["expected_plans"]
        ):
            raise deployer.DeploymentError("deployment inputs changed")

    def run(_argv: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        nonlocal observed
        plan_path = Path(kwargs["env"]["AEGIS_M4J_PLAN_FILE"])
        document = json.loads(plan_path.read_text(encoding="utf-8"))
        assert document["plans"] == expected_plans
        observed = changed_plans
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(deployer, "_require_plan_inputs_unchanged", require_unchanged)
    runtime, runtime_sha256 = _fake_ansible_runtime(tmp_path)
    monkeypatch.setattr(
        deployer,
        "_validate_ansible_runtime",
        lambda *_args, **_kwargs: runtime,
    )
    monkeypatch.setattr(deployer.subprocess, "run", run)
    known_hosts = _known_hosts_path(tmp_path)
    with deployer._stable_known_hosts(known_hosts) as (
        stable_known_hosts,
        known_hosts_sha256,
    ), deployer._stable_plan_file(SOURCE_COMMIT, expected_plans) as (
        stable_plan_file,
        stable_plan_file_sha256,
    ):
        with pytest.raises(deployer.DeploymentError, match="inputs changed"):
            deployer._apply(
                source_commit=SOURCE_COMMIT,
                bundle_directory=inputs[0],
                runtime_image_directory=inputs[1],
                secret_directory=inputs[2],
                expected_plans=expected_plans,
                plan_file=stable_plan_file,
                expected_plan_file_sha256=stable_plan_file_sha256,
                known_hosts_file=stable_known_hosts,
                ansible_playbook=runtime,
                expected_ansible_playbook_sha256=runtime_sha256,
                orchestration_root=ROOT,
                expected_known_hosts_sha256=known_hosts_sha256,
            )


def test_deployer_rejects_untracked_ansible_auto_load_inputs(
    deployer: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        deployer,
        "_run_git",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="?? infra/ansible/group_vars/trust.yml\0",
            returncode=0,
        ),
    )

    with pytest.raises(deployer.DeploymentError, match="completely clean"):
        deployer._require_clean_checkout()


@pytest.mark.parametrize(
    "ignored_path",
    (
        "scripts/__pycache__/validate_m4j_workloads.cpython-314.pyc",
        "src/aegis_ot/__pycache__/workload_identity.cpython-314.pyc",
        "infra/ansible/filter_plugins/ignored_override.py",
        "infra/ansible/collections/ansible_collections/example/action.py",
    ),
)
def test_deployer_rejects_ignored_executable_and_ansible_autoload_artifacts(
    deployer: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    ignored_path: str,
) -> None:
    def run_git(*arguments: str, **_kwargs: Any) -> SimpleNamespace:
        output = "" if arguments[0] == "status" else ignored_path + "\0"
        return SimpleNamespace(stdout=output, returncode=0)

    monkeypatch.setattr(deployer, "_run_git", run_git)

    with pytest.raises(deployer.DeploymentError, match="ignored executable"):
        deployer._require_clean_checkout()


def test_deployer_dynamic_source_load_does_not_create_ignored_bytecode(
    deployer: ModuleType,
) -> None:
    before = {path.resolve() for path in ROOT.rglob("*.pyc")}
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = False
    try:
        loaded = deployer._load_compiler()
    finally:
        sys.dont_write_bytecode = previous

    assert loaded.ROOT == ROOT
    assert {path.resolve() for path in ROOT.rglob("*.pyc")} == before


def test_deployer_project_imports_ignore_an_earlier_foreign_pythonpath(
    deployer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foreign = tmp_path / "foreign"
    package = foreign / "aegis_ot"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        'raise RuntimeError("foreign aegis_ot package executed")\n', encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(foreign))
    saved = {
        name: module
        for name, module in tuple(sys.modules.items())
        if name == "aegis_ot" or name.startswith("aegis_ot.")
    }
    for name in saved:
        sys.modules.pop(name, None)
    try:
        deployer._load_compiler()
        loaded_package = sys.modules["aegis_ot"]
        assert deployer._is_within(Path(loaded_package.__file__), ROOT / "src")
    finally:
        for name in tuple(sys.modules):
            if name == "aegis_ot" or name.startswith("aegis_ot."):
                sys.modules.pop(name, None)
        sys.modules.update(saved)


def test_deployer_git_runner_disables_config_execution_and_external_objects(
    deployer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    git_directory = tmp_path / ".git"
    git_directory.mkdir()
    monkeypatch.setattr(deployer, "ROOT", tmp_path)
    monkeypatch.setattr(deployer, "_require_closed_git_topology", lambda: git_directory)
    captured: dict[str, Any] = {}

    def run(argv: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        captured.update(argv=argv, **kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(deployer.subprocess, "run", run)
    deployer._run_git("status", "--porcelain=v1")

    argv = captured["argv"]
    assert argv[0] == "/usr/bin/git"
    assert "--no-replace-objects" in argv
    assert "core.fsmonitor=false" in argv
    assert "core.hooksPath=/dev/null" in argv
    assert captured["env"] == {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def test_deployer_rejects_assume_unchanged_source_and_snapshots_head_blobs(
    deployer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        ("/usr/bin/git", "init", "-q", str(tmp_path)), check=True
    )
    helper = tmp_path / "helper.py"
    helper.write_text("trusted = True\n", encoding="utf-8")
    subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        ("/usr/bin/git", "-C", str(tmp_path), "add", "helper.py"),
        check=True,
    )
    subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        (
            "/usr/bin/git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ),
        check=True,
    )
    commit = subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        ("/usr/bin/git", "-C", str(tmp_path), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        (
            "/usr/bin/git",
            "-C",
            str(tmp_path),
            "update-index",
            "--assume-unchanged",
            "helper.py",
        ),
        check=True,
    )
    helper.write_text("forged = True\n", encoding="utf-8")
    assert (
        subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
            ("/usr/bin/git", "-C", str(tmp_path), "status", "--porcelain"),
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        == ""
    )
    monkeypatch.setattr(deployer, "ROOT", tmp_path)
    monkeypatch.setattr(deployer, "SOURCE_BOUND_PATHS", ("helper.py",))
    with pytest.raises(deployer.DeploymentError, match="bytes differ from HEAD"):
        deployer._require_exact_orchestrator_source(commit)

    helper.write_text("trusted = True\n", encoding="utf-8")
    with deployer._stable_head_source(commit) as snapshot:
        assert (snapshot / "helper.py").read_text(encoding="utf-8") == "trusted = True\n"


def test_deployer_rejects_corrupt_head_blob_even_when_worktree_matches(
    deployer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        ("/usr/bin/git", "init", "-q", str(tmp_path)), check=True
    )
    helper = tmp_path / "helper.py"
    trusted = b'print("SAFE")\n'
    malicious = b'print("PWN!")\n'
    assert len(trusted) == len(malicious)
    helper.write_bytes(trusted)
    subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        ("/usr/bin/git", "-C", str(tmp_path), "add", "helper.py"),
        check=True,
    )
    subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        (
            "/usr/bin/git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ),
        check=True,
    )
    commit = subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        ("/usr/bin/git", "-C", str(tmp_path), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    object_id = subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        ("/usr/bin/git", "-C", str(tmp_path), "rev-parse", "HEAD:helper.py"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
        (
            "/usr/bin/git",
            "-C",
            str(tmp_path),
            "update-index",
            "--assume-unchanged",
            "helper.py",
        ),
        check=True,
    )
    helper.write_bytes(malicious)
    loose_object = tmp_path / ".git" / "objects" / object_id[:2] / object_id[2:]
    loose_object.chmod(0o600)
    loose_object.write_bytes(
        zlib.compress(f"blob {len(malicious)}\0".encode("ascii") + malicious)
    )
    assert (
        subprocess.run(  # noqa: S603 - fixed trusted Git executable in a private fixture
            ("/usr/bin/git", "-C", str(tmp_path), "status", "--porcelain"),
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        == ""
    )
    monkeypatch.setattr(deployer, "ROOT", tmp_path)
    monkeypatch.setattr(deployer, "SOURCE_BOUND_PATHS", ("helper.py",))

    with pytest.raises(deployer.DeploymentError, match="Git object read failed"):
        deployer._require_exact_orchestrator_source(commit)


def test_bundle_parser_must_exist_in_exact_source_inventory(
    deployer: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        deployer,
        "SOURCE_BOUND_PATHS",
        ("scripts/build_m4j_bundle.py",),
    )
    monkeypatch.setattr(deployer, "_run_git_bytes", lambda *_args: b"")

    with pytest.raises(deployer.DeploymentError, match="absent from the exact commit"):
        deployer._head_blob_inventory(SOURCE_COMMIT)


def test_explicit_ansible_runtime_is_hash_version_and_environment_bound(
    deployer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, runtime_sha256 = _fake_ansible_runtime(tmp_path)
    known_hosts = _known_hosts_path(tmp_path)
    captured: dict[str, Any] = {}

    def run(argv: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        captured.update(argv=argv, **kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout="ansible-playbook [core 2.19.12]\n",
            stderr="",
        )

    monkeypatch.setattr(deployer.subprocess, "run", run)
    with deployer._closed_ansible_environment(
        orchestration_root=ROOT,
        known_hosts_file=known_hosts,
    ) as environment:
        assert (
            deployer._validate_ansible_runtime(runtime, runtime_sha256, environment)
            == runtime
        )
        assert captured["argv"] == (str(runtime), "--version")
        assert captured["env"] is environment
        assert captured["env"]["PATH"] == "/usr/bin:/bin"
        with pytest.raises(deployer.DeploymentError, match="SHA-256"):
            deployer._validate_ansible_runtime(runtime, "0" * 64, environment)

        def wrong_version(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
            return SimpleNamespace(
                returncode=0,
                stdout="ansible-playbook [core 2.19.11]\n",
                stderr="",
            )

        monkeypatch.setattr(deployer.subprocess, "run", wrong_version)
        with pytest.raises(deployer.DeploymentError, match="exactly 2.19.12"):
            deployer._validate_ansible_runtime(runtime, runtime_sha256, environment)


def test_private_input_snapshot_is_the_only_mutable_artifact_source(
    deployer: ModuleType,
    tmp_path: Path,
) -> None:
    inputs = []
    for name in ("bundle", "runtime", "secrets"):
        path = tmp_path / name
        path.mkdir(mode=0o700)
        artifact = path / "artifact"
        artifact.write_bytes(name.encode("ascii"))
        artifact.chmod(0o600)
        inputs.append(path)

    with deployer._stable_input_snapshot(*inputs) as snapshots:
        for source, snapshot, name in zip(
            inputs,
            snapshots,
            ("bundle", "runtime", "secrets"),
            strict=True,
        ):
            (source / "artifact").write_bytes(b"swapped")
            assert (snapshot / "artifact").read_bytes() == name.encode("ascii")
            assert snapshot != source


def test_controller_plan_hashes_the_slurped_bytes_and_canonical_plans() -> None:
    playbook = (ROOT / "infra" / "ansible" / "workloads.yml").read_text()
    assert (
        "m4j_controller_plan_content.content | b64decode | hash('sha256')"
        in playbook
    )
    assert "to_json(sort_keys=True, separators=[',', ':']" in playbook
    assert playbook.index("ansible.builtin.slurp") < playbook.index(
        "m4j_controller_plan_content.content | b64decode | hash('sha256')"
    )


def test_candidate_service_has_one_exact_python_entrypoint(
    compiler: ModuleType,
) -> None:
    workload, *_rest = compiler._validate_contract(
        ROOT / "infra" / "m4j" / "workloads.yml",
        ROOT / "infra" / "m4j" / "deployment.yml",
        ROOT / "infra" / "m4j" / "topology.yml",
    )
    assert workload["services"]["candidate"]["command"][:5] == [
        "python",
        "-m",
        "aegis_ot.spire_mtls",
        "serve",
        "--app",
    ]
    assert workload["services"]["candidate"]["command"].count("python") == 1


def test_deployer_rejects_symlinked_git_object_store(
    deployer: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    git_directory = tmp_path / ".git"
    outside = tmp_path / "outside-objects"
    git_directory.mkdir()
    outside.mkdir()
    (git_directory / "objects").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(deployer, "ROOT", tmp_path)

    with pytest.raises(deployer.DeploymentError, match="object store"):
        deployer._require_closed_git_topology()


@pytest.mark.parametrize(
    "mutation",
    ["missing_role", "wrong_address", "duplicate_key", "wrong_mode"],
)
def test_deployer_rejects_inexact_known_host_evidence(
    deployer: ModuleType,
    tmp_path: Path,
    mutation: str,
) -> None:
    path = _known_hosts_path(tmp_path)
    lines = path.read_text(encoding="ascii").splitlines()
    if mutation == "missing_role":
        lines.pop()
    elif mutation == "wrong_address":
        lines[0] = lines[0].replace("192.168.56.10", "192.168.56.99")
    elif mutation == "duplicate_key":
        first_key = lines[0].split(" ")[2]
        parts = lines[1].split(" ")
        lines[1] = f"{parts[0]} {parts[1]} {first_key}"
    else:
        path.chmod(0o644)
    if mutation != "wrong_mode":
        path.write_text("\n".join(lines) + "\n", encoding="ascii")
        path.chmod(0o600)

    with pytest.raises(deployer.DeploymentError):
        deployer._validate_known_hosts(path)


def test_deployer_disallows_probe_without_same_invocation_apply(
    deployer: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = [
        "--source-commit",
        SOURCE_COMMIT,
        "--bundle",
        str(tmp_path / "bundle"),
        "--runtime-images",
        str(tmp_path / "runtime"),
        "--secrets",
        str(tmp_path / "secrets"),
        "--probe",
        "--probe-output",
        str(tmp_path / "probe.json"),
        "--probe-signing-key",
        str(tmp_path / "signing.private"),
        "--probe-trusted-public-key",
        str(tmp_path / "signing.public"),
    ]

    assert deployer.main(arguments) == 1
    assert "--probe requires --apply" in capsys.readouterr().err
    assert "probe_existing" not in (ROOT / "scripts" / "deploy_m4j_workloads.py").read_text()


def _desired_entry() -> dict[str, Any]:
    return {
        "entry_id": "m4j-agents-agent-probe-v1",
        "parent_id": "spiffe://aegis-ot.m4g.local/agent/agents",
        "spiffe_id": "spiffe://aegis-ot.m4g.local/workload/agent-probe",
        "selectors": [
            {"type": "unix", "value": "uid:65532"},
            {"type": "unix", "value": "gid:65538"},
        ],
        "x509_svid_ttl": 300,
    }


def _write_entry(path: Path) -> None:
    document = {"entries": [_desired_entry()]}
    path.write_bytes(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )


def _observed_entry(*, entry_id: str | None = None) -> dict[str, Any]:
    desired = _desired_entry()
    return {
        "id": entry_id or desired["entry_id"],
        "parent_id": {"trust_domain": "aegis-ot.m4g.local", "path": "/agent/agents"},
        "spiffe_id": {
            "trust_domain": "aegis-ot.m4g.local",
            "path": "/workload/agent-probe",
        },
        "selectors": desired["selectors"],
        "x509_svid_ttl": 300,
        "federates_with": [],
        "admin": False,
        "downstream": False,
        "dns_names": [],
        "store_svid": False,
        "jwt_svid_ttl": 0,
        "expires_at": "0",
    }


def _completed(
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess((), returncode, stdout=stdout, stderr=stderr)


def test_reconciler_rejects_incorrect_post_update_readback(
    reconciler: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry_path = tmp_path / "entry.json"
    _write_entry(entry_path)
    wrong = _observed_entry()
    wrong["parent_id"] = {
        "trust_domain": "aegis-ot.m4g.local",
        "path": "/agent/trust",
    }
    reads = iter((wrong, wrong))
    monkeypatch.setattr(reconciler, "_read_exact", lambda _entry_id: next(reads))
    monkeypatch.setattr(reconciler, "_run", lambda *_args: _completed())

    with pytest.raises(reconciler.ReconcileError, match="after reconciliation readback"):
        reconciler.reconcile(
            entry_path,
            container_path="/etc/spire/registrations/m4j-agents-agent-probe-v1.json",
        )


def test_reconciler_does_not_treat_operational_read_failure_as_absence(
    reconciler: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reconciler,
        "_show",
        lambda _entry_id: _completed(returncode=1, stderr="permission denied"),
    )

    with pytest.raises(reconciler.ReconcileError, match="entry read failed"):
        reconciler._read_exact("m4j-agents-agent-probe-v1")


def test_registration_audit_rejects_stale_managed_entry(
    reconciler: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "registrations"
    directory.mkdir(mode=0o700)
    _write_entry(directory / "m4j-agents-agent-probe-v1.json")
    observed = [_observed_entry(), _observed_entry(entry_id="m4j-stale-entry-v1")]
    output = json.dumps(
        {"entries": observed, "next_page_token": ""},
        sort_keys=True,
        separators=(",", ":"),
    )
    monkeypatch.setattr(reconciler, "_show", lambda: _completed(stdout=output))

    with pytest.raises(reconciler.ReconcileError, match="missing or stale"):
        reconciler.audit(directory)


def test_registration_convergence_prunes_only_bounded_managed_prefix_then_audits(
    reconciler: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "registrations"
    directory.mkdir(mode=0o700)
    _write_entry(directory / "m4j-agents-agent-probe-v1.json")
    desired = _observed_entry()
    stale = _observed_entry(entry_id="m4j-stale-entry-v1")
    managed_reads = iter(
        (
            {desired["id"]: desired, stale["id"]: stale},
            {desired["id"]: desired},
        )
    )
    monkeypatch.setattr(reconciler, "_read_managed", lambda: next(managed_reads))
    monkeypatch.setattr(reconciler, "_read_exact", lambda _entry_id: None)
    commands: list[tuple[str, ...]] = []

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        commands.append(arguments)
        return _completed()

    monkeypatch.setattr(reconciler, "_run", run)
    monkeypatch.setattr(
        reconciler,
        "_reconcile_entry",
        lambda entry, *, container_path: {
            "entry_id": entry["entry_id"],
            "created": False,
            "updated": False,
            "changed": False,
        },
    )

    result = reconciler.converge(directory)

    assert commands == [("delete", "-entryID", "m4j-stale-entry-v1")]
    assert result["pruned_entry_ids"] == ["m4j-stale-entry-v1"]
    assert result["managed_entry_ids"] == ["m4j-agents-agent-probe-v1"]
    playbook = (ROOT / "infra" / "ansible" / "workloads.yml").read_text()
    assert playbook.index("--converge-directory") < playbook.index(
        "Install and activate the plant workload first"
    )
    with pytest.raises(reconciler.ReconcileError, match="deletion scope"):
        reconciler._managed_entries([{"id": "m4j-outside-contract"}])


def test_registration_reader_uses_nofollow_for_entry_material(
    reconciler: ModuleType,
    tmp_path: Path,
) -> None:
    target = tmp_path / "entry.json"
    _write_entry(target)
    link = tmp_path / "linked.json"
    link.symlink_to(target)

    with pytest.raises(reconciler.ReconcileError, match="linked"):
        reconciler._load_entry(link)


def test_ufw_reconciler_removes_same_comment_tuple_drift_and_duplicates(
    firewall_reconciler: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = {
        "rules": [
            {
                "rule_id": "management-ssh",
                "interface": "eth1",
                "source_address": "192.168.56.1",
                "destination_address": "192.168.56.10",
                "port": 22,
                "protocol": "tcp",
            }
        ],
        "status_lines": [
            "[ 1] 192.168.56.10 22/tcp on eth1 ALLOW IN 192.168.56.1 # Aegis-M4j-management-ssh",
            "[ 2] 192.168.56.10 22/tcp on eth1 ALLOW IN 0.0.0.0 # Aegis-M4j-management-ssh",
            "[ 3] 192.168.56.10 22/tcp on eth1 ALLOW IN 192.168.56.1 # Aegis-M4j-management-ssh",
        ],
    }

    def supply() -> None:
        monkeypatch.setattr(
            firewall_reconciler.sys,
            "stdin",
            SimpleNamespace(buffer=io.BytesIO(json.dumps(document).encode())),
        )

    supply()
    result = firewall_reconciler.reconcile(audit=False)
    assert result["preserved_rule_numbers"] == [1]
    assert result["stale_rule_numbers"] == [3, 2]
    assert result["exact_set"] is False
    supply()
    with pytest.raises(firewall_reconciler.FirewallReconcileError, match="non-exact"):
        firewall_reconciler.reconcile(audit=True)


def test_join_token_revoker_tolerates_consumed_state_and_verifies_absence(
    token_revoker: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_directory = tmp_path / "server"
    database_directory.mkdir(mode=0o700)
    database = database_directory / "datastore.sqlite3"
    token = "123e4567-e89b-42d3-a456-426614174000"  # noqa: S105 - synthetic token
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE join_tokens (id INTEGER PRIMARY KEY, token TEXT, expiry INTEGER)"
    )
    connection.execute(
        "INSERT INTO join_tokens (token, expiry) VALUES (?, ?)", (token, 4102444800)
    )
    connection.commit()
    connection.close()
    database.chmod(0o600)
    monkeypatch.setattr(token_revoker, "DEFAULT_DATABASE", database)

    revoked = token_revoker.revoke(database, token)
    absent = token_revoker.revoke(database, token)

    assert revoked["outcome"] == "revoked"
    assert revoked["token_present_after"] is False
    assert absent["outcome"] == "consumed_or_not_found"
    assert absent["token_present_after"] is False
    playbook = (ROOT / "infra" / "ansible" / "workloads.yml").read_text()
    assert "Revoke any unconsumed server-side join token and verify absence" in playbook
    assert playbook.index("Revoke any unconsumed server-side join token") < playbook.index(
        "Clear the in-memory join-token fact"
    )


JOIN_TOKEN = "123e4567-e89b-42d3-a456-426614174000"  # noqa: S105 - synthetic token
JOIN_TOKEN_AGENT_ID = (
    "spiffe://aegis-ot.m4g.local/spire/agent/join_token/" + JOIN_TOKEN
)
ROLE_ALIAS_ID = "spiffe://aegis-ot.m4g.local/agent/agents"
AUTO_ALIAS_ENTRY_ID = "223e4567-e89b-42d3-a456-426614174000"


def _proto_spiffe_id(spiffe_id: str) -> dict[str, str]:
    prefix = "spiffe://"
    assert spiffe_id.startswith(prefix)
    trust_domain, path = spiffe_id.removeprefix(prefix).split("/", 1)
    return {"trust_domain": trust_domain, "path": f"/{path}"}


def _join_token_agent() -> dict[str, Any]:
    return {
        "id": _proto_spiffe_id(JOIN_TOKEN_AGENT_ID),
        "attestation_type": "join_token",
        "x509_svid_serial_number": "01",
        "x509_svid_expires_at": "4102444800",
        "selectors": [{"type": "spiffe_id", "value": JOIN_TOKEN_AGENT_ID}],
        "banned": False,
        "can_reattest": False,
        "agent_version": "1.15.2",
    }


def _auto_alias_entry() -> dict[str, Any]:
    return {
        "id": AUTO_ALIAS_ENTRY_ID,
        "parent_id": _proto_spiffe_id(JOIN_TOKEN_AGENT_ID),
        "spiffe_id": _proto_spiffe_id(ROLE_ALIAS_ID),
        "selectors": [{"type": "spiffe_id", "value": JOIN_TOKEN_AGENT_ID}],
        "x509_svid_ttl": 0,
        "federates_with": [],
        "admin": False,
        "downstream": False,
        "expires_at": "0",
        "dns_names": [],
        "store_svid": False,
        "jwt_svid_ttl": 0,
        "hint": "",
    }


def _spire_json(document: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return _completed(
        stdout=json.dumps(document, sort_keys=True, separators=(",", ":"))
    )


def _token_absence_result() -> dict[str, object]:
    return {
        "outcome": "consumed_or_not_found",
        "token_present_after": False,
    }


def test_escrowed_token_generation_remains_reconcilable_after_lost_response(
    token_revoker: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt_directory = tmp_path / "attempts"
    attempt_directory.mkdir(mode=0o700)
    monkeypatch.setattr(token_revoker, "DEFAULT_ATTEMPT_DIRECTORY", attempt_directory)

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        if arguments[:2] == ("entry", "show"):
            return _spire_json({"entries": [], "next_page_token": ""})
        if arguments[:2] == ("token", "generate"):
            return _spire_json({"value": JOIN_TOKEN})
        raise AssertionError(f"unexpected SPIRE command: {arguments}")

    monkeypatch.setattr(token_revoker, "_run_spire", run)
    armed = token_revoker.arm_attempt(ROLE_ALIAS_ID)
    generated = token_revoker.generate_attempt(
        ROLE_ALIAS_ID,
        token_ttl_seconds=300,
    )
    assert armed["attempt_armed"] is True
    assert generated["value"] == JOIN_TOKEN
    assert (attempt_directory / "agents.json").is_file()

    reconciled: list[tuple[str, str, bool]] = []

    def cleanup(
        _database: Path,
        token: str,
        *,
        alias_spiffe_id: str,
        bootstrap_verified: bool,
        trust_domain: str,
    ) -> dict[str, object]:
        assert trust_domain == token_revoker.TRUST_DOMAIN
        reconciled.append((token, alias_spiffe_id, bootstrap_verified))
        return {
            "schema_version": "aegis-ot-m4j-spire-bootstrap-cleanup-v1",
            "token_outcome": "revoked",
            "token_present_after": False,
            "actual_agent_present_after": False,
            "agent_action": "already_absent",
            "alias_action": "already_absent",
            "alias_present_after": False,
            "bootstrap_outcome": "unverified",
            "token_material_returned": False,
            "identity_material_returned": False,
        }

    monkeypatch.setattr(token_revoker, "cleanup", cleanup)
    result = token_revoker.cleanup_attempt(
        tmp_path / "datastore.sqlite3",
        alias_spiffe_id=ROLE_ALIAS_ID,
        bootstrap_verified=False,
    )

    assert reconciled == [(JOIN_TOKEN, ROLE_ALIAS_ID, False)]
    assert result["attempt_outcome"] == "generated_token_reconciled"
    assert result["attempt_file_present_after"] is False
    assert not (attempt_directory / "agents.json").exists()


def test_bootstrap_arm_preserves_a_previously_verified_role_alias(
    token_revoker: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt_directory = tmp_path / "attempts"
    attempt_directory.mkdir(mode=0o700)
    monkeypatch.setattr(token_revoker, "DEFAULT_ATTEMPT_DIRECTORY", attempt_directory)
    monkeypatch.setattr(
        token_revoker,
        "_read_alias_entries",
        lambda _alias: [_auto_alias_entry()],
    )

    with pytest.raises(token_revoker.TokenRevocationError, match="existing role alias"):
        token_revoker.arm_attempt(ROLE_ALIAS_ID)

    result = token_revoker.cleanup_attempt(
        tmp_path / "datastore.sqlite3",
        alias_spiffe_id=ROLE_ALIAS_ID,
        bootstrap_verified=False,
    )
    assert result["attempt_outcome"] == "no_attempt"
    assert result["prior_identity_action"] == "preserved"
    assert list(attempt_directory.iterdir()) == []


def test_armed_attempt_without_token_is_removed_without_identity_mutation(
    token_revoker: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt_directory = tmp_path / "attempts"
    attempt_directory.mkdir(mode=0o700)
    monkeypatch.setattr(token_revoker, "DEFAULT_ATTEMPT_DIRECTORY", attempt_directory)
    monkeypatch.setattr(token_revoker, "_read_alias_entries", lambda _alias: [])
    token_revoker.arm_attempt(ROLE_ALIAS_ID)
    monkeypatch.setattr(
        token_revoker,
        "cleanup",
        lambda *_args, **_kwargs: pytest.fail("no token cleanup was expected"),
    )

    result = token_revoker.cleanup_attempt(
        tmp_path / "datastore.sqlite3",
        alias_spiffe_id=ROLE_ALIAS_ID,
        bootstrap_verified=False,
    )

    assert result["attempt_outcome"] == "no_token_generated"
    assert result["prior_identity_action"] == "preserved"
    assert not (attempt_directory / "agents.json").exists()


def test_join_token_cleanup_preserves_exact_alias_for_attested_actual_node(
    token_revoker: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(token_revoker, "revoke", lambda *_args: _token_absence_result())
    calls: list[tuple[str, ...]] = []

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        if arguments[:2] == ("agent", "list"):
            return _spire_json(
                {"agents": [_join_token_agent()], "next_page_token": ""}
            )
        if arguments[:2] == ("entry", "show"):
            return _spire_json(
                {"entries": [_auto_alias_entry()], "next_page_token": ""}
            )
        raise AssertionError(f"unexpected SPIRE command: {arguments}")

    monkeypatch.setattr(token_revoker, "_run_spire", run)

    result = token_revoker.cleanup(
        tmp_path / "datastore.sqlite3",
        JOIN_TOKEN,
        alias_spiffe_id=ROLE_ALIAS_ID,
        bootstrap_verified=True,
    )

    assert result["actual_agent_present_after"] is True
    assert result["alias_action"] == "preserved"
    assert result["alias_present_after"] is True
    assert result["identity_material_returned"] is False
    assert all(JOIN_TOKEN not in argument for call in calls for argument in call)
    assert not any(call[:2] == ("entry", "delete") for call in calls)


def test_join_token_identity_audit_rejects_boolean_counts_and_nonfinite_json(
    token_revoker: ModuleType,
) -> None:
    agent = _join_token_agent()
    agent["x509_svid_expires_at"] = True
    assert not token_revoker._agent_is_exact(agent, expected_id=JOIN_TOKEN_AGENT_ID)

    alias = _auto_alias_entry()
    alias["x509_svid_ttl"] = False
    assert not token_revoker._alias_entry_is_exact(
        alias,
        alias_spiffe_id=ROLE_ALIAS_ID,
        actual_agent_id=JOIN_TOKEN_AGENT_ID,
    )
    alias = _auto_alias_entry()
    alias["admin"] = 0
    assert not token_revoker._alias_entry_is_exact(
        alias,
        alias_spiffe_id=ROLE_ALIAS_ID,
        actual_agent_id=JOIN_TOKEN_AGENT_ID,
    )

    with pytest.raises(token_revoker.TokenRevocationError, match="forbidden SPIRE JSON"):
        token_revoker._parse_cli_object(
            _completed(stdout='{"value":NaN}'),
            operation="adversarial fixture",
        )


def test_join_token_cleanup_deletes_only_exact_alias_when_agent_is_absent(
    token_revoker: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(token_revoker, "revoke", lambda *_args: _token_absence_result())
    calls: list[tuple[str, ...]] = []
    alias_reads = iter(([_auto_alias_entry()], *([[]] * token_revoker.STABLE_ABSENCE_READS)))
    monkeypatch.setattr(token_revoker.time, "sleep", lambda _seconds: None)

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        if arguments[:2] == ("agent", "list"):
            return _spire_json({"agents": [], "next_page_token": ""})
        if arguments[:2] == ("entry", "show"):
            return _spire_json(
                {"entries": next(alias_reads), "next_page_token": ""}
            )
        if arguments[:2] == ("entry", "delete"):
            assert arguments == ("entry", "delete", "-entryID", AUTO_ALIAS_ENTRY_ID)
            return _completed()
        raise AssertionError(f"unexpected SPIRE command: {arguments}")

    monkeypatch.setattr(token_revoker, "_run_spire", run)

    result = token_revoker.cleanup(
        tmp_path / "datastore.sqlite3",
        JOIN_TOKEN,
        alias_spiffe_id=ROLE_ALIAS_ID,
        bootstrap_verified=False,
    )

    assert result["actual_agent_present_after"] is False
    assert result["alias_action"] == "deleted"
    assert result["alias_present_after"] is False
    assert calls.count(("entry", "delete", "-entryID", AUTO_ALIAS_ENTRY_ID)) == 1
    assert sum(call[:2] == ("agent", "list") for call in calls) == (
        1 + token_revoker.STABLE_ABSENCE_READS
    )
    assert all(JOIN_TOKEN not in argument for call in calls for argument in call)


def test_unverified_join_token_cleanup_evicts_late_inflight_identity(
    token_revoker: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(token_revoker, "revoke", lambda *_args: _token_absence_result())
    monkeypatch.setattr(token_revoker.time, "sleep", lambda _seconds: None)
    absent_tail = [None] * token_revoker.STABLE_ABSENCE_READS
    agent_reads = iter([None, _join_token_agent(), *absent_tail])
    alias_reads = iter([None, _auto_alias_entry(), *absent_tail])
    evicted: list[str] = []
    deleted: list[str] = []
    monkeypatch.setattr(
        token_revoker,
        "_read_exact_agent",
        lambda _actual_id: next(agent_reads),
    )
    monkeypatch.setattr(
        token_revoker,
        "_read_exact_alias",
        lambda _alias_id, **_kwargs: next(alias_reads),
    )
    monkeypatch.setattr(token_revoker, "_evict_agent", evicted.append)
    monkeypatch.setattr(token_revoker, "_delete_alias", deleted.append)

    result = token_revoker.cleanup(
        tmp_path / "datastore.sqlite3",
        JOIN_TOKEN,
        alias_spiffe_id=ROLE_ALIAS_ID,
        bootstrap_verified=False,
    )

    assert evicted == [JOIN_TOKEN_AGENT_ID]
    assert deleted == [AUTO_ALIAS_ENTRY_ID]
    assert result["agent_action"] == "evicted"
    assert result["alias_action"] == "deleted"
    assert result["actual_agent_present_after"] is False
    assert result["alias_present_after"] is False


@pytest.mark.parametrize("drift", ["ambiguous", "wrong_selector"])
def test_join_token_cleanup_rejects_unexpected_or_ambiguous_alias_entries(
    token_revoker: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    revocations: list[str] = []

    def revoke(_database: Path, token: str) -> dict[str, object]:
        revocations.append(token)
        return _token_absence_result()

    observed = _auto_alias_entry()
    if drift == "ambiguous":
        entries = [observed, {**observed, "id": "323e4567-e89b-42d3-a456-426614174000"}]
    else:
        observed["selectors"] = [{"type": "spiffe_id", "value": ROLE_ALIAS_ID}]
        entries = [observed]

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        if arguments[:2] == ("agent", "list"):
            return _spire_json({"agents": [], "next_page_token": ""})
        if arguments[:2] == ("entry", "show"):
            return _spire_json({"entries": entries, "next_page_token": ""})
        raise AssertionError(f"unexpected SPIRE command: {arguments}")

    monkeypatch.setattr(token_revoker, "revoke", revoke)
    monkeypatch.setattr(token_revoker, "_run_spire", run)

    with pytest.raises(token_revoker.TokenRevocationError, match="alias"):
        token_revoker.cleanup(
            tmp_path / "datastore.sqlite3",
            JOIN_TOKEN,
            alias_spiffe_id=ROLE_ALIAS_ID,
            bootstrap_verified=False,
        )

    assert revocations == [JOIN_TOKEN]


def test_join_token_playbook_audits_actual_identity_and_enables_alias_selector() -> None:
    playbook = (ROOT / "infra" / "ansible" / "workloads.yml").read_text()
    plays = yaml.safe_load(playbook)
    server_config = (
        ROOT
        / "infra"
        / "ansible"
        / "roles"
        / "m4j_spire_server"
        / "templates"
        / "server.conf.j2"
    ).read_text()

    assert "agent_spiffe_id_as_selector = true" in server_config
    assert "'/spire/agent/join_token/' ~ m4j_join_token" in playbook
    assert "Read the bounded join-token agent inventory before token clearing" in playbook
    assert playbook.index(
        "Read the bounded join-token agent inventory before token clearing"
    ) < playbook.index("Clear the in-memory join-token fact")
    assert "Read the configured role alias as a registration entry" in playbook
    assert "Exact-audit the role alias and its actual token-derived agent" in playbook
    assert "--alias-spiffe-id" in playbook
    assert "--bootstrap-outcome" in playbook
    assert "'verified'" in playbook and "'unverified'" in playbook
    assert "Arm one server-side role-bound bootstrap attempt" in playbook
    assert "Generate and escrow one role-bound short-lived SPIRE join token" in playbook
    assert "- cleanup-escrow" in playbook
    assert "stdin: \"{{ m4j_join_token }}\\n\"" not in playbook
    assert "when: m4j_join_token is defined" not in playbook
    assert "Reconcile retained server escrow for an already healthy exact agent" in playbook
    assert "Require retained escrow absence without changing a healthy identity" in playbook
    assert "banned is sameas false" in playbook
    assert "x509_svid_ttl | type_debug == \"int\"" in playbook
    assert "x509_svid_expires_at is string" in playbook
    former_alias_agent_show = (
        "- show\n          - -spiffeID\n"
        '          - "{{ m4j_workload_plan.node_agent.spiffe_id }}"'
    )
    assert former_alias_agent_show not in playbook

    agent_play = next(
        play
        for play in plays
        if play["name"]
        == "Configure and attest each SPIRE agent with distinct one-time material"
    )
    bootstrap = next(
        task
        for task in agent_play["tasks"]
        if task["name"] == "Bootstrap only an agent without a current healthy local identity"
    )
    cleanup_names = [task["name"] for task in bootstrap["always"]]
    assert cleanup_names == [
        "Quiesce any bootstrap attempt that did not complete exact identity audit",
        "Revoke any unconsumed server-side join token and verify absence",
        "Delete the one-time join-token file after each host attempt",
        "Delete the one-time bootstrap argument after each host attempt",
        "Clear the in-memory join-token fact after every host attempt",
        "Require every server, host, and in-memory cleanup outcome",
    ]
    for task in bootstrap["always"][:-1]:
        assert task["failed_when"] is False
    assert "when" not in bootstrap["always"][-1]
    bootstrap_names = [task["name"] for task in bootstrap["block"]]
    assert bootstrap_names.index(
        "Arm one server-side role-bound bootstrap attempt before token mutation"
    ) < bootstrap_names.index(
        "Generate and escrow one role-bound short-lived SPIRE join token on trust"
    )
    server_tasks = yaml.safe_load(
        (
            ROOT
            / "infra"
            / "ansible"
            / "roles"
            / "m4j_spire_server"
            / "tasks"
            / "main.yml"
        ).read_text()
    )
    attempt_directory = next(
        item
        for task in server_tasks
        if task["name"].startswith("Create private SPIRE server")
        for item in task["loop"]
        if item["path"] == "/run/aegis-ot/spire/bootstrap-attempts"
    )
    assert attempt_directory == {
        "path": "/run/aegis-ot/spire/bootstrap-attempts",
        "owner": "root",
        "group": "root",
        "mode": "0700",
    }


def test_workload_environment_and_registration_mount_are_runtime_readable() -> None:
    template_root = (
        ROOT
        / "infra"
        / "ansible"
        / "roles"
        / "m4j_workload_services"
        / "templates"
    )
    template = (template_root / "service.env.j2").read_text(encoding="utf-8")
    peer_map = '{"gateway.m4j.internal":"spiffe://aegis-ot.m4g.local/workload/gateway"}'
    environment = {
        "AEGIS_SPIFFE_PEER_IDS": peer_map,
        "AEGIS_SPIRE_MTLS_MODE": "required",
        "SPIFFE_ENDPOINT_SOCKET": "unix:///run/spire/agent/public/api.sock",
    }
    rendered_lines = [f"{name}={value}" for name, value in sorted(environment.items())]

    assert "{{ name }}={{ value }}" in template
    assert "to_json" not in template
    assert rendered_lines == [
        f"AEGIS_SPIFFE_PEER_IDS={peer_map}",
        "AEGIS_SPIRE_MTLS_MODE=required",
        "SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent/public/api.sock",
    ]
    server_tasks = yaml.safe_load(
        (
            ROOT
            / "infra"
            / "ansible"
            / "roles"
            / "m4j_spire_server"
            / "tasks"
            / "main.yml"
        ).read_text(encoding="utf-8")
    )
    registration_root = next(
        item
        for item in server_tasks[0]["loop"]
        if item["path"] == "/etc/aegis-ot/spire/registrations"
    )
    assert registration_root == {
        "path": "/etc/aegis-ot/spire/registrations",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    }
    server_unit = (
        ROOT
        / "infra"
        / "ansible"
        / "roles"
        / "m4j_spire_server"
        / "templates"
        / "aegis-m4j-spire-server.service.j2"
    ).read_text(encoding="utf-8")
    assert "--user 1000:1000" in server_unit
    assert (
        "src=/etc/aegis-ot/spire/registrations,"
        "dst=/etc/spire/registrations,readonly"
    ) in server_unit


def _probe_record() -> dict[str, Any]:
    return {
        "schema_version": "m4g-capability-probe-v1",
        "gateway_health": {
            "status": "ready",
            "effect_coordination_mode": "required",
            "coordination_backend": "durable-prepare-commit-query-http-v1",
            "coordination_journal_records": 1,
            "coordination_pending_effects": 0,
        },
        "nominal": {"status": "completed", "dispatch_attempts": 1},
        "exact_gateway_request_replay": {
            "status": "not_dispatched",
            "dispatch_attempts": 0,
            "reasons": [
                "observation_sequence_regressed",
                "observation_challenge_replayed",
            ],
        },
        "unsafe": {
            "status": "not_dispatched",
            "dispatch_attempts": 0,
            "reasons": ["critical_load_below_limit"],
        },
        "agent_direct_reachability": {
            "observer": False,
            "candidate": False,
            "ot-adapter": False,
            "simulation": False,
        },
    }


@pytest.mark.parametrize(
    ("section", "field", "value", "gate"),
    (
        ("gateway_health", "coordination_journal_records", True, "durable_coordination_ready"),
        ("gateway_health", "coordination_journal_records", -1, "durable_coordination_ready"),
        ("gateway_health", "coordination_pending_effects", False, "durable_coordination_ready"),
        ("gateway_health", "coordination_pending_effects", -1, "durable_coordination_ready"),
        ("nominal", "dispatch_attempts", True, "nominal_action_completed_once"),
        ("nominal", "dispatch_attempts", -1, "nominal_action_completed_once"),
        (
            "exact_gateway_request_replay",
            "dispatch_attempts",
            False,
            "exact_replay_failed_closed",
        ),
        (
            "exact_gateway_request_replay",
            "dispatch_attempts",
            -1,
            "exact_replay_failed_closed",
        ),
        ("unsafe", "dispatch_attempts", False, "unsafe_action_failed_closed"),
        ("unsafe", "dispatch_attempts", -1, "unsafe_action_failed_closed"),
    ),
)
def test_live_probe_count_gates_reject_booleans_and_negative_counts(
    probe_runner: ModuleType,
    section: str,
    field: str,
    value: object,
    gate: str,
) -> None:
    record = _probe_record()
    record[section][field] = value

    assert probe_runner._record_gates(record)[gate] is False


def test_live_probe_reuses_the_applied_exact_ssh_host_trust(
    probe_runner: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    known_hosts = _known_hosts_path(tmp_path)
    known_hosts_sha256 = hashlib.sha256(known_hosts.read_bytes()).hexdigest()
    staging = tmp_path / "staging"
    staging.mkdir(mode=0o700)
    monkeypatch.setattr(
        probe_runner.shutil,
        "which",
        lambda name: "/usr/bin/ansible-playbook" if name == "ansible-playbook" else None,
    )
    captured: dict[str, Any] = {}

    def run(argv: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        captured.update(argv=argv, **kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(probe_runner.subprocess, "run", run)
    probe_runner._execute_probe_playbook(
        source_commit=SOURCE_COMMIT,
        application_image_id=APPLICATION_IMAGE_ID,
        staging_directory=staging,
        known_hosts_file=known_hosts,
        expected_known_hosts_sha256=known_hosts_sha256,
    )

    environment = captured["env"]
    assert {
        name: value for name, value in environment.items() if name.startswith("ANSIBLE_")
    } == {
        "ANSIBLE_CONFIG": str(ROOT / "infra" / "ansible" / "ansible.cfg"),
        "ANSIBLE_HOST_KEY_CHECKING": "True",
        "ANSIBLE_SSH_COMMON_ARGS": (
            "-F /dev/null -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes "
            f"-o UserKnownHostsFile={known_hosts} "
            "-o GlobalKnownHostsFile=/dev/null"
        ),
        "ANSIBLE_SSH_EXECUTABLE": "/usr/bin/ssh",
    }
    with pytest.raises(probe_runner.WorkloadProbeError, match="differs"):
        probe_runner._execute_probe_playbook(
            source_commit=SOURCE_COMMIT,
            application_image_id=APPLICATION_IMAGE_ID,
            staging_directory=staging,
            known_hosts_file=known_hosts,
            expected_known_hosts_sha256="0" * 64,
        )


def test_live_probe_envelope_is_scoped_private_and_offline_verifiable(
    probe_runner: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _probe_record()
    material = probe_runner._canonical_bytes(record) + b"\n"

    def execute(**kwargs: Any) -> None:
        staging = kwargs["staging_directory"]
        for filename in probe_runner.PROBE_RECORD_NAMES:
            (staging / filename).write_bytes(material)

    monkeypatch.setattr(probe_runner, "_execute_probe_playbook", execute)
    output = tmp_path / "live-probe.json"
    private_key, trusted_public_key = _evidence_key_paths(tmp_path)
    known_hosts = _known_hosts_path(tmp_path)
    known_hosts_sha256 = hashlib.sha256(known_hosts.read_bytes()).hexdigest()
    envelope = probe_runner.run_live_probe(
        source_commit=SOURCE_COMMIT,
        application_image_id=APPLICATION_IMAGE_ID,
        host_plan_semantic_sha256=HOST_PLAN_SHA256,
        output_path=output,
        signing_private_key_path=private_key,
        trusted_public_key_path=trusted_public_key,
        known_hosts_file=known_hosts,
        expected_known_hosts_sha256=known_hosts_sha256,
    )

    assert oct(output.stat().st_mode & 0o777) == "0o600"
    payload = envelope["payload"]
    assert payload["probe_contract_passed"] is True
    assert payload["deployment_acceptance_established"] is False
    assert payload["g7_acceptance_established"] is False
    assert "accepted" not in payload
    assert payload["phase_semantics"]["after_bounded_restart"].endswith(
        "not_general_recovery_correctness"
    )
    assert probe_runner.verify_evidence(
        output,
        expected_source_commit=SOURCE_COMMIT,
        expected_application_image_id=APPLICATION_IMAGE_ID,
        expected_host_plan_semantic_sha256=HOST_PLAN_SHA256,
        expected_controller_known_hosts_sha256=known_hosts_sha256,
        trusted_public_key_path=trusted_public_key,
    ) == envelope
    assert probe_runner.main(
        [
            "--source-commit",
            SOURCE_COMMIT,
            "--verify",
            str(output),
            "--expect-application-image-id",
            APPLICATION_IMAGE_ID,
            "--expect-host-plan-semantic-sha256",
            HOST_PLAN_SHA256,
            "--expect-controller-known-hosts-sha256",
            known_hosts_sha256,
            "--trusted-public-key",
            str(trusted_public_key),
        ]
    ) == 0
    cli_result = json.loads(capsys.readouterr().out)
    assert cli_result["canonical_record_consistency_passed"] is True
    assert cli_result["trusted_controller_signature_valid"] is True
    assert cli_result["independent_execution_provenance_established"] is False
    assert "verified" not in cli_result

    with pytest.raises(probe_runner.WorkloadProbeError, match="bindings"):
        probe_runner.verify_evidence(
            output,
            expected_source_commit=SOURCE_COMMIT,
            expected_application_image_id="sha256:" + "d" * 64,
            expected_host_plan_semantic_sha256=HOST_PLAN_SHA256,
            expected_controller_known_hosts_sha256=known_hosts_sha256,
            trusted_public_key_path=trusted_public_key,
        )
    with pytest.raises(probe_runner.WorkloadProbeError, match="bindings"):
        probe_runner.verify_evidence(
            output,
            expected_source_commit=SOURCE_COMMIT,
            expected_application_image_id=APPLICATION_IMAGE_ID,
            expected_host_plan_semantic_sha256=HOST_PLAN_SHA256,
            expected_controller_known_hosts_sha256="0" * 64,
            trusted_public_key_path=trusted_public_key,
        )
    wrong_trust_anchor = tmp_path / "wrong-controller.public"
    wrong_trust_anchor.write_bytes(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    )
    wrong_trust_anchor.chmod(0o600)
    with pytest.raises(probe_runner.WorkloadProbeError, match="trust anchor"):
        probe_runner.verify_evidence(
            output,
            expected_source_commit=SOURCE_COMMIT,
            expected_application_image_id=APPLICATION_IMAGE_ID,
            expected_host_plan_semantic_sha256=HOST_PLAN_SHA256,
            expected_controller_known_hosts_sha256=known_hosts_sha256,
            trusted_public_key_path=wrong_trust_anchor,
        )


def test_offline_probe_verifier_rejects_boundary_widening(
    probe_runner: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = probe_runner._canonical_bytes(_probe_record()) + b"\n"

    def execute(**kwargs: Any) -> None:
        staging = kwargs["staging_directory"]
        for filename in probe_runner.PROBE_RECORD_NAMES:
            (staging / filename).write_bytes(material)

    monkeypatch.setattr(probe_runner, "_execute_probe_playbook", execute)
    output = tmp_path / "tampered-probe.json"
    private_key, trusted_public_key = _evidence_key_paths(tmp_path)
    known_hosts = _known_hosts_path(tmp_path)
    known_hosts_sha256 = hashlib.sha256(known_hosts.read_bytes()).hexdigest()
    probe_runner.run_live_probe(
        source_commit=SOURCE_COMMIT,
        application_image_id=APPLICATION_IMAGE_ID,
        host_plan_semantic_sha256=HOST_PLAN_SHA256,
        output_path=output,
        signing_private_key_path=private_key,
        trusted_public_key_path=trusted_public_key,
        known_hosts_file=known_hosts,
        expected_known_hosts_sha256=known_hosts_sha256,
    )
    envelope = json.loads(output.read_text())
    envelope["payload"]["g7_acceptance_established"] = True
    envelope["payload_sha256"] = hashlib.sha256(
        probe_runner._canonical_bytes(envelope["payload"])
    ).hexdigest()
    output.write_bytes(probe_runner._canonical_bytes(envelope) + b"\n")
    os.chmod(output, 0o600)

    with pytest.raises(probe_runner.WorkloadProbeError, match="signature"):
        probe_runner.verify_evidence(
            output,
            expected_source_commit=SOURCE_COMMIT,
            expected_application_image_id=APPLICATION_IMAGE_ID,
            expected_host_plan_semantic_sha256=HOST_PLAN_SHA256,
            expected_controller_known_hosts_sha256=known_hosts_sha256,
            trusted_public_key_path=trusted_public_key,
        )


@pytest.mark.parametrize("unsafe", ["mode", "symlink"])
def test_probe_phase_reader_rejects_unsafe_fetched_paths(
    probe_runner: ModuleType,
    tmp_path: Path,
    unsafe: str,
) -> None:
    material = probe_runner._canonical_bytes(_probe_record()) + b"\n"
    target = tmp_path / "phase.json"
    target.write_bytes(material)
    if unsafe == "mode":
        target.chmod(0o644)
        path = target
    else:
        target.chmod(0o600)
        path = tmp_path / "phase-link.json"
        path.symlink_to(target)

    with pytest.raises(probe_runner.WorkloadProbeError, match="private|linked"):
        probe_runner._load_probe_record(path)


def test_runtime_contract_pins_orchestrator_images_and_probe_transport(
    compiler: ModuleType,
) -> None:
    workload, _deployment, _topology, _bindings = compiler._validate_contract(
        compiler.DEFAULT_WORKLOADS,
        compiler.DEFAULT_DEPLOYMENT,
        compiler.DEFAULT_TOPOLOGY,
    )
    assert workload["orchestration"] == compiler.ORCHESTRATION_CONTRACT
    assert workload["orchestration"]["version"] == "2.19.12"
    assert workload["runtime_images"] == compiler.RUNTIME_IMAGE_REFS
    agent = workload["services"]["agent-probe"]
    gateway = workload["services"]["segmented-gateway"]
    assert agent["environment"]["AEGIS_GATEWAY_URL"].startswith("https://")
    assert agent["environment"]["AEGIS_SPIRE_MTLS_MODE"] == "required"
    assert agent["environment"]["AEGIS_AGENT_ACTOR_ID"] == "agent:operator-1"
    assert gateway["environment"]["AEGIS_AGENT_ACTOR_ID"] == "agent:operator-1"
    assert gateway["command"].count("--allowed-client-spiffe-id") == 1
    assert "aegis_ot.spire_mtls" in gateway["command"]


def test_primary_probe_transport_cannot_downgrade_required_spire_mtls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_SPIRE_MTLS_MODE", "required")
    monkeypatch.setattr(
        m4g_probe,
        "plaintext_request_json",
        lambda *_args, **_kwargs: pytest.fail("primary exchange used plaintext"),
    )

    with pytest.raises(m4g_probe.ServiceExchangeError, match="requires an HTTPS"):
        m4g_probe.request_json("GET", "http://192.168.58.13:8081/health")
