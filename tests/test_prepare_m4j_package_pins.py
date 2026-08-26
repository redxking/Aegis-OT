from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import zlib
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_m4j_package_pins.py"
EXPECTED_ROLES = ("management", "trust", "agents", "gateway", "ot", "simulation")
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
COMMIT = "a" * 40
DIGEST = "b" * 64


def _git(*arguments: str, text: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(  # noqa: S603 - fixed /usr/bin/git in private test repositories
        ("/usr/bin/git", *arguments),
        check=True,
        capture_output=text,
        text=text,
    )


@pytest.fixture(scope="module")
def setup_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_test_prepare_m4j_package_pins", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tool(tmp_path: Path, name: str) -> tuple[Path, str]:
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    path.chmod(0o700)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _private_path(tmp_path: Path) -> Path:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    return parent / "m4j-package-pins.env"


def _home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("MUST_NOT_LEAK", "ambient")
    return path


def _versions(suffix: str = "") -> dict[str, str]:
    return {
        package: f"1:{index}.2.3-4ubuntu5{suffix}"
        for index, package in enumerate(EXPECTED_PACKAGE_ENV, start=1)
    }


def _observation(setup_module: ModuleType, *, suffix: str = "") -> bytes:
    payload = {
        "apt_sources_manifest_sha256": DIGEST,
        "package_versions": _versions(suffix),
        "schema_version": setup_module.OBSERVATION_SCHEMA,
    }
    return cast(bytes, setup_module._canonical_json(payload)) + b"\n"


def _fake_commands(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    *,
    vagrant: Path,
    ansible: Path,
    observation_for: Callable[[str], bytes] | None = None,
    ansible_version: str = "2.19.12",
    mutate_vagrant: bool = False,
) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def fake_run(arguments: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        command = tuple(arguments)
        calls.append((command, kwargs))
        if command == (str(ansible), "--version"):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    f"ansible-playbook [core {ansible_version}]\n  python version = 3\n"
                ).encode(),
                stderr=b"",
            )
        assert command[0] == str(vagrant)
        if command[1:3] == ("up", "--no-provision"):
            if mutate_vagrant:
                vagrant.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
            return subprocess.CompletedProcess(command, 0, stdout=b"up\n", stderr=b"")
        if command[1] == "ssh":
            role = command[2]
            material = (
                _observation(setup_module) if observation_for is None else observation_for(role)
            )
            return subprocess.CompletedProcess(command, 0, stdout=material, stderr=b"")
        assert command[1:] == ("provision",)
        return subprocess.CompletedProcess(command, 0, stdout=b"provisioned\n", stderr=b"")

    monkeypatch.setattr(setup_module.subprocess, "run", fake_run)
    return calls


def _run(
    setup_module: ModuleType,
    *,
    vagrant: tuple[Path, str],
    ansible: tuple[Path, str],
    output: Path,
    provision: bool,
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        setup_module.prepare_package_pins(
            vagrant=vagrant[0],
            vagrant_sha256=vagrant[1],
            ansible_playbook=ansible[0],
            ansible_playbook_sha256=ansible[1],
            output=output,
            provision=provision,
        ),
    )


def test_contract_is_closed_and_remote_digest_matches_the_ansible_algorithm(
    setup_module: ModuleType,
) -> None:
    assert setup_module.ROLES == EXPECTED_ROLES
    assert setup_module.PACKAGE_ENV == EXPECTED_PACKAGE_ENV
    assert setup_module.ANSIBLE_CORE_VERSION == "2.19.12"
    assert "hashlib.sha1()" in setup_module._REMOTE_HELPER
    assert (
        'manifest = "".join(path + "=" + digest + "\\n" for path, digest in sorted(records))'
        in setup_module._REMOTE_HELPER
    )
    assert 'hashlib.sha256(manifest.encode("utf-8")).hexdigest()' in setup_module._REMOTE_HELPER
    assert "AllowInsecureRepositories=false" in setup_module._REMOTE_HELPER
    assert "AllowUnauthenticated=false" in setup_module._REMOTE_HELPER
    assert all(role not in setup_module.REMOTE_QUERY_COMMAND for role in EXPECTED_ROLES)


def test_six_node_agreement_writes_private_env_and_provisions_with_closed_environment(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = _home(monkeypatch, tmp_path)
    vagrant = _tool(tmp_path, "vagrant")
    ansible = _tool(tmp_path, "ansible-playbook")
    output = _private_path(tmp_path)
    monkeypatch.setattr(setup_module, "_require_clean_source", lambda: COMMIT)
    calls = _fake_commands(
        setup_module,
        monkeypatch,
        vagrant=vagrant[0],
        ansible=ansible[0],
    )

    result = _run(
        setup_module,
        vagrant=vagrant,
        ansible=ansible,
        output=output,
        provision=True,
    )

    assert result == {
        "ansible_core_version": "2.19.12",
        "apt_sources_manifest_sha256": DIGEST,
        "output": str(output),
        "package_versions": _versions(),
        "provisioned": True,
        "roles": list(EXPECTED_ROLES),
        "source_commit": COMMIT,
    }
    assert stat_mode(output) == 0o600
    expected_lines = {
        "AEGIS_M4J_ANSIBLE_CORE_VERSION": "2.19.12",
        "AEGIS_M4J_APT_SOURCES_MANIFEST_SHA256": DIGEST,
        **{variable: _versions()[package] for package, variable in EXPECTED_PACKAGE_ENV.items()},
    }
    assert (
        dict(line.split("=", 1) for line in output.read_text("ascii").splitlines())
        == expected_lines
    )

    commands = [command for command, _kwargs in calls]
    assert commands[0] == (str(ansible[0]), "--version")
    assert commands[1] == (str(vagrant[0]), "up", "--no-provision")
    assert commands[2:8] == [
        (
            str(vagrant[0]),
            "ssh",
            role,
            "--command",
            setup_module.REMOTE_QUERY_COMMAND,
        )
        for role in EXPECTED_ROLES
    ]
    assert commands[8] == (str(vagrant[0]), "provision")
    for _command, kwargs in calls:
        assert "shell" not in kwargs
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["cwd"] == ROOT
        assert "MUST_NOT_LEAK" not in kwargs["env"]
    up_environment = calls[1][1]["env"]
    assert up_environment == {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": f"{ansible[0].parent}:/usr/bin:/bin",
        "VAGRANT_CWD": str(ROOT),
    }
    assert calls[-1][1]["env"] == {**up_environment, **expected_lines}


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_node_disagreement_refuses_artifact_and_provision(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _home(monkeypatch, tmp_path)
    vagrant = _tool(tmp_path, "vagrant")
    ansible = _tool(tmp_path, "ansible-playbook")
    output = _private_path(tmp_path)
    monkeypatch.setattr(setup_module, "_require_clean_source", lambda: COMMIT)
    calls = _fake_commands(
        setup_module,
        monkeypatch,
        vagrant=vagrant[0],
        ansible=ansible[0],
        observation_for=lambda role: _observation(
            setup_module,
            suffix=".1" if role == "simulation" else "",
        ),
    )

    with pytest.raises(setup_module.PackagePinSetupError, match="do not agree"):
        _run(
            setup_module,
            vagrant=vagrant,
            ansible=ansible,
            output=output,
            provision=True,
        )

    assert not output.exists()
    assert all(command[1:] != ("provision",) for command, _kwargs in calls)


@pytest.mark.parametrize(
    "malformed",
    [
        b"{}\n",
        _observation,
        b'{"schema_version":"x","schema_version":"x"}\n',
    ],
    ids=("missing-fields", "extra-line", "duplicate-key"),
)
def test_malformed_or_ambiguous_guest_data_is_rejected(
    setup_module: ModuleType,
    malformed: bytes | Callable[..., bytes],
) -> None:
    raw = _observation(setup_module) + b"unexpected\n" if callable(malformed) else malformed
    with pytest.raises(setup_module.PackagePinSetupError):
        setup_module._parse_observation("management", raw, b"")


def test_non_exact_candidate_and_guest_stderr_are_rejected(setup_module: ModuleType) -> None:
    payload = json.loads(_observation(setup_module))
    payload["package_versions"]["docker.io"] = "(none)"
    raw = setup_module._canonical_json(payload) + b"\n"
    with pytest.raises(setup_module.PackagePinSetupError, match="non-exact"):
        setup_module._parse_observation("management", raw, b"")
    with pytest.raises(setup_module.PackagePinSetupError, match="unsafe"):
        setup_module._parse_observation(
            "management",
            _observation(setup_module),
            b"sudo warning\n",
        )


def test_dirty_or_changing_source_refuses_vagrant_or_artifact(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _home(monkeypatch, tmp_path)
    vagrant = _tool(tmp_path, "vagrant")
    ansible = _tool(tmp_path, "ansible-playbook")
    output = _private_path(tmp_path)
    calls = _fake_commands(
        setup_module,
        monkeypatch,
        vagrant=vagrant[0],
        ansible=ansible[0],
    )

    def dirty() -> str:
        raise setup_module.PackagePinSetupError("clean source required")

    monkeypatch.setattr(setup_module, "_require_clean_source", dirty)
    with pytest.raises(setup_module.PackagePinSetupError, match="clean source"):
        _run(
            setup_module,
            vagrant=vagrant,
            ansible=ansible,
            output=output,
            provision=False,
        )
    assert [command for command, _kwargs in calls] == [(str(ansible[0]), "--version")]
    assert not output.exists()

    identities = iter((COMMIT, "c" * 40))
    monkeypatch.setattr(setup_module, "_require_clean_source", lambda: next(identities))
    calls.clear()
    with pytest.raises(setup_module.PackagePinSetupError, match="changed"):
        _run(
            setup_module,
            vagrant=vagrant,
            ansible=ansible,
            output=output,
            provision=False,
        )
    assert not output.exists()


@pytest.mark.parametrize("index_flag", ["--assume-unchanged", "--skip-worktree"])
def test_source_binding_rejects_index_masked_provisioning_bytes(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    index_flag: str,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    _git("init", "-q", str(checkout))
    vagrantfile = checkout / "Vagrantfile"
    vagrantfile.write_text("SAFE\n", encoding="ascii")
    _git("-C", str(checkout), "add", "Vagrantfile")
    _git(
        "-C",
        str(checkout),
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    _git(
        "-C",
        str(checkout),
        "update-index",
        index_flag,
        "Vagrantfile",
    )
    vagrantfile.write_text("MALICIOUS PROVISIONER\n", encoding="ascii")
    monkeypatch.setattr(setup_module, "ROOT", checkout)
    monkeypatch.setattr(setup_module, "SOURCE_BOUND_PATHS", ("Vagrantfile",))

    with pytest.raises(setup_module.PackagePinSetupError, match="differs from HEAD"):
        setup_module._require_clean_source()


def test_source_binding_rejects_corrupt_provisioning_blob(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    _git("init", "-q", str(checkout))
    vagrantfile = checkout / "Vagrantfile"
    safe = b"SAFE PROVISIONER\n"
    malicious = b"EVIL PROVISIONER\n"
    assert len(safe) == len(malicious)
    vagrantfile.write_bytes(safe)
    _git("-C", str(checkout), "add", "Vagrantfile")
    _git(
        "-C",
        str(checkout),
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    object_id = _git(
        "-C", str(checkout), "rev-parse", "HEAD:Vagrantfile", text=True
    ).stdout.strip()
    _git(
        "-C",
        str(checkout),
        "update-index",
        "--assume-unchanged",
        "Vagrantfile",
    )
    vagrantfile.write_bytes(malicious)
    loose_object = checkout / ".git" / "objects" / object_id[:2] / object_id[2:]
    loose_object.chmod(0o600)
    loose_object.write_bytes(
        zlib.compress(f"blob {len(malicious)}\0".encode("ascii") + malicious)
    )
    monkeypatch.setattr(setup_module, "ROOT", checkout)
    monkeypatch.setattr(setup_module, "SOURCE_BOUND_PATHS", ("Vagrantfile",))

    with pytest.raises(setup_module.PackagePinSetupError, match="Git source preflight failed"):
        setup_module._require_clean_source()


def test_existing_management_marker_refuses_non_bootstrap_query(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _home(monkeypatch, tmp_path)
    checkout = tmp_path / "checkout"
    marker = (
        checkout / ".vagrant" / "machines" / "trust" / "virtualbox" / "m4j-management-communicator"
    )
    marker.parent.mkdir(parents=True)
    marker.write_text("management\n", encoding="ascii")
    monkeypatch.setattr(setup_module, "ROOT", checkout)
    monkeypatch.setattr(setup_module, "_require_clean_source", lambda: COMMIT)
    vagrant = _tool(tmp_path, "vagrant")
    ansible = _tool(tmp_path, "ansible-playbook")
    output = _private_path(tmp_path)
    calls = _fake_commands(
        setup_module,
        monkeypatch,
        vagrant=vagrant[0],
        ansible=ansible[0],
    )

    with pytest.raises(setup_module.PackagePinSetupError, match="bootstrap channels"):
        _run(
            setup_module,
            vagrant=vagrant,
            ansible=ansible,
            output=output,
            provision=False,
        )
    assert [command for command, _kwargs in calls] == [(str(ansible[0]), "--version")]
    assert not output.exists()


def test_wrong_runtime_hash_or_ansible_version_stops_before_vagrant(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _home(monkeypatch, tmp_path)
    vagrant = _tool(tmp_path, "vagrant")
    ansible = _tool(tmp_path, "ansible-playbook")
    output = _private_path(tmp_path)
    calls: list[Any] = []
    monkeypatch.setattr(setup_module.subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(setup_module.PackagePinSetupError, match="SHA-256"):
        _run(
            setup_module,
            vagrant=(vagrant[0], "0" * 64),
            ansible=ansible,
            output=output,
            provision=False,
        )
    assert calls == []

    calls = _fake_commands(
        setup_module,
        monkeypatch,
        vagrant=vagrant[0],
        ansible=ansible[0],
        ansible_version="2.19.11",
    )
    with pytest.raises(setup_module.PackagePinSetupError, match="exactly 2.19.12"):
        _run(
            setup_module,
            vagrant=vagrant,
            ansible=ansible,
            output=output,
            provision=False,
        )
    assert [command for command, _kwargs in calls] == [(str(ansible[0]), "--version")]


def test_runtime_swap_is_detected_before_any_guest_query(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _home(monkeypatch, tmp_path)
    vagrant = _tool(tmp_path, "vagrant")
    ansible = _tool(tmp_path, "ansible-playbook")
    output = _private_path(tmp_path)
    monkeypatch.setattr(setup_module, "_require_clean_source", lambda: COMMIT)
    calls = _fake_commands(
        setup_module,
        monkeypatch,
        vagrant=vagrant[0],
        ansible=ansible[0],
        mutate_vagrant=True,
    )

    with pytest.raises(setup_module.PackagePinSetupError, match="SHA-256"):
        _run(
            setup_module,
            vagrant=vagrant,
            ansible=ansible,
            output=output,
            provision=False,
        )
    assert [command[1] for command, _kwargs in calls if command[0] == str(vagrant[0])] == ["up"]
    assert not output.exists()


def test_output_requires_private_external_parent_and_never_overwrites(
    setup_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o755)
    unsafe_parent.chmod(0o755)
    with pytest.raises(setup_module.PackagePinSetupError, match="mode-0700"):
        setup_module._private_output(unsafe_parent / "pins.env")

    private_checkout = tmp_path / "checkout"
    private_checkout.mkdir(mode=0o700)
    private_checkout.chmod(0o700)
    monkeypatch.setattr(setup_module, "ROOT", private_checkout)
    with pytest.raises(setup_module.PackagePinSetupError, match="outside"):
        setup_module._private_output(private_checkout / "pins.env")

    output = _private_path(tmp_path)
    output.write_text("existing\n", encoding="ascii")
    output.chmod(0o600)
    with pytest.raises(setup_module.PackagePinSetupError, match="overwrite"):
        setup_module._private_output(output)
    with pytest.raises(setup_module.PackagePinSetupError, match="overwrite"):
        setup_module._write_private(output, b"replacement\n")
    assert output.read_bytes() == b"existing\n"
