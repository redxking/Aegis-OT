#!/usr/bin/env python3
"""Derive one agreed, exact package-pin environment for the six-host M4j lab."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_GIT = Path("/usr/bin/git")
ROLES = ("management", "trust", "agents", "gateway", "ot", "simulation")
PACKAGE_ENV = {
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
ANSIBLE_CORE_VERSION = "2.19.12"
OBSERVATION_SCHEMA = "aegis-ot-m4j-package-pin-observation-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
PACKAGE_VERSION = re.compile(r"^[0-9][0-9A-Za-z.+:~_-]*$")
SAFE_LEAF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_TOOL_BYTES = 16 * 1024 * 1024
MAX_OBSERVATION_BYTES = 32 * 1024
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
SOURCE_BOUND_PATHS = (
    "Vagrantfile",
    "infra/m4j/topology.yml",
    "infra/ansible/ansible.cfg",
    "infra/ansible/inventory.ini",
    "infra/ansible/site.yml",
    "infra/ansible/group_vars/all.yml",
    "infra/ansible/roles/m4j_base",
    "scripts/prepare_m4j_package_pins.py",
)


class PackagePinSetupError(RuntimeError):
    """The M4j package-pin setup cannot proceed safely."""


def _fail(message: str) -> NoReturn:
    raise PackagePinSetupError(message)


_REMOTE_HELPER = r"""import fnmatch
import hashlib
import json
import os
import re
import stat
import subprocess
import sys

PACKAGES = (
    "ca-certificates", "python3", "python3-venv", "iproute2", "iptables",
    "runc", "containerd", "ufw", "docker.io",
)
VERSION = re.compile(r"^[0-9][0-9A-Za-z.+:~_-]*$")
ENVIRONMENT = {
    "DEBIAN_FRONTEND": "noninteractive", "LANG": "C", "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}


def stop(message, status):
    sys.stderr.write(message + "\n")
    raise SystemExit(status)


update = subprocess.run(
    (
        "/usr/bin/apt-get",
        "-o", "Acquire::AllowInsecureRepositories=false",
        "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
        "-o", "APT::Get::AllowUnauthenticated=false",
        "-o", "APT::Update::Error-Mode=any",
        "update",
    ),
    check=False,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    env=ENVIRONMENT,
    timeout=600,
)
if update.returncode != 0:
    stop("authenticated apt metadata refresh failed", 41)

records = []
for directory, directory_names, filenames in os.walk("/etc/apt", topdown=True, followlinks=False):
    directory_names[:] = sorted(
        name
        for name in directory_names
        if not os.path.islink(os.path.join(directory, name))
    )
    for name in sorted(filenames):
        if not (fnmatch.fnmatchcase(name, "*.list") or fnmatch.fnmatchcase(name, "*.sources")):
            continue
        path = os.path.join(directory, name)
        try:
            metadata = os.lstat(path)
        except OSError:
            stop("apt source inventory changed while it was enumerated", 42)
        if not stat.S_ISREG(metadata.st_mode):
            continue
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            stop("apt source file could not be opened without following links", 43)
        try:
            before = os.fstat(descriptor)
            digest = hashlib.sha1()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if not stat.S_ISREG(before.st_mode) or identity_before != identity_after:
            stop("apt source file changed while it was hashed", 44)
        records.append((path, digest.hexdigest()))
if not records:
    stop("no regular apt source files were available", 45)

manifest = "".join(path + "=" + digest + "\n" for path, digest in sorted(records))
manifest_sha256 = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
versions = {}
for package in PACKAGES:
    policy = subprocess.run(
        ("/usr/bin/apt-cache", "policy", package),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=ENVIRONMENT,
        timeout=60,
    )
    if policy.returncode != 0:
        stop("apt candidate query failed", 46)
    try:
        lines = policy.stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError:
        stop("apt candidate query returned non-UTF-8 output", 47)
    candidates = [line[13:] for line in lines if line.startswith("  Candidate: ")]
    if len(candidates) != 1 or VERSION.fullmatch(candidates[0]) is None:
        stop("apt candidate query returned an absent or ambiguous version", 48)
    versions[package] = candidates[0]

payload = {
    "apt_sources_manifest_sha256": manifest_sha256,
    "package_versions": versions,
    "schema_version": "aegis-ot-m4j-package-pin-observation-v1",
}
sys.stdout.write(
    json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
)
"""
_REMOTE_HELPER_B64 = base64.b64encode(_REMOTE_HELPER.encode("utf-8")).decode("ascii")
REMOTE_QUERY_COMMAND = (
    "/usr/bin/sudo --non-interactive /usr/bin/env -i "
    "PATH=/usr/bin:/bin LANG=C LC_ALL=C /usr/bin/python3 -c "
    f"'import base64;exec(base64.b64decode(\"{_REMOTE_HELPER_B64}\"))'"
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _read_tool(path: Path, *, label: str) -> tuple[os.stat_result, bytes]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PackagePinSetupError(f"{label} could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.getuid()}
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not before.st_mode & stat.S_IXUSR
            or before.st_size <= 0
            or before.st_size > MAX_TOOL_BYTES
        ):
            _fail(f"{label} must be a protected regular executable")
        material = b""
        while len(material) <= MAX_TOOL_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_TOOL_BYTES + 1 - len(material)))
            if not chunk:
                break
            material += chunk
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or len(material) != before.st_size:
            _fail(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    return before, material


def _validate_executable(
    path: Path,
    expected_sha256: str,
    *,
    label: str,
    required_name: str | None = None,
) -> Path:
    if not path.is_absolute() or SHA256.fullmatch(expected_sha256) is None:
        _fail(f"{label} requires an absolute path and lowercase SHA-256")
    if required_name is not None and path.name != required_name:
        _fail(f"{label} must be named {required_name}")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise PackagePinSetupError(f"{label} is unavailable") from exc
    if path.is_symlink() or resolved != path.absolute() or not stat.S_ISREG(metadata.st_mode):
        _fail(f"{label} must be an explicit, non-linked regular file")
    _, material = _read_tool(path, label=label)
    if hashlib.sha256(material).hexdigest() != expected_sha256:
        _fail(f"{label} differs from its supplied SHA-256")
    return resolved


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _require_closed_git_topology() -> None:
    try:
        root_metadata = ROOT.lstat()
        root = ROOT.resolve(strict=True)
        git_directory = root / ".git"
        git_metadata = git_directory.lstat()
    except OSError as exc:
        raise PackagePinSetupError("the authoritative Git checkout is unavailable") from exc
    if (
        ROOT.is_symlink()
        or root != ROOT.absolute()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or root_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or git_directory.is_symlink()
        or not stat.S_ISDIR(git_metadata.st_mode)
        or git_metadata.st_uid != os.getuid()
        or git_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _fail("the authoritative Git checkout must be a protected user-owned directory")
    if (git_directory / "commondir").exists() or (git_directory / "commondir").is_symlink():
        _fail("linked Git worktree metadata is forbidden")
    for prohibited in (
        git_directory / "objects" / "info" / "alternates",
        git_directory / "objects" / "info" / "http-alternates",
        git_directory / "info" / "grafts",
    ):
        if prohibited.exists() or prohibited.is_symlink():
            _fail("Git alternate, HTTP alternate, and graft object sources are forbidden")
    object_directory = git_directory / "objects"
    try:
        object_metadata = object_directory.lstat()
    except OSError as exc:
        raise PackagePinSetupError("the authoritative Git object store is unavailable") from exc
    if (
        object_directory.is_symlink()
        or not stat.S_ISDIR(object_metadata.st_mode)
        or object_metadata.st_uid != git_metadata.st_uid
        or object_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _fail("the authoritative Git object store is unsafe")
    for directory, directory_names, filenames in os.walk(object_directory, followlinks=False):
        for name in (*directory_names, *filenames):
            candidate = Path(directory) / name
            metadata = candidate.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != git_metadata.st_uid
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                _fail("the Git object store contains unsafe material")


def _run_git(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    git_directory = ROOT / ".git"
    try:
        metadata = git_directory.lstat()
    except OSError as exc:
        raise PackagePinSetupError("the authoritative Git directory is unavailable") from exc
    if (
        git_directory.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
    ):
        _fail("the authoritative Git directory must be a user-owned real directory")
    if not TRUSTED_GIT.is_file() or not os.access(TRUSTED_GIT, os.X_OK):
        _fail("the pinned /usr/bin/git executable is unavailable")
    completed = subprocess.run(  # noqa: S603 - pinned Git executable and fixed arguments
        (
            str(TRUSTED_GIT),
            "--git-dir",
            str(git_directory),
            "--work-tree",
            str(ROOT),
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "core.pager=cat",
            *arguments,
        ),
        cwd=ROOT,
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if completed.returncode != 0:
        _fail("Git source preflight failed")
    return completed


def _source_inventory(commit: str) -> dict[str, tuple[str, bytes]]:
    listing = _run_git(
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        commit,
        "--",
        *SOURCE_BOUND_PATHS,
    ).stdout
    inventory: dict[str, tuple[str, bytes]] = {}
    for raw_entry in listing.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", maxsplit=1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            relative = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise PackagePinSetupError("Git returned a malformed setup-source inventory") from exc
        path = Path(relative)
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or GIT_OBJECT.fullmatch(object_id) is None
            or path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or relative in inventory
        ):
            _fail("Git setup-source inventory contains an unsafe or duplicate entry")
        material = _run_git("cat-file", "blob", object_id).stdout
        if len(material) > MAX_SOURCE_FILE_BYTES:
            _fail(f"Git setup-source blob exceeds its limit: {relative}")
        object_material = f"blob {len(material)}\0".encode("ascii") + material
        if len(object_id) == 40:
            observed_object_id = hashlib.sha1(  # noqa: S324 - Git SHA-1 object address
                object_material,
                usedforsecurity=False,
            ).hexdigest()
        else:
            observed_object_id = hashlib.sha256(object_material).hexdigest()
        if observed_object_id != object_id:
            _fail(f"Git setup-source blob hash differs from HEAD: {relative}")
        inventory[relative] = (mode, material)
    for requested in SOURCE_BOUND_PATHS:
        if requested not in inventory and not any(
            relative.startswith(requested + "/") for relative in inventory
        ):
            _fail(f"setup-source path is absent from the exact commit: {requested}")
    return inventory


def _read_source_file(path: Path, *, relative: str, maximum: int) -> tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PackagePinSetupError(f"setup-source path is unavailable: {relative}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_size < 0
            or before.st_size > maximum
        ):
            _fail(f"setup-source path is not a bounded owned regular file: {relative}")
        material = bytearray()
        while len(material) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(material)))
            if not chunk:
                break
            material.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(material) != before.st_size
            or (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
        ):
            _fail(f"setup-source path changed while it was read: {relative}")
        return bytes(material), before.st_mode
    finally:
        os.close(descriptor)


def _require_source_matches_head(inventory: Mapping[str, tuple[str, bytes]]) -> None:
    root = ROOT.resolve(strict=True)
    for relative, (mode, expected) in inventory.items():
        candidate = root.joinpath(*Path(relative).parts)
        try:
            if candidate.resolve(strict=True) != candidate.absolute():
                _fail(f"setup-source path traverses a link: {relative}")
        except OSError as exc:
            raise PackagePinSetupError(f"setup-source path is unavailable: {relative}") from exc
        observed, observed_mode = _read_source_file(
            candidate,
            relative=relative,
            maximum=MAX_SOURCE_FILE_BYTES,
        )
        expected_executable = mode == "100755"
        observed_executable = bool(
            observed_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        )
        if observed != expected or observed_executable != expected_executable:
            _fail(f"setup-source path differs from HEAD: {relative}")


def _require_clean_source() -> str:
    _require_closed_git_topology()
    head_raw = _run_git("rev-parse", "--verify", "HEAD^{commit}").stdout
    try:
        head = head_raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise PackagePinSetupError("Git returned a malformed source identity") from exc
    if GIT_OBJECT.fullmatch(head) is None:
        _fail("Git returned a malformed source identity")
    _run_git(
        "-c",
        "fsck.skipList=/dev/null",
        "fsck",
        "--strict",
        "--full",
        "--no-dangling",
        "--no-reflogs",
        "--no-progress",
        head,
    )
    _require_source_matches_head(_source_inventory(head))
    status = _run_git("status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    if status:
        _fail("package-pin setup requires a completely clean source checkout")
    return head


def _require_bootstrap_channel() -> None:
    for role in ROLES:
        marker = (
            ROOT / ".vagrant" / "machines" / role / "virtualbox" / "m4j-management-communicator"
        )
        if marker.exists() or marker.is_symlink():
            _fail(
                "package-pin discovery requires marker-free Vagrant bootstrap channels; "
                f"{role} is already configured for management SSH"
            )


def _private_output(output: Path) -> Path:
    if not output.is_absolute() or SAFE_LEAF.fullmatch(output.name) is None:
        _fail("output must be an absolute path with a safe filename")
    if output.exists() or output.is_symlink():
        _fail("refusing to overwrite the package-pin environment artifact")
    try:
        parent_metadata = output.parent.lstat()
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise PackagePinSetupError("output parent is unavailable") from exc
    if (
        output.parent.is_symlink()
        or parent != output.parent.absolute()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
    ):
        _fail("output parent must be a user-owned, non-linked mode-0700 directory")
    destination = parent / output.name
    try:
        destination.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return destination
    _fail("package-pin environment artifacts must remain outside the checkout")


def _base_environment(vagrant: Path, ansible_playbook: Path) -> dict[str, str]:
    home_text = os.environ.get("HOME", "")
    home = Path(home_text)
    try:
        home_metadata = home.lstat()
        home_resolved = home.resolve(strict=True)
    except OSError as exc:
        raise PackagePinSetupError("a valid explicit controller HOME is required") from exc
    if (
        not home.is_absolute()
        or home.is_symlink()
        or home_resolved != home.absolute()
        or not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.getuid()
    ):
        _fail("controller HOME must be a user-owned, non-linked directory")
    path_parts = tuple(
        dict.fromkeys((str(ansible_playbook.parent), str(vagrant.parent), "/usr/bin", "/bin"))
    )
    return {
        "HOME": str(home_resolved),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": ":".join(path_parts),
        "VAGRANT_CWD": str(ROOT),
    }


def _run_checked(
    executable: Path,
    expected_sha256: str,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    label: str,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    resolved = _validate_executable(executable, expected_sha256, label=label)
    try:
        completed = subprocess.run(  # noqa: S603 - attested executable and closed argv/env
            (str(resolved), *arguments),
            cwd=ROOT,
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            env=dict(environment),
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PackagePinSetupError(f"{label} command did not complete safely") from exc
    _validate_executable(executable, expected_sha256, label=label)
    return completed


def _validate_ansible(
    executable: Path,
    expected_sha256: str,
    environment: Mapping[str, str],
) -> None:
    _validate_executable(
        executable,
        expected_sha256,
        label="explicit Ansible runtime",
        required_name="ansible-playbook",
    )
    completed = _run_checked(
        executable,
        expected_sha256,
        ("--version",),
        environment=environment,
        label="explicit Ansible runtime",
        timeout=30,
    )
    if len(completed.stdout) > MAX_OBSERVATION_BYTES or completed.stderr:
        _fail("Ansible version query returned unsafe output")
    try:
        lines = completed.stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise PackagePinSetupError("Ansible version query returned malformed output") from exc
    if not lines or lines[0] != f"ansible-playbook [core {ANSIBLE_CORE_VERSION}]":
        _fail(f"Ansible Core must be exactly {ANSIBLE_CORE_VERSION}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("guest observation contains a duplicate JSON key")
        result[key] = value
    return result


def _parse_observation(role: str, stdout: bytes, stderr: bytes) -> dict[str, Any]:
    if role not in ROLES or stderr or not stdout or len(stdout) > MAX_OBSERVATION_BYTES:
        _fail(f"{role} returned unsafe package-pin observation output")
    try:
        text = stdout.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: _fail("guest observation contains a non-finite value"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackagePinSetupError(f"{role} returned malformed package-pin data") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "apt_sources_manifest_sha256",
        "package_versions",
        "schema_version",
    }:
        _fail(f"{role} returned an unexpected package-pin observation schema")
    digest = payload["apt_sources_manifest_sha256"]
    versions = payload["package_versions"]
    if payload["schema_version"] != OBSERVATION_SCHEMA:
        _fail(f"{role} returned an unsupported package-pin observation schema")
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        _fail(f"{role} returned a malformed apt-source manifest digest")
    if not isinstance(versions, dict) or set(versions) != set(PACKAGE_ENV):
        _fail(f"{role} returned an incomplete package candidate set")
    for package, version in versions.items():
        if not isinstance(package, str) or not isinstance(version, str):
            _fail(f"{role} returned a malformed package candidate")
        if PACKAGE_VERSION.fullmatch(version) is None:
            _fail(f"{role} returned a non-exact package candidate")
    if stdout != _canonical_json(payload) + b"\n":
        _fail(f"{role} returned non-canonical or ambiguous package-pin data")
    return payload


def _agreed_environment(observations: Mapping[str, dict[str, Any]]) -> dict[str, str]:
    if tuple(observations) != ROLES:
        _fail("package-pin observations must cover the six roles in authoritative order")
    first = observations[ROLES[0]]
    for role in ROLES[1:]:
        if observations[role] != first:
            _fail("the six M4j nodes do not agree on package candidates and apt sources")
    versions = first["package_versions"]
    environment = {
        "AEGIS_M4J_ANSIBLE_CORE_VERSION": ANSIBLE_CORE_VERSION,
        "AEGIS_M4J_APT_SOURCES_MANIFEST_SHA256": first["apt_sources_manifest_sha256"],
    }
    environment.update({variable: versions[package] for package, variable in PACKAGE_ENV.items()})
    return environment


def _environment_bytes(environment: Mapping[str, str]) -> bytes:
    expected_order = (
        "AEGIS_M4J_ANSIBLE_CORE_VERSION",
        "AEGIS_M4J_APT_SOURCES_MANIFEST_SHA256",
        *PACKAGE_ENV.values(),
    )
    if tuple(environment) != expected_order:
        _fail("controller package-pin environment is not closed")
    material = "".join(f"{key}={environment[key]}\n" for key in expected_order).encode("ascii")
    if any(byte in material for byte in (0, ord("$"), ord("`"), ord("'"), ord('"'))):
        _fail("controller package-pin environment contains shell interpolation material")
    return material


def _write_private(path: Path, material: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise PackagePinSetupError(
            "package-pin artifact could not be created without overwrite"
        ) from exc
    try:
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                _fail("package-pin artifact write made no progress")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(material)
        ):
            _fail("package-pin artifact was not created as a private regular file")
    finally:
        os.close(descriptor)


def prepare_package_pins(
    *,
    vagrant: Path,
    vagrant_sha256: str,
    ansible_playbook: Path,
    ansible_playbook_sha256: str,
    output: Path,
    provision: bool,
) -> dict[str, Any]:
    destination = _private_output(output)
    vagrant = _validate_executable(vagrant, vagrant_sha256, label="explicit Vagrant runtime")
    ansible_playbook = _validate_executable(
        ansible_playbook,
        ansible_playbook_sha256,
        label="explicit Ansible runtime",
        required_name="ansible-playbook",
    )
    base_environment = _base_environment(vagrant, ansible_playbook)
    _validate_ansible(ansible_playbook, ansible_playbook_sha256, base_environment)
    source_commit = _require_clean_source()
    _require_bootstrap_channel()

    up = _run_checked(
        vagrant,
        vagrant_sha256,
        ("up", "--no-provision"),
        environment=base_environment,
        label="explicit Vagrant runtime",
        timeout=1800,
    )
    if up.returncode != 0:
        _fail("vagrant up --no-provision failed")
    _require_bootstrap_channel()

    observations: dict[str, dict[str, Any]] = {}
    for role in ROLES:
        _require_bootstrap_channel()
        query = _run_checked(
            vagrant,
            vagrant_sha256,
            ("ssh", role, "--command", REMOTE_QUERY_COMMAND),
            environment=base_environment,
            label="explicit Vagrant runtime",
            timeout=900,
        )
        if query.returncode != 0:
            _fail(f"{role} package-pin query failed over the Vagrant bootstrap channel")
        observations[role] = _parse_observation(role, query.stdout, query.stderr)

    pins = _agreed_environment(observations)
    if _require_clean_source() != source_commit:
        _fail("source identity changed during package-pin discovery")

    if provision:
        provision_environment = {**base_environment, **pins}
        result = _run_checked(
            vagrant,
            vagrant_sha256,
            ("provision",),
            environment=provision_environment,
            label="explicit Vagrant runtime",
            timeout=3600,
        )
        if result.returncode != 0:
            _fail("vagrant provision failed under the closed package-pin environment")
        if _require_clean_source() != source_commit:
            _fail("source identity changed during M4j provisioning")

    material = _environment_bytes(pins)
    _write_private(destination, material)
    return {
        "ansible_core_version": ANSIBLE_CORE_VERSION,
        "apt_sources_manifest_sha256": pins["AEGIS_M4J_APT_SOURCES_MANIFEST_SHA256"],
        "output": str(destination),
        "package_versions": observations[ROLES[0]]["package_versions"],
        "provisioned": provision,
        "roles": list(ROLES),
        "source_commit": source_commit,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vagrant", type=Path, required=True)
    parser.add_argument("--vagrant-sha256", required=True)
    parser.add_argument("--ansible-playbook", type=Path, required=True)
    parser.add_argument("--ansible-playbook-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provision", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = prepare_package_pins(
            vagrant=arguments.vagrant,
            vagrant_sha256=arguments.vagrant_sha256,
            ansible_playbook=arguments.ansible_playbook,
            ansible_playbook_sha256=arguments.ansible_playbook_sha256,
            output=arguments.output,
            provision=arguments.provision,
        )
    except PackagePinSetupError as exc:
        print(f"m4j package-pin setup refused: {exc}", file=sys.stderr)
        return 2
    print(_canonical_json(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
