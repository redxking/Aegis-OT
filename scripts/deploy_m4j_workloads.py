#!/usr/bin/env python3
"""Plan or apply the exact-source six-host M4j workload deployment."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_GIT = Path("/usr/bin/git")
ROLES = ("management", "trust", "agents", "gateway", "ot", "simulation")
MANAGEMENT_ADDRESSES = {
    "management": "192.168.56.10",
    "trust": "192.168.56.11",
    "agents": "192.168.56.12",
    "gateway": "192.168.56.13",
    "ot": "192.168.56.14",
    "simulation": "192.168.56.15",
}
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SOURCE_BOUND_PATHS = (
    "Vagrantfile",
    "infra/m4j/topology.yml",
    "infra/m4j/deployment.yml",
    "infra/m4j/workloads.yml",
    "infra/ansible/inventory.ini",
    "infra/ansible/ansible.cfg",
    "infra/ansible/site.yml",
    "infra/ansible/group_vars/all.yml",
    "infra/ansible/requirements.yml",
    "infra/ansible/workloads.yml",
    "infra/ansible/probe.yml",
    "infra/ansible/roles/m4j_base",
    "infra/ansible/roles/m4j_artifacts",
    "infra/ansible/roles/m4j_spire_server",
    "infra/ansible/roles/m4j_spire_agent",
    "infra/ansible/roles/m4j_workload_firewall",
    "infra/ansible/roles/m4j_workload_services",
    "scripts/prepare_m4j_secrets.py",
    "scripts/prepare_m4j_ssh_transport.py",
    "scripts/prepare_m4j_runtime_images.py",
    "scripts/build_m4j_bundle.py",
    "scripts/reconcile_m4j_spire_entries.py",
    "scripts/reconcile_m4j_ufw_rules.py",
    "scripts/revoke_m4j_spire_join_token.py",
    "scripts/validate_m4j_deployment.py",
    "scripts/validate_m4j_workloads.py",
    "scripts/deploy_m4j_workloads.py",
    "scripts/run_m4j_workload_probe.py",
    "src/aegis_ot",
)
ANSIBLE_CORE_VERSION = "2.19.12"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXECUTABLE_CACHE_SUFFIXES = (".pyc", ".pyo", ".pyd", ".so", ".dylib", ".dll")
ANSIBLE_AUTOLOAD_PARTS = frozenset(
    {
        "action_plugins",
        "become_plugins",
        "cache_plugins",
        "callback_plugins",
        "collections",
        "connection_plugins",
        "filter_plugins",
        "httpapi_plugins",
        "inventory_plugins",
        "library",
        "lookup_plugins",
        "module_utils",
        "netconf_plugins",
        "strategy_plugins",
        "terminal_plugins",
        "test_plugins",
        "vars_plugins",
    }
)


class DeploymentError(RuntimeError):
    """The M4j deployment cannot proceed from the supplied exact inputs."""


def _fail(message: str) -> NoReturn:
    raise DeploymentError(message)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(parent.resolve(strict=True))
    except (OSError, ValueError):
        return False
    return True


@contextlib.contextmanager
def _exact_project_import_path(orchestration_root: Path | None = None) -> Iterator[None]:
    """Bind project imports to this checkout while executing source-bound helpers."""
    selected_root = ROOT if orchestration_root is None else orchestration_root
    source_root = (selected_root / "src").resolve(strict=True)
    unexpected = []
    for name, module in tuple(sys.modules.items()):
        if name != "aegis_ot" and not name.startswith("aegis_ot."):
            continue
        origin = getattr(module, "__file__", None)
        if origin is not None and not _is_within(Path(origin), source_root):
            unexpected.append(f"{name}={origin}")
    if unexpected:
        _fail(
            "an aegis_ot module was already loaded outside the exact checkout: "
            + ", ".join(sorted(unexpected)[:10])
        )

    previous_path = list(sys.path)
    remaining_path = [
        entry for entry in previous_path if entry != str(source_root)
    ]
    sys.path[:] = [str(source_root), *remaining_path]
    importlib.invalidate_caches()
    try:
        yield
        for name, module in tuple(sys.modules.items()):
            if name != "aegis_ot" and not name.startswith("aegis_ot."):
                continue
            origin = getattr(module, "__file__", None)
            if origin is None or not _is_within(Path(origin), source_root):
                _fail(f"project module {name} was not loaded from the exact checkout")
    finally:
        sys.path[:] = previous_path
        importlib.invalidate_caches()


def _load_compiler(orchestration_root: Path | None = None) -> ModuleType:
    selected_root = ROOT if orchestration_root is None else orchestration_root
    path = selected_root / "scripts" / "validate_m4j_workloads.py"
    spec = importlib.util.spec_from_file_location("_aegis_m4j_workload_compiler", path)
    if spec is None or spec.loader is None:
        _fail("M4j workload compiler could not be loaded")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        with _exact_project_import_path(selected_root):
            spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def _load_probe_runner(orchestration_root: Path | None = None) -> ModuleType:
    selected_root = ROOT if orchestration_root is None else orchestration_root
    path = selected_root / "scripts" / "run_m4j_workload_probe.py"
    spec = importlib.util.spec_from_file_location("_aegis_m4j_workload_probe", path)
    if spec is None or spec.loader is None:
        _fail("M4j workload probe runner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        with _exact_project_import_path(selected_root):
            spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def _require_closed_git_topology() -> Path:
    git_directory = ROOT / ".git"
    try:
        git_metadata = git_directory.lstat()
    except OSError as exc:
        raise DeploymentError("the authoritative Git directory is unavailable") from exc
    if not stat.S_ISDIR(git_metadata.st_mode) or git_directory.is_symlink():
        _fail("the authoritative .git path must be a real directory")
    if git_metadata.st_uid != os.getuid():
        _fail("the authoritative Git directory must be owned by the invoking user")

    object_directory = git_directory / "objects"
    try:
        object_metadata = object_directory.lstat()
    except OSError as exc:
        raise DeploymentError("the authoritative Git object store is unavailable") from exc
    if not stat.S_ISDIR(object_metadata.st_mode) or object_directory.is_symlink():
        _fail("the authoritative Git object store must be a real directory")
    if object_metadata.st_uid != git_metadata.st_uid:
        _fail("the Git object store has an unexpected owner")
    for prohibited in (
        object_directory / "info" / "alternates",
        object_directory / "info" / "http-alternates",
        git_directory / "info" / "grafts",
    ):
        if prohibited.exists() or prohibited.is_symlink():
            _fail("Git alternate, HTTP alternate, and graft object sources are forbidden")
    for directory, directory_names, filenames in os.walk(object_directory, followlinks=False):
        for name in (*directory_names, *filenames):
            candidate = Path(directory) / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                _fail("the Git object store must not contain symbolic links")
            if metadata.st_uid != git_metadata.st_uid:
                _fail("the Git object store contains material with an unexpected owner")
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                _fail("the Git object store must not be group- or world-writable")
    return git_directory


def _run_git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    git_directory = _require_closed_git_topology()
    if not TRUSTED_GIT.is_file() or not os.access(TRUSTED_GIT, os.X_OK):
        _fail("the pinned /usr/bin/git executable is unavailable")
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    completed = subprocess.run(  # noqa: S603 - resolved Git executable and fixed argv
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
            "core.pager=cat",
            *arguments,
        ),
        cwd=ROOT,
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise DeploymentError(f"Git preflight failed: {detail[-1000:]}")
    return completed


def _run_git_bytes(*arguments: str) -> bytes:
    """Read exact Git object bytes without consulting the index or ambient config."""
    git_directory = _require_closed_git_topology()
    if not TRUSTED_GIT.is_file() or not os.access(TRUSTED_GIT, os.X_OK):
        _fail("the pinned /usr/bin/git executable is unavailable")
    completed = subprocess.run(  # noqa: S603 - resolved Git executable and fixed argv
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
            "core.pager=cat",
            *arguments,
        ),
        cwd=ROOT,
        check=False,
        capture_output=True,
        env={
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": "/dev/null",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise DeploymentError(f"Git object read failed: {detail[-1000:]}")
    return completed.stdout


def _head_blob_inventory(expected_commit: str) -> dict[str, tuple[str, str, bytes]]:
    listing = _run_git_bytes(
        "ls-tree", "-r", "-z", "--full-tree", expected_commit, "--", *SOURCE_BOUND_PATHS
    )
    inventory: dict[str, tuple[str, str, bytes]] = {}
    for raw_entry in listing.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", maxsplit=1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise DeploymentError("Git returned a malformed source inventory") from exc
        candidate = Path(path)
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or GIT_OBJECT.fullmatch(object_id) is None
            or candidate.is_absolute()
            or ".." in candidate.parts
            or path in inventory
        ):
            _fail("Git source inventory contains an unsafe or duplicate entry")
        material = _run_git_bytes("cat-file", "blob", object_id)
        object_material = f"blob {len(material)}\0".encode("ascii") + material
        if len(object_id) == 40:
            observed_object_id = hashlib.sha1(  # noqa: S324 - Git SHA-1 object address
                object_material,
                usedforsecurity=False,
            ).hexdigest()
        elif len(object_id) == 64:
            observed_object_id = hashlib.sha256(object_material).hexdigest()
        else:  # guarded by GIT_OBJECT; retained as a closed parser boundary
            _fail("Git source inventory uses an unsupported object format")
        if observed_object_id != object_id:
            _fail(f"Git blob content hash differs from HEAD: {path}")
        inventory[path] = (mode, object_id, material)
    for requested in SOURCE_BOUND_PATHS:
        if requested not in inventory and not any(
            path.startswith(requested + "/") for path in inventory
        ):
            _fail(f"source-bound path is absent from the exact commit: {requested}")
    return inventory


def _read_regular(path: Path, *, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.absolute(), flags)
    except OSError as exc:
        raise DeploymentError(f"{label} could not be opened without following links") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            _fail(f"{label} must be an owned regular file")
        if metadata.st_size < 0 or metadata.st_size > maximum:
            _fail(f"{label} has an invalid size")
        material = b""
        while len(material) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(material)))
            if not chunk:
                break
            material += chunk
        if len(material) != metadata.st_size:
            _fail(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    return material


def _read_trusted_builder_public_key(path: Path) -> bytes:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    except OSError as exc:
        raise DeploymentError("trusted-builder public key is unavailable") from exc
    else:
        _fail("trusted-builder public key must remain outside the checkout")
    material = _read_regular(
        path,
        maximum=32,
        label="trusted-builder public key",
    )
    try:
        metadata = path.lstat()
    except OSError as exc:  # pragma: no cover - opened successfully above
        raise DeploymentError("trusted-builder public key became unavailable") from exc
    if (
        len(material) != 32
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _fail(
            "trusted-builder public key must be an owned, protected raw Ed25519 key"
        )
    return material


def _require_worktree_matches_head(
    inventory: dict[str, tuple[str, str, bytes]],
) -> None:
    for relative, (mode, _object_id, expected) in inventory.items():
        candidate = ROOT / relative
        try:
            if candidate.absolute() != candidate.resolve(strict=True):
                _fail(f"source-bound path traverses a link: {relative}")
            metadata = candidate.lstat()
        except OSError as exc:
            raise DeploymentError(f"source-bound path is unavailable: {relative}") from exc
        if not stat.S_ISREG(metadata.st_mode):
            _fail(f"source-bound path is not regular: {relative}")
        expected_executable = mode == "100755"
        if bool(metadata.st_mode & stat.S_IXUSR) != expected_executable:
            _fail(f"source-bound executable mode differs from HEAD: {relative}")
        observed = _read_regular(
            candidate,
            maximum=max(len(expected), 1) + 1,
            label=f"source-bound path {relative}",
        )
        if observed != expected:
            _fail(f"source-bound bytes differ from HEAD: {relative}")


def _require_exact_orchestrator_source(expected_commit: str) -> None:
    if GIT_OBJECT.fullmatch(expected_commit) is None:
        _fail("source commit must be a full lowercase Git object ID")
    head = _run_git("rev-parse", "HEAD").stdout.strip()
    if head != expected_commit:
        _fail("deployment commit must equal the current checkout HEAD")
    _run_git_bytes(
        "-c",
        "fsck.skipList=/dev/null",
        "fsck",
        "--strict",
        "--full",
        "--no-dangling",
        "--no-reflogs",
        "--no-progress",
        expected_commit,
    )
    _require_clean_checkout()
    _require_worktree_matches_head(_head_blob_inventory(expected_commit))


def _require_clean_checkout() -> None:
    status = _run_git(
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    ).stdout
    if status:
        _fail(
            "deployment checkout must be completely clean, including untracked "
            "Ansible auto-load paths"
        )
    ignored = _run_git(
        "ls-files",
        "--others",
        "--ignored",
        "--exclude-standard",
        "-z",
    ).stdout.split("\0")
    unsafe: list[str] = []
    for path_text in ignored:
        if not path_text:
            continue
        parts = Path(path_text).parts
        in_python_runtime = path_text.startswith(("scripts/", "src/aegis_ot/"))
        executable_cache = (
            "__pycache__" in parts
            or path_text.casefold().endswith(EXECUTABLE_CACHE_SUFFIXES)
        )
        ansible_autoload = path_text.startswith("infra/ansible/") and any(
            part in ANSIBLE_AUTOLOAD_PARTS for part in parts
        )
        if in_python_runtime and executable_cache or ansible_autoload:
            unsafe.append(path_text)
    if unsafe:
        _fail(
            "deployment checkout contains ignored executable or Ansible auto-load "
            "artifacts: " + ", ".join(sorted(unsafe)[:20])
        )


def _decode_ed25519_host_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise DeploymentError("known-hosts contains invalid base64 key material") from exc
    algorithm = b"ssh-ed25519"
    expected = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + (32).to_bytes(4, "big")
    )
    if len(decoded) != len(expected) + 32 or not decoded.startswith(expected):
        _fail("known-hosts must contain canonical SSH Ed25519 public keys")
    return decoded


def _validate_known_hosts(path: Path) -> tuple[bytes, str]:
    absolute = path.absolute()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise DeploymentError(f"known-hosts evidence could not be opened: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            _fail("known-hosts evidence must be a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            _fail("known-hosts evidence must have mode 0600")
        if metadata.st_uid != os.getuid():
            _fail("known-hosts evidence must be owned by the invoking user")
        if metadata.st_size <= 0 or metadata.st_size > 65536:
            _fail("known-hosts evidence has an invalid size")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(65537)
    finally:
        os.close(descriptor)

    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DeploymentError("known-hosts evidence must be ASCII") from exc
    lines = text.splitlines()
    if len(lines) != len(ROLES) or any(not line or line != line.strip() for line in lines):
        _fail("known-hosts must contain exactly six non-empty canonical entries")

    observed: dict[str, bytes] = {}
    for line in lines:
        fields = line.split(" ")
        if len(fields) != 3 or any(not field for field in fields):
            _fail("known-hosts entries must contain host pattern, key type, and key")
        host_pattern, key_type, encoded_key = fields
        if key_type != "ssh-ed25519":
            _fail("known-hosts permits only SSH Ed25519 host keys")
        matches = [
            role
            for role, address in MANAGEMENT_ADDRESSES.items()
            if host_pattern == f"{role},{address}"
        ]
        if len(matches) != 1 or matches[0] in observed:
            _fail("known-hosts aliases and management addresses must match exactly")
        observed[matches[0]] = _decode_ed25519_host_key(encoded_key)
    if set(observed) != set(ROLES):
        _fail("known-hosts must bind all six M4j role aliases and addresses")
    if len(set(observed.values())) != len(ROLES):
        _fail("known-hosts must bind a distinct host key to each M4j node")
    return content, hashlib.sha256(content).hexdigest()


def _require_private_parent(path: Path) -> None:
    parent = path.absolute().parent
    try:
        metadata = parent.stat()
    except OSError as exc:
        raise DeploymentError("known-hosts private parent is unavailable") from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail("known-hosts working copy must be inside an owned mode-0700 directory")


def _write_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                _fail("known-hosts working-copy write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_private_regular(source: Path, destination: Path, *, label: str) -> None:
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_descriptor = os.open(source.absolute(), source_flags)
    except OSError as exc:
        raise DeploymentError(f"{label} could not be opened safely") from exc
    try:
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
            _fail(f"{label} must be an owned regular file")
        destination_descriptor = os.open(destination, destination_flags, 0o600)
        try:
            copied = 0
            while True:
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_descriptor, view)
                    if written <= 0:
                        _fail(f"{label} snapshot write made no progress")
                    copied += written
                    view = view[written:]
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        after = os.fstat(source_descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _fail(f"{label} changed while its private snapshot was created")
        if copied != before.st_size:
            _fail(f"{label} snapshot is incomplete")
    finally:
        os.close(source_descriptor)


def _copy_private_tree(source: Path, destination: Path, *, label: str) -> None:
    try:
        metadata = source.absolute().lstat()
    except OSError as exc:
        raise DeploymentError(f"{label} is unavailable") from exc
    if (
        source.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail(f"{label} must be an owned, non-linked mode-0700 directory")
    destination.mkdir(mode=0o700)
    for directory, directory_names, filenames in os.walk(source, followlinks=False):
        directory_names.sort()
        filenames.sort()
        current = Path(directory)
        relative = current.relative_to(source)
        target_directory = destination / relative
        for name in directory_names:
            child = current / name
            child_metadata = child.lstat()
            if (
                child.is_symlink()
                or not stat.S_ISDIR(child_metadata.st_mode)
                or child_metadata.st_uid != os.getuid()
            ):
                _fail(f"{label} contains an unsafe directory: {child.relative_to(source)}")
            (target_directory / name).mkdir(mode=0o700)
        for name in filenames:
            child = current / name
            _copy_private_regular(
                child,
                target_directory / name,
                label=f"{label} file {child.relative_to(source)}",
            )


@contextlib.contextmanager
def _stable_head_source(expected_commit: str) -> Iterator[Path]:
    """Materialize executable project inputs from exact HEAD blobs, never the index."""
    inventory = _head_blob_inventory(expected_commit)
    _require_worktree_matches_head(inventory)
    container = Path(tempfile.mkdtemp(prefix="aegis-m4j-head-source-"))
    container.chmod(0o700)
    snapshot = container / "repo"
    snapshot.mkdir(mode=0o700)
    try:
        for relative, (mode, _object_id, material) in sorted(inventory.items()):
            destination = snapshot / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _write_private_file(destination, material)
            if mode == "100755":
                destination.chmod(0o700)
            if _read_regular(
                destination,
                maximum=max(len(material), 1) + 1,
                label=f"HEAD snapshot {relative}",
            ) != material:
                _fail(f"HEAD snapshot differs from the committed blob: {relative}")
        yield snapshot
    finally:
        if container.exists() and not container.is_symlink():
            shutil.rmtree(container)


@contextlib.contextmanager
def _stable_input_snapshot(
    bundle_directory: Path,
    runtime_image_directory: Path,
    secret_directory: Path,
) -> Iterator[tuple[Path, Path, Path]]:
    container = Path(tempfile.mkdtemp(prefix="aegis-m4j-inputs-"))
    container.chmod(0o700)
    bundle = container / "bundle"
    runtime = container / "runtime-images"
    secrets = container / "secrets"
    try:
        _copy_private_tree(bundle_directory, bundle, label="application bundle")
        _copy_private_tree(
            runtime_image_directory,
            runtime,
            label="runtime image bundle",
        )
        _copy_private_tree(secret_directory, secrets, label="secret package")
        yield bundle, runtime, secrets
    finally:
        if container.exists() and not container.is_symlink():
            shutil.rmtree(container)


def _snapshot_vagrant_management_state(orchestration_root: Path) -> None:
    for role in ROLES:
        destination = (
            orchestration_root / ".vagrant" / "machines" / role / "virtualbox"
        )
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in ("m4j-management-communicator", "private_key"):
            source = ROOT / ".vagrant" / "machines" / role / "virtualbox" / name
            _copy_private_regular(
                source,
                destination / name,
                label=f"Vagrant {role} {name}",
            )


@contextlib.contextmanager
def _stable_known_hosts(path: Path) -> Iterator[tuple[Path, str]]:
    content, digest = _validate_known_hosts(path)
    directory = Path(tempfile.mkdtemp(prefix="aegis-m4j-known-hosts-"))
    directory.chmod(0o700)
    stable = directory / "known_hosts"
    try:
        _write_private_file(stable, content)
        _require_private_parent(stable)
        copied, copied_digest = _validate_known_hosts(stable)
        if copied != content or copied_digest != digest:
            _fail("known-hosts working copy differs from validated caller evidence")
        yield stable, digest
    finally:
        if directory.exists() and not directory.is_symlink():
            shutil.rmtree(directory)


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DeploymentError("M4j host plans are not canonical JSON") from exc


def _compile_host_plans(
    *,
    source_commit: str,
    bundle_directory: Path,
    runtime_image_directory: Path,
    secret_directory: Path,
    trusted_builder_public_key: bytes,
    expected_builder_profile_sha256: str,
    orchestration_root: Path | None = None,
) -> dict[str, Any]:
    compiler = _load_compiler(orchestration_root)
    return {
        role: compiler.compile_plan(
            role=role,
            expected_commit=source_commit,
            bundle_directory=bundle_directory,
            runtime_image_directory=runtime_image_directory,
            secret_directory=secret_directory,
            trusted_builder_public_key=trusted_builder_public_key,
            expected_builder_profile_sha256=expected_builder_profile_sha256,
        )
        for role in ROLES
    }


def _deployment_summary(source_commit: str, plans: dict[str, Any]) -> dict[str, Any]:
    if tuple(plans) != ROLES:
        _fail("M4j host plans do not cover the exact ordered six-role inventory")
    semantic_sha256 = hashlib.sha256(_canonical_bytes(plans)).hexdigest()
    return {
        "schema_version": "aegis-ot-m4j-deployment-orchestration-plan-v1",
        "mode": "plan_only",
        "source_git_commit": source_commit,
        "roles": list(ROLES),
        "host_plan_semantic_sha256": semantic_sha256,
        "application_image_id": plans["agents"]["bundle"]["application_image_id"],
        "builder_profile_sha256": plans["agents"]["bundle"][
            "builder_profile_sha256"
        ],
        "distinct_node_agent_ids": [
            plans[role]["node_agent"]["spiffe_id"]
            for role in ROLES
            if role != "management"
        ],
        "join_token_delivery": (
            "per_host_no_log_management_ssh_then_local_delete_and_server_revoke_check"
        ),
        "ansible_core_version": plans["management"]["orchestration"]["version"],
        "controller_authority_private_key_distributed": False,
        "managed_hosts_mutated": False,
        "claim_boundary": "configuration_validated_not_live_deployed",
    }


def _compile_deployment(
    *,
    source_commit: str,
    bundle_directory: Path,
    runtime_image_directory: Path,
    secret_directory: Path,
    trusted_builder_public_key: bytes,
    expected_builder_profile_sha256: str,
    orchestration_root: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _require_exact_orchestrator_source(source_commit)
    plans = _compile_host_plans(
        source_commit=source_commit,
        bundle_directory=bundle_directory,
        runtime_image_directory=runtime_image_directory,
        secret_directory=secret_directory,
        trusted_builder_public_key=trusted_builder_public_key,
        expected_builder_profile_sha256=expected_builder_profile_sha256,
        orchestration_root=orchestration_root,
    )
    return _deployment_summary(source_commit, plans), plans


def _require_plan_inputs_unchanged(
    *,
    expected_plans: dict[str, Any],
    source_commit: str,
    bundle_directory: Path,
    runtime_image_directory: Path,
    secret_directory: Path,
    trusted_builder_public_key: bytes,
    expected_builder_profile_sha256: str,
    orchestration_root: Path | None = None,
) -> None:
    observed_plans = _compile_host_plans(
        source_commit=source_commit,
        bundle_directory=bundle_directory,
        runtime_image_directory=runtime_image_directory,
        secret_directory=secret_directory,
        trusted_builder_public_key=trusted_builder_public_key,
        expected_builder_profile_sha256=expected_builder_profile_sha256,
        orchestration_root=orchestration_root,
    )
    if _canonical_bytes(observed_plans) != _canonical_bytes(expected_plans):
        _fail("M4j deployment inputs changed after the signed host plans were compiled")


def _validate_plan_file(path: Path, expected_sha256: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        _fail("controller plan-file digest must be lowercase SHA-256")
    _require_private_parent(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path.absolute(), flags)
    except OSError as exc:
        raise DeploymentError("controller plan file could not be opened") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            _fail("controller plan file must be regular")
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.getuid():
            _fail("controller plan file must be owned by the invoking user with mode 0600")
        if metadata.st_size <= 0 or metadata.st_size > 8 * 1024 * 1024:
            _fail("controller plan file has an invalid size")
        content = b""
        while len(content) <= 8 * 1024 * 1024:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            content += chunk
    finally:
        os.close(descriptor)
    observed = hashlib.sha256(content).hexdigest()
    if observed != expected_sha256:
        _fail("controller plan file changed after exact compilation")
    return observed


@contextlib.contextmanager
def _stable_plan_file(
    source_commit: str,
    plans: dict[str, Any],
) -> Iterator[tuple[Path, str]]:
    host_plan_semantic_sha256 = hashlib.sha256(_canonical_bytes(plans)).hexdigest()
    document = {
        "schema_version": "aegis-ot-m4j-controller-plan-set-v1",
        "source_git_commit": source_commit,
        "host_plan_semantic_sha256": host_plan_semantic_sha256,
        "plans": plans,
    }
    content = _canonical_bytes(document) + b"\n"
    digest = hashlib.sha256(content).hexdigest()
    directory = Path(tempfile.mkdtemp(prefix="aegis-m4j-controller-plan-"))
    directory.chmod(0o700)
    path = directory / "host-plans.json"
    try:
        _write_private_file(path, content)
        _validate_plan_file(path, digest)
        yield path, digest
    finally:
        if directory.exists() and not directory.is_symlink():
            shutil.rmtree(directory)


def plan_deployment(
    *,
    source_commit: str,
    bundle_directory: Path,
    runtime_image_directory: Path,
    secret_directory: Path,
    trusted_builder_public_key: bytes,
    expected_builder_profile_sha256: str,
) -> dict[str, Any]:
    summary, _plans = _compile_deployment(
        source_commit=source_commit,
        bundle_directory=bundle_directory,
        runtime_image_directory=runtime_image_directory,
        secret_directory=secret_directory,
        trusted_builder_public_key=trusted_builder_public_key,
        expected_builder_profile_sha256=expected_builder_profile_sha256,
    )
    return summary


@contextlib.contextmanager
def _closed_ansible_environment(
    *,
    orchestration_root: Path,
    known_hosts_file: Path,
) -> Iterator[dict[str, str]]:
    control = Path(tempfile.mkdtemp(prefix="aegis-m4j-ansible-control-"))
    control.chmod(0o700)
    try:
        directories = {
            name: control / name
            for name in ("home", "local-tmp", "tmp", "plugins", "collections")
        }
        for directory in directories.values():
            directory.mkdir(mode=0o700)
        known_hosts = known_hosts_file.absolute()
        ssh_arguments = " ".join(
            (
                "-F /dev/null",
                "-o IdentitiesOnly=yes",
                "-o StrictHostKeyChecking=yes",
                f"-o UserKnownHostsFile={shlex.quote(str(known_hosts))}",
                "-o GlobalKnownHostsFile=/dev/null",
            )
        )
        plugin_path = str(directories["plugins"])
        environment = {
            "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": str(directories["tmp"]),
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "ANSIBLE_CONFIG": str(
                orchestration_root / "infra" / "ansible" / "ansible.cfg"
            ),
            "ANSIBLE_HOME": str(directories["home"]),
            "ANSIBLE_LOCAL_TEMP": str(directories["local-tmp"]),
            "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_SSH_COMMON_ARGS": ssh_arguments,
            "ANSIBLE_SSH_EXECUTABLE": "/usr/bin/ssh",
            "ANSIBLE_ROLES_PATH": str(
                orchestration_root / "infra" / "ansible" / "roles"
            ),
            "ANSIBLE_COLLECTIONS_PATH": str(directories["collections"]),
            "ANSIBLE_INVENTORY_ENABLED": "ini",
            "ANSIBLE_STDOUT_CALLBACK": "default",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_ACTION_PLUGINS": plugin_path,
            "ANSIBLE_BECOME_PLUGINS": plugin_path,
            "ANSIBLE_CACHE_PLUGINS": plugin_path,
            "ANSIBLE_CALLBACK_PLUGINS": plugin_path,
            "ANSIBLE_CLICONF_PLUGINS": plugin_path,
            "ANSIBLE_CONNECTION_PLUGINS": plugin_path,
            "ANSIBLE_FILTER_PLUGINS": plugin_path,
            "ANSIBLE_HTTPAPI_PLUGINS": plugin_path,
            "ANSIBLE_LIBRARY": plugin_path,
            "ANSIBLE_LOOKUP_PLUGINS": plugin_path,
            "ANSIBLE_NETCONF_PLUGINS": plugin_path,
            "ANSIBLE_STRATEGY_PLUGINS": plugin_path,
            "ANSIBLE_TERMINAL_PLUGINS": plugin_path,
            "ANSIBLE_TEST_PLUGINS": plugin_path,
            "ANSIBLE_VARS_PLUGINS": plugin_path,
        }
        yield environment
    finally:
        if control.exists() and not control.is_symlink():
            shutil.rmtree(control)


def _validate_ansible_runtime_material(
    executable: Path,
    expected_sha256: str,
) -> Path:
    if SHA256.fullmatch(expected_sha256) is None or not executable.is_absolute():
        _fail("Ansible runtime requires an absolute path and lowercase SHA-256")
    try:
        resolved = executable.resolve(strict=True)
        metadata = executable.lstat()
    except OSError as exc:
        raise DeploymentError("the explicit Ansible runtime is unavailable") from exc
    if (
        resolved != executable.absolute()
        or executable.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & stat.S_IXUSR
    ):
        _fail("the explicit Ansible runtime must be an owned, non-linked executable")
    material = _read_regular(
        executable,
        maximum=4 * 1024 * 1024,
        label="explicit Ansible runtime",
    )
    if hashlib.sha256(material).hexdigest() != expected_sha256:
        _fail("the explicit Ansible runtime differs from its supplied SHA-256")
    return resolved


def _validate_ansible_runtime(
    executable: Path,
    expected_sha256: str,
    environment: dict[str, str],
) -> Path:
    resolved = _validate_ansible_runtime_material(executable, expected_sha256)
    completed = subprocess.run(  # noqa: S603 - exact absolute runtime and fixed argv
        (str(resolved), "--version"),
        cwd=resolved.parent.parent,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    first_line = completed.stdout.splitlines()[0] if completed.stdout.splitlines() else ""
    if completed.returncode != 0 or first_line != (
        f"ansible-playbook [core {ANSIBLE_CORE_VERSION}]"
    ):
        _fail(f"Ansible Core must be exactly {ANSIBLE_CORE_VERSION}")
    return resolved


def _apply(
    *,
    source_commit: str,
    bundle_directory: Path,
    runtime_image_directory: Path,
    secret_directory: Path,
    expected_plans: dict[str, Any],
    plan_file: Path,
    expected_plan_file_sha256: str,
    known_hosts_file: Path,
    ansible_playbook: Path,
    expected_ansible_playbook_sha256: str,
    orchestration_root: Path,
    expected_known_hosts_sha256: str | None = None,
    trusted_builder_public_key: bytes = b"",
    expected_builder_profile_sha256: str = "",
) -> str:
    ssh_executable = Path("/usr/bin/ssh")
    if not ssh_executable.is_file() or not os.access(ssh_executable, os.X_OK):
        _fail("the pinned /usr/bin/ssh transport is unavailable")
    _require_private_parent(known_hosts_file)
    _validate_plan_file(plan_file, expected_plan_file_sha256)
    expected_host_plan_semantic_sha256 = hashlib.sha256(
        _canonical_bytes(expected_plans)
    ).hexdigest()
    _require_plan_inputs_unchanged(
        expected_plans=expected_plans,
        source_commit=source_commit,
        bundle_directory=bundle_directory,
        runtime_image_directory=runtime_image_directory,
        secret_directory=secret_directory,
        trusted_builder_public_key=trusted_builder_public_key,
        expected_builder_profile_sha256=expected_builder_profile_sha256,
        orchestration_root=orchestration_root,
    )
    _known_hosts_content, known_hosts_sha256 = _validate_known_hosts(known_hosts_file)
    if (
        expected_known_hosts_sha256 is not None
        and known_hosts_sha256 != expected_known_hosts_sha256
    ):
        _fail("known-hosts working copy differs from validated caller evidence")
    known_hosts = known_hosts_file.absolute()
    with _closed_ansible_environment(
        orchestration_root=orchestration_root,
        known_hosts_file=known_hosts,
    ) as environment:
        executable = _validate_ansible_runtime(
            ansible_playbook,
            expected_ansible_playbook_sha256,
            environment,
        )
        environment.update(
            {
                "AEGIS_M4J_SOURCE_COMMIT": source_commit,
                "AEGIS_M4J_BUNDLE_DIRECTORY": str(
                    bundle_directory.resolve(strict=True)
                ),
                "AEGIS_M4J_RUNTIME_IMAGE_DIRECTORY": str(
                    runtime_image_directory.resolve(strict=True)
                ),
                "AEGIS_M4J_SECRET_DIRECTORY": str(
                    secret_directory.resolve(strict=True)
                ),
                "AEGIS_M4J_PLAN_FILE": str(plan_file.resolve(strict=True)),
                "AEGIS_M4J_PLAN_FILE_SHA256": expected_plan_file_sha256,
                "AEGIS_M4J_HOST_PLAN_SEMANTIC_SHA256": (
                    expected_host_plan_semantic_sha256
                ),
            }
        )
        completed = subprocess.run(  # noqa: S603 - verified Ansible and fixed argv
            (
                str(executable),
                "--inventory",
                str(orchestration_root / "infra" / "ansible" / "inventory.ini"),
                str(orchestration_root / "infra" / "ansible" / "workloads.yml"),
            ),
            cwd=orchestration_root,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
    if completed.returncode != 0:
        raise DeploymentError(
            "M4j Ansible workload deployment failed; partial mutation is possible and "
            "exact reconciliation is required"
        )
    _validate_plan_file(plan_file, expected_plan_file_sha256)
    _require_plan_inputs_unchanged(
        expected_plans=expected_plans,
        source_commit=source_commit,
        bundle_directory=bundle_directory,
        runtime_image_directory=runtime_image_directory,
        secret_directory=secret_directory,
        trusted_builder_public_key=trusted_builder_public_key,
        expected_builder_profile_sha256=expected_builder_profile_sha256,
        orchestration_root=orchestration_root,
    )
    _validate_ansible_runtime_material(
        ansible_playbook,
        expected_ansible_playbook_sha256,
    )
    _require_private_parent(known_hosts)
    _post_apply_content, post_apply_sha256 = _validate_known_hosts(known_hosts)
    if post_apply_sha256 != known_hosts_sha256:
        _fail("known-hosts working copy changed during M4j deployment")
    return known_hosts_sha256


def _execute_probe_playbook(
    *,
    source_commit: str,
    application_image_id: str,
    staging_directory: Path,
    known_hosts_file: Path,
    expected_known_hosts_sha256: str,
    ansible_playbook: Path,
    expected_ansible_playbook_sha256: str,
    orchestration_root: Path,
) -> None:
    _material, known_hosts_sha256 = _validate_known_hosts(known_hosts_file)
    if known_hosts_sha256 != expected_known_hosts_sha256:
        _fail("controller known-hosts evidence differs from the applied deployment")
    with _closed_ansible_environment(
        orchestration_root=orchestration_root,
        known_hosts_file=known_hosts_file,
    ) as environment:
        executable = _validate_ansible_runtime(
            ansible_playbook,
            expected_ansible_playbook_sha256,
            environment,
        )
        environment.update(
            {
                "AEGIS_M4J_SOURCE_COMMIT": source_commit,
                "AEGIS_M4J_APPLICATION_IMAGE_ID": application_image_id,
                "AEGIS_M4J_PROBE_STAGING_DIRECTORY": str(staging_directory),
            }
        )
        completed = subprocess.run(  # noqa: S603 - verified Ansible and fixed argv
            (
                str(executable),
                "--inventory",
                str(orchestration_root / "infra" / "ansible" / "inventory.ini"),
                str(orchestration_root / "infra" / "ansible" / "probe.yml"),
            ),
            cwd=orchestration_root,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise DeploymentError(
            "M4j workload probe failed after possible partial service restart; "
            f"exact reconciliation is required: {detail[-2000:]}"
        )
    _validate_ansible_runtime_material(
        ansible_playbook,
        expected_ansible_playbook_sha256,
    )
    _post_material, post_sha256 = _validate_known_hosts(known_hosts_file)
    if post_sha256 != known_hosts_sha256:
        _fail("controller known-hosts evidence changed during the workload probe")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--runtime-images", type=Path, required=True)
    parser.add_argument("--secrets", type=Path, required=True)
    parser.add_argument(
        "--builder-trusted-public-key",
        type=Path,
        help="out-of-band raw Ed25519 public key for the trusted image builder",
    )
    parser.add_argument(
        "--expected-builder-profile-sha256",
        help="out-of-band reviewed SHA-256 of the exact Docker/BuildKit profile",
    )
    parser.add_argument(
        "--known-hosts",
        type=Path,
        help=(
            "private mode-0600 file containing exactly one distinct Ed25519 host key "
            "for each role,address management endpoint"
        ),
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--ansible-playbook",
        type=Path,
        help="absolute path to the explicitly reviewed Ansible 2.19.12 executable",
    )
    parser.add_argument(
        "--ansible-playbook-sha256",
        help="lowercase SHA-256 of the explicit Ansible executable",
    )
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--probe-output", type=Path)
    parser.add_argument("--probe-signing-key", type=Path)
    parser.add_argument("--probe-trusted-public-key", type=Path)
    arguments = parser.parse_args(argv)
    try:
        probe_inputs = (
            arguments.probe,
            arguments.probe_output is not None,
            arguments.probe_signing_key is not None,
            arguments.probe_trusted_public_key is not None,
        )
        if any(probe_inputs) and not all(probe_inputs):
            _fail(
                "--probe, --probe-output, --probe-signing-key, and "
                "--probe-trusted-public-key must be supplied together"
            )
        if arguments.probe and not arguments.apply:
            _fail("--probe requires --apply; probing an unattested existing plan is disallowed")
        if arguments.apply and arguments.known_hosts is None:
            _fail("--apply requires private exact --known-hosts evidence")
        if arguments.apply and (
            arguments.ansible_playbook is None
            or arguments.ansible_playbook_sha256 is None
        ):
            _fail(
                "--apply requires --ansible-playbook and "
                "--ansible-playbook-sha256"
            )
        if not arguments.apply and arguments.known_hosts is not None:
            _fail("--known-hosts is accepted only with --apply")
        if arguments.builder_trusted_public_key is None:
            _fail("--builder-trusted-public-key is required for every deployment plan")
        if (
            arguments.expected_builder_profile_sha256 is None
            or SHA256.fullmatch(arguments.expected_builder_profile_sha256) is None
        ):
            _fail(
                "--expected-builder-profile-sha256 is required for every deployment plan"
            )
        trusted_builder_public_key = _read_trusted_builder_public_key(
            arguments.builder_trusted_public_key
        )
        with contextlib.ExitStack() as stack:
            _require_exact_orchestrator_source(arguments.source_commit)
            orchestration_root = stack.enter_context(
                _stable_head_source(arguments.source_commit)
            )
            bundle_directory = arguments.bundle
            runtime_image_directory = arguments.runtime_images
            secret_directory = arguments.secrets
            if arguments.apply:
                (
                    bundle_directory,
                    runtime_image_directory,
                    secret_directory,
                ) = stack.enter_context(
                    _stable_input_snapshot(
                        arguments.bundle,
                        arguments.runtime_images,
                        arguments.secrets,
                    )
                )
                _snapshot_vagrant_management_state(orchestration_root)
            plan, host_plans = _compile_deployment(
                source_commit=arguments.source_commit,
                bundle_directory=bundle_directory,
                runtime_image_directory=runtime_image_directory,
                secret_directory=secret_directory,
                trusted_builder_public_key=trusted_builder_public_key,
                expected_builder_profile_sha256=(
                    arguments.expected_builder_profile_sha256
                ),
                orchestration_root=orchestration_root,
            )
            probe_runner = None
            controller_signer_key_id = None
            if arguments.probe:
                probe_runner = _load_probe_runner(orchestration_root)
                probe_runner._private_output_path(arguments.probe_output)
                controller_signer_key_id = probe_runner.controller_signing_identity(
                    arguments.probe_signing_key,
                    arguments.probe_trusted_public_key,
                )
            stable_known_hosts = None
            known_hosts_sha256 = None
            if arguments.apply:
                stable_known_hosts, known_hosts_sha256 = stack.enter_context(
                    _stable_known_hosts(arguments.known_hosts)
                )
                stable_plan_file, stable_plan_file_sha256 = stack.enter_context(
                    _stable_plan_file(arguments.source_commit, host_plans)
                )
                _require_exact_orchestrator_source(arguments.source_commit)
                observed_known_hosts_sha256 = _apply(
                    source_commit=arguments.source_commit,
                    bundle_directory=bundle_directory,
                    runtime_image_directory=runtime_image_directory,
                    secret_directory=secret_directory,
                    expected_plans=host_plans,
                    plan_file=stable_plan_file,
                    expected_plan_file_sha256=stable_plan_file_sha256,
                    known_hosts_file=stable_known_hosts,
                    ansible_playbook=arguments.ansible_playbook,
                    expected_ansible_playbook_sha256=(
                        arguments.ansible_playbook_sha256
                    ),
                    orchestration_root=orchestration_root,
                    expected_known_hosts_sha256=known_hosts_sha256,
                    trusted_builder_public_key=trusted_builder_public_key,
                    expected_builder_profile_sha256=(
                        arguments.expected_builder_profile_sha256
                    ),
                )
                if observed_known_hosts_sha256 != known_hosts_sha256:
                    _fail("applied SSH host trust differs from validated caller evidence")
                _require_exact_orchestrator_source(arguments.source_commit)
                plan = {
                    **plan,
                    "mode": "apply_requested",
                    "managed_hosts_mutated": True,
                    "controller_known_hosts_sha256": known_hosts_sha256,
                    "claim_boundary": "configuration_applied_live_acceptance_not_established",
                }
            if arguments.probe:
                if probe_runner is None:  # pragma: no cover - parser/control-flow invariant
                    _fail("M4j workload probe runner was not preflighted")
                if stable_known_hosts is None or known_hosts_sha256 is None:
                    _fail("M4j probe lacks the stable host-trust copy used for apply")
                setattr(  # noqa: B010 - helper is a dynamically loaded ModuleType
                    probe_runner,
                    "_execute_probe_playbook",
                    lambda **kwargs: _execute_probe_playbook(
                        **kwargs,
                        ansible_playbook=arguments.ansible_playbook,
                        expected_ansible_playbook_sha256=(
                            arguments.ansible_playbook_sha256
                        ),
                        orchestration_root=orchestration_root,
                    ),
                )
                try:
                    probe = probe_runner.run_live_probe(
                        source_commit=arguments.source_commit,
                        application_image_id=plan["application_image_id"],
                        host_plan_semantic_sha256=plan["host_plan_semantic_sha256"],
                        output_path=arguments.probe_output,
                        signing_private_key_path=arguments.probe_signing_key,
                        trusted_public_key_path=arguments.probe_trusted_public_key,
                        known_hosts_file=stable_known_hosts,
                        expected_known_hosts_sha256=known_hosts_sha256,
                    )
                except probe_runner.WorkloadProbeError as exc:
                    raise DeploymentError(str(exc)) from exc
                _require_exact_orchestrator_source(arguments.source_commit)
                probe_payload = probe["payload"]
                plan = {
                    **plan,
                    "mode": "apply_and_probe",
                    "managed_hosts_mutated": True,
                    "live_probe": {
                        "probe_contract_passed": probe_payload[
                            "probe_contract_passed"
                        ],
                        "deployment_acceptance_established": False,
                        "g7_acceptance_established": False,
                        "output": str(arguments.probe_output),
                        "semantic_sha256": probe_payload["semantic_sha256"],
                        "controller_known_hosts_sha256": probe_payload[
                            "controller_known_hosts_sha256"
                        ],
                        "controller_signer_key_id": controller_signer_key_id,
                        "independent_execution_provenance_established": False,
                    },
                    "claim_boundary": (
                        "bounded_local_live_workload_probe_contract_passed_"
                        "production_and_independent_validation_not_established"
                    ),
                }
    except (DeploymentError, OSError, ValueError) as exc:
        print(f"M4j workload deployment rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(plan, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
