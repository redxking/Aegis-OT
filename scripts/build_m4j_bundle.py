"""Build one exact-source M4j application-image distribution bundle.

The build context is exported from a resolved Git commit. The mutable checkout
is never supplied to Docker. A successful build produces one source archive,
one saved application-image archive, and one canonical manifest. Plan-only
output contains the source archive and a manifest, performs no Docker mutation,
and is not an accepted deployment bundle.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import errno
import gzip
import hashlib
import ipaddress
import json
import os
import platform as python_platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast

import yaml  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_GIT = Path("/usr/bin/git")
SCHEMA_VERSION = "m4j-exact-source-application-image-bundle-v2"
PROVENANCE_SCHEMA_VERSION = "aegis-ot-m4j-builder-provenance-v1"
ATTESTATION_SCHEMA_VERSION = "aegis-ot-m4j-builder-attestation-v1"
SOURCE_ARCHIVE_NAME = "source.tar"
IMAGE_ARCHIVE_NAME = "application-image.tar"
MANIFEST_NAME = "manifest.json"
DEFAULT_PLATFORM = "linux/amd64"
INSTALL_TARGET = ".[simulation]"
OCI_REVISION_LABEL = "org.opencontainers.image.revision"
BUILD_INVOCATION_LABEL = "org.aegis-ot.bundle.invocation"
REQUIRED_ARCHIVED_FILES = (
    "Dockerfile",
    ".dockerignore",
    "requirements.lock",
    "pyproject.toml",
    "infra/m4j/topology.yml",
    "scripts/build_m4j_bundle.py",
)
MAX_SOURCE_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_IMAGE_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVED_FILE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVED_TOTAL_BYTES = 512 * 1024 * 1024
MAX_IMAGE_ARCHIVE_MEMBERS = 10_000
MAX_IMAGE_METADATA_BYTES = 4 * 1024 * 1024
MAX_COMMIT_OBJECT_BYTES = 4 * 1024 * 1024
MAX_DOCKER_CLIENT_BYTES = 256 * 1024 * 1024
BUILDER_PROFILE_SCHEMA_VERSION = "aegis-ot-m4j-builder-execution-profile-v1"

TOPOLOGY_SCHEMA_VERSION = "aegis-ot-m4j-topology-v1"
TOPOLOGY_ROLES = ("management", "trust", "agents", "gateway", "ot", "simulation")
TOPOLOGY_NETWORKS: dict[str, dict[str, Any]] = {
    "management": {
        "cidr": "192.168.56.0/24",
        "kind": "host_only",
        "purpose": "ssh_control_only",
        "gateway": "192.168.56.1",
        "internal_name": None,
        "members": list(TOPOLOGY_ROLES),
    },
    "trust_enrollment": {
        "cidr": "192.168.57.0/24",
        "kind": "virtualbox_internal",
        "purpose": "workload_identity_enrollment",
        "gateway": None,
        "internal_name": "aegis-m4j-trust-enrollment",
        "members": ["trust", "agents", "gateway", "ot", "simulation"],
    },
    "agent_lane": {
        "cidr": "192.168.58.0/24",
        "kind": "virtualbox_internal",
        "purpose": "agent_to_gateway_only",
        "gateway": None,
        "internal_name": "aegis-m4j-agent-lane",
        "members": ["agents", "gateway"],
    },
    "control_dmz": {
        "cidr": "192.168.59.0/24",
        "kind": "virtualbox_internal",
        "purpose": "trusted_control_services",
        "gateway": None,
        "internal_name": "aegis-m4j-control-dmz",
        "members": ["trust", "gateway", "ot"],
    },
    "simulation_lane": {
        "cidr": "192.168.60.0/24",
        "kind": "virtualbox_internal",
        "purpose": "plant_access_only",
        "gateway": None,
        "internal_name": "aegis-m4j-simulation-lane",
        "members": ["trust", "ot", "simulation"],
    },
}
TOPOLOGY_NODE_RESOURCES = {
    "management": (1, 2048),
    "trust": (2, 3072),
    "agents": (2, 2048),
    "gateway": (2, 3072),
    "ot": (2, 3072),
    "simulation": (2, 4096),
}

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INVOCATION_ID = re.compile(r"^[0-9a-f]{64}$")
_PLATFORM = re.compile(
    r"^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*"
    r"(?:/[a-z0-9][a-z0-9._-]*)?$"
)
_PINNED_IMAGE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?"
    r"@sha256:[0-9a-f]{64}$"
)
_ARG_PYTHON_IMAGE = re.compile(
    r"^[ \t]*ARG[ \t]+PYTHON_IMAGE=([^ \t\r\n]+)[ \t]*$",
    re.MULTILINE,
)
_FROM = re.compile(r"^[ \t]*FROM[ \t]+([^ \t\r\n]+)", re.MULTILINE)
_DOCKER_LEGACY_CONFIG_NAME = re.compile(r"^([0-9a-f]{64})\.json$")
_OCI_BLOB_NAME = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")
_OCI_INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
_OCI_MANIFEST_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
_OCI_CONFIG_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.config.v1+json",
        "application/vnd.docker.container.image.v1+json",
    }
)
_OCI_IDENTITY_LAYER_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.docker.image.rootfs.diff.tar",
    }
)
_OCI_GZIP_LAYER_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
    }
)
_UNSAFE_SECRET_SUFFIXES = frozenset(
    {".key", ".pem", ".p12", ".pfx", ".jks", ".private"}
)
_UNSAFE_SECRET_NAMES = frozenset(
    {".env", "id_rsa", "id_ed25519", "credentials", "credentials.json"}
)

_ACTIVE_DOCKER_BOUNDARY: dict[str, Any] | None = None


class BundleError(RuntimeError):
    """An exact-source M4j bundle could not be established."""


def _closed_git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _run(
    *args: str,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    if args and args[0] == "docker":
        boundary = _ACTIVE_DOCKER_BOUNDARY
        if boundary is None:
            raise BundleError(
                "Docker execution requires an active closed trusted-builder boundary"
            )
        if len(args) >= 2 and args[1] == "buildx":
            command = (str(boundary["buildx_plugin_path"]), *args[2:])
        else:
            command = (
                str(boundary["client_execution_path"]),
                "--config",
                str(boundary["docker_config"]),
                "--host",
                f"unix://{boundary['socket_path']}",
                *args[1:],
            )
        environment = cast(dict[str, str], boundary["environment"])
    elif args and args[0] == "git":
        if not TRUSTED_GIT.is_file() or not os.access(TRUSTED_GIT, os.X_OK):
            raise BundleError("pinned /usr/bin/git executable is unavailable")
        command = (
            str(TRUSTED_GIT),
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.pager=cat",
            *args[1:],
        )
        environment = _closed_git_environment()
    else:
        raise BundleError("builder attempted an unsupported external command")
    completed = subprocess.run(  # noqa: S603 - fixed argv, never a shell command
        command,
        cwd=cwd or ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise BundleError(f"command failed ({' '.join(args)}): {detail[-4000:]}")
    return completed


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _load_builder_signer(path: Path) -> tuple[Ed25519PrivateKey, bytes]:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    except OSError as exc:
        raise BundleError("trusted-builder signing key is unavailable") from exc
    else:
        raise BundleError("trusted-builder signing key must remain outside the checkout")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.absolute(), flags)
    except OSError as exc:
        raise BundleError("trusted-builder signing key could not be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 32
        ):
            raise BundleError(
                "trusted-builder signing key must be an owned mode-0600 raw Ed25519 key"
            )
        material = os.read(descriptor, 33)
        if len(material) != metadata.st_size or os.read(descriptor, 1):
            raise BundleError("trusted-builder signing key changed while being read")
    finally:
        os.close(descriptor)
    try:
        signer = Ed25519PrivateKey.from_private_bytes(material)
    except ValueError as exc:  # pragma: no cover - length is checked above
        raise BundleError("trusted-builder signing key is invalid") from exc
    return signer, signer.public_key().public_bytes_raw()


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _file_evidence(
    path: Path,
    *,
    maximum_bytes: int,
    require_nonempty: bool = True,
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BundleError(f"bundle artifact is unavailable: {path.name}") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise BundleError(f"bundle artifact is not a regular file: {path.name}")
    if metadata.st_size > maximum_bytes or (require_nonempty and metadata.st_size == 0):
        raise BundleError(f"bundle artifact size is invalid: {path.name}")
    digest = hashlib.sha256()
    read = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                read += len(chunk)
                if read > maximum_bytes:
                    raise BundleError(f"bundle artifact exceeds its limit: {path.name}")
                digest.update(chunk)
    except OSError as exc:
        raise BundleError(f"bundle artifact cannot be read: {path.name}") from exc
    if read != metadata.st_size:
        raise BundleError(f"bundle artifact changed while hashing: {path.name}")
    return {
        "path": path.name,
        "sha256": digest.hexdigest(),
        "size_bytes": read,
    }


def _require_protected_path_ancestry(path: Path, *, label: str) -> None:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BundleError(f"{label} path is unavailable") from exc
    if resolved != path:
        raise BundleError(f"{label} path must contain no symbolic links")
    current = path.parent
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise BundleError(f"{label} path ancestry is unavailable") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, os.getuid()}
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise BundleError(
                f"{label} path ancestry must be root/caller-owned and non-writable "
                "by group or other users"
            )
        if current.parent == current:
            break
        current = current.parent


def _protected_docker_executable_evidence(
    path: Path,
    expected_sha256: str,
    *,
    label: str,
) -> dict[str, Any]:
    if not path.is_absolute() or _SHA256.fullmatch(expected_sha256) is None:
        raise BundleError(
            f"{label} requires an absolute path and lowercase SHA-256"
        )
    evidence, _material = _read_protected_docker_executable(
        path,
        expected_sha256,
        label=label,
    )
    return evidence


def _read_protected_docker_executable(
    path: Path,
    expected_sha256: str,
    *,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    if not path.is_absolute() or _SHA256.fullmatch(expected_sha256) is None:
        raise BundleError(
            f"{label} requires an absolute path and lowercase SHA-256"
        )
    try:
        resolved = path.resolve(strict=True)
        path_metadata = path.lstat()
    except OSError as exc:
        raise BundleError(f"explicit {label} is unavailable") from exc
    if resolved != path or path.is_symlink():
        raise BundleError(f"{label} path must be canonical and non-symbolic")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BundleError(f"explicit {label} could not be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.getuid()}
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not metadata.st_mode & stat.S_IXUSR
            or metadata.st_size <= 0
            or metadata.st_size > MAX_DOCKER_CLIENT_BYTES
            or (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
            )
            != (
                path_metadata.st_dev,
                path_metadata.st_ino,
                path_metadata.st_size,
            )
        ):
            raise BundleError(
                f"{label} must be an absolute, protected, non-linked executable"
            )
        material = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            material.extend(chunk)
            if len(material) > MAX_DOCKER_CLIENT_BYTES:
                raise BundleError(f"{label} exceeds its size limit")
        final_metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    digest = hashlib.sha256(material).hexdigest()
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_size != metadata.st_size
        or len(material) != metadata.st_size
        or digest != expected_sha256
    ):
        raise BundleError(f"{label} bytes differ from the supplied SHA-256")
    return {
        "path": str(path),
        "sha256": expected_sha256,
        "size_bytes": len(material),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }, bytes(material)


def _docker_client_evidence(path: Path, expected_sha256: str) -> dict[str, Any]:
    return _protected_docker_executable_evidence(
        path,
        expected_sha256,
        label="Docker client",
    )


def _docker_buildx_plugin_evidence(
    path: Path,
    expected_sha256: str,
) -> dict[str, Any]:
    return _protected_docker_executable_evidence(
        path,
        expected_sha256,
        label="Docker Buildx plugin",
    )


def _docker_socket_identity(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise BundleError("Docker endpoint must be an absolute Unix socket path")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise BundleError("explicit Docker Unix socket is unavailable") from exc
    _require_protected_path_ancestry(path, label="Docker Unix socket")
    if (
        resolved != path
        or path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid not in {0, os.getuid()}
        or metadata.st_mode & stat.S_IWOTH
    ):
        raise BundleError(
            "Docker endpoint must be a protected real Unix socket owned by root or the caller"
        )
    return {
        "transport": "unix",
        "path": str(path),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }


def _require_docker_boundary_unchanged(boundary: dict[str, Any]) -> None:
    client = cast(dict[str, Any], boundary["client"])
    buildx_plugin = cast(dict[str, Any], boundary["buildx_plugin"])
    endpoint = cast(dict[str, Any], boundary["endpoint"])
    staged_plugin = cast(Path, boundary["buildx_plugin_path"])
    staged_client = cast(Path, boundary["client_execution_path"])
    staged_client_evidence = _file_evidence(
        staged_client,
        maximum_bytes=MAX_DOCKER_CLIENT_BYTES,
    )
    staged_evidence = _file_evidence(
        staged_plugin,
        maximum_bytes=MAX_DOCKER_CLIENT_BYTES,
    )
    if (
        _docker_client_evidence(
            cast(Path, boundary["client_path"]),
            cast(str, client["sha256"]),
        )
        != client
        or staged_client.is_symlink()
        or staged_client_evidence["sha256"] != client["sha256"]
        or staged_client_evidence["size_bytes"] != client["size_bytes"]
        or stat.S_IMODE(staged_client.lstat().st_mode) != 0o700
        or _docker_buildx_plugin_evidence(
            cast(Path, boundary["buildx_plugin_source_path"]),
            cast(str, buildx_plugin["sha256"]),
        )
        != buildx_plugin
        or staged_plugin.is_symlink()
        or staged_evidence["sha256"] != buildx_plugin["sha256"]
        or staged_evidence["size_bytes"] != buildx_plugin["size_bytes"]
        or stat.S_IMODE(staged_plugin.lstat().st_mode) != 0o700
        or _docker_socket_identity(cast(Path, boundary["socket_path"])) != endpoint
        or _file_evidence(
            cast(Path, boundary["docker_config_file"]),
            maximum_bytes=MAX_IMAGE_METADATA_BYTES,
        )
        != boundary["docker_config_evidence"]
    ):
        raise BundleError(
            "Docker client, Buildx plugin, configuration, or Unix endpoint identity "
            "changed during the build"
        )
    boundary["final_verified"] = True


@contextlib.contextmanager
def _closed_docker_boundary(
    *,
    client_path: Path,
    expected_client_sha256: str,
    buildx_plugin_path: Path,
    expected_buildx_plugin_sha256: str,
    socket_path: Path,
) -> Iterator[dict[str, Any]]:
    global _ACTIVE_DOCKER_BOUNDARY
    if _ACTIVE_DOCKER_BOUNDARY is not None:
        raise BundleError("nested or concurrent Docker builder execution is forbidden")
    client, client_material = _read_protected_docker_executable(
        client_path,
        expected_client_sha256,
        label="Docker client",
    )
    buildx_plugin, buildx_plugin_material = _read_protected_docker_executable(
        buildx_plugin_path,
        expected_buildx_plugin_sha256,
        label="Docker Buildx plugin",
    )
    endpoint = _docker_socket_identity(socket_path)
    container = Path(tempfile.mkdtemp(prefix="aegis-m4j-docker-boundary-"))
    container.chmod(0o700)
    directories = {
        name: container / name
        for name in (
            "home",
            "docker-config",
            "buildx-config",
            "cli-bin",
            "cli-plugins",
            "tmp",
        )
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    if any(any(directory.iterdir()) for directory in directories.values()):
        raise BundleError("fresh Docker builder configuration is not empty")
    staged_client = directories["cli-bin"] / "docker"
    staged_client.write_bytes(client_material)
    staged_client.chmod(0o700)
    _fsync_file(staged_client)
    staged_client_evidence = _file_evidence(
        staged_client,
        maximum_bytes=MAX_DOCKER_CLIENT_BYTES,
    )
    if (
        staged_client_evidence["sha256"] != client["sha256"]
        or staged_client_evidence["size_bytes"] != client["size_bytes"]
        or _docker_client_evidence(client_path, expected_client_sha256) != client
    ):
        raise BundleError("Docker client changed while it was staged")
    staged_plugin = directories["cli-plugins"] / "docker-buildx"
    staged_plugin.write_bytes(buildx_plugin_material)
    staged_plugin.chmod(0o700)
    _fsync_file(staged_plugin)
    staged_evidence = _file_evidence(
        staged_plugin,
        maximum_bytes=MAX_DOCKER_CLIENT_BYTES,
    )
    if (
        staged_evidence["sha256"] != buildx_plugin["sha256"]
        or staged_evidence["size_bytes"] != buildx_plugin["size_bytes"]
        or _docker_buildx_plugin_evidence(
            buildx_plugin_path,
            expected_buildx_plugin_sha256,
        )
        != buildx_plugin
    ):
        raise BundleError("Docker Buildx plugin changed while it was staged")
    docker_config_file = directories["docker-config"] / "config.json"
    docker_config_file.write_bytes(
        _canonical_bytes(
            {"cliPluginsExtraDirs": [str(directories["cli-plugins"])]}
        )
        + b"\n"
    )
    docker_config_file.chmod(0o600)
    _fsync_file(docker_config_file)
    docker_config_evidence = _file_evidence(
        docker_config_file,
        maximum_bytes=MAX_IMAGE_METADATA_BYTES,
    )
    environment = {
        "BUILDX_CONFIG": str(directories["buildx-config"]),
        "DOCKER_BUILDKIT": "1",
        "DOCKER_CONFIG": str(directories["docker-config"]),
        "DOCKER_HOST": f"unix://{socket_path}",
        "HOME": str(directories["home"]),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(directories["tmp"]),
    }
    boundary: dict[str, Any] = {
        "client_path": client_path,
        "client_execution_path": staged_client,
        "client": client,
        "buildx_plugin_source_path": buildx_plugin_path,
        "buildx_plugin_path": staged_plugin,
        "buildx_plugin": buildx_plugin,
        "socket_path": socket_path,
        "endpoint": endpoint,
        "docker_config": directories["docker-config"],
        "docker_config_file": docker_config_file,
        "docker_config_evidence": docker_config_evidence,
        "environment": environment,
        "final_verified": False,
    }
    _ACTIVE_DOCKER_BOUNDARY = boundary
    try:
        yield boundary
    finally:
        try:
            if not boundary["final_verified"]:
                _require_docker_boundary_unchanged(boundary)
        finally:
            _ACTIVE_DOCKER_BOUNDARY = None
            if container.exists() and not container.is_symlink():
                shutil.rmtree(container)


def _fsync_file(path: Path) -> None:
    try:
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
    except OSError as exc:
        raise BundleError(f"bundle artifact could not be synchronized: {path.name}") from exc


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise BundleError(f"bundle directory could not be synchronized: {path}") from exc


def _resolve_commit(reference: str) -> dict[str, str]:
    if (
        not reference
        or reference.strip() != reference
        or reference.casefold() == "unknown"
        or reference.startswith("-")
        or any(ord(character) < 32 or character.isspace() for character in reference)
        or len(reference) > 512
    ):
        raise BundleError("Git commit reference is malformed or unknown")
    resolved = _run(
        "git",
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        f"{reference}^{{commit}}",
        check=False,
    )
    commit = resolved.stdout.strip()
    if resolved.returncode != 0 or _GIT_OBJECT.fullmatch(commit) is None:
        raise BundleError("Git commit reference did not resolve to a full commit")
    object_type = _run("git", "cat-file", "-t", commit).stdout.strip()
    if object_type != "commit":
        raise BundleError("resolved Git object is not a commit")
    tree = _run("git", "rev-parse", f"{commit}^{{tree}}").stdout.strip()
    if _GIT_OBJECT.fullmatch(tree) is None:
        raise BundleError("resolved Git tree identifier is malformed")
    committed_at = _run(
        "git",
        "show",
        "-s",
        "--format=%cI",
        commit,
    ).stdout.strip()
    if not committed_at or "\n" in committed_at:
        raise BundleError("resolved Git commit timestamp is malformed")
    commit_binding = _read_git_commit_binding(commit, expected_tree=tree)
    return {
        "requested_reference": reference,
        "commit": commit,
        "tree": tree,
        "committed_at": committed_at,
        "object_format": cast(str, commit_binding["object_format"]),
        "commit_object_base64": cast(str, commit_binding["commit_object_base64"]),
    }


def _git_object_id(kind: str, material: bytes, *, object_format: str) -> str:
    if kind not in {"blob", "tree", "commit"}:
        raise BundleError("Git object type is unsupported")
    header = f"{kind} {len(material)}\0".encode("ascii")
    if object_format == "sha1":
        return hashlib.sha1(header + material, usedforsecurity=False).hexdigest()
    if object_format == "sha256":
        return hashlib.sha256(header + material).hexdigest()
    raise BundleError("Git object format is unsupported")


def _commit_tree(material: bytes, *, object_format: str) -> str:
    header, separator, _message = material.partition(b"\n\n")
    if not separator:
        raise BundleError("Git commit object lacks a message separator")
    oid_length = 40 if object_format == "sha1" else 64
    tree_lines = [line for line in header.splitlines() if line.startswith(b"tree ")]
    if len(tree_lines) != 1:
        raise BundleError("Git commit object does not declare exactly one tree")
    try:
        tree = tree_lines[0].removeprefix(b"tree ").decode("ascii")
    except UnicodeDecodeError as exc:
        raise BundleError("Git commit tree identifier is not ASCII") from exc
    if re.fullmatch(rf"[0-9a-f]{{{oid_length}}}", tree) is None:
        raise BundleError("Git commit tree identifier is malformed")
    return tree


def _read_git_commit_binding(commit: str, *, expected_tree: str) -> dict[str, Any]:
    object_format = "sha1" if len(commit) == 40 else "sha256"
    if not TRUSTED_GIT.is_file() or not os.access(TRUSTED_GIT, os.X_OK):
        raise BundleError("pinned /usr/bin/git executable is unavailable")
    completed = subprocess.run(  # noqa: S603 - resolved Git and fixed object read
        (
            str(TRUSTED_GIT),
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.pager=cat",
            "cat-file",
            "commit",
            commit,
        ),
        cwd=ROOT,
        check=False,
        capture_output=True,
        env=_closed_git_environment(),
    )
    material = completed.stdout
    if (
        completed.returncode != 0
        or not material
        or len(material) > MAX_COMMIT_OBJECT_BYTES
        or _git_object_id("commit", material, object_format=object_format) != commit
        or _commit_tree(material, object_format=object_format) != expected_tree
    ):
        raise BundleError("Git commit object does not cryptographically bind its tree")
    return {
        "object_format": object_format,
        "commit_object_base64": base64.b64encode(material).decode("ascii"),
    }


def _archive_commit_id(archive: Path) -> str:
    if not TRUSTED_GIT.is_file() or not os.access(TRUSTED_GIT, os.X_OK):
        raise BundleError("pinned /usr/bin/git executable is unavailable")
    try:
        with archive.open("rb") as handle:
            completed = subprocess.run(  # noqa: S603 - resolved Git executable
                (
                    str(TRUSTED_GIT),
                    "--no-replace-objects",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.attributesFile=/dev/null",
                    "-c",
                    "core.pager=cat",
                    "get-tar-commit-id",
                ),
                cwd=ROOT,
                check=False,
                stdin=handle,
                capture_output=True,
                env=_closed_git_environment(),
            )
    except OSError as exc:
        raise BundleError("source archive commit marker could not be read") from exc
    try:
        commit = completed.stdout.decode("ascii").strip()
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
    except UnicodeError as exc:
        raise BundleError("source archive commit marker was malformed") from exc
    if completed.returncode != 0 or _GIT_OBJECT.fullmatch(commit) is None:
        raise BundleError(
            "source archive lacks an exact Git commit marker"
            + (f": {detail[-1000:]}" if detail else "")
        )
    return commit


def _member_path(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise BundleError("source archive member path is malformed")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", "..", ".git"} for part in path.parts):
        raise BundleError(f"source archive member path is unsafe: {name!r}")
    return path


def _looks_like_secret(path: PurePosixPath) -> bool:
    name = path.name.casefold()
    suffix = PurePosixPath(name).suffix
    return name in _UNSAFE_SECRET_NAMES or suffix in _UNSAFE_SECRET_SUFFIXES


def _write_archive_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
) -> None:
    source = archive.extractfile(member)
    if source is None:
        raise BundleError(f"source archive file cannot be read: {member.name}")
    descriptor = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o755 if member.mode & 0o111 else 0o644,
    )
    copied = 0
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            while chunk := source.read(1024 * 1024):
                copied += len(chunk)
                if copied > member.size or copied > MAX_ARCHIVED_FILE_BYTES:
                    raise BundleError(
                        f"source archive member exceeds its declared size: {member.name}"
                    )
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        source.close()
        os.close(descriptor)
    if copied != member.size:
        raise BundleError(f"source archive member size changed: {member.name}")


def _safe_extract_source(archive_path: Path, destination: Path) -> tuple[str, ...]:
    if destination.exists() or destination.is_symlink():
        raise BundleError("source extraction destination already exists")
    destination.mkdir(mode=0o700)
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            paths: dict[str, tuple[PurePosixPath, tarfile.TarInfo]] = {}
            total_size = 0
            member_count = 0
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise BundleError("source archive member count is invalid")
                path = _member_path(member.name)
                normalized = path.as_posix().rstrip("/")
                if not normalized or normalized in paths:
                    raise BundleError("source archive contains duplicate member paths")
                if not member.isfile() and not member.isdir():
                    raise BundleError(
                        f"source archive contains an unsafe member type: {member.name}"
                    )
                if member.isfile():
                    if _looks_like_secret(path):
                        raise BundleError(
                            f"source archive contains a secret-like file: {member.name}"
                        )
                    if member.size < 0 or member.size > MAX_ARCHIVED_FILE_BYTES:
                        raise BundleError(
                            f"source archive member size is invalid: {member.name}"
                        )
                    total_size += member.size
                    if total_size > MAX_ARCHIVED_TOTAL_BYTES:
                        raise BundleError("source archive expanded size exceeds its limit")
                paths[normalized] = (path, member)

            if member_count == 0:
                raise BundleError("source archive member count is invalid")

            for path, member in sorted(
                paths.values(), key=lambda item: (len(item[0].parts), item[0].as_posix())
            ):
                target = destination.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                _write_archive_member(archive, member, target)
    except (tarfile.TarError, OSError) as exc:
        raise BundleError("source archive could not be safely extracted") from exc
    _fsync_directory(destination)
    return tuple(
        sorted(
            path.as_posix()
            for path, member in paths.values()
            if member.isfile()
        )
    )


def _source_archive_tree_id(archive_path: Path, *, object_format: str) -> str:
    files: dict[tuple[str, ...], tuple[str, str]] = {}
    declared_directories: set[tuple[str, ...]] = set()
    archive_paths: set[str] = set()
    total_size = 0
    member_count = 0
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise BundleError("source archive member count is invalid")
                path = _member_path(member.name)
                normalized = path.as_posix().rstrip("/")
                if (
                    not normalized
                    or normalized != member.name.rstrip("/")
                    or normalized in archive_paths
                ):
                    raise BundleError("source archive contains duplicate member paths")
                archive_paths.add(normalized)
                if member.isdir():
                    if member.size != 0:
                        raise BundleError("source archive directory size is invalid")
                    declared_directories.add(path.parts)
                    continue
                if not member.isfile() or _looks_like_secret(path):
                    raise BundleError("source archive contains a non-Git-safe member")
                if member.size < 0 or member.size > MAX_ARCHIVED_FILE_BYTES:
                    raise BundleError("source archive member size is invalid")
                total_size += member.size
                if total_size > MAX_ARCHIVED_TOTAL_BYTES:
                    raise BundleError("source archive expanded size exceeds its limit")
                source = archive.extractfile(member)
                if source is None:
                    raise BundleError("source archive member could not be read")
                header = f"blob {member.size}\0".encode("ascii")
                digest = (
                    hashlib.sha1(usedforsecurity=False)
                    if object_format == "sha1"
                    else hashlib.sha256()
                    if object_format == "sha256"
                    else None
                )
                if digest is None:
                    raise BundleError("Git object format is unsupported")
                digest.update(header)
                copied = 0
                try:
                    while chunk := source.read(1024 * 1024):
                        copied += len(chunk)
                        if copied > member.size:
                            raise BundleError("source archive member exceeded its size")
                        digest.update(chunk)
                finally:
                    source.close()
                if copied != member.size:
                    raise BundleError("source archive member size changed")
                files[path.parts] = (
                    "100755" if member.mode & 0o111 else "100644",
                    digest.hexdigest(),
                )
    except (OSError, tarfile.TarError) as exc:
        raise BundleError("source archive tree could not be inspected") from exc
    if not files:
        raise BundleError("source archive contains no Git files")
    implied_directories = {
        parts[:depth]
        for parts in files
        for depth in range(1, len(parts))
    }
    if declared_directories != implied_directories:
        raise BundleError(
            "source archive directory members do not exactly match tracked file ancestors"
        )

    def build_tree(prefix: tuple[str, ...]) -> str:
        direct_files: dict[str, tuple[str, str]] = {}
        child_directories: set[str] = set()
        for parts, evidence in files.items():
            if parts[: len(prefix)] != prefix:
                continue
            if len(parts) == len(prefix) + 1:
                direct_files[parts[-1]] = evidence
            elif len(parts) > len(prefix) + 1:
                child_directories.add(parts[len(prefix)])
        if set(direct_files) & child_directories:
            raise BundleError("source archive contains a file/directory collision")
        entries: list[tuple[bytes, bytes]] = []
        for name, (mode, object_id) in direct_files.items():
            try:
                encoded_name = name.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise BundleError("source archive path is not strict UTF-8") from exc
            entries.append(
                (
                    encoded_name,
                    mode.encode("ascii")
                    + b" "
                    + encoded_name
                    + b"\0"
                    + bytes.fromhex(object_id),
                )
            )
        for name in child_directories:
            encoded_name = name.encode("utf-8")
            object_id = build_tree((*prefix, name))
            entries.append(
                (
                    encoded_name + b"/",
                    b"40000 " + encoded_name + b"\0" + bytes.fromhex(object_id),
                )
            )
        content = b"".join(value for _sort_key, value in sorted(entries))
        return _git_object_id("tree", content, object_format=object_format)

    return build_tree(())


def _validate_source_archive_binding(
    archive_path: Path,
    *,
    expected_commit: str,
    source_binding: dict[str, Any],
) -> dict[str, str]:
    object_format = source_binding.get("git_object_format")
    encoded_commit = source_binding.get("commit_object_base64")
    declared_tree = source_binding.get("git_tree")
    expected_format = "sha1" if len(expected_commit) == 40 else "sha256"
    if (
        object_format != expected_format
        or not isinstance(encoded_commit, str)
        or not isinstance(declared_tree, str)
    ):
        raise BundleError("source Git object binding is malformed")
    try:
        commit_material = base64.b64decode(encoded_commit, validate=True)
    except ValueError as exc:
        raise BundleError("source Git commit object is not canonical base64") from exc
    if (
        not commit_material
        or len(commit_material) > MAX_COMMIT_OBJECT_BYTES
        or _git_object_id("commit", commit_material, object_format=object_format)
        != expected_commit
    ):
        raise BundleError("source Git commit object digest does not match the request")
    committed_tree = _commit_tree(commit_material, object_format=object_format)
    archived_tree = _source_archive_tree_id(
        archive_path,
        object_format=object_format,
    )
    if declared_tree != committed_tree or archived_tree != committed_tree:
        raise BundleError("source archive tree does not match the committed Git tree")
    if _archive_commit_id(archive_path) != expected_commit:
        raise BundleError("source archive commit marker does not match the request")
    return {
        "git_object_format": object_format,
        "commit_sha": expected_commit,
        "tree_sha": committed_tree,
        "archive_tree_sha": archived_tree,
    }


def _archived_input_evidence(context: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for relative in REQUIRED_ARCHIVED_FILES:
        path = context / relative
        evidence = _file_evidence(
            path,
            maximum_bytes=MAX_ARCHIVED_FILE_BYTES,
        )
        result[relative] = {
            "sha256": evidence["sha256"],
            "size_bytes": evidence["size_bytes"],
        }
    return result


def _builder_helper_binding(
    context: Path,
    *,
    object_format: str,
) -> dict[str, Any]:
    relative = "scripts/build_m4j_bundle.py"
    archived_path = context / relative
    archived = _file_evidence(
        archived_path,
        maximum_bytes=MAX_IMAGE_METADATA_BYTES,
    )
    live_path = Path(__file__).absolute()
    try:
        metadata = live_path.lstat()
        resolved = live_path.resolve(strict=True)
    except OSError as exc:
        raise BundleError("executing builder helper is unavailable") from exc
    if (
        resolved != live_path
        or live_path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.getuid()}
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise BundleError("executing builder helper is not a protected regular file")
    live_before = _file_evidence(
        live_path,
        maximum_bytes=MAX_IMAGE_METADATA_BYTES,
    )
    try:
        material = live_path.read_bytes()
    except OSError as exc:
        raise BundleError("executing builder helper could not be read") from exc
    live_after = _file_evidence(
        live_path,
        maximum_bytes=MAX_IMAGE_METADATA_BYTES,
    )
    if (
        live_before != live_after
        or live_before["sha256"] != archived["sha256"]
        or live_before["size_bytes"] != archived["size_bytes"]
        or len(material) != live_before["size_bytes"]
        or hashlib.sha256(material).hexdigest() != live_before["sha256"]
    ):
        raise BundleError(
            "executing builder helper bytes differ from the exact source commit"
        )
    return {
        "path": relative,
        "sha256": live_before["sha256"],
        "size_bytes": live_before["size_bytes"],
        "git_object_format": object_format,
        "git_blob_id": _git_object_id(
            "blob",
            material,
            object_format=object_format,
        ),
    }


def _mapping(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise BundleError(f"{label} must be a string-keyed mapping")
    return value


def _validate_m4j_topology(path: Path) -> dict[str, Any]:
    evidence = _file_evidence(path, maximum_bytes=MAX_ARCHIVED_FILE_BYTES)
    try:
        material = path.read_text(encoding="utf-8")
        raw = yaml.safe_load(material)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise BundleError("archived M4j topology is not valid strict UTF-8 YAML") from exc
    if len(material.encode("utf-8")) != evidence["size_bytes"]:
        raise BundleError("archived M4j topology changed during validation")
    topology = _mapping(raw, label="archived M4j topology")
    expected_top_level = {
        "schema_version",
        "deployment_status",
        "claim_boundary",
        "box",
        "bootstrap_nat",
        "capacity",
        "addressing",
        "networks",
        "nodes",
    }
    if set(topology) != expected_top_level:
        raise BundleError("archived M4j topology fields do not match the closed contract")
    if topology["schema_version"] != TOPOLOGY_SCHEMA_VERSION:
        raise BundleError("archived M4j topology schema version is unsupported")
    if topology["deployment_status"] != "configuration_only" or topology[
        "claim_boundary"
    ] != "no_live_deployment_or_multi_host_isolation_evidence":
        raise BundleError("archived M4j topology claim boundary is not closed")
    if _mapping(topology["box"], label="archived M4j topology box") != {
        "name": "generic/ubuntu2204",
        "version": "4.3.12",
        "provider": "virtualbox",
        "check_update": False,
    }:
        raise BundleError("archived M4j topology box contract is not pinned")
    if _mapping(
        topology["bootstrap_nat"], label="archived M4j bootstrap NAT"
    ) != {
        "enabled": True,
        "purpose": "vagrant_bootstrap_only",
        "application_bindings_allowed": False,
        "guest_ssh_port": 22,
    }:
        raise BundleError("archived M4j topology bootstrap NAT contract is invalid")

    capacity = _mapping(topology["capacity"], label="archived M4j capacity")
    if capacity != {
        "max_total_cpus": 12,
        "max_total_memory_mb": 18432,
        "max_node_cpus": 4,
        "max_node_memory_mb": 4096,
    }:
        raise BundleError("archived M4j topology capacity contract is invalid")
    addressing = _mapping(topology["addressing"], label="archived M4j addressing")
    if addressing != {"ipv4_prefix_length": 24, "first_node_host_offset": 10}:
        raise BundleError("archived M4j topology addressing contract is invalid")

    networks = _mapping(topology["networks"], label="archived M4j networks")
    if list(networks) != list(TOPOLOGY_NETWORKS):
        raise BundleError("archived M4j topology network set or order is invalid")
    parsed_networks: dict[str, ipaddress.IPv4Network] = {}
    for name, expected in TOPOLOGY_NETWORKS.items():
        actual = _mapping(networks[name], label=f"archived M4j network {name}")
        if actual != expected:
            raise BundleError(f"archived M4j network contract is invalid: {name}")
        try:
            parsed = ipaddress.ip_network(actual["cidr"], strict=True)
        except ValueError as exc:
            raise BundleError(f"archived M4j network CIDR is invalid: {name}") from exc
        if not isinstance(parsed, ipaddress.IPv4Network) or not parsed.is_private:
            raise BundleError(f"archived M4j network CIDR is unsafe: {name}")
        parsed_networks[name] = parsed
    parsed_values = list(parsed_networks.values())
    if any(
        left.overlaps(right)
        for index, left in enumerate(parsed_values)
        for right in parsed_values[index + 1 :]
    ):
        raise BundleError("archived M4j topology networks overlap")

    nodes = _mapping(topology["nodes"], label="archived M4j nodes")
    if tuple(nodes) != TOPOLOGY_ROLES:
        raise BundleError("archived M4j topology node set or order is invalid")
    configured_addresses: set[ipaddress.IPv4Address] = set()
    total_cpus = 0
    total_memory = 0
    first_offset = addressing["first_node_host_offset"]
    for role_index, role in enumerate(TOPOLOGY_ROLES):
        node = _mapping(nodes[role], label=f"archived M4j node {role}")
        if set(node) != {"hostname", "cpus", "memory_mb", "interfaces"}:
            raise BundleError(f"archived M4j node fields are invalid: {role}")
        cpus, memory_mb = TOPOLOGY_NODE_RESOURCES[role]
        if (
            node["hostname"] != f"aegis-{role}"
            or node["cpus"] != cpus
            or node["memory_mb"] != memory_mb
        ):
            raise BundleError(f"archived M4j node resources are invalid: {role}")
        total_cpus += cpus
        total_memory += memory_mb
        interfaces = _mapping(
            node["interfaces"], label=f"archived M4j node interfaces {role}"
        )
        expected_interfaces = [
            name
            for name, network in TOPOLOGY_NETWORKS.items()
            if role in network["members"]
        ]
        if list(interfaces) != expected_interfaces:
            raise BundleError(f"archived M4j node interfaces are invalid: {role}")
        for network_name, raw_address in interfaces.items():
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise BundleError(
                    f"archived M4j node address is invalid: {role}/{network_name}"
                ) from exc
            network = parsed_networks[network_name]
            if (
                not isinstance(address, ipaddress.IPv4Address)
                or address != network.network_address + first_offset + role_index
                or address in configured_addresses
                or str(address) == TOPOLOGY_NETWORKS[network_name]["gateway"]
            ):
                raise BundleError(
                    f"archived M4j node address contract is invalid: {role}/{network_name}"
                )
            configured_addresses.add(address)
    if total_cpus > capacity["max_total_cpus"] or total_memory > capacity[
        "max_total_memory_mb"
    ]:
        raise BundleError("archived M4j topology exceeds its aggregate capacity")
    verified_again = _file_evidence(path, maximum_bytes=MAX_ARCHIVED_FILE_BYTES)
    if verified_again != evidence:
        raise BundleError("archived M4j topology changed during contract validation")
    return {
        "schema_version": TOPOLOGY_SCHEMA_VERSION,
        "deployment_status": "configuration_only",
        "claim_boundary": "no_live_deployment_or_multi_host_isolation_evidence",
        "node_count": len(nodes),
        "network_count": len(networks),
        "contract_validated": True,
    }


def _pinned_base_image(dockerfile: Path) -> str:
    evidence = _file_evidence(
        dockerfile,
        maximum_bytes=MAX_ARCHIVED_FILE_BYTES,
    )
    try:
        material = dockerfile.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise BundleError("archived Dockerfile is not strict UTF-8") from exc
    if len(material.encode("utf-8")) != evidence["size_bytes"]:
        raise BundleError("archived Dockerfile changed during validation")
    arguments: list[str] = _ARG_PYTHON_IMAGE.findall(material)
    from_values: list[str] = _FROM.findall(material)
    if len(arguments) != 1 or from_values != ["${PYTHON_IMAGE}"]:
        raise BundleError("archived Dockerfile base-image contract is not closed")
    reference = arguments[0]
    if _PINNED_IMAGE.fullmatch(reference) is None or reference.endswith(":latest"):
        raise BundleError("archived Dockerfile base image is not digest-pinned")
    return reference


def _export_source(
    *,
    commit: str,
    archive_path: Path,
    context: Path,
) -> dict[str, Any]:
    if _GIT_OBJECT.fullmatch(commit) is None:
        raise BundleError("source export commit is malformed")
    if archive_path.exists() or archive_path.is_symlink() or context.exists():
        raise BundleError("source export paths must not exist")
    _run(
        "git",
        "archive",
        "--format=tar",
        f"--output={archive_path}",
        commit,
    )
    archive_path.chmod(0o600)
    _fsync_file(archive_path)
    archive_evidence = _file_evidence(
        archive_path,
        maximum_bytes=MAX_SOURCE_ARCHIVE_BYTES,
    )
    if _archive_commit_id(archive_path) != commit:
        raise BundleError("source archive commit marker does not match the selected commit")
    archived_files = _safe_extract_source(archive_path, context)
    inputs = _archived_input_evidence(context)
    base_image = _pinned_base_image(context / "Dockerfile")
    topology_contract = _validate_m4j_topology(context / "infra/m4j/topology.yml")
    verified_again = _file_evidence(
        archive_path,
        maximum_bytes=MAX_SOURCE_ARCHIVE_BYTES,
    )
    if verified_again != archive_evidence:
        raise BundleError("source archive changed during extraction and validation")
    return {
        "archive": archive_evidence,
        "archived_file_count": len(archived_files),
        "archived_inputs": inputs,
        "pinned_base_image": base_image,
        "topology_contract": topology_contract,
        "secret_like_member_count": 0,
    }


def _target_platform(value: str) -> dict[str, str | None]:
    if _PLATFORM.fullmatch(value) is None:
        raise BundleError("target platform must be an explicit OS/architecture[/variant]")
    parts = value.split("/")
    return {
        "requested": value,
        "os": parts[0],
        "architecture": parts[1],
        "variant": parts[2] if len(parts) == 3 else None,
    }


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"JSON document contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise BundleError(f"JSON document contains forbidden constant: {value}")


def _load_json(raw: str, *, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise BundleError(f"{label} did not return JSON") from exc


def _json_object(raw: str, *, label: str) -> dict[str, Any]:
    value = _load_json(raw, label=label)
    if not isinstance(value, dict):
        raise BundleError(f"{label} JSON root is not an object")
    return value


def _inspect_image(
    reference: str,
    *,
    expected_commit: str,
    expected_platform: dict[str, str | None],
    expected_tag: str | None,
    expected_invocation: str | None = None,
) -> dict[str, Any]:
    completed = _run("docker", "image", "inspect", reference)
    try:
        values = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BundleError("Docker image inspection did not return JSON") from exc
    if (
        not isinstance(values, list)
        or len(values) != 1
        or not isinstance(values[0], dict)
    ):
        raise BundleError("Docker image inspection returned an unexpected shape")
    inspected = values[0]
    image_id = inspected.get("Id")
    if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
        raise BundleError("application image ID is empty or malformed")
    config = inspected.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    revision = labels.get(OCI_REVISION_LABEL) if isinstance(labels, dict) else None
    if revision != expected_commit:
        raise BundleError("application image OCI revision does not match the commit")
    invocation = (
        labels.get(BUILD_INVOCATION_LABEL) if isinstance(labels, dict) else None
    )
    if expected_invocation is not None and invocation != expected_invocation:
        raise BundleError("application image invocation ownership label does not match")
    actual_os = inspected.get("Os")
    actual_architecture = inspected.get("Architecture")
    raw_variant = inspected.get("Variant")
    actual_variant = raw_variant if isinstance(raw_variant, str) and raw_variant else None
    if (
        actual_os != expected_platform["os"]
        or actual_architecture != expected_platform["architecture"]
        or actual_variant != expected_platform["variant"]
    ):
        raise BundleError("application image platform does not match the target")
    raw_tags = inspected.get("RepoTags") or []
    if not isinstance(raw_tags, list) or not all(
        isinstance(item, str) for item in raw_tags
    ):
        raise BundleError("application image repository tags are malformed")
    if expected_tag is not None and expected_tag not in raw_tags:
        raise BundleError("application image tag does not bind the inspected image")
    raw_digests = inspected.get("RepoDigests") or []
    if not isinstance(raw_digests, list) or not all(
        isinstance(item, str)
        and re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", item) is not None
        for item in raw_digests
    ):
        raise BundleError("application image repository digests are malformed")
    return {
        "image_id": image_id,
        "oci_revision": revision,
        "build_invocation": invocation,
        "platform": {
            "os": actual_os,
            "architecture": actual_architecture,
            "variant": actual_variant,
        },
        "repo_digests": sorted(set(raw_digests)),
    }


def _docker_command_detail(completed: subprocess.CompletedProcess[str]) -> str:
    return (completed.stderr.strip() or completed.stdout.strip())[-4000:]


def _docker_image_document_if_present(reference: str) -> dict[str, Any] | None:
    inspected = _run("docker", "image", "inspect", reference, check=False)
    if inspected.returncode != 0:
        stdout = inspected.stdout.strip()
        stderr = inspected.stderr.strip()
        missing_messages = {
            f"Error response from daemon: No such image: {reference}",
            f"Error: No such image: {reference}",
        }
        if stdout in {"", "[]"} and stderr in missing_messages:
            return None
        detail = _docker_command_detail(inspected)
        raise BundleError(
            "Docker image presence could not be established"
            + (f": {detail}" if detail else "")
        )
    try:
        values = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise BundleError("Docker image presence inspection did not return JSON") from exc
    if (
        not isinstance(values, list)
        or len(values) != 1
        or not isinstance(values[0], dict)
    ):
        raise BundleError("Docker image presence inspection returned an unexpected shape")
    document = values[0]
    image_id = document.get("Id")
    if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
        raise BundleError("Docker image presence inspection returned a malformed ID")
    return document


def _docker_invocation_image_ids(invocation_id: str) -> set[str]:
    if _INVOCATION_ID.fullmatch(invocation_id) is None:
        raise BundleError("Docker build invocation identifier is malformed")
    completed = _run(
        "docker",
        "image",
        "ls",
        "--filter",
        f"label={BUILD_INVOCATION_LABEL}={invocation_id}",
        "--quiet",
        "--no-trunc",
    )
    image_ids = {line.strip() for line in completed.stdout.splitlines() if line.strip()}
    if any(_IMAGE_ID.fullmatch(image_id) is None for image_id in image_ids):
        raise BundleError("Docker invocation image lookup returned a malformed ID")
    if len(image_ids) > 1:
        raise BundleError("Docker invocation label resolved to multiple images")
    return image_ids


def _read_image_id_file(path: Path) -> str:
    evidence_before = _file_evidence(path, maximum_bytes=256)
    try:
        material = path.read_bytes()
        image_id = material.decode("ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise BundleError("Docker build image-ID file is malformed") from exc
    evidence_after = _file_evidence(path, maximum_bytes=256)
    if (
        evidence_after != evidence_before
        or evidence_before["size_bytes"] != len(material)
        or evidence_before["sha256"] != _sha256(material)
    ):
        raise BundleError("Docker build image-ID file changed while being read")
    if _IMAGE_ID.fullmatch(image_id) is None:
        raise BundleError("Docker build image-ID file did not contain an immutable ID")
    return image_id


def _read_docker_archive_member(
    archive_path: Path,
    member_name: str,
) -> tuple[bytes, dict[str, tuple[str, int]]]:
    found: bytes | None = None
    member_types: dict[str, tuple[str, int]] = {}
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            member_count = 0
            total_size = 0
            for member in archive:
                member_count += 1
                if member_count > MAX_IMAGE_ARCHIVE_MEMBERS:
                    raise BundleError("saved image archive member count exceeds its limit")
                normalized = _member_path(member.name).as_posix().rstrip("/")
                if (
                    not normalized
                    or normalized != member.name.rstrip("/")
                    or normalized in member_types
                ):
                    raise BundleError("saved image archive contains duplicate member paths")
                if member.isfile():
                    if member.size < 0 or member.size > MAX_IMAGE_ARCHIVE_BYTES:
                        raise BundleError("saved image archive member size is invalid")
                    total_size += member.size
                    if total_size > MAX_IMAGE_ARCHIVE_BYTES:
                        raise BundleError(
                            "saved image archive expanded size exceeds its limit"
                        )
                    member_types[normalized] = ("file", member.size)
                elif member.isdir():
                    if member.size != 0:
                        raise BundleError(
                            "saved image archive directory size is invalid"
                        )
                    member_types[normalized] = ("directory", 0)
                else:
                    raise BundleError("saved image archive contains an unsafe member type")
                if normalized != member_name:
                    continue
                if not member.isfile() or member.size < 0 or member.size > MAX_IMAGE_METADATA_BYTES:
                    raise BundleError(
                        f"saved image archive metadata member is invalid: {member_name}"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise BundleError(
                        f"saved image archive metadata cannot be read: {member_name}"
                    )
                try:
                    found = source.read(MAX_IMAGE_METADATA_BYTES + 1)
                finally:
                    source.close()
                if len(found) != member.size:
                    raise BundleError(
                        f"saved image archive metadata size changed: {member_name}"
                    )
            if member_count == 0:
                raise BundleError("saved image archive is empty")
    except (tarfile.TarError, OSError) as exc:
        raise BundleError("saved image archive could not be safely inspected") from exc
    if found is None:
        raise BundleError(f"saved image archive lacks {member_name}")
    return found, member_types


def _verify_docker_archive_payloads(
    archive_path: Path,
    *,
    expectations: dict[str, tuple[str, int | None, bool]],
    expected_member_types: dict[str, tuple[str, int]],
) -> list[dict[str, Any]]:
    """Verify saved layer bytes without extracting or buffering whole layers.

    Each expectation is ``digest, stored_size, hash_uncompressed``. OCI
    descriptor digests cover the stored blob bytes. Docker image ``diff_ids``
    cover the uncompressed layer tar stream, so gzip storage is decoded before
    hashing and other recognized compression formats fail closed.
    """

    if not expectations:
        return []
    for path, (
        requested_digest,
        expected_size,
        _hash_uncompressed,
    ) in expectations.items():
        if (
            _member_path(path).as_posix() != path
            or _SHA256.fullmatch(requested_digest) is None
        ):
            raise BundleError("saved image layer verification request is malformed")
        evidence = expected_member_types.get(path)
        if evidence is None or evidence[0] != "file":
            raise BundleError("saved image archive lacks a referenced layer payload")
        if expected_size is not None and evidence[1] != expected_size:
            raise BundleError("saved image layer descriptor size is invalid")

    verified: dict[str, dict[str, Any]] = {}
    observed_member_types: dict[str, tuple[str, int]] = {}
    decoded_total = 0
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            member_count = 0
            stored_total = 0
            for member in archive:
                member_count += 1
                if member_count > MAX_IMAGE_ARCHIVE_MEMBERS:
                    raise BundleError(
                        "saved image archive member count exceeds its limit"
                    )
                normalized = _member_path(member.name).as_posix().rstrip("/")
                if (
                    not normalized
                    or normalized != member.name.rstrip("/")
                    or normalized in observed_member_types
                ):
                    raise BundleError(
                        "saved image archive contains duplicate member paths"
                    )
                if member.isfile():
                    if member.size < 0 or member.size > MAX_IMAGE_ARCHIVE_BYTES:
                        raise BundleError("saved image archive member size is invalid")
                    stored_total += member.size
                    if stored_total > MAX_IMAGE_ARCHIVE_BYTES:
                        raise BundleError(
                            "saved image archive expanded size exceeds its limit"
                        )
                    observed_member_types[normalized] = ("file", member.size)
                elif member.isdir():
                    if member.size != 0:
                        raise BundleError(
                            "saved image archive directory size is invalid"
                        )
                    observed_member_types[normalized] = ("directory", 0)
                else:
                    raise BundleError("saved image archive contains an unsafe member type")
                expectation = expectations.get(normalized)
                if expectation is None:
                    continue
                expected_digest, expected_size, hash_uncompressed = expectation
                if expected_size is not None and member.size != expected_size:
                    raise BundleError("saved image layer descriptor size is invalid")
                source = archive.extractfile(member)
                if source is None:
                    raise BundleError("saved image layer payload cannot be read")
                reader: Any = source
                storage_encoding = "identity"
                try:
                    if hash_uncompressed:
                        prefix = cast(Any, source).peek(6)[:6]
                        if prefix.startswith(b"\x1f\x8b"):
                            reader = gzip.GzipFile(fileobj=source, mode="rb")
                            storage_encoding = "gzip"
                        elif (
                            prefix.startswith(b"\x28\xb5\x2f\xfd")
                            or prefix.startswith(b"\xfd7zXZ\x00")
                            or prefix.startswith(b"BZh")
                        ):
                            raise BundleError(
                                "saved image legacy layer compression is unsupported"
                            )
                    hasher = hashlib.sha256()
                    hashed_size = 0
                    while chunk := reader.read(1024 * 1024):
                        hashed_size += len(chunk)
                        decoded_total += len(chunk)
                        if (
                            hashed_size > MAX_IMAGE_ARCHIVE_BYTES
                            or decoded_total > MAX_IMAGE_ARCHIVE_BYTES
                        ):
                            raise BundleError(
                                "saved image layer expanded size exceeds its limit"
                            )
                        hasher.update(chunk)
                    if not hash_uncompressed and hashed_size != member.size:
                        raise BundleError("saved image layer payload size changed")
                    if hash_uncompressed and source.tell() != member.size:
                        raise BundleError("saved image compressed layer was not fully consumed")
                finally:
                    if reader is not source:
                        reader.close()
                    source.close()
                actual_digest = hasher.hexdigest()
                if actual_digest != expected_digest:
                    semantics = (
                        "uncompressed diff ID" if hash_uncompressed else "descriptor"
                    )
                    raise BundleError(
                        f"saved image layer {semantics} digest is invalid"
                    )
                verified[normalized] = {
                    "path": normalized,
                    "sha256": actual_digest,
                    "size_bytes": hashed_size,
                    "digest_semantics": (
                        "uncompressed_diff_id"
                        if hash_uncompressed
                        else "stored_descriptor_digest"
                    ),
                    "storage_encoding": storage_encoding,
                }
            if member_count == 0:
                raise BundleError("saved image archive is empty")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise BundleError("saved image archive layer payload could not be verified") from exc
    if observed_member_types != expected_member_types:
        raise BundleError("saved image archive changed during layer verification")
    if set(verified) != set(expectations):
        raise BundleError("saved image archive lacks a referenced layer payload")
    return [verified[path] for path in expectations]


def _digest_value(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None:
        raise BundleError(f"saved image {label} digest is malformed")
    return value.removeprefix("sha256:")


def _read_oci_blob(
    archive_path: Path,
    *,
    digest: str,
    expected_size: int | None,
    expected_member_types: dict[str, tuple[str, int]],
    label: str,
) -> bytes:
    path = f"blobs/sha256/{digest}"
    member_evidence = expected_member_types.get(path)
    if member_evidence is None or member_evidence[0] != "file":
        raise BundleError(f"saved image archive lacks referenced {label} blob")
    material, member_types = _read_docker_archive_member(archive_path, path)
    if member_types != expected_member_types:
        raise BundleError("saved image archive changed between metadata reads")
    if _sha256(material) != digest:
        raise BundleError(f"saved image {label} blob digest is invalid")
    if expected_size is not None and len(material) != expected_size:
        raise BundleError(f"saved image {label} blob size is invalid")
    return material


def _oci_descriptor(
    value: object,
    *,
    label: str,
    maximum_size: int = MAX_IMAGE_METADATA_BYTES,
) -> tuple[str, int, str, dict[str, Any] | None]:
    descriptor = _mapping(value, label=f"saved image {label} descriptor")
    digest = _digest_value(descriptor.get("digest"), label=label)
    size = descriptor.get("size")
    media_type = descriptor.get("mediaType")
    platform = descriptor.get("platform")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or size > maximum_size
        or not isinstance(media_type, str)
        or not media_type
    ):
        raise BundleError(f"saved image {label} descriptor is malformed")
    if platform is not None:
        platform = _mapping(platform, label=f"saved image {label} platform")
    return digest, size, media_type, platform


def _platform_matches(
    platform: dict[str, Any] | None,
    expected: dict[str, str | None],
) -> bool:
    if platform is None:
        return False
    raw_variant = platform.get("variant")
    if raw_variant is not None and not isinstance(raw_variant, str):
        return False
    if not {"os", "architecture"}.issubset(platform) or not set(platform).issubset(
        {"os", "architecture", "variant"}
    ):
        return False
    variant = raw_variant or None
    return (
        platform.get("os") == expected["os"]
        and platform.get("architecture") == expected["architecture"]
        and variant == expected["variant"]
    )


def _resolve_oci_image_id(
    archive_path: Path,
    *,
    root_digest: str,
    expected_platform: dict[str, str | None],
    member_types: dict[str, tuple[str, int]],
) -> dict[str, Any]:
    current_digest = root_digest
    current_size: int | None = None
    current_media_type: str | None = None
    visited: set[str] = set()
    root_media_type: str | None = None
    for _depth in range(4):
        if current_digest in visited:
            raise BundleError("saved image OCI descriptor chain contains a cycle")
        visited.add(current_digest)
        material = _read_oci_blob(
            archive_path,
            digest=current_digest,
            expected_size=current_size,
            expected_member_types=member_types,
            label="OCI descriptor",
        )
        try:
            document = _json_object(
                material.decode("utf-8"), label="saved image OCI descriptor"
            )
        except UnicodeError as exc:
            raise BundleError("saved image OCI descriptor is not strict UTF-8") from exc
        media_type = document.get("mediaType")
        if document.get("schemaVersion") != 2 or not isinstance(media_type, str):
            raise BundleError("saved image OCI descriptor contract is malformed")
        if current_media_type is not None and media_type != current_media_type:
            raise BundleError("saved image OCI descriptor media type changed")
        if root_media_type is None:
            root_media_type = media_type
        if media_type in _OCI_INDEX_MEDIA_TYPES:
            raw_manifests = document.get("manifests")
            if not isinstance(raw_manifests, list) or len(raw_manifests) != 1:
                raise BundleError(
                    "saved image OCI index must contain exactly one descriptor"
                )
            candidates: list[tuple[str, int, str]] = []
            for index, raw_descriptor in enumerate(raw_manifests):
                digest, size, descriptor_media_type, platform = _oci_descriptor(
                    raw_descriptor,
                    label=f"OCI index entry {index}",
                )
                if (
                    descriptor_media_type
                    in (_OCI_INDEX_MEDIA_TYPES | _OCI_MANIFEST_MEDIA_TYPES)
                    and _platform_matches(platform, expected_platform)
                ):
                    candidates.append((digest, size, descriptor_media_type))
            if len(candidates) != 1:
                raise BundleError(
                    "saved image OCI index does not select exactly one target platform"
                )
            current_digest, current_size, current_media_type = candidates[0]
            continue
        if media_type in _OCI_MANIFEST_MEDIA_TYPES:
            config_digest, config_size, config_media_type, config_platform = (
                _oci_descriptor(document.get("config"), label="OCI config")
            )
            if (
                config_platform is not None
                or config_media_type not in _OCI_CONFIG_MEDIA_TYPES
            ):
                raise BundleError("saved image OCI config descriptor is invalid")
            raw_layers = document.get("layers")
            if not isinstance(raw_layers, list):
                raise BundleError("saved image OCI layer descriptors are malformed")
            layer_digests: list[str] = []
            layer_media_types: list[str] = []
            layer_expectations: dict[str, tuple[str, int | None, bool]] = {}
            for index, raw_layer in enumerate(raw_layers):
                layer_digest, _layer_size, _layer_media_type, layer_platform = (
                    _oci_descriptor(
                        raw_layer,
                        label=f"OCI layer {index}",
                        maximum_size=MAX_IMAGE_ARCHIVE_BYTES,
                    )
                )
                if layer_platform is not None:
                    raise BundleError("saved image OCI layer descriptor has a platform field")
                if _layer_media_type not in (
                    _OCI_IDENTITY_LAYER_MEDIA_TYPES | _OCI_GZIP_LAYER_MEDIA_TYPES
                ):
                    raise BundleError("saved image OCI layer media type is unsupported")
                layer_member = member_types.get(f"blobs/sha256/{layer_digest}")
                if (
                    layer_member is None
                    or layer_member[0] != "file"
                    or layer_member[1] != _layer_size
                ):
                    raise BundleError("saved image archive lacks a referenced OCI layer")
                layer_digests.append(layer_digest)
                layer_media_types.append(_layer_media_type)
                layer_expectations[f"blobs/sha256/{layer_digest}"] = (
                    layer_digest,
                    _layer_size,
                    False,
                )
            verified_layers = _verify_docker_archive_payloads(
                archive_path,
                expectations=layer_expectations,
                expected_member_types=member_types,
            )
            return {
                "kind": "oci_descriptor_chain",
                "root_digest": root_digest,
                "root_media_type": root_media_type,
                "image_manifest_digest": current_digest,
                "descriptor_digests": sorted(visited),
                "config_digest": config_digest,
                "config_size": config_size,
                "layer_digests": layer_digests,
                "layer_media_types": layer_media_types,
                "verified_layers": verified_layers,
            }
        raise BundleError("saved image OCI descriptor media type is unsupported")
    raise BundleError("saved image OCI descriptor chain exceeds its depth limit")


def _validate_saved_image_archive(
    archive_path: Path,
    *,
    expected_image_id: str,
    expected_commit: str | None,
    expected_platform: dict[str, str | None],
    allow_unreferenced: bool = False,
) -> dict[str, Any]:
    if _IMAGE_ID.fullmatch(expected_image_id) is None:
        raise BundleError("saved image archive expected ID is malformed")
    manifest_bytes, member_types = _read_docker_archive_member(
        archive_path, "manifest.json"
    )
    try:
        manifest = _load_json(
            manifest_bytes.decode("utf-8"),
            label="saved image archive manifest",
        )
    except UnicodeDecodeError as exc:
        raise BundleError("saved image archive manifest is not strict UTF-8") from exc
    if (
        not isinstance(manifest, list)
        or len(manifest) != 1
        or not isinstance(manifest[0], dict)
        or set(manifest[0]) != {"Config", "RepoTags", "Layers"}
    ):
        raise BundleError("saved image archive manifest is not a single-image contract")
    entry = manifest[0]
    config_path = entry["Config"]
    legacy_config = (
        _DOCKER_LEGACY_CONFIG_NAME.fullmatch(config_path)
        if isinstance(config_path, str)
        else None
    )
    oci_config = (
        _OCI_BLOB_NAME.fullmatch(config_path) if isinstance(config_path, str) else None
    )
    if (legacy_config is None and oci_config is None) or member_types.get(
        str(config_path), ("", -1)
    )[0] != "file":
        raise BundleError("saved image archive config reference is malformed")
    layers = entry["Layers"]
    if not isinstance(layers, list) or not layers or not all(
        isinstance(layer, str)
        and _member_path(layer).as_posix() == layer
        and member_types.get(layer, ("", -1))[0] == "file"
        for layer in layers
    ):
        raise BundleError("saved image archive layer references are malformed")
    if len(layers) != len(set(layers)):
        raise BundleError("saved image archive layer references are duplicated")
    raw_repo_tags = entry["RepoTags"]
    if raw_repo_tags is None:
        repo_tags: list[str] = []
    elif isinstance(raw_repo_tags, list) and all(
        isinstance(tag, str) and tag and not any(character.isspace() for character in tag)
        for tag in raw_repo_tags
    ):
        repo_tags = sorted(set(raw_repo_tags))
    else:
        raise BundleError("saved image archive repository tags are malformed")

    config_bytes, config_member_types = _read_docker_archive_member(
        archive_path, config_path
    )
    if config_member_types != member_types:
        raise BundleError("saved image archive changed between metadata reads")
    config_digest = _sha256(config_bytes)
    if legacy_config is not None:
        referenced_config_digest = legacy_config.group(1)
    elif oci_config is not None:
        referenced_config_digest = oci_config.group(1)
    else:  # pragma: no cover - config-reference invariant above
        raise BundleError("saved image archive config reference is malformed")
    if referenced_config_digest != config_digest:
        raise BundleError("saved image config digest does not match its archive reference")
    expected_digest = expected_image_id.removeprefix("sha256:")
    if expected_digest == config_digest:
        image_id_binding: dict[str, Any] = {
            "kind": "legacy_config_digest",
            "root_digest": expected_digest,
            "root_media_type": None,
            "image_manifest_digest": None,
            "config_digest": config_digest,
            "layer_digests": [],
        }
    else:
        image_id_binding = _resolve_oci_image_id(
            archive_path,
            root_digest=expected_digest,
            expected_platform=expected_platform,
            member_types=member_types,
        )
        if image_id_binding["config_digest"] != config_digest:
            raise BundleError(
                "saved image OCI descriptor chain does not bind the archived config"
            )
        if image_id_binding["config_size"] != len(config_bytes):
            raise BundleError("saved image OCI config descriptor size is invalid")
        expected_layer_paths = [
            f"blobs/sha256/{digest}" for digest in image_id_binding["layer_digests"]
        ]
        if layers != expected_layer_paths:
            raise BundleError(
                "saved image legacy manifest and OCI layer references do not agree"
            )
    try:
        config = _json_object(config_bytes.decode("utf-8"), label="saved image config")
    except UnicodeError as exc:
        raise BundleError("saved image config is not strict UTF-8") from exc
    labels_parent = config.get("config")
    labels = labels_parent.get("Labels") if isinstance(labels_parent, dict) else None
    revision = labels.get(OCI_REVISION_LABEL) if isinstance(labels, dict) else None
    raw_variant = config.get("variant")
    if raw_variant is not None and not isinstance(raw_variant, str):
        raise BundleError("saved image config variant is malformed")
    variant = raw_variant if isinstance(raw_variant, str) and raw_variant else None
    if expected_commit is not None and revision != expected_commit:
        raise BundleError("saved image OCI revision does not match the commit")
    if (
        config.get("os") != expected_platform["os"]
        or config.get("architecture") != expected_platform["architecture"]
        or variant != expected_platform["variant"]
    ):
        raise BundleError("saved image config platform does not match the target")
    rootfs = _mapping(config.get("rootfs"), label="saved image config rootfs")
    raw_diff_ids = rootfs.get("diff_ids")
    if rootfs.get("type") != "layers" or not isinstance(raw_diff_ids, list):
        raise BundleError("saved image config rootfs metadata is unsupported")
    if len(raw_diff_ids) != len(layers):
        raise BundleError(
            "saved image config diff ID count does not match archived layers"
        )
    diff_ids = [
        _digest_value(value, label=f"config diff ID {index}")
        for index, value in enumerate(raw_diff_ids)
    ]
    diff_id_expectations: dict[str, tuple[str, int | None, bool]] = {
        layer: (diff_id, None, True)
        for layer, diff_id in zip(layers, diff_ids, strict=True)
    }
    verified_diff_ids = _verify_docker_archive_payloads(
        archive_path,
        expectations=diff_id_expectations,
        expected_member_types=member_types,
    )
    stored_blob_expectations: dict[str, tuple[str, int | None, bool]] = {}
    for layer in layers:
        match = _OCI_BLOB_NAME.fullmatch(layer)
        if match is not None:
            stored_blob_expectations[layer] = (match.group(1), None, False)
    if stored_blob_expectations:
        _verify_docker_archive_payloads(
            archive_path,
            expectations=stored_blob_expectations,
            expected_member_types=member_types,
        )
    if image_id_binding["kind"] == "legacy_config_digest":
        image_id_binding["layer_digests"] = diff_ids
        image_id_binding["verified_layers"] = verified_diff_ids
    else:
        expected_encodings = [
            "identity" if media_type in _OCI_IDENTITY_LAYER_MEDIA_TYPES else "gzip"
            for media_type in image_id_binding["layer_media_types"]
        ]
        if [item["storage_encoding"] for item in verified_diff_ids] != expected_encodings:
            raise BundleError(
                "saved image OCI layer compression differs from its media type"
            )
        image_id_binding["diff_ids"] = diff_ids
        image_id_binding["verified_diff_ids"] = verified_diff_ids
    reachable_files = {"manifest.json", config_path, *layers}
    if image_id_binding["kind"] == "oci_descriptor_chain":
        reachable_files.update(
            f"blobs/sha256/{digest}"
            for digest in image_id_binding["descriptor_digests"]
        )
    implied_directories = {
        "/".join(PurePosixPath(path).parts[:depth])
        for path in reachable_files
        for depth in range(1, len(PurePosixPath(path).parts))
    }
    unexpected = {
        path
        for path, (kind, _size) in member_types.items()
        if (kind == "file" and path not in reachable_files)
        or (kind == "directory" and path not in implied_directories)
    }
    if unexpected and not allow_unreferenced:
        raise BundleError(
            "saved image archive contains unreferenced members: "
            + ", ".join(sorted(unexpected)[:20])
        )
    return {
        "format": "docker-image-save-v1",
        "manifest_image_count": 1,
        "config_path": config_path,
        "config_sha256": config_digest,
        "config_size_bytes": len(config_bytes),
        "image_id_binding": image_id_binding,
        "oci_revision": revision,
        "build_invocation": (
            labels.get(BUILD_INVOCATION_LABEL) if isinstance(labels, dict) else None
        ),
        "platform": {
            "os": config["os"],
            "architecture": config["architecture"],
            "variant": variant,
        },
        "layer_count": len(layers),
        "repo_tags": repo_tags,
        "reachable_members": sorted(reachable_files),
    }


def _canonicalize_saved_image_archive(
    archive_path: Path,
    *,
    expected_image_id: str,
    expected_commit: str | None,
    expected_platform: dict[str, str | None],
) -> dict[str, Any]:
    binding = _validate_saved_image_archive(
        archive_path,
        expected_image_id=expected_image_id,
        expected_commit=expected_commit,
        expected_platform=expected_platform,
        allow_unreferenced=True,
    )
    reachable = set(cast(list[str], binding["reachable_members"]))
    temporary = archive_path.with_name(f".{archive_path.name}.canonical")
    if temporary.exists() or temporary.is_symlink():
        raise BundleError("saved image canonicalization path already exists")
    try:
        with tarfile.open(archive_path, mode="r:") as source_archive, tarfile.open(
            temporary,
            mode="w:",
            format=tarfile.PAX_FORMAT,
        ) as destination_archive:
            for member in source_archive:
                normalized = _member_path(member.name).as_posix().rstrip("/")
                if normalized not in reachable:
                    continue
                if not member.isfile():
                    raise BundleError("reachable image archive member is not regular")
                source = source_archive.extractfile(member)
                if source is None:
                    raise BundleError("reachable image archive member cannot be read")
                canonical_member = tarfile.TarInfo(normalized)
                canonical_member.size = member.size
                canonical_member.mode = 0o600
                canonical_member.mtime = 0
                canonical_member.uid = 0
                canonical_member.gid = 0
                canonical_member.uname = ""
                canonical_member.gname = ""
                try:
                    destination_archive.addfile(canonical_member, source)
                finally:
                    source.close()
        temporary.chmod(0o600)
        _fsync_file(temporary)
        os.replace(temporary, archive_path)
        _fsync_directory(archive_path.parent)
    finally:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
    return _validate_saved_image_archive(
        archive_path,
        expected_image_id=expected_image_id,
        expected_commit=expected_commit,
        expected_platform=expected_platform,
    )


def _remove_docker_reference(reference: str) -> None:
    removed = _run("docker", "image", "rm", reference, check=False)
    if removed.returncode != 0:
        detail = _docker_command_detail(removed)
        raise BundleError(
            "invocation-owned Docker image reference could not be removed"
            + (f": {detail}" if detail else "")
        )


def _cleanup_invocation_owned_image(*, image_id: str, invocation_id: str) -> None:
    if _IMAGE_ID.fullmatch(image_id) is None or _INVOCATION_ID.fullmatch(
        invocation_id
    ) is None:
        raise BundleError("invocation-owned image cleanup identity is malformed")
    document = _docker_image_document_if_present(image_id)
    if document is None:
        return
    config = document.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        not isinstance(labels, dict)
        or labels.get(BUILD_INVOCATION_LABEL) != invocation_id
    ):
        raise BundleError(
            "Docker image ownership changed; refusing destructive cleanup"
        )
    repo_tags = document.get("RepoTags") or []
    repo_digests = document.get("RepoDigests") or []
    if not isinstance(repo_tags, list) or not isinstance(repo_digests, list):
        raise BundleError("invocation-owned image references are malformed")
    if repo_tags or repo_digests:
        return
    _remove_docker_reference(image_id)


def _build_and_save_image(
    *,
    context: Path,
    commit: str,
    base_image: str,
    target: dict[str, str | None],
    image_archive: Path,
) -> dict[str, Any]:
    if not context.is_dir() or context.is_symlink():
        raise BundleError("archived application build context is unavailable")
    if _PINNED_IMAGE.fullmatch(base_image) is None:
        raise BundleError("application image build base is not digest-pinned")
    requested_platform = target.get("requested")
    if not isinstance(requested_platform, str):
        raise BundleError("application image target platform is malformed")
    if image_archive.exists() or image_archive.is_symlink():
        raise BundleError("application image archive path already exists")
    invocation_id = secrets.token_hex(32)
    if _INVOCATION_ID.fullmatch(invocation_id) is None:
        raise BundleError("Docker build invocation identifier is malformed")
    image_id_file = image_archive.with_name(".application-image.iid")
    image_id: str | None = None
    try:
        _run(
            "docker",
            "buildx",
            "build",
            "--load",
            "--platform",
            requested_platform,
            "--pull",
            "--iidfile",
            str(image_id_file),
            "--label",
            f"{BUILD_INVOCATION_LABEL}={invocation_id}",
            "--build-arg",
            f"PYTHON_IMAGE={base_image}",
            "--build-arg",
            f"AEGIS_SOURCE_REVISION={commit}",
            "--build-arg",
            f"AEGIS_INSTALL_TARGET={INSTALL_TARGET}",
            str(context),
        )
        image_id = _read_image_id_file(image_id_file)
        inspected = _inspect_image(
            image_id,
            expected_commit=commit,
            expected_platform=target,
            expected_tag=None,
            expected_invocation=invocation_id,
        )
        if inspected["image_id"] != image_id:
            raise BundleError("application image ID changed before archival")
        _run(
            "docker",
            "image",
            "save",
            f"--output={image_archive}",
            image_id,
        )
        image_archive.chmod(0o600)
        _fsync_file(image_archive)
        archive_binding = _canonicalize_saved_image_archive(
            image_archive,
            expected_image_id=image_id,
            expected_commit=commit,
            expected_platform=target,
        )
        archive_evidence = _file_evidence(
            image_archive,
            maximum_bytes=MAX_IMAGE_ARCHIVE_BYTES,
        )
        verified_binding = _validate_saved_image_archive(
            image_archive,
            expected_image_id=image_id,
            expected_commit=commit,
            expected_platform=target,
        )
        archive_verified_again = _file_evidence(
            image_archive,
            maximum_bytes=MAX_IMAGE_ARCHIVE_BYTES,
        )
        if verified_binding != archive_binding or archive_verified_again != archive_evidence:
            raise BundleError("application image archive changed during validation")
        verified = _inspect_image(
            image_id,
            expected_commit=commit,
            expected_platform=target,
            expected_tag=None,
            expected_invocation=invocation_id,
        )
        if verified["image_id"] != image_id:
            raise BundleError("application image ID changed while its archive was written")
        return {
            "image_built": True,
            "build_invocations": 1,
            "tag": None,
            "image_id": image_id,
            "build_invocation": invocation_id,
            "repo_digests": inspected["repo_digests"],
            "oci_revision": inspected["oci_revision"],
            "platform": inspected["platform"],
            "archive": archive_evidence,
            "archive_binding": archive_binding,
        }
    except Exception as exc:
        try:
            owned_ids = _docker_invocation_image_ids(invocation_id)
            if image_id is not None:
                owned_ids.add(image_id)
            for owned_image_id in sorted(owned_ids):
                _cleanup_invocation_owned_image(
                    image_id=owned_image_id,
                    invocation_id=invocation_id,
                )
        except BundleError as cleanup_exc:
            raise BundleError(
                f"{exc}; invocation-owned Docker cleanup was incomplete: {cleanup_exc}"
            ) from exc
        raise
    finally:
        if image_id_file.exists() and not image_id_file.is_symlink():
            image_id_file.unlink()


def _tool_version(*args: str, label: str) -> str:
    value = _run(*args).stdout.strip()
    if not value or "\n" in value or len(value) > 512:
        raise BundleError(f"{label} tool version is malformed")
    return value


def _version_field(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\n" in value
        or "\r" in value
        or len(value) > 512
    ):
        raise BundleError(f"{label} version field is malformed")
    return value


def _buildx_inspect_field(
    fields: dict[str, str],
    name: str,
    *,
    label: str,
) -> str:
    return _version_field(fields.get(name), label=label)


def _canonical_architecture(value: str) -> str:
    return {
        "aarch64": "arm64",
        "x86_64": "amd64",
    }.get(value.casefold(), value.casefold())


def _parse_buildx_inspect(material: str) -> dict[str, Any]:
    if not material or len(material.encode("utf-8")) > MAX_IMAGE_METADATA_BYTES:
        raise BundleError("Docker Buildx builder profile is unavailable")
    builder_fields: dict[str, str] = {}
    raw_nodes: list[dict[str, str]] = []
    current_node: dict[str, str] | None = None
    in_nodes = False
    field_pattern = re.compile(r"^([A-Za-z][A-Za-z ]*):[ \t]*(.*)$")
    for line in material.splitlines():
        if line == "Nodes:":
            if in_nodes:
                raise BundleError("Docker Buildx builder profile duplicates Nodes")
            in_nodes = True
            continue
        match = field_pattern.fullmatch(line)
        if match is None:
            continue
        name, value = match.groups()
        if not in_nodes:
            if name in builder_fields:
                raise BundleError("Docker Buildx builder identity field is duplicated")
            builder_fields[name] = value
            continue
        if name == "Name":
            if current_node is not None:
                raw_nodes.append(current_node)
            current_node = {"Name": value}
            continue
        if current_node is not None and name in {
            "Endpoint",
            "Status",
            "BuildKit version",
            "Platforms",
        }:
            if name in current_node:
                raise BundleError("Docker BuildKit node identity field is duplicated")
            current_node[name] = value
    if current_node is not None:
        raw_nodes.append(current_node)
    nodes: list[dict[str, Any]] = []
    for index, raw_node in enumerate(raw_nodes):
        status = _buildx_inspect_field(
            raw_node,
            "Status",
            label=f"BuildKit node {index} status",
        )
        if status.casefold() != "running":
            raise BundleError("Docker BuildKit node is not running")
        raw_platforms = _buildx_inspect_field(
            raw_node,
            "Platforms",
            label=f"BuildKit node {index} platforms",
        )
        platforms = sorted(
            {value.strip() for value in raw_platforms.split(",") if value.strip()}
        )
        if not platforms:
            raise BundleError("Docker BuildKit node platforms are malformed")
        nodes.append(
            {
                "name": _buildx_inspect_field(
                    raw_node,
                    "Name",
                    label=f"BuildKit node {index} name",
                ),
                "endpoint": _buildx_inspect_field(
                    raw_node,
                    "Endpoint",
                    label=f"BuildKit node {index} endpoint",
                ),
                "status": status,
                "buildkit_version": _buildx_inspect_field(
                    raw_node,
                    "BuildKit version",
                    label=f"BuildKit node {index} version",
                ),
                "platforms": platforms,
            }
        )
    if not nodes:
        raise BundleError("Docker BuildKit worker profile is unavailable")
    nodes.sort(key=lambda value: (value["name"], value["endpoint"]))
    if len({(node["name"], node["endpoint"]) for node in nodes}) != len(nodes):
        raise BundleError("Docker BuildKit node identities are duplicated")
    return {
        "builder_name": _buildx_inspect_field(
            builder_fields,
            "Name",
            label="Buildx builder name",
        ),
        "driver": _buildx_inspect_field(
            builder_fields,
            "Driver",
            label="Docker Buildx driver",
        ),
        "nodes": nodes,
    }


def _builder_execution_profile(boundary: dict[str, Any]) -> dict[str, Any]:
    raw_version = _run("docker", "version", "--format", "{{json .}}").stdout.strip()
    version = _json_object(raw_version, label="Docker version")
    client = _mapping(version.get("Client"), label="Docker client version")
    server = _mapping(version.get("Server"), label="Docker daemon version")
    server_platform = _mapping(
        server.get("Platform"), label="Docker daemon platform"
    )
    raw_info = _run("docker", "info", "--format", "{{json .}}").stdout.strip()
    info = _json_object(raw_info, label="Docker daemon information")
    buildx = _tool_version("docker", "buildx", "version", label="Docker Buildx")
    raw_builder = _run(
        "docker",
        "buildx",
        "inspect",
        "--bootstrap",
    ).stdout.strip()
    builder = _parse_buildx_inspect(raw_builder)
    security_options = info.get("SecurityOptions")
    if not isinstance(security_options, list) or any(
        not isinstance(value, str) or not value for value in security_options
    ):
        raise BundleError("Docker daemon security profile is malformed")
    daemon = {
        "id": _version_field(info.get("ID"), label="Docker daemon ID"),
        "name": _version_field(info.get("Name"), label="Docker daemon name"),
        "driver": _version_field(info.get("Driver"), label="Docker storage driver"),
        "version": _version_field(server.get("Version"), label="Docker daemon"),
        "git_commit": _version_field(
            server.get("GitCommit"), label="Docker daemon commit"
        ),
        "os": _version_field(server.get("Os"), label="Docker daemon OS"),
        "architecture": _version_field(
            server.get("Arch"), label="Docker daemon architecture"
        ),
        "information_architecture": _version_field(
            info.get("Architecture"),
            label="Docker daemon information architecture",
        ),
        "platform_name": _version_field(
            server_platform.get("Name"), label="Docker daemon platform"
        ),
        "security_options": sorted(security_options),
    }
    if (
        info.get("ServerVersion") != daemon["version"]
        or info.get("OSType") != daemon["os"]
        or _canonical_architecture(cast(str, daemon["information_architecture"]))
        != _canonical_architecture(cast(str, daemon["architecture"]))
    ):
        raise BundleError("Docker daemon version and information profiles disagree")
    return {
        "schema_version": BUILDER_PROFILE_SCHEMA_VERSION,
        "docker_client": {
            **cast(dict[str, Any], boundary["client"]),
            "execution": "private_exact_byte_copy",
            "reported_version": _version_field(
                client.get("Version"), label="Docker client"
            ),
            "reported_git_commit": _version_field(
                client.get("GitCommit"), label="Docker client commit"
            ),
            "reported_os": _version_field(client.get("Os"), label="Docker client OS"),
            "reported_architecture": _version_field(
                client.get("Arch"), label="Docker client architecture"
            ),
        },
        "docker_buildx_plugin": {
            **cast(dict[str, Any], boundary["buildx_plugin"]),
            "execution": "private_exact_byte_copy",
        },
        "endpoint": boundary["endpoint"],
        "daemon": daemon,
        "buildkit": {
            "buildx_version": buildx,
            "builder_name": builder["builder_name"],
            "driver": builder["driver"],
            "nodes": builder["nodes"],
        },
        "environment_policy": {
            "ambient_docker_variables": "excluded",
            "ambient_proxy_variables": "excluded",
            "ambient_path": "excluded",
            "docker_config": "fresh_private_single_pinned_buildx_plugin",
            "buildx_config": "fresh_private_empty",
            "credential_helpers": "excluded_by_empty_config",
            "extra_plugin_directories": "excluded",
            "process_environment_allowlist": sorted(
                cast(dict[str, str], boundary["environment"])
            ),
        },
        "network_policy": {
            "client_endpoint": "explicit_unix_socket_only",
            "base_pull": "registry_network_for_exact_digest_pin_only",
            "build_network": "profiled_daemon_default_network",
        },
        "trusted_boundary": (
            "The exact profiled Docker daemon and BuildKit worker are explicitly "
            "trusted to execute the signed build recipe correctly; this attestation "
            "does not independently derive or prove their behavior."
        ),
    }


def inspect_builder_profile(
    *,
    docker_client: Path,
    docker_client_sha256: str,
    docker_buildx_plugin: Path,
    docker_buildx_plugin_sha256: str,
    docker_socket: Path,
) -> dict[str, Any]:
    with _closed_docker_boundary(
        client_path=docker_client,
        expected_client_sha256=docker_client_sha256,
        buildx_plugin_path=docker_buildx_plugin,
        expected_buildx_plugin_sha256=docker_buildx_plugin_sha256,
        socket_path=docker_socket,
    ) as boundary:
        profile = _builder_execution_profile(boundary)
        _require_docker_boundary_unchanged(boundary)
    return {
        "profile": profile,
        "profile_sha256": _canonical_sha256(profile),
    }


def _docker_tool_versions(profile: dict[str, Any]) -> dict[str, str]:
    client = cast(dict[str, Any], profile["docker_client"])
    daemon = cast(dict[str, Any], profile["daemon"])
    buildkit = cast(dict[str, Any], profile["buildkit"])
    return {
        "docker_client": " ".join(
            (
                cast(str, client["reported_version"]),
                cast(str, client["reported_git_commit"]),
                f"{client['reported_os']}/{client['reported_architecture']}",
            )
        ),
        "docker_daemon": " ".join(
            (
                cast(str, daemon["version"]),
                cast(str, daemon["git_commit"]),
                f"{daemon['os']}/{daemon['architecture']}",
            )
        ),
        "docker_daemon_platform": cast(str, daemon["platform_name"]),
        "docker_buildx": cast(str, buildkit["buildx_version"]),
        "docker_buildx_driver": cast(str, buildkit["driver"]),
        "buildkit_worker": ",".join(
            cast(str, node["buildkit_version"])
            for node in cast(list[dict[str, Any]], buildkit["nodes"])
        ),
    }


def _tool_versions(
    *,
    plan_only: bool = False,
    builder_profile: dict[str, Any] | None = None,
) -> dict[str, str]:
    versions = {
        "builder": SCHEMA_VERSION,
        "git": _tool_version("git", "--version", label="Git"),
        "python": (
            f"{python_platform.python_implementation()} "
            f"{python_platform.python_version()}"
        ),
    }
    if plan_only:
        versions["docker_build"] = "not_invoked_plan_only"
    else:
        if builder_profile is None:
            raise BundleError("accepted build lacks a trusted-builder execution profile")
        versions.update(_docker_tool_versions(builder_profile))
    return versions


def _build_contract(
    *,
    revision: dict[str, str],
    source: dict[str, Any],
    target: dict[str, str | None],
) -> dict[str, Any]:
    return {
        "dockerfile": "Dockerfile",
        "install_target": INSTALL_TARGET,
        "pinned_base_image": source["pinned_base_image"],
        "source_revision_build_argument": revision["commit"],
        "target_platform": target,
        "tag_policy": "untagged_load_saved_by_immutable_image_id",
        "docker_build_secret_mount_count": 0,
        "docker_build_secret_mount_scope": (
            "No --secret mount arguments are supplied by this builder; the "
            "secret-like source-name rejection is a bounded heuristic, not proof "
            "that arbitrary committed content contains no secret material."
        ),
    }


def _builder_provenance_statement(
    *,
    source: dict[str, Any],
    image: dict[str, Any],
    build_contract: dict[str, Any],
    tools: dict[str, str],
    builder_helper: dict[str, Any],
    builder_profile: dict[str, Any],
    key_id: str,
) -> dict[str, Any]:
    context = {
        "archive": source["archive"],
        "archived_file_count": source["archived_file_count"],
        "archived_inputs": source["archived_inputs"],
        "tree_binding": source["tree_binding"],
    }
    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "purpose": "aegis-ot-m4j-exact-source-application-image",
        "builder": {
            "identity": f"ed25519-sha256:{key_id}",
            "key_id": key_id,
            "helper": builder_helper,
            "execution_profile": builder_profile,
            "execution_profile_sha256": _canonical_sha256(builder_profile),
            "tool_versions": tools,
        },
        "source": {
            "git_commit": source["git_commit"],
            "git_tree": source["git_tree"],
            "git_object_format": source["git_object_format"],
            "context_sha256": _canonical_sha256(context),
            **context,
        },
        "build": {
            **build_contract,
            "build_arguments": {
                "AEGIS_INSTALL_TARGET": build_contract["install_target"],
                "AEGIS_SOURCE_REVISION": build_contract[
                    "source_revision_build_argument"
                ],
                "PYTHON_IMAGE": build_contract["pinned_base_image"],
            },
            "dockerignore": source["archived_inputs"][".dockerignore"],
            "dockerfile_input": source["archived_inputs"]["Dockerfile"],
            "lockfile_input": source["archived_inputs"]["requirements.lock"],
            "pyproject_input": source["archived_inputs"]["pyproject.toml"],
        },
        "subject": {
            "image_id": image["image_id"],
            "oci_revision": image["oci_revision"],
            "platform": image["platform"],
            "build_invocation": image["build_invocation"],
            "archive": image["archive"],
            "archive_binding": image["archive_binding"],
        },
    }


def _sign_builder_attestation(
    *,
    source: dict[str, Any],
    image: dict[str, Any],
    build_contract: dict[str, Any],
    tools: dict[str, str],
    builder_helper: dict[str, Any],
    builder_profile: dict[str, Any],
    signer: Ed25519PrivateKey,
    public_key: bytes,
) -> dict[str, Any]:
    if len(public_key) != 32:
        raise BundleError("trusted-builder public identity is malformed")
    key_id = hashlib.sha256(public_key).hexdigest()
    statement = _builder_provenance_statement(
        source=source,
        image=image,
        build_contract=build_contract,
        tools=tools,
        builder_helper=builder_helper,
        builder_profile=builder_profile,
        key_id=key_id,
    )
    material = _canonical_bytes(statement)
    signature = signer.sign(material)
    if len(signature) != 64:
        raise BundleError("trusted-builder signature is malformed")
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "statement_sha256": hashlib.sha256(material).hexdigest(),
        "statement": statement,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }


def _manifest(
    *,
    revision: dict[str, str],
    source: dict[str, Any],
    image: dict[str, Any],
    target: dict[str, str | None],
    tools: dict[str, str],
    plan_only: bool,
    builder_helper: dict[str, Any] | None = None,
    builder_profile: dict[str, Any] | None = None,
    builder_signer: Ed25519PrivateKey | None = None,
    builder_public_key: bytes | None = None,
) -> dict[str, Any]:
    image_built = image.get("image_built") is True
    if plan_only == image_built:
        raise BundleError("bundle mode and image-build evidence are inconsistent")
    if image.get("tag") is not None:
        raise BundleError("bundle image evidence violates the untagged build contract")
    accepted = image_built and not plan_only
    if accepted != (
        builder_signer is not None
        and builder_public_key is not None
        and builder_helper is not None
        and builder_profile is not None
    ):
        raise BundleError(
            "accepted bundles require exactly one explicit trusted-builder signing key"
        )
    manifest_source = {
        "requested_reference": revision["requested_reference"],
        "git_commit": revision["commit"],
        "git_tree": revision["tree"],
        "git_object_format": revision["object_format"],
        "commit_object_base64": revision["commit_object_base64"],
        "committed_at": revision["committed_at"],
        "context_origin": "git_archive_of_exact_commit",
        "mutable_worktree_used": False,
        "archive": source["archive"],
        "archived_file_count": source["archived_file_count"],
        "archived_inputs": source["archived_inputs"],
        "topology_contract": source["topology_contract"],
        "secret_like_member_count": source["secret_like_member_count"],
        "tree_binding": source["tree_binding"],
    }
    build_contract = _build_contract(
        revision=revision,
        source=source,
        target=target,
    )
    attestation = (
        _sign_builder_attestation(
            source=manifest_source,
            image=image,
            build_contract=build_contract,
            tools=tools,
            builder_helper=cast(dict[str, Any], builder_helper),
            builder_profile=cast(dict[str, Any], builder_profile),
            signer=cast(Ed25519PrivateKey, builder_signer),
            public_key=cast(bytes, builder_public_key),
        )
        if accepted
        else None
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "plan_only" if plan_only else "build",
        "accepted_deploy_bundle": accepted,
        "source": manifest_source,
        "application_image": image,
        "build_contract": build_contract,
        "tool_versions": dict(sorted(tools.items())),
        "builder_attestation": attestation,
        "distribution_boundary": {
            "single_build": (
                "The application image is built at most once from the exact archived "
                "commit context."
            ),
            "distribute_identical_image": (
                "Consumers receive the one saved image archive bound to the verified "
                "image ID and OCI revision; they do not rebuild from a mutable checkout."
            ),
            "plan_only": (
                "Plan-only validates and retains exact source but builds no image and "
                "is not an accepted deployment bundle."
            ),
            "not_established": [
                "deployment",
                "runtime_acceptance",
                "external_validation",
            ],
        },
    }


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise BundleError("bundle manifest path already exists")
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(_canonical_bytes(manifest))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _validate_output_target(output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise BundleError("refusing to overwrite an existing M4j bundle path")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise BundleError("M4j bundle parent must be an existing non-symlink directory")
    if output.name in {"", ".", ".."}:
        raise BundleError("M4j bundle output name is malformed")


def _publish_directory_noreplace(source: Path, destination: Path) -> None:
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    result: int
    if sys.platform == "darwin":
        rename_exclusive = 0x00000004
        libc = ctypes.CDLL(None, use_errno=True)
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise BundleError("atomic no-replace directory publication is unavailable")
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = int(renamex_np(source_bytes, destination_bytes, rename_exclusive))
    elif sys.platform.startswith("linux"):
        at_fdcwd = -100
        rename_noreplace = 1
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise BundleError("atomic no-replace directory publication is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = int(
            renameat2(
                at_fdcwd,
                source_bytes,
                at_fdcwd,
                destination_bytes,
                rename_noreplace,
            )
        )
    elif os.name == "nt":  # pragma: no cover - Windows rename is no-clobber
        try:
            os.rename(source, destination)
        except FileExistsError as exc:
            raise BundleError("refusing to overwrite an existing M4j bundle path") from exc
        except OSError as exc:
            raise BundleError("M4j bundle could not be atomically published") from exc
        return
    else:  # pragma: no cover - accepted builds fail closed on unknown kernels
        raise BundleError("atomic no-replace directory publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise BundleError("refusing to overwrite an existing M4j bundle path")
    raise BundleError(
        "M4j bundle could not be atomically published: "
        f"{os.strerror(error_number)}"
    )


def build_bundle(
    output: Path,
    *,
    commit_reference: str = "HEAD",
    target_platform: str = DEFAULT_PLATFORM,
    plan_only: bool = False,
    builder_signing_key: Path | None = None,
    docker_client: Path | None = None,
    docker_client_sha256: str | None = None,
    docker_buildx_plugin: Path | None = None,
    docker_buildx_plugin_sha256: str | None = None,
    docker_socket: Path | None = None,
    expected_builder_profile_sha256: str | None = None,
) -> dict[str, Any]:
    _validate_output_target(output)
    docker_inputs = (
        docker_client,
        docker_client_sha256,
        docker_buildx_plugin,
        docker_buildx_plugin_sha256,
        docker_socket,
        expected_builder_profile_sha256,
    )
    if plan_only:
        if builder_signing_key is not None or any(value is not None for value in docker_inputs):
            raise BundleError(
                "plan-only bundles must not consume signing or Docker trust inputs"
            )
        builder_signer = None
        builder_public_key = None
    else:
        if (
            builder_signing_key is None
            or docker_client is None
            or docker_client_sha256 is None
            or docker_buildx_plugin is None
            or docker_buildx_plugin_sha256 is None
            or docker_socket is None
            or expected_builder_profile_sha256 is None
            or _SHA256.fullmatch(expected_builder_profile_sha256) is None
        ):
            raise BundleError(
                "accepted bundles require the signing key, pinned Docker client/socket, "
                "pinned Buildx plugin, and an out-of-band expected builder profile "
                "SHA-256"
            )
        builder_signer, builder_public_key = _load_builder_signer(
            builder_signing_key
        )
    revision = _resolve_commit(commit_reference)
    target = _target_platform(target_platform)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output.name}.m4j-",
            dir=output.parent,
        )
    )
    staging.chmod(0o700)
    published = False
    built_image: dict[str, Any] | None = None
    docker_stack = contextlib.ExitStack()
    try:
        if plan_only:
            docker_boundary = None
            builder_profile = None
        else:
            docker_boundary = docker_stack.enter_context(
                _closed_docker_boundary(
                    client_path=cast(Path, docker_client),
                    expected_client_sha256=cast(str, docker_client_sha256),
                    buildx_plugin_path=cast(Path, docker_buildx_plugin),
                    expected_buildx_plugin_sha256=cast(
                        str,
                        docker_buildx_plugin_sha256,
                    ),
                    socket_path=cast(Path, docker_socket),
                )
            )
            builder_profile = _builder_execution_profile(docker_boundary)
            if _canonical_sha256(builder_profile) != expected_builder_profile_sha256:
                raise BundleError(
                    "live Docker daemon/BuildKit profile differs from the separately "
                    "reviewed expected SHA-256"
                )
        source_archive = staging / SOURCE_ARCHIVE_NAME
        context = staging / ".archived-build-context"
        source = _export_source(
            commit=revision["commit"],
            archive_path=source_archive,
            context=context,
        )
        source["tree_binding"] = _validate_source_archive_binding(
            source_archive,
            expected_commit=revision["commit"],
            source_binding={
                "git_object_format": revision["object_format"],
                "commit_object_base64": revision["commit_object_base64"],
                "git_tree": revision["tree"],
            },
        )
        builder_helper = _builder_helper_binding(
            context,
            object_format=revision["object_format"],
        )
        tools = _tool_versions(
            plan_only=plan_only,
            builder_profile=builder_profile,
        )
        if plan_only:
            image: dict[str, Any] = {
                "image_built": False,
                "build_invocations": 0,
                "tag": None,
                "image_id": None,
                "build_invocation": None,
                "repo_digests": [],
                "oci_revision": None,
                "platform": None,
                "archive": None,
                "archive_binding": None,
            }
        else:
            image = _build_and_save_image(
                context=context,
                commit=revision["commit"],
                base_image=source["pinned_base_image"],
                target=target,
                image_archive=staging / IMAGE_ARCHIVE_NAME,
            )
            built_image = image
            final_profile = _builder_execution_profile(
                cast(dict[str, Any], docker_boundary)
            )
            final_helper = _builder_helper_binding(
                context,
                object_format=revision["object_format"],
            )
            if (
                final_profile != builder_profile
                or _canonical_sha256(final_profile)
                != expected_builder_profile_sha256
                or final_helper != builder_helper
            ):
                raise BundleError(
                    "trusted builder profile or helper changed during the build"
                )
            _require_docker_boundary_unchanged(
                cast(dict[str, Any], docker_boundary)
            )
        manifest = _manifest(
            revision=revision,
            source=source,
            image=image,
            target=target,
            tools=tools,
            plan_only=plan_only,
            builder_helper=builder_helper if not plan_only else None,
            builder_profile=builder_profile,
            builder_signer=builder_signer,
            builder_public_key=builder_public_key,
        )
        shutil.rmtree(context)
        expected_names = {
            SOURCE_ARCHIVE_NAME,
            MANIFEST_NAME,
            *(() if plan_only else (IMAGE_ARCHIVE_NAME,)),
        }
        source_after = _file_evidence(
            source_archive,
            maximum_bytes=MAX_SOURCE_ARCHIVE_BYTES,
        )
        if source_after != source["archive"]:
            raise BundleError("source archive changed before bundle publication")
        if not plan_only:
            image_after = _file_evidence(
                staging / IMAGE_ARCHIVE_NAME,
                maximum_bytes=MAX_IMAGE_ARCHIVE_BYTES,
            )
            if image_after != image["archive"]:
                raise BundleError("application image archive changed before publication")
        _write_manifest(staging / MANIFEST_NAME, manifest)
        actual_names = {path.name for path in staging.iterdir()}
        if actual_names != expected_names:
            raise BundleError("M4j bundle staging contains partial or extra outputs")
        _fsync_directory(staging)
        _publish_directory_noreplace(staging, output)
        published = True
        _fsync_directory(output.parent)
        return manifest
    except Exception as exc:
        if not published and built_image is not None:
            built_image_id = built_image.get("image_id")
            built_invocation = built_image.get("build_invocation")
            if isinstance(built_image_id, str) and isinstance(built_invocation, str):
                try:
                    _cleanup_invocation_owned_image(
                        image_id=built_image_id,
                        invocation_id=built_invocation,
                    )
                except BundleError as cleanup_exc:
                    raise BundleError(
                        f"{exc}; invocation-owned Docker cleanup was incomplete: "
                        f"{cleanup_exc}"
                    ) from exc
        raise
    finally:
        try:
            docker_stack.close()
        finally:
            if not published and staging.exists() and not staging.is_symlink():
                shutil.rmtree(staging)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--commit", default="HEAD")
    parser.add_argument("--platform", default=DEFAULT_PLATFORM)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument(
        "--inspect-builder-profile",
        action="store_true",
        help=(
            "inspect and print the canonical Docker daemon/BuildKit profile without "
            "building or signing; review its SHA-256 out of band before a build"
        ),
    )
    parser.add_argument(
        "--builder-signing-key",
        type=Path,
        help=(
            "owned mode-0600 raw Ed25519 private key for the explicitly trusted "
            "builder; required for accepted build bundles"
        ),
    )
    parser.add_argument("--docker-client", type=Path)
    parser.add_argument("--docker-client-sha256")
    parser.add_argument("--docker-buildx-plugin", type=Path)
    parser.add_argument("--docker-buildx-plugin-sha256")
    parser.add_argument("--docker-socket", type=Path)
    parser.add_argument("--expected-builder-profile-sha256")
    arguments = parser.parse_args()
    if arguments.inspect_builder_profile:
        if (
            arguments.docker_client is None
            or arguments.docker_client_sha256 is None
            or arguments.docker_buildx_plugin is None
            or arguments.docker_buildx_plugin_sha256 is None
            or arguments.docker_socket is None
        ):
            parser.error(
                "--inspect-builder-profile requires --docker-client, "
                "--docker-client-sha256, --docker-buildx-plugin, "
                "--docker-buildx-plugin-sha256, and --docker-socket"
            )
        if (
            arguments.output is not None
            or arguments.builder_signing_key is not None
            or arguments.expected_builder_profile_sha256 is not None
            or arguments.plan_only
        ):
            parser.error(
                "profile inspection cannot build, sign, publish, or consume an "
                "expected profile hash"
            )
        result = inspect_builder_profile(
            docker_client=arguments.docker_client,
            docker_client_sha256=arguments.docker_client_sha256,
            docker_buildx_plugin=arguments.docker_buildx_plugin,
            docker_buildx_plugin_sha256=arguments.docker_buildx_plugin_sha256,
            docker_socket=arguments.docker_socket,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return
    if arguments.output is None:
        parser.error("bundle construction requires --output")
    manifest = build_bundle(
        arguments.output,
        commit_reference=arguments.commit,
        target_platform=arguments.platform,
        plan_only=arguments.plan_only,
        builder_signing_key=arguments.builder_signing_key,
        docker_client=arguments.docker_client,
        docker_client_sha256=arguments.docker_client_sha256,
        docker_buildx_plugin=arguments.docker_buildx_plugin,
        docker_buildx_plugin_sha256=arguments.docker_buildx_plugin_sha256,
        docker_socket=arguments.docker_socket,
        expected_builder_profile_sha256=(
            arguments.expected_builder_profile_sha256
        ),
    )
    print(
        json.dumps(
            {
                "accepted_deploy_bundle": manifest["accepted_deploy_bundle"],
                "git_commit": manifest["source"]["git_commit"],
                "image_built": manifest["application_image"]["image_built"],
                "output": str(arguments.output),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
