#!/usr/bin/env python3
"""Prepare closed SSH transport inputs from locally provisioned M4j Vagrant state.

The VM host keys consumed here are exported by the source-bound Vagrant/Ansible
provisioning channel.  They establish trust for this local Vagrant environment;
they are not independent host-identity validation or production trust evidence.
"""

from __future__ import annotations

import argparse
import base64
import binascii
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

import yaml  # type: ignore[import-untyped]
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_GIT = Path("/usr/bin/git")
SCHEMA_VERSION = "aegis-ot-m4j-ssh-transport-v1"
MARKER_SCHEMA = "aegis-ot-m4j-management-communicator-v2"
HOST_KEY_EVIDENCE_NAME = "m4j-ssh-host-ed25519.pub"
PROVIDER = "virtualbox"
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
HOST_KEY_TEXT = re.compile(r"^ssh-ed25519 ([A-Za-z0-9+/]{68})\n$")
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_MARKER_BYTES = 1024
MAX_HOST_KEY_BYTES = 1024
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
SOURCE_BOUND_PATHS = (
    "infra/m4j/topology.yml",
    "scripts/prepare_m4j_ssh_transport.py",
)


class TransportPreparationError(RuntimeError):
    """The local M4j SSH transport could not be prepared safely."""


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise TransportPreparationError("topology contains an unhashable mapping key") from exc
        if duplicate:
            raise TransportPreparationError(f"topology contains duplicate key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _fail(message: str) -> NoReturn:
    raise TransportPreparationError(message)


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _absolute_literal(path: Path) -> Path:
    value = path.expanduser().absolute()
    rendered = str(value)
    if not rendered or "\x00" in rendered or "\n" in rendered or "\r" in rendered:
        _fail("path contains a forbidden control character")
    return value


def _owned_directory(
    path: Path,
    *,
    label: str,
    exact_mode: int | None = None,
) -> os.stat_result:
    absolute = _absolute_literal(path)
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise TransportPreparationError(f"{label} is unavailable: {exc}") from exc
    mode = stat.S_IMODE(metadata.st_mode)
    if absolute.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{label} must be a real directory")
    if metadata.st_uid != os.getuid():
        _fail(f"{label} must be owned by the invoking user")
    if exact_mode is not None:
        if mode != exact_mode:
            _fail(f"{label} must have mode {exact_mode:04o}")
    elif mode & 0o022:
        _fail(f"{label} must not be writable by group or other users")
    return metadata


def _read_owned_regular(
    path: Path,
    *,
    label: str,
    allowed_modes: frozenset[int] | None,
    maximum_bytes: int,
) -> tuple[bytes, int]:
    absolute = _absolute_literal(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise TransportPreparationError(f"{label} could not be opened safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
            _fail(f"{label} must be a regular invoking-user-owned file")
        if before.st_nlink != 1:
            _fail(f"{label} must not have hard-link aliases")
        if allowed_modes is None:
            if mode & 0o022 or mode & 0o400 == 0:
                _fail(f"{label} has unsafe permissions")
        elif mode not in allowed_modes:
            expected = ", ".join(f"{value:04o}" for value in sorted(allowed_modes))
            _fail(f"{label} mode must be one of: {expected}")
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            _fail(f"{label} has an invalid size")
        material = bytearray()
        while len(material) <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(material)))
            if not chunk:
                break
            material.extend(chunk)
        after = os.fstat(descriptor)
        invariant_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        invariant_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if len(material) != before.st_size or invariant_before != invariant_after:
            _fail(f"{label} changed while it was read")
        return bytes(material), mode
    finally:
        os.close(descriptor)


def _write_private(path: Path, material: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise TransportPreparationError(
            f"refusing to overwrite or follow transport output {path.name}: {exc}"
        ) from exc
    try:
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                _fail("private transport output write made no progress")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(material)
        ):
            _fail("private transport output did not retain its closed file contract")
    finally:
        os.close(descriptor)


def _mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} must be a string-keyed mapping")
    return value


def _topology_addresses(root: Path) -> dict[str, str]:
    topology_path = root / "infra" / "m4j" / "topology.yml"
    material, _mode = _read_owned_regular(
        topology_path,
        label="M4j topology",
        allowed_modes=None,
        maximum_bytes=128 * 1024,
    )
    try:
        document = yaml.load(material.decode("utf-8"), Loader=_UniqueKeyLoader)  # noqa: S506
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise TransportPreparationError("M4j topology is not strict UTF-8 YAML") from exc
    topology = _mapping(document, label="M4j topology")
    if topology.get("schema_version") != "aegis-ot-m4j-topology-v1":
        _fail("M4j topology has an unsupported schema")
    box = _mapping(topology.get("box"), label="M4j box")
    if box.get("provider") != PROVIDER:
        _fail("M4j SSH transport requires the exact VirtualBox provider")
    nodes = _mapping(topology.get("nodes"), label="M4j nodes")
    if tuple(nodes) != ROLES:
        _fail("M4j topology must contain the six exact ordered roles")
    observed: dict[str, str] = {}
    for role in ROLES:
        node = _mapping(nodes[role], label=f"M4j node {role}")
        interfaces = _mapping(node.get("interfaces"), label=f"M4j node {role} interfaces")
        address = interfaces.get("management")
        if not isinstance(address, str) or address != MANAGEMENT_ADDRESSES[role]:
            _fail(f"M4j role {role} has the wrong management address")
        observed[role] = address
    return observed


def _decode_host_key(encoded: str) -> bytes:
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TransportPreparationError("host-key evidence contains invalid base64") from exc
    algorithm = b"ssh-ed25519"
    prefix = len(algorithm).to_bytes(4, "big") + algorithm + (32).to_bytes(4, "big")
    if len(decoded) != len(prefix) + 32 or not decoded.startswith(prefix):
        _fail("host-key evidence is not a canonical SSH Ed25519 key")
    return decoded


def _validated_host_key(path: Path, *, role: str) -> tuple[bytes, bytes]:
    material, _mode = _read_owned_regular(
        path,
        label=f"exported SSH host key for {role}",
        allowed_modes=frozenset({0o600}),
        maximum_bytes=MAX_HOST_KEY_BYTES,
    )
    try:
        text = material.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TransportPreparationError("exported SSH host keys must be ASCII") from exc
    match = HOST_KEY_TEXT.fullmatch(text)
    if match is None:
        _fail("exported SSH host keys must contain one canonical Ed25519 key without a comment")
    return material, _decode_host_key(match.group(1))


def _validated_private_key(path: Path, *, role: str) -> tuple[bytes, str]:
    material, _mode = _read_owned_regular(
        path,
        label=f"Vagrant SSH identity for {role}",
        allowed_modes=frozenset({0o400, 0o600}),
        maximum_bytes=MAX_PRIVATE_KEY_BYTES,
    )
    try:
        key: object
        if material.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
            key = serialization.load_ssh_private_key(material, password=None)
        else:
            key = serialization.load_pem_private_key(material, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise TransportPreparationError(
            f"Vagrant SSH identity for {role} is not a supported unencrypted private key"
        ) from exc
    if not callable(getattr(key, "public_key", None)):
        _fail(f"Vagrant SSH identity for {role} has no usable public identity")
    return material, _sha256(material)


def _marker_material(role: str, address: str, host_key_material: bytes) -> bytes:
    return (
        f"{MARKER_SCHEMA}\n"
        f"role={role}\n"
        f"address={address}\n"
        f"host_key_sha256={_sha256(host_key_material)}\n"
    ).encode("ascii")


def _validate_marker(
    path: Path,
    *,
    role: str,
    address: str,
    host_key_material: bytes,
) -> str:
    material, _mode = _read_owned_regular(
        path,
        label=f"Vagrant management communicator marker for {role}",
        allowed_modes=frozenset({0o600}),
        maximum_bytes=MAX_MARKER_BYTES,
    )
    expected = _marker_material(role, address, host_key_material)
    if material != expected:
        _fail(f"Vagrant management communicator marker for {role} is stale or malformed")
    return _sha256(material)


def _ssh_config_identity(path: Path) -> str:
    rendered = str(path)
    if "%" in rendered:
        _fail("Vagrant identity paths must be literal and cannot contain SSH token expansion")
    if all(character not in rendered for character in (' ', '\t', '"', '\\')):
        return rendered
    return '"' + rendered.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _machine_directory(root: Path, role: str) -> Path:
    directory = root / ".vagrant" / "machines" / role / PROVIDER
    _owned_directory(directory, label=f"Vagrant machine directory for {role}")
    return directory


def _prepare_inputs(root: Path) -> tuple[bytes, bytes, list[dict[str, str]]]:
    addresses = _topology_addresses(root)
    _owned_directory(root / ".vagrant", label="Vagrant state directory")
    _owned_directory(root / ".vagrant" / "machines", label="Vagrant machine-state directory")

    config_lines: list[str] = []
    known_host_lines: list[str] = []
    evidence: list[dict[str, str]] = []
    host_keys: set[bytes] = set()
    identity_digests: set[str] = set()
    for role in ROLES:
        address = addresses[role]
        machine = _machine_directory(root, role)
        private_key_path = machine / "private_key"
        _identity, identity_sha256 = _validated_private_key(private_key_path, role=role)
        if identity_sha256 in identity_digests:
            _fail("each M4j Vagrant machine must use a distinct SSH client identity")
        identity_digests.add(identity_sha256)

        host_key_material, decoded_host_key = _validated_host_key(
            machine / HOST_KEY_EVIDENCE_NAME,
            role=role,
        )
        if decoded_host_key in host_keys:
            _fail("each M4j role must export a distinct Ed25519 SSH host key")
        host_keys.add(decoded_host_key)
        marker_sha256 = _validate_marker(
            machine / "m4j-management-communicator",
            role=role,
            address=address,
            host_key_material=host_key_material,
        )

        encoded = HOST_KEY_TEXT.fullmatch(host_key_material.decode("ascii"))
        if encoded is None:  # pragma: no cover - validated by _validated_host_key
            _fail("validated host key was unexpectedly noncanonical")
        known_host_lines.append(f"{role},{address} ssh-ed25519 {encoded.group(1)}")
        config_lines.extend(
            (
                f"Host {role}",
                f"    HostName {address}",
                "    User vagrant",
                f"    IdentityFile {_ssh_config_identity(private_key_path)}",
            )
        )
        evidence.append(
            {
                "role": role,
                "management_address": address,
                "host_key_sha256": _sha256(decoded_host_key),
                "identity_sha256": identity_sha256,
                "communicator_marker_sha256": marker_sha256,
            }
        )
    return (
        ("\n".join(config_lines) + "\n").encode("utf-8"),
        ("\n".join(known_host_lines) + "\n").encode("ascii"),
        evidence,
    )


def _output_destination(output: Path) -> Path:
    destination = _absolute_literal(output)
    if destination.name in {"", ".", ".."}:
        _fail("transport output directory has an invalid name")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise TransportPreparationError(f"transport output could not be checked: {exc}") from exc
    else:
        _fail("refusing to overwrite an existing transport output path")
    _owned_directory(destination.parent, label="transport output parent")
    return destination


def _remove_failed_output(destination: Path, created: os.stat_result) -> None:
    """Remove only this invocation's still-owned, closed partial output."""
    try:
        current = destination.lstat()
    except OSError:
        return
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_uid != os.getuid()
        or stat.S_IMODE(current.st_mode) != 0o700
        or (current.st_dev, current.st_ino) != (created.st_dev, created.st_ino)
    ):
        return
    for name in ("ssh_config", "known_hosts"):
        path = destination / name
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            return
        path.unlink()
    try:
        destination.rmdir()
    except OSError:
        pass


def prepare_transport(
    output: Path,
    *,
    root: Path = ROOT,
    source_commit: str,
) -> dict[str, Any]:
    if GIT_OBJECT.fullmatch(source_commit) is None:
        _fail("source commit must be an exact lowercase Git object ID")
    checkout = _absolute_literal(root)
    _owned_directory(checkout, label="M4j checkout")
    ssh_config, known_hosts, role_evidence = _prepare_inputs(checkout)
    destination = _output_destination(output)
    try:
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise TransportPreparationError("private transport output could not be created") from exc
    created = _owned_directory(
        destination,
        label="transport output directory",
        exact_mode=0o700,
    )
    try:
        config_path = destination / "ssh_config"
        known_hosts_path = destination / "known_hosts"
        _write_private(config_path, ssh_config)
        _write_private(known_hosts_path, known_hosts)
        descriptor = os.open(
            destination,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        _remove_failed_output(destination, created)
        raise
    return {
        "schema_version": SCHEMA_VERSION,
        "source_git_commit": source_commit,
        "output_directory": str(destination),
        "ssh_config": {
            "path": str(config_path),
            "sha256": _sha256(ssh_config),
            "mode": "0600",
        },
        "known_hosts": {
            "path": str(known_hosts_path),
            "sha256": _sha256(known_hosts),
            "mode": "0600",
            "algorithm": "ssh-ed25519",
            "distinct_host_key_count": len(role_evidence),
        },
        "roles": role_evidence,
        "trust_boundary": (
            "local_vagrant_provisioning_channel_not_independent_or_production_host_identity"
        ),
        "private_key_material_printed": False,
    }


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _require_closed_git_topology(root: Path) -> tuple[Path, Path]:
    checkout = root.resolve(strict=True)
    try:
        root_metadata = root.lstat()
        git_directory = checkout / ".git"
        git_metadata = git_directory.lstat()
        object_directory = git_directory / "objects"
        object_metadata = object_directory.lstat()
    except OSError as exc:
        raise TransportPreparationError("the authoritative Git checkout is unavailable") from exc
    if (
        root.is_symlink()
        or checkout != root.absolute()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or root_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or git_directory.is_symlink()
        or not stat.S_ISDIR(git_metadata.st_mode)
        or git_metadata.st_uid != os.getuid()
        or git_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or object_directory.is_symlink()
        or not stat.S_ISDIR(object_metadata.st_mode)
        or object_metadata.st_uid != git_metadata.st_uid
        or object_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _fail("the authoritative Git checkout and object store must be protected")
    if (git_directory / "commondir").exists() or (git_directory / "commondir").is_symlink():
        _fail("linked Git worktree metadata is forbidden")
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
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != git_metadata.st_uid
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                _fail("the Git object store contains unsafe material")
    return checkout, git_directory


def _git(root: Path, *arguments: str) -> bytes:
    if not TRUSTED_GIT.is_file() or TRUSTED_GIT.is_symlink():
        _fail("trusted /usr/bin/git executable is unavailable")
    checkout = root.resolve(strict=True)
    git_directory = checkout / ".git"
    completed = subprocess.run(  # noqa: S603 - fixed trusted executable and closed argv
        (
            str(TRUSTED_GIT),
            "--git-dir",
            str(git_directory),
            "--work-tree",
            str(checkout),
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
        cwd=checkout,
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise TransportPreparationError(f"Git source binding failed: {detail[-1000:]}")
    return completed.stdout


def _source_inventory(root: Path, commit: str) -> dict[str, tuple[str, bytes]]:
    listing = _git(
        root,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        commit,
        "--",
        *SOURCE_BOUND_PATHS,
    )
    inventory: dict[str, tuple[str, bytes]] = {}
    for raw_entry in listing.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", maxsplit=1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            relative = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise TransportPreparationError("Git returned a malformed transport inventory") from exc
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
            _fail("Git transport inventory contains an unsafe or duplicate entry")
        material = _git(root, "cat-file", "blob", object_id)
        if len(material) > MAX_SOURCE_FILE_BYTES:
            _fail(f"Git transport blob exceeds its limit: {relative}")
        object_material = f"blob {len(material)}\0".encode("ascii") + material
        if len(object_id) == 40:
            observed_object_id = hashlib.sha1(  # noqa: S324 - Git SHA-1 object address
                object_material,
                usedforsecurity=False,
            ).hexdigest()
        else:
            observed_object_id = hashlib.sha256(object_material).hexdigest()
        if observed_object_id != object_id:
            _fail(f"Git transport blob hash differs from HEAD: {relative}")
        inventory[relative] = (mode, material)
    for requested in SOURCE_BOUND_PATHS:
        if requested not in inventory and not any(
            relative.startswith(requested + "/") for relative in inventory
        ):
            _fail(f"transport source path is absent from the exact commit: {requested}")
    return inventory


def _require_source_matches_head(
    root: Path,
    inventory: Mapping[str, tuple[str, bytes]],
) -> None:
    checkout = root.resolve(strict=True)
    for relative, (mode, expected) in inventory.items():
        candidate = checkout.joinpath(*Path(relative).parts)
        try:
            if candidate.resolve(strict=True) != candidate.absolute():
                _fail(f"transport source path traverses a link: {relative}")
        except OSError as exc:
            raise TransportPreparationError(
                f"transport source path is unavailable: {relative}"
            ) from exc
        observed, observed_mode = _read_owned_regular(
            candidate,
            label=f"transport source path {relative}",
            allowed_modes=None,
            maximum_bytes=MAX_SOURCE_FILE_BYTES,
        )
        expected_executable = mode == "100755"
        observed_executable = bool(
            observed_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        )
        if observed != expected or observed_executable != expected_executable:
            _fail(f"transport source path differs from HEAD: {relative}")


def _resolve_clean_head(root: Path, reference: str) -> str:
    if (
        not reference
        or reference != reference.strip()
        or reference.startswith("-")
        or len(reference) > 512
        or any(character.isspace() or ord(character) < 32 for character in reference)
    ):
        _fail("source commit reference is malformed")
    checkout, _git_directory = _require_closed_git_topology(root)
    top = Path(_git(checkout, "rev-parse", "--show-toplevel").decode("utf-8").strip())
    if top.resolve(strict=True) != checkout:
        _fail("M4j transport must be prepared from the repository root")
    resolved = _git(
        checkout,
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        f"{reference}^{{commit}}",
    ).decode("ascii").strip()
    head = _git(checkout, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    if GIT_OBJECT.fullmatch(resolved) is None or resolved != head:
        _fail("source commit must resolve to the checked-out HEAD")
    _git(
        checkout,
        "-c",
        "fsck.skipList=/dev/null",
        "fsck",
        "--strict",
        "--full",
        "--no-dangling",
        "--no-reflogs",
        "--no-progress",
        resolved,
    )
    _require_source_matches_head(checkout, _source_inventory(checkout, resolved))
    if _git(checkout, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        _fail("M4j transport preparation requires a clean exact-source checkout")
    return resolved


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", default="HEAD")
    arguments = parser.parse_args(argv)
    try:
        source_commit = _resolve_clean_head(ROOT, arguments.source_commit)
        result = prepare_transport(
            arguments.output,
            root=ROOT,
            source_commit=source_commit,
        )
    except (OSError, TransportPreparationError, ValueError) as exc:
        print(f"M4j SSH transport preparation rejected: {exc}", file=sys.stderr)
        return 1
    print(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
