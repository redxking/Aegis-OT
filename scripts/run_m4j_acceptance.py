"""Plan or run the fail-closed six-host M4j network acceptance campaign.

Plan mode validates the exact committed runner and topology and prints the
closed acceptance contract.  It performs no SSH calls and writes no files.
Live mode requires an external SSH configuration whose host aliases are the
six topology roles.  It records only normalized host observations and hashes
of command inputs and outputs; SSH configuration contents and packet payloads
are never retained.

The live campaign establishes bounded local VM-network evidence only.  It does
not establish production deployment, hostile-host resistance, independent
validation, or operational effectiveness.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
RUNNER_RELATIVE_PATH = "scripts/run_m4j_acceptance.py"
TOPOLOGY_RELATIVE_PATH = "infra/m4j/topology.yml"
DEPLOYMENT_RELATIVE_PATH = "infra/m4j/deployment.yml"
WORKLOAD_RELATIVE_PATH = "infra/m4j/workloads.yml"
SCHEMA_VERSION = "aegis-ot-m4j-network-acceptance-v2"
TOPOLOGY_SCHEMA_VERSION = "aegis-ot-m4j-topology-v1"
DEPLOYMENT_SCHEMA_VERSION = "aegis-ot-m4j-deployment-v2"
EXPECTED_ROLES = ("management", "trust", "agents", "gateway", "ot", "simulation")
MANAGEMENT_ADDRESSES = {
    "management": "192.168.56.10",
    "trust": "192.168.56.11",
    "agents": "192.168.56.12",
    "gateway": "192.168.56.13",
    "ot": "192.168.56.14",
    "simulation": "192.168.56.15",
}
EXPECTED_NETWORKS: dict[str, dict[str, Any]] = {
    "management": {
        "kind": "host_only",
        "purpose": "ssh_control_only",
        "members": EXPECTED_ROLES,
    },
    "trust_enrollment": {
        "kind": "virtualbox_internal",
        "purpose": "workload_identity_enrollment",
        "members": ("trust", "agents", "gateway", "ot", "simulation"),
    },
    "agent_lane": {
        "kind": "virtualbox_internal",
        "purpose": "agent_to_gateway_only",
        "members": ("agents", "gateway"),
    },
    "control_dmz": {
        "kind": "virtualbox_internal",
        "purpose": "trusted_control_services",
        "members": ("trust", "gateway", "ot"),
    },
    "simulation_lane": {
        "kind": "virtualbox_internal",
        "purpose": "plant_access_only",
        "members": ("trust", "ot", "simulation"),
    },
}
EXPECTED_TOP_LEVEL_FIELDS = frozenset(
    {
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
)
EXPECTED_NETWORK_FIELDS = frozenset(
    {"cidr", "kind", "purpose", "gateway", "internal_name", "members"}
)
EXPECTED_NODE_FIELDS = frozenset({"hostname", "cpus", "memory_mb", "interfaces"})

EXPECTED_WORKLOAD_PLACEMENT: dict[str, tuple[str, ...]] = {
    "management": ("orchestration", "evidence-retention"),
    "trust": (
        "spire-server",
        "spire-bootstrap",
        "spire-agent",
        "policy-relay",
        "opa",
        "observer",
        "candidate",
    ),
    "agents": ("agent-probe", "spire-agent"),
    "gateway": ("segmented-gateway", "spire-agent"),
    "ot": ("ot-adapter", "spire-agent"),
    "simulation": ("plant", "spire-agent"),
}
ACCEPTANCE_GATES = (
    "source_unchanged",
    "six_host_identity_interfaces_routes_exact",
    "forwarding_disabled",
    "ufw_exact_deployment_ingress_default_deny",
    "role_specific_listeners_exact",
    "closed_connectivity_matrix",
    "direct_agents_to_ot_denied",
    "direct_agents_to_simulation_denied",
    "gateway_partition_denied",
    "gateway_partition_cleanup_verified",
    "bounded_interface_counter_metadata",
    "command_result_hashes_complete",
    "private_unique_output",
)

EVIDENCE_BOUNDARIES = (
    "The campaign is a local six-VM network acceptance run, not a production deployment.",
    (
        "TCP connection outcomes establish bounded path reachability or denial at observation "
        "time; they do not establish application authorization semantics."
    ),
    (
        "Interface packet and byte counters are metadata only; no packet payloads are "
        "captured or retained."
    ),
    (
        "A clean exact-source run is not independent validation or evidence of operational "
        "effectiveness."
    ),
    (
        "The gateway partition probe exercises one bounded agents-to-gateway TCP path and "
        "does not establish Byzantine, quorum, rollback, or hostile-host resistance."
    ),
    (
        "Host-level TCP reachability cannot establish the separately implemented workload "
        "authorization and mTLS contract; signed live workload-probe evidence remains pending."
    ),
)

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SAFE_ROLE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_SAFE_RUN_TOKEN = re.compile(r"^[a-f0-9]{16}$")
_MAX_TOPOLOGY_BYTES = 128 * 1024
_MAX_SSH_CONFIG_BYTES = 256 * 1024
_MAX_SSH_IDENTITY_BYTES = 256 * 1024
_MAX_REMOTE_STREAM_BYTES = 1024 * 1024
_MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
_SSH_TIMEOUT_SECONDS = 30.0
_CONNECT_TIMEOUT_SECONDS = 1.5
_PARTITION_STABLE_ABSENCE_READS = 7
_PARTITION_MAX_RECONCILIATION_READS = 30
_PARTITION_RECONCILIATION_INTERVAL_SECONDS = 1.0
_TRUSTED_GIT = Path("/usr/bin/git")
_TRUSTED_SSH = Path("/usr/bin/ssh")


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise AcceptanceError("YAML mapping keys must be scalar and hashable") from exc
        if duplicate:
            raise AcceptanceError("duplicate YAML mapping key is prohibited")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)

_REMOTE_FACTS_SOURCE = r'''# aegis-m4j-remote-probe-v1:facts
import json
import os
import stat
import subprocess


def run(argv):
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode != 0:
        raise RuntimeError("remote inspection command failed")
    return result.stdout


role = PAYLOAD["role"]
marker_path = f"/etc/aegis-ot/{role}/role"
descriptor = os.open(
    marker_path,
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    marker_stat = os.fstat(descriptor)
    if not stat.S_ISREG(marker_stat.st_mode) or marker_stat.st_size > 4096:
        raise RuntimeError("role marker is invalid")
    marker = os.read(descriptor, 4097).decode("utf-8")
finally:
    os.close(descriptor)

facts = {
    "hostname": run(["/bin/hostname"]).strip(),
    "role_marker": marker,
    "role_marker_mode": stat.S_IMODE(marker_stat.st_mode),
    "role_marker_uid": marker_stat.st_uid,
    "addresses": json.loads(
        run(["/usr/sbin/ip", "-j", "-4", "address", "show", "scope", "global"])
    ),
    "routes": json.loads(run(["/usr/sbin/ip", "-j", "-4", "route", "show", "table", "main"])),
    "link_stats": json.loads(run(["/usr/sbin/ip", "-j", "-s", "link", "show"])),
    "forwarding": {
        key: run(["/usr/sbin/sysctl", "-n", key]).strip()
        for key in (
            "net.ipv4.ip_forward",
            "net.ipv6.conf.all.forwarding",
            "net.ipv6.conf.default.forwarding",
        )
    },
    "ufw_verbose": run(["/usr/sbin/ufw", "status", "verbose"]),
    "ufw_numbered": run(["/usr/sbin/ufw", "status", "numbered"]),
    "ufw_added": run(["/usr/sbin/ufw", "show", "added"]),
    "listeners_ipv4": run(["/usr/bin/ss", "-H", "-4", "-lnt"]),
    "listeners_ipv6": run(["/usr/bin/ss", "-H", "-6", "-lnt"]),
    "listeners_unix": run(["/usr/bin/ss", "-H", "-xl"]),
}
print(json.dumps(facts, sort_keys=True, separators=(",", ":"), allow_nan=False))
'''

_REMOTE_CONNECT_SOURCE = r'''# aegis-m4j-remote-probe-v1:connectivity
import errno
import json
import socket
import time

results = []
for target in PAYLOAD["targets"]:
    started = time.monotonic_ns()
    connected = False
    error_number = None
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.settimeout(PAYLOAD["timeout_seconds"])
        connection.bind((target["source_address"], 0))
        error_number = connection.connect_ex((target["destination_address"], target["port"]))
        connected = error_number == 0
    except OSError as exc:
        error_number = exc.errno if exc.errno is not None else errno.EIO
    finally:
        connection.close()
    results.append(
        {
            "check_id": target["check_id"],
            "connected": connected,
            "errno": error_number,
            "elapsed_ms": max(0, (time.monotonic_ns() - started) // 1_000_000),
        }
    )
print(json.dumps({"results": results}, sort_keys=True, separators=(",", ":"), allow_nan=False))
'''


class AcceptanceError(RuntimeError):
    """M4j acceptance could not be established."""


@dataclass(frozen=True)
class SshOutcome:
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed_ms: int


SshExecutor = Callable[[Path, str, tuple[str, ...], bytes, float], SshOutcome]


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
        raise AcceptanceError("acceptance material was not canonical JSON") from exc


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AcceptanceError(f"{label} must be a string-keyed mapping")
    return value


def _exact_fields(value: Mapping[str, Any], expected: frozenset[str], *, label: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        raise AcceptanceError(f"{label} fields differ from the closed contract")


def _positive_integer(value: Any, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise AcceptanceError(f"{label} must be a positive integer")
    return value


def _safe_text(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AcceptanceError(f"{label} must be a non-empty trimmed string")
    return value


def _require_owned_git_path(
    path: Path,
    *,
    label: str,
    directory: bool,
    required: bool = True,
) -> os.stat_result | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if not required:
            return None
        raise AcceptanceError(f"{label} is unavailable") from None
    except OSError as exc:
        raise AcceptanceError(f"{label} is unavailable") from exc
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if path.is_symlink() or not expected_type(metadata.st_mode):
        raise AcceptanceError(f"{label} must be a real {'directory' if directory else 'file'}")
    if metadata.st_uid != os.getuid() or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise AcceptanceError(f"{label} must be owned and writable only by the invoking user")
    return metadata


def _reject_git_config_includes(path: Path) -> None:
    metadata = _require_owned_git_path(
        path,
        label=f"Git configuration {path.name}",
        directory=False,
        required=False,
    )
    if metadata is None:
        return
    if metadata.st_size <= 0 or metadata.st_size > 1024 * 1024:
        raise AcceptanceError("Git repository configuration has an invalid size")
    material = path.read_bytes()
    if len(material) != metadata.st_size or b"\x00" in material:
        raise AcceptanceError("Git repository configuration changed or is malformed")
    try:
        text = material.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("Git repository configuration is not UTF-8") from exc
    for line in text.splitlines():
        normalized = line.strip().casefold()
        if re.match(r"^\[\s*include(?:if\b[^]]*)?\s*]$", normalized) or re.match(
            r"^include(?:if)?[.]path\s*=", normalized
        ):
            raise AcceptanceError("external Git configuration includes are forbidden")


def _require_closed_git_topology(root: Path) -> tuple[Path, Path]:
    try:
        work_tree = root.resolve(strict=True)
    except OSError as exc:
        raise AcceptanceError("M4j source checkout is unavailable") from exc
    _require_owned_git_path(
        work_tree,
        label="M4j source checkout",
        directory=True,
    )
    git_directory = work_tree / ".git"
    git_metadata = _require_owned_git_path(
        git_directory,
        label="authoritative Git directory",
        directory=True,
    )
    assert git_metadata is not None
    if (git_directory / "commondir").exists() or (git_directory / "commondir").is_symlink():
        raise AcceptanceError("linked Git worktree metadata is forbidden")

    _reject_git_config_includes(git_directory / "config")
    _reject_git_config_includes(git_directory / "config.worktree")
    for name, required in (("HEAD", True), ("index", True), ("packed-refs", False)):
        metadata = _require_owned_git_path(
            git_directory / name,
            label=f"Git {name}",
            directory=False,
            required=required,
        )
        if metadata is not None and metadata.st_size > 64 * 1024 * 1024:
            raise AcceptanceError(f"Git {name} has an invalid size")

    object_directory = git_directory / "objects"
    _require_owned_git_path(
        object_directory,
        label="authoritative Git object store",
        directory=True,
    )
    for prohibited in (
        object_directory / "info" / "alternates",
        object_directory / "info" / "http-alternates",
        git_directory / "info" / "grafts",
    ):
        if prohibited.exists() or prohibited.is_symlink():
            raise AcceptanceError("Git alternate, HTTP alternate, and graft sources are forbidden")
    for directory, directory_names, filenames in os.walk(object_directory, followlinks=False):
        for name in (*directory_names, *filenames):
            candidate = Path(directory) / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise AcceptanceError("the Git object store must not contain symbolic links")
            if metadata.st_uid != git_metadata.st_uid:
                raise AcceptanceError("the Git object store contains material with a wrong owner")
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise AcceptanceError("the Git object store contains shared-writable material")
    return work_tree, git_directory


def _run_git_bytes(
    root: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
) -> bytes:
    work_tree, git_directory = _require_closed_git_topology(root)
    if not _TRUSTED_GIT.is_file() or not os.access(_TRUSTED_GIT, os.X_OK):
        raise AcceptanceError("the pinned /usr/bin/git executable is unavailable")
    completed = subprocess.run(  # noqa: S603 - pinned Git and fixed argv
        (
            str(_TRUSTED_GIT),
            "--git-dir",
            str(git_directory),
            "--work-tree",
            str(work_tree),
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
        cwd=work_tree,
        check=False,
        capture_output=True,
        input=input_bytes,
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
        raise AcceptanceError("Git could not establish the exact M4j source binding")
    return completed.stdout


def _run_git_text(root: Path, *arguments: str) -> str:
    try:
        return _run_git_bytes(root, *arguments).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("Git returned non-UTF-8 source metadata") from exc


def _regular_file_bytes(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AcceptanceError(f"{label} is unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise AcceptanceError(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise AcceptanceError(f"{label} has an invalid size")
    try:
        material = path.read_bytes()
    except OSError as exc:
        raise AcceptanceError(f"{label} could not be read") from exc
    if len(material) != metadata.st_size:
        raise AcceptanceError(f"{label} changed while it was read")
    return material


def _head_blob_entries(root: Path, commit: str) -> list[tuple[str, str, str]]:
    """Return every committed blob path, mode, and object ID without consulting the index."""

    raw = _run_git_bytes(root, "ls-tree", "-rz", "--full-tree", commit)
    entries: list[tuple[str, str, str]] = []
    seen_paths: set[str] = set()
    for record in raw.split(b"\x00"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", maxsplit=1)
            mode_bytes, kind, object_id_bytes = metadata.split(b" ", maxsplit=2)
            mode = mode_bytes.decode("ascii")
            object_id = object_id_bytes.decode("ascii")
            relative = encoded_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise AcceptanceError("Git tree inventory is malformed or non-UTF-8") from exc
        parts = PurePosixPath(relative).parts
        if (
            kind != b"blob"
            or mode not in {"100644", "100755", "120000"}
            or _GIT_OBJECT.fullmatch(object_id) is None
            or not parts
            or relative.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
            or relative in seen_paths
        ):
            raise AcceptanceError("Git tree inventory differs from the closed file contract")
        seen_paths.add(relative)
        entries.append((relative, mode, object_id))
    if not entries:
        raise AcceptanceError("Git tree inventory is empty")
    return entries


def _head_blob_material(
    root: Path,
    entries: Sequence[tuple[str, str, str]],
) -> dict[str, bytes]:
    """Read all HEAD blobs through one closed Git batch operation."""

    request = b"".join(f"{object_id}\n".encode("ascii") for _, _, object_id in entries)
    output = _run_git_bytes(root, "cat-file", "--batch", input_bytes=request)
    offset = 0
    material: dict[str, bytes] = {}
    for relative, _mode, expected_object_id in entries:
        header_end = output.find(b"\n", offset)
        if header_end < 0:
            raise AcceptanceError("Git blob batch response is truncated")
        header = output[offset:header_end].split(b" ")
        if len(header) != 3:
            raise AcceptanceError("Git blob batch response header is malformed")
        try:
            object_id = header[0].decode("ascii")
            kind = header[1].decode("ascii")
            size = int(header[2].decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise AcceptanceError("Git blob batch response header is malformed") from exc
        if object_id != expected_object_id or kind != "blob" or size < 0:
            raise AcceptanceError("Git blob batch response differs from the HEAD tree")
        start = header_end + 1
        end = start + size
        if end >= len(output) or output[end : end + 1] != b"\n":
            raise AcceptanceError("Git blob batch response body is truncated")
        body = output[start:end]
        object_material = f"blob {len(body)}\x00".encode("ascii") + body
        if len(expected_object_id) == 40:
            computed_object_id = hashlib.sha1(  # noqa: S324 - Git SHA-1 object address
                object_material,
                usedforsecurity=False,
            ).hexdigest()
        elif len(expected_object_id) == 64:
            computed_object_id = hashlib.sha256(object_material).hexdigest()
        else:  # guarded by _GIT_OBJECT, retained here as a closed parser boundary
            raise AcceptanceError("Git blob object ID uses an unsupported format")
        if computed_object_id != expected_object_id:
            raise AcceptanceError(f"Git blob content hash differs from HEAD: {relative}")
        material[relative] = body
        offset = end + 1
    if offset != len(output):
        raise AcceptanceError("Git blob batch response contains trailing material")
    return material


def _require_real_parent_directories(root: Path, relative: str) -> None:
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise AcceptanceError(f"tracked parent directory is unavailable: {relative}") from exc
        if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise AcceptanceError(f"tracked parent directory is not a real directory: {relative}")


def _read_tracked_regular_file(path: Path, *, relative: str) -> tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AcceptanceError(f"tracked file is unavailable: {relative}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AcceptanceError(f"tracked path is not a regular file: {relative}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise AcceptanceError(f"tracked file changed while it was read: {relative}")
    value = b"".join(chunks)
    if len(value) != before.st_size:
        raise AcceptanceError(f"tracked file changed while it was read: {relative}")
    return value, before.st_mode


def _require_worktree_matches_head(root: Path, commit: str) -> None:
    """Compare every tracked path directly with HEAD, ignoring index masking flags."""

    entries = _head_blob_entries(root, commit)
    blobs = _head_blob_material(root, entries)
    for relative, mode, _object_id in entries:
        _require_real_parent_directories(root, relative)
        path = root.joinpath(*PurePosixPath(relative).parts)
        expected = blobs[relative]
        if mode == "120000":
            try:
                before = path.lstat()
                target = os.fsencode(os.readlink(path))
                after = path.lstat()
            except OSError as exc:
                raise AcceptanceError(f"tracked symbolic link is unavailable: {relative}") from exc
            if (
                not stat.S_ISLNK(before.st_mode)
                or before != after
                or target != expected
            ):
                raise AcceptanceError(f"tracked symbolic link differs from HEAD: {relative}")
            continue
        working, working_mode = _read_tracked_regular_file(path, relative=relative)
        expected_executable = mode == "100755"
        working_executable = bool(working_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if working != expected or working_executable != expected_executable:
            raise AcceptanceError(f"tracked file differs from HEAD: {relative}")


def _source_binding(root: Path = ROOT) -> dict[str, Any]:
    resolved_root = root.resolve()
    git_root = Path(_run_git_text(root, "rev-parse", "--show-toplevel").strip()).resolve()
    if git_root != resolved_root:
        raise AcceptanceError("runner root does not match the Git checkout root")
    commit = _run_git_text(root, "rev-parse", "HEAD").strip()
    tree = _run_git_text(root, "rev-parse", "HEAD^{tree}").strip()
    if _GIT_OBJECT.fullmatch(commit) is None or _GIT_OBJECT.fullmatch(tree) is None:
        raise AcceptanceError("Git commit or tree binding was malformed")
    _run_git_bytes(
        root,
        "-c",
        "fsck.skipList=/dev/null",
        "fsck",
        "--strict",
        "--full",
        "--no-dangling",
        "--no-reflogs",
        "--no-progress",
        commit,
    )
    _require_worktree_matches_head(root, commit)
    if _run_git_bytes(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise AcceptanceError("M4j acceptance requires a clean checkout")

    files: list[dict[str, Any]] = []
    committed_material: dict[str, bytes] = {}
    for relative in (
        RUNNER_RELATIVE_PATH,
        TOPOLOGY_RELATIVE_PATH,
        DEPLOYMENT_RELATIVE_PATH,
        WORKLOAD_RELATIVE_PATH,
    ):
        path = root / relative
        working = _regular_file_bytes(
            path,
            maximum_bytes=(
                _MAX_TOPOLOGY_BYTES
                if relative
                in {
                    TOPOLOGY_RELATIVE_PATH,
                    DEPLOYMENT_RELATIVE_PATH,
                    WORKLOAD_RELATIVE_PATH,
                }
                else 2 * 1024 * 1024
            ),
            label=relative,
        )
        archived = _run_git_bytes(root, "show", f"{commit}:{relative}")
        if working != archived:
            raise AcceptanceError(f"{relative} differs from the bound Git commit")
        blob = _run_git_text(root, "rev-parse", f"{commit}:{relative}").strip()
        if _GIT_OBJECT.fullmatch(blob) is None:
            raise AcceptanceError(f"{relative} Git blob binding was malformed")
        entry = {
            "path": relative,
            "git_blob": blob,
            "sha256": _sha256(archived),
            "size_bytes": len(archived),
        }
        files.append(entry)
        committed_material[relative] = archived

    fingerprint_material = {
        "schema_version": "aegis-ot-m4j-source-fingerprint-v1",
        "git_commit": commit,
        "git_tree": tree,
        "files": files,
    }
    return {
        **fingerprint_material,
        "source_fingerprint_sha256": _sha256(_canonical_bytes(fingerprint_material)),
        "clean_checkout": True,
        "_committed_material": committed_material,
    }


def _public_source_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in binding.items() if not key.startswith("_")}


def _assert_source_unchanged(binding: Mapping[str, Any], root: Path = ROOT) -> None:
    current = _source_binding(root)
    if _public_source_binding(current) != _public_source_binding(binding):
        raise AcceptanceError("M4j source binding changed during acceptance")


def _parse_network(value: Any, *, label: str) -> ipaddress.IPv4Network:
    text = _safe_text(value, label=label)
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise AcceptanceError(f"{label} is not a canonical network") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise AcceptanceError(f"{label} must be IPv4")
    return network


def _parse_address(value: Any, *, label: str) -> ipaddress.IPv4Address:
    text = _safe_text(value, label=label)
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise AcceptanceError(f"{label} is invalid") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise AcceptanceError(f"{label} must be IPv4")
    return address


def _load_unique_yaml(material: bytes, *, label: str) -> dict[str, Any]:
    try:
        text = material.decode("utf-8")
        loader = _UniqueKeyLoader(text)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise AcceptanceError(f"{label} is not valid unique-key UTF-8 YAML") from exc
    return _mapping(value, label=label)


def _load_topology(material: bytes) -> dict[str, Any]:
    if not material or len(material) > _MAX_TOPOLOGY_BYTES:
        raise AcceptanceError("M4j topology size is invalid")
    topology = _load_unique_yaml(material, label="M4j topology")
    _exact_fields(topology, EXPECTED_TOP_LEVEL_FIELDS, label="M4j topology")
    if topology["schema_version"] != TOPOLOGY_SCHEMA_VERSION:
        raise AcceptanceError("unsupported M4j topology schema")
    if topology["deployment_status"] != "configuration_only":
        raise AcceptanceError("M4j topology deployment status is not configuration_only")
    if topology["claim_boundary"] != "no_live_deployment_or_multi_host_isolation_evidence":
        raise AcceptanceError("M4j topology claim boundary is absent or broadened")

    box = _mapping(topology["box"], label="M4j box")
    _exact_fields(
        box,
        frozenset({"name", "version", "provider", "check_update"}),
        label="M4j box",
    )
    if box != {
        "name": "generic/ubuntu2204",
        "version": "4.3.12",
        "provider": "virtualbox",
        "check_update": False,
    }:
        raise AcceptanceError("M4j box differs from the pinned VirtualBox contract")

    bootstrap_nat = _mapping(topology["bootstrap_nat"], label="M4j bootstrap NAT")
    _exact_fields(
        bootstrap_nat,
        frozenset(
            {"enabled", "purpose", "application_bindings_allowed", "guest_ssh_port"}
        ),
        label="M4j bootstrap NAT",
    )
    if bootstrap_nat != {
        "enabled": True,
        "purpose": "vagrant_bootstrap_only",
        "application_bindings_allowed": False,
        "guest_ssh_port": 22,
    }:
        raise AcceptanceError("M4j bootstrap NAT differs from its non-application contract")

    capacity = _mapping(topology["capacity"], label="M4j capacity")
    capacity_fields = frozenset(
        {"max_total_cpus", "max_total_memory_mb", "max_node_cpus", "max_node_memory_mb"}
    )
    _exact_fields(capacity, capacity_fields, label="M4j capacity")
    capacity_values = {
        key: _positive_integer(value, label=f"M4j capacity {key}")
        for key, value in capacity.items()
    }

    addressing = _mapping(topology["addressing"], label="M4j addressing")
    _exact_fields(
        addressing,
        frozenset({"ipv4_prefix_length", "first_node_host_offset"}),
        label="M4j addressing",
    )
    prefix = _positive_integer(addressing["ipv4_prefix_length"], label="IPv4 prefix")
    first_offset = _positive_integer(
        addressing["first_node_host_offset"], label="first host offset"
    )
    if prefix != 24 or first_offset != 10:
        raise AcceptanceError("M4j addressing differs from the closed /24 offset contract")

    networks = _mapping(topology["networks"], label="M4j networks")
    if tuple(networks) != tuple(EXPECTED_NETWORKS):
        raise AcceptanceError("M4j network set or deterministic order differs")
    parsed_networks: dict[str, ipaddress.IPv4Network] = {}
    internal_names: set[str] = set()
    for name, expected in EXPECTED_NETWORKS.items():
        network = _mapping(networks[name], label=f"M4j network {name}")
        _exact_fields(network, EXPECTED_NETWORK_FIELDS, label=f"M4j network {name}")
        if (
            network["kind"] != expected["kind"]
            or network["purpose"] != expected["purpose"]
            or tuple(network["members"]) != expected["members"]
        ):
            raise AcceptanceError(f"M4j network {name} differs from the closed boundary")
        parsed = _parse_network(network["cidr"], label=f"M4j network {name} CIDR")
        rfc1918: tuple[ipaddress.IPv4Network, ...] = (
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        )
        if parsed.prefixlen != prefix or not any(parsed.subnet_of(space) for space in rfc1918):
            raise AcceptanceError(f"M4j network {name} must be a private /24")
        parsed_networks[name] = parsed
        if name == "management":
            gateway = _parse_address(network["gateway"], label="management gateway")
            if gateway != parsed.network_address + 1 or network["internal_name"] is not None:
                raise AcceptanceError("M4j management gateway contract differs")
        else:
            if network["gateway"] is not None:
                raise AcceptanceError(f"M4j data network {name} must not be routed")
            internal_name = _safe_text(
                network["internal_name"], label=f"M4j network {name} internal name"
            )
            if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", internal_name) is None:
                raise AcceptanceError(f"M4j network {name} internal name is unsafe")
            if internal_name != f"aegis-m4j-{name.replace('_', '-')}":
                raise AcceptanceError(f"M4j network {name} internal name differs")
            if internal_name in internal_names:
                raise AcceptanceError("M4j internal network names are not unique")
            internal_names.add(internal_name)
    for index, left in enumerate(parsed_networks.values()):
        for right in tuple(parsed_networks.values())[index + 1 :]:
            if left.overlaps(right):
                raise AcceptanceError("M4j topology networks overlap")

    nodes = _mapping(topology["nodes"], label="M4j nodes")
    if tuple(nodes) != EXPECTED_ROLES:
        raise AcceptanceError("M4j role set or deterministic order differs")
    observed_addresses: set[ipaddress.IPv4Address] = set()
    total_cpus = 0
    total_memory = 0
    for role_index, role in enumerate(EXPECTED_ROLES):
        node = _mapping(nodes[role], label=f"M4j node {role}")
        _exact_fields(node, EXPECTED_NODE_FIELDS, label=f"M4j node {role}")
        if node["hostname"] != f"aegis-{role}":
            raise AcceptanceError(f"M4j hostname differs for {role}")
        cpus = _positive_integer(node["cpus"], label=f"M4j {role} CPUs")
        memory = _positive_integer(node["memory_mb"], label=f"M4j {role} memory")
        if memory % 256:
            raise AcceptanceError(f"M4j {role} memory is not a 256 MiB increment")
        if (
            cpus > capacity_values["max_node_cpus"]
            or memory > capacity_values["max_node_memory_mb"]
        ):
            raise AcceptanceError(f"M4j {role} exceeds per-node capacity")
        total_cpus += cpus
        total_memory += memory
        interfaces = _mapping(node["interfaces"], label=f"M4j node {role} interfaces")
        expected_interface_names = tuple(
            name for name, expected in EXPECTED_NETWORKS.items() if role in expected["members"]
        )
        if tuple(interfaces) != expected_interface_names:
            raise AcceptanceError(f"M4j interface membership differs for {role}")
        for network_name, value in interfaces.items():
            address = _parse_address(value, label=f"M4j {role} {network_name} address")
            parsed_node_network = parsed_networks[network_name]
            expected_address = (
                parsed_node_network.network_address + first_offset + role_index
            )
            if address != expected_address or address in observed_addresses:
                raise AcceptanceError(f"M4j address is unsafe or nondeterministic for {role}")
            observed_addresses.add(address)
    if (
        total_cpus > capacity_values["max_total_cpus"]
        or total_memory > capacity_values["max_total_memory_mb"]
    ):
        raise AcceptanceError("M4j roles exceed aggregate capacity")
    return topology


def _expected_deployment_listeners(topology: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    nodes = _mapping(topology["nodes"], label="M4j nodes")

    def address(role: str, network: str) -> str:
        node = _mapping(nodes[role], label=f"M4j node {role}")
        return str(_mapping(node["interfaces"], label=f"M4j {role} interfaces")[network])

    def listener(
        role: str,
        service: str,
        scope: str,
        network: str,
        bind_address: str,
        transport: str,
        port: int | None,
    ) -> dict[str, Any]:
        return {
            "role": role,
            "service": service,
            "scope": scope,
            "network": network,
            "bind_address": bind_address,
            "transport": transport,
            "port": port,
        }

    listeners = {
        f"{role}-sshd": listener(
            role,
            "sshd",
            "infrastructure",
            "management",
            address(role, "management"),
            "tcp",
            22,
        )
        for role in EXPECTED_ROLES
    }
    listeners.update(
        {
            "spire-server-enrollment": listener(
                "trust",
                "spire-server",
                "identity",
                "trust_enrollment",
                address("trust", "trust_enrollment"),
                "tcp",
                8081,
            ),
            "spire-server-admin": listener(
                "trust",
                "spire-server",
                "identity",
                "local",
                "/run/spire/server/private/api.sock",
                "unix",
                None,
            ),
            "trust-spire-workload-api": listener(
                "trust",
                "spire-agent",
                "identity",
                "local",
                "/run/spire/agent/public/api.sock",
                "unix",
                None,
            ),
            "agents-spire-workload-api": listener(
                "agents",
                "spire-agent",
                "identity",
                "local",
                "/run/spire/agent/public/api.sock",
                "unix",
                None,
            ),
            "gateway-spire-workload-api": listener(
                "gateway",
                "spire-agent",
                "identity",
                "local",
                "/run/spire/agent/public/api.sock",
                "unix",
                None,
            ),
            "ot-spire-workload-api": listener(
                "ot",
                "spire-agent",
                "identity",
                "local",
                "/run/spire/agent/public/api.sock",
                "unix",
                None,
            ),
            "simulation-spire-workload-api": listener(
                "simulation",
                "spire-agent",
                "identity",
                "local",
                "/run/spire/agent/public/api.sock",
                "unix",
                None,
            ),
            "segmented-gateway-api": listener(
                "gateway",
                "segmented-gateway",
                "application",
                "agent_lane",
                address("gateway", "agent_lane"),
                "tcp",
                8081,
            ),
            "policy-relay-api": listener(
                "trust",
                "policy-relay",
                "application",
                "control_dmz",
                address("trust", "control_dmz"),
                "tcp",
                8181,
            ),
            "opa-loopback": listener(
                "trust",
                "opa",
                "application",
                "local",
                "127.0.0.1",
                "tcp",
                8182,
            ),
            "observer-api": listener(
                "trust",
                "observer",
                "application",
                "control_dmz",
                address("trust", "control_dmz"),
                "tcp",
                8082,
            ),
            "candidate-api": listener(
                "trust",
                "candidate",
                "application",
                "control_dmz",
                address("trust", "control_dmz"),
                "tcp",
                8085,
            ),
            "ot-adapter-api": listener(
                "ot",
                "ot-adapter",
                "application",
                "control_dmz",
                address("ot", "control_dmz"),
                "tcp",
                8083,
            ),
            "plant-api": listener(
                "simulation",
                "plant",
                "application",
                "simulation_lane",
                address("simulation", "simulation_lane"),
                "tcp",
                8084,
            ),
        }
    )
    return listeners


def _load_deployment(material: bytes, topology: Mapping[str, Any]) -> dict[str, Any]:
    if not material or len(material) > _MAX_TOPOLOGY_BYTES:
        raise AcceptanceError("M4j deployment contract size is invalid")
    deployment = _load_unique_yaml(material, label="M4j deployment contract")
    _exact_fields(
        deployment,
        frozenset(
            {
                "schema_version",
                "deployment_status",
                "claim_boundary",
                "topology_binding",
                "policy",
                "roles",
                "listeners",
                "external_control_sources",
                "peer_edges",
                "implementation_gates",
            }
        ),
        label="M4j deployment contract",
    )
    if (
        deployment["schema_version"] != DEPLOYMENT_SCHEMA_VERSION
        or deployment["deployment_status"] != "configuration_only"
        or deployment["claim_boundary"]
        != "no_live_deployment_or_multi_host_isolation_evidence"
    ):
        raise AcceptanceError("M4j deployment identity or claim boundary differs")

    topology_binding = _mapping(
        deployment["topology_binding"], label="M4j deployment topology binding"
    )
    _exact_fields(
        topology_binding,
        frozenset({"path", "schema_version", "canonical_sha256"}),
        label="M4j deployment topology binding",
    )
    if topology_binding != {
        "path": TOPOLOGY_RELATIVE_PATH,
        "schema_version": TOPOLOGY_SCHEMA_VERSION,
        "canonical_sha256": _sha256(_canonical_bytes(topology)),
    }:
        raise AcceptanceError("M4j deployment is not bound to the authoritative topology")

    policy = _mapping(deployment["policy"], label="M4j deployment policy")
    expected_policy = {
        "default_peer_policy": "deny",
        "management_purpose": "orchestration_and_evidence_only",
        "management_application_listeners_allowed": False,
        "bootstrap_nat_purpose": "vagrant_bootstrap_only",
        "bootstrap_nat_application_bindings_allowed": False,
        "agent_control_ingress_role": "gateway",
        "direct_agents_to_ot_allowed": False,
        "direct_agents_to_simulation_allowed": False,
        "spire_enrollment_network": "trust_enrollment",
        "spire_workload_api_socket": "/run/spire/agent/public/api.sock",
    }
    if policy != expected_policy:
        raise AcceptanceError("M4j deployment policy differs from the closed contract")

    topology_nodes = _mapping(topology["nodes"], label="M4j nodes")
    roles = _mapping(deployment["roles"], label="M4j deployment roles")
    if tuple(roles) != EXPECTED_ROLES:
        raise AcceptanceError("M4j deployment role set or order differs")
    for role in EXPECTED_ROLES:
        value = _mapping(roles[role], label=f"M4j deployment role {role}")
        _exact_fields(
            value,
            frozenset({"hostname", "workloads", "infrastructure_services"}),
            label=f"M4j deployment role {role}",
        )
        if (
            value["hostname"]
            != _mapping(topology_nodes[role], label=f"M4j node {role}")["hostname"]
            or tuple(value["workloads"]) != EXPECTED_WORKLOAD_PLACEMENT[role]
            or value["infrastructure_services"] != ["sshd"]
        ):
            raise AcceptanceError(f"M4j service placement differs for {role}")

    listeners = _mapping(deployment["listeners"], label="M4j deployment listeners")
    expected_listeners = _expected_deployment_listeners(topology)
    if listeners != expected_listeners:
        raise AcceptanceError("M4j listener contract differs from the closed role placement")

    external_sources = _mapping(
        deployment["external_control_sources"], label="M4j external control sources"
    )
    management_gateway = _mapping(
        _mapping(topology["networks"], label="M4j networks")["management"],
        label="M4j management network",
    )["gateway"]
    expected_ssh_listeners = [f"{role}-sshd" for role in EXPECTED_ROLES]
    if external_sources != {
        "vagrant-host": {
            "source_type": "external_host",
            "source_address": management_gateway,
            "network": "management",
            "protocol": "ssh",
            "authentication": "ssh_public_key",
            "purpose": "vagrant_control_provisioning_and_evidence",
            "destination_listeners": expected_ssh_listeners,
        }
    }:
        raise AcceptanceError("M4j external management source contract differs")

    edges = deployment["peer_edges"]
    if not isinstance(edges, list):
        raise AcceptanceError("M4j peer-edge contract must be a list")
    edge_ids: set[str] = set()
    allowed_roles: dict[str, set[str]] = {listener_id: set() for listener_id in listeners}
    for raw_edge in edges:
        edge = _mapping(raw_edge, label="M4j peer edge")
        _exact_fields(
            edge,
            frozenset(
                {
                    "id",
                    "source_role",
                    "source_service",
                    "destination_listener",
                    "network",
                    "protocol",
                    "authentication",
                }
            ),
            label="M4j peer edge",
        )
        edge_id = _safe_text(edge["id"], label="M4j peer edge ID")
        source_role = edge["source_role"]
        destination_id = edge["destination_listener"]
        if (
            edge_id in edge_ids
            or source_role not in EXPECTED_ROLES
            or destination_id not in listeners
        ):
            raise AcceptanceError("M4j peer edge is duplicated or references an unknown role")
        edge_ids.add(edge_id)
        destination = _mapping(listeners[destination_id], label="M4j destination listener")
        if edge["network"] != destination["network"]:
            raise AcceptanceError("M4j peer edge network differs from its listener")
        allowed_roles[destination_id].add(str(source_role))

    expected_network_sources = {
        "spire-server-enrollment": {"trust", "agents", "gateway", "ot", "simulation"},
        "segmented-gateway-api": {"agents"},
        "observer-api": {"gateway", "ot"},
        "candidate-api": {"gateway"},
        "ot-adapter-api": {"gateway"},
        "plant-api": {"trust", "ot"},
        "policy-relay-api": {"gateway"},
        "opa-loopback": {"trust"},
    }
    for listener_id, expected_sources in expected_network_sources.items():
        if allowed_roles[listener_id] != expected_sources:
            raise AcceptanceError(f"M4j peer sources differ for {listener_id}")
    if any(
        source == "agents"
        and _mapping(listeners[destination], label="M4j listener")["role"]
        in {"ot", "simulation"}
        for destination, sources in allowed_roles.items()
        for source in sources
    ):
        raise AcceptanceError("M4j deployment permits a direct agents bypass path")

    agent_gateway_edges = [
        edge
        for edge in edges
        if _mapping(edge, label="M4j peer edge").get("id")
        == "agent-probe-to-segmented-gateway"
    ]
    if agent_gateway_edges != [
        {
            "id": "agent-probe-to-segmented-gateway",
            "source_role": "agents",
            "source_service": "agent-probe",
            "destination_listener": "segmented-gateway-api",
            "network": "agent_lane",
            "protocol": "https",
            "authentication": "spiffe_mtls_plus_signed_workload_capability",
        }
    ]:
        raise AcceptanceError("agent-to-gateway application edge is not mTLS-bound")

    implementation = deployment["implementation_gates"]
    expected_implementation = [
        {
            "gate_id": "multi_host_spire_bootstrap",
            "status": "implemented_live_validation_pending",
            "blocks": "live_multi_host_deployment_evidence",
            "implementation_contracts": [
                "infra/m4j/workloads.yml",
                "infra/ansible/workloads.yml",
                "scripts/deploy_m4j_workloads.py",
                "scripts/reconcile_m4j_spire_entries.py",
                "scripts/revoke_m4j_spire_join_token.py",
            ],
            "implemented_controls": [
                "distinct_node_attestation_identity_per_host",
                "one_time_non_shared_join_material_per_host",
                "exact_workload_registration_parent_binding",
                "bounded_managed_registration_pruning_and_readback",
                "join_token_cleanup_and_absence_verification",
            ],
            "live_evidence_status": "not_run",
            "required_validation": (
                "apply_exact_source_bundle_then_run_signed_two_phase_live_workload_"
                "probe_on_all_six_hosts"
            ),
        }
    ]
    if (
        not isinstance(implementation, list)
        or implementation != expected_implementation
    ):
        raise AcceptanceError("M4j SPIRE implementation/live-evidence boundary differs")
    return deployment


def _topology_projection(topology: Mapping[str, Any]) -> dict[str, Any]:
    networks = _mapping(topology["networks"], label="M4j networks")
    nodes = _mapping(topology["nodes"], label="M4j nodes")
    return {
        "schema_version": topology["schema_version"],
        "roles": list(EXPECTED_ROLES),
        "networks": {
            name: {
                "cidr": _mapping(value, label=name)["cidr"],
                "kind": _mapping(value, label=name)["kind"],
                "purpose": _mapping(value, label=name)["purpose"],
                "members": list(_mapping(value, label=name)["members"]),
            }
            for name, value in networks.items()
        },
        "nodes": {
            role: {
                "hostname": _mapping(value, label=role)["hostname"],
                "interfaces": dict(_mapping(value, label=role)["interfaces"]),
            }
            for role, value in nodes.items()
        },
    }


def _allowed_source_roles(deployment: Mapping[str, Any]) -> dict[str, set[str]]:
    listeners = _mapping(deployment["listeners"], label="M4j deployment listeners")
    allowed: dict[str, set[str]] = {listener_id: set() for listener_id in listeners}
    edges = deployment["peer_edges"]
    if not isinstance(edges, list):
        raise AcceptanceError("M4j peer-edge contract must be a list")
    for raw_edge in edges:
        edge = _mapping(raw_edge, label="M4j peer edge")
        destination = edge.get("destination_listener")
        source = edge.get("source_role")
        if not isinstance(destination, str) or destination not in allowed:
            raise AcceptanceError("M4j peer edge references an unknown listener")
        if not isinstance(source, str) or source not in EXPECTED_ROLES:
            raise AcceptanceError("M4j peer edge references an unknown source role")
        allowed[destination].add(source)
    return allowed


def _listener_contract(deployment: Mapping[str, Any]) -> list[dict[str, Any]]:
    listeners = _mapping(deployment["listeners"], label="M4j deployment listeners")
    allowed = _allowed_source_roles(deployment)
    projected: list[dict[str, Any]] = []
    for listener_id, raw_listener in listeners.items():
        listener = _mapping(raw_listener, label=f"M4j listener {listener_id}")
        projected.append(
            {
                "listener_id": listener_id,
                "service": listener["service"],
                "role": listener["role"],
                "scope": listener["scope"],
                "network": listener["network"],
                "bind_address": listener["bind_address"],
                "transport": listener["transport"],
                "port": listener["port"],
                "allowed_source_roles": sorted(allowed[listener_id]),
                "wildcard_binding_allowed": False,
            }
        )
    return projected


def _source_bind_address(
    topology: Mapping[str, Any], source_role: str, destination_network: str
) -> tuple[str, str]:
    node = _mapping(
        _mapping(topology["nodes"], label="M4j nodes")[source_role],
        label=f"M4j node {source_role}",
    )
    interfaces = _mapping(node["interfaces"], label=f"M4j node {source_role} interfaces")
    if destination_network in interfaces:
        return destination_network, str(interfaces[destination_network])
    preferred_operational_lane = {
        "trust": "control_dmz",
        "agents": "agent_lane",
        "gateway": "control_dmz",
        "ot": "control_dmz",
        "simulation": "simulation_lane",
    }.get(source_role)
    if preferred_operational_lane is not None and preferred_operational_lane in interfaces:
        return preferred_operational_lane, str(interfaces[preferred_operational_lane])
    for network_name, address in interfaces.items():
        if network_name != "management":
            return network_name, str(address)
    return "management", str(interfaces["management"])


def _connectivity_contract(
    topology: Mapping[str, Any], deployment: Mapping[str, Any]
) -> list[dict[str, Any]]:
    listeners = _listener_contract(deployment)
    checks: list[dict[str, Any]] = []
    for listener in listeners:
        if listener["transport"] != "tcp":
            continue
        if listener["network"] == "local":
            checks.append(
                {
                    "check_id": (
                        f"{listener['role']}-local-to-{listener['listener_id']}-"
                        f"{listener['port']}"
                    ),
                    "source_role": listener["role"],
                    "source_network": "local",
                    "source_address": "127.0.0.1",
                    "destination_role": listener["role"],
                    "destination_network": "local",
                    "destination_address": listener["bind_address"],
                    "port": listener["port"],
                    "expected_connected": True,
                }
            )
            continue
        for source_role in EXPECTED_ROLES:
            if source_role == listener["role"]:
                continue
            source_network, source_address = _source_bind_address(
                topology, source_role, str(listener["network"])
            )
            expected_connected = source_role in listener["allowed_source_roles"]
            check_id = f"{source_role}-to-{listener['listener_id']}-{listener['port']}"
            checks.append(
                {
                    "check_id": check_id,
                    "source_role": source_role,
                    "source_network": source_network,
                    "source_address": source_address,
                    "destination_role": listener["role"],
                    "destination_network": listener["network"],
                    "destination_address": listener["bind_address"],
                    "port": listener["port"],
                    "expected_connected": expected_connected,
                }
            )
    return checks


def _firewall_contract(
    topology: Mapping[str, Any],
    deployment: Mapping[str, Any],
    role: str,
    *,
    interface_names: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    nodes = _mapping(topology["nodes"], label="M4j nodes")
    listeners = _mapping(deployment["listeners"], label="M4j deployment listeners")
    destination_node = _mapping(nodes[role], label=f"M4j node {role}")
    destination_interfaces = _mapping(
        destination_node["interfaces"], label=f"M4j {role} interfaces"
    )
    rules_by_key: dict[tuple[str, str, str, int], dict[str, Any]] = {}

    def add_rule(
        *,
        source_id: str,
        source_address: str,
        listener_id: str,
        edge_id: str,
    ) -> None:
        listener = _mapping(listeners[listener_id], label=f"M4j listener {listener_id}")
        if (
            listener["role"] != role
            or listener["transport"] != "tcp"
            or listener["network"] == "local"
            or not isinstance(listener["port"], int)
        ):
            raise AcceptanceError("firewall rule references a non-ingress listener")
        network = str(listener["network"])
        if network not in destination_interfaces:
            raise AcceptanceError("firewall listener network is absent from its role")
        source = str(_parse_address(source_address, label="firewall source address"))
        destination = str(
            _parse_address(listener["bind_address"], label="firewall destination address")
        )
        if interface_names is not None and network not in interface_names:
            raise AcceptanceError("runtime firewall interface could not be resolved")
        interface = (
            interface_names[network]
            if interface_names is not None
            else "resolved_at_runtime_from_exact_address"
        )
        port = int(listener["port"])
        key = (network, source, destination, port)
        existing = rules_by_key.get(key)
        if existing is None:
            rules_by_key[key] = {
                "direction": "in",
                "interface_network": network,
                "interface": interface,
                "source_address": source,
                "destination_address": destination,
                "protocol": "tcp",
                "port": port,
                "listener_ids": [listener_id],
                "source_ids": [source_id],
                "edge_ids": [edge_id],
            }
            return
        for field, value in (
            ("listener_ids", listener_id),
            ("source_ids", source_id),
            ("edge_ids", edge_id),
        ):
            values = existing[field]
            if not isinstance(values, list):
                raise AcceptanceError("firewall rule aggregation was malformed")
            if value not in values:
                values.append(value)

    external_sources = _mapping(
        deployment["external_control_sources"], label="M4j external control sources"
    )
    for source_name, raw_source in external_sources.items():
        source = _mapping(raw_source, label=f"M4j external source {source_name}")
        destinations = source.get("destination_listeners")
        if not isinstance(destinations, list):
            raise AcceptanceError("external control destinations were malformed")
        for listener_id in destinations:
            if not isinstance(listener_id, str) or listener_id not in listeners:
                raise AcceptanceError("external control destination is unknown")
            listener = _mapping(listeners[listener_id], label=f"M4j listener {listener_id}")
            if listener["role"] != role:
                continue
            add_rule(
                source_id=f"external:{source_name}",
                source_address=str(source["source_address"]),
                listener_id=listener_id,
                edge_id=f"external:{source_name}-to-{listener_id}",
            )

    edges = deployment["peer_edges"]
    if not isinstance(edges, list):
        raise AcceptanceError("M4j peer-edge contract must be a list")
    for raw_edge in edges:
        edge = _mapping(raw_edge, label="M4j peer edge")
        listener_id = edge.get("destination_listener")
        source_role = edge.get("source_role")
        if (
            not isinstance(listener_id, str)
            or listener_id not in listeners
            or not isinstance(source_role, str)
            or source_role not in EXPECTED_ROLES
        ):
            raise AcceptanceError("M4j peer edge could not define a firewall rule")
        listener = _mapping(listeners[listener_id], label=f"M4j listener {listener_id}")
        if (
            listener["role"] != role
            or listener["transport"] != "tcp"
            or listener["network"] == "local"
            or source_role == role
        ):
            continue
        source_node = _mapping(nodes[source_role], label=f"M4j node {source_role}")
        source_interfaces = _mapping(
            source_node["interfaces"], label=f"M4j {source_role} interfaces"
        )
        network = str(listener["network"])
        if network not in source_interfaces:
            raise AcceptanceError("peer edge source lacks the destination network")
        add_rule(
            source_id=f"role:{source_role}",
            source_address=str(source_interfaces[network]),
            listener_id=listener_id,
            edge_id=str(edge["id"]),
        )

    rules = list(rules_by_key.values())
    for rule in rules:
        for field in ("listener_ids", "source_ids", "edge_ids"):
            rule[field] = sorted(rule[field])
    return sorted(
        rules,
        key=lambda rule: (
            str(rule["interface_network"]),
            str(rule["destination_address"]),
            int(rule["port"]),
            str(rule["source_address"]),
        ),
    )


def build_plan(root: Path = ROOT) -> dict[str, Any]:
    binding = _source_binding(root)
    committed = _mapping(binding["_committed_material"], label="committed material")
    topology_material = committed[TOPOLOGY_RELATIVE_PATH]
    deployment_material = committed[DEPLOYMENT_RELATIVE_PATH]
    if not isinstance(topology_material, bytes) or not isinstance(deployment_material, bytes):
        raise AcceptanceError("committed topology or deployment material was malformed")
    topology = _load_topology(topology_material)
    deployment = _load_deployment(deployment_material, topology)
    listener_contract = _listener_contract(deployment)
    connectivity_contract = _connectivity_contract(topology, deployment)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "plan_only",
        "network_acceptance_passed": False,
        "source_binding": _public_source_binding(binding),
        "topology": _topology_projection(topology),
        "deployment_schema_version": deployment["schema_version"],
        "implementation_gates": deployment["implementation_gates"],
        "workload_live_probe": {
            "evidence_supplied": False,
            "status": "not_run",
        },
        "listener_contract": listener_contract,
        "connectivity_contract": connectivity_contract,
        "firewall_contract": {
            role: _firewall_contract(topology, deployment, role)
            for role in EXPECTED_ROLES
        },
        "gateway_partition_contract": {
            "source_role": "agents",
            "destination_role": "gateway",
            "service": "segmented-gateway",
            "port": 8081,
            "method": "one uniquely tagged exact INPUT reject rule with verified exact removal",
        },
        "packet_metadata_contract": {
            "method": "pre_and_post_interface_packet_and_byte_counters",
            "payload_capture": False,
        },
        "acceptance_gates": list(ACCEPTANCE_GATES),
        "evidence_boundaries": list(EVIDENCE_BOUNDARIES),
    }


def _remote_script(source: str, payload: Mapping[str, Any]) -> bytes:
    payload_text = _canonical_bytes(payload).decode("ascii")
    prefix = (
        "import json\n"
        f"PAYLOAD = json.loads({payload_text!r})\n"
    )
    return (prefix + source).encode("utf-8")


def _execute_ssh(
    ssh_config: Path,
    role: str,
    remote_argv: tuple[str, ...],
    stdin_bytes: bytes,
    timeout_seconds: float,
) -> SshOutcome:
    if _SAFE_ROLE.fullmatch(role) is None or role not in EXPECTED_ROLES:
        raise AcceptanceError("SSH role alias is invalid")
    if not _TRUSTED_SSH.is_file() or not os.access(_TRUSTED_SSH, os.X_OK):
        raise AcceptanceError("the pinned /usr/bin/ssh executable is unavailable")
    command = (
        str(_TRUSTED_SSH),
        "-F",
        str(ssh_config),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={ssh_config.parent / 'known_hosts'}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "HostKeyAlgorithms=ssh-ed25519",
        "-o",
        "CheckHostIP=yes",
        "-o",
        "CanonicalizeHostname=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        role,
        "--",
        *remote_argv,
    )
    environment = {
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    started = time.monotonic_ns()
    try:
        completed = subprocess.run(  # noqa: S603 - validated SSH alias and fixed argv
            command,
            check=False,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout_seconds,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcceptanceError(f"SSH command timed out for role {role}") from exc
    elapsed_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
    if (
        len(completed.stdout) > _MAX_REMOTE_STREAM_BYTES
        or len(completed.stderr) > _MAX_REMOTE_STREAM_BYTES
    ):
        raise AcceptanceError(f"SSH command output exceeded its bound for role {role}")
    return SshOutcome(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        elapsed_ms=elapsed_ms,
    )


def _recorded_ssh(
    *,
    ssh_config: Path,
    role: str,
    command_id: str,
    remote_argv: tuple[str, ...],
    stdin_bytes: bytes,
    command_records: list[dict[str, Any]],
    allowed_returncodes: frozenset[int] = frozenset({0}),
    executor: SshExecutor | None = None,
) -> SshOutcome:
    outcome = (executor or _execute_ssh)(
        ssh_config,
        role,
        remote_argv,
        stdin_bytes,
        _SSH_TIMEOUT_SECONDS,
    )
    sequence = len(command_records) + 1
    command_material = {
        "transport": "ssh_config_role_alias",
        "role": role,
        "remote_argv": list(remote_argv),
        "stdin_sha256": _sha256(stdin_bytes),
        "stdin_size_bytes": len(stdin_bytes),
    }
    command_records.append(
        {
            "sequence": sequence,
            "command_id": command_id,
            "role": role,
            "command_sha256": _sha256(_canonical_bytes(command_material)),
            "stdin_sha256": command_material["stdin_sha256"],
            "stdin_size_bytes": len(stdin_bytes),
            "result": {
                "returncode": outcome.returncode,
                "stdout_sha256": _sha256(outcome.stdout),
                "stdout_size_bytes": len(outcome.stdout),
                "stderr_sha256": _sha256(outcome.stderr),
                "stderr_size_bytes": len(outcome.stderr),
                "elapsed_ms": outcome.elapsed_ms,
            },
        }
    )
    if outcome.returncode not in allowed_returncodes:
        raise AcceptanceError(f"remote command {command_id} failed for role {role}")
    return outcome


def _json_output(outcome: SshOutcome, *, label: str) -> dict[str, Any]:
    if not outcome.stdout or len(outcome.stdout) > _MAX_REMOTE_STREAM_BYTES:
        raise AcceptanceError(f"{label} JSON output size is invalid")
    try:
        value = json.loads(outcome.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError(f"{label} did not return valid JSON") from exc
    return _mapping(value, label=label)


def _parse_ss_local(value: str) -> tuple[str, int]:
    fields = value.split()
    if len(fields) < 4 or fields[0] != "LISTEN":
        raise AcceptanceError("ss listener output was malformed")
    endpoint = fields[3]
    if endpoint.startswith("["):
        close = endpoint.rfind("]:")
        if close < 0:
            raise AcceptanceError("IPv6 listener endpoint was malformed")
        host = endpoint[1:close]
        port_text = endpoint[close + 2 :]
    else:
        try:
            host, port_text = endpoint.rsplit(":", maxsplit=1)
        except ValueError as exc:
            raise AcceptanceError("listener endpoint was malformed") from exc
    try:
        port = int(port_text)
    except ValueError as exc:
        raise AcceptanceError("listener port was malformed") from exc
    if not 1 <= port <= 65535:
        raise AcceptanceError("listener port was outside the valid range")
    return host, port


def _normalize_firewall_host(value: str, *, label: str) -> str:
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 32:
                raise AcceptanceError(f"{label} must identify exactly one IPv4 host")
            return str(network.network_address)
        return str(_parse_address(value, label=label))
    except ValueError as exc:
        raise AcceptanceError(f"{label} is invalid") from exc


def _validate_ufw_rules(
    *,
    role: str,
    added: str,
    numbered: str,
    expected: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    observed_keys: list[tuple[str, str, str, int]] = []
    header_seen = False
    for raw_line in added.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Added user rules"):
            if header_seen:
                raise AcceptanceError(f"UFW added-rule header was duplicated on {role}")
            header_seen = True
            continue
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError as exc:
            raise AcceptanceError(f"UFW added rule was malformed on {role}") from exc
        if (
            len(tokens) < 13
            or tokens[:4] != ["ufw", "allow", "in", "on"]
            or tokens[5] != "from"
            or tokens[7] != "to"
            or tokens[9] != "port"
            or tokens[11:13] != ["proto", "tcp"]
            or (len(tokens) != 13 and (len(tokens) != 15 or tokens[13] != "comment"))
        ):
            raise AcceptanceError(f"UFW contains a non-exact ingress rule on {role}")
        interface = tokens[4]
        source = _normalize_firewall_host(tokens[6], label=f"{role} UFW source")
        destination = _normalize_firewall_host(
            tokens[8], label=f"{role} UFW destination"
        )
        try:
            port = int(tokens[10])
        except ValueError as exc:
            raise AcceptanceError(f"UFW port was malformed on {role}") from exc
        if not interface or not 1 <= port <= 65535:
            raise AcceptanceError(f"UFW interface or port was malformed on {role}")
        observed_keys.append((interface, source, destination, port))

    expected_keys = [
        (
            str(rule["interface"]),
            str(rule["source_address"]),
            str(rule["destination_address"]),
            int(rule["port"]),
        )
        for rule in expected
    ]
    if (
        not header_seen
        or len(observed_keys) != len(set(observed_keys))
        or set(observed_keys) != set(expected_keys)
        or len(observed_keys) != len(expected_keys)
    ):
        raise AcceptanceError(f"UFW ingress rules differ from deployment edges on {role}")

    allow_in_lines = [line for line in numbered.splitlines() if "ALLOW IN" in line]
    routed_or_outbound_allows = [
        line
        for line in numbered.splitlines()
        if "ALLOW FWD" in line or "ALLOW OUT" in line
    ]
    if len(allow_in_lines) != len(expected_keys) or routed_or_outbound_allows:
        raise AcceptanceError(f"UFW contains extra inbound, routed, or outbound allows on {role}")
    return [dict(rule) for rule in expected]


def _interface_counters(
    raw: Any, expected_interfaces: Mapping[str, str]
) -> dict[str, dict[str, int]]:
    if not isinstance(raw, list):
        raise AcceptanceError("link statistics were malformed")
    by_name: dict[str, Mapping[str, Any]] = {}
    for item in raw:
        mapping = _mapping(item, label="link statistic")
        name = mapping.get("ifname")
        if isinstance(name, str):
            by_name[name] = mapping
    counters: dict[str, dict[str, int]] = {}
    for network_name, interface_name in expected_interfaces.items():
        item = by_name.get(interface_name)
        if item is None:
            raise AcceptanceError("expected interface counter metadata is absent")
        stats = item.get("stats64", item.get("stats"))
        stats_mapping = _mapping(stats, label="link counters")
        rx = _mapping(stats_mapping.get("rx"), label="link RX counters")
        tx = _mapping(stats_mapping.get("tx"), label="link TX counters")
        selected: dict[str, int] = {}
        for direction, values in (("rx", rx), ("tx", tx)):
            for field in ("packets", "bytes"):
                value = values.get(field)
                if type(value) is not int or value < 0:
                    raise AcceptanceError("interface counter was malformed")
                selected[f"{direction}_{field}"] = value
        counters[network_name] = selected
    return counters


def _validate_host_facts(
    role: str,
    topology: Mapping[str, Any],
    deployment: Mapping[str, Any],
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    node = _mapping(
        _mapping(topology["nodes"], label="M4j nodes")[role],
        label=f"M4j node {role}",
    )
    expected_addresses = _mapping(node["interfaces"], label=f"M4j node {role} interfaces")
    if raw.get("hostname") != node["hostname"]:
        raise AcceptanceError(f"hostname identity mismatch for {role}")
    expected_marker = (
        f"schema_version={TOPOLOGY_SCHEMA_VERSION}\n"
        f"role={role}\n"
        "deployment_status=configuration_only\n"
    )
    if (
        raw.get("role_marker") != expected_marker
        or raw.get("role_marker_mode") != 0o440
        or raw.get("role_marker_uid") != 0
    ):
        raise AcceptanceError(f"role marker identity mismatch for {role}")

    raw_addresses = raw.get("addresses")
    if not isinstance(raw_addresses, list):
        raise AcceptanceError(f"address inventory was malformed for {role}")
    address_entries: list[tuple[str, str, int]] = []
    for raw_interface in raw_addresses:
        interface = _mapping(raw_interface, label=f"{role} address interface")
        interface_name = interface.get("ifname")
        if not isinstance(interface_name, str) or not interface_name:
            raise AcceptanceError(f"interface name was malformed for {role}")
        addr_info = interface.get("addr_info")
        if not isinstance(addr_info, list):
            raise AcceptanceError(f"address information was malformed for {role}")
        for raw_address in addr_info:
            address = _mapping(raw_address, label=f"{role} address")
            if address.get("family") != "inet" or address.get("scope") != "global":
                continue
            local = address.get("local")
            prefixlen = address.get("prefixlen")
            if not isinstance(local, str) or type(prefixlen) is not int:
                raise AcceptanceError(f"global address was malformed for {role}")
            _parse_address(local, label=f"{role} global address")
            address_entries.append((local, interface_name, prefixlen))

    topology_networks = {
        name: _parse_network(
            _mapping(value, label=f"M4j network {name}")["cidr"],
            label=f"M4j network {name} CIDR",
        )
        for name, value in _mapping(topology["networks"], label="M4j networks").items()
    }
    interfaces: dict[str, str] = {}
    interface_projection: list[dict[str, Any]] = []
    for network_name, expected_address in expected_addresses.items():
        matches = [entry for entry in address_entries if entry[0] == expected_address]
        if len(matches) != 1 or matches[0][2] != topology_networks[network_name].prefixlen:
            raise AcceptanceError(f"authoritative {network_name} address mismatch for {role}")
        interface_name = matches[0][1]
        if interface_name in interfaces.values():
            raise AcceptanceError(f"topology lanes share an interface on {role}")
        interfaces[network_name] = interface_name
        interface_projection.append(
            {
                "network": network_name,
                "interface": interface_name,
                "address": expected_address,
                "prefix_length": matches[0][2],
            }
        )
    for local, _, _ in address_entries:
        parsed = _parse_address(local, label=f"{role} global address")
        containing = [name for name, network in topology_networks.items() if parsed in network]
        if containing and local not in expected_addresses.values():
            raise AcceptanceError(f"unexpected topology-network address observed on {role}")

    raw_routes = raw.get("routes")
    if not isinstance(raw_routes, list):
        raise AcceptanceError(f"route inventory was malformed for {role}")
    routes = [_mapping(value, label=f"{role} route") for value in raw_routes]
    route_projection: list[dict[str, Any]] = []
    for network_name, interface_name in interfaces.items():
        cidr = str(topology_networks[network_name])
        route_matches = [route for route in routes if route.get("dst") == cidr]
        if (
            len(route_matches) != 1
            or route_matches[0].get("dev") != interface_name
            or "gateway" in route_matches[0]
        ):
            raise AcceptanceError(f"connected route mismatch for {role}/{network_name}")
        route_projection.append(
            {"destination": cidr, "interface": interface_name, "gateway": None}
        )
    for route in routes:
        destination = route.get("dst")
        if destination in (None, "default"):
            continue
        if not isinstance(destination, str):
            raise AcceptanceError(f"route destination was malformed for {role}")
        try:
            parsed_route = ipaddress.ip_network(destination, strict=False)
        except ValueError as exc:
            raise AcceptanceError(f"route destination was malformed for {role}") from exc
        if not isinstance(parsed_route, ipaddress.IPv4Network):
            continue
        overlapping = [
            name
            for name, network in topology_networks.items()
            if parsed_route.overlaps(network)
        ]
        if overlapping and destination not in {
            str(topology_networks[name]) for name in expected_addresses
        }:
            raise AcceptanceError(f"unexpected route reaches a topology lane from {role}")
    default_routes = [route for route in routes if route.get("dst") in (None, "default")]
    if len(default_routes) != 1:
        raise AcceptanceError(f"bootstrap NAT default route was absent or ambiguous for {role}")
    default_route = default_routes[0]
    if default_route.get("dev") in interfaces.values():
        raise AcceptanceError(f"default route used a topology lane on {role}")
    gateway_value = default_route.get("gateway")
    gateway = _parse_address(gateway_value, label=f"{role} default gateway")
    if any(gateway in network for network in topology_networks.values()):
        raise AcceptanceError(f"default route gateway overlaps a topology lane on {role}")
    route_projection.append(
        {
            "destination": "default",
            "interface": default_route.get("dev"),
            "gateway": str(gateway),
        }
    )

    forwarding = _mapping(raw.get("forwarding"), label=f"{role} forwarding")
    expected_forwarding = {
        "net.ipv4.ip_forward",
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
    }
    if set(forwarding) != expected_forwarding or set(forwarding.values()) != {"0"}:
        raise AcceptanceError(f"IP forwarding was not fully disabled on {role}")

    ufw_verbose = raw.get("ufw_verbose")
    ufw_numbered = raw.get("ufw_numbered")
    ufw_added = raw.get("ufw_added")
    if (
        not isinstance(ufw_verbose, str)
        or not isinstance(ufw_numbered, str)
        or not isinstance(ufw_added, str)
    ):
        raise AcceptanceError(f"UFW evidence was malformed for {role}")
    if (
        "Status: active" not in ufw_verbose
        or "Default: deny (incoming), allow (outgoing), deny (routed)" not in ufw_verbose
    ):
        raise AcceptanceError(f"UFW default-deny policy mismatch for {role}")
    management_interface = interfaces["management"]
    management_address = str(expected_addresses["management"])
    expected_firewall = _firewall_contract(
        topology,
        deployment,
        role,
        interface_names=interfaces,
    )
    normalized_firewall = _validate_ufw_rules(
        role=role,
        added=ufw_added,
        numbered=ufw_numbered,
        expected=expected_firewall,
    )

    listener_contract = [item for item in _listener_contract(deployment) if item["role"] == role]
    expected_tcp = {
        (str(item["bind_address"]), int(item["port"]))
        for item in listener_contract
        if item["transport"] == "tcp" and isinstance(item["port"], int)
    }
    expected_external_tcp = {
        endpoint
        for endpoint, item in (
            (
                (str(listener["bind_address"]), int(listener["port"])),
                listener,
            )
            for listener in listener_contract
            if listener["transport"] == "tcp" and isinstance(listener["port"], int)
        )
        if item["network"] != "local"
    }
    expected_local_tcp = expected_tcp - expected_external_tcp
    expected_unix = {
        str(item["bind_address"])
        for item in listener_contract
        if item["transport"] == "unix"
    }
    ipv4_text = raw.get("listeners_ipv4")
    ipv6_text = raw.get("listeners_ipv6")
    unix_text = raw.get("listeners_unix")
    if (
        not isinstance(ipv4_text, str)
        or not isinstance(ipv6_text, str)
        or not isinstance(unix_text, str)
    ):
        raise AcceptanceError(f"listener evidence was malformed for {role}")
    ipv4 = [_parse_ss_local(line) for line in ipv4_text.splitlines() if line.strip()]
    ipv6 = [_parse_ss_local(line) for line in ipv6_text.splitlines() if line.strip()]
    external_ipv4 = {
        (host, port)
        for host, port in ipv4
        if host in {"0.0.0.0", "*"}  # noqa: S104 - detecting forbidden wildcard listeners
        or not _parse_address(host.split("%", maxsplit=1)[0], label="listener address").is_loopback
    }
    if external_ipv4 != expected_external_tcp:
        raise AcceptanceError(f"role-specific listener contract mismatch for {role}")
    observed_local_tcp = {
        (host, port)
        for host, port in ipv4
        if host not in {"0.0.0.0", "*"}  # noqa: S104 - classifying wildcard listeners
        and _parse_address(
            host.split("%", maxsplit=1)[0], label="local listener address"
        ).is_loopback
        and port >= 1024
    }
    if observed_local_tcp != expected_local_tcp:
        raise AcceptanceError(f"local TCP listener contract mismatch for {role}")
    if ipv6:
        raise AcceptanceError(f"unexpected IPv6 TCP listener observed on {role}")
    observed_unix_paths = {
        field
        for line in unix_text.splitlines()
        for field in line.split()
        if field.startswith("/")
    }
    if not expected_unix.issubset(observed_unix_paths):
        raise AcceptanceError(f"required Unix listener was absent on {role}")

    counters = _interface_counters(raw.get("link_stats"), interfaces)
    return {
        "role": role,
        "hostname": node["hostname"],
        "role_marker_sha256": _sha256(expected_marker.encode("utf-8")),
        "interfaces": interface_projection,
        "routes": route_projection,
        "forwarding": dict(sorted(forwarding.items())),
        "ufw": {
            "active": True,
            "default_incoming": "deny",
            "default_outgoing": "allow",
            "default_routed": "deny",
            "management_interface": management_interface,
            "management_address": management_address,
            "normalized_ingress_rules": normalized_firewall,
            "ingress_rule_count": len(normalized_firewall),
            "extra_inbound_or_routed_allow_count": 0,
        },
        "listeners": {
            "tcp": [
                {
                    "listener_id": item["listener_id"],
                    "service": item["service"],
                    "scope": item["scope"],
                    "network": item["network"],
                    "address": item["bind_address"],
                    "port": item["port"],
                }
                for item in listener_contract
                if item["transport"] == "tcp"
            ],
            "unix": [
                {
                    "listener_id": item["listener_id"],
                    "service": item["service"],
                    "address": item["bind_address"],
                }
                for item in listener_contract
                if item["transport"] == "unix"
            ],
        },
        "interface_counters": counters,
    }


def _collect_facts(
    *,
    phase: str,
    role: str,
    topology: Mapping[str, Any],
    deployment: Mapping[str, Any],
    ssh_config: Path,
    command_records: list[dict[str, Any]],
    executor: SshExecutor | None,
) -> dict[str, Any]:
    script = _remote_script(_REMOTE_FACTS_SOURCE, {"role": role})
    outcome = _recorded_ssh(
        ssh_config=ssh_config,
        role=role,
        command_id=f"{phase}-facts-{role}",
        remote_argv=("/usr/bin/sudo", "-n", "/usr/bin/python3", "-"),
        stdin_bytes=script,
        command_records=command_records,
        executor=executor,
    )
    return _validate_host_facts(
        role,
        topology,
        deployment,
        _json_output(outcome, label=f"{role} facts"),
    )


def _collect_connectivity(
    *,
    phase: str,
    role: str,
    checks: Sequence[Mapping[str, Any]],
    ssh_config: Path,
    command_records: list[dict[str, Any]],
    executor: SshExecutor | None,
) -> list[dict[str, Any]]:
    remote_targets = [
        {
            "check_id": check["check_id"],
            "source_address": check["source_address"],
            "destination_address": check["destination_address"],
            "port": check["port"],
        }
        for check in checks
    ]
    script = _remote_script(
        _REMOTE_CONNECT_SOURCE,
        {"timeout_seconds": _CONNECT_TIMEOUT_SECONDS, "targets": remote_targets},
    )
    outcome = _recorded_ssh(
        ssh_config=ssh_config,
        role=role,
        command_id=f"{phase}-connectivity-{role}",
        remote_argv=("/usr/bin/python3", "-"),
        stdin_bytes=script,
        command_records=command_records,
        executor=executor,
    )
    response = _json_output(outcome, label=f"{role} connectivity")
    raw_results = response.get("results")
    if not isinstance(raw_results, list):
        raise AcceptanceError(f"connectivity results were malformed for {role}")
    expected = {str(check["check_id"]): check for check in checks}
    if len(raw_results) != len(expected):
        raise AcceptanceError(f"connectivity result count differed for {role}")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_result in raw_results:
        result = _mapping(raw_result, label=f"{role} connectivity result")
        check_id = result.get("check_id")
        connected = result.get("connected")
        error_number = result.get("errno")
        elapsed_ms = result.get("elapsed_ms")
        if (
            not isinstance(check_id, str)
            or check_id not in expected
            or check_id in seen
            or type(connected) is not bool
            or (error_number is not None and type(error_number) is not int)
            or type(elapsed_ms) is not int
            or elapsed_ms < 0
        ):
            raise AcceptanceError(f"connectivity result was malformed for {role}")
        check = expected[check_id]
        if connected is not check["expected_connected"]:
            raise AcceptanceError(f"connectivity contract failed: {check_id}")
        seen.add(check_id)
        normalized.append(
            {
                "check_id": check_id,
                "source_role": role,
                "destination_role": check["destination_role"],
                "destination_address": check["destination_address"],
                "port": check["port"],
                "expected_connected": check["expected_connected"],
                "observed_connected": connected,
                "errno": error_number,
                "elapsed_ms": elapsed_ms,
            }
        )
    if seen != set(expected):
        raise AcceptanceError(f"connectivity result IDs differed for {role}")
    return normalized


def _partition_rule_argv(
    *, action: str, source: str, destination: str, port: int, marker: str
) -> tuple[str, ...]:
    if action not in {"check", "insert", "delete"}:
        raise AcceptanceError("gateway partition action is invalid")
    _parse_address(source, label="partition source")
    _parse_address(destination, label="partition destination")
    if not 1 <= port <= 65535 or _SAFE_RUN_TOKEN.fullmatch(marker) is None:
        raise AcceptanceError("gateway partition rule is malformed")
    operation = {"check": "-C", "insert": "-I", "delete": "-D"}[action]
    prefix: tuple[str, ...] = ("/usr/sbin/iptables", "-w", "5", operation, "INPUT")
    if action == "insert":
        prefix += ("1",)
    return (
        "/usr/bin/sudo",
        "-n",
        *prefix,
        "-s",
        source,
        "-d",
        destination,
        "-p",
        "tcp",
        "--dport",
        str(port),
        "-m",
        "comment",
        "--comment",
        f"aegis-m4j-{marker}",
        "-j",
        "REJECT",
        "--reject-with",
        "tcp-reset",
    )


def _reconcile_gateway_partition_absence(
    *,
    source: str,
    destination: str,
    marker: str,
    ssh_config: Path,
    command_records: list[dict[str, Any]],
    executor: SshExecutor | None,
) -> None:
    stable_absence = 0
    last_error: AcceptanceError | None = None
    for read_number in range(1, _PARTITION_MAX_RECONCILIATION_READS + 1):
        try:
            observed = _recorded_ssh(
                ssh_config=ssh_config,
                role="gateway",
                command_id=f"gateway-partition-cleanup-check-{read_number}",
                remote_argv=_partition_rule_argv(
                    action="check",
                    source=source,
                    destination=destination,
                    port=8081,
                    marker=marker,
                ),
                stdin_bytes=b"",
                command_records=command_records,
                allowed_returncodes=frozenset({0, 1}),
                executor=executor,
            )
        except AcceptanceError as exc:
            stable_absence = 0
            last_error = exc
        else:
            if observed.returncode == 1:
                stable_absence += 1
                if stable_absence >= _PARTITION_STABLE_ABSENCE_READS:
                    return
            else:
                stable_absence = 0
                try:
                    _recorded_ssh(
                        ssh_config=ssh_config,
                        role="gateway",
                        command_id=f"gateway-partition-cleanup-delete-{read_number}",
                        remote_argv=_partition_rule_argv(
                            action="delete",
                            source=source,
                            destination=destination,
                            port=8081,
                            marker=marker,
                        ),
                        stdin_bytes=b"",
                        command_records=command_records,
                        allowed_returncodes=frozenset({0, 1}),
                        executor=executor,
                    )
                except AcceptanceError as exc:
                    last_error = exc
        if read_number < _PARTITION_MAX_RECONCILIATION_READS:
            time.sleep(_PARTITION_RECONCILIATION_INTERVAL_SECONDS)
    raise AcceptanceError(
        "gateway partition rule did not remain absent after bounded reconciliation"
    ) from last_error


def _gateway_partition_probe(
    *,
    topology: Mapping[str, Any],
    ssh_config: Path,
    command_records: list[dict[str, Any]],
    executor: SshExecutor | None,
) -> dict[str, Any]:
    nodes = _mapping(topology["nodes"], label="M4j nodes")
    agents = _mapping(nodes["agents"], label="M4j agents")
    gateway = _mapping(nodes["gateway"], label="M4j gateway")
    source = str(_mapping(agents["interfaces"], label="agents interfaces")["agent_lane"])
    destination = str(
        _mapping(gateway["interfaces"], label="gateway interfaces")["agent_lane"]
    )
    marker = os.urandom(8).hex()
    if _SAFE_RUN_TOKEN.fullmatch(marker) is None:
        raise AcceptanceError("gateway partition marker generation failed")
    insert_attempted = False
    cleanup_verified = False
    denial_verified = False
    restoration_verified = False
    try:
        insert_attempted = True
        _recorded_ssh(
            ssh_config=ssh_config,
            role="gateway",
            command_id="gateway-partition-precheck",
            remote_argv=_partition_rule_argv(
                action="check", source=source, destination=destination, port=8081, marker=marker
            ),
            stdin_bytes=b"",
            command_records=command_records,
            allowed_returncodes=frozenset({1}),
            executor=executor,
        )
        _recorded_ssh(
            ssh_config=ssh_config,
            role="gateway",
            command_id="gateway-partition-install",
            remote_argv=_partition_rule_argv(
                action="insert", source=source, destination=destination, port=8081, marker=marker
            ),
            stdin_bytes=b"",
            command_records=command_records,
            executor=executor,
        )
        _recorded_ssh(
            ssh_config=ssh_config,
            role="gateway",
            command_id="gateway-partition-present",
            remote_argv=_partition_rule_argv(
                action="check", source=source, destination=destination, port=8081, marker=marker
            ),
            stdin_bytes=b"",
            command_records=command_records,
            executor=executor,
        )
        partition_check = {
            "check_id": "agents-to-segmented-gateway-8081-partitioned",
            "source_role": "agents",
            "source_address": source,
            "destination_role": "gateway",
            "destination_address": destination,
            "port": 8081,
            "expected_connected": False,
        }
        _collect_connectivity(
            phase="partition",
            role="agents",
            checks=(partition_check,),
            ssh_config=ssh_config,
            command_records=command_records,
            executor=executor,
        )
        denial_verified = True
    finally:
        if insert_attempted:
            _reconcile_gateway_partition_absence(
                source=source,
                destination=destination,
                marker=marker,
                ssh_config=ssh_config,
                command_records=command_records,
                executor=executor,
            )
            cleanup_verified = True
    if denial_verified and cleanup_verified:
        restoration_check = {
            "check_id": "agents-to-segmented-gateway-8081-restored",
            "source_role": "agents",
            "source_address": source,
            "destination_role": "gateway",
            "destination_address": destination,
            "port": 8081,
            "expected_connected": True,
        }
        _collect_connectivity(
            phase="partition-cleanup",
            role="agents",
            checks=(restoration_check,),
            ssh_config=ssh_config,
            command_records=command_records,
            executor=executor,
        )
        restoration_verified = True
    return {
        "source_role": "agents",
        "destination_role": "gateway",
        "destination_address": destination,
        "port": 8081,
        "rule_marker_sha256": _sha256(f"aegis-m4j-{marker}".encode("ascii")),
        "denial_verified": denial_verified,
        "cleanup_verified": cleanup_verified,
        "restoration_verified": restoration_verified,
    }


def _counter_delta(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> dict[str, dict[str, int]]:
    if set(before) != set(after):
        raise AcceptanceError("interface counter set changed during acceptance")
    delta: dict[str, dict[str, int]] = {}
    for network_name in before:
        left = _mapping(before[network_name], label="pre-campaign interface counters")
        right = _mapping(after[network_name], label="post-campaign interface counters")
        if set(left) != {"rx_packets", "rx_bytes", "tx_packets", "tx_bytes"} or set(
            right
        ) != set(left):
            raise AcceptanceError("interface counter fields were malformed")
        values: dict[str, int] = {}
        for field, initial in left.items():
            final = right[field]
            if type(initial) is not int or type(final) is not int or final < initial:
                raise AcceptanceError("interface counters decreased or were malformed")
            values[field] = final - initial
        delta[network_name] = values
    return delta


def _facts_without_counters(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "interface_counters"}


def _command_hashes_complete(records: Sequence[Mapping[str, Any]]) -> bool:
    if not records:
        return False
    expected_sequence = list(range(1, len(records) + 1))
    if [record.get("sequence") for record in records] != expected_sequence:
        return False
    for record in records:
        result = record.get("result")
        if not isinstance(result, Mapping):
            return False
        hashes = (
            record.get("command_sha256"),
            record.get("stdin_sha256"),
            result.get("stdout_sha256"),
            result.get("stderr_sha256"),
        )
        if any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in hashes
        ):
            return False
    return True


def _private_regular_file_bytes(
    path: Path,
    *,
    maximum_bytes: int,
    label: str,
    allowed_modes: frozenset[int] = frozenset({0o600}),
) -> tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.absolute(), flags)
    except OSError as exc:
        raise AcceptanceError(f"{label} could not be opened as a private file") from exc
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
            raise AcceptanceError(f"{label} must be a regular invoking-user-owned file")
        if mode not in allowed_modes:
            expected = ", ".join(f"{value:04o}" for value in sorted(allowed_modes))
            raise AcceptanceError(f"{label} mode must be one of: {expected}")
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            raise AcceptanceError(f"{label} has an invalid size")
        material = b""
        while len(material) <= maximum_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - len(material)))
            if not chunk:
                break
            material += chunk
        after = os.fstat(descriptor)
        if (
            len(material) != before.st_size
            or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise AcceptanceError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    return material, mode


def _decode_ed25519_host_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise AcceptanceError("known-hosts contains invalid base64 key material") from exc
    algorithm = b"ssh-ed25519"
    prefix = len(algorithm).to_bytes(4, "big") + algorithm + (32).to_bytes(4, "big")
    if len(decoded) != len(prefix) + 32 or not decoded.startswith(prefix):
        raise AcceptanceError("known-hosts must contain canonical SSH Ed25519 public keys")
    return decoded


def _validate_known_hosts(path: Path) -> tuple[bytes, dict[str, Any]]:
    material, mode = _private_regular_file_bytes(
        path,
        maximum_bytes=65536,
        label="SSH known-hosts evidence",
    )
    try:
        text = material.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("known-hosts evidence must be ASCII") from exc
    lines = text.splitlines()
    if len(lines) != len(EXPECTED_ROLES) or any(
        not line or line != line.strip() for line in lines
    ):
        raise AcceptanceError("known-hosts must contain exactly six canonical entries")
    observed: dict[str, bytes] = {}
    for line in lines:
        fields = line.split(" ")
        if len(fields) != 3 or any(not field for field in fields):
            raise AcceptanceError("known-hosts entries must have exactly three fields")
        host_pattern, key_type, encoded_key = fields
        if key_type != "ssh-ed25519":
            raise AcceptanceError("known-hosts permits only SSH Ed25519 host keys")
        matches = [
            role
            for role, address in MANAGEMENT_ADDRESSES.items()
            if host_pattern == f"{role},{address}"
        ]
        if len(matches) != 1 or matches[0] in observed:
            raise AcceptanceError("known-hosts role and management-address bindings differ")
        observed[matches[0]] = _decode_ed25519_host_key(encoded_key)
    if tuple(sorted(observed)) != tuple(sorted(EXPECTED_ROLES)):
        raise AcceptanceError("known-hosts does not bind all six M4j roles")
    if len(set(observed.values())) != len(EXPECTED_ROLES):
        raise AcceptanceError("known-hosts must use a distinct host key for every M4j role")
    return material, {
        "sha256": _sha256(material),
        "size_bytes": len(material),
        "mode": f"{mode:04o}",
        "algorithm": "ssh-ed25519",
        "role_address_bindings": [
            {"role": role, "address": MANAGEMENT_ADDRESSES[role]}
            for role in EXPECTED_ROLES
        ],
        "distinct_host_key_count": len(observed),
    }


def _parse_ssh_config(path: Path) -> tuple[bytes, dict[str, dict[str, str]], dict[str, Any]]:
    material, mode = _private_regular_file_bytes(
        path,
        maximum_bytes=_MAX_SSH_CONFIG_BYTES,
        label="SSH configuration",
    )
    try:
        text = material.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("SSH configuration must be UTF-8") from exc
    roles: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        try:
            fields = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise AcceptanceError(
                f"SSH configuration line {line_number} is malformed"
            ) from exc
        if not fields:
            continue
        if len(fields) != 2 or "=" in fields[0]:
            raise AcceptanceError("SSH configuration must use one closed directive per line")
        keyword, value = fields[0].casefold(), fields[1]
        if keyword == "host":
            if value not in EXPECTED_ROLES or value in roles:
                raise AcceptanceError("SSH configuration must contain each exact role once")
            roles[value] = {}
            current = value
            continue
        if current is None or keyword not in {"hostname", "user", "identityfile"}:
            raise AcceptanceError("SSH configuration contains a forbidden directive")
        if keyword in roles[current]:
            raise AcceptanceError("SSH configuration contains a duplicate role directive")
        roles[current][keyword] = value
    if tuple(sorted(roles)) != tuple(sorted(EXPECTED_ROLES)):
        raise AcceptanceError("SSH configuration must contain exactly six role stanzas")

    identity_digests: dict[str, str] = {}
    for role in EXPECTED_ROLES:
        role_config = roles[role]
        if set(role_config) != {"hostname", "user", "identityfile"}:
            raise AcceptanceError(f"SSH role {role} lacks its closed connection fields")
        if role_config["hostname"] != MANAGEMENT_ADDRESSES[role]:
            raise AcceptanceError(f"SSH role {role} has the wrong management address")
        if role_config["user"] != "vagrant":
            raise AcceptanceError(f"SSH role {role} must use the vagrant management account")
        identity_path = Path(role_config["identityfile"])
        if not identity_path.is_absolute() or "%" in role_config["identityfile"]:
            raise AcceptanceError("SSH identity-file paths must be absolute and literal")
        identity, _identity_mode = _private_regular_file_bytes(
            identity_path,
            maximum_bytes=_MAX_SSH_IDENTITY_BYTES,
            label=f"SSH identity for {role}",
            allowed_modes=frozenset({0o400, 0o600}),
        )
        identity_digests[role] = _sha256(identity)
    return material, roles, {
        "sha256": _sha256(material),
        "size_bytes": len(material),
        "mode": f"{mode:04o}",
        "schema": "six_exact_host_user_identity_stanzas_v1",
        "identity_sha256": identity_digests,
    }


def _write_private_file(path: Path, material: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                raise AcceptanceError("private SSH transport file write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def _stable_ssh_transport(
    ssh_config: Path,
    known_hosts: Path,
) -> Iterator[tuple[Path, dict[str, Any]]]:
    _config_material, roles, config_evidence = _parse_ssh_config(ssh_config)
    known_hosts_material, known_hosts_evidence = _validate_known_hosts(known_hosts)
    directory = Path(tempfile.mkdtemp(prefix="aegis-m4j-acceptance-ssh-"))
    directory.chmod(0o700)
    stable_known_hosts = directory / "known_hosts"
    stable_config = directory / "config"
    expected_files: dict[Path, bytes] = {}
    try:
        _write_private_file(stable_known_hosts, known_hosts_material)
        expected_files[stable_known_hosts] = known_hosts_material
        lines: list[str] = []
        for role in EXPECTED_ROLES:
            source_identity = Path(roles[role]["identityfile"])
            identity, _mode = _private_regular_file_bytes(
                source_identity,
                maximum_bytes=_MAX_SSH_IDENTITY_BYTES,
                label=f"SSH identity for {role}",
                allowed_modes=frozenset({0o400, 0o600}),
            )
            if _sha256(identity) != config_evidence["identity_sha256"][role]:
                raise AcceptanceError(f"SSH identity for {role} changed during stabilization")
            stable_identity = directory / f"{role}.identity"
            _write_private_file(stable_identity, identity)
            expected_files[stable_identity] = identity
            lines.extend(
                (
                    f"Host {role}",
                    f"    HostName {MANAGEMENT_ADDRESSES[role]}",
                    "    User vagrant",
                    "    Port 22",
                    f"    IdentityFile {stable_identity}",
                    "    IdentitiesOnly yes",
                    "    BatchMode yes",
                    "    PasswordAuthentication no",
                    "    KbdInteractiveAuthentication no",
                    "    PreferredAuthentications publickey",
                    "    StrictHostKeyChecking yes",
                    f"    UserKnownHostsFile {stable_known_hosts}",
                    "    GlobalKnownHostsFile /dev/null",
                    "    HostKeyAlgorithms ssh-ed25519",
                    "    CheckHostIP yes",
                    "    CanonicalizeHostname no",
                    "    ProxyCommand none",
                    "    ProxyJump none",
                    "    ClearAllForwardings yes",
                    "    PermitLocalCommand no",
                )
            )
        stable_config_material = ("\n".join(lines) + "\n").encode("utf-8")
        _write_private_file(stable_config, stable_config_material)
        expected_files[stable_config] = stable_config_material
        evidence = {
            "configuration": config_evidence,
            "known_hosts": known_hosts_evidence,
            "role_aliases": list(EXPECTED_ROLES),
            "batch_mode": True,
            "strict_host_key_checking": True,
            "stable_private_copy": True,
        }
        yield stable_config, evidence
    finally:
        if directory.exists() and not directory.is_symlink():
            try:
                for path, expected in expected_files.items():
                    observed, _mode = _private_regular_file_bytes(
                        path,
                        maximum_bytes=max(len(expected), 1),
                        label="stable SSH transport input",
                    )
                    if observed != expected:
                        raise AcceptanceError(
                            "stable SSH transport input changed during acceptance"
                        )
            finally:
                shutil.rmtree(directory)


def _output_is_outside_checkout(output: Path, root: Path) -> None:
    resolved_output = output.parent.resolve() / output.name
    try:
        resolved_output.relative_to(root.resolve())
    except ValueError:
        return
    raise AcceptanceError("live M4j evidence output must be outside the source checkout")


def _reserve_output(output: Path, root: Path) -> int:
    _output_is_outside_checkout(output, root)
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise AcceptanceError("evidence parent must be an existing non-symlink directory")
    if output.name in {"", ".", ".."}:
        raise AcceptanceError("evidence output name is malformed")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        return os.open(output, flags, 0o600)
    except FileExistsError as exc:
        raise AcceptanceError("refusing to overwrite existing M4j evidence") from exc
    except OSError as exc:
        raise AcceptanceError("M4j evidence output could not be reserved") from exc


def _write_reserved_output(descriptor: int, output: Path, evidence: Mapping[str, Any]) -> None:
    material = _canonical_bytes(evidence) + b"\n"
    if len(material) > _MAX_EVIDENCE_BYTES:
        raise AcceptanceError("M4j evidence exceeded its maximum size")
    written = 0
    while written < len(material):
        count = os.write(descriptor, material[written:])
        if count <= 0:
            raise AcceptanceError("M4j evidence write did not progress")
        written += count
    os.fsync(descriptor)
    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
        raise AcceptanceError("M4j evidence file was not private")
    directory_descriptor = os.open(output.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _campaign(
    *,
    binding: Mapping[str, Any],
    topology: Mapping[str, Any],
    deployment: Mapping[str, Any],
    ssh_config: Path,
    ssh_transport_evidence: Mapping[str, Any],
    root: Path,
    executor: SshExecutor | None,
) -> dict[str, Any]:
    command_records: list[dict[str, Any]] = []
    before: dict[str, dict[str, Any]] = {}
    for role in EXPECTED_ROLES:
        before[role] = _collect_facts(
            phase="before",
            role=role,
            topology=topology,
            deployment=deployment,
            ssh_config=ssh_config,
            command_records=command_records,
            executor=executor,
        )

    contract = _connectivity_contract(topology, deployment)
    connectivity: list[dict[str, Any]] = []
    for role in EXPECTED_ROLES:
        role_checks = [check for check in contract if check["source_role"] == role]
        connectivity.extend(
            _collect_connectivity(
                phase="baseline",
                role=role,
                checks=role_checks,
                ssh_config=ssh_config,
                command_records=command_records,
                executor=executor,
            )
        )

    partition = _gateway_partition_probe(
        topology=topology,
        ssh_config=ssh_config,
        command_records=command_records,
        executor=executor,
    )

    after: dict[str, dict[str, Any]] = {}
    packet_metadata: dict[str, Any] = {}
    for role in EXPECTED_ROLES:
        after[role] = _collect_facts(
            phase="after",
            role=role,
            topology=topology,
            deployment=deployment,
            ssh_config=ssh_config,
            command_records=command_records,
            executor=executor,
        )
        if _facts_without_counters(before[role]) != _facts_without_counters(after[role]):
            raise AcceptanceError(f"host contract changed during acceptance for {role}")
        packet_metadata[role] = {
            "method": "interface_packet_and_byte_counter_delta",
            "payload_captured": False,
            "delta": _counter_delta(
                _mapping(before[role]["interface_counters"], label="before counters"),
                _mapping(after[role]["interface_counters"], label="after counters"),
            ),
        }

    _assert_source_unchanged(binding, root)
    direct_ot_id = "agents-to-ot-adapter-api-8083"
    direct_simulation_id = "agents-to-plant-api-8084"
    by_id = {item["check_id"]: item for item in connectivity}
    gates = {
        "source_unchanged": True,
        "six_host_identity_interfaces_routes_exact": set(before) == set(EXPECTED_ROLES),
        "forwarding_disabled": all(
            set(_mapping(value["forwarding"], label="forwarding").values()) == {"0"}
            for value in before.values()
        ),
        "ufw_exact_deployment_ingress_default_deny": all(
            _mapping(value["ufw"], label="UFW")[
                "extra_inbound_or_routed_allow_count"
            ]
            == 0
            for value in before.values()
        ),
        "role_specific_listeners_exact": True,
        "closed_connectivity_matrix": len(connectivity) == len(contract),
        "direct_agents_to_ot_denied": (
            direct_ot_id in by_id and by_id[direct_ot_id]["observed_connected"] is False
        ),
        "direct_agents_to_simulation_denied": (
            direct_simulation_id in by_id
            and by_id[direct_simulation_id]["observed_connected"] is False
        ),
        "gateway_partition_denied": partition["denial_verified"] is True,
        "gateway_partition_cleanup_verified": (
            partition["cleanup_verified"] is True
            and partition["restoration_verified"] is True
        ),
        "bounded_interface_counter_metadata": all(
            item["payload_captured"] is False for item in packet_metadata.values()
        ),
        "command_result_hashes_complete": _command_hashes_complete(command_records),
        "private_unique_output": True,
    }
    if tuple(gates) != ACCEPTANCE_GATES or not all(gates.values()):
        failed = [name for name in ACCEPTANCE_GATES if gates.get(name) is not True]
        raise AcceptanceError("M4j acceptance gates failed: " + ", ".join(failed))

    semantic_projection = {
        "source_fingerprint_sha256": binding["source_fingerprint_sha256"],
        "topology_sha256": next(
            item["sha256"]
            for item in binding["files"]
            if item["path"] == TOPOLOGY_RELATIVE_PATH
        ),
        "roles": list(EXPECTED_ROLES),
        "listener_contract": _listener_contract(deployment),
        "firewall_contract": {
            role: _firewall_contract(topology, deployment, role)
            for role in EXPECTED_ROLES
        },
        "connectivity": [
            {
                "check_id": item["check_id"],
                "expected_connected": item["expected_connected"],
                "observed_connected": item["observed_connected"],
            }
            for item in connectivity
        ],
        "gateway_partition": {
            key: partition[key]
            for key in ("denial_verified", "cleanup_verified", "restoration_verified")
        },
        "ssh_transport": {
            "configuration_sha256": ssh_transport_evidence["configuration"]["sha256"],
            "known_hosts_sha256": ssh_transport_evidence["known_hosts"]["sha256"],
            "identity_sha256": ssh_transport_evidence["configuration"][
                "identity_sha256"
            ],
            "role_address_bindings": ssh_transport_evidence["known_hosts"][
                "role_address_bindings"
            ],
        },
        "acceptance": gates,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "live_ssh",
        "generated_at": datetime.now(UTC).isoformat(),
        "analyst": "Angelis Pseftis",
        "network_acceptance_passed": True,
        "source_binding": _public_source_binding(binding),
        "ssh_transport": {
            **dict(ssh_transport_evidence),
            "configuration_contents_retained": False,
            "known_hosts_contents_retained": False,
            "private_identity_contents_retained": False,
        },
        "topology": _topology_projection(topology),
        "deployment": {
            "schema_version": deployment["schema_version"],
            "implementation_gates": deployment["implementation_gates"],
            "workload_live_probe": {
                "evidence_supplied": False,
                "status": "not_run",
            },
        },
        "host_observations": before,
        "connectivity_observations": connectivity,
        "gateway_partition": partition,
        "packet_metadata": packet_metadata,
        "commands": command_records,
        "acceptance": gates,
        "semantic_projection": semantic_projection,
        "semantic_outcome_sha256": _sha256(_canonical_bytes(semantic_projection)),
        "evidence_boundaries": list(EVIDENCE_BOUNDARIES),
    }


def run_live(
    output: Path,
    ssh_config: Path,
    known_hosts: Path,
    *,
    root: Path = ROOT,
    executor: SshExecutor | None = None,
) -> dict[str, Any]:
    binding = _source_binding(root)
    committed = _mapping(binding["_committed_material"], label="committed material")
    topology_material = committed[TOPOLOGY_RELATIVE_PATH]
    deployment_material = committed[DEPLOYMENT_RELATIVE_PATH]
    if not isinstance(topology_material, bytes) or not isinstance(deployment_material, bytes):
        raise AcceptanceError("committed topology or deployment material was malformed")
    topology = _load_topology(topology_material)
    deployment = _load_deployment(deployment_material, topology)
    descriptor: int | None = None
    published = False
    try:
        with _stable_ssh_transport(ssh_config, known_hosts) as (
            stable_ssh_config,
            ssh_transport_evidence,
        ):
            descriptor = _reserve_output(output, root)
            evidence = _campaign(
                binding=binding,
                topology=topology,
                deployment=deployment,
                ssh_config=stable_ssh_config,
                ssh_transport_evidence=ssh_transport_evidence,
                root=root,
                executor=executor,
            )
        if descriptor is None:  # pragma: no cover - context/control-flow invariant
            raise AcceptanceError("M4j evidence output was not reserved")
        _write_reserved_output(descriptor, output, evidence)
        published = True
        return evidence
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if descriptor is not None and not published:
            try:
                output.unlink()
            except FileNotFoundError:
                pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--known-hosts", type=Path)
    return parser


def main() -> None:
    arguments = _parser().parse_args()
    if arguments.plan:
        if any(
            value is not None
            for value in (arguments.output, arguments.ssh_config, arguments.known_hosts)
        ):
            raise SystemExit(
                "--plan does not accept --output, --ssh-config, or --known-hosts"
            )
        print(json.dumps(build_plan(), sort_keys=True, separators=(",", ":")))
        return
    if (
        arguments.output is None
        or arguments.ssh_config is None
        or arguments.known_hosts is None
    ):
        raise SystemExit("--live requires --output, --ssh-config, and --known-hosts")
    evidence = run_live(arguments.output, arguments.ssh_config, arguments.known_hosts)
    print(
        json.dumps(
            {
                "network_acceptance_passed": evidence[
                    "network_acceptance_passed"
                ],
                "output": str(arguments.output),
                "semantic_outcome_sha256": evidence["semantic_outcome_sha256"],
                "source_fingerprint_sha256": evidence["source_binding"][
                    "source_fingerprint_sha256"
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    try:
        main()
    except AcceptanceError as exc:
        print(f"M4j acceptance failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
