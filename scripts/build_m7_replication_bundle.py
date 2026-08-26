"""Build and offline-verify an exact-source M7 replication candidate.

The bundle is deliberately narrower than a release or replication claim.  It
captures one committed source tree, the declarations needed to reconstruct its
environment, a source-derived SPDX SBOM, and an explicitly unexecuted
replication protocol.  It does not fetch dependencies, build images, run the
protocol, publish anything, or establish independent validation.

Unsigned verification uses only the Python standard library.  The optional
Ed25519 signing and trusted-key verification mode uses the project's pinned
``cryptography`` dependency.  Git-tree and raw-commit reconstruction remain
offline and do not depend on a checkout or a Git executable.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = "aegis-ot-m7-replication-bundle-v2"
VERIFICATION_SCHEMA_VERSION = "aegis-ot-m7-replication-verification-v2"
SOURCE_INDEX_SCHEMA_VERSION = "aegis-ot-m7-source-index-v1"
SOURCE_COMMIT_SCHEMA_VERSION = "aegis-ot-m7-source-commit-v1"
INPUTS_SCHEMA_VERSION = "aegis-ot-m7-reproduction-inputs-v1"
PROTOCOL_SCHEMA_VERSION = "aegis-ot-m7-replication-protocol-v1"
EVIDENCE_SCHEMA_VERSION = "aegis-ot-m7-milestone-evidence-inventory-v1"
SIGNATURE_SCHEMA_VERSION = "aegis-ot-m7-manifest-signature-v1"

SOURCE_PREFIX = "aegis-ot-source"
SOURCE_ARCHIVE_NAME = "source.tar"
SOURCE_INDEX_NAME = "source-index.json"
SOURCE_COMMIT_NAME = "source-commit.json"
INPUTS_NAME = "reproduction-inputs.json"
SBOM_NAME = "sbom.spdx.json"
PROTOCOL_NAME = "replication-protocol.json"
EVIDENCE_NAME = "milestone-evidence-inventory.json"
VERIFIER_NAME = "verify_m7_replication_bundle.py"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.signature.json"
BUILDER_SOURCE_PATH = "scripts/build_m7_replication_bundle.py"
RELEASE_SECURITY_POLICY_PATH = "config/release-security-policy.json"

ARTIFACT_NAMES = (
    SOURCE_ARCHIVE_NAME,
    SOURCE_INDEX_NAME,
    SOURCE_COMMIT_NAME,
    INPUTS_NAME,
    SBOM_NAME,
    PROTOCOL_NAME,
    EVIDENCE_NAME,
    VERIFIER_NAME,
)
BUNDLE_NAMES = frozenset((*ARTIFACT_NAMES, MANIFEST_NAME))
SIGNED_BUNDLE_NAMES = frozenset((*BUNDLE_NAMES, SIGNATURE_NAME))

MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_SOURCE_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_SOURCE_FILES = 20_000
MAX_KEY_BYTES = 64 * 1024

_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_LOCK_PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([A-Za-z0-9_,.-]+)\])?"
    r"==([A-Za-z0-9][A-Za-z0-9.!+_-]*)$"
)
_IMAGE_ARGUMENT = re.compile(
    r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*_IMAGE)=([^\s#]+)\s*(?:#.*)?$"
)
_FROM = re.compile(r"^\s*FROM\s+(.+?)\s*(?:#.*)?$")
_YAML_IMAGE = re.compile(r"^\s*image\s*:\s*(.+?)\s*(?:#.*)?$")
_VARIABLE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_VARIABLE_DEFAULT = re.compile(
    r"^\$\{([A-Za-z_][A-Za-z0-9_]*):-([^{}]+)\}$"
)
_COMMITTER = re.compile(rb"^committer .+ ([0-9]+) ([+-][0-9]{4})$")
_UNSAFE_SECRET_SUFFIXES = frozenset(
    {".key", ".pem", ".p12", ".pfx", ".jks", ".private"}
)
_UNSAFE_SECRET_NAMES = frozenset(
    {".env", "id_rsa", "id_ed25519", "credentials", "credentials.json"}
)

CLAIM_BOUNDARIES = (
    "This is a locally constructed replication-candidate bundle. An unsigned "
    "bundle has no signer binding; an embedded-key Ed25519 signature establishes "
    "cryptographic integrity but not external key trust, authenticity, or custody.",
    "Caller-supplied trusted-key verification establishes an exact key match and "
    "valid signature only; it does not establish signer custody, release approval, "
    "independent validation, publication, or deployment.",
    "The bundle does not execute its replication protocol and does not establish "
    "independent replication or independent validation.",
    "The bundle is not a publication, public release, deployment, production-"
    "readiness determination, field result, or operational-effectiveness result.",
    "Dependency and OCI declarations are inventoried but dependency payloads, "
    "container images, VM boxes, and external toolchains are not vendored.",
    "Committed evidence-file presence is inventory only; this builder does not "
    "reinterpret, accept, or independently validate milestone evidence.",
)

SIGNATURE_BOUNDARY = (
    "The detached Ed25519 signature binds the exact canonical manifest bytes. "
    "The embedded public key is self-asserted. External authenticity requires a "
    "separately trusted public key supplied by the verifier caller, and even that "
    "does not establish custody, approval, publication, or independent validation."
)

SECURITY_USE_BOUNDARY = (
    "Defensive research in synthetic and explicitly authorized simulation "
    "environments only; do not connect the bundle or reconstructed system to "
    "production control systems, utility networks, third-party infrastructure, "
    "or real operational credentials."
)

MILESTONE_SPECS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "M1",
        "bounded_formal_authorization",
        ("results/formal/m1-authorization-conformance/manifest.json",),
    ),
    (
        "M2",
        "synthetic_independent_oracle",
        (
            "results/m2-independent-oracle/manifest.json",
            "results/m2-independent-oracle/trials.jsonl",
        ),
    ),
    (
        "M3",
        "single_host_physical_model_and_virtual_device",
        (
            "results/m3-physical-modbus/manifest.json",
            "results/m3-physical-modbus-reproduction/manifest.json",
        ),
    ),
    (
        "M4a",
        "local_process_capability_separation",
        ("results/m4a-capability-evidence/manifest.json",),
    ),
    (
        "M4b",
        "root_signed_capability_evidence",
        (
            "results/m4b-capability-evidence/manifest.json",
            "results/m4b-capability-evidence/manifest.signature.json",
            "results/m4b-capability-evidence-reproduction/manifest.json",
            "results/m4b-capability-evidence-reproduction/manifest.signature.json",
        ),
    ),
    (
        "M4c",
        "local_fault_and_adversarial_campaign",
        (
            "results/m4c-fault-campaign-v6.json",
            "results/m4c-fault-campaign-v6-reproduction.json",
        ),
    ),
    (
        "M4d",
        "single_host_segmented_compose",
        (
            "results/m4d-segmented-evidence.json",
            "results/m4d-segmented-evidence-reproduction.json",
        ),
    ),
    (
        "M4e",
        "authenticated_gateway_ot_transport",
        (
            "results/m4e-authenticated-transport-evidence.json",
            "results/m4e-authenticated-transport-evidence-reproduction.json",
        ),
    ),
    (
        "M4f",
        "durable_exact_envelope_replay_control",
        (
            "results/m4f-durable-transport-replay-evidence.json",
            "results/m4f-durable-transport-replay-evidence-reproduction.json",
        ),
    ),
    (
        "M4g",
        "workload_identity_and_revocation",
        (
            "results/m4g-workload-identity-evidence.json",
            "results/m4g-workload-identity-evidence-v2.json",
        ),
    ),
    (
        "M4h",
        "full_capability_contract_transport",
        ("results/m4h-capability-contract-evidence.json",),
    ),
    (
        "M4i",
        "durable_transaction_coordination_and_reconciliation",
        (
            "results/m4i-coordination-evidence.json",
            "results/m4i-coordination-evidence-v2.json",
        ),
    ),
    (
        "M4j",
        "current_source_multi_node_deployment",
        ("results/m4j-multi-node-acceptance.json",),
    ),
    (
        "M5",
        "operate_through_compromise",
        ("results/m5-compromise-evidence.json",),
    ),
    (
        "M6",
        "fleet_scaling_and_economics",
        ("results/m6-fleet-economics-evidence.json",),
    ),
    (
        "M7",
        "replication_candidate_bundle",
        ("results/m7-replication-evidence.json",),
    ),
    (
        "M8",
        "independent_replication_and_public_release",
        ("results/m8-independent-replication-attestation.json",),
    ),
)


class BundleError(RuntimeError):
    """The replication candidate could not be built or verified safely."""


@dataclass(frozen=True)
class SourceFile:
    """One regular file from an exact Git tree."""

    path: str
    mode: str
    blob_oid: str
    content: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    @property
    def sha1(self) -> str:
        return hashlib.sha1(self.content, usedforsecurity=False).hexdigest()

    def index_record(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "mode": self.mode,
            "size_bytes": len(self.content),
            "git_blob_oid": self.blob_oid,
            "sha1": self.sha1,
            "sha256": self.sha256,
        }


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _reject_constant(value: str) -> NoReturn:
    raise BundleError(f"JSON contains a non-finite number: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"JSON contains a duplicate key: {key}")
        result[key] = value
    return result


def _parse_canonical_json(material: bytes, *, label: str) -> dict[str, Any]:
    if not material or len(material) > MAX_JSON_BYTES:
        raise BundleError(f"{label} size is invalid")
    try:
        parsed = json.loads(
            material.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise BundleError(f"{label} must be a JSON object")
    if material != _canonical_bytes(parsed) + b"\n":
        raise BundleError(f"{label} is not canonical JSON")
    return parsed


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            args,
            cwd=cwd or ROOT,
            check=False,
            capture_output=True,
            env={**os.environ, "LC_ALL": "C"},
        )
    except OSError as exc:
        raise BundleError(f"command could not start: {' '.join(args)}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise BundleError(f"command failed ({' '.join(args)}): {detail[-2000:]}")
    return completed


def _command_text(*args: str, cwd: Path | None = None) -> str:
    material = _run(*args, cwd=cwd).stdout
    try:
        return material.decode("ascii").strip()
    except UnicodeError as exc:
        raise BundleError(f"command returned non-ASCII output: {' '.join(args)}") from exc


def _safe_source_path(raw: str) -> PurePosixPath:
    if (
        not raw
        or "\\" in raw
        or "\x00" in raw
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
    ):
        raise BundleError(f"source path is malformed: {raw!r}")
    try:
        raw.encode("ascii")
    except UnicodeError as exc:
        raise BundleError("source paths must be portable ASCII") from exc
    path = PurePosixPath(raw)
    if (
        path.as_posix() != raw
        or path.is_absolute()
        or any(part in {"", ".", "..", ".git"} for part in path.parts)
    ):
        raise BundleError(f"source path is unsafe: {raw!r}")
    if len(raw.encode("ascii")) > 220:
        raise BundleError(f"source path exceeds the portable archive limit: {raw!r}")
    return path


def _looks_like_secret(path: PurePosixPath) -> bool:
    name = path.name.casefold()
    return name in _UNSAFE_SECRET_NAMES or path.suffix.casefold() in _UNSAFE_SECRET_SUFFIXES


def _git_hash(name: str, content: bytes, object_format: str) -> str:
    if object_format not in {"sha1", "sha256"}:
        raise BundleError("unsupported Git object format")
    framed = name.encode("ascii") + b" " + str(len(content)).encode("ascii") + b"\0" + content
    if object_format == "sha1":
        return hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    return hashlib.sha256(framed).hexdigest()


def _parse_commit_object(
    content: bytes,
    *,
    object_format: str,
) -> tuple[str, int]:
    try:
        header, _message = content.split(b"\n\n", 1)
    except ValueError as exc:
        raise BundleError("Git commit object lacks a header/message boundary") from exc
    lines = header.splitlines()
    expected_length = 40 if object_format == "sha1" else 64
    if not lines or not lines[0].startswith(b"tree "):
        raise BundleError("Git commit object lacks a leading tree header")
    try:
        tree = lines[0][5:].decode("ascii")
    except UnicodeError as exc:
        raise BundleError("Git commit tree identifier is malformed") from exc
    if len(tree) != expected_length or _OBJECT_ID.fullmatch(tree) is None:
        raise BundleError("Git commit tree identifier is malformed")
    committer_lines = [line for line in lines if line.startswith(b"committer ")]
    if len(committer_lines) != 1:
        raise BundleError("Git commit object has an invalid committer header count")
    match = _COMMITTER.fullmatch(committer_lines[0])
    if match is None:
        raise BundleError("Git commit timestamp is malformed")
    committed_epoch = int(match.group(1))
    if committed_epoch < 0:
        raise BundleError("Git commit timestamp is invalid")
    return tree, committed_epoch


def _resolve_current_source(reference: str) -> dict[str, Any]:
    if (
        not reference
        or reference.strip() != reference
        or reference.startswith("-")
        or len(reference) > 512
        or any(character.isspace() or ord(character) < 32 for character in reference)
    ):
        raise BundleError("Git commit reference is malformed")
    if _run("git", "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout:
        raise BundleError("M7 bundle construction requires a clean checkout")
    commit = _command_text(
        "git", "rev-parse", "--verify", "--end-of-options", f"{reference}^{{commit}}"
    )
    head = _command_text("git", "rev-parse", "HEAD")
    if commit != head or _OBJECT_ID.fullmatch(commit) is None:
        raise BundleError("M7 source must resolve to the current exact HEAD commit")
    object_format = _command_text("git", "rev-parse", "--show-object-format")
    expected_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    if expected_length == 0 or len(commit) != expected_length:
        raise BundleError("Git commit identifier does not match the object format")
    tree = _command_text("git", "rev-parse", f"{commit}^{{tree}}")
    if len(tree) != expected_length or _OBJECT_ID.fullmatch(tree) is None:
        raise BundleError("Git tree identifier is malformed")
    commit_object = _run("git", "cat-file", "commit", commit).stdout
    parsed_tree, committed_epoch = _parse_commit_object(
        commit_object, object_format=object_format
    )
    if parsed_tree != tree or _git_hash("commit", commit_object, object_format) != commit:
        raise BundleError("Git commit object binding is inconsistent")
    return {
        "commit": commit,
        "tree": tree,
        "object_format": object_format,
        "committed_epoch": committed_epoch,
        "commit_object": commit_object,
    }


def _load_git_files(commit: str, object_format: str) -> tuple[SourceFile, ...]:
    output = _run("git", "ls-tree", "-r", "-z", "--full-tree", commit).stdout
    records: list[SourceFile] = []
    total = 0
    seen: set[str] = set()
    for raw_record in output.split(b"\0"):
        if not raw_record:
            continue
        try:
            metadata, path_bytes = raw_record.split(b"\t", 1)
            mode_bytes, object_type, object_id = metadata.split(b" ", 2)
            mode = mode_bytes.decode("ascii")
            kind = object_type.decode("ascii")
            blob_oid = object_id.decode("ascii")
            path_text = path_bytes.decode("utf-8")
        except (ValueError, UnicodeError) as exc:
            raise BundleError("Git tree listing is malformed") from exc
        path = _safe_source_path(path_text)
        if path.as_posix() in seen:
            raise BundleError("Git tree contains duplicate source paths")
        seen.add(path.as_posix())
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise BundleError(
                f"source tree contains a symlink, gitlink, or special mode: {path_text}"
            )
        if _looks_like_secret(path):
            raise BundleError(f"source tree contains a secret-like path: {path_text}")
        if _OBJECT_ID.fullmatch(blob_oid) is None:
            raise BundleError("Git blob identifier is malformed")
        content = _run("git", "cat-file", "blob", blob_oid).stdout
        if len(content) > MAX_SOURCE_FILE_BYTES:
            raise BundleError(f"source file exceeds its size limit: {path_text}")
        total += len(content)
        if total > MAX_SOURCE_TOTAL_BYTES:
            raise BundleError("source tree exceeds its expanded size limit")
        if _git_hash("blob", content, object_format) != blob_oid:
            raise BundleError(f"Git blob content is inconsistent: {path_text}")
        records.append(SourceFile(path.as_posix(), mode, blob_oid, content))
        if len(records) > MAX_SOURCE_FILES:
            raise BundleError("source tree contains too many files")
    if not records:
        raise BundleError("source tree is empty")
    records.sort(key=lambda item: item.path.encode("ascii"))
    return tuple(records)


def _tree_oid(files: tuple[SourceFile, ...], object_format: str) -> str:
    root: dict[str, object] = {}
    for source in files:
        parts = PurePosixPath(source.path).parts
        node = root
        for component in parts[:-1]:
            existing = node.get(component)
            if existing is None:
                child: dict[str, object] = {}
                node[component] = child
                node = child
            elif isinstance(existing, dict):
                node = existing
            else:
                raise BundleError("source paths conflict between file and directory")
        if parts[-1] in node:
            raise BundleError("source tree contains a duplicate leaf")
        node[parts[-1]] = source

    def hash_node(node: dict[str, object]) -> str:
        encoded: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            name_bytes = name.encode("ascii")
            if isinstance(value, dict):
                oid = hash_node(value)
                sort_key = name_bytes + b"/"
                record = b"40000 " + name_bytes + b"\0" + bytes.fromhex(oid)
            elif isinstance(value, SourceFile):
                sort_key = name_bytes
                record = value.mode.encode("ascii") + b" " + name_bytes + b"\0"
                record += bytes.fromhex(value.blob_oid)
            else:  # pragma: no cover - construction above is closed
                raise BundleError("source tree node type is invalid")
            encoded.append((sort_key, record))
        material = b"".join(record for _key, record in sorted(encoded))
        return _git_hash("tree", material, object_format)

    return hash_node(root)


def _write_bytes(path: Path, material: bytes, *, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: object) -> None:
    _write_bytes(path, _canonical_bytes(value) + b"\n")


def _write_source_archive(
    path: Path,
    files: tuple[SourceFile, ...],
    *,
    committed_epoch: int,
) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            with tarfile.open(
                fileobj=handle,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as archive:
                for source in files:
                    member = tarfile.TarInfo(f"{SOURCE_PREFIX}/{source.path}")
                    member.type = tarfile.REGTYPE
                    member.mode = 0o755 if source.mode == "100755" else 0o644
                    member.uid = 0
                    member.gid = 0
                    member.uname = ""
                    member.gname = ""
                    member.mtime = committed_epoch
                    member.size = len(source.content)
                    archive.addfile(member, io.BytesIO(source.content))
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, ValueError, tarfile.TarError) as exc:
        raise BundleError("source archive could not be written in portable USTAR form") from exc
    finally:
        os.close(descriptor)
    if path.stat().st_size > MAX_SOURCE_ARCHIVE_BYTES:
        raise BundleError("source archive exceeds its size limit")


def _source_index(revision: dict[str, Any], files: tuple[SourceFile, ...]) -> dict[str, Any]:
    return {
        "schema_version": SOURCE_INDEX_SCHEMA_VERSION,
        "source_prefix": SOURCE_PREFIX,
        "git": {
            "object_format": revision["object_format"],
            "commit": revision["commit"],
            "tree": revision["tree"],
            "committed_epoch": revision["committed_epoch"],
        },
        "file_count": len(files),
        "total_size_bytes": sum(len(item.content) for item in files),
        "files": [item.index_record() for item in files],
    }


def _source_commit(revision: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SOURCE_COMMIT_SCHEMA_VERSION,
        "object_format": revision["object_format"],
        "commit_oid": revision["commit"],
        "tree_oid": revision["tree"],
        "committed_epoch": revision["committed_epoch"],
        "commit_object_base64": base64.b64encode(revision["commit_object"]).decode("ascii"),
    }


def _strict_text(files: dict[str, bytes], path: str) -> str:
    material = files.get(path)
    if material is None:
        raise BundleError(f"required source declaration is missing: {path}")
    try:
        return material.decode("utf-8")
    except UnicodeError as exc:
        raise BundleError(f"source declaration is not strict UTF-8: {path}") from exc


def _pinned_image(reference: str, *, location: str) -> tuple[str, str]:
    if reference.count("@sha256:") != 1 or any(character.isspace() for character in reference):
        raise BundleError(f"OCI input is not digest pinned: {location}")
    name, digest = reference.rsplit("@sha256:", 1)
    if (
        not name
        or "@" in name
        or name.casefold().endswith(":latest")
        or _SHA256.fullmatch(digest) is None
    ):
        raise BundleError(f"OCI input is not digest pinned: {location}")
    return name, digest


def _python_pins(lock_text: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(lock_text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _LOCK_PIN.fullmatch(line)
        if match is None:
            raise BundleError(f"requirements.lock line {line_number} is not an exact pin")
        name, extras, version = match.groups()
        normalized = re.sub(r"[-_.]+", "-", name).casefold()
        identity = normalized + (f"[{extras.casefold()}]" if extras else "")
        if identity in seen:
            raise BundleError(f"requirements.lock contains a duplicate pin: {identity}")
        seen.add(identity)
        result.append(
            {
                "name": name,
                "normalized_name": normalized,
                "extras": sorted(extras.split(",")) if extras else [],
                "version": version,
                "requirement": line,
                "line": line_number,
            }
        )
    if not result:
        raise BundleError("requirements.lock contains no exact pins")
    return sorted(result, key=lambda item: (item["normalized_name"], item["requirement"]))


def _unquote_scalar(value: str, *, location: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    if not value or any(character in value for character in "\r\n"):
        raise BundleError(f"OCI image scalar is malformed: {location}")
    return value


def _oci_inputs(files: dict[str, bytes]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in sorted(files):
        name = PurePosixPath(path).name
        is_dockerfile = name == "Dockerfile" or name.startswith("Dockerfile.")
        is_compose = (
            name.startswith("docker-compose.") and PurePosixPath(name).suffix in {".yml", ".yaml"}
        )
        if not is_dockerfile and not is_compose:
            continue
        text = _strict_text(files, path)
        if is_dockerfile:
            arguments: dict[str, str] = {}
            for line_number, line in enumerate(text.splitlines(), start=1):
                argument = _IMAGE_ARGUMENT.fullmatch(line)
                if argument is not None:
                    variable, reference = argument.groups()
                    if variable in arguments:
                        raise BundleError(f"duplicate OCI image ARG: {path}:{line_number}")
                    _pinned_image(reference, location=f"{path}:{line_number}")
                    arguments[variable] = reference
                    result.append(
                        {
                            "declaration_path": path,
                            "line": line_number,
                            "kind": "dockerfile_pinned_argument",
                            "reference": reference,
                            "environment_override": None,
                        }
                    )
                    continue
                from_match = _FROM.fullmatch(line)
                if from_match is None:
                    continue
                tokens = from_match.group(1).split()
                while tokens and tokens[0].startswith("--"):
                    tokens.pop(0)
                if not tokens:
                    raise BundleError(f"Dockerfile FROM is malformed: {path}:{line_number}")
                source = tokens[0]
                variable_match = _VARIABLE.fullmatch(source)
                if variable_match is not None:
                    if variable_match.group(1) not in arguments:
                        raise BundleError(
                            f"Dockerfile FROM uses an unpinned image variable: {path}:{line_number}"
                        )
                else:
                    _pinned_image(source, location=f"{path}:{line_number}")
                    result.append(
                        {
                            "declaration_path": path,
                            "line": line_number,
                            "kind": "dockerfile_direct_from",
                            "reference": source,
                            "environment_override": None,
                        }
                    )
        else:
            image_lines = 0
            for line_number, line in enumerate(text.splitlines(), start=1):
                if re.match(r"^\s*image\s*:", line):
                    image_lines += 1
                match = _YAML_IMAGE.fullmatch(line)
                if match is None:
                    continue
                scalar = _unquote_scalar(
                    match.group(1), location=f"{path}:{line_number}"
                )
                variable_default = _VARIABLE_DEFAULT.fullmatch(scalar)
                if variable_default is not None:
                    environment, reference = variable_default.groups()
                else:
                    environment, reference = None, scalar
                _pinned_image(reference, location=f"{path}:{line_number}")
                result.append(
                    {
                        "declaration_path": path,
                        "line": line_number,
                        "kind": (
                            "compose_digest_pinned_default"
                            if environment is not None
                            else "compose_digest_pinned_reference"
                        ),
                        "reference": reference,
                        "environment_override": environment,
                    }
                )
            parsed_lines = sum(
                1
                for record in result
                if record["declaration_path"] == path
                and str(record["kind"]).startswith("compose_")
            )
            if image_lines != parsed_lines:
                raise BundleError(f"Compose image declaration is not a closed scalar: {path}")
    if not result:
        raise BundleError("source tree declares no digest-pinned OCI inputs")
    return sorted(
        result,
        key=lambda item: (item["declaration_path"], item["line"], item["kind"]),
    )


def _reproduction_inputs(files: dict[str, bytes]) -> dict[str, Any]:
    lock = files.get("requirements.lock")
    pyproject = files.get("pyproject.toml")
    if lock is None or pyproject is None:
        raise BundleError("source tree lacks the root reproduction declarations")
    pins = _python_pins(_strict_text(files, "requirements.lock"))
    return {
        "schema_version": INPUTS_SCHEMA_VERSION,
        "python_environment": {
            "lock_path": "requirements.lock",
            "lock_sha256": hashlib.sha256(lock).hexdigest(),
            "pyproject_path": "pyproject.toml",
            "pyproject_sha256": hashlib.sha256(pyproject).hexdigest(),
            "exact_pin_count": len(pins),
            "exact_pins": pins,
            "payloads_vendored": False,
        },
        "oci_inputs": _oci_inputs(files),
        "declaration_boundary": [
            "The Python lock records exact versions but not artifact hashes or bundled wheels.",
            (
                "OCI references record digest-pinned declarations/defaults; images are "
                "not bundled or pulled."
            ),
            (
                "Environment-overridable Compose defaults do not bind a later "
                "operator-supplied override."
            ),
            "VM boxes and host packages are not included in this OCI/dependency inventory.",
        ],
    }


def _project_metadata(files: dict[str, bytes]) -> tuple[str, str, str]:
    try:
        parsed = tomllib.loads(_strict_text(files, "pyproject.toml"))
    except tomllib.TOMLDecodeError as exc:
        raise BundleError("pyproject.toml is invalid") from exc
    project = parsed.get("project")
    if not isinstance(project, dict):
        raise BundleError("pyproject.toml lacks project metadata")
    name = project.get("name")
    version = project.get("version")
    license_value = project.get("license")
    if isinstance(license_value, dict):
        license_id = license_value.get("text")
    else:
        license_id = license_value
    if not isinstance(name, str) or not name:
        raise BundleError("pyproject.toml project name is incomplete")
    if not isinstance(version, str) or not version:
        raise BundleError("pyproject.toml project version is incomplete")
    if not isinstance(license_id, str) or not license_id:
        raise BundleError("pyproject.toml project metadata is incomplete")
    return name, version, license_id


def _spdx_id(prefix: str, value: str, index: int) -> str:
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-") or "item"
    return f"SPDXRef-{prefix}-{index:05d}-{safe[:48]}"


def _spdx_sbom(
    files: tuple[SourceFile, ...],
    revision: dict[str, Any],
    inputs: dict[str, Any],
) -> dict[str, Any]:
    file_map = {item.path: item.content for item in files}
    project_name, project_version, license_id = _project_metadata(file_map)
    root_id = "SPDXRef-Package-Aegis-OT"
    spdx_files: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    for index, source in enumerate(files, start=1):
        file_id = _spdx_id(
            "File", hashlib.sha256(source.path.encode("ascii")).hexdigest(), index
        )
        spdx_files.append(
            {
                "SPDXID": file_id,
                "fileName": f"./{source.path}",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": source.sha1},
                    {"algorithm": "SHA256", "checksumValue": source.sha256},
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )
    verification_material = "".join(sorted(source.sha1 for source in files)).encode("ascii")
    verification_code = hashlib.sha1(
        verification_material, usedforsecurity=False
    ).hexdigest()
    packages: list[dict[str, Any]] = [
        {
            "SPDXID": root_id,
            "name": project_name,
            "versionInfo": project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "packageVerificationCode": {"packageVerificationCodeValue": verification_code},
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license_id,
            "copyrightText": "Copyright 2026 Angelis Pseftis",
            "primaryPackagePurpose": "APPLICATION",
        }
    ]
    python_environment = inputs["python_environment"]
    if not isinstance(python_environment, dict):
        raise BundleError("Python input inventory is malformed")
    pins = python_environment.get("exact_pins")
    if not isinstance(pins, list):
        raise BundleError("Python input pins are malformed")
    for index, pin in enumerate(pins, start=1):
        if not isinstance(pin, dict):
            raise BundleError("Python input pin is malformed")
        package_id = _spdx_id("Package-Python", str(pin["normalized_name"]), index)
        packages.append(
            {
                "SPDXID": package_id,
                "name": pin["name"],
                "versionInfo": pin["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "primaryPackagePurpose": "LIBRARY",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": (
                            f"pkg:pypi/{quote(str(pin['normalized_name']))}@"
                            f"{quote(str(pin['version']))}"
                        ),
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )
    oci = inputs.get("oci_inputs")
    if not isinstance(oci, list):
        raise BundleError("OCI input inventory is malformed")
    references = sorted({str(record["reference"]) for record in oci if isinstance(record, dict)})
    for index, reference in enumerate(references, start=1):
        name, digest = _pinned_image(reference, location="SBOM OCI inventory")
        package_id = _spdx_id("Package-OCI", name, index)
        packages.append(
            {
                "SPDXID": package_id,
                "name": name,
                "versionInfo": f"sha256:{digest}",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "primaryPackagePurpose": "CONTAINER",
                "externalRefs": [
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "oci-reference",
                        "referenceLocator": reference,
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )
    created = datetime.fromtimestamp(
        int(revision["committed_epoch"]), tz=UTC
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name}-{revision['commit']}-source",
        "documentNamespace": (
            "https://github.com/redxking/aegis-ot/spdx/"
            f"{revision['commit']}"
        ),
        "creationInfo": {
            "created": created,
            "creators": ["Person: Angelis Pseftis"],
            "comment": (
                "Source-derived offline inventory; dependency licenses and OCI contents "
                "were not resolved or analyzed."
            ),
        },
        "documentDescribes": [root_id],
        "packages": packages,
        "files": spdx_files,
        "relationships": relationships,
    }


def _evidence_inventory(files: dict[str, bytes]) -> dict[str, Any]:
    milestones: list[dict[str, Any]] = []
    for milestone, capability, paths in MILESTONE_SPECS:
        artifacts: list[dict[str, Any]] = []
        present = 0
        for path in paths:
            material = files.get(path)
            is_present = material is not None
            present += int(is_present)
            artifacts.append(
                {
                    "path": path,
                    "presence": (
                        "present_in_source_archive"
                        if is_present
                        else "missing_from_source_archive"
                    ),
                    "size_bytes": len(material) if material is not None else None,
                    "sha256": (
                        hashlib.sha256(material).hexdigest()
                        if material is not None
                        else None
                    ),
                }
            )
        if present == len(paths):
            presence_state = "all_declared_artifacts_present_unverified"
        elif present == 0:
            presence_state = "no_declared_artifact_present"
        else:
            presence_state = "partial_declared_artifacts_present_unverified"
        milestones.append(
            {
                "milestone": milestone,
                "capability": capability,
                "artifact_presence_state": presence_state,
                "declared_artifacts": artifacts,
                "execution_state": "not_executed_by_this_bundle",
                "artifact_acceptance_state": "not_evaluated_by_this_inventory",
                "independent_replication_state": "not_established",
                "publication_state": "not_established",
                "deployment_state": "not_established",
                "operational_effectiveness_state": "not_established",
            }
        )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "classification": "committed_file_presence_inventory_only",
        "inventory_rule": (
            "Presence, size, and digest are recorded from the exact source tree. "
            "No artifact is executed, semantically accepted, externally attested, "
            "or promoted by this inventory."
        ),
        "milestones": milestones,
    }


def _replication_protocol(revision: dict[str, Any]) -> dict[str, Any]:
    short = str(revision["commit"])[:12]
    return {
        "schema_version": PROTOCOL_SCHEMA_VERSION,
        "protocol_state": "specified_but_not_executed_by_bundle",
        "source": {
            "git_commit": revision["commit"],
            "git_tree": revision["tree"],
            "expected_commit_argument_required_for_external_authenticity": True,
        },
        "prerequisites": [
            "A separately trusted copy or digest of this verifier and the expected Git commit.",
            (
                "For trusted-signature mode, a separately obtained Ed25519 public key; "
                "the embedded key is not a trust anchor."
            ),
            "CPython 3.11 or newer for offline bundle verification and extraction.",
            "An isolated reconstruction host; dependency access or a separately acquired cache.",
            (
                "Docker, Vagrant, VirtualBox, and external toolchains only for the "
                "relevant optional gates."
            ),
        ],
        "steps": [
            {
                "id": "verify_bundle",
                "state": "not_executed_by_bundle",
                "command": (
                    "python verify_m7_replication_bundle.py verify --bundle . "
                    f"--expected-commit {revision['commit']}"
                ),
                "expected_result": "valid internal consistency and caller-supplied commit match",
            },
            {
                "id": "extract_exact_source",
                "state": "not_executed_by_bundle",
                "command": (
                    "python verify_m7_replication_bundle.py extract --bundle . "
                    f"--output ../aegis-ot-source-{short} --expected-commit {revision['commit']}"
                ),
                "expected_result": (
                    "new no-clobber directory containing only verified regular files"
                ),
            },
            {
                "id": "verify_trusted_signature_if_required",
                "state": "not_executed_by_bundle",
                "command": (
                    "python verify_m7_replication_bundle.py verify --bundle . "
                    f"--expected-commit {revision['commit']} --require-signature "
                    "--trusted-public-key <trusted-ed25519-public-key.pem>"
                ),
                "expected_result": (
                    "valid Ed25519 signature and exact caller-supplied key match; "
                    "unsigned or wrong-key bundles fail closed"
                ),
            },
            {
                "id": "create_environment",
                "state": "not_executed_by_bundle",
                "command": "python -m venv .venv",
                "expected_result": (
                    "isolated Python environment; no dependency payload is supplied here"
                ),
            },
            {
                "id": "install_declared_environment",
                "state": "not_executed_by_bundle",
                "command": (
                    ".venv/bin/python -m pip install --constraint requirements.lock "
                    "-e '.[dev,docs,simulation]'"
                ),
                "expected_result": (
                    "versions constrained by requirements.lock; artifact hashes and "
                    "network-independent installation are not established"
                ),
            },
            {
                "id": "run_static_checks",
                "state": "not_executed_by_bundle",
                "command": ".venv/bin/ruff check . && .venv/bin/mypy",
                "expected_result": "tool exit status zero",
            },
            {
                "id": "run_test_suite",
                "state": "not_executed_by_bundle",
                "command": "PYTHONPATH=src .venv/bin/python -m pytest",
                "expected_result": "test exit status zero; local conformance only",
            },
            {
                "id": "run_milestone_specific_protocols",
                "state": "not_executed_by_bundle",
                "command": (
                    "follow exact-source milestone runners and offline verifiers in "
                    "the source tree"
                ),
                "expected_result": (
                    "record each gate separately, including unavailable, failed, and "
                    "unexecuted states"
                ),
            },
            {
                "id": "independent_review",
                "state": "not_executed_by_bundle",
                "command": "performed by an independent actor under documented custody",
                "expected_result": (
                    "a separate attestation; never inferred from this bundle or a same-team rerun"
                ),
            },
        ],
        "required_reporting_boundaries": list(CLAIM_BOUNDARIES),
    }


def _descriptor(path: Path) -> dict[str, Any]:
    material = _read_regular(path, maximum=MAX_SOURCE_ARCHIVE_BYTES)
    return {
        "path": path.name,
        "size_bytes": len(material),
        "sha256": hashlib.sha256(material).hexdigest(),
    }


def _manifest(
    revision: dict[str, Any],
    artifact_descriptors: dict[str, dict[str, Any]],
    files: dict[str, bytes],
    *,
    signer_key_id: str | None = None,
) -> dict[str, Any]:
    license_material = files.get("LICENSE")
    security_material = files.get("SECURITY.md")
    release_policy_material = files.get(RELEASE_SECURITY_POLICY_PATH)
    if (
        license_material is None
        or security_material is None
        or release_policy_material is None
    ):
        raise BundleError(
            "source tree must contain LICENSE, SECURITY.md, and the release security policy"
        )
    _project_name, _project_version, license_identifier = _project_metadata(files)
    return {
        "schema_version": SCHEMA_VERSION,
        "bundle_kind": "replication_candidate",
        "release_state": "not_published_or_publicly_released",
        "authorship": {"creator": "Angelis Pseftis"},
        "source": {
            "git_commit": revision["commit"],
            "git_tree": revision["tree"],
            "git_object_format": revision["object_format"],
            "committed_epoch": revision["committed_epoch"],
            "exact_source_binding": (
                "raw_commit_object_hash_and_offline_reconstructed_git_tree"
            ),
            "current_clean_head_required_at_build": True,
            "mutable_checkout_content_packaged": False,
            "external_authenticity_without_expected_commit": "not_established",
        },
        "artifacts": artifact_descriptors,
        "license": {
            "identifier": license_identifier,
            "path": "LICENSE",
            "sha256": hashlib.sha256(license_material).hexdigest(),
        },
        "security": {
            "policy_path": "SECURITY.md",
            "policy_sha256": hashlib.sha256(security_material).hexdigest(),
            "release_policy_path": RELEASE_SECURITY_POLICY_PATH,
            "release_policy_sha256": hashlib.sha256(release_policy_material).hexdigest(),
            "authorized_use_boundary": SECURITY_USE_BOUNDARY,
            "secret_path_screen": "bounded_filename_heuristic_only",
        },
        "reproducibility": {
            "archive_content_deterministic_for_commit": True,
            "source_date_epoch": revision["committed_epoch"],
            "network_access_performed_by_builder": False,
            "dependency_payloads_vendored": False,
            "oci_images_vendored": False,
            "protocol_executed_by_builder": False,
            "sbom": "SPDX-2.3 source_and_declared_input_inventory",
        },
        "attestation": {
            "signature": (
                "ed25519_detached_manifest"
                if signer_key_id is not None
                else "none"
            ),
            "signer_key_id": signer_key_id,
            "embedded_public_key_trust": (
                "self_asserted_not_trusted"
                if signer_key_id is not None
                else "not_applicable_unsigned"
            ),
            "external_custody": "not_established",
            "independent_replication": "not_established",
            "independent_validation": "not_established",
        },
        "claim_boundaries": list(CLAIM_BOUNDARIES),
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _resolved_external_output(output: Path) -> Path:
    if output.name in {"", ".", ".."}:
        raise BundleError("bundle output name is malformed")
    if output.exists() or output.is_symlink():
        raise BundleError("refusing to overwrite an existing M7 bundle path")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise BundleError("bundle parent must be an existing non-symlink directory")
    resolved_parent = parent.resolve(strict=True)
    resolved = resolved_parent / output.name
    root = ROOT.resolve(strict=True)
    if resolved == root or resolved.is_relative_to(root):
        raise BundleError("M7 bundle output must be outside the source checkout")
    return resolved


def _publish_directory_noreplace(source: Path, destination: Path) -> None:
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    result: int
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise BundleError("atomic no-replace publication is unavailable")
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = int(renamex_np(source_bytes, destination_bytes, 0x00000004))
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise BundleError("atomic no-replace publication is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = int(renameat2(-100, source_bytes, -100, destination_bytes, 1))
    elif os.name == "nt":  # pragma: no cover
        try:
            os.rename(source, destination)
        except FileExistsError as exc:
            raise BundleError("refusing to overwrite an existing M7 bundle path") from exc
        except OSError as exc:
            raise BundleError("M7 bundle could not be atomically published") from exc
        return
    else:  # pragma: no cover
        raise BundleError("atomic no-replace publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise BundleError("refusing to overwrite an existing M7 bundle path")
    raise BundleError(
        f"M7 bundle could not be atomically published: {os.strerror(error_number)}"
    )


def _read_regular(
    path: Path,
    *,
    maximum: int,
    require_private: bool = False,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BundleError(f"bundle artifact cannot be opened safely: {path.name}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise BundleError(f"bundle artifact size or type is invalid: {path.name}")
        if require_private and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise BundleError("M7 signing key permissions are not private")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise BundleError(f"bundle artifact exceeds its limit: {path.name}")
        if total != metadata.st_size:
            raise BundleError(f"bundle artifact changed while reading: {path.name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_external_key(path: Path, *, private: bool) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise BundleError("key path must be a regular non-symlink file")
    resolved = path.resolve(strict=True)
    if private and resolved.is_relative_to(ROOT.resolve(strict=True)):
        raise BundleError("M7 signing key must be stored outside the source checkout")
    return _read_regular(
        resolved,
        maximum=MAX_KEY_BYTES,
        require_private=private,
    )


def _ed25519_dependencies() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise BundleError(
            "Ed25519 signing or signature verification requires the pinned "
            "cryptography dependency"
        ) from exc
    return serialization, Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def _signing_identity(private_key_path: Path) -> tuple[Any, bytes, str]:
    serialization, private_type, _public_type, _invalid_signature = _ed25519_dependencies()
    material = _read_external_key(private_key_path, private=True)
    try:
        private_key = serialization.load_pem_private_key(material, password=None)
    except (TypeError, ValueError) as exc:
        raise BundleError("M7 signing key is not an unencrypted PEM private key") from exc
    if not isinstance(private_key, private_type):
        raise BundleError("M7 signing key is not an Ed25519 private key")
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = f"sha256:{hashlib.sha256(public_key).hexdigest()}"
    return private_key, public_key, key_id


def _load_trusted_public_key(public_key_path: Path) -> bytes:
    serialization, _private_type, public_type, _invalid_signature = _ed25519_dependencies()
    material = _read_external_key(public_key_path, private=False)
    try:
        public_key = serialization.load_pem_public_key(material)
    except (TypeError, ValueError) as exc:
        raise BundleError("trusted M7 public key is not PEM") from exc
    if not isinstance(public_key, public_type):
        raise BundleError("trusted M7 public key is not an Ed25519 public key")
    return cast(
        bytes,
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def _canonical_base64(value: object, *, label: str, size: int) -> bytes:
    if not isinstance(value, str):
        raise BundleError(f"{label} is not a base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleError(f"{label} is not canonical base64") from exc
    if len(decoded) != size or base64.b64encode(decoded).decode("ascii") != value:
        raise BundleError(f"{label} length or encoding is invalid")
    return decoded


def _signature_artifact(
    manifest_material: bytes,
    *,
    private_key: Any,
    public_key: bytes,
    key_id: str,
) -> dict[str, Any]:
    signature = private_key.sign(manifest_material)
    return {
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "algorithm": "Ed25519",
        "signed_artifact": MANIFEST_NAME,
        "signed_artifact_sha256": hashlib.sha256(manifest_material).hexdigest(),
        "signer_key_id": key_id,
        "public_key_base64": base64.b64encode(public_key).decode("ascii"),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "trust_state": "embedded_key_self_asserted",
        "authenticity_boundary": SIGNATURE_BOUNDARY,
    }


def _verify_signature_artifact(
    value: dict[str, Any],
    manifest_material: bytes,
    *,
    trusted_public_key: Path | None,
) -> dict[str, Any]:
    expected_keys = {
        "schema_version",
        "algorithm",
        "signed_artifact",
        "signed_artifact_sha256",
        "signer_key_id",
        "public_key_base64",
        "signature_base64",
        "trust_state",
        "authenticity_boundary",
    }
    if set(value) != expected_keys:
        raise BundleError("M7 signature artifact does not match the closed schema")
    if (
        value.get("schema_version") != SIGNATURE_SCHEMA_VERSION
        or value.get("algorithm") != "Ed25519"
        or value.get("signed_artifact") != MANIFEST_NAME
        or value.get("trust_state") != "embedded_key_self_asserted"
        or value.get("authenticity_boundary") != SIGNATURE_BOUNDARY
    ):
        raise BundleError("M7 signature artifact semantics are invalid")
    digest = value.get("signed_artifact_sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise BundleError("M7 signature artifact manifest digest is malformed")
    if digest != hashlib.sha256(manifest_material).hexdigest():
        raise BundleError("M7 signature does not bind the exact manifest bytes")
    public_key = _canonical_base64(
        value.get("public_key_base64"), label="M7 embedded public key", size=32
    )
    signature = _canonical_base64(
        value.get("signature_base64"), label="M7 signature", size=64
    )
    key_id = f"sha256:{hashlib.sha256(public_key).hexdigest()}"
    if value.get("signer_key_id") != key_id:
        raise BundleError("M7 signature signer key ID is inconsistent")
    _serialization, _private_type, public_type, invalid_signature = _ed25519_dependencies()
    try:
        public_type.from_public_bytes(public_key).verify(signature, manifest_material)
    except invalid_signature as exc:
        raise BundleError("M7 Ed25519 manifest signature is invalid") from exc
    if trusted_public_key is None:
        trust_mode = "embedded_key_untrusted"
        authenticity = "not_established_without_caller_supplied_trusted_key"
    else:
        trusted_key = _load_trusted_public_key(trusted_public_key)
        if trusted_key != public_key:
            raise BundleError("M7 signature does not match the caller-supplied trusted key")
        trust_mode = "caller_supplied_trusted_key_matched"
        authenticity = "trusted_key_and_signature_matched_custody_not_established"
    return {
        "signature_present": True,
        "cryptographic_signature_valid": True,
        "signer_key_id": key_id,
        "trust_mode": trust_mode,
        "external_authenticity": authenticity,
        "external_custody": "not_established",
        "release_authorization": "not_established",
    }


def _validate_private_bundle_directory(bundle: Path) -> tuple[Path, bool]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise BundleError("bundle path must be a non-symlink directory")
    resolved = bundle.resolve(strict=True)
    if stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        raise BundleError("bundle directory is not private")
    names = {entry.name for entry in resolved.iterdir()}
    if names not in {BUNDLE_NAMES, SIGNED_BUNDLE_NAMES}:
        raise BundleError("bundle file set is incomplete or contains unexpected entries")
    for name in names:
        path = resolved / name
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise BundleError(f"bundle entry is not a regular file: {name}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise BundleError(f"bundle artifact is not private: {name}")
    return resolved, SIGNATURE_NAME in names


def _verified_commit_artifact(
    value: dict[str, Any],
) -> dict[str, Any]:
    if set(value) != {
        "schema_version",
        "object_format",
        "commit_oid",
        "tree_oid",
        "committed_epoch",
        "commit_object_base64",
    } or value.get("schema_version") != SOURCE_COMMIT_SCHEMA_VERSION:
        raise BundleError("source commit artifact does not match the closed schema")
    object_format = value.get("object_format")
    commit = value.get("commit_oid")
    tree = value.get("tree_oid")
    epoch = value.get("committed_epoch")
    encoded = value.get("commit_object_base64")
    if (
        object_format not in {"sha1", "sha256"}
        or not isinstance(commit, str)
        or not isinstance(tree, str)
        or not isinstance(epoch, int)
        or isinstance(epoch, bool)
        or not isinstance(encoded, str)
    ):
        raise BundleError("source commit artifact fields are malformed")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise BundleError("source commit object is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise BundleError("source commit object is not canonical base64")
    parsed_tree, parsed_epoch = _parse_commit_object(raw, object_format=object_format)
    if (
        _git_hash("commit", raw, object_format) != commit
        or parsed_tree != tree
        or parsed_epoch != epoch
    ):
        raise BundleError("source commit object hash, tree, or timestamp is inconsistent")
    return {
        "commit": commit,
        "tree": tree,
        "object_format": object_format,
        "committed_epoch": epoch,
        "commit_object": raw,
    }


def _index_records(index: dict[str, Any], revision: dict[str, Any]) -> tuple[SourceFile, ...]:
    if set(index) != {
        "schema_version",
        "source_prefix",
        "git",
        "file_count",
        "total_size_bytes",
        "files",
    } or index.get("schema_version") != SOURCE_INDEX_SCHEMA_VERSION:
        raise BundleError("source index does not match the closed schema")
    if index.get("source_prefix") != SOURCE_PREFIX:
        raise BundleError("source index prefix is invalid")
    if index.get("git") != {
        "object_format": revision["object_format"],
        "commit": revision["commit"],
        "tree": revision["tree"],
        "committed_epoch": revision["committed_epoch"],
    }:
        raise BundleError("source index Git binding is inconsistent")
    raw_files = index.get("files")
    count = index.get("file_count")
    total_size = index.get("total_size_bytes")
    if (
        not isinstance(raw_files, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or not isinstance(total_size, int)
        or isinstance(total_size, bool)
        or count != len(raw_files)
        or count <= 0
        or count > MAX_SOURCE_FILES
    ):
        raise BundleError("source index counts are invalid")
    records: list[SourceFile] = []
    previous = ""
    accumulated = 0
    for raw in raw_files:
        if not isinstance(raw, dict) or set(raw) != {
            "path",
            "mode",
            "size_bytes",
            "git_blob_oid",
            "sha1",
            "sha256",
        }:
            raise BundleError("source index file record is malformed")
        path = raw.get("path")
        mode = raw.get("mode")
        size = raw.get("size_bytes")
        blob_oid = raw.get("git_blob_oid")
        sha1 = raw.get("sha1")
        sha256 = raw.get("sha256")
        if (
            not isinstance(path, str)
            or _safe_source_path(path).as_posix() != path
            or path <= previous
            or mode not in {"100644", "100755"}
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_SOURCE_FILE_BYTES
            or not isinstance(blob_oid, str)
            or _OBJECT_ID.fullmatch(blob_oid) is None
            or not isinstance(sha1, str)
            or _SHA1.fullmatch(sha1) is None
            or not isinstance(sha256, str)
            or _SHA256.fullmatch(sha256) is None
        ):
            raise BundleError("source index file fields are invalid")
        previous = path
        accumulated += size
        if accumulated > MAX_SOURCE_TOTAL_BYTES:
            raise BundleError("source index expanded size exceeds its limit")
        # Content is filled from the archive after metadata validation.
        records.append(SourceFile(path, str(mode), blob_oid, b""))
    if accumulated != total_size:
        raise BundleError("source index total size is inconsistent")
    return tuple(records)


def _verify_source_archive(
    archive_path: Path,
    index: dict[str, Any],
    revision: dict[str, Any],
) -> tuple[SourceFile, ...]:
    declared = _index_records(index, revision)
    expected = {record.path: record for record in declared}
    raw_records = index["files"]
    raw_by_path = {str(record["path"]): record for record in raw_records}
    observed: list[SourceFile] = []
    seen: set[str] = set()
    total = 0
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            for member in archive:
                if len(seen) >= MAX_SOURCE_FILES:
                    raise BundleError("source archive contains too many members")
                name = member.name
                path = _safe_source_path(name)
                if len(path.parts) < 2 or path.parts[0] != SOURCE_PREFIX:
                    raise BundleError(f"source archive member is outside its prefix: {name}")
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                _safe_source_path(relative)
                if relative in seen:
                    raise BundleError("source archive contains a duplicate member name")
                seen.add(relative)
                if (
                    member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}
                    or not member.isfile()
                    or member.linkname
                    or member.pax_headers
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.mtime != revision["committed_epoch"]
                ):
                    raise BundleError(f"source archive contains an unsafe member: {name}")
                declared_record = expected.get(relative)
                raw_record = raw_by_path.get(relative)
                if declared_record is None or raw_record is None:
                    raise BundleError("source archive contains an undeclared member")
                expected_mode = 0o755 if declared_record.mode == "100755" else 0o644
                if member.mode != expected_mode or member.size != raw_record["size_bytes"]:
                    raise BundleError("source archive member mode or size is inconsistent")
                if member.size > MAX_SOURCE_FILE_BYTES:
                    raise BundleError("source archive member exceeds its size limit")
                stream = archive.extractfile(member)
                if stream is None:
                    raise BundleError("source archive regular file cannot be read")
                content = stream.read(MAX_SOURCE_FILE_BYTES + 1)
                if stream.read(1) or len(content) != member.size:
                    raise BundleError("source archive member length is inconsistent")
                total += len(content)
                if total > MAX_SOURCE_TOTAL_BYTES:
                    raise BundleError("source archive expanded size exceeds its limit")
                source = SourceFile(
                    relative,
                    declared_record.mode,
                    declared_record.blob_oid,
                    content,
                )
                if (
                    source.sha1 != raw_record["sha1"]
                    or source.sha256 != raw_record["sha256"]
                    or _git_hash("blob", content, revision["object_format"])
                    != source.blob_oid
                ):
                    raise BundleError("source archive content digest is inconsistent")
                observed.append(source)
    except (OSError, tarfile.TarError) as exc:
        raise BundleError("source archive is malformed or unreadable") from exc
    observed.sort(key=lambda item: item.path)
    if seen != set(expected) or len(observed) != len(declared):
        raise BundleError("source archive and source index file sets differ")
    result = tuple(observed)
    if _tree_oid(result, revision["object_format"]) != revision["tree"]:
        raise BundleError("source archive does not reconstruct the committed Git tree")
    return result


def _artifact_descriptors(bundle: Path) -> dict[str, dict[str, Any]]:
    return {name: _descriptor(bundle / name) for name in sorted(ARTIFACT_NAMES)}


def _verify_bundle_details(
    bundle: Path,
    *,
    expected_commit: str | None,
    trusted_public_key: Path | None,
    require_signature: bool,
) -> tuple[dict[str, Any], tuple[SourceFile, ...]]:
    resolved, signature_present = _validate_private_bundle_directory(bundle)
    if require_signature and not signature_present:
        raise BundleError("M7 signature is required but the bundle is unsigned")
    if trusted_public_key is not None and not signature_present:
        raise BundleError("caller supplied a trusted key for an unsigned M7 bundle")
    manifest_material = _read_regular(resolved / MANIFEST_NAME, maximum=MAX_JSON_BYTES)
    manifest = _parse_canonical_json(
        manifest_material,
        label="bundle manifest",
    )
    if signature_present:
        signature_value = _parse_canonical_json(
            _read_regular(resolved / SIGNATURE_NAME, maximum=MAX_JSON_BYTES),
            label="M7 manifest signature",
        )
        signature_report = _verify_signature_artifact(
            signature_value,
            manifest_material,
            trusted_public_key=trusted_public_key,
        )
        signer_key_id = str(signature_report["signer_key_id"])
    else:
        signature_report = {
            "signature_present": False,
            "cryptographic_signature_valid": False,
            "signer_key_id": None,
            "trust_mode": "unsigned",
            "external_authenticity": "not_established_unsigned",
            "external_custody": "not_established",
            "release_authorization": "not_established",
        }
        signer_key_id = None
    descriptors = _artifact_descriptors(resolved)
    artifact_claims = manifest.get("artifacts")
    if artifact_claims != descriptors:
        raise BundleError("bundle artifact checksums do not match the manifest")
    commit_artifact = _parse_canonical_json(
        _read_regular(resolved / SOURCE_COMMIT_NAME, maximum=MAX_JSON_BYTES),
        label="source commit artifact",
    )
    revision = _verified_commit_artifact(commit_artifact)
    if expected_commit is not None:
        if _OBJECT_ID.fullmatch(expected_commit) is None:
            raise BundleError("expected commit is malformed")
        if expected_commit != revision["commit"]:
            raise BundleError("bundle does not match the caller-supplied expected commit")
    index = _parse_canonical_json(
        _read_regular(resolved / SOURCE_INDEX_NAME, maximum=MAX_JSON_BYTES),
        label="source index",
    )
    files = _verify_source_archive(resolved / SOURCE_ARCHIVE_NAME, index, revision)
    file_map = {item.path: item.content for item in files}
    if file_map.get(BUILDER_SOURCE_PATH) != _read_regular(
        resolved / VERIFIER_NAME, maximum=MAX_JSON_BYTES
    ):
        raise BundleError("standalone verifier does not match the exact committed source")
    inputs = _parse_canonical_json(
        _read_regular(resolved / INPUTS_NAME, maximum=MAX_JSON_BYTES),
        label="reproduction inputs",
    )
    expected_inputs = _reproduction_inputs(file_map)
    if inputs != expected_inputs:
        raise BundleError("reproduction input inventory is not source-derived")
    sbom = _parse_canonical_json(
        _read_regular(resolved / SBOM_NAME, maximum=MAX_JSON_BYTES),
        label="SPDX SBOM",
    )
    if sbom != _spdx_sbom(files, revision, expected_inputs):
        raise BundleError("SPDX SBOM is not the exact source-derived inventory")
    protocol = _parse_canonical_json(
        _read_regular(resolved / PROTOCOL_NAME, maximum=MAX_JSON_BYTES),
        label="replication protocol",
    )
    if protocol != _replication_protocol(revision):
        raise BundleError("replication protocol is altered or overstates execution")
    inventory = _parse_canonical_json(
        _read_regular(resolved / EVIDENCE_NAME, maximum=MAX_JSON_BYTES),
        label="milestone evidence inventory",
    )
    if inventory != _evidence_inventory(file_map):
        raise BundleError("milestone evidence inventory is altered or overstates evidence")
    expected_manifest = _manifest(
        revision,
        descriptors,
        file_map,
        signer_key_id=signer_key_id,
    )
    if manifest != expected_manifest:
        raise BundleError("bundle manifest is altered or overstates source/release claims")
    report = {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "valid": True,
        "source": {
            "git_commit": revision["commit"],
            "git_tree": revision["tree"],
            "file_count": len(files),
            "caller_supplied_expected_commit": expected_commit,
            "external_commit_match": expected_commit is not None,
            "external_authenticity": (
                "caller_supplied_commit_matched"
                if expected_commit is not None
                else "not_established_without_external_expected_commit"
            ),
        },
        "artifact_count": len(ARTIFACT_NAMES) + int(signature_present),
        "attestation": signature_report,
        "release_state": "not_published_or_publicly_released",
        "protocol_state": "specified_but_not_executed_by_bundle",
        "independent_replication": "not_established",
        "deployment": "not_established",
        "operational_effectiveness": "not_established",
    }
    return report, files


def verify_bundle(
    bundle: Path,
    *,
    expected_commit: str | None = None,
    trusted_public_key: Path | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    """Verify without Git/network; signed mode requires ``cryptography``."""

    report, _files = _verify_bundle_details(
        bundle,
        expected_commit=expected_commit,
        trusted_public_key=trusted_public_key,
        require_signature=require_signature,
    )
    return report


def _write_extracted_file(path: Path, source: SourceFile) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write_bytes(path, source.content, mode=0o755 if source.mode == "100755" else 0o644)


def extract_bundle_source(
    bundle: Path,
    output: Path,
    *,
    expected_commit: str | None = None,
    trusted_public_key: Path | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    """Verify and safely extract regular source files into a new directory."""

    report, files = _verify_bundle_details(
        bundle,
        expected_commit=expected_commit,
        trusted_public_key=trusted_public_key,
        require_signature=require_signature,
    )
    if output.exists() or output.is_symlink() or output.name in {"", ".", ".."}:
        raise BundleError("refusing to overwrite an existing extraction path")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise BundleError("extraction parent must be an existing non-symlink directory")
    resolved_output = output.parent.resolve(strict=True) / output.name
    resolved_bundle = bundle.resolve(strict=True)
    if resolved_output == resolved_bundle or resolved_output.is_relative_to(resolved_bundle):
        raise BundleError("source extraction path must be outside the bundle")
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.m7-extract-", dir=output.parent))
    staging.chmod(0o700)
    published = False
    try:
        for source in files:
            _write_extracted_file(staging.joinpath(*PurePosixPath(source.path).parts), source)
        for directory in sorted(
            (path for path in staging.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
        _fsync_directory(staging)
        _publish_directory_noreplace(staging, resolved_output)
        published = True
        _fsync_directory(resolved_output.parent)
    finally:
        if not published and staging.exists():
            shutil.rmtree(staging)
    return {
        **report,
        "extracted": True,
        "extraction_path": str(resolved_output),
        "extracted_file_count": len(files),
    }


def build_bundle(
    output: Path,
    *,
    commit_reference: str = "HEAD",
    signing_private_key: Path | None = None,
) -> dict[str, Any]:
    """Build a deterministic candidate from the current clean exact HEAD."""

    destination = _resolved_external_output(output)
    revision = _resolve_current_source(commit_reference)
    if signing_private_key is None:
        private_key = None
        public_key = None
        signer_key_id = None
    else:
        private_key, public_key, signer_key_id = _signing_identity(signing_private_key)
    files = _load_git_files(str(revision["commit"]), str(revision["object_format"]))
    if _tree_oid(files, str(revision["object_format"])) != revision["tree"]:
        raise BundleError("loaded source files do not reconstruct the Git tree")
    file_map = {item.path: item.content for item in files}
    verifier = file_map.get(BUILDER_SOURCE_PATH)
    if verifier is None:
        raise BundleError("exact source commit does not contain the M7 verifier")
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.m7-", dir=destination.parent)
    )
    staging.chmod(0o700)
    published = False
    try:
        _write_source_archive(
            staging / SOURCE_ARCHIVE_NAME,
            files,
            committed_epoch=int(revision["committed_epoch"]),
        )
        _write_json(staging / SOURCE_INDEX_NAME, _source_index(revision, files))
        _write_json(staging / SOURCE_COMMIT_NAME, _source_commit(revision))
        inputs = _reproduction_inputs(file_map)
        _write_json(staging / INPUTS_NAME, inputs)
        _write_json(staging / SBOM_NAME, _spdx_sbom(files, revision, inputs))
        _write_json(staging / PROTOCOL_NAME, _replication_protocol(revision))
        _write_json(staging / EVIDENCE_NAME, _evidence_inventory(file_map))
        _write_bytes(staging / VERIFIER_NAME, verifier)
        descriptors = _artifact_descriptors(staging)
        manifest = _manifest(
            revision,
            descriptors,
            file_map,
            signer_key_id=signer_key_id,
        )
        manifest_material = _canonical_bytes(manifest) + b"\n"
        _write_bytes(staging / MANIFEST_NAME, manifest_material)
        if private_key is not None and public_key is not None and signer_key_id is not None:
            _write_json(
                staging / SIGNATURE_NAME,
                _signature_artifact(
                    manifest_material,
                    private_key=private_key,
                    public_key=public_key,
                    key_id=signer_key_id,
                ),
            )
        _fsync_directory(staging)
        _verify_bundle_details(
            staging,
            expected_commit=str(revision["commit"]),
            trusted_public_key=None,
            require_signature=signer_key_id is not None,
        )
        if (
            _command_text("git", "rev-parse", "HEAD") != revision["commit"]
            or _run(
                "git", "status", "--porcelain=v1", "-z", "--untracked-files=all"
            ).stdout
        ):
            raise BundleError("source checkout changed during bundle construction")
        _publish_directory_noreplace(staging, destination)
        published = True
        _fsync_directory(destination.parent)
        report = verify_bundle(
            destination,
            expected_commit=str(revision["commit"]),
            require_signature=signer_key_id is not None,
        )
        bundle_names = SIGNED_BUNDLE_NAMES if signer_key_id is not None else BUNDLE_NAMES
        bundle_descriptors = {
            name: _descriptor(destination / name) for name in sorted(bundle_names)
        }
        return {
            **report,
            "bundle_path": str(destination),
            "artifact_set_sha256": hashlib.sha256(
                _canonical_bytes(bundle_descriptors)
            ).hexdigest(),
        }
    finally:
        if not published and staging.exists():
            shutil.rmtree(staging)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build or offline-verify an exact-source M7 replication candidate."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build from the current clean exact HEAD")
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--commit", default="HEAD")
    build.add_argument(
        "--signing-private-key",
        type=Path,
        help="external unencrypted Ed25519 PEM key; emits a detached local signature",
    )
    verify = commands.add_parser("verify", help="verify a retained bundle offline")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--expected-commit")
    verify.add_argument("--trusted-public-key", type=Path)
    verify.add_argument("--require-signature", action="store_true")
    extract = commands.add_parser("extract", help="verify and safely extract exact source")
    extract.add_argument("--bundle", type=Path, required=True)
    extract.add_argument("--output", type=Path, required=True)
    extract.add_argument("--expected-commit")
    extract.add_argument("--trusted-public-key", type=Path)
    extract.add_argument("--require-signature", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "build":
            result = build_bundle(
                arguments.output,
                commit_reference=arguments.commit,
                signing_private_key=arguments.signing_private_key,
            )
        elif arguments.command == "verify":
            result = verify_bundle(
                arguments.bundle,
                expected_commit=arguments.expected_commit,
                trusted_public_key=arguments.trusted_public_key,
                require_signature=arguments.require_signature,
            )
        else:
            result = extract_bundle_source(
                arguments.bundle,
                arguments.output,
                expected_commit=arguments.expected_commit,
                trusted_public_key=arguments.trusted_public_key,
                require_signature=arguments.require_signature,
            )
    except BundleError as exc:
        print(f"M7 replication bundle error: {exc}", file=sys.stderr)
        return 2
    print((_canonical_bytes(result) + b"\n").decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
