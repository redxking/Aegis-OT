#!/usr/bin/env python3
"""Create source-bound M5 degraded-operation authority and runtime artifacts.

The ``authority`` command creates an operator-controlled Ed25519 keypair outside
the checkout.  The ``bundle`` command reads that private authority and publishes
a separate runtime-input directory that contains only the public key, one
complete role/path snapshot generation, a signed lease bound to that exact
snapshot, and initial monotonic state.  The ``reversal`` command publishes a
separate operator-only revocation package; it is never a gateway runtime input.

These artifacts are explicit administrative inputs.  They do not detect a
compromise, operate a management service, authorize a plant effect, deploy the
gateway, or establish mission continuity.  A lease can only admit a request to
the unchanged primary assurance path, and every non-management loss remains a
safe-state or hold-state result under the existing M5 policy matrix.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis_ot.crypto import verify_bytes
from aegis_ot.m5_degraded import (
    ROLE_LOSS_POLICIES,
    DegradedBehavior,
    DegradedModeAuthorization,
    DegradedModeReversal,
    DegradedOperationState,
    DegradedRole,
    DegradedRuntimeSnapshot,
    RoleCondition,
)
from aegis_ot.models import Operation

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_SCHEMA: Final[str] = "aegis-ot-m5-degraded-authority-v1"
BUNDLE_SCHEMA: Final[str] = "aegis-ot-m5-degraded-runtime-inputs-v1"
REVERSAL_PACKAGE_SCHEMA: Final[str] = "aegis-ot-m5-degraded-reversal-package-v1"
AUTHORITY_METADATA_NAME: Final[str] = "authority.json"
AUTHORITY_PRIVATE_NAME: Final[str] = "authority.private"
AUTHORITY_PUBLIC_NAME: Final[str] = "authority.public"
SNAPSHOT_NAME: Final[str] = "degraded-snapshot.json"
AUTHORIZATION_NAME: Final[str] = "degraded-authorization.json"
REVERSAL_NAME: Final[str] = "degraded-reversal.json"
STATE_NAME: Final[str] = "degraded-state.initial.json"
MANIFEST_NAME: Final[str] = "manifest.json"
MAX_ARTIFACT_BYTES: Final[int] = 1024 * 1024
MAX_LEASE_SECONDS: Final[int] = 300
MAX_SNAPSHOT_AGE_SECONDS: Final[int] = 5
_STAGING_PREFIX: Final[str] = ".m5-degraded-artifacts-"
_GIT_OBJECT: Final[re.Pattern[str]] = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_AUTHORITY_ID: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_CANONICAL_TEXT: Final[re.Pattern[str]] = re.compile(r"^[^\s]{1,256}$")

SOURCE_PATHS: Final[tuple[str, ...]] = (
    "pyproject.toml",
    "scripts/prepare_m5_degraded_artifacts.py",
    "src/aegis_ot/crypto.py",
    "src/aegis_ot/m5_degraded.py",
    "src/aegis_ot/models.py",
    "src/aegis_ot/segmented_capability_runtime.py",
)

AUTHORITY_FILES: Final[frozenset[str]] = frozenset(
    {AUTHORITY_METADATA_NAME, AUTHORITY_PRIVATE_NAME, AUTHORITY_PUBLIC_NAME}
)
BUNDLE_FILES: Final[frozenset[str]] = frozenset(
    {
        AUTHORITY_PUBLIC_NAME,
        SNAPSHOT_NAME,
        AUTHORIZATION_NAME,
        STATE_NAME,
        MANIFEST_NAME,
    }
)
REVERSAL_PACKAGE_FILES: Final[frozenset[str]] = frozenset(
    {REVERSAL_NAME, MANIFEST_NAME}
)


class M5ArtifactError(RuntimeError):
    """The M5 authority or runtime-input package could not be trusted."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise M5ArtifactError("M5 artifact material is not canonical finite JSON") from exc


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _current_uid() -> int:
    return os.geteuid()


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise M5ArtifactError(f"duplicate M5 artifact JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise M5ArtifactError(f"non-finite M5 artifact value is prohibited: {value}")


def _load_json(material: bytes, *, label: str) -> dict[str, Any]:
    if material.startswith(b"\xef\xbb\xbf"):
        raise M5ArtifactError(f"{label} contains a prohibited UTF-8 BOM")
    try:
        value = json.loads(
            material.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise M5ArtifactError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise M5ArtifactError(f"{label} root must be an object")
    if _canonical_bytes(value) != material:
        raise M5ArtifactError(f"{label} is not canonical JSON")
    return value


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git(*arguments: str, binary: bool = False) -> bytes | str:
    executable = shutil.which("git", path="/usr/bin:/bin")
    if executable is None:
        raise M5ArtifactError("Git is required for M5 source binding")
    completed = subprocess.run(  # noqa: S603 - resolved executable and fixed argv
        (executable, "-C", str(ROOT), "--no-replace-objects", *arguments),
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise M5ArtifactError(f"Git source-binding command failed: {detail[-1000:]}")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise M5ArtifactError("Git returned non-UTF-8 source metadata") from exc


def _canonical_reference(reference: str) -> str:
    if (
        not reference
        or reference != reference.strip()
        or reference.startswith("-")
        or len(reference) > 512
        or any(character.isspace() or ord(character) < 32 for character in reference)
    ):
        raise M5ArtifactError("source commit reference is malformed")
    return reference


def _read_source_file(relative: str) -> bytes:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or pure.as_posix() != relative
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise M5ArtifactError(f"source path is noncanonical: {relative}")
    path = ROOT.joinpath(*pure.parts)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise M5ArtifactError(f"required source is unavailable: {relative}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or resolved != path
        or not resolved.is_relative_to(ROOT.resolve(strict=True))
    ):
        raise M5ArtifactError(f"required source is not one exact regular file: {relative}")
    try:
        material = path.read_bytes()
    except OSError as exc:
        raise M5ArtifactError(f"required source could not be read: {relative}") from exc
    if not material or len(material) > MAX_ARTIFACT_BYTES * 16:
        raise M5ArtifactError(f"required source size is outside the bound: {relative}")
    return material


def _assert_clean_source(reference: str) -> dict[str, Any]:
    """Bind artifact generation to the exact clean checked-out commit."""

    reference = _canonical_reference(reference)
    try:
        imported = Path(__file__).resolve(strict=True)
        expected = (ROOT / SOURCE_PATHS[1]).resolve(strict=True)
    except OSError as exc:
        raise M5ArtifactError("M5 artifact generator source is unavailable") from exc
    if imported != expected:
        raise M5ArtifactError("M5 artifact generator was imported from stale source")
    top = _git("rev-parse", "--show-toplevel")
    if top != str(ROOT.resolve(strict=True)):
        raise M5ArtifactError("M5 artifact generator is not in the authoritative checkout")
    status = _git("status", "--porcelain=v1", "-z", "--untracked-files=all", binary=True)
    if status:
        raise M5ArtifactError("M5 artifact generation requires an exact clean checkout")
    head = _git("rev-parse", "--verify", "HEAD^{commit}")
    commit = _git("rev-parse", "--verify", f"{reference}^{{commit}}")
    if not isinstance(head, str) or not isinstance(commit, str):
        raise M5ArtifactError("Git commit resolution returned an invalid type")
    if not _GIT_OBJECT.fullmatch(head) or commit != head:
        raise M5ArtifactError("source commit must resolve to the exact checked-out HEAD")
    tree = _git("rev-parse", "--verify", f"{commit}^{{tree}}")
    if not isinstance(tree, str) or not _GIT_OBJECT.fullmatch(tree):
        raise M5ArtifactError("source tree identifier is noncanonical")

    bindings: list[dict[str, Any]] = []
    for relative in SOURCE_PATHS:
        working = _read_source_file(relative)
        retained = _git("show", f"{commit}:{relative}", binary=True)
        if not isinstance(retained, bytes) or retained != working:
            raise M5ArtifactError(f"required source differs from commit: {relative}")
        record = _git("ls-tree", commit, "--", relative)
        if not isinstance(record, str):
            raise M5ArtifactError("Git tree record returned an invalid type")
        try:
            header, retained_path = record.split("\t", 1)
            mode, object_type, object_id = header.split(" ")
        except ValueError as exc:
            raise M5ArtifactError(f"Git returned a malformed source entry: {relative}") from exc
        if (
            retained_path != relative
            or object_type != "blob"
            or mode not in {"100644", "100755"}
            or not _GIT_OBJECT.fullmatch(object_id)
        ):
            raise M5ArtifactError(f"Git source entry is noncanonical: {relative}")
        bindings.append(
            {
                "path": relative,
                "size_bytes": len(working),
                "sha256": _sha256(working),
                "git_mode": mode,
                "git_blob": object_id,
            }
        )
    material = {"git_commit": commit, "git_tree": tree, "source_files": bindings}
    return {
        **material,
        "clean_checkout": True,
        "source_fingerprint_sha256": _sha256(_canonical_bytes(material)),
    }


def _validate_source_binding(binding: Mapping[str, Any]) -> None:
    if set(binding) != {
        "git_commit",
        "git_tree",
        "clean_checkout",
        "source_files",
        "source_fingerprint_sha256",
    }:
        raise M5ArtifactError("M5 source-binding fields are not exact")
    if binding.get("clean_checkout") is not True:
        raise M5ArtifactError("M5 source binding is not a clean checkout")
    commit = binding.get("git_commit")
    tree = binding.get("git_tree")
    if not isinstance(commit, str) or not _GIT_OBJECT.fullmatch(commit):
        raise M5ArtifactError("M5 source commit is noncanonical")
    if not isinstance(tree, str) or not _GIT_OBJECT.fullmatch(tree):
        raise M5ArtifactError("M5 source tree is noncanonical")
    files = binding.get("source_files")
    if not isinstance(files, list) or len(files) != len(SOURCE_PATHS):
        raise M5ArtifactError("M5 source path inventory is incomplete")
    paths: list[str] = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "size_bytes",
            "sha256",
            "git_mode",
            "git_blob",
        }:
            raise M5ArtifactError("M5 source-file binding fields are not exact")
        path = item.get("path")
        paths.append(path if isinstance(path, str) else "")
        if (
            type(item.get("size_bytes")) is not int
            or item["size_bytes"] <= 0
            or not isinstance(item.get("sha256"), str)
            or not _SHA256.fullmatch(item["sha256"])
            or item.get("git_mode") not in {"100644", "100755"}
            or not isinstance(item.get("git_blob"), str)
            or not _GIT_OBJECT.fullmatch(item["git_blob"])
        ):
            raise M5ArtifactError("M5 source-file binding is noncanonical")
    if paths != list(SOURCE_PATHS):
        raise M5ArtifactError("M5 source path order is not exact")
    material = {"git_commit": commit, "git_tree": tree, "source_files": files}
    if binding.get("source_fingerprint_sha256") != _sha256(_canonical_bytes(material)):
        raise M5ArtifactError("M5 source fingerprint is invalid")


def _reject_symlink_components(path: Path) -> None:
    if not path.is_absolute():
        raise M5ArtifactError("M5 artifact path must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if current == path:
                return
            raise M5ArtifactError("M5 artifact parent is unavailable") from None
        except OSError as exc:
            raise M5ArtifactError("M5 artifact path could not be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise M5ArtifactError("M5 artifact path must not contain symlinks")


def _open_safe_parent(output: Path) -> tuple[Path, int]:
    if not output.is_absolute() or output.name in {"", ".", ".."}:
        raise M5ArtifactError("M5 artifact output must be an absolute named path")
    _reject_symlink_components(output.parent)
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise M5ArtifactError("M5 artifact parent is unavailable") from exc
    destination = parent / output.name
    try:
        destination.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise M5ArtifactError("M5 artifacts must be created outside the checkout")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(parent, flags)
    except OSError as exc:
        raise M5ArtifactError("M5 artifact parent could not be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != _current_uid():
            raise M5ArtifactError("M5 artifact parent must be an owned directory")
        if mode & stat.S_IRWXU != stat.S_IRWXU or mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise M5ArtifactError(
                "M5 artifact parent must grant owner rwx and deny group/other writes"
            )
        try:
            os.stat(output.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise M5ArtifactError("refusing to overwrite an M5 artifact path")
    except BaseException:
        os.close(descriptor)
        raise
    return destination, descriptor


def _write_file(directory_fd: int, name: str, material: bytes) -> None:
    if not material or len(material) > MAX_ARTIFACT_BYTES:
        raise M5ArtifactError(f"M5 artifact size is outside the bound: {name}")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except OSError as exc:
        raise M5ArtifactError(f"M5 artifact could not be created: {name}") from exc
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                raise M5ArtifactError("M5 artifact write made no progress")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != _current_uid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(material)
        ):
            raise M5ArtifactError(f"M5 artifact is not an owned mode-0600 file: {name}")
    finally:
        os.close(descriptor)


def _publish_directory_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a new directory without replacing any existing path."""

    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise M5ArtifactError("atomic no-replace publication is unavailable")
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = int(renamex_np(source_bytes, destination_bytes, 0x00000004))
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise M5ArtifactError("atomic no-replace publication is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = int(renameat2(-100, source_bytes, -100, destination_bytes, 1))
    elif os.name == "nt":  # pragma: no cover - Windows rename is no-clobber
        try:
            os.rename(source, destination)
        except FileExistsError as exc:
            raise M5ArtifactError("refusing to overwrite an M5 artifact path") from exc
        except OSError as exc:
            raise M5ArtifactError("M5 artifact publication failed") from exc
        return
    else:  # pragma: no cover - fail closed on an unknown primitive
        raise M5ArtifactError("atomic no-replace publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise M5ArtifactError("refusing to overwrite an M5 artifact path")
    raise M5ArtifactError(
        f"M5 artifact publication failed: {os.strerror(error_number)}"
    )


def _read_private_file(path: Path, *, label: str, exact_size: int | None = None) -> bytes:
    if not path.is_absolute():
        raise M5ArtifactError(f"{label} path must be absolute")
    _reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise M5ArtifactError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != _current_uid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= MAX_ARTIFACT_BYTES
        ):
            raise M5ArtifactError(f"{label} must be an owned mode-0600 regular file")
        material = os.read(descriptor, MAX_ARTIFACT_BYTES + 1)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(material) != before.st_size
        ):
            raise M5ArtifactError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    if exact_size is not None and len(material) != exact_size:
        raise M5ArtifactError(f"{label} must contain exactly {exact_size} raw bytes")
    return material


def _read_directory_artifact(directory: Path, name: str) -> bytes:
    return _read_private_file(directory / name, label=f"M5 artifact {name}")


def _staging_directory(parent_fd: int) -> tuple[str, int]:
    name = f"{_STAGING_PREFIX}{secrets.token_hex(16)}"
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o700)
    except OSError as exc:
        raise M5ArtifactError("private M5 staging directory could not be created") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != _current_uid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise M5ArtifactError("M5 staging directory is not owned mode 0700")
    return name, descriptor


def _cleanup_staging(parent_fd: int, staging_fd: int | None, staging_name: str) -> None:
    if staging_fd is not None:
        try:
            names = os.listdir(staging_fd)
        except OSError:
            names = []
        for name in names:
            try:
                os.unlink(name, dir_fd=staging_fd)
            except OSError:
                pass
    try:
        os.rmdir(staging_name, dir_fd=parent_fd)
    except OSError:
        pass


def _validate_authority_id(authority_id: str) -> str:
    if not _AUTHORITY_ID.fullmatch(authority_id):
        raise M5ArtifactError("M5 authority ID is noncanonical")
    return authority_id


def _authority_metadata(
    *,
    authority_id: str,
    public_material: bytes,
    private_material: bytes,
    source_binding: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": AUTHORITY_SCHEMA,
        "authority_id": authority_id,
        "algorithm": "Ed25519",
        "key_id": _sha256(public_material),
        "key_encoding": "raw",
        "files": {
            AUTHORITY_PRIVATE_NAME: {
                "size_bytes": len(private_material),
                "sha256": _sha256(private_material),
                "distribution": "operator_only_never_runtime_bundle",
            },
            AUTHORITY_PUBLIC_NAME: {
                "size_bytes": len(public_material),
                "sha256": _sha256(public_material),
                "distribution": "gateway_runtime_input",
            },
        },
        "source_binding": dict(source_binding),
        "claim_boundary": {
            "establishes": "local operator-configured M5 administrative authority",
            "does_not_establish": [
                "compromise detection",
                "independent authority custody",
                "deployment",
                "plant-effect authorization",
                "mission continuity",
                "operational effectiveness",
            ],
        },
    }


def _load_authority(directory: Path) -> tuple[dict[str, Any], Ed25519PrivateKey, bytes]:
    if not directory.is_absolute():
        raise M5ArtifactError("M5 authority directory path must be absolute")
    _reject_symlink_components(directory)
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise M5ArtifactError("M5 authority directory is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != _current_uid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or {item.name for item in directory.iterdir()} != AUTHORITY_FILES
    ):
        raise M5ArtifactError("M5 authority directory is not an exact owned mode-0700 package")
    private_material = _read_directory_artifact(directory, AUTHORITY_PRIVATE_NAME)
    public_material = _read_directory_artifact(directory, AUTHORITY_PUBLIC_NAME)
    metadata_material = _read_directory_artifact(directory, AUTHORITY_METADATA_NAME)
    if len(private_material) != 32 or len(public_material) != 32:
        raise M5ArtifactError("M5 authority keys must contain exactly 32 raw bytes")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(private_material)
    except ValueError as exc:
        raise M5ArtifactError("M5 authority private key is invalid") from exc
    if _raw_public(private_key) != public_material:
        raise M5ArtifactError("M5 authority public and private keys do not match")
    document = _load_json(metadata_material, label=AUTHORITY_METADATA_NAME)
    if set(document) != {
        "schema_version",
        "authority_id",
        "algorithm",
        "key_id",
        "key_encoding",
        "files",
        "source_binding",
        "claim_boundary",
    } or document.get("schema_version") != AUTHORITY_SCHEMA:
        raise M5ArtifactError("M5 authority metadata fields or schema are not exact")
    authority_id = document.get("authority_id")
    if not isinstance(authority_id, str):
        raise M5ArtifactError("M5 authority ID is missing")
    _validate_authority_id(authority_id)
    if (
        document.get("algorithm") != "Ed25519"
        or document.get("key_encoding") != "raw"
        or document.get("key_id") != _sha256(public_material)
    ):
        raise M5ArtifactError("M5 authority cryptographic metadata is inconsistent")
    files = document.get("files")
    expected_files = {
        AUTHORITY_PRIVATE_NAME: {
            "size_bytes": 32,
            "sha256": _sha256(private_material),
            "distribution": "operator_only_never_runtime_bundle",
        },
        AUTHORITY_PUBLIC_NAME: {
            "size_bytes": 32,
            "sha256": _sha256(public_material),
            "distribution": "gateway_runtime_input",
        },
    }
    if files != expected_files:
        raise M5ArtifactError("M5 authority file inventory is inconsistent")
    source_binding = document.get("source_binding")
    if not isinstance(source_binding, dict):
        raise M5ArtifactError("M5 authority lacks a source binding")
    _validate_source_binding(source_binding)
    return document, private_key, public_material


def create_authority(
    output: Path,
    *,
    authority_id: str,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Atomically publish a private M5 administrative authority."""

    authority_id = _validate_authority_id(authority_id)
    source_binding = _assert_clean_source(source_reference)
    destination, parent_fd = _open_safe_parent(output)
    staging_name = ""
    staging_fd: int | None = None
    published = False
    try:
        staging_name, staging_fd = _staging_directory(parent_fd)
        key = Ed25519PrivateKey.generate()
        private_material = _raw_private(key)
        public_material = _raw_public(key)
        metadata = _authority_metadata(
            authority_id=authority_id,
            public_material=public_material,
            private_material=private_material,
            source_binding=source_binding,
        )
        _write_file(staging_fd, AUTHORITY_PRIVATE_NAME, private_material)
        _write_file(staging_fd, AUTHORITY_PUBLIC_NAME, public_material)
        _write_file(staging_fd, AUTHORITY_METADATA_NAME, _canonical_bytes(metadata))
        os.fsync(staging_fd)
        staging_path = destination.with_name(staging_name)
        _load_authority(staging_path)
        _publish_directory_noreplace(staging_path, destination)
        published = True
        os.fsync(parent_fd)
        return metadata
    finally:
        if not published and staging_name:
            _cleanup_staging(parent_fd, staging_fd, staging_name)
        if staging_fd is not None:
            os.close(staging_fd)
        os.close(parent_fd)


def _effective_behavior(affected: frozenset[DegradedRole]) -> DegradedBehavior:
    behaviors = {ROLE_LOSS_POLICIES[role].behavior for role in affected}
    if DegradedBehavior.SAFE_STATE in behaviors:
        return DegradedBehavior.SAFE_STATE
    if DegradedBehavior.HOLD_STATE in behaviors:
        return DegradedBehavior.HOLD_STATE
    return DegradedBehavior.MISSION_PRESERVING


def _artifact_record(material: bytes, *, purpose: str) -> dict[str, Any]:
    return {"size_bytes": len(material), "sha256": _sha256(material), "purpose": purpose}


def _bundle_material(
    *,
    authority_id: str,
    private_key: Ed25519PrivateKey,
    public_material: bytes,
    source_binding: Mapping[str, Any],
    role: DegradedRole,
    surface: str,
    condition: RoleCondition,
    actor_id: str,
    mission_id: str,
    resource: str,
    operation: Operation,
    maximum_risk_score: float,
    lease_seconds: int,
    sequence: int,
    now: datetime,
    unresolved_effect: bool,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    if surface not in {"service", "communication"}:
        raise M5ArtifactError("M5 affected surface must be service or communication")
    if condition is RoleCondition.HEALTHY:
        raise M5ArtifactError("M5 degraded input must name a non-healthy condition")
    if not 1 <= lease_seconds <= MAX_LEASE_SECONDS:
        raise M5ArtifactError(f"M5 lease duration must be between 1 and {MAX_LEASE_SECONDS}")
    if type(sequence) is not int or sequence < 1:
        raise M5ArtifactError("M5 authorization sequence must be a positive integer")
    if (
        not math.isfinite(maximum_risk_score)
        or not 0 <= maximum_risk_score <= 100
    ):
        raise M5ArtifactError("M5 maximum risk score must be finite and between 0 and 100")
    for label, value in {
        "actor ID": actor_id,
        "mission ID": mission_id,
        "resource": resource,
    }.items():
        if not _CANONICAL_TEXT.fullmatch(value):
            raise M5ArtifactError(f"M5 {label} is noncanonical")
    if now.tzinfo is None or now.utcoffset() is None:
        raise M5ArtifactError("M5 artifact time must be timezone-aware")
    issued_at = now.astimezone(UTC)
    role_conditions = {item: RoleCondition.HEALTHY for item in DegradedRole}
    communication_conditions = {item: RoleCondition.HEALTHY for item in DegradedRole}
    target = role_conditions if surface == "service" else communication_conditions
    target[role] = condition
    token = secrets.token_hex(16)
    snapshot = DegradedRuntimeSnapshot(
        snapshot_id=f"m5-degraded-snapshot-{token}",
        captured_at=issued_at,
        role_conditions=role_conditions,
        communication_conditions=communication_conditions,
        unresolved_effect=unresolved_effect,
    )
    authorization = DegradedModeAuthorization(
        authorization_id=f"m5-degraded-authorization-{token}",
        sequence=sequence,
        authority_id=authority_id,
        mode_name=f"{role.value}-{surface}-degraded",
        behavior=ROLE_LOSS_POLICIES[role].behavior,
        affected_roles=frozenset({role}),
        allowed_actor_ids=frozenset({actor_id}),
        allowed_mission_ids=frozenset({mission_id}),
        allowed_resources=frozenset({resource}),
        allowed_operations=frozenset({operation}),
        maximum_risk_score=maximum_risk_score,
        snapshot_sha256=snapshot.digest,
        recovery_checkpoint_id=f"m5-recovery-checkpoint-{token}",
        nonce=f"m5-degraded-authorization-nonce-{token}",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=lease_seconds),
    ).signed(private_key)
    state = DegradedOperationState.initial(authority_id)

    materials = {
        AUTHORITY_PUBLIC_NAME: public_material,
        SNAPSHOT_NAME: _canonical_bytes(snapshot.model_dump(mode="json")),
        AUTHORIZATION_NAME: _canonical_bytes(authorization.model_dump(mode="json")),
        STATE_NAME: _canonical_bytes(state.model_dump(mode="json")),
    }
    files = {
        AUTHORITY_PUBLIC_NAME: _artifact_record(
            materials[AUTHORITY_PUBLIC_NAME], purpose="gateway_pinned_authority"
        ),
        SNAPSHOT_NAME: _artifact_record(
            materials[SNAPSHOT_NAME], purpose="gateway_runtime_snapshot"
        ),
        AUTHORIZATION_NAME: _artifact_record(
            materials[AUTHORIZATION_NAME], purpose="gateway_signed_degraded_lease"
        ),
        STATE_NAME: _artifact_record(
            materials[STATE_NAME], purpose="gateway_mutable_state_bootstrap"
        ),
    }
    manifest: dict[str, Any] = {
        "schema_version": BUNDLE_SCHEMA,
        "source_binding": dict(source_binding),
        "authority": {
            "authority_id": authority_id,
            "algorithm": "Ed25519",
            "key_id": _sha256(public_material),
            "private_key_included": False,
        },
        "scenario": {
            "role": role.value,
            "surface": surface,
            "condition": condition.value,
            "behavior": ROLE_LOSS_POLICIES[role].behavior.value,
            "unresolved_effect": unresolved_effect,
            "operator_asserted_not_detected": True,
        },
        "snapshot_signature_binding": {
            "mechanism": "signed_authorization_snapshot_sha256",
            "snapshot_sha256": snapshot.digest,
            "authorization_sha256": authorization.digest,
            "authorization_signature_verified_before_publication": True,
            "independent_snapshot_signature": False,
        },
        "snapshot_freshness_contract": {
            "maximum_age_seconds": MAX_SNAPSHOT_AGE_SECONDS,
            "single_generation_artifact": True,
            "continuous_refresh_provided": False,
            "stale_snapshot_fails_closed": True,
            "external_trusted_monitor_required": True,
            "operator_assertion_is_not_compromise_detection": True,
        },
        "lease": {
            "authorization_id": authorization.authorization_id,
            "sequence": authorization.sequence,
            "issued_at": authorization.issued_at.isoformat(),
            "expires_at": authorization.expires_at.isoformat(),
            "maximum_lifetime_seconds": MAX_LEASE_SECONDS,
            "execution_authorized": False,
        },
        "reversal_contract": {
            "separate_operator_package_required": True,
            "runtime_bundle_contains_reversal": False,
            "create_command": "prepare_m5_degraded_artifacts.py reversal",
        },
        "runtime_environment_contract": {
            "AEGIS_M5_DEGRADED_AUTHORITY_ID": authority_id,
            "AEGIS_M5_DEGRADED_AUTHORITY_PUBLIC_KEY_FILE": AUTHORITY_PUBLIC_NAME,
            "AEGIS_M5_DEGRADED_SNAPSHOT_FILE": SNAPSHOT_NAME,
            "AEGIS_M5_DEGRADED_AUTHORIZATION_FILE": AUTHORIZATION_NAME,
            "AEGIS_M5_DEGRADED_STATE_FILE": STATE_NAME,
        },
        "files": files,
        "distribution_boundary": {
            "runtime_inputs": [
                AUTHORITY_PUBLIC_NAME,
                SNAPSHOT_NAME,
                AUTHORIZATION_NAME,
                STATE_NAME,
            ],
            "operator_only": [],
            "state_bootstrap_requires_private_writable_runtime_copy": True,
            "private_authority_included": False,
        },
        "claim_boundary": {
            "establishes": (
                "source-bound local administrative inputs for the existing M5 "
                "pre-authorization gate"
            ),
            "does_not_establish": [
                "live compromise detection",
                "automatic health assessment",
                "continuous five-second snapshot refresh",
                "deployment or runtime activation",
                "plant-effect authorization",
                "mission completion or continuity",
                "independent validation",
                "operational effectiveness",
            ],
        },
    }
    return materials, manifest


def _verify_bundle_directory(
    directory: Path,
    *,
    expected_source_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not directory.is_absolute():
        raise M5ArtifactError("M5 runtime bundle path must be absolute")
    _reject_symlink_components(directory)
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise M5ArtifactError("M5 runtime bundle is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != _current_uid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or {item.name for item in directory.iterdir()} != BUNDLE_FILES
    ):
        raise M5ArtifactError("M5 runtime bundle is not an exact owned mode-0700 package")
    materials = {name: _read_directory_artifact(directory, name) for name in BUNDLE_FILES}
    if len(materials[AUTHORITY_PUBLIC_NAME]) != 32:
        raise M5ArtifactError("M5 runtime authority public key must be 32 raw bytes")
    manifest = _load_json(materials[MANIFEST_NAME], label=MANIFEST_NAME)
    if set(manifest) != {
        "schema_version",
        "source_binding",
        "authority",
        "scenario",
        "snapshot_signature_binding",
        "snapshot_freshness_contract",
        "lease",
        "reversal_contract",
        "runtime_environment_contract",
        "files",
        "distribution_boundary",
        "claim_boundary",
    } or manifest.get("schema_version") != BUNDLE_SCHEMA:
        raise M5ArtifactError("M5 runtime manifest fields or schema are not exact")
    source_binding = manifest.get("source_binding")
    if not isinstance(source_binding, dict):
        raise M5ArtifactError("M5 runtime manifest lacks an exact source binding")
    _validate_source_binding(source_binding)
    if expected_source_binding is not None and source_binding != dict(expected_source_binding):
        raise M5ArtifactError("M5 runtime bundle source binding differs from the checkout")

    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != BUNDLE_FILES - {MANIFEST_NAME}:
        raise M5ArtifactError("M5 runtime bundle file inventory is incomplete")
    for name, record in files.items():
        if not isinstance(record, dict) or set(record) != {"size_bytes", "sha256", "purpose"}:
            raise M5ArtifactError("M5 runtime artifact descriptor fields are not exact")
        material = materials[name]
        if (
            record.get("size_bytes") != len(material)
            or record.get("sha256") != _sha256(material)
            or not isinstance(record.get("purpose"), str)
            or not record["purpose"]
        ):
            raise M5ArtifactError(f"M5 runtime artifact descriptor is invalid: {name}")

    try:
        public_key = Ed25519PublicKey.from_public_bytes(materials[AUTHORITY_PUBLIC_NAME])
        snapshot = DegradedRuntimeSnapshot.model_validate(
            _load_json(materials[SNAPSHOT_NAME], label=SNAPSHOT_NAME)
        )
        authorization = DegradedModeAuthorization.model_validate(
            _load_json(materials[AUTHORIZATION_NAME], label=AUTHORIZATION_NAME)
        )
        state = DegradedOperationState.model_validate(
            _load_json(materials[STATE_NAME], label=STATE_NAME)
        )
    except (TypeError, ValueError) as exc:
        raise M5ArtifactError("M5 runtime input model validation failed") from exc
    authority = manifest.get("authority")
    if not isinstance(authority, dict) or authority != {
        "authority_id": authorization.authority_id,
        "algorithm": "Ed25519",
        "key_id": _sha256(materials[AUTHORITY_PUBLIC_NAME]),
        "private_key_included": False,
    }:
        raise M5ArtifactError("M5 runtime authority metadata is inconsistent")
    if (
        not authorization.signature
        or not verify_bytes(
            public_key,
            authorization.signing_payload(),
            authorization.signature,
        )
    ):
        raise M5ArtifactError("M5 runtime administrative signature verification failed")
    if authorization.snapshot_sha256 != snapshot.digest:
        raise M5ArtifactError("M5 signed lease does not bind the exact runtime snapshot")
    if authorization.affected_roles != snapshot.affected_roles or not snapshot.affected_roles:
        raise M5ArtifactError("M5 lease and runtime snapshot affected roles disagree")
    expected_behavior = _effective_behavior(snapshot.affected_roles)
    if authorization.behavior is not expected_behavior:
        raise M5ArtifactError("M5 lease behavior does not match the fail-closed role matrix")
    if authorization.expires_at - authorization.issued_at > timedelta(
        seconds=MAX_LEASE_SECONDS
    ):
        raise M5ArtifactError("M5 lease exceeds the bounded runtime lifetime")
    if state != DegradedOperationState.initial(authorization.authority_id):
        raise M5ArtifactError("M5 runtime state bootstrap is not the exact initial state")
    scenario = manifest.get("scenario")
    if not isinstance(scenario, dict) or scenario != {
        "role": next(iter(snapshot.affected_roles)).value,
        "surface": scenario.get("surface"),
        "condition": scenario.get("condition"),
        "behavior": expected_behavior.value,
        "unresolved_effect": snapshot.unresolved_effect,
        "operator_asserted_not_detected": True,
    }:
        raise M5ArtifactError("M5 runtime scenario metadata is inconsistent")
    role = next(iter(snapshot.affected_roles))
    surface = scenario.get("surface")
    condition_value = scenario.get("condition")
    if surface not in {"service", "communication"} or not isinstance(
        condition_value, str
    ):
        raise M5ArtifactError("M5 runtime scenario surface or condition is invalid")
    try:
        condition = RoleCondition(condition_value)
    except ValueError as exc:
        raise M5ArtifactError("M5 runtime scenario condition is unknown") from exc
    if condition is RoleCondition.HEALTHY:
        raise M5ArtifactError("M5 runtime scenario cannot encode a healthy condition")
    expected_service = condition if surface == "service" else RoleCondition.HEALTHY
    expected_communication = (
        condition if surface == "communication" else RoleCondition.HEALTHY
    )
    if (
        snapshot.role_conditions[role] is not expected_service
        or snapshot.communication_conditions[role] is not expected_communication
        or any(
            item is not role
            and (
                snapshot.role_conditions[item] is not RoleCondition.HEALTHY
                or snapshot.communication_conditions[item] is not RoleCondition.HEALTHY
            )
            for item in DegradedRole
        )
    ):
        raise M5ArtifactError("M5 runtime snapshot exceeds the declared single-fault scope")
    binding = manifest.get("snapshot_signature_binding")
    if not isinstance(binding, dict) or binding != {
        "mechanism": "signed_authorization_snapshot_sha256",
        "snapshot_sha256": snapshot.digest,
        "authorization_sha256": authorization.digest,
        "authorization_signature_verified_before_publication": True,
        "independent_snapshot_signature": False,
    }:
        raise M5ArtifactError("M5 signed snapshot binding metadata is inconsistent")
    freshness = manifest.get("snapshot_freshness_contract")
    if freshness != {
        "maximum_age_seconds": MAX_SNAPSHOT_AGE_SECONDS,
        "single_generation_artifact": True,
        "continuous_refresh_provided": False,
        "stale_snapshot_fails_closed": True,
        "external_trusted_monitor_required": True,
        "operator_assertion_is_not_compromise_detection": True,
    }:
        raise M5ArtifactError("M5 snapshot freshness contract is inconsistent")
    lease = manifest.get("lease")
    if lease != {
        "authorization_id": authorization.authorization_id,
        "sequence": authorization.sequence,
        "issued_at": authorization.issued_at.isoformat(),
        "expires_at": authorization.expires_at.isoformat(),
        "maximum_lifetime_seconds": MAX_LEASE_SECONDS,
        "execution_authorized": False,
    }:
        raise M5ArtifactError("M5 lease metadata is inconsistent")
    if manifest.get("reversal_contract") != {
        "separate_operator_package_required": True,
        "runtime_bundle_contains_reversal": False,
        "create_command": "prepare_m5_degraded_artifacts.py reversal",
    }:
        raise M5ArtifactError("M5 reversal separation contract is inconsistent")
    environment = manifest.get("runtime_environment_contract")
    if environment != {
        "AEGIS_M5_DEGRADED_AUTHORITY_ID": authorization.authority_id,
        "AEGIS_M5_DEGRADED_AUTHORITY_PUBLIC_KEY_FILE": AUTHORITY_PUBLIC_NAME,
        "AEGIS_M5_DEGRADED_SNAPSHOT_FILE": SNAPSHOT_NAME,
        "AEGIS_M5_DEGRADED_AUTHORIZATION_FILE": AUTHORIZATION_NAME,
        "AEGIS_M5_DEGRADED_STATE_FILE": STATE_NAME,
    }:
        raise M5ArtifactError("M5 runtime environment contract is inconsistent")
    boundary = manifest.get("distribution_boundary")
    if boundary != {
        "runtime_inputs": [
            AUTHORITY_PUBLIC_NAME,
            SNAPSHOT_NAME,
            AUTHORIZATION_NAME,
            STATE_NAME,
        ],
        "operator_only": [],
        "state_bootstrap_requires_private_writable_runtime_copy": True,
        "private_authority_included": False,
    }:
        raise M5ArtifactError("M5 runtime distribution boundary is inconsistent")
    return {
        "valid": True,
        "schema_version": BUNDLE_SCHEMA,
        "source_git_commit": source_binding["git_commit"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
        "authority_id": authorization.authority_id,
        "authority_key_id": _sha256(materials[AUTHORITY_PUBLIC_NAME]),
        "snapshot_sha256": snapshot.digest,
        "authorization_sha256": authorization.digest,
        "behavior": authorization.behavior.value,
        "execution_authorized": False,
        "private_authority_included": False,
        "single_generation_artifact": True,
        "continuous_refresh_provided": False,
    }


def create_runtime_bundle(
    output: Path,
    *,
    authority_directory: Path,
    role: DegradedRole,
    surface: str,
    condition: RoleCondition,
    actor_id: str,
    mission_id: str,
    resource: str,
    operation: Operation,
    maximum_risk_score: float,
    lease_seconds: int = 300,
    sequence: int = 1,
    source_reference: str = "HEAD",
    now: datetime | None = None,
    unresolved_effect: bool = False,
) -> dict[str, Any]:
    """Atomically publish one single-fault M5 runtime-input package."""

    source_binding = _assert_clean_source(source_reference)
    authority, private_key, public_material = _load_authority(authority_directory)
    authority_id = authority.get("authority_id")
    if not isinstance(authority_id, str):
        raise M5ArtifactError("M5 authority metadata lacks its identifier")
    materials, manifest = _bundle_material(
        authority_id=authority_id,
        private_key=private_key,
        public_material=public_material,
        source_binding=source_binding,
        role=role,
        surface=surface,
        condition=condition,
        actor_id=actor_id,
        mission_id=mission_id,
        resource=resource,
        operation=operation,
        maximum_risk_score=maximum_risk_score,
        lease_seconds=lease_seconds,
        sequence=sequence,
        now=datetime.now(UTC) if now is None else now,
        unresolved_effect=unresolved_effect,
    )
    destination, parent_fd = _open_safe_parent(output)
    authority_path = authority_directory.resolve(strict=True)
    if destination == authority_path or destination.is_relative_to(authority_path):
        os.close(parent_fd)
        raise M5ArtifactError("M5 runtime bundle must be separate from its authority")
    staging_name = ""
    staging_fd: int | None = None
    published = False
    try:
        staging_name, staging_fd = _staging_directory(parent_fd)
        for name, material in materials.items():
            _write_file(staging_fd, name, material)
        _write_file(staging_fd, MANIFEST_NAME, _canonical_bytes(manifest))
        os.fsync(staging_fd)
        staging_path = destination.with_name(staging_name)
        _verify_bundle_directory(
            staging_path,
            expected_source_binding=source_binding,
        )
        _publish_directory_noreplace(staging_path, destination)
        published = True
        os.fsync(parent_fd)
        return _verify_bundle_directory(
            destination,
            expected_source_binding=source_binding,
        )
    finally:
        if not published and staging_name:
            _cleanup_staging(parent_fd, staging_fd, staging_name)
        if staging_fd is not None:
            os.close(staging_fd)
        os.close(parent_fd)


def verify_runtime_bundle(
    directory: Path,
    *,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Verify bundle integrity, signatures, semantics, and exact source binding."""

    source_binding = _assert_clean_source(source_reference)
    return _verify_bundle_directory(
        directory.resolve(strict=True),
        expected_source_binding=source_binding,
    )


def _reversal_material(
    *,
    authority_id: str,
    private_key: Ed25519PrivateKey,
    public_material: bytes,
    authorization: DegradedModeAuthorization,
    snapshot_sha256: str,
    source_binding: Mapping[str, Any],
    sequence: int,
    reason_code: str,
    issued_at: datetime,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    if type(sequence) is not int or sequence < 1:
        raise M5ArtifactError("M5 reversal sequence must be a positive integer")
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise M5ArtifactError("M5 reversal time must be timezone-aware")
    issued_at = issued_at.astimezone(UTC)
    if issued_at < authorization.issued_at or issued_at > authorization.expires_at:
        raise M5ArtifactError("M5 reversal must be issued during the signed lease lifetime")
    try:
        reversal = DegradedModeReversal(
            reversal_id=f"m5-degraded-reversal-{secrets.token_hex(16)}",
            sequence=sequence,
            authority_id=authority_id,
            authorization_id=authorization.authorization_id,
            authorization_sha256=authorization.digest,
            recovery_checkpoint_id=authorization.recovery_checkpoint_id,
            reason_code=reason_code,
            nonce=f"m5-degraded-reversal-nonce-{secrets.token_hex(16)}",
            issued_at=issued_at,
        ).signed(private_key)
    except ValueError as exc:
        raise M5ArtifactError("M5 reversal fields are noncanonical") from exc
    reversal_material = _canonical_bytes(reversal.model_dump(mode="json"))
    materials = {REVERSAL_NAME: reversal_material}
    manifest: dict[str, Any] = {
        "schema_version": REVERSAL_PACKAGE_SCHEMA,
        "source_binding": dict(source_binding),
        "authority": {
            "authority_id": authority_id,
            "algorithm": "Ed25519",
            "key_id": _sha256(public_material),
            "private_key_included": False,
        },
        "runtime_bundle_binding": {
            "schema_version": BUNDLE_SCHEMA,
            "authorization_sha256": authorization.digest,
            "snapshot_sha256": snapshot_sha256,
            "source_fingerprint_sha256": source_binding[
                "source_fingerprint_sha256"
            ],
        },
        "reversal": {
            "reversal_id": reversal.reversal_id,
            "sequence": reversal.sequence,
            "issued_at": reversal.issued_at.isoformat(),
            "reason_code": reversal.reason_code,
            "maximum_runtime_application_age_seconds": MAX_LEASE_SECONDS,
            "operator_application_required": True,
            "mounted_as_runtime_input": False,
        },
        "files": {
            REVERSAL_NAME: _artifact_record(
                reversal_material,
                purpose="operator_applied_exact_lease_reversal",
            )
        },
        "distribution_boundary": {
            "operator_only": [REVERSAL_NAME],
            "runtime_inputs": [],
            "private_authority_included": False,
            "application_requires_operator_workflow": True,
        },
        "claim_boundary": {
            "establishes": "source-bound signed direction to revoke one exact M5 lease",
            "does_not_establish": [
                "reversal application",
                "live recovery detection",
                "runtime deployment",
                "plant state change",
                "mission continuity",
                "independent validation",
                "operational effectiveness",
            ],
        },
    }
    return materials, manifest


def _verify_reversal_directory(
    directory: Path,
    *,
    runtime_bundle: Path,
    expected_source_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not directory.is_absolute():
        raise M5ArtifactError("M5 reversal package path must be absolute")
    _reject_symlink_components(directory)
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise M5ArtifactError("M5 reversal package is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != _current_uid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or {item.name for item in directory.iterdir()} != REVERSAL_PACKAGE_FILES
    ):
        raise M5ArtifactError(
            "M5 reversal package is not an exact owned mode-0700 package"
        )
    materials = {
        name: _read_directory_artifact(directory, name)
        for name in REVERSAL_PACKAGE_FILES
    }
    manifest = _load_json(materials[MANIFEST_NAME], label=MANIFEST_NAME)
    if set(manifest) != {
        "schema_version",
        "source_binding",
        "authority",
        "runtime_bundle_binding",
        "reversal",
        "files",
        "distribution_boundary",
        "claim_boundary",
    } or manifest.get("schema_version") != REVERSAL_PACKAGE_SCHEMA:
        raise M5ArtifactError("M5 reversal manifest fields or schema are not exact")
    source_binding = manifest.get("source_binding")
    if not isinstance(source_binding, dict):
        raise M5ArtifactError("M5 reversal manifest lacks an exact source binding")
    _validate_source_binding(source_binding)
    if expected_source_binding is not None and source_binding != dict(
        expected_source_binding
    ):
        raise M5ArtifactError("M5 reversal source binding differs from the checkout")

    runtime_bundle = runtime_bundle.resolve(strict=True)
    bundle_report = _verify_bundle_directory(
        runtime_bundle,
        expected_source_binding=source_binding,
    )
    public_material = _read_directory_artifact(runtime_bundle, AUTHORITY_PUBLIC_NAME)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_material)
        authorization = DegradedModeAuthorization.model_validate(
            _load_json(
                _read_directory_artifact(runtime_bundle, AUTHORIZATION_NAME),
                label=AUTHORIZATION_NAME,
            )
        )
        reversal = DegradedModeReversal.model_validate(
            _load_json(materials[REVERSAL_NAME], label=REVERSAL_NAME)
        )
    except (TypeError, ValueError) as exc:
        raise M5ArtifactError("M5 reversal input model validation failed") from exc
    if not reversal.signature or not verify_bytes(
        public_key,
        reversal.signing_payload(),
        reversal.signature,
    ):
        raise M5ArtifactError("M5 reversal signature verification failed")
    if (
        reversal.authority_id != authorization.authority_id
        or reversal.authorization_id != authorization.authorization_id
        or reversal.authorization_sha256 != authorization.digest
        or reversal.recovery_checkpoint_id != authorization.recovery_checkpoint_id
        or reversal.issued_at < authorization.issued_at
        or reversal.issued_at > authorization.expires_at
    ):
        raise M5ArtifactError("M5 reversal does not bind the exact live signed lease")

    files = manifest.get("files")
    expected_files = {
        REVERSAL_NAME: _artifact_record(
            materials[REVERSAL_NAME],
            purpose="operator_applied_exact_lease_reversal",
        )
    }
    if files != expected_files:
        raise M5ArtifactError("M5 reversal artifact inventory is inconsistent")
    if manifest.get("authority") != {
        "authority_id": authorization.authority_id,
        "algorithm": "Ed25519",
        "key_id": _sha256(public_material),
        "private_key_included": False,
    }:
        raise M5ArtifactError("M5 reversal authority metadata is inconsistent")
    if manifest.get("runtime_bundle_binding") != {
        "schema_version": BUNDLE_SCHEMA,
        "authorization_sha256": authorization.digest,
        "snapshot_sha256": bundle_report["snapshot_sha256"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
    }:
        raise M5ArtifactError("M5 reversal runtime bundle binding is inconsistent")
    if manifest.get("reversal") != {
        "reversal_id": reversal.reversal_id,
        "sequence": reversal.sequence,
        "issued_at": reversal.issued_at.isoformat(),
        "reason_code": reversal.reason_code,
        "maximum_runtime_application_age_seconds": MAX_LEASE_SECONDS,
        "operator_application_required": True,
        "mounted_as_runtime_input": False,
    }:
        raise M5ArtifactError("M5 reversal metadata is inconsistent")
    if manifest.get("distribution_boundary") != {
        "operator_only": [REVERSAL_NAME],
        "runtime_inputs": [],
        "private_authority_included": False,
        "application_requires_operator_workflow": True,
    }:
        raise M5ArtifactError("M5 reversal distribution boundary is inconsistent")
    return {
        "valid": True,
        "schema_version": REVERSAL_PACKAGE_SCHEMA,
        "source_git_commit": source_binding["git_commit"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
        "authority_id": reversal.authority_id,
        "authority_key_id": _sha256(public_material),
        "authorization_sha256": authorization.digest,
        "reversal_sha256": reversal.digest,
        "operator_application_required": True,
        "runtime_application_time_evaluated": False,
        "private_authority_included": False,
    }


def create_reversal_package(
    output: Path,
    *,
    authority_directory: Path,
    runtime_bundle: Path,
    sequence: int = 1,
    reason_code: str = "runtime_dependencies_recovered",
    source_reference: str = "HEAD",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Atomically publish an operator-only reversal for one runtime lease."""

    source_binding = _assert_clean_source(source_reference)
    authority, private_key, public_material = _load_authority(authority_directory)
    runtime_bundle = runtime_bundle.resolve(strict=True)
    bundle_report = _verify_bundle_directory(
        runtime_bundle,
        expected_source_binding=source_binding,
    )
    if _read_directory_artifact(runtime_bundle, AUTHORITY_PUBLIC_NAME) != public_material:
        raise M5ArtifactError("M5 authority does not match the runtime bundle authority")
    authorization = DegradedModeAuthorization.model_validate(
        _load_json(
            _read_directory_artifact(runtime_bundle, AUTHORIZATION_NAME),
            label=AUTHORIZATION_NAME,
        )
    )
    authority_id = authority.get("authority_id")
    if authority_id != authorization.authority_id:
        raise M5ArtifactError("M5 authority identifier does not match the runtime lease")
    materials, manifest = _reversal_material(
        authority_id=authorization.authority_id,
        private_key=private_key,
        public_material=public_material,
        authorization=authorization,
        snapshot_sha256=bundle_report["snapshot_sha256"],
        source_binding=source_binding,
        sequence=sequence,
        reason_code=reason_code,
        issued_at=datetime.now(UTC) if now is None else now,
    )
    destination, parent_fd = _open_safe_parent(output)
    authority_path = authority_directory.resolve(strict=True)
    if (
        destination == authority_path
        or destination.is_relative_to(authority_path)
        or destination == runtime_bundle
        or destination.is_relative_to(runtime_bundle)
    ):
        os.close(parent_fd)
        raise M5ArtifactError(
            "M5 reversal package must be separate from authority and runtime inputs"
        )
    staging_name = ""
    staging_fd: int | None = None
    published = False
    try:
        staging_name, staging_fd = _staging_directory(parent_fd)
        for name, material in materials.items():
            _write_file(staging_fd, name, material)
        _write_file(staging_fd, MANIFEST_NAME, _canonical_bytes(manifest))
        os.fsync(staging_fd)
        staging_path = destination.with_name(staging_name)
        _verify_reversal_directory(
            staging_path,
            runtime_bundle=runtime_bundle,
            expected_source_binding=source_binding,
        )
        _publish_directory_noreplace(staging_path, destination)
        published = True
        os.fsync(parent_fd)
        return _verify_reversal_directory(
            destination,
            runtime_bundle=runtime_bundle,
            expected_source_binding=source_binding,
        )
    finally:
        if not published and staging_name:
            _cleanup_staging(parent_fd, staging_fd, staging_name)
        if staging_fd is not None:
            os.close(staging_fd)
        os.close(parent_fd)


def verify_reversal_package(
    directory: Path,
    *,
    runtime_bundle: Path,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Verify an operator reversal against its exact runtime bundle and source."""

    source_binding = _assert_clean_source(source_reference)
    return _verify_reversal_directory(
        directory.resolve(strict=True),
        runtime_bundle=runtime_bundle.resolve(strict=True),
        expected_source_binding=source_binding,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    authority = commands.add_parser(
        "authority", help="create a private external M5 administrative authority"
    )
    authority.add_argument("--output", type=Path, required=True)
    authority.add_argument("--authority-id", required=True)
    authority.add_argument("--source-commit", default="HEAD")

    bundle = commands.add_parser(
        "bundle", help="create a public-key-only source-bound M5 runtime bundle"
    )
    bundle.add_argument("--output", type=Path, required=True)
    bundle.add_argument("--authority-directory", type=Path, required=True)
    bundle.add_argument("--role", choices=[item.value for item in DegradedRole], required=True)
    bundle.add_argument("--surface", choices=("service", "communication"), required=True)
    bundle.add_argument(
        "--condition",
        choices=[item.value for item in RoleCondition if item is not RoleCondition.HEALTHY],
        required=True,
    )
    bundle.add_argument("--actor-id", default="agent:operator-1")
    bundle.add_argument("--mission-id", default="microgrid-containment")
    bundle.add_argument("--resource", default="feeder-1")
    bundle.add_argument(
        "--operation",
        choices=[item.value for item in Operation],
        default=Operation.ISOLATE_ASSET.value,
    )
    bundle.add_argument("--maximum-risk-score", type=float, default=65.0)
    bundle.add_argument("--lease-seconds", type=int, default=300)
    bundle.add_argument("--sequence", type=int, default=1)
    bundle.add_argument("--source-commit", default="HEAD")
    bundle.add_argument("--unresolved-effect", action="store_true")

    verify = commands.add_parser("verify", help="verify an M5 runtime bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--source-commit", default="HEAD")

    reversal = commands.add_parser(
        "reversal", help="create a separate operator-only lease reversal package"
    )
    reversal.add_argument("--output", type=Path, required=True)
    reversal.add_argument("--authority-directory", type=Path, required=True)
    reversal.add_argument("--runtime-bundle", type=Path, required=True)
    reversal.add_argument("--sequence", type=int, default=1)
    reversal.add_argument(
        "--reason-code", default="runtime_dependencies_recovered"
    )
    reversal.add_argument("--source-commit", default="HEAD")

    verify_reversal = commands.add_parser(
        "verify-reversal", help="verify an operator reversal package"
    )
    verify_reversal.add_argument("--package", type=Path, required=True)
    verify_reversal.add_argument("--runtime-bundle", type=Path, required=True)
    verify_reversal.add_argument("--source-commit", default="HEAD")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "authority":
            result = create_authority(
                arguments.output,
                authority_id=arguments.authority_id,
                source_reference=arguments.source_commit,
            )
            public = result["files"][AUTHORITY_PUBLIC_NAME]
            report = {
                "schema_version": result["schema_version"],
                "output_directory": str(arguments.output),
                "authority_id": result["authority_id"],
                "authority_key_id": result["key_id"],
                "public_key_sha256": public["sha256"],
                "source_git_commit": result["source_binding"]["git_commit"],
                "secret_material_printed": False,
                "claim_boundary": result["claim_boundary"],
            }
        elif arguments.command == "bundle":
            report = create_runtime_bundle(
                arguments.output,
                authority_directory=arguments.authority_directory,
                role=DegradedRole(arguments.role),
                surface=arguments.surface,
                condition=RoleCondition(arguments.condition),
                actor_id=arguments.actor_id,
                mission_id=arguments.mission_id,
                resource=arguments.resource,
                operation=Operation(arguments.operation),
                maximum_risk_score=arguments.maximum_risk_score,
                lease_seconds=arguments.lease_seconds,
                sequence=arguments.sequence,
                source_reference=arguments.source_commit,
                unresolved_effect=arguments.unresolved_effect,
            )
            report = {
                **report,
                "output_directory": str(arguments.output),
                "secret_material_printed": False,
            }
        elif arguments.command == "verify":
            report = verify_runtime_bundle(
                arguments.bundle,
                source_reference=arguments.source_commit,
            )
        elif arguments.command == "reversal":
            report = create_reversal_package(
                arguments.output,
                authority_directory=arguments.authority_directory,
                runtime_bundle=arguments.runtime_bundle,
                sequence=arguments.sequence,
                reason_code=arguments.reason_code,
                source_reference=arguments.source_commit,
            )
            report = {
                **report,
                "output_directory": str(arguments.output),
                "secret_material_printed": False,
            }
        else:
            report = verify_reversal_package(
                arguments.package,
                runtime_bundle=arguments.runtime_bundle,
                source_reference=arguments.source_commit,
            )
    except (M5ArtifactError, OSError, ValueError) as exc:
        print(f"M5 degraded artifact error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
