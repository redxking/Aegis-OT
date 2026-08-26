#!/usr/bin/env python3
"""Provision source-bound M5 continuous-publication trust material.

This v2 tool creates deliberately separate trust and runtime-input packages:

* ``authority`` retains the operator root private key and the publisher leaf
  private key under administrative custody;
* ``runtime`` contains only public trust material plus the stable, scoped
  degraded-mode authorization consumed by the gateway;
* ``publisher`` contains the publisher leaf private key, its root-signed
  credential, the root public key, the status input, and the exact stable
  authorization; and
* ``reversal`` contains one root-signed direction bound to the exact stable
  authorization and recovery checkpoint; and
* ``healthy-status`` contains a fresh, complete recovery assertion generated
  from public runtime trust without exposing either private key.

Every command publishes one new private directory atomically and refuses to
replace an existing path.  Runtime packages contain no private key and no
mutable replay/high-watermark state.  Publisher packages contain no operator
root private key.  The generated status is an operator-provided lab input; it
is not automatic health assessment or compromise detection.
"""

from __future__ import annotations

import argparse
import base64
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
from collections.abc import Callable, Mapping, Sequence
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
    DegradedModeReversal,
    DegradedRole,
    RoleCondition,
)
from aegis_ot.m5_degraded_publication import (
    MAX_PUBLICATION_AGE_SECONDS as CORE_MAX_PUBLICATION_AGE_SECONDS,
)
from aegis_ot.m5_degraded_publication import (
    MAX_STABLE_AUTHORIZATION_SECONDS,
    MAX_STATUS_INPUT_AGE_SECONDS,
    DegradedPublisherCredential,
    DegradedStatusInput,
    StableDegradedAuthorization,
    degraded_role_policy_sha256,
)
from aegis_ot.models import Operation

ROOT = Path(__file__).resolve().parents[1]

AUTHORITY_SCHEMA: Final[str] = "aegis-ot-m5-degraded-publication-authority-v2"
RUNTIME_SCHEMA: Final[str] = "aegis-ot-m5-degraded-publication-runtime-v2"
PUBLISHER_SCHEMA: Final[str] = "aegis-ot-m5-degraded-publication-publisher-v2"
REVERSAL_SCHEMA: Final[str] = "aegis-ot-m5-degraded-publication-reversal-v2"
HEALTHY_STATUS_SCHEMA: Final[str] = "aegis-ot-m5-degraded-healthy-status-v1"

MANIFEST_NAME: Final[str] = "manifest.json"
ROOT_PRIVATE_NAME: Final[str] = "operator-authority.private"
ROOT_PUBLIC_NAME: Final[str] = "operator-authority.public"
PUBLISHER_PRIVATE_NAME: Final[str] = "publisher.private"
PUBLISHER_CREDENTIAL_NAME: Final[str] = "publisher-credential.json"
STABLE_AUTHORIZATION_NAME: Final[str] = "stable-authorization.json"
STATUS_INPUT_NAME: Final[str] = "status-input.json"
REVERSAL_NAME: Final[str] = "degraded-reversal.json"

AUTHORITY_FILES: Final[frozenset[str]] = frozenset(
    {
        ROOT_PRIVATE_NAME,
        ROOT_PUBLIC_NAME,
        PUBLISHER_PRIVATE_NAME,
        PUBLISHER_CREDENTIAL_NAME,
        STABLE_AUTHORIZATION_NAME,
        STATUS_INPUT_NAME,
        MANIFEST_NAME,
    }
)
RUNTIME_FILES: Final[frozenset[str]] = frozenset(
    {
        ROOT_PUBLIC_NAME,
        PUBLISHER_CREDENTIAL_NAME,
        STABLE_AUTHORIZATION_NAME,
        MANIFEST_NAME,
    }
)
PUBLISHER_FILES: Final[frozenset[str]] = frozenset(
    {
        ROOT_PUBLIC_NAME,
        PUBLISHER_PRIVATE_NAME,
        PUBLISHER_CREDENTIAL_NAME,
        STABLE_AUTHORIZATION_NAME,
        STATUS_INPUT_NAME,
        MANIFEST_NAME,
    }
)
REVERSAL_FILES: Final[frozenset[str]] = frozenset({REVERSAL_NAME, MANIFEST_NAME})
HEALTHY_STATUS_FILES: Final[frozenset[str]] = frozenset(
    {STATUS_INPUT_NAME, MANIFEST_NAME}
)

AUTHORITY_PURPOSES: Final[dict[str, tuple[str, str]]] = {
    ROOT_PRIVATE_NAME: (
        "sign publisher credentials authorizations and exact reversals",
        "operator_only_never_runtime_or_publisher",
    ),
    ROOT_PUBLIC_NAME: (
        "verify root-signed publication trust material",
        "runtime_and_publisher",
    ),
    PUBLISHER_PRIVATE_NAME: (
        "sign continuously refreshed runtime publications",
        "publisher_only_never_runtime",
    ),
    PUBLISHER_CREDENTIAL_NAME: (
        "bind publisher leaf identity and health source to the root",
        "runtime_and_publisher",
    ),
    STABLE_AUTHORIZATION_NAME: (
        "authorize one bounded degraded condition and proposal scope",
        "runtime_and_publisher",
    ),
    STATUS_INPUT_NAME: (
        "operator-provided complete role and communication status",
        "publisher_only_never_runtime",
    ),
}
RUNTIME_PURPOSES: Final[dict[str, tuple[str, str]]] = {
    ROOT_PUBLIC_NAME: AUTHORITY_PURPOSES[ROOT_PUBLIC_NAME],
    PUBLISHER_CREDENTIAL_NAME: AUTHORITY_PURPOSES[PUBLISHER_CREDENTIAL_NAME],
    STABLE_AUTHORIZATION_NAME: AUTHORITY_PURPOSES[STABLE_AUTHORIZATION_NAME],
}
PUBLISHER_PURPOSES: Final[dict[str, tuple[str, str]]] = {
    ROOT_PUBLIC_NAME: AUTHORITY_PURPOSES[ROOT_PUBLIC_NAME],
    PUBLISHER_PRIVATE_NAME: AUTHORITY_PURPOSES[PUBLISHER_PRIVATE_NAME],
    PUBLISHER_CREDENTIAL_NAME: AUTHORITY_PURPOSES[PUBLISHER_CREDENTIAL_NAME],
    STABLE_AUTHORIZATION_NAME: AUTHORITY_PURPOSES[STABLE_AUTHORIZATION_NAME],
    STATUS_INPUT_NAME: AUTHORITY_PURPOSES[STATUS_INPUT_NAME],
}
REVERSAL_PURPOSES: Final[dict[str, tuple[str, str]]] = {
    REVERSAL_NAME: (
        "revoke one exact stable degraded authorization",
        "operator_to_runtime_reversal_inbox",
    )
}
HEALTHY_STATUS_PURPOSES: Final[dict[str, tuple[str, str]]] = {
    STATUS_INPUT_NAME: (
        "assert fresh complete recovery of configured role and communication status",
        "operator_to_publisher_status_inbox",
    )
}

MAX_ARTIFACT_BYTES: Final[int] = 1024 * 1024
MAX_CREDENTIAL_SECONDS: Final[int] = 7 * 24 * 60 * 60
MAX_AUTHORIZATION_SECONDS: Final[int] = MAX_STABLE_AUTHORIZATION_SECONDS
MAX_PUBLICATION_AGE_SECONDS: Final[int] = CORE_MAX_PUBLICATION_AGE_SECONDS
DEFAULT_CREDENTIAL_SECONDS: Final[int] = 24 * 60 * 60
DEFAULT_AUTHORIZATION_SECONDS: Final[int] = MAX_STABLE_AUTHORIZATION_SECONDS
DEFAULT_PUBLICATION_AGE_SECONDS: Final[int] = 5
DEFAULT_STATUS_INPUT_AGE_SECONDS: Final[int] = MAX_STATUS_INPUT_AGE_SECONDS
_STAGING_PREFIX: Final[str] = ".m5-degraded-publication-"
_GIT_OBJECT: Final[re.Pattern[str]] = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,255}$")
_CANONICAL_TEXT: Final[re.Pattern[str]] = re.compile(r"^[^\s]{1,256}$")

SOURCE_PATHS: Final[tuple[str, ...]] = (
    "pyproject.toml",
    "scripts/prepare_m5_degraded_publication.py",
    "src/aegis_ot/crypto.py",
    "src/aegis_ot/m5_degraded.py",
    "src/aegis_ot/m5_degraded_publication.py",
    "src/aegis_ot/models.py",
    "src/aegis_ot/segmented_capability_runtime.py",
)


class PublicationArtifactError(RuntimeError):
    """A v2 publication package could not be created or trusted."""


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
        raise PublicationArtifactError(
            "M5 publication material is not canonical finite JSON"
        ) from exc


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _model_bytes(value: Any) -> bytes:
    material = value.model_dump(mode="json")
    if not isinstance(material, dict):
        raise PublicationArtifactError("M5 publication model did not serialize as an object")
    return _canonical_bytes(material)


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


def _public_key_id(material: bytes) -> str:
    if len(material) != 32:
        raise PublicationArtifactError("Ed25519 public key must contain exactly 32 bytes")
    return _sha256(material)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicationArtifactError(f"duplicate M5 publication JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise PublicationArtifactError(f"non-finite M5 publication value is forbidden: {value}")


def _load_json(material: bytes, *, label: str) -> dict[str, Any]:
    if material.startswith(b"\xef\xbb\xbf"):
        raise PublicationArtifactError(f"{label} contains a prohibited UTF-8 BOM")
    try:
        value = json.loads(
            material.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicationArtifactError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise PublicationArtifactError(f"{label} root must be an object")
    if _canonical_bytes(value) != material:
        raise PublicationArtifactError(f"{label} is not canonical JSON")
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
        raise PublicationArtifactError("Git is required for M5 publication source binding")
    completed = subprocess.run(  # noqa: S603 - fixed executable and argument vector
        (executable, "-C", str(ROOT), "--no-replace-objects", *arguments),
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise PublicationArtifactError(f"Git source-binding command failed: {detail[-1000:]}")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise PublicationArtifactError("Git returned non-UTF-8 source metadata") from exc


def _canonical_reference(reference: str) -> str:
    if (
        not reference
        or reference != reference.strip()
        or reference.startswith("-")
        or len(reference) > 512
        or any(character.isspace() or ord(character) < 32 for character in reference)
    ):
        raise PublicationArtifactError("source commit reference is malformed")
    return reference


def _read_source_file(relative: str) -> bytes:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or pure.as_posix() != relative
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise PublicationArtifactError(f"source path is noncanonical: {relative}")
    path = ROOT.joinpath(*pure.parts)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise PublicationArtifactError(f"required source is unavailable: {relative}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or resolved != path
        or not resolved.is_relative_to(ROOT.resolve(strict=True))
    ):
        raise PublicationArtifactError(f"required source is not one exact regular file: {relative}")
    try:
        material = path.read_bytes()
    except OSError as exc:
        raise PublicationArtifactError(f"required source could not be read: {relative}") from exc
    if not material or len(material) > MAX_ARTIFACT_BYTES * 16:
        raise PublicationArtifactError(f"required source size is outside the bound: {relative}")
    return material


def _assert_clean_source(reference: str) -> dict[str, Any]:
    """Bind generation to the exact clean checked-out commit."""

    reference = _canonical_reference(reference)
    try:
        imported = Path(__file__).resolve(strict=True)
        expected = (ROOT / SOURCE_PATHS[1]).resolve(strict=True)
    except OSError as exc:
        raise PublicationArtifactError("M5 publication generator source is unavailable") from exc
    if imported != expected:
        raise PublicationArtifactError("M5 publication generator was imported from stale source")
    if _git("rev-parse", "--show-toplevel") != str(ROOT.resolve(strict=True)):
        raise PublicationArtifactError("generator is not in the authoritative checkout")
    if _git("status", "--porcelain=v1", "-z", "--untracked-files=all", binary=True):
        raise PublicationArtifactError("generation requires an exact clean checkout")
    head = _git("rev-parse", "--verify", "HEAD^{commit}")
    commit = _git("rev-parse", "--verify", f"{reference}^{{commit}}")
    if (
        not isinstance(head, str)
        or not isinstance(commit, str)
        or not _GIT_OBJECT.fullmatch(head)
        or commit != head
    ):
        raise PublicationArtifactError(
            "source reference must resolve to the exact checked-out HEAD"
        )
    tree = _git("rev-parse", "--verify", f"{commit}^{{tree}}")
    if not isinstance(tree, str) or not _GIT_OBJECT.fullmatch(tree):
        raise PublicationArtifactError("source tree identifier is noncanonical")

    bindings: list[dict[str, Any]] = []
    for relative in SOURCE_PATHS:
        working = _read_source_file(relative)
        retained = _git("show", f"{commit}:{relative}", binary=True)
        if not isinstance(retained, bytes) or retained != working:
            raise PublicationArtifactError(f"required source differs from commit: {relative}")
        record = _git("ls-tree", commit, "--", relative)
        if not isinstance(record, str):
            raise PublicationArtifactError("Git tree record returned an invalid type")
        try:
            header, retained_path = record.split("\t", 1)
            mode, object_type, object_id = header.split(" ")
        except ValueError as exc:
            raise PublicationArtifactError(
                f"Git returned a malformed source entry: {relative}"
            ) from exc
        if (
            retained_path != relative
            or object_type != "blob"
            or mode not in {"100644", "100755"}
            or not _GIT_OBJECT.fullmatch(object_id)
        ):
            raise PublicationArtifactError(f"Git source entry is noncanonical: {relative}")
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
        raise PublicationArtifactError("source-binding fields are not exact")
    if binding.get("clean_checkout") is not True:
        raise PublicationArtifactError("source binding is not a clean checkout")
    commit = binding.get("git_commit")
    tree = binding.get("git_tree")
    if not isinstance(commit, str) or not _GIT_OBJECT.fullmatch(commit):
        raise PublicationArtifactError("source commit is noncanonical")
    if not isinstance(tree, str) or not _GIT_OBJECT.fullmatch(tree):
        raise PublicationArtifactError("source tree is noncanonical")
    files = binding.get("source_files")
    if not isinstance(files, list) or len(files) != len(SOURCE_PATHS):
        raise PublicationArtifactError("source path inventory is incomplete")
    paths: list[str] = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "size_bytes",
            "sha256",
            "git_mode",
            "git_blob",
        }:
            raise PublicationArtifactError("source-file binding fields are not exact")
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
            raise PublicationArtifactError("source-file binding is noncanonical")
    if paths != list(SOURCE_PATHS):
        raise PublicationArtifactError("source path order is not exact")
    material = {"git_commit": commit, "git_tree": tree, "source_files": files}
    if binding.get("source_fingerprint_sha256") != _sha256(_canonical_bytes(material)):
        raise PublicationArtifactError("source fingerprint is invalid")


def _reject_symlink_components(path: Path) -> None:
    if not path.is_absolute():
        raise PublicationArtifactError("artifact path must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if current == path:
                return
            raise PublicationArtifactError("artifact parent is unavailable") from None
        except OSError as exc:
            raise PublicationArtifactError("artifact path could not be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise PublicationArtifactError("artifact path must not contain symlinks")


def _open_safe_parent(output: Path) -> tuple[Path, int]:
    if not output.is_absolute() or output.name in {"", ".", ".."}:
        raise PublicationArtifactError("artifact output must be an absolute named path")
    _reject_symlink_components(output.parent)
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise PublicationArtifactError("artifact parent is unavailable") from exc
    destination = parent / output.name
    try:
        destination.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise PublicationArtifactError("publication artifacts must be outside the checkout")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(parent, flags)
    except OSError as exc:
        raise PublicationArtifactError("artifact parent could not be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != _current_uid():
            raise PublicationArtifactError("artifact parent must be an owned directory")
        if mode & stat.S_IRWXU != stat.S_IRWXU or mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PublicationArtifactError(
                "artifact parent must grant owner rwx and deny group/other writes"
            )
        try:
            os.stat(output.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PublicationArtifactError("refusing to overwrite an M5 publication path")
    except BaseException:
        os.close(descriptor)
        raise
    return destination, descriptor


def _write_file(directory_fd: int, name: str, material: bytes) -> None:
    if not material or len(material) > MAX_ARTIFACT_BYTES:
        raise PublicationArtifactError(f"artifact size is outside the bound: {name}")
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
        raise PublicationArtifactError(f"artifact could not be created: {name}") from exc
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                raise PublicationArtifactError("artifact write made no progress")
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
            raise PublicationArtifactError(f"artifact is not an owned mode-0600 file: {name}")
    finally:
        os.close(descriptor)


def _publish_directory_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing an existing path."""

    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise PublicationArtifactError("atomic no-replace publication is unavailable")
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = int(renamex_np(source_bytes, destination_bytes, 0x00000004))
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise PublicationArtifactError("atomic no-replace publication is unavailable")
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
            raise PublicationArtifactError("refusing to overwrite an M5 publication path") from exc
        except OSError as exc:
            raise PublicationArtifactError("artifact publication failed") from exc
        return
    else:  # pragma: no cover - unknown primitive must fail closed
        raise PublicationArtifactError("atomic no-replace publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise PublicationArtifactError("refusing to overwrite an M5 publication path")
    raise PublicationArtifactError(f"artifact publication failed: {os.strerror(error_number)}")


def _read_private_file(path: Path, *, label: str, exact_size: int | None = None) -> bytes:
    if not path.is_absolute():
        raise PublicationArtifactError(f"{label} path must be absolute")
    _reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublicationArtifactError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != _current_uid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= MAX_ARTIFACT_BYTES
        ):
            raise PublicationArtifactError(f"{label} must be an owned mode-0600 regular file")
        material = os.read(descriptor, MAX_ARTIFACT_BYTES + 1)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or len(material) != before.st_size:
            raise PublicationArtifactError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    if exact_size is not None and len(material) != exact_size:
        raise PublicationArtifactError(f"{label} must contain exactly {exact_size} raw bytes")
    return material


def _read_artifact(directory: Path, name: str) -> bytes:
    return _read_private_file(directory / name, label=f"M5 publication artifact {name}")


def _staging_directory(parent_fd: int) -> tuple[str, int]:
    name = f"{_STAGING_PREFIX}{secrets.token_hex(16)}"
    descriptor = -1
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
        if descriptor >= 0:
            os.close(descriptor)
        raise PublicationArtifactError("private staging directory could not be created") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != _current_uid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise PublicationArtifactError("staging directory is not owned mode 0700")
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


def _package_directory(directory: Path, expected_files: frozenset[str], *, label: str) -> None:
    if not directory.is_absolute():
        raise PublicationArtifactError(f"{label} path must be absolute")
    _reject_symlink_components(directory)
    try:
        metadata = directory.lstat()
        names = {item.name for item in directory.iterdir()}
    except OSError as exc:
        raise PublicationArtifactError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != _current_uid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or names != expected_files
    ):
        raise PublicationArtifactError(f"{label} is not an exact owned mode-0700 package")


def _artifact_record(material: bytes, *, purpose: str, distribution: str) -> dict[str, Any]:
    return {
        "size_bytes": len(material),
        "sha256": _sha256(material),
        "purpose": purpose,
        "distribution": distribution,
    }


def _validate_identifier(value: str, *, label: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise PublicationArtifactError(f"{label} is noncanonical")
    return value


def _validate_scope(value: str, *, label: str) -> str:
    if not _CANONICAL_TEXT.fullmatch(value):
        raise PublicationArtifactError(f"{label} is noncanonical")
    return value


def _validate_positive_seconds(value: int, *, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not 1 <= value <= maximum:
        raise PublicationArtifactError(f"{label} must be between 1 and {maximum} seconds")
    return value


def _load_private_key(material: bytes, *, label: str) -> Ed25519PrivateKey:
    if len(material) != 32:
        raise PublicationArtifactError(f"{label} must contain exactly 32 raw bytes")
    try:
        return Ed25519PrivateKey.from_private_bytes(material)
    except ValueError as exc:
        raise PublicationArtifactError(f"{label} is not an Ed25519 private key") from exc


def _load_public_key(material: bytes, *, label: str) -> Ed25519PublicKey:
    if len(material) != 32:
        raise PublicationArtifactError(f"{label} must contain exactly 32 raw bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(material)
    except ValueError as exc:
        raise PublicationArtifactError(f"{label} is not an Ed25519 public key") from exc


def _publish_package(
    output: Path,
    materials: Mapping[str, bytes],
    *,
    verify_staging: Callable[[Path], dict[str, Any]],
) -> dict[str, Any]:
    destination, parent_fd = _open_safe_parent(output)
    staging_name = ""
    staging_fd: int | None = None
    published = False
    try:
        staging_name, staging_fd = _staging_directory(parent_fd)
        for name, material in materials.items():
            _write_file(staging_fd, name, material)
        os.fsync(staging_fd)
        staging_path = destination.with_name(staging_name)
        report = verify_staging(staging_path)
        _publish_directory_noreplace(staging_path, destination)
        published = True
        os.fsync(parent_fd)
        return report
    finally:
        if not published and staging_name:
            _cleanup_staging(parent_fd, staging_fd, staging_name)
        if staging_fd is not None:
            os.close(staging_fd)
        os.close(parent_fd)


def _load_model(model: Any, material: bytes, *, label: str) -> Any:
    try:
        return model.model_validate(_load_json(material, label=label))
    except PublicationArtifactError:
        raise
    except Exception as exc:
        raise PublicationArtifactError(f"{label} failed strict model validation") from exc


def _package_manifest(
    *,
    schema_version: str,
    package_kind: str,
    source_binding: Mapping[str, Any],
    materials: Mapping[str, bytes],
    purposes: Mapping[str, tuple[str, str]],
    authority_id: str,
    authority_key_id: str,
    publisher_id: str,
    publisher_key_id: str,
    publisher_credential_sha256: str,
    stable_authorization_id: str,
    stable_authorization_sha256: str,
    status_input_sha256: str | None,
    reversal_sha256: str | None = None,
) -> dict[str, Any]:
    if set(materials) != set(purposes):
        raise PublicationArtifactError("package purpose map differs from its payload inventory")
    return {
        "schema_version": schema_version,
        "package_kind": package_kind,
        "source_binding": dict(source_binding),
        "trust": {
            "authority_id": authority_id,
            "authority_key_id": authority_key_id,
            "publisher_id": publisher_id,
            "publisher_key_id": publisher_key_id,
            "publisher_credential_sha256": publisher_credential_sha256,
            "root_and_publisher_keys_distinct": authority_key_id != publisher_key_id,
        },
        "authorization": {
            "authorization_id": stable_authorization_id,
            "authorization_sha256": stable_authorization_sha256,
            "role_policy_sha256": degraded_role_policy_sha256(),
            "status_input_sha256": status_input_sha256,
            "reversal_sha256": reversal_sha256,
            "execution_authorized": False,
        },
        "files": {
            name: _artifact_record(
                material,
                purpose=purposes[name][0],
                distribution=purposes[name][1],
            )
            for name, material in materials.items()
        },
        "claim_boundary": {
            "establishes": (
                "source-bound local trust and configuration material for the M5 "
                "signed continuous-publication path"
            ),
            "does_not_establish": [
                "automatic health assessment",
                "live compromise detection",
                "approved degraded-mode policy",
                "plant-effect authorization",
                "mission continuity",
                "deployment",
                "independent validation",
                "operational effectiveness",
            ],
        },
    }


def _validate_manifest(
    value: Mapping[str, Any],
    *,
    expected: Mapping[str, Any],
    schema_version: str,
    package_kind: str,
) -> None:
    if dict(value) != dict(expected):
        raise PublicationArtifactError(f"{package_kind} manifest is inconsistent")
    if value.get("schema_version") != schema_version:
        raise PublicationArtifactError(f"{package_kind} manifest schema is unsupported")
    if value.get("package_kind") != package_kind:
        raise PublicationArtifactError(f"{package_kind} manifest kind is inconsistent")
    binding = value.get("source_binding")
    if not isinstance(binding, dict):
        raise PublicationArtifactError(f"{package_kind} manifest lacks a source binding")
    _validate_source_binding(binding)


def _model_public_key(credential: DegradedPublisherCredential) -> bytes:
    encoded = credential.publisher_public_key_b64
    try:
        material = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise PublicationArtifactError(
            "publisher credential public key is not strict base64"
        ) from exc
    if len(material) != 32:
        raise PublicationArtifactError(
            "publisher credential public key must contain exactly 32 bytes"
        )
    return material


def _require_credential_authorization_binding(
    credential: DegradedPublisherCredential,
    authorization: StableDegradedAuthorization,
    root_public_key: Ed25519PublicKey,
) -> None:
    if not credential.verify(root_public_key):
        raise PublicationArtifactError("publisher credential signature is invalid")
    if not authorization.verify(root_public_key):
        raise PublicationArtifactError("stable authorization signature is invalid")
    if authorization.authority_id != credential.authority_id:
        raise PublicationArtifactError("authorization authority differs from credential")
    if authorization.authority_key_id != credential.authority_key_id:
        raise PublicationArtifactError("authorization root key differs from credential")
    if authorization.publisher_credential_sha256 != credential.digest:
        raise PublicationArtifactError("authorization does not bind the exact credential")
    if authorization.publisher_key_id != credential.publisher_key_id:
        raise PublicationArtifactError("authorization publisher key differs from credential")
    if authorization.role_policy_sha256 != degraded_role_policy_sha256():
        raise PublicationArtifactError("authorization role policy differs from this source")
    if authorization.behavior is not _effective_behavior(authorization.affected_roles):
        raise PublicationArtifactError("authorization behavior differs from its exact role set")


def _effective_behavior(affected_roles: frozenset[DegradedRole]) -> DegradedBehavior:
    behaviors = {ROLE_LOSS_POLICIES[role].behavior for role in affected_roles}
    if DegradedBehavior.SAFE_STATE in behaviors:
        return DegradedBehavior.SAFE_STATE
    if DegradedBehavior.HOLD_STATE in behaviors:
        return DegradedBehavior.HOLD_STATE
    return DegradedBehavior.MISSION_PRESERVING


def _require_status_authorization_binding(
    status_input: DegradedStatusInput,
    authorization: StableDegradedAuthorization,
) -> None:
    if dict(status_input.role_conditions) != dict(authorization.role_conditions):
        raise PublicationArtifactError("status role conditions differ from authorization")
    if dict(status_input.communication_conditions) != dict(authorization.communication_conditions):
        raise PublicationArtifactError("status communication conditions differ from authorization")
    affected_roles = frozenset(
        role
        for role in DegradedRole
        if status_input.role_conditions[role] is not RoleCondition.HEALTHY
        or status_input.communication_conditions[role] is not RoleCondition.HEALTHY
    )
    if affected_roles != authorization.affected_roles:
        raise PublicationArtifactError("status affected roles differ from authorization")


def _provisioning_material(
    *,
    source_binding: Mapping[str, Any],
    authority_id: str,
    publisher_id: str,
    health_source_id: str,
    role: DegradedRole,
    surface: str,
    condition: RoleCondition,
    actor_id: str,
    mission_id: str,
    resource: str,
    operation: Operation,
    maximum_risk_score: float,
    credential_seconds: int,
    authorization_seconds: int,
    maximum_publication_age_seconds: int,
    maximum_status_input_age_seconds: int,
    authorization_sequence: int,
    now: datetime,
    unresolved_effect: bool,
) -> tuple[
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    DegradedPublisherCredential,
    StableDegradedAuthorization,
    DegradedStatusInput,
]:
    authority_id = _validate_identifier(authority_id, label="authority ID")
    publisher_id = _validate_identifier(publisher_id, label="publisher ID")
    health_source_id = _validate_identifier(health_source_id, label="health source ID")
    actor_id = _validate_scope(actor_id, label="actor ID")
    mission_id = _validate_scope(mission_id, label="mission ID")
    resource = _validate_scope(resource, label="resource")
    credential_seconds = _validate_positive_seconds(
        credential_seconds,
        label="publisher credential lifetime",
        maximum=MAX_CREDENTIAL_SECONDS,
    )
    authorization_seconds = _validate_positive_seconds(
        authorization_seconds,
        label="stable authorization lifetime",
        maximum=MAX_AUTHORIZATION_SECONDS,
    )
    maximum_publication_age_seconds = _validate_positive_seconds(
        maximum_publication_age_seconds,
        label="maximum publication age",
        maximum=MAX_PUBLICATION_AGE_SECONDS,
    )
    maximum_status_input_age_seconds = _validate_positive_seconds(
        maximum_status_input_age_seconds,
        label="maximum status input age",
        maximum=MAX_STATUS_INPUT_AGE_SECONDS,
    )
    if authorization_seconds > credential_seconds:
        raise PublicationArtifactError(
            "stable authorization cannot outlive its publisher credential"
        )
    if maximum_status_input_age_seconds > credential_seconds:
        raise PublicationArtifactError(
            "status input cannot outlive its publisher credential"
        )
    if isinstance(authorization_sequence, bool) or authorization_sequence < 1:
        raise PublicationArtifactError("stable authorization sequence must be positive")
    if surface not in {"service", "communication"}:
        raise PublicationArtifactError("affected surface must be service or communication")
    if condition is RoleCondition.HEALTHY:
        raise PublicationArtifactError("provisioned degraded condition must be non-healthy")
    if not math.isfinite(maximum_risk_score) or not 0 <= maximum_risk_score <= 100:
        raise PublicationArtifactError("maximum risk score must be finite and between zero and 100")
    if now.tzinfo is None or now.utcoffset() is None:
        raise PublicationArtifactError("provisioning time must be timezone-aware")
    issued_at = now.astimezone(UTC)

    role_conditions = {item: RoleCondition.HEALTHY for item in DegradedRole}
    communication_conditions = {item: RoleCondition.HEALTHY for item in DegradedRole}
    target = role_conditions if surface == "service" else communication_conditions
    target[role] = condition
    affected_roles = frozenset({role})

    authority_private_key = Ed25519PrivateKey.generate()
    publisher_private_key = Ed25519PrivateKey.generate()
    authority_public = _raw_public(authority_private_key)
    publisher_public = _raw_public(publisher_private_key)
    if authority_public == publisher_public:  # cryptographically negligible; fail closed
        raise PublicationArtifactError("root and publisher leaf keys must be distinct")
    authority_key_id = _public_key_id(authority_public)
    publisher_key_id = _public_key_id(publisher_public)
    token = secrets.token_hex(16)

    credential = DegradedPublisherCredential(
        credential_id=f"m5-publisher-credential-{token}",
        authority_id=authority_id,
        authority_key_id=authority_key_id,
        publisher_id=publisher_id,
        publisher_key_id=publisher_key_id,
        publisher_public_key_b64=base64.b64encode(publisher_public).decode("ascii"),
        health_source_id=health_source_id,
        source_git_commit=str(source_binding["git_commit"]),
        source_fingerprint_sha256=str(source_binding["source_fingerprint_sha256"]),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=credential_seconds),
        maximum_publication_age_seconds=maximum_publication_age_seconds,
        maximum_status_input_age_seconds=maximum_status_input_age_seconds,
    ).signed(authority_private_key)

    authorization = StableDegradedAuthorization(
        authorization_id=f"m5-stable-authorization-{token}",
        sequence=authorization_sequence,
        authority_id=authority_id,
        authority_key_id=authority_key_id,
        publisher_credential_sha256=credential.digest,
        publisher_key_id=publisher_key_id,
        mode_name=f"{role.value}-{surface}-{condition.value}",
        behavior=_effective_behavior(affected_roles),
        affected_roles=affected_roles,
        role_conditions=role_conditions,
        communication_conditions=communication_conditions,
        allowed_actor_ids=frozenset({actor_id}),
        allowed_mission_ids=frozenset({mission_id}),
        allowed_resources=frozenset({resource}),
        allowed_operations=frozenset({operation}),
        maximum_risk_score=maximum_risk_score,
        role_policy_sha256=degraded_role_policy_sha256(),
        recovery_checkpoint_id=f"m5-recovery-checkpoint-{token}",
        nonce=f"m5-stable-authorization-nonce-{token}",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=authorization_seconds),
    ).signed(authority_private_key)

    status_input = DegradedStatusInput(
        status_input_id=f"m5-status-input-{token}",
        sequence=1,
        source_id=health_source_id,
        observed_at=issued_at,
        expires_at=issued_at + timedelta(seconds=maximum_status_input_age_seconds),
        role_conditions=role_conditions,
        communication_conditions=communication_conditions,
        unresolved_effect=unresolved_effect,
        operator_asserted_not_detected=True,
    )
    return (
        authority_private_key,
        publisher_private_key,
        credential,
        authorization,
        status_input,
    )


def _authority_manifest(
    *,
    source_binding: Mapping[str, Any],
    materials: Mapping[str, bytes],
    credential: DegradedPublisherCredential,
    authorization: StableDegradedAuthorization,
    status_input: DegradedStatusInput,
) -> dict[str, Any]:
    return _package_manifest(
        schema_version=AUTHORITY_SCHEMA,
        package_kind="offline_authority",
        source_binding=source_binding,
        materials=materials,
        purposes=AUTHORITY_PURPOSES,
        authority_id=credential.authority_id,
        authority_key_id=credential.authority_key_id,
        publisher_id=credential.publisher_id,
        publisher_key_id=credential.publisher_key_id,
        publisher_credential_sha256=credential.digest,
        stable_authorization_id=authorization.authorization_id,
        stable_authorization_sha256=authorization.digest,
        status_input_sha256=status_input.digest,
    )


def _verify_authority_package(
    directory: Path,
    *,
    expected_source_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _package_directory(directory, AUTHORITY_FILES, label="M5 offline authority package")
    payload_names = set(AUTHORITY_FILES) - {MANIFEST_NAME}
    materials = {name: _read_artifact(directory, name) for name in payload_names}
    root_private = _load_private_key(
        materials[ROOT_PRIVATE_NAME], label="operator authority private key"
    )
    root_public_material = materials[ROOT_PUBLIC_NAME]
    root_public = _load_public_key(root_public_material, label="operator authority public key")
    if _raw_public(root_private) != root_public_material:
        raise PublicationArtifactError("operator authority key pair does not match")
    publisher_private = _load_private_key(
        materials[PUBLISHER_PRIVATE_NAME], label="publisher leaf private key"
    )
    credential = _load_model(
        DegradedPublisherCredential,
        materials[PUBLISHER_CREDENTIAL_NAME],
        label=PUBLISHER_CREDENTIAL_NAME,
    )
    authorization = _load_model(
        StableDegradedAuthorization,
        materials[STABLE_AUTHORIZATION_NAME],
        label=STABLE_AUTHORIZATION_NAME,
    )
    status_input = _load_model(
        DegradedStatusInput,
        materials[STATUS_INPUT_NAME],
        label=STATUS_INPUT_NAME,
    )
    if _raw_public(publisher_private) != _model_public_key(credential):
        raise PublicationArtifactError("publisher leaf key differs from its credential")
    if credential.authority_key_id != _public_key_id(root_public_material):
        raise PublicationArtifactError("credential root key ID differs from package root")
    _require_credential_authorization_binding(credential, authorization, root_public)
    _require_status_authorization_binding(status_input, authorization)
    if status_input.source_id != credential.health_source_id:
        raise PublicationArtifactError("status source differs from publisher credential")
    if not (
        credential.issued_at <= authorization.issued_at
        and authorization.expires_at <= credential.expires_at
    ):
        raise PublicationArtifactError("authorization validity is outside the publisher credential")
    manifest = _load_json(_read_artifact(directory, MANIFEST_NAME), label=MANIFEST_NAME)
    source_binding = manifest.get("source_binding")
    if not isinstance(source_binding, dict):
        raise PublicationArtifactError("offline authority manifest lacks source binding")
    _require_credential_source_binding(credential, source_binding)
    if expected_source_binding is not None and source_binding != dict(expected_source_binding):
        raise PublicationArtifactError("offline authority source binding differs")
    expected_manifest = _authority_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
        status_input=status_input,
    )
    _validate_manifest(
        manifest,
        expected=expected_manifest,
        schema_version=AUTHORITY_SCHEMA,
        package_kind="offline_authority",
    )
    return {
        "valid": True,
        "schema_version": AUTHORITY_SCHEMA,
        "source_git_commit": source_binding["git_commit"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
        "authority_id": credential.authority_id,
        "authority_key_id": credential.authority_key_id,
        "publisher_id": credential.publisher_id,
        "publisher_key_id": credential.publisher_key_id,
        "publisher_credential_sha256": credential.digest,
        "stable_authorization_id": authorization.authorization_id,
        "stable_authorization_sha256": authorization.digest,
        "status_input_sha256": status_input.digest,
        "root_and_publisher_keys_distinct": (
            credential.authority_key_id != credential.publisher_key_id
        ),
        "execution_authorized": False,
    }


def create_authority_package(
    output: Path,
    *,
    authority_id: str,
    publisher_id: str,
    health_source_id: str,
    role: DegradedRole,
    surface: str,
    condition: RoleCondition,
    actor_id: str,
    mission_id: str,
    resource: str,
    operation: Operation,
    maximum_risk_score: float,
    credential_seconds: int = DEFAULT_CREDENTIAL_SECONDS,
    authorization_seconds: int = DEFAULT_AUTHORIZATION_SECONDS,
    maximum_publication_age_seconds: int = DEFAULT_PUBLICATION_AGE_SECONDS,
    maximum_status_input_age_seconds: int = DEFAULT_STATUS_INPUT_AGE_SECONDS,
    authorization_sequence: int = 1,
    source_reference: str = "HEAD",
    now: datetime | None = None,
    unresolved_effect: bool = False,
) -> dict[str, Any]:
    """Create one private offline-root and publisher-leaf provisioning package."""

    source_binding = _assert_clean_source(source_reference)
    (
        root_private,
        publisher_private,
        credential,
        authorization,
        status_input,
    ) = _provisioning_material(
        source_binding=source_binding,
        authority_id=authority_id,
        publisher_id=publisher_id,
        health_source_id=health_source_id,
        role=role,
        surface=surface,
        condition=condition,
        actor_id=actor_id,
        mission_id=mission_id,
        resource=resource,
        operation=operation,
        maximum_risk_score=maximum_risk_score,
        credential_seconds=credential_seconds,
        authorization_seconds=authorization_seconds,
        maximum_publication_age_seconds=maximum_publication_age_seconds,
        maximum_status_input_age_seconds=maximum_status_input_age_seconds,
        authorization_sequence=authorization_sequence,
        now=datetime.now(UTC) if now is None else now,
        unresolved_effect=unresolved_effect,
    )
    materials = {
        ROOT_PRIVATE_NAME: _raw_private(root_private),
        ROOT_PUBLIC_NAME: _raw_public(root_private),
        PUBLISHER_PRIVATE_NAME: _raw_private(publisher_private),
        PUBLISHER_CREDENTIAL_NAME: _model_bytes(credential),
        STABLE_AUTHORIZATION_NAME: _model_bytes(authorization),
        STATUS_INPUT_NAME: _model_bytes(status_input),
    }
    manifest = _authority_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
        status_input=status_input,
    )
    package = {**materials, MANIFEST_NAME: _canonical_bytes(manifest)}
    return _publish_package(
        output,
        package,
        verify_staging=lambda path: _verify_authority_package(
            path, expected_source_binding=source_binding
        ),
    )


def verify_authority_package(
    directory: Path,
    *,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Verify the exact offline package and its current-source binding."""

    return _verify_authority_package(
        directory.resolve(strict=True),
        expected_source_binding=_assert_clean_source(source_reference),
    )


def _reject_output_within(output: Path, source: Path, *, label: str) -> None:
    try:
        source = source.resolve(strict=True)
        prospective = output.parent.resolve(strict=True) / output.name
    except OSError as exc:
        raise PublicationArtifactError(f"{label} path could not be resolved") from exc
    if prospective == source or source in prospective.parents:
        raise PublicationArtifactError(f"output must be separate from {label}")


def _load_public_trust_material(
    materials: Mapping[str, bytes],
) -> tuple[Ed25519PublicKey, DegradedPublisherCredential, StableDegradedAuthorization]:
    root_public = _load_public_key(
        materials[ROOT_PUBLIC_NAME], label="operator authority public key"
    )
    credential = _load_model(
        DegradedPublisherCredential,
        materials[PUBLISHER_CREDENTIAL_NAME],
        label=PUBLISHER_CREDENTIAL_NAME,
    )
    authorization = _load_model(
        StableDegradedAuthorization,
        materials[STABLE_AUTHORIZATION_NAME],
        label=STABLE_AUTHORIZATION_NAME,
    )
    if credential.authority_key_id != _public_key_id(materials[ROOT_PUBLIC_NAME]):
        raise PublicationArtifactError("credential root key ID differs from package root")
    _require_credential_authorization_binding(credential, authorization, root_public)
    return root_public, credential, authorization


def _require_credential_source_binding(
    credential: DegradedPublisherCredential,
    source_binding: Mapping[str, Any],
) -> None:
    if (
        credential.source_git_commit != source_binding.get("git_commit")
        or credential.source_fingerprint_sha256
        != source_binding.get("source_fingerprint_sha256")
    ):
        raise PublicationArtifactError(
            "root-signed publisher credential differs from package source binding"
        )


def _runtime_manifest(
    *,
    source_binding: Mapping[str, Any],
    materials: Mapping[str, bytes],
    credential: DegradedPublisherCredential,
    authorization: StableDegradedAuthorization,
) -> dict[str, Any]:
    return _package_manifest(
        schema_version=RUNTIME_SCHEMA,
        package_kind="gateway_runtime",
        source_binding=source_binding,
        materials=materials,
        purposes=RUNTIME_PURPOSES,
        authority_id=credential.authority_id,
        authority_key_id=credential.authority_key_id,
        publisher_id=credential.publisher_id,
        publisher_key_id=credential.publisher_key_id,
        publisher_credential_sha256=credential.digest,
        stable_authorization_id=authorization.authorization_id,
        stable_authorization_sha256=authorization.digest,
        status_input_sha256=None,
    )


def _verify_runtime_package(
    directory: Path,
    *,
    expected_source_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _package_directory(directory, RUNTIME_FILES, label="M5 gateway runtime package")
    payload_names = set(RUNTIME_FILES) - {MANIFEST_NAME}
    materials = {name: _read_artifact(directory, name) for name in payload_names}
    _, credential, authorization = _load_public_trust_material(materials)
    manifest = _load_json(_read_artifact(directory, MANIFEST_NAME), label=MANIFEST_NAME)
    source_binding = manifest.get("source_binding")
    if not isinstance(source_binding, dict):
        raise PublicationArtifactError("runtime manifest lacks source binding")
    _require_credential_source_binding(credential, source_binding)
    if expected_source_binding is not None and source_binding != dict(expected_source_binding):
        raise PublicationArtifactError("runtime source binding differs")
    expected_manifest = _runtime_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
    )
    _validate_manifest(
        manifest,
        expected=expected_manifest,
        schema_version=RUNTIME_SCHEMA,
        package_kind="gateway_runtime",
    )
    return {
        "valid": True,
        "schema_version": RUNTIME_SCHEMA,
        "source_git_commit": source_binding["git_commit"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
        "authority_id": credential.authority_id,
        "authority_key_id": credential.authority_key_id,
        "publisher_id": credential.publisher_id,
        "publisher_key_id": credential.publisher_key_id,
        "publisher_credential_sha256": credential.digest,
        "stable_authorization_id": authorization.authorization_id,
        "stable_authorization_sha256": authorization.digest,
        "private_key_material_included": False,
        "mutable_state_included": False,
        "execution_authorized": False,
    }


def create_runtime_package(
    output: Path,
    *,
    authority_directory: Path,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Create public-only immutable inputs for the gateway consumer."""

    source_binding = _assert_clean_source(source_reference)
    authority_directory = authority_directory.resolve(strict=True)
    _reject_output_within(output, authority_directory, label="offline authority package")
    _verify_authority_package(authority_directory, expected_source_binding=source_binding)
    materials = {name: _read_artifact(authority_directory, name) for name in RUNTIME_PURPOSES}
    _, credential, authorization = _load_public_trust_material(materials)
    manifest = _runtime_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
    )
    package = {**materials, MANIFEST_NAME: _canonical_bytes(manifest)}
    return _publish_package(
        output,
        package,
        verify_staging=lambda path: _verify_runtime_package(
            path, expected_source_binding=source_binding
        ),
    )


def verify_runtime_package(
    directory: Path,
    *,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Verify gateway trust inputs and prove absence of private/state material."""

    return _verify_runtime_package(
        directory.resolve(strict=True),
        expected_source_binding=_assert_clean_source(source_reference),
    )


def _healthy_status_manifest(
    *,
    source_binding: Mapping[str, Any],
    materials: Mapping[str, bytes],
    credential: DegradedPublisherCredential,
    authorization: StableDegradedAuthorization,
    status_input: DegradedStatusInput,
) -> dict[str, Any]:
    return _package_manifest(
        schema_version=HEALTHY_STATUS_SCHEMA,
        package_kind="healthy_status_input",
        source_binding=source_binding,
        materials=materials,
        purposes=HEALTHY_STATUS_PURPOSES,
        authority_id=credential.authority_id,
        authority_key_id=credential.authority_key_id,
        publisher_id=credential.publisher_id,
        publisher_key_id=credential.publisher_key_id,
        publisher_credential_sha256=credential.digest,
        stable_authorization_id=authorization.authorization_id,
        stable_authorization_sha256=authorization.digest,
        status_input_sha256=status_input.digest,
    )


def _verify_healthy_status_package(
    directory: Path,
    *,
    runtime_package: Path,
    expected_source_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _package_directory(directory, HEALTHY_STATUS_FILES, label="M5 healthy status package")
    runtime_report = _verify_runtime_package(
        runtime_package,
        expected_source_binding=expected_source_binding,
    )
    runtime_materials = {
        name: _read_artifact(runtime_package, name) for name in RUNTIME_PURPOSES
    }
    _, credential, authorization = _load_public_trust_material(runtime_materials)
    status_material = _read_artifact(directory, STATUS_INPUT_NAME)
    status_input = _load_model(
        DegradedStatusInput,
        status_material,
        label=STATUS_INPUT_NAME,
    )
    if status_input.sequence < 2:
        raise PublicationArtifactError("healthy status sequence must follow initial status")
    if status_input.source_id != credential.health_source_id:
        raise PublicationArtifactError("healthy status source differs from publisher credential")
    if (
        set(status_input.role_conditions.values()) != {RoleCondition.HEALTHY}
        or set(status_input.communication_conditions.values()) != {RoleCondition.HEALTHY}
        or status_input.unresolved_effect
    ):
        raise PublicationArtifactError("healthy status must assert complete resolved recovery")
    if (
        status_input.observed_at < credential.issued_at
        or status_input.expires_at > credential.expires_at
        or status_input.expires_at - status_input.observed_at
        > timedelta(seconds=credential.maximum_status_input_age_seconds)
    ):
        raise PublicationArtifactError("healthy status validity is outside its credential")
    manifest = _load_json(_read_artifact(directory, MANIFEST_NAME), label=MANIFEST_NAME)
    source_binding = manifest.get("source_binding")
    if not isinstance(source_binding, dict):
        raise PublicationArtifactError("healthy status manifest lacks source binding")
    _require_credential_source_binding(credential, source_binding)
    if expected_source_binding is not None and source_binding != dict(expected_source_binding):
        raise PublicationArtifactError("healthy status source binding differs")
    materials = {STATUS_INPUT_NAME: status_material}
    expected_manifest = _healthy_status_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
        status_input=status_input,
    )
    _validate_manifest(
        manifest,
        expected=expected_manifest,
        schema_version=HEALTHY_STATUS_SCHEMA,
        package_kind="healthy_status_input",
    )
    return {
        "valid": True,
        "schema_version": HEALTHY_STATUS_SCHEMA,
        "source_git_commit": runtime_report["source_git_commit"],
        "source_fingerprint_sha256": runtime_report["source_fingerprint_sha256"],
        "publisher_credential_sha256": credential.digest,
        "stable_authorization_sha256": authorization.digest,
        "status_input_id": status_input.status_input_id,
        "status_input_sequence": status_input.sequence,
        "status_input_sha256": status_input.digest,
        "observed_at": status_input.observed_at.isoformat(),
        "expires_at": status_input.expires_at.isoformat(),
        "complete_recovery_asserted": True,
        "private_key_material_included": False,
        "execution_authorized": False,
    }


def create_healthy_status_package(
    output: Path,
    *,
    runtime_package: Path,
    sequence: int,
    valid_seconds: int = DEFAULT_STATUS_INPUT_AGE_SECONDS,
    source_reference: str = "HEAD",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Create one fresh complete recovery assertion from public runtime trust."""

    source_binding = _assert_clean_source(source_reference)
    runtime_package = runtime_package.resolve(strict=True)
    _reject_output_within(output, runtime_package, label="gateway runtime package")
    _verify_runtime_package(runtime_package, expected_source_binding=source_binding)
    runtime_materials = {
        name: _read_artifact(runtime_package, name) for name in RUNTIME_PURPOSES
    }
    _, credential, authorization = _load_public_trust_material(runtime_materials)
    if isinstance(sequence, bool) or sequence < 2:
        raise PublicationArtifactError("healthy status sequence must be at least two")
    valid_seconds = _validate_positive_seconds(
        valid_seconds,
        label="healthy status lifetime",
        maximum=credential.maximum_status_input_age_seconds,
    )
    observed_at = datetime.now(UTC) if now is None else now
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise PublicationArtifactError("healthy status observation must be timezone-aware")
    observed_at = observed_at.astimezone(UTC)
    expires_at = observed_at + timedelta(seconds=valid_seconds)
    if not credential.issued_at <= observed_at < expires_at <= credential.expires_at:
        raise PublicationArtifactError("healthy status validity is outside its credential")
    healthy = {role: RoleCondition.HEALTHY for role in DegradedRole}
    status_input = DegradedStatusInput(
        status_input_id=f"m5-healthy-status-input-{secrets.token_hex(16)}",
        sequence=sequence,
        source_id=credential.health_source_id,
        observed_at=observed_at,
        expires_at=expires_at,
        role_conditions=healthy,
        communication_conditions=healthy,
        unresolved_effect=False,
        operator_asserted_not_detected=True,
    )
    materials = {STATUS_INPUT_NAME: _model_bytes(status_input)}
    manifest = _healthy_status_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
        status_input=status_input,
    )
    package = {**materials, MANIFEST_NAME: _canonical_bytes(manifest)}
    return _publish_package(
        output,
        package,
        verify_staging=lambda path: _verify_healthy_status_package(
            path,
            runtime_package=runtime_package,
            expected_source_binding=source_binding,
        ),
    )


def verify_healthy_status_package(
    directory: Path,
    *,
    runtime_package: Path,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Verify one healthy status package against public runtime trust."""

    return _verify_healthy_status_package(
        directory.resolve(strict=True),
        runtime_package=runtime_package.resolve(strict=True),
        expected_source_binding=_assert_clean_source(source_reference),
    )


def _publisher_manifest(
    *,
    source_binding: Mapping[str, Any],
    materials: Mapping[str, bytes],
    credential: DegradedPublisherCredential,
    authorization: StableDegradedAuthorization,
    status_input: DegradedStatusInput,
) -> dict[str, Any]:
    return _package_manifest(
        schema_version=PUBLISHER_SCHEMA,
        package_kind="online_publisher",
        source_binding=source_binding,
        materials=materials,
        purposes=PUBLISHER_PURPOSES,
        authority_id=credential.authority_id,
        authority_key_id=credential.authority_key_id,
        publisher_id=credential.publisher_id,
        publisher_key_id=credential.publisher_key_id,
        publisher_credential_sha256=credential.digest,
        stable_authorization_id=authorization.authorization_id,
        stable_authorization_sha256=authorization.digest,
        status_input_sha256=status_input.digest,
    )


def _verify_publisher_package(
    directory: Path,
    *,
    expected_source_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _package_directory(directory, PUBLISHER_FILES, label="M5 online publisher package")
    payload_names = set(PUBLISHER_FILES) - {MANIFEST_NAME}
    materials = {name: _read_artifact(directory, name) for name in payload_names}
    _, credential, authorization = _load_public_trust_material(materials)
    publisher_private = _load_private_key(
        materials[PUBLISHER_PRIVATE_NAME], label="publisher leaf private key"
    )
    if _raw_public(publisher_private) != _model_public_key(credential):
        raise PublicationArtifactError("publisher leaf key differs from its credential")
    status_input = _load_model(
        DegradedStatusInput,
        materials[STATUS_INPUT_NAME],
        label=STATUS_INPUT_NAME,
    )
    _require_status_authorization_binding(status_input, authorization)
    if status_input.source_id != credential.health_source_id:
        raise PublicationArtifactError("status source differs from publisher credential")
    manifest = _load_json(_read_artifact(directory, MANIFEST_NAME), label=MANIFEST_NAME)
    source_binding = manifest.get("source_binding")
    if not isinstance(source_binding, dict):
        raise PublicationArtifactError("publisher manifest lacks source binding")
    _require_credential_source_binding(credential, source_binding)
    if expected_source_binding is not None and source_binding != dict(expected_source_binding):
        raise PublicationArtifactError("publisher source binding differs")
    expected_manifest = _publisher_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
        status_input=status_input,
    )
    _validate_manifest(
        manifest,
        expected=expected_manifest,
        schema_version=PUBLISHER_SCHEMA,
        package_kind="online_publisher",
    )
    return {
        "valid": True,
        "schema_version": PUBLISHER_SCHEMA,
        "source_git_commit": source_binding["git_commit"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
        "authority_id": credential.authority_id,
        "authority_key_id": credential.authority_key_id,
        "publisher_id": credential.publisher_id,
        "publisher_key_id": credential.publisher_key_id,
        "publisher_credential_sha256": credential.digest,
        "stable_authorization_id": authorization.authorization_id,
        "stable_authorization_sha256": authorization.digest,
        "status_input_sha256": status_input.digest,
        "root_private_key_included": False,
        "publisher_private_key_included": True,
        "mutable_state_included": False,
        "operator_asserted_not_detected": status_input.operator_asserted_not_detected,
        "execution_authorized": False,
    }


def create_publisher_package(
    output: Path,
    *,
    authority_directory: Path,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Create the exact online publisher inputs without the root private key."""

    source_binding = _assert_clean_source(source_reference)
    authority_directory = authority_directory.resolve(strict=True)
    _reject_output_within(output, authority_directory, label="offline authority package")
    _verify_authority_package(authority_directory, expected_source_binding=source_binding)
    materials = {name: _read_artifact(authority_directory, name) for name in PUBLISHER_PURPOSES}
    _, credential, authorization = _load_public_trust_material(materials)
    status_input = _load_model(
        DegradedStatusInput,
        materials[STATUS_INPUT_NAME],
        label=STATUS_INPUT_NAME,
    )
    manifest = _publisher_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
        status_input=status_input,
    )
    package = {**materials, MANIFEST_NAME: _canonical_bytes(manifest)}
    return _publish_package(
        output,
        package,
        verify_staging=lambda path: _verify_publisher_package(
            path, expected_source_binding=source_binding
        ),
    )


def verify_publisher_package(
    directory: Path,
    *,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Verify the online leaf package and its distribution boundary."""

    return _verify_publisher_package(
        directory.resolve(strict=True),
        expected_source_binding=_assert_clean_source(source_reference),
    )


def _reversal_manifest(
    *,
    source_binding: Mapping[str, Any],
    materials: Mapping[str, bytes],
    credential: DegradedPublisherCredential,
    authorization: StableDegradedAuthorization,
    reversal: DegradedModeReversal,
) -> dict[str, Any]:
    return _package_manifest(
        schema_version=REVERSAL_SCHEMA,
        package_kind="exact_authorization_reversal",
        source_binding=source_binding,
        materials=materials,
        purposes=REVERSAL_PURPOSES,
        authority_id=credential.authority_id,
        authority_key_id=credential.authority_key_id,
        publisher_id=credential.publisher_id,
        publisher_key_id=credential.publisher_key_id,
        publisher_credential_sha256=credential.digest,
        stable_authorization_id=authorization.authorization_id,
        stable_authorization_sha256=authorization.digest,
        status_input_sha256=None,
        reversal_sha256=reversal.digest,
    )


def _verify_reversal_package(
    directory: Path,
    *,
    runtime_package: Path,
    expected_source_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _package_directory(directory, REVERSAL_FILES, label="M5 exact reversal package")
    _verify_runtime_package(
        runtime_package,
        expected_source_binding=expected_source_binding,
    )
    runtime_materials = {name: _read_artifact(runtime_package, name) for name in RUNTIME_PURPOSES}
    root_public, credential, authorization = _load_public_trust_material(runtime_materials)
    reversal_material = _read_artifact(directory, REVERSAL_NAME)
    reversal = _load_model(
        DegradedModeReversal,
        reversal_material,
        label=REVERSAL_NAME,
    )
    if (
        reversal.authority_id != credential.authority_id
        or reversal.authorization_id != authorization.authorization_id
        or reversal.authorization_sha256 != authorization.digest
        or reversal.recovery_checkpoint_id != authorization.recovery_checkpoint_id
    ):
        raise PublicationArtifactError("reversal does not bind the exact stable authorization")
    if not reversal.signature or not verify_bytes(
        root_public,
        reversal.signing_payload(),
        reversal.signature,
    ):
        raise PublicationArtifactError("reversal signature is invalid")
    if reversal.issued_at < authorization.issued_at:
        raise PublicationArtifactError("reversal predates the stable authorization")
    manifest = _load_json(_read_artifact(directory, MANIFEST_NAME), label=MANIFEST_NAME)
    source_binding = manifest.get("source_binding")
    if not isinstance(source_binding, dict):
        raise PublicationArtifactError("reversal manifest lacks source binding")
    _require_credential_source_binding(credential, source_binding)
    if expected_source_binding is not None and source_binding != dict(expected_source_binding):
        raise PublicationArtifactError("reversal source binding differs")
    materials = {REVERSAL_NAME: reversal_material}
    expected_manifest = _reversal_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
        reversal=reversal,
    )
    _validate_manifest(
        manifest,
        expected=expected_manifest,
        schema_version=REVERSAL_SCHEMA,
        package_kind="exact_authorization_reversal",
    )
    return {
        "valid": True,
        "schema_version": REVERSAL_SCHEMA,
        "source_git_commit": source_binding["git_commit"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
        "authority_id": credential.authority_id,
        "authority_key_id": credential.authority_key_id,
        "stable_authorization_id": authorization.authorization_id,
        "stable_authorization_sha256": authorization.digest,
        "reversal_sha256": reversal.digest,
        "root_private_key_included": False,
        "publisher_private_key_included": False,
        "mutable_state_included": False,
        "operator_application_required": True,
        "execution_authorized": False,
    }


def create_reversal_package(
    output: Path,
    *,
    authority_directory: Path,
    runtime_package: Path,
    sequence: int = 1,
    reason_code: str = "runtime_dependencies_recovered",
    source_reference: str = "HEAD",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Create one root-signed direction for the exact runtime authorization."""

    if isinstance(sequence, bool) or sequence < 1:
        raise PublicationArtifactError("reversal sequence must be positive")
    source_binding = _assert_clean_source(source_reference)
    authority_directory = authority_directory.resolve(strict=True)
    runtime_package = runtime_package.resolve(strict=True)
    _reject_output_within(output, authority_directory, label="offline authority package")
    _reject_output_within(output, runtime_package, label="runtime package")
    _verify_authority_package(authority_directory, expected_source_binding=source_binding)
    _verify_runtime_package(runtime_package, expected_source_binding=source_binding)
    root_private_material = _read_artifact(authority_directory, ROOT_PRIVATE_NAME)
    root_public_material = _read_artifact(authority_directory, ROOT_PUBLIC_NAME)
    root_private = _load_private_key(root_private_material, label="operator authority private key")
    if _raw_public(root_private) != root_public_material:
        raise PublicationArtifactError("operator authority key pair does not match")
    authority_credential_material = _read_artifact(authority_directory, PUBLISHER_CREDENTIAL_NAME)
    authority_authorization_material = _read_artifact(
        authority_directory, STABLE_AUTHORIZATION_NAME
    )
    if (
        authority_credential_material != _read_artifact(runtime_package, PUBLISHER_CREDENTIAL_NAME)
        or authority_authorization_material
        != _read_artifact(runtime_package, STABLE_AUTHORIZATION_NAME)
        or root_public_material != _read_artifact(runtime_package, ROOT_PUBLIC_NAME)
    ):
        raise PublicationArtifactError(
            "runtime trust material differs from the offline authority package"
        )
    credential = _load_model(
        DegradedPublisherCredential,
        authority_credential_material,
        label=PUBLISHER_CREDENTIAL_NAME,
    )
    authorization = _load_model(
        StableDegradedAuthorization,
        authority_authorization_material,
        label=STABLE_AUTHORIZATION_NAME,
    )
    issued_at = datetime.now(UTC) if now is None else now
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise PublicationArtifactError("reversal time must be timezone-aware")
    issued_at = issued_at.astimezone(UTC)
    reversal = DegradedModeReversal(
        reversal_id=f"m5-stable-reversal-{secrets.token_hex(16)}",
        sequence=sequence,
        authority_id=credential.authority_id,
        authorization_id=authorization.authorization_id,
        authorization_sha256=authorization.digest,
        recovery_checkpoint_id=authorization.recovery_checkpoint_id,
        reason_code=reason_code,
        nonce=f"m5-stable-reversal-nonce-{secrets.token_hex(16)}",
        issued_at=issued_at,
    ).signed(root_private)
    materials = {REVERSAL_NAME: _model_bytes(reversal)}
    manifest = _reversal_manifest(
        source_binding=source_binding,
        materials=materials,
        credential=credential,
        authorization=authorization,
        reversal=reversal,
    )
    package = {**materials, MANIFEST_NAME: _canonical_bytes(manifest)}
    return _publish_package(
        output,
        package,
        verify_staging=lambda path: _verify_reversal_package(
            path,
            runtime_package=runtime_package,
            expected_source_binding=source_binding,
        ),
    )


def verify_reversal_package(
    directory: Path,
    *,
    runtime_package: Path,
    source_reference: str = "HEAD",
) -> dict[str, Any]:
    """Verify an exact reversal using the public-only runtime trust package."""

    return _verify_reversal_package(
        directory.resolve(strict=True),
        runtime_package=runtime_package.resolve(strict=True),
        expected_source_binding=_assert_clean_source(source_reference),
    )


def _source_reference_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--source-reference",
        default="HEAD",
        help="commit reference that must resolve to the exact clean checkout",
    )


def source_binding_report(*, source_reference: str = "HEAD") -> dict[str, Any]:
    """Return the exact clean source identity needed before image build."""

    binding = _assert_clean_source(source_reference)
    return {
        "schema_version": "aegis-ot-m5-degraded-source-binding-v1",
        **binding,
        "execution_authorized": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    source_binding = commands.add_parser(
        "source-binding",
        help="report the exact clean source revision and fingerprint before image build",
    )
    _source_reference_argument(source_binding)

    authority = commands.add_parser(
        "authority",
        help="create one private offline-root and publisher-leaf provisioning package",
    )
    authority.add_argument("--output", type=Path, required=True)
    authority.add_argument("--authority-id", required=True)
    authority.add_argument("--publisher-id", required=True)
    authority.add_argument("--health-source-id", required=True)
    authority.add_argument("--role", choices=[item.value for item in DegradedRole], required=True)
    authority.add_argument("--surface", choices=["service", "communication"], required=True)
    authority.add_argument(
        "--condition", choices=[item.value for item in RoleCondition], required=True
    )
    authority.add_argument("--actor-id", required=True)
    authority.add_argument("--mission-id", required=True)
    authority.add_argument("--resource", required=True)
    authority.add_argument("--operation", choices=[item.value for item in Operation], required=True)
    authority.add_argument("--maximum-risk-score", type=float, required=True)
    authority.add_argument("--credential-seconds", type=int, default=DEFAULT_CREDENTIAL_SECONDS)
    authority.add_argument(
        "--authorization-seconds", type=int, default=DEFAULT_AUTHORIZATION_SECONDS
    )
    authority.add_argument(
        "--maximum-publication-age-seconds",
        type=int,
        default=DEFAULT_PUBLICATION_AGE_SECONDS,
    )
    authority.add_argument(
        "--maximum-status-input-age-seconds",
        type=int,
        default=DEFAULT_STATUS_INPUT_AGE_SECONDS,
    )
    authority.add_argument("--authorization-sequence", type=int, default=1)
    authority.add_argument("--unresolved-effect", action="store_true")
    _source_reference_argument(authority)

    runtime = commands.add_parser(
        "runtime", help="create the public-only immutable gateway trust package"
    )
    runtime.add_argument("--output", type=Path, required=True)
    runtime.add_argument("--authority", type=Path, required=True)
    _source_reference_argument(runtime)

    publisher = commands.add_parser(
        "publisher", help="create online publisher inputs without the root private key"
    )
    publisher.add_argument("--output", type=Path, required=True)
    publisher.add_argument("--authority", type=Path, required=True)
    _source_reference_argument(publisher)

    reversal = commands.add_parser(
        "reversal", help="create one root-signed exact-authorization reversal package"
    )
    reversal.add_argument("--output", type=Path, required=True)
    reversal.add_argument("--authority", type=Path, required=True)
    reversal.add_argument("--runtime", type=Path, required=True)
    reversal.add_argument("--sequence", type=int, default=1)
    reversal.add_argument("--reason-code", default="runtime_dependencies_recovered")
    _source_reference_argument(reversal)

    healthy_status = commands.add_parser(
        "healthy-status",
        help="create one fresh complete recovery assertion from public runtime trust",
    )
    healthy_status.add_argument("--output", type=Path, required=True)
    healthy_status.add_argument("--runtime", type=Path, required=True)
    healthy_status.add_argument("--sequence", type=int, required=True)
    healthy_status.add_argument(
        "--valid-seconds",
        type=int,
        default=DEFAULT_STATUS_INPUT_AGE_SECONDS,
    )
    _source_reference_argument(healthy_status)

    for name, help_text in (
        ("verify-authority", "verify the private offline provisioning package"),
        ("verify-runtime", "verify the public-only gateway package"),
        ("verify-publisher", "verify the online publisher leaf package"),
    ):
        verify = commands.add_parser(name, help=help_text)
        verify.add_argument("--package", type=Path, required=True)
        _source_reference_argument(verify)

    verify_reversal = commands.add_parser(
        "verify-reversal", help="verify a reversal against a runtime package"
    )
    verify_reversal.add_argument("--package", type=Path, required=True)
    verify_reversal.add_argument("--runtime", type=Path, required=True)
    _source_reference_argument(verify_reversal)

    verify_healthy_status = commands.add_parser(
        "verify-healthy-status",
        help="verify a healthy status assertion against a runtime package",
    )
    verify_healthy_status.add_argument("--package", type=Path, required=True)
    verify_healthy_status.add_argument("--runtime", type=Path, required=True)
    _source_reference_argument(verify_healthy_status)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "source-binding":
            report = source_binding_report(source_reference=arguments.source_reference)
        elif arguments.command == "authority":
            report = create_authority_package(
                arguments.output,
                authority_id=arguments.authority_id,
                publisher_id=arguments.publisher_id,
                health_source_id=arguments.health_source_id,
                role=DegradedRole(arguments.role),
                surface=arguments.surface,
                condition=RoleCondition(arguments.condition),
                actor_id=arguments.actor_id,
                mission_id=arguments.mission_id,
                resource=arguments.resource,
                operation=Operation(arguments.operation),
                maximum_risk_score=arguments.maximum_risk_score,
                credential_seconds=arguments.credential_seconds,
                authorization_seconds=arguments.authorization_seconds,
                maximum_publication_age_seconds=(arguments.maximum_publication_age_seconds),
                maximum_status_input_age_seconds=(
                    arguments.maximum_status_input_age_seconds
                ),
                authorization_sequence=arguments.authorization_sequence,
                unresolved_effect=arguments.unresolved_effect,
                source_reference=arguments.source_reference,
            )
        elif arguments.command == "runtime":
            report = create_runtime_package(
                arguments.output,
                authority_directory=arguments.authority,
                source_reference=arguments.source_reference,
            )
        elif arguments.command == "publisher":
            report = create_publisher_package(
                arguments.output,
                authority_directory=arguments.authority,
                source_reference=arguments.source_reference,
            )
        elif arguments.command == "reversal":
            report = create_reversal_package(
                arguments.output,
                authority_directory=arguments.authority,
                runtime_package=arguments.runtime,
                sequence=arguments.sequence,
                reason_code=arguments.reason_code,
                source_reference=arguments.source_reference,
            )
        elif arguments.command == "healthy-status":
            report = create_healthy_status_package(
                arguments.output,
                runtime_package=arguments.runtime,
                sequence=arguments.sequence,
                valid_seconds=arguments.valid_seconds,
                source_reference=arguments.source_reference,
            )
        elif arguments.command == "verify-authority":
            report = verify_authority_package(
                arguments.package,
                source_reference=arguments.source_reference,
            )
        elif arguments.command == "verify-runtime":
            report = verify_runtime_package(
                arguments.package,
                source_reference=arguments.source_reference,
            )
        elif arguments.command == "verify-publisher":
            report = verify_publisher_package(
                arguments.package,
                source_reference=arguments.source_reference,
            )
        elif arguments.command == "verify-reversal":
            report = verify_reversal_package(
                arguments.package,
                runtime_package=arguments.runtime,
                source_reference=arguments.source_reference,
            )
        else:
            report = verify_healthy_status_package(
                arguments.package,
                runtime_package=arguments.runtime,
                source_reference=arguments.source_reference,
            )
    except (OSError, ValueError, PublicationArtifactError) as exc:
        print(f"M5 publication provisioning error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
