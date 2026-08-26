#!/usr/bin/env python3
"""Create a private local signing identity for the configured M4j builder.

This establishes only a local, operator-configured builder authority.  A
signature made with this identity does not establish independent provenance,
an externally operated builder, or that a build was executed correctly.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "aegis-ot-m4j-local-builder-identity-v1"
PRIVATE_KEY_NAME = "builder.private"
PUBLIC_KEY_NAME = "builder.public"
_STAGING_PREFIX = ".m4j-builder-identity-"


class BuilderIdentityError(RuntimeError):
    """A local builder identity could not be created safely."""


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


def _reject_symlink_components(path: Path) -> None:
    """Reject an existing symlink anywhere in an absolute parent path."""

    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise BuilderIdentityError("builder-identity parent is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise BuilderIdentityError("builder-identity parent must not contain symlinks")


def _target_exists(parent_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise BuilderIdentityError("builder-identity output could not be inspected") from exc
    return True


def _open_safe_parent(output: Path) -> tuple[Path, int]:
    if not output.is_absolute():
        raise BuilderIdentityError("builder-identity output must be an absolute path")
    if output.name in {"", ".", ".."}:
        raise BuilderIdentityError("builder-identity output name is invalid")

    _reject_symlink_components(output.parent)
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise BuilderIdentityError("builder-identity parent is unavailable") from exc
    destination = parent / output.name
    try:
        destination.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    except OSError as exc:
        raise BuilderIdentityError("checkout boundary could not be resolved") from exc
    else:
        raise BuilderIdentityError("builder identity must be created outside the checkout")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_descriptor = os.open(parent, flags)
    except OSError as exc:
        raise BuilderIdentityError("builder-identity parent could not be opened safely") from exc

    try:
        metadata = os.fstat(parent_descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISDIR(metadata.st_mode):
            raise BuilderIdentityError("builder-identity parent is not a directory")
        if metadata.st_uid != _current_uid():
            raise BuilderIdentityError("builder-identity parent must be owned by the current user")
        if mode & stat.S_IRWXU != stat.S_IRWXU or mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise BuilderIdentityError(
                "builder-identity parent must grant the owner rwx and deny group/other writes"
            )
        if _target_exists(parent_descriptor, output.name):
            raise BuilderIdentityError("refusing to overwrite a builder-identity path")
    except BaseException:
        os.close(parent_descriptor)
        raise
    return destination, parent_descriptor


def _write_raw_key(
    directory_descriptor: int,
    name: str,
    material: bytes,
) -> None:
    if len(material) != 32:
        raise BuilderIdentityError("builder identity key material is not raw Ed25519")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
    except OSError as exc:
        raise BuilderIdentityError("builder identity key file could not be created") from exc
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                raise BuilderIdentityError("builder identity key write made no progress")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != _current_uid()
            or metadata.st_size != 32
        ):
            raise BuilderIdentityError(
                "builder identity key must be an owned mode-0600 32-byte regular file"
            )
    except OSError as exc:
        raise BuilderIdentityError("builder identity key could not be written durably") from exc
    finally:
        os.close(descriptor)


def _cleanup_staging(
    parent_descriptor: int,
    staging_descriptor: int | None,
    staging_name: str,
) -> None:
    if staging_descriptor is not None:
        for name in (PRIVATE_KEY_NAME, PUBLIC_KEY_NAME):
            try:
                os.unlink(name, dir_fd=staging_descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass
    try:
        os.rmdir(staging_name, dir_fd=parent_descriptor)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _publish_directory_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing any existing path."""

    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    result: int
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise BuilderIdentityError("atomic no-replace publication is unavailable")
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = int(renamex_np(source_bytes, destination_bytes, 0x00000004))
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise BuilderIdentityError("atomic no-replace publication is unavailable")
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
            raise BuilderIdentityError(
                "refusing to overwrite a builder-identity path"
            ) from exc
        except OSError as exc:
            raise BuilderIdentityError(
                "builder identity could not be atomically published"
            ) from exc
        return
    else:  # pragma: no cover - fail closed on an unknown publication primitive
        raise BuilderIdentityError("atomic no-replace publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise BuilderIdentityError("refusing to overwrite a builder-identity path")
    raise BuilderIdentityError(
        f"builder identity could not be atomically published: {os.strerror(error_number)}"
    )


def create_builder_identity(output: Path) -> dict[str, Any]:
    """Atomically publish a new local builder keypair and public metadata."""

    destination, parent_descriptor = _open_safe_parent(output)
    staging_name = f"{_STAGING_PREFIX}{secrets.token_hex(16)}"
    staging_descriptor: int | None = None
    published = False
    try:
        try:
            os.mkdir(staging_name, mode=0o700, dir_fd=parent_descriptor)
        except OSError as exc:
            raise BuilderIdentityError(
                "private builder-identity staging directory could not be created"
            ) from exc
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            staging_descriptor = os.open(
                staging_name,
                flags,
                dir_fd=parent_descriptor,
            )
            os.fchmod(staging_descriptor, 0o700)
        except OSError as exc:
            raise BuilderIdentityError(
                "private builder-identity staging directory could not be opened"
            ) from exc
        directory_metadata = os.fstat(staging_descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or directory_metadata.st_uid != _current_uid()
        ):
            raise BuilderIdentityError(
                "builder-identity directory must be owned mode 0700"
            )

        key = Ed25519PrivateKey.generate()
        private_material = _raw_private(key)
        public_material = _raw_public(key)
        _write_raw_key(staging_descriptor, PRIVATE_KEY_NAME, private_material)
        _write_raw_key(staging_descriptor, PUBLIC_KEY_NAME, public_material)
        os.fsync(staging_descriptor)

        if _target_exists(parent_descriptor, destination.name):
            raise BuilderIdentityError("refusing to overwrite a builder-identity path")
        _publish_directory_noreplace(
            destination.with_name(staging_name),
            destination,
        )
        published = True
        os.fsync(parent_descriptor)

        key_id = hashlib.sha256(public_material).hexdigest()
        return {
            "schema_version": SCHEMA_VERSION,
            "output_directory": str(destination),
            "authority": {
                "type": "local_configured_builder_authority",
                "algorithm": "Ed25519",
                "key_id": key_id,
                "public_key_path": str(destination / PUBLIC_KEY_NAME),
                "public_key_encoding": "raw",
                "public_key_size_bytes": len(public_material),
            },
            "claim_boundary": {
                "establishes": "local operator-configured builder signing authority",
                "does_not_establish": [
                    "independent provenance",
                    "external builder identity",
                    "correct source-to-image build execution",
                ],
            },
            "secret_material_printed": False,
        }
    except OSError as exc:
        raise BuilderIdentityError("builder identity could not be created durably") from exc
    finally:
        if not published:
            _cleanup_staging(parent_descriptor, staging_descriptor, staging_name)
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        os.close(parent_descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help=(
            "new absolute mode-0700 directory outside the checkout; its parent "
            "must be current-user-owned and not group/other writable"
        ),
    )
    arguments = parser.parse_args()
    try:
        metadata = create_builder_identity(arguments.output)
    except BuilderIdentityError as exc:
        parser.error(str(exc))
    print(json.dumps(metadata, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
