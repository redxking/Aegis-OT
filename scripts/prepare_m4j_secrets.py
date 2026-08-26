#!/usr/bin/env python3
"""Create one private, source-bound M4j deployment-secret package.

The package is an operator input, not deployment evidence.  It deliberately
retains the workload authority private key only at the controller boundary so
short-lived application credentials can be renewed without copying that key to
any managed host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_ot.m4g_identity_init import initialize
from aegis_ot.workload_identity import workload_key_id

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "aegis-ot-m4j-deployment-secrets-v1"
MANIFEST_NAME = "secrets-manifest.json"
TRUST_DOMAIN = "aegis-ot.m4g.local"
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
KEY_NAMES = (
    "workload_authority",
    "agent",
    "gateway",
    "ot",
    "permit",
    "observer",
    "candidate",
    "plant",
)
STATIC_KEY_IDS = {
    "permit": "m4g-permit-key-v1",
    "observer": "m4g-observer-key-v1",
    "candidate": "m4g-candidate-key-v1",
    "plant": "m4g-plant-key-v1",
}


class SecretPackageError(RuntimeError):
    """The private M4j secret package could not be created safely."""


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _write_private(path: Path, material: bytes) -> None:
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
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                raise SecretPackageError("secret-package write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SecretPackageError(f"secret-package artifact is not private: {path.name}")


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


def _resolve_commit(reference: str) -> str:
    if (
        not reference
        or reference != reference.strip()
        or reference.startswith("-")
        or len(reference) > 512
        or any(character.isspace() or ord(character) < 32 for character in reference)
    ):
        raise SecretPackageError("source commit reference is malformed")
    git = shutil.which("git")
    if git is None:
        raise SecretPackageError("Git executable is unavailable")
    completed = subprocess.run(  # noqa: S603 - resolved Git executable and fixed argv
        (
            git,
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            f"{reference}^{{commit}}",
        ),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    commit = completed.stdout.strip()
    if completed.returncode != 0 or GIT_OBJECT.fullmatch(commit) is None:
        raise SecretPackageError("source commit did not resolve to an exact Git commit")
    return commit


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_output(output: Path) -> Path:
    if output.exists() or output.is_symlink():
        raise SecretPackageError("refusing to overwrite a secret-package path")
    parent = output.parent.resolve(strict=True)
    if parent.is_symlink() or not parent.is_dir():
        raise SecretPackageError("secret-package parent must be a real directory")
    resolved = parent / output.name
    if output.name in {"", ".", ".."} or _is_within(resolved, ROOT.resolve()):
        raise SecretPackageError("secret packages must be created outside the checkout")
    return resolved


@contextmanager
def _installed_environment(values: dict[str, str]) -> Iterator[None]:
    previous = {name: os.environ.get(name) for name in values}
    try:
        os.environ.update(values)
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _file_evidence(root: Path, path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SecretPackageError("secret-package files must be regular mode-0600 files")
    material = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(material).hexdigest(),
        "size_bytes": len(material),
    }


def create_secret_package(
    output: Path,
    *,
    source_reference: str,
    credential_ttl_seconds: int = 86_400,
) -> dict[str, Any]:
    if not 600 <= credential_ttl_seconds <= 86_400:
        raise SecretPackageError("credential TTL must be between 600 and 86400 seconds")
    destination = _validate_output(output)
    source_commit = _resolve_commit(source_reference)
    try:
        destination.mkdir(mode=0o700)
        destination.chmod(0o700)
    except OSError as exc:
        raise SecretPackageError("secret-package directory could not be created") from exc
    if stat.S_IMODE(destination.lstat().st_mode) != 0o700:
        raise SecretPackageError("secret-package directory is not private mode 0700")

    published = False
    try:
        keys: dict[str, Ed25519PrivateKey] = {}
        for name in KEY_NAMES:
            key = Ed25519PrivateKey.generate()
            keys[name] = key
            _write_private(destination / f"{name}.private", _raw_private(key))
            _write_private(destination / f"{name}.public", _raw_public(key))

        identity_directory = destination / "identity"
        identity_directory.mkdir(mode=0o700)
        identity_directory.chmod(0o700)
        now = datetime.now(UTC)
        identity_environment = {
            "AEGIS_WORKLOAD_IDENTITY_DIRECTORY": str(identity_directory),
            "AEGIS_WORKLOAD_AUTHORITY_PRIVATE_KEY_FILE": str(
                destination / "workload_authority.private"
            ),
            "AEGIS_AGENT_PUBLIC_KEY_FILE": str(destination / "agent.public"),
            "AEGIS_GATEWAY_PUBLIC_KEY_FILE": str(destination / "gateway.public"),
            "AEGIS_OT_PUBLIC_KEY_FILE": str(destination / "ot.public"),
            "AEGIS_WORKLOAD_TRUST_DOMAIN": TRUST_DOMAIN,
            "AEGIS_AGENT_WORKLOAD_SUBJECT": "urn:aegis-ot:m4g:workload:agent-probe",
            "AEGIS_GATEWAY_WORKLOAD_SUBJECT": "urn:aegis-ot:m4g:workload:gateway",
            "AEGIS_OT_WORKLOAD_SUBJECT": "urn:aegis-ot:m4g:workload:ot-adapter",
            "AEGIS_WORKLOAD_CREDENTIAL_TTL_SECONDS": str(credential_ttl_seconds),
            "AEGIS_WORKLOAD_BUNDLE_TTL_SECONDS": str(credential_ttl_seconds),
            "AEGIS_RUNTIME_UID": str(os.getuid()),
            "AEGIS_RUNTIME_GID": str(os.getgid()),
        }
        with _installed_environment(identity_environment):
            identity = initialize(now=now)

        key_ids = {
            name: workload_key_id(keys[name].public_key())
            for name in ("workload_authority", "agent", "gateway", "ot")
        }
        key_ids.update(STATIC_KEY_IDS)
        artifact_paths = sorted(
            path
            for path in destination.rglob("*")
            if path.is_file() and path.name != MANIFEST_NAME
        )
        files = {
            evidence["path"]: evidence
            for evidence in (_file_evidence(destination, path) for path in artifact_paths)
        }
        credential_expirations = {
            role: value["expires_at"] for role, value in identity["credentials"].items()
        }
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "source_git_commit": source_commit,
            "created_at": now.isoformat(),
            "trust_domain": TRUST_DOMAIN,
            "key_ids": key_ids,
            "identity": {
                "authority_key_id": identity["authority_key_id"],
                "trust_bundle_expires_at": identity["trust_bundle"]["expires_at"],
                "credential_expires_at": credential_expirations,
            },
            "files": dict(sorted(files.items())),
            "distribution_boundary": {
                "controller_only": ["workload_authority.private"],
                "host_delivery": "least_privilege_per_service_only",
                "join_tokens_included": False,
                "not_established": ["deployment", "runtime_acceptance"],
            },
        }
        _write_private(destination / MANIFEST_NAME, _canonical_bytes(manifest))
        directory_descriptor = os.open(destination, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        published = True
        return manifest
    finally:
        if not published and destination.exists() and not destination.is_symlink():
            shutil.rmtree(destination)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", default="HEAD")
    parser.add_argument("--credential-ttl-seconds", type=int, default=86_400)
    arguments = parser.parse_args()
    manifest = create_secret_package(
        arguments.output,
        source_reference=arguments.source_commit,
        credential_ttl_seconds=arguments.credential_ttl_seconds,
    )
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "schema_version": manifest["schema_version"],
                "source_git_commit": manifest["source_git_commit"],
                "secret_material_printed": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
