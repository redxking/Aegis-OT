"""Offline initializer for the M4g application workload-identity artifacts.

The authority private key is an input secret.  It is never copied into the
runtime identity directory.  Existing workload leaf public keys are certified
so that the corresponding private keys remain under the runner's existing
secret-management boundary.
"""

from __future__ import annotations

import json
import os
import stat
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    OT_CAPABILITY_AUDIENCE,
)
from .workload_identity import (
    SignedWorkloadCredential,
    WorkloadCredential,
    WorkloadRole,
    WorkloadTrustBundle,
    canonical_json_file_bytes,
    public_key_base64,
    workload_key_id,
)

MAX_LIFETIME_SECONDS = 24 * 60 * 60
DEFAULT_LIFETIME_SECONDS = 60 * 60

AUTHORITY_PUBLIC_FILENAME = "authority.public"
TRUST_BUNDLE_FILENAME = "trust-bundle.json"
CREDENTIAL_FILENAMES = {
    WorkloadRole.AGENT: "agent.credential.json",
    WorkloadRole.GATEWAY: "gateway.credential.json",
    WorkloadRole.OT_ADAPTER: "ot.credential.json",
}


def _required_environment(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value:
        raise RuntimeError(f"required M4g identity setting is missing: {name}")
    return value


def _lifetime_from_environment(name: str) -> timedelta:
    raw_value = os.getenv(name, str(DEFAULT_LIFETIME_SECONDS))
    try:
        seconds = int(raw_value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer number of seconds") from exc
    if not 1 <= seconds <= MAX_LIFETIME_SECONDS:
        raise RuntimeError(f"{name} must be between 1 and {MAX_LIFETIME_SECONDS}")
    return timedelta(seconds=seconds)


def _evaluated_at(value: datetime | None) -> datetime:
    evaluated = value or datetime.now(UTC)
    if evaluated.tzinfo is None:
        raise RuntimeError("M4g identity publication time must be timezone-aware")
    return evaluated.astimezone(UTC)


def _read_exact_regular_file(path: Path, *, length: int, label: str) -> bytes:
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise RuntimeError(f"{label} must be a regular file: {path}")
    try:
        material = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable: {path}") from exc
    if len(material) != length:
        raise RuntimeError(f"{label} must contain exactly {length} raw bytes")
    return material


def _load_authority_private_key(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        _read_exact_regular_file(
            path,
            length=32,
            label="workload identity authority private key",
        )
    )


def _load_leaf_public_key(path: Path) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(
        _read_exact_regular_file(path, length=32, label="workload leaf public key")
    )


def _require_distinct_identity_keys(
    authority_public_key: Ed25519PublicKey,
    leaves: dict[WorkloadRole, Ed25519PublicKey],
) -> None:
    """Reject authority/leaf and cross-role key reuse before certification."""

    key_owners: dict[bytes, str] = {
        authority_public_key.public_bytes_raw(): "authority"
    }
    for role, public_key in leaves.items():
        material = public_key.public_bytes_raw()
        prior = key_owners.get(material)
        if prior is not None:
            raise RuntimeError(
                "workload identity signing keys must be distinct: "
                f"{prior} and {role.value} reuse one public key"
            )
        key_owners[material] = role.value


def _write_all(descriptor: int, material: bytes) -> None:
    offset = 0
    while offset < len(material):
        written = os.write(descriptor, material[offset:])
        if written <= 0:
            raise OSError("identity artifact write made no progress")
        offset += written


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_temporary(path: Path, material: bytes) -> Path:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, material)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise RuntimeError(f"M4g identity artifact could not be staged: {path}") from exc
    return temporary


def _atomic_create(path: Path, material: bytes) -> None:
    """Publish a fully persisted file without an overwrite race."""

    temporary = _write_temporary(path, material)
    linked = False
    try:
        os.link(temporary, path, follow_symlinks=False)
        linked = True
        temporary.unlink()
        _fsync_directory(path.parent)
    except FileExistsError as exc:
        raise RuntimeError(f"M4g identity initializer refuses overwrite: {path}") from exc
    except OSError as exc:
        if linked:
            with suppress(FileNotFoundError):
                path.unlink()
        raise RuntimeError(f"M4g identity artifact could not be published: {path}") from exc
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _atomic_replace(path: Path, material: bytes) -> None:
    """Persist and atomically replace one existing, non-symlink artifact."""

    try:
        target_stat = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"M4g identity artifact is unavailable: {path}") from exc
    if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
        raise RuntimeError(f"M4g identity artifact must be a regular file: {path}")
    temporary = _write_temporary(path, material)
    replaced = False
    try:
        os.chown(temporary, target_stat.st_uid, target_stat.st_gid)
        temporary.chmod(0o600)
        os.replace(temporary, path)
        replaced = True
        _fsync_directory(path.parent)
    except OSError as exc:
        raise RuntimeError(f"M4g identity artifact could not be replaced: {path}") from exc
    finally:
        if not replaced:
            with suppress(FileNotFoundError):
                temporary.unlink()


def _prepare_empty_identity_directory(path: Path) -> None:
    try:
        directory_stat = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"M4g identity directory is unavailable: {path}") from exc
    if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
        raise RuntimeError(f"M4g identity path is not a directory: {path}")
    try:
        populated = any(path.iterdir())
    except OSError as exc:
        raise RuntimeError(f"M4g identity directory cannot be inspected: {path}") from exc
    if populated:
        raise RuntimeError(f"M4g identity initializer refuses nonempty directory: {path}")
    path.chmod(0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise RuntimeError(f"M4g identity directory mode was not set to 0700: {path}")


def _assign_runtime_file(path: Path, *, target_uid: int, target_gid: int) -> None:
    os.chown(path, target_uid, target_gid)
    path.chmod(0o600)
    file_stat = path.stat()
    if file_stat.st_uid != target_uid or file_stat.st_gid != target_gid:
        raise RuntimeError(f"M4g identity artifact ownership was not assigned: {path}")
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise RuntimeError(f"M4g identity artifact mode was not set to 0600: {path}")


def _assign_runtime_directory(path: Path, *, target_uid: int, target_gid: int) -> None:
    os.chown(path, target_uid, target_gid)
    path.chmod(0o700)
    directory_stat = path.stat()
    if directory_stat.st_uid != target_uid or directory_stat.st_gid != target_gid:
        raise RuntimeError("M4g identity directory ownership was not assigned to the runtime")
    if stat.S_IMODE(directory_stat.st_mode) != 0o700:
        raise RuntimeError("M4g identity directory mode was not set to 0700")


def _issue_credential(
    *,
    authority_private_key: Ed25519PrivateKey,
    trust_domain: str,
    subject: str,
    role: WorkloadRole,
    audiences: tuple[str, ...],
    public_key: Ed25519PublicKey,
    issued_at: datetime,
    lifetime: timedelta,
) -> SignedWorkloadCredential:
    authority_public_key = authority_private_key.public_key()
    credential = WorkloadCredential(
        credential_id=f"credential-{uuid4().hex}",
        trust_domain=trust_domain,
        subject=subject,
        role=role,
        key_id=workload_key_id(public_key),
        public_key_b64=public_key_base64(public_key),
        authority_key_id=workload_key_id(authority_public_key),
        audiences=tuple(sorted(set(audiences))),
        issued_at=issued_at,
        not_before=issued_at,
        expires_at=issued_at + lifetime,
    )
    return SignedWorkloadCredential.issue(credential, authority_private_key)


def _credential_summary(path: Path, signed: SignedWorkloadCredential) -> dict[str, Any]:
    credential = signed.credential
    return {
        "path": str(path),
        "credential_id": credential.credential_id,
        "subject": credential.subject,
        "role": credential.role.value,
        "key_id": credential.key_id,
        "audiences": list(credential.audiences),
        "expires_at": credential.expires_at.isoformat(),
    }


def initialize(*, now: datetime | None = None) -> dict[str, Any]:
    """Create one closed initial identity state from environment configuration."""

    issued_at = _evaluated_at(now)
    credential_lifetime = _lifetime_from_environment(
        "AEGIS_WORKLOAD_CREDENTIAL_TTL_SECONDS"
    )
    bundle_lifetime = _lifetime_from_environment("AEGIS_WORKLOAD_BUNDLE_TTL_SECONDS")
    if bundle_lifetime < credential_lifetime:
        raise RuntimeError("workload trust-bundle lifetime must cover credential lifetime")

    identity_directory = Path(_required_environment("AEGIS_WORKLOAD_IDENTITY_DIRECTORY"))
    _prepare_empty_identity_directory(identity_directory)
    authority_private_key = _load_authority_private_key(
        Path(_required_environment("AEGIS_WORKLOAD_AUTHORITY_PRIVATE_KEY_FILE"))
    )
    authority_public_key = authority_private_key.public_key()
    authority_key_id = workload_key_id(authority_public_key)
    trust_domain = _required_environment("AEGIS_WORKLOAD_TRUST_DOMAIN")
    try:
        target_uid = int(os.getenv("AEGIS_RUNTIME_UID", "65532"))
        target_gid = int(os.getenv("AEGIS_RUNTIME_GID", "65532"))
    except ValueError as exc:
        raise RuntimeError("M4g runtime UID and GID must be integers") from exc
    if target_uid < 0 or target_gid < 0:
        raise RuntimeError("M4g runtime UID and GID must be nonnegative integers")

    definitions = (
        (
            WorkloadRole.AGENT,
            _load_leaf_public_key(
                Path(_required_environment("AEGIS_AGENT_PUBLIC_KEY_FILE"))
            ),
            _required_environment("AEGIS_AGENT_WORKLOAD_SUBJECT"),
            (GATEWAY_CAPABILITY_AUDIENCE,),
        ),
        (
            WorkloadRole.GATEWAY,
            _load_leaf_public_key(
                Path(_required_environment("AEGIS_GATEWAY_PUBLIC_KEY_FILE"))
            ),
            _required_environment("AEGIS_GATEWAY_WORKLOAD_SUBJECT"),
            (OT_CAPABILITY_AUDIENCE,),
        ),
        (
            WorkloadRole.OT_ADAPTER,
            _load_leaf_public_key(
                Path(_required_environment("AEGIS_OT_PUBLIC_KEY_FILE"))
            ),
            _required_environment("AEGIS_OT_WORKLOAD_SUBJECT"),
            (GATEWAY_CAPABILITY_AUDIENCE,),
        ),
    )
    _require_distinct_identity_keys(
        authority_public_key,
        {role: public_key for role, public_key, _, _ in definitions},
    )
    credentials: dict[WorkloadRole, SignedWorkloadCredential] = {}
    for role, public_key, subject, audiences in definitions:
        credentials[role] = _issue_credential(
            authority_private_key=authority_private_key,
            trust_domain=trust_domain,
            subject=subject,
            role=role,
            audiences=audiences,
            public_key=public_key,
            issued_at=issued_at,
            lifetime=credential_lifetime,
        )

    bundle = WorkloadTrustBundle(
        bundle_id=f"bundle-{uuid4().hex}",
        sequence=1,
        trust_domain=trust_domain,
        authority_key_id=authority_key_id,
        authority_public_key_b64=public_key_base64(authority_public_key),
        issued_at=issued_at,
        expires_at=issued_at + bundle_lifetime,
    ).signed(authority_private_key)

    authority_public_path = identity_directory / AUTHORITY_PUBLIC_FILENAME
    trust_bundle_path = identity_directory / TRUST_BUNDLE_FILENAME
    credential_paths = {
        role: identity_directory / filename
        for role, filename in CREDENTIAL_FILENAMES.items()
    }
    artifacts = (
        (
            authority_public_path,
            authority_public_key.public_bytes_raw(),
        ),
        (trust_bundle_path, canonical_json_file_bytes(bundle)),
        *(
            (credential_paths[role], canonical_json_file_bytes(credentials[role]))
            for role in (
                WorkloadRole.AGENT,
                WorkloadRole.GATEWAY,
                WorkloadRole.OT_ADAPTER,
            )
        ),
    )
    created: list[Path] = []
    try:
        for path, material in artifacts:
            _atomic_create(path, material)
            created.append(path)
        for path in created:
            _assign_runtime_file(path, target_uid=target_uid, target_gid=target_gid)
        _assign_runtime_directory(
            identity_directory,
            target_uid=target_uid,
            target_gid=target_gid,
        )
    except Exception:
        for path in reversed(created):
            with suppress(FileNotFoundError):
                path.unlink()
        _fsync_directory(identity_directory)
        raise

    return {
        "schema_version": "m4g-workload-identity-initialization-v1",
        "identity_directory": str(identity_directory),
        "trust_domain": trust_domain,
        "authority_key_id": authority_key_id,
        "authority_public_key_file": str(authority_public_path),
        "trust_bundle": {
            "path": str(trust_bundle_path),
            "bundle_id": bundle.bundle_id,
            "sequence": bundle.sequence,
            "expires_at": bundle.expires_at.isoformat(),
        },
        "credentials": {
            role.value: _credential_summary(credential_paths[role], credentials[role])
            for role in (
                WorkloadRole.AGENT,
                WorkloadRole.GATEWAY,
                WorkloadRole.OT_ADAPTER,
            )
        },
        "directory_mode": "0700",
        "artifact_mode": "0600",
        "runtime_uid": target_uid,
        "runtime_gid": target_gid,
        "authority_private_key_retained": False,
    }


def main() -> None:
    print(json.dumps(initialize(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
