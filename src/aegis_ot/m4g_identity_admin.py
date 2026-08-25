"""Offline rotation and revocation publisher for M4g workload identities.

Both operations derive their next trust state from the currently published,
authority-signed bundle.  The sequence is always exactly ``current + 1``.  A
rotation certifies an externally provisioned leaf public key; this job never
generates, receives, or writes a workload runtime private key.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .m4g_identity_init import (
    CREDENTIAL_FILENAMES,
    DEFAULT_LIFETIME_SECONDS,
    MAX_LIFETIME_SECONDS,
    _atomic_replace,
    _credential_summary,
    _evaluated_at,
    _issue_credential,
    _load_authority_private_key,
    _load_leaf_public_key,
)
from .workload_identity import (
    SignedWorkloadCredential,
    WorkloadRevocation,
    WorkloadRole,
    WorkloadTrustBundle,
    canonical_json_file_bytes,
    load_signed_workload_credential,
    load_workload_trust_bundle,
    public_key_base64,
    workload_key_id,
)


def _lifetime(seconds: int, *, label: str) -> timedelta:
    if not 1 <= seconds <= MAX_LIFETIME_SECONDS:
        raise RuntimeError(f"{label} must be between 1 and {MAX_LIFETIME_SECONDS}")
    return timedelta(seconds=seconds)


def _reason(value: str) -> str:
    if not value or value != value.strip() or len(value) > 256:
        raise RuntimeError("workload revocation reason must be 1-256 trimmed characters")
    return value


@contextmanager
def _publication_lock(bundle_path: Path) -> Iterator[None]:
    lock_path = bundle_path.with_name(f".{bundle_path.name}.admin.lock")
    descriptor = -1
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except OSError as exc:
        raise RuntimeError("M4g identity administration lock is unavailable") from exc
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _trusted_admin_state(
    *,
    authority_private_key: Ed25519PrivateKey,
    bundle_path: Path,
    evaluated_at: datetime,
    expected_sequence: int | None,
) -> WorkloadTrustBundle:
    bundle = load_workload_trust_bundle(bundle_path)
    authority_public_key = authority_private_key.public_key()
    if (
        bundle.authority_key_id != workload_key_id(authority_public_key)
        or bundle.authority_public_key_b64 != public_key_base64(authority_public_key)
        or not bundle.verify(authority_public_key)
    ):
        raise RuntimeError("authority private key does not control the published trust bundle")
    if bundle.issued_at > evaluated_at:
        raise RuntimeError("identity administration clock is earlier than published state")
    if expected_sequence is not None and bundle.sequence != expected_sequence:
        raise RuntimeError(
            f"published trust-bundle sequence is {bundle.sequence}, expected {expected_sequence}"
        )
    return bundle


def _require_external_authority_secret(
    authority_private_key_path: Path,
    bundle_path: Path,
) -> None:
    try:
        authority_path = authority_private_key_path.resolve(strict=True)
        identity_directory = bundle_path.parent.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("M4g identity administration path is unavailable") from exc
    if authority_path == identity_directory or authority_path.is_relative_to(
        identity_directory
    ):
        raise RuntimeError(
            "authority private key must remain outside the runtime identity directory"
        )


def _trusted_credential(
    path: Path,
    *,
    bundle: WorkloadTrustBundle,
    authority_public_key: Ed25519PublicKey,
) -> SignedWorkloadCredential:
    signed = load_signed_workload_credential(path)
    credential = signed.credential
    if (
        credential.trust_domain != bundle.trust_domain
        or credential.authority_key_id != bundle.authority_key_id
        or not signed.verify(authority_public_key)
    ):
        raise RuntimeError("workload credential is outside the published authority state")
    return signed


def _next_bundle(
    current: WorkloadTrustBundle,
    *,
    authority_private_key: Ed25519PrivateKey,
    issued_at: datetime,
    lifetime: timedelta,
    added_revocation: WorkloadRevocation,
    retain_existing_revocation: bool = False,
) -> WorkloadTrustBundle:
    already_revoked = any(
        item.credential_id == added_revocation.credential_id
        for item in current.revocations
    )
    if already_revoked and not retain_existing_revocation:
        raise RuntimeError("workload credential is already revoked")
    revocations = current.revocations
    if not already_revoked:
        revocations = tuple(
            sorted(
                (*current.revocations, added_revocation),
                key=lambda item: item.credential_id,
            )
        )
    return WorkloadTrustBundle(
        bundle_id=f"bundle-{uuid4().hex}",
        sequence=current.sequence + 1,
        trust_domain=current.trust_domain,
        authority_key_id=current.authority_key_id,
        authority_public_key_b64=current.authority_public_key_b64,
        issued_at=issued_at,
        expires_at=issued_at + lifetime,
        revocations=revocations,
    ).signed(authority_private_key)


def _published_peer_keys(
    *,
    bundle_path: Path,
    credential_path: Path,
    bundle: WorkloadTrustBundle,
    authority_public_key: Ed25519PublicKey,
) -> dict[WorkloadRole, Ed25519PublicKey]:
    """Load every other canonical role credential under the published state."""

    try:
        target = credential_path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("workload credential path is unavailable") from exc
    peers: dict[WorkloadRole, Ed25519PublicKey] = {}
    for role, filename in CREDENTIAL_FILENAMES.items():
        peer_path = bundle_path.parent / filename
        try:
            peer_target = peer_path.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError(
                f"published {role.value} workload credential is unavailable"
            ) from exc
        if peer_target == target:
            continue
        peer = _trusted_credential(
            peer_path,
            bundle=bundle,
            authority_public_key=authority_public_key,
        )
        if peer.credential.role is not role:
            raise RuntimeError(
                f"published {role.value} credential has the wrong workload role"
            )
        peers[role] = peer.credential.public_key
    return peers


def rotate_credential(
    *,
    authority_private_key_path: Path,
    bundle_path: Path,
    credential_path: Path,
    leaf_public_key_path: Path,
    reason: str = "leaf key rotation",
    credential_lifetime_seconds: int = DEFAULT_LIFETIME_SECONDS,
    bundle_lifetime_seconds: int = DEFAULT_LIFETIME_SECONDS,
    expected_sequence: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Publish a rotated credential and an N+1 bundle revoking its predecessor."""

    issued_at = _evaluated_at(now)
    credential_lifetime = _lifetime(
        credential_lifetime_seconds,
        label="workload credential lifetime",
    )
    bundle_lifetime = _lifetime(
        bundle_lifetime_seconds,
        label="workload trust-bundle lifetime",
    )
    if bundle_lifetime < credential_lifetime:
        raise RuntimeError("workload trust-bundle lifetime must cover credential lifetime")
    checked_reason = _reason(reason)
    _require_external_authority_secret(authority_private_key_path, bundle_path)
    authority_private_key = _load_authority_private_key(authority_private_key_path)

    with _publication_lock(bundle_path):
        current_bundle = _trusted_admin_state(
            authority_private_key=authority_private_key,
            bundle_path=bundle_path,
            evaluated_at=issued_at,
            expected_sequence=expected_sequence,
        )
        current_credential = _trusted_credential(
            credential_path,
            bundle=current_bundle,
            authority_public_key=authority_private_key.public_key(),
        )
        new_public_key = _load_leaf_public_key(leaf_public_key_path)
        authority_public_key = authority_private_key.public_key()
        if (
            new_public_key.public_bytes_raw()
            == current_credential.credential.public_key.public_bytes_raw()
        ):
            raise RuntimeError("workload rotation requires a different leaf public key")
        if new_public_key.public_bytes_raw() == authority_public_key.public_bytes_raw():
            raise RuntimeError("workload rotation leaf conflicts with the authority key")
        for role, peer_public_key in _published_peer_keys(
            bundle_path=bundle_path,
            credential_path=credential_path,
            bundle=current_bundle,
            authority_public_key=authority_public_key,
        ).items():
            if new_public_key.public_bytes_raw() == peer_public_key.public_bytes_raw():
                raise RuntimeError(
                    "workload rotation leaf conflicts with the published "
                    f"{role.value} key"
                )

        credential = current_credential.credential
        rotated = _issue_credential(
            authority_private_key=authority_private_key,
            trust_domain=credential.trust_domain,
            subject=credential.subject,
            role=credential.role,
            audiences=credential.audiences,
            public_key=new_public_key,
            issued_at=issued_at,
            lifetime=credential_lifetime,
        )
        next_bundle = _next_bundle(
            current_bundle,
            authority_private_key=authority_private_key,
            issued_at=issued_at,
            lifetime=bundle_lifetime,
            added_revocation=WorkloadRevocation(
                credential_id=credential.credential_id,
                revoked_at=issued_at,
                reason=checked_reason,
            ),
            retain_existing_revocation=True,
        )

        # Publish predecessor revocation first.  A crash before credential
        # replacement therefore leaves a recoverable fail-closed outage rather
        # than an unrevoked predecessor credential.
        _atomic_replace(bundle_path, canonical_json_file_bytes(next_bundle))
        _atomic_replace(credential_path, canonical_json_file_bytes(rotated))

    return {
        "schema_version": "m4g-workload-identity-administration-v1",
        "operation": "rotate",
        "trust_domain": next_bundle.trust_domain,
        "prior_sequence": current_bundle.sequence,
        "published_sequence": next_bundle.sequence,
        "bundle_id": next_bundle.bundle_id,
        "bundle_expires_at": next_bundle.expires_at.isoformat(),
        "revoked_credential_id": current_credential.credential.credential_id,
        "credential": _credential_summary(credential_path, rotated),
        "runtime_private_key_written": False,
    }


def revoke_credential(
    *,
    authority_private_key_path: Path,
    bundle_path: Path,
    credential_path: Path,
    reason: str,
    bundle_lifetime_seconds: int = DEFAULT_LIFETIME_SECONDS,
    expected_sequence: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Publish an N+1 bundle that immediately revokes one signed credential."""

    issued_at = _evaluated_at(now)
    bundle_lifetime = _lifetime(
        bundle_lifetime_seconds,
        label="workload trust-bundle lifetime",
    )
    checked_reason = _reason(reason)
    _require_external_authority_secret(authority_private_key_path, bundle_path)
    authority_private_key = _load_authority_private_key(authority_private_key_path)

    with _publication_lock(bundle_path):
        current_bundle = _trusted_admin_state(
            authority_private_key=authority_private_key,
            bundle_path=bundle_path,
            evaluated_at=issued_at,
            expected_sequence=expected_sequence,
        )
        credential = _trusted_credential(
            credential_path,
            bundle=current_bundle,
            authority_public_key=authority_private_key.public_key(),
        )
        next_bundle = _next_bundle(
            current_bundle,
            authority_private_key=authority_private_key,
            issued_at=issued_at,
            lifetime=bundle_lifetime,
            added_revocation=WorkloadRevocation(
                credential_id=credential.credential.credential_id,
                revoked_at=issued_at,
                reason=checked_reason,
            ),
        )
        _atomic_replace(bundle_path, canonical_json_file_bytes(next_bundle))

    return {
        "schema_version": "m4g-workload-identity-administration-v1",
        "operation": "revoke",
        "trust_domain": next_bundle.trust_domain,
        "prior_sequence": current_bundle.sequence,
        "published_sequence": next_bundle.sequence,
        "bundle_id": next_bundle.bundle_id,
        "bundle_expires_at": next_bundle.expires_at.isoformat(),
        "revoked_credential_id": credential.credential.credential_id,
        "runtime_private_key_written": False,
    }


def _environment_path(name: str) -> Path | None:
    value = os.getenv(name)
    return Path(value) if value else None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("rotate", "revoke"):
        subparser = subparsers.add_parser(operation)
        authority_default = _environment_path(
            "AEGIS_WORKLOAD_AUTHORITY_PRIVATE_KEY_FILE"
        )
        bundle_default = _environment_path("AEGIS_WORKLOAD_TRUST_BUNDLE_FILE")
        subparser.add_argument(
            "--authority-private-key-file",
            type=Path,
            default=authority_default,
            required=authority_default is None,
        )
        subparser.add_argument(
            "--trust-bundle-file",
            type=Path,
            default=bundle_default,
            required=bundle_default is None,
        )
        subparser.add_argument("--credential-file", type=Path, required=True)
        subparser.add_argument("--reason", required=operation == "revoke")
        subparser.add_argument(
            "--bundle-ttl-seconds",
            type=int,
            default=int(
                os.getenv(
                    "AEGIS_WORKLOAD_BUNDLE_TTL_SECONDS",
                    str(DEFAULT_LIFETIME_SECONDS),
                )
            ),
        )
        subparser.add_argument("--expected-sequence", type=int)
        if operation == "rotate":
            subparser.add_argument("--leaf-public-key-file", type=Path, required=True)
            subparser.add_argument(
                "--credential-ttl-seconds",
                type=int,
                default=int(
                    os.getenv(
                        "AEGIS_WORKLOAD_CREDENTIAL_TTL_SECONDS",
                        str(DEFAULT_LIFETIME_SECONDS),
                    )
                ),
            )
    return parser


def main() -> None:
    arguments = _parser().parse_args()
    common = {
        "authority_private_key_path": arguments.authority_private_key_file,
        "bundle_path": arguments.trust_bundle_file,
        "credential_path": arguments.credential_file,
        "reason": arguments.reason or "leaf key rotation",
        "bundle_lifetime_seconds": arguments.bundle_ttl_seconds,
        "expected_sequence": arguments.expected_sequence,
    }
    if arguments.operation == "rotate":
        result = rotate_credential(
            **common,
            leaf_public_key_path=arguments.leaf_public_key_file,
            credential_lifetime_seconds=arguments.credential_ttl_seconds,
        )
    else:
        result = revoke_credential(**common)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
