"""Environment-backed workload identity bindings for segmented runtimes."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .workload_identity import (
    ResolvedWorkloadIdentity,
    WorkloadCredentialBinding,
    WorkloadIdentityError,
    WorkloadIdentityUnavailable,
    WorkloadIdentityVerifier,
    WorkloadRole,
    WorkloadSigner,
)


def workload_identity_enabled() -> bool:
    """Return whether lifecycle identity is required for this runtime.

    The closed values deliberately avoid truthy parsing. A misspelling must
    not silently reactivate the static-key path. Legacy experiment launchers
    set ``disabled`` explicitly; the M4g identity overlay sets ``required``.
    """

    mode = os.getenv("AEGIS_WORKLOAD_IDENTITY_MODE")
    if mode == "required":
        return True
    if mode == "disabled":
        return False
    raise WorkloadIdentityError(
        "workload identity mode must be required or disabled; configure it explicitly"
    )


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise WorkloadIdentityUnavailable(
            f"required workload identity setting is missing: {name}"
        )
    return value


def _public_key(path: Path) -> Ed25519PublicKey:
    try:
        material = path.read_bytes()
    except OSError as exc:
        raise WorkloadIdentityUnavailable("workload trust root is unavailable") from exc
    if len(material) != 32:
        raise WorkloadIdentityUnavailable(
            "workload trust root must contain exactly 32 raw bytes"
        )
    return Ed25519PublicKey.from_public_bytes(material)


def verifier_from_environment() -> WorkloadIdentityVerifier:
    return WorkloadIdentityVerifier(
        trust_root_public_key=_public_key(
            Path(_required("AEGIS_WORKLOAD_TRUST_ROOT_PUBLIC_KEY_FILE"))
        ),
        trust_root_key_id=_required("AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID"),
        trust_domain=_required("AEGIS_WORKLOAD_TRUST_DOMAIN"),
        trust_bundle_path=Path(_required("AEGIS_WORKLOAD_TRUST_BUNDLE_FILE")),
        trust_sequence_state_path=Path(
            _required("AEGIS_WORKLOAD_TRUST_SEQUENCE_STATE_FILE")
        ),
    )


def credential_binding_from_environment(
    verifier: WorkloadIdentityVerifier,
    prefix: str,
    *,
    role: WorkloadRole,
    audience: str,
) -> WorkloadCredentialBinding:
    return WorkloadCredentialBinding(
        verifier=verifier,
        credential_path=Path(_required(f"AEGIS_{prefix}_WORKLOAD_CREDENTIAL_FILE")),
        expected_role=role,
        expected_audience=audience,
        expected_subject=_required(f"AEGIS_{prefix}_WORKLOAD_SUBJECT"),
        expected_actor_id=(
            _required(f"AEGIS_{prefix}_ACTOR_ID")
            if role is WorkloadRole.AGENT
            else None
        ),
    )


@dataclass(frozen=True)
class LocalWorkloadIdentity:
    binding: WorkloadCredentialBinding
    signer: WorkloadSigner

    def resolve(self, *, now: datetime | None = None) -> ResolvedWorkloadIdentity:
        """Resolve the local credential at the caller's trust-decision time."""

        resolved = self.binding.resolve(now=now)
        if resolved.key_id != self.signer.credential.credential.key_id:
            raise WorkloadIdentityUnavailable(
                "local workload credential changed without its signer"
            )
        if (
            resolved.public_key.public_bytes_raw()
            != self.signer.private_key.public_key().public_bytes_raw()
        ):
            raise WorkloadIdentityUnavailable(
                "local workload signer no longer matches its credential"
            )
        return resolved


def local_identity_from_environment(
    verifier: WorkloadIdentityVerifier,
    prefix: str,
    *,
    role: WorkloadRole,
    audience: str,
) -> LocalWorkloadIdentity:
    binding = credential_binding_from_environment(
        verifier,
        prefix,
        role=role,
        audience=audience,
    )
    signer = WorkloadSigner.from_files(
        binding.credential_path,
        Path(_required(f"AEGIS_{prefix}_WORKLOAD_PRIVATE_KEY_FILE")),
    )
    identity = LocalWorkloadIdentity(binding=binding, signer=signer)
    identity.resolve()
    return identity
