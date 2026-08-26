from __future__ import annotations

import errno
import json
import multiprocessing
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis_ot.workload_identity import (
    ResolvedWorkloadIdentity,
    SignedWorkloadCredential,
    WorkloadCredential,
    WorkloadCredentialBinding,
    WorkloadIdentityError,
    WorkloadIdentityVerifier,
    WorkloadRevocation,
    WorkloadRole,
    WorkloadSigner,
    WorkloadTrustBundle,
    canonical_json_file_bytes,
    load_signed_workload_credential,
    public_key_base64,
    workload_key_id,
)
from aegis_ot.workload_runtime import (
    LocalWorkloadIdentity,
    credential_binding_from_environment,
    local_identity_from_environment,
    verifier_from_environment,
    workload_identity_enabled,
)
from aegis_ot.workload_trust_state import WorkloadTrustSequenceState

NOW = datetime.now(UTC)
TRUST_DOMAIN = "aegis-ot.test"
GATEWAY_SUBJECT = "urn:aegis-ot:test:workload:gateway"
GATEWAY_AUDIENCE = "aegis-ot:m4g:ot-adapter"
AGENT_SUBJECT = "urn:aegis-ot:test:workload:agent-probe"
AGENT_ACTOR_ID = "agent:operator-1"


def _restart_verifier_worker(
    start: Any,
    results: Any,
    public_key_raw: bytes,
    authority_key_id: str,
    trust_bundle_path: str,
    trust_sequence_state_path: str,
    credential_path: str,
    evaluated_at: datetime,
) -> None:
    """Resolve one identity in a fresh interpreter against shared state."""

    start_event = start
    result_queue = results
    try:
        start_event.wait(timeout=10)
        verifier = WorkloadIdentityVerifier(
            trust_root_public_key=Ed25519PublicKey.from_public_bytes(public_key_raw),
            trust_root_key_id=authority_key_id,
            trust_domain=TRUST_DOMAIN,
            trust_bundle_path=Path(trust_bundle_path),
            trust_sequence_state_path=Path(trust_sequence_state_path),
        )
        verifier.verify_credential(
            load_signed_workload_credential(Path(credential_path)),
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=GATEWAY_AUDIENCE,
            expected_subject=GATEWAY_SUBJECT,
            now=evaluated_at,
        )
    except Exception as exc:  # pragma: no cover - returned to the parent assertion
        result_queue.put(f"{type(exc).__name__}: {exc}")
    else:
        result_queue.put("ok")


def _private_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _issue_credential(
    authority_private_key: Ed25519PrivateKey,
    leaf_private_key: Ed25519PrivateKey,
    *,
    credential_id: str = "credential-gateway-0001",
    subject: str = GATEWAY_SUBJECT,
    role: WorkloadRole = WorkloadRole.GATEWAY,
    actor_id: str | None = None,
    audiences: tuple[str, ...] = (GATEWAY_AUDIENCE,),
    issued_at: datetime = NOW - timedelta(minutes=5),
    not_before: datetime = NOW - timedelta(minutes=4),
    expires_at: datetime = NOW + timedelta(minutes=30),
) -> SignedWorkloadCredential:
    authority_key_id = workload_key_id(authority_private_key.public_key())
    leaf_public_key = leaf_private_key.public_key()
    credential = WorkloadCredential(
        credential_id=credential_id,
        trust_domain=TRUST_DOMAIN,
        subject=subject,
        role=role,
        actor_id=actor_id,
        key_id=workload_key_id(leaf_public_key),
        public_key_b64=public_key_base64(leaf_public_key),
        authority_key_id=authority_key_id,
        audiences=audiences,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
    )
    return SignedWorkloadCredential.issue(credential, authority_private_key)


def _issue_bundle(
    authority_private_key: Ed25519PrivateKey,
    *,
    sequence: int = 1,
    bundle_id: str = "identity-bundle-0001",
    issued_at: datetime = NOW - timedelta(minutes=5),
    expires_at: datetime = NOW + timedelta(hours=1),
    revocations: tuple[WorkloadRevocation, ...] = (),
) -> WorkloadTrustBundle:
    authority_public_key = authority_private_key.public_key()
    return WorkloadTrustBundle(
        bundle_id=bundle_id,
        sequence=sequence,
        trust_domain=TRUST_DOMAIN,
        authority_key_id=workload_key_id(authority_public_key),
        authority_public_key_b64=public_key_base64(authority_public_key),
        issued_at=issued_at,
        expires_at=expires_at,
        revocations=revocations,
    ).signed(authority_private_key)


def _write_identity_model(
    path: Path,
    value: SignedWorkloadCredential | WorkloadTrustBundle,
) -> None:
    path.write_bytes(canonical_json_file_bytes(value))


@dataclass(frozen=True)
class IdentityArtifacts:
    authority_private_key: Ed25519PrivateKey
    authority_key_id: str
    trust_root_path: Path
    trust_bundle_path: Path
    trust_sequence_state_path: Path
    credential_path: Path
    private_key_path: Path
    leaf_private_key: Ed25519PrivateKey
    signed_credential: SignedWorkloadCredential

    def verifier(self) -> WorkloadIdentityVerifier:
        return WorkloadIdentityVerifier(
            trust_root_public_key=self.authority_private_key.public_key(),
            trust_root_key_id=self.authority_key_id,
            trust_domain=TRUST_DOMAIN,
            trust_bundle_path=self.trust_bundle_path,
            trust_sequence_state_path=self.trust_sequence_state_path,
        )

    def binding(self, verifier: WorkloadIdentityVerifier) -> WorkloadCredentialBinding:
        return WorkloadCredentialBinding(
            verifier=verifier,
            credential_path=self.credential_path,
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=GATEWAY_AUDIENCE,
            expected_subject=GATEWAY_SUBJECT,
        )


@pytest.fixture
def identity(tmp_path: Path) -> IdentityArtifacts:
    authority_private_key = Ed25519PrivateKey.generate()
    leaf_private_key = Ed25519PrivateKey.generate()
    signed_credential = _issue_credential(authority_private_key, leaf_private_key)
    trust_root_path = tmp_path / "authority-public.key"
    trust_bundle_path = tmp_path / "trust-bundle.json"
    trust_sequence_directory = tmp_path / "trust-sequence"
    trust_sequence_directory.mkdir(mode=0o700)
    trust_sequence_directory.chmod(0o700)
    trust_sequence_state_path = trust_sequence_directory / "state.json"
    credential_path = tmp_path / "gateway-credential.json"
    private_key_path = tmp_path / "gateway-private.key"
    trust_root_path.write_bytes(_public_key_bytes(authority_private_key.public_key()))
    _write_identity_model(trust_bundle_path, _issue_bundle(authority_private_key))
    _write_identity_model(credential_path, signed_credential)
    private_key_path.write_bytes(_private_key_bytes(leaf_private_key))
    return IdentityArtifacts(
        authority_private_key=authority_private_key,
        authority_key_id=workload_key_id(authority_private_key.public_key()),
        trust_root_path=trust_root_path,
        trust_bundle_path=trust_bundle_path,
        trust_sequence_state_path=trust_sequence_state_path,
        credential_path=credential_path,
        private_key_path=private_key_path,
        leaf_private_key=leaf_private_key,
        signed_credential=signed_credential,
    )


def test_binding_resolves_valid_authority_signed_identity(
    identity: IdentityArtifacts,
) -> None:
    resolved = identity.binding(identity.verifier()).resolve(now=NOW)

    assert resolved.subject == GATEWAY_SUBJECT
    assert resolved.key_id == workload_key_id(identity.leaf_private_key.public_key())
    assert _public_key_bytes(resolved.public_key) == _public_key_bytes(
        identity.leaf_private_key.public_key()
    )


def test_credential_rejects_authority_key_as_workload_leaf() -> None:
    authority = Ed25519PrivateKey.generate()

    with pytest.raises(ValueError, match="leaf key must differ from the authority"):
        _issue_credential(authority, authority)


@pytest.mark.parametrize(
    ("role", "actor_id"),
    [
        (WorkloadRole.AGENT, None),
        (WorkloadRole.GATEWAY, AGENT_ACTOR_ID),
        (WorkloadRole.OT_ADAPTER, AGENT_ACTOR_ID),
    ],
)
def test_credential_actor_claim_is_exactly_scoped_to_agent_role(
    role: WorkloadRole,
    actor_id: str | None,
) -> None:
    with pytest.raises(ValueError, match="agent workload credentials require one actor"):
        _issue_credential(
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate(),
            role=role,
            actor_id=actor_id,
        )


def test_agent_actor_binding_verifies_exactly_and_is_retained_in_evidence(
    identity: IdentityArtifacts,
) -> None:
    agent_private = Ed25519PrivateKey.generate()
    credential = _issue_credential(
        identity.authority_private_key,
        agent_private,
        credential_id="credential-agent-actor-bound-0001",
        subject=AGENT_SUBJECT,
        role=WorkloadRole.AGENT,
        actor_id=AGENT_ACTOR_ID,
    )
    receipt = identity.verifier().verify_credential_with_receipt(
        credential,
        expected_role=WorkloadRole.AGENT,
        expected_audience=GATEWAY_AUDIENCE,
        expected_subject=AGENT_SUBJECT,
        expected_actor_id=AGENT_ACTOR_ID,
        now=NOW,
    )

    assert receipt.actor_id == AGENT_ACTOR_ID
    assert receipt.evidence_fields()["actor_id"] == AGENT_ACTOR_ID
    with pytest.raises(WorkloadIdentityError, match="actor is not authorized"):
        identity.verifier().verify_credential(
            credential,
            expected_role=WorkloadRole.AGENT,
            expected_audience=GATEWAY_AUDIENCE,
            expected_subject=AGENT_SUBJECT,
            expected_actor_id="agent:impersonated-operator",
            now=NOW,
        )


def test_tampering_agent_actor_invalidates_authority_signature(
    identity: IdentityArtifacts,
) -> None:
    credential = _issue_credential(
        identity.authority_private_key,
        Ed25519PrivateKey.generate(),
        credential_id="credential-agent-actor-tamper-0001",
        subject=AGENT_SUBJECT,
        role=WorkloadRole.AGENT,
        actor_id=AGENT_ACTOR_ID,
    )
    claims = credential.credential.model_copy(
        update={"actor_id": "agent:impersonated-operator"}
    )
    tampered = credential.model_copy(update={"credential": claims})

    with pytest.raises(WorkloadIdentityError, match="issuer or signature"):
        identity.verifier().verify_credential(
            tampered,
            expected_role=WorkloadRole.AGENT,
            expected_audience=GATEWAY_AUDIENCE,
            expected_subject=AGENT_SUBJECT,
            expected_actor_id="agent:impersonated-operator",
            now=NOW,
        )


def test_forged_credential_is_rejected(identity: IdentityArtifacts) -> None:
    forged_claims = identity.signed_credential.credential.model_copy(
        update={"subject": "urn:aegis-ot:test:workload:forged-gateway"}
    )
    forged = identity.signed_credential.model_copy(update={"credential": forged_claims})

    with pytest.raises(WorkloadIdentityError, match="issuer or signature"):
        identity.verifier().verify_credential(
            forged,
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=GATEWAY_AUDIENCE,
            expected_subject=forged_claims.subject,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("expected_role", "expected_audience", "expected_subject", "message"),
    [
        (
            WorkloadRole.OT_ADAPTER,
            GATEWAY_AUDIENCE,
            GATEWAY_SUBJECT,
            "role is not authorized",
        ),
        (
            WorkloadRole.GATEWAY,
            GATEWAY_AUDIENCE,
            "urn:aegis-ot:test:workload:other-gateway",
            "subject is not authorized",
        ),
        (
            WorkloadRole.GATEWAY,
            "aegis-ot:m4g:observer",
            GATEWAY_SUBJECT,
            "audience is not authorized",
        ),
    ],
)
def test_role_subject_and_audience_mismatches_fail_closed(
    identity: IdentityArtifacts,
    expected_role: WorkloadRole,
    expected_audience: str,
    expected_subject: str,
    message: str,
) -> None:
    with pytest.raises(WorkloadIdentityError, match=message):
        identity.verifier().verify_credential(
            identity.signed_credential,
            expected_role=expected_role,
            expected_audience=expected_audience,
            expected_subject=expected_subject,
            now=NOW,
        )


def test_expired_credential_is_rejected(identity: IdentityArtifacts) -> None:
    expired = _issue_credential(
        identity.authority_private_key,
        Ed25519PrivateKey.generate(),
        credential_id="credential-expired-0001",
        issued_at=NOW - timedelta(hours=1),
        not_before=NOW - timedelta(minutes=30),
        expires_at=NOW - timedelta(seconds=1),
    )

    with pytest.raises(WorkloadIdentityError, match="credential is not currently valid"):
        identity.verifier().verify_credential(
            expired,
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=GATEWAY_AUDIENCE,
            expected_subject=GATEWAY_SUBJECT,
            now=NOW,
        )


def test_revoked_credential_is_rejected_immediately(identity: IdentityArtifacts) -> None:
    revocation = WorkloadRevocation(
        credential_id=identity.signed_credential.credential.credential_id,
        revoked_at=NOW + timedelta(days=1),
        reason="compromise investigation",
    )
    _write_identity_model(
        identity.trust_bundle_path,
        _issue_bundle(
            identity.authority_private_key,
            sequence=2,
            bundle_id="identity-bundle-revoked-0002",
            revocations=(revocation,),
        ),
    )

    with pytest.raises(WorkloadIdentityError, match="credential is revoked"):
        identity.binding(identity.verifier()).resolve(now=NOW)


@pytest.mark.parametrize("failure", ["missing", "corrupt"])
def test_missing_or_corrupt_bundle_fails_closed(
    identity: IdentityArtifacts,
    failure: str,
) -> None:
    if failure == "missing":
        identity.trust_bundle_path.unlink()
    else:
        identity.trust_bundle_path.write_bytes(b'{"not":"a trust bundle"}\n')

    with pytest.raises(WorkloadIdentityError, match="trust-bundle file is unavailable"):
        identity.binding(identity.verifier()).resolve(now=NOW)


def test_expired_bundle_is_rejected(identity: IdentityArtifacts) -> None:
    expired = _issue_bundle(
        identity.authority_private_key,
        sequence=2,
        bundle_id="identity-bundle-expired-0002",
        issued_at=NOW - timedelta(hours=2),
        expires_at=NOW - timedelta(hours=1),
    )
    _write_identity_model(identity.trust_bundle_path, expired)

    with pytest.raises(WorkloadIdentityError, match="bundle is not currently valid"):
        identity.binding(identity.verifier()).resolve(now=NOW)


def test_bundle_sequence_rollback_is_rejected(identity: IdentityArtifacts) -> None:
    verifier = identity.verifier()
    sequence_two = _issue_bundle(
        identity.authority_private_key,
        sequence=2,
        bundle_id="identity-bundle-sequence-0002",
    )
    _write_identity_model(identity.trust_bundle_path, sequence_two)
    identity.binding(verifier).resolve(now=NOW)

    sequence_one = _issue_bundle(
        identity.authority_private_key,
        sequence=1,
        bundle_id="identity-bundle-sequence-0001",
    )
    _write_identity_model(identity.trust_bundle_path, sequence_one)

    with pytest.raises(WorkloadIdentityError, match="sequence rolled back"):
        identity.binding(verifier).resolve(now=NOW)


def test_same_sequence_bundle_equivocation_is_rejected(
    identity: IdentityArtifacts,
) -> None:
    verifier = identity.verifier()
    first = _issue_bundle(
        identity.authority_private_key,
        sequence=3,
        bundle_id="identity-bundle-equivocation-a",
    )
    _write_identity_model(identity.trust_bundle_path, first)
    identity.binding(verifier).resolve(now=NOW)

    second = _issue_bundle(
        identity.authority_private_key,
        sequence=3,
        bundle_id="identity-bundle-equivocation-b",
    )
    _write_identity_model(identity.trust_bundle_path, second)

    with pytest.raises(WorkloadIdentityError, match="sequence was equivocated"):
        identity.binding(verifier).resolve(now=NOW)


def test_trust_sequence_checkpoint_survives_restart_and_accepts_same_or_higher(
    identity: IdentityArtifacts,
) -> None:
    sequence_two = _issue_bundle(
        identity.authority_private_key,
        sequence=2,
        bundle_id="identity-bundle-restart-0002",
    )
    _write_identity_model(identity.trust_bundle_path, sequence_two)
    identity.binding(identity.verifier()).resolve(now=NOW)

    # A fresh verifier accepts the exact observation retained by its predecessor.
    identity.binding(identity.verifier()).resolve(now=NOW)

    sequence_three = _issue_bundle(
        identity.authority_private_key,
        sequence=3,
        bundle_id="identity-bundle-restart-0003",
    )
    _write_identity_model(identity.trust_bundle_path, sequence_three)
    identity.binding(identity.verifier()).resolve(now=NOW)

    _write_identity_model(identity.trust_bundle_path, sequence_two)
    with pytest.raises(WorkloadIdentityError, match="sequence rolled back"):
        identity.binding(identity.verifier()).resolve(now=NOW)


def test_restart_rejects_same_sequence_bundle_equivocation(
    identity: IdentityArtifacts,
) -> None:
    first = _issue_bundle(
        identity.authority_private_key,
        sequence=4,
        bundle_id="identity-bundle-restart-equivocation-a",
    )
    _write_identity_model(identity.trust_bundle_path, first)
    identity.binding(identity.verifier()).resolve(now=NOW)

    second = _issue_bundle(
        identity.authority_private_key,
        sequence=4,
        bundle_id="identity-bundle-restart-equivocation-b",
    )
    _write_identity_model(identity.trust_bundle_path, second)
    with pytest.raises(WorkloadIdentityError, match="sequence was equivocated"):
        identity.binding(identity.verifier()).resolve(now=NOW)


def test_higher_valid_bundle_is_checkpointed_before_credential_admission(
    identity: IdentityArtifacts,
) -> None:
    identity.binding(identity.verifier()).resolve(now=NOW)
    sequence_two = _issue_bundle(
        identity.authority_private_key,
        sequence=2,
        bundle_id="identity-bundle-before-admission-0002",
    )
    _write_identity_model(identity.trust_bundle_path, sequence_two)
    forged_claims = identity.signed_credential.credential.model_copy(
        update={"subject": "urn:aegis-ot:test:workload:forged-gateway"}
    )
    forged = identity.signed_credential.model_copy(update={"credential": forged_claims})
    with pytest.raises(WorkloadIdentityError, match="issuer or signature"):
        identity.verifier().verify_credential(
            forged,
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=GATEWAY_AUDIENCE,
            expected_subject=forged_claims.subject,
            now=NOW,
        )

    _write_identity_model(
        identity.trust_bundle_path,
        _issue_bundle(
            identity.authority_private_key,
            sequence=1,
            bundle_id="identity-bundle-before-admission-0001",
        ),
    )
    with pytest.raises(WorkloadIdentityError, match="sequence rolled back"):
        identity.binding(identity.verifier()).resolve(now=NOW)


def test_trust_sequence_checkpoint_is_canonical_private_and_self_checking(
    identity: IdentityArtifacts,
) -> None:
    receipt = identity.verifier().verify_credential_with_receipt(
        identity.signed_credential,
        expected_role=WorkloadRole.GATEWAY,
        expected_audience=GATEWAY_AUDIENCE,
        expected_subject=GATEWAY_SUBJECT,
        now=NOW,
    )

    material = identity.trust_sequence_state_path.read_bytes()
    payload = json.loads(material)
    state = WorkloadTrustSequenceState.model_validate(payload)
    assert set(payload) == {
        "authority_key_id",
        "authority_public_key_sha256",
        "highest_bundle_sha256",
        "highest_sequence",
        "integrity_sha256",
        "schema_version",
        "trust_domain",
    }
    assert state.highest_sequence == receipt.trust_bundle_sequence
    assert state.highest_bundle_sha256 == receipt.trust_bundle_sha256
    assert material == canonical_json_file_bytes(state)
    assert set(identity.trust_sequence_state_path.parent.iterdir()) == {
        identity.trust_sequence_state_path,
        identity.trust_sequence_state_path.with_name(".state.json.lock"),
    }
    for path in identity.trust_sequence_state_path.parent.iterdir():
        metadata = path.stat()
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_nlink == 1
        assert metadata.st_uid == os.geteuid()


@pytest.mark.parametrize("layout", ["state_only", "lock_only", "unexpected"])
def test_partial_or_unexpected_trust_sequence_layout_fails_closed(
    identity: IdentityArtifacts,
    layout: str,
) -> None:
    directory = identity.trust_sequence_state_path.parent
    if layout == "state_only":
        identity.trust_sequence_state_path.write_bytes(b"{}\n")
        identity.trust_sequence_state_path.chmod(0o600)
    elif layout == "lock_only":
        lock_path = identity.trust_sequence_state_path.with_name(".state.json.lock")
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
    else:
        (directory / "unexpected").write_bytes(b"")

    with pytest.raises(WorkloadIdentityError, match="must both exist|unexpected"):
        identity.verifier()


def test_missing_checkpoint_after_initialization_fails_closed(
    identity: IdentityArtifacts,
) -> None:
    identity.binding(identity.verifier()).resolve(now=NOW)
    identity.trust_sequence_state_path.unlink()

    with pytest.raises(WorkloadIdentityError, match="must both exist"):
        identity.verifier()


@pytest.mark.parametrize("target", ["checkpoint", "lock"])
def test_symlinked_trust_sequence_artifact_fails_closed(
    identity: IdentityArtifacts,
    target: str,
) -> None:
    identity.binding(identity.verifier()).resolve(now=NOW)
    path = (
        identity.trust_sequence_state_path
        if target == "checkpoint"
        else identity.trust_sequence_state_path.with_name(".state.json.lock")
    )
    path.unlink()
    path.symlink_to(identity.trust_bundle_path)

    with pytest.raises(WorkloadIdentityError, match="checkpoint|stable lock"):
        identity.binding(identity.verifier()).resolve(now=NOW)


@pytest.mark.parametrize("target", ["directory", "checkpoint", "lock"])
def test_non_private_trust_sequence_mode_fails_closed(
    identity: IdentityArtifacts,
    target: str,
) -> None:
    if target != "directory":
        identity.binding(identity.verifier()).resolve(now=NOW)
    path = {
        "directory": identity.trust_sequence_state_path.parent,
        "checkpoint": identity.trust_sequence_state_path,
        "lock": identity.trust_sequence_state_path.with_name(".state.json.lock"),
    }[target]
    path.chmod(0o755 if target == "directory" else 0o644)

    with pytest.raises(WorkloadIdentityError, match="0700|0600"):
        identity.binding(identity.verifier()).resolve(now=NOW)


def test_trust_sequence_owner_mismatch_fails_closed(
    identity: IdentityArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis_ot import workload_trust_state

    monkeypatch.setattr(workload_trust_state.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(WorkloadIdentityError, match="owner-matching"):
        identity.verifier()


def test_hard_linked_trust_sequence_checkpoint_fails_closed(
    identity: IdentityArtifacts,
) -> None:
    identity.binding(identity.verifier()).resolve(now=NOW)
    os.link(
        identity.trust_sequence_state_path,
        identity.trust_sequence_state_path.parent.parent / "linked-state",
    )

    with pytest.raises(WorkloadIdentityError, match="single-link"):
        identity.binding(identity.verifier()).resolve(now=NOW)


def test_corrupt_trust_sequence_integrity_digest_fails_closed(
    identity: IdentityArtifacts,
) -> None:
    identity.binding(identity.verifier()).resolve(now=NOW)
    payload = json.loads(identity.trust_sequence_state_path.read_bytes())
    payload["highest_sequence"] = payload["highest_sequence"] + 1
    identity.trust_sequence_state_path.write_bytes(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    identity.trust_sequence_state_path.chmod(0o600)

    with pytest.raises(WorkloadIdentityError, match="checkpoint is invalid"):
        identity.binding(identity.verifier()).resolve(now=NOW)


def test_failed_checkpoint_update_poisons_verifier_instance(
    identity: IdentityArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis_ot import workload_trust_state

    verifier = identity.verifier()
    identity.binding(verifier).resolve(now=NOW)
    _write_identity_model(
        identity.trust_bundle_path,
        _issue_bundle(
            identity.authority_private_key,
            sequence=2,
            bundle_id="identity-bundle-write-failure-0002",
        ),
    )
    with monkeypatch.context() as context:
        context.setattr(
            workload_trust_state.os,
            "fsync",
            lambda _descriptor: (_ for _ in ()).throw(OSError("synthetic fsync failure")),
        )
        with pytest.raises(WorkloadIdentityError, match="checkpoint update failed"):
            identity.binding(verifier).resolve(now=NOW)

    with pytest.raises(WorkloadIdentityError, match="instance is poisoned"):
        identity.binding(verifier).resolve(now=NOW)


def test_trust_sequence_lock_wait_is_bounded(
    identity: IdentityArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis_ot import workload_trust_state

    verifier = WorkloadIdentityVerifier(
        trust_root_public_key=identity.authority_private_key.public_key(),
        trust_root_key_id=identity.authority_key_id,
        trust_domain=TRUST_DOMAIN,
        trust_bundle_path=identity.trust_bundle_path,
        trust_sequence_state_path=identity.trust_sequence_state_path,
        trust_sequence_lock_timeout_seconds=0.0,
    )

    def report_busy(_descriptor: int, _operation: int) -> None:
        raise BlockingIOError(errno.EAGAIN, "synthetic held lock")

    monkeypatch.setattr(workload_trust_state.fcntl, "flock", report_busy)
    with pytest.raises(WorkloadIdentityError, match="acquisition timed out"):
        identity.binding(verifier).resolve(now=NOW)


def test_concurrent_restart_verifiers_linearize_shared_checkpoint(
    identity: IdentityArtifacts,
) -> None:
    identity.binding(identity.verifier()).resolve(now=NOW)
    _write_identity_model(
        identity.trust_bundle_path,
        _issue_bundle(
            identity.authority_private_key,
            sequence=2,
            bundle_id="identity-bundle-concurrent-0002",
        ),
    )
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    arguments = (
        start,
        results,
        _public_key_bytes(identity.authority_private_key.public_key()),
        identity.authority_key_id,
        str(identity.trust_bundle_path),
        str(identity.trust_sequence_state_path),
        str(identity.credential_path),
        NOW,
    )
    processes = [
        context.Process(target=_restart_verifier_worker, args=arguments)
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=15)

    assert [process.exitcode for process in processes] == [0, 0]
    assert sorted(results.get(timeout=2) for _ in processes) == ["ok", "ok"]


def test_leaf_rotation_updates_peer_key_and_requires_local_signer_rotation(
    identity: IdentityArtifacts,
) -> None:
    verifier = identity.verifier()
    binding = identity.binding(verifier)
    original = binding.resolve(now=NOW)
    original_signer = WorkloadSigner(
        credential=identity.signed_credential,
        private_key=identity.leaf_private_key,
    )
    local = LocalWorkloadIdentity(binding=binding, signer=original_signer)

    rotated_private_key = Ed25519PrivateKey.generate()
    rotated_credential = _issue_credential(
        identity.authority_private_key,
        rotated_private_key,
        credential_id="credential-gateway-rotated-0002",
    )
    _write_identity_model(identity.credential_path, rotated_credential)
    rotated = binding.resolve(now=NOW)

    assert isinstance(original, ResolvedWorkloadIdentity)
    assert rotated.subject == original.subject
    assert rotated.key_id != original.key_id
    assert _public_key_bytes(rotated.public_key) == _public_key_bytes(
        rotated_private_key.public_key()
    )
    with pytest.raises(WorkloadIdentityError, match="changed without its signer"):
        local.resolve()

    rotated_local = LocalWorkloadIdentity(
        binding=binding,
        signer=WorkloadSigner(
            credential=rotated_credential,
            private_key=rotated_private_key,
        ),
    )
    assert rotated_local.resolve().key_id == rotated.key_id


def test_environment_builds_and_resolves_local_identity(
    identity: IdentityArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "AEGIS_WORKLOAD_TRUST_ROOT_PUBLIC_KEY_FILE",
        str(identity.trust_root_path),
    )
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID", identity.authority_key_id)
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_DOMAIN", TRUST_DOMAIN)
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_BUNDLE_FILE", str(identity.trust_bundle_path))
    monkeypatch.setenv(
        "AEGIS_WORKLOAD_TRUST_SEQUENCE_STATE_FILE",
        str(identity.trust_sequence_state_path),
    )
    monkeypatch.setenv(
        "AEGIS_GATEWAY_WORKLOAD_CREDENTIAL_FILE",
        str(identity.credential_path),
    )
    monkeypatch.setenv(
        "AEGIS_GATEWAY_WORKLOAD_PRIVATE_KEY_FILE",
        str(identity.private_key_path),
    )
    monkeypatch.setenv("AEGIS_GATEWAY_WORKLOAD_SUBJECT", GATEWAY_SUBJECT)

    verifier = verifier_from_environment()
    local = local_identity_from_environment(
        verifier,
        "GATEWAY",
        role=WorkloadRole.GATEWAY,
        audience=GATEWAY_AUDIENCE,
    )

    assert local.resolve().subject == GATEWAY_SUBJECT
    assert local.signer.credential == identity.signed_credential


def test_environment_requires_durable_trust_sequence_state_path(
    identity: IdentityArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "AEGIS_WORKLOAD_TRUST_ROOT_PUBLIC_KEY_FILE",
        str(identity.trust_root_path),
    )
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID", identity.authority_key_id)
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_DOMAIN", TRUST_DOMAIN)
    monkeypatch.setenv("AEGIS_WORKLOAD_TRUST_BUNDLE_FILE", str(identity.trust_bundle_path))
    monkeypatch.delenv("AEGIS_WORKLOAD_TRUST_SEQUENCE_STATE_FILE", raising=False)

    with pytest.raises(
        WorkloadIdentityError,
        match="AEGIS_WORKLOAD_TRUST_SEQUENCE_STATE_FILE",
    ):
        verifier_from_environment()


def test_agent_environment_requires_actor_binding_at_startup(
    identity: IdentityArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "AEGIS_AGENT_WORKLOAD_CREDENTIAL_FILE",
        str(identity.credential_path),
    )
    monkeypatch.setenv("AEGIS_AGENT_WORKLOAD_SUBJECT", AGENT_SUBJECT)
    monkeypatch.delenv("AEGIS_AGENT_ACTOR_ID", raising=False)

    with pytest.raises(WorkloadIdentityError, match="AEGIS_AGENT_ACTOR_ID"):
        credential_binding_from_environment(
            identity.verifier(),
            "AGENT",
            role=WorkloadRole.AGENT,
            audience=GATEWAY_AUDIENCE,
        )


@pytest.mark.parametrize(
    ("value", "expected"),
    [("required", True), ("disabled", False)],
)
def test_workload_identity_mode_accepts_only_closed_values(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
    expected: bool,
) -> None:
    monkeypatch.setenv("AEGIS_WORKLOAD_IDENTITY_MODE", value)

    assert workload_identity_enabled() is expected


@pytest.mark.parametrize("value", ["", "true", "REQUIRED", "required ", "1"])
def test_invalid_workload_identity_mode_value_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("AEGIS_WORKLOAD_IDENTITY_MODE", value)

    with pytest.raises(WorkloadIdentityError, match="must be required or disabled"):
        workload_identity_enabled()


def test_workload_identity_mode_must_be_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGIS_WORKLOAD_IDENTITY_MODE", raising=False)

    with pytest.raises(WorkloadIdentityError, match="explicitly"):
        workload_identity_enabled()
