from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis_ot.m4g_identity_admin as identity_admin
import aegis_ot.m4g_identity_init as identity_init
from aegis_ot.m4g_identity_admin import revoke_credential, rotate_credential
from aegis_ot.m4g_identity_init import initialize
from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    OT_CAPABILITY_AUDIENCE,
)
from aegis_ot.workload_identity import (
    WorkloadIdentityError,
    WorkloadIdentityVerifier,
    WorkloadRole,
    load_signed_workload_credential,
    load_workload_trust_bundle,
    workload_key_id,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
TRUST_DOMAIN = "research.aegis-ot.test"


@pytest.mark.parametrize(("is_directory", "mode"), [(False, 0o600), (True, 0o700)])
def test_runtime_assignment_sets_mode_before_transferring_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    is_directory: bool,
    mode: int,
) -> None:
    target = tmp_path / "runtime-artifact"
    if is_directory:
        target.mkdir()
    else:
        target.write_bytes(b"artifact")
    ownership_transferred = False
    original_chmod = Path.chmod

    def guarded_chmod(path: Path, requested_mode: int) -> None:
        assert not ownership_transferred
        original_chmod(path, requested_mode)

    def transfer_ownership(path: str | bytes | int, uid: int, gid: int) -> None:
        nonlocal ownership_transferred
        assert Path(path) == target
        assert stat.S_IMODE(target.stat().st_mode) == mode
        assert uid == os.getuid()
        assert gid == os.getgid()
        ownership_transferred = True

    monkeypatch.setattr(Path, "chmod", guarded_chmod)
    monkeypatch.setattr(identity_init.os, "chown", transfer_ownership)
    assign = (
        identity_init._assign_runtime_directory
        if is_directory
        else identity_init._assign_runtime_file
    )
    assign(target, target_uid=os.getuid(), target_gid=os.getgid())

    assert ownership_transferred
    assert stat.S_IMODE(target.stat().st_mode) == mode


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


@dataclass(frozen=True)
class ProvisionedIdentity:
    directory: Path
    authority_path: Path
    authority: Ed25519PrivateKey
    leaves: dict[WorkloadRole, Ed25519PrivateKey]
    summary: dict[str, object]


def _provision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> ProvisionedIdentity:
    input_directory = tmp_path / "inputs"
    identity_directory = tmp_path / "identity"
    input_directory.mkdir()
    identity_directory.mkdir()
    authority = Ed25519PrivateKey.generate()
    authority_path = input_directory / "authority.private"
    authority_path.write_bytes(_raw_private(authority))
    authority_path.chmod(0o400)
    leaves = {
        WorkloadRole.AGENT: Ed25519PrivateKey.generate(),
        WorkloadRole.GATEWAY: Ed25519PrivateKey.generate(),
        WorkloadRole.OT_ADAPTER: Ed25519PrivateKey.generate(),
    }
    public_paths = {
        role: input_directory / f"{role.value}.public" for role in leaves
    }
    for role, key in leaves.items():
        public_paths[role].write_bytes(_raw_public(key))

    environment = {
        "AEGIS_WORKLOAD_IDENTITY_DIRECTORY": identity_directory,
        "AEGIS_WORKLOAD_AUTHORITY_PRIVATE_KEY_FILE": authority_path,
        "AEGIS_WORKLOAD_TRUST_DOMAIN": TRUST_DOMAIN,
        "AEGIS_AGENT_PUBLIC_KEY_FILE": public_paths[WorkloadRole.AGENT],
        "AEGIS_GATEWAY_PUBLIC_KEY_FILE": public_paths[WorkloadRole.GATEWAY],
        "AEGIS_OT_PUBLIC_KEY_FILE": public_paths[WorkloadRole.OT_ADAPTER],
    }
    for name, path in environment.items():
        monkeypatch.setenv(name, str(path))
    monkeypatch.setenv("AEGIS_AGENT_WORKLOAD_SUBJECT", "agent/probe-1")
    monkeypatch.setenv("AEGIS_GATEWAY_WORKLOAD_SUBJECT", "gateway/control-1")
    monkeypatch.setenv("AEGIS_OT_WORKLOAD_SUBJECT", "ot-adapter/plc-1")
    monkeypatch.setenv("AEGIS_RUNTIME_UID", str(os.getuid()))
    monkeypatch.setenv("AEGIS_RUNTIME_GID", str(os.getgid()))
    summary = initialize(now=NOW)
    return ProvisionedIdentity(
        directory=identity_directory,
        authority_path=authority_path,
        authority=authority,
        leaves=leaves,
        summary=summary,
    )


def _verifier(provisioned: ProvisionedIdentity) -> WorkloadIdentityVerifier:
    return WorkloadIdentityVerifier(
        trust_root_public_key=provisioned.authority.public_key(),
        trust_root_key_id=workload_key_id(provisioned.authority.public_key()),
        trust_domain=TRUST_DOMAIN,
        trust_bundle_path=provisioned.directory / "trust-bundle.json",
    )


def _configure_uninitialized_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    keys: dict[str, Ed25519PrivateKey],
) -> Path:
    input_directory = tmp_path / "collision-inputs"
    identity_directory = tmp_path / "collision-identity"
    input_directory.mkdir()
    identity_directory.mkdir()
    authority_path = input_directory / "authority.private"
    authority_path.write_bytes(_raw_private(keys["authority"]))
    public_paths: dict[str, Path] = {}
    for role in ("agent", "gateway", "ot"):
        public_path = input_directory / f"{role}.public"
        public_path.write_bytes(_raw_public(keys[role]))
        public_paths[role] = public_path
    environment = {
        "AEGIS_WORKLOAD_IDENTITY_DIRECTORY": identity_directory,
        "AEGIS_WORKLOAD_AUTHORITY_PRIVATE_KEY_FILE": authority_path,
        "AEGIS_WORKLOAD_TRUST_DOMAIN": TRUST_DOMAIN,
        "AEGIS_AGENT_PUBLIC_KEY_FILE": public_paths["agent"],
        "AEGIS_GATEWAY_PUBLIC_KEY_FILE": public_paths["gateway"],
        "AEGIS_OT_PUBLIC_KEY_FILE": public_paths["ot"],
    }
    for name, path in environment.items():
        monkeypatch.setenv(name, str(path))
    monkeypatch.setenv("AEGIS_AGENT_WORKLOAD_SUBJECT", "agent/probe-1")
    monkeypatch.setenv("AEGIS_GATEWAY_WORKLOAD_SUBJECT", "gateway/control-1")
    monkeypatch.setenv("AEGIS_OT_WORKLOAD_SUBJECT", "ot-adapter/plc-1")
    monkeypatch.setenv("AEGIS_RUNTIME_UID", str(os.getuid()))
    monkeypatch.setenv("AEGIS_RUNTIME_GID", str(os.getgid()))
    return identity_directory


def test_initializer_certifies_existing_leaf_keys_without_retaining_authority_private_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisioned = _provision(tmp_path, monkeypatch)
    bundle = load_workload_trust_bundle(provisioned.directory / "trust-bundle.json")

    assert bundle.sequence == 1
    assert bundle.verify(provisioned.authority.public_key())
    assert bundle.issued_at == NOW
    assert bundle.expires_at == NOW + timedelta(hours=1)
    assert not (provisioned.directory / "authority.private").exists()
    assert (provisioned.directory / "authority.public").read_bytes() == _raw_public(
        provisioned.authority
    )
    assert stat.S_IMODE(provisioned.directory.stat().st_mode) == 0o700
    assert provisioned.directory.stat().st_uid == os.getuid()
    assert provisioned.directory.stat().st_gid == os.getgid()

    definitions = (
        (
            "agent.credential.json",
            WorkloadRole.AGENT,
            "agent/probe-1",
            GATEWAY_CAPABILITY_AUDIENCE,
        ),
        (
            "gateway.credential.json",
            WorkloadRole.GATEWAY,
            "gateway/control-1",
            OT_CAPABILITY_AUDIENCE,
        ),
        (
            "ot.credential.json",
            WorkloadRole.OT_ADAPTER,
            "ot-adapter/plc-1",
            GATEWAY_CAPABILITY_AUDIENCE,
        ),
    )
    verifier = _verifier(provisioned)
    for filename, role, subject, audience in definitions:
        path = provisioned.directory / filename
        signed = load_signed_workload_credential(path)
        verified_key = verifier.verify_credential(
            signed,
            expected_role=role,
            expected_subject=subject,
            expected_audience=audience,
            now=NOW,
        )
        assert verified_key.public_bytes_raw() == _raw_public(provisioned.leaves[role])
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_uid == os.getuid()
        assert path.stat().st_gid == os.getgid()

    for path in provisioned.directory.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    summary_json = json.dumps(provisioned.summary, sort_keys=True)
    authority_private_b64 = base64.urlsafe_b64encode(
        _raw_private(provisioned.authority)
    ).decode("ascii")
    assert authority_private_b64 not in summary_json
    assert provisioned.summary["authority_private_key_retained"] is False


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("authority", "agent"),
        ("agent", "gateway"),
        ("gateway", "ot"),
    ],
)
def test_initializer_rejects_authority_and_cross_role_key_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    first: str,
    second: str,
) -> None:
    keys = {
        name: Ed25519PrivateKey.generate()
        for name in ("authority", "agent", "gateway", "ot")
    }
    keys[second] = keys[first]
    identity_directory = _configure_uninitialized_identity(tmp_path, monkeypatch, keys)

    with pytest.raises(RuntimeError, match="signing keys must be distinct"):
        initialize(now=NOW)

    assert list(identity_directory.iterdir()) == []


def test_initializer_refuses_overwrite_and_invalid_lifetime_without_partial_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisioned = _provision(tmp_path, monkeypatch)
    before = {
        path.name: path.read_bytes() for path in provisioned.directory.iterdir()
    }

    with pytest.raises(RuntimeError, match="refuses nonempty directory"):
        initialize(now=NOW)

    assert {path.name: path.read_bytes() for path in provisioned.directory.iterdir()} == before

    empty_directory = tmp_path / "empty-identity"
    empty_directory.mkdir()
    monkeypatch.setenv("AEGIS_WORKLOAD_IDENTITY_DIRECTORY", str(empty_directory))
    monkeypatch.setenv("AEGIS_WORKLOAD_CREDENTIAL_TTL_SECONDS", "3601")
    monkeypatch.setenv("AEGIS_WORKLOAD_BUNDLE_TTL_SECONDS", "3600")
    with pytest.raises(RuntimeError, match="must cover credential lifetime"):
        initialize(now=NOW)
    assert list(empty_directory.iterdir()) == []

    with pytest.raises(RuntimeError, match="timezone-aware"):
        initialize(now=NOW.replace(tzinfo=None))
    assert list(empty_directory.iterdir()) == []


def test_admin_rotation_preserves_identity_claims_and_revokes_predecessor_at_n_plus_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisioned = _provision(tmp_path, monkeypatch)
    bundle_path = provisioned.directory / "trust-bundle.json"
    credential_path = provisioned.directory / "gateway.credential.json"
    old_credential = load_signed_workload_credential(credential_path)
    old_stat = credential_path.stat()
    rotated_leaf = Ed25519PrivateKey.generate()
    rotated_public_path = tmp_path / "gateway-rotated.public"
    rotated_public_path.write_bytes(_raw_public(rotated_leaf))
    rotated_at = NOW + timedelta(minutes=5)

    summary = rotate_credential(
        authority_private_key_path=provisioned.authority_path,
        bundle_path=bundle_path,
        credential_path=credential_path,
        leaf_public_key_path=rotated_public_path,
        expected_sequence=1,
        now=rotated_at,
    )

    next_bundle = load_workload_trust_bundle(bundle_path)
    rotated = load_signed_workload_credential(credential_path)
    assert summary["prior_sequence"] == 1
    assert summary["published_sequence"] == 2
    assert summary["runtime_private_key_written"] is False
    assert next_bundle.sequence == 2
    assert next_bundle.verify(provisioned.authority.public_key())
    assert [item.credential_id for item in next_bundle.revocations] == [
        old_credential.credential.credential_id
    ]
    assert rotated.credential.credential_id != old_credential.credential.credential_id
    assert rotated.credential.subject == old_credential.credential.subject
    assert rotated.credential.role == old_credential.credential.role
    assert rotated.credential.audiences == old_credential.credential.audiences
    assert rotated.credential.public_key.public_bytes_raw() == _raw_public(rotated_leaf)
    assert credential_path.stat().st_uid == old_stat.st_uid
    assert credential_path.stat().st_gid == old_stat.st_gid
    assert stat.S_IMODE(credential_path.stat().st_mode) == 0o600

    verifier = _verifier(provisioned)
    verifier.verify_credential(
        rotated,
        expected_role=WorkloadRole.GATEWAY,
        expected_subject="gateway/control-1",
        expected_audience=OT_CAPABILITY_AUDIENCE,
        now=rotated_at,
    )
    with pytest.raises(WorkloadIdentityError, match="revoked"):
        verifier.verify_credential(
            old_credential,
            expected_role=WorkloadRole.GATEWAY,
            expected_subject="gateway/control-1",
            expected_audience=OT_CAPABILITY_AUDIENCE,
            now=rotated_at,
        )
    assert not any("private" in path.name for path in provisioned.directory.iterdir())


@pytest.mark.parametrize(
    "collision",
    ["authority", WorkloadRole.AGENT, WorkloadRole.OT_ADAPTER],
)
def test_admin_rotation_rejects_authority_and_published_role_key_collisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collision: str | WorkloadRole,
) -> None:
    provisioned = _provision(tmp_path, monkeypatch)
    bundle_path = provisioned.directory / "trust-bundle.json"
    credential_path = provisioned.directory / "gateway.credential.json"
    collision_key = (
        provisioned.leaves[collision]
        if isinstance(collision, WorkloadRole)
        else provisioned.authority
    )
    public_path = tmp_path / "colliding-rotation.public"
    public_path.write_bytes(_raw_public(collision_key))
    before_bundle = bundle_path.read_bytes()
    before_credential = credential_path.read_bytes()

    with pytest.raises(RuntimeError, match="rotation leaf conflicts"):
        rotate_credential(
            authority_private_key_path=provisioned.authority_path,
            bundle_path=bundle_path,
            credential_path=credential_path,
            leaf_public_key_path=public_path,
            expected_sequence=1,
            now=NOW + timedelta(minutes=1),
        )

    assert bundle_path.read_bytes() == before_bundle
    assert credential_path.read_bytes() == before_credential


def test_revoked_credential_can_be_rotated_without_losing_prior_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisioned = _provision(tmp_path, monkeypatch)
    bundle_path = provisioned.directory / "trust-bundle.json"
    credential_path = provisioned.directory / "gateway.credential.json"
    predecessor = load_signed_workload_credential(credential_path)
    revoke_credential(
        authority_private_key_path=provisioned.authority_path,
        bundle_path=bundle_path,
        credential_path=credential_path,
        reason="urgent gateway compromise response",
        expected_sequence=1,
        now=NOW + timedelta(minutes=1),
    )
    rotated_leaf = Ed25519PrivateKey.generate()
    rotated_public_path = tmp_path / "gateway-recovery.public"
    rotated_public_path.write_bytes(_raw_public(rotated_leaf))

    summary = rotate_credential(
        authority_private_key_path=provisioned.authority_path,
        bundle_path=bundle_path,
        credential_path=credential_path,
        leaf_public_key_path=rotated_public_path,
        reason="gateway recovery after revocation",
        expected_sequence=2,
        now=NOW + timedelta(minutes=2),
    )

    bundle = load_workload_trust_bundle(bundle_path)
    rotated = load_signed_workload_credential(credential_path)
    assert summary["prior_sequence"] == 2
    assert summary["published_sequence"] == 3
    assert bundle.sequence == 3
    assert [item.credential_id for item in bundle.revocations] == [
        predecessor.credential.credential_id
    ]
    assert rotated.credential.public_key.public_bytes_raw() == _raw_public(rotated_leaf)
    _verifier(provisioned).verify_credential(
        rotated,
        expected_role=WorkloadRole.GATEWAY,
        expected_subject="gateway/control-1",
        expected_audience=OT_CAPABILITY_AUDIENCE,
        now=NOW + timedelta(minutes=2),
    )


def test_rotation_publication_failure_leaves_predecessor_revoked_and_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisioned = _provision(tmp_path, monkeypatch)
    bundle_path = provisioned.directory / "trust-bundle.json"
    credential_path = provisioned.directory / "gateway.credential.json"
    predecessor_material = credential_path.read_bytes()
    predecessor = load_signed_workload_credential(credential_path)
    rotated_leaf = Ed25519PrivateKey.generate()
    rotated_public_path = tmp_path / "gateway-fail-closed.public"
    rotated_public_path.write_bytes(_raw_public(rotated_leaf))
    original_replace = identity_admin._atomic_replace

    def fail_credential_publication(path: Path, material: bytes) -> None:
        if path == credential_path:
            raise RuntimeError("injected credential publication failure")
        original_replace(path, material)

    monkeypatch.setattr(
        identity_admin,
        "_atomic_replace",
        fail_credential_publication,
    )
    with pytest.raises(RuntimeError, match="injected credential publication failure"):
        rotate_credential(
            authority_private_key_path=provisioned.authority_path,
            bundle_path=bundle_path,
            credential_path=credential_path,
            leaf_public_key_path=rotated_public_path,
            expected_sequence=1,
            now=NOW + timedelta(minutes=1),
        )

    failed_bundle = load_workload_trust_bundle(bundle_path)
    assert failed_bundle.sequence == 2
    assert credential_path.read_bytes() == predecessor_material
    assert [item.credential_id for item in failed_bundle.revocations] == [
        predecessor.credential.credential_id
    ]
    with pytest.raises(WorkloadIdentityError, match="revoked"):
        _verifier(provisioned).verify_credential(
            predecessor,
            expected_role=WorkloadRole.GATEWAY,
            expected_subject="gateway/control-1",
            expected_audience=OT_CAPABILITY_AUDIENCE,
            now=NOW + timedelta(minutes=1),
        )

    monkeypatch.setattr(identity_admin, "_atomic_replace", original_replace)
    recovery = rotate_credential(
        authority_private_key_path=provisioned.authority_path,
        bundle_path=bundle_path,
        credential_path=credential_path,
        leaf_public_key_path=rotated_public_path,
        expected_sequence=2,
        now=NOW + timedelta(minutes=2),
    )
    assert recovery["published_sequence"] == 3
    assert load_signed_workload_credential(credential_path).credential.key_id == (
        workload_key_id(rotated_leaf.public_key())
    )


def test_admin_revocation_is_sequence_checked_authority_signed_and_idempotently_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisioned = _provision(tmp_path, monkeypatch)
    bundle_path = provisioned.directory / "trust-bundle.json"
    credential_path = provisioned.directory / "agent.credential.json"
    credential_material = credential_path.read_bytes()
    signed = load_signed_workload_credential(credential_path)

    summary = revoke_credential(
        authority_private_key_path=provisioned.authority_path,
        bundle_path=bundle_path,
        credential_path=credential_path,
        reason="operator-compromise-response",
        expected_sequence=1,
        now=NOW + timedelta(minutes=1),
    )
    published = bundle_path.read_bytes()
    bundle = load_workload_trust_bundle(bundle_path)
    assert summary["operation"] == "revoke"
    assert bundle.sequence == 2
    assert bundle.verify(provisioned.authority.public_key())
    assert bundle.revocations[0].credential_id == signed.credential.credential_id
    assert bundle.revocations[0].reason == "operator-compromise-response"
    assert credential_path.read_bytes() == credential_material
    with pytest.raises(WorkloadIdentityError, match="revoked"):
        _verifier(provisioned).verify_credential(
            signed,
            expected_role=WorkloadRole.AGENT,
            expected_subject="agent/probe-1",
            expected_audience=GATEWAY_CAPABILITY_AUDIENCE,
            now=NOW + timedelta(minutes=1),
        )

    with pytest.raises(RuntimeError, match="expected 1"):
        revoke_credential(
            authority_private_key_path=provisioned.authority_path,
            bundle_path=bundle_path,
            credential_path=credential_path,
            reason="duplicate",
            expected_sequence=1,
            now=NOW + timedelta(minutes=2),
        )
    assert bundle_path.read_bytes() == published

    wrong_authority_path = tmp_path / "wrong-authority.private"
    wrong_authority_path.write_bytes(_raw_private(Ed25519PrivateKey.generate()))
    with pytest.raises(RuntimeError, match="does not control"):
        revoke_credential(
            authority_private_key_path=wrong_authority_path,
            bundle_path=bundle_path,
            credential_path=credential_path,
            reason="wrong-authority",
            expected_sequence=2,
            now=NOW + timedelta(minutes=2),
        )
    assert bundle_path.read_bytes() == published
