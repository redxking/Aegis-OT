from __future__ import annotations

from datetime import timedelta

from aegis_ot.crypto import generate_keypair, sign_bytes, verify_bytes
from aegis_ot.delegation import DelegationGrant, DelegationValidator
from aegis_ot.models import Operation


def test_ed25519_signature_round_trip() -> None:
    private, public = generate_keypair()
    signature = sign_bytes(private, b"proposal")
    assert verify_bytes(public, b"proposal", signature)
    assert not verify_bytes(public, b"tampered", signature)


def test_valid_full_chain(lab, proposal, now) -> None:
    result = lab.gateway.delegation.validate(proposal, now)
    assert result.valid
    assert not result.reasons


def test_revoked_ancestor_invalidates_leaf(lab, proposal, now) -> None:
    lab.gateway.delegation.revoke(lab.root_grant.grant_id)
    result = lab.gateway.delegation.validate(proposal, now)
    assert not result.valid
    assert "revoked_grant:grant-root" in result.reasons


def test_expired_grant_is_rejected(lab, proposal, now) -> None:
    result = lab.gateway.delegation.validate(proposal, now + timedelta(hours=2))
    assert not result.valid
    assert any(reason.startswith("inactive_grant") for reason in result.reasons)


def test_operation_amplification_is_rejected(lab, proposal, now) -> None:
    amplified = lab.leaf_grant.model_copy(
        update={
            "operations": frozenset(Operation),
            "signature": "",
        }
    ).signed(lab.supervisor_private_key)
    validator = DelegationValidator(
        {lab.root_grant.grant_id: lab.root_grant, amplified.grant_id: amplified},
        lab.gateway.delegation._public_keys,  # noqa: SLF001 - white-box security test
    )
    # Root currently allows all operations; narrow it to demonstrate amplification.
    narrow_root = lab.root_grant.model_copy(
        update={"operations": frozenset({Operation.ISOLATE_ASSET}), "signature": ""}
    ).signed(lab.root_private_key)
    validator = DelegationValidator(
        {narrow_root.grant_id: narrow_root, amplified.grant_id: amplified},
        lab.gateway.delegation._public_keys,  # noqa: SLF001
    )
    result = validator.validate(proposal, now)
    assert not result.valid
    assert "operation_amplification:grant-leaf" in result.reasons


def test_forged_grant_is_rejected(lab, proposal, now) -> None:
    forged = lab.leaf_grant.model_copy(update={"risk_limit": 90.0})
    validator = DelegationValidator(
        {lab.root_grant.grant_id: lab.root_grant, forged.grant_id: forged},
        lab.gateway.delegation._public_keys,  # noqa: SLF001
    )
    result = validator.validate(proposal, now)
    assert not result.valid
    assert "invalid_signature:grant-leaf" in result.reasons


def test_grant_rejects_inverted_time_window(lab) -> None:
    try:
        DelegationGrant(
            grant_id="bad",
            issuer_id="a",
            subject_id="b",
            mission_id="m",
            resources=frozenset({"r"}),
            operations=frozenset({Operation.ISOLATE_ASSET}),
            not_before=lab.root_grant.expires_at,
            expires_at=lab.root_grant.not_before,
            risk_limit=1,
            delegation_depth_remaining=0,
        )
    except ValueError:
        return
    raise AssertionError("inverted grant window was accepted")
