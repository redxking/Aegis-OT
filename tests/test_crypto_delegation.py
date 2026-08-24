from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

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


def test_grant_rejects_naive_time_window(lab) -> None:
    data = lab.root_grant.model_dump()
    data["not_before"] = datetime(2026, 8, 24, 15, 0)
    with pytest.raises(ValidationError, match="timezone-aware"):
        DelegationGrant.model_validate(data)


def test_delegation_cycle_is_rejected(lab, proposal, now) -> None:
    cyclic = proposal.model_copy(
        update={"delegation_chain": ("grant-root", "grant-leaf", "grant-root")}
    )
    result = lab.gateway.delegation.validate(cyclic, now)
    assert result.reasons == ("delegation_cycle",)


def test_unknown_grant_and_missing_issuer_key_are_rejected(lab, proposal, now) -> None:
    unknown = proposal.model_copy(update={"delegation_chain": ("grant-missing",)})
    unknown_result = lab.gateway.delegation.validate(unknown, now)
    assert unknown_result.reasons == ("unknown_grant:grant-missing",)

    validator = DelegationValidator(
        {lab.root_grant.grant_id: lab.root_grant, lab.leaf_grant.grant_id: lab.leaf_grant},
        {},
    )
    missing_key_result = validator.validate(proposal, now)
    assert "invalid_signature:grant-root" in missing_key_result.reasons
    assert "invalid_signature:grant-leaf" in missing_key_result.reasons


def test_root_parent_reference_is_rejected(lab, proposal, now) -> None:
    root = lab.root_grant.model_copy(update={"parent_grant_id": "unexpected", "signature": ""})
    root = root.signed(lab.root_private_key)
    validator = DelegationValidator(
        {root.grant_id: root, lab.leaf_grant.grant_id: lab.leaf_grant},
        lab.gateway.delegation._public_keys,  # noqa: SLF001
    )
    result = validator.validate(proposal, now)
    assert "root_has_parent" in result.reasons


def test_child_attenuation_violations_are_rejected(lab, proposal, now) -> None:
    supervisor_public = lab.gateway.delegation._public_keys["agent:supervisor"]  # noqa: SLF001
    child = lab.leaf_grant.model_copy(
        update={
            "issuer_id": "agent:other-supervisor",
            "parent_grant_id": "wrong-parent",
            "resources": lab.root_grant.resources | {"feeder-unauthorized"},
            "risk_limit": 95.0,
            "delegation_depth_remaining": lab.root_grant.delegation_depth_remaining,
            "not_before": lab.root_grant.not_before - timedelta(seconds=1),
            "expires_at": lab.root_grant.expires_at + timedelta(seconds=1),
            "signature": "",
        }
    ).signed(lab.supervisor_private_key)
    public_keys = dict(lab.gateway.delegation._public_keys)  # noqa: SLF001
    public_keys[child.issuer_id] = supervisor_public
    validator = DelegationValidator(
        {lab.root_grant.grant_id: lab.root_grant, child.grant_id: child},
        public_keys,
    )
    result = validator.validate(proposal, now)
    assert set(result.reasons) >= {
        "broken_parent_link:grant-leaf",
        "issuer_subject_mismatch:grant-leaf",
        "resource_amplification:grant-leaf",
        "risk_amplification:grant-leaf",
        "depth_not_attenuated:grant-leaf",
        "time_amplification:grant-leaf",
    }


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"actor_id": "agent:other"}, "leaf_subject_mismatch"),
        ({"mission_id": "other-mission"}, "mission_out_of_scope"),
        ({"resource": "feeder-2"}, "resource_out_of_scope"),
        ({"operation": Operation.RESTORE_ASSET}, "operation_out_of_scope"),
        ({"risk_score": 80.0}, "risk_out_of_scope"),
    ],
)
def test_leaf_scope_violations_are_rejected(lab, proposal, now, updates, reason) -> None:
    result = lab.gateway.delegation.validate(proposal.model_copy(update=updates), now)
    assert reason in result.reasons
