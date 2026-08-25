"""Signed, attenuated delegation grants and full-chain validation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .crypto import sign_bytes, verify_bytes
from .models import ActionProposal, Operation


class DelegationGrant(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    grant_id: str = Field(min_length=1)
    issuer_id: str = Field(min_length=1)
    subject_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    resources: frozenset[str] = Field(min_length=1)
    operations: frozenset[Operation] = Field(min_length=1)
    not_before: datetime
    expires_at: datetime
    risk_limit: float = Field(ge=0, le=100)
    delegation_depth_remaining: int = Field(ge=0)
    parent_grant_id: str | None = None
    signature: str = ""

    @model_validator(mode="after")
    def valid_window(self) -> DelegationGrant:
        if self.not_before.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("grant timestamps must be timezone-aware")
        if self.expires_at <= self.not_before:
            raise ValueError("grant expiry must follow not_before")
        return self

    def signing_bytes(self) -> bytes:
        data = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def signed(self, private_key: Ed25519PrivateKey) -> DelegationGrant:
        return self.model_copy(update={"signature": sign_bytes(private_key, self.signing_bytes())})


class DelegationValidation(BaseModel):
    valid: bool
    reasons: tuple[str, ...] = ()


class DelegationValidator:
    def __init__(
        self,
        grants: Mapping[str, DelegationGrant],
        public_keys: Mapping[str, Ed25519PublicKey],
        revoked_grants: set[str] | None = None,
    ) -> None:
        self._grants = grants
        self._public_keys = public_keys
        self._revoked = revoked_grants if revoked_grants is not None else set()

    def revoke(self, grant_id: str) -> None:
        self._revoked.add(grant_id)

    def validate(self, proposal: ActionProposal, now: datetime) -> DelegationValidation:
        reasons: list[str] = []
        chain_ids = proposal.delegation_chain
        if len(chain_ids) != len(set(chain_ids)):
            return DelegationValidation(valid=False, reasons=("delegation_cycle",))

        chain: list[DelegationGrant] = []
        for grant_id in chain_ids:
            grant = self._grants.get(grant_id)
            if grant is None:
                reasons.append(f"unknown_grant:{grant_id}")
                continue
            chain.append(grant)
            key = self._public_keys.get(grant.issuer_id)
            if key is None or not verify_bytes(key, grant.signing_bytes(), grant.signature):
                reasons.append(f"invalid_signature:{grant_id}")
            if grant_id in self._revoked:
                reasons.append(f"revoked_grant:{grant_id}")
            if not grant.not_before <= now <= grant.expires_at:
                reasons.append(f"inactive_grant:{grant_id}")

        if reasons or len(chain) != len(chain_ids):
            return DelegationValidation(valid=False, reasons=tuple(reasons))

        for index, grant in enumerate(chain):
            if index == 0:
                if grant.parent_grant_id is not None:
                    reasons.append("root_has_parent")
            else:
                parent = chain[index - 1]
                if grant.parent_grant_id != parent.grant_id:
                    reasons.append(f"broken_parent_link:{grant.grant_id}")
                if grant.issuer_id != parent.subject_id:
                    reasons.append(f"issuer_subject_mismatch:{grant.grant_id}")
                if not grant.resources <= parent.resources:
                    reasons.append(f"resource_amplification:{grant.grant_id}")
                if not grant.operations <= parent.operations:
                    reasons.append(f"operation_amplification:{grant.grant_id}")
                if grant.risk_limit > parent.risk_limit:
                    reasons.append(f"risk_amplification:{grant.grant_id}")
                if grant.delegation_depth_remaining >= parent.delegation_depth_remaining:
                    reasons.append(f"depth_not_attenuated:{grant.grant_id}")
                if grant.not_before < parent.not_before or grant.expires_at > parent.expires_at:
                    reasons.append(f"time_amplification:{grant.grant_id}")

        if chain:
            leaf = chain[-1]
            if leaf.subject_id != proposal.actor_id:
                reasons.append("leaf_subject_mismatch")
            if leaf.mission_id != proposal.mission_id:
                reasons.append("mission_out_of_scope")
            if proposal.resource not in leaf.resources:
                reasons.append("resource_out_of_scope")
            if proposal.operation not in leaf.operations:
                reasons.append("operation_out_of_scope")
            if proposal.risk_score > leaf.risk_limit:
                reasons.append("risk_out_of_scope")

        return DelegationValidation(valid=not reasons, reasons=tuple(reasons))
