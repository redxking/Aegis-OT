"""Deterministic local lab construction for demos and tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import generate_keypair
from .delegation import DelegationGrant, DelegationValidator
from .evidence import EvidenceChain
from .gateway import AegisGateway
from .identity import AllowlistIdentityVerifier
from .models import Operation
from .policy import ContextualPolicy
from .replay import ReplayLedger
from .safety import SafetyKernel


@dataclass(frozen=True)
class LocalLab:
    gateway: AegisGateway
    root_grant: DelegationGrant
    leaf_grant: DelegationGrant
    root_private_key: Ed25519PrivateKey
    supervisor_private_key: Ed25519PrivateKey


def build_local_lab(
    now: datetime | None = None,
    *,
    agent_actor_id: str = "agent:operator-1",
) -> LocalLab:
    if (
        not agent_actor_id
        or agent_actor_id != agent_actor_id.strip()
        or any(character.isspace() for character in agent_actor_id)
    ):
        raise ValueError("agent actor ID must be non-empty and contain no whitespace")
    reference_time = now or datetime.now(UTC)
    root_private, root_public = generate_keypair()
    supervisor_private, supervisor_public = generate_keypair()
    root = DelegationGrant(
        grant_id="grant-root",
        issuer_id="human:principal-investigator",
        subject_id="agent:supervisor",
        mission_id="microgrid-containment",
        resources=frozenset({"feeder-1", "feeder-2", "battery-1"}),
        operations=frozenset(Operation),
        not_before=reference_time - timedelta(minutes=1),
        expires_at=reference_time + timedelta(hours=1),
        risk_limit=90.0,
        delegation_depth_remaining=2,
    ).signed(root_private)
    leaf = DelegationGrant(
        grant_id="grant-leaf",
        issuer_id="agent:supervisor",
        subject_id=agent_actor_id,
        mission_id="microgrid-containment",
        resources=frozenset({"feeder-1", "battery-1"}),
        operations=frozenset({Operation.ISOLATE_ASSET, Operation.DISPATCH_BATTERY}),
        not_before=reference_time - timedelta(seconds=30),
        expires_at=reference_time + timedelta(minutes=30),
        risk_limit=74.0,
        delegation_depth_remaining=1,
        parent_grant_id=root.grant_id,
    ).signed(supervisor_private)
    validator = DelegationValidator(
        grants={root.grant_id: root, leaf.grant_id: leaf},
        public_keys={
            root.issuer_id: root_public,
            leaf.issuer_id: supervisor_public,
        },
    )
    gateway = AegisGateway(
        identity=AllowlistIdentityVerifier(frozenset({agent_actor_id})),
        delegation=validator,
        policy=ContextualPolicy(),
        safety=SafetyKernel(),
        replay=ReplayLedger(),
        evidence=EvidenceChain(),
    )
    return LocalLab(gateway, root, leaf, root_private, supervisor_private)
