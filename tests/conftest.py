from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis_ot.factory import LocalLab, build_local_lab
from aegis_ot.lab import nominal_state
from aegis_ot.models import ActionProposal, Operation, SystemState


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 8, 24, 16, 0, tzinfo=UTC)


@pytest.fixture
def lab(now: datetime) -> LocalLab:
    return build_local_lab(now)


@pytest.fixture
def state(now: datetime) -> SystemState:
    return nominal_state(observed_at=now)


@pytest.fixture
def proposal(now: datetime) -> ActionProposal:
    return ActionProposal(
        proposal_id="proposal-1",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=1,
        observed_at=now,
        submitted_at=now,
        nonce="0123456789abcdef",
        confidence=0.9,
        risk_score=60.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )
