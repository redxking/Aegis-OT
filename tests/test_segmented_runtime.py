from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import yaml
from fastapi import HTTPException

import aegis_ot.segmented_runtime as segmented
from aegis_ot.lab import nominal_state
from aegis_ot.models import ActionProposal, Decision, DecisionOutcome, Operation
from aegis_ot.policy import ContextualPolicy


def _proposal(*, impact: float = 5.0, nonce: str | None = None) -> ActionProposal:
    now = datetime.now(UTC)
    return ActionProposal(
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": impact},
        observed_state_version=1,
        observed_at=now,
        submitted_at=now,
        nonce=nonce or str(uuid4()),
        confidence=0.9,
        risk_score=60.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


def _permit(proposal: ActionProposal) -> Decision:
    return Decision(
        proposal_id=proposal.proposal_id,
        outcome=DecisionOutcome.PERMIT,
        reasons=("all_checks_passed",),
        policy_version="test-policy",
        safety_version="test-safety",
        state_version=proposal.observed_state_version,
    )


def test_opa_policy_requires_local_and_external_agreement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = nominal_state(observed_at=datetime.now(UTC))
    proposal = _proposal().model_copy(update={"observed_at": state.observed_at})
    policy = segmented.OpaBackedPolicy("http://opa:8181")

    monkeypatch.setattr(segmented, "request_json", lambda *args, **kwargs: {"result": True})
    assert policy.evaluate(proposal, state).permitted

    monkeypatch.setattr(segmented, "request_json", lambda *args, **kwargs: {"result": False})
    assert policy.evaluate(proposal, state).reasons == ("external_policy_denied",)

    def unavailable(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise segmented.ServiceExchangeError("unavailable")

    monkeypatch.setattr(segmented, "request_json", unavailable)
    assert policy.evaluate(proposal, state).reasons == ("policy_service_unavailable",)

    low_confidence = proposal.model_copy(update={"confidence": 0.1})
    policy = segmented.OpaBackedPolicy("http://opa:8181", ContextualPolicy())
    assert policy.evaluate(low_confidence, state).reasons == (
        "confidence_below_policy_minimum",
    )


def test_simulation_rechecks_gateway_permit_and_state_version() -> None:
    plant = segmented.MutableSurrogatePlant()
    state = plant.observe()
    proposal = _proposal().model_copy(
        update={"observed_at": state.observed_at, "observed_state_version": state.version}
    )
    result = plant.execute(
        segmented.SegmentedExecutionRequest(proposal=proposal, decision=_permit(proposal))
    )
    assert result.executed
    assert result.resulting_state is not None
    assert result.resulting_state.version == state.version + 1

    stale = _proposal().model_copy(
        update={"observed_at": state.observed_at, "observed_state_version": state.version}
    )
    rejected = plant.execute(
        segmented.SegmentedExecutionRequest(proposal=stale, decision=_permit(stale))
    )
    assert not rejected.executed
    assert rejected.reason == "time_of_check_time_of_use_state_change"


def test_ot_adapter_rejects_nonpermit_before_simulation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposal = _proposal()
    denied = _permit(proposal).model_copy(update={"outcome": DecisionOutcome.DENY})
    monkeypatch.setattr(
        segmented,
        "request_json",
        lambda *args, **kwargs: pytest.fail("simulation must not be contacted"),
    )
    with pytest.raises(HTTPException) as exc:
        segmented.ot_execute(
            segmented.SegmentedExecutionRequest(proposal=proposal, decision=denied)
        )
    assert exc.value.status_code == 403


def test_gateway_denies_unsafe_action_without_ot_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = nominal_state(observed_at=datetime.now(UTC))
    proposal = _proposal(impact=30.0).model_copy(update={"observed_at": state.observed_at})
    segmented._gateway_lab = None
    segmented._observation_cache.clear()
    segmented._cache_observation(state)

    calls: list[str] = []

    def exchange(method: str, url: str, payload: Any = None, **kwargs: Any) -> dict[str, Any]:
        del method, payload, kwargs
        calls.append(url)
        if "/v1/data/" in url:
            return {"result": True}
        raise AssertionError("OT must not be contacted for an unsafe proposal")

    monkeypatch.setattr(segmented, "request_json", exchange)
    result = segmented.gateway_action(proposal)
    assert result.decision.outcome is DecisionOutcome.DENY
    assert "critical_load_below_limit" in result.decision.reasons
    assert result.execution is None
    assert calls == ["http://opa:8181/v1/data/aegis/authz/policy_permit"]


def test_gateway_rejects_observation_it_did_not_issue() -> None:
    segmented._observation_cache.clear()
    with pytest.raises(HTTPException) as exc:
        segmented.gateway_action(_proposal())
    assert exc.value.status_code == 409


def test_compose_places_agent_probe_outside_control_networks() -> None:
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    networks = compose["networks"]

    assert set(services["agent-probe"]["networks"]) == {"agent"}
    assert set(services["segmented-gateway"]["networks"]) == {
        "agent",
        "trust",
        "control_dmz",
    }
    assert set(services["observer"]["networks"]) == {"control_dmz", "simulation"}
    assert set(services["ot-adapter"]["networks"]) == {"control_dmz", "simulation"}
    assert set(services["simulation"]["networks"]) == {"simulation"}
    assert set(services["opa"]["networks"]) == {"trust"}
    internal_networks = ("trust", "control_dmz", "simulation")
    assert all(networks[name].get("internal") is True for name in internal_networks)
    assert "ports" not in services["observer"]
    assert "ports" not in services["ot-adapter"]
    assert "ports" not in services["simulation"]
    assert "ports" not in services["opa"]
