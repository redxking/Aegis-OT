from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from pydantic import ValidationError

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


def test_authenticated_ot_adapter_verifies_gateway_and_signs_bound_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway_private = Ed25519PrivateKey.generate()
    ot_private = Ed25519PrivateKey.generate()
    gateway_public_path = tmp_path / "gateway.public"
    ot_private_path = tmp_path / "ot.private"
    gateway_public_path.write_bytes(
        gateway_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    ot_private_path.write_bytes(
        ot_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "true")
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-test-key")
    monkeypatch.setenv("AEGIS_GATEWAY_PUBLIC_KEY_FILE", str(gateway_public_path))
    monkeypatch.setenv("AEGIS_OT_KEY_ID", "ot-test-key")
    monkeypatch.setenv("AEGIS_OT_PRIVATE_KEY_FILE", str(ot_private_path))
    segmented._ot_transport_nonces.clear()

    plant = segmented.MutableSurrogatePlant()
    state = plant.observe()
    proposal = _proposal().model_copy(
        update={"observed_at": state.observed_at, "observed_state_version": state.version}
    )
    execution_request = segmented.SegmentedExecutionRequest(
        proposal=proposal,
        decision=_permit(proposal),
    )
    now = datetime.now(UTC)
    signed = segmented.SignedSegmentedExecutionRequest(
        request=execution_request,
        gateway_key_id="gateway-test-key",
        transport_nonce=str(uuid4()),
        issued_at=now,
        expires_at=now + timedelta(seconds=5),
    ).signed(gateway_private)

    def simulation_exchange(*args: Any, **kwargs: Any) -> dict[str, Any]:
        del args, kwargs
        return plant.execute(execution_request).model_dump(mode="json")

    monkeypatch.setattr(segmented, "request_json", simulation_exchange)
    response = segmented.ot_execute(signed)
    assert isinstance(response, segmented.SignedSegmentedExecutionResponse)
    assert response.verify(ot_private.public_key())
    assert response.request_sha256 == segmented._sha256(signed)
    assert response.execution.executed

    with pytest.raises(HTTPException) as replayed:
        segmented.ot_execute(signed)
    assert replayed.value.status_code == 409

    altered = signed.model_copy(update={"transport_nonce": str(uuid4())})
    with pytest.raises(HTTPException) as tampered:
        segmented.ot_execute(altered)
    assert tampered.value.status_code == 403

    unsupported = signed.model_dump(mode="json")
    unsupported["schema_version"] = "m4e-signed-execution-request-v2"
    with pytest.raises(ValidationError):
        segmented.SignedSegmentedExecutionRequest.model_validate(unsupported)


def test_authenticated_ot_adapter_rejects_unsigned_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "true")
    proposal = _proposal()
    with pytest.raises(HTTPException) as exc:
        segmented.ot_execute(
            segmented.SegmentedExecutionRequest(
                proposal=proposal,
                decision=_permit(proposal),
            )
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
