from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
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
from aegis_ot.lab import SimulatedCommandAdapter, nominal_state
from aegis_ot.models import ActionProposal, Decision, DecisionOutcome, Operation
from aegis_ot.policy import ContextualPolicy
from aegis_ot.transport_replay import (
    DurableTransportReplayLedger,
    TransportReplayLedgerError,
)


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


def _configure_durable_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    plant: segmented.MutableSurrogatePlant,
    *,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    decision_outcome: DecisionOutcome = DecisionOutcome.PERMIT,
) -> tuple[
    segmented.SignedSegmentedExecutionRequest,
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    Path,
]:
    gateway_private = Ed25519PrivateKey.generate()
    ot_private = Ed25519PrivateKey.generate()
    gateway_public = gateway_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    gateway_public_path = tmp_path / "gateway.public"
    ot_private_path = tmp_path / "ot.private"
    gateway_public_path.write_bytes(gateway_public)
    ot_private_path.write_bytes(
        ot_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    replay_directory = tmp_path / "replay"
    replay_directory.mkdir(mode=0o700)
    replay_path = replay_directory / "transport-replay.json"
    DurableTransportReplayLedger(
        replay_path,
        audience="aegis-ot:ot-adapter",
        gateway_key_id="gateway-test-key",
        gateway_public_key_sha256=hashlib.sha256(gateway_public).hexdigest(),
        initialize=True,
    )
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "true")
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_MODE", "durable")
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_LEDGER_FILE", str(replay_path))
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-test-key")
    monkeypatch.setenv("AEGIS_GATEWAY_PUBLIC_KEY_FILE", str(gateway_public_path))
    monkeypatch.setenv("AEGIS_OT_KEY_ID", "ot-test-key")
    monkeypatch.setenv("AEGIS_OT_PRIVATE_KEY_FILE", str(ot_private_path))
    segmented._durable_transport_replay = None
    segmented._durable_transport_replay_config = None

    state = plant.observe()
    proposal = _proposal().model_copy(
        update={"observed_at": state.observed_at, "observed_state_version": state.version}
    )
    decision = _permit(proposal).model_copy(update={"outcome": decision_outcome})
    now = datetime.now(UTC)
    signed = segmented.SignedSegmentedExecutionRequest(
        request=segmented.SegmentedExecutionRequest(
            proposal=proposal,
            decision=decision,
        ),
        gateway_key_id="gateway-test-key",
        transport_nonce=str(uuid4()),
        issued_at=issued_at or now,
        expires_at=expires_at or now + timedelta(seconds=5),
    ).signed(gateway_private)
    return signed, gateway_private, ot_private, replay_path


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


def test_durable_transport_replay_survives_runtime_reconstruction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plant = segmented.MutableSurrogatePlant()
    signed, _, ot_private, replay_path = _configure_durable_transport(
        tmp_path,
        monkeypatch,
        plant,
    )
    simulation_calls = 0

    def simulation_exchange(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal simulation_calls
        del args, kwargs
        simulation_calls += 1
        return plant.execute(signed.request).model_dump(mode="json")

    monkeypatch.setattr(segmented, "request_json", simulation_exchange)
    response = segmented.ot_execute(signed)
    assert isinstance(response, segmented.SignedSegmentedExecutionResponse)
    assert response.verify(ot_private.public_key())
    assert simulation_calls == 1

    segmented._durable_transport_replay = None
    segmented._durable_transport_replay_config = None
    with pytest.raises(HTTPException) as replayed:
        segmented.ot_execute(signed)
    assert replayed.value.status_code == 409
    assert simulation_calls == 1
    health = segmented.ot_health()
    assert health["replay_mode"] == "durable"
    assert health["replay_reservations"] == 1
    assert DurableTransportReplayLedger(
        replay_path,
        audience="aegis-ot:ot-adapter",
        gateway_key_id="gateway-test-key",
        gateway_public_key_sha256=hashlib.sha256(
            (tmp_path / "gateway.public").read_bytes()
        ).hexdigest(),
    ).reservation_count == 1


def test_durable_replay_missing_or_corrupt_fails_closed_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plant = segmented.MutableSurrogatePlant()
    signed, _, _, replay_path = _configure_durable_transport(
        tmp_path,
        monkeypatch,
        plant,
    )
    replay_path.unlink()
    segmented._durable_transport_replay = None
    segmented._durable_transport_replay_config = None
    monkeypatch.setattr(
        segmented,
        "request_json",
        lambda *args, **kwargs: pytest.fail("simulation must not be contacted"),
    )
    with pytest.raises(HTTPException) as missing:
        segmented.ot_execute(signed)
    assert missing.value.status_code == 503
    with pytest.raises(HTTPException) as unhealthy:
        segmented.ot_health()
    assert unhealthy.value.status_code == 503

    replay_path.write_text("{corrupt", encoding="utf-8")
    replay_path.chmod(0o600)
    segmented._durable_transport_replay = None
    segmented._durable_transport_replay_config = None
    with pytest.raises(HTTPException) as corrupt:
        segmented.ot_execute(signed)
    assert corrupt.value.status_code == 503


def test_durable_transport_invalid_requests_do_not_consume_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plant = segmented.MutableSurrogatePlant()
    signed, gateway_private, _, replay_path = _configure_durable_transport(
        tmp_path,
        monkeypatch,
        plant,
    )
    monkeypatch.setattr(
        segmented,
        "request_json",
        lambda *args, **kwargs: pytest.fail("simulation must not be contacted"),
    )

    now = datetime.now(UTC)
    expired = signed.model_copy(
        update={
            "transport_nonce": str(uuid4()),
            "issued_at": now - timedelta(seconds=10),
            "expires_at": now - timedelta(seconds=5),
            "signature": "",
        }
    ).signed(gateway_private)
    excessive_ttl = signed.model_copy(
        update={
            "transport_nonce": str(uuid4()),
            "issued_at": now,
            "expires_at": now + timedelta(seconds=61),
            "signature": "",
        }
    ).signed(gateway_private)
    denied_request = signed.request.model_copy(
        update={
            "decision": signed.request.decision.model_copy(
                update={"outcome": DecisionOutcome.DENY}
            )
        }
    )
    denied = signed.model_copy(
        update={
            "request": denied_request,
            "transport_nonce": str(uuid4()),
            "signature": "",
        }
    ).signed(gateway_private)
    forged = signed.model_copy(
        update={"transport_nonce": str(uuid4()), "signature": ""}
    ).signed(Ed25519PrivateKey.generate())

    for invalid in (expired, excessive_ttl, denied, forged):
        with pytest.raises(HTTPException) as rejected:
            segmented.ot_execute(invalid)
        assert rejected.value.status_code == 403
    assert segmented._durable_replay_ledger().reservation_count == 0
    assert replay_path.exists()
def test_durable_reservation_failure_prevents_simulation_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plant = segmented.MutableSurrogatePlant()
    signed, _, _, _ = _configure_durable_transport(tmp_path, monkeypatch, plant)
    monkeypatch.setattr(
        segmented,
        "_reserve_transport_nonce",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            TransportReplayLedgerError("injected persistence failure")
        ),
    )
    monkeypatch.setattr(
        segmented,
        "request_json",
        lambda *args, **kwargs: pytest.fail("simulation must not be contacted"),
    )
    with pytest.raises(HTTPException) as unavailable:
        segmented.ot_execute(signed)
    assert unavailable.value.status_code == 503


def test_ot_adapter_rejects_unbound_simulation_result_before_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plant = segmented.MutableSurrogatePlant()
    signed, _, _, _ = _configure_durable_transport(tmp_path, monkeypatch, plant)
    valid = SimulatedCommandAdapter().execute(
        signed.request.proposal,
        signed.request.decision,
        plant.observe(),
    )
    mismatched = valid.model_copy(update={"proposal_id": "unrelated-proposal"})
    monkeypatch.setattr(
        segmented,
        "request_json",
        lambda *args, **kwargs: mismatched.model_dump(mode="json"),
    )

    with pytest.raises(HTTPException) as unavailable:
        segmented.ot_execute(signed)
    assert unavailable.value.status_code == 503
    with pytest.raises(HTTPException) as replayed:
        segmented.ot_execute(signed)
    assert replayed.value.status_code == 409


@pytest.mark.parametrize("effect_applied", [False, True])
def test_lost_simulation_response_consumes_reservation_without_redispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    effect_applied: bool,
) -> None:
    plant = segmented.MutableSurrogatePlant()
    signed, _, _, _ = _configure_durable_transport(tmp_path, monkeypatch, plant)
    initial_version = plant.observe().version
    simulation_calls = 0

    def lost_response(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal simulation_calls
        del args, kwargs
        simulation_calls += 1
        if effect_applied:
            assert plant.execute(signed.request).executed
        raise segmented.ServiceExchangeError("injected response loss")

    monkeypatch.setattr(segmented, "request_json", lost_response)
    with pytest.raises(HTTPException) as unavailable:
        segmented.ot_execute(signed)
    assert unavailable.value.status_code == 503
    resulting_version = plant.observe().version
    assert resulting_version == initial_version + int(effect_applied)

    with pytest.raises(HTTPException) as replayed:
        segmented.ot_execute(signed)
    assert replayed.value.status_code == 409
    assert simulation_calls == 1
    assert plant.observe().version == resulting_version


def test_concurrent_durable_signed_request_dispatches_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plant = segmented.MutableSurrogatePlant()
    signed, _, _, _ = _configure_durable_transport(tmp_path, monkeypatch, plant)
    simulation_calls = 0

    def simulation_exchange(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal simulation_calls
        del args, kwargs
        simulation_calls += 1
        return plant.execute(signed.request).model_dump(mode="json")

    monkeypatch.setattr(segmented, "request_json", simulation_exchange)

    def execute() -> int:
        try:
            segmented.ot_execute(signed)
        except HTTPException as exc:
            return exc.status_code
        return 200

    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(lambda _: execute(), range(8)))
    assert statuses.count(200) == 1
    assert statuses.count(409) == 7
    assert simulation_calls == 1


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


def test_gateway_rejects_signed_ot_response_with_unbound_inner_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway_private = Ed25519PrivateKey.generate()
    ot_private = Ed25519PrivateKey.generate()
    gateway_private_path = tmp_path / "gateway.private"
    ot_public_path = tmp_path / "ot.public"
    gateway_private_path.write_bytes(
        gateway_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    ot_public_path.write_bytes(
        ot_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "true")
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-test-key")
    monkeypatch.setenv("AEGIS_GATEWAY_PRIVATE_KEY_FILE", str(gateway_private_path))
    monkeypatch.setenv("AEGIS_OT_KEY_ID", "ot-test-key")
    monkeypatch.setenv("AEGIS_OT_PUBLIC_KEY_FILE", str(ot_public_path))
    state = nominal_state(observed_at=datetime.now(UTC))
    proposal = _proposal().model_copy(
        update={"observed_at": state.observed_at, "observed_state_version": state.version}
    )
    segmented._gateway_lab = None
    segmented._observation_cache.clear()
    segmented._cache_observation(state)

    def exchange(
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        del method, kwargs
        if "/v1/data/" in url:
            return {"result": True}
        assert payload is not None
        signed_request = segmented.SignedSegmentedExecutionRequest.model_validate(payload)
        execution = SimulatedCommandAdapter().execute(
            signed_request.request.proposal,
            signed_request.request.decision,
            state,
        ).model_copy(update={"decision_id": "unrelated-decision"})
        return segmented.SignedSegmentedExecutionResponse(
            request_sha256=segmented._sha256(signed_request),
            execution=execution,
            ot_key_id="ot-test-key",
            signed_at=datetime.now(UTC),
        ).signed(ot_private).model_dump(mode="json")

    monkeypatch.setattr(segmented, "request_json", exchange)
    with pytest.raises(HTTPException) as unavailable:
        segmented.gateway_action(proposal)
    assert unavailable.value.status_code == 503


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


def test_replay_overlay_requires_identity_bound_single_writer_volume() -> None:
    base = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    replay = yaml.safe_load(
        Path("docker-compose.replay.yml").read_text(encoding="utf-8")
    )
    ot_base = base["services"]["ot-adapter"]
    ot_replay = replay["services"]["ot-adapter"]
    initializer = replay["services"]["replay-init"]

    assert "--workers" not in ot_base["command"]
    assert ot_replay["environment"]["AEGIS_TRANSPORT_REPLAY_MODE"] == "durable"
    assert ot_replay["volumes"] == ["transport_replay:/var/lib/aegis-ot"]
    assert ot_replay["depends_on"]["replay-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert initializer["user"] == "0:0"
    assert initializer["cap_drop"] == ["ALL"]
    assert initializer["cap_add"] == ["CHOWN"]
    assert initializer["network_mode"] == "none"
    assert set(replay["volumes"]) == {"transport_replay", "transport_probe"}
