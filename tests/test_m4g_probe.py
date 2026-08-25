from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from aegis_ot import m4g_probe
from aegis_ot.capability_models import ObservationPhase, SignedObservationEnvelope
from aegis_ot.crypto import generate_keypair
from aegis_ot.physical_factory import build_physical_local_lab
from aegis_ot.segmented_runtime import ServiceExchangeError

NOW = datetime(2026, 8, 25, 20, 0, tzinfo=UTC)


def _observation() -> SignedObservationEnvelope:
    private_key, _ = generate_keypair()
    snapshot = build_physical_local_lab(NOW).plant.read_state()
    return SignedObservationEnvelope.issue(
        snapshot=snapshot,
        correlation_id="m4g-probe-correlation-0001",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="m4g-probe-observation-challenge-0001",
        observer_id="observer:m4g-probe",
        observer_key_id="m4g-probe-observer-key-0001",
        observer_boot_epoch="m4g-probe-observer-boot-0001",
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=private_key,
    )


def test_gateway_url_normalizes_configured_and_default_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGIS_GATEWAY_URL", raising=False)
    assert m4g_probe._gateway_url() == "http://segmented-gateway:8081"

    monkeypatch.setenv("AEGIS_GATEWAY_URL", "http://gateway.example:8081///")
    assert m4g_probe._gateway_url() == "http://gateway.example:8081"


def test_await_gateway_retries_transport_and_readiness_then_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses: list[dict[str, Any] | Exception] = [
        ServiceExchangeError("offline"),
        {"status": "starting"},
        {"status": "ready", "boot_epoch": "gateway-boot"},
    ]
    sleeps: list[float] = []

    def exchange(*_: Any, **__: Any) -> dict[str, Any]:
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(m4g_probe, "request_json", exchange)
    monkeypatch.setattr(m4g_probe.time, "sleep", sleeps.append)

    assert m4g_probe._await_gateway("http://gateway", attempts=3) == {
        "status": "ready",
        "boot_epoch": "gateway-boot",
    }
    assert sleeps == [0.25, 0.25]


def test_await_gateway_exhaustion_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        m4g_probe,
        "request_json",
        lambda *_args, **_kwargs: {"status": "starting"},
    )
    monkeypatch.setattr(m4g_probe.time, "sleep", lambda _: None)

    with pytest.raises(RuntimeError, match="did not become ready"):
        m4g_probe._await_gateway("http://gateway", attempts=2)


def test_capture_pre_uses_bound_challenge_and_json_mode_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    parsed = object()

    class Parser:
        @staticmethod
        def model_validate(value: dict[str, Any]) -> object:
            captured["parsed"] = value
            return parsed

    def exchange(
        method: str,
        url: str,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        captured.update(method=method, url=url, payload=payload)
        return {"signed": "observation"}

    monkeypatch.setattr(m4g_probe, "SignedObservationEnvelope", Parser)
    monkeypatch.setattr(m4g_probe, "request_json", exchange)
    monkeypatch.setattr(m4g_probe.secrets, "token_urlsafe", lambda _: "fixed-challenge")

    assert m4g_probe._capture_pre("http://gateway", "correlation-1") is parsed
    assert captured == {
        "method": "POST",
        "url": "http://gateway/v1/observations/pre",
        "payload": {
            "correlation_id": "correlation-1",
            "challenge_nonce": "fixed-challenge",
        },
        "parsed": {"signed": "observation"},
    }


def test_request_binds_proposal_to_exact_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    observation = _observation()
    monkeypatch.setattr(m4g_probe.secrets, "token_urlsafe", lambda _: "fixed-proposal-nonce")

    request = m4g_probe._request(
        observation,
        proposal_id="m4g-probe-proposal-0001",
        critical_load_impact_pct=5.0,
    )

    assert request.correlation_id == observation.correlation_id
    assert request.observation_id == observation.observation_id
    assert request.observation_envelope_digest == observation.envelope_digest
    assert request.observation_challenge_nonce == observation.challenge_nonce
    assert request.proposal.observed_state_version == observation.snapshot.state_version
    assert request.proposal.observed_at == observation.snapshot.observed_at
    assert request.proposal.nonce == "fixed-proposal-nonce"
    assert request.proposal.parameters == {"critical_load_impact_pct": 5.0}


def test_execute_posts_exact_request_and_parses_terminal_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = m4g_probe._request(
        _observation(),
        proposal_id="m4g-probe-execute-0001",
        critical_load_impact_pct=5.0,
    )
    captured: dict[str, Any] = {}
    parsed = object()

    class Parser:
        @staticmethod
        def model_validate(value: dict[str, Any]) -> object:
            captured["parsed"] = value
            return parsed

    def exchange(*args: Any, **kwargs: Any) -> dict[str, Any]:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"terminal": "result"}

    monkeypatch.setattr(m4g_probe, "SegmentedCapabilityClosedLoopResult", Parser)
    monkeypatch.setattr(m4g_probe, "request_json", exchange)

    assert m4g_probe._execute("http://gateway", request) is parsed
    assert captured["args"] == (
        "POST",
        "http://gateway/v1/capability/actions",
        request.model_dump(mode="json"),
    )
    assert captured["kwargs"] == {"timeout_seconds": 15.0}
    assert captured["parsed"] == {"terminal": "result"}


def test_bypass_results_classify_each_direct_service_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exchange(_method: str, url: str, **_: Any) -> dict[str, Any]:
        if "candidate" in url or "simulation" in url:
            raise ServiceExchangeError("blocked")
        return {"status": "ready"}

    monkeypatch.setattr(m4g_probe, "request_json", exchange)

    assert m4g_probe._bypass_results() == {
        "observer": True,
        "candidate": False,
        "ot-adapter": True,
        "simulation": False,
    }


def test_run_probe_sequences_nominal_replay_and_unsafe_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_WORKLOAD_IDENTITY_MODE", "disabled")
    observations = [object(), object()]
    nominal_request = object()
    unsafe_request = object()
    requests = [nominal_request, unsafe_request]
    results = [
        {"status": "applied"},
        {"status": "rejected", "reason": "replay"},
        {"status": "denied", "reason": "unsafe"},
    ]
    executed: list[object] = []

    class Result:
        def __init__(self, value: dict[str, str]) -> None:
            self.value = value

        def model_dump(self, *, mode: str) -> dict[str, str]:
            assert mode == "json"
            return self.value

    monkeypatch.setattr(m4g_probe, "_gateway_url", lambda: "http://gateway")
    monkeypatch.setattr(
        m4g_probe,
        "_await_gateway",
        lambda _: {"status": "ready"},
    )
    monkeypatch.setattr(m4g_probe, "_capture_pre", lambda *_: observations.pop(0))
    monkeypatch.setattr(m4g_probe, "_request", lambda *_args, **_kwargs: requests.pop(0))

    def execute(_url: str, request: object) -> Result:
        executed.append(request)
        return Result(results.pop(0))

    monkeypatch.setattr(m4g_probe, "_execute", execute)
    monkeypatch.setattr(
        m4g_probe,
        "_bypass_results",
        lambda: {"observer": False},
    )

    record = m4g_probe.run_probe()

    assert record == {
        "schema_version": "m4g-capability-probe-v1",
        "gateway_health": {"status": "ready"},
        "nominal": {"status": "applied"},
        "exact_gateway_request_replay": {"status": "rejected", "reason": "replay"},
        "unsafe": {"status": "denied", "reason": "unsafe"},
        "agent_direct_reachability": {"observer": False},
    }
    assert executed == [nominal_request, nominal_request, unsafe_request]


def test_main_emits_one_canonical_json_record(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = {"z": 1, "a": {"value": True}}
    monkeypatch.setattr(m4g_probe, "run_probe", lambda: record)

    m4g_probe.main()

    assert capsys.readouterr().out == json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
