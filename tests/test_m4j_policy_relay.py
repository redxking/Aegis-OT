from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from aegis_ot.lab import nominal_state
from aegis_ot.models import ActionProposal, Operation
from aegis_ot.policy_relay import (
    DEFAULT_OPA_BACKEND_URL,
    OPA_POLICY_PATH,
    PolicyQuery,
    PolicyRelay,
    create_policy_relay_app,
)
from aegis_ot.segmented_capability_transport import (
    CapabilityTransportUnavailable,
    HttpExchangeResponse,
)
from aegis_ot.segmented_runtime import OpaBackedPolicy


class RecordingExchange:
    def __init__(self, response: HttpExchangeResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> HttpExchangeResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "body": body,
                "headers": dict(headers),
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.response


def _query() -> dict[str, object]:
    return {
        "input": {
            "proposal": {
                "confidence": 0.91,
                "risk_score": 41.0,
            }
        }
    }


def _proposal() -> ActionProposal:
    now = datetime.now(UTC)
    return ActionProposal(
        actor_id="agent:m4j-policy-test",
        mission_id="m4j-policy-relay",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=1,
        observed_at=now,
        submitted_at=now,
        nonce=str(uuid4()),
        confidence=0.91,
        risk_score=41.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://opa:8182",
        "http://localhost:8182",
        "http://192.168.59.11:8182",
        "https://127.0.0.1:8182",
        "http://127.0.0.1:8181",
        "http://user:password@127.0.0.1:8182",
        "http://127.0.0.1:8182/path",
    ],
)
def test_policy_relay_rejects_noncontract_backend_urls(url: str) -> None:
    with pytest.raises(ValueError, match="OPA backend"):
        PolicyRelay(url)


def test_policy_relay_forwards_only_the_exact_policy_query() -> None:
    exchange = RecordingExchange(
        HttpExchangeResponse(
            status_code=200,
            content_type="application/json; charset=utf-8",
            body=b'{"result":true}',
        )
    )
    relay = PolicyRelay(DEFAULT_OPA_BACKEND_URL, exchange=exchange)

    result = relay.evaluate(PolicyQuery.model_validate(_query(), strict=True))

    assert result.result is True
    assert exchange.calls == [
        {
            "method": "POST",
            "url": f"{DEFAULT_OPA_BACKEND_URL}{OPA_POLICY_PATH}",
            "body": b'{"input":{"proposal":{"confidence":0.91,"risk_score":41.0}}}',
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            "timeout_seconds": 3.0,
        }
    ]


def test_policy_relay_app_rejects_ambiguous_or_expanded_input() -> None:
    exchange = RecordingExchange(
        HttpExchangeResponse(200, "application/json", b'{"result":true}')
    )
    client = TestClient(
        create_policy_relay_app(PolicyRelay(DEFAULT_OPA_BACKEND_URL, exchange=exchange))
    )

    duplicate = b'{"input":{"proposal":{"confidence":0.91,"confidence":0.4,"risk_score":41.0}}}'
    response = client.post(
        OPA_POLICY_PATH,
        content=duplicate,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json() == {
        "status": "rejected",
        "reason": "duplicate_json_key",
    }

    expanded = _query()
    assert isinstance(expanded["input"], dict)
    expanded["input"]["identity"] = {"verified": True}
    response = client.post(OPA_POLICY_PATH, json=expanded)
    assert response.status_code == 400
    assert response.json() == {
        "status": "rejected",
        "reason": "request_model_validation_failed",
    }
    assert exchange.calls == []


def test_policy_relay_app_returns_only_a_decision_and_fails_closed() -> None:
    permitted = RecordingExchange(
        HttpExchangeResponse(200, "application/json", b'{"result":true}')
    )
    client = TestClient(
        create_policy_relay_app(PolicyRelay(DEFAULT_OPA_BACKEND_URL, exchange=permitted))
    )
    response = client.post(OPA_POLICY_PATH, json=_query())
    assert response.status_code == 200
    assert response.json() == {"result": True}

    def unavailable(**_kwargs: Any) -> HttpExchangeResponse:
        raise CapabilityTransportUnavailable("OPA unavailable")

    failed_client = TestClient(
        create_policy_relay_app(PolicyRelay(DEFAULT_OPA_BACKEND_URL, exchange=unavailable))
    )
    failed = failed_client.post(OPA_POLICY_PATH, json=_query())
    assert failed.status_code == 503
    assert failed.json() == {
        "status": "error",
        "reason": "policy_backend_unavailable",
    }


@pytest.mark.parametrize(
    ("response", "expected_reasons"),
    [
        (
            HttpExchangeResponse(200, "application/json", b'{"result":true}'),
            (),
        ),
        (
            HttpExchangeResponse(200, "application/json", b'{"result":false}'),
            ("external_policy_denied",),
        ),
        (
            HttpExchangeResponse(200, "application/json", b'{"result":true,"extra":1}'),
            ("policy_service_unavailable",),
        ),
        (
            HttpExchangeResponse(503, "application/json", b'{"result":true}'),
            ("policy_service_unavailable",),
        ),
    ],
)
def test_gateway_policy_uses_the_configured_authenticated_exchange(
    response: HttpExchangeResponse,
    expected_reasons: tuple[str, ...],
) -> None:
    exchange = RecordingExchange(response)
    policy = OpaBackedPolicy("https://192.168.59.11:8181", exchange=exchange)

    result = policy.evaluate(_proposal(), nominal_state(version=1))

    assert result.reasons == expected_reasons
    assert result.permitted is not bool(expected_reasons)
    assert exchange.calls[0]["url"] == f"https://192.168.59.11:8181{OPA_POLICY_PATH}"
    assert json.loads(exchange.calls[0]["body"]) == _query()

