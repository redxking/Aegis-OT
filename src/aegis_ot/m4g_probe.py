"""Agent-network probe for the M4g-a signed capability experiment."""

from __future__ import annotations

import json
import os
import secrets
import socket
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from .capability_models import (
    CapabilityActionRequest,
    SignedObservationEnvelope,
)
from .models import ActionProposal, Operation
from .segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    SegmentedCapabilityClosedLoopResult,
    WorkloadAuthenticatedCapabilityAction,
)
from .segmented_capability_transport import MAX_JSON_BYTES, CapabilityTransportError
from .segmented_runtime import ServiceExchangeError
from .segmented_runtime import request_json as plaintext_request_json
from .spire_mtls import capability_http_exchange_from_environment
from .workload_identity import WorkloadRole
from .workload_runtime import (
    local_identity_from_environment,
    verifier_from_environment,
    workload_identity_enabled,
)

AGENT_PROOF_TTL = timedelta(seconds=30)


def _unique_response_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ServiceExchangeError("required service response repeats a JSON key")
        result[key] = value
    return result


def _reject_response_constant(value: str) -> None:
    raise ServiceExchangeError(f"forbidden JSON constant: {value}")


def request_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Use the explicitly configured primary gateway transport without downgrade."""

    mode = os.getenv("AEGIS_SPIRE_MTLS_MODE")
    scheme = urlsplit(url).scheme
    if mode == "disabled":
        if scheme != "http":
            raise ServiceExchangeError("disabled SPIRE mode requires an HTTP gateway URL")
        return plaintext_request_json(
            method,
            url,
            payload,
            timeout_seconds=timeout_seconds,
        )
    if mode != "required" or scheme != "https":
        raise ServiceExchangeError("required SPIRE mode requires an HTTPS gateway URL")
    body = None if payload is None else _wire_json(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        response = capability_http_exchange_from_environment()(
            method=method,
            url=url,
            body=body,
            headers=headers,
            timeout_seconds=timeout_seconds,
        )
    except (CapabilityTransportError, OSError, TimeoutError, ValueError) as exc:
        raise ServiceExchangeError(f"required service exchange failed: {url}") from exc
    if (
        not 200 <= response.status_code < 300
        or response.content_type.split(";", maxsplit=1)[0].strip().lower()
        != "application/json"
        or len(response.body) > MAX_JSON_BYTES
    ):
        raise ServiceExchangeError("required service response failed its HTTP contract")
    try:
        value = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_unique_response_object,
            parse_constant=_reject_response_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ServiceExchangeError("required service response was not strict JSON") from exc
    if not isinstance(value, dict):
        raise ServiceExchangeError("required service response root was not an object")
    return value


def _tcp_reachable(host: str, port: int, *, timeout_seconds: float = 1.0) -> bool:
    """Observe path reachability without conflating it with TLS rejection."""

    try:
        connection = socket.create_connection((host, port), timeout=timeout_seconds)
    except (OSError, TimeoutError):
        return False
    connection.close()
    return True


def _wire_json(payload: dict[str, Any]) -> str:
    """Re-enter Pydantic through its strict JSON decoding boundary."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _gateway_url() -> str:
    return os.getenv(
        "AEGIS_GATEWAY_URL",
        "http://segmented-gateway:8081",
    ).rstrip("/")


def _await_gateway(url: str, attempts: int = 80) -> dict[str, Any]:
    for _ in range(attempts):
        try:
            health = request_json("GET", f"{url}/health", timeout_seconds=1.0)
        except ServiceExchangeError:
            time.sleep(0.25)
            continue
        if health.get("status") == "ready":
            return health
        time.sleep(0.25)
    raise RuntimeError("M4g gateway did not become ready")


def _capture_pre(url: str, correlation_id: str) -> SignedObservationEnvelope:
    payload = request_json(
        "POST",
        f"{url}/v1/observations/pre",
        {
            "correlation_id": correlation_id,
            "challenge_nonce": secrets.token_urlsafe(24),
        },
    )
    return SignedObservationEnvelope.model_validate_json(_wire_json(payload))


def _request(
    observation: SignedObservationEnvelope,
    *,
    proposal_id: str,
    critical_load_impact_pct: float,
) -> CapabilityActionRequest:
    proposal = ActionProposal(
        proposal_id=proposal_id,
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": critical_load_impact_pct},
        observed_state_version=observation.snapshot.state_version,
        observed_at=observation.snapshot.observed_at,
        submitted_at=datetime.now(UTC),
        nonce=secrets.token_urlsafe(24),
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )
    return CapabilityActionRequest(
        correlation_id=observation.correlation_id,
        proposal=proposal,
        observation_id=observation.observation_id,
        observation_envelope_digest=observation.envelope_digest,
        observation_challenge_nonce=observation.challenge_nonce,
    )


def _execute(
    url: str,
    request: CapabilityActionRequest | WorkloadAuthenticatedCapabilityAction,
) -> SegmentedCapabilityClosedLoopResult:
    payload = request_json(
        "POST",
        f"{url}/v1/capability/actions",
        request.model_dump(mode="json"),
        timeout_seconds=15.0,
    )
    return SegmentedCapabilityClosedLoopResult.model_validate_json(_wire_json(payload))


def _wire_request(
    request: CapabilityActionRequest,
) -> CapabilityActionRequest | WorkloadAuthenticatedCapabilityAction:
    if not workload_identity_enabled():
        return request
    verifier = verifier_from_environment()
    agent = local_identity_from_environment(
        verifier,
        "AGENT",
        role=WorkloadRole.AGENT,
        audience=GATEWAY_CAPABILITY_AUDIENCE,
    )
    issued_at = datetime.now(UTC)
    return WorkloadAuthenticatedCapabilityAction.issue(
        request=request,
        signer=agent.signer,
        request_nonce=request.proposal.nonce,
        issued_at=issued_at,
        expires_at=issued_at + AGENT_PROOF_TTL,
    )


def _bypass_results() -> dict[str, bool]:
    reachable: dict[str, bool] = {}
    for service, port in (
        ("observer", 8082),
        ("candidate", 8085),
        ("ot-adapter", 8083),
        ("simulation", 8084),
    ):
        reachable[service] = _tcp_reachable(service, port)
    return reachable


def run_probe() -> dict[str, Any]:
    url = _gateway_url()
    health = _await_gateway(url)

    nominal_observation = _capture_pre(url, str(uuid4()))
    nominal_request = _request(
        nominal_observation,
        proposal_id=f"m4g-nominal-{uuid4()}",
        critical_load_impact_pct=5.0,
    )
    nominal_wire_request = _wire_request(nominal_request)
    nominal = _execute(url, nominal_wire_request)
    replay = _execute(url, nominal_wire_request)

    unsafe_observation = _capture_pre(url, str(uuid4()))
    unsafe_request = _request(
        unsafe_observation,
        proposal_id=f"m4g-unsafe-{uuid4()}",
        critical_load_impact_pct=30.0,
    )
    unsafe = _execute(url, _wire_request(unsafe_request))

    return {
        "schema_version": "m4g-capability-probe-v1",
        "gateway_health": health,
        "nominal": nominal.model_dump(mode="json"),
        "exact_gateway_request_replay": replay.model_dump(mode="json"),
        "unsafe": unsafe.model_dump(mode="json"),
        "agent_direct_reachability": _bypass_results(),
    }


def main() -> None:
    print(json.dumps(run_probe(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
