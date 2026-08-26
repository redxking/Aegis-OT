"""Bounded trust-host relay between SPIRE mTLS and loopback-only OPA.

The relay exposes only the supervisory policy query used by the segmented
gateway.  TLS client authentication is supplied by ``aegis_ot.spire_mtls``;
this ASGI layer strictly validates the request and permits outbound access only
to the fixed loopback OPA endpoint declared by the M4j deployment contract.
"""

from __future__ import annotations

import ipaddress
import json
import os
from typing import Final
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .segmented_capability_transport import (
    CapabilityTransportError,
    HttpExchange,
    urllib_http_exchange,
)
from .segmented_runtime import ServiceExchangeError, _parse_opa_exchange_response
from .strict_json_request import StrictJsonRequestError, parse_strict_json_request

OPA_POLICY_PATH: Final = "/v1/data/aegis/authz/policy_permit"
OPA_LOOPBACK_PORT: Final = 8182
DEFAULT_OPA_BACKEND_URL: Final = f"http://127.0.0.1:{OPA_LOOPBACK_PORT}"
DEFAULT_TIMEOUT_SECONDS: Final = 3.0


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
    )


class PolicyProposal(_StrictModel):
    confidence: float = Field(ge=0, le=1)
    risk_score: float = Field(ge=0, le=100)


class PolicyInput(_StrictModel):
    proposal: PolicyProposal


class PolicyQuery(_StrictModel):
    input: PolicyInput


class PolicyDecision(_StrictModel):
    result: bool


def _normalized_backend_url(value: str) -> str:
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("OPA backend must use an explicit loopback IP address and port") from exc
    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or port != OPA_LOOPBACK_PORT
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            f"OPA backend must be loopback HTTP on the fixed port {OPA_LOOPBACK_PORT}"
        )
    return normalized


class PolicyRelay:
    """Forward one exact policy query to a fixed, local-only OPA service."""

    def __init__(
        self,
        backend_url: str,
        *,
        exchange: HttpExchange = urllib_http_exchange,
    ) -> None:
        self.backend_url = _normalized_backend_url(backend_url)
        self.exchange = exchange

    def evaluate(self, query: PolicyQuery) -> PolicyDecision:
        body = json.dumps(
            query.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        try:
            response = self.exchange(
                method="POST",
                url=f"{self.backend_url}{OPA_POLICY_PATH}",
                body=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
            )
            result = _parse_opa_exchange_response(
                status_code=response.status_code,
                content_type=response.content_type,
                body=response.body,
            )
        except (CapabilityTransportError, ServiceExchangeError, ValueError) as exc:
            raise ServiceExchangeError("loopback OPA decision is unavailable") from exc
        return PolicyDecision(result=result)


def _rejection(exc: StrictJsonRequestError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "rejected", "reason": exc.reason.value},
    )


def create_policy_relay_app(relay: PolicyRelay) -> FastAPI:
    app = FastAPI(title="Aegis-OT M4j SPIRE-authenticated Policy Relay")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": "policy-relay",
            "backend_scope": "loopback-only",
        }

    @app.post(OPA_POLICY_PATH, response_model=PolicyDecision)
    async def policy_permit(request: Request) -> PolicyDecision | JSONResponse:
        try:
            query = await parse_strict_json_request(request, PolicyQuery)
        except StrictJsonRequestError as exc:
            return _rejection(exc)
        try:
            return relay.evaluate(query)
        except ServiceExchangeError:
            return JSONResponse(
                status_code=503,
                content={"status": "error", "reason": "policy_backend_unavailable"},
            )

    return app


policy_relay_app = create_policy_relay_app(
    PolicyRelay(os.getenv("AEGIS_OPA_BACKEND_URL", DEFAULT_OPA_BACKEND_URL))
)

