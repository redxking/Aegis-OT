"""Minimum container-network assurance path for the M4d segmentation increment.

The services in this module deliberately reuse the bounded v0.1 supervisory
model. They test network placement and fail-closed service composition; they
do not claim workload-credential, OpenPLC, HELICS, or production-OT fidelity.
"""

from __future__ import annotations

import json
import os
import socket
from collections import OrderedDict
from datetime import UTC, datetime
from threading import Lock
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from .factory import LocalLab, build_local_lab
from .lab import SimulatedCommandAdapter, nominal_state
from .models import (
    ActionProposal,
    Decision,
    DecisionOutcome,
    ExecutionResult,
    Operation,
    SystemState,
)
from .policy import ContextualPolicy, PolicyResult


class ServiceExchangeError(RuntimeError):
    """A required segmented peer did not return a trustworthy JSON response."""


def request_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if urlsplit(url).scheme not in {"http", "https"}:
        raise ServiceExchangeError("required service URL must use HTTP or HTTPS")
    request = Request(url, data=body, headers=headers, method=method)  # noqa: S310
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            raw = response.read(1_048_577)
    except (HTTPError, TimeoutError, URLError, OSError) as exc:
        raise ServiceExchangeError(f"required service exchange failed: {url}") from exc
    if len(raw) > 1_048_576:
        raise ServiceExchangeError("required service response exceeded the size limit")
    try:
        parsed = json.loads(raw)
    except (RecursionError, ValueError) as exc:
        raise ServiceExchangeError("required service response was not JSON") from exc
    if not isinstance(parsed, dict):
        raise ServiceExchangeError("required service response root was not an object")
    return parsed


class OpaBackedPolicy:
    """Apply local contextual rules and require OPA agreement for permits."""

    version = "contextual-v1+opa-aegis-v1"

    def __init__(self, opa_url: str, local: ContextualPolicy | None = None) -> None:
        self.opa_url = opa_url.rstrip("/")
        self.local = local or ContextualPolicy()

    def evaluate(self, proposal: ActionProposal, state: SystemState) -> PolicyResult:
        local_result = self.local.evaluate(proposal, state)
        if local_result.reasons:
            return local_result
        try:
            response = request_json(
                "POST",
                f"{self.opa_url}/v1/data/aegis/authz/policy_permit",
                {
                    "input": {
                        "proposal": {
                            "confidence": proposal.confidence,
                            "risk_score": proposal.risk_score,
                        }
                    }
                },
            )
        except ServiceExchangeError:
            return PolicyResult(permitted=False, reasons=("policy_service_unavailable",))
        if response.get("result") is not True:
            return PolicyResult(permitted=False, reasons=("external_policy_denied",))
        return PolicyResult(permitted=True, reasons=())


class SegmentedExecutionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal: ActionProposal
    decision: Decision


class SegmentedActionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal_id: str
    decision: Decision
    execution: ExecutionResult | None = None


class MutableSurrogatePlant:
    """One authoritative synthetic state owned only by the simulation service."""

    def __init__(self) -> None:
        self._state = nominal_state()
        self._lock = Lock()
        self._adapter = SimulatedCommandAdapter()

    def observe(self) -> SystemState:
        with self._lock:
            return self._state.model_copy(update={"observed_at": datetime.now(UTC)})

    def execute(self, request: SegmentedExecutionRequest) -> ExecutionResult:
        with self._lock:
            current = self._state.model_copy(update={"observed_at": datetime.now(UTC)})
            result = self._adapter.execute(request.proposal, request.decision, current)
            if result.executed:
                assert result.resulting_state is not None
                self._state = result.resulting_state
            return result


def build_gateway_lab(opa_url: str) -> LocalLab:
    lab = build_local_lab()
    lab.gateway.policy = OpaBackedPolicy(opa_url)
    return lab


simulation_app = FastAPI(title="Aegis-OT M4d Synthetic Simulation Service")
observer_app = FastAPI(title="Aegis-OT M4d Read-Only Observer Service")
ot_adapter_app = FastAPI(title="Aegis-OT M4d OT Command Adapter")
segmented_gateway_app = FastAPI(title="Aegis-OT M4d Segmented Gateway")

_plant = MutableSurrogatePlant()
_gateway_lab: LocalLab | None = None
_gateway_lock = Lock()
_observation_cache: OrderedDict[tuple[int, str], SystemState] = OrderedDict()
_observation_cache_lock = Lock()
_MAX_CACHED_OBSERVATIONS = 128


def _gateway() -> LocalLab:
    global _gateway_lab  # noqa: PLW0603 - one process-local gateway instance
    if _gateway_lab is None:
        with _gateway_lock:
            if _gateway_lab is None:
                _gateway_lab = build_gateway_lab(os.getenv("AEGIS_OPA_URL", "http://opa:8181"))
    return _gateway_lab


def _observation_key(state: SystemState) -> tuple[int, str]:
    return state.version, state.observed_at.isoformat()


def _cache_observation(state: SystemState) -> None:
    key = _observation_key(state)
    with _observation_cache_lock:
        _observation_cache[key] = state
        _observation_cache.move_to_end(key)
        while len(_observation_cache) > _MAX_CACHED_OBSERVATIONS:
            _observation_cache.popitem(last=False)


def _resolve_observation(proposal: ActionProposal) -> SystemState | None:
    key = proposal.observed_state_version, proposal.observed_at.isoformat()
    with _observation_cache_lock:
        return _observation_cache.get(key)


@simulation_app.get("/health")
def simulation_health() -> dict[str, str]:
    return {"status": "ok", "role": "synthetic-simulation"}


@simulation_app.get("/internal/state", response_model=SystemState)
def simulation_state() -> SystemState:
    return _plant.observe()


@simulation_app.post("/internal/apply", response_model=ExecutionResult)
def simulation_apply(request: SegmentedExecutionRequest) -> ExecutionResult:
    return _plant.execute(request)


@observer_app.get("/health")
def observer_health() -> dict[str, str]:
    return {"status": "ok", "role": "observer"}


@observer_app.get("/internal/state", response_model=SystemState)
def observed_state() -> SystemState:
    try:
        payload = request_json(
            "GET",
            f"{os.getenv('AEGIS_SIMULATION_URL', 'http://simulation:8084')}/internal/state",
        )
        return SystemState.model_validate(payload)
    except (ServiceExchangeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="simulation observation unavailable") from exc


@ot_adapter_app.get("/health")
def ot_health() -> dict[str, str]:
    return {"status": "ok", "role": "ot-adapter"}


@ot_adapter_app.post("/internal/execute", response_model=ExecutionResult)
def ot_execute(request: SegmentedExecutionRequest) -> ExecutionResult:
    if (
        request.decision.outcome is not DecisionOutcome.PERMIT
        or request.decision.proposal_id != request.proposal.proposal_id
    ):
        raise HTTPException(status_code=403, detail="gateway permit required")
    try:
        payload = request_json(
            "POST",
            f"{os.getenv('AEGIS_SIMULATION_URL', 'http://simulation:8084')}/internal/apply",
            request.model_dump(mode="json"),
        )
        return ExecutionResult.model_validate(payload)
    except (ServiceExchangeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="simulation execution unavailable") from exc


@segmented_gateway_app.get("/health")
def gateway_health() -> dict[str, str]:
    return {"status": "ok", "role": "gateway", "mode": "m4d-segmented-surrogate"}


@segmented_gateway_app.get("/v1/observation", response_model=SystemState)
def gateway_observation() -> SystemState:
    try:
        payload = request_json(
            "GET",
            f"{os.getenv('AEGIS_OBSERVER_URL', 'http://observer:8082')}/internal/state",
        )
        state = SystemState.model_validate(payload)
    except (ServiceExchangeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="trusted observation unavailable") from exc
    _cache_observation(state)
    return state


@segmented_gateway_app.post("/v1/actions", response_model=SegmentedActionResult)
def gateway_action(proposal: ActionProposal) -> SegmentedActionResult:
    state = _resolve_observation(proposal)
    if state is None:
        raise HTTPException(status_code=409, detail="observation was not issued by this gateway")
    decision = _gateway().gateway.decide(proposal, state)
    if decision.outcome is not DecisionOutcome.PERMIT:
        return SegmentedActionResult(proposal_id=proposal.proposal_id, decision=decision)
    request = SegmentedExecutionRequest(proposal=proposal, decision=decision)
    try:
        payload = request_json(
            "POST",
            f"{os.getenv('AEGIS_OT_URL', 'http://ot-adapter:8083')}/internal/execute",
            request.model_dump(mode="json"),
        )
        execution = ExecutionResult.model_validate(payload)
    except (ServiceExchangeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="OT execution outcome unavailable") from exc
    return SegmentedActionResult(
        proposal_id=proposal.proposal_id,
        decision=decision,
        execution=execution,
    )


def run_segmented_probe() -> dict[str, Any]:
    """Run in the agent-only container and prove allowed and forbidden paths."""

    gateway_url = os.getenv("AEGIS_GATEWAY_URL", "http://segmented-gateway:8081").rstrip("/")
    bypass: dict[str, bool] = {}
    for service, port in (("observer", 8082), ("ot-adapter", 8083), ("simulation", 8084)):
        try:
            request_json("GET", f"http://{service}:{port}/health", timeout_seconds=1.0)
        except ServiceExchangeError:
            bypass[service] = False
        else:
            bypass[service] = True

    observation = SystemState.model_validate(request_json("GET", f"{gateway_url}/v1/observation"))
    def proposal(impact: float) -> ActionProposal:
        return ActionProposal(
            proposal_id=f"segmented-{uuid4()}",
            actor_id="agent:operator-1",
            mission_id="microgrid-containment",
            resource="feeder-1",
            operation=Operation.ISOLATE_ASSET,
            parameters={"critical_load_impact_pct": impact},
            observed_state_version=observation.version,
            observed_at=observation.observed_at,
            submitted_at=datetime.now(UTC),
            nonce=str(uuid4()),
            confidence=0.9,
            risk_score=60.0,
            delegation_chain=("grant-root", "grant-leaf"),
        )

    unsafe_proposal = proposal(30.0)
    unsafe = SegmentedActionResult.model_validate(
        request_json(
            "POST",
            f"{gateway_url}/v1/actions",
            unsafe_proposal.model_dump(mode="json"),
        )
    )
    safe_proposal = proposal(5.0)
    safe = SegmentedActionResult.model_validate(
        request_json(
            "POST",
            f"{gateway_url}/v1/actions",
            safe_proposal.model_dump(mode="json"),
        )
    )
    replay = SegmentedActionResult.model_validate(
        request_json(
            "POST",
            f"{gateway_url}/v1/actions",
            safe_proposal.model_dump(mode="json"),
        )
    )
    final_observation = SystemState.model_validate(
        request_json("GET", f"{gateway_url}/v1/observation")
    )
    return {
        "schema_version": "m4d-segmented-probe-v1",
        "agent_network_direct_reachability": bypass,
        "initial_state_version": observation.version,
        "unsafe": {
            "decision": unsafe.decision.outcome,
            "reasons": unsafe.decision.reasons,
            "dispatched": unsafe.execution is not None,
        },
        "safe": {
            "decision": safe.decision.outcome,
            "executed": safe.execution.executed if safe.execution is not None else False,
            "resulting_state_version": (
                safe.execution.resulting_state.version
                if safe.execution is not None and safe.execution.resulting_state is not None
                else None
            ),
        },
        "replay": {
            "decision": replay.decision.outcome,
            "reasons": replay.decision.reasons,
            "dispatched": replay.execution is not None,
        },
        "final_state_version": final_observation.version,
        "final_isolated_assets": sorted(final_observation.isolated_assets),
        "accepted": (
            not any(bypass.values())
            and unsafe.decision.outcome is DecisionOutcome.DENY
            and "critical_load_below_limit" in unsafe.decision.reasons
            and unsafe.execution is None
            and safe.decision.outcome is DecisionOutcome.PERMIT
            and safe.execution is not None
            and safe.execution.executed
            and replay.decision.outcome is DecisionOutcome.DENY
            and "replayed_nonce" in replay.decision.reasons
            and replay.execution is None
            and final_observation.version == observation.version + 1
            and final_observation.isolated_assets == frozenset({"feeder-1"})
        ),
        "agent_hostname": socket.gethostname(),
    }
