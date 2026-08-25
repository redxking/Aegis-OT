"""Minimum container-network assurance path for the M4d segmentation increment.

The services in this module deliberately reuse the bounded v0.1 supervisory
model. They test network placement and fail-closed service composition; they
do not claim workload-credential, OpenPLC, HELICS, or production-OT fidelity.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .crypto import sign_bytes, verify_bytes
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
from .transport_replay import DurableTransportReplayLedger, TransportReplayLedgerError


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


def _canonical_bytes(value: BaseModel | dict[str, Any]) -> bytes:
    material = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


class SignedSegmentedExecutionRequest(BaseModel):
    """Gateway-signed authorization carried across the M4e network boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["m4e-signed-execution-request-v1"] = (
        "m4e-signed-execution-request-v1"
    )
    request: SegmentedExecutionRequest
    audience: str = "aegis-ot:ot-adapter"
    gateway_key_id: str = Field(min_length=1)
    transport_nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_window(self) -> SignedSegmentedExecutionRequest:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("signed request timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("signed request expiry must follow issuance")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_bytes(self.model_dump(mode="json", exclude={"signature"}))

    def signed(self, key: Ed25519PrivateKey) -> SignedSegmentedExecutionRequest:
        return self.model_copy(update={"signature": sign_bytes(key, self.signing_payload())})

    def verify(self, key: Ed25519PublicKey) -> bool:
        return bool(self.signature) and verify_bytes(key, self.signing_payload(), self.signature)


class SignedSegmentedExecutionResponse(BaseModel):
    """OT-adapter-signed result bound to one signed gateway request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["m4e-signed-execution-response-v1"] = (
        "m4e-signed-execution-response-v1"
    )
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution: ExecutionResult
    ot_key_id: str = Field(min_length=1)
    signed_at: datetime
    signature: str = ""

    def signing_payload(self) -> bytes:
        return _canonical_bytes(self.model_dump(mode="json", exclude={"signature"}))

    def signed(self, key: Ed25519PrivateKey) -> SignedSegmentedExecutionResponse:
        return self.model_copy(update={"signature": sign_bytes(key, self.signing_payload())})

    def verify(self, key: Ed25519PublicKey) -> bool:
        return bool(self.signature) and verify_bytes(key, self.signing_payload(), self.signature)


def _sha256(value: BaseModel) -> str:
    import hashlib

    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _load_private_key(path: str) -> Ed25519PrivateKey:
    raw = open(path, "rb").read(33)  # noqa: PTH123
    if len(raw) != 32:
        raise RuntimeError("Ed25519 private key file must contain exactly 32 raw bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _load_public_key(path: str) -> Ed25519PublicKey:
    raw = open(path, "rb").read(33)  # noqa: PTH123
    if len(raw) != 32:
        raise RuntimeError("Ed25519 public key file must contain exactly 32 raw bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


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
_ot_transport_nonces: set[str] = set()
_ot_transport_nonce_lock = Lock()
_durable_transport_replay: DurableTransportReplayLedger | None = None
_durable_transport_replay_config: tuple[str, str, str, str] | None = None
_durable_transport_replay_lock = Lock()
_ot_boot_epoch = str(uuid4())
_MAX_SIGNED_REQUEST_TTL = timedelta(seconds=60)
_OT_AUDIENCE = "aegis-ot:ot-adapter"


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


def _authenticated_mode() -> bool:
    return os.getenv("AEGIS_AUTHENTICATED_MODE", "false").lower() == "true"


def _transport_replay_mode() -> Literal["memory", "durable"]:
    mode = os.getenv("AEGIS_TRANSPORT_REPLAY_MODE", "memory")
    if mode == "memory":
        return "memory"
    if mode == "durable":
        return "durable"
    raise TransportReplayLedgerError("transport replay mode is unsupported")


def _gateway_public_key_sha256(path: str) -> str:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise TransportReplayLedgerError(
            "gateway public key cannot be read for replay identity"
        ) from exc
    if len(raw) != 32:
        raise TransportReplayLedgerError(
            "gateway public key must contain exactly 32 raw bytes"
        )
    return hashlib.sha256(raw).hexdigest()


def _durable_replay_ledger() -> DurableTransportReplayLedger:
    if not _authenticated_mode():
        raise TransportReplayLedgerError(
            "durable transport replay requires authenticated transport"
        )
    ledger_file = os.getenv("AEGIS_TRANSPORT_REPLAY_LEDGER_FILE")
    public_key_file = os.getenv("AEGIS_GATEWAY_PUBLIC_KEY_FILE")
    gateway_key_id = os.getenv("AEGIS_GATEWAY_KEY_ID")
    if not ledger_file or not public_key_file or not gateway_key_id:
        raise TransportReplayLedgerError("durable transport replay is not fully configured")
    public_key_sha256 = _gateway_public_key_sha256(public_key_file)
    config = (ledger_file, _OT_AUDIENCE, gateway_key_id, public_key_sha256)
    global _durable_transport_replay  # noqa: PLW0603 - process-local singleton
    global _durable_transport_replay_config  # noqa: PLW0603 - cache identity
    with _durable_transport_replay_lock:
        if (
            _durable_transport_replay is None
            or _durable_transport_replay_config != config
        ):
            _durable_transport_replay = DurableTransportReplayLedger(
                Path(ledger_file),
                audience=_OT_AUDIENCE,
                gateway_key_id=gateway_key_id,
                gateway_public_key_sha256=public_key_sha256,
            )
            _durable_transport_replay_config = config
        return _durable_transport_replay


def _transport_nonce_seen(nonce: str) -> bool:
    if _transport_replay_mode() == "durable":
        return _durable_replay_ledger().contains(nonce)
    with _ot_transport_nonce_lock:
        return nonce in _ot_transport_nonces


def _reserve_transport_nonce(nonce: str, signed_request_sha256: str) -> bool:
    if _transport_replay_mode() == "durable":
        return _durable_replay_ledger().reserve(nonce, signed_request_sha256)
    with _ot_transport_nonce_lock:
        if nonce in _ot_transport_nonces:
            return False
        _ot_transport_nonces.add(nonce)
        return True


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
def ot_health() -> dict[str, str | int]:
    try:
        replay_mode = _transport_replay_mode()
        if replay_mode == "durable":
            ledger = _durable_replay_ledger()
            reservations, ledger_sha256 = ledger.status()
        else:
            reservations = len(_ot_transport_nonces)
            ledger_sha256 = "not-durable"
    except TransportReplayLedgerError as exc:
        raise HTTPException(
            status_code=503,
            detail="transport replay ledger unavailable",
        ) from exc
    return {
        "status": "ok",
        "role": "ot-adapter",
        "replay_mode": replay_mode,
        "replay_reservations": reservations,
        "replay_ledger_sha256": ledger_sha256,
        "boot_epoch": _ot_boot_epoch,
        "pid": os.getpid(),
    }


@ot_adapter_app.post("/internal/execute")
def ot_execute(
    request: SegmentedExecutionRequest | SignedSegmentedExecutionRequest,
) -> ExecutionResult | SignedSegmentedExecutionResponse:
    signed_request: SignedSegmentedExecutionRequest | None = None
    signed_request_sha256 = ""
    if isinstance(request, SignedSegmentedExecutionRequest):
        signed_request = request
        if not _authenticated_mode():
            raise HTTPException(status_code=403, detail="authenticated transport is disabled")
        expected_key_id = os.environ["AEGIS_GATEWAY_KEY_ID"]
        gateway_public = _load_public_key(os.environ["AEGIS_GATEWAY_PUBLIC_KEY_FILE"])
        if (
            request.gateway_key_id != expected_key_id
            or request.audience != _OT_AUDIENCE
            or not request.verify(gateway_public)
        ):
            raise HTTPException(status_code=403, detail="gateway signature rejected")
        signed_request_sha256 = _sha256(request)
        try:
            replayed = _transport_nonce_seen(request.transport_nonce)
        except TransportReplayLedgerError as exc:
            raise HTTPException(
                status_code=503,
                detail="transport replay ledger unavailable",
            ) from exc
        if replayed:
            raise HTTPException(status_code=409, detail="transport request replayed")
        now = datetime.now(UTC)
        if (
            request.expires_at - request.issued_at > _MAX_SIGNED_REQUEST_TTL
            or not request.issued_at <= now < request.expires_at
        ):
            raise HTTPException(status_code=403, detail="gateway signature rejected")
        execution_request = request.request
    else:
        if _authenticated_mode():
            raise HTTPException(status_code=403, detail="signed gateway request required")
        execution_request = request
    if (
        execution_request.decision.outcome is not DecisionOutcome.PERMIT
        or execution_request.decision.proposal_id != execution_request.proposal.proposal_id
    ):
        raise HTTPException(status_code=403, detail="gateway permit required")
    if signed_request is not None:
        try:
            reserved = _reserve_transport_nonce(
                signed_request.transport_nonce,
                signed_request_sha256,
            )
        except TransportReplayLedgerError as exc:
            raise HTTPException(
                status_code=503,
                detail="transport replay ledger unavailable",
            ) from exc
        if not reserved:
            raise HTTPException(status_code=409, detail="transport request replayed")
    try:
        payload = request_json(
            "POST",
            f"{os.getenv('AEGIS_SIMULATION_URL', 'http://simulation:8084')}/internal/apply",
            execution_request.model_dump(mode="json"),
        )
        execution = ExecutionResult.model_validate(payload)
        if (
            execution.proposal_id != execution_request.proposal.proposal_id
            or execution.decision_id != execution_request.decision.decision_id
        ):
            raise ValueError("simulation result is not bound to the authorized request")
    except (ServiceExchangeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="simulation execution unavailable") from exc
    if signed_request is None:
        return execution
    response = SignedSegmentedExecutionResponse(
        request_sha256=_sha256(signed_request),
        execution=execution,
        ot_key_id=os.environ["AEGIS_OT_KEY_ID"],
        signed_at=datetime.now(UTC),
    )
    return response.signed(_load_private_key(os.environ["AEGIS_OT_PRIVATE_KEY_FILE"]))


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
    outbound: BaseModel = request
    signed_request: SignedSegmentedExecutionRequest | None = None
    if _authenticated_mode():
        now = datetime.now(UTC)
        signed_request = SignedSegmentedExecutionRequest(
            request=request,
            gateway_key_id=os.environ["AEGIS_GATEWAY_KEY_ID"],
            transport_nonce=str(uuid4()),
            issued_at=now,
            expires_at=now + timedelta(seconds=5),
        ).signed(_load_private_key(os.environ["AEGIS_GATEWAY_PRIVATE_KEY_FILE"]))
        outbound = signed_request
    try:
        payload = request_json(
            "POST",
            f"{os.getenv('AEGIS_OT_URL', 'http://ot-adapter:8083')}/internal/execute",
            outbound.model_dump(mode="json"),
        )
        if signed_request is None:
            execution = ExecutionResult.model_validate(payload)
        else:
            response = SignedSegmentedExecutionResponse.model_validate(payload)
            ot_public = _load_public_key(os.environ["AEGIS_OT_PUBLIC_KEY_FILE"])
            if (
                response.ot_key_id != os.environ["AEGIS_OT_KEY_ID"]
                or response.request_sha256 != _sha256(signed_request)
                or not response.verify(ot_public)
            ):
                raise ValueError("OT response signature or request binding failed")
            execution = response.execution
        if (
            execution.proposal_id != proposal.proposal_id
            or execution.decision_id != decision.decision_id
        ):
            raise ValueError("OT execution result is not bound to the gateway decision")
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
