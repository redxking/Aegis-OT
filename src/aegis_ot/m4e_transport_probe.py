"""Controlled M4e network-peer and key-holder transport fault probe."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import ActionProposal, Decision, DecisionOutcome, Operation, SystemState
from .segmented_runtime import (
    SegmentedExecutionRequest,
    SignedSegmentedExecutionRequest,
    SignedSegmentedExecutionResponse,
    _load_private_key,
    _load_public_key,
    _sha256,
)


def _exchange(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    request = Request(  # noqa: S310 - fixed internal experiment URL
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5.0) as response:  # noqa: S310
            status = response.status
            raw = response.read(1_048_577)
    except HTTPError as exc:
        status = exc.code
        raw = exc.read(1_048_577)
    if len(raw) > 1_048_576:
        raise RuntimeError("probe response exceeded its size bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("probe response root was not an object")
    return status, value


def _read_observation() -> SystemState:
    with urlopen("http://observer:8082/internal/state", timeout=5.0) as response:  # noqa: S310
        value = json.loads(response.read(1_048_577))
    return SystemState.model_validate(value)


def _execution_request(state: SystemState) -> SegmentedExecutionRequest:
    proposal = ActionProposal(
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="battery-1",
        operation=Operation.DISPATCH_BATTERY,
        parameters={
            "mw": 1.0,
            "minimum_voltage_delta_pu": 0.0,
            "maximum_voltage_delta_pu": 0.0,
        },
        observed_state_version=state.version,
        observed_at=state.observed_at,
        submitted_at=datetime.now(UTC),
        nonce=str(uuid4()),
        confidence=0.9,
        risk_score=60.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )
    decision = Decision(
        proposal_id=proposal.proposal_id,
        outcome=DecisionOutcome.PERMIT,
        reasons=("controlled_transport_probe",),
        policy_version="controlled-probe",
        safety_version="controlled-probe",
        state_version=state.version,
    )
    return SegmentedExecutionRequest(proposal=proposal, decision=decision)


def main() -> None:
    target = "http://ot-adapter:8083/internal/execute"
    execution_request = _execution_request(_read_observation())
    unsigned_status, unsigned_body = _exchange(
        target, execution_request.model_dump(mode="json")
    )

    now = datetime.now(UTC)
    forged = SignedSegmentedExecutionRequest(
        request=execution_request,
        gateway_key_id=os.environ["AEGIS_GATEWAY_KEY_ID"],
        transport_nonce=str(uuid4()),
        issued_at=now,
        expires_at=now + timedelta(seconds=5),
    ).signed(Ed25519PrivateKey.generate())
    forged_status, forged_body = _exchange(target, forged.model_dump(mode="json"))

    gateway_private = _load_private_key(os.environ["AEGIS_GATEWAY_PRIVATE_KEY_FILE"])
    valid = forged.model_copy(
        update={"transport_nonce": str(uuid4()), "signature": ""}
    ).signed(gateway_private)
    valid_status, valid_body = _exchange(target, valid.model_dump(mode="json"))
    response = SignedSegmentedExecutionResponse.model_validate(valid_body)
    response_verified = (
        response.request_sha256 == _sha256(valid)
        and response.verify(_load_public_key(os.environ["AEGIS_OT_PUBLIC_KEY_FILE"]))
    )

    replay_status, replay_body = _exchange(target, valid.model_dump(mode="json"))
    altered = valid.model_copy(update={"transport_nonce": str(uuid4())})
    altered_status, altered_body = _exchange(target, altered.model_dump(mode="json"))
    output: dict[str, Any] = {
        "schema_version": "m4e-transport-probe-v1",
        "unsigned": {"http_status": unsigned_status, "response": unsigned_body},
        "forged_signature": {"http_status": forged_status, "response": forged_body},
        "valid_key_holder": {
            "http_status": valid_status,
            "executed": response.execution.executed,
            "response_signature_verified": response_verified,
        },
        "exact_transport_replay": {
            "http_status": replay_status,
            "response": replay_body,
        },
        "post_signature_tamper": {
            "http_status": altered_status,
            "response": altered_body,
        },
    }
    output["accepted"] = (
        unsigned_status == 403
        and unsigned_body.get("detail") == "signed gateway request required"
        and forged_status == 403
        and forged_body.get("detail") == "gateway signature rejected"
        and valid_status == 200
        and response.execution.executed
        and response_verified
        and replay_status == 409
        and replay_body.get("detail") == "transport request replayed"
        and altered_status == 403
        and altered_body.get("detail") == "gateway signature rejected"
    )
    print(json.dumps(output, sort_keys=True, indent=2))
    if output["accepted"] is not True:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
