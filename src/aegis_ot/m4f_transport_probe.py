"""M4f signed-envelope restart, liveness, and exact-replay probe."""

from __future__ import annotations

import json
import os
import socket
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .m4e_transport_probe import _execution_request
from .models import SystemState
from .segmented_runtime import (
    SignedSegmentedExecutionRequest,
    SignedSegmentedExecutionResponse,
    _canonical_bytes,
    _load_private_key,
    _load_public_key,
    _sha256,
)

TARGET = "http://ot-adapter:8083/internal/execute"
HEALTH = "http://ot-adapter:8083/health"
STATE = "http://observer:8082/internal/state"


def _exchange(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    request = Request(  # noqa: S310 - fixed internal experiment URL
        TARGET,
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


def _get(url: str) -> dict[str, Any]:
    try:
        with urlopen(url, timeout=5.0) as response:  # noqa: S310
            raw = response.read(1_048_577)
    except (TimeoutError, URLError, OSError) as exc:
        raise RuntimeError(f"probe dependency unavailable: {url}") from exc
    if len(raw) > 1_048_576:
        raise RuntimeError("probe response exceeded its size bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("probe response root was not an object")
    return value


def _await_exchange(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    last_error: OSError | None = None
    for _ in range(40):
        try:
            return _exchange(payload)
        except (TimeoutError, URLError, OSError) as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError("OT adapter did not become reachable") from last_error


def _await_get(url: str) -> dict[str, Any]:
    last_error: RuntimeError | None = None
    for _ in range(40):
        try:
            return _get(url)
        except RuntimeError as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError(f"probe dependency did not become ready: {url}") from last_error


def _state() -> SystemState:
    return SystemState.model_validate(_await_get(STATE))


def _state_projection(state: SystemState) -> dict[str, Any]:
    value = state.model_dump(mode="json")
    value.pop("observed_at", None)
    return value


def _signed_request(
    state: SystemState,
    *,
    ttl_seconds: int = 30,
) -> SignedSegmentedExecutionRequest:
    now = datetime.now(UTC)
    return SignedSegmentedExecutionRequest(
        request=_execution_request(state),
        gateway_key_id=os.environ["AEGIS_GATEWAY_KEY_ID"],
        transport_nonce=str(uuid4()),
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
    ).signed(_load_private_key(os.environ["AEGIS_GATEWAY_PRIVATE_KEY_FILE"]))


def _verify_response(
    request: SignedSegmentedExecutionRequest,
    payload: dict[str, Any],
) -> tuple[SignedSegmentedExecutionResponse, bool]:
    response = SignedSegmentedExecutionResponse.model_validate(payload)
    gateway_private = _load_private_key(
        os.environ["AEGIS_GATEWAY_PRIVATE_KEY_FILE"]
    )
    verified = (
        request.audience == "aegis-ot:ot-adapter"
        and request.gateway_key_id == os.environ["AEGIS_GATEWAY_KEY_ID"]
        and request.verify(gateway_private.public_key())
        and response.ot_key_id == os.getenv("AEGIS_OT_KEY_ID", "m4e-ot-key-v1")
        and response.request_sha256 == _sha256(request)
        and response.execution.proposal_id == request.request.proposal.proposal_id
        and response.execution.decision_id == request.request.decision.decision_id
        and response.verify(_load_public_key(os.environ["AEGIS_OT_PUBLIC_KEY_FILE"]))
    )
    return response, verified


def _write_exact_request(
    path: Path,
    request: SignedSegmentedExecutionRequest,
) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError("exact signed-request probe file already exists")
    material = _canonical_bytes(request)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                raise OSError("signed-request probe write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _load_exact_request(path: Path) -> SignedSegmentedExecutionRequest:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
        raise RuntimeError("exact signed-request probe file is unavailable")
    if path.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError("exact signed-request probe file mode is not 0600")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8", errors="strict"))
    request = SignedSegmentedExecutionRequest.model_validate(value)
    if raw != _canonical_bytes(request):
        raise RuntimeError("exact signed-request probe file is not canonical")
    return request


def _full() -> dict[str, Any]:
    health_before = _await_get(HEALTH)
    state_before = _state()
    execution_request = _execution_request(state_before)
    unsigned_status, unsigned_body = _exchange(execution_request.model_dump(mode="json"))

    now = datetime.now(UTC)
    forged = SignedSegmentedExecutionRequest(
        request=execution_request,
        gateway_key_id=os.environ["AEGIS_GATEWAY_KEY_ID"],
        transport_nonce=str(uuid4()),
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
    ).signed(Ed25519PrivateKey.generate())
    forged_status, forged_body = _exchange(forged.model_dump(mode="json"))

    valid = forged.model_copy(
        update={"transport_nonce": str(uuid4()), "signature": ""}
    ).signed(_load_private_key(os.environ["AEGIS_GATEWAY_PRIVATE_KEY_FILE"]))
    valid_status, valid_body = _exchange(valid.model_dump(mode="json"))
    valid_response, response_verified = _verify_response(valid, valid_body)
    state_after_valid = _state()
    replay_status, replay_body = _exchange(valid.model_dump(mode="json"))
    state_after_replay = _state()

    altered = valid.model_copy(update={"transport_nonce": str(uuid4())})
    altered_status, altered_body = _exchange(altered.model_dump(mode="json"))

    resign_now = datetime.now(UTC)
    resigned = valid.model_copy(
        update={
            "transport_nonce": str(uuid4()),
            "issued_at": resign_now,
            "expires_at": resign_now + timedelta(seconds=30),
            "signature": "",
        }
    ).signed(_load_private_key(os.environ["AEGIS_GATEWAY_PRIVATE_KEY_FILE"]))
    resigned_status, resigned_body = _exchange(resigned.model_dump(mode="json"))
    resigned_response, resigned_verified = _verify_response(resigned, resigned_body)
    state_after_resigned = _state()
    health_after = _await_get(HEALTH)

    output: dict[str, Any] = {
        "schema_version": "m4f-transport-probe-v1",
        "mode": "full",
        "probe_hostname": socket.gethostname(),
        "health_before": health_before,
        "health_after": health_after,
        "state_before": state_before.model_dump(mode="json"),
        "state_after_valid": state_after_valid.model_dump(mode="json"),
        "state_after_replay": state_after_replay.model_dump(mode="json"),
        "state_after_resigned_request": state_after_resigned.model_dump(mode="json"),
        "unsigned": {"http_status": unsigned_status, "response": unsigned_body},
        "forged_signature": {"http_status": forged_status, "response": forged_body},
        "valid_key_holder": {
            "http_status": valid_status,
            "signed_request": valid.model_dump(mode="json"),
            "signed_response": valid_response.model_dump(mode="json"),
            "request_sha256": _sha256(valid),
            "executed": valid_response.execution.executed,
            "response_signature_verified": response_verified,
        },
        "exact_same_boot_replay": {
            "http_status": replay_status,
            "response": replay_body,
        },
        "post_signature_tamper": {
            "http_status": altered_status,
            "response": altered_body,
        },
        "resigned_same_inner_request": {
            "http_status": resigned_status,
            "signed_request": resigned.model_dump(mode="json"),
            "signed_response": resigned_response.model_dump(mode="json"),
            "executed": resigned_response.execution.executed,
            "reason": resigned_response.execution.reason,
            "response_signature_verified": resigned_verified,
        },
    }
    before_count = health_before.get("replay_reservations")
    after_count = health_after.get("replay_reservations")
    output["accepted"] = (
        health_before.get("replay_mode") == "durable"
        and isinstance(before_count, int)
        and after_count == before_count + 2
        and unsigned_status == 403
        and forged_status == 403
        and valid_status == 200
        and valid_response.execution.executed
        and response_verified
        and state_after_valid.version == state_before.version + 1
        and replay_status == 409
        and _state_projection(state_after_replay) == _state_projection(state_after_valid)
        and altered_status == 403
        and resigned_status == 200
        and not resigned_response.execution.executed
        and resigned_response.execution.reason == "time_of_check_time_of_use_state_change"
        and resigned_verified
        and _state_projection(state_after_resigned) == _state_projection(state_after_valid)
    )
    return output


def _prepare_restart(path: Path) -> dict[str, Any]:
    health_before = _await_get(HEALTH)
    state_before = _state()
    request = _signed_request(state_before, ttl_seconds=60)
    status, body = _exchange(request.model_dump(mode="json"))
    response, verified = _verify_response(request, body)
    state_after = _state()
    health_after = _await_get(HEALTH)
    _write_exact_request(path, request)
    output: dict[str, Any] = {
        "schema_version": "m4f-transport-probe-v1",
        "mode": "prepare-restart",
        "probe_hostname": socket.gethostname(),
        "health_before": health_before,
        "health_after": health_after,
        "state_before": state_before.model_dump(mode="json"),
        "state_after": state_after.model_dump(mode="json"),
        "prepared_request": {
            "http_status": status,
            "signed_request": request.model_dump(mode="json"),
            "signed_response": response.model_dump(mode="json"),
            "request_sha256": _sha256(request),
            "executed": response.execution.executed,
            "response_signature_verified": verified,
        },
    }
    before_count = health_before.get("replay_reservations")
    after_count = health_after.get("replay_reservations")
    output["accepted"] = (
        health_before.get("replay_mode") == "durable"
        and isinstance(before_count, int)
        and after_count == before_count + 1
        and status == 200
        and response.execution.executed
        and verified
        and state_after.version == state_before.version + 1
    )
    return output


def _restart(path: Path) -> dict[str, Any]:
    exact = _load_exact_request(path)
    health_before = _await_get(HEALTH)
    state_before = _state()
    replay_sent_at = datetime.now(UTC)
    replay_status, replay_body = _exchange(exact.model_dump(mode="json"))
    replay_received_at = datetime.now(UTC)
    state_after_replay = _state()
    health_after_replay = _await_get(HEALTH)

    fresh = _signed_request(state_after_replay)
    fresh_status, fresh_body = _exchange(fresh.model_dump(mode="json"))
    fresh_response, fresh_verified = _verify_response(fresh, fresh_body)
    state_after_fresh = _state()
    health_after_fresh = _await_get(HEALTH)

    output: dict[str, Any] = {
        "schema_version": "m4f-transport-probe-v1",
        "mode": "restart-replay",
        "probe_hostname": socket.gethostname(),
        "health_before": health_before,
        "health_after_replay": health_after_replay,
        "health_after_fresh": health_after_fresh,
        "state_before": state_before.model_dump(mode="json"),
        "state_after_replay": state_after_replay.model_dump(mode="json"),
        "state_after_fresh": state_after_fresh.model_dump(mode="json"),
        "exact_restart_replay": {
            "http_status": replay_status,
            "response": replay_body,
            "signed_request": exact.model_dump(mode="json"),
            "request_sha256": _sha256(exact),
            "sent_at": replay_sent_at.isoformat(),
            "received_at": replay_received_at.isoformat(),
            "validity_margin_at_send_seconds": (
                exact.expires_at - replay_sent_at
            ).total_seconds(),
            "response_within_original_validity_window": (
                replay_received_at < exact.expires_at
            ),
        },
        "fresh_after_restart": {
            "http_status": fresh_status,
            "signed_request": fresh.model_dump(mode="json"),
            "signed_response": fresh_response.model_dump(mode="json"),
            "executed": fresh_response.execution.executed,
            "response_signature_verified": fresh_verified,
        },
    }
    before_count = health_before.get("replay_reservations")
    replay_count = health_after_replay.get("replay_reservations")
    fresh_count = health_after_fresh.get("replay_reservations")
    output["accepted"] = (
        health_before.get("replay_mode") == "durable"
        and isinstance(before_count, int)
        and replay_count == before_count
        and fresh_count == before_count + 1
        and replay_status == 409
        and replay_body.get("detail") == "transport request replayed"
        and (exact.expires_at - replay_sent_at).total_seconds() >= 5.0
        and replay_received_at < exact.expires_at
        and _state_projection(state_after_replay) == _state_projection(state_before)
        and fresh_status == 200
        and fresh_response.execution.executed
        and fresh_verified
        and state_after_fresh.version == state_after_replay.version + 1
    )
    return output


def _ledger_fault(path: Path) -> dict[str, Any]:
    exact = _load_exact_request(path)
    state_before = _state()
    status, body = _await_exchange(exact.model_dump(mode="json"))
    state_after = _state()
    output: dict[str, Any] = {
        "schema_version": "m4f-transport-probe-v1",
        "mode": "ledger-fault",
        "probe_hostname": socket.gethostname(),
        "state_before": state_before.model_dump(mode="json"),
        "state_after": state_after.model_dump(mode="json"),
        "request": {
            "http_status": status,
            "response": body,
            "signed_request": exact.model_dump(mode="json"),
            "request_sha256": _sha256(exact),
        },
    }
    output["accepted"] = (
        status == 503
        and body.get("detail") == "transport replay ledger unavailable"
        and _state_projection(state_after) == _state_projection(state_before)
    )
    return output


def main() -> None:
    mode = os.getenv("AEGIS_TRANSPORT_PROBE_MODE", "full")
    path = Path(os.getenv("AEGIS_TRANSPORT_PROBE_FILE", "/probe/exact-signed-request.json"))
    if mode == "full":
        output = _full()
    elif mode == "prepare_restart":
        output = _prepare_restart(path)
    elif mode == "restart_replay":
        output = _restart(path)
    elif mode == "ledger_fault":
        output = _ledger_fault(path)
    else:
        raise RuntimeError(f"unsupported M4f transport probe mode: {mode}")
    print(json.dumps(output, sort_keys=True, indent=2))
    if output.get("accepted") is not True:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
