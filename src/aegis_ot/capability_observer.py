"""Signed-observer process with a read-only plant capability and bounded cache."""

from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import dataclass
from multiprocessing.connection import wait
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from .capability_ipc import (
    IpcProtocolError,
    IpcResponseFrame,
    IpcResponseStatus,
    IpcTransportError,
    JsonPipeClient,
    bounded_error_reason,
    receive_request,
    send_response,
)
from .capability_models import ObservationPhase, SignedObservationEnvelope
from .capability_plant import ObserverPlantClient, PlantProcessInfo
from .crypto import generate_keypair
from .physical_models import PhysicalControlCommand

OBSERVER_CAPABILITIES: dict[str, frozenset[str]] = {
    "admin": frozenset({"health", "probe_plant_apply", "shutdown"}),
    "telemetry": frozenset({"health", "capture_pre"}),
    "gateway": frozenset({"health", "resolve", "capture_post"}),
}


class ObserverServiceError(RuntimeError):
    """The signed-observer service rejected a request or became unusable."""


@dataclass(frozen=True)
class ObserverProcessInfo:
    pid: int
    observer_id: str
    boot_epoch: str
    key_id: str
    public_key_bytes: bytes
    plant_boot_epoch: str
    capabilities: dict[str, tuple[str, ...]]

    @property
    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.public_key_bytes)


def _observer_process_main(
    ready_connection: Any,
    admin_connection: Any,
    telemetry_connection: Any,
    gateway_connection: Any,
    plant_connection: Any,
    plant_info_payload: dict[str, Any],
    retained_private_key_bytes: bytes | None,
) -> None:
    boot_epoch = str(uuid4())
    observer_id = "signed-observer:deterministic-local"
    key_id = "signed-observer-key-v1"
    response_counter = 0
    observer_sequence = 0
    capture_count = 0
    resolve_count = 0
    previous_digest: str | None = None
    cache: OrderedDict[str, SignedObservationEnvelope] = OrderedDict()
    running = True
    endpoints = {
        "admin": admin_connection,
        "telemetry": telemetry_connection,
        "gateway": gateway_connection,
    }
    plant_info = PlantProcessInfo(**plant_info_payload)
    plant = ObserverPlantClient(plant_connection, plant_info)
    if retained_private_key_bytes is None:
        private_key, public_key = generate_keypair()
    else:
        private_key = Ed25519PrivateKey.from_private_bytes(retained_private_key_bytes)
        public_key = private_key.public_key()
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    def capture(
        *,
        correlation_id: str,
        challenge_nonce: str,
        phase: ObservationPhase,
        transaction_previous_digest: str | None = None,
        permit_id: str | None = None,
        command_digest: str | None = None,
        plc_acknowledgment_digest: str | None = None,
    ) -> SignedObservationEnvelope:
        nonlocal observer_sequence, capture_count, previous_digest
        snapshot = plant.capture_state()
        observer_sequence += 1
        capture_count += 1
        envelope = SignedObservationEnvelope.issue(
            snapshot=snapshot,
            correlation_id=correlation_id,
            phase=phase,
            challenge_nonce=challenge_nonce,
            observer_id=observer_id,
            observer_key_id=key_id,
            observer_boot_epoch=boot_epoch,
            observer_sequence=observer_sequence,
            previous_envelope_digest=(
                transaction_previous_digest
                if phase is ObservationPhase.POST_DISPATCH
                else previous_digest
            ),
            permit_id=permit_id,
            command_digest=command_digest,
            plc_acknowledgment_digest=plc_acknowledgment_digest,
            private_key=private_key,
        )
        previous_digest = envelope.envelope_digest
        cache[envelope.observation_id] = envelope
        cache.move_to_end(envelope.observation_id)
        while len(cache) > 128:
            cache.popitem(last=False)
        return envelope

    try:
        ready_connection.send(
            {
                "pid": os.getpid(),
                "observer_id": observer_id,
                "boot_epoch": boot_epoch,
                "key_id": key_id,
                "public_key_bytes": public_raw,
                "plant_boot_epoch": plant_info.boot_epoch,
                "capabilities": {
                    role: tuple(sorted(operations))
                    for role, operations in OBSERVER_CAPABILITIES.items()
                },
            }
        )
        while running and endpoints:
            ready = wait(list(endpoints.values()), timeout=0.1)
            for ready_endpoint in ready:
                connection: Any = ready_endpoint
                role = next(name for name, endpoint in endpoints.items() if endpoint is connection)
                try:
                    request = receive_request(connection)
                except (IpcProtocolError, IpcTransportError):
                    connection.close()
                    del endpoints[role]
                    break
                response_counter += 1
                status = IpcResponseStatus.OK
                error_code: str | None = None
                payload: dict[str, Any]
                if request.operation not in OBSERVER_CAPABILITIES[role]:
                    status = IpcResponseStatus.REJECTED
                    error_code = "capability_denied"
                    payload = {"role": role, "operation": request.operation}
                else:
                    try:
                        if request.operation == "health":
                            payload = {
                                "status": "ready",
                                "pid": os.getpid(),
                                "observer_id": observer_id,
                                "boot_epoch": boot_epoch,
                                "key_id": key_id,
                                "role": role,
                                "capabilities": tuple(sorted(OBSERVER_CAPABILITIES[role])),
                                "capture_count": capture_count,
                                "resolve_count": resolve_count,
                                "cached_observations": len(cache),
                            }
                        elif request.operation == "shutdown":
                            payload = {"status": "stopping"}
                            running = False
                        elif request.operation == "probe_plant_apply":
                            command = PhysicalControlCommand.model_validate(
                                request.payload["command"]
                            )
                            payload = {
                                "decision": plant.probe_forbidden_apply(command)
                            }
                        elif request.operation == "capture_pre":
                            envelope = capture(
                                correlation_id=str(request.payload["correlation_id"]),
                                challenge_nonce=str(request.payload["challenge_nonce"]),
                                phase=ObservationPhase.PRE_AUTHORIZATION,
                            )
                            payload = {"observation": envelope.model_dump(mode="json")}
                        elif request.operation == "resolve":
                            resolve_count += 1
                            observation_id = str(request.payload["observation_id"])
                            expected_digest = str(request.payload["envelope_digest"])
                            cached_envelope = cache.get(observation_id)
                            if (
                                cached_envelope is None
                                or cached_envelope.envelope_digest != expected_digest
                            ):
                                status = IpcResponseStatus.REJECTED
                                error_code = "observation_not_found"
                                payload = {"observation_id": observation_id}
                            else:
                                payload = {
                                    "observation": cached_envelope.model_dump(mode="json")
                                }
                        elif request.operation == "capture_post":
                            transaction_previous_digest = str(
                                request.payload["previous_envelope_digest"]
                            )
                            transaction_predecessor = next(
                                (
                                    cached
                                    for cached in cache.values()
                                    if cached.envelope_digest
                                    == transaction_previous_digest
                                ),
                                None,
                            )
                            if (
                                transaction_predecessor is None
                                or transaction_predecessor.phase
                                is not ObservationPhase.PRE_AUTHORIZATION
                                or transaction_predecessor.correlation_id
                                != str(request.payload["correlation_id"])
                            ):
                                raise ValueError(
                                    "post observation predecessor is unavailable or invalid"
                                )
                            envelope = capture(
                                correlation_id=str(request.payload["correlation_id"]),
                                challenge_nonce=str(request.payload["challenge_nonce"]),
                                phase=ObservationPhase.POST_DISPATCH,
                                transaction_previous_digest=transaction_previous_digest,
                                permit_id=str(request.payload["permit_id"]),
                                command_digest=str(request.payload["command_digest"]),
                                plc_acknowledgment_digest=str(
                                    request.payload["plc_acknowledgment_digest"]
                                ),
                            )
                            payload = {"observation": envelope.model_dump(mode="json")}
                        else:
                            raise RuntimeError("unreachable observer operation")
                    except (KeyError, TypeError, ValidationError, ValueError) as exc:
                        status = IpcResponseStatus.REJECTED
                        error_code = "invalid_payload"
                        payload = {
                            "reason": bounded_error_reason(exc),
                            "error_type": type(exc).__name__,
                        }
                    except Exception as exc:
                        status = IpcResponseStatus.ERROR
                        error_code = "observer_internal_error"
                        payload = {
                            "reason": bounded_error_reason(exc),
                            "error_type": type(exc).__name__,
                        }
                response = IpcResponseFrame.create(
                    request,
                    status=status,  # type: ignore[arg-type]
                    payload=payload,
                    error_code=error_code,
                    server_boot_epoch=boot_epoch,
                    response_counter=response_counter,
                )
                try:
                    send_response(connection, response)
                except (IpcProtocolError, IpcTransportError):
                    connection.close()
                    del endpoints[role]
                    break
                if not running:
                    break
    except Exception as exc:
        try:
            ready_connection.send({"error": type(exc).__name__, "reason": str(exc)})
        except (BrokenPipeError, OSError):
            pass
        raise
    finally:
        ready_connection.close()
        plant.close()
        for connection in endpoints.values():
            connection.close()


class _ObserverClient:
    def __init__(self, connection: Any, info: ObserverProcessInfo) -> None:
        self._ipc = JsonPipeClient(connection, expected_boot_epoch=info.boot_epoch)
        self.info = info

    def _request(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._ipc.request(operation, payload)
        if response.status != IpcResponseStatus.OK:
            reason = str(response.payload.get("reason", response.error_code))
            raise ObserverServiceError(reason)
        return response.payload

    def health(self) -> dict[str, Any]:
        return self._request("health", {})

    def close(self) -> None:
        self._ipc.close()


class TelemetryObserverClient(_ObserverClient):
    def capture_pre(
        self,
        *,
        correlation_id: str,
        challenge_nonce: str,
    ) -> SignedObservationEnvelope:
        payload = self._request(
            "capture_pre",
            {"correlation_id": correlation_id, "challenge_nonce": challenge_nonce},
        )
        try:
            return SignedObservationEnvelope.model_validate(payload["observation"])
        except (KeyError, TypeError, ValidationError, ValueError) as exc:
            raise ObserverServiceError("observer returned an invalid observation") from exc

    def probe_forbidden_post_capture(self) -> str:
        response = self._ipc.request("capture_post", {})
        return str(response.error_code or response.status)


class GatewayObserverClient(_ObserverClient):
    def resolve(
        self,
        *,
        observation_id: str,
        envelope_digest: str,
    ) -> SignedObservationEnvelope:
        payload = self._request(
            "resolve",
            {"observation_id": observation_id, "envelope_digest": envelope_digest},
        )
        try:
            return SignedObservationEnvelope.model_validate(payload["observation"])
        except (KeyError, TypeError, ValidationError, ValueError) as exc:
            raise ObserverServiceError("observer returned an invalid observation") from exc

    def capture_post(
        self,
        *,
        correlation_id: str,
        challenge_nonce: str,
        previous_envelope_digest: str,
        permit_id: str,
        command_digest: str,
        plc_acknowledgment_digest: str,
    ) -> SignedObservationEnvelope:
        payload = self._request(
            "capture_post",
            {
                "correlation_id": correlation_id,
                "challenge_nonce": challenge_nonce,
                "previous_envelope_digest": previous_envelope_digest,
                "permit_id": permit_id,
                "command_digest": command_digest,
                "plc_acknowledgment_digest": plc_acknowledgment_digest,
            },
        )
        try:
            return SignedObservationEnvelope.model_validate(payload["observation"])
        except (KeyError, TypeError, ValidationError, ValueError) as exc:
            raise ObserverServiceError("observer returned an invalid observation") from exc


class ObserverAdminClient(_ObserverClient):
    def probe_forbidden_plant_apply(self, command: PhysicalControlCommand) -> str:
        payload = self._request(
            "probe_plant_apply",
            {"command": command.model_dump(mode="json")},
        )
        return str(payload["decision"])

    def shutdown(self) -> None:
        try:
            self._request("shutdown", {})
        except (IpcTransportError, ObserverServiceError):
            pass
