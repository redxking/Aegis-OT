"""Bounded canonical-JSON framing for local capability pipe endpoints."""

from __future__ import annotations

import json
from threading import RLock
from typing import Any, Literal, TypeVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .physical_models import SHA256_PATTERN, canonical_digest

MAX_FRAME_BYTES = 1_048_576
MAX_ERROR_REASON_CHARS = 2_048


class IpcProtocolError(RuntimeError):
    """A local pipe peer returned a malformed or mismatched frame."""


class IpcTransportError(RuntimeError):
    """A nonconsequential local pipe exchange did not complete."""


class IpcOutcomeUnknownError(RuntimeError):
    """A consequential request was sent but no trustworthy response was obtained."""


class IpcResponseStatus(str):
    OK = "ok"
    REJECTED = "rejected"
    ERROR = "error"


class IpcRequestFrame(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["capability-ipc-request-v1"] = "capability-ipc-request-v1"
    request_id: str = Field(
        default_factory=lambda: str(uuid4()),
        min_length=1,
        max_length=128,
    )
    operation: str = Field(min_length=1, max_length=64)
    payload: dict[str, Any]
    payload_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_payload_digest(self) -> IpcRequestFrame:
        if self.payload_digest != canonical_digest(self.payload):
            raise ValueError("IPC request payload digest is inconsistent")
        return self

    @classmethod
    def create(cls, operation: str, payload: dict[str, Any]) -> IpcRequestFrame:
        return cls(operation=operation, payload=payload, payload_digest=canonical_digest(payload))


class IpcResponseFrame(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["capability-ipc-response-v1"] = "capability-ipc-response-v1"
    request_id: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=64)
    request_payload_digest: str = Field(pattern=SHA256_PATTERN)
    status: Literal["ok", "rejected", "error"]
    payload: dict[str, Any]
    payload_digest: str = Field(pattern=SHA256_PATTERN)
    error_code: str | None = Field(default=None, max_length=128)
    server_boot_epoch: str = Field(min_length=16, max_length=256)
    response_counter: int = Field(ge=1)

    @model_validator(mode="after")
    def require_consistency(self) -> IpcResponseFrame:
        if self.payload_digest != canonical_digest(self.payload):
            raise ValueError("IPC response payload digest is inconsistent")
        if self.status == IpcResponseStatus.OK and self.error_code is not None:
            raise ValueError("successful IPC response cannot contain an error code")
        if self.status != IpcResponseStatus.OK and not self.error_code:
            raise ValueError("unsuccessful IPC response requires an error code")
        return self

    @classmethod
    def create(
        cls,
        request: IpcRequestFrame,
        *,
        status: Literal["ok", "rejected", "error"],
        payload: dict[str, Any],
        error_code: str | None,
        server_boot_epoch: str,
        response_counter: int,
    ) -> IpcResponseFrame:
        return cls(
            request_id=request.request_id,
            operation=request.operation,
            request_payload_digest=request.payload_digest,
            status=status,
            payload=payload,
            payload_digest=canonical_digest(payload),
            error_code=error_code,
            server_boot_epoch=server_boot_epoch,
            response_counter=response_counter,
        )


FrameModel = TypeVar("FrameModel", bound=BaseModel)


def encode_frame(frame: BaseModel) -> bytes:
    try:
        payload = json.dumps(
            frame.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, ValueError) as exc:
        raise IpcProtocolError("IPC frame cannot be encoded as canonical JSON") from exc
    if len(payload) > MAX_FRAME_BYTES:
        raise IpcProtocolError("IPC frame exceeds the bounded payload size")
    return payload


def decode_frame(payload: bytes, model: type[FrameModel]) -> FrameModel:
    if len(payload) > MAX_FRAME_BYTES:
        raise IpcProtocolError("IPC frame exceeds the bounded payload size")
    try:
        parsed = json.loads(payload)
    except (RecursionError, ValueError) as exc:
        raise IpcProtocolError("IPC frame is not canonical JSON data") from exc
    if not isinstance(parsed, dict):
        raise IpcProtocolError("IPC frame root must be an object")
    try:
        result = model.model_validate(parsed)
    except (RecursionError, ValueError) as exc:
        raise IpcProtocolError("IPC frame failed structural validation") from exc
    if encode_frame(result) != payload:
        raise IpcProtocolError("IPC frame is not in canonical JSON form")
    return result


def bounded_error_reason(error: Exception) -> str:
    """Bound local diagnostic text before it is copied into an IPC response."""

    return str(error)[:MAX_ERROR_REASON_CHARS]


class JsonPipeClient:
    """Thread-safe request client over one dedicated capability endpoint."""

    def __init__(
        self,
        connection: Any,
        *,
        expected_boot_epoch: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("IPC timeout must be positive")
        self._connection = connection
        self.expected_boot_epoch = expected_boot_epoch
        self.timeout_seconds = timeout_seconds
        self._last_response_counter = 0
        self._closed = False
        self._lock = RLock()
        self.request_counts: dict[str, int] = {}

    def request(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        consequential: bool = False,
    ) -> IpcResponseFrame:
        frame = IpcRequestFrame.create(operation, payload)
        raw = encode_frame(frame)
        with self._lock:
            if self._closed:
                raise IpcTransportError("IPC client is closed")
            try:
                self._connection.send_bytes(raw)
                self.request_counts[operation] = self.request_counts.get(operation, 0) + 1
                if not self._connection.poll(self.timeout_seconds):
                    self._connection.close()
                    self._closed = True
                    if consequential:
                        raise IpcOutcomeUnknownError("consequential IPC response timed out")
                    raise IpcTransportError("IPC response timed out")
                response_raw = self._connection.recv_bytes(MAX_FRAME_BYTES)
            except IpcOutcomeUnknownError:
                raise
            except (EOFError, BrokenPipeError, OSError) as exc:
                self._connection.close()
                self._closed = True
                if consequential:
                    raise IpcOutcomeUnknownError(
                        "consequential IPC response became unavailable"
                    ) from exc
                raise IpcTransportError("IPC peer became unavailable") from exc
            try:
                response = decode_frame(response_raw, IpcResponseFrame)
            except IpcProtocolError as exc:
                self._connection.close()
                self._closed = True
                if consequential:
                    raise IpcOutcomeUnknownError(
                        "consequential IPC response failed protocol validation"
                    ) from exc
                raise
            if (
                response.request_id != frame.request_id
                or response.operation != frame.operation
                or response.request_payload_digest != frame.payload_digest
            ):
                self._connection.close()
                self._closed = True
                if consequential:
                    raise IpcOutcomeUnknownError(
                        "consequential IPC response did not match the request"
                    )
                raise IpcProtocolError("IPC response does not match the request")
            if response.server_boot_epoch != self.expected_boot_epoch:
                self._connection.close()
                self._closed = True
                if consequential:
                    raise IpcOutcomeUnknownError(
                        "consequential IPC response came from an unexpected boot epoch"
                    )
                raise IpcProtocolError("IPC response came from an unexpected boot epoch")
            if response.response_counter <= self._last_response_counter:
                self._connection.close()
                self._closed = True
                if consequential:
                    raise IpcOutcomeUnknownError(
                        "consequential IPC response counter did not advance"
                    )
                raise IpcProtocolError("IPC response counter did not advance")
            self._last_response_counter = response.response_counter
            return response

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True


def receive_request(connection: Any) -> IpcRequestFrame:
    try:
        return decode_frame(connection.recv_bytes(MAX_FRAME_BYTES), IpcRequestFrame)
    except (EOFError, OSError) as exc:
        raise IpcTransportError("IPC request endpoint closed") from exc


def send_response(connection: Any, response: IpcResponseFrame) -> None:
    try:
        connection.send_bytes(encode_frame(response))
    except (BrokenPipeError, OSError) as exc:
        raise IpcTransportError("IPC response endpoint closed") from exc
