"""Strict, bounded JSON request parsing for trusted HTTP boundaries.

FastAPI's normal model binding is convenient, but it does not make duplicate
JSON names or request-size handling explicit.  This module provides one small
ASGI boundary parser so consequential M4g endpoints can reject ambiguous wire
representations before Pydantic sees them.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any, Final, NoReturn, TypeVar

from pydantic import BaseModel, TypeAdapter, ValidationError
from starlette.requests import ClientDisconnect, Request

from .segmented_capability_transport import MAX_JSON_BYTES

APPLICATION_JSON: Final = "application/json"


class StrictJsonRequestReason(StrEnum):
    """Stable, disclosure-safe reasons for rejecting a request."""

    CONTENT_TYPE_REQUIRED = "content_type_must_be_application_json"
    CONTENT_LENGTH_REQUIRED = "content_length_required"
    CONTENT_LENGTH_INVALID = "content_length_invalid"
    CONTENT_LENGTH_MISMATCH = "content_length_mismatch"
    BODY_TOO_LARGE = "request_body_too_large"
    BODY_INCOMPLETE = "request_body_incomplete"
    UTF8_BOM_FORBIDDEN = "utf8_bom_forbidden"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_JSON = "invalid_json"
    DUPLICATE_JSON_KEY = "duplicate_json_key"
    NONFINITE_JSON_NUMBER = "nonfinite_json_number"
    JSON_ROOT_NOT_OBJECT = "json_root_must_be_object"
    MODEL_VALIDATION_FAILED = "request_model_validation_failed"


class StrictJsonRequestError(ValueError):
    """Typed rejection that is safe to map directly to an HTTP response."""

    def __init__(self, status_code: int, reason: StrictJsonRequestReason) -> None:
        super().__init__(reason.value)
        self.status_code = status_code
        self.reason = reason


class _DuplicateJsonKey(ValueError):
    """Internal marker that prevents an attacker-controlled name from escaping."""


class _NonfiniteJsonNumber(ValueError):
    """Internal marker for JSON constants forbidden by RFC 8259."""


def _reject(
    status_code: int,
    reason: StrictJsonRequestReason,
) -> NoReturn:
    raise StrictJsonRequestError(status_code, reason)


def _one_header(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    if not values:
        return None
    if len(values) != 1:
        if name == "content-length":
            _reject(400, StrictJsonRequestReason.CONTENT_LENGTH_INVALID)
        _reject(415, StrictJsonRequestReason.CONTENT_TYPE_REQUIRED)
    return values[0]


def _require_application_json(request: Request) -> None:
    raw_content_type = _one_header(request, "content-type")
    if raw_content_type is None:
        _reject(415, StrictJsonRequestReason.CONTENT_TYPE_REQUIRED)
    parts = [part.strip() for part in raw_content_type.split(";")]
    if parts[0].lower() != APPLICATION_JSON:
        _reject(415, StrictJsonRequestReason.CONTENT_TYPE_REQUIRED)
    if len(parts) == 1:
        return
    if len(parts) != 2 or not parts[1]:
        _reject(415, StrictJsonRequestReason.CONTENT_TYPE_REQUIRED)
    name, separator, value = parts[1].partition("=")
    charset = value.strip().lower()
    if charset.startswith('"') or charset.endswith('"'):
        if len(charset) < 2 or not charset.startswith('"') or not charset.endswith('"'):
            _reject(415, StrictJsonRequestReason.CONTENT_TYPE_REQUIRED)
        charset = charset[1:-1]
    if (
        separator != "="
        or name.strip().lower() != "charset"
        or charset not in {"utf-8", "utf8"}
    ):
        _reject(415, StrictJsonRequestReason.CONTENT_TYPE_REQUIRED)


def _require_content_length(request: Request, *, max_bytes: int) -> int:
    raw_length = _one_header(request, "content-length")
    if raw_length is None:
        _reject(411, StrictJsonRequestReason.CONTENT_LENGTH_REQUIRED)
    if (
        not raw_length.isascii()
        or not raw_length.isdecimal()
        or len(raw_length) > len(str(max_bytes))
    ):
        _reject(400, StrictJsonRequestReason.CONTENT_LENGTH_INVALID)
    declared_length = int(raw_length)
    if declared_length > max_bytes:
        _reject(413, StrictJsonRequestReason.BODY_TOO_LARGE)
    return declared_length


async def _read_bounded_body(
    request: Request,
    *,
    declared_length: int,
    max_bytes: int,
) -> bytes:
    material = bytearray()
    try:
        async for chunk in request.stream():
            next_length = len(material) + len(chunk)
            if next_length > max_bytes:
                _reject(413, StrictJsonRequestReason.BODY_TOO_LARGE)
            if next_length > declared_length:
                _reject(400, StrictJsonRequestReason.CONTENT_LENGTH_MISMATCH)
            material.extend(chunk)
    except ClientDisconnect:
        _reject(400, StrictJsonRequestReason.BODY_INCOMPLETE)
    if len(material) != declared_length:
        _reject(400, StrictJsonRequestReason.CONTENT_LENGTH_MISMATCH)
    return bytes(material)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise _DuplicateJsonKey
        result[name] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    raise _NonfiniteJsonNumber


def _prevalidate_json_object(material: bytes) -> None:
    if material.startswith(b"\xef\xbb\xbf"):
        _reject(400, StrictJsonRequestReason.UTF8_BOM_FORBIDDEN)
    try:
        decoded = material.decode("utf-8")
    except UnicodeDecodeError:
        _reject(400, StrictJsonRequestReason.INVALID_UTF8)
    try:
        value = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except _DuplicateJsonKey:
        _reject(400, StrictJsonRequestReason.DUPLICATE_JSON_KEY)
    except _NonfiniteJsonNumber:
        _reject(400, StrictJsonRequestReason.NONFINITE_JSON_NUMBER)
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        _reject(400, StrictJsonRequestReason.INVALID_JSON)
    if not isinstance(value, dict):
        _reject(400, StrictJsonRequestReason.JSON_ROOT_NOT_OBJECT)


ModelT = TypeVar("ModelT", bound=BaseModel)
AdapterT = TypeVar("AdapterT")


async def _strict_json_material(
    request: Request,
    *,
    max_bytes: int,
) -> bytes:
    if max_bytes < 1 or max_bytes > MAX_JSON_BYTES:
        raise ValueError("max_bytes must be within the M4g JSON size limit")
    _require_application_json(request)
    declared_length = _require_content_length(request, max_bytes=max_bytes)
    material = await _read_bounded_body(
        request,
        declared_length=declared_length,
        max_bytes=max_bytes,
    )
    _prevalidate_json_object(material)
    return material


async def parse_strict_json_request(
    request: Request,
    model: type[ModelT],
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> ModelT:
    """Read and validate one exact JSON object request without ambiguity.

    The request must carry one ``application/json`` Content-Type and one exact
    decimal Content-Length.  The body is streamed with an independent bound,
    checked for strict UTF-8 JSON semantics, and then passed to Pydantic's JSON
    validator.  JSON-mode validation is material for strict datetime and enum
    fields, which are represented as strings on the wire.
    """

    material = await _strict_json_material(request, max_bytes=max_bytes)
    try:
        return model.model_validate_json(material, strict=True)
    except (ValidationError, ValueError, TypeError):
        _reject(400, StrictJsonRequestReason.MODEL_VALIDATION_FAILED)


async def parse_strict_json_request_adapter(
    request: Request,
    adapter: TypeAdapter[AdapterT],
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> AdapterT:
    """Strictly parse a closed union without initializing a runtime first."""

    material = await _strict_json_material(request, max_bytes=max_bytes)
    try:
        return adapter.validate_json(material, strict=True)
    except (ValidationError, ValueError, TypeError):
        _reject(400, StrictJsonRequestReason.MODEL_VALIDATION_FAILED)
