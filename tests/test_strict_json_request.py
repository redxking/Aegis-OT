from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.requests import Request

from aegis_ot.segmented_capability_models import (
    PlantCallerRole,
    PlantCapturePayload,
    PlantOperation,
    SignedPlantCall,
)
from aegis_ot.segmented_capability_transport import MAX_JSON_BYTES
from aegis_ot.strict_json_request import (
    StrictJsonRequestError,
    StrictJsonRequestReason,
    parse_strict_json_request,
)


def _request(
    body: bytes,
    *,
    content_type: str = "application/json",
    content_length: str | None = None,
    include_content_type: bool = True,
    include_content_length: bool = True,
    extra_headers: Sequence[tuple[bytes, bytes]] = (),
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if include_content_type:
        headers.append((b"content-type", content_type.encode("ascii")))
    if include_content_length:
        headers.append(
            (
                b"content-length",
                (str(len(body)) if content_length is None else content_length).encode("ascii"),
            )
        )
    headers.extend(extra_headers)
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/plant/call",
            "raw_path": b"/v1/plant/call",
            "query_string": b"",
            "headers": headers,
            "client": ("test", 1234),
            "server": ("test", 80),
        },
        receive,
    )


def _parse(
    body: bytes,
    model: type[SignedPlantCall] = SignedPlantCall,
    **request_kwargs: Any,
) -> SignedPlantCall:
    return asyncio.run(parse_strict_json_request(_request(body, **request_kwargs), model))


def _assert_rejected(
    body: bytes,
    *,
    status_code: int,
    reason: StrictJsonRequestReason,
    **request_kwargs: Any,
) -> None:
    with pytest.raises(StrictJsonRequestError) as captured:
        _parse(body, **request_kwargs)
    assert captured.value.status_code == status_code
    assert captured.value.reason is reason
    assert str(captured.value) == reason.value


def test_signed_strict_enum_and_datetime_model_round_trips_in_json_mode() -> None:
    private_key = Ed25519PrivateKey.generate()
    issued_at = datetime(2026, 8, 25, 12, 30, tzinfo=UTC)
    call = SignedPlantCall.issue(
        role=PlantCallerRole.OBSERVER,
        operation=PlantOperation.CAPTURE,
        payload=PlantCapturePayload(
            correlation_id="m4g-strict-wire-round-trip",
            challenge_nonce="m4g-strict-wire-challenge-0001",
        ),
        caller_key_id="m4g-observer-key-v1",
        target_plant_key_id="m4g-plant-key-v1",
        target_plant_boot_epoch="m4g-plant-boot-epoch-0001",
        call_nonce="m4g-strict-wire-call-nonce-0001",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=5),
        private_key=private_key,
    )

    parsed = _parse(call.model_dump_json().encode("utf-8"))

    assert parsed == call
    assert parsed.role is PlantCallerRole.OBSERVER
    assert parsed.operation is PlantOperation.CAPTURE
    assert parsed.issued_at == issued_at
    assert parsed.verify(private_key.public_key())


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b'{"broken":', StrictJsonRequestReason.INVALID_JSON),
        (b'{"field":1,"field":2}', StrictJsonRequestReason.DUPLICATE_JSON_KEY),
        (
            b'{"outer":{"field":1,"field":2}}',
            StrictJsonRequestReason.DUPLICATE_JSON_KEY,
        ),
        (b'{"field":NaN}', StrictJsonRequestReason.NONFINITE_JSON_NUMBER),
        (b'{"field":Infinity}', StrictJsonRequestReason.NONFINITE_JSON_NUMBER),
        (b'{"field":-Infinity}', StrictJsonRequestReason.NONFINITE_JSON_NUMBER),
        (b"[]", StrictJsonRequestReason.JSON_ROOT_NOT_OBJECT),
        (b"\xef\xbb\xbf{}", StrictJsonRequestReason.UTF8_BOM_FORBIDDEN),
        (b'{"field":"\xff"}', StrictJsonRequestReason.INVALID_UTF8),
    ],
)
def test_ambiguous_or_malformed_wire_json_is_rejected(
    body: bytes,
    reason: StrictJsonRequestReason,
) -> None:
    _assert_rejected(body, status_code=400, reason=reason)


def test_declared_or_actual_oversize_body_is_rejected_before_model_validation() -> None:
    _assert_rejected(
        b"{}",
        content_length=str(MAX_JSON_BYTES + 1),
        status_code=413,
        reason=StrictJsonRequestReason.BODY_TOO_LARGE,
    )
    oversized = b" " * (MAX_JSON_BYTES + 1)
    _assert_rejected(
        oversized,
        content_length=str(MAX_JSON_BYTES),
        status_code=413,
        reason=StrictJsonRequestReason.BODY_TOO_LARGE,
    )


@pytest.mark.parametrize(
    "content_type",
    [
        "text/json",
        "application/problem+json",
        "",
        'application/json; charset="utf-8',
        "application/json; charset=utf-8; charset=utf-8",
    ],
)
def test_non_application_json_content_type_is_rejected(content_type: str) -> None:
    _assert_rejected(
        b"{}",
        content_type=content_type,
        status_code=415,
        reason=StrictJsonRequestReason.CONTENT_TYPE_REQUIRED,
    )


def test_utf8_content_type_parameter_is_accepted_but_other_parameters_are_not() -> None:
    body = b"{}"
    with pytest.raises(StrictJsonRequestError) as validation_failure:
        _parse(body, content_type="application/json; charset=utf-8")
    assert validation_failure.value.reason is StrictJsonRequestReason.MODEL_VALIDATION_FAILED

    _assert_rejected(
        body,
        content_type="application/json; charset=iso-8859-1",
        status_code=415,
        reason=StrictJsonRequestReason.CONTENT_TYPE_REQUIRED,
    )


@pytest.mark.parametrize("content_length", ["-1", "+2", "2.0", "1, 1"])
def test_invalid_content_length_is_rejected(content_length: str) -> None:
    _assert_rejected(
        b"{}",
        content_length=content_length,
        status_code=400,
        reason=StrictJsonRequestReason.CONTENT_LENGTH_INVALID,
    )


def test_required_content_headers_cannot_be_omitted() -> None:
    _assert_rejected(
        b"{}",
        include_content_type=False,
        status_code=415,
        reason=StrictJsonRequestReason.CONTENT_TYPE_REQUIRED,
    )
    _assert_rejected(
        b"{}",
        include_content_length=False,
        status_code=411,
        reason=StrictJsonRequestReason.CONTENT_LENGTH_REQUIRED,
    )


def test_duplicate_content_headers_and_length_mismatch_are_rejected() -> None:
    _assert_rejected(
        b"{}",
        extra_headers=((b"content-length", b"2"),),
        status_code=400,
        reason=StrictJsonRequestReason.CONTENT_LENGTH_INVALID,
    )
    _assert_rejected(
        b"{}",
        content_length="3",
        status_code=400,
        reason=StrictJsonRequestReason.CONTENT_LENGTH_MISMATCH,
    )
    _assert_rejected(
        b"{}",
        extra_headers=((b"content-type", b"application/json"),),
        status_code=415,
        reason=StrictJsonRequestReason.CONTENT_TYPE_REQUIRED,
    )
