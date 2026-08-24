from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis_ot.crypto import generate_keypair
from aegis_ot.modbus_wire import (
    MAX_PAYLOAD_BYTES,
    REQUEST_HEADER_REGISTERS,
    RESPONSE_HEADER_REGISTERS,
    ControlWord,
    RequestHeader,
    ResponseHeader,
    SignedWireResponse,
    WireOperation,
    WireResultCode,
    WireStatus,
    bytes_to_registers,
    canonical_json_bytes,
    registers_to_bytes,
    sha256_hex,
)
from aegis_ot.physical_models import canonical_digest


@pytest.mark.parametrize("payload", [b"", b"a", b"ab", b"abc", bytes(range(255))])
def test_wire_register_encoding_round_trip(payload: bytes) -> None:
    registers = bytes_to_registers(payload)
    assert registers_to_bytes(registers, len(payload)) == payload


def test_wire_encoding_rejects_oversize_and_dimension_mismatch() -> None:
    with pytest.raises(ValueError, match="capacity"):
        bytes_to_registers(b"x" * (MAX_PAYLOAD_BYTES + 1))
    with pytest.raises(ValueError, match="register count"):
        registers_to_bytes([1, 2], 2)


def test_request_header_round_trip_and_reserved_field_rejection() -> None:
    payload = b"request"
    header = RequestHeader(
        control=ControlWord.BEGIN,
        operation=WireOperation.EXECUTE,
        transaction_id=2**48 + 7,
        payload_byte_length=len(payload),
        payload_register_count=len(bytes_to_registers(payload)),
        payload_digest=sha256_hex(payload),
    )
    registers = header.to_registers()
    assert len(registers) == REQUEST_HEADER_REGISTERS
    assert RequestHeader.from_registers(registers) == header
    registers[28] = 1
    with pytest.raises(ValueError, match="reserved"):
        RequestHeader.from_registers(registers)


def test_response_header_round_trip() -> None:
    payload = b"response"
    header = ResponseHeader(
        status=WireStatus.COMPLETE,
        operation=WireOperation.READ_STATE,
        transaction_id=9,
        payload_byte_length=len(payload),
        payload_register_count=len(bytes_to_registers(payload)),
        result_code=WireResultCode.OK,
        payload_digest=sha256_hex(payload),
        device_transaction_counter=3,
        state_version_hint=4,
    )
    registers = header.to_registers()
    assert len(registers) == RESPONSE_HEADER_REGISTERS
    assert ResponseHeader.from_registers(registers) == header


def test_signed_wire_response_binds_request_payload_device_and_epoch() -> None:
    private, public = generate_keypair()
    payload = {"state": {"version": 1}}
    response = SignedWireResponse(
        transaction_id=1,
        operation=WireOperation.READ_STATE,
        request_digest="a" * 64,
        status=WireStatus.COMPLETE,
        result_code=WireResultCode.OK,
        payload=payload,
        payload_digest=canonical_digest(payload),
        device_id="device:1",
        device_key_id="key:1",
        boot_epoch="boot-epoch-00000001",
        device_transaction_counter=1,
    ).signed(private)
    assert response.verify(public)
    assert canonical_json_bytes(response) == canonical_json_bytes(response.model_dump(mode="json"))
    tampered = response.model_copy(update={"transaction_id": 2})
    assert not tampered.verify(public)
    with pytest.raises(ValidationError, match="payload digest"):
        SignedWireResponse.model_validate(
            response.model_dump(mode="python") | {"payload_digest": "b" * 64}
        )
