"""Signed application mailbox framing carried over Modbus TCP registers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .crypto import sign_bytes, verify_bytes
from .physical_models import SHA256_PATTERN, canonical_digest

WIRE_VERSION = 1
DEVICE_ID = 1
REQUEST_HEADER_START = 0
REQUEST_HEADER_REGISTERS = 32
REQUEST_PAYLOAD_START = 32
REQUEST_PAYLOAD_REGISTERS = 4096
RESPONSE_HEADER_START = REQUEST_PAYLOAD_START + REQUEST_PAYLOAD_REGISTERS
RESPONSE_HEADER_REGISTERS = 40
RESPONSE_PAYLOAD_START = RESPONSE_HEADER_START + RESPONSE_HEADER_REGISTERS
RESPONSE_PAYLOAD_REGISTERS = 4096
REGISTER_COUNT = RESPONSE_PAYLOAD_START + RESPONSE_PAYLOAD_REGISTERS
MAX_PAYLOAD_BYTES = REQUEST_PAYLOAD_REGISTERS * 2
WRITE_CHUNK_REGISTERS = 120
READ_CHUNK_REGISTERS = 120
REQUEST_MAGIC = 0xAE63
RESPONSE_MAGIC = 0xAE64


class ControlWord(IntEnum):
    BEGIN = 0xA500
    COMMIT = 0xA501
    RELEASE = 0xA502


class WireOperation(IntEnum):
    READ_STATE = 1
    SIMULATE_CANDIDATE = 2
    EXECUTE = 3
    HEALTH = 4


class WireStatus(IntEnum):
    IDLE = 0
    STAGING = 1
    PROCESSING = 2
    COMPLETE = 3
    REJECTED_BEFORE_DISPATCH = 4
    UNKNOWN_EFFECT = 5


class WireResultCode(IntEnum):
    OK = 0
    INVALID_HEADER = 1
    INVALID_PAYLOAD = 2
    INVALID_SCHEMA = 3
    APPLICATION_REJECTED = 4
    APPLICATION_UNKNOWN_EFFECT = 5
    INTERNAL_ERROR = 6


def canonical_json_bytes(value: BaseModel | dict[str, Any]) -> bytes:
    material = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def bytes_to_registers(payload: bytes) -> list[int]:
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("wire payload exceeds the fixed mailbox capacity")
    padded = payload + (b"\x00" if len(payload) % 2 else b"")
    return [int.from_bytes(padded[index : index + 2], "big") for index in range(0, len(padded), 2)]


def registers_to_bytes(registers: list[int], byte_length: int) -> bytes:
    if byte_length < 0 or byte_length > MAX_PAYLOAD_BYTES:
        raise ValueError("wire byte length is outside the mailbox capacity")
    if len(registers) != (byte_length + 1) // 2:
        raise ValueError("wire register count does not match the declared byte length")
    payload = b"".join(int(value).to_bytes(2, "big") for value in registers)
    return payload[:byte_length]


def _u32_registers(value: int) -> list[int]:
    if not 0 <= value < 2**32:
        raise ValueError("value is outside unsigned 32-bit range")
    return [(value >> 16) & 0xFFFF, value & 0xFFFF]


def _u64_registers(value: int) -> list[int]:
    if not 0 <= value < 2**64:
        raise ValueError("value is outside unsigned 64-bit range")
    return [(value >> shift) & 0xFFFF for shift in (48, 32, 16, 0)]


def _registers_u32(values: list[int]) -> int:
    if len(values) != 2:
        raise ValueError("unsigned 32-bit value requires two registers")
    return (values[0] << 16) | values[1]


def _registers_u64(values: list[int]) -> int:
    if len(values) != 4:
        raise ValueError("unsigned 64-bit value requires four registers")
    result = 0
    for value in values:
        result = (result << 16) | value
    return result


def _digest_registers(digest: str) -> list[int]:
    raw = bytes.fromhex(digest)
    return [int.from_bytes(raw[index : index + 2], "big") for index in range(0, 32, 2)]


def _registers_digest(values: list[int]) -> str:
    if len(values) != 16:
        raise ValueError("SHA-256 requires sixteen registers")
    return b"".join(value.to_bytes(2, "big") for value in values).hex()


class WireRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["modbus-wire-request-v1"] = "modbus-wire-request-v1"
    transaction_id: int = Field(ge=0, lt=2**64)
    operation: WireOperation
    payload: dict[str, Any]


class SignedWireResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    schema_version: Literal["modbus-wire-response-v1"] = "modbus-wire-response-v1"
    transaction_id: int = Field(ge=0, lt=2**64)
    operation: WireOperation
    request_digest: str = Field(pattern=SHA256_PATTERN)
    status: WireStatus
    result_code: WireResultCode
    payload: dict[str, Any]
    payload_digest: str = Field(pattern=SHA256_PATTERN)
    device_id: str = Field(min_length=1)
    device_key_id: str = Field(min_length=1)
    boot_epoch: str = Field(min_length=16)
    device_transaction_counter: int = Field(ge=1)
    signature: str = ""

    @model_validator(mode="after")
    def require_payload_digest(self) -> SignedWireResponse:
        if self.payload_digest != canonical_digest(self.payload):
            raise ValueError("wire response payload digest is inconsistent")
        return self

    def signing_payload(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json", exclude={"signature"}))

    def signed(self, private_key: Ed25519PrivateKey) -> SignedWireResponse:
        signature = sign_bytes(private_key, self.signing_payload())
        return self.model_copy(update={"signature": signature})

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )


@dataclass(frozen=True)
class RequestHeader:
    control: ControlWord
    operation: WireOperation
    transaction_id: int
    payload_byte_length: int
    payload_register_count: int
    payload_digest: str

    def to_registers(self) -> list[int]:
        registers = [0] * REQUEST_HEADER_REGISTERS
        registers[0] = int(self.control)
        registers[1] = REQUEST_MAGIC
        registers[2] = WIRE_VERSION
        registers[3] = int(self.operation)
        registers[4:8] = _u64_registers(self.transaction_id)
        registers[8:10] = _u32_registers(self.payload_byte_length)
        registers[10] = self.payload_register_count
        registers[11] = 0
        registers[12:28] = _digest_registers(self.payload_digest)
        return registers

    @classmethod
    def from_registers(cls, values: list[int]) -> RequestHeader:
        if len(values) != REQUEST_HEADER_REGISTERS:
            raise ValueError("request header has the wrong register count")
        if values[1] != REQUEST_MAGIC or values[2] != WIRE_VERSION:
            raise ValueError("request header magic or version is invalid")
        if values[11] != 0 or any(values[28:32]):
            raise ValueError("request header reserved fields must be zero")
        byte_length = _registers_u32(values[8:10])
        register_count = values[10]
        if byte_length > MAX_PAYLOAD_BYTES or register_count != (byte_length + 1) // 2:
            raise ValueError("request payload dimensions are invalid")
        return cls(
            control=ControlWord(values[0]),
            operation=WireOperation(values[3]),
            transaction_id=_registers_u64(values[4:8]),
            payload_byte_length=byte_length,
            payload_register_count=register_count,
            payload_digest=_registers_digest(values[12:28]),
        )


@dataclass(frozen=True)
class ResponseHeader:
    status: WireStatus
    operation: WireOperation
    transaction_id: int
    payload_byte_length: int
    payload_register_count: int
    result_code: WireResultCode
    payload_digest: str
    device_transaction_counter: int
    state_version_hint: int

    def to_registers(self) -> list[int]:
        registers = [0] * RESPONSE_HEADER_REGISTERS
        registers[0] = RESPONSE_MAGIC
        registers[1] = WIRE_VERSION
        registers[2] = int(self.status)
        registers[3] = int(self.operation)
        registers[4:8] = _u64_registers(self.transaction_id)
        registers[8:10] = _u32_registers(self.payload_byte_length)
        registers[10] = self.payload_register_count
        registers[11] = int(self.result_code)
        registers[12:28] = _digest_registers(self.payload_digest)
        registers[28:32] = _u64_registers(self.device_transaction_counter)
        registers[32:36] = _u64_registers(self.state_version_hint)
        return registers

    @classmethod
    def from_registers(cls, values: list[int]) -> ResponseHeader:
        if len(values) != RESPONSE_HEADER_REGISTERS:
            raise ValueError("response header has the wrong register count")
        if values[0] != RESPONSE_MAGIC or values[1] != WIRE_VERSION:
            raise ValueError("response header magic or version is invalid")
        if any(values[36:40]):
            raise ValueError("response header reserved fields must be zero")
        byte_length = _registers_u32(values[8:10])
        register_count = values[10]
        if byte_length > MAX_PAYLOAD_BYTES or register_count != (byte_length + 1) // 2:
            raise ValueError("response payload dimensions are invalid")
        return cls(
            status=WireStatus(values[2]),
            operation=WireOperation(values[3]),
            transaction_id=_registers_u64(values[4:8]),
            payload_byte_length=byte_length,
            payload_register_count=register_count,
            result_code=WireResultCode(values[11]),
            payload_digest=_registers_digest(values[12:28]),
            device_transaction_counter=_registers_u64(values[28:32]),
            state_version_hint=_registers_u64(values[32:36]),
        )
