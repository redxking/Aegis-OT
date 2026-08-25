"""Separate-process signed Modbus mailbox for the M3 physical control path."""

from __future__ import annotations

import asyncio
import base64
import json
import multiprocessing
import socket
import time
from dataclasses import dataclass, replace
from datetime import datetime
from threading import RLock
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError
from pymodbus.client import ModbusTcpClient
from pymodbus.constants import ExcCodes
from pymodbus.server import ModbusTcpServer
from pymodbus.simulator import DataType, SimData, SimDevice

from .crypto import decode_urlsafe_b64, generate_keypair
from .modbus_wire import (
    DEVICE_ID,
    MAX_PAYLOAD_BYTES,
    READ_CHUNK_REGISTERS,
    REGISTER_COUNT,
    REQUEST_HEADER_REGISTERS,
    REQUEST_PAYLOAD_START,
    RESPONSE_HEADER_REGISTERS,
    RESPONSE_HEADER_START,
    RESPONSE_PAYLOAD_START,
    WRITE_CHUNK_REGISTERS,
    ControlWord,
    RequestHeader,
    ResponseHeader,
    SignedWireResponse,
    WireOperation,
    WireRequest,
    WireResultCode,
    WireStatus,
    bytes_to_registers,
    canonical_json_bytes,
    registers_to_bytes,
    sha256_hex,
)
from .models import ActionProposal, Decision
from .pandapower_plant import PandapowerCigreMVPlant
from .physical_control import (
    Clock,
    ControlDispatchUnknownEffect,
    PermitAwareVirtualControlDevice,
    utc_now,
)
from .physical_models import (
    CandidateAssessment,
    CommandAcknowledgment,
    CommandStatus,
    ExecutionPermit,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
)


class ModbusTransportError(RuntimeError):
    """The mailbox transaction failed before a consequential commit was sent."""


class ModbusUnknownEffectError(ControlDispatchUnknownEffect):
    """A failure after EXECUTE commit means physical effect was not established."""


class ModbusProtocolError(RuntimeError):
    """A signed or framed mailbox response violated the application contract."""


class _ApplicationUnknownEffect(RuntimeError):
    """The server entered command processing before an uncategorized failure."""


@dataclass(frozen=True)
class ModbusDeviceInfo:
    host: str
    port: int
    pid: int
    boot_epoch: str
    audience: str
    device_id: str
    device_key_id: str
    device_public_key_b64: str
    model_digest: str
    simulator_version: str
    protocol_version: int

    @property
    def device_public_key(self) -> Ed25519PublicKey:
        raw = decode_urlsafe_b64(self.device_public_key_b64)
        return Ed25519PublicKey.from_public_bytes(raw)


class _MailboxService:
    def __init__(
        self,
        *,
        plant: PandapowerCigreMVPlant,
        control_device: PermitAwareVirtualControlDevice,
        response_private_key: Ed25519PrivateKey,
        boot_epoch: str,
    ) -> None:
        self.plant = plant
        self.control_device = control_device
        self.response_private_key = response_private_key
        self.boot_epoch = boot_epoch
        self._transaction_counter = 0
        self._active_transaction: int | None = None
        self._active_header: RequestHeader | None = None
        self._terminal_transaction: int | None = None
        self._commit_lock = asyncio.Lock()

    @staticmethod
    def _clear_response(registers: list[int]) -> None:
        start = RESPONSE_HEADER_START
        for index in range(start, REGISTER_COUNT):
            registers[index] = 0

    def _signed_response(
        self,
        *,
        transaction_id: int,
        operation: WireOperation,
        request_digest: str,
        status: WireStatus,
        result_code: WireResultCode,
        payload: dict[str, Any],
    ) -> SignedWireResponse:
        self._transaction_counter += 1
        response = SignedWireResponse(
            transaction_id=transaction_id,
            operation=operation,
            request_digest=request_digest,
            status=status,
            result_code=result_code,
            payload=payload,
            payload_digest=canonical_digest(payload),
            device_id=self.control_device.device_id,
            device_key_id=self.control_device.acknowledgment_key_id,
            boot_epoch=self.boot_epoch,
            device_transaction_counter=self._transaction_counter,
        )
        return response.signed(self.response_private_key)

    def _write_response(
        self,
        registers: list[int],
        response: SignedWireResponse,
        *,
        state_version_hint: int,
    ) -> None:
        payload = canonical_json_bytes(response)
        payload_registers = bytes_to_registers(payload)
        header = ResponseHeader(
            status=response.status,
            operation=response.operation,
            transaction_id=response.transaction_id,
            payload_byte_length=len(payload),
            payload_register_count=len(payload_registers),
            result_code=response.result_code,
            payload_digest=sha256_hex(payload),
            device_transaction_counter=response.device_transaction_counter,
            state_version_hint=state_version_hint,
        )
        self._clear_response(registers)
        registers[RESPONSE_HEADER_START : RESPONSE_HEADER_START + RESPONSE_HEADER_REGISTERS] = (
            header.to_registers()
        )
        registers[RESPONSE_PAYLOAD_START : RESPONSE_PAYLOAD_START + len(payload_registers)] = (
            payload_registers
        )

    def _handle_application(
        self,
        request: WireRequest,
    ) -> tuple[WireStatus, WireResultCode, dict[str, Any], int]:
        if request.operation is WireOperation.READ_STATE:
            if request.payload:
                raise ValueError("read-state payload must be empty")
            state = self.plant.capture_state()
            return (
                WireStatus.COMPLETE,
                WireResultCode.OK,
                {"state": state.model_dump(mode="json")},
                state.state_version,
            )
        if request.operation is WireOperation.SIMULATE_CANDIDATE:
            command = PhysicalControlCommand.model_validate(request.payload.get("command"))
            assessment = self.plant.simulate_candidate(command)
            return (
                WireStatus.COMPLETE,
                WireResultCode.OK,
                {"assessment": assessment.model_dump(mode="json")},
                assessment.pre_state.state_version,
            )
        if request.operation is WireOperation.EXECUTE:
            permit = ExecutionPermit.model_validate(request.payload.get("permit"))
            proposal = ActionProposal.model_validate(request.payload.get("proposal"))
            decision = Decision.model_validate(request.payload.get("decision"))
            assessment = CandidateAssessment.model_validate(request.payload.get("assessment"))
            try:
                acknowledgment = self.control_device.execute(
                    permit,
                    proposal=proposal,
                    decision=decision,
                    assessment=assessment,
                )
                post_state = self.plant.read_state()
            except Exception as exc:
                raise _ApplicationUnknownEffect from exc
            if acknowledgment.status is CommandStatus.APPLIED:
                status = WireStatus.COMPLETE
                result_code = WireResultCode.OK
            elif acknowledgment.status is CommandStatus.REJECTED:
                status = WireStatus.REJECTED_BEFORE_DISPATCH
                result_code = WireResultCode.APPLICATION_REJECTED
            else:
                status = WireStatus.UNKNOWN_EFFECT
                result_code = WireResultCode.APPLICATION_UNKNOWN_EFFECT
            return (
                status,
                result_code,
                {
                    "acknowledgment": acknowledgment.model_dump(mode="json"),
                    "post_state": post_state.model_dump(mode="json"),
                },
                post_state.state_version,
            )
        if request.operation is WireOperation.HEALTH:
            if request.payload:
                raise ValueError("health payload must be empty")
            state = self.plant.read_state()
            return (
                WireStatus.COMPLETE,
                WireResultCode.OK,
                {
                    "status": "ready",
                    "protocol_version": 1,
                    "model_digest": state.model_digest,
                    "simulator_version": state.simulator_version,
                    "device_id": self.control_device.device_id,
                    "device_key_id": self.control_device.acknowledgment_key_id,
                    "boot_epoch": self.boot_epoch,
                    "state_version": state.state_version,
                },
                state.state_version,
            )
        raise ValueError("unsupported wire operation")

    def _process_commit(self, registers: list[int]) -> None:
        raw_header = list(registers[:REQUEST_HEADER_REGISTERS])
        request_digest = "0" * 64
        transaction_id = self._active_transaction or 0
        operation = WireOperation.HEALTH
        try:
            header = RequestHeader.from_registers(raw_header)
            if header.control is not ControlWord.BEGIN:
                raise ValueError("staged request does not contain BEGIN")
            transaction_id = header.transaction_id
            operation = header.operation
            if transaction_id != self._active_transaction:
                raise ValueError("commit transaction does not match active staging")
            payload_registers = list(
                registers[
                    REQUEST_PAYLOAD_START : REQUEST_PAYLOAD_START + header.payload_register_count
                ]
            )
            payload_bytes = registers_to_bytes(payload_registers, header.payload_byte_length)
            request_digest = sha256_hex(payload_bytes)
            if request_digest != header.payload_digest:
                raise ValueError("request payload digest mismatch")
            raw_request = json.loads(payload_bytes.decode("utf-8"))
            request = WireRequest.model_validate(raw_request)
            if canonical_json_bytes(request) != payload_bytes:
                raise ValueError("request is not canonical JSON")
            if request.transaction_id != transaction_id or request.operation is not operation:
                raise ValueError("request payload does not match header")
            status, result_code, payload, state_version = self._handle_application(request)
        except _ApplicationUnknownEffect as exc:
            status = WireStatus.UNKNOWN_EFFECT
            result_code = WireResultCode.APPLICATION_UNKNOWN_EFFECT
            payload = {"error": type(exc).__name__, "reason": "unclassified_server_failure"}
            state_version = self.plant.read_state().state_version
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
            status = WireStatus.REJECTED_BEFORE_DISPATCH
            result_code = WireResultCode.INVALID_SCHEMA
            payload = {"error": type(exc).__name__, "reason": str(exc)}
            state_version = self.plant.read_state().state_version
        except Exception as exc:
            status = (
                WireStatus.UNKNOWN_EFFECT
                if operation is WireOperation.EXECUTE
                else WireStatus.REJECTED_BEFORE_DISPATCH
            )
            result_code = (
                WireResultCode.APPLICATION_UNKNOWN_EFFECT
                if operation is WireOperation.EXECUTE
                else WireResultCode.INTERNAL_ERROR
            )
            payload = {"error": type(exc).__name__, "reason": "unclassified_server_failure"}
            state_version = self.plant.read_state().state_version
        response = self._signed_response(
            transaction_id=transaction_id,
            operation=operation,
            request_digest=request_digest,
            status=status,
            result_code=result_code,
            payload=payload,
        )
        self._write_response(registers, response, state_version_hint=state_version)

    async def action(
        self,
        function_code: int,
        start_address: int,
        address: int,
        count: int,
        current_registers: list[int],
        set_values: list[int] | list[bool] | None,
    ) -> ExcCodes | None:
        del function_code
        if set_values is None:
            return None
        if start_address != 0 or not all(isinstance(value, int) for value in set_values):
            return ExcCodes.ILLEGAL_VALUE
        values = [int(value) for value in set_values]
        if address >= RESPONSE_HEADER_START:
            return ExcCodes.ILLEGAL_ADDRESS
        if address == 0:
            if count == REQUEST_HEADER_REGISTERS and values[0] in {
                ControlWord.BEGIN,
                ControlWord.RELEASE,
            }:
                try:
                    header = RequestHeader.from_registers(values)
                except ValueError:
                    return ExcCodes.ILLEGAL_VALUE
                if header.control is ControlWord.RELEASE:
                    if (
                        self._active_header is None
                        or self._terminal_transaction != self._active_transaction
                        or header != replace(self._active_header, control=ControlWord.RELEASE)
                    ):
                        return ExcCodes.ILLEGAL_VALUE
                    self._active_transaction = None
                    self._active_header = None
                    self._terminal_transaction = None
                    return None
                if header.control is not ControlWord.BEGIN:
                    return ExcCodes.ILLEGAL_VALUE
                if self._active_header is not None:
                    return (
                        None
                        if header == self._active_header and self._terminal_transaction is None
                        else ExcCodes.DEVICE_BUSY
                    )
                self._active_transaction = header.transaction_id
                self._active_header = header
                self._clear_response(current_registers)
                return None
            if count != 1:
                return ExcCodes.ILLEGAL_VALUE
            if values[0] == ControlWord.COMMIT:
                if self._active_transaction is None:
                    return ExcCodes.ILLEGAL_VALUE
                async with self._commit_lock:
                    if self._terminal_transaction is None:
                        self._process_commit(current_registers)
                        self._terminal_transaction = self._active_transaction
                return None
            return ExcCodes.ILLEGAL_VALUE
        payload_end = REQUEST_PAYLOAD_START + 4096
        if (
            self._active_transaction is None
            or self._terminal_transaction is not None
            or address < REQUEST_PAYLOAD_START
            or address + count > payload_end
        ):
            return ExcCodes.ILLEGAL_ADDRESS
        return None


class ModbusPhysicalDeviceClient:
    """Verified synchronous client implementing state, candidate, and control interfaces."""

    def __init__(
        self,
        info: ModbusDeviceInfo,
        *,
        timeout_seconds: float = 3.0,
    ) -> None:
        self.info = info
        self.device_id = info.device_id
        self.acknowledgment_key_id = info.device_key_id
        self.acknowledgment_public_key = info.device_public_key
        self._client = ModbusTcpClient(
            info.host,
            port=info.port,
            timeout=timeout_seconds,
            retries=0,
        )
        self._transaction_id = 0
        self._last_device_transaction_counter = 0
        self._lock = RLock()
        if not self._client.connect():  # type: ignore[no-untyped-call]
            raise ModbusTransportError("could not connect to the virtual Modbus device")

    def close(self) -> None:
        self._client.close()  # type: ignore[no-untyped-call]

    @staticmethod
    def _require_success(response: Any, operation: str) -> None:
        if response is None or response.isError():
            raise ModbusTransportError(f"Modbus {operation} failed: {response!r}")

    def _write_registers(self, address: int, values: list[int]) -> None:
        response = self._client.write_registers(address, values, device_id=DEVICE_ID)
        self._require_success(response, "write-multiple-registers")

    def _read_registers(self, address: int, count: int) -> list[int]:
        values: list[int] = []
        offset = 0
        while offset < count:
            chunk_count = min(READ_CHUNK_REGISTERS, count - offset)
            response = self._client.read_holding_registers(
                address + offset,
                count=chunk_count,
                device_id=DEVICE_ID,
            )
            self._require_success(response, "read-holding-registers")
            values.extend(int(value) for value in response.registers)
            offset += chunk_count
        return values

    def _release(self, header: RequestHeader) -> None:
        try:
            release = replace(header, control=ControlWord.RELEASE)
            self._client.write_registers(0, release.to_registers(), device_id=DEVICE_ID)
        except Exception:
            return

    def _request(self, operation: WireOperation, payload: dict[str, Any]) -> SignedWireResponse:
        with self._lock:
            self._transaction_id += 1
            transaction_id = self._transaction_id
            request = WireRequest(
                transaction_id=transaction_id,
                operation=operation,
                payload=payload,
            )
            request_bytes = canonical_json_bytes(request)
            if len(request_bytes) > MAX_PAYLOAD_BYTES:
                raise ModbusTransportError("request exceeds the Modbus mailbox capacity")
            request_registers = bytes_to_registers(request_bytes)
            header = RequestHeader(
                control=ControlWord.BEGIN,
                operation=operation,
                transaction_id=transaction_id,
                payload_byte_length=len(request_bytes),
                payload_register_count=len(request_registers),
                payload_digest=sha256_hex(request_bytes),
            )
            commit_sent = False
            response_verified = False
            try:
                self._write_registers(0, header.to_registers())
                for offset in range(0, len(request_registers), WRITE_CHUNK_REGISTERS):
                    chunk = request_registers[offset : offset + WRITE_CHUNK_REGISTERS]
                    self._write_registers(REQUEST_PAYLOAD_START + offset, chunk)
                commit_response = self._client.write_register(
                    0,
                    int(ControlWord.COMMIT),
                    device_id=DEVICE_ID,
                )
                commit_sent = True
                self._require_success(commit_response, "commit")
                raw_header = self._read_registers(
                    RESPONSE_HEADER_START,
                    RESPONSE_HEADER_REGISTERS,
                )
                response_header = ResponseHeader.from_registers(raw_header)
                if (
                    response_header.transaction_id != transaction_id
                    or response_header.operation is not operation
                ):
                    raise ModbusProtocolError("response header transaction correlation failed")
                raw_payload_registers = self._read_registers(
                    RESPONSE_PAYLOAD_START,
                    response_header.payload_register_count,
                )
                response_bytes = registers_to_bytes(
                    raw_payload_registers,
                    response_header.payload_byte_length,
                )
                if sha256_hex(response_bytes) != response_header.payload_digest:
                    raise ModbusProtocolError("response mailbox digest mismatch")
                raw_response = json.loads(response_bytes.decode("utf-8"))
                response = SignedWireResponse.model_validate(raw_response)
                if canonical_json_bytes(response) != response_bytes:
                    raise ModbusProtocolError("response is not canonical JSON")
                if (
                    response.transaction_id != transaction_id
                    or response.operation is not operation
                    or response.request_digest != sha256_hex(request_bytes)
                    or response.device_id != self.info.device_id
                    or response.device_key_id != self.info.device_key_id
                    or response.boot_epoch != self.info.boot_epoch
                    or not response.verify(self.acknowledgment_public_key)
                ):
                    raise ModbusProtocolError("signed response correlation or integrity failed")
                if (
                    response.status != response_header.status
                    or response.result_code != response_header.result_code
                    or response.device_transaction_counter
                    != response_header.device_transaction_counter
                ):
                    raise ModbusProtocolError("signed response does not match response header")
                if response.device_transaction_counter <= self._last_device_transaction_counter:
                    raise ModbusProtocolError("signed response transaction counter did not advance")
                state_version = response.payload.get("state_version")
                if operation is WireOperation.READ_STATE:
                    state_version = response.payload.get("state", {}).get("state_version")
                elif operation is WireOperation.SIMULATE_CANDIDATE:
                    state_version = (
                        response.payload.get("assessment", {})
                        .get("pre_state", {})
                        .get("state_version")
                    )
                elif operation is WireOperation.EXECUTE:
                    state_version = response.payload.get("post_state", {}).get("state_version")
                if state_version != response_header.state_version_hint:
                    raise ModbusProtocolError("response state-version hint is inconsistent")
                self._last_device_transaction_counter = response.device_transaction_counter
                response_verified = True
                return response
            except (ModbusTransportError, ModbusProtocolError):
                if commit_sent and operation is WireOperation.EXECUTE:
                    raise ModbusUnknownEffectError(
                        "execute failed after commit; automatic retry is prohibited"
                    ) from None
                raise
            except Exception as exc:
                if commit_sent and operation is WireOperation.EXECUTE:
                    raise ModbusUnknownEffectError(
                        "execute failed after commit; automatic retry is prohibited"
                    ) from exc
                raise ModbusTransportError("Modbus mailbox transaction failed") from exc
            finally:
                if response_verified or not (commit_sent and operation is WireOperation.EXECUTE):
                    self._release(header)

    def health(self) -> dict[str, Any]:
        response = self._request(WireOperation.HEALTH, {})
        if response.status is not WireStatus.COMPLETE:
            raise ModbusProtocolError(f"health request failed: {response.payload}")
        return response.payload

    def read_state(self) -> PhysicalStateSnapshot:
        response = self._request(WireOperation.READ_STATE, {})
        if response.status is not WireStatus.COMPLETE:
            raise ModbusProtocolError(f"state request failed: {response.payload}")
        return PhysicalStateSnapshot.model_validate(response.payload.get("state"))

    def capture_state(self) -> PhysicalStateSnapshot:
        """Request a newly captured observation envelope from the device process."""

        return self.read_state()

    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
        response = self._request(
            WireOperation.SIMULATE_CANDIDATE,
            {"command": command.model_dump(mode="json")},
        )
        if response.status is not WireStatus.COMPLETE:
            raise ModbusProtocolError(f"candidate request failed: {response.payload}")
        return CandidateAssessment.model_validate(response.payload.get("assessment"))

    def execute(
        self,
        permit: ExecutionPermit,
        *,
        proposal: ActionProposal,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> CommandAcknowledgment:
        response = self._request(
            WireOperation.EXECUTE,
            {
                "permit": permit.model_dump(mode="json"),
                "proposal": proposal.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
                "assessment": assessment.model_dump(mode="json"),
            },
        )
        if response.status not in {
            WireStatus.COMPLETE,
            WireStatus.REJECTED_BEFORE_DISPATCH,
            WireStatus.UNKNOWN_EFFECT,
        }:
            raise ModbusProtocolError(f"execution response is incomplete: {response.payload}")
        if (
            response.status is WireStatus.UNKNOWN_EFFECT
            and "acknowledgment" not in response.payload
        ):
            raise ModbusUnknownEffectError("device returned an unclassified execution outcome")
        return CommandAcknowledgment.model_validate(response.payload.get("acknowledgment"))


async def _run_server_async(
    ready_connection: Any,
    stop_event: Any,
    *,
    port: int,
    permit_public_key_bytes: bytes,
    permit_key_id: str,
    fixed_now_iso: str | None,
) -> None:
    fixed_now = datetime.fromisoformat(fixed_now_iso) if fixed_now_iso is not None else None
    clock: Clock = (lambda: fixed_now) if fixed_now is not None else utc_now
    boot_epoch = str(uuid4())
    device_id = f"virtual-modbus-device:m3:{boot_epoch}"
    ack_private, ack_public = generate_keypair()
    ack_key_id = "m3-modbus-device-key-1"
    plant = PandapowerCigreMVPlant(observation_clock=clock)
    permit_public_key = Ed25519PublicKey.from_public_bytes(permit_public_key_bytes)
    control_device = PermitAwareVirtualControlDevice(
        plant,
        device_id=device_id,
        permit_audience=device_id,
        permit_public_keys={permit_key_id: permit_public_key},
        acknowledgment_private_key=ack_private,
        acknowledgment_key_id=ack_key_id,
        clock=clock,
    )
    service = _MailboxService(
        plant=plant,
        control_device=control_device,
        response_private_key=ack_private,
        boot_epoch=boot_epoch,
    )
    simdata = [
        SimData(
            address=0,
            count=RESPONSE_HEADER_START,
            values=0,
            datatype=DataType.REGISTERS,
        ),
        SimData(
            address=RESPONSE_HEADER_START,
            count=REGISTER_COUNT - RESPONSE_HEADER_START,
            values=0,
            datatype=DataType.REGISTERS,
            readonly=True,
        ),
    ]
    server = ModbusTcpServer(
        SimDevice(id=DEVICE_ID, simdata=simdata, action=service.action),
        address=("127.0.0.1", port),
    )
    await server.serve_forever(background=True)
    public_raw = ack_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ready_connection.send(
        {
            "host": "127.0.0.1",
            "port": port,
            "pid": multiprocessing.current_process().pid,
            "boot_epoch": boot_epoch,
            "audience": device_id,
            "device_id": device_id,
            "device_key_id": ack_key_id,
            "device_public_key_b64": base64.urlsafe_b64encode(public_raw).decode("ascii"),
            "model_digest": plant.model_digest,
            "simulator_version": plant.simulator_version,
            "protocol_version": 1,
        }
    )
    while not stop_event.is_set():
        await asyncio.sleep(0.05)
    await server.shutdown()  # type: ignore[no-untyped-call]


def _server_process_main(
    ready_connection: Any,
    stop_event: Any,
    port: int,
    permit_public_key_bytes: bytes,
    permit_key_id: str,
    fixed_now_iso: str | None,
) -> None:
    try:
        asyncio.run(
            _run_server_async(
                ready_connection,
                stop_event,
                port=port,
                permit_public_key_bytes=permit_public_key_bytes,
                permit_key_id=permit_key_id,
                fixed_now_iso=fixed_now_iso,
            )
        )
    except Exception as exc:
        try:
            ready_connection.send({"error": type(exc).__name__, "reason": str(exc)})
        except (BrokenPipeError, OSError) as send_error:
            _ = send_error
        raise
    finally:
        ready_connection.close()


@dataclass
class ModbusDeviceProcess:
    process: Any
    stop_event: Any
    info: ModbusDeviceInfo

    def stop(self, timeout_seconds: float = 5.0) -> None:
        self.stop_event.set()
        self.process.join(timeout_seconds)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout_seconds)

    def __enter__(self) -> ModbusDeviceProcess:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.stop()


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def start_modbus_device_process(
    permit_public_key: Ed25519PublicKey,
    *,
    permit_key_id: str = "m3-permit-key-1",
    fixed_now: datetime | None = None,
    readiness_timeout_seconds: float = 20.0,
) -> ModbusDeviceProcess:
    """Start the localhost-only plant/device process and return verified bootstrap metadata."""

    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=False)
    stop_event = context.Event()
    port = _reserve_loopback_port()
    public_raw = permit_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    process = context.Process(
        target=_server_process_main,
        args=(
            child_connection,
            stop_event,
            port,
            public_raw,
            permit_key_id,
            fixed_now.isoformat() if fixed_now is not None else None,
        ),
        name="aegis-ot-m3-modbus-device",
    )
    process.start()
    child_connection.close()
    deadline = time.monotonic() + readiness_timeout_seconds
    while time.monotonic() < deadline and not parent_connection.poll(0.1):
        if not process.is_alive():
            break
    if not parent_connection.poll():
        stop_event.set()
        process.join(1.0)
        if process.is_alive():
            process.terminate()
            process.join(1.0)
        raise ModbusTransportError("virtual Modbus device did not become ready")
    payload = parent_connection.recv()
    parent_connection.close()
    if "error" in payload:
        stop_event.set()
        process.join(1.0)
        raise ModbusTransportError(f"virtual Modbus device failed: {payload}")
    info = ModbusDeviceInfo(**payload)
    return ModbusDeviceProcess(process=process, stop_event=stop_event, info=info)
