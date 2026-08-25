from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from aegis_ot.capability_factory import (
    CapabilityProcessStack,
    CapabilitySeparatedLab,
    CapabilityStartupError,
    RemotePlcProcessHandle,
    _await_ready,
    _observer_info_for_wire,
    _plc_info_from_wire,
    _stop_process,
    start_capability_separated_lab,
)
from aegis_ot.capability_ipc import (
    MAX_ERROR_REASON_CHARS,
    IpcOutcomeUnknownError,
    IpcProtocolError,
    IpcRequestFrame,
    IpcResponseFrame,
    IpcResponseStatus,
    IpcTransportError,
    JsonPipeClient,
    bounded_error_reason,
    decode_frame,
    encode_frame,
    send_response,
)
from aegis_ot.capability_observer import (
    GatewayObserverClient,
    ObserverAdminClient,
    ObserverProcessInfo,
    ObserverServiceError,
    TelemetryObserverClient,
)
from aegis_ot.capability_plant import (
    PlantAdminClient,
    PlantCapabilityError,
    PlantProcessInfo,
    PlcPlantClient,
)
from aegis_ot.capability_plc import (
    GatewayPlcClient,
    PlcAdminClient,
    PlcProcessInfo,
    PlcServiceError,
)
from aegis_ot.crypto import generate_keypair
from aegis_ot.models import Operation
from aegis_ot.pandapower_plant import PhysicalSimulationError
from aegis_ot.physical_models import PhysicalCommandType, PhysicalControlCommand

NOW = datetime(2026, 8, 24, 16, 0, tzinfo=UTC)
BOOT_EPOCH = "service-boot-epoch-0001"


class _AnyPayload(BaseModel):
    value: Any


class _DynamicConnection:
    def __init__(
        self,
        responder: Callable[[IpcRequestFrame, int], bytes] | None = None,
        *,
        send_error: Exception | None = None,
        receive_error: Exception | None = None,
        poll_result: bool = True,
    ) -> None:
        self.responder = responder
        self.send_error = send_error
        self.receive_error = receive_error
        self.poll_result = poll_result
        self.send_count = 0
        self.response: bytes | None = None
        self.closed = False

    def send_bytes(self, payload: bytes) -> None:
        if self.send_error is not None:
            raise self.send_error
        self.send_count += 1
        request = decode_frame(payload, IpcRequestFrame)
        if self.responder is not None:
            self.response = self.responder(request, self.send_count)

    def poll(self, timeout_seconds: float | None = None) -> bool:
        del timeout_seconds
        return self.poll_result

    def recv_bytes(self, maximum: int) -> bytes:
        del maximum
        if self.receive_error is not None:
            raise self.receive_error
        if self.response is None:
            raise EOFError
        return self.response

    def close(self) -> None:
        self.closed = True


class _BrokenResponseConnection:
    def send_bytes(self, payload: bytes) -> None:
        del payload
        raise BrokenPipeError


@dataclass
class _StubResponse:
    status: str
    payload: dict[str, Any]
    error_code: str | None = None


class _StubIpc:
    def __init__(
        self,
        response: _StubResponse | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.calls: list[tuple[str, dict[str, Any], bool]] = []
        self.closed = False

    def request(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        consequential: bool = False,
    ) -> _StubResponse:
        self.calls.append((operation, payload, consequential))
        if self.error is not None:
            raise self.error
        if self.response is None:
            raise AssertionError("stub response was not configured")
        return self.response

    def close(self) -> None:
        self.closed = True


def _response_bytes(
    request: IpcRequestFrame,
    counter: int,
    *,
    fault: str | None = None,
) -> bytes:
    response = IpcResponseFrame.create(
        request,
        status=IpcResponseStatus.OK,
        payload={"accepted": True},
        error_code=None,
        server_boot_epoch=BOOT_EPOCH,
        response_counter=counter,
    )
    if fault == "request_id":
        response = response.model_copy(update={"request_id": "unrelated-request"})
    elif fault == "operation":
        response = response.model_copy(update={"operation": "unrelated-operation"})
    elif fault == "request_payload_digest":
        response = response.model_copy(update={"request_payload_digest": "0" * 64})
    elif fault == "boot_epoch":
        response = response.model_copy(update={"server_boot_epoch": "wrong-boot-epoch-0001"})
    return encode_frame(response)


def _client_with_stub(client_type: type[Any], stub: _StubIpc) -> Any:
    client = object.__new__(client_type)
    client._ipc = stub
    return client


def _plant_info() -> PlantProcessInfo:
    return PlantProcessInfo(
        pid=1001,
        boot_epoch="plant-boot-epoch-0001",
        backend="deterministic-local-v1",
        model_digest="1" * 64,
        simulator_version="test-simulator-v1",
        observation_source_id="test-observer-source",
        capabilities={"admin": ("health",)},
    )


def _observer_info(public_key_bytes: bytes = b"o" * 32) -> ObserverProcessInfo:
    return ObserverProcessInfo(
        pid=1002,
        observer_id="observer:test",
        boot_epoch="observer-boot-epoch-0001",
        key_id="observer-key-v1",
        public_key_bytes=public_key_bytes,
        plant_boot_epoch="plant-boot-epoch-0001",
        capabilities={"admin": ("health",)},
    )


def _plc_wire_payload(**updates: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "pid": 1003,
        "plc_id": "plc:test",
        "boot_epoch": "plc-boot-epoch-0001",
        "key_id": "plc-key-v1",
        "public_key_b64": base64.urlsafe_b64encode(b"p" * 32).decode("ascii"),
        "permit_key_id": "permit-key-v1",
        "plant_boot_epoch": "plant-boot-epoch-0001",
        "observer_boot_epoch": "observer-boot-epoch-0001",
        "capabilities": {"gateway": ["execute", "health"], "ignored": "not-a-list"},
    }
    payload.update(updates)
    return payload


def test_ipc_encoding_and_validation_reject_noncanonical_or_unbounded_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_noncanonical_json(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise ValueError("noncanonical value")

    monkeypatch.setattr("aegis_ot.capability_ipc.json.dumps", reject_noncanonical_json)
    with pytest.raises(IpcProtocolError, match="cannot be encoded"):
        encode_frame(_AnyPayload(value="unencodable"))
    monkeypatch.undo()

    with pytest.raises(IpcProtocolError, match="root must be an object"):
        decode_frame(b"[]", IpcRequestFrame)

    request = IpcRequestFrame.create("health", {})
    response = IpcResponseFrame.create(
        request,
        status=IpcResponseStatus.OK,
        payload={},
        error_code=None,
        server_boot_epoch=BOOT_EPOCH,
        response_counter=1,
    )
    invalid = response.model_dump(mode="json")
    invalid["payload_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="payload digest is inconsistent"):
        IpcResponseFrame.model_validate(invalid)

    long_reason = bounded_error_reason(RuntimeError("x" * (MAX_ERROR_REASON_CHARS + 100)))
    assert long_reason == "x" * MAX_ERROR_REASON_CHARS

    with pytest.raises(ValueError, match="timeout must be positive"):
        JsonPipeClient(object(), expected_boot_epoch=BOOT_EPOCH, timeout_seconds=0)


@pytest.mark.parametrize("consequential", [False, True])
@pytest.mark.parametrize("stage", ["send", "receive"])
def test_json_pipe_client_classifies_peer_loss_by_dispatch_consequence(
    stage: str,
    consequential: bool,
) -> None:
    connection = _DynamicConnection(
        lambda request, counter: _response_bytes(request, counter),
        send_error=OSError("send failed") if stage == "send" else None,
        receive_error=EOFError() if stage == "receive" else None,
    )
    client = JsonPipeClient(connection, expected_boot_epoch=BOOT_EPOCH)
    expected = IpcOutcomeUnknownError if consequential else IpcTransportError

    with pytest.raises(expected):
        client.request("execute", {}, consequential=consequential)

    assert connection.closed
    assert client.request_counts.get("execute", 0) == (0 if stage == "send" else 1)


@pytest.mark.parametrize("consequential", [False, True])
@pytest.mark.parametrize(
    "fault",
    ["malformed", "request_id", "operation", "request_payload_digest", "boot_epoch"],
)
def test_json_pipe_client_rejects_untrusted_responses_and_closes_endpoint(
    fault: str,
    consequential: bool,
) -> None:
    def responder(request: IpcRequestFrame, counter: int) -> bytes:
        if fault == "malformed":
            return b"{}"
        return _response_bytes(request, counter, fault=fault)

    connection = _DynamicConnection(responder)
    client = JsonPipeClient(connection, expected_boot_epoch=BOOT_EPOCH)
    expected = IpcOutcomeUnknownError if consequential else IpcProtocolError

    with pytest.raises(expected):
        client.request("execute", {"sequence": 1}, consequential=consequential)

    assert connection.closed
    with pytest.raises(IpcTransportError, match="closed"):
        client.request("health", {})


@pytest.mark.parametrize("consequential", [False, True])
def test_json_pipe_client_rejects_replayed_response_counter(
    consequential: bool,
) -> None:
    connection = _DynamicConnection(lambda request, counter: _response_bytes(request, 1))
    client = JsonPipeClient(connection, expected_boot_epoch=BOOT_EPOCH)
    assert client.request("health", {}).response_counter == 1
    expected = IpcOutcomeUnknownError if consequential else IpcProtocolError

    with pytest.raises(expected, match="counter did not advance"):
        client.request("health", {}, consequential=consequential)

    assert connection.closed


def test_send_response_normalizes_a_closed_response_endpoint() -> None:
    request = IpcRequestFrame.create("health", {})
    response = IpcResponseFrame.create(
        request,
        status=IpcResponseStatus.OK,
        payload={},
        error_code=None,
        server_boot_epoch=BOOT_EPOCH,
        response_counter=1,
    )
    with pytest.raises(IpcTransportError, match="response endpoint closed"):
        send_response(_BrokenResponseConnection(), response)


def test_observer_clients_normalize_rejection_and_malformed_observations() -> None:
    rejected = _StubIpc(_StubResponse(IpcResponseStatus.REJECTED, {}, "observation_not_found"))
    admin = _client_with_stub(ObserverAdminClient, rejected)
    with pytest.raises(ObserverServiceError, match="observation_not_found"):
        admin.health()

    invalid = _StubResponse(IpcResponseStatus.OK, {})
    telemetry = _client_with_stub(TelemetryObserverClient, _StubIpc(invalid))
    with pytest.raises(ObserverServiceError, match="invalid observation"):
        telemetry.capture_pre(correlation_id="correlation", challenge_nonce="challenge")

    gateway = _client_with_stub(GatewayObserverClient, _StubIpc(invalid))
    with pytest.raises(ObserverServiceError, match="invalid observation"):
        gateway.resolve(observation_id="observation", envelope_digest="0" * 64)

    gateway = _client_with_stub(GatewayObserverClient, _StubIpc(invalid))
    with pytest.raises(ObserverServiceError, match="invalid observation"):
        gateway.capture_post(
            correlation_id="correlation",
            challenge_nonce="challenge",
            previous_envelope_digest="0" * 64,
            permit_id="permit",
            command_digest="1" * 64,
            plc_acknowledgment_digest="2" * 64,
        )


def test_service_admin_shutdowns_are_idempotent_when_transport_is_gone() -> None:
    observer_stub = _StubIpc(error=IpcTransportError("closed"))
    _client_with_stub(ObserverAdminClient, observer_stub).shutdown()
    plant_stub = _StubIpc(error=PlantCapabilityError("already stopped"))
    _client_with_stub(PlantAdminClient, plant_stub).shutdown()
    plc_stub = _StubIpc(error=PlcServiceError("already stopped"))
    _client_with_stub(PlcAdminClient, plc_stub).shutdown()

    assert observer_stub.calls[0][0] == "shutdown"
    assert plant_stub.calls[0][0] == "shutdown"
    assert plc_stub.calls[0][0] == "shutdown"


def test_plant_and_plc_clients_normalize_service_failures() -> None:
    rejected_plant = _client_with_stub(
        PlantAdminClient,
        _StubIpc(_StubResponse(IpcResponseStatus.REJECTED, {}, "capability_denied")),
    )
    with pytest.raises(PlantCapabilityError, match="capability_denied"):
        rejected_plant.health()

    rejected_plc = _client_with_stub(
        PlcAdminClient,
        _StubIpc(_StubResponse(IpcResponseStatus.REJECTED, {}, "device_rejected")),
    )
    with pytest.raises(PlcServiceError, match="device_rejected"):
        rejected_plc.health()

    malformed_plc = _client_with_stub(
        GatewayPlcClient,
        _StubIpc(_StubResponse(IpcResponseStatus.OK, {})),
    )
    placeholder = SimpleNamespace(model_dump=lambda **kwargs: {})
    with pytest.raises(PlcServiceError, match="invalid acknowledgment"):
        malformed_plc.execute(
            request=placeholder,
            permit=placeholder,
            pre_observation=placeholder,
            decision=placeholder,
            assessment=placeholder,
        )


@pytest.mark.parametrize(
    ("response", "expected", "match"),
    [
        (
            _StubResponse(IpcResponseStatus.ERROR, {}, "plant_internal_error"),
            IpcOutcomeUnknownError,
            "internal error",
        ),
        (
            _StubResponse(
                IpcResponseStatus.REJECTED,
                {"reason": "precommit_state_digest_changed"},
                "physical_simulation_rejected",
            ),
            PhysicalSimulationError,
            "precommit_state_digest_changed",
        ),
        (
            _StubResponse(IpcResponseStatus.OK, {}),
            IpcOutcomeUnknownError,
            "invalid committed-state",
        ),
    ],
)
def test_consequential_plant_apply_never_leaks_ambiguous_response_errors(
    response: _StubResponse,
    expected: type[Exception],
    match: str,
) -> None:
    client = _client_with_stub(PlcPlantClient, _StubIpc(response))
    command = PhysicalControlCommand(
        proposal_id="edge-proposal",
        operation=Operation.ISOLATE_ASSET,
        resource="feeder-1",
        command_type=PhysicalCommandType.SET_LINE_SERVICE,
        target="Line 5-6",
        target_index=4,
        setpoint=0.0,
        unit="boolean",
    )
    with pytest.raises(expected, match=match):
        client.apply_authorized_command(command)


class _ReadyConnection:
    def __init__(self, payload: Any = None, *, available: bool = True) -> None:
        self.payload = payload
        self.available = available

    def poll(self, timeout_seconds: float | None = None) -> bool:
        del timeout_seconds
        return self.available

    def recv(self) -> Any:
        return self.payload


class _Process:
    def __init__(self, *, alive: bool) -> None:
        self.alive = alive
        self.join_calls: list[float] = []
        self.terminated = False
        self.killed = False

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout_seconds: float) -> None:
        self.join_calls.append(timeout_seconds)

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True
        self.alive = False


def test_readiness_validation_rejects_dead_invalid_and_failed_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("aegis_ot.capability_factory.time.monotonic", lambda: 0.0)
    with pytest.raises(CapabilityStartupError, match="did not become ready"):
        _await_ready(
            _Process(alive=False),
            _ReadyConnection(available=False),
            label="test service",
            timeout_seconds=1.0,
        )

    with pytest.raises(CapabilityStartupError, match="invalid readiness metadata"):
        _await_ready(
            _Process(alive=True),
            _ReadyConnection("not-a-dict"),
            label="test service",
            timeout_seconds=0.0,
        )

    with pytest.raises(CapabilityStartupError, match="failed during startup"):
        _await_ready(
            _Process(alive=True),
            _ReadyConnection({"error": "startup failed"}),
            label="test service",
            timeout_seconds=0.0,
        )

    assert (
        _await_ready(
            _Process(alive=True),
            _ReadyConnection({"status": "ready"}),
            label="test service",
            timeout_seconds=0.0,
        )["status"]
        == "ready"
    )


def test_stop_process_escalates_from_terminate_to_kill() -> None:
    process = _Process(alive=True)
    _stop_process(process, timeout_seconds=0.25)
    assert process.join_calls == [0.25, 2.0, 2.0]
    assert process.terminated
    assert process.killed


def test_readiness_key_normalization_is_strict() -> None:
    invalid_observer = _observer_info()
    object.__setattr__(invalid_observer, "public_key_bytes", "not-bytes")
    with pytest.raises(CapabilityStartupError, match="observer readiness key is invalid"):
        _observer_info_for_wire(invalid_observer)

    with pytest.raises(CapabilityStartupError, match="key is missing"):
        _plc_info_from_wire(_plc_wire_payload(public_key_b64=None))
    with pytest.raises(CapabilityStartupError, match="key is invalid"):
        _plc_info_from_wire(_plc_wire_payload(public_key_b64="%%%"))
    with pytest.raises(CapabilityStartupError, match="invalid length"):
        _plc_info_from_wire(
            _plc_wire_payload(public_key_b64=base64.urlsafe_b64encode(b"short").decode())
        )
    with pytest.raises(CapabilityStartupError, match="capabilities are invalid"):
        _plc_info_from_wire(_plc_wire_payload(capabilities=[]))

    info = _plc_info_from_wire(_plc_wire_payload())
    assert isinstance(info, PlcProcessInfo)
    assert info.public_key_bytes == b"p" * 32
    assert info.capabilities == {"gateway": ("execute", "health")}


class _HealthAdmin:
    def __init__(self, health: Any = None, *, error: Exception | None = None) -> None:
        self._health = health
        self._error = error

    def health(self) -> Any:
        if self._error is not None:
            raise self._error
        return self._health


def test_remote_plc_liveness_requires_a_matching_typed_plant_record() -> None:
    assert not RemotePlcProcessHandle(7, _HealthAdmin(error=RuntimeError("gone"))).is_alive()
    assert not RemotePlcProcessHandle(7, _HealthAdmin({"plc_processes": []})).is_alive()
    assert not RemotePlcProcessHandle(
        7,
        _HealthAdmin({"plc_processes": {"bad": "record", "other": {"pid": 8}}}),
    ).is_alive()
    assert RemotePlcProcessHandle(
        7,
        _HealthAdmin({"plc_processes": {"active": {"pid": 7, "alive": True}}}),
    ).is_alive()
    assert not RemotePlcProcessHandle(
        7,
        _HealthAdmin({"plc_processes": {"active": {"pid": 7, "alive": False}}}),
    ).is_alive()


class _Recorder:
    def __init__(self, name: str, events: list[str], *, fail_shutdown: bool = False) -> None:
        self.name = name
        self.events = events
        self.fail_shutdown = fail_shutdown

    def shutdown(self) -> None:
        self.events.append(f"{self.name}.shutdown")
        if self.fail_shutdown:
            raise RuntimeError(f"{self.name} shutdown failed")

    def close(self) -> None:
        self.events.append(f"{self.name}.close")


class _StoppedProcess:
    def __init__(self, name: str, events: list[str]) -> None:
        self.name = name
        self.events = events

    def join(self, timeout_seconds: float) -> None:
        self.events.append(f"{self.name}.join:{timeout_seconds}")

    def is_alive(self) -> bool:
        return False


def _stack_for_cleanup(tmp_path: Path, events: list[str]) -> CapabilityProcessStack:
    stack = object.__new__(CapabilityProcessStack)
    stack.closed = False
    stack.plc_admin = _Recorder("plc_admin", events, fail_shutdown=True)
    stack.plc_gateway = _Recorder("plc_gateway", events)
    stack.replacement_plc_admin_connection = _Recorder("replacement_admin", events)
    stack.replacement_plc_gateway_connection = _Recorder("replacement_gateway", events)
    stack.observer_admin = _Recorder("observer_admin", events)
    stack.observer_gateway = _Recorder("observer_gateway", events)
    stack.telemetry = _Recorder("telemetry", events)
    stack.observer_process = _StoppedProcess("observer", events)
    stack.simulator = _Recorder("simulator", events)
    stack.plant_admin = _Recorder("plant_admin", events)
    stack.plant_process = _StoppedProcess("plant", events)
    stack.replay_directory = tmp_path / "replay-ledger"
    stack.replay_directory.mkdir()
    return stack


def test_process_stack_cleanup_is_best_effort_and_reports_aggregated_failure(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    stack = _stack_for_cleanup(tmp_path, events)

    with pytest.raises(RuntimeError, match="cleanup had 1 failure") as caught:
        stack.close()

    assert isinstance(caught.value.__cause__, RuntimeError)
    assert stack.closed
    assert stack.replacement_plc_admin_connection is None
    assert stack.replacement_plc_gateway_connection is None
    assert not stack.replay_directory.exists()
    assert "observer_admin.shutdown" in events
    assert "plant_admin.shutdown" in events
    before = list(events)
    stack.close()
    assert events == before


def test_process_stack_preserves_externally_owned_replay_directory(tmp_path: Path) -> None:
    events: list[str] = []
    stack = _stack_for_cleanup(tmp_path, events)
    stack.owns_replay_directory = False

    with pytest.raises(RuntimeError, match="cleanup had 1 failure"):
        stack.close()

    assert stack.replay_directory.is_dir()


def test_process_stack_restart_guards_closed_consumed_and_stuck_plc() -> None:
    closed = object.__new__(CapabilityProcessStack)
    closed.closed = True
    with pytest.raises(RuntimeError, match="stack is closed"):
        closed.restart_plc()

    consumed = object.__new__(CapabilityProcessStack)
    consumed.closed = False
    consumed.replacement_plc_admin_connection = None
    consumed.replacement_plc_gateway_connection = None
    with pytest.raises(RuntimeError, match="already been consumed"):
        consumed.restart_plc()

    events: list[str] = []
    stuck = object.__new__(CapabilityProcessStack)
    stuck.closed = False
    stuck.replacement_plc_admin_connection = _Recorder("replacement_admin", events)
    stuck.replacement_plc_gateway_connection = _Recorder("replacement_gateway", events)
    stuck.plc_admin = _Recorder("plc_admin", events)
    stuck.plc_gateway = _Recorder("plc_gateway", events)
    stuck.plc_process = _Process(alive=True)
    with pytest.raises(CapabilityStartupError, match="did not stop"):
        stuck.restart_plc(timeout_seconds=0.0)


def test_lab_startup_failure_preserves_primary_error_and_cleanup_failure_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenTelemetry:
        def capture_pre(self, **kwargs: Any) -> None:
            del kwargs
            raise ValueError("initial observation failed")

    class _BrokenStack:
        telemetry = _BrokenTelemetry()

        def close(self) -> None:
            raise RuntimeError("cleanup failed")

    permit_private, permit_public = generate_keypair()
    monkeypatch.setattr(
        "aegis_ot.capability_factory.start_capability_process_stack",
        lambda **kwargs: (_BrokenStack(), permit_private, permit_public),
    )

    with pytest.raises(ValueError, match="initial observation failed") as caught:
        start_capability_separated_lab(NOW)

    assert caught.value.__notes__ == ["capability lab cleanup also failed: cleanup failed"]


@pytest.fixture(scope="module")
def service_lab() -> Iterator[CapabilitySeparatedLab]:
    lab = start_capability_separated_lab(NOW)
    try:
        yield lab
    finally:
        lab.close()


def test_live_services_reject_invalid_handler_requests_without_losing_health(
    service_lab: CapabilitySeparatedLab,
) -> None:
    stack = service_lab.processes

    with pytest.raises(ObserverServiceError, match="observation_not_found"):
        stack.observer_gateway.resolve(
            observation_id="unknown-observation",
            envelope_digest="0" * 64,
        )
    invalid_pre = stack.telemetry._ipc.request("capture_pre", {})
    assert invalid_pre.status == IpcResponseStatus.REJECTED
    assert invalid_pre.error_code == "invalid_payload"
    invalid_post = stack.observer_gateway._ipc.request(
        "capture_post",
        {
            "correlation_id": "unbound-correlation",
            "challenge_nonce": "challenge",
            "previous_envelope_digest": "0" * 64,
            "permit_id": "permit",
            "command_digest": "1" * 64,
            "plc_acknowledgment_digest": "2" * 64,
        },
    )
    assert invalid_post.status == IpcResponseStatus.REJECTED
    assert invalid_post.error_code == "invalid_payload"

    duplicate_configuration = stack.plant_admin._ipc.request("configure_plc", {})
    assert duplicate_configuration.status == IpcResponseStatus.REJECTED
    assert duplicate_configuration.error_code == "invalid_payload"
    invalid_simulation = stack.simulator._ipc.request("simulate_candidate", {})
    assert invalid_simulation.status == IpcResponseStatus.REJECTED
    assert invalid_simulation.error_code == "invalid_payload"
    wrong_target = PhysicalControlCommand(
        proposal_id="wrong-target-proposal",
        operation=Operation.ISOLATE_ASSET,
        resource="feeder-1",
        command_type=PhysicalCommandType.SET_LINE_SERVICE,
        target="Line 5-6",
        target_index=999,
        setpoint=0.0,
        unit="boolean",
    )
    physical_rejection = stack.simulator._ipc.request(
        "simulate_candidate",
        {"command": wrong_target.model_dump(mode="json")},
    )
    assert physical_rejection.status == IpcResponseStatus.REJECTED
    assert physical_rejection.error_code == "physical_simulation_rejected"

    denied_execute = stack.plc_admin._ipc.request("execute", {})
    assert denied_execute.status == IpcResponseStatus.REJECTED
    assert denied_execute.error_code == "capability_denied"
    invalid_execute = stack.plc_gateway._ipc.request("execute", {})
    assert invalid_execute.status == IpcResponseStatus.REJECTED
    assert invalid_execute.error_code == "invalid_payload"

    assert stack.observer_admin.health()["status"] == "ready"
    assert stack.plant_admin.health()["status"] == "ready"
    assert stack.plc_admin.health()["status"] == "ready"
