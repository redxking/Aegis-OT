"""Sole-owner plant process and statically allowlisted capability clients."""

from __future__ import annotations

import base64
import multiprocessing
import os
from dataclasses import dataclass
from datetime import datetime
from multiprocessing.connection import wait
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from .capability_ipc import (
    IpcOutcomeUnknownError,
    IpcProtocolError,
    IpcResponseFrame,
    IpcResponseStatus,
    IpcTransportError,
    JsonPipeClient,
    bounded_error_reason,
    receive_request,
    send_response,
)
from .crypto import decode_urlsafe_b64
from .pandapower_plant import PandapowerCigreMVPlant, PhysicalSimulationError
from .physical_models import CandidateAssessment, PhysicalControlCommand, PhysicalStateSnapshot

BACKEND_ID = "deterministic-local-v1"

PLANT_CAPABILITIES: dict[str, frozenset[str]] = {
    "admin": frozenset(
        {"health", "configure_plc", "spawn_replacement_plc", "shutdown"}
    ),
    "observer": frozenset({"health", "capture_state"}),
    "simulation": frozenset({"health", "simulate_candidate"}),
    "plc": frozenset(
        {"health", "read_state", "simulate_candidate", "apply_authorized_command"}
    ),
    "plc_restart": frozenset(
        {"health", "read_state", "simulate_candidate", "apply_authorized_command"}
    ),
}


class PlantCapabilityError(RuntimeError):
    """The dedicated plant endpoint rejected an operation or payload."""


@dataclass(frozen=True)
class PlantProcessInfo:
    pid: int
    boot_epoch: str
    backend: str
    model_digest: str
    simulator_version: str
    observation_source_id: str
    capabilities: dict[str, tuple[str, ...]]


def _plant_process_main(
    ready_connection: Any,
    admin_connection: Any,
    observer_connection: Any,
    simulation_connection: Any,
    plc_admin_connection: Any,
    plc_gateway_connection: Any,
    replacement_plc_admin_connection: Any,
    replacement_plc_gateway_connection: Any,
    fixed_now_iso: str | None,
) -> None:
    boot_epoch = str(uuid4())
    observation_source_id = f"capability-plant:{boot_epoch}"
    fixed_now = datetime.fromisoformat(fixed_now_iso) if fixed_now_iso is not None else None
    clock = (lambda: fixed_now) if fixed_now is not None else None
    response_counter = 0
    apply_requests = 0
    commit_count = 0
    capture_count = 0
    running = True
    plc_configuration: dict[str, Any] | None = None
    plc_processes: dict[str, Any] = {}
    plc_service_endpoints: dict[str, tuple[Any, Any]] = {
        "plc": (plc_admin_connection, plc_gateway_connection),
        "plc_restart": (
            replacement_plc_admin_connection,
            replacement_plc_gateway_connection,
        ),
    }
    endpoints = {
        "admin": admin_connection,
        "observer": observer_connection,
        "simulation": simulation_connection,
    }
    try:
        plant = PandapowerCigreMVPlant(
            observation_clock=clock,
            observation_source_id=observation_source_id,
        )
        plant_info_payload = {
            "pid": os.getpid(),
            "boot_epoch": boot_epoch,
            "backend": BACKEND_ID,
            "model_digest": plant.model_digest,
            "simulator_version": plant.simulator_version,
            "observation_source_id": observation_source_id,
            "capabilities": {
                role: tuple(sorted(operations)) for role, operations in PLANT_CAPABILITIES.items()
            },
        }

        def spawn_plc(role: str) -> dict[str, Any]:
            if plc_configuration is None:
                raise RuntimeError("PLC configuration is unavailable")
            service_connections = plc_service_endpoints.pop(role, None)
            if service_connections is None:
                raise RuntimeError("PLC service capability has already been consumed")
            from .capability_plc import _plc_process_main

            context = multiprocessing.get_context("spawn")
            plant_server, plant_client = context.Pipe(duplex=True)
            ready_parent, ready_child = context.Pipe(duplex=False)
            process = context.Process(
                target=_plc_process_main,
                args=(
                    ready_child,
                    service_connections[0],
                    service_connections[1],
                    plant_client,
                    plant_info_payload,
                    plc_configuration["observer_info"],
                    decode_urlsafe_b64(plc_configuration["permit_public_key_b64"]),
                    plc_configuration["permit_key_id"],
                    plc_configuration["replay_ledger_path"],
                    fixed_now_iso,
                ),
                name=f"aegis-ot-capability-{role}",
            )
            process.start()
            ready_child.close()
            plant_client.close()
            service_connections[0].close()
            service_connections[1].close()
            if not ready_parent.poll(20.0):
                process.terminate()
                process.join(2.0)
                plant_server.close()
                raise RuntimeError(f"{role} did not become ready")
            child_payload = ready_parent.recv()
            ready_parent.close()
            if not isinstance(child_payload, dict) or "error" in child_payload:
                process.terminate()
                process.join(2.0)
                plant_server.close()
                raise RuntimeError(f"{role} failed during startup: {child_payload}")
            public_key_bytes = child_payload.pop("public_key_bytes")
            if not isinstance(public_key_bytes, bytes):
                raise RuntimeError("PLC readiness key is invalid")
            child_payload["public_key_b64"] = base64.urlsafe_b64encode(
                public_key_bytes
            ).decode("ascii")
            endpoints[role] = plant_server
            plc_processes[role] = process
            return child_payload

        ready_connection.send(
            plant_info_payload
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
                if request.operation not in PLANT_CAPABILITIES[role]:
                    status = IpcResponseStatus.REJECTED
                    error_code = "capability_denied"
                    payload = {"role": role, "operation": request.operation}
                else:
                    try:
                        if request.operation == "health":
                            state = plant.read_state()
                            payload = {
                                "status": "ready",
                                "pid": os.getpid(),
                                "backend": BACKEND_ID,
                                "boot_epoch": boot_epoch,
                                "role": role,
                                "capabilities": tuple(sorted(PLANT_CAPABILITIES[role])),
                                "state_version": state.state_version,
                                "state_digest": state.state_digest,
                                "apply_requests": apply_requests,
                                "commit_count": commit_count,
                                "capture_count": capture_count,
                                "plc_processes": {
                                    child_role: {
                                        "pid": child.pid,
                                        "alive": child.is_alive(),
                                    }
                                    for child_role, child in plc_processes.items()
                                },
                            }
                        elif request.operation == "shutdown":
                            payload = {"status": "stopping"}
                            running = False
                        elif request.operation == "configure_plc":
                            if plc_configuration is not None:
                                raise ValueError("PLC configuration is already established")
                            configured_observer = dict(request.payload["observer_info"])
                            configured_observer["public_key_bytes"] = decode_urlsafe_b64(
                                configured_observer.pop("public_key_b64")
                            )
                            plc_configuration = {
                                "observer_info": configured_observer,
                                "permit_public_key_b64": str(
                                    request.payload["permit_public_key_b64"]
                                ),
                                "permit_key_id": str(request.payload["permit_key_id"]),
                                "replay_ledger_path": str(
                                    request.payload["replay_ledger_path"]
                                ),
                            }
                            payload = {"plc": spawn_plc("plc")}
                        elif request.operation == "spawn_replacement_plc":
                            active = plc_processes.get("plc")
                            if active is not None:
                                active.join(5.0)
                                if active.is_alive():
                                    raise RuntimeError("active PLC must stop before replacement")
                            payload = {"plc": spawn_plc("plc_restart")}
                        elif request.operation == "capture_state":
                            capture_count += 1
                            payload = {"state": plant.capture_state().model_dump(mode="json")}
                        elif request.operation == "read_state":
                            payload = {"state": plant.read_state().model_dump(mode="json")}
                        elif request.operation == "simulate_candidate":
                            command = PhysicalControlCommand.model_validate(
                                request.payload["command"]
                            )
                            assessment = plant.simulate_candidate(command)
                            payload = {"assessment": assessment.model_dump(mode="json")}
                        elif request.operation == "apply_authorized_command":
                            command = PhysicalControlCommand.model_validate(
                                request.payload["command"]
                            )
                            apply_requests += 1
                            state = plant.apply_authorized_command(
                                command,
                                expected_pre_state_version=request.payload.get(
                                    "expected_pre_state_version"
                                ),
                                expected_pre_state_digest=request.payload.get(
                                    "expected_pre_state_digest"
                                ),
                                expected_pre_observation_digest=request.payload.get(
                                    "expected_pre_observation_digest"
                                ),
                                expected_post_state_digest=request.payload.get(
                                    "expected_post_state_digest"
                                ),
                                expected_post_topology_digest=request.payload.get(
                                    "expected_post_topology_digest"
                                ),
                            )
                            commit_count += 1
                            payload = {"state": state.model_dump(mode="json")}
                        else:
                            raise IpcProtocolError("unreachable plant operation")
                    except PhysicalSimulationError as exc:
                        status = IpcResponseStatus.REJECTED
                        error_code = "physical_simulation_rejected"
                        payload = {
                            "reason": bounded_error_reason(exc),
                            "error_type": type(exc).__name__,
                        }
                    except (KeyError, TypeError, ValidationError, ValueError) as exc:
                        status = IpcResponseStatus.REJECTED
                        error_code = "invalid_payload"
                        payload = {
                            "reason": bounded_error_reason(exc),
                            "error_type": type(exc).__name__,
                        }
                    except Exception as exc:
                        status = IpcResponseStatus.ERROR
                        error_code = "plant_internal_error"
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
        for process in plc_processes.values():
            process.join(1.0)
            if process.is_alive():
                process.terminate()
                process.join(2.0)
        for connection in endpoints.values():
            connection.close()
        for service_pair in plc_service_endpoints.values():
            service_pair[0].close()
            service_pair[1].close()


class _PlantCapabilityClient:
    def __init__(self, connection: Any, info: PlantProcessInfo) -> None:
        self._ipc = JsonPipeClient(connection, expected_boot_epoch=info.boot_epoch)
        self.info = info

    def _request(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._ipc.request(operation, payload)
        if response.status != IpcResponseStatus.OK:
            reason = str(response.payload.get("reason", response.error_code))
            raise PlantCapabilityError(reason)
        return response.payload

    def health(self) -> dict[str, Any]:
        return self._request("health", {})

    def close(self) -> None:
        self._ipc.close()


class ObserverPlantClient(_PlantCapabilityClient):
    """Read-only plant capability held only by the signed observer child."""

    def capture_state(self) -> PhysicalStateSnapshot:
        payload = self._request("capture_state", {})
        return PhysicalStateSnapshot.model_validate(payload["state"])

    def probe_forbidden_apply(self, command: PhysicalControlCommand) -> str:
        """Return the server decision for the observer's negative capability test."""

        response = self._ipc.request(
            "apply_authorized_command",
            {"command": command.model_dump(mode="json")},
        )
        return str(response.error_code or response.status)


class SimulationPlantClient(_PlantCapabilityClient):
    """Nonmutating candidate-simulation capability retained by the coordinator."""

    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
        payload = self._request(
            "simulate_candidate",
            {"command": command.model_dump(mode="json")},
        )
        return CandidateAssessment.model_validate(payload["assessment"])

    def probe_forbidden_apply(self, command: PhysicalControlCommand) -> str:
        """Return the server decision for a deliberate negative capability test."""

        response = self._ipc.request(
            "apply_authorized_command",
            {"command": command.model_dump(mode="json")},
        )
        return str(response.error_code or response.status)


class PlcPlantClient(_PlantCapabilityClient):
    """Plant control capability passed directly to, and retained only by, the PLC child."""

    def read_state(self) -> PhysicalStateSnapshot:
        payload = self._request("read_state", {})
        return PhysicalStateSnapshot.model_validate(payload["state"])

    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
        payload = self._request(
            "simulate_candidate",
            {"command": command.model_dump(mode="json")},
        )
        return CandidateAssessment.model_validate(payload["assessment"])

    def apply_authorized_command(
        self,
        command: PhysicalControlCommand,
        *,
        expected_pre_state_version: int | None = None,
        expected_pre_state_digest: str | None = None,
        expected_pre_observation_digest: str | None = None,
        expected_post_state_digest: str | None = None,
        expected_post_topology_digest: str | None = None,
    ) -> PhysicalStateSnapshot:
        try:
            response = self._ipc.request(
                "apply_authorized_command",
                {
                    "command": command.model_dump(mode="json"),
                    "expected_pre_state_version": expected_pre_state_version,
                    "expected_pre_state_digest": expected_pre_state_digest,
                    "expected_pre_observation_digest": expected_pre_observation_digest,
                    "expected_post_state_digest": expected_post_state_digest,
                    "expected_post_topology_digest": expected_post_topology_digest,
                },
                consequential=True,
            )
            if response.status == IpcResponseStatus.ERROR:
                raise IpcOutcomeUnknownError("plant apply response reported an internal error")
            if response.status != IpcResponseStatus.OK:
                reason = str(response.payload.get("reason", response.error_code))
                raise PlantCapabilityError(reason)
            payload = response.payload
        except PlantCapabilityError as exc:
            raise PhysicalSimulationError(str(exc)) from exc
        try:
            return PhysicalStateSnapshot.model_validate(payload["state"])
        except (KeyError, TypeError, ValidationError) as exc:
            raise IpcOutcomeUnknownError(
                "plant apply response contained an invalid committed-state payload"
            ) from exc


class PlantAdminClient(_PlantCapabilityClient):
    def probe_forbidden_apply(self, command: PhysicalControlCommand) -> str:
        """Return the admin endpoint decision for a negative capability test."""

        response = self._ipc.request(
            "apply_authorized_command",
            {"command": command.model_dump(mode="json")},
        )
        return str(response.error_code or response.status)

    def configure_plc(
        self,
        *,
        observer_info: dict[str, Any],
        permit_public_key_bytes: bytes,
        permit_key_id: str,
        replay_ledger_path: str,
    ) -> dict[str, Any]:
        payload = self._request(
            "configure_plc",
            {
                "observer_info": observer_info,
                "permit_public_key_b64": base64.urlsafe_b64encode(
                    permit_public_key_bytes
                ).decode("ascii"),
                "permit_key_id": permit_key_id,
                "replay_ledger_path": replay_ledger_path,
            },
        )
        return dict(payload["plc"])

    def spawn_replacement_plc(self) -> dict[str, Any]:
        payload = self._request("spawn_replacement_plc", {})
        return dict(payload["plc"])

    def shutdown(self) -> None:
        try:
            self._request("shutdown", {})
        except (IpcTransportError, PlantCapabilityError):
            pass
