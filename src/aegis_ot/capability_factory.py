"""Construction and lifecycle for the bounded capability-separated local lab."""

from __future__ import annotations

import base64
import binascii
import multiprocessing
import secrets
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .capability_control import (
    CapabilityClosedLoopController,
    CapabilityPermitIssuer,
    SignedObservationVerifier,
)
from .capability_models import CapabilityActionRequest, SignedObservationEnvelope
from .capability_observer import (
    GatewayObserverClient,
    ObserverAdminClient,
    ObserverProcessInfo,
    TelemetryObserverClient,
    _observer_process_main,
)
from .capability_plant import (
    PlantAdminClient,
    PlantProcessInfo,
    SimulationPlantClient,
    _plant_process_main,
)
from .capability_plc import (
    GatewayPlcClient,
    PlcAdminClient,
    PlcProcessInfo,
)
from .crypto import generate_keypair
from .factory import LocalLab, build_local_lab
from .models import ActionProposal
from .physical_control import ExecutionPermitIssuer, TrustedCommandTranslator, utc_now
from .safety import SafetyKernel, SafetyLimits


class CapabilityStartupError(RuntimeError):
    """A required child process did not produce valid readiness metadata."""


def _await_ready(
    process: Any,
    connection: Any,
    *,
    label: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline and not connection.poll(0.1):
        if not process.is_alive():
            break
    if not connection.poll():
        raise CapabilityStartupError(f"{label} did not become ready")
    payload = connection.recv()
    if not isinstance(payload, dict):
        raise CapabilityStartupError(f"{label} returned invalid readiness metadata")
    if "error" in payload:
        raise CapabilityStartupError(f"{label} failed during startup: {payload}")
    return payload


def _stop_process(process: Any, timeout_seconds: float = 5.0) -> None:
    process.join(timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join(2.0)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(2.0)


def _observer_info_for_wire(info: ObserverProcessInfo) -> dict[str, Any]:
    payload = asdict(info)
    public_key_bytes = payload.pop("public_key_bytes")
    if not isinstance(public_key_bytes, bytes):
        raise CapabilityStartupError("observer readiness key is invalid")
    payload["public_key_b64"] = base64.urlsafe_b64encode(public_key_bytes).decode("ascii")
    return payload


def _plc_info_from_wire(payload: dict[str, Any]) -> PlcProcessInfo:
    normalized = dict(payload)
    encoded_key = normalized.pop("public_key_b64", None)
    if not isinstance(encoded_key, str):
        raise CapabilityStartupError("PLC readiness key is missing")
    try:
        public_key_bytes = base64.b64decode(
            encoded_key,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise CapabilityStartupError("PLC readiness key is invalid") from exc
    if len(public_key_bytes) != 32:
        raise CapabilityStartupError("PLC readiness key has an invalid length")
    capabilities = normalized.get("capabilities")
    if not isinstance(capabilities, dict):
        raise CapabilityStartupError("PLC readiness capabilities are invalid")
    normalized["capabilities"] = {
        str(role): tuple(str(operation) for operation in operations)
        for role, operations in capabilities.items()
        if isinstance(operations, (list, tuple))
    }
    normalized["public_key_bytes"] = public_key_bytes
    return PlcProcessInfo(**normalized)


@dataclass(frozen=True)
class RemotePlcProcessHandle:
    """Read-only process liveness view exposed through the plant supervisor."""

    pid: int
    plant_admin: PlantAdminClient

    def is_alive(self) -> bool:
        try:
            health = self.plant_admin.health()
        except Exception:
            return False
        process_records = health.get("plc_processes")
        if not isinstance(process_records, dict):
            return False
        for record in process_records.values():
            if not isinstance(record, dict):
                continue
            if record.get("pid") == self.pid:
                return record.get("alive") is True
        return False


@dataclass
class CapabilityProcessStack:
    context: Any
    plant_process: Any
    observer_process: Any
    plc_process: Any
    plant_info: PlantProcessInfo
    observer_info: ObserverProcessInfo
    plc_info: PlcProcessInfo
    plant_admin: PlantAdminClient
    simulator: SimulationPlantClient
    observer_admin: ObserverAdminClient
    telemetry: TelemetryObserverClient
    observer_gateway: GatewayObserverClient
    plc_admin: PlcAdminClient
    plc_gateway: GatewayPlcClient
    permit_public_key_bytes: bytes
    permit_key_id: str
    replay_ledger_path: Path
    fixed_now_iso: str | None
    replacement_plc_admin_connection: Any | None
    replacement_plc_gateway_connection: Any | None
    replay_directory: Path
    closed: bool = False

    def restart_plc(self, timeout_seconds: float = 20.0) -> PlcProcessInfo:
        """Replace the PLC child once while retaining its local replay reservations."""

        if self.closed:
            raise RuntimeError("capability process stack is closed")
        if (
            self.replacement_plc_admin_connection is None
            or self.replacement_plc_gateway_connection is None
        ):
            raise RuntimeError("the preallocated PLC restart capability has already been consumed")
        self.plc_admin.shutdown()
        self.plc_gateway.close()
        self.plc_admin.close()
        deadline = time.monotonic() + timeout_seconds
        while self.plc_process.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if self.plc_process.is_alive():
            raise CapabilityStartupError("active virtual PLC did not stop before replacement")

        payload = self.plant_admin.spawn_replacement_plc()
        info = _plc_info_from_wire(payload)
        admin_connection = self.replacement_plc_admin_connection
        gateway_connection = self.replacement_plc_gateway_connection
        self.replacement_plc_admin_connection = None
        self.replacement_plc_gateway_connection = None
        self.plc_process = RemotePlcProcessHandle(info.pid, self.plant_admin)
        self.plc_info = info
        self.plc_admin = PlcAdminClient(admin_connection, info)
        self.plc_gateway = GatewayPlcClient(gateway_connection, info)
        return info

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        failures: list[Exception] = []

        def attempt(operation: Any) -> None:
            try:
                operation()
            except Exception as exc:
                failures.append(exc)

        attempt(self.plc_admin.shutdown)
        attempt(self.plc_gateway.close)
        attempt(self.plc_admin.close)
        if self.replacement_plc_admin_connection is not None:
            attempt(self.replacement_plc_admin_connection.close)
            self.replacement_plc_admin_connection = None
        if self.replacement_plc_gateway_connection is not None:
            attempt(self.replacement_plc_gateway_connection.close)
            self.replacement_plc_gateway_connection = None
        attempt(self.observer_admin.shutdown)
        attempt(self.observer_gateway.close)
        attempt(self.telemetry.close)
        attempt(self.observer_admin.close)
        attempt(lambda: _stop_process(self.observer_process))
        attempt(self.simulator.close)
        attempt(self.plant_admin.shutdown)
        attempt(self.plant_admin.close)
        attempt(lambda: _stop_process(self.plant_process))
        shutil.rmtree(self.replay_directory, ignore_errors=True)
        if failures:
            raise RuntimeError(
                f"capability process stack cleanup had {len(failures)} failure(s)"
            ) from failures[0]


def start_capability_process_stack(
    *,
    fixed_now: datetime | None = None,
    readiness_timeout_seconds: float = 20.0,
    observer_post_snapshot_source: Literal["plant", "predecessor"] = "plant",
) -> tuple[CapabilityProcessStack, Ed25519PrivateKey, Ed25519PublicKey]:
    """Start plant, observer, and virtual-PLC children with dedicated pipe capabilities."""

    context = multiprocessing.get_context("spawn")
    permit_private, permit_public = generate_keypair()
    permit_public_raw = permit_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    permit_key_id = "capability-permit-key-v1"
    replay_directory = Path(tempfile.mkdtemp(prefix="aegis-ot-capability-replay-"))
    replay_path = replay_directory / "plc-replay-ledger.json"
    fixed_now_iso = fixed_now.isoformat() if fixed_now is not None else None

    plant_admin_parent, plant_admin_child = context.Pipe(duplex=True)
    observer_plant_parent, observer_plant_child = context.Pipe(duplex=True)
    simulation_parent, simulation_child = context.Pipe(duplex=True)
    plc_admin_parent, plc_admin_service = context.Pipe(duplex=True)
    plc_gateway_parent, plc_gateway_service = context.Pipe(duplex=True)
    replacement_plc_admin_parent, replacement_plc_admin_service = context.Pipe(
        duplex=True
    )
    replacement_plc_gateway_parent, replacement_plc_gateway_service = context.Pipe(
        duplex=True
    )
    plant_ready_parent, plant_ready_child = context.Pipe(duplex=False)
    plant_process = context.Process(
        target=_plant_process_main,
        args=(
            plant_ready_child,
            plant_admin_child,
            observer_plant_child,
            simulation_child,
            plc_admin_service,
            plc_gateway_service,
            replacement_plc_admin_service,
            replacement_plc_gateway_service,
            fixed_now_iso,
        ),
        name="aegis-ot-capability-plant",
    )
    plant_process.start()
    plant_ready_child.close()
    plant_admin_child.close()
    observer_plant_child.close()
    simulation_child.close()
    plc_admin_service.close()
    plc_gateway_service.close()
    replacement_plc_admin_service.close()
    replacement_plc_gateway_service.close()
    try:
        plant_payload = _await_ready(
            plant_process,
            plant_ready_parent,
            label="plant process",
            timeout_seconds=readiness_timeout_seconds,
        )
    except Exception:
        plc_admin_parent.close()
        plc_gateway_parent.close()
        replacement_plc_admin_parent.close()
        replacement_plc_gateway_parent.close()
        plant_process.terminate()
        _stop_process(plant_process)
        shutil.rmtree(replay_directory, ignore_errors=True)
        raise
    finally:
        plant_ready_parent.close()
    plant_info = PlantProcessInfo(**plant_payload)
    plant_admin = PlantAdminClient(plant_admin_parent, plant_info)
    simulator = SimulationPlantClient(simulation_parent, plant_info)

    observer_admin_parent, observer_admin_child = context.Pipe(duplex=True)
    telemetry_parent, telemetry_child = context.Pipe(duplex=True)
    observer_gateway_parent, observer_gateway_child = context.Pipe(duplex=True)
    observer_ready_parent, observer_ready_child = context.Pipe(duplex=False)
    observer_process = context.Process(
        target=_observer_process_main,
        args=(
            observer_ready_child,
            observer_admin_child,
            telemetry_child,
            observer_gateway_child,
            observer_plant_parent,
            asdict(plant_info),
            None,
            observer_post_snapshot_source,
        ),
        name="aegis-ot-capability-observer",
    )
    observer_process.start()
    observer_ready_child.close()
    observer_admin_child.close()
    telemetry_child.close()
    observer_gateway_child.close()
    observer_plant_parent.close()
    try:
        observer_payload = _await_ready(
            observer_process,
            observer_ready_parent,
            label="signed observer",
            timeout_seconds=readiness_timeout_seconds,
        )
    except Exception:
        plc_admin_parent.close()
        plc_gateway_parent.close()
        replacement_plc_admin_parent.close()
        replacement_plc_gateway_parent.close()
        observer_process.terminate()
        _stop_process(observer_process)
        simulator.close()
        plant_admin.shutdown()
        plant_admin.close()
        _stop_process(plant_process)
        shutil.rmtree(replay_directory, ignore_errors=True)
        raise
    finally:
        observer_ready_parent.close()
    observer_info = ObserverProcessInfo(**observer_payload)
    observer_admin = ObserverAdminClient(observer_admin_parent, observer_info)
    telemetry = TelemetryObserverClient(telemetry_parent, observer_info)
    observer_gateway = GatewayObserverClient(observer_gateway_parent, observer_info)

    try:
        plc_payload = plant_admin.configure_plc(
            observer_info=_observer_info_for_wire(observer_info),
            permit_public_key_bytes=permit_public_raw,
            permit_key_id=permit_key_id,
            replay_ledger_path=str(replay_path),
        )
        plc_info = _plc_info_from_wire(plc_payload)
    except Exception:
        plc_admin_parent.close()
        plc_gateway_parent.close()
        replacement_plc_admin_parent.close()
        replacement_plc_gateway_parent.close()
        observer_admin.shutdown()
        observer_gateway.close()
        telemetry.close()
        observer_admin.close()
        _stop_process(observer_process)
        simulator.close()
        plant_admin.shutdown()
        plant_admin.close()
        _stop_process(plant_process)
        shutil.rmtree(replay_directory, ignore_errors=True)
        raise
    stack = CapabilityProcessStack(
        context=context,
        plant_process=plant_process,
        observer_process=observer_process,
        plc_process=RemotePlcProcessHandle(plc_info.pid, plant_admin),
        plant_info=plant_info,
        observer_info=observer_info,
        plc_info=plc_info,
        plant_admin=plant_admin,
        simulator=simulator,
        observer_admin=observer_admin,
        telemetry=telemetry,
        observer_gateway=observer_gateway,
        plc_admin=PlcAdminClient(plc_admin_parent, plc_info),
        plc_gateway=GatewayPlcClient(plc_gateway_parent, plc_info),
        permit_public_key_bytes=permit_public_raw,
        permit_key_id=permit_key_id,
        replay_ledger_path=replay_path,
        fixed_now_iso=fixed_now_iso,
        replacement_plc_admin_connection=replacement_plc_admin_parent,
        replacement_plc_gateway_connection=replacement_plc_gateway_parent,
        replay_directory=replay_directory,
    )
    return stack, permit_private, permit_public


@dataclass
class CapabilitySeparatedLab:
    authorization: LocalLab
    controller: CapabilityClosedLoopController
    processes: CapabilityProcessStack
    initial_observation: SignedObservationEnvelope
    permit_public_key: Ed25519PublicKey
    permit_private_key: Ed25519PrivateKey

    @property
    def topology_pids(self) -> dict[str, int]:
        return {
            "coordinator": multiprocessing.current_process().pid or -1,
            "plant": self.processes.plant_info.pid,
            "observer": self.processes.observer_info.pid,
            "plc": self.processes.plc_info.pid,
        }

    def capture_observation(
        self,
        *,
        correlation_id: str | None = None,
        challenge_nonce: str | None = None,
    ) -> SignedObservationEnvelope:
        return self.processes.telemetry.capture_pre(
            correlation_id=correlation_id or str(uuid4()),
            challenge_nonce=challenge_nonce or secrets.token_urlsafe(24),
        )

    @staticmethod
    def request_for(
        proposal: ActionProposal,
        observation: SignedObservationEnvelope,
    ) -> CapabilityActionRequest:
        return CapabilityActionRequest(
            correlation_id=observation.correlation_id,
            proposal=proposal,
            observation_id=observation.observation_id,
            observation_envelope_digest=observation.envelope_digest,
            observation_challenge_nonce=observation.challenge_nonce,
        )

    def restart_plc(self) -> PlcProcessInfo:
        info = self.processes.restart_plc()
        self.controller.plc = self.processes.plc_gateway
        self.controller.plc_info = info
        self.controller.plc_public_key = info.public_key
        self.controller.permit_issuer.rotate_target(info)
        return info

    def close(self) -> None:
        self.processes.close()

    def __enter__(self) -> CapabilitySeparatedLab:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def start_capability_separated_lab(
    now: datetime | None = None,
    *,
    observer_post_snapshot_source: Literal["plant", "predecessor"] = "plant",
) -> CapabilitySeparatedLab:
    """Start the first WP4 process/capability slice for local PyCharm execution."""

    stack, permit_private, permit_public = start_capability_process_stack(
        fixed_now=now,
        observer_post_snapshot_source=observer_post_snapshot_source,
    )
    try:
        initial = stack.telemetry.capture_pre(
            correlation_id=str(uuid4()),
            challenge_nonce=secrets.token_urlsafe(24),
        )
        reference_time = now or initial.snapshot.observed_at
        authorization = build_local_lab(reference_time)
        authorization.gateway.safety = SafetyKernel(
            SafetyLimits(minimum_voltage_pu=0.90, maximum_voltage_pu=1.10),
            version="surrogate-safety-v1-capability-supervisory-limits",
        )
        clock = (lambda: now) if now is not None else utc_now
        base_issuer = ExecutionPermitIssuer(
            permit_private,
            signing_key_id=stack.permit_key_id,
            audience=stack.plc_info.plc_id,
            evidence=authorization.gateway.evidence,
            clock=clock,
        )
        permit_issuer = CapabilityPermitIssuer(base_issuer, permit_private, stack.plc_info)
        observation_verifier = SignedObservationVerifier(
            observer_info=stack.observer_info,
            plant_info=stack.plant_info,
        )
        controller = CapabilityClosedLoopController(
            gateway=authorization.gateway,
            observer=stack.observer_gateway,
            simulator=stack.simulator,
            plc=stack.plc_gateway,
            translator=TrustedCommandTranslator(),
            permit_issuer=permit_issuer,
            observation_verifier=observation_verifier,
            plc_info=stack.plc_info,
            plc_public_key=stack.plc_info.public_key,
            evidence=authorization.gateway.evidence,
            clock=clock,
        )
        return CapabilitySeparatedLab(
            authorization=authorization,
            controller=controller,
            processes=stack,
            initial_observation=initial,
            permit_public_key=permit_public,
            permit_private_key=permit_private,
        )
    except Exception as exc:
        try:
            stack.close()
        except Exception as cleanup_exc:
            exc.add_note(f"capability lab cleanup also failed: {cleanup_exc}")
        raise
