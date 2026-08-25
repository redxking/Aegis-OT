"""Construction and lifecycle helpers for the separate-process M3 Modbus path."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import generate_keypair
from .factory import LocalLab, build_local_lab
from .modbus_device import (
    ModbusDeviceInfo,
    ModbusDeviceProcess,
    ModbusPhysicalDeviceClient,
    start_modbus_device_process,
)
from .physical_control import (
    Clock,
    ExecutionPermitIssuer,
    PhysicalClosedLoopController,
    TrustedCommandTranslator,
    utc_now,
)
from .safety import SafetyKernel, SafetyLimits


@dataclass
class ModbusPhysicalLab:
    authorization: LocalLab
    controller: PhysicalClosedLoopController
    client: ModbusPhysicalDeviceClient
    process: ModbusDeviceProcess
    permit_public_key: Ed25519PublicKey

    @property
    def info(self) -> ModbusDeviceInfo:
        return self.process.info

    def close(self) -> None:
        self.client.close()
        self.process.stop()

    def __enter__(self) -> ModbusPhysicalLab:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def start_modbus_physical_lab(now: datetime | None = None) -> ModbusPhysicalLab:
    """Start a localhost process boundary suitable for PyCharm and controlled M3 runs."""

    permit_private, permit_public = generate_keypair()
    process = start_modbus_device_process(permit_public, fixed_now=now)
    try:
        client = ModbusPhysicalDeviceClient(process.info)
        initial_state = client.read_state()
        reference_time = initial_state.observed_at
        authorization = build_local_lab(reference_time)
        authorization.gateway.safety = SafetyKernel(
            SafetyLimits(minimum_voltage_pu=0.90, maximum_voltage_pu=1.10),
            version="surrogate-safety-v1-m3-supervisory-limits",
        )
        clock: Clock = (lambda: now) if now is not None else utc_now
        permit_issuer = ExecutionPermitIssuer(
            permit_private,
            signing_key_id="m3-permit-key-1",
            audience=process.info.audience,
            evidence=authorization.gateway.evidence,
            clock=clock,
        )
        controller = PhysicalClosedLoopController(
            gateway=authorization.gateway,
            plant=client,
            translator=TrustedCommandTranslator(),
            permit_issuer=permit_issuer,
            control_device=client,
            evidence=authorization.gateway.evidence,
            acknowledgment_public_key=client.acknowledgment_public_key,
            clock=clock,
        )
        return ModbusPhysicalLab(
            authorization=authorization,
            controller=controller,
            client=client,
            process=process,
            permit_public_key=permit_public,
        )
    except Exception:
        process.stop()
        raise
