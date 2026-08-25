"""Local construction of the optional M3 physical-simulation stack."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import generate_keypair
from .factory import LocalLab, build_local_lab
from .pandapower_plant import PandapowerCigreMVPlant
from .physical_control import (
    ExecutionPermitIssuer,
    PermitAwareVirtualControlDevice,
    PhysicalClosedLoopController,
    TrustedCommandTranslator,
)
from .safety import SafetyKernel, SafetyLimits


@dataclass(frozen=True)
class PhysicalLocalLab:
    authorization: LocalLab
    plant: PandapowerCigreMVPlant
    controller: PhysicalClosedLoopController
    control_device: PermitAwareVirtualControlDevice
    permit_public_key: Ed25519PublicKey
    acknowledgment_public_key: Ed25519PublicKey


def build_physical_local_lab(now: datetime | None = None) -> PhysicalLocalLab:
    """Construct the M3 steady-state/virtual-device path for local PyCharm runs."""

    reference_time = now or datetime.now(UTC)
    clock = (lambda: reference_time) if now is not None else (lambda: datetime.now(UTC))
    authorization = build_local_lab(reference_time)
    authorization.gateway.safety = SafetyKernel(
        SafetyLimits(minimum_voltage_pu=0.90, maximum_voltage_pu=1.10),
        version="surrogate-safety-v1-m3-supervisory-limits",
    )
    plant = PandapowerCigreMVPlant(observed_at=reference_time)
    permit_private, permit_public = generate_keypair()
    acknowledgment_private, acknowledgment_public = generate_keypair()
    audience = "virtual-control-device:m3"
    permit_issuer = ExecutionPermitIssuer(
        permit_private,
        signing_key_id="m3-permit-key-1",
        audience=audience,
        evidence=authorization.gateway.evidence,
        clock=clock,
    )
    control_device = PermitAwareVirtualControlDevice(
        plant,
        device_id=audience,
        permit_audience=audience,
        permit_public_keys={"m3-permit-key-1": permit_public},
        acknowledgment_private_key=acknowledgment_private,
        acknowledgment_key_id="m3-device-ack-key-1",
        clock=clock,
    )
    controller = PhysicalClosedLoopController(
        gateway=authorization.gateway,
        plant=plant,
        translator=TrustedCommandTranslator(),
        permit_issuer=permit_issuer,
        control_device=control_device,
        evidence=authorization.gateway.evidence,
        acknowledgment_public_key=acknowledgment_public,
        clock=clock,
    )
    return PhysicalLocalLab(
        authorization=authorization,
        plant=plant,
        controller=controller,
        control_device=control_device,
        permit_public_key=permit_public,
        acknowledgment_public_key=acknowledgment_public,
    )
