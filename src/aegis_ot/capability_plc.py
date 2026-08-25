"""Permit-aware research virtual-PLC process for the deterministic-local slice."""

from __future__ import annotations

import json
import os
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from multiprocessing.connection import wait
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Any, Protocol, Self, runtime_checkable
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from .capability_ipc import (
    IpcProtocolError,
    IpcResponseFrame,
    IpcResponseStatus,
    IpcTransportError,
    JsonPipeClient,
    bounded_error_reason,
    receive_request,
    send_response,
)
from .capability_models import (
    CapabilityActionRequest,
    CapabilityExecutionPermit,
    DispatchPhase,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from .capability_observer import ObserverProcessInfo
from .capability_plant import PlantProcessInfo, PlcPlantClient
from .crypto import generate_keypair
from .models import Decision, DecisionOutcome
from .pandapower_plant import PhysicalSimulationError
from .physical_control import Clock, utc_now
from .physical_models import (
    CandidateAssessment,
    CommandStatus,
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    proposal_digest,
)
from .transport_replay import _LifetimeReplayWriterLock, _ReplayWriterLockError

PLC_CAPABILITIES: dict[str, frozenset[str]] = {
    "admin": frozenset({"health", "shutdown"}),
    "gateway": frozenset({"health", "execute"}),
}


class PlcServiceError(RuntimeError):
    """The virtual-PLC service rejected an exchange before returning a signed ACK."""


class CapabilityPlcPlantPort(Protocol):
    """Plant operations retained by the permit-aware virtual PLC."""

    def read_state(self) -> PhysicalStateSnapshot: ...

    def simulate_candidate(
        self,
        command: PhysicalControlCommand,
    ) -> CandidateAssessment: ...

    def apply_authorized_command(
        self,
        command: PhysicalControlCommand,
        *,
        expected_pre_state_version: int | None = None,
        expected_pre_state_digest: str | None = None,
        expected_pre_observation_digest: str | None = None,
        expected_post_state_digest: str | None = None,
        expected_post_topology_digest: str | None = None,
    ) -> PhysicalStateSnapshot: ...


@runtime_checkable
class EffectDeadlineCapabilityPlcPlantPort(Protocol):
    """Optional plant port that carries the permit deadline to final effect."""

    def apply_authorized_command_with_deadline(
        self,
        command: PhysicalControlCommand,
        *,
        expected_pre_state_version: int,
        expected_pre_state_digest: str,
        expected_pre_observation_digest: str,
        expected_post_state_digest: str,
        expected_post_topology_digest: str,
        authorization_expires_at: datetime,
    ) -> PhysicalStateSnapshot: ...


@dataclass(frozen=True)
class PlcProcessInfo:
    pid: int
    plc_id: str
    boot_epoch: str
    key_id: str
    public_key_bytes: bytes
    permit_key_id: str
    plant_boot_epoch: str
    observer_boot_epoch: str
    capabilities: dict[str, tuple[str, ...]]

    @property
    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.public_key_bytes)


class OrderlyRestartReplayReservations:
    """Single-writer replay reservations persisted by file-and-directory fsync."""

    MAX_LEDGER_BYTES = 4 * 1024 * 1024

    def __init__(self, path: Path, *, initialize: bool = False) -> None:
        self.path = path
        self._lock = RLock()
        self._writer_lock: _LifetimeReplayWriterLock | None = None
        self._state = self._empty()
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise ValueError("PLC replay ledger directory must be a non-symlink directory")
        try:
            self._writer_lock = _LifetimeReplayWriterLock(self.path)
            if initialize:
                if self.path.exists() or self.path.is_symlink():
                    raise ValueError(
                        "PLC replay ledger already exists; refusing to initialize"
                    )
                self._persist()
            self._state = self._load()
        except _ReplayWriterLockError as exc:
            self.close()
            raise ValueError(
                "PLC replay writer lock is already held or unavailable"
            ) from exc
        except Exception:
            self.close()
            raise

    @property
    def writer_lock_path(self) -> Path:
        return _LifetimeReplayWriterLock.path_for(self.path)

    def _assert_writer(self) -> None:
        writer_lock = self._writer_lock
        if writer_lock is None:
            raise ValueError("PLC replay writer lock is closed")
        try:
            writer_lock.assert_held_by_current_process()
        except _ReplayWriterLockError as exc:
            raise ValueError(str(exc)) from exc

    def close(self) -> None:
        writer_lock = self._writer_lock
        self._writer_lock = None
        if writer_lock is not None:
            writer_lock.close()

    def __enter__(self) -> Self:
        self._assert_writer()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()

    @staticmethod
    def _empty() -> dict[str, set[str]]:
        return {
            "request_digests": set(),
            "permit_ids": set(),
            "permit_nonces": set(),
            "command_ids": set(),
        }

    def _load(self) -> dict[str, set[str]]:
        self._assert_writer()
        if not self.path.exists():
            raise ValueError("PLC replay ledger is missing or unavailable")
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("PLC replay ledger must be a regular non-symlink file")
        if self.path.stat().st_size > self.MAX_LEDGER_BYTES:
            raise ValueError("PLC replay ledger exceeds its size limit")

        def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("PLC replay ledger contains a duplicate key")
                value[key] = item
            return value

        parsed = json.loads(
            self.path.read_text(encoding="utf-8"),
            object_pairs_hook=closed_object,
        )
        if not isinstance(parsed, dict):
            raise ValueError("PLC replay ledger root must be an object")
        expected = self._empty()
        if set(parsed) != set(expected):
            raise ValueError("PLC replay ledger has unexpected or missing fields")
        for key in expected:
            values = parsed.get(key)
            if (
                not isinstance(values, list)
                or not all(isinstance(value, str) and value for value in values)
                or values != sorted(set(values))
            ):
                raise ValueError("PLC replay ledger has an invalid reservation set")
            expected[key] = set(values)
        return expected

    def _persist(self) -> None:
        self._assert_writer()
        temporary = self.path.with_suffix(f".{uuid4().hex}.tmp")
        material = json.dumps(
            {key: sorted(values) for key, values in sorted(self._state.items())},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        replaced = False
        try:
            offset = 0
            while offset < len(material):
                offset += os.write(descriptor, material[offset:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self.path)
            replaced = True
            directory_descriptor = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

    def replay_reason(
        self,
        *,
        request_digest: str,
        permit_id: str,
        permit_nonce: str,
        command_id: str,
    ) -> str | None:
        with self._lock:
            self._state = self._load()
            return self._replay_reason(
                request_digest=request_digest,
                permit_id=permit_id,
                permit_nonce=permit_nonce,
                command_id=command_id,
            )

    def _replay_reason(
        self,
        *,
        request_digest: str,
        permit_id: str,
        permit_nonce: str,
        command_id: str,
    ) -> str | None:
        checks = (
            (request_digest in self._state["request_digests"], "transaction_replayed"),
            (permit_id in self._state["permit_ids"], "permit_replayed"),
            (permit_nonce in self._state["permit_nonces"], "permit_nonce_replayed"),
            (command_id in self._state["command_ids"], "command_replayed"),
        )
        return next((reason for replayed, reason in checks if replayed), None)

    def reserve(
        self,
        *,
        request_digest: str,
        permit_id: str,
        permit_nonce: str,
        command_id: str,
    ) -> None:
        with self._lock:
            self._state = self._load()
            reason = self._replay_reason(
                request_digest=request_digest,
                permit_id=permit_id,
                permit_nonce=permit_nonce,
                command_id=command_id,
            )
            if reason is not None:
                raise ValueError(reason)
            self._state["request_digests"].add(request_digest)
            self._state["permit_ids"].add(permit_id)
            self._state["permit_nonces"].add(permit_nonce)
            self._state["command_ids"].add(command_id)
            self._persist()

    @property
    def reservation_count(self) -> int:
        with self._lock:
            self._state = self._load()
            return len(self._state["request_digests"])


class CapabilityVirtualPlc:
    """Verifies one exact authorization transaction before using the plant-apply capability."""

    def __init__(
        self,
        plant: CapabilityPlcPlantPort,
        *,
        plc_id: str,
        boot_epoch: str,
        permit_key_id: str,
        permit_public_key: Ed25519PublicKey,
        observer_info: ObserverProcessInfo,
        acknowledgment_private_key: Ed25519PrivateKey,
        acknowledgment_key_id: str,
        replay: OrderlyRestartReplayReservations,
        clock: Clock = utc_now,
    ) -> None:
        self.plant = plant
        self.plc_id = plc_id
        self.boot_epoch = boot_epoch
        self.permit_key_id = permit_key_id
        self.permit_public_key = permit_public_key
        self.observer_info = observer_info
        self.acknowledgment_private_key = acknowledgment_private_key
        self.acknowledgment_key_id = acknowledgment_key_id
        self.replay = replay
        self.clock = clock
        self.scan_counter = 0
        self.execute_requests = 0
        self.automatic_retry_count = 0
        self._lock = RLock()

    @staticmethod
    def _actuator_setpoint(
        state: PhysicalStateSnapshot,
        command: PhysicalControlCommand,
    ) -> float:
        if command.command_type is PhysicalCommandType.SET_LINE_SERVICE:
            return 0.0 if command.resource in state.isolated_resources else 1.0
        return state.battery_injection_mw.get(command.resource, 0.0)

    def _acknowledge(
        self,
        *,
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        status: CommandStatus,
        phase: DispatchPhase,
        reason: str,
        acknowledged_at: datetime,
        pre_state: PhysicalStateSnapshot,
        post_state: PhysicalStateSnapshot | None = None,
    ) -> PlcCommandAcknowledgment:
        command = permit.base_permit.command
        acknowledgment = PlcCommandAcknowledgment(
            request_digest=request.digest,
            permit_digest=permit.digest,
            observation_envelope_digest=permit.observation_envelope_digest,
            permit_id=permit.base_permit.permit_id,
            permit_nonce=permit.base_permit.permit_nonce,
            command_id=command.command_id,
            command_digest=permit.base_permit.command_digest,
            assessment_digest=permit.base_permit.assessment_digest,
            proposal_id=permit.base_permit.proposal_id,
            decision_id=permit.base_permit.decision_id,
            plc_id=self.plc_id,
            plc_key_id=self.acknowledgment_key_id,
            plc_boot_epoch=self.boot_epoch,
            plc_scan=self.scan_counter,
            status=status,
            dispatch_phase=phase,
            reason=reason,
            acknowledged_at=acknowledged_at,
            pre_state=pre_state,
            pre_state_digest=pre_state.state_digest,
            pre_state_version=pre_state.state_version,
            post_state_digest=post_state.state_digest if post_state is not None else None,
            post_state_version=post_state.state_version if post_state is not None else None,
            post_topology_digest=post_state.topology_digest if post_state is not None else None,
            pre_actuator_setpoint=self._actuator_setpoint(pre_state, command),
            post_actuator_setpoint=(
                self._actuator_setpoint(post_state, command)
                if post_state is not None
                else (
                    self._actuator_setpoint(pre_state, command)
                    if status is CommandStatus.REJECTED
                    else None
                )
            ),
            simulation_time_s=(
                post_state.simulation_time_s
                if post_state is not None
                else pre_state.simulation_time_s
            ),
        )
        return acknowledgment.signed(self.acknowledgment_private_key)

    def execute(
        self,
        *,
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        pre_observation: SignedObservationEnvelope,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> PlcCommandAcknowledgment:
        with self._lock:
            self.execute_requests += 1
            self.scan_counter += 1
            return self._execute_locked(
                request=request,
                permit=permit,
                pre_observation=pre_observation,
                decision=decision,
                assessment=assessment,
            )

    def _execute_locked(
        self,
        *,
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        pre_observation: SignedObservationEnvelope,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> PlcCommandAcknowledgment:
        evaluated_at = self.clock()
        current = self.plant.read_state()
        base = permit.base_permit
        replay_reason = self.replay.replay_reason(
            request_digest=request.digest,
            permit_id=base.permit_id,
            permit_nonce=base.permit_nonce,
            command_id=base.command.command_id,
        )
        if replay_reason is not None:
            return self._acknowledge(
                request=request,
                permit=permit,
                status=CommandStatus.REJECTED,
                phase=DispatchPhase.PRE_DISPATCH,
                reason=replay_reason,
                acknowledged_at=evaluated_at,
                pre_state=current,
            )
        checks: tuple[tuple[bool, str], ...] = (
            (base.audience == self.plc_id, "permit_wrong_audience"),
            (permit.signing_key_id == self.permit_key_id, "permit_unknown_signing_key"),
            (permit.verify(self.permit_public_key), "permit_signature_invalid"),
            (permit.target_plc_id == self.plc_id, "permit_wrong_plc"),
            (
                permit.target_plc_key_id == self.acknowledgment_key_id,
                "permit_wrong_plc_key",
            ),
            (
                permit.target_plc_boot_epoch == self.boot_epoch,
                "permit_wrong_plc_boot",
            ),
            (permit.request_digest == request.digest, "permit_request_digest_mismatch"),
            (
                permit.observation_id == pre_observation.observation_id,
                "permit_observation_id_mismatch",
            ),
            (
                permit.observation_envelope_digest == pre_observation.envelope_digest,
                "permit_observation_digest_mismatch",
            ),
            (permit.observer_id == pre_observation.observer_id, "permit_observer_id_mismatch"),
            (
                permit.observer_key_id == pre_observation.observer_key_id,
                "permit_observer_key_mismatch",
            ),
            (
                permit.observer_boot_epoch == pre_observation.observer_boot_epoch,
                "permit_observer_boot_mismatch",
            ),
            (
                pre_observation.verify(self.observer_info.public_key),
                "observation_signature_invalid",
            ),
            (
                pre_observation.observer_id == self.observer_info.observer_id,
                "observation_source_mismatch",
            ),
            (
                pre_observation.observer_key_id == self.observer_info.key_id,
                "observation_key_mismatch",
            ),
            (
                pre_observation.observer_boot_epoch == self.observer_info.boot_epoch,
                "observation_boot_mismatch",
            ),
            (
                pre_observation.phase is ObservationPhase.PRE_AUTHORIZATION,
                "observation_phase_mismatch",
            ),
            (
                request.observation_challenge_nonce == pre_observation.challenge_nonce,
                "observation_challenge_mismatch",
            ),
            (
                request.correlation_id == pre_observation.correlation_id,
                "observation_correlation_mismatch",
            ),
            (
                request.proposal.observed_state_version
                == pre_observation.snapshot.state_version,
                "proposal_observation_version_mismatch",
            ),
            (
                request.proposal.observed_at == pre_observation.snapshot.observed_at,
                "proposal_observation_time_mismatch",
            ),
            (evaluated_at >= base.issued_at, "permit_not_yet_valid"),
            (evaluated_at < base.expires_at, "permit_expired"),
            (base.proposal_id == request.proposal.proposal_id, "permit_proposal_id_mismatch"),
            (
                base.proposal_digest == proposal_digest(request.proposal),
                "permit_proposal_digest_mismatch",
            ),
            (base.decision_id == decision.decision_id, "permit_decision_id_mismatch"),
            (decision.outcome is DecisionOutcome.PERMIT, "decision_not_permit"),
            (decision.proposal_id == request.proposal.proposal_id, "decision_proposal_mismatch"),
            (
                decision.evidence_record_hash == base.evidence_record_hash,
                "decision_evidence_mismatch",
            ),
            (base.policy_version == decision.policy_version, "decision_policy_version_mismatch"),
            (base.safety_version == decision.safety_version, "decision_safety_version_mismatch"),
            (base.state_version == decision.state_version, "decision_state_version_mismatch"),
            (base.command_digest == base.command.digest, "permit_command_digest_mismatch"),
            (base.assessment_digest == assessment.digest, "permit_assessment_digest_mismatch"),
            (assessment.safe, "candidate_not_safe"),
            (assessment.command_digest == base.command_digest, "candidate_command_mismatch"),
            (
                assessment.pre_state.state_digest == base.state_digest,
                "candidate_state_digest_mismatch",
            ),
            (
                assessment.post_state.state_version == base.expected_post_state_version,
                "candidate_post_version_mismatch",
            ),
            (
                assessment.post_state.state_digest == base.expected_post_state_digest,
                "candidate_post_digest_mismatch",
            ),
            (
                assessment.post_state.topology_digest == base.expected_post_topology_digest,
                "candidate_post_topology_mismatch",
            ),
            (current.verify_digest(), "current_state_digest_invalid"),
            (base.model_digest == current.model_digest, "model_digest_changed"),
            (base.topology_digest == current.topology_digest, "topology_digest_changed"),
            (base.state_version == current.state_version, "precommit_state_version_changed"),
            (base.state_digest == current.state_digest, "precommit_state_digest_changed"),
            (
                base.observation_digest == current.observation_digest,
                "precommit_observation_changed",
            ),
        )
        for passed, reason in checks:
            if not passed:
                return self._acknowledge(
                    request=request,
                    permit=permit,
                    status=CommandStatus.REJECTED,
                    phase=DispatchPhase.PRE_DISPATCH,
                    reason=reason,
                    acknowledged_at=evaluated_at,
                    pre_state=current,
                )

        fresh_assessment = self.plant.simulate_candidate(base.command)
        if (
            not fresh_assessment.safe
            or fresh_assessment.pre_state.state_digest != assessment.pre_state.state_digest
            or fresh_assessment.post_state.state_digest != assessment.post_state.state_digest
            or fresh_assessment.command_digest != assessment.command_digest
        ):
            return self._acknowledge(
                request=request,
                permit=permit,
                status=CommandStatus.REJECTED,
                phase=DispatchPhase.PRE_DISPATCH,
                reason="candidate_attestation_mismatch",
                acknowledged_at=self.clock(),
                pre_state=current,
            )
        commit_time = self.clock()
        if commit_time >= base.expires_at:
            return self._acknowledge(
                request=request,
                permit=permit,
                status=CommandStatus.REJECTED,
                phase=DispatchPhase.PRE_DISPATCH,
                reason="permit_expired_before_dispatch",
                acknowledged_at=commit_time,
                pre_state=current,
            )

        try:
            self.replay.reserve(
                request_digest=request.digest,
                permit_id=base.permit_id,
                permit_nonce=base.permit_nonce,
                command_id=base.command.command_id,
            )
        except ValueError as exc:
            return self._acknowledge(
                request=request,
                permit=permit,
                status=CommandStatus.REJECTED,
                phase=DispatchPhase.PRE_DISPATCH,
                reason=str(exc),
                acknowledged_at=self.clock(),
                pre_state=current,
            )

        final_dispatch_time = self.clock()
        if final_dispatch_time >= base.expires_at:
            return self._acknowledge(
                request=request,
                permit=permit,
                status=CommandStatus.REJECTED,
                phase=DispatchPhase.PRE_DISPATCH,
                reason="permit_expired_after_replay_reservation",
                acknowledged_at=final_dispatch_time,
                pre_state=current,
            )

        try:
            if isinstance(self.plant, EffectDeadlineCapabilityPlcPlantPort):
                post_state = self.plant.apply_authorized_command_with_deadline(
                    base.command,
                    expected_pre_state_version=base.state_version,
                    expected_pre_state_digest=base.state_digest,
                    expected_pre_observation_digest=base.observation_digest,
                    expected_post_state_digest=base.expected_post_state_digest,
                    expected_post_topology_digest=base.expected_post_topology_digest,
                    authorization_expires_at=base.expires_at,
                )
            else:
                post_state = self.plant.apply_authorized_command(
                    base.command,
                    expected_pre_state_version=base.state_version,
                    expected_pre_state_digest=base.state_digest,
                    expected_pre_observation_digest=base.observation_digest,
                    expected_post_state_digest=base.expected_post_state_digest,
                    expected_post_topology_digest=base.expected_post_topology_digest,
                )
        except PhysicalSimulationError as exc:
            reason = str(exc)
            cas_reasons = {
                "model_digest_changed",
                "topology_digest_changed",
                "precommit_state_version_changed",
                "precommit_state_digest_changed",
                "precommit_observation_changed",
            }
            rejection_state = self.plant.read_state() if reason in cas_reasons else current
            return self._acknowledge(
                request=request,
                permit=permit,
                status=CommandStatus.REJECTED,
                phase=DispatchPhase.KNOWN_NO_EFFECT,
                reason=reason,
                acknowledged_at=self.clock(),
                pre_state=rejection_state,
            )
        except Exception:
            return self._acknowledge(
                request=request,
                permit=permit,
                status=CommandStatus.UNKNOWN_EFFECT,
                phase=DispatchPhase.EFFECT_UNKNOWN,
                reason="plant_dispatch_outcome_unavailable",
                acknowledged_at=self.clock(),
                pre_state=current,
            )
        if (
            post_state.state_digest != base.expected_post_state_digest
            or post_state.state_version != base.expected_post_state_version
            or post_state.topology_digest != base.expected_post_topology_digest
            or post_state.unsafe_state
        ):
            return self._acknowledge(
                request=request,
                permit=permit,
                status=CommandStatus.UNKNOWN_EFFECT,
                phase=DispatchPhase.EFFECT_UNKNOWN,
                reason="post_dispatch_candidate_divergence",
                acknowledged_at=self.clock(),
                pre_state=current,
            )
        return self._acknowledge(
            request=request,
            permit=permit,
            status=CommandStatus.APPLIED,
            phase=DispatchPhase.COMMITTED,
            reason="command_applied_and_plc_read_back",
            acknowledged_at=self.clock(),
            pre_state=current,
            post_state=post_state,
        )


def _plc_process_main(
    ready_connection: Any,
    admin_connection: Any,
    gateway_connection: Any,
    plant_connection: Any,
    plant_info_payload: dict[str, Any],
    observer_info_payload: dict[str, Any],
    permit_public_key_bytes: bytes,
    permit_key_id: str,
    replay_ledger_path: str,
    fixed_now_iso: str | None,
) -> None:
    boot_epoch = str(uuid4())
    plc_id = "research-virtual-plc:deterministic-local"
    acknowledgment_key_id = "research-virtual-plc-key-v1"
    fixed_now = datetime.fromisoformat(fixed_now_iso) if fixed_now_iso is not None else None
    clock: Clock = (lambda: fixed_now) if fixed_now is not None else utc_now
    response_counter = 0
    running = True
    endpoints = {"admin": admin_connection, "gateway": gateway_connection}
    plant_info = PlantProcessInfo(**plant_info_payload)
    observer_info = ObserverProcessInfo(**observer_info_payload)
    plant = PlcPlantClient(plant_connection, plant_info)
    permit_public_key = Ed25519PublicKey.from_public_bytes(permit_public_key_bytes)
    acknowledgment_private, acknowledgment_public = generate_keypair()
    replay_path = Path(replay_ledger_path)
    writer_lock_path = _LifetimeReplayWriterLock.path_for(replay_path)
    replay = OrderlyRestartReplayReservations(
        replay_path,
        initialize=not replay_path.exists() and not writer_lock_path.exists(),
    )
    device = CapabilityVirtualPlc(
        plant,
        plc_id=plc_id,
        boot_epoch=boot_epoch,
        permit_key_id=permit_key_id,
        permit_public_key=permit_public_key,
        observer_info=observer_info,
        acknowledgment_private_key=acknowledgment_private,
        acknowledgment_key_id=acknowledgment_key_id,
        replay=replay,
        clock=clock,
    )
    public_raw = acknowledgment_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    try:
        ready_connection.send(
            {
                "pid": os.getpid(),
                "plc_id": plc_id,
                "boot_epoch": boot_epoch,
                "key_id": acknowledgment_key_id,
                "public_key_bytes": public_raw,
                "permit_key_id": permit_key_id,
                "plant_boot_epoch": plant_info.boot_epoch,
                "observer_boot_epoch": observer_info.boot_epoch,
                "capabilities": {
                    role: tuple(sorted(operations)) for role, operations in PLC_CAPABILITIES.items()
                },
            }
        )
        while running and endpoints:
            ready = wait(list(endpoints.values()), timeout=0.1)
            for ready_endpoint in ready:
                connection: Any = ready_endpoint
                role = next(name for name, endpoint in endpoints.items() if endpoint is connection)
                try:
                    ipc_request = receive_request(connection)
                except (IpcProtocolError, IpcTransportError):
                    connection.close()
                    del endpoints[role]
                    break
                response_counter += 1
                status = IpcResponseStatus.OK
                error_code: str | None = None
                payload: dict[str, Any]
                if ipc_request.operation not in PLC_CAPABILITIES[role]:
                    status = IpcResponseStatus.REJECTED
                    error_code = "capability_denied"
                    payload = {"role": role, "operation": ipc_request.operation}
                else:
                    try:
                        if ipc_request.operation == "health":
                            plant_health = plant.health()
                            payload = {
                                "status": "ready",
                                "pid": os.getpid(),
                                "plc_id": plc_id,
                                "boot_epoch": boot_epoch,
                                "key_id": acknowledgment_key_id,
                                "role": role,
                                "capabilities": tuple(sorted(PLC_CAPABILITIES[role])),
                                "execute_requests": device.execute_requests,
                                "plc_scan": device.scan_counter,
                                "automatic_retry_count": device.automatic_retry_count,
                                "replay_reservations": replay.reservation_count,
                                "plant": plant_health,
                            }
                        elif ipc_request.operation == "shutdown":
                            payload = {"status": "stopping"}
                            running = False
                        elif ipc_request.operation == "execute":
                            request = CapabilityActionRequest.model_validate(
                                ipc_request.payload["request"]
                            )
                            permit = CapabilityExecutionPermit.model_validate(
                                ipc_request.payload["permit"]
                            )
                            pre_observation = SignedObservationEnvelope.model_validate(
                                ipc_request.payload["pre_observation"]
                            )
                            decision = Decision.model_validate(ipc_request.payload["decision"])
                            assessment = CandidateAssessment.model_validate(
                                ipc_request.payload["assessment"]
                            )
                            acknowledgment = device.execute(
                                request=request,
                                permit=permit,
                                pre_observation=pre_observation,
                                decision=decision,
                                assessment=assessment,
                            )
                            payload = {
                                "acknowledgment": acknowledgment.model_dump(mode="json")
                            }
                        else:
                            raise RuntimeError("unreachable PLC operation")
                    except (KeyError, TypeError, ValidationError, ValueError) as exc:
                        status = IpcResponseStatus.REJECTED
                        error_code = "invalid_payload"
                        payload = {
                            "reason": bounded_error_reason(exc),
                            "error_type": type(exc).__name__,
                        }
                    except Exception as exc:
                        status = IpcResponseStatus.ERROR
                        error_code = "plc_internal_error"
                        payload = {
                            "reason": bounded_error_reason(exc),
                            "error_type": type(exc).__name__,
                        }
                response = IpcResponseFrame.create(
                    ipc_request,
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
        plant.close()
        for connection in endpoints.values():
            connection.close()


class _PlcClient:
    def __init__(self, connection: Any, info: PlcProcessInfo) -> None:
        self._ipc = JsonPipeClient(connection, expected_boot_epoch=info.boot_epoch)
        self.info = info

    def _request(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        consequential: bool = False,
    ) -> dict[str, Any]:
        response = self._ipc.request(operation, payload, consequential=consequential)
        if response.status != IpcResponseStatus.OK:
            reason = str(response.payload.get("reason", response.error_code))
            raise PlcServiceError(reason)
        return response.payload

    def health(self) -> dict[str, Any]:
        return self._request("health", {})

    def close(self) -> None:
        self._ipc.close()


class GatewayPlcClient(_PlcClient):
    def execute(
        self,
        *,
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        pre_observation: SignedObservationEnvelope,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> PlcCommandAcknowledgment:
        payload = self._request(
            "execute",
            {
                "request": request.model_dump(mode="json"),
                "permit": permit.model_dump(mode="json"),
                "pre_observation": pre_observation.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
                "assessment": assessment.model_dump(mode="json"),
            },
            consequential=True,
        )
        try:
            return PlcCommandAcknowledgment.model_validate(payload["acknowledgment"])
        except (KeyError, TypeError, ValidationError, ValueError) as exc:
            raise PlcServiceError("virtual PLC returned an invalid acknowledgment") from exc


class PlcAdminClient(_PlcClient):
    def shutdown(self) -> None:
        try:
            self._request("shutdown", {})
        except (IpcTransportError, PlcServiceError):
            pass
