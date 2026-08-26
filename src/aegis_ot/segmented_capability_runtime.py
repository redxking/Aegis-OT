"""M4g-a signed full-capability services for the segmented Docker experiment.

This module carries the complete M4a transaction artifacts over bounded HTTP
while retaining one authoritative pandapower plant.  Its Ed25519 files are
experiment trust pins; they are not SPIFFE identities, TLS credentials, or
evidence of hostile-host isolation.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any, Generic, Literal, Never, TypeVar
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from .capability_control import (
    CapabilityClosedLoopController,
    CapabilityPermitIssuer,
    SignedObservationVerifier,
)
from .capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopResult,
    CapabilityClosedLoopStatus,
    CapabilityExecutionPermit,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from .capability_observer import ObserverProcessInfo
from .capability_plant import PlantProcessInfo
from .capability_plc import (
    CapabilityVirtualPlc,
    OrderlyRestartReplayReservations,
    PlcProcessInfo,
)
from .coordination_anchor import (
    AnchoredRecoveryStatus,
    CoordinationAnchorAdmissionError,
    CoordinationAnchorAdmissionPhase,
    CoordinationAnchorAdmissionPort,
)
from .coordination_journal import (
    CommitAdmissionStatus,
    CoordinationCollisionError,
    CoordinationJournalError,
    CoordinationJournalRecord,
    DurableEffectCoordinationJournal,
    DurableGatewayCoordinationJournal,
    EffectCommitAttempt,
    EffectPrepareAttempt,
    EffectQueryAttempt,
    IllegalCoordinationTransition,
)
from .coordination_models import (
    EFFECT_COORDINATOR_AUDIENCE,
    GATEWAY_COORDINATION_AUDIENCE,
    CapabilityOutcomePending,
    CapabilityOutcomeResolution,
    CoordinationReceipt,
    CoordinationState,
    DurableCommitAcceptance,
    EffectDisposition,
    SignedEffectCommitRequest,
    SignedEffectOutcome,
    SignedEffectPrepareRequest,
    SignedEffectQueryRequest,
    WorkloadAuthenticatedEffectReconciliation,
)
from .coordination_recovery import (
    CoordinationRecoveryReason,
    CoordinationRecoveryResult,
    CoordinationRecoveryStatus,
    validate_coordination_recovery,
)
from .factory import LocalLab, build_local_lab
from .m5_degraded import (
    DegradedOperationGate,
    FileDegradedAuthorizationSource,
    FileDegradedOperationStateStore,
    FileDegradedSnapshotSource,
)
from .m5_degraded_publication import (
    FileDegradedConsumerStateStore,
    FileDegradedPublicationSource,
    FileDegradedReversalSource,
    FileStableDegradedAuthorizationSource,
    PublishedDegradedOperationGate,
    load_authority_public_key,
    load_publisher_credential,
)
from .models import Decision
from .pandapower_plant import PandapowerCigreMVPlant, PhysicalSimulationError
from .physical_control import (
    Clock,
    ExecutionPermitIssuer,
    TrustedCommandTranslator,
    utc_now,
)
from .physical_models import (
    CandidateAssessment,
    CommandStatus,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
)
from .plant_checkpoint import DurablePlantCheckpointStore, PlantCheckpointError
from .safety import SafetyKernel, SafetyLimits
from .segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    OT_CAPABILITY_AUDIENCE,
    PHYSICAL_PLANT_AUDIENCE,
    PlantApplyPayload,
    PlantCallerRole,
    PlantCapturePayload,
    PlantExchange,
    PlantFailureResponsePayload,
    PlantOperation,
    PlantReadPayload,
    PlantResponseStatus,
    PlantSimulatePayload,
    PlantSimulationResponsePayload,
    PlantStateResponsePayload,
    SegmentedCapabilityClosedLoopResult,
    SegmentedCapabilityDispatch,
    SignedPlantCall,
    SignedPlantResponse,
    SignedSegmentedCapabilityDispatch,
    SignedSegmentedCapabilityResponse,
    WorkloadAuthenticatedCapabilityAction,
    WorkloadSignedCapabilityDispatch,
    WorkloadSignedCapabilityResponse,
)
from .segmented_capability_transport import (
    CandidateHealthMetadata,
    CapabilityTransportError,
    CapabilityTransportRejected,
    CoordinatedWorkloadRemoteVirtualPlcPort,
    HttpExchange,
    ObserverHealthMetadata,
    OtCoordinationRecoveryMetadata,
    OtHealthMetadata,
    PlantHealthMetadata,
    RemoteCandidatePlantClient,
    RemoteCandidatePort,
    RemoteObservationPort,
    RemoteObserverPlantClient,
    RemotePlcPlantClient,
    RemoteVirtualPlcPort,
    SegmentedCapabilityDiscovery,
    TransportFailureBody,
    WorkloadRemoteVirtualPlcPort,
    discover_segmented_capabilities_via_ot,
    fetch_observer_health,
    fetch_plant_health,
    urllib_http_exchange,
)
from .segmented_runtime import OpaBackedPolicy
from .spire_mtls import capability_http_exchange_from_environment
from .strict_json_request import (
    StrictJsonRequestError,
    parse_strict_json_request,
    parse_strict_json_request_adapter,
)
from .transport_replay import (
    DurableTransportReplayLedger,
    TransportReplayLedgerError,
)
from .workload_identity import (
    ResolvedWorkloadIdentity,
    WorkloadCredentialBinding,
    WorkloadCredentialRejected,
    WorkloadIdentityError,
    WorkloadIdentityUnavailable,
    WorkloadIdentityVerifier,
    WorkloadRole,
    WorkloadSigner,
)
from .workload_replay import DurableWorkloadReplayLedger, WorkloadReplayLedgerError
from .workload_runtime import (
    LocalWorkloadIdentity,
    credential_binding_from_environment,
    local_identity_from_environment,
    verifier_from_environment,
    workload_identity_enabled,
)

PLANT_BACKEND = "pandapower-cigre-mv-segmented-http-v1"
PLC_ID = "virtual-control-device:m4g-segmented"
MAX_OBSERVATION_CACHE = 128

_OT_EXECUTE_REQUEST_ADAPTER: TypeAdapter[
    SignedSegmentedCapabilityDispatch | WorkloadSignedCapabilityDispatch
] = TypeAdapter(SignedSegmentedCapabilityDispatch | WorkloadSignedCapabilityDispatch)
_GATEWAY_ACTION_REQUEST_ADAPTER: TypeAdapter[
    CapabilityActionRequest | WorkloadAuthenticatedCapabilityAction
] = TypeAdapter(CapabilityActionRequest | WorkloadAuthenticatedCapabilityAction)


class CapabilityRuntimeError(RuntimeError):
    """Base error for a bounded M4g-a service disposition."""


class CapabilityAdmissionRejected(CapabilityRuntimeError):
    """A request was rejected before crossing a consequential boundary."""


class CapabilityRuntimeUnavailable(CapabilityRuntimeError):
    """A required trusted dependency or durable state was unavailable."""


class EffectCommitIndeterminate(CapabilityRuntimeError):
    """A durably accepted commit must be reconciled rather than re-executed."""


def effect_coordination_enabled() -> bool:
    """Return whether the OT consequence path requires M4i coordination."""

    mode = os.getenv("AEGIS_EFFECT_COORDINATION_MODE")
    if mode == "required":
        return True
    if mode == "disabled":
        return False
    raise CapabilityRuntimeUnavailable(
        "effect coordination mode must be required or disabled; configure it explicitly"
    )


class _StrictRequest(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
    )


class ObservationCaptureRequest(_StrictRequest):
    correlation_id: str = Field(min_length=1, max_length=256)
    challenge_nonce: str = Field(min_length=16, max_length=256)


class ObservationResolveRequest(_StrictRequest):
    observation_id: str = Field(min_length=1, max_length=256)
    envelope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class PostObservationCaptureRequest(ObservationCaptureRequest):
    previous_envelope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    permit_id: str = Field(min_length=1, max_length=256)
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    plc_acknowledgment_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class CandidateSimulationRequest(_StrictRequest):
    command: PhysicalControlCommand


@dataclass(frozen=True)
class TrustedPlantCaller:
    key_id: str
    public_key: Ed25519PublicKey


@dataclass(frozen=True)
class _EffectCoordinationContext:
    journal: DurableEffectCoordinationJournal
    verifier: WorkloadIdentityVerifier
    gateway: ResolvedWorkloadIdentity
    local: ResolvedWorkloadIdentity
    signer: WorkloadSigner


@dataclass(frozen=True)
class _LiveCommitMarker:
    effect_id: str
    prepare_request_sha256: str
    receipt_sha256: str
    runtime_boot_epoch: str

    def matches_prepare(
        self,
        request: SignedEffectPrepareRequest,
        *,
        boot_epoch: str,
    ) -> bool:
        return (
            self.effect_id == request.effect.effect_id
            and self.prepare_request_sha256 == request.digest
            and self.runtime_boot_epoch == boot_epoch
        )

    def matches(self, request: SignedEffectCommitRequest, *, boot_epoch: str) -> bool:
        return (
            self.effect_id == request.effect.effect_id
            and self.prepare_request_sha256 == request.receipt.prepare_request.digest
            and self.receipt_sha256 == request.receipt.digest
            and self.runtime_boot_epoch == boot_epoch
        )


@dataclass(frozen=True)
class _PlantCallReservation:
    request_sha256: str
    terminal: tuple[int, SignedPlantResponse] | None = None


def _public_key_b64(key: Ed25519PublicKey) -> str:
    return base64.urlsafe_b64encode(key.public_bytes_raw()).decode("ascii")


def _read_exact_key(path: str) -> bytes:
    try:
        material = Path(path).read_bytes()
    except OSError as exc:
        raise CapabilityRuntimeUnavailable("configured signing key is unavailable") from exc
    if len(material) != 32:
        raise CapabilityRuntimeUnavailable(
            "configured Ed25519 key must contain exactly 32 raw bytes"
        )
    return material


def _load_private_key(path: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_read_exact_key(path))


def _load_public_key(path: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_read_exact_key(path))


def _same_public_key(left: Ed25519PublicKey, right: Ed25519PublicKey) -> bool:
    return left.public_bytes_raw() == right.public_bytes_raw()


def _require_distinct_public_keys(
    keys: Mapping[str, Ed25519PublicKey],
) -> None:
    raw_to_role: dict[bytes, str] = {}
    for role, key in keys.items():
        raw = key.public_bytes_raw()
        prior = raw_to_role.get(raw)
        if prior is not None:
            raise ValueError(
                f"signing key material must be distinct for {prior} and {role}"
            )
        raw_to_role[raw] = role


def _require_pin(
    *,
    label: str,
    actual_key_id: str,
    actual_public_key: Ed25519PublicKey,
    expected_key_id: str,
    expected_public_key: Ed25519PublicKey,
) -> None:
    if actual_key_id != expected_key_id or not _same_public_key(
        actual_public_key,
        expected_public_key,
    ):
        raise CapabilityRuntimeUnavailable(f"{label} discovery does not match its trust pin")


def _failure_response(
    status_code: int,
    reason: str,
    *,
    status: Literal["rejected", "error"],
) -> JSONResponse:
    bounded = reason[:512] if reason else "capability_runtime_failure"
    body = TransportFailureBody(status=status, reason=bounded)
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


def _wire_rejection(exc: StrictJsonRequestError) -> JSONResponse:
    return _failure_response(
        exc.status_code,
        exc.reason.value,
        status="rejected",
    )


class CapabilityPlantRuntime:
    """Sole-owner physical plant with role/key/boot-bound signed calls."""

    def __init__(
        self,
        *,
        plant: PandapowerCigreMVPlant,
        private_key: Ed25519PrivateKey,
        key_id: str,
        trusted_callers: Mapping[PlantCallerRole, TrustedPlantCaller],
        boot_epoch: str | None = None,
        clock: Clock = utc_now,
        checkpoint_required: bool = False,
        checkpoint_store: DurablePlantCheckpointStore | None = None,
    ) -> None:
        expected_roles = {
            PlantCallerRole.OBSERVER,
            PlantCallerRole.CANDIDATE,
            PlantCallerRole.PLC,
        }
        if set(trusted_callers) != expected_roles:
            raise ValueError("plant caller registry must define observer, candidate, and PLC")
        key_ids = {caller.key_id for caller in trusted_callers.values()}
        if len(key_ids) != len(expected_roles) or key_id in key_ids:
            raise ValueError("plant and caller signing key IDs must be distinct")
        _require_distinct_public_keys(
            {
                "plant": private_key.public_key(),
                **{
                    role.value: caller.public_key
                    for role, caller in trusted_callers.items()
                },
            }
        )
        if checkpoint_required and checkpoint_store is None:
            raise ValueError("required plant checkpoint store is missing")
        if not checkpoint_required and checkpoint_store is not None:
            raise ValueError("disabled plant checkpoint mode cannot retain a store")
        if checkpoint_store is not None and (
            checkpoint_store.plant_key_id != key_id
            or checkpoint_store.model_digest != plant.model_digest
        ):
            raise ValueError("plant checkpoint store identity does not match the runtime")
        self.plant = plant
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id
        self.trusted_callers = dict(trusted_callers)
        self.boot_epoch = boot_epoch or str(uuid4())
        self.clock = clock
        self.checkpoint_required = checkpoint_required
        self.checkpoint_store = checkpoint_store
        self._lock = RLock()
        self._call_reservations: dict[str, _PlantCallReservation] = {}
        self.apply_requests = 0
        self.commit_count = 0
        if self.checkpoint_required:
            self._verified_checkpoint_state()

    def _verified_checkpoint_state(
        self,
        state: PhysicalStateSnapshot | None = None,
    ) -> PhysicalStateSnapshot:
        """Return live state only when required durability still agrees with it."""

        if not self.checkpoint_required:
            return state if state is not None else self.plant.read_state()
        checkpoint_store = self.checkpoint_store
        if checkpoint_store is None:  # pragma: no cover - constructor invariant
            raise CapabilityRuntimeUnavailable("plant_checkpoint_unavailable")
        try:
            live = state if state is not None else self.plant.read_state()
            checkpoint_store.verify_current(live)
        except (PhysicalSimulationError, PlantCheckpointError) as exc:
            raise CapabilityRuntimeUnavailable("plant_checkpoint_unavailable") from exc
        return live

    def _commit_checkpoint_before_swap(
        self,
        current: PhysicalStateSnapshot,
        next_state: PhysicalStateSnapshot,
        *,
        effect_deadline: datetime,
    ) -> None:
        checkpoint_store = self.checkpoint_store
        if not self.checkpoint_required or checkpoint_store is None:
            raise CapabilityRuntimeUnavailable("plant_checkpoint_unavailable")
        try:
            checkpoint_store.commit_next(
                current=current,
                next_state=next_state,
                effect_deadline=effect_deadline,
                effect_clock=self.clock,
            )
        except PlantCheckpointError as exc:
            raise CapabilityRuntimeUnavailable("plant_checkpoint_unavailable") from exc

    def health(self) -> PlantHealthMetadata:
        with self._lock:
            state = self._verified_checkpoint_state()
            apply_requests = self.apply_requests
            commit_count = self.commit_count
            reservations = len(self._call_reservations)
        return PlantHealthMetadata(
            pid=os.getpid(),
            boot_epoch=self.boot_epoch,
            key_id=self.key_id,
            public_key_b64=_public_key_b64(self.public_key),
            backend=PLANT_BACKEND,
            model_digest=self.plant.model_digest,
            simulator_version=self.plant.simulator_version,
            observation_source_id=state.observation_source_id,
            state_version=state.state_version,
            state_digest=state.state_digest,
            apply_requests=apply_requests,
            commit_count=commit_count,
            call_reservations=reservations,
        )

    def _signed_failure(
        self,
        call: SignedPlantCall,
        reason: str,
    ) -> SignedPlantResponse:
        return SignedPlantResponse.issue(
            call=call,
            status=PlantResponseStatus.REJECTED,
            payload=PlantFailureResponsePayload(
                status=PlantResponseStatus.REJECTED,
                reason=reason[:512],
            ),
            plant_boot_epoch=self.boot_epoch,
            plant_key_id=self.key_id,
            signed_at=self.clock(),
            private_key=self.private_key,
        )

    def execute(self, call: SignedPlantCall) -> tuple[int, SignedPlantResponse]:
        caller = self.trusted_callers[call.role]
        evaluated_at = self.clock()
        if not call.verify_for_plant(
            caller.public_key,
            expected_role=call.role,
            expected_caller_key_id=caller.key_id,
            expected_audience=PHYSICAL_PLANT_AUDIENCE,
            expected_plant_key_id=self.key_id,
            expected_plant_boot_epoch=self.boot_epoch,
            evaluated_at=evaluated_at,
        ):
            raise CapabilityAdmissionRejected("plant_call_authentication_rejected")
        with self._lock:
            self._verified_checkpoint_state()
            prior = self._call_reservations.get(call.call_nonce)
            if prior is not None:
                if prior.request_sha256 == call.digest and prior.terminal is not None:
                    return prior.terminal
                # A prior call with this nonce may be in flight or may have
                # crossed the effect boundary without a terminal response.
                # Never turn that ambiguity into a signed known-no-effect claim.
                raise CapabilityRuntimeUnavailable("plant_call_outcome_indeterminate")
            self._call_reservations[call.call_nonce] = _PlantCallReservation(
                request_sha256=call.digest
            )
            if call.operation is PlantOperation.APPLY:
                self.apply_requests += 1
            boundary_time = self.clock()
            if not call.issued_at <= boundary_time < call.expires_at:
                raise CapabilityRuntimeUnavailable("plant_call_expired_before_effect")
            try:
                if call.operation is PlantOperation.CAPTURE:
                    if not isinstance(call.payload, PlantCapturePayload):
                        raise CapabilityAdmissionRejected("plant_call_payload_rejected")
                    payload: PlantStateResponsePayload | PlantSimulationResponsePayload = (
                        PlantStateResponsePayload(snapshot=self.plant.capture_state())
                    )
                elif call.operation is PlantOperation.READ:
                    if not isinstance(call.payload, PlantReadPayload):
                        raise CapabilityAdmissionRejected("plant_call_payload_rejected")
                    payload = PlantStateResponsePayload(snapshot=self.plant.read_state())
                elif call.operation is PlantOperation.SIMULATE:
                    if not isinstance(call.payload, PlantSimulatePayload):
                        raise CapabilityAdmissionRejected("plant_call_payload_rejected")
                    payload = PlantSimulationResponsePayload(
                        assessment=self.plant.simulate_candidate(call.payload.command)
                    )
                else:
                    if not isinstance(call.payload, PlantApplyPayload):
                        raise CapabilityAdmissionRejected("plant_call_payload_rejected")
                    request = call.payload
                    if boundary_time >= request.authorization_expires_at:
                        response = self._signed_failure(
                            call,
                            "authorization_expired_before_effect",
                        )
                        terminal = (409, response)
                        self._call_reservations[call.call_nonce] = (
                            _PlantCallReservation(call.digest, terminal)
                        )
                        return terminal
                    effect_deadline = min(
                        call.expires_at,
                        request.authorization_expires_at,
                    )
                    if self.checkpoint_required:
                        snapshot = self.plant.apply_authorized_command(
                            request.command,
                            expected_pre_state_version=request.expected_pre_state_version,
                            expected_pre_state_digest=request.expected_pre_state_digest,
                            expected_pre_observation_digest=(
                                request.expected_pre_observation_digest
                            ),
                            expected_post_state_digest=request.expected_post_state_digest,
                            expected_post_topology_digest=(
                                request.expected_post_topology_digest
                            ),
                            effect_deadline=effect_deadline,
                            effect_clock=self.clock,
                            durable_commit=lambda current, next_state: (
                                self._commit_checkpoint_before_swap(
                                    current,
                                    next_state,
                                    effect_deadline=effect_deadline,
                                )
                            ),
                        )
                        snapshot = self._verified_checkpoint_state()
                    else:
                        snapshot = self.plant.apply_authorized_command(
                            request.command,
                            expected_pre_state_version=request.expected_pre_state_version,
                            expected_pre_state_digest=request.expected_pre_state_digest,
                            expected_pre_observation_digest=(
                                request.expected_pre_observation_digest
                            ),
                            expected_post_state_digest=request.expected_post_state_digest,
                            expected_post_topology_digest=(
                                request.expected_post_topology_digest
                            ),
                            effect_deadline=effect_deadline,
                            effect_clock=self.clock,
                        )
                    self.commit_count += 1
                    payload = PlantStateResponsePayload(snapshot=snapshot)
            except PhysicalSimulationError as exc:
                response = self._signed_failure(call, str(exc))
                terminal = (409, response)
                self._call_reservations[call.call_nonce] = _PlantCallReservation(
                    call.digest,
                    terminal,
                )
                return terminal
            response = SignedPlantResponse.issue(
                call=call,
                status=PlantResponseStatus.OK,
                payload=payload,
                plant_boot_epoch=self.boot_epoch,
                plant_key_id=self.key_id,
                signed_at=self.clock(),
                private_key=self.private_key,
            )
            terminal = (200, response)
            self._call_reservations[call.call_nonce] = _PlantCallReservation(
                call.digest,
                terminal,
            )
            return terminal


class CapabilityObserverRuntime:
    """Signed observer with a bounded boot-scoped cache and plant read capability."""

    def __init__(
        self,
        *,
        plant: RemoteObserverPlantClient,
        plant_info: PlantHealthMetadata,
        private_key: Ed25519PrivateKey,
        key_id: str,
        observer_id: str = "signed-observer:m4g-segmented",
        boot_epoch: str | None = None,
        cache_capacity: int = MAX_OBSERVATION_CACHE,
    ) -> None:
        if cache_capacity < 1:
            raise ValueError("observer cache capacity must be positive")
        if key_id == plant_info.key_id or _same_public_key(
            private_key.public_key(),
            plant_info.public_key,
        ):
            raise ValueError("observer and plant signing identities must be distinct")
        self.plant = plant
        self.plant_info = plant_info
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id
        self.observer_id = observer_id
        self.boot_epoch = boot_epoch or str(uuid4())
        self.cache_capacity = cache_capacity
        self._lock = RLock()
        self._sequence = 0
        self._previous_digest: str | None = None
        self._cache: OrderedDict[str, SignedObservationEnvelope] = OrderedDict()
        self.capture_count = 0
        self.resolve_count = 0

    def health(self) -> ObserverHealthMetadata:
        with self._lock:
            capture_count = self.capture_count
            resolve_count = self.resolve_count
            cached = len(self._cache)
        return ObserverHealthMetadata(
            pid=os.getpid(),
            observer_id=self.observer_id,
            boot_epoch=self.boot_epoch,
            key_id=self.key_id,
            public_key_b64=_public_key_b64(self.public_key),
            plant_boot_epoch=self.plant_info.boot_epoch,
            plant_model_digest=self.plant_info.model_digest,
            capture_count=capture_count,
            resolve_count=resolve_count,
            cached_observations=cached,
        )

    def _capture(
        self,
        *,
        correlation_id: str,
        challenge_nonce: str,
        phase: ObservationPhase,
        previous_envelope_digest: str | None = None,
        permit_id: str | None = None,
        command_digest: str | None = None,
        plc_acknowledgment_digest: str | None = None,
    ) -> SignedObservationEnvelope:
        with self._lock:
            if phase is ObservationPhase.POST_DISPATCH:
                predecessor = next(
                    (
                        item
                        for item in self._cache.values()
                        if item.envelope_digest == previous_envelope_digest
                    ),
                    None,
                )
                if (
                    predecessor is None
                    or predecessor.phase is not ObservationPhase.PRE_AUTHORIZATION
                    or predecessor.correlation_id != correlation_id
                ):
                    raise CapabilityAdmissionRejected(
                        "post_observation_predecessor_rejected"
                    )
            snapshot = self.plant.capture_bound_state(
                correlation_id=correlation_id,
                challenge_nonce=challenge_nonce,
            )
            self._sequence += 1
            envelope = SignedObservationEnvelope.issue(
                snapshot=snapshot,
                correlation_id=correlation_id,
                phase=phase,
                challenge_nonce=challenge_nonce,
                observer_id=self.observer_id,
                observer_key_id=self.key_id,
                observer_boot_epoch=self.boot_epoch,
                observer_sequence=self._sequence,
                previous_envelope_digest=(
                    previous_envelope_digest
                    if phase is ObservationPhase.POST_DISPATCH
                    else self._previous_digest
                ),
                permit_id=permit_id,
                command_digest=command_digest,
                plc_acknowledgment_digest=plc_acknowledgment_digest,
                private_key=self.private_key,
            )
            self.capture_count += 1
            self._previous_digest = envelope.envelope_digest
            self._cache[envelope.observation_id] = envelope
            self._cache.move_to_end(envelope.observation_id)
            while len(self._cache) > self.cache_capacity:
                self._cache.popitem(last=False)
            return envelope

    def capture_pre(self, request: ObservationCaptureRequest) -> SignedObservationEnvelope:
        return self._capture(
            correlation_id=request.correlation_id,
            challenge_nonce=request.challenge_nonce,
            phase=ObservationPhase.PRE_AUTHORIZATION,
        )

    def resolve(self, request: ObservationResolveRequest) -> SignedObservationEnvelope:
        with self._lock:
            self.resolve_count += 1
            observation = self._cache.get(request.observation_id)
            if (
                observation is None
                or observation.envelope_digest != request.envelope_digest
            ):
                raise CapabilityAdmissionRejected("observation_not_found")
            return observation

    def capture_post(
        self,
        request: PostObservationCaptureRequest,
    ) -> SignedObservationEnvelope:
        return self._capture(
            correlation_id=request.correlation_id,
            challenge_nonce=request.challenge_nonce,
            phase=ObservationPhase.POST_DISPATCH,
            previous_envelope_digest=request.previous_envelope_digest,
            permit_id=request.permit_id,
            command_digest=request.command_digest,
            plc_acknowledgment_digest=request.plc_acknowledgment_digest,
        )


class CapabilityCandidateRuntime:
    """Candidate bridge that preserves both caller and plant signatures."""

    def __init__(
        self,
        *,
        plant: RemoteCandidatePlantClient,
        plant_info: PlantHealthMetadata,
        private_key: Ed25519PrivateKey,
        key_id: str,
        boot_epoch: str | None = None,
    ) -> None:
        if key_id == plant_info.key_id or _same_public_key(
            private_key.public_key(),
            plant_info.public_key,
        ):
            raise ValueError("candidate and plant signing identities must be distinct")
        self.plant = plant
        self.plant_info = plant_info
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id
        self.boot_epoch = boot_epoch or str(uuid4())
        self._lock = RLock()
        self.simulation_count = 0

    def health(self) -> CandidateHealthMetadata:
        with self._lock:
            count = self.simulation_count
        return CandidateHealthMetadata(
            pid=os.getpid(),
            boot_epoch=self.boot_epoch,
            key_id=self.key_id,
            public_key_b64=_public_key_b64(self.public_key),
            plant_boot_epoch=self.plant_info.boot_epoch,
            plant_model_digest=self.plant_info.model_digest,
            simulation_count=count,
        )

    def simulate(self, request: CandidateSimulationRequest) -> PlantExchange:
        exchange = self.plant.simulate_exchange(request.command)
        with self._lock:
            self.simulation_count += 1
        return exchange


class CapabilityOtRuntime:
    """Transport admission plus the existing permit-aware virtual PLC."""

    def __init__(
        self,
        *,
        device: CapabilityVirtualPlc,
        transport_replay: DurableTransportReplayLedger | DurableWorkloadReplayLedger,
        gateway_public_key: Ed25519PublicKey,
        gateway_key_id: str,
        observer_info: ObserverProcessInfo,
        permit_public_key: Ed25519PublicKey,
        permit_key_id: str,
        private_key: Ed25519PrivateKey,
        key_id: str,
        plc_id: str,
        boot_epoch: str,
        plant_info: PlantHealthMetadata,
        semantic_replay: OrderlyRestartReplayReservations,
        gateway_workload_identity: WorkloadCredentialBinding | None = None,
        local_workload_identity: LocalWorkloadIdentity | None = None,
        coordination_required: bool = False,
        coordination_journal: DurableEffectCoordinationJournal | None = None,
        plant_health_loader: Callable[[], PlantHealthMetadata] | None = None,
        coordination_anchor_required: bool = False,
        coordination_anchor_admission: CoordinationAnchorAdmissionPort | None = None,
        after_coordination_terminal_persist: Callable[[], None] | None = None,
        clock: Clock = utc_now,
    ) -> None:
        if (gateway_workload_identity is None) != (local_workload_identity is None):
            raise ValueError("gateway and OT workload identities must be configured together")
        if coordination_required and (
            gateway_workload_identity is None
            or local_workload_identity is None
            or coordination_journal is None
            or plant_health_loader is None
        ):
            raise ValueError(
                "required effect coordination needs workload identities, an OT journal, "
                "and a current plant-health loader"
            )
        if not coordination_required and (
            coordination_journal is not None
            or plant_health_loader is not None
            or coordination_anchor_required
            or coordination_anchor_admission is not None
            or after_coordination_terminal_persist is not None
        ):
            raise ValueError(
                "coordination state, anchor admission, and terminal hook require "
                "effect coordination"
            )
        if coordination_required and (
            coordination_anchor_required
            != (coordination_anchor_admission is not None)
        ):
            raise ValueError(
                "required coordination anchoring needs exactly one anchor admission port"
            )
        if device.acknowledgment_key_id != key_id or device.plc_id != plc_id:
            raise ValueError("OT runtime identity does not match its virtual PLC")
        if device.boot_epoch != boot_epoch:
            raise ValueError("OT runtime boot epoch does not match its virtual PLC")
        if not _same_public_key(
            private_key.public_key(),
            device.acknowledgment_private_key.public_key(),
        ):
            raise ValueError("OT response key does not match the PLC acknowledgment key")
        key_ids = {
            key_id,
            gateway_key_id,
            observer_info.key_id,
            permit_key_id,
            plant_info.key_id,
        }
        if len(key_ids) != 5:
            raise ValueError("OT trust-role signing key IDs must be distinct")
        _require_distinct_public_keys(
            {
                "ot": private_key.public_key(),
                "gateway": gateway_public_key,
                "observer": observer_info.public_key,
                "permit": permit_public_key,
                "plant": plant_info.public_key,
            }
        )
        self.device = device
        self.transport_replay = transport_replay
        self.gateway_public_key = gateway_public_key
        self.gateway_key_id = gateway_key_id
        self.observer_info = observer_info
        self.permit_public_key = permit_public_key
        self.permit_key_id = permit_key_id
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id
        self.plc_id = plc_id
        self.boot_epoch = boot_epoch
        self.plant_info = plant_info
        self.semantic_replay = semantic_replay
        self.gateway_workload_identity = gateway_workload_identity
        self.local_workload_identity = local_workload_identity
        self.coordination_required = coordination_required
        self.coordination_journal = coordination_journal
        self.coordination_anchor_required = coordination_anchor_required
        self.coordination_anchor_admission = coordination_anchor_admission
        self._plant_health_loader = plant_health_loader
        self._coordination_recovery: CoordinationRecoveryResult | None = None
        self._coordination_recovery_plant: PlantHealthMetadata | None = None
        self._live_commit_marker: _LiveCommitMarker | None = None
        self._after_coordination_terminal_persist = after_coordination_terminal_persist
        self._coordination_terminal_hook_armed = (
            after_coordination_terminal_persist is not None
        )
        self.clock = clock
        self._lock = RLock()
        self._coordination_lock = RLock()
        self.execute_requests = 0
        if coordination_required:
            with self._coordination_lock:
                self._refresh_coordination_recovery_locked()

    def _require_anchor_admission_locked(
        self,
        *,
        phase: CoordinationAnchorAdmissionPhase,
        effect_id: str,
        request_sha256: str,
        evaluated_at: datetime,
    ) -> None:
        if not self.coordination_anchor_required:
            return
        port = self.coordination_anchor_admission
        if port is None:
            raise CapabilityRuntimeUnavailable(
                f"effect_coordination_anchor_{phase.value}_unavailable"
            )
        try:
            decision = port.require_admission(
                phase=phase,
                effect_id=effect_id,
                request_sha256=request_sha256,
                evaluated_at=evaluated_at,
            )
        except CoordinationAnchorAdmissionError as exc:
            raise CapabilityRuntimeUnavailable(
                f"effect_coordination_anchor_{phase.value}_unavailable"
            ) from exc
        except Exception as exc:
            raise CapabilityRuntimeUnavailable(
                f"effect_coordination_anchor_{phase.value}_unavailable"
            ) from exc
        if (
            decision.status is not AnchoredRecoveryStatus.ADMISSION_READY
            or not decision.admission_allowed
        ):
            raise CapabilityRuntimeUnavailable(
                f"effect_coordination_anchor_{phase.value}_unavailable"
            )

    @staticmethod
    def _same_pinned_plant_identity(
        current: PlantHealthMetadata,
        expected: PlantHealthMetadata,
    ) -> bool:
        return (
            current.boot_epoch,
            current.key_id,
            current.public_key_b64,
            current.backend,
            current.model_digest,
            current.simulator_version,
            current.observation_source_id,
        ) == (
            expected.boot_epoch,
            expected.key_id,
            expected.public_key_b64,
            expected.backend,
            expected.model_digest,
            expected.simulator_version,
            expected.observation_source_id,
        )

    def _refresh_coordination_recovery_locked(self) -> CoordinationRecoveryResult:
        journal = self.coordination_journal
        loader = self._plant_health_loader
        if journal is None or loader is None:
            raise CapabilityRuntimeUnavailable(
                "effect_coordination_recovery_unavailable"
            )
        try:
            plant = loader()
            if not isinstance(plant, PlantHealthMetadata) or not (
                self._same_pinned_plant_identity(plant, self.plant_info)
            ):
                raise ValueError("current plant health changed its pinned identity")
            result = validate_coordination_recovery(journal.records(), plant)
        except Exception as exc:
            raise CapabilityRuntimeUnavailable(
                "effect_coordination_recovery_unavailable"
            ) from exc
        self._coordination_recovery = result
        self._coordination_recovery_plant = plant
        marker = self._live_commit_marker
        if marker is not None and not (
            result.status is CoordinationRecoveryStatus.RECOVERY_REQUIRED
            and result.reason
            is CoordinationRecoveryReason.PENDING_EFFECT_AT_PRE_STATE
            and result.pending_effect_id == marker.effect_id
        ):
            self._live_commit_marker = None
        if result.status in {
            CoordinationRecoveryStatus.INCONSISTENT,
            CoordinationRecoveryStatus.UNAVAILABLE,
        }:
            raise CapabilityRuntimeUnavailable(
                "effect_coordination_recovery_unavailable"
            )
        return result

    def _require_coordination_alignment_locked(
        self,
        *,
        query_only: bool = False,
        prepare_request: SignedEffectPrepareRequest | None = None,
        commit_request: SignedEffectCommitRequest | None = None,
    ) -> CoordinationRecoveryResult:
        result = self._refresh_coordination_recovery_locked()
        if result.status is CoordinationRecoveryStatus.ALIGNED:
            return result
        if query_only:
            return result
        marker = self._live_commit_marker
        if (
            result.status is CoordinationRecoveryStatus.RECOVERY_REQUIRED
            and result.reason
            is CoordinationRecoveryReason.PENDING_EFFECT_AT_PRE_STATE
            and marker is not None
            and result.pending_effect_id == marker.effect_id
            and (
                (
                    prepare_request is not None
                    and marker.matches_prepare(
                        prepare_request,
                        boot_epoch=self.boot_epoch,
                    )
                )
                or (
                    commit_request is not None
                    and marker.matches(commit_request, boot_epoch=self.boot_epoch)
                )
            )
        ):
            return result
        raise CapabilityAdmissionRejected("effect_reconciliation_required")

    def _coordination_recovery_projection_locked(
        self,
    ) -> OtCoordinationRecoveryMetadata:
        result = self._coordination_recovery
        plant = self._coordination_recovery_plant
        if result is None or plant is None:
            raise CapabilityRuntimeUnavailable(
                "effect_coordination_recovery_unavailable"
            )
        return OtCoordinationRecoveryMetadata(
            status=result.status,
            reason=result.reason,
            record_count=result.record_count,
            applied_effect_count=result.applied_effect_count,
            pending_effect_count=result.pending_effect_count,
            plant_model_digest=plant.model_digest,
            plant_state_version=result.plant_state_version,
            plant_state_digest=result.plant_state_digest,
            latest_applied_state_version=result.latest_applied_state_version,
            latest_applied_state_digest=result.latest_applied_state_digest,
            pending_effect_id=result.pending_effect_id,
            pending_expected_post_state_version=(
                result.pending_expected_post_state_version
            ),
            pending_expected_post_state_digest=(
                result.pending_expected_post_state_digest
            ),
            live_commit_armed=self._live_commit_marker is not None,
        )

    def _coordination_context(
        self,
        *,
        evaluated_at: datetime,
    ) -> _EffectCoordinationContext:
        if not self.coordination_required:
            raise CapabilityAdmissionRejected("effect_coordination_is_disabled")
        gateway_binding = self.gateway_workload_identity
        local_identity = self.local_workload_identity
        journal = self.coordination_journal
        if gateway_binding is None or local_identity is None or journal is None:
            raise CapabilityRuntimeUnavailable("effect_coordination_is_unconfigured")
        try:
            gateway = gateway_binding.resolve(now=evaluated_at)
            local = local_identity.resolve(now=evaluated_at)
        except WorkloadCredentialRejected as exc:
            raise CapabilityAdmissionRejected(
                "effect_coordination_workload_identity_rejected"
            ) from exc
        except WorkloadIdentityUnavailable as exc:
            raise CapabilityRuntimeUnavailable(
                "effect_coordination_workload_trust_unavailable"
            ) from exc
        if (
            local.key_id != self.key_id
            or local.public_key.public_bytes_raw() != self.public_key.public_bytes_raw()
        ):
            raise CapabilityAdmissionRejected(
                "effect_coordination_workload_identity_rejected"
            )
        return _EffectCoordinationContext(
            journal=journal,
            verifier=gateway_binding.verifier,
            gateway=gateway,
            local=local,
            signer=WorkloadSigner(
                credential=local.credential,
                private_key=local_identity.signer.private_key,
            ),
        )

    def _run_coordination_terminal_hook(self) -> None:
        hook = self._after_coordination_terminal_persist
        if hook is None or not self._coordination_terminal_hook_armed:
            return
        self._coordination_terminal_hook_armed = False
        hook()

    def _raise_coordination_journal_failure(
        self,
        exc: CoordinationJournalError,
    ) -> Never:
        if isinstance(
            exc,
            (CoordinationCollisionError, IllegalCoordinationTransition),
        ):
            raise CapabilityAdmissionRejected(
                "effect_coordination_state_rejected"
            ) from exc
        raise CapabilityRuntimeUnavailable("effect_coordination_journal_unavailable") from exc

    @staticmethod
    def _latest_retained_effect_outcome(
        record: CoordinationJournalRecord,
    ) -> SignedEffectOutcome | None:
        for attempt in reversed(record.attempts):
            if (
                isinstance(attempt, (EffectCommitAttempt, EffectQueryAttempt))
                and attempt.outcome is not None
            ):
                return attempt.outcome
        return None

    @staticmethod
    def _retained_commit_outcome(
        record: CoordinationJournalRecord,
        request: SignedEffectCommitRequest,
    ) -> SignedEffectOutcome | None:
        for attempt in reversed(record.attempts):
            if (
                isinstance(attempt, EffectCommitAttempt)
                and attempt.request_sha256 == request.digest
            ):
                return attempt.outcome
        return None

    def _stored_receipt_complete_for_query(
        self,
        receipt: CoordinationReceipt,
        context: _EffectCoordinationContext,
        *,
        evaluated_at: datetime,
    ) -> bool:
        prepare = receipt.prepare_request
        return (
            receipt.verify_historical_for_request(
                context.verifier,
                request=prepare,
                expected_gateway_subject=context.gateway.subject,
                expected_coordinator_subject=context.local.subject,
                evaluated_at=evaluated_at,
            )
            and self._dispatch_complete_for_historical_reconciliation(
                prepare.dispatch,
                expected_plc_key_id=receipt.coordinator_key_id,
                evaluated_at=receipt.prepared_at,
            )
        )

    def _receipt_complete_for_prepare_response(
        self,
        receipt: CoordinationReceipt,
        request: SignedEffectPrepareRequest,
        context: _EffectCoordinationContext,
        *,
        evaluated_at: datetime,
    ) -> bool:
        return (
            receipt.prepare_request == request
            and receipt.verify_for_request(
                context.verifier,
                request=request,
                expected_gateway_subject=context.gateway.subject,
                expected_coordinator_subject=context.local.subject,
                evaluated_at=evaluated_at,
            )
            and self._dispatch_complete_for_ot(
                request.dispatch,
                evaluated_at=evaluated_at,
            )
        )

    def _stored_acceptance_complete(
        self,
        acceptance: DurableCommitAcceptance,
        context: _EffectCoordinationContext,
        *,
        evaluated_at: datetime,
    ) -> bool:
        dispatch = acceptance.commit_request.receipt.prepare_request.dispatch
        observation = dispatch.pre_observation
        permit = dispatch.permit
        return acceptance.verify_for_commit(
            context.verifier,
            request=acceptance.commit_request,
            expected_gateway_subject=context.gateway.subject,
            expected_coordinator_subject=context.local.subject,
            observer_public_key=self.observer_info.public_key,
            expected_observer_id=self.observer_info.observer_id,
            expected_observer_key_id=self.observer_info.key_id,
            expected_observer_boot_epoch=observation.observer_boot_epoch,
            permit_public_key=self.permit_public_key,
            expected_permit_key_id=self.permit_key_id,
            expected_plc_id=self.plc_id,
            expected_plc_key_id=acceptance.coordinator_credential.credential.key_id,
            expected_plc_boot_epoch=permit.target_plc_boot_epoch,
            evaluated_at=evaluated_at,
        )

    def _stored_acknowledgment_complete(
        self,
        acknowledgment: PlcCommandAcknowledgment,
        acceptance: DurableCommitAcceptance,
    ) -> bool:
        dispatch = acceptance.commit_request.receipt.prepare_request.dispatch
        permit = dispatch.permit
        return acknowledgment.verify_for_transaction(
            acceptance.coordinator_credential.credential.public_key,
            request=dispatch.request,
            permit=dispatch.permit,
            pre_observation=dispatch.pre_observation,
            expected_plc_id=self.plc_id,
            expected_plc_key_id=acceptance.coordinator_credential.credential.key_id,
            expected_plc_boot_epoch=permit.target_plc_boot_epoch,
        )

    def _query_outcome_complete(
        self,
        request: SignedEffectQueryRequest,
        outcome: SignedEffectOutcome,
        context: _EffectCoordinationContext,
        *,
        evaluated_at: datetime,
    ) -> bool:
        record = context.journal.get(request.effect)
        if record is None:
            return False
        acceptance = outcome.acceptance
        if acceptance is None:
            receipt = record.latest_receipt
            if (
                record.latest_acceptance is not None
                or receipt is None
                or not self._stored_receipt_complete_for_query(
                    receipt,
                    context,
                    evaluated_at=evaluated_at,
                )
            ):
                return False
            dispatch = receipt.prepare_request.dispatch
            expected_plc_key_id = receipt.coordinator_key_id
        else:
            if (
                record.latest_acceptance != acceptance
                or not self._stored_acceptance_complete(
                    acceptance,
                    context,
                    evaluated_at=evaluated_at,
                )
                or (
                    outcome.acknowledgment is not None
                    and not self._stored_acknowledgment_complete(
                        outcome.acknowledgment,
                        acceptance,
                    )
                )
            ):
                return False
            dispatch = acceptance.commit_request.receipt.prepare_request.dispatch
            expected_plc_key_id = acceptance.coordinator_credential.credential.key_id
        expected_disposition = {
            CoordinationState.NOT_DISPATCHED: EffectDisposition.NOT_DISPATCHED,
            CoordinationState.COMMIT_ACCEPTED: EffectDisposition.UNKNOWN_EFFECT,
            CoordinationState.UNKNOWN_EFFECT: EffectDisposition.UNKNOWN_EFFECT,
            CoordinationState.APPLIED: EffectDisposition.APPLIED,
            CoordinationState.REJECTED: EffectDisposition.REJECTED,
        }.get(record.state)
        observation = dispatch.pre_observation
        permit = dispatch.permit
        return (
            expected_disposition is outcome.disposition
            and outcome.verify_for_request(
                context.verifier,
                request=request,
                expected_gateway_subject=context.gateway.subject,
                expected_coordinator_subject=context.local.subject,
                observer_public_key=self.observer_info.public_key,
                expected_observer_id=self.observer_info.observer_id,
                expected_observer_key_id=self.observer_info.key_id,
                expected_observer_boot_epoch=observation.observer_boot_epoch,
                permit_public_key=self.permit_public_key,
                expected_permit_key_id=self.permit_key_id,
                expected_plc_id=self.plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=permit.target_plc_boot_epoch,
                evaluated_at=evaluated_at,
            )
        )

    def prepare_effect(
        self,
        request: SignedEffectPrepareRequest,
    ) -> CoordinationReceipt:
        evaluated_at = self.clock()
        context = self._coordination_context(evaluated_at=evaluated_at)
        if (
            request.sender_credential != context.gateway.credential
            or not request.verify_complete_for_admission(
                context.verifier,
                expected_gateway_subject=context.gateway.subject,
                observer_public_key=self.observer_info.public_key,
                expected_observer_id=self.observer_info.observer_id,
                expected_observer_key_id=self.observer_info.key_id,
                expected_observer_boot_epoch=self.observer_info.boot_epoch,
                permit_public_key=self.permit_public_key,
                expected_permit_key_id=self.permit_key_id,
                expected_plc_id=self.plc_id,
                expected_plc_key_id=self.key_id,
                expected_plc_boot_epoch=self.boot_epoch,
                evaluated_at=evaluated_at,
                expected_audience=EFFECT_COORDINATOR_AUDIENCE,
            )
            or not self._dispatch_complete_for_ot(
                request.dispatch,
                evaluated_at=evaluated_at,
            )
        ):
            raise CapabilityAdmissionRejected("effect_prepare_authentication_rejected")
        try:
            with self._coordination_lock:
                self._require_anchor_admission_locked(
                    phase=CoordinationAnchorAdmissionPhase.PREPARE,
                    effect_id=request.effect.effect_id,
                    request_sha256=request.digest,
                    evaluated_at=evaluated_at,
                )
                self._require_coordination_alignment_locked(prepare_request=request)
                pending = context.journal.pending()
                if any(record.effect != request.effect for record in pending):
                    raise CapabilityAdmissionRejected(
                        "effect_reconciliation_required"
                    )
                existing = context.journal.get(request.effect)
                receipt = context.journal.prepare_effect(
                    request,
                    lambda exact_request, retained_at: CoordinationReceipt.issue(
                        request=exact_request,
                        signer=context.signer,
                        prepared_at=retained_at,
                    ),
                    recorded_at=evaluated_at,
                )
                if not self._receipt_complete_for_prepare_response(
                    receipt,
                    request,
                    context,
                    evaluated_at=evaluated_at,
                ):
                    raise CapabilityRuntimeUnavailable(
                        "effect_prepare_stored_receipt_rejected"
                    )
                if existing is None:
                    self._live_commit_marker = _LiveCommitMarker(
                        effect_id=request.effect.effect_id,
                        prepare_request_sha256=request.digest,
                        receipt_sha256=receipt.digest,
                        runtime_boot_epoch=self.boot_epoch,
                    )
                return receipt
        except CoordinationJournalError as exc:
            self._raise_coordination_journal_failure(exc)
        except (OSError, ValueError) as exc:
            raise CapabilityRuntimeUnavailable(
                "effect_prepare_outcome_unavailable"
            ) from exc

    def _retain_unknown_commit_outcome(
        self,
        request: SignedEffectCommitRequest,
        acceptance: DurableCommitAcceptance,
        context: _EffectCoordinationContext,
    ) -> SignedEffectOutcome:
        signed_at = self.clock()
        try:
            outcome = SignedEffectOutcome.issue(
                request=request,
                disposition=EffectDisposition.UNKNOWN_EFFECT,
                reason="device_outcome_unavailable_after_commit_acceptance",
                signer=context.signer,
                signed_at=signed_at,
                acceptance=acceptance,
            )
        except (OSError, ValueError) as exc:
            try:
                context.journal.mark_commit_unknown(
                    request,
                    reason="signed_unknown_outcome_unavailable_after_commit_acceptance",
                    recorded_at=signed_at,
                )
            except CoordinationJournalError:
                pass
            raise EffectCommitIndeterminate(
                "effect_commit_indeterminate_query_required"
            ) from exc
        try:
            context.journal.finish_commit(
                request,
                outcome,
                recorded_at=signed_at,
            )
        except (CoordinationJournalError, OSError, ValueError) as exc:
            raise EffectCommitIndeterminate(
                "effect_commit_indeterminate_query_required"
            ) from exc
        return outcome

    def commit_effect(
        self,
        request: SignedEffectCommitRequest,
    ) -> SignedEffectOutcome:
        evaluated_at = self.clock()
        context = self._coordination_context(evaluated_at=evaluated_at)
        dispatch = request.receipt.prepare_request.dispatch
        if (
            request.sender_credential != context.gateway.credential
            or not request.verify_complete_for_admission(
                context.verifier,
                expected_gateway_subject=context.gateway.subject,
                expected_coordinator_subject=context.local.subject,
                observer_public_key=self.observer_info.public_key,
                expected_observer_id=self.observer_info.observer_id,
                expected_observer_key_id=self.observer_info.key_id,
                expected_observer_boot_epoch=self.observer_info.boot_epoch,
                permit_public_key=self.permit_public_key,
                expected_permit_key_id=self.permit_key_id,
                expected_plc_id=self.plc_id,
                expected_plc_key_id=self.key_id,
                expected_plc_boot_epoch=self.boot_epoch,
                evaluated_at=evaluated_at,
                expected_audience=EFFECT_COORDINATOR_AUDIENCE,
            )
            or not self._dispatch_complete_for_ot(
                dispatch,
                evaluated_at=evaluated_at,
            )
        ):
            raise CapabilityAdmissionRejected("effect_commit_authentication_rejected")

        def issue_acceptance(
            exact_request: SignedEffectCommitRequest,
            *,
            accepted_at: datetime,
            transition_sequence: Literal[3],
        ) -> DurableCommitAcceptance:
            return DurableCommitAcceptance.issue(
                request=exact_request,
                signer=context.signer,
                accepted_at=accepted_at,
                transition_sequence=transition_sequence,
            )

        with self._coordination_lock:
            self._require_anchor_admission_locked(
                phase=CoordinationAnchorAdmissionPhase.COMMIT,
                effect_id=request.effect.effect_id,
                request_sha256=request.digest,
                evaluated_at=evaluated_at,
            )
            self._require_coordination_alignment_locked(
                commit_request=request,
            )
            try:
                admission = context.journal.begin_commit(
                    request,
                    issue_acceptance,
                    recorded_at=evaluated_at,
                )
            except CoordinationJournalError as exc:
                self._live_commit_marker = None
                self._raise_coordination_journal_failure(exc)
            except (OSError, ValueError) as exc:
                self._live_commit_marker = None
                raise CapabilityRuntimeUnavailable(
                    "effect_commit_acceptance_unavailable"
                ) from exc
            self._live_commit_marker = None

            acceptance = admission.acceptance
            if (
                acceptance is None
                or acceptance.commit_request != request
                or not self._stored_acceptance_complete(
                    acceptance,
                    context,
                    evaluated_at=evaluated_at,
                )
            ):
                raise EffectCommitIndeterminate(
                    "effect_commit_indeterminate_query_required"
                )
            if admission.status is CommitAdmissionStatus.TERMINAL:
                retained = self._retained_commit_outcome(
                    admission.record,
                    request,
                )
                if (
                    retained is None
                    or retained.request_kind != "commit"
                    or retained.request_sha256 != request.digest
                    or retained.acceptance != acceptance
                    or not retained.verify_for_request(
                        context.verifier,
                        request=request,
                        expected_gateway_subject=context.gateway.subject,
                        expected_coordinator_subject=context.local.subject,
                        observer_public_key=self.observer_info.public_key,
                        expected_observer_id=self.observer_info.observer_id,
                        expected_observer_key_id=self.observer_info.key_id,
                        expected_observer_boot_epoch=self.observer_info.boot_epoch,
                        permit_public_key=self.permit_public_key,
                        expected_permit_key_id=self.permit_key_id,
                        expected_plc_id=self.plc_id,
                        expected_plc_key_id=self.key_id,
                        expected_plc_boot_epoch=self.boot_epoch,
                        evaluated_at=evaluated_at,
                    )
                ):
                    raise EffectCommitIndeterminate(
                        "effect_commit_indeterminate_query_required"
                    )
                self._refresh_coordination_recovery_locked()
                return retained
            if admission.status is not CommitAdmissionStatus.NEW:
                raise EffectCommitIndeterminate(
                    "effect_commit_indeterminate_query_required"
                )

            with self._lock:
                self.execute_requests += 1
            try:
                acknowledgment = self.device.execute(
                    request=dispatch.request,
                    permit=dispatch.permit,
                    pre_observation=dispatch.pre_observation,
                    decision=dispatch.decision,
                    assessment=dispatch.assessment,
                )
                disposition = EffectDisposition(acknowledgment.status.value)
                outcome = SignedEffectOutcome.issue(
                    request=request,
                    disposition=disposition,
                    reason=acknowledgment.reason,
                    signer=context.signer,
                    signed_at=self.clock(),
                    acceptance=acceptance,
                    acknowledgment=acknowledgment,
                )
            except Exception:
                return self._retain_unknown_commit_outcome(
                    request,
                    acceptance,
                    context,
                )
            try:
                context.journal.finish_commit(
                    request,
                    outcome,
                    recorded_at=outcome.signed_at,
                )
            except (CoordinationJournalError, OSError, ValueError) as exc:
                raise EffectCommitIndeterminate(
                    "effect_commit_indeterminate_query_required"
                ) from exc
            if disposition in {
                EffectDisposition.APPLIED,
                EffectDisposition.REJECTED,
            }:
                self._refresh_coordination_recovery_locked()
                self._run_coordination_terminal_hook()
            return outcome

    def query_effect(
        self,
        request: SignedEffectQueryRequest,
    ) -> SignedEffectOutcome:
        evaluated_at = self.clock()
        context = self._coordination_context(evaluated_at=evaluated_at)
        if (
            request.sender_credential != context.gateway.credential
            or not request.verify_workload_envelope_for_admission(
                context.verifier,
                expected_audience=EFFECT_COORDINATOR_AUDIENCE,
                expected_sender_subject=context.gateway.subject,
                evaluated_at=evaluated_at,
            )
        ):
            raise CapabilityAdmissionRejected("effect_query_authentication_rejected")

        def issue_outcome(
            exact_request: SignedEffectQueryRequest,
            record: CoordinationJournalRecord,
            retained_at: datetime,
        ) -> SignedEffectOutcome:
            acceptance = record.latest_acceptance
            prior = self._latest_retained_effect_outcome(record)
            acknowledgment: PlcCommandAcknowledgment | None = None
            if acceptance is None:
                receipt = record.latest_receipt
                if record.state not in {
                    CoordinationState.DISPATCH_ARMED,
                    CoordinationState.NOT_DISPATCHED,
                } or receipt is None or not self._stored_receipt_complete_for_query(
                    receipt,
                    context,
                    evaluated_at=retained_at,
                ):
                    raise CapabilityRuntimeUnavailable(
                        "effect_query_stored_receipt_rejected"
                    )
                disposition = EffectDisposition.NOT_DISPATCHED
                reason = "no_commit_was_durably_accepted"
            elif not self._stored_acceptance_complete(
                acceptance,
                context,
                evaluated_at=retained_at,
            ):
                raise CapabilityRuntimeUnavailable(
                    "effect_query_stored_acceptance_rejected"
                )
            elif record.state is CoordinationState.APPLIED:
                if (
                    prior is None
                    or prior.acknowledgment is None
                    or prior.acknowledgment.status is not CommandStatus.APPLIED
                ):
                    raise CapabilityRuntimeUnavailable(
                        "effect_query_record_lacks_terminal_acknowledgment"
                    )
                disposition = EffectDisposition.APPLIED
                acknowledgment = prior.acknowledgment
                reason = "stored_plc_acknowledgment_reports_applied"
            elif record.state is CoordinationState.REJECTED:
                if (
                    prior is None
                    or prior.acknowledgment is None
                    or prior.acknowledgment.status is not CommandStatus.REJECTED
                ):
                    raise CapabilityRuntimeUnavailable(
                        "effect_query_record_lacks_terminal_acknowledgment"
                    )
                disposition = EffectDisposition.REJECTED
                acknowledgment = prior.acknowledgment
                reason = "stored_plc_acknowledgment_reports_rejected"
            elif record.state in {
                CoordinationState.COMMIT_ACCEPTED,
                CoordinationState.UNKNOWN_EFFECT,
            }:
                disposition = EffectDisposition.UNKNOWN_EFFECT
                if (
                    prior is not None
                    and prior.acknowledgment is not None
                    and prior.acknowledgment.status is CommandStatus.UNKNOWN_EFFECT
                ):
                    acknowledgment = prior.acknowledgment
                    reason = "stored_plc_acknowledgment_reports_unknown"
                else:
                    reason = "commit_accepted_effect_outcome_unknown"
            else:
                raise CapabilityRuntimeUnavailable(
                    "effect_query_record_state_is_inconsistent"
                )
            if acknowledgment is not None and (
                acceptance is None
                or not self._stored_acknowledgment_complete(
                    acknowledgment,
                    acceptance,
                )
            ):
                raise CapabilityRuntimeUnavailable(
                    "effect_query_stored_acknowledgment_rejected"
                )
            return SignedEffectOutcome.issue(
                request=exact_request,
                disposition=disposition,
                reason=reason,
                signer=context.signer,
                signed_at=retained_at,
                acceptance=acceptance,
                acknowledgment=acknowledgment,
            )

        try:
            with self._coordination_lock:
                self._require_coordination_alignment_locked(query_only=True)
                outcome = context.journal.answer_query(
                    request,
                    issue_outcome,
                    recorded_at=evaluated_at,
                )
                if not self._query_outcome_complete(
                    request,
                    outcome,
                    context,
                    evaluated_at=evaluated_at,
                ):
                    raise CapabilityRuntimeUnavailable(
                        "effect_query_stored_outcome_rejected"
                    )
                final_record = context.journal.get(request.effect)
                if final_record is None:
                    raise CapabilityRuntimeUnavailable(
                        "effect_coordination_recovery_unavailable"
                    )
                if final_record.state.terminal:
                    marker = self._live_commit_marker
                    if marker is not None and marker.effect_id == request.effect.effect_id:
                        self._live_commit_marker = None
                    self._refresh_coordination_recovery_locked()
                return outcome
        except CoordinationJournalError as exc:
            self._raise_coordination_journal_failure(exc)
        except (OSError, ValueError) as exc:
            raise CapabilityRuntimeUnavailable("effect_query_outcome_unavailable") from exc

    def _dispatch_complete_for_ot(
        self,
        dispatch: SegmentedCapabilityDispatch,
        *,
        evaluated_at: datetime,
    ) -> bool:
        """Verify every trusted inner artifact before any durable admission."""

        observation = dispatch.pre_observation
        permit = dispatch.permit
        base = permit.base_permit
        return (
            evaluated_at.tzinfo is not None
            and evaluated_at.utcoffset() is not None
            and dispatch.bindings_match()
            and observation.observer_id == self.observer_info.observer_id
            and observation.observer_key_id == self.observer_info.key_id
            and observation.observer_boot_epoch == self.observer_info.boot_epoch
            and observation.verify(self.observer_info.public_key)
            and permit.signing_key_id == self.permit_key_id
            and base.signing_key_id == self.permit_key_id
            and permit.target_plc_id == self.plc_id
            and permit.target_plc_key_id == self.key_id
            and permit.target_plc_boot_epoch == self.boot_epoch
            and base.audience == self.plc_id
            and base.issued_at <= evaluated_at < base.expires_at
            and permit.verify(self.permit_public_key)
        )

    def _dispatch_complete_for_historical_reconciliation(
        self,
        dispatch: SegmentedCapabilityDispatch,
        *,
        expected_plc_key_id: str,
        evaluated_at: datetime,
    ) -> bool:
        """Use pinned role trust while preserving historical process/key bindings.

        Observer and permit role IDs remain configured pins. The PLC key ID is
        supplied by the authority-validated historical coordinator credential;
        observer and PLC boot epochs remain those signed into the dispatch.
        """

        observation = dispatch.pre_observation
        permit = dispatch.permit
        base = permit.base_permit
        return (
            evaluated_at.tzinfo is not None
            and evaluated_at.utcoffset() is not None
            and dispatch.bindings_match()
            and observation.observer_id == self.observer_info.observer_id
            and observation.observer_key_id == self.observer_info.key_id
            and observation.verify(self.observer_info.public_key)
            and permit.signing_key_id == self.permit_key_id
            and base.signing_key_id == self.permit_key_id
            and permit.target_plc_id == self.plc_id
            and permit.target_plc_key_id == expected_plc_key_id
            and base.audience == self.plc_id
            and base.issued_at <= evaluated_at < base.expires_at
            and permit.verify(self.permit_public_key)
        )

    def health(self) -> OtHealthMetadata:
        try:
            transport_count = self.transport_replay.reservation_count
            semantic_count = self.semantic_replay.reservation_count
            gateway_key_id = self.gateway_key_id
            gateway_public_key = self.gateway_public_key
            key_id = self.key_id
            public_key = self.public_key
            if self.gateway_workload_identity is not None:
                evaluated_at = self.clock()
                gateway = self.gateway_workload_identity.resolve(now=evaluated_at)
                assert self.local_workload_identity is not None
                local = self.local_workload_identity.resolve(now=evaluated_at)
                gateway_key_id = gateway.key_id
                gateway_public_key = gateway.public_key
                key_id = local.key_id
                public_key = local.public_key
        except (
            TransportReplayLedgerError,
            WorkloadReplayLedgerError,
            WorkloadIdentityError,
            ValueError,
            OSError,
        ) as exc:
            raise CapabilityRuntimeUnavailable("OT replay state is unavailable") from exc
        recovery: OtCoordinationRecoveryMetadata | None = None
        current_plant = self.plant_info
        if self.coordination_required:
            with self._coordination_lock:
                self._refresh_coordination_recovery_locked()
                recovery = self._coordination_recovery_projection_locked()
                retained_plant = self._coordination_recovery_plant
                if retained_plant is None:
                    raise CapabilityRuntimeUnavailable(
                        "effect_coordination_recovery_unavailable"
                    )
                current_plant = retained_plant
        with self._lock:
            execute_requests = self.execute_requests
            scan_counter = self.device.scan_counter
        return OtHealthMetadata(
            pid=os.getpid(),
            plc_id=self.plc_id,
            boot_epoch=self.boot_epoch,
            key_id=key_id,
            public_key_b64=_public_key_b64(public_key),
            gateway_key_id=gateway_key_id,
            gateway_public_key_b64=_public_key_b64(gateway_public_key),
            permit_key_id=self.permit_key_id,
            permit_public_key_b64=_public_key_b64(self.permit_public_key),
            plant_boot_epoch=current_plant.boot_epoch,
            plant_model_digest=current_plant.model_digest,
            plant=current_plant,
            observer_boot_epoch=self.observer_info.boot_epoch,
            transport_replay_reservations=transport_count,
            semantic_replay_reservations=semantic_count,
            execute_requests=execute_requests,
            scan_counter=scan_counter,
            coordination_recovery=recovery,
        )

    def execute(
        self,
        request: SignedSegmentedCapabilityDispatch | WorkloadSignedCapabilityDispatch,
    ) -> SignedSegmentedCapabilityResponse | WorkloadSignedCapabilityResponse:
        if self.coordination_required:
            raise CapabilityAdmissionRejected("effect_coordination_required")
        evaluated_at = self.clock()
        workload_request: WorkloadSignedCapabilityDispatch | None = None
        gateway_public_key = self.gateway_public_key
        expected_gateway_key_id = self.gateway_key_id
        signed_request: SignedSegmentedCapabilityDispatch
        if self.gateway_workload_identity is not None:
            if not isinstance(request, WorkloadSignedCapabilityDispatch):
                raise CapabilityAdmissionRejected("gateway_workload_credential_required")
            assert self.local_workload_identity is not None
            try:
                gateway = self.gateway_workload_identity.resolve(now=evaluated_at)
                local = self.local_workload_identity.resolve(now=evaluated_at)
            except WorkloadCredentialRejected as exc:
                raise CapabilityAdmissionRejected(
                    "capability_workload_identity_rejected"
                ) from exc
            except WorkloadIdentityUnavailable as exc:
                raise CapabilityRuntimeUnavailable(
                    "capability_workload_trust_unavailable"
                ) from exc
            if (
                request.sender_credential != gateway.credential
                or not request.verify(gateway.public_key, evaluated_at=evaluated_at)
                or local.key_id != self.key_id
                or local.public_key.public_bytes_raw() != self.public_key.public_bytes_raw()
            ):
                raise CapabilityAdmissionRejected(
                    "capability_workload_identity_rejected"
                )
            workload_request = request
            signed_request = request.request
            gateway_public_key = gateway.public_key
            expected_gateway_key_id = gateway.key_id
        else:
            if not isinstance(request, SignedSegmentedCapabilityDispatch):
                raise CapabilityAdmissionRejected("workload_identity_is_disabled")
            signed_request = request
        if not (
            signed_request.verify_for_admission(
                gateway_public_key,
                expected_audience=OT_CAPABILITY_AUDIENCE,
                expected_gateway_key_id=expected_gateway_key_id,
                evaluated_at=evaluated_at,
            )
            and self._dispatch_complete_for_ot(
                signed_request.dispatch,
                evaluated_at=evaluated_at,
            )
        ):
            raise CapabilityAdmissionRejected("capability_dispatch_authentication_rejected")
        try:
            reserved = self.transport_replay.reserve(
                request.transport_nonce,
                request.digest,
            )
        except (TransportReplayLedgerError, WorkloadReplayLedgerError) as exc:
            raise CapabilityRuntimeUnavailable("OT transport replay state is unavailable") from exc
        if not reserved:
            raise CapabilityAdmissionRejected("transport_request_replayed")
        dispatch = signed_request.dispatch
        with self._lock:
            self.execute_requests += 1
        try:
            acknowledgment = self.device.execute(
                request=dispatch.request,
                permit=dispatch.permit,
                pre_observation=dispatch.pre_observation,
                decision=dispatch.decision,
                assessment=dispatch.assessment,
            )
        except (ValueError, OSError) as exc:
            raise CapabilityRuntimeUnavailable("OT semantic replay state is unavailable") from exc
        if workload_request is not None:
            assert self.local_workload_identity is not None
            return WorkloadSignedCapabilityResponse.issue(
                request=workload_request,
                acknowledgment=acknowledgment,
                signer=self.local_workload_identity.signer,
                signed_at=self.clock(),
            )
        return SignedSegmentedCapabilityResponse.issue(
            request=signed_request,
            acknowledgment=acknowledgment,
            ot_key_id=self.key_id,
            signed_at=self.clock(),
            private_key=self.private_key,
        )


class SegmentedCapabilityController(CapabilityClosedLoopController):
    """Capability controller that retains the verified candidate exchange."""

    simulator: RemoteCandidatePort

    def _execute_locked(
        self,
        request: CapabilityActionRequest,
    ) -> CapabilityClosedLoopResult:
        if isinstance(self.plc, WorkloadRemoteVirtualPlcPort):
            try:
                self.plc.preflight_identity()
            except Exception as exc:
                return self._record(
                    status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
                    reasons=("ot_workload_identity_unavailable", type(exc).__name__),
                    request=request,
                    dispatch_attempts=0,
                )
        return super()._execute_locked(request)

    def _record(
        self,
        *,
        status: CapabilityClosedLoopStatus,
        reasons: tuple[str, ...],
        request: CapabilityActionRequest,
        dispatch_attempts: int,
        pre_observation: SignedObservationEnvelope | None = None,
        decision: Decision | None = None,
        command: PhysicalControlCommand | None = None,
        assessment: CandidateAssessment | None = None,
        permit: CapabilityExecutionPermit | None = None,
        acknowledgment: PlcCommandAcknowledgment | None = None,
        post_observation: SignedObservationEnvelope | None = None,
        last_observation: SignedObservationEnvelope | None = None,
    ) -> CapabilityClosedLoopResult:
        candidate_exchange = (
            self.simulator.last_exchange if assessment is not None else None
        )
        if candidate_exchange is not None:
            response_payload = candidate_exchange.response.payload
            if (
                not isinstance(response_payload, PlantSimulationResponsePayload)
                or response_payload.assessment != assessment
            ):
                candidate_exchange = None
        record = self.evidence.append(
            proposal_id=request.proposal.proposal_id,
            decision_id=(
                decision.decision_id
                if decision is not None
                else f"not-issued:{request.request_id}"
            ),
            payload={
                "event_type": "capability_closed_loop_disposition",
                "coordination_backend": "segmented-compose-http-v1",
                "status": status.value,
                "reasons": list(reasons),
                "dispatch_attempts": dispatch_attempts,
                "automatic_retry_count": 0,
                "request": request.model_dump(mode="json"),
                "pre_observation": (
                    pre_observation.model_dump(mode="json")
                    if pre_observation
                    else None
                ),
                "decision": decision.model_dump(mode="json") if decision else None,
                "command": command.model_dump(mode="json") if command else None,
                "candidate_exchange": (
                    candidate_exchange.model_dump(mode="json")
                    if candidate_exchange
                    else None
                ),
                "assessment": assessment.model_dump(mode="json") if assessment else None,
                "permit": permit.model_dump(mode="json") if permit else None,
                "acknowledgment": (
                    acknowledgment.model_dump(mode="json") if acknowledgment else None
                ),
                "post_observation": (
                    post_observation.model_dump(mode="json")
                    if post_observation
                    else None
                ),
                "last_observation": (
                    last_observation.model_dump(mode="json")
                    if last_observation
                    else None
                ),
            },
        )
        return SegmentedCapabilityClosedLoopResult(
            status=status,
            reasons=reasons,
            request=request,
            pre_observation=pre_observation,
            decision=decision,
            command=command,
            candidate_exchange=candidate_exchange,
            assessment=assessment,
            permit=permit,
            acknowledgment=acknowledgment,
            post_observation=post_observation,
            last_observation=last_observation,
            dispatch_attempts=dispatch_attempts,
            execution_evidence_hash=record.record_hash,
        )


class CapabilityGatewayRuntime:
    """One serialized gateway/controller over pinned segmented capabilities."""

    def __init__(
        self,
        *,
        authorization: LocalLab,
        controller: SegmentedCapabilityController,
        observer: RemoteObservationPort,
        discovery: SegmentedCapabilityDiscovery,
        gateway_key_id: str,
        agent_workload_verifier: WorkloadIdentityVerifier | None = None,
        agent_workload_subject: str | None = None,
        coordination_required: bool = False,
        coordination_journal: DurableGatewayCoordinationJournal | None = None,
        degraded_operation: (
            DegradedOperationGate | PublishedDegradedOperationGate | None
        ) = None,
        clock: Clock = utc_now,
    ) -> None:
        if (agent_workload_verifier is None) != (agent_workload_subject is None):
            raise ValueError(
                "agent workload verifier and stable subject must be configured together"
            )
        plc = getattr(controller, "plc", None)
        if coordination_required:
            if coordination_journal is None:
                raise ValueError("required effect coordination needs a gateway journal")
            if not isinstance(plc, CoordinatedWorkloadRemoteVirtualPlcPort):
                raise ValueError("required effect coordination needs a coordinated OT port")
            if plc.coordination_journal is not coordination_journal:
                raise ValueError("gateway runtime and OT port must share one journal")
        elif coordination_journal is not None or isinstance(
            plc,
            CoordinatedWorkloadRemoteVirtualPlcPort,
        ):
            raise ValueError("disabled effect coordination cannot retain coordination state")
        self.authorization = authorization
        self.controller = controller
        self.observer = observer
        self.discovery = discovery
        self.gateway_key_id = gateway_key_id
        self.agent_workload_verifier = agent_workload_verifier
        self.agent_workload_subject = agent_workload_subject
        self.coordination_required = coordination_required
        self.coordination_journal = coordination_journal
        self.degraded_operation = degraded_operation
        self.clock = clock
        # Agent-facing pre-capture and action entry points share this lock.  A
        # capture flood therefore cannot evict the active predecessor after an
        # action has entered authorization and before its post observation.
        self._transaction_lock = RLock()

    def capture_pre(
        self,
        request: ObservationCaptureRequest,
    ) -> SignedObservationEnvelope:
        with self._transaction_lock:
            return self.observer.capture_pre(
                correlation_id=request.correlation_id,
                challenge_nonce=request.challenge_nonce,
            )

    @staticmethod
    def _record_binds_reconciliation_action(
        record: CoordinationJournalRecord,
        action: CapabilityActionRequest,
    ) -> bool:
        prepare_attempts = tuple(
            attempt
            for attempt in record.attempts
            if isinstance(attempt, EffectPrepareAttempt)
        )
        return (
            record.effect.request_sha256 == action.digest
            and bool(prepare_attempts)
            and all(
                attempt.request.effect == record.effect
                and attempt.request.dispatch.request == action
                for attempt in prepare_attempts
            )
        )

    def reconcile_effect(
        self,
        request: WorkloadAuthenticatedEffectReconciliation,
    ) -> CapabilityOutcomeResolution | CapabilityOutcomePending:
        """Resolve one retained action without re-entering the execution path."""

        with self._transaction_lock:
            if not self.coordination_required:
                raise CapabilityAdmissionRejected("effect_coordination_is_disabled")
            verifier = self.agent_workload_verifier
            agent_subject = self.agent_workload_subject
            if verifier is None or agent_subject is None:
                raise CapabilityAdmissionRejected(
                    "agent_reconciliation_identity_rejected"
                )
            evaluated_at = self.clock()
            try:
                verification = verifier.verify_credential_with_receipt(
                    request.sender_credential,
                    expected_role=WorkloadRole.AGENT,
                    expected_audience=GATEWAY_CAPABILITY_AUDIENCE,
                    expected_subject=agent_subject,
                    expected_actor_id=request.request.proposal.actor_id,
                    now=evaluated_at,
                )
            except WorkloadCredentialRejected as exc:
                raise CapabilityAdmissionRejected(
                    "agent_reconciliation_identity_rejected"
                ) from exc
            except WorkloadIdentityUnavailable as exc:
                raise CapabilityRuntimeUnavailable(
                    "agent_reconciliation_trust_unavailable"
                ) from exc
            if not request.verify_for_admission(
                verifier,
                expected_agent_subject=agent_subject,
                evaluated_at=evaluated_at,
            ) or not request.verify(verification.public_key):
                raise CapabilityAdmissionRejected(
                    "agent_reconciliation_proof_rejected"
                )

            journal = self.coordination_journal
            if journal is None:
                raise CapabilityRuntimeUnavailable(
                    "gateway_coordination_journal_unavailable"
                )
            action = request.request
            try:
                record = journal.find_action(
                    action.digest,
                    action.proposal.actor_id,
                    action.proposal.nonce,
                )
            except CoordinationCollisionError as exc:
                raise CapabilityAdmissionRejected(
                    "agent_reconciliation_action_conflict"
                ) from exc
            except CoordinationJournalError as exc:
                raise CapabilityRuntimeUnavailable(
                    "gateway_coordination_journal_unavailable"
                ) from exc
            if record is None:
                raise CapabilityAdmissionRejected("coordinated_action_not_found")
            if not self._record_binds_reconciliation_action(record, action):
                raise CapabilityAdmissionRejected(
                    "agent_reconciliation_action_conflict"
                )

            plc = getattr(self.controller, "plc", None)
            if not isinstance(plc, CoordinatedWorkloadRemoteVirtualPlcPort):
                raise CapabilityRuntimeUnavailable(
                    "effect_reconciliation_unavailable"
                )
            state_before_request = record.state
            try:
                evidence = plc.reconcile_effect_evidence(record.effect)
            except CapabilityTransportRejected as exc:
                reason = {
                    "coordination_effect_not_recorded": "coordinated_action_not_found",
                    "effect_was_not_committed": "effect_was_not_committed",
                    "effect_not_query_resolved": "effect_not_query_resolved",
                }.get(exc.reason_code)
                if reason is None:
                    raise CapabilityRuntimeUnavailable(
                        "effect_reconciliation_unavailable"
                    ) from exc
                raise CapabilityAdmissionRejected(reason) from exc
            except CapabilityTransportError as exc:
                reason = str(exc)
                if reason not in {
                    "gateway_coordination_journal_unavailable",
                    "effect_reconciliation_unavailable",
                    "retained_effect_verification_failed",
                }:
                    reason = "effect_reconciliation_unavailable"
                raise CapabilityRuntimeUnavailable(reason) from exc

            try:
                final_record = journal.get(record.effect)
            except CoordinationJournalError as exc:
                raise CapabilityRuntimeUnavailable(
                    "gateway_coordination_journal_unavailable"
                ) from exc
            if final_record is None:
                raise CapabilityRuntimeUnavailable(
                    "retained_effect_verification_failed"
                )
            if isinstance(evidence, CapabilityOutcomeResolution):
                expected_state = CoordinationState(evidence.disposition.value)
                final_state_valid = final_record.state is expected_state
            else:
                final_state_valid = (
                    final_record.state is CoordinationState.UNKNOWN_EFFECT
                )
            if (
                not final_state_valid
                or final_record.latest_evidence_sha256 != evidence.outcome.digest
            ):
                raise CapabilityRuntimeUnavailable(
                    "retained_effect_verification_failed"
                )

            self.authorization.gateway.evidence.append(
                proposal_id=action.proposal.proposal_id,
                decision_id=f"effect-reconciliation:{record.effect.effect_id}",
                payload={
                    "event_type": "capability_effect_reconciliation",
                    "entrypoint": "agent-to-segmented-gateway",
                    "proof_sha256": request.digest,
                    "action_request_sha256": action.digest,
                    "effect_sha256": record.effect.digest,
                    "query_request_sha256": evidence.query.digest,
                    "outcome_sha256": evidence.outcome.digest,
                    "reconciliation_evidence_sha256": evidence.digest,
                    "journal_evidence_sha256": final_record.latest_evidence_sha256,
                    "prior_state": evidence.prior_state.value,
                    "state_before_request": state_before_request.value,
                    "final_state": final_record.state.value,
                    "disposition": evidence.disposition.value,
                    "commit_retry_count": 0,
                    "post_observation_status": "not_attempted",
                    **verification.evidence_fields(),
                },
            )
            return evidence

    def execute(
        self,
        request: CapabilityActionRequest | WorkloadAuthenticatedCapabilityAction,
    ) -> SegmentedCapabilityClosedLoopResult:
        # This is the active full-capability action entry.  Degraded admission
        # therefore precedes workload identity, policy/safety, replay,
        # coordination, permit creation, and dispatch.  Reconciliation has a
        # separate method and remains available to close an uncertain effect.
        action = (
            request.request
            if isinstance(request, WorkloadAuthenticatedCapabilityAction)
            else request
        )
        evaluated_at = self.clock()
        if self.degraded_operation is not None:
            untrusted_action_sha256 = action.digest
            try:
                admission = self.degraded_operation.evaluate(
                    action.proposal,
                    now=evaluated_at,
                )
            except Exception:
                self.authorization.gateway.evidence.append(
                    proposal_id=f"untrusted:{untrusted_action_sha256}",
                    decision_id=f"m5-degraded-admission:{untrusted_action_sha256}",
                    payload={
                        "event_type": "m5_degraded_runtime_admission",
                        "entrypoint": "agent-to-segmented-gateway",
                        "untrusted_action_sha256": untrusted_action_sha256,
                        "outcome": "unavailable",
                        "reason": "m5_degraded_admission_unavailable",
                        "execution_authorized": False,
                    },
                )
                raise CapabilityAdmissionRejected(
                    "m5_degraded_admission_unavailable"
                ) from None
            if not admission.may_enter_primary_assurance:
                self.authorization.gateway.evidence.append(
                    proposal_id=f"untrusted:{untrusted_action_sha256}",
                    decision_id=f"m5-degraded-admission:{untrusted_action_sha256}",
                    payload={
                        "event_type": "m5_degraded_runtime_admission",
                        "entrypoint": "agent-to-segmented-gateway",
                        "untrusted_action_sha256": untrusted_action_sha256,
                        "admission": admission.model_dump(mode="json"),
                        "execution_authorized": False,
                    },
                )
                raise CapabilityAdmissionRejected(
                    f"m5_degraded_{admission.outcome.value}"
                )
        if self.agent_workload_verifier is not None:
            if not isinstance(request, WorkloadAuthenticatedCapabilityAction):
                raise CapabilityAdmissionRejected("agent_workload_credential_required")
            assert self.agent_workload_subject is not None
            try:
                verification = self.agent_workload_verifier.verify_credential_with_receipt(
                    request.sender_credential,
                    expected_role=WorkloadRole.AGENT,
                    expected_audience=GATEWAY_CAPABILITY_AUDIENCE,
                    expected_subject=self.agent_workload_subject,
                    expected_actor_id=action.proposal.actor_id,
                    now=evaluated_at,
                )
            except WorkloadCredentialRejected as exc:
                raise CapabilityAdmissionRejected(
                    "agent_workload_identity_rejected"
                ) from exc
            except WorkloadIdentityUnavailable as exc:
                raise CapabilityRuntimeUnavailable(
                    "agent_workload_trust_unavailable"
                ) from exc
            if not request.verify(
                verification.public_key,
                evaluated_at=evaluated_at,
            ):
                raise CapabilityAdmissionRejected("agent_workload_proof_rejected")
            action = request.request
            self.authorization.gateway.evidence.append(
                proposal_id=action.proposal.proposal_id,
                decision_id=f"identity-admission:{action.request_id}",
                payload={
                    "event_type": "workload_identity_admission",
                    "entrypoint": "agent-to-segmented-gateway",
                    "proof_sha256": request.digest,
                    **verification.evidence_fields(),
                },
            )
        else:
            if isinstance(request, WorkloadAuthenticatedCapabilityAction):
                raise CapabilityAdmissionRejected("workload_identity_is_disabled")
        with self._transaction_lock:
            if self.coordination_required:
                journal = self.coordination_journal
                if journal is None:
                    raise CapabilityRuntimeUnavailable(
                        "required gateway coordination journal is unavailable"
                    )
                try:
                    retained = journal.find_action(
                        action.digest,
                        action.proposal.actor_id,
                        action.proposal.nonce,
                    )
                except CoordinationCollisionError as exc:
                    raise CapabilityAdmissionRejected(
                        "agent_action_coordination_conflict"
                    ) from exc
                except CoordinationJournalError as exc:
                    raise CapabilityRuntimeUnavailable(
                        "gateway coordination journal is unavailable"
                    ) from exc
                if retained is not None:
                    raise CapabilityAdmissionRejected(
                        "agent_action_already_coordinated"
                    )
                try:
                    pending = journal.pending()
                except CoordinationJournalError as exc:
                    raise CapabilityRuntimeUnavailable(
                        "gateway_coordination_journal_unavailable"
                    ) from exc
                if pending:
                    raise CapabilityAdmissionRejected(
                        "effect_reconciliation_required"
                    )
            result = self.controller.execute(action)
            if not isinstance(result, SegmentedCapabilityClosedLoopResult):
                raise RuntimeError("segmented controller returned an invalid terminal model")
            return result

    def health(self) -> dict[str, Any]:
        plc = getattr(self.controller, "plc", None)
        if isinstance(plc, WorkloadRemoteVirtualPlcPort):
            # Readiness is a current trust decision. A stale health response
            # must not hide a missing, corrupt, rolled-back, or revoked
            # consequence-path credential.
            plc.preflight_identity()
        degraded_readiness: dict[str, Any] | None = None
        if isinstance(self.degraded_operation, PublishedDegradedOperationGate):
            try:
                degraded_readiness = self.degraded_operation.readiness(
                    now=self.clock()
                )
            except Exception as exc:
                raise CapabilityRuntimeUnavailable(
                    "required M5 signed publication is unavailable"
                ) from exc
        coordination_records = 0
        coordination_pending = 0
        if self.coordination_required:
            journal = self.coordination_journal
            if journal is None:
                raise CapabilityRuntimeUnavailable(
                    "required gateway coordination journal is unavailable"
                )
            try:
                records = journal.records()
            except CoordinationJournalError as exc:
                raise CapabilityRuntimeUnavailable(
                    "gateway coordination journal is unavailable"
                ) from exc
            coordination_records = len(records)
            coordination_pending = sum(
                not record.state.terminal for record in records
            )
        return {
            "schema_version": "m4g-gateway-health-v1",
            "status": "ready",
            "role": "segmented-gateway",
            "pid": os.getpid(),
            "gateway_key_id": self.gateway_key_id,
            "effect_coordination_mode": (
                "required" if self.coordination_required else "disabled"
            ),
            "coordination_backend": (
                "durable-prepare-commit-query-http-v1"
                if self.coordination_required
                else "segmented-compose-http-v1"
            ),
            "coordination_journal_records": coordination_records,
            "coordination_pending_effects": coordination_pending,
            "coordination_startup_recovery": "not-attempted",
            "m5_signed_publication_mode": (
                "required"
                if isinstance(
                    self.degraded_operation,
                    PublishedDegradedOperationGate,
                )
                else (
                    "legacy"
                    if isinstance(self.degraded_operation, DegradedOperationGate)
                    else "disabled"
                )
            ),
            "m5_degraded_readiness": degraded_readiness,
            "plant_boot_epoch": self.discovery.plant.boot_epoch,
            "observer_boot_epoch": self.discovery.observer.boot_epoch,
            "candidate_boot_epoch": self.discovery.candidate.boot_epoch,
            "ot_boot_epoch": self.discovery.ot.boot_epoch,
            "evidence_records": len(self.authorization.gateway.evidence.records),
        }


RuntimeT = TypeVar("RuntimeT")


class _LazyProvider(Generic[RuntimeT]):
    def __init__(self, factory: Callable[[], RuntimeT]) -> None:
        self.factory = factory
        self._lock = RLock()
        self._runtime: RuntimeT | None = None

    def __call__(self) -> RuntimeT:
        if self._runtime is None:
            with self._lock:
                if self._runtime is None:
                    self._runtime = self.factory()
        return self._runtime


def _expected_environment(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise CapabilityRuntimeUnavailable(f"required runtime setting is missing: {name}")
    return value


def _configured_legacy_m5_degraded_gate() -> DegradedOperationGate | None:
    settings = {
        "authority_id": os.getenv("AEGIS_M5_DEGRADED_AUTHORITY_ID"),
        "authority_key": os.getenv(
            "AEGIS_M5_DEGRADED_AUTHORITY_PUBLIC_KEY_FILE"
        ),
        "snapshot": os.getenv("AEGIS_M5_DEGRADED_SNAPSHOT_FILE"),
        "authorization": os.getenv("AEGIS_M5_DEGRADED_AUTHORIZATION_FILE"),
        "state": os.getenv("AEGIS_M5_DEGRADED_STATE_FILE"),
    }
    if not any(settings.values()):
        return None
    if not all(settings.values()):
        raise CapabilityRuntimeUnavailable(
            "M5 degraded operation configuration is incomplete"
        )
    paths = {
        name: Path(value)
        for name, value in settings.items()
        if name != "authority_id" and value is not None
    }
    if any(not path.is_absolute() for path in paths.values()):
        raise CapabilityRuntimeUnavailable(
            "M5 degraded operation file paths must be absolute"
        )
    assert settings["authority_id"] is not None
    gate = DegradedOperationGate(
        authority_id=settings["authority_id"],
        authority_public_key=_load_public_key(str(paths["authority_key"])),
        snapshot_source=FileDegradedSnapshotSource(paths["snapshot"]),
        authorization_source=FileDegradedAuthorizationSource(paths["authorization"]),
        state_store=FileDegradedOperationStateStore(
            paths["state"],
            authority_id=settings["authority_id"],
            require_existing=True,
        ),
    )
    try:
        gate.snapshot_source()
        gate.authorization_source()
        gate.state_store.read()
    except Exception as exc:
        raise CapabilityRuntimeUnavailable(
            "M5 degraded operation configuration is invalid"
        ) from exc
    return gate


def _configured_m5_degraded_gate() -> (
    DegradedOperationGate | PublishedDegradedOperationGate | None
):
    mode_name = "AEGIS_M5_SIGNED_PUBLICATION_MODE"
    mode_value = os.getenv(mode_name)
    legacy_names = (
        "AEGIS_M5_DEGRADED_AUTHORITY_ID",
        "AEGIS_M5_DEGRADED_AUTHORITY_PUBLIC_KEY_FILE",
        "AEGIS_M5_DEGRADED_SNAPSHOT_FILE",
        "AEGIS_M5_DEGRADED_AUTHORIZATION_FILE",
        "AEGIS_M5_DEGRADED_STATE_FILE",
    )
    signed_names = (
        "AEGIS_M5_ROOT_PUBLIC_KEY_FILE",
        "AEGIS_M5_PUBLISHER_CREDENTIAL_FILE",
        "AEGIS_M5_STABLE_AUTHORIZATION_FILE",
        "AEGIS_M5_PUBLICATION_FILE",
        "AEGIS_M5_CONSUMER_STATE_FILE",
        "AEGIS_M5_REVERSAL_FILE",
    )
    legacy_configured = any(os.getenv(name) for name in legacy_names)
    signed_configured = any(os.getenv(name) for name in signed_names)
    if mode_value is None:
        if signed_configured:
            raise CapabilityRuntimeUnavailable(
                f"required runtime setting is missing: {mode_name}"
            )
        return _configured_legacy_m5_degraded_gate()

    mode = mode_value.strip().lower()
    if mode not in {"disabled", "required"}:
        raise CapabilityRuntimeUnavailable(
            "M5 signed publication mode must be disabled or required"
        )
    if mode == "disabled":
        if legacy_configured or signed_configured:
            raise CapabilityRuntimeUnavailable(
                "disabled M5 signed publication cannot retain M5 configuration"
            )
        return None
    if legacy_configured:
        raise CapabilityRuntimeUnavailable(
            "M5 legacy and signed publication configuration cannot be mixed"
        )

    values = {name: os.getenv(name) for name in signed_names}
    missing = tuple(name for name, value in values.items() if not value)
    if missing:
        raise CapabilityRuntimeUnavailable(
            "M5 signed publication configuration is incomplete: "
            + ",".join(missing)
        )
    paths = {name: Path(value) for name, value in values.items() if value is not None}
    if any(not path.is_absolute() for path in paths.values()):
        raise CapabilityRuntimeUnavailable(
            "M5 signed publication file paths must be absolute"
        )
    try:
        authority_public_key = load_authority_public_key(
            paths["AEGIS_M5_ROOT_PUBLIC_KEY_FILE"]
        )
        credential = load_publisher_credential(
            paths["AEGIS_M5_PUBLISHER_CREDENTIAL_FILE"]
        )
        stable_authorization = FileStableDegradedAuthorizationSource(
            paths["AEGIS_M5_STABLE_AUTHORIZATION_FILE"]
        )()
        gate = PublishedDegradedOperationGate(
            authority_id=credential.authority_id,
            authority_public_key=authority_public_key,
            publisher_credential=credential,
            stable_authorization=stable_authorization,
            publication_source=FileDegradedPublicationSource(
                paths["AEGIS_M5_PUBLICATION_FILE"]
            ),
            state_store=FileDegradedConsumerStateStore(
                paths["AEGIS_M5_CONSUMER_STATE_FILE"]
            ),
            reversal_source=FileDegradedReversalSource(
                paths["AEGIS_M5_REVERSAL_FILE"]
            ),
        )
        gate.readiness()
    except Exception as exc:
        raise CapabilityRuntimeUnavailable(
            "M5 signed publication configuration is invalid"
        ) from exc
    return gate


def _plant_process_info(health: PlantHealthMetadata) -> PlantProcessInfo:
    return PlantProcessInfo(
        pid=health.pid,
        boot_epoch=health.boot_epoch,
        backend=health.backend,
        model_digest=health.model_digest,
        simulator_version=health.simulator_version,
        observation_source_id=health.observation_source_id,
        capabilities={
            "observer": ("capture_state",),
            "simulation": ("simulate_candidate",),
            "plc": ("read_state", "simulate_candidate", "apply_authorized_command"),
        },
    )


def _observer_process_info(health: ObserverHealthMetadata) -> ObserverProcessInfo:
    return ObserverProcessInfo(
        pid=health.pid,
        observer_id=health.observer_id,
        boot_epoch=health.boot_epoch,
        key_id=health.key_id,
        public_key_bytes=health.public_key.public_bytes_raw(),
        plant_boot_epoch=health.plant_boot_epoch,
        capabilities={
            "telemetry": ("capture_pre",),
            "gateway": ("resolve", "capture_post"),
        },
    )


def _plc_process_info(health: OtHealthMetadata) -> PlcProcessInfo:
    return PlcProcessInfo(
        pid=health.pid,
        plc_id=health.plc_id,
        boot_epoch=health.boot_epoch,
        key_id=health.key_id,
        public_key_bytes=health.public_key.public_bytes_raw(),
        permit_key_id=health.permit_key_id,
        plant_boot_epoch=health.plant_boot_epoch,
        observer_boot_epoch=health.observer_boot_epoch,
        capabilities={"gateway": ("health", "execute")},
    )


def _validate_plant_pin(health: PlantHealthMetadata) -> None:
    _require_pin(
        label="plant",
        actual_key_id=health.key_id,
        actual_public_key=health.public_key,
        expected_key_id=_expected_environment("AEGIS_PLANT_KEY_ID"),
        expected_public_key=_load_public_key(
            _expected_environment("AEGIS_PLANT_PUBLIC_KEY_FILE")
        ),
    )


def _configured_capability_exchange() -> HttpExchange:
    """Select one explicit transport for every outbound service link."""

    return capability_http_exchange_from_environment()


def _fetch_plant_over_configured_transport(
    url: str,
    exchange: HttpExchange,
) -> PlantHealthMetadata:
    # Retain the exact plain-HTTP call shape for the non-SPIRE lab and its
    # existing test seams. Required mTLS receives the selected exchange on
    # discovery as well as every subsequent call.
    if exchange is urllib_http_exchange:
        return fetch_plant_health(url)
    return fetch_plant_health(url, exchange=exchange)


def _fetch_observer_over_configured_transport(
    url: str,
    exchange: HttpExchange,
) -> ObserverHealthMetadata:
    if exchange is urllib_http_exchange:
        return fetch_observer_health(url)
    return fetch_observer_health(url, exchange=exchange)


def _discover_over_configured_transport(
    *,
    observer_url: str,
    candidate_url: str,
    ot_url: str,
    gateway_key_id: str,
    exchange: HttpExchange,
) -> SegmentedCapabilityDiscovery:
    if exchange is urllib_http_exchange:
        return discover_segmented_capabilities_via_ot(
            observer_url=observer_url,
            candidate_url=candidate_url,
            ot_url=ot_url,
            gateway_key_id=gateway_key_id,
        )
    return discover_segmented_capabilities_via_ot(
        observer_url=observer_url,
        candidate_url=candidate_url,
        ot_url=ot_url,
        gateway_key_id=gateway_key_id,
        exchange=exchange,
    )


def _build_plant_runtime() -> CapabilityPlantRuntime:
    checkpoint_required = effect_coordination_enabled()
    boot_epoch = str(uuid4())
    private_key = _load_private_key(
        _expected_environment("AEGIS_PLANT_PRIVATE_KEY_FILE")
    )
    callers = {
        PlantCallerRole.OBSERVER: TrustedPlantCaller(
            key_id=_expected_environment("AEGIS_OBSERVER_KEY_ID"),
            public_key=_load_public_key(
                _expected_environment("AEGIS_OBSERVER_PUBLIC_KEY_FILE")
            ),
        ),
        PlantCallerRole.CANDIDATE: TrustedPlantCaller(
            key_id=_expected_environment("AEGIS_CANDIDATE_KEY_ID"),
            public_key=_load_public_key(
                _expected_environment("AEGIS_CANDIDATE_PUBLIC_KEY_FILE")
            ),
        ),
        PlantCallerRole.PLC: TrustedPlantCaller(
            key_id=_expected_environment("AEGIS_OT_KEY_ID"),
            public_key=_load_public_key(
                _expected_environment("AEGIS_OT_PUBLIC_KEY_FILE")
            ),
        ),
    }
    plant = PandapowerCigreMVPlant(
        observation_source_id=f"segmented-capability-plant:{boot_epoch}"
    )
    key_id = _expected_environment("AEGIS_PLANT_KEY_ID")
    checkpoint_store: DurablePlantCheckpointStore | None = None
    try:
        if checkpoint_required:
            checkpoint_store = DurablePlantCheckpointStore(
                Path(_expected_environment("AEGIS_PLANT_CHECKPOINT_FILE")),
                plant_key_id=key_id,
                model_digest=plant.model_digest,
            )
            checkpoint = checkpoint_store.current()
            if checkpoint is None:
                checkpoint_store.install_baseline(plant.read_state())
            else:
                plant.restore_state(checkpoint)
        return CapabilityPlantRuntime(
            plant=plant,
            private_key=private_key,
            key_id=key_id,
            trusted_callers=callers,
            boot_epoch=boot_epoch,
            checkpoint_required=checkpoint_required,
            checkpoint_store=checkpoint_store,
        )
    except (PhysicalSimulationError, PlantCheckpointError) as exc:
        if checkpoint_store is not None:
            checkpoint_store.close()
        raise CapabilityRuntimeUnavailable("plant_checkpoint_unavailable") from exc
    except Exception:
        if checkpoint_store is not None:
            checkpoint_store.close()
        raise


def _build_observer_runtime() -> CapabilityObserverRuntime:
    plant_url = _expected_environment("AEGIS_PLANT_URL")
    exchange = _configured_capability_exchange()
    plant = _fetch_plant_over_configured_transport(plant_url, exchange)
    _validate_plant_pin(plant)
    private_key = _load_private_key(
        _expected_environment("AEGIS_OBSERVER_PRIVATE_KEY_FILE")
    )
    key_id = _expected_environment("AEGIS_OBSERVER_KEY_ID")
    boot_epoch = str(uuid4())
    metadata = ObserverHealthMetadata(
        pid=os.getpid(),
        observer_id="signed-observer:m4g-segmented",
        boot_epoch=boot_epoch,
        key_id=key_id,
        public_key_b64=_public_key_b64(private_key.public_key()),
        plant_boot_epoch=plant.boot_epoch,
        plant_model_digest=plant.model_digest,
        capture_count=0,
        resolve_count=0,
        cached_observations=0,
    )
    client = RemoteObserverPlantClient(
        plant_url,
        plant=plant,
        observer=metadata,
        caller_private_key=private_key,
        exchange=exchange,
    )
    return CapabilityObserverRuntime(
        plant=client,
        plant_info=plant,
        private_key=private_key,
        key_id=key_id,
        observer_id=metadata.observer_id,
        boot_epoch=boot_epoch,
    )


def _build_candidate_runtime() -> CapabilityCandidateRuntime:
    plant_url = _expected_environment("AEGIS_PLANT_URL")
    exchange = _configured_capability_exchange()
    plant = _fetch_plant_over_configured_transport(plant_url, exchange)
    _validate_plant_pin(plant)
    private_key = _load_private_key(
        _expected_environment("AEGIS_CANDIDATE_PRIVATE_KEY_FILE")
    )
    key_id = _expected_environment("AEGIS_CANDIDATE_KEY_ID")
    boot_epoch = str(uuid4())
    metadata = CandidateHealthMetadata(
        pid=os.getpid(),
        boot_epoch=boot_epoch,
        key_id=key_id,
        public_key_b64=_public_key_b64(private_key.public_key()),
        plant_boot_epoch=plant.boot_epoch,
        plant_model_digest=plant.model_digest,
        simulation_count=0,
    )
    client = RemoteCandidatePlantClient(
        plant_url,
        plant=plant,
        candidate=metadata,
        caller_private_key=private_key,
        exchange=exchange,
    )
    return CapabilityCandidateRuntime(
        plant=client,
        plant_info=plant,
        private_key=private_key,
        key_id=key_id,
        boot_epoch=boot_epoch,
    )


def _build_ot_runtime() -> CapabilityOtRuntime:
    coordination_required = effect_coordination_enabled()
    identity_required = workload_identity_enabled()
    if coordination_required and not identity_required:
        raise CapabilityRuntimeUnavailable(
            "required effect coordination needs required workload identity"
        )
    plant_url = _expected_environment("AEGIS_PLANT_URL")
    observer_url = _expected_environment("AEGIS_OBSERVER_URL")
    exchange = _configured_capability_exchange()
    plant = _fetch_plant_over_configured_transport(plant_url, exchange)
    observer = _fetch_observer_over_configured_transport(observer_url, exchange)
    _validate_plant_pin(plant)
    _require_pin(
        label="observer",
        actual_key_id=observer.key_id,
        actual_public_key=observer.public_key,
        expected_key_id=_expected_environment("AEGIS_OBSERVER_KEY_ID"),
        expected_public_key=_load_public_key(
            _expected_environment("AEGIS_OBSERVER_PUBLIC_KEY_FILE")
        ),
    )
    if (
        observer.plant_boot_epoch != plant.boot_epoch
        or observer.plant_model_digest != plant.model_digest
    ):
        raise CapabilityRuntimeUnavailable("observer and plant discovery are inconsistent")
    gateway_workload_identity: WorkloadCredentialBinding | None = None
    local_workload_identity: LocalWorkloadIdentity | None = None
    workload_verifier: WorkloadIdentityVerifier | None = None
    if identity_required:
        workload_verifier = verifier_from_environment()
        gateway_workload_identity = credential_binding_from_environment(
            workload_verifier,
            "GATEWAY",
            role=WorkloadRole.GATEWAY,
            audience=OT_CAPABILITY_AUDIENCE,
        )
        local_workload_identity = local_identity_from_environment(
            workload_verifier,
            "OT",
            role=WorkloadRole.OT_ADAPTER,
            audience=GATEWAY_CAPABILITY_AUDIENCE,
        )
        gateway_identity = gateway_workload_identity.resolve()
        local_identity = local_workload_identity.resolve()
        private_key = local_workload_identity.signer.private_key
        key_id = local_identity.key_id
        gateway_key_id = gateway_identity.key_id
        gateway_public = gateway_identity.public_key
    else:
        private_key = _load_private_key(_expected_environment("AEGIS_OT_PRIVATE_KEY_FILE"))
        key_id = _expected_environment("AEGIS_OT_KEY_ID")
        gateway_key_id = _expected_environment("AEGIS_GATEWAY_KEY_ID")
        gateway_public = _load_public_key(
            _expected_environment("AEGIS_GATEWAY_PUBLIC_KEY_FILE")
        )
    permit_key_id = _expected_environment("AEGIS_PERMIT_KEY_ID")
    permit_public = _load_public_key(
        _expected_environment("AEGIS_PERMIT_PUBLIC_KEY_FILE")
    )
    boot_epoch = str(uuid4())
    provisional = OtHealthMetadata(
        pid=os.getpid(),
        plc_id=PLC_ID,
        boot_epoch=boot_epoch,
        key_id=key_id,
        public_key_b64=_public_key_b64(private_key.public_key()),
        gateway_key_id=gateway_key_id,
        gateway_public_key_b64=_public_key_b64(gateway_public),
        permit_key_id=permit_key_id,
        permit_public_key_b64=_public_key_b64(permit_public),
        plant_boot_epoch=plant.boot_epoch,
        plant_model_digest=plant.model_digest,
        plant=plant,
        observer_boot_epoch=observer.boot_epoch,
        transport_replay_reservations=0,
        semantic_replay_reservations=0,
        execute_requests=0,
        scan_counter=0,
    )
    semantic_replay = OrderlyRestartReplayReservations(
        Path(_expected_environment("AEGIS_SEMANTIC_REPLAY_LEDGER_FILE"))
    )
    transport_replay: (
        DurableTransportReplayLedger | DurableWorkloadReplayLedger | None
    ) = None
    coordination_journal: DurableEffectCoordinationJournal | None = None
    try:
        observer_info = _observer_process_info(observer)
        plant_client = RemotePlcPlantClient(
            plant_url,
            plant=plant,
            ot=provisional,
            caller_private_key=private_key,
            exchange=exchange,
        )
        device = CapabilityVirtualPlc(
            plant_client,
            plc_id=PLC_ID,
            boot_epoch=boot_epoch,
            permit_key_id=permit_key_id,
            permit_public_key=permit_public,
            observer_info=observer_info,
            acknowledgment_private_key=private_key,
            acknowledgment_key_id=key_id,
            replay=semantic_replay,
        )
        if workload_verifier is not None:
            assert gateway_workload_identity is not None
            transport_replay = DurableWorkloadReplayLedger(
                Path(_expected_environment("AEGIS_WORKLOAD_REPLAY_LEDGER_FILE")),
                audience=OT_CAPABILITY_AUDIENCE,
                trust_domain=workload_verifier.trust_domain,
                workload_subject=gateway_workload_identity.expected_subject,
                authority_key_id=workload_verifier.trust_root_key_id,
            )
        else:
            transport_replay = DurableTransportReplayLedger(
                Path(_expected_environment("AEGIS_TRANSPORT_REPLAY_LEDGER_FILE")),
                audience=OT_CAPABILITY_AUDIENCE,
                gateway_key_id=gateway_key_id,
                gateway_public_key_sha256=hashlib.sha256(
                    gateway_public.public_bytes_raw()
                ).hexdigest(),
            )
        if coordination_required:
            coordination_journal = DurableEffectCoordinationJournal(
                Path(_expected_environment("AEGIS_OT_COORDINATION_JOURNAL_FILE")),
                owner_subject=_expected_environment("AEGIS_OT_WORKLOAD_SUBJECT"),
            )

        def load_current_plant_health() -> PlantHealthMetadata:
            return _fetch_plant_over_configured_transport(plant_url, exchange)

        return CapabilityOtRuntime(
            device=device,
            transport_replay=transport_replay,
            gateway_public_key=gateway_public,
            gateway_key_id=gateway_key_id,
            observer_info=observer_info,
            permit_public_key=permit_public,
            permit_key_id=permit_key_id,
            private_key=private_key,
            key_id=key_id,
            plc_id=PLC_ID,
            boot_epoch=boot_epoch,
            plant_info=plant,
            semantic_replay=semantic_replay,
            gateway_workload_identity=gateway_workload_identity,
            local_workload_identity=local_workload_identity,
            coordination_required=coordination_required,
            coordination_journal=coordination_journal,
            plant_health_loader=(
                load_current_plant_health if coordination_required else None
            ),
        )
    except Exception:
        if coordination_journal is not None:
            coordination_journal.close()
        if transport_replay is not None:
            transport_replay.close()
        semantic_replay.close()
        raise


def _build_gateway_runtime() -> CapabilityGatewayRuntime:
    coordination_required = effect_coordination_enabled()
    identity_required = workload_identity_enabled()
    degraded_operation = _configured_m5_degraded_gate()
    if coordination_required and not identity_required:
        raise CapabilityRuntimeUnavailable(
            "required effect coordination needs workload identity"
        )
    workload_verifier: WorkloadIdentityVerifier | None = None
    gateway_workload_identity: LocalWorkloadIdentity | None = None
    ot_workload_identity: WorkloadCredentialBinding | None = None
    if identity_required:
        workload_verifier = verifier_from_environment()
        gateway_workload_identity = local_identity_from_environment(
            workload_verifier,
            "GATEWAY",
            role=WorkloadRole.GATEWAY,
            audience=(
                EFFECT_COORDINATOR_AUDIENCE
                if coordination_required
                else OT_CAPABILITY_AUDIENCE
            ),
        )
        ot_workload_identity = credential_binding_from_environment(
            workload_verifier,
            "OT",
            role=WorkloadRole.OT_ADAPTER,
            audience=(
                GATEWAY_COORDINATION_AUDIENCE
                if coordination_required
                else GATEWAY_CAPABILITY_AUDIENCE
            ),
        )
        gateway_key_id = gateway_workload_identity.resolve().key_id
    else:
        gateway_key_id = _expected_environment("AEGIS_GATEWAY_KEY_ID")
    exchange = _configured_capability_exchange()
    observer_url = _expected_environment("AEGIS_OBSERVER_URL")
    candidate_url = _expected_environment("AEGIS_CANDIDATE_URL")
    ot_url = _expected_environment("AEGIS_OT_URL")
    discovery = _discover_over_configured_transport(
        observer_url=observer_url,
        candidate_url=candidate_url,
        ot_url=ot_url,
        gateway_key_id=gateway_key_id,
        exchange=exchange,
    )
    _validate_plant_pin(discovery.plant)
    pinned_peers = [
        (
            "observer",
            discovery.observer.key_id,
            discovery.observer.public_key,
            "AEGIS_OBSERVER_KEY_ID",
            "AEGIS_OBSERVER_PUBLIC_KEY_FILE",
        ),
        (
            "candidate",
            discovery.candidate.key_id,
            discovery.candidate.public_key,
            "AEGIS_CANDIDATE_KEY_ID",
            "AEGIS_CANDIDATE_PUBLIC_KEY_FILE",
        ),
    ]
    if workload_verifier is None:
        pinned_peers.append(
            (
                "OT",
                discovery.ot.key_id,
                discovery.ot.public_key,
                "AEGIS_OT_KEY_ID",
                "AEGIS_OT_PUBLIC_KEY_FILE",
            )
        )
    else:
        assert ot_workload_identity is not None
        target = ot_workload_identity.resolve()
        if (
            target.key_id != discovery.ot.key_id
            or target.public_key.public_bytes_raw()
            != discovery.ot.public_key.public_bytes_raw()
        ):
            raise CapabilityRuntimeUnavailable(
                "OT discovery does not match its workload identity"
            )
    for label, actual_id, actual_key, id_env, key_env in pinned_peers:
        _require_pin(
            label=label,
            actual_key_id=actual_id,
            actual_public_key=actual_key,
            expected_key_id=_expected_environment(id_env),
            expected_public_key=_load_public_key(_expected_environment(key_env)),
        )
    permit_key_id = _expected_environment("AEGIS_PERMIT_KEY_ID")
    if discovery.ot.permit_key_id != permit_key_id:
        raise CapabilityRuntimeUnavailable("OT permit key ID does not match the gateway")
    gateway_private = (
        gateway_workload_identity.signer.private_key
        if gateway_workload_identity is not None
        else _load_private_key(_expected_environment("AEGIS_GATEWAY_PRIVATE_KEY_FILE"))
    )
    permit_private = _load_private_key(
        _expected_environment("AEGIS_PERMIT_PRIVATE_KEY_FILE")
    )
    if not _same_public_key(
        gateway_private.public_key(),
        discovery.ot.gateway_public_key,
    ):
        raise CapabilityRuntimeUnavailable(
            "gateway private key does not match the OT trust pin"
        )
    if not _same_public_key(
        permit_private.public_key(),
        discovery.ot.permit_public_key,
    ):
        raise CapabilityRuntimeUnavailable(
            "permit private key does not match the OT trust pin"
        )
    _require_distinct_public_keys(
        {
            "gateway": gateway_private.public_key(),
            "permit": permit_private.public_key(),
            "plant": discovery.plant.public_key,
            "observer": discovery.observer.public_key,
            "candidate": discovery.candidate.public_key,
            "ot": discovery.ot.public_key,
        }
    )
    authorization = build_local_lab(
        agent_actor_id=(
            _expected_environment("AEGIS_AGENT_ACTOR_ID")
            if identity_required
            else "agent:operator-1"
        )
    )
    authorization.gateway.degraded_operation = degraded_operation
    opa_url = os.getenv("AEGIS_OPA_URL", "http://opa:8181")
    authorization.gateway.policy = OpaBackedPolicy(
        opa_url,
        exchange=exchange if urlsplit(opa_url).scheme == "https" else None,
    )
    authorization.gateway.safety = SafetyKernel(
        SafetyLimits(minimum_voltage_pu=0.90, maximum_voltage_pu=1.10),
        version="surrogate-safety-v1-m4g-supervisory-limits",
    )
    observer_port = RemoteObservationPort(
        observer_url,
        observer=discovery.observer,
        exchange=exchange,
    )
    candidate_port = RemoteCandidatePort(
        candidate_url,
        candidate=discovery.candidate,
        plant=discovery.plant,
        exchange=exchange,
    )
    coordination_journal: DurableGatewayCoordinationJournal | None = None
    if coordination_required:
        assert gateway_workload_identity is not None
        assert ot_workload_identity is not None
        coordination_journal = DurableGatewayCoordinationJournal(
            Path(_expected_environment("AEGIS_GATEWAY_COORDINATION_JOURNAL_FILE")),
            owner_subject=gateway_workload_identity.binding.expected_subject,
        )
        try:
            plc_port: RemoteVirtualPlcPort = CoordinatedWorkloadRemoteVirtualPlcPort(
                ot_url,
                ot=discovery.ot,
                observer=discovery.observer,
                gateway_identity=gateway_workload_identity,
                ot_identity=ot_workload_identity,
                coordination_journal=coordination_journal,
                exchange=exchange,
            )
        except Exception:
            coordination_journal.close()
            raise
    elif gateway_workload_identity is not None:
        assert ot_workload_identity is not None
        plc_port = WorkloadRemoteVirtualPlcPort(
            ot_url,
            ot=discovery.ot,
            gateway_identity=gateway_workload_identity,
            ot_identity=ot_workload_identity,
            exchange=exchange,
        )
    else:
        plc_port = RemoteVirtualPlcPort(
            ot_url,
            ot=discovery.ot,
            gateway_key_id=gateway_key_id,
            gateway_private_key=gateway_private,
            exchange=exchange,
        )
    plc_info = _plc_process_info(discovery.ot)
    base_issuer = ExecutionPermitIssuer(
        permit_private,
        signing_key_id=permit_key_id,
        audience=plc_info.plc_id,
        evidence=authorization.gateway.evidence,
    )
    permit_issuer = CapabilityPermitIssuer(base_issuer, permit_private, plc_info)
    controller = SegmentedCapabilityController(
        gateway=authorization.gateway,
        observer=observer_port,
        simulator=candidate_port,
        plc=plc_port,
        translator=TrustedCommandTranslator(),
        permit_issuer=permit_issuer,
        observation_verifier=SignedObservationVerifier(
            observer_info=_observer_process_info(discovery.observer),
            plant_info=_plant_process_info(discovery.plant),
        ),
        plc_info=plc_info,
        plc_public_key=discovery.ot.public_key,
        evidence=authorization.gateway.evidence,
    )
    try:
        return CapabilityGatewayRuntime(
            authorization=authorization,
            controller=controller,
            observer=observer_port,
            discovery=discovery,
            gateway_key_id=gateway_key_id,
            agent_workload_verifier=workload_verifier,
            agent_workload_subject=(
                _expected_environment("AEGIS_AGENT_WORKLOAD_SUBJECT")
                if workload_verifier is not None
                else None
            ),
            coordination_required=coordination_required,
            coordination_journal=coordination_journal,
            degraded_operation=degraded_operation,
        )
    except Exception:
        if coordination_journal is not None:
            coordination_journal.close()
        raise


def create_plant_app(
    runtime: Callable[[], CapabilityPlantRuntime],
) -> FastAPI:
    app = FastAPI(title="Aegis-OT M4g Signed Physical Plant")

    @app.get("/health", response_model=PlantHealthMetadata)
    def health() -> PlantHealthMetadata | JSONResponse:
        try:
            return runtime().health()
        except Exception:
            return _failure_response(503, "plant_runtime_unavailable", status="error")

    @app.post("/v1/plant/call", response_model=SignedPlantResponse)
    async def call(request: Request) -> SignedPlantResponse | JSONResponse:
        try:
            parsed = await parse_strict_json_request(request, SignedPlantCall)
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            status_code, response = runtime().execute(parsed)
            if status_code == 200:
                return response
            return JSONResponse(
                status_code=status_code,
                content=response.model_dump(mode="json"),
            )
        except CapabilityAdmissionRejected as exc:
            return _failure_response(403, str(exc), status="rejected")
        except Exception:
            # An unexpected apply failure may follow an effect.  Never relabel
            # it as a signed known-no-effect plant rejection.
            return _failure_response(503, "plant_outcome_unavailable", status="error")

    return app


def create_observer_app(
    runtime: Callable[[], CapabilityObserverRuntime],
) -> FastAPI:
    app = FastAPI(title="Aegis-OT M4g Signed Observer")

    @app.get("/health", response_model=ObserverHealthMetadata)
    def health() -> ObserverHealthMetadata | JSONResponse:
        try:
            return runtime().health()
        except Exception:
            return _failure_response(503, "observer_runtime_unavailable", status="error")

    @app.post("/v1/observations/pre", response_model=SignedObservationEnvelope)
    async def capture_pre(request: Request) -> SignedObservationEnvelope | JSONResponse:
        try:
            parsed = await parse_strict_json_request(request, ObservationCaptureRequest)
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            return runtime().capture_pre(parsed)
        except CapabilityAdmissionRejected as exc:
            return _failure_response(409, str(exc), status="rejected")
        except Exception:
            return _failure_response(503, "observation_unavailable", status="error")

    @app.post("/v1/observations/resolve", response_model=SignedObservationEnvelope)
    async def resolve(request: Request) -> SignedObservationEnvelope | JSONResponse:
        try:
            parsed = await parse_strict_json_request(request, ObservationResolveRequest)
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            return runtime().resolve(parsed)
        except CapabilityAdmissionRejected as exc:
            return _failure_response(404, str(exc), status="rejected")
        except Exception:
            return _failure_response(503, "observation_unavailable", status="error")

    @app.post("/v1/observations/post", response_model=SignedObservationEnvelope)
    async def capture_post(request: Request) -> SignedObservationEnvelope | JSONResponse:
        try:
            parsed = await parse_strict_json_request(
                request,
                PostObservationCaptureRequest,
            )
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            return runtime().capture_post(parsed)
        except CapabilityAdmissionRejected as exc:
            return _failure_response(409, str(exc), status="rejected")
        except Exception:
            return _failure_response(503, "observation_unavailable", status="error")

    return app


def create_candidate_app(
    runtime: Callable[[], CapabilityCandidateRuntime],
) -> FastAPI:
    app = FastAPI(title="Aegis-OT M4g Signed Candidate Bridge")

    @app.get("/health", response_model=CandidateHealthMetadata)
    def health() -> CandidateHealthMetadata | JSONResponse:
        try:
            return runtime().health()
        except Exception:
            return _failure_response(503, "candidate_runtime_unavailable", status="error")

    @app.post("/v1/candidates/simulate", response_model=PlantExchange)
    async def simulate(request: Request) -> PlantExchange | JSONResponse:
        try:
            parsed = await parse_strict_json_request(request, CandidateSimulationRequest)
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            return runtime().simulate(parsed)
        except CapabilityAdmissionRejected as exc:
            return _failure_response(409, str(exc), status="rejected")
        except Exception:
            return _failure_response(503, "candidate_simulation_unavailable", status="error")

    return app


def create_ot_app(runtime: Callable[[], CapabilityOtRuntime]) -> FastAPI:
    app = FastAPI(title="Aegis-OT M4g Permit-Aware OT Adapter")

    @app.get("/health", response_model=OtHealthMetadata)
    def health() -> OtHealthMetadata | JSONResponse:
        try:
            return runtime().health()
        except CapabilityRuntimeUnavailable as exc:
            reason = str(exc)
            if reason == "effect_coordination_recovery_unavailable":
                return _failure_response(503, reason, status="error")
            return _failure_response(503, "ot_runtime_unavailable", status="error")
        except Exception:
            return _failure_response(503, "ot_runtime_unavailable", status="error")

    @app.post(
        "/v1/capability/execute",
        response_model=(
            SignedSegmentedCapabilityResponse | WorkloadSignedCapabilityResponse
        ),
    )
    async def execute(
        request: Request,
    ) -> (
        SignedSegmentedCapabilityResponse
        | WorkloadSignedCapabilityResponse
        | JSONResponse
    ):
        try:
            parsed = await parse_strict_json_request_adapter(
                request,
                _OT_EXECUTE_REQUEST_ADAPTER,
            )
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            instance = runtime()
        except CapabilityRuntimeUnavailable as exc:
            reason = str(exc)
            if reason == "effect_coordination_recovery_unavailable":
                return _failure_response(503, reason, status="error")
            return _failure_response(503, "ot_runtime_unavailable", status="error")
        except Exception:
            return _failure_response(503, "ot_runtime_unavailable", status="error")
        try:
            return instance.execute(parsed)
        except CapabilityAdmissionRejected as exc:
            status_code = 409 if "replayed" in str(exc) else 403
            return _failure_response(status_code, str(exc), status="rejected")
        except Exception:
            return _failure_response(503, "ot_outcome_unavailable", status="error")

    @app.post("/v1/effects/prepare", response_model=CoordinationReceipt)
    async def prepare_effect(request: Request) -> CoordinationReceipt | JSONResponse:
        try:
            parsed = await parse_strict_json_request(
                request,
                SignedEffectPrepareRequest,
            )
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            instance = runtime()
        except CapabilityRuntimeUnavailable as exc:
            reason = str(exc)
            if reason == "effect_coordination_recovery_unavailable":
                return _failure_response(503, reason, status="error")
            return _failure_response(503, "ot_runtime_unavailable", status="error")
        except Exception:
            return _failure_response(503, "ot_runtime_unavailable", status="error")
        try:
            return instance.prepare_effect(parsed)
        except CapabilityAdmissionRejected as exc:
            status_code = 409 if str(exc) == "effect_reconciliation_required" else 403
            return _failure_response(status_code, str(exc), status="rejected")
        except CapabilityRuntimeUnavailable as exc:
            reason = str(exc)
            if reason == "effect_coordination_recovery_unavailable":
                return _failure_response(503, reason, status="error")
            return _failure_response(503, "effect_prepare_unavailable", status="error")
        except Exception:
            return _failure_response(503, "effect_prepare_unavailable", status="error")

    @app.post("/v1/effects/commit", response_model=SignedEffectOutcome)
    async def commit_effect(request: Request) -> SignedEffectOutcome | JSONResponse:
        try:
            parsed = await parse_strict_json_request(
                request,
                SignedEffectCommitRequest,
            )
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            instance = runtime()
        except CapabilityRuntimeUnavailable as exc:
            reason = str(exc)
            if reason == "effect_coordination_recovery_unavailable":
                return _failure_response(503, reason, status="error")
            return _failure_response(503, "ot_runtime_unavailable", status="error")
        except Exception:
            return _failure_response(503, "ot_runtime_unavailable", status="error")
        try:
            return instance.commit_effect(parsed)
        except EffectCommitIndeterminate as exc:
            return _failure_response(409, str(exc), status="error")
        except CapabilityAdmissionRejected as exc:
            status_code = 409 if str(exc) == "effect_reconciliation_required" else 403
            return _failure_response(status_code, str(exc), status="rejected")
        except CapabilityRuntimeUnavailable as exc:
            reason = str(exc)
            if reason == "effect_coordination_recovery_unavailable":
                return _failure_response(503, reason, status="error")
            return _failure_response(503, "effect_commit_unavailable", status="error")
        except Exception:
            return _failure_response(503, "effect_commit_unavailable", status="error")

    @app.post("/v1/effects/query", response_model=SignedEffectOutcome)
    async def query_effect(request: Request) -> SignedEffectOutcome | JSONResponse:
        try:
            parsed = await parse_strict_json_request(
                request,
                SignedEffectQueryRequest,
            )
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            instance = runtime()
        except CapabilityRuntimeUnavailable as exc:
            reason = str(exc)
            if reason == "effect_coordination_recovery_unavailable":
                return _failure_response(503, reason, status="error")
            return _failure_response(503, "ot_runtime_unavailable", status="error")
        except Exception:
            return _failure_response(503, "ot_runtime_unavailable", status="error")
        try:
            return instance.query_effect(parsed)
        except CapabilityAdmissionRejected as exc:
            return _failure_response(403, str(exc), status="rejected")
        except CapabilityRuntimeUnavailable as exc:
            reason = str(exc)
            if reason == "effect_coordination_recovery_unavailable":
                return _failure_response(503, reason, status="error")
            return _failure_response(503, "effect_query_unavailable", status="error")
        except Exception:
            return _failure_response(503, "effect_query_unavailable", status="error")

    return app


def create_gateway_app(
    runtime: Callable[[], CapabilityGatewayRuntime],
) -> FastAPI:
    app = FastAPI(title="Aegis-OT M4g Segmented Capability Gateway")

    @app.get("/health", response_model=None)
    def health() -> dict[str, Any] | JSONResponse:
        try:
            return runtime().health()
        except Exception:
            return _failure_response(503, "gateway_runtime_unavailable", status="error")

    @app.post("/v1/observations/pre", response_model=SignedObservationEnvelope)
    async def capture_pre(request: Request) -> SignedObservationEnvelope | JSONResponse:
        try:
            parsed = await parse_strict_json_request(request, ObservationCaptureRequest)
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            return runtime().capture_pre(parsed)
        except CapabilityAdmissionRejected as exc:
            return _failure_response(409, str(exc), status="rejected")
        except Exception:
            return _failure_response(503, "observation_unavailable", status="error")

    @app.post("/v1/capability/actions", response_model=SegmentedCapabilityClosedLoopResult)
    async def execute(request: Request) -> SegmentedCapabilityClosedLoopResult | JSONResponse:
        try:
            parsed = await parse_strict_json_request_adapter(
                request,
                _GATEWAY_ACTION_REQUEST_ADAPTER,
            )
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            instance = runtime()
        except Exception:
            return _failure_response(503, "gateway_runtime_unavailable", status="error")
        try:
            return instance.execute(parsed)
        except CapabilityAdmissionRejected as exc:
            status_code = (
                409
                if str(exc)
                in {
                    "agent_action_already_coordinated",
                    "agent_action_coordination_conflict",
                    "effect_reconciliation_required",
                }
                else 403
            )
            return _failure_response(status_code, str(exc), status="rejected")
        except Exception:
            return _failure_response(503, "gateway_runtime_unavailable", status="error")

    @app.post(
        "/v1/capability/effects/reconcile",
        response_model=CapabilityOutcomeResolution | CapabilityOutcomePending,
    )
    async def reconcile_effect(
        request: Request,
    ) -> CapabilityOutcomeResolution | CapabilityOutcomePending | JSONResponse:
        try:
            parsed = await parse_strict_json_request(
                request,
                WorkloadAuthenticatedEffectReconciliation,
            )
        except StrictJsonRequestError as exc:
            return _wire_rejection(exc)
        try:
            instance = runtime()
        except Exception:
            return _failure_response(503, "gateway_runtime_unavailable", status="error")
        try:
            result = instance.reconcile_effect(parsed)
        except CapabilityAdmissionRejected as exc:
            reason = str(exc)
            status_code = {
                "effect_coordination_is_disabled": 409,
                "agent_reconciliation_identity_rejected": 403,
                "agent_reconciliation_proof_rejected": 403,
                "agent_reconciliation_action_conflict": 409,
                "coordinated_action_not_found": 404,
                "effect_was_not_committed": 409,
                "effect_not_query_resolved": 409,
            }.get(reason, 403)
            return _failure_response(status_code, reason, status="rejected")
        except CapabilityRuntimeUnavailable as exc:
            return _failure_response(503, str(exc), status="error")
        except Exception:
            return _failure_response(
                503,
                "effect_reconciliation_unavailable",
                status="error",
            )
        if isinstance(result, CapabilityOutcomePending):
            return JSONResponse(
                status_code=202,
                content=result.model_dump(mode="json"),
            )
        return result

    return app


_plant_provider = _LazyProvider(_build_plant_runtime)
_observer_provider = _LazyProvider(_build_observer_runtime)
_candidate_provider = _LazyProvider(_build_candidate_runtime)
_ot_provider = _LazyProvider(_build_ot_runtime)
_gateway_provider = _LazyProvider(_build_gateway_runtime)

capability_plant_app = create_plant_app(_plant_provider)
capability_observer_app = create_observer_app(_observer_provider)
capability_candidate_app = create_candidate_app(_candidate_provider)
capability_ot_app = create_ot_app(_ot_provider)
capability_gateway_app = create_gateway_app(_gateway_provider)
