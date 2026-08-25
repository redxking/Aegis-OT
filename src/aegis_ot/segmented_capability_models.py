"""Closed M4g-a contracts for the segmented capability transport.

These models move the existing M4a signed transaction artifacts across a
network boundary without changing their evidence semantics.  The Ed25519
transport keys used by this slice are experiment credentials, not SPIFFE
workload identities or TLS peer credentials.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopResult,
    CapabilityExecutionPermit,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from .crypto import sign_bytes, verify_bytes
from .models import Decision, DecisionOutcome
from .physical_models import (
    SHA256_PATTERN,
    CandidateAssessment,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
    proposal_digest,
)
from .workload_identity import SignedWorkloadCredential, WorkloadSigner

MAX_SIGNED_CALL_TTL = timedelta(seconds=60)
OT_CAPABILITY_AUDIENCE = "aegis-ot:m4g:ot-adapter"
GATEWAY_CAPABILITY_AUDIENCE = "aegis-ot:m4g:gateway"
PHYSICAL_PLANT_AUDIENCE = "aegis-ot:m4g:physical-plant"


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
    )


def _canonical_json(value: BaseModel | dict[str, Any]) -> bytes:
    material = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _validate_window(issued_at: datetime, expires_at: datetime, *, label: str) -> None:
    if not _is_aware(issued_at) or not _is_aware(expires_at):
        raise ValueError(f"{label} timestamps must be timezone-aware")
    if expires_at <= issued_at:
        raise ValueError(f"{label} expiry must follow issuance")
    if expires_at - issued_at > MAX_SIGNED_CALL_TTL:
        raise ValueError(f"{label} lifetime exceeds the registered maximum")


def _valid_at(issued_at: datetime, expires_at: datetime, evaluated_at: datetime) -> bool:
    return _is_aware(evaluated_at) and issued_at <= evaluated_at < expires_at


class SegmentedCapabilityDispatch(_StrictFrozenModel):
    """The complete artifact set the gateway sends to the virtual PLC."""

    schema_version: Literal["m4g-capability-dispatch-v1"] = (
        "m4g-capability-dispatch-v1"
    )
    request: CapabilityActionRequest
    pre_observation: SignedObservationEnvelope
    decision: Decision
    assessment: CandidateAssessment
    permit: CapabilityExecutionPermit

    def bindings_match(self) -> bool:
        request = self.request
        observation = self.pre_observation
        proposal = request.proposal
        decision = self.decision
        assessment = self.assessment
        permit = self.permit
        base = permit.base_permit
        snapshot = observation.snapshot
        return all(
            (
                observation.phase is ObservationPhase.PRE_AUTHORIZATION,
                request.correlation_id == observation.correlation_id,
                request.observation_id == observation.observation_id,
                request.observation_envelope_digest == observation.envelope_digest,
                request.observation_challenge_nonce == observation.challenge_nonce,
                proposal.observed_state_version == snapshot.state_version,
                proposal.observed_at == snapshot.observed_at,
                _is_aware(decision.decided_at),
                decision.outcome is DecisionOutcome.PERMIT,
                decision.proposal_id == proposal.proposal_id,
                decision.evidence_record_hash is not None,
                assessment.safe,
                permit.request_digest == request.digest,
                permit.observation_id == observation.observation_id,
                permit.observation_envelope_digest == observation.envelope_digest,
                permit.observer_id == observation.observer_id,
                permit.observer_key_id == observation.observer_key_id,
                permit.observer_boot_epoch == observation.observer_boot_epoch,
                base.audience == permit.target_plc_id,
                base.proposal_id == proposal.proposal_id,
                base.proposal_digest == proposal_digest(proposal),
                base.decision_id == decision.decision_id,
                base.decision_outcome is DecisionOutcome.PERMIT,
                base.evidence_record_hash == decision.evidence_record_hash,
                base.policy_version == decision.policy_version,
                base.safety_version == decision.safety_version,
                base.state_version == decision.state_version == snapshot.state_version,
                base.state_digest == snapshot.state_digest,
                base.observation_digest == snapshot.observation_digest,
                base.topology_digest == snapshot.topology_digest,
                base.model_digest == snapshot.model_digest,
                base.command.digest == base.command_digest == assessment.command_digest,
                base.assessment_digest == assessment.digest,
                assessment.pre_state == snapshot,
                assessment.post_state.state_version == base.expected_post_state_version,
                assessment.post_state.state_digest == base.expected_post_state_digest,
                assessment.post_state.topology_digest
                == base.expected_post_topology_digest,
            )
        )

    @model_validator(mode="after")
    def require_exact_bindings(self) -> SegmentedCapabilityDispatch:
        if not self.bindings_match():
            raise ValueError("segmented capability dispatch bindings are inconsistent")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class SegmentedCapabilityClosedLoopResult(CapabilityClosedLoopResult):
    """Terminal result whose schema names the segmented coordination backend."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
    )
    # Deliberate closed discriminator narrowing; Pydantic validates the override.
    schema_version: Literal["segmented-capability-closed-loop-result-v1"] = (
        "segmented-capability-closed-loop-result-v1"  # type: ignore[assignment]
    )
    coordination_backend: Literal["segmented-compose-http-v1"] = (
        "segmented-compose-http-v1"  # type: ignore[assignment]
    )
    candidate_exchange: PlantExchange | None = None

    @model_validator(mode="after")
    def require_candidate_exchange_binding(self) -> SegmentedCapabilityClosedLoopResult:
        if self.assessment is None:
            if self.candidate_exchange is not None:
                raise ValueError("candidate exchange requires a retained assessment")
            return self
        exchange = self.candidate_exchange
        if (
            exchange is None
            or exchange.response.status is not PlantResponseStatus.OK
            or not isinstance(
                exchange.response.payload,
                PlantSimulationResponsePayload,
            )
            or exchange.response.payload.assessment != self.assessment
        ):
            raise ValueError("segmented assessment requires its exact candidate exchange")
        return self


class SignedSegmentedCapabilityDispatch(_StrictFrozenModel):
    """Gateway-signed, audience-bound transport envelope for one full dispatch."""

    schema_version: Literal["m4g-signed-capability-dispatch-v1"] = (
        "m4g-signed-capability-dispatch-v1"
    )
    dispatch: SegmentedCapabilityDispatch
    dispatch_sha256: str = Field(pattern=SHA256_PATTERN)
    audience: str = Field(default=OT_CAPABILITY_AUDIENCE, min_length=1)
    gateway_key_id: str = Field(min_length=1)
    transport_nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_window_and_hash(self) -> SignedSegmentedCapabilityDispatch:
        _validate_window(self.issued_at, self.expires_at, label="dispatch envelope")
        if self.dispatch_sha256 != self.dispatch.digest:
            raise ValueError("dispatch envelope hash does not match its dispatch")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @classmethod
    def issue(
        cls,
        *,
        dispatch: SegmentedCapabilityDispatch,
        gateway_key_id: str,
        transport_nonce: str,
        issued_at: datetime,
        expires_at: datetime,
        private_key: Ed25519PrivateKey,
        audience: str = OT_CAPABILITY_AUDIENCE,
    ) -> SignedSegmentedCapabilityDispatch:
        envelope = cls(
            dispatch=dispatch,
            dispatch_sha256=dispatch.digest,
            audience=audience,
            gateway_key_id=gateway_key_id,
            transport_nonce=transport_nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return envelope.model_copy(
            update={"signature": sign_bytes(private_key, envelope.signing_payload())}
        )

    @property
    def digest(self) -> str:
        """Hash the exact signed request, including its signature."""

        return canonical_digest(self)

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return (
            self.dispatch.bindings_match()
            and self.dispatch_sha256 == self.dispatch.digest
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )

    def verify_for_admission(
        self,
        public_key: Ed25519PublicKey,
        *,
        expected_audience: str,
        expected_gateway_key_id: str,
        evaluated_at: datetime,
    ) -> bool:
        return (
            self.audience == expected_audience
            and self.gateway_key_id == expected_gateway_key_id
            and _valid_at(self.issued_at, self.expires_at, evaluated_at)
            and self.verify(public_key)
        )

    def verify_complete_for_ot(
        self,
        gateway_public_key: Ed25519PublicKey,
        *,
        expected_audience: str,
        expected_gateway_key_id: str,
        observer_public_key: Ed25519PublicKey,
        expected_observer_id: str,
        expected_observer_key_id: str,
        expected_observer_boot_epoch: str,
        permit_public_key: Ed25519PublicKey,
        expected_permit_key_id: str,
        expected_plc_id: str,
        expected_plc_key_id: str,
        expected_plc_boot_epoch: str,
        evaluated_at: datetime,
    ) -> bool:
        """Verify both transport authentication and every trusted inner signer.

        The virtual PLC repeats the semantic transaction checks before any
        effect.  This method closes the earlier admission ambiguity: a valid
        gateway wrapper alone is not evidence that the observer or permit
        artifacts are authentic.
        """

        observation = self.dispatch.pre_observation
        permit = self.dispatch.permit
        base = permit.base_permit
        return (
            self.verify_for_admission(
                gateway_public_key,
                expected_audience=expected_audience,
                expected_gateway_key_id=expected_gateway_key_id,
                evaluated_at=evaluated_at,
            )
            and observation.observer_id == expected_observer_id
            and observation.observer_key_id == expected_observer_key_id
            and observation.observer_boot_epoch == expected_observer_boot_epoch
            and observation.verify(observer_public_key)
            and permit.signing_key_id == expected_permit_key_id
            and base.signing_key_id == expected_permit_key_id
            and permit.target_plc_id == expected_plc_id
            and permit.target_plc_key_id == expected_plc_key_id
            and permit.target_plc_boot_epoch == expected_plc_boot_epoch
            and base.audience == expected_plc_id
            and _valid_at(base.issued_at, base.expires_at, evaluated_at)
            and permit.verify(permit_public_key)
        )


class SignedSegmentedCapabilityResponse(_StrictFrozenModel):
    """OT-signed acknowledgment bound to the exact signed gateway envelope."""

    schema_version: Literal["m4g-signed-capability-response-v1"] = (
        "m4g-signed-capability-response-v1"
    )
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    acknowledgment: PlcCommandAcknowledgment
    ot_key_id: str = Field(min_length=1)
    signed_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_aware_signature_time(self) -> SignedSegmentedCapabilityResponse:
        if not _is_aware(self.signed_at):
            raise ValueError("capability response signature time must be timezone-aware")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @staticmethod
    def acknowledgment_matches_request(
        acknowledgment: PlcCommandAcknowledgment,
        request: SignedSegmentedCapabilityDispatch,
    ) -> bool:
        dispatch = request.dispatch
        permit = dispatch.permit
        base = permit.base_permit
        return all(
            (
                acknowledgment.request_digest == dispatch.request.digest,
                acknowledgment.permit_digest == permit.digest,
                acknowledgment.observation_envelope_digest
                == dispatch.pre_observation.envelope_digest,
                acknowledgment.permit_id == base.permit_id,
                acknowledgment.permit_nonce == base.permit_nonce,
                acknowledgment.command_id == base.command.command_id,
                acknowledgment.command_digest == base.command_digest,
                acknowledgment.assessment_digest == dispatch.assessment.digest,
                acknowledgment.proposal_id == dispatch.request.proposal.proposal_id,
                acknowledgment.decision_id == dispatch.decision.decision_id,
            )
        )

    @classmethod
    def issue(
        cls,
        *,
        request: SignedSegmentedCapabilityDispatch,
        acknowledgment: PlcCommandAcknowledgment,
        ot_key_id: str,
        signed_at: datetime,
        private_key: Ed25519PrivateKey,
    ) -> SignedSegmentedCapabilityResponse:
        if not cls.acknowledgment_matches_request(acknowledgment, request):
            raise ValueError("OT acknowledgment is not bound to the signed dispatch")
        if not (
            request.issued_at <= acknowledgment.acknowledged_at <= signed_at
        ):
            raise ValueError("OT response chronology is inconsistent")
        response = cls(
            request_sha256=request.digest,
            acknowledgment=acknowledgment,
            ot_key_id=ot_key_id,
            signed_at=signed_at,
        )
        return response.model_copy(
            update={"signature": sign_bytes(private_key, response.signing_payload())}
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )

    def verify_for_request(
        self,
        public_key: Ed25519PublicKey,
        *,
        request: SignedSegmentedCapabilityDispatch,
        expected_ot_key_id: str,
    ) -> bool:
        return (
            self.ot_key_id == expected_ot_key_id
            and self.request_sha256 == request.digest
            and self.acknowledgment_matches_request(self.acknowledgment, request)
            and self.verify(public_key)
        )

    def verify_complete_for_request(
        self,
        ot_public_key: Ed25519PublicKey,
        *,
        request: SignedSegmentedCapabilityDispatch,
        expected_ot_key_id: str,
        plc_public_key: Ed25519PublicKey,
        expected_plc_id: str,
        expected_plc_key_id: str,
        expected_plc_boot_epoch: str,
        evaluated_at: datetime,
        maximum_future_skew: timedelta = timedelta(seconds=1),
    ) -> bool:
        """Verify the outer response, the PLC ACK, and response chronology."""

        acknowledgment = self.acknowledgment
        if maximum_future_skew < timedelta(0) or not _is_aware(evaluated_at):
            return False
        return (
            self.verify_for_request(
                ot_public_key,
                request=request,
                expected_ot_key_id=expected_ot_key_id,
            )
            and acknowledgment.verify_for_transaction(
                plc_public_key,
                request=request.dispatch.request,
                permit=request.dispatch.permit,
                pre_observation=request.dispatch.pre_observation,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
            )
            and request.issued_at <= acknowledgment.acknowledged_at <= self.signed_at
            and self.signed_at <= evaluated_at + maximum_future_skew
        )


class WorkloadAuthenticatedCapabilityAction(_StrictFrozenModel):
    """Agent action proof bound to the exact gateway method, path, and request."""

    schema_version: Literal["m4g-workload-capability-action-v1"] = (
        "m4g-workload-capability-action-v1"
    )
    method: Literal["POST"] = "POST"
    path: Literal["/v1/capability/actions"] = "/v1/capability/actions"
    audience: str = Field(default=GATEWAY_CAPABILITY_AUDIENCE, min_length=1)
    request: CapabilityActionRequest
    sender_credential: SignedWorkloadCredential
    request_nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_window(self) -> WorkloadAuthenticatedCapabilityAction:
        _validate_window(self.issued_at, self.expires_at, label="agent action proof")
        if self.request_nonce != self.request.proposal.nonce:
            raise ValueError("agent proof nonce must match the proposal replay nonce")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @classmethod
    def issue(
        cls,
        *,
        request: CapabilityActionRequest,
        signer: WorkloadSigner,
        request_nonce: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> WorkloadAuthenticatedCapabilityAction:
        proof = cls(
            request=request,
            sender_credential=signer.credential,
            request_nonce=request_nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return proof.model_copy(
            update={"signature": sign_bytes(signer.private_key, proof.signing_payload())}
        )

    def verify(self, public_key: Ed25519PublicKey, *, evaluated_at: datetime) -> bool:
        return (
            self.audience == GATEWAY_CAPABILITY_AUDIENCE
            and _valid_at(self.issued_at, self.expires_at, evaluated_at)
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )


class WorkloadSignedCapabilityDispatch(_StrictFrozenModel):
    """Credential-bearing outer proof for the existing full dispatch envelope."""

    schema_version: Literal["m4g-workload-capability-dispatch-v1"] = (
        "m4g-workload-capability-dispatch-v1"
    )
    request: SignedSegmentedCapabilityDispatch
    sender_credential: SignedWorkloadCredential
    signature: str = ""

    @model_validator(mode="after")
    def require_leaf_binding(self) -> WorkloadSignedCapabilityDispatch:
        if self.request.gateway_key_id != self.sender_credential.credential.key_id:
            raise ValueError("gateway dispatch key does not match its workload credential")
        return self

    @property
    def transport_nonce(self) -> str:
        return self.request.transport_nonce

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @classmethod
    def issue(
        cls,
        *,
        dispatch: SegmentedCapabilityDispatch,
        signer: WorkloadSigner,
        transport_nonce: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> WorkloadSignedCapabilityDispatch:
        inner = SignedSegmentedCapabilityDispatch.issue(
            dispatch=dispatch,
            gateway_key_id=signer.credential.credential.key_id,
            transport_nonce=transport_nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            private_key=signer.private_key,
        )
        proof = cls(request=inner, sender_credential=signer.credential)
        return proof.model_copy(
            update={"signature": sign_bytes(signer.private_key, proof.signing_payload())}
        )

    def verify(self, public_key: Ed25519PublicKey, *, evaluated_at: datetime) -> bool:
        return (
            self.request.verify_for_admission(
                public_key,
                expected_audience=OT_CAPABILITY_AUDIENCE,
                expected_gateway_key_id=self.sender_credential.credential.key_id,
                evaluated_at=evaluated_at,
            )
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )


class WorkloadSignedCapabilityResponse(_StrictFrozenModel):
    """Credential-bearing OT proof bound to the exact outer gateway request."""

    schema_version: Literal["m4g-workload-capability-response-v1"] = (
        "m4g-workload-capability-response-v1"
    )
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response: SignedSegmentedCapabilityResponse
    audience: str = Field(default=GATEWAY_CAPABILITY_AUDIENCE, min_length=1)
    sender_credential: SignedWorkloadCredential
    signature: str = ""

    @model_validator(mode="after")
    def require_leaf_binding(self) -> WorkloadSignedCapabilityResponse:
        if self.response.ot_key_id != self.sender_credential.credential.key_id:
            raise ValueError("OT response key does not match its workload credential")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @classmethod
    def issue(
        cls,
        *,
        request: WorkloadSignedCapabilityDispatch,
        acknowledgment: PlcCommandAcknowledgment,
        signer: WorkloadSigner,
        signed_at: datetime,
    ) -> WorkloadSignedCapabilityResponse:
        inner = SignedSegmentedCapabilityResponse.issue(
            request=request.request,
            acknowledgment=acknowledgment,
            ot_key_id=signer.credential.credential.key_id,
            signed_at=signed_at,
            private_key=signer.private_key,
        )
        proof = cls(
            request_sha256=request.digest,
            response=inner,
            sender_credential=signer.credential,
        )
        return proof.model_copy(
            update={"signature": sign_bytes(signer.private_key, proof.signing_payload())}
        )

    def verify_for_request(
        self,
        public_key: Ed25519PublicKey,
        *,
        request: WorkloadSignedCapabilityDispatch,
        expected_plc_id: str,
        expected_plc_boot_epoch: str,
        evaluated_at: datetime,
    ) -> bool:
        key_id = self.sender_credential.credential.key_id
        return (
            self.audience == GATEWAY_CAPABILITY_AUDIENCE
            and self.request_sha256 == request.digest
            and self.response.verify_complete_for_request(
                public_key,
                request=request.request,
                expected_ot_key_id=key_id,
                plc_public_key=public_key,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
                evaluated_at=evaluated_at,
            )
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )


class PlantCallerRole(StrEnum):
    OBSERVER = "observer"
    CANDIDATE = "candidate"
    PLC = "plc"


class PlantOperation(StrEnum):
    CAPTURE = "capture"
    READ = "read"
    SIMULATE = "simulate"
    APPLY = "apply"


class PlantCapturePayload(_StrictFrozenModel):
    schema_version: Literal["m4g-plant-capture-v1"] = "m4g-plant-capture-v1"
    correlation_id: str = Field(min_length=1, max_length=256)
    challenge_nonce: str = Field(min_length=16, max_length=256)


class PlantReadPayload(_StrictFrozenModel):
    schema_version: Literal["m4g-plant-read-v1"] = "m4g-plant-read-v1"
    correlation_id: str = Field(min_length=1, max_length=256)


class PlantSimulatePayload(_StrictFrozenModel):
    schema_version: Literal["m4g-plant-simulate-v1"] = "m4g-plant-simulate-v1"
    command: PhysicalControlCommand


class PlantApplyPayload(_StrictFrozenModel):
    """Low-level CAS command; semantic authorization remains at the OT adapter.

    A plant signature does not establish permit validity or semantic replay
    resistance.  The plant receives no gateway request or full permit.  It does
    receive the OT-asserted authorization deadline so that both that deadline
    and the shorter plant-call deadline can be rechecked immediately before the
    atomic compare-and-swap effect.
    """

    schema_version: Literal["m4g-plant-apply-v1"] = "m4g-plant-apply-v1"
    command: PhysicalControlCommand
    expected_pre_state_version: int = Field(ge=0)
    expected_pre_state_digest: str = Field(pattern=SHA256_PATTERN)
    expected_pre_observation_digest: str = Field(pattern=SHA256_PATTERN)
    expected_post_state_digest: str = Field(pattern=SHA256_PATTERN)
    expected_post_topology_digest: str = Field(pattern=SHA256_PATTERN)
    authorization_expires_at: datetime

    @model_validator(mode="after")
    def require_aware_authorization_deadline(self) -> PlantApplyPayload:
        if not _is_aware(self.authorization_expires_at):
            raise ValueError("plant authorization deadline must be timezone-aware")
        return self


PlantCallPayload = Annotated[
    PlantCapturePayload | PlantReadPayload | PlantSimulatePayload | PlantApplyPayload,
    Field(discriminator="schema_version"),
]

_ROLE_OPERATIONS: dict[PlantCallerRole, frozenset[PlantOperation]] = {
    PlantCallerRole.OBSERVER: frozenset({PlantOperation.CAPTURE}),
    PlantCallerRole.CANDIDATE: frozenset({PlantOperation.SIMULATE}),
    PlantCallerRole.PLC: frozenset(
        {PlantOperation.READ, PlantOperation.SIMULATE, PlantOperation.APPLY}
    ),
}
_OPERATION_PAYLOAD_TYPES: dict[PlantOperation, type[_StrictFrozenModel]] = {
    PlantOperation.CAPTURE: PlantCapturePayload,
    PlantOperation.READ: PlantReadPayload,
    PlantOperation.SIMULATE: PlantSimulatePayload,
    PlantOperation.APPLY: PlantApplyPayload,
}


class SignedPlantCall(_StrictFrozenModel):
    """A role-constrained signed request to the authoritative physical plant."""

    schema_version: Literal["m4g-signed-plant-call-v1"] = (
        "m4g-signed-plant-call-v1"
    )
    role: PlantCallerRole
    operation: PlantOperation
    payload: PlantCallPayload
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    audience: str = Field(default=PHYSICAL_PLANT_AUDIENCE, min_length=1)
    target_plant_key_id: str = Field(min_length=1, max_length=256)
    target_plant_boot_epoch: str = Field(min_length=16, max_length=256)
    caller_key_id: str = Field(min_length=1)
    call_nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    def role_operation_matches(self) -> bool:
        return (
            self.operation in _ROLE_OPERATIONS[self.role]
            and isinstance(self.payload, _OPERATION_PAYLOAD_TYPES[self.operation])
        )

    @model_validator(mode="after")
    def require_role_operation_window_and_hash(self) -> SignedPlantCall:
        if not self.role_operation_matches():
            raise ValueError("plant role is not authorized for the requested operation")
        _validate_window(self.issued_at, self.expires_at, label="plant call")
        if self.payload_sha256 != canonical_digest(self.payload):
            raise ValueError("plant call payload hash does not match its payload")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @classmethod
    def issue(
        cls,
        *,
        role: PlantCallerRole,
        operation: PlantOperation,
        payload: PlantCapturePayload
        | PlantReadPayload
        | PlantSimulatePayload
        | PlantApplyPayload,
        caller_key_id: str,
        target_plant_key_id: str,
        target_plant_boot_epoch: str,
        call_nonce: str,
        issued_at: datetime,
        expires_at: datetime,
        private_key: Ed25519PrivateKey,
        audience: str = PHYSICAL_PLANT_AUDIENCE,
    ) -> SignedPlantCall:
        call = cls(
            role=role,
            operation=operation,
            payload=payload,
            payload_sha256=canonical_digest(payload),
            audience=audience,
            target_plant_key_id=target_plant_key_id,
            target_plant_boot_epoch=target_plant_boot_epoch,
            caller_key_id=caller_key_id,
            call_nonce=call_nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return call.model_copy(
            update={"signature": sign_bytes(private_key, call.signing_payload())}
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return (
            self.role_operation_matches()
            and self.payload_sha256 == canonical_digest(self.payload)
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )

    def verify_for_plant(
        self,
        public_key: Ed25519PublicKey,
        *,
        expected_role: PlantCallerRole,
        expected_caller_key_id: str,
        expected_audience: str,
        expected_plant_key_id: str,
        expected_plant_boot_epoch: str,
        evaluated_at: datetime,
    ) -> bool:
        return (
            self.role is expected_role
            and self.caller_key_id == expected_caller_key_id
            and self.audience == expected_audience
            and self.target_plant_key_id == expected_plant_key_id
            and self.target_plant_boot_epoch == expected_plant_boot_epoch
            and _valid_at(self.issued_at, self.expires_at, evaluated_at)
            and self.verify(public_key)
        )


class PlantResponseStatus(StrEnum):
    OK = "ok"
    REJECTED = "rejected"
    ERROR = "error"


class PlantStateResponsePayload(_StrictFrozenModel):
    """Successful capture, read, or apply result."""

    schema_version: Literal["m4g-plant-state-response-v1"] = (
        "m4g-plant-state-response-v1"
    )
    snapshot: PhysicalStateSnapshot

    @model_validator(mode="after")
    def require_valid_snapshot_digest(self) -> PlantStateResponsePayload:
        if not self.snapshot.verify_digest():
            raise ValueError("plant response snapshot digest is invalid")
        return self


class PlantSimulationResponsePayload(_StrictFrozenModel):
    """Successful candidate-simulation result."""

    schema_version: Literal["m4g-plant-simulation-response-v1"] = (
        "m4g-plant-simulation-response-v1"
    )
    assessment: CandidateAssessment


class PlantFailureResponsePayload(_StrictFrozenModel):
    """Closed negative response with no implied state or assessment result."""

    schema_version: Literal["m4g-plant-failure-response-v1"] = (
        "m4g-plant-failure-response-v1"
    )
    status: Literal[PlantResponseStatus.REJECTED, PlantResponseStatus.ERROR]
    reason: str = Field(min_length=1, max_length=512)


PlantResponsePayload = Annotated[
    PlantStateResponsePayload
    | PlantSimulationResponsePayload
    | PlantFailureResponsePayload,
    Field(discriminator="schema_version"),
]

_STATE_RESPONSE_OPERATIONS = frozenset(
    {PlantOperation.CAPTURE, PlantOperation.READ, PlantOperation.APPLY}
)


class SignedPlantResponse(_StrictFrozenModel):
    """Plant-signed result bound to one exact signed plant call."""

    schema_version: Literal["m4g-signed-plant-response-v1"] = (
        "m4g-signed-plant-response-v1"
    )
    call_sha256: str = Field(pattern=SHA256_PATTERN)
    operation: PlantOperation
    status: PlantResponseStatus
    payload: PlantResponsePayload
    plant_boot_epoch: str = Field(min_length=16, max_length=256)
    plant_key_id: str = Field(min_length=1, max_length=256)
    signed_at: datetime
    signature: str = ""

    def response_shape_matches(self) -> bool:
        if self.status is PlantResponseStatus.OK:
            if self.operation is PlantOperation.SIMULATE:
                return isinstance(self.payload, PlantSimulationResponsePayload)
            return self.operation in _STATE_RESPONSE_OPERATIONS and isinstance(
                self.payload,
                PlantStateResponsePayload,
            )
        return (
            isinstance(self.payload, PlantFailureResponsePayload)
            and self.payload.status is self.status
        )

    def payload_matches_call(self, call: SignedPlantCall) -> bool:
        if self.operation is not call.operation or not self.response_shape_matches():
            return False
        if self.status is not PlantResponseStatus.OK:
            return True
        if self.operation is PlantOperation.SIMULATE:
            return (
                isinstance(call.payload, PlantSimulatePayload)
                and isinstance(self.payload, PlantSimulationResponsePayload)
                and self.payload.assessment.command_digest == call.payload.command.digest
            )
        if self.operation is PlantOperation.APPLY:
            return (
                isinstance(call.payload, PlantApplyPayload)
                and isinstance(self.payload, PlantStateResponsePayload)
                and self.payload.snapshot.state_version
                == call.payload.expected_pre_state_version + 1
                and self.payload.snapshot.state_digest
                == call.payload.expected_post_state_digest
                and self.payload.snapshot.topology_digest
                == call.payload.expected_post_topology_digest
            )
        return (
            self.operation in {PlantOperation.CAPTURE, PlantOperation.READ}
            and isinstance(self.payload, PlantStateResponsePayload)
        )

    @model_validator(mode="after")
    def require_response_shape_and_time(self) -> SignedPlantResponse:
        if not self.response_shape_matches():
            raise ValueError("plant response payload does not match operation and status")
        if not _is_aware(self.signed_at):
            raise ValueError("plant response signature time must be timezone-aware")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @classmethod
    def issue(
        cls,
        *,
        call: SignedPlantCall,
        status: PlantResponseStatus,
        payload: PlantStateResponsePayload
        | PlantSimulationResponsePayload
        | PlantFailureResponsePayload,
        plant_boot_epoch: str,
        plant_key_id: str,
        signed_at: datetime,
        private_key: Ed25519PrivateKey,
    ) -> SignedPlantResponse:
        response = cls(
            call_sha256=call.digest,
            operation=call.operation,
            status=status,
            payload=payload,
            plant_boot_epoch=plant_boot_epoch,
            plant_key_id=plant_key_id,
            signed_at=signed_at,
        )
        if not response.payload_matches_call(call):
            raise ValueError("plant response payload does not match its signed call")
        return response.model_copy(
            update={"signature": sign_bytes(private_key, response.signing_payload())}
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return (
            self.response_shape_matches()
            and _is_aware(self.signed_at)
            and bool(self.signature)
            and verify_bytes(public_key, self.signing_payload(), self.signature)
        )

    def verify_for_call(
        self,
        public_key: Ed25519PublicKey,
        *,
        call: SignedPlantCall,
        expected_plant_boot_epoch: str,
        expected_plant_key_id: str,
    ) -> bool:
        return (
            call.role_operation_matches()
            and call.payload_sha256 == canonical_digest(call.payload)
            and self.call_sha256 == call.digest
            and self.operation is call.operation
            and self.payload_matches_call(call)
            and self.plant_boot_epoch == expected_plant_boot_epoch
            and self.plant_key_id == expected_plant_key_id
            and self.signed_at >= call.issued_at
            and self.signed_at < call.expires_at
            and self.verify(public_key)
        )


class PlantExchange(_StrictFrozenModel):
    """One signed caller request paired with the plant's signed response."""

    schema_version: Literal["m4g-plant-exchange-v1"] = "m4g-plant-exchange-v1"
    call: SignedPlantCall
    response: SignedPlantResponse

    def bindings_match(self) -> bool:
        return (
            self.response.call_sha256 == self.call.digest
            and self.response.operation is self.call.operation
            and self.response.payload_matches_call(self.call)
            and self.response.signed_at >= self.call.issued_at
            and self.response.signed_at < self.call.expires_at
        )

    @model_validator(mode="after")
    def require_exact_call_binding(self) -> PlantExchange:
        if not self.bindings_match():
            raise ValueError("plant response is not bound to the exact signed call")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    def verify(
        self,
        caller_public_key: Ed25519PublicKey,
        plant_public_key: Ed25519PublicKey,
        *,
        expected_role: PlantCallerRole,
        expected_caller_key_id: str,
        expected_audience: str,
        expected_plant_boot_epoch: str,
        expected_plant_key_id: str,
        evaluated_at: datetime,
    ) -> bool:
        return (
            self.bindings_match()
            and self.call.verify_for_plant(
                caller_public_key,
                expected_role=expected_role,
                expected_caller_key_id=expected_caller_key_id,
                expected_audience=expected_audience,
                expected_plant_key_id=expected_plant_key_id,
                expected_plant_boot_epoch=expected_plant_boot_epoch,
                evaluated_at=evaluated_at,
            )
            and self.response.verify_for_call(
                plant_public_key,
                call=self.call,
                expected_plant_boot_epoch=expected_plant_boot_epoch,
                expected_plant_key_id=expected_plant_key_id,
            )
        )


SegmentedCapabilityClosedLoopResult.model_rebuild()
