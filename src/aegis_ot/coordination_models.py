"""Closed M4i contracts for durable effect coordination and reconciliation.

The models in this module define an application-level, single-writer
prepare/commit/query protocol.  They do not claim distributed consensus,
rollback resistance, or exactly-once execution across independent hosts.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .capability_models import CapabilityActionRequest, PlcCommandAcknowledgment
from .crypto import sign_bytes, verify_bytes
from .physical_models import (
    SHA256_PATTERN,
    CommandStatus,
    canonical_digest,
)
from .segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    SegmentedCapabilityDispatch,
)
from .workload_identity import (
    SignedWorkloadCredential,
    WorkloadIdentityError,
    WorkloadIdentityVerifier,
    WorkloadRole,
    WorkloadSigner,
)

MAX_COORDINATION_REQUEST_TTL = timedelta(seconds=60)
MAX_COORDINATION_FUTURE_SKEW = timedelta(seconds=1)
EFFECT_COORDINATOR_AUDIENCE = "aegis-ot:m4i:effect-coordinator"
GATEWAY_COORDINATION_AUDIENCE = "aegis-ot:m4i:gateway"
# Compatibility alias for the unpublished first draft.  New code should use
# the role-neutral effect-coordinator name.
PLANT_COORDINATION_AUDIENCE = EFFECT_COORDINATOR_AUDIENCE


class _ClosedModel(BaseModel):
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
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _validate_request_window(
    issued_at: datetime,
    expires_at: datetime,
    *,
    label: str,
) -> None:
    if not _is_aware(issued_at) or not _is_aware(expires_at):
        raise ValueError(f"{label} timestamps must be timezone-aware")
    if expires_at <= issued_at:
        raise ValueError(f"{label} expiry must follow issuance")
    if expires_at - issued_at > MAX_COORDINATION_REQUEST_TTL:
        raise ValueError(f"{label} lifetime exceeds the registered maximum")


def _valid_at(issued_at: datetime, expires_at: datetime, evaluated_at: datetime) -> bool:
    return _is_aware(evaluated_at) and issued_at <= evaluated_at < expires_at


def _credential_public_key(
    verifier: WorkloadIdentityVerifier,
    credential: SignedWorkloadCredential,
    *,
    expected_role: WorkloadRole,
    expected_audience: str,
    expected_subject: str,
    evaluated_at: datetime,
) -> Ed25519PublicKey | None:
    try:
        return verifier.verify_credential(
            credential,
            expected_role=expected_role,
            expected_audience=expected_audience,
            expected_subject=expected_subject,
            now=evaluated_at,
        )
    except WorkloadIdentityError:
        return None


def _historical_credential_public_key(
    verifier: WorkloadIdentityVerifier,
    credential: SignedWorkloadCredential,
    *,
    expected_role: WorkloadRole,
    expected_audience: str,
    expected_subject: str,
    authenticated_at: datetime,
    evaluated_at: datetime,
    maximum_future_skew: timedelta,
) -> Ed25519PublicKey | None:
    """Validate retained admission against the current signed lifecycle state."""

    try:
        return verifier.verify_historical_credential(
            credential,
            expected_role=expected_role,
            expected_audience=expected_audience,
            expected_subject=expected_subject,
            authenticated_at=authenticated_at,
            now=evaluated_at,
            maximum_future_skew=maximum_future_skew,
        )
    except WorkloadIdentityError:
        return None


def _credential_claim_valid_at(
    credential: SignedWorkloadCredential,
    asserted_at: datetime,
) -> bool:
    claims = credential.credential
    return (
        _is_aware(asserted_at)
        and claims.issued_at <= claims.not_before <= asserted_at < claims.expires_at
    )


def _require_signer_match(signer: WorkloadSigner, payload: bytes, signature: str) -> None:
    if not verify_bytes(
        signer.credential.credential.public_key,
        payload,
        signature,
    ):
        raise ValueError("workload signer does not match its authority-issued credential")


class CoordinationState(StrEnum):
    """Durable gateway or effect-coordinator knowledge about one semantic effect."""

    RECEIVED = "received"
    DISPATCH_ARMED = "dispatch_armed"
    COMMIT_ACCEPTED = "commit_accepted"
    NOT_DISPATCHED = "not_dispatched"
    UNKNOWN_EFFECT = "unknown_effect"
    APPLIED = "applied"
    REJECTED = "rejected"

    @property
    def terminal(self) -> bool:
        return self in {
            CoordinationState.NOT_DISPATCHED,
            CoordinationState.APPLIED,
            CoordinationState.REJECTED,
        }

    def can_transition_to(self, target: CoordinationState) -> bool:
        return target in _LEGAL_TRANSITIONS[self]


_LEGAL_TRANSITIONS: dict[CoordinationState, frozenset[CoordinationState]] = {
    CoordinationState.RECEIVED: frozenset(
        {CoordinationState.DISPATCH_ARMED, CoordinationState.NOT_DISPATCHED}
    ),
    CoordinationState.DISPATCH_ARMED: frozenset(
        {CoordinationState.COMMIT_ACCEPTED, CoordinationState.NOT_DISPATCHED}
    ),
    CoordinationState.COMMIT_ACCEPTED: frozenset(
        {
            CoordinationState.UNKNOWN_EFFECT,
            CoordinationState.APPLIED,
            CoordinationState.REJECTED,
        }
    ),
    CoordinationState.UNKNOWN_EFFECT: frozenset(
        {CoordinationState.APPLIED, CoordinationState.REJECTED}
    ),
    CoordinationState.NOT_DISPATCHED: frozenset(),
    CoordinationState.APPLIED: frozenset(),
    CoordinationState.REJECTED: frozenset(),
}


class EffectDisposition(StrEnum):
    """Evidence-bounded disposition exposed outside the coordinator."""

    NOT_DISPATCHED = "not_dispatched"
    UNKNOWN_EFFECT = "unknown_effect"
    APPLIED = "applied"
    REJECTED = "rejected"

    @classmethod
    def for_state(cls, state: CoordinationState) -> EffectDisposition | None:
        if state in {
            CoordinationState.RECEIVED,
            CoordinationState.DISPATCH_ARMED,
            CoordinationState.COMMIT_ACCEPTED,
        }:
            return None
        return cls(state.value)


class EffectIdentity(_ClosedModel):
    """Canonical semantic effect key, independent of M4i delivery lifecycle.

    Exact proposal, decision, command, and authorization trace remains in the
    signed dispatch.  It is deliberately absent here so one ``effect_id`` has
    exactly one possible ``EffectIdentity`` value.
    """

    schema_version: Literal["m4i-effect-identity-v1"] = "m4i-effect-identity-v1"
    effect_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    command_semantics_sha256: str = Field(pattern=SHA256_PATTERN)
    target_id: str = Field(min_length=1, max_length=256)
    authorized_state_sha256: str = Field(pattern=SHA256_PATTERN)
    authorized_state_version: int = Field(ge=0)
    authorized_observation_sha256: str = Field(pattern=SHA256_PATTERN)
    authorized_topology_sha256: str = Field(pattern=SHA256_PATTERN)
    authorized_model_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_post_state_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_post_state_version: int = Field(ge=0)
    expected_post_topology_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator(
        "effect_id",
        "target_id",
    )
    @classmethod
    def require_canonical_identifier(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("effect identity identifiers cannot have outer whitespace")
        return value

    @model_validator(mode="after")
    def require_stable_identity(self) -> EffectIdentity:
        if self.expected_post_state_version != self.authorized_state_version + 1:
            raise ValueError("effect identity must advance exactly one state version")
        if self.effect_id != self.derived_effect_id():
            raise ValueError("effect ID is not derived from its stable semantic material")
        return self

    def stable_material(self) -> dict[str, Any]:
        """Return consequence semantics while excluding delivery/key lifecycle."""

        return {
            "schema_version": "m4i-effect-material-v1",
            "request_sha256": self.request_sha256,
            "command_semantics_sha256": self.command_semantics_sha256,
            "target_id": self.target_id,
            "authorized_state_sha256": self.authorized_state_sha256,
            "authorized_state_version": self.authorized_state_version,
            "authorized_observation_sha256": self.authorized_observation_sha256,
            "authorized_topology_sha256": self.authorized_topology_sha256,
            "authorized_model_sha256": self.authorized_model_sha256,
            "expected_post_state_sha256": self.expected_post_state_sha256,
            "expected_post_state_version": self.expected_post_state_version,
            "expected_post_topology_sha256": self.expected_post_topology_sha256,
        }

    def derived_effect_id(self) -> str:
        return f"sha256:{canonical_digest(self.stable_material())}"

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @classmethod
    def from_dispatch(
        cls,
        dispatch: SegmentedCapabilityDispatch,
    ) -> EffectIdentity:
        base = dispatch.permit.base_permit
        command_semantics = base.command.model_dump(
            mode="json",
            exclude={"command_id", "proposal_id"},
        )
        material: dict[str, Any] = {
            "request_sha256": dispatch.request.digest,
            "command_semantics_sha256": canonical_digest(command_semantics),
            "target_id": dispatch.permit.target_plc_id,
            "authorized_state_sha256": base.state_digest,
            "authorized_state_version": base.state_version,
            "authorized_observation_sha256": base.observation_digest,
            "authorized_topology_sha256": base.topology_digest,
            "authorized_model_sha256": base.model_digest,
            "expected_post_state_sha256": base.expected_post_state_digest,
            "expected_post_state_version": base.expected_post_state_version,
            "expected_post_topology_sha256": base.expected_post_topology_digest,
        }
        effect_material = {"schema_version": "m4i-effect-material-v1", **material}
        effect_id = f"sha256:{canonical_digest(effect_material)}"
        return cls(effect_id=effect_id, **material)


class WorkloadAuthenticatedEffectReconciliation(_ClosedModel):
    """Agent proof requesting recovery of one exact retained capability action."""

    schema_version: Literal["m4i-workload-effect-reconciliation-v1"] = (
        "m4i-workload-effect-reconciliation-v1"
    )
    method: Literal["POST"] = "POST"
    path: Literal["/v1/capability/effects/reconcile"] = (
        "/v1/capability/effects/reconcile"
    )
    audience: str = Field(default=GATEWAY_CAPABILITY_AUDIENCE, min_length=1)
    request: CapabilityActionRequest
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    sender_credential: SignedWorkloadCredential
    request_nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_closed_request(self) -> WorkloadAuthenticatedEffectReconciliation:
        _validate_request_window(
            self.issued_at,
            self.expires_at,
            label="effect reconciliation request",
        )
        if self.request_sha256 != self.request.digest:
            raise ValueError("effect reconciliation action hash is inconsistent")
        if self.request_nonce == self.request.proposal.nonce:
            raise ValueError("effect reconciliation nonce must be fresh")
        credential = self.sender_credential.credential
        if credential.role is not WorkloadRole.AGENT:
            raise ValueError("effect reconciliation requires an agent workload credential")
        if self.audience not in credential.audiences:
            raise ValueError("effect reconciliation audience is not authorized")
        if not _credential_claim_valid_at(self.sender_credential, self.issued_at):
            raise ValueError("effect reconciliation credential is not valid at issuance")
        return self

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @property
    def sender_subject(self) -> str:
        return self.sender_credential.credential.subject

    @classmethod
    def issue(
        cls,
        *,
        request: CapabilityActionRequest,
        signer: WorkloadSigner,
        request_nonce: str,
        issued_at: datetime,
        expires_at: datetime,
        audience: str = GATEWAY_CAPABILITY_AUDIENCE,
    ) -> WorkloadAuthenticatedEffectReconciliation:
        reconciliation = cls(
            request=request,
            request_sha256=request.digest,
            audience=audience,
            sender_credential=signer.credential,
            request_nonce=request_nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signed = reconciliation.model_copy(
            update={
                "signature": sign_bytes(
                    signer.private_key,
                    reconciliation.signing_payload(),
                )
            }
        )
        _require_signer_match(signer, signed.signing_payload(), signed.signature)
        return signed

    def verify(self, public_key: Ed25519PublicKey | None = None) -> bool:
        public_key = public_key or self.sender_credential.credential.public_key
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )

    def verify_for_admission(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        expected_agent_subject: str,
        evaluated_at: datetime,
    ) -> bool:
        public_key = _credential_public_key(
            verifier,
            self.sender_credential,
            expected_role=WorkloadRole.AGENT,
            expected_audience=GATEWAY_CAPABILITY_AUDIENCE,
            expected_subject=expected_agent_subject,
            evaluated_at=evaluated_at,
        )
        return (
            public_key is not None
            and self.audience == GATEWAY_CAPABILITY_AUDIENCE
            and self.sender_subject == expected_agent_subject
            and self.request_sha256 == self.request.digest
            and _valid_at(self.issued_at, self.expires_at, evaluated_at)
            and self.verify(public_key)
        )


def _verify_inner_dispatch(
    dispatch: SegmentedCapabilityDispatch,
    *,
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
    observation = dispatch.pre_observation
    permit = dispatch.permit
    base = permit.base_permit
    return (
        dispatch.bindings_match()
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


class _SignedRequest(_ClosedModel):
    effect: EffectIdentity
    effect_sha256: str = Field(pattern=SHA256_PATTERN)
    audience: str = Field(default=EFFECT_COORDINATOR_AUDIENCE, min_length=1)
    sender_credential: SignedWorkloadCredential
    request_nonce: str = Field(min_length=16, max_length=256)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""

    def _validate_common(self, *, label: str) -> None:
        _validate_request_window(self.issued_at, self.expires_at, label=label)
        if self.effect_sha256 != self.effect.digest:
            raise ValueError(f"{label} effect hash is inconsistent")
        credential = self.sender_credential.credential
        if credential.role is not WorkloadRole.GATEWAY:
            raise ValueError(f"{label} requires a gateway workload credential")
        if self.audience not in credential.audiences:
            raise ValueError(f"{label} audience is not authorized by its credential")
        if not _credential_claim_valid_at(self.sender_credential, self.issued_at):
            raise ValueError(f"{label} credential is not valid at issuance")

    @property
    def sender_subject(self) -> str:
        return self.sender_credential.credential.subject

    @property
    def sender_key_id(self) -> str:
        return self.sender_credential.credential.key_id

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @property
    def digest(self) -> str:
        """Hash the exact signed request, including the signature."""

        return canonical_digest(self)

    def verify(self, public_key: Ed25519PublicKey | None = None) -> bool:
        public_key = public_key or self.sender_credential.credential.public_key
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )

    def verify_workload_envelope_for_admission(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        expected_audience: str,
        expected_sender_subject: str,
        evaluated_at: datetime,
    ) -> bool:
        """Verify only the current gateway workload envelope.

        This deliberately does not authenticate the embedded observer or permit
        artifacts.  Call a concrete ``verify_complete_for_admission`` method at
        the OT trust boundary before durable admission.
        """

        public_key = _credential_public_key(
            verifier,
            self.sender_credential,
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=expected_audience,
            expected_subject=expected_sender_subject,
            evaluated_at=evaluated_at,
        )
        return (
            public_key is not None
            and self.effect_sha256 == self.effect.digest
            and self.audience == expected_audience
            and self.sender_subject == expected_sender_subject
            and _valid_at(self.issued_at, self.expires_at, evaluated_at)
            and self.verify(public_key)
        )


class SignedEffectPrepareRequest(_SignedRequest):
    """Gateway-signed prepare intent binding the exact admitted dispatch."""

    schema_version: Literal["m4i-effect-prepare-request-v1"] = "m4i-effect-prepare-request-v1"
    dispatch: SegmentedCapabilityDispatch
    dispatch_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_closed_prepare(self) -> SignedEffectPrepareRequest:
        self._validate_common(label="effect prepare request")
        if self.dispatch_sha256 != self.dispatch.digest:
            raise ValueError("effect prepare dispatch hash is inconsistent")
        if self.effect != EffectIdentity.from_dispatch(self.dispatch):
            raise ValueError("effect prepare identity does not match its exact dispatch")
        return self

    @classmethod
    def issue(
        cls,
        *,
        dispatch: SegmentedCapabilityDispatch,
        signer: WorkloadSigner,
        request_nonce: str,
        issued_at: datetime,
        expires_at: datetime,
        audience: str = EFFECT_COORDINATOR_AUDIENCE,
    ) -> SignedEffectPrepareRequest:
        effect = EffectIdentity.from_dispatch(dispatch)
        request = cls(
            effect=effect,
            effect_sha256=effect.digest,
            dispatch=dispatch,
            dispatch_sha256=dispatch.digest,
            audience=audience,
            sender_credential=signer.credential,
            request_nonce=request_nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signed = request.model_copy(
            update={"signature": sign_bytes(signer.private_key, request.signing_payload())}
        )
        _require_signer_match(signer, signed.signing_payload(), signed.signature)
        return signed

    def verify_complete_for_admission(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        expected_gateway_subject: str,
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
        expected_audience: str = EFFECT_COORDINATOR_AUDIENCE,
    ) -> bool:
        """Verify workload transport plus every trusted inner dispatch signer."""

        return self.verify_workload_envelope_for_admission(
            verifier,
            expected_audience=expected_audience,
            expected_sender_subject=expected_gateway_subject,
            evaluated_at=evaluated_at,
        ) and _verify_inner_dispatch(
            self.dispatch,
            observer_public_key=observer_public_key,
            expected_observer_id=expected_observer_id,
            expected_observer_key_id=expected_observer_key_id,
            expected_observer_boot_epoch=expected_observer_boot_epoch,
            permit_public_key=permit_public_key,
            expected_permit_key_id=expected_permit_key_id,
            expected_plc_id=expected_plc_id,
            expected_plc_key_id=expected_plc_key_id,
            expected_plc_boot_epoch=expected_plc_boot_epoch,
            evaluated_at=evaluated_at,
        )


class CoordinationReceipt(_ClosedModel):
    """Coordinator-signed proof that an exact effect was durably prepared."""

    schema_version: Literal["m4i-coordination-receipt-v1"] = "m4i-coordination-receipt-v1"
    effect: EffectIdentity
    effect_sha256: str = Field(pattern=SHA256_PATTERN)
    prepare_request: SignedEffectPrepareRequest
    prepare_request_sha256: str = Field(pattern=SHA256_PATTERN)
    state: Literal[CoordinationState.DISPATCH_ARMED] = CoordinationState.DISPATCH_ARMED
    audience: str = Field(default=GATEWAY_COORDINATION_AUDIENCE, min_length=1)
    coordinator_credential: SignedWorkloadCredential
    prepared_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_closed_receipt(self) -> CoordinationReceipt:
        if self.effect_sha256 != self.effect.digest:
            raise ValueError("coordination receipt effect hash is inconsistent")
        if (
            self.prepare_request.effect != self.effect
            or self.prepare_request_sha256 != self.prepare_request.digest
        ):
            raise ValueError("coordination receipt prepare binding is inconsistent")
        if not _is_aware(self.prepared_at):
            raise ValueError("coordination receipt time must be timezone-aware")
        if not (
            self.prepare_request.issued_at <= self.prepared_at < self.prepare_request.expires_at
        ):
            raise ValueError("coordination receipt time is outside the prepare window")
        credential = self.coordinator_credential.credential
        if credential.role is not WorkloadRole.OT_ADAPTER:
            raise ValueError("coordination receipt requires an OT coordinator credential")
        if self.audience not in credential.audiences:
            raise ValueError("coordination receipt audience is not authorized")
        if not _credential_claim_valid_at(self.coordinator_credential, self.prepared_at):
            raise ValueError("coordination receipt credential is not valid at preparation")
        if credential.key_id != self.prepare_request.dispatch.permit.target_plc_key_id:
            raise ValueError("coordination receipt signer is not the prepared OT target")
        return self

    @property
    def coordinator_subject(self) -> str:
        return self.coordinator_credential.credential.subject

    @property
    def coordinator_key_id(self) -> str:
        return self.coordinator_credential.credential.key_id

    @property
    def plant_subject(self) -> str:
        """Compatibility projection; the signer is the effect coordinator."""

        return self.coordinator_subject

    @property
    def plant_key_id(self) -> str:
        """Compatibility projection; the signer is the effect coordinator."""

        return self.coordinator_key_id

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @classmethod
    def issue(
        cls,
        *,
        request: SignedEffectPrepareRequest,
        signer: WorkloadSigner,
        prepared_at: datetime,
        audience: str = GATEWAY_COORDINATION_AUDIENCE,
    ) -> CoordinationReceipt:
        receipt = cls(
            effect=request.effect,
            effect_sha256=request.effect.digest,
            prepare_request=request,
            prepare_request_sha256=request.digest,
            audience=audience,
            coordinator_credential=signer.credential,
            prepared_at=prepared_at,
        )
        signed = receipt.model_copy(
            update={"signature": sign_bytes(signer.private_key, receipt.signing_payload())}
        )
        _require_signer_match(signer, signed.signing_payload(), signed.signature)
        return signed

    def verify(self, public_key: Ed25519PublicKey | None = None) -> bool:
        public_key = public_key or self.coordinator_credential.credential.public_key
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )

    def verify_for_request(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        request: SignedEffectPrepareRequest,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
        evaluated_at: datetime,
        expected_audience: str = GATEWAY_COORDINATION_AUDIENCE,
        expected_request_audience: str = EFFECT_COORDINATOR_AUDIENCE,
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        if maximum_future_skew < timedelta(0) or not _is_aware(evaluated_at):
            return False
        gateway_public_key = _historical_credential_public_key(
            verifier,
            request.sender_credential,
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=expected_request_audience,
            expected_subject=expected_gateway_subject,
            authenticated_at=self.prepared_at,
            evaluated_at=evaluated_at,
            maximum_future_skew=maximum_future_skew,
        )
        coordinator_public_key = _historical_credential_public_key(
            verifier,
            self.coordinator_credential,
            expected_role=WorkloadRole.OT_ADAPTER,
            expected_audience=expected_audience,
            expected_subject=expected_coordinator_subject,
            authenticated_at=self.prepared_at,
            evaluated_at=evaluated_at,
            maximum_future_skew=maximum_future_skew,
        )
        return (
            gateway_public_key is not None
            and coordinator_public_key is not None
            and self.prepare_request == request
            and self.effect == request.effect
            and self.effect_sha256 == request.effect.digest
            and self.prepare_request_sha256 == request.digest
            and request.audience == expected_request_audience
            and self.audience == expected_audience
            and self.coordinator_subject == expected_coordinator_subject
            and self.coordinator_key_id == request.dispatch.permit.target_plc_key_id
            and request.issued_at <= self.prepared_at < request.expires_at
            and self.prepared_at <= evaluated_at + maximum_future_skew
            and request.verify(gateway_public_key)
            and self.verify(coordinator_public_key)
        )

    def verify_historical_for_request(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        request: SignedEffectPrepareRequest,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
        evaluated_at: datetime,
        expected_audience: str = GATEWAY_COORDINATION_AUDIENCE,
        expected_request_audience: str = EFFECT_COORDINATOR_AUDIENCE,
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        """Verify receipt-time identities without rejecting later leaf rotation."""

        if maximum_future_skew < timedelta(0) or not _is_aware(evaluated_at):
            return False
        gateway_public_key = _historical_credential_public_key(
            verifier,
            request.sender_credential,
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=expected_request_audience,
            expected_subject=expected_gateway_subject,
            authenticated_at=self.prepared_at,
            evaluated_at=evaluated_at,
            maximum_future_skew=maximum_future_skew,
        )
        coordinator_public_key = _historical_credential_public_key(
            verifier,
            self.coordinator_credential,
            expected_role=WorkloadRole.OT_ADAPTER,
            expected_audience=expected_audience,
            expected_subject=expected_coordinator_subject,
            authenticated_at=self.prepared_at,
            evaluated_at=evaluated_at,
            maximum_future_skew=maximum_future_skew,
        )
        return (
            gateway_public_key is not None
            and coordinator_public_key is not None
            and self.prepare_request == request
            and self.effect == request.effect
            and self.effect_sha256 == request.effect.digest
            and self.prepare_request_sha256 == request.digest
            and request.audience == expected_request_audience
            and self.audience == expected_audience
            and self.coordinator_subject == expected_coordinator_subject
            and self.coordinator_key_id == request.dispatch.permit.target_plc_key_id
            and request.issued_at <= self.prepared_at < request.expires_at
            and self.prepared_at <= evaluated_at + maximum_future_skew
            and request.verify(gateway_public_key)
            and self.verify(coordinator_public_key)
        )


class SignedEffectCommitRequest(_SignedRequest):
    """Gateway-signed commit bound to the exact coordinator prepare receipt."""

    schema_version: Literal["m4i-effect-commit-request-v1"] = "m4i-effect-commit-request-v1"
    receipt: CoordinationReceipt
    receipt_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_closed_commit(self) -> SignedEffectCommitRequest:
        self._validate_common(label="effect commit request")
        if self.receipt.effect != self.effect:
            raise ValueError("effect commit receipt refers to a different effect")
        if self.receipt_sha256 != self.receipt.digest:
            raise ValueError("effect commit receipt hash is inconsistent")
        if self.issued_at < self.receipt.prepared_at:
            raise ValueError("effect commit cannot precede preparation")
        return self

    @classmethod
    def issue(
        cls,
        *,
        receipt: CoordinationReceipt,
        signer: WorkloadSigner,
        request_nonce: str,
        issued_at: datetime,
        expires_at: datetime,
        audience: str = EFFECT_COORDINATOR_AUDIENCE,
    ) -> SignedEffectCommitRequest:
        request = cls(
            effect=receipt.effect,
            effect_sha256=receipt.effect.digest,
            receipt=receipt,
            receipt_sha256=receipt.digest,
            audience=audience,
            sender_credential=signer.credential,
            request_nonce=request_nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signed = request.model_copy(
            update={"signature": sign_bytes(signer.private_key, request.signing_payload())}
        )
        _require_signer_match(signer, signed.signing_payload(), signed.signature)
        return signed

    def verify_complete_for_admission(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
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
        expected_audience: str = EFFECT_COORDINATOR_AUDIENCE,
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        """Verify the current commit, retained receipt, and full inner dispatch."""

        return (
            self.verify_workload_envelope_for_admission(
                verifier,
                expected_audience=expected_audience,
                expected_sender_subject=expected_gateway_subject,
                evaluated_at=evaluated_at,
            )
            and self.receipt.verify_historical_for_request(
                verifier,
                request=self.receipt.prepare_request,
                expected_gateway_subject=expected_gateway_subject,
                expected_coordinator_subject=expected_coordinator_subject,
                evaluated_at=evaluated_at,
                maximum_future_skew=maximum_future_skew,
            )
            and _verify_inner_dispatch(
                self.receipt.prepare_request.dispatch,
                observer_public_key=observer_public_key,
                expected_observer_id=expected_observer_id,
                expected_observer_key_id=expected_observer_key_id,
                expected_observer_boot_epoch=expected_observer_boot_epoch,
                permit_public_key=permit_public_key,
                expected_permit_key_id=expected_permit_key_id,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
                evaluated_at=evaluated_at,
            )
        )


class DurableCommitAcceptance(_ClosedModel):
    """Coordinator-signed proof of the exact durably accepted commit intent.

    The transition sequence is per effect: RECEIVED=1, DISPATCH_ARMED=2, and
    COMMIT_ACCEPTED=3.  This application-level receipt remains bounded by the
    single-writer journal and does not claim an external timestamp, consensus,
    or hostile rollback resistance.
    """

    schema_version: Literal["m4i-durable-commit-acceptance-v1"] = "m4i-durable-commit-acceptance-v1"
    effect: EffectIdentity
    effect_sha256: str = Field(pattern=SHA256_PATTERN)
    commit_request: SignedEffectCommitRequest
    commit_request_sha256: str = Field(pattern=SHA256_PATTERN)
    state: Literal[CoordinationState.COMMIT_ACCEPTED] = CoordinationState.COMMIT_ACCEPTED
    transition_sequence: Literal[3] = 3
    audience: str = Field(default=GATEWAY_COORDINATION_AUDIENCE, min_length=1)
    coordinator_credential: SignedWorkloadCredential
    accepted_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_closed_acceptance(self) -> DurableCommitAcceptance:
        request = self.commit_request
        receipt = request.receipt
        credential = self.coordinator_credential.credential
        if self.effect != request.effect or self.effect_sha256 != request.effect.digest:
            raise ValueError("commit acceptance effect binding is inconsistent")
        if self.commit_request_sha256 != request.digest:
            raise ValueError("commit acceptance request hash is inconsistent")
        if not _is_aware(self.accepted_at):
            raise ValueError("commit acceptance time must be timezone-aware")
        if not request.issued_at <= self.accepted_at < request.expires_at:
            raise ValueError("commit acceptance time is outside the commit window")
        if self.accepted_at < receipt.prepared_at:
            raise ValueError("commit acceptance cannot precede durable preparation")
        if credential.role is not WorkloadRole.OT_ADAPTER:
            raise ValueError("commit acceptance requires an OT coordinator credential")
        if self.audience not in credential.audiences:
            raise ValueError("commit acceptance audience is not authorized")
        if self.coordinator_credential != receipt.coordinator_credential:
            raise ValueError("commit acceptance signer differs from the prepared OT target")
        if not _credential_claim_valid_at(self.coordinator_credential, self.accepted_at):
            raise ValueError("commit acceptance credential is not valid at acceptance")
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
        request: SignedEffectCommitRequest,
        signer: WorkloadSigner,
        accepted_at: datetime,
        transition_sequence: Literal[3] = 3,
        audience: str = GATEWAY_COORDINATION_AUDIENCE,
    ) -> DurableCommitAcceptance:
        if (
            not request.verify()
            or not request.receipt.verify()
            or not request.receipt.prepare_request.verify()
        ):
            raise ValueError("commit acceptance requires an intact signed request chain")
        acceptance = cls(
            effect=request.effect,
            effect_sha256=request.effect.digest,
            commit_request=request,
            commit_request_sha256=request.digest,
            transition_sequence=transition_sequence,
            audience=audience,
            coordinator_credential=signer.credential,
            accepted_at=accepted_at,
        )
        signed = acceptance.model_copy(
            update={"signature": sign_bytes(signer.private_key, acceptance.signing_payload())}
        )
        _require_signer_match(signer, signed.signing_payload(), signed.signature)
        return signed

    def verify(self, public_key: Ed25519PublicKey | None = None) -> bool:
        public_key = public_key or self.coordinator_credential.credential.public_key
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )

    def verify_for_commit(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        request: SignedEffectCommitRequest,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
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
        expected_audience: str = GATEWAY_COORDINATION_AUDIENCE,
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        if maximum_future_skew < timedelta(0) or not _is_aware(evaluated_at):
            return False
        gateway_public_key = _historical_credential_public_key(
            verifier,
            request.sender_credential,
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=EFFECT_COORDINATOR_AUDIENCE,
            expected_subject=expected_gateway_subject,
            authenticated_at=self.accepted_at,
            evaluated_at=evaluated_at,
            maximum_future_skew=maximum_future_skew,
        )
        coordinator_public_key = _historical_credential_public_key(
            verifier,
            self.coordinator_credential,
            expected_role=WorkloadRole.OT_ADAPTER,
            expected_audience=expected_audience,
            expected_subject=expected_coordinator_subject,
            authenticated_at=self.accepted_at,
            evaluated_at=evaluated_at,
            maximum_future_skew=maximum_future_skew,
        )
        return (
            gateway_public_key is not None
            and coordinator_public_key is not None
            and self.commit_request == request
            and self.commit_request_sha256 == request.digest
            and self.effect == request.effect
            and self.effect_sha256 == request.effect.digest
            and self.audience == expected_audience
            and self.coordinator_credential == request.receipt.coordinator_credential
            and request.issued_at <= self.accepted_at < request.expires_at
            and request.receipt.prepared_at <= self.accepted_at
            and self.accepted_at <= evaluated_at + maximum_future_skew
            and request.verify(gateway_public_key)
            and request.receipt.verify_historical_for_request(
                verifier,
                request=request.receipt.prepare_request,
                expected_gateway_subject=expected_gateway_subject,
                expected_coordinator_subject=expected_coordinator_subject,
                evaluated_at=evaluated_at,
                maximum_future_skew=maximum_future_skew,
            )
            and _verify_inner_dispatch(
                request.receipt.prepare_request.dispatch,
                observer_public_key=observer_public_key,
                expected_observer_id=expected_observer_id,
                expected_observer_key_id=expected_observer_key_id,
                expected_observer_boot_epoch=expected_observer_boot_epoch,
                permit_public_key=permit_public_key,
                expected_permit_key_id=expected_permit_key_id,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
                evaluated_at=self.accepted_at,
            )
            and self.verify(coordinator_public_key)
        )


class SignedEffectQueryRequest(_SignedRequest):
    """Gateway-signed query by stable effect identity after ambiguous delivery."""

    schema_version: Literal["m4i-effect-query-request-v1"] = "m4i-effect-query-request-v1"

    @model_validator(mode="after")
    def require_closed_query(self) -> SignedEffectQueryRequest:
        self._validate_common(label="effect query request")
        return self

    @classmethod
    def issue(
        cls,
        *,
        effect: EffectIdentity,
        signer: WorkloadSigner,
        request_nonce: str,
        issued_at: datetime,
        expires_at: datetime,
        audience: str = EFFECT_COORDINATOR_AUDIENCE,
    ) -> SignedEffectQueryRequest:
        request = cls(
            effect=effect,
            effect_sha256=effect.digest,
            audience=audience,
            sender_credential=signer.credential,
            request_nonce=request_nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        signed = request.model_copy(
            update={"signature": sign_bytes(signer.private_key, request.signing_payload())}
        )
        _require_signer_match(signer, signed.signing_payload(), signed.signature)
        return signed


class SignedEffectOutcome(_ClosedModel):
    """Coordinator-signed answer to an exact commit or reconciliation query."""

    schema_version: Literal["m4i-effect-outcome-v1"] = "m4i-effect-outcome-v1"
    request_kind: Literal["commit", "query"]
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    effect: EffectIdentity
    effect_sha256: str = Field(pattern=SHA256_PATTERN)
    disposition: EffectDisposition
    acceptance: DurableCommitAcceptance | None = None
    acknowledgment: PlcCommandAcknowledgment | None = None
    reason: str = Field(min_length=1, max_length=512)
    audience: str = Field(default=GATEWAY_COORDINATION_AUDIENCE, min_length=1)
    coordinator_credential: SignedWorkloadCredential
    signed_at: datetime
    signature: str = ""

    @model_validator(mode="after")
    def require_closed_outcome(self) -> SignedEffectOutcome:
        if self.effect_sha256 != self.effect.digest:
            raise ValueError("effect outcome hash is inconsistent")
        if not _is_aware(self.signed_at):
            raise ValueError("effect outcome time must be timezone-aware")
        credential = self.coordinator_credential.credential
        if credential.role is not WorkloadRole.OT_ADAPTER:
            raise ValueError("effect outcome requires an OT coordinator credential")
        if self.audience not in credential.audiences:
            raise ValueError("effect outcome audience is not authorized")
        if not _credential_claim_valid_at(self.coordinator_credential, self.signed_at):
            raise ValueError("effect outcome credential is not valid at signing")
        if self.disposition is EffectDisposition.NOT_DISPATCHED:
            if self.request_kind != "query":
                raise ValueError("not-dispatched outcome is only valid for a query")
            if self.acceptance is not None or self.acknowledgment is not None:
                raise ValueError("not-dispatched outcome cannot assert dispatch evidence")
            return self
        acceptance = self.acceptance
        if acceptance is None or acceptance.effect != self.effect:
            raise ValueError("dispatched outcome requires its exact durable commit acceptance")
        if acceptance.accepted_at > self.signed_at:
            raise ValueError("effect outcome cannot precede durable commit acceptance")
        if credential.subject != acceptance.coordinator_credential.credential.subject:
            raise ValueError("effect outcome coordinator differs from the accepted commit")
        expected_status = {
            EffectDisposition.APPLIED: CommandStatus.APPLIED,
            EffectDisposition.REJECTED: CommandStatus.REJECTED,
            EffectDisposition.UNKNOWN_EFFECT: CommandStatus.UNKNOWN_EFFECT,
        }[self.disposition]
        if self.disposition in {EffectDisposition.APPLIED, EffectDisposition.REJECTED} and (
            self.acknowledgment is None or self.acknowledgment.status is not expected_status
        ):
            raise ValueError("terminal effect outcome requires a matching PLC acknowledgment")
        if self.disposition is EffectDisposition.UNKNOWN_EFFECT and (
            self.acknowledgment is not None
            and self.acknowledgment.status is not CommandStatus.UNKNOWN_EFFECT
        ):
            raise ValueError("unknown outcome cannot retain known-effect evidence")
        if self.acknowledgment is not None:
            acknowledgment = self.acknowledgment
            receipt = acceptance.commit_request.receipt
            dispatch = receipt.prepare_request.dispatch
            if not acceptance.accepted_at <= acknowledgment.acknowledged_at <= self.signed_at:
                raise ValueError("effect outcome acknowledgment chronology is inconsistent")
            if not acknowledgment.verify_for_transaction(
                acceptance.coordinator_credential.credential.public_key,
                request=dispatch.request,
                permit=dispatch.permit,
                pre_observation=dispatch.pre_observation,
                expected_plc_id=dispatch.permit.target_plc_id,
                expected_plc_key_id=dispatch.permit.target_plc_key_id,
                expected_plc_boot_epoch=dispatch.permit.target_plc_boot_epoch,
            ):
                raise ValueError("effect outcome acknowledgment transaction is invalid")
        return self

    @property
    def receipt(self) -> CoordinationReceipt | None:
        if self.acceptance is None:
            return None
        return self.acceptance.commit_request.receipt

    @property
    def receipt_sha256(self) -> str | None:
        receipt = self.receipt
        return None if receipt is None else receipt.digest

    @property
    def coordinator_subject(self) -> str:
        return self.coordinator_credential.credential.subject

    @property
    def coordinator_key_id(self) -> str:
        return self.coordinator_credential.credential.key_id

    @property
    def plant_subject(self) -> str:
        """Compatibility projection; the signer is the effect coordinator."""

        return self.coordinator_subject

    @property
    def plant_key_id(self) -> str:
        """Compatibility projection; the signer is the effect coordinator."""

        return self.coordinator_key_id

    @property
    def execution_evidence_sha256(self) -> str | None:
        """Exact PLC acknowledgment digest, never a caller-supplied assertion."""

        if self.acknowledgment is None:
            return None
        return self.acknowledgment.digest

    def signing_payload(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @classmethod
    def issue(
        cls,
        *,
        request: SignedEffectCommitRequest | SignedEffectQueryRequest,
        disposition: EffectDisposition,
        reason: str,
        signer: WorkloadSigner,
        signed_at: datetime,
        acceptance: DurableCommitAcceptance | None = None,
        acknowledgment: PlcCommandAcknowledgment | None = None,
        audience: str = GATEWAY_COORDINATION_AUDIENCE,
    ) -> SignedEffectOutcome:
        if not request.issued_at <= signed_at < request.expires_at:
            raise ValueError("effect outcome time is outside the request window")
        if isinstance(request, SignedEffectCommitRequest):
            request_kind: Literal["commit", "query"] = "commit"
            if acceptance is None or acceptance.commit_request != request:
                raise ValueError("commit outcome requires its exact durable acceptance")
        else:
            request_kind = "query"
        if disposition is EffectDisposition.NOT_DISPATCHED:
            if acceptance is not None or acknowledgment is not None:
                raise ValueError("not-dispatched outcome cannot retain dispatch evidence")
        elif acceptance is None or acceptance.effect != request.effect:
            raise ValueError("dispatched outcome requires durable commit acceptance")
        if acceptance is not None and not acceptance.verify():
            raise ValueError("effect outcome durable commit acceptance signature is invalid")
        outcome = cls(
            request_kind=request_kind,
            request_sha256=request.digest,
            effect=request.effect,
            effect_sha256=request.effect.digest,
            disposition=disposition,
            acceptance=acceptance,
            acknowledgment=acknowledgment,
            reason=reason,
            audience=audience,
            coordinator_credential=signer.credential,
            signed_at=signed_at,
        )
        signed = outcome.model_copy(
            update={"signature": sign_bytes(signer.private_key, outcome.signing_payload())}
        )
        _require_signer_match(signer, signed.signing_payload(), signed.signature)
        return signed

    def verify(self, public_key: Ed25519PublicKey | None = None) -> bool:
        public_key = public_key or self.coordinator_credential.credential.public_key
        return bool(self.signature) and verify_bytes(
            public_key,
            self.signing_payload(),
            self.signature,
        )

    def verify_for_request(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        request: SignedEffectCommitRequest | SignedEffectQueryRequest,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
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
        expected_audience: str = GATEWAY_COORDINATION_AUDIENCE,
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        if maximum_future_skew < timedelta(0) or not _is_aware(evaluated_at):
            return False
        expected_kind = "commit" if isinstance(request, SignedEffectCommitRequest) else "query"
        request_valid = request.verify_workload_envelope_for_admission(
            verifier,
            expected_audience=EFFECT_COORDINATOR_AUDIENCE,
            expected_sender_subject=expected_gateway_subject,
            evaluated_at=evaluated_at,
        )
        coordinator_public_key = _credential_public_key(
            verifier,
            self.coordinator_credential,
            expected_role=WorkloadRole.OT_ADAPTER,
            expected_audience=expected_audience,
            expected_subject=expected_coordinator_subject,
            evaluated_at=evaluated_at,
        )
        acceptance_valid = self.acceptance is None
        acknowledgment_valid = self.acknowledgment is None
        if self.acceptance is not None:
            acceptance_valid = self.acceptance.verify_for_commit(
                verifier,
                request=self.acceptance.commit_request,
                expected_gateway_subject=expected_gateway_subject,
                expected_coordinator_subject=expected_coordinator_subject,
                observer_public_key=observer_public_key,
                expected_observer_id=expected_observer_id,
                expected_observer_key_id=expected_observer_key_id,
                expected_observer_boot_epoch=expected_observer_boot_epoch,
                permit_public_key=permit_public_key,
                expected_permit_key_id=expected_permit_key_id,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
                evaluated_at=evaluated_at,
                maximum_future_skew=maximum_future_skew,
            )
        if self.acknowledgment is not None and self.acceptance is not None:
            dispatch = self.acceptance.commit_request.receipt.prepare_request.dispatch
            acknowledgment_valid = self.acknowledgment.verify_for_transaction(
                self.acceptance.coordinator_credential.credential.public_key,
                request=dispatch.request,
                permit=dispatch.permit,
                pre_observation=dispatch.pre_observation,
                expected_plc_id=dispatch.permit.target_plc_id,
                expected_plc_key_id=dispatch.permit.target_plc_key_id,
                expected_plc_boot_epoch=dispatch.permit.target_plc_boot_epoch,
            )
        return (
            request_valid
            and coordinator_public_key is not None
            and self.request_kind == expected_kind
            and self.request_sha256 == request.digest
            and self.effect == request.effect
            and self.effect_sha256 == request.effect.digest
            and (
                not isinstance(request, SignedEffectCommitRequest)
                or (self.acceptance is not None and self.acceptance.commit_request == request)
            )
            and acceptance_valid
            and acknowledgment_valid
            and self.audience == expected_audience
            and self.coordinator_subject == expected_coordinator_subject
            and request.issued_at <= self.signed_at < request.expires_at
            and self.signed_at <= evaluated_at + maximum_future_skew
            and self.verify(coordinator_public_key)
        )

    def verify_historical_for_request(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        request: SignedEffectCommitRequest | SignedEffectQueryRequest,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
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
        expected_audience: str = GATEWAY_COORDINATION_AUDIENCE,
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        """Revalidate a retained outcome without reviving its request TTL.

        A commit request credential is checked at durable commit acceptance;
        a query request credential and the outcome credential are checked when
        the coordinator signed the outcome. Verification still consumes the
        current signed trust bundle and its temporally effective revocations.
        Later leaf expiry, rotation, or revocation does not erase an already
        retained terminal fact.
        """

        if maximum_future_skew < timedelta(0) or not _is_aware(evaluated_at):
            return False
        expected_kind = "commit" if isinstance(request, SignedEffectCommitRequest) else "query"
        request_authenticated_at = self.signed_at
        if isinstance(request, SignedEffectCommitRequest) and self.acceptance is not None:
            request_authenticated_at = self.acceptance.accepted_at
        gateway_public_key = _historical_credential_public_key(
            verifier,
            request.sender_credential,
            expected_role=WorkloadRole.GATEWAY,
            expected_audience=EFFECT_COORDINATOR_AUDIENCE,
            expected_subject=expected_gateway_subject,
            authenticated_at=request_authenticated_at,
            evaluated_at=evaluated_at,
            maximum_future_skew=maximum_future_skew,
        )
        coordinator_public_key = _historical_credential_public_key(
            verifier,
            self.coordinator_credential,
            expected_role=WorkloadRole.OT_ADAPTER,
            expected_audience=expected_audience,
            expected_subject=expected_coordinator_subject,
            authenticated_at=self.signed_at,
            evaluated_at=evaluated_at,
            maximum_future_skew=maximum_future_skew,
        )
        acceptance_valid = (
            self.disposition is EffectDisposition.NOT_DISPATCHED and self.acceptance is None
        )
        if self.acceptance is not None:
            acceptance_valid = self.acceptance.verify_for_commit(
                verifier,
                request=self.acceptance.commit_request,
                expected_gateway_subject=expected_gateway_subject,
                expected_coordinator_subject=expected_coordinator_subject,
                observer_public_key=observer_public_key,
                expected_observer_id=expected_observer_id,
                expected_observer_key_id=expected_observer_key_id,
                expected_observer_boot_epoch=expected_observer_boot_epoch,
                permit_public_key=permit_public_key,
                expected_permit_key_id=expected_permit_key_id,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
                evaluated_at=evaluated_at,
                maximum_future_skew=maximum_future_skew,
            )
        acknowledgment_valid = self.acknowledgment is None
        if self.acknowledgment is not None and self.acceptance is not None:
            dispatch = self.acceptance.commit_request.receipt.prepare_request.dispatch
            expected_status = {
                EffectDisposition.APPLIED: CommandStatus.APPLIED,
                EffectDisposition.REJECTED: CommandStatus.REJECTED,
                EffectDisposition.UNKNOWN_EFFECT: CommandStatus.UNKNOWN_EFFECT,
            }.get(self.disposition)
            acknowledgment_valid = (
                expected_status is not None
                and self.acknowledgment.status is expected_status
                and self.acceptance.accepted_at
                <= self.acknowledgment.acknowledged_at
                <= self.signed_at
                and self.acknowledgment.verify_for_transaction(
                    self.acceptance.coordinator_credential.credential.public_key,
                    request=dispatch.request,
                    permit=dispatch.permit,
                    pre_observation=dispatch.pre_observation,
                    expected_plc_id=dispatch.permit.target_plc_id,
                    expected_plc_key_id=dispatch.permit.target_plc_key_id,
                    expected_plc_boot_epoch=dispatch.permit.target_plc_boot_epoch,
                )
            )
        if self.disposition in {EffectDisposition.APPLIED, EffectDisposition.REJECTED}:
            acknowledgment_valid = self.acknowledgment is not None and acknowledgment_valid
        return (
            gateway_public_key is not None
            and coordinator_public_key is not None
            and self.request_kind == expected_kind
            and self.request_sha256 == request.digest
            and self.effect == request.effect
            and self.effect_sha256 == request.effect.digest
            and request.audience == EFFECT_COORDINATOR_AUDIENCE
            and request.sender_subject == expected_gateway_subject
            and request.issued_at <= self.signed_at < request.expires_at
            and request.verify(gateway_public_key)
            and (
                not isinstance(request, SignedEffectCommitRequest)
                or (self.acceptance is not None and self.acceptance.commit_request == request)
            )
            and acceptance_valid
            and acknowledgment_valid
            and self.audience == expected_audience
            and self.coordinator_subject == expected_coordinator_subject
            and self.signed_at <= evaluated_at + maximum_future_skew
            and self.verify(coordinator_public_key)
        )


class CapabilityOutcomeResolution(_ClosedModel):
    """Exact query-bound evidence for resolving a formerly unknown effect."""

    schema_version: Literal["m4i-capability-outcome-resolution-v1"] = (
        "m4i-capability-outcome-resolution-v1"
    )
    effect: EffectIdentity
    prior_state: Literal[
        CoordinationState.DISPATCH_ARMED,
        CoordinationState.COMMIT_ACCEPTED,
        CoordinationState.UNKNOWN_EFFECT,
    ] = CoordinationState.UNKNOWN_EFFECT
    disposition: Literal[EffectDisposition.APPLIED, EffectDisposition.REJECTED]
    query: SignedEffectQueryRequest
    acceptance: DurableCommitAcceptance
    outcome: SignedEffectOutcome
    resolved_at: datetime

    @model_validator(mode="after")
    def require_exact_resolution(self) -> CapabilityOutcomeResolution:
        if not _is_aware(self.resolved_at):
            raise ValueError("outcome resolution time must be timezone-aware")
        if (
            self.outcome.request_kind != "query"
            or self.query.effect != self.effect
            or self.outcome.request_sha256 != self.query.digest
            or self.outcome.effect != self.effect
            or self.outcome.disposition.value != self.disposition.value
            or self.acceptance.effect != self.effect
            or self.outcome.acceptance != self.acceptance
            or self.outcome.signed_at > self.resolved_at
        ):
            raise ValueError("outcome resolution bindings are inconsistent")
        return self

    @property
    def query_request_sha256(self) -> str:
        return self.query.digest

    @property
    def receipt(self) -> CoordinationReceipt:
        return self.acceptance.commit_request.receipt

    def verify_complete(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
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
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        return (
            self.resolved_at <= evaluated_at + maximum_future_skew
            and self.outcome.verify_for_request(
                verifier,
                request=self.query,
                expected_gateway_subject=expected_gateway_subject,
                expected_coordinator_subject=expected_coordinator_subject,
                observer_public_key=observer_public_key,
                expected_observer_id=expected_observer_id,
                expected_observer_key_id=expected_observer_key_id,
                expected_observer_boot_epoch=expected_observer_boot_epoch,
                permit_public_key=permit_public_key,
                expected_permit_key_id=expected_permit_key_id,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
                evaluated_at=evaluated_at,
                maximum_future_skew=maximum_future_skew,
            )
        )

    def verify_historical_complete(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
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
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        """Verify retained resolution evidence at its historical trust instants."""

        return (
            self.resolved_at <= evaluated_at + maximum_future_skew
            and self.outcome.verify_historical_for_request(
                verifier,
                request=self.query,
                expected_gateway_subject=expected_gateway_subject,
                expected_coordinator_subject=expected_coordinator_subject,
                observer_public_key=observer_public_key,
                expected_observer_id=expected_observer_id,
                expected_observer_key_id=expected_observer_key_id,
                expected_observer_boot_epoch=expected_observer_boot_epoch,
                permit_public_key=permit_public_key,
                expected_permit_key_id=expected_permit_key_id,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
                evaluated_at=evaluated_at,
                maximum_future_skew=maximum_future_skew,
            )
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class CapabilityOutcomePending(_ClosedModel):
    """Exact retained query evidence that leaves a committed effect unknown."""

    schema_version: Literal["m4i-capability-outcome-pending-v1"] = (
        "m4i-capability-outcome-pending-v1"
    )
    effect: EffectIdentity
    prior_state: Literal[
        CoordinationState.DISPATCH_ARMED,
        CoordinationState.COMMIT_ACCEPTED,
        CoordinationState.UNKNOWN_EFFECT,
    ]
    disposition: Literal[EffectDisposition.UNKNOWN_EFFECT] = (
        EffectDisposition.UNKNOWN_EFFECT
    )
    query: SignedEffectQueryRequest
    acceptance: DurableCommitAcceptance
    outcome: SignedEffectOutcome
    retained_at: datetime

    @model_validator(mode="after")
    def require_exact_pending(self) -> CapabilityOutcomePending:
        if not _is_aware(self.retained_at):
            raise ValueError("pending outcome retention time must be timezone-aware")
        if (
            self.outcome.request_kind != "query"
            or self.query.effect != self.effect
            or self.outcome.request_sha256 != self.query.digest
            or self.outcome.effect != self.effect
            or self.outcome.disposition is not EffectDisposition.UNKNOWN_EFFECT
            or self.acceptance.effect != self.effect
            or self.outcome.acceptance != self.acceptance
            or self.outcome.signed_at > self.retained_at
        ):
            raise ValueError("pending outcome bindings are inconsistent")
        return self

    @property
    def query_request_sha256(self) -> str:
        return self.query.digest

    @property
    def receipt(self) -> CoordinationReceipt:
        return self.acceptance.commit_request.receipt

    def verify_complete(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
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
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        return (
            self.retained_at <= evaluated_at + maximum_future_skew
            and self.outcome.verify_for_request(
                verifier,
                request=self.query,
                expected_gateway_subject=expected_gateway_subject,
                expected_coordinator_subject=expected_coordinator_subject,
                observer_public_key=observer_public_key,
                expected_observer_id=expected_observer_id,
                expected_observer_key_id=expected_observer_key_id,
                expected_observer_boot_epoch=expected_observer_boot_epoch,
                permit_public_key=permit_public_key,
                expected_permit_key_id=expected_permit_key_id,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
                evaluated_at=evaluated_at,
                maximum_future_skew=maximum_future_skew,
            )
        )

    def verify_historical_complete(
        self,
        verifier: WorkloadIdentityVerifier,
        *,
        expected_gateway_subject: str,
        expected_coordinator_subject: str,
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
        maximum_future_skew: timedelta = MAX_COORDINATION_FUTURE_SKEW,
    ) -> bool:
        return (
            self.retained_at <= evaluated_at + maximum_future_skew
            and self.outcome.verify_historical_for_request(
                verifier,
                request=self.query,
                expected_gateway_subject=expected_gateway_subject,
                expected_coordinator_subject=expected_coordinator_subject,
                observer_public_key=observer_public_key,
                expected_observer_id=expected_observer_id,
                expected_observer_key_id=expected_observer_key_id,
                expected_observer_boot_epoch=expected_observer_boot_epoch,
                permit_public_key=permit_public_key,
                expected_permit_key_id=expected_permit_key_id,
                expected_plc_id=expected_plc_id,
                expected_plc_key_id=expected_plc_key_id,
                expected_plc_boot_epoch=expected_plc_boot_epoch,
                evaluated_at=evaluated_at,
                maximum_future_skew=maximum_future_skew,
            )
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self)


# Readable protocol aliases retained for callers that prefer verb-first names.
SignedPrepareEffectRequest = SignedEffectPrepareRequest
SignedCommitEffectRequest = SignedEffectCommitRequest
SignedQueryEffectRequest = SignedEffectQueryRequest
