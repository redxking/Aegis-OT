"""Closed evidence contracts for the bounded WP4 M4b retained-evidence gate.

The contracts in this module make package structure, correlations, digests, and
signature inputs explicit.  They establish local package integrity; they do not
establish external custody, independent replication, physical validity, or WP4
completion.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    PlainSerializer,
    WithJsonSchema,
    field_validator,
    model_validator,
)

from .capability_models import (
    CapabilityClosedLoopResult,
    CapabilityClosedLoopStatus,
    DispatchPhase,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from .crypto import decode_urlsafe_b64, sign_bytes, verify_bytes
from .physical_models import (
    SHA256_PATTERN,
    CommandStatus,
    PhysicalControlCommand,
    canonical_digest,
)

MANIFEST_SIGNATURE_DOMAIN: Literal["AEGIS-OT-M4B-MANIFEST-V1"] = (
    "AEGIS-OT-M4B-MANIFEST-V1"
)
INDEPENDENT_REPORT_SIGNATURE_DOMAIN = b"AEGIS-OT-M4B-INDEPENDENT-REPORT-V1\x00"
_DECIMAL_PATTERN = r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$"


def canonical_json_bytes(value: BaseModel | JsonValue) -> bytes:
    """Serialize one contract or mapping as deterministic UTF-8 JSON."""

    material = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return the lower-case SHA-256 digest for exact bytes."""

    return hashlib.sha256(value).hexdigest()


def public_key_base64(public_key: Ed25519PublicKey) -> str:
    """Return the canonical padded URL-safe Base64 encoding for an Ed25519 key."""

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii")


def public_key_from_base64(value: str) -> Ed25519PublicKey:
    """Decode and length-check one canonical Ed25519 public key."""

    raw = decode_urlsafe_b64(value)
    if len(raw) != 32:
        raise ValueError("Ed25519 public keys must contain exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def _require_timezone(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value


def _require_public_key(value: str) -> str:
    public_key_from_base64(value)
    return value


def _require_signature(value: str) -> str:
    if not value:
        return value
    raw = decode_urlsafe_b64(value)
    if len(raw) != 64:
        raise ValueError("Ed25519 signatures must contain exactly 64 bytes")
    return value


def _require_finite_decimal(value: Decimal) -> Decimal:
    if not value.is_finite():
        raise ValueError("decimal value must be finite")
    return value


def _require_decimal_input(value: object) -> object:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, str) and re.fullmatch(_DECIMAL_PATTERN, value):
        return value
    raise ValueError("decimal wire values must be plain decimal strings")


def _decimal_to_json(value: Decimal) -> str:
    return format(value, "f")


def _require_sorted_unique(values: tuple[str, ...], *, label: str) -> None:
    if any(not item for item in values):
        raise ValueError(f"{label} cannot contain empty values")
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{label} must be unique and lexicographically sorted")


def _require_unique(values: tuple[str, ...], *, label: str) -> None:
    if any(not item for item in values):
        raise ValueError(f"{label} cannot contain empty values")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


def _require_json_value(value: JsonValue, *, label: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{label} cannot contain non-finite numbers")
        return
    if isinstance(value, list):
        for item in value:
            _require_json_value(item, label=label)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{label} must use string keys")
            _require_json_value(item, label=label)
        return
    raise ValueError(f"{label} must contain JSON-compatible values")


def _manifest_signature_payload(domain: str, manifest_bytes: bytes) -> bytes:
    return domain.encode("ascii") + b"\x00" + manifest_bytes


AwareDatetime = Annotated[datetime, AfterValidator(_require_timezone)]
Sha256 = Annotated[str, Field(pattern=SHA256_PATTERN)]
Identifier = Annotated[str, Field(min_length=1, max_length=256)]
BootEpoch = Annotated[str, Field(min_length=16, max_length=256)]
PublicKeyBase64 = Annotated[str, AfterValidator(_require_public_key)]
SignatureBase64 = Annotated[str, AfterValidator(_require_signature)]
FiniteDecimal = Annotated[
    Decimal,
    BeforeValidator(_require_decimal_input),
    AfterValidator(_require_finite_decimal),
    PlainSerializer(_decimal_to_json, return_type=str),
    WithJsonSchema({"type": "string", "pattern": _DECIMAL_PATTERN}),
]
NonNegativeDecimal = Annotated[
    Decimal,
    BeforeValidator(_require_decimal_input),
    Field(ge=0),
    AfterValidator(_require_finite_decimal),
    PlainSerializer(_decimal_to_json, return_type=str),
    WithJsonSchema({"type": "string", "pattern": _DECIMAL_PATTERN}),
]
PercentageDecimal = Annotated[
    Decimal,
    BeforeValidator(_require_decimal_input),
    Field(ge=0, le=100),
    AfterValidator(_require_finite_decimal),
    PlainSerializer(_decimal_to_json, return_type=str),
    WithJsonSchema({"type": "string", "pattern": _DECIMAL_PATTERN}),
]


class M4bClosedModel(BaseModel):
    """Shared immutable, closed contract behavior."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    @property
    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


class M4bComponentRole(StrEnum):
    PLANT = "plant"
    OBSERVER = "observer"
    PLC = "plc"
    REPLACEMENT_PLC = "replacement_plc"
    PERMIT_SIGNER = "permit_signer"
    INDEPENDENT_EVALUATOR = "independent_evaluator"


class M4bTrustAnchor(M4bClosedModel):
    """Package root public key and its bounded validity interval."""

    schema_version: Literal["m4b-trust-anchor-v1"] = "m4b-trust-anchor-v1"
    anchor_id: Identifier
    key_id: Identifier
    public_key_b64: PublicKeyBase64
    public_key_sha256: Sha256
    purpose: Literal["m4b-evidence-root"] = "m4b-evidence-root"
    not_before: AwareDatetime
    not_after: AwareDatetime | None = None

    @model_validator(mode="after")
    def require_consistent_anchor(self) -> M4bTrustAnchor:
        raw = decode_urlsafe_b64(self.public_key_b64)
        if self.public_key_sha256 != sha256_bytes(raw):
            raise ValueError("trust-anchor public-key digest is inconsistent")
        if self.not_after is not None and self.not_after <= self.not_before:
            raise ValueError("trust-anchor expiry must be after its validity start")
        return self

    @property
    def public_key(self) -> Ed25519PublicKey:
        return public_key_from_base64(self.public_key_b64)


class M4bComponentRegistration(M4bClosedModel):
    """One process instance, boot epoch, key identity, and capability inventory."""

    schema_version: Literal["m4b-component-registration-v1"] = (
        "m4b-component-registration-v1"
    )
    session_id: Identifier
    session_index: int = Field(ge=0)
    master_seed: int = Field(ge=0)
    role: M4bComponentRole
    component_id: Identifier
    pid: int = Field(ge=1)
    boot_epoch: BootEpoch
    key_id: Identifier | None = None
    public_key_b64: PublicKeyBase64 | None = None
    public_key_sha256: Sha256 | None = None
    capabilities: tuple[str, ...] = Field(min_length=1)
    plant_boot_epoch: BootEpoch | None = None
    model_digest: Sha256 | None = None
    registered_at: AwareDatetime

    @model_validator(mode="after")
    def require_consistent_registration(self) -> M4bComponentRegistration:
        _require_sorted_unique(self.capabilities, label="component capabilities")
        key_values = (self.key_id, self.public_key_b64, self.public_key_sha256)
        if any(value is None for value in key_values) and any(
            value is not None for value in key_values
        ):
            raise ValueError("component key ID, public key, and public-key digest are atomic")
        keyed_roles = {
            M4bComponentRole.OBSERVER,
            M4bComponentRole.PLC,
            M4bComponentRole.REPLACEMENT_PLC,
            M4bComponentRole.PERMIT_SIGNER,
            M4bComponentRole.INDEPENDENT_EVALUATOR,
        }
        if self.role in keyed_roles and self.public_key_b64 is None:
            raise ValueError("the registered component role requires an Ed25519 key")
        if self.public_key_b64 is not None:
            assert self.public_key_sha256 is not None
            if self.public_key_sha256 != sha256_bytes(
                decode_urlsafe_b64(self.public_key_b64)
            ):
                raise ValueError("component public-key digest is inconsistent")
        if self.role is M4bComponentRole.PLANT:
            if self.plant_boot_epoch != self.boot_epoch or self.model_digest is None:
                raise ValueError("plant registration must bind its boot epoch and model digest")
        return self


class M4bTransactionRecord(M4bClosedModel):
    """One retained M4a terminal result plus package-level chain bindings.

    The independent evaluator must bind to the transaction before its report
    exists. ``evaluation_binding_sha256`` therefore hashes the stable
    transaction projection that excludes the two report-reference fields. The
    final record can retain the report without creating an impossible record ->
    report -> request -> record digest cycle.
    """

    schema_version: Literal["m4b-transaction-record-v1"] = "m4b-transaction-record-v1"
    session_id: Identifier
    session_index: int = Field(ge=0)
    master_seed: int = Field(ge=0)
    condition: Identifier
    expected_terminal_status: CapabilityClosedLoopStatus
    result: CapabilityClosedLoopResult
    result_sha256: Sha256
    evidence_first_sequence: int = Field(ge=0)
    evidence_last_sequence: int = Field(ge=0)
    evidence_chain_head: Sha256
    component_registration_sha256: Sha256
    pre_health_sha256: Sha256
    post_health_sha256: Sha256
    independent_report_id: Identifier | None = None
    independent_report_sha256: Sha256 | None = None

    def evaluation_binding_material(self) -> dict[str, Any]:
        """Return the stable pre-report projection supplied to the evaluator."""

        return self.model_dump(
            mode="json",
            exclude={"independent_report_id", "independent_report_sha256"},
        )

    @property
    def evaluation_binding_sha256(self) -> str:
        """Digest the transaction without its later independent-report reference."""

        return canonical_digest(self.evaluation_binding_material())

    @model_validator(mode="after")
    def require_consistent_record(self) -> M4bTransactionRecord:
        if self.expected_terminal_status is not self.result.status:
            raise ValueError("expected terminal status does not match the retained result")
        if self.result_sha256 != canonical_digest(self.result):
            raise ValueError("transaction result digest is inconsistent")
        if self.evidence_last_sequence < self.evidence_first_sequence:
            raise ValueError("transaction evidence sequence range is reversed")
        if (self.independent_report_id is None) != (
            self.independent_report_sha256 is None
        ):
            raise ValueError("independent report ID and digest must be present together")
        return self


class M4bCapabilityProbeRecord(M4bClosedModel):
    """Observed result of one forbidden cross-capability request."""

    schema_version: Literal["m4b-capability-probe-v1"] = "m4b-capability-probe-v1"
    session_id: Identifier
    ordinal: int = Field(ge=1)
    endpoint_role: M4bComponentRole
    operation: Identifier
    expected_disposition: Literal["capability_denied"] = "capability_denied"
    actual_disposition: Identifier
    request_payload_sha256: Sha256 | None = None
    response_payload_sha256: Sha256 | None = None
    server_boot_epoch: BootEpoch | None = None
    response_counter: int | None = Field(default=None, ge=1)
    observed_at: AwareDatetime

    @property
    def matched_expectation(self) -> bool:
        return self.actual_disposition == self.expected_disposition


class M4bCapabilityProbeBundle(M4bClosedModel):
    """Canonical, self-digesting set of ordered negative capability probes."""

    schema_version: Literal["m4b-capability-probe-bundle-v1"] = (
        "m4b-capability-probe-bundle-v1"
    )
    session_id: Identifier
    records: tuple[M4bCapabilityProbeRecord, ...] = Field(min_length=1)
    bundle_sha256: Sha256

    def digest_material(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"bundle_sha256"})

    @property
    def expected_bundle_sha256(self) -> str:
        return canonical_digest(self.digest_material())

    @model_validator(mode="after")
    def require_consistent_bundle(self) -> M4bCapabilityProbeBundle:
        if any(record.session_id != self.session_id for record in self.records):
            raise ValueError("probe records must belong to the bundle session")
        ordinals = tuple(record.ordinal for record in self.records)
        if ordinals != tuple(range(1, len(self.records) + 1)):
            raise ValueError("probe records must use contiguous ascending ordinals")
        if self.bundle_sha256 != self.expected_bundle_sha256:
            raise ValueError("capability-probe bundle digest is inconsistent")
        return self

    @classmethod
    def issue(
        cls,
        *,
        session_id: str,
        records: tuple[M4bCapabilityProbeRecord, ...],
    ) -> M4bCapabilityProbeBundle:
        material: dict[str, Any] = {
            "schema_version": "m4b-capability-probe-bundle-v1",
            "session_id": session_id,
            "records": [record.model_dump(mode="json") for record in records],
        }
        return cls.model_validate(
            {**material, "bundle_sha256": canonical_digest(material)}
        )


class M4bOrderlyRestartReplayRecord(M4bClosedModel):
    """Evidence that one prior command is rejected by a replacement PLC instance."""

    schema_version: Literal["m4b-orderly-restart-replay-v1"] = (
        "m4b-orderly-restart-replay-v1"
    )
    session_id: Identifier
    original_transaction_sha256: Sha256
    original_request_digest: Sha256
    original_permit_digest: Sha256
    original_command_digest: Sha256
    prior_plc_registration_sha256: Sha256
    replacement_plc_registration_sha256: Sha256
    replay_acknowledgment: PlcCommandAcknowledgment
    before_plant_health_sha256: Sha256
    after_plant_health_sha256: Sha256
    post_replay_observation: SignedObservationEnvelope
    replay_state_unchanged: bool
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def require_consistent_replay(self) -> M4bOrderlyRestartReplayRecord:
        if self.prior_plc_registration_sha256 == self.replacement_plc_registration_sha256:
            raise ValueError("orderly restart must bind distinct PLC registrations")
        acknowledgment = self.replay_acknowledgment
        if (
            acknowledgment.request_digest != self.original_request_digest
            or acknowledgment.permit_digest != self.original_permit_digest
            or acknowledgment.command_digest != self.original_command_digest
        ):
            raise ValueError("replay acknowledgment does not bind the original transaction")
        if (
            acknowledgment.status is not CommandStatus.REJECTED
            or acknowledgment.dispatch_phase is not DispatchPhase.PRE_DISPATCH
            or acknowledgment.reason
            not in {
                "transaction_replayed",
                "permit_replayed",
                "permit_nonce_replayed",
                "command_replayed",
            }
        ):
            raise ValueError("orderly-restart replay must retain a pre-dispatch replay rejection")
        if not acknowledgment.signature or not self.post_replay_observation.signature:
            raise ValueError("orderly-restart replay evidence requires signed artifacts")
        if self.replay_state_unchanged and (
            self.post_replay_observation.snapshot.state_digest
            != acknowledgment.pre_state_digest
        ):
            raise ValueError("unchanged replay evidence must retain the same plant state")
        if self.recorded_at < max(
            acknowledgment.acknowledged_at,
            self.post_replay_observation.captured_at,
        ):
            raise ValueError("replay record time precedes a retained replay artifact")
        return self


class IndependentMetricName(StrEnum):
    TOTAL_LOAD_DEMAND_MW = "total_load_demand_mw"
    SERVED_LOAD_MW = "served_load_mw"
    PRIORITY_LOAD_DEMAND_MW = "priority_load_demand_mw"
    PRIORITY_LOAD_SERVED_MW = "priority_load_served_mw"
    TOTAL_LOAD_SERVED_PCT = "total_load_served_pct"
    PRIORITY_LOAD_SERVED_PCT = "priority_load_served_pct"
    ISOLATED_RESOURCES = "isolated_resources"


class IndependentConsequenceValues(M4bClosedModel):
    """Independent evaluator consequence values; Decimal fields serialize as strings."""

    source_connected_bus_count: int | None = Field(default=None, ge=0)
    total_load_demand_mw: NonNegativeDecimal
    served_load_mw: NonNegativeDecimal
    priority_load_demand_mw: NonNegativeDecimal
    priority_load_served_mw: NonNegativeDecimal
    total_load_served_pct: PercentageDecimal
    priority_load_served_pct: PercentageDecimal
    isolated_resources: tuple[str, ...]

    @model_validator(mode="after")
    def require_canonical_resources(self) -> IndependentConsequenceValues:
        _require_sorted_unique(self.isolated_resources, label="isolated resources")
        return self


class IndependentMetricComparison(M4bClosedModel):
    """One evaluator-to-observer comparison and its declared tolerance."""

    metric: IndependentMetricName
    expected: str = Field(min_length=1)
    observed: str = Field(min_length=1)
    tolerance: str = Field(min_length=1)
    outcome: Literal["match", "mismatch"]

    @model_validator(mode="after")
    def require_consistent_outcome(self) -> IndependentMetricComparison:
        if self.metric is IndependentMetricName.ISOLATED_RESOURCES:
            if self.tolerance != "exact":
                raise ValueError("isolated-resource comparisons require exact tolerance")
            try:
                expected = json.loads(self.expected)
                observed = json.loads(self.observed)
            except json.JSONDecodeError as exc:
                raise ValueError("isolated resources must be canonical JSON arrays") from exc
            for value in (expected, observed):
                if (
                    not isinstance(value, list)
                    or any(not isinstance(item, str) or not item for item in value)
                    or value != sorted(set(value))
                ):
                    raise ValueError("isolated resources must be sorted unique string arrays")
            canonical_expected = json.dumps(expected, separators=(",", ":"))
            canonical_observed = json.dumps(observed, separators=(",", ":"))
            if self.expected != canonical_expected or self.observed != canonical_observed:
                raise ValueError("isolated-resource arrays must use canonical JSON")
            matched = expected == observed
        else:
            for label, value in (
                ("expected", self.expected),
                ("observed", self.observed),
                ("tolerance", self.tolerance),
            ):
                if not re.fullmatch(_DECIMAL_PATTERN, value):
                    raise ValueError(f"comparison {label} must be a plain decimal string")
            expected_decimal = Decimal(self.expected)
            observed_decimal = Decimal(self.observed)
            tolerance_decimal = Decimal(self.tolerance)
            if (
                not expected_decimal.is_finite()
                or not observed_decimal.is_finite()
                or not tolerance_decimal.is_finite()
                or tolerance_decimal < 0
            ):
                raise ValueError("comparison decimals must be finite with nonnegative tolerance")
            matched = abs(expected_decimal - observed_decimal) <= tolerance_decimal
        if (self.outcome == "match") != matched:
            raise ValueError("metric comparison outcome is inconsistent with its values")
        return self


class IndependentEvaluationRequest(M4bClosedModel):
    """Independent consequence input, intentionally excluding gateway expected-post data.

    ``transaction_record_digest`` is the transaction record's stable
    ``evaluation_binding_sha256`` projection, not the digest of the final record
    after it has been linked to this evaluation's report.
    """

    schema_version: Literal["m4b-independent-evaluation-request-v1"] = (
        "m4b-independent-evaluation-request-v1"
    )
    request_id: Identifier
    session_index: int = Field(ge=0)
    master_seed: int = Field(ge=0)
    transaction_record_digest: Sha256
    fixture_id: Identifier
    fixture_digest: Sha256
    evaluator_profile: Literal["topology-connectivity-v1"] = "topology-connectivity-v1"
    nonce: str = Field(min_length=16, max_length=256)
    pre_observation: SignedObservationEnvelope | None = None
    post_observation: SignedObservationEnvelope | None = None
    command: PhysicalControlCommand | None = None
    observer_key_id: Identifier
    observer_public_key_b64: PublicKeyBase64
    absolute_tolerance_mw: NonNegativeDecimal
    absolute_tolerance_pct: NonNegativeDecimal

    @model_validator(mode="after")
    def require_consistent_inputs(self) -> IndependentEvaluationRequest:
        observations = tuple(
            value
            for value in (self.pre_observation, self.post_observation)
            if value is not None
        )
        if any(value.observer_key_id != self.observer_key_id for value in observations):
            raise ValueError("evaluation observations do not match the declared observer key")
        if self.pre_observation is not None and (
            self.pre_observation.phase is not ObservationPhase.PRE_AUTHORIZATION
        ):
            raise ValueError("evaluation pre-observation has the wrong phase")
        if self.post_observation is not None:
            if self.pre_observation is None or self.command is None:
                raise ValueError("post-observation evaluation requires pre-state and command")
            if self.post_observation.phase is not ObservationPhase.POST_DISPATCH:
                raise ValueError("evaluation post-observation has the wrong phase")
            if (
                self.post_observation.observer_id != self.pre_observation.observer_id
                or self.post_observation.observer_boot_epoch
                != self.pre_observation.observer_boot_epoch
                or self.post_observation.observer_sequence
                <= self.pre_observation.observer_sequence
                or self.post_observation.previous_envelope_digest
                != self.pre_observation.envelope_digest
                or self.post_observation.command_digest != self.command.digest
            ):
                raise ValueError("evaluation observations do not form one bound transition")
        return self

    def verify_observation_signatures(self) -> bool:
        public_key = public_key_from_base64(self.observer_public_key_b64)
        observations = tuple(
            value
            for value in (self.pre_observation, self.post_observation)
            if value is not None
        )
        return bool(observations) and all(value.verify(public_key) for value in observations)


class IndependentEvaluationStatus(StrEnum):
    AGREE = "agree"
    CONTRADICT = "contradict"
    INDETERMINATE = "indeterminate"
    NOT_APPLICABLE = "not_applicable"
    INPUT_REJECTED = "input_rejected"


class IndependentConsequenceReport(M4bClosedModel):
    """Signed result from the separately implemented topology consequence evaluator."""

    schema_version: Literal["m4b-independent-consequence-report-v1"] = (
        "m4b-independent-consequence-report-v1"
    )
    report_id: Identifier
    request_id: Identifier
    request_digest: Sha256
    evaluator_id: Literal["m4b-independent-topology-evaluator"] = (
        "m4b-independent-topology-evaluator"
    )
    key_id: Identifier
    public_key_b64: PublicKeyBase64
    boot_epoch: BootEpoch
    pid: int = Field(ge=1)
    sequence: int = Field(ge=1)
    evaluated_at: AwareDatetime
    fixture_id: Identifier
    fixture_digest: Sha256
    evaluator_profile: Literal["topology-connectivity-v1"] = "topology-connectivity-v1"
    algorithm_id: Literal["m4b-topology-consequence-bfs-decimal-v1"] = (
        "m4b-topology-consequence-bfs-decimal-v1"
    )
    evaluator_source_sha256: Sha256
    status: IndependentEvaluationStatus
    reasons: tuple[str, ...]
    predicted_values: IndependentConsequenceValues | None = None
    observed_values: IndependentConsequenceValues | None = None
    metric_comparisons: tuple[IndependentMetricComparison, ...] = ()
    signature: SignatureBase64 = ""

    @model_validator(mode="after")
    def require_consistent_report(self) -> IndependentConsequenceReport:
        _require_unique(self.reasons, label="independent evaluation reasons")
        metric_names = tuple(item.metric for item in self.metric_comparisons)
        if len(set(metric_names)) != len(metric_names):
            raise ValueError("independent report cannot compare one metric more than once")
        complete_metrics = set(IndependentMetricName)
        compared_metrics = set(metric_names)
        if self.status in {
            IndependentEvaluationStatus.AGREE,
            IndependentEvaluationStatus.CONTRADICT,
        }:
            if self.predicted_values is None or self.observed_values is None:
                raise ValueError("definitive independent reports require both value sets")
            if compared_metrics != complete_metrics:
                raise ValueError("definitive independent reports require every registered metric")
        if self.status is IndependentEvaluationStatus.AGREE and any(
            item.outcome != "match" for item in self.metric_comparisons
        ):
            raise ValueError("agree status cannot retain a metric mismatch")
        if self.status is IndependentEvaluationStatus.CONTRADICT:
            if not any(item.outcome == "mismatch" for item in self.metric_comparisons):
                raise ValueError("contradict status requires at least one metric mismatch")
            if not self.reasons:
                raise ValueError("contradict status requires an explanatory reason")
        if self.status in {
            IndependentEvaluationStatus.INDETERMINATE,
            IndependentEvaluationStatus.NOT_APPLICABLE,
            IndependentEvaluationStatus.INPUT_REJECTED,
        } and not self.reasons:
            raise ValueError("non-definitive independent reports require a reason")
        return self

    def signing_payload(self) -> bytes:
        unsigned = canonical_json_bytes(
            self.model_dump(mode="json", exclude={"signature"})
        )
        return INDEPENDENT_REPORT_SIGNATURE_DOMAIN + unsigned

    def signed(self, private_key: Ed25519PrivateKey) -> IndependentConsequenceReport:
        if public_key_base64(private_key.public_key()) != self.public_key_b64:
            raise ValueError("report private key does not match the declared evaluator key")
        return self.model_copy(
            update={"signature": sign_bytes(private_key, self.signing_payload())}
        )

    def verify(self) -> bool:
        return bool(self.signature) and verify_bytes(
            public_key_from_base64(self.public_key_b64),
            self.signing_payload(),
            self.signature,
        )

    def verify_for_request(self, request: IndependentEvaluationRequest) -> bool:
        return (
            self.verify()
            and self.request_id == request.request_id
            and self.request_digest == request.digest
            and self.fixture_id == request.fixture_id
            and self.fixture_digest == request.fixture_digest
            and self.evaluator_profile == request.evaluator_profile
        )


class M4bArtifactDescriptor(M4bClosedModel):
    """Exact-byte descriptor for one regular file in an M4b evidence package."""

    path: str = Field(min_length=1, max_length=1024)
    media_type: str = Field(min_length=1, max_length=256)
    byte_length: int = Field(ge=0)
    sha256: Sha256
    record_count: int | None = Field(default=None, ge=0)

    @field_validator("path")
    @classmethod
    def require_safe_relative_path(cls, value: str) -> str:
        if "\\" in value or value.startswith("/") or value.endswith("/"):
            raise ValueError("artifact path must be a relative POSIX file path")
        path = PurePosixPath(value)
        if any(part in {"", ".", ".."} for part in path.parts) or str(path) != value:
            raise ValueError("artifact path must be normalized and traversal-free")
        return value


class M4bPackageDisposition(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class M4bEvidenceManifest(M4bClosedModel):
    """Strict top-level manifest for one immutable M4b package directory."""

    schema_version: Literal["m4b-evidence-manifest-v1"] = "m4b-evidence-manifest-v1"
    experiment_id: Identifier
    experiment_version: Identifier
    outcome_projection_version: Identifier
    protocol_version: Identifier
    package_disposition: M4bPackageDisposition
    started_at_utc: AwareDatetime
    completed_at_utc: AwareDatetime
    git: dict[str, JsonValue]
    root_seed: int = Field(ge=0)
    master_seeds: tuple[int, ...] = Field(min_length=1)
    session_count: int = Field(ge=0)
    transaction_record_count: int = Field(ge=0)
    evidence_record_count: int = Field(ge=0)
    component_registration_count: int = Field(ge=0)
    probe_record_count: int = Field(ge=0)
    independent_evaluation_count: int = Field(ge=0)
    artifacts: tuple[M4bArtifactDescriptor, ...] = Field(min_length=1)
    source_sha256: dict[str, Sha256]
    schema_sha256: dict[str, Sha256]
    configuration_sha256: dict[str, Sha256]
    fixture_sha256: dict[str, Sha256]
    deterministic_outcome_sha256: Sha256
    root_anchor_id: Identifier
    root_key_id: Identifier
    root_public_key_sha256: Sha256
    host: dict[str, JsonValue]
    component_versions: dict[str, str]
    boundary: dict[str, JsonValue]
    known_limitations: tuple[str, ...]
    analyst: Literal["Angelis Pseftis"] = "Angelis Pseftis"
    summary: dict[str, JsonValue]

    @field_validator("git", "host", "boundary", "summary")
    @classmethod
    def require_json_objects(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        _require_json_value(value, label="manifest structured field")
        return value

    @model_validator(mode="after")
    def require_consistent_manifest(self) -> M4bEvidenceManifest:
        if self.completed_at_utc < self.started_at_utc:
            raise ValueError("manifest completion precedes its start")
        if len(set(self.master_seeds)) != len(self.master_seeds):
            raise ValueError("manifest master seeds must be unique")
        if self.session_count != len(self.master_seeds):
            raise ValueError("manifest session count must match its master seeds")
        paths = tuple(item.path for item in self.artifacts)
        if paths != tuple(sorted(set(paths))):
            raise ValueError("manifest artifact paths must be unique and sorted")
        reserved = {
            "manifest.json",
            "manifest.signature.json",
            "manifest.sig.json",
        }
        if any(path in reserved for path in paths):
            raise ValueError("manifest and detached signature cannot describe themselves")
        for label, mapping in (
            ("source hashes", self.source_sha256),
            ("schema hashes", self.schema_sha256),
            ("configuration hashes", self.configuration_sha256),
            ("fixture hashes", self.fixture_sha256),
        ):
            if not mapping:
                raise ValueError(f"manifest {label} cannot be empty")
            if tuple(mapping) != tuple(sorted(mapping)):
                raise ValueError(f"manifest {label} paths must be sorted")
            for path in mapping:
                M4bArtifactDescriptor.require_safe_relative_path(path)
        if tuple(self.component_versions) != tuple(sorted(self.component_versions)):
            raise ValueError("component-version keys must be sorted")
        _require_unique(self.known_limitations, label="known limitations")
        if self.independent_evaluation_count > self.transaction_record_count:
            raise ValueError("independent evaluation count exceeds transaction records")
        return self


class M4bManifestSignature(M4bClosedModel):
    """Detached Ed25519 signature over a domain-separated exact manifest byte stream."""

    schema_version: Literal["m4b-manifest-signature-v1"] = "m4b-manifest-signature-v1"
    manifest_sha256: Sha256
    package_id: Sha256
    signer_anchor_id: Identifier
    signer_key_id: Identifier
    algorithm: Literal["Ed25519"] = "Ed25519"
    domain: Literal["AEGIS-OT-M4B-MANIFEST-V1"] = MANIFEST_SIGNATURE_DOMAIN
    signature: SignatureBase64

    @model_validator(mode="after")
    def require_package_binding(self) -> M4bManifestSignature:
        if self.package_id != self.manifest_sha256:
            raise ValueError("M4b package ID must equal the exact manifest digest")
        if not self.signature:
            raise ValueError("detached manifest signature cannot be empty")
        return self

    @classmethod
    def issue(
        cls,
        *,
        manifest_bytes: bytes,
        signer_anchor_id: str,
        signer_key_id: str,
        private_key: Ed25519PrivateKey,
    ) -> M4bManifestSignature:
        manifest_sha256 = sha256_bytes(manifest_bytes)
        payload = _manifest_signature_payload(MANIFEST_SIGNATURE_DOMAIN, manifest_bytes)
        return cls(
            manifest_sha256=manifest_sha256,
            package_id=manifest_sha256,
            signer_anchor_id=signer_anchor_id,
            signer_key_id=signer_key_id,
            signature=sign_bytes(private_key, payload),
        )

    @classmethod
    def issue_for_manifest(
        cls,
        *,
        manifest: M4bEvidenceManifest,
        signer_anchor_id: str,
        signer_key_id: str,
        private_key: Ed25519PrivateKey,
    ) -> M4bManifestSignature:
        return cls.issue(
            manifest_bytes=manifest.canonical_bytes(),
            signer_anchor_id=signer_anchor_id,
            signer_key_id=signer_key_id,
            private_key=private_key,
        )

    def verify(self, manifest_bytes: bytes, public_key: Ed25519PublicKey) -> bool:
        return (
            sha256_bytes(manifest_bytes) == self.manifest_sha256
            and verify_bytes(
                public_key,
                _manifest_signature_payload(self.domain, manifest_bytes),
                self.signature,
            )
        )

    def verify_for_manifest(
        self,
        manifest: M4bEvidenceManifest,
        public_key: Ed25519PublicKey,
    ) -> bool:
        return self.verify(manifest.canonical_bytes(), public_key)


# Readable compatibility names for callers that do not carry the milestone prefix.
M4bIndependentEvaluationRequest = IndependentEvaluationRequest
M4bIndependentConsequenceReport = IndependentConsequenceReport
M4bOrderlyRestartRecord = M4bOrderlyRestartReplayRecord
M4bDetachedManifestSignature = M4bManifestSignature
