"""Bounded HTTP adapters for the M4g-a segmented capability experiment.

The adapters retain the existing M4a artifact semantics across explicit JSON
HTTP boundaries.  Message signatures authenticate configured experiment keys;
they are not TLS workload identity or hostile-host isolation evidence.
"""

from __future__ import annotations

import json
import math
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final, Literal, Protocol, TypeVar, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .capability_control import CandidatePort, ObservationPort, VirtualPlcPort
from .capability_models import (
    CapabilityActionRequest,
    CapabilityExecutionPermit,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from .capability_plc import CapabilityPlcPlantPort
from .crypto import decode_urlsafe_b64
from .models import Decision
from .pandapower_plant import PhysicalSimulationError
from .physical_control import Clock, utc_now
from .physical_models import (
    SHA256_PATTERN,
    CandidateAssessment,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
)
from .segmented_capability_models import (
    MAX_SIGNED_CALL_TTL,
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
    SegmentedCapabilityDispatch,
    SignedPlantCall,
    SignedPlantResponse,
    SignedSegmentedCapabilityDispatch,
    SignedSegmentedCapabilityResponse,
)

MAX_JSON_BYTES: Final = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS: Final = 5.0
DEFAULT_CALL_TTL: Final = timedelta(seconds=15)


class CapabilityTransportError(RuntimeError):
    """Base failure at an M4g-a HTTP capability boundary."""


class CapabilityTransportProtocolError(CapabilityTransportError):
    """A peer response was malformed, unbound, or cryptographically invalid."""


class CapabilityTransportUnavailable(CapabilityTransportError):
    """A nonconsequential exchange did not produce a usable response."""


class CapabilityTransportRejected(CapabilityTransportError):
    """A peer returned a closed HTTP 4xx rejection before a usable result."""

    def __init__(self, reason: str, *, status_code: int) -> None:
        super().__init__(reason)
        self.status_code = status_code


class ConsequentialTransportOutcomeUnknown(CapabilityTransportError):
    """A consequential request may have crossed its dispatch boundary."""


class RemotePhysicalRejection(PhysicalSimulationError):
    """The signed plant response establishes a known rejected apply."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
    )


def _public_key(value: str) -> Ed25519PublicKey:
    raw = decode_urlsafe_b64(value)
    if len(raw) != 32:
        raise ValueError("Ed25519 public keys must contain exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


class PlantHealthMetadata(_StrictModel):
    schema_version: Literal["m4g-plant-health-v1"] = "m4g-plant-health-v1"
    status: Literal["ready"] = "ready"
    role: Literal["plant"] = "plant"
    pid: int = Field(ge=1)
    boot_epoch: str = Field(min_length=16, max_length=256)
    key_id: str = Field(min_length=1, max_length=256)
    public_key_b64: str = Field(min_length=1)
    backend: str = Field(min_length=1, max_length=256)
    model_digest: str = Field(pattern=SHA256_PATTERN)
    simulator_version: str = Field(min_length=1, max_length=256)
    observation_source_id: str = Field(min_length=1, max_length=256)
    state_version: int = Field(ge=0)
    state_digest: str = Field(pattern=SHA256_PATTERN)
    apply_requests: int = Field(ge=0)
    commit_count: int = Field(ge=0)
    call_reservations: int = Field(ge=0)

    @model_validator(mode="after")
    def require_valid_key_and_counters(self) -> PlantHealthMetadata:
        _public_key(self.public_key_b64)
        if self.commit_count > self.apply_requests:
            raise ValueError("plant commits cannot exceed apply requests")
        return self

    @property
    def public_key(self) -> Ed25519PublicKey:
        return _public_key(self.public_key_b64)


class ObserverHealthMetadata(_StrictModel):
    schema_version: Literal["m4g-observer-health-v1"] = "m4g-observer-health-v1"
    status: Literal["ready"] = "ready"
    role: Literal["observer"] = "observer"
    pid: int = Field(ge=1)
    observer_id: str = Field(min_length=1, max_length=256)
    boot_epoch: str = Field(min_length=16, max_length=256)
    key_id: str = Field(min_length=1, max_length=256)
    public_key_b64: str = Field(min_length=1)
    plant_boot_epoch: str = Field(min_length=16, max_length=256)
    plant_model_digest: str = Field(pattern=SHA256_PATTERN)
    capture_count: int = Field(ge=0)
    resolve_count: int = Field(ge=0)
    cached_observations: int = Field(ge=0)

    @model_validator(mode="after")
    def require_valid_key(self) -> ObserverHealthMetadata:
        _public_key(self.public_key_b64)
        return self

    @property
    def public_key(self) -> Ed25519PublicKey:
        return _public_key(self.public_key_b64)


class CandidateHealthMetadata(_StrictModel):
    schema_version: Literal["m4g-candidate-health-v1"] = "m4g-candidate-health-v1"
    status: Literal["ready"] = "ready"
    role: Literal["candidate"] = "candidate"
    pid: int = Field(ge=1)
    boot_epoch: str = Field(min_length=16, max_length=256)
    key_id: str = Field(min_length=1, max_length=256)
    public_key_b64: str = Field(min_length=1)
    plant_boot_epoch: str = Field(min_length=16, max_length=256)
    plant_model_digest: str = Field(pattern=SHA256_PATTERN)
    simulation_count: int = Field(ge=0)

    @model_validator(mode="after")
    def require_valid_key(self) -> CandidateHealthMetadata:
        _public_key(self.public_key_b64)
        return self

    @property
    def public_key(self) -> Ed25519PublicKey:
        return _public_key(self.public_key_b64)


class OtHealthMetadata(_StrictModel):
    schema_version: Literal["m4g-ot-health-v1"] = "m4g-ot-health-v1"
    status: Literal["ready"] = "ready"
    role: Literal["ot-adapter"] = "ot-adapter"
    pid: int = Field(ge=1)
    plc_id: str = Field(min_length=1, max_length=256)
    boot_epoch: str = Field(min_length=16, max_length=256)
    key_id: str = Field(min_length=1, max_length=256)
    public_key_b64: str = Field(min_length=1)
    gateway_key_id: str = Field(min_length=1, max_length=256)
    gateway_public_key_b64: str = Field(min_length=1)
    permit_key_id: str = Field(min_length=1, max_length=256)
    permit_public_key_b64: str = Field(min_length=1)
    plant_boot_epoch: str = Field(min_length=16, max_length=256)
    plant_model_digest: str = Field(pattern=SHA256_PATTERN)
    plant: PlantHealthMetadata | None = None
    observer_boot_epoch: str = Field(min_length=16, max_length=256)
    transport_replay_reservations: int = Field(ge=0)
    semantic_replay_reservations: int = Field(ge=0)
    execute_requests: int = Field(ge=0)
    scan_counter: int = Field(ge=0)

    @model_validator(mode="after")
    def require_valid_key_and_counters(self) -> OtHealthMetadata:
        _public_key(self.public_key_b64)
        _public_key(self.gateway_public_key_b64)
        _public_key(self.permit_public_key_b64)
        if len(
            {
                self.public_key_b64,
                self.gateway_public_key_b64,
                self.permit_public_key_b64,
            }
        ) != 3:
            raise ValueError("OT, gateway, and permit key material must be distinct")
        if self.scan_counter > self.execute_requests:
            raise ValueError("OT scan counter cannot exceed execute requests")
        if self.plant is not None and (
            self.plant.boot_epoch != self.plant_boot_epoch
            or self.plant.model_digest != self.plant_model_digest
        ):
            raise ValueError("OT embedded plant metadata is inconsistent")
        return self

    @property
    def public_key(self) -> Ed25519PublicKey:
        return _public_key(self.public_key_b64)

    @property
    def gateway_public_key(self) -> Ed25519PublicKey:
        return _public_key(self.gateway_public_key_b64)

    @property
    def permit_public_key(self) -> Ed25519PublicKey:
        return _public_key(self.permit_public_key_b64)


class SegmentedCapabilityDiscovery(_StrictModel):
    """One mutually consistent discovery snapshot used to build the gateway."""

    schema_version: Literal["m4g-capability-discovery-v1"] = (
        "m4g-capability-discovery-v1"
    )
    plant: PlantHealthMetadata
    observer: ObserverHealthMetadata
    candidate: CandidateHealthMetadata
    ot: OtHealthMetadata

    @model_validator(mode="after")
    def require_consistent_dependencies(self) -> SegmentedCapabilityDiscovery:
        for role, boot_epoch, model_digest in (
            (
                "observer",
                self.observer.plant_boot_epoch,
                self.observer.plant_model_digest,
            ),
            (
                "candidate",
                self.candidate.plant_boot_epoch,
                self.candidate.plant_model_digest,
            ),
            ("ot", self.ot.plant_boot_epoch, self.ot.plant_model_digest),
        ):
            if boot_epoch != self.plant.boot_epoch:
                raise ValueError(f"{role} reports a different plant boot epoch")
            if model_digest != self.plant.model_digest:
                raise ValueError(f"{role} reports a different plant model digest")
        if self.ot.observer_boot_epoch != self.observer.boot_epoch:
            raise ValueError("OT reports a different observer boot epoch")
        identities = (
            self.plant.key_id,
            self.observer.key_id,
            self.candidate.key_id,
            self.ot.key_id,
            self.ot.gateway_key_id,
            self.ot.permit_key_id,
        )
        if len(set(identities)) != len(identities):
            raise ValueError("segmented component signing key IDs must be distinct")
        public_keys = (
            self.plant.public_key_b64,
            self.observer.public_key_b64,
            self.candidate.public_key_b64,
            self.ot.public_key_b64,
            self.ot.gateway_public_key_b64,
            self.ot.permit_public_key_b64,
        )
        if len(set(public_keys)) != len(public_keys):
            raise ValueError("segmented component signing key material must be distinct")
        return self

    def require_distinct_gateway_key(self, gateway_key_id: str) -> None:
        if not gateway_key_id or gateway_key_id != self.ot.gateway_key_id:
            raise ValueError("gateway transport key does not match OT discovery")


class TransportFailureBody(_StrictModel):
    schema_version: Literal["m4g-transport-failure-v1"] = (
        "m4g-transport-failure-v1"
    )
    status: Literal["rejected", "error"]
    reason: str = Field(min_length=1, max_length=512)


def _same_plant_identity(
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


def _same_observer_identity(
    current: ObserverHealthMetadata,
    expected: ObserverHealthMetadata,
) -> bool:
    return (
        current.observer_id,
        current.boot_epoch,
        current.key_id,
        current.public_key_b64,
        current.plant_boot_epoch,
        current.plant_model_digest,
    ) == (
        expected.observer_id,
        expected.boot_epoch,
        expected.key_id,
        expected.public_key_b64,
        expected.plant_boot_epoch,
        expected.plant_model_digest,
    )


def _same_candidate_identity(
    current: CandidateHealthMetadata,
    expected: CandidateHealthMetadata,
) -> bool:
    return (
        current.boot_epoch,
        current.key_id,
        current.public_key_b64,
        current.plant_boot_epoch,
        current.plant_model_digest,
    ) == (
        expected.boot_epoch,
        expected.key_id,
        expected.public_key_b64,
        expected.plant_boot_epoch,
        expected.plant_model_digest,
    )


def _same_ot_identity(current: OtHealthMetadata, expected: OtHealthMetadata) -> bool:
    base_matches = (
        current.plc_id,
        current.boot_epoch,
        current.key_id,
        current.public_key_b64,
        current.gateway_key_id,
        current.gateway_public_key_b64,
        current.permit_key_id,
        current.permit_public_key_b64,
        current.plant_boot_epoch,
        current.plant_model_digest,
        current.observer_boot_epoch,
    ) == (
        expected.plc_id,
        expected.boot_epoch,
        expected.key_id,
        expected.public_key_b64,
        expected.gateway_key_id,
        expected.gateway_public_key_b64,
        expected.permit_key_id,
        expected.permit_public_key_b64,
        expected.plant_boot_epoch,
        expected.plant_model_digest,
        expected.observer_boot_epoch,
    )
    if not base_matches:
        return False
    if current.plant is None or expected.plant is None:
        return current.plant is expected.plant
    return _same_plant_identity(current.plant, expected.plant)


@dataclass(frozen=True)
class HttpExchangeResponse:
    status_code: int
    content_type: str
    body: bytes


class HttpExchange(Protocol):
    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> HttpExchangeResponse: ...


def _validate_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("capability endpoint must be an HTTP(S) URL without credentials")


def _bounded_body(response: Any) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            declared_length = int(declared)
        except ValueError as exc:
            raise CapabilityTransportProtocolError(
                "response Content-Length is invalid"
            ) from exc
        if declared_length < 0 or declared_length > MAX_JSON_BYTES:
            raise CapabilityTransportProtocolError("response exceeds the JSON size limit")
    material = cast(bytes, response.read(MAX_JSON_BYTES + 1))
    if len(material) > MAX_JSON_BYTES:
        raise CapabilityTransportProtocolError("response exceeds the JSON size limit")
    return material


def urllib_http_exchange(
    *,
    method: str,
    url: str,
    body: bytes | None,
    headers: Mapping[str, str],
    timeout_seconds: float,
) -> HttpExchangeResponse:
    """Perform exactly one bounded HTTP exchange without application retries."""

    _validate_url(url)
    if method not in {"GET", "POST"}:
        raise ValueError("capability exchange method is unsupported")
    request = Request(  # noqa: S310 - URL scheme and authority are validated above
        url,
        data=body,
        headers=dict(headers),
        method=method,
    )
    try:
        response = urlopen(request, timeout=timeout_seconds)  # noqa: S310 - URL is validated
        with response:
            if str(response.geturl()) != url:
                raise CapabilityTransportProtocolError("HTTP redirects are forbidden")
            return HttpExchangeResponse(
                status_code=int(response.status),
                content_type=str(response.headers.get("Content-Type", "")),
                body=_bounded_body(response),
            )
    except HTTPError as exc:
        with exc:
            return HttpExchangeResponse(
                status_code=int(exc.code),
                content_type=str(exc.headers.get("Content-Type", "")),
                body=_bounded_body(exc),
            )
    except (CapabilityTransportProtocolError, ValueError):
        raise
    except (OSError, TimeoutError, URLError) as exc:
        raise CapabilityTransportUnavailable("HTTP exchange failed") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CapabilityTransportProtocolError("response contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise CapabilityTransportProtocolError(f"response contains forbidden constant {value}")


def _canonical_json(value: BaseModel | dict[str, Any]) -> bytes:
    material = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise ValueError("request exceeds the JSON size limit")
    return encoded


def _strict_json_object(material: bytes) -> dict[str, Any]:
    if len(material) > MAX_JSON_BYTES:
        raise CapabilityTransportProtocolError("response exceeds the JSON size limit")
    if material.startswith(b"\xef\xbb\xbf"):
        raise CapabilityTransportProtocolError("response UTF-8 BOM is forbidden")
    try:
        decoded = material.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except CapabilityTransportProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CapabilityTransportProtocolError("response is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CapabilityTransportProtocolError("response JSON root must be an object")
    return cast(dict[str, Any], value)


ModelT = TypeVar("ModelT", bound=BaseModel)


def _parse_model(response: HttpExchangeResponse, model: type[ModelT]) -> ModelT:
    if response.content_type.split(";", maxsplit=1)[0].strip().lower() != "application/json":
        raise CapabilityTransportProtocolError("response Content-Type must be application/json")
    value = _strict_json_object(response.body)
    try:
        # JSON-mode validation preserves strict wire types for datetime and enums.
        return model.model_validate_json(_canonical_json(value))
    except (ValidationError, ValueError, TypeError) as exc:
        raise CapabilityTransportProtocolError(
            f"response does not match {model.__name__}"
        ) from exc


class _RemoteJsonService:
    def __init__(
        self,
        base_url: str,
        *,
        exchange: HttpExchange = urllib_http_exchange,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        normalized = base_url.rstrip("/")
        _validate_url(normalized)
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("HTTP timeout must be positive and finite")
        self.base_url = normalized
        self.exchange = exchange
        self.timeout_seconds = timeout_seconds

    def _raw(
        self,
        method: str,
        path: str,
        payload: BaseModel | dict[str, Any] | None,
        *,
        consequential: bool,
    ) -> HttpExchangeResponse:
        body = _canonical_json(payload) if payload is not None else None
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            response = self.exchange(
                method=method,
                url=f"{self.base_url}{path}",
                body=body,
                headers=headers,
                timeout_seconds=self.timeout_seconds,
            )
        except ConsequentialTransportOutcomeUnknown:
            raise
        except CapabilityTransportProtocolError as exc:
            if consequential:
                raise ConsequentialTransportOutcomeUnknown(
                    "consequential HTTP exchange violated the transport protocol"
                ) from exc
            raise
        except (CapabilityTransportUnavailable, OSError, TimeoutError) as exc:
            if consequential:
                raise ConsequentialTransportOutcomeUnknown(
                    "consequential HTTP response was unavailable"
                ) from exc
            raise CapabilityTransportUnavailable("HTTP response was unavailable") from exc
        if (
            type(response.status_code) is not int
            or not 100 <= response.status_code <= 599
            or not isinstance(response.content_type, str)
            or not isinstance(response.body, bytes)
            or len(response.body) > MAX_JSON_BYTES
        ):
            error = CapabilityTransportProtocolError("exchange returned an invalid response")
            if consequential:
                raise ConsequentialTransportOutcomeUnknown(str(error)) from error
            raise error
        return response

    def _success_model(
        self,
        method: str,
        path: str,
        payload: BaseModel | dict[str, Any] | None,
        model: type[ModelT],
        *,
        consequential: bool = False,
    ) -> ModelT:
        response = self._raw(method, path, payload, consequential=consequential)
        if 200 <= response.status_code < 300:
            try:
                return _parse_model(response, model)
            except CapabilityTransportProtocolError as exc:
                if consequential:
                    raise ConsequentialTransportOutcomeUnknown(
                        "consequential response was invalid"
                    ) from exc
                raise
        try:
            failure = _parse_model(response, TransportFailureBody)
        except CapabilityTransportProtocolError as exc:
            if consequential:
                raise ConsequentialTransportOutcomeUnknown(
                    "consequential failure response was invalid"
                ) from exc
            if response.status_code >= 500:
                raise CapabilityTransportUnavailable(
                    "server failure response was invalid"
                ) from exc
            raise
        if 400 <= response.status_code < 500 and failure.status == "rejected":
            raise CapabilityTransportRejected(
                failure.reason,
                status_code=response.status_code,
            )
        if consequential:
            raise ConsequentialTransportOutcomeUnknown(failure.reason)
        raise CapabilityTransportUnavailable(failure.reason)


def _private_key_matches(private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey) -> bool:
    return private_key.public_key().public_bytes_raw() == public_key.public_bytes_raw()


def fetch_plant_health(
    base_url: str,
    *,
    exchange: HttpExchange = urllib_http_exchange,
) -> PlantHealthMetadata:
    return _RemoteJsonService(base_url, exchange=exchange)._success_model(
        "GET", "/health", None, PlantHealthMetadata
    )


def fetch_observer_health(
    base_url: str,
    *,
    exchange: HttpExchange = urllib_http_exchange,
) -> ObserverHealthMetadata:
    return _RemoteJsonService(base_url, exchange=exchange)._success_model(
        "GET", "/health", None, ObserverHealthMetadata
    )


def fetch_candidate_health(
    base_url: str,
    *,
    exchange: HttpExchange = urllib_http_exchange,
) -> CandidateHealthMetadata:
    return _RemoteJsonService(base_url, exchange=exchange)._success_model(
        "GET", "/health", None, CandidateHealthMetadata
    )


def fetch_ot_health(
    base_url: str,
    *,
    exchange: HttpExchange = urllib_http_exchange,
) -> OtHealthMetadata:
    return _RemoteJsonService(base_url, exchange=exchange)._success_model(
        "GET", "/health", None, OtHealthMetadata
    )


def discover_segmented_capabilities(
    *,
    plant_url: str,
    observer_url: str,
    candidate_url: str,
    ot_url: str,
    gateway_key_id: str,
    exchange: HttpExchange = urllib_http_exchange,
) -> SegmentedCapabilityDiscovery:
    discovery = SegmentedCapabilityDiscovery(
        plant=fetch_plant_health(plant_url, exchange=exchange),
        observer=fetch_observer_health(observer_url, exchange=exchange),
        candidate=fetch_candidate_health(candidate_url, exchange=exchange),
        ot=fetch_ot_health(ot_url, exchange=exchange),
    )
    discovery.require_distinct_gateway_key(gateway_key_id)
    return discovery


def discover_segmented_capabilities_via_ot(
    *,
    observer_url: str,
    candidate_url: str,
    ot_url: str,
    gateway_key_id: str,
    exchange: HttpExchange = urllib_http_exchange,
) -> SegmentedCapabilityDiscovery:
    """Discover the plant through OT without granting the gateway a plant route."""

    ot = fetch_ot_health(ot_url, exchange=exchange)
    if ot.plant is None:
        raise CapabilityTransportProtocolError(
            "OT health omitted the plant metadata required by the gateway"
        )
    discovery = SegmentedCapabilityDiscovery(
        plant=ot.plant,
        observer=fetch_observer_health(observer_url, exchange=exchange),
        candidate=fetch_candidate_health(candidate_url, exchange=exchange),
        ot=ot,
    )
    discovery.require_distinct_gateway_key(gateway_key_id)
    return discovery


class RemoteObservationPort(_RemoteJsonService, ObservationPort):
    def __init__(
        self,
        base_url: str,
        *,
        observer: ObserverHealthMetadata,
        exchange: HttpExchange = urllib_http_exchange,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        super().__init__(base_url, exchange=exchange, timeout_seconds=timeout_seconds)
        self.observer = observer

    def health(self) -> ObserverHealthMetadata:
        health = self._success_model("GET", "/health", None, ObserverHealthMetadata)
        if not _same_observer_identity(health, self.observer):
            raise CapabilityTransportProtocolError("observer health identity changed")
        return health

    def _verify(self, observation: SignedObservationEnvelope) -> None:
        if (
            observation.observer_id != self.observer.observer_id
            or observation.observer_key_id != self.observer.key_id
            or observation.observer_boot_epoch != self.observer.boot_epoch
            or observation.snapshot.model_digest != self.observer.plant_model_digest
            or not observation.verify(self.observer.public_key)
        ):
            raise CapabilityTransportProtocolError(
                "observer response identity, plant, or signature is invalid"
            )

    def resolve(
        self,
        *,
        observation_id: str,
        envelope_digest: str,
    ) -> SignedObservationEnvelope:
        if not observation_id or not _is_sha256(envelope_digest):
            raise ValueError("observation resolution binding is invalid")
        observation = self._success_model(
            "POST",
            "/v1/observations/resolve",
            {
                "observation_id": observation_id,
                "envelope_digest": envelope_digest,
            },
            SignedObservationEnvelope,
        )
        self._verify(observation)
        if (
            observation.observation_id != observation_id
            or observation.envelope_digest != envelope_digest
        ):
            raise CapabilityTransportProtocolError("resolved observation binding is wrong")
        return observation

    def capture_pre(
        self,
        *,
        correlation_id: str,
        challenge_nonce: str,
    ) -> SignedObservationEnvelope:
        if not correlation_id or not 16 <= len(challenge_nonce) <= 256:
            raise ValueError("pre-observation request binding is invalid")
        observation = self._success_model(
            "POST",
            "/v1/observations/pre",
            {
                "correlation_id": correlation_id,
                "challenge_nonce": challenge_nonce,
            },
            SignedObservationEnvelope,
        )
        self._verify(observation)
        if not all(
            (
                observation.phase is ObservationPhase.PRE_AUTHORIZATION,
                observation.correlation_id == correlation_id,
                observation.challenge_nonce == challenge_nonce,
            )
        ):
            raise CapabilityTransportProtocolError("pre-observation response binding is wrong")
        return observation

    def capture_post(
        self,
        *,
        correlation_id: str,
        challenge_nonce: str,
        previous_envelope_digest: str,
        permit_id: str,
        command_digest: str,
        plc_acknowledgment_digest: str,
    ) -> SignedObservationEnvelope:
        if (
            not correlation_id
            or len(challenge_nonce) < 16
            or not permit_id
            or not all(
                _is_sha256(value)
                for value in (
                    previous_envelope_digest,
                    command_digest,
                    plc_acknowledgment_digest,
                )
            )
        ):
            raise ValueError("post-observation request binding is invalid")
        observation = self._success_model(
            "POST",
            "/v1/observations/post",
            {
                "correlation_id": correlation_id,
                "challenge_nonce": challenge_nonce,
                "previous_envelope_digest": previous_envelope_digest,
                "permit_id": permit_id,
                "command_digest": command_digest,
                "plc_acknowledgment_digest": plc_acknowledgment_digest,
            },
            SignedObservationEnvelope,
        )
        self._verify(observation)
        if not all(
            (
                observation.phase is ObservationPhase.POST_DISPATCH,
                observation.correlation_id == correlation_id,
                observation.challenge_nonce == challenge_nonce,
                observation.previous_envelope_digest == previous_envelope_digest,
                observation.permit_id == permit_id,
                observation.command_digest == command_digest,
                observation.plc_acknowledgment_digest == plc_acknowledgment_digest,
            )
        ):
            raise CapabilityTransportProtocolError("post-observation response binding is wrong")
        return observation


class RemoteCandidatePort(_RemoteJsonService, CandidatePort):
    def __init__(
        self,
        base_url: str,
        *,
        candidate: CandidateHealthMetadata,
        plant: PlantHealthMetadata,
        exchange: HttpExchange = urllib_http_exchange,
        clock: Clock = utc_now,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        super().__init__(base_url, exchange=exchange, timeout_seconds=timeout_seconds)
        if (
            candidate.plant_boot_epoch != plant.boot_epoch
            or candidate.plant_model_digest != plant.model_digest
        ):
            raise ValueError("candidate discovery does not match the configured plant")
        self.candidate = candidate
        self.plant = plant
        self.clock = clock
        self.last_exchange: PlantExchange | None = None

    def health(self) -> CandidateHealthMetadata:
        health = self._success_model("GET", "/health", None, CandidateHealthMetadata)
        if not _same_candidate_identity(health, self.candidate):
            raise CapabilityTransportProtocolError("candidate health identity changed")
        return health

    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
        exchange = self._success_model(
            "POST",
            "/v1/candidates/simulate",
            {"command": command.model_dump(mode="json")},
            PlantExchange,
        )
        if not exchange.verify(
            self.candidate.public_key,
            self.plant.public_key,
            expected_role=PlantCallerRole.CANDIDATE,
            expected_caller_key_id=self.candidate.key_id,
            expected_audience=PHYSICAL_PLANT_AUDIENCE,
            expected_plant_boot_epoch=self.plant.boot_epoch,
            expected_plant_key_id=self.plant.key_id,
            evaluated_at=self.clock(),
        ):
            raise CapabilityTransportProtocolError(
                "candidate plant exchange signature or identity is invalid"
            )
        if (
            exchange.call.operation is not PlantOperation.SIMULATE
            or not isinstance(exchange.call.payload, PlantSimulatePayload)
            or exchange.call.payload.command.digest != command.digest
            or exchange.response.status is not PlantResponseStatus.OK
            or not isinstance(
                exchange.response.payload,
                PlantSimulationResponsePayload,
            )
        ):
            raise CapabilityTransportProtocolError(
                "candidate plant exchange is not the requested successful simulation"
            )
        assessment = exchange.response.payload.assessment
        if (
            assessment.command_digest != command.digest
            or assessment.pre_state.model_digest != self.candidate.plant_model_digest
            or assessment.post_state.model_digest != self.candidate.plant_model_digest
        ):
            raise CapabilityTransportProtocolError("candidate response binding is wrong")
        self.last_exchange = exchange
        return assessment


class RemoteVirtualPlcPort(_RemoteJsonService, VirtualPlcPort):
    def __init__(
        self,
        base_url: str,
        *,
        ot: OtHealthMetadata,
        gateway_key_id: str,
        gateway_private_key: Ed25519PrivateKey,
        exchange: HttpExchange = urllib_http_exchange,
        clock: Clock = utc_now,
        call_ttl: timedelta = DEFAULT_CALL_TTL,
        nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(24),
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        super().__init__(base_url, exchange=exchange, timeout_seconds=timeout_seconds)
        _validate_ttl(call_ttl)
        if not gateway_key_id or gateway_key_id != ot.gateway_key_id:
            raise ValueError("gateway transport key does not match OT discovery")
        if not _private_key_matches(gateway_private_key, ot.gateway_public_key):
            raise ValueError("gateway private key does not match OT discovery")
        self.ot = ot
        self.gateway_key_id = gateway_key_id
        self.gateway_private_key = gateway_private_key
        self.clock = clock
        self.call_ttl = call_ttl
        self.nonce_factory = nonce_factory

    def health(self) -> OtHealthMetadata:
        health = self._success_model("GET", "/health", None, OtHealthMetadata)
        if not _same_ot_identity(health, self.ot):
            raise CapabilityTransportProtocolError("OT health identity changed")
        return health

    def execute(
        self,
        *,
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        pre_observation: SignedObservationEnvelope,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> PlcCommandAcknowledgment:
        dispatch = SegmentedCapabilityDispatch(
            request=request,
            pre_observation=pre_observation,
            decision=decision,
            assessment=assessment,
            permit=permit,
        )
        issued_at = self.clock()
        signed = SignedSegmentedCapabilityDispatch.issue(
            dispatch=dispatch,
            gateway_key_id=self.gateway_key_id,
            transport_nonce=_nonce(self.nonce_factory),
            issued_at=issued_at,
            expires_at=issued_at + self.call_ttl,
            private_key=self.gateway_private_key,
            audience=OT_CAPABILITY_AUDIENCE,
        )
        response = self._raw(
            "POST",
            "/v1/capability/execute",
            signed,
            consequential=True,
        )
        if response.status_code >= 500:
            raise ConsequentialTransportOutcomeUnknown(
                "OT returned a server failure after consequential dispatch"
            )
        if 400 <= response.status_code < 500:
            try:
                failure = _parse_model(response, TransportFailureBody)
            except CapabilityTransportProtocolError as exc:
                raise ConsequentialTransportOutcomeUnknown(
                    "OT rejection response was unverifiable"
                ) from exc
            if failure.status == "rejected":
                raise CapabilityTransportRejected(
                    failure.reason,
                    status_code=response.status_code,
                )
            raise ConsequentialTransportOutcomeUnknown(failure.reason)
        if not 200 <= response.status_code < 300:
            raise ConsequentialTransportOutcomeUnknown("OT returned an invalid HTTP status")
        try:
            verified = _parse_model(response, SignedSegmentedCapabilityResponse)
        except CapabilityTransportProtocolError as exc:
            raise ConsequentialTransportOutcomeUnknown(
                "OT response was not a valid signed artifact"
            ) from exc
        acknowledgment = verified.acknowledgment
        if not verified.verify_complete_for_request(
            self.ot.public_key,
            request=signed,
            expected_ot_key_id=self.ot.key_id,
            plc_public_key=self.ot.public_key,
            expected_plc_id=self.ot.plc_id,
            expected_plc_key_id=self.ot.key_id,
            expected_plc_boot_epoch=self.ot.boot_epoch,
            evaluated_at=self.clock(),
        ):
            raise ConsequentialTransportOutcomeUnknown(
                "OT response signature or transaction binding is invalid"
            )
        return acknowledgment


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_ttl(value: timedelta) -> None:
    if value <= timedelta(0) or value > MAX_SIGNED_CALL_TTL:
        raise ValueError("signed call TTL is outside the registered bound")


def _nonce(factory: Callable[[], str]) -> str:
    value = factory()
    if not isinstance(value, str) or not 16 <= len(value) <= 256:
        raise ValueError("transport nonce is outside the registered bound")
    return value


class _RemotePlantClient(_RemoteJsonService):
    def __init__(
        self,
        base_url: str,
        *,
        plant: PlantHealthMetadata,
        role: PlantCallerRole,
        caller_key_id: str,
        caller_private_key: Ed25519PrivateKey,
        exchange: HttpExchange = urllib_http_exchange,
        clock: Clock = utc_now,
        call_ttl: timedelta = DEFAULT_CALL_TTL,
        nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(24),
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        super().__init__(base_url, exchange=exchange, timeout_seconds=timeout_seconds)
        _validate_ttl(call_ttl)
        if not caller_key_id or caller_key_id == plant.key_id:
            raise ValueError("plant caller and response keys must be distinct")
        self.plant = plant
        self.role = role
        self.caller_key_id = caller_key_id
        self.caller_private_key = caller_private_key
        self.clock = clock
        self.call_ttl = call_ttl
        self.nonce_factory = nonce_factory

    def health(self) -> PlantHealthMetadata:
        health = self._success_model("GET", "/health", None, PlantHealthMetadata)
        if not _same_plant_identity(health, self.plant):
            raise CapabilityTransportProtocolError("plant health identity changed")
        return health

    def _exchange_call(
        self,
        operation: PlantOperation,
        payload: PlantCapturePayload
        | PlantReadPayload
        | PlantSimulatePayload
        | PlantApplyPayload,
        *,
        consequential: bool,
    ) -> PlantExchange:
        issued_at = self.clock()
        call = SignedPlantCall.issue(
            role=self.role,
            operation=operation,
            payload=payload,
            caller_key_id=self.caller_key_id,
            target_plant_key_id=self.plant.key_id,
            target_plant_boot_epoch=self.plant.boot_epoch,
            call_nonce=_nonce(self.nonce_factory),
            issued_at=issued_at,
            expires_at=issued_at + self.call_ttl,
            private_key=self.caller_private_key,
            audience=PHYSICAL_PLANT_AUDIENCE,
        )
        response = self._raw(
            "POST",
            "/v1/plant/call",
            call,
            consequential=consequential,
        )
        if response.status_code >= 500 and consequential:
            raise ConsequentialTransportOutcomeUnknown(
                "plant returned a server failure after apply"
            )
        try:
            signed = _parse_model(response, SignedPlantResponse)
        except CapabilityTransportProtocolError as exc:
            if consequential:
                raise ConsequentialTransportOutcomeUnknown(
                    "plant apply response was unverifiable"
                ) from exc
            raise
        if (
            not signed.verify_for_call(
                self.plant.public_key,
                call=call,
                expected_plant_boot_epoch=self.plant.boot_epoch,
                expected_plant_key_id=self.plant.key_id,
            )
            or not call.issued_at <= signed.signed_at < call.expires_at
        ):
            error = CapabilityTransportProtocolError(
                "plant response signature, identity, time, or call binding is invalid"
            )
            if consequential:
                raise ConsequentialTransportOutcomeUnknown(str(error)) from error
            raise error
        if 400 <= response.status_code < 500 and signed.status is not PlantResponseStatus.REJECTED:
            error = CapabilityTransportProtocolError(
                "plant HTTP rejection does not carry a signed rejection"
            )
            if consequential:
                raise ConsequentialTransportOutcomeUnknown(str(error)) from error
            raise error
        if not (200 <= response.status_code < 300 or 400 <= response.status_code < 500):
            if consequential:
                raise ConsequentialTransportOutcomeUnknown(
                    "plant returned an ambiguous HTTP status"
                )
            raise CapabilityTransportUnavailable("plant returned an unavailable status")
        if signed.status is PlantResponseStatus.REJECTED:
            failure = cast(PlantFailureResponsePayload, signed.payload)
            raise RemotePhysicalRejection(failure.reason)
        if signed.status is PlantResponseStatus.ERROR:
            failure = cast(PlantFailureResponsePayload, signed.payload)
            if consequential:
                raise ConsequentialTransportOutcomeUnknown(failure.reason)
            raise CapabilityTransportUnavailable(failure.reason)
        return PlantExchange(call=call, response=signed)

    def _call(
        self,
        operation: PlantOperation,
        payload: PlantCapturePayload
        | PlantReadPayload
        | PlantSimulatePayload
        | PlantApplyPayload,
        *,
        consequential: bool,
    ) -> SignedPlantResponse:
        return self._exchange_call(
            operation,
            payload,
            consequential=consequential,
        ).response


class RemoteObserverPlantClient(_RemotePlantClient):
    def __init__(
        self,
        base_url: str,
        *,
        plant: PlantHealthMetadata,
        observer: ObserverHealthMetadata,
        caller_private_key: Ed25519PrivateKey,
        exchange: HttpExchange = urllib_http_exchange,
        clock: Clock = utc_now,
        call_ttl: timedelta = DEFAULT_CALL_TTL,
        nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(24),
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if (
            observer.plant_boot_epoch != plant.boot_epoch
            or observer.plant_model_digest != plant.model_digest
        ):
            raise ValueError("observer discovery does not match the configured plant")
        if not _private_key_matches(caller_private_key, observer.public_key):
            raise ValueError("observer plant-call private key does not match discovery")
        super().__init__(
            base_url,
            plant=plant,
            role=PlantCallerRole.OBSERVER,
            caller_key_id=observer.key_id,
            caller_private_key=caller_private_key,
            exchange=exchange,
            clock=clock,
            call_ttl=call_ttl,
            nonce_factory=nonce_factory,
            timeout_seconds=timeout_seconds,
        )

    def capture_state(self) -> PhysicalStateSnapshot:
        return self.capture_bound_state(
            correlation_id=str(uuid4()),
            challenge_nonce=_nonce(self.nonce_factory),
        )

    def capture_bound_state(
        self,
        *,
        correlation_id: str,
        challenge_nonce: str,
    ) -> PhysicalStateSnapshot:
        if not correlation_id or not 16 <= len(challenge_nonce) <= 256:
            raise ValueError("plant capture binding is invalid")
        response = self._call(
            PlantOperation.CAPTURE,
            PlantCapturePayload(
                correlation_id=correlation_id,
                challenge_nonce=challenge_nonce,
            ),
            consequential=False,
        )
        payload = cast(PlantStateResponsePayload, response.payload)
        return payload.snapshot


class RemoteCandidatePlantClient(_RemotePlantClient, CandidatePort):
    def __init__(
        self,
        base_url: str,
        *,
        plant: PlantHealthMetadata,
        candidate: CandidateHealthMetadata,
        caller_private_key: Ed25519PrivateKey,
        exchange: HttpExchange = urllib_http_exchange,
        clock: Clock = utc_now,
        call_ttl: timedelta = DEFAULT_CALL_TTL,
        nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(24),
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if (
            candidate.plant_boot_epoch != plant.boot_epoch
            or candidate.plant_model_digest != plant.model_digest
        ):
            raise ValueError("candidate discovery does not match the configured plant")
        if not _private_key_matches(caller_private_key, candidate.public_key):
            raise ValueError("candidate plant-call private key does not match discovery")
        super().__init__(
            base_url,
            plant=plant,
            role=PlantCallerRole.CANDIDATE,
            caller_key_id=candidate.key_id,
            caller_private_key=caller_private_key,
            exchange=exchange,
            clock=clock,
            call_ttl=call_ttl,
            nonce_factory=nonce_factory,
            timeout_seconds=timeout_seconds,
        )

    def simulate_exchange(
        self,
        command: PhysicalControlCommand,
    ) -> PlantExchange:
        return self._exchange_call(
            PlantOperation.SIMULATE,
            PlantSimulatePayload(command=command),
            consequential=False,
        )

    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
        exchange = self.simulate_exchange(command)
        payload = cast(PlantSimulationResponsePayload, exchange.response.payload)
        if payload.assessment.command_digest != command.digest:
            raise CapabilityTransportProtocolError(
                "plant simulation response is bound to a different command"
            )
        return payload.assessment


class RemotePlcPlantClient(_RemotePlantClient, CapabilityPlcPlantPort):
    def __init__(
        self,
        base_url: str,
        *,
        plant: PlantHealthMetadata,
        ot: OtHealthMetadata,
        caller_private_key: Ed25519PrivateKey,
        exchange: HttpExchange = urllib_http_exchange,
        clock: Clock = utc_now,
        call_ttl: timedelta = DEFAULT_CALL_TTL,
        nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(24),
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if (
            ot.plant_boot_epoch != plant.boot_epoch
            or ot.plant_model_digest != plant.model_digest
        ):
            raise ValueError("PLC discovery does not match the configured plant")
        if not _private_key_matches(caller_private_key, ot.public_key):
            raise ValueError("PLC plant-call private key does not match discovery")
        super().__init__(
            base_url,
            plant=plant,
            role=PlantCallerRole.PLC,
            caller_key_id=ot.key_id,
            caller_private_key=caller_private_key,
            exchange=exchange,
            clock=clock,
            call_ttl=call_ttl,
            nonce_factory=nonce_factory,
            timeout_seconds=timeout_seconds,
        )

    def read_state(self) -> PhysicalStateSnapshot:
        response = self._call(
            PlantOperation.READ,
            PlantReadPayload(correlation_id=str(uuid4())),
            consequential=False,
        )
        return cast(PlantStateResponsePayload, response.payload).snapshot

    def simulate_candidate(self, command: PhysicalControlCommand) -> CandidateAssessment:
        response = self._call(
            PlantOperation.SIMULATE,
            PlantSimulatePayload(command=command),
            consequential=False,
        )
        assessment = cast(PlantSimulationResponsePayload, response.payload).assessment
        if assessment.command_digest != command.digest:
            raise CapabilityTransportProtocolError(
                "PLC plant simulation response is bound to a different command"
            )
        return assessment

    def apply_authorized_command(
        self,
        command: PhysicalControlCommand,
        *,
        expected_pre_state_version: int | None = None,
        expected_pre_state_digest: str | None = None,
        expected_pre_observation_digest: str | None = None,
        expected_post_state_digest: str | None = None,
        expected_post_topology_digest: str | None = None,
        authorization_expires_at: datetime | None = None,
    ) -> PhysicalStateSnapshot:
        bindings = (
            expected_pre_state_version,
            expected_pre_state_digest,
            expected_pre_observation_digest,
            expected_post_state_digest,
            expected_post_topology_digest,
            authorization_expires_at,
        )
        if any(value is None for value in bindings):
            raise RemotePhysicalRejection("plant_apply_bindings_required")
        response = self._call(
            PlantOperation.APPLY,
            PlantApplyPayload(
                command=command,
                expected_pre_state_version=cast(int, expected_pre_state_version),
                expected_pre_state_digest=cast(str, expected_pre_state_digest),
                expected_pre_observation_digest=cast(
                    str, expected_pre_observation_digest
                ),
                expected_post_state_digest=cast(str, expected_post_state_digest),
                expected_post_topology_digest=cast(
                    str, expected_post_topology_digest
                ),
                authorization_expires_at=cast(datetime, authorization_expires_at),
            ),
            consequential=True,
        )
        snapshot = cast(PlantStateResponsePayload, response.payload).snapshot
        if (
            snapshot.state_digest != expected_post_state_digest
            or snapshot.topology_digest != expected_post_topology_digest
            or snapshot.state_version != cast(int, expected_pre_state_version) + 1
        ):
            raise ConsequentialTransportOutcomeUnknown(
                "plant apply response diverges from the authorized post-state"
            )
        return snapshot

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
    ) -> PhysicalStateSnapshot:
        """Carry the signed permit deadline through the plant CAS call."""

        return self.apply_authorized_command(
            command,
            expected_pre_state_version=expected_pre_state_version,
            expected_pre_state_digest=expected_pre_state_digest,
            expected_pre_observation_digest=expected_pre_observation_digest,
            expected_post_state_digest=expected_post_state_digest,
            expected_post_topology_digest=expected_post_topology_digest,
            authorization_expires_at=authorization_expires_at,
        )
