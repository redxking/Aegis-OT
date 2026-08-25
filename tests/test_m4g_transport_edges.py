from __future__ import annotations

from datetime import timedelta
from io import BytesIO
from typing import Any, cast
from urllib.error import HTTPError, URLError

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ValidationError
from test_m4g_transport import (
    CANDIDATE_KEY_ID,
    GATEWAY_KEY_ID,
    NOW,
    OBSERVER_KEY_ID,
    OT_KEY_ID,
    PLANT_BOOT,
    PLANT_KEY_ID,
    Artifacts,
    StubExchange,
    _candidate_exchange,
    _json_response,
    _plant_exchange,
)
from test_m4g_transport import (
    artifacts as _artifacts_fixture,
)

import aegis_ot.segmented_capability_transport as transport
from aegis_ot.capability_models import ObservationPhase, SignedObservationEnvelope
from aegis_ot.crypto import generate_keypair
from aegis_ot.segmented_capability_models import (
    PHYSICAL_PLANT_AUDIENCE,
    PlantCallerRole,
    PlantExchange,
    PlantFailureResponsePayload,
    PlantOperation,
    PlantResponseStatus,
    PlantSimulatePayload,
    PlantSimulationResponsePayload,
    SignedPlantCall,
    SignedPlantResponse,
    SignedSegmentedCapabilityDispatch,
    SignedSegmentedCapabilityResponse,
)
from aegis_ot.segmented_capability_transport import (
    MAX_JSON_BYTES,
    CapabilityTransportProtocolError,
    CapabilityTransportRejected,
    CapabilityTransportUnavailable,
    ConsequentialTransportOutcomeUnknown,
    HttpExchangeResponse,
    OtHealthMetadata,
    PlantHealthMetadata,
    RemoteCandidatePlantClient,
    RemoteCandidatePort,
    RemoteObservationPort,
    RemoteObserverPlantClient,
    RemotePhysicalRejection,
    RemotePlcPlantClient,
    RemoteVirtualPlcPort,
    SegmentedCapabilityDiscovery,
    TransportFailureBody,
    discover_segmented_capabilities_via_ot,
    urllib_http_exchange,
)

artifacts = _artifacts_fixture


class FakeUrlResponse:
    def __init__(
        self,
        body: bytes = b"{}",
        *,
        status: int = 200,
        content_type: str = "application/json",
        content_length: str | None = None,
        url: str = "http://peer/health",
    ) -> None:
        self.status = status
        self.headers: dict[str, str] = {"Content-Type": content_type}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self.body = body
        self.url = url
        self.read_size: int | None = None

    def __enter__(self) -> FakeUrlResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, size: int) -> bytes:
        self.read_size = size
        return self.body


def _apply_kwargs(artifacts: Artifacts) -> dict[str, Any]:
    return {
        "expected_pre_state_version": artifacts.pre_state.state_version,
        "expected_pre_state_digest": artifacts.pre_state.state_digest,
        "expected_pre_observation_digest": artifacts.pre_state.observation_digest,
        "expected_post_state_digest": artifacts.assessment.post_state.state_digest,
        "expected_post_topology_digest": artifacts.assessment.post_state.topology_digest,
        "authorization_expires_at": artifacts.permit.base_permit.expires_at,
    }


def _plc_client(
    artifacts: Artifacts,
    handler: Any,
    **overrides: Any,
) -> RemotePlcPlantClient:
    values: dict[str, Any] = {
        "plant": artifacts.plant_health,
        "ot": artifacts.ot_health,
        "caller_private_key": artifacts.ot_private,
        "clock": lambda: NOW,
        "nonce_factory": lambda: "m4g-edge-plant-call-nonce-0001",
        "exchange": StubExchange(handler),
    }
    values.update(overrides)
    return RemotePlcPlantClient("http://plant", **values)


def _virtual_plc(
    artifacts: Artifacts,
    handler: Any,
    **overrides: Any,
) -> RemoteVirtualPlcPort:
    values: dict[str, Any] = {
        "ot": artifacts.ot_health,
        "gateway_key_id": GATEWAY_KEY_ID,
        "gateway_private_key": artifacts.gateway_private,
        "clock": lambda: NOW,
        "nonce_factory": lambda: "m4g-edge-gateway-call-nonce-0001",
        "exchange": StubExchange(handler),
    }
    values.update(overrides)
    return RemoteVirtualPlcPort("http://ot", **values)


def _execute(port: RemoteVirtualPlcPort, artifacts: Artifacts) -> Any:
    return port.execute(
        request=artifacts.request,
        permit=artifacts.permit,
        pre_observation=artifacts.pre_observation,
        decision=artifacts.decision,
        assessment=artifacts.assessment,
    )


@pytest.mark.parametrize(
    "url",
    [
        "ftp://peer",
        "http:///missing-host",
        "http://user@peer",
        "http://user:password@peer",
        "http://peer/path?query=1",
        "http://peer/path#fragment",
    ],
)
def test_remote_service_rejects_ambiguous_or_credentialed_urls(url: str) -> None:
    with pytest.raises(ValueError, match=r"HTTP\(S\) URL without credentials"):
        RemoteObservationPort(
            url,
            observer=cast(Any, object()),
            exchange=cast(Any, object()),
        )


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("inf"), float("nan")])
def test_remote_service_requires_positive_finite_timeout(
    artifacts: Artifacts,
    timeout: float,
) -> None:
    with pytest.raises(ValueError, match="positive and finite"):
        RemoteObservationPort(
            "http://observer",
            observer=artifacts.observer_health,
            timeout_seconds=timeout,
        )


def test_urllib_exchange_accepts_one_bounded_nonredirected_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeUrlResponse(body=b'{"status":"ready"}', content_length="18")
    monkeypatch.setattr(transport, "urlopen", lambda *_args, **_kwargs: fake)

    response = urllib_http_exchange(
        method="GET",
        url="http://peer/health",
        body=None,
        headers={"Accept": "application/json"},
        timeout_seconds=1.0,
    )

    assert response.status_code == 200
    assert response.body == b'{"status":"ready"}'
    assert fake.read_size == MAX_JSON_BYTES + 1


def test_urllib_exchange_returns_bounded_http_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = HTTPError(
        "http://peer/health",
        409,
        "conflict",
        {"Content-Type": "application/json", "Content-Length": "2"},
        BytesIO(b"{}"),
    )

    def fail(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(transport, "urlopen", fail)
    response = urllib_http_exchange(
        method="GET",
        url="http://peer/health",
        body=None,
        headers={},
        timeout_seconds=1.0,
    )
    assert (response.status_code, response.body) == (409, b"{}")


def test_urllib_exchange_forbids_redirects_and_unknown_methods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        transport,
        "urlopen",
        lambda *_args, **_kwargs: FakeUrlResponse(url="http://other/health"),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="redirects"):
        urllib_http_exchange(
            method="GET",
            url="http://peer/health",
            body=None,
            headers={},
            timeout_seconds=1.0,
        )
    with pytest.raises(ValueError, match="method is unsupported"):
        urllib_http_exchange(
            method="DELETE",
            url="http://peer/health",
            body=None,
            headers={},
            timeout_seconds=1.0,
        )


@pytest.mark.parametrize(
    "failure",
    [OSError("network down"), TimeoutError("timed out"), URLError("refused")],
)
def test_urllib_exchange_maps_network_failures_to_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr(transport, "urlopen", fail)
    with pytest.raises(CapabilityTransportUnavailable, match="HTTP exchange failed"):
        urllib_http_exchange(
            method="GET",
            url="http://peer/health",
            body=None,
            headers={},
            timeout_seconds=1.0,
        )


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (FakeUrlResponse(content_length="not-an-integer"), "Content-Length is invalid"),
        (FakeUrlResponse(content_length="-1"), "exceeds the JSON size limit"),
        (
            FakeUrlResponse(content_length=str(MAX_JSON_BYTES + 1)),
            "exceeds the JSON size limit",
        ),
        (
            FakeUrlResponse(body=b"x" * (MAX_JSON_BYTES + 1)),
            "exceeds the JSON size limit",
        ),
    ],
)
def test_bounded_response_body_rejects_bad_or_oversize_lengths(
    response: FakeUrlResponse,
    message: str,
) -> None:
    with pytest.raises(CapabilityTransportProtocolError, match=message):
        transport._bounded_body(response)


@pytest.mark.parametrize(
    "body",
    [
        b"\xef\xbb\xbf{}",
        b"\xff",
        b"{",
        b"[]",
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":1,"value":2}',
        b"x" * (MAX_JSON_BYTES + 1),
    ],
)
def test_strict_json_parser_rejects_noncanonical_wire_shapes(body: bytes) -> None:
    with pytest.raises(CapabilityTransportProtocolError):
        transport._strict_json_object(body)


def test_canonical_request_and_model_parser_enforce_bounds_and_schema(
    artifacts: Artifacts,
) -> None:
    with pytest.raises(ValueError, match="request exceeds"):
        transport._canonical_json({"payload": "x" * MAX_JSON_BYTES})

    wrong_schema = HttpExchangeResponse(
        status_code=200,
        content_type="application/json; charset=utf-8",
        body=artifacts.observer_health.model_dump_json().encode(),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="PlantHealthMetadata"):
        transport._parse_model(wrong_schema, PlantHealthMetadata)


@pytest.mark.parametrize(
    ("failure", "consequential", "expected"),
    [
        (
            CapabilityTransportProtocolError("bad wire"),
            False,
            CapabilityTransportProtocolError,
        ),
        (
            CapabilityTransportProtocolError("bad wire"),
            True,
            ConsequentialTransportOutcomeUnknown,
        ),
        (CapabilityTransportUnavailable("down"), False, CapabilityTransportUnavailable),
        (
            CapabilityTransportUnavailable("down"),
            True,
            ConsequentialTransportOutcomeUnknown,
        ),
        (OSError("reset"), False, CapabilityTransportUnavailable),
        (OSError("reset"), True, ConsequentialTransportOutcomeUnknown),
        (
            ConsequentialTransportOutcomeUnknown("already unknown"),
            True,
            ConsequentialTransportOutcomeUnknown,
        ),
    ],
)
def test_raw_exchange_preserves_consequential_uncertainty(
    failure: Exception,
    consequential: bool,
    expected: type[Exception],
) -> None:
    def fail(**_kwargs: object) -> HttpExchangeResponse:
        raise failure

    service = transport._RemoteJsonService("http://peer", exchange=fail)
    with pytest.raises(expected):
        service._raw("GET", "/health", None, consequential=consequential)


@pytest.mark.parametrize("consequential", [False, True])
@pytest.mark.parametrize(
    "response",
    [
        HttpExchangeResponse(True, "application/json", b"{}"),
        HttpExchangeResponse(99, "application/json", b"{}"),
        HttpExchangeResponse(600, "application/json", b"{}"),
        HttpExchangeResponse(200, cast(Any, 1), b"{}"),
        HttpExchangeResponse(200, "application/json", cast(Any, bytearray(b"{}"))),
        HttpExchangeResponse(200, "application/json", b"x" * (MAX_JSON_BYTES + 1)),
    ],
)
def test_raw_exchange_rejects_invalid_adapter_responses(
    response: HttpExchangeResponse,
    consequential: bool,
) -> None:
    service = transport._RemoteJsonService(
        "http://peer",
        exchange=lambda **_kwargs: response,
    )
    expected = (
        ConsequentialTransportOutcomeUnknown if consequential else CapabilityTransportProtocolError
    )
    with pytest.raises(expected, match="invalid response"):
        service._raw("GET", "/health", None, consequential=consequential)


@pytest.mark.parametrize(
    ("response", "consequential", "expected"),
    [
        (
            HttpExchangeResponse(200, "application/json", b"{}"),
            False,
            CapabilityTransportProtocolError,
        ),
        (
            HttpExchangeResponse(200, "application/json", b"{}"),
            True,
            ConsequentialTransportOutcomeUnknown,
        ),
        (
            HttpExchangeResponse(503, "text/plain", b"bad"),
            False,
            CapabilityTransportUnavailable,
        ),
        (
            HttpExchangeResponse(503, "text/plain", b"bad"),
            True,
            ConsequentialTransportOutcomeUnknown,
        ),
        (
            HttpExchangeResponse(409, "text/plain", b"bad"),
            False,
            CapabilityTransportProtocolError,
        ),
        (
            _json_response(
                TransportFailureBody(status="rejected", reason="closed rejection"),
                status_code=409,
            ),
            False,
            CapabilityTransportRejected,
        ),
        (
            _json_response(
                TransportFailureBody(status="error", reason="peer failed"),
                status_code=503,
            ),
            False,
            CapabilityTransportUnavailable,
        ),
        (
            _json_response(
                TransportFailureBody(status="error", reason="outcome unclear"),
                status_code=503,
            ),
            True,
            ConsequentialTransportOutcomeUnknown,
        ),
    ],
)
def test_success_model_maps_wire_status_without_retry(
    response: HttpExchangeResponse,
    consequential: bool,
    expected: type[Exception],
) -> None:
    service = transport._RemoteJsonService(
        "http://peer",
        exchange=lambda **_kwargs: response,
    )
    with pytest.raises(expected):
        service._success_model(
            "GET",
            "/health",
            None,
            PlantHealthMetadata,
            consequential=consequential,
        )


def test_health_models_reject_invalid_keys_counters_and_embedded_plant(
    artifacts: Artifacts,
) -> None:
    short_key = artifacts.plant_health.model_dump(mode="json")
    short_key["public_key_b64"] = "YQ=="
    with pytest.raises(ValidationError, match="exactly 32 bytes"):
        PlantHealthMetadata.model_validate(short_key)

    bad_plant_count = artifacts.plant_health.model_dump(mode="json")
    bad_plant_count.update({"apply_requests": 1, "commit_count": 2})
    with pytest.raises(ValidationError, match="commits cannot exceed"):
        PlantHealthMetadata.model_validate(bad_plant_count)

    duplicate_ot_key = artifacts.ot_health.model_dump(mode="json")
    duplicate_ot_key["gateway_public_key_b64"] = duplicate_ot_key["public_key_b64"]
    with pytest.raises(ValidationError, match="key material must be distinct"):
        OtHealthMetadata.model_validate(duplicate_ot_key)

    bad_scan = artifacts.ot_health.model_dump(mode="json")
    bad_scan.update({"execute_requests": 1, "scan_counter": 2})
    with pytest.raises(ValidationError, match="scan counter"):
        OtHealthMetadata.model_validate(bad_scan)

    inconsistent = artifacts.ot_health.model_dump(mode="json")
    inconsistent["plant"] = artifacts.plant_health.model_copy(
        update={"boot_epoch": "m4g-different-plant-boot-epoch"}
    ).model_dump(mode="json")
    with pytest.raises(ValidationError, match="embedded plant metadata"):
        OtHealthMetadata.model_validate(inconsistent)

    assert len(artifacts.plant_health.public_key.public_bytes_raw()) == 32
    assert len(artifacts.ot_health.gateway_public_key.public_bytes_raw()) == 32
    assert len(artifacts.ot_health.permit_public_key.public_bytes_raw()) == 32


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("observer_model", "0" * 64, "observer reports a different plant model"),
        (
            "observer_boot",
            "m4g-different-observer-boot-epoch",
            "OT reports a different observer boot",
        ),
        ("duplicate_id", OBSERVER_KEY_ID, "signing key IDs must be distinct"),
    ],
)
def test_discovery_rejects_cross_service_identity_inconsistency(
    artifacts: Artifacts,
    field: str,
    value: str,
    message: str,
) -> None:
    observer = artifacts.observer_health
    candidate = artifacts.candidate_health
    ot = artifacts.ot_health
    if field == "observer_model":
        observer = observer.model_copy(update={"plant_model_digest": value})
    elif field == "observer_boot":
        ot = ot.model_copy(update={"observer_boot_epoch": value})
    else:
        candidate = candidate.model_copy(update={"key_id": value})

    with pytest.raises(ValidationError, match=message):
        SegmentedCapabilityDiscovery(
            plant=artifacts.plant_health,
            observer=observer,
            candidate=candidate,
            ot=ot,
        )


def test_discovery_via_ot_uses_embedded_plant_and_checks_gateway_key(
    artifacts: Artifacts,
) -> None:
    ot = artifacts.ot_health.model_copy(update={"plant": artifacts.plant_health})
    health: dict[str, BaseModel] = {
        "ot": ot,
        "observer": artifacts.observer_health,
        "candidate": artifacts.candidate_health,
    }
    seen: list[str] = []

    def handler(method: str, url: str, body: bytes | None) -> HttpExchangeResponse:
        assert method == "GET" and body is None
        host = url.split("//", maxsplit=1)[1].split("/", maxsplit=1)[0]
        seen.append(host)
        return _json_response(health[host])

    discovery = discover_segmented_capabilities_via_ot(
        observer_url="http://observer",
        candidate_url="http://candidate",
        ot_url="http://ot",
        gateway_key_id=GATEWAY_KEY_ID,
        exchange=StubExchange(handler),
    )
    assert discovery.plant == artifacts.plant_health
    assert seen == ["ot", "observer", "candidate"]

    with pytest.raises(ValueError, match="gateway transport key"):
        discover_segmented_capabilities_via_ot(
            observer_url="http://observer",
            candidate_url="http://candidate",
            ot_url="http://ot",
            gateway_key_id="wrong-gateway-key",
            exchange=StubExchange(handler),
        )


def test_discovery_via_ot_fails_when_ot_omits_plant(artifacts: Artifacts) -> None:
    stub = StubExchange(lambda *_: _json_response(artifacts.ot_health))
    with pytest.raises(CapabilityTransportProtocolError, match="omitted the plant metadata"):
        discover_segmented_capabilities_via_ot(
            observer_url="http://observer",
            candidate_url="http://candidate",
            ot_url="http://ot",
            gateway_key_id=GATEWAY_KEY_ID,
            exchange=stub,
        )
    assert len(stub.calls) == 1


def test_remote_health_revalidation_accepts_counters_but_rejects_identity_drift(
    artifacts: Artifacts,
) -> None:
    observer_dynamic = artifacts.observer_health.model_copy(update={"capture_count": 99})
    observer = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(lambda *_: _json_response(observer_dynamic)),
    )
    assert observer.health().capture_count == 99

    candidate_dynamic = artifacts.candidate_health.model_copy(update={"simulation_count": 9})
    candidate = RemoteCandidatePort(
        "http://candidate",
        candidate=artifacts.candidate_health,
        plant=artifacts.plant_health,
        exchange=StubExchange(lambda *_: _json_response(candidate_dynamic)),
    )
    assert candidate.health().simulation_count == 9

    plant_dynamic = artifacts.plant_health.model_copy(update={"call_reservations": 7})
    plant = RemoteCandidatePlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        candidate=artifacts.candidate_health,
        caller_private_key=artifacts.candidate_private,
        exchange=StubExchange(lambda *_: _json_response(plant_dynamic)),
    )
    assert plant.health().call_reservations == 7

    ot_dynamic = artifacts.ot_health.model_copy(update={"execute_requests": 7})
    ot = _virtual_plc(artifacts, lambda *_: _json_response(ot_dynamic))
    assert ot.health().execute_requests == 7

    observer_drift = artifacts.observer_health.model_copy(
        update={"boot_epoch": "m4g-observer-replacement-epoch"}
    )
    observer = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(lambda *_: _json_response(observer_drift)),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="observer health identity"):
        observer.health()

    candidate_drift = artifacts.candidate_health.model_copy(
        update={"boot_epoch": "m4g-candidate-replacement-epoch"}
    )
    candidate = RemoteCandidatePort(
        "http://candidate",
        candidate=artifacts.candidate_health,
        plant=artifacts.plant_health,
        exchange=StubExchange(lambda *_: _json_response(candidate_drift)),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="candidate health identity"):
        candidate.health()

    plant_drift = artifacts.plant_health.model_copy(update={"backend": "other-backend"})
    plant = RemoteCandidatePlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        candidate=artifacts.candidate_health,
        caller_private_key=artifacts.candidate_private,
        exchange=StubExchange(lambda *_: _json_response(plant_drift)),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="plant health identity"):
        plant.health()

    ot_drift = artifacts.ot_health.model_copy(
        update={"boot_epoch": "m4g-ot-replacement-boot-epoch"}
    )
    ot = _virtual_plc(artifacts, lambda *_: _json_response(ot_drift))
    with pytest.raises(CapabilityTransportProtocolError, match="OT health identity"):
        ot.health()


def test_ot_health_revalidation_compares_embedded_plant_identity(
    artifacts: Artifacts,
) -> None:
    expected = artifacts.ot_health.model_copy(update={"plant": artifacts.plant_health})
    current = expected.model_copy(
        update={
            "plant": artifacts.plant_health.model_copy(update={"backend": "identity-drift-backend"})
        }
    )
    stable = _virtual_plc(
        artifacts,
        lambda *_: _json_response(expected),
        ot=expected,
    )
    assert stable.health().plant == artifacts.plant_health

    drifted = _virtual_plc(
        artifacts,
        lambda *_: _json_response(current),
        ot=expected,
    )
    with pytest.raises(CapabilityTransportProtocolError, match="OT health identity"):
        drifted.health()

    unexpectedly_embedded = _virtual_plc(
        artifacts,
        lambda *_: _json_response(expected),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="OT health identity"):
        unexpectedly_embedded.health()


def test_observation_requests_validate_inputs_and_exact_response_bindings(
    artifacts: Artifacts,
) -> None:
    port = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(lambda *_: _json_response(artifacts.pre_observation)),
    )
    with pytest.raises(ValueError, match="resolution binding"):
        port.resolve(observation_id="", envelope_digest="not-a-digest")
    with pytest.raises(ValueError, match="pre-observation request"):
        port.capture_pre(correlation_id="", challenge_nonce="short")
    with pytest.raises(ValueError, match="post-observation request"):
        port.capture_post(
            correlation_id="",
            challenge_nonce="short",
            previous_envelope_digest="bad",
            permit_id="",
            command_digest="bad",
            plc_acknowledgment_digest="bad",
        )

    with pytest.raises(CapabilityTransportProtocolError, match="resolved observation binding"):
        port.resolve(
            observation_id="different-observation-id",
            envelope_digest=artifacts.pre_observation.envelope_digest,
        )

    post_port = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(lambda *_: _json_response(artifacts.post_observation)),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="post-observation response"):
        post_port.capture_post(
            correlation_id=artifacts.post_observation.correlation_id,
            challenge_nonce="m4g-different-post-challenge-0001",
            previous_envelope_digest=artifacts.pre_observation.envelope_digest,
            permit_id=artifacts.permit.base_permit.permit_id,
            command_digest=artifacts.command.digest,
            plc_acknowledgment_digest=artifacts.acknowledgment.digest,
        )


def test_observation_rejects_signed_artifact_from_wrong_plant_model(
    artifacts: Artifacts,
) -> None:
    observer = artifacts.observer_health.model_copy(update={"plant_model_digest": "0" * 64})
    port = RemoteObservationPort(
        "http://observer",
        observer=observer,
        exchange=StubExchange(lambda *_: _json_response(artifacts.pre_observation)),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="identity, plant, or signature"):
        port.resolve(
            observation_id=artifacts.pre_observation.observation_id,
            envelope_digest=artifacts.pre_observation.envelope_digest,
        )


def test_candidate_constructor_and_response_reject_dependency_drift(
    artifacts: Artifacts,
) -> None:
    mismatched_candidate = artifacts.candidate_health.model_copy(
        update={"plant_boot_epoch": "m4g-different-plant-boot-epoch"}
    )
    with pytest.raises(ValueError, match="candidate discovery"):
        RemoteCandidatePort(
            "http://candidate",
            candidate=mismatched_candidate,
            plant=artifacts.plant_health,
        )

    rejected_exchange = _candidate_exchange(artifacts)
    rejection = SignedPlantResponse.issue(
        call=rejected_exchange.call,
        status=PlantResponseStatus.REJECTED,
        payload=PlantFailureResponsePayload(
            status=PlantResponseStatus.REJECTED,
            reason="candidate simulation rejected",
        ),
        plant_boot_epoch=PLANT_BOOT,
        plant_key_id=PLANT_KEY_ID,
        signed_at=NOW,
        private_key=artifacts.plant_private,
    )
    port = RemoteCandidatePort(
        "http://candidate",
        candidate=artifacts.candidate_health,
        plant=artifacts.plant_health,
        clock=lambda: NOW,
        exchange=StubExchange(
            lambda *_: _json_response(
                PlantExchange(call=rejected_exchange.call, response=rejection)
            )
        ),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="successful simulation"):
        port.simulate_candidate(artifacts.command)

    different_model = "0" * 64
    plant = artifacts.plant_health.model_copy(update={"model_digest": different_model})
    candidate = artifacts.candidate_health.model_copy(
        update={"plant_model_digest": different_model}
    )
    port = RemoteCandidatePort(
        "http://candidate",
        candidate=candidate,
        plant=plant,
        clock=lambda: NOW,
        exchange=StubExchange(lambda *_: _json_response(_candidate_exchange(artifacts))),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="response binding"):
        port.simulate_candidate(artifacts.command)


def test_client_constructors_reject_wrong_keys_dependencies_and_ttls(
    artifacts: Artifacts,
) -> None:
    wrong_private, _ = generate_keypair()
    observer_drift = artifacts.observer_health.model_copy(
        update={"plant_boot_epoch": "m4g-other-plant-boot-epoch"}
    )
    candidate_drift = artifacts.candidate_health.model_copy(update={"plant_model_digest": "0" * 64})
    ot_drift = artifacts.ot_health.model_copy(
        update={"plant_boot_epoch": "m4g-other-plant-boot-epoch"}
    )

    with pytest.raises(ValueError, match="observer discovery"):
        RemoteObserverPlantClient(
            "http://plant",
            plant=artifacts.plant_health,
            observer=observer_drift,
            caller_private_key=artifacts.observer_private,
        )
    with pytest.raises(ValueError, match="observer plant-call private key"):
        RemoteObserverPlantClient(
            "http://plant",
            plant=artifacts.plant_health,
            observer=artifacts.observer_health,
            caller_private_key=wrong_private,
        )
    with pytest.raises(ValueError, match="candidate discovery"):
        RemoteCandidatePlantClient(
            "http://plant",
            plant=artifacts.plant_health,
            candidate=candidate_drift,
            caller_private_key=artifacts.candidate_private,
        )
    with pytest.raises(ValueError, match="candidate plant-call private key"):
        RemoteCandidatePlantClient(
            "http://plant",
            plant=artifacts.plant_health,
            candidate=artifacts.candidate_health,
            caller_private_key=wrong_private,
        )
    with pytest.raises(ValueError, match="PLC discovery"):
        RemotePlcPlantClient(
            "http://plant",
            plant=artifacts.plant_health,
            ot=ot_drift,
            caller_private_key=artifacts.ot_private,
        )
    with pytest.raises(ValueError, match="PLC plant-call private key"):
        RemotePlcPlantClient(
            "http://plant",
            plant=artifacts.plant_health,
            ot=artifacts.ot_health,
            caller_private_key=wrong_private,
        )

    observer_reused_id = artifacts.observer_health.model_copy(
        update={"key_id": artifacts.plant_health.key_id}
    )
    with pytest.raises(ValueError, match="caller and response keys must be distinct"):
        RemoteObserverPlantClient(
            "http://plant",
            plant=artifacts.plant_health,
            observer=observer_reused_id,
            caller_private_key=artifacts.observer_private,
        )

    with pytest.raises(ValueError, match="gateway transport key"):
        RemoteVirtualPlcPort(
            "http://ot",
            ot=artifacts.ot_health,
            gateway_key_id=OT_KEY_ID,
            gateway_private_key=artifacts.gateway_private,
        )
    with pytest.raises(ValueError, match="registered bound"):
        RemoteVirtualPlcPort(
            "http://ot",
            ot=artifacts.ot_health,
            gateway_key_id=GATEWAY_KEY_ID,
            gateway_private_key=artifacts.gateway_private,
            call_ttl=timedelta(0),
        )
    with pytest.raises(ValueError, match="registered bound"):
        RemoteCandidatePlantClient(
            "http://plant",
            plant=artifacts.plant_health,
            candidate=artifacts.candidate_health,
            caller_private_key=artifacts.candidate_private,
            call_ttl=transport.MAX_SIGNED_CALL_TTL + timedelta(microseconds=1),
        )


def test_remote_virtual_plc_rejects_invalid_nonce_before_network(
    artifacts: Artifacts,
) -> None:
    stub = StubExchange(lambda *_: pytest.fail("network must not be called"))
    port = _virtual_plc(artifacts, stub.handler, nonce_factory=lambda: "short")
    with pytest.raises(ValueError, match="transport nonce"):
        _execute(port, artifacts)
    assert stub.calls == []


@pytest.mark.parametrize(
    ("response", "expected", "message"),
    [
        (
            HttpExchangeResponse(503, "text/plain", b"offline"),
            ConsequentialTransportOutcomeUnknown,
            "server failure",
        ),
        (
            HttpExchangeResponse(409, "text/plain", b"invalid rejection"),
            ConsequentialTransportOutcomeUnknown,
            "unverifiable",
        ),
        (
            _json_response(
                TransportFailureBody(status="rejected", reason="not authorized"),
                status_code=409,
            ),
            CapabilityTransportRejected,
            "not authorized",
        ),
        (
            _json_response(
                TransportFailureBody(status="error", reason="adapter fault"),
                status_code=409,
            ),
            ConsequentialTransportOutcomeUnknown,
            "adapter fault",
        ),
        (
            HttpExchangeResponse(302, "application/json", b"{}"),
            ConsequentialTransportOutcomeUnknown,
            "invalid HTTP status",
        ),
        (
            HttpExchangeResponse(200, "application/json", b"{}"),
            ConsequentialTransportOutcomeUnknown,
            "valid signed artifact",
        ),
    ],
)
def test_virtual_plc_distinguishes_closed_rejection_from_unknown_outcome(
    artifacts: Artifacts,
    response: HttpExchangeResponse,
    expected: type[Exception],
    message: str,
) -> None:
    port = _virtual_plc(artifacts, lambda *_: response)
    with pytest.raises(expected, match=message):
        _execute(port, artifacts)


def test_gateway_private_key_mismatch_fails_before_network(
    artifacts: Artifacts,
) -> None:
    wrong_private, _ = generate_keypair()
    stub = StubExchange(lambda *_: pytest.fail("network must not be called"))
    with pytest.raises(ValueError, match="gateway private key"):
        _virtual_plc(
            artifacts,
            stub.handler,
            gateway_private_key=wrong_private,
        )
    assert stub.calls == []


def test_virtual_plc_rejects_tampered_signed_ot_response(
    artifacts: Artifacts,
) -> None:
    def handler(_method: str, _url: str, body: bytes | None) -> HttpExchangeResponse:
        assert body is not None
        request = SignedSegmentedCapabilityDispatch.model_validate_json(body)
        response = SignedSegmentedCapabilityResponse.issue(
            request=request,
            acknowledgment=artifacts.acknowledgment,
            ot_key_id=OT_KEY_ID,
            signed_at=NOW,
            private_key=artifacts.ot_private,
        )
        return _json_response(response.model_copy(update={"signature": "tampered"}))

    with pytest.raises(ConsequentialTransportOutcomeUnknown, match="signature or transaction"):
        _execute(_virtual_plc(artifacts, handler), artifacts)


def _plant_handler_with_response(
    artifacts: Artifacts,
    *,
    status: PlantResponseStatus = PlantResponseStatus.OK,
    http_status: int = 200,
    tamper_signature: bool = False,
) -> Any:
    def handler(_method: str, _url: str, body: bytes | None) -> HttpExchangeResponse:
        assert body is not None
        call = SignedPlantCall.model_validate_json(body)
        response = _plant_exchange(artifacts, call, status=status).response
        if tamper_signature:
            response = response.model_copy(update={"signature": "tampered"})
        return _json_response(response, status_code=http_status)

    return handler


@pytest.mark.parametrize("consequential", [False, True])
def test_plant_response_tamper_is_protocol_error_or_unknown_outcome(
    artifacts: Artifacts,
    consequential: bool,
) -> None:
    client = _plc_client(
        artifacts,
        _plant_handler_with_response(artifacts, tamper_signature=True),
    )
    expected = (
        ConsequentialTransportOutcomeUnknown if consequential else CapabilityTransportProtocolError
    )
    with pytest.raises(expected, match="signature, identity, time, or call binding"):
        if consequential:
            client.apply_authorized_command(artifacts.command, **_apply_kwargs(artifacts))
        else:
            client.read_state()


@pytest.mark.parametrize("consequential", [False, True])
def test_malformed_plant_response_is_protocol_error_or_unknown_outcome(
    artifacts: Artifacts,
    consequential: bool,
) -> None:
    client = _plc_client(
        artifacts,
        lambda *_: HttpExchangeResponse(200, "application/json", b"{}"),
    )
    expected = (
        ConsequentialTransportOutcomeUnknown if consequential else CapabilityTransportProtocolError
    )
    with pytest.raises(expected, match="plant apply response|SignedPlantResponse"):
        if consequential:
            client.apply_authorized_command(artifacts.command, **_apply_kwargs(artifacts))
        else:
            client.read_state()


@pytest.mark.parametrize("consequential", [False, True])
def test_plant_http_rejection_requires_signed_rejected_status(
    artifacts: Artifacts,
    consequential: bool,
) -> None:
    client = _plc_client(
        artifacts,
        _plant_handler_with_response(artifacts, http_status=409),
    )
    expected = (
        ConsequentialTransportOutcomeUnknown if consequential else CapabilityTransportProtocolError
    )
    with pytest.raises(expected, match="does not carry a signed rejection"):
        if consequential:
            client.apply_authorized_command(artifacts.command, **_apply_kwargs(artifacts))
        else:
            client.read_state()


@pytest.mark.parametrize("consequential", [False, True])
def test_plant_ambiguous_status_preserves_effect_uncertainty(
    artifacts: Artifacts,
    consequential: bool,
) -> None:
    client = _plc_client(
        artifacts,
        _plant_handler_with_response(artifacts, http_status=302),
    )
    expected = (
        ConsequentialTransportOutcomeUnknown if consequential else CapabilityTransportUnavailable
    )
    with pytest.raises(expected, match="ambiguous HTTP status|unavailable status"):
        if consequential:
            client.apply_authorized_command(artifacts.command, **_apply_kwargs(artifacts))
        else:
            client.read_state()


@pytest.mark.parametrize("consequential", [False, True])
def test_signed_plant_error_preserves_effect_uncertainty(
    artifacts: Artifacts,
    consequential: bool,
) -> None:
    client = _plc_client(
        artifacts,
        _plant_handler_with_response(artifacts, status=PlantResponseStatus.ERROR),
    )
    expected = (
        ConsequentialTransportOutcomeUnknown if consequential else CapabilityTransportUnavailable
    )
    with pytest.raises(expected, match="known_remote_rejection"):
        if consequential:
            client.apply_authorized_command(artifacts.command, **_apply_kwargs(artifacts))
        else:
            client.read_state()


def test_signed_plant_rejection_is_known_for_nonconsequential_call(
    artifacts: Artifacts,
) -> None:
    client = _plc_client(
        artifacts,
        _plant_handler_with_response(
            artifacts,
            status=PlantResponseStatus.REJECTED,
            http_status=409,
        ),
    )
    with pytest.raises(RemotePhysicalRejection, match="known_remote_rejection"):
        client.read_state()


def test_plant_capture_and_apply_require_complete_local_bindings(
    artifacts: Artifacts,
) -> None:
    observer = RemoteObserverPlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        observer=artifacts.observer_health,
        caller_private_key=artifacts.observer_private,
        clock=lambda: NOW,
        exchange=StubExchange(_plant_handler_with_response(artifacts)),
    )
    assert observer.capture_state() == artifacts.pre_state
    with pytest.raises(ValueError, match="plant capture binding"):
        observer.capture_bound_state(correlation_id="", challenge_nonce="short")

    plc = _plc_client(artifacts, _plant_handler_with_response(artifacts))
    with pytest.raises(RemotePhysicalRejection, match="plant_apply_bindings_required"):
        plc.apply_authorized_command(artifacts.command)

    assert (
        plc.apply_authorized_command_with_deadline(
            artifacts.command,
            expected_pre_state_version=artifacts.pre_state.state_version,
            expected_pre_state_digest=artifacts.pre_state.state_digest,
            expected_pre_observation_digest=artifacts.pre_state.observation_digest,
            expected_post_state_digest=artifacts.assessment.post_state.state_digest,
            expected_post_topology_digest=artifacts.assessment.post_state.topology_digest,
            authorization_expires_at=artifacts.permit.base_permit.expires_at,
        )
        == artifacts.assessment.post_state
    )


def test_plant_client_rejects_invalid_nonce_before_network(artifacts: Artifacts) -> None:
    stub = StubExchange(lambda *_: pytest.fail("network must not be called"))
    client = _plc_client(
        artifacts,
        stub.handler,
        nonce_factory=lambda: cast(Any, None),
    )
    with pytest.raises(ValueError, match="transport nonce"):
        client.read_state()
    assert stub.calls == []


def test_candidate_and_plc_simulation_return_verified_assessment(
    artifacts: Artifacts,
) -> None:
    handler = _plant_handler_with_response(artifacts)
    candidate = RemoteCandidatePlantClient(
        "http://plant",
        plant=artifacts.plant_health,
        candidate=artifacts.candidate_health,
        caller_private_key=artifacts.candidate_private,
        clock=lambda: NOW,
        exchange=StubExchange(handler),
    )
    plc = _plc_client(artifacts, handler)
    assert candidate.simulate_candidate(artifacts.command) == artifacts.assessment
    assert plc.simulate_candidate(artifacts.command) == artifacts.assessment


def test_strict_response_parser_rejects_non_object_observation_payload(
    artifacts: Artifacts,
) -> None:
    port = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(lambda *_: HttpExchangeResponse(200, "application/json", b"[]")),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="root must be an object"):
        port.resolve(
            observation_id=artifacts.pre_observation.observation_id,
            envelope_digest=artifacts.pre_observation.envelope_digest,
        )


def test_valid_observation_phase_is_cryptographically_bound(artifacts: Artifacts) -> None:
    post_as_pre = SignedObservationEnvelope.issue(
        snapshot=artifacts.pre_state,
        correlation_id=artifacts.pre_observation.correlation_id,
        phase=ObservationPhase.POST_DISPATCH,
        challenge_nonce=artifacts.pre_observation.challenge_nonce,
        observer_id=artifacts.pre_observation.observer_id,
        observer_key_id=artifacts.pre_observation.observer_key_id,
        observer_boot_epoch=artifacts.pre_observation.observer_boot_epoch,
        observer_sequence=3,
        previous_envelope_digest=artifacts.pre_observation.envelope_digest,
        permit_id=artifacts.permit.base_permit.permit_id,
        command_digest=artifacts.command.digest,
        plc_acknowledgment_digest=artifacts.acknowledgment.digest,
        private_key=artifacts.observer_private,
    )
    port = RemoteObservationPort(
        "http://observer",
        observer=artifacts.observer_health,
        exchange=StubExchange(lambda *_: _json_response(post_as_pre)),
    )
    with pytest.raises(CapabilityTransportProtocolError, match="pre-observation response"):
        port.capture_pre(
            correlation_id=artifacts.pre_observation.correlation_id,
            challenge_nonce=artifacts.pre_observation.challenge_nonce,
        )


def test_unmatched_gateway_key_id_is_rejected_by_discovery(artifacts: Artifacts) -> None:
    discovery = SegmentedCapabilityDiscovery(
        plant=artifacts.plant_health,
        observer=artifacts.observer_health,
        candidate=artifacts.candidate_health,
        ot=artifacts.ot_health,
    )
    with pytest.raises(ValueError, match="gateway transport key"):
        discovery.require_distinct_gateway_key("")


def test_private_key_match_helper_distinguishes_keys(artifacts: Artifacts) -> None:
    other: Ed25519PrivateKey
    other, _ = generate_keypair()
    assert transport._private_key_matches(
        artifacts.ot_private,
        artifacts.ot_health.public_key,
    )
    assert not transport._private_key_matches(other, artifacts.ot_health.public_key)


def test_sha256_shape_check_rejects_nonstring_uppercase_and_wrong_length() -> None:
    assert transport._is_sha256("0" * 64)
    assert not transport._is_sha256(cast(Any, 1))
    assert not transport._is_sha256("A" * 64)
    assert not transport._is_sha256("0" * 63)


def test_signed_plant_response_helper_preserves_exact_exchange(
    artifacts: Artifacts,
) -> None:
    call = SignedPlantCall.issue(
        role=PlantCallerRole.CANDIDATE,
        operation=PlantOperation.SIMULATE,
        payload=PlantSimulatePayload(command=artifacts.command),
        caller_key_id=CANDIDATE_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        call_nonce="m4g-edge-candidate-call-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=15),
        private_key=artifacts.candidate_private,
        audience=PHYSICAL_PLANT_AUDIENCE,
    )
    response = SignedPlantResponse.issue(
        call=call,
        status=PlantResponseStatus.OK,
        payload=PlantSimulationResponsePayload(assessment=artifacts.assessment),
        plant_boot_epoch=PLANT_BOOT,
        plant_key_id=PLANT_KEY_ID,
        signed_at=NOW,
        private_key=artifacts.plant_private,
    )
    assert PlantExchange(call=call, response=response).bindings_match()
