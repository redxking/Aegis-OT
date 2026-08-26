from __future__ import annotations

import http.client
import ssl
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from test_m4i_coordination_transport import (
    _ARTIFACT_FACTORY,
    M4iArtifacts,
    _port_harness,
)
from test_spire_mtls import (
    GATEWAY_ID,
    OBSERVER_ID,
    _boundary,
    _identity,
    _root,
)

import aegis_ot.segmented_capability_transport as transport
import aegis_ot.spire_mtls as spire_mtls
from aegis_ot.coordination_journal import (
    CoordinationCollisionError,
    CoordinationJournalError,
)
from aegis_ot.coordination_models import CoordinationState, EffectDisposition
from aegis_ot.coordination_recovery import (
    CoordinationRecoveryReason,
    CoordinationRecoveryStatus,
)
from aegis_ot.segmented_capability_transport import (
    MAX_JSON_BYTES,
    CapabilityPreDispatchUnavailable,
    CapabilityTransportProtocolError,
    CapabilityTransportRejected,
    CapabilityTransportUnavailable,
    ConsequentialTransportOutcomeUnknown,
    CoordinatedWorkloadRemoteVirtualPlcPort,
    HttpExchangeResponse,
    OtCoordinationRecoveryMetadata,
    TransportFailureBody,
    WorkloadRemoteVirtualPlcPort,
)
from aegis_ot.spire_mtls import (
    SpireMtlsError,
    SpireMtlsHttpExchange,
    TemporaryKeyMaterialBoundary,
)
from aegis_ot.spire_workload_identity import WorkloadIdentityError
from aegis_ot.workload_identity import (
    WorkloadCredentialRejected,
    WorkloadIdentityUnavailable,
    WorkloadRole,
)


@pytest.fixture
def m4i_artifacts(tmp_path: Path) -> M4iArtifacts:
    return _ARTIFACT_FACTORY(tmp_path)


def _recovery_projection(**updates: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "status": CoordinationRecoveryStatus.ALIGNED,
        "reason": CoordinationRecoveryReason.ALIGNED_EMPTY_BASELINE,
        "record_count": 0,
        "applied_effect_count": 0,
        "pending_effect_count": 0,
        "plant_model_digest": "1" * 64,
        "plant_state_version": 0,
        "plant_state_digest": "2" * 64,
    }
    values.update(updates)
    return values


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        (
            {"record_count": 0, "applied_effect_count": 1},
            "counts are inconsistent",
        ),
        (
            {"record_count": 1, "applied_effect_count": 1},
            "applied projection is inconsistent",
        ),
        (
            {"record_count": 1, "pending_effect_count": 1},
            "pending projection is inconsistent",
        ),
        (
            {"live_commit_armed": True},
            "live commit marker",
        ),
    ],
)
def test_recovery_projection_rejects_internally_inconsistent_evidence(
    updates: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        OtCoordinationRecoveryMetadata.model_validate(_recovery_projection(**updates))


class _Response:
    def __init__(self, content_length: str | None, body: bytes) -> None:
        self.content_length = content_length
        self.body = body

    def getheader(self, name: str, default: str | None = None) -> str | None:
        assert name == "Content-Length"
        return self.content_length if self.content_length is not None else default

    def read(self, size: int) -> bytes:
        assert size == MAX_JSON_BYTES + 1
        return self.body


@pytest.mark.parametrize("declared", ["invalid", "-1", str(MAX_JSON_BYTES + 1)])
def test_mtls_response_body_rejects_invalid_or_oversized_length(declared: str) -> None:
    with pytest.raises(CapabilityTransportProtocolError):
        spire_mtls._bounded_response_body(  # noqa: SLF001
            cast(http.client.HTTPResponse, _Response(declared, b"{}"))
        )


def test_mtls_response_body_rejects_undeclared_oversized_material() -> None:
    with pytest.raises(CapabilityTransportProtocolError, match="size limit"):
        spire_mtls._bounded_response_body(  # noqa: SLF001
            cast(http.client.HTTPResponse, _Response(None, b"x" * (MAX_JSON_BYTES + 1)))
        )


def test_temporary_key_boundary_rejects_path_and_identity_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="absolute"):
        TemporaryKeyMaterialBoundary(Path("relative"))
    with pytest.raises(SpireMtlsError, match="unavailable"):
        TemporaryKeyMaterialBoundary(tmp_path / "missing")

    root = tmp_path / "owned"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    monkeypatch.setattr(spire_mtls.os, "geteuid", lambda: root.stat().st_uid + 1)
    with pytest.raises(SpireMtlsError, match="not owned"):
        TemporaryKeyMaterialBoundary(root)
    monkeypatch.undo()

    boundary = TemporaryKeyMaterialBoundary(root)
    original = root.stat()
    changed = SimpleNamespace(st_dev=original.st_dev, st_ino=original.st_ino + 1)
    monkeypatch.setattr(boundary, "_validate_root", lambda _root: changed)
    with pytest.raises(SpireMtlsError, match="changed after validation"):
        with boundary.paths(cast(Any, object())):
            raise AssertionError("substituted roots must fail before key material is written")


def test_temporary_key_boundary_maps_filesystem_failure_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _boundary(tmp_path / "private")

    class BrokenTemporaryDirectory:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise OSError("filesystem unavailable")

    monkeypatch.setattr(spire_mtls.tempfile, "TemporaryDirectory", BrokenTemporaryDirectory)
    with pytest.raises(SpireMtlsError, match="handled safely"):
        with boundary.paths(cast(Any, object())):
            raise AssertionError("no paths can be exposed after a filesystem failure")


def test_peer_certificate_failures_are_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SpireMtlsError, match="did not present"):
        spire_mtls.peer_spiffe_id(b"")
    with pytest.raises(SpireMtlsError, match="no usable SAN"):
        spire_mtls.peer_spiffe_id(b"not-a-certificate")

    class FakeSan:
        def get_values_for_type(self, _kind: object) -> list[str]:
            return ["https://not-a-spiffe-id"]

    class FakeExtensions:
        def get_extension_for_oid(self, _oid: object) -> SimpleNamespace:
            return SimpleNamespace(value=FakeSan())

    monkeypatch.setattr(
        spire_mtls.x509,
        "load_der_x509_certificate",
        lambda _material: SimpleNamespace(extensions=FakeExtensions()),
    )
    with pytest.raises(SpireMtlsError, match="not a valid SPIFFE ID"):
        spire_mtls.peer_spiffe_id(b"synthetic-certificate")


def test_empty_trust_bundle_and_invalid_key_loading_fail_closed(
    tmp_path: Path,
) -> None:
    identity = SimpleNamespace(trust_bundle=SimpleNamespace(x509_authorities=set()))
    with pytest.raises(SpireMtlsError, match="no X.509 authorities"):
        spire_mtls._trust_bundle_pem(cast(Any, identity))  # noqa: SLF001

    @contextmanager
    def key_paths(_identity: object) -> Iterator[tuple[Path, Path]]:
        yield tmp_path / "certificate", tmp_path / "private-key"

    context = SimpleNamespace(
        load_cert_chain=lambda **_kwargs: (_ for _ in ()).throw(ValueError("invalid PEM"))
    )
    boundary = SimpleNamespace(paths=key_paths)
    with pytest.raises(SpireMtlsError, match="unable to load"):
        spire_mtls._load_certificate_chain(  # noqa: SLF001
            cast(ssl.SSLContext, context),
            cast(Any, object()),
            cast(TemporaryKeyMaterialBoundary, boundary),
        )


@pytest.mark.parametrize("factory", [spire_mtls.client_ssl_context, spire_mtls.server_ssl_context])
def test_tls_context_rejects_unloadable_trust_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    factory: Any,
) -> None:
    now = datetime.now(tz=UTC)
    root_key, root = _root(now)
    identity = _identity(GATEWAY_ID, root_key=root_key, root=root, now=now)

    class RejectingContext:
        options = 0

        def __init__(self, _protocol: object) -> None:
            self.check_hostname = True
            self.verify_mode = ssl.CERT_NONE
            self.minimum_version: ssl.TLSVersion | None = None
            self.maximum_version: ssl.TLSVersion | None = None

        def set_alpn_protocols(self, _protocols: list[str]) -> None:
            return None

        def load_verify_locations(self, *, cadata: str) -> None:
            assert "BEGIN CERTIFICATE" in cadata
            raise ValueError("trust material rejected")

    monkeypatch.setattr(spire_mtls.ssl, "SSLContext", RejectingContext)
    expected = (
        "client trust bundle" if factory is spire_mtls.client_ssl_context else "server trust bundle"
    )
    with pytest.raises(SpireMtlsError, match=expected):
        factory(identity, key_boundary=_boundary(tmp_path / "keys"))


def test_https_connection_rejects_non_tls_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    class PlainSocket:
        def close(self) -> None:
            return None

    monkeypatch.setattr(
        http.client.HTTPSConnection,
        "connect",
        lambda connection: setattr(connection, "sock", PlainSocket()),
    )
    connection = spire_mtls._IdentityVerifyingHttpsConnection(  # noqa: SLF001
        "peer",
        port=443,
        timeout=1.0,
        context=ssl.create_default_context(),
        expected_peer_id=OBSERVER_ID,
    )
    with pytest.raises(SpireMtlsError, match="did not establish TLS"):
        connection.connect()


@pytest.mark.parametrize(
    "url",
    [
        "http://observer/health",
        "https:///health",
        "https://user@observer/health",
        "https://observer/health?query=1",
        "https://observer/health#fragment",
    ],
)
def test_mtls_target_rejects_downgraded_or_ambiguous_urls(url: str) -> None:
    with pytest.raises(CapabilityTransportProtocolError, match="must be HTTPS"):
        spire_mtls._https_target(url)  # noqa: SLF001


class _IdentitySource:
    def __init__(self, result: object) -> None:
        self.result = result

    def fetch_and_verify(self) -> Any:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _mtls_exchange(source: object, boundary: TemporaryKeyMaterialBoundary) -> SpireMtlsHttpExchange:
    return SpireMtlsHttpExchange(
        identity_source=cast(Any, _IdentitySource(source)),
        expected_peer_ids={"observer": OBSERVER_ID},
        key_boundary=boundary,
    )


@pytest.mark.parametrize("hostname", ["Observer", " observer", "observer:443", "observer/path"])
def test_mtls_peer_map_requires_normalized_hostnames(
    tmp_path: Path,
    hostname: str,
) -> None:
    with pytest.raises(ValueError, match="normalized host names"):
        SpireMtlsHttpExchange(
            identity_source=cast(Any, _IdentitySource(object())),
            expected_peer_ids={hostname: OBSERVER_ID},
            key_boundary=_boundary(tmp_path / "keys"),
        )


def test_mtls_exchange_validates_method_timeout_and_current_identity(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path / "keys")
    with pytest.raises(ValueError, match="at least one"):
        SpireMtlsHttpExchange(
            identity_source=cast(Any, _IdentitySource(object())),
            expected_peer_ids={},
            key_boundary=boundary,
        )
    exchange = _mtls_exchange(WorkloadIdentityError("SPIRE unavailable"), boundary)
    with pytest.raises(ValueError, match="method"):
        exchange(method="DELETE", url="https://observer", body=None, headers={}, timeout_seconds=1)
    with pytest.raises(ValueError, match="positive and finite"):
        exchange(method="GET", url="https://observer", body=None, headers={}, timeout_seconds=0)
    with pytest.raises(CapabilityTransportUnavailable, match="identity is unavailable"):
        exchange(method="GET", url="https://observer", body=None, headers={}, timeout_seconds=1)


def test_mtls_exchange_preserves_protocol_failure_and_closes_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(tz=UTC)
    root_key, root = _root(now)
    identity = _identity(GATEWAY_ID, root_key=root_key, root=root, now=now)
    closed: list[bool] = []

    class FailingConnection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def request(self, *_args: Any, **_kwargs: Any) -> None:
            raise CapabilityTransportProtocolError("oversized peer response")

        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(spire_mtls, "client_ssl_context", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(spire_mtls, "_IdentityVerifyingHttpsConnection", FailingConnection)
    exchange = _mtls_exchange(identity, _boundary(tmp_path / "keys"))
    with pytest.raises(CapabilityTransportProtocolError, match="oversized"):
        exchange(method="GET", url="https://observer", body=None, headers={}, timeout_seconds=1)
    assert closed == [True]


@pytest.mark.parametrize(
    "raw",
    [None, "[]", "{}", '{"observer": 1}'],
)
def test_environment_peer_map_rejects_missing_or_non_string_contract(
    monkeypatch: pytest.MonkeyPatch,
    raw: str | None,
) -> None:
    if raw is None:
        monkeypatch.delenv("AEGIS_SPIFFE_PEER_IDS", raising=False)
    else:
        monkeypatch.setenv("AEGIS_SPIFFE_PEER_IDS", raw)
    with pytest.raises(ValueError, match="AEGIS_SPIFFE_PEER_IDS"):
        spire_mtls._peer_map_from_environment()  # noqa: SLF001


def test_server_protocol_rejects_plaintext_before_uvicorn() -> None:
    protocol_type = spire_mtls.spiffe_client_auth_protocol(frozenset({GATEWAY_ID}))
    protocol = object.__new__(protocol_type)
    aborted: list[bool] = []
    fake_transport = SimpleNamespace(
        get_extra_info=lambda _name: None,
        abort=lambda: aborted.append(True),
    )
    protocol.connection_made(cast(Any, fake_transport))
    assert aborted == [True]


def _refresher(
    tmp_path: Path,
    *,
    source: object | None = None,
) -> spire_mtls._ServerIdentityRefresher:  # noqa: SLF001
    return spire_mtls._ServerIdentityRefresher(  # noqa: SLF001
        adapter=cast(Any, _IdentitySource(source or object())),
        refresh_seconds=1.0,
        key_boundary=_boundary(tmp_path / "refresh-keys"),
    )


@pytest.mark.parametrize("interval", [0.0, -1.0, float("inf"), float("nan")])
def test_server_identity_refresh_requires_finite_positive_interval(
    tmp_path: Path,
    interval: float,
) -> None:
    with pytest.raises(ValueError, match="positive and finite"):
        spire_mtls._ServerIdentityRefresher(  # noqa: SLF001
            adapter=cast(Any, _IdentitySource(object())),
            refresh_seconds=interval,
            key_boundary=_boundary(tmp_path / "keys"),
        )


def test_server_identity_refresher_start_and_callback_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refresher = _refresher(tmp_path)
    with pytest.raises(RuntimeError, match="initialized"):
        refresher.start()

    error = WorkloadIdentityError("refresh failed")
    refresher._invalidate(error)  # noqa: SLF001
    callbacks: list[Exception] = []
    refresher.set_fatal_callback(callbacks.append)
    assert callbacks == [error]
    refresher._invalidate(WorkloadIdentityError("second failure"))  # noqa: SLF001
    assert refresher.fatal_error is error

    fake_thread = SimpleNamespace(start=lambda: None, join=lambda timeout: None)
    monkeypatch.setattr(spire_mtls.threading, "Thread", lambda **_kwargs: fake_thread)
    refresher._fatal_error = None  # noqa: SLF001
    refresher._current = (cast(ssl.SSLContext, object()), cast(Any, object()))  # noqa: SLF001
    refresher.start()
    with pytest.raises(RuntimeError, match="already running"):
        refresher.start()
    refresher.close()


@pytest.mark.parametrize("condition", ["missing", "fatal", "future", "expired"])
def test_server_identity_selection_fails_closed_for_unusable_current_svid(
    tmp_path: Path,
    condition: str,
) -> None:
    refresher = _refresher(tmp_path)
    now = datetime.now(tz=UTC)
    identity = SimpleNamespace(
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=1),
    )
    refresher._current = (cast(ssl.SSLContext, object()), cast(Any, identity))  # noqa: SLF001
    if condition == "missing":
        refresher._current = None  # noqa: SLF001
    elif condition == "fatal":
        refresher._fatal_error = WorkloadIdentityError("fatal")  # noqa: SLF001
    elif condition == "future":
        identity.not_before = now + timedelta(minutes=1)
    else:
        identity.expires_at = now - timedelta(minutes=1)
    with pytest.raises(ssl.SSLError, match="unavailable"):
        refresher._select_context(  # noqa: SLF001
            cast(ssl.SSLSocket, SimpleNamespace()),
            None,
            cast(ssl.SSLContext, object()),
        )


def test_server_identity_selection_installs_current_context(tmp_path: Path) -> None:
    refresher = _refresher(tmp_path)
    now = datetime.now(tz=UTC)
    context = object()
    identity = SimpleNamespace(
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=1),
    )
    refresher._current = (cast(ssl.SSLContext, context), cast(Any, identity))  # noqa: SLF001
    socket = SimpleNamespace(context=None)
    refresher._select_context(  # noqa: SLF001
        cast(ssl.SSLSocket, socket),
        None,
        cast(ssl.SSLContext, object()),
    )
    assert socket.context is context


def test_refresher_context_manager_initializes_starts_and_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refresher = _refresher(tmp_path)
    lifecycle: list[str] = []
    monkeypatch.setattr(refresher, "initialize", lambda: lifecycle.append("initialize"))
    monkeypatch.setattr(refresher, "start", lambda: lifecycle.append("start"))
    monkeypatch.setattr(refresher, "close", lambda: lifecycle.append("close"))
    with refresher as entered:
        assert entered is refresher
    assert lifecycle == ["initialize", "start", "close"]


def test_server_entrypoint_fails_closed_when_tls_mode_is_not_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_SPIRE_MTLS_MODE", "disabled")
    result = spire_mtls.run_server(
        [
            "--app",
            "aegis_ot.api:app",
            "--port",
            "8443",
            "--expected-spiffe-id",
            GATEWAY_ID,
            "--allowed-client-spiffe-id",
            OBSERVER_ID,
        ]
    )
    assert result == 2


@pytest.mark.parametrize(
    ("fatal_error", "started", "expected"),
    [(None, True, 0), (WorkloadIdentityError("refresh lost"), True, 2), (None, False, 2)],
)
def test_server_entrypoint_reports_runtime_readiness_truthfully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fatal_error: Exception | None,
    started: bool,
    expected: int,
) -> None:
    root = tmp_path / "keys"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    monkeypatch.setenv("AEGIS_SPIRE_MTLS_MODE", "required")
    monkeypatch.setenv("AEGIS_SPIRE_MTLS_TMPDIR", str(root))
    context = object()

    class FakeRefresher:
        def __init__(self, **_kwargs: Any) -> None:
            self.fatal_error = fatal_error

        def initialize(self) -> object:
            return context

        def set_fatal_callback(self, callback: Any) -> None:
            self.callback = callback

        def start(self) -> None:
            return None

        def close(self) -> None:
            return None

    class FakeConfig:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    class FakeServer:
        def __init__(self, config: FakeConfig) -> None:
            self.config = config
            self.started = started
            self.should_exit = False

        async def serve(self) -> None:
            return None

    monkeypatch.setattr(spire_mtls, "SpireWorkloadIdentityAdapter", lambda **_kwargs: object())
    monkeypatch.setattr(spire_mtls, "_ServerIdentityRefresher", FakeRefresher)
    monkeypatch.setattr(spire_mtls.uvicorn, "Config", FakeConfig)
    monkeypatch.setattr(spire_mtls.uvicorn, "Server", FakeServer)

    result = spire_mtls.run_server(
        [
            "--app",
            "aegis_ot.api:app",
            "--port",
            "8443",
            "--expected-spiffe-id",
            GATEWAY_ID,
            "--allowed-client-spiffe-id",
            OBSERVER_ID,
        ]
    )
    assert result == expected


def test_main_requires_explicit_serve_and_forwards_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert spire_mtls.main([]) == 2
    received: list[list[str]] = []
    monkeypatch.setattr(spire_mtls, "run_server", lambda values: received.append(list(values)) or 7)
    assert spire_mtls.main(["serve", "--app", "test:app"]) == 7
    assert received == [["--app", "test:app"]]


class _ResolveSequence:
    def __init__(self, *values: object) -> None:
        self.values = iter(values)

    def resolve(self, **_kwargs: Any) -> Any:
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return value


def _workload_port_for_preflight(
    gateway_result: object,
    target_result: object,
) -> WorkloadRemoteVirtualPlcPort:
    port = object.__new__(WorkloadRemoteVirtualPlcPort)
    gateway_private = Ed25519PrivateKey.generate()
    target_private = Ed25519PrivateKey.generate()
    port.gateway_identity = cast(Any, _ResolveSequence(gateway_result))
    port.ot_identity = cast(Any, _ResolveSequence(target_result))
    port.gateway_key_id = "gateway-key"
    port.gateway_private_key = gateway_private
    port.ot = cast(
        Any,
        SimpleNamespace(key_id="ot-key", public_key=target_private.public_key()),
    )
    return port


@pytest.mark.parametrize(
    ("gateway_result", "target_result", "exception", "reason"),
    [
        (
            WorkloadCredentialRejected("revoked"),
            object(),
            CapabilityTransportRejected,
            "rejected_before_dispatch",
        ),
        (
            WorkloadIdentityUnavailable("bundle unavailable"),
            object(),
            CapabilityPreDispatchUnavailable,
            "unavailable_before_dispatch",
        ),
    ],
)
def test_workload_preflight_classifies_identity_failure_before_dispatch(
    gateway_result: object,
    target_result: object,
    exception: type[Exception],
    reason: str,
) -> None:
    port = _workload_port_for_preflight(gateway_result, target_result)
    with pytest.raises(exception, match=reason) as caught:
        port.preflight_identity()
    assert getattr(caught.value, "dispatch_attempts", 0) == 0


def test_workload_preflight_rejects_key_change_and_accepts_exact_current_keys() -> None:
    gateway_private = Ed25519PrivateKey.generate()
    target_private = Ed25519PrivateKey.generate()
    matching_gateway = SimpleNamespace(
        key_id="gateway-key",
        public_key=gateway_private.public_key(),
    )
    matching_target = SimpleNamespace(key_id="ot-key", public_key=target_private.public_key())
    port = _workload_port_for_preflight(matching_gateway, matching_target)
    port.gateway_private_key = gateway_private
    port.ot = cast(Any, SimpleNamespace(key_id="ot-key", public_key=target_private.public_key()))
    port.preflight_identity()

    changed_gateway = SimpleNamespace(
        key_id="rotated-key",
        public_key=gateway_private.public_key(),
    )
    port.gateway_identity = cast(Any, _ResolveSequence(changed_gateway))
    port.ot_identity = cast(Any, _ResolveSequence(matching_target))
    with pytest.raises(CapabilityTransportRejected, match="changed_before_dispatch") as caught:
        port.preflight_identity()
    assert caught.value.known_no_effect


def _workload_execute(
    port: WorkloadRemoteVirtualPlcPort,
    artifacts: M4iArtifacts,
) -> Any:
    dispatch = artifacts.dispatch
    return WorkloadRemoteVirtualPlcPort.execute(
        port,
        request=dispatch.request,
        permit=dispatch.permit,
        pre_observation=dispatch.pre_observation,
        decision=dispatch.decision,
        assessment=dispatch.assessment,
    )


def _failure_response(status_code: int, *, status: str, reason: str) -> HttpExchangeResponse:
    body = TransportFailureBody.model_validate({"status": status, "reason": reason})
    return HttpExchangeResponse(
        status_code=status_code,
        content_type="application/json",
        body=body.model_dump_json().encode(),
    )


@pytest.mark.parametrize(
    ("response", "exception", "message"),
    [
        (
            HttpExchangeResponse(503, "application/json", b"{}"),
            ConsequentialTransportOutcomeUnknown,
            "server failure",
        ),
        (
            HttpExchangeResponse(403, "application/json", b"{}"),
            ConsequentialTransportOutcomeUnknown,
            "unverifiable",
        ),
        (
            _failure_response(403, status="rejected", reason="policy_denied"),
            CapabilityTransportRejected,
            "policy_denied",
        ),
        (
            _failure_response(409, status="error", reason="coordinator_unavailable"),
            ConsequentialTransportOutcomeUnknown,
            "coordinator_unavailable",
        ),
        (
            HttpExchangeResponse(302, "application/json", b"{}"),
            ConsequentialTransportOutcomeUnknown,
            "invalid HTTP status",
        ),
        (
            HttpExchangeResponse(200, "application/json", b"{}"),
            ConsequentialTransportOutcomeUnknown,
            "trusted signed artifact",
        ),
    ],
)
def test_workload_execute_maps_every_untrusted_response_to_closed_outcome(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
    response: HttpExchangeResponse,
    exception: type[Exception],
    message: str,
) -> None:
    harness = _port_harness(tmp_path, m4i_artifacts)
    port = harness.port
    port.preflight_identity = lambda: None
    port._raw = lambda *_args, **_kwargs: response
    with pytest.raises(exception, match=message):
        _workload_execute(port, m4i_artifacts)
    harness.journal.close()


def test_workload_execute_rechecks_target_identity_and_signed_response_binding(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _port_harness(tmp_path, m4i_artifacts)
    port = harness.port
    port.preflight_identity = lambda: None
    port._raw = lambda *_args, **_kwargs: HttpExchangeResponse(
        200,
        "application/json",
        b"{}",
    )
    target = port.ot_identity.resolve(now=port.clock())
    signed_response = SimpleNamespace(
        sender_credential=target.credential,
        verify_for_request=lambda *_args, **_kwargs: True,
        response=SimpleNamespace(acknowledgment=m4i_artifacts.acknowledgment),
    )
    monkeypatch.setattr(transport, "_parse_model", lambda *_args, **_kwargs: signed_response)
    port.ot_identity = cast(
        Any,
        _ResolveSequence(
            target,
            target,
            WorkloadIdentityUnavailable("rotated away"),
        ),
    )

    assert _workload_execute(port, m4i_artifacts) == m4i_artifacts.acknowledgment

    signed_response.verify_for_request = lambda *_args, **_kwargs: False
    with pytest.raises(ConsequentialTransportOutcomeUnknown, match="transaction binding"):
        _workload_execute(port, m4i_artifacts)

    with pytest.raises(ConsequentialTransportOutcomeUnknown, match="trusted signed artifact"):
        _workload_execute(port, m4i_artifacts)
    harness.journal.close()


@pytest.mark.parametrize(
    ("gateway_role", "target_role", "target_matches", "message"),
    [
        (WorkloadRole.OBSERVER, WorkloadRole.OT_ADAPTER, True, "not a gateway"),
        (WorkloadRole.GATEWAY, WorkloadRole.OBSERVER, True, "not an OT adapter"),
        (WorkloadRole.GATEWAY, WorkloadRole.OT_ADAPTER, False, "does not match"),
    ],
)
def test_workload_client_constructor_rejects_wrong_role_or_target_key(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
    gateway_role: WorkloadRole,
    target_role: WorkloadRole,
    target_matches: bool,
    message: str,
) -> None:
    harness = _port_harness(tmp_path, m4i_artifacts)
    ot = harness.port.ot
    target_private = Ed25519PrivateKey.generate()
    target = SimpleNamespace(
        credential=SimpleNamespace(credential=SimpleNamespace(role=target_role)),
        key_id=ot.key_id if target_matches else "different-key",
        public_key=ot.public_key if target_matches else target_private.public_key(),
    )
    gateway = SimpleNamespace(
        credential=SimpleNamespace(credential=SimpleNamespace(role=gateway_role)),
        key_id=ot.gateway_key_id,
        public_key=harness.port.gateway_private_key.public_key(),
    )
    gateway_identity = SimpleNamespace(
        resolve=lambda **_kwargs: gateway,
        signer=harness.port.gateway_identity.signer,
    )
    ot_identity = SimpleNamespace(resolve=lambda **_kwargs: target)
    with pytest.raises(ValueError, match=message):
        WorkloadRemoteVirtualPlcPort(
            "https://ot.test",
            ot=ot,
            gateway_identity=cast(Any, gateway_identity),
            ot_identity=cast(Any, ot_identity),
        )
    harness.journal.close()


def test_coordinated_identity_failures_remain_known_before_dispatch(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, m4i_artifacts)
    port = harness.port
    port.gateway_identity = cast(
        Any,
        _ResolveSequence(WorkloadCredentialRejected("gateway revoked")),
    )
    with pytest.raises(CapabilityTransportRejected, match="rejected_before_coordination") as caught:
        port._current_identities(evaluated_at=port.clock(), require_pinned_target=True)
    assert caught.value.known_no_effect

    port.gateway_identity = cast(
        Any,
        _ResolveSequence(WorkloadIdentityUnavailable("trust bundle missing")),
    )
    with pytest.raises(CapabilityPreDispatchUnavailable, match="unavailable_before_coordination"):
        port._current_identities(evaluated_at=port.clock(), require_pinned_target=True)
    harness.journal.close()


@pytest.mark.parametrize("journal_error", [CoordinationCollisionError, CoordinationJournalError])
def test_prepare_requires_durable_nonconflicting_intent_before_network(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    journal_error: type[CoordinationJournalError],
) -> None:
    harness = _port_harness(tmp_path, m4i_artifacts)

    def fail_begin(*_args: Any, **_kwargs: Any) -> None:
        raise journal_error("journal rejected prepare")

    monkeypatch.setattr(harness.journal, "begin", fail_begin)
    expected = (
        ConsequentialTransportOutcomeUnknown
        if journal_error is CoordinationCollisionError
        else CapabilityPreDispatchUnavailable
    )
    with pytest.raises(expected):
        harness.port._prepare(m4i_artifacts.dispatch)
    assert harness.exchange.paths == []
    harness.journal.close()


@pytest.mark.parametrize("method", ["close", "ambiguous"])
def test_journal_write_failure_preserves_closed_effect_classification(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    harness = _port_harness(tmp_path, m4i_artifacts)
    effect = transport.EffectIdentity.from_dispatch(m4i_artifacts.dispatch)

    def fail(*_args: Any, **_kwargs: Any) -> None:
        raise CoordinationJournalError("fsync failed")

    if method == "close":
        monkeypatch.setattr(harness.journal, "close_not_dispatched", fail)
        with pytest.raises(CapabilityPreDispatchUnavailable, match="durably close"):
            harness.port._close_before_commit(
                effect,
                reason="known_no_effect",
                evidence_sha256="1" * 64,
                recorded_at=harness.exchange.clock(),
            )
    else:
        monkeypatch.setattr(harness.journal, "mark_commit_unknown", fail)
        request = SimpleNamespace()
        with pytest.raises(ConsequentialTransportOutcomeUnknown, match="ambiguity"):
            harness.port._mark_commit_ambiguous(
                cast(Any, request),
                reason="unknown",
                evidence_sha256="2" * 64,
                recorded_at=harness.exchange.clock(),
            )
    harness.journal.close()


@pytest.mark.parametrize("disposition", [EffectDisposition.APPLIED, EffectDisposition.REJECTED])
def test_terminal_outcome_never_exposes_missing_acknowledgment(
    disposition: EffectDisposition,
) -> None:
    outcome = SimpleNamespace(
        disposition=disposition,
        acknowledgment=None,
        reason="missing_acknowledgment",
    )
    port = object.__new__(CoordinatedWorkloadRemoteVirtualPlcPort)
    with pytest.raises(ConsequentialTransportOutcomeUnknown, match="omitted"):
        port._expose_outcome(cast(Any, outcome))


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (CoordinationState.DISPATCH_ARMED, CoordinationState.DISPATCH_ARMED),
        (CoordinationState.COMMIT_ACCEPTED, CoordinationState.COMMIT_ACCEPTED),
        (CoordinationState.UNKNOWN_EFFECT, CoordinationState.UNKNOWN_EFFECT),
    ],
)
def test_query_evidence_reconstructs_the_last_independent_prior_state(
    state: CoordinationState,
    expected: CoordinationState,
) -> None:
    now = datetime.now(tz=UTC)
    outcome = SimpleNamespace(digest="1" * 64, acceptance=SimpleNamespace(digest="2" * 64))
    attempt = SimpleNamespace(outcome=outcome, retained_at=now)
    transitions = (
        SimpleNamespace(
            recorded_at=now - timedelta(seconds=2),
            evidence_sha256="1" * 64,
            state=CoordinationState.DISPATCH_ARMED,
        ),
        SimpleNamespace(
            recorded_at=now - timedelta(seconds=1),
            evidence_sha256="3" * 64,
            state=state,
        ),
        SimpleNamespace(
            recorded_at=now + timedelta(seconds=1),
            evidence_sha256="4" * 64,
            state=CoordinationState.REJECTED,
        ),
    )
    record = SimpleNamespace(transitions=transitions)
    assert (
        CoordinatedWorkloadRemoteVirtualPlcPort._prior_state_for_query(
            cast(Any, record),
            cast(Any, attempt),
        )
        is expected
    )


def test_query_evidence_rejects_missing_prior_dispatch_state() -> None:
    now = datetime.now(tz=UTC)
    attempt = SimpleNamespace(outcome=None, retained_at=now)
    record = SimpleNamespace(
        transitions=(
            SimpleNamespace(
                recorded_at=now,
                evidence_sha256="1" * 64,
                state=CoordinationState.RECEIVED,
            ),
        )
    )
    with pytest.raises(ConsequentialTransportOutcomeUnknown, match="verification_failed"):
        CoordinatedWorkloadRemoteVirtualPlcPort._prior_state_for_query(
            cast(Any, record),
            cast(Any, attempt),
        )


def test_resume_and_query_fail_closed_without_retained_protocol_artifacts() -> None:
    port = object.__new__(CoordinatedWorkloadRemoteVirtualPlcPort)
    terminal = SimpleNamespace(
        state=CoordinationState.NOT_DISPATCHED,
        terminal_outcome=None,
        attempts=(),
        latest_receipt=None,
    )
    with pytest.raises(CapabilityTransportRejected, match="durably_not_dispatched") as caught:
        port._resume(cast(Any, terminal))
    assert caught.value.known_no_effect

    received = SimpleNamespace(
        state=CoordinationState.RECEIVED,
        attempts=(),
        latest_receipt=None,
    )
    with pytest.raises(CapabilityPreDispatchUnavailable, match="durable receipt"):
        port._resume(cast(Any, received))
    with pytest.raises(CapabilityPreDispatchUnavailable, match="no retained commit"):
        port._query(cast(Any, received))


@pytest.mark.parametrize("operation", ["effect", "pending"])
def test_reconciliation_journal_unavailability_never_dispatches(
    operation: str,
) -> None:
    class FailedJournal:
        def get(self, _effect: object) -> None:
            raise CoordinationJournalError("journal unavailable")

        def pending(self) -> None:
            raise CoordinationJournalError("journal unavailable")

    port = object.__new__(CoordinatedWorkloadRemoteVirtualPlcPort)
    port.coordination_journal = cast(Any, FailedJournal())
    with pytest.raises(ConsequentialTransportOutcomeUnknown, match="journal is unavailable"):
        if operation == "effect":
            port.reconcile_effect("effect-id")
        else:
            port.reconcile_pending_once()


def test_reconciliation_reports_absent_effect_and_empty_queue_without_network() -> None:
    class EmptyJournal:
        def get(self, _effect: object) -> None:
            return None

        def pending(self) -> tuple[()]:
            return ()

    port = object.__new__(CoordinatedWorkloadRemoteVirtualPlcPort)
    port.coordination_journal = cast(Any, EmptyJournal())
    with pytest.raises(CapabilityPreDispatchUnavailable, match="not recorded"):
        port.reconcile_effect("missing-effect")
    assert port.reconcile_pending_once() is None
