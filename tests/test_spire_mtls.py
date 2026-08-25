from __future__ import annotations

import ssl
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.svid.x509_svid import X509Svid
from uvicorn.protocols.http.h11_impl import H11Protocol

from aegis_ot import spire_mtls
from aegis_ot.segmented_capability_transport import (
    CapabilityTransportProtocolError,
    CapabilityTransportUnavailable,
    urllib_http_exchange,
)
from aegis_ot.spire_mtls import (
    SpireMtlsError,
    SpireMtlsHttpExchange,
    TemporaryKeyMaterialBoundary,
    capability_http_exchange_from_environment,
    peer_spiffe_id,
    require_peer_spiffe_id,
    server_ssl_context,
    spiffe_client_auth_protocol,
)
from aegis_ot.spire_workload_identity import (
    VerifiedWorkloadIdentity,
    WorkloadIdentityError,
)

TRUST_DOMAIN = "aegis-ot.m4g.local"
GATEWAY_ID = f"spiffe://{TRUST_DOMAIN}/workload/gateway"
OBSERVER_ID = f"spiffe://{TRUST_DOMAIN}/workload/observer"
OT_ID = f"spiffe://{TRUST_DOMAIN}/workload/ot-adapter"
PLANT_ID = f"spiffe://{TRUST_DOMAIN}/workload/plant"


def _key_usage(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def _root(now: datetime) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegis SPIRE test root")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_key_usage(ca=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _identity(
    spiffe_id: str,
    *,
    root_key: ec.EllipticCurvePrivateKey,
    root: x509.Certificate,
    now: datetime,
    extra_uri_sans: tuple[str, ...] = (),
    trust_root: x509.Certificate | None = None,
) -> VerifiedWorkloadIdentity:
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(root.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=5))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(value) for value in (spiffe_id, *extra_uri_sans)]
            ),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(ca=False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False
        )
        .sign(root_key, hashes.SHA256())
    )
    parsed_id = SpiffeId(spiffe_id)
    svid = X509Svid(parsed_id, [leaf], key)
    bundle = X509Bundle(parsed_id.trust_domain, {trust_root or root})
    return VerifiedWorkloadIdentity(
        spiffe_id=spiffe_id,
        fetched_at=now,
        not_before=leaf.not_valid_before_utc,
        expires_at=leaf.not_valid_after_utc,
        certificate_sha256=leaf.fingerprint(hashes.SHA256()).hex(),
        svid=svid,
        trust_bundle=bundle,
    )


def _boundary(path: Path) -> TemporaryKeyMaterialBoundary:
    path.mkdir()
    path.chmod(0o700)
    return TemporaryKeyMaterialBoundary(path)


class _SequenceIdentitySource:
    def __init__(self, results: Iterator[VerifiedWorkloadIdentity | Exception]) -> None:
        self._results = results
        self.calls = 0

    def fetch_and_verify(self) -> VerifiedWorkloadIdentity:
        self.calls += 1
        value = next(self._results)
        if isinstance(value, Exception):
            raise value
        return value


def test_peer_certificate_requires_one_exact_allowed_spiffe_uri_san() -> None:
    now = datetime.now(tz=UTC)
    root_key, root = _root(now)
    gateway = _identity(GATEWAY_ID, root_key=root_key, root=root, now=now)
    certificate_der = gateway.svid.leaf.public_bytes(serialization.Encoding.DER)

    assert peer_spiffe_id(certificate_der) == GATEWAY_ID
    assert require_peer_spiffe_id(certificate_der, frozenset({GATEWAY_ID})) == GATEWAY_ID
    with pytest.raises(SpireMtlsError, match="not authorized"):
        require_peer_spiffe_id(certificate_der, frozenset({OBSERVER_ID}))

    ambiguous = _identity(
        GATEWAY_ID,
        root_key=root_key,
        root=root,
        now=now,
        extra_uri_sans=(OBSERVER_ID,),
    )
    with pytest.raises(SpireMtlsError, match="exactly one"):
        peer_spiffe_id(ambiguous.svid.leaf.public_bytes(serialization.Encoding.DER))


def test_temporary_key_boundary_is_explicit_private_and_ephemeral(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGIS_SPIRE_MTLS_TMPDIR", raising=False)
    with pytest.raises(SpireMtlsError, match="must name"):
        TemporaryKeyMaterialBoundary.from_environment()

    permissive = tmp_path / "permissive"
    permissive.mkdir(mode=0o755)
    with pytest.raises(SpireMtlsError, match="mode 0700"):
        TemporaryKeyMaterialBoundary(permissive)

    target = tmp_path / "private"
    target.mkdir(mode=0o700)
    target.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(SpireMtlsError, match="real directory"):
        TemporaryKeyMaterialBoundary(link)

    now = datetime.now(tz=UTC)
    root_key, root = _root(now)
    identity = _identity(GATEWAY_ID, root_key=root_key, root=root, now=now)
    boundary = TemporaryKeyMaterialBoundary(target)
    seen: dict[str, int | bool] = {}

    class FakeContext:
        def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
            cert_path = Path(certfile)
            key_path = Path(keyfile)
            seen["cert_mode"] = cert_path.stat().st_mode & 0o777
            seen["key_mode"] = key_path.stat().st_mode & 0o777
            seen["key_present"] = key_path.exists()

    spire_mtls._load_certificate_chain(  # noqa: SLF001 - security-boundary unit test
        cast(ssl.SSLContext, FakeContext()),
        identity,
        boundary,
    )
    assert seen == {"cert_mode": 0o600, "key_mode": 0o600, "key_present": True}
    assert list(target.iterdir()) == []


class _MtlsHandler(BaseHTTPRequestHandler):
    expected_client_id = ""
    peer_fingerprints: list[str] = []
    tls_versions: list[str] = []
    requests_seen = 0

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        connection = cast(ssl.SSLSocket, self.connection)
        certificate_der = cast(bytes, connection.getpeercert(binary_form=True))
        require_peer_spiffe_id(certificate_der, frozenset({self.expected_client_id}))
        certificate = x509.load_der_x509_certificate(certificate_der)
        self.peer_fingerprints.append(certificate.fingerprint(hashes.SHA256()).hex())
        self.tls_versions.append(cast(str, connection.version()))
        type(self).requests_seen += 1
        body = b'{"status":"ready"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _tls_server(
    identity: VerifiedWorkloadIdentity,
    *,
    expected_client_id: str,
    request_count: int,
    boundary: TemporaryKeyMaterialBoundary,
) -> tuple[HTTPServer, threading.Thread, list[BaseException]]:
    class Handler(_MtlsHandler):
        pass

    Handler.expected_client_id = expected_client_id
    Handler.peer_fingerprints = []
    Handler.tls_versions = []
    Handler.requests_seen = 0
    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 1.0
    server.socket = server_ssl_context(identity, key_boundary=boundary).wrap_socket(
        server.socket,
        server_side=True,
    )
    failures: list[BaseException] = []

    def serve() -> None:
        try:
            for _ in range(request_count):
                server.handle_request()
        except BaseException as exc:  # pragma: no cover - asserted through failures
            failures.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return server, thread, failures


def test_exchange_uses_tls13_rotates_client_svid_and_checks_server_id(
    tmp_path: Path,
) -> None:
    boundary = _boundary(tmp_path / "keys")
    now = datetime.now(tz=UTC)
    root_key, root = _root(now)
    plant = _identity(PLANT_ID, root_key=root_key, root=root, now=now)
    gateway_one = _identity(GATEWAY_ID, root_key=root_key, root=root, now=now)
    gateway_two = _identity(GATEWAY_ID, root_key=root_key, root=root, now=now)
    source = _SequenceIdentitySource(iter((gateway_one, gateway_two)))
    server, thread, failures = _tls_server(
        plant,
        expected_client_id=GATEWAY_ID,
        request_count=2,
        boundary=boundary,
    )
    port = cast(tuple[str, int], server.server_address)[1]
    exchange = SpireMtlsHttpExchange(
        identity_source=source,
        expected_peer_ids={"127.0.0.1": PLANT_ID},
        key_boundary=boundary,
    )

    for _ in range(2):
        response = exchange(
            method="GET",
            url=f"https://127.0.0.1:{port}/health",
            body=None,
            headers={"Accept": "application/json"},
            timeout_seconds=2.0,
        )
        assert response.status_code == 200

    thread.join(timeout=3)
    server.server_close()
    assert not failures
    assert source.calls == 2
    handler = cast(type[_MtlsHandler], server.RequestHandlerClass)
    assert handler.requests_seen == 2
    assert len(set(handler.peer_fingerprints)) == 2
    assert handler.tls_versions == ["TLSv1.3", "TLSv1.3"]

    wrong_server, wrong_thread, _ = _tls_server(
        plant,
        expected_client_id=GATEWAY_ID,
        request_count=1,
        boundary=boundary,
    )
    wrong_port = cast(tuple[str, int], wrong_server.server_address)[1]
    wrong_exchange = SpireMtlsHttpExchange(
        identity_source=_SequenceIdentitySource(iter((gateway_one,))),
        expected_peer_ids={"127.0.0.1": OBSERVER_ID},
        key_boundary=boundary,
    )
    with pytest.raises(CapabilityTransportProtocolError, match="identity was rejected"):
        wrong_exchange(
            method="GET",
            url=f"https://127.0.0.1:{wrong_port}/health",
            body=None,
            headers={"Accept": "application/json"},
            timeout_seconds=2.0,
        )
    wrong_thread.join(timeout=3)
    wrong_server.server_close()
    assert cast(type[_MtlsHandler], wrong_server.RequestHandlerClass).requests_seen == 0


def test_exchange_rejects_untrusted_server_ca_before_http(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path / "keys")
    now = datetime.now(tz=UTC)
    trusted_key, trusted_root = _root(now)
    rogue_key, rogue_root = _root(now)
    client = _identity(GATEWAY_ID, root_key=trusted_key, root=trusted_root, now=now)
    rogue_server = _identity(
        PLANT_ID,
        root_key=rogue_key,
        root=rogue_root,
        trust_root=trusted_root,
        now=now,
    )
    server, thread, _ = _tls_server(
        rogue_server,
        expected_client_id=GATEWAY_ID,
        request_count=1,
        boundary=boundary,
    )
    port = cast(tuple[str, int], server.server_address)[1]
    exchange = SpireMtlsHttpExchange(
        identity_source=_SequenceIdentitySource(iter((client,))),
        expected_peer_ids={"127.0.0.1": PLANT_ID},
        key_boundary=boundary,
    )

    with pytest.raises(CapabilityTransportUnavailable, match="exchange failed"):
        exchange(
            method="GET",
            url=f"https://127.0.0.1:{port}/health",
            body=None,
            headers={},
            timeout_seconds=2.0,
        )
    thread.join(timeout=3)
    server.server_close()
    assert cast(type[_MtlsHandler], server.RequestHandlerClass).requests_seen == 0


def test_server_protocol_applies_service_allowlist_before_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(tz=UTC)
    root_key, root = _root(now)
    gateway = _identity(GATEWAY_ID, root_key=root_key, root=root, now=now)
    observer = _identity(OBSERVER_ID, root_key=root_key, root=root, now=now)
    gateway_der = gateway.svid.leaf.public_bytes(serialization.Encoding.DER)
    observer_der = observer.svid.leaf.public_bytes(serialization.Encoding.DER)
    accepted: list[object] = []
    monkeypatch.setattr(
        H11Protocol,
        "connection_made",
        lambda _self, transport: accepted.append(transport),
    )

    class FakeSslObject:
        def __init__(self, certificate: bytes) -> None:
            self.certificate = certificate

        def getpeercert(self, *, binary_form: bool = False) -> bytes:
            assert binary_form is True
            return self.certificate

    class FakeTransport:
        def __init__(self, certificate: bytes) -> None:
            self.ssl_object = FakeSslObject(certificate)
            self.aborted = False

        def get_extra_info(self, name: str) -> object:
            assert name == "ssl_object"
            return self.ssl_object

        def abort(self) -> None:
            self.aborted = True

    protocol_type = spiffe_client_auth_protocol(frozenset({GATEWAY_ID, OT_ID}))
    protocol = object.__new__(protocol_type)
    allowed = FakeTransport(gateway_der)
    protocol.connection_made(cast(Any, allowed))
    assert allowed.aborted is False
    assert accepted == [allowed]

    denied = FakeTransport(observer_der)
    protocol.connection_made(cast(Any, denied))
    assert denied.aborted is True
    assert accepted == [allowed]


def test_server_identity_rotates_then_refresh_failure_fails_closed(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path / "keys")
    now = datetime.now(tz=UTC)
    root_key, root = _root(now)
    first = _identity(PLANT_ID, root_key=root_key, root=root, now=now)
    rotated = _identity(PLANT_ID, root_key=root_key, root=root, now=now)
    source = _SequenceIdentitySource(
        iter((first, rotated, WorkloadIdentityError("issuance unavailable")))
    )
    refresher = spire_mtls._ServerIdentityRefresher(  # noqa: SLF001 - focused unit test
        adapter=source,
        refresh_seconds=0.01,
        key_boundary=boundary,
    )
    fatal = threading.Event()
    refresher.initialize()
    refresher.set_fatal_callback(lambda _error: fatal.set())
    refresher.start()

    deadline = time.monotonic() + 2
    saw_rotation = False
    while time.monotonic() < deadline and not fatal.is_set():
        saw_rotation = (
            saw_rotation or refresher.current_certificate_sha256 == rotated.certificate_sha256
        )
        time.sleep(0.002)
    refresher.close()

    assert saw_rotation is True
    assert fatal.is_set()
    assert isinstance(refresher.fatal_error, WorkloadIdentityError)
    assert refresher.current_certificate_sha256 is None


def test_environment_mode_is_explicit_and_never_silently_downgrades(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "AEGIS_SPIRE_MTLS_MODE",
        "AEGIS_SPIFFE_ID",
        "AEGIS_SPIFFE_PEER_IDS",
        "AEGIS_SPIRE_MTLS_TMPDIR",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValueError, match="explicitly set"):
        capability_http_exchange_from_environment()
    monkeypatch.setenv("AEGIS_SPIRE_MTLS_MODE", " disabled ")
    with pytest.raises(ValueError, match="explicitly set"):
        capability_http_exchange_from_environment()
    monkeypatch.setenv("AEGIS_SPIRE_MTLS_MODE", "disabled")
    assert capability_http_exchange_from_environment() is urllib_http_exchange

    monkeypatch.setenv("AEGIS_SPIRE_MTLS_MODE", "required")
    with pytest.raises(ValueError, match="AEGIS_SPIFFE_ID"):
        capability_http_exchange_from_environment()
    monkeypatch.setenv("AEGIS_SPIFFE_ID", GATEWAY_ID)
    monkeypatch.setenv("AEGIS_SPIFFE_PEER_IDS", f'{{"observer":"{OBSERVER_ID}"}}')
    with pytest.raises(SpireMtlsError, match="must name"):
        capability_http_exchange_from_environment()

    boundary_path = tmp_path / "keys"
    boundary_path.mkdir(mode=0o700)
    boundary_path.chmod(0o700)
    monkeypatch.setenv("AEGIS_SPIRE_MTLS_TMPDIR", str(boundary_path))
    assert isinstance(capability_http_exchange_from_environment(), SpireMtlsHttpExchange)

    monkeypatch.setenv(
        "AEGIS_SPIFFE_PEER_IDS",
        f'{{"observer":"{OBSERVER_ID}","observer":"{OBSERVER_ID}"}}',
    )
    with pytest.raises(ValueError, match="unique keys"):
        capability_http_exchange_from_environment()


def test_https_target_must_have_a_configured_peer(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path / "keys")
    source = _SequenceIdentitySource(iter(()))
    exchange = SpireMtlsHttpExchange(
        identity_source=source,
        expected_peer_ids={"observer": OBSERVER_ID},
        key_boundary=boundary,
    )
    with pytest.raises(CapabilityTransportProtocolError, match="no configured"):
        exchange(
            method="GET",
            url="https://candidate:8085/health",
            body=None,
            headers={},
            timeout_seconds=1.0,
        )
    assert source.calls == 0


def test_server_context_requires_tls13_and_mutual_certificate_auth(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path / "keys")
    now = datetime.now(tz=UTC)
    root_key, root = _root(now)
    identity = _identity(PLANT_ID, root_key=root_key, root=root, now=now)
    context = server_ssl_context(identity, key_boundary=boundary)

    assert context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert context.maximum_version is ssl.TLSVersion.TLSv1_3
    assert context.verify_mode is ssl.CERT_REQUIRED
