"""TLS 1.3 transport identity for segmented Aegis-OT service links.

SPIRE mTLS adds a transport authentication boundary; it does not replace the
application signatures, permits, replay ledgers, policy checks, or physical
safety checks.  Client identities are fetched for every exchange.  Server
identities rotate in-process and any refresh failure stops new handshakes and
requests process shutdown.
"""

from __future__ import annotations

import argparse
import asyncio
import http.client
import json
import logging
import math
import os
import ssl
import stat
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, cast
from urllib.parse import SplitResult, urlsplit

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from uvicorn.protocols.http.h11_impl import H11Protocol

from .segmented_capability_transport import (
    MAX_JSON_BYTES,
    CapabilityTransportProtocolError,
    CapabilityTransportUnavailable,
    HttpExchange,
    HttpExchangeResponse,
    urllib_http_exchange,
)
from .spire_workload_identity import (
    SpireWorkloadIdentityAdapter,
    VerifiedWorkloadIdentity,
    WorkloadIdentityError,
    validated_spiffe_id,
)

_LOGGER = logging.getLogger(__name__)
_DEFAULT_REFRESH_SECONDS = 2.0
_DEFAULT_SOCKET = "unix:///run/spire/agent/public/api.sock"
_MODE_ENV = "AEGIS_SPIRE_MTLS_MODE"
_SELF_ID_ENV = "AEGIS_SPIFFE_ID"
_PEERS_ENV = "AEGIS_SPIFFE_PEER_IDS"
_TMPDIR_ENV = "AEGIS_SPIRE_MTLS_TMPDIR"


class SpireMtlsError(RuntimeError):
    """SPIRE mTLS material or peer identity is unusable."""


class _IdentitySource(Protocol):
    def fetch_and_verify(self) -> VerifiedWorkloadIdentity: ...


class TemporaryKeyMaterialBoundary:
    """Private, explicitly configured boundary for transient PEM key loading.

    CPython/OpenSSL's ``load_cert_chain`` accepts paths rather than in-memory
    key bytes.  The deployment must therefore mount this root as a per-service
    tmpfs owned by the workload UID with mode 0700.  This class rejects an
    implicit system temporary directory, symlinks, foreign ownership, and any
    group/world access.  Per-load directories and key files are deleted as soon
    as OpenSSL has imported the material.
    """

    def __init__(self, root: Path) -> None:
        root_stat = self._validate_root(root)
        self._root = root
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)

    @staticmethod
    def _validate_root(root: Path) -> os.stat_result:
        if not root.is_absolute():
            raise ValueError("temporary key material root must be absolute")
        try:
            root_stat = root.lstat()
        except OSError as exc:
            raise SpireMtlsError("temporary key material root is unavailable") from exc
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            raise SpireMtlsError("temporary key material root must be a real directory")
        if root_stat.st_uid != os.geteuid():
            raise SpireMtlsError("temporary key material root is not owned by this workload")
        if stat.S_IMODE(root_stat.st_mode) & 0o077:
            raise SpireMtlsError("temporary key material root must have mode 0700")
        return root_stat

    @classmethod
    def from_environment(cls) -> TemporaryKeyMaterialBoundary:
        value = os.environ.get(_TMPDIR_ENV)
        if value is None or not value:
            raise SpireMtlsError(f"{_TMPDIR_ENV} must name a private per-service tmpfs directory")
        return cls(Path(value))

    @contextmanager
    def paths(self, identity: VerifiedWorkloadIdentity) -> Iterator[tuple[Path, Path]]:
        current = self._validate_root(self._root)
        if (current.st_dev, current.st_ino) != self._root_identity:
            raise SpireMtlsError("temporary key material root changed after validation")
        try:
            with tempfile.TemporaryDirectory(prefix="aegis-spire-mtls-", dir=self._root) as raw:
                directory = Path(raw)
                directory.chmod(0o700)
                certificate_path = directory / "svid-chain.pem"
                private_key_path = directory / "svid-key.pem"
                certificate_path.write_bytes(_certificate_chain_pem(identity))
                private_key_path.write_bytes(_private_key_pem(identity))
                certificate_path.chmod(0o600)
                private_key_path.chmod(0o600)
                yield certificate_path, private_key_path
        except OSError as exc:
            raise SpireMtlsError(
                "temporary SPIRE key material could not be handled safely"
            ) from exc


def peer_spiffe_id(certificate_der: bytes) -> str:
    """Return the sole SPIFFE URI SAN from a DER peer certificate."""

    if not certificate_der:
        raise SpireMtlsError("TLS peer did not present a certificate")
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        san = cast(
            x509.SubjectAlternativeName,
            certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value,
        )
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise SpireMtlsError("TLS peer certificate has no usable SAN") from exc
    uri_sans = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uri_sans) != 1:
        raise SpireMtlsError("TLS peer certificate must contain exactly one SPIFFE URI SAN")
    try:
        return validated_spiffe_id(uri_sans[0], label="TLS peer URI SAN")
    except ValueError as exc:
        raise SpireMtlsError("TLS peer URI SAN is not a valid SPIFFE ID") from exc


def require_peer_spiffe_id(certificate_der: bytes, allowed_ids: frozenset[str]) -> str:
    """Require a chain-verified peer to carry an explicitly allowed SPIFFE ID."""

    normalized = _allowed_peer_ids(tuple(allowed_ids))
    actual = peer_spiffe_id(certificate_der)
    if actual not in normalized:
        raise SpireMtlsError("TLS peer SPIFFE ID is not authorized for this service")
    return actual


def _certificate_chain_pem(identity: VerifiedWorkloadIdentity) -> bytes:
    return b"".join(
        certificate.public_bytes(serialization.Encoding.PEM)
        for certificate in identity.svid.cert_chain
    )


def _private_key_pem(identity: VerifiedWorkloadIdentity) -> bytes:
    return identity.svid.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _trust_bundle_pem(identity: VerifiedWorkloadIdentity) -> str:
    authorities = sorted(
        identity.trust_bundle.x509_authorities,
        key=lambda certificate: certificate.public_bytes(serialization.Encoding.DER),
    )
    if not authorities:
        raise SpireMtlsError("SPIRE trust bundle has no X.509 authorities")
    return b"".join(
        certificate.public_bytes(serialization.Encoding.PEM) for certificate in authorities
    ).decode("ascii")


def _load_certificate_chain(
    context: ssl.SSLContext,
    identity: VerifiedWorkloadIdentity,
    boundary: TemporaryKeyMaterialBoundary,
) -> None:
    try:
        with boundary.paths(identity) as (certificate_path, private_key_path):
            context.load_cert_chain(
                certfile=str(certificate_path),
                keyfile=str(private_key_path),
            )
    except (ValueError, ssl.SSLError) as exc:
        raise SpireMtlsError("unable to load the verified SPIRE X.509-SVID") from exc


def _harden_context(context: ssl.SSLContext) -> None:
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        context.options |= ssl.OP_NO_RENEGOTIATION


def client_ssl_context(
    identity: VerifiedWorkloadIdentity,
    *,
    key_boundary: TemporaryKeyMaterialBoundary | None = None,
) -> ssl.SSLContext:
    """Build a TLS 1.3 client-auth context from a verified Workload API result."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    _harden_context(context)
    try:
        context.load_verify_locations(cadata=_trust_bundle_pem(identity))
    except (ValueError, ssl.SSLError) as exc:
        raise SpireMtlsError("unable to load the SPIRE client trust bundle") from exc
    _load_certificate_chain(
        context,
        identity,
        key_boundary or TemporaryKeyMaterialBoundary.from_environment(),
    )
    return context


def server_ssl_context(
    identity: VerifiedWorkloadIdentity,
    *,
    key_boundary: TemporaryKeyMaterialBoundary | None = None,
) -> ssl.SSLContext:
    """Build a TLS 1.3 server context requiring a trusted client certificate."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    _harden_context(context)
    try:
        context.load_verify_locations(cadata=_trust_bundle_pem(identity))
    except (ValueError, ssl.SSLError) as exc:
        raise SpireMtlsError("unable to load the SPIRE server trust bundle") from exc
    _load_certificate_chain(
        context,
        identity,
        key_boundary or TemporaryKeyMaterialBoundary.from_environment(),
    )
    return context


class _IdentityVerifyingHttpsConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        *,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
        expected_peer_id: str,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._expected_peer_id = expected_peer_id

    def connect(self) -> None:
        super().connect()
        if not isinstance(self.sock, ssl.SSLSocket):
            self.close()
            raise SpireMtlsError("HTTPS connection did not establish TLS")
        try:
            require_peer_spiffe_id(
                cast(bytes, self.sock.getpeercert(binary_form=True)),
                frozenset({self._expected_peer_id}),
            )
        except (SpireMtlsError, ValueError):
            self.close()
            raise


def _bounded_response_body(response: http.client.HTTPResponse) -> bytes:
    declared = response.getheader("Content-Length")
    if declared is not None:
        try:
            declared_length = int(declared)
        except ValueError as exc:
            raise CapabilityTransportProtocolError("response Content-Length is invalid") from exc
        if declared_length < 0 or declared_length > MAX_JSON_BYTES:
            raise CapabilityTransportProtocolError("response exceeds the JSON size limit")
    material = response.read(MAX_JSON_BYTES + 1)
    if len(material) > MAX_JSON_BYTES:
        raise CapabilityTransportProtocolError("response exceeds the JSON size limit")
    return material


def _https_target(url: str) -> tuple[SplitResult, str, int]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise CapabilityTransportProtocolError(
            "SPIRE mTLS endpoints must be HTTPS URLs without credentials, query, or fragment"
        )
    return parsed, parsed.hostname, parsed.port or 443


class SpireMtlsHttpExchange:
    """One-shot HTTPS exchange using a fresh client SVID and exact server ID."""

    def __init__(
        self,
        *,
        identity_source: _IdentitySource,
        expected_peer_ids: Mapping[str, str],
        key_boundary: TemporaryKeyMaterialBoundary,
    ) -> None:
        if not expected_peer_ids:
            raise ValueError("at least one mTLS peer mapping is required")
        normalized: dict[str, str] = {}
        for hostname, spiffe_id in expected_peer_ids.items():
            if (
                not hostname
                or hostname != hostname.strip().lower()
                or ":" in hostname
                or "/" in hostname
            ):
                raise ValueError("mTLS peer hostnames must be lowercase normalized host names")
            normalized[hostname] = validated_spiffe_id(
                spiffe_id,
                label=f"mTLS peer {hostname}",
            )
        self._identity_source = identity_source
        self._expected_peer_ids = normalized
        self._key_boundary = key_boundary

    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> HttpExchangeResponse:
        if method not in {"GET", "POST"}:
            raise ValueError("capability exchange method is unsupported")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("HTTP timeout must be positive and finite")
        parsed, hostname, port = _https_target(url)
        expected_peer_id = self._expected_peer_ids.get(hostname)
        if expected_peer_id is None:
            raise CapabilityTransportProtocolError(
                "HTTPS endpoint has no configured SPIFFE peer identity"
            )
        try:
            identity = self._identity_source.fetch_and_verify()
            context = client_ssl_context(identity, key_boundary=self._key_boundary)
        except (WorkloadIdentityError, SpireMtlsError) as exc:
            raise CapabilityTransportUnavailable(
                "current SPIRE client identity is unavailable"
            ) from exc

        connection = _IdentityVerifyingHttpsConnection(
            hostname,
            port=port,
            timeout=timeout_seconds,
            context=context,
            expected_peer_id=expected_peer_id,
        )
        try:
            connection.request(
                method,
                parsed.path or "/",
                body=body,
                headers=dict(headers),
            )
            response = connection.getresponse()
            return HttpExchangeResponse(
                status_code=response.status,
                content_type=response.getheader("Content-Type", ""),
                body=_bounded_response_body(response),
            )
        except SpireMtlsError as exc:
            raise CapabilityTransportProtocolError(
                "HTTPS server SPIFFE identity was rejected"
            ) from exc
        except CapabilityTransportProtocolError:
            raise
        except (http.client.HTTPException, OSError, TimeoutError, ssl.SSLError) as exc:
            raise CapabilityTransportUnavailable("SPIRE mTLS exchange failed") from exc
        finally:
            connection.close()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _peer_map_from_environment() -> dict[str, str]:
    raw = os.environ.get(_PEERS_ENV)
    if raw is None:
        raise ValueError(f"{_PEERS_ENV} is required when SPIRE mTLS is required")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{_PEERS_ENV} must be a JSON object with unique keys") from exc
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{_PEERS_ENV} must be a non-empty JSON object")
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        raise ValueError(f"{_PEERS_ENV} keys and values must be strings")
    return cast(dict[str, str], value)


def _configured_mode() -> str:
    value = os.environ.get(_MODE_ENV)
    if value not in {"disabled", "required"}:
        raise ValueError(f"{_MODE_ENV} must be explicitly set to 'disabled' or 'required'")
    return value


def capability_http_exchange_from_environment() -> HttpExchange:
    """Select explicit plaintext or required SPIRE mTLS without downgrade."""

    mode = _configured_mode()
    if mode == "disabled":
        return urllib_http_exchange
    expected_id = os.environ.get(_SELF_ID_ENV)
    if expected_id is None:
        raise ValueError(f"{_SELF_ID_ENV} is required when SPIRE mTLS is required")
    return SpireMtlsHttpExchange(
        identity_source=SpireWorkloadIdentityAdapter(
            expected_spiffe_id=validated_spiffe_id(expected_id, label=_SELF_ID_ENV)
        ),
        expected_peer_ids=_peer_map_from_environment(),
        key_boundary=TemporaryKeyMaterialBoundary.from_environment(),
    )


def _allowed_peer_ids(values: Sequence[str]) -> frozenset[str]:
    if not values:
        raise ValueError("at least one allowed client SPIFFE ID is required")
    return frozenset(
        validated_spiffe_id(value, label="allowed client SPIFFE ID") for value in values
    )


def spiffe_client_auth_protocol(allowed_ids: frozenset[str]) -> type[H11Protocol]:
    """Return a Uvicorn protocol enforcing a per-service client allowlist."""

    validated = _allowed_peer_ids(tuple(allowed_ids))

    class SpiffeClientAuthH11Protocol(H11Protocol):
        def connection_made(  # type: ignore[override]
            self,
            transport: asyncio.Transport,
        ) -> None:
            ssl_object = transport.get_extra_info("ssl_object")
            try:
                if ssl_object is None:
                    raise SpireMtlsError("service connection is not protected by TLS")
                certificate = ssl_object.getpeercert(binary_form=True)
                require_peer_spiffe_id(cast(bytes, certificate), validated)
            except (SpireMtlsError, ValueError):
                _LOGGER.warning("rejecting TLS connection from an unauthorized SPIFFE peer")
                transport.abort()
                return
            super().connection_made(transport)

    SpiffeClientAuthH11Protocol.__name__ = "SpiffeClientAuthH11Protocol"
    return SpiffeClientAuthH11Protocol


class _ServerIdentityRefresher:
    """Own a replaceable server context and fail closed on refresh loss."""

    def __init__(
        self,
        *,
        adapter: _IdentitySource,
        refresh_seconds: float,
        key_boundary: TemporaryKeyMaterialBoundary,
    ) -> None:
        if not math.isfinite(refresh_seconds) or refresh_seconds <= 0:
            raise ValueError("SPIRE refresh interval must be positive and finite")
        self._adapter = adapter
        self._refresh_seconds = refresh_seconds
        self._key_boundary = key_boundary
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._current: tuple[ssl.SSLContext, VerifiedWorkloadIdentity] | None = None
        self._fatal_callback: Callable[[Exception], None] | None = None
        self._fatal_error: Exception | None = None

    @property
    def fatal_error(self) -> Exception | None:
        with self._lock:
            return self._fatal_error

    @property
    def current_certificate_sha256(self) -> str | None:
        with self._lock:
            return self._current[1].certificate_sha256 if self._current else None

    def initialize(self) -> ssl.SSLContext:
        identity = self._adapter.fetch_and_verify()
        context = server_ssl_context(identity, key_boundary=self._key_boundary)
        with self._lock:
            self._current = (context, identity)
        context.set_servername_callback(cast(Any, self._select_context))
        return context

    def set_fatal_callback(self, callback: Callable[[Exception], None]) -> None:
        with self._lock:
            self._fatal_callback = callback
            error = self._fatal_error
        if error is not None:
            callback(error)

    def start(self) -> None:
        with self._lock:
            if self._current is None:
                raise RuntimeError("server TLS context must be initialized before refresh")
            if self._thread is not None:
                raise RuntimeError("server identity refresh is already running")
            self._thread = threading.Thread(
                target=self._refresh_loop,
                name="aegis-spire-mtls-refresh",
                daemon=True,
            )
            self._thread.start()

    def _select_context(
        self,
        tls_socket: ssl.SSLSocket,
        _server_name: str | None,
        _initial_context: ssl.SSLContext,
    ) -> None:
        with self._lock:
            current = self._current
            error = self._fatal_error
        now = datetime.now(tz=UTC)
        if (
            current is None
            or error is not None
            or now < current[1].not_before
            or now >= current[1].expires_at
        ):
            raise ssl.SSLError("current SPIRE server identity is unavailable")
        tls_socket.context = current[0]

    def _refresh_loop(self) -> None:
        while not self._stop.wait(self._refresh_seconds):
            try:
                identity = self._adapter.fetch_and_verify()
                context = server_ssl_context(identity, key_boundary=self._key_boundary)
            except (WorkloadIdentityError, SpireMtlsError, ValueError) as exc:
                self._invalidate(exc)
                return
            with self._lock:
                previous = self._current
                self._current = (context, identity)
            if previous is None or previous[1].certificate_sha256 != identity.certificate_sha256:
                _LOGGER.info(
                    "loaded rotated SPIRE server identity id=%s certificate_sha256=%s",
                    identity.spiffe_id,
                    identity.certificate_sha256,
                )

    def _invalidate(self, error: Exception) -> None:
        with self._lock:
            if self._fatal_error is not None:
                return
            self._fatal_error = error
            self._current = None
            callback = self._fatal_callback
        _LOGGER.error("SPIRE server identity refresh failed closed: %s", error)
        if callback is not None:
            callback(error)

    def close(self) -> None:
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=6.0)

    def __enter__(self) -> _ServerIdentityRefresher:
        self.initialize()
        self.start()
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()


def _server_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one Uvicorn service with SPIRE X.509-SVID mutual TLS"
    )
    parser.add_argument("--app", required=True)
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104 - container listener
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--expected-spiffe-id", required=True)
    parser.add_argument("--allowed-client-spiffe-id", action="append", required=True)
    parser.add_argument("--socket-path")
    parser.add_argument("--refresh-seconds", type=float, default=_DEFAULT_REFRESH_SECONDS)
    return parser


def run_server(argv: Sequence[str]) -> int:
    args = _server_parser().parse_args(argv)
    try:
        if _configured_mode() != "required":
            raise ValueError(f"{_MODE_ENV} must be 'required' for the SPIRE TLS server")
        expected_id = validated_spiffe_id(
            cast(str, args.expected_spiffe_id),
            label="expected server SPIFFE ID",
        )
        allowed_ids = _allowed_peer_ids(cast(list[str], args.allowed_client_spiffe_id))
        key_boundary = TemporaryKeyMaterialBoundary.from_environment()
        adapter = SpireWorkloadIdentityAdapter(
            expected_spiffe_id=expected_id,
            socket_path=cast(str | None, args.socket_path)
            or os.environ.get("SPIFFE_ENDPOINT_SOCKET", _DEFAULT_SOCKET),
        )
        refresher = _ServerIdentityRefresher(
            adapter=adapter,
            refresh_seconds=cast(float, args.refresh_seconds),
            key_boundary=key_boundary,
        )
        front_context = refresher.initialize()
    except (ValueError, WorkloadIdentityError, SpireMtlsError) as exc:
        _LOGGER.error("SPIRE mTLS server initialization failed: %s", exc)
        return 2

    config = uvicorn.Config(
        app=cast(str, args.app),
        host=cast(str, args.host),
        port=cast(int, args.port),
        http=spiffe_client_auth_protocol(allowed_ids),
        proxy_headers=False,
        server_header=False,
        timeout_keep_alive=0,
        ssl_context_factory=lambda _config, _default: front_context,
    )
    server = uvicorn.Server(config)
    refresher.set_fatal_callback(lambda _error: setattr(server, "should_exit", True))
    refresher.start()
    try:
        asyncio.run(server.serve())
    finally:
        refresher.close()
    return 2 if refresher.fatal_error is not None or not server.started else 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    if arguments[:1] != ["serve"]:
        _LOGGER.error("expected the 'serve' subcommand")
        return 2
    return run_server(arguments[1:])


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    raise SystemExit(main())
