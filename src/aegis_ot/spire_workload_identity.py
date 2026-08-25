"""Fail-closed SPIRE Workload API integration for Aegis-OT services.

The adapter fetches one short-lived X.509-SVID and its trust bundle from a
local SPIRE Agent.  It then independently checks the exact SPIFFE identity,
leaf profile, key binding, lifetime, and certification path before returning
material to the mTLS layer.  Registration deletion prevents future issuance;
it is not represented here as immediate revocation of an already-issued SVID.
"""

from __future__ import annotations

import argparse
import logging
import math
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from cryptography.x509.verification import (
    ExtensionPolicy,
    PolicyBuilder,
    Store,
    VerificationError,
)
from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.svid.x509_svid import X509Svid
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.workloadapi.x509_context import X509Context

_LOGGER = logging.getLogger(__name__)
_DEFAULT_SOCKET = "unix:///run/spire/agent/public/api.sock"
_DEFAULT_FETCH_TIMEOUT_SECONDS = 5.0
_DEFAULT_MAX_SVID_TTL = timedelta(minutes=10)
_DEFAULT_MIN_REMAINING_LIFETIME = timedelta(seconds=30)
AEGIS_SPIFFE_TRUST_DOMAIN = "aegis-ot.m4g.local"


class WorkloadIdentityError(RuntimeError):
    """SPIRE identity material could not be fetched or trusted."""


class _WorkloadApiClient(Protocol):
    def fetch_x509_context(self, timeout: float | None = None) -> X509Context: ...

    def close(self) -> None: ...


_ClientFactory = Callable[[str, float], _WorkloadApiClient]
_Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class VerifiedWorkloadIdentity:
    """Verified workload material plus non-secret audit attributes."""

    spiffe_id: str
    fetched_at: datetime
    not_before: datetime
    expires_at: datetime
    certificate_sha256: str
    svid: X509Svid = field(repr=False, compare=False)
    trust_bundle: X509Bundle = field(repr=False, compare=False)


def _default_client_factory(socket_path: str, timeout: float) -> WorkloadApiClient:
    return WorkloadApiClient(socket_path=socket_path, default_timeout=timeout)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def validated_spiffe_id(value: str, *, label: str) -> str:
    """Return a canonical workload SPIFFE ID or reject it."""

    try:
        parsed = SpiffeId(value)
    except Exception as exc:
        raise ValueError(f"{label} must be a valid SPIFFE ID") from exc
    if not parsed.path:
        raise ValueError(f"{label} must identify a workload path")
    if parsed.trust_domain.name != AEGIS_SPIFFE_TRUST_DOMAIN:
        raise ValueError(f"{label} must use the {AEGIS_SPIFFE_TRUST_DOMAIN} trust domain")
    return str(parsed)


class SpireWorkloadIdentityAdapter:
    """Fetch and verify exactly one expected X.509-SVID."""

    def __init__(
        self,
        *,
        expected_spiffe_id: str,
        socket_path: str | None = None,
        fetch_timeout_seconds: float = _DEFAULT_FETCH_TIMEOUT_SECONDS,
        max_svid_ttl: timedelta = _DEFAULT_MAX_SVID_TTL,
        minimum_remaining_lifetime: timedelta = _DEFAULT_MIN_REMAINING_LIFETIME,
        clock: _Clock = _utc_now,
        client_factory: _ClientFactory = _default_client_factory,
    ) -> None:
        expected_id = validated_spiffe_id(
            expected_spiffe_id,
            label="expected_spiffe_id",
        )
        resolved_socket = socket_path or os.environ.get(
            "SPIFFE_ENDPOINT_SOCKET",
            _DEFAULT_SOCKET,
        )
        parsed_socket = urlparse(resolved_socket)
        if (
            parsed_socket.scheme != "unix"
            or not parsed_socket.path.startswith("/")
            or parsed_socket.netloc
            or parsed_socket.params
            or parsed_socket.query
            or parsed_socket.fragment
        ):
            raise ValueError("socket_path must be an absolute unix:/// Workload API endpoint")
        if not math.isfinite(fetch_timeout_seconds) or fetch_timeout_seconds <= 0:
            raise ValueError("fetch_timeout_seconds must be positive and finite")
        if max_svid_ttl <= timedelta(0):
            raise ValueError("max_svid_ttl must be positive")
        if minimum_remaining_lifetime < timedelta(0):
            raise ValueError("minimum_remaining_lifetime cannot be negative")
        if minimum_remaining_lifetime >= max_svid_ttl:
            raise ValueError("minimum_remaining_lifetime must be shorter than max_svid_ttl")

        self._expected_id = SpiffeId(expected_id)
        self._socket_path = resolved_socket
        self._fetch_timeout_seconds = fetch_timeout_seconds
        self._max_svid_ttl = max_svid_ttl
        self._minimum_remaining_lifetime = minimum_remaining_lifetime
        self._clock = clock
        self._client_factory = client_factory

    def fetch_and_verify(self) -> VerifiedWorkloadIdentity:
        """Fetch a current context, close the client, and verify locally."""

        client: _WorkloadApiClient | None = None
        try:
            client = self._client_factory(self._socket_path, self._fetch_timeout_seconds)
            context = client.fetch_x509_context(timeout=self._fetch_timeout_seconds)
        except Exception as exc:
            raise WorkloadIdentityError("SPIRE Workload API fetch failed") from exc
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    _LOGGER.warning("SPIRE Workload API client close failed", exc_info=True)
        return self.verify_context(context)

    def verify_context(self, context: X509Context) -> VerifiedWorkloadIdentity:
        """Verify identity, lifetime, key binding, profile, and RFC 5280 path."""

        svids = context.x509_svids
        if len(svids) != 1:
            raise WorkloadIdentityError("expected exactly one X.509-SVID")
        svid = svids[0]
        actual_id = str(svid.spiffe_id)
        expected_id = str(self._expected_id)
        if actual_id != expected_id:
            raise WorkloadIdentityError("X.509-SVID does not match the expected workload identity")

        bundle = context.x509_bundle_set.get_bundle_for_trust_domain(svid.spiffe_id.trust_domain)
        if bundle is None or not bundle.x509_authorities:
            raise WorkloadIdentityError(
                "no X.509 trust bundle exists for the workload trust domain"
            )

        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise WorkloadIdentityError("verification clock must return a timezone-aware datetime")
        now = now.astimezone(UTC)
        leaf = svid.leaf
        not_before = leaf.not_valid_before_utc
        expires_at = leaf.not_valid_after_utc
        if now < not_before:
            raise WorkloadIdentityError("X.509-SVID is not yet valid")
        if now >= expires_at:
            raise WorkloadIdentityError("X.509-SVID is expired")
        if expires_at - not_before > self._max_svid_ttl:
            raise WorkloadIdentityError("X.509-SVID lifetime exceeds the configured maximum")
        if expires_at - now < self._minimum_remaining_lifetime:
            raise WorkloadIdentityError("X.509-SVID has insufficient remaining lifetime")

        self._verify_leaf_profile(leaf, expected_id)
        self._verify_key_binding(svid)
        self._verify_trust_path(svid, bundle, now)
        return VerifiedWorkloadIdentity(
            spiffe_id=actual_id,
            fetched_at=now,
            not_before=not_before,
            expires_at=expires_at,
            certificate_sha256=leaf.fingerprint(hashes.SHA256()).hex(),
            svid=svid,
            trust_bundle=bundle,
        )

    @staticmethod
    def _verify_leaf_profile(leaf: x509.Certificate, expected_id: str) -> None:
        try:
            san_extension = leaf.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            constraints_extension = leaf.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            key_usage_extension = leaf.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        except x509.ExtensionNotFound as exc:
            raise WorkloadIdentityError("X.509-SVID is missing a required leaf extension") from exc

        san = cast(x509.SubjectAlternativeName, san_extension.value)
        uri_sans = san.get_values_for_type(x509.UniformResourceIdentifier)
        if uri_sans != [expected_id]:
            raise WorkloadIdentityError("X.509-SVID URI SAN is not the expected SPIFFE ID")
        if san.get_values_for_type(x509.DNSName):
            raise WorkloadIdentityError("X.509-SVID must not contain DNS SANs")

        constraints = cast(x509.BasicConstraints, constraints_extension.value)
        if constraints.ca:
            raise WorkloadIdentityError("X.509-SVID leaf certificate is a CA")
        usage = cast(x509.KeyUsage, key_usage_extension.value)
        if not key_usage_extension.critical:
            raise WorkloadIdentityError("X.509-SVID key usage extension is not critical")
        if not usage.digital_signature or usage.key_cert_sign or usage.crl_sign:
            raise WorkloadIdentityError("X.509-SVID leaf key usage is invalid")

        try:
            extended_usage = cast(
                x509.ExtendedKeyUsage,
                leaf.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value,
            )
        except x509.ExtensionNotFound:
            return
        required = {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH}
        if not required.issubset(set(extended_usage)):
            raise WorkloadIdentityError("X.509-SVID extended key usage is incomplete")

    @staticmethod
    def _verify_key_binding(svid: X509Svid) -> None:
        encoding = serialization.Encoding.DER
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
        leaf_public = svid.leaf.public_key().public_bytes(encoding, public_format)
        private_public = svid.private_key.public_key().public_bytes(encoding, public_format)
        if leaf_public != private_public:
            raise WorkloadIdentityError("X.509-SVID private key does not match its certificate")

    @staticmethod
    def _verify_trust_path(svid: X509Svid, bundle: X509Bundle, now: datetime) -> None:
        try:
            verifier = (
                PolicyBuilder()
                .store(Store(list(bundle.x509_authorities)))
                .time(now)
                .extension_policies(
                    ee_policy=ExtensionPolicy.permit_all(),
                    ca_policy=ExtensionPolicy.webpki_defaults_ca(),
                )
                .build_client_verifier()
            )
            verifier.verify(svid.leaf, svid.cert_chain[1:])
        except (VerificationError, ValueError) as exc:
            raise WorkloadIdentityError("X.509-SVID certification path is not trusted") from exc


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify an expected SPIRE X.509-SVID before starting a workload"
    )
    parser.add_argument("--expected-spiffe-id", required=True)
    parser.add_argument("--socket-path")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    command = cast(list[str], args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        _LOGGER.error("no workload command was provided after --")
        return 2
    try:
        identity = SpireWorkloadIdentityAdapter(
            expected_spiffe_id=cast(str, args.expected_spiffe_id),
            socket_path=cast(str | None, args.socket_path),
        ).fetch_and_verify()
    except (ValueError, WorkloadIdentityError) as exc:
        _LOGGER.error("SPIRE workload identity preflight failed: %s", exc)
        return 2
    _LOGGER.info(
        "verified SPIRE workload identity id=%s certificate_sha256=%s expires_at=%s",
        identity.spiffe_id,
        identity.certificate_sha256,
        identity.expires_at.isoformat(),
    )
    try:
        os.execvp(command[0], command)  # noqa: S606 - intentional PID-preserving exec
    except OSError as exc:
        _LOGGER.error("unable to start workload command: %s", exc)
        return 127


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    raise SystemExit(main())
