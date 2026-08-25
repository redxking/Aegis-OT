from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.svid.x509_svid import X509Svid
from spiffe.workloadapi.x509_context import X509Context

from aegis_ot.spire_workload_identity import (
    SpireWorkloadIdentityAdapter,
    WorkloadIdentityError,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 25, 16, 0, tzinfo=UTC)
TRUST_DOMAIN = "aegis-ot.m4g.local"
GATEWAY_ID = f"spiffe://{TRUST_DOMAIN}/workload/gateway"


@dataclass(frozen=True)
class _Materials:
    context: X509Context
    svid: X509Svid
    bundle_set: X509BundleSet


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


def _materials(
    *,
    spiffe_id: str = GATEWAY_ID,
    not_before: datetime = NOW - timedelta(seconds=5),
    expires_at: datetime = NOW + timedelta(seconds=295),
    key_usage_critical: bool = True,
    extra_uri_sans: tuple[str, ...] = (),
    dns_sans: tuple[str, ...] = (),
    include_eku: bool = True,
    eku: tuple[x509.ObjectIdentifier, ...] = (
        ExtendedKeyUsageOID.CLIENT_AUTH,
        ExtendedKeyUsageOID.SERVER_AUTH,
    ),
) -> _Materials:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegis SPIRE test root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_key_usage(ca=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    san_values: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(value) for value in (spiffe_id, *extra_uri_sans)
    ]
    san_values.extend(x509.DNSName(value) for value in dns_sans)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(expires_at)
        .add_extension(x509.SubjectAlternativeName(san_values), critical=True)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(ca=False), critical=key_usage_critical)
    )
    if include_eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
    leaf = (
        builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False
        )
        .sign(root_key, hashes.SHA256())
    )
    parsed_id = SpiffeId(spiffe_id)
    svid = X509Svid(parsed_id, [leaf], leaf_key)
    bundle = X509Bundle(parsed_id.trust_domain, {root})
    bundle_set = X509BundleSet.of([bundle])
    return _Materials(X509Context([svid], bundle_set), svid, bundle_set)


class _FakeClient:
    def __init__(self, context: X509Context, error: Exception | None = None) -> None:
        self.context = context
        self.error = error
        self.closed = False
        self.timeout: float | None = None

    def fetch_x509_context(self, timeout: float | None = None) -> X509Context:
        self.timeout = timeout
        if self.error is not None:
            raise self.error
        return self.context

    def close(self) -> None:
        self.closed = True


def _adapter(materials: _Materials, **overrides: Any) -> SpireWorkloadIdentityAdapter:
    return SpireWorkloadIdentityAdapter(
        expected_spiffe_id=GATEWAY_ID,
        clock=lambda: NOW,
        client_factory=lambda _socket, _timeout: _FakeClient(materials.context),
        **overrides,
    )


def test_fetches_closes_and_verifies_exact_short_lived_svid() -> None:
    materials = _materials()
    client = _FakeClient(materials.context)
    factory_args: list[tuple[str, float]] = []

    def factory(socket_path: str, timeout: float) -> _FakeClient:
        factory_args.append((socket_path, timeout))
        return client

    identity = SpireWorkloadIdentityAdapter(
        expected_spiffe_id=GATEWAY_ID,
        clock=lambda: NOW,
        client_factory=factory,
    ).fetch_and_verify()

    assert identity.spiffe_id == GATEWAY_ID
    assert identity.fetched_at == NOW
    assert identity.expires_at == NOW + timedelta(seconds=295)
    assert re.fullmatch(r"[0-9a-f]{64}", identity.certificate_sha256)
    assert identity.svid is materials.svid
    assert client.closed is True
    assert client.timeout == 5.0
    assert factory_args == [("unix:///run/spire/agent/public/api.sock", 5.0)]


def test_fetch_failure_is_closed_and_client_is_closed() -> None:
    materials = _materials()
    client = _FakeClient(materials.context, OSError("socket unavailable"))
    adapter = SpireWorkloadIdentityAdapter(
        expected_spiffe_id=GATEWAY_ID,
        clock=lambda: NOW,
        client_factory=lambda _socket, _timeout: client,
    )

    with pytest.raises(WorkloadIdentityError, match="Workload API fetch failed"):
        adapter.fetch_and_verify()
    assert client.closed is True


def test_rejects_wrong_ambiguous_and_extra_san_identities() -> None:
    observer = _materials(spiffe_id=f"spiffe://{TRUST_DOMAIN}/workload/observer")
    with pytest.raises(WorkloadIdentityError, match="expected workload identity"):
        _adapter(observer).verify_context(observer.context)

    gateway = _materials()
    ambiguous_context = X509Context([gateway.svid, gateway.svid], gateway.bundle_set)
    with pytest.raises(WorkloadIdentityError, match="exactly one"):
        _adapter(gateway).verify_context(ambiguous_context)

    extra_uri = _materials(extra_uri_sans=(f"spiffe://{TRUST_DOMAIN}/workload/observer",))
    with pytest.raises(WorkloadIdentityError, match="URI SAN"):
        _adapter(extra_uri).verify_context(extra_uri.context)

    dns = _materials(dns_sans=("gateway",))
    with pytest.raises(WorkloadIdentityError, match="DNS SAN"):
        _adapter(dns).verify_context(dns.context)


def test_rejects_untrusted_signer_and_private_key_mismatch() -> None:
    trusted = _materials()
    untrusted = _materials()
    wrong_bundle_context = X509Context([untrusted.svid], trusted.bundle_set)
    with pytest.raises(WorkloadIdentityError, match="certification path"):
        _adapter(trusted).verify_context(wrong_bundle_context)

    mismatched_svid = X509Svid(
        trusted.svid.spiffe_id,
        trusted.svid.cert_chain,
        ec.generate_private_key(ec.SECP256R1()),
    )
    mismatched_context = X509Context([mismatched_svid], trusted.bundle_set)
    with pytest.raises(WorkloadIdentityError, match="private key"):
        _adapter(trusted).verify_context(mismatched_context)


@pytest.mark.parametrize(
    ("not_before", "expires_at", "message"),
    [
        (NOW + timedelta(seconds=1), NOW + timedelta(minutes=5), "not yet valid"),
        (NOW - timedelta(minutes=5), NOW, "expired"),
        (NOW - timedelta(seconds=1), NOW + timedelta(minutes=11), "configured maximum"),
        (NOW - timedelta(minutes=5), NOW + timedelta(seconds=29), "remaining lifetime"),
    ],
)
def test_rejects_invalid_time_windows(
    not_before: datetime,
    expires_at: datetime,
    message: str,
) -> None:
    materials = _materials(not_before=not_before, expires_at=expires_at)
    with pytest.raises(WorkloadIdentityError, match=message):
        _adapter(materials).verify_context(materials.context)


def test_rejects_invalid_leaf_profiles() -> None:
    noncritical = _materials(key_usage_critical=False)
    with pytest.raises(WorkloadIdentityError, match="key usage extension is not critical"):
        _adapter(noncritical).verify_context(noncritical.context)

    incomplete_eku = _materials(eku=(ExtendedKeyUsageOID.CLIENT_AUTH,))
    with pytest.raises(WorkloadIdentityError, match="extended key usage is incomplete"):
        _adapter(incomplete_eku).verify_context(incomplete_eku.context)

    no_eku = _materials(include_eku=False)
    assert _adapter(no_eku).verify_context(no_eku.context).spiffe_id == GATEWAY_ID


@pytest.mark.parametrize(
    "socket_path",
    ["tcp://127.0.0.1:8080", "unix://relative.sock", "unix:///run/sock?query=1"],
)
def test_rejects_non_local_or_noncanonical_workload_api_endpoint(socket_path: str) -> None:
    with pytest.raises(ValueError, match="absolute unix"):
        SpireWorkloadIdentityAdapter(
            expected_spiffe_id=GATEWAY_ID,
            socket_path=socket_path,
        )


def test_rejects_nonfinite_fetch_timeout() -> None:
    with pytest.raises(ValueError, match="positive and finite"):
        SpireWorkloadIdentityAdapter(
            expected_spiffe_id=GATEWAY_ID,
            fetch_timeout_seconds=float("nan"),
        )


def test_rejects_foreign_spiffe_trust_domain() -> None:
    with pytest.raises(ValueError, match=TRUST_DOMAIN):
        SpireWorkloadIdentityAdapter(expected_spiffe_id="spiffe://foreign.example/workload/gateway")


def test_registration_uses_shared_uid_and_service_specific_gid_selectors() -> None:
    registration = json.loads(
        (ROOT / "infra/spire/registration-entries.json").read_text(encoding="utf-8")
    )
    expected_gids = {
        "gateway": "gid:65532",
        "observer": "gid:65533",
        "candidate": "gid:65534",
        "ot-adapter": "gid:65535",
        "plant": "gid:65536",
    }
    entries = registration["entries"]
    assert len(entries) == 5
    assert len({entry["entry_id"] for entry in entries}) == 5
    for entry in entries:
        role = entry["spiffe_id"].rsplit("/", 1)[1]
        selectors = {item["value"] for item in entry["selectors"]}
        assert selectors == {"uid:65532", expected_gids[role]}
        assert entry["parent_id"] == f"spiffe://{TRUST_DOMAIN}/agent/compose"
        assert entry["x509_svid_ttl"] == 300

    assert f'trust_domain = "{TRUST_DOMAIN}"' in (ROOT / "infra/spire/server.conf").read_text(
        encoding="utf-8"
    )
    assert f'trust_domain = "{TRUST_DOMAIN}"' in (ROOT / "infra/spire/agent.conf").read_text(
        encoding="utf-8"
    )

    agent_config = (ROOT / "infra/spire/agent.conf").read_text(encoding="utf-8")
    server_config = (ROOT / "infra/spire/server.conf").read_text(encoding="utf-8")
    assert "insecure_bootstrap" not in agent_config
    assert 'trust_bundle_path = "/run/spire/bootstrap/bundle.pem"' in agent_config
    assert 'join_token_file = "/run/spire/bootstrap/join-token"' in agent_config
    assert 'default_x509_svid_ttl = "5m"' in server_config
    assert "disable_jwt_svids = true" in server_config

    bootstrap_dockerfile = (ROOT / "infra/spire/Dockerfile.bootstrap").read_text(encoding="utf-8")
    digest_pin = re.compile(r"[^\s]+:[^@\s]+@sha256:[0-9a-f]{64}")
    assert len(digest_pin.findall(bootstrap_dockerfile)) == 2


def test_bootstrap_is_idempotent_and_writes_private_join_material(tmp_path: Path) -> None:
    fake_spire = tmp_path / "fake-spire-server"
    calls_file = tmp_path / "calls"
    fake_spire.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$*" >> "$SPIRE_FAKE_CALLS"\n'
        'case "$1:$2" in\n'
        "  bundle:show) printf '%s\\n' '-----BEGIN CERTIFICATE-----' 'test' "
        "'-----END CERTIFICATE-----' ;;\n"
        "  token:generate) printf '%s\\n' '{\"value\":\"test-join-token\"}' ;;\n"
        "  entry:create) exit 0 ;;\n"
        "  *) exit 9 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    fake_spire.chmod(0o755)
    output_dir = tmp_path / "bootstrap"
    environment = {
        **os.environ,
        "SPIRE_SERVER_BIN": str(fake_spire),
        "SPIRE_SERVER_SOCKET": str(tmp_path / "server.sock"),
        "SPIRE_BOOTSTRAP_DIR": str(output_dir),
        "SPIRE_REGISTRATION_FILE": str(ROOT / "infra/spire/registration-entries.json"),
        "SPIRE_FAKE_CALLS": str(calls_file),
    }

    for _ in range(2):
        subprocess.run(  # noqa: S603 - fixed interpreter and repository-owned script
            ["/bin/sh", str(ROOT / "infra/spire/bootstrap.sh")],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )

    assert (output_dir / "join-token").read_text(encoding="utf-8") == "test-join-token\n"
    assert (output_dir / "join-token").stat().st_mode & 0o777 == 0o600
    assert "BEGIN CERTIFICATE" in (output_dir / "bundle.pem").read_text(encoding="utf-8")
    calls = calls_file.read_text(encoding="utf-8").splitlines()
    assert sum(line.startswith("token generate") for line in calls) == 1
    assert sum(line.startswith("entry create") for line in calls) == 1
    assert sum(line.startswith("bundle show") for line in calls) == 2
