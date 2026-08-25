"""Run one bounded M4g SPIRE/mTLS fail-closed experiment.

The experiment composes the committed application workload-identity controls
with an actual SPIRE server, agent, X.509-SVID issuance, and mutually
authenticated TLS on the internal capability links.  It retains no private
keys, certificate bodies, join tokens, or trust bundles.  Registration
deletion is reported as loss of fresh issuance; it is not described as
immediate cryptographic revocation of an already-issued certificate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import run_m4d_experiment as m4d
import run_m4g_experiment as m4g

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_OVERLAYS = (
    "docker-compose.yml",
    "docker-compose.auth.yml",
    "docker-compose.replay.yml",
    "docker-compose.capability.yml",
    "docker-compose.identity.yml",
    "docker-compose.spire.yml",
)
WORKLOADS: dict[str, tuple[str, str]] = {
    "segmented-gateway": (
        "65532:65532",
        "spiffe://aegis-ot.m4g.local/workload/gateway",
    ),
    "observer": (
        "65532:65533",
        "spiffe://aegis-ot.m4g.local/workload/observer",
    ),
    "candidate": (
        "65532:65534",
        "spiffe://aegis-ot.m4g.local/workload/candidate",
    ),
    "ot-adapter": (
        "65532:65535",
        "spiffe://aegis-ot.m4g.local/workload/ot-adapter",
    ),
    "simulation": (
        "65532:65536",
        "spiffe://aegis-ot.m4g.local/workload/plant",
    ),
}
SPIRE_SERVICES = (
    "spire-storage-init",
    "spire-server",
    "spire-bootstrap",
    "spire-agent",
)
RUNTIME_SERVICES = (
    "opa",
    "identity-init",
    "replay-init",
    *SPIRE_SERVICES,
    "simulation",
    "observer",
    "candidate",
    "ot-adapter",
    "segmented-gateway",
)
OPERATIONAL_SERVICES = (
    "opa",
    "simulation",
    "observer",
    "candidate",
    "ot-adapter",
    "segmented-gateway",
)
APP_BUILD_SERVICES = (
    "identity-init",
    "replay-init",
    "simulation",
    "observer",
    "candidate",
    "ot-adapter",
    "segmented-gateway",
    "agent-probe",
)
APP_IDENTITY_REQUIRED_SERVICES = (
    "segmented-gateway",
    "ot-adapter",
    "replay-init",
    "agent-probe",
)
MTLS_CLIENT_SERVICES = (
    "segmented-gateway",
    "observer",
    "candidate",
    "ot-adapter",
)
MTLS_SERVER_SERVICES = (
    "observer",
    "candidate",
    "ot-adapter",
    "simulation",
)
MTLS_URL_VARIABLES: dict[str, tuple[str, ...]] = {
    "segmented-gateway": (
        "AEGIS_OBSERVER_URL",
        "AEGIS_CANDIDATE_URL",
        "AEGIS_OT_URL",
    ),
    "observer": ("AEGIS_PLANT_URL",),
    "candidate": ("AEGIS_PLANT_URL",),
    "ot-adapter": ("AEGIS_OBSERVER_URL", "AEGIS_PLANT_URL"),
}
EXPECTED_MTLS_PEERS: dict[str, dict[str, str]] = {
    "segmented-gateway": {
        "candidate": WORKLOADS["candidate"][1],
        "observer": WORKLOADS["observer"][1],
        "ot-adapter": WORKLOADS["ot-adapter"][1],
    },
    "observer": {"simulation": WORKLOADS["simulation"][1]},
    "candidate": {"simulation": WORKLOADS["simulation"][1]},
    "ot-adapter": {
        "observer": WORKLOADS["observer"][1],
        "simulation": WORKLOADS["simulation"][1],
    },
}
EXPECTED_MTLS_CLIENTS: dict[str, frozenset[str]] = {
    "observer": frozenset({WORKLOADS["segmented-gateway"][1], WORKLOADS["ot-adapter"][1]}),
    "candidate": frozenset({WORKLOADS["segmented-gateway"][1]}),
    "ot-adapter": frozenset({WORKLOADS["segmented-gateway"][1]}),
    "simulation": frozenset(
        {
            WORKLOADS["observer"][1],
            WORKLOADS["candidate"][1],
            WORKLOADS["ot-adapter"][1],
        }
    ),
}
SOURCE_BINDING_FILES = (
    *COMPOSE_OVERLAYS,
    "Dockerfile",
    "infra/spire/Dockerfile.bootstrap",
    "infra/spire/agent.conf",
    "infra/spire/bootstrap.sh",
    "infra/spire/registration-entries.json",
    "infra/spire/server.conf",
    "pyproject.toml",
    "requirements.lock",
    "src/aegis_ot/m4g_probe.py",
    "src/aegis_ot/segmented_capability_runtime.py",
    "src/aegis_ot/segmented_capability_transport.py",
    "src/aegis_ot/spire_mtls.py",
    "src/aegis_ot/spire_workload_identity.py",
    "src/aegis_ot/workload_identity.py",
    "src/aegis_ot/workload_runtime.py",
    "scripts/run_m4g_experiment.py",
    "scripts/run_m4g_spire_mtls_experiment.py",
)
GATEWAY_ENTRY_ID = "m4g-workload-gateway-v1"
DEFAULT_ROTATION_TIMEOUT_SECONDS = 240.0
DEFAULT_ROTATION_POLL_SECONDS = 5.0
DEFAULT_FETCH_LOSS_TIMEOUT_SECONDS = 30.0
DEFAULT_FETCH_LOSS_POLL_SECONDS = 0.5

_DIGEST_PIN = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")
_GIT_OBJECT = re.compile(r"^[0-9a-f]{40,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_OT_EXECUTE_LOG_MARKER = "POST /v1/capability/execute"
_MTLS_TMPDIR = "/run/aegis-spire-mtls"

_IDENTITY_QUERY_CODE = r"""
import json
import sys
from datetime import timedelta
from aegis_ot.spire_workload_identity import (
    SpireWorkloadIdentityAdapter,
    WorkloadIdentityError,
)

expected = sys.argv[1]
try:
    identity = SpireWorkloadIdentityAdapter(
        expected_spiffe_id=expected,
        max_svid_ttl=timedelta(minutes=10),
        minimum_remaining_lifetime=timedelta(seconds=0),
    ).fetch_and_verify()
except (ValueError, WorkloadIdentityError) as exc:
    result = {
        "schema_version": "m4g-spire-identity-query-v1",
        "expected_spiffe_id": expected,
        "accepted": False,
        "error_type": type(exc).__name__,
        "reason": str(exc),
    }
else:
    result = {
        "schema_version": "m4g-spire-identity-query-v1",
        "expected_spiffe_id": expected,
        "accepted": True,
        "spiffe_id": identity.spiffe_id,
        "fetched_at": identity.fetched_at.isoformat(),
        "not_before": identity.not_before.isoformat(),
        "expires_at": identity.expires_at.isoformat(),
        "certificate_sha256": identity.certificate_sha256,
    }
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
""".strip()

_PREPARE_FRESH_ACTION_CODE = r"""
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4
from aegis_ot.m4g_probe import (
    _await_gateway,
    _capture_pre,
    _gateway_url,
    _request,
)
from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    WorkloadAuthenticatedCapabilityAction,
)
from aegis_ot.workload_identity import WorkloadRole
from aegis_ot.workload_runtime import (
    local_identity_from_environment,
    verifier_from_environment,
)

url = _gateway_url()
_await_gateway(url)
observation = _capture_pre(url, str(uuid4()))
request = _request(
    observation,
    proposal_id=f"m4g-spire-post-delete-{uuid4()}",
    critical_load_impact_pct=5.0,
)
verifier = verifier_from_environment()
agent = local_identity_from_environment(
    verifier,
    "AGENT",
    role=WorkloadRole.AGENT,
    audience=GATEWAY_CAPABILITY_AUDIENCE,
)
issued_at = datetime.now(UTC)
wire = WorkloadAuthenticatedCapabilityAction.issue(
    request=request,
    signer=agent.signer,
    request_nonce=request.proposal.nonce,
    issued_at=issued_at,
    expires_at=issued_at + timedelta(seconds=60),
)
print(json.dumps({
    "schema_version": "m4g-spire-prepared-action-v1",
    "wire_request": wire.model_dump(mode="json"),
    "wire_request_sha256": wire.digest,
    "request_sha256": request.digest,
    "proposal_id": request.proposal.proposal_id,
    "proposal_nonce": request.proposal.nonce,
    "observation_id": request.observation_id,
    "proof_expires_at": wire.expires_at.isoformat(),
}, sort_keys=True, separators=(",", ":")))
""".strip()

_MTLS_HEALTH_CODE = r"""
import hashlib
import json
import sys
from aegis_ot.spire_mtls import capability_http_exchange_from_environment

response = capability_http_exchange_from_environment()(
    method="GET",
    url=sys.argv[1],
    body=None,
    headers={"Accept": "application/json"},
    timeout_seconds=5.0,
)
document = json.loads(response.body)
print(json.dumps({
    "status_code": response.status_code,
    "content_type": response.content_type,
    "wire_sha256": hashlib.sha256(response.body).hexdigest(),
    "document": document,
}, sort_keys=True, separators=(",", ":")))
""".strip()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _canonical_text(value: Any) -> str:
    return _canonical_bytes(value).decode("utf-8") + "\n"


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _parse_json_object(raw: str, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise m4d.ExperimentError(f"{label} was not JSON") from exc
    if not isinstance(value, dict):
        raise m4d.ExperimentError(f"{label} was not an object")
    return value


def _required_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise m4d.ExperimentError(f"{label} was not an object")
    return value


def _required_string(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise m4d.ExperimentError(f"{label} was not a non-empty string")
    return value


def _parse_utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise m4d.ExperimentError(f"{label} was not a timestamp string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise m4d.ExperimentError(f"{label} was not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise m4d.ExperimentError(f"{label} was not timezone-aware")
    return parsed.astimezone(UTC)


def _validate_project_name(project_name: str) -> None:
    if _PROJECT_NAME.fullmatch(project_name) is None:
        raise m4d.ExperimentError(
            "M4g SPIRE/mTLS project name must be a bounded lowercase Compose name"
        )


def _compose_prefix(project_name: str) -> tuple[str, ...]:
    files: list[str] = []
    for overlay in COMPOSE_OVERLAYS:
        files.extend(("-f", overlay))
    return ("docker", "compose", "-p", project_name, *files)


def _file_sha256(relative_path: str) -> str:
    path = ROOT / relative_path
    if not path.is_file() or path.is_symlink():
        raise m4d.ExperimentError(f"source-binding file was missing: {relative_path}")
    return _sha256(path.read_bytes())


def _source_binding(commit: str) -> dict[str, Any]:
    checkout = m4g._assert_source_checkout()
    tree = m4d._run("git", "rev-parse", "HEAD^{tree}").stdout.strip()
    if _GIT_OBJECT.fullmatch(tree) is None:
        raise m4d.ExperimentError("git tree binding was malformed")
    files = {path: _file_sha256(path) for path in SOURCE_BINDING_FILES}
    binding = {
        "git_commit": commit,
        "git_tree": tree,
        "checkout": checkout,
        "files": files,
    }
    binding["source_fingerprint_sha256"] = _sha256(_canonical_bytes(binding))
    return binding


def _service(compose: dict[str, Any], name: str) -> dict[str, Any]:
    services = _required_mapping(compose.get("services"), label="Compose services")
    return _required_mapping(services.get(name), label=f"Compose service {name}")


def _environment(compose: dict[str, Any], name: str) -> dict[str, Any]:
    return _required_mapping(
        _service(compose, name).get("environment"),
        label=f"{name} environment",
    )


def _entrypoint(compose: dict[str, Any], name: str) -> list[str]:
    value = _service(compose, name).get("entrypoint")
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise m4d.ExperimentError(f"{name} entrypoint was malformed")
    return value


def _flag_values(entrypoint: list[str], flag: str) -> list[str]:
    values: list[str] = []
    for index, item in enumerate(entrypoint):
        if item == flag:
            if index + 1 >= len(entrypoint):
                raise m4d.ExperimentError(f"entrypoint flag had no value: {flag}")
            values.append(entrypoint[index + 1])
    return values


def _read_only_spire_socket(service: dict[str, Any]) -> bool:
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        return False
    return any(
        isinstance(item, dict)
        and item.get("target") == "/run/spire/agent/public"
        and item.get("read_only") is True
        for item in volumes
    )


def _private_mtls_tmpfs(service: dict[str, Any], expected_user: str) -> bool:
    tmpfs = service.get("tmpfs")
    if not isinstance(tmpfs, list):
        return False
    uid, gid = expected_user.split(":", 1)
    required = {
        "rw",
        "noexec",
        "nosuid",
        "nodev",
        "mode=0700",
        f"uid={uid}",
        f"gid={gid}",
    }
    for value in tmpfs:
        if not isinstance(value, str):
            continue
        target, separator, raw_options = value.partition(":")
        if separator and target == _MTLS_TMPDIR and required.issubset(set(raw_options.split(","))):
            return True
    return False


def _configuration_binding(compose: dict[str, Any]) -> dict[str, Any]:
    pins = {
        "opa.image": _required_string(_service(compose, "opa").get("image"), label="OPA image"),
        "spire-server.image": _required_string(
            _service(compose, "spire-server").get("image"),
            label="SPIRE server image",
        ),
        "spire-agent.image": _required_string(
            _service(compose, "spire-agent").get("image"),
            label="SPIRE agent image",
        ),
        "spire-storage-init.image": _required_string(
            _service(compose, "spire-storage-init").get("image"),
            label="SPIRE storage initializer image",
        ),
    }
    bootstrap_build = _required_mapping(
        _service(compose, "spire-bootstrap").get("build"),
        label="SPIRE bootstrap build",
    )
    bootstrap_args = _required_mapping(
        bootstrap_build.get("args"), label="SPIRE bootstrap build args"
    )
    for argument in ("SPIRE_SERVER_IMAGE", "BUSYBOX_IMAGE"):
        pins[f"spire-bootstrap.{argument}"] = _required_string(
            bootstrap_args.get(argument), label=f"SPIRE bootstrap {argument}"
        )

    application_modes = {
        name: _environment(compose, name).get("AEGIS_WORKLOAD_IDENTITY_MODE")
        for name in APP_IDENTITY_REQUIRED_SERVICES
    }
    workload_bindings: dict[str, dict[str, Any]] = {}
    for name, (expected_user, expected_id) in WORKLOADS.items():
        service = _service(compose, name)
        environment = _environment(compose, name)
        entrypoint = _entrypoint(compose, name)
        configured_ids = _flag_values(entrypoint, "--expected-spiffe-id")
        workload_bindings[name] = {
            "configured_user": service.get("user"),
            "expected_user": expected_user,
            "configured_spiffe_id": configured_ids[0] if len(configured_ids) == 1 else None,
            "expected_spiffe_id": expected_id,
            "workload_api_socket": environment.get("SPIFFE_ENDPOINT_SOCKET"),
            "socket_mount_read_only": _read_only_spire_socket(service),
            "mtls_private_tmpdir": environment.get("AEGIS_SPIRE_MTLS_TMPDIR"),
            "mtls_private_tmpfs": _private_mtls_tmpfs(service, expected_user),
            "matches_expected": (
                service.get("user") == expected_user
                and configured_ids == [expected_id]
                and environment.get("SPIFFE_ENDPOINT_SOCKET")
                == "unix:///run/spire/agent/public/api.sock"
                and _read_only_spire_socket(service)
                and environment.get("AEGIS_SPIRE_MTLS_TMPDIR") == _MTLS_TMPDIR
                and _private_mtls_tmpfs(service, expected_user)
            ),
        }

    mtls_clients: dict[str, dict[str, Any]] = {}
    for name in MTLS_CLIENT_SERVICES:
        environment = _environment(compose, name)
        raw_peers = environment.get("AEGIS_SPIFFE_PEER_IDS")
        try:
            peers = json.loads(raw_peers) if isinstance(raw_peers, str) else None
        except json.JSONDecodeError:
            peers = None
        internal_urls = {key: environment.get(key) for key in MTLS_URL_VARIABLES[name]}
        legacy_urls = {
            key: value
            for key, value in environment.items()
            if key.endswith("_URL") and key not in {*MTLS_URL_VARIABLES[name], "AEGIS_OPA_URL"}
        }
        mtls_clients[name] = {
            "mode": environment.get("AEGIS_SPIRE_MTLS_MODE"),
            "self_spiffe_id": environment.get("AEGIS_SPIFFE_ID"),
            "expected_spiffe_id": WORKLOADS[name][1],
            "peer_ids": peers,
            "expected_peer_ids": EXPECTED_MTLS_PEERS[name],
            "internal_urls": internal_urls,
            "non_capability_legacy_urls": legacy_urls,
            "matches_expected": (
                environment.get("AEGIS_SPIRE_MTLS_MODE") == "required"
                and environment.get("AEGIS_SPIFFE_ID") == WORKLOADS[name][1]
                and peers == EXPECTED_MTLS_PEERS[name]
                and bool(internal_urls)
                and all(
                    isinstance(value, str) and value.startswith("https://")
                    for value in internal_urls.values()
                )
            ),
        }

    mtls_servers: dict[str, dict[str, Any]] = {}
    for name in MTLS_SERVER_SERVICES:
        entrypoint = _entrypoint(compose, name)
        environment = _environment(compose, name)
        expected_id = WORKLOADS[name][1]
        expected_ids = _flag_values(entrypoint, "--expected-spiffe-id")
        allowed_ids = _flag_values(entrypoint, "--allowed-client-spiffe-id")
        mtls_servers[name] = {
            "module": entrypoint[2] if len(entrypoint) > 2 else None,
            "subcommand": entrypoint[3] if len(entrypoint) > 3 else None,
            "mode": environment.get("AEGIS_SPIRE_MTLS_MODE"),
            "expected_spiffe_id": expected_ids[0] if len(expected_ids) == 1 else None,
            "allowed_client_spiffe_ids": sorted(allowed_ids),
            "expected_allowed_client_spiffe_ids": sorted(EXPECTED_MTLS_CLIENTS[name]),
            "matches_expected": (
                entrypoint[:4] == ["python", "-m", "aegis_ot.spire_mtls", "serve"]
                and environment.get("AEGIS_SPIRE_MTLS_MODE") == "required"
                and expected_ids == [expected_id]
                and sorted(allowed_ids) == sorted(EXPECTED_MTLS_CLIENTS[name])
            ),
        }

    agent_service = _service(compose, "agent-probe")
    agent_environment = _environment(compose, "agent-probe")
    gateway_url = agent_environment.get("AEGIS_GATEWAY_URL")
    agent_has_spire_identity = (
        bool(agent_environment.get("AEGIS_SPIFFE_ID"))
        or bool(agent_environment.get("SPIFFE_ENDPOINT_SOCKET"))
        or _read_only_spire_socket(agent_service)
    )
    agent_ingress_boundary = {
        "agent_probe_has_spire_svid": agent_has_spire_identity,
        "agent_to_gateway_url": gateway_url,
        "agent_to_gateway_transport": (
            "http" if isinstance(gateway_url, str) and gateway_url.startswith("http://") else None
        ),
        "agent_to_gateway_application_authentication": (
            "authority-signed M4g workload capability action"
        ),
        "matches_expected": (
            agent_has_spire_identity is False
            and isinstance(gateway_url, str)
            and gateway_url.startswith("http://")
            and agent_environment.get("AEGIS_WORKLOAD_IDENTITY_MODE") == "required"
        ),
    }

    return {
        "critical_external_references": pins,
        "all_critical_external_references_digest_pinned": all(
            _DIGEST_PIN.fullmatch(value) is not None for value in pins.values()
        ),
        "application_workload_identity_modes": application_modes,
        "application_workload_identity_required": all(
            value == "required" for value in application_modes.values()
        ),
        "workload_bindings": workload_bindings,
        "all_workload_bindings_match": all(
            item["matches_expected"] is True for item in workload_bindings.values()
        ),
        "mtls_clients": mtls_clients,
        "all_mtls_client_modes_required": all(
            item["matches_expected"] is True for item in mtls_clients.values()
        ),
        "mtls_servers": mtls_servers,
        "all_internal_servers_require_spiffe_mtls": all(
            item["matches_expected"] is True for item in mtls_servers.values()
        ),
        "agent_ingress_boundary": agent_ingress_boundary,
    }


def _query_identity(
    compose_prefix: tuple[str, ...],
    *,
    service: str,
    user: str,
    expected_spiffe_id: str,
) -> dict[str, Any]:
    completed = m4d._run(
        *compose_prefix,
        "exec",
        "-T",
        "--user",
        user,
        service,
        "python",
        "-c",
        _IDENTITY_QUERY_CODE,
        expected_spiffe_id,
    )
    raw = completed.stdout.strip()
    result = _parse_json_object(raw, label=f"{service} SPIRE identity query")
    if raw.encode("utf-8") != _canonical_bytes(result):
        raise m4d.ExperimentError(f"{service} SPIRE identity query was not canonical JSON")
    uid, primary_gid = user.split(":", 1)
    result.update(
        {
            "service": service,
            "configured_user": user,
            "unix_uid": uid,
            "primary_gid": primary_gid,
        }
    )
    return result


def _collect_identities(
    compose_prefix: tuple[str, ...],
) -> dict[str, dict[str, Any]]:
    return {
        service: _query_identity(
            compose_prefix,
            service=service,
            user=user,
            expected_spiffe_id=spiffe_id,
        )
        for service, (user, spiffe_id) in WORKLOADS.items()
    }


def _identity_acceptance(identities: dict[str, dict[str, Any]]) -> dict[str, bool]:
    fingerprints: set[str] = set()
    observed_ids: set[str] = set()
    exact = True
    lifetimes = True
    now = datetime.now(UTC)
    for service, (user, expected_id) in WORKLOADS.items():
        query = identities.get(service, {})
        fingerprint = query.get("certificate_sha256")
        exact &= (
            query.get("accepted") is True
            and query.get("configured_user") == user
            and query.get("spiffe_id") == expected_id
            and query.get("expected_spiffe_id") == expected_id
            and isinstance(fingerprint, str)
            and _SHA256.fullmatch(fingerprint) is not None
        )
        if isinstance(fingerprint, str):
            fingerprints.add(fingerprint)
        if isinstance(query.get("spiffe_id"), str):
            observed_ids.add(query["spiffe_id"])
        try:
            fetched_at = _parse_utc(query.get("fetched_at"), label="SVID fetched_at")
            not_before = _parse_utc(query.get("not_before"), label="SVID not_before")
            expires_at = _parse_utc(query.get("expires_at"), label="SVID expires_at")
        except m4d.ExperimentError:
            lifetimes = False
        else:
            lifetimes &= not_before <= fetched_at < expires_at and expires_at > now
    return {
        "five_gid_distinguished_svids_issued_and_verified": (
            len(identities) == len(WORKLOADS)
            and exact
            and observed_ids == {item[1] for item in WORKLOADS.values()}
        ),
        "five_leaf_certificates_are_distinct": len(fingerprints) == len(WORKLOADS),
        "issued_svid_lifetimes_are_current": lifetimes,
    }


def _await_issued_rotation(
    compose_prefix: tuple[str, ...],
    initial: dict[str, Any],
    *,
    timeout_seconds: float,
    poll_seconds: float = DEFAULT_ROTATION_POLL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if timeout_seconds <= 0 or poll_seconds <= 0:
        raise ValueError("rotation timeout and poll interval must be positive")
    initial_fingerprint = initial.get("certificate_sha256")
    initial_expiry = _parse_utc(initial.get("expires_at"), label="initial SVID expiry")
    if not isinstance(initial_fingerprint, str) or _SHA256.fullmatch(initial_fingerprint) is None:
        raise m4d.ExperimentError("initial SVID fingerprint was malformed")
    started = monotonic()
    attempts = 0
    latest = initial
    while monotonic() - started < timeout_seconds:
        sleeper(poll_seconds)
        attempts += 1
        latest = _query_identity(
            compose_prefix,
            service="segmented-gateway",
            user=WORKLOADS["segmented-gateway"][0],
            expected_spiffe_id=WORKLOADS["segmented-gateway"][1],
        )
        fingerprint = latest.get("certificate_sha256")
        if latest.get("accepted") is True and fingerprint != initial_fingerprint:
            rotated_expiry = _parse_utc(latest.get("expires_at"), label="rotated SVID expiry")
            if not isinstance(fingerprint, str) or _SHA256.fullmatch(fingerprint) is None:
                raise m4d.ExperimentError("rotated SVID fingerprint was malformed")
            return {
                "issued_rotation_observed": True,
                "service": "segmented-gateway",
                "spiffe_id": WORKLOADS["segmented-gateway"][1],
                "attempts": attempts,
                "elapsed_seconds": round(monotonic() - started, 3),
                "initial_query": initial,
                "rotated_query": latest,
                "fingerprint_changed": True,
                "expiry_advanced": rotated_expiry > initial_expiry,
                "measurement": "fresh same-selector Workload API query",
                "long_running_process_consumption_directly_observed": False,
                "interpretation": (
                    "SPIRE issued a different current X.509-SVID for the gateway "
                    "selector. This query alone does not prove which certificate a "
                    "separate long-running process consumed."
                ),
            }
    raise m4d.ExperimentError(
        "SPIRE did not expose a rotated gateway X.509-SVID within the bounded interval; "
        f"attempts={attempts}, last_accepted={latest.get('accepted')}"
    )


def _run_agent_probe(compose_prefix: tuple[str, ...]) -> dict[str, Any]:
    completed = m4d._run(
        *compose_prefix,
        "--profile",
        "experiment",
        "run",
        "--rm",
        "--no-deps",
        "agent-probe",
    )
    raw = completed.stdout.strip()
    probe = _parse_json_object(raw, label="M4g SPIRE/mTLS capability probe")
    if raw.encode("utf-8") != _canonical_bytes(probe):
        raise m4d.ExperimentError("M4g SPIRE/mTLS probe was not canonical JSON")
    return probe


def _prepare_fresh_action(
    compose_prefix: tuple[str, ...],
) -> tuple[dict[str, Any], dict[str, Any]]:
    completed = m4d._run(
        *compose_prefix,
        "--profile",
        "experiment",
        "run",
        "--rm",
        "--no-deps",
        "--entrypoint",
        "python",
        "agent-probe",
        "-c",
        _PREPARE_FRESH_ACTION_CODE,
    )
    raw = completed.stdout.strip()
    prepared = _parse_json_object(raw, label="fresh post-deletion action fixture")
    if raw.encode("utf-8") != _canonical_bytes(prepared):
        raise m4d.ExperimentError("prepared action fixture was not canonical JSON")
    wire_request = prepared.pop("wire_request", None)
    if not isinstance(wire_request, dict):
        raise m4d.ExperimentError("prepared action fixture had no wire request")
    digest = prepared.get("wire_request_sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise m4d.ExperimentError("prepared action fixture digest was malformed")
    prepared["wire_request_retained"] = False
    return wire_request, prepared


def _mtls_health(
    compose_prefix: tuple[str, ...],
    *,
    client_service: str,
    url: str,
) -> dict[str, Any]:
    completed = m4d._run(
        *compose_prefix,
        "exec",
        "-T",
        client_service,
        "python",
        "-c",
        _MTLS_HEALTH_CODE,
        url,
    )
    raw = completed.stdout.strip()
    result = _parse_json_object(raw, label=f"{client_service} mTLS health query")
    if raw.encode("utf-8") != _canonical_bytes(result):
        raise m4d.ExperimentError("mTLS health query was not canonical JSON")
    result["client_service"] = client_service
    result["url"] = url
    return result


def _ot_dispatch_log_snapshot(compose_prefix: tuple[str, ...]) -> dict[str, Any]:
    material = m4d._run(
        *compose_prefix,
        "logs",
        "--no-color",
        "--no-log-prefix",
        "ot-adapter",
    ).stdout.encode("utf-8")
    return {
        "log_bytes": len(material),
        "log_sha256": _sha256(material),
        "execute_endpoint_records": material.count(_OT_EXECUTE_LOG_MARKER.encode()),
        "raw_logs_retained": False,
    }


def _delete_gateway_registration(compose_prefix: tuple[str, ...]) -> dict[str, Any]:
    completed = m4d._run(
        *compose_prefix,
        "exec",
        "-T",
        "spire-server",
        "/opt/spire/bin/spire-server",
        "entry",
        "delete",
        "-entryID",
        GATEWAY_ENTRY_ID,
        "-socketPath",
        "/run/spire/server/private/api.sock",
    )
    return {
        "registration_entry_id": GATEWAY_ENTRY_ID,
        "deleted_at": datetime.now(UTC).isoformat(),
        "command_exit_code": completed.returncode,
        "registration_entry_deleted": completed.returncode == 0,
    }


def _await_fresh_fetch_unavailable(
    compose_prefix: tuple[str, ...],
    *,
    timeout_seconds: float = DEFAULT_FETCH_LOSS_TIMEOUT_SECONDS,
    poll_seconds: float = DEFAULT_FETCH_LOSS_POLL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if timeout_seconds <= 0 or poll_seconds <= 0:
        raise ValueError("fetch-loss timeout and poll interval must be positive")
    started = monotonic()
    attempts = 0
    latest: dict[str, Any] | None = None
    while monotonic() - started < timeout_seconds:
        attempts += 1
        latest = _query_identity(
            compose_prefix,
            service="segmented-gateway",
            user=WORKLOADS["segmented-gateway"][0],
            expected_spiffe_id=WORKLOADS["segmented-gateway"][1],
        )
        if latest.get("accepted") is False:
            return {
                "fresh_fetch_unavailable": True,
                "attempts": attempts,
                "elapsed_seconds": round(monotonic() - started, 3),
                "query": latest,
                "already_issued_certificate_immediate_revocation_measured": False,
                "already_issued_certificate_immediate_revocation_proven": False,
                "interpretation": (
                    "The deleted registration stopped a new Workload API identity "
                    "fetch. This does not establish immediate rejection of every "
                    "already-issued certificate before its expiry."
                ),
            }
        sleeper(poll_seconds)
    raise m4d.ExperimentError(
        "deleted gateway registration remained available to fresh Workload API fetches; "
        f"attempts={attempts}, last_accepted={latest and latest.get('accepted')}"
    )


def _post_deletion_acceptance(
    *,
    response_status: int,
    response_document: dict[str, Any],
    fetch_loss: dict[str, Any],
    plant_before: dict[str, Any],
    plant_after: dict[str, Any],
    ot_before: dict[str, Any],
    ot_after: dict[str, Any],
) -> dict[str, bool]:
    before = plant_before.get("document", {})
    after = plant_after.get("document", {})
    unchanged_plant = (
        isinstance(before, dict)
        and isinstance(after, dict)
        and before.get("state_version") == after.get("state_version")
        and before.get("state_digest") == after.get("state_digest")
        and before.get("apply_requests") == after.get("apply_requests")
        and before.get("commit_count") == after.get("commit_count")
    )
    no_ot_dispatch = ot_before.get("execute_endpoint_records", 0) >= 1 and ot_before.get(
        "execute_endpoint_records"
    ) == ot_after.get("execute_endpoint_records")
    return {
        "fresh_gateway_svid_fetch_unavailable": (fetch_loss.get("fresh_fetch_unavailable") is True),
        "fresh_action_failed_closed": (
            response_status == 503
            and response_document.get("status") == "error"
            and response_document.get("reason") == "gateway_runtime_unavailable"
        ),
        "no_ot_consequence_dispatch_observed": no_ot_dispatch,
        "plant_effect_absent": unchanged_plant,
    }


def _project_resources(project_name: str) -> dict[str, list[str]]:
    commands = {
        "containers": (
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--format",
            "{{.ID}}",
        ),
        "volumes": (
            "docker",
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--format",
            "{{.Name}}",
        ),
        "networks": (
            "docker",
            "network",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--format",
            "{{.Name}}",
        ),
    }
    return {
        kind: [line for line in m4d._run(*command).stdout.splitlines() if line]
        for kind, command in commands.items()
    }


def _assert_project_absent(project_name: str) -> None:
    resources = _project_resources(project_name)
    if any(resources.values()):
        raise m4d.ExperimentError(f"M4g SPIRE/mTLS project name is already in use: {project_name}")


def _inspect_service(compose_prefix: tuple[str, ...], service: str) -> dict[str, Any]:
    container_ids = [
        line
        for line in m4d._run(*compose_prefix, "ps", "-a", "-q", service).stdout.splitlines()
        if line
    ]
    if len(container_ids) != 1:
        raise m4d.ExperimentError(f"service identity was incomplete for {service}")
    values = json.loads(m4d._run("docker", "inspect", container_ids[0]).stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise m4d.ExperimentError(f"container inspection was malformed for {service}")
    record = _required_mapping(values[0], label=f"{service} inspection")
    state = _required_mapping(record.get("State"), label=f"{service} state")
    config = _required_mapping(record.get("Config"), label=f"{service} config")
    host = _required_mapping(record.get("HostConfig"), label=f"{service} host config")
    health = state.get("Health")
    return {
        "service": service,
        "container_id": record.get("Id"),
        "image_id": record.get("Image"),
        "configured_user": config.get("User"),
        "running": state.get("Running"),
        "status": state.get("Status"),
        "exit_code": state.get("ExitCode"),
        "health_status": health.get("Status") if isinstance(health, dict) else None,
        "pid_mode": host.get("PidMode"),
    }


def _runtime_inventory(compose_prefix: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    return {service: _inspect_service(compose_prefix, service) for service in RUNTIME_SERVICES}


def _runtime_acceptance(inventory: dict[str, dict[str, Any]]) -> dict[str, bool]:
    running = (
        "opa",
        "spire-server",
        "spire-agent",
        "simulation",
        "observer",
        "candidate",
        "ot-adapter",
        "segmented-gateway",
    )
    completed = ("identity-init", "replay-init", "spire-storage-init", "spire-bootstrap")
    return {
        "actual_spire_server_and_agent_are_healthy": (
            inventory.get("spire-server", {}).get("running") is True
            and inventory.get("spire-server", {}).get("health_status") == "healthy"
            and inventory.get("spire-agent", {}).get("running") is True
            and inventory.get("spire-agent", {}).get("health_status") == "healthy"
            and inventory.get("spire-agent", {}).get("pid_mode") == "host"
        ),
        "runtime_services_are_running": all(
            inventory.get(service, {}).get("running") is True for service in running
        ),
        "bounded_initializers_completed_successfully": all(
            inventory.get(service, {}).get("running") is False
            and inventory.get(service, {}).get("exit_code") == 0
            for service in completed
        ),
        "runtime_users_match_gid_selector_design": all(
            inventory.get(service, {}).get("configured_user") == expected_user
            for service, (expected_user, _spiffe_id) in WORKLOADS.items()
        ),
        "runtime_image_ids_are_bound": all(
            isinstance(item.get("image_id"), str) and str(item["image_id"]).startswith("sha256:")
            for item in inventory.values()
        ),
    }


def _campaign(
    project_name: str,
    commit: str,
    *,
    rotation_timeout_seconds: float,
) -> dict[str, Any]:
    _validate_project_name(project_name)
    _assert_project_absent(project_name)
    m4g._assert_checkout(commit)
    source_binding = _source_binding(commit)
    compose_prefix = _compose_prefix(project_name)
    key_directory = Path(tempfile.mkdtemp(prefix="aegis-ot-m4g-spire-mtls-keys-"))
    environment: dict[str, str] = {}
    project_created = False
    evidence: dict[str, Any] | None = None
    cleanup: dict[str, Any] = {}
    try:
        key_paths, key_ids = m4g._provision_key_material(key_directory)
        environment = m4g._campaign_environment(key_paths, key_ids, commit)
        environment["AEGIS_FAULT_SUPPRESS_OT_RESPONSE_ONCE"] = "false"
        with m4g._installed_environment(environment):
            compose = _parse_json_object(
                m4d._run(
                    *compose_prefix,
                    "--profile",
                    "experiment",
                    "config",
                    "--format",
                    "json",
                ).stdout,
                label="resolved six-overlay SPIRE/mTLS Compose configuration",
            )
            normalized = m4g._normalize(compose, key_directory, project_name, checkout_root=ROOT)
            if not isinstance(normalized, dict):
                raise m4d.ExperimentError("normalized Compose configuration failed")
            normalized_compose_sha256 = m4d._canonical_sha256(normalized)
            configuration_binding = _configuration_binding(compose)

            m4d._run(
                *compose_prefix,
                "--profile",
                "experiment",
                "build",
                "--build-arg",
                f"AEGIS_SOURCE_REVISION={commit}",
            )
            image_provenance = m4g._image_provenance(
                compose,
                commit,
                APP_BUILD_SERVICES,
            )
            project_created = True
            m4d._run(
                *compose_prefix,
                "up",
                "-d",
                "--force-recreate",
                *OPERATIONAL_SERVICES,
            )
            gateway_health = m4g._await_gateway()
            m4d._await_opa(compose_prefix)

            initial_identities = _collect_identities(compose_prefix)
            identity_acceptance = _identity_acceptance(initial_identities)
            primary_probe = _run_agent_probe(compose_prefix)
            runtime_inventory = _runtime_inventory(compose_prefix)
            initial_gateway = initial_identities["segmented-gateway"]
            issued_rotation = _await_issued_rotation(
                compose_prefix,
                initial_gateway,
                timeout_seconds=rotation_timeout_seconds,
            )
            post_rotation_probe = _run_agent_probe(compose_prefix)

            wire_request, prepared_action = _prepare_fresh_action(compose_prefix)
            plant_before = _mtls_health(
                compose_prefix,
                client_service="observer",
                url="https://simulation:8084/health",
            )
            ot_before = _ot_dispatch_log_snapshot(compose_prefix)

            registration_deletion = _delete_gateway_registration(compose_prefix)
            fetch_loss = _await_fresh_fetch_unavailable(compose_prefix)
            response_status, response_document = m4d._http_json(
                "POST",
                "http://127.0.0.1:8081/v1/capability/actions",
                wire_request,
            )
            plant_after = _mtls_health(
                compose_prefix,
                client_service="observer",
                url="https://simulation:8084/health",
            )
            ot_after = _ot_dispatch_log_snapshot(compose_prefix)
            post_deletion_acceptance = _post_deletion_acceptance(
                response_status=response_status,
                response_document=response_document,
                fetch_loss=fetch_loss,
                plant_before=plant_before,
                plant_after=plant_after,
                ot_before=ot_before,
                ot_after=ot_after,
            )

            acceptance: dict[str, bool] = {
                "six_overlays_resolved_in_required_order": (
                    list(COMPOSE_OVERLAYS)
                    == [
                        "docker-compose.yml",
                        "docker-compose.auth.yml",
                        "docker-compose.replay.yml",
                        "docker-compose.capability.yml",
                        "docker-compose.identity.yml",
                        "docker-compose.spire.yml",
                    ]
                ),
                "built_application_images_match_source_commit": all(
                    item.get("oci_revision") == commit for item in image_provenance.values()
                ),
                "critical_external_references_digest_pinned": configuration_binding[
                    "all_critical_external_references_digest_pinned"
                ]
                is True,
                "application_workload_identity_mode_required": configuration_binding[
                    "application_workload_identity_required"
                ]
                is True,
                "five_runtime_selector_bindings_match": configuration_binding[
                    "all_workload_bindings_match"
                ]
                is True,
                "internal_mtls_client_mode_required": configuration_binding[
                    "all_mtls_client_modes_required"
                ]
                is True,
                "internal_servers_require_spiffe_mtls": configuration_binding[
                    "all_internal_servers_require_spiffe_mtls"
                ]
                is True,
                "agent_ingress_boundary_is_explicitly_bounded": configuration_binding[
                    "agent_ingress_boundary"
                ]["matches_expected"]
                is True,
                **identity_acceptance,
                "nominal_signed_capability_flow_completed": m4g._probe_accepted(primary_probe),
                "post_rotation_signed_capability_flow_completed": m4g._probe_accepted(
                    post_rotation_probe
                ),
                "gateway_svid_issuance_rotated": (
                    issued_rotation.get("issued_rotation_observed") is True
                    and issued_rotation.get("fingerprint_changed") is True
                    and issued_rotation.get("expiry_advanced") is True
                ),
                "gateway_registration_entry_deleted": registration_deletion[
                    "registration_entry_deleted"
                ]
                is True,
                **post_deletion_acceptance,
                **_runtime_acceptance(runtime_inventory),
            }
            semantic_projection = {
                "git_commit": commit,
                "git_tree": source_binding["git_tree"],
                "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
                "normalized_compose_sha256": normalized_compose_sha256,
                "workload_ids": sorted(item[1] for item in WORKLOADS.values()),
                "workload_users": sorted(item[0] for item in WORKLOADS.values()),
                "primary_nominal_status": primary_probe.get("nominal", {}).get("status"),
                "post_rotation_nominal_status": post_rotation_probe.get("nominal", {}).get(
                    "status"
                ),
                "issued_rotation": {
                    "observed": issued_rotation.get("issued_rotation_observed"),
                    "fingerprint_changed": issued_rotation.get("fingerprint_changed"),
                    "expiry_advanced": issued_rotation.get("expiry_advanced"),
                },
                "registration_deletion": {
                    "fresh_fetch_unavailable": fetch_loss.get("fresh_fetch_unavailable"),
                    "immediate_certificate_revocation_proven": fetch_loss.get(
                        "already_issued_certificate_immediate_revocation_proven"
                    ),
                },
                "post_deletion_action": {
                    "status": response_status,
                    "reason": response_document.get("reason"),
                    "ot_execute_records_unchanged": ot_before.get("execute_endpoint_records")
                    == ot_after.get("execute_endpoint_records"),
                    "plant_state_unchanged": post_deletion_acceptance["plant_effect_absent"],
                },
                "acceptance": acceptance,
            }
            evidence = {
                "schema_version": "m4g-spire-mtls-experiment-v1",
                "generated_at": datetime.now(UTC).isoformat(),
                "analyst": "Angelis Pseftis",
                "git_commit": commit,
                "clean_checkout_start": True,
                "project_name": project_name,
                "compose_overlays": list(COMPOSE_OVERLAYS),
                "normalized_compose_sha256": normalized_compose_sha256,
                "source_binding": source_binding,
                "configuration_binding": configuration_binding,
                "image_provenance": image_provenance,
                "credential_material_retained": False,
                "host": {
                    "platform": platform.platform(),
                    "machine": platform.machine(),
                    "docker": _parse_json_object(
                        m4d._run("docker", "version", "--format", "{{json .}}").stdout,
                        label="Docker version",
                    ),
                },
                "gateway_health_before_experiment": gateway_health,
                "initial_workload_identities": initial_identities,
                "primary_agent_probe": primary_probe,
                "runtime_inventory": runtime_inventory,
                "issued_rotation": issued_rotation,
                "post_rotation_agent_probe": post_rotation_probe,
                "prepared_post_deletion_action": prepared_action,
                "registration_deletion": registration_deletion,
                "fresh_fetch_loss": fetch_loss,
                "post_deletion_action": {
                    "http_status": response_status,
                    "response": response_document,
                    "plant_before": plant_before,
                    "plant_after": plant_after,
                    "ot_dispatch_log_before": ot_before,
                    "ot_dispatch_log_after": ot_after,
                    "acceptance": post_deletion_acceptance,
                },
                "acceptance": acceptance,
                "accepted": all(acceptance.values()),
                "semantic_projection": semantic_projection,
                "semantic_outcome_sha256": m4d._canonical_sha256(semantic_projection),
                "evidence_boundary": [
                    (
                        "Actual SPIRE server, agent, Unix Workload API, five "
                        "GID-distinguished X.509-SVIDs, and SPIFFE-authenticated mTLS "
                        "on internal capability links in one local Compose lab."
                    ),
                    (
                        "Agent-probe has no SPIRE SVID in this slice. Agent-to-gateway "
                        "traffic remains HTTP and is authenticated by the committed "
                        "authority-signed application workload credential."
                    ),
                    (
                        "Registration deletion established loss of fresh gateway SVID "
                        "fetches. It did not establish immediate cryptographic revocation "
                        "of every already-issued certificate."
                    ),
                    (
                        "The post-deletion action returned a fail-closed gateway error "
                        "without a new OT execute-endpoint record or plant-state change."
                    ),
                    (
                        "UID/GID selectors plus host PID visibility are a bounded lab "
                        "attestation mechanism, not production container or hardware "
                        "workload attestation."
                    ),
                    (
                        "Synthetic plant and single-host local evidence are not a "
                        "production OT deployment or independent validation."
                    ),
                ],
            }
            m4g._assert_checkout(commit)
            if evidence["accepted"] is not True:
                raise m4d.ExperimentError(
                    "M4g SPIRE/mTLS acceptance criteria were not all satisfied"
                )
    finally:
        if project_created:
            with m4g._installed_environment(environment):
                down = m4d._run(
                    *compose_prefix,
                    "down",
                    "-v",
                    "--remove-orphans",
                    check=False,
                )
            cleanup["compose_down_succeeded"] = down.returncode == 0
        else:
            cleanup["compose_down_succeeded"] = True
        resources = _project_resources(project_name)
        cleanup["project_resources_removed"] = not any(resources.values())
        cleanup["remaining_project_resources"] = resources
        shutil.rmtree(key_directory, ignore_errors=True)
        cleanup["private_key_directory_removed"] = not key_directory.exists()
    if evidence is None:
        raise m4d.ExperimentError("M4g SPIRE/mTLS campaign ended without evidence")
    evidence["cleanup"] = cleanup
    if not (
        cleanup["compose_down_succeeded"]
        and cleanup["project_resources_removed"]
        and cleanup["private_key_directory_removed"]
    ):
        raise m4d.ExperimentError("M4g SPIRE/mTLS scoped cleanup was incomplete")
    return evidence


def _assert_non_secret_evidence(value: Any) -> None:
    material = _canonical_bytes(value).lower()
    forbidden = (
        b"begin private key",
        b"begin ec private key",
        b"begin certificate",
        b"join-token",
        b"private_key_b64",
        b'wire_request"',
    )
    if any(marker in material for marker in forbidden):
        raise m4d.ExperimentError("retained SPIRE/mTLS evidence contained credential material")


def _atomic_write_bytes(path: Path, material: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                raise OSError("retained evidence write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise m4d.ExperimentError(f"retained evidence file is not private: {path.name}")


def _retain_results(results_directory: Path, evidence: dict[str, Any]) -> dict[str, Any]:
    if results_directory.exists() or results_directory.is_symlink():
        raise m4d.ExperimentError(
            f"refusing to overwrite retained M4g SPIRE/mTLS results: {results_directory}"
        )
    _assert_non_secret_evidence(evidence)
    results_directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{results_directory.name}.staging-",
            dir=results_directory.parent,
        )
    )
    try:
        files = {
            "source-binding.json": _canonical_text(evidence["source_binding"]).encode(),
            "configuration-binding.json": _canonical_text(
                evidence["configuration_binding"]
            ).encode(),
            "nominal-probe.json": _canonical_text(evidence["primary_agent_probe"]).encode(),
            "post-deletion-fail-closed.json": _canonical_text(
                {
                    "registration_deletion": evidence["registration_deletion"],
                    "fresh_fetch_loss": evidence["fresh_fetch_loss"],
                    "prepared_action": evidence["prepared_post_deletion_action"],
                    "post_deletion_action": evidence["post_deletion_action"],
                }
            ).encode(),
            "campaign.json": (
                json.dumps(evidence, sort_keys=True, indent=2, allow_nan=False) + "\n"
            ).encode(),
        }
        metadata: dict[str, dict[str, Any]] = {}
        for name, material in files.items():
            _atomic_write_bytes(staging / name, material)
            parsed = json.loads(material)
            metadata[name] = {
                "bytes": len(material),
                "sha256": _sha256(material),
                "json_object": isinstance(parsed, dict),
            }
        manifest = {
            "schema_version": "m4g-spire-mtls-results-manifest-v1",
            "generated_at": datetime.now(UTC).isoformat(),
            "analyst": "Angelis Pseftis",
            "git_commit": evidence["git_commit"],
            "source_fingerprint_sha256": evidence["source_binding"]["source_fingerprint_sha256"],
            "semantic_outcome_sha256": evidence["semantic_outcome_sha256"],
            "accepted": evidence["accepted"],
            "credential_material_retained": False,
            "files": metadata,
        }
        _assert_non_secret_evidence(manifest)
        _atomic_write_bytes(
            staging / "manifest.json",
            (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(),
        )
        descriptor = os.open(staging, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(staging, results_directory)
        parent_descriptor = os.open(results_directory.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        return manifest
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def run_experiment(
    results_directory: Path,
    project_name: str,
    *,
    rotation_timeout_seconds: float = DEFAULT_ROTATION_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if results_directory.exists() or results_directory.is_symlink():
        raise m4d.ExperimentError(
            f"refusing to overwrite retained M4g SPIRE/mTLS results: {results_directory}"
        )
    _validate_project_name(project_name)
    m4g._assert_source_checkout()
    if m4d._run("git", "status", "--porcelain").stdout:
        raise m4d.ExperimentError("M4g SPIRE/mTLS retained evidence requires a clean checkout")
    commit = m4d._run("git", "rev-parse", "HEAD").stdout.strip()
    evidence = _campaign(
        project_name,
        commit,
        rotation_timeout_seconds=rotation_timeout_seconds,
    )
    m4g._assert_checkout(commit)
    evidence["clean_checkout_end"] = True
    manifest = _retain_results(results_directory, evidence)
    return {"evidence": evidence, "manifest": manifest}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--project-name", default="aegis-ot-m4g-spire-mtls")
    parser.add_argument(
        "--rotation-timeout-seconds",
        type=float,
        default=DEFAULT_ROTATION_TIMEOUT_SECONDS,
    )
    arguments = parser.parse_args()
    result = run_experiment(
        arguments.results_dir,
        arguments.project_name,
        rotation_timeout_seconds=arguments.rotation_timeout_seconds,
    )
    print(
        json.dumps(
            {
                "accepted": result["evidence"]["accepted"],
                "results_directory": str(arguments.results_dir),
                "source_fingerprint_sha256": result["manifest"]["source_fingerprint_sha256"],
                "semantic_outcome_sha256": result["evidence"]["semantic_outcome_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
