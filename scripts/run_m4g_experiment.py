"""Run one bounded clean-checkout M4g workload-identity campaign.

The campaign is intentionally single-host and synthetic.  It establishes the
consequence-path workload credential, revocation, leaf-rotation, and stable
replay behavior exercised by the five Compose overlays; it does not establish
multi-host deployment, hostile-host rollback resistance, or independent
validation.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import run_m4d_experiment as m4d
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis_ot
from aegis_ot.workload_identity import workload_key_id

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.auth.yml",
    "docker-compose.replay.yml",
    "docker-compose.capability.yml",
    "docker-compose.identity.yml",
)
OPERATIONAL_SERVICES = (
    "opa",
    "simulation",
    "observer",
    "candidate",
    "ot-adapter",
    "segmented-gateway",
)
CAMPAIGN_BUILD_SERVICES = (
    "identity-admin",
    "identity-init",
    "replay-init",
    "simulation",
    "observer",
    "candidate",
    "ot-adapter",
    "segmented-gateway",
    "agent-probe",
)
AEGIS_HEALTH_PORTS = {
    "simulation": 8084,
    "observer": 8082,
    "candidate": 8085,
    "ot-adapter": 8083,
    "segmented-gateway": 8081,
}
PROJECT_VOLUME_SUFFIXES = (
    "workload_identity",
    "workload_replay",
    "transport_replay",
    "transport_probe",
)
TRUST_DOMAIN = "aegis-ot.m4g.local"
AGENT_SUBJECT = "urn:aegis-ot:m4g:workload:agent-probe"
GATEWAY_SUBJECT = "urn:aegis-ot:m4g:workload:gateway"
OT_SUBJECT = "urn:aegis-ot:m4g:workload:ot-adapter"
FIXED_ROTATION_NONCE = "m4g-cross-leaf-transport-nonce-0001"
MAX_CAPTURE_BYTES = 1_048_576


def _compose_prefix(project_name: str) -> tuple[str, ...]:
    prefix: list[str] = ["docker", "compose", "-p", project_name]
    for filename in COMPOSE_FILES:
        prefix.extend(("-f", filename))
    return tuple(prefix)


def _assert_source_checkout() -> dict[str, str]:
    module_file = aegis_ot.__file__
    if module_file is None:
        raise m4d.ExperimentError("aegis_ot package has no filesystem source")
    actual = Path(module_file).resolve().parent
    expected = (ROOT / "src" / "aegis_ot").resolve()
    if actual != expected:
        raise m4d.ExperimentError(
            f"aegis_ot imported from stale source: expected {expected}, got {actual}"
        )
    return {
        "package_directory": str(actual.relative_to(ROOT)),
        "checkout_root": str(ROOT),
    }


def _assert_checkout(commit: str) -> None:
    if m4d._run("git", "rev-parse", "HEAD").stdout.strip() != commit:
        raise m4d.ExperimentError("checkout HEAD changed during the M4g campaign")
    if m4d._run("git", "status", "--porcelain").stdout:
        raise m4d.ExperimentError("checkout changed during the M4g campaign")


def _assert_project_absent(project_name: str) -> None:
    containers = m4d._run(
        "docker",
        "ps",
        "-a",
        "--filter",
        f"label=com.docker.compose.project={project_name}",
        "--format",
        "{{.ID}}",
    ).stdout.strip()
    volumes = [
        f"{project_name}_{suffix}"
        for suffix in PROJECT_VOLUME_SUFFIXES
        if m4d._run(
            "docker",
            "volume",
            "inspect",
            f"{project_name}_{suffix}",
            check=False,
        ).returncode
        == 0
    ]
    if containers or volumes:
        raise m4d.ExperimentError(
            f"M4g project name is already in use; refusing cleanup: {project_name}"
        )


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _write_private(path: Path, material: bytes) -> None:
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
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise m4d.ExperimentError(f"ephemeral key file is not private: {path.name}")


def _provision_key_material(directory: Path) -> tuple[dict[str, Path], dict[str, str]]:
    directory.chmod(0o700)
    paths: dict[str, Path] = {}
    workload_key_ids: dict[str, str] = {}
    for name in (
        "workload_authority",
        "agent",
        "gateway",
        "ot",
        "permit",
        "observer",
        "candidate",
        "plant",
    ):
        private_key = Ed25519PrivateKey.generate()
        private_path = directory / f"{name}.private"
        public_path = directory / f"{name}.public"
        _write_private(private_path, _raw_private(private_key))
        _write_private(public_path, _raw_public(private_key))
        paths[f"{name}_private"] = private_path
        paths[f"{name}_public"] = public_path
        if name in {"workload_authority", "agent", "gateway", "ot"}:
            workload_key_ids[name] = workload_key_id(private_key.public_key())
    return paths, workload_key_ids


def _provision_rotated_gateway(
    directory: Path,
) -> tuple[dict[str, Path], str]:
    private_key = Ed25519PrivateKey.generate()
    private_path = directory / "gateway-rotated.private"
    public_path = directory / "gateway-rotated.public"
    _write_private(private_path, _raw_private(private_key))
    _write_private(public_path, _raw_public(private_key))
    return (
        {"gateway_private": private_path, "gateway_public": public_path},
        workload_key_id(private_key.public_key()),
    )


def _campaign_environment(
    paths: dict[str, Path],
    key_ids: dict[str, str],
    commit: str,
) -> dict[str, str]:
    environment = {
        "AEGIS_SOURCE_REVISION": commit,
        "AEGIS_WORKLOAD_TRUST_DOMAIN": TRUST_DOMAIN,
        "AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID": key_ids["workload_authority"],
        "AEGIS_OT_WORKLOAD_KEY_ID": key_ids["ot"],
        "AEGIS_AGENT_WORKLOAD_SUBJECT": AGENT_SUBJECT,
        "AEGIS_GATEWAY_WORKLOAD_SUBJECT": GATEWAY_SUBJECT,
        "AEGIS_OT_WORKLOAD_SUBJECT": OT_SUBJECT,
    }
    for role in (
        "gateway",
        "ot",
        "permit",
        "observer",
        "candidate",
        "plant",
        "agent",
    ):
        upper = role.upper()
        environment[f"AEGIS_{upper}_PRIVATE_KEY_FILE"] = str(
            paths[f"{role}_private"]
        )
        environment[f"AEGIS_{upper}_PUBLIC_KEY_FILE"] = str(
            paths[f"{role}_public"]
        )
    environment["AEGIS_WORKLOAD_AUTHORITY_PRIVATE_KEY_FILE"] = str(
        paths["workload_authority_private"]
    )
    return environment


@contextmanager
def _installed_environment(values: dict[str, str]) -> Iterator[None]:
    prior = {name: os.environ.get(name) for name in values}
    try:
        os.environ.update(values)
        yield
    finally:
        for name, previous in prior.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous


def _replace_path_prefix(value: str, path: Path, marker: str) -> str:
    prefixes = sorted(
        {str(path), str(path.absolute()), str(path.resolve())},
        key=len,
        reverse=True,
    )
    for prefix in prefixes:
        if value == prefix:
            return marker
        if value.startswith(f"{prefix}{os.sep}"):
            return f"{marker}{value[len(prefix):]}"
    return value


def _normalize(
    value: Any,
    key_directory: Path,
    project_name: str,
    checkout_root: Path = ROOT,
) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize(item, key_directory, project_name, checkout_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _normalize(item, key_directory, project_name, checkout_root)
            for item in value
        ]
    if isinstance(value, str):
        normalized = _replace_path_prefix(value, key_directory, "<ephemeral-key-dir>")
        normalized = _replace_path_prefix(
            normalized,
            checkout_root,
            "<checkout-root>",
        )
        return normalized.replace(project_name, "<compose-project>")
    return value


def _json_object(raw: str, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise m4d.ExperimentError(f"{label} did not emit JSON") from exc
    if not isinstance(value, dict):
        raise m4d.ExperimentError(f"{label} JSON root was not an object")
    return value


def _last_json_log(prefix: tuple[str, ...], service: str) -> dict[str, Any]:
    raw = m4d._run(
        *prefix,
        "logs",
        "--no-color",
        "--no-log-prefix",
        service,
    ).stdout
    for line in reversed(raw.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise m4d.ExperimentError(f"{service} initialization record was not found")


def _run_input(
    args: tuple[str, ...],
    input_text: str,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(  # noqa: S603 - fixed Docker argv and scoped input
        args,
        cwd=ROOT,
        check=False,
        input=input_text,
        capture_output=True,
        text=True,
        env={**os.environ, "COMPOSE_ANSI": "never"},
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise m4d.ExperimentError(
            f"command failed ({' '.join(args)}): {detail[-4000:]}"
        )
    return completed


def _await_gateway() -> dict[str, Any]:
    last_error: Exception | None = None
    for _ in range(80):
        try:
            status, value = m4d._http_json(
                "GET",
                "http://127.0.0.1:8081/health",
            )
            if status == 200 and value.get("status") == "ready":
                return value
        except m4d.ExperimentError as exc:
            last_error = exc
        time.sleep(0.25)
    raise m4d.ExperimentError("M4g gateway did not become ready") from last_error


def _service_health(
    prefix: tuple[str, ...],
    service: str,
    port: int,
) -> dict[str, Any]:
    code = (
        "import json; from urllib.request import urlopen; "
        f"print(json.dumps(json.loads(urlopen('http://127.0.0.1:{port}/health', "
        "timeout=3).read()),sort_keys=True,separators=(',',':')))"
    )
    return _json_object(
        m4d._run(*prefix, "exec", "-T", service, "python", "-c", code).stdout,
        label=f"{service} health",
    )


def _health_snapshot(prefix: tuple[str, ...]) -> dict[str, Any]:
    return {
        service: _service_health(prefix, service, port)
        for service, port in AEGIS_HEALTH_PORTS.items()
    }


def _container_identity(
    prefix: tuple[str, ...],
    service: str,
) -> dict[str, Any]:
    container_id = m4d._run(
        *prefix,
        "ps",
        "-q",
        "--all",
        service,
    ).stdout.strip()
    if not container_id:
        raise m4d.ExperimentError(f"container identity is unavailable: {service}")
    values = json.loads(m4d._run("docker", "inspect", container_id).stdout)
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise m4d.ExperimentError(f"container inspection was malformed: {service}")
    inspected = values[0]
    state = inspected.get("State", {})
    config = inspected.get("Config", {})
    mounts = inspected.get("Mounts", [])
    network_settings = inspected.get("NetworkSettings", {})
    networks = network_settings.get("Networks", {}) if isinstance(network_settings, dict) else {}
    if not isinstance(state, dict) or not isinstance(config, dict):
        raise m4d.ExperimentError(f"container state was malformed: {service}")
    return {
        "service": service,
        "container_id": inspected.get("Id"),
        "created": inspected.get("Created"),
        "started_at": state.get("StartedAt"),
        "status": state.get("Status"),
        "running": state.get("Running"),
        "exit_code": state.get("ExitCode"),
        "image_id": inspected.get("Image"),
        "configured_image": config.get("Image"),
        "oci_revision": (
            config.get("Labels", {}).get("org.opencontainers.image.revision")
            if isinstance(config.get("Labels"), dict)
            else None
        ),
        "networks": sorted(networks) if isinstance(networks, dict) else [],
        "volume_mounts": sorted(
            (
                {
                    "destination": item.get("Destination"),
                    "name": item.get("Name"),
                    "rw": item.get("RW"),
                }
                for item in mounts
                if isinstance(item, dict) and item.get("Type") == "volume"
            ),
            key=lambda item: str(item.get("destination")),
        ),
    }


def _container_snapshot(prefix: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    return {
        service: _container_identity(prefix, service)
        for service in (*OPERATIONAL_SERVICES, "identity-init", "replay-init")
    }


def _image_provenance(
    compose: dict[str, Any],
    commit: str,
    service_names: tuple[str, ...] = CAMPAIGN_BUILD_SERVICES,
) -> dict[str, dict[str, Any]]:
    services = compose.get("services")
    if not isinstance(services, dict):
        raise m4d.ExperimentError("resolved Compose services were malformed")
    project_name = compose.get("name")
    if not isinstance(project_name, str) or not project_name:
        raise m4d.ExperimentError("resolved Compose project name was malformed")
    result: dict[str, dict[str, Any]] = {}
    for service in service_names:
        definition = services.get(service)
        if not isinstance(definition, dict) or "build" not in definition:
            raise m4d.ExperimentError(
                f"campaign service has no resolved build: {service}"
            )
        configured_image = definition.get("image")
        image = (
            configured_image
            if isinstance(configured_image, str) and configured_image
            else f"{project_name}-{service}"
        )
        inspected_values = json.loads(m4d._run("docker", "image", "inspect", image).stdout)
        if (
            not isinstance(inspected_values, list)
            or len(inspected_values) != 1
            or not isinstance(inspected_values[0], dict)
        ):
            raise m4d.ExperimentError(f"image inspection was malformed: {service}")
        inspected = inspected_values[0]
        config = inspected.get("Config", {})
        labels = config.get("Labels", {}) if isinstance(config, dict) else {}
        revision = (
            labels.get("org.opencontainers.image.revision")
            if isinstance(labels, dict)
            else None
        )
        if revision != commit:
            raise m4d.ExperimentError(
                f"built image revision mismatch for {service}: {revision!r}"
            )
        result[service] = {
            "image": image,
            "image_id": inspected.get("Id"),
            "repo_digests": sorted(inspected.get("RepoDigests") or []),
            "created": inspected.get("Created"),
            "oci_revision": revision,
        }
    if not result:
        raise m4d.ExperimentError("no M4g built-image provenance was resolved")
    return result


_IDENTITY_SNAPSHOT_CODE = r"""
import base64, hashlib, json, stat
from pathlib import Path
root = Path('/run/aegis-identity')
result = {}
for name in (
    'authority.public',
    'trust-bundle.json',
    'agent.credential.json',
    'gateway.credential.json',
    'ot.credential.json',
):
    path = root / name
    material = path.read_bytes()
    item = {
        'bytes_base64': base64.b64encode(material).decode('ascii'),
        'sha256': hashlib.sha256(material).hexdigest(),
        'mode': format(stat.S_IMODE(path.stat().st_mode), '04o'),
        'uid': path.stat().st_uid,
        'gid': path.stat().st_gid,
    }
    if name.endswith('.json'):
        item['document'] = json.loads(material)
    result[name] = item
print(json.dumps(result,sort_keys=True,separators=(',',':')))
"""


def _identity_snapshot(prefix: tuple[str, ...]) -> dict[str, Any]:
    return _json_object(
        m4d._run(
            *prefix,
            "exec",
            "-T",
            "segmented-gateway",
            "python",
            "-c",
            _IDENTITY_SNAPSHOT_CODE,
        ).stdout,
        label="M4g identity snapshot",
    )


_REPLAY_SNAPSHOT_CODE = r"""
import base64, hashlib, json, stat
from pathlib import Path
result = {}
for name in ('workload-replay.json','semantic-replay.json'):
    path = Path('/var/lib/aegis-ot') / name
    material = path.read_bytes()
    result[name] = {
        'bytes_base64': base64.b64encode(material).decode('ascii'),
        'sha256': hashlib.sha256(material).hexdigest(),
        'mode': format(stat.S_IMODE(path.stat().st_mode), '04o'),
        'uid': path.stat().st_uid,
        'gid': path.stat().st_gid,
        'document': json.loads(material),
    }
print(json.dumps(result,sort_keys=True,separators=(',',':')))
"""


def _replay_snapshot(prefix: tuple[str, ...]) -> dict[str, Any]:
    return _json_object(
        m4d._run(
            *prefix,
            "exec",
            "-T",
            "ot-adapter",
            "python",
            "-c",
            _REPLAY_SNAPSHOT_CODE,
        ).stdout,
        label="M4g replay snapshot",
    )


_ROTATION_FIXTURE_CODE = r"""
import json, os, secrets
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4
from aegis_ot.capability_models import CapabilityActionRequest
from aegis_ot.models import ActionProposal, DecisionOutcome, Operation
from aegis_ot.physical_control import physical_state_to_gateway_state
from aegis_ot.segmented_capability_models import (
    OT_CAPABILITY_AUDIENCE,
    SegmentedCapabilityDispatch,
    WorkloadSignedCapabilityDispatch,
    WorkloadSignedCapabilityResponse,
)
from aegis_ot.segmented_capability_runtime import (
    ObservationCaptureRequest,
    _build_gateway_runtime,
)
from aegis_ot.workload_identity import WorkloadRole
from aegis_ot.workload_runtime import local_identity_from_environment, verifier_from_environment
runtime = _build_gateway_runtime()
correlation_id = str(uuid4())
observation = runtime.capture_pre(ObservationCaptureRequest(
    correlation_id=correlation_id,
    challenge_nonce=secrets.token_urlsafe(24),
))
action = CapabilityActionRequest(
    correlation_id=correlation_id,
    proposal=ActionProposal(
        proposal_id=f'm4g-rotation-fixture-{uuid4()}',
        actor_id='agent:operator-1',
        mission_id='microgrid-containment',
        resource='feeder-1',
        operation=Operation.ISOLATE_ASSET,
        parameters={'critical_load_impact_pct': 5.0},
        observed_state_version=observation.snapshot.state_version,
        observed_at=observation.snapshot.observed_at,
        submitted_at=datetime.now(UTC),
        nonce=secrets.token_urlsafe(24),
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=('grant-root', 'grant-leaf'),
    ),
    observation_id=observation.observation_id,
    observation_envelope_digest=observation.envelope_digest,
    observation_challenge_nonce=observation.challenge_nonce,
)
controller = runtime.controller
observed = controller.observer.resolve(
    observation_id=action.observation_id,
    envelope_digest=action.observation_envelope_digest,
)
evaluated_at = controller.clock()
observation_reasons = controller.observation_verifier.verify_pre(
    observed,
    action,
    evaluated_at=evaluated_at,
)
if observation_reasons:
    raise RuntimeError(
        'fresh rotation fixture observation was rejected: '
        + ','.join(observation_reasons)
    )
gateway_state = physical_state_to_gateway_state(observed.snapshot)
decision = controller.gateway.decide(action.proposal, gateway_state, evaluated_at)
if decision.outcome is not DecisionOutcome.PERMIT:
    raise RuntimeError(
        'fresh rotation fixture authorization was rejected: '
        + ','.join(decision.reasons)
    )
command = controller.translator.translate(action.proposal)
assessment = controller.simulator.simulate_candidate(command)
snapshot = observed.snapshot
candidate_matches = (
    assessment.command_digest == command.digest
    and assessment.pre_state.state_version == snapshot.state_version
    and assessment.pre_state.state_digest == snapshot.state_digest
    and assessment.pre_state.observation_digest == snapshot.observation_digest
    and assessment.pre_state.topology_digest == snapshot.topology_digest
    and assessment.pre_state.model_digest == snapshot.model_digest
)
if not assessment.safe or not candidate_matches:
    raise RuntimeError('fresh rotation fixture candidate was not safe and bound')
verifier = verifier_from_environment()
local = local_identity_from_environment(
    verifier,
    'GATEWAY',
    role=WorkloadRole.GATEWAY,
    audience=OT_CAPABILITY_AUDIENCE,
)
plc = controller.plc
target = plc.ot_identity.resolve(now=datetime.now(UTC))
permit = controller.permit_issuer.issue(
    request=action,
    pre_observation=observed,
    decision=decision,
    command=command,
    assessment=assessment,
)
dispatch = SegmentedCapabilityDispatch(
    request=action,
    pre_observation=observed,
    decision=decision,
    assessment=assessment,
    permit=permit,
)
issued_at = datetime.now(UTC)
signed = WorkloadSignedCapabilityDispatch.issue(
    dispatch=dispatch,
    signer=local.signer,
    transport_nonce=os.environ['AEGIS_M4G_FIXED_TRANSPORT_NONCE'],
    issued_at=issued_at,
    expires_at=issued_at + timedelta(seconds=30),
)
body = signed.model_dump_json().encode('utf-8')
request = Request(
    os.environ['AEGIS_OT_URL'].rstrip('/') + '/v1/capability/execute',
    data=body,
    headers={'Accept':'application/json','Content-Type':'application/json'},
    method='POST',
)
permit_remaining_ms_at_post = int(
    (permit.base_permit.expires_at - datetime.now(UTC)).total_seconds() * 1000
)
if permit_remaining_ms_at_post <= 0:
    raise RuntimeError('fresh rotation fixture permit expired before direct dispatch')
try:
    with urlopen(request, timeout=10) as response:
        status = response.status
        material = response.read(1048577)
except HTTPError as exc:
    status = exc.code
    material = exc.read(1048577)
if len(material) > 1048576:
    raise RuntimeError('direct OT response exceeded evidence limit')
response_value = json.loads(material)
response_verified = False
ack_status = None
ack_dispatch_phase = None
ack_reason = None
post_observation_verified = False
post_observation_digest = None
if status == 200:
    verified = WorkloadSignedCapabilityResponse.model_validate(response_value)
    response_verified = (
        verified.sender_credential == target.credential
        and verified.verify_for_request(
            target.public_key,
            request=signed,
            expected_plc_id=plc.ot.plc_id,
            expected_plc_boot_epoch=plc.ot.boot_epoch,
            evaluated_at=datetime.now(UTC),
        )
    )
    if not response_verified:
        raise RuntimeError('fresh rotation fixture response did not verify')
    acknowledgment = verified.response.acknowledgment
    ack_status = acknowledgment.status.value
    ack_dispatch_phase = acknowledgment.dispatch_phase.value
    ack_reason = acknowledgment.reason
    if (
        ack_status != 'applied'
        or ack_dispatch_phase != 'committed'
        or ack_reason != 'command_applied_and_plc_read_back'
    ):
        raise RuntimeError('fresh rotation fixture was not committed by the PLC')
    post_challenge_nonce = secrets.token_urlsafe(24)
    post_observation = controller.observer.capture_post(
        correlation_id=action.correlation_id,
        challenge_nonce=post_challenge_nonce,
        previous_envelope_digest=observed.envelope_digest,
        permit_id=permit.base_permit.permit_id,
        command_digest=permit.base_permit.command_digest,
        plc_acknowledgment_digest=acknowledgment.digest,
    )
    post_reasons = controller.observation_verifier.verify_post(
        post_observation,
        request=action,
        permit=permit,
        acknowledgment=acknowledgment,
        challenge_nonce=post_challenge_nonce,
        evaluated_at=controller.clock(),
    )
    if post_reasons:
        raise RuntimeError(
            'fresh rotation fixture post observation was rejected: '
            + ','.join(post_reasons)
        )
    post_observation_verified = True
    post_observation_digest = post_observation.envelope_digest
print(json.dumps({
    'fresh_transaction_prepared': True,
    'direct_dispatch_attempted': True,
    'fresh_transaction_request_digest': action.digest,
    'fresh_transaction_permit_id': permit.base_permit.permit_id,
    'fresh_transaction_dispatch_digest': dispatch.digest,
    'http_status': status,
    'response_verified': response_verified,
    'ack_status': ack_status,
    'ack_dispatch_phase': ack_dispatch_phase,
    'ack_reason': ack_reason,
    'post_observation_verified': post_observation_verified,
    'post_observation_digest': post_observation_digest,
    'permit_remaining_ms_at_post': permit_remaining_ms_at_post,
    'transport_nonce': signed.transport_nonce,
    'signed_request_sha256': signed.digest,
    'gateway_key_id': local.signer.credential.credential.key_id,
    'gateway_credential_id': local.signer.credential.credential.credential_id,
    'response': response_value,
},sort_keys=True,separators=(',',':')))
"""


def _rotation_fixture(
    prefix: tuple[str, ...],
    nonce: str,
) -> dict[str, Any]:
    completed = m4d._run(
        *prefix,
        "exec",
        "-T",
        "-e",
        f"AEGIS_M4G_FIXED_TRANSPORT_NONCE={nonce}",
        "segmented-gateway",
        "python",
        "-c",
        _ROTATION_FIXTURE_CODE,
    )
    return _json_object(completed.stdout, label="M4g rotation replay fixture")


def _run_agent_probe(
    prefix: tuple[str, ...],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return m4d._run(
        *prefix,
        "--profile",
        "experiment",
        "run",
        "--rm",
        "--no-deps",
        "agent-probe",
        check=check,
    )


def _probe_accepted(probe: dict[str, Any]) -> bool:
    nominal = probe.get("nominal", {})
    replay = probe.get("exact_gateway_request_replay", {})
    unsafe = probe.get("unsafe", {})
    reachability = probe.get("agent_direct_reachability", {})
    return (
        isinstance(nominal, dict)
        and nominal.get("status") == "completed"
        and nominal.get("dispatch_attempts") == 1
        and isinstance(replay, dict)
        and replay.get("status") == "not_dispatched"
        and replay.get("dispatch_attempts") == 0
        and "replayed_nonce" in replay.get("reasons", [])
        and isinstance(unsafe, dict)
        and unsafe.get("status") == "candidate_rejected"
        and unsafe.get("dispatch_attempts") == 0
        and isinstance(reachability, dict)
        and bool(reachability)
        and not any(reachability.values())
    )


def _rotate_gateway(
    prefix: tuple[str, ...],
    public_key_path: Path,
) -> dict[str, Any]:
    mount = f"{public_key_path.resolve()}:/run/rotation/gateway.public:ro"
    completed = m4d._run(
        *prefix,
        "--profile",
        "identity-admin",
        "run",
        "--rm",
        "--no-deps",
        "--volume",
        mount,
        "identity-admin",
        "rotate",
        "--credential-file",
        "/var/lib/aegis-ot/identity/gateway.credential.json",
        "--leaf-public-key-file",
        "/run/rotation/gateway.public",
        "--reason",
        "bounded M4g gateway leaf rotation",
        "--expected-sequence",
        "1",
    )
    return _json_object(completed.stdout, label="M4g gateway rotation")


_BUNDLE_MUTATOR_CODE = r"""
import base64, json, os, stat, sys
from pathlib import Path
payload = json.load(sys.stdin)
path = Path('/var/lib/aegis-ot/identity/trust-bundle.json')
if payload['operation'] == 'missing':
    path.unlink()
else:
    material = base64.b64decode(payload['bytes_base64'], validate=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                raise OSError('trust-bundle write made no progress')
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)
directory_descriptor = os.open(path.parent, os.O_RDONLY)
try:
    os.fsync(directory_descriptor)
finally:
    os.close(directory_descriptor)
print(json.dumps({'operation':payload['operation'],'present':path.exists()},sort_keys=True))
"""


def _mutate_bundle(
    prefix: tuple[str, ...],
    *,
    operation: str,
    material: bytes | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"operation": operation}
    if material is not None:
        payload["bytes_base64"] = base64.b64encode(material).decode("ascii")
    completed = _run_input(
        (
            *prefix,
            "--profile",
            "identity-admin",
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "python",
            "identity-admin",
            "-c",
            _BUNDLE_MUTATOR_CODE,
        ),
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
    )
    return _json_object(completed.stdout, label=f"trust-bundle mutation {operation}")


def _bundle_fault_case(
    prefix: tuple[str, ...],
    *,
    condition: str,
    fault_material: bytes | None,
    restore_material: bytes,
) -> dict[str, Any]:
    before = _service_health(prefix, "simulation", 8084)
    mutation: dict[str, Any] | None = None
    probe: subprocess.CompletedProcess[str] | None = None
    restored = False
    try:
        mutation = _mutate_bundle(
            prefix,
            operation="missing" if fault_material is None else "replace",
            material=fault_material,
        )
        probe = _run_agent_probe(prefix, check=False)
        after = _service_health(prefix, "simulation", 8084)
    finally:
        _mutate_bundle(prefix, operation="replace", material=restore_material)
        restored = True
    _await_gateway()
    if probe is None or mutation is None:
        raise m4d.ExperimentError(f"bundle fault case did not run: {condition}")
    no_effect = (
        before.get("state_version") == after.get("state_version")
        and before.get("state_digest") == after.get("state_digest")
        and before.get("commit_count") == after.get("commit_count")
    )
    return {
        "condition": condition,
        "mutation": mutation,
        "probe_exit_code": probe.returncode,
        "probe_stdout_tail": probe.stdout[-4000:],
        "probe_stderr_tail": probe.stderr[-4000:],
        "plant_before": before,
        "plant_after": after,
        "effect_absent": no_effect,
        "bundle_restored": restored,
        "accepted": probe.returncode != 0 and no_effect and restored,
    }


def _decode_artifact(snapshot: dict[str, Any], name: str) -> bytes:
    try:
        encoded = snapshot[name]["bytes_base64"]
        return base64.b64decode(encoded, validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise m4d.ExperimentError(f"identity artifact snapshot is malformed: {name}") from exc


def _only_gateway_recreated(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> bool:
    if before["segmented-gateway"]["container_id"] == after["segmented-gateway"][
        "container_id"
    ]:
        return False
    return all(
        before[service]["container_id"] == after[service]["container_id"]
        and before[service]["started_at"] == after[service]["started_at"]
        for service in OPERATIONAL_SERVICES
        if service != "segmented-gateway"
    )


def _cross_leaf_accepted(
    before: dict[str, Any],
    after: dict[str, Any],
) -> bool:
    response = after.get("response", {})
    return (
        before.get("http_status") == 200
        and before.get("fresh_transaction_prepared") is True
        and before.get("direct_dispatch_attempted") is True
        and before.get("response_verified") is True
        and before.get("ack_status") == "applied"
        and before.get("ack_dispatch_phase") == "committed"
        and before.get("ack_reason") == "command_applied_and_plc_read_back"
        and before.get("post_observation_verified") is True
        and isinstance(before.get("post_observation_digest"), str)
        and after.get("http_status") == 409
        and after.get("fresh_transaction_prepared") is True
        and after.get("direct_dispatch_attempted") is True
        and after.get("response_verified") is False
        and after.get("post_observation_verified") is False
        and before.get("transport_nonce") == after.get("transport_nonce")
        and before.get("gateway_key_id") != after.get("gateway_key_id")
        and before.get("gateway_credential_id") != after.get("gateway_credential_id")
        and before.get("signed_request_sha256") != after.get("signed_request_sha256")
        and before.get("fresh_transaction_request_digest")
        != after.get("fresh_transaction_request_digest")
        and before.get("fresh_transaction_permit_id")
        != after.get("fresh_transaction_permit_id")
        and before.get("fresh_transaction_dispatch_digest")
        != after.get("fresh_transaction_dispatch_digest")
        and isinstance(response, dict)
        and response.get("reason") == "transport_request_replayed"
    )


def _redacted_environment(
    environment: dict[str, str],
    key_directory: Path,
) -> dict[str, str]:
    return {
        name: _replace_path_prefix(value, key_directory, "<ephemeral-key-dir>")
        for name, value in sorted(environment.items())
    }


def _campaign(project_name: str, commit: str) -> dict[str, Any]:
    _assert_project_absent(project_name)
    _assert_checkout(commit)
    source_binding = _assert_source_checkout()
    key_directory = Path(tempfile.mkdtemp(prefix="aegis-ot-m4g-keys-"))
    prefix = _compose_prefix(project_name)
    project_created = False
    evidence: dict[str, Any] | None = None
    cleanup: dict[str, bool] = {}
    environment: dict[str, str] = {}
    try:
        key_paths, workload_key_ids = _provision_key_material(key_directory)
        environment = _campaign_environment(key_paths, workload_key_ids, commit)
        with _installed_environment(environment):
            compose = _json_object(
                m4d._run(
                    *prefix,
                    "--profile",
                    "experiment",
                    "--profile",
                    "identity-admin",
                    "config",
                    "--format",
                    "json",
                ).stdout,
                label="five-overlay M4g Compose config",
            )
            normalized_compose = _normalize(compose, key_directory, project_name)
            normalized_compose_sha256 = m4d._canonical_sha256(normalized_compose)
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "--profile",
                "identity-admin",
                "build",
                "--build-arg",
                f"AEGIS_SOURCE_REVISION={commit}",
                *CAMPAIGN_BUILD_SERVICES,
            )
            image_provenance = _image_provenance(compose, commit)
            project_created = True
            m4d._run(
                *prefix,
                "up",
                "-d",
                "--force-recreate",
                *OPERATIONAL_SERVICES,
            )
            gateway_health = _await_gateway()
            health_before = _health_snapshot(prefix)
            identity_initial = _identity_snapshot(prefix)
            replay_initial = _replay_snapshot(prefix)
            identity_initialization = _last_json_log(prefix, "identity-init")
            replay_initialization = _last_json_log(prefix, "replay-init")
            containers_before = _container_snapshot(prefix)

            primary_probe = _json_object(
                _run_agent_probe(prefix).stdout,
                label="primary M4g agent probe",
            )
            direct_before_rotation = _rotation_fixture(
                prefix,
                FIXED_ROTATION_NONCE,
            )
            replay_after_fixed_nonce = _replay_snapshot(prefix)

            rotated_paths, rotated_gateway_key_id = _provision_rotated_gateway(
                key_directory
            )
            rotation = _rotate_gateway(prefix, rotated_paths["gateway_public"])
            os.environ["AEGIS_GATEWAY_PRIVATE_KEY_FILE"] = str(
                rotated_paths["gateway_private"]
            )
            os.environ["AEGIS_GATEWAY_PUBLIC_KEY_FILE"] = str(
                rotated_paths["gateway_public"]
            )
            m4d._run(
                *prefix,
                "up",
                "-d",
                "--force-recreate",
                "--no-deps",
                "--no-build",
                "segmented-gateway",
            )
            gateway_health_after_rotation = _await_gateway()
            containers_after = _container_snapshot(prefix)
            identity_rotated = _identity_snapshot(prefix)

            fresh_after_rotation = _json_object(
                _run_agent_probe(prefix).stdout,
                label="post-rotation M4g agent probe",
            )
            direct_after_rotation = _rotation_fixture(
                prefix,
                FIXED_ROTATION_NONCE,
            )
            replay_after_rotation = _replay_snapshot(prefix)
            health_after_rotation = _health_snapshot(prefix)

            initial_bundle = _decode_artifact(identity_initial, "trust-bundle.json")
            rotated_bundle = _decode_artifact(identity_rotated, "trust-bundle.json")
            fault_cases = {
                "missing": _bundle_fault_case(
                    prefix,
                    condition="missing_trust_bundle",
                    fault_material=None,
                    restore_material=rotated_bundle,
                ),
                "corrupt": _bundle_fault_case(
                    prefix,
                    condition="corrupt_trust_bundle",
                    fault_material=b"{corrupt",
                    restore_material=rotated_bundle,
                ),
                "rollback": _bundle_fault_case(
                    prefix,
                    condition="same_process_trust_bundle_rollback",
                    fault_material=initial_bundle,
                    restore_material=rotated_bundle,
                ),
            }
            health_final = _health_snapshot(prefix)
            replay_final = _replay_snapshot(prefix)

            initial_gateway_credential = identity_initial[
                "gateway.credential.json"
            ]["document"]["credential"]
            rotated_gateway_credential = identity_rotated[
                "gateway.credential.json"
            ]["document"]["credential"]
            rotated_bundle_document = identity_rotated["trust-bundle.json"]["document"]
            revoked_ids = {
                item.get("credential_id")
                for item in rotated_bundle_document.get("revocations", [])
                if isinstance(item, dict)
            }
            workload_document = replay_after_rotation["workload-replay.json"][
                "document"
            ]
            reservations = {
                item.get("nonce"): item.get("signed_request_sha256")
                for item in workload_document.get("reservations", [])
                if isinstance(item, dict)
            }
            acceptance = {
                "clean_source_bound_to_images_and_containers": (
                    gateway_health.get("status") == "ready"
                    and all(
                        item.get("oci_revision") == commit
                        for item in image_provenance.values()
                    )
                    and all(
                        containers_before[service].get("oci_revision") == commit
                        for service in (
                            "simulation",
                            "observer",
                            "candidate",
                            "ot-adapter",
                            "segmented-gateway",
                            "identity-init",
                            "replay-init",
                        )
                    )
                ),
                "identity_and_replay_initialized_private": (
                    identity_initialization.get("authority_key_id")
                    == workload_key_ids["workload_authority"]
                    and replay_initialization.get("authority_key_id")
                    == workload_key_ids["workload_authority"]
                    and identity_initialization.get("directory_mode") == "0700"
                    and identity_initialization.get("artifact_mode") == "0600"
                    and replay_initialization.get("directory_mode") == "0700"
                    and replay_initialization.get("workload_ledger_mode") == "0600"
                    and replay_initialization.get("semantic_ledger_mode") == "0600"
                ),
                "primary_agent_campaign_accepted": _probe_accepted(primary_probe),
                "gateway_leaf_rotated_same_subject_and_old_leaf_revoked": (
                    rotation.get("operation") == "rotate"
                    and rotation.get("prior_sequence") == 1
                    and rotation.get("published_sequence") == 2
                    and initial_gateway_credential.get("subject")
                    == rotated_gateway_credential.get("subject")
                    == GATEWAY_SUBJECT
                    and initial_gateway_credential.get("key_id")
                    == workload_key_ids["gateway"]
                    and rotated_gateway_credential.get("key_id")
                    == rotated_gateway_key_id
                    and initial_gateway_credential.get("credential_id") in revoked_ids
                ),
                "only_gateway_recreated_for_leaf_rotation": _only_gateway_recreated(
                    containers_before,
                    containers_after,
                ),
                "fresh_request_after_rotation_accepted": _probe_accepted(
                    fresh_after_rotation
                ),
                "cross_leaf_reused_transport_nonce_rejected": (
                    _cross_leaf_accepted(
                        direct_before_rotation,
                        direct_after_rotation,
                    )
                    and reservations.get(FIXED_ROTATION_NONCE)
                    == direct_before_rotation.get("signed_request_sha256")
                ),
                "stable_replay_subject_survived_leaf_rotation": (
                    workload_document.get("workload_subject") == GATEWAY_SUBJECT
                    and workload_document.get("authority_key_id")
                    == workload_key_ids["workload_authority"]
                    and "key_id" not in workload_document
                    and "public_key" not in workload_document
                ),
                "bundle_faults_failed_closed_without_effect": all(
                    item.get("accepted") is True for item in fault_cases.values()
                ),
            }
            semantic_projection = {
                "git_commit": commit,
                "normalized_compose_sha256": normalized_compose_sha256,
                "workload_key_ids": {
                    "authority": workload_key_ids["workload_authority"],
                    "agent": workload_key_ids["agent"],
                    "gateway_initial": workload_key_ids["gateway"],
                    "gateway_rotated": rotated_gateway_key_id,
                    "ot": workload_key_ids["ot"],
                },
                "primary_probe": {
                    "nominal_status": primary_probe.get("nominal", {}).get("status"),
                    "replay_status": primary_probe.get(
                        "exact_gateway_request_replay", {}
                    ).get("status"),
                    "unsafe_status": primary_probe.get("unsafe", {}).get("status"),
                    "direct_reachability": primary_probe.get(
                        "agent_direct_reachability"
                    ),
                },
                "rotation": {
                    "prior_sequence": rotation.get("prior_sequence"),
                    "published_sequence": rotation.get("published_sequence"),
                    "same_subject": initial_gateway_credential.get("subject")
                    == rotated_gateway_credential.get("subject"),
                    "old_credential_revoked": initial_gateway_credential.get(
                        "credential_id"
                    )
                    in revoked_ids,
                    "only_gateway_recreated": _only_gateway_recreated(
                        containers_before,
                        containers_after,
                    ),
                },
                "cross_leaf_replay": {
                    "initial_status": direct_before_rotation.get("http_status"),
                    "rotated_status": direct_after_rotation.get("http_status"),
                    "same_nonce": direct_before_rotation.get("transport_nonce")
                    == direct_after_rotation.get("transport_nonce"),
                    "request_digests_differ": direct_before_rotation.get(
                        "signed_request_sha256"
                    )
                    != direct_after_rotation.get("signed_request_sha256"),
                },
                "bundle_faults": {
                    name: {
                        "probe_exit_code": item.get("probe_exit_code"),
                        "effect_absent": item.get("effect_absent"),
                    }
                    for name, item in fault_cases.items()
                },
                "acceptance": acceptance,
            }
            evidence = {
                "schema_version": "m4g-workload-identity-experiment-v1",
                "generated_at": datetime.now(UTC).isoformat(),
                "analyst": "Angelis Pseftis",
                "git_commit": commit,
                "clean_checkout_start": True,
                "project_name": project_name,
                "source_checkout_binding": source_binding,
                "compose_files": list(COMPOSE_FILES),
                "normalized_compose_sha256": normalized_compose_sha256,
                "campaign_environment": _redacted_environment(
                    environment,
                    key_directory,
                ),
                "image_provenance": image_provenance,
                "workload_public_key_ids": {
                    **workload_key_ids,
                    "gateway_rotated": rotated_gateway_key_id,
                },
                "private_key_material_retained": False,
                "identity_initialization": identity_initialization,
                "replay_initialization": replay_initialization,
                "identity_initial": identity_initial,
                "replay_initial": replay_initial,
                "health_before": health_before,
                "containers_before_rotation": containers_before,
                "primary_probe": primary_probe,
                "rotation_fixture_classification": (
                    "Gateway-internal fresh full-authorization and OT-transport "
                    "fixture; agent ingress is exercised separately by agent-probe"
                ),
                "direct_dispatch_before_rotation": direct_before_rotation,
                "replay_after_fixed_nonce": replay_after_fixed_nonce,
                "rotation": rotation,
                "gateway_health_after_rotation": gateway_health_after_rotation,
                "identity_rotated": identity_rotated,
                "containers_after_rotation": containers_after,
                "fresh_probe_after_rotation": fresh_after_rotation,
                "direct_dispatch_after_rotation": direct_after_rotation,
                "replay_after_rotation": replay_after_rotation,
                "health_after_rotation": health_after_rotation,
                "bundle_fault_cases": fault_cases,
                "health_final": health_final,
                "replay_final": replay_final,
                "acceptance": acceptance,
                "accepted": all(acceptance.values()),
                "semantic_projection": semantic_projection,
                "semantic_outcome_sha256": m4d._canonical_sha256(
                    semantic_projection
                ),
                "evidence_boundary": [
                    (
                        "Application-layer authority-signed workload credentials, "
                        "not mTLS or SPIFFE runtime attestation"
                    ),
                    (
                        "One single-host Docker Compose campaign, not multi-host "
                        "or multi-replica validation"
                    ),
                    (
                        "Same-process signed-bundle rollback rejection, not hostile "
                        "restart rollback resistance"
                    ),
                    (
                        "Durable stable-subject replay admission, not exactly-once "
                        "physical effects"
                    ),
                    (
                        "Synthetic plant and local campaign evidence, not production "
                        "OT deployment or independent validation"
                    ),
                    (
                        "Ephemeral experiment keys were removed and no runtime received "
                        "the authority private key"
                    ),
                    (
                        "The fixed-nonce rotation fixture runs inside the gateway "
                        "workload; it does not represent a second agent-ingress test"
                    ),
                ],
            }
            _assert_checkout(commit)
            if evidence["accepted"] is not True:
                raise m4d.ExperimentError(
                    "M4g workload-identity acceptance criteria were not all satisfied"
                )
    finally:
        if project_created:
            # Compose must still resolve its required secret paths while it
            # identifies the scoped project resources to remove.
            with _installed_environment(environment):
                down = m4d._run(
                    *prefix,
                    "down",
                    "-v",
                    "--remove-orphans",
                    check=False,
                )
            cleanup["compose_project_removed"] = down.returncode == 0
        else:
            cleanup["compose_project_removed"] = True
        for suffix in PROJECT_VOLUME_SUFFIXES:
            cleanup[f"{suffix}_volume_removed"] = (
                m4d._run(
                    "docker",
                    "volume",
                    "inspect",
                    f"{project_name}_{suffix}",
                    check=False,
                ).returncode
                != 0
            )
        shutil.rmtree(key_directory, ignore_errors=True)
        cleanup["private_key_directory_removed"] = not key_directory.exists()
    if evidence is None:
        raise m4d.ExperimentError("M4g campaign ended without accepted evidence")
    evidence["cleanup"] = cleanup
    if not all(cleanup.values()):
        raise m4d.ExperimentError("M4g scoped cleanup was incomplete")
    return evidence


def run_experiment(output: Path, project_name: str) -> dict[str, Any]:
    _assert_source_checkout()
    if output.exists() or output.is_symlink():
        raise m4d.ExperimentError("refusing to overwrite retained M4g evidence")
    if m4d._run("git", "status", "--porcelain").stdout:
        raise m4d.ExperimentError("M4g retained evidence requires a clean checkout")
    commit = m4d._run("git", "rev-parse", "HEAD").stdout.strip()
    _assert_checkout(commit)
    evidence = _campaign(project_name, commit)
    _assert_checkout(commit)
    evidence["clean_checkout_end"] = True
    try:
        m4d._atomic_write_json(output, evidence)
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project", default="aegis-ot-m4g-primary")
    arguments = parser.parse_args()
    evidence = run_experiment(arguments.output, arguments.project)
    print(
        json.dumps(
            {
                "accepted": evidence["accepted"],
                "semantic_outcome_sha256": evidence["semantic_outcome_sha256"],
                "output": str(arguments.output),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
