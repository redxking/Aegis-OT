"""Run one bounded clean-checkout M4i coordination and recovery campaign.

The campaign is a single-host, single-writer synthetic exercise over trusted,
intact Docker volumes.  It demonstrates at-most-one commit transmission plus
query recovery.  It does not claim exactly-once effects, distributed consensus,
hostile-host rollback resistance, deployment, or external validation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import run_m4d_experiment as m4d
import run_m4g_experiment as m4g

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.auth.yml",
    "docker-compose.replay.yml",
    "docker-compose.capability.yml",
    "docker-compose.identity.yml",
    "docker-compose.coordination.yml",
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
    "identity-init",
    "replay-init",
    "coordination-init",
    "simulation",
    "observer",
    "candidate",
    "ot-adapter",
    "segmented-gateway",
    "agent-probe",
)
PROJECT_VOLUME_SUFFIXES = (
    *m4g.PROJECT_VOLUME_SUFFIXES,
    "gateway_coordination",
    "ot_coordination",
    "plant_checkpoint",
)
SOURCE_BINDING_FILES = (
    *COMPOSE_FILES,
    "Dockerfile",
    "pyproject.toml",
    "scripts/export_schemas.py",
    "scripts/run_m4d_experiment.py",
    "scripts/run_m4g_experiment.py",
    "scripts/run_m4i_experiment.py",
    "src/aegis_ot/coordination_journal.py",
    "src/aegis_ot/coordination_models.py",
    "src/aegis_ot/coordination_recovery.py",
    "src/aegis_ot/m4g_probe.py",
    "src/aegis_ot/m4i_coordination_init.py",
    "src/aegis_ot/pandapower_plant.py",
    "src/aegis_ot/plant_checkpoint.py",
    "src/aegis_ot/segmented_capability_runtime.py",
    "src/aegis_ot/segmented_capability_transport.py",
)
LOCK_FILE = "requirements.lock"
M4I_SCHEMA_FILES = (
    "schemas/m4i-capability-outcome-pending.schema.json",
    "schemas/m4i-capability-outcome-resolution.schema.json",
    "schemas/m4i-coordination-receipt.schema.json",
    "schemas/m4i-durable-commit-acceptance.schema.json",
    "schemas/m4i-effect-identity.schema.json",
    "schemas/m4i-signed-effect-commit-request.schema.json",
    "schemas/m4i-signed-effect-outcome.schema.json",
    "schemas/m4i-signed-effect-prepare-request.schema.json",
    "schemas/m4i-signed-effect-query-request.schema.json",
    "schemas/m4i-workload-effect-reconciliation.schema.json",
)
RECONCILIATION_ENDPOINT = "/v1/capability/effects/reconcile"
GATEWAY_DIRECTORY = "/var/lib/aegis-ot/gateway-coordination"
OT_DIRECTORY = "/var/lib/aegis-ot/ot-coordination"
PLANT_DIRECTORY = "/var/lib/aegis-ot/plant-checkpoint"
GATEWAY_FILE = f"{GATEWAY_DIRECTORY}/gateway-coordination.json"
OT_FILE = f"{OT_DIRECTORY}/ot-coordination.json"
PLANT_FILE = f"{PLANT_DIRECTORY}/plant-checkpoint.json"
MAX_RETAINED_BYTES = 1_048_576
DEFAULT_READY_TIMEOUT_SECONDS = 30.0
DEFAULT_POLL_SECONDS = 0.25

ACCEPTANCE_GATE_NAMES = (
    "required_coordination_health",
    "nominal_effect_one_prepare_one_commit",
    "lost_commit_response_remains_unknown",
    "agent_reconciliation_one_query_zero_commit_retries",
    "gateway_ot_restart_preserves_byte_equivalent_resolution",
    "plant_checkpoint_restores_exact_state",
    "unresolved_effect_blocks_fresh_action_and_second_prepare",
    "isolated_private_gateway_ot_plant_state",
    "state_corruption_fails_closed",
    "cleanup_and_private_material_deletion",
)

EVIDENCE_BOUNDARIES = (
    (
        "Single-host, single-writer application coordination over trusted, intact "
        "Docker volumes; not a distributed-system or hostile-storage claim"
    ),
    (
        "At most one commit transmission for the tested effect followed by query "
        "recovery; not exactly-once execution"
    ),
    "No distributed consensus or multi-replica coordination is established",
    "No hostile-host rollback resistance or external monotonic anchor is established",
    "Synthetic plant and local Compose evidence; not deployment or production OT",
    "Local retained evidence; not independent or external validation",
    (
        "The scoped relay forwards one exact commit and discards its response; it is "
        "campaign infrastructure, not a production fault-control endpoint"
    ),
)

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _file_sha256(relative_path: str) -> str:
    path = ROOT / relative_path
    if not path.is_file() or path.is_symlink():
        raise m4d.ExperimentError(f"source-binding file was missing: {relative_path}")
    return _sha256(path.read_bytes())


def _compose_prefix(project_name: str) -> tuple[str, ...]:
    prefix: list[str] = ["docker", "compose", "-p", project_name]
    for filename in COMPOSE_FILES:
        prefix.extend(("-f", filename))
    return tuple(prefix)


def _validate_project_name(project_name: str) -> None:
    if _PROJECT_NAME.fullmatch(project_name) is None:
        raise m4d.ExperimentError("M4i project name must be a bounded lowercase Compose name")


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
    relay = m4d._run(
        "docker",
        "container",
        "inspect",
        _relay_name(project_name),
        check=False,
    ).returncode == 0
    if containers or volumes or relay:
        raise m4d.ExperimentError(
            f"M4i project name is already in use; refusing cleanup: {project_name}"
        )


def _assert_checkout(commit: str) -> None:
    m4g._assert_checkout(commit)


def _source_binding(commit: str) -> dict[str, Any]:
    checkout = m4g._assert_source_checkout()
    tree = m4d._run("git", "rev-parse", "HEAD^{tree}").stdout.strip()
    if _GIT_OBJECT.fullmatch(tree) is None:
        raise m4d.ExperimentError("M4i git tree binding was malformed")
    source_files = {path: _file_sha256(path) for path in SOURCE_BINDING_FILES}
    schemas = {path: _file_sha256(path) for path in M4I_SCHEMA_FILES}
    lock = {"path": LOCK_FILE, "sha256": _file_sha256(LOCK_FILE)}
    binding: dict[str, Any] = {
        "git_commit": commit,
        "git_tree": tree,
        "checkout": checkout,
        "source_files": source_files,
        "source_files_sha256": _sha256(_canonical_bytes(source_files)),
        "dependency_lock": lock,
        "schemas": schemas,
        "schema_set_sha256": _sha256(_canonical_bytes(schemas)),
    }
    binding["source_binding_sha256"] = _sha256(_canonical_bytes(binding))
    return binding


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _service(compose: dict[str, Any], name: str) -> dict[str, Any]:
    services = _mapping(compose.get("services"))
    service = services.get(name)
    if not isinstance(service, dict):
        raise m4d.ExperimentError(f"resolved Compose service was missing: {name}")
    return service


def _environment(compose: dict[str, Any], name: str) -> dict[str, Any]:
    environment = _service(compose, name).get("environment")
    if not isinstance(environment, dict):
        raise m4d.ExperimentError(f"resolved Compose environment was missing: {name}")
    return environment


def _mount_source(compose: dict[str, Any], service: str, target: str) -> str:
    volumes = _service(compose, service).get("volumes")
    if not isinstance(volumes, list):
        raise m4d.ExperimentError(f"resolved Compose volumes were missing: {service}")
    matches = [
        item.get("source")
        for item in volumes
        if isinstance(item, dict) and item.get("target") == target
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise m4d.ExperimentError(
            f"resolved Compose mount was not unique: {service}:{target}"
        )
    return matches[0]


def _configuration_binding(
    compose: dict[str, Any],
    *,
    key_directory: Path,
    project_name: str,
) -> dict[str, Any]:
    gateway_environment = _environment(compose, "segmented-gateway")
    ot_environment = _environment(compose, "ot-adapter")
    plant_environment = _environment(compose, "simulation")
    initializer = _service(compose, "coordination-init")
    initializer_environment = _environment(compose, "coordination-init")
    expected = (
        (gateway_environment, "AEGIS_GATEWAY_COORDINATION_JOURNAL_FILE", GATEWAY_FILE),
        (ot_environment, "AEGIS_OT_COORDINATION_JOURNAL_FILE", OT_FILE),
        (plant_environment, "AEGIS_PLANT_CHECKPOINT_FILE", PLANT_FILE),
    )
    if any(environment.get(name) != value for environment, name, value in expected):
        raise m4d.ExperimentError("resolved M4i state paths were not exact")
    if any(
        environment.get("AEGIS_EFFECT_COORDINATION_MODE") != "required"
        for environment in (gateway_environment, ot_environment, plant_environment)
    ):
        raise m4d.ExperimentError("resolved M4i coordination mode was not required")
    if initializer.get("network_mode") != "none" or "secrets" in initializer:
        raise m4d.ExperimentError("coordination initializer was not offline and secretless")
    mounts = {
        "gateway": _mount_source(compose, "segmented-gateway", GATEWAY_DIRECTORY),
        "ot": _mount_source(compose, "ot-adapter", OT_DIRECTORY),
        "plant": _mount_source(compose, "simulation", PLANT_DIRECTORY),
    }
    if len(set(mounts.values())) != 3:
        raise m4d.ExperimentError("resolved M4i state volumes were not isolated")
    for service in ("segmented-gateway", "ot-adapter", "simulation"):
        depends = _mapping(_service(compose, service).get("depends_on"))
        init_dependency = _mapping(depends.get("coordination-init"))
        if init_dependency.get("condition") != "service_completed_successfully":
            raise m4d.ExperimentError(
                f"{service} was not gated on successful coordination initialization"
            )
    normalized = m4g._normalize(compose, key_directory, project_name)
    if not isinstance(normalized, dict):
        raise m4d.ExperimentError("normalized M4i Compose configuration was malformed")
    return {
        "compose_files": {
            path: _file_sha256(path) for path in COMPOSE_FILES
        },
        "normalized_compose": normalized,
        "normalized_compose_sha256": _sha256(_canonical_bytes(normalized)),
        "coordination_modes": {
            "gateway": gateway_environment["AEGIS_EFFECT_COORDINATION_MODE"],
            "ot": ot_environment["AEGIS_EFFECT_COORDINATION_MODE"],
            "plant": plant_environment["AEGIS_EFFECT_COORDINATION_MODE"],
        },
        "state_paths": {
            "gateway": gateway_environment["AEGIS_GATEWAY_COORDINATION_JOURNAL_FILE"],
            "ot": ot_environment["AEGIS_OT_COORDINATION_JOURNAL_FILE"],
            "plant": plant_environment["AEGIS_PLANT_CHECKPOINT_FILE"],
        },
        "state_volumes": mounts,
        "state_runtime_ids": {
            "gateway": {
                "uid": initializer_environment.get("AEGIS_GATEWAY_RUNTIME_UID"),
                "gid": initializer_environment.get("AEGIS_GATEWAY_RUNTIME_GID"),
            },
            "ot": {
                "uid": initializer_environment.get("AEGIS_OT_RUNTIME_UID"),
                "gid": initializer_environment.get("AEGIS_OT_RUNTIME_GID"),
            },
            "plant": {
                "uid": initializer_environment.get("AEGIS_PLANT_RUNTIME_UID"),
                "gid": initializer_environment.get("AEGIS_PLANT_RUNTIME_GID"),
            },
        },
    }


_AGENT_EXCHANGE_CODE = r"""
import base64
import hashlib
import json
import secrets
import sys
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

from aegis_ot.capability_models import CapabilityActionRequest
from aegis_ot.coordination_models import WorkloadAuthenticatedEffectReconciliation
from aegis_ot.m4g_probe import _await_gateway, _capture_pre, _gateway_url, _request
from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    WorkloadAuthenticatedCapabilityAction,
)
from aegis_ot.workload_identity import WorkloadRole
from aegis_ot.workload_runtime import local_identity_from_environment, verifier_from_environment

inputs = json.loads(sys.stdin.read())
if not isinstance(inputs, dict) or set(inputs) != {'mode', 'material'}:
    raise RuntimeError('M4i agent exchange input was not closed')
mode = inputs['mode']
material = inputs['material']
if not isinstance(material, dict):
    raise RuntimeError('M4i agent exchange material was not an object')
url = _gateway_url()
_await_gateway(url)
verifier = verifier_from_environment()
agent = local_identity_from_environment(
    verifier,
    'AGENT',
    role=WorkloadRole.AGENT,
    audience=GATEWAY_CAPABILITY_AUDIENCE,
)

def exchange(path, payload):
    body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    request = Request(
        url.rstrip('/') + path,
        data=body,
        headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urlopen(request, timeout=20) as response:
            status = response.status
            raw = response.read(1048577)
    except HTTPError as exc:
        status = exc.code
        raw = exc.read(1048577)
    if len(raw) > 1048576:
        raise RuntimeError('M4i gateway response exceeded evidence limit')
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise RuntimeError('M4i gateway response was not an object')
    return {
        'http_status': status,
        'response': document,
        'response_bytes_base64': base64.b64encode(raw).decode('ascii'),
        'response_sha256': hashlib.sha256(raw).hexdigest(),
    }

if mode == 'prepare_action':
    observation = _capture_pre(url, str(uuid4()))
    action = _request(
        observation,
        proposal_id=f'm4i-live-{uuid4()}',
        critical_load_impact_pct=5.0,
    )
    issued_at = datetime.now(UTC)
    wire = WorkloadAuthenticatedCapabilityAction.issue(
        request=action,
        signer=agent.signer,
        request_nonce=action.proposal.nonce,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=60),
    )
    output = {
        'mode': mode,
        'action': action.model_dump(mode='json'),
        'action_sha256': action.digest,
        'wire_request': wire.model_dump(mode='json'),
        'wire_request_sha256': wire.digest,
        'agent_credential_id': agent.signer.credential.credential.credential_id,
        'agent_subject': agent.signer.credential.credential.subject,
    }
elif mode == 'submit_action':
    wire = WorkloadAuthenticatedCapabilityAction.model_validate_json(
        json.dumps(material['wire_request'], sort_keys=True, separators=(',', ':'))
    )
    output = {
        'mode': mode,
        'action': wire.request.model_dump(mode='json'),
        'action_sha256': wire.request.digest,
        'wire_request_sha256': wire.digest,
        **exchange('/v1/capability/actions', wire.model_dump(mode='json')),
    }
elif mode == 'reconcile':
    action = CapabilityActionRequest.model_validate_json(
        json.dumps(material['action'], sort_keys=True, separators=(',', ':'))
    )
    issued_at = datetime.now(UTC)
    request_nonce = secrets.token_urlsafe(24)
    wire = WorkloadAuthenticatedEffectReconciliation.issue(
        request=action,
        signer=agent.signer,
        request_nonce=request_nonce,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=60),
    )
    output = {
        'mode': mode,
        'action_sha256': action.digest,
        'proof_sha256': wire.digest,
        'request_nonce': request_nonce,
        'proposal_nonce': action.proposal.nonce,
        'credential_role': wire.sender_credential.credential.role.value,
        'agent_credential_id': wire.sender_credential.credential.credential_id,
        'agent_subject': wire.sender_credential.credential.subject,
        **exchange(
            '/v1/capability/effects/reconcile',
            wire.model_dump(mode='json'),
        ),
    }
else:
    raise RuntimeError(f'unsupported M4i agent exchange mode: {mode}')
print(json.dumps(output, sort_keys=True, separators=(',', ':')))
""".strip()


_ARTIFACT_SNAPSHOT_CODE = r"""
import base64
import hashlib
import json
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
lock_path = path.with_name(f'.{path.name}.writer.lock')
material = path.read_bytes()
if len(material) > 1048576:
    raise RuntimeError('M4i state artifact exceeded evidence limit')
document = json.loads(material)
if not isinstance(document, dict):
    raise RuntimeError('M4i state artifact was not an object')

def metadata(item):
    status = item.stat()
    return {
        'path': str(item),
        'mode': format(stat.S_IMODE(status.st_mode), '04o'),
        'uid': status.st_uid,
        'gid': status.st_gid,
        'regular': stat.S_ISREG(status.st_mode),
        'symlink': item.is_symlink(),
    }

print(json.dumps({
    'bytes_base64': base64.b64encode(material).decode('ascii'),
    'sha256': hashlib.sha256(material).hexdigest(),
    'document': document,
    'directory': metadata(path.parent),
    'artifact': metadata(path),
    'writer_lock': metadata(lock_path),
}, sort_keys=True, separators=(',', ':')))
""".strip()


_ARTIFACT_MUTATOR_CODE = r"""
import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

path = Path(sys.argv[1])
operation = sys.argv[2]
if operation == 'corrupt':
    material = b'{corrupt-m4i-state'
elif operation == 'restore':
    material = base64.b64decode(sys.stdin.read().encode('ascii'), validate=True)
else:
    raise RuntimeError('unsupported M4i artifact mutation')
temporary = path.with_name(f'.{path.name}.{uuid4().hex}.campaign.tmp')
descriptor = os.open(
    temporary,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_CLOEXEC', 0),
    0o600,
)
try:
    offset = 0
    while offset < len(material):
        written = os.write(descriptor, material[offset:])
        if written <= 0:
            raise OSError('M4i artifact mutation made no progress')
        offset += written
    os.fsync(descriptor)
finally:
    os.close(descriptor)
os.replace(temporary, path)
directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(json.dumps({
    'operation': operation,
    'sha256': hashlib.sha256(material).hexdigest(),
    'size_bytes': len(material),
}, sort_keys=True, separators=(',', ':')))
""".strip()


_COMMIT_RESPONSE_RELAY_CODE = r"""
import hashlib
import http.client
import json
import os
import socket
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from aegis_ot.coordination_models import (
    CoordinationReceipt,
    SignedEffectCommitRequest,
    SignedEffectOutcome,
    SignedEffectPrepareRequest,
)

CONTROL = Path('/evidence/arm.json')
STATUS = Path('/evidence/relay.json')
TARGET_HOST = os.environ['AEGIS_M4I_RELAY_TARGET_HOST']
TARGET_PORT = int(os.environ['AEGIS_M4I_RELAY_TARGET_PORT'])
LOCK = threading.Lock()
STATE = {
    'schema_version': 'm4i-scoped-commit-response-relay-v1',
    'armed_action_sha256': None,
    'prepare_request_sha256': None,
    'commit_request_sha256': None,
    'commit_response_sha256': None,
    'commit_response_discarded': False,
    'path_counters': {'health': 0, 'prepare': 0, 'commit': 0, 'query': 0, 'other': 0},
    'violations': [],
}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')

def persist():
    temporary = STATUS.with_name(f'.{STATUS.name}.{uuid4().hex}.tmp')
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_CLOEXEC', 0),
        0o600,
    )
    try:
        material = canonical(STATE)
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                raise OSError('relay status write made no progress')
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, STATUS)

def violation(reason):
    STATE['violations'].append(reason)
    persist()

def arm():
    if STATE['armed_action_sha256'] is not None:
        return STATE['armed_action_sha256']
    try:
        material = CONTROL.read_bytes()
        value = json.loads(material)
    except Exception as exc:
        raise RuntimeError('relay arm control is unavailable') from exc
    if (
        not isinstance(value, dict)
        or set(value) != {'schema_version', 'expected_action_sha256'}
        or value['schema_version'] != 'm4i-scoped-relay-arm-v1'
        or not isinstance(value['expected_action_sha256'], str)
        or len(value['expected_action_sha256']) != 64
        or any(character not in '0123456789abcdef'
               for character in value['expected_action_sha256'])
    ):
        raise RuntimeError('relay arm control is malformed')
    STATE['armed_action_sha256'] = value['expected_action_sha256']
    persist()
    return value['expected_action_sha256']

def forward(method, path, body, headers):
    connection = http.client.HTTPConnection(TARGET_HOST, TARGET_PORT, timeout=10)
    outbound = {
        'Accept': 'application/json',
        'Connection': 'close',
    }
    content_type = headers.get('Content-Type')
    if content_type:
        outbound['Content-Type'] = content_type
    connection.request(method, path, body=body or None, headers=outbound)
    response = connection.getresponse()
    material = response.read(1048577)
    if len(material) > 1048576:
        raise RuntimeError('relayed response exceeded evidence limit')
    result = (response.status, response.getheader('Content-Type') or '', material)
    connection.close()
    return result

class Relay(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, _format, *_args):
        return

    def reject(self, reason):
        with LOCK:
            violation(reason)
        body = canonical({'status': 'rejected', 'reason': reason})
        self.send_response(409)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != '/health':
            with LOCK:
                STATE['path_counters']['other'] += 1
            self.reject('relay_unexpected_path')
            return
        with LOCK:
            STATE['path_counters']['health'] += 1
            persist()
        try:
            status, content_type, material = forward('GET', '/health', b'', self.headers)
        except Exception:
            self.reject('relay_health_forward_failed')
            return
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(material)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(material)

    def do_POST(self):
        length = self.headers.get('Content-Length')
        if length is None or not length.isdigit() or int(length) > 1048576:
            self.reject('relay_request_size_rejected')
            return
        body = self.rfile.read(int(length))
        if self.path == '/v1/effects/query':
            with LOCK:
                STATE['path_counters']['query'] += 1
            self.reject('relay_query_forbidden')
            return
        if self.path not in {'/v1/effects/prepare', '/v1/effects/commit'}:
            with LOCK:
                STATE['path_counters']['other'] += 1
            self.reject('relay_unexpected_path')
            return
        try:
            if self.path == '/v1/effects/prepare':
                request = SignedEffectPrepareRequest.model_validate_json(body)
                request_sha256 = request.digest
                with LOCK:
                    expected_action = arm()
                    if (
                        STATE['path_counters']['prepare'] != 0
                        or STATE['path_counters']['commit'] != 0
                        or request.effect.request_sha256 != expected_action
                        or not request.verify()
                    ):
                        raise RuntimeError('prepare request was not the armed action')
                    STATE['path_counters']['prepare'] = 1
                    STATE['prepare_request_sha256'] = request_sha256
                    persist()
                status, content_type, material = forward(
                    'POST', self.path, body, self.headers
                )
                receipt = CoordinationReceipt.model_validate_json(material)
                if (
                    not 200 <= status < 300
                    or receipt.prepare_request_sha256 != request_sha256
                    or not receipt.verify()
                ):
                    raise RuntimeError('prepare response did not bind the exact request')
            else:
                request = SignedEffectCommitRequest.model_validate_json(body)
                request_sha256 = request.digest
                with LOCK:
                    expected_action = arm()
                    if (
                        STATE['path_counters']['prepare'] != 1
                        or STATE['path_counters']['commit'] != 0
                        or request.effect.request_sha256 != expected_action
                        or request.receipt.prepare_request_sha256
                        != STATE['prepare_request_sha256']
                        or not request.verify()
                        or not request.receipt.verify()
                    ):
                        raise RuntimeError(
                            'commit request was not the armed prepared action'
                        )
                    STATE['path_counters']['commit'] = 1
                    STATE['commit_request_sha256'] = request_sha256
                    persist()
                status, content_type, material = forward(
                    'POST', self.path, body, self.headers
                )
                outcome = SignedEffectOutcome.model_validate_json(material)
                if (
                    not 200 <= status < 300
                    or outcome.request_kind != 'commit'
                    or outcome.request_sha256 != request_sha256
                    or not outcome.verify()
                ):
                    raise RuntimeError('commit response did not bind the exact request')
                with LOCK:
                    STATE['commit_response_sha256'] = hashlib.sha256(material).hexdigest()
                    STATE['commit_response_discarded'] = True
                    persist()
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                return
        except Exception as exc:
            self.reject(f'relay_validation_failed:{type(exc).__name__}')
            return
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(material)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(material)

persist()
server = ThreadingHTTPServer(('0.0.0.0', 8083), Relay)
server.serve_forever()
""".strip()


def _json_object(raw: str, *, label: str) -> dict[str, Any]:
    return m4g._json_object(raw, label=label)


def _run_input(
    args: tuple[str, ...],
    input_text: str,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return m4g._run_input(args, input_text, check=check)


def _run_agent_exchange(
    prefix: tuple[str, ...],
    *,
    mode: str,
    material: dict[str, Any] | None = None,
) -> dict[str, Any]:
    completed = _run_input(
        (
            *prefix,
            "--profile",
            "experiment",
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "agent-probe",
            "python",
            "-c",
            _AGENT_EXCHANGE_CODE,
        ),
        json.dumps(
            {"mode": mode, "material": material or {}},
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return _json_object(completed.stdout, label=f"M4i agent exchange {mode}")


def _artifact_snapshot(
    prefix: tuple[str, ...],
    *,
    service: str,
    path: str,
) -> dict[str, Any]:
    completed = m4d._run(
        *prefix,
        "exec",
        "-T",
        service,
        "python",
        "-c",
        _ARTIFACT_SNAPSHOT_CODE,
        path,
    )
    return _json_object(completed.stdout, label=f"{service} M4i state snapshot")


def _state_snapshots(prefix: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    return {
        "gateway": _artifact_snapshot(
            prefix,
            service="segmented-gateway",
            path=GATEWAY_FILE,
        ),
        "ot": _artifact_snapshot(prefix, service="ot-adapter", path=OT_FILE),
        "plant": _artifact_snapshot(prefix, service="simulation", path=PLANT_FILE),
    }


def _relay_name(project_name: str) -> str:
    return f"{project_name}-m4i-commit-relay"


def _atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise m4d.ExperimentError(f"refusing to overwrite private campaign control: {path}")
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
        material = _canonical_bytes(value)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise m4d.ExperimentError("M4i relay control file was not private")


def _arm_relay(directory: Path, action_sha256: str) -> None:
    if _SHA256.fullmatch(action_sha256) is None:
        raise m4d.ExperimentError("M4i relay action digest was malformed")
    _atomic_private_json(
        directory / "arm.json",
        {
            "schema_version": "m4i-scoped-relay-arm-v1",
            "expected_action_sha256": action_sha256,
        },
    )


def _relay_status(directory: Path) -> dict[str, Any]:
    path = directory / "relay.json"
    if not path.is_file() or path.is_symlink():
        raise m4d.ExperimentError("M4i relay status was unavailable")
    if path.stat().st_size > MAX_RETAINED_BYTES:
        raise m4d.ExperimentError("M4i relay status exceeded its size limit")
    return _json_object(path.read_text(encoding="utf-8"), label="M4i relay status")


def _await_relay_status(
    directory: Path,
    *,
    predicate: Callable[[dict[str, Any]], bool],
    timeout_seconds: float = DEFAULT_READY_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            last = _relay_status(directory)
        except (m4d.ExperimentError, OSError, UnicodeError):
            pass
        else:
            if predicate(last):
                return last
        time.sleep(DEFAULT_POLL_SECONDS)
    raise m4d.ExperimentError(f"M4i relay did not reach its expected state: {last}")


def _service_container(prefix: tuple[str, ...], service: str) -> str:
    container = m4d._run(*prefix, "ps", "-q", service).stdout.strip()
    if not container:
        raise m4d.ExperimentError(f"M4i service container was unavailable: {service}")
    return container


def _control_network(container: str, project_name: str) -> str:
    values = json.loads(m4d._run("docker", "inspect", container).stdout)
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise m4d.ExperimentError("M4i OT container inspection was malformed")
    settings = _mapping(values[0].get("NetworkSettings"))
    networks = _mapping(settings.get("Networks"))
    expected = f"{project_name}_control_dmz"
    if expected not in networks:
        raise m4d.ExperimentError("M4i OT control network was unavailable")
    return expected


def _start_relay(
    *,
    prefix: tuple[str, ...],
    project_name: str,
    image: str,
    directory: Path,
) -> dict[str, str]:
    entries = tuple(directory.iterdir())
    if (
        len(entries) != 1
        or entries[0].name != "arm.json"
        or entries[0].is_symlink()
        or stat.S_IMODE(entries[0].stat().st_mode) != 0o600
    ):
        raise m4d.ExperimentError("M4i relay directory was not exactly armed")
    directory.chmod(0o700)
    m4d._run(*prefix, "stop", "segmented-gateway")
    ot_container = _service_container(prefix, "ot-adapter")
    network = _control_network(ot_container, project_name)
    relay_name = _relay_name(project_name)
    override_path = directory / "compose.relay.json"
    _atomic_private_json(
        override_path,
        {
            "services": {
                "segmented-gateway": {
                    "environment": {
                        "AEGIS_OT_URL": f"http://{relay_name}:8083",
                    }
                }
            }
        },
    )
    try:
        m4d._run(
            "docker",
            "run",
            "--detach",
            "--rm",
            "--name",
            relay_name,
            "--network",
            network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            "64",
            "--memory",
            "128m",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--mount",
            f"type=bind,source={directory.resolve()},target=/evidence",
            "--env",
            "AEGIS_M4I_RELAY_TARGET_HOST=ot-adapter",
            "--env",
            "AEGIS_M4I_RELAY_TARGET_PORT=8083",
            image,
            "python",
            "-c",
            _COMMIT_RESPONSE_RELAY_CODE,
        )
        _await_relay_status(directory, predicate=lambda value: not value.get("violations"))
        m4d._run(
            *prefix,
            "-f",
            str(override_path),
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "segmented-gateway",
        )
        m4g._await_gateway()
        return {
            "relay_name": relay_name,
            "network": network,
            "override_path": str(override_path),
        }
    except Exception:
        m4d._run(
            "docker",
            "rm",
            "-f",
            _relay_name(project_name),
            check=False,
        )
        override_path.unlink(missing_ok=True)
        raise


def _stop_relay(
    *,
    prefix: tuple[str, ...],
    relay: dict[str, str],
) -> dict[str, bool]:
    m4d._run(*prefix, "stop", "segmented-gateway", check=False)
    relay_removed = (
        m4d._run("docker", "rm", "-f", relay["relay_name"], check=False).returncode
        == 0
    )
    override_path = Path(relay["override_path"])
    override_path.unlink(missing_ok=True)
    override_removed = not override_path.exists() and not override_path.is_symlink()
    m4d._run(
        *prefix,
        "up",
        "-d",
        "--force-recreate",
        "--no-deps",
        "segmented-gateway",
    )
    m4g._await_gateway()
    absent = (
        m4d._run(
            "docker",
            "container",
            "inspect",
            relay["relay_name"],
            check=False,
        ).returncode
        != 0
    )
    if not absent:
        raise m4d.ExperimentError("M4i relay remained present after teardown")
    if not relay_removed or not override_removed:
        raise m4d.ExperimentError("M4i relay teardown could not be established")
    return {
        "relay_container_removed_before_reconciliation": True,
        "gateway_direct_ot_route_restored_before_reconciliation": True,
    }


def _journal_records(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    entries = _mapping(snapshot.get("document")).get("entries")
    if not isinstance(entries, list) or not all(
        isinstance(item, dict) for item in entries
    ):
        raise m4d.ExperimentError("M4i coordination journal entries were malformed")
    return entries


def _record_for_action(
    snapshot: dict[str, Any],
    action_sha256: str,
) -> dict[str, Any]:
    if _SHA256.fullmatch(action_sha256) is None:
        raise m4d.ExperimentError("M4i action digest was malformed")
    matches = [
        item
        for item in _journal_records(snapshot)
        if _mapping(item.get("effect")).get("request_sha256") == action_sha256
    ]
    if len(matches) != 1:
        raise m4d.ExperimentError(
            "M4i coordination journal did not contain one exact action record"
        )
    return matches[0]


def _attempt_counts(record: dict[str, Any]) -> dict[str, int]:
    attempts = record.get("attempts")
    if not isinstance(attempts, list) or not all(
        isinstance(item, dict) for item in attempts
    ):
        raise m4d.ExperimentError("M4i coordination attempts were malformed")
    counts = {"prepare": 0, "commit": 0, "query": 0}
    for attempt in attempts:
        kind = attempt.get("kind")
        if kind not in counts:
            raise m4d.ExperimentError("M4i coordination attempt kind was unexpected")
        counts[kind] += 1
    return counts


def _commit_attempt_status(record: dict[str, Any]) -> str | None:
    attempts = record.get("attempts")
    if not isinstance(attempts, list):
        raise m4d.ExperimentError("M4i coordination attempts were malformed")
    matches = [
        item.get("status")
        for item in attempts
        if isinstance(item, dict) and item.get("kind") == "commit"
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        return None
    return matches[0]


def _record_state(record: dict[str, Any]) -> str | None:
    transitions = record.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        return None
    final = transitions[-1]
    return final.get("state") if isinstance(final, dict) else None


def _terminal_outcome(record: dict[str, Any]) -> dict[str, Any]:
    attempts = record.get("attempts")
    if not isinstance(attempts, list):
        raise m4d.ExperimentError("M4i coordination attempts were malformed")
    matches = [
        outcome
        for item in attempts
        if isinstance(item, dict)
        and item.get("kind") in {"commit", "query"}
        and isinstance((outcome := item.get("outcome")), dict)
        and outcome.get("disposition") in {"applied", "rejected"}
    ]
    if not matches:
        raise m4d.ExperimentError("M4i terminal coordination outcome was unavailable")
    final = matches[-1]
    return final


def _terminal_projection(record: dict[str, Any]) -> dict[str, str]:
    outcome = _terminal_outcome(record)
    material = _canonical_bytes(outcome)
    return {
        "bytes_base64": base64.b64encode(material).decode("ascii"),
        "sha256": _sha256(material),
        "disposition": str(outcome.get("disposition")),
    }


def _private_state_artifact(snapshot: dict[str, Any]) -> bool:
    directory = _mapping(snapshot.get("directory"))
    artifact = _mapping(snapshot.get("artifact"))
    writer_lock = _mapping(snapshot.get("writer_lock"))
    return (
        directory.get("mode") == "0700"
        and directory.get("symlink") is False
        and artifact.get("mode") == "0600"
        and artifact.get("regular") is True
        and artifact.get("symlink") is False
        and writer_lock.get("mode") == "0600"
        and writer_lock.get("regular") is True
        and writer_lock.get("symlink") is False
    )


def _result_reason(exchange: dict[str, Any]) -> str | None:
    response = _mapping(exchange.get("response"))
    direct = response.get("reason")
    if isinstance(direct, str):
        return direct
    reasons = response.get("reasons")
    if isinstance(reasons, list) and reasons and isinstance(reasons[0], str):
        return reasons[0]
    return None


def _accepted_gates(
    observations: dict[str, Any],
    configuration: dict[str, Any],
    cleanup: dict[str, bool],
) -> dict[str, bool]:
    health = _mapping(observations.get("health_initial"))
    gateway_health = _mapping(health.get("segmented-gateway"))
    ot_health = _mapping(health.get("ot-adapter"))
    initial_ot_recovery = _mapping(ot_health.get("coordination_recovery"))
    initialization = _mapping(observations.get("coordination_initialization"))
    nominal = _mapping(observations.get("nominal"))
    nominal_result = _mapping(nominal.get("result"))
    nominal_gateway = _mapping(nominal.get("gateway_record"))
    nominal_ot = _mapping(nominal.get("ot_record"))
    lost = _mapping(observations.get("lost_response"))
    lost_result = _mapping(lost.get("result"))
    relay = _mapping(lost.get("relay"))
    relay_counters = _mapping(relay.get("path_counters"))
    gateway_unknown = _mapping(lost.get("gateway_before_reconciliation"))
    ot_before = _mapping(lost.get("ot_before_reconciliation"))
    gateway_resolved = _mapping(lost.get("gateway_after_reconciliation"))
    ot_resolved = _mapping(lost.get("ot_after_reconciliation"))
    reconciliation = _mapping(lost.get("reconciliation"))
    reconciliation_response = _mapping(reconciliation.get("response"))
    fresh = _mapping(lost.get("fresh_action"))
    relay_cleanup = _mapping(lost.get("relay_teardown"))
    restart = _mapping(observations.get("gateway_ot_restart"))
    restart_ot_health = _mapping(restart.get("ot_health_after"))
    restart_ot_recovery = _mapping(
        restart_ot_health.get("coordination_recovery")
    )
    plant_restart = _mapping(observations.get("plant_restart"))
    plant_stack_health = _mapping(plant_restart.get("stack_health_after"))
    plant_restart_ot_health = _mapping(plant_stack_health.get("ot-adapter"))
    plant_restart_ot_recovery = _mapping(
        plant_restart_ot_health.get("coordination_recovery")
    )
    storage = _mapping(observations.get("storage"))
    storage_snapshots = _mapping(storage.get("snapshots"))
    corruption = _mapping(observations.get("corruption"))

    try:
        nominal_gateway_counts = _attempt_counts(nominal_gateway)
        nominal_ot_counts = _attempt_counts(nominal_ot)
        unknown_gateway_counts = _attempt_counts(gateway_unknown)
        unknown_ot_counts = _attempt_counts(ot_before)
        resolved_gateway_counts = _attempt_counts(gateway_resolved)
        resolved_ot_counts = _attempt_counts(ot_resolved)
    except m4d.ExperimentError:
        nominal_gateway_counts = {}
        nominal_ot_counts = {}
        unknown_gateway_counts = {}
        unknown_ot_counts = {}
        resolved_gateway_counts = {}
        resolved_ot_counts = {}

    required_health = (
        set(health) == set(m4g.AEGIS_HEALTH_PORTS)
        and all(_mapping(value).get("status") == "ready" for value in health.values())
        and gateway_health.get("effect_coordination_mode") == "required"
        and gateway_health.get("coordination_backend")
        == "durable-prepare-commit-query-http-v1"
        and initial_ot_recovery.get("schema_version")
        == "m4i-ot-coordination-recovery-v1"
        and initial_ot_recovery.get("status") == "aligned"
        and initial_ot_recovery.get("reason") == "aligned_empty_baseline"
        and initial_ot_recovery.get("record_count") == 0
        and initial_ot_recovery.get("applied_effect_count") == 0
        and initial_ot_recovery.get("pending_effect_count") == 0
        and initial_ot_recovery.get("plant_state_version") == 0
        and initial_ot_recovery.get("live_commit_armed") is False
        and initial_ot_recovery.get("limitation")
        == "ordinary_single_volume_alignment_only"
        and initialization.get("schema_version")
        == "m4i-coordination-volume-initialization-v2"
        and initialization.get("state_artifact_count") == 3
    )
    nominal_accepted = (
        nominal_result.get("status") == "completed"
        and nominal_result.get("dispatch_attempts") == 1
        and _record_state(nominal_gateway) == "applied"
        and _record_state(nominal_ot) == "applied"
        and nominal_gateway_counts == {"prepare": 1, "commit": 1, "query": 0}
        and nominal_ot_counts == nominal_gateway_counts
    )
    loss_unknown = (
        lost_result.get("http_status") == 200
        and _mapping(lost_result.get("response")).get("status") == "unknown_effect"
        and _mapping(lost_result.get("response")).get("dispatch_attempts") == 1
        and _record_state(gateway_unknown) == "dispatch_armed"
        and _commit_attempt_status(gateway_unknown) == "outcome_unknown"
        and _record_state(ot_before) == "applied"
        and unknown_gateway_counts == {"prepare": 1, "commit": 1, "query": 0}
        and unknown_ot_counts == {"prepare": 1, "commit": 1, "query": 0}
        and relay.get("armed_action_sha256") == lost.get("action_sha256")
        and relay.get("commit_response_discarded") is True
        and isinstance(relay.get("commit_request_sha256"), str)
        and isinstance(relay.get("commit_response_sha256"), str)
        and relay_counters.get("prepare") == 1
        and relay_counters.get("commit") == 1
        and relay_counters.get("query") == 0
        and relay_counters.get("other") == 0
        and relay.get("violations") == []
    )
    reconciliation_accepted = (
        reconciliation.get("http_status") == 200
        and reconciliation.get("credential_role") == "agent"
        and reconciliation.get("request_nonce") != reconciliation.get("proposal_nonce")
        and reconciliation_response.get("schema_version")
        == "m4i-capability-outcome-resolution-v1"
        and reconciliation_response.get("disposition") in {"applied", "rejected"}
        and resolved_gateway_counts == {"prepare": 1, "commit": 1, "query": 1}
        and resolved_ot_counts == resolved_gateway_counts
        and relay_counters.get("commit") == 1
        and relay_cleanup.get("relay_container_removed_before_reconciliation") is True
        and relay_cleanup.get("gateway_direct_ot_route_restored_before_reconciliation")
        is True
    )
    restart_accepted = (
        _mapping(restart.get("gateway_container_before")).get("container_id")
        != _mapping(restart.get("gateway_container_after")).get("container_id")
        and _mapping(restart.get("ot_container_before")).get("container_id")
        != _mapping(restart.get("ot_container_after")).get("container_id")
        and restart.get("gateway_terminal_before")
        == restart.get("gateway_terminal_after")
        and restart.get("ot_terminal_before") == restart.get("ot_terminal_after")
        and _mapping(restart.get("health_after")).get("status") == "ready"
        and restart_ot_health.get("status") == "ready"
        and restart_ot_recovery.get("status") == "aligned"
        and restart_ot_recovery.get("reason") == "aligned_applied_chain"
        and restart_ot_recovery.get("record_count") == 2
        and restart_ot_recovery.get("applied_effect_count") == 2
        and restart_ot_recovery.get("pending_effect_count") == 0
        and restart_ot_recovery.get("live_commit_armed") is False
    )
    plant_before = _mapping(plant_restart.get("health_before"))
    plant_after = _mapping(plant_restart.get("health_after"))
    checkpoint_before = _mapping(plant_restart.get("checkpoint_before"))
    checkpoint_after = _mapping(plant_restart.get("checkpoint_after"))
    plant_accepted = (
        plant_before.get("boot_epoch") != plant_after.get("boot_epoch")
        and plant_before.get("model_digest") == plant_after.get("model_digest")
        and plant_before.get("state_version") == plant_after.get("state_version")
        and plant_before.get("state_digest") == plant_after.get("state_digest")
        and checkpoint_before.get("bytes_base64")
        == checkpoint_after.get("bytes_base64")
        and checkpoint_before.get("sha256") == checkpoint_after.get("sha256")
        and _mapping(
            _mapping(checkpoint_after.get("document")).get("checkpoint")
        ).get("state_digest")
        == plant_after.get("state_digest")
        and plant_restart_ot_health.get("status") == "ready"
        and plant_restart_ot_recovery.get("status") == "aligned"
        and plant_restart_ot_recovery.get("reason") == "aligned_applied_chain"
        and plant_restart_ot_recovery.get("plant_state_version")
        == plant_after.get("state_version")
        and plant_restart_ot_recovery.get("plant_state_digest")
        == plant_after.get("state_digest")
        and plant_restart_ot_recovery.get("live_commit_armed") is False
    )
    fresh_blocked = (
        fresh.get("http_status") == 409
        and _result_reason(fresh) == "effect_reconciliation_required"
        and lost.get("ot_prepare_count_before_fresh")
        == lost.get("ot_prepare_count_after_fresh")
        and lost.get("gateway_record_count_before_fresh")
        == lost.get("gateway_record_count_after_fresh")
    )
    volumes = _mapping(configuration.get("state_volumes"))
    paths = _mapping(configuration.get("state_paths"))
    isolated_private = (
        len(set(volumes.values())) == 3
        and len(set(paths.values())) == 3
        and initialization.get("directory_mode") == "0700"
        and initialization.get("artifact_mode") == "0600"
        and initialization.get("secrets_consumed") == 0
        and set(storage_snapshots) == {"gateway", "ot", "plant"}
        and all(
            _private_state_artifact(_mapping(value))
            for value in storage_snapshots.values()
        )
    )
    corruption_closed = set(corruption) == {"gateway", "ot", "plant"} and all(
        _mapping(value).get("startup_ready") is False
        and _mapping(value).get("restored") is True
        and _mapping(value).get("restored_sha256")
        == _mapping(value).get("original_sha256")
        for value in corruption.values()
    )
    return {
        "required_coordination_health": required_health,
        "nominal_effect_one_prepare_one_commit": nominal_accepted,
        "lost_commit_response_remains_unknown": loss_unknown,
        "agent_reconciliation_one_query_zero_commit_retries": (
            reconciliation_accepted
        ),
        "gateway_ot_restart_preserves_byte_equivalent_resolution": (
            restart_accepted
        ),
        "plant_checkpoint_restores_exact_state": plant_accepted,
        "unresolved_effect_blocks_fresh_action_and_second_prepare": fresh_blocked,
        "isolated_private_gateway_ot_plant_state": isolated_private,
        "state_corruption_fails_closed": corruption_closed,
        "cleanup_and_private_material_deletion": (
            bool(cleanup)
            and set(cleanup)
            >= {
                "compose_project_removed",
                "relay_container_removed",
                "private_key_directory_removed",
                "relay_evidence_directory_removed",
            }
            and all(cleanup.values())
        ),
    }


def _failed_acceptance_names(acceptance: dict[str, bool]) -> tuple[str, ...]:
    if set(acceptance) != set(ACCEPTANCE_GATE_NAMES):
        raise m4d.ExperimentError("M4i acceptance gate set was not closed")
    return tuple(
        name for name in ACCEPTANCE_GATE_NAMES if acceptance.get(name) is not True
    )


def _run_nominal_action(prefix: tuple[str, ...]) -> dict[str, Any]:
    prepared = _run_agent_exchange(prefix, mode="prepare_action")
    prepared_digest = prepared.get("action_sha256")
    wire_request = prepared.get("wire_request")
    if not isinstance(prepared_digest, str) or not isinstance(wire_request, dict):
        raise m4d.ExperimentError("nominal M4i prepared action was malformed")
    submitted = _run_agent_exchange(
        prefix,
        mode="submit_action",
        material={"wire_request": wire_request},
    )
    if (
        submitted.get("http_status") != 200
        or submitted.get("action_sha256") != prepared_digest
    ):
        raise m4d.ExperimentError("nominal M4i action exchange was not exact")
    result = _mapping(submitted.get("response"))
    if _action_sha256(result) != prepared_digest:
        raise m4d.ExperimentError("nominal M4i result did not bind its prepared action")
    return result


def _container_identity(
    prefix: tuple[str, ...],
    service: str,
) -> dict[str, Any]:
    return m4g._container_identity(prefix, service)


_HEALTH_EXCHANGE_CODE = r"""
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

url = sys.argv[1]
try:
    with urlopen(url, timeout=2) as response:
        status = response.status
        material = response.read(1048577)
except HTTPError as exc:
    status = exc.code
    material = exc.read(1048577)
except (TimeoutError, URLError, OSError) as exc:
    print(json.dumps({
        'reachable': False,
        'error_type': type(exc).__name__,
    }, sort_keys=True, separators=(',', ':')))
    raise SystemExit(0)
if len(material) > 1048576:
    raise RuntimeError('M4i health response exceeded evidence limit')
try:
    document = json.loads(material)
except Exception:
    document = None
print(json.dumps({
    'reachable': True,
    'http_status': status,
    'document': document,
}, sort_keys=True, separators=(',', ':')))
""".strip()


def _service_health_exchange(
    prefix: tuple[str, ...],
    *,
    service: str,
    port: int,
) -> dict[str, Any]:
    completed = m4d._run(
        *prefix,
        "exec",
        "-T",
        service,
        "python",
        "-c",
        _HEALTH_EXCHANGE_CODE,
        f"http://127.0.0.1:{port}/health",
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return {
            "reachable": False,
            "exec_exit_code": completed.returncode,
            "stderr_tail": completed.stderr[-4000:],
        }
    try:
        return _json_object(completed.stdout, label=f"{service} health exchange")
    except m4d.ExperimentError:
        return {
            "reachable": False,
            "exec_exit_code": completed.returncode,
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
        }


def _await_service_ready(
    prefix: tuple[str, ...],
    *,
    service: str,
    port: int,
    timeout_seconds: float = DEFAULT_READY_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = _service_health_exchange(prefix, service=service, port=port)
        document = _mapping(last.get("document"))
        if last.get("http_status") == 200 and document.get("status") == "ready":
            return document
        time.sleep(DEFAULT_POLL_SECONDS)
    raise m4d.ExperimentError(
        f"M4i service did not become ready: {service}: {last}"
    )


def _await_service_not_ready(
    prefix: tuple[str, ...],
    *,
    service: str,
    port: int,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = _service_health_exchange(prefix, service=service, port=port)
        document = _mapping(last.get("document"))
        if last.get("http_status") == 200 and document.get("status") == "ready":
            return {"startup_ready": True, "health_exchange": last}
        if last.get("reachable") is True and last.get("http_status") != 200:
            return {"startup_ready": False, "health_exchange": last}
        time.sleep(DEFAULT_POLL_SECONDS)
    return {"startup_ready": False, "health_exchange": last}


def _restart_service(
    prefix: tuple[str, ...],
    *,
    service: str,
    port: int,
) -> dict[str, Any]:
    m4d._run(*prefix, "stop", service)
    m4d._run(
        *prefix,
        "up",
        "-d",
        "--force-recreate",
        "--no-deps",
        "--no-build",
        service,
    )
    return _await_service_ready(prefix, service=service, port=port)


def _restart_gateway_and_ot(prefix: tuple[str, ...]) -> dict[str, Any]:
    before = {
        "gateway": _container_identity(prefix, "segmented-gateway"),
        "ot": _container_identity(prefix, "ot-adapter"),
    }
    m4d._run(*prefix, "stop", "segmented-gateway", "ot-adapter")
    m4d._run(
        *prefix,
        "up",
        "-d",
        "--force-recreate",
        "--no-deps",
        "--no-build",
        "ot-adapter",
    )
    ot_health = _await_service_ready(prefix, service="ot-adapter", port=8083)
    m4d._run(
        *prefix,
        "up",
        "-d",
        "--force-recreate",
        "--no-deps",
        "--no-build",
        "segmented-gateway",
    )
    gateway_health = _await_service_ready(
        prefix,
        service="segmented-gateway",
        port=8081,
    )
    return {
        "gateway_container_before": before["gateway"],
        "ot_container_before": before["ot"],
        "gateway_container_after": _container_identity(prefix, "segmented-gateway"),
        "ot_container_after": _container_identity(prefix, "ot-adapter"),
        "health_after": gateway_health,
        "ot_health_after": ot_health,
    }


def _restart_plant_stack(prefix: tuple[str, ...]) -> dict[str, Any]:
    m4d._run(
        *prefix,
        "stop",
        "segmented-gateway",
        "ot-adapter",
        "observer",
        "candidate",
        "simulation",
    )
    for service, port in (
        ("simulation", 8084),
        ("observer", 8082),
        ("candidate", 8085),
        ("ot-adapter", 8083),
        ("segmented-gateway", 8081),
    ):
        m4d._run(
            *prefix,
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "--no-build",
            service,
        )
        _await_service_ready(prefix, service=service, port=port)
    return m4g._health_snapshot(prefix)


def _mutate_artifact(
    *,
    image: str,
    volume: str,
    relative_path: str,
    uid: str,
    gid: str,
    operation: str,
    material_base64: str = "",
) -> dict[str, Any]:
    if operation not in {"corrupt", "restore"}:
        raise m4d.ExperimentError("M4i artifact mutation operation was invalid")
    if not uid.isdigit() or not gid.isdigit():
        raise m4d.ExperimentError("M4i artifact runtime identity was malformed")
    if Path(relative_path).name != relative_path:
        raise m4d.ExperimentError("M4i artifact relative path was not bounded")
    completed = _run_input(
        (
            "docker",
            "run",
            "--rm",
            "--interactive",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--user",
            f"{uid}:{gid}",
            "--mount",
            f"type=volume,source={volume},target=/state",
            image,
            "python",
            "-c",
            _ARTIFACT_MUTATOR_CODE,
            f"/state/{relative_path}",
            operation,
        ),
        material_base64,
    )
    result = _json_object(
        completed.stdout,
        label=f"M4i artifact {operation} result",
    )
    if (
        result.get("operation") != operation
        or not isinstance(result.get("size_bytes"), int)
        or result["size_bytes"] < 0
        or not isinstance(result.get("sha256"), str)
        or _SHA256.fullmatch(result["sha256"]) is None
    ):
        raise m4d.ExperimentError("M4i artifact mutation result was malformed")
    return result


def _artifact_fault_case(
    prefix: tuple[str, ...],
    *,
    service: str,
    port: int,
    image: str,
    volume: str,
    relative_path: str,
    uid: str,
    gid: str,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    original_sha256 = snapshot.get("sha256")
    original_material = snapshot.get("bytes_base64")
    if not isinstance(original_sha256, str) or not isinstance(original_material, str):
        raise m4d.ExperimentError("M4i fault snapshot was malformed")
    m4d._run(*prefix, "stop", service)
    restored = False
    try:
        corrupted = _mutate_artifact(
            image=image,
            volume=volume,
            relative_path=relative_path,
            uid=uid,
            gid=gid,
            operation="corrupt",
        )
        if corrupted["sha256"] == original_sha256:
            raise m4d.ExperimentError("M4i corruption did not change the state artifact")
        m4d._run(
            *prefix,
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "--no-build",
            service,
        )
        failed = _await_service_not_ready(prefix, service=service, port=port)
    finally:
        m4d._run(*prefix, "stop", service, check=False)
        restoration = _mutate_artifact(
            image=image,
            volume=volume,
            relative_path=relative_path,
            uid=uid,
            gid=gid,
            operation="restore",
            material_base64=original_material,
        )
        restored = restoration["sha256"] == original_sha256
        if not restored:
            raise m4d.ExperimentError(
                "M4i state artifact restoration did not reproduce the original digest"
            )
    return {
        **failed,
        "original_sha256": original_sha256,
        "restored": restored,
    }


def _action_sha256(result: dict[str, Any]) -> str:
    request = result.get("request")
    if not isinstance(request, dict):
        raise m4d.ExperimentError("M4i result omitted its exact action request")
    digest = _sha256(_canonical_bytes(request))
    if _SHA256.fullmatch(digest) is None:  # pragma: no cover - hashlib invariant
        raise m4d.ExperimentError("M4i result action digest was malformed")
    return digest


def _runtime_identity(
    configuration: dict[str, Any],
    role: str,
) -> tuple[str, str]:
    identity = _mapping(_mapping(configuration.get("state_runtime_ids")).get(role))
    uid = identity.get("uid")
    gid = identity.get("gid")
    if not isinstance(uid, str) or not isinstance(gid, str):
        raise m4d.ExperimentError(f"M4i runtime identity was missing: {role}")
    return uid, gid


def _restore_service_after_fault(
    prefix: tuple[str, ...],
    *,
    service: str,
    port: int,
) -> dict[str, Any]:
    return _restart_service(prefix, service=service, port=port)


def _campaign(project_name: str, commit: str) -> dict[str, Any]:
    _validate_project_name(project_name)
    _assert_project_absent(project_name)
    _assert_checkout(commit)
    source_binding = _source_binding(commit)
    key_directory = Path(tempfile.mkdtemp(prefix="aegis-ot-m4i-keys-"))
    relay_directory = Path(tempfile.mkdtemp(prefix="aegis-ot-m4i-relay-"))
    key_directory.chmod(0o700)
    relay_directory.chmod(0o700)
    prefix = _compose_prefix(project_name)
    project_created = False
    relay_active: dict[str, str] | None = None
    cleanup: dict[str, bool] = {}
    environment: dict[str, str] = {}
    observations: dict[str, Any] | None = None
    configuration: dict[str, Any] | None = None
    image_provenance: dict[str, dict[str, Any]] | None = None
    try:
        key_paths, workload_key_ids = m4g._provision_key_material(key_directory)
        environment = m4g._campaign_environment(
            key_paths,
            workload_key_ids,
            commit,
        )
        with m4g._installed_environment(environment):
            compose = _json_object(
                m4d._run(
                    *prefix,
                    "--profile",
                    "experiment",
                    "config",
                    "--format",
                    "json",
                ).stdout,
                label="six-overlay M4i Compose config",
            )
            configuration = _configuration_binding(
                compose,
                key_directory=key_directory,
                project_name=project_name,
            )
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "build",
                "--build-arg",
                f"AEGIS_SOURCE_REVISION={commit}",
                *CAMPAIGN_BUILD_SERVICES,
            )
            image_provenance = m4g._image_provenance(
                compose,
                commit,
                CAMPAIGN_BUILD_SERVICES,
            )
            project_created = True
            m4d._run(
                *prefix,
                "up",
                "-d",
                "--force-recreate",
                *OPERATIONAL_SERVICES,
            )
            m4g._await_gateway()
            health_initial = m4g._health_snapshot(prefix)
            initialization = m4g._last_json_log(prefix, "coordination-init")
            storage_initial = _state_snapshots(prefix)

            nominal_result = _run_nominal_action(prefix)
            nominal_action_sha256 = _action_sha256(nominal_result)
            nominal_snapshots = _state_snapshots(prefix)
            nominal = {
                "result": nominal_result,
                "action_sha256": nominal_action_sha256,
                "gateway_record": _record_for_action(
                    nominal_snapshots["gateway"],
                    nominal_action_sha256,
                ),
                "ot_record": _record_for_action(
                    nominal_snapshots["ot"],
                    nominal_action_sha256,
                ),
            }

            prepared = _run_agent_exchange(prefix, mode="prepare_action")
            lost_action_sha256 = prepared.get("action_sha256")
            if not isinstance(lost_action_sha256, str):
                raise m4d.ExperimentError("M4i prepared action digest was unavailable")
            _arm_relay(relay_directory, lost_action_sha256)
            relay_active = _start_relay(
                prefix=prefix,
                project_name=project_name,
                image=image_provenance["segmented-gateway"]["image"],
                directory=relay_directory,
            )
            try:
                lost_result = _run_agent_exchange(
                    prefix,
                    mode="submit_action",
                    material={"wire_request": prepared["wire_request"]},
                )
                relay_status = _await_relay_status(
                    relay_directory,
                    predicate=lambda value: (
                        value.get("commit_response_discarded") is True
                    ),
                )
                unknown_snapshots = _state_snapshots(prefix)
                gateway_unknown = _record_for_action(
                    unknown_snapshots["gateway"],
                    lost_action_sha256,
                )
                ot_unknown = _record_for_action(
                    unknown_snapshots["ot"],
                    lost_action_sha256,
                )
                ot_prepare_before = _attempt_counts(ot_unknown)["prepare"]
                gateway_records_before = len(
                    _journal_records(unknown_snapshots["gateway"])
                )
                fresh_prepared = _run_agent_exchange(prefix, mode="prepare_action")
                fresh_result = _run_agent_exchange(
                    prefix,
                    mode="submit_action",
                    material={"wire_request": fresh_prepared["wire_request"]},
                )
                blocked_snapshots = _state_snapshots(prefix)
                ot_prepare_after = _attempt_counts(
                    _record_for_action(
                        blocked_snapshots["ot"],
                        lost_action_sha256,
                    )
                )["prepare"]
                gateway_records_after = len(
                    _journal_records(blocked_snapshots["gateway"])
                )
            finally:
                relay_teardown = _stop_relay(prefix=prefix, relay=relay_active)
                relay_active = None

            reconciliation = _run_agent_exchange(
                prefix,
                mode="reconcile",
                material={"action": prepared["action"]},
            )
            resolved_snapshots = _state_snapshots(prefix)
            gateway_resolved = _record_for_action(
                resolved_snapshots["gateway"],
                lost_action_sha256,
            )
            ot_resolved = _record_for_action(
                resolved_snapshots["ot"],
                lost_action_sha256,
            )
            lost_response = {
                "action_sha256": lost_action_sha256,
                "prepared_action": prepared,
                "result": lost_result,
                "relay": relay_status,
                "relay_teardown": relay_teardown,
                "gateway_before_reconciliation": gateway_unknown,
                "ot_before_reconciliation": ot_unknown,
                "fresh_action": fresh_result,
                "fresh_action_sha256": fresh_prepared.get("action_sha256"),
                "ot_prepare_count_before_fresh": ot_prepare_before,
                "ot_prepare_count_after_fresh": ot_prepare_after,
                "gateway_record_count_before_fresh": gateway_records_before,
                "gateway_record_count_after_fresh": gateway_records_after,
                "reconciliation": reconciliation,
                "gateway_after_reconciliation": gateway_resolved,
                "ot_after_reconciliation": ot_resolved,
            }

            gateway_terminal = _terminal_projection(gateway_resolved)
            ot_terminal = _terminal_projection(ot_resolved)
            gateway_ot_restart = _restart_gateway_and_ot(prefix)
            restarted_snapshots = _state_snapshots(prefix)
            gateway_ot_restart.update(
                {
                    "gateway_terminal_before": gateway_terminal,
                    "gateway_terminal_after": _terminal_projection(
                        _record_for_action(
                            restarted_snapshots["gateway"],
                            lost_action_sha256,
                        )
                    ),
                    "ot_terminal_before": ot_terminal,
                    "ot_terminal_after": _terminal_projection(
                        _record_for_action(
                            restarted_snapshots["ot"],
                            lost_action_sha256,
                        )
                    ),
                    "gateway_journal_bytes_preserved": (
                        resolved_snapshots["gateway"]["bytes_base64"]
                        == restarted_snapshots["gateway"]["bytes_base64"]
                    ),
                    "ot_journal_bytes_preserved": (
                        resolved_snapshots["ot"]["bytes_base64"]
                        == restarted_snapshots["ot"]["bytes_base64"]
                    ),
                }
            )

            plant_health_before = m4g._service_health(prefix, "simulation", 8084)
            checkpoint_before = restarted_snapshots["plant"]
            health_after_plant_restart = _restart_plant_stack(prefix)
            plant_health_after = _mapping(
                health_after_plant_restart.get("simulation")
            )
            checkpoint_after = _artifact_snapshot(
                prefix,
                service="simulation",
                path=PLANT_FILE,
            )
            plant_restart = {
                "health_before": plant_health_before,
                "health_after": plant_health_after,
                "checkpoint_before": checkpoint_before,
                "checkpoint_after": checkpoint_after,
                "stack_health_after": health_after_plant_restart,
            }

            fault_baseline = _state_snapshots(prefix)
            gateway_uid, gateway_gid = _runtime_identity(configuration, "gateway")
            ot_uid, ot_gid = _runtime_identity(configuration, "ot")
            plant_uid, plant_gid = _runtime_identity(configuration, "plant")
            corruption: dict[str, dict[str, Any]] = {}
            corruption["gateway"] = _artifact_fault_case(
                prefix,
                service="segmented-gateway",
                port=8081,
                image=image_provenance["segmented-gateway"]["image"],
                volume=f"{project_name}_gateway_coordination",
                relative_path="gateway-coordination.json",
                uid=gateway_uid,
                gid=gateway_gid,
                snapshot=fault_baseline["gateway"],
            )
            _restore_service_after_fault(
                prefix,
                service="segmented-gateway",
                port=8081,
            )
            gateway_restored = _artifact_snapshot(
                prefix,
                service="segmented-gateway",
                path=GATEWAY_FILE,
            )
            corruption["gateway"]["restored_sha256"] = gateway_restored["sha256"]

            m4d._run(*prefix, "stop", "segmented-gateway")
            corruption["ot"] = _artifact_fault_case(
                prefix,
                service="ot-adapter",
                port=8083,
                image=image_provenance["ot-adapter"]["image"],
                volume=f"{project_name}_ot_coordination",
                relative_path="ot-coordination.json",
                uid=ot_uid,
                gid=ot_gid,
                snapshot=fault_baseline["ot"],
            )
            _restore_service_after_fault(
                prefix,
                service="ot-adapter",
                port=8083,
            )
            ot_restored = _artifact_snapshot(
                prefix,
                service="ot-adapter",
                path=OT_FILE,
            )
            corruption["ot"]["restored_sha256"] = ot_restored["sha256"]
            _restore_service_after_fault(
                prefix,
                service="segmented-gateway",
                port=8081,
            )

            m4d._run(
                *prefix,
                "stop",
                "segmented-gateway",
                "ot-adapter",
                "observer",
                "candidate",
            )
            corruption["plant"] = _artifact_fault_case(
                prefix,
                service="simulation",
                port=8084,
                image=image_provenance["simulation"]["image"],
                volume=f"{project_name}_plant_checkpoint",
                relative_path="plant-checkpoint.json",
                uid=plant_uid,
                gid=plant_gid,
                snapshot=fault_baseline["plant"],
            )
            final_health = _restart_plant_stack(prefix)
            plant_restored = _artifact_snapshot(
                prefix,
                service="simulation",
                path=PLANT_FILE,
            )
            corruption["plant"]["restored_sha256"] = plant_restored["sha256"]
            storage_final = _state_snapshots(prefix)
            observations = {
                "health_initial": health_initial,
                "health_final": final_health,
                "coordination_initialization": initialization,
                "nominal": nominal,
                "lost_response": lost_response,
                "gateway_ot_restart": gateway_ot_restart,
                "plant_restart": plant_restart,
                "storage": {
                    "initial_snapshots": storage_initial,
                    "snapshots": storage_final,
                },
                "corruption": corruption,
            }
            _assert_checkout(commit)
    finally:
        emergency_relay_teardown_succeeded = True
        if relay_active is not None:
            try:
                with m4g._installed_environment(environment):
                    _stop_relay(prefix=prefix, relay=relay_active)
            except Exception:
                emergency_relay_teardown_succeeded = False
        cleanup["emergency_relay_teardown_succeeded"] = (
            emergency_relay_teardown_succeeded
        )
        cleanup["relay_container_removed"] = (
            m4d._run(
                "docker",
                "container",
                "inspect",
                _relay_name(project_name),
                check=False,
            ).returncode
            != 0
        )
        if project_created:
            with m4g._installed_environment(environment):
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
        shutil.rmtree(relay_directory, ignore_errors=True)
        cleanup["private_key_directory_removed"] = not key_directory.exists()
        cleanup["relay_evidence_directory_removed"] = not relay_directory.exists()

    if observations is None or configuration is None or image_provenance is None:
        raise m4d.ExperimentError("M4i campaign ended without complete observations")
    acceptance = _accepted_gates(observations, configuration, cleanup)
    failed = _failed_acceptance_names(acceptance)
    semantic_projection = {
        "git_commit": commit,
        "source_binding_sha256": source_binding["source_binding_sha256"],
        "normalized_compose_sha256": configuration["normalized_compose_sha256"],
        "nominal_action_sha256": _mapping(observations["nominal"]).get(
            "action_sha256"
        ),
        "lost_action_sha256": _mapping(observations["lost_response"]).get(
            "action_sha256"
        ),
        "relay_path_counters": _mapping(
            _mapping(observations["lost_response"]).get("relay")
        ).get("path_counters"),
        "reconciliation_disposition": _mapping(
            _mapping(
                _mapping(observations["lost_response"]).get("reconciliation")
            ).get("response")
        ).get("disposition"),
        "plant_state": {
            key: _mapping(
                _mapping(observations["plant_restart"]).get("health_after")
            ).get(key)
            for key in ("model_digest", "state_version", "state_digest")
        },
        "acceptance": acceptance,
    }
    evidence = {
        "schema_version": "m4i-live-coordination-experiment-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "analyst": "Angelis Pseftis",
        "git_commit": commit,
        "clean_checkout_start": True,
        "project_name": project_name,
        "source_binding": source_binding,
        "configuration_binding": configuration,
        "campaign_environment": m4g._redacted_environment(
            environment,
            key_directory,
        ),
        "image_provenance": image_provenance,
        "private_key_material_retained": False,
        "observations": observations,
        "cleanup": cleanup,
        "acceptance": acceptance,
        "accepted": not failed,
        "semantic_projection": semantic_projection,
        "semantic_outcome_sha256": _sha256(_canonical_bytes(semantic_projection)),
        "evidence_boundaries": list(EVIDENCE_BOUNDARIES),
    }
    if failed:
        raise m4d.ExperimentError(
            "M4i live coordination acceptance criteria failed: " + ", ".join(failed)
        )
    return evidence


def run_experiment(output: Path, project_name: str) -> dict[str, Any]:
    _validate_project_name(project_name)
    m4g._assert_source_checkout()
    if output.exists() or output.is_symlink():
        raise m4d.ExperimentError("refusing to overwrite retained M4i evidence")
    if m4d._run("git", "status", "--porcelain").stdout:
        raise m4d.ExperimentError("M4i retained evidence requires a clean checkout")
    commit = m4d._run("git", "rev-parse", "HEAD").stdout.strip()
    if _GIT_OBJECT.fullmatch(commit) is None:
        raise m4d.ExperimentError("M4i git commit binding was malformed")
    _assert_checkout(commit)
    evidence = _campaign(project_name, commit)
    _assert_checkout(commit)
    evidence["clean_checkout_end"] = True
    try:
        m4d._atomic_write_json(output, evidence)
        if stat.S_IMODE(output.stat().st_mode) != 0o600:
            raise m4d.ExperimentError("retained M4i evidence file was not private")
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project", default="aegis-ot-m4i-primary")
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
