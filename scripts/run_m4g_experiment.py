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
import hashlib
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
    "workload_trust_sequence_agent",
    "workload_trust_sequence_gateway",
    "workload_trust_sequence_ot",
    "transport_replay",
    "transport_probe",
)
SOURCE_BINDING_FILES = (
    *COMPOSE_FILES,
    "Dockerfile",
    "pyproject.toml",
    "requirements.lock",
    "scripts/run_m4d_experiment.py",
    "scripts/run_m4g_experiment.py",
    "src/aegis_ot/m4g_identity_admin.py",
    "src/aegis_ot/m4g_identity_init.py",
    "src/aegis_ot/m4g_probe.py",
    "src/aegis_ot/segmented_capability_models.py",
    "src/aegis_ot/segmented_capability_runtime.py",
    "src/aegis_ot/workload_identity.py",
    "src/aegis_ot/workload_runtime.py",
    "src/aegis_ot/workload_trust_state.py",
)
TRUST_DOMAIN = "aegis-ot.m4g.local"
AGENT_ACTOR_ID = "agent:operator-1"
AGENT_SUBJECT = "urn:aegis-ot:m4g:workload:agent-probe"
GATEWAY_SUBJECT = "urn:aegis-ot:m4g:workload:gateway"
OT_SUBJECT = "urn:aegis-ot:m4g:workload:ot-adapter"
FIXED_ROTATION_NONCE = "m4g-cross-leaf-transport-nonce-0001"
MAX_CAPTURE_BYTES = 1_048_576
TRUST_SEQUENCE_DIRECTORY = "/var/lib/aegis-ot/trust-sequence"
TRUST_SEQUENCE_STATE_FILE = f"{TRUST_SEQUENCE_DIRECTORY}/state.json"
TRUST_SEQUENCE_VOLUME_SUFFIXES = {
    "agent": "workload_trust_sequence_agent",
    "gateway": "workload_trust_sequence_gateway",
    "ot-adapter": "workload_trust_sequence_ot",
}


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


def _source_binding(commit: str) -> dict[str, Any]:
    checkout = _assert_source_checkout()
    if m4d._run("git", "rev-parse", "HEAD").stdout.strip() != commit:
        raise m4d.ExperimentError("M4g source-binding commit changed")
    git_tree = m4d._run("git", "rev-parse", f"{commit}^{{tree}}").stdout.strip()
    source_files: dict[str, str] = {}
    for relative in SOURCE_BINDING_FILES:
        path = ROOT / relative
        try:
            material = path.read_bytes()
        except OSError as exc:
            raise m4d.ExperimentError(
                f"M4g source-binding file is unavailable: {relative}"
            ) from exc
        source_files[relative] = hashlib.sha256(material).hexdigest()
    binding: dict[str, Any] = {
        **checkout,
        "git_commit": commit,
        "git_tree": git_tree,
        "source_files": source_files,
        "source_files_sha256": m4d._canonical_sha256(source_files),
    }
    binding["source_binding_sha256"] = m4d._canonical_sha256(binding)
    return binding


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
        "AEGIS_AGENT_ACTOR_ID": AGENT_ACTOR_ID,
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
    environment["AEGIS_WORKLOAD_AUTHORITY_PUBLIC_KEY_FILE"] = str(
        paths["workload_authority_public"]
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


_TRUST_SEQUENCE_SNAPSHOT_CODE = r"""
import base64, hashlib, json, stat
from pathlib import Path
root = Path('/var/lib/aegis-ot/trust-sequence')
metadata = root.lstat()
result = {
    'directory': {
        'path': str(root),
        'entries': sorted(item.name for item in root.iterdir()),
        'mode': format(stat.S_IMODE(metadata.st_mode), '04o'),
        'uid': metadata.st_uid,
        'gid': metadata.st_gid,
    },
    'files': {},
}
for name in ('state.json', '.state.json.lock'):
    path = root / name
    material = path.read_bytes()
    item_metadata = path.lstat()
    item = {
        'bytes_base64': base64.b64encode(material).decode('ascii'),
        'sha256': hashlib.sha256(material).hexdigest(),
        'size_bytes': len(material),
        'mode': format(stat.S_IMODE(item_metadata.st_mode), '04o'),
        'uid': item_metadata.st_uid,
        'gid': item_metadata.st_gid,
        'regular': stat.S_ISREG(item_metadata.st_mode),
        'links': item_metadata.st_nlink,
    }
    if name == 'state.json':
        item['document'] = json.loads(material)
    result['files'][name] = item
print(json.dumps(result,sort_keys=True,separators=(',',':')))
"""


def _service_trust_sequence_snapshot(
    prefix: tuple[str, ...],
    service: str,
) -> dict[str, Any]:
    profile = ("--profile", "experiment") if service == "agent-probe" else ()
    completed = m4d._run(
        *prefix,
        *profile,
        "run",
        "--rm",
        "--no-deps",
        "--entrypoint",
        "python",
        service,
        "-c",
        _TRUST_SEQUENCE_SNAPSHOT_CODE,
    )
    return _json_object(
        completed.stdout,
        label=f"{service} trust-sequence snapshot",
    )


def _trust_sequence_snapshot(prefix: tuple[str, ...]) -> dict[str, Any]:
    return {
        "agent": _service_trust_sequence_snapshot(prefix, "agent-probe"),
        "gateway": _service_trust_sequence_snapshot(prefix, "segmented-gateway"),
        "ot-adapter": _service_trust_sequence_snapshot(prefix, "ot-adapter"),
    }


def _trust_sequence_snapshot_at(
    snapshot: dict[str, Any],
    *,
    sequence: int,
) -> bool:
    if set(snapshot) != set(TRUST_SEQUENCE_VOLUME_SUFFIXES):
        return False
    for item in snapshot.values():
        if not isinstance(item, dict):
            return False
        directory = item.get("directory")
        files = item.get("files")
        if not isinstance(directory, dict) or not isinstance(files, dict):
            return False
        if (
            directory.get("path") != TRUST_SEQUENCE_DIRECTORY
            or directory.get("entries") != [".state.json.lock", "state.json"]
            or directory.get("mode") != "0700"
            or directory.get("uid") != 65532
            or directory.get("gid") != 65532
            or set(files) != {"state.json", ".state.json.lock"}
        ):
            return False
        state = files["state.json"]
        lock = files[".state.json.lock"]
        if not isinstance(state, dict) or not isinstance(lock, dict):
            return False
        document = state.get("document")
        if (
            not isinstance(document, dict)
            or document.get("schema_version")
            != "m4g-workload-trust-sequence-state-v1"
            or document.get("highest_sequence") != sequence
            or document.get("trust_domain") != TRUST_DOMAIN
            or not isinstance(document.get("highest_bundle_sha256"), str)
            or len(document["highest_bundle_sha256"]) != 64
        ):
            return False
        for persisted in (state, lock):
            if (
                persisted.get("mode") != "0600"
                or persisted.get("uid") != 65532
                or persisted.get("gid") != 65532
                or persisted.get("regular") is not True
                or persisted.get("links") != 1
            ):
                return False
    return True


def _trust_sequence_floors(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        role: item.get("files", {})
        .get("state.json", {})
        .get("document", {})
        .get("highest_sequence")
        for role, item in snapshot.items()
        if isinstance(item, dict)
    }


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
        actor_id=os.environ['AEGIS_AGENT_ACTOR_ID'],
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
    verified = WorkloadSignedCapabilityResponse.model_validate_json(material)
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
    replay_reasons = replay.get("reasons", []) if isinstance(replay, dict) else []
    return (
        isinstance(nominal, dict)
        and nominal.get("status") == "completed"
        and nominal.get("dispatch_attempts") == 1
        and isinstance(replay, dict)
        and replay.get("status") == "not_dispatched"
        and replay.get("dispatch_attempts") == 0
        and isinstance(replay_reasons, list)
        and set(replay_reasons)
        == {"observation_sequence_regressed", "observation_challenge_replayed"}
        and isinstance(unsafe, dict)
        and unsafe.get("status") == "not_dispatched"
        and unsafe.get("dispatch_attempts") == 0
        and "critical_load_below_limit" in unsafe.get("reasons", [])
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


_LOCAL_TRUST_VERIFIER_PROBE_CODE = r"""
import json, os
from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    OT_CAPABILITY_AUDIENCE,
)
from aegis_ot.workload_identity import WorkloadRole
from aegis_ot.workload_runtime import (
    local_identity_from_environment,
    verifier_from_environment,
)
prefix = os.environ['AEGIS_M4G_TRUST_TEST_PREFIX']
if prefix == 'GATEWAY':
    role = WorkloadRole.GATEWAY
    audience = OT_CAPABILITY_AUDIENCE
elif prefix == 'OT':
    role = WorkloadRole.OT_ADAPTER
    audience = GATEWAY_CAPABILITY_AUDIENCE
else:
    raise RuntimeError('unsupported trust verifier probe prefix')
identity = local_identity_from_environment(
    verifier_from_environment(),
    prefix,
    role=role,
    audience=audience,
)
resolved = identity.resolve()
print(json.dumps({
    'credential_id': identity.signer.credential.credential.credential_id,
    'sequence': resolved.verification.trust_bundle_sequence,
},sort_keys=True,separators=(',',':')))
"""

_LOCAL_HEALTH_EXCHANGE_CODE = r"""
import json, os
from urllib.error import HTTPError
from urllib.request import urlopen
url = 'http://127.0.0.1:' + os.environ['AEGIS_M4G_HEALTH_PORT'] + '/health'
try:
    with urlopen(url, timeout=3) as response:
        status = response.status
        material = response.read(1048577)
except HTTPError as exc:
    status = exc.code
    material = exc.read(1048577)
if len(material) > 1048576:
    raise RuntimeError('local health response exceeded evidence limit')
print(json.dumps({
    'http_status': status,
    'body': json.loads(material),
},sort_keys=True,separators=(',',':')))
"""


def _local_trust_verifier_probe(
    prefix: tuple[str, ...],
    *,
    service: str,
    identity_prefix: str,
    check: bool,
) -> subprocess.CompletedProcess[str]:
    return m4d._run(
        *prefix,
        "run",
        "--rm",
        "--no-deps",
        "--entrypoint",
        "python",
        "--env",
        f"AEGIS_M4G_TRUST_TEST_PREFIX={identity_prefix}",
        service,
        "-c",
        _LOCAL_TRUST_VERIFIER_PROBE_CODE,
        check=check,
    )


def _recreate_gateway_ot(
    prefix: tuple[str, ...],
    *,
    await_ready: bool = True,
) -> dict[str, Any]:
    before = {
        service: _container_identity(prefix, service)
        for service in ("segmented-gateway", "ot-adapter")
    }
    m4d._run(
        *prefix,
        "up",
        "-d",
        "--force-recreate",
        "--no-deps",
        "--no-build",
        "segmented-gateway",
        "ot-adapter",
    )
    if await_ready:
        _await_gateway()
        after = {
            service: _container_identity(prefix, service)
            for service in ("segmented-gateway", "ot-adapter")
        }
        health: dict[str, Any] = {}
    else:
        after, health = _await_gateway_ot_unavailable(prefix)
    return {"before": before, "after": after, "health": health}


def _local_health_exchange(
    prefix: tuple[str, ...],
    *,
    service: str,
    port: int,
) -> dict[str, Any]:
    completed = m4d._run(
        *prefix,
        "exec",
        "-T",
        "-e",
        f"AEGIS_M4G_HEALTH_PORT={port}",
        service,
        "python",
        "-c",
        _LOCAL_HEALTH_EXCHANGE_CODE,
    )
    return _json_object(completed.stdout, label=f"{service} rollback health")


def _await_gateway_ot_unavailable(
    prefix: tuple[str, ...],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    latest_containers: dict[str, dict[str, Any]] = {}
    latest_health: dict[str, Any] = {}
    for _ in range(80):
        latest_containers = {
            service: _container_identity(prefix, service)
            for service in ("segmented-gateway", "ot-adapter")
        }
        try:
            latest_health = {
                "segmented-gateway": _local_health_exchange(
                    prefix,
                    service="segmented-gateway",
                    port=8081,
                ),
                "ot-adapter": _local_health_exchange(
                    prefix,
                    service="ot-adapter",
                    port=8083,
                ),
            }
        except m4d.ExperimentError:
            time.sleep(0.25)
            continue
        expected_reasons = {
            "segmented-gateway": "gateway_runtime_unavailable",
            "ot-adapter": "ot_runtime_unavailable",
        }
        if all(
            latest_containers[service].get("running") is True
            and latest_health[service].get("http_status") == 503
            and isinstance(latest_health[service].get("body"), dict)
            and latest_health[service]["body"].get("reason") == reason
            for service, reason in expected_reasons.items()
        ):
            return latest_containers, latest_health
        time.sleep(0.25)
    raise m4d.ExperimentError(
        "M4g gateway and OT adapter did not become unavailable under trust rollback"
    )


def _gateway_ot_recreated(
    snapshots: dict[str, Any],
) -> bool:
    before = snapshots.get("before", {})
    after = snapshots.get("after", {})
    return all(
        isinstance(before.get(service), dict)
        and isinstance(after.get(service), dict)
        and before[service].get("container_id") != after[service].get("container_id")
        and before[service].get("started_at") != after[service].get("started_at")
        for service in ("segmented-gateway", "ot-adapter")
    )


def _gateway_ot_failed_closed(
    snapshots: dict[str, Any],
) -> bool:
    after = snapshots.get("after", {})
    health = snapshots.get("health", {})
    expected_reasons = {
        "segmented-gateway": "gateway_runtime_unavailable",
        "ot-adapter": "ot_runtime_unavailable",
    }
    return (
        isinstance(after, dict)
        and isinstance(health, dict)
        and set(after) == set(expected_reasons)
        and set(health) == set(expected_reasons)
        and all(
            isinstance(after[service], dict)
            and after[service].get("running") is True
            and isinstance(health[service], dict)
            and health[service].get("http_status") == 503
            and isinstance(health[service].get("body"), dict)
            and health[service]["body"].get("reason") == reason
            for service, reason in expected_reasons.items()
        )
    )


def _rollback_rejected(process: subprocess.CompletedProcess[str]) -> bool:
    detail = f"{process.stdout}\n{process.stderr}"
    return process.returncode != 0 and "sequence rolled back" in detail


def _restart_durable_bundle_rollback_case(
    prefix: tuple[str, ...],
    *,
    sequence_one_bundle: bytes,
    sequence_two_bundle: bytes,
) -> dict[str, Any]:
    """Prove intact local floors reject signed rollback after process recreation."""

    sequence_two_before_restart = _trust_sequence_snapshot(prefix)
    intact_restart = _recreate_gateway_ot(prefix)
    intact_restart_probe = _json_object(
        _run_agent_probe(prefix).stdout,
        label="intact-volume restart M4g agent probe",
    )
    sequence_two_after_restart = _trust_sequence_snapshot(prefix)

    plant_before = _service_health(prefix, "simulation", 8084)
    mutation: dict[str, Any] | None = None
    rollback_restart: dict[str, Any] | None = None
    agent_probe: subprocess.CompletedProcess[str] | None = None
    gateway_probe: subprocess.CompletedProcess[str] | None = None
    ot_probe: subprocess.CompletedProcess[str] | None = None
    sequence_after_rejection: dict[str, Any] | None = None
    plant_after: dict[str, Any] | None = None
    bundle_restored = False
    recovery_restart: dict[str, Any] | None = None
    try:
        mutation = _mutate_bundle(
            prefix,
            operation="replace",
            material=sequence_one_bundle,
        )
        rollback_restart = _recreate_gateway_ot(prefix, await_ready=False)
        agent_probe = _run_agent_probe(prefix, check=False)
        gateway_probe = _local_trust_verifier_probe(
            prefix,
            service="segmented-gateway",
            identity_prefix="GATEWAY",
            check=False,
        )
        ot_probe = _local_trust_verifier_probe(
            prefix,
            service="ot-adapter",
            identity_prefix="OT",
            check=False,
        )
        sequence_after_rejection = _trust_sequence_snapshot(prefix)
        plant_after = _service_health(prefix, "simulation", 8084)
    finally:
        _mutate_bundle(
            prefix,
            operation="replace",
            material=sequence_two_bundle,
        )
        bundle_restored = True
        recovery_restart = _recreate_gateway_ot(prefix)

    if (
        mutation is None
        or rollback_restart is None
        or agent_probe is None
        or gateway_probe is None
        or ot_probe is None
        or sequence_after_rejection is None
        or plant_after is None
        or recovery_restart is None
    ):
        raise m4d.ExperimentError(
            "restart-durable M4g trust-bundle rollback case did not complete"
        )

    recovery_probe = _json_object(
        _run_agent_probe(prefix).stdout,
        label="post-rollback-recovery M4g agent probe",
    )
    sequence_after_recovery = _trust_sequence_snapshot(prefix)
    no_effect = (
        plant_before.get("state_version") == plant_after.get("state_version")
        and plant_before.get("state_digest") == plant_after.get("state_digest")
        and plant_before.get("commit_count") == plant_after.get("commit_count")
    )
    verifier_exit_codes = {
        "agent": agent_probe.returncode,
        "gateway": gateway_probe.returncode,
        "ot-adapter": ot_probe.returncode,
    }
    verifier_rejections = {
        "agent": _rollback_rejected(agent_probe),
        "gateway": _rollback_rejected(gateway_probe),
        "ot-adapter": _rollback_rejected(ot_probe),
    }
    accepted = (
        _trust_sequence_snapshot_at(sequence_two_before_restart, sequence=2)
        and _gateway_ot_recreated(intact_restart)
        and _probe_accepted(intact_restart_probe)
        and _trust_sequence_snapshot_at(sequence_two_after_restart, sequence=2)
        and mutation.get("present") is True
        and _gateway_ot_recreated(rollback_restart)
        and _gateway_ot_failed_closed(rollback_restart)
        and all(verifier_rejections.values())
        and no_effect
        and _trust_sequence_snapshot_at(sequence_after_rejection, sequence=2)
        and bundle_restored
        and _gateway_ot_recreated(recovery_restart)
        and _probe_accepted(recovery_probe)
        and _trust_sequence_snapshot_at(sequence_after_recovery, sequence=2)
    )
    return {
        "condition": "signed_sequence_one_after_intact_sequence_two_restart",
        "sequence_two_before_restart": sequence_two_before_restart,
        "intact_restart": intact_restart,
        "intact_restart_probe": intact_restart_probe,
        "sequence_two_after_restart": sequence_two_after_restart,
        "mutation": mutation,
        "rollback_restart": rollback_restart,
        "verifier_exit_codes": verifier_exit_codes,
        "verifier_rollback_rejections": verifier_rejections,
        "verifier_stderr_tails": {
            "agent": agent_probe.stderr[-4000:],
            "gateway": gateway_probe.stderr[-4000:],
            "ot-adapter": ot_probe.stderr[-4000:],
        },
        "plant_before": plant_before,
        "plant_after": plant_after,
        "effect_absent": no_effect,
        "sequence_after_rejection": sequence_after_rejection,
        "bundle_restored": bundle_restored,
        "recovery_restart": recovery_restart,
        "recovery_probe": recovery_probe,
        "sequence_after_recovery": sequence_after_recovery,
        "accepted": accepted,
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


def _failed_acceptance_names(acceptance: dict[str, bool]) -> tuple[str, ...]:
    return tuple(
        name for name, accepted in sorted(acceptance.items()) if accepted is not True
    )


def _redacted_environment(
    environment: dict[str, str],
    key_directory: Path,
) -> dict[str, str]:
    return {
        name: _replace_path_prefix(value, key_directory, "<ephemeral-key-dir>")
        for name, value in sorted(environment.items())
    }


def _resolved_volume_at(service: dict[str, Any], target: str) -> dict[str, Any] | None:
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        return None
    matches = [
        item
        for item in volumes
        if isinstance(item, dict)
        and item.get("type") == "volume"
        and item.get("target") == target
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _trust_sequence_compose_bound(compose: dict[str, Any]) -> bool:
    services = compose.get("services")
    if not isinstance(services, dict):
        return False
    expected = {
        "agent-probe": "workload_trust_sequence_agent",
        "segmented-gateway": "workload_trust_sequence_gateway",
        "ot-adapter": "workload_trust_sequence_ot",
    }
    for service_name, suffix in expected.items():
        service = services.get(service_name)
        if not isinstance(service, dict):
            return False
        environment = service.get("environment")
        mount = _resolved_volume_at(service, TRUST_SEQUENCE_DIRECTORY)
        if (
            not isinstance(environment, dict)
            or environment.get("AEGIS_WORKLOAD_TRUST_SEQUENCE_STATE_FILE")
            != TRUST_SEQUENCE_STATE_FILE
            or not isinstance(mount, dict)
            or not str(mount.get("source", "")).endswith(suffix)
            or mount.get("read_only", False) is not False
        ):
            return False

    initializer = services.get("identity-init")
    administrator = services.get("identity-admin")
    if not isinstance(initializer, dict) or not isinstance(administrator, dict):
        return False
    initializer_environment = initializer.get("environment")
    if not isinstance(initializer_environment, dict):
        return False
    init_targets = {
        "workload_trust_sequence_agent": (
            "/var/lib/aegis-ot/trust-sequence-state/agent",
            "AEGIS_AGENT_TRUST_SEQUENCE_DIRECTORY",
        ),
        "workload_trust_sequence_gateway": (
            "/var/lib/aegis-ot/trust-sequence-state/gateway",
            "AEGIS_GATEWAY_TRUST_SEQUENCE_DIRECTORY",
        ),
        "workload_trust_sequence_ot": (
            "/var/lib/aegis-ot/trust-sequence-state/ot",
            "AEGIS_OT_TRUST_SEQUENCE_DIRECTORY",
        ),
    }
    for suffix, (target, setting) in init_targets.items():
        mount = _resolved_volume_at(initializer, target)
        if (
            initializer_environment.get(setting) != target
            or not isinstance(mount, dict)
            or not str(mount.get("source", "")).endswith(suffix)
            or mount.get("read_only", False) is not False
        ):
            return False
    administrator_volumes = administrator.get("volumes", [])
    if not isinstance(administrator_volumes, list):
        return False
    return not any(
        isinstance(item, dict)
        and str(item.get("source", "")).endswith(
            tuple(TRUST_SEQUENCE_VOLUME_SUFFIXES.values())
        )
        for item in administrator_volumes
    )


def _campaign(project_name: str, commit: str) -> dict[str, Any]:
    _assert_project_absent(project_name)
    _assert_checkout(commit)
    source_binding = _source_binding(commit)
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
            trust_sequence_initial = _trust_sequence_snapshot(prefix)
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
            trust_sequence_rotated = _trust_sequence_snapshot(prefix)
            replay_after_rotation = _replay_snapshot(prefix)
            health_after_rotation = _health_snapshot(prefix)

            initial_bundle = _decode_artifact(identity_initial, "trust-bundle.json")
            rotated_bundle = _decode_artifact(identity_rotated, "trust-bundle.json")
            restart_durable_rollback = _restart_durable_bundle_rollback_case(
                prefix,
                sequence_one_bundle=initial_bundle,
                sequence_two_bundle=rotated_bundle,
            )
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
                "isolated_durable_trust_sequence_state_configured": (
                    _trust_sequence_compose_bound(compose)
                    and identity_initialization.get("trust_sequence_directories")
                    == {
                        "agent": {
                            "path": (
                                "/var/lib/aegis-ot/trust-sequence-state/agent"
                            ),
                            "state": "bootstrap_prepared",
                            "directory_mode": "0700",
                        },
                        "gateway": {
                            "path": (
                                "/var/lib/aegis-ot/trust-sequence-state/gateway"
                            ),
                            "state": "bootstrap_prepared",
                            "directory_mode": "0700",
                        },
                        "ot-adapter": {
                            "path": "/var/lib/aegis-ot/trust-sequence-state/ot",
                            "state": "bootstrap_prepared",
                            "directory_mode": "0700",
                        },
                    }
                ),
                "primary_agent_campaign_accepted": _probe_accepted(primary_probe),
                "all_verifiers_persisted_sequence_one": (
                    _trust_sequence_snapshot_at(trust_sequence_initial, sequence=1)
                ),
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
                "all_verifiers_persisted_sequence_two": (
                    _trust_sequence_snapshot_at(trust_sequence_rotated, sequence=2)
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
                "intact_restart_rejects_signed_sequence_rollback": (
                    restart_durable_rollback.get("accepted") is True
                ),
            }
            semantic_projection = {
                "git_commit": commit,
                "source_binding_sha256": source_binding[
                    "source_binding_sha256"
                ],
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
                "durable_trust_sequence": {
                    "sequence_one_floors": _trust_sequence_floors(
                        trust_sequence_initial
                    ),
                    "sequence_two_floors": _trust_sequence_floors(
                        trust_sequence_rotated
                    ),
                    "rollback_rejected": restart_durable_rollback.get("accepted"),
                    "post_rejection_floors": _trust_sequence_floors(
                        restart_durable_rollback.get(
                            "sequence_after_rejection", {}
                        )
                    ),
                    "effect_absent": restart_durable_rollback.get("effect_absent"),
                    "recovery_accepted": _probe_accepted(
                        restart_durable_rollback.get("recovery_probe", {})
                    ),
                },
                "acceptance": acceptance,
            }
            evidence = {
                "schema_version": "m4g-workload-identity-experiment-v2",
                "generated_at": datetime.now(UTC).isoformat(),
                "analyst": "Angelis Pseftis",
                "git_commit": commit,
                "clean_checkout_start": True,
                "project_name": project_name,
                "source_checkout_binding": source_binding,
                "source_binding": source_binding,
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
                "trust_sequence_initial": trust_sequence_initial,
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
                "trust_sequence_rotated": trust_sequence_rotated,
                "replay_after_rotation": replay_after_rotation,
                "health_after_rotation": health_after_rotation,
                "bundle_fault_cases": fault_cases,
                "restart_durable_bundle_rollback": restart_durable_rollback,
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
                        "Restart-durable signed-bundle rollback rejection uses intact "
                        "trusted per-verifier Docker volumes; a hostile host can still "
                        "roll back or replace those volumes"
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
                failed = _failed_acceptance_names(acceptance)
                raise m4d.ExperimentError(
                    "M4g workload-identity acceptance criteria failed: "
                    + ", ".join(failed)
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
