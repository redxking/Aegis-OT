#!/usr/bin/env python3
"""Run and validate the bounded two-phase M4j live workload probe."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parents[1]
PROBE_PLAYBOOK = ROOT / "infra" / "ansible" / "probe.yml"
INVENTORY = ROOT / "infra" / "ansible" / "inventory.ini"
PROBE_RECORD_NAMES = ("initial.json", "after-bounded-restart.json")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_PROBE_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_BYTES = 12 * 1024 * 1024
EVIDENCE_SCHEMA = "aegis-ot-m4j-live-workload-probe-envelope-v2"
PAYLOAD_SCHEMA = "aegis-ot-m4j-live-workload-probe-v1"
SIGNATURE_SCOPE = (
    "controller_signature_authenticates_canonical_record_bytes_"
    "not_independent_execution_provenance"
)
CLAIM_BOUNDARY = (
    "bounded_local_live_probe_only_not_production_deployment_"
    "independent_validation_or_operational_effectiveness"
)
PROBE_FIELDS = frozenset(
    {
        "schema_version",
        "gateway_health",
        "nominal",
        "exact_gateway_request_replay",
        "unsafe",
        "agent_direct_reachability",
    }
)
BYPASS_TARGETS = frozenset({"observer", "candidate", "ot-adapter", "simulation"})


class WorkloadProbeError(RuntimeError):
    """The bounded live workload probe could not establish its exact gates."""


def _fail(message: str) -> NoReturn:
    raise WorkloadProbeError(message)


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WorkloadProbeError("probe material is not canonical JSON") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate probe JSON key: {key}")
        value[key] = item
    return value


def _mapping(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} must be a string-keyed object")
    return cast(dict[str, Any], value)


def _read_private_regular(path: Path, *, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WorkloadProbeError(f"{label} is unavailable or linked") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            _fail(f"{label} is not a bounded private regular file")
        material = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - len(material))):
            material.extend(chunk)
            if len(material) > maximum:
                _fail(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or len(material) != metadata.st_size
        ):
            _fail(f"{label} changed while it was read")
        return bytes(material)
    finally:
        os.close(descriptor)


def _require_private_parent(path: Path, *, label: str) -> None:
    parent = path.absolute().parent
    try:
        metadata = parent.stat()
    except OSError as exc:
        raise WorkloadProbeError(f"{label} parent is unavailable") from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail(f"{label} must be inside an owned mode-0700 directory")


def _load_signing_private_key(path: Path) -> Ed25519PrivateKey:
    material = _read_private_regular(
        path,
        maximum=32,
        label="controller evidence signing private key",
    )
    if len(material) != 32:
        _fail("controller evidence signing private key must be 32 raw Ed25519 bytes")
    try:
        return Ed25519PrivateKey.from_private_bytes(material)
    except ValueError as exc:
        raise WorkloadProbeError("controller evidence signing private key is invalid") from exc


def _load_trusted_public_key(path: Path) -> Ed25519PublicKey:
    material = _read_private_regular(
        path,
        maximum=32,
        label="trusted controller evidence public key",
    )
    if len(material) != 32:
        _fail("trusted controller evidence public key must be 32 raw Ed25519 bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(material)
    except ValueError as exc:
        raise WorkloadProbeError("trusted controller evidence public key is invalid") from exc


def _key_id(public_key: Ed25519PublicKey) -> str:
    return "sha256:" + hashlib.sha256(public_key.public_bytes_raw()).hexdigest()


def controller_signing_identity(
    private_key_path: Path,
    trusted_public_key_path: Path,
) -> str:
    private_key = _load_signing_private_key(private_key_path)
    trusted_public_key = _load_trusted_public_key(trusted_public_key_path)
    if private_key.public_key().public_bytes_raw() != trusted_public_key.public_bytes_raw():
        _fail("controller evidence signing key does not match the explicit trust anchor")
    return _key_id(trusted_public_key)


def _load_probe_record(path: Path) -> dict[str, Any]:
    material = _read_private_regular(
        path,
        maximum=MAX_PROBE_BYTES,
        label=f"probe record {path.name}",
    )
    try:
        record = json.loads(
            material.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: _fail(f"forbidden JSON constant: {value}"),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WorkloadProbeError(f"probe record is not strict JSON: {path.name}") from exc
    record = _mapping(record, label=f"probe record {path.name}")
    if material != _canonical_bytes(record) + b"\n":
        _fail(f"probe record is not canonical JSON: {path.name}")
    if frozenset(record) != PROBE_FIELDS:
        _fail(f"probe record fields differ from the closed contract: {path.name}")
    if record["schema_version"] != "m4g-capability-probe-v1":
        _fail(f"probe record schema differs: {path.name}")
    return record


def _record_gates(record: Mapping[str, Any]) -> dict[str, bool]:
    health = _mapping(record.get("gateway_health"), label="gateway health")
    nominal = _mapping(record.get("nominal"), label="nominal result")
    replay = _mapping(
        record.get("exact_gateway_request_replay"),
        label="exact replay result",
    )
    unsafe = _mapping(record.get("unsafe"), label="unsafe result")
    reachability = _mapping(
        record.get("agent_direct_reachability"),
        label="agent direct reachability",
    )
    replay_reasons = replay.get("reasons")
    unsafe_reasons = unsafe.get("reasons")

    def exact_count(value: object, expected: int) -> bool:
        # JSON booleans become bool, which is an int subclass in Python.  A
        # count gate must therefore use an exact type check before equality.
        return type(value) is int and value == expected

    def nonnegative_count(value: object) -> bool:
        return type(value) is int and value >= 0

    return {
        "gateway_ready": health.get("status") == "ready",
        "durable_coordination_ready": (
            health.get("effect_coordination_mode") == "required"
            and health.get("coordination_backend")
            == "durable-prepare-commit-query-http-v1"
            and nonnegative_count(health.get("coordination_journal_records"))
            and exact_count(health.get("coordination_pending_effects"), 0)
        ),
        "nominal_action_completed_once": (
            nominal.get("status") == "completed"
            and exact_count(nominal.get("dispatch_attempts"), 1)
        ),
        "exact_replay_failed_closed": (
            replay.get("status") == "not_dispatched"
            and exact_count(replay.get("dispatch_attempts"), 0)
            and isinstance(replay_reasons, list)
            and set(replay_reasons)
            == {"observation_sequence_regressed", "observation_challenge_replayed"}
        ),
        "unsafe_action_failed_closed": (
            unsafe.get("status") == "not_dispatched"
            and exact_count(unsafe.get("dispatch_attempts"), 0)
            and isinstance(unsafe_reasons, list)
            and "critical_load_below_limit" in unsafe_reasons
        ),
        "direct_workload_bypass_denied": (
            frozenset(reachability) == BYPASS_TARGETS
            and all(value is False for value in reachability.values())
        ),
    }


def _private_output_path(path: Path) -> Path:
    if path.exists() or path.is_symlink():
        _fail("refusing to overwrite a live probe evidence path")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise WorkloadProbeError("probe evidence parent is unavailable") from exc
    destination = parent / path.name
    try:
        destination.relative_to(ROOT.resolve())
    except ValueError:
        return destination
    _fail("live probe evidence must remain outside the checkout")


def _write_private(path: Path, material: bytes) -> None:
    if not material or len(material) > MAX_EVIDENCE_BYTES:
        _fail("live probe evidence size is invalid")
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
                _fail("live probe evidence write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_private_empty(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    os.close(descriptor)


def _execute_probe_playbook(
    *,
    source_commit: str,
    application_image_id: str,
    staging_directory: Path,
    known_hosts_file: Path,
    expected_known_hosts_sha256: str,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        _fail("ansible-playbook is unavailable")
    ssh_executable = Path("/usr/bin/ssh")
    if not ssh_executable.is_file() or not os.access(ssh_executable, os.X_OK):
        _fail("the pinned /usr/bin/ssh transport is unavailable")
    _require_private_parent(known_hosts_file, label="controller known-hosts evidence")
    known_hosts_material = _read_private_regular(
        known_hosts_file,
        maximum=65536,
        label="controller known-hosts evidence",
    )
    if (
        SHA256.fullmatch(expected_known_hosts_sha256) is None
        or hashlib.sha256(known_hosts_material).hexdigest()
        != expected_known_hosts_sha256
    ):
        _fail("controller known-hosts evidence differs from the applied deployment")
    known_hosts = known_hosts_file.absolute()
    ssh_arguments = " ".join(
        (
            "-F /dev/null",
            "-o IdentitiesOnly=yes",
            "-o StrictHostKeyChecking=yes",
            f"-o UserKnownHostsFile={shlex.quote(str(known_hosts))}",
            "-o GlobalKnownHostsFile=/dev/null",
        )
    )
    environment = {
        **{
            name: value
            for name, value in os.environ.items()
            if not name.startswith("ANSIBLE_")
            and name not in {"PYTHONHOME", "PYTHONPATH"}
        },
        "AEGIS_M4J_SOURCE_COMMIT": source_commit,
        "AEGIS_M4J_APPLICATION_IMAGE_ID": application_image_id,
        "AEGIS_M4J_PROBE_STAGING_DIRECTORY": str(staging_directory),
        "ANSIBLE_CONFIG": str(ROOT / "infra" / "ansible" / "ansible.cfg"),
        "ANSIBLE_HOST_KEY_CHECKING": "True",
        "ANSIBLE_SSH_COMMON_ARGS": ssh_arguments,
        "ANSIBLE_SSH_EXECUTABLE": str(ssh_executable),
    }
    completed = subprocess.run(  # noqa: S603 - resolved Ansible and fixed argv
        (executable, "--inventory", str(INVENTORY), str(PROBE_PLAYBOOK)),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise WorkloadProbeError(
            "M4j workload probe failed after possible partial service restart; "
            f"exact reconciliation is required: {detail[-2000:]}"
        )
    _require_private_parent(known_hosts, label="controller known-hosts evidence")
    post_probe_material = _read_private_regular(
        known_hosts,
        maximum=65536,
        label="controller known-hosts evidence",
    )
    if hashlib.sha256(post_probe_material).hexdigest() != expected_known_hosts_sha256:
        _fail("controller known-hosts evidence changed during the workload probe")


def _signed_envelope(
    payload: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    trusted_public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    key_id = _key_id(trusted_public_key)
    unsigned = {
        "schema_version": EVIDENCE_SCHEMA,
        "payload": payload,
        "payload_sha256": hashlib.sha256(_canonical_bytes(payload)).hexdigest(),
        "controller_signature_context": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "scope": SIGNATURE_SCOPE,
        },
    }
    signature = private_key.sign(_canonical_bytes(unsigned))
    return {
        **unsigned,
        "controller_signature": base64.b64encode(signature).decode("ascii"),
    }


def run_live_probe(
    *,
    source_commit: str,
    application_image_id: str,
    host_plan_semantic_sha256: str,
    output_path: Path,
    signing_private_key_path: Path,
    trusted_public_key_path: Path,
    known_hosts_file: Path,
    expected_known_hosts_sha256: str,
) -> dict[str, Any]:
    """Execute two live phases and persist one private, semantically checked record."""

    if GIT_OBJECT.fullmatch(source_commit) is None:
        _fail("live probe source commit is not a full lowercase Git object ID")
    if IMAGE_ID.fullmatch(application_image_id) is None:
        _fail("live probe application image ID is not immutable")
    if SHA256.fullmatch(host_plan_semantic_sha256) is None:
        _fail("live probe host-plan digest is malformed")
    expected_signer_key_id = controller_signing_identity(
        signing_private_key_path,
        trusted_public_key_path,
    )
    private_key = _load_signing_private_key(signing_private_key_path)
    trusted_public_key = _load_trusted_public_key(trusted_public_key_path)
    if (
        _key_id(trusted_public_key) != expected_signer_key_id
        or private_key.public_key().public_bytes_raw()
        != trusted_public_key.public_bytes_raw()
    ):
        _fail("controller evidence trust anchor changed after preflight")
    destination = _private_output_path(output_path)
    staging_directory = Path(
        tempfile.mkdtemp(prefix=".aegis-m4j-probe-", dir=destination.parent)
    )
    staging_directory.chmod(0o700)
    for filename in PROBE_RECORD_NAMES:
        _create_private_empty(staging_directory / filename)
    started_at = datetime.now(UTC)
    try:
        _execute_probe_playbook(
            source_commit=source_commit,
            application_image_id=application_image_id,
            staging_directory=staging_directory,
            known_hosts_file=known_hosts_file,
            expected_known_hosts_sha256=expected_known_hosts_sha256,
        )
        records: dict[str, dict[str, Any]] = {}
        phase_gates: dict[str, dict[str, bool]] = {}
        for filename in PROBE_RECORD_NAMES:
            path = staging_directory / filename
            phase = "initial" if filename == "initial.json" else "after_bounded_restart"
            record = _load_probe_record(path)
            gates = _record_gates(record)
            if not all(gates.values()):
                failed = sorted(name for name, accepted in gates.items() if not accepted)
                _fail(f"M4j {phase} workload probe gates failed: {failed}")
            records[phase] = record
            phase_gates[phase] = gates
        completed_at = datetime.now(UTC)
        semantic_projection = {
            "source_git_commit": source_commit,
            "application_image_id": application_image_id,
            "host_plan_semantic_sha256": host_plan_semantic_sha256,
            "controller_known_hosts_sha256": expected_known_hosts_sha256,
            "phase_gates": phase_gates,
            "probe_records": records,
        }
        semantic_sha256 = hashlib.sha256(
            _canonical_bytes(semantic_projection)
        ).hexdigest()
        payload = {
            "schema_version": PAYLOAD_SCHEMA,
            "source_git_commit": source_commit,
            "application_image_id": application_image_id,
            "host_plan_semantic_sha256": host_plan_semantic_sha256,
            "controller_known_hosts_sha256": expected_known_hosts_sha256,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "phases": ["initial", "after_bounded_restart"],
            "restart_order": [
                "plant",
                "observer",
                "candidate",
                "ot-adapter",
                "segmented-gateway",
            ],
            "phase_semantics": {
                "initial": "identity_policy_and_action_contract",
                "after_bounded_restart": (
                    "post_restart_liveness_and_persistent_state_reuse_not_"
                    "general_recovery_correctness"
                ),
            },
            "phase_gates": phase_gates,
            "probe_records": records,
            "semantic_sha256": semantic_sha256,
            "probe_contract_passed": True,
            "deployment_acceptance_established": False,
            "g7_acceptance_established": False,
            "secret_material_retained": False,
            "claim_boundary": CLAIM_BOUNDARY,
        }
        envelope = _signed_envelope(
            payload,
            private_key=private_key,
            trusted_public_key=trusted_public_key,
        )
        _write_private(destination, _canonical_bytes(envelope) + b"\n")
        return verify_evidence(
            destination,
            expected_source_commit=source_commit,
            expected_application_image_id=application_image_id,
            expected_host_plan_semantic_sha256=host_plan_semantic_sha256,
            expected_controller_known_hosts_sha256=expected_known_hosts_sha256,
            trusted_public_key_path=trusted_public_key_path,
        )
    finally:
        if staging_directory.exists() and not staging_directory.is_symlink():
            shutil.rmtree(staging_directory)


def _load_evidence(path: Path) -> dict[str, Any]:
    material = _read_private_regular(
        path,
        maximum=MAX_EVIDENCE_BYTES,
        label="M4j live probe evidence",
    )
    try:
        envelope = json.loads(
            material.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: _fail(f"forbidden JSON constant: {value}"),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WorkloadProbeError("M4j live probe evidence is not strict JSON") from exc
    envelope = _mapping(envelope, label="M4j live probe evidence")
    if material != _canonical_bytes(envelope) + b"\n":
        _fail("M4j live probe evidence is not canonical JSON")
    return envelope


def verify_evidence(
    path: Path,
    *,
    expected_source_commit: str,
    expected_application_image_id: str,
    expected_host_plan_semantic_sha256: str,
    expected_controller_known_hosts_sha256: str,
    trusted_public_key_path: Path,
) -> dict[str, Any]:
    """Check one canonical probe record against explicit source, image, and signer pins."""

    if GIT_OBJECT.fullmatch(expected_source_commit) is None:
        _fail("expected live probe source commit is malformed")
    if IMAGE_ID.fullmatch(expected_application_image_id) is None:
        _fail("expected live probe application image ID is malformed")
    if SHA256.fullmatch(expected_host_plan_semantic_sha256) is None:
        _fail("expected live probe host-plan digest is malformed")
    if SHA256.fullmatch(expected_controller_known_hosts_sha256) is None:
        _fail("expected controller known-hosts digest is malformed")
    trusted_public_key = _load_trusted_public_key(trusted_public_key_path)
    envelope = _load_evidence(path)
    if set(envelope) != {
        "schema_version",
        "payload",
        "payload_sha256",
        "controller_signature_context",
        "controller_signature",
    }:
        _fail("M4j live probe evidence envelope fields differ")
    payload = _mapping(envelope["payload"], label="M4j live probe payload")
    signature_context = _mapping(
        envelope["controller_signature_context"],
        label="M4j controller signature context",
    )
    if (
        envelope["schema_version"] != EVIDENCE_SCHEMA
        or not isinstance(envelope["payload_sha256"], str)
        or hashlib.sha256(_canonical_bytes(payload)).hexdigest()
        != envelope["payload_sha256"]
    ):
        _fail("M4j live probe outer integrity differs")
    if signature_context != {
        "algorithm": "Ed25519",
        "key_id": _key_id(trusted_public_key),
        "scope": SIGNATURE_SCOPE,
    } or not isinstance(envelope["controller_signature"], str):
        _fail("M4j controller signature context differs from the explicit trust anchor")
    try:
        signature = base64.b64decode(envelope["controller_signature"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise WorkloadProbeError("M4j controller signature is not strict base64") from exc
    if (
        len(signature) != 64
        or base64.b64encode(signature).decode("ascii")
        != envelope["controller_signature"]
    ):
        _fail("M4j controller signature encoding differs")
    unsigned = {
        "schema_version": envelope["schema_version"],
        "payload": payload,
        "payload_sha256": envelope["payload_sha256"],
        "controller_signature_context": signature_context,
    }
    try:
        trusted_public_key.verify(signature, _canonical_bytes(unsigned))
    except InvalidSignature as exc:
        raise WorkloadProbeError(
            "M4j controller signature does not match the explicit trust anchor"
        ) from exc
    expected_payload_fields = {
        "schema_version",
        "source_git_commit",
        "application_image_id",
        "host_plan_semantic_sha256",
        "controller_known_hosts_sha256",
        "started_at",
        "completed_at",
        "phases",
        "restart_order",
        "phase_semantics",
        "phase_gates",
        "probe_records",
        "semantic_sha256",
        "probe_contract_passed",
        "deployment_acceptance_established",
        "g7_acceptance_established",
        "secret_material_retained",
        "claim_boundary",
    }
    if set(payload) != expected_payload_fields:
        _fail("M4j live probe payload fields differ")
    if (
        payload["schema_version"] != PAYLOAD_SCHEMA
        or payload["source_git_commit"] != expected_source_commit
        or payload["application_image_id"] != expected_application_image_id
        or payload["host_plan_semantic_sha256"]
        != expected_host_plan_semantic_sha256
        or payload["controller_known_hosts_sha256"]
        != expected_controller_known_hosts_sha256
        or not isinstance(payload["application_image_id"], str)
        or IMAGE_ID.fullmatch(payload["application_image_id"]) is None
        or payload["phases"] != ["initial", "after_bounded_restart"]
        or payload["restart_order"]
        != [
            "plant",
            "observer",
            "candidate",
            "ot-adapter",
            "segmented-gateway",
        ]
        or payload["phase_semantics"]
        != {
            "initial": "identity_policy_and_action_contract",
            "after_bounded_restart": (
                "post_restart_liveness_and_persistent_state_reuse_not_"
                "general_recovery_correctness"
            ),
        }
        or payload["claim_boundary"] != CLAIM_BOUNDARY
        or payload["probe_contract_passed"] is not True
        or payload["deployment_acceptance_established"] is not False
        or payload["g7_acceptance_established"] is not False
        or payload["secret_material_retained"] is not False
    ):
        _fail("M4j live probe bindings or scoped boundaries differ")
    try:
        started_at = datetime.fromisoformat(cast(str, payload["started_at"]))
        completed_at = datetime.fromisoformat(cast(str, payload["completed_at"]))
    except (TypeError, ValueError) as exc:
        raise WorkloadProbeError("M4j live probe timestamps are malformed") from exc
    if (
        started_at.tzinfo is None
        or completed_at.tzinfo is None
        or completed_at < started_at
        or completed_at > datetime.now(UTC) + timedelta(minutes=1)
    ):
        _fail("M4j live probe timestamps are not a bounded completed interval")
    records = _mapping(payload["probe_records"], label="M4j probe records")
    phase_gates = _mapping(payload["phase_gates"], label="M4j phase gates")
    if set(records) != {"initial", "after_bounded_restart"} or set(
        phase_gates
    ) != {"initial", "after_bounded_restart"}:
        _fail("M4j live probe phases differ")
    recomputed_gates: dict[str, dict[str, bool]] = {}
    normalized_records: dict[str, dict[str, Any]] = {}
    for phase in ("initial", "after_bounded_restart"):
        record = _mapping(records[phase], label=f"M4j {phase} probe record")
        if frozenset(record) != PROBE_FIELDS or record.get("schema_version") != (
            "m4g-capability-probe-v1"
        ):
            _fail(f"M4j {phase} probe record fields differ")
        gates = _record_gates(record)
        if phase_gates[phase] != gates or not all(gates.values()):
            _fail(f"M4j {phase} probe gates differ or failed")
        normalized_records[phase] = record
        recomputed_gates[phase] = gates
    semantic_projection = {
        "source_git_commit": expected_source_commit,
        "application_image_id": expected_application_image_id,
        "host_plan_semantic_sha256": expected_host_plan_semantic_sha256,
        "controller_known_hosts_sha256": expected_controller_known_hosts_sha256,
        "phase_gates": recomputed_gates,
        "probe_records": normalized_records,
    }
    if (
        not isinstance(payload["semantic_sha256"], str)
        or hashlib.sha256(_canonical_bytes(semantic_projection)).hexdigest()
        != payload["semantic_sha256"]
    ):
        _fail("M4j live probe semantic digest differs")
    return envelope


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--verify", type=Path, required=True)
    parser.add_argument("--expect-application-image-id", required=True)
    parser.add_argument("--expect-host-plan-semantic-sha256", required=True)
    parser.add_argument("--expect-controller-known-hosts-sha256", required=True)
    parser.add_argument("--trusted-public-key", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        envelope = verify_evidence(
            arguments.verify,
            expected_source_commit=arguments.source_commit,
            expected_application_image_id=arguments.expect_application_image_id,
            expected_host_plan_semantic_sha256=(
                arguments.expect_host_plan_semantic_sha256
            ),
            expected_controller_known_hosts_sha256=(
                arguments.expect_controller_known_hosts_sha256
            ),
            trusted_public_key_path=arguments.trusted_public_key,
        )
        payload = cast(dict[str, Any], envelope["payload"])
        signature_context = cast(
            dict[str, Any], envelope["controller_signature_context"]
        )
        result = {
            "canonical_record_consistency_passed": True,
            "trusted_controller_signature_valid": True,
            "controller_signer_key_id": signature_context["key_id"],
            "independent_execution_provenance_established": False,
            "probe_contract_passed": payload["probe_contract_passed"],
            "deployment_acceptance_established": payload[
                "deployment_acceptance_established"
            ],
            "g7_acceptance_established": payload["g7_acceptance_established"],
            "semantic_sha256": payload["semantic_sha256"],
            "controller_known_hosts_sha256": payload[
                "controller_known_hosts_sha256"
            ],
            "claim_boundary": payload["claim_boundary"],
        }
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"M4j live workload probe rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
