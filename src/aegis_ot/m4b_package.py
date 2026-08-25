"""Content-addressed finalizer and fail-closed offline verifier for M4b evidence.

The separately retained public trust anchor establishes internal package
integrity only. It does not establish external custody, independent operation,
physical-model validity, deployment, or operational effectiveness.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, JsonValue, ValidationError

from .capability_models import CapabilityClosedLoopStatus
from .evidence import EvidenceRecord
from .m4b_experiment import (
    EXPERIMENT_VERSION,
    OUTCOME_PROJECTION_VERSION,
    PROTOCOL_VERSION,
    CollectedM4bExperiment,
    collect_m4b_experiment,
    collection_summary,
)
from .m4b_models import (
    IndependentConsequenceReport,
    IndependentEvaluationRequest,
    IndependentEvaluationStatus,
    IndependentMetricName,
    M4bArtifactDescriptor,
    M4bCapabilityProbeBundle,
    M4bComponentRegistration,
    M4bComponentRole,
    M4bEvidenceManifest,
    M4bManifestSignature,
    M4bOrderlyRestartReplayRecord,
    M4bPackageDisposition,
    M4bTransactionRecord,
    M4bTrustAnchor,
    canonical_json_bytes,
    public_key_base64,
    public_key_from_base64,
    sha256_bytes,
)
from .physical_models import canonical_digest

MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.signature.json"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_JSONL_RECORDS = 100_000
MAX_ARTIFACTS = 512
MAX_ERRORS = 200

CORE_ARTIFACT_PATHS = frozenset(
    {
        "protocol/scenarios.json",
        "protocol/acceptance.json",
        "transactions/results.jsonl",
        "transactions/evidence-records.jsonl",
        "sessions/component-registrations.jsonl",
        "sessions/component-health.jsonl",
        "topology/capability-probes.jsonl",
        "lifecycle/orderly-restart-replay.jsonl",
        "independent/requests.jsonl",
        "independent/evaluations.jsonl",
        "independent/topology-fixture.json",
        "summary.json",
    }
)
EXPECTED_CONDITIONS = (
    ("unknown_identity", CapabilityClosedLoopStatus.NOT_DISPATCHED),
    ("stale_observation", CapabilityClosedLoopStatus.NOT_DISPATCHED),
    ("nominal_permitted_execution", CapabilityClosedLoopStatus.COMPLETED),
)
EXPECTED_PROBES = (
    (M4bComponentRole.OBSERVER, "telemetry:capture_post"),
    (M4bComponentRole.OBSERVER, "admin->plant:apply_authorized_command"),
    (M4bComponentRole.PLANT, "admin:apply_authorized_command"),
    (M4bComponentRole.PLANT, "simulation:apply_authorized_command"),
)
RUNTIME_ROLES = (
    M4bComponentRole.PLANT,
    M4bComponentRole.OBSERVER,
    M4bComponentRole.PLC,
    M4bComponentRole.PERMIT_SIGNER,
    M4bComponentRole.REPLACEMENT_PLC,
)
SESSION_ROLES = frozenset({*RUNTIME_ROLES, M4bComponentRole.INDEPENDENT_EVALUATOR})
HEALTH_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "session_index",
        "master_seed",
        "phase",
        "captured_at",
        "records",
        "bundle_sha256",
    }
)
EVIDENCE_WRAPPER_FIELDS = frozenset(
    {"schema_version", "session_id", "session_index", "master_seed", "record"}
)


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _strict_json(material: bytes, *, label: str) -> Any:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate field {key!r}")
            result[key] = value
        return result

    if material.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{label} contains a UTF-8 BOM")
    return json.loads(
        material,
        object_pairs_hook=pairs_hook,
        parse_constant=_reject_constant,
    )


def _jsonl(material: bytes, model: type[BaseModel], *, label: str) -> tuple[BaseModel, ...]:
    if not material.endswith(b"\n"):
        raise ValueError(f"{label} must end with a newline")
    lines = material.splitlines()
    if len(lines) > MAX_JSONL_RECORDS:
        raise ValueError(f"{label} exceeds the record limit")
    records: list[BaseModel] = []
    for index, line in enumerate(lines, start=1):
        if not line:
            raise ValueError(f"{label} contains an empty record at line {index}")
        value = _strict_json(line, label=f"{label} line {index}")
        record = model.model_validate(value)
        if canonical_json_bytes(record) != line:
            raise ValueError(f"{label} line {index} is not canonical")
        records.append(record)
    return tuple(records)


def _dict_jsonl(material: bytes, *, label: str) -> tuple[dict[str, JsonValue], ...]:
    if not material.endswith(b"\n"):
        raise ValueError(f"{label} must end with a newline")
    lines = material.splitlines()
    if len(lines) > MAX_JSONL_RECORDS:
        raise ValueError(f"{label} exceeds the record limit")
    records: list[dict[str, JsonValue]] = []
    for index, line in enumerate(lines, start=1):
        value = _strict_json(line, label=f"{label} line {index}")
        if not isinstance(value, dict):
            raise ValueError(f"{label} line {index} must be an object")
        if canonical_json_bytes(value) != line:
            raise ValueError(f"{label} line {index} is not canonical")
        records.append(cast(dict[str, JsonValue], value))
    return tuple(records)


def _canonical_json_artifact(material: bytes, *, label: str) -> Any:
    value = _strict_json(material, label=label)
    if canonical_json_bytes(value) + b"\n" != material:
        raise ValueError(f"{label} is not canonical JSON with one final newline")
    return value


def _canonicalize_json_artifacts(artifacts: dict[str, bytes]) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path, material in artifacts.items():
        if path.endswith(".json"):
            value = _strict_json(material, label=path)
            result[path] = canonical_json_bytes(value) + b"\n"
        else:
            result[path] = material
    return {path: result[path] for path in sorted(result)}


def _artifact_path_allowed(path: str) -> bool:
    if path in CORE_ARTIFACT_PATHS:
        return True
    parts = PurePosixPath(path).parts
    if len(parts) == 2 and parts[0] == "contracts":
        return parts[1].endswith(".schema.json") and not parts[1].startswith(".")
    if len(parts) == 2 and parts[0] == "source":
        return parts[1] in {"pyproject.toml", "requirements.lock"}
    if len(parts) == 4 and parts[:3] in {
        ("source", "src", "aegis_ot"),
        ("source", "src", "aegis_ot_independent"),
    }:
        return parts[3].endswith(".py") and not parts[3].startswith(".")
    return False


def _media_type(path: str) -> str:
    if path.endswith(".jsonl"):
        return "application/x-ndjson"
    if path.endswith(".json"):
        return "application/json"
    if path.endswith(".py"):
        return "text/x-python"
    if path.endswith(".toml"):
        return "application/toml"
    return "text/plain"


def _record_count(path: str, material: bytes) -> int | None:
    return len(material.splitlines()) if path.endswith(".jsonl") else None


def _descriptor(path: str, material: bytes) -> M4bArtifactDescriptor:
    return M4bArtifactDescriptor(
        path=path,
        media_type=_media_type(path),
        byte_length=len(material),
        sha256=sha256_bytes(material),
        record_count=_record_count(path, material),
    )


def build_artifact_descriptors(
    artifacts: dict[str, bytes],
) -> tuple[M4bArtifactDescriptor, ...]:
    """Validate exact retained bytes and construct the signed file inventory."""

    if not artifacts or len(artifacts) > MAX_ARTIFACTS:
        raise ValueError("artifact inventory is empty or exceeds the registered limit")
    if not CORE_ARTIFACT_PATHS <= set(artifacts):
        raise ValueError("required M4b artifacts are missing")
    total = 0
    descriptors: list[M4bArtifactDescriptor] = []
    for path, material in sorted(artifacts.items()):
        M4bArtifactDescriptor.require_safe_relative_path(path)
        if not _artifact_path_allowed(path):
            raise ValueError(f"artifact path is outside the registered M4b profile: {path}")
        if not isinstance(material, bytes):
            raise TypeError(f"artifact material must be bytes: {path}")
        if len(material) > MAX_ARTIFACT_BYTES:
            raise ValueError(f"artifact exceeds size limit: {path}")
        if path.endswith(".jsonl"):
            _dict_jsonl(material, label=path)
        elif path.endswith(".json"):
            _canonical_json_artifact(material, label=path)
        else:
            material.decode("utf-8")
        total += len(material)
        if total > MAX_PACKAGE_BYTES:
            raise ValueError("aggregate artifact size exceeds the registered limit")
        descriptors.append(_descriptor(path, material))
    return tuple(descriptors)


def _outcome_projection(
    *,
    root_seed: int,
    master_seeds: tuple[int, ...],
    transactions: tuple[M4bTransactionRecord, ...],
    probes: tuple[M4bCapabilityProbeBundle, ...],
    replays: tuple[M4bOrderlyRestartReplayRecord, ...],
    reports: tuple[IndependentConsequenceReport, ...],
) -> dict[str, JsonValue]:
    """Return the timing/key/PID-independent experimental outcome projection."""

    session_indexes = {item.session_id: item.session_index for item in transactions}
    report_indexes = {
        item.independent_report_id: item.session_index
        for item in transactions
        if item.independent_report_id is not None
    }
    condition_order = {name: index for index, (name, _) in enumerate(EXPECTED_CONDITIONS)}
    return {
        "schema_version": OUTCOME_PROJECTION_VERSION,
        "root_seed": root_seed,
        "master_seeds": list(master_seeds),
        "transactions": [
            {
                "session_index": item.session_index,
                "master_seed": item.master_seed,
                "condition": item.condition,
                "status": item.result.status.value,
                "reasons": list(item.result.reasons),
                "dispatch_attempts": item.result.dispatch_attempts,
                "automatic_retry_count": item.result.automatic_retry_count,
            }
            for item in sorted(
                transactions,
                key=lambda value: (
                    value.session_index,
                    condition_order.get(value.condition, len(condition_order)),
                ),
            )
        ],
        "capability_probes": [
            {
                "session_index": session_indexes.get(bundle.session_id),
                "outcomes": [
                    {
                        "ordinal": record.ordinal,
                        "role": record.endpoint_role.value,
                        "operation": record.operation,
                        "actual_disposition": record.actual_disposition,
                    }
                    for record in bundle.records
                ],
            }
            for bundle in sorted(
                probes,
                key=lambda value: session_indexes.get(value.session_id, -1),
            )
        ],
        "restart_replays": [
            {
                "session_index": session_indexes.get(item.session_id),
                "status": item.replay_acknowledgment.status.value,
                "phase": item.replay_acknowledgment.dispatch_phase.value,
                "reason": item.replay_acknowledgment.reason,
                "state_unchanged": item.replay_state_unchanged,
            }
            for item in sorted(
                replays,
                key=lambda value: session_indexes.get(value.session_id, -1),
            )
        ],
        "independent_evaluations": [
            {
                "session_index": report_indexes.get(report.report_id),
                "status": report.status.value,
                "reasons": list(report.reasons),
                "predicted_values": (
                    report.predicted_values.model_dump(mode="json")
                    if report.predicted_values is not None
                    else None
                ),
                "observed_values": (
                    report.observed_values.model_dump(mode="json")
                    if report.observed_values is not None
                    else None
                ),
                "metric_comparisons": [
                    item.model_dump(mode="json") for item in report.metric_comparisons
                ],
            }
            for report in sorted(
                reports,
                key=lambda value: report_indexes.get(value.report_id, -1),
            )
        ],
    }


def _safe_write(root: Path, relative: str, material: bytes) -> None:
    M4bArtifactDescriptor.require_safe_relative_path(relative)
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(material):
            offset += os.write(descriptor, material[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _make_read_only(root: Path) -> None:
    directories = [root]
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in names:
            child = base / name
            if child.is_symlink() or not child.is_dir():
                raise ValueError(f"non-directory package entry: {child}")
            directories.append(child)
        for name in files:
            child = base / name
            if child.is_symlink() or not child.is_file():
                raise ValueError(f"non-regular package entry: {child}")
            os.chmod(child, 0o444, follow_symlinks=False)
    for retained_directory in sorted(
        directories,
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        os.chmod(retained_directory, 0o555, follow_symlinks=False)  # noqa: S103


def _require_absent(path: Path, label: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise FileExistsError(f"{label} already exists: {path}")


def _collection_manifest_fields(
    collection: CollectedM4bExperiment,
    artifacts: dict[str, bytes],
) -> dict[str, Any]:
    outcome = _outcome_projection(
        root_seed=collection.root_seed,
        master_seeds=collection.master_seeds,
        transactions=collection.transaction_records,
        probes=collection.probe_bundles,
        replays=collection.replay_records,
        reports=collection.evaluation_reports,
    )
    summary = collection_summary(collection)
    return {
        "experiment_id": f"m4b-capability-evidence-{collection.root_seed}",
        "experiment_version": EXPERIMENT_VERSION,
        "outcome_projection_version": OUTCOME_PROJECTION_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "package_disposition": M4bPackageDisposition.COMPLETE,
        "started_at_utc": collection.started_at_utc,
        "completed_at_utc": collection.completed_at_utc,
        "git": collection.git,
        "root_seed": collection.root_seed,
        "master_seeds": collection.master_seeds,
        "session_count": len(collection.master_seeds),
        "transaction_record_count": len(collection.transaction_records),
        "evidence_record_count": len(collection.evidence_records),
        "component_registration_count": len(collection.component_registrations),
        "probe_record_count": sum(
            len(bundle.records) for bundle in collection.probe_bundles
        ),
        "independent_evaluation_count": len(collection.evaluation_reports),
        "source_sha256": {
            path: sha256_bytes(material)
            for path, material in artifacts.items()
            if path.startswith("source/")
        },
        "schema_sha256": {
            path: sha256_bytes(material)
            for path, material in artifacts.items()
            if path.startswith("contracts/")
        },
        "configuration_sha256": {
            path: sha256_bytes(artifacts[path])
            for path in ("protocol/acceptance.json", "protocol/scenarios.json")
        },
        "fixture_sha256": {
            "independent/topology-fixture.json": sha256_bytes(
                artifacts["independent/topology-fixture.json"]
            )
        },
        "deterministic_outcome_sha256": sha256_bytes(canonical_json_bytes(outcome)),
        "host": collection.host,
        "component_versions": collection.component_versions,
        "boundary": {
            "coordination": "deterministic-local-v1",
            "host_scope": "single-host-single-user",
            "independent_evaluator": "separate-process-code-path",
            "physical_scope": "pandapower-steady-state-and-python-virtual-plc",
        },
        "known_limitations": (
            "no external custody or timestamp anchor",
            "no independent sensing or independently validated physical model",
            "no segmented or multi-host deployment",
            "no HELICS OpenPLC hardware-in-the-loop or field evidence",
            "no external replication or operational-effectiveness evidence",
        ),
        "summary": summary,
    }


def finalize_m4b_package(
    *,
    output_dir: Path,
    trust_anchor_path: Path,
    artifacts: dict[str, bytes],
    manifest_fields: dict[str, Any],
    trust_anchor: M4bTrustAnchor,
    root_private_key: Ed25519PrivateKey,
) -> M4bEvidenceManifest:
    """Sign and publish a closed package plus its external public trust anchor."""

    output_dir = output_dir.absolute()
    trust_anchor_path = trust_anchor_path.absolute()
    _require_absent(output_dir, "M4b output")
    _require_absent(trust_anchor_path, "M4b trust anchor")
    if output_dir == trust_anchor_path.parent or output_dir in trust_anchor_path.parents:
        raise ValueError("the trust anchor must be outside the evidence package")
    if not output_dir.parent.is_dir() or output_dir.parent.is_symlink():
        raise ValueError("output parent must be an existing non-symlink directory")
    if not trust_anchor_path.parent.is_dir() or trust_anchor_path.parent.is_symlink():
        raise ValueError("anchor parent must be an existing non-symlink directory")

    root_raw = root_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    anchor_raw = trust_anchor.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if root_raw != anchor_raw:
        raise ValueError("root private key does not match the external trust anchor")
    descriptors = build_artifact_descriptors(artifacts)
    supplied = dict(manifest_fields)
    for reserved in (
        "artifacts",
        "root_anchor_id",
        "root_key_id",
        "root_public_key_sha256",
    ):
        supplied.pop(reserved, None)
    manifest = M4bEvidenceManifest.model_validate(
        {
            **supplied,
            "artifacts": [item.model_dump(mode="json") for item in descriptors],
            "root_anchor_id": trust_anchor.anchor_id,
            "root_key_id": trust_anchor.key_id,
            "root_public_key_sha256": trust_anchor.public_key_sha256,
        }
    )
    if manifest.started_at_utc < trust_anchor.not_before or (
        trust_anchor.not_after is not None
        and manifest.completed_at_utc > trust_anchor.not_after
    ):
        raise ValueError("manifest timestamps fall outside the anchor validity interval")
    signature = M4bManifestSignature.issue_for_manifest(
        manifest=manifest,
        signer_anchor_id=trust_anchor.anchor_id,
        signer_key_id=trust_anchor.key_id,
        private_key=root_private_key,
    )

    staging = output_dir.parent / f".{output_dir.name}.staging-{uuid4().hex}"
    anchor_staging = trust_anchor_path.parent / (
        f".{trust_anchor_path.name}.staging-{uuid4().hex}"
    )
    staging.mkdir(mode=0o700)
    for path, material in sorted(artifacts.items()):
        _safe_write(staging, path, material)
    _safe_write(staging, MANIFEST_NAME, manifest.canonical_bytes())
    _safe_write(staging, SIGNATURE_NAME, signature.canonical_bytes())
    _safe_write(anchor_staging.parent, anchor_staging.name, trust_anchor.canonical_bytes())
    for directory, _, _ in os.walk(staging, topdown=False, followlinks=False):
        _fsync_directory(Path(directory))
    _fsync_directory(staging.parent)
    _fsync_directory(anchor_staging.parent)

    verification = verify_m4b_package(staging, anchor_staging)
    if verification["package_valid"] is not True:
        raise ValueError(f"staged package failed self-verification: {verification}")
    _make_read_only(staging)
    os.chmod(anchor_staging, 0o444, follow_symlinks=False)
    _require_absent(trust_anchor_path, "M4b trust anchor")
    os.rename(anchor_staging, trust_anchor_path)
    _fsync_directory(trust_anchor_path.parent)
    _require_absent(output_dir, "M4b output")
    os.rename(staging, output_dir)
    _fsync_directory(output_dir.parent)
    return manifest


def write_m4b_experiment(
    output_dir: Path,
    *,
    trust_anchor_path: Path | None = None,
    root_seed: int = 20260825,
    seed_count: int = 30,
    progress: Any | None = None,
    require_clean_checkout: bool = True,
) -> M4bEvidenceManifest:
    """Collect the bounded experiment, then perform root-key-only finalization."""

    if trust_anchor_path is None:
        trust_anchor_path = output_dir.parent / f"{output_dir.name}.trust-anchor.json"
    _require_absent(output_dir, "M4b output")
    _require_absent(trust_anchor_path, "M4b trust anchor")
    collection = collect_m4b_experiment(
        root_seed=root_seed,
        seed_count=seed_count,
        progress=progress,
        require_clean_checkout=require_clean_checkout,
    )
    artifacts = _canonicalize_json_artifacts(collection.artifacts)
    manifest_fields = _collection_manifest_fields(collection, artifacts)
    root_private = Ed25519PrivateKey.generate()
    root_public = root_private.public_key()
    root_raw = root_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    anchor = M4bTrustAnchor(
        anchor_id="m4b-package-root-anchor",
        key_id="m4b-package-root-key",
        public_key_b64=public_key_base64(root_public),
        public_key_sha256=sha256_bytes(root_raw),
        not_before=collection.started_at_utc,
    )
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    trust_anchor_path.parent.mkdir(parents=True, exist_ok=True)
    return finalize_m4b_package(
        output_dir=output_dir,
        trust_anchor_path=trust_anchor_path,
        artifacts=artifacts,
        manifest_fields=manifest_fields,
        trust_anchor=anchor,
        root_private_key=root_private,
    )


def _listed_files(root: Path) -> set[str]:
    files: set[str] = set()
    for directory, names, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in names:
            path = base / name
            if path.is_symlink():
                raise ValueError(f"package contains a symlink directory: {path}")
        for name in filenames:
            path = base / name
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"package contains a non-regular file: {path}")
            files.add(path.relative_to(root).as_posix())
            if len(files) > MAX_ARTIFACTS + 2:
                raise ValueError("package file inventory exceeds the registered limit")
    return files


def _artifact_bytes(root: Path, descriptor: M4bArtifactDescriptor) -> bytes:
    path = root.joinpath(*descriptor.path.split("/"))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    file_descriptor = os.open(path, flags)
    try:
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"artifact is not a regular file: {descriptor.path}")
        if before.st_size > MAX_ARTIFACT_BYTES:
            raise ValueError(f"artifact exceeds size limit: {descriptor.path}")
        chunks: list[bytes] = []
        remaining = MAX_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(file_descriptor)
    finally:
        os.close(file_descriptor)
    material = b"".join(chunks)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(material) != after.st_size
    ):
        raise ValueError(f"artifact changed while being read: {descriptor.path}")
    if len(material) != descriptor.byte_length:
        raise ValueError(f"artifact length mismatch: {descriptor.path}")
    if sha256_bytes(material) != descriptor.sha256:
        raise ValueError(f"artifact hash mismatch: {descriptor.path}")
    if (
        descriptor.record_count is not None
        and len(material.splitlines()) != descriptor.record_count
    ):
        raise ValueError(f"artifact record count mismatch: {descriptor.path}")
    if descriptor.media_type != _media_type(descriptor.path):
        raise ValueError(f"artifact media type mismatch: {descriptor.path}")
    if descriptor.path.endswith(".jsonl"):
        _dict_jsonl(material, label=descriptor.path)
    elif descriptor.path.endswith(".json"):
        _canonical_json_artifact(material, label=descriptor.path)
    return material


def _require_mapping_hashes(
    manifest: M4bEvidenceManifest,
    artifacts: dict[str, bytes],
) -> None:
    for label, mapping in (
        ("source", manifest.source_sha256),
        ("schema", manifest.schema_sha256),
        ("configuration", manifest.configuration_sha256),
        ("fixture", manifest.fixture_sha256),
    ):
        expected_paths = {
            path
            for path in artifacts
            if (
                (label == "source" and path.startswith("source/"))
                or (label == "schema" and path.startswith("contracts/"))
                or (
                    label == "configuration"
                    and path in {"protocol/acceptance.json", "protocol/scenarios.json"}
                )
                or (label == "fixture" and path == "independent/topology-fixture.json")
            )
        }
        if set(mapping) != expected_paths:
            raise ValueError(f"{label} binding inventory is incomplete or excessive")
        for path, expected in mapping.items():
            material = artifacts.get(path)
            if material is None or sha256_bytes(material) != expected:
                raise ValueError(f"{label} binding mismatch: {path}")


def _health_by_session(
    records: tuple[dict[str, JsonValue], ...],
) -> dict[tuple[int, int], dict[str, dict[str, JsonValue]]]:
    grouped: dict[tuple[int, int], dict[str, dict[str, JsonValue]]] = {}
    session_ids: dict[tuple[int, int], str] = {}
    for record in records:
        if set(record) != HEALTH_FIELDS or record.get("schema_version") != (
            "m4b-component-health-bundle-v1"
        ):
            raise ValueError("component health bundle has an invalid shape")
        session_index = record.get("session_index")
        master_seed = record.get("master_seed")
        phase = record.get("phase")
        digest = record.get("bundle_sha256")
        session_id = record.get("session_id")
        captured_at = record.get("captured_at")
        health_records = record.get("records")
        if (
            isinstance(session_index, bool)
            or not isinstance(session_index, int)
            or isinstance(master_seed, bool)
            or not isinstance(master_seed, int)
            or not isinstance(phase, str)
            or not isinstance(digest, str)
            or not isinstance(session_id, str)
            or not session_id
            or not isinstance(captured_at, str)
            or not isinstance(health_records, dict)
            or set(health_records) != {"observer", "plant", "plc"}
            or any(not isinstance(value, dict) for value in health_records.values())
        ):
            raise ValueError("component health bundle fields have invalid types")
        timestamp = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("component health timestamp is not timezone-aware")
        material = {key: value for key, value in record.items() if key != "bundle_sha256"}
        if sha256_bytes(canonical_json_bytes(material)) != digest:
            raise ValueError("component health bundle digest is invalid")
        key = (session_index, master_seed)
        if session_ids.setdefault(key, session_id) != session_id:
            raise ValueError("component health session IDs diverge")
        phases = grouped.setdefault(key, {})
        if phase in phases:
            raise ValueError("duplicate component health phase")
        phases[phase] = record
    expected = {"pre_transactions", "post_nominal", "pre_replay", "post_replay"}
    if any(set(phases) != expected for phases in grouped.values()):
        raise ValueError("component health phases are incomplete")
    return grouped


def _evidence_by_session(
    wrappers: tuple[dict[str, JsonValue], ...],
) -> dict[tuple[int, int], tuple[EvidenceRecord, ...]]:
    grouped: dict[tuple[int, int], list[EvidenceRecord]] = {}
    session_ids: dict[tuple[int, int], str] = {}
    for wrapper in wrappers:
        if (
            set(wrapper) != EVIDENCE_WRAPPER_FIELDS
            or wrapper.get("schema_version") != "m4b-evidence-record-wrapper-v1"
        ):
            raise ValueError("evidence wrapper has an invalid shape")
        session_index = wrapper.get("session_index")
        master_seed = wrapper.get("master_seed")
        value = wrapper.get("record")
        session_id = wrapper.get("session_id")
        if (
            isinstance(session_index, bool)
            or not isinstance(session_index, int)
            or isinstance(master_seed, bool)
            or not isinstance(master_seed, int)
            or not isinstance(session_id, str)
            or not session_id
            or not isinstance(value, dict)
        ):
            raise ValueError("evidence wrapper fields have invalid types")
        key = (session_index, master_seed)
        if session_ids.setdefault(key, session_id) != session_id:
            raise ValueError("evidence wrapper session IDs diverge")
        grouped.setdefault(key, []).append(
            EvidenceRecord.model_validate(value)
        )
    result: dict[tuple[int, int], tuple[EvidenceRecord, ...]] = {}
    global_hashes: set[str] = set()
    for key, records in grouped.items():
        previous_hash = "0" * 64
        for sequence, record in enumerate(records):
            material = {
                "sequence": record.sequence,
                "recorded_at": record.recorded_at.isoformat(),
                "proposal_id": record.proposal_id,
                "decision_id": record.decision_id,
                "previous_hash": record.previous_hash,
                "payload": record.payload,
            }
            expected_hash = hashlib.sha256(
                json.dumps(
                    material,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode()
            ).hexdigest()
            if (
                record.sequence != sequence
                or record.previous_hash != previous_hash
                or record.record_hash != expected_hash
                or record.record_hash in global_hashes
            ):
                raise ValueError("evidence hash chain is invalid")
            previous_hash = record.record_hash
            global_hashes.add(record.record_hash)
        result[key] = tuple(records)
    return result


def _registration_groups(
    registrations: tuple[M4bComponentRegistration, ...],
) -> dict[tuple[int, int], tuple[M4bComponentRegistration, ...]]:
    grouped: dict[tuple[int, int], list[M4bComponentRegistration]] = {}
    for item in registrations:
        grouped.setdefault((item.session_index, item.master_seed), []).append(item)
    result = {key: tuple(values) for key, values in grouped.items()}
    expected_roles = (*RUNTIME_ROLES, M4bComponentRole.INDEPENDENT_EVALUATOR)
    if any(tuple(item.role for item in values) != expected_roles for values in result.values()):
        raise ValueError("component registration roles are incomplete or reordered")
    for values in result.values():
        boots = [item.boot_epoch for item in values]
        if len(set(boots)) != len(boots):
            raise ValueError("component boot epochs are not distinct")
        runtime_pids = [item.pid for item in values[:5]]
        if len(set(runtime_pids)) != len(runtime_pids):
            raise ValueError("simultaneous runtime component PIDs are not distinct")
        keyed = [item for item in values if item.public_key_b64 is not None]
        if len({item.public_key_b64 for item in keyed}) != len(keyed):
            raise ValueError("component signing keys are not distinct")
    return result


def _verify_transaction_signatures(
    transaction: M4bTransactionRecord,
    registrations: tuple[M4bComponentRegistration, ...],
) -> None:
    observer, plc, permit_signer = registrations[1], registrations[2], registrations[3]
    if (
        observer.public_key_b64 is None
        or plc.public_key_b64 is None
        or permit_signer.public_key_b64 is None
    ):
        raise ValueError("required transaction verification key is missing")
    observer_key = public_key_from_base64(observer.public_key_b64)
    result = transaction.result
    for observation in (
        result.pre_observation,
        result.post_observation,
        result.last_observation,
    ):
        if observation is not None and (
            observation.observer_key_id != observer.key_id
            or observation.observer_boot_epoch != observer.boot_epoch
            or not observation.verify(observer_key)
        ):
            raise ValueError("transaction observation signature or identity is invalid")
    if result.pre_observation is not None and (
        result.request.observation_id != result.pre_observation.observation_id
        or result.request.observation_envelope_digest
        != result.pre_observation.envelope_digest
        or result.request.observation_challenge_nonce
        != result.pre_observation.challenge_nonce
        or result.request.correlation_id != result.pre_observation.correlation_id
    ):
        raise ValueError("transaction request-to-observation binding is invalid")
    if result.permit is not None and (
        result.permit.signing_key_id != permit_signer.key_id
        or not result.permit.verify(public_key_from_base64(permit_signer.public_key_b64))
    ):
        raise ValueError("transaction permit signature or identity is invalid")
    if result.acknowledgment is not None:
        if result.permit is None or result.pre_observation is None or result.decision is None:
            raise ValueError("acknowledged transaction is missing verification inputs")
        if not result.acknowledgment.verify_for_transaction(
            public_key_from_base64(plc.public_key_b64),
            request=result.request,
            permit=result.permit,
            pre_observation=result.pre_observation,
            expected_plc_id=plc.component_id,
            expected_plc_key_id=plc.key_id or "",
            expected_plc_boot_epoch=plc.boot_epoch,
        ):
            raise ValueError("transaction acknowledgment signature or binding is invalid")


def _transaction_evidence_payload(transaction: M4bTransactionRecord) -> dict[str, Any]:
    result = transaction.result
    return {
        "event_type": "capability_closed_loop_disposition",
        "coordination_backend": result.coordination_backend,
        "status": result.status.value,
        "reasons": list(result.reasons),
        "dispatch_attempts": result.dispatch_attempts,
        "automatic_retry_count": result.automatic_retry_count,
        "request": result.request.model_dump(mode="json"),
        "pre_observation": (
            result.pre_observation.model_dump(mode="json")
            if result.pre_observation is not None
            else None
        ),
        "decision": result.decision.model_dump(mode="json") if result.decision else None,
        "command": result.command.model_dump(mode="json") if result.command else None,
        "assessment": (
            result.assessment.model_dump(mode="json") if result.assessment else None
        ),
        "permit": result.permit.model_dump(mode="json") if result.permit else None,
        "acknowledgment": (
            result.acknowledgment.model_dump(mode="json")
            if result.acknowledgment
            else None
        ),
        "post_observation": (
            result.post_observation.model_dump(mode="json")
            if result.post_observation
            else None
        ),
        "last_observation": (
            result.last_observation.model_dump(mode="json")
            if result.last_observation
            else None
        ),
    }


def _independent_source_digest(artifacts: dict[str, bytes]) -> str:
    prefix = "source/src/aegis_ot_independent/"
    paths = sorted(
        path for path in artifacts if path.startswith(prefix) and path.endswith(".py")
    )
    if not paths:
        raise ValueError("independent evaluator source snapshot is absent")
    material = bytearray()
    for path in paths:
        material.extend(PurePosixPath(path).name.encode("utf-8"))
        material.extend(b"\0")
        material.extend(artifacts[path])
        material.extend(b"\0")
    return sha256_bytes(bytes(material))


def _comparison_values(report: IndependentConsequenceReport) -> dict[str, tuple[str, str]]:
    if report.predicted_values is None or report.observed_values is None:
        return {}
    predicted = report.predicted_values.model_dump(mode="json")
    observed = report.observed_values.model_dump(mode="json")
    values: dict[str, tuple[str, str]] = {}
    for metric in IndependentMetricName:
        name = metric.value
        if metric is IndependentMetricName.ISOLATED_RESOURCES:
            values[name] = (
                json.dumps(predicted[name], separators=(",", ":")),
                json.dumps(observed[name], separators=(",", ":")),
            )
        else:
            values[name] = (str(predicted[name]), str(observed[name]))
    return values


def _verify_semantics(manifest: M4bEvidenceManifest, artifacts: dict[str, bytes]) -> bool:
    transactions = cast(
        tuple[M4bTransactionRecord, ...],
        _jsonl(
            artifacts["transactions/results.jsonl"],
            M4bTransactionRecord,
            label="transaction records",
        ),
    )
    registrations = cast(
        tuple[M4bComponentRegistration, ...],
        _jsonl(
            artifacts["sessions/component-registrations.jsonl"],
            M4bComponentRegistration,
            label="component registrations",
        ),
    )
    probes = cast(
        tuple[M4bCapabilityProbeBundle, ...],
        _jsonl(
            artifacts["topology/capability-probes.jsonl"],
            M4bCapabilityProbeBundle,
            label="capability probes",
        ),
    )
    replays = cast(
        tuple[M4bOrderlyRestartReplayRecord, ...],
        _jsonl(
            artifacts["lifecycle/orderly-restart-replay.jsonl"],
            M4bOrderlyRestartReplayRecord,
            label="restart replays",
        ),
    )
    requests = cast(
        tuple[IndependentEvaluationRequest, ...],
        _jsonl(
            artifacts["independent/requests.jsonl"],
            IndependentEvaluationRequest,
            label="independent requests",
        ),
    )
    reports = cast(
        tuple[IndependentConsequenceReport, ...],
        _jsonl(
            artifacts["independent/evaluations.jsonl"],
            IndependentConsequenceReport,
            label="independent reports",
        ),
    )
    evidence = _dict_jsonl(
        artifacts["transactions/evidence-records.jsonl"],
        label="evidence records",
    )
    health = _dict_jsonl(
        artifacts["sessions/component-health.jsonl"],
        label="component health",
    )
    if len(transactions) != manifest.transaction_record_count:
        raise ValueError("transaction count differs from manifest")
    if len(evidence) != manifest.evidence_record_count:
        raise ValueError("evidence count differs from manifest")
    if len(registrations) != manifest.component_registration_count:
        raise ValueError("registration count differs from manifest")
    if sum(len(item.records) for item in probes) != manifest.probe_record_count:
        raise ValueError("probe count differs from manifest")
    if len(reports) != manifest.independent_evaluation_count or len(requests) != len(reports):
        raise ValueError("independent evaluation count differs from manifest")
    if len(replays) != manifest.session_count or len(probes) != manifest.session_count:
        raise ValueError("session-level artifact counts differ from manifest")
    if len(health) != manifest.session_count * 4:
        raise ValueError("health bundle count differs from session count")
    experiment_accepted = all(
        record.matched_expectation for bundle in probes for record in bundle.records
    ) and all(
        item.replay_state_unchanged
        and item.replay_acknowledgment.reason == "transaction_replayed"
        for item in replays
    )

    expected_sessions = tuple(enumerate(manifest.master_seeds))
    expected_session_keys = set(expected_sessions)
    health_groups = _health_by_session(health)
    evidence_groups = _evidence_by_session(evidence)
    registration_groups = _registration_groups(registrations)
    if (
        set(health_groups) != expected_session_keys
        or set(evidence_groups) != expected_session_keys
        or set(registration_groups) != expected_session_keys
    ):
        raise ValueError("session identities differ across retained artifacts")

    transactions_by_key: dict[tuple[int, int], list[M4bTransactionRecord]] = {}
    for transaction in transactions:
        transactions_by_key.setdefault(
            (transaction.session_index, transaction.master_seed), []
        ).append(transaction)
    if set(transactions_by_key) != expected_session_keys:
        raise ValueError("transaction session identities differ from manifest")
    for key in expected_sessions:
        session_transactions = transactions_by_key[key]
        if tuple(
            (item.condition, item.expected_terminal_status) for item in session_transactions
        ) != EXPECTED_CONDITIONS:
            raise ValueError("registered transaction order or terminal status differs")
        session_registrations = registration_groups[key]
        registration_digest = sha256_bytes(
            canonical_json_bytes(
                [item.model_dump(mode="json") for item in session_registrations[:5]]
            )
        )
        session_health = health_groups[key]
        unknown_identity, stale_observation, nominal = session_transactions
        nominal_post = nominal.result.post_observation
        post_nominal_plant = cast(
            dict[str, JsonValue],
            cast(dict[str, Any], session_health["post_nominal"]["records"])["plant"],
        )
        experiment_accepted = experiment_accepted and (
            unknown_identity.result.status
            is CapabilityClosedLoopStatus.NOT_DISPATCHED
            and "identity_not_verified" in unknown_identity.result.reasons
            and unknown_identity.result.dispatch_attempts == 0
            and stale_observation.result.status
            is CapabilityClosedLoopStatus.NOT_DISPATCHED
            and "observation_stale" in stale_observation.result.reasons
            and stale_observation.result.dispatch_attempts == 0
            and nominal.result.status is CapabilityClosedLoopStatus.COMPLETED
            and nominal.result.dispatch_attempts == 1
            and nominal.result.automatic_retry_count == 0
            and nominal_post is not None
            and nominal_post.snapshot.isolated_resources == ("feeder-1",)
            and type(post_nominal_plant.get("commit_count")) is int
            and post_nominal_plant["commit_count"] == 1
            and type(post_nominal_plant.get("apply_requests")) is int
            and post_nominal_plant["apply_requests"] == 1
            and type(post_nominal_plant.get("state_version")) is int
            and post_nominal_plant["state_version"] == 1
        )
        pre_health_digest = sha256_bytes(
            canonical_json_bytes(session_health["pre_transactions"])
        )
        post_health_digest = sha256_bytes(
            canonical_json_bytes(session_health["post_nominal"])
        )
        session_evidence = evidence_groups[key]
        next_sequence = 0
        for transaction in session_transactions:
            if (
                transaction.component_registration_sha256 != registration_digest
                or transaction.pre_health_sha256 != pre_health_digest
                or transaction.post_health_sha256 != post_health_digest
            ):
                raise ValueError("transaction package-level binding is invalid")
            if (
                transaction.evidence_first_sequence != next_sequence
                or transaction.evidence_last_sequence >= len(session_evidence)
            ):
                raise ValueError("transaction evidence range is invalid")
            terminal = session_evidence[transaction.evidence_last_sequence]
            if (
                terminal.record_hash != transaction.evidence_chain_head
                or terminal.record_hash != transaction.result.execution_evidence_hash
                or terminal.payload != _transaction_evidence_payload(transaction)
                or terminal.proposal_id
                != transaction.result.request.proposal.proposal_id
            ):
                raise ValueError("transaction terminal evidence binding is invalid")
            next_sequence = transaction.evidence_last_sequence + 1
            _verify_transaction_signatures(transaction, session_registrations)
        if next_sequence != len(session_evidence):
            raise ValueError("session contains unassigned evidence records")

    probes_by_session = {item.session_id: item for item in probes}
    replays_by_session = {item.session_id: item for item in replays}
    if len(probes_by_session) != len(probes) or len(replays_by_session) != len(replays):
        raise ValueError("duplicate session-level probe or replay record")
    for key in expected_sessions:
        session_transactions = transactions_by_key[key]
        session_id = session_transactions[0].session_id
        if any(item.session_id != session_id for item in session_transactions):
            raise ValueError("transaction session IDs are inconsistent")
        probe = probes_by_session.get(session_id)
        replay = replays_by_session.get(session_id)
        if probe is None or replay is None:
            raise ValueError("session lacks its probe or replay record")
        if tuple((item.endpoint_role, item.operation) for item in probe.records) != EXPECTED_PROBES:
            raise ValueError("capability-probe profile differs from registration")
        nominal = session_transactions[-1]
        nominal_result = nominal.result
        replacement = registration_groups[key][4]
        observer = registration_groups[key][1]
        if replacement.public_key_b64 is None or observer.public_key_b64 is None:
            raise ValueError("replay verification key is missing")
        if (
            replay.original_transaction_sha256 != nominal.digest
            or nominal_result.permit is None
            or nominal_result.pre_observation is None
            or nominal_result.decision is None
        ):
            raise ValueError("replay does not bind the nominal transaction")
        if not replay.replay_acknowledgment.verify_for_transaction(
            public_key_from_base64(replacement.public_key_b64),
            request=nominal_result.request,
            permit=nominal_result.permit,
            pre_observation=nominal_result.pre_observation,
            expected_plc_id=replacement.component_id,
            expected_plc_key_id=replacement.key_id or "",
            expected_plc_boot_epoch=replacement.boot_epoch,
        ):
            raise ValueError("replacement PLC replay acknowledgment is invalid")
        if not replay.post_replay_observation.verify(
            public_key_from_base64(observer.public_key_b64)
        ):
            raise ValueError("post-replay observation signature is invalid")
        phases = health_groups[key]
        if (
            replay.before_plant_health_sha256
            != canonical_digest(cast(dict[str, Any], phases["pre_replay"]["records"])["plant"])
            or replay.after_plant_health_sha256
            != canonical_digest(cast(dict[str, Any], phases["post_replay"]["records"])["plant"])
        ):
            raise ValueError("replay health binding is invalid")
        pre_plant = cast(dict[str, Any], phases["pre_replay"]["records"])["plant"]
        post_plant = cast(dict[str, Any], phases["post_replay"]["records"])["plant"]
        invariant_fields = ("state_version", "state_digest", "apply_requests", "commit_count")
        if any(
            field not in pre_plant
            or field not in post_plant
            or pre_plant[field] != post_plant[field]
            for field in invariant_fields
        ):
            raise ValueError("replay plant-health invariants changed")
        if (
            replay.replay_acknowledgment.pre_state_digest != pre_plant["state_digest"]
            or replay.post_replay_observation.snapshot.state_digest
            != post_plant["state_digest"]
        ):
            raise ValueError("replay signed state differs from retained plant health")

    transaction_by_session = {
        (item.session_index, item.master_seed, item.condition): item for item in transactions
    }
    if len(transaction_by_session) != len(transactions):
        raise ValueError("duplicate transaction identity")
    request_by_session = {(item.session_index, item.master_seed): item for item in requests}
    report_by_request = {item.request_id: item for item in reports}
    if len(request_by_session) != len(requests) or len(report_by_request) != len(reports):
        raise ValueError("duplicate independent evaluation identity")
    if set(request_by_session) != expected_session_keys:
        raise ValueError("independent requests differ from manifest sessions")
    fixture = _strict_json(
        artifacts["independent/topology-fixture.json"],
        label="independent topology fixture",
    )
    if not isinstance(fixture, dict):
        raise ValueError("independent topology fixture must be an object")
    fixture_digest = fixture.get("fixture_digest")
    fixture_material = {key: value for key, value in fixture.items() if key != "fixture_digest"}
    if (
        not isinstance(fixture_digest, str)
        or sha256_bytes(canonical_json_bytes(fixture_material)) != fixture_digest
    ):
        raise ValueError("independent topology fixture digest is invalid")
    evaluator_source_digest = _independent_source_digest(artifacts)
    for request in requests:
        independent_nominal = transaction_by_session.get(
            (request.session_index, request.master_seed, "nominal_permitted_execution")
        )
        report = report_by_request.get(request.request_id)
        if independent_nominal is None or report is None:
            raise ValueError("independent evaluation lacks its nominal transaction")
        if (
            request.transaction_record_digest
            != independent_nominal.evaluation_binding_sha256
        ):
            raise ValueError("independent request transaction binding mismatch")
        if (
            request.fixture_id != fixture.get("fixture_id")
            or request.fixture_digest != fixture_digest
        ):
            raise ValueError("independent request fixture binding mismatch")
        if not request.verify_observation_signatures():
            raise ValueError("independent request observation signature is invalid")
        nominal_result = independent_nominal.result
        if (
            request.pre_observation != nominal_result.pre_observation
            or request.post_observation != nominal_result.post_observation
            or request.command != nominal_result.command
        ):
            raise ValueError("independent request differs from nominal observer inputs")
        if not report.verify_for_request(request):
            raise ValueError("independent report signature or request binding is invalid")
        experiment_accepted = (
            experiment_accepted and report.status is IndependentEvaluationStatus.AGREE
        )
        if (
            independent_nominal.independent_report_id != report.report_id
            or independent_nominal.independent_report_sha256 != report.digest
        ):
            raise ValueError("nominal transaction report binding mismatch")
        evaluator = registration_groups[(request.session_index, request.master_seed)][5]
        if (
            evaluator.component_id != report.evaluator_id
            or evaluator.pid != report.pid
            or evaluator.boot_epoch != report.boot_epoch
            or evaluator.key_id != report.key_id
            or evaluator.public_key_b64 != report.public_key_b64
            or report.evaluator_source_sha256 != evaluator_source_digest
        ):
            raise ValueError("independent evaluator registration differs from its report")
        observer = registration_groups[(request.session_index, request.master_seed)][1]
        if (
            request.observer_key_id != observer.key_id
            or request.observer_public_key_b64 != observer.public_key_b64
        ):
            raise ValueError("independent request observer identity is invalid")
        comparisons = {item.metric.value: item for item in report.metric_comparisons}
        request_wire = request.model_dump(mode="json")
        for metric, (predicted, observed) in _comparison_values(report).items():
            comparison = comparisons.get(metric)
            expected_tolerance = (
                "exact"
                if metric == IndependentMetricName.ISOLATED_RESOURCES.value
                else (
                    str(request_wire["absolute_tolerance_pct"])
                    if metric.endswith("_pct")
                    else str(request_wire["absolute_tolerance_mw"])
                )
            )
            if (
                comparison is None
                or comparison.expected != predicted
                or comparison.observed != observed
                or comparison.tolerance != expected_tolerance
            ):
                raise ValueError("independent comparison is not bound to report values")

    projection = _outcome_projection(
        root_seed=manifest.root_seed,
        master_seeds=manifest.master_seeds,
        transactions=transactions,
        probes=probes,
        replays=replays,
        reports=reports,
    )
    if sha256_bytes(canonical_json_bytes(projection)) != manifest.deterministic_outcome_sha256:
        raise ValueError("deterministic outcome projection mismatch")
    summary = _canonical_json_artifact(artifacts["summary.json"], label="summary")
    if summary != manifest.summary:
        raise ValueError("summary artifact differs from manifest summary")
    recomputed_summary: dict[str, Any] = {
        "schema_version": "m4b-summary-v1",
        "session_count": manifest.session_count,
        "transaction_record_count": len(transactions),
        "evidence_record_count": len(evidence),
        "component_registration_count": len(registrations),
        "probe_record_count": sum(len(item.records) for item in probes),
        "independent_evaluation_count": len(reports),
        "terminal_status_counts": {
            status.value: sum(item.result.status is status for item in transactions)
            for status in CapabilityClosedLoopStatus
        },
        "capability_probe_match_count": sum(
            record.matched_expectation for bundle in probes for record in bundle.records
        ),
        "independent_status_counts": {
            status.value: sum(report.status is status for report in reports)
            for status in IndependentEvaluationStatus
        },
        "orderly_restart_replay_rejection_count": sum(
            item.replay_acknowledgment.reason == "transaction_replayed" for item in replays
        ),
        "orderly_restart_replay_unchanged_count": sum(
            item.replay_state_unchanged for item in replays
        ),
        "experiment_criteria_met": experiment_accepted,
    }
    if summary != recomputed_summary:
        raise ValueError("summary differs from retained semantic records")
    return experiment_accepted


def _read_regular_path(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise ValueError(f"{label} is non-regular or oversized")
        material = bytearray()
        while len(material) <= maximum_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - len(material)))
            if not chunk:
                break
            material.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(material) != after.st_size
        or len(material) > maximum_bytes
    ):
        raise ValueError(f"{label} changed while being read")
    return bytes(material)


def _checkout_path(package_path: str) -> str | None:
    if package_path.startswith("source/"):
        return package_path.removeprefix("source/")
    if package_path.startswith("contracts/"):
        return f"schemas/{package_path.removeprefix('contracts/')}"
    if package_path == "independent/topology-fixture.json":
        return "fixtures/m4b/cigre-mv-topology-v1.json"
    return None


def _checkout_matches(
    manifest: M4bEvidenceManifest,
    checkout_root: Path,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    bound: dict[str, str] = {}
    for mapping in (
        manifest.source_sha256,
        manifest.schema_sha256,
        manifest.configuration_sha256,
        manifest.fixture_sha256,
    ):
        bound.update(mapping)
    checked = 0
    for package_path, expected in sorted(bound.items()):
        relative = _checkout_path(package_path)
        if relative is None:
            continue
        checked += 1
        try:
            material = _read_regular_path(
                checkout_root / PurePosixPath(relative),
                label=relative,
                maximum_bytes=MAX_ARTIFACT_BYTES,
            )
            if package_path.endswith(".json"):
                value = _strict_json(material, label=relative)
                material = canonical_json_bytes(value) + b"\n"
            if sha256_bytes(material) != expected:
                errors.append(f"checkout digest mismatch: {relative}")
        except (OSError, ValueError, UnicodeError) as exc:
            errors.append(f"checkout file cannot be verified: {relative}: {exc}")
    if checked == 0:
        errors.append("manifest contains no registered checkout bindings")
    return not errors, errors


def _invalid_result(
    message: str,
    *,
    checkout_evaluated: bool,
) -> dict[str, JsonValue]:
    return {
        "valid": False,
        "root_trusted": False,
        "package_valid": False,
        "experiment_accepted": False,
        "checkout_matches": False,
        "checkout_evaluated": checkout_evaluated,
        "errors": [message],
        "acceptance_errors": [],
        "checkout_errors": [],
        "checks": {"defensive_boundary": False},
        "claim_boundary": (
            "signed local simulated-OT evidence; not external custody, independent "
            "replication, physical validation, deployment, or WP4 completion"
        ),
    }


def verify_m4b_package(
    package_dir: Path,
    trust_anchor_path: Path,
    checkout_root: Path | None = None,
) -> dict[str, JsonValue]:
    """Verify trust, package semantics, acceptance, and checkout match offline."""

    errors: list[str] = []
    acceptance_errors: list[str] = []
    checks: dict[str, bool] = {}
    package_dir = package_dir.absolute()
    trust_anchor_path = trust_anchor_path.absolute()
    checkout_evaluated = checkout_root is not None
    if package_dir.is_symlink() or not package_dir.is_dir():
        return _invalid_result(
            "package path is not a regular directory",
            checkout_evaluated=checkout_evaluated,
        )
    if package_dir == trust_anchor_path.parent or package_dir in trust_anchor_path.parents:
        return _invalid_result(
            "trust anchor is inside the evidence package",
            checkout_evaluated=checkout_evaluated,
        )

    manifest: M4bEvidenceManifest | None = None
    signature: M4bManifestSignature | None = None
    anchor: M4bTrustAnchor | None = None
    manifest_bytes = b""
    try:
        manifest_bytes = _read_regular_path(
            package_dir / MANIFEST_NAME,
            label="manifest",
            maximum_bytes=MAX_MANIFEST_BYTES,
        )
        manifest_value = _strict_json(manifest_bytes, label="manifest")
        manifest = M4bEvidenceManifest.model_validate(manifest_value)
        if manifest.canonical_bytes() != manifest_bytes:
            raise ValueError("manifest is not exact canonical JSON")
        checks["manifest"] = True
    except (OSError, ValueError, ValidationError, UnicodeError) as exc:
        errors.append(f"manifest: {exc}")
        checks["manifest"] = False
    try:
        signature_bytes = _read_regular_path(
            package_dir / SIGNATURE_NAME,
            label="manifest signature",
            maximum_bytes=MAX_MANIFEST_BYTES,
        )
        signature_value = _strict_json(signature_bytes, label="manifest signature")
        signature = M4bManifestSignature.model_validate(signature_value)
        if signature.canonical_bytes() != signature_bytes:
            raise ValueError("manifest signature is not exact canonical JSON")
        checks["manifest_signature"] = True
    except (OSError, ValueError, ValidationError, UnicodeError) as exc:
        errors.append(f"manifest_signature: {exc}")
        checks["manifest_signature"] = False
    try:
        anchor_bytes = _read_regular_path(
            trust_anchor_path,
            label="external trust anchor",
            maximum_bytes=MAX_MANIFEST_BYTES,
        )
        anchor_value = _strict_json(anchor_bytes, label="external trust anchor")
        anchor = M4bTrustAnchor.model_validate(anchor_value)
        if anchor.canonical_bytes() != anchor_bytes:
            raise ValueError("external trust anchor is not exact canonical JSON")
        checks["trust_anchor"] = True
    except (OSError, ValueError, ValidationError, UnicodeError) as exc:
        errors.append(f"trust_anchor: {exc}")
        checks["trust_anchor"] = False

    root_trusted = False
    if manifest is not None and signature is not None and anchor is not None:
        root_trusted = all(
            (
                manifest.root_anchor_id == anchor.anchor_id,
                manifest.root_key_id == anchor.key_id,
                manifest.root_public_key_sha256 == anchor.public_key_sha256,
                signature.signer_anchor_id == anchor.anchor_id,
                signature.signer_key_id == anchor.key_id,
                manifest.started_at_utc >= anchor.not_before,
                anchor.not_after is None or manifest.completed_at_utc <= anchor.not_after,
                signature.verify(manifest_bytes, anchor.public_key),
            )
        )
        if not root_trusted:
            errors.append("root_signature: detached signature or anchor binding is invalid")
    checks["root_signature"] = root_trusted

    artifacts: dict[str, bytes] = {}
    semantic_acceptance = False
    if manifest is not None:
        descriptors = {item.path: item for item in manifest.artifacts}
        expected_files = set(descriptors) | {MANIFEST_NAME, SIGNATURE_NAME}
        try:
            listed = _listed_files(package_dir)
            if listed != expected_files:
                raise ValueError("package file inventory differs from the signed manifest")
            if len(descriptors) > MAX_ARTIFACTS:
                raise ValueError("artifact inventory exceeds the registered limit")
            if not CORE_ARTIFACT_PATHS <= set(descriptors):
                raise ValueError("required M4b artifacts are missing")
            if any(not _artifact_path_allowed(path) for path in descriptors):
                raise ValueError("manifest contains an unregistered artifact path")
            if sum(item.byte_length for item in manifest.artifacts) > MAX_PACKAGE_BYTES:
                raise ValueError("declared package size exceeds the registered limit")
            for path, descriptor in descriptors.items():
                artifacts[path] = _artifact_bytes(package_dir, descriptor)
            checks["artifact_integrity"] = True
        except (OSError, ValueError, ValidationError, UnicodeError) as exc:
            errors.append(f"artifact_integrity: {exc}")
            checks["artifact_integrity"] = False
        if len(artifacts) == len(descriptors):
            try:
                _require_mapping_hashes(manifest, artifacts)
                checks["manifest_bindings"] = True
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"manifest_bindings: {exc}")
                checks["manifest_bindings"] = False
            try:
                semantic_acceptance = _verify_semantics(manifest, artifacts)
                checks["experiment_semantics"] = True
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
                errors.append(f"experiment_semantics: {exc}")
                checks["experiment_semantics"] = False

        git = manifest.git
        commit = git.get("commit")
        branch = git.get("branch")
        if set(git) != {
            "commit",
            "branch",
            "working_tree_dirty_at_start",
            "working_tree_dirty_at_end",
        }:
            acceptance_errors.append("Git provenance has missing or unknown fields")
        if (
            not isinstance(commit, str)
            or len(commit) != 40
            or any(character not in "0123456789abcdef" for character in commit)
            or not isinstance(branch, str)
            or not branch
        ):
            acceptance_errors.append("Git commit or branch provenance is invalid")
        if git.get("working_tree_dirty_at_start") is not False:
            acceptance_errors.append("working tree was dirty at experiment start")
        if git.get("working_tree_dirty_at_end") is not False:
            acceptance_errors.append("working tree was dirty at experiment completion")
        if manifest.package_disposition is not M4bPackageDisposition.COMPLETE:
            acceptance_errors.append("package disposition is not complete")
        if not semantic_acceptance:
            acceptance_errors.append("registered experiment acceptance criteria were not met")

    checkout_matches = False
    checkout_errors: list[str] = []
    if checkout_root is not None and manifest is not None:
        checkout_matches, checkout_errors = _checkout_matches(
            manifest,
            checkout_root.absolute(),
        )

    package_valid = root_trusted and not errors and all(checks.values())
    experiment_accepted = package_valid and not acceptance_errors
    return {
        "valid": package_valid,
        "root_trusted": root_trusted,
        "package_valid": package_valid,
        "experiment_accepted": experiment_accepted,
        "checkout_matches": checkout_matches,
        "checkout_evaluated": checkout_evaluated,
        "errors": cast(JsonValue, errors),
        "acceptance_errors": cast(JsonValue, acceptance_errors),
        "checkout_errors": cast(JsonValue, checkout_errors),
        "checks": cast(JsonValue, checks),
        "package_id": (
            signature.package_id if isinstance(signature, M4bManifestSignature) else None
        ),
        "deterministic_outcome_sha256": (
            manifest.deterministic_outcome_sha256 if manifest is not None else None
        ),
        "session_count": manifest.session_count if manifest is not None else 0,
        "transaction_record_count": (
            manifest.transaction_record_count if manifest is not None else 0
        ),
        "claim_boundary": (
            "signed local simulated-OT evidence with a separately implemented topology "
            "consequence check; not external custody, independent replication, physical "
            "validation, deployment, or WP4 completion"
        ),
    }
