"""Retain and offline-verify M8 v2 evidence-backed traceability.

Campaign acceptance is limited to package integrity, exact repository bindings,
and open-state traceability semantics.  It does not approve the proposed
requirements baseline, accept any requirement, close any TBR, establish
independent validation, complete G7, authorize deployment, or establish
operational effectiveness.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import stat
import sys
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, cast

import aegis_ot.m8_evidence_traceability as m8v2

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_PATH = m8v2.AUTHORITATIVE_REQUIREMENTS_PATH
MAPPING_PATH = m8v2.AUTHORITATIVE_MAPPING_PATH
REPORT_SCHEMA = "aegis-ot-m8-evidence-traceability-campaign-v2"
PLAN_SCHEMA = "aegis-ot-m8-evidence-traceability-plan-v2"
SEMANTIC_SCHEMA = "aegis-ot-m8-evidence-traceability-semantic-v2"
CAMPAIGN_ID = "m8-evidence-backed-bidirectional-traceability-v2"
OUTPUT_PREFIX = "aegis-ot-m8-evidence-traceability-"
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024

SOURCE_PATHS = (
    REQUIREMENTS_PATH,
    MAPPING_PATH,
    "pyproject.toml",
    "requirements.lock",
    "scripts/run_m8_evidence_traceability.py",
    "src/aegis_ot/m8_evidence_traceability.py",
    "src/aegis_ot/m8_traceability.py",
)

GATE_NAMES = (
    "exact_clean_committed_source_bound",
    "explicit_unapproved_mapping_ingested",
    "every_referenced_artifact_exactly_git_bound",
    "forward_and_inverse_indexes_retained",
    "all_223_requirements_remain_open",
    "all_35_tbrs_remain_open",
    "zero_requirements_accepted",
    "no_external_attestation_fabricated",
    "independent_validation_remains_external",
    "qualification_deployment_effectiveness_remain_external",
)

ACCEPTANCE_SCOPE = (
    "Acceptance means only that the retained M8 v2 traceability package rebuilds from "
    "the exact clean committed source, ingests the explicit unapproved evidence map, "
    "binds every referenced repository file to an exact regular-file blob and SHA-256 "
    "digest, retains consistent forward and inverse indexes, and preserves all 223 "
    "requirements and 35 TBRs as open. It is not baseline approval, requirement "
    "acceptance, TBR closure, independent validation, G7 completion, qualification, "
    "authorization, deployment, production readiness, or operational-effectiveness "
    "evidence."
)

EVIDENCE_LIMITS = (
    "Only explicitly mapped local artifacts populate evidence fields; unmapped fields remain open.",
    "A repository mapping is not proof that the mapped requirement is completely implemented.",
    "The committed map is reviewed within implementation custody and is explicitly unapproved.",
    "No external attestation is included in this campaign.",
    (
        "The Ed25519 verifier interface validates configured trust, signature, freshness, "
        "and exact bindings but never automatically accepts a requirement."
    ),
    (
        "Independent validation, G7 qualification and authorization, deployment, and "
        "operational effectiveness remain external."
    ),
)


class CampaignError(RuntimeError):
    """Raised when the M8 v2 retained package cannot be trusted."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CampaignError("campaign material is not canonical finite JSON") from exc


def _sha256_json(value: object) -> str:
    return m8v2.sha256_bytes(_canonical_bytes(value))


def _source_fingerprint_material(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "git_commit": binding["git_commit"],
        "git_tree": binding["git_tree"],
        "source_files": binding["source_files"],
    }


def _source_binding(root: Path = ROOT) -> dict[str, Any]:
    try:
        root = m8v2.canonical_repository_root(root)
        m8v2.require_clean_checkout(root)
        commit, tree = m8v2.resolve_commit(root)
        files = [m8v2.bind_committed_file(root, commit, path).as_dict() for path in SOURCE_PATHS]
    except m8v2.TraceabilityError as exc:
        raise CampaignError(str(exc)) from exc
    binding: dict[str, Any] = {
        "git_commit": commit,
        "git_tree": tree,
        "clean_checkout": True,
        "source_files": files,
    }
    binding["source_fingerprint_sha256"] = _sha256_json(
        _source_fingerprint_material(binding)
    )
    return binding


def _assert_exact_source() -> dict[str, Any]:
    expected = (ROOT / "src/aegis_ot/m8_evidence_traceability.py").resolve()
    imported = Path(m8v2.__file__ or "").resolve()
    if imported != expected:
        raise CampaignError(f"M8 v2 imported from stale source: {imported}")
    return _source_binding()


def _validate_binding(binding: Mapping[str, Any]) -> None:
    if set(binding) != {
        "git_commit",
        "git_tree",
        "clean_checkout",
        "source_files",
        "source_fingerprint_sha256",
    }:
        raise CampaignError("source-binding fields are not exact")
    if binding.get("clean_checkout") is not True:
        raise CampaignError("source binding is not an exact clean checkout")
    for field in ("git_commit", "git_tree"):
        value = binding.get(field)
        if not isinstance(value, str) or not m8v2.GIT_OBJECT_RE.fullmatch(value):
            raise CampaignError(f"source-binding {field} is noncanonical")
    files = binding.get("source_files")
    if not isinstance(files, list) or len(files) != len(SOURCE_PATHS):
        raise CampaignError("source binding does not retain the exact source path set")
    paths: list[str] = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "bytes",
            "sha256",
            "git_mode",
            "git_blob",
        }:
            raise CampaignError("source-file binding fields are not exact")
        path = item.get("path")
        paths.append(path if isinstance(path, str) else "")
        if (
            type(item.get("bytes")) is not int
            or item["bytes"] <= 0
            or not isinstance(item.get("sha256"), str)
            or not m8v2.SHA256_RE.fullmatch(item["sha256"])
            or item.get("git_mode") not in {"100644", "100755"}
            or not isinstance(item.get("git_blob"), str)
            or not m8v2.GIT_OBJECT_RE.fullmatch(item["git_blob"])
        ):
            raise CampaignError("source-file binding is noncanonical")
    if paths != list(SOURCE_PATHS):
        raise CampaignError("source binding does not retain the exact source path order")
    if binding.get("source_fingerprint_sha256") != _sha256_json(
        _source_fingerprint_material(binding)
    ):
        raise CampaignError("source-binding fingerprint is invalid")


def _validate_exact_source_binding(binding: Mapping[str, Any], root: Path) -> None:
    _validate_binding(binding)
    if dict(binding) != _source_binding(root):
        raise CampaignError("source binding does not match the exact authoritative repository")


def _build_traceability(*, authoritative_root: Path | None = None) -> dict[str, Any]:
    root = ROOT if authoritative_root is None else authoritative_root
    try:
        report = m8v2.build_evidence_traceability(
            root,
            requirements_path=REQUIREMENTS_PATH,
            mapping_path=MAPPING_PATH,
        )
        m8v2.validate_evidence_traceability(
            report,
            root=root,
            requirements_path=REQUIREMENTS_PATH,
            mapping_path=MAPPING_PATH,
        )
    except (OSError, ValueError, m8v2.TraceabilityError) as exc:
        raise CampaignError("M8 v2 traceability could not be rebuilt") from exc
    return report


def _gates(
    source_binding: Mapping[str, Any],
    traceability: Mapping[str, Any],
    *,
    rebuilt_exactly: bool,
    authoritative_root: Path | None = None,
) -> dict[str, bool]:
    root = ROOT if authoritative_root is None else authoritative_root
    try:
        _validate_exact_source_binding(source_binding, root)
        m8v2.validate_evidence_traceability(
            traceability,
            root=root,
            requirements_path=REQUIREMENTS_PATH,
            mapping_path=MAPPING_PATH,
        )
        valid = True
    except (CampaignError, m8v2.TraceabilityError):
        valid = False
    summary = traceability.get("summary") if valid else None
    mapping = traceability.get("mapping") if valid else None
    forward = traceability.get("forward_index") if valid else None
    inverse = traceability.get("inverse_index") if valid else None
    source = traceability.get("source_binding") if valid else None
    artifacts = inverse.get("artifacts") if isinstance(inverse, dict) else None
    bound_artifacts = (
        isinstance(artifacts, dict)
        and bool(artifacts)
        and all(
            isinstance(item, dict)
            and isinstance(item.get("binding"), dict)
            and isinstance(item["binding"].get("sha256"), str)
            and m8v2.SHA256_RE.fullmatch(item["binding"]["sha256"])
            and isinstance(item["binding"].get("git_blob"), str)
            and m8v2.GIT_OBJECT_RE.fullmatch(item["binding"]["git_blob"])
            for item in artifacts.values()
        )
    )
    gates = {
        "exact_clean_committed_source_bound": (
            valid
            and rebuilt_exactly
            and source_binding.get("clean_checkout") is True
            and isinstance(source, dict)
            and source.get("git_commit") == source_binding.get("git_commit")
            and source.get("git_tree") == source_binding.get("git_tree")
        ),
        "explicit_unapproved_mapping_ingested": (
            valid
            and isinstance(mapping, dict)
            and mapping.get("schema") == m8v2.MAPPING_SCHEMA
            and mapping.get("approval_state") == "not_approved"
            and mapping.get("review_authority") == "implementation_custody"
        ),
        "every_referenced_artifact_exactly_git_bound": valid and bound_artifacts,
        "forward_and_inverse_indexes_retained": (
            valid
            and isinstance(forward, dict)
            and bool(forward)
            and isinstance(inverse, dict)
            and isinstance(inverse.get("procedures"), dict)
            and bool(inverse["procedures"])
        ),
        "all_223_requirements_remain_open": (
            valid
            and isinstance(summary, dict)
            and summary.get("requirements_tracked") == 223
            and summary.get("requirements_open") == 223
        ),
        "all_35_tbrs_remain_open": (
            valid
            and isinstance(summary, dict)
            and summary.get("tbrs_tracked") == 35
            and summary.get("tbrs_open") == 35
        ),
        "zero_requirements_accepted": (
            valid
            and isinstance(summary, dict)
            and summary.get("requirements_accepted") == 0
            and summary.get("end_state_accepted") is False
        ),
        "no_external_attestation_fabricated": (
            valid and traceability.get("external_attestations") == []
        ),
        "independent_validation_remains_external": (
            valid
            and isinstance(traceability.get("attestation_interface"), dict)
            and traceability["attestation_interface"].get(
                "independent_validation_established"
            )
            is False
        ),
        "qualification_deployment_effectiveness_remain_external": (
            valid
            and isinstance(traceability.get("claim_boundary"), str)
            and all(
                phrase in traceability["claim_boundary"]
                for phrase in (
                    "qualification",
                    "authorization",
                    "deployment",
                    "operational effectiveness",
                )
            )
        ),
    }
    if tuple(gates) != GATE_NAMES:
        raise CampaignError("M8 v2 gate implementation drifted from its fixed catalog")
    return gates


def _semantic_projection(
    traceability: Mapping[str, Any], gates: Mapping[str, bool]
) -> dict[str, Any]:
    return {
        "schema": SEMANTIC_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "traceability": dict(traceability),
        "gates": dict(gates),
        "package_integrity_accepted": all(gates.values()),
        "acceptance_scope": ACCEPTANCE_SCOPE,
        "evidence_limits": list(EVIDENCE_LIMITS),
        "system_acceptance": {
            "baseline_approved": False,
            "requirements_accepted": 0,
            "requirements_open": 223,
            "tbrs_open": 35,
            "end_state_accepted": False,
            "g7_completed": False,
            "independent_validation_established": False,
            "deployment_established": False,
            "operational_effectiveness_established": False,
        },
    }


def _build_report(
    source_binding: Mapping[str, Any],
    traceability: Mapping[str, Any],
    *,
    run_id: str | None = None,
    generated_at: datetime | None = None,
    authoritative_root: Path | None = None,
) -> dict[str, Any]:
    root = ROOT if authoritative_root is None else authoritative_root
    _validate_exact_source_binding(source_binding, root)
    m8v2.validate_evidence_traceability(
        traceability,
        root=root,
        requirements_path=REQUIREMENTS_PATH,
        mapping_path=MAPPING_PATH,
    )
    gates = _gates(
        source_binding,
        traceability,
        rebuilt_exactly=True,
        authoritative_root=root,
    )
    semantic = _semantic_projection(traceability, gates)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "run_id": str(uuid.uuid4()) if run_id is None else run_id,
        "generated_at": (
            datetime.now(UTC) if generated_at is None else generated_at
        ).isoformat(),
        "execution_mode": "retained_local_bidirectional_traceability",
        "source_binding": dict(source_binding),
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
        },
        "traceability": dict(traceability),
        "gates": gates,
        "package_integrity_accepted": all(gates.values()),
        "acceptance_scope": ACCEPTANCE_SCOPE,
        "evidence_limits": list(EVIDENCE_LIMITS),
        "system_acceptance": semantic["system_acceptance"],
        "semantic_schema": SEMANTIC_SCHEMA,
        "semantic_outcome_sha256": _sha256_json(semantic),
        "offline_verification": {
            "command": (
                "python scripts/run_m8_evidence_traceability.py --verify "
                "<absolute-evidence-path>"
            ),
            "network_required": False,
            "rebuilds_exact_projection": True,
        },
    }
    report["integrity"] = {"canonical_payload_sha256": _sha256_json(report)}
    _verify_payload(
        report,
        expected_source_binding=source_binding,
        expected_traceability=traceability,
        authoritative_root=root,
    )
    return report


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CampaignError(f"evidence contains duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise CampaignError(f"evidence contains prohibited nonfinite JSON value: {value}")


def _load_private_report(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or ".." in path.parts or path.name != "evidence.json":
        raise CampaignError("evidence path must be absolute, canonical, and named evidence.json")
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
        file_metadata = path.lstat()
        resolved_path = path.resolve(strict=True)
    except OSError as exc:
        raise CampaignError("retained evidence is unavailable") from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or resolved_parent != parent
        or not parent.name.startswith(OUTPUT_PREFIX)
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or path.is_symlink()
        or not stat.S_ISREG(file_metadata.st_mode)
        or file_metadata.st_nlink != 1
        or stat.S_IMODE(file_metadata.st_mode) != 0o600
        or resolved_path != path
        or file_metadata.st_size <= 0
        or file_metadata.st_size > MAX_EVIDENCE_BYTES
    ):
        raise CampaignError("retained evidence path, type, link count, mode, or size is unsafe")
    if {entry.name for entry in os.scandir(parent)} != {"evidence.json"}:
        raise CampaignError("retained evidence directory must contain exactly evidence.json")
    if parent == ROOT or parent.is_relative_to(ROOT):
        raise CampaignError("retained evidence must remain outside the source checkout")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != file_metadata.st_dev
            or opened.st_ino != file_metadata.st_ino
            or opened.st_size != file_metadata.st_size
            or opened.st_nlink != 1
        ):
            raise CampaignError("retained evidence changed while opening")
        material = bytearray()
        while len(material) <= MAX_EVIDENCE_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_EVIDENCE_BYTES + 1 - len(material)),
            )
            if not chunk:
                break
            material.extend(chunk)
        if len(material) != opened.st_size or len(material) > MAX_EVIDENCE_BYTES:
            raise CampaignError("retained evidence changed while reading")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(
            bytes(material).decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CampaignError("retained evidence is not strict finite UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CampaignError("retained evidence root must be an object")
    return value


def _verify_payload(
    report: Mapping[str, Any],
    *,
    expected_source_binding: Mapping[str, Any],
    expected_traceability: Mapping[str, Any],
    authoritative_root: Path | None = None,
) -> None:
    root = ROOT if authoritative_root is None else authoritative_root
    if set(report) != {
        "schema",
        "campaign_id",
        "run_id",
        "generated_at",
        "execution_mode",
        "source_binding",
        "runtime",
        "traceability",
        "gates",
        "package_integrity_accepted",
        "acceptance_scope",
        "evidence_limits",
        "system_acceptance",
        "semantic_schema",
        "semantic_outcome_sha256",
        "offline_verification",
        "integrity",
    }:
        raise CampaignError("retained evidence fields are not exact")
    if report.get("schema") != REPORT_SCHEMA or report.get("campaign_id") != CAMPAIGN_ID:
        raise CampaignError("retained evidence schema or campaign ID is unsupported")
    run_id = report.get("run_id")
    generated_text = report.get("generated_at")
    if not isinstance(run_id, str) or not isinstance(generated_text, str):
        raise CampaignError("retained run identity or time is malformed")
    try:
        parsed_id = uuid.UUID(run_id)
        generated_at = datetime.fromisoformat(generated_text)
    except ValueError as exc:
        raise CampaignError("retained run identity or time is malformed") from exc
    if str(parsed_id) != run_id or generated_at.tzinfo is None:
        raise CampaignError("retained run identity or time is noncanonical")
    source = report.get("source_binding")
    traceability = report.get("traceability")
    if not isinstance(source, dict) or source != dict(expected_source_binding):
        raise CampaignError("retained package does not match the exact current source")
    _validate_exact_source_binding(source, root)
    if not isinstance(traceability, dict):
        raise CampaignError("retained traceability is not an object")
    m8v2.validate_evidence_traceability(
        traceability,
        root=root,
        requirements_path=REQUIREMENTS_PATH,
        mapping_path=MAPPING_PATH,
    )
    if traceability != dict(expected_traceability):
        raise CampaignError("retained traceability does not rebuild exactly")
    gates = _gates(
        source,
        traceability,
        rebuilt_exactly=True,
        authoritative_root=root,
    )
    if report.get("gates") != gates or report.get("package_integrity_accepted") is not all(
        gates.values()
    ):
        raise CampaignError("retained package gates are inconsistent")
    semantic = _semantic_projection(traceability, gates)
    if (
        report.get("acceptance_scope") != ACCEPTANCE_SCOPE
        or report.get("evidence_limits") != list(EVIDENCE_LIMITS)
        or report.get("system_acceptance") != semantic["system_acceptance"]
        or report.get("semantic_schema") != SEMANTIC_SCHEMA
        or report.get("semantic_outcome_sha256") != _sha256_json(semantic)
    ):
        raise CampaignError("retained semantic or claim-boundary fields are inconsistent")
    runtime = report.get("runtime")
    if (
        not isinstance(runtime, dict)
        or set(runtime) != {"python", "implementation"}
        or not all(isinstance(value, str) and value for value in runtime.values())
    ):
        raise CampaignError("retained runtime fields are invalid")
    offline = report.get("offline_verification")
    if not isinstance(offline, dict) or offline != {
        "command": (
            "python scripts/run_m8_evidence_traceability.py --verify "
            "<absolute-evidence-path>"
        ),
        "network_required": False,
        "rebuilds_exact_projection": True,
    }:
        raise CampaignError("offline-verification declaration is inconsistent")
    integrity = report.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {"canonical_payload_sha256"}:
        raise CampaignError("retained integrity fields are invalid")
    unsigned = dict(report)
    unsigned.pop("integrity")
    if integrity.get("canonical_payload_sha256") != _sha256_json(unsigned):
        raise CampaignError("retained evidence integrity digest is invalid")


def _validate_output_parent(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise CampaignError("output parent must be an absolute traversal-free path")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CampaignError("output parent is unavailable") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or resolved != path:
        raise CampaignError("output parent must be a canonical non-symlink directory")
    if path == ROOT or path.is_relative_to(ROOT):
        raise CampaignError("retained evidence must be written outside the source checkout")
    return path


def _write_private(path: Path, report: Mapping[str, Any]) -> None:
    material = json.dumps(
        report,
        allow_nan=False,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(material) > MAX_EVIDENCE_BYTES:
        raise CampaignError("retained evidence exceeds its size limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _cleanup_owned(directory: Path) -> None:
    if (
        not directory.is_absolute()
        or directory == ROOT
        or directory.is_relative_to(ROOT)
        or not directory.name.startswith(OUTPUT_PREFIX)
        or directory.is_symlink()
    ):
        raise CampaignError("refusing cleanup of a directory not owned by this runner")
    entries = list(directory.iterdir())
    if entries:
        if len(entries) != 1 or entries[0].name != "evidence.json":
            raise CampaignError("refusing cleanup of unexpected output content")
        child = entries[0]
        metadata = child.lstat()
        if child.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CampaignError("refusing cleanup of unsafe output content")
        child.unlink()
    directory.rmdir()


def run_campaign(output_parent: Path | None = None) -> Path:
    initial = _assert_exact_source()
    traceability = _build_traceability()
    if _assert_exact_source() != initial:
        raise CampaignError("source changed while M8 v2 traceability was being built")
    report = _build_report(initial, traceability)
    parent = _validate_output_parent(
        Path(tempfile.gettempdir()).resolve() if output_parent is None else output_parent
    )
    directory = Path(tempfile.mkdtemp(prefix=OUTPUT_PREFIX, dir=parent))
    directory.chmod(0o700)
    evidence = directory / "evidence.json"
    try:
        _write_private(evidence, report)
        verify_evidence(evidence)
    except Exception:
        _cleanup_owned(directory)
        raise
    return evidence


def verify_evidence(path: Path) -> dict[str, Any]:
    retained = _load_private_report(path)
    initial = _assert_exact_source()
    traceability = _build_traceability()
    if _assert_exact_source() != initial:
        raise CampaignError("source changed while M8 v2 evidence was being verified")
    _verify_payload(
        retained,
        expected_source_binding=initial,
        expected_traceability=traceability,
    )
    gates = cast(dict[str, bool], retained["gates"])
    summary = cast(dict[str, Any], traceability["summary"])
    return {
        "campaign_id": CAMPAIGN_ID,
        "package_integrity_accepted": all(gates.values()),
        "gates": gates,
        "source_fingerprint_sha256": initial["source_fingerprint_sha256"],
        "semantic_outcome_sha256": retained["semantic_outcome_sha256"],
        "requirements_mapped": summary["requirements_mapped"],
        "requirements_open": summary["requirements_open"],
        "requirements_accepted": summary["requirements_accepted"],
        "tbrs_open": summary["tbrs_open"],
        "external_attestations": 0,
        "independent_validation_established": False,
        "g7_completed": False,
        "deployment_established": False,
    }


def build_plan() -> dict[str, Any]:
    return {
        "schema": PLAN_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "execution_mode": "plan_only",
        "execution_claimed": False,
        "package_integrity_accepted": False,
        "source_paths": list(SOURCE_PATHS),
        "requirements_contract": {
            "tracked": 223,
            "open": 223,
            "accepted": 0,
            "tbrs_open": 35,
            "baseline_status": "proposed_not_approved",
        },
        "mapping_contract": {
            "explicit_entries_only": True,
            "unknown_duplicate_conflicting_overbroad_rejected": True,
            "every_repo_file_exactly_git_bound": True,
            "forward_and_inverse_indexes_required": True,
        },
        "attestation_contract": {
            "trusted_ed25519_authority_supplied_out_of_band": True,
            "signature_freshness_schema_and_exact_bindings_required": True,
            "purpose_audience_challenge_and_monotonic_sequence_required": True,
            "durable_replay_safe_ingestion_required_for_state_change": True,
            "stateless_verification_changes_assurance_state": False,
            "attestation_included": False,
            "automatic_requirement_acceptance": False,
            "independent_validation_established": False,
        },
        "gate_names": list(GATE_NAMES),
        "acceptance_scope": ACCEPTANCE_SCOPE,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true", help="retain a clean-source M8 v2 package")
    mode.add_argument("--verify", type=Path, metavar="EVIDENCE", help="offline-verify evidence")
    parser.add_argument(
        "--output-parent",
        type=Path,
        help="existing absolute directory outside the checkout for --run",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.verify is not None:
            if arguments.output_parent is not None:
                raise CampaignError("--output-parent is valid only with --run")
            result = verify_evidence(arguments.verify)
        elif arguments.run:
            evidence = run_campaign(arguments.output_parent)
            result = {
                "evidence_path": str(evidence),
                "verification": verify_evidence(evidence),
            }
        else:
            if arguments.output_parent is not None:
                raise CampaignError("--output-parent is valid only with --run")
            result = build_plan()
    except CampaignError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
