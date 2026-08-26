"""Plan, retain, and offline-verify the M8 requirements-traceability package.

Package acceptance is limited to exact-source traceability-package integrity.  It
does not accept or approve the proposed baseline, close a requirement or TBR,
complete G7, establish independent validation, authorize deployment, or establish
operational effectiveness.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

import aegis_ot.m8_traceability as m8

ROOT = Path(__file__).resolve().parents[1]
DOCX_RELATIVE_PATH = "docs/requirements/Aegis-OT_End-State_System_Requirements.docx"
REPORT_SCHEMA = "aegis-ot-m8-traceability-campaign-v1"
PLAN_SCHEMA = "aegis-ot-m8-traceability-plan-v1"
SEMANTIC_PROJECTION_VERSION = "aegis-ot-m8-traceability-semantic-projection-v1"
CAMPAIGN_ID = "m8-requirements-traceability-v1"
OUTPUT_PREFIX = "aegis-ot-m8-traceability-"
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

SOURCE_PATHS = (
    DOCX_RELATIVE_PATH,
    "pyproject.toml",
    "scripts/run_m8_traceability.py",
    "src/aegis_ot/m8_traceability.py",
)

ACCEPTANCE_GATE_NAMES = (
    "exact_clean_committed_source_bound",
    "complete_canonical_projection_retained",
    "all_223_requirements_explicitly_open",
    "all_35_tbrs_explicitly_open",
    "proposed_unapproved_baseline_explicit",
    "zero_system_requirements_accepted",
    "g7_remains_external",
    "independent_validation_remains_external",
    "deployment_and_operational_effectiveness_remain_external",
    "package_only_acceptance_scope_explicit",
)

ACCEPTANCE_SCOPE = (
    "Acceptance means only that this retained traceability package has the complete "
    "223-requirement and 35-TBR canonical projection, explicit open-state boundaries, "
    "valid integrity digests, and an exact clean committed source binding. It is not "
    "approval of the proposed baseline; acceptance of any system requirement; closure "
    "of any TBR; G7 completion; independent validation, qualification, or authorization; "
    "deployment; or operational-effectiveness evidence."
)

EVIDENCE_LIMITS = (
    (
        "The package records requirements traceability and open-gap accounting only; "
        "traceability does not establish implementation or evidence truth."
    ),
    (
        "All 223 system requirements remain open and not assessed; zero system "
        "requirements are accepted."
    ),
    "All 35 TBRs remain open with no retained closure artifact or authority decision.",
    "The authoritative requirements baseline remains proposed and unapproved.",
    (
        "G7 independent qualification and authorization remains external to this "
        "campaign and has not been completed."
    ),
    (
        "The package does not establish independent validation, qualification, "
        "authorization, deployment, production readiness, or operational effectiveness."
    ),
)

OFFLINE_VERIFICATION = {
    "verifier": "scripts/run_m8_traceability.py --verify <absolute-evidence-path>",
    "network_required": False,
    "complete_projection_rebuilt_from_exact_source": True,
    "passed_before_retention": True,
}


class CampaignError(RuntimeError):
    """Raised when M8 traceability evidence cannot be retained or verified safely."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CampaignError("campaign material is not canonical JSON") from exc


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _git_executable() -> str:
    executable = shutil.which("git")
    if executable is None:
        raise CampaignError("git is required for retained source binding")
    return executable


def _run_git_bytes(root: Path, *args: str) -> bytes:
    completed = subprocess.run(  # noqa: S603 - fixed executable and no shell
        [_git_executable(), "-C", str(root), *args],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise CampaignError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout


def _run_git_text(root: Path, *args: str) -> str:
    try:
        return _run_git_bytes(root, *args).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CampaignError(f"git {' '.join(args)} returned non-UTF-8 output") from exc


def _validated_source_path(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != relative
    ):
        raise CampaignError(f"required source path is unsafe: {relative}")
    candidate = root.joinpath(*pure.parts)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CampaignError(f"required source is unavailable: {relative}") from exc
    if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise CampaignError(f"required source must be a regular non-symlink file: {relative}")
    if metadata.st_nlink != 1:
        raise CampaignError(f"required source must have exactly one hard link: {relative}")
    if resolved != candidate or not resolved.is_relative_to(root):
        raise CampaignError(f"required source escapes the checkout: {relative}")
    return candidate


def _read_regular_source(root: Path, relative: str) -> bytes:
    path = _validated_source_path(root, relative)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CampaignError(f"required source could not be opened safely: {relative}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CampaignError(f"required source changed while opening: {relative}")
        if metadata.st_size <= 0 or metadata.st_size > MAX_SOURCE_BYTES:
            raise CampaignError(f"required source size is outside the allowed range: {relative}")
        material = bytearray()
        while len(material) <= MAX_SOURCE_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_SOURCE_BYTES + 1 - len(material)))
            if not chunk:
                break
            material.extend(chunk)
        if len(material) != metadata.st_size or len(material) > MAX_SOURCE_BYTES:
            raise CampaignError(f"required source changed while reading: {relative}")
        return bytes(material)
    finally:
        os.close(descriptor)


def _source_fingerprint_material(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "git_commit": binding["git_commit"],
        "git_tree": binding["git_tree"],
        "source_files": binding["source_files"],
    }


def _git_blob_binding(root: Path, commit: str, relative: str, working: bytes) -> dict[str, Any]:
    tree_record = _run_git_bytes(root, "ls-tree", "-z", commit, "--", relative)
    records = [item for item in tree_record.split(b"\0") if item]
    if len(records) != 1:
        raise CampaignError(f"Git did not return one exact source entry for {relative}")
    try:
        header, retained_path = records[0].split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        committed_path = retained_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise CampaignError(f"Git returned a malformed source entry for {relative}") from exc
    if (
        committed_path != relative
        or object_type != "blob"
        or mode not in {"100644", "100755"}
        or not GIT_OBJECT_RE.fullmatch(object_id)
    ):
        raise CampaignError(f"Git source entry is noncanonical for {relative}")
    committed = _run_git_bytes(root, "show", f"{commit}:{relative}")
    if committed != working:
        raise CampaignError(f"required source differs from commit: {relative}")
    return {
        "path": relative,
        "bytes": len(working),
        "sha256": _sha256_bytes(working),
        "git_mode": mode,
        "git_blob": object_id,
    }


def _source_binding(root: Path) -> dict[str, Any]:
    try:
        root_metadata = root.lstat()
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise CampaignError("source checkout is unavailable") from exc
    if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode) or root != resolved_root:
        raise CampaignError("source checkout must be a canonical non-symlink directory")
    top_level = Path(_run_git_text(root, "rev-parse", "--show-toplevel").strip()).resolve()
    if top_level != root:
        raise CampaignError("runner is not executing from its authoritative Git checkout")
    status = _run_git_text(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise CampaignError("retained M8 execution requires an exact clean checkout")

    commit = _run_git_text(root, "rev-parse", "HEAD^{commit}").strip()
    tree = _run_git_text(root, "rev-parse", "HEAD^{tree}").strip()
    if not GIT_OBJECT_RE.fullmatch(commit) or not GIT_OBJECT_RE.fullmatch(tree):
        raise CampaignError("Git returned a noncanonical commit or tree object ID")

    source_files = [
        _git_blob_binding(root, commit, relative, _read_regular_source(root, relative))
        for relative in SOURCE_PATHS
    ]
    binding: dict[str, Any] = {
        "git_commit": commit,
        "git_tree": tree,
        "clean_checkout": True,
        "source_files": source_files,
    }
    binding["source_fingerprint_sha256"] = _sha256_json(
        _source_fingerprint_material(binding)
    )
    return binding


def _assert_clean_source() -> dict[str, Any]:
    expected_module = (ROOT / "src" / "aegis_ot" / "m8_traceability.py").resolve()
    imported_module = Path(m8.__file__ or "").resolve()
    if imported_module != expected_module:
        raise CampaignError(
            f"M8 module imported from stale source: expected {expected_module}, got "
            f"{imported_module}"
        )
    return _source_binding(ROOT)


def _verify_source_binding_shape(binding: Mapping[str, Any]) -> None:
    if set(binding) != {
        "git_commit",
        "git_tree",
        "clean_checkout",
        "source_files",
        "source_fingerprint_sha256",
    }:
        raise CampaignError("source binding fields are not exact")
    if binding.get("clean_checkout") is not True:
        raise CampaignError("evidence is not bound to a clean checkout")
    for field in ("git_commit", "git_tree"):
        value = binding.get(field)
        if not isinstance(value, str) or not GIT_OBJECT_RE.fullmatch(value):
            raise CampaignError(f"source binding {field} is not canonical")

    source_files = binding.get("source_files")
    if not isinstance(source_files, list) or [
        item.get("path") for item in source_files if isinstance(item, dict)
    ] != list(SOURCE_PATHS):
        raise CampaignError("source binding does not contain the exact source path set")
    if len(source_files) != len(SOURCE_PATHS):
        raise CampaignError("source binding does not contain the exact source path set")
    for item in source_files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "bytes",
            "sha256",
            "git_mode",
            "git_blob",
        }:
            raise CampaignError("source file binding fields are not exact")
        if (
            type(item["bytes"]) is not int
            or item["bytes"] <= 0
            or not isinstance(item["sha256"], str)
            or not SHA256_RE.fullmatch(item["sha256"])
            or item["git_mode"] not in {"100644", "100755"}
            or not isinstance(item["git_blob"], str)
            or not GIT_OBJECT_RE.fullmatch(item["git_blob"])
        ):
            raise CampaignError("source file binding is noncanonical")
    if binding.get("source_fingerprint_sha256") != _sha256_json(
        _source_fingerprint_material(binding)
    ):
        raise CampaignError("source fingerprint does not match its bound material")


def _json_copy(value: Any) -> Any:
    return json.loads(_canonical_bytes(value))


def _mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CampaignError(f"{label} must be a string-keyed object")
    return value


def _projection_open_state(projection: Mapping[str, Any]) -> dict[str, Any]:
    summary = _mapping(projection.get("summary"), label="traceability summary")
    return {
        "baseline_status": "proposed_not_approved",
        "requirements_tracked": summary.get("requirements_tracked"),
        "requirements_open": summary.get("requirements_open"),
        "requirements_accepted": summary.get("requirements_accepted"),
        "tbrs_tracked": summary.get("tbrs_tracked"),
        "tbrs_open": summary.get("tbrs_open"),
        "end_state_accepted": summary.get("end_state_accepted"),
    }


def _external_boundaries() -> dict[str, Any]:
    return {
        "g7": {
            "status": "external_not_completed",
            "boundary": "Independent qualification and authorization is a G7 activity.",
        },
        "independent_validation": {
            "status": "external_not_established",
            "boundary": "No independent validation or reproduction is established here.",
        },
        "deployment": {
            "status": "external_not_established",
            "boundary": (
                "No deployment, production readiness, field use, or operational "
                "effectiveness is established here."
            ),
        },
    }


def _system_acceptance_state() -> dict[str, Any]:
    return {
        "baseline_approved": False,
        "requirements_accepted": 0,
        "requirements_open": m8.EXPECTED_REQUIREMENT_COUNT,
        "tbrs_open": m8.EXPECTED_TBR_COUNT,
        "end_state_accepted": False,
        "g7_completed": False,
        "independent_validation_established": False,
        "deployment_established": False,
        "operational_effectiveness_established": False,
    }


def _validate_projection(projection: Mapping[str, Any]) -> None:
    if projection.get("schema") != m8.TRACEABILITY_SCHEMA:
        raise CampaignError("traceability projection schema is unsupported")
    source = _mapping(projection.get("source"), label="traceability source")
    if source.get("path") != DOCX_RELATIVE_PATH:
        raise CampaignError("traceability projection source path is not canonical")
    if source.get("status") != "proposed_not_approved":
        raise CampaignError("requirements baseline is not explicitly proposed and unapproved")
    source_hash = source.get("sha256")
    if not isinstance(source_hash, str) or not SHA256_RE.fullmatch(source_hash):
        raise CampaignError("requirements source digest is noncanonical")

    expected_open_state = {
        "baseline_status": "proposed_not_approved",
        "requirements_tracked": m8.EXPECTED_REQUIREMENT_COUNT,
        "requirements_open": m8.EXPECTED_REQUIREMENT_COUNT,
        "requirements_accepted": 0,
        "tbrs_tracked": m8.EXPECTED_TBR_COUNT,
        "tbrs_open": m8.EXPECTED_TBR_COUNT,
        "end_state_accepted": False,
    }
    if _projection_open_state(projection) != expected_open_state:
        raise CampaignError("traceability projection does not retain the exact open state")

    requirements = projection.get("requirements")
    if not isinstance(requirements, list) or len(requirements) != m8.EXPECTED_REQUIREMENT_COUNT:
        raise CampaignError("traceability projection does not contain all 223 requirements")
    requirement_ids: list[str] = []
    for item in requirements:
        record = _mapping(item, label="requirement record")
        identity = _mapping(record.get("identity"), label="requirement identity")
        verification = _mapping(record.get("verification"), label="requirement verification")
        disposition = _mapping(record.get("disposition"), label="requirement disposition")
        history = record.get("change_history")
        requirement_id = identity.get("requirement_id")
        if not isinstance(requirement_id, str):
            raise CampaignError("requirement identity is malformed")
        requirement_ids.append(requirement_id)
        if (
            verification.get("result") != "not_assessed"
            or verification.get("artifact") != []
            or disposition.get("implementation_state") != "not_assessed"
            or disposition.get("claim_state") != "C0"
            or disposition.get("finding_status") != "open"
            or disposition.get("approving_authority") is not None
            or not isinstance(history, list)
            or len(history) != 1
            or not isinstance(history[0], dict)
            or history[0].get("approval") != "not_approved"
            or history[0].get("effective_baseline") != "proposed"
        ):
            raise CampaignError("one or more requirements are not explicitly open and unapproved")
    if len(set(requirement_ids)) != m8.EXPECTED_REQUIREMENT_COUNT:
        raise CampaignError("traceability projection requirement identifiers are not unique")

    tbrs = projection.get("tbrs")
    if not isinstance(tbrs, list) or len(tbrs) != m8.EXPECTED_TBR_COUNT:
        raise CampaignError("traceability projection does not contain all 35 TBRs")
    if [item.get("tbr_id") for item in tbrs if isinstance(item, dict)] != [
        f"TBR-{index:03d}" for index in range(1, m8.EXPECTED_TBR_COUNT + 1)
    ]:
        raise CampaignError("traceability projection TBR identifiers are not exact")
    if any(
        not isinstance(item, dict)
        or item.get("status") != "open"
        or item.get("closure_artifacts") != []
        or item.get("closed_by") is not None
        or item.get("closed_at") is not None
        for item in tbrs
    ):
        raise CampaignError("one or more TBRs are not explicitly open")

    gates = _mapping(projection.get("gates"), label="gate catalog")
    if gates.get("G7") != "Independent qualification and authorization":
        raise CampaignError("G7 independent qualification boundary is not retained")
    claim_states = _mapping(projection.get("claim_states"), label="claim-state catalog")
    if (
        claim_states.get("C6") != "Externally qualified and authorized"
        or claim_states.get("C7") != "Deployed"
        or claim_states.get("C8") != "Operationally effective"
    ):
        raise CampaignError("external qualification or deployment claim boundaries drifted")
    boundary = projection.get("claim_boundary")
    if not isinstance(boundary, str) or not all(
        phrase in boundary
        for phrase in ("independent validation", "deployment", "operational effectiveness")
    ):
        raise CampaignError("traceability projection claim boundary is incomplete")
    catalog_hash = projection.get("catalog_sha256")
    if not isinstance(catalog_hash, str) or catalog_hash != _sha256_json(
        {
            "requirements": requirements,
            "tbrs": tbrs,
            "gates": gates,
            "claim_states": claim_states,
        }
    ):
        raise CampaignError("traceability catalog digest is invalid")


def _rebuild_traceability_projection(root: Path = ROOT) -> dict[str, Any]:
    source_path = root / DOCX_RELATIVE_PATH
    try:
        raw = m8.build_traceability_report(source_path)
        checks = m8.verify_traceability_report(source_path, raw)
    except (OSError, ValueError) as exc:
        raise CampaignError("authoritative requirements projection could not be rebuilt") from exc
    if not checks or not all(checks.values()):
        raise CampaignError("authoritative requirements projection failed canonical verification")
    projection = copy.deepcopy(raw)
    source = projection.get("source")
    if not isinstance(source, dict) or source.get("path") != source_path.as_posix():
        raise CampaignError("rebuilt requirements source path is unexpected")
    source["path"] = DOCX_RELATIVE_PATH
    _validate_projection(projection)
    return projection


def _acceptance_gates(
    projection: Mapping[str, Any], *, canonical_matches: bool, source_bound: bool
) -> dict[str, bool]:
    try:
        _validate_projection(projection)
        valid = True
    except CampaignError:
        valid = False
    open_state = _projection_open_state(projection) if valid else {}
    system_state = _system_acceptance_state()
    gates = {
        "exact_clean_committed_source_bound": source_bound,
        "complete_canonical_projection_retained": canonical_matches and valid,
        "all_223_requirements_explicitly_open": (
            valid
            and open_state.get("requirements_tracked") == m8.EXPECTED_REQUIREMENT_COUNT
            and open_state.get("requirements_open") == m8.EXPECTED_REQUIREMENT_COUNT
        ),
        "all_35_tbrs_explicitly_open": (
            valid
            and open_state.get("tbrs_tracked") == m8.EXPECTED_TBR_COUNT
            and open_state.get("tbrs_open") == m8.EXPECTED_TBR_COUNT
        ),
        "proposed_unapproved_baseline_explicit": (
            valid and open_state.get("baseline_status") == "proposed_not_approved"
        ),
        "zero_system_requirements_accepted": (
            valid
            and open_state.get("requirements_accepted") == 0
            and system_state["requirements_accepted"] == 0
            and system_state["end_state_accepted"] is False
        ),
        "g7_remains_external": valid and system_state["g7_completed"] is False,
        "independent_validation_remains_external": (
            valid and system_state["independent_validation_established"] is False
        ),
        "deployment_and_operational_effectiveness_remain_external": (
            valid
            and system_state["deployment_established"] is False
            and system_state["operational_effectiveness_established"] is False
        ),
        "package_only_acceptance_scope_explicit": (
            "Acceptance means only" in ACCEPTANCE_SCOPE
            and "not approval" in ACCEPTANCE_SCOPE
            and "G7 completion" in ACCEPTANCE_SCOPE
            and "deployment" in ACCEPTANCE_SCOPE
        ),
    }
    if tuple(gates) != ACCEPTANCE_GATE_NAMES:
        raise CampaignError("acceptance-gate implementation drifted from its fixed catalog")
    return gates


def _semantic_projection(
    projection: Mapping[str, Any], gates: Mapping[str, bool]
) -> dict[str, Any]:
    return {
        "projection_version": SEMANTIC_PROJECTION_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "traceability_report": dict(projection),
        "open_state": _projection_open_state(projection),
        "system_acceptance": _system_acceptance_state(),
        "external_boundaries": _external_boundaries(),
        "package_integrity_gates": dict(gates),
        "package_integrity_accepted": all(gates.values()),
        "acceptance_scope": ACCEPTANCE_SCOPE,
        "evidence_limits": list(EVIDENCE_LIMITS),
    }


def _runtime_versions() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
    }


def _build_report(
    source_binding: Mapping[str, Any],
    projection: Mapping[str, Any],
    *,
    run_id: str | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    _verify_source_binding_shape(source_binding)
    _validate_projection(projection)
    gates = _acceptance_gates(projection, canonical_matches=True, source_bound=True)
    semantic = _semantic_projection(projection, gates)
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "run_id": str(uuid.uuid4()) if run_id is None else run_id,
        "generated_at": (
            datetime.now(UTC) if generated_at is None else generated_at
        ).isoformat(),
        "execution_mode": "retained_local_requirements_projection",
        "source_binding": dict(source_binding),
        "runtime_versions": _runtime_versions(),
        "traceability_report": dict(projection),
        "open_state": _projection_open_state(projection),
        "system_acceptance": _system_acceptance_state(),
        "external_boundaries": _external_boundaries(),
        "package_integrity_gates": gates,
        "package_integrity_accepted": all(gates.values()),
        "acceptance_scope": ACCEPTANCE_SCOPE,
        "semantic_projection_version": SEMANTIC_PROJECTION_VERSION,
        "semantic_outcome_sha256": _sha256_json(semantic),
        "evidence_limits": list(EVIDENCE_LIMITS),
        "offline_verification": dict(OFFLINE_VERIFICATION),
    }
    report["integrity"] = {"canonical_payload_sha256": _sha256_json(report)}
    _verify_report_payload(
        report,
        expected_source_binding=source_binding,
        expected_projection=projection,
    )
    return report


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CampaignError(f"evidence contains duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> NoReturn:
    raise CampaignError(f"evidence contains prohibited nonfinite JSON value: {value}")


def _directory_entries(path: Path) -> set[str]:
    try:
        return {entry.name for entry in os.scandir(path)}
    except OSError as exc:
        raise CampaignError("evidence directory could not be enumerated safely") from exc


def _load_report(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or ".." in path.parts:
        raise CampaignError("evidence path must be absolute and traversal-free")
    if path.name != "evidence.json":
        raise CampaignError("retained evidence filename must be evidence.json")
    parent = path.parent
    try:
        parent_status = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise CampaignError("evidence directory is unavailable") from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_status.st_mode)
        or parent != resolved_parent
    ):
        raise CampaignError("evidence directory must be a canonical non-symlink directory")
    if not parent.name.startswith(OUTPUT_PREFIX):
        raise CampaignError("evidence directory is not owned by the M8 runner")
    if stat.S_IMODE(parent_status.st_mode) != 0o700:
        raise CampaignError("retained evidence directory must be mode 0700")
    if hasattr(os, "getuid") and parent_status.st_uid != os.getuid():
        raise CampaignError("retained evidence directory must be owned by the verifier")
    root = ROOT.resolve()
    if parent == root or parent.is_relative_to(root):
        raise CampaignError("retained evidence must remain outside the source checkout")
    if path != parent / "evidence.json":
        raise CampaignError("evidence path is not canonical")
    if _directory_entries(parent) != {"evidence.json"}:
        raise CampaignError("evidence directory must contain exactly evidence.json")

    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_descriptor = os.open(parent, directory_flags)
    except OSError as exc:
        raise CampaignError("evidence directory could not be opened safely") from exc
    try:
        opened_parent = os.fstat(directory_descriptor)
        if (
            opened_parent.st_dev != parent_status.st_dev
            or opened_parent.st_ino != parent_status.st_ino
            or stat.S_IMODE(opened_parent.st_mode) != 0o700
        ):
            raise CampaignError("evidence directory changed while opening")
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open("evidence.json", file_flags, dir_fd=directory_descriptor)
        except OSError as exc:
            raise CampaignError("evidence file must be a regular non-symlink file") from exc
        try:
            file_status = os.fstat(descriptor)
            if not stat.S_ISREG(file_status.st_mode):
                raise CampaignError("evidence file must be a regular non-symlink file")
            if stat.S_IMODE(file_status.st_mode) != 0o600:
                raise CampaignError("retained evidence file must be mode 0600")
            if file_status.st_nlink != 1:
                raise CampaignError("retained evidence file must have exactly one hard link")
            if hasattr(os, "getuid") and file_status.st_uid != os.getuid():
                raise CampaignError("retained evidence file must be owned by the verifier")
            if file_status.st_size <= 0 or file_status.st_size > MAX_EVIDENCE_BYTES:
                raise CampaignError("evidence file size is outside the verifier limit")
            material = bytearray()
            while len(material) <= MAX_EVIDENCE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, MAX_EVIDENCE_BYTES + 1 - len(material)),
                )
                if not chunk:
                    break
                material.extend(chunk)
            if len(material) != file_status.st_size or len(material) > MAX_EVIDENCE_BYTES:
                raise CampaignError("evidence file changed while reading")
            try:
                current_status = os.stat(
                    "evidence.json",
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise CampaignError("evidence file changed while reading") from exc
            if (
                current_status.st_dev != file_status.st_dev
                or current_status.st_ino != file_status.st_ino
                or current_status.st_size != file_status.st_size
                or current_status.st_nlink != 1
                or stat.S_IMODE(current_status.st_mode) != 0o600
            ):
                raise CampaignError("evidence file changed while reading")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_descriptor)
    if _directory_entries(parent) != {"evidence.json"}:
        raise CampaignError("evidence directory changed while reading")
    try:
        text = bytes(material).decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise CampaignError("evidence is not strict finite UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CampaignError("evidence root must be an object")
    return value


def _verify_report_payload(
    report: Mapping[str, Any],
    *,
    expected_source_binding: Mapping[str, Any],
    expected_projection: Mapping[str, Any],
) -> None:
    if set(report) != {
        "schema_version",
        "campaign_id",
        "run_id",
        "generated_at",
        "execution_mode",
        "source_binding",
        "runtime_versions",
        "traceability_report",
        "open_state",
        "system_acceptance",
        "external_boundaries",
        "package_integrity_gates",
        "package_integrity_accepted",
        "acceptance_scope",
        "semantic_projection_version",
        "semantic_outcome_sha256",
        "evidence_limits",
        "offline_verification",
        "integrity",
    }:
        raise CampaignError("evidence top-level fields are not exact")
    if report.get("schema_version") != REPORT_SCHEMA:
        raise CampaignError("evidence schema version is unsupported")
    if report.get("campaign_id") != CAMPAIGN_ID:
        raise CampaignError("evidence campaign ID is not exact")
    run_id = report.get("run_id")
    generated_text = report.get("generated_at")
    if not isinstance(run_id, str) or not isinstance(generated_text, str):
        raise CampaignError("run identity or generation time is malformed")
    try:
        parsed_run_id = uuid.UUID(run_id)
        generated_at = datetime.fromisoformat(generated_text)
    except ValueError as exc:
        raise CampaignError("run identity or generation time is malformed") from exc
    if str(parsed_run_id) != run_id:
        raise CampaignError("run identity must use canonical UUID text")
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise CampaignError("evidence generation time must be timezone-aware")
    if report.get("execution_mode") != "retained_local_requirements_projection":
        raise CampaignError("evidence execution mode is unsupported")

    source_binding = report.get("source_binding")
    if not isinstance(source_binding, dict):
        raise CampaignError("evidence source binding must be an object")
    _verify_source_binding_shape(source_binding)
    if dict(source_binding) != dict(expected_source_binding):
        raise CampaignError("evidence source binding does not match the exact current source")

    runtime_versions = report.get("runtime_versions")
    if (
        not isinstance(runtime_versions, dict)
        or set(runtime_versions) != {"python", "implementation"}
        or not all(isinstance(item, str) and item for item in runtime_versions.values())
    ):
        raise CampaignError("runtime-version evidence fields are not exact")

    projection = report.get("traceability_report")
    if not isinstance(projection, dict):
        raise CampaignError("traceability report must be an object")
    _validate_projection(projection)
    if projection != dict(expected_projection):
        raise CampaignError("retained traceability projection does not rebuild exactly")
    expected_open_state = _projection_open_state(expected_projection)
    if report.get("open_state") != expected_open_state:
        raise CampaignError("retained open-state summary is inconsistent")
    if report.get("system_acceptance") != _system_acceptance_state():
        raise CampaignError("system-acceptance boundary is not exact")
    if report.get("external_boundaries") != _external_boundaries():
        raise CampaignError("external G7, validation, or deployment boundary is not exact")
    if report.get("acceptance_scope") != ACCEPTANCE_SCOPE:
        raise CampaignError("package-only acceptance scope is not exact")
    if report.get("evidence_limits") != list(EVIDENCE_LIMITS):
        raise CampaignError("evidence limits are not exact")

    gates = _acceptance_gates(
        projection,
        canonical_matches=projection == dict(expected_projection),
        source_bound=source_binding == dict(expected_source_binding),
    )
    if report.get("package_integrity_gates") != gates:
        raise CampaignError("package-integrity gates do not match rebuilt outcomes")
    if report.get("package_integrity_accepted") is not all(gates.values()):
        raise CampaignError("package-integrity acceptance is inconsistent")
    if report.get("semantic_projection_version") != SEMANTIC_PROJECTION_VERSION:
        raise CampaignError("semantic projection version is unsupported")
    if report.get("semantic_outcome_sha256") != _sha256_json(
        _semantic_projection(projection, gates)
    ):
        raise CampaignError("semantic outcome digest is invalid")
    if report.get("offline_verification") != OFFLINE_VERIFICATION:
        raise CampaignError("offline-verification declaration is not exact")

    integrity = report.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {"canonical_payload_sha256"}:
        raise CampaignError("evidence integrity fields are not exact")
    unsigned = dict(report)
    unsigned.pop("integrity")
    if integrity.get("canonical_payload_sha256") != _sha256_json(unsigned):
        raise CampaignError("evidence canonical payload digest is invalid")


def _validate_output_parent(output_parent: Path) -> Path:
    if not output_parent.is_absolute() or ".." in output_parent.parts:
        raise CampaignError("output parent must be an absolute traversal-free path")
    try:
        metadata = output_parent.lstat()
        resolved = output_parent.resolve(strict=True)
    except OSError as exc:
        raise CampaignError("output parent must be an existing directory") from exc
    if (
        output_parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or output_parent != resolved
    ):
        raise CampaignError("output parent must be a canonical non-symlink directory")
    root = ROOT.resolve()
    if resolved == root or resolved.is_relative_to(root):
        raise CampaignError("retained evidence must be written outside the source checkout")
    return resolved


def _write_private_report(path: Path, report: Mapping[str, Any]) -> None:
    material = json.dumps(
        report,
        allow_nan=False,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(material) > MAX_EVIDENCE_BYTES:
        raise CampaignError("retained evidence exceeds the verifier size limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise CampaignError("retained evidence could not be created safely") from exc
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    status = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(status.st_mode)
        or stat.S_IMODE(status.st_mode) != 0o600
        or status.st_nlink != 1
    ):
        raise CampaignError("retained evidence file is not a unique mode-0600 regular file")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_descriptor = os.open(path.parent, directory_flags)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _remove_owned_output(directory: Path) -> None:
    root = ROOT.resolve()
    if (
        not directory.is_absolute()
        or directory.parent == directory
        or directory == root
        or directory.is_relative_to(root)
        or not directory.name.startswith(OUTPUT_PREFIX)
        or directory.is_symlink()
    ):
        raise CampaignError("refusing cleanup of an output directory not owned by this runner")
    entries = list(directory.iterdir())
    if entries:
        if len(entries) != 1 or entries[0].name != "evidence.json":
            raise CampaignError("refusing cleanup of unexpected output-directory content")
        child = entries[0]
        status = child.lstat()
        if child.is_symlink() or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise CampaignError("refusing cleanup of unsafe evidence content")
        child.unlink()
    directory.rmdir()


def run_campaign(output_parent: Path | None = None) -> Path:
    source_binding = _assert_clean_source()
    projection = _rebuild_traceability_projection()
    if _assert_clean_source() != source_binding:
        raise CampaignError("source changed while the M8 projection was being built")
    report = _build_report(source_binding, projection)
    default_parent = Path(tempfile.gettempdir()).resolve()
    parent = _validate_output_parent(default_parent if output_parent is None else output_parent)
    output_directory = Path(tempfile.mkdtemp(prefix=OUTPUT_PREFIX, dir=parent))
    output_directory.chmod(0o700)
    if stat.S_IMODE(output_directory.stat().st_mode) != 0o700:
        _remove_owned_output(output_directory)
        raise CampaignError("retained output directory is not mode 0700")
    evidence_path = output_directory / "evidence.json"
    try:
        _write_private_report(evidence_path, report)
        verify_evidence(evidence_path)
    except Exception:
        _remove_owned_output(output_directory)
        raise
    return evidence_path


def verify_evidence(path: Path) -> dict[str, Any]:
    report = _load_report(path)
    source_binding = _assert_clean_source()
    projection = _rebuild_traceability_projection()
    _verify_report_payload(
        report,
        expected_source_binding=source_binding,
        expected_projection=projection,
    )
    if _assert_clean_source() != source_binding:
        raise CampaignError("source changed while M8 evidence was being verified")
    return {
        "package_integrity_accepted": report["package_integrity_accepted"],
        "baseline_approved": False,
        "requirements_tracked": m8.EXPECTED_REQUIREMENT_COUNT,
        "requirements_open": m8.EXPECTED_REQUIREMENT_COUNT,
        "requirements_accepted": 0,
        "tbrs_tracked": m8.EXPECTED_TBR_COUNT,
        "tbrs_open": m8.EXPECTED_TBR_COUNT,
        "end_state_accepted": False,
        "g7_completed": False,
        "independent_validation_established": False,
        "deployment_established": False,
        "git_commit": source_binding["git_commit"],
        "git_tree": source_binding["git_tree"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
        "catalog_sha256": projection["catalog_sha256"],
        "semantic_outcome_sha256": report["semantic_outcome_sha256"],
        "canonical_payload_sha256": report["integrity"]["canonical_payload_sha256"],
    }


def build_plan() -> dict[str, Any]:
    return {
        "schema_version": PLAN_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "execution_mode": "plan_only",
        "source_paths": list(SOURCE_PATHS),
        "projection_contract": {
            "requirements_tracked": m8.EXPECTED_REQUIREMENT_COUNT,
            "requirements_open": m8.EXPECTED_REQUIREMENT_COUNT,
            "requirements_accepted": 0,
            "tbrs_tracked": m8.EXPECTED_TBR_COUNT,
            "tbrs_open": m8.EXPECTED_TBR_COUNT,
            "baseline_status": "proposed_not_approved",
            "end_state_accepted": False,
        },
        "acceptance_gate_names": list(ACCEPTANCE_GATE_NAMES),
        "acceptance_scope": ACCEPTANCE_SCOPE,
        "external_boundaries": _external_boundaries(),
        "retained_execution_requirements": [
            "exact clean committed commit, tree, and four-file blob binding",
            "complete canonical 223-requirement and 35-TBR projection rebuild",
            "unique mode-0700 output directory outside the checkout",
            "unique mode-0600 regular evidence file",
            "strict finite UTF-8 JSON with duplicate keys rejected",
            "no symlink, hardlink, or traversal path acceptance",
        ],
        "evidence_limits": list(EVIDENCE_LIMITS),
        "execution_claimed": False,
        "package_integrity_accepted": False,
        "system_requirements_accepted": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--plan", action="store_true", help="print the fixed plan")
    operation.add_argument("--run", action="store_true", help="run and retain evidence")
    operation.add_argument(
        "--verify",
        type=Path,
        metavar="EVIDENCE",
        help="offline-verify evidence against the exact clean source revision",
    )
    parser.add_argument(
        "--output-parent",
        type=Path,
        help="absolute existing directory outside the checkout for private retained output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.output_parent is not None and not args.run:
        raise CampaignError("--output-parent is valid only with --run")
    if args.plan:
        print(json.dumps(build_plan(), indent=2, sort_keys=True))
        return 0
    if args.verify is not None:
        print(json.dumps(verify_evidence(args.verify), indent=2, sort_keys=True))
        return 0
    evidence_path = run_campaign(args.output_parent)
    retained = _load_report(evidence_path)
    print(
        json.dumps(
            {
                "package_integrity_accepted": retained["package_integrity_accepted"],
                "system_requirements_accepted": False,
                "baseline_approved": False,
                "requirements_open": m8.EXPECTED_REQUIREMENT_COUNT,
                "tbrs_open": m8.EXPECTED_TBR_COUNT,
                "g7_completed": False,
                "independent_validation_established": False,
                "deployment_established": False,
                "evidence_path": str(evidence_path),
                "git_commit": retained["source_binding"]["git_commit"],
                "git_tree": retained["source_binding"]["git_tree"],
                "source_fingerprint_sha256": retained["source_binding"][
                    "source_fingerprint_sha256"
                ],
                "catalog_sha256": retained["traceability_report"]["catalog_sha256"],
                "semantic_outcome_sha256": retained["semantic_outcome_sha256"],
                "canonical_payload_sha256": retained["integrity"][
                    "canonical_payload_sha256"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CampaignError as exc:
        print(f"M8 traceability campaign failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
