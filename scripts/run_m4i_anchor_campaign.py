#!/usr/bin/env python3
"""Retain an exact-source M4i external-anchor contract campaign.

This deterministic campaign exercises the rollback, readback, fencing, and
compare-and-advance semantics in ``coordination_anchor``.  Its authority is an
in-process reference model.  Passing evidence therefore validates the code
contract only; it is not evidence of an independently hosted anchor,
distributed consensus, actuator fencing, deployment, or external validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_ot.coordination_anchor import (
    AnchorAuthorityError,
    AnchoredRecoveryDecision,
    AnchoredRecoveryReason,
    AnchoredRecoveryStatus,
    BoundCoordinationAnchorAdmissionDecision,
    CoordinationAnchorAdmissionError,
    CoordinationAnchorAdmissionPhase,
    CoordinationAnchorReadback,
    FailClosedCoordinationAnchorAdmission,
    InMemoryMonotonicAnchorReference,
    LocalCoordinationProjection,
    SignedCoordinationAnchor,
    TrustedAnchorFloor,
    validate_anchored_coordination_recovery,
)
from aegis_ot.coordination_recovery import (
    CoordinationRecoveryReason,
    CoordinationRecoveryResult,
    CoordinationRecoveryStatus,
)

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN_ID = "m4i-monotonic-anchor-and-fencing-v1"
SCHEMA_VERSION = "m4i-anchor-campaign-evidence-v1"
STREAM_ID = "aegis-ot:m4i:retained-campaign"
READ_NONCE = "m4i-anchor-retained-readback-nonce-0001"
MAX_EVIDENCE_BYTES = 1_048_576
SOURCE_BINDING_FILES = (
    "pyproject.toml",
    "requirements.lock",
    "scripts/run_m4i_anchor_campaign.py",
    "src/aegis_ot/coordination_anchor.py",
    "src/aegis_ot/coordination_journal.py",
    "src/aegis_ot/coordination_models.py",
    "src/aegis_ot/coordination_recovery.py",
    "src/aegis_ot/crypto.py",
    "src/aegis_ot/physical_models.py",
    "src/aegis_ot/segmented_capability_runtime.py",
    "src/aegis_ot/workload_identity.py",
    "tests/test_m4i_anchor_campaign_runner.py",
    "tests/test_m4i_anchor_runtime_admission.py",
    "tests/test_m4i_coordination_anchor.py",
    "tests/test_m4i_ot_coordination_runtime.py",
)
SCENARIO_NAMES = (
    "fresh_readback",
    "fenced_admission",
    "local_advance",
    "advanced_readback",
    "coordinated_rollback",
    "same_version_journal_conflict",
    "anchor_unavailable",
    "expired_readback",
    "stale_anchor_sequence",
    "authority_equivocation",
    "stale_fence",
    "current_fence",
    "pending_recovery",
    "runtime_admission_port",
    "stale_compare_and_advance",
)
GATE_NAMES = (
    "fresh_signed_readback_matches_exact_local_state",
    "consequential_admission_requires_current_fence",
    "fenced_local_advance_requires_external_checkpoint",
    "compare_and_advance_restores_exact_readback_alignment",
    "coordinated_local_rollback_is_detected",
    "same_version_conflict_fails_closed",
    "unavailable_anchor_fails_closed",
    "expired_readback_fails_closed",
    "trusted_floor_rejects_stale_anchor",
    "trusted_floor_rejects_authority_equivocation",
    "newer_fence_invalidates_prior_holder",
    "pending_effect_requires_recovery_not_admission",
    "runtime_admission_port_denies_every_nonready_decision",
    "stale_compare_and_advance_is_rejected",
)
EVIDENCE_BOUNDARIES = (
    "In-process reference authority; not an independently hosted rollback domain",
    "Signed nonce-bound readback and monotonic CAS model; not distributed consensus",
    "Trusted authority key and non-Byzantine authority are assumptions, not validated facts",
    "Application fencing contract; no actuator or multi-replica fencing is deployed",
    "Deterministic local evidence; not independent or external validation",
    "No exactly-once physical-effect claim",
)
REQUIREMENT_MAPPING = {
    "requirements": ["AOT-COORD-014", "AOT-NET-010", "AOT-SEC-013"],
    "tbr": "TBR-018",
    "status": "contract_modeled_not_architecture_approved",
}

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CampaignError(RuntimeError):
    """The retained anchor campaign or its evidence was invalid."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _git(root: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise CampaignError("git is required for retained source binding")
    completed = subprocess.run(  # noqa: S603 - resolved Git and fixed argv, no shell
        (executable, "-C", str(root), *args),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise CampaignError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout.strip()


def _source_binding(root: Path) -> dict[str, Any]:
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise CampaignError("M4i anchor campaign requires an exact clean checkout")
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    if _GIT_OBJECT.fullmatch(commit) is None or _GIT_OBJECT.fullmatch(tree) is None:
        raise CampaignError("git source identity was malformed")
    files: dict[str, str] = {}
    for relative in SOURCE_BINDING_FILES:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise CampaignError(f"source-binding file is unavailable: {relative}")
        files[relative] = _sha256(path.read_bytes())
    return {
        "git_commit": commit,
        "git_tree": tree,
        "source_files_sha256": files,
        "source_fingerprint_sha256": _sha256(_canonical_bytes(files)),
        "clean_checkout": True,
    }


def _projection(
    version: int,
    *,
    journal_marker: str,
    state_marker: str,
    fencing_token: int,
    based_on_sequence: int | None = None,
    based_on_sha256: str | None = None,
    recovery_status: CoordinationRecoveryStatus = CoordinationRecoveryStatus.ALIGNED,
) -> LocalCoordinationProjection:
    if recovery_status is CoordinationRecoveryStatus.ALIGNED:
        reason = (
            CoordinationRecoveryReason.ALIGNED_EMPTY_BASELINE
            if version == 0
            else CoordinationRecoveryReason.ALIGNED_APPLIED_CHAIN
        )
        pending = 0
    else:
        reason = CoordinationRecoveryReason.PENDING_EFFECT_AT_PRE_STATE
        pending = 1
    recovery = CoordinationRecoveryResult(
        status=recovery_status,
        reason=reason,
        record_count=version + pending,
        applied_effect_count=version,
        pending_effect_count=pending,
        plant_state_version=version,
        plant_state_digest=state_marker * 64,
        latest_applied_state_version=version if version else None,
        latest_applied_state_digest=state_marker * 64 if version else None,
    )
    return LocalCoordinationProjection.from_recovery(
        recovery,
        gateway_journal_sha256=journal_marker * 64,
        ot_journal_sha256=journal_marker.upper() * 64,
        plant_model_sha256="f" * 64,
        writer_fencing_token=fencing_token,
        based_on_anchor_sequence=based_on_sequence,
        based_on_anchor_sha256=based_on_sha256,
    )


def _evaluate(
    authority: InMemoryMonotonicAnchorReference,
    local: LocalCoordinationProjection,
    readback: CoordinationAnchorReadback | None,
    *,
    evaluated_at: datetime,
    trusted_floor: TrustedAnchorFloor | None = None,
    fence: Any = None,
    require_fence: bool = False,
) -> AnchoredRecoveryDecision:
    return validate_anchored_coordination_recovery(
        local,
        readback=readback,
        expected_stream_id=STREAM_ID,
        expected_request_nonce=READ_NONCE,
        authority_public_key=authority.public_key,
        evaluated_at=evaluated_at,
        trusted_floor=trusted_floor,
        fence=fence,
        require_fence=require_fence,
    )


def _scenario_result(decision: AnchoredRecoveryDecision) -> dict[str, Any]:
    return decision.model_dump(mode="json")


class _StaticDecisionSource:
    def __init__(self, decision: AnchoredRecoveryDecision) -> None:
        self.decision = decision

    def __call__(
        self,
        *,
        phase: CoordinationAnchorAdmissionPhase,
        effect_id: str,
        request_sha256: str,
        evaluated_at: datetime,
    ) -> BoundCoordinationAnchorAdmissionDecision:
        return BoundCoordinationAnchorAdmissionDecision(
            phase=phase,
            effect_id=effect_id,
            request_sha256=request_sha256,
            evaluated_at=evaluated_at,
            decision=self.decision,
        )


def _admission_port_scenario(
    decisions: dict[str, AnchoredRecoveryDecision],
    *,
    evaluated_at: datetime,
) -> dict[str, bool]:
    results: dict[str, bool] = {}
    for name, decision in decisions.items():
        guard = FailClosedCoordinationAnchorAdmission(_StaticDecisionSource(decision))
        try:
            guard.require_admission(
                phase=CoordinationAnchorAdmissionPhase.PREPARE,
                effect_id="sha256:" + "a" * 64,
                request_sha256="b" * 64,
                evaluated_at=evaluated_at,
            )
        except CoordinationAnchorAdmissionError:
            results[name] = not decision.admission_allowed
        else:
            results[name] = decision.admission_allowed
    cached = BoundCoordinationAnchorAdmissionDecision(
        phase=CoordinationAnchorAdmissionPhase.PREPARE,
        effect_id="sha256:" + "c" * 64,
        request_sha256="d" * 64,
        evaluated_at=evaluated_at,
        decision=decisions["current_fence_admitted"],
    )

    def cached_source(
        *,
        phase: CoordinationAnchorAdmissionPhase,
        effect_id: str,
        request_sha256: str,
        evaluated_at: datetime,
    ) -> BoundCoordinationAnchorAdmissionDecision:
        del phase, effect_id, request_sha256, evaluated_at
        return cached

    try:
        FailClosedCoordinationAnchorAdmission(cached_source).require_admission(
            phase=CoordinationAnchorAdmissionPhase.PREPARE,
            effect_id="sha256:" + "e" * 64,
            request_sha256="f" * 64,
            evaluated_at=evaluated_at,
        )
    except CoordinationAnchorAdmissionError:
        results["cached_ready_binding_mismatch_denied"] = True
    else:
        results["cached_ready_binding_mismatch_denied"] = False
    return results


def _run_scenarios() -> tuple[dict[str, Any], dict[str, bool]]:
    now = datetime(2026, 8, 26, 16, 0, tzinfo=UTC)
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"aegis-ot-m4i-anchor-campaign-authority-v1").digest()
    )
    baseline = _projection(
        0,
        journal_marker="1",
        state_marker="a",
        fencing_token=0,
    )
    authority = InMemoryMonotonicAnchorReference(
        stream_id=STREAM_ID,
        genesis=baseline,
        authority_private_key=private_key,
        initialized_at=now,
    )
    genesis_readback = authority.readback(
        request_nonce=READ_NONCE,
        read_at=now,
    )
    genesis_floor = TrustedAnchorFloor.from_readback(genesis_readback)
    fresh = _evaluate(
        authority,
        baseline,
        genesis_readback,
        evaluated_at=now + timedelta(seconds=1),
    )
    unavailable = _evaluate(
        authority,
        baseline,
        None,
        evaluated_at=now + timedelta(seconds=1),
    )
    expired = _evaluate(
        authority,
        baseline,
        genesis_readback,
        evaluated_at=now + timedelta(seconds=61),
    )

    first_fence = authority.acquire_fence(
        holder_id="ot-writer:campaign",
        request_nonce="m4i-anchor-first-fence-request-0001",
        expected_anchor_sha256=genesis_readback.anchor.digest,
        issued_at=now + timedelta(seconds=2),
    )
    fenced_readback = authority.readback(
        request_nonce=READ_NONCE,
        read_at=now + timedelta(seconds=2),
    )
    admission = _evaluate(
        authority,
        baseline,
        fenced_readback,
        evaluated_at=now + timedelta(seconds=3),
        fence=first_fence,
        require_fence=True,
    )
    advanced_local = _projection(
        1,
        journal_marker="2",
        state_marker="b",
        fencing_token=first_fence.fencing_token,
        based_on_sequence=genesis_readback.anchor.anchor_sequence,
        based_on_sha256=genesis_readback.anchor.digest,
    )
    local_advance = _evaluate(
        authority,
        advanced_local,
        fenced_readback,
        evaluated_at=now + timedelta(seconds=3),
    )
    advanced_anchor = authority.compare_and_advance(
        expected_anchor_sha256=genesis_readback.anchor.digest,
        projection=advanced_local,
        fence=first_fence,
        advanced_at=now + timedelta(seconds=4),
    )
    advanced_readback = authority.readback(
        request_nonce=READ_NONCE,
        read_at=now + timedelta(seconds=5),
    )
    aligned_advanced = _evaluate(
        authority,
        advanced_local,
        advanced_readback,
        evaluated_at=now + timedelta(seconds=6),
        trusted_floor=genesis_floor,
    )
    coordinated_rollback = _evaluate(
        authority,
        baseline,
        advanced_readback,
        evaluated_at=now + timedelta(seconds=6),
    )
    same_version_conflict = _evaluate(
        authority,
        advanced_local.model_copy(update={"gateway_journal_sha256": "3" * 64}),
        advanced_readback,
        evaluated_at=now + timedelta(seconds=6),
    )
    current_floor = TrustedAnchorFloor.from_readback(advanced_readback)
    stale_anchor = _evaluate(
        authority,
        baseline,
        genesis_readback,
        evaluated_at=now + timedelta(seconds=6),
        trusted_floor=current_floor,
    )

    equivocal_projection = _projection(
        1,
        journal_marker="4",
        state_marker="b",
        fencing_token=first_fence.fencing_token,
        based_on_sequence=genesis_readback.anchor.anchor_sequence,
        based_on_sha256=genesis_readback.anchor.digest,
    )
    equivocal_anchor = SignedCoordinationAnchor.issue(
        stream_id=STREAM_ID,
        anchor_sequence=advanced_anchor.anchor_sequence,
        fencing_token=first_fence.fencing_token,
        previous_anchor_sha256=genesis_readback.anchor.digest,
        projection=equivocal_projection,
        authority_private_key=private_key,
        issued_at=now + timedelta(seconds=4),
    )
    equivocal_readback = CoordinationAnchorReadback.issue(
        request_nonce=READ_NONCE,
        anchor=equivocal_anchor,
        authority_fencing_token=first_fence.fencing_token,
        authority_private_key=private_key,
        read_at=now + timedelta(seconds=5),
        expires_at=now + timedelta(seconds=30),
    )
    equivocation = _evaluate(
        authority,
        equivocal_projection,
        equivocal_readback,
        evaluated_at=now + timedelta(seconds=6),
        trusted_floor=current_floor,
    )

    stale_fence = authority.acquire_fence(
        holder_id="ot-writer:stale",
        request_nonce="m4i-anchor-stale-fence-request-0001",
        expected_anchor_sha256=advanced_anchor.digest,
        issued_at=now + timedelta(seconds=7),
    )
    current_fence = authority.acquire_fence(
        holder_id="ot-writer:current",
        request_nonce="m4i-anchor-current-fence-request-0001",
        expected_anchor_sha256=advanced_anchor.digest,
        issued_at=now + timedelta(seconds=8),
    )
    current_readback = authority.readback(
        request_nonce=READ_NONCE,
        read_at=now + timedelta(seconds=8),
    )
    stale_fence_decision = _evaluate(
        authority,
        advanced_local,
        current_readback,
        evaluated_at=now + timedelta(seconds=9),
        fence=stale_fence,
        require_fence=True,
    )
    current_fence_decision = _evaluate(
        authority,
        advanced_local,
        current_readback,
        evaluated_at=now + timedelta(seconds=9),
        fence=current_fence,
        require_fence=True,
    )
    pending_local = _projection(
        1,
        journal_marker="5",
        state_marker="b",
        fencing_token=current_fence.fencing_token,
        based_on_sequence=advanced_anchor.anchor_sequence,
        based_on_sha256=advanced_anchor.digest,
        recovery_status=CoordinationRecoveryStatus.RECOVERY_REQUIRED,
    )
    pending_recovery = _evaluate(
        authority,
        pending_local,
        current_readback,
        evaluated_at=now + timedelta(seconds=9),
    )
    stale_cas_rejected = False
    try:
        authority.compare_and_advance(
            expected_anchor_sha256=genesis_readback.anchor.digest,
            projection=advanced_local,
            fence=first_fence,
            advanced_at=now + timedelta(seconds=9),
        )
    except AnchorAuthorityError:
        stale_cas_rejected = True
    admission_port = _admission_port_scenario(
        {
            "unavailable_denied": unavailable,
            "expired_denied": expired,
            "conflict_denied": same_version_conflict,
            "current_fence_admitted": current_fence_decision,
        },
        evaluated_at=now + timedelta(seconds=9),
    )

    scenarios = {
        "fresh_readback": _scenario_result(fresh),
        "fenced_admission": _scenario_result(admission),
        "local_advance": _scenario_result(local_advance),
        "advanced_readback": _scenario_result(aligned_advanced),
        "coordinated_rollback": _scenario_result(coordinated_rollback),
        "same_version_journal_conflict": _scenario_result(same_version_conflict),
        "anchor_unavailable": _scenario_result(unavailable),
        "expired_readback": _scenario_result(expired),
        "stale_anchor_sequence": _scenario_result(stale_anchor),
        "authority_equivocation": _scenario_result(equivocation),
        "stale_fence": _scenario_result(stale_fence_decision),
        "current_fence": _scenario_result(current_fence_decision),
        "pending_recovery": _scenario_result(pending_recovery),
        "runtime_admission_port": admission_port,
        "stale_compare_and_advance": {
            "rejected": stale_cas_rejected,
            "reason": "anchor_compare_and_advance_used_stale_state",
        },
    }
    gates = {
        "fresh_signed_readback_matches_exact_local_state": (
            fresh.status is AnchoredRecoveryStatus.ALIGNED
            and fresh.reason is AnchoredRecoveryReason.ALIGNED_TO_CURRENT_ANCHOR
            and not fresh.admission_allowed
        ),
        "consequential_admission_requires_current_fence": (
            admission.status is AnchoredRecoveryStatus.ADMISSION_READY
            and admission.admission_allowed
        ),
        "fenced_local_advance_requires_external_checkpoint": (
            local_advance.status is AnchoredRecoveryStatus.RECOVERY_REQUIRED
            and local_advance.reason
            is AnchoredRecoveryReason.LOCAL_ADVANCE_REQUIRES_ANCHOR
        ),
        "compare_and_advance_restores_exact_readback_alignment": (
            advanced_anchor.anchor_sequence == 1
            and aligned_advanced.status is AnchoredRecoveryStatus.ALIGNED
        ),
        "coordinated_local_rollback_is_detected": (
            coordinated_rollback.status is AnchoredRecoveryStatus.INCONSISTENT
            and coordinated_rollback.reason
            is AnchoredRecoveryReason.COORDINATED_ROLLBACK_DETECTED
        ),
        "same_version_conflict_fails_closed": (
            same_version_conflict.status is AnchoredRecoveryStatus.INCONSISTENT
            and same_version_conflict.reason
            is AnchoredRecoveryReason.ANCHORED_STATE_CONFLICT
        ),
        "unavailable_anchor_fails_closed": (
            unavailable.status is AnchoredRecoveryStatus.UNAVAILABLE
            and unavailable.reason is AnchoredRecoveryReason.ANCHOR_UNAVAILABLE
        ),
        "expired_readback_fails_closed": (
            expired.status is AnchoredRecoveryStatus.UNAVAILABLE
            and expired.reason is AnchoredRecoveryReason.ANCHOR_READBACK_STALE
        ),
        "trusted_floor_rejects_stale_anchor": (
            stale_anchor.reason is AnchoredRecoveryReason.ANCHOR_SEQUENCE_STALE
            and stale_anchor.fail_closed
        ),
        "trusted_floor_rejects_authority_equivocation": (
            equivocation.reason is AnchoredRecoveryReason.ANCHOR_EQUIVOCATION
            and equivocation.fail_closed
        ),
        "newer_fence_invalidates_prior_holder": (
            stale_fence_decision.reason is AnchoredRecoveryReason.FENCE_STALE
            and current_fence_decision.status
            is AnchoredRecoveryStatus.ADMISSION_READY
        ),
        "pending_effect_requires_recovery_not_admission": (
            pending_recovery.status is AnchoredRecoveryStatus.RECOVERY_REQUIRED
            and pending_recovery.reason
            is AnchoredRecoveryReason.LOCAL_RECOVERY_REQUIRED
            and not pending_recovery.admission_allowed
        ),
        "runtime_admission_port_denies_every_nonready_decision": all(
            admission_port.values()
        ),
        "stale_compare_and_advance_is_rejected": stale_cas_rejected,
    }
    return scenarios, gates


def _build_evidence(source_binding: dict[str, Any]) -> dict[str, Any]:
    scenarios, gates = _run_scenarios()
    if tuple(scenarios) != SCENARIO_NAMES or tuple(gates) != GATE_NAMES:
        raise CampaignError("anchor campaign emitted a non-closed result set")
    accepted = all(gates.values())
    semantic_projection = {
        "campaign_id": CAMPAIGN_ID,
        "scenarios": scenarios,
        "gates": gates,
        "accepted": accepted,
        "requirement_mapping": REQUIREMENT_MAPPING,
        "evidence_boundaries": list(EVIDENCE_BOUNDARIES),
    }
    evidence: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "generated_at": datetime.now(UTC).isoformat(),
        "source_binding": source_binding,
        "scenarios": scenarios,
        "gates": gates,
        "accepted": accepted,
        "requirement_mapping": REQUIREMENT_MAPPING,
        "evidence_boundaries": list(EVIDENCE_BOUNDARIES),
        "semantic_projection": semantic_projection,
        "semantic_outcome_sha256": _sha256(_canonical_bytes(semantic_projection)),
    }
    evidence["canonical_evidence_sha256"] = _sha256(_canonical_bytes(evidence))
    if not accepted:
        failed = [name for name in GATE_NAMES if not gates[name]]
        raise CampaignError("M4i anchor campaign gates failed: " + ", ".join(failed))
    return evidence


def _write_evidence(output_parent: Path, evidence: dict[str, Any]) -> Path:
    if not output_parent.is_dir() or output_parent.is_symlink():
        raise CampaignError("output parent must be an existing non-symlink directory")
    output = Path(tempfile.mkdtemp(prefix="aegis-ot-m4i-anchor-", dir=output_parent))
    output.chmod(0o700)
    path = output / "evidence.json"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        material = _canonical_bytes(evidence) + b"\n"
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    directory_descriptor = os.open(output, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return path


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CampaignError("evidence path must be a regular non-symlink file")
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_EVIDENCE_BYTES:
        raise CampaignError("evidence file is not a bounded regular file")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        decoded: dict[str, Any] = {}
        for key, value in pairs:
            if key in decoded:
                raise CampaignError(f"duplicate JSON key: {key}")
            decoded[key] = value
        return decoded

    try:
        decoded = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CampaignError("evidence was not strict UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise CampaignError("evidence root must be an object")
    return decoded


def verify_evidence(path: Path, *, source_root: Path | None = None) -> dict[str, Any]:
    evidence = _load_json(path)
    expected_keys = {
        "schema_version",
        "campaign_id",
        "generated_at",
        "source_binding",
        "scenarios",
        "gates",
        "accepted",
        "requirement_mapping",
        "evidence_boundaries",
        "semantic_projection",
        "semantic_outcome_sha256",
        "canonical_evidence_sha256",
    }
    errors: list[str] = []
    if set(evidence) != expected_keys:
        errors.append("evidence field set is not closed")
    if evidence.get("schema_version") != SCHEMA_VERSION:
        errors.append("evidence schema version is unsupported")
    if evidence.get("campaign_id") != CAMPAIGN_ID:
        errors.append("campaign identifier is unexpected")
    scenarios = evidence.get("scenarios")
    gates = evidence.get("gates")
    if not isinstance(scenarios, dict) or set(scenarios) != set(SCENARIO_NAMES):
        errors.append("scenario set is not closed")
    if not isinstance(gates, dict) or set(gates) != set(GATE_NAMES):
        errors.append("gate set is not closed")
    elif any(gates.get(name) is not True for name in GATE_NAMES):
        errors.append("one or more acceptance gates are not true")
    if evidence.get("accepted") is not True:
        errors.append("campaign is not accepted")
    if evidence.get("requirement_mapping") != REQUIREMENT_MAPPING:
        errors.append("requirement mapping changed")
    if evidence.get("evidence_boundaries") != list(EVIDENCE_BOUNDARIES):
        errors.append("evidence boundaries changed")
    semantic = evidence.get("semantic_projection")
    if not isinstance(semantic, dict) or evidence.get("semantic_outcome_sha256") != _sha256(
        _canonical_bytes(semantic)
    ):
        errors.append("semantic projection digest is invalid")
    expected_semantic = {
        "campaign_id": CAMPAIGN_ID,
        "scenarios": scenarios,
        "gates": gates,
        "accepted": evidence.get("accepted"),
        "requirement_mapping": evidence.get("requirement_mapping"),
        "evidence_boundaries": evidence.get("evidence_boundaries"),
    }
    if semantic != expected_semantic:
        errors.append("semantic projection is not bound to evidence results")
    canonical = dict(evidence)
    claimed_canonical = canonical.pop("canonical_evidence_sha256", None)
    if claimed_canonical != _sha256(_canonical_bytes(canonical)):
        errors.append("canonical evidence digest is invalid")
    source = evidence.get("source_binding")
    if not isinstance(source, dict):
        errors.append("source binding is missing")
    else:
        files = source.get("source_files_sha256")
        if (
            not isinstance(files, dict)
            or set(files) != set(SOURCE_BINDING_FILES)
            or any(
                not isinstance(value, str) or _SHA256.fullmatch(value) is None
                for value in files.values()
            )
            or source.get("source_fingerprint_sha256")
            != _sha256(_canonical_bytes(files))
            or source.get("clean_checkout") is not True
            or _GIT_OBJECT.fullmatch(str(source.get("git_commit", ""))) is None
            or _GIT_OBJECT.fullmatch(str(source.get("git_tree", ""))) is None
        ):
            errors.append("source binding is invalid")
        if source_root is not None:
            try:
                current = _source_binding(source_root)
            except CampaignError as exc:
                errors.append(str(exc))
            else:
                if current != source:
                    errors.append("evidence does not bind the supplied exact source")
    return {
        "valid": not errors,
        "errors": errors,
        "campaign_id": evidence.get("campaign_id"),
        "git_commit": source.get("git_commit") if isinstance(source, dict) else None,
        "source_fingerprint_sha256": (
            source.get("source_fingerprint_sha256")
            if isinstance(source, dict)
            else None
        ),
        "semantic_outcome_sha256": evidence.get("semantic_outcome_sha256"),
        "canonical_evidence_sha256": evidence.get("canonical_evidence_sha256"),
    }


def run_campaign(output_parent: Path, *, source_root: Path = ROOT) -> tuple[Path, dict[str, Any]]:
    evidence = _build_evidence(_source_binding(source_root))
    path = _write_evidence(output_parent, evidence)
    result = verify_evidence(path, source_root=source_root)
    if result["valid"] is not True:
        raise CampaignError("newly retained M4i anchor evidence did not verify")
    return path, result


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--verify", type=Path)
    parser.add_argument("--output-parent", type=Path, default=Path("/private/tmp"))
    parser.add_argument(
        "--bind-current-source",
        action="store_true",
        help="when verifying, also require the evidence to match this clean checkout",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        if arguments.run:
            path, result = run_campaign(arguments.output_parent.resolve())
            output = {"evidence_path": str(path), **result}
        else:
            source_root = ROOT if arguments.bind_current_source else None
            output = verify_evidence(arguments.verify.resolve(), source_root=source_root)
    except CampaignError as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, sort_keys=True))
        return 1
    print(json.dumps(output, sort_keys=True))
    return 0 if output.get("valid") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
