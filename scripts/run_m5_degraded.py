"""Run and offline-verify the deterministic M5 degraded-operation campaign.

This v2 companion does not alter the accepted M5 compromise campaign.  It
exercises the separately authorized pre-authorization gate for every required
role and service/path loss across unavailable, unknown, conflicting, untrusted,
and compromised conditions. Its results are local model evidence only; no
scenario dispatches a plant effect.
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
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import aegis_ot.m5_degraded as degraded
from aegis_ot.models import ActionProposal, Operation

ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = "aegis-ot-m5-degraded-operation-campaign-v2"
PLAN_SCHEMA = "aegis-ot-m5-degraded-operation-plan-v2"
CAMPAIGN_ID = "m5-bounded-degraded-operation-v2"
CAMPAIGN_TIME = datetime(2026, 8, 26, 15, 0, tzinfo=UTC)
AUTHORITY_ID = "m5-degraded-campaign-authority"
OUTPUT_PREFIX = "aegis-ot-m5-degraded-"
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SOURCE_PATHS = (
    "pyproject.toml",
    "scripts/run_m5_degraded.py",
    "src/aegis_ot/gateway.py",
    "src/aegis_ot/m5_degraded.py",
    "src/aegis_ot/segmented_capability_runtime.py",
)

SURFACES = ("service", "communication")
CONDITIONS = (
    degraded.RoleCondition.UNAVAILABLE,
    degraded.RoleCondition.UNKNOWN,
    degraded.RoleCondition.CONFLICTING,
    degraded.RoleCondition.UNTRUSTED,
    degraded.RoleCondition.COMPROMISED,
)

ACCEPTANCE_GATE_NAMES = (
    "role_loss_matrix_complete",
    "service_and_communication_paths_covered",
    "unavailable_unknown_conflicting_and_compromised_states_covered",
    "safe_and_hold_states_never_continue",
    "mission_preserving_is_management_only",
    "mission_preserving_enters_primary_assurance_only",
    "lease_scope_escape_is_held",
    "unresolved_effect_blocks_new_work",
    "missing_authorization_fails_safe",
    "signed_exact_lease_reversal_is_observable",
    "reversed_lease_cannot_continue_while_loss_persists",
    "all_results_deny_execution_authority",
    "exact_clean_source_bound",
    "private_key_material_not_retained",
    "formal_g5_and_operational_claims_remain_open",
)

EVIDENCE_LIMITS = (
    "Deterministic local model evidence only; the campaign invokes no plant adapter.",
    (
        "Mission-preserving means entry to the unchanged primary assurance path, "
        "not a permit or execution authorization."
    ),
    (
        "The role-loss behavior matrix is proposed and unapproved; TBR-019 and "
        "formal G5 acceptance remain open."
    ),
    (
        "Compromised and untrusted conditions are injected model inputs; the "
        "campaign does not prove live compromise detection."
    ),
    (
        "The campaign does not establish deployment, service availability, "
        "hostile-host resistance, independent validation, field effectiveness, "
        "or production readiness."
    ),
    (
        "The ephemeral signing key is not serialized; Python process memory is "
        "not guaranteed to be zeroized."
    ),
)

CLAIM_BOUNDARIES = {
    "execution_authorized_by_campaign": False,
    "plant_adapter_invoked": False,
    "approved_compromise_matrix": False,
    "tbr_019_resolved": False,
    "formal_g5_accepted": False,
    "deployment_established": False,
    "operational_effectiveness_established": False,
    "independent_validation_established": False,
}

REPORT_KEYS = {
    "schema_version",
    "campaign_id",
    "run_id",
    "campaign_time",
    "evidence_class",
    "requirements",
    "role_loss_policies",
    "scenarios",
    "negative_controls",
    "reversal",
    "key_material",
    "source_binding",
    "acceptance_gates",
    "accepted",
    "claim_boundaries",
    "evidence_limits",
    "semantic_outcome_sha256",
    "integrity",
}


class CampaignError(RuntimeError):
    """Raised when v2 degraded evidence cannot be safely produced or replayed."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _model_json(value: Any) -> dict[str, Any]:
    material = value.model_dump(mode="json")
    if not isinstance(material, dict):
        raise CampaignError("model serialization did not produce an object")
    return material


def _git(*args: str, binary: bool = False) -> bytes | str:
    executable = shutil.which("git")
    if executable is None:
        raise CampaignError("git is required for retained source binding")
    completed = subprocess.run(  # noqa: S603
        [executable, "-C", str(ROOT), *args],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise CampaignError(f"git {' '.join(args)} failed: {detail}")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CampaignError(f"git {' '.join(args)} returned non-UTF-8 output") from exc


def _source_fingerprint_material(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "git_commit": binding["git_commit"],
        "git_tree": binding["git_tree"],
        "source_files": binding["source_files"],
    }


def _assert_clean_source() -> dict[str, Any]:
    module_path = Path(degraded.__file__ or "").resolve()
    expected_module = (ROOT / "src" / "aegis_ot" / "m5_degraded.py").resolve()
    if module_path != expected_module:
        raise CampaignError(
            f"M5 degraded module imported from stale source: {module_path}"
        )
    top_level = Path(str(_git("rev-parse", "--show-toplevel")).strip()).resolve()
    if top_level != ROOT.resolve():
        raise CampaignError("runner is not executing from its authoritative checkout")
    if str(_git("status", "--porcelain=v1", "--untracked-files=all")):
        raise CampaignError("retained M5 degraded execution requires an exact clean checkout")

    commit = str(_git("rev-parse", "HEAD^{commit}")).strip()
    tree = str(_git("rev-parse", "HEAD^{tree}")).strip()
    if not GIT_OBJECT_RE.fullmatch(commit) or not GIT_OBJECT_RE.fullmatch(tree):
        raise CampaignError("git returned a noncanonical commit or tree object ID")
    source_files: list[dict[str, Any]] = []
    for relative in SOURCE_PATHS:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise CampaignError(f"required source is missing or symlinked: {relative}")
        working = path.read_bytes()
        committed_raw = _git("show", f"{commit}:{relative}", binary=True)
        assert isinstance(committed_raw, bytes)
        if working != committed_raw:
            raise CampaignError(f"required source differs from commit: {relative}")
        blob = str(_git("rev-parse", f"{commit}:{relative}")).strip()
        if not GIT_OBJECT_RE.fullmatch(blob):
            raise CampaignError(f"git returned a noncanonical blob ID for {relative}")
        source_files.append(
            {
                "path": relative,
                "bytes": len(working),
                "sha256": _sha256_bytes(working),
                "git_blob": blob,
            }
        )
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


def _verify_source_binding_shape(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "git_commit",
        "git_tree",
        "clean_checkout",
        "source_files",
        "source_fingerprint_sha256",
    }:
        raise CampaignError("source binding has the wrong shape")
    if value["clean_checkout"] is not True:
        raise CampaignError("source binding does not attest a clean checkout")
    if not GIT_OBJECT_RE.fullmatch(value["git_commit"]):
        raise CampaignError("source commit is noncanonical")
    if not GIT_OBJECT_RE.fullmatch(value["git_tree"]):
        raise CampaignError("source tree is noncanonical")
    files = value["source_files"]
    if not isinstance(files, list) or [item.get("path") for item in files] != list(
        SOURCE_PATHS
    ):
        raise CampaignError("source binding does not contain the exact source path set")
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "bytes",
            "sha256",
            "git_blob",
        }:
            raise CampaignError("source file binding has the wrong shape")
        if not isinstance(item["bytes"], int) or item["bytes"] < 1:
            raise CampaignError("source file byte count is invalid")
        if not SHA256_RE.fullmatch(item["sha256"]):
            raise CampaignError("source file SHA-256 is invalid")
        if not GIT_OBJECT_RE.fullmatch(item["git_blob"]):
            raise CampaignError("source file blob is invalid")
    expected = _sha256_json(_source_fingerprint_material(value))
    if value["source_fingerprint_sha256"] != expected:
        raise CampaignError("source fingerprint does not match its material")


def _healthy_conditions() -> dict[degraded.DegradedRole, degraded.RoleCondition]:
    return {role: degraded.RoleCondition.HEALTHY for role in degraded.DegradedRole}


def _snapshot(
    case_id: str,
    *,
    role: degraded.DegradedRole | None = None,
    surface: str = "service",
    condition: degraded.RoleCondition = degraded.RoleCondition.UNAVAILABLE,
    unresolved_effect: bool = False,
) -> degraded.DegradedRuntimeSnapshot:
    services = _healthy_conditions()
    communications = _healthy_conditions()
    if role is not None:
        target = communications if surface == "communication" else services
        target[role] = condition
    return degraded.DegradedRuntimeSnapshot(
        snapshot_id=f"m5-degraded-snapshot-{case_id}",
        captured_at=CAMPAIGN_TIME,
        role_conditions=services,
        communication_conditions=communications,
        unresolved_effect=unresolved_effect,
    )


def _proposal(
    case_id: str,
    *,
    mission_id: str = "microgrid-containment",
    resource: str = "feeder-1",
    operation: Operation = Operation.ISOLATE_ASSET,
    risk_score: float = 60.0,
) -> ActionProposal:
    return ActionProposal(
        proposal_id=f"m5-degraded-proposal-{case_id}",
        actor_id="agent:operator-1",
        mission_id=mission_id,
        resource=resource,
        operation=operation,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=1,
        observed_at=CAMPAIGN_TIME,
        submitted_at=CAMPAIGN_TIME,
        nonce=f"m5-degraded-proposal-nonce-{case_id}",
        confidence=0.9,
        risk_score=risk_score,
        delegation_chain=("grant-root", "grant-leaf"),
    )


def _authorization(
    private_key: Ed25519PrivateKey,
    snapshot: degraded.DegradedRuntimeSnapshot,
    *,
    case_id: str,
    role: degraded.DegradedRole,
    sequence: int,
    allowed_resources: frozenset[str] = frozenset({"feeder-1"}),
) -> degraded.DegradedModeAuthorization:
    return degraded.DegradedModeAuthorization(
        authorization_id=f"m5-degraded-authorization-{case_id}",
        sequence=sequence,
        authority_id=AUTHORITY_ID,
        mode_name=f"{role.value}-loss-{case_id}",
        behavior=degraded.ROLE_LOSS_POLICIES[role].behavior,
        affected_roles=frozenset({role}),
        allowed_actor_ids=frozenset({"agent:operator-1"}),
        allowed_mission_ids=frozenset({"microgrid-containment"}),
        allowed_resources=allowed_resources,
        allowed_operations=frozenset({Operation.ISOLATE_ASSET}),
        maximum_risk_score=65.0,
        snapshot_sha256=snapshot.digest,
        recovery_checkpoint_id=f"m5-degraded-recovery-{case_id}",
        nonce=f"m5-degraded-authorization-nonce-{case_id}",
        issued_at=CAMPAIGN_TIME - timedelta(seconds=1),
        expires_at=CAMPAIGN_TIME + timedelta(minutes=2),
    ).signed(private_key)


def _gate(
    public_key: Ed25519PublicKey,
    snapshot_source: Any,
    authorization_source: Any,
) -> degraded.DegradedOperationGate:
    return degraded.DegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=public_key,
        snapshot_source=snapshot_source,
        authorization_source=authorization_source,
    )


def _role_policy_catalog() -> list[dict[str, Any]]:
    return [
        {
            "role": role.value,
            **_model_json(degraded.ROLE_LOSS_POLICIES[role]),
        }
        for role in degraded.DegradedRole
    ]


def _build_scenarios(private_key: Ed25519PrivateKey) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    sequence = 1
    for role in degraded.DegradedRole:
        for surface in SURFACES:
            for condition in CONDITIONS:
                case_id = f"{role.value}-{surface}-{condition.value}"
                snapshot = _snapshot(
                    case_id,
                    role=role,
                    surface=surface,
                    condition=condition,
                )
                authorization = _authorization(
                    private_key,
                    snapshot,
                    case_id=case_id,
                    role=role,
                    sequence=sequence,
                )
                proposal = _proposal(case_id)
                result = _gate(
                    private_key.public_key(),
                    lambda value=snapshot: value,
                    lambda value=authorization: value,
                ).evaluate(proposal, now=CAMPAIGN_TIME)
                scenarios.append(
                    {
                        "case_id": case_id,
                        "role": role.value,
                        "surface": surface,
                        "condition": condition.value,
                        "snapshot": _model_json(snapshot),
                        "authorization": _model_json(authorization),
                        "proposal": _model_json(proposal),
                        "result": _model_json(result),
                        "plant_adapter_invoked": False,
                    }
                )
                sequence += 1
    return scenarios


def _build_negative_controls(
    private_key: Ed25519PrivateKey,
    *,
    sequence_start: int,
) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []

    missing_snapshot = _snapshot(
        "missing-authorization",
        role=degraded.DegradedRole.OBSERVER,
        condition=degraded.RoleCondition.UNKNOWN,
    )
    missing_proposal = _proposal("missing-authorization")
    missing_result = _gate(
        private_key.public_key(),
        lambda: missing_snapshot,
        lambda: None,
    ).evaluate(missing_proposal, now=CAMPAIGN_TIME)
    controls.append(
        {
            "case_id": "missing-authorization",
            "kind": "missing_authorization",
            "snapshot": _model_json(missing_snapshot),
            "authorization": None,
            "proposal": _model_json(missing_proposal),
            "result": _model_json(missing_result),
            "plant_adapter_invoked": False,
        }
    )

    scope_snapshot = _snapshot(
        "management-scope-escape",
        role=degraded.DegradedRole.MANAGEMENT,
    )
    scope_authorization = _authorization(
        private_key,
        scope_snapshot,
        case_id="management-scope-escape",
        role=degraded.DegradedRole.MANAGEMENT,
        sequence=sequence_start,
        allowed_resources=frozenset({"feeder-2"}),
    )
    scope_proposal = _proposal("management-scope-escape")
    scope_result = _gate(
        private_key.public_key(),
        lambda: scope_snapshot,
        lambda: scope_authorization,
    ).evaluate(scope_proposal, now=CAMPAIGN_TIME)
    controls.append(
        {
            "case_id": "management-scope-escape",
            "kind": "scope_escape",
            "snapshot": _model_json(scope_snapshot),
            "authorization": _model_json(scope_authorization),
            "proposal": _model_json(scope_proposal),
            "result": _model_json(scope_result),
            "plant_adapter_invoked": False,
        }
    )

    unresolved_snapshot = _snapshot(
        "management-unresolved-effect",
        role=degraded.DegradedRole.MANAGEMENT,
        unresolved_effect=True,
    )
    unresolved_authorization = _authorization(
        private_key,
        unresolved_snapshot,
        case_id="management-unresolved-effect",
        role=degraded.DegradedRole.MANAGEMENT,
        sequence=sequence_start + 1,
    )
    unresolved_proposal = _proposal("management-unresolved-effect")
    unresolved_result = _gate(
        private_key.public_key(),
        lambda: unresolved_snapshot,
        lambda: unresolved_authorization,
    ).evaluate(unresolved_proposal, now=CAMPAIGN_TIME)
    controls.append(
        {
            "case_id": "management-unresolved-effect",
            "kind": "unresolved_effect",
            "snapshot": _model_json(unresolved_snapshot),
            "authorization": _model_json(unresolved_authorization),
            "proposal": _model_json(unresolved_proposal),
            "result": _model_json(unresolved_result),
            "plant_adapter_invoked": False,
        }
    )
    return controls


def _build_reversal(
    private_key: Ed25519PrivateKey,
    *,
    sequence: int,
) -> dict[str, Any]:
    degraded_snapshot = _snapshot(
        "signed-reversal",
        role=degraded.DegradedRole.MANAGEMENT,
    )
    authorization = _authorization(
        private_key,
        degraded_snapshot,
        case_id="signed-reversal",
        role=degraded.DegradedRole.MANAGEMENT,
        sequence=sequence,
    )
    proposal = _proposal("signed-reversal")
    current = {"snapshot": degraded_snapshot}
    gate = _gate(
        private_key.public_key(),
        lambda: current["snapshot"],
        lambda: authorization,
    )
    before = gate.evaluate(proposal, now=CAMPAIGN_TIME)
    current["snapshot"] = _snapshot("signed-reversal-recovered")
    awaiting_reversal = gate.evaluate(proposal, now=CAMPAIGN_TIME)
    reversal = degraded.DegradedModeReversal(
        reversal_id="m5-degraded-reversal-signed-reversal",
        sequence=1,
        authority_id=AUTHORITY_ID,
        authorization_id=authorization.authorization_id,
        authorization_sha256=authorization.digest,
        recovery_checkpoint_id=authorization.recovery_checkpoint_id,
        reason_code="runtime_dependencies_recovered",
        nonce="m5-degraded-reversal-nonce-signed-reversal",
        issued_at=CAMPAIGN_TIME,
    ).signed(private_key)
    reversal_result = gate.apply_reversal(reversal, authorization, now=CAMPAIGN_TIME)
    after = gate.evaluate(proposal, now=CAMPAIGN_TIME)
    current["snapshot"] = degraded_snapshot
    loss_persists = gate.evaluate(proposal, now=CAMPAIGN_TIME)
    return {
        "case_id": "signed-exact-lease-reversal",
        "degraded_snapshot": _model_json(degraded_snapshot),
        "healthy_snapshot": _model_json(_snapshot("signed-reversal-recovered")),
        "authorization": _model_json(authorization),
        "proposal": _model_json(proposal),
        "before_recovery": _model_json(before),
        "awaiting_reversal": _model_json(awaiting_reversal),
        "reversal": _model_json(reversal),
        "reversal_result": _model_json(reversal_result),
        "after_reversal": _model_json(after),
        "loss_persists_after_reversal": _model_json(loss_persists),
        "plant_adapter_invoked": False,
    }


def _acceptance_gates(
    scenarios: Sequence[Mapping[str, Any]],
    negative_controls: Sequence[Mapping[str, Any]],
    reversal: Mapping[str, Any],
    source_binding: Mapping[str, Any],
    *,
    private_key_material_retained: bool,
) -> dict[str, bool]:
    expected_cases = len(degraded.DegradedRole) * len(SURFACES) * len(CONDITIONS)
    expected_matrix = {
        (role.value, surface, condition.value)
        for role in degraded.DegradedRole
        for surface in SURFACES
        for condition in CONDITIONS
    }
    actual_matrix = {
        (item["role"], item["surface"], item["condition"])
        for item in scenarios
    }
    roles = {item["role"] for item in scenarios}
    surfaces = {item["surface"] for item in scenarios}
    conditions = {item["condition"] for item in scenarios}
    management = [
        item for item in scenarios if item["role"] == degraded.DegradedRole.MANAGEMENT.value
    ]
    protected = [
        item for item in scenarios if item["role"] != degraded.DegradedRole.MANAGEMENT.value
    ]
    negative_by_kind = {item["kind"]: item for item in negative_controls}
    gates = {
        "role_loss_matrix_complete": (
            len(scenarios) == expected_cases
            and roles == {role.value for role in degraded.DegradedRole}
            and actual_matrix == expected_matrix
        ),
        "service_and_communication_paths_covered": surfaces == set(SURFACES),
        "unavailable_unknown_conflicting_and_compromised_states_covered": conditions
        == {condition.value for condition in CONDITIONS},
        "safe_and_hold_states_never_continue": all(
            item["result"]["outcome"] in {"safe_state", "hold_state"}
            and item["result"]["may_enter_primary_assurance"] is False
            for item in protected
        ),
        "mission_preserving_is_management_only": (
            {role.value for role, policy in degraded.ROLE_LOSS_POLICIES.items()
             if policy.mission_preserving_eligible}
            == {degraded.DegradedRole.MANAGEMENT.value}
        ),
        "mission_preserving_enters_primary_assurance_only": all(
            item["result"]["outcome"] == "continue_primary_assurance"
            and item["result"]["may_enter_primary_assurance"] is True
            and item["result"]["execution_authorized"] is False
            for item in management
        ),
        "lease_scope_escape_is_held": (
            negative_by_kind["scope_escape"]["result"]["outcome"] == "hold_state"
            and "degraded_resource_out_of_scope"
            in negative_by_kind["scope_escape"]["result"]["reasons"]
        ),
        "unresolved_effect_blocks_new_work": (
            negative_by_kind["unresolved_effect"]["result"]["outcome"] == "safe_state"
            and "degraded_unresolved_effect_blocks_new_work"
            in negative_by_kind["unresolved_effect"]["result"]["reasons"]
        ),
        "missing_authorization_fails_safe": (
            negative_by_kind["missing_authorization"]["result"]["outcome"]
            == "safe_state"
        ),
        "signed_exact_lease_reversal_is_observable": (
            reversal["reversal_result"]["applied"] is True
            and reversal["after_reversal"]["outcome"]
            == "continue_primary_assurance"
            and reversal["awaiting_reversal"]["outcome"] == "hold_state"
        ),
        "reversed_lease_cannot_continue_while_loss_persists": (
            reversal["loss_persists_after_reversal"]["outcome"] == "safe_state"
            and "degraded_authorization_revoked"
            in reversal["loss_persists_after_reversal"]["reasons"]
        ),
        "all_results_deny_execution_authority": all(
            item["result"]["execution_authorized"] is False
            and item["plant_adapter_invoked"] is False
            for item in (*scenarios, *negative_controls)
        )
        and all(
            reversal[name]["execution_authorized"] is False
            for name in (
                "before_recovery",
                "awaiting_reversal",
                "after_reversal",
                "loss_persists_after_reversal",
            )
        )
        and reversal["plant_adapter_invoked"] is False,
        "exact_clean_source_bound": source_binding.get("clean_checkout") is True,
        "private_key_material_not_retained": not private_key_material_retained,
        "formal_g5_and_operational_claims_remain_open": True,
    }
    if tuple(gates) != ACCEPTANCE_GATE_NAMES:
        raise CampaignError("acceptance gate order changed")
    return gates


def _semantic_projection(report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "campaign_id": report["campaign_id"],
        "role_loss_policies": report["role_loss_policies"],
        "scenarios": [
            {
                "case_id": item["case_id"],
                "role": item["role"],
                "surface": item["surface"],
                "condition": item["condition"],
                "outcome": item["result"]["outcome"],
                "reasons": item["result"]["reasons"],
                "may_enter_primary_assurance": item["result"][
                    "may_enter_primary_assurance"
                ],
                "execution_authorized": item["result"]["execution_authorized"],
            }
            for item in report["scenarios"]
        ],
        "negative_controls": [
            {
                "case_id": item["case_id"],
                "kind": item["kind"],
                "outcome": item["result"]["outcome"],
                "reasons": item["result"]["reasons"],
            }
            for item in report["negative_controls"]
        ],
        "reversal": {
            "awaiting_reversal": report["reversal"]["awaiting_reversal"]["outcome"],
            "applied": report["reversal"]["reversal_result"]["applied"],
            "after_reversal": report["reversal"]["after_reversal"]["outcome"],
            "loss_persists": report["reversal"]["loss_persists_after_reversal"][
                "outcome"
            ],
        },
        "acceptance_gates": report["acceptance_gates"],
        "claim_boundaries": report["claim_boundaries"],
    }


def build_plan() -> dict[str, Any]:
    return {
        "schema_version": PLAN_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "execution_mode": "plan_only",
        "execution_claimed": False,
        "case_count": len(degraded.DegradedRole) * len(SURFACES) * len(CONDITIONS),
        "roles": [role.value for role in degraded.DegradedRole],
        "surfaces": list(SURFACES),
        "conditions": [condition.value for condition in CONDITIONS],
        "acceptance_gate_names": list(ACCEPTANCE_GATE_NAMES),
        "evidence_limits": list(EVIDENCE_LIMITS),
    }


def _build_report(source_binding: Mapping[str, Any]) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes_raw()
    ).decode("ascii")
    scenarios = _build_scenarios(private_key)
    negative_controls = _build_negative_controls(
        private_key,
        sequence_start=len(scenarios) + 1,
    )
    reversal = _build_reversal(private_key, sequence=len(scenarios) + 3)
    private_key_material_retained = False
    gates = _acceptance_gates(
        scenarios,
        negative_controls,
        reversal,
        source_binding,
        private_key_material_retained=private_key_material_retained,
    )
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "run_id": str(uuid4()),
        "campaign_time": CAMPAIGN_TIME.isoformat(),
        "evidence_class": "deterministic_local_model",
        "requirements": ["AOT-RES-002", "AOT-RES-003", "AOT-RES-004", "AOT-RES-007"],
        "role_loss_policies": _role_policy_catalog(),
        "scenarios": scenarios,
        "negative_controls": negative_controls,
        "reversal": reversal,
        "key_material": {
            "authority_id": AUTHORITY_ID,
            "authority_public_key_base64": public_key_b64,
            "private_key_material_retained": private_key_material_retained,
        },
        "source_binding": dict(source_binding),
        "acceptance_gates": gates,
        "accepted": all(gates.values()),
        "claim_boundaries": dict(CLAIM_BOUNDARIES),
        "evidence_limits": list(EVIDENCE_LIMITS),
    }
    report["semantic_outcome_sha256"] = _sha256_json(_semantic_projection(report))
    report["integrity"] = {"canonical_payload_sha256": _sha256_json(report)}
    return report


def _public_key(report: Mapping[str, Any]) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(
            report["key_material"]["authority_public_key_base64"],
            validate=True,
        )
        return Ed25519PublicKey.from_public_bytes(raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise CampaignError("authority public key is invalid") from exc


def _contains_private_material(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if (
                isinstance(key, str)
                and "private" in key.lower()
                and key
                not in {
                    "private_key_material_retained",
                    "private_key_material_not_retained",
                }
            ):
                return True
            if _contains_private_material(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_private_material(item) for item in value)
    return isinstance(value, str) and "BEGIN PRIVATE KEY" in value


def _replay_scenario(
    item: Mapping[str, Any],
    public_key: Ed25519PublicKey,
) -> None:
    try:
        snapshot = degraded.DegradedRuntimeSnapshot.model_validate(item["snapshot"])
        authorization = degraded.DegradedModeAuthorization.model_validate(
            item["authorization"]
        )
        proposal = ActionProposal.model_validate(item["proposal"])
        retained = degraded.DegradedAdmissionResult.model_validate(item["result"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CampaignError("scenario material is invalid") from exc
    try:
        role = degraded.DegradedRole(item["role"])
        condition = degraded.RoleCondition(item["condition"])
        surface = str(item["surface"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CampaignError("scenario catalog metadata is invalid") from exc
    expected_case_id = f"{role.value}-{surface}-{condition.value}"
    if item.get("case_id") != expected_case_id or surface not in SURFACES:
        raise CampaignError("scenario catalog metadata does not match its case ID")
    expected_services = _healthy_conditions()
    expected_communications = _healthy_conditions()
    target = expected_communications if surface == "communication" else expected_services
    target[role] = condition
    if (
        dict(snapshot.role_conditions) != expected_services
        or dict(snapshot.communication_conditions) != expected_communications
        or authorization.affected_roles != frozenset({role})
        or authorization.behavior is not degraded.ROLE_LOSS_POLICIES[role].behavior
    ):
        raise CampaignError("scenario material does not match its role-loss metadata")
    replayed = _gate(
        public_key,
        lambda: snapshot,
        lambda: authorization,
    ).evaluate(proposal, now=CAMPAIGN_TIME)
    if replayed != retained:
        raise CampaignError(f"scenario {item.get('case_id')} does not replay exactly")


def _replay_negative(
    item: Mapping[str, Any],
    public_key: Ed25519PublicKey,
) -> None:
    try:
        snapshot = degraded.DegradedRuntimeSnapshot.model_validate(item["snapshot"])
        authorization_raw = item["authorization"]
        authorization = (
            None
            if authorization_raw is None
            else degraded.DegradedModeAuthorization.model_validate(authorization_raw)
        )
        proposal = ActionProposal.model_validate(item["proposal"])
        retained = degraded.DegradedAdmissionResult.model_validate(item["result"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CampaignError("negative-control material is invalid") from exc
    replayed = _gate(
        public_key,
        lambda: snapshot,
        lambda: authorization,
    ).evaluate(proposal, now=CAMPAIGN_TIME)
    if replayed != retained:
        raise CampaignError(f"negative control {item.get('case_id')} does not replay exactly")


def _replay_reversal(value: Mapping[str, Any], public_key: Ed25519PublicKey) -> None:
    try:
        degraded_snapshot = degraded.DegradedRuntimeSnapshot.model_validate(
            value["degraded_snapshot"]
        )
        healthy_snapshot = degraded.DegradedRuntimeSnapshot.model_validate(
            value["healthy_snapshot"]
        )
        authorization = degraded.DegradedModeAuthorization.model_validate(
            value["authorization"]
        )
        proposal = ActionProposal.model_validate(value["proposal"])
        reversal = degraded.DegradedModeReversal.model_validate(value["reversal"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CampaignError("reversal material is invalid") from exc
    current = {"snapshot": degraded_snapshot}
    gate = _gate(public_key, lambda: current["snapshot"], lambda: authorization)
    before = gate.evaluate(proposal, now=CAMPAIGN_TIME)
    current["snapshot"] = healthy_snapshot
    awaiting = gate.evaluate(proposal, now=CAMPAIGN_TIME)
    reversal_result = gate.apply_reversal(reversal, authorization, now=CAMPAIGN_TIME)
    after = gate.evaluate(proposal, now=CAMPAIGN_TIME)
    current["snapshot"] = degraded_snapshot
    loss_persists = gate.evaluate(proposal, now=CAMPAIGN_TIME)
    retained_pairs = (
        (before, value["before_recovery"]),
        (awaiting, value["awaiting_reversal"]),
        (reversal_result, value["reversal_result"]),
        (after, value["after_reversal"]),
        (loss_persists, value["loss_persists_after_reversal"]),
    )
    if any(_model_json(actual) != retained for actual, retained in retained_pairs):
        raise CampaignError("signed reversal does not replay exactly")


def _verify_report_payload(
    report: Any,
    *,
    expected_source_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise CampaignError("evidence root must be an object")
    if set(report) != REPORT_KEYS:
        raise CampaignError("evidence root has the wrong field set")
    integrity = report.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {"canonical_payload_sha256"}:
        raise CampaignError("evidence integrity block is invalid")
    payload = dict(report)
    payload.pop("integrity")
    if integrity["canonical_payload_sha256"] != _sha256_json(payload):
        raise CampaignError("evidence canonical payload digest mismatch")
    if report.get("schema_version") != REPORT_SCHEMA or report.get("campaign_id") != CAMPAIGN_ID:
        raise CampaignError("evidence schema or campaign ID is unsupported")
    if report.get("campaign_time") != CAMPAIGN_TIME.isoformat():
        raise CampaignError("campaign time changed")
    if report.get("evidence_class") != "deterministic_local_model":
        raise CampaignError("evidence class changed")
    if report.get("requirements") != [
        "AOT-RES-002",
        "AOT-RES-003",
        "AOT-RES-004",
        "AOT-RES-007",
    ]:
        raise CampaignError("requirement mapping changed")
    if report.get("role_loss_policies") != _role_policy_catalog():
        raise CampaignError("role-loss policy catalog changed")
    _verify_source_binding_shape(report.get("source_binding"))
    if expected_source_binding is not None and report["source_binding"] != dict(
        expected_source_binding
    ):
        raise CampaignError("evidence source binding differs from the expected source")
    public_key = _public_key(report)
    scenarios = report.get("scenarios")
    negative_controls = report.get("negative_controls")
    reversal = report.get("reversal")
    if not isinstance(scenarios, list) or len(scenarios) != (
        len(degraded.DegradedRole) * len(SURFACES) * len(CONDITIONS)
    ):
        raise CampaignError("scenario matrix is incomplete")
    if not isinstance(negative_controls, list) or len(negative_controls) != 3:
        raise CampaignError("negative-control catalog is incomplete")
    if not isinstance(reversal, dict):
        raise CampaignError("reversal evidence is missing")
    if len({item.get("case_id") for item in scenarios}) != len(scenarios):
        raise CampaignError("scenario IDs are not unique")
    for item in scenarios:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "case_id",
                "role",
                "surface",
                "condition",
                "snapshot",
                "authorization",
                "proposal",
                "result",
                "plant_adapter_invoked",
            }
            or item.get("plant_adapter_invoked") is not False
        ):
            raise CampaignError("scenario shape or plant boundary is invalid")
        _replay_scenario(item, public_key)
    for item in negative_controls:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "case_id",
                "kind",
                "snapshot",
                "authorization",
                "proposal",
                "result",
                "plant_adapter_invoked",
            }
            or item.get("plant_adapter_invoked") is not False
        ):
            raise CampaignError("negative-control shape or plant boundary is invalid")
        _replay_negative(item, public_key)
    if {item["kind"] for item in negative_controls} != {
        "missing_authorization",
        "scope_escape",
        "unresolved_effect",
    }:
        raise CampaignError("negative-control kinds changed")
    if set(reversal) != {
        "case_id",
        "degraded_snapshot",
        "healthy_snapshot",
        "authorization",
        "proposal",
        "before_recovery",
        "awaiting_reversal",
        "reversal",
        "reversal_result",
        "after_reversal",
        "loss_persists_after_reversal",
        "plant_adapter_invoked",
    } or reversal.get("plant_adapter_invoked") is not False:
        raise CampaignError("reversal evidence shape or plant boundary is invalid")
    _replay_reversal(reversal, public_key)
    key_material = report.get("key_material")
    if (
        not isinstance(key_material, dict)
        or set(key_material)
        != {
            "authority_id",
            "authority_public_key_base64",
            "private_key_material_retained",
        }
        or key_material.get("private_key_material_retained") is not False
        or key_material.get("authority_id") != AUTHORITY_ID
        or _contains_private_material(report)
    ):
        raise CampaignError("private-key retention boundary is invalid")
    gates = _acceptance_gates(
        scenarios,
        negative_controls,
        reversal,
        report["source_binding"],
        private_key_material_retained=False,
    )
    if report.get("acceptance_gates") != gates or report.get("accepted") is not all(
        gates.values()
    ):
        raise CampaignError("acceptance disposition does not replay")
    if report.get("semantic_outcome_sha256") != _sha256_json(
        _semantic_projection(report)
    ):
        raise CampaignError("semantic outcome digest mismatch")
    boundaries = report.get("claim_boundaries")
    if boundaries != CLAIM_BOUNDARIES:
        raise CampaignError("formal or operational claim boundary was overstated")
    if report.get("evidence_limits") != list(EVIDENCE_LIMITS):
        raise CampaignError("evidence limits changed")
    return report


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CampaignError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_report(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CampaignError("evidence path must be a regular non-symlink file")
    size = path.stat().st_size
    if size < 2 or size > MAX_EVIDENCE_BYTES:
        raise CampaignError("evidence file is outside the verifier size limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CampaignError("evidence file is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CampaignError("evidence root must be an object")
    return value


def verify_evidence(path: Path) -> dict[str, Any]:
    return _verify_report_payload(_load_report(path))


def run_campaign(output_parent: Path) -> Path:
    parent = output_parent.expanduser().resolve()
    if ROOT.resolve() == parent or ROOT.resolve() in parent.parents:
        raise CampaignError("retained evidence must be written outside the source checkout")
    parent.mkdir(parents=True, exist_ok=True)
    source_binding = _assert_clean_source()
    report = _build_report(source_binding)
    _verify_report_payload(report, expected_source_binding=source_binding)
    output_dir = Path(tempfile.mkdtemp(prefix=OUTPUT_PREFIX, dir=parent))
    os.chmod(output_dir, 0o700)
    output_path = output_dir / "evidence.json"
    descriptor = os.open(
        output_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical_bytes(report) + b"\n")
    except Exception:
        output_path.unlink(missing_ok=True)
        output_dir.rmdir()
        raise
    if stat.S_IMODE(output_dir.stat().st_mode) != 0o700:
        raise CampaignError("retained evidence directory is not private")
    if stat.S_IMODE(output_path.stat().st_mode) != 0o600:
        raise CampaignError("retained evidence file is not private")
    verify_evidence(output_path)
    return output_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="print the fixed plan")
    mode.add_argument("--run", action="store_true", help="run and retain the campaign")
    mode.add_argument("--verify", type=Path, help="offline-verify retained evidence")
    parser.add_argument(
        "--output-parent",
        type=Path,
        default=Path("/private/tmp"),
        help="parent directory for a new private retained-evidence directory",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify is not None:
            report = verify_evidence(args.verify)
            result = {
                "valid": True,
                "accepted": report["accepted"],
                "campaign_id": report["campaign_id"],
                "semantic_outcome_sha256": report["semantic_outcome_sha256"],
                "source_fingerprint_sha256": report["source_binding"][
                    "source_fingerprint_sha256"
                ],
            }
        elif args.run:
            path = run_campaign(args.output_parent)
            report = verify_evidence(path)
            result = {
                "evidence_path": str(path),
                "accepted": report["accepted"],
                "semantic_outcome_sha256": report["semantic_outcome_sha256"],
                "source_fingerprint_sha256": report["source_binding"][
                    "source_fingerprint_sha256"
                ],
            }
        else:
            result = build_plan()
    except CampaignError as exc:
        print(f"M5 degraded campaign failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
