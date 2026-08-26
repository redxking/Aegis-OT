"""Run and offline-verify the deterministic M5 compromise campaign.

The campaign exercises only the M5 admission and administrative recovery
contracts.  A mission result that continues may enter the primary assurance
pipeline; it is not an execution permit.  Recovery operations cannot encode a
plant-control action and this runner never invokes a plant adapter.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import aegis_ot.m5_compromise as m5

ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = "aegis-ot-m5-compromise-campaign-v1"
PLAN_SCHEMA = "aegis-ot-m5-compromise-plan-v1"
SEMANTIC_PROJECTION_VERSION = "aegis-ot-m5-semantic-projection-v1"
CAMPAIGN_ID = "m5-operate-through-compromise-v1"
CAMPAIGN_TIME = datetime(2026, 8, 25, 21, 0, tzinfo=UTC)
AUTHORITY_ID = "m5-recovery-authority"
RECOVERY_SUBJECT = "m5-recovery-controller"
OUTPUT_PREFIX = "aegis-ot-m5-compromise-"
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")

SOURCE_PATHS = (
    "pyproject.toml",
    "scripts/run_m5_compromise.py",
    "src/aegis_ot/crypto.py",
    "src/aegis_ot/m5_compromise.py",
)

SCENARIO_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "scenario_id": "m5-01-compromised-leaf-branch-isolation",
        "category": "compromised_leaf_and_unrelated_branch",
        "requirements": [
            "compromised leaf is quarantined",
            "unrelated healthy branch may continue only to primary assurance",
            "neither M5 result authorizes execution",
        ],
        "mission_case_ids": ["compromised-leaf", "unrelated-healthy-branch"],
        "recovery_case_ids": [],
    },
    {
        "scenario_id": "m5-02-affected-supervisor-descendants",
        "category": "supervisor_compromise_and_revocation",
        "requirements": [
            "compromised supervisor blocks descendant",
            "revoked supervisor blocks descendant",
        ],
        "mission_case_ids": ["compromised-supervisor", "revoked-supervisor"],
        "recovery_case_ids": [],
    },
    {
        "scenario_id": "m5-03-assurance-service-failures",
        "category": "assurance_service_failure_and_bounded_recovery",
        "requirements": [
            "identity policy evidence and gateway faults fail closed",
            "unavailable and untrusted conditions are both covered",
            "service recovery authorization is administrative only",
        ],
        "mission_case_ids": [
            f"{service.value}-{condition.value}"
            for service in m5.AssuranceService
            for condition in (m5.ServiceCondition.UNAVAILABLE, m5.ServiceCondition.UNTRUSTED)
        ],
        "recovery_case_ids": [
            f"restore-{service.value}-{condition.value}"
            for service in m5.AssuranceService
            for condition in (m5.ServiceCondition.UNAVAILABLE, m5.ServiceCondition.UNTRUSTED)
        ],
    },
    {
        "scenario_id": "m5-04-telemetry-integrity",
        "category": "nonfresh_or_untrustworthy_telemetry",
        "requirements": [
            "delayed replayed biased contradictory and unavailable telemetry fail closed",
        ],
        "mission_case_ids": [
            "telemetry-delayed",
            "telemetry-replayed",
            "telemetry-biased",
            "telemetry-contradictory",
            "telemetry-unavailable",
        ],
        "recovery_case_ids": [],
    },
    {
        "scenario_id": "m5-05-quarantine-release",
        "category": "quarantine_release_authority_and_reconciliation",
        "requirements": [
            "unresolved effects block fresh mission work and release",
            "release requires exact evidence and pinned signed authority",
            "release requires completed reconciliation",
            "authorization replay fails closed",
            "recovery contract contains no plant-control operation",
        ],
        "mission_case_ids": ["unresolved-effect-fresh-work"],
        "recovery_case_ids": [
            "release-unresolved-effect",
            "release-incomplete-reconciliation",
            "release-forged-authority",
            "release-stale-evidence",
            "release-valid-first-use",
            "release-valid-replay",
        ],
    },
)

ACCEPTANCE_GATE_NAMES = (
    "fixed_scenario_catalog_complete",
    "compromised_leaf_quarantined_without_execution",
    "unrelated_branch_continues_only_to_primary_assurance",
    "affected_supervisor_blocks_descendants",
    "all_assurance_service_faults_fail_closed",
    "service_recovery_is_administrative_only",
    "all_nonfresh_telemetry_fails_closed",
    "unresolved_effect_blocks_fresh_work",
    "release_requires_completed_reconciliation",
    "release_requires_exact_pinned_signed_authority",
    "valid_reconciled_release_is_administrative_only",
    "release_authorization_replay_fails_closed",
    "recovery_contract_has_no_plant_control_operation",
    "exact_clean_source_bound",
    "private_key_material_not_retained",
)

EVIDENCE_LIMITS = (
    "Deterministic local model evidence only; no live plant or plant-control operation is used.",
    (
        "Continue-to-primary-assurance is not execution authorization and does not "
        "show mission completion."
    ),
    (
        "Administrative recovery authorization does not prove that a service was "
        "restored or a quarantine was operationally lifted."
    ),
    (
        "The campaign does not establish hostile-host resistance, independent validation, "
        "deployment, field effectiveness, or production readiness."
    ),
    (
        "No latency, throughput, hard-real-time, availability, or wall-clock performance "
        "claim is made."
    ),
    (
        "Recovery private keys exist only as in-process objects and are not serialized by "
        "this runner; Python process memory is not guaranteed to be zeroized."
    ),
)


class CampaignError(RuntimeError):
    """Raised when retained evidence cannot be produced or verified safely."""


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


def _git_executable() -> str:
    executable = shutil.which("git")
    if executable is None:
        raise CampaignError("git is required for retained source binding")
    return executable


def _run_git_bytes(*args: str) -> bytes:
    completed = subprocess.run(  # noqa: S603
        [_git_executable(), "-C", str(ROOT), *args],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise CampaignError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout


def _run_git_text(*args: str) -> str:
    try:
        return _run_git_bytes(*args).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CampaignError(f"git {' '.join(args)} returned non-UTF-8 output") from exc


def _source_fingerprint_material(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "git_commit": binding["git_commit"],
        "git_tree": binding["git_tree"],
        "source_files": binding["source_files"],
    }


def _assert_clean_source() -> dict[str, Any]:
    module_path = Path(m5.__file__ or "").resolve()
    expected_module = (ROOT / "src" / "aegis_ot" / "m5_compromise.py").resolve()
    if module_path != expected_module:
        raise CampaignError(
            f"M5 module imported from stale source: expected {expected_module}, got {module_path}"
        )

    top_level = Path(_run_git_text("rev-parse", "--show-toplevel").strip()).resolve()
    if top_level != ROOT.resolve():
        raise CampaignError("runner is not executing from its authoritative Git checkout")
    status = _run_git_text("status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise CampaignError("retained M5 execution requires an exact clean checkout")

    commit = _run_git_text("rev-parse", "HEAD^{commit}").strip()
    tree = _run_git_text("rev-parse", "HEAD^{tree}").strip()
    if not GIT_OBJECT_RE.fullmatch(commit) or not GIT_OBJECT_RE.fullmatch(tree):
        raise CampaignError("Git returned a noncanonical commit or tree object ID")

    source_files: list[dict[str, Any]] = []
    for relative in SOURCE_PATHS:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise CampaignError(f"required source is missing or symlinked: {relative}")
        committed = _run_git_bytes("show", f"{commit}:{relative}")
        working = path.read_bytes()
        if working != committed:
            raise CampaignError(f"required source differs from commit: {relative}")
        blob = _run_git_text("rev-parse", f"{commit}:{relative}").strip()
        if not GIT_OBJECT_RE.fullmatch(blob):
            raise CampaignError(f"Git returned a noncanonical blob ID for {relative}")
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


def _healthy_services() -> dict[m5.AssuranceService, m5.ServiceCondition]:
    return {service: m5.ServiceCondition.HEALTHY for service in m5.AssuranceService}


def _snapshot(
    case_id: str,
    *,
    services: Mapping[m5.AssuranceService, m5.ServiceCondition] | None = None,
    telemetry: m5.TelemetryCondition = m5.TelemetryCondition.FRESH,
    compromised: frozenset[str] = frozenset(),
    revoked: frozenset[str] = frozenset(),
    quarantined: frozenset[str] = frozenset(),
    unresolved_effect: bool = False,
) -> m5.CompromiseSnapshot:
    return m5.CompromiseSnapshot(
        snapshot_id=f"m5-snapshot-{case_id}",
        captured_at=CAMPAIGN_TIME,
        service_conditions=_healthy_services() if services is None else services,
        telemetry_condition=telemetry,
        compromised_principals=compromised,
        revoked_principals=revoked,
        quarantined_principals=quarantined,
        unresolved_effect=unresolved_effect,
    )


def _mission(
    case_id: str,
    *,
    actor_id: str,
    path: tuple[str, ...],
) -> m5.MissionAdmissionRequest:
    return m5.MissionAdmissionRequest(
        request_id=f"m5-mission-request-{case_id}",
        actor_id=actor_id,
        delegation_principals=path,
        requested_at=CAMPAIGN_TIME,
    )


def _authorization(
    private_key: Ed25519PrivateKey,
    snapshot: m5.CompromiseSnapshot,
    *,
    case_id: str,
    sequence: int,
    operation: m5.RecoveryOperation,
    target: str,
    reconciliation_complete: bool,
    evidence_sha256: str | None = None,
) -> m5.RecoveryAuthorization:
    authorization = m5.RecoveryAuthorization(
        authorization_id=f"m5-recovery-authorization-{case_id}",
        sequence=sequence,
        authority_id=AUTHORITY_ID,
        subject_id=RECOVERY_SUBJECT,
        operation=operation,
        target=target,
        evidence_sha256=snapshot.digest if evidence_sha256 is None else evidence_sha256,
        reconciliation_complete=reconciliation_complete,
        nonce=f"m5-recovery-nonce-{case_id}",
        issued_at=CAMPAIGN_TIME - timedelta(seconds=30),
        expires_at=CAMPAIGN_TIME + timedelta(minutes=5),
    )
    return authorization.signed(private_key)


def _recovery_request(
    snapshot: m5.CompromiseSnapshot,
    *,
    operation: m5.RecoveryOperation,
    target: str,
    reconciliation_complete: bool,
    evidence_sha256: str | None = None,
) -> m5.RecoveryRequest:
    return m5.RecoveryRequest(
        subject_id=RECOVERY_SUBJECT,
        operation=operation,
        target=target,
        evidence_sha256=snapshot.digest if evidence_sha256 is None else evidence_sha256,
        reconciliation_complete=reconciliation_complete,
    )


def _mission_record(
    case_id: str,
    request: m5.MissionAdmissionRequest,
    snapshot: m5.CompromiseSnapshot,
) -> dict[str, Any]:
    result = m5.evaluate_mission_admission(request, snapshot, now=CAMPAIGN_TIME)
    return {
        "case_id": case_id,
        "request": _model_json(request),
        "snapshot": _model_json(snapshot),
        "result": _model_json(result),
    }


def _recovery_record(
    case_id: str,
    verifier_scope: str,
    verifier: m5.RecoveryAuthorizationVerifier,
    request: m5.RecoveryRequest,
    authorization: m5.RecoveryAuthorization,
    snapshot: m5.CompromiseSnapshot,
) -> dict[str, Any]:
    result = verifier.evaluate(request, authorization, snapshot, now=CAMPAIGN_TIME)
    return {
        "case_id": case_id,
        "verifier_scope": verifier_scope,
        "request": _model_json(request),
        "authorization": _model_json(authorization),
        "snapshot": _model_json(snapshot),
        "result": _model_json(result),
    }


def _scenario_shell(catalog: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "scenario_id": catalog["scenario_id"],
        "category": catalog["category"],
        "mission_evaluations": [],
        "recovery_evaluations": [],
        "contract_observations": {},
    }


def _execute_scenarios(
    authority_private_key: Ed25519PrivateKey,
) -> list[dict[str, Any]]:
    public_key = authority_private_key.public_key()
    attacker_key = Ed25519PrivateKey.generate()
    scenarios = [_scenario_shell(catalog) for catalog in SCENARIO_CATALOG]

    branch = scenarios[0]
    branch_snapshot = _snapshot(
        "branch-isolation",
        compromised=frozenset({"agent-red"}),
    )
    branch["mission_evaluations"] = [
        _mission_record(
            "compromised-leaf",
            _mission(
                "compromised-leaf",
                actor_id="agent-red",
                path=("mission-root", "supervisor-red", "agent-red"),
            ),
            branch_snapshot,
        ),
        _mission_record(
            "unrelated-healthy-branch",
            _mission(
                "unrelated-healthy-branch",
                actor_id="agent-blue",
                path=("mission-root", "supervisor-blue", "agent-blue"),
            ),
            branch_snapshot,
        ),
    ]

    supervisors = scenarios[1]
    child_request = _mission(
        "affected-supervisor-child",
        actor_id="agent-red",
        path=("mission-root", "supervisor-red", "agent-red"),
    )
    supervisors["mission_evaluations"] = [
        _mission_record(
            "compromised-supervisor",
            child_request,
            _snapshot(
                "compromised-supervisor",
                compromised=frozenset({"supervisor-red"}),
            ),
        ),
        _mission_record(
            "revoked-supervisor",
            child_request.model_copy(
                update={"request_id": "m5-mission-request-revoked-supervisor"}
            ),
            _snapshot(
                "revoked-supervisor",
                revoked=frozenset({"supervisor-red"}),
            ),
        ),
    ]

    services_scenario = scenarios[2]
    mission_cases: list[dict[str, Any]] = []
    recovery_cases: list[dict[str, Any]] = []
    service_sequence = 1
    for service in m5.AssuranceService:
        for condition in (
            m5.ServiceCondition.UNAVAILABLE,
            m5.ServiceCondition.UNTRUSTED,
        ):
            case_id = f"{service.value}-{condition.value}"
            conditions = _healthy_services()
            conditions[service] = condition
            snapshot = _snapshot(case_id, services=conditions)
            mission_cases.append(
                _mission_record(
                    case_id,
                    _mission(
                        case_id,
                        actor_id="agent-blue",
                        path=("mission-root", "supervisor-blue", "agent-blue"),
                    ),
                    snapshot,
                )
            )
            recovery_case_id = f"restore-{case_id}"
            request = _recovery_request(
                snapshot,
                operation=m5.RecoveryOperation.RESTORE_ASSURANCE_SERVICE,
                target=service.value,
                reconciliation_complete=False,
            )
            authorization = _authorization(
                authority_private_key,
                snapshot,
                case_id=recovery_case_id,
                sequence=service_sequence,
                operation=m5.RecoveryOperation.RESTORE_ASSURANCE_SERVICE,
                target=service.value,
                reconciliation_complete=False,
            )
            recovery_cases.append(
                _recovery_record(
                    recovery_case_id,
                    f"single-use-{recovery_case_id}",
                    m5.RecoveryAuthorizationVerifier(AUTHORITY_ID, public_key),
                    request,
                    authorization,
                    snapshot,
                )
            )
            service_sequence += 1
    services_scenario["mission_evaluations"] = mission_cases
    services_scenario["recovery_evaluations"] = recovery_cases

    telemetry_scenario = scenarios[3]
    telemetry_conditions = (
        m5.TelemetryCondition.DELAYED,
        m5.TelemetryCondition.REPLAYED,
        m5.TelemetryCondition.BIASED,
        m5.TelemetryCondition.CONTRADICTORY,
        m5.TelemetryCondition.UNAVAILABLE,
    )
    telemetry_scenario["mission_evaluations"] = [
        _mission_record(
            f"telemetry-{condition.value}",
            _mission(
                f"telemetry-{condition.value}",
                actor_id="agent-blue",
                path=("mission-root", "supervisor-blue", "agent-blue"),
            ),
            _snapshot(f"telemetry-{condition.value}", telemetry=condition),
        )
        for condition in telemetry_conditions
    ]

    release_scenario = scenarios[4]
    unresolved_snapshot = _snapshot(
        "unresolved-release",
        quarantined=frozenset({"agent-red"}),
        unresolved_effect=True,
    )
    release_scenario["mission_evaluations"] = [
        _mission_record(
            "unresolved-effect-fresh-work",
            _mission(
                "unresolved-effect-fresh-work",
                actor_id="agent-blue",
                path=("mission-root", "supervisor-blue", "agent-blue"),
            ),
            unresolved_snapshot,
        )
    ]
    reconciled_snapshot = _snapshot(
        "reconciled-release",
        quarantined=frozenset({"agent-red"}),
        unresolved_effect=False,
    )
    incomplete_snapshot = _snapshot(
        "incomplete-release",
        quarantined=frozenset({"agent-red"}),
        unresolved_effect=False,
    )
    stale_snapshot = _snapshot(
        "stale-release-authority-view",
        quarantined=frozenset({"agent-red"}),
        revoked=frozenset({"newly-revoked-agent"}),
    )

    release_records: list[dict[str, Any]] = []

    def release_record(
        case_id: str,
        scope: str,
        snapshot: m5.CompromiseSnapshot,
        *,
        private_key: Ed25519PrivateKey = authority_private_key,
        reconciliation_complete: bool,
        evidence_sha256: str | None = None,
        verifier: m5.RecoveryAuthorizationVerifier | None = None,
        authorization: m5.RecoveryAuthorization | None = None,
    ) -> tuple[dict[str, Any], m5.RecoveryAuthorization]:
        request = _recovery_request(
            snapshot,
            operation=m5.RecoveryOperation.RELEASE_QUARANTINE,
            target="agent-red",
            reconciliation_complete=reconciliation_complete,
        )
        signed = authorization or _authorization(
            private_key,
            snapshot,
            case_id=case_id,
            sequence=1,
            operation=m5.RecoveryOperation.RELEASE_QUARANTINE,
            target="agent-red",
            reconciliation_complete=reconciliation_complete,
            evidence_sha256=evidence_sha256,
        )
        selected_verifier = verifier or m5.RecoveryAuthorizationVerifier(
            AUTHORITY_ID, public_key
        )
        return (
            _recovery_record(
                case_id,
                scope,
                selected_verifier,
                request,
                signed,
                snapshot,
            ),
            signed,
        )

    unresolved_record, _ = release_record(
        "release-unresolved-effect",
        "single-use-release-unresolved-effect",
        unresolved_snapshot,
        reconciliation_complete=True,
    )
    release_records.append(unresolved_record)
    incomplete_record, _ = release_record(
        "release-incomplete-reconciliation",
        "single-use-release-incomplete-reconciliation",
        incomplete_snapshot,
        reconciliation_complete=False,
    )
    release_records.append(incomplete_record)
    forged_record, _ = release_record(
        "release-forged-authority",
        "single-use-release-forged-authority",
        reconciled_snapshot,
        private_key=attacker_key,
        reconciliation_complete=True,
    )
    release_records.append(forged_record)
    stale_record, _ = release_record(
        "release-stale-evidence",
        "single-use-release-stale-evidence",
        reconciled_snapshot,
        reconciliation_complete=True,
        evidence_sha256=stale_snapshot.digest,
    )
    release_records.append(stale_record)
    replay_verifier = m5.RecoveryAuthorizationVerifier(AUTHORITY_ID, public_key)
    valid_record, valid_authorization = release_record(
        "release-valid-first-use",
        "shared-valid-release-replay",
        reconciled_snapshot,
        reconciliation_complete=True,
        verifier=replay_verifier,
    )
    release_records.append(valid_record)
    replay_record, _ = release_record(
        "release-valid-replay",
        "shared-valid-release-replay",
        reconciled_snapshot,
        reconciliation_complete=True,
        verifier=replay_verifier,
        authorization=valid_authorization,
    )
    release_records.append(replay_record)
    release_scenario["recovery_evaluations"] = release_records
    release_scenario["contract_observations"] = {
        "recovery_operations": [operation.value for operation in m5.RecoveryOperation],
        "plant_control_operation_present": False,
        "plant_adapter_invoked": False,
    }
    return scenarios


def _scenario_by_id(
    scenarios: Sequence[Mapping[str, Any]], scenario_id: str
) -> Mapping[str, Any]:
    matches = [item for item in scenarios if item.get("scenario_id") == scenario_id]
    if len(matches) != 1:
        raise CampaignError(f"expected exactly one scenario {scenario_id}")
    return matches[0]


def _evaluation_by_id(
    scenario: Mapping[str, Any], collection: str, case_id: str
) -> Mapping[str, Any]:
    values = scenario.get(collection)
    if not isinstance(values, list):
        raise CampaignError(f"scenario {scenario.get('scenario_id')} lacks {collection}")
    matches = [item for item in values if isinstance(item, dict) and item.get("case_id") == case_id]
    if len(matches) != 1:
        raise CampaignError(f"expected exactly one case {case_id}")
    return matches[0]


def _mission_result(record: Mapping[str, Any]) -> Mapping[str, Any]:
    result = record.get("result")
    if not isinstance(result, dict):
        raise CampaignError("mission evaluation lacks a result object")
    return result


def _recovery_result(record: Mapping[str, Any]) -> Mapping[str, Any]:
    result = record.get("result")
    if not isinstance(result, dict):
        raise CampaignError("recovery evaluation lacks a result object")
    return result


def _acceptance_gates(
    scenarios: Sequence[Mapping[str, Any]],
    *,
    source_bound: bool,
    private_key_retained: bool,
) -> dict[str, bool]:
    scenario_ids = [item.get("scenario_id") for item in scenarios]
    fixed_catalog_complete = scenario_ids == [
        catalog["scenario_id"] for catalog in SCENARIO_CATALOG
    ]
    if fixed_catalog_complete:
        for catalog, scenario in zip(SCENARIO_CATALOG, scenarios, strict=True):
            mission_ids = [
                item.get("case_id")
                for item in scenario.get("mission_evaluations", [])
                if isinstance(item, dict)
            ]
            recovery_ids = [
                item.get("case_id")
                for item in scenario.get("recovery_evaluations", [])
                if isinstance(item, dict)
            ]
            fixed_catalog_complete = fixed_catalog_complete and (
                mission_ids == catalog["mission_case_ids"]
                and recovery_ids == catalog["recovery_case_ids"]
                and scenario.get("category") == catalog["category"]
            )

    branch = _scenario_by_id(scenarios, SCENARIO_CATALOG[0]["scenario_id"])
    compromised_leaf = _mission_result(
        _evaluation_by_id(branch, "mission_evaluations", "compromised-leaf")
    )
    unrelated = _mission_result(
        _evaluation_by_id(branch, "mission_evaluations", "unrelated-healthy-branch")
    )

    supervisors = _scenario_by_id(scenarios, SCENARIO_CATALOG[1]["scenario_id"])
    compromised_supervisor = _mission_result(
        _evaluation_by_id(supervisors, "mission_evaluations", "compromised-supervisor")
    )
    revoked_supervisor = _mission_result(
        _evaluation_by_id(supervisors, "mission_evaluations", "revoked-supervisor")
    )

    service_scenario = _scenario_by_id(scenarios, SCENARIO_CATALOG[2]["scenario_id"])
    service_missions = service_scenario.get("mission_evaluations", [])
    service_recoveries = service_scenario.get("recovery_evaluations", [])
    expected_service_reasons = {
        f"{service.value}_{condition.value}"
        for service in m5.AssuranceService
        for condition in (m5.ServiceCondition.UNAVAILABLE, m5.ServiceCondition.UNTRUSTED)
    }
    observed_service_reasons = {
        result["reasons"][0]
        for record in service_missions
        if isinstance(record, dict)
        and (result := _mission_result(record)).get("outcome") == m5.MissionGateOutcome.DENY.value
        and result.get("may_enter_primary_assurance") is False
        and result.get("execution_authorized") is False
        and isinstance(result.get("reasons"), list)
        and len(result["reasons"]) == 1
    }
    service_faults_closed = (
        len(service_missions) == 8 and observed_service_reasons == expected_service_reasons
    )
    service_recovery_bounded = len(service_recoveries) == 8 and all(
        isinstance(record, dict)
        and (result := _recovery_result(record)).get("allowed") is True
        and result.get("reasons") == ["authorized_recovery_step"]
        and result.get("plant_control_authorized") is False
        and isinstance(record.get("request"), dict)
        and record["request"].get("operation")
        == m5.RecoveryOperation.RESTORE_ASSURANCE_SERVICE.value
        for record in service_recoveries
    )

    telemetry_scenario = _scenario_by_id(scenarios, SCENARIO_CATALOG[3]["scenario_id"])
    telemetry_records = telemetry_scenario.get("mission_evaluations", [])
    expected_telemetry_reasons = {
        "telemetry_delayed",
        "telemetry_replayed",
        "telemetry_biased",
        "telemetry_contradictory",
        "telemetry_unavailable",
    }
    observed_telemetry_reasons = {
        result["reasons"][0]
        for record in telemetry_records
        if isinstance(record, dict)
        and (result := _mission_result(record)).get("outcome") == m5.MissionGateOutcome.DENY.value
        and result.get("may_enter_primary_assurance") is False
        and result.get("execution_authorized") is False
        and isinstance(result.get("reasons"), list)
        and len(result["reasons"]) == 1
    }

    release_scenario = _scenario_by_id(scenarios, SCENARIO_CATALOG[4]["scenario_id"])
    unresolved_mission = _mission_result(
        _evaluation_by_id(
            release_scenario, "mission_evaluations", "unresolved-effect-fresh-work"
        )
    )
    unresolved_release = _recovery_result(
        _evaluation_by_id(
            release_scenario, "recovery_evaluations", "release-unresolved-effect"
        )
    )
    incomplete_release = _recovery_result(
        _evaluation_by_id(
            release_scenario,
            "recovery_evaluations",
            "release-incomplete-reconciliation",
        )
    )
    forged_release = _recovery_result(
        _evaluation_by_id(
            release_scenario, "recovery_evaluations", "release-forged-authority"
        )
    )
    stale_release = _recovery_result(
        _evaluation_by_id(
            release_scenario, "recovery_evaluations", "release-stale-evidence"
        )
    )
    valid_release = _recovery_result(
        _evaluation_by_id(
            release_scenario, "recovery_evaluations", "release-valid-first-use"
        )
    )
    replay_release = _recovery_result(
        _evaluation_by_id(
            release_scenario, "recovery_evaluations", "release-valid-replay"
        )
    )
    contract = release_scenario.get("contract_observations", {})
    exact_operations = [
        m5.RecoveryOperation.PUBLISH_REVOCATION.value,
        m5.RecoveryOperation.ROTATE_CREDENTIAL.value,
        m5.RecoveryOperation.RECONCILE_EFFECT.value,
        m5.RecoveryOperation.RESTORE_ASSURANCE_SERVICE.value,
        m5.RecoveryOperation.RELEASE_QUARANTINE.value,
    ]

    gates = {
        "fixed_scenario_catalog_complete": fixed_catalog_complete,
        "compromised_leaf_quarantined_without_execution": (
            compromised_leaf.get("outcome") == m5.MissionGateOutcome.QUARANTINE.value
            and compromised_leaf.get("reasons") == ["actor_compromised"]
            and compromised_leaf.get("may_enter_primary_assurance") is False
            and compromised_leaf.get("execution_authorized") is False
        ),
        "unrelated_branch_continues_only_to_primary_assurance": (
            unrelated.get("outcome")
            == m5.MissionGateOutcome.CONTINUE_PRIMARY_ASSURANCE.value
            and unrelated.get("reasons") == ["continue_to_primary_assurance"]
            and unrelated.get("may_enter_primary_assurance") is True
            and unrelated.get("execution_authorized") is False
        ),
        "affected_supervisor_blocks_descendants": (
            compromised_supervisor.get("outcome") == m5.MissionGateOutcome.DENY.value
            and compromised_supervisor.get("reasons")
            == ["delegation_ancestor_compromised"]
            and revoked_supervisor.get("outcome") == m5.MissionGateOutcome.DENY.value
            and revoked_supervisor.get("reasons") == ["delegation_ancestor_revoked"]
        ),
        "all_assurance_service_faults_fail_closed": service_faults_closed,
        "service_recovery_is_administrative_only": service_recovery_bounded,
        "all_nonfresh_telemetry_fails_closed": (
            len(telemetry_records) == 5
            and observed_telemetry_reasons == expected_telemetry_reasons
        ),
        "unresolved_effect_blocks_fresh_work": (
            unresolved_mission.get("outcome") == m5.MissionGateOutcome.DENY.value
            and unresolved_mission.get("reasons") == ["outcome_reconciliation_required"]
        ),
        "release_requires_completed_reconciliation": (
            unresolved_release.get("allowed") is False
            and "recovery_reconciliation_incomplete"
            in unresolved_release.get("reasons", [])
            and incomplete_release.get("allowed") is False
            and "recovery_reconciliation_incomplete"
            in incomplete_release.get("reasons", [])
        ),
        "release_requires_exact_pinned_signed_authority": (
            forged_release.get("allowed") is False
            and "recovery_authority_invalid" in forged_release.get("reasons", [])
            and stale_release.get("allowed") is False
            and "recovery_request_evidence_mismatch"
            in stale_release.get("reasons", [])
            and "recovery_snapshot_evidence_mismatch"
            in stale_release.get("reasons", [])
        ),
        "valid_reconciled_release_is_administrative_only": (
            valid_release.get("allowed") is True
            and valid_release.get("reasons") == ["authorized_recovery_step"]
            and valid_release.get("plant_control_authorized") is False
        ),
        "release_authorization_replay_fails_closed": (
            replay_release.get("allowed") is False
            and "recovery_authorization_sequence_not_monotonic"
            in replay_release.get("reasons", [])
            and "recovery_authorization_replayed" in replay_release.get("reasons", [])
        ),
        "recovery_contract_has_no_plant_control_operation": (
            isinstance(contract, dict)
            and contract.get("recovery_operations") == exact_operations
            and contract.get("plant_control_operation_present") is False
            and contract.get("plant_adapter_invoked") is False
            and all(
                _recovery_result(record).get("plant_control_authorized") is False
                for scenario in scenarios
                for record in scenario.get("recovery_evaluations", [])
                if isinstance(record, dict)
            )
        ),
        "exact_clean_source_bound": source_bound,
        "private_key_material_not_retained": not private_key_retained,
    }
    if tuple(gates) != ACCEPTANCE_GATE_NAMES:
        raise CampaignError("acceptance-gate implementation drifted from its fixed catalog")
    return gates


def _semantic_projection(
    scenarios: Sequence[Mapping[str, Any]], gates: Mapping[str, bool]
) -> dict[str, Any]:
    projected_scenarios: list[dict[str, Any]] = []
    for scenario in scenarios:
        mission_projection = []
        for record in scenario.get("mission_evaluations", []):
            result = _mission_result(record)
            mission_projection.append(
                {
                    "case_id": record["case_id"],
                    "outcome": result["outcome"],
                    "reasons": result["reasons"],
                    "may_enter_primary_assurance": result[
                        "may_enter_primary_assurance"
                    ],
                    "execution_authorized": result["execution_authorized"],
                }
            )
        recovery_projection = []
        for record in scenario.get("recovery_evaluations", []):
            result = _recovery_result(record)
            request = record.get("request", {})
            recovery_projection.append(
                {
                    "case_id": record["case_id"],
                    "operation": request.get("operation"),
                    "allowed": result["allowed"],
                    "reasons": result["reasons"],
                    "plant_control_authorized": result["plant_control_authorized"],
                }
            )
        projected_scenarios.append(
            {
                "scenario_id": scenario["scenario_id"],
                "mission_evaluations": mission_projection,
                "recovery_evaluations": recovery_projection,
                "contract_observations": scenario.get("contract_observations", {}),
            }
        )
    return {
        "projection_version": SEMANTIC_PROJECTION_VERSION,
        "scenario_catalog_sha256": _sha256_json(SCENARIO_CATALOG),
        "scenarios": projected_scenarios,
        "acceptance_gates": dict(gates),
        "accepted": all(gates.values()),
    }


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _runtime_versions() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "cryptography": importlib.metadata.version("cryptography"),
        "pydantic": importlib.metadata.version("pydantic"),
    }


def _build_report(source_binding: Mapping[str, Any]) -> dict[str, Any]:
    authority_private_key = Ed25519PrivateKey.generate()
    public_material = _raw_public_key(authority_private_key)
    scenarios = _execute_scenarios(authority_private_key)
    gates = _acceptance_gates(
        scenarios,
        source_bound=True,
        private_key_retained=False,
    )
    semantic_projection = _semantic_projection(scenarios, gates)
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "run_id": str(uuid.uuid4()),
        "generated_at": datetime.now(UTC).isoformat(),
        "execution_mode": "retained_local_model",
        "source_binding": dict(source_binding),
        "runtime_versions": _runtime_versions(),
        "scenario_catalog": list(SCENARIO_CATALOG),
        "scenario_catalog_sha256": _sha256_json(SCENARIO_CATALOG),
        "scenarios": scenarios,
        "acceptance_gates": gates,
        "accepted": all(gates.values()),
        "semantic_projection_version": SEMANTIC_PROJECTION_VERSION,
        "semantic_outcome_sha256": _sha256_json(semantic_projection),
        "key_material": {
            "authority_id": AUTHORITY_ID,
            "authority_public_key_base64": base64.b64encode(public_material).decode("ascii"),
            "authority_public_key_sha256": _sha256_bytes(public_material),
            "private_key_material_retained": False,
            "key_generation": "ephemeral_in_memory",
        },
        "evidence_limits": list(EVIDENCE_LIMITS),
        "offline_verification": {
            "verifier": "scripts/run_m5_compromise.py --verify <evidence.json>",
            "network_required": False,
            "passed_before_publication": True,
        },
    }
    report["integrity"] = {
        "canonical_payload_sha256": _sha256_json(report),
    }
    _verify_report_payload(report, expected_source_binding=source_binding)
    return report


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CampaignError(f"evidence contains duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_report(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CampaignError("evidence path must be a regular non-symlink file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_EVIDENCE_BYTES:
        raise CampaignError("evidence file size is outside the verifier limit")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CampaignError("evidence is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CampaignError("evidence root must be an object")
    return value


def _private_material_flag(value: Any, *, path: str = "$") -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            if key == "private_key_material_retained":
                if item is not False:
                    return True
                continue
            if key == "private_key_material_not_retained":
                if item is not True:
                    return True
                continue
            normalized = key.lower().replace("-", "_")
            if "private_key" in normalized or normalized in {
                "private_material",
                "secret_key",
                "seed",
            }:
                return True
            if _private_material_flag(item, path=child):
                return True
    elif isinstance(value, list):
        return any(
            _private_material_flag(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        )
    return False


def _contains_private_pem(value: Any) -> bool:
    if isinstance(value, str):
        return "-----BEGIN PRIVATE KEY-----" in value or (
            "-----BEGIN" in value and "PRIVATE KEY-----" in value
        )
    if isinstance(value, dict):
        return any(_contains_private_pem(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_private_pem(item) for item in value)
    return False


def _verify_source_binding_shape(binding: Mapping[str, Any]) -> None:
    expected_keys = {
        "git_commit",
        "git_tree",
        "clean_checkout",
        "source_files",
        "source_fingerprint_sha256",
    }
    if set(binding) != expected_keys:
        raise CampaignError("source binding fields are not exact")
    if binding.get("clean_checkout") is not True:
        raise CampaignError("evidence is not bound to a clean checkout")
    if not isinstance(binding.get("git_commit"), str) or not GIT_OBJECT_RE.fullmatch(
        binding["git_commit"]
    ):
        raise CampaignError("source binding commit is not canonical")
    if not isinstance(binding.get("git_tree"), str) or not GIT_OBJECT_RE.fullmatch(
        binding["git_tree"]
    ):
        raise CampaignError("source binding tree is not canonical")
    source_files = binding.get("source_files")
    if not isinstance(source_files, list) or [
        item.get("path") for item in source_files if isinstance(item, dict)
    ] != list(SOURCE_PATHS):
        raise CampaignError("source binding does not contain the exact source path set")
    for item in source_files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "bytes",
            "sha256",
            "git_blob",
        }:
            raise CampaignError("source file binding fields are not exact")
        if (
            isinstance(item["bytes"], bool)
            or not isinstance(item["bytes"], int)
            or item["bytes"] <= 0
            or not isinstance(item["sha256"], str)
            or not SHA256_RE.fullmatch(item["sha256"])
            or not isinstance(item["git_blob"], str)
            or not GIT_OBJECT_RE.fullmatch(item["git_blob"])
        ):
            raise CampaignError("source file binding is noncanonical")
    expected_fingerprint = _sha256_json(_source_fingerprint_material(binding))
    if binding.get("source_fingerprint_sha256") != expected_fingerprint:
        raise CampaignError("source fingerprint does not match its bound material")


def _replay_and_verify_scenarios(
    scenarios: Sequence[Mapping[str, Any]], authority_public_key: Ed25519PublicKey
) -> None:
    verifier_scopes: dict[str, m5.RecoveryAuthorizationVerifier] = {}
    for scenario in scenarios:
        if set(scenario) != {
            "scenario_id",
            "category",
            "mission_evaluations",
            "recovery_evaluations",
            "contract_observations",
        }:
            raise CampaignError("scenario fields are not exact")
        mission_values = scenario.get("mission_evaluations")
        recovery_values = scenario.get("recovery_evaluations")
        if not isinstance(mission_values, list) or not isinstance(recovery_values, list):
            raise CampaignError("scenario evaluation collections must be arrays")
        for record in mission_values:
            if not isinstance(record, dict) or set(record) != {
                "case_id",
                "request",
                "snapshot",
                "result",
            }:
                raise CampaignError("mission evaluation fields are not exact")
            try:
                mission_request = m5.MissionAdmissionRequest.model_validate(
                    record["request"]
                )
                mission_snapshot = m5.CompromiseSnapshot.model_validate(
                    record["snapshot"]
                )
                mission_retained = m5.MissionGateResult.model_validate(record["result"])
            except Exception as exc:
                raise CampaignError("mission evaluation failed strict model validation") from exc
            mission_replayed = m5.evaluate_mission_admission(
                mission_request, mission_snapshot, now=CAMPAIGN_TIME
            )
            if _model_json(mission_replayed) != _model_json(mission_retained):
                raise CampaignError(f"mission case {record['case_id']} does not replay exactly")

        for record in recovery_values:
            if not isinstance(record, dict) or set(record) != {
                "case_id",
                "verifier_scope",
                "request",
                "authorization",
                "snapshot",
                "result",
            }:
                raise CampaignError("recovery evaluation fields are not exact")
            scope = record["verifier_scope"]
            if not isinstance(scope, str) or not scope:
                raise CampaignError("recovery verifier scope must be non-empty")
            try:
                recovery_request = m5.RecoveryRequest.model_validate(record["request"])
                authorization = m5.RecoveryAuthorization.model_validate(
                    record["authorization"]
                )
                recovery_snapshot = m5.CompromiseSnapshot.model_validate(
                    record["snapshot"]
                )
                recovery_retained = m5.RecoveryGateResult.model_validate(
                    record["result"]
                )
            except Exception as exc:
                raise CampaignError("recovery evaluation failed strict model validation") from exc
            verifier = verifier_scopes.setdefault(
                scope,
                m5.RecoveryAuthorizationVerifier(AUTHORITY_ID, authority_public_key),
            )
            recovery_replayed = verifier.evaluate(
                recovery_request,
                authorization,
                recovery_snapshot,
                now=CAMPAIGN_TIME,
            )
            if _model_json(recovery_replayed) != _model_json(recovery_retained):
                raise CampaignError(f"recovery case {record['case_id']} does not replay exactly")


def _verify_report_payload(
    report: Mapping[str, Any], *, expected_source_binding: Mapping[str, Any]
) -> None:
    expected_top_level = {
        "schema_version",
        "campaign_id",
        "run_id",
        "generated_at",
        "execution_mode",
        "source_binding",
        "runtime_versions",
        "scenario_catalog",
        "scenario_catalog_sha256",
        "scenarios",
        "acceptance_gates",
        "accepted",
        "semantic_projection_version",
        "semantic_outcome_sha256",
        "key_material",
        "evidence_limits",
        "offline_verification",
        "integrity",
    }
    if set(report) != expected_top_level:
        raise CampaignError("evidence top-level fields are not exact")
    if report.get("schema_version") != REPORT_SCHEMA:
        raise CampaignError("evidence schema version is unsupported")
    if report.get("campaign_id") != CAMPAIGN_ID:
        raise CampaignError("evidence campaign ID is not exact")
    try:
        parsed_run_id = uuid.UUID(str(report.get("run_id")))
        generated_at = datetime.fromisoformat(str(report.get("generated_at")))
    except (ValueError, TypeError) as exc:
        raise CampaignError("run identity or generation time is malformed") from exc
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise CampaignError("evidence generation time must be timezone-aware")
    if str(parsed_run_id) != report.get("run_id"):
        raise CampaignError("run identity must use canonical UUID text")
    if report.get("execution_mode") != "retained_local_model":
        raise CampaignError("evidence execution mode is unsupported")

    source_binding = report.get("source_binding")
    if not isinstance(source_binding, dict):
        raise CampaignError("evidence source binding must be an object")
    _verify_source_binding_shape(source_binding)
    if dict(source_binding) != dict(expected_source_binding):
        raise CampaignError("evidence source binding does not match the exact current source")

    if report.get("scenario_catalog") != list(SCENARIO_CATALOG):
        raise CampaignError("evidence scenario catalog is not the fixed M5 catalog")
    catalog_digest = _sha256_json(SCENARIO_CATALOG)
    if report.get("scenario_catalog_sha256") != catalog_digest:
        raise CampaignError("evidence scenario catalog digest is invalid")
    if report.get("semantic_projection_version") != SEMANTIC_PROJECTION_VERSION:
        raise CampaignError("semantic projection version is unsupported")
    runtime_versions = report.get("runtime_versions")
    if (
        not isinstance(runtime_versions, dict)
        or set(runtime_versions)
        != {"python", "implementation", "cryptography", "pydantic"}
        or not all(
            isinstance(value, str) and value and "PRIVATE KEY" not in value
            for value in runtime_versions.values()
        )
    ):
        raise CampaignError("runtime-version evidence fields are not exact")
    if report.get("evidence_limits") != list(EVIDENCE_LIMITS):
        raise CampaignError("evidence limits are not exact")
    if _private_material_flag(report) or _contains_private_pem(report):
        raise CampaignError("evidence contains or claims retained private key material")

    key_material = report.get("key_material")
    if not isinstance(key_material, dict) or set(key_material) != {
        "authority_id",
        "authority_public_key_base64",
        "authority_public_key_sha256",
        "private_key_material_retained",
        "key_generation",
    }:
        raise CampaignError("key-material evidence fields are not exact")
    if (
        key_material.get("authority_id") != AUTHORITY_ID
        or key_material.get("private_key_material_retained") is not False
        or key_material.get("key_generation") != "ephemeral_in_memory"
    ):
        raise CampaignError("key-material evidence violates the campaign contract")
    try:
        public_material = base64.b64decode(
            key_material["authority_public_key_base64"], validate=True
        )
        public_key = Ed25519PublicKey.from_public_bytes(public_material)
    except (ValueError, TypeError) as exc:
        raise CampaignError("authority public key is invalid") from exc
    if (
        len(public_material) != 32
        or key_material.get("authority_public_key_sha256")
        != _sha256_bytes(public_material)
    ):
        raise CampaignError("authority public key digest is invalid")

    scenarios = report.get("scenarios")
    if not isinstance(scenarios, list) or not all(
        isinstance(item, dict) for item in scenarios
    ):
        raise CampaignError("evidence scenarios must be objects")
    _replay_and_verify_scenarios(scenarios, public_key)
    recomputed_gates = _acceptance_gates(
        scenarios,
        source_bound=True,
        private_key_retained=False,
    )
    if report.get("acceptance_gates") != recomputed_gates:
        raise CampaignError("retained acceptance gates do not match replayed outcomes")
    if report.get("accepted") is not all(recomputed_gates.values()):
        raise CampaignError("retained campaign acceptance is inconsistent")
    semantic = _semantic_projection(scenarios, recomputed_gates)
    if report.get("semantic_outcome_sha256") != _sha256_json(semantic):
        raise CampaignError("semantic outcome digest is invalid")

    offline = report.get("offline_verification")
    if not isinstance(offline, dict) or offline != {
        "verifier": "scripts/run_m5_compromise.py --verify <evidence.json>",
        "network_required": False,
        "passed_before_publication": True,
    }:
        raise CampaignError("offline-verification declaration is not exact")
    integrity = report.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {
        "canonical_payload_sha256"
    }:
        raise CampaignError("evidence integrity fields are not exact")
    unsigned = dict(report)
    unsigned.pop("integrity")
    if integrity.get("canonical_payload_sha256") != _sha256_json(unsigned):
        raise CampaignError("evidence canonical payload digest is invalid")


def _validate_output_parent(output_parent: Path) -> Path:
    if output_parent.is_symlink():
        raise CampaignError("output parent must not be a symlink")
    resolved = output_parent.resolve()
    if not resolved.is_dir():
        raise CampaignError("output parent must be an existing directory")
    if resolved == ROOT.resolve() or resolved.is_relative_to(ROOT.resolve()):
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
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise CampaignError("retained evidence file is not mode 0600")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_descriptor = os.open(path.parent, directory_flags)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _remove_owned_output(directory: Path) -> None:
    if not directory.name.startswith(OUTPUT_PREFIX):
        raise CampaignError("refusing cleanup of an output directory not owned by this runner")
    for child in directory.iterdir():
        if child.name != "evidence.json" or child.is_dir():
            raise CampaignError("refusing cleanup of unexpected output-directory content")
        child.unlink()
    directory.rmdir()


def run_campaign(output_parent: Path | None = None) -> Path:
    source_binding = _assert_clean_source()
    report = _build_report(source_binding)
    parent = _validate_output_parent(
        Path(tempfile.gettempdir()) if output_parent is None else output_parent
    )
    output_directory = Path(tempfile.mkdtemp(prefix=OUTPUT_PREFIX, dir=parent))
    output_directory.chmod(0o700)
    if stat.S_IMODE(output_directory.stat().st_mode) != 0o700:
        _remove_owned_output(output_directory)
        raise CampaignError("retained output directory is not mode 0700")
    evidence_path = output_directory / "evidence.json"
    try:
        _write_private_report(evidence_path, report)
        final_binding = _assert_clean_source()
        if final_binding != source_binding:
            raise CampaignError("source changed while the retained M5 campaign was running")
        verify_evidence(evidence_path)
    except Exception:
        _remove_owned_output(output_directory)
        raise
    return evidence_path


def verify_evidence(path: Path) -> dict[str, Any]:
    report = _load_report(path)
    source_binding = _assert_clean_source()
    _verify_report_payload(report, expected_source_binding=source_binding)
    return {
        "accepted": report["accepted"],
        "git_commit": source_binding["git_commit"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
        "semantic_outcome_sha256": report["semantic_outcome_sha256"],
        "canonical_payload_sha256": report["integrity"][
            "canonical_payload_sha256"
        ],
        "private_key_material_retained": False,
    }


def build_plan() -> dict[str, Any]:
    return {
        "schema_version": PLAN_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "execution_mode": "plan_only",
        "scenario_catalog": list(SCENARIO_CATALOG),
        "scenario_catalog_sha256": _sha256_json(SCENARIO_CATALOG),
        "acceptance_gate_names": list(ACCEPTANCE_GATE_NAMES),
        "retained_execution_requirements": [
            "exact clean committed source",
            "unique mode-0700 output directory outside the checkout",
            "mode-0600 evidence file",
            "ephemeral in-memory recovery private keys",
            "same-script offline replay and signature verification",
        ],
        "evidence_limits": list(EVIDENCE_LIMITS),
        "execution_claimed": False,
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
        help="offline-verify evidence from the exact clean source revision",
    )
    parser.add_argument(
        "--output-parent",
        type=Path,
        help="existing parent outside the checkout for a unique private run directory",
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
                "accepted": retained["accepted"],
                "evidence_path": str(evidence_path),
                "git_commit": retained["source_binding"]["git_commit"],
                "source_fingerprint_sha256": retained["source_binding"][
                    "source_fingerprint_sha256"
                ],
                "semantic_outcome_sha256": retained["semantic_outcome_sha256"],
                "canonical_payload_sha256": retained["integrity"][
                    "canonical_payload_sha256"
                ],
                "private_key_material_retained": False,
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
        print(f"M5 campaign failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
