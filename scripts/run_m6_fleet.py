"""Run and offline-verify the deterministic M6 fleet-model campaign.

This runner retains synthetic model output.  It does not benchmark a host,
instantiate a fleet, deploy Aegis-OT, validate production capacity, or establish
operational effectiveness.  Economic values are model estimates under the
retained assumptions, not forecasts or observed costs.
"""

from __future__ import annotations

import argparse
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
from pathlib import Path
from typing import Any

import aegis_ot.m6_fleet as m6

ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = "aegis-ot-m6-fleet-campaign-v1"
PLAN_SCHEMA = "aegis-ot-m6-fleet-plan-v1"
SEMANTIC_PROJECTION_VERSION = "aegis-ot-m6-fleet-semantic-projection-v1"
CAMPAIGN_ID = "m6-fleet-scaling-and-economics-v1"
OUTPUT_PREFIX = "aegis-ot-m6-fleet-"
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")

SOURCE_PATHS = (
    "pyproject.toml",
    "scripts/run_m6_fleet.py",
    "src/aegis_ot/m6_fleet.py",
)

REQUIRED_ASSUMPTION_FIELDS = (
    "seed",
    "horizon_seconds",
    "events_per_logical_agent_per_horizon",
    "arrival_jitter_window_microseconds",
    "service_worker_count",
    "service_time_min_microseconds",
    "service_time_max_microseconds",
    "maximum_simulated_events",
    "delegation_branching_factor",
    "revocation_edge_delay_microseconds",
    "revocation_edge_jitter_microseconds",
    "policy_document_bytes",
    "policy_distribution_bandwidth_bytes_per_second",
    "policy_edge_delay_microseconds",
    "policy_edge_jitter_microseconds",
    "policy_updates_per_month",
    "evidence_bytes_per_event",
    "target_logical_agents_per_operator",
    "operator_oversight_hours_per_operator_month",
    "modeled_incidents_per_10000_logical_agent_months",
    "incident_base_effort_minutes",
    "incident_effort_minutes_per_delegation_depth",
    "incident_handoff_minutes_per_operator",
    "governance_base_hours_per_month",
    "governance_review_minutes_per_policy_update",
    "governance_review_minutes_per_depth_update",
    "governance_review_minutes_per_1000_agents_update",
    "evidence_review_minutes_per_retained_gib",
    "economic_cases",
)

REQUIRED_ECONOMIC_CASE_FIELDS = (
    "name",
    "operator_labor_usd_per_hour",
    "incident_responder_labor_usd_per_hour",
    "governance_labor_usd_per_hour",
    "infrastructure_usd_per_logical_agent_month_at_full_utilization",
    "evidence_storage_usd_per_gib_month",
    "utilization_basis_points",
    "retention_days",
)

REQUIRED_SCALE_FIELDS = (
    "logical_agents",
    "queue",
    "delegation_graph",
    "revocation",
    "policy_distribution",
    "evidence",
    "operator_span",
    "incident_response",
    "economics",
)

MEASURE_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "measure_id": "logical_fleet_workload",
        "classification": "synthetic_model_output",
        "field_paths": [
            "logical_agents",
            "queue.generated_events",
            "queue.completed_events",
        ],
    },
    {
        "measure_id": "throughput_and_queue_delay",
        "classification": "synthetic_model_output_not_wall_clock_measurement",
        "field_paths": [
            "queue.modeled_throughput_events_per_second",
            "queue.modeled_mean_queue_delay_microseconds",
            "queue.modeled_p95_queue_delay_microseconds",
            "queue.modeled_maximum_queue_delay_microseconds",
            "queue.modeled_maximum_queue_depth_events",
            "queue.modeled_service_utilization_percent",
            "queue.completion_window_microseconds",
            "queue.event_trace_sha256",
        ],
    },
    {
        "measure_id": "delegation_complexity",
        "classification": "synthetic_model_output",
        "field_paths": [
            "delegation_graph.nodes",
            "delegation_graph.edges",
            "delegation_graph.maximum_depth_hops",
            "delegation_graph.branching_factor",
            "delegation_graph.topology_sha256",
        ],
    },
    {
        "measure_id": "revocation_propagation",
        "classification": "synthetic_model_output_not_network_measurement",
        "field_paths": [
            "revocation.root_issuer_count",
            "revocation.recipient_count",
            "revocation.propagation_messages",
            "revocation.modeled_p95_propagation_microseconds",
            "revocation.modeled_maximum_propagation_microseconds",
            "revocation.propagation_trace_sha256",
        ],
    },
    {
        "measure_id": "policy_distribution",
        "classification": "synthetic_model_output_not_network_measurement",
        "field_paths": [
            "policy_distribution.recipient_count",
            "policy_distribution.policy_document_bytes",
            "policy_distribution.bytes_transmitted_per_update",
            "policy_distribution.bytes_transmitted_per_month",
            "policy_distribution.updates_per_month",
            "policy_distribution.modeled_p95_distribution_microseconds",
            "policy_distribution.modeled_maximum_distribution_microseconds",
            "policy_distribution.distribution_trace_sha256",
        ],
    },
    {
        "measure_id": "evidence_volume_and_retention",
        "classification": "synthetic_model_output",
        "field_paths": [
            "evidence.evidence_bytes_per_event",
            "evidence.evidence_bytes_per_model_horizon",
            "evidence.modeled_evidence_bytes_per_day",
            "evidence.base_retention_days",
            "evidence.modeled_base_retained_bytes",
            "evidence.modeled_base_retained_gib",
        ],
    },
    {
        "measure_id": "operator_span",
        "classification": "modeled_staffing_requirement_not_observed_staffing",
        "field_paths": [
            "operator_span.target_logical_agents_per_operator",
            "operator_span.required_operators",
            "operator_span.modeled_logical_agents_per_operator",
            "operator_span.modeled_oversight_labor_hours_per_month",
        ],
    },
    {
        "measure_id": "incident_response_effort",
        "classification": "modeled_effort_not_observed_incident_response",
        "field_paths": [
            "incident_response.modeled_incidents_per_month",
            "incident_response.modeled_effort_hours_per_incident",
            "incident_response.modeled_total_effort_hours_per_month",
            "incident_response.basis_incidents_per_10000_logical_agent_months",
        ],
    },
    {
        "measure_id": "fleet_economics_and_marginal_governance_cost",
        "classification": "modeled_cost_under_assumptions_not_forecast",
        "field_paths": [
            "economics[].sensitivity_case",
            "economics[].modeled_operator_labor_usd_per_month",
            "economics[].modeled_incident_response_labor_usd_per_month",
            "economics[].modeled_governance_labor_usd_per_month",
            "economics[].modeled_infrastructure_usd_per_month",
            "economics[].modeled_evidence_storage_usd_per_month",
            "economics[].modeled_total_governance_cost_usd_per_month",
            (
                "economics[]."
                "modeled_marginal_governance_cost_usd_per_added_logical_agent_month"
            ),
            "economics[].modeled_governance_labor_hours_per_month",
            "economics[].modeled_retained_evidence_gib",
        ],
    },
)

ACCEPTANCE_GATE_NAMES = (
    "exact_required_logical_agent_scales",
    "complete_per_scale_measure_contract",
    "throughput_and_queue_outputs_retained",
    "delegation_and_revocation_outputs_retained",
    "policy_and_evidence_outputs_retained",
    "operator_and_incident_effort_outputs_retained",
    "economic_sensitivity_outputs_retained",
    "all_model_assumptions_and_units_retained",
    "canonical_model_result_hash_valid",
    "synthetic_modeled_boundary_explicit",
    "deployment_and_effectiveness_claims_excluded",
    "exact_clean_committed_source_bound",
    "evidence_contains_no_sensitive_material",
)

EVIDENCE_LIMITS = (
    (
        "Deterministic synthetic model evidence only; no host benchmark, network "
        "measurement, or observed fleet-performance result is retained."
    ),
    (
        "A logical agent is an identity-bearing model actor, not a VM, host, process, "
        "physical endpoint, or deployed workload."
    ),
    (
        "Throughput, queue delay, propagation, distribution, evidence volume, staffing, "
        "incident effort, and cost are modeled outputs under retained assumptions."
    ),
    (
        "Economic values are sensitivity estimates, not budgets, quotes, forecasts, "
        "procurement data, or observed operating costs."
    ),
    (
        "Campaign acceptance means only that the deterministic model and retained-evidence "
        "contract passed against the exact source revision."
    ),
    (
        "The campaign does not establish deployment, production readiness, empirical "
        "capacity, operational effectiveness, independent validation, or replication."
    ),
)

MATERIAL_HANDLING = {
    "classification": "non_sensitive_synthetic_model_evidence",
    "private_or_sensitive_material_retained": False,
    "retained_material": [
        "public Git object identifiers and file digests",
        "fixed public model inputs and units",
        "synthetic model outputs and canonical digests",
        "Python runtime version",
    ],
    "excluded_material": [
        "credentials and authentication material",
        "environment variables and host identity",
        "plant telemetry and operational records",
        "proprietary pricing and procurement data",
    ],
}


class CampaignError(RuntimeError):
    """Raised when retained M6 evidence cannot be produced or verified safely."""


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
    module_path = Path(m6.__file__ or "").resolve()
    expected_module = (ROOT / "src" / "aegis_ot" / "m6_fleet.py").resolve()
    if module_path != expected_module:
        raise CampaignError(
            f"M6 module imported from stale source: expected {expected_module}, got {module_path}"
        )

    top_level = Path(_run_git_text("rev-parse", "--show-toplevel").strip()).resolve()
    if top_level != ROOT.resolve():
        raise CampaignError("runner is not executing from its authoritative Git checkout")
    status = _run_git_text("status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise CampaignError("retained M6 execution requires an exact clean checkout")

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


def _nested_field_present(value: Mapping[str, Any], path: str) -> bool:
    current: Any = value
    for component in path.split("."):
        if component.endswith("[]"):
            key = component[:-2]
            if not isinstance(current, Mapping):
                return False
            collection = current.get(key)
            if not isinstance(collection, list) or not collection:
                return False
            current = collection
            continue
        if isinstance(current, list):
            if not all(isinstance(item, Mapping) and component in item for item in current):
                return False
            current = [item[component] for item in current]
            continue
        if not isinstance(current, Mapping) or component not in current:
            return False
        current = current[component]
    return True


def _study_result_digest(study: Mapping[str, Any]) -> str:
    payload = dict(study)
    retained = payload.pop("result_sha256", None)
    if not isinstance(retained, str):
        raise CampaignError("model result digest is missing")
    return _sha256_json(payload)


def _acceptance_gates(
    study: Mapping[str, Any],
    *,
    source_bound: bool,
    sensitive_material_retained: bool,
) -> dict[str, bool]:
    scale_points = study.get("scale_points")
    scales = study.get("scales")
    exact_scales = (
        scale_points == list(m6.SCALE_POINTS)
        and isinstance(scales, list)
        and [item.get("logical_agents") for item in scales if isinstance(item, dict)]
        == list(m6.SCALE_POINTS)
        and len(scales) == len(m6.SCALE_POINTS)
    )
    scale_fields_complete = bool(scales) and all(
        isinstance(item, dict) and set(item) == set(REQUIRED_SCALE_FIELDS)
        for item in scales or []
    )

    def measure_complete(measure_id: str) -> bool:
        catalog_entry = next(
            item for item in MEASURE_CATALOG if item["measure_id"] == measure_id
        )
        return bool(scales) and all(
            isinstance(scale, dict)
            and all(
                _nested_field_present(scale, path)
                for path in catalog_entry["field_paths"]
            )
            for scale in scales or []
        )

    assumptions = study.get("assumptions")
    assumptions_complete = (
        isinstance(assumptions, dict)
        and set(assumptions) == set(REQUIRED_ASSUMPTION_FIELDS)
        and isinstance(assumptions.get("economic_cases"), list)
        and [
            item.get("name")
            for item in assumptions["economic_cases"]
            if isinstance(item, dict)
        ]
        == list(m6.SENSITIVITY_CASES)
        and len(assumptions["economic_cases"]) == len(m6.SENSITIVITY_CASES)
        and all(
            isinstance(item, dict)
            and set(item) == set(REQUIRED_ECONOMIC_CASE_FIELDS)
            for item in assumptions["economic_cases"]
        )
        and study.get("units") == dict(m6.UNIT_REGISTRY)
    )
    economics_complete = measure_complete(
        "fleet_economics_and_marginal_governance_cost"
    ) and all(
        isinstance(scale, dict)
        and isinstance(scale.get("economics"), list)
        and [
            item.get("sensitivity_case")
            for item in scale["economics"]
            if isinstance(item, dict)
        ]
        == list(m6.SENSITIVITY_CASES)
        and len(scale["economics"]) == len(m6.SENSITIVITY_CASES)
        for scale in scales or []
    )
    excluded = study.get("excluded_claims")
    boundaries_rendered = _canonical_bytes(
        {
            "claim_scope": study.get("claim_scope"),
            "logical_agent_definition": study.get("logical_agent_definition"),
            "excluded_claims": excluded,
        }
    ).decode("ascii").lower()
    try:
        result_hash_valid = study.get("result_sha256") == _study_result_digest(study)
    except CampaignError:
        result_hash_valid = False

    gates = {
        "exact_required_logical_agent_scales": exact_scales,
        "complete_per_scale_measure_contract": scale_fields_complete,
        "throughput_and_queue_outputs_retained": measure_complete(
            "throughput_and_queue_delay"
        ),
        "delegation_and_revocation_outputs_retained": (
            measure_complete("delegation_complexity")
            and measure_complete("revocation_propagation")
        ),
        "policy_and_evidence_outputs_retained": (
            measure_complete("policy_distribution")
            and measure_complete("evidence_volume_and_retention")
        ),
        "operator_and_incident_effort_outputs_retained": (
            measure_complete("operator_span")
            and measure_complete("incident_response_effort")
        ),
        "economic_sensitivity_outputs_retained": economics_complete,
        "all_model_assumptions_and_units_retained": assumptions_complete,
        "canonical_model_result_hash_valid": result_hash_valid,
        "synthetic_modeled_boundary_explicit": (
            study.get("evidence_classification") == "synthetic_model_output_only"
            and study.get("model_kind") == m6.MODEL_KIND
            and "modeled, not measured" in boundaries_rendered
            and "not a vm" in boundaries_rendered
        ),
        "deployment_and_effectiveness_claims_excluded": (
            isinstance(excluded, list)
            and "no deployment" in boundaries_rendered
            and "operational-effectiveness" in boundaries_rendered
            and "no independent validation or replication claim" in boundaries_rendered
        ),
        "exact_clean_committed_source_bound": source_bound,
        "evidence_contains_no_sensitive_material": not sensitive_material_retained,
    }
    if tuple(gates) != ACCEPTANCE_GATE_NAMES:
        raise CampaignError("acceptance-gate implementation drifted from its fixed catalog")
    return gates


def _semantic_projection(
    study: Mapping[str, Any], gates: Mapping[str, bool]
) -> dict[str, Any]:
    return {
        "projection_version": SEMANTIC_PROJECTION_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "study": dict(study),
        "measure_catalog": list(MEASURE_CATALOG),
        "acceptance_gates": dict(gates),
        "accepted": all(gates.values()),
        "evidence_limits": list(EVIDENCE_LIMITS),
    }


def _runtime_versions() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
    }


def _build_report(
    source_binding: Mapping[str, Any],
    *,
    run_id: str | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    study = m6.run_m6_fleet_study().to_dict()
    gates = _acceptance_gates(
        study,
        source_bound=True,
        sensitive_material_retained=False,
    )
    semantic_projection = _semantic_projection(study, gates)
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "run_id": str(uuid.uuid4()) if run_id is None else run_id,
        "generated_at": (
            datetime.now(UTC) if generated_at is None else generated_at
        ).isoformat(),
        "execution_mode": "retained_local_synthetic_model",
        "source_binding": dict(source_binding),
        "runtime_versions": _runtime_versions(),
        "scale_contract": list(m6.SCALE_POINTS),
        "measure_catalog": list(MEASURE_CATALOG),
        "assumption_contract": {
            "model_fields": list(REQUIRED_ASSUMPTION_FIELDS),
            "economic_case_fields": list(REQUIRED_ECONOMIC_CASE_FIELDS),
            "sensitivity_cases": list(m6.SENSITIVITY_CASES),
        },
        "study": study,
        "acceptance_gates": gates,
        "accepted": all(gates.values()),
        "semantic_projection_version": SEMANTIC_PROJECTION_VERSION,
        "semantic_outcome_sha256": _sha256_json(semantic_projection),
        "evidence_limits": list(EVIDENCE_LIMITS),
        "material_handling": dict(MATERIAL_HANDLING),
        "offline_verification": {
            "verifier": "scripts/run_m6_fleet.py --verify <evidence.json>",
            "network_required": False,
            "model_recomputed_from_exact_source": True,
            "passed_before_publication": True,
        },
    }
    report["integrity"] = {"canonical_payload_sha256": _sha256_json(report)}
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
    if path.name != "evidence.json":
        raise CampaignError("retained evidence filename must be evidence.json")
    file_status = path.stat()
    if stat.S_IMODE(file_status.st_mode) != 0o600:
        raise CampaignError("retained evidence file must be mode 0600")
    if file_status.st_nlink != 1:
        raise CampaignError("retained evidence file must have exactly one hard link")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise CampaignError("evidence directory must be a regular non-symlink directory")
    if not parent.name.startswith(OUTPUT_PREFIX):
        raise CampaignError("evidence directory is not owned by the M6 runner")
    if stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise CampaignError("retained evidence directory must be mode 0700")
    resolved_parent = parent.resolve()
    if resolved_parent == ROOT.resolve() or resolved_parent.is_relative_to(ROOT.resolve()):
        raise CampaignError("retained evidence must remain outside the source checkout")
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


def _contains_prohibited_material(value: Any) -> bool:
    prohibited_key_fragments = (
        "private_key",
        "password",
        "credential",
        "access_token",
        "api_key",
        "secret_key",
    )
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.lower().replace("-", "_")
            if key == "private_or_sensitive_material_retained":
                if item is not False:
                    return True
                continue
            if any(fragment in normalized for fragment in prohibited_key_fragments):
                return True
            if _contains_prohibited_material(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_prohibited_material(item) for item in value)
    if isinstance(value, str):
        upper = value.upper()
        return "-----BEGIN" in upper and "PRIVATE KEY-----" in upper
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
        "scale_contract",
        "measure_catalog",
        "assumption_contract",
        "study",
        "acceptance_gates",
        "accepted",
        "semantic_projection_version",
        "semantic_outcome_sha256",
        "evidence_limits",
        "material_handling",
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
    if report.get("execution_mode") != "retained_local_synthetic_model":
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
    if report.get("scale_contract") != list(m6.SCALE_POINTS):
        raise CampaignError("evidence scale contract is not exact")
    if report.get("measure_catalog") != list(MEASURE_CATALOG):
        raise CampaignError("evidence measure catalog is not exact")
    if report.get("assumption_contract") != {
        "model_fields": list(REQUIRED_ASSUMPTION_FIELDS),
        "economic_case_fields": list(REQUIRED_ECONOMIC_CASE_FIELDS),
        "sensitivity_cases": list(m6.SENSITIVITY_CASES),
    }:
        raise CampaignError("evidence assumption contract is not exact")
    if report.get("evidence_limits") != list(EVIDENCE_LIMITS):
        raise CampaignError("evidence limits are not exact")
    if report.get("material_handling") != MATERIAL_HANDLING:
        raise CampaignError("evidence material-handling declaration is not exact")
    if _contains_prohibited_material(report):
        raise CampaignError("evidence contains private or sensitive material")

    study = report.get("study")
    if not isinstance(study, dict):
        raise CampaignError("evidence study must be an object")
    expected_study = m6.run_m6_fleet_study().to_dict()
    if study != expected_study:
        raise CampaignError("retained M6 study does not replay exactly")
    if study.get("result_sha256") != _study_result_digest(study):
        raise CampaignError("retained model result digest is invalid")

    recomputed_gates = _acceptance_gates(
        study,
        source_bound=True,
        sensitive_material_retained=False,
    )
    if report.get("acceptance_gates") != recomputed_gates:
        raise CampaignError("retained acceptance gates do not match replayed outcomes")
    if report.get("accepted") is not all(recomputed_gates.values()):
        raise CampaignError("retained campaign acceptance is inconsistent")
    if report.get("semantic_projection_version") != SEMANTIC_PROJECTION_VERSION:
        raise CampaignError("semantic projection version is unsupported")
    semantic = _semantic_projection(study, recomputed_gates)
    if report.get("semantic_outcome_sha256") != _sha256_json(semantic):
        raise CampaignError("semantic outcome digest is invalid")

    offline = report.get("offline_verification")
    if not isinstance(offline, dict) or offline != {
        "verifier": "scripts/run_m6_fleet.py --verify <evidence.json>",
        "network_required": False,
        "model_recomputed_from_exact_source": True,
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
        if child.name != "evidence.json" or child.is_dir() or child.is_symlink():
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
            raise CampaignError("source changed while the retained M6 campaign was running")
        verify_evidence(evidence_path)
    except Exception:
        _remove_owned_output(output_directory)
        raise
    return evidence_path


def verify_evidence(path: Path) -> dict[str, Any]:
    report = _load_report(path)
    source_binding = _assert_clean_source()
    _verify_report_payload(report, expected_source_binding=source_binding)
    final_binding = _assert_clean_source()
    if final_binding != source_binding:
        raise CampaignError("source changed while M6 evidence was being verified")
    study = report["study"]
    return {
        "accepted": report["accepted"],
        "git_commit": source_binding["git_commit"],
        "source_fingerprint_sha256": source_binding["source_fingerprint_sha256"],
        "model_result_sha256": study["result_sha256"],
        "semantic_outcome_sha256": report["semantic_outcome_sha256"],
        "canonical_payload_sha256": report["integrity"]["canonical_payload_sha256"],
        "scale_points": report["scale_contract"],
        "private_or_sensitive_material_retained": False,
    }


def build_plan() -> dict[str, Any]:
    return {
        "schema_version": PLAN_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "execution_mode": "plan_only",
        "scale_contract": list(m6.SCALE_POINTS),
        "measure_catalog": list(MEASURE_CATALOG),
        "assumption_contract": {
            "model_fields": list(REQUIRED_ASSUMPTION_FIELDS),
            "economic_case_fields": list(REQUIRED_ECONOMIC_CASE_FIELDS),
            "sensitivity_cases": list(m6.SENSITIVITY_CASES),
        },
        "acceptance_gate_names": list(ACCEPTANCE_GATE_NAMES),
        "retained_execution_requirements": [
            "exact clean committed source",
            "exact logical-agent scales 10, 100, 1000, and 10000",
            "deterministic model recomputation by the same script",
            "unique mode-0700 output directory outside the checkout",
            "mode-0600 evidence file",
            "no private or sensitive material",
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
                "model_result_sha256": retained["study"]["result_sha256"],
                "semantic_outcome_sha256": retained["semantic_outcome_sha256"],
                "canonical_payload_sha256": retained["integrity"][
                    "canonical_payload_sha256"
                ],
                "private_or_sensitive_material_retained": False,
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
        print(f"M6 campaign failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
