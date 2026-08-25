"""File-oriented, independently implemented topology consequence evaluation.

The algorithm intentionally covers only source connectivity and served-load
arithmetic for the registered fresh-baseline line-isolation profile.  It does
not import or execute the Aegis-OT plant, controller, safety kernel, candidate,
permit, or acknowledgment implementation.
"""

from __future__ import annotations

import math
import os
import secrets
from collections import deque
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import (
    canonical_digest,
    canonical_json_bytes,
    public_key_b64,
    public_key_from_b64,
    sha256_bytes,
    sign_b64,
    strict_json_loads,
    verify_b64,
)

REQUEST_SCHEMA_VERSION = "m4b-independent-evaluation-request-v1"
REPORT_SCHEMA_VERSION = "m4b-independent-consequence-report-v1"
FIXTURE_SCHEMA_VERSION = "m4b-neutral-topology-fixture-v1"
EVALUATOR_PROFILE = "topology-connectivity-v1"
ALGORITHM_ID = "m4b-topology-consequence-bfs-decimal-v1"
EVALUATOR_ID = "m4b-independent-topology-evaluator"
REPORT_DOMAIN = b"AEGIS-OT-M4B-INDEPENDENT-REPORT-V1\0"
SHA256_LENGTH = 64

EvaluationStatus = Literal[
    "agree",
    "contradict",
    "indeterminate",
    "not_applicable",
    "input_rejected",
]

REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "session_index",
        "master_seed",
        "transaction_record_digest",
        "fixture_id",
        "fixture_digest",
        "evaluator_profile",
        "nonce",
        "pre_observation",
        "post_observation",
        "command",
        "observer_key_id",
        "observer_public_key_b64",
        "absolute_tolerance_mw",
        "absolute_tolerance_pct",
    }
)
REPORT_FIELDS = frozenset(
    {
        "schema_version",
        "report_id",
        "request_id",
        "request_digest",
        "evaluator_id",
        "key_id",
        "public_key_b64",
        "boot_epoch",
        "pid",
        "sequence",
        "evaluated_at",
        "fixture_id",
        "fixture_digest",
        "evaluator_profile",
        "algorithm_id",
        "evaluator_source_sha256",
        "status",
        "reasons",
        "predicted_values",
        "observed_values",
        "metric_comparisons",
        "signature",
    }
)
OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "observation_id",
        "correlation_id",
        "phase",
        "challenge_nonce",
        "observer_id",
        "observer_key_id",
        "observer_boot_epoch",
        "observer_sequence",
        "captured_at",
        "logical_time_s",
        "snapshot",
        "permit_id",
        "command_digest",
        "plc_acknowledgment_digest",
        "previous_envelope_digest",
        "envelope_digest",
        "signature",
    }
)
SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "model_id",
        "simulator_version",
        "model_digest",
        "input_digest",
        "topology_digest",
        "state_digest",
        "observation_digest",
        "observation_sequence",
        "observation_source_id",
        "observation_clock_domain",
        "state_version",
        "simulation_time_s",
        "observed_at",
        "converged",
        "total_load_demand_mw",
        "served_load_mw",
        "unserved_load_mw",
        "total_load_served_pct",
        "priority_load_demand_mw",
        "priority_load_served_mw",
        "priority_load_served_pct",
        "minimum_voltage_pu",
        "maximum_voltage_pu",
        "maximum_line_loading_pct",
        "voltage_violation_count",
        "thermal_violation_count",
        "unsafe_state",
        "isolated_resources",
        "battery_injection_mw",
        "bus_voltage_pu",
        "line_loading_pct",
    }
)
COMMAND_FIELDS = frozenset(
    {
        "schema_version",
        "command_id",
        "proposal_id",
        "operation",
        "resource",
        "command_type",
        "target",
        "target_index",
        "setpoint",
        "unit",
    }
)
FIXTURE_FIELDS = frozenset(
    {
        "schema_version",
        "fixture_id",
        "source",
        "buses",
        "branches",
        "sources",
        "loads",
        "controlled_resources",
        "fixture_digest",
    }
)
COMPARISON_METRICS = (
    "total_load_demand_mw",
    "served_load_mw",
    "priority_load_demand_mw",
    "priority_load_served_mw",
    "total_load_served_pct",
    "priority_load_served_pct",
    "isolated_resources",
)


class EvaluationInputError(ValueError):
    """A malformed or integrity-invalid evaluator input."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationInputError(f"{label}_must_be_object")
    return cast(dict[str, Any], value)


def _require_exact_fields(value: dict[str, Any], expected: frozenset[str], label: str) -> None:
    if set(value) != expected:
        raise EvaluationInputError(f"{label}_fields_invalid")


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_sha256(value: Any, label: str) -> str:
    if not _is_sha256(value):
        raise EvaluationInputError(f"{label}_invalid")
    return cast(str, value)


def _require_string(value: Any, label: str, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value) < minimum:
        raise EvaluationInputError(f"{label}_invalid")
    return value


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise EvaluationInputError(f"{label}_invalid")
    return value


def _decimal(value: Any, label: str, *, nonnegative: bool = True) -> Decimal:
    if not isinstance(value, str) or not value:
        raise EvaluationInputError(f"{label}_must_be_decimal_string")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise EvaluationInputError(f"{label}_invalid") from exc
    if not result.is_finite() or (nonnegative and result < 0):
        raise EvaluationInputError(f"{label}_invalid")
    return result


def _decimal_from_json(value: Any, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvaluationInputError(f"{label}_must_be_number")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise EvaluationInputError(f"{label}_invalid")
    return Decimal(str(value))


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    rendered = format(value.normalize(), "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _utc_now_text() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def evaluator_source_sha256() -> str:
    """Hash the complete independent package source set in a stable order."""

    root = Path(__file__).resolve().parent
    material = bytearray()
    for path in sorted(root.glob("*.py"), key=lambda item: item.name):
        material.extend(path.name.encode("utf-8"))
        material.extend(b"\0")
        material.extend(path.read_bytes())
        material.extend(b"\0")
    return sha256_bytes(bytes(material))


def _validate_snapshot(snapshot: Any, label: str) -> dict[str, Any]:
    value = _require_object(snapshot, label)
    _require_exact_fields(value, SNAPSHOT_FIELDS, label)
    if value.get("schema_version") != "physical-state-v1":
        raise EvaluationInputError(f"{label}_schema_invalid")
    for field in (
        "model_digest",
        "input_digest",
        "topology_digest",
        "state_digest",
        "observation_digest",
    ):
        _require_sha256(value.get(field), f"{label}_{field}")
    _require_int(value.get("state_version"), f"{label}_state_version")
    _require_int(value.get("observation_sequence"), f"{label}_observation_sequence")
    if not isinstance(value.get("converged"), bool):
        raise EvaluationInputError(f"{label}_converged_invalid")
    isolated = value.get("isolated_resources")
    if (
        not isinstance(isolated, list)
        or any(not isinstance(item, str) or not item for item in isolated)
        or len(set(isolated)) != len(isolated)
        or isolated != sorted(isolated)
    ):
        raise EvaluationInputError(f"{label}_isolated_resources_invalid")
    digest_material = {
        key: item
        for key, item in value.items()
        if key
        not in {
            "state_digest",
            "observation_digest",
            "observation_sequence",
            "observation_source_id",
            "observation_clock_domain",
            "observed_at",
        }
    }
    if value["state_digest"] != canonical_digest(digest_material):
        raise EvaluationInputError(f"{label}_state_digest_mismatch")
    observed_at = value.get("observed_at")
    if not isinstance(observed_at, str):
        raise EvaluationInputError(f"{label}_observed_at_invalid")
    try:
        parsed_observed_at = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvaluationInputError(f"{label}_observed_at_invalid") from exc
    if parsed_observed_at.tzinfo is None:
        raise EvaluationInputError(f"{label}_observed_at_invalid")
    observation_material = {
        "state_digest": value["state_digest"],
        # PhysicalStateSnapshot computes this digest from datetime.isoformat(),
        # while its JSON representation emits UTC with a trailing ``Z``.
        "observed_at": parsed_observed_at.isoformat(),
        "observation_sequence": value["observation_sequence"],
        "observation_source_id": value["observation_source_id"],
        "observation_clock_domain": value["observation_clock_domain"],
    }
    if value["observation_digest"] != canonical_digest(observation_material):
        raise EvaluationInputError(f"{label}_observation_digest_mismatch")
    return value


def _validate_observation(
    observation: Any,
    *,
    label: str,
    expected_phase: str,
    observer_key_id: str,
    observer_public_key_b64: str,
) -> dict[str, Any]:
    value = _require_object(observation, label)
    _require_exact_fields(value, OBSERVATION_FIELDS, label)
    if value.get("schema_version") != "signed-observation-v1":
        raise EvaluationInputError(f"{label}_schema_invalid")
    if value.get("phase") != expected_phase:
        raise EvaluationInputError(f"{label}_phase_invalid")
    if value.get("observer_key_id") != observer_key_id:
        raise EvaluationInputError(f"{label}_observer_key_mismatch")
    _validate_snapshot(value.get("snapshot"), f"{label}_snapshot")
    _require_sha256(value.get("envelope_digest"), f"{label}_envelope_digest")
    digest_material = {
        key: item
        for key, item in value.items()
        if key not in {"envelope_digest", "signature"}
    }
    if value["envelope_digest"] != canonical_digest(digest_material):
        raise EvaluationInputError(f"{label}_envelope_digest_mismatch")
    public_key = public_key_from_b64(observer_public_key_b64)
    signing_payload = canonical_json_bytes(
        {key: item for key, item in value.items() if key != "signature"}
    )
    if not isinstance(value.get("signature"), str) or not verify_b64(
        public_key,
        signing_payload,
        value["signature"],
    ):
        raise EvaluationInputError(f"{label}_signature_invalid")
    return value


def _validate_command(command: Any) -> dict[str, Any]:
    value = _require_object(command, "command")
    _require_exact_fields(value, COMMAND_FIELDS, "command")
    if value.get("schema_version") != "physical-command-v1":
        raise EvaluationInputError("command_schema_invalid")
    _require_string(value.get("command_id"), "command_id")
    _require_string(value.get("proposal_id"), "command_proposal_id")
    _require_string(value.get("resource"), "command_resource")
    _require_string(value.get("target"), "command_target")
    _require_int(value.get("target_index"), "command_target_index")
    setpoint = value.get("setpoint")
    if isinstance(setpoint, bool) or not isinstance(setpoint, (int, float)):
        raise EvaluationInputError("command_setpoint_invalid")
    if not math.isfinite(float(setpoint)):
        raise EvaluationInputError("command_setpoint_invalid")
    return value


def _validate_request(value: Any) -> dict[str, Any]:
    request = _require_object(value, "request")
    _require_exact_fields(request, REQUEST_FIELDS, "request")
    if request.get("schema_version") != REQUEST_SCHEMA_VERSION:
        raise EvaluationInputError("request_schema_invalid")
    _require_string(request.get("request_id"), "request_id")
    _require_int(request.get("session_index"), "session_index")
    _require_int(request.get("master_seed"), "master_seed")
    _require_sha256(request.get("transaction_record_digest"), "transaction_record_digest")
    _require_string(request.get("fixture_id"), "fixture_id")
    _require_sha256(request.get("fixture_digest"), "fixture_digest")
    if request.get("evaluator_profile") != EVALUATOR_PROFILE:
        raise EvaluationInputError("evaluator_profile_unsupported")
    _require_string(request.get("nonce"), "nonce", minimum=16)
    observer_key_id = _require_string(request.get("observer_key_id"), "observer_key_id")
    observer_public = _require_string(
        request.get("observer_public_key_b64"),
        "observer_public_key_b64",
    )
    public_key_from_b64(observer_public)
    _decimal(request.get("absolute_tolerance_mw"), "absolute_tolerance_mw")
    _decimal(request.get("absolute_tolerance_pct"), "absolute_tolerance_pct")
    if request.get("pre_observation") is None:
        raise EvaluationInputError("pre_observation_required")
    pre = _validate_observation(
        request["pre_observation"],
        label="pre_observation",
        expected_phase="pre_authorization",
        observer_key_id=observer_key_id,
        observer_public_key_b64=observer_public,
    )
    post_value = request.get("post_observation")
    post: dict[str, Any] | None = None
    if post_value is not None:
        post = _validate_observation(
            post_value,
            label="post_observation",
            expected_phase="post_dispatch",
            observer_key_id=observer_key_id,
            observer_public_key_b64=observer_public,
        )
        if (
            post.get("observer_id") != pre.get("observer_id")
            or post.get("observer_boot_epoch") != pre.get("observer_boot_epoch")
            or cast(int, post.get("observer_sequence"))
            <= cast(int, pre.get("observer_sequence"))
            or post.get("previous_envelope_digest") != pre.get("envelope_digest")
        ):
            raise EvaluationInputError("observation_pair_binding_invalid")
    command_value = request.get("command")
    command = _validate_command(command_value) if command_value is not None else None
    if command is None and post is not None:
        raise EvaluationInputError("post_observation_without_command")
    if command is not None and post is not None:
        if post.get("command_digest") != canonical_digest(command):
            raise EvaluationInputError("post_observation_command_digest_mismatch")
    return request


def _validate_fixture(value: Any) -> dict[str, Any]:
    fixture = _require_object(value, "fixture")
    _require_exact_fields(fixture, FIXTURE_FIELDS, "fixture")
    if fixture.get("schema_version") != FIXTURE_SCHEMA_VERSION:
        raise EvaluationInputError("fixture_schema_invalid")
    _require_string(fixture.get("fixture_id"), "fixture_id")
    _require_sha256(fixture.get("fixture_digest"), "fixture_digest")
    digest_material = {key: item for key, item in fixture.items() if key != "fixture_digest"}
    if fixture["fixture_digest"] != canonical_digest(digest_material):
        raise EvaluationInputError("fixture_digest_mismatch")

    buses = fixture.get("buses")
    if (
        not isinstance(buses, list)
        or any(type(item) is not int or item < 0 for item in buses)
        or len(set(buses)) != len(buses)
        or buses != sorted(buses)
    ):
        raise EvaluationInputError("fixture_buses_invalid")
    bus_set = set(cast(list[int], buses))

    branch_ids: set[str] = set()
    branches = fixture.get("branches")
    if not isinstance(branches, list) or not branches:
        raise EvaluationInputError("fixture_branches_invalid")
    for item in branches:
        branch = _require_object(item, "fixture_branch")
        if set(branch) != {
            "branch_id",
            "kind",
            "target_index",
            "from_bus",
            "to_bus",
            "baseline_in_service",
        }:
            raise EvaluationInputError("fixture_branch_fields_invalid")
        branch_id = _require_string(branch.get("branch_id"), "fixture_branch_id")
        if branch_id in branch_ids:
            raise EvaluationInputError("fixture_branch_duplicate")
        branch_ids.add(branch_id)
        if branch.get("kind") not in {"line", "transformer"}:
            raise EvaluationInputError("fixture_branch_kind_invalid")
        _require_int(branch.get("target_index"), "fixture_branch_target_index")
        if branch.get("from_bus") not in bus_set or branch.get("to_bus") not in bus_set:
            raise EvaluationInputError("fixture_branch_bus_invalid")
        if not isinstance(branch.get("baseline_in_service"), bool):
            raise EvaluationInputError("fixture_branch_service_invalid")

    sources = fixture.get("sources")
    if not isinstance(sources, list) or not sources:
        raise EvaluationInputError("fixture_sources_invalid")
    source_ids: set[str] = set()
    for item in sources:
        source = _require_object(item, "fixture_source")
        if set(source) != {"source_id", "bus", "in_service"}:
            raise EvaluationInputError("fixture_source_fields_invalid")
        source_id = _require_string(source.get("source_id"), "fixture_source_id")
        if source_id in source_ids or source.get("bus") not in bus_set:
            raise EvaluationInputError("fixture_source_invalid")
        source_ids.add(source_id)
        if not isinstance(source.get("in_service"), bool):
            raise EvaluationInputError("fixture_source_service_invalid")

    loads = fixture.get("loads")
    if not isinstance(loads, list):
        raise EvaluationInputError("fixture_loads_invalid")
    load_ids: set[str] = set()
    for item in loads:
        load = _require_object(item, "fixture_load")
        if set(load) != {"load_id", "bus", "p_mw", "in_service", "priority"}:
            raise EvaluationInputError("fixture_load_fields_invalid")
        load_id = _require_string(load.get("load_id"), "fixture_load_id")
        if load_id in load_ids or load.get("bus") not in bus_set:
            raise EvaluationInputError("fixture_load_invalid")
        load_ids.add(load_id)
        _decimal(load.get("p_mw"), "fixture_load_p_mw")
        if not isinstance(load.get("in_service"), bool) or not isinstance(
            load.get("priority"), bool
        ):
            raise EvaluationInputError("fixture_load_state_invalid")

    resources = fixture.get("controlled_resources")
    if not isinstance(resources, list):
        raise EvaluationInputError("fixture_resources_invalid")
    resource_ids: set[str] = set()
    for item in resources:
        resource = _require_object(item, "fixture_resource")
        if set(resource) != {
            "resource",
            "command_type",
            "branch_id",
            "target",
            "target_index",
        }:
            raise EvaluationInputError("fixture_resource_fields_invalid")
        name = _require_string(resource.get("resource"), "fixture_resource_name")
        if name in resource_ids or resource.get("branch_id") not in branch_ids:
            raise EvaluationInputError("fixture_resource_invalid")
        resource_ids.add(name)
        if resource.get("command_type") != "set_line_service":
            raise EvaluationInputError("fixture_resource_command_invalid")
        _require_string(resource.get("target"), "fixture_resource_target")
        _require_int(resource.get("target_index"), "fixture_resource_target_index")
    return fixture


def _connected_buses(
    fixture: dict[str, Any],
    *,
    branch_override: tuple[str, bool] | None,
) -> set[int]:
    graph: dict[int, set[int]] = {int(bus): set() for bus in fixture["buses"]}
    for branch in fixture["branches"]:
        enabled = bool(branch["baseline_in_service"])
        if branch_override is not None and branch["branch_id"] == branch_override[0]:
            enabled = branch_override[1]
        if enabled:
            start = int(branch["from_bus"])
            end = int(branch["to_bus"])
            graph[start].add(end)
            graph[end].add(start)
    reachable = {
        int(source["bus"])
        for source in fixture["sources"]
        if bool(source["in_service"])
    }
    queue: deque[int] = deque(sorted(reachable))
    while queue:
        current = queue.popleft()
        for neighbor in sorted(graph[current]):
            if neighbor not in reachable:
                reachable.add(neighbor)
                queue.append(neighbor)
    return reachable


def _topology_values(
    fixture: dict[str, Any],
    *,
    branch_override: tuple[str, bool] | None,
    isolated_resources: tuple[str, ...],
) -> dict[str, Any]:
    reachable = _connected_buses(fixture, branch_override=branch_override)
    total_demand = Decimal(0)
    served = Decimal(0)
    priority_demand = Decimal(0)
    priority_served = Decimal(0)
    for load in fixture["loads"]:
        if not bool(load["in_service"]):
            continue
        demand = _decimal(load["p_mw"], "fixture_load_p_mw")
        total_demand += demand
        supplied = int(load["bus"]) in reachable
        if supplied:
            served += demand
        if bool(load["priority"]):
            priority_demand += demand
            if supplied:
                priority_served += demand
    total_pct = Decimal(100) if total_demand == 0 else served * Decimal(100) / total_demand
    priority_pct = (
        Decimal(100)
        if priority_demand == 0
        else priority_served * Decimal(100) / priority_demand
    )
    return {
        "source_connected_bus_count": len(reachable),
        "total_load_demand_mw": _decimal_text(total_demand),
        "served_load_mw": _decimal_text(served),
        "priority_load_demand_mw": _decimal_text(priority_demand),
        "priority_load_served_mw": _decimal_text(priority_served),
        "total_load_served_pct": _decimal_text(total_pct),
        "priority_load_served_pct": _decimal_text(priority_pct),
        "isolated_resources": list(isolated_resources),
    }


def _observed_values(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_connected_bus_count": None,
        "total_load_demand_mw": _decimal_text(
            _decimal_from_json(snapshot["total_load_demand_mw"], "total_load_demand_mw")
        ),
        "served_load_mw": _decimal_text(
            _decimal_from_json(snapshot["served_load_mw"], "served_load_mw")
        ),
        "priority_load_demand_mw": _decimal_text(
            _decimal_from_json(
                snapshot["priority_load_demand_mw"], "priority_load_demand_mw"
            )
        ),
        "priority_load_served_mw": _decimal_text(
            _decimal_from_json(
                snapshot["priority_load_served_mw"], "priority_load_served_mw"
            )
        ),
        "total_load_served_pct": _decimal_text(
            _decimal_from_json(snapshot["total_load_served_pct"], "total_load_served_pct")
        ),
        "priority_load_served_pct": _decimal_text(
            _decimal_from_json(
                snapshot["priority_load_served_pct"], "priority_load_served_pct"
            )
        ),
        "isolated_resources": list(snapshot["isolated_resources"]),
    }


def _metric_comparisons(
    predicted: dict[str, Any],
    observed: dict[str, Any],
    *,
    tolerance_mw: Decimal,
    tolerance_pct: Decimal,
) -> list[dict[str, str]]:
    comparisons: list[dict[str, str]] = []
    for metric in COMPARISON_METRICS:
        if metric == "isolated_resources":
            expected_text = canonical_json_bytes(predicted[metric]).decode("utf-8")
            observed_text = canonical_json_bytes(observed[metric]).decode("utf-8")
            match = expected_text == observed_text
            tolerance = "exact"
        else:
            expected_text = cast(str, predicted[metric])
            observed_text = cast(str, observed[metric])
            tolerance_value = tolerance_pct if metric.endswith("_pct") else tolerance_mw
            tolerance = _decimal_text(tolerance_value)
            match = abs(Decimal(expected_text) - Decimal(observed_text)) <= tolerance_value
        comparisons.append(
            {
                "metric": metric,
                "expected": expected_text,
                "observed": observed_text,
                "tolerance": tolerance,
                "outcome": "match" if match else "mismatch",
            }
        )
    return comparisons


def _new_report_base(
    request: dict[str, Any] | None,
    *,
    request_digest: str,
    fixture: dict[str, Any] | None,
    private_key: Ed25519PrivateKey,
    boot_epoch: str,
    sequence: int,
) -> dict[str, Any]:
    public_key = private_key.public_key()
    public_b64 = public_key_b64(public_key)
    fingerprint = sha256_bytes(public_key_from_b64(public_b64).public_bytes_raw())
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_id": str(uuid4()),
        "request_id": (
            request.get("request_id")
            if isinstance(request, dict) and isinstance(request.get("request_id"), str)
            else "unavailable"
        ),
        "request_digest": request_digest,
        "evaluator_id": EVALUATOR_ID,
        "key_id": f"m4b-independent:{fingerprint[:24]}",
        "public_key_b64": public_b64,
        "boot_epoch": boot_epoch,
        "pid": os.getpid(),
        "sequence": sequence,
        "evaluated_at": _utc_now_text(),
        "fixture_id": (
            fixture.get("fixture_id")
            if isinstance(fixture, dict) and isinstance(fixture.get("fixture_id"), str)
            else (
                request.get("fixture_id")
                if isinstance(request, dict) and isinstance(request.get("fixture_id"), str)
                else "unavailable"
            )
        ),
        "fixture_digest": (
            fixture.get("fixture_digest")
            if isinstance(fixture, dict) and _is_sha256(fixture.get("fixture_digest"))
            else (
                request.get("fixture_digest")
                if isinstance(request, dict) and _is_sha256(request.get("fixture_digest"))
                else "0" * SHA256_LENGTH
            )
        ),
        "evaluator_profile": EVALUATOR_PROFILE,
        "algorithm_id": ALGORITHM_ID,
        "evaluator_source_sha256": evaluator_source_sha256(),
        "status": "input_rejected",
        "reasons": ["input_rejected"],
        "predicted_values": None,
        "observed_values": None,
        "metric_comparisons": [],
        "signature": "",
    }


def _sign_report(report: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    unsigned = {key: item for key, item in report.items() if key != "signature"}
    return {
        **unsigned,
        "signature": sign_b64(private_key, REPORT_DOMAIN + canonical_json_bytes(unsigned)),
    }


def _report(
    request: dict[str, Any] | None,
    *,
    request_digest: str,
    fixture: dict[str, Any] | None,
    private_key: Ed25519PrivateKey,
    boot_epoch: str,
    sequence: int,
    status: EvaluationStatus,
    reasons: list[str],
    predicted: dict[str, Any] | None = None,
    observed: dict[str, Any] | None = None,
    comparisons: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    base = _new_report_base(
        request,
        request_digest=request_digest,
        fixture=fixture,
        private_key=private_key,
        boot_epoch=boot_epoch,
        sequence=sequence,
    )
    base.update(
        {
            "status": status,
            "reasons": reasons,
            "predicted_values": predicted,
            "observed_values": observed,
            "metric_comparisons": comparisons or [],
        }
    )
    return _sign_report(base, private_key)


def evaluate_request(
    request_value: Any,
    fixture_value: Any,
    *,
    private_key: Ed25519PrivateKey | None = None,
    boot_epoch: str | None = None,
    sequence: int = 1,
) -> dict[str, Any]:
    """Evaluate one already-decoded request and return a signed report."""

    signer = private_key or Ed25519PrivateKey.generate()
    boot = boot_epoch or secrets.token_urlsafe(24)
    raw_request_digest = canonical_digest(request_value)
    request: dict[str, Any] | None = request_value if isinstance(request_value, dict) else None
    fixture: dict[str, Any] | None = fixture_value if isinstance(fixture_value, dict) else None
    try:
        request = _validate_request(request_value)
        fixture = _validate_fixture(fixture_value)
        request_digest = canonical_digest(request)
        if request["fixture_id"] != fixture["fixture_id"]:
            raise EvaluationInputError("request_fixture_id_mismatch")
        if request["fixture_digest"] != fixture["fixture_digest"]:
            raise EvaluationInputError("request_fixture_digest_mismatch")
    except (EvaluationInputError, ValueError, TypeError) as exc:
        return _report(
            request,
            request_digest=raw_request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="input_rejected",
            reasons=(
                [str(exc)]
                if isinstance(exc, EvaluationInputError)
                else [f"input_invalid:{type(exc).__name__}"]
            ),
        )

    command = cast(dict[str, Any] | None, request["command"])
    post = cast(dict[str, Any] | None, request["post_observation"])
    pre = cast(dict[str, Any], request["pre_observation"])
    if command is None and post is None:
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="not_applicable",
            reasons=["transaction_has_no_consequence_artifacts"],
        )
    if command is None:
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="input_rejected",
            reasons=["post_observation_without_command"],
        )
    if post is None:
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="indeterminate",
            reasons=["post_observation_unavailable"],
        )
    if command.get("command_type") != "set_line_service":
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="indeterminate",
            reasons=["command_type_outside_topology_profile"],
        )
    if command.get("unit") != "boolean" or Decimal(str(command.get("setpoint"))) not in {
        Decimal(0),
        Decimal(1),
    }:
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="indeterminate",
            reasons=["command_outside_line_service_profile"],
        )

    resource = next(
        (
            item
            for item in fixture["controlled_resources"]
            if item["resource"] == command.get("resource")
        ),
        None,
    )
    if resource is None:
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="indeterminate",
            reasons=["resource_outside_registered_fixture"],
        )
    if (
        resource["target"] != command.get("target")
        or resource["target_index"] != command.get("target_index")
    ):
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="input_rejected",
            reasons=["command_fixture_binding_mismatch"],
        )

    pre_snapshot = cast(dict[str, Any], pre["snapshot"])
    post_snapshot = cast(dict[str, Any], post["snapshot"])
    if not bool(pre_snapshot["converged"]):
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="indeterminate",
            reasons=["pre_observation_not_converged"],
        )
    if pre_snapshot["isolated_resources"]:
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="indeterminate",
            reasons=["prestate_outside_registered_fresh_baseline"],
        )
    if not bool(post_snapshot["converged"]):
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="indeterminate",
            reasons=["post_observation_not_converged"],
        )

    baseline = _topology_values(
        fixture,
        branch_override=None,
        isolated_resources=(),
    )
    pre_values = _observed_values(pre_snapshot)
    tolerance_mw = _decimal(request["absolute_tolerance_mw"], "absolute_tolerance_mw")
    tolerance_pct = _decimal(request["absolute_tolerance_pct"], "absolute_tolerance_pct")
    baseline_comparisons = _metric_comparisons(
        baseline,
        pre_values,
        tolerance_mw=tolerance_mw,
        tolerance_pct=tolerance_pct,
    )
    if any(item["outcome"] != "match" for item in baseline_comparisons):
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="indeterminate",
            reasons=["prestate_does_not_match_registered_fixture"],
            predicted=baseline,
            observed=pre_values,
            comparisons=baseline_comparisons,
        )

    enabled = Decimal(str(command["setpoint"])) == Decimal(1)
    isolated = () if enabled else (cast(str, resource["resource"]),)
    predicted = _topology_values(
        fixture,
        branch_override=(cast(str, resource["branch_id"]), enabled),
        isolated_resources=isolated,
    )
    observed = _observed_values(post_snapshot)
    comparisons = _metric_comparisons(
        predicted,
        observed,
        tolerance_mw=tolerance_mw,
        tolerance_pct=tolerance_pct,
    )
    mismatches = [item["metric"] for item in comparisons if item["outcome"] == "mismatch"]
    if mismatches:
        return _report(
            request,
            request_digest=request_digest,
            fixture=fixture,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="contradict",
            reasons=[f"metric_mismatch:{metric}" for metric in mismatches],
            predicted=predicted,
            observed=observed,
            comparisons=comparisons,
        )
    return _report(
        request,
        request_digest=request_digest,
        fixture=fixture,
        private_key=signer,
        boot_epoch=boot,
        sequence=sequence,
        status="agree",
        reasons=["registered_topology_consequence_matches"],
        predicted=predicted,
        observed=observed,
        comparisons=comparisons,
    )


def evaluate_material(
    request_material: bytes,
    fixture_material: bytes,
    *,
    private_key: Ed25519PrivateKey | None = None,
    boot_epoch: str | None = None,
    sequence: int = 1,
) -> dict[str, Any]:
    """Decode strict JSON materials and always return a signed report."""

    signer = private_key or Ed25519PrivateKey.generate()
    boot = boot_epoch or secrets.token_urlsafe(24)
    request: Any = None
    fixture: Any = None
    try:
        request = strict_json_loads(request_material)
        fixture = strict_json_loads(fixture_material)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        return _report(
            request if isinstance(request, dict) else None,
            request_digest=sha256_bytes(request_material),
            fixture=fixture if isinstance(fixture, dict) else None,
            private_key=signer,
            boot_epoch=boot,
            sequence=sequence,
            status="input_rejected",
            reasons=[f"json_invalid:{type(exc).__name__}"],
        )
    return evaluate_request(
        request,
        fixture,
        private_key=signer,
        boot_epoch=boot,
        sequence=sequence,
    )


def verify_report(report_value: Any) -> bool:
    """Verify the report's closed shape and self-signature.

    The included key proves consistency with the report signer.  A future M4b
    package must separately bind that key to an out-of-package trust anchor.
    """

    try:
        report = _require_object(report_value, "report")
        _require_exact_fields(report, REPORT_FIELDS, "report")
        if (
            report.get("schema_version") != REPORT_SCHEMA_VERSION
            or report.get("evaluator_id") != EVALUATOR_ID
            or report.get("evaluator_profile") != EVALUATOR_PROFILE
            or report.get("algorithm_id") != ALGORITHM_ID
            or report.get("status")
            not in {
                "agree",
                "contradict",
                "indeterminate",
                "not_applicable",
                "input_rejected",
            }
            or not isinstance(report.get("reasons"), list)
            or not report["reasons"]
            or any(not isinstance(item, str) or not item for item in report["reasons"])
        ):
            return False
        for field in (
            "request_digest",
            "fixture_digest",
            "evaluator_source_sha256",
        ):
            if not _is_sha256(report.get(field)):
                return False
        _require_int(report.get("pid"), "report_pid", minimum=1)
        _require_int(report.get("sequence"), "report_sequence", minimum=1)
        public_key = public_key_from_b64(cast(str, report.get("public_key_b64")))
        unsigned = {key: item for key, item in report.items() if key != "signature"}
        signature = report.get("signature")
        return isinstance(signature, str) and verify_b64(
            public_key,
            REPORT_DOMAIN + canonical_json_bytes(unsigned),
            signature,
        )
    except (EvaluationInputError, TypeError, ValueError):
        return False
