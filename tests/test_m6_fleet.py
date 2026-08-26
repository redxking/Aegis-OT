from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest

from aegis_ot.m6_fleet import (
    BYTES_PER_GIB,
    DEFAULT_ECONOMIC_CASES,
    MODEL_KIND,
    SCALE_POINTS,
    EconomicCase,
    FleetModelAssumptions,
    run_m6_fleet_study,
)

ROOT = Path(__file__).resolve().parents[1]


def _canonical_sha256(value: object) -> str:
    material = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(material).hexdigest()


def _case(scale: Any, name: str) -> Any:
    return next(item for item in scale.economics if item.sensitivity_case == name)


def test_study_covers_only_the_four_required_logical_agent_scales() -> None:
    report = run_m6_fleet_study()

    assert report.scale_points == (10, 100, 1_000, 10_000) == SCALE_POINTS
    assert tuple(item.logical_agents for item in report.scales) == SCALE_POINTS
    assert report.model_kind == MODEL_KIND
    assert report.logical_agent_definition.endswith(
        "not a VM, host, process, physical endpoint, or deployed system."
    )

    events_per_agent = report.assumptions.events_per_logical_agent_per_horizon
    for scale in report.scales:
        assert scale.queue.generated_events == scale.logical_agents * events_per_agent
        assert scale.queue.completed_events == scale.queue.generated_events
        assert scale.delegation_graph.nodes == scale.logical_agents
        assert scale.delegation_graph.edges == scale.logical_agents - 1
        assert scale.revocation.recipient_count == scale.logical_agents - 1
        assert scale.revocation.propagation_messages == scale.logical_agents - 1
        assert scale.policy_distribution.recipient_count == scale.logical_agents - 1


def test_default_study_is_deterministic_and_canonically_hashed() -> None:
    first = run_m6_fleet_study()
    second = run_m6_fleet_study()

    assert first == second
    assert first.canonical_json() == second.canonical_json()
    assert first.result_sha256 == second.result_sha256
    assert first.result_sha256 == _canonical_sha256(first.result_payload())
    decoded = cast(dict[str, Any], json.loads(first.canonical_json()))
    assert decoded["result_sha256"] == first.result_sha256


def test_result_hash_is_stable_across_python_hash_seeds() -> None:
    code = (
        "from aegis_ot.m6_fleet import run_m6_fleet_study; "
        "print(run_m6_fleet_study().result_sha256)"
    )
    observed: list[str] = []
    for hash_seed in ("1", "987654321"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = hash_seed
        environment["PYTHONPATH"] = str(ROOT / "src")
        completed = subprocess.run(  # noqa: S603 - fixed interpreter and literal test code
            [sys.executable, "-c", code],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        observed.append(completed.stdout.strip())

    assert len(set(observed)) == 1
    assert observed[0] == run_m6_fleet_study().result_sha256


def test_seed_changes_traces_but_not_closed_workload_counts() -> None:
    first = run_m6_fleet_study(
        assumptions=FleetModelAssumptions(seed="aegis-ot-m6-seed-one")
    )
    second = run_m6_fleet_study(
        assumptions=FleetModelAssumptions(seed="aegis-ot-m6-seed-two")
    )

    assert first.result_sha256 != second.result_sha256
    assert [item.queue.generated_events for item in first.scales] == [
        item.queue.generated_events for item in second.scales
    ]
    assert [item.queue.event_trace_sha256 for item in first.scales] != [
        item.queue.event_trace_sha256 for item in second.scales
    ]
    assert [item.revocation.propagation_trace_sha256 for item in first.scales] != [
        item.revocation.propagation_trace_sha256 for item in second.scales
    ]


def test_units_and_decimal_encoding_are_explicit() -> None:
    report = run_m6_fleet_study()
    assert report.units == {
        "logical_agent": "logical_agent",
        "queue_throughput": "modeled_event/second",
        "event_count": "event",
        "time": "microsecond",
        "service_utilization": "percent",
        "delegation_depth": "hop",
        "data_volume": "byte",
        "retained_data_volume": "GiB (2^30 byte)",
        "operator_count": "operator",
        "operator_span": "logical_agent/operator",
        "incident_rate": "modeled_incident/month",
        "labor_effort": "labor-hour/month",
        "labor_rate": "USD/labor-hour",
        "infrastructure_rate": (
            "USD/logical-agent-month at 100 percent utilization"
        ),
        "storage_rate": "USD/GiB-month",
        "monthly_cost": "USD/month",
        "marginal_governance_cost": "USD/added-logical-agent-month",
        "retention": "day",
        "utilization_input": "basis-point (1 basis-point = 0.01 percent)",
    }
    decoded = cast(dict[str, Any], json.loads(report.canonical_json()))
    first_queue = decoded["scales"][0]["queue"]
    first_cost = decoded["scales"][0]["economics"][0]
    assert isinstance(first_queue["modeled_throughput_events_per_second"], str)
    assert isinstance(first_queue["modeled_mean_queue_delay_microseconds"], str)
    assert isinstance(first_cost["modeled_total_governance_cost_usd_per_month"], str)


def test_queue_graph_propagation_policy_and_evidence_relationships_are_auditable() -> None:
    report = run_m6_fleet_study()
    scales = report.scales

    throughput = [item.queue.modeled_throughput_events_per_second for item in scales]
    p95_queue_delay = [item.queue.modeled_p95_queue_delay_microseconds for item in scales]
    queue_depth = [item.queue.modeled_maximum_queue_depth_events for item in scales]
    graph_depth = [item.delegation_graph.maximum_depth_hops for item in scales]
    revocation_max = [item.revocation.modeled_maximum_propagation_microseconds for item in scales]
    policy_max = [
        item.policy_distribution.modeled_maximum_distribution_microseconds for item in scales
    ]
    evidence = [item.evidence.modeled_evidence_bytes_per_day for item in scales]

    assert throughput == sorted(throughput)
    assert len(set(throughput)) == len(throughput)
    assert p95_queue_delay == sorted(p95_queue_delay)
    assert queue_depth == sorted(queue_depth)
    assert graph_depth == [1, 2, 3, 4]
    assert revocation_max == sorted(revocation_max)
    assert policy_max == sorted(policy_max)
    assert evidence == sorted(evidence)
    assert len(set(evidence)) == len(evidence)

    assumptions = report.assumptions
    for scale in scales:
        expected_policy_bytes = (
            (scale.logical_agents - 1) * assumptions.policy_document_bytes
        )
        assert scale.policy_distribution.bytes_transmitted_per_update == expected_policy_bytes
        assert scale.policy_distribution.bytes_transmitted_per_month == (
            expected_policy_bytes * assumptions.policy_updates_per_month
        )
        assert scale.evidence.evidence_bytes_per_model_horizon == (
            scale.queue.generated_events * assumptions.evidence_bytes_per_event
        )


def test_operator_span_and_incident_effort_are_reported_with_step_boundaries() -> None:
    report = run_m6_fleet_study()

    assert [item.operator_span.required_operators for item in report.scales] == [1, 1, 4, 40]
    assert [item.operator_span.modeled_logical_agents_per_operator for item in report.scales] == [
        Decimal("10.000000"),
        Decimal("100.000000"),
        Decimal("250.000000"),
        Decimal("250.000000"),
    ]
    assert [item.incident_response.modeled_incidents_per_month for item in report.scales] == [
        Decimal("0.020000"),
        Decimal("0.200000"),
        Decimal("2.000000"),
        Decimal("20.000000"),
    ]
    assert all(
        item.incident_response.modeled_total_effort_hours_per_month >= 0
        for item in report.scales
    )


def test_economic_cases_cover_rates_infrastructure_utilization_and_retention() -> None:
    report = run_m6_fleet_study()
    low, base, high = report.assumptions.economic_cases

    assert (low.name, base.name, high.name) == ("low", "base", "high")
    assert low.operator_labor_usd_per_hour < base.operator_labor_usd_per_hour < (
        high.operator_labor_usd_per_hour
    )
    assert (
        low.incident_responder_labor_usd_per_hour
        < base.incident_responder_labor_usd_per_hour
        < high.incident_responder_labor_usd_per_hour
    )
    assert low.governance_labor_usd_per_hour < base.governance_labor_usd_per_hour < (
        high.governance_labor_usd_per_hour
    )
    assert (
        low.infrastructure_usd_per_logical_agent_month_at_full_utilization
        < base.infrastructure_usd_per_logical_agent_month_at_full_utilization
        < high.infrastructure_usd_per_logical_agent_month_at_full_utilization
    )
    assert low.evidence_storage_usd_per_gib_month < base.evidence_storage_usd_per_gib_month < (
        high.evidence_storage_usd_per_gib_month
    )
    assert low.utilization_basis_points > base.utilization_basis_points > (
        high.utilization_basis_points
    )
    assert low.retention_days < base.retention_days < high.retention_days


def test_cost_sensitivity_and_marginal_cost_calculations_are_consistent() -> None:
    report = run_m6_fleet_study()
    previous_agents = 0
    previous_totals = {name: Decimal("0") for name in ("low", "base", "high")}

    for scale in report.scales:
        totals = [item.modeled_total_governance_cost_usd_per_month for item in scale.economics]
        assert totals == sorted(totals)
        assert len(set(totals)) == len(totals)
        for result in scale.economics:
            assert result.modeled_total_governance_cost_usd_per_month == sum(
                (
                    result.modeled_operator_labor_usd_per_month,
                    result.modeled_incident_response_labor_usd_per_month,
                    result.modeled_governance_labor_usd_per_month,
                    result.modeled_infrastructure_usd_per_month,
                    result.modeled_evidence_storage_usd_per_month,
                ),
                Decimal("0"),
            )
            expected_marginal = (
                result.modeled_total_governance_cost_usd_per_month
                - previous_totals[result.sensitivity_case]
            ) / Decimal(scale.logical_agents - previous_agents)
            assert (
                result.modeled_marginal_governance_cost_usd_per_added_logical_agent_month
                == expected_marginal.quantize(Decimal("0.000001"))
            )
            previous_totals[result.sensitivity_case] = (
                result.modeled_total_governance_cost_usd_per_month
            )
        previous_agents = scale.logical_agents

    for sensitivity in ("low", "base", "high"):
        total_by_scale = [
            _case(scale, sensitivity).modeled_total_governance_cost_usd_per_month
            for scale in report.scales
        ]
        assert total_by_scale == sorted(total_by_scale)
        marginal_by_scale = [
            _case(
                scale,
                sensitivity,
            ).modeled_marginal_governance_cost_usd_per_added_logical_agent_month
            for scale in report.scales
        ]
        assert marginal_by_scale != sorted(marginal_by_scale)
    assert any("non-monotonic" in note for note in report.relationship_notes)
    assert any("zero-cost, zero-agent" in note for note in report.relationship_notes)


def test_retention_cost_uses_binary_gib_and_each_case_retention_period() -> None:
    report = run_m6_fleet_study()
    scale = report.scales[-1]

    for assumption, result in zip(
        report.assumptions.economic_cases,
        scale.economics,
        strict=True,
    ):
        expected = (
            Decimal(scale.evidence.modeled_evidence_bytes_per_day * assumption.retention_days)
            / Decimal(BYTES_PER_GIB)
        ).quantize(Decimal("0.000001"))
        assert result.modeled_retained_evidence_gib == expected


def test_report_preserves_the_non_empirical_claim_boundary() -> None:
    report = run_m6_fleet_study()
    rendered = report.canonical_json().lower()

    assert report.evidence_classification == "synthetic_model_output_only"
    assert report.claim_scope.endswith("modeled, not measured.")
    assert "no empirical performance or capacity measurement" in rendered
    assert "no deployment" in rendered
    assert "no independent validation or replication claim" in rendered
    assert "not a vm" in rendered
    assert "modeled_throughput_events_per_second" in rendered
    assert "measured_throughput" not in rendered
    assert "benchmark_result" not in rendered


@pytest.mark.parametrize(
    ("changes", "error_type", "message"),
    [
        ({"seed": ""}, ValueError, "model seed"),
        ({"seed": " seed"}, ValueError, "model seed"),
        ({"horizon_seconds": True}, TypeError, "horizon seconds"),
        ({"service_worker_count": 0}, ValueError, "service worker count"),
        (
            {"service_time_min_microseconds": 6_000},
            ValueError,
            "minimum service time",
        ),
        (
            {"arrival_jitter_window_microseconds": 12_000_000},
            ValueError,
            "arrival jitter",
        ),
        ({"maximum_simulated_events": 49_999}, ValueError, "10000-agent scale"),
        (
            {"operator_oversight_hours_per_operator_month": Decimal("NaN")},
            ValueError,
            "must be finite",
        ),
        (
            {"governance_base_hours_per_month": 8.0},
            TypeError,
            "must be a Decimal",
        ),
        ({"economic_cases": list(DEFAULT_ECONOMIC_CASES)}, TypeError, "immutable tuple"),
    ],
)
def test_invalid_assumptions_fail_closed(
    changes: dict[str, Any],
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        replace(FleetModelAssumptions(), **changes)


def test_invalid_economic_ranges_and_types_fail_closed() -> None:
    low, base, high = DEFAULT_ECONOMIC_CASES
    with pytest.raises(TypeError, match="must be a Decimal"):
        replace(base, operator_labor_usd_per_hour=cast(Any, 105.0))
    with pytest.raises(ValueError, match="economic utilization"):
        replace(base, utilization_basis_points=0)
    with pytest.raises(ValueError, match="must be increasing"):
        FleetModelAssumptions(
            economic_cases=(
                replace(low, operator_labor_usd_per_hour=Decimal("200")),
                base,
                high,
            )
        )
    with pytest.raises(ValueError, match="must be increasing"):
        FleetModelAssumptions(economic_cases=(low, replace(base, retention_days=30), high))
    with pytest.raises(ValueError, match="low/base/high order"):
        FleetModelAssumptions(economic_cases=(base, low, high))
    with pytest.raises(ValueError, match="low, base, or high"):
        EconomicCase(
            name="optimistic",
            operator_labor_usd_per_hour=Decimal("1"),
            incident_responder_labor_usd_per_hour=Decimal("1"),
            governance_labor_usd_per_hour=Decimal("1"),
            infrastructure_usd_per_logical_agent_month_at_full_utilization=Decimal("1"),
            evidence_storage_usd_per_gib_month=Decimal("1"),
            utilization_basis_points=10_000,
            retention_days=1,
        )


def test_scale_and_assumption_api_inputs_fail_closed() -> None:
    with pytest.raises(TypeError, match="immutable tuple"):
        run_m6_fleet_study(scale_points=cast(Any, [10, 100, 1_000, 10_000]))
    with pytest.raises(ValueError, match="exactly"):
        run_m6_fleet_study(scale_points=(10, 100, 1_000))
    with pytest.raises(ValueError, match="exactly"):
        run_m6_fleet_study(scale_points=(10, 100, 1_000, 10_001))
    with pytest.raises(TypeError, match="FleetModelAssumptions"):
        run_m6_fleet_study(assumptions=cast(Any, object()))
