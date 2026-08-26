"""Deterministic synthetic logical-fleet scaling and economic model.

The outputs from this module are model results, not measurements.  A logical
agent is an identity-bearing workload actor in the model; it is not a virtual
machine, host, process, deployed endpoint, or claim of operational capacity.

The model intentionally uses a small, auditable discrete-event queue and a
closed balanced delegation tree.  Integer microseconds and bytes are retained
through the simulations.  Decimal arithmetic is used for rates and costs so a
host's floating-point behavior cannot change the canonical result hash.
"""

from __future__ import annotations

import hashlib
import heapq
import json
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from decimal import ROUND_HALF_UP, Decimal
from types import MappingProxyType
from typing import Final, cast

SCALE_POINTS: Final[tuple[int, ...]] = (10, 100, 1_000, 10_000)
SENSITIVITY_CASES: Final[tuple[str, ...]] = ("low", "base", "high")
MODEL_SCHEMA_VERSION: Final[str] = "aegis-ot-m6-fleet-study-v1"
MODEL_KIND: Final[str] = "deterministic_synthetic_discrete_event_model"

MICROSECONDS_PER_SECOND: Final[int] = 1_000_000
SECONDS_PER_DAY: Final[int] = 86_400
BYTES_PER_GIB: Final[int] = 1 << 30
MAX_LOGICAL_AGENTS: Final[int] = 10_000
MAX_EVENTS_PER_LOGICAL_AGENT: Final[int] = 25
MAX_SIMULATED_EVENTS_BOUND: Final[int] = 250_000

JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]


def _require_int(
    value: object,
    *,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    integer = value
    if not minimum <= integer <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return integer


def _require_decimal(
    value: object,
    *,
    label: str,
    minimum: Decimal,
    maximum: Decimal,
) -> Decimal:
    if not isinstance(value, Decimal):
        raise TypeError(f"{label} must be a Decimal")
    if not value.is_finite():
        raise ValueError(f"{label} must be finite")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _quantize(value: Decimal, quantum: str = "0.000001") -> Decimal:
    return value.quantize(Decimal(quantum), rounding=ROUND_HALF_UP)


def _ceil_div(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ValueError("division denominator must be positive")
    return -(-numerator // denominator)


def _deterministic_offset(
    seed: str,
    domain: str,
    *coordinates: int,
    modulus: int,
) -> int:
    """Return a stable pseudorandom offset without Python hash-state dependence."""

    if modulus <= 0:
        raise ValueError("deterministic offset modulus must be positive")
    material = "\x00".join((seed, domain, *(str(item) for item in coordinates))).encode()
    digest = hashlib.sha256(material).digest()
    return int.from_bytes(digest[:8], "big") % modulus


def _json_value(value: object) -> JsonValue:
    """Convert only the model's closed value set to canonical JSON values."""

    if value is None or type(value) in {bool, int, str}:
        return cast(None | bool | int | str, value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("canonical model output cannot contain a non-finite Decimal")
        return format(value, "f")
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _json_value(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        string_items: list[tuple[str, object]] = []
        for key, item_value in value.items():
            if type(key) is not str:
                raise TypeError("canonical model dictionaries require string keys")
            string_items.append((key, item_value))
        for key, item_value in sorted(string_items):
            result[key] = _json_value(item_value)
        return result
    raise TypeError(f"unsupported canonical model value: {type(value).__name__}")


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        _json_value(value),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class EconomicCase:
    """One closed monthly cost case.  Field names carry their exact units."""

    name: str
    operator_labor_usd_per_hour: Decimal
    incident_responder_labor_usd_per_hour: Decimal
    governance_labor_usd_per_hour: Decimal
    infrastructure_usd_per_logical_agent_month_at_full_utilization: Decimal
    evidence_storage_usd_per_gib_month: Decimal
    utilization_basis_points: int
    retention_days: int

    def __post_init__(self) -> None:
        if type(self.name) is not str or self.name not in SENSITIVITY_CASES:
            raise ValueError("economic case name must be low, base, or high")
        for label, value in (
            ("operator labor rate", self.operator_labor_usd_per_hour),
            ("incident responder labor rate", self.incident_responder_labor_usd_per_hour),
            ("governance labor rate", self.governance_labor_usd_per_hour),
            (
                "infrastructure rate",
                self.infrastructure_usd_per_logical_agent_month_at_full_utilization,
            ),
            ("evidence storage rate", self.evidence_storage_usd_per_gib_month),
        ):
            _require_decimal(
                value,
                label=label,
                minimum=Decimal("0"),
                maximum=Decimal("10000"),
            )
        _require_int(
            self.utilization_basis_points,
            label="economic utilization",
            minimum=1,
            maximum=10_000,
        )
        _require_int(
            self.retention_days,
            label="economic evidence retention",
            minimum=1,
            maximum=3_650,
        )


DEFAULT_ECONOMIC_CASES: Final[tuple[EconomicCase, ...]] = (
    EconomicCase(
        name="low",
        operator_labor_usd_per_hour=Decimal("70"),
        incident_responder_labor_usd_per_hour=Decimal("95"),
        governance_labor_usd_per_hour=Decimal("110"),
        infrastructure_usd_per_logical_agent_month_at_full_utilization=Decimal("0.90"),
        evidence_storage_usd_per_gib_month=Decimal("0.012"),
        utilization_basis_points=8_500,
        retention_days=30,
    ),
    EconomicCase(
        name="base",
        operator_labor_usd_per_hour=Decimal("105"),
        incident_responder_labor_usd_per_hour=Decimal("145"),
        governance_labor_usd_per_hour=Decimal("165"),
        infrastructure_usd_per_logical_agent_month_at_full_utilization=Decimal("1.40"),
        evidence_storage_usd_per_gib_month=Decimal("0.023"),
        utilization_basis_points=7_000,
        retention_days=90,
    ),
    EconomicCase(
        name="high",
        operator_labor_usd_per_hour=Decimal("160"),
        incident_responder_labor_usd_per_hour=Decimal("225"),
        governance_labor_usd_per_hour=Decimal("250"),
        infrastructure_usd_per_logical_agent_month_at_full_utilization=Decimal("2.20"),
        evidence_storage_usd_per_gib_month=Decimal("0.045"),
        utilization_basis_points=5_500,
        retention_days=365,
    ),
)


@dataclass(frozen=True, slots=True)
class FleetModelAssumptions:
    """Bounded inputs for the queue, graph, evidence, staffing, and cost models."""

    seed: str = "aegis-ot-m6-reference-seed-v1"
    horizon_seconds: int = 60
    events_per_logical_agent_per_horizon: int = 5
    arrival_jitter_window_microseconds: int = 200_000
    service_worker_count: int = 4
    service_time_min_microseconds: int = 3_000
    service_time_max_microseconds: int = 5_000
    maximum_simulated_events: int = 100_000
    delegation_branching_factor: int = 10
    revocation_edge_delay_microseconds: int = 2_000
    revocation_edge_jitter_microseconds: int = 1_000
    policy_document_bytes: int = 8_192
    policy_distribution_bandwidth_bytes_per_second: int = 5_000_000
    policy_edge_delay_microseconds: int = 5_000
    policy_edge_jitter_microseconds: int = 2_000
    policy_updates_per_month: int = 4
    evidence_bytes_per_event: int = 1_536
    target_logical_agents_per_operator: int = 250
    operator_oversight_hours_per_operator_month: Decimal = Decimal("12")
    modeled_incidents_per_10000_logical_agent_months: int = 20
    incident_base_effort_minutes: int = 180
    incident_effort_minutes_per_delegation_depth: int = 15
    incident_handoff_minutes_per_operator: int = 2
    governance_base_hours_per_month: Decimal = Decimal("8")
    governance_review_minutes_per_policy_update: Decimal = Decimal("45")
    governance_review_minutes_per_depth_update: Decimal = Decimal("5")
    governance_review_minutes_per_1000_agents_update: Decimal = Decimal("2")
    evidence_review_minutes_per_retained_gib: Decimal = Decimal("0.25")
    economic_cases: tuple[EconomicCase, ...] = DEFAULT_ECONOMIC_CASES

    def __post_init__(self) -> None:
        if type(self.seed) is not str:
            raise TypeError("model seed must be a string")
        seed_bytes = self.seed.encode("utf-8")
        if (
            not self.seed
            or self.seed != self.seed.strip()
            or not self.seed.isprintable()
            or len(seed_bytes) > 256
        ):
            raise ValueError("model seed must be 1-256 printable UTF-8 bytes without edge space")

        integer_bounds = (
            ("horizon seconds", self.horizon_seconds, 1, 86_400),
            (
                "events per logical agent per horizon",
                self.events_per_logical_agent_per_horizon,
                1,
                MAX_EVENTS_PER_LOGICAL_AGENT,
            ),
            (
                "arrival jitter window",
                self.arrival_jitter_window_microseconds,
                1,
                10_000_000,
            ),
            ("service worker count", self.service_worker_count, 1, 128),
            ("minimum service time", self.service_time_min_microseconds, 1, 10_000_000),
            ("maximum service time", self.service_time_max_microseconds, 1, 10_000_000),
            (
                "maximum simulated events",
                self.maximum_simulated_events,
                1,
                MAX_SIMULATED_EVENTS_BOUND,
            ),
            ("delegation branching factor", self.delegation_branching_factor, 2, 64),
            ("revocation edge delay", self.revocation_edge_delay_microseconds, 1, 60_000_000),
            (
                "revocation edge jitter",
                self.revocation_edge_jitter_microseconds,
                1,
                60_000_000,
            ),
            ("policy document bytes", self.policy_document_bytes, 1, 100_000_000),
            (
                "policy distribution bandwidth",
                self.policy_distribution_bandwidth_bytes_per_second,
                1,
                10_000_000_000,
            ),
            ("policy edge delay", self.policy_edge_delay_microseconds, 1, 60_000_000),
            ("policy edge jitter", self.policy_edge_jitter_microseconds, 1, 60_000_000),
            ("policy updates per month", self.policy_updates_per_month, 1, 10_000),
            ("evidence bytes per event", self.evidence_bytes_per_event, 1, 100_000_000),
            (
                "target logical agents per operator",
                self.target_logical_agents_per_operator,
                1,
                MAX_LOGICAL_AGENTS,
            ),
            (
                "modeled incidents per 10000 logical agent months",
                self.modeled_incidents_per_10000_logical_agent_months,
                0,
                10_000,
            ),
            ("incident base effort", self.incident_base_effort_minutes, 0, 100_000),
            (
                "incident effort per delegation depth",
                self.incident_effort_minutes_per_delegation_depth,
                0,
                100_000,
            ),
            (
                "incident handoff effort per operator",
                self.incident_handoff_minutes_per_operator,
                0,
                100_000,
            ),
        )
        for label, integer_value, minimum, maximum in integer_bounds:
            _require_int(integer_value, label=label, minimum=minimum, maximum=maximum)

        if self.service_time_min_microseconds > self.service_time_max_microseconds:
            raise ValueError("minimum service time must not exceed maximum service time")
        horizon_microseconds = self.horizon_seconds * MICROSECONDS_PER_SECOND
        arrival_interval = horizon_microseconds // self.events_per_logical_agent_per_horizon
        if self.arrival_jitter_window_microseconds >= arrival_interval:
            raise ValueError("arrival jitter must be smaller than each event arrival interval")
        largest_event_count = MAX_LOGICAL_AGENTS * self.events_per_logical_agent_per_horizon
        if largest_event_count > self.maximum_simulated_events:
            raise ValueError("maximum simulated events cannot contain the 10000-agent scale")

        decimal_bounds = (
            ("operator oversight hours", self.operator_oversight_hours_per_operator_month),
            ("governance base hours", self.governance_base_hours_per_month),
            (
                "governance review minutes per policy update",
                self.governance_review_minutes_per_policy_update,
            ),
            (
                "governance review minutes per depth update",
                self.governance_review_minutes_per_depth_update,
            ),
            (
                "governance review minutes per 1000 agents update",
                self.governance_review_minutes_per_1000_agents_update,
            ),
            (
                "evidence review minutes per retained GiB",
                self.evidence_review_minutes_per_retained_gib,
            ),
        )
        for label, decimal_value in decimal_bounds:
            _require_decimal(
                decimal_value,
                label=label,
                minimum=Decimal("0"),
                maximum=Decimal("100000"),
            )

        if type(self.economic_cases) is not tuple:
            raise TypeError("economic cases must be an immutable tuple")
        if tuple(item.name for item in self.economic_cases) != SENSITIVITY_CASES:
            raise ValueError("economic cases must appear exactly once in low/base/high order")
        self._validate_economic_sensitivity_order()

    def _validate_economic_sensitivity_order(self) -> None:
        low, base, high = self.economic_cases
        ascending = (
            (
                low.operator_labor_usd_per_hour,
                base.operator_labor_usd_per_hour,
                high.operator_labor_usd_per_hour,
            ),
            (
                low.incident_responder_labor_usd_per_hour,
                base.incident_responder_labor_usd_per_hour,
                high.incident_responder_labor_usd_per_hour,
            ),
            (
                low.governance_labor_usd_per_hour,
                base.governance_labor_usd_per_hour,
                high.governance_labor_usd_per_hour,
            ),
            (
                low.infrastructure_usd_per_logical_agent_month_at_full_utilization,
                base.infrastructure_usd_per_logical_agent_month_at_full_utilization,
                high.infrastructure_usd_per_logical_agent_month_at_full_utilization,
            ),
            (
                low.evidence_storage_usd_per_gib_month,
                base.evidence_storage_usd_per_gib_month,
                high.evidence_storage_usd_per_gib_month,
            ),
            (
                Decimal(low.retention_days),
                Decimal(base.retention_days),
                Decimal(high.retention_days),
            ),
        )
        if any(not first < second < third for first, second, third in ascending):
            raise ValueError("low/base/high cost and retention assumptions must be increasing")
        if not (
            low.utilization_basis_points
            > base.utilization_basis_points
            > high.utilization_basis_points
        ):
            raise ValueError("low/base/high utilization assumptions must be decreasing")


@dataclass(frozen=True, slots=True)
class QueueModelResult:
    generated_events: int
    completed_events: int
    modeled_throughput_events_per_second: Decimal
    modeled_mean_queue_delay_microseconds: Decimal
    modeled_p95_queue_delay_microseconds: int
    modeled_maximum_queue_delay_microseconds: int
    modeled_maximum_queue_depth_events: int
    modeled_service_utilization_percent: Decimal
    completion_window_microseconds: int
    event_trace_sha256: str


@dataclass(frozen=True, slots=True)
class DelegationGraphResult:
    nodes: int
    edges: int
    maximum_depth_hops: int
    branching_factor: int
    topology_sha256: str


@dataclass(frozen=True, slots=True)
class RevocationPropagationResult:
    root_issuer_count: int
    recipient_count: int
    propagation_messages: int
    modeled_p95_propagation_microseconds: int
    modeled_maximum_propagation_microseconds: int
    propagation_trace_sha256: str


@dataclass(frozen=True, slots=True)
class PolicyDistributionResult:
    recipient_count: int
    policy_document_bytes: int
    bytes_transmitted_per_update: int
    bytes_transmitted_per_month: int
    updates_per_month: int
    modeled_p95_distribution_microseconds: int
    modeled_maximum_distribution_microseconds: int
    distribution_trace_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceRetentionResult:
    evidence_bytes_per_event: int
    evidence_bytes_per_model_horizon: int
    modeled_evidence_bytes_per_day: int
    base_retention_days: int
    modeled_base_retained_bytes: int
    modeled_base_retained_gib: Decimal


@dataclass(frozen=True, slots=True)
class OperatorSpanResult:
    target_logical_agents_per_operator: int
    required_operators: int
    modeled_logical_agents_per_operator: Decimal
    modeled_oversight_labor_hours_per_month: Decimal


@dataclass(frozen=True, slots=True)
class IncidentResponseResult:
    modeled_incidents_per_month: Decimal
    modeled_effort_hours_per_incident: Decimal
    modeled_total_effort_hours_per_month: Decimal
    basis_incidents_per_10000_logical_agent_months: int


@dataclass(frozen=True, slots=True)
class EconomicResult:
    sensitivity_case: str
    modeled_operator_labor_usd_per_month: Decimal
    modeled_incident_response_labor_usd_per_month: Decimal
    modeled_governance_labor_usd_per_month: Decimal
    modeled_infrastructure_usd_per_month: Decimal
    modeled_evidence_storage_usd_per_month: Decimal
    modeled_total_governance_cost_usd_per_month: Decimal
    modeled_marginal_governance_cost_usd_per_added_logical_agent_month: Decimal
    modeled_governance_labor_hours_per_month: Decimal
    modeled_retained_evidence_gib: Decimal


@dataclass(frozen=True, slots=True)
class FleetScaleResult:
    logical_agents: int
    queue: QueueModelResult
    delegation_graph: DelegationGraphResult
    revocation: RevocationPropagationResult
    policy_distribution: PolicyDistributionResult
    evidence: EvidenceRetentionResult
    operator_span: OperatorSpanResult
    incident_response: IncidentResponseResult
    economics: tuple[EconomicResult, ...]


@dataclass(frozen=True, slots=True)
class FleetStudyReport:
    schema_version: str
    model_kind: str
    evidence_classification: str
    claim_scope: str
    logical_agent_definition: str
    excluded_claims: tuple[str, ...]
    scale_points: tuple[int, ...]
    units: Mapping[str, str]
    assumptions: FleetModelAssumptions
    scales: tuple[FleetScaleResult, ...]
    relationship_notes: tuple[str, ...]

    def result_payload(self) -> dict[str, JsonValue]:
        payload = _json_value(self)
        if not isinstance(payload, dict):
            raise TypeError("fleet report must serialize as an object")
        return payload

    @property
    def result_sha256(self) -> str:
        return hashlib.sha256(_canonical_json_bytes(self.result_payload())).hexdigest()

    def to_dict(self) -> dict[str, JsonValue]:
        payload = self.result_payload()
        payload["result_sha256"] = self.result_sha256
        return payload

    def canonical_json(self) -> str:
        return _canonical_json_bytes(self.to_dict()).decode("utf-8")


UNIT_REGISTRY: Final[Mapping[str, str]] = MappingProxyType({
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
    "infrastructure_rate": "USD/logical-agent-month at 100 percent utilization",
    "storage_rate": "USD/GiB-month",
    "monthly_cost": "USD/month",
    "marginal_governance_cost": "USD/added-logical-agent-month",
    "retention": "day",
    "utilization_input": "basis-point (1 basis-point = 0.01 percent)",
})


def _nearest_rank_percentile(sorted_values: list[int], percentile: int) -> int:
    if not sorted_values:
        raise ValueError("percentile requires at least one value")
    if not 1 <= percentile <= 100:
        raise ValueError("percentile must be between 1 and 100")
    rank = _ceil_div(percentile * len(sorted_values), 100)
    return sorted_values[rank - 1]


def _simulate_queue(
    logical_agents: int,
    assumptions: FleetModelAssumptions,
) -> QueueModelResult:
    event_count = logical_agents * assumptions.events_per_logical_agent_per_horizon
    if event_count > assumptions.maximum_simulated_events:
        raise ValueError("requested fleet exceeds the configured simulated-event bound")
    horizon_microseconds = assumptions.horizon_seconds * MICROSECONDS_PER_SECOND
    interval = horizon_microseconds // assumptions.events_per_logical_agent_per_horizon
    arrivals: list[tuple[int, int, int]] = []
    for event_ordinal in range(assumptions.events_per_logical_agent_per_horizon):
        interval_start = event_ordinal * interval
        for agent_index in range(logical_agents):
            jitter = _deterministic_offset(
                assumptions.seed,
                "queue-arrival-v1",
                agent_index,
                event_ordinal,
                modulus=assumptions.arrival_jitter_window_microseconds,
            )
            arrivals.append((interval_start + jitter, agent_index, event_ordinal))
    arrivals.sort()

    workers = [0] * assumptions.service_worker_count
    heapq.heapify(workers)
    service_span = (
        assumptions.service_time_max_microseconds
        - assumptions.service_time_min_microseconds
        + 1
    )
    delays: list[int] = []
    starts: list[int] = []
    total_service_microseconds = 0
    trace = hashlib.sha256()
    for arrival, agent_index, event_ordinal in arrivals:
        available = heapq.heappop(workers)
        start = max(arrival, available)
        delay = start - arrival
        service = assumptions.service_time_min_microseconds + _deterministic_offset(
            assumptions.seed,
            "queue-service-v1",
            agent_index,
            event_ordinal,
            modulus=service_span,
        )
        completion = start + service
        heapq.heappush(workers, completion)
        delays.append(delay)
        starts.append(start)
        total_service_microseconds += service
        trace.update(f"{arrival},{agent_index},{event_ordinal},{start},{completion}\n".encode())

    maximum_queue_depth = 0
    arrival_cursor = 0
    start_cursor = 0
    while arrival_cursor < len(arrivals):
        timestamp = arrivals[arrival_cursor][0]
        while arrival_cursor < len(arrivals) and arrivals[arrival_cursor][0] == timestamp:
            arrival_cursor += 1
        while start_cursor < len(starts) and starts[start_cursor] <= timestamp:
            start_cursor += 1
        maximum_queue_depth = max(maximum_queue_depth, arrival_cursor - start_cursor)

    completion_window = max(horizon_microseconds, max(workers))
    sorted_delays = sorted(delays)
    throughput = _quantize(
        Decimal(event_count * MICROSECONDS_PER_SECOND) / Decimal(completion_window)
    )
    mean_delay = _quantize(Decimal(sum(delays)) / Decimal(event_count))
    utilization = _quantize(
        Decimal(total_service_microseconds * 100)
        / Decimal(assumptions.service_worker_count * completion_window)
    )
    return QueueModelResult(
        generated_events=event_count,
        completed_events=event_count,
        modeled_throughput_events_per_second=throughput,
        modeled_mean_queue_delay_microseconds=mean_delay,
        modeled_p95_queue_delay_microseconds=_nearest_rank_percentile(sorted_delays, 95),
        modeled_maximum_queue_delay_microseconds=sorted_delays[-1],
        modeled_maximum_queue_depth_events=maximum_queue_depth,
        modeled_service_utilization_percent=utilization,
        completion_window_microseconds=completion_window,
        event_trace_sha256=trace.hexdigest(),
    )


def _build_delegation_graph(
    logical_agents: int,
    assumptions: FleetModelAssumptions,
) -> tuple[list[int], list[int], DelegationGraphResult]:
    parents = [-1]
    depths = [0]
    trace = hashlib.sha256(b"root:0\n")
    for node in range(1, logical_agents):
        parent = (node - 1) // assumptions.delegation_branching_factor
        depth = depths[parent] + 1
        parents.append(parent)
        depths.append(depth)
        trace.update(f"{node}:{parent}:{depth}\n".encode())
    result = DelegationGraphResult(
        nodes=logical_agents,
        edges=logical_agents - 1,
        maximum_depth_hops=max(depths),
        branching_factor=assumptions.delegation_branching_factor,
        topology_sha256=trace.hexdigest(),
    )
    return parents, depths, result


def _simulate_revocation(
    parents: list[int],
    assumptions: FleetModelAssumptions,
) -> RevocationPropagationResult:
    arrival_times = [0]
    trace = hashlib.sha256(b"issuer:0:0\n")
    for node in range(1, len(parents)):
        edge_delay = assumptions.revocation_edge_delay_microseconds + _deterministic_offset(
            assumptions.seed,
            "revocation-edge-v1",
            parents[node],
            node,
            modulus=assumptions.revocation_edge_jitter_microseconds,
        )
        arrival = arrival_times[parents[node]] + edge_delay
        arrival_times.append(arrival)
        trace.update(f"{node}:{parents[node]}:{arrival}\n".encode())
    recipient_times = sorted(arrival_times[1:])
    return RevocationPropagationResult(
        root_issuer_count=1,
        recipient_count=len(parents) - 1,
        propagation_messages=len(parents) - 1,
        modeled_p95_propagation_microseconds=_nearest_rank_percentile(recipient_times, 95),
        modeled_maximum_propagation_microseconds=recipient_times[-1],
        propagation_trace_sha256=trace.hexdigest(),
    )


def _simulate_policy_distribution(
    parents: list[int],
    assumptions: FleetModelAssumptions,
) -> PolicyDistributionResult:
    serialization_microseconds = _ceil_div(
        assumptions.policy_document_bytes * MICROSECONDS_PER_SECOND,
        assumptions.policy_distribution_bandwidth_bytes_per_second,
    )
    arrival_times = [0]
    trace = hashlib.sha256(b"publisher:0:0\n")
    for node in range(1, len(parents)):
        edge_delay = (
            assumptions.policy_edge_delay_microseconds
            + serialization_microseconds
            + _deterministic_offset(
                assumptions.seed,
                "policy-edge-v1",
                parents[node],
                node,
                modulus=assumptions.policy_edge_jitter_microseconds,
            )
        )
        arrival = arrival_times[parents[node]] + edge_delay
        arrival_times.append(arrival)
        trace.update(f"{node}:{parents[node]}:{arrival}\n".encode())
    recipient_times = sorted(arrival_times[1:])
    bytes_per_update = assumptions.policy_document_bytes * (len(parents) - 1)
    return PolicyDistributionResult(
        recipient_count=len(parents) - 1,
        policy_document_bytes=assumptions.policy_document_bytes,
        bytes_transmitted_per_update=bytes_per_update,
        bytes_transmitted_per_month=bytes_per_update * assumptions.policy_updates_per_month,
        updates_per_month=assumptions.policy_updates_per_month,
        modeled_p95_distribution_microseconds=_nearest_rank_percentile(recipient_times, 95),
        modeled_maximum_distribution_microseconds=recipient_times[-1],
        distribution_trace_sha256=trace.hexdigest(),
    )


def _model_evidence(
    generated_events: int,
    assumptions: FleetModelAssumptions,
) -> EvidenceRetentionResult:
    horizon_bytes = generated_events * assumptions.evidence_bytes_per_event
    daily_bytes = _ceil_div(
        horizon_bytes * SECONDS_PER_DAY,
        assumptions.horizon_seconds,
    )
    base_case = assumptions.economic_cases[1]
    retained_bytes = daily_bytes * base_case.retention_days
    return EvidenceRetentionResult(
        evidence_bytes_per_event=assumptions.evidence_bytes_per_event,
        evidence_bytes_per_model_horizon=horizon_bytes,
        modeled_evidence_bytes_per_day=daily_bytes,
        base_retention_days=base_case.retention_days,
        modeled_base_retained_bytes=retained_bytes,
        modeled_base_retained_gib=_quantize(Decimal(retained_bytes) / Decimal(BYTES_PER_GIB)),
    )


def _model_operator_span(
    logical_agents: int,
    assumptions: FleetModelAssumptions,
) -> OperatorSpanResult:
    operators = _ceil_div(logical_agents, assumptions.target_logical_agents_per_operator)
    return OperatorSpanResult(
        target_logical_agents_per_operator=assumptions.target_logical_agents_per_operator,
        required_operators=operators,
        modeled_logical_agents_per_operator=_quantize(
            Decimal(logical_agents) / Decimal(operators)
        ),
        modeled_oversight_labor_hours_per_month=_quantize(
            Decimal(operators) * assumptions.operator_oversight_hours_per_operator_month
        ),
    )


def _model_incident_response(
    logical_agents: int,
    graph: DelegationGraphResult,
    operator_span: OperatorSpanResult,
    assumptions: FleetModelAssumptions,
) -> IncidentResponseResult:
    incidents = _quantize(
        Decimal(logical_agents * assumptions.modeled_incidents_per_10000_logical_agent_months)
        / Decimal(10_000)
    )
    effort_minutes = Decimal(
        assumptions.incident_base_effort_minutes
        + graph.maximum_depth_hops * assumptions.incident_effort_minutes_per_delegation_depth
        + operator_span.required_operators * assumptions.incident_handoff_minutes_per_operator
    )
    effort_per_incident = _quantize(effort_minutes / Decimal(60))
    return IncidentResponseResult(
        modeled_incidents_per_month=incidents,
        modeled_effort_hours_per_incident=effort_per_incident,
        modeled_total_effort_hours_per_month=_quantize(incidents * effort_per_incident),
        basis_incidents_per_10000_logical_agent_months=(
            assumptions.modeled_incidents_per_10000_logical_agent_months
        ),
    )


def _model_economics(
    logical_agents: int,
    graph: DelegationGraphResult,
    evidence: EvidenceRetentionResult,
    operator_span: OperatorSpanResult,
    incident_response: IncidentResponseResult,
    assumptions: FleetModelAssumptions,
) -> tuple[EconomicResult, ...]:
    scale_blocks = _ceil_div(logical_agents, 1_000)
    results: list[EconomicResult] = []
    for case in assumptions.economic_cases:
        retained_bytes = evidence.modeled_evidence_bytes_per_day * case.retention_days
        retained_gib = _quantize(Decimal(retained_bytes) / Decimal(BYTES_PER_GIB))
        policy_review_minutes = Decimal(assumptions.policy_updates_per_month) * (
            assumptions.governance_review_minutes_per_policy_update
            + Decimal(graph.maximum_depth_hops)
            * assumptions.governance_review_minutes_per_depth_update
            + Decimal(scale_blocks)
            * assumptions.governance_review_minutes_per_1000_agents_update
        )
        evidence_review_minutes = (
            retained_gib * assumptions.evidence_review_minutes_per_retained_gib
        )
        governance_hours = _quantize(
            assumptions.governance_base_hours_per_month
            + (policy_review_minutes + evidence_review_minutes) / Decimal(60)
        )
        operator_cost = _quantize(
            operator_span.modeled_oversight_labor_hours_per_month
            * case.operator_labor_usd_per_hour
        )
        incident_cost = _quantize(
            incident_response.modeled_total_effort_hours_per_month
            * case.incident_responder_labor_usd_per_hour
        )
        governance_cost = _quantize(governance_hours * case.governance_labor_usd_per_hour)
        infrastructure_cost = _quantize(
            Decimal(logical_agents)
            * case.infrastructure_usd_per_logical_agent_month_at_full_utilization
            * Decimal(10_000)
            / Decimal(case.utilization_basis_points)
        )
        storage_cost = _quantize(retained_gib * case.evidence_storage_usd_per_gib_month)
        total = _quantize(
            operator_cost
            + incident_cost
            + governance_cost
            + infrastructure_cost
            + storage_cost
        )
        results.append(
            EconomicResult(
                sensitivity_case=case.name,
                modeled_operator_labor_usd_per_month=operator_cost,
                modeled_incident_response_labor_usd_per_month=incident_cost,
                modeled_governance_labor_usd_per_month=governance_cost,
                modeled_infrastructure_usd_per_month=infrastructure_cost,
                modeled_evidence_storage_usd_per_month=storage_cost,
                modeled_total_governance_cost_usd_per_month=total,
                modeled_marginal_governance_cost_usd_per_added_logical_agent_month=Decimal(
                    "0"
                ),
                modeled_governance_labor_hours_per_month=governance_hours,
                modeled_retained_evidence_gib=retained_gib,
            )
        )
    return tuple(results)


def _simulate_scale(
    logical_agents: int,
    assumptions: FleetModelAssumptions,
) -> FleetScaleResult:
    if logical_agents not in SCALE_POINTS:
        raise ValueError("logical-agent scale must be one of 10, 100, 1000, or 10000")
    queue = _simulate_queue(logical_agents, assumptions)
    parents, _depths, graph = _build_delegation_graph(logical_agents, assumptions)
    revocation = _simulate_revocation(parents, assumptions)
    policy_distribution = _simulate_policy_distribution(parents, assumptions)
    evidence = _model_evidence(queue.generated_events, assumptions)
    operator_span = _model_operator_span(logical_agents, assumptions)
    incident_response = _model_incident_response(
        logical_agents,
        graph,
        operator_span,
        assumptions,
    )
    economics = _model_economics(
        logical_agents,
        graph,
        evidence,
        operator_span,
        incident_response,
        assumptions,
    )
    return FleetScaleResult(
        logical_agents=logical_agents,
        queue=queue,
        delegation_graph=graph,
        revocation=revocation,
        policy_distribution=policy_distribution,
        evidence=evidence,
        operator_span=operator_span,
        incident_response=incident_response,
        economics=economics,
    )


def _attach_marginal_costs(
    results: tuple[FleetScaleResult, ...],
) -> tuple[FleetScaleResult, ...]:
    output: list[FleetScaleResult] = []
    previous_agents = 0
    previous_totals = {case: Decimal("0") for case in SENSITIVITY_CASES}
    for scale in results:
        added_agents = scale.logical_agents - previous_agents
        if added_agents <= 0:
            raise ValueError("fleet scales must be strictly increasing")
        economics: list[EconomicResult] = []
        for result in scale.economics:
            marginal = _quantize(
                (
                    result.modeled_total_governance_cost_usd_per_month
                    - previous_totals[result.sensitivity_case]
                )
                / Decimal(added_agents)
            )
            if marginal < 0:
                raise ValueError("modeled marginal governance cost must not be negative")
            economics.append(
                replace(
                    result,
                    modeled_marginal_governance_cost_usd_per_added_logical_agent_month=(
                        marginal
                    ),
                )
            )
            previous_totals[result.sensitivity_case] = (
                result.modeled_total_governance_cost_usd_per_month
            )
        output.append(replace(scale, economics=tuple(economics)))
        previous_agents = scale.logical_agents
    return tuple(output)


def run_m6_fleet_study(
    *,
    assumptions: FleetModelAssumptions | None = None,
    scale_points: tuple[int, ...] = SCALE_POINTS,
) -> FleetStudyReport:
    """Compute the four required logical scales under one closed assumption set."""

    if type(scale_points) is not tuple:
        raise TypeError("scale points must be an immutable tuple")
    if scale_points != SCALE_POINTS:
        raise ValueError("M6 requires exactly the 10, 100, 1000, and 10000 scale points")
    if assumptions is None:
        assumptions = FleetModelAssumptions()
    elif not isinstance(assumptions, FleetModelAssumptions):
        raise TypeError("assumptions must be FleetModelAssumptions")

    raw_results = tuple(_simulate_scale(point, assumptions) for point in scale_points)
    results = _attach_marginal_costs(raw_results)
    return FleetStudyReport(
        schema_version=MODEL_SCHEMA_VERSION,
        model_kind=MODEL_KIND,
        evidence_classification="synthetic_model_output_only",
        claim_scope=(
            "All throughput, queue-delay, propagation, effort, and cost values are "
            "modeled, not measured."
        ),
        logical_agent_definition=(
            "An identity-bearing logical workload actor in this model; not a VM, host, "
            "process, physical endpoint, or deployed system."
        ),
        excluded_claims=(
            "No empirical performance or capacity measurement.",
            "No deployment, production-readiness, operational-effectiveness, or cost "
            "forecast claim.",
            "No independent validation or replication claim.",
        ),
        scale_points=scale_points,
        units=UNIT_REGISTRY,
        assumptions=assumptions,
        scales=results,
        relationship_notes=(
            "Workload and evidence counts grow with the exact logical-agent scale by "
            "construction.",
            "Queue delay and throughput are outputs of a seeded FCFS synthetic queue; "
            "they are not host benchmarks.",
            "Delegation depth, operator headcount, and review blocks are integer steps, "
            "so modeled marginal cost can be non-monotonic even while total cost is "
            "nondecreasing.",
            "The first marginal-cost point uses a zero-cost, zero-agent reference and "
            "therefore includes fixed monthly governance labor.",
            "Daily evidence volume is the model-horizon volume scaled to one day and "
            "rounded upward to a whole byte.",
            "The policy and revocation fan-out assumes level-parallel delivery over the "
            "balanced delegation tree.",
        ),
    )
