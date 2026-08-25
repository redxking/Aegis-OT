"""Typed data contract for the packaged, read-only public demonstration."""

from __future__ import annotations

import math
from functools import lru_cache
from importlib.resources import files
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .physical_models import SHA256_PATTERN

M2BaselineId = Literal[
    "B0_DIRECT",
    "B1_IDENTITY",
    "B2_STATIC_POLICY",
    "B3_ASSURED",
    "B4_CONTEXTUAL_ABAC",
    "B5_RISK_AWARE",
    "B6_SAFETY_NO_DELEGATION",
    "B7_DELEGATION_NO_FRESHNESS",
]
REGISTERED_M2_BASELINES = (
    "B0_DIRECT",
    "B1_IDENTITY",
    "B2_STATIC_POLICY",
    "B3_ASSURED",
    "B4_CONTEXTUAL_ABAC",
    "B5_RISK_AWARE",
    "B6_SAFETY_NO_DELEGATION",
    "B7_DELEGATION_NO_FRESHNESS",
)
REGISTERED_M3_CONDITIONS = (
    "unknown_identity",
    "stale_state",
    "wrong_audience_permit",
    "nominal_permitted_execution",
    "permit_replay",
)
REGISTERED_M3_METRICS = (
    "non_nominal_effect",
    "nominal_completion",
    "replay_second_effect",
    "unknown_effect",
    "trace_complete",
)
REGISTERED_M3_INTERNAL_CHECKS = (
    "manifest",
    "artifact_hashes",
    "record_counts",
    "event_chains",
    "trial_semantics",
    "deterministic_outcome",
    "summary",
    "configuration_bindings",
)
REGISTERED_DEMO_SOURCE_PATHS = (
    "results/m2-independent-oracle/manifest.json",
    "results/m2-independent-oracle/trials.jsonl",
    "results/m3-physical-modbus/manifest.json",
    "results/m3-physical-modbus/summary.json",
    "results/m3-physical-modbus-reproduction/manifest.json",
)
REGISTERED_ARCHITECTURE_STAGES = (
    "identity",
    "delegation",
    "policy_state",
    "safety",
    "permit",
    "device",
    "plant",
)


class DemoModel(BaseModel):
    """Strict base model for public-demo data loaded at the API boundary."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        allow_inf_nan=False,
        strict=True,
    )


class DemoSourceArtifact(DemoModel):
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)


class DemoProjectState(DemoModel):
    name: Literal["Aegis-OT"] = "Aegis-OT"
    study_title: str = Field(min_length=1)
    mode: Literal["synthetic-local"] = "synthetic-local"
    milestone: str = Field(min_length=1)
    overall_status: str = Field(min_length=1)
    question: str = Field(min_length=1)
    claim_boundary: str = Field(min_length=1)


class DemoWilsonCI95(DemoModel):
    method: Literal["wilson-score"] = "wilson-score"
    confidence_level: float = Field(default=0.95, ge=0.95, le=0.95)
    lower: float = Field(ge=0, le=1)
    upper: float = Field(ge=0, le=1)


def _wilson(successes: int, denominator: int) -> tuple[float, float]:
    z = 1.959963984540054
    estimate = successes / denominator
    scale = 1 + z**2 / denominator
    center = (estimate + z**2 / (2 * denominator)) / scale
    margin = z * math.sqrt(
        estimate * (1 - estimate) / denominator + z**2 / (4 * denominator**2)
    )
    margin /= scale
    lower = 0.0 if successes == 0 else max(0.0, center - margin)
    upper = 1.0 if successes == denominator else min(1.0, center + margin)
    return lower, upper


class DemoBinomialMetric(DemoModel):
    numerator: int = Field(ge=0)
    denominator: int = Field(gt=0)
    estimate: float = Field(ge=0, le=1)
    wilson_ci95: DemoWilsonCI95

    @model_validator(mode="after")
    def validate_binomial_identity(self) -> Self:
        if self.numerator > self.denominator:
            raise ValueError("binomial numerator exceeds denominator")
        expected_estimate = self.numerator / self.denominator
        if not math.isclose(self.estimate, expected_estimate, rel_tol=0, abs_tol=1e-15):
            raise ValueError("binomial estimate differs from numerator and denominator")
        expected_lower, expected_upper = _wilson(self.numerator, self.denominator)
        if not (
            self.wilson_ci95.lower <= self.estimate <= self.wilson_ci95.upper
            and math.isclose(
                self.wilson_ci95.lower, expected_lower, rel_tol=0, abs_tol=1e-15
            )
            and math.isclose(
                self.wilson_ci95.upper, expected_upper, rel_tol=0, abs_tol=1e-15
            )
        ):
            raise ValueError("binomial Wilson interval is inconsistent")
        return self


class DemoM2Metrics(DemoModel):
    unsafe_action_escape: DemoBinomialMetric
    unauthorized_execution: DemoBinomialMetric
    false_block: DemoBinomialMetric
    mission_success: DemoBinomialMetric


class DemoBaseline(DemoModel):
    baseline_id: M2BaselineId
    display_id: str = Field(pattern=r"^B[0-7]$")
    label: str = Field(min_length=1)
    trials: int = Field(gt=0)
    metrics: DemoM2Metrics
    mean_decision_latency_ms: float = Field(ge=0)
    kernel_oracle_disagreements: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_baseline_identity(self) -> Self:
        if self.display_id != self.baseline_id.split("_", 1)[0]:
            raise ValueError("baseline display identifier differs from evidence identity")
        metrics = (
            self.metrics.unsafe_action_escape,
            self.metrics.unauthorized_execution,
            self.metrics.false_block,
            self.metrics.mission_success,
        )
        if any(metric.denominator > self.trials for metric in metrics):
            raise ValueError("baseline metric denominator exceeds baseline trials")
        if self.metrics.mission_success.denominator != self.trials:
            raise ValueError("mission-success denominator must equal baseline trials")
        if self.kernel_oracle_disagreements > self.trials:
            raise ValueError("kernel-oracle disagreement count exceeds baseline trials")
        return self


class DemoM2Evidence(DemoModel):
    experiment_id: str = Field(min_length=1)
    evidence_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    retention_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    recorded_commit_bound: Literal[True] = True
    trial_records: int = Field(gt=0)
    raw_trials_sha256: str = Field(pattern=SHA256_PATTERN)
    master_seed_count: int = Field(gt=0)
    deterministic_outcome_sha256: str = Field(pattern=SHA256_PATTERN)
    baselines: tuple[DemoBaseline, ...] = Field(min_length=8, max_length=8)
    finding: str = Field(min_length=1)
    limitation: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_m2_aggregates(self) -> Self:
        identities = tuple(item.baseline_id for item in self.baselines)
        if identities != REGISTERED_M2_BASELINES:
            raise ValueError("M2 baselines differ from the registered order")
        if sum(item.trials for item in self.baselines) != self.trial_records:
            raise ValueError("M2 baseline counts differ from total trial records")
        if len({item.trials for item in self.baselines}) != 1:
            raise ValueError("M2 registered design is not balanced across baselines")
        denominator_sets = (
            {item.metrics.unsafe_action_escape.denominator for item in self.baselines},
            {item.metrics.unauthorized_execution.denominator for item in self.baselines},
            {item.metrics.false_block.denominator for item in self.baselines},
            {item.metrics.mission_success.denominator for item in self.baselines},
        )
        if any(len(values) != 1 for values in denominator_sets):
            raise ValueError("M2 conditional denominators differ across baselines")
        return self


StageState = Literal[
    "pass",
    "deny",
    "effect",
    "no_effect",
    "not_reached",
    "reused",
    "tampered",
]


class DemoCondition(DemoModel):
    condition_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    trials: int = Field(gt=0)
    disposition: str = Field(min_length=1)
    modeled_effects: int = Field(ge=0)
    device_applied: int = Field(ge=0)
    unknown_effects: int = Field(ge=0)
    terminal_completions: int = Field(ge=0)
    trace_complete: int = Field(ge=0)
    path: tuple[StageState, ...] = Field(min_length=7, max_length=7)
    evidence_note: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_condition_counts(self) -> Self:
        if any(
            value > self.trials
            for value in (
                self.modeled_effects,
                self.device_applied,
                self.unknown_effects,
                self.terminal_completions,
                self.trace_complete,
            )
        ):
            raise ValueError("condition count exceeds condition trials")
        return self


class DemoNamedBinomialMetric(DemoBinomialMetric):
    metric_id: str = Field(pattern=r"^[a-z][a-z0-9_]+$")
    label: str = Field(min_length=1)
    interpretation: str = Field(min_length=1)


class DemoNominalState(DemoModel):
    minimum_voltage_pu: float = Field(gt=0)
    maximum_line_loading_pct: float = Field(ge=0)
    priority_load_served_pct: float = Field(ge=0, le=100)
    host_latency_mean_ms: float = Field(ge=0)
    host_latency_median_ms: float = Field(ge=0)


class DemoM3Verification(DemoModel):
    internal_checks: tuple[str, ...] = Field(min_length=8, max_length=8)
    primary_internal_checks_passed: Literal[True] = True
    reproduction_internal_checks_passed: Literal[True] = True
    recorded_commit_bound: Literal[True] = True
    current_checkout_binding_status: Literal["match", "mismatch"]
    boundary: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_internal_checks(self) -> Self:
        if self.internal_checks != REGISTERED_M3_INTERNAL_CHECKS:
            raise ValueError("M3 internal checks differ from the registered verifier set")
        return self


class DemoM3Evidence(DemoModel):
    experiment_id: str = Field(min_length=1)
    reproduction_experiment_id: str = Field(min_length=1)
    evidence_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    retention_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    sessions: int = Field(gt=0)
    trial_records: int = Field(gt=0)
    evidence_events: int = Field(gt=0)
    deterministic_outcome_sha256: str = Field(pattern=SHA256_PATTERN)
    model_digest: str = Field(pattern=SHA256_PATTERN)
    verification: DemoM3Verification
    conditions: tuple[DemoCondition, ...] = Field(min_length=5, max_length=5)
    metrics: tuple[DemoNamedBinomialMetric, ...] = Field(min_length=5, max_length=5)
    nominal_state: DemoNominalState
    finding: str = Field(min_length=1)
    limitation: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_m3_aggregates(self) -> Self:
        condition_ids = tuple(item.condition_id for item in self.conditions)
        metric_ids = tuple(item.metric_id for item in self.metrics)
        if condition_ids != REGISTERED_M3_CONDITIONS:
            raise ValueError("M3 conditions differ from the registered order")
        if metric_ids != REGISTERED_M3_METRICS:
            raise ValueError("M3 metrics differ from the registered order")
        if sum(item.trials for item in self.conditions) != self.trial_records:
            raise ValueError("M3 condition counts differ from total trial records")
        if any(item.trials != self.sessions for item in self.conditions):
            raise ValueError("M3 fixed-condition counts differ from session count")
        metrics = {item.metric_id: item for item in self.metrics}
        expected_denominators = {
            "non_nominal_effect": self.sessions * 4,
            "nominal_completion": self.sessions,
            "replay_second_effect": self.sessions,
            "unknown_effect": self.trial_records,
            "trace_complete": self.trial_records,
        }
        if any(
            metrics[metric_id].denominator != denominator
            for metric_id, denominator in expected_denominators.items()
        ):
            raise ValueError("M3 metric denominator differs from the registered design")
        conditions = {item.condition_id: item for item in self.conditions}
        if metrics["non_nominal_effect"].numerator != sum(
            item.modeled_effects
            for item in self.conditions
            if item.condition_id != "nominal_permitted_execution"
        ):
            raise ValueError("M3 non-nominal effect metric differs from condition counts")
        if (
            metrics["replay_second_effect"].numerator
            != conditions["permit_replay"].modeled_effects
        ):
            raise ValueError("M3 replay-effect metric differs from condition counts")
        if metrics["unknown_effect"].numerator != sum(
            item.unknown_effects for item in self.conditions
        ):
            raise ValueError("M3 unknown-effect metric differs from condition counts")
        if (
            metrics["nominal_completion"].numerator
            != conditions["nominal_permitted_execution"].terminal_completions
        ):
            raise ValueError("M3 nominal-completion metric differs from condition counts")
        if metrics["trace_complete"].numerator != sum(
            item.trace_complete for item in self.conditions
        ):
            raise ValueError("M3 trace-completeness metric differs from condition counts")
        return self


class DemoArchitectureStage(DemoModel):
    stage_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    responsibility: str = Field(min_length=1)


class PublicDemoEvidence(DemoModel):
    schema_version: Literal["public-demo-v2"] = "public-demo-v2"
    project: DemoProjectState
    generated_from: tuple[DemoSourceArtifact, ...] = Field(min_length=5)
    architecture: tuple[DemoArchitectureStage, ...] = Field(min_length=7, max_length=7)
    m2: DemoM2Evidence
    m3: DemoM3Evidence
    next_gates: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_public_bindings(self) -> Self:
        paths = tuple(item.path for item in self.generated_from)
        stage_ids = tuple(item.stage_id for item in self.architecture)
        if paths != REGISTERED_DEMO_SOURCE_PATHS:
            raise ValueError("public-demo source paths differ from the registered evidence set")
        if stage_ids != REGISTERED_ARCHITECTURE_STAGES:
            raise ValueError("public-demo architecture differs from the registered order")
        return self


@lru_cache(maxsize=1)
def load_public_demo_evidence() -> PublicDemoEvidence:
    """Load and validate the generated evidence summary packaged with the service."""

    material = (
        files("aegis_ot")
        .joinpath("web_demo", "evidence.json")
        .read_text(encoding="utf-8")
    )
    return PublicDemoEvidence.model_validate_json(material)
