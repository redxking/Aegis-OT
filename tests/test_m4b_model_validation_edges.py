from __future__ import annotations

from decimal import Decimal

import pytest

from aegis_ot.m4b_models import (
    IndependentMetricComparison,
    IndependentMetricName,
    _require_decimal_input,
    _require_finite_decimal,
    _require_json_value,
    _require_signature,
    _require_sorted_unique,
    _require_unique,
)


def test_m4b_signature_and_decimal_helpers_reject_invalid_wire_values() -> None:
    assert _require_signature("") == ""
    with pytest.raises(ValueError, match="exactly 64 bytes"):
        _require_signature("YQ==")

    assert _require_finite_decimal(Decimal("1.25")) == Decimal("1.25")
    with pytest.raises(ValueError, match="must be finite"):
        _require_finite_decimal(Decimal("NaN"))

    assert _require_decimal_input(Decimal("1")) == Decimal("1")
    assert _require_decimal_input("-1.25") == "-1.25"
    with pytest.raises(ValueError, match="plain decimal strings"):
        _require_decimal_input(1.25)


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (("",), "cannot contain empty"),
        (("b", "a"), "unique and lexicographically sorted"),
        (("a", "a"), "unique and lexicographically sorted"),
    ],
)
def test_m4b_sorted_unique_helper_rejects_noncanonical_sets(
    values: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _require_sorted_unique(values, label="values")
    _require_sorted_unique(("a", "b"), label="values")


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (("",), "cannot contain empty"),
        (("a", "a"), "must be unique"),
    ],
)
def test_m4b_unique_helper_rejects_empty_and_duplicate_values(
    values: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _require_unique(values, label="values")
    _require_unique(("b", "a"), label="values")


def test_m4b_json_value_helper_walks_nested_values_and_rejects_non_json_data() -> None:
    _require_json_value(
        {
            "none": None,
            "text": "value",
            "boolean": True,
            "integer": 1,
            "float": 1.5,
            "nested": [1, {"value": False}],
        },
        label="structured field",
    )

    with pytest.raises(ValueError, match="non-finite"):
        _require_json_value(float("inf"), label="structured field")
    with pytest.raises(ValueError, match="string keys"):
        _require_json_value({1: "value"}, label="structured field")  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="JSON-compatible"):
        _require_json_value(object(), label="structured field")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("expected", "observed", "tolerance", "outcome", "message"),
    [
        ("not-decimal", "1", "0", "mismatch", "plain decimal string"),
        ("1", "1", "-1", "match", "nonnegative tolerance"),
        ("1", "1", "0", "mismatch", "outcome is inconsistent"),
    ],
)
def test_m4b_numeric_metric_comparison_rejects_invalid_or_inconsistent_values(
    expected: str,
    observed: str,
    tolerance: str,
    outcome: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        IndependentMetricComparison.model_validate(
            {
                "metric": IndependentMetricName.SERVED_LOAD_MW,
                "expected": expected,
                "observed": observed,
                "tolerance": tolerance,
                "outcome": outcome,
            }
        )

    valid = IndependentMetricComparison(
        metric=IndependentMetricName.SERVED_LOAD_MW,
        expected="1.0",
        observed="1.1",
        tolerance="0.1",
        outcome="match",
    )
    assert valid.outcome == "match"


@pytest.mark.parametrize(
    ("expected", "observed", "tolerance", "outcome", "message"),
    [
        ('["feeder-1"]', '["feeder-1"]', "0", "match", "exact tolerance"),
        ("not-json", "[]", "exact", "match", "canonical JSON arrays"),
        ('["feeder-1","feeder-1"]', "[]", "exact", "mismatch", "sorted unique"),
        ('[ "feeder-1" ]', '["feeder-1"]', "exact", "match", "canonical JSON"),
        ('["feeder-1"]', '["feeder-1"]', "exact", "mismatch", "outcome is inconsistent"),
    ],
)
def test_m4b_isolated_resource_comparison_rejects_noncanonical_evidence(
    expected: str,
    observed: str,
    tolerance: str,
    outcome: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        IndependentMetricComparison.model_validate(
            {
                "metric": IndependentMetricName.ISOLATED_RESOURCES,
                "expected": expected,
                "observed": observed,
                "tolerance": tolerance,
                "outcome": outcome,
            }
        )

    valid = IndependentMetricComparison(
        metric=IndependentMetricName.ISOLATED_RESOURCES,
        expected='["feeder-1"]',
        observed="[]",
        tolerance="exact",
        outcome="mismatch",
    )
    assert valid.outcome == "mismatch"
