from __future__ import annotations

import json

from aegis_ot.capability_models import CapabilityClosedLoopStatus
from aegis_ot.m4b_experiment import collect_m4b_experiment, collection_summary
from aegis_ot.m4b_models import IndependentEvaluationStatus, M4bComponentRole


def test_one_session_collection_closes_stack_then_retains_complete_evidence() -> None:
    collection = collect_m4b_experiment(
        root_seed=20260825,
        seed_count=1,
        require_clean_checkout=False,
    )

    assert tuple(record.condition for record in collection.transaction_records) == (
        "unknown_identity",
        "stale_observation",
        "nominal_permitted_execution",
    )
    assert tuple(record.result.status for record in collection.transaction_records) == (
        CapabilityClosedLoopStatus.NOT_DISPATCHED,
        CapabilityClosedLoopStatus.NOT_DISPATCHED,
        CapabilityClosedLoopStatus.COMPLETED,
    )
    assert len(collection.evidence_records) == 5
    assert tuple(record.role for record in collection.component_registrations) == (
        M4bComponentRole.PLANT,
        M4bComponentRole.OBSERVER,
        M4bComponentRole.PLC,
        M4bComponentRole.PERMIT_SIGNER,
        M4bComponentRole.REPLACEMENT_PLC,
        M4bComponentRole.INDEPENDENT_EVALUATOR,
    )
    assert len(collection.probe_bundles) == 1
    assert len(collection.probe_bundles[0].records) == 4
    assert all(record.matched_expectation for record in collection.probe_bundles[0].records)
    assert collection.replay_records[0].replay_acknowledgment.reason == "transaction_replayed"
    assert collection.replay_records[0].replay_state_unchanged
    assert collection.evaluation_reports[0].status is IndependentEvaluationStatus.AGREE
    assert collection.evaluation_reports[0].verify_for_request(
        collection.evaluation_requests[0]
    )

    nominal = collection.transaction_records[-1]
    assert nominal.independent_report_id == collection.evaluation_reports[0].report_id
    assert nominal.independent_report_sha256 == collection.evaluation_reports[0].digest
    assert collection.replay_records[0].original_transaction_sha256 == nominal.digest
    assert collection_summary(collection)["experiment_criteria_met"] is True
    assert json.loads(collection.artifacts["summary.json"])["session_count"] == 1
    assert "source/src/aegis_ot/capability_control.py" in collection.source_sha256
    assert "source/src/aegis_ot_independent/evaluator.py" in collection.source_sha256
    assert (
        collection.fixture_sha256["independent/topology-fixture.json"]
        == "d93154564bd1a69205a492d1640fc55e92c6570b45079aa300edad27af0405a1"
    )
