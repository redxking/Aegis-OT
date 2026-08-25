from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from aegis_ot.capability_factory import CapabilitySeparatedLab, start_capability_separated_lab
from aegis_ot.capability_models import CapabilityClosedLoopStatus, SignedObservationEnvelope
from aegis_ot.m4b_experiment import (
    build_independent_evaluation_request,
    load_fixture,
    run_independent_evaluator,
)
from aegis_ot.m4b_models import M4bTransactionRecord
from aegis_ot.models import ActionProposal, Operation
from aegis_ot.physical_models import canonical_digest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "fixtures/m4b/cigre-mv-topology-v1.json"
NOW = datetime(2026, 8, 25, 16, 0, tzinfo=UTC)


def _nominal_proposal(
    lab: CapabilitySeparatedLab,
    observation: SignedObservationEnvelope,
) -> ActionProposal:
    snapshot = observation.snapshot
    authorization = lab.authorization
    return ActionProposal(
        proposal_id="m4b-live-nominal-proposal-0001",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=snapshot.state_version,
        observed_at=snapshot.observed_at,
        submitted_at=snapshot.observed_at,
        nonce="m4b-live-nominal-proposal-nonce-0001",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=(
            authorization.root_grant.grant_id,
            authorization.leaf_grant.grant_id,
        ),
    )


def test_live_lab_transaction_crosses_independent_process_boundary(tmp_path: Path) -> None:
    with start_capability_separated_lab(NOW) as lab:
        proposal = _nominal_proposal(lab, lab.initial_observation)
        before_health = {
            "plant": lab.processes.plant_admin.health(),
            "observer": lab.processes.observer_admin.health(),
            "plc": lab.processes.plc_admin.health(),
        }
        result = lab.controller.execute(lab.request_for(proposal, lab.initial_observation))
        after_health = {
            "plant": lab.processes.plant_admin.health(),
            "observer": lab.processes.observer_admin.health(),
            "plc": lab.processes.plc_admin.health(),
        }
        assert result.status is CapabilityClosedLoopStatus.COMPLETED
        record = M4bTransactionRecord(
            session_id="m4b-live-session-0001",
            session_index=0,
            master_seed=20260825,
            condition="nominal-line-isolation",
            expected_terminal_status=CapabilityClosedLoopStatus.COMPLETED,
            result=result,
            result_sha256=canonical_digest(result),
            evidence_first_sequence=lab.authorization.gateway.evidence.records[0].sequence,
            evidence_last_sequence=lab.authorization.gateway.evidence.records[-1].sequence,
            evidence_chain_head=lab.authorization.gateway.evidence.records[-1].record_hash,
            component_registration_sha256=canonical_digest(lab.topology_pids),
            pre_health_sha256=canonical_digest(before_health),
            post_health_sha256=canonical_digest(after_health),
        )
        observer_public_key = lab.processes.observer_info.public_key

    fixture = load_fixture(FIXTURE_PATH)
    request = build_independent_evaluation_request(
        record=record,
        fixture=fixture,
        observer_public_key=observer_public_key,
        request_id="m4b-live-independent-request-0001",
        nonce="m4b-live-independent-request-nonce-0001",
    )
    report = run_independent_evaluator(
        request=request,
        fixture_path=FIXTURE_PATH,
        request_path=tmp_path / "request.json",
        report_path=tmp_path / "report.json",
    )

    assert request.transaction_record_digest == record.evaluation_binding_sha256
    assert report.status.value == "agree"
    assert report.reasons == ("registered_topology_consequence_matches",)
    assert report.verify_for_request(request)
    linked = record.model_copy(
        update={
            "independent_report_id": report.report_id,
            "independent_report_sha256": canonical_digest(report),
        }
    )
    assert linked.evaluation_binding_sha256 == request.transaction_record_digest
