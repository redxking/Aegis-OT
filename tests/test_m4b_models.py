from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ValidationError

from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopResult,
    CapabilityClosedLoopStatus,
    DispatchPhase,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from aegis_ot.m4b_models import (
    IndependentConsequenceReport,
    IndependentConsequenceValues,
    IndependentEvaluationRequest,
    IndependentEvaluationStatus,
    IndependentMetricComparison,
    IndependentMetricName,
    M4bArtifactDescriptor,
    M4bCapabilityProbeBundle,
    M4bCapabilityProbeRecord,
    M4bComponentRegistration,
    M4bComponentRole,
    M4bEvidenceManifest,
    M4bManifestSignature,
    M4bOrderlyRestartReplayRecord,
    M4bPackageDisposition,
    M4bTransactionRecord,
    M4bTrustAnchor,
    public_key_base64,
    sha256_bytes,
)
from aegis_ot.models import ActionProposal, Operation
from aegis_ot.physical_models import (
    CommandStatus,
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
)

NOW = datetime(2026, 8, 25, 14, 0, tzinfo=UTC)
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
ROOT = Path(__file__).resolve().parents[1]


def _public_key_sha256(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_bytes(raw)


def _state(
    *,
    state_version: int,
    observed_at: datetime,
    observation_sequence: int,
    isolated_resources: tuple[str, ...] = (),
) -> PhysicalStateSnapshot:
    provisional = PhysicalStateSnapshot(
        model_id="m4b-test-model",
        simulator_version="test-1",
        model_digest=DIGEST_A,
        input_digest=DIGEST_B,
        topology_digest=DIGEST_C,
        state_digest="0" * 64,
        observation_digest="0" * 64,
        observation_sequence=observation_sequence,
        observation_source_id="plant:m4b-test",
        observation_clock_domain="deterministic-test",
        state_version=state_version,
        simulation_time_s=float(state_version),
        observed_at=observed_at,
        converged=True,
        total_load_demand_mw=10.0,
        served_load_mw=10.0,
        unserved_load_mw=0.0,
        total_load_served_pct=100.0,
        priority_load_demand_mw=5.0,
        priority_load_served_mw=5.0,
        priority_load_served_pct=100.0,
        minimum_voltage_pu=0.99,
        maximum_voltage_pu=1.01,
        maximum_line_loading_pct=20.0,
        voltage_violation_count=0,
        thermal_violation_count=0,
        unsafe_state=False,
        isolated_resources=isolated_resources,
        battery_injection_mw={},
        bus_voltage_pu=(1.0,),
        line_loading_pct=(20.0,),
    )
    with_state = provisional.model_copy(
        update={"state_digest": canonical_digest(provisional.digest_material())}
    )
    state = with_state.model_copy(
        update={"observation_digest": canonical_digest(with_state.observation_material())}
    )
    assert state.verify_digest()
    return state


def _command() -> PhysicalControlCommand:
    return PhysicalControlCommand(
        command_id="m4b-command-1",
        proposal_id="m4b-proposal-1",
        operation=Operation.ISOLATE_ASSET,
        resource="feeder-1",
        command_type=PhysicalCommandType.SET_LINE_SERVICE,
        target="line.in_service",
        target_index=1,
        setpoint=0.0,
        unit="boolean",
    )


def _observations(
    private_key: Ed25519PrivateKey,
) -> tuple[SignedObservationEnvelope, SignedObservationEnvelope, PhysicalControlCommand]:
    command = _command()
    pre_state = _state(state_version=0, observed_at=NOW, observation_sequence=1)
    post_state = _state(
        state_version=1,
        observed_at=NOW + timedelta(seconds=1),
        observation_sequence=2,
        isolated_resources=("feeder-1",),
    )
    pre = SignedObservationEnvelope.issue(
        snapshot=pre_state,
        correlation_id="m4b-correlation-1",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="m4b-pre-observation-nonce",
        observer_id="observer:m4b-test",
        observer_key_id="observer-key-1",
        observer_boot_epoch="observer-boot-epoch-0001",
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=private_key,
    )
    post = SignedObservationEnvelope.issue(
        snapshot=post_state,
        correlation_id=pre.correlation_id,
        phase=ObservationPhase.POST_DISPATCH,
        challenge_nonce="m4b-post-observation-nonce",
        observer_id=pre.observer_id,
        observer_key_id=pre.observer_key_id,
        observer_boot_epoch=pre.observer_boot_epoch,
        observer_sequence=2,
        previous_envelope_digest=pre.envelope_digest,
        permit_id="permit-1",
        command_digest=command.digest,
        plc_acknowledgment_digest=DIGEST_D,
        private_key=private_key,
    )
    return pre, post, command


def _evaluation_request(
    private_key: Ed25519PrivateKey,
) -> IndependentEvaluationRequest:
    pre, post, command = _observations(private_key)
    return IndependentEvaluationRequest(
        request_id="independent-request-1",
        session_index=0,
        master_seed=20260825,
        transaction_record_digest=DIGEST_A,
        fixture_id="neutral-topology-fixture-1",
        fixture_digest=DIGEST_B,
        nonce="independent-request-nonce-0001",
        pre_observation=pre,
        post_observation=post,
        command=command,
        observer_key_id=pre.observer_key_id,
        observer_public_key_b64=public_key_base64(private_key.public_key()),
        absolute_tolerance_mw=Decimal("0.000001"),
        absolute_tolerance_pct=Decimal("0.0001"),
    )


def _consequence_values() -> IndependentConsequenceValues:
    return IndependentConsequenceValues(
        source_connected_bus_count=4,
        total_load_demand_mw=Decimal("10.0"),
        served_load_mw=Decimal("10.0"),
        priority_load_demand_mw=Decimal("5.0"),
        priority_load_served_mw=Decimal("5.0"),
        total_load_served_pct=Decimal("100.0"),
        priority_load_served_pct=Decimal("100.0"),
        isolated_resources=("feeder-1",),
    )


def _matching_comparisons() -> tuple[IndependentMetricComparison, ...]:
    comparisons: list[IndependentMetricComparison] = []
    for metric in IndependentMetricName:
        if metric is IndependentMetricName.ISOLATED_RESOURCES:
            value = '["feeder-1"]'
            tolerance = "exact"
        else:
            value = "10.0"
            tolerance = "0.0001"
        comparisons.append(
            IndependentMetricComparison(
                metric=metric,
                expected=value,
                observed=value,
                tolerance=tolerance,
                outcome="match",
            )
        )
    return tuple(comparisons)


def _report(
    request: IndependentEvaluationRequest,
    private_key: Ed25519PrivateKey,
) -> IndependentConsequenceReport:
    values = _consequence_values()
    return IndependentConsequenceReport(
        report_id="independent-report-1",
        request_id=request.request_id,
        request_digest=request.digest,
        key_id="independent-evaluator-key-1",
        public_key_b64=public_key_base64(private_key.public_key()),
        boot_epoch="independent-evaluator-boot-0001",
        pid=1234,
        sequence=1,
        evaluated_at=NOW + timedelta(seconds=2),
        fixture_id=request.fixture_id,
        fixture_digest=request.fixture_digest,
        evaluator_source_sha256=DIGEST_C,
        status=IndependentEvaluationStatus.AGREE,
        reasons=(),
        predicted_values=values,
        observed_values=values,
        metric_comparisons=_matching_comparisons(),
    ).signed(private_key)


def _not_dispatched_result() -> CapabilityClosedLoopResult:
    proposal = ActionProposal(
        proposal_id="m4b-proposal-1",
        actor_id="agent:test",
        mission_id="m4b-test",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=0,
        observed_at=NOW,
        submitted_at=NOW,
        nonce="m4b-action-proposal-nonce-1",
        confidence=Decimal("0.9"),
        risk_score=Decimal("20"),
        delegation_chain=("grant-1",),
    )
    request = CapabilityActionRequest(
        request_id="m4b-action-request-1",
        correlation_id="m4b-correlation-1",
        proposal=proposal,
        observation_id="missing-observation-1",
        observation_envelope_digest=DIGEST_A,
        observation_challenge_nonce="missing-observation-nonce",
    )
    return CapabilityClosedLoopResult(
        status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
        reasons=("observer_unavailable",),
        request=request,
        dispatch_attempts=0,
        execution_evidence_hash=DIGEST_B,
    )


def _artifact(path: str = "records/transactions.jsonl") -> M4bArtifactDescriptor:
    return M4bArtifactDescriptor(
        path=path,
        media_type="application/x-ndjson",
        byte_length=123,
        sha256=DIGEST_A,
        record_count=1,
    )


def _manifest() -> M4bEvidenceManifest:
    return M4bEvidenceManifest(
        experiment_id="m4b-evidence-test",
        experiment_version="m4b-v1",
        outcome_projection_version="m4b-outcome-v1",
        protocol_version="m4b-protocol-v1",
        package_disposition=M4bPackageDisposition.COMPLETE,
        started_at_utc=NOW,
        completed_at_utc=NOW + timedelta(seconds=5),
        git={"commit": "1" * 40, "dirty": False},
        root_seed=20260825,
        master_seeds=(20260826,),
        session_count=1,
        transaction_record_count=1,
        evidence_record_count=2,
        component_registration_count=4,
        probe_record_count=1,
        independent_evaluation_count=1,
        artifacts=(_artifact(),),
        source_sha256={"src/aegis_ot/m4b_models.py": DIGEST_A},
        schema_sha256={"schemas/m4b-evidence-manifest.schema.json": DIGEST_B},
        configuration_sha256={"config/lab.yaml": DIGEST_C},
        fixture_sha256={"fixtures/topology.json": DIGEST_D},
        deterministic_outcome_sha256=DIGEST_A,
        root_anchor_id="m4b-root-anchor",
        root_key_id="m4b-root-key",
        root_public_key_sha256=DIGEST_B,
        host={"system": "test", "cpu_count": 1},
        component_versions={"aegis-ot": "0.1.0", "python": "3.14"},
        boundary={"claim": "local package integrity only"},
        known_limitations=("no external custody",),
        summary={"completed": 1, "unknown_effect": 0},
    )


def test_trust_anchor_validates_key_digest_time_and_closed_frozen_shape() -> None:
    private_key = Ed25519PrivateKey.generate()
    anchor = M4bTrustAnchor(
        anchor_id="m4b-root-anchor",
        key_id="m4b-root-key",
        public_key_b64=public_key_base64(private_key.public_key()),
        public_key_sha256=_public_key_sha256(private_key),
        not_before=NOW,
        not_after=NOW + timedelta(days=1),
    )
    assert anchor.public_key.public_bytes_raw() == private_key.public_key().public_bytes_raw()
    assert len(anchor.digest) == 64
    with pytest.raises(ValidationError):
        M4bTrustAnchor.model_validate(
            {**anchor.model_dump(mode="json"), "public_key_sha256": DIGEST_A}
        )
    with pytest.raises(ValidationError):
        M4bTrustAnchor.model_validate({**anchor.model_dump(mode="json"), "extra": True})
    with pytest.raises(ValidationError):
        anchor.key_id = "changed"  # type: ignore[misc]


def test_component_registration_requires_atomic_key_and_canonical_capabilities() -> None:
    private_key = Ed25519PrivateKey.generate()
    registration = M4bComponentRegistration(
        session_id="session-1",
        session_index=0,
        master_seed=1,
        role=M4bComponentRole.OBSERVER,
        component_id="observer:test",
        pid=100,
        boot_epoch="observer-boot-epoch-0001",
        key_id="observer-key-1",
        public_key_b64=public_key_base64(private_key.public_key()),
        public_key_sha256=_public_key_sha256(private_key),
        capabilities=("admin:health", "telemetry:capture"),
        plant_boot_epoch="plant-boot-epoch-0000001",
        registered_at=NOW,
    )
    assert registration.role is M4bComponentRole.OBSERVER
    with pytest.raises(ValidationError, match="atomic"):
        M4bComponentRegistration.model_validate(
            {**registration.model_dump(mode="json"), "public_key_sha256": None}
        )
    with pytest.raises(ValidationError, match="sorted"):
        M4bComponentRegistration.model_validate(
            {
                **registration.model_dump(mode="json"),
                "capabilities": ["telemetry:capture", "admin:health"],
            }
        )


def test_transaction_record_binds_result_status_digest_and_report_pair() -> None:
    result = _not_dispatched_result()
    record = M4bTransactionRecord(
        session_id="session-1",
        session_index=0,
        master_seed=1,
        condition="observer-unavailable",
        expected_terminal_status=result.status,
        result=result,
        result_sha256=canonical_digest(result),
        evidence_first_sequence=1,
        evidence_last_sequence=2,
        evidence_chain_head=DIGEST_A,
        component_registration_sha256=DIGEST_B,
        pre_health_sha256=DIGEST_C,
        post_health_sha256=DIGEST_D,
    )
    assert record.digest == canonical_digest(record)
    with pytest.raises(ValidationError, match="result digest"):
        M4bTransactionRecord.model_validate(
            {**record.model_dump(mode="json"), "result_sha256": DIGEST_A}
        )
    with pytest.raises(ValidationError, match="present together"):
        M4bTransactionRecord.model_validate(
            {**record.model_dump(mode="json"), "independent_report_id": "report-1"}
        )


def test_transaction_evaluation_binding_is_stable_after_report_linkage() -> None:
    result = _not_dispatched_result()
    record = M4bTransactionRecord(
        session_id="session-1",
        session_index=0,
        master_seed=20260825,
        condition="identity-denied",
        expected_terminal_status=result.status,
        result=result,
        result_sha256=canonical_digest(result),
        evidence_first_sequence=0,
        evidence_last_sequence=0,
        evidence_chain_head=DIGEST_B,
        component_registration_sha256=DIGEST_C,
        pre_health_sha256=DIGEST_D,
        post_health_sha256=DIGEST_A,
    )

    before = record.evaluation_binding_sha256
    linked = record.model_copy(
        update={
            "independent_report_id": "independent-report-1",
            "independent_report_sha256": DIGEST_D,
        }
    )

    assert linked.evaluation_binding_sha256 == before
    assert canonical_digest(linked) != canonical_digest(record)


def test_probe_bundle_is_ordered_self_digesting_and_can_retain_a_failed_probe() -> None:
    record = M4bCapabilityProbeRecord(
        session_id="session-1",
        ordinal=1,
        endpoint_role=M4bComponentRole.OBSERVER,
        operation="probe_plant_apply",
        actual_disposition="unexpected_success",
        request_payload_sha256=DIGEST_A,
        response_payload_sha256=DIGEST_B,
        server_boot_epoch="observer-boot-epoch-0001",
        response_counter=1,
        observed_at=NOW,
    )
    bundle = M4bCapabilityProbeBundle.issue(session_id="session-1", records=(record,))
    assert not record.matched_expectation
    assert bundle.bundle_sha256 == bundle.expected_bundle_sha256
    with pytest.raises(ValidationError, match="digest"):
        M4bCapabilityProbeBundle.model_validate(
            {**bundle.model_dump(mode="json"), "bundle_sha256": DIGEST_A}
        )


def test_orderly_restart_record_rejects_unbound_or_effectful_replay_claim() -> None:
    plc_private = Ed25519PrivateKey.generate()
    observer_private = Ed25519PrivateKey.generate()
    pre_state = _state(state_version=0, observed_at=NOW, observation_sequence=1)
    acknowledgment = PlcCommandAcknowledgment(
        request_digest=DIGEST_A,
        permit_digest=DIGEST_B,
        observation_envelope_digest=DIGEST_C,
        permit_id="permit-1",
        permit_nonce="permit-nonce-replay-0001",
        command_id="m4b-command-1",
        command_digest=DIGEST_D,
        assessment_digest="e" * 64,
        proposal_id="m4b-proposal-1",
        decision_id="m4b-decision-1",
        plc_id="plc:replacement",
        plc_key_id="plc-key-2",
        plc_boot_epoch="replacement-plc-boot-0001",
        plc_scan=1,
        status=CommandStatus.REJECTED,
        dispatch_phase=DispatchPhase.PRE_DISPATCH,
        reason="command_replayed",
        acknowledged_at=NOW + timedelta(seconds=1),
        pre_state=pre_state,
        pre_state_digest=pre_state.state_digest,
        pre_state_version=pre_state.state_version,
        pre_actuator_setpoint=1.0,
        post_actuator_setpoint=1.0,
        simulation_time_s=pre_state.simulation_time_s,
    ).signed(plc_private)
    later_state = _state(
        state_version=0,
        observed_at=NOW + timedelta(seconds=2),
        observation_sequence=2,
    )
    observation = SignedObservationEnvelope.issue(
        snapshot=later_state,
        correlation_id="replay-observation-1",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="post-replay-observation-nonce",
        observer_id="observer:test",
        observer_key_id="observer-key-1",
        observer_boot_epoch="observer-boot-epoch-0001",
        observer_sequence=2,
        previous_envelope_digest=None,
        private_key=observer_private,
    )
    replay = M4bOrderlyRestartReplayRecord(
        session_id="session-1",
        original_transaction_sha256="f" * 64,
        original_request_digest=DIGEST_A,
        original_permit_digest=DIGEST_B,
        original_command_digest=DIGEST_D,
        prior_plc_registration_sha256=DIGEST_A,
        replacement_plc_registration_sha256=DIGEST_B,
        replay_acknowledgment=acknowledgment,
        before_plant_health_sha256=DIGEST_C,
        after_plant_health_sha256=DIGEST_D,
        post_replay_observation=observation,
        replay_state_unchanged=True,
        recorded_at=NOW + timedelta(seconds=3),
    )
    assert replay.replay_state_unchanged
    with pytest.raises(ValidationError, match="distinct"):
        M4bOrderlyRestartReplayRecord.model_validate(
            {
                **replay.model_dump(mode="json"),
                "replacement_plc_registration_sha256": DIGEST_A,
            }
        )


def test_independent_request_has_no_gateway_oracle_inputs_and_verifies_observer() -> None:
    observer_private = Ed25519PrivateKey.generate()
    request = _evaluation_request(observer_private)
    assert request.verify_observation_signatures()
    assert isinstance(request.absolute_tolerance_mw, Decimal)
    dumped = request.model_dump(mode="json")
    assert dumped["absolute_tolerance_mw"] == "0.000001"
    forbidden = {
        "candidate",
        "candidate_context",
        "permit",
        "permit_context",
        "acknowledgment",
        "expected_post_state_digest",
    }
    assert forbidden.isdisjoint(dumped)
    with pytest.raises(ValidationError):
        IndependentEvaluationRequest.model_validate({**dumped, "permit": {}})
    with pytest.raises(ValidationError, match="decimal wire values"):
        IndependentEvaluationRequest.model_validate(
            {**dumped, "absolute_tolerance_mw": 0.000001}
        )
    with pytest.raises(ValidationError):
        IndependentEvaluationRequest.model_validate(
            {**dumped, "absolute_tolerance_mw": "NaN"}
        )


def test_independent_request_allows_nonevaluable_terminal_shapes_but_binds_post() -> None:
    observer_private = Ed25519PrivateKey.generate()
    request = _evaluation_request(observer_private)
    not_applicable = request.model_copy(
        update={"pre_observation": None, "post_observation": None, "command": None}
    )
    assert IndependentEvaluationRequest.model_validate(
        not_applicable.model_dump(mode="json")
    ).command is None
    invalid = request.model_dump(mode="json")
    invalid["command"]["command_id"] = "substituted-command"  # type: ignore[index]
    with pytest.raises(ValidationError, match="bound transition"):
        IndependentEvaluationRequest.model_validate(invalid)


def test_independent_report_signature_and_request_binding_are_canonical() -> None:
    observer_private = Ed25519PrivateKey.generate()
    evaluator_private = Ed25519PrivateKey.generate()
    request = _evaluation_request(observer_private)
    report = _report(request, evaluator_private)
    assert report.verify()
    assert report.verify_for_request(request)
    assert "report_digest" not in report.model_dump(mode="json")
    tampered = report.model_copy(update={"fixture_digest": DIGEST_D})
    assert not tampered.verify()
    with pytest.raises(ValueError, match="does not match"):
        report.model_copy(update={"signature": ""}).signed(Ed25519PrivateKey.generate())


def test_independent_report_status_semantics_and_comparison_math() -> None:
    with pytest.raises(ValidationError, match="inconsistent"):
        IndependentMetricComparison(
            metric=IndependentMetricName.SERVED_LOAD_MW,
            expected="10.0",
            observed="9.0",
            tolerance="0.1",
            outcome="match",
        )
    observer_private = Ed25519PrivateKey.generate()
    evaluator_private = Ed25519PrivateKey.generate()
    request = _evaluation_request(observer_private)
    report = _report(request, evaluator_private)
    with pytest.raises(ValidationError, match="mismatch"):
        IndependentConsequenceReport.model_validate(
            {**report.model_dump(mode="json"), "status": "contradict"}
        )
    non_applicable: dict[str, Any] = {
        **report.model_dump(mode="json"),
        "status": "not_applicable",
        "reasons": ["terminal result has no command or post observation"],
        "predicted_values": None,
        "observed_values": None,
        "metric_comparisons": [],
        "signature": "",
    }
    assert (
        IndependentConsequenceReport.model_validate(non_applicable).status
        is IndependentEvaluationStatus.NOT_APPLICABLE
    )


def test_artifact_descriptor_rejects_unsafe_paths() -> None:
    for path in ("/absolute.json", "../escape.json", "a/../escape.json", "a\\b.json"):
        with pytest.raises(ValidationError):
            _artifact(path)


def test_manifest_semantics_and_detached_exact_byte_signature() -> None:
    manifest = _manifest()
    private_key = Ed25519PrivateKey.generate()
    detached = M4bManifestSignature.issue_for_manifest(
        manifest=manifest,
        signer_anchor_id=manifest.root_anchor_id,
        signer_key_id=manifest.root_key_id,
        private_key=private_key,
    )
    assert detached.package_id == sha256_bytes(manifest.canonical_bytes())
    assert detached.verify_for_manifest(manifest, private_key.public_key())
    pretty_manifest = json.dumps(manifest.model_dump(mode="json"), indent=2).encode()
    assert not detached.verify(pretty_manifest, private_key.public_key())
    with pytest.raises(ValidationError, match="package ID"):
        M4bManifestSignature.model_validate(
            {**detached.model_dump(mode="json"), "package_id": DIGEST_A}
        )


def test_manifest_rejects_count_drift_duplicate_paths_and_nonfinite_nested_data() -> None:
    manifest = _manifest()
    with pytest.raises(ValidationError, match="session count"):
        M4bEvidenceManifest.model_validate(
            {**manifest.model_dump(mode="json"), "session_count": 2}
        )
    duplicate = manifest.model_dump(mode="json")
    duplicate["artifacts"] = [duplicate["artifacts"][0], duplicate["artifacts"][0]]
    with pytest.raises(ValidationError, match="unique and sorted"):
        M4bEvidenceManifest.model_validate(duplicate)
    invalid_host = manifest.model_dump(mode="python")
    invalid_host["host"] = {"load": float("inf")}
    with pytest.raises(ValidationError):
        M4bEvidenceManifest.model_validate(invalid_host)


def test_m4b_schema_files_match_models_and_remain_closed() -> None:
    schema_models: dict[str, type[BaseModel]] = {
        "m4b-artifact-descriptor.schema.json": M4bArtifactDescriptor,
        "m4b-capability-probe-bundle.schema.json": M4bCapabilityProbeBundle,
        "m4b-component-registration.schema.json": M4bComponentRegistration,
        "m4b-evidence-manifest.schema.json": M4bEvidenceManifest,
        "m4b-independent-consequence-report.schema.json": IndependentConsequenceReport,
        "m4b-independent-evaluation-request.schema.json": IndependentEvaluationRequest,
        "m4b-manifest-signature.schema.json": M4bManifestSignature,
        "m4b-orderly-restart-replay.schema.json": M4bOrderlyRestartReplayRecord,
        "m4b-transaction-record.schema.json": M4bTransactionRecord,
        "m4b-trust-anchor.schema.json": M4bTrustAnchor,
    }
    for filename, model in schema_models.items():
        schema_path = ROOT / "schemas" / filename
        assert json.loads(schema_path.read_text(encoding="utf-8")) == model.model_json_schema()
        assert model.model_json_schema()["additionalProperties"] is False


def test_key_and_signature_encodings_are_canonical_and_length_checked() -> None:
    private_key = Ed25519PrivateKey.generate()
    anchor = M4bTrustAnchor(
        anchor_id="anchor-1",
        key_id="key-1",
        public_key_b64=public_key_base64(private_key.public_key()),
        public_key_sha256=_public_key_sha256(private_key),
        not_before=NOW,
    )
    unpadded = anchor.public_key_b64.rstrip("=")
    with pytest.raises(ValidationError):
        M4bTrustAnchor.model_validate(
            {**anchor.model_dump(mode="json"), "public_key_b64": unpadded}
        )
    short_key = base64.urlsafe_b64encode(b"x" * 31).decode("ascii")
    with pytest.raises(ValidationError):
        M4bTrustAnchor.model_validate(
            {**anchor.model_dump(mode="json"), "public_key_b64": short_key}
        )
    with pytest.raises(ValidationError, match="timezone-aware"):
        M4bTrustAnchor.model_validate(
            {**anchor.model_dump(mode="json"), "not_before": NOW.replace(tzinfo=None)}
        )


def test_m4b_anchor_and_registration_reject_remaining_identity_inconsistencies() -> None:
    private_key = Ed25519PrivateKey.generate()
    anchor = M4bTrustAnchor(
        anchor_id="anchor-1",
        key_id="key-1",
        public_key_b64=public_key_base64(private_key.public_key()),
        public_key_sha256=_public_key_sha256(private_key),
        not_before=NOW,
    )
    with pytest.raises(ValidationError, match="expiry must be after"):
        M4bTrustAnchor.model_validate(
            {**anchor.model_dump(mode="json"), "not_after": NOW.isoformat()}
        )

    base = {
        "session_id": "session-1",
        "session_index": 0,
        "master_seed": 1,
        "component_id": "component:test",
        "pid": 100,
        "boot_epoch": "component-boot-epoch-0001",
        "capabilities": ["admin:health"],
        "registered_at": NOW.isoformat(),
    }
    with pytest.raises(ValidationError, match="requires an Ed25519 key"):
        M4bComponentRegistration.model_validate(
            {**base, "role": M4bComponentRole.OBSERVER}
        )
    with pytest.raises(ValidationError, match="digest is inconsistent"):
        M4bComponentRegistration.model_validate(
            {
                **base,
                "role": M4bComponentRole.OBSERVER,
                "key_id": "observer-key",
                "public_key_b64": public_key_base64(private_key.public_key()),
                "public_key_sha256": DIGEST_A,
            }
        )
    with pytest.raises(ValidationError, match="plant registration"):
        M4bComponentRegistration.model_validate(
            {**base, "role": M4bComponentRole.PLANT}
        )


def test_m4b_manifest_rejects_temporal_collection_and_count_inconsistencies() -> None:
    manifest = _manifest()

    invalid_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {
                **manifest.model_dump(mode="json"),
                "completed_at_utc": (NOW - timedelta(seconds=1)).isoformat(),
            },
            "completion precedes",
        ),
        (
            {
                **manifest.model_dump(mode="json"),
                "master_seeds": [20260826, 20260826],
                "session_count": 2,
            },
            "master seeds must be unique",
        ),
        (
            {
                **manifest.model_dump(mode="json"),
                "artifacts": [
                    _artifact("manifest.json").model_dump(mode="json"),
                ],
            },
            "cannot describe themselves",
        ),
        (
            {**manifest.model_dump(mode="json"), "source_sha256": {}},
            "source hashes cannot be empty",
        ),
        (
            {
                **manifest.model_dump(mode="json"),
                "source_sha256": {"z.py": DIGEST_A, "a.py": DIGEST_B},
            },
            "source hashes paths must be sorted",
        ),
        (
            {
                **manifest.model_dump(mode="json"),
                "component_versions": {"python": "3.14", "aegis-ot": "0.1.0"},
            },
            "component-version keys must be sorted",
        ),
        (
            {
                **manifest.model_dump(mode="json"),
                "known_limitations": ["same limitation", "same limitation"],
            },
            "known limitations must be unique",
        ),
        (
            {
                **manifest.model_dump(mode="json"),
                "transaction_record_count": 0,
                "independent_evaluation_count": 1,
            },
            "exceeds transaction records",
        ),
    )
    for value, message in invalid_cases:
        with pytest.raises(ValidationError, match=message):
            M4bEvidenceManifest.model_validate(value)


def test_m4b_independent_report_rejects_incomplete_or_misclassified_results() -> None:
    observer_private = Ed25519PrivateKey.generate()
    evaluator_private = Ed25519PrivateKey.generate()
    request = _evaluation_request(observer_private)
    report = _report(request, evaluator_private)
    material = report.model_dump(mode="json")

    with pytest.raises(ValidationError, match="require both value sets"):
        IndependentConsequenceReport.model_validate(
            {**material, "predicted_values": None, "signature": ""}
        )
    with pytest.raises(ValidationError, match="every registered metric"):
        IndependentConsequenceReport.model_validate(
            {**material, "metric_comparisons": material["metric_comparisons"][:-1], "signature": ""}
        )

    mismatched = list(material["metric_comparisons"])
    mismatched[0] = {**mismatched[0], "outcome": "mismatch", "observed": "9.0"}
    with pytest.raises(ValidationError, match="agree status cannot"):
        IndependentConsequenceReport.model_validate(
            {**material, "metric_comparisons": mismatched, "signature": ""}
        )
    with pytest.raises(ValidationError, match="explanatory reason"):
        IndependentConsequenceReport.model_validate(
            {
                **material,
                "status": "contradict",
                "reasons": [],
                "metric_comparisons": mismatched,
                "signature": "",
            }
        )
    with pytest.raises(ValidationError, match="require a reason"):
        IndependentConsequenceReport.model_validate(
            {
                **material,
                "status": "indeterminate",
                "reasons": [],
                "predicted_values": None,
                "observed_values": None,
                "metric_comparisons": [],
                "signature": "",
            }
        )
