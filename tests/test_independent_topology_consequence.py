from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_ot.capability_models import ObservationPhase, SignedObservationEnvelope
from aegis_ot.m4b_models import (
    IndependentConsequenceReport,
    IndependentEvaluationRequest,
)
from aegis_ot.models import Operation
from aegis_ot.pandapower_plant import PandapowerCigreMVPlant
from aegis_ot.physical_models import (
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
)
from aegis_ot_independent.canonical import (
    canonical_json_bytes,
    public_key_b64,
    strict_json_loads,
)
from aegis_ot_independent.evaluator import (
    EVALUATOR_PROFILE,
    REQUEST_SCHEMA_VERSION,
    evaluate_material,
    evaluate_request,
    verify_report,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "fixtures/m4b/cigre-mv-topology-v1.json"
NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


def _redigest_snapshot(
    snapshot: PhysicalStateSnapshot,
    **updates: Any,
) -> PhysicalStateSnapshot:
    changed = snapshot.model_copy(update=updates)
    with_state = changed.model_copy(
        update={"state_digest": canonical_digest(changed.digest_material())}
    )
    return with_state.model_copy(
        update={
            "observation_digest": canonical_digest(with_state.observation_material())
        }
    )


def _observation_pair(
    command: PhysicalControlCommand | None = None,
    *,
    post_snapshot: PhysicalStateSnapshot | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str, str]:
    plant = PandapowerCigreMVPlant(observed_at=NOW)
    selected = command or PhysicalControlCommand(
        command_id="m4b-independent-command-0001",
        proposal_id="m4b-independent-proposal-0001",
        operation=Operation.ISOLATE_ASSET,
        resource="feeder-1",
        command_type=PhysicalCommandType.SET_LINE_SERVICE,
        target="Line 5-6",
        target_index=4,
        setpoint=0.0,
        unit="boolean",
    )
    assessment = plant.simulate_candidate(selected)
    observer_key = Ed25519PrivateKey.generate()
    observer_key_id = "m4b-independent-observer-key-0001"
    pre = SignedObservationEnvelope.issue(
        snapshot=assessment.pre_state,
        correlation_id="m4b-independent-correlation-0001",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="m4b-independent-pre-challenge-0001",
        observer_id="observer:m4b-independent-test",
        observer_key_id=observer_key_id,
        observer_boot_epoch="m4b-independent-observer-boot-0001",
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=observer_key,
    )
    post = SignedObservationEnvelope.issue(
        snapshot=post_snapshot or assessment.post_state,
        correlation_id=pre.correlation_id,
        phase=ObservationPhase.POST_DISPATCH,
        challenge_nonce="m4b-independent-post-challenge-0001",
        observer_id=pre.observer_id,
        observer_key_id=observer_key_id,
        observer_boot_epoch=pre.observer_boot_epoch,
        observer_sequence=2,
        previous_envelope_digest=pre.envelope_digest,
        permit_id="m4b-independent-permit-0001",
        command_digest=selected.digest,
        plc_acknowledgment_digest="a" * 64,
        private_key=observer_key,
    )
    return (
        selected.model_dump(mode="json"),
        pre.model_dump(mode="json"),
        post.model_dump(mode="json"),
        observer_key_id,
        public_key_b64(observer_key.public_key()),
    )


def _request(
    *,
    command: dict[str, Any] | None | object = ...,
    pre: dict[str, Any] | None | object = ...,
    post: dict[str, Any] | None | object = ...,
    transaction_digest: str = "b" * 64,
) -> dict[str, Any]:
    built_command, built_pre, built_post, observer_key_id, observer_public = (
        _observation_pair()
    )
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": "m4b-independent-evaluation-request-0001",
        "session_index": 0,
        "master_seed": 20260825,
        "transaction_record_digest": transaction_digest,
        "fixture_id": "pandapower-cigre-mv-all-neutral-topology-v1",
        "fixture_digest": "58ed983e507811935c448e6d468e952ff34620958eae893d16d454a89651709f",
        "evaluator_profile": EVALUATOR_PROFILE,
        "nonce": "m4b-independent-evaluation-nonce-0001",
        "pre_observation": built_pre if pre is ... else pre,
        "post_observation": built_post if post is ... else post,
        "command": built_command if command is ... else command,
        "observer_key_id": observer_key_id,
        "observer_public_key_b64": observer_public,
        "absolute_tolerance_mw": "0.000000001",
        "absolute_tolerance_pct": "0.000000001",
    }


def _fixture() -> dict[str, Any]:
    value = strict_json_loads(FIXTURE_PATH.read_bytes())
    assert isinstance(value, dict)
    return value


def test_registered_fixture_is_reproducible() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/build_m4b_topology_fixture.py",
            "--check",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_independent_package_has_no_main_or_solver_imports() -> None:
    forbidden_roots = {"aegis_ot", "pandapower", "networkx", "numpy", "scipy"}
    package = ROOT / "src/aegis_ot_independent"
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = {alias.name.split(".", maxsplit=1)[0] for alias in node.names}
                assert imported.isdisjoint(forbidden_roots), (path, imported)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                assert node.module.split(".", maxsplit=1)[0] not in forbidden_roots, path


def test_graph_and_decimal_evaluator_agrees_with_registered_line_isolation() -> None:
    report = evaluate_request(_request(), _fixture())

    assert report["status"] == "agree"
    assert report["reasons"] == ["registered_topology_consequence_matches"]
    assert report["predicted_values"] == {
        "source_connected_bus_count": 14,
        "total_load_demand_mw": "44.74215",
        "served_load_mw": "44.1941",
        "priority_load_demand_mw": "1.01575",
        "priority_load_served_mw": "1.01575",
        "total_load_served_pct": "98.77509239050872611173133164",
        "priority_load_served_pct": "100",
        "isolated_resources": ["feeder-1"],
    }
    assert all(item["outcome"] == "match" for item in report["metric_comparisons"])
    assert verify_report(report)


def test_signed_contradiction_is_evidence_not_input_failure() -> None:
    command, pre, post, key_id, public_key = _observation_pair()
    post_model = SignedObservationEnvelope.model_validate(post)
    contradictory_snapshot = _redigest_snapshot(
        post_model.snapshot,
        served_load_mw=post_model.snapshot.served_load_mw + 1.0,
    )
    # Reissue the changed observation under a fresh test observer so the
    # evaluator receives a cryptographically valid but contradictory value.
    observer_key = Ed25519PrivateKey.generate()
    new_pre = SignedObservationEnvelope.issue(
        snapshot=SignedObservationEnvelope.model_validate(pre).snapshot,
        correlation_id="m4b-contradiction-correlation-0001",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="m4b-contradiction-pre-challenge-0001",
        observer_id="observer:m4b-contradiction",
        observer_key_id=key_id,
        observer_boot_epoch="m4b-contradiction-observer-boot-0001",
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=observer_key,
    )
    new_post = SignedObservationEnvelope.issue(
        snapshot=contradictory_snapshot,
        correlation_id=new_pre.correlation_id,
        phase=ObservationPhase.POST_DISPATCH,
        challenge_nonce="m4b-contradiction-post-challenge-0001",
        observer_id=new_pre.observer_id,
        observer_key_id=key_id,
        observer_boot_epoch=new_pre.observer_boot_epoch,
        observer_sequence=2,
        previous_envelope_digest=new_pre.envelope_digest,
        permit_id="m4b-contradiction-permit-0001",
        command_digest=canonical_digest(command),
        plc_acknowledgment_digest="c" * 64,
        private_key=observer_key,
    )
    request = _request(
        command=command,
        pre=new_pre.model_dump(mode="json"),
        post=new_post.model_dump(mode="json"),
    )
    request["observer_public_key_b64"] = public_key_b64(observer_key.public_key())
    report = evaluate_request(request, _fixture())

    assert report["status"] == "contradict"
    assert "metric_mismatch:served_load_mw" in report["reasons"]
    assert verify_report(report)


def test_candidate_permit_and_ack_expected_post_cannot_feed_prediction() -> None:
    request_a = _request(transaction_digest="1" * 64)
    request_b = _request(transaction_digest="2" * 64)
    # The transaction digest can change because any upstream candidate, permit,
    # or ACK field changed, but those artifacts are absent from this contract.
    assert not {"candidate", "permit", "acknowledgment"} & set(request_a)

    report_a = evaluate_request(request_a, _fixture())
    report_b = evaluate_request(request_b, _fixture())

    for field in ("status", "reasons", "predicted_values", "observed_values", "metric_comparisons"):
        assert report_a[field] == report_b[field]
    assert report_a["request_digest"] != report_b["request_digest"]

    injected = deepcopy(request_a)
    injected["permit"] = {"expected_post_state_digest": "0" * 64}
    rejected = evaluate_request(injected, _fixture())
    assert rejected["status"] == "input_rejected"
    assert rejected["reasons"] == ["request_fields_invalid"]


def test_not_applicable_indeterminate_and_input_rejected_are_signed() -> None:
    not_applicable = evaluate_request(
        _request(command=None, post=None),
        _fixture(),
    )
    assert not_applicable["status"] == "not_applicable"
    assert verify_report(not_applicable)

    command, pre, _, key_id, public_key = _observation_pair()
    missing_post = _request(command=command, pre=pre, post=None)
    missing_post["observer_key_id"] = key_id
    missing_post["observer_public_key_b64"] = public_key
    indeterminate = evaluate_request(missing_post, _fixture())
    assert indeterminate["status"] == "indeterminate"
    assert indeterminate["reasons"] == ["post_observation_unavailable"]
    assert verify_report(indeterminate)

    malformed = evaluate_material(
        b'{"schema_version":"one","schema_version":"two"}',
        FIXTURE_PATH.read_bytes(),
    )
    assert malformed["status"] == "input_rejected"
    assert verify_report(malformed)


def test_observation_signature_and_fixture_integrity_fail_closed() -> None:
    request = _request()
    request["post_observation"]["signature"] = "tampered"
    invalid_observation = evaluate_request(request, _fixture())
    assert invalid_observation["status"] == "input_rejected"
    assert invalid_observation["reasons"] == ["post_observation_signature_invalid"]

    fixture = _fixture()
    fixture["loads"][0]["p_mw"] = "999"
    invalid_fixture = evaluate_request(_request(), fixture)
    assert invalid_fixture["status"] == "input_rejected"
    assert invalid_fixture["reasons"] == ["fixture_digest_mismatch"]


def test_report_signature_detects_mutation() -> None:
    report = evaluate_request(_request(), _fixture())
    assert verify_report(report)
    changed = deepcopy(report)
    changed["status"] = "contradict"
    assert not verify_report(changed)


def test_wire_contract_is_accepted_by_main_package_models() -> None:
    request_value = _request()
    request = IndependentEvaluationRequest.model_validate(request_value)
    report = IndependentConsequenceReport.model_validate(
        evaluate_request(request_value, _fixture())
    )

    assert request.verify_observation_signatures()
    assert report.verify_for_request(request)


def test_file_cli_runs_in_a_separate_process_and_writes_exclusively(tmp_path: Path) -> None:
    request_path = tmp_path / "request.json"
    fixture_path = tmp_path / "fixture.json"
    output_path = tmp_path / "report.json"
    request_path.write_bytes(canonical_json_bytes(_request()))
    fixture_path.write_bytes(FIXTURE_PATH.read_bytes())
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")

    completed = subprocess.run(  # noqa: S603 - fixed interpreter/module; paths are test-owned
        [
            sys.executable,
            "-m",
            "aegis_ot_independent",
            "--request",
            str(request_path),
            "--fixture",
            str(fixture_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = strict_json_loads(output_path.read_bytes())
    assert report["status"] == "agree"
    assert report["pid"] != os.getpid()
    assert verify_report(report)
    assert output_path.stat().st_mode & 0o777 == 0o600

    repeated = subprocess.run(  # noqa: S603 - fixed interpreter/module; paths are test-owned
        [
            sys.executable,
            "-m",
            "aegis_ot_independent",
            "--request",
            str(request_path),
            "--fixture",
            str(fixture_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert repeated.returncode == 3
    assert "File exists" in repeated.stdout


def test_request_and_fixture_json_are_strict_and_canonicalizable() -> None:
    request = _request()
    decoded = strict_json_loads(canonical_json_bytes(request))
    assert decoded == request
    fixture = _fixture()
    assert json.loads(canonical_json_bytes(fixture)) == fixture
