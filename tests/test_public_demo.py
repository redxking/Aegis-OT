from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError

from aegis_ot.api import app, public_app
from aegis_ot.public_demo import PublicDemoEvidence, load_public_demo_evidence

ROOT = Path(__file__).resolve().parents[1]
_BUILDER_SPEC = spec_from_file_location(
    "aegis_ot_test_build_public_demo",
    ROOT / "scripts" / "build_public_demo.py",
)
if _BUILDER_SPEC is None or _BUILDER_SPEC.loader is None:
    raise RuntimeError("public-demo builder could not be loaded")
demo_builder = module_from_spec(_BUILDER_SPEC)
_BUILDER_SPEC.loader.exec_module(demo_builder)
EXPECTED_M2_OUTCOME = "b5ad54a6984f659f961975adaf386eade41f733307c289ea7c3ecaa11c6b5b90"
EXPECTED_M3_OUTCOME = "150b32da0055da6086a8f858f8dab4425d06b5bfd836ba653a10c1f20adf9005"
M2_EXECUTION_COMMIT = "cd20986ac31eb224d6678875e63f8e8a907d1b76"
M2_RETENTION_COMMIT = "bc6130f150b4ebc9ac944433b67aa8dfdee78dfb"
M3_EXECUTION_COMMIT = "168b8bd61a13f70e0871d36e56acbe76a8ebb659"
M3_RETENTION_COMMIT = "0c48c39ae5eb575791e2bf58bfa49a8d61538524"
M3_INTERNAL_CHECKS = (
    "manifest",
    "artifact_hashes",
    "record_counts",
    "event_chains",
    "trial_semantics",
    "deterministic_outcome",
    "summary",
    "configuration_bindings",
)


def _mutable_evidence_payload() -> dict[str, Any]:
    return copy.deepcopy(load_public_demo_evidence().model_dump(mode="python"))


def test_demo_root_redirects_to_read_only_explorer() -> None:
    response = TestClient(public_app).get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/demo"
    assert response.headers["x-frame-options"] == "DENY"


def test_public_app_route_set_contains_only_safe_reads() -> None:
    methods = {
        method
        for route in public_app.routes
        for method in (getattr(route, "methods", None) or set())
    }
    assert methods <= {"GET", "HEAD"}


def test_compose_entrypoint_resolves_to_the_read_only_public_app() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    gateway = compose["services"]["gateway"]

    assert app is public_app
    assert gateway["command"] == [
        "uvicorn",
        "aegis_ot.api:app",
        "--host",
        "0.0.0.0",  # noqa: S104 - exact container entrypoint regression check
        "--port",
        "8080",
    ]
    assert gateway["build"]["context"] == "."
    assert gateway["build"]["args"]["PYTHON_IMAGE"].startswith(
        "${PYTHON_IMAGE:-python:3.13.7-slim@sha256:"
    )


def test_public_app_does_not_mount_mutable_decision_surface() -> None:
    client = TestClient(public_app)
    response = client.post("/v1/decisions", json={"proposal": {}, "state": {}})
    health = client.get("/health")
    schema = client.get("/openapi.json").json()

    assert response.status_code == 404
    assert health.headers["cache-control"] == "no-store"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert "/v1/decisions" not in schema["paths"]
    assert "/v1/state" not in schema["paths"]
    assert set(schema["paths"]) == {"/health", "/v1/demo/evidence"}


def test_demo_page_is_self_contained_and_explicitly_non_operational() -> None:
    response = TestClient(public_app).get("/demo")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in response.headers["content-security-policy"]
    assert "Evidence-backed research demonstration" in response.text
    assert "This page does not issue control commands" in response.text
    assert "Angelis Pseftis" in response.text
    assert "https://" not in response.text


def test_demo_assets_are_allowlisted_and_do_not_call_control_api() -> None:
    client = TestClient(public_app)
    css = client.get("/demo/app.css")
    javascript = client.get("/demo/app.js")
    missing = client.get("/demo/not-registered.svg")

    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert javascript.status_code == 200
    assert javascript.headers["content-type"].startswith("text/javascript")
    assert javascript.headers["x-content-type-options"] == "nosniff"
    assert "/v1/demo/evidence" in javascript.text
    assert "/v1/decisions" not in javascript.text
    assert "/v1/state" not in javascript.text
    assert "innerHTML" not in javascript.text
    assert 'evidence.schema_version !== "public-demo-v2"' in javascript.text
    assert "tampered:" in javascript.text
    assert "metric.numerator" in javascript.text
    assert "metric.wilson_ci95.lower" in javascript.text
    assert "metrics.false_block" in javascript.text
    assert "progress.max = 1" in javascript.text
    assert "estimate_pct" not in javascript.text
    assert "unsafe_escape_pct" not in javascript.text
    assert "Demo service reachable" in javascript.text
    assert "fetchJsonWithRetry" in javascript.text
    assert 'fetchJsonWithRetry("/v1/demo/evidence")' in javascript.text
    assert "const REQUEST_TIMEOUT_MS = 5000" in javascript.text
    assert "new AbortController()" in javascript.text
    assert "signal: controller.signal" in javascript.text
    assert "window.clearTimeout(timeout)" in javascript.text
    for key in ("ArrowRight", "ArrowLeft", "Home", "End"):
        assert key in javascript.text
    assert missing.status_code == 404


def test_packaged_demo_evidence_retains_claim_boundaries() -> None:
    response = TestClient(public_app).get("/v1/demo/evidence")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    evidence = PublicDemoEvidence.model_validate_json(response.text)

    assert evidence.schema_version == "public-demo-v2"
    assert evidence.project.mode == "synthetic-local"
    assert "issues no control commands" in evidence.project.claim_boundary
    assert "independent replication" in evidence.project.claim_boundary
    assert evidence.m2.trial_records == 8_640
    assert evidence.m2.master_seed_count == 30
    assert evidence.m2.deterministic_outcome_sha256 == EXPECTED_M2_OUTCOME
    assert evidence.m3.sessions == 30
    assert evidence.m3.trial_records == 150
    assert evidence.m3.evidence_events == 270
    assert evidence.m3.deterministic_outcome_sha256 == EXPECTED_M3_OUTCOME
    assert evidence.m3.reproduction_experiment_id != evidence.m3.experiment_id
    assert len(evidence.next_gates) == 6


def test_demo_conditions_and_negative_m2_finding_are_not_sanitized() -> None:
    evidence = load_public_demo_evidence()
    conditions = {item.condition_id: item for item in evidence.m3.conditions}
    baselines = {item.baseline_id: item for item in evidence.m2.baselines}

    assert conditions["nominal_permitted_execution"].modeled_effects == 30
    assert conditions["nominal_permitted_execution"].device_applied == 30
    assert sum(item.modeled_effects for item in conditions.values()) == 30
    assert all(item.unknown_effects == 0 for item in conditions.values())
    tampered = conditions["wrong_audience_permit"]
    assert tampered.label == "Tampered permit audience"
    assert tampered.path == (
        "pass",
        "pass",
        "pass",
        "pass",
        "tampered",
        "deny",
        "no_effect",
    )
    assert "returned permit_wrong_audience" in tampered.evidence_note
    assert "also invalidated the signature" in tampered.evidence_note
    assert "validly signed wrong-audience case was not exercised" in tampered.evidence_note
    assert "device audience validation" in tampered.disposition
    assert "audience validation succeeded" not in tampered.evidence_note

    b3 = baselines["B3_ASSURED"]
    assert b3.display_id == "B3"
    assert b3.trials == 1_080
    assert b3.metrics.model_dump(mode="json") == {
        "unsafe_action_escape": {
            "numerator": 270,
            "denominator": 450,
            "estimate": 0.6,
            "wilson_ci95": {
                "method": "wilson-score",
                "confidence_level": 0.95,
                "lower": 0.5540741606857974,
                "upper": 0.6442329755416084,
            },
        },
        "unauthorized_execution": {
            "numerator": 0,
            "denominator": 450,
            "estimate": 0.0,
            "wilson_ci95": {
                "method": "wilson-score",
                "confidence_level": 0.95,
                "lower": 0.0,
                "upper": 0.008464318862970662,
            },
        },
        "false_block": {
            "numerator": 0,
            "denominator": 180,
            "estimate": 0.0,
            "wilson_ci95": {
                "method": "wilson-score",
                "confidence_level": 0.95,
                "lower": 0.0,
                "upper": 0.02089549792161305,
            },
        },
        "mission_success": {
            "numerator": 810,
            "denominator": 1_080,
            "estimate": 0.75,
            "wilson_ci95": {
                "method": "wilson-score",
                "confidence_level": 0.95,
                "lower": 0.7233197145385128,
                "upper": 0.7749081356745275,
            },
        },
    }
    assert b3.metrics.unsafe_action_escape.denominator != b3.trials
    assert b3.metrics.unauthorized_execution.denominator != b3.trials
    assert b3.metrics.false_block.denominator != b3.trials
    assert "60 percent" in evidence.m2.finding


def test_demo_provenance_distinguishes_execution_retention_and_internal_checks() -> None:
    evidence = load_public_demo_evidence()

    assert evidence.m2.evidence_commit == M2_EXECUTION_COMMIT
    assert evidence.m2.retention_commit == M2_RETENTION_COMMIT
    assert evidence.m2.recorded_commit_bound is True
    assert evidence.m2.raw_trials_sha256 == (
        "7426b3ae83aa790f7416262fc7b7a3331704d2632d10e8134921e7fb92cdcb22"
    )
    assert evidence.m3.evidence_commit == M3_EXECUTION_COMMIT
    assert evidence.m3.retention_commit == M3_RETENTION_COMMIT
    assert evidence.m3.verification.internal_checks == M3_INTERNAL_CHECKS
    assert evidence.m3.verification.primary_internal_checks_passed is True
    assert evidence.m3.verification.reproduction_internal_checks_passed is True
    assert evidence.m3.verification.recorded_commit_bound is True
    assert evidence.m3.verification.current_checkout_binding_status == "mismatch"
    assert "not external custody" in evidence.m3.verification.boundary
    assert "independent replication" in evidence.m3.verification.boundary

    assert tuple(source.path for source in evidence.generated_from) == (
        "results/m2-independent-oracle/manifest.json",
        "results/m2-independent-oracle/trials.jsonl",
        "results/m3-physical-modbus/manifest.json",
        "results/m3-physical-modbus/summary.json",
        "results/m3-physical-modbus-reproduction/manifest.json",
    )


def test_demo_source_hashes_bind_to_retained_artifacts() -> None:
    evidence = load_public_demo_evidence()
    for source in evidence.generated_from:
        source_path = ROOT / source.path
        assert source_path.is_file()
        assert hashlib.sha256(source_path.read_bytes()).hexdigest() == source.sha256


def test_m2_package_bytes_match_registered_retention_commit() -> None:
    demo_builder._bind_directory_to_retention_commit(
        demo_builder.M2_RETENTION_COMMIT,
        demo_builder.M2_PACKAGE_DIR,
    )


def test_binomial_model_rejects_numerator_greater_than_denominator() -> None:
    payload = _mutable_evidence_payload()
    metric = payload["m2"]["baselines"][3]["metrics"]["unsafe_action_escape"]
    metric["numerator"] = metric["denominator"] + 1

    with pytest.raises(ValidationError, match="numerator exceeds denominator"):
        PublicDemoEvidence.model_validate(payload)


def test_binomial_model_rejects_estimate_detached_from_counts() -> None:
    payload = _mutable_evidence_payload()
    payload["m2"]["baselines"][3]["metrics"]["unsafe_action_escape"]["estimate"] = 0.61

    with pytest.raises(ValidationError, match="estimate differs"):
        PublicDemoEvidence.model_validate(payload)


def test_binomial_model_rejects_reversed_or_mismatched_wilson_interval() -> None:
    payload = _mutable_evidence_payload()
    interval = payload["m2"]["baselines"][3]["metrics"]["unsafe_action_escape"][
        "wilson_ci95"
    ]
    interval["lower"] = 0.7
    interval["upper"] = 0.6

    with pytest.raises(ValidationError, match="Wilson interval is inconsistent"):
        PublicDemoEvidence.model_validate(payload)


def test_condition_model_rejects_counts_above_registered_trials() -> None:
    payload = _mutable_evidence_payload()
    condition = payload["m3"]["conditions"][0]
    condition["modeled_effects"] = condition["trials"] + 1

    with pytest.raises(ValidationError, match="condition count exceeds condition trials"):
        PublicDemoEvidence.model_validate(payload)


def test_m3_metrics_remain_bound_to_condition_counts() -> None:
    nominal_payload = _mutable_evidence_payload()
    nominal_payload["m3"]["conditions"][3]["terminal_completions"] = 29
    with pytest.raises(ValidationError, match="nominal-completion metric differs"):
        PublicDemoEvidence.model_validate(nominal_payload)

    trace_payload = _mutable_evidence_payload()
    trace_payload["m3"]["conditions"][0]["trace_complete"] = 29
    with pytest.raises(ValidationError, match="trace-completeness metric differs"):
        PublicDemoEvidence.model_validate(trace_payload)


def test_public_model_rejects_duplicate_condition_and_source_identifiers() -> None:
    condition_payload = _mutable_evidence_payload()
    condition_payload["m3"]["conditions"][1]["condition_id"] = condition_payload["m3"][
        "conditions"
    ][0]["condition_id"]
    with pytest.raises(ValidationError, match="conditions differ from the registered order"):
        PublicDemoEvidence.model_validate(condition_payload)

    source_payload = _mutable_evidence_payload()
    source_payload["generated_from"][1]["path"] = source_payload["generated_from"][0]["path"]
    with pytest.raises(
        ValidationError,
        match="source paths differ from the registered evidence set",
    ):
        PublicDemoEvidence.model_validate(source_payload)


def test_builder_rejects_tampered_m2_raw_trials(tmp_path: Path, monkeypatch: Any) -> None:
    copied_package = tmp_path / "m2-independent-oracle"
    shutil.copytree(demo_builder.M2_PACKAGE_DIR, copied_package)
    copied_manifest = copied_package / "manifest.json"
    copied_trials = copied_package / "trials.jsonl"
    copied_trials.write_bytes(copied_trials.read_bytes() + b" ")

    monkeypatch.setattr(demo_builder, "M2_PACKAGE_DIR", copied_package)
    monkeypatch.setattr(demo_builder, "M2_MANIFEST_PATH", copied_manifest)
    monkeypatch.setattr(demo_builder, "M2_TRIALS_PATH", copied_trials)

    with pytest.raises(ValueError, match="raw trial hash differs"):
        demo_builder._validate_m2_package(demo_builder._load_json(copied_manifest))


@pytest.mark.parametrize(
    ("checkout_binding", "expected_status"),
    ((True, "match"), (False, "mismatch")),
)
def test_builder_derives_current_checkout_status_from_verifier(
    checkout_binding: bool,
    expected_status: str,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    manifest = {
        "session_count": 1,
        "trial_record_count": 5,
        "event_record_count": 9,
        "deterministic_outcome_sha256": "1" * 64,
    }
    report = {
        "checks": {
            **{name: True for name in M3_INTERNAL_CHECKS},
            "checkout_bindings": checkout_binding,
        },
        "errors": (
            []
            if checkout_binding
            else ["checkout_bindings: current checkout differs from recorded evidence"]
        ),
        **manifest,
    }
    monkeypatch.setattr(demo_builder, "verify_m3_package", lambda _package: report)
    monkeypatch.setattr(demo_builder, "_bind_m3_execution_commit", lambda _manifest: None)

    checks, status = demo_builder._validate_m3_report(tmp_path, manifest)

    assert checks == M3_INTERNAL_CHECKS
    assert status == expected_status


@pytest.mark.parametrize(
    "package_name",
    ("m3-physical-modbus", "m3-physical-modbus-reproduction"),
)
def test_builder_rejects_tampered_m3_package(package_name: str, tmp_path: Path) -> None:
    source_package = ROOT / "results" / package_name
    copied_package = tmp_path / package_name
    shutil.copytree(source_package, copied_package)
    events = copied_package / "events.jsonl"
    events.write_bytes(events.read_bytes() + b"\n")

    manifest = demo_builder._load_json(copied_package / "manifest.json")
    with pytest.raises(ValueError, match="M3 internal package verification failed"):
        demo_builder._validate_m3_report(copied_package, manifest)


def test_builder_rejects_reproduction_drift_on_registered_field() -> None:
    primary = demo_builder._load_json(demo_builder.M3_MANIFEST_PATH)
    reproduction = demo_builder._load_json(demo_builder.M3_REPRODUCTION_MANIFEST_PATH)
    demo_builder._validate_m3_pair(primary, reproduction)

    reproduction["model_digest"] = "0" * 64
    with pytest.raises(ValueError, match="registered field: model_digest"):
        demo_builder._validate_m3_pair(primary, reproduction)


def test_packaged_demo_evidence_is_current() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/build_public_demo.py", "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout

    report_source = (ROOT / "scripts" / "build_research_doc.py").read_text(
        encoding="utf-8"
    )
    figure_source = (ROOT / "scripts" / "build_figures.py").read_text(encoding="utf-8")
    revision_log = json.loads(
        (ROOT / "research" / "revision_log.json").read_text(encoding="utf-8")
    )
    report_paths = tuple(
        (ROOT / "research").glob("Aegis-OT_Research_Study*.docx")
    )

    assert len(report_paths) == 1
    with zipfile.ZipFile(report_paths[0]) as package:
        names = package.namelist()
        assert "docProps/custom.xml" not in names
        document_xml = ElementTree.fromstring(  # noqa: S314 - controlled DOCX
            package.read("word/document.xml")
        )
        core_properties = ElementTree.fromstring(  # noqa: S314 - controlled DOCX
            package.read("docProps/core.xml")
        )
        app_properties = ElementTree.fromstring(  # noqa: S314 - controlled DOCX
            package.read("docProps/app.xml")
        )
    report_text = "\n".join(document_xml.itertext())
    assert "audience is altered after signing" in report_text
    assert "invalidates the permit's original signature" in report_text
    assert "validly signed wrong-audience permit" in report_text
    assert "Wrong-audience permit" not in report_text
    assert "wrong permit audience" not in report_text
    assert "passed 478 tests" in report_text
    assert "strict mypy" in report_text
    assert "92.05 percent branch-aware coverage" in report_text
    assert "M4a currently has no equivalent retained package" in report_text
    assert "not a continuous global observation chain" in report_text
    assert "controller has no plant-apply handle" in report_text
    assert "289 passing tests" not in report_text
    assert "264 passing tests" not in report_text
    assert "91.57 percent" not in report_text
    assert '"wrong_audience_permit": "Audience altered post-signing"' in report_source
    assert '"wrong_audience_permit": "Audience altered post-signing"' in figure_source

    assert revision_log["author"] == "Angelis Pseftis"
    assert revision_log["editor"] == "Angelis Pseftis"
    assert len(revision_log["revisions"]) == 7
    assert {revision["editor"] for revision in revision_log["revisions"]} == {
        "Angelis Pseftis"
    }
    current_revision = revision_log["revisions"][-1]
    assert current_revision["revision"] == "0.7"
    assert current_revision["git_commit"] == (
        "e323bbf113bfebd301c60a92fc246ae3b0126ce5"
    )
    core_namespace = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    dc_namespace = "http://purl.org/dc/elements/1.1/"
    assert core_properties.findtext(f"{{{dc_namespace}}}creator") == "Angelis Pseftis"
    assert (
        core_properties.findtext(f"{{{core_namespace}}}lastModifiedBy")
        == "Angelis Pseftis"
    )
    core_revision = core_properties.findtext(f"{{{core_namespace}}}revision")
    assert core_revision is not None
    assert int(core_revision) >= len(revision_log["revisions"])

    app_namespace = (
        "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
    )
    pages = app_properties.find(f"{{{app_namespace}}}Pages")
    assert pages is not None
    # The revision log preserves the page count observed when that revision was
    # recorded; later in-place Word saves may repaginate the same document.
    assert int(pages.text or "0") > 0
