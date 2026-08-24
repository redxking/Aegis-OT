from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from aegis_ot import m3_experiment as m3


@pytest.fixture(scope="module")
def retained_m3_package(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create one real retained-evidence package for all verifier cases."""

    output_dir = tmp_path_factory.mktemp("m3-verifier-package")
    manifest = m3.write_m3_experiment(output_dir, (0x4D33,))
    assert manifest["session_count"] == 1
    assert manifest["trial_record_count"] == len(m3.CONDITION_ORDER)
    return output_dir


@pytest.fixture(scope="module")
def retained_two_session_m3_package(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create a real two-session package for cross-session binding cases."""

    output_dir = tmp_path_factory.mktemp("m3-verifier-two-session-package")
    manifest = m3.write_m3_experiment(output_dir, (0x4D33, 0x4D34))
    assert manifest["session_count"] == 2
    assert manifest["trial_record_count"] == 2 * len(m3.CONDITION_ORDER)
    return output_dir


def _clone_package(source: Path, tmp_path: Path) -> Path:
    destination = tmp_path / "m3-package"
    shutil.copytree(source, destination)
    return destination


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(m3._jsonl_text(records), encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(m3._json_text(value), encoding="utf-8")


def _refresh_artifact_hash(package: Path, relative_path: str) -> None:
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["artifact_sha256"][relative_path] = hashlib.sha256(
        (package / relative_path).read_bytes()
    ).hexdigest()
    _write_json(manifest_path, manifest)


def _refresh_physical_state_digests(state: dict[str, Any]) -> None:
    state["state_digest"] = "0" * 64
    state["observation_digest"] = "0" * 64
    snapshot = m3.PhysicalStateSnapshot.model_validate(state)
    state["state_digest"] = m3.canonical_digest(snapshot.digest_material())
    snapshot = m3.PhysicalStateSnapshot.model_validate(state)
    state["observation_digest"] = m3.canonical_digest(snapshot.observation_material())


def _correlate_denied_decision_payloads(
    trials: list[dict[str, Any]],
    events: list[dict[str, Any]],
    *,
    condition: str,
) -> None:
    """Mirror a denied decision mutation into both retained evidence payloads."""

    trial = next(item for item in trials if item["condition"] == condition)
    decision = trial["artifacts"]["decision"]
    decision_event = next(
        event
        for event in events
        if event["record"]["record_hash"] == decision["evidence_record_hash"]
    )
    terminal_event = next(
        event
        for event in events
        if event["record"]["record_hash"] == trial["artifacts"]["execution_evidence_hash"]
    )
    decision_event["record"]["payload"]["decision"] = {
        **copy.deepcopy(decision),
        "evidence_record_hash": None,
    }
    terminal_event["record"]["payload"]["decision"] = copy.deepcopy(decision)
    terminal_event["record"]["payload"]["reasons"] = copy.deepcopy(trial["reasons"])


def _assert_invalid(result: dict[str, Any], *error_terms: str) -> None:
    assert result["valid"] is False
    assert result["errors"]
    assert result["checks"]
    assert any(value is False for value in result["checks"].values())
    errors = " ".join(str(error) for error in result["errors"]).lower()
    assert any(term in errors for term in error_terms), errors


def _assert_check_failed(
    result: dict[str, Any],
    check: str,
    *error_terms: str,
) -> None:
    _assert_invalid(result, *error_terms)
    assert result["checks"][check] is False


def test_verify_m3_package_accepts_fresh_retained_evidence(
    retained_m3_package: Path,
) -> None:
    result = m3.verify_m3_package(retained_m3_package)

    assert result["valid"] is True
    assert result["errors"] == []
    assert result["checks"]
    assert all(result["checks"].values())


def test_verify_m3_package_detects_tampered_trial_content(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    trials = _read_jsonl(trials_path)
    trials[0]["reasons"].append("injected-tamper-marker")
    _write_jsonl(trials_path, trials)

    result = m3.verify_m3_package(package)

    _assert_invalid(result, "artifact", "sha256", "hash")


def test_verify_m3_package_detects_rehashed_event_payload_tamper(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    events_path = package / "events.jsonl"
    events = _read_jsonl(events_path)
    events[0]["record"]["payload"]["injected_tamper_marker"] = True
    _write_jsonl(events_path, events)
    _refresh_artifact_hash(package, "events.jsonl")

    result = m3.verify_m3_package(package)

    _assert_invalid(result, "event", "evidence", "chain", "record")


@pytest.mark.parametrize(
    "mutation",
    ("string-session-index", "fractional-master-seed", "boolean-sequence"),
)
def test_verify_m3_package_rejects_noninteger_outer_event_metadata(
    retained_m3_package: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    events_path = package / "events.jsonl"
    events = _read_jsonl(events_path)
    first_event = events[0]
    if mutation == "string-session-index":
        first_event["session_index"] = str(first_event["session_index"])
    elif mutation == "fractional-master-seed":
        first_event["master_seed"] = float(first_event["master_seed"]) + 0.5
    else:
        assert first_event["sequence"] == 0
        first_event["sequence"] = False
    _write_jsonl(events_path, events)
    _refresh_artifact_hash(package, "events.jsonl")

    result = m3.verify_m3_package(package)

    assert result["checks"]["artifact_hashes"] is True
    _assert_check_failed(result, "event_chains", "event", "outer", "integer")


@pytest.mark.parametrize(
    "mutation",
    ("string-inner-sequence", "extra-inner-field", "extra-outer-field"),
)
def test_verify_m3_package_rejects_noncanonical_event_record_shapes(
    retained_m3_package: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    events_path = package / "events.jsonl"
    events = _read_jsonl(events_path)
    first_event = events[0]
    if mutation == "string-inner-sequence":
        first_event["record"]["sequence"] = str(first_event["record"]["sequence"])
    elif mutation == "extra-inner-field":
        first_event["record"]["external_validation"] = "passed"
    else:
        first_event["production_ready"] = True
    _write_jsonl(events_path, events)
    _refresh_artifact_hash(package, "events.jsonl")

    result = m3.verify_m3_package(package)

    assert result["checks"]["artifact_hashes"] is True
    _assert_check_failed(result, "event_chains", "event", "record", "field", "shape")


def test_verify_m3_package_rejects_extra_trial_claim(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    trials = _read_jsonl(trials_path)
    trials[0]["production_ready"] = True
    _write_jsonl(trials_path, trials)
    _refresh_artifact_hash(package, "trials.jsonl")

    result = m3.verify_m3_package(package)

    assert result["checks"]["artifact_hashes"] is True
    _assert_check_failed(result, "trial_semantics", "trial", "field", "shape")


def test_verify_m3_package_detects_tampered_manifest_artifact_hash(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_sha256"]["trials.jsonl"] = "0" * 64
    manifest_path.write_text(m3._json_text(manifest), encoding="utf-8")

    result = m3.verify_m3_package(package)

    _assert_invalid(result, "artifact", "sha256", "hash")


def test_verify_m3_package_detects_rehashed_invalid_acknowledgment_signature(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    component_health = json.loads((package / "component-health.json").read_text(encoding="utf-8"))
    session = component_health["sessions"][0]
    assert session["permit_public_key_b64"]
    assert session["process"]["device_public_key_b64"]

    trials_path = package / "trials.jsonl"
    trials = _read_jsonl(trials_path)
    nominal = next(trial for trial in trials if trial["condition"] == "nominal_permitted_execution")
    acknowledgment = nominal["artifacts"]["acknowledgment"]
    assert acknowledgment is not None and acknowledgment["signature"]
    acknowledgment["signature"] = base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii")
    _write_jsonl(trials_path, trials)
    _refresh_artifact_hash(package, "trials.jsonl")

    result = m3.verify_m3_package(package)

    _assert_invalid(result, "acknowledgment", "signature")


@pytest.mark.parametrize("key_kind", ("permit", "device"))
def test_verify_m3_package_rejects_noncanonical_public_key_encoding(
    retained_m3_package: Path,
    tmp_path: Path,
    key_kind: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    session = component_health["sessions"][0]
    if key_kind == "permit":
        session["permit_public_key_b64"] = f" {session['permit_public_key_b64']}"
    else:
        process = session["process"]
        process["device_public_key_b64"] = f"{process['device_public_key_b64']}!!!!"
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "key", "metadata", "encoding")


def test_verify_m3_package_rejects_noncanonical_acknowledgment_signature_encoding(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    events_path = package / "events.jsonl"
    trials = _read_jsonl(trials_path)
    events = _read_jsonl(events_path)
    nominal = next(trial for trial in trials if trial["condition"] == "nominal_permitted_execution")
    acknowledgment = nominal["artifacts"]["acknowledgment"]
    acknowledgment["signature"] = f"{acknowledgment['signature']}!!!!"
    terminal_event = next(
        event
        for event in events
        if event["record"]["record_hash"] == nominal["artifacts"]["execution_evidence_hash"]
    )
    terminal_event["record"]["payload"]["acknowledgment"]["signature"] = acknowledgment["signature"]
    _write_jsonl(trials_path, trials)
    _write_jsonl(events_path, events)
    _refresh_artifact_hash(package, "trials.jsonl")
    _refresh_artifact_hash(package, "events.jsonl")

    result = m3.verify_m3_package(package)

    assert result["checks"]["event_chains"] is False
    _assert_check_failed(result, "trial_semantics", "acknowledgment", "signature", "encoding")


def test_verify_m3_package_rejects_missing_manifest(tmp_path: Path) -> None:
    result = m3.verify_m3_package(tmp_path / "missing-package")

    _assert_check_failed(result, "manifest", "manifest", "read")


@pytest.mark.parametrize("manifest_text", ("[]\n", "{not-json\n"))
def test_verify_m3_package_rejects_unreadable_or_nonobject_manifest(
    retained_m3_package: Path,
    tmp_path: Path,
    manifest_text: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    (package / "manifest.json").write_text(manifest_text, encoding="utf-8")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "manifest", "manifest", "json", "object")


def test_verify_m3_package_rejects_unsupported_versions(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["experiment_version"] = "m3-unsupported"
    manifest["outcome_projection_version"] = "projection-unsupported"
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "manifest", "version", "unsupported")


def test_verify_m3_package_rejects_missing_required_artifact_hash(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    del manifest["artifact_sha256"]["trials.jsonl"]
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "artifact_hashes", "artifact", "missing")


def test_verify_m3_package_rejects_unsafe_manifest_artifact_path(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["artifact_sha256"]["../outside-package"] = "0" * 64
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "artifact_hashes", "artifact", "unsafe", "verified")


@pytest.mark.parametrize("suffix", ("\n", "[]\n"))
def test_verify_m3_package_rejects_malformed_jsonl_records(
    retained_m3_package: Path,
    tmp_path: Path,
    suffix: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    trials_path.write_text(
        trials_path.read_text(encoding="utf-8") + suffix,
        encoding="utf-8",
    )
    _refresh_artifact_hash(package, "trials.jsonl")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "manifest", "parse", "json", "record", "retained")


def test_verify_m3_package_rejects_invalid_manifest_record_metadata(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["trial_record_count"] = -1
    manifest["master_seeds"] = ["not-an-integer"]
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "count", "seed", "session")


@pytest.mark.parametrize(
    "field",
    (
        "master_seed_count",
        "session_count",
        "conditions_per_session",
        "trial_record_count",
        "event_record_count",
    ),
)
def test_verify_m3_package_rejects_noninteger_manifest_counts(
    retained_m3_package: Path,
    tmp_path: Path,
    field: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    value = manifest[field]
    manifest[field] = True if value == 1 else float(value)
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "count", "integer", "metadata")


def test_verify_m3_package_rejects_noninteger_individual_seed_copy(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["individual_seeds"] = [float(seed) for seed in manifest["master_seeds"]]
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "seed", "integer", "metadata")


def test_verify_m3_package_rejects_duplicate_master_seeds(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    seed = manifest["master_seeds"][0]
    manifest["master_seeds"] = [seed, seed]
    manifest["individual_seeds"] = [seed, seed]
    manifest["master_seed_count"] = 2
    manifest["session_count"] = 2
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "master", "seed", "invalid", "unique")


def test_write_m3_experiment_rejects_duplicate_master_seeds(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unique"):
        m3.write_m3_experiment(tmp_path / "duplicate-seeds", (101, 101))


def test_verify_m3_package_enforces_session_limit(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    seeds = list(range(m3.MAX_M3_SESSIONS + 1))
    manifest["master_seeds"] = seeds
    manifest["individual_seeds"] = copy.deepcopy(seeds)
    manifest["master_seed_count"] = len(seeds)
    manifest["session_count"] = len(seeds)
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "seed", "session", "invalid", "limit")


@pytest.mark.parametrize(
    "mutation",
    ("reversed-timestamps", "fabricated-id", "git-type", "host-type", "extra-field"),
)
def test_verify_m3_package_rejects_invalid_manifest_provenance_shape(
    retained_m3_package: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    if mutation == "reversed-timestamps":
        manifest["started_at_utc"] = "2999-01-01T00:00:00+00:00"
        manifest["completed_at_utc"] = "1900-01-01T00:00:00+00:00"
    elif mutation == "fabricated-id":
        manifest["experiment_id"] = f"{m3.EXPERIMENT_VERSION}-fabricated"
    elif mutation == "git-type":
        manifest["git"]["working_tree_dirty_at_start"] = "false"
    elif mutation == "host-type":
        manifest["host"]["logical_cpu_count"] = True
    else:
        manifest["external_validation"] = "passed"
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "manifest", "manifest", "timestamp", "field", "type")


def test_verify_m3_package_rejects_extra_manifest_artifact(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    extra_path = package / "unregistered-claim.json"
    extra_path.write_text('{"production_ready":true}\n', encoding="utf-8")
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["artifact_sha256"][extra_path.name] = hashlib.sha256(
        extra_path.read_bytes()
    ).hexdigest()
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "artifact_hashes", "artifact", "extra", "registered")


def test_verify_m3_package_does_not_open_unregistered_artifact_paths(
    retained_m3_package: Path,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["artifact_sha256"]["attacker-controlled-path"] = "0" * 64
    _write_json(manifest_path, manifest)
    opened_paths: list[str] = []
    original_read = m3._read_package_bytes

    def tracked_read(
        output_dir: Path,
        relative_path: str,
        *,
        maximum_bytes: int = m3.MAX_PACKAGE_FILE_BYTES,
    ) -> bytes:
        opened_paths.append(relative_path)
        return original_read(output_dir, relative_path, maximum_bytes=maximum_bytes)

    monkeypatch.setattr(m3, "_read_package_bytes", tracked_read)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "artifact_hashes", "artifact", "registered", "path")
    assert "attacker-controlled-path" not in opened_paths


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO support")
def test_verify_m3_package_rejects_nonregular_required_artifact(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    summary_path = package / "summary.json"
    summary_path.unlink()
    os.mkfifo(summary_path)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "artifact_hashes", "regular", "artifact")


def test_verify_m3_package_rejects_oversized_required_artifact(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    summary_path = package / "summary.json"
    with summary_path.open("wb") as handle:
        handle.truncate(m3.MAX_PACKAGE_FILE_BYTES + 1)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "artifact_hashes", "byte", "limit", "artifact")


def test_verify_m3_package_enforces_aggregate_artifact_limit(
    retained_m3_package: Path,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    monkeypatch.setattr(m3, "MAX_PACKAGE_TOTAL_BYTES", 1)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "artifact_hashes", "aggregate", "limit", "package")


def test_verify_m3_package_enforces_jsonl_record_limit(
    retained_m3_package: Path,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    monkeypatch.setattr(m3, "MAX_JSONL_RECORDS", 1)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "manifest", "record", "limit", "parse")


def test_verify_m3_package_caps_reported_errors(
    retained_m3_package: Path,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    events_path = package / "events.jsonl"
    events = _read_jsonl(events_path)
    for event in events:
        event["unknown_field"] = True
    _write_jsonl(events_path, events)
    _refresh_artifact_hash(package, "events.jsonl")
    monkeypatch.setattr(m3, "MAX_VERIFIER_ERRORS", 2)

    result = m3.verify_m3_package(package)

    assert result["valid"] is False
    assert len(result["errors"]) == 3
    assert result["errors"][-1].startswith("error_limit:")
    assert "additional errors omitted" in result["errors"][-1]


def test_verify_m3_package_rejects_missing_retained_session_catalogs(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    for relative_path in ("component-health.json", "evidence-verification.json"):
        artifact_path = package / relative_path
        artifact = _read_json(artifact_path)
        artifact["sessions"] = []
        _write_json(artifact_path, artifact)
        _refresh_artifact_hash(package, relative_path)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "session", "manifest")


def test_verify_m3_package_rejects_reordered_conditions(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    trials = _read_jsonl(trials_path)
    trials[0], trials[1] = trials[1], trials[0]
    _write_jsonl(trials_path, trials)
    _refresh_artifact_hash(package, "trials.jsonl")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "condition", "order")


@pytest.mark.parametrize("inconsistency", ("health", "initial-state"))
def test_verify_m3_package_rejects_component_health_inconsistency(
    retained_m3_package: Path,
    tmp_path: Path,
    inconsistency: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    session = component_health["sessions"][0]
    if inconsistency == "health":
        session["verified_health_payload"]["status"] = "not-ready"
    else:
        session["initial_state"]["state_digest"] = "0" * 64
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "process", "health", "state")


@pytest.mark.parametrize("location", ("component", "process", "health"))
def test_verify_m3_package_rejects_extra_component_metadata(
    retained_m3_package: Path,
    tmp_path: Path,
    location: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    session = component_health["sessions"][0]
    target = (
        session
        if location == "component"
        else session["verified_health_payload" if location == "health" else location]
    )
    target["external_validation"] = "passed"
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "component", "process", "health", "field")


def test_verify_m3_package_rejects_noncanonical_component_initial_state(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    initial_state = component_health["sessions"][0]["initial_state"]
    assert initial_state["simulation_time_s"] == 0.0
    initial_state["simulation_time_s"] = 0
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "initial", "state", "canonical", "type")


def test_verify_m3_package_rejects_noninteger_component_master_seed(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    session = component_health["sessions"][0]
    session["master_seed"] = float(session["master_seed"])
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "component", "seed", "integer")


@pytest.mark.parametrize(
    "mutation",
    (
        "separate-process-type",
        "pid-type",
        "non-loopback-host",
        "invalid-port",
        "protocol-value",
        "protocol-type",
    ),
)
def test_verify_m3_package_rejects_untrusted_process_metadata(
    retained_m3_package: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    session = component_health["sessions"][0]
    process = session["process"]
    if mutation == "separate-process-type":
        session["separate_process_verified"] = "false"
    elif mutation == "pid-type":
        process["pid"] = str(session["parent_pid"])
    elif mutation == "non-loopback-host":
        process["host"] = "0.0.0.0"  # noqa: S104 - intentional hostile fixture
    elif mutation == "invalid-port":
        process["port"] = 0
    elif mutation == "protocol-value":
        process["protocol_version"] = 2
        session["verified_health_payload"]["protocol_version"] = 2
    else:
        process["protocol_version"] = True
        session["verified_health_payload"]["protocol_version"] = True
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "process", "metadata", "boundary")


@pytest.mark.parametrize(
    "mutation",
    ("state-version", "policy-version", "safety-version", "reason-order"),
)
def test_verify_m3_package_rejects_inexact_denied_decision_semantics(
    retained_m3_package: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    events_path = package / "events.jsonl"
    trials = _read_jsonl(trials_path)
    events = _read_jsonl(events_path)
    trial = next(item for item in trials if item["condition"] == "unknown_identity")
    decision = trial["artifacts"]["decision"]
    if mutation == "state-version":
        decision["state_version"] += 1
    elif mutation == "policy-version":
        decision["policy_version"] = "unregistered-policy"
    elif mutation == "safety-version":
        decision["safety_version"] = "unregistered-safety-kernel"
    else:
        decision["reasons"].reverse()
        trial["reasons"] = copy.deepcopy(decision["reasons"])
        trial["artifacts"]["reasons"] = copy.deepcopy(decision["reasons"])
    _correlate_denied_decision_payloads(
        trials,
        events,
        condition="unknown_identity",
    )
    _write_jsonl(trials_path, trials)
    _write_jsonl(events_path, events)
    _refresh_artifact_hash(package, "trials.jsonl")
    _refresh_artifact_hash(package, "events.jsonl")

    result = m3.verify_m3_package(package)

    # The evidence-chain digest check also fails because this fixture deliberately
    # retains the original event identifiers. The semantic check must independently
    # reject the internally correlated but unregistered denied decision.
    assert result["checks"]["event_chains"] is False
    _assert_check_failed(
        result,
        "trial_semantics",
        "decision",
        "binding",
        "reason",
        "injection",
    )


@pytest.mark.parametrize("artifact_name", ("command", "assessment", "permit"))
def test_verify_m3_package_rejects_authorization_artifact_on_gateway_denial(
    retained_m3_package: Path,
    tmp_path: Path,
    artifact_name: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    events_path = package / "events.jsonl"
    trials = _read_jsonl(trials_path)
    events = _read_jsonl(events_path)
    denied = next(item for item in trials if item["condition"] == "unknown_identity")
    nominal = next(item for item in trials if item["condition"] == "nominal_permitted_execution")
    denied["artifacts"][artifact_name] = copy.deepcopy(nominal["artifacts"][artifact_name])
    terminal_event = next(
        event
        for event in events
        if event["record"]["record_hash"] == denied["artifacts"]["execution_evidence_hash"]
    )
    terminal_event["record"]["payload"][artifact_name] = copy.deepcopy(
        denied["artifacts"][artifact_name]
    )
    _write_jsonl(trials_path, trials)
    _write_jsonl(events_path, events)
    _refresh_artifact_hash(package, "trials.jsonl")
    _refresh_artifact_hash(package, "events.jsonl")

    result = m3.verify_m3_package(package)

    assert result["checks"]["event_chains"] is False
    _assert_check_failed(
        result,
        "trial_semantics",
        "denial",
        "artifact",
        "authorization",
    )


@pytest.mark.parametrize(
    ("artifact_name", "field"),
    (("permit", "state_version"), ("acknowledgment", "device_scan")),
)
def test_verify_m3_package_rejects_coerced_signed_artifact_types(
    retained_m3_package: Path,
    tmp_path: Path,
    artifact_name: str,
    field: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    trials = _read_jsonl(trials_path)
    nominal = next(item for item in trials if item["condition"] == "nominal_permitted_execution")
    artifact = nominal["artifacts"][artifact_name]
    artifact[field] = str(artifact[field])
    _write_jsonl(trials_path, trials)
    _refresh_artifact_hash(package, "trials.jsonl")

    result = m3.verify_m3_package(package)

    assert result["checks"]["artifact_hashes"] is True
    _assert_check_failed(result, "trial_semantics", "artifact", "type", "schema")


def test_verify_m3_package_does_not_complete_trial_semantics_without_component(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    component_health["sessions"] = []
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "component", "session")
    assert result["checks"]["trial_semantics"] is not True


def test_verify_m3_package_rejects_inconsistent_evidence_verification_counts(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    verification_path = package / "evidence-verification.json"
    verification = _read_json(verification_path)
    verification["sessions"][0]["condition_count"] += 1
    _write_json(verification_path, verification)
    _refresh_artifact_hash(package, "evidence-verification.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "verification", "count")


@pytest.mark.parametrize(
    "field",
    (
        "evidence_record_count",
        "condition_count",
        "trace_complete_count",
        "acknowledgment_verified_count",
    ),
)
def test_verify_m3_package_rejects_noninteger_evidence_verification_counts(
    retained_m3_package: Path,
    tmp_path: Path,
    field: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    verification_path = package / "evidence-verification.json"
    verification = _read_json(verification_path)
    verification["sessions"][0][field] = float(verification["sessions"][0][field])
    _write_json(verification_path, verification)
    _refresh_artifact_hash(package, "evidence-verification.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "verification", "count", "integer")


@pytest.mark.parametrize("mutation", ("extra-field", "master-seed-type"))
def test_verify_m3_package_rejects_invalid_evidence_verification_shape(
    retained_m3_package: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    verification_path = package / "evidence-verification.json"
    verification = _read_json(verification_path)
    session = verification["sessions"][0]
    if mutation == "extra-field":
        session["external_validation"] = "passed"
    else:
        session["master_seed"] = float(session["master_seed"])
    _write_json(verification_path, verification)
    _refresh_artifact_hash(package, "evidence-verification.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "verification", "field", "seed")


def test_verify_m3_package_rejects_deterministic_outcome_hash_mismatch(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["deterministic_outcome_sha256"] = "0" * 64
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "deterministic_outcome", "outcome", "hash")


def test_verify_m3_package_rejects_summary_binding_mismatch(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    summary_path = package / "summary.json"
    summary = _read_json(summary_path)
    summary["trial_record_count"] += 1
    _write_json(summary_path, summary)
    _refresh_artifact_hash(package, "summary.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "summary", "summary", "trial")


def test_verify_m3_package_requires_exact_json_summary_types(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    summary_path = package / "summary.json"
    summary = _read_json(summary_path)
    assert summary["session_count"] == 1
    summary["session_count"] = True
    _write_json(summary_path, summary)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    manifest["summary"] = copy.deepcopy(summary)
    manifest["artifact_sha256"]["summary.json"] = hashlib.sha256(
        summary_path.read_bytes()
    ).hexdigest()
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "summary", "summary", "type", "exact")


def test_verify_m3_package_rejects_configuration_binding_mismatch(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    solver_path = package / "solver/configuration.json"
    solver = _read_json(solver_path)
    solver["step_seconds"] = 2.0
    _write_json(solver_path, solver)
    _refresh_artifact_hash(package, "solver/configuration.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "configuration_bindings", "configuration", "solver")


@pytest.mark.parametrize(
    "mutation",
    ("manifest-protocol-bool", "boundary-bool-as-int", "solver-float-as-int"),
)
def test_verify_m3_package_requires_exact_json_configuration_types(
    retained_m3_package: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    if mutation == "manifest-protocol-bool":
        manifest["experiment_configuration"]["protocol_version"] = True
    elif mutation == "boundary-bool-as-int":
        manifest["boundary"]["containers_exercised"] = 0
    else:
        solver_path = package / "solver/configuration.json"
        solver = _read_json(solver_path)
        assert solver["step_seconds"] == 1.0
        solver["step_seconds"] = 1
        _write_json(solver_path, solver)
        manifest["artifact_sha256"]["solver/configuration.json"] = hashlib.sha256(
            solver_path.read_bytes()
        ).hexdigest()
        manifest["configuration_sha256"]["solver"] = m3.canonical_digest(solver)
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(
        result,
        "configuration_bindings",
        "configuration",
        "metadata",
        "solver",
    )


def test_verify_m3_package_rejects_incomplete_source_and_schema_hashes(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    manifest_path = package / "manifest.json"
    manifest = _read_json(manifest_path)
    del manifest["source_sha256"][m3.M3_SOURCE_PATHS[0]]
    del manifest["schema_sha256"][m3.M3_SCHEMA_PATHS[0]]
    _write_json(manifest_path, manifest)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "checkout_bindings", "source", "schema", "checkout")


def test_verify_m3_package_rejects_scalar_component_sessions_without_raising(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    component_health["sessions"] = "not-a-session-list"
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "component", "session", "list")


def test_verify_m3_package_rejects_nonfinite_required_json_without_raising(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    solver_path = package / "solver/configuration.json"
    solver = _read_json(solver_path)
    solver["step_seconds"] = float("nan")
    solver_path.write_text(
        json.dumps(solver, indent=2, sort_keys=True, allow_nan=True) + "\n",
        encoding="utf-8",
    )
    _refresh_artifact_hash(package, "solver/configuration.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "manifest", "finite", "nan", "parse", "prohibited")


def test_verify_m3_package_rejects_null_closed_loop_post_state_without_raising(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    trials = _read_jsonl(trials_path)
    nominal = next(trial for trial in trials if trial["condition"] == "nominal_permitted_execution")
    assert nominal["artifacts"]["schema_version"] == "closed-loop-result-v1"
    nominal["artifacts"]["post_state"] = None
    _write_jsonl(trials_path, trials)
    _refresh_artifact_hash(package, "trials.jsonl")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "post-state", "artifact", "closed-loop")


def test_verify_m3_package_rejects_duplicate_retained_session_rows(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    for relative_path in ("component-health.json", "evidence-verification.json"):
        artifact_path = package / relative_path
        artifact = _read_json(artifact_path)
        artifact["sessions"].append(copy.deepcopy(artifact["sessions"][0]))
        _write_json(artifact_path, artifact)
        _refresh_artifact_hash(package, relative_path)

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "record_counts", "duplicate", "session", "row")


def test_verify_m3_package_rejects_required_artifact_symlink_escape(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    artifact_path = package / "solver/configuration.json"
    outside_path = tmp_path / "outside-solver.json"
    outside_path.write_bytes(artifact_path.read_bytes())
    artifact_path.unlink()
    artifact_path.symlink_to(outside_path)

    result = m3.verify_m3_package(package)

    _assert_invalid(result, "artifact", "unsafe", "package", "verified")


@pytest.mark.parametrize(
    "mutation",
    ("acknowledgment", "proposal", "pre_state", "post_state"),
)
def test_verify_m3_package_rejects_rehashed_uncorrelated_terminal_event(
    retained_m3_package: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    events_path = package / "events.jsonl"
    trials = _read_jsonl(trials_path)
    events = _read_jsonl(events_path)
    replay = next(trial for trial in trials if trial["condition"] == "permit_replay")
    original_hash = replay["artifacts"]["execution_evidence_hash"]
    terminal_event = next(
        event for event in events if event["record"]["record_hash"] == original_hash
    )
    assert terminal_event == events[-1]
    payload = terminal_event["record"]["payload"]
    if mutation == "acknowledgment":
        payload["acknowledgment"]["reason"] = "contradicted-acknowledgment"
    elif mutation == "proposal":
        payload["proposal"]["actor_id"] = "agent:contradicted"
    else:
        del payload[mutation]

    record = m3.EvidenceRecord.model_validate(terminal_event["record"])
    rehashed_record = m3._evidence_record_digest(record)
    terminal_event["record"]["record_hash"] = rehashed_record
    replay["artifacts"]["execution_evidence_hash"] = rehashed_record
    _write_jsonl(events_path, events)
    _write_jsonl(trials_path, trials)
    _refresh_artifact_hash(package, "events.jsonl")
    _refresh_artifact_hash(package, "trials.jsonl")

    result = m3.verify_m3_package(package)

    assert result["checks"]["event_chains"] is True
    _assert_check_failed(result, "trial_semantics", "correlated", "evidence", "transaction")


def test_verify_m3_package_rejects_reused_cross_session_component_identities(
    retained_two_session_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_two_session_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    first, second = component_health["sessions"]

    second["process"]["boot_epoch"] = first["process"]["boot_epoch"]
    second["process"]["device_id"] = first["process"]["device_id"]
    second["process"]["audience"] = first["process"]["audience"]
    second["process"]["device_public_key_b64"] = first["process"][
        "device_public_key_b64"
    ]
    second["permit_public_key_b64"] = first["permit_public_key_b64"]
    second["verified_health_payload"]["boot_epoch"] = first["verified_health_payload"][
        "boot_epoch"
    ]
    second["verified_health_payload"]["device_id"] = first["verified_health_payload"][
        "device_id"
    ]
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "unique", "component", "identity")
    errors = " ".join(str(error) for error in result["errors"]).lower()
    for identity_name in (
        "boot epoch",
        "device identifier",
        "device public key",
        "permit public key",
    ):
        assert f"unique {identity_name}" in errors


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("model_id", "unregistered-model"),
        ("simulator_version", "unregistered-simulator"),
        ("observation_source_id", "replayed-file"),
        ("observation_clock_domain", "LOCAL"),
    ),
)
def test_verify_m3_package_rejects_unregistered_initial_state_bindings(
    retained_m3_package: Path,
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    health_path = package / "component-health.json"
    component_health = _read_json(health_path)
    initial_state = component_health["sessions"][0]["initial_state"]
    initial_state[field] = replacement
    _refresh_physical_state_digests(initial_state)
    _write_json(health_path, component_health)
    _refresh_artifact_hash(package, "component-health.json")

    result = m3.verify_m3_package(package)

    _assert_check_failed(result, "trial_semantics", "initial state is invalid")


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("model_id", "unregistered-model"),
        ("simulator_version", "unregistered-simulator"),
        ("observation_source_id", "replayed-file"),
        ("observation_clock_domain", "LOCAL"),
    ),
)
def test_verify_m3_package_rejects_unregistered_trial_state_bindings(
    retained_m3_package: Path,
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    trials = _read_jsonl(trials_path)
    trials[0]["pre_state"][field] = replacement
    _refresh_physical_state_digests(trials[0]["pre_state"])
    _write_jsonl(trials_path, trials)
    _refresh_artifact_hash(package, "trials.jsonl")

    result = m3.verify_m3_package(package)

    _assert_check_failed(
        result,
        "trial_semantics",
        "physical states do not match the session model",
    )


def test_verify_m3_package_rejects_observation_sequence_regression(
    retained_m3_package: Path,
    tmp_path: Path,
) -> None:
    package = _clone_package(retained_m3_package, tmp_path)
    trials_path = package / "trials.jsonl"
    trials = _read_jsonl(trials_path)
    prior_observation = trials[0]["post_state"]
    regressed_observation = trials[1]["pre_state"]
    assert prior_observation["observation_sequence"] > 0
    regressed_observation["observation_sequence"] = (
        prior_observation["observation_sequence"] - 1
    )
    _refresh_physical_state_digests(regressed_observation)
    _write_jsonl(trials_path, trials)
    _refresh_artifact_hash(package, "trials.jsonl")

    result = m3.verify_m3_package(package)

    _assert_check_failed(
        result,
        "trial_semantics",
        "observation sequence is not monotonic",
    )
