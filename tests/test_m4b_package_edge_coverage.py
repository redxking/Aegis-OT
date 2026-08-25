from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis_ot.m4b_package as package
from aegis_ot.m4b_models import (
    IndependentConsequenceReport,
    M4bArtifactDescriptor,
    M4bComponentRegistration,
    M4bEvidenceManifest,
    M4bTransactionRecord,
    M4bTrustAnchor,
    canonical_json_bytes,
    sha256_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
RETAINED_PACKAGE = ROOT / "results/m4b-capability-evidence"
RETAINED_ANCHOR = ROOT / "results/m4b-capability-evidence.trust-anchor.json"


@pytest.fixture(scope="module")
def retained_material() -> tuple[M4bEvidenceManifest, dict[str, bytes]]:
    manifest = M4bEvidenceManifest.model_validate(
        json.loads((RETAINED_PACKAGE / package.MANIFEST_NAME).read_bytes())
    )
    artifacts = {
        descriptor.path: (RETAINED_PACKAGE / descriptor.path).read_bytes()
        for descriptor in manifest.artifacts
    }
    return manifest, artifacts


@pytest.fixture(scope="module")
def session_records(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
) -> tuple[M4bTransactionRecord, tuple[M4bComponentRegistration, ...]]:
    _, artifacts = retained_material
    transactions = tuple(
        M4bTransactionRecord.model_validate(json.loads(line))
        for line in artifacts["transactions/results.jsonl"].splitlines()
    )
    registrations = tuple(
        M4bComponentRegistration.model_validate(json.loads(line))
        for line in artifacts["sessions/component-registrations.jsonl"].splitlines()
    )
    nominal = next(
        item
        for item in transactions
        if item.session_index == 0 and item.condition == "nominal_permitted_execution"
    )
    first_session = tuple(item for item in registrations if item.session_index == 0)
    assert len(first_session) == 6
    return nominal, first_session


def _rows(material: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in material.splitlines()]


def _jsonl(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(row) + b"\n" for row in rows)


def _retained_descriptor(
    manifest: M4bEvidenceManifest,
    path: str,
) -> M4bArtifactDescriptor:
    return next(item for item in manifest.artifacts if item.path == path)


def _health_digest(record: dict[str, Any]) -> None:
    material = {key: value for key, value in record.items() if key != "bundle_sha256"}
    record["bundle_sha256"] = sha256_bytes(canonical_json_bytes(material))


@pytest.mark.parametrize(
    ("material", "message"),
    (
        (b"\xef\xbb\xbf{}", "UTF-8 BOM"),
        (b'{"field":1,"field":2}', "duplicate field"),
        (b'{"field":NaN}', "non-finite JSON constant"),
    ),
)
def test_strict_json_rejects_ambiguous_or_nonfinite_input(
    material: bytes,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        package._strict_json(material, label="adversarial JSON")


def test_typed_jsonl_rejects_framing_limits_and_noncanonical_records(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, artifacts = retained_material
    line = artifacts["transactions/results.jsonl"].splitlines()[0]

    with pytest.raises(ValueError, match="must end with a newline"):
        package._jsonl(line, M4bTransactionRecord, label="transactions")
    with pytest.raises(ValueError, match="empty record"):
        package._jsonl(b"\n", M4bTransactionRecord, label="transactions")
    with pytest.raises(ValueError, match="not canonical"):
        package._jsonl(b" " + line + b"\n", M4bTransactionRecord, label="transactions")

    monkeypatch.setattr(package, "MAX_JSONL_RECORDS", 0)
    with pytest.raises(ValueError, match="record limit"):
        package._jsonl(line + b"\n", M4bTransactionRecord, label="transactions")


def test_dictionary_jsonl_and_json_artifacts_reject_invalid_canonical_forms() -> None:
    with pytest.raises(ValueError, match="must end with a newline"):
        package._dict_jsonl(b"{}", label="dictionary records")
    with pytest.raises(ValueError, match="must be an object"):
        package._dict_jsonl(b"[]\n", label="dictionary records")
    with pytest.raises(ValueError, match="not canonical"):
        package._dict_jsonl(b'{"z":1, "a":2}\n', label="dictionary records")
    with pytest.raises(ValueError, match="not canonical JSON"):
        package._canonical_json_artifact(b'{"field":1}', label="JSON artifact")


def test_descriptor_builder_rejects_missing_unsafe_and_unregistered_paths(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
) -> None:
    _, retained = retained_material
    core = {path: retained[path] for path in package.CORE_ARTIFACT_PATHS}

    with pytest.raises(ValueError, match="required M4b artifacts are missing"):
        package.build_artifact_descriptors({"summary.json": core["summary.json"]})

    unsafe = dict(core)
    unsafe["../escape.json"] = b"{}\n"
    with pytest.raises(ValueError):
        package.build_artifact_descriptors(unsafe)

    unregistered = dict(core)
    unregistered["source/unregistered.txt"] = b"outside the profile"
    with pytest.raises(ValueError, match="outside the registered M4b profile"):
        package.build_artifact_descriptors(unregistered)


def test_descriptor_builder_rejects_wrong_types_and_size_limits(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, retained = retained_material
    core = {path: retained[path] for path in package.CORE_ARTIFACT_PATHS}
    wrong_type: dict[str, Any] = dict(core)
    wrong_type["summary.json"] = "not bytes"
    with pytest.raises(TypeError, match="artifact material must be bytes"):
        package.build_artifact_descriptors(wrong_type)

    monkeypatch.setattr(package, "MAX_ARTIFACT_BYTES", 0)
    with pytest.raises(ValueError, match="artifact exceeds size limit"):
        package.build_artifact_descriptors(core)

    monkeypatch.setattr(package, "MAX_ARTIFACT_BYTES", 32 * 1024 * 1024)
    monkeypatch.setattr(package, "MAX_PACKAGE_BYTES", 0)
    with pytest.raises(ValueError, match="aggregate artifact size"):
        package.build_artifact_descriptors(core)


def test_descriptor_builder_rejects_inventory_limit(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, retained = retained_material
    core = {path: retained[path] for path in package.CORE_ARTIFACT_PATHS}
    monkeypatch.setattr(package, "MAX_ARTIFACTS", len(core) - 1)
    with pytest.raises(ValueError, match="inventory is empty or exceeds"):
        package.build_artifact_descriptors(core)


@pytest.mark.parametrize("link_kind", ("directory", "file"))
def test_file_inventory_rejects_symlinks(tmp_path: Path, link_kind: str) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    target = tmp_path / "target"
    if link_kind == "directory":
        target.mkdir()
        (package_root / "linked").symlink_to(target, target_is_directory=True)
        expected = "symlink directory"
    else:
        target.write_text("target", encoding="utf-8")
        (package_root / "linked").symlink_to(target)
        expected = "non-regular file"
    with pytest.raises(ValueError, match=expected):
        package._listed_files(package_root)


def test_file_inventory_rejects_excessive_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    for index in range(3):
        (package_root / f"artifact-{index}").write_text("x", encoding="utf-8")
    monkeypatch.setattr(package, "MAX_ARTIFACTS", 0)
    with pytest.raises(ValueError, match="inventory exceeds"):
        package._listed_files(package_root)


@pytest.mark.parametrize(
    ("update", "message"),
    (
        ({"byte_length": 1}, "length mismatch"),
        ({"sha256": "0" * 64}, "hash mismatch"),
        ({"record_count": 0}, "record count mismatch"),
        ({"media_type": "text/plain"}, "media type mismatch"),
    ),
)
def test_artifact_reader_rejects_descriptor_mismatch(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    tmp_path: Path,
    update: dict[str, Any],
    message: str,
) -> None:
    manifest, artifacts = retained_material
    descriptor = _retained_descriptor(manifest, "transactions/results.jsonl")
    path = tmp_path / descriptor.path
    path.parent.mkdir(parents=True)
    path.write_bytes(artifacts[descriptor.path])
    if "byte_length" in update:
        update = {"byte_length": descriptor.byte_length + update["byte_length"]}
    if "record_count" in update:
        assert descriptor.record_count is not None
        update = {"record_count": descriptor.record_count + 1}
    bad_descriptor = descriptor.model_copy(update=update)
    with pytest.raises(ValueError, match=message):
        package._artifact_bytes(tmp_path, bad_descriptor)


def test_artifact_reader_rejects_nonregular_and_oversized_paths(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, artifacts = retained_material
    descriptor = _retained_descriptor(manifest, "summary.json")
    directory_root = tmp_path / "directory-case"
    (directory_root / descriptor.path).mkdir(parents=True)
    with pytest.raises(ValueError, match="not a regular file"):
        package._artifact_bytes(directory_root, descriptor)

    oversized_root = tmp_path / "oversized-case"
    oversized_path = oversized_root / descriptor.path
    oversized_path.parent.mkdir(parents=True)
    oversized_path.write_bytes(artifacts[descriptor.path])
    monkeypatch.setattr(package, "MAX_ARTIFACT_BYTES", len(artifacts[descriptor.path]) - 1)
    with pytest.raises(ValueError, match="artifact exceeds size limit"):
        package._artifact_bytes(oversized_root, descriptor)


def test_manifest_mapping_bindings_reject_inventory_and_digest_drift(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
) -> None:
    manifest, artifacts = retained_material
    incomplete = manifest.model_copy(update={"source_sha256": {}})
    with pytest.raises(ValueError, match="source binding inventory"):
        package._require_mapping_hashes(incomplete, artifacts)

    drifted = dict(manifest.source_sha256)
    first_path = next(iter(drifted))
    drifted[first_path] = "0" * 64
    wrong_digest = manifest.model_copy(update={"source_sha256": drifted})
    with pytest.raises(ValueError, match="source binding mismatch"):
        package._require_mapping_hashes(wrong_digest, artifacts)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("shape", "invalid shape"),
        ("type", "invalid types"),
        ("timestamp", "not timezone-aware"),
        ("digest", "digest is invalid"),
        ("session", "session IDs diverge"),
        ("phase", "duplicate component health phase"),
        ("incomplete", "phases are incomplete"),
    ),
)
def test_health_grouping_rejects_malformed_or_duplicate_records(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    mutation: str,
    message: str,
) -> None:
    _, artifacts = retained_material
    records = copy.deepcopy(_rows(artifacts["sessions/component-health.jsonl"])[:4])
    if mutation == "shape":
        records[0].pop("captured_at")
    elif mutation == "type":
        records[0]["session_index"] = True
    elif mutation == "timestamp":
        records[0]["captured_at"] = "2026-08-25T12:00:00"
        _health_digest(records[0])
    elif mutation == "digest":
        records[0]["bundle_sha256"] = "0" * 64
    elif mutation == "session":
        records[1]["session_id"] = "divergent-session"
        _health_digest(records[1])
    elif mutation == "phase":
        records[1]["phase"] = records[0]["phase"]
        _health_digest(records[1])
    else:
        records.pop()
    with pytest.raises(ValueError, match=message):
        package._health_by_session(tuple(records))


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("shape", "invalid shape"),
        ("type", "invalid types"),
        ("session", "session IDs diverge"),
        ("chain", "hash chain is invalid"),
    ),
)
def test_evidence_grouping_rejects_shape_identity_and_hash_chain_drift(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    mutation: str,
    message: str,
) -> None:
    _, artifacts = retained_material
    records = copy.deepcopy(_rows(artifacts["transactions/evidence-records.jsonl"])[:5])
    if mutation == "shape":
        records[0].pop("schema_version")
    elif mutation == "type":
        records[0]["master_seed"] = True
    elif mutation == "session":
        records[1]["session_id"] = "divergent-session"
    else:
        records[0]["record"]["record_hash"] = "0" * 64
    with pytest.raises(ValueError, match=message):
        package._evidence_by_session(tuple(records))


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("roles", "roles are incomplete or reordered"),
        ("boot", "boot epochs are not distinct"),
        ("pid", "runtime component PIDs are not distinct"),
        ("key", "signing keys are not distinct"),
    ),
)
def test_registration_grouping_rejects_duplicate_component_identity(
    session_records: tuple[M4bTransactionRecord, tuple[M4bComponentRegistration, ...]],
    mutation: str,
    message: str,
) -> None:
    _, retained = session_records
    registrations = list(retained)
    if mutation == "roles":
        registrations[0], registrations[1] = registrations[1], registrations[0]
    elif mutation == "boot":
        registrations[1] = registrations[1].model_copy(
            update={"boot_epoch": registrations[0].boot_epoch}
        )
    elif mutation == "pid":
        registrations[1] = registrations[1].model_copy(update={"pid": registrations[0].pid})
    else:
        registrations[2] = registrations[2].model_copy(
            update={"public_key_b64": registrations[1].public_key_b64}
        )
    with pytest.raises(ValueError, match=message):
        package._registration_groups(tuple(registrations))


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("missing_key", "verification key is missing"),
        ("observation", "observation signature or identity"),
        ("request_binding", "request-to-observation binding"),
        ("permit", "permit signature or identity"),
        ("missing_ack_input", "missing verification inputs"),
        ("acknowledgment", "acknowledgment signature or binding"),
    ),
)
def test_transaction_signature_verifier_rejects_identity_and_binding_drift(
    session_records: tuple[M4bTransactionRecord, tuple[M4bComponentRegistration, ...]],
    mutation: str,
    message: str,
) -> None:
    transaction, retained_registrations = session_records
    registrations = list(retained_registrations)
    changed = transaction
    if mutation == "missing_key":
        registrations[1] = registrations[1].model_copy(update={"public_key_b64": None})
    elif mutation == "observation":
        assert transaction.result.pre_observation is not None
        observation = transaction.result.pre_observation.model_copy(update={"signature": ""})
        result = transaction.result.model_copy(update={"pre_observation": observation})
        changed = transaction.model_copy(update={"result": result})
    elif mutation == "request_binding":
        request = transaction.result.request.model_copy(update={"observation_id": "wrong-id"})
        result = transaction.result.model_copy(update={"request": request})
        changed = transaction.model_copy(update={"result": result})
    elif mutation == "permit":
        assert transaction.result.permit is not None
        permit = transaction.result.permit.model_copy(update={"signing_key_id": "wrong-key"})
        result = transaction.result.model_copy(update={"permit": permit})
        changed = transaction.model_copy(update={"result": result})
    elif mutation == "missing_ack_input":
        result = transaction.result.model_copy(update={"permit": None})
        changed = transaction.model_copy(update={"result": result})
    else:
        assert transaction.result.acknowledgment is not None
        acknowledgment = transaction.result.acknowledgment.model_copy(update={"signature": ""})
        result = transaction.result.model_copy(update={"acknowledgment": acknowledgment})
        changed = transaction.model_copy(update={"result": result})
    with pytest.raises(ValueError, match=message):
        package._verify_transaction_signatures(changed, tuple(registrations))


@pytest.mark.parametrize(
    ("field", "message"),
    (
        ("transaction_record_count", "transaction count"),
        ("evidence_record_count", "evidence count"),
        ("component_registration_count", "registration count"),
        ("probe_record_count", "probe count"),
        ("independent_evaluation_count", "independent evaluation count"),
        ("session_count", "session-level artifact counts"),
    ),
)
def test_semantic_verifier_rejects_manifest_count_drift(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    field: str,
    message: str,
) -> None:
    manifest, artifacts = retained_material
    changed = manifest.model_copy(update={field: getattr(manifest, field) + 1})
    with pytest.raises(ValueError, match=message):
        package._verify_semantics(changed, artifacts)


def test_semantic_verifier_rejects_health_count_drift(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
) -> None:
    manifest, retained = retained_material
    artifacts = dict(retained)
    rows = _rows(artifacts["sessions/component-health.jsonl"])
    artifacts["sessions/component-health.jsonl"] = _jsonl(rows[:-1])
    with pytest.raises(ValueError, match="health bundle count"):
        package._verify_semantics(manifest, artifacts)


@pytest.mark.parametrize(
    ("field", "message"),
    (
        ("component_registration_sha256", "package-level binding"),
        ("evidence_first_sequence", "evidence range"),
        ("evidence_chain_head", "terminal evidence binding"),
    ),
)
def test_semantic_verifier_rejects_transaction_binding_drift(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    field: str,
    message: str,
) -> None:
    manifest, retained = retained_material
    artifacts = dict(retained)
    rows = _rows(artifacts["transactions/results.jsonl"])
    if field == "evidence_first_sequence":
        rows[0][field] += 1
    else:
        rows[0][field] = "0" * 64
    artifacts["transactions/results.jsonl"] = _jsonl(rows)
    with pytest.raises(ValueError, match=message):
        package._verify_semantics(manifest, artifacts)


def test_semantic_verifier_rejects_duplicate_session_probe(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
) -> None:
    manifest, retained = retained_material
    artifacts = dict(retained)
    rows = _rows(artifacts["topology/capability-probes.jsonl"])
    rows[-1] = copy.deepcopy(rows[0])
    artifacts["topology/capability-probes.jsonl"] = _jsonl(rows)
    with pytest.raises(ValueError, match="duplicate session-level probe"):
        package._verify_semantics(manifest, artifacts)


def test_semantic_verifier_rejects_duplicate_independent_request_identity(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
) -> None:
    manifest, retained = retained_material
    artifacts = dict(retained)
    rows = _rows(artifacts["independent/requests.jsonl"])
    rows[-1] = copy.deepcopy(rows[0])
    artifacts["independent/requests.jsonl"] = _jsonl(rows)
    with pytest.raises(ValueError, match="duplicate independent evaluation identity"):
        package._verify_semantics(manifest, artifacts)


def test_semantic_helpers_reject_absent_source_and_incomplete_report(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
) -> None:
    _, artifacts = retained_material
    with pytest.raises(ValueError, match="source snapshot is absent"):
        package._independent_source_digest({"source/pyproject.toml": b"[project]\n"})

    report = IndependentConsequenceReport.model_validate(
        json.loads(artifacts["independent/evaluations.jsonl"].splitlines()[0])
    )
    incomplete = report.model_copy(update={"predicted_values": None})
    assert package._comparison_values(incomplete) == {}


def test_checkout_binding_reports_digest_missing_file_and_empty_inventory(
    retained_material: tuple[M4bEvidenceManifest, dict[str, bytes]],
    tmp_path: Path,
) -> None:
    manifest, _ = retained_material
    expected = manifest.source_sha256["source/pyproject.toml"]
    one_binding = manifest.model_copy(
        update={
            "source_sha256": {"source/pyproject.toml": expected},
            "schema_sha256": {},
            "configuration_sha256": {},
            "fixture_sha256": {},
        }
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='wrong'\n", encoding="utf-8")
    matches, errors = package._checkout_matches(one_binding, tmp_path)
    assert matches is False
    assert errors == ["checkout digest mismatch: pyproject.toml"]

    (tmp_path / "pyproject.toml").unlink()
    matches, errors = package._checkout_matches(one_binding, tmp_path)
    assert matches is False
    assert any("cannot be verified" in item for item in errors)

    no_bindings = manifest.model_copy(
        update={
            "source_sha256": {},
            "schema_sha256": {},
            "configuration_sha256": {},
            "fixture_sha256": {},
        }
    )
    matches, errors = package._checkout_matches(no_bindings, tmp_path)
    assert matches is False
    assert errors == ["manifest contains no registered checkout bindings"]


def test_finalizer_rejects_unsafe_publication_paths_and_mismatched_root(
    tmp_path: Path,
) -> None:
    anchor = M4bTrustAnchor.model_validate(json.loads(RETAINED_ANCHOR.read_bytes()))
    private_key = Ed25519PrivateKey.generate()

    output = tmp_path / "inside"
    with pytest.raises(ValueError, match="trust anchor must be outside"):
        package.finalize_m4b_package(
            output_dir=output,
            trust_anchor_path=output / "anchor.json",
            artifacts={},
            manifest_fields={},
            trust_anchor=anchor,
            root_private_key=private_key,
        )

    with pytest.raises(ValueError, match="output parent"):
        package.finalize_m4b_package(
            output_dir=tmp_path / "missing-output-parent" / "package",
            trust_anchor_path=tmp_path / "anchor.json",
            artifacts={},
            manifest_fields={},
            trust_anchor=anchor,
            root_private_key=private_key,
        )

    with pytest.raises(ValueError, match="anchor parent"):
        package.finalize_m4b_package(
            output_dir=tmp_path / "package",
            trust_anchor_path=tmp_path / "missing-anchor-parent" / "anchor.json",
            artifacts={},
            manifest_fields={},
            trust_anchor=anchor,
            root_private_key=private_key,
        )

    with pytest.raises(ValueError, match="root private key does not match"):
        package.finalize_m4b_package(
            output_dir=tmp_path / "package",
            trust_anchor_path=tmp_path / "anchor.json",
            artifacts={},
            manifest_fields={},
            trust_anchor=anchor,
            root_private_key=private_key,
        )


def test_verifier_rejects_noncanonical_envelopes_and_unsafe_paths(tmp_path: Path) -> None:
    missing = package.verify_m4b_package(tmp_path / "missing", RETAINED_ANCHOR)
    assert missing["package_valid"] is False
    assert missing["errors"] == ["package path is not a regular directory"]

    package_root = tmp_path / "package"
    package_root.mkdir()
    inside_anchor = package.verify_m4b_package(package_root, package_root / "anchor.json")
    assert inside_anchor["package_valid"] is False
    assert inside_anchor["errors"] == ["trust anchor is inside the evidence package"]

    manifest = json.loads((RETAINED_PACKAGE / package.MANIFEST_NAME).read_bytes())
    (package_root / package.MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    result = package.verify_m4b_package(package_root, RETAINED_ANCHOR)
    assert result["checks"]["manifest"] is False
    assert any("not exact canonical JSON" in item for item in result["errors"])
