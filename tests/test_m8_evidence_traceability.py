from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis_ot.m8_evidence_traceability as m8v2
from aegis_ot.m8_evidence_traceability import (
    ATTESTATION_SCHEMA,
    AttestationContext,
    TraceabilityError,
    TrustedAttestationAuthority,
    attestation_context,
    attestation_signing_bytes,
    bind_committed_file,
    bind_historical_result,
    build_evidence_traceability,
    ingest_external_attestation,
    parse_evidence_mapping,
    sha256_json,
    validate_evidence_traceability,
    verify_external_attestation_stateless,
)
from aegis_ot.m8_traceability import parse_requirements_docx

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_PATH = "docs/requirements/Aegis-OT_End-State_System_Requirements.docx"
MAPPING_PATH = "config/m8-requirements-evidence-map.json"
CAMPAIGN_SOURCE_PATHS = {
    "pyproject.toml",
    "requirements.lock",
    "scripts/run_m8_evidence_traceability.py",
    "src/aegis_ot/m8_evidence_traceability.py",
    "src/aegis_ot/m8_traceability.py",
}


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603 - test-owned fixture repository
        ("/usr/bin/git", "-C", str(root), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _mapped_paths(mapping: dict[str, Any]) -> set[str]:
    paths = {REQUIREMENTS_PATH, MAPPING_PATH}
    for entry in mapping["entries"]:
        paths.update(entry["implementation_artifacts"])
        paths.update(entry["result_artifacts"])
        paths.update(
            procedure.removeprefix("pytest::").split("::", 1)[0]
            for procedure in entry["procedure_or_test_ids"]
        )
    return paths


def _repository(tmp_path: Path) -> Path:
    repository = (tmp_path / "repository").resolve()
    repository.mkdir()
    mapping = json.loads((ROOT / MAPPING_PATH).read_text(encoding="utf-8"))
    result_paths = {
        path for entry in mapping["entries"] for path in entry["result_artifacts"]
    }
    initial_paths = (
        _mapped_paths(mapping) | CAMPAIGN_SOURCE_PATHS
    ) - result_paths - {MAPPING_PATH}
    for relative in sorted(initial_paths):
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    _git(repository, "init", "-q")
    _git(repository, "add", "--", *sorted(initial_paths))
    _git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "historical exercised source",
    )
    historical_commit = _git(repository, "rev-parse", "HEAD").strip()
    source_path = "src/aegis_ot/evidence.py"
    source_sha256 = hashlib.sha256((repository / source_path).read_bytes()).hexdigest()
    for relative in sorted(result_paths):
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "git_commit": historical_commit,
                    "working_tree_dirty": False,
                    "source_sha256": {source_path: source_sha256},
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    mapping_target = repository / MAPPING_PATH
    mapping_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / MAPPING_PATH, mapping_target)
    _git(repository, "add", "--", MAPPING_PATH, *sorted(result_paths))
    _git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "current mapping",
    )
    return repository


def _report(repository: Path) -> dict[str, Any]:
    return build_evidence_traceability(
        repository,
        requirements_path=REQUIREMENTS_PATH,
        mapping_path=MAPPING_PATH,
    )


def _validate(report: dict[str, Any], repository: Path) -> None:
    validate_evidence_traceability(
        report,
        root=repository,
        requirements_path=REQUIREMENTS_PATH,
        mapping_path=MAPPING_PATH,
    )


def _known_ids() -> frozenset[str]:
    baseline = parse_requirements_docx(ROOT / REQUIREMENTS_PATH)
    return frozenset(item.requirement_id for item in baseline.requirements)


def _mapping_value() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((ROOT / MAPPING_PATH).read_text(encoding="utf-8")),
    )


def _mapping_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _rehash(report: dict[str, Any]) -> None:
    report.pop("content_sha256", None)
    report["content_sha256"] = sha256_json(report)


def test_v2_maps_only_explicit_local_evidence_and_keeps_every_item_open(
    tmp_path: Path,
) -> None:
    report = _report(_repository(tmp_path))

    assert report["summary"] == {
        "requirements_tracked": 223,
        "requirements_mapped": 6,
        "requirements_unmapped": 217,
        "requirements_open": 223,
        "requirements_accepted": 0,
        "tbrs_tracked": 35,
        "tbrs_open": 35,
        "end_state_accepted": False,
    }
    assert len(report["requirements"]) == 223
    assert all(item["disposition"]["finding_status"] == "open" for item in report["requirements"])
    assert all(item["disposition"]["claim_state"] == "C0" for item in report["requirements"])
    assert all(item["status"] == "open" for item in report["tbrs"])
    assert report["external_attestations"] == []
    assert report["attestation_interface"]["independent_validation_established"] is False

    by_id = {
        item["identity"]["requirement_id"]: item for item in report["requirements"]
    }
    mapped = by_id["AOT-EVID-001"]
    assert mapped["engineering_basis"]["rationale"].startswith("The mapped evidence-chain")
    assert mapped["engineering_basis"]["trust_boundary"].startswith("Evidence writers")
    assert mapped["verification"]["result"] == "not_executed"
    assert mapped["disposition"]["implementation_state"] == (
        "local_evidence_mapped_not_accepted"
    )
    assert mapped["disposition"]["owner"] == "evidence_service_implementation_custody"
    assert mapped["disposition"]["approving_authority"] is None
    historical = mapped["evidence_mapping"]["historical_result_evidence"]
    assert len(historical) == 1
    assert historical[0]["relationship_to_current_source"] == "historical"
    assert historical[0]["source_files_verified"] == 1

    unmapped = by_id["AOT-AUTH-004"]
    assert unmapped["engineering_basis"]["rationale"] is None
    assert unmapped["engineering_basis"]["trust_boundary"] is None
    assert unmapped["verification"]["artifact"] == []
    assert unmapped["verification"]["result"] == "not_assessed"
    for requirement_id in ("AOT-EXEC-001", "AOT-PERF-007", "AOT-PERF-008"):
        current_only = by_id[requirement_id]
        assert current_only["verification"]["result"] == "not_executed"
        assert current_only["evidence_mapping"]["result_artifact_state"] == (
            "no_result_artifact"
        )
        assert current_only["evidence_mapping"]["historical_result_evidence"] == []


def test_forward_and_inverse_indexes_are_exact_and_artifacts_are_git_bound(
    tmp_path: Path,
) -> None:
    report = _report(_repository(tmp_path))
    forward = report["forward_index"]
    inverse = report["inverse_index"]

    assert sorted(forward) == report["coverage"]["mapped_requirement_ids"]
    assert inverse["artifacts"]["src/aegis_ot/m6_fleet.py"]["requirement_ids"] == [
        "AOT-PERF-007",
        "AOT-PERF-008",
    ]
    assert inverse["artifacts"]["src/aegis_ot/m6_fleet.py"]["roles"] == [
        "implementation"
    ]
    assert inverse["historical_results"][
        "results/m4b-capability-evidence/manifest.json"
    ]["requirement_ids"] == ["AOT-EVID-001", "AOT-EVID-005"]
    procedure = "pytest::tests/test_gateway.py::test_replay_is_denied"
    assert inverse["procedures"][procedure] == ["AOT-EXEC-001"]
    for value in inverse["artifacts"].values():
        binding = value["binding"]
        assert binding["git_mode"] in {"100644", "100755"}
        assert len(binding["sha256"]) == 64
        assert len(binding["git_blob"]) in {40, 64}
        assert binding["bytes"] > 0


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("unknown", "unknown requirement"),
        ("duplicate", "unique and lexically sorted"),
        ("overbroad", "noncanonical or overbroad"),
        ("conflicting", "conflicting artifact roles"),
        ("acceptance", "remain open"),
    ],
)
def test_mapping_rejects_unknown_duplicate_conflicting_and_overbroad_entries(
    mutation: str,
    message: str,
) -> None:
    value = _mapping_value()
    if mutation == "unknown":
        value["entries"][0]["requirement_id"] = "AOT-UNKNOWN-999"
    elif mutation == "duplicate":
        value["entries"].insert(1, copy.deepcopy(value["entries"][0]))
    elif mutation == "overbroad":
        value["entries"][0]["implementation_artifacts"] = ["src/**"]
    elif mutation == "conflicting":
        value["entries"][0]["result_artifacts"] = ["src/aegis_ot/evidence.py"]
    else:
        value["entries"][0]["disposition"] = "accepted"

    with pytest.raises(TraceabilityError, match=message):
        parse_evidence_mapping(_mapping_bytes(value), known_requirement_ids=_known_ids())


def test_builder_rejects_a_test_id_that_does_not_resolve_to_an_exact_function(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    mapping_path = repository / MAPPING_PATH
    value = json.loads(mapping_path.read_text(encoding="utf-8"))
    value["entries"][0]["procedure_or_test_ids"][0] = (
        "pytest::tests/test_evidence_replay.py::test_not_a_real_procedure"
    )
    value["entries"][0]["procedure_or_test_ids"].sort()
    mapping_path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    _git(repository, "add", "--", MAPPING_PATH)
    _git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "invalid test ID",
    )

    with pytest.raises(TraceabilityError, match="does not exist exactly"):
        _report(repository)


def test_git_binding_rejects_modified_uncommitted_and_linked_artifacts(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    commit = _git(repository, "rev-parse", "HEAD").strip()
    path = repository / "src/aegis_ot/evidence.py"
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(TraceabilityError, match="differs from commit"):
        bind_committed_file(repository, commit, "src/aegis_ot/evidence.py")

    untracked = repository / "untracked.py"
    untracked.write_text("value = 1\n", encoding="utf-8")
    with pytest.raises(TraceabilityError, match="not one committed file"):
        bind_committed_file(repository, commit, "untracked.py")

    path.write_bytes(_git(repository, "show", f"{commit}:src/aegis_ot/evidence.py").encode())
    alias = tmp_path / "alias.py"
    shutil.copy2(path, alias)
    path.unlink()
    path.symlink_to(alias)
    with pytest.raises(TraceabilityError, match="regular non-link"):
        bind_committed_file(repository, commit, "src/aegis_ot/evidence.py")


def _signed_attestation(
    context: AttestationContext,
    private_key: Ed25519PrivateKey,
    authority: TrustedAttestationAuthority,
    now: datetime,
    *,
    requirement_id: str = "AOT-EVID-001",
    sequence: int = 1,
    attestation_id: str = "12345678-1234-4234-9234-1234567890ab",
) -> dict[str, Any]:
    unsigned: dict[str, Any] = {
        "schema": ATTESTATION_SCHEMA,
        "attestation_id": attestation_id,
        "authority_id": authority.authority_id,
        "key_id": authority.key_id,
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "requirements_source_sha256": context.requirements_source_sha256,
        "git_commit": context.git_commit,
        "git_tree": context.git_tree,
        "mapping_sha256": context.mapping_sha256,
        "traceability_content_sha256": context.traceability_content_sha256,
        "purpose": context.purpose,
        "audience": context.audience,
        "challenge_nonce": context.challenge_nonce,
        "sequence": sequence,
        "requirement_ids": [requirement_id],
        "findings": [
            {
                "requirement_id": requirement_id,
                "disposition": "inconclusive",
                "statement": "Fixture attestation used only to exercise verification behavior.",
                "artifact_bindings": [
                    item.as_dict()
                    for item in context.artifacts_by_requirement[requirement_id]
                ],
            }
        ],
    }
    signature = private_key.sign(attestation_signing_bytes(unsigned))
    return {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii"),
    }


def _attestation_context(
    report: dict[str, Any],
    repository: Path,
    *,
    challenge_nonce: str = "challenge_nonce_0123456789abcdef",
) -> AttestationContext:
    return attestation_context(
        report,
        root=repository,
        requirements_path=REQUIREMENTS_PATH,
        mapping_path=MAPPING_PATH,
        purpose="requirements-evidence-attestation",
        audience="aegis-ot-assurance-authority",
        challenge_nonce=challenge_nonce,
    )


def test_external_attestation_verifies_configured_trust_freshness_and_exact_bindings(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    report = _report(repository)
    context = _attestation_context(report, repository)
    private_key = Ed25519PrivateKey.generate()
    authority = TrustedAttestationAuthority(
        authority_id="independent-assessor-fixture",
        public_key=private_key.public_key(),
        allowed_requirement_ids=frozenset({"AOT-EVID-001"}),
    )
    now = datetime(2026, 8, 26, 16, 0, tzinfo=UTC)
    attestation = _signed_attestation(context, private_key, authority, now)

    verified = verify_external_attestation_stateless(
        json.dumps(attestation, sort_keys=True).encode(),
        authority=authority,
        context=context,
        now=now,
    )

    assert verified["signature_and_bindings_verified"] is True
    assert verified["replay_safe_ingestion_completed"] is False
    assert verified["automatic_requirement_acceptance"] is False
    assert verified["independent_validation_established"] is False
    assert verified["requirement_ids"] == ["AOT-EVID-001"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("baseline", "requirements_source_sha256 binding does not match"),
        ("artifact", "artifact binding does not match exactly"),
        ("expired", "expired"),
        ("scope", "configured authority scope"),
        ("content", "traceability_content_sha256 binding does not match"),
        ("purpose", "purpose binding does not match"),
        ("audience", "audience binding does not match"),
        ("challenge", "challenge_nonce binding does not match"),
        ("sequence", "sequence is not a positive integer"),
        ("signature", "signature is invalid"),
    ],
)
def test_external_attestation_rejects_binding_freshness_scope_and_signature_attacks(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    repository = _repository(tmp_path)
    report = _report(repository)
    context = _attestation_context(report, repository)
    private_key = Ed25519PrivateKey.generate()
    authority = TrustedAttestationAuthority(
        authority_id="independent-assessor-fixture",
        public_key=private_key.public_key(),
        allowed_requirement_ids=frozenset({"AOT-EVID-001"}),
    )
    now = datetime(2026, 8, 26, 16, 0, tzinfo=UTC)
    value = _signed_attestation(context, private_key, authority, now)
    if mutation == "baseline":
        value["requirements_source_sha256"] = "0" * 64
    elif mutation == "artifact":
        value["findings"][0]["artifact_bindings"][0]["sha256"] = "0" * 64
    elif mutation == "expired":
        value["expires_at"] = (now - timedelta(seconds=1)).isoformat()
    elif mutation == "scope":
        value = _signed_attestation(
            context,
            private_key,
            authority,
            now,
            requirement_id="AOT-EVID-005",
        )
    elif mutation == "content":
        value["traceability_content_sha256"] = "0" * 64
    elif mutation == "purpose":
        value["purpose"] = "different-purpose"
    elif mutation == "audience":
        value["audience"] = "different-audience"
    elif mutation == "challenge":
        value["challenge_nonce"] = "different_challenge_0123456789abc"
    elif mutation == "sequence":
        value["sequence"] = 0
    else:
        value["signature"] = base64.urlsafe_b64encode(b"x" * 64).decode("ascii")

    with pytest.raises(TraceabilityError, match=message):
        verify_external_attestation_stateless(
            json.dumps(value, sort_keys=True).encode(),
            authority=authority,
            context=context,
            now=now,
        )


def test_report_validation_rejects_rehashed_false_acceptance_or_attestation(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    report = _report(repository)
    accepted = copy.deepcopy(report)
    accepted["requirements"][0]["disposition"]["finding_status"] = "accepted"
    _rehash(accepted)
    with pytest.raises(TraceabilityError, match="not exactly open"):
        _validate(accepted, repository)

    fabricated = copy.deepcopy(report)
    fabricated["external_attestations"] = [{"claimed": True}]
    _rehash(fabricated)
    with pytest.raises(TraceabilityError, match="must not contain fabricated"):
        _validate(fabricated, repository)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("duplicate_requirement", "duplicated or incomplete"),
        ("inverse_index", "artifact inverse index"),
        ("gate", "gate catalog or semantics drifted"),
        ("claim", "claim boundary drifted"),
    ],
)
def test_full_validation_rejects_catalog_index_gate_and_claim_drift(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    repository = _repository(tmp_path)
    report = _report(repository)
    altered = copy.deepcopy(report)
    if mutation == "duplicate_requirement":
        altered["requirements"][1]["identity"]["requirement_id"] = altered[
            "requirements"
        ][0]["identity"]["requirement_id"]
    elif mutation == "inverse_index":
        first = next(iter(altered["inverse_index"]["artifacts"].values()))
        first["requirement_ids"] = ["AOT-SYS-001"]
    elif mutation == "gate":
        altered["gates"]["G7"] = "Locally approved"
    else:
        altered["claim_boundary"] += " Accepted."
    _rehash(altered)

    with pytest.raises(TraceabilityError, match=message):
        _validate(altered, repository)


@pytest.mark.parametrize(
    "mutation",
    [
        "unmapped_id",
        "normative_text",
        "tbr_decision_or_value",
        "catalog_digest",
        "source_sha256",
        "source_git_blob",
    ],
)
def test_exact_validation_rejects_rehashed_canonical_baseline_forgery(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository = _repository(tmp_path)
    forged = copy.deepcopy(_report(repository))
    if mutation == "unmapped_id":
        old_id = "AOT-AUTH-004"
        new_id = "AOT-AUTH-999"
        record = next(
            item
            for item in forged["requirements"]
            if item["identity"]["requirement_id"] == old_id
        )
        record["identity"]["requirement_id"] = new_id
        unmapped = forged["coverage"]["unmapped_requirement_ids"]
        forged["coverage"]["unmapped_requirement_ids"] = sorted(
            new_id if item == old_id else item for item in unmapped
        )
    elif mutation == "normative_text":
        forged["requirements"][0]["identity"]["normative_text"] += " Forged."
    elif mutation == "tbr_decision_or_value":
        forged["tbrs"][0]["decision_or_value"] += " Forged."
    elif mutation == "catalog_digest":
        forged["catalog_sha256"] = "0" * 64
    elif mutation == "source_sha256":
        forged["source_binding"]["requirements"]["sha256"] = "0" * 64
    else:
        forged["source_binding"]["requirements"]["git_blob"] = "0" * 40
    _rehash(forged)

    with pytest.raises(TraceabilityError, match="exact current repository"):
        _validate(forged, repository)


def test_attestation_context_requires_exact_current_repo_binding_and_content(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    report = _report(repository)

    forged_binding = copy.deepcopy(report)
    forged_binding["source_binding"]["mapping"]["sha256"] = "0" * 64
    _rehash(forged_binding)
    with pytest.raises(TraceabilityError, match="exact current repository"):
        _attestation_context(forged_binding, repository)

    forged_content = copy.deepcopy(report)
    forged_content["requirements"][0]["identity"]["normative_text"] += " Forged."
    _rehash(forged_content)
    with pytest.raises(TraceabilityError, match="exact current repository"):
        _attestation_context(forged_content, repository)


def test_result_evidence_requires_clean_resolvable_exercised_source_identity(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    result_path = repository / "results/m4b-capability-evidence/manifest.json"
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["source_sha256"]["src/aegis_ot/evidence.py"] = "0" * 64
    result_path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    _git(repository, "add", "--", "results/m4b-capability-evidence/manifest.json")
    _git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "forged result source",
    )

    with pytest.raises(TraceabilityError, match="source inventory digest does not match"):
        _report(repository)


def test_committed_historical_results_bind_their_actual_exercised_source() -> None:
    commit = _git(ROOT, "rev-parse", "HEAD").strip()
    m4b = bind_historical_result(
        ROOT,
        commit,
        "results/m4b-capability-evidence/manifest.json",
    )
    m2 = bind_historical_result(
        ROOT,
        commit,
        "results/m2-independent-oracle/manifest.json",
    )

    assert m4b.relationship_to_current_source == "historical"
    assert m4b.exercised_git_commit == "ad3f3a9c861d53293c1b764226e33c7bcc991234"
    assert m4b.source_files_verified == 44
    assert m2.relationship_to_current_source == "historical"
    assert m2.exercised_git_commit == "cd20986ac31eb224d6678875e63f8e8a907d1b76"
    assert m2.source_files_verified == 3


def test_git_binding_uses_pinned_executable_sanitized_environment_and_real_git_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository(tmp_path)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "attacker.git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "attacker-worktree"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(tmp_path / "attacker-objects"))
    monkeypatch.setenv(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", str(tmp_path / "attacker-alternates")
    )
    monkeypatch.setenv("GIT_REPLACE_REF_BASE", "refs/attacker/")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "alias.show")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "!false")

    report = _report(repository)
    assert report["summary"]["requirements_open"] == 223

    real_git = repository / ".git"
    moved_git = repository / ".git-real"
    real_git.rename(moved_git)
    real_git.symlink_to(moved_git, target_is_directory=True)
    with pytest.raises(TraceabilityError, match="real directory"):
        _report(repository)


def test_git_binding_forces_fsmonitor_off_without_executing_repo_config(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    hook = tmp_path / "attacker-fsmonitor"
    marker = tmp_path / "fsmonitor-invoked"
    hook.write_text(
        '#!/bin/sh\n: > "${0%/*}/fsmonitor-invoked"\n',
        encoding="utf-8",
    )
    hook.chmod(0o700)
    _git(repository, "config", "core.fsmonitor", str(hook))

    report = _report(repository)

    assert report["summary"]["requirements_open"] == 223
    assert not marker.exists()


def test_git_binding_rejects_redirected_objects_and_alternate_stores(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    objects = repository / ".git/objects"
    outside_objects = tmp_path / "outside-objects"
    objects.rename(outside_objects)
    objects.symlink_to(outside_objects, target_is_directory=True)
    with pytest.raises(TraceabilityError, match="objects must be"):
        _report(repository)

    objects.unlink()
    outside_objects.rename(objects)
    alternates = objects / "info/alternates"
    alternates.write_text(str(tmp_path / "attacker-alternate"), encoding="utf-8")
    with pytest.raises(TraceabilityError, match="alternate object stores"):
        _report(repository)


def test_git_executable_rejects_a_substituted_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    substituted = tmp_path / "git"
    substituted.symlink_to("/usr/bin/git")
    monkeypatch.setattr(m8v2, "PINNED_GIT_EXECUTABLE", substituted)

    with pytest.raises(TraceabilityError, match="pinned Git executable"):
        m8v2._git_executable()


def test_replay_safe_attestation_ingestion_consumes_id_content_challenge_and_sequence(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    report = _report(repository)
    private_key = Ed25519PrivateKey.generate()
    authority = TrustedAttestationAuthority(
        authority_id="independent-assessor-fixture",
        public_key=private_key.public_key(),
        allowed_requirement_ids=frozenset({"AOT-EVID-001"}),
    )
    now = datetime(2026, 8, 26, 16, 0, tzinfo=UTC)
    state_dir = tmp_path / "private-state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    state_path = state_dir / "attestation-replay-state.json"
    first_context = _attestation_context(report, repository)
    first = _signed_attestation(first_context, private_key, authority, now)
    material = json.dumps(first, sort_keys=True).encode()

    ingested = ingest_external_attestation(
        material,
        authority=authority,
        context=first_context,
        now=now,
        state_path=state_path,
    )

    assert ingested["replay_safe_ingestion_completed"] is True
    assert ingested["automatic_requirement_acceptance"] is False
    assert ingested["independent_validation_established"] is False
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((state_dir / "attestation-replay-state.lock").stat().st_mode) == 0o600
    with pytest.raises(TraceabilityError, match="already consumed"):
        ingest_external_attestation(
            material,
            authority=authority,
            context=first_context,
            now=now,
            state_path=state_path,
        )

    second_context = _attestation_context(
        report,
        repository,
        challenge_nonce="second_challenge_0123456789abcdef",
    )
    nonmonotonic = _signed_attestation(
        second_context,
        private_key,
        authority,
        now,
        sequence=1,
        attestation_id="22345678-1234-4234-9234-1234567890ab",
    )
    with pytest.raises(TraceabilityError, match="not monotonic"):
        ingest_external_attestation(
            json.dumps(nonmonotonic, sort_keys=True).encode(),
            authority=authority,
            context=second_context,
            now=now,
            state_path=state_path,
        )

    second = _signed_attestation(
        second_context,
        private_key,
        authority,
        now,
        sequence=2,
        attestation_id="22345678-1234-4234-9234-1234567890ab",
    )
    ingested_second = ingest_external_attestation(
        json.dumps(second, sort_keys=True).encode(),
        authority=authority,
        context=second_context,
        now=now,
        state_path=state_path,
    )
    assert ingested_second["sequence"] == 2


def test_replay_store_rejects_nonprivate_directory_and_symlink_state(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    report = _report(repository)
    context = _attestation_context(report, repository)
    private_key = Ed25519PrivateKey.generate()
    authority = TrustedAttestationAuthority(
        authority_id="independent-assessor-fixture",
        public_key=private_key.public_key(),
        allowed_requirement_ids=frozenset({"AOT-EVID-001"}),
    )
    now = datetime(2026, 8, 26, 16, 0, tzinfo=UTC)
    material = json.dumps(
        _signed_attestation(context, private_key, authority, now), sort_keys=True
    ).encode()
    unsafe_dir = tmp_path / "unsafe-state"
    unsafe_dir.mkdir(mode=0o755)
    unsafe_dir.chmod(0o755)
    with pytest.raises(TraceabilityError, match="private, owned"):
        ingest_external_attestation(
            material,
            authority=authority,
            context=context,
            now=now,
            state_path=unsafe_dir / "attestation-replay-state.json",
        )


def test_mapping_loader_rejects_duplicate_json_keys_and_hard_links(tmp_path: Path) -> None:
    with pytest.raises(TraceabilityError, match="duplicate JSON key"):
        parse_evidence_mapping(
            b'{"schema":"one","schema":"two"}',
            known_requirement_ids=_known_ids(),
        )

    repository = _repository(tmp_path)
    commit = _git(repository, "rev-parse", "HEAD").strip()
    path = repository / "src/aegis_ot/safety.py"
    os.link(path, tmp_path / "outside-hard-link.py")
    with pytest.raises(TraceabilityError, match="regular non-link"):
        bind_committed_file(repository, commit, "src/aegis_ot/safety.py")
