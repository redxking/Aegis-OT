from __future__ import annotations

import base64
import copy
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_m8_evidence_traceability import _mapping_value, _report, _repository

import aegis_ot.m8_evidence_traceability as m8

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 26, 16, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def exact_report(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    repository = _repository(tmp_path_factory.mktemp("m8-contract-repository"))
    return repository, _report(repository)


def _mapping_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _rehash_replay_state(state: dict[str, Any]) -> dict[str, Any]:
    state.pop("integrity", None)
    state["integrity"] = {"canonical_payload_sha256": m8.sha256_json(state)}
    return state


def _first_mapped(report: dict[str, Any]) -> dict[str, Any]:
    return next(item for item in report["requirements"] if "evidence_mapping" in item)


def _first_unmapped(report: dict[str, Any]) -> dict[str, Any]:
    return next(item for item in report["requirements"] if "evidence_mapping" not in item)


def _shared_current_records(report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    by_path: dict[str, list[dict[str, Any]]] = {}
    for record in report["requirements"]:
        for binding in record["verification"]["artifact"]:
            by_path.setdefault(binding["path"], []).append(record)
    return next((records[0], records[1]) for records in by_path.values() if len(records) > 1)


def _shared_historical_records(report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    by_path: dict[str, list[dict[str, Any]]] = {}
    for record in report["requirements"]:
        evidence = record.get("evidence_mapping", {})
        for retained in evidence.get("historical_result_evidence", []):
            by_path.setdefault(retained["artifact"]["path"], []).append(record)
    return next((records[0], records[1]) for records in by_path.values() if len(records) > 1)


@pytest.mark.parametrize(
    ("material", "message"),
    [
        (b"", "size is outside"),
        (b"\xff", "not strict UTF-8 JSON"),
        (b"[]", "root must be an object"),
        (b'{"value":NaN}', "nonfinite JSON value"),
    ],
)
def test_strict_json_boundary_rejects_ambiguous_material(
    material: bytes,
    message: str,
) -> None:
    with pytest.raises(m8.TraceabilityError, match=message):
        m8.load_strict_json_bytes(material, label="fixture")


def test_canonical_json_boundary_rejects_nonserializable_material() -> None:
    with pytest.raises(m8.TraceabilityError, match="canonical finite JSON"):
        m8.canonical_json_bytes({"unsupported": object()})


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("top_fields", "fields are not exact"),
        ("schema", "schema is unsupported"),
        ("baseline", "proposed baseline status"),
        ("approval", "explicitly unapproved"),
        ("mapping_id", "canonical text"),
        ("independent", "self-assert independent"),
        ("entries", "at least one explicit entry"),
        ("entry_object", "string-keyed object"),
        ("entry_fields", "fields are not exact"),
        ("procedures_empty", "allowed number of strings"),
        ("procedures_values", "only nonempty strings"),
        ("procedures_order", "unique and lexically sorted"),
        ("procedure_id", "unsupported test ID"),
        ("implementation_type", "allowed number of strings"),
        ("implementation_value", "only nonempty strings"),
        ("unsafe_path", "unsafe or overbroad"),
        ("too_many_paths", "maps too many repository paths"),
        ("blank_owner", "canonical text"),
    ],
)
def test_mapping_parser_rejects_noncanonical_or_overbroad_links(
    mutation: str,
    message: str,
) -> None:
    value = _mapping_value()
    entry = value["entries"][0]
    if mutation == "top_fields":
        value["unexpected"] = True
    elif mutation == "schema":
        value["schema"] = "unsupported"
    elif mutation == "baseline":
        value["baseline_status"] = "approved"
    elif mutation == "approval":
        value["approval_state"] = "approved"
    elif mutation == "mapping_id":
        value["mapping_id"] = " "
    elif mutation == "independent":
        value["review_authority"] = "independent assessor"
    elif mutation == "entries":
        value["entries"] = []
    elif mutation == "entry_object":
        value["entries"] = ["not-an-object"]
    elif mutation == "entry_fields":
        entry.pop("limitations")
    elif mutation == "procedures_empty":
        entry["procedure_or_test_ids"] = []
    elif mutation == "procedures_values":
        entry["procedure_or_test_ids"] = [""]
    elif mutation == "procedures_order":
        procedure = entry["procedure_or_test_ids"][0]
        entry["procedure_or_test_ids"] = [procedure, procedure]
    elif mutation == "procedure_id":
        entry["procedure_or_test_ids"] = ["pytest::tests/test_x.py::helper"]
    elif mutation == "implementation_type":
        entry["implementation_artifacts"] = "src/aegis_ot/evidence.py"
    elif mutation == "implementation_value":
        entry["implementation_artifacts"] = [""]
    elif mutation == "unsafe_path":
        entry["implementation_artifacts"] = ["src/../secrets"]
    elif mutation == "too_many_paths":
        entry["implementation_artifacts"] = sorted(
            f"src/component_{index}.py" for index in range(24)
        )
        entry["result_artifacts"] = []
        entry["result_artifact_state"] = "no_result_artifact"
    else:
        entry["owner"] = " owner "

    with pytest.raises(m8.TraceabilityError, match=message):
        m8.parse_evidence_mapping(_mapping_bytes(value), known_requirement_ids=frozenset({
            item["requirement_id"] for item in value["entries"] if isinstance(item, dict)
        }))


def test_procedure_boundary_rejects_noncanonical_identifier() -> None:
    with pytest.raises(m8.TraceabilityError, match="test procedure ID is noncanonical"):
        m8._procedure_path_and_name("pytest::tests/test_x.py::helper")


def _mutate_report(report: dict[str, Any], mutation: str) -> None:
    mapped = _first_mapped(report)
    unmapped = _first_unmapped(report)
    if mutation == "report_fields":
        report["unexpected"] = True
    elif mutation == "schema":
        report["schema"] = "unsupported"
    elif mutation == "source_fields":
        report["source_binding"].pop("git_tree")
    elif mutation == "source_identity":
        report["source_binding"]["git_commit"] = "invalid"
    elif mutation == "binding_fields":
        report["source_binding"]["requirements"].pop("bytes")
    elif mutation == "binding_value":
        report["source_binding"]["requirements"]["bytes"] = 0
    elif mutation == "binding_path":
        report["source_binding"]["requirements"]["path"] = "../outside"
    elif mutation == "source_conflict":
        report["source_binding"]["mapping"]["path"] = report["source_binding"][
            "requirements"
        ]["path"]
    elif mutation == "mapping_fields":
        report["mapping"].pop("mapping_id")
    elif mutation == "mapping_metadata":
        report["mapping"]["approval_state"] = "approved"
    elif mutation == "summary_fields":
        report["summary"].pop("requirements_open")
    elif mutation == "summary_state":
        report["summary"]["requirements_accepted"] = 1
    elif mutation == "requirements_count":
        report["requirements"].pop()
    elif mutation == "requirement_fields":
        mapped["unexpected"] = True
    elif mutation == "identity_fields":
        mapped["identity"].pop("revision")
    elif mutation == "requirement_id":
        mapped["identity"]["requirement_id"] = "invalid"
    elif mutation == "requirement_open_state":
        mapped["disposition"]["finding_status"] = "accepted"
    elif mutation == "duplicate_requirements":
        report["requirements"][1]["identity"]["requirement_id"] = report["requirements"][0][
            "identity"
        ]["requirement_id"]
    elif mutation == "tbr_count":
        report["tbrs"].pop()
    elif mutation == "tbr_order":
        report["tbrs"][0]["tbr_id"] = "TBR-999"
    elif mutation == "tbr_open":
        report["tbrs"][0]["status"] = "closed"
    elif mutation == "gates":
        report["gates"]["G0"] = "Approved"
    elif mutation == "claims":
        report["claim_states"]["C0"] = "Accepted"
    elif mutation == "catalog":
        report["catalog_sha256"] = "invalid"
    elif mutation == "inverse_fields":
        report["inverse_index"].pop("procedures")
    elif mutation == "coverage_fields":
        report["coverage"].pop("unmapped_requirement_ids")
    elif mutation == "coverage_list":
        report["coverage"]["mapped_requirement_ids"] = ["AOT-ZZZ-999", "AOT-AAA-001"]
    elif mutation == "coverage_mismatch":
        report["coverage"]["unmapped_requirement_ids"].pop()
    elif mutation == "forward_fields":
        first_id = report["coverage"]["mapped_requirement_ids"][0]
        report["forward_index"][first_id].pop("owner")
    elif mutation == "role_fields":
        first_id = report["coverage"]["mapped_requirement_ids"][0]
        report["forward_index"][first_id]["artifact_paths_by_role"]["unexpected"] = []
    elif mutation == "role_paths":
        first_id = report["coverage"]["mapped_requirement_ids"][0]
        report["forward_index"][first_id]["artifact_paths_by_role"]["implementation"] = [
            "z.py",
            "a.py",
        ]
    elif mutation == "role_conflict":
        requirement_id = mapped["identity"]["requirement_id"]
        roles = report["forward_index"][requirement_id]["artifact_paths_by_role"]
        roles["procedure"] = [roles["implementation"][0]]
    elif mutation == "procedure_paths":
        requirement_id = mapped["identity"]["requirement_id"]
        report["forward_index"][requirement_id]["procedure_or_test_ids"] = []
    elif mutation == "mapped_semantics":
        mapped["verification"]["result"] = "passed"
    elif mutation == "artifact_list":
        mapped["verification"]["artifact"] = "not-a-list"
    elif mutation == "current_binding_conflict":
        _, second = _shared_current_records(report)
        second["verification"]["artifact"][0]["sha256"] = "0" * 64
    elif mutation == "historical_length":
        mapped["evidence_mapping"]["historical_result_evidence"] = []
    elif mutation == "historical_identity":
        mapped["evidence_mapping"]["historical_result_evidence"][0][
            "relationship_to_current_source"
        ] = "current_exact"
    elif mutation == "historical_binding_fields":
        mapped["evidence_mapping"]["historical_result_evidence"][0]["artifact"].pop("bytes")
    elif mutation == "historical_binding_conflict":
        _, second = _shared_historical_records(report)
        second["evidence_mapping"]["historical_result_evidence"][0][
            "exercised_git_commit"
        ] = "0" * 40
    elif mutation == "historical_paths":
        mapped["evidence_mapping"]["historical_result_evidence"][0]["artifact"][
            "path"
        ] = "results/different.json"
    elif mutation == "unmapped_evidence":
        unmapped["verification"]["result"] = "not_executed"
    elif mutation == "inverse_values":
        report["inverse_index"]["artifacts"] = []
    elif mutation == "inverse_artifact_paths":
        report["inverse_index"]["artifacts"].pop(next(iter(report["inverse_index"]["artifacts"])))
    elif mutation == "inverse_artifact":
        report["inverse_index"]["artifacts"][next(iter(report["inverse_index"]["artifacts"]))][
            "roles"
        ] = []
    elif mutation == "inverse_procedure":
        report["inverse_index"]["procedures"] = {}
    elif mutation == "inverse_historical_paths":
        report["inverse_index"]["historical_results"] = {}
    elif mutation == "inverse_historical":
        report["inverse_index"]["historical_results"][
            next(iter(report["inverse_index"]["historical_results"]))
        ]["requirement_ids"] = []
    elif mutation == "external_attestations":
        report["external_attestations"] = [{"asserted": True}]
    elif mutation == "attestation_interface":
        report["attestation_interface"]["automatic_requirement_acceptance"] = True
    elif mutation == "claim_boundary":
        report["claim_boundary"] = "Accepted"
    elif mutation == "content_hash":
        report["content_sha256"] = "0" * 64
    else:
        raise AssertionError(f"unknown mutation: {mutation}")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("report_fields", "fields or schema"),
        ("schema", "fields or schema"),
        ("source_fields", "source-binding fields"),
        ("source_identity", "source commit or tree"),
        ("binding_fields", "binding fields"),
        ("binding_value", "binding is noncanonical"),
        ("binding_path", "repository path"),
        ("source_conflict", "source bindings conflict"),
        ("mapping_fields", "mapping metadata fields"),
        ("mapping_metadata", "mapping metadata is not bounded"),
        ("summary_fields", "summary fields"),
        ("summary_state", "exact open state"),
        ("requirements_count", "retain all requirements"),
        ("requirement_fields", "requirement record fields"),
        ("identity_fields", "identity fields"),
        ("requirement_id", "identifier is noncanonical"),
        ("requirement_open_state", "not exactly open"),
        ("duplicate_requirements", "duplicated or incomplete"),
        ("tbr_count", "retain all TBRs"),
        ("tbr_order", "TBR identities"),
        ("tbr_open", "TBRs is not explicitly open"),
        ("gates", "gate catalog"),
        ("claims", "claim-state catalog"),
        ("catalog", "catalog digest"),
        ("inverse_fields", "forward or inverse"),
        ("coverage_fields", "coverage fields"),
        ("coverage_list", "unique sorted string list"),
        ("coverage_mismatch", "coverage and forward index"),
        ("forward_fields", "forward link fields"),
        ("role_fields", "artifact roles"),
        ("role_paths", "unique sorted string list"),
        ("role_conflict", "artifact roles conflict"),
        ("procedure_paths", "procedure IDs and procedure artifacts"),
        ("mapped_semantics", "mapped requirement semantics"),
        ("artifact_list", "current artifact bindings"),
        ("current_binding_conflict", "binding conflicts across requirements"),
        ("historical_length", "historical result evidence"),
        ("historical_identity", "historical result source identity"),
        ("historical_binding_fields", "binding fields"),
        ("historical_binding_conflict", "historical result binding conflicts"),
        ("historical_paths", "paths and evidence"),
        ("unmapped_evidence", "unmapped requirement contains inferred"),
        ("inverse_values", "inverse index values"),
        ("inverse_artifact_paths", "artifact inverse index path set"),
        ("inverse_artifact", "artifact inverse index is inconsistent"),
        ("inverse_procedure", "procedure inverse index"),
        ("inverse_historical_paths", "historical result inverse index path set"),
        ("inverse_historical", "historical result inverse index is inconsistent"),
        ("external_attestations", "must not contain fabricated"),
        ("attestation_interface", "attestation boundaries"),
        ("claim_boundary", "claim boundary"),
        ("content_hash", "content digest"),
    ],
)
def test_structural_validator_rejects_rehashed_claim_and_index_forgeries(
    exact_report: tuple[Path, dict[str, Any]],
    mutation: str,
    message: str,
) -> None:
    report = copy.deepcopy(exact_report[1])
    _mutate_report(report, mutation)

    with pytest.raises(m8.TraceabilityError, match=message):
        m8._validate_evidence_traceability_structure(report)


def test_structural_validator_accepts_the_exact_open_report(
    exact_report: tuple[Path, dict[str, Any]],
) -> None:
    m8._validate_evidence_traceability_structure(exact_report[1])


def _attestation_fixture() -> tuple[
    Ed25519PrivateKey,
    m8.TrustedAttestationAuthority,
    m8.AttestationContext,
]:
    private = Ed25519PrivateKey.generate()
    authority = m8.TrustedAttestationAuthority(
        authority_id="independent-assessor-fixture",
        public_key=private.public_key(),
        allowed_requirement_ids=frozenset({"AOT-EVID-001", "AOT-EVID-005"}),
    )
    first = m8.AttestedArtifactBinding("src/a.py", "1" * 64, "2" * 40)
    second = m8.AttestedArtifactBinding("src/b.py", "3" * 64, "4" * 40)
    context = m8.AttestationContext(
        requirements_source_sha256="5" * 64,
        git_commit="6" * 40,
        git_tree="7" * 40,
        mapping_sha256="8" * 64,
        traceability_content_sha256="9" * 64,
        purpose="requirements-evidence-attestation",
        audience="aegis-ot-assurance-authority",
        challenge_nonce="challenge_nonce_0123456789abcdef",
        artifacts_by_requirement={
            "AOT-EVID-001": (first,),
            "AOT-EVID-005": (second,),
        },
    )
    return private, authority, context


def _signed_attestation(
    private: Ed25519PrivateKey,
    authority: m8.TrustedAttestationAuthority,
    context: m8.AttestationContext,
    *,
    requirement_ids: list[str] | None = None,
) -> dict[str, Any]:
    selected = requirement_ids or ["AOT-EVID-001"]
    unsigned: dict[str, Any] = {
        "schema": m8.ATTESTATION_SCHEMA,
        "attestation_id": "12345678-1234-4234-9234-1234567890ab",
        "authority_id": authority.authority_id,
        "key_id": authority.key_id,
        "issued_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=1)).isoformat(),
        "requirements_source_sha256": context.requirements_source_sha256,
        "git_commit": context.git_commit,
        "git_tree": context.git_tree,
        "mapping_sha256": context.mapping_sha256,
        "traceability_content_sha256": context.traceability_content_sha256,
        "purpose": context.purpose,
        "audience": context.audience,
        "challenge_nonce": context.challenge_nonce,
        "sequence": 1,
        "requirement_ids": selected,
        "findings": [
            {
                "requirement_id": requirement_id,
                "disposition": "inconclusive",
                "statement": "Bounded external assessment fixture.",
                "artifact_bindings": [
                    item.as_dict() for item in context.artifacts_by_requirement[requirement_id]
                ],
            }
            for requirement_id in selected
        ],
    }
    return _resign(unsigned, private)


def _resign(value: dict[str, Any], private: Ed25519PrivateKey) -> dict[str, Any]:
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    signature = private.sign(m8.attestation_signing_bytes(unsigned))
    return {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii"),
    }


def _attestation_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _mutate_attestation(
    value: dict[str, Any],
    mutation: str,
    context: m8.AttestationContext,
) -> datetime:
    verification_time = NOW
    if mutation == "schema":
        value["schema"] = "unsupported"
    elif mutation == "authority":
        value["authority_id"] = "untrusted"
    elif mutation == "id":
        value["attestation_id"] = "not-a-uuid"
    elif mutation == "naive_now":
        verification_time = NOW.replace(tzinfo=None)
    elif mutation == "issued_type":
        value["issued_at"] = 1
    elif mutation == "issued_syntax":
        value["issued_at"] = "not-a-time"
    elif mutation == "issued_zone":
        value["issued_at"] = (NOW - timedelta(minutes=1)).replace(tzinfo=None).isoformat()
    elif mutation == "future":
        value["issued_at"] = (NOW + timedelta(minutes=6)).isoformat()
    elif mutation == "stale":
        value["issued_at"] = (NOW - timedelta(days=31)).isoformat()
    elif mutation == "validity":
        value["expires_at"] = (NOW + timedelta(days=32)).isoformat()
    elif mutation == "unmapped":
        value["requirement_ids"] = ["AOT-SYS-001"]
        value["findings"] = []
    elif mutation == "findings_length":
        value["findings"] = []
    elif mutation == "finding_object":
        value["findings"] = ["not-an-object"]
    elif mutation == "disposition":
        value["findings"][0]["disposition"] = "accepted"
    elif mutation == "artifacts_list":
        value["findings"][0]["artifact_bindings"] = "not-a-list"
    elif mutation == "artifact_object":
        value["findings"][0]["artifact_bindings"] = ["not-an-object"]
    elif mutation == "artifact_digest":
        value["findings"][0]["artifact_bindings"][0]["sha256"] = "invalid"
    elif mutation == "finding_order":
        value["requirement_ids"] = ["AOT-EVID-001", "AOT-EVID-005"]
        value["findings"] = [
            {
                "requirement_id": requirement_id,
                "disposition": "inconclusive",
                "statement": "Bounded external assessment fixture.",
                "artifact_bindings": [
                    item.as_dict() for item in context.artifacts_by_requirement[requirement_id]
                ],
            }
            for requirement_id in reversed(value["requirement_ids"])
        ]
    else:
        raise AssertionError(f"unknown mutation: {mutation}")
    return verification_time


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("schema", "schema is unsupported"),
        ("authority", "configured authority"),
        ("id", "canonical UUID"),
        ("naive_now", "timezone-aware"),
        ("issued_type", "canonical UTC text"),
        ("issued_syntax", "not a valid timestamp"),
        ("issued_zone", "timezone-aware UTC text"),
        ("future", "too far in the future"),
        ("stale", "is stale"),
        ("validity", "validity interval"),
        ("unmapped", "unmapped requirement"),
        ("findings_length", "findings do not match"),
        ("finding_object", "must be an object"),
        ("disposition", "disposition is invalid"),
        ("artifacts_list", "artifacts are invalid"),
        ("artifact_object", "artifact is not an object"),
        ("artifact_digest", "artifact digest is invalid"),
        ("finding_order", "unique and ordered"),
    ],
)
def test_attestation_verifier_rejects_malformed_trust_and_scope_claims(
    mutation: str,
    message: str,
) -> None:
    private, authority, context = _attestation_fixture()
    value = _signed_attestation(private, authority, context)
    verification_time = _mutate_attestation(value, mutation, context)
    value = _resign(value, private)
    if mutation == "unmapped":
        authority = m8.TrustedAttestationAuthority(
            authority_id=authority.authority_id,
            public_key=private.public_key(),
            allowed_requirement_ids=authority.allowed_requirement_ids | {"AOT-SYS-001"},
        )

    with pytest.raises(m8.TraceabilityError, match=message):
        m8.verify_external_attestation_stateless(
            _attestation_bytes(value),
            authority=authority,
            context=context,
            now=verification_time,
        )


@pytest.mark.parametrize(
    ("signature", "message"),
    [
        (1, "canonical URL-safe Base64"),
        ("not+urlsafe", "not canonical URL-safe Base64"),
        (base64.urlsafe_b64encode(b"short").decode("ascii"), "canonical Ed25519 Base64"),
    ],
)
def test_attestation_verifier_rejects_noncanonical_signature_encodings(
    signature: Any,
    message: str,
) -> None:
    private, authority, context = _attestation_fixture()
    value = _signed_attestation(private, authority, context)
    value["signature"] = signature

    with pytest.raises(m8.TraceabilityError, match=message):
        m8.verify_external_attestation_stateless(
            _attestation_bytes(value),
            authority=authority,
            context=context,
            now=NOW,
        )


def test_signing_boundary_rejects_material_that_already_contains_a_signature() -> None:
    with pytest.raises(m8.TraceabilityError, match="contains a signature"):
        m8.attestation_signing_bytes({"signature": "self-declared"})


@pytest.mark.parametrize(
    ("authority_id", "scope", "age", "validity", "skew", "message"),
    [
        (
            " ",
            frozenset({"AOT-EVID-001"}),
            timedelta(days=1),
            timedelta(days=1),
            timedelta(0),
            "ID",
        ),
        ("authority", frozenset(), timedelta(days=1), timedelta(days=1), timedelta(0), "scope"),
        (
            "authority",
            frozenset({"AOT-EVID-001"}),
            timedelta(0),
            timedelta(days=1),
            timedelta(0),
            "freshness",
        ),
        (
            "authority",
            frozenset({"AOT-EVID-001"}),
            timedelta(days=1),
            timedelta(0),
            timedelta(0),
            "freshness",
        ),
        (
            "authority",
            frozenset({"AOT-EVID-001"}),
            timedelta(days=1),
            timedelta(days=1),
            timedelta(seconds=-1),
            "freshness",
        ),
    ],
)
def test_trusted_authority_rejects_ambiguous_scope_or_freshness(
    authority_id: str,
    scope: frozenset[str],
    age: timedelta,
    validity: timedelta,
    skew: timedelta,
    message: str,
) -> None:
    public = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(m8.TraceabilityError, match=message):
        m8.TrustedAttestationAuthority(
            authority_id=authority_id,
            public_key=public,
            allowed_requirement_ids=scope,
            maximum_age=age,
            maximum_validity=validity,
            future_skew=skew,
        )


def _consumed(
    *,
    attestation_id: str = "12345678-1234-4234-9234-1234567890ab",
    digest: str = "a" * 64,
    nonce: str = "challenge_nonce_0123456789abcdef",
    sequence: int = 1,
) -> dict[str, Any]:
    return {
        "attestation_id": attestation_id,
        "content_sha256": digest,
        "challenge_nonce": nonce,
        "sequence": sequence,
    }


def _populated_replay_state() -> dict[str, Any]:
    entry = {
        "authority_id": "independent-assessor-fixture",
        "key_id": "ed25519-sha256:" + "b" * 64,
        "highest_sequence": 1,
        "consumed": [_consumed()],
    }
    return _rehash_replay_state(
        {
            "schema": m8.ATTESTATION_REPLAY_SCHEMA,
            "authorities": {entry["key_id"]: entry},
        }
    )


def _mutate_replay_state(state: dict[str, Any], mutation: str) -> None:
    entry = next(iter(state["authorities"].values()))
    if mutation == "fields":
        state["extra"] = True
    elif mutation == "schema":
        state["schema"] = "unsupported"
    elif mutation == "authorities":
        state["authorities"] = []
    elif mutation == "authority_entry":
        entry["highest_sequence"] = -1
    elif mutation == "consumed_log":
        entry["consumed"] = "not-a-list"
    elif mutation == "consumed_fields":
        entry["consumed"][0].pop("sequence")
    elif mutation == "consumed_value":
        entry["consumed"][0]["content_sha256"] = "invalid"
    elif mutation == "duplicate_id":
        duplicate = copy.deepcopy(entry["consumed"][0])
        duplicate["content_sha256"] = "c" * 64
        duplicate["challenge_nonce"] = "different_challenge_0123456789abc"
        duplicate["sequence"] = 2
        entry["consumed"].append(duplicate)
        entry["highest_sequence"] = 2
    elif mutation == "sequence_order":
        second = _consumed(
            attestation_id="22345678-1234-4234-9234-1234567890ab",
            digest="c" * 64,
            nonce="different_challenge_0123456789abc",
            sequence=2,
        )
        entry["consumed"] = [second, entry["consumed"][0]]
        entry["highest_sequence"] = 2
    elif mutation == "highest_sequence":
        entry["highest_sequence"] = 2
    elif mutation == "integrity":
        state["integrity"]["canonical_payload_sha256"] = "0" * 64
        return
    else:
        raise AssertionError(f"unknown mutation: {mutation}")
    _rehash_replay_state(state)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("fields", "fields are not exact"),
        ("schema", "schema is unsupported"),
        ("authorities", "authority catalog"),
        ("authority_entry", "authority entry"),
        ("consumed_log", "consumption log"),
        ("consumed_fields", "consumed entry"),
        ("consumed_value", "consumed value"),
        ("duplicate_id", "monotonic history"),
        ("sequence_order", "monotonic history"),
        ("highest_sequence", "monotonic history"),
        ("integrity", "integrity is invalid"),
    ],
)
def test_replay_state_validator_rejects_rollback_and_duplicate_history(
    mutation: str,
    message: str,
) -> None:
    state = _populated_replay_state()
    _mutate_replay_state(state, mutation)
    with pytest.raises(m8.TraceabilityError, match=message):
        m8._validate_replay_state(state)


def test_replay_state_validator_accepts_empty_and_monotonic_history() -> None:
    m8._validate_replay_state(m8._initial_replay_state())
    m8._validate_replay_state(_populated_replay_state())


@pytest.mark.parametrize("relative", [Path("state.json"), ROOT / "wrong-name.json"])
def test_replay_store_requires_absolute_fixed_state_path(relative: Path) -> None:
    with pytest.raises(m8.TraceabilityError, match="absolute and use the fixed filename"):
        m8._private_state_parent(relative)


def test_replay_store_requires_an_existing_private_real_directory(tmp_path: Path) -> None:
    with pytest.raises(m8.TraceabilityError, match="directory is unavailable"):
        m8._private_state_parent(tmp_path / "missing" / "attestation-replay-state.json")

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    unsafe.chmod(0o755)
    with pytest.raises(m8.TraceabilityError, match="private, owned"):
        m8._private_state_parent(unsafe / "attestation-replay-state.json")


def test_replay_lock_rejects_symlink_and_nonprivate_file(tmp_path: Path) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    target = directory / "target"
    target.write_text("target", encoding="utf-8")
    (directory / "attestation-replay-state.lock").symlink_to(target)
    parent_fd = os.open(directory, os.O_RDONLY)
    try:
        with pytest.raises(m8.TraceabilityError, match="cannot be opened safely"):
            m8._open_private_lock(parent_fd)
    finally:
        os.close(parent_fd)

    (directory / "attestation-replay-state.lock").unlink()
    (directory / "attestation-replay-state.lock").write_text("lock", encoding="utf-8")
    (directory / "attestation-replay-state.lock").chmod(0o644)
    parent_fd = os.open(directory, os.O_RDONLY)
    try:
        with pytest.raises(m8.TraceabilityError, match="not a private owned file"):
            m8._open_private_lock(parent_fd)
    finally:
        os.close(parent_fd)


def test_replay_reader_rejects_symlink_unsafe_mode_and_short_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    state_path = directory / "attestation-replay-state.json"
    target = directory / "target"
    target.write_text("{}", encoding="utf-8")
    state_path.symlink_to(target)
    parent_fd = os.open(directory, os.O_RDONLY)
    try:
        with pytest.raises(m8.TraceabilityError, match="cannot be opened safely"):
            m8._read_replay_state(parent_fd)
    finally:
        os.close(parent_fd)

    state_path.unlink()
    state_path.write_text(json.dumps(m8._initial_replay_state()), encoding="utf-8")
    state_path.chmod(0o644)
    parent_fd = os.open(directory, os.O_RDONLY)
    try:
        with pytest.raises(m8.TraceabilityError, match="file is unsafe"):
            m8._read_replay_state(parent_fd)
    finally:
        os.close(parent_fd)

    state_path.chmod(0o600)
    parent_fd = os.open(directory, os.O_RDONLY)
    monkeypatch.setattr(m8.os, "read", lambda _fd, _count: b"")
    try:
        with pytest.raises(m8.TraceabilityError, match="changed while reading"):
            m8._read_replay_state(parent_fd)
    finally:
        os.close(parent_fd)


def test_replay_writer_rejects_oversize_and_atomic_write_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    parent_fd = os.open(directory, os.O_RDONLY)
    oversized = _populated_replay_state()
    entry = next(iter(oversized["authorities"].values()))
    entry["authority_id"] = "x" * m8.MAX_JSON_BYTES
    _rehash_replay_state(oversized)
    try:
        with pytest.raises(m8.TraceabilityError, match="exceeds its size limit"):
            m8._write_replay_state(parent_fd, oversized)
    finally:
        os.close(parent_fd)

    parent_fd = os.open(directory, os.O_RDONLY)
    original_open = m8.os.open

    def deny_temporary(path: Any, *args: Any, **kwargs: Any) -> int:
        if isinstance(path, str) and path.startswith(".attestation-replay-state."):
            raise OSError("denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(m8.os, "open", deny_temporary)
    try:
        with pytest.raises(m8.TraceabilityError, match="cannot be committed atomically"):
            m8._write_replay_state(parent_fd, m8._initial_replay_state())
    finally:
        os.close(parent_fd)


def test_replay_writer_closes_partial_temporary_file_after_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    parent_fd = os.open(directory, os.O_RDONLY)
    monkeypatch.setattr(m8.os, "fchmod", lambda _fd, _mode: (_ for _ in ()).throw(OSError()))
    try:
        with pytest.raises(m8.TraceabilityError, match="cannot be committed atomically"):
            m8._write_replay_state(parent_fd, m8._initial_replay_state())
    finally:
        os.close(parent_fd)


def _verified_ingestion_record(
    authority: m8.TrustedAttestationAuthority,
    *,
    attestation_id: str = "12345678-1234-4234-9234-1234567890ab",
    digest: str = "d" * 64,
    nonce: str = "challenge_nonce_0123456789abcdef",
    sequence: int = 2,
) -> dict[str, Any]:
    return {
        "attestation_id": attestation_id,
        "authority_id": authority.authority_id,
        "key_id": authority.key_id,
        "challenge_nonce": nonce,
        "sequence": sequence,
        "attestation_content_sha256": digest,
        "replay_safe_ingestion_completed": False,
        "automatic_requirement_acceptance": False,
        "independent_validation_established": False,
    }


def _write_state_fixture(path: Path, state: dict[str, Any]) -> None:
    path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)


def _ingest_with_verified_record(
    state_path: Path,
    authority: m8.TrustedAttestationAuthority,
    context: m8.AttestationContext,
) -> dict[str, Any]:
    return m8.ingest_external_attestation(
        b"verification-is-patched-to-a-validated-record",
        authority=authority,
        context=context,
        now=NOW,
        state_path=state_path,
    )


def test_ingestion_rejects_directory_race_and_lock_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, authority, context = _attestation_fixture()
    verified = _verified_ingestion_record(authority)
    monkeypatch.setattr(
        m8,
        "verify_external_attestation_stateless",
        lambda *_args, **_kwargs: verified,
    )
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    state_path = directory / "attestation-replay-state.json"
    original_fstat = m8.os.fstat

    def changed_inode(descriptor: int) -> os.stat_result:
        result = original_fstat(descriptor)
        fields = list(result)
        fields[1] += 1
        return os.stat_result(fields)

    with monkeypatch.context() as race:
        race.setattr(
            m8,
            "verify_external_attestation_stateless",
            lambda *_args, **_kwargs: verified,
        )
        race.setattr(m8.os, "fstat", changed_inode)
        with pytest.raises(m8.TraceabilityError, match="directory changed while opening"):
            _ingest_with_verified_record(state_path, authority, context)

    monkeypatch.setattr(
        m8,
        "_open_private_lock",
        lambda _fd: (_ for _ in ()).throw(m8.TraceabilityError("lock failure")),
    )
    with pytest.raises(m8.TraceabilityError, match="lock failure"):
        _ingest_with_verified_record(state_path, authority, context)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("authority", "authority conflicts"),
        ("content", "content was already consumed"),
        ("challenge", "challenge was already consumed"),
        ("capacity", "capacity is exhausted"),
    ],
)
def test_ingestion_rejects_replay_aliases_and_capacity_exhaustion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    _, authority, context = _attestation_fixture()
    verified = _verified_ingestion_record(authority)
    monkeypatch.setattr(
        m8,
        "verify_external_attestation_stateless",
        lambda *_args, **_kwargs: verified,
    )
    directory = tmp_path / mutation
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    state_path = directory / "attestation-replay-state.json"
    consumed = _consumed(
        attestation_id="22345678-1234-4234-9234-1234567890ab",
        digest="e" * 64,
        nonce="different_challenge_0123456789abc",
    )
    entry = {
        "authority_id": authority.authority_id,
        "key_id": authority.key_id,
        "highest_sequence": 1,
        "consumed": [consumed],
    }
    if mutation == "authority":
        entry["authority_id"] = "different-authority"
    elif mutation == "content":
        consumed["content_sha256"] = verified["attestation_content_sha256"]
    elif mutation == "challenge":
        consumed["challenge_nonce"] = verified["challenge_nonce"]
    else:
        entry["consumed"] = [consumed] * 10_000
        monkeypatch.setattr(
            m8,
            "_read_replay_state",
            lambda _fd: {
                "schema": m8.ATTESTATION_REPLAY_SCHEMA,
                "authorities": {authority.key_id: entry},
                "integrity": {},
            },
        )
    state = _rehash_replay_state(
        {
            "schema": m8.ATTESTATION_REPLAY_SCHEMA,
            "authorities": {authority.key_id: entry},
        }
    )
    if mutation != "capacity":
        _write_state_fixture(state_path, state)

    with pytest.raises(m8.TraceabilityError, match=message):
        _ingest_with_verified_record(state_path, authority, context)


def test_attestation_context_rejects_unbounded_purpose_and_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(m8, "validate_evidence_traceability", lambda *_args, **_kwargs: None)
    with pytest.raises(m8.TraceabilityError, match="purpose is not bounded"):
        m8.attestation_context(
            {},
            root=ROOT,
            requirements_path=m8.AUTHORITATIVE_REQUIREMENTS_PATH,
            mapping_path=m8.AUTHORITATIVE_MAPPING_PATH,
            purpose=" ",
            audience="bounded-audience",
            challenge_nonce="challenge_nonce_0123456789abcdef",
        )
    with pytest.raises(m8.TraceabilityError, match="challenge nonce is noncanonical"):
        m8.attestation_context(
            {},
            root=ROOT,
            requirements_path=m8.AUTHORITATIVE_REQUIREMENTS_PATH,
            mapping_path=m8.AUTHORITATIVE_MAPPING_PATH,
            purpose="bounded-purpose",
            audience="bounded-audience",
            challenge_nonce="short",
        )


def test_local_git_config_rejects_missing_unsafe_and_executable_configuration(
    tmp_path: Path,
) -> None:
    owner = os.getuid()
    missing = tmp_path / "missing"
    missing.mkdir()
    with pytest.raises(m8.TraceabilityError, match="config is unavailable"):
        m8._validate_local_git_config(missing, owner=owner)

    wrong_type = tmp_path / "wrong-type"
    (wrong_type / "config").mkdir(parents=True)
    with pytest.raises(m8.TraceabilityError, match="not a bounded owned file"):
        m8._validate_local_git_config(wrong_type, owner=owner)

    non_utf8 = tmp_path / "non-utf8"
    non_utf8.mkdir()
    (non_utf8 / "config").write_bytes(b"\xff")
    with pytest.raises(m8.TraceabilityError, match="config is not UTF-8"):
        m8._validate_local_git_config(non_utf8, owner=owner)

    executable = tmp_path / "executable"
    executable.mkdir()
    (executable / "config").write_text('[filter "hostile"]\nclean = !false\n', encoding="utf-8")
    with pytest.raises(m8.TraceabilityError, match="executor config is prohibited"):
        m8._validate_local_git_config(executable, owner=owner)

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / "config").write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")
    (worktree / "config.worktree").write_text("[core]\n", encoding="utf-8")
    with pytest.raises(m8.TraceabilityError, match="worktree config is prohibited"):
        m8._validate_local_git_config(worktree, owner=owner)


def test_local_git_config_rejects_open_and_read_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    git_dir = tmp_path / "git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")
    owner = os.getuid()
    original_open = m8.os.open
    with monkeypatch.context() as denied:
        denied.setattr(m8.os, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
        with pytest.raises(m8.TraceabilityError, match="config cannot be opened"):
            m8._validate_local_git_config(git_dir, owner=owner)

    original_fstat = m8.os.fstat

    def changed_size(descriptor: int) -> os.stat_result:
        result = original_fstat(descriptor)
        fields = list(result)
        fields[6] += 1
        return os.stat_result(fields)

    with monkeypatch.context() as opening_race:
        opening_race.setattr(m8.os, "fstat", changed_size)
        with pytest.raises(m8.TraceabilityError, match="changed while opening"):
            m8._validate_local_git_config(git_dir, owner=owner)

    with monkeypatch.context() as read_race:
        read_race.setattr(m8.os, "read", lambda _fd, _count: b"")
        with pytest.raises(m8.TraceabilityError, match="changed while reading"):
            m8._validate_local_git_config(git_dir, owner=owner)
    assert original_open is m8.os.open


def test_git_execution_boundary_rejects_missing_binary_nontext_and_dirty_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(m8, "PINNED_GIT_EXECUTABLE", tmp_path / "missing-git")
    with pytest.raises(m8.TraceabilityError, match="pinned /usr/bin/git executable is unavailable"):
        m8._git_executable()

    monkeypatch.setattr(m8, "_git_bytes", lambda *_args: b"\xff")
    with pytest.raises(m8.TraceabilityError, match="returned non-UTF-8 output"):
        m8._git_text(ROOT, "status")

    monkeypatch.setattr(m8, "canonical_repository_root", lambda root: root)
    monkeypatch.setattr(m8, "_git_text", lambda *_args: "dirty\n")
    with pytest.raises(m8.TraceabilityError, match="exact clean checkout"):
        m8.require_clean_checkout(ROOT)


def test_historical_result_identity_rejects_unbound_or_ambiguous_source() -> None:
    valid_commit = "a" * 40
    cases: list[tuple[dict[str, Any], str]] = [
        (
            {
                "git_commit": "invalid",
                "working_tree_dirty": False,
                "source_sha256": {"a": "b"},
            },
            "canonical exercised",
        ),
        ({"git_commit": valid_commit, "source_sha256": {"a": "b"}}, "explicitly clean"),
        (
            {"git_commit": valid_commit, "working_tree_dirty": False, "source_sha256": {}},
            "bounded source-hash",
        ),
    ]
    for value, message in cases:
        with pytest.raises(m8.TraceabilityError, match=message):
            m8._historical_source_identity(value)


def test_validation_entry_point_requires_authoritative_source_paths(
    exact_report: tuple[Path, dict[str, Any]],
) -> None:
    with pytest.raises(m8.TraceabilityError, match="authoritative source paths"):
        m8.validate_evidence_traceability(
            exact_report[1],
            root=exact_report[0],
            requirements_path="requirements.docx",
            mapping_path=m8.AUTHORITATIVE_MAPPING_PATH,
        )
