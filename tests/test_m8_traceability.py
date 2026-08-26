from __future__ import annotations

import copy
import zipfile
from pathlib import Path
from typing import Any, cast

import pytest

from aegis_ot.m8_traceability import (
    EXPECTED_AUTHOR,
    EXPECTED_CLAIM_STATE_COUNT,
    EXPECTED_GATE_COUNT,
    EXPECTED_REQUIREMENT_COUNT,
    EXPECTED_TBR_COUNT,
    build_traceability_report,
    parse_requirements_docx,
    verify_traceability_report,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/requirements/Aegis-OT_End-State_System_Requirements.docx"


def _rewrite_member(source: Path, target: Path, member: str, old: bytes, new: bytes) -> None:
    with zipfile.ZipFile(source) as input_archive:
        with zipfile.ZipFile(target, "w") as output_archive:
            for item in input_archive.infolist():
                material = input_archive.read(item.filename)
                if item.filename == member:
                    assert old in material
                    material = material.replace(old, new, 1)
                output_archive.writestr(item, material)


def test_authoritative_docx_yields_the_closed_requirement_and_tbr_catalog() -> None:
    baseline = parse_requirements_docx(SOURCE)

    assert len(baseline.requirements) == EXPECTED_REQUIREMENT_COUNT == 223
    assert len(baseline.tbrs) == EXPECTED_TBR_COUNT == 35
    assert len(baseline.gates) == EXPECTED_GATE_COUNT == 8
    assert len(baseline.claim_states) == EXPECTED_CLAIM_STATE_COUNT == 9
    assert baseline.metadata["creator"] == EXPECTED_AUTHOR
    assert baseline.metadata["last_modified_by"] == EXPECTED_AUTHOR
    assert baseline.metadata["description"].startswith(
        "Single authoritative proposed end-state requirements document."
    )

    requirement_ids = [item.requirement_id for item in baseline.requirements]
    assert len(requirement_ids) == len(set(requirement_ids))
    assert requirement_ids[0] == "AOT-SYS-001"
    assert requirement_ids[-1] == "AOT-GOV-010"
    assert [item.tbr_id for item in baseline.tbrs] == [
        f"TBR-{index:03d}" for index in range(1, 36)
    ]


def test_requirements_retain_normative_fields_allocations_and_dependencies() -> None:
    baseline = parse_requirements_docx(SOURCE)
    by_id = {item.requirement_id: item for item in baseline.requirements}

    m6 = by_id["AOT-PERF-007"]
    assert m6.domain == "PERF"
    assert m6.requirement_class == "M"
    assert m6.verification_methods == ("T", "A")
    assert m6.gate == "G6"
    assert m6.tbrs == ("TBR-023",)
    assert "10,000 logical agents" in m6.normative_text
    assert "Performance engineering" in m6.allocation
    assert m6.source_basis

    qualification = by_id["AOT-VV-012"]
    assert qualification.gate == "G7"
    assert qualification.tbrs == ("TBR-029",)
    assert "independent of implementation custody" in qualification.normative_text


def test_report_tracks_every_item_without_inventing_acceptance() -> None:
    report = build_traceability_report(SOURCE)
    summary = report["summary"]

    assert isinstance(summary, dict)
    assert summary == {
        "requirements_tracked": 223,
        "requirements_open": 223,
        "requirements_accepted": 0,
        "tbrs_tracked": 35,
        "tbrs_open": 35,
        "end_state_accepted": False,
        "domain_counts": {
            "ARCH": 9,
            "AUTH": 12,
            "COORD": 17,
            "DELG": 9,
            "EVID": 13,
            "EXEC": 12,
            "GOV": 10,
            "HMI": 8,
            "IF": 10,
            "NET": 11,
            "OBS": 10,
            "OPS": 10,
            "PERF": 10,
            "PHY": 10,
            "POL": 11,
            "RES": 12,
            "SAFE": 11,
            "SEC": 14,
            "SYS": 11,
            "VV": 13,
        },
        "gate_counts": {
            "G0": 13,
            "G1": 8,
            "G2": 5,
            "G3": 55,
            "G4": 41,
            "G5": 47,
            "G6": 25,
            "G7": 29,
        },
        "class_counts": {"C": 1, "M": 222},
    }
    assert report["catalog_sha256"] == (
        "d03db35e241aae20e7e55d9cc4d363e0b3b7d1d64ec9c9031735c3f5a8b3a93e"
    )
    records = report["requirements"]
    assert isinstance(records, list)
    for record in records:
        assert isinstance(record, dict)
        verification = cast(dict[str, Any], record["verification"])
        disposition = cast(dict[str, Any], record["disposition"])
        assert verification["result"] == "not_assessed"
        assert disposition["claim_state"] == "C0"
        assert disposition["finding_status"] == "open"


def test_offline_verification_rebuilds_the_complete_canonical_projection() -> None:
    report = build_traceability_report(SOURCE)
    assert all(verify_traceability_report(SOURCE, report).values())

    altered = copy.deepcopy(report)
    requirements = altered["requirements"]
    assert isinstance(requirements, list)
    first = requirements[0]
    assert isinstance(first, dict)
    disposition = cast(dict[str, Any], first["disposition"])
    disposition["claim_state"] = "C8"
    checks = verify_traceability_report(SOURCE, altered)
    assert checks["canonical_report_matches"] is False
    assert checks["no_false_end_state_acceptance"] is True


def test_parser_rejects_non_authoritative_authorship(tmp_path: Path) -> None:
    altered = tmp_path / "wrong-author.docx"
    _rewrite_member(
        SOURCE,
        altered,
        "docProps/core.xml",
        b"<dc:creator>Angelis Pseftis</dc:creator>",
        b"<dc:creator>Unapproved Author</dc:creator>",
    )

    with pytest.raises(ValueError, match="creator must be exactly Angelis Pseftis"):
        parse_requirements_docx(altered)


def test_parser_rejects_requirement_catalog_drift(tmp_path: Path) -> None:
    altered = tmp_path / "missing-requirement.docx"
    _rewrite_member(
        SOURCE,
        altered,
        "word/document.xml",
        b"AOT-SYS-001",
        b"NOT-SYS-001",
    )

    with pytest.raises(ValueError, match="expected 223 requirements, found 222"):
        parse_requirements_docx(altered)
