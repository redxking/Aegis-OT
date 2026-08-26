"""Closed extraction and gap accounting for the authoritative requirements DOCX.

This module does not infer implementation or acceptance from source-code presence.
It converts every normative requirement and TBR in the proposed baseline into a
machine-verifiable record whose unevidenced fields remain explicitly open.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, cast
from xml.etree import ElementTree

REQUIREMENT_ID: Final[re.Pattern[str]] = re.compile(r"AOT-([A-Z]+)-(\d{3})")
TBR_ID: Final[re.Pattern[str]] = re.compile(r"TBR-(\d{3})")
GATE_ID: Final[re.Pattern[str]] = re.compile(r"G([0-7])")
CLAIM_STATE_ID: Final[re.Pattern[str]] = re.compile(r"C([0-8])")

EXPECTED_REQUIREMENT_COUNT: Final[int] = 223
EXPECTED_TBR_COUNT: Final[int] = 35
EXPECTED_GATE_COUNT: Final[int] = 8
EXPECTED_CLAIM_STATE_COUNT: Final[int] = 9
EXPECTED_AUTHOR: Final[str] = "Angelis Pseftis"
TRACEABILITY_SCHEMA: Final[str] = "aegis-ot-m8-requirements-traceability-v1"

_WORD_NS: Final[str] = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_CORE_NS: Final[dict[str, str]] = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
}
_W: Final[str] = f"{{{_WORD_NS}}}"

JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]


def _canonical_json_bytes(value: JsonValue) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text(element: ElementTree.Element) -> str:
    fragments = [node.text or "" for node in element.iter(f"{_W}t")]
    return "".join(fragments).strip()


def _paragraph_style(element: ElementTree.Element) -> str:
    style = element.find(f"{_W}pPr/{_W}pStyle")
    return "" if style is None else style.get(f"{_W}val", "")


def _table_rows(table: ElementTree.Element) -> list[list[str]]:
    rows: list[list[str]] = []
    for row in table.findall(f"{_W}tr"):
        cells = [_text(cell) for cell in row.findall(f"{_W}tc")]
        if cells:
            rows.append(cells)
    return rows


def _member_bytes(archive: zipfile.ZipFile, member: str) -> bytes:
    path = PurePosixPath(member)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe DOCX member path: {member}")
    try:
        info = archive.getinfo(member)
    except KeyError as exc:
        raise ValueError(f"DOCX is missing required member {member}") from exc
    if info.is_dir() or info.file_size > 20_000_000:
        raise ValueError(f"invalid DOCX member {member}")
    if info.compress_size > 0 and info.file_size / info.compress_size > 1_000:
        raise ValueError(f"suspicious DOCX compression ratio for {member}")
    return archive.read(info)


def _parse_xml(value: bytes, *, label: str) -> ElementTree.Element:
    if b"<!DOCTYPE" in value.upper() or b"<!ENTITY" in value.upper():
        raise ValueError(f"{label} contains a prohibited XML declaration")
    try:
        return ElementTree.fromstring(value)  # noqa: S314 - DTD/entity declarations rejected
    except ElementTree.ParseError as exc:
        raise ValueError(f"{label} is not well-formed XML") from exc


def _metadata(core: ElementTree.Element) -> dict[str, str]:
    def value(path: str) -> str:
        node = core.find(path, _CORE_NS)
        return "" if node is None else (node.text or "").strip()

    result = {
        "title": value("dc:title"),
        "subject": value("dc:subject"),
        "creator": value("dc:creator"),
        "last_modified_by": value("cp:lastModifiedBy"),
        "revision": value("cp:revision"),
        "description": value("dc:description"),
    }
    if result["creator"] != EXPECTED_AUTHOR:
        raise ValueError(f"DOCX creator must be exactly {EXPECTED_AUTHOR}")
    if result["last_modified_by"] != EXPECTED_AUTHOR:
        raise ValueError(f"DOCX last modifier must be exactly {EXPECTED_AUTHOR}")
    return result


@dataclass(frozen=True, slots=True)
class Requirement:
    requirement_id: str
    domain: str
    ordinal: int
    revision: str
    title: str
    normative_text: str
    requirement_class: str
    applicability: str
    verification_methods: tuple[str, ...]
    gate: str
    tbrs: tuple[str, ...]
    allocation: str
    source_basis: str

    def traceability_record(self) -> dict[str, JsonValue]:
        return {
            "identity": {
                "requirement_id": self.requirement_id,
                "revision": self.revision,
                "title": self.title,
                "normative_text": self.normative_text,
                "class": self.requirement_class,
                "applicability": self.applicability,
            },
            "engineering_basis": {
                "source": self.source_basis,
                "rationale": None,
                "assumptions": [],
                "dependencies": list(self.tbrs),
                "trust_boundary": None,
                "hazard_or_threat_relationship": None,
                "allocated_component": self.allocation,
            },
            "verification": {
                "method": list(self.verification_methods),
                "procedure_or_test_id": [],
                "configuration": None,
                "acceptance_threshold": None,
                "environment": None,
                "assessor": None,
                "result": "not_assessed",
                "artifact": [],
                "date": None,
            },
            "disposition": {
                "implementation_state": "not_assessed",
                "claim_state": "C0",
                "finding_status": "open",
                "residual_risk": "No implementation or acceptance evidence is allocated.",
                "waiver_or_deviation": None,
                "approving_authority": None,
                "affected_release": "proposed-research-baseline",
                "required_gate": self.gate,
            },
            "change_history": [
                {
                    "old_text": None,
                    "new_text": self.normative_text,
                    "rationale": "Initial extraction from the authoritative proposed baseline.",
                    "impact_analysis": "Not assessed.",
                    "originator": EXPECTED_AUTHOR,
                    "reviewers": [],
                    "approval": "not_approved",
                    "effective_baseline": "proposed",
                }
            ],
        }


@dataclass(frozen=True, slots=True)
class ToBeResolved:
    tbr_id: str
    decision_or_value: str
    closure_authority: str
    due_gate: str
    required_closure_evidence: str

    def record(self) -> dict[str, JsonValue]:
        return {
            "tbr_id": self.tbr_id,
            "decision_or_value": self.decision_or_value,
            "closure_authority": self.closure_authority,
            "due_gate": self.due_gate,
            "required_closure_evidence": self.required_closure_evidence,
            "status": "open",
            "closure_artifacts": [],
            "closed_by": None,
            "closed_at": None,
        }


@dataclass(frozen=True, slots=True)
class RequirementsBaseline:
    source_path: str
    source_sha256: str
    metadata: dict[str, str]
    requirements: tuple[Requirement, ...]
    tbrs: tuple[ToBeResolved, ...]
    gates: dict[str, str]
    claim_states: dict[str, str]

    def report(self) -> dict[str, JsonValue]:
        requirements: list[JsonValue] = [
            cast(JsonValue, item.traceability_record()) for item in self.requirements
        ]
        tbrs: list[JsonValue] = [cast(JsonValue, item.record()) for item in self.tbrs]
        domain_counts = Counter(item.domain for item in self.requirements)
        gate_counts = Counter(item.gate for item in self.requirements)
        class_counts = Counter(item.requirement_class for item in self.requirements)
        gates_json = cast(dict[str, JsonValue], self.gates)
        claim_states_json = cast(dict[str, JsonValue], self.claim_states)
        catalog_material: JsonValue = {
            "requirements": requirements,
            "tbrs": tbrs,
            "gates": gates_json,
            "claim_states": claim_states_json,
        }
        return {
            "schema": TRACEABILITY_SCHEMA,
            "source": {
                "path": self.source_path,
                "sha256": self.source_sha256,
                "metadata": cast(dict[str, JsonValue], self.metadata),
                "status": "proposed_not_approved",
            },
            "summary": {
                "requirements_tracked": len(requirements),
                "requirements_open": len(requirements),
                "requirements_accepted": 0,
                "tbrs_tracked": len(tbrs),
                "tbrs_open": len(tbrs),
                "end_state_accepted": False,
                "domain_counts": dict(sorted(domain_counts.items())),
                "gate_counts": dict(sorted(gate_counts.items())),
                "class_counts": dict(sorted(class_counts.items())),
            },
            "requirements": requirements,
            "tbrs": tbrs,
            "gates": gates_json,
            "claim_states": claim_states_json,
            "catalog_sha256": _sha256_bytes(_canonical_json_bytes(catalog_material)),
            "claim_boundary": (
                "Complete catalog extraction and open-gap accounting only. Source-code, test, "
                "configuration, or package presence is not inferred as implementation, local "
                "acceptance, independent validation, qualification, deployment, or operational "
                "effectiveness."
            ),
        }


def parse_requirements_docx(path: Path) -> RequirementsBaseline:
    """Parse and strictly validate the authoritative proposed requirements baseline."""

    source = path.read_bytes()
    try:
        with zipfile.ZipFile(path) as archive:
            document = _parse_xml(
                _member_bytes(archive, "word/document.xml"),
                label="word/document.xml",
            )
            core = _parse_xml(
                _member_bytes(archive, "docProps/core.xml"),
                label="docProps/core.xml",
            )
    except zipfile.BadZipFile as exc:
        raise ValueError("requirements source is not a valid DOCX archive") from exc

    metadata = _metadata(core)
    body = document.find(f"{_W}body")
    if body is None:
        raise ValueError("requirements DOCX has no document body")

    current_title = ""
    current_domain = ""
    current_allocation = ""
    current_source_basis = ""
    requirements: list[Requirement] = []
    tbrs: list[ToBeResolved] = []
    gates: dict[str, str] = {}
    claim_states: dict[str, str] = {}

    for child in body:
        if child.tag == f"{_W}p":
            paragraph = _text(child)
            style = _paragraph_style(child).lower()
            heading_match = re.search(r"\((?P<domain>[A-Z]+)\)\s*$", paragraph)
            if style.startswith("heading") and heading_match and paragraph.startswith("5."):
                current_title = paragraph
                current_domain = heading_match.group("domain")
                current_allocation = ""
                current_source_basis = ""
            if paragraph.startswith("Allocation:"):
                allocation_text = paragraph.removeprefix("Allocation:").strip()
                allocation, separator, basis = allocation_text.partition("Source basis:")
                current_allocation = allocation.strip().rstrip(".")
                current_source_basis = basis.strip() if separator else ""
            continue
        if child.tag != f"{_W}tbl":
            continue
        for cells in _table_rows(child):
            if len(cells) < 2:
                continue
            first = cells[0]
            requirement_match = REQUIREMENT_ID.fullmatch(first)
            if requirement_match:
                if len(cells) != 6:
                    raise ValueError(f"{first} does not have the six required catalog fields")
                domain = requirement_match.group(1)
                if domain != current_domain:
                    raise ValueError(f"{first} is outside its matching domain section")
                methods = tuple(item.strip() for item in cells[3].split(",") if item.strip())
                tbr_ids = tuple(TBR_ID.findall(cells[5]))
                normalized_tbrs = tuple(f"TBR-{item}" for item in tbr_ids)
                requirements.append(
                    Requirement(
                        requirement_id=first,
                        domain=domain,
                        ordinal=int(requirement_match.group(2)),
                        revision=metadata["revision"],
                        title=current_title,
                        normative_text=cells[2],
                        requirement_class=cells[1],
                        applicability="end-state-assurance-profile",
                        verification_methods=methods,
                        gate=cells[4],
                        tbrs=normalized_tbrs,
                        allocation=current_allocation,
                        source_basis=current_source_basis,
                    )
                )
                continue
            tbr_match = TBR_ID.fullmatch(first)
            if tbr_match and len(cells) == 5:
                tbrs.append(
                    ToBeResolved(
                        tbr_id=first,
                        decision_or_value=cells[1],
                        closure_authority=cells[2],
                        due_gate=cells[3],
                        required_closure_evidence=cells[4],
                    )
                )
                continue
            gate_match = GATE_ID.fullmatch(first)
            if gate_match and len(cells) >= 3 and first not in gates:
                gates[first] = cells[1]
                continue
            claim_match = CLAIM_STATE_ID.fullmatch(first)
            if claim_match and len(cells) >= 3 and first not in claim_states:
                claim_states[first] = cells[1]

    _validate_catalog(requirements, tbrs, gates, claim_states)
    return RequirementsBaseline(
        source_path=path.as_posix(),
        source_sha256=_sha256_bytes(source),
        metadata=metadata,
        requirements=tuple(requirements),
        tbrs=tuple(tbrs),
        gates=dict(sorted(gates.items())),
        claim_states=dict(sorted(claim_states.items())),
    )


def _validate_catalog(
    requirements: list[Requirement],
    tbrs: list[ToBeResolved],
    gates: dict[str, str],
    claim_states: dict[str, str],
) -> None:
    if len(requirements) != EXPECTED_REQUIREMENT_COUNT:
        raise ValueError(
            f"expected {EXPECTED_REQUIREMENT_COUNT} requirements, found {len(requirements)}"
        )
    requirement_ids = [item.requirement_id for item in requirements]
    if len(requirement_ids) != len(set(requirement_ids)):
        raise ValueError("requirement identifiers are not unique")
    if any(" shall " not in f" {item.normative_text} " for item in requirements):
        raise ValueError("every normative requirement must retain its full statement")
    if any(item.requirement_class not in {"M", "C"} for item in requirements):
        raise ValueError("requirement class must be mandatory or conditional")
    if any(not item.verification_methods for item in requirements):
        raise ValueError("every requirement must retain at least one verification method")
    if any(not GATE_ID.fullmatch(item.gate) for item in requirements):
        raise ValueError("every requirement must name a valid gate")
    if any(not item.allocation or not item.source_basis for item in requirements):
        raise ValueError("every requirement must retain allocation and source basis")

    if len(tbrs) != EXPECTED_TBR_COUNT:
        raise ValueError(f"expected {EXPECTED_TBR_COUNT} TBRs, found {len(tbrs)}")
    tbr_ids = [item.tbr_id for item in tbrs]
    if len(tbr_ids) != len(set(tbr_ids)):
        raise ValueError("TBR identifiers are not unique")
    known_tbrs = set(tbr_ids)
    referenced_tbrs = {tbr for item in requirements for tbr in item.tbrs}
    if not referenced_tbrs <= known_tbrs:
        raise ValueError("one or more requirements reference an undefined TBR")

    if len(gates) != EXPECTED_GATE_COUNT or set(gates) != {
        f"G{index}" for index in range(EXPECTED_GATE_COUNT)
    }:
        raise ValueError("gate catalog must contain exactly G0 through G7")
    if len(claim_states) != EXPECTED_CLAIM_STATE_COUNT or set(claim_states) != {
        f"C{index}" for index in range(EXPECTED_CLAIM_STATE_COUNT)
    }:
        raise ValueError("claim-state catalog must contain exactly C0 through C8")


def build_traceability_report(path: Path) -> dict[str, JsonValue]:
    return parse_requirements_docx(path).report()


def verify_traceability_report(path: Path, report: object) -> dict[str, bool]:
    """Rebuild the traceability projection and compare the complete canonical result."""

    expected = build_traceability_report(path)
    supplied = cast(JsonValue, report)
    source = report.get("source") if isinstance(report, dict) else None
    summary = report.get("summary") if isinstance(report, dict) else None
    expected_source = expected.get("source")
    expected_source_sha256 = (
        expected_source.get("sha256") if isinstance(expected_source, dict) else None
    )
    return {
        "schema_matches": (
            isinstance(report, dict) and report.get("schema") == TRACEABILITY_SCHEMA
        ),
        "source_hash_matches": (
            isinstance(source, dict)
            and source.get("sha256") == expected_source_sha256
        ),
        "all_requirements_tracked": (
            isinstance(summary, dict)
            and summary.get("requirements_tracked") == EXPECTED_REQUIREMENT_COUNT
        ),
        "all_tbrs_tracked": (
            isinstance(summary, dict) and summary.get("tbrs_tracked") == EXPECTED_TBR_COUNT
        ),
        "no_false_end_state_acceptance": (
            isinstance(summary, dict)
            and summary.get("requirements_accepted") == 0
            and summary.get("tbrs_open") == EXPECTED_TBR_COUNT
            and summary.get("end_state_accepted") is False
        ),
        "canonical_report_matches": _canonical_json_bytes(supplied)
        == _canonical_json_bytes(expected),
    }
