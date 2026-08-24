"""Build the single controlled Aegis-OT research study document."""

from __future__ import annotations

import json
import re
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree

from docx import Document
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "research" / "Aegis-OT_Research_Study.docx"
REVISION = json.loads((ROOT / "research" / "revision_log.json").read_text())
MANIFEST = json.loads(
    (ROOT / "results" / "m2-independent-oracle" / "manifest.json").read_text()
)
FORMAL_MANIFEST = json.loads(
    (ROOT / "results" / "formal" / "m1-authorization-conformance" / "manifest.json").read_text()
)
FORMAL_INTENDED = next(case for case in FORMAL_MANIFEST["cases"] if case["name"] == "intended")
CURRENT_REVISION = REVISION["revisions"][-1]
REVISION_NUMBER = CURRENT_REVISION["revision"]
BLUE = RGBColor(23, 105, 170)
DARK = RGBColor(16, 42, 67)
MUTED = RGBColor(82, 96, 109)
LIGHT_FILL = "EAF2F8"
EXTENDED_PROPERTIES_NAMESPACE = (
    "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
)


def set_font(run, size: float, *, bold: bool = False, color: RGBColor = DARK) -> None:
    run.font.name = "Arial"
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:ascii"), "Arial")
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:hAnsi"), "Arial")
    run.font.size = Pt(size)
    run.bold = bold
    run.font.color.rgb = color


def shade(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def set_cell_margins(cell, top: int = 100, start: int = 120, bottom: int = 100, end: int = 120) -> None:
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for margin, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tc_mar.find(qn(f"w:{margin}"))
        if node is None:
            node = OxmlElement(f"w:{margin}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_repeat_table_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    header = OxmlElement("w:tblHeader")
    header.set(qn("w:val"), "true")
    tr_pr.append(header)


def set_alt_text(inline_shape, description: str) -> None:
    doc_pr = inline_shape._inline.docPr
    doc_pr.set("descr", description)
    doc_pr.set("title", description.split(".")[0])


def add_paragraph(doc: Document, text: str, *, bold_lead: str | None = None) -> None:
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.space_after = Pt(8)
    paragraph.paragraph_format.line_spacing = 1.22
    if bold_lead and text.startswith(bold_lead):
        lead = paragraph.add_run(bold_lead)
        set_font(lead, 10.5, bold=True)
        body = paragraph.add_run(text[len(bold_lead) :])
        set_font(body, 10.5)
    else:
        run = paragraph.add_run(text)
        set_font(run, 10.5)


def add_bullets(doc: Document, items: list[str]) -> None:
    for item in items:
        paragraph = doc.add_paragraph(style="List Bullet")
        paragraph.paragraph_format.left_indent = Inches(0.5)
        paragraph.paragraph_format.first_line_indent = Inches(-0.25)
        paragraph.paragraph_format.space_after = Pt(6)
        paragraph.paragraph_format.line_spacing = 1.2
        set_font(paragraph.add_run(item), 10.5)


def heading(doc: Document, text: str, level: int = 1) -> None:
    paragraph = doc.add_heading(text, level=level)
    paragraph.paragraph_format.keep_with_next = True
    paragraph.paragraph_format.line_spacing = 1.05


def table(doc: Document, headers: list[str], rows: list[list[str]], widths: list[float]) -> None:
    tbl = doc.add_table(rows=1, cols=len(headers))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    tbl.style = "Table Grid"
    for index, header in enumerate(headers):
        cell = tbl.rows[0].cells[index]
        cell.width = Inches(widths[index])
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        shade(cell, LIGHT_FILL)
        set_cell_margins(cell)
        set_font(cell.paragraphs[0].add_run(header), 9, bold=True)
    set_repeat_table_header(tbl.rows[0])
    for values in rows:
        cells = tbl.add_row().cells
        for index, value in enumerate(values):
            cells[index].width = Inches(widths[index])
            cells[index].vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            set_cell_margins(cells[index])
            cells[index].paragraphs[0].paragraph_format.space_after = Pt(0)
            set_font(cells[index].paragraphs[0].add_run(value), 8.6)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def figure(doc: Document, filename: str, caption: str, alt: str) -> None:
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    shape = paragraph.add_run().add_picture(str(ROOT / "assets" / filename), width=Inches(6.25))
    set_alt_text(shape, alt)
    caption_p = doc.add_paragraph()
    caption_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    caption_p.paragraph_format.keep_with_next = True
    run = caption_p.add_run(caption)
    set_font(run, 9, bold=True, color=MUTED)


def configure_styles(doc: Document) -> None:
    section = doc.sections[0]
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)
    section.left_margin = Inches(1.0)
    section.right_margin = Inches(1.0)
    section.header_distance = Inches(0.45)
    section.footer_distance = Inches(0.45)
    normal = doc.styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(10.5)
    normal.paragraph_format.space_after = Pt(8)
    normal.paragraph_format.line_spacing = 1.22
    for style_name, size, before, after, color in (
        ("Heading 1", 16, 16, 8, BLUE),
        ("Heading 2", 13, 12, 6, BLUE),
        ("Heading 3", 11.5, 8, 4, DARK),
    ):
        style = doc.styles[style_name]
        style.font.name = "Arial"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = color
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True


def add_header_footer(doc: Document) -> None:
    for section in doc.sections:
        header = section.header.paragraphs[0]
        header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        set_font(
            header.add_run(
                f"AEGIS-OT-STUDY-001 | CONTROLLED RESEARCH STUDY | REV {REVISION_NUMBER}"
            ),
            8,
            color=MUTED,
        )
        footer = section.footer.paragraphs[0]
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
        field = OxmlElement("w:fldSimple")
        field.set(qn("w:instr"), "PAGE")
        footer._p.append(field)


def add_cover(doc: Document) -> None:
    for _ in range(5):
        doc.add_paragraph()
    kicker = doc.add_paragraph()
    kicker.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(kicker.add_run("CONTROLLED RESEARCH STUDY"), 11, bold=True, color=BLUE)
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.space_after = Pt(10)
    set_font(title.add_run("Aegis-OT"), 30, bold=True)
    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.paragraph_format.space_after = Pt(22)
    set_font(
        subtitle.add_run(
            "Assured Agentic AI for Critical Infrastructure:\nIdentity-Bound Runtime Authorization and Operate-Through-Compromise Resilience"
        ),
        15,
        color=BLUE,
    )
    author = doc.add_paragraph()
    author.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(author.add_run("Angelis Pseftis"), 12, bold=True)
    metadata = doc.add_paragraph()
    metadata.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(
        metadata.add_run(
            f"Document AEGIS-OT-STUDY-001 | Revision {REVISION_NUMBER} | 24 August 2026"
        ),
        10,
        color=MUTED,
    )
    boundary = doc.add_paragraph()
    boundary.alignment = WD_ALIGN_PARAGRAPH.CENTER
    boundary.paragraph_format.space_before = Pt(28)
    set_font(boundary.add_run("RESEARCH USE ONLY - SYNTHETIC AND SIMULATED ENVIRONMENTS"), 10, bold=True, color=RGBColor(166, 27, 27))
    doc.add_page_break()


def patch_extended_properties(path: Path, pages: int, words: int) -> None:
    """Preserve useful publication metadata omitted by python-docx."""
    with zipfile.ZipFile(path) as source:
        app_xml = source.read("docProps/app.xml")
        root = ElementTree.fromstring(app_xml)  # noqa: S314 - self-generated DOCX part
        for name, value in (("Pages", pages), ("Words", words)):
            node = root.find(f"{{{EXTENDED_PROPERTIES_NAMESPACE}}}{name}")
            if node is not None:
                node.text = str(value)
        updated = ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix=".docx", delete=False) as handle:
            temporary_path = Path(handle.name)
        try:
            with zipfile.ZipFile(temporary_path, "w", zipfile.ZIP_DEFLATED) as target:
                for item in source.infolist():
                    target.writestr(
                        item,
                        updated if item.filename == "docProps/app.xml" else source.read(item.filename),
                    )
            temporary_path.replace(path)
        finally:
            temporary_path.unlink(missing_ok=True)


def build() -> None:
    doc = Document()
    configure_styles(doc)
    props = doc.core_properties
    props.author = "Angelis Pseftis"
    props.last_modified_by = "Angelis Pseftis"
    props.title = "Aegis-OT Research Study"
    props.subject = "Identity-bound runtime assurance for simulated critical infrastructure"
    props.keywords = "Aegis-OT, runtime assurance, workload identity, delegation, OT security"
    props.comments = "Controlled research document. Author and editor: Angelis Pseftis."
    props.created = datetime.fromisoformat(REVISION["created_at_utc"].replace("Z", "+00:00"))
    props.modified = datetime.now(UTC)
    props.revision = len(REVISION["revisions"])
    add_cover(doc)

    heading(doc, "Document Control")
    table(
        doc,
        ["Field", "Controlled value"],
        [
            ["Document identifier", "AEGIS-OT-STUDY-001"],
            ["Revision", REVISION_NUMBER],
            ["Author and editor", "Angelis Pseftis"],
            ["Canonical file", "research/Aegis-OT_Research_Study.docx"],
            ["Evidence boundary", "Reconstructed repository; lost historical artifacts are not current evidence"],
        ],
        [1.65, 4.85],
    )
    add_paragraph(doc, "Control statement: This DOCX is the single authoritative editable manuscript. Git history and research/revision_log.json preserve its revision trail. Supporting Markdown, figures, renders, and data are not alternate manuscripts.")
    doc.add_page_break()
    heading(doc, "Revision History", 2)
    revision_rows = []
    for revision in REVISION["revisions"]:
        evidence_link = (
            revision.get("evidence_label")
            or revision.get("experiment_manifest")
            or revision.get("evidence_artifact")
            or "No linked artifact"
        )
        revision_rows.append(
            [
                revision["revision"],
                revision["timestamp_utc"],
                revision["editor"],
                revision["description"],
                evidence_link,
            ]
        )
    table(
        doc,
        ["Revision", "UTC timestamp", "Editor", "Substantive change", "Evidence link"],
        revision_rows,
        [0.55, 1.15, 0.9, 2.7, 1.2],
    )
    doc.add_page_break()
    heading(doc, "Contents")
    sections = [
        "1 Abstract", "2 Executive Summary", "3 Introduction and Research Gap", "4 Research Objectives, Questions, and Hypotheses",
        "5 Scope, Assumptions, and Claim Boundaries", "6 Threat Model", "7 System Requirements", "8 Reference Architecture",
        "9 Authorization and Safety Model", "10 Formal Specification Strategy", "11 Experimental Methodology",
        "12 Implementation and Verification Status", "13 M2 Controlled Results", "14 Multi-VM Integration Plan",
        "15 Operate-Through-Compromise Test Program", "16 Scale and Economic Analysis Plan", "17 Reproducibility and Data Management",
        "18 Risks, Limitations, and Validity Threats", "19 Work Plan and Completion Criteria", "20 Conclusions", "21 References",
        "22 Requirements Traceability Appendix", "23 Data and Message Schemas Appendix", "24 Reproduction Runbook Appendix",
        "25 Version-Control Audit Trail Appendix",
    ]
    add_bullets(doc, sections)
    doc.add_page_break()

    heading(doc, "1. Abstract")
    add_paragraph(doc, "Aegis-OT investigates whether an independently enforced runtime-assurance control plane can prevent a validly authenticated but compromised, misled, stale, or faulty AI agent from executing actions outside its delegated mission and modeled cyber-physical safety envelope while preserving legitimate containment and recovery. The reconstructed v0.1 implementation binds typed proposals to Ed25519-signed delegation chains, contextual policy, state freshness, replay protection, a deterministic safety kernel, a command adapter, and hash-chained evidence. The M2 experiment removes the initial circular oracle path: a separately implemented decimal-arithmetic reference model computes candidate states directly from proposals and pre-action state, applies conservative guardbands, and records disagreements. Results establish only synthetic local control-path behavior, not physical accuracy or field effectiveness.")

    heading(doc, "2. Executive Summary")
    add_paragraph(doc, "The central engineering decision is that identity is necessary but insufficient. An agent never receives direct simulated-control authority; it receives authority to propose a bounded action. The gateway remains the policy-enforcement point and fails closed when identity, delegation, state, replay, policy, safety, or required approval cannot be established.")
    add_bullets(doc, [
        "Current verified implementation evidence: 79 passing tests, clean static type checking, clean linting, schema-drift validation, and 93 percent branch-aware coverage on the local Python 3.14 host. Gateway, policy, trust-boundary model, replay, and evidence paths each measure 100 percent coverage in this suite; coverage is implementation-conformance evidence, not independent validation.",
        f"Current formal evidence: TLC explored {FORMAL_INTENDED['states_generated']:,} generated and {FORMAL_INTENDED['distinct_states']:,} distinct states to depth {FORMAL_INTENDED['search_depth']} in the intended bounded configuration without an invariant or liveness violation. Sixteen targeted weakened configurations each produced the expected counterexample. This is bounded model evidence, not proof of the Python implementation or physical process.",
        "Current experiment evidence: 8,640 decision records across eight baselines, 12 reviewed scenario templates, 30 master seeds, and 36 sampled trials per seed per baseline. An independent reproduction matched deterministic outcome hash b5ad54a6984f659f961975adaf386eade41f733307c289ea7c3ecaa11c6b5b90.",
        "Current result: the assured path produced zero unauthorized executions among 450 authorization-negative records but executed 60 percent of the 450 reference-unsafe records because three conservative guardband templates remained inside the runtime kernel limits. This is a threshold-sensitivity finding, not physical evidence.",
        "Next decision gate: use an independently executed power-system simulator and virtual PLC boundary to calibrate consequence envelopes and test whether the observed guardband gap represents appropriate operating policy or unsafe permissiveness.",
    ])

    doc.add_page_break()
    heading(doc, "3. Introduction and Research Gap")
    add_paragraph(doc, "Workload identity, delegated authorization, policy engines, runtime assurance, cyber-physical safety analysis, and tamper-evident logging are established fields. Aegis-OT does not claim novelty for those elements individually. The research contribution under evaluation is the integration and reproducible testing of those mechanisms as an independent action-control plane for adversarial autonomous-agent operation in simulated critical infrastructure.")
    add_paragraph(doc, "The present gap statement is provisional. Public evidence has not yet established a mature benchmark that jointly measures cryptographic agent identity, attenuation and revocation, contextual cyber policy, physical-state validation, operate-through-compromise behavior, evidence reconstruction, fleet scale, and governance cost. Absence of identified public evidence is not proof that no comparable system exists; the related-work search must actively seek counterexamples and narrow the claim.")

    heading(doc, "4. Research Objectives, Questions, and Hypotheses")
    add_paragraph(doc, "Primary objective: determine whether independently enforced, identity-bound and state-aware authorization reduces unsafe or unauthorized execution without imposing unacceptable mission, latency, availability, evidence, or operator costs.")
    table(doc, ["ID", "Research question", "Initial hypothesis"], [
        ["RQ1", "Unsafe-action containment", "B3 reduces unsafe execution relative to direct, identity-only, and static-policy baselines in defined scenarios."],
        ["RQ2", "Operational availability", "Bounded recovery authority can preserve safe mission actions with measurable false-block cost."],
        ["RQ3-RQ5", "Blast radius, state value, and revocation", "Attenuation and fresh physical state reduce reachable consequences; revocation remains bounded under stated availability assumptions."],
        ["RQ6-RQ9", "Performance, scale, economics, and evidence", "Assurance costs are measurable and increase with chain depth, state simulation, evidence volume, and approval burden."],
        ["RQ10", "Generalizability", "Some authorization properties transfer across domains; physical findings remain model-specific."],
    ], [0.7, 2.4, 3.4])

    heading(doc, "5. Scope, Assumptions, and Claim Boundaries")
    add_bullets(doc, [
        "In scope: synthetic telemetry, typed proposals, simulated assets, bounded adversarial conditions, local and future multi-node deployment, and reproducible evidence.",
        "Out of scope: production OT, real utility credentials, live third-party infrastructure, sub-cycle protection claims, and operational authorization.",
        "Formal guarantees apply only to the stated model, constants, invariants, trusted computing base, and explored state space.",
        "Empirical findings apply only to recorded versions, configurations, seeds, scenarios, and hosts.",
        "The v0.1 safety thresholds are provisional research parameters, not universal utility settings.",
    ])

    heading(doc, "6. Threat Model")
    add_paragraph(doc, "The adversary may compromise an authenticated agent, possess a bounded credential, forge or amplify a grant, replay a proposal, poison synthetic observations, delay revocation, exploit stale policy or state, create conflicting proposals, or disrupt a supporting service. The gateway, cryptographic implementation, trusted host, and evidence head are initially trusted; later work must reduce and test that trusted computing base.")
    table(doc, ["Threat family", "Required control", "Primary measure"], [
        ["Identity and credential compromise", "Short-lived identity, scope-bound grant, revocation", "Unauthorized execution and revocation delay"],
        ["Instruction or telemetry manipulation", "Typed proposal, freshness, independent state evaluation", "Unsafe escape and state divergence"],
        ["Replay and concurrency", "Atomic nonce reservation and TOCTOU check", "Duplicate execution and conflict rate"],
        ["Supervisor compromise", "Full-chain attenuation and bounded depth", "Agent and asset blast radius"],
        ["Service loss", "Explicit fail-closed and bounded degraded modes", "Availability, recovery time, residual risk"],
    ], [1.7, 2.9, 1.9])

    heading(doc, "7. System Requirements")
    table(doc, ["Requirement", "Statement", "Verification method"], [
        ["REQ-AUTH-001", "No action executes without verified actor identity and a valid full delegation chain.", "Negative and property tests; formal invariant"],
        ["REQ-DELEG-002", "A child grant cannot exceed parent resources, operations, time, risk, or delegation depth.", "Chain fuzzing and model checking"],
        ["REQ-SAFE-003", "A modeled-unsafe candidate transition is denied by an evaluator outside agent reasoning.", "Scenario tests and independent-oracle comparison"],
        ["REQ-REPLAY-004", "Nonce reuse is atomically rejected within the retention window.", "Concurrency test"],
        ["REQ-EVID-005", "Every gateway decision creates linked evidence sufficient for reconstruction.", "Chain verification and completeness audit"],
        ["REQ-TOCTOU-006", "The adapter rejects authorization when state version changes before execution.", "Integration test"],
    ], [1.05, 3.65, 1.8])

    heading(doc, "8. Reference Architecture")
    figure(doc, "architecture.png", "Figure 1. Aegis-OT reference action path.", "Architecture diagram showing synthetic telemetry flowing through a bounded agent, typed proposal, Aegis-OT gateway, authorization-bound command adapter, and simulated process. Gateway checks include identity, delegation, policy, freshness, replay, safety, approval, and evidence.")
    add_paragraph(doc, "The reference architecture separates observation, agent, authorization, safety, control, simulation, and evidence responsibilities. The current in-process implementation is an executable approximation of those interfaces; it does not demonstrate independent service or host isolation.")

    heading(doc, "9. Authorization and Safety Model")
    add_paragraph(doc, "The execution condition is: Executed(a) implies authenticated actor, valid and attenuated delegation, contextual policy permission, fresh matching state, unique nonce, modeled-safe candidate transition, and required approval. The adapter additionally binds the decision to the proposal and state version at execution time.")
    figure(doc, "decision_sequence.png", "Figure 2. Authorization and execution evidence sequence.", "Sequence diagram with agent, gateway, trust services, safety kernel, adapter, and evidence lanes. It shows proposal submission, identity and delegation verification, candidate transition evaluation, evidence append, command authorization, and acknowledgment.")

    heading(doc, "10. Formal Specification Strategy")
    add_paragraph(doc, f"The expanded TLA+ state machine models submission, authorization or denial, approval, dispatch, acknowledgment, execution, delegation validity, ancestor revocation with an explicit propagation bound, expiry, replay, policy and state consistency, conflicting actions, evidence, compromise, quarantine, and decision liveness. TLC version {FORMAL_MANIFEST['tool_version']} checked the intended configuration at commit {FORMAL_MANIFEST['git_commit'][:7]} with model SHA-256 {FORMAL_MANIFEST['model_sha256']}. It generated {FORMAL_INTENDED['states_generated']:,} states, found {FORMAL_INTENDED['distinct_states']:,} distinct states, reached depth {FORMAL_INTENDED['search_depth']}, and reported no invariant or liveness violation. All sixteen deliberately weakened cases reported their expected invariant violation. The result applies only to this abstraction, configuration, fairness condition, constants, tool build, and explored state space.")
    add_paragraph(doc, "Initial model-check finding: The first TLC run against the earlier scaffold found a specification defect: its revocation invariant retroactively treated a later grant revocation as invalidating an execution that had already completed. Revision 0.3 corrects this by recording whether revocation, expiry, state staleness, acknowledgment absence, or quarantine was effective at execution time. This was a defect in the specification, not evidence of a corresponding runtime exploit.", bold_lead="Initial model-check finding:")

    heading(doc, "11. Experimental Methodology")
    add_paragraph(doc, "The controlled M2 experiment executes eight baselines and ablations against 12 human-reviewed synthetic scenario templates spanning nominal, consequence-unsafe, guardband, identity, delegation-scope, freshness, confidence, and approval conditions. Thirty master seeds each run three shuffled catalog cycles. Trial seeds sample bounded action parameters within each template; execution stops if either the kernel or reference classification departs from the catalog's reviewed expectation. B0-B3 preserve the original direct, identity-only, static-policy, and complete-gateway paths. B4-B7 add contextual ABAC, risk-aware, safety-without-delegation, and delegation-without-freshness comparisons.")
    add_paragraph(doc, "The reference oracle receives the proposal and pre-action state and independently calculates the candidate state with decimal arithmetic. It does not consume the kernel's predicted state. Its tighter load, voltage, thermal, isolation, and battery guardbands deliberately expose sensitivity. Primary measures are conditional unsafe-action escape, unauthorized execution, false block, mission correctness, decision latency, and kernel-oracle disagreement. Wilson 95 percent intervals characterize records under the balanced synthetic design; they do not capture model-form or field uncertainty.")

    heading(doc, "12. Implementation and Verification Status")
    table(doc, ["Capability", "Current state", "Evidence boundary"], [
        ["Typed proposal and state", "Closed Pydantic models with operation-specific finite parameter validation and generated JSON Schema", "Local conformance only"],
        ["Signed delegation", "Ed25519 full-chain validation and attenuation", "Local keys; no SPIRE integration"],
        ["Gateway", "Fail-closed decision path with replay and freshness", "Single process"],
        ["Safety and oracle", "Separate candidate-state implementations with intentionally different guardbands", "Code-path independence only; no physical validation"],
        ["Evidence", "Hash-chained decision records", "Tamper-evident while trusted head is preserved"],
        ["Verification", "79 tests; ruff and strict mypy clean; 93 percent branch-aware coverage", "Python 3.14 local host; CI not yet observed"],
        ["Formal model", "17 safety/type invariants and one decision-liveness property checked; 16 weakened cases produced expected violations", "Bounded abstraction; not implementation or physical proof"],
    ], [1.55, 2.25, 2.7])

    heading(doc, "13. M2 Controlled Results")
    summary = MANIFEST["summary"]
    result_rows = []
    for baseline, values in summary.items():
        unsafe_ci = values["unsafe_action_escape_ci95"]
        unauthorized_ci = values["unauthorized_execution_ci95"]
        mission_ci = values["mission_success_ci95"]
        result_rows.append([
            baseline.split("_")[0],
            f"{values['unsafe_action_escape_rate']:.0%} [{unsafe_ci['lower']:.1%}, {unsafe_ci['upper']:.1%}]",
            f"{values['unauthorized_execution_rate']:.0%} [{unauthorized_ci['lower']:.1%}, {unauthorized_ci['upper']:.1%}]",
            f"{values['false_block_rate']:.0%}",
            f"{values['mission_success_rate']:.0%} [{mission_ci['lower']:.1%}, {mission_ci['upper']:.1%}]",
        ])
    table(doc, ["Baseline", "Unsafe escape [95% CI]", "Unauthorized [95% CI]", "False block", "Mission correct [95% CI]"], result_rows, [1.05, 1.55, 1.55, 0.85, 1.5])
    figure(doc, "baseline_results.png", "Figure 3. M2 synthetic baseline and ablation outcomes.", "Grouped bar chart comparing conditional unsafe-action escape and unauthorized execution across eight baselines. Each baseline has 1,080 trial records from 30 master seeds and 12 sampled scenario templates.")
    add_paragraph(doc, "Interpretation: B3_ASSURED recorded zero unauthorized executions among 450 authorization-negative records (Wilson 95 percent upper bound 0.85 percent), zero false blocks among 180 authorized reference-safe records (upper bound 2.09 percent), and 75 percent overall mission correctness (72.3-77.5 percent). It nevertheless executed 270 of 450 reference-unsafe records, a 60 percent conditional escape rate (55.4-64.4 percent), because the load, thermal, and voltage guardband templates were inside the runtime kernel's looser thresholds. B6 and B7 matched the 60 percent physical escape rate but each executed 20 percent of authorization-negative records, isolating the value of the omitted delegation or freshness control. Rates are conditional on this balanced catalog and do not estimate operational incident likelihood.")
    add_paragraph(doc, f"Reproducibility: the controlled run started from clean commit {MANIFEST['git_commit'][:7]}, wrote {MANIFEST['total_trial_records']:,} records, and produced deterministic outcome SHA-256 {MANIFEST['deterministic_outcome_sha256']}. A second run produced the same outcome hash. Raw hashes differ as expected because host timing is retained separately. B3 mean in-process decision latency was {summary['B3_ASSURED']['mean_decision_latency_ms']:.3f} ms on the recorded host; this is a local development measurement, not a deployment latency claim.")

    heading(doc, "14. Multi-VM Integration Plan")
    add_paragraph(doc, "The six-node scaffold separates management, trust, agent, gateway, OT, and simulation functions. The gateway must become the only routed path between the agent network and the OT environment. Exit evidence includes route and firewall inspection, negative connectivity tests, packet capture, gateway partition behavior, and host-specific deployment documentation. The present Vagrant file is an unvalidated VirtualBox scaffold; it is not evidence that a six-VM range has been deployed.")

    heading(doc, "15. Operate-Through-Compromise Test Program")
    add_bullets(doc, [
        "Compromise a leaf agent while unrelated agents retain bounded mission functions.",
        "Compromise or revoke a supervisor and measure descendant authority and propagation delay.",
        "Remove identity, policy, evidence, or gateway services and measure fail-closed behavior and recovery capacity.",
        "Inject delayed, replayed, biased, or contradictory telemetry and measure state-aware authorization value.",
        "Define quarantine and recovery authority before execution; do not introduce an emergency bypass that recreates direct control.",
    ])

    heading(doc, "16. Scale and Economic Analysis Plan")
    add_paragraph(doc, "Fleet experiments will use logical identities and synthetic authorization workloads at 10, 100, 1,000, and 10,000 agents rather than one VM per agent. Measures include throughput, queue delay, delegation graph complexity, revocation propagation, policy distribution, evidence volume, operator span, incident-response effort, and marginal governance cost. Any cost finding will state labor rates, infrastructure assumptions, utilization, retention, and sensitivity ranges.")

    heading(doc, "17. Reproducibility and Data Management")
    add_paragraph(doc, "The M2 manifest records clean-start Git state, scenario catalog and source hashes, all master seeds, baseline definitions, component versions, host details, raw-data path, timing-inclusive raw SHA-256, timing-independent outcome SHA-256, analyst, and known limitations. Raw JSONL retains sampled parameters and conditional outcomes. Derived summaries and figures are generated from committed code. The original exploratory run remains separately labeled and is excluded from M2 comparison.")

    heading(doc, "18. Risks, Limitations, and Validity Threats")
    table(doc, ["Threat to validity", "Current consequence", "Required mitigation"], [
        ["Rule-model physical validity", "Separate code paths can share incorrect physics", "Use an independently executed power-flow simulator and virtual PLC"],
        ["Guardband selection", "B3 permits three reference-unsafe boundary templates", "Calibrate thresholds and uncertainty against physical-model evidence"],
        ["Synthetic prevalence", "Rates do not estimate incident likelihood", "Report conditional scenario performance only"],
        ["Single host", "Trust boundaries and availability are untested", "Deploy and negatively test independent services and networks"],
        ["Designed scenario distribution", "Wilson intervals do not capture model-form or field uncertainty", "Add externally justified distributions and sensitivity analysis"],
    ], [1.65, 2.25, 2.6])

    heading(doc, "19. Work Plan and Completion Criteria")
    add_paragraph(doc, "The project advances through controlled governance, executable-kernel, formal-conformance, single-host experiment, physical and PLC integration, multi-node trust-boundary, operate-through-compromise, fleet-scale/economics, and independent-validation gates. A demonstration, green test suite, or perfect synthetic baseline does not satisfy the final completion definition.")

    heading(doc, "20. Conclusions")
    add_paragraph(doc, "The reconstructed v0.1 foundation now supports a defensible narrow finding: under the reviewed synthetic authorization cases, the complete gateway prevented authorization-invalid execution and outperformed partial control paths. The separately implemented reference model also exposed a material threshold-sensitivity gap: the gateway permitted every sampled load, thermal, and voltage guardband case classified outside the conservative reference envelope. That result prevents a premature perfect-safety claim and defines the next experiment. The bounded formal evidence and M2 control-path measurements remain insufficient to conclude that autonomous agents can be trusted on real critical infrastructure. The next defensible advance is independent power-system and virtual-PLC outcome evaluation, followed by deployed trust boundaries.")

    heading(doc, "21. References")
    references = [
        "National Institute of Standards and Technology. Guide to Operational Technology (OT) Security. NIST SP 800-82 Rev. 3, September 2023. https://doi.org/10.6028/NIST.SP.800-82r3. Retrieved 2026-08-24.",
        "National Institute of Standards and Technology. Zero Trust Architecture. NIST SP 800-207, August 2020. https://doi.org/10.6028/NIST.SP.800-207. Retrieved 2026-08-24.",
        "National Institute of Standards and Technology. A Zero Trust Architecture Model for Access Control in Cloud-Native Applications in Multi-Cloud Environments. NIST SP 800-207A, September 2023. https://doi.org/10.6028/NIST.SP.800-207A. Retrieved 2026-08-24.",
        "SPIFFE Project. The SPIFFE Standard and Workload API, specification v1.15.2. https://spiffe.io/docs/latest/spiffe-specs/. Retrieved 2026-08-24.",
        "Open Policy Agent. Policy Language and deployment documentation. https://www.openpolicyagent.org/docs/policy-language. Retrieved 2026-08-24.",
    ]
    add_bullets(doc, references)

    heading(doc, "22. Requirements Traceability Appendix")
    table(doc, ["Requirement", "Implementation", "Test/evidence", "Residual gap"], [
        ["REQ-AUTH-001", "gateway.py; identity.py; delegation.py", "test_unknown_identity; test_valid_full_chain", "No SPIRE service"],
        ["REQ-DELEG-002", "delegation.py", "Full-chain negative tests covering scope, time, depth, signature, expiry, revocation, and linkage", "Mutation testing and distributed revocation remain absent"],
        ["REQ-SAFE-003", "safety.py; oracle.py", "Independent candidate-state tests; 30-seed M2 comparison", "No independent physical simulator"],
        ["REQ-REPLAY-004", "replay.py", "Concurrent reservation and retention tests", "Distributed replay store absent"],
        ["REQ-EVID-005", "evidence.py", "Chain integrity and tampering tests", "No signature or external anchor"],
        ["REQ-TOCTOU-006", "lab.py", "State-version change integration test", "No real PLC acknowledgment"],
    ], [1.05, 1.8, 2.25, 1.4])

    heading(doc, "23. Data and Message Schemas Appendix")
    add_paragraph(doc, "The ActionProposal schema binds actor, mission, resource, operation, parameters, observed state and time, submission time, nonce, confidence, risk score, delegation chain, and optional approval identifier. Operation-specific parameter sets are closed, and non-finite numeric inputs, out-of-range percentages, extra fields, and timezone-naive timestamps are rejected at the validation boundary. The committed JSON Schema is generated from the authoritative Pydantic model and checked for drift in CI. Decision records bind outcome, reasons, policy and safety versions, state version, decision time, and evidence-record hash.")

    heading(doc, "24. Reproduction Runbook Appendix")
    add_bullets(doc, [
        "Create and activate a clean Python 3.11-or-later virtual environment.",
        "Install with pip install -e \".[dev,docs]\"; do not rely on PYTHONPATH.",
        "Run python scripts/export_schemas.py --check, ruff check ., mypy src, and pytest --cov=aegis_ot --cov-branch --cov-report=term-missing --cov-fail-under=90.",
        "Acquire the pinned TLC 1.8.0 JAR, verify SHA-256 eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a, and run python scripts/run_formal.py --jar /path/to/tla2tools.jar --output-dir results/formal/<run-name>.",
        "Run python -m aegis_ot demo --output-dir results/demo.",
        "Run python -m aegis_ot experiment --trials-per-seed 36 --seed-count 30 --seed 20260824 --output-dir results/m2-independent-oracle.",
        "Verify clean-start Git state, the raw-data hash, and deterministic outcome hash before reporting results; reproduce into a separate directory and compare outcome hashes.",
        "Build figures and the canonical document from committed scripts, then render and inspect every page.",
    ])

    heading(doc, "25. Version-Control Audit Trail Appendix")
    add_paragraph(doc, "This reconstruction begins a new Git history because the original package and its local uncommitted state were unavailable. No earlier commit hash is represented as an ancestor of this repository. Commit e94e47f records the reconstructed v0.1 foundation, c906ae7 records trust-boundary hardening, 3b5f129 records the bounded formal model and conformance mapping, e8b304d introduces the independent multi-seed evaluator, 050f9b1 corrects clean-start provenance capture, and cd20986 adds sampled reviewed scenario envelopes. The controlled M2 evidence was generated from clean cd20986 and independently reproduced by deterministic outcome hash. No tagged release or external CI run has been observed.")

    add_header_footer(doc)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUTPUT)
    body_text = " ".join(node.text or "" for node in doc.element.body.iter(qn("w:t")))
    words = len(re.findall(r"\b[\w'-]+\b", body_text))
    patch_extended_properties(OUTPUT, int(CURRENT_REVISION["page_count"]), words)
    print(json.dumps({"output": str(OUTPUT), "paragraph_word_count": words, "revision": REVISION_NUMBER}))


if __name__ == "__main__":
    build()
