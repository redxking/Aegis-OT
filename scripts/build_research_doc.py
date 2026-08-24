"""Build the single controlled Aegis-OT research study document."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from docx import Document
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "research" / "Aegis-OT_Research_Study.docx"
REVISION = json.loads((ROOT / "research" / "revision_log.json").read_text())
MANIFEST = json.loads((ROOT / "results" / "reproduction-v0.1" / "manifest.json").read_text())
BLUE = RGBColor(23, 105, 170)
DARK = RGBColor(16, 42, 67)
MUTED = RGBColor(82, 96, 109)
LIGHT_FILL = "EAF2F8"


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
        paragraph.paragraph_format.space_after = Pt(4)
        paragraph.paragraph_format.line_spacing = 1.15
        set_font(paragraph.add_run(item), 10.5)


def heading(doc: Document, text: str, level: int = 1) -> None:
    paragraph = doc.add_heading(text, level=level)
    paragraph.paragraph_format.keep_with_next = True


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
        set_font(header.add_run("AEGIS-OT-STUDY-001 | CONTROLLED RESEARCH STUDY | REV 0.1"), 8, color=MUTED)
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
    set_font(metadata.add_run("Document AEGIS-OT-STUDY-001 | Revision 0.1 | 24 August 2026"), 10, color=MUTED)
    boundary = doc.add_paragraph()
    boundary.alignment = WD_ALIGN_PARAGRAPH.CENTER
    boundary.paragraph_format.space_before = Pt(28)
    set_font(boundary.add_run("RESEARCH USE ONLY - SYNTHETIC AND SIMULATED ENVIRONMENTS"), 10, bold=True, color=RGBColor(166, 27, 27))
    doc.add_page_break()


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
    props.created = datetime(2026, 8, 24, 14, 39, 38, tzinfo=UTC)
    props.modified = datetime.now(UTC)
    props.revision = 1
    add_cover(doc)

    heading(doc, "Document Control")
    table(
        doc,
        ["Field", "Controlled value"],
        [
            ["Document identifier", "AEGIS-OT-STUDY-001"],
            ["Revision", "0.1"],
            ["Author and editor", "Angelis Pseftis"],
            ["Canonical file", "research/Aegis-OT_Research_Study.docx"],
            ["Evidence boundary", "Reconstructed repository; lost historical artifacts are not current evidence"],
        ],
        [1.65, 4.85],
    )
    heading(doc, "Revision History", 2)
    revision = REVISION["revisions"][0]
    table(
        doc,
        ["Revision", "UTC timestamp", "Editor", "Substantive change", "Evidence link"],
        [[revision["revision"], revision["timestamp_utc"], revision["editor"], revision["description"], revision["experiment_manifest"]]],
        [0.65, 1.2, 1.05, 2.55, 1.05],
    )
    add_paragraph(doc, "Control statement: This DOCX is the single authoritative editable manuscript. Git history and research/revision_log.json preserve its revision trail. Supporting Markdown, figures, renders, and data are not alternate manuscripts.")

    heading(doc, "Contents")
    sections = [
        "1 Abstract", "2 Executive Summary", "3 Introduction and Research Gap", "4 Research Objectives, Questions, and Hypotheses",
        "5 Scope, Assumptions, and Claim Boundaries", "6 Threat Model", "7 System Requirements", "8 Reference Architecture",
        "9 Authorization and Safety Model", "10 Formal Specification Strategy", "11 Experimental Methodology",
        "12 Implementation and Verification Status", "13 Preliminary Controlled Results", "14 Multi-VM Integration Plan",
        "15 Operate-Through-Compromise Test Program", "16 Scale and Economic Analysis Plan", "17 Reproducibility and Data Management",
        "18 Risks, Limitations, and Validity Threats", "19 Work Plan and Completion Criteria", "20 Conclusions", "21 References",
        "22 Requirements Traceability Appendix", "23 Data and Message Schemas Appendix", "24 Reproduction Runbook Appendix",
        "25 Version-Control Audit Trail Appendix",
    ]
    add_bullets(doc, sections)
    doc.add_page_break()

    heading(doc, "1. Abstract")
    add_paragraph(doc, "Aegis-OT investigates whether an independently enforced runtime-assurance control plane can prevent a validly authenticated but compromised, misled, stale, or faulty AI agent from executing actions outside its delegated mission and modeled cyber-physical safety envelope while preserving legitimate containment and recovery. The reconstructed v0.1 implementation binds typed proposals to Ed25519-signed delegation chains, contextual policy, state freshness, replay protection, a deterministic safety kernel, a command adapter, and hash-chained evidence. A separate post-decision rule oracle is used for initial experiments, although both it and the enforcer depend on the same simplified transition model. Current results therefore establish only internal control-path behavior in a synthetic local environment.")

    heading(doc, "2. Executive Summary")
    add_paragraph(doc, "The central engineering decision is that identity is necessary but insufficient. An agent never receives direct simulated-control authority; it receives authority to propose a bounded action. The gateway remains the policy-enforcement point and fails closed when identity, delegation, state, replay, policy, safety, or required approval cannot be established.")
    add_bullets(doc, [
        "Current verified implementation evidence: 26 passing tests, clean static type checking, clean linting, and 88 percent measured line coverage on the local Python 3.14 host.",
        "Current experiment evidence: 200 synthetic trials per baseline using a shared seed set and master seed 20260824.",
        "Current limitation: perfect performance by the assured baseline is expected under the simplified rules and cannot support a claim of field effectiveness.",
        "Next decision gate: strengthen delegation and concurrency testing, run the TLA+ model and weakened variants, and replace the shared transition model with an independently executed power-system reference.",
    ])

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
    add_paragraph(doc, "The initial TLA+ scaffold models submission, authorization, denial, execution, revocation, nonce use, and evidence existence. It includes invariants for authentication, scope, modeled safety, replay, evidence completeness, and revoked-grant execution. This document does not claim that TLC has been run. The next milestone must record the exact tool version, model hash, state count, runtime, invariant results, and counterexamples from deliberately weakened configurations.")

    heading(doc, "11. Experimental Methodology")
    add_paragraph(doc, "The reconstructed smoke experiment executes four baselines against the same 200 seeded isolation scenarios. The scenario generator varies critical-load impact and classifies the resulting candidate state using a post-decision oracle implemented outside the gateway. Direct access, identity-only, and static resource/risk policy baselines execute the proposed action; the assured baseline also evaluates delegation, contextual policy, freshness, replay, and modeled safety.")
    add_paragraph(doc, "Primary measures are unsafe-action escape, false block, mission-correct outcome, decision latency, and safety-kernel/oracle disagreement. This smoke design is exploratory: it has one master seed, a deterministic agent, synthetic prevalence, weak comparison baselines, and no confidence intervals or external physical simulator.")

    heading(doc, "12. Implementation and Verification Status")
    table(doc, ["Capability", "Current state", "Evidence boundary"], [
        ["Typed proposal and state", "Implemented with Pydantic validation", "Local conformance only"],
        ["Signed delegation", "Ed25519 full-chain validation and attenuation", "Local keys; no SPIRE integration"],
        ["Gateway", "Fail-closed decision path with replay and freshness", "Single process"],
        ["Safety and oracle", "Separate rule evaluators using a shared surrogate transition", "Not independent physical validation"],
        ["Evidence", "Hash-chained decision records", "Tamper-evident while trusted head is preserved"],
        ["Verification", "26 tests; ruff and strict mypy clean; 88 percent measured line coverage", "Python 3.14 local host; CI not yet observed"],
    ], [1.55, 2.25, 2.7])

    heading(doc, "13. Preliminary Controlled Results")
    summary = MANIFEST["summary"]
    result_rows = []
    for baseline, values in summary.items():
        result_rows.append([
            baseline,
            f"{values['unsafe_action_escape_rate']:.0%}",
            f"{values['false_block_rate']:.0%}",
            f"{values['mission_success_rate']:.0%}",
            f"{values['mean_decision_latency_ms']:.4f} ms",
        ])
    table(doc, ["Baseline", "Unsafe escape", "False block", "Mission success", "Mean latency"], result_rows, [1.35, 1.15, 1.05, 1.2, 1.75])
    figure(doc, "baseline_results.png", "Figure 3. Preliminary synthetic baseline outcomes.", "Grouped bar chart comparing unsafe-action escape and mission success for direct, identity-only, static-policy, and assured baselines over 200 shared-seed synthetic trials.")
    add_paragraph(doc, "Interpretation: the result demonstrates that the implemented assured path blocks the unsafe conditions encoded by the initial surrogate while permitting all encoded safe conditions. It does not demonstrate that real agents, PLCs, grids, operators, or incidents would produce the same result. The zero disagreement count is expected because both evaluators apply equivalent limits to the same simplified predicted state.")

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
    add_paragraph(doc, "The experiment manifest records the working-tree state, configuration hash, master and individual seeds, baseline definitions, component versions, host details, raw-data path, SHA-256 result hash, analyst, and known limitations. Raw JSONL is retained separately from derived summaries. The exploratory run that used different seed sets across baselines is preserved under results/exploratory-invalid-independent-seeds and excluded from controlled comparison.")

    heading(doc, "18. Risks, Limitations, and Validity Threats")
    table(doc, ["Threat to validity", "Current consequence", "Required mitigation"], [
        ["Shared transition model", "Kernel and oracle disagreement is not a strong independence test", "Use a separately executed power-flow simulator and reviewed truth set"],
        ["Weak baselines", "Effect size can be inflated", "Add contextual ABAC, risk-aware, and ablation baselines"],
        ["Synthetic prevalence", "Rates do not estimate incident likelihood", "Report conditional scenario performance only"],
        ["Single host", "Trust boundaries and availability are untested", "Deploy and negatively test independent services and networks"],
        ["One seed set", "Uncertainty is not characterized", "Use at least 30 independent seeds per condition and confidence intervals"],
    ], [1.65, 2.25, 2.6])

    heading(doc, "19. Work Plan and Completion Criteria")
    add_paragraph(doc, "The project advances through controlled governance, executable-kernel, formal-conformance, single-host experiment, physical and PLC integration, multi-node trust-boundary, operate-through-compromise, fleet-scale/economics, and independent-validation gates. A demonstration, green test suite, or perfect synthetic baseline does not satisfy the final completion definition.")

    heading(doc, "20. Conclusions")
    add_paragraph(doc, "The reconstructed v0.1 foundation is sufficient to test a narrow proposition: under its explicit synthetic rules, the gateway can distinguish safe from unsafe isolation proposals and preserve evidence of the decision. It is not sufficient to conclude that autonomous agents can be trusted on real critical infrastructure. The next defensible advance is independent model checking and physical outcome evaluation, followed by stronger baselines and deployed trust boundaries.")

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
        ["REQ-DELEG-002", "delegation.py", "amplification, expiry, forgery, ancestor revocation tests", "More property and fuzz coverage"],
        ["REQ-SAFE-003", "safety.py; oracle.py", "Hypothesis comparison and unsafe denial", "Shared transition model"],
        ["REQ-REPLAY-004", "replay.py", "Concurrent reservation and retention tests", "Distributed replay store absent"],
        ["REQ-EVID-005", "evidence.py", "Chain integrity and tampering tests", "No signature or external anchor"],
        ["REQ-TOCTOU-006", "lab.py", "State-version change integration test", "No real PLC acknowledgment"],
    ], [1.05, 1.8, 2.25, 1.4])

    heading(doc, "23. Data and Message Schemas Appendix")
    add_paragraph(doc, "The ActionProposal schema binds actor, mission, resource, operation, parameters, observed state and time, submission time, nonce, confidence, risk score, delegation chain, and optional approval identifier. Decision records bind outcome, reasons, policy and safety versions, state version, decision time, and evidence-record hash. JSON Schema source is maintained under schemas/ and Pydantic models are authoritative for the current implementation.")

    heading(doc, "24. Reproduction Runbook Appendix")
    add_bullets(doc, [
        "Create and activate a clean Python 3.11-or-later virtual environment.",
        "Install with pip install -e \".[dev,docs]\"; do not rely on PYTHONPATH.",
        "Run ruff check ., mypy src, and pytest --cov=aegis_ot --cov-report=term-missing.",
        "Run python -m aegis_ot demo --output-dir results/demo.",
        "Run python -m aegis_ot experiment --trials 200 --seed 20260824 --output-dir results/reproduction-v0.1.",
        "Verify the manifest raw-data hash and dirty-tree declaration before reporting results.",
        "Build figures and the canonical document from committed scripts, then render and inspect every page.",
    ])

    heading(doc, "25. Version-Control Audit Trail Appendix")
    add_paragraph(doc, "This reconstruction begins a new Git history because the original package and its local uncommitted state were unavailable. No earlier commit hash is represented as an ancestor of this repository. The initial controlled commit remains pending at document-build time so the experiment manifest correctly records an unknown commit and dirty working tree. A post-commit reproduction run is required before any tagged release.")

    add_header_footer(doc)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUTPUT)
    words = len(re.findall(r"\b[\w'-]+\b", " ".join(p.text for p in doc.paragraphs)))
    print(json.dumps({"output": str(OUTPUT), "paragraph_word_count": words, "revision": "0.1"}))


if __name__ == "__main__":
    build()
