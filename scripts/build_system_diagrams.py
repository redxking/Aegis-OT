"""Build or check the maintained Aegis-OT systems-engineering diagram set."""

# ruff: noqa: E501

from __future__ import annotations

import argparse
import html
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
OUTPUT_DIR: Final = ROOT / "assets" / "diagrams"


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


@dataclass(frozen=True)
class Point:
    x: int
    y: int


class Diagram:
    """Small deterministic SVG composer with a shared accessible visual language."""

    def __init__(
        self,
        title: str,
        subtitle: str,
        description: str,
        *,
        width: int = 1600,
        height: int = 900,
    ) -> None:
        self.title = title
        self.subtitle = subtitle
        self.description = description
        self.width = width
        self.height = height
        self.body: list[str] = []

    def raw(self, value: str) -> None:
        self.body.append(value)

    def rect(
        self,
        x: int,
        y: int,
        width: int,
        height: int,
        *,
        css: str = "component",
        radius: int = 14,
    ) -> None:
        self.raw(
            f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
            f'rx="{radius}" class="{_escape(css)}"/>'
        )

    def text(
        self,
        x: int,
        y: int,
        value: str,
        *,
        css: str = "body-text",
        anchor: str = "start",
    ) -> None:
        self.raw(
            f'<text x="{x}" y="{y}" class="{_escape(css)}" '
            f'text-anchor="{_escape(anchor)}">{_escape(value)}</text>'
        )

    def multiline(
        self,
        x: int,
        y: int,
        lines: Sequence[str],
        *,
        css: str = "box-text",
        anchor: str = "middle",
        spacing: int = 22,
    ) -> None:
        spans = "".join(
            f'<tspan x="{x}" dy="{0 if index == 0 else spacing}">{_escape(line)}</tspan>'
            for index, line in enumerate(lines)
        )
        self.raw(
            f'<text x="{x}" y="{y}" class="{_escape(css)}" '
            f'text-anchor="{_escape(anchor)}">{spans}</text>'
        )

    def box(
        self,
        x: int,
        y: int,
        width: int,
        height: int,
        title: str,
        lines: Sequence[str] = (),
        *,
        kind: str = "component",
        title_y: int = 34,
        text_css: str = "box-text",
        line_spacing: int = 23,
    ) -> None:
        self.rect(x, y, width, height, css=kind)
        self.text(x + width // 2, y + title_y, title, css="box-title", anchor="middle")
        if lines:
            self.multiline(
                x + width // 2,
                y + title_y + 29,
                lines,
                css=text_css,
                anchor="middle",
                spacing=line_spacing,
            )

    def lane(
        self,
        x: int,
        y: int,
        width: int,
        height: int,
        title: str,
        *,
        css: str = "lane",
    ) -> None:
        self.rect(x, y, width, height, css=css, radius=18)
        self.text(x + 24, y + 32, title, css="lane-title")

    def arrow(
        self,
        points: Iterable[Point],
        *,
        kind: str = "flow",
        label: str | None = None,
        label_at: Point | None = None,
    ) -> None:
        rendered = " ".join(f"{point.x},{point.y}" for point in points)
        self.raw(f'<polyline points="{rendered}" class="{_escape(kind)}"/>')
        if label is not None and label_at is not None:
            self.text(label_at.x, label_at.y, label, css="line-label", anchor="middle")

    def line(
        self,
        start: Point,
        end: Point,
        *,
        css: str = "connector",
    ) -> None:
        self.raw(
            f'<line x1="{start.x}" y1="{start.y}" x2="{end.x}" y2="{end.y}" '
            f'class="{_escape(css)}"/>'
        )

    def status(self, x: int, y: int, label: str, kind: str) -> None:
        width = max(108, 18 + len(label) * 8)
        self.rect(x, y, width, 28, css=f"status-{kind}", radius=14)
        self.text(x + width // 2, y + 19, label, css="status-text", anchor="middle")

    def render(self) -> str:
        style = """
      .page-title{font:700 36px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#13283f}
      .page-subtitle{font:500 17px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#516479}
      .lane-title{font:700 18px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#21364e}
      .section-title{font:700 20px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#172d45}
      .box-title{font:700 18px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#172d45}
      .box-text{font:500 14px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#455970}
      .box-text-large{font:500 16px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#40566f}
      .body-text{font:500 14px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#455970}
      .body-text-large{font:500 16px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#40566f}
      .small-text{font:500 13px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#5a6c80}
      .line-label{font:600 14px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#41556c;paint-order:stroke;stroke:#fff;stroke-width:6px;stroke-linejoin:round}
      .step-number{font:700 15px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#fff}
      .status-text{font:700 12px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#26394f}
      .lane{fill:#f8fafc;stroke:#9bacc0;stroke-width:2;stroke-dasharray:9 7}
      .lane-blue{fill:#f4f8fd;stroke:#89a6c5;stroke-width:2}
      .lane-green{fill:#f2faf6;stroke:#82b69c;stroke-width:2}
      .lane-amber{fill:#fffaf0;stroke:#c89543;stroke-width:2}
      .component{fill:#fff;stroke:#2b5d92;stroke-width:2.5}
      .primary{fill:#e8f2ff;stroke:#1768a8;stroke-width:3}
      .policy{fill:#f2edff;stroke:#7050a5;stroke-width:2.5}
      .plant{fill:#e9f7ef;stroke:#27835c;stroke-width:2.5}
      .evidence{fill:#f3f5f7;stroke:#687b91;stroke-width:2.5}
      .optional{fill:#fff8e9;stroke:#b56c14;stroke-width:2;stroke-dasharray:8 6}
      .active{fill:#fff2f2;stroke:#ad4949;stroke-width:2;stroke-dasharray:8 6}
      .outside{fill:#f7f7f8;stroke:#929aa4;stroke-width:2;stroke-dasharray:7 6}
      .terminal-good{fill:#e8f7ef;stroke:#27835c;stroke-width:2.5}
      .terminal-bad{fill:#fff0f0;stroke:#ad4949;stroke-width:2.5}
      .terminal-neutral{fill:#f3f5f7;stroke:#687b91;stroke-width:2.5}
      .flow{fill:none;stroke:#2b5d92;stroke-width:3;marker-end:url(#arrow-blue)}
      .return-flow{fill:none;stroke:#27835c;stroke-width:3;marker-end:url(#arrow-green)}
      .optional-flow{fill:none;stroke:#b56c14;stroke-width:2.5;stroke-dasharray:8 6;marker-end:url(#arrow-amber)}
      .active-flow{fill:none;stroke:#ad4949;stroke-width:2.5;stroke-dasharray:8 6;marker-end:url(#arrow-red)}
      .evidence-flow{fill:none;stroke:#687b91;stroke-width:3;marker-end:url(#arrow-gray)}
      .connector{stroke:#93a4b7;stroke-width:2;fill:none}
      .bus{stroke:#2b5d92;stroke-width:3;fill:none}
      .lifeline{stroke:#9bacc0;stroke-width:2;stroke-dasharray:7 6}
      .divider{stroke:#d7dee7;stroke-width:2}
      .status-implemented{fill:#e8f7ef;stroke:#27835c;stroke-width:1.5}
      .status-retained{fill:#e8f2ff;stroke:#1768a8;stroke-width:1.5}
      .status-optional{fill:#fff8e9;stroke:#b56c14;stroke-width:1.5}
      .status-active{fill:#fff2f2;stroke:#ad4949;stroke-width:1.5}
      .status-outside{fill:#f3f5f7;stroke:#929aa4;stroke-width:1.5}
      .phase-band{fill:#f8fafc;stroke:none}
      .phase-band-alt{fill:#eef5fb;stroke:none}
      .phase-label{font:700 12px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#687b91;letter-spacing:1px}
        """.strip()
        body = "\n  ".join(self.body)
        return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" height="{self.height}" viewBox="0 0 {self.width} {self.height}" role="img" aria-labelledby="title description">
  <title id="title">{_escape(self.title)}</title>
  <desc id="description">{_escape(self.description)}</desc>
  <metadata>Author: Angelis Pseftis</metadata>
  <defs>
    <style>{style}</style>
    <marker id="arrow-blue" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#2b5d92"/></marker>
    <marker id="arrow-green" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#27835c"/></marker>
    <marker id="arrow-amber" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#b56c14"/></marker>
    <marker id="arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#ad4949"/></marker>
    <marker id="arrow-gray" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#687b91"/></marker>
  </defs>
  <rect width="{self.width}" height="{self.height}" fill="#fff"/>
  <text x="64" y="54" class="page-title">{_escape(self.title)}</text>
  <text x="64" y="83" class="page-subtitle">{_escape(self.subtitle)}</text>
  {body}
</svg>
"""


def _step(diagram: Diagram, x: int, y: int, number: int) -> None:
    diagram.raw(f'<circle cx="{x}" cy="{y}" r="17" fill="#1768a8"/>')
    diagram.text(x, y + 5, str(number), css="step-number", anchor="middle")


def system_overview() -> Diagram:
    diagram = Diagram(
        "Aegis-OT segmented capability architecture",
        "Current single-host research configuration • simulated OT only",
        "The bounded agent reaches only the segmented gateway. The gateway checks OPA and uses separate observer, candidate, and OT-adapter services. Only the OT adapter can invoke plant apply. Optional identity and transport controls cover consequence-path workloads. M4i coordination is an optional bounded overlay with retained single-host evidence. The public demo is a separate read-only service using build-time packaged evidence.",
        height=1000,
    )
    diagram.lane(45, 110, 1510, 590, "Consequence path")
    diagram.box(
        75,
        325,
        205,
        105,
        "Bounded agent",
        ("ActionProposal", "No plant access"),
        text_css="box-text-large",
        line_spacing=25,
    )
    diagram.box(
        350,
        285,
        275,
        185,
        "Segmented gateway",
        (
            "Sole authorization route",
            "Identity + delegation",
            "Policy + replay + safety",
            "Evidence + disposition",
        ),
        kind="primary",
        text_css="box-text-large",
        line_spacing=25,
    )
    diagram.box(
        375,
        175,
        225,
        75,
        "OPA policy",
        ("Context policy",),
        kind="policy",
        text_css="box-text-large",
    )
    diagram.box(
        735,
        225,
        280,
        85,
        "Signed observer",
        ("Signed pre/post state",),
        text_css="box-text-large",
    )
    diagram.box(
        735,
        340,
        280,
        85,
        "Candidate evaluator",
        ("Non-mutating simulation",),
        text_css="box-text-large",
    )
    diagram.box(
        735,
        455,
        280,
        85,
        "OT adapter",
        ("Permit check + sole apply",),
        text_css="box-text-large",
    )
    diagram.box(
        1170,
        295,
        270,
        170,
        "Synthetic plant",
        (
            "Authoritative lab state",
            "capture • simulate",
            "apply + readback",
        ),
        kind="plant",
        text_css="box-text-large",
        line_spacing=25,
    )
    diagram.rect(700, 122, 780, 88, css="optional", radius=12)
    diagram.text(724, 151, "OPTIONAL IDENTITY + TRANSPORT OVERLAY", css="section-title")
    diagram.text(724, 176, "Application workload credentials • SPIRE X.509-SVID • mTLS")
    diagram.text(
        724,
        198,
        "App credentials: agent, gateway, OT • SPIRE SVIDs: gateway, observer, candidate, OT, plant",
    )
    diagram.arrow((Point(280, 378), Point(350, 378)), label="proposal", label_at=Point(315, 363))
    diagram.arrow(
        (Point(488, 285), Point(488, 250)), label="policy check", label_at=Point(548, 273)
    )
    diagram.line(Point(625, 378), Point(675, 378), css="connector")
    diagram.line(Point(675, 268), Point(675, 498), css="connector")
    for y, label in ((268, "observe"), (383, "simulate"), (498, "dispatch")):
        diagram.arrow((Point(675, y), Point(735, y)), label=label, label_at=Point(713, y - 17))
    for y in (268, 383, 498):
        diagram.line(Point(1015, y), Point(1085, y), css="connector")
    diagram.line(Point(1085, 268), Point(1085, 498), css="connector")
    diagram.arrow((Point(1085, 383), Point(1170, 383)), kind="return-flow")
    diagram.rect(350, 585, 1090, 74, css="evidence", radius=12)
    diagram.text(375, 615, "M4i EFFECT COORDINATION • BOUNDED OPTIONAL OVERLAY", css="section-title")
    diagram.text(
        375,
        641,
        "Gateway journal  ↔  signed prepare / commit / query  ↔  effect-coordinator journal",
    )
    diagram.text(1415, 641, "Retained single-host campaign • no exactly-once claim", anchor="end")
    diagram.lane(45, 735, 1510, 185, "Separate read-only evidence path")
    diagram.box(185, 800, 225, 78, "Browser / reviewer", title_y=45, kind="evidence")
    diagram.box(
        570,
        800,
        285,
        78,
        "Public evidence demo",
        ("127.0.0.1:8080 • GET only",),
        title_y=29,
        kind="evidence",
        text_css="box-text-large",
    )
    diagram.box(
        1040,
        800,
        300,
        78,
        "Packaged evidence.json",
        ("Built from retained M2/M3",),
        title_y=29,
        kind="evidence",
        text_css="box-text-large",
    )
    diagram.arrow((Point(410, 839), Point(570, 839)), kind="evidence-flow")
    diagram.arrow((Point(1040, 839), Point(855, 839)), kind="evidence-flow")
    diagram.text(
        1515, 965, "Research evidence ≠ deployment validation", css="small-text", anchor="end"
    )
    return diagram


def system_context() -> Diagram:
    diagram = Diagram(
        "System context and external interfaces",
        "Who interacts with Aegis-OT, what crosses the boundary, and what remains outside scope",
        "The context view separates proposal sources, reviewers, trust administration, simulated OT, and retained research evidence from the Aegis-OT runtime-assurance boundary.",
        height=1000,
    )
    diagram.lane(360, 120, 850, 595, "Aegis-OT runtime-assurance boundary", css="lane-blue")
    diagram.box(
        450,
        170,
        670,
        110,
        "Independent authorization",
        ("authority • freshness • replay • OPA policy • modeled safety • approval reference",),
        kind="primary",
    )
    diagram.box(
        450,
        355,
        310,
        130,
        "Evidence services",
        ("correlate", "sign / hash", "classify outcome"),
        kind="evidence",
    )
    diagram.box(
        810,
        355,
        310,
        130,
        "Consequence services",
        ("fresh observe", "non-mutating simulate", "dispatch at most once"),
    )
    diagram.box(
        450,
        560,
        670,
        95,
        "Fail-closed result",
        ("permit • deny • require approval • known no effect • unknown effect",),
        kind="terminal-neutral",
    )
    diagram.box(
        60,
        170,
        240,
        110,
        "Bounded agent",
        ("Proposes actions", "No direct control authority"),
        kind="outside",
    )
    diagram.box(
        1290,
        170,
        240,
        110,
        "Trust administrator",
        ("Policy • trust roots", "Credentials • registration"),
        kind="outside",
    )
    diagram.box(
        1290,
        355,
        240,
        130,
        "Simulated OT",
        ("Authoritative lab state", "PyModbus / pandapower", "No production connection"),
        kind="plant",
    )
    diagram.box(
        60,
        790,
        240,
        100,
        "Reviewer / operator",
        ("Reviews packaged evidence", "No direct runtime control"),
        kind="outside",
    )
    diagram.box(
        1290,
        790,
        240,
        100,
        "Retained results",
        ("Manifests • raw records", "hashes • signatures"),
        kind="evidence",
    )
    diagram.arrow(
        (Point(300, 225), Point(450, 225)), label="ActionProposal", label_at=Point(375, 208)
    )
    diagram.arrow(
        (Point(1290, 225), Point(1120, 225)),
        kind="optional-flow",
        label="policy + trust",
        label_at=Point(1205, 208),
    )
    diagram.arrow((Point(970, 280), Point(970, 355)), label="authorize", label_at=Point(1010, 322))
    diagram.arrow(
        (Point(600, 280), Point(600, 355)),
        kind="evidence-flow",
        label="decision record",
        label_at=Point(655, 322),
    )
    diagram.arrow(
        (Point(810, 420), Point(760, 420)),
        kind="evidence-flow",
        label="events",
        label_at=Point(785, 403),
    )
    diagram.arrow(
        (Point(1120, 400), Point(1290, 400)),
        kind="return-flow",
        label="bounded command",
        label_at=Point(1205, 383),
    )
    diagram.arrow(
        (Point(1290, 450), Point(1120, 450)),
        kind="return-flow",
        label="state + ACK",
        label_at=Point(1205, 475),
    )
    diagram.arrow(
        (Point(605, 485), Point(605, 560)),
        kind="evidence-flow",
        label="disposition",
        label_at=Point(655, 530),
    )
    diagram.arrow(
        (Point(1120, 607), Point(1235, 607), Point(1235, 820), Point(1290, 820)),
        kind="evidence-flow",
        label="retain",
        label_at=Point(1260, 745),
    )
    diagram.arrow(
        (Point(1290, 865), Point(300, 865)),
        kind="evidence-flow",
        label="read-only projection",
        label_at=Point(795, 847),
    )
    diagram.text(360, 748, "LEGEND", css="section-title")
    diagram.status(455, 731, "UNTRUSTED INPUT", "outside")
    diagram.status(645, 731, "IMPLEMENTED", "implemented")
    diagram.status(815, 731, "OPTIONAL", "optional")
    diagram.status(955, 731, "RETAINED EVIDENCE", "retained")
    diagram.text(
        1510,
        950,
        "Physical PLCs • HIL • multi-host deployment • field operation are outside the current boundary",
        css="small-text",
        anchor="end",
    )
    return diagram


def functional_decomposition() -> Diagram:
    diagram = Diagram(
        "Functional decomposition and decision responsibility",
        "Authorization produces a decision; only a permit can continue to controlled execution",
        "A functional view of the implemented decision path. It distinguishes input validation, authorization, consequence-path services, outcome classification, and retained evidence responsibilities.",
        height=1000,
    )
    diagram.lane(45, 120, 1510, 805, "Aegis-OT functional boundary", css="lane-blue")
    diagram.box(
        75,
        180,
        220,
        150,
        "Proposal intake",
        ("Schema validation", "Action + target", "Context + correlation"),
    )
    diagram.box(
        350,
        180,
        250,
        150,
        "Precondition evidence",
        ("Fresh signed capture", "Plant revision binding", "Observation correlation"),
    )
    diagram.box(
        655,
        150,
        420,
        210,
        "Independent authorization",
        (
            "Actor authority + optional workload credential",
            "Delegation scope and audience",
            "Freshness and replay resistance",
            "OPA contextual policy",
            "Safety envelope + approval reference",
        ),
        kind="primary",
    )
    diagram.box(
        1130,
        180,
        390,
        150,
        "Decision result",
        ("permit → consequence path", "deny → no dispatch", "require approval → no dispatch"),
        kind="terminal-neutral",
    )
    diagram.box(
        1200,
        460,
        300,
        150,
        "Candidate evaluation",
        ("Non-mutating simulate", "Modeled safety result", "Signed response"),
    )
    diagram.box(
        825,
        460,
        300,
        150,
        "Capability issuance",
        ("Signed permit", "Bound action + snapshot", "Expiry + correlation"),
        kind="policy",
    )
    diagram.box(
        450,
        460,
        300,
        150,
        "Controlled execution",
        ("Verify permit", "Dispatch once", "Acknowledge + readback"),
    )
    diagram.box(
        75,
        460,
        300,
        150,
        "Outcome evidence",
        ("Post-capture correlation", "Terminal classification", "Reason code + hashes"),
        kind="evidence",
    )
    diagram.box(
        300,
        680,
        1000,
        115,
        "Terminal disposition",
        (
            "not_dispatched • candidate_rejected • plc_rejected",
            "unknown_effect • observation_diverged • completed",
        ),
        kind="terminal-neutral",
    )
    for start, end in ((295, 350), (600, 655), (1075, 1130)):
        diagram.arrow((Point(start, 255), Point(end, 255)))
    diagram.arrow(
        (Point(1350, 330), Point(1350, 460)),
        label="permit only",
        label_at=Point(1400, 405),
    )
    diagram.arrow((Point(1200, 535), Point(1125, 535)))
    diagram.arrow((Point(825, 535), Point(750, 535)))
    diagram.arrow((Point(450, 535), Point(375, 535)), kind="evidence-flow")
    diagram.arrow(
        (Point(225, 610), Point(225, 650), Point(500, 650), Point(500, 680)),
        kind="evidence-flow",
        label="classify",
        label_at=Point(365, 640),
    )
    diagram.arrow(
        (Point(1350, 610), Point(1350, 650), Point(1100, 650), Point(1100, 680)),
        kind="evidence-flow",
        label="unsafe or misbound",
        label_at=Point(1225, 640),
    )
    diagram.arrow(
        (Point(1520, 255), Point(1535, 255), Point(1535, 737), Point(1300, 737)),
        kind="evidence-flow",
        label="deny or approval required",
        label_at=Point(1440, 670),
    )
    diagram.rect(150, 835, 1380, 70, css="optional", radius=12)
    diagram.text(175, 866, "APPROVAL BOUNDARY", css="section-title")
    diagram.text(
        515,
        867,
        "Current implementation checks that an approval reference is present when required; it does not validate an approval authority or signature.",
    )
    diagram.text(
        1510,
        965,
        "Enumerated but not emitted by the current gateway: quarantine • modify • defer • simulate • revoke",
        css="small-text",
        anchor="end",
    )
    return diagram


def deployment_network() -> Diagram:
    diagram = Diagram(
        "Deployment and network segmentation",
        "Base topology with optional capability membership noted • single host • internal consequence-path networks",
        "The default Compose deployment publishes only the read-only demo and segmented gateway on loopback. Internal networks constrain service reachability; the same service may bridge adjacent zones.",
    )
    diagram.rect(40, 110, 1520, 690, css="outside", radius=20)
    diagram.text(65, 142, "SINGLE CONTAINER HOST", css="section-title")
    rows = (
        ("demo", 175, "lane", "public gateway", "Read-only packaged evidence service"),
        (
            "agent",
            285,
            "lane-blue",
            "agent-probe (experiment profile) • segmented-gateway",
            "Proposal ingress",
        ),
        (
            "trust • internal",
            395,
            "lane-amber",
            "segmented-gateway • OPA",
            "Optional: SPIRE server + agent • policy and workload API",
        ),
        (
            "control_dmz • internal",
            505,
            "lane-blue",
            "segmented-gateway • observer • OT adapter",
            "Optional: candidate + transport-probe • consequence orchestration",
        ),
        (
            "simulation • internal",
            615,
            "lane-green",
            "observer • OT adapter • synthetic plant",
            "Optional: candidate • capture, simulate, apply/readback",
        ),
    )
    for name, y, css, members, purpose in rows:
        diagram.rect(265, y, 1225, 82, css=css, radius=12)
        diagram.text(290, y + 31, members, css="box-title")
        diagram.text(290, y + 57, purpose, css="body-text")
        diagram.text(1460, y + 46, name, css="line-label", anchor="end")
    diagram.box(
        65,
        200,
        160,
        70,
        "Loopback port",
        ("127.0.0.1:8080",),
        kind="evidence",
        title_y=25,
    )
    diagram.box(
        65,
        310,
        160,
        70,
        "Loopback port",
        ("127.0.0.1:8081",),
        kind="primary",
        title_y=25,
    )
    diagram.arrow((Point(225, 236), Point(265, 216)), kind="evidence-flow")
    diagram.arrow((Point(225, 346), Point(265, 326)))
    diagram.rect(55, 445, 180, 192, css="optional", radius=12)
    diagram.text(145, 478, "Bridging services", css="box-title", anchor="middle")
    diagram.multiline(
        145,
        510,
        (
            "gateway",
            "agent • trust • DMZ",
            "observer • candidate",
            "OT adapter",
            "DMZ • simulation",
        ),
        css="box-text",
    )
    diagram.box(
        65,
        675,
        160,
        72,
        "No host port",
        ("OPA + OT services",),
        kind="terminal-good",
        title_y=26,
    )
    diagram.text(
        75,
        835,
        "Default `docker compose up` starts the base topology. Candidate and assurance controls are introduced only by explicit overlays.",
        css="small-text",
    )
    diagram.status(1275, 820, "IMPLEMENTED TOPOLOGY", "implemented")
    return diagram


def assurance_overlay_stack() -> Diagram:
    diagram = Diagram(
        "Assurance overlay stack",
        "Compose overlays are ordered experiments, not features enabled by the default command",
        "Each overlay extends the layers below it. The final coordination overlay is optional, has retained single-host evidence, and is not the default control path.",
    )
    x = 220
    width = 1160
    layers = (
        (
            "BASE",
            "docker-compose.yml",
            "Segmentation • OPA • observer • OT adapter • synthetic plant",
            "retained",
            "RETAINED EVIDENCE",
        ),
        (
            "AUTH",
            "docker-compose.auth.yml",
            "Signed request envelopes • audience • freshness",
            "retained",
            "RETAINED EVIDENCE",
        ),
        (
            "REPLAY",
            "docker-compose.replay.yml",
            "Persistent exact-envelope replay ledger",
            "retained",
            "RETAINED EVIDENCE",
        ),
        (
            "CAPABILITY",
            "docker-compose.capability.yml",
            "Signed observation • candidate simulation • signed permit • plant ACK",
            "implemented",
            "IMPLEMENTED",
        ),
        (
            "IDENTITY",
            "docker-compose.identity.yml",
            "Application workload credentials • trust bundle • semantic replay",
            "retained",
            "RETAINED EVIDENCE",
        ),
        (
            "SPIRE",
            "docker-compose.spire.yml",
            "SPIFFE X.509-SVID issuance • internal mTLS",
            "optional",
            "OPTIONAL • NO RETAINED RUN",
        ),
        (
            "COORDINATION",
            "docker-compose.coordination.yml",
            "Two journals • prepare / commit / query protocol",
            "retained",
            "RETAINED SINGLE-HOST EVIDENCE",
        ),
    )
    for index, (label, filename, purpose, status, badge_label) in enumerate(layers):
        y = 130 + index * 91
        css = (
            "active" if status == "active" else "optional" if status == "optional" else "component"
        )
        if index == 0:
            css = "primary"
        diagram.rect(x, y, width, 66, css=css, radius=12)
        diagram.text(x + 24, y + 27, label, css="box-title")
        diagram.text(x + 205, y + 27, filename, css="line-label")
        diagram.text(x + 205, y + 51, purpose, css="small-text")
        badge_x = x + width - max(108, 18 + len(badge_label) * 8) - 18
        diagram.status(badge_x, y + 18, badge_label, status)
        if index < len(layers) - 1:
            diagram.arrow((Point(800, y + 66), Point(800, y + 91)), kind="optional-flow")
    diagram.box(40, 130, 145, 66, "Default", ("base only",), kind="terminal-good", title_y=25)
    diagram.arrow((Point(185, 163), Point(220, 163)), kind="return-flow")
    diagram.rect(220, 785, 1160, 58, css="evidence", radius=12)
    diagram.text(
        800,
        820,
        "M4i is exercised through the optional coordination overlay; the default gateway remains non-coordinated and required mode rejects the legacy execute path.",
        css="body-text",
        anchor="middle",
    )
    return diagram


def action_transaction_sequence() -> Diagram:
    diagram = Diagram(
        "Authorized action transaction",
        "Observe first • authorize independently • simulate • dispatch once • verify effect",
        "Sequence view of the capability transaction from challenged pre-observation through authorization, candidate evaluation, permit verification, plant acknowledgment, post-observation, and terminal classification.",
        height=1100,
    )
    phases = (
        (185, 170, "OBSERVE", "phase-band"),
        (360, 195, "AUTHORIZE", "phase-band-alt"),
        (560, 50, "SIMULATE", "phase-band"),
        (615, 185, "DISPATCH", "phase-band-alt"),
        (805, 135, "VERIFY + CLASSIFY", "phase-band"),
    )
    for y, height, label, css in phases:
        diagram.rect(45, y, 1510, height, css=css, radius=0)
        diagram.text(1535, y + 22, label, css="phase-label", anchor="end")
    actors = (
        ("Agent", 90),
        ("Gateway", 300),
        ("OPA", 500),
        ("Observer", 700),
        ("Candidate", 910),
        ("OT adapter", 1140),
        ("Plant", 1400),
    )
    for name, x in actors:
        diagram.box(x - 75, 115, 150, 52, name, kind="component", title_y=32)
        diagram.line(Point(x, 167), Point(x, 940), css="lifeline")
    steps = (
        (1, 200, 90, 300, "Request challenged pre-observation", "flow"),
        (2, 245, 300, 700, "Request pre-capture", "flow"),
        (3, 290, 700, 1400, "Signed read-only capture", "flow"),
        (4, 335, 700, 300, "Signed pre-observation", "return-flow"),
        (5, 390, 90, 300, "Action + bound pre-observation", "flow"),
        (6, 435, 300, 700, "Resolve + verify pre-observation", "flow"),
        (7, 480, 300, 500, "OPA policy-permit query", "flow"),
        (8, 535, 300, 910, "Request candidate evaluation", "flow"),
        (9, 580, 910, 1400, "Non-mutating bound simulation", "flow"),
        (10, 645, 300, 1140, "Execute once with signed permit", "flow"),
        (11, 690, 1140, 1400, "Signed compare-and-set apply", "flow"),
        (12, 735, 1400, 1140, "Signed effect acknowledgment", "return-flow"),
        (13, 780, 1140, 300, "Verified signed response", "return-flow"),
        (14, 825, 300, 700, "Post-capture after valid applied ACK", "flow"),
        (15, 870, 700, 1400, "Signed read-only post-capture", "flow"),
        (16, 915, 700, 300, "Bound post-observation + terminal status", "return-flow"),
    )
    for number, y, start, end, label, kind in steps:
        _step(diagram, min(start, end) - 28, y, number)
        diagram.arrow(
            (Point(start, y), Point(end, y)),
            kind=kind,
            label=label,
            label_at=Point((start + end) // 2, y - 21),
        )
    diagram.rect(235, 970, 1285, 82, css="active", radius=10)
    diagram.multiline(
        878,
        998,
        (
            "Policy denial or unsafe candidate → no dispatch • missing consequential evidence → unknown_effect • automatic_retry_count = 0",
            "M4i prepare / commit / query is an optional overlay and is not a default branch of this transaction",
        ),
        css="box-text",
        anchor="middle",
    )
    return diagram


def outcome_state_model() -> Diagram:
    diagram = Diagram(
        "Outcome and effect state models",
        "Implemented capability disposition above • M4i coordination model below",
        "Two related state models: the implemented capability transaction terminal classifications and the component-tested M4i effect coordination states. M4i is not wired end to end.",
        height=1030,
    )
    diagram.lane(
        45, 115, 1510, 420, "Implemented capability terminal classification", css="lane-blue"
    )
    diagram.box(
        80, 175, 240, 70, "Prerequisite gates", ("before PLC call",), kind="primary", title_y=29
    )
    diagram.box(
        470, 175, 240, 70, "PLC gateway called", ("at most once",), kind="policy", title_y=29
    )
    diagram.box(
        860,
        175,
        285,
        70,
        "ACK + post evidence",
        ("verify transaction bindings",),
        kind="evidence",
        title_y=29,
    )
    diagram.arrow(
        (Point(320, 210), Point(470, 210)),
        label="permitted candidate",
        label_at=Point(395, 194),
    )
    diagram.arrow((Point(710, 210), Point(860, 210)), label="signed ACK", label_at=Point(785, 194))
    terminals = (
        (
            "not_dispatched",
            ("known before call", "dispatch_attempts = 0"),
            55,
            "terminal-neutral",
        ),
        (
            "candidate_rejected",
            ("unsafe/misbound candidate", "or signed attestation reject"),
            305,
            "terminal-bad",
        ),
        ("plc_rejected", ("valid signed reject ACK", "known no effect"), 555, "terminal-bad"),
        (
            "unknown_effect",
            ("consequential evidence", "missing / invalid / uncertain"),
            805,
            "active",
        ),
        (
            "observation_diverged",
            ("applied ACK contradicts", "valid signed post-state"),
            1055,
            "active",
        ),
        ("completed", ("applied ACK matches", "signed post-state"), 1305, "terminal-good"),
    )
    for title, lines, x, kind in terminals:
        diagram.box(x, 365, 220, 105, title, lines, kind=kind, title_y=30)
    diagram.arrow((Point(200, 245), Point(165, 365)))
    diagram.arrow((Point(280, 245), Point(415, 365)))
    diagram.arrow((Point(570, 245), Point(665, 365)))
    diagram.arrow((Point(650, 245), Point(915, 365)))
    diagram.arrow((Point(1000, 245), Point(1165, 365)))
    diagram.arrow((Point(1060, 245), Point(1415, 365)))
    diagram.text(
        800,
        510,
        "No automatic retry after consequential dispatch • terminal status is bounded transaction evidence, not field validation",
        css="small-text",
        anchor="middle",
    )

    diagram.lane(
        45,
        580,
        1510,
        355,
        "M4i effect-coordinator state machine • bounded optional overlay",
        css="lane-amber",
    )
    states = (
        ("RECEIVED", 85, 650, "primary"),
        ("DISPATCH_ARMED", 355, 650, "policy"),
        ("COMMIT_ACCEPTED", 690, 650, "policy"),
        ("APPLIED", 1085, 620, "terminal-good"),
        ("REJECTED", 1325, 620, "terminal-bad"),
        ("UNKNOWN_EFFECT", 1085, 785, "active"),
        ("NOT_DISPATCHED", 355, 810, "terminal-neutral"),
    )
    widths = {
        "RECEIVED": 200,
        "DISPATCH_ARMED": 250,
        "COMMIT_ACCEPTED": 270,
        "APPLIED": 190,
        "REJECTED": 190,
        "UNKNOWN_EFFECT": 430,
        "NOT_DISPATCHED": 250,
    }
    for title, x, y, kind in states:
        if title == "UNKNOWN_EFFECT":
            diagram.box(
                x,
                y,
                widths[title],
                85,
                title,
                ("query may resolve to APPLIED or REJECTED",),
                kind=kind,
                title_y=29,
            )
        else:
            diagram.box(x, y, widths[title], 65, title, kind=kind, title_y=40)
    diagram.arrow((Point(285, 682), Point(355, 682)), label="prepare", label_at=Point(320, 666))
    diagram.arrow((Point(605, 682), Point(690, 682)), label="commit", label_at=Point(647, 666))
    diagram.arrow((Point(960, 672), Point(1085, 652)))
    diagram.arrow(
        (Point(960, 688), Point(1000, 688), Point(1000, 725), Point(1420, 725), Point(1420, 685)),
    )
    diagram.arrow((Point(825, 715), Point(1085, 827)))
    diagram.arrow(
        (Point(185, 715), Point(185, 842), Point(355, 842)),
    )
    diagram.arrow((Point(480, 715), Point(480, 810)))
    diagram.arrow(
        (Point(1150, 785), Point(1035, 745), Point(1035, 600), Point(1180, 600), Point(1180, 620)),
        kind="return-flow",
    )
    diagram.arrow(
        (Point(1450, 785), Point(1525, 745), Point(1525, 590), Point(1420, 590), Point(1420, 620)),
        kind="return-flow",
    )
    diagram.text(
        800,
        915,
        "Nonterminal knowledge states: COMMIT_ACCEPTED, UNKNOWN_EFFECT • terminal: NOT_DISPATCHED, APPLIED, REJECTED",
        css="small-text",
        anchor="middle",
    )
    diagram.status(80, 965, "RETAINED SINGLE-HOST", "retained")
    diagram.text(
        1515,
        985,
        "Retained local campaign • no consensus • no exactly-once-effect claim",
        css="small-text",
        anchor="end",
    )
    return diagram


def identity_trust_lifecycle() -> Diagram:
    diagram = Diagram(
        "Identity and transport trust lifecycle",
        "Application credentials and SPIRE mTLS are complementary controls with different boundaries",
        "The identity view separates application-level workload credentials from optional SPIRE-issued X.509-SVIDs. It also shows which links remain HTTP and the non-immediate revocation boundary.",
    )
    diagram.lane(45, 120, 725, 650, "Application workload identity • M4g", css="lane-blue")
    diagram.box(
        80,
        190,
        260,
        100,
        "Offline authority",
        ("Root signs credentials", "Trust bundle distributed"),
        kind="policy",
    )
    diagram.box(
        445,
        165,
        275,
        130,
        "identity-init",
        ("Creates agent, gateway,", "and OT credentials", "Mounts bundle read-only"),
    )
    diagram.arrow((Point(340, 240), Point(445, 240)), label="signing key", label_at=Point(392, 222))
    diagram.text(68, 325, "PROVISIONING", css="phase-label")
    diagram.line(Point(65, 340), Point(750, 340), css="divider")
    diagram.text(68, 365, "RUNTIME", css="phase-label")
    for title, y in (("Agent probe", 375), ("Segmented gateway", 495), ("OT adapter", 615)):
        diagram.box(120, y, 245, 75, title, ("credential + private key",), title_y=29)
    diagram.line(Point(500, 295), Point(500, 330), css="bus")
    diagram.line(Point(80, 330), Point(500, 330), css="bus")
    diagram.line(Point(80, 330), Point(80, 652), css="bus")
    diagram.text(290, 319, "read-only credential files", css="line-label", anchor="middle")
    for y in (412, 532, 652):
        diagram.arrow((Point(80, y), Point(120, y)))
    diagram.box(
        465,
        420,
        235,
        135,
        "Signed envelopes",
        ("agent → gateway proposal", "gateway → OT dispatch", "subject • audience • freshness"),
        kind="primary",
    )
    diagram.box(465, 625, 235, 85, "Workload replay", ("persistent ledger",), kind="evidence")
    diagram.arrow(
        (Point(365, 412), Point(465, 462)), label="sign proposal", label_at=Point(412, 424)
    )
    diagram.arrow(
        (Point(365, 532), Point(465, 502)), label="sign dispatch", label_at=Point(415, 480)
    )
    diagram.arrow(
        (Point(465, 522), Point(415, 522), Point(415, 652), Point(365, 652)),
        kind="return-flow",
        label="verify",
        label_at=Point(390, 635),
    )
    diagram.arrow((Point(582, 555), Point(582, 625)), kind="evidence-flow")

    diagram.lane(
        825, 120, 730, 650, "SPIRE transport identity • optional overlay", css="lane-amber"
    )
    diagram.box(
        865,
        170,
        260,
        100,
        "SPIRE server",
        ("Registration entries", "Trust domain authority"),
        kind="policy",
    )
    diagram.box(1230, 170, 260, 100, "SPIRE agent", ("Node attestation", "Workload API socket"))
    diagram.arrow(
        (Point(1125, 220), Point(1230, 220)),
        kind="optional-flow",
        label="issue",
        label_at=Point(1177, 204),
    )
    diagram.box(
        900,
        355,
        550,
        105,
        "Consequence-path workloads",
        (
            "gateway • observer • candidate • OT adapter • plant",
            "X.509-SVID + peer SPIFFE-ID allowlists",
        ),
        kind="optional",
    )
    diagram.arrow(
        (Point(1360, 270), Point(1360, 315), Point(1175, 315), Point(1175, 355)),
        kind="optional-flow",
        label="Workload API",
        label_at=Point(1265, 305),
    )
    diagram.box(
        900,
        520,
        550,
        85,
        "Internal mTLS links",
        ("Gateway ↔ consequence services ↔ plant",),
        kind="terminal-good",
    )
    diagram.arrow((Point(1175, 460), Point(1175, 520)), kind="optional-flow")
    diagram.rect(875, 650, 600, 82, css="active", radius=12)
    diagram.multiline(
        1175,
        678,
        (
            "Deleting a registration stops fresh issuance;",
            "it does not immediately revoke an already-issued certificate.",
        ),
        css="box-text",
    )
    diagram.text(
        800,
        820,
        "Agent → gateway and host → gateway remain HTTP; application-level credentials protect the agent proposal path.",
        css="small-text",
        anchor="middle",
    )
    return diagram


def replay_effect_coordination() -> Diagram:
    diagram = Diagram(
        "Replay resistance and effect coordination",
        "Three layers address different duplicate and uncertainty hazards",
        "Transport replay, semantic replay, and M4i effect coordination are distinct controls. The first two are integrated; M4i remains a component-tested protocol not wired into the current end-to-end runtime.",
    )
    columns = (
        (
            55,
            "1 • Exact-envelope replay",
            ("Signed request bytes", "Nonce / freshness / audience", "Persistent transport ledger"),
            "Duplicate envelope → reject",
            "component",
        ),
        (
            590,
            "2 • Semantic replay",
            (
                "Workload subject + action",
                "Effect/correlation identity",
                "Persistent semantic ledger",
            ),
            "Same intended effect → reject",
            "primary",
        ),
        (
            1125,
            "3 • Effect coordination",
            (
                "Signed prepare / commit / query",
                "Gateway + OT journals",
                "Recovery by reconciliation",
            ),
            "Uncertain result → query; no blind retry",
            "active",
        ),
    )
    for x, title, lines, outcome, kind in columns:
        diagram.box(x, 170, 420, 180, title, lines, kind=kind)
        diagram.arrow(
            (Point(x + 210, 350), Point(x + 210, 430)),
            kind="active-flow" if kind == "active" else "flow",
        )
        diagram.box(
            x + 30,
            430,
            360,
            90,
            "Guarded result",
            (outcome,),
            kind="terminal-neutral",
            title_y=30,
        )
    diagram.arrow((Point(475, 260), Point(590, 260)), kind="optional-flow")
    diagram.arrow((Point(1010, 260), Point(1125, 260)), kind="active-flow")
    diagram.status(211, 540, "INTEGRATED", "implemented")
    diagram.status(746, 540, "INTEGRATED", "implemented")
    diagram.status(1250, 540, "RETAINED SINGLE-HOST", "retained")
    diagram.lane(55, 590, 1430, 235, "M4i protocol boundary • bounded optional overlay", css="lane-amber")
    diagram.box(
        105,
        650,
        300,
        95,
        "Gateway journal",
        ("RECEIVED", "→ DISPATCH_ARMED"),
        kind="evidence",
    )
    diagram.box(
        640,
        630,
        320,
        130,
        "Signed coordination",
        ("prepare", "commit", "query"),
        kind="active",
    )
    diagram.box(
        1195,
        650,
        270,
        95,
        "OT journal",
        ("COMMIT_ACCEPTED", "effect outcome"),
        kind="evidence",
    )
    diagram.arrow(
        (Point(405, 680), Point(640, 680)),
        kind="active-flow",
        label="prepare",
        label_at=Point(522, 662),
    )
    diagram.arrow(
        (Point(960, 680), Point(1195, 680)),
        kind="active-flow",
        label="commit / query",
        label_at=Point(1078, 662),
    )
    diagram.arrow(
        (Point(1195, 730), Point(960, 730)),
        kind="return-flow",
        label="signed outcome",
        label_at=Point(1078, 754),
    )
    return diagram


def evidence_reproducibility() -> Diagram:
    diagram = Diagram(
        "Evidence, provenance, and public-demo flow",
        "Experiment artifacts are built and verified before the read-only runtime serves a packaged projection",
        "The evidence flow distinguishes source and experiment execution from offline verification, retained artifacts, build-time public-demo packaging, and runtime presentation.",
    )
    diagram.lane(45, 120, 1510, 355, "Experiment and retention boundary", css="lane-blue")
    diagram.box(
        75,
        205,
        205,
        120,
        "Clean source state",
        ("Revision + dirty state", "Config + seeds", "Pinned dependencies"),
    )
    diagram.box(
        345,
        205,
        205,
        120,
        "Experiment runner",
        ("Formal / synthetic", "fault / adversarial", "primary + reproduction"),
        kind="primary",
    )
    diagram.box(
        615,
        185,
        230,
        160,
        "Raw artifacts",
        ("Trials / traces", "Summary reports", "Manifests", "Hashes / signatures"),
        kind="evidence",
    )
    diagram.box(
        910,
        205,
        225,
        120,
        "Offline verification",
        ("Package integrity", "Acceptance criteria", "Source binding"),
        kind="policy",
    )
    diagram.box(
        1200,
        205,
        280,
        120,
        "Retained evidence",
        ("Immutable directory per run", "Primary + local reproduction", "External trust anchors"),
        kind="terminal-good",
    )
    for start, end in ((280, 345), (550, 615), (845, 910), (1135, 1200)):
        diagram.arrow((Point(start, 265), Point(end, 265)), kind="evidence-flow")
    diagram.rect(75, 365, 1405, 82, css="optional", radius=12)
    diagram.multiline(
        777,
        397,
        (
            "Evidence strength varies by milestone.",
            "Absence of a retained campaign is not validation evidence.",
        ),
        css="body-text-large",
        anchor="middle",
        spacing=24,
    )

    diagram.lane(
        45, 520, 1510, 275, "Build-time package → runtime read-only projection", css="lane-green"
    )
    diagram.box(
        100,
        595,
        300,
        110,
        "M2 + M3 retained inputs",
        ("Raw / manifests / packages", "Git object checks"),
        kind="evidence",
    )
    diagram.box(
        500,
        575,
        320,
        150,
        "build_public_demo.py",
        (
            "Recomputes and validates M2",
            "Verifies both M3 packages",
            "Checks equivalence + source blobs",
            "Writes packaged projection",
        ),
        kind="policy",
    )
    diagram.box(
        920,
        595,
        250,
        110,
        "evidence.json",
        ("Stored under web_demo", "Copied into image"),
        kind="primary",
    )
    diagram.box(
        1270,
        595,
        220,
        110,
        "Public demo",
        ("Loads packaged JSON", "GET-only evidence API"),
        kind="terminal-good",
    )
    diagram.arrow((Point(400, 650), Point(500, 650)), kind="evidence-flow")
    diagram.arrow((Point(820, 650), Point(920, 650)), kind="evidence-flow")
    diagram.arrow((Point(1170, 650), Point(1270, 650)), kind="evidence-flow")
    diagram.text(660, 765, "BUILD TIME", css="line-label", anchor="middle")
    diagram.text(1375, 765, "RUNTIME", css="line-label", anchor="middle")
    diagram.line(Point(1215, 550), Point(1215, 625), css="divider")
    diagram.line(Point(1215, 675), Point(1215, 760), css="divider")
    diagram.text(
        1515,
        840,
        "The runtime does not read mutable results/ directories.",
        css="small-text",
        anchor="end",
    )
    return diagram


def developer_setup_verification() -> Diagram:
    diagram = Diagram(
        "Developer setup and verification workflow",
        "A reproducible path from clean checkout to locally verified evidence",
        "The setup workflow separates environment preparation, static and unit checks, Compose validation, bounded experiments, offline verification, and evidence retention.",
    )
    phases = (
        ("1", "Prepare", ("Clean checkout", "Python 3.11+", "Create .venv"), 65, "component"),
        (
            "2",
            "Install",
            ("pip install -e '.[dev]'", "Optional simulation extra", "No generated evidence yet"),
            325,
            "component",
        ),
        ("3", "Local checks", ("ruff + formatting", "mypy", "pytest"), 585, "primary"),
        (
            "4",
            "Topology checks",
            ("Compose config", "Base smoke", "Explicit overlay runner"),
            845,
            "policy",
        ),
        (
            "5",
            "Experiment",
            ("New output directory", "Fixed config + seeds", "Record source state"),
            1105,
            "optional",
        ),
        (
            "6",
            "Verify + retain",
            ("Offline verifier", "Acceptance criteria", "Preserve trust anchor"),
            1365,
            "terminal-good",
        ),
    )
    for number, title, phase_lines, x, kind in phases:
        diagram.raw(f'<circle cx="{x + 85}" cy="165" r="28" fill="#1768a8"/>')
        diagram.text(x + 85, 172, number, css="step-number", anchor="middle")
        diagram.box(x, 220, 200, 160, title, phase_lines, kind=kind)
    for x in (265, 525, 785, 1045, 1305):
        diagram.arrow((Point(x, 300), Point(x + 60, 300)))
    diagram.lane(65, 455, 1450, 250, "Decision gates", css="lane-blue")
    gates = (
        (100, "Source gate", ("Expected revision", "Dirty state explicit")),
        (390, "Quality gate", ("Checks pass", "No unexplained skips")),
        (680, "Boundary gate", ("Correct overlay order", "Loopback / internal nets")),
        (970, "Evidence gate", ("Artifact complete", "Hashes / signatures valid")),
        (1260, "Claim gate", ("Local result only", "No deployment claim")),
    )
    for x, title, gate_lines in gates:
        diagram.box(x, 520, 230, 115, title, gate_lines, kind="evidence")
    diagram.arrow((Point(330, 577), Point(390, 577)), kind="evidence-flow")
    diagram.arrow((Point(620, 577), Point(680, 577)), kind="evidence-flow")
    diagram.arrow((Point(910, 577), Point(970, 577)), kind="evidence-flow")
    diagram.arrow((Point(1200, 577), Point(1260, 577)), kind="evidence-flow")
    diagram.rect(165, 745, 1270, 92, css="active", radius=12)
    diagram.multiline(
        800,
        778,
        (
            "Use a new evidence directory. Some early M2/M3 writers can overwrite existing outputs.",
            "Later retained runners enforce stronger non-overwrite and clean-source rules.",
        ),
        css="body-text",
        anchor="middle",
        spacing=25,
    )
    return diagram


def public_demo_data_path() -> Diagram:
    diagram = Diagram(
        "Public demo: build-time evidence, read-only runtime",
        "The browser sees a validated packaged projection; it never reads mutable experiment directories",
        "The public-demo path validates retained M2 and M3 evidence during the build, packages one typed JSON object, and exposes only allowlisted read-only resources at runtime. The mutable control app is separate.",
        height=1000,
    )
    diagram.lane(45, 115, 1510, 405, "BUILD / CI", css="lane-blue")
    diagram.box(
        75,
        185,
        285,
        150,
        "Retained inputs",
        (
            "M2 manifest + trials",
            "M3 primary package",
            "M3 reproduction package",
            "historical Git objects",
        ),
        kind="evidence",
    )
    diagram.box(
        450,
        165,
        500,
        200,
        "build_public_demo.py",
        (
            "recompute M2 statistics + hash",
            "run both complete M3 verifiers",
            "check source + retention Git bindings",
            "compare registered M3 equivalence",
            "validate strict PublicDemoEvidence model",
        ),
        kind="policy",
    )
    diagram.box(
        1050,
        195,
        420,
        130,
        "Packaged output",
        ("src/aegis_ot/web_demo/evidence.json", "only evidence object read at runtime"),
        kind="primary",
    )
    diagram.arrow(
        (Point(360, 260), Point(450, 260)),
        kind="evidence-flow",
        label="validate",
        label_at=Point(405, 242),
    )
    diagram.arrow(
        (Point(950, 260), Point(1050, 260)),
        kind="evidence-flow",
        label="write",
        label_at=Point(1000, 242),
    )
    diagram.rect(75, 395, 1395, 85, css="optional", radius=12)
    diagram.multiline(
        772,
        428,
        (
            "M2 is recomputed • both M3 packages are verified • source and retention bindings are checked",
            "Primary and reproduction must satisfy the registered equivalence contract",
        ),
        css="body-text-large",
        anchor="middle",
        spacing=25,
    )

    diagram.line(Point(45, 560), Point(650, 560), css="divider")
    diagram.line(Point(950, 560), Point(1555, 560), css="divider")
    diagram.text(800, 566, "BUILD / RUNTIME BOUNDARY", css="line-label", anchor="middle")
    diagram.lane(
        45, 590, 1030, 300, "CONTAINER RUNTIME • demo network • 127.0.0.1:8080", css="lane-green"
    )
    diagram.box(
        90,
        640,
        260,
        175,
        "Packaged resources",
        ("evidence.json", "index.html", "app.css", "app.js"),
        kind="evidence",
    )
    diagram.box(
        430,
        640,
        300,
        175,
        "aegis_ot.api:public_app",
        (
            "strict typed load + cache",
            "GET /health",
            "GET /v1/demo/evidence",
            "GET /demo + static assets",
            "docs / redoc disabled",
        ),
        kind="terminal-good",
    )
    diagram.box(
        815,
        660,
        210,
        135,
        "Browser",
        ("DOM text rendering", "bounded fetch retry", "no innerHTML"),
        kind="outside",
    )
    diagram.arrow((Point(350, 727), Point(430, 727)), kind="evidence-flow")
    diagram.arrow(
        (Point(730, 727), Point(815, 727)),
        kind="return-flow",
        label="GET only",
        label_at=Point(772, 710),
    )
    diagram.lane(1120, 590, 435, 300, "EXCLUDED CONTROL SURFACE", css="lane-amber")
    diagram.box(
        1170,
        665,
        335,
        125,
        "control_app • separate process",
        ("POST /v1/decisions", "GET /v1/state", "loopback :8085 when launched"),
        kind="active",
    )
    diagram.text(1337, 830, "No connector to public_app", css="line-label", anchor="middle")
    diagram.text(
        800,
        940,
        "No results/ mount • no device socket • no experiment rerun • no control command • presentation is not operational validation",
        css="small-text",
        anchor="middle",
    )
    return diagram


def verification_gates() -> Diagram:
    diagram = Diagram(
        "Implementation and evidence verification gates",
        "Passing one gate does not imply acceptance at the next evidence level",
        "The verification workflow distinguishes generated-artifact drift, static checks, runtime tests, formal model checks, local Compose resolution, retained experiment acceptance, and external validation.",
        height=1000,
    )
    diagram.box(
        60,
        145,
        260,
        85,
        "Candidate source state",
        ("full-history checkout where required",),
        kind="primary",
        title_y=30,
    )
    diagram.line(Point(190, 230), Point(190, 270), css="bus")
    diagram.line(Point(190, 270), Point(1460, 270), css="bus")
    gates = (
        (
            60,
            315,
            "Generated artifacts",
            ("schema export --check", "public demo --check", "diagram set --check"),
        ),
        (390, 315, "Static analysis", ("Ruff", "format check", "strict mypy")),
        (
            720,
            315,
            "Runtime tests",
            (
                "unit • property • contract",
                "integration • verifier • Compose",
                "branch coverage ≥ 90%",
            ),
        ),
        (
            1050,
            315,
            "Formal checks",
            ("intended TLA+ model", "16 registered weakened cases", "tool + model hashes retained"),
        ),
    )
    for x, y, title, lines in gates:
        diagram.box(x, y, 285, 145, title, lines, kind="component")
        diagram.arrow((Point(x + 142, 270), Point(x + 142, y)), kind="flow")
    diagram.box(
        1370,
        315,
        180,
        145,
        "Local topology",
        ("Compose config", "base smoke", "explicit overlays"),
        kind="optional",
    )
    diagram.arrow((Point(1460, 270), Point(1460, 315)), kind="optional-flow")
    diagram.line(Point(200, 505), Point(1460, 505), css="connector")
    for x in (202, 532, 862, 1192, 1460):
        diagram.line(Point(x, 460), Point(x, 505), css="connector")
    diagram.arrow((Point(830, 505), Point(830, 575)), kind="return-flow")
    diagram.box(
        610,
        575,
        440,
        85,
        "Locally verified implementation state",
        ("all applicable gates pass together",),
        kind="terminal-good",
        title_y=31,
    )
    diagram.arrow((Point(830, 660), Point(830, 720)), kind="evidence-flow")
    diagram.box(
        520,
        720,
        620,
        95,
        "Retained experiment entry gate",
        (
            "clean source • unique output • registered configuration",
            "runner-specific acceptance + offline verification",
        ),
        kind="evidence",
    )
    diagram.arrow((Point(830, 815), Point(830, 870)), kind="evidence-flow")
    diagram.box(
        580, 870, 500, 70, "Accepted local retained result", kind="terminal-neutral", title_y=43
    )
    diagram.rect(60, 715, 350, 225, css="optional", radius=14)
    diagram.text(85, 750, "CI OBSERVATION", css="section-title")
    diagram.multiline(
        85,
        785,
        (
            "Test job: Python 3.11–3.14",
            "Formal job: Python 3.13 + Java 21",
            "Pinned TLC 1.8.0 + checksum",
            "CI status must be observed separately",
        ),
        css="box-text",
        anchor="start",
        spacing=25,
    )
    diagram.rect(1190, 715, 350, 225, css="active", radius=14)
    diagram.text(1215, 750, "CLAIM BOUNDARY", css="section-title")
    diagram.multiline(
        1215,
        785,
        (
            "Compose resolution ≠ startup",
            "Passing tests ≠ accepted experiment",
            "Local result ≠ observed CI acceptance",
            "CI ≠ independent validation",
            "Retained evidence ≠ operational readiness",
        ),
        css="box-text",
        anchor="start",
        spacing=25,
    )
    return diagram


def rendered_diagrams() -> dict[Path, str]:
    diagrams = (
        ("00-system-overview.svg", system_overview()),
        ("01-system-context.svg", system_context()),
        ("02-functional-decomposition.svg", functional_decomposition()),
        ("03-deployment-network.svg", deployment_network()),
        ("04-assurance-overlay-stack.svg", assurance_overlay_stack()),
        ("05-action-transaction-sequence.svg", action_transaction_sequence()),
        ("06-outcome-state-model.svg", outcome_state_model()),
        ("07-identity-trust-lifecycle.svg", identity_trust_lifecycle()),
        ("08-replay-effect-coordination.svg", replay_effect_coordination()),
        ("09-evidence-reproducibility.svg", evidence_reproducibility()),
        ("10-public-demo-data-path.svg", public_demo_data_path()),
        ("11-developer-setup-verification.svg", developer_setup_verification()),
        ("12-verification-gates.svg", verification_gates()),
    )
    return {OUTPUT_DIR / filename: diagram.render() for filename, diagram in diagrams}


def _check(rendered: dict[Path, str]) -> int:
    expected_paths = set(rendered)
    actual_paths = set(OUTPUT_DIR.glob("*.svg")) if OUTPUT_DIR.exists() else set()
    problems: list[str] = []
    for path, expected in rendered.items():
        if not path.exists():
            problems.append(f"missing: {path.relative_to(ROOT)}")
        elif path.read_text(encoding="utf-8") != expected:
            problems.append(f"stale: {path.relative_to(ROOT)}")
    for path in sorted(actual_paths - expected_paths):
        problems.append(f"unexpected: {path.relative_to(ROOT)}")
    if problems:
        for problem in problems:
            print(problem)
        print("Run: python scripts/build_system_diagrams.py")
        return 1
    print(f"System diagram set is current ({len(rendered)} files).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when generated SVGs are missing, stale, or unexpected",
    )
    args = parser.parse_args()
    rendered = rendered_diagrams()
    if args.check:
        return _check(rendered)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for path, content in rendered.items():
        path.write_text(content, encoding="utf-8")
    print(f"Wrote {len(rendered)} diagrams to {OUTPUT_DIR.relative_to(ROOT)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
