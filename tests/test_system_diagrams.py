from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIAGRAM_DIR = ROOT / "assets" / "diagrams"
BUILDER = ROOT / "scripts" / "build_system_diagrams.py"

EXPECTED_DIAGRAMS = {
    "00-system-overview.svg",
    "01-system-context.svg",
    "02-functional-decomposition.svg",
    "03-deployment-network.svg",
    "04-assurance-overlay-stack.svg",
    "05-action-transaction-sequence.svg",
    "06-outcome-state-model.svg",
    "07-identity-trust-lifecycle.svg",
    "08-replay-effect-coordination.svg",
    "09-evidence-reproducibility.svg",
    "10-public-demo-data-path.svg",
    "11-developer-setup-verification.svg",
    "12-verification-gates.svg",
}


def test_system_diagram_set_is_current() -> None:
    result = subprocess.run(  # noqa: S603 - fixed local interpreter and repository script
        [sys.executable, str(BUILDER), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_system_diagram_set_is_complete_and_accessible() -> None:
    actual = {path.name for path in DIAGRAM_DIR.glob("*.svg")}
    assert actual == EXPECTED_DIAGRAMS

    namespace = {"svg": "http://www.w3.org/2000/svg"}
    for path in sorted(DIAGRAM_DIR.glob("*.svg")):
        root = ET.parse(path).getroot()  # noqa: S314 - parses only generated local SVGs
        assert root.tag == "{http://www.w3.org/2000/svg}svg"
        assert root.attrib["role"] == "img"
        assert root.attrib["aria-labelledby"] == "title description"
        title = root.find("svg:title", namespace)
        description = root.find("svg:desc", namespace)
        metadata = root.find("svg:metadata", namespace)
        assert title is not None and title.text
        assert description is not None and description.text
        assert metadata is not None and metadata.text == "Author: Angelis Pseftis"
