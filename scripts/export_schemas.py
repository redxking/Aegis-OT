"""Generate or verify committed schemas from authoritative Pydantic models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from aegis_ot.modbus_wire import SignedWireResponse, WireRequest
from aegis_ot.physical_models import (
    CandidateAssessment,
    ClosedLoopResult,
    CommandAcknowledgment,
    ExecutionPermit,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
)
from aegis_ot.schema import action_proposal_schema

ROOT = Path(__file__).resolve().parents[1]
ACTION_PROPOSAL_PATH = ROOT / "schemas" / "action-proposal.schema.json"
MODEL_SCHEMAS: dict[Path, type[BaseModel]] = {
    ROOT / "schemas" / "m3-candidate-assessment.schema.json": CandidateAssessment,
    ROOT / "schemas" / "m3-closed-loop-result.schema.json": ClosedLoopResult,
    ROOT / "schemas" / "m3-command-acknowledgment.schema.json": CommandAcknowledgment,
    ROOT / "schemas" / "m3-execution-permit.schema.json": ExecutionPermit,
    ROOT / "schemas" / "m3-modbus-wire-request.schema.json": WireRequest,
    ROOT / "schemas" / "m3-modbus-wire-response.schema.json": SignedWireResponse,
    ROOT / "schemas" / "m3-physical-command.schema.json": PhysicalControlCommand,
    ROOT / "schemas" / "m3-physical-state.schema.json": PhysicalStateSnapshot,
}


def rendered_schemas() -> dict[Path, str]:
    schemas: dict[Path, dict[str, Any]] = {ACTION_PROPOSAL_PATH: action_proposal_schema()}
    schemas.update({path: model.model_json_schema() for path, model in MODEL_SCHEMAS.items()})
    return {
        path: json.dumps(schema, indent=2, sort_keys=True) + "\n"
        for path, schema in schemas.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed schema differs from the authoritative model",
    )
    args = parser.parse_args()
    rendered = rendered_schemas()
    if args.check:
        stale = [
            str(path.relative_to(ROOT))
            for path, expected in rendered.items()
            if not path.is_file() or path.read_text(encoding="utf-8") != expected
        ]
        if stale:
            raise SystemExit(f"committed schemas are stale: {', '.join(stale)}")
        return
    for path, material in rendered.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(material, encoding="utf-8")


if __name__ == "__main__":
    main()
