"""Generate or verify committed schemas from authoritative Pydantic models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aegis_ot.schema import action_proposal_schema

ROOT = Path(__file__).resolve().parents[1]
ACTION_PROPOSAL_PATH = ROOT / "schemas" / "action-proposal.schema.json"


def rendered_action_proposal_schema() -> str:
    return json.dumps(action_proposal_schema(), indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed schema differs from the authoritative model",
    )
    args = parser.parse_args()
    rendered = rendered_action_proposal_schema()
    if args.check:
        if not ACTION_PROPOSAL_PATH.is_file() or ACTION_PROPOSAL_PATH.read_text() != rendered:
            raise SystemExit("committed ActionProposal schema is stale")
        return
    ACTION_PROPOSAL_PATH.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
