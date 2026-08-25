"""Build or check the neutral topology fixture used by the M4b evaluator.

The builder uses pandapower only to extract a reviewed, solver-neutral graph and
load table.  The runtime evaluator does not import pandapower or this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pandapower as pp  # type: ignore[import-untyped]
import pandapower.networks as pn  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "fixtures/m4b/cigre-mv-topology-v1.json"
PRIORITY_LOAD_INDICES = frozenset({12, 13, 16, 17})
CONTROLLED_RESOURCES = (
    {
        "resource": "feeder-1",
        "command_type": "set_line_service",
        "branch_id": "line:4",
        "target": "Line 5-6",
        "target_index": 4,
    },
    {
        "resource": "feeder-2",
        "command_type": "set_line_service",
        "branch_id": "line:6",
        "target": "Line 8-9",
        "target_index": 6,
    },
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _decimal_text(value: Any) -> str:
    # The source table is IEEE-754, but the benchmark values are authored with
    # substantially fewer significant digits.  A fixed 12-significant-digit
    # projection removes binary representation noise without changing any
    # registered load value.
    numeric = Decimal(format(float(value), ".12g"))
    if numeric == 0:
        return "0"
    rendered = format(numeric.normalize(), "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _switches_allow(net: Any, element_type: str, element_index: int) -> bool:
    matching = net.switch[
        (net.switch.et == element_type) & (net.switch.element == element_index)
    ]
    return all(bool(value) for value in matching.closed.tolist())


def build_fixture() -> dict[str, Any]:
    net = pn.create_cigre_network_mv(with_der="all")
    buses = sorted(int(index) for index in net.bus.index)
    branches: list[dict[str, Any]] = []
    for index, row in net.line.sort_index().iterrows():
        numeric_index = int(index)
        branches.append(
            {
                "branch_id": f"line:{numeric_index}",
                "kind": "line",
                "target_index": numeric_index,
                "from_bus": int(row.from_bus),
                "to_bus": int(row.to_bus),
                "baseline_in_service": bool(row.in_service)
                and _switches_allow(net, "l", numeric_index),
            }
        )
    for index, row in net.trafo.sort_index().iterrows():
        numeric_index = int(index)
        branches.append(
            {
                "branch_id": f"transformer:{numeric_index}",
                "kind": "transformer",
                "target_index": numeric_index,
                "from_bus": int(row.hv_bus),
                "to_bus": int(row.lv_bus),
                "baseline_in_service": bool(row.in_service)
                and _switches_allow(net, "t", numeric_index),
            }
        )
    sources = [
        {
            "source_id": f"ext_grid:{int(index)}",
            "bus": int(row.bus),
            "in_service": bool(row.in_service),
        }
        for index, row in net.ext_grid.sort_index().iterrows()
    ]
    loads = [
        {
            "load_id": f"load:{int(index)}",
            "bus": int(row.bus),
            "p_mw": _decimal_text(float(row.p_mw)),
            "in_service": bool(row.in_service),
            "priority": int(index) in PRIORITY_LOAD_INDICES,
        }
        for index, row in net.load.sort_index().iterrows()
    ]
    for resource in CONTROLLED_RESOURCES:
        index = cast(int, resource["target_index"])
        if str(net.line.at[index, "name"]) != resource["target"]:
            raise RuntimeError(f"controlled-resource mapping changed for {resource['resource']}")
    material: dict[str, Any] = {
        "schema_version": "m4b-neutral-topology-fixture-v1",
        "fixture_id": "pandapower-cigre-mv-all-neutral-topology-v1",
        "source": {
            "model_id": "pandapower-cigre-mv-all",
            "constructor": "pandapower.networks.create_cigre_network_mv(with_der='all')",
            "pandapower_version": pp.__version__,
            "priority_load_indices": sorted(PRIORITY_LOAD_INDICES),
            "projection": (
                "solver-neutral bus, switched-branch, source, active-load, and "
                "controlled-line mapping"
            ),
            "boundary": (
                "derived from the packaged pandapower benchmark; not an independent "
                "sensor, AC solver, dynamic model, or external model validation"
            ),
        },
        "buses": buses,
        "branches": branches,
        "sources": sources,
        "loads": loads,
        "controlled_resources": list(CONTROLLED_RESOURCES),
    }
    return {
        **material,
        "fixture_digest": hashlib.sha256(_canonical_bytes(material)).hexdigest(),
    }


def rendered_fixture() -> str:
    return json.dumps(build_fixture(), indent=2, sort_keys=True, allow_nan=False) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()
    rendered = rendered_fixture()
    if args.stdout:
        print(rendered, end="")
        return
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != rendered:
            raise SystemExit(f"topology fixture is stale: {args.output}")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
