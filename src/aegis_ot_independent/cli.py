"""Command-line file boundary for the independent consequence evaluator."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Final

from .canonical import canonical_json_text
from .evaluator import evaluate_material, verify_report

MAX_INPUT_BYTES: Final = 4 * 1024 * 1024


def _read_regular_file(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"{label} exceeds the {MAX_INPUT_BYTES}-byte limit")
    return path.read_bytes()


def _write_exclusive(path: Path, material: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = material.encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate one bounded topology consequence from files; no Aegis-OT "
            "plant or controller code is imported."
        )
    )
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        request_material = _read_regular_file(args.request, "request")
        fixture_material = _read_regular_file(args.fixture, "fixture")
        report = evaluate_material(request_material, fixture_material)
        if not verify_report(report):
            raise RuntimeError("evaluator produced an unverifiable report")
        _write_exclusive(args.output, canonical_json_text(report))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"independent evaluator failed: {exc}")
        return 3
    status = report["status"]
    if status in {"agree", "not_applicable"}:
        return 0
    if status in {"contradict", "indeterminate"}:
        return 1
    return 2
