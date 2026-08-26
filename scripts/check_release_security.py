"""Run bounded offline release-security policy checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis_ot.release_security import (
    ReleaseSecurityError,
    check_installed_licenses,
    check_repository,
)

ROOT = Path(__file__).resolve().parents[1]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--installed-licenses",
        action="store_true",
        help="also require every locked distribution and approved package metadata",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        reports = {"repository": check_repository(arguments.root)}
        if arguments.installed_licenses:
            reports["installed_licenses"] = check_installed_licenses(arguments.root)
    except (OSError, ReleaseSecurityError) as exc:
        print(f"release security check failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(reports, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
