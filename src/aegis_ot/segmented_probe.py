"""Container entry point for the M4d agent-network probe."""

from __future__ import annotations

import json

from .segmented_runtime import run_segmented_probe


def main() -> None:
    result = run_segmented_probe()
    print(json.dumps(result, sort_keys=True, indent=2))
    if result["accepted"] is not True:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
