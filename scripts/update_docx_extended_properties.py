"""Update honest page/word counts in the canonical DOCX extended properties."""

from __future__ import annotations

import argparse
import re
import tempfile
import zipfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("docx", type=Path)
    parser.add_argument("--pages", type=int, required=True)
    parser.add_argument("--words", type=int, required=True)
    args = parser.parse_args()
    if args.pages < 1 or args.words < 1:
        raise SystemExit("page and word counts must be positive")

    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False, dir=args.docx.parent) as handle:
        temp_path = Path(handle.name)
    try:
        with zipfile.ZipFile(args.docx) as source, zipfile.ZipFile(temp_path, "w") as target:
            for item in source.infolist():
                data = source.read(item.filename)
                if item.filename == "docProps/app.xml":
                    text = data.decode("utf-8")
                    text = re.sub(r"<Pages>.*?</Pages>", f"<Pages>{args.pages}</Pages>", text)
                    text = re.sub(r"<Words>.*?</Words>", f"<Words>{args.words}</Words>", text)
                    text = re.sub(
                        r"<Characters>.*?</Characters>",
                        "<Characters>0</Characters>",
                        text,
                    )
                    data = text.encode("utf-8")
                target.writestr(item, data)
        temp_path.replace(args.docx)
    finally:
        temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
