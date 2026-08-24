"""Reproducibly build Aegis-OT study figures from source and experiment artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
INK = "#102A43"
BLUE = "#1769AA"
LIGHT = "#EAF2F8"
GOLD = "#B7791F"
RED = "#A61B1B"
GREEN = "#1B7F5A"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica.ttc",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def centered(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], text: str, size: int, bold: bool = False) -> None:
    fnt = font(size, bold)
    bounds = draw.multiline_textbbox((0, 0), text, font=fnt, spacing=5, align="center")
    width = bounds[2] - bounds[0]
    height = bounds[3] - bounds[1]
    x = box[0] + (box[2] - box[0] - width) / 2
    y = box[1] + (box[3] - box[1] - height) / 2
    draw.multiline_text((x, y), text, font=fnt, fill=INK, spacing=5, align="center")


def arrow(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int]) -> None:
    draw.line((start, end), fill=INK, width=5)
    ex, ey = end
    draw.polygon([(ex, ey), (ex - 14, ey - 10), (ex - 14, ey + 10)], fill=INK)


def architecture() -> None:
    image = Image.new("RGB", (2000, 1125), "white")
    draw = ImageDraw.Draw(image)
    draw.text((80, 55), "Aegis-OT reference action path", font=font(48, True), fill=INK)
    draw.text((80, 115), "Proposal is data; only the gateway can authorize simulated control", font=font(26), fill=BLUE)
    labels = [
        "Synthetic\ntelemetry",
        "Bounded\nagent",
        "Typed\nActionProposal",
        "Aegis-OT\ngateway",
        "Authorization-bound\ncommand adapter",
        "Simulated PLC /\nphysical process",
    ]
    boxes: list[tuple[int, int, int, int]] = []
    x = 70
    for index, label in enumerate(labels):
        width = 270 if index not in {3, 4} else 310
        box = (x, 400, x + width, 580)
        boxes.append(box)
        fill = "#D9EAF7" if index == 3 else LIGHT
        draw.rounded_rectangle(box, radius=18, fill=fill, outline=BLUE, width=4)
        centered(draw, box, label, 25, bold=index == 3)
        x += width + 45
    for left, right in zip(boxes, boxes[1:], strict=True):
        arrow(draw, (left[2] + 5, 490), (right[0] - 8, 490))

    gateway = boxes[3]
    checks = ["Identity", "Delegation", "Policy", "Freshness", "Replay", "Safety", "Approval", "Evidence"]
    start_x = gateway[0] - 300
    for index, label in enumerate(checks):
        cx = start_x + (index % 4) * 180
        cy = 720 + (index // 4) * 130
        box = (cx, cy, cx + 155, cy + 80)
        draw.rounded_rectangle(box, radius=12, fill="white", outline=GOLD, width=3)
        centered(draw, box, label, 21, bold=True)
        draw.line(((box[0] + box[2]) // 2, box[1], (gateway[0] + gateway[2]) // 2, gateway[3]), fill=GOLD, width=2)
    draw.text((80, 1040), "Development approximation: in-process components preserve interfaces but not deployment independence.", font=font(23), fill=RED)
    image.save(ASSETS / "architecture.png", dpi=(220, 220))


def decision_sequence() -> None:
    image = Image.new("RGB", (2000, 1250), "white")
    draw = ImageDraw.Draw(image)
    draw.text((80, 55), "Decision and execution sequence", font=font(48, True), fill=INK)
    lanes = ["Agent", "Gateway", "Trust services", "Safety kernel", "Adapter", "Evidence"]
    x_positions = [150, 470, 800, 1130, 1460, 1770]
    for label, x in zip(lanes, x_positions, strict=True):
        draw.text((x - 60, 150), label, font=font(24, True), fill=BLUE)
        draw.line((x, 205, x, 1160), fill="#9FB3C8", width=3)
    events = [
        (0, 1, 270, "ActionProposal"),
        (1, 2, 380, "verify identity + full grant chain"),
        (2, 1, 490, "identity / delegation result"),
        (1, 3, 600, "simulate candidate transition"),
        (3, 1, 710, "safety result + reasons"),
        (1, 5, 820, "append decision evidence"),
        (1, 4, 930, "permit-bound command"),
        (4, 5, 1040, "acknowledgment + resulting state"),
    ]
    for source, target, y, label in events:
        start = (x_positions[source], y)
        end = (x_positions[target], y)
        direction = 1 if end[0] > start[0] else -1
        draw.line((start, end), fill=INK, width=4)
        draw.polygon(
            [(end[0], y), (end[0] - 14 * direction, y - 9), (end[0] - 14 * direction, y + 9)],
            fill=INK,
        )
        midpoint = (start[0] + end[0]) // 2
        bounds = draw.textbbox((0, 0), label, font=font(20))
        draw.rectangle((midpoint - (bounds[2] - bounds[0]) // 2 - 8, y - 35, midpoint + (bounds[2] - bounds[0]) // 2 + 8, y - 7), fill="white")
        draw.text((midpoint - (bounds[2] - bounds[0]) // 2, y - 33), label, font=font(20), fill=INK)
    image.save(ASSETS / "decision_sequence.png", dpi=(220, 220))


def baseline_results() -> None:
    manifest_path = ROOT / "results" / "reproduction-v0.1" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    summary = manifest["summary"]
    image = Image.new("RGB", (1800, 1100), "white")
    draw = ImageDraw.Draw(image)
    draw.text((80, 55), "Preliminary synthetic baseline outcomes", font=font(46, True), fill=INK)
    draw.text((80, 115), "200 trials per baseline; shared seed set; master seed 20260824", font=font(25), fill=BLUE)
    baselines = list(summary)
    colors = [RED, "#C05621", GOLD, GREEN]
    chart_left, chart_bottom = 180, 900
    group_width = 370
    for index, baseline in enumerate(baselines):
        x = chart_left + index * group_width
        values = [summary[baseline]["unsafe_action_escape_rate"], summary[baseline]["mission_success_rate"]]
        bar_data = zip(
            values,
            [colors[index], BLUE],
            ["unsafe escape", "mission success"],
            strict=True,
        )
        for offset, (value, color, label) in enumerate(bar_data):
            bar_x = x + offset * 120
            height = int(value * 520)
            draw.rectangle((bar_x, chart_bottom - height, bar_x + 85, chart_bottom), fill=color)
            draw.text((bar_x + 12, chart_bottom - height - 38), f"{value:.0%}", font=font(22, True), fill=INK)
            draw.text((bar_x - 10, chart_bottom + 15 + offset * 30), label, font=font(17), fill=INK)
        draw.text((x, 970), baseline.replace("_", " "), font=font(21, True), fill=INK)
    draw.line((120, chart_bottom, 1680, chart_bottom), fill=INK, width=3)
    draw.text((80, 1040), "These results test internal control-path behavior under a simplified surrogate; they are not field validation.", font=font(22), fill=RED)
    image.save(ASSETS / "baseline_results.png", dpi=(220, 220))


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    architecture()
    decision_sequence()
    baseline_results()


if __name__ == "__main__":
    main()
