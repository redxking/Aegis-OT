"""Reproducibly build Aegis-OT study figures from source and experiment artifacts."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from statistics import median

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
INK = "#102A43"
BLUE = "#1769AA"
LIGHT = "#EAF2F8"
GOLD = "#B7791F"
RED = "#A61B1B"
GREEN = "#1B7F5A"
M3_CONDITIONS = (
    "unknown_identity",
    "stale_state",
    "wrong_audience_permit",
    "nominal_permitted_execution",
    "permit_replay",
)


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
    for left, right in zip(boxes, boxes[1:], strict=False):
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
    manifest_path = ROOT / "results" / "m2-independent-oracle" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    summary = manifest["summary"]
    image = Image.new("RGB", (1800, 1180), "white")
    draw = ImageDraw.Draw(image)
    draw.text((80, 55), "M2 synthetic authorization and consequence outcomes", font=font(43, True), fill=INK)
    draw.text((80, 115), "30 master seeds; 1,080 sampled trials per baseline; Wilson intervals in report", font=font(24), fill=BLUE)
    baselines = list(summary)
    chart_left, chart_bottom = 135, 910
    group_width = 205
    for index, baseline in enumerate(baselines):
        x = chart_left + index * group_width
        values = [summary[baseline]["unsafe_action_escape_rate"], summary[baseline]["unauthorized_execution_rate"]]
        bar_data = zip(
            values,
            [RED, BLUE],
            ["unsafe", "unauth"],
            strict=True,
        )
        for offset, (value, color, label) in enumerate(bar_data):
            bar_x = x + offset * 65
            height = int(value * 520)
            draw.rectangle((bar_x, chart_bottom - height, bar_x + 50, chart_bottom), fill=color)
            draw.text((bar_x - 1, chart_bottom - height - 34), f"{value:.0%}", font=font(19, True), fill=INK)
            draw.text((bar_x - 3, chart_bottom + 14 + offset * 26), label, font=font(15), fill=INK)
        draw.text((x + 22, 1015), baseline.split("_")[0], font=font(21, True), fill=INK)
    draw.line((110, chart_bottom, 1710, chart_bottom), fill=INK, width=3)
    draw.text((80, 1080), "Unsafe = execution outside the conservative reference envelope; unauth = execution when catalog authorization is false.", font=font(20), fill=INK)
    draw.text((80, 1125), "Rule-based synthetic evidence only; guardband disagreements are intentionally retained and are not physical validation.", font=font(20), fill=RED)
    image.save(ASSETS / "baseline_results.png", dpi=(220, 220))


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def m3_physical_results() -> None:
    trials_path = ROOT / "results" / "m3-physical-modbus" / "trials.jsonl"
    if not trials_path.is_file():
        return
    trials = [json.loads(line) for line in trials_path.read_text(encoding="utf-8").splitlines()]
    by_condition = {
        condition: [item for item in trials if item["condition"] == condition]
        for condition in M3_CONDITIONS
    }
    image = Image.new("RGB", (2100, 1500), "white")
    draw = ImageDraw.Draw(image)
    draw.text((80, 55), "M3 closed-loop conformance and host latency", font=font(46, True), fill=INK)
    draw.text((80, 115), "Thirty fresh virtual-device processes; five fixed conditions per process", font=font(25), fill=BLUE)

    draw.text((80, 205), "Observed state effects and device applications", font=font(30, True), fill=INK)
    table_x = 90
    row_y = 285
    headers = ("Condition", "Trials", "State effects", "Device applied", "Unknown effect")
    widths = (760, 220, 290, 300, 300)
    x = table_x
    for header, width in zip(headers, widths, strict=True):
        draw.rectangle((x, row_y, x + width, row_y + 70), fill=LIGHT, outline="#9FB3C8", width=2)
        centered(draw, (x, row_y, x + width, row_y + 70), header, 22, bold=True)
        x += width
    condition_labels = {
        "unknown_identity": "Unknown identity",
        "stale_state": "Stale state",
        "wrong_audience_permit": "Wrong-audience permit",
        "nominal_permitted_execution": "Nominal permitted execution",
        "permit_replay": "Permit replay",
    }
    for row_index, condition in enumerate(M3_CONDITIONS, start=1):
        subset = by_condition[condition]
        values = (
            condition_labels[condition],
            str(len(subset)),
            str(sum(bool(item["state_changed"]) for item in subset)),
            str(sum(bool(item["device_applied"]) for item in subset)),
            str(sum(item["terminal_status"] == "unknown_effect" for item in subset)),
        )
        x = table_x
        y = row_y + row_index * 70
        for value, width in zip(values, widths, strict=True):
            draw.rectangle((x, y, x + width, y + 70), fill="white", outline="#CBD5E1", width=2)
            centered(draw, (x, y, x + width, y + 70), value, 22, bold=condition == "nominal_permitted_execution")
            x += width

    chart_top = 800
    chart_left = 540
    chart_right = 1970
    draw.text((80, 720), "End-to-end latency distribution by condition", font=font(30, True), fill=INK)
    latencies = {
        condition: [float(item["latency_ms"]["end_to_end_ms"]) for item in subset]
        for condition, subset in by_condition.items()
    }
    maximum = max(value for values in latencies.values() for value in values)
    scale_max = max(1.0, math.ceil(maximum / 10.0) * 10.0)
    for tick in range(6):
        value = scale_max * tick / 5
        x = chart_left + int((chart_right - chart_left) * tick / 5)
        draw.line((x, chart_top, x, 1280), fill="#E2E8F0", width=2)
        draw.text((x - 30, 1300), f"{value:.0f}", font=font(19), fill=INK)
    draw.text((chart_right - 75, 1345), "ms", font=font(20, True), fill=INK)
    for row_index, condition in enumerate(M3_CONDITIONS):
        values = latencies[condition]
        y = chart_top + 55 + row_index * 90
        draw.text((80, y - 18), condition_labels[condition], font=font(22), fill=INK)
        low, q1, middle, q3, high = (
            min(values),
            percentile(values, 0.25),
            median(values),
            percentile(values, 0.75),
            max(values),
        )

        def x_position(value: float) -> int:
            return chart_left + int((chart_right - chart_left) * value / scale_max)

        draw.line((x_position(low), y, x_position(high), y), fill=BLUE, width=4)
        draw.rectangle((x_position(q1), y - 23, x_position(q3), y + 23), fill="#D9EAF7", outline=BLUE, width=3)
        draw.line((x_position(middle), y - 25, x_position(middle), y + 25), fill=INK, width=4)
        for value in values:
            draw.ellipse((x_position(value) - 4, y - 4, x_position(value) + 4, y + 4), fill=GOLD)
    draw.text((80, 1410), "Latency is a single-host process measurement and is excluded from the deterministic outcome hash.", font=font(21), fill=RED)
    draw.text((80, 1450), "The figure is conformance evidence for the retained fixtures, not field validation or an OT performance bound.", font=font(21), fill=RED)
    image.save(ASSETS / "m3_physical_results.png", dpi=(220, 220))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build reproducible Aegis-OT figures")
    parser.add_argument(
        "--figure",
        choices=("all", "architecture", "decision", "baseline", "m3"),
        default="all",
    )
    args = parser.parse_args()
    ASSETS.mkdir(parents=True, exist_ok=True)
    builders = {
        "architecture": architecture,
        "decision": decision_sequence,
        "baseline": baseline_results,
        "m3": m3_physical_results,
    }
    selected = tuple(builders) if args.figure == "all" else (args.figure,)
    for name in selected:
        builders[name]()


if __name__ == "__main__":
    main()
