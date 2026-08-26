#!/usr/bin/env python3
"""Select non-exact or duplicate UFW rules from one closed M4j host plan."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections.abc import Sequence
from typing import Any, NoReturn

MAX_INPUT_BYTES = 1024 * 1024
RULE_ID = re.compile(r"^[a-z][a-z0-9-]{0,95}$")
INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
NUMBERED = re.compile(r"^\[\s*([0-9]+)\]\s+")


class FirewallReconcileError(RuntimeError):
    """The effective UFW rules could not be mapped to the exact host plan."""


def _fail(message: str) -> NoReturn:
    raise FirewallReconcileError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate firewall input key: {key}")
        result[key] = value
    return result


def _load_input() -> tuple[list[dict[str, Any]], list[str]]:
    material = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not material or len(material) > MAX_INPUT_BYTES:
        _fail("firewall reconciliation input size is invalid")
    try:
        document = json.loads(material, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FirewallReconcileError("firewall reconciliation input is not strict JSON") from exc
    if not isinstance(document, dict) or set(document) != {"rules", "status_lines"}:
        _fail("firewall reconciliation input fields differ")
    rules = document["rules"]
    status_lines = document["status_lines"]
    if (
        not isinstance(rules, list)
        or not rules
        or len(rules) > 64
        or any(not isinstance(rule, dict) for rule in rules)
        or not isinstance(status_lines, list)
        or len(status_lines) > 1024
        or any(not isinstance(line, str) or len(line) > 4096 for line in status_lines)
    ):
        _fail("firewall rules or status lines exceed the closed bounds")
    return rules, status_lines


def _rule_pattern(rule: dict[str, Any]) -> re.Pattern[str]:
    expected_fields = {
        "rule_id",
        "interface",
        "source_address",
        "destination_address",
        "port",
        "protocol",
    }
    if set(rule) != expected_fields:
        _fail("firewall rule fields differ from the exact tuple")
    try:
        source = str(ipaddress.IPv4Address(rule["source_address"]))
        destination = str(ipaddress.IPv4Address(rule["destination_address"]))
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise FirewallReconcileError("firewall tuple contains a non-IPv4 address") from exc
    rule_id = rule["rule_id"]
    interface = rule["interface"]
    port = rule["port"]
    protocol = rule["protocol"]
    if (
        not isinstance(rule_id, str)
        or RULE_ID.fullmatch(rule_id) is None
        or not isinstance(interface, str)
        or INTERFACE.fullmatch(interface) is None
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        or protocol not in {"tcp", "udp"}
    ):
        _fail("firewall tuple identity, interface, port, or protocol is invalid")
    return re.compile(
        r"^\[\s*[0-9]+\]\s+"
        + re.escape(destination)
        + r"\s+"
        + str(port)
        + "/"
        + protocol
        + r"\s+on\s+"
        + re.escape(interface)
        + r"\s+ALLOW IN\s+"
        + re.escape(source)
        + r"\s+#\s+Aegis-M4j-"
        + re.escape(rule_id)
        + r"$"
    )


def reconcile(*, audit: bool) -> dict[str, Any]:
    rules, status_lines = _load_input()
    numbered: dict[int, str] = {}
    for line in status_lines:
        match = NUMBERED.match(line)
        if match is None:
            continue
        number = int(match.group(1))
        if number <= 0 or number in numbered:
            _fail("UFW status contains an invalid or duplicate rule number")
        numbered[number] = line
    patterns = [_rule_pattern(rule) for rule in rules]
    if len({rule["rule_id"] for rule in rules}) != len(rules):
        _fail("firewall rule IDs are duplicated")
    preserved: list[int] = []
    exact_counts: dict[str, int] = {}
    for rule, pattern in zip(rules, patterns, strict=True):
        matches = sorted(number for number, line in numbered.items() if pattern.fullmatch(line))
        if not matches:
            _fail(f"exact UFW tuple is absent: {rule['rule_id']}")
        preserved.append(matches[0])
        exact_counts[rule["rule_id"]] = len(matches)
    if len(set(preserved)) != len(preserved):
        _fail("one UFW rule ambiguously satisfies multiple exact tuples")
    stale = sorted(set(numbered) - set(preserved), reverse=True)
    if audit and (stale or any(count != 1 for count in exact_counts.values())):
        _fail("effective UFW set contains a non-exact or duplicate rule")
    return {
        "schema_version": "aegis-ot-m4j-ufw-convergence-v1",
        "mode": "audit" if audit else "select_cleanup",
        "expected_rule_count": len(rules),
        "preserved_rule_numbers": sorted(preserved),
        "stale_rule_numbers": stale,
        "exact_set": not stale and all(count == 1 for count in exact_counts.values()),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        result = reconcile(audit=arguments.audit)
    except FirewallReconcileError as exc:
        print(f"M4j UFW reconciliation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
