#!/usr/bin/env python3
"""Idempotently create or update one closed M4j SPIRE workload entry."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NoReturn

MAX_ENTRY_BYTES = 64 * 1024
ENTRY_ID = re.compile(r"^m4j-[a-z0-9-]+-v1$")
SPIFFE_ID = re.compile(r"^spiffe://aegis-ot[.]m4g[.]local/(?:agent|workload)/[a-z0-9-]+$")
CONTAINER_NAME = "aegis-m4j-spire-server"
SERVER_BINARY = "/opt/spire/bin/spire-server"
SERVER_SOCKET = "/run/spire/server/private/api.sock"
MANAGED_ENTRY_PREFIX = "m4j-"
MAX_SHOW_BYTES = 4 * 1024 * 1024
MAX_MANAGED_ENTRIES = 64


class ReconcileError(RuntimeError):
    """The desired SPIRE entry could not be reconciled safely."""


def _fail(message: str) -> NoReturn:
    raise ReconcileError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular_nofollow(path: Path, *, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReconcileError(f"{label} is unavailable or linked") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o022
            or before.st_size <= 0
            or before.st_size > MAX_ENTRY_BYTES
        ):
            _fail(f"{label} is not a bounded owner-controlled regular file")
        material = bytearray()
        while chunk := os.read(descriptor, min(65536, MAX_ENTRY_BYTES + 1 - len(material))):
            material.extend(chunk)
            if len(material) > MAX_ENTRY_BYTES:
                _fail(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
            or len(material) != before.st_size
        ):
            _fail(f"{label} changed while it was read")
        return bytes(material)
    finally:
        os.close(descriptor)


def _parse_entry_material(material: bytes) -> dict[str, Any]:
    if not material or len(material) > MAX_ENTRY_BYTES:
        _fail("SPIRE entry input size is invalid")
    try:
        document = json.loads(material, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReconcileError("SPIRE entry input is not strict JSON") from exc
    if not isinstance(document, dict) or set(document) != {"entries"}:
        _fail("SPIRE entry input must contain only entries")
    entries = document["entries"]
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        _fail("SPIRE reconciliation accepts exactly one entry")
    entry = entries[0]
    if set(entry) != {
        "entry_id",
        "parent_id",
        "spiffe_id",
        "selectors",
        "x509_svid_ttl",
    }:
        _fail("SPIRE entry fields differ from the closed M4j contract")
    if (
        not isinstance(entry["entry_id"], str)
        or ENTRY_ID.fullmatch(entry["entry_id"]) is None
        or not isinstance(entry["parent_id"], str)
        or SPIFFE_ID.fullmatch(entry["parent_id"]) is None
        or "/agent/" not in entry["parent_id"]
        or not isinstance(entry["spiffe_id"], str)
        or SPIFFE_ID.fullmatch(entry["spiffe_id"]) is None
        or "/workload/" not in entry["spiffe_id"]
        or entry["x509_svid_ttl"] != 300
    ):
        _fail("SPIRE entry identity or TTL is invalid")
    selectors = entry["selectors"]
    if (
        not isinstance(selectors, list)
        or len(selectors) != 2
        or any(not isinstance(selector, dict) for selector in selectors)
        or selectors[0] != {"type": "unix", "value": "uid:65532"}
        or set(selectors[1]) != {"type", "value"}
        or selectors[1]["type"] != "unix"
        or not isinstance(selectors[1]["value"], str)
        or re.fullmatch(r"gid:6553[2-8]", selectors[1]["value"]) is None
    ):
        _fail("SPIRE entry selectors are not the closed UID/GID pair")
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    if material != canonical:
        _fail("SPIRE entry input must be canonical JSON")
    return entry


def _load_entry(path: Path) -> dict[str, Any]:
    return _parse_entry_material(
        _read_regular_nofollow(path, label="SPIRE entry input")
    )


def _load_desired_directory(directory: Path) -> dict[str, dict[str, Any]]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        raise ReconcileError("registration directory is unavailable or linked") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            _fail("registration directory is not owner-controlled")
        names = sorted(name for name in os.listdir(descriptor) if name.endswith(".json"))
        if not names or len(names) > MAX_MANAGED_ENTRIES:
            _fail("registration inputs are absent or exceed the managed bound")
        desired: dict[str, dict[str, Any]] = {}
        for name in names:
            if ENTRY_ID.fullmatch(name.removesuffix(".json")) is None:
                _fail("registration input filename is outside the managed prefix contract")
            try:
                entry_descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise ReconcileError("registration input is unavailable or linked") from exc
            try:
                before = os.fstat(entry_descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.geteuid()
                    or before.st_mode & 0o022
                    or before.st_size <= 0
                    or before.st_size > MAX_ENTRY_BYTES
                ):
                    _fail("registration input is not owner-controlled")
                material = bytearray()
                while chunk := os.read(
                    entry_descriptor,
                    min(65536, MAX_ENTRY_BYTES + 1 - len(material)),
                ):
                    material.extend(chunk)
                    if len(material) > MAX_ENTRY_BYTES:
                        _fail("registration input exceeds its size limit")
                after = os.fstat(entry_descriptor)
                if (
                    (after.st_dev, after.st_ino, after.st_size)
                    != (before.st_dev, before.st_ino, before.st_size)
                    or len(material) != before.st_size
                ):
                    _fail("registration input changed while it was read")
            finally:
                os.close(entry_descriptor)
            entry = _parse_entry_material(bytes(material))
            if name != f"{entry['entry_id']}.json" or entry["entry_id"] in desired:
                _fail("registration filename or entry ID is ambiguous")
            desired[entry["entry_id"]] = entry
        return desired
    finally:
        os.close(descriptor)


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed Docker argv and validated path
        (
            "/usr/bin/docker",
            "exec",
            CONTAINER_NAME,
            SERVER_BINARY,
            "entry",
            *arguments,
            "-socketPath",
            SERVER_SOCKET,
        ),
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )


def _spiffe_id(value: object, *, label: str) -> str:
    if not isinstance(value, dict) or set(value) != {"trust_domain", "path"}:
        _fail(f"SPIRE {label} output is malformed")
    trust_domain = value["trust_domain"]
    path = value["path"]
    if not isinstance(trust_domain, str) or not isinstance(path, str):
        _fail(f"SPIRE {label} output is malformed")
    return f"spiffe://{trust_domain}{path}"


def _parse_show(completed: subprocess.CompletedProcess[str]) -> list[dict[str, Any]]:
    material = completed.stdout.encode("utf-8")
    if not material or len(material) > MAX_SHOW_BYTES:
        _fail("SPIRE entry readback output size is invalid")
    try:
        document = json.loads(completed.stdout, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReconcileError("SPIRE entry readback is not strict JSON") from exc
    if not isinstance(document, dict) or set(document) != {"entries", "next_page_token"}:
        _fail("SPIRE entry readback envelope is malformed")
    entries = document["entries"]
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        _fail("SPIRE entry readback entries are malformed")
    return entries


def _show(entry_id: str | None = None) -> subprocess.CompletedProcess[str]:
    arguments = ["show"]
    if entry_id is not None:
        arguments.extend(("-entryID", entry_id))
    arguments.extend(("-output", "json"))
    return _run(*arguments)


def _entry_matches(observed: dict[str, Any], desired: dict[str, Any]) -> bool:
    try:
        selectors = observed["selectors"]
        return (
            observed["id"] == desired["entry_id"]
            and _spiffe_id(observed["parent_id"], label="parent ID")
            == desired["parent_id"]
            and _spiffe_id(observed["spiffe_id"], label="SPIFFE ID")
            == desired["spiffe_id"]
            and isinstance(selectors, list)
            and all(isinstance(selector, dict) for selector in selectors)
            and sorted(
                selectors,
                key=lambda selector: (selector.get("type"), selector.get("value")),
            )
            == sorted(
                desired["selectors"],
                key=lambda selector: (selector["type"], selector["value"]),
            )
            and observed["x509_svid_ttl"] == desired["x509_svid_ttl"]
            and observed.get("federates_with") == []
            and observed.get("admin") is False
            and observed.get("downstream") is False
            and observed.get("dns_names") == []
            and observed.get("store_svid") is False
            and observed.get("jwt_svid_ttl") == 0
            and observed.get("expires_at") in {"0", 0}
        )
    except (KeyError, TypeError):
        return False


def _read_exact(entry_id: str) -> dict[str, Any] | None:
    shown = _show(entry_id)
    if shown.returncode != 0:
        detail = shown.stderr.strip() or shown.stdout.strip()
        if "code = NotFound" in detail and "no such registration entry" in detail:
            return None
        raise ReconcileError(f"SPIRE entry read failed: {detail[-1000:]}")
    entries = _parse_show(shown)
    if len(entries) != 1:
        _fail("SPIRE entry readback did not return exactly one entry")
    return entries[0]


def _reconcile_entry(entry: dict[str, Any], *, container_path: str) -> dict[str, Any]:
    if (
        not container_path.startswith("/etc/spire/registrations/")
        or not container_path.endswith(".json")
        or ".." in Path(container_path).parts
    ):
        _fail("container registration path is outside the closed mount")
    observed = _read_exact(entry["entry_id"])
    created = False
    updated = False
    if observed is None:
        created_result = _run("create", "-data", container_path)
        if created_result.returncode != 0:
            detail = created_result.stderr.strip() or created_result.stdout.strip()
            raise ReconcileError(f"SPIRE entry create failed: {detail[-1000:]}")
        created = True
    elif not _entry_matches(observed, entry):
        update_result = _run("update", "-data", container_path)
        if update_result.returncode != 0:
            detail = update_result.stderr.strip() or update_result.stdout.strip()
            raise ReconcileError(f"SPIRE entry update failed: {detail[-1000:]}")
        updated = True
    readback = _read_exact(entry["entry_id"])
    if readback is None or not _entry_matches(readback, entry):
        _fail("SPIRE entry differs after reconciliation readback")
    return {
        "schema_version": "aegis-ot-m4j-spire-entry-reconciliation-v1",
        "entry_id": entry["entry_id"],
        "parent_id": entry["parent_id"],
        "created": created,
        "updated": updated,
        "changed": created or updated,
        "converged": True,
        "secret_material_present": False,
    }


def reconcile(path: Path, *, container_path: str) -> dict[str, Any]:
    return _reconcile_entry(_load_entry(path), container_path=container_path)


def _managed_entries(observed_entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if len(observed_entries) > MAX_MANAGED_ENTRIES * 16:
        _fail("SPIRE entry readback exceeds the bounded server inventory")
    managed: dict[str, dict[str, Any]] = {}
    for entry in observed_entries:
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id.startswith(MANAGED_ENTRY_PREFIX):
            continue
        if ENTRY_ID.fullmatch(entry_id) is None:
            _fail("SPIRE managed-prefix entry ID is outside the closed deletion scope")
        if entry_id in managed:
            _fail("SPIRE server returned a duplicate managed entry ID")
        managed[entry_id] = entry
    if len(managed) > MAX_MANAGED_ENTRIES:
        _fail("SPIRE managed entry set exceeds the deletion bound")
    return managed


def _read_managed() -> dict[str, dict[str, Any]]:
    shown = _show()
    if shown.returncode != 0:
        detail = shown.stderr.strip() or shown.stdout.strip()
        raise ReconcileError(f"SPIRE managed-entry audit failed: {detail[-1000:]}")
    return _managed_entries(_parse_show(shown))


def _assert_exact_managed(
    managed: dict[str, dict[str, Any]], desired: dict[str, dict[str, Any]]
) -> None:
    if set(managed) != set(desired):
        _fail("SPIRE managed entry set contains missing or stale registrations")
    if any(not _entry_matches(managed[entry_id], entry) for entry_id, entry in desired.items()):
        _fail("SPIRE managed entry audit found exact-state drift")


def audit(directory: Path) -> dict[str, Any]:
    desired = _load_desired_directory(directory)
    managed = _read_managed()
    _assert_exact_managed(managed, desired)
    return {
        "schema_version": "aegis-ot-m4j-spire-entry-audit-v1",
        "managed_entry_ids": sorted(managed),
        "managed_entry_count": len(managed),
        "converged": True,
        "secret_material_present": False,
    }


def converge(directory: Path) -> dict[str, Any]:
    """Prune only stale M4j-prefixed entries, reconcile desired entries, and audit."""

    desired = _load_desired_directory(directory)
    managed = _read_managed()
    stale_entry_ids = sorted(set(managed) - set(desired))
    if len(stale_entry_ids) > MAX_MANAGED_ENTRIES:
        _fail("SPIRE stale managed entry set exceeds the deletion bound")
    pruned: list[str] = []
    for entry_id in stale_entry_ids:
        deleted = _run("delete", "-entryID", entry_id)
        detail = deleted.stderr.strip() or deleted.stdout.strip()
        if deleted.returncode != 0 and "not found" not in detail.lower():
            raise ReconcileError(f"SPIRE stale managed entry deletion failed: {detail[-1000:]}")
        if _read_exact(entry_id) is not None:
            _fail("SPIRE stale managed entry remained after bounded deletion")
        pruned.append(entry_id)

    reconciliations = [
        _reconcile_entry(
            entry,
            container_path=f"/etc/spire/registrations/{entry_id}.json",
        )
        for entry_id, entry in sorted(desired.items())
    ]
    final_managed = _read_managed()
    _assert_exact_managed(final_managed, desired)
    return {
        "schema_version": "aegis-ot-m4j-spire-entry-convergence-v1",
        "managed_entry_ids": sorted(final_managed),
        "managed_entry_count": len(final_managed),
        "pruned_entry_ids": pruned,
        "created_entry_ids": sorted(
            result["entry_id"] for result in reconciliations if result["created"]
        ),
        "updated_entry_ids": sorted(
            result["entry_id"] for result in reconciliations if result["updated"]
        ),
        "changed": bool(pruned)
        or any(result["changed"] for result in reconciliations),
        "converged": True,
        "secret_material_present": False,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--entry", type=Path)
    mode.add_argument("--audit-directory", type=Path)
    mode.add_argument("--converge-directory", type=Path)
    parser.add_argument("--container-path")
    arguments = parser.parse_args(argv)
    try:
        if arguments.entry is not None:
            if arguments.container_path is None:
                _fail("entry reconciliation requires --container-path")
            result = reconcile(arguments.entry, container_path=arguments.container_path)
        elif arguments.audit_directory is not None:
            if arguments.container_path is not None:
                _fail("managed-entry audit does not accept --container-path")
            result = audit(arguments.audit_directory)
        else:
            if arguments.container_path is not None:
                _fail("managed-entry convergence does not accept --container-path")
            result = converge(arguments.converge_directory)
    except ReconcileError as exc:
        print(f"M4j SPIRE entry reconciliation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
