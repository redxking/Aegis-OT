#!/usr/bin/env python3
"""Bounded cleanup of one M4j SPIRE join-token bootstrap attempt."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NoReturn, cast

DEFAULT_DATABASE = Path("/var/lib/aegis-ot/spire/server/datastore.sqlite3")
DEFAULT_ATTEMPT_DIRECTORY = Path("/run/aegis-ot/spire/bootstrap-attempts")
TOKEN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
MAX_TOKEN_BYTES = 256
MAX_CLI_BYTES = 4 * 1024 * 1024
MAX_JOIN_TOKEN_AGENTS = 64
STABLE_ABSENCE_READS = 6
MAX_RECONCILIATION_READS = 30
RECONCILIATION_INTERVAL_SECONDS = 0.5
ATTEMPT_LOCK_READS = 60
ATTEMPT_LOCK_INTERVAL_SECONDS = 0.5
TRUST_DOMAIN = "aegis-ot.m4g.local"
ALIAS_SPIFFE_ID = re.compile(
    r"^spiffe://aegis-ot[.]m4g[.]local/agent/(?:trust|agents|gateway|ot|simulation)$"
)
ENTRY_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
CONTAINER_NAME = "aegis-m4j-spire-server"
SERVER_BINARY = "/opt/spire/bin/spire-server"
SERVER_SOCKET = "/run/spire/server/private/api.sock"


class TokenRevocationError(RuntimeError):
    """The one-time bootstrap state could not be reconciled safely."""


def _fail(message: str) -> NoReturn:
    raise TokenRevocationError(message)


def _read_token() -> str:
    material = sys.stdin.buffer.read(MAX_TOKEN_BYTES + 1)
    if len(material) > MAX_TOKEN_BYTES:
        _fail("join token input exceeds its bound")
    try:
        token = material.decode("ascii").removesuffix("\n")
    except UnicodeError as exc:
        raise TokenRevocationError("join token input is not ASCII") from exc
    if material != token.encode("ascii") + b"\n" or TOKEN.fullmatch(token) is None:
        _fail("join token input is not one canonical SPIRE UUID")
    return token


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate SPIRE CLI JSON key: {key}")
        result[key] = value
    return result


def _run_spire(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed Docker argv and validated inputs
        (
            "/usr/bin/docker",
            "exec",
            CONTAINER_NAME,
            SERVER_BINARY,
            *arguments,
            "-socketPath",
            SERVER_SOCKET,
        ),
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )


def _cli_failure(completed: subprocess.CompletedProcess[str], *, operation: str) -> NoReturn:
    detail = completed.stderr.strip() or completed.stdout.strip()
    raise TokenRevocationError(f"SPIRE {operation} failed: {detail[-1000:]}")


def _parse_cli_object(
    completed: subprocess.CompletedProcess[str], *, operation: str
) -> dict[str, Any]:
    if completed.returncode != 0:
        _cli_failure(completed, operation=operation)
    try:
        material = completed.stdout.encode("utf-8")
    except UnicodeError as exc:
        raise TokenRevocationError(f"SPIRE {operation} output is not UTF-8") from exc
    if not material or len(material) > MAX_CLI_BYTES:
        _fail(f"SPIRE {operation} output size is invalid")
    try:
        document = json.loads(
            completed.stdout,
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: _fail(f"forbidden SPIRE JSON constant: {value}"),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise TokenRevocationError(f"SPIRE {operation} output is not strict JSON") from exc
    if not isinstance(document, dict):
        _fail(f"SPIRE {operation} output is not a JSON object")
    return document


def _spiffe_id(value: object, *, label: str) -> str:
    if not isinstance(value, dict) or set(value) != {"trust_domain", "path"}:
        _fail(f"SPIRE {label} is malformed")
    trust_domain = value["trust_domain"]
    path = value["path"]
    if not isinstance(trust_domain, str) or not isinstance(path, str):
        _fail(f"SPIRE {label} is malformed")
    return f"spiffe://{trust_domain}{path}"


def _is_zero(value: object) -> bool:
    return type(value) is int and value == 0 or isinstance(value, str) and value == "0"


def _is_positive_integer(value: object) -> bool:
    return type(value) is int and value > 0 or (
        isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value) is not None
    )


def _agent_is_exact(agent: dict[str, Any], *, expected_id: str) -> bool:
    try:
        return (
            _spiffe_id(agent["id"], label="agent ID") == expected_id
            and agent["attestation_type"] == "join_token"
            and agent["selectors"] == [{"type": "spiffe_id", "value": expected_id}]
            and agent["banned"] is False
            and agent["can_reattest"] is False
            and isinstance(agent["x509_svid_serial_number"], str)
            and bool(agent["x509_svid_serial_number"])
            and _is_positive_integer(agent["x509_svid_expires_at"])
        )
    except (KeyError, TypeError):
        return False


def _read_exact_agent(expected_id: str) -> dict[str, Any] | None:
    document = _parse_cli_object(
        _run_spire("agent", "list", "-attestationType", "join_token", "-output", "json"),
        operation="join-token agent inventory read",
    )
    if set(document) != {"agents", "next_page_token"}:
        _fail("SPIRE join-token agent inventory envelope is malformed")
    if document["next_page_token"] != "":
        _fail("SPIRE join-token agent inventory is paginated and therefore incomplete")
    agents = document["agents"]
    if (
        not isinstance(agents, list)
        or len(agents) > MAX_JOIN_TOKEN_AGENTS
        or any(not isinstance(agent, dict) for agent in agents)
    ):
        _fail("SPIRE join-token agent inventory is malformed or unbounded")
    typed_agents = cast(list[dict[str, Any]], agents)
    matches = [
        agent
        for agent in typed_agents
        if _spiffe_id(agent.get("id"), label="agent ID") == expected_id
    ]
    if len(matches) > 1:
        _fail("SPIRE token-derived agent inventory is ambiguous")
    if not matches:
        return None
    if not _agent_is_exact(matches[0], expected_id=expected_id):
        _fail("SPIRE token-derived agent differs from the closed join-token contract")
    return matches[0]


def _alias_entry_is_exact(
    entry: dict[str, Any], *, alias_spiffe_id: str, actual_agent_id: str
) -> bool:
    try:
        entry_id = entry["id"]
        return (
            isinstance(entry_id, str)
            and ENTRY_ID.fullmatch(entry_id) is not None
            and _spiffe_id(entry["parent_id"], label="alias parent ID") == actual_agent_id
            and _spiffe_id(entry["spiffe_id"], label="alias SPIFFE ID") == alias_spiffe_id
            and entry["selectors"]
            == [{"type": "spiffe_id", "value": actual_agent_id}]
            and _is_zero(entry["x509_svid_ttl"])
            and _is_zero(entry["jwt_svid_ttl"])
            and _is_zero(entry["expires_at"])
            and entry["federates_with"] == []
            and entry["dns_names"] == []
            and entry["admin"] is False
            and entry["downstream"] is False
            and entry["store_svid"] is False
            and entry.get("hint", "") == ""
            and entry.get("additional_attributes") in (None, {})
        )
    except (KeyError, TypeError):
        return False


def _read_alias_entries(alias_spiffe_id: str) -> list[dict[str, Any]]:
    document = _parse_cli_object(
        _run_spire("entry", "show", "-spiffeID", alias_spiffe_id, "-output", "json"),
        operation="join-token alias read",
    )
    if set(document) != {"entries", "next_page_token"}:
        _fail("SPIRE join-token alias envelope is malformed")
    if document["next_page_token"] != "":
        _fail("SPIRE join-token alias inventory is paginated and therefore incomplete")
    entries = document["entries"]
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        _fail("SPIRE join-token alias inventory is malformed")
    typed_entries = cast(list[dict[str, Any]], entries)
    if len(typed_entries) > 1:
        _fail("SPIRE join-token alias mapping is ambiguous")
    return typed_entries


def _read_exact_alias(
    alias_spiffe_id: str, *, actual_agent_id: str
) -> dict[str, Any] | None:
    typed_entries = _read_alias_entries(alias_spiffe_id)
    if not typed_entries:
        return None
    if not _alias_entry_is_exact(
        typed_entries[0], alias_spiffe_id=alias_spiffe_id, actual_agent_id=actual_agent_id
    ):
        _fail("SPIRE join-token alias mapping differs from the exact auto-alias contract")
    return typed_entries[0]


def _delete_alias(entry_id: str) -> None:
    if ENTRY_ID.fullmatch(entry_id) is None:
        _fail("SPIRE join-token alias entry ID is invalid")
    completed = _run_spire("entry", "delete", "-entryID", entry_id)
    if completed.returncode != 0:
        _cli_failure(completed, operation="join-token alias deletion")


def _evict_agent(actual_agent_id: str) -> None:
    completed = _run_spire("agent", "evict", "-spiffeID", actual_agent_id)
    if completed.returncode != 0:
        _cli_failure(completed, operation="unverified token-derived agent eviction")


def _reconcile_unverified_absence(
    alias_spiffe_id: str,
    *,
    actual_agent_id: str,
) -> tuple[str, str]:
    stable_absence = 0
    alias_deleted = False
    agent_evicted = False
    for read_number in range(MAX_RECONCILIATION_READS):
        agent = _read_exact_agent(actual_agent_id)
        alias = _read_exact_alias(alias_spiffe_id, actual_agent_id=actual_agent_id)
        if alias is not None:
            _delete_alias(alias["id"])
            alias_deleted = True
        if agent is not None:
            _evict_agent(actual_agent_id)
            agent_evicted = True
        if agent is None and alias is None:
            stable_absence += 1
            if stable_absence >= STABLE_ABSENCE_READS:
                return (
                    "deleted" if alias_deleted else "already_absent",
                    "evicted" if agent_evicted else "already_absent",
                )
        else:
            stable_absence = 0
        if read_number + 1 < MAX_RECONCILIATION_READS:
            time.sleep(RECONCILIATION_INTERVAL_SECONDS)
    _fail("unverified SPIRE bootstrap identity did not remain stably absent")


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise TokenRevocationError("bootstrap attempt state is not canonical JSON") from exc


def _attempt_path(alias_spiffe_id: str) -> Path:
    if ALIAS_SPIFFE_ID.fullmatch(alias_spiffe_id) is None:
        _fail("SPIRE alias SPIFFE ID differs from the closed M4j contract")
    role = alias_spiffe_id.rsplit("/", maxsplit=1)[-1]
    return DEFAULT_ATTEMPT_DIRECTORY / f"{role}.json"


def _require_attempt_directory() -> None:
    try:
        metadata = DEFAULT_ATTEMPT_DIRECTORY.lstat()
    except OSError as exc:
        raise TokenRevocationError("SPIRE bootstrap-attempt directory is unavailable") from exc
    if (
        DEFAULT_ATTEMPT_DIRECTORY.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail("SPIRE bootstrap-attempt directory is not a private real directory")


def _lock_attempt(descriptor: int) -> None:
    for read_number in range(ATTEMPT_LOCK_READS):
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if read_number + 1 < ATTEMPT_LOCK_READS:
                time.sleep(ATTEMPT_LOCK_INTERVAL_SECONDS)
    _fail("SPIRE bootstrap attempt remained locked past its bound")


def _open_attempt(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise TokenRevocationError("SPIRE bootstrap attempt could not be opened") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > 4096
    ):
        os.close(descriptor)
        _fail("SPIRE bootstrap attempt is not a private bounded regular file")
    return descriptor


def _read_attempt(descriptor: int) -> dict[str, Any]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    material = os.read(descriptor, 4097)
    if not material or len(material) > 4096:
        _fail("SPIRE bootstrap attempt state has an invalid size")
    try:
        document = json.loads(
            material,
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: _fail(
                f"forbidden bootstrap-attempt JSON constant: {value}"
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise TokenRevocationError("SPIRE bootstrap attempt is not strict JSON") from exc
    if not isinstance(document, dict) or material != _canonical_bytes(document) + b"\n":
        _fail("SPIRE bootstrap attempt is not one canonical JSON object")
    state = document.get("state")
    expected = {"schema_version", "state", "alias_spiffe_id"}
    if state == "generated":
        expected.add("token")
    if set(document) != expected:
        _fail("SPIRE bootstrap attempt fields differ from the closed contract")
    if document.get("schema_version") != "aegis-ot-m4j-spire-bootstrap-attempt-v1":
        _fail("SPIRE bootstrap attempt schema differs")
    if state not in {"armed", "generated"}:
        _fail("SPIRE bootstrap attempt state is invalid")
    alias = document.get("alias_spiffe_id")
    if not isinstance(alias, str) or ALIAS_SPIFFE_ID.fullmatch(alias) is None:
        _fail("SPIRE bootstrap attempt alias is invalid")
    if state == "generated":
        token = document.get("token")
        if not isinstance(token, str) or TOKEN.fullmatch(token) is None:
            _fail("SPIRE bootstrap attempt token is invalid")
    return document


def _write_attempt(descriptor: int, document: dict[str, object]) -> None:
    material = _canonical_bytes(document) + b"\n"
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    offset = 0
    while offset < len(material):
        written = os.write(descriptor, material[offset:])
        if written <= 0:
            _fail("SPIRE bootstrap attempt write made no progress")
        offset += written
    os.fsync(descriptor)


def arm_attempt(alias_spiffe_id: str) -> dict[str, object]:
    _require_attempt_directory()
    path = _attempt_path(alias_spiffe_id)
    if path.exists() or path.is_symlink():
        _fail("a prior SPIRE bootstrap attempt requires cleanup before re-arming")
    if _read_alias_entries(alias_spiffe_id):
        _fail("an existing role alias is preserved; automatic rebootstrap is refused")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise TokenRevocationError("SPIRE bootstrap attempt could not be armed") from exc
    try:
        _lock_attempt(descriptor)
        _write_attempt(
            descriptor,
            {
                "schema_version": "aegis-ot-m4j-spire-bootstrap-attempt-v1",
                "state": "armed",
                "alias_spiffe_id": alias_spiffe_id,
            },
        )
    finally:
        os.close(descriptor)
    return {
        "schema_version": "aegis-ot-m4j-spire-bootstrap-attempt-arm-v1",
        "attempt_armed": True,
        "prior_alias_present": False,
        "token_generated": False,
    }


def generate_attempt(alias_spiffe_id: str, *, token_ttl_seconds: int) -> dict[str, object]:
    if type(token_ttl_seconds) is not int or token_ttl_seconds != 300:
        _fail("SPIRE join-token TTL differs from the closed M4j contract")
    _require_attempt_directory()
    path = _attempt_path(alias_spiffe_id)
    descriptor = _open_attempt(path)
    try:
        _lock_attempt(descriptor)
        attempt = _read_attempt(descriptor)
        if attempt["state"] != "armed" or attempt["alias_spiffe_id"] != alias_spiffe_id:
            _fail("SPIRE bootstrap attempt was not armed for this exact role alias")
        if _read_alias_entries(alias_spiffe_id):
            _fail("an existing role alias appeared; token generation is refused")
        response = _parse_cli_object(
            _run_spire(
                "token",
                "generate",
                "-output",
                "json",
                "-spiffeID",
                alias_spiffe_id,
                "-ttl",
                str(token_ttl_seconds),
            ),
            operation="escrowed join-token generation",
        )
        token = response.get("value")
        if not isinstance(token, str) or TOKEN.fullmatch(token) is None:
            _fail("SPIRE token generation did not return one canonical token")
        _write_attempt(
            descriptor,
            {
                "schema_version": "aegis-ot-m4j-spire-bootstrap-attempt-v1",
                "state": "generated",
                "alias_spiffe_id": alias_spiffe_id,
                "token": token,
            },
        )
    finally:
        os.close(descriptor)
    return {
        "schema_version": "aegis-ot-m4j-spire-escrowed-token-generation-v1",
        "value": token,
        "escrowed": True,
    }


def revoke(database: Path, token: str) -> dict[str, object]:
    if database.name != "datastore.sqlite3" or database.parent != DEFAULT_DATABASE.parent:
        _fail("SPIRE datastore path is outside the closed location")
    parent_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        parent_descriptor = os.open(database.parent, parent_flags)
    except OSError as exc:
        raise TokenRevocationError("SPIRE datastore directory is unavailable or linked") from exc
    try:
        parent = os.fstat(parent_descriptor)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
            _fail("SPIRE datastore directory is not owner-controlled")
        try:
            database_descriptor = os.open(
                database.name,
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise TokenRevocationError("SPIRE datastore is unavailable or linked") from exc
        metadata = os.fstat(database_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {os.geteuid(), 1000}
            or metadata.st_mode & 0o022
        ):
            _fail("SPIRE datastore is not an owner-controlled regular file")

        try:
            connection = sqlite3.connect(database, timeout=10, isolation_level=None)
        except sqlite3.Error as exc:
            raise TokenRevocationError("SPIRE datastore could not be opened") from exc
        try:
            opened = os.stat(database.name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                stat.S_ISLNK(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            ):
                _fail("SPIRE datastore changed while it was opened")
            connection.execute("PRAGMA busy_timeout = 10000")
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'join_tokens'"
            ).fetchall()
            columns = {
                row[1]
                for row in connection.execute('PRAGMA table_info("join_tokens")').fetchall()
                if len(row) >= 2 and isinstance(row[1], str)
            }
            if table != [("join_tokens",)] or not {"token", "expiry"}.issubset(columns):
                _fail("SPIRE join-token datastore schema differs from the pinned contract")
            connection.execute("BEGIN IMMEDIATE")
            before = connection.execute(
                'SELECT COUNT(*) FROM "join_tokens" WHERE "token" = ?', (token,)
            ).fetchone()
            if before is None or before[0] not in {0, 1}:
                _fail("SPIRE join-token lookup is ambiguous")
            connection.execute('DELETE FROM "join_tokens" WHERE "token" = ?', (token,))
            after = connection.execute(
                'SELECT COUNT(*) FROM "join_tokens" WHERE "token" = ?', (token,)
            ).fetchone()
            if after != (0,):
                _fail("SPIRE join token remained after revocation")
            connection.execute("COMMIT")
        except (sqlite3.Error, TokenRevocationError) as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            if isinstance(exc, TokenRevocationError):
                raise
            raise TokenRevocationError("SPIRE join-token revocation transaction failed") from exc
        finally:
            connection.close()
    finally:
        if "database_descriptor" in locals():
            os.close(database_descriptor)
        os.close(parent_descriptor)
    removed = before == (1,)
    return {
        "schema_version": "aegis-ot-m4j-spire-join-token-revocation-v1",
        "outcome": "revoked" if removed else "consumed_or_not_found",
        "removed": removed,
        "token_present_after": False,
        "token_material_returned": False,
    }


def cleanup(
    database: Path,
    token: str,
    *,
    alias_spiffe_id: str,
    bootstrap_verified: bool,
    trust_domain: str = TRUST_DOMAIN,
) -> dict[str, object]:
    if TOKEN.fullmatch(token) is None:
        _fail("join token is not one canonical SPIRE UUID")
    if trust_domain != TRUST_DOMAIN:
        _fail("SPIRE trust domain differs from the closed M4j contract")
    if ALIAS_SPIFFE_ID.fullmatch(alias_spiffe_id) is None:
        _fail("SPIRE alias SPIFFE ID differs from the closed M4j contract")
    actual_agent_id = f"spiffe://{trust_domain}/spire/agent/join_token/{token}"

    token_result = revoke(database, token)
    if bootstrap_verified:
        agent = _read_exact_agent(actual_agent_id)
        alias = _read_exact_alias(alias_spiffe_id, actual_agent_id=actual_agent_id)
        if agent is None or alias is None:
            _fail("verified bootstrap is missing its exact agent or auto-alias entry")
        alias_action = "preserved"
        agent_action = "preserved"
        alias_after = _read_exact_alias(alias_spiffe_id, actual_agent_id=actual_agent_id)
        agent_after = _read_exact_agent(actual_agent_id)
        if (
            alias_after is None
            or alias_after["id"] != alias["id"]
            or agent_after is None
            or agent_after["id"] != agent["id"]
        ):
            _fail("verified SPIRE bootstrap identity was not preserved exactly")
        agent_present_after = True
        alias_present_after = True
    else:
        alias_action, agent_action = _reconcile_unverified_absence(
            alias_spiffe_id,
            actual_agent_id=actual_agent_id,
        )
        agent_present_after = False
        alias_present_after = False

    return {
        "schema_version": "aegis-ot-m4j-spire-bootstrap-cleanup-v1",
        "token_outcome": token_result["outcome"],
        "token_present_after": token_result["token_present_after"],
        "actual_agent_present_after": agent_present_after,
        "agent_action": agent_action,
        "alias_action": alias_action,
        "alias_present_after": alias_present_after,
        "bootstrap_outcome": "verified" if bootstrap_verified else "unverified",
        "token_material_returned": False,
        "identity_material_returned": False,
    }


def cleanup_attempt(
    database: Path,
    *,
    alias_spiffe_id: str,
    bootstrap_verified: bool,
    trust_domain: str = TRUST_DOMAIN,
) -> dict[str, object]:
    if trust_domain != TRUST_DOMAIN:
        _fail("SPIRE trust domain differs from the closed M4j contract")
    _require_attempt_directory()
    path = _attempt_path(alias_spiffe_id)
    try:
        path_metadata = path.lstat()
    except FileNotFoundError:
        return {
            "schema_version": "aegis-ot-m4j-spire-bootstrap-attempt-cleanup-v1",
            "attempt_outcome": "no_attempt",
            "attempt_file_present_after": False,
            "bootstrap_outcome": "verified" if bootstrap_verified else "unverified",
            "prior_identity_action": "preserved",
            "token_material_returned": False,
            "identity_material_returned": False,
        }
    if stat.S_ISLNK(path_metadata.st_mode):
        _fail("SPIRE bootstrap attempt path must not be linked")

    descriptor = _open_attempt(path)
    remove_attempt = False
    try:
        _lock_attempt(descriptor)
        attempt = _read_attempt(descriptor)
        if attempt["alias_spiffe_id"] != alias_spiffe_id:
            _fail("SPIRE bootstrap attempt alias changed before cleanup")
        if attempt["state"] == "armed":
            result: dict[str, object] = {
                "schema_version": "aegis-ot-m4j-spire-bootstrap-attempt-cleanup-v1",
                "attempt_outcome": "no_token_generated",
                "attempt_file_present_after": False,
                "bootstrap_outcome": (
                    "verified" if bootstrap_verified else "unverified"
                ),
                "prior_identity_action": "preserved",
                "token_material_returned": False,
                "identity_material_returned": False,
            }
        else:
            token = attempt["token"]
            if not isinstance(token, str):  # pragma: no cover - strict reader invariant
                _fail("SPIRE bootstrap attempt token is malformed")
            result = {
                **cleanup(
                    database,
                    token,
                    alias_spiffe_id=alias_spiffe_id,
                    bootstrap_verified=bootstrap_verified,
                    trust_domain=trust_domain,
                ),
                "attempt_outcome": "generated_token_reconciled",
                "attempt_file_present_after": False,
            }
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        current = path.lstat()
        opened = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            _fail("SPIRE bootstrap attempt path changed during cleanup")
        path.unlink()
        remove_attempt = True
    finally:
        os.close(descriptor)
    if not remove_attempt or path.exists() or path.is_symlink():
        _fail("SPIRE bootstrap attempt remained after successful cleanup")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--operation",
        choices=("arm", "generate", "cleanup-escrow", "cleanup-stdin"),
        default="cleanup-stdin",
    )
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--alias-spiffe-id", required=True)
    parser.add_argument(
        "--bootstrap-outcome",
        choices=("verified", "unverified"),
    )
    parser.add_argument("--token-ttl-seconds", type=int)
    parser.add_argument("--trust-domain", default=TRUST_DOMAIN, choices=(TRUST_DOMAIN,))
    arguments = parser.parse_args(argv)
    try:
        if arguments.operation == "arm":
            if arguments.bootstrap_outcome is not None or arguments.token_ttl_seconds is not None:
                _fail("arming does not accept cleanup outcome or token TTL")
            result = arm_attempt(arguments.alias_spiffe_id)
        elif arguments.operation == "generate":
            if arguments.bootstrap_outcome is not None or arguments.token_ttl_seconds is None:
                _fail("generation requires only the exact token TTL")
            result = generate_attempt(
                arguments.alias_spiffe_id,
                token_ttl_seconds=arguments.token_ttl_seconds,
            )
        else:
            if arguments.bootstrap_outcome is None or arguments.token_ttl_seconds is not None:
                _fail("cleanup requires the exact bootstrap outcome and no token TTL")
            if arguments.operation == "cleanup-escrow":
                result = cleanup_attempt(
                    arguments.database,
                    alias_spiffe_id=arguments.alias_spiffe_id,
                    bootstrap_verified=arguments.bootstrap_outcome == "verified",
                    trust_domain=arguments.trust_domain,
                )
            else:
                result = cleanup(
                    arguments.database,
                    _read_token(),
                    alias_spiffe_id=arguments.alias_spiffe_id,
                    bootstrap_verified=arguments.bootstrap_outcome == "verified",
                    trust_domain=arguments.trust_domain,
                )
    except (OSError, TokenRevocationError) as exc:
        print(f"M4j SPIRE join-token cleanup failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
