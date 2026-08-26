"""Evidence-backed, bidirectional traceability for the proposed M8 baseline.

The traceability produced here is deliberately narrower than requirement
acceptance.  An explicit mapping may associate local repository artifacts and
test procedures with a requirement, but every requirement and TBR remains open.
Likewise, a cryptographically valid external attestation proves only signature,
freshness, and exact binding; it does not automatically establish assessor
independence, approve the baseline, or accept a requirement.
"""

from __future__ import annotations

import ast
import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Final, NoReturn, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis_ot.m8_traceability import (
    EXPECTED_REQUIREMENT_COUNT,
    EXPECTED_TBR_COUNT,
    RequirementsBaseline,
    parse_requirements_docx,
)

TRACEABILITY_SCHEMA: Final[str] = "aegis-ot-m8-evidence-traceability-v2"
MAPPING_SCHEMA: Final[str] = "aegis-ot-m8-reviewed-evidence-map-v1"
ATTESTATION_SCHEMA: Final[str] = "aegis-ot-m8-external-attestation-v1"
ATTESTATION_DOMAIN: Final[bytes] = b"AEGIS-OT:M8:EXTERNAL-ATTESTATION:V1\x00"
ATTESTATION_REPLAY_SCHEMA: Final[str] = "aegis-ot-m8-attestation-replay-state-v1"
PINNED_GIT_EXECUTABLE: Final[Path] = Path("/usr/bin/git")
AUTHORITATIVE_REQUIREMENTS_PATH: Final[str] = (
    "docs/requirements/Aegis-OT_End-State_System_Requirements.docx"
)
AUTHORITATIVE_MAPPING_PATH: Final[str] = "config/m8-requirements-evidence-map.json"
MAX_JSON_BYTES: Final[int] = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES: Final[int] = 64 * 1024 * 1024
MAX_GIT_CONFIG_BYTES: Final[int] = 1024 * 1024
MAX_PATHS_PER_REQUIREMENT: Final[int] = 24
MAX_TESTS_PER_REQUIREMENT: Final[int] = 24
SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_RE: Final[re.Pattern[str]] = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REQUIREMENT_RE: Final[re.Pattern[str]] = re.compile(r"^AOT-[A-Z]+-[0-9]{3}$")
REPO_PATH_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._/-]+$")
TEST_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^pytest::(?P<path>tests/[A-Za-z0-9_./-]+\.py)::(?P<name>test_[A-Za-z0-9_]+)$"
)

_MAPPING_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "mapping_id",
        "baseline_status",
        "review_scope",
        "review_authority",
        "approval_state",
        "entries",
    }
)
_ENTRY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "requirement_id",
        "rationale",
        "trust_boundary",
        "procedure_or_test_ids",
        "configuration",
        "environment",
        "implementation_artifacts",
        "result_artifacts",
        "owner",
        "disposition",
        "result",
        "result_artifact_state",
        "limitations",
    }
)
_ATTESTATION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "attestation_id",
        "authority_id",
        "key_id",
        "issued_at",
        "expires_at",
        "requirements_source_sha256",
        "git_commit",
        "git_tree",
        "mapping_sha256",
        "traceability_content_sha256",
        "purpose",
        "audience",
        "challenge_nonce",
        "sequence",
        "requirement_ids",
        "findings",
        "signature",
    }
)
_FINDING_FIELDS: Final[frozenset[str]] = frozenset(
    {"requirement_id", "disposition", "statement", "artifact_bindings"}
)
_ATTESTED_ARTIFACT_FIELDS: Final[frozenset[str]] = frozenset(
    {"path", "sha256", "git_blob"}
)
_MAPPED_RESULTS: Final[frozenset[str]] = frozenset({"not_executed"})
_RESULT_ARTIFACT_STATES: Final[frozenset[str]] = frozenset(
    {"no_result_artifact", "historical_only_no_current_result"}
)
_ATTESTATION_DISPOSITIONS: Final[frozenset[str]] = frozenset(
    {"satisfied", "not_satisfied", "inconclusive"}
)
CLAIM_BOUNDARY: Final[str] = (
    "Repository artifact and test mappings establish trace links only. All 223 "
    "requirements and all 35 TBRs remain open; no requirement is accepted. No "
    "external attestation is included, and independent validation, qualification, "
    "authorization, deployment, and operational effectiveness remain external."
)
ATTESTATION_INTERFACE: Final[dict[str, JsonValue]] = {
    "schema": ATTESTATION_SCHEMA,
    "trusted_authority_key_source": "application_supplied_out_of_band",
    "self_declared_keys_trusted": False,
    "stateless_verification_changes_assurance_state": False,
    "replay_safe_ingestion_required_for_state_change": True,
    "automatic_requirement_acceptance": False,
    "independent_validation_established": False,
}
EXPECTED_GATES: Final[dict[str, str]] = {
    "G0": "Controlled baseline",
    "G1": "Contracts and authorization kernel",
    "G2": "Bounded simulation and evidence",
    "G3": "Integrated capability transaction",
    "G4": "Representative multi-host and OT integration",
    "G5": "Compromise, resilience, and recovery",
    "G6": "Fleet, operations, usability, and economics",
    "G7": "Independent qualification and authorization",
}
EXPECTED_CLAIM_STATES: Final[dict[str, str]] = {
    "C0": "Specified",
    "C1": "Implemented",
    "C2": "Locally tested",
    "C3": "Retained evidence accepted",
    "C4": "Independently reproduced",
    "C5": "Representative multi-host/HIL validated",
    "C6": "Externally qualified and authorized",
    "C7": "Deployed",
    "C8": "Operationally effective",
}

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


class TraceabilityError(ValueError):
    """Raised when traceability material is unsafe, ambiguous, or noncanonical."""


def canonical_json_bytes(value: object) -> bytes:
    """Return finite, deterministic JSON bytes."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TraceabilityError("material is not canonical finite JSON") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TraceabilityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise TraceabilityError(f"nonfinite JSON value is prohibited: {value}")


def load_strict_json_bytes(material: bytes, *, label: str) -> dict[str, Any]:
    if not material or len(material) > MAX_JSON_BYTES:
        raise TraceabilityError(f"{label} size is outside the allowed range")
    try:
        decoded = material.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise TraceabilityError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise TraceabilityError(f"{label} root must be an object")
    return value


def _git_executable() -> str:
    try:
        metadata = PINNED_GIT_EXECUTABLE.lstat()
        resolved = PINNED_GIT_EXECUTABLE.resolve(strict=True)
    except OSError as exc:
        raise TraceabilityError("the pinned /usr/bin/git executable is unavailable") from exc
    if (
        PINNED_GIT_EXECUTABLE.is_symlink()
        or resolved != PINNED_GIT_EXECUTABLE
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink < 1
        or metadata.st_uid != 0
        or not os.access(PINNED_GIT_EXECUTABLE, os.X_OK)
    ):
        raise TraceabilityError("the pinned Git executable is not an authoritative root-owned file")
    return str(PINNED_GIT_EXECUTABLE)


def _git_environment() -> dict[str, str]:
    """Return a closed Git environment with ambient repository/config injection removed."""

    return {
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
        "GIT_EDITOR": "/usr/bin/false",
        "GIT_EXTERNAL_DIFF": "",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_SEQUENCE_EDITOR": "/usr/bin/false",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": "/usr/bin:/bin",
        "SSH_ASKPASS": "/usr/bin/false",
    }


def _validate_local_git_config(git_dir: Path, *, owner: int) -> None:
    """Reject local config sources capable of adding unbounded executors.

    Git's system and global configuration are disabled separately.  Local
    fsmonitor, hook, and pager keys are allowed because every invocation
    force-overrides them below; executable filter/diff/merge sections and
    include expansion are rejected fail closed.
    """

    config = git_dir / "config"
    try:
        metadata = config.lstat()
        resolved = config.resolve(strict=True)
    except OSError as exc:
        raise TraceabilityError("authoritative repository config is unavailable") from exc
    if (
        config.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != owner
        or resolved != config
        or metadata.st_size <= 0
        or metadata.st_size > MAX_GIT_CONFIG_BYTES
    ):
        raise TraceabilityError("authoritative repository config is not a bounded owned file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(config, flags)
    except OSError as exc:
        raise TraceabilityError("authoritative repository config cannot be opened") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
            or opened.st_nlink != 1
        ):
            raise TraceabilityError("authoritative repository config changed while opening")
        material = os.read(descriptor, MAX_GIT_CONFIG_BYTES + 1)
        if len(material) != opened.st_size or len(material) > MAX_GIT_CONFIG_BYTES:
            raise TraceabilityError("authoritative repository config changed while reading")
    finally:
        os.close(descriptor)
    try:
        text = material.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TraceabilityError("authoritative repository config is not UTF-8") from exc
    prohibited_section = re.compile(
        r'^\s*\[(?:include(?:if)?|filter|diff|merge)(?:\s|"|\])',
        flags=re.IGNORECASE,
    )
    if any(prohibited_section.match(line) for line in text.splitlines()):
        raise TraceabilityError(
            "repository-local include or filter/diff/merge executor config is prohibited"
        )
    if os.path.lexists(git_dir / "config.worktree"):
        raise TraceabilityError("repository-local worktree config is prohibited")


def _authoritative_git_dir(root: Path) -> Path:
    git_dir = root / ".git"
    try:
        root_status = root.lstat()
        metadata = git_dir.lstat()
        resolved = git_dir.resolve(strict=True)
    except OSError as exc:
        raise TraceabilityError("authoritative repository metadata is unavailable") from exc
    if (
        git_dir.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or resolved != git_dir
        or metadata.st_uid != root_status.st_uid
    ):
        raise TraceabilityError("authoritative repository .git must be a same-owner real directory")
    if os.path.lexists(git_dir / "commondir"):
        raise TraceabilityError("authoritative repository must not redirect common Git metadata")
    objects = git_dir / "objects"
    try:
        objects_metadata = objects.lstat()
        objects_resolved = objects.resolve(strict=True)
    except OSError as exc:
        raise TraceabilityError("authoritative repository object store is unavailable") from exc
    if (
        objects.is_symlink()
        or not stat.S_ISDIR(objects_metadata.st_mode)
        or objects_metadata.st_uid != root_status.st_uid
        or objects_resolved != objects
        or not objects_resolved.is_relative_to(git_dir)
    ):
        raise TraceabilityError(
            "authoritative repository objects must be a same-owner real in-repository directory"
        )
    for directory_name in ("info", "pack"):
        directory = objects / directory_name
        if not os.path.lexists(directory):
            continue
        directory_metadata = directory.lstat()
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != root_status.st_uid
            or directory.resolve(strict=True) != directory
        ):
            raise TraceabilityError("authoritative repository object topology is unsafe")
    for alternate_name in ("alternates", "http-alternates"):
        if os.path.lexists(objects / "info" / alternate_name):
            raise TraceabilityError("Git alternate object stores are prohibited")
    _validate_local_git_config(git_dir, owner=root_status.st_uid)
    return git_dir


def _git_bytes(root: Path, *args: str) -> bytes:
    git_dir = _authoritative_git_dir(root)
    completed = subprocess.run(  # noqa: S603 - fixed executable and no shell
        [
            _git_executable(),
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.pager=cat",
            "-c",
            "pager.rev-parse=false",
            "-c",
            "pager.status=false",
            "-c",
            "pager.ls-tree=false",
            "-c",
            "pager.cat-file=false",
            "-c",
            "pager.show=false",
            "-c",
            "diff.external=",
            "-c",
            "diff.trustExitCode=false",
            "-c",
            "interactive.diffFilter=",
            f"--git-dir={git_dir}",
            f"--work-tree={root}",
            *args,
        ],
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise TraceabilityError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout


def _git_text(root: Path, *args: str) -> str:
    try:
        return _git_bytes(root, *args).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TraceabilityError(f"git {' '.join(args)} returned non-UTF-8 output") from exc


def canonical_repository_root(root: Path) -> Path:
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise TraceabilityError("repository root is unavailable") from exc
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or root != resolved:
        raise TraceabilityError("repository root must be a canonical non-symlink directory")
    git_dir = _authoritative_git_dir(root)
    top = Path(_git_text(root, "rev-parse", "--show-toplevel").strip()).resolve()
    if top != root:
        raise TraceabilityError("repository root is not the authoritative Git checkout")
    reported_git_dir = Path(
        _git_text(root, "rev-parse", "--absolute-git-dir").strip()
    ).resolve()
    if reported_git_dir != git_dir:
        raise TraceabilityError("Git did not resolve the authoritative root .git directory")
    return root


def resolve_commit(root: Path, revision: str = "HEAD") -> tuple[str, str]:
    canonical_repository_root(root)
    commit = _git_text(root, "rev-parse", f"{revision}^{{commit}}").strip()
    tree = _git_text(root, "rev-parse", f"{revision}^{{tree}}").strip()
    if not GIT_OBJECT_RE.fullmatch(commit) or not GIT_OBJECT_RE.fullmatch(tree):
        raise TraceabilityError("Git returned a noncanonical commit or tree")
    return commit, tree


def require_clean_checkout(root: Path) -> None:
    canonical_repository_root(root)
    if _git_text(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise TraceabilityError("retained traceability requires an exact clean checkout")


def _canonical_repo_path(relative: str) -> PurePosixPath:
    if not isinstance(relative, str) or not REPO_PATH_RE.fullmatch(relative):
        raise TraceabilityError(f"repository path is noncanonical or overbroad: {relative!r}")
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", "..", ".git"} for part in pure.parts)
        or pure.as_posix() != relative
        or any(character in relative for character in "*?[]{}")
    ):
        raise TraceabilityError(f"repository path is unsafe or overbroad: {relative}")
    return pure


def _read_working_regular_file(root: Path, relative: str) -> bytes:
    pure = _canonical_repo_path(relative)
    candidate = root.joinpath(*pure.parts)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise TraceabilityError(f"mapped repository artifact is unavailable: {relative}") from exc
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or resolved != candidate
        or not resolved.is_relative_to(root)
        or metadata.st_size < 0
        or metadata.st_size > MAX_ARTIFACT_BYTES
    ):
        raise TraceabilityError(
            f"mapped repository artifact must be a bounded regular non-link file: {relative}"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise TraceabilityError(f"mapped repository artifact cannot be opened: {relative}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
        ):
            raise TraceabilityError(f"mapped repository artifact changed while opening: {relative}")
        material = bytearray()
        while len(material) <= MAX_ARTIFACT_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_ARTIFACT_BYTES + 1 - len(material)),
            )
            if not chunk:
                break
            material.extend(chunk)
        if len(material) != opened.st_size or len(material) > MAX_ARTIFACT_BYTES:
            raise TraceabilityError(f"mapped repository artifact changed while reading: {relative}")
        return bytes(material)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class ArtifactBinding:
    path: str
    bytes: int
    sha256: str
    git_mode: str
    git_blob: str

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "path": self.path,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "git_mode": self.git_mode,
            "git_blob": self.git_blob,
        }

    def attested_dict(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256, "git_blob": self.git_blob}


@dataclass(frozen=True, slots=True)
class HistoricalResultBinding:
    artifact: ArtifactBinding
    exercised_git_commit: str
    exercised_git_tree: str
    source_files_verified: int
    relationship_to_current_source: str

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "artifact": self.artifact.as_dict(),
            "exercised_git_commit": self.exercised_git_commit,
            "exercised_git_tree": self.exercised_git_tree,
            "source_files_verified": self.source_files_verified,
            "relationship_to_current_source": self.relationship_to_current_source,
        }


def bind_committed_file(root: Path, commit: str, relative: str) -> ArtifactBinding:
    """Bind a regular working file to the exact blob stored in ``commit``."""

    canonical_repository_root(root)
    if not GIT_OBJECT_RE.fullmatch(commit):
        raise TraceabilityError("commit identifier is noncanonical")
    working = _read_working_regular_file(root, relative)
    tree_record = _git_bytes(root, "ls-tree", "-z", commit, "--", relative)
    records = [record for record in tree_record.split(b"\0") if record]
    if len(records) != 1:
        raise TraceabilityError(f"mapped artifact is not one committed file: {relative}")
    try:
        header, retained_path = records[0].split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        committed_path = retained_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise TraceabilityError(f"Git returned a malformed entry for {relative}") from exc
    if (
        committed_path != relative
        or object_type != "blob"
        or mode not in {"100644", "100755"}
        or not GIT_OBJECT_RE.fullmatch(object_id)
    ):
        raise TraceabilityError(f"mapped artifact is not a committed regular file: {relative}")
    committed = _git_bytes(root, "show", f"{commit}:{relative}")
    if working != committed:
        raise TraceabilityError(f"mapped artifact differs from commit: {relative}")
    return ArtifactBinding(
        path=relative,
        bytes=len(working),
        sha256=sha256_bytes(working),
        git_mode=mode,
        git_blob=object_id,
    )


def _historical_source_identity(value: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
    nested = value.get("git")
    if isinstance(nested, dict):
        commit = nested.get("commit")
        dirty_values = (
            nested.get("working_tree_dirty_at_start"),
            nested.get("working_tree_dirty_at_end"),
        )
    else:
        commit = value.get("git_commit")
        dirty_values = (
            value.get("working_tree_dirty"),
            value.get("git_dirty_at_start"),
        )
    if not isinstance(commit, str) or not GIT_OBJECT_RE.fullmatch(commit):
        raise TraceabilityError("result artifact lacks a canonical exercised Git commit")
    supplied_dirty = [item for item in dirty_values if item is not None]
    if not supplied_dirty or any(item is not False for item in supplied_dirty):
        raise TraceabilityError("result artifact is not bound to an explicitly clean execution")
    source_hashes = value.get("source_sha256")
    if (
        not isinstance(source_hashes, dict)
        or not source_hashes
        or len(source_hashes) > 256
        or not all(isinstance(key, str) for key in source_hashes)
    ):
        raise TraceabilityError("result artifact lacks a bounded source-hash inventory")
    return commit, cast(Mapping[str, Any], source_hashes)


def bind_historical_result(
    root: Path,
    current_commit: str,
    relative: str,
) -> HistoricalResultBinding:
    """Bind a JSON result and independently check its exercised source identity."""

    artifact = bind_committed_file(root, current_commit, relative)
    material = _git_bytes(root, "show", f"{current_commit}:{relative}")
    value = load_strict_json_bytes(material, label=f"result artifact {relative}")
    exercised_commit, source_hashes = _historical_source_identity(value)
    try:
        exercised_tree = _git_text(
            root,
            "rev-parse",
            f"{exercised_commit}^{{tree}}",
        ).strip()
    except TraceabilityError as exc:
        raise TraceabilityError(
            f"result artifact exercised commit is unavailable: {relative}"
        ) from exc
    if not GIT_OBJECT_RE.fullmatch(exercised_tree):
        raise TraceabilityError(f"result artifact exercised tree is invalid: {relative}")
    verified = 0
    for stored_path, digest in sorted(source_hashes.items()):
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise TraceabilityError(f"result source digest is invalid: {relative}")
        source_path = stored_path.removeprefix("source/")
        _canonical_repo_path(source_path)
        try:
            source = _git_bytes(root, "show", f"{exercised_commit}:{source_path}")
        except TraceabilityError as exc:
            raise TraceabilityError(
                f"result source inventory cannot be resolved: {relative}:{source_path}"
            ) from exc
        if sha256_bytes(source) != digest:
            raise TraceabilityError(
                f"result source inventory digest does not match: {relative}:{source_path}"
            )
        verified += 1
    relationship = "current_exact" if exercised_commit == current_commit else "historical"
    return HistoricalResultBinding(
        artifact=artifact,
        exercised_git_commit=exercised_commit,
        exercised_git_tree=exercised_tree,
        source_files_verified=verified,
        relationship_to_current_source=relationship,
    )


@dataclass(frozen=True, slots=True)
class EvidenceMappingEntry:
    requirement_id: str
    rationale: str
    trust_boundary: str
    procedure_or_test_ids: tuple[str, ...]
    configuration: str
    environment: str
    implementation_artifacts: tuple[str, ...]
    result_artifacts: tuple[str, ...]
    owner: str
    disposition: str
    result: str
    result_artifact_state: str
    limitations: str


@dataclass(frozen=True, slots=True)
class EvidenceMapping:
    mapping_id: str
    review_scope: str
    review_authority: str
    entries: tuple[EvidenceMappingEntry, ...]


def _exact_fields(value: Mapping[str, Any], expected: frozenset[str], *, label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise TraceabilityError(f"{label} fields are not exact; missing={missing}, extra={extra}")


def _required_text(value: Mapping[str, Any], key: str, *, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip() or item != item.strip():
        raise TraceabilityError(f"{label}.{key} must be nonempty canonical text")
    return item


def _unique_sorted_strings(
    value: Any,
    *,
    label: str,
    maximum: int,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value) or len(value) > maximum:
        raise TraceabilityError(f"{label} must contain an allowed number of strings")
    if not all(isinstance(item, str) and item for item in value):
        raise TraceabilityError(f"{label} must contain only nonempty strings")
    items = cast(list[str], value)
    if items != sorted(items) or len(items) != len(set(items)):
        raise TraceabilityError(f"{label} must be unique and lexically sorted")
    return tuple(items)


def parse_evidence_mapping(
    material: bytes,
    *,
    known_requirement_ids: frozenset[str],
) -> EvidenceMapping:
    raw = load_strict_json_bytes(material, label="evidence mapping")
    _exact_fields(raw, _MAPPING_FIELDS, label="evidence mapping")
    if raw.get("schema") != MAPPING_SCHEMA:
        raise TraceabilityError("evidence mapping schema is unsupported")
    if raw.get("baseline_status") != "proposed_not_approved":
        raise TraceabilityError("evidence mapping must retain the proposed baseline status")
    if raw.get("approval_state") != "not_approved":
        raise TraceabilityError("evidence mapping must remain explicitly unapproved")
    mapping_id = _required_text(raw, "mapping_id", label="evidence mapping")
    review_scope = _required_text(raw, "review_scope", label="evidence mapping")
    review_authority = _required_text(raw, "review_authority", label="evidence mapping")
    if "independent" in review_authority.lower():
        raise TraceabilityError("mapping may not self-assert independent review authority")
    entries_raw = raw.get("entries")
    if not isinstance(entries_raw, list) or not entries_raw:
        raise TraceabilityError("evidence mapping must contain at least one explicit entry")
    entries: list[EvidenceMappingEntry] = []
    requirement_ids: list[str] = []
    for index, item in enumerate(entries_raw):
        if not isinstance(item, dict) or not all(isinstance(key, str) for key in item):
            raise TraceabilityError(f"mapping entry {index} must be a string-keyed object")
        _exact_fields(item, _ENTRY_FIELDS, label=f"mapping entry {index}")
        requirement_id = _required_text(item, "requirement_id", label=f"mapping entry {index}")
        if (
            not REQUIREMENT_RE.fullmatch(requirement_id)
            or requirement_id not in known_requirement_ids
        ):
            raise TraceabilityError(f"mapping entry names an unknown requirement: {requirement_id}")
        requirement_ids.append(requirement_id)
        procedures = _unique_sorted_strings(
            item.get("procedure_or_test_ids"),
            label=f"{requirement_id}.procedure_or_test_ids",
            maximum=MAX_TESTS_PER_REQUIREMENT,
            allow_empty=False,
        )
        for procedure in procedures:
            if not TEST_ID_RE.fullmatch(procedure):
                raise TraceabilityError(
                    f"{requirement_id} contains an overbroad or unsupported test ID: {procedure}"
                )
        implementation = _unique_sorted_strings(
            item.get("implementation_artifacts"),
            label=f"{requirement_id}.implementation_artifacts",
            maximum=MAX_PATHS_PER_REQUIREMENT,
            allow_empty=False,
        )
        results = _unique_sorted_strings(
            item.get("result_artifacts"),
            label=f"{requirement_id}.result_artifacts",
            maximum=MAX_PATHS_PER_REQUIREMENT,
            allow_empty=True,
        )
        for relative in (*implementation, *results):
            _canonical_repo_path(relative)
        procedure_paths = sorted(
            {
                cast(re.Match[str], TEST_ID_RE.fullmatch(procedure)).group("path")
                for procedure in procedures
            }
        )
        combined_paths = [*implementation, *results, *procedure_paths]
        if len(combined_paths) > MAX_PATHS_PER_REQUIREMENT:
            raise TraceabilityError(f"{requirement_id} maps too many repository paths")
        if len(combined_paths) != len(set(combined_paths)):
            raise TraceabilityError(
                f"{requirement_id} maps one path in conflicting artifact roles"
            )
        disposition = _required_text(item, "disposition", label=requirement_id)
        result = _required_text(item, "result", label=requirement_id)
        result_artifact_state = _required_text(
            item,
            "result_artifact_state",
            label=requirement_id,
        )
        if (
            disposition != "open_not_accepted"
            or result not in _MAPPED_RESULTS
            or result_artifact_state not in _RESULT_ARTIFACT_STATES
            or (bool(results) != (result_artifact_state == "historical_only_no_current_result"))
        ):
            raise TraceabilityError(
                f"{requirement_id} mapping must remain open with a consistent bounded result state"
            )
        entries.append(
            EvidenceMappingEntry(
                requirement_id=requirement_id,
                rationale=_required_text(item, "rationale", label=requirement_id),
                trust_boundary=_required_text(item, "trust_boundary", label=requirement_id),
                procedure_or_test_ids=procedures,
                configuration=_required_text(item, "configuration", label=requirement_id),
                environment=_required_text(item, "environment", label=requirement_id),
                implementation_artifacts=implementation,
                result_artifacts=results,
                owner=_required_text(item, "owner", label=requirement_id),
                disposition=disposition,
                result=result,
                result_artifact_state=result_artifact_state,
                limitations=_required_text(item, "limitations", label=requirement_id),
            )
        )
    if requirement_ids != sorted(requirement_ids) or len(requirement_ids) != len(
        set(requirement_ids)
    ):
        raise TraceabilityError(
            "mapping requirement entries must be unique and lexically sorted"
        )
    return EvidenceMapping(
        mapping_id=mapping_id,
        review_scope=review_scope,
        review_authority=review_authority,
        entries=tuple(entries),
    )


def _procedure_path_and_name(procedure: str) -> tuple[str, str]:
    match = TEST_ID_RE.fullmatch(procedure)
    if match is None:
        raise TraceabilityError(f"test procedure ID is noncanonical: {procedure}")
    return match.group("path"), match.group("name")


def _verify_test_procedure(root: Path, commit: str, procedure: str) -> str:
    relative, name = _procedure_path_and_name(procedure)
    source = _git_bytes(root, "show", f"{commit}:{relative}")
    try:
        tree = ast.parse(source, filename=relative)
    except (SyntaxError, ValueError) as exc:
        raise TraceabilityError(f"test procedure source is not valid Python: {procedure}") from exc
    declared = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if name not in declared:
        raise TraceabilityError(f"mapped test procedure does not exist exactly: {procedure}")
    return relative


def _copy_json(value: object) -> Any:
    return json.loads(canonical_json_bytes(value))


def _baseline_requirement_ids(baseline: RequirementsBaseline) -> frozenset[str]:
    return frozenset(item.requirement_id for item in baseline.requirements)


def _bind_cached(
    root: Path,
    commit: str,
    relative: str,
    cache: dict[str, ArtifactBinding],
) -> ArtifactBinding:
    binding = cache.get(relative)
    if binding is None:
        binding = bind_committed_file(root, commit, relative)
        cache[relative] = binding
    return binding


def _mapped_record(
    record: dict[str, Any],
    entry: EvidenceMappingEntry,
    role_paths: Mapping[str, Sequence[str]],
    bindings: Mapping[str, ArtifactBinding],
    historical_results: Sequence[HistoricalResultBinding],
) -> dict[str, Any]:
    result = cast(dict[str, Any], _copy_json(record))
    engineering = cast(dict[str, Any], result["engineering_basis"])
    verification = cast(dict[str, Any], result["verification"])
    disposition = cast(dict[str, Any], result["disposition"])
    engineering["rationale"] = entry.rationale
    engineering["trust_boundary"] = entry.trust_boundary
    verification["procedure_or_test_id"] = list(entry.procedure_or_test_ids)
    verification["configuration"] = entry.configuration
    verification["environment"] = entry.environment
    verification["result"] = entry.result
    all_paths = sorted({path for paths in role_paths.values() for path in paths})
    verification["artifact"] = [bindings[path].as_dict() for path in all_paths]
    disposition["implementation_state"] = "local_evidence_mapped_not_accepted"
    disposition["claim_state"] = "C0"
    disposition["finding_status"] = "open"
    disposition["owner"] = entry.owner
    disposition["residual_risk"] = entry.limitations
    disposition["approving_authority"] = None
    result["evidence_mapping"] = {
        "disposition": entry.disposition,
        "result_artifact_state": entry.result_artifact_state,
        "artifact_paths_by_role": {
            role: list(paths) for role, paths in sorted(role_paths.items())
        },
        "historical_result_evidence": [item.as_dict() for item in historical_results],
        "limitations": entry.limitations,
    }
    return result


def _traceability_content(report: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in report.items() if key != "content_sha256"}


def build_evidence_traceability(
    root: Path,
    *,
    requirements_path: str,
    mapping_path: str,
    revision: str = "HEAD",
) -> dict[str, Any]:
    """Build a complete open-state catalog plus exact forward and inverse links."""

    root = canonical_repository_root(root)
    commit, tree = resolve_commit(root, revision)
    requirements_binding = bind_committed_file(root, commit, requirements_path)
    mapping_binding = bind_committed_file(root, commit, mapping_path)
    baseline = parse_requirements_docx(root / requirements_path)
    if baseline.source_sha256 != requirements_binding.sha256:
        raise TraceabilityError("requirements baseline digest differs from its Git binding")
    mapping_material = _git_bytes(root, "show", f"{commit}:{mapping_path}")
    mapping = parse_evidence_mapping(
        mapping_material,
        known_requirement_ids=_baseline_requirement_ids(baseline),
    )

    cache: dict[str, ArtifactBinding] = {
        requirements_path: requirements_binding,
        mapping_path: mapping_binding,
    }
    forward: dict[str, dict[str, JsonValue]] = {}
    inverse_artifacts: dict[str, dict[str, Any]] = {}
    inverse_historical_results: dict[str, dict[str, Any]] = {}
    inverse_procedures: dict[str, list[str]] = {}
    historical_by_requirement: dict[str, list[HistoricalResultBinding]] = {}
    entries = {entry.requirement_id: entry for entry in mapping.entries}

    for entry in mapping.entries:
        procedure_paths: list[str] = []
        for procedure in entry.procedure_or_test_ids:
            relative = _verify_test_procedure(root, commit, procedure)
            procedure_paths.append(relative)
            inverse_procedures.setdefault(procedure, []).append(entry.requirement_id)
        role_paths: dict[str, tuple[str, ...]] = {
            "implementation": entry.implementation_artifacts,
            "procedure": tuple(sorted(set(procedure_paths))),
        }
        all_paths = sorted({path for paths in role_paths.values() for path in paths})
        for path in all_paths:
            binding = _bind_cached(root, commit, path, cache)
            inverse = inverse_artifacts.setdefault(
                path,
                {
                    "binding": binding.as_dict(),
                    "requirement_ids": [],
                    "roles": [],
                },
            )
            cast(list[str], inverse["requirement_ids"]).append(entry.requirement_id)
            for role, paths in role_paths.items():
                if path in paths and role not in cast(list[str], inverse["roles"]):
                    cast(list[str], inverse["roles"]).append(role)
        historical_results: list[HistoricalResultBinding] = []
        for path in entry.result_artifacts:
            historical = bind_historical_result(root, commit, path)
            if historical.relationship_to_current_source != "historical":
                raise TraceabilityError(
                    f"result artifact declared historical but matches current source: {path}"
                )
            historical_results.append(historical)
            inverse = inverse_historical_results.setdefault(
                path,
                {
                    "binding": historical.as_dict(),
                    "requirement_ids": [],
                },
            )
            cast(list[str], inverse["requirement_ids"]).append(entry.requirement_id)
        historical_by_requirement[entry.requirement_id] = historical_results
        forward[entry.requirement_id] = {
            "artifact_paths_by_role": {
                role: list(paths) for role, paths in sorted(role_paths.items())
            },
            "procedure_or_test_ids": list(entry.procedure_or_test_ids),
            "historical_result_paths": list(entry.result_artifacts),
            "owner": entry.owner,
            "disposition": entry.disposition,
            "result": entry.result,
            "result_artifact_state": entry.result_artifact_state,
        }

    for value in inverse_artifacts.values():
        value["requirement_ids"] = sorted(set(cast(list[str], value["requirement_ids"])))
        value["roles"] = sorted(cast(list[str], value["roles"]))
    for procedure, requirement_ids in inverse_procedures.items():
        inverse_procedures[procedure] = sorted(set(requirement_ids))
    for value in inverse_historical_results.values():
        value["requirement_ids"] = sorted(
            set(cast(list[str], value["requirement_ids"]))
        )

    base_report = baseline.report()
    base_requirements = cast(list[dict[str, Any]], base_report["requirements"])
    requirements: list[dict[str, Any]] = []
    for record in base_requirements:
        identity = cast(dict[str, Any], record["identity"])
        requirement_id = cast(str, identity["requirement_id"])
        mapped_entry = entries.get(requirement_id)
        if mapped_entry is None:
            requirements.append(cast(dict[str, Any], _copy_json(record)))
            continue
        role_paths_raw = cast(
            dict[str, list[str]],
            forward[requirement_id]["artifact_paths_by_role"],
        )
        requirements.append(
            _mapped_record(
                record,
                mapped_entry,
                role_paths_raw,
                cache,
                historical_by_requirement[requirement_id],
            )
        )

    if len(requirements) != EXPECTED_REQUIREMENT_COUNT:
        raise TraceabilityError("complete requirement catalog was not retained")
    if any(
        cast(dict[str, Any], item["disposition"])["finding_status"] != "open"
        or cast(dict[str, Any], item["disposition"])["claim_state"] != "C0"
        or cast(dict[str, Any], item["disposition"])["approving_authority"] is not None
        for item in requirements
    ):
        raise TraceabilityError("mapped traceability changed an open requirement state")
    tbrs = cast(list[dict[str, Any]], base_report["tbrs"])
    if len(tbrs) != EXPECTED_TBR_COUNT or any(item["status"] != "open" for item in tbrs):
        raise TraceabilityError("mapped traceability changed an open TBR state")

    mapped_ids = sorted(entries)
    all_ids = [
        cast(str, cast(dict[str, Any], item["identity"])["requirement_id"])
        for item in requirements
    ]
    report: dict[str, Any] = {
        "schema": TRACEABILITY_SCHEMA,
        "source_binding": {
            "git_commit": commit,
            "git_tree": tree,
            "requirements": requirements_binding.as_dict(),
            "mapping": mapping_binding.as_dict(),
        },
        "mapping": {
            "schema": MAPPING_SCHEMA,
            "mapping_id": mapping.mapping_id,
            "review_scope": mapping.review_scope,
            "review_authority": mapping.review_authority,
            "approval_state": "not_approved",
        },
        "summary": {
            "requirements_tracked": EXPECTED_REQUIREMENT_COUNT,
            "requirements_mapped": len(mapped_ids),
            "requirements_unmapped": EXPECTED_REQUIREMENT_COUNT - len(mapped_ids),
            "requirements_open": EXPECTED_REQUIREMENT_COUNT,
            "requirements_accepted": 0,
            "tbrs_tracked": EXPECTED_TBR_COUNT,
            "tbrs_open": EXPECTED_TBR_COUNT,
            "end_state_accepted": False,
        },
        "requirements": requirements,
        "tbrs": _copy_json(tbrs),
        "gates": _copy_json(base_report["gates"]),
        "claim_states": _copy_json(base_report["claim_states"]),
        "catalog_sha256": base_report["catalog_sha256"],
        "forward_index": {key: forward[key] for key in sorted(forward)},
        "inverse_index": {
            "artifacts": {
                key: inverse_artifacts[key] for key in sorted(inverse_artifacts)
            },
            "historical_results": {
                key: inverse_historical_results[key]
                for key in sorted(inverse_historical_results)
            },
            "procedures": {
                key: inverse_procedures[key] for key in sorted(inverse_procedures)
            },
        },
        "coverage": {
            "mapped_requirement_ids": mapped_ids,
            "unmapped_requirement_ids": sorted(set(all_ids) - set(mapped_ids)),
        },
        "external_attestations": [],
        "attestation_interface": _copy_json(ATTESTATION_INTERFACE),
        "claim_boundary": CLAIM_BOUNDARY,
    }
    report["content_sha256"] = sha256_json(_traceability_content(report))
    _validate_evidence_traceability_structure(report)
    return report


def _validate_binding_dict(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "bytes",
        "sha256",
        "git_mode",
        "git_blob",
    }:
        raise TraceabilityError(f"{label} binding fields are not exact")
    if (
        not isinstance(value.get("path"), str)
        or type(value.get("bytes")) is not int
        or value["bytes"] <= 0
        or not isinstance(value.get("sha256"), str)
        or not SHA256_RE.fullmatch(value["sha256"])
        or value.get("git_mode") not in {"100644", "100755"}
        or not isinstance(value.get("git_blob"), str)
        or not GIT_OBJECT_RE.fullmatch(value["git_blob"])
    ):
        raise TraceabilityError(f"{label} binding is noncanonical")
    _canonical_repo_path(cast(str, value["path"]))
    return value


def _ordered_unique_strings(value: Any, *, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not all(isinstance(item, str) and item for item in value)
        or value != sorted(value)
        or len(value) != len(set(value))
    ):
        raise TraceabilityError(f"{label} must be a unique sorted string list")
    return cast(list[str], value)


def _validate_evidence_traceability_structure(report: Mapping[str, Any]) -> None:
    """Validate closed structure and cross-index semantics without rebuilding."""

    if set(report) != {
        "schema",
        "source_binding",
        "mapping",
        "summary",
        "requirements",
        "tbrs",
        "gates",
        "claim_states",
        "catalog_sha256",
        "forward_index",
        "inverse_index",
        "coverage",
        "external_attestations",
        "attestation_interface",
        "claim_boundary",
        "content_sha256",
    } or report.get("schema") != TRACEABILITY_SCHEMA:
        raise TraceabilityError("traceability report fields or schema are not exact")

    source = report.get("source_binding")
    if not isinstance(source, dict) or set(source) != {
        "git_commit",
        "git_tree",
        "requirements",
        "mapping",
    }:
        raise TraceabilityError("traceability source-binding fields are not exact")
    if not all(
        isinstance(source.get(field), str) and GIT_OBJECT_RE.fullmatch(source[field])
        for field in ("git_commit", "git_tree")
    ):
        raise TraceabilityError("traceability source commit or tree is noncanonical")
    requirements_source = _validate_binding_dict(
        source.get("requirements"), label="requirements source"
    )
    mapping_source = _validate_binding_dict(source.get("mapping"), label="mapping source")
    if requirements_source["path"] == mapping_source["path"]:
        raise TraceabilityError("requirements and mapping source bindings conflict")

    mapping = report.get("mapping")
    if not isinstance(mapping, dict) or set(mapping) != {
        "schema",
        "mapping_id",
        "review_scope",
        "review_authority",
        "approval_state",
    }:
        raise TraceabilityError("traceability mapping metadata fields are not exact")
    if (
        mapping.get("schema") != MAPPING_SCHEMA
        or mapping.get("approval_state") != "not_approved"
        or mapping.get("review_authority") != "implementation_custody"
        or not isinstance(mapping.get("mapping_id"), str)
        or not isinstance(mapping.get("review_scope"), str)
    ):
        raise TraceabilityError("traceability mapping metadata is not bounded")

    summary = report.get("summary")
    if not isinstance(summary, dict) or set(summary) != {
        "requirements_tracked",
        "requirements_mapped",
        "requirements_unmapped",
        "requirements_open",
        "requirements_accepted",
        "tbrs_tracked",
        "tbrs_open",
        "end_state_accepted",
    }:
        raise TraceabilityError("traceability summary fields are not exact")
    mapped_count = summary.get("requirements_mapped")
    unmapped_count = summary.get("requirements_unmapped")
    if (
        summary.get("requirements_tracked") != EXPECTED_REQUIREMENT_COUNT
        or type(mapped_count) is not int
        or type(unmapped_count) is not int
        or mapped_count <= 0
        or unmapped_count < 0
        or mapped_count + unmapped_count != EXPECTED_REQUIREMENT_COUNT
        or summary.get("requirements_open") != EXPECTED_REQUIREMENT_COUNT
        or summary.get("requirements_accepted") != 0
        or summary.get("tbrs_tracked") != EXPECTED_TBR_COUNT
        or summary.get("tbrs_open") != EXPECTED_TBR_COUNT
        or summary.get("end_state_accepted") is not False
    ):
        raise TraceabilityError("traceability summary does not preserve the exact open state")

    requirements = report.get("requirements")
    if not isinstance(requirements, list) or len(requirements) != EXPECTED_REQUIREMENT_COUNT:
        raise TraceabilityError("traceability report does not retain all requirements")
    requirement_ids: list[str] = []
    records_by_id: dict[str, dict[str, Any]] = {}
    for item in requirements:
        if not isinstance(item, dict) or set(item) not in (
            {"identity", "engineering_basis", "verification", "disposition", "change_history"},
            {
                "identity",
                "engineering_basis",
                "verification",
                "disposition",
                "change_history",
                "evidence_mapping",
            },
        ):
            raise TraceabilityError("requirement record fields are not exact")
        identity = item.get("identity")
        verification = item.get("verification")
        disposition = item.get("disposition")
        history = item.get("change_history")
        if not isinstance(identity, dict) or set(identity) != {
            "requirement_id",
            "revision",
            "title",
            "normative_text",
            "class",
            "applicability",
        }:
            raise TraceabilityError("requirement identity fields are not exact")
        requirement_id = identity.get("requirement_id")
        if not isinstance(requirement_id, str) or not REQUIREMENT_RE.fullmatch(requirement_id):
            raise TraceabilityError("requirement identifier is noncanonical")
        requirement_ids.append(requirement_id)
        records_by_id[requirement_id] = item
        if (
            not isinstance(verification, dict)
            or set(verification) != {
                "method",
                "procedure_or_test_id",
                "configuration",
                "acceptance_threshold",
                "environment",
                "assessor",
                "result",
                "artifact",
                "date",
            }
            or not isinstance(disposition, dict)
            or disposition.get("finding_status") != "open"
            or disposition.get("claim_state") != "C0"
            or disposition.get("approving_authority") is not None
            or not isinstance(history, list)
            or len(history) != 1
            or not isinstance(history[0], dict)
            or history[0].get("approval") != "not_approved"
            or history[0].get("effective_baseline") != "proposed"
        ):
            raise TraceabilityError("one or more system requirements is not exactly open")
    if len(set(requirement_ids)) != EXPECTED_REQUIREMENT_COUNT:
        raise TraceabilityError("requirement identities are duplicated or incomplete")

    tbrs = report.get("tbrs")
    if not isinstance(tbrs, list) or len(tbrs) != EXPECTED_TBR_COUNT:
        raise TraceabilityError("traceability report does not retain all TBRs")
    expected_tbr_ids = [f"TBR-{index:03d}" for index in range(1, EXPECTED_TBR_COUNT + 1)]
    if [item.get("tbr_id") for item in tbrs if isinstance(item, dict)] != expected_tbr_ids:
        raise TraceabilityError("TBR identities are duplicated, missing, or reordered")
    if any(
        not isinstance(item, dict)
        or item.get("status") != "open"
        or item.get("closure_artifacts") != []
        or item.get("closed_by") is not None
        or item.get("closed_at") is not None
        for item in tbrs
    ):
        raise TraceabilityError("one or more TBRs is not explicitly open")

    gates = report.get("gates")
    claims = report.get("claim_states")
    if gates != EXPECTED_GATES:
        raise TraceabilityError("gate catalog or semantics drifted")
    if claims != EXPECTED_CLAIM_STATES:
        raise TraceabilityError("claim-state catalog or semantics drifted")
    catalog_hash = report.get("catalog_sha256")
    if not isinstance(catalog_hash, str) or not SHA256_RE.fullmatch(catalog_hash):
        raise TraceabilityError("catalog digest is noncanonical")

    forward = report.get("forward_index")
    inverse = report.get("inverse_index")
    coverage = report.get("coverage")
    if not isinstance(forward, dict) or not isinstance(inverse, dict) or set(inverse) != {
        "artifacts",
        "historical_results",
        "procedures",
    }:
        raise TraceabilityError("forward or inverse index fields are not exact")
    if not isinstance(coverage, dict) or set(coverage) != {
        "mapped_requirement_ids",
        "unmapped_requirement_ids",
    }:
        raise TraceabilityError("coverage fields are not exact")
    mapped_ids = _ordered_unique_strings(
        coverage.get("mapped_requirement_ids"), label="mapped requirement coverage"
    )
    unmapped_ids = _ordered_unique_strings(
        coverage.get("unmapped_requirement_ids"), label="unmapped requirement coverage"
    )
    if (
        mapped_ids != sorted(forward)
        or len(mapped_ids) != mapped_count
        or len(unmapped_ids) != unmapped_count
        or set(mapped_ids).isdisjoint(unmapped_ids) is False
        or set(mapped_ids) | set(unmapped_ids) != set(requirement_ids)
    ):
        raise TraceabilityError("mapping coverage and forward index are inconsistent")

    expected_artifacts: dict[str, dict[str, set[str]]] = {}
    expected_artifact_bindings: dict[str, dict[str, Any]] = {}
    expected_procedures: dict[str, set[str]] = {}
    expected_historical: dict[str, set[str]] = {}
    expected_historical_bindings: dict[str, dict[str, Any]] = {}
    for requirement_id in mapped_ids:
        link = forward.get(requirement_id)
        record = records_by_id[requirement_id]
        evidence_mapping = record.get("evidence_mapping")
        if not isinstance(link, dict) or set(link) != {
            "artifact_paths_by_role",
            "procedure_or_test_ids",
            "historical_result_paths",
            "owner",
            "disposition",
            "result",
            "result_artifact_state",
        } or not isinstance(evidence_mapping, dict) or set(evidence_mapping) != {
            "disposition",
            "result_artifact_state",
            "artifact_paths_by_role",
            "historical_result_evidence",
            "limitations",
        }:
            raise TraceabilityError("mapped forward link fields are not exact")
        roles = link.get("artifact_paths_by_role")
        if not isinstance(roles, dict) or set(roles) != {"implementation", "procedure"}:
            raise TraceabilityError("current artifact roles are not exactly separated")
        role_paths: dict[str, list[str]] = {}
        for role in ("implementation", "procedure"):
            role_paths[role] = _ordered_unique_strings(
                roles.get(role), label=f"{requirement_id} {role} paths"
            )
            for path in role_paths[role]:
                _canonical_repo_path(path)
                state = expected_artifacts.setdefault(
                    path, {"requirements": set(), "roles": set()}
                )
                state["requirements"].add(requirement_id)
                state["roles"].add(role)
        if set(role_paths["implementation"]) & set(role_paths["procedure"]):
            raise TraceabilityError("mapped current artifact roles conflict")
        procedures = _ordered_unique_strings(
            link.get("procedure_or_test_ids"), label=f"{requirement_id} procedures"
        )
        if sorted({_procedure_path_and_name(item)[0] for item in procedures}) != role_paths[
            "procedure"
        ]:
            raise TraceabilityError("procedure IDs and procedure artifacts are inconsistent")
        for procedure in procedures:
            expected_procedures.setdefault(procedure, set()).add(requirement_id)
        historical_paths = _ordered_unique_strings(
            link.get("historical_result_paths"),
            label=f"{requirement_id} historical results",
        )
        for path in historical_paths:
            _canonical_repo_path(path)
            expected_historical.setdefault(path, set()).add(requirement_id)
        verification = cast(dict[str, Any], record["verification"])
        disposition = cast(dict[str, Any], record["disposition"])
        if (
            verification.get("procedure_or_test_id") != procedures
            or verification.get("result") != "not_executed"
            or disposition.get("implementation_state")
            != "local_evidence_mapped_not_accepted"
            or disposition.get("owner") != link.get("owner")
            or link.get("disposition") != "open_not_accepted"
            or link.get("result") != "not_executed"
            or link.get("result_artifact_state")
            not in _RESULT_ARTIFACT_STATES
            or bool(historical_paths)
            != (link.get("result_artifact_state") == "historical_only_no_current_result")
            or evidence_mapping.get("artifact_paths_by_role") != roles
            or evidence_mapping.get("result_artifact_state")
            != link.get("result_artifact_state")
        ):
            raise TraceabilityError("mapped requirement semantics are inconsistent")
        artifacts = verification.get("artifact")
        expected_paths = sorted(role_paths["implementation"] + role_paths["procedure"])
        artifact_bindings: list[dict[str, Any]] = []
        if isinstance(artifacts, list):
            artifact_bindings = [
                _validate_binding_dict(item, label=f"{requirement_id} current artifact")
                for item in artifacts
            ]
        if [item["path"] for item in artifact_bindings] != expected_paths:
            raise TraceabilityError("mapped current artifact bindings are inconsistent")
        for binding in artifact_bindings:
            path = cast(str, binding["path"])
            prior = expected_artifact_bindings.setdefault(path, binding)
            if prior != binding:
                raise TraceabilityError("current artifact binding conflicts across requirements")
        historical_evidence = evidence_mapping.get("historical_result_evidence")
        if not isinstance(historical_evidence, list) or len(historical_evidence) != len(
            historical_paths
        ):
            raise TraceabilityError("historical result evidence is inconsistent")
        retained_historical_paths: list[str] = []
        for value in historical_evidence:
            if (
                not isinstance(value, dict)
                or set(value) != {
                    "artifact",
                    "exercised_git_commit",
                    "exercised_git_tree",
                    "source_files_verified",
                    "relationship_to_current_source",
                }
                or value.get("relationship_to_current_source") != "historical"
                or not isinstance(value.get("exercised_git_commit"), str)
                or not GIT_OBJECT_RE.fullmatch(value["exercised_git_commit"])
                or not isinstance(value.get("exercised_git_tree"), str)
                or not GIT_OBJECT_RE.fullmatch(value["exercised_git_tree"])
                or type(value.get("source_files_verified")) is not int
                or value["source_files_verified"] <= 0
            ):
                raise TraceabilityError("historical result source identity is invalid")
            artifact = _validate_binding_dict(
                value.get("artifact"), label=f"{requirement_id} historical result"
            )
            path = cast(str, artifact["path"])
            retained_historical_paths.append(path)
            prior = expected_historical_bindings.setdefault(path, value)
            if prior != value:
                raise TraceabilityError("historical result binding conflicts across requirements")
        if retained_historical_paths != historical_paths:
            raise TraceabilityError("historical result paths and evidence are inconsistent")

    for requirement_id in unmapped_ids:
        record = records_by_id[requirement_id]
        verification = cast(dict[str, Any], record["verification"])
        disposition = cast(dict[str, Any], record["disposition"])
        if (
            "evidence_mapping" in record
            or verification.get("procedure_or_test_id") != []
            or verification.get("artifact") != []
            or verification.get("result") != "not_assessed"
            or disposition.get("implementation_state") != "not_assessed"
            or "owner" in disposition
        ):
            raise TraceabilityError("unmapped requirement contains inferred evidence fields")

    inverse_artifacts = inverse.get("artifacts")
    inverse_procedures = inverse.get("procedures")
    inverse_historical = inverse.get("historical_results")
    if not all(
        isinstance(item, dict)
        for item in (inverse_artifacts, inverse_procedures, inverse_historical)
    ):
        raise TraceabilityError("inverse index values are not objects")
    inverse_artifacts = cast(dict[str, Any], inverse_artifacts)
    inverse_procedures = cast(dict[str, Any], inverse_procedures)
    inverse_historical = cast(dict[str, Any], inverse_historical)
    if set(inverse_artifacts) != set(expected_artifacts):
        raise TraceabilityError("artifact inverse index path set is inconsistent")
    for path, expected in expected_artifacts.items():
        value = inverse_artifacts[path]
        if (
            not isinstance(value, dict)
            or set(value) != {"binding", "requirement_ids", "roles"}
            or value.get("requirement_ids") != sorted(expected["requirements"])
            or value.get("roles") != sorted(expected["roles"])
            or _validate_binding_dict(
                value.get("binding"), label=f"inverse artifact {path}"
            )
            != expected_artifact_bindings[path]
        ):
            raise TraceabilityError("artifact inverse index is inconsistent")
    if inverse_procedures != {
        key: sorted(value) for key, value in sorted(expected_procedures.items())
    }:
        raise TraceabilityError("procedure inverse index is inconsistent")
    if set(inverse_historical) != set(expected_historical):
        raise TraceabilityError("historical result inverse index path set is inconsistent")
    for path, requirement_set in expected_historical.items():
        value = inverse_historical[path]
        if (
            not isinstance(value, dict)
            or set(value) != {"binding", "requirement_ids"}
            or value.get("requirement_ids") != sorted(requirement_set)
            or not isinstance(value.get("binding"), dict)
            or value["binding"] != expected_historical_bindings[path]
        ):
            raise TraceabilityError("historical result inverse index is inconsistent")

    if report.get("external_attestations") != []:
        raise TraceabilityError("the v2 local campaign must not contain fabricated attestations")
    if report.get("attestation_interface") != ATTESTATION_INTERFACE:
        raise TraceabilityError("external attestation boundaries are not exact")
    if report.get("claim_boundary") != CLAIM_BOUNDARY:
        raise TraceabilityError("traceability claim boundary drifted")
    content_hash = report.get("content_sha256")
    if not isinstance(content_hash, str) or content_hash != sha256_json(
        _traceability_content(report)
    ):
        raise TraceabilityError("traceability content digest is invalid")


def validate_evidence_traceability(
    report: Mapping[str, Any],
    *,
    root: Path,
    requirements_path: str,
    mapping_path: str,
) -> None:
    """Validate ``report`` against an exact clean authoritative HEAD rebuild.

    Structural validity alone is intentionally not exported as an assurance
    decision.  This entry point binds the complete 223-requirement/35-TBR
    catalog, its recomputed catalog digest, every source and artifact blob, and
    all forward/inverse semantics to one stable authoritative repository state.
    """

    if (
        requirements_path != AUTHORITATIVE_REQUIREMENTS_PATH
        or mapping_path != AUTHORITATIVE_MAPPING_PATH
    ):
        raise TraceabilityError("traceability validation requires the authoritative source paths")
    _validate_evidence_traceability_structure(report)
    root = canonical_repository_root(root)
    require_clean_checkout(root)
    before_commit, before_tree = resolve_commit(root)
    rebuilt = build_evidence_traceability(
        root,
        requirements_path=requirements_path,
        mapping_path=mapping_path,
        revision=before_commit,
    )
    require_clean_checkout(root)
    if resolve_commit(root) != (before_commit, before_tree):
        raise TraceabilityError("repository changed during exact traceability validation")
    if report.get("source_binding") != rebuilt["source_binding"]:
        raise TraceabilityError(
            "traceability source and blob identities do not match the exact current repository"
        )
    if report.get("catalog_sha256") != rebuilt["catalog_sha256"]:
        raise TraceabilityError(
            "traceability catalog digest does not match the exact current repository baseline"
        )
    if (
        report.get("requirements") != rebuilt["requirements"]
        or report.get("tbrs") != rebuilt["tbrs"]
    ):
        raise TraceabilityError(
            "traceability requirements or TBRs do not match the exact current repository baseline"
        )
    if canonical_json_bytes(report) != canonical_json_bytes(rebuilt):
        raise TraceabilityError(
            "traceability does not match the exact current repository baseline"
        )


@dataclass(frozen=True, slots=True)
class TrustedAttestationAuthority:
    """Out-of-band trust configuration; never populated from an attestation."""

    authority_id: str
    public_key: Ed25519PublicKey
    allowed_requirement_ids: frozenset[str]
    maximum_age: timedelta = timedelta(days=30)
    maximum_validity: timedelta = timedelta(days=31)
    future_skew: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        if not self.authority_id or self.authority_id != self.authority_id.strip():
            raise TraceabilityError("trusted authority ID must be nonempty canonical text")
        if not self.allowed_requirement_ids or any(
            not REQUIREMENT_RE.fullmatch(item) for item in self.allowed_requirement_ids
        ):
            raise TraceabilityError("trusted authority requirement scope is invalid")
        if (
            self.maximum_age <= timedelta(0)
            or self.maximum_validity <= timedelta(0)
            or self.future_skew < timedelta(0)
        ):
            raise TraceabilityError("trusted authority freshness limits are invalid")

    @property
    def key_id(self) -> str:
        return "ed25519-sha256:" + sha256_bytes(self.public_key.public_bytes_raw())


@dataclass(frozen=True, slots=True)
class AttestedArtifactBinding:
    path: str
    sha256: str
    git_blob: str

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256, "git_blob": self.git_blob}


@dataclass(frozen=True, slots=True)
class AttestationContext:
    requirements_source_sha256: str
    git_commit: str
    git_tree: str
    mapping_sha256: str
    traceability_content_sha256: str
    purpose: str
    audience: str
    challenge_nonce: str
    artifacts_by_requirement: Mapping[str, tuple[AttestedArtifactBinding, ...]]


def attestation_context(
    report: Mapping[str, Any],
    *,
    root: Path,
    requirements_path: str,
    mapping_path: str,
    purpose: str,
    audience: str,
    challenge_nonce: str,
) -> AttestationContext:
    """Build an attestation context only after an exact current-repository rebuild."""

    validate_evidence_traceability(
        report,
        root=root,
        requirements_path=requirements_path,
        mapping_path=mapping_path,
    )
    for label, value in (("purpose", purpose), ("audience", audience)):
        if not value or value != value.strip() or len(value) > 200:
            raise TraceabilityError(f"attestation {label} is not bounded canonical text")
    if (
        not isinstance(challenge_nonce, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", challenge_nonce)
    ):
        raise TraceabilityError("attestation challenge nonce is noncanonical")
    source = cast(dict[str, Any], report["source_binding"])
    requirements = cast(dict[str, Any], source["requirements"])
    mapping = cast(dict[str, Any], source["mapping"])
    forward = cast(dict[str, dict[str, Any]], report["forward_index"])
    inverse = cast(dict[str, Any], report["inverse_index"])
    artifacts = cast(dict[str, dict[str, Any]], inverse["artifacts"])
    by_requirement: dict[str, tuple[AttestedArtifactBinding, ...]] = {}
    for requirement_id, link in forward.items():
        paths_by_role = cast(dict[str, list[str]], link["artifact_paths_by_role"])
        paths = sorted({path for values in paths_by_role.values() for path in values})
        bound: list[AttestedArtifactBinding] = []
        for path in paths:
            binding = cast(dict[str, Any], artifacts[path]["binding"])
            bound.append(
                AttestedArtifactBinding(
                    path=path,
                    sha256=cast(str, binding["sha256"]),
                    git_blob=cast(str, binding["git_blob"]),
                )
            )
        by_requirement[requirement_id] = tuple(bound)
    return AttestationContext(
        requirements_source_sha256=cast(str, requirements["sha256"]),
        git_commit=cast(str, source["git_commit"]),
        git_tree=cast(str, source["git_tree"]),
        mapping_sha256=cast(str, mapping["sha256"]),
        traceability_content_sha256=cast(str, report["content_sha256"]),
        purpose=purpose,
        audience=audience,
        challenge_nonce=challenge_nonce,
        artifacts_by_requirement=MappingProxyType(by_requirement),
    )


def attestation_signing_bytes(unsigned: Mapping[str, Any]) -> bytes:
    if "signature" in unsigned:
        raise TraceabilityError("unsigned attestation material contains a signature field")
    return ATTESTATION_DOMAIN + canonical_json_bytes(dict(unsigned))


def _canonical_time(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise TraceabilityError(f"{label} must be canonical UTC text")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TraceabilityError(f"{label} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0) or parsed.isoformat() != value:
        raise TraceabilityError(f"{label} must be canonical timezone-aware UTC text")
    return parsed.astimezone(UTC)


def _canonical_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise TraceabilityError("attestation signature must be canonical URL-safe Base64")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise TraceabilityError("attestation signature is not canonical URL-safe Base64") from exc
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).decode("ascii") != value:
        raise TraceabilityError("attestation signature is not canonical Ed25519 Base64")
    return decoded


def verify_external_attestation_stateless(
    material: bytes,
    *,
    authority: TrustedAttestationAuthority,
    context: AttestationContext,
    now: datetime,
) -> dict[str, JsonValue]:
    """Statelessly verify trust, freshness, purpose, and exact bindings.

    The returned record is safe to retain as a cryptographic-verification result,
    but it intentionally contains false values for automatic acceptance and
    independent-validation establishment.
    """

    value = load_strict_json_bytes(material, label="external attestation")
    _exact_fields(value, _ATTESTATION_FIELDS, label="external attestation")
    if value.get("schema") != ATTESTATION_SCHEMA:
        raise TraceabilityError("external attestation schema is unsupported")
    if (
        value.get("authority_id") != authority.authority_id
        or value.get("key_id") != authority.key_id
    ):
        raise TraceabilityError("external attestation authority is not the configured authority")
    for field, expected in {
        "requirements_source_sha256": context.requirements_source_sha256,
        "git_commit": context.git_commit,
        "git_tree": context.git_tree,
        "mapping_sha256": context.mapping_sha256,
        "traceability_content_sha256": context.traceability_content_sha256,
        "purpose": context.purpose,
        "audience": context.audience,
        "challenge_nonce": context.challenge_nonce,
    }.items():
        if value.get(field) != expected:
            raise TraceabilityError(f"external attestation {field} binding does not match")
    sequence = value.get("sequence")
    if type(sequence) is not int or sequence <= 0:
        raise TraceabilityError("external attestation sequence is not a positive integer")
    attestation_id = value.get("attestation_id")
    if not isinstance(attestation_id, str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        attestation_id,
    ):
        raise TraceabilityError("external attestation ID is not a canonical UUID")
    if now.tzinfo is None or now.utcoffset() is None:
        raise TraceabilityError("attestation verification time must be timezone-aware")
    now_utc = now.astimezone(UTC)
    issued_at = _canonical_time(value.get("issued_at"), label="issued_at")
    expires_at = _canonical_time(value.get("expires_at"), label="expires_at")
    if issued_at > now_utc + authority.future_skew:
        raise TraceabilityError("external attestation is issued too far in the future")
    if issued_at < now_utc - authority.maximum_age:
        raise TraceabilityError("external attestation is stale")
    if expires_at <= now_utc:
        raise TraceabilityError("external attestation is expired")
    if expires_at <= issued_at or expires_at - issued_at > authority.maximum_validity:
        raise TraceabilityError("external attestation validity interval is invalid")

    requirement_ids = _unique_sorted_strings(
        value.get("requirement_ids"),
        label="external attestation requirement_ids",
        maximum=EXPECTED_REQUIREMENT_COUNT,
        allow_empty=False,
    )
    if not set(requirement_ids) <= authority.allowed_requirement_ids:
        raise TraceabilityError("external attestation exceeds the configured authority scope")
    if not set(requirement_ids) <= set(context.artifacts_by_requirement):
        raise TraceabilityError("external attestation names an unmapped requirement")
    findings = value.get("findings")
    if not isinstance(findings, list) or len(findings) != len(requirement_ids):
        raise TraceabilityError("external attestation findings do not match its exact scope")
    found_ids: list[str] = []
    dispositions: dict[str, str] = {}
    for index, finding_raw in enumerate(findings):
        if not isinstance(finding_raw, dict):
            raise TraceabilityError(f"external attestation finding {index} must be an object")
        _exact_fields(finding_raw, _FINDING_FIELDS, label=f"attestation finding {index}")
        requirement_id = _required_text(
            finding_raw,
            "requirement_id",
            label=f"attestation finding {index}",
        )
        found_ids.append(requirement_id)
        disposition = _required_text(finding_raw, "disposition", label=requirement_id)
        if disposition not in _ATTESTATION_DISPOSITIONS:
            raise TraceabilityError(
                f"external attestation disposition is invalid: {requirement_id}"
            )
        _required_text(finding_raw, "statement", label=requirement_id)
        artifacts_raw = finding_raw.get("artifact_bindings")
        if not isinstance(artifacts_raw, list):
            raise TraceabilityError(f"external attestation artifacts are invalid: {requirement_id}")
        normalized: list[dict[str, str]] = []
        for artifact_raw in artifacts_raw:
            if not isinstance(artifact_raw, dict):
                raise TraceabilityError(
                    f"external attestation artifact is not an object: {requirement_id}"
                )
            _exact_fields(
                artifact_raw,
                _ATTESTED_ARTIFACT_FIELDS,
                label=f"attested artifact for {requirement_id}",
            )
            path = _required_text(artifact_raw, "path", label=requirement_id)
            digest = _required_text(artifact_raw, "sha256", label=requirement_id)
            blob = _required_text(artifact_raw, "git_blob", label=requirement_id)
            if not SHA256_RE.fullmatch(digest) or not GIT_OBJECT_RE.fullmatch(blob):
                raise TraceabilityError(
                    f"external attestation artifact digest is invalid: {requirement_id}"
                )
            normalized.append({"path": path, "sha256": digest, "git_blob": blob})
        expected_artifacts = [
            item.as_dict() for item in context.artifacts_by_requirement[requirement_id]
        ]
        if normalized != expected_artifacts:
            raise TraceabilityError(
                f"external attestation artifact binding does not match exactly: {requirement_id}"
            )
        dispositions[requirement_id] = disposition
    if tuple(found_ids) != requirement_ids:
        raise TraceabilityError(
            "external attestation findings must be unique and ordered like requirement_ids"
        )

    signature = _canonical_signature(value.get("signature"))
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    try:
        authority.public_key.verify(signature, attestation_signing_bytes(unsigned))
    except InvalidSignature as exc:
        raise TraceabilityError("external attestation signature is invalid") from exc
    return {
        "attestation_id": attestation_id,
        "authority_id": authority.authority_id,
        "key_id": authority.key_id,
        "issued_at": cast(str, value["issued_at"]),
        "expires_at": cast(str, value["expires_at"]),
        "purpose": context.purpose,
        "audience": context.audience,
        "challenge_nonce": context.challenge_nonce,
        "sequence": sequence,
        "requirement_ids": list(requirement_ids),
        "dispositions": cast(dict[str, JsonValue], dispositions),
        "attestation_content_sha256": sha256_json(unsigned),
        "signature_and_bindings_verified": True,
        "replay_safe_ingestion_completed": False,
        "automatic_requirement_acceptance": False,
        "independent_validation_established": False,
    }


def _private_state_parent(state_path: Path) -> Path:
    if (
        not state_path.is_absolute()
        or ".." in state_path.parts
        or state_path.name != "attestation-replay-state.json"
    ):
        raise TraceabilityError(
            "attestation replay-state path must be absolute and use the fixed filename"
        )
    parent = state_path.parent
    try:
        metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise TraceabilityError("attestation replay-state directory is unavailable") from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or resolved != parent
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise TraceabilityError(
            "attestation replay-state directory must be private, owned, and non-symlinked"
        )
    return parent


def _open_private_lock(parent_fd: int) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            "attestation-replay-state.lock",
            flags,
            0o600,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise TraceabilityError("attestation replay-state lock cannot be opened safely") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        os.close(descriptor)
        raise TraceabilityError("attestation replay-state lock is not a private owned file")
    return descriptor


def _initial_replay_state() -> dict[str, Any]:
    state: dict[str, Any] = {"schema": ATTESTATION_REPLAY_SCHEMA, "authorities": {}}
    state["integrity"] = {"canonical_payload_sha256": sha256_json(state)}
    return state


def _validate_replay_state(value: Mapping[str, Any]) -> None:
    if set(value) != {"schema", "authorities", "integrity"}:
        raise TraceabilityError("attestation replay-state fields are not exact")
    if value.get("schema") != ATTESTATION_REPLAY_SCHEMA:
        raise TraceabilityError("attestation replay-state schema is unsupported")
    authorities = value.get("authorities")
    if not isinstance(authorities, dict) or len(authorities) > 128:
        raise TraceabilityError("attestation replay-state authority catalog is invalid")
    for key_id, entry in authorities.items():
        if (
            not isinstance(key_id, str)
            or not isinstance(entry, dict)
            or set(entry) != {
                "authority_id",
                "key_id",
                "highest_sequence",
                "consumed",
            }
            or entry.get("key_id") != key_id
            or not isinstance(entry.get("authority_id"), str)
            or type(entry.get("highest_sequence")) is not int
            or entry["highest_sequence"] < 0
        ):
            raise TraceabilityError("attestation replay-state authority entry is invalid")
        consumed = entry.get("consumed")
        if not isinstance(consumed, list) or len(consumed) > 10_000:
            raise TraceabilityError("attestation replay-state consumption log is invalid")
        ids: list[str] = []
        digests: list[str] = []
        nonces: list[str] = []
        sequences: list[int] = []
        for item in consumed:
            if not isinstance(item, dict) or set(item) != {
                "attestation_id",
                "content_sha256",
                "challenge_nonce",
                "sequence",
            }:
                raise TraceabilityError("attestation replay-state consumed entry is invalid")
            attestation_id = item.get("attestation_id")
            digest = item.get("content_sha256")
            nonce = item.get("challenge_nonce")
            sequence = item.get("sequence")
            if (
                not isinstance(attestation_id, str)
                or not isinstance(digest, str)
                or not SHA256_RE.fullmatch(digest)
                or not isinstance(nonce, str)
                or type(sequence) is not int
                or sequence <= 0
            ):
                raise TraceabilityError("attestation replay-state consumed value is invalid")
            ids.append(attestation_id)
            digests.append(digest)
            nonces.append(nonce)
            sequences.append(sequence)
        if (
            len(ids) != len(set(ids))
            or len(digests) != len(set(digests))
            or len(nonces) != len(set(nonces))
            or sequences != sorted(sequences)
            or len(sequences) != len(set(sequences))
            or (sequences and entry["highest_sequence"] != sequences[-1])
            or (not sequences and entry["highest_sequence"] != 0)
        ):
            raise TraceabilityError("attestation replay-state monotonic history is inconsistent")
    integrity = value.get("integrity")
    unsigned = dict(value)
    unsigned.pop("integrity", None)
    if (
        not isinstance(integrity, dict)
        or set(integrity) != {"canonical_payload_sha256"}
        or integrity.get("canonical_payload_sha256") != sha256_json(unsigned)
    ):
        raise TraceabilityError("attestation replay-state integrity is invalid")


def _read_replay_state(parent_fd: int) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            "attestation-replay-state.json",
            flags,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return _initial_replay_state()
    except OSError as exc:
        raise TraceabilityError("attestation replay-state cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > MAX_JSON_BYTES
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise TraceabilityError("attestation replay-state file is unsafe")
        material = bytearray()
        while len(material) <= MAX_JSON_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_JSON_BYTES + 1 - len(material)),
            )
            if not chunk:
                break
            material.extend(chunk)
        if len(material) != metadata.st_size or len(material) > MAX_JSON_BYTES:
            raise TraceabilityError("attestation replay-state changed while reading")
    finally:
        os.close(descriptor)
    state = load_strict_json_bytes(bytes(material), label="attestation replay-state")
    _validate_replay_state(state)
    return state


def _write_replay_state(parent_fd: int, state: Mapping[str, Any]) -> None:
    _validate_replay_state(state)
    material = json.dumps(
        state,
        allow_nan=False,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(material) > MAX_JSON_BYTES:
        raise TraceabilityError("attestation replay-state exceeds its size limit")
    temporary_name = f".attestation-replay-state.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(material):
            offset += os.write(descriptor, material[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            "attestation-replay-state.json",
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    except OSError as exc:
        raise TraceabilityError("attestation replay-state cannot be committed atomically") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass


def ingest_external_attestation(
    material: bytes,
    *,
    authority: TrustedAttestationAuthority,
    context: AttestationContext,
    now: datetime,
    state_path: Path,
) -> dict[str, JsonValue]:
    """Verify and atomically consume an attestation challenge and sequence once."""

    verified = verify_external_attestation_stateless(
        material,
        authority=authority,
        context=context,
        now=now,
    )
    parent = _private_state_parent(state_path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(parent, directory_flags)
    expected_parent = parent.lstat()
    opened_parent = os.fstat(parent_fd)
    if (
        opened_parent.st_dev != expected_parent.st_dev
        or opened_parent.st_ino != expected_parent.st_ino
        or stat.S_IMODE(opened_parent.st_mode) != 0o700
        or (hasattr(os, "getuid") and opened_parent.st_uid != os.getuid())
    ):
        os.close(parent_fd)
        raise TraceabilityError("attestation replay-state directory changed while opening")
    try:
        lock_fd = _open_private_lock(parent_fd)
    except Exception:
        os.close(parent_fd)
        raise
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = _read_replay_state(parent_fd)
        authorities = cast(dict[str, Any], state["authorities"])
        entry = authorities.get(authority.key_id)
        if entry is None:
            entry = {
                "authority_id": authority.authority_id,
                "key_id": authority.key_id,
                "highest_sequence": 0,
                "consumed": [],
            }
            authorities[authority.key_id] = entry
        if not isinstance(entry, dict) or entry.get("authority_id") != authority.authority_id:
            raise TraceabilityError("attestation replay-state authority conflicts")
        consumed = cast(list[dict[str, Any]], entry["consumed"])
        attestation_id = cast(str, verified["attestation_id"])
        content_digest = cast(str, verified["attestation_content_sha256"])
        challenge_nonce = cast(str, verified["challenge_nonce"])
        sequence = cast(int, verified["sequence"])
        if any(item["attestation_id"] == attestation_id for item in consumed):
            raise TraceabilityError("external attestation ID was already consumed")
        if any(item["content_sha256"] == content_digest for item in consumed):
            raise TraceabilityError("external attestation content was already consumed")
        if any(item["challenge_nonce"] == challenge_nonce for item in consumed):
            raise TraceabilityError("external attestation challenge was already consumed")
        if sequence <= cast(int, entry["highest_sequence"]):
            raise TraceabilityError("external attestation sequence is not monotonic")
        if len(consumed) >= 10_000:
            raise TraceabilityError("attestation replay-state capacity is exhausted")
        consumed.append(
            {
                "attestation_id": attestation_id,
                "content_sha256": content_digest,
                "challenge_nonce": challenge_nonce,
                "sequence": sequence,
            }
        )
        entry["highest_sequence"] = sequence
        state.pop("integrity", None)
        state["integrity"] = {"canonical_payload_sha256": sha256_json(state)}
        _write_replay_state(parent_fd, state)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        os.close(parent_fd)
    result = dict(verified)
    result["replay_safe_ingestion_completed"] = True
    result["automatic_requirement_acceptance"] = False
    result["independent_validation_established"] = False
    return result
