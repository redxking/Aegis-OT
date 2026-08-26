"""Fail-closed repository and dependency policy checks for release candidates.

These checks are intentionally bounded.  They validate tracked declarations,
immutable workflow references, high-confidence secret material, YAML syntax,
OCI digest pins, installed-version equality, and package-reported license
metadata.  They do not replace a vulnerability feed, legal review, independent
security assessment, release approval, or artifact custody.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tomllib
from collections.abc import Callable
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Protocol

import yaml  # type: ignore[import-untyped]

POLICY_SCHEMA_VERSION = "aegis-ot-release-security-policy-v1"
REPORT_SCHEMA_VERSION = "aegis-ot-release-security-report-v1"
POLICY_PATH = PurePosixPath("config/release-security-policy.json")

_EXTERNAL_ACTION = re.compile(
    r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_./-]+)@([^\s#]+)$"
)
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HASH_OPTION = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")
_LOCK_PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([A-Za-z0-9_,.-]+)\])?"
    r"==([A-Za-z0-9][A-Za-z0-9.!+_-]*)$"
)
_DECLARED_DEPENDENCY = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[([A-Za-z0-9_,.-]+)\])?"
    r"(?:\s*(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9][A-Za-z0-9.!+*_-]*"
    r"(?:\s*,\s*(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9][A-Za-z0-9.!+*_-]*)*"
    r")?$"
)
_IMAGE_DIGEST = re.compile(r"^[^\s@]+(?::[^\s@]+)?@sha256:[0-9a-f]{64}$")
_IMAGE_ARGUMENT = re.compile(
    r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*_IMAGE)=([^\s#]+)\s*(?:#.*)?$",
    re.IGNORECASE,
)
_FROM = re.compile(r"^\s*FROM\s+(.+?)\s*(?:#.*)?$", re.IGNORECASE)
_VARIABLE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_VARIABLE_DEFAULT = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*):-([^{}]+)\}$")
_PEM_PRIVATE_KEY = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]+"
    rb"[A-Za-z0-9+/=]{32,}"
)
_TOKEN_PATTERNS = (
    re.compile(rb"gh[pousr]_[A-Za-z0-9_]{30,}"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
)
_MAX_TRACKED_FILE_BYTES = 64 * 1024 * 1024
_GIT_EXECUTABLE = Path("/usr/bin/git")
_REQUIRED_CI_STEPS: dict[tuple[str, str], tuple[str, tuple[str, ...]]] = {
    ("test", "Enforce branch coverage floor"): (
        "run",
        ("pytest", "--cov=aegis_ot", "--cov-branch", "--cov-fail-under=90"),
    ),
    ("release-security", "Install exact declared environment"): (
        "run",
        (
            "pip install --constraint requirements.lock --requirement requirements.lock",
            "pip install --no-deps --no-build-isolation --editable .",
        ),
    ),
    ("release-security", "Repository security policy"): (
        "run",
        ("python scripts/check_release_security.py",),
    ),
    ("release-security", "Installed dependency license policy"): (
        "run",
        ("python scripts/check_release_security.py --installed-licenses",),
    ),
    ("release-security", "Verify signed M7 provenance"): (
        "run",
        (
            "scripts/build_m7_replication_bundle.py build",
            "scripts/build_m7_replication_bundle.py verify",
            "--trusted-public-key",
            "--require-signature",
        ),
    ),
    ("release-security", "Install hash-locked vulnerability scanner"): (
        "run",
        ("pip install", "--require-hashes", "security/requirements.lock"),
    ),
    ("release-security", "Python dependency vulnerability audit"): (
        "run",
        ("aegis-security-tools/bin/pip-audit", "--requirement requirements.lock"),
    ),
    ("release-security", "Secret and configuration scan"): (
        "uses",
        ("aquasecurity/trivy-action@",),
    ),
    ("release-security", "Build exact-declaration container"): (
        "run",
        ("docker build", "AEGIS_SOURCE_REVISION", 'aegis-ot-ci:$GITHUB_SHA'),
    ),
    ("release-security", "Container vulnerability scan"): (
        "uses",
        ("aquasecurity/trivy-action@",),
    ),
    ("codeql", "Initialize CodeQL static analysis"): (
        "uses",
        ("github/codeql-action/init@",),
    ),
    ("codeql", "Complete CodeQL static analysis"): (
        "uses",
        ("github/codeql-action/analyze@",),
    ),
}
_REQUIRED_CI_WITH: dict[tuple[str, str], dict[str, object]] = {
    ("release-security", "Secret and configuration scan"): {
        "scan-type": "fs",
        "scan-ref": ".",
        "scanners": "secret,misconfig",
        "severity": "HIGH,CRITICAL",
        "exit-code": "1",
        "cache": "false",
        "version": "v0.70.0",
        "skip-setup-trivy": "false",
    },
    ("release-security", "Container vulnerability scan"): {
        "scan-type": "image",
        "image-ref": "aegis-ot-ci:${{ github.sha }}",
        "scanners": "vuln,secret,misconfig",
        "vuln-type": "os,library",
        "severity": "CRITICAL",
        "ignore-unfixed": "true",
        "exit-code": "1",
        "cache": "false",
        "version": "v0.70.0",
        "skip-setup-trivy": "true",
    },
    ("codeql", "Initialize CodeQL static analysis"): {
        "languages": "python",
        "build-mode": "none",
    },
}
_EXPECTED_CI_JOBS = frozenset({"test", "formal", "release-security", "codeql"})
_EXPECTED_CI_JOB_KEYS = {
    "test": frozenset({"runs-on", "strategy", "steps"}),
    "formal": frozenset({"runs-on", "steps"}),
    "release-security": frozenset({"runs-on", "steps"}),
    "codeql": frozenset({"runs-on", "permissions", "steps"}),
}


class ReleaseSecurityError(RuntimeError):
    """A release-security invariant was not satisfied."""


class DistributionLike(Protocol):
    @property
    def version(self) -> str: ...

    @property
    def metadata(self) -> Any: ...


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


class _WorkflowLoader(_UniqueKeyLoader):
    def compose_node(self, parent: object, index: object) -> yaml.nodes.Node:
        event = self.peek_event()
        if isinstance(event, yaml.events.AliasEvent) or getattr(event, "anchor", None):
            raise ReleaseSecurityError("security-scoped YAML anchors and aliases are forbidden")
        return super().compose_node(parent, index)


# GitHub Actions follows YAML 1.2 boolean spelling.  PyYAML's default YAML 1.1
# resolver would otherwise turn the workflow key `on` into the boolean True.
_UniqueKeyLoader.yaml_implicit_resolvers = {
    key: [
        (tag, pattern)
        for tag, pattern in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_UniqueKeyLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    explicit: set[object] = set()
    for key_node, _value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            if isinstance(loader, _WorkflowLoader):
                raise ReleaseSecurityError("security-scoped YAML merge keys are forbidden")
            continue
        key = loader.construct_object(key_node, deep=deep)
        if key in explicit:
            raise ReleaseSecurityError(f"YAML contains duplicate key: {key!r}")
        explicit.add(key)
    loader.flatten_mapping(node)
    return dict(loader.construct_pairs(node, deep=deep))


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _reject_constant(value: str) -> NoReturn:
    raise ReleaseSecurityError(f"policy contains a non-finite number: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseSecurityError(f"policy contains duplicate key: {key}")
        result[key] = value
    return result


def _load_policy(root: Path) -> dict[str, Any]:
    path = root.joinpath(*POLICY_PATH.parts)
    try:
        material = path.read_bytes()
    except OSError as exc:
        raise ReleaseSecurityError(f"release security policy is unavailable: {path}") from exc
    try:
        parsed = json.loads(
            material.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseSecurityError("release security policy is not strict JSON") from exc
    if not isinstance(parsed, dict) or parsed.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise ReleaseSecurityError("release security policy schema is unsupported")
    return parsed


def _validated_git_context(root: Path) -> tuple[Path, Path]:
    git = _GIT_EXECUTABLE
    git_directory = root / ".git"
    try:
        root_metadata = root.stat()
        git_metadata = git.stat()
        git_directory_metadata = git_directory.stat()
    except OSError as exc:
        raise ReleaseSecurityError("pinned Git or repository metadata is unavailable") from exc
    if (
        git.is_symlink()
        or not stat.S_ISREG(git_metadata.st_mode)
        or git_metadata.st_uid != 0
        or git_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not os.access(git, os.X_OK)
    ):
        raise ReleaseSecurityError("pinned Git executable is not a trusted root-owned binary")
    if (
        git_directory.is_symlink()
        or not stat.S_ISDIR(git_directory_metadata.st_mode)
        or git_directory_metadata.st_uid != root_metadata.st_uid
        or git_directory_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ReleaseSecurityError("repository .git directory is not an owned private directory")
    return git, git_directory


def _run_git(root: Path, *arguments: str) -> bytes:
    git, git_directory = _validated_git_context(root)
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable and closed arguments
            (
                str(git),
                "--no-replace-objects",
                "--git-dir",
                str(git_directory),
                "--work-tree",
                str(root),
                *arguments,
            ),
            cwd=root,
            check=False,
            capture_output=True,
            env=environment,
        )
    except OSError as exc:
        raise ReleaseSecurityError("Git could not enumerate the source declarations") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseSecurityError(f"Git declaration query failed: {detail[-1000:]}")
    return completed.stdout


def _tracked_files(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for raw_path in _run_git(root, "ls-files", "-z").split(b"\0"):
        if not raw_path:
            continue
        try:
            path_text = raw_path.decode("utf-8")
        except UnicodeError as exc:
            raise ReleaseSecurityError("tracked path is not UTF-8") from exc
        path = PurePosixPath(path_text)
        if path.is_absolute() or any(part in {"", ".", "..", ".git"} for part in path.parts):
            raise ReleaseSecurityError(f"tracked path is unsafe: {path_text!r}")
        disk_path = root.joinpath(*path.parts)
        if disk_path.is_symlink() or not disk_path.is_file():
            raise ReleaseSecurityError(f"tracked declaration is not a regular file: {path_text}")
        try:
            size = disk_path.stat().st_size
            if size > _MAX_TRACKED_FILE_BYTES:
                continue
            result[path_text] = disk_path.read_bytes()
        except OSError as exc:
            raise ReleaseSecurityError(f"tracked file could not be read: {path_text}") from exc
    if not result:
        raise ReleaseSecurityError("repository contains no tracked files")
    return result


def _strict_text(files: dict[str, bytes], path: str) -> str:
    material = files.get(path)
    if material is None:
        raise ReleaseSecurityError(f"required tracked declaration is missing: {path}")
    try:
        return material.decode("utf-8")
    except UnicodeError as exc:
        raise ReleaseSecurityError(f"tracked declaration is not UTF-8: {path}") from exc


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _lock_pins(lock_text: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line_number, raw in enumerate(lock_text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _LOCK_PIN.fullmatch(line)
        if match is None:
            raise ReleaseSecurityError(
                f"requirements.lock line {line_number} is not an exact version pin"
            )
        name, extras, version = match.groups()
        if extras:
            raise ReleaseSecurityError(
                f"requirements.lock line {line_number} must pin a distribution, not extras"
            )
        normalized = _normalized_name(name)
        if normalized in pins:
            raise ReleaseSecurityError(f"requirements.lock duplicates {normalized}")
        pins[normalized] = version
    if not pins:
        raise ReleaseSecurityError("requirements.lock contains no exact pins")
    return pins


def _declared_dependencies(pyproject: dict[str, Any]) -> set[str]:
    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise ReleaseSecurityError("pyproject.toml lacks project metadata")
    raw_groups: list[object] = []
    dependencies = project.get("dependencies")
    if not isinstance(dependencies, list):
        raise ReleaseSecurityError("pyproject.toml dependencies are malformed")
    raw_groups.extend(dependencies)
    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict):
        raise ReleaseSecurityError("pyproject.toml optional dependencies are malformed")
    for group, values in optional.items():
        if not isinstance(group, str) or not isinstance(values, list):
            raise ReleaseSecurityError("pyproject.toml optional dependency group is malformed")
        raw_groups.extend(values)
    names: set[str] = set()
    for declaration in raw_groups:
        if not isinstance(declaration, str):
            raise ReleaseSecurityError("pyproject.toml dependency is not a string")
        match = _DECLARED_DEPENDENCY.fullmatch(declaration)
        if match is None:
            raise ReleaseSecurityError(
                "dependency declaration is malformed or uses a URL, VCS, path, "
                f"or environment marker: {declaration!r}"
            )
        names.add(_normalized_name(match.group(1)))
    return names


def _check_build_system(pyproject: dict[str, Any], policy: dict[str, Any]) -> tuple[str, str]:
    observed = pyproject.get("build-system")
    expected = policy.get("build_system")
    if not isinstance(observed, dict) or not isinstance(expected, dict):
        raise ReleaseSecurityError("build-system release policy is malformed")
    expected_backend = expected.get("build_backend")
    expected_requires = expected.get("requires")
    if (
        not isinstance(expected_backend, str)
        or not expected_backend
        or not isinstance(expected_requires, list)
        or len(expected_requires) != 1
        or not isinstance(expected_requires[0], str)
    ):
        raise ReleaseSecurityError("build-system release policy is malformed")
    closed = {
        "build-backend": expected_backend,
        "requires": expected_requires,
    }
    if observed != closed:
        raise ReleaseSecurityError(
            "pyproject.toml build-system differs from the closed release contract"
        )
    match = _LOCK_PIN.fullmatch(expected_requires[0])
    if match is None or match.group(2) is not None:
        raise ReleaseSecurityError("approved build-system requirement is not an exact pin")
    return _normalized_name(match.group(1)), match.group(3)


def _check_project_and_lock(files: dict[str, bytes], policy: dict[str, Any]) -> int:
    try:
        pyproject = tomllib.loads(_strict_text(files, "pyproject.toml"))
    except tomllib.TOMLDecodeError as exc:
        raise ReleaseSecurityError("pyproject.toml is invalid") from exc
    project = pyproject.get("project")
    expected = policy.get("project")
    if not isinstance(project, dict) or not isinstance(expected, dict):
        raise ReleaseSecurityError("project release policy is malformed")
    license_value = project.get("license")
    observed_license = license_value.get("text") if isinstance(license_value, dict) else None
    authors = project.get("authors")
    if observed_license != expected.get("license"):
        raise ReleaseSecurityError("project license does not match release policy")
    if authors != [{"name": expected.get("author")}]:
        raise ReleaseSecurityError("project authorship does not match release policy")
    pins = _lock_pins(_strict_text(files, "requirements.lock"))
    build_name, build_version = _check_build_system(pyproject, policy)
    if pins.get(build_name) != build_version:
        raise ReleaseSecurityError(
            "approved build-system requirement is absent from requirements.lock"
        )
    missing = sorted(_declared_dependencies(pyproject) - pins.keys())
    if missing:
        raise ReleaseSecurityError(
            "direct dependencies are absent from requirements.lock: " + ", ".join(missing)
        )
    return len(pins)


def _logical_requirements(lock_text: str) -> list[list[str]]:
    logical: list[list[str]] = []
    pending: list[str] = []
    for raw in lock_text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        token = stripped[:-1].strip() if continued else stripped
        if token:
            pending.append(token)
        if continued:
            continue
        logical.append(pending)
        pending = []
    if pending:
        raise ReleaseSecurityError("security tool lock has an unterminated continuation")
    return logical


def _check_hashed_security_tools(files: dict[str, bytes], policy: dict[str, Any]) -> int:
    tooling = policy.get("security_tools")
    if not isinstance(tooling, dict):
        raise ReleaseSecurityError("security tool policy is malformed")
    input_path = tooling.get("input_path")
    lock_path = tooling.get("lock_path")
    version = tooling.get("pip_audit_version")
    if not isinstance(input_path, str) or not input_path:
        raise ReleaseSecurityError("security tool policy paths or version are malformed")
    if not isinstance(lock_path, str) or not lock_path:
        raise ReleaseSecurityError("security tool policy paths or version are malformed")
    if not isinstance(version, str) or not version:
        raise ReleaseSecurityError("security tool policy paths or version are malformed")
    input_pins = _lock_pins(_strict_text(files, input_path))
    if input_pins != {"pip-audit": version}:
        raise ReleaseSecurityError(
            "security tool input must contain only the approved pip-audit pin"
        )
    locked: dict[str, str] = {}
    hashes: set[str] = set()
    for tokens in _logical_requirements(_strict_text(files, lock_path)):
        if not tokens:
            continue
        match = _LOCK_PIN.fullmatch(tokens[0])
        if match is None or match.group(2) is not None:
            raise ReleaseSecurityError("security tool lock contains a non-exact requirement")
        name = _normalized_name(match.group(1))
        if name in locked:
            raise ReleaseSecurityError(f"security tool lock duplicates {name}")
        if len(tokens) < 2:
            raise ReleaseSecurityError(f"security tool lock lacks artifact hashes: {name}")
        for option in tokens[1:]:
            hash_match = _HASH_OPTION.fullmatch(option)
            if hash_match is None:
                raise ReleaseSecurityError(
                    f"security tool lock contains an unsupported option: {option}"
                )
            digest = hash_match.group(1)
            if digest in hashes:
                raise ReleaseSecurityError("security tool lock repeats an artifact hash")
            hashes.add(digest)
        locked[name] = match.group(3)
    if locked.get("pip-audit") != version:
        raise ReleaseSecurityError(
            "security tool lock does not bind the approved pip-audit version"
        )
    if len(locked) < 2:
        raise ReleaseSecurityError("security tool lock does not include transitive dependencies")
    return len(locked)


def _load_yaml_documents(
    material: bytes,
    *,
    path: str,
    workflow_security: bool = False,
) -> list[object]:
    try:
        text = material.decode("utf-8")
    except UnicodeError as exc:
        raise ReleaseSecurityError(f"YAML declaration is not UTF-8: {path}") from exc
    try:
        loader = _WorkflowLoader if workflow_security else _UniqueKeyLoader
        return list(yaml.load_all(text, Loader=loader))
    except ReleaseSecurityError:
        raise
    except yaml.YAMLError as exc:
        raise ReleaseSecurityError(f"YAML declaration is invalid: {path}: {exc}") from exc


def _workflow_uses(value: object, *, path: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "uses":
                if not isinstance(child, str) or not child:
                    raise ReleaseSecurityError(
                        f"workflow action reference is not a string: {path}"
                    )
                found.append(child)
            found.extend(_workflow_uses(child, path=path))
    elif isinstance(value, list):
        for child in value:
            found.extend(_workflow_uses(child, path=path))
    return found


def _required_step_identifiers() -> list[str]:
    return [f"{job}:{name}" for job, name in _REQUIRED_CI_STEPS]


def _workflow_semantic_sha256(workflow: dict[object, object]) -> str:
    try:
        canonical = json.dumps(
            workflow,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReleaseSecurityError("CI workflow cannot be canonically serialized") from exc
    return hashlib.sha256(canonical).hexdigest()


def _validate_ci_contract(files: dict[str, bytes], workflow_policy: dict[str, Any]) -> None:
    configured = workflow_policy.get("required_steps")
    if configured != _required_step_identifiers():
        raise ReleaseSecurityError("required CI step policy is incomplete or reordered")
    path = ".github/workflows/ci.yml"
    documents = _load_yaml_documents(
        files.get(path, b""), path=path, workflow_security=True
    )
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise ReleaseSecurityError("CI workflow must contain one mapping document")
    workflow = documents[0]
    if set(workflow) != {"name", "on", "permissions", "jobs"} or workflow.get("name") != "ci":
        raise ReleaseSecurityError("CI top-level structure differs from the closed contract")
    if workflow.get("permissions") != {"contents": "read"}:
        raise ReleaseSecurityError("CI top-level permissions differ from the closed contract")
    triggers = workflow.get("on")
    if triggers != {"push": None, "pull_request": None}:
        raise ReleaseSecurityError("CI triggers differ from push and pull_request contract")
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != _EXPECTED_CI_JOBS:
        raise ReleaseSecurityError("CI jobs differ from the closed contract")
    indexed_steps: dict[tuple[str, str], dict[object, object]] = {}
    for job_name, raw_job in jobs.items():
        if not isinstance(job_name, str) or not isinstance(raw_job, dict):
            raise ReleaseSecurityError("CI job declaration is malformed")
        if set(raw_job) != _EXPECTED_CI_JOB_KEYS[job_name]:
            raise ReleaseSecurityError(
                f"CI job fields differ from the closed contract: {job_name}"
            )
        if raw_job.get("runs-on") != "ubuntu-24.04":
            raise ReleaseSecurityError(f"CI runner differs from the closed contract: {job_name}")
        permissions = raw_job.get("permissions")
        expected_permissions = (
            {"contents": "read", "security-events": "write"}
            if job_name == "codeql"
            else None
        )
        if permissions != expected_permissions:
            raise ReleaseSecurityError(
                f"CI job permissions differ from the closed contract: {job_name}"
            )
        if job_name == "test" and raw_job.get("strategy") != {
            "fail-fast": False,
            "matrix": {"python-version": ["3.11", "3.12", "3.13", "3.14"]},
        }:
            raise ReleaseSecurityError("CI test matrix differs from the closed contract")
        steps = raw_job.get("steps")
        if not isinstance(steps, list):
            raise ReleaseSecurityError(f"CI job steps are malformed: {job_name}")
        names: set[str] = set()
        for raw_step in steps:
            if not isinstance(raw_step, dict):
                raise ReleaseSecurityError(f"CI step is malformed: {job_name}")
            name = raw_step.get("name")
            if not isinstance(name, str) or not name:
                raise ReleaseSecurityError(f"CI step lacks an exact name: {job_name}")
            if name in names:
                raise ReleaseSecurityError(f"CI step name is duplicated: {job_name}:{name}")
            has_run = "run" in raw_step
            has_uses = "uses" in raw_step
            if has_run == has_uses:
                raise ReleaseSecurityError(
                    f"CI step must contain exactly one of run or uses: {job_name}:{name}"
                )
            allowed_step_keys = {"name", "run" if has_run else "uses"}
            if "with" in raw_step:
                allowed_step_keys.add("with")
            if set(raw_step) != allowed_step_keys:
                raise ReleaseSecurityError(
                    f"CI step fields differ from the closed contract: {job_name}:{name}"
                )
            names.add(name)
            indexed_steps[(job_name, name)] = raw_step
    for identifier, (field, fragments) in _REQUIRED_CI_STEPS.items():
        step = indexed_steps.get(identifier)
        if step is None:
            raise ReleaseSecurityError(
                f"required CI step is absent: {identifier[0]}:{identifier[1]}"
            )
        scalar = step.get(field)
        if not isinstance(scalar, str) or any(fragment not in scalar for fragment in fragments):
            raise ReleaseSecurityError(
                f"required CI step differs from its contract: {identifier[0]}:{identifier[1]}"
            )
        expected_with = _REQUIRED_CI_WITH.get(identifier)
        if expected_with is not None:
            observed_with = step.get("with")
            if observed_with != expected_with:
                raise ReleaseSecurityError(
                    f"required CI step inputs differ: {identifier[0]}:{identifier[1]}"
                )
    expected_digest = workflow_policy.get("semantic_sha256")
    if not isinstance(expected_digest, str) or _SHA256.fullmatch(expected_digest) is None:
        raise ReleaseSecurityError("CI workflow semantic digest policy is malformed")
    if _workflow_semantic_sha256(workflow) != expected_digest:
        raise ReleaseSecurityError("CI workflow semantics differ from the approved digest")


def _check_action_pins(files: dict[str, bytes], policy: dict[str, Any]) -> int:
    workflow_policy = policy.get("workflow")
    if not isinstance(workflow_policy, dict):
        raise ReleaseSecurityError("workflow release policy is malformed")
    owners = workflow_policy.get("allowed_action_owners")
    if (
        not isinstance(owners, list)
        or not owners
        or not all(isinstance(item, str) for item in owners)
    ):
        raise ReleaseSecurityError("allowed action owners policy is malformed")
    allowed = set(owners)
    approved_actions = workflow_policy.get("approved_external_actions")
    if (
        not isinstance(approved_actions, dict)
        or not approved_actions
        or not all(
            isinstance(identity, str)
            and isinstance(revision, str)
            and _FULL_SHA.fullmatch(revision) is not None
            for identity, revision in approved_actions.items()
        )
    ):
        raise ReleaseSecurityError("approved external action policy is malformed")
    count = 0
    for path, material in files.items():
        if not path.startswith(".github/workflows/") or not path.endswith((".yml", ".yaml")):
            continue
        for document in _load_yaml_documents(
            material, path=path, workflow_security=True
        ):
            for scalar in _workflow_uses(document, path=path):
                if scalar.startswith("./"):
                    local = PurePosixPath(scalar[2:])
                    if (
                        not local.parts
                        or any(part in {"", ".", "..", ".git"} for part in local.parts)
                        or not any(
                            local.joinpath(name).as_posix() in files
                            for name in ("action.yml", "action.yaml")
                        )
                    ):
                        raise ReleaseSecurityError(
                            f"local workflow action is not a tracked closed path: {scalar}"
                        )
                    continue
                match = _EXTERNAL_ACTION.fullmatch(scalar)
                if match is None:
                    raise ReleaseSecurityError(
                        f"workflow action reference is malformed: {scalar}"
                    )
                owner, repository, reference = match.groups()
                count += 1
                if owner not in allowed:
                    raise ReleaseSecurityError(
                        f"workflow action owner is not approved: {owner}/{repository}"
                    )
                if _FULL_SHA.fullmatch(reference) is None:
                    raise ReleaseSecurityError(
                        f"workflow action is not pinned to a full commit SHA: "
                        f"{owner}/{repository}@{reference}"
                    )
                identity = f"{owner}/{repository}"
                if approved_actions.get(identity) != reference:
                    raise ReleaseSecurityError(
                        f"workflow action revision is not approved: {identity}@{reference}"
                    )
    if count == 0:
        raise ReleaseSecurityError("no external workflow actions were found")
    _validate_ci_contract(files, workflow_policy)
    return count


def _check_yaml(files: dict[str, bytes]) -> int:
    count = 0
    for path, material in files.items():
        if not path.endswith((".yml", ".yaml")):
            continue
        # Compose commonly uses anchors to share service defaults.  Permit them
        # only there; all other YAML stays closed to alias/merge indirection so
        # security review observes the declaration exactly as written.
        _load_yaml_documents(
            material,
            path=path,
            workflow_security=not _is_compose_declaration(path),
        )
        count += 1
    if count == 0:
        raise ReleaseSecurityError("repository contains no YAML declarations")
    return count


def _require_image_digest(reference: str, *, location: str) -> None:
    if _IMAGE_DIGEST.fullmatch(reference) is None or reference.casefold().endswith(":latest"):
        raise ReleaseSecurityError(f"OCI image is not digest pinned: {location}")


def _is_compose_declaration(path: str) -> bool:
    name = PurePosixPath(path).name.casefold()
    return name in {
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    } or (
        name.startswith(("compose.", "docker-compose."))
        and name.endswith((".yml", ".yaml"))
    )


def _declared_image_reference(value: object, *, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseSecurityError(f"OCI image is not a closed scalar: {location}")
    default = _VARIABLE_DEFAULT.fullmatch(value)
    reference = default.group(2) if default is not None else value
    if "$" in reference or "{" in reference or "}" in reference:
        raise ReleaseSecurityError(f"OCI image lacks a pinned default: {location}")
    _require_image_digest(reference, location=location)
    return reference


def _check_compose_images(material: bytes, *, path: str) -> int:
    documents = _load_yaml_documents(material, path=path)
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise ReleaseSecurityError(f"Compose declaration is malformed: {path}")
    services = documents[0].get("services")
    if not isinstance(services, dict) or not services:
        raise ReleaseSecurityError(f"Compose services are malformed: {path}")
    count = 0
    for service_name, service in services.items():
        if not isinstance(service_name, str) or not isinstance(service, dict):
            raise ReleaseSecurityError(f"Compose service is malformed: {path}")
        if "image" not in service:
            continue
        _declared_image_reference(
            service["image"], location=f"{path}:services.{service_name}.image"
        )
        count += 1
    return count


def _check_workflow_images(material: bytes, *, path: str) -> int:
    count = 0
    for document in _load_yaml_documents(
        material, path=path, workflow_security=True
    ):
        if not isinstance(document, dict):
            raise ReleaseSecurityError(f"workflow declaration is malformed: {path}")
        jobs = document.get("jobs")
        if not isinstance(jobs, dict):
            raise ReleaseSecurityError(f"workflow jobs are malformed: {path}")
        for job_name, job in jobs.items():
            if not isinstance(job_name, str) or not isinstance(job, dict):
                raise ReleaseSecurityError(f"workflow job is malformed: {path}")
            container = job.get("container")
            if container is not None:
                image = container.get("image") if isinstance(container, dict) else container
                _declared_image_reference(
                    image, location=f"{path}:jobs.{job_name}.container.image"
                )
                count += 1
            services = job.get("services")
            if services is None:
                continue
            if not isinstance(services, dict):
                raise ReleaseSecurityError(f"workflow services are malformed: {path}")
            for service_name, service in services.items():
                if not isinstance(service_name, str) or not isinstance(service, dict):
                    raise ReleaseSecurityError(f"workflow service is malformed: {path}")
                _declared_image_reference(
                    service.get("image"),
                    location=f"{path}:jobs.{job_name}.services.{service_name}.image",
                )
                count += 1
    return count


def _check_oci_declarations(files: dict[str, bytes]) -> int:
    count = 0
    for path in sorted(files):
        name = PurePosixPath(path).name
        folded_name = name.casefold()
        is_dockerfile = folded_name == "dockerfile" or folded_name.startswith("dockerfile.")
        is_compose = _is_compose_declaration(path)
        is_workflow = path.startswith(".github/workflows/") and path.endswith(
            (".yml", ".yaml")
        )
        if not is_dockerfile and not is_compose and not is_workflow:
            continue
        if is_dockerfile:
            text = _strict_text(files, path)
            arguments: dict[str, str] = {}
            from_count = 0
            for line_number, line in enumerate(text.splitlines(), start=1):
                argument = _IMAGE_ARGUMENT.fullmatch(line)
                if argument is not None:
                    variable, reference = argument.groups()
                    if variable in arguments:
                        raise ReleaseSecurityError(
                            f"Dockerfile image argument is duplicated: {path}:{line_number}"
                        )
                    _require_image_digest(reference, location=f"{path}:{line_number}")
                    arguments[variable] = reference
                    continue
                matched_from = _FROM.fullmatch(line)
                if matched_from is None:
                    continue
                tokens = matched_from.group(1).split()
                while tokens and tokens[0].startswith("--"):
                    tokens.pop(0)
                if not tokens:
                    raise ReleaseSecurityError(
                        f"Dockerfile FROM is malformed: {path}:{line_number}"
                    )
                reference = tokens[0]
                variable = _VARIABLE.fullmatch(reference)
                if variable is not None:
                    if variable.group(1) not in arguments:
                        raise ReleaseSecurityError(
                            f"Dockerfile FROM uses an unpinned variable: {path}:{line_number}"
                        )
                else:
                    _require_image_digest(reference, location=f"{path}:{line_number}")
                from_count += 1
            if from_count == 0:
                raise ReleaseSecurityError(f"Dockerfile contains no FROM declaration: {path}")
            count += from_count
        if is_compose:
            count += _check_compose_images(files[path], path=path)
        if is_workflow:
            count += _check_workflow_images(files[path], path=path)
    if count == 0:
        raise ReleaseSecurityError("repository declares no digest-pinned OCI inputs")
    return count


def _check_high_confidence_secrets(files: dict[str, bytes]) -> int:
    scanned = 0
    for path, material in files.items():
        if b"\0" in material:
            continue
        scanned += 1
        if _PEM_PRIVATE_KEY.search(material) is not None:
            raise ReleaseSecurityError(f"tracked private key material detected: {path}")
        if any(pattern.search(material) is not None for pattern in _TOKEN_PATTERNS):
            raise ReleaseSecurityError(f"tracked credential-like token detected: {path}")
    return scanned


def _check_release_boundaries(policy: dict[str, Any]) -> None:
    expected = {
        "dependency_artifact_hashes": "not_yet_complete",
        "external_release_authorization": "required_not_established_by_ci",
        "independent_security_assessment": "not_established",
        "production_readiness": "not_established",
    }
    if policy.get("release_boundaries") != expected:
        raise ReleaseSecurityError("release boundary declaration is incomplete or overstated")


def check_repository(root: Path) -> dict[str, Any]:
    """Validate tracked release declarations without network access."""

    root = root.resolve(strict=True)
    files = _tracked_files(root)
    policy = _load_policy(root)
    _check_release_boundaries(policy)
    result = {
        "action_pin_count": _check_action_pins(files, policy),
        "high_confidence_secret_files_scanned": _check_high_confidence_secrets(files),
        "oci_declaration_count": _check_oci_declarations(files),
        "python_pin_count": _check_project_and_lock(files, policy),
        "security_tool_pin_count": _check_hashed_security_tools(files, policy),
        "yaml_declaration_count": _check_yaml(files),
    }
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "valid": True,
        "mode": "tracked_repository_declarations",
        "checks": result,
        "boundaries": policy["release_boundaries"],
    }


def _allowed_spdx_expression(expression: str, allowed: set[str]) -> bool:
    tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expression)
    identifiers = [token for token in tokens if token not in {"AND", "OR", "WITH"}]
    return bool(identifiers) and all(identifier in allowed for identifier in identifiers)


def _license_signal(distribution: DistributionLike, policy: dict[str, Any]) -> tuple[str, str]:
    license_policy = policy.get("dependency_license_policy")
    if not isinstance(license_policy, dict):
        raise ReleaseSecurityError("dependency license policy is malformed")
    metadata_value = distribution.metadata
    expression = metadata_value.get("License-Expression")
    allowed_spdx = license_policy.get("allowed_spdx_identifiers")
    if not isinstance(allowed_spdx, list) or not all(
        isinstance(item, str) for item in allowed_spdx
    ):
        raise ReleaseSecurityError("allowed SPDX policy is malformed")
    if isinstance(expression, str) and expression:
        if not _allowed_spdx_expression(expression, set(allowed_spdx)):
            raise ReleaseSecurityError(
                f"dependency license expression is not approved: {expression}"
            )
        return "license_expression", expression
    classifiers = [
        item.removeprefix("License :: ")
        for item in (metadata_value.get_all("Classifier") or [])
        if item.startswith("License :: ")
    ]
    allowed_classifiers = license_policy.get("allowed_classifiers")
    if not isinstance(allowed_classifiers, list) or not all(
        isinstance(item, str) for item in allowed_classifiers
    ):
        raise ReleaseSecurityError("allowed classifier policy is malformed")
    if classifiers:
        unexpected = sorted(set(classifiers) - set(allowed_classifiers))
        if unexpected:
            raise ReleaseSecurityError(
                "dependency license classifier is not approved: " + ", ".join(unexpected)
            )
        return "classifier", " OR ".join(sorted(set(classifiers)))
    legacy = metadata_value.get("License")
    allowed_legacy = license_policy.get("allowed_legacy_fields")
    if not isinstance(allowed_legacy, list) or not all(
        isinstance(item, str) for item in allowed_legacy
    ):
        raise ReleaseSecurityError("allowed legacy license policy is malformed")
    if isinstance(legacy, str) and legacy in allowed_legacy:
        return "legacy_field", legacy
    raise ReleaseSecurityError("dependency provides no approved license metadata signal")


def check_installed_licenses(
    root: Path,
    *,
    distribution_lookup: Callable[[str], DistributionLike] = metadata.distribution,
) -> dict[str, Any]:
    """Check installed locked versions and package-provided license metadata."""

    root = root.resolve(strict=True)
    policy = _load_policy(root)
    pins = _lock_pins((root / "requirements.lock").read_text(encoding="utf-8"))
    records: list[dict[str, str]] = []
    for name, expected_version in sorted(pins.items()):
        try:
            distribution = distribution_lookup(name)
        except metadata.PackageNotFoundError as exc:
            raise ReleaseSecurityError(f"locked distribution is not installed: {name}") from exc
        if distribution.version != expected_version:
            raise ReleaseSecurityError(
                f"installed version does not match requirements.lock: "
                f"{name}=={distribution.version}, expected {expected_version}"
            )
        signal_kind, signal = _license_signal(distribution, policy)
        records.append(
            {
                "distribution": name,
                "version": expected_version,
                "signal_kind": signal_kind,
                "license_signal": signal,
            }
        )
    license_policy = policy["dependency_license_policy"]
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "valid": True,
        "mode": "installed_dependency_license_metadata",
        "distribution_count": len(records),
        "distributions": records,
        "evidence_boundary": license_policy["evidence_boundary"],
        "release_authorization": "not_established",
    }
