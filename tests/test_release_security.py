from __future__ import annotations

import json
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest

from aegis_ot import release_security as security
from aegis_ot.release_security import (
    POLICY_PATH,
    ReleaseSecurityError,
    check_installed_licenses,
    check_repository,
)


def _run(root: Path, *arguments: str) -> None:
    completed = subprocess.run(  # noqa: S603 - fixed executable, test-fixture arguments
        arguments,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    _run(root, "git", "init", "-q")
    policy_target = root.joinpath(*POLICY_PATH.parts)
    policy_target.parent.mkdir(parents=True)
    policy_target.write_bytes(
        Path(__file__).parents[1].joinpath(*POLICY_PATH.parts).read_bytes()
    )
    (root / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools==80.9.0"]
build-backend = "setuptools.build_meta"

[project]
name = "fixture"
version = "1.0.0"
license = {text = "Apache-2.0"}
authors = [{name = "Angelis Pseftis"}]
dependencies = ["foo>=1,<2"]

[project.optional-dependencies]
dev = ["bar==2.0"]
""",
        encoding="utf-8",
    )
    (root / "requirements.lock").write_text(
        "foo==1.0\nbar==2.0\nsetuptools==80.9.0\n", encoding="utf-8"
    )
    security_directory = root / "security"
    security_directory.mkdir()
    (security_directory / "requirements.in").write_text(
        "pip-audit==2.10.1\n", encoding="utf-8"
    )
    security_lock = (
        "pip-audit==2.10.1 \\\n    --hash=sha256:"
        + "1" * 64
        + "\n"
        + "dependency==1.0 \\\n    --hash=sha256:"
        + "2" * 64
        + "\n"
    )
    (security_directory / "requirements.lock").write_text(
        security_lock, encoding="utf-8"
    )
    (root / "Dockerfile").write_text(
        "ARG BASE_IMAGE=python:3.13-slim@sha256:" + "1" * 64 + "\nFROM ${BASE_IMAGE}\n",
        encoding="utf-8",
    )
    workflow = root / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_bytes(
        Path(__file__).parents[1].joinpath(".github", "workflows", "ci.yml").read_bytes()
    )
    (root / "config" / "plain.yaml").write_text("safe: true\n", encoding="utf-8")
    (root / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("Synthetic research only.\n", encoding="utf-8")
    _run(root, "git", "add", ".")
    return root


def test_repository_policy_accepts_closed_pinned_declarations(repository: Path) -> None:
    report = check_repository(repository)

    assert report["valid"] is True
    assert report["mode"] == "tracked_repository_declarations"
    assert report["checks"]["action_pin_count"] == 12
    assert report["checks"]["python_pin_count"] == 3
    assert report["checks"]["security_tool_pin_count"] == 2
    assert report["checks"]["oci_declaration_count"] == 1
    assert report["boundaries"]["external_release_authorization"].startswith("required_")


@pytest.mark.parametrize(
    ("input_material", "lock_material", "message"),
    (
        ("pip-audit==2.10.0\n", None, "only the approved"),
        (
            None,
            "pip-audit==2.10.1\ndependency==1.0 \\\n    --hash=sha256:" + "2" * 64 + "\n",
            "lacks artifact hashes",
        ),
        (
            None,
            "pip-audit>=2.10.1 \\\n    --hash=sha256:" + "1" * 64 + "\n",
            "non-exact requirement",
        ),
        (
            None,
            "pip-audit==2.10.1 \\\n    --index-url=https://example.invalid\n",
            "unsupported option",
        ),
        (
            None,
            "pip-audit==2.10.1 \\\n    --hash=sha256:" + "1" * 64 + "\n",
            "transitive dependencies",
        ),
        (
            None,
            (
                "pip-audit==2.10.1 \\\n    --hash=sha256:"
                + "1" * 64
                + "\n"
                + "dependency==1.0 \\\n    --hash=sha256:"
                + "1" * 64
                + "\n"
            ),
            "repeats an artifact hash",
        ),
        (
            None,
            "pip-audit==2.10.0 \\\n    --hash=sha256:" + "1" * 64 + "\n"
            "dependency==1.0 \\\n    --hash=sha256:" + "2" * 64 + "\n",
            "approved pip-audit version",
        ),
        (None, "pip-audit==2.10.1 \\\n", "unterminated continuation"),
    ),
)
def test_security_tool_lock_fails_closed_on_drift_and_unhashed_inputs(
    repository: Path,
    input_material: str | None,
    lock_material: str | None,
    message: str,
) -> None:
    policy = security._load_policy(repository)
    files = security._tracked_files(repository)
    if input_material is not None:
        files["security/requirements.in"] = input_material.encode()
    if lock_material is not None:
        files["security/requirements.lock"] = lock_material.encode()

    with pytest.raises(ReleaseSecurityError, match=message):
        security._check_hashed_security_tools(files, policy)


def test_security_tool_policy_rejects_malformed_contract(repository: Path) -> None:
    files = security._tracked_files(repository)
    with pytest.raises(ReleaseSecurityError, match="policy is malformed"):
        security._check_hashed_security_tools(files, {})
    with pytest.raises(ReleaseSecurityError, match="paths or version"):
        security._check_hashed_security_tools(files, {"security_tools": {}})


def test_repository_policy_rejects_mutable_action_reference(repository: Path) -> None:
    workflow = repository / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v4",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReleaseSecurityError, match="full commit SHA"):
        check_repository(repository)


def test_repository_policy_rejects_quoted_mutable_action_reference(
    repository: Path,
) -> None:
    workflow = repository / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            'uses: "actions/checkout@v7"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReleaseSecurityError, match="full commit SHA"):
        check_repository(repository)


def test_repository_policy_rejects_secret_material_and_floating_image(
    repository: Path,
) -> None:
    secret = repository / "tracked.txt"
    secret.write_text(
        "-----BEGIN PRIVATE KEY-----\n" + "A" * 64 + "\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    _run(repository, "git", "add", "tracked.txt")
    with pytest.raises(ReleaseSecurityError, match="private key"):
        check_repository(repository)

    secret.unlink()
    _run(repository, "git", "rm", "--cached", "tracked.txt")
    dockerfile = repository / "Dockerfile"
    dockerfile.write_text("FROM python:latest\n", encoding="utf-8")
    with pytest.raises(ReleaseSecurityError, match="not digest pinned"):
        check_repository(repository)


def test_repository_policy_rejects_duplicate_yaml_and_unlocked_dependency(
    repository: Path,
) -> None:
    declaration = repository / "config" / "plain.yaml"
    declaration.write_text("value: one\nvalue: two\n", encoding="utf-8")
    with pytest.raises(ReleaseSecurityError, match="duplicate key"):
        check_repository(repository)

    declaration.write_text("value: one\n", encoding="utf-8")
    pyproject = repository / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            'dependencies = ["foo>=1,<2"]',
            'dependencies = ["foo>=1,<2", "missing>=1"]',
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseSecurityError, match="absent from requirements.lock"):
        check_repository(repository)


class _Metadata(dict[str, str]):
    def __init__(self, values: dict[str, str], classifiers: list[str] | None = None) -> None:
        super().__init__(values)
        self._classifiers = classifiers or []

    def get_all(self, key: str) -> list[str] | None:
        return self._classifiers if key == "Classifier" else None


class _Distribution:
    def __init__(
        self,
        version: str,
        values: dict[str, str],
        classifiers: list[str] | None = None,
    ) -> None:
        self.version = version
        self.metadata = _Metadata(values, classifiers)


def test_installed_license_policy_binds_versions_and_metadata(repository: Path) -> None:
    distributions = {
        "foo": _Distribution("1.0", {"License-Expression": "MIT"}),
        "bar": _Distribution(
            "2.0",
            {},
            ["License :: OSI Approved :: BSD License"],
        ),
        "setuptools": _Distribution("80.9.0", {"License-Expression": "MIT"}),
    }

    report = check_installed_licenses(repository, distribution_lookup=distributions.__getitem__)

    assert report["valid"] is True
    assert report["distribution_count"] == 3
    assert {item["signal_kind"] for item in report["distributions"]} == {
        "classifier",
        "license_expression",
    }
    assert report["release_authorization"] == "not_established"


def test_installed_license_policy_rejects_version_drift_unknown_and_copyleft(
    repository: Path,
) -> None:
    with pytest.raises(ReleaseSecurityError, match="installed version"):
        check_installed_licenses(
            repository,
            distribution_lookup=lambda _name: _Distribution(
                "9.9", {"License-Expression": "MIT"}
            ),
        )

    def missing(name: str) -> _Distribution:
        if name == "foo":
            raise metadata.PackageNotFoundError(name)
        version = "80.9.0" if name == "setuptools" else "2.0"
        return _Distribution(version, {"License-Expression": "MIT"})

    with pytest.raises(ReleaseSecurityError, match="not installed"):
        check_installed_licenses(repository, distribution_lookup=missing)

    distributions = {
        "foo": _Distribution("1.0", {"License-Expression": "GPL-3.0-only"}),
        "bar": _Distribution("2.0", {"License-Expression": "MIT"}),
        "setuptools": _Distribution("80.9.0", {"License-Expression": "MIT"}),
    }
    with pytest.raises(ReleaseSecurityError, match="not approved"):
        check_installed_licenses(repository, distribution_lookup=distributions.__getitem__)


def test_release_security_cli_emits_machine_readable_report(
    repository: Path,
) -> None:
    script = Path(__file__).parents[1] / "scripts" / "check_release_security.py"
    completed = subprocess.run(  # noqa: S603 - current interpreter and fixed script
        (sys.executable, str(script), "--root", str(repository)),
        cwd=Path(__file__).parents[1],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["repository"]["valid"] is True


def test_policy_parser_rejects_missing_non_json_duplicate_and_wrong_schema(
    tmp_path: Path,
) -> None:
    policy = tmp_path.joinpath(*POLICY_PATH.parts)
    policy.parent.mkdir(parents=True)
    with pytest.raises(ReleaseSecurityError, match="unavailable"):
        security._load_policy(tmp_path)

    for material, message in (
        (b"\xff", "not strict JSON"),
        (b'{"schema_version":NaN}', "non-finite"),
        (b'{"schema_version":"one","schema_version":"two"}', "duplicate key"),
        (b'{"schema_version":"wrong"}', "unsupported"),
    ):
        policy.write_bytes(material)
        with pytest.raises(ReleaseSecurityError, match=message):
            security._load_policy(tmp_path)


def test_git_enumeration_failures_are_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(security, "_GIT_EXECUTABLE", tmp_path / "missing-git")
    with pytest.raises(ReleaseSecurityError, match="metadata is unavailable"):
        security._run_git(tmp_path, "status")

    monkeypatch.setattr(security, "_GIT_EXECUTABLE", Path("/usr/bin/git"))
    _run(tmp_path, "/usr/bin/git", "init", "-q")

    def cannot_start(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise OSError("blocked")

    monkeypatch.setattr(subprocess, "run", cannot_start)
    with pytest.raises(ReleaseSecurityError, match="could not enumerate"):
        security._run_git(tmp_path, "status")

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=("git",), returncode=2, stdout=b"", stderr=b"bad repository"
        ),
    )
    with pytest.raises(ReleaseSecurityError, match="bad repository"):
        security._run_git(tmp_path, "status")


@pytest.mark.parametrize(
    ("lock_text", "message"),
    (
        ("foo>=1\n", "not an exact"),
        ("foo[extra]==1\n", "not extras"),
        ("foo==1\nFoo==2\n", "duplicates"),
        ("# empty\n", "no exact pins"),
    ),
)
def test_lock_parser_rejects_open_duplicate_and_extra_pins(
    lock_text: str,
    message: str,
) -> None:
    with pytest.raises(ReleaseSecurityError, match=message):
        security._lock_pins(lock_text)


@pytest.mark.parametrize(
    ("pyproject", "message"),
    (
        ({}, "lacks project"),
        ({"project": {"dependencies": "bad", "optional-dependencies": {}}}, "malformed"),
        ({"project": {"dependencies": [], "optional-dependencies": []}}, "malformed"),
        (
            {"project": {"dependencies": [], "optional-dependencies": {1: []}}},
            "group is malformed",
        ),
        (
            {"project": {"dependencies": [1], "optional-dependencies": {}}},
            "not a string",
        ),
        (
            {"project": {"dependencies": ["!bad"], "optional-dependencies": {}}},
            "declaration is malformed",
        ),
        (
            {
                "project": {
                    "dependencies": ["foo @ https://attacker.invalid/foo.whl"],
                    "optional-dependencies": {},
                }
            },
            "URL, VCS, path",
        ),
    ),
)
def test_dependency_declaration_parser_rejects_malformed_shapes(
    pyproject: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ReleaseSecurityError, match=message):
        security._declared_dependencies(pyproject)


def test_workflow_policy_rejects_unapproved_malformed_and_privileged_actions(
    repository: Path,
) -> None:
    policy = security._load_policy(repository)
    files = security._tracked_files(repository)
    workflow_path = ".github/workflows/ci.yml"
    original = files[workflow_path].decode("utf-8")

    files[workflow_path] = (
        original + "\n      - uses: unapproved/example@" + "a" * 40 + "\n"
    ).encode()
    with pytest.raises(ReleaseSecurityError, match="owner is not approved"):
        security._check_action_pins(files, policy)

    files[workflow_path] = (original + "\n      - uses: docker://floating\n").encode()
    with pytest.raises(ReleaseSecurityError, match="reference is malformed"):
        security._check_action_pins(files, policy)

    files[workflow_path] = original.replace("contents: read", "contents: write", 1).encode()
    with pytest.raises(ReleaseSecurityError, match="top-level permissions"):
        security._check_action_pins(files, policy)

    files[workflow_path] = b"\xff"
    with pytest.raises(ReleaseSecurityError, match="YAML declaration is not UTF-8"):
        security._check_action_pins(files, policy)


def test_workflow_policy_validates_local_actions_and_required_contract(
    repository: Path,
) -> None:
    policy = security._load_policy(repository)
    files = security._tracked_files(repository)
    workflow_path = ".github/workflows/ci.yml"
    original = files[workflow_path].decode("utf-8")
    local_workflow = ".github/workflows/local.yml"
    files[local_workflow] = b"""name: local
on:
  push:
permissions:
  contents: read
jobs:
  local:
    runs-on: ubuntu-24.04
    steps:
      - name: Run local action
        uses: ./.github/actions/local
"""
    with pytest.raises(ReleaseSecurityError, match="not a tracked closed path"):
        security._check_action_pins(files, policy)

    files[".github/actions/local/action.yml"] = (
        b"name: local\nruns: {using: composite, steps: []}\n"
    )
    assert security._check_action_pins(files, policy) == 12

    no_actions = {workflow_path: b"name: empty\n"}
    with pytest.raises(ReleaseSecurityError, match="no external"):
        security._check_action_pins(no_actions, policy)

    incomplete = dict(files)
    incomplete[workflow_path] = (
        original.replace(
        "name: Container vulnerability scan", "name: container check"
        )
        + "\n# name: Container vulnerability scan\n"
    ).encode()
    with pytest.raises(ReleaseSecurityError, match="required CI step is absent"):
        security._check_action_pins(incomplete, policy)


@pytest.mark.parametrize(
    ("before", "after", "message"),
    (
        (
            "  release-security:\n",
            "  release-security:\n    if: ${{ false }}\n",
            "job fields differ",
        ),
        (
            "      - name: Repository security policy\n",
            "      - name: Repository security policy\n        continue-on-error: true\n",
            "step fields differ",
        ),
        (
            "        run: python scripts/check_release_security.py\n",
            '        run: "true # python scripts/check_release_security.py"\n',
            "approved digest",
        ),
        (
            "on:\n  push:\n  pull_request:\n",
            "on: {}\n",
            "triggers differ",
        ),
        (
            "          scan-ref: .\n",
            "          scan-ref: /tmp/empty\n",
            "step inputs differ",
        ),
    ),
)
def test_workflow_contract_rejects_disabled_or_redirected_gates(
    repository: Path,
    before: str,
    after: str,
    message: str,
) -> None:
    policy = security._load_policy(repository)
    files = security._tracked_files(repository)
    workflow_path = ".github/workflows/ci.yml"
    original = files[workflow_path].decode("utf-8")
    assert before in original
    files[workflow_path] = original.replace(before, after, 1).encode()
    with pytest.raises(ReleaseSecurityError, match=message):
        security._check_action_pins(files, policy)


def test_workflow_contract_rejects_unapproved_action_revision(repository: Path) -> None:
    policy = security._load_policy(repository)
    files = security._tracked_files(repository)
    workflow_path = ".github/workflows/ci.yml"
    original = files[workflow_path].decode("utf-8")
    files[workflow_path] = original.replace(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/checkout@" + "a" * 40,
        1,
    ).encode()
    with pytest.raises(ReleaseSecurityError, match="revision is not approved"):
        security._check_action_pins(files, policy)


@pytest.mark.parametrize(
    ("files", "message"),
    (
        ({"Dockerfile": b"ARG BASE_IMAGE=x@sha256:" + b"1" * 64 + b"\n"}, "no FROM"),
        ({"Dockerfile": b"FROM ${BASE_IMAGE}\n"}, "unpinned variable"),
        (
            {
                "Dockerfile": (
                    b"ARG BASE_IMAGE=x@sha256:" + b"1" * 64 + b"\n"
                    b"ARG BASE_IMAGE=x@sha256:" + b"2" * 64 + b"\n"
                    b"FROM ${BASE_IMAGE}\n"
                )
            },
            "duplicated",
        ),
        ({"docker-compose.yml": b"services:\n  x:\n    image: ${IMAGE}\n"}, "lacks a pinned"),
        ({"docker-compose.yml": b"services:\n  x:\n    image: [bad]\n"}, "closed scalar"),
        ({"safe.txt": b"none\n"}, "declares no"),
    ),
)
def test_oci_policy_rejects_open_or_missing_declarations(
    files: dict[str, bytes],
    message: str,
) -> None:
    with pytest.raises(ReleaseSecurityError, match=message):
        security._check_oci_declarations(files)


def test_oci_policy_accepts_direct_platform_and_compose_default() -> None:
    digest = "a" * 64
    files = {
        "Dockerfile": f"FROM --platform=linux/amd64 python:3.13@sha256:{digest}\n".encode(),
        "docker-compose.yml": (
            "services:\n  x:\n"
            f"    image: '${{IMAGE:-example/image:1@sha256:{digest}}}'\n"
        ).encode(),
    }
    assert security._check_oci_declarations(files) == 2


def test_oci_policy_covers_case_insensitive_stages_standard_compose_and_workflows() -> None:
    digest = "a" * 64
    with pytest.raises(ReleaseSecurityError, match="not digest pinned"):
        security._check_oci_declarations(
            {
                "Dockerfile": (
                    f"FROM python:3.13@sha256:{digest}\nfrom alpine:latest\n"
                ).encode()
            }
        )
    with pytest.raises(ReleaseSecurityError, match="not digest pinned"):
        security._check_oci_declarations(
            {"compose.yaml": b"services:\n  x:\n    image: alpine:latest\n"}
        )
    workflow = b"""name: container
on:
  push:
jobs:
  scan:
    runs-on: ubuntu-24.04
    container: ubuntu:latest
    steps:
      - name: Run
        run: 'true'
"""
    with pytest.raises(ReleaseSecurityError, match="not digest pinned"):
        security._check_oci_declarations({".github/workflows/container.yml": workflow})


def test_oci_policy_resolves_compose_anchors_structurally() -> None:
    digest = "a" * 64
    compose = (
        f"x-image: &image example/app:1@sha256:{digest}\n"
        "services:\n  x:\n    image: *image\n"
    ).encode()
    assert security._check_oci_declarations({"compose.yml": compose}) == 1


def test_yaml_secret_and_boundary_checks_cover_binary_merge_and_tokens() -> None:
    merged = b"base: &base\n  one: 1\nitem:\n  <<: *base\n  two: 2\n"
    with pytest.raises(ReleaseSecurityError, match="anchors and aliases"):
        security._check_yaml({"merged.yaml": merged})
    with pytest.raises(ReleaseSecurityError, match="merge keys"):
        security._check_yaml({"merged.yaml": b"item:\n  <<: {one: 1}\n"})
    with pytest.raises(ReleaseSecurityError, match="anchors and aliases"):
        security._load_yaml_documents(
            merged, path=".github/workflows/bad.yml", workflow_security=True
        )
    with pytest.raises(ReleaseSecurityError, match="not UTF-8"):
        security._check_yaml({"bad.yaml": b"\xff"})
    with pytest.raises(ReleaseSecurityError, match="no YAML"):
        security._check_yaml({"safe.txt": b"safe"})

    assert security._check_high_confidence_secrets(
        {"binary": b"\0github_pat_" + b"A" * 40, "safe": b"safe"}
    ) == 1
    with pytest.raises(ReleaseSecurityError, match="credential-like"):
        security._check_high_confidence_secrets(
            {"token.txt": b"github_pat_" + b"A" * 40}
        )
    with pytest.raises(ReleaseSecurityError, match="boundary"):
        security._check_release_boundaries({"release_boundaries": {}})


def test_license_policy_accepts_legacy_and_rejects_unknown_or_mixed_classifier(
    repository: Path,
) -> None:
    policy = security._load_policy(repository)
    kind, value = security._license_signal(
        _Distribution("1", {"License": "Apache-2.0"}), policy
    )
    assert (kind, value) == ("legacy_field", "Apache-2.0")

    with pytest.raises(ReleaseSecurityError, match="classifier is not approved"):
        security._license_signal(
            _Distribution(
                "1",
                {},
                [
                    "License :: OSI Approved :: MIT License",
                    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
                ],
            ),
            policy,
        )
    with pytest.raises(ReleaseSecurityError, match="no approved"):
        security._license_signal(_Distribution("1", {}), policy)


def test_project_contract_rejects_invalid_toml_license_and_author(
    repository: Path,
) -> None:
    policy = security._load_policy(repository)
    files = security._tracked_files(repository)
    files["pyproject.toml"] = b"[project\n"
    with pytest.raises(ReleaseSecurityError, match="invalid"):
        security._check_project_and_lock(files, policy)

    original = security._tracked_files(repository)
    files = dict(original)
    files["pyproject.toml"] = original["pyproject.toml"].replace(b"Apache-2.0", b"MIT")
    with pytest.raises(ReleaseSecurityError, match="license"):
        security._check_project_and_lock(files, policy)

    files = dict(original)
    files["pyproject.toml"] = original["pyproject.toml"].replace(
        b"Angelis Pseftis", b"Another Author"
    )
    with pytest.raises(ReleaseSecurityError, match="authorship"):
        security._check_project_and_lock(files, policy)


def test_project_contract_closes_build_backend_and_direct_dependency_sources(
    repository: Path,
) -> None:
    policy = security._load_policy(repository)
    original = security._tracked_files(repository)

    files = dict(original)
    files["pyproject.toml"] = original["pyproject.toml"].replace(
        b'setuptools==80.9.0', b'evil @ https://attacker.invalid/build.whl'
    )
    with pytest.raises(ReleaseSecurityError, match="build-system differs"):
        security._check_project_and_lock(files, policy)

    files = dict(original)
    files["pyproject.toml"] = original["pyproject.toml"].replace(
        b'foo>=1,<2', b'foo @ git+https://attacker.invalid/repository.git'
    )
    with pytest.raises(ReleaseSecurityError, match="URL, VCS, path"):
        security._check_project_and_lock(files, policy)

    files = dict(original)
    files["requirements.lock"] = b"foo==1.0\nbar==2.0\n"
    with pytest.raises(ReleaseSecurityError, match="build-system requirement is absent"):
        security._check_project_and_lock(files, policy)
