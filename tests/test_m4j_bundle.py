from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def bundler(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("build_m4j_bundle")


@pytest.fixture
def workload_validator(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("validate_m4j_workloads")


@pytest.fixture
def runtime_preparer(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("prepare_m4j_runtime_images")


def _write_repository_files(root: Path, *, topology: bool = True) -> None:
    (root / ".dockerignore").write_text(".git\n.env\n*.key\n", encoding="utf-8")
    (root / "Dockerfile").write_text(
        "\n".join(
            (
                "ARG PYTHON_IMAGE=python:3.13-slim@sha256:" + "1" * 64,
                "FROM ${PYTHON_IMAGE}",
                "ARG AEGIS_SOURCE_REVISION=unknown",
                'LABEL org.opencontainers.image.revision="${AEGIS_SOURCE_REVISION}"',
                "ARG AEGIS_INSTALL_TARGET=.",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "requirements.lock").write_text("pydantic==2.11.7\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "0.0.1"\n',
        encoding="utf-8",
    )
    (root / "tracked.txt").write_text("committed-source\n", encoding="utf-8")
    policy = root / "policy" / "aegis.rego"
    policy.parent.mkdir()
    policy.write_text("package aegis\ndefault allow := false\n", encoding="utf-8")
    helper = root / "scripts" / "build_m4j_bundle.py"
    helper.parent.mkdir()
    helper.write_bytes(
        (Path(__file__).parents[1] / "scripts" / "build_m4j_bundle.py").read_bytes()
    )
    if topology:
        topology_path = root / "infra" / "m4j" / "topology.yml"
        topology_path.parent.mkdir(parents=True)
        topology_path.write_bytes(
            (Path(__file__).parents[1] / "infra" / "m4j" / "topology.yml").read_bytes()
        )


def _commit(bundler: Any, root: Path, message: str) -> str:
    bundler._run("git", "add", ".", cwd=root)
    bundler._run(
        "git",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        message,
        cwd=root,
    )
    return cast(str, bundler._run("git", "rev-parse", "HEAD", cwd=root).stdout.strip())


def _repository(bundler: Any, root: Path, *, topology: bool = True) -> str:
    root.mkdir()
    bundler._run("git", "init", "-q", cwd=root)
    _write_repository_files(root, topology=topology)
    return _commit(bundler, root, "fixture")


def _fixed_tools(
    *,
    plan_only: bool = False,
    builder_profile: dict[str, Any] | None = None,
) -> dict[str, str]:
    del builder_profile
    return {
        "builder": "m4j-exact-source-application-image-bundle-v2",
        "docker_build": "not_invoked_plan_only" if plan_only else "fixture",
        "docker_daemon": "fixture",
        "buildkit_worker": "fixture",
        "git": "git version fixture",
        "python": "CPython fixture",
    }


def _builder_key(tmp_path: Path, *, name: str = "builder") -> tuple[Path, bytes]:
    signer = Ed25519PrivateKey.generate()
    private_path = tmp_path / f"{name}.private"
    private_path.write_bytes(signer.private_bytes_raw())
    private_path.chmod(0o600)
    return private_path, signer.public_key().public_bytes_raw()


def _builder_boundary(
    bundler: Any,
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> tuple[dict[str, Any], socket.socket]:
    (
        client,
        client_sha256,
        buildx_plugin,
        buildx_plugin_sha256,
        socket_path,
        endpoint,
    ) = _docker_boundary_materials(tmp_path, request)
    inspected = bundler.inspect_builder_profile(
        docker_client=client,
        docker_client_sha256=client_sha256,
        docker_buildx_plugin=buildx_plugin,
        docker_buildx_plugin_sha256=buildx_plugin_sha256,
        docker_socket=socket_path,
    )
    return (
        {
            "docker_client": client,
            "docker_client_sha256": client_sha256,
            "docker_buildx_plugin": buildx_plugin,
            "docker_buildx_plugin_sha256": buildx_plugin_sha256,
            "docker_socket": socket_path,
            "expected_builder_profile_sha256": inspected["profile_sha256"],
        },
        endpoint,
    )


def _docker_boundary_materials(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> tuple[Path, str, Path, str, Path, socket.socket]:
    client = tmp_path / "docker-client"
    client.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    client.chmod(0o700)
    client_sha256 = hashlib.sha256(client.read_bytes()).hexdigest()
    buildx_plugin = tmp_path / "docker-buildx"
    buildx_plugin.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    buildx_plugin.chmod(0o700)
    buildx_plugin_sha256 = hashlib.sha256(buildx_plugin.read_bytes()).hexdigest()
    socket_root = Path(
        tempfile.mkdtemp(
            prefix=".m4jb-",
            dir=Path(__file__).parents[1],
        )
    )
    socket_path = socket_root / "docker.sock"
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    endpoint.bind(str(socket_path))
    request.addfinalizer(endpoint.close)
    request.addfinalizer(lambda: shutil.rmtree(socket_root, ignore_errors=True))
    return (
        client,
        client_sha256,
        buildx_plugin,
        buildx_plugin_sha256,
        socket_path,
        endpoint,
    )


def _image_config(
    commit: str,
    *,
    architecture: str = "amd64",
    layer: bytes = b"fixture-layer",
    invocation_id: str | None = None,
) -> bytes:
    labels = {"org.opencontainers.image.revision": commit}
    if invocation_id is not None:
        labels["org.aegis-ot.bundle.invocation"] = invocation_id
    return json.dumps(
        {
            "architecture": architecture,
            "os": "linux",
            "config": {"Labels": labels},
            "rootfs": {
                "type": "layers",
                "diff_ids": [f"sha256:{hashlib.sha256(layer).hexdigest()}"],
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write_saved_image_archive(
    path: Path,
    *,
    config: bytes,
    config_name: str | None = None,
    repo_tags: list[str] | None = None,
    layer: bytes = b"fixture-layer",
) -> str:
    digest = hashlib.sha256(config).hexdigest()
    name = config_name or f"{digest}.json"
    layer_name = f"{hashlib.sha256(layer).hexdigest()}/layer.tar"
    manifest = json.dumps(
        [
            {
                "Config": name,
                "RepoTags": repo_tags,
                "Layers": [layer_name],
            }
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    with tarfile.open(path, mode="w") as archive:
        for member_name, material in (
            (name, config),
            (layer_name, layer),
            ("manifest.json", manifest),
        ):
            member = tarfile.TarInfo(member_name)
            member.size = len(material)
            archive.addfile(member, io.BytesIO(material))
    return f"sha256:{digest}"


def _write_oci_saved_image_archive(
    path: Path,
    *,
    commit: str,
    stored_layer: bytes | None = None,
    config_layer: bytes | None = None,
) -> tuple[str, str]:
    layer = b"fixture-oci-layer"
    config = _image_config(commit, layer=config_layer or layer)
    config_digest = hashlib.sha256(config).hexdigest()
    layer_digest = hashlib.sha256(layer).hexdigest()
    image_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{config_digest}",
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": f"sha256:{layer_digest}",
                    "size": len(layer),
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    image_manifest_digest = hashlib.sha256(image_manifest).hexdigest()
    image_index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{image_manifest_digest}",
                    "size": len(image_manifest),
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    image_index_digest = hashlib.sha256(image_index).hexdigest()
    manifest = json.dumps(
        [
            {
                "Config": f"blobs/sha256/{config_digest}",
                "RepoTags": None,
                "Layers": [f"blobs/sha256/{layer_digest}"],
            }
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    materials = {
        "manifest.json": manifest,
        f"blobs/sha256/{config_digest}": config,
        f"blobs/sha256/{layer_digest}": stored_layer or layer,
        f"blobs/sha256/{image_manifest_digest}": image_manifest,
        f"blobs/sha256/{image_index_digest}": image_index,
    }
    with tarfile.open(path, mode="w") as archive:
        for member_name, material in materials.items():
            member = tarfile.TarInfo(member_name)
            member.size = len(material)
            archive.addfile(member, io.BytesIO(material))
    return f"sha256:{image_index_digest}", config_digest


class _FakeDocker:
    def __init__(
        self,
        bundler: Any,
        original_run: Any,
        *,
        commit: str,
        tamper_saved_config: bool = False,
        malformed_iid: bool = False,
    ) -> None:
        self._bundler = bundler
        self._original_run = original_run
        self.commit = commit
        self.layer = b"fixture-layer"
        self.invocation_id: str | None = None
        self.config = _image_config(commit, layer=self.layer)
        self.image_id = f"sha256:{hashlib.sha256(self.config).hexdigest()}"
        self.tamper_saved_config = tamper_saved_config
        self.malformed_iid = malformed_iid
        self.image_present = False
        self.tags: dict[str, str] = {}
        self.calls: list[tuple[str, ...]] = []

    def _completed(
        self,
        args: tuple[str, ...],
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def _inspect(self, args: tuple[str, ...], reference: str) -> subprocess.CompletedProcess[str]:
        image_id = self.tags.get(reference)
        if image_id is None and self.image_present and reference == self.image_id:
            image_id = self.image_id
        if image_id is None:
            return self._completed(
                args,
                returncode=1,
                stdout="[]\n",
                stderr=f"Error response from daemon: No such image: {reference}\n",
            )
        repo_tags = sorted(tag for tag, value in self.tags.items() if value == image_id)
        document = [
            {
                "Id": image_id,
                "Os": "linux",
                "Architecture": "amd64",
                "Config": {
                    "Labels": {
                        self._bundler.OCI_REVISION_LABEL: self.commit,
                        **(
                            {
                                self._bundler.BUILD_INVOCATION_LABEL: self.invocation_id,
                            }
                            if self.invocation_id is not None
                            else {}
                        ),
                    }
                },
                "RepoTags": repo_tags,
                "RepoDigests": [],
            }
        ]
        return self._completed(args, stdout=json.dumps(document))

    def run(self, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if not args or args[0] != "docker":
            return cast(
                subprocess.CompletedProcess[str],
                self._original_run(*args, **kwargs),
            )
        command = tuple(args)
        self.calls.append(command)
        if command[1:3] == ("version", "--format"):
            return self._completed(
                command,
                stdout=json.dumps(
                    {
                        "Client": {
                            "Version": "29.7.2",
                            "GitCommit": "fixture-client",
                            "Os": "darwin",
                            "Arch": "arm64",
                        },
                        "Server": {
                            "Version": "29.7.2",
                            "GitCommit": "fixture-server",
                            "Os": "linux",
                            "Arch": "amd64",
                            "Platform": {"Name": "fixture-daemon"},
                        },
                    }
                ),
            )
        if command[1:3] == ("info", "--format"):
            return self._completed(
                command,
                stdout=json.dumps(
                    {
                        "ID": "fixture-daemon-id",
                        "Name": "fixture-daemon",
                        "Driver": "overlay2",
                        "ServerVersion": "29.7.2",
                        "OSType": "linux",
                        "Architecture": "amd64",
                        "SecurityOptions": ["name=seccomp,profile=builtin"],
                    }
                ),
            )
        if command[1:3] == ("buildx", "version"):
            return self._completed(
                command,
                stdout="github.com/docker/buildx v0.36.1 fixture\n",
            )
        if command[1:3] == ("buildx", "inspect"):
            return self._completed(
                command,
                stdout=(
                    "Name: fixture-builder\n"
                    "Driver: docker\n\n"
                    "Nodes:\n"
                    "Name: fixture-node\n"
                    "Endpoint: unix:///fixture/buildkit.sock\n"
                    "Status: running\n"
                    "BuildKit version: v0.32.2\n"
                    "Platforms: linux/amd64\n"
                ),
            )
        if command[1:3] == ("image", "inspect"):
            return self._inspect(command, command[3])
        if command[1:3] == ("image", "ls"):
            expected_filter = (
                f"label={self._bundler.BUILD_INVOCATION_LABEL}="
                f"{self.invocation_id}"
            )
            if self.invocation_id is None or expected_filter not in command:
                return self._completed(command)
            stdout = f"{self.image_id}\n" if self.image_present else ""
            return self._completed(command, stdout=stdout)
        if command[1:3] == ("buildx", "build"):
            iid_path = Path(command[command.index("--iidfile") + 1])
            label = command[command.index("--label") + 1]
            prefix = f"{self._bundler.BUILD_INVOCATION_LABEL}="
            assert label.startswith(prefix)
            assert "--tag" not in command
            self.invocation_id = label.removeprefix(prefix)
            self.config = _image_config(
                self.commit,
                layer=self.layer,
                invocation_id=self.invocation_id,
            )
            self.image_id = f"sha256:{hashlib.sha256(self.config).hexdigest()}"
            self.image_present = True
            iid_path.write_text(
                "malformed\n" if self.malformed_iid else self.image_id + "\n",
                encoding="ascii",
            )
            return self._completed(command)
        if command[1:3] == ("image", "save"):
            output_argument = next(value for value in command if value.startswith("--output="))
            output = Path(output_argument.removeprefix("--output="))
            config = self.config + (b" " if self.tamper_saved_config else b"")
            _write_saved_image_archive(
                output,
                config=config,
                config_name=f"{self.image_id.removeprefix('sha256:')}.json",
                repo_tags=sorted(self.tags),
                layer=self.layer,
            )
            return self._completed(command)
        if command[1:3] == ("image", "rm"):
            reference = command[3]
            if reference in self.tags:
                del self.tags[reference]
            elif reference == self.image_id:
                self.image_present = False
            return self._completed(command)
        pytest.fail(f"unexpected Docker command: {command}")


def test_plan_bundle_uses_exact_commit_not_dirty_worktree_and_is_deterministic(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    (repository / "tracked.txt").write_text("dirty-worktree-change\n", encoding="utf-8")
    (repository / "dirty-only.txt").write_text("must-not-leak\n", encoding="utf-8")
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    original_run = bundler._run

    def no_docker(*args: str, **kwargs: Any) -> Any:
        if args and args[0] == "docker":
            pytest.fail("plan-only mode must not invoke Docker")
        return original_run(*args, **kwargs)

    monkeypatch.setattr(bundler, "_run", no_docker)
    first_output = tmp_path / "bundle-one"
    second_output = tmp_path / "bundle-two"

    first = bundler.build_bundle(
        first_output,
        commit_reference=commit,
        plan_only=True,
    )
    second = bundler.build_bundle(
        second_output,
        commit_reference=commit,
        plan_only=True,
    )

    assert first == second
    assert (first_output / "manifest.json").read_bytes() == bundler._canonical_bytes(
        first
    ) + b"\n"
    assert (first_output / "manifest.json").read_bytes() == (
        second_output / "manifest.json"
    ).read_bytes()
    assert {path.name for path in first_output.iterdir()} == {
        "manifest.json",
        "source.tar",
    }
    assert first["accepted_deploy_bundle"] is False
    assert first["application_image"]["image_built"] is False
    assert first["application_image"]["build_invocations"] == 0
    assert first["application_image"]["tag"] is None
    assert first["build_contract"]["tag_policy"] == (
        "untagged_load_saved_by_immutable_image_id"
    )
    assert first["source"]["git_commit"] == commit
    assert first["source"]["mutable_worktree_used"] is False
    assert set(first["source"]["archived_inputs"]) == set(
        bundler.REQUIRED_ARCHIVED_FILES
    )
    assert first["source"]["topology_contract"] == {
        "schema_version": "aegis-ot-m4j-topology-v1",
        "deployment_status": "configuration_only",
        "claim_boundary": "no_live_deployment_or_multi_host_isolation_evidence",
        "node_count": 6,
        "network_count": 5,
        "contract_validated": True,
    }
    assert first["source"]["archive"]["sha256"] == second["source"]["archive"][
        "sha256"
    ]
    assert "@sha256:" in first["build_contract"]["pinned_base_image"]
    with tarfile.open(first_output / "source.tar", mode="r:") as archive:
        names = set(archive.getnames())
        tracked = archive.extractfile("tracked.txt")
        assert tracked is not None
        assert tracked.read() == b"committed-source\n"
    assert "dirty-only.txt" not in names
    assert "single_build" in first["distribution_boundary"]
    assert "distribute_identical_image" in first["distribution_boundary"]
    assert first["build_contract"]["docker_build_secret_mount_count"] == 0
    assert "secrets_consumed" not in first["build_contract"]


def test_selected_commit_without_m4j_topology_fails_without_partial_output(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    older_commit = _repository(bundler, repository, topology=False)
    topology = repository / "infra" / "m4j" / "topology.yml"
    topology.parent.mkdir(parents=True)
    topology.write_bytes(
        (Path(__file__).parents[1] / "infra" / "m4j" / "topology.yml").read_bytes()
    )
    _commit(bundler, repository, "add topology")
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    output = tmp_path / "old-bundle"

    with pytest.raises(bundler.BundleError, match="artifact is unavailable"):
        bundler.build_bundle(output, commit_reference=older_commit, plan_only=True)

    assert not output.exists()
    assert not tuple(tmp_path.glob(".old-bundle.m4j-*"))


def test_source_archive_tamper_and_unsafe_members_are_rejected(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    original_extract = bundler._safe_extract_source

    def tamper(archive: Path, destination: Path) -> tuple[str, ...]:
        result = cast(tuple[str, ...], original_extract(archive, destination))
        with archive.open("ab") as handle:
            handle.write(b"tampered-after-validation")
        return result

    monkeypatch.setattr(bundler, "_safe_extract_source", tamper)
    with pytest.raises(bundler.BundleError, match="changed during extraction"):
        bundler._export_source(
            commit=commit,
            archive_path=tmp_path / "tampered.tar",
            context=tmp_path / "tampered-context",
        )

    unsafe = tmp_path / "unsafe.tar"
    with tarfile.open(unsafe, mode="w") as archive:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(bundler.BundleError, match="path is unsafe"):
        original_extract(unsafe, tmp_path / "unsafe-context")
    assert not (tmp_path / "escape").exists()

    streamed = tmp_path / "streamed.tar"
    with tarfile.open(streamed, mode="w") as archive:
        member = tarfile.TarInfo("one.txt")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    monkeypatch.setattr(
        tarfile.TarFile,
        "getmembers",
        lambda self: pytest.fail("source extraction must stream the member cap"),
    )
    assert original_extract(streamed, tmp_path / "streamed-context") == ("one.txt",)
    capped = tmp_path / "capped.tar"
    with tarfile.open(capped, mode="w") as archive:
        for name in ("one.txt", "two.txt"):
            member = tarfile.TarInfo(name)
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
    monkeypatch.setattr(bundler, "MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(bundler.BundleError, match="member count"):
        original_extract(capped, tmp_path / "capped-context")


def test_source_archive_tree_binding_rejects_rehashed_extra_directory(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    output = tmp_path / "plan-bundle"
    manifest = bundler.build_bundle(
        output,
        commit_reference=commit,
        plan_only=True,
    )
    source_archive = output / "source.tar"
    with tarfile.open(source_archive, mode="a") as archive:
        extra = tarfile.TarInfo("extra-empty")
        extra.type = tarfile.DIRTYPE
        extra.mode = 0o755
        archive.addfile(extra)

    with pytest.raises(bundler.BundleError, match="directory members"):
        bundler._validate_source_archive_binding(
            source_archive,
            expected_commit=commit,
            source_binding=manifest["source"],
        )


def test_unpinned_base_and_existing_or_symlink_outputs_are_rejected(
    bundler: Any,
    tmp_path: Path,
) -> None:
    with pytest.raises(bundler.BundleError, match="malformed or unknown"):
        bundler._resolve_commit("unknown")
    with pytest.raises(bundler.BundleError, match="malformed or unknown"):
        bundler._resolve_commit(" --malformed")

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "ARG PYTHON_IMAGE=python:latest\nFROM ${PYTHON_IMAGE}\n",
        encoding="utf-8",
    )
    with pytest.raises(bundler.BundleError, match="not digest-pinned"):
        bundler._pinned_base_image(dockerfile)

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(bundler.BundleError, match="overwrite"):
        bundler._validate_output_target(existing)
    symlink = tmp_path / "bundle-link"
    symlink.symlink_to(existing, target_is_directory=True)
    with pytest.raises(bundler.BundleError, match="overwrite"):
        bundler._validate_output_target(symlink)


def test_topology_contract_is_validated_not_only_hashed(
    bundler: Any,
    tmp_path: Path,
) -> None:
    topology = tmp_path / "topology.yml"
    topology.write_bytes(
        (Path(__file__).parents[1] / "infra" / "m4j" / "topology.yml").read_bytes()
    )
    assert bundler._validate_m4j_topology(topology)["contract_validated"] is True
    topology.write_text(
        topology.read_text(encoding="utf-8").replace(
            "application_bindings_allowed: false",
            "application_bindings_allowed: true",
        ),
        encoding="utf-8",
    )
    with pytest.raises(bundler.BundleError, match="bootstrap NAT contract"):
        bundler._validate_m4j_topology(topology)


def test_saved_archive_is_cryptographically_bound_to_image_config(
    bundler: Any,
    tmp_path: Path,
) -> None:
    commit = "a" * 40
    config = _image_config(commit)
    archive = tmp_path / "application-image.tar"
    image_id = _write_saved_image_archive(archive, config=config)

    binding = bundler._validate_saved_image_archive(
        archive,
        expected_image_id=image_id,
        expected_commit=commit,
        expected_platform=bundler._target_platform("linux/amd64"),
    )

    assert binding["config_sha256"] == image_id.removeprefix("sha256:")
    assert binding["oci_revision"] == commit
    assert binding["platform"] == {
        "os": "linux",
        "architecture": "amd64",
        "variant": None,
    }
    assert binding["image_id_binding"]["kind"] == "legacy_config_digest"
    assert binding["image_id_binding"]["verified_layers"][0][
        "digest_semantics"
    ] == "uncompressed_diff_id"

    compressed_layer = b"compressed-fixture-layer"
    compressed_config = _image_config(commit, layer=compressed_layer)
    compressed_archive = tmp_path / "application-image-gzip.tar"
    compressed_image_id = _write_saved_image_archive(
        compressed_archive,
        config=compressed_config,
        layer=gzip.compress(compressed_layer, mtime=0),
    )
    compressed_binding = bundler._validate_saved_image_archive(
        compressed_archive,
        expected_image_id=compressed_image_id,
        expected_commit=commit,
        expected_platform=bundler._target_platform("linux/amd64"),
    )
    assert compressed_binding["image_id_binding"]["verified_layers"][0][
        "storage_encoding"
    ] == "gzip"

    oci_archive = tmp_path / "application-image-oci.tar"
    oci_image_id, oci_config_digest = _write_oci_saved_image_archive(
        oci_archive,
        commit=commit,
    )
    oci_binding = bundler._validate_saved_image_archive(
        oci_archive,
        expected_image_id=oci_image_id,
        expected_commit=commit,
        expected_platform=bundler._target_platform("linux/amd64"),
    )
    assert oci_binding["config_sha256"] == oci_config_digest
    assert oci_binding["image_id_binding"]["kind"] == "oci_descriptor_chain"
    assert oci_binding["image_id_binding"]["root_digest"] == (
        oci_image_id.removeprefix("sha256:")
    )
    assert oci_binding["image_id_binding"]["root_media_type"] == (
        "application/vnd.oci.image.index.v1+json"
    )
    assert oci_binding["image_id_binding"]["verified_layers"][0][
        "digest_semantics"
    ] == "stored_descriptor_digest"
    wrong_diff_id = tmp_path / "wrong-oci-diff-id.tar"
    wrong_diff_id_image, _ = _write_oci_saved_image_archive(
        wrong_diff_id,
        commit=commit,
        config_layer=b"different-uncompressed-layer",
    )
    with pytest.raises(bundler.BundleError, match="uncompressed diff ID digest"):
        bundler._validate_saved_image_archive(
            wrong_diff_id,
            expected_image_id=wrong_diff_id_image,
            expected_commit=commit,
            expected_platform=bundler._target_platform("linux/amd64"),
        )
    tampered = tmp_path / "tampered-image.tar"
    _write_saved_image_archive(
        tampered,
        config=config + b" ",
        config_name=f"{image_id.removeprefix('sha256:')}.json",
    )
    with pytest.raises(bundler.BundleError, match="config digest"):
        bundler._validate_saved_image_archive(
            tampered,
            expected_image_id=image_id,
            expected_commit=commit,
            expected_platform=bundler._target_platform("linux/amd64"),
        )

    tampered_layer = tmp_path / "tampered-layer.tar"
    _write_saved_image_archive(
        tampered_layer,
        config=config,
        layer=b"tampered-byte",
    )
    with pytest.raises(bundler.BundleError, match="uncompressed diff ID digest"):
        bundler._validate_saved_image_archive(
            tampered_layer,
            expected_image_id=image_id,
            expected_commit=commit,
            expected_platform=bundler._target_platform("linux/amd64"),
        )

    tampered_oci = tmp_path / "tampered-oci-layer.tar"
    tampered_oci_image_id, _ = _write_oci_saved_image_archive(
        tampered_oci,
        commit=commit,
        stored_layer=b"x" * len(b"fixture-oci-layer"),
    )
    with pytest.raises(bundler.BundleError, match="descriptor digest"):
        bundler._validate_saved_image_archive(
            tampered_oci,
            expected_image_id=tampered_oci_image_id,
            expected_commit=commit,
            expected_platform=bundler._target_platform("linux/amd64"),
        )

    missing_rootfs_document = json.loads(config)
    del missing_rootfs_document["rootfs"]
    missing_rootfs_config = json.dumps(
        missing_rootfs_document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    missing_rootfs = tmp_path / "missing-rootfs.tar"
    missing_rootfs_id = _write_saved_image_archive(
        missing_rootfs,
        config=missing_rootfs_config,
    )
    with pytest.raises(bundler.BundleError, match="rootfs must be"):
        bundler._validate_saved_image_archive(
            missing_rootfs,
            expected_image_id=missing_rootfs_id,
            expected_commit=commit,
            expected_platform=bundler._target_platform("linux/amd64"),
        )


def test_saved_archive_canonicalization_removes_unreferenced_payloads(
    bundler: Any,
    tmp_path: Path,
) -> None:
    commit = "a" * 40
    config = _image_config(commit)
    archive_path = tmp_path / "image.tar"
    image_id = _write_saved_image_archive(archive_path, config=config)
    with tarfile.open(archive_path, mode="a") as archive:
        material = b'{"untrusted":"ancillary"}'
        member = tarfile.TarInfo("repositories")
        member.size = len(material)
        archive.addfile(member, io.BytesIO(material))

    with pytest.raises(bundler.BundleError, match="unreferenced members"):
        bundler._validate_saved_image_archive(
            archive_path,
            expected_image_id=image_id,
            expected_commit=commit,
            expected_platform=bundler._target_platform("linux/amd64"),
        )
    binding = bundler._canonicalize_saved_image_archive(
        archive_path,
        expected_image_id=image_id,
        expected_commit=commit,
        expected_platform=bundler._target_platform("linux/amd64"),
    )
    assert "repositories" not in binding["reachable_members"]
    with tarfile.open(archive_path, mode="r:") as archive:
        assert "repositories" not in archive.getnames()


def test_docker_image_presence_distinguishes_not_found_from_daemon_failure(
    bundler: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tag = "aegis-ot-m4j:fixture"

    def result(*, stderr: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=("docker",),
            returncode=1,
            stdout="[]\n",
            stderr=stderr,
        )

    monkeypatch.setattr(
        bundler,
        "_run",
        lambda *args, **kwargs: result(
            stderr=f"Error response from daemon: No such image: {tag}\n"
        ),
    )
    assert bundler._docker_image_document_if_present(tag) is None
    monkeypatch.setattr(
        bundler,
        "_run",
        lambda *args, **kwargs: result(
            stderr="permission denied while trying to connect to Docker\n"
        ),
    )
    with pytest.raises(bundler.BundleError, match="could not be established"):
        bundler._docker_image_document_if_present(tag)


def test_docker_daemon_buildx_and_buildkit_provenance_is_recorded(
    bundler: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker_version = {
        "Client": {
            "Version": "29.7.2",
            "GitCommit": "client-commit",
            "Os": "darwin",
            "Arch": "arm64",
        },
        "Server": {
            "Version": "29.7.2",
            "GitCommit": "server-commit",
            "Os": "linux",
            "Arch": "arm64",
            "Platform": {"Name": "Docker Desktop fixture"},
        },
    }

    def fake_run(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        command = tuple(args)
        if command[1:3] == ("version", "--format"):
            stdout = json.dumps(docker_version)
        elif command[1:3] == ("buildx", "version"):
            stdout = "github.com/docker/buildx v0.36.1 fixture\n"
        elif command[1:3] == ("info", "--format"):
            stdout = json.dumps(
                {
                    "ID": "daemon-id",
                    "Name": "daemon-name",
                    "Driver": "overlay2",
                    "ServerVersion": "29.7.2",
                    "OSType": "linux",
                    "Architecture": "arm64",
                    "SecurityOptions": ["name=seccomp,profile=builtin"],
                }
            )
        elif command[1:3] == ("buildx", "inspect"):
            stdout = (
                "Name: fixture-builder\n"
                "Driver: docker-container\n\n"
                "Nodes:\n"
                "Name: fixture-node\n"
                "Endpoint: unix:///fixture/buildkit.sock\n"
                "Status: running\n"
                "BuildKit version: v0.32.2\n"
                "Platforms: linux/arm64, linux/amd64\n"
            )
        else:
            pytest.fail(f"unexpected provenance command: {command}")
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(bundler, "_run", fake_run)

    profile = bundler._builder_execution_profile(
        {
            "client": {
                "path": "/usr/local/bin/docker",
                "sha256": "a" * 64,
                "size_bytes": 100,
                "uid": 0,
                "gid": 0,
                "mode": "0755",
            },
            "buildx_plugin": {
                "path": "/usr/local/lib/docker/cli-plugins/docker-buildx",
                "sha256": "b" * 64,
                "size_bytes": 200,
                "uid": 0,
                "gid": 0,
                "mode": "0755",
            },
            "endpoint": {
                "transport": "unix",
                "path": "/var/run/docker.sock",
                "uid": 0,
                "gid": 0,
                "mode": "0660",
            },
            "environment": {
                "DOCKER_CONFIG": "/private/empty",
                "PATH": "/usr/bin:/bin",
            },
        }
    )

    assert profile["docker_client"]["reported_version"] == "29.7.2"
    assert profile["docker_client"]["execution"] == "private_exact_byte_copy"
    assert profile["docker_buildx_plugin"] == {
        "path": "/usr/local/lib/docker/cli-plugins/docker-buildx",
        "sha256": "b" * 64,
        "size_bytes": 200,
        "uid": 0,
        "gid": 0,
        "mode": "0755",
        "execution": "private_exact_byte_copy",
    }
    assert profile["daemon"]["id"] == "daemon-id"
    assert profile["daemon"]["platform_name"] == "Docker Desktop fixture"
    assert profile["buildkit"]["builder_name"] == "fixture-builder"
    assert profile["buildkit"]["driver"] == "docker-container"
    assert profile["buildkit"]["nodes"] == [
        {
            "name": "fixture-node",
            "endpoint": "unix:///fixture/buildkit.sock",
            "status": "running",
            "buildkit_version": "v0.32.2",
            "platforms": ["linux/amd64", "linux/arm64"],
        }
    ]
    versions = bundler._docker_tool_versions(profile)
    assert versions["docker_buildx_driver"] == "docker-container"
    assert versions["buildkit_worker"] == "v0.32.2"


def test_closed_docker_boundary_excludes_hostile_ambient_inputs(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    (
        client,
        client_sha256,
        buildx_plugin,
        buildx_plugin_sha256,
        socket_path,
        _endpoint,
    ) = _docker_boundary_materials(tmp_path, request)
    for name, value in {
        "DOCKER_HOST": "tcp://attacker.invalid:2375",
        "DOCKER_CONTEXT": "attacker",
        "DOCKER_CONFIG": "/attacker/docker-config",
        "BUILDX_CONFIG": "/attacker/buildx-config",
        "DOCKER_CLI_PLUGIN_EXTRA_DIRS": "/attacker/plugins",
        "HTTP_PROXY": "http://attacker.invalid",
        "HTTPS_PROXY": "http://attacker.invalid",
        "ALL_PROXY": "socks5://attacker.invalid",
        "PATH": "/attacker/bin",
    }.items():
        monkeypatch.setenv(name, value)
    observed: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def capture_run(command: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append((command, kwargs["env"]))
        return subprocess.CompletedProcess(command, 0, "ok\n", "")

    monkeypatch.setattr(bundler.subprocess, "run", capture_run)
    with bundler._closed_docker_boundary(
        client_path=client,
        expected_client_sha256=client_sha256,
        buildx_plugin_path=buildx_plugin,
        expected_buildx_plugin_sha256=buildx_plugin_sha256,
        socket_path=socket_path,
    ) as boundary:
        bundler._run("docker", "version")
        bundler._run("docker", "buildx", "version")
        staged_client = boundary["client_execution_path"]
        staged_plugin = boundary["buildx_plugin_path"]

    command, environment = observed[0]
    assert command[0] == str(staged_client)
    assert command[0] != str(client)
    assert command[1:3] == ("--config", environment["DOCKER_CONFIG"])
    assert command[3:5] == ("--host", f"unix://{socket_path}")
    assert command[5:] == ("version",)
    plugin_command, plugin_environment = observed[1]
    assert plugin_command == (str(staged_plugin), "version")
    assert plugin_environment == environment
    assert environment["PATH"] == "/usr/bin:/bin"
    assert environment["DOCKER_HOST"] == f"unix://{socket_path}"
    assert set(environment) == {
        "BUILDX_CONFIG",
        "DOCKER_BUILDKIT",
        "DOCKER_CONFIG",
        "DOCKER_HOST",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "TMPDIR",
    }


def test_closed_docker_boundary_detects_client_byte_drift(
    bundler: Any,
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    (
        client,
        client_sha256,
        buildx_plugin,
        buildx_plugin_sha256,
        socket_path,
        _endpoint,
    ) = _docker_boundary_materials(tmp_path, request)
    with pytest.raises(bundler.BundleError, match="client bytes differ"):
        with bundler._closed_docker_boundary(
            client_path=client,
            expected_client_sha256=client_sha256,
            buildx_plugin_path=buildx_plugin,
            expected_buildx_plugin_sha256=buildx_plugin_sha256,
            socket_path=socket_path,
        ):
            client.write_text("#!/bin/sh\nexit 99\n", encoding="ascii")


def test_closed_docker_boundary_detects_buildx_plugin_byte_drift(
    bundler: Any,
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    (
        client,
        client_sha256,
        buildx_plugin,
        buildx_plugin_sha256,
        socket_path,
        _endpoint,
    ) = _docker_boundary_materials(tmp_path, request)
    with pytest.raises(bundler.BundleError, match="Buildx plugin bytes differ"):
        with bundler._closed_docker_boundary(
            client_path=client,
            expected_client_sha256=client_sha256,
            buildx_plugin_path=buildx_plugin,
            expected_buildx_plugin_sha256=buildx_plugin_sha256,
            socket_path=socket_path,
        ):
            buildx_plugin.write_text("#!/bin/sh\nexit 99\n", encoding="ascii")


def test_docker_client_under_world_writable_parent_executes_only_private_copy(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    unsafe_root = Path(
        tempfile.mkdtemp(
            prefix=".m4jb-unsafe-client-",
            dir=Path(__file__).parents[1],
        )
    )
    request.addfinalizer(lambda: shutil.rmtree(unsafe_root, ignore_errors=True))
    unsafe_root.chmod(0o777)
    client = unsafe_root / "docker"
    client.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    client.chmod(0o700)
    trusted_client = client.read_bytes()
    digest = hashlib.sha256(trusted_client).hexdigest()
    (
        _safe_client,
        _safe_client_sha256,
        buildx_plugin,
        buildx_plugin_sha256,
        socket_path,
        _endpoint,
    ) = _docker_boundary_materials(tmp_path, request)
    observed: list[tuple[str, ...]] = []

    def capture_run(
        command: tuple[str, ...],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        observed.append(command)
        return subprocess.CompletedProcess(command, 0, "ok\n", "")

    monkeypatch.setattr(bundler.subprocess, "run", capture_run)
    with pytest.raises(bundler.BundleError, match="client bytes differ"):
        with bundler._closed_docker_boundary(
            client_path=client,
            expected_client_sha256=digest,
            buildx_plugin_path=buildx_plugin,
            expected_buildx_plugin_sha256=buildx_plugin_sha256,
            socket_path=socket_path,
        ) as boundary:
            staged_client = cast(Path, boundary["client_execution_path"])
            client.rename(unsafe_root / "trusted-client-replaced")
            client.write_text("#!/bin/sh\nexit 99\n", encoding="ascii")
            client.chmod(0o700)
            bundler._run("docker", "version")
            assert staged_client.read_bytes() == trusted_client
            assert stat.S_IMODE(staged_client.parent.stat().st_mode) == 0o700

    assert observed[0][0] == str(staged_client)
    assert observed[0][0] != str(client)


def test_docker_socket_rejects_nonsticky_world_writable_parent(
    bundler: Any,
    request: pytest.FixtureRequest,
) -> None:
    unsafe_root = Path(
        tempfile.mkdtemp(
            prefix=".m4jb-unsafe-socket-",
            dir=Path(__file__).parents[1],
        )
    )
    request.addfinalizer(lambda: shutil.rmtree(unsafe_root, ignore_errors=True))
    unsafe_root.chmod(0o777)
    socket_path = unsafe_root / "docker.sock"
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    endpoint.bind(str(socket_path))
    request.addfinalizer(endpoint.close)

    with pytest.raises(bundler.BundleError, match="path ancestry"):
        bundler._docker_socket_identity(socket_path)


def test_builder_helper_must_match_exact_archived_source(
    bundler: Any,
    tmp_path: Path,
) -> None:
    helper = tmp_path / "scripts" / "build_m4j_bundle.py"
    helper.parent.mkdir()
    helper.write_text("raise SystemExit('foreign helper')\n", encoding="utf-8")
    with pytest.raises(bundler.BundleError, match="exact source commit"):
        bundler._builder_helper_binding(tmp_path, object_format="sha1")


def test_atomic_publication_refuses_race_created_empty_directory(
    bundler: Any,
    tmp_path: Path,
) -> None:
    staged = tmp_path / ".staged"
    staged.mkdir()
    (staged / "manifest.json").write_text("staged\n", encoding="utf-8")
    output = tmp_path / "bundle"
    output.mkdir()
    (output / "racer-owned").write_text("preserve\n", encoding="utf-8")

    with pytest.raises(bundler.BundleError, match="overwrite"):
        bundler._publish_directory_noreplace(staged, output)

    assert (output / "racer-owned").read_text(encoding="utf-8") == "preserve\n"
    assert staged.is_dir()


def test_cleanup_removes_only_unreferenced_invocation_owned_image(
    bundler: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "a" * 40
    fake = _FakeDocker(bundler, bundler._run, commit=commit)
    invocation_id = "1" * 64
    fake.invocation_id = invocation_id
    fake.config = _image_config(
        commit,
        layer=fake.layer,
        invocation_id=invocation_id,
    )
    fake.image_id = f"sha256:{hashlib.sha256(fake.config).hexdigest()}"
    shared_tag = "shared:fixture"
    fake.image_present = True
    fake.tags = {shared_tag: fake.image_id}
    monkeypatch.setattr(bundler, "_run", fake.run)

    bundler._cleanup_invocation_owned_image(
        image_id=fake.image_id,
        invocation_id=invocation_id,
    )

    removal_calls = [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert removal_calls == []
    assert fake.tags == {shared_tag: fake.image_id}
    assert fake.image_present is True

    fake.tags = {}
    bundler._cleanup_invocation_owned_image(
        image_id=fake.image_id,
        invocation_id=invocation_id,
    )
    removal_calls = [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert removal_calls == [("docker", "image", "rm", fake.image_id)]
    assert fake.image_present is False

    fake.image_present = True
    with pytest.raises(bundler.BundleError, match="ownership changed"):
        bundler._cleanup_invocation_owned_image(
            image_id=fake.image_id,
            invocation_id="2" * 64,
        )
    assert fake.image_present is True


@pytest.mark.parametrize(
    ("image_id", "revision", "error"),
    (
        ("", "a" * 40, "ID is empty or malformed"),
        ("sha256:" + "b" * 64, "c" * 40, "OCI revision"),
    ),
)
def test_docker_inspect_rejects_wrong_image_id_or_revision(
    bundler: Any,
    monkeypatch: pytest.MonkeyPatch,
    image_id: str,
    revision: str,
    error: str,
) -> None:
    expected_commit = "a" * 40
    tag = "aegis-ot-m4j:test-bound-tag"
    inspection = [
        {
            "Id": image_id,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Labels": {bundler.OCI_REVISION_LABEL: revision}},
            "RepoTags": [tag],
            "RepoDigests": [],
        }
    ]
    monkeypatch.setattr(
        bundler,
        "_run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(inspection)),
    )

    with pytest.raises(bundler.BundleError, match=error):
        bundler._inspect_image(
            tag,
            expected_commit=expected_commit,
            expected_platform=bundler._target_platform("linux/amd64"),
            expected_tag=tag,
        )


def test_manifest_binds_one_built_image_archive_and_exact_source(
    bundler: Any,
) -> None:
    signer = Ed25519PrivateKey.generate()
    revision = {
        "requested_reference": "release",
        "commit": "a" * 40,
        "tree": "b" * 40,
        "object_format": "sha1",
        "commit_object_base64": "Zml4dHVyZQ==",
        "committed_at": "2026-08-25T12:00:00+00:00",
    }
    source = {
        "archive": {"path": "source.tar", "sha256": "c" * 64, "size_bytes": 1},
        "archived_file_count": 4,
        "archived_inputs": {
            path: {"sha256": "d" * 64, "size_bytes": 1}
            for path in bundler.REQUIRED_ARCHIVED_FILES
        },
        "pinned_base_image": "python:3.13@sha256:" + "e" * 64,
        "topology_contract": {
            "schema_version": "aegis-ot-m4j-topology-v1",
            "deployment_status": "configuration_only",
            "claim_boundary": "no_live_deployment_or_multi_host_isolation_evidence",
            "node_count": 6,
            "network_count": 5,
            "contract_validated": True,
        },
        "secret_like_member_count": 0,
        "tree_binding": {
            "git_object_format": "sha1",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "archive_tree_sha": "b" * 40,
        },
    }
    image = {
        "image_built": True,
        "build_invocations": 1,
        "tag": None,
        "image_id": "sha256:" + "f" * 64,
        "build_invocation": "1" * 64,
        "repo_digests": ["aegis-ot-m4j@sha256:" + "0" * 64],
        "oci_revision": "a" * 40,
        "platform": {"os": "linux", "architecture": "amd64", "variant": None},
        "archive": {
            "path": "application-image.tar",
            "sha256": "1" * 64,
            "size_bytes": 2,
        },
        "archive_binding": {
            "format": "docker-image-save-v1",
            "config_sha256": "f" * 64,
        },
    }
    target = bundler._target_platform("linux/amd64")
    builder_helper = {
        "path": "scripts/build_m4j_bundle.py",
        "sha256": "2" * 64,
        "size_bytes": 1,
        "git_object_format": "sha1",
        "git_blob_id": "3" * 40,
    }
    builder_profile = {
        "schema_version": "aegis-ot-m4j-builder-execution-profile-v1",
        "fixture": True,
    }

    first = bundler._manifest(
        revision=revision,
        source=source,
        image=image,
        target=target,
        tools=_fixed_tools(),
        plan_only=False,
        builder_helper=builder_helper,
        builder_profile=builder_profile,
        builder_signer=signer,
        builder_public_key=signer.public_key().public_bytes_raw(),
    )
    second = bundler._manifest(
        revision=revision,
        source=source,
        image=image,
        target=target,
        tools=_fixed_tools(),
        plan_only=False,
        builder_helper=builder_helper,
        builder_profile=builder_profile,
        builder_signer=signer,
        builder_public_key=signer.public_key().public_bytes_raw(),
    )

    assert bundler._canonical_bytes(first) == bundler._canonical_bytes(second)
    assert first["accepted_deploy_bundle"] is True
    assert first["source"]["git_commit"] == "a" * 40
    assert first["source"]["git_tree"] == "b" * 40
    assert first["application_image"]["archive"]["sha256"] == "1" * 64
    assert first["application_image"]["build_invocations"] == 1
    assert first["build_contract"]["docker_build_secret_mount_count"] == 0


def test_mocked_build_constructs_once_saves_by_id_and_atomically_publishes(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    fake = _FakeDocker(bundler, bundler._run, commit=commit)
    monkeypatch.setattr(bundler, "_run", fake.run)
    output = tmp_path / "accepted-bundle"
    signing_key, _public_key = _builder_key(tmp_path)
    boundary, _endpoint = _builder_boundary(bundler, tmp_path, request)

    manifest = bundler.build_bundle(
        output,
        commit_reference=commit,
        builder_signing_key=signing_key,
        **boundary,
    )

    build_calls = [call for call in fake.calls if call[1:3] == ("buildx", "build")]
    save_calls = [call for call in fake.calls if call[1:3] == ("image", "save")]
    assert len(build_calls) == 1
    assert len(save_calls) == 1
    assert save_calls[0][-1] == fake.image_id
    assert build_calls[0].count("--provenance=false") == 1
    assert "--secret" not in build_calls[0]
    assert "--tag" not in build_calls[0]
    assert "--label" in build_calls[0]
    assert manifest["accepted_deploy_bundle"] is True
    assert manifest["application_image"]["build_invocations"] == 1
    assert manifest["application_image"]["image_id"] == fake.image_id
    assert manifest["application_image"]["tag"] is None
    assert manifest["build_contract"]["tag_policy"] == (
        "untagged_load_saved_by_immutable_image_id"
    )
    assert manifest["build_contract"]["buildkit_default_provenance"] == (
        "disabled_replaced_by_signed_aegis_attestation"
    )
    assert manifest["application_image"]["archive_binding"]["config_sha256"] == (
        fake.image_id.removeprefix("sha256:")
    )
    assert manifest["source"]["topology_contract"]["contract_validated"] is True
    assert {path.name for path in output.iterdir()} == {
        "application-image.tar",
        "manifest.json",
        "source.tar",
    }
    retained = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert retained == manifest


def test_build_refuses_unreviewed_live_builder_profile_before_image_build(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    fake = _FakeDocker(bundler, bundler._run, commit=commit)
    monkeypatch.setattr(bundler, "_run", fake.run)
    signing_key, _public_key = _builder_key(tmp_path)
    boundary, _endpoint = _builder_boundary(bundler, tmp_path, request)
    boundary["expected_builder_profile_sha256"] = "0" * 64

    with pytest.raises(bundler.BundleError, match="separately reviewed"):
        bundler.build_bundle(
            tmp_path / "unreviewed-profile-bundle",
            commit_reference=commit,
            builder_signing_key=signing_key,
            **boundary,
        )

    assert not [call for call in fake.calls if call[1:3] == ("buildx", "build")]


def test_mocked_post_build_failure_cleans_only_owned_image_for_retry(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    fake = _FakeDocker(
        bundler,
        bundler._run,
        commit=commit,
        tamper_saved_config=True,
    )
    monkeypatch.setattr(bundler, "_run", fake.run)
    output = tmp_path / "failed-bundle"
    signing_key, _public_key = _builder_key(tmp_path)
    boundary, _endpoint = _builder_boundary(bundler, tmp_path, request)

    with pytest.raises(bundler.BundleError, match="config digest"):
        bundler.build_bundle(
            output,
            commit_reference=commit,
            builder_signing_key=signing_key,
            **boundary,
        )

    build_calls = [call for call in fake.calls if call[1:3] == ("buildx", "build")]
    removal_calls = [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert len(build_calls) == 1
    assert removal_calls == [("docker", "image", "rm", fake.image_id)]
    assert fake.tags == {}
    assert fake.image_present is False
    assert not output.exists()
    assert not tuple(tmp_path.glob(".failed-bundle.m4j-*"))

    fake.tamper_saved_config = False
    retry = bundler.build_bundle(
        output,
        commit_reference=commit,
        builder_signing_key=signing_key,
        **boundary,
    )
    assert retry["accepted_deploy_bundle"] is True
    assert len(
        [call for call in fake.calls if call[1:3] == ("buildx", "build")]
    ) == 2


def test_mocked_malformed_iid_cleans_untagged_owned_image_for_retry(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    fake = _FakeDocker(
        bundler,
        bundler._run,
        commit=commit,
        malformed_iid=True,
    )
    monkeypatch.setattr(bundler, "_run", fake.run)
    output = tmp_path / "bad-iid-bundle"
    signing_key, _public_key = _builder_key(tmp_path)
    boundary, _endpoint = _builder_boundary(bundler, tmp_path, request)

    with pytest.raises(bundler.BundleError, match="immutable ID"):
        bundler.build_bundle(
            output,
            commit_reference=commit,
            builder_signing_key=signing_key,
            **boundary,
        )

    removal_calls = [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert removal_calls == [("docker", "image", "rm", fake.image_id)]
    assert fake.image_present is False
    assert not output.exists()

    fake.malformed_iid = False
    retry = bundler.build_bundle(
        output,
        commit_reference=commit,
        builder_signing_key=signing_key,
        **boundary,
    )
    assert retry["accepted_deploy_bundle"] is True
    assert len(
        [call for call in fake.calls if call[1:3] == ("buildx", "build")]
    ) == 2


def test_untagged_cleanup_refuses_foreign_invocation_label_collision(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    fake = _FakeDocker(
        bundler,
        bundler._run,
        commit=commit,
        malformed_iid=True,
    )
    foreign_id = "sha256:" + "e" * 64

    def raced_run(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        command = tuple(args)
        if command[1:3] == ("image", "ls"):
            return subprocess.CompletedProcess(command, 0, foreign_id + "\n", "")
        if command[1:3] == ("image", "inspect") and command[3] == foreign_id:
            document = [
                {
                    "Id": foreign_id,
                    "Os": "linux",
                    "Architecture": "amd64",
                    "Config": {
                        "Labels": {
                            bundler.OCI_REVISION_LABEL: commit,
                            bundler.BUILD_INVOCATION_LABEL: "f" * 64,
                        }
                    },
                    "RepoTags": ["foreign:owned"],
                    "RepoDigests": [],
                }
            ]
            return subprocess.CompletedProcess(command, 0, json.dumps(document), "")
        return fake.run(*args, **kwargs)

    monkeypatch.setattr(bundler, "_run", raced_run)
    output = tmp_path / "foreign-race-bundle"
    signing_key, _public_key = _builder_key(tmp_path)
    boundary, _endpoint = _builder_boundary(bundler, tmp_path, request)

    with pytest.raises(bundler.BundleError, match="refusing destructive cleanup"):
        bundler.build_bundle(
            output,
            commit_reference=commit,
            builder_signing_key=signing_key,
            **boundary,
        )

    assert not [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert not output.exists()


def test_mocked_publication_race_after_build_cleans_owned_docker_state(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    fake = _FakeDocker(bundler, bundler._run, commit=commit)
    monkeypatch.setattr(bundler, "_run", fake.run)
    original_publish = bundler._publish_directory_noreplace
    output = tmp_path / "raced-bundle"

    def race_publication(staging: Path, destination: Path) -> None:
        destination.mkdir()
        (destination / "racer-owned").write_text("preserve\n", encoding="utf-8")
        original_publish(staging, destination)

    monkeypatch.setattr(bundler, "_publish_directory_noreplace", race_publication)
    signing_key, _public_key = _builder_key(tmp_path)
    boundary, _endpoint = _builder_boundary(bundler, tmp_path, request)

    with pytest.raises(bundler.BundleError, match="overwrite"):
        bundler.build_bundle(
            output,
            commit_reference=commit,
            builder_signing_key=signing_key,
            **boundary,
        )

    removal_calls = [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert removal_calls == [("docker", "image", "rm", fake.image_id)]
    assert fake.tags == {}
    assert fake.image_present is False
    assert (output / "racer-owned").read_text(encoding="utf-8") == "preserve\n"
    assert not tuple(tmp_path.glob(".raced-bundle.m4j-*"))


def test_consumer_requires_out_of_band_trusted_builder_for_foreign_image(
    bundler: Any,
    workload_validator: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    trusted_private, trusted_public = _builder_key(tmp_path, name="trusted-builder")
    trusted_fake = _FakeDocker(bundler, bundler._run, commit=commit)
    monkeypatch.setattr(bundler, "_run", trusted_fake.run)
    boundary, _endpoint = _builder_boundary(bundler, tmp_path, request)
    trusted_bundle = tmp_path / "trusted-bundle"
    manifest = bundler.build_bundle(
        trusted_bundle,
        commit_reference=commit,
        builder_signing_key=trusted_private,
        **boundary,
    )

    validated = workload_validator._validate_bundle(
        trusted_bundle,
        commit,
        trusted_public,
        boundary["expected_builder_profile_sha256"],
    )
    assert validated["application_image_id"] == trusted_fake.image_id
    assert validated["builder_attestation_key_id"] == hashlib.sha256(
        trusted_public
    ).hexdigest()
    assert manifest["builder_attestation"]["key_id"] == validated[
        "builder_attestation_key_id"
    ]
    with pytest.raises(
        workload_validator.WorkloadContractError,
        match="explicit raw Ed25519",
    ):
        workload_validator._validate_bundle(
            trusted_bundle,
            commit,
            b"",
            boundary["expected_builder_profile_sha256"],
        )
    with pytest.raises(
        workload_validator.WorkloadContractError,
        match="execution profile",
    ):
        workload_validator._validate_bundle(
            trusted_bundle,
            commit,
            trusted_public,
            "0" * 64,
        )

    foreign_private, _foreign_public = _builder_key(tmp_path, name="foreign-builder")
    foreign_fake = _FakeDocker(bundler, bundler._run, commit=commit)
    foreign_fake.layer = b"foreign-image-layer"
    monkeypatch.setattr(bundler, "_run", foreign_fake.run)
    foreign_bundle = tmp_path / "foreign-bundle"
    bundler.build_bundle(
        foreign_bundle,
        commit_reference=commit,
        builder_signing_key=foreign_private,
        **boundary,
    )
    with pytest.raises(
        workload_validator.WorkloadContractError,
        match="trusted-builder provenance",
    ):
        workload_validator._validate_bundle(
            foreign_bundle,
            commit,
            trusted_public,
            boundary["expected_builder_profile_sha256"],
        )


def test_runtime_archive_is_cryptographically_bound_to_registry_manifest(
    runtime_preparer: Any,
    tmp_path: Path,
) -> None:
    layer = b"registry-bound-runtime-layer"
    config = _image_config("a" * 40, layer=layer)
    config_digest = hashlib.sha256(config).hexdigest()
    layer_digest = hashlib.sha256(layer).hexdigest()
    registry_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{config_digest}",
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": f"sha256:{layer_digest}",
                    "size": len(layer),
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    root_digest = "sha256:" + hashlib.sha256(registry_manifest).hexdigest()
    reference = f"registry.example.invalid/runtime:1@{root_digest}"
    root_descriptor = {
        "digest": root_digest,
        "size_bytes": len(registry_manifest),
        "media_type": "application/vnd.oci.image.manifest.v1+json",
        "document_base64": base64.b64encode(registry_manifest).decode("ascii"),
    }
    registry_binding = {
        "schema_version": "aegis-ot-oci-registry-archive-binding-v1",
        "registry_reference": reference,
        "target_platform": "linux/amd64",
        "root_descriptor": root_descriptor,
        "selected_manifest": dict(root_descriptor),
        "config_descriptor": {
            "digest": f"sha256:{config_digest}",
            "size_bytes": len(config),
            "media_type": "application/vnd.oci.image.config.v1+json",
        },
        "layer_descriptors": [
            {
                "digest": f"sha256:{layer_digest}",
                "size_bytes": len(layer),
                "media_type": "application/vnd.oci.image.layer.v1.tar",
            }
        ],
    }
    distribution_tag = "aegis-m4j-runtime/fixture:0123456789abcdef"
    archive_path = tmp_path / "runtime-image.tar"
    image_id = _write_saved_image_archive(
        archive_path,
        config=config,
        repo_tags=[distribution_tag],
        layer=layer,
    )

    binding = runtime_preparer._validate_saved_runtime_archive(
        archive_path,
        reference=reference,
        distribution_tag=distribution_tag,
        image_id=image_id,
        registry_binding=registry_binding,
    )
    assert binding["config_sha256"] == config_digest

    wrong_reference = reference.rsplit("sha256:", maxsplit=1)[0] + "sha256:" + "0" * 64
    with pytest.raises(
        runtime_preparer.RuntimeImageBundleError,
        match="exact request",
    ):
        runtime_preparer._validate_saved_runtime_archive(
            archive_path,
            reference=wrong_reference,
            distribution_tag=distribution_tag,
            image_id=image_id,
            registry_binding=registry_binding,
        )

    foreign_layer = b"foreign-runtime-layer"
    foreign_config = _image_config("a" * 40, layer=foreign_layer)
    foreign_archive = tmp_path / "foreign-runtime-image.tar"
    foreign_image_id = _write_saved_image_archive(
        foreign_archive,
        config=foreign_config,
        repo_tags=[distribution_tag],
        layer=foreign_layer,
    )
    with pytest.raises(
        runtime_preparer.RuntimeImageBundleError,
        match="not bound to the registry",
    ):
        runtime_preparer._validate_saved_runtime_archive(
            foreign_archive,
            reference=reference,
            distribution_tag=distribution_tag,
            image_id=foreign_image_id,
            registry_binding=registry_binding,
        )
