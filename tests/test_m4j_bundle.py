from __future__ import annotations

import gzip
import hashlib
import io
import json
import subprocess
import tarfile
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest


@pytest.fixture
def bundler(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("build_m4j_bundle")


def _write_repository_files(root: Path, *, topology: bool = True) -> None:
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


def _fixed_tools(*, plan_only: bool = False) -> dict[str, str]:
    return {
        "builder": "m4j-exact-source-application-image-bundle-v1",
        "docker_build": "not_invoked_plan_only" if plan_only else "fixture",
        "docker_daemon": "fixture",
        "buildkit_worker": "fixture",
        "git": "git version fixture",
        "python": "CPython fixture",
    }


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
) -> tuple[str, str]:
    layer = b"fixture-oci-layer"
    config = _image_config(commit, layer=layer)
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
        elif command[1:3] == ("buildx", "inspect"):
            stdout = (
                "Name: fixture\nDriver: docker\nNodes:\n"
                "BuildKit version: v0.32.2\n"
            )
        else:
            pytest.fail(f"unexpected provenance command: {command}")
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(bundler, "_run", fake_run)

    provenance = bundler._docker_build_provenance()

    assert provenance["docker_client"] == "29.7.2 client-commit darwin/arm64"
    assert provenance["docker_daemon"] == "29.7.2 server-commit linux/arm64"
    assert provenance["docker_daemon_platform"] == "Docker Desktop fixture"
    assert provenance["docker_buildx"] == "github.com/docker/buildx v0.36.1 fixture"
    assert provenance["docker_buildx_driver"] == "docker"
    assert provenance["buildkit_worker"] == "v0.32.2"


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
    revision = {
        "requested_reference": "release",
        "commit": "a" * 40,
        "tree": "b" * 40,
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

    first = bundler._manifest(
        revision=revision,
        source=source,
        image=image,
        target=target,
        tools=_fixed_tools(),
        plan_only=False,
    )
    second = bundler._manifest(
        revision=revision,
        source=source,
        image=image,
        target=target,
        tools=_fixed_tools(),
        plan_only=False,
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
) -> None:
    repository = tmp_path / "repository"
    commit = _repository(bundler, repository)
    monkeypatch.setattr(bundler, "ROOT", repository)
    monkeypatch.setattr(bundler, "_tool_versions", _fixed_tools)
    fake = _FakeDocker(bundler, bundler._run, commit=commit)
    monkeypatch.setattr(bundler, "_run", fake.run)
    output = tmp_path / "accepted-bundle"

    manifest = bundler.build_bundle(output, commit_reference=commit)

    build_calls = [call for call in fake.calls if call[1:3] == ("buildx", "build")]
    save_calls = [call for call in fake.calls if call[1:3] == ("image", "save")]
    assert len(build_calls) == 1
    assert len(save_calls) == 1
    assert save_calls[0][-1] == fake.image_id
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


def test_mocked_post_build_failure_cleans_only_owned_image_for_retry(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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

    with pytest.raises(bundler.BundleError, match="config digest"):
        bundler.build_bundle(output, commit_reference=commit)

    build_calls = [call for call in fake.calls if call[1:3] == ("buildx", "build")]
    removal_calls = [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert len(build_calls) == 1
    assert removal_calls == [("docker", "image", "rm", fake.image_id)]
    assert fake.tags == {}
    assert fake.image_present is False
    assert not output.exists()
    assert not tuple(tmp_path.glob(".failed-bundle.m4j-*"))

    fake.tamper_saved_config = False
    retry = bundler.build_bundle(output, commit_reference=commit)
    assert retry["accepted_deploy_bundle"] is True
    assert len(
        [call for call in fake.calls if call[1:3] == ("buildx", "build")]
    ) == 2


def test_mocked_malformed_iid_cleans_untagged_owned_image_for_retry(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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

    with pytest.raises(bundler.BundleError, match="immutable ID"):
        bundler.build_bundle(output, commit_reference=commit)

    removal_calls = [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert removal_calls == [("docker", "image", "rm", fake.image_id)]
    assert fake.image_present is False
    assert not output.exists()

    fake.malformed_iid = False
    retry = bundler.build_bundle(output, commit_reference=commit)
    assert retry["accepted_deploy_bundle"] is True
    assert len(
        [call for call in fake.calls if call[1:3] == ("buildx", "build")]
    ) == 2


def test_untagged_cleanup_refuses_foreign_invocation_label_collision(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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

    with pytest.raises(bundler.BundleError, match="refusing destructive cleanup"):
        bundler.build_bundle(output, commit_reference=commit)

    assert not [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert not output.exists()


def test_mocked_publication_race_after_build_cleans_owned_docker_state(
    bundler: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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

    with pytest.raises(bundler.BundleError, match="overwrite"):
        bundler.build_bundle(output, commit_reference=commit)

    removal_calls = [call for call in fake.calls if call[1:3] == ("image", "rm")]
    assert removal_calls == [("docker", "image", "rm", fake.image_id)]
    assert fake.tags == {}
    assert fake.image_present is False
    assert (output / "racer-owned").read_text(encoding="utf-8") == "preserve\n"
    assert not tuple(tmp_path.glob(".raced-bundle.m4j-*"))
