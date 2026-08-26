from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from importlib import import_module
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def bundler(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("build_m7_replication_bundle")


def _run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(  # noqa: S603 - fixture argv, no shell
        args,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return completed


def _commit(root: Path, message: str) -> str:
    _run(root, "git", "add", ".")
    _run(
        root,
        "git",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        message,
    )
    return _run(root, "git", "rev-parse", "HEAD").stdout.strip()


def _repository(bundler: Any, root: Path) -> str:
    root.mkdir()
    _run(root, "git", "init", "-q")
    (root / "scripts").mkdir()
    (root / "scripts" / "build_m7_replication_bundle.py").write_bytes(
        Path(cast(str, bundler.__file__)).read_bytes()
    )
    (root / "src").mkdir()
    (root / "src" / "fixture.py").write_text("VALUE = 7\n", encoding="utf-8")
    executable = root / "run-fixture"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    (root / "pyproject.toml").write_text(
        "\n".join(
            (
                "[project]",
                'name = "aegis-ot-fixture"',
                'version = "0.1.0"',
                'license = {text = "Apache-2.0"}',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "requirements.lock").write_text(
        "# exact fixture\ncryptography==46.0.7\npytest==8.4.2\n",
        encoding="utf-8",
    )
    (root / "Dockerfile").write_text(
        "\n".join(
            (
                "ARG PYTHON_IMAGE=python:3.13-slim@sha256:" + "1" * 64,
                "FROM ${PYTHON_IMAGE}",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "docker-compose.yml").write_text(
        'services:\n  opa:\n    image: "${OPA_IMAGE:-openpolicyagent/opa:1.0@sha256:'
        + "2" * 64
        + '}"\n',
        encoding="utf-8",
    )
    (root / "LICENSE").write_text(
        "Apache License\nVersion 2.0\nCopyright 2026 Angelis Pseftis\n",
        encoding="utf-8",
    )
    (root / "SECURITY.md").write_text(
        "# Security\nSynthetic authorized research only.\n", encoding="utf-8"
    )
    release_policy = root / "config" / "release-security-policy.json"
    release_policy.parent.mkdir()
    release_policy.write_bytes(
        Path(__file__).parents[1].joinpath("config", "release-security-policy.json").read_bytes()
    )
    formal = root / "results" / "formal" / "m1-authorization-conformance"
    formal.mkdir(parents=True)
    (formal / "manifest.json").write_text('{"bounded":true}\n', encoding="utf-8")
    return _commit(root, "fixture")


@pytest.fixture
def repository(bundler: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    root = tmp_path / "repository"
    commit = _repository(bundler, root)
    monkeypatch.setattr(bundler, "ROOT", root)
    return root, commit


def _json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _signing_keys(tmp_path: Path, stem: str = "m7") -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / f"{stem}-private.pem"
    public_path = tmp_path / f"{stem}-public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_path.chmod(0o644)
    return private_path, public_path


def _refresh_descriptor(bundle: Path, artifact_name: str) -> None:
    manifest_path = bundle / "manifest.json"
    manifest = _json(manifest_path)
    material = (bundle / artifact_name).read_bytes()
    manifest["artifacts"][artifact_name] = {
        "path": artifact_name,
        "size_bytes": len(material),
        "sha256": hashlib.sha256(material).hexdigest(),
    }
    manifest_path.write_bytes(_canonical(manifest))


def _append_tar_member(
    archive_path: Path,
    *,
    name: str,
    member_type: bytes = tarfile.REGTYPE,
    content: bytes = b"injected",
    mtime: int,
) -> None:
    with tarfile.open(archive_path, mode="a") as archive:
        member = tarfile.TarInfo(name)
        member.type = member_type
        member.mode = 0o644
        member.uid = 0
        member.gid = 0
        member.uname = ""
        member.gname = ""
        member.mtime = mtime
        if member_type == tarfile.SYMTYPE:
            member.linkname = "../outside"
            member.size = 0
            archive.addfile(member)
        elif member_type == tarfile.FIFOTYPE:
            member.size = 0
            archive.addfile(member)
        else:
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))


def test_build_is_deterministic_private_and_offline_verifiable(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, commit = repository
    first = tmp_path / "bundle-one"
    second = tmp_path / "bundle-two"

    report = bundler.build_bundle(first, commit_reference="HEAD")
    bundler.build_bundle(second, commit_reference=commit)

    assert report["valid"] is True
    assert report["source"]["git_commit"] == commit
    assert report["source"]["external_authenticity"] == "caller_supplied_commit_matched"
    assert stat.S_IMODE(first.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in first.iterdir())
    assert {path.name for path in first.iterdir()} == bundler.BUNDLE_NAMES
    assert {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in first.iterdir()
    } == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in second.iterdir()
    }

    verified = bundler.verify_bundle(first, expected_commit=commit)
    assert verified["valid"] is True
    assert verified["release_state"] == "not_published_or_publicly_released"
    assert verified["independent_replication"] == "not_established"

    no_external_commit = bundler.verify_bundle(first)
    assert (
        no_external_commit["source"]["external_authenticity"]
        == "not_established_without_external_expected_commit"
    )


def test_bundle_contains_source_derived_spdx_inputs_and_conservative_inventory(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, _commit_id = repository
    bundle = tmp_path / "bundle"
    bundler.build_bundle(bundle)

    sbom = _json(bundle / "sbom.spdx.json")
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["creationInfo"]["creators"] == ["Person: Angelis Pseftis"]
    assert any(package["name"] == "cryptography" for package in sbom["packages"])
    assert any(
        package.get("primaryPackagePurpose") == "CONTAINER" for package in sbom["packages"]
    )

    inputs = _json(bundle / "reproduction-inputs.json")
    assert inputs["python_environment"]["exact_pin_count"] == 2
    assert all("@sha256:" in item["reference"] for item in inputs["oci_inputs"])
    assert inputs["python_environment"]["payloads_vendored"] is False

    inventory = _json(bundle / "milestone-evidence-inventory.json")
    m1 = next(item for item in inventory["milestones"] if item["milestone"] == "M1")
    m4g = next(item for item in inventory["milestones"] if item["milestone"] == "M4g")
    m4i = next(item for item in inventory["milestones"] if item["milestone"] == "M4i")
    m8 = next(item for item in inventory["milestones"] if item["milestone"] == "M8")
    assert m1["artifact_presence_state"] == "all_declared_artifacts_present_unverified"
    assert m1["artifact_acceptance_state"] == "not_evaluated_by_this_inventory"
    assert [item["path"] for item in m4g["declared_artifacts"]] == [
        "results/m4g-workload-identity-evidence.json",
        "results/m4g-workload-identity-evidence-v2.json",
    ]
    assert m4g["artifact_presence_state"] == "no_declared_artifact_present"
    assert [item["path"] for item in m4i["declared_artifacts"]] == [
        "results/m4i-coordination-evidence.json",
        "results/m4i-coordination-evidence-v2.json",
    ]
    assert m4i["artifact_presence_state"] == "no_declared_artifact_present"
    assert m8["artifact_presence_state"] == "no_declared_artifact_present"
    assert m8["execution_state"] == "not_executed_by_this_bundle"
    assert m8["independent_replication_state"] == "not_established"


def test_standalone_verifier_runs_without_checkout_imports(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, commit = repository
    bundle = tmp_path / "bundle"
    bundler.build_bundle(bundle)

    completed = subprocess.run(  # noqa: S603 - exact interpreter and fixture path
        (
            sys.executable,
            str(bundle / "verify_m7_replication_bundle.py"),
            "verify",
            "--bundle",
            str(bundle),
            "--expected-commit",
            commit,
        ),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["valid"] is True


def test_signed_bundle_verifies_in_explicit_trusted_key_mode(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, commit = repository
    private_key, public_key = _signing_keys(tmp_path)
    bundle = tmp_path / "signed-bundle"

    built = bundler.build_bundle(
        bundle,
        commit_reference=commit,
        signing_private_key=private_key,
    )

    assert {path.name for path in bundle.iterdir()} == bundler.SIGNED_BUNDLE_NAMES
    assert built["attestation"]["signature_present"] is True
    assert built["attestation"]["trust_mode"] == "embedded_key_untrusted"
    manifest = _json(bundle / "manifest.json")
    assert manifest["attestation"]["signature"] == "ed25519_detached_manifest"
    assert bundler.SIGNATURE_NAME not in manifest["artifacts"]

    verified = bundler.verify_bundle(
        bundle,
        expected_commit=commit,
        trusted_public_key=public_key,
        require_signature=True,
    )
    assert verified["valid"] is True
    assert verified["attestation"]["cryptographic_signature_valid"] is True
    assert verified["attestation"]["trust_mode"] == "caller_supplied_trusted_key_matched"
    assert verified["attestation"]["external_custody"] == "not_established"
    assert verified["attestation"]["release_authorization"] == "not_established"

    standalone = subprocess.run(  # noqa: S603 - fixed interpreter and fixture path
        (
            sys.executable,
            str(bundle / bundler.VERIFIER_NAME),
            "verify",
            "--bundle",
            str(bundle),
            "--expected-commit",
            commit,
            "--require-signature",
            "--trusted-public-key",
            str(public_key),
        ),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert standalone.returncode == 0, standalone.stderr
    assert (
        json.loads(standalone.stdout)["attestation"]["trust_mode"]
        == "caller_supplied_trusted_key_matched"
    )


def test_signed_bundle_rejects_wrong_trusted_key_and_signature_tamper(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, commit = repository
    private_key, _public_key = _signing_keys(tmp_path, "correct")
    _wrong_private, wrong_public = _signing_keys(tmp_path, "wrong")
    bundle = tmp_path / "signed-bundle"
    bundler.build_bundle(bundle, signing_private_key=private_key)

    with pytest.raises(bundler.BundleError, match="caller-supplied trusted key"):
        bundler.verify_bundle(
            bundle,
            expected_commit=commit,
            trusted_public_key=wrong_public,
            require_signature=True,
        )

    signature_path = bundle / bundler.SIGNATURE_NAME
    signature = _json(signature_path)
    signature["signature_base64"] = base64.b64encode(b"\0" * 64).decode("ascii")
    signature_path.write_bytes(_canonical(signature))
    with pytest.raises(bundler.BundleError, match="signature is invalid"):
        bundler.verify_bundle(bundle, expected_commit=commit, require_signature=True)


def test_trusted_key_mode_rejects_unsigned_bundle_and_exposed_signing_key(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, _commit = repository
    private_key, public_key = _signing_keys(tmp_path)
    unsigned = tmp_path / "unsigned"
    bundler.build_bundle(unsigned)

    with pytest.raises(bundler.BundleError, match="required.*unsigned"):
        bundler.verify_bundle(unsigned, require_signature=True)
    with pytest.raises(bundler.BundleError, match="trusted key.*unsigned"):
        bundler.verify_bundle(unsigned, trusted_public_key=public_key)

    private_key.chmod(0o644)
    with pytest.raises(bundler.BundleError, match="permissions are not private"):
        bundler.build_bundle(tmp_path / "exposed", signing_private_key=private_key)


def test_safe_extraction_preserves_exact_content_and_executable_mode(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    root, commit = repository
    bundle = tmp_path / "bundle"
    output = tmp_path / "extracted"
    bundler.build_bundle(bundle)

    report = bundler.extract_bundle_source(bundle, output, expected_commit=commit)

    assert report["extracted"] is True
    assert (output / "src" / "fixture.py").read_bytes() == (
        root / "src" / "fixture.py"
    ).read_bytes()
    assert stat.S_IMODE((output / "run-fixture").stat().st_mode) == 0o755
    with pytest.raises(bundler.BundleError, match="overwrite"):
        bundler.extract_bundle_source(bundle, output, expected_commit=commit)


def test_build_rejects_dirty_checkout_inside_output_and_no_clobber(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    root, _commit_id = repository
    with pytest.raises(bundler.BundleError, match="outside"):
        bundler.build_bundle(root / "bundle")

    (root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(bundler.BundleError, match="clean checkout"):
        bundler.build_bundle(tmp_path / "dirty-bundle")
    (root / "untracked.txt").unlink()

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(bundler.BundleError, match="overwrite"):
        bundler.build_bundle(existing)


def test_build_rejects_historical_commit_unpinned_oci_and_tracked_symlink(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    root, first_commit = repository
    (root / "src" / "later.py").write_text("LATER = True\n", encoding="utf-8")
    _commit(root, "later")
    with pytest.raises(bundler.BundleError, match="current exact HEAD"):
        bundler.build_bundle(tmp_path / "historical", commit_reference=first_commit)

    (root / "Dockerfile").write_text("FROM python:3.13-slim\n", encoding="utf-8")
    _commit(root, "unpinned")
    with pytest.raises(bundler.BundleError, match="not digest pinned"):
        bundler.build_bundle(tmp_path / "unpinned")

    (root / "Dockerfile").write_text(
        "FROM python:3.13-slim@sha256:" + "3" * 64 + "\n", encoding="utf-8"
    )
    os.symlink("src/fixture.py", root / "linked-source")
    _commit(root, "symlink")
    with pytest.raises(bundler.BundleError, match="symlink, gitlink, or special"):
        bundler.build_bundle(tmp_path / "symlink")


def test_verifier_rejects_artifact_tampering(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, _commit_id = repository
    bundle = tmp_path / "bundle"
    bundler.build_bundle(bundle)
    with (bundle / "sbom.spdx.json").open("ab") as handle:
        handle.write(b" ")

    with pytest.raises(bundler.BundleError, match="checksums"):
        bundler.verify_bundle(bundle)


@pytest.mark.parametrize(
    ("name", "member_type", "message"),
    (
        ("../escape", tarfile.REGTYPE, "unsafe"),
        ("aegis-ot-source/src/fixture.py", tarfile.REGTYPE, "duplicate"),
        ("aegis-ot-source/linked", tarfile.SYMTYPE, "unsafe"),
        ("aegis-ot-source/fifo", tarfile.FIFOTYPE, "unsafe"),
    ),
)
def test_verifier_rejects_traversal_duplicates_symlinks_and_special_files(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
    name: str,
    member_type: bytes,
    message: str,
) -> None:
    _root, _commit_id = repository
    bundle = tmp_path / f"bundle-{hashlib.sha256(name.encode()).hexdigest()[:8]}"
    bundler.build_bundle(bundle)
    manifest = _json(bundle / "manifest.json")
    epoch = manifest["source"]["committed_epoch"]
    _append_tar_member(
        bundle / "source.tar",
        name=name,
        member_type=member_type,
        mtime=epoch,
    )
    _refresh_descriptor(bundle, "source.tar")

    with pytest.raises(bundler.BundleError, match=message):
        bundler.verify_bundle(bundle)


def test_verifier_rejects_rehashed_evidence_and_release_overstatement(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, _commit_id = repository
    bundle = tmp_path / "bundle"
    bundler.build_bundle(bundle)
    inventory_path = bundle / "milestone-evidence-inventory.json"
    inventory = _json(inventory_path)
    inventory["milestones"][-1]["execution_state"] = "accepted"
    inventory["milestones"][-1]["independent_replication_state"] = "validated"
    inventory_path.write_bytes(_canonical(inventory))
    _refresh_descriptor(bundle, "milestone-evidence-inventory.json")

    with pytest.raises(bundler.BundleError, match="overstates evidence"):
        bundler.verify_bundle(bundle)

    second = tmp_path / "bundle-two"
    bundler.build_bundle(second)
    manifest_path = second / "manifest.json"
    manifest = _json(manifest_path)
    manifest["release_state"] = "published"
    manifest["attestation"]["independent_validation"] = "established"
    manifest_path.write_bytes(_canonical(manifest))
    with pytest.raises(bundler.BundleError, match="overstates source/release claims"):
        bundler.verify_bundle(second)


def test_verifier_rejects_rehashed_source_index_claim_and_wrong_expected_commit(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, _commit_id = repository
    bundle = tmp_path / "bundle"
    bundler.build_bundle(bundle)
    index_path = bundle / "source-index.json"
    index = _json(index_path)
    index["files"][0]["sha256"] = "0" * 64
    index_path.write_bytes(_canonical(index))
    _refresh_descriptor(bundle, "source-index.json")
    with pytest.raises(bundler.BundleError, match="digest is inconsistent"):
        bundler.verify_bundle(bundle)

    second = tmp_path / "bundle-two"
    bundler.build_bundle(second)
    with pytest.raises(bundler.BundleError, match="caller-supplied"):
        bundler.verify_bundle(second, expected_commit="f" * 40)


def test_verifier_rejects_non_private_or_unexpected_bundle_entries(
    bundler: Any,
    repository: tuple[Path, str],
    tmp_path: Path,
) -> None:
    _root, _commit_id = repository
    bundle = tmp_path / "bundle"
    bundler.build_bundle(bundle)
    (bundle / "manifest.json").chmod(0o644)
    with pytest.raises(bundler.BundleError, match="not private"):
        bundler.verify_bundle(bundle)

    (bundle / "manifest.json").chmod(0o600)
    (bundle / "extra").write_text("unexpected\n", encoding="utf-8")
    (bundle / "extra").chmod(0o600)
    with pytest.raises(bundler.BundleError, match="unexpected"):
        bundler.verify_bundle(bundle)
