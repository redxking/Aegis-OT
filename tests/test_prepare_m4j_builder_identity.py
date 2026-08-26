from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from importlib import import_module
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def identity_generator(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return import_module("prepare_m4j_builder_identity")


def _safe_parent(tmp_path: Path, name: str = "authority-parent") -> Path:
    parent = tmp_path / name
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    return parent


def test_identity_is_atomically_published_with_raw_private_keys(
    identity_generator: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = _safe_parent(tmp_path)
    output = parent / "builder-authority"
    observed_ready_state = False
    fsync_calls = 0
    real_publish = identity_generator._publish_directory_noreplace
    real_fsync = identity_generator.os.fsync

    def observe_publish(source: Path, destination: Path) -> None:
        nonlocal observed_ready_state
        assert source.name.startswith(identity_generator._STAGING_PREFIX)
        assert destination == output
        assert not output.exists()
        assert stat.S_IMODE(source.stat().st_mode) == 0o700
        assert (source / identity_generator.PRIVATE_KEY_NAME).stat().st_size == 32
        assert (source / identity_generator.PUBLIC_KEY_NAME).stat().st_size == 32
        observed_ready_state = True
        real_publish(source, destination)

    def observe_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        real_fsync(descriptor)

    monkeypatch.setattr(identity_generator, "_publish_directory_noreplace", observe_publish)
    monkeypatch.setattr(identity_generator.os, "fsync", observe_fsync)

    metadata = identity_generator.create_builder_identity(output)

    private_path = output / identity_generator.PRIVATE_KEY_NAME
    public_path = output / identity_generator.PUBLIC_KEY_NAME
    private_material = private_path.read_bytes()
    public_material = public_path.read_bytes()
    assert observed_ready_state
    assert fsync_calls == 4
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(public_path.stat().st_mode) == 0o600
    assert len(private_material) == len(public_material) == 32
    assert (
        Ed25519PrivateKey.from_private_bytes(private_material)
        .public_key()
        .public_bytes_raw()
        == public_material
    )
    assert metadata["authority"]["key_id"] == hashlib.sha256(public_material).hexdigest()
    assert metadata["authority"]["type"] == "local_configured_builder_authority"
    assert "independent provenance" in metadata["claim_boundary"]["does_not_establish"]
    assert not list(parent.glob(f"{identity_generator._STAGING_PREFIX}*"))


def test_cli_prints_public_metadata_but_no_key_material(
    identity_generator: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parent = _safe_parent(tmp_path)
    output = parent / "builder-authority"
    monkeypatch.setattr(sys, "argv", ["prepare_m4j_builder_identity.py", "--output", str(output)])

    identity_generator.main()

    stdout = capsys.readouterr().out
    document = json.loads(stdout)
    private_material = (output / identity_generator.PRIVATE_KEY_NAME).read_bytes()
    public_material = (output / identity_generator.PUBLIC_KEY_NAME).read_bytes()
    assert document["authority"]["key_id"] == hashlib.sha256(public_material).hexdigest()
    assert document["secret_material_printed"] is False
    assert "local operator-configured builder signing authority" in json.dumps(document)
    assert "independent provenance" in json.dumps(document)
    assert private_material.hex() not in stdout
    assert public_material.hex() not in stdout


@pytest.mark.parametrize("existing_kind", ["directory", "symlink"])
def test_existing_or_symlink_output_is_never_replaced(
    identity_generator: ModuleType,
    tmp_path: Path,
    existing_kind: str,
) -> None:
    parent = _safe_parent(tmp_path)
    output = parent / "builder-authority"
    if existing_kind == "directory":
        output.mkdir()
        marker = output / "preserve"
        marker.write_text("owned by caller", encoding="utf-8")
    else:
        target = parent / "existing-target"
        target.mkdir()
        marker = target / "preserve"
        marker.write_text("owned by caller", encoding="utf-8")
        output.symlink_to(target, target_is_directory=True)

    with pytest.raises(identity_generator.BuilderIdentityError, match="overwrite"):
        identity_generator.create_builder_identity(output)

    assert marker.read_text(encoding="utf-8") == "owned by caller"


def test_parent_must_be_owned_and_not_group_or_other_writable(
    identity_generator: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writable_parent = _safe_parent(tmp_path, "writable-parent")
    writable_parent.chmod(0o770)
    with pytest.raises(identity_generator.BuilderIdentityError, match="deny group/other writes"):
        identity_generator.create_builder_identity(writable_parent / "identity")

    owned_parent = _safe_parent(tmp_path, "foreign-parent")
    monkeypatch.setattr(identity_generator, "_current_uid", lambda: os.geteuid() + 1)
    with pytest.raises(identity_generator.BuilderIdentityError, match="owned by the current user"):
        identity_generator.create_builder_identity(owned_parent / "identity")


def test_symlink_parent_and_checkout_destination_are_rejected(
    identity_generator: ModuleType,
    tmp_path: Path,
) -> None:
    real_parent = _safe_parent(tmp_path)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(identity_generator.BuilderIdentityError, match="must not contain symlinks"):
        identity_generator.create_builder_identity(linked_parent / "identity")
    with pytest.raises(identity_generator.BuilderIdentityError, match="outside the checkout"):
        identity_generator.create_builder_identity(ROOT / ".builder-identity-test")


def test_partial_keypair_is_removed_when_publication_fails(
    identity_generator: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = _safe_parent(tmp_path)
    output = parent / "builder-authority"
    real_write = identity_generator._write_raw_key

    def fail_after_private(
        descriptor: int,
        name: str,
        material: bytes,
    ) -> None:
        real_write(descriptor, name, material)
        if name == identity_generator.PRIVATE_KEY_NAME:
            raise identity_generator.BuilderIdentityError("injected publication failure")

    monkeypatch.setattr(identity_generator, "_write_raw_key", fail_after_private)

    with pytest.raises(identity_generator.BuilderIdentityError, match="injected"):
        identity_generator.create_builder_identity(output)

    assert not output.exists()
    assert not list(parent.iterdir())
