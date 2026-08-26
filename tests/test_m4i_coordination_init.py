from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis_ot.m4i_coordination_init as coordination_init
from aegis_ot.m4g_identity_init import (
    EFFECT_COORDINATOR_AUDIENCE,
    GATEWAY_COORDINATION_AUDIENCE,
)
from aegis_ot.m4g_identity_init import initialize as initialize_identity
from aegis_ot.pandapower_plant import PandapowerCigreMVPlant
from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    OT_CAPABILITY_AUDIENCE,
)
from aegis_ot.workload_identity import (
    WorkloadRole,
    load_signed_workload_credential,
)

NOW = datetime(2026, 8, 25, 16, 0, tzinfo=UTC)


class _PlantModelStub:
    model_digest = "0" * 64


def _configure_coordination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path]:
    gateway_directory = tmp_path / "gateway-coordination"
    ot_directory = tmp_path / "ot-coordination"
    plant_directory = tmp_path / "plant-checkpoint"
    gateway_directory.mkdir()
    ot_directory.mkdir()
    plant_directory.mkdir()
    gateway_path = gateway_directory / "gateway-coordination.json"
    ot_path = ot_directory / "ot-coordination.json"
    plant_path = plant_directory / "plant-checkpoint.json"
    environment = {
        "AEGIS_GATEWAY_COORDINATION_JOURNAL_FILE": gateway_path,
        "AEGIS_GATEWAY_WORKLOAD_SUBJECT": "urn:aegis-ot:m4g:workload:gateway",
        "AEGIS_GATEWAY_RUNTIME_UID": os.getuid(),
        "AEGIS_GATEWAY_RUNTIME_GID": os.getgid(),
        "AEGIS_OT_COORDINATION_JOURNAL_FILE": ot_path,
        "AEGIS_OT_WORKLOAD_SUBJECT": "urn:aegis-ot:m4g:workload:ot-adapter",
        "AEGIS_OT_RUNTIME_UID": os.getuid(),
        "AEGIS_OT_RUNTIME_GID": os.getgid(),
        "AEGIS_PLANT_CHECKPOINT_FILE": plant_path,
        "AEGIS_PLANT_KEY_ID": "m4g-plant-key-v1",
        "AEGIS_PLANT_RUNTIME_UID": os.getuid(),
        "AEGIS_PLANT_RUNTIME_GID": os.getgid(),
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, str(value))
    return gateway_path, ot_path, plant_path


def _writer_lock_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.writer.lock")


def test_initializer_creates_three_closed_private_state_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway_path, ot_path, plant_path = _configure_coordination(tmp_path, monkeypatch)

    summary = coordination_init.initialize()
    model_digest = PandapowerCigreMVPlant().model_digest

    expected_documents = {
        gateway_path: {
            "entries": [],
            "journal_role": "gateway",
            "owner_subject": "urn:aegis-ot:m4g:workload:gateway",
            "schema_version": "m4i-coordination-journal-v2",
        },
        ot_path: {
            "entries": [],
            "journal_role": "effect_coordinator",
            "owner_subject": "urn:aegis-ot:m4g:workload:ot-adapter",
            "schema_version": "m4i-coordination-journal-v2",
        },
        plant_path: {
            "checkpoint": None,
            "model_digest": model_digest,
            "plant_key_id": "m4g-plant-key-v1",
            "schema_version": "m4i-plant-checkpoint-v1",
        },
    }
    for path, expected_document in expected_documents.items():
        assert json.loads(path.read_bytes()) == expected_document
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert path.parent.stat().st_uid == os.getuid()
        assert path.parent.stat().st_gid == os.getgid()
        for artifact in (path, _writer_lock_path(path)):
            assert artifact.is_file()
            assert not artifact.is_symlink()
            assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
            assert artifact.stat().st_uid == os.getuid()
            assert artifact.stat().st_gid == os.getgid()

    assert summary == {
        "schema_version": "m4i-coordination-volume-initialization-v2",
        "state_artifact_count": 3,
        "gateway_journal_file": str(gateway_path),
        "gateway_journal_role": "gateway",
        "gateway_owner_subject": "urn:aegis-ot:m4g:workload:gateway",
        "gateway_runtime_uid": os.getuid(),
        "gateway_runtime_gid": os.getgid(),
        "ot_journal_file": str(ot_path),
        "ot_journal_role": "effect_coordinator",
        "ot_owner_subject": "urn:aegis-ot:m4g:workload:ot-adapter",
        "ot_runtime_uid": os.getuid(),
        "ot_runtime_gid": os.getgid(),
        "plant_checkpoint_file": str(plant_path),
        "plant_checkpoint_role": "plant_checkpoint",
        "plant_key_id": "m4g-plant-key-v1",
        "plant_model_digest": model_digest,
        "plant_runtime_uid": os.getuid(),
        "plant_runtime_gid": os.getgid(),
        "directory_mode": "0700",
        "artifact_mode": "0600",
        "secrets_consumed": 0,
    }


def test_initializer_refuses_shared_or_populated_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway_path, ot_path, plant_path = _configure_coordination(tmp_path, monkeypatch)
    monkeypatch.setattr(coordination_init, "PandapowerCigreMVPlant", _PlantModelStub)
    monkeypatch.setenv(
        "AEGIS_OT_COORDINATION_JOURNAL_FILE",
        str(gateway_path.parent / "ot-coordination.json"),
    )
    with pytest.raises(RuntimeError, match="distinct directories"):
        coordination_init.initialize()
    assert list(gateway_path.parent.iterdir()) == []
    assert list(ot_path.parent.iterdir()) == []
    assert list(plant_path.parent.iterdir()) == []

    monkeypatch.setenv("AEGIS_OT_COORDINATION_JOURNAL_FILE", str(ot_path))
    monkeypatch.setenv("AEGIS_PLANT_CHECKPOINT_FILE", str(gateway_path))
    with pytest.raises(RuntimeError, match="distinct files"):
        coordination_init.initialize()
    assert list(gateway_path.parent.iterdir()) == []
    assert list(ot_path.parent.iterdir()) == []
    assert list(plant_path.parent.iterdir()) == []

    monkeypatch.setenv(
        "AEGIS_PLANT_CHECKPOINT_FILE",
        str(ot_path.parent / "plant-checkpoint.json"),
    )
    with pytest.raises(RuntimeError, match="distinct directories"):
        coordination_init.initialize()
    assert list(gateway_path.parent.iterdir()) == []
    assert list(ot_path.parent.iterdir()) == []
    assert list(plant_path.parent.iterdir()) == []

    monkeypatch.setenv("AEGIS_PLANT_CHECKPOINT_FILE", str(plant_path))
    existing = gateway_path.parent / "retained-state"
    existing.write_text("do-not-overwrite", encoding="utf-8")
    with pytest.raises(RuntimeError, match="must be empty"):
        coordination_init.initialize()
    assert existing.read_text(encoding="utf-8") == "do-not-overwrite"
    assert list(ot_path.parent.iterdir()) == []
    assert list(plant_path.parent.iterdir()) == []


def test_initializer_removes_both_journals_if_checkpoint_creation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway_path, ot_path, plant_path = _configure_coordination(tmp_path, monkeypatch)
    monkeypatch.setattr(coordination_init, "PandapowerCigreMVPlant", _PlantModelStub)

    class FailedPlantCheckpoint:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("injected plant checkpoint initialization failure")

    monkeypatch.setattr(
        coordination_init,
        "DurablePlantCheckpointStore",
        FailedPlantCheckpoint,
    )
    with pytest.raises(
        RuntimeError,
        match="injected plant checkpoint initialization failure",
    ):
        coordination_init.initialize()

    assert list(gateway_path.parent.iterdir()) == []
    assert list(ot_path.parent.iterdir()) == []
    assert list(plant_path.parent.iterdir()) == []


def test_identity_initializer_adds_m4i_audiences_without_removing_m4g_audiences(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_directory = tmp_path / "identity-inputs"
    identity_directory = tmp_path / "identity"
    input_directory.mkdir()
    identity_directory.mkdir()
    keys = {
        name: Ed25519PrivateKey.generate()
        for name in ("authority", "agent", "gateway", "ot")
    }
    private_path = input_directory / "authority.private"
    private_path.write_bytes(keys["authority"].private_bytes_raw())
    public_paths: dict[str, Path] = {}
    for name in ("agent", "gateway", "ot"):
        path = input_directory / f"{name}.public"
        path.write_bytes(keys[name].public_key().public_bytes_raw())
        public_paths[name] = path
    environment = {
        "AEGIS_WORKLOAD_IDENTITY_DIRECTORY": identity_directory,
        "AEGIS_WORKLOAD_AUTHORITY_PRIVATE_KEY_FILE": private_path,
        "AEGIS_WORKLOAD_TRUST_DOMAIN": "aegis-ot.m4i.test",
        "AEGIS_AGENT_PUBLIC_KEY_FILE": public_paths["agent"],
        "AEGIS_GATEWAY_PUBLIC_KEY_FILE": public_paths["gateway"],
        "AEGIS_OT_PUBLIC_KEY_FILE": public_paths["ot"],
        "AEGIS_AGENT_ACTOR_ID": "agent:operator-1",
        "AEGIS_AGENT_WORKLOAD_SUBJECT": "agent/probe",
        "AEGIS_GATEWAY_WORKLOAD_SUBJECT": "gateway/control",
        "AEGIS_OT_WORKLOAD_SUBJECT": "ot/effect-coordinator",
        "AEGIS_RUNTIME_UID": os.getuid(),
        "AEGIS_RUNTIME_GID": os.getgid(),
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, str(value))

    initialize_identity(now=NOW)

    gateway = load_signed_workload_credential(
        identity_directory / "gateway.credential.json"
    )
    ot = load_signed_workload_credential(identity_directory / "ot.credential.json")
    agent = load_signed_workload_credential(identity_directory / "agent.credential.json")
    assert set(gateway.credential.audiences) == {
        OT_CAPABILITY_AUDIENCE,
        EFFECT_COORDINATOR_AUDIENCE,
    }
    assert set(ot.credential.audiences) == {
        GATEWAY_CAPABILITY_AUDIENCE,
        GATEWAY_COORDINATION_AUDIENCE,
    }
    assert agent.credential.role is WorkloadRole.AGENT
    assert agent.credential.actor_id == "agent:operator-1"
    assert agent.credential.audiences == (GATEWAY_CAPABILITY_AUDIENCE,)
