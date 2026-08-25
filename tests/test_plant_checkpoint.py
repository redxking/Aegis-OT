from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import aegis_ot.plant_checkpoint as checkpoint_module
from aegis_ot.models import Operation
from aegis_ot.pandapower_plant import (
    PandapowerCigreMVPlant,
    PhysicalSimulationError,
)
from aegis_ot.physical_models import (
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
)
from aegis_ot.plant_checkpoint import (
    DurablePlantCheckpointStore,
    PlantCheckpointError,
)

NOW = datetime(2026, 8, 25, 19, 0, tzinfo=UTC)
PLANT_KEY_ID = "m4i-test-plant-key-v1"


def _line_isolation(command_id: str = "checkpoint-line-command") -> PhysicalControlCommand:
    return PhysicalControlCommand(
        command_id=command_id,
        proposal_id=f"proposal-{command_id}",
        operation=Operation.ISOLATE_ASSET,
        resource="feeder-1",
        command_type=PhysicalCommandType.SET_LINE_SERVICE,
        target="Line 5-6",
        target_index=4,
        setpoint=0.0,
        unit="boolean",
    )


def _battery_dispatch(
    setpoint: float = 0.2,
    *,
    command_id: str = "checkpoint-battery-command",
) -> PhysicalControlCommand:
    return PhysicalControlCommand(
        command_id=command_id,
        proposal_id=f"proposal-{command_id}",
        operation=Operation.DISPATCH_BATTERY,
        resource="battery-1",
        command_type=PhysicalCommandType.SET_BATTERY_INJECTION,
        target="Battery 1",
        target_index=0,
        setpoint=setpoint,
        unit="MW",
    )


def _plant(source: str = "checkpoint-test-plant") -> PandapowerCigreMVPlant:
    return PandapowerCigreMVPlant(
        observed_at=NOW,
        observation_source_id=source,
    )


def _path(tmp_path: Path) -> Path:
    directory = tmp_path / "plant-checkpoint"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory / "checkpoint.json"


def _provisioned_store(
    tmp_path: Path,
    plant: PandapowerCigreMVPlant,
) -> DurablePlantCheckpointStore:
    return DurablePlantCheckpointStore(
        _path(tmp_path),
        plant_key_id=PLANT_KEY_ID,
        model_digest=plant.model_digest,
        initialize=True,
    )


def _commit_through_plant(
    plant: PandapowerCigreMVPlant,
    store: DurablePlantCheckpointStore,
    command: PhysicalControlCommand,
) -> PhysicalStateSnapshot:
    return plant.apply_authorized_command(
        command,
        durable_commit=lambda current, next_state: store.commit_next(
            current=current,
            next_state=next_state,
        ),
    )


def test_empty_sentinel_installs_exact_baseline_and_reopens_next_state(
    tmp_path: Path,
) -> None:
    plant = _plant()
    baseline = plant.read_state()
    store = _provisioned_store(tmp_path, plant)
    path = store.path
    lock_path = store.writer_lock_path

    assert store.current() is None
    assert json.loads(path.read_bytes()) == {
        "checkpoint": None,
        "model_digest": plant.model_digest,
        "plant_key_id": PLANT_KEY_ID,
        "schema_version": "m4i-plant-checkpoint-v1",
    }
    for artifact in (path, lock_path):
        assert artifact.is_file()
        assert not artifact.is_symlink()
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700

    assert store.install_baseline(baseline) == baseline
    committed = _commit_through_plant(plant, store, _line_isolation())
    assert store.verify_current(plant.read_state()) == committed
    store.close()

    with DurablePlantCheckpointStore(
        path,
        plant_key_id=PLANT_KEY_ID,
        model_digest=plant.model_digest,
    ) as reopened:
        assert reopened.current() == committed


def test_baseline_and_next_state_must_be_exactly_monotonic(tmp_path: Path) -> None:
    source = _plant()
    version_one = source.apply_authorized_command(_line_isolation())
    empty = _provisioned_store(tmp_path, source)

    with pytest.raises(PlantCheckpointError, match="version-zero"):
        empty.install_baseline(version_one)
    baseline = _plant("baseline-source").read_state()
    empty.install_baseline(baseline)

    advanced = _plant("advanced-source")
    advanced.apply_authorized_command(_line_isolation("advance-line"))
    version_two = advanced.apply_authorized_command(
        _battery_dispatch(command_id="advance-battery")
    )
    with pytest.raises(PlantCheckpointError, match="exactly one version"):
        empty.commit_next(current=baseline, next_state=version_two)

    assert empty.current() == baseline
    empty.close()


@pytest.mark.parametrize(
    "fault",
    ("corrupt", "missing", "symlink", "mode", "noncanonical", "oversize"),
)
def test_reopen_rejects_untrusted_checkpoint_artifacts(
    tmp_path: Path,
    fault: str,
) -> None:
    plant = _plant()
    store = _provisioned_store(tmp_path, plant)
    path = store.path
    store.close()

    if fault == "corrupt":
        path.write_bytes(b"{")
    elif fault == "missing":
        path.unlink()
    elif fault == "symlink":
        path.unlink()
        target = tmp_path / "outside-checkpoint.json"
        target.write_text("{}", encoding="utf-8")
        path.symlink_to(target)
    elif fault == "mode":
        path.chmod(0o640)
    elif fault == "noncanonical":
        document = json.loads(path.read_bytes())
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    else:
        path.write_bytes(b" " * (DurablePlantCheckpointStore.MAX_CHECKPOINT_BYTES + 1))

    with pytest.raises(PlantCheckpointError):
        DurablePlantCheckpointStore(
            path,
            plant_key_id=PLANT_KEY_ID,
            model_digest=plant.model_digest,
        )


def test_reopen_rejects_identity_mismatch_and_missing_or_wrong_mode_lock(
    tmp_path: Path,
) -> None:
    plant = _plant()
    store = _provisioned_store(tmp_path, plant)
    path = store.path
    lock_path = store.writer_lock_path
    store.close()

    with pytest.raises(PlantCheckpointError, match="identity"):
        DurablePlantCheckpointStore(
            path,
            plant_key_id="different-plant-key-v1",
            model_digest=plant.model_digest,
        )
    with pytest.raises(PlantCheckpointError, match="identity"):
        DurablePlantCheckpointStore(
            path,
            plant_key_id=PLANT_KEY_ID,
            model_digest="f" * 64,
        )

    lock_path.unlink()
    with pytest.raises(PlantCheckpointError, match="writer lock"):
        DurablePlantCheckpointStore(
            path,
            plant_key_id=PLANT_KEY_ID,
            model_digest=plant.model_digest,
        )

    lock_path.write_bytes(b"")
    lock_path.chmod(0o640)
    with pytest.raises(PlantCheckpointError, match="mode must be 0600"):
        DurablePlantCheckpointStore(
            path,
            plant_key_id=PLANT_KEY_ID,
            model_digest=plant.model_digest,
        )


def test_parent_mode_and_second_lifetime_writer_fail_closed(tmp_path: Path) -> None:
    plant = _plant()
    insecure = tmp_path / "insecure"
    insecure.mkdir(mode=0o755)
    insecure.chmod(0o755)
    with pytest.raises(PlantCheckpointError, match="directory mode must be 0700"):
        DurablePlantCheckpointStore(
            insecure / "checkpoint.json",
            plant_key_id=PLANT_KEY_ID,
            model_digest=plant.model_digest,
            initialize=True,
        )

    first = _provisioned_store(tmp_path, plant)
    with pytest.raises(PlantCheckpointError, match="held"):
        DurablePlantCheckpointStore(
            first.path,
            plant_key_id=PLANT_KEY_ID,
            model_digest=plant.model_digest,
        )
    first.close()


def test_pre_replace_failure_keeps_old_disk_and_memory_and_poisons_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plant = _plant()
    baseline = plant.read_state()
    store = _provisioned_store(tmp_path, plant)
    path = store.path
    store.install_baseline(baseline)

    def fail_replace(_source: object, _target: object) -> None:
        raise OSError("injected pre-replace failure")

    monkeypatch.setattr(checkpoint_module.os, "replace", fail_replace)
    with pytest.raises(PlantCheckpointError, match="update failed") as captured:
        _commit_through_plant(plant, store, _line_isolation())
    assert not isinstance(captured.value, PhysicalSimulationError)
    assert plant.read_state() == baseline
    with pytest.raises(PlantCheckpointError, match="uncertain update"):
        store.current()
    store.close()

    with DurablePlantCheckpointStore(
        path,
        plant_key_id=PLANT_KEY_ID,
        model_digest=plant.model_digest,
    ) as reopened:
        assert reopened.current() == baseline


def test_deadline_expiry_after_temp_fsync_keeps_old_disk_and_memory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plant = _plant()
    baseline = plant.read_state()
    store = _provisioned_store(tmp_path, plant)
    store.install_baseline(baseline)
    deadline = NOW + timedelta(seconds=1)
    regular_fsyncs = 0
    clock_calls = 0
    real_fsync = os.fsync

    def track_fsync(descriptor: int) -> None:
        nonlocal regular_fsyncs
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            regular_fsyncs += 1
        real_fsync(descriptor)

    def effect_clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        if clock_calls == 1:
            return NOW
        assert regular_fsyncs == 1
        return deadline

    monkeypatch.setattr(checkpoint_module.os, "fsync", track_fsync)
    with pytest.raises(PlantCheckpointError, match="deadline expired") as captured:
        plant.apply_authorized_command(
            _line_isolation(),
            effect_deadline=deadline,
            effect_clock=effect_clock,
            durable_commit=lambda current, next_state: store.commit_next(
                current=current,
                next_state=next_state,
                effect_deadline=deadline,
                effect_clock=effect_clock,
            ),
        )

    assert not isinstance(captured.value, PhysicalSimulationError)
    assert clock_calls == 2
    assert plant.read_state() == baseline
    assert store.current() == baseline
    assert tuple(store.path.parent.glob("*.tmp")) == ()
    store.close()


def test_callback_failure_cannot_be_reported_as_a_physical_rejection() -> None:
    plant = _plant()
    baseline = plant.read_state()

    def invalid_callback(
        _current: PhysicalStateSnapshot,
        _next_state: PhysicalStateSnapshot,
    ) -> None:
        raise PhysicalSimulationError("misclassified persistence failure")

    with pytest.raises(RuntimeError, match="durable_pre_swap_commit_failed") as captured:
        plant.apply_authorized_command(
            _line_isolation(),
            durable_commit=invalid_callback,
        )

    assert type(captured.value) is RuntimeError
    assert plant.read_state() == baseline


def test_post_replace_directory_fsync_failure_recovers_new_checkpoint_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plant = _plant()
    baseline = plant.read_state()
    command = _line_isolation()
    expected = plant.simulate_candidate(command).post_state
    store = _provisioned_store(tmp_path, plant)
    path = store.path
    store.install_baseline(baseline)
    real_fsync = os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected post-replace directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(checkpoint_module.os, "fsync", fail_directory_fsync)
    with pytest.raises(PlantCheckpointError, match="update failed") as captured:
        _commit_through_plant(plant, store, command)
    assert not isinstance(captured.value, PhysicalSimulationError)
    assert plant.read_state() == baseline
    with pytest.raises(PlantCheckpointError, match="uncertain update"):
        store.current()
    store.close()

    with DurablePlantCheckpointStore(
        path,
        plant_key_id=PLANT_KEY_ID,
        model_digest=plant.model_digest,
    ) as reopened:
        retained = reopened.current()
        assert retained is not None
        assert retained.state_version == expected.state_version == 1
        assert retained.state_digest == expected.state_digest
        restored = _plant("recovered-after-uncertain-replace")
        recovered = restored.restore_state(retained)
        assert recovered.state_version == retained.state_version
        assert recovered.state_digest == retained.state_digest
        assert reopened.verify_current(recovered).state_digest == retained.state_digest
