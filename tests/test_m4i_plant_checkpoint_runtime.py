from __future__ import annotations

import os
import stat
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_m4g_runtime import (
    CANDIDATE_KEY_ID,
    NOW,
    OBSERVER_KEY_ID,
    OT_KEY_ID,
    PLANT_BOOT,
    PLANT_KEY_ID,
    RuntimeArtifacts,
    _apply_payload,
    _plant_call,
    _trusted_callers,
)
from test_m4g_runtime import artifacts as _runtime_artifacts_fixture

import aegis_ot.plant_checkpoint as checkpoint_module
import aegis_ot.segmented_capability_runtime as runtime_module
from aegis_ot.models import Operation
from aegis_ot.pandapower_plant import PandapowerCigreMVPlant
from aegis_ot.physical_models import (
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
)
from aegis_ot.plant_checkpoint import (
    DurablePlantCheckpointStore,
    PlantCheckpointError,
)
from aegis_ot.segmented_capability_models import (
    PHYSICAL_PLANT_AUDIENCE,
    PlantApplyPayload,
    PlantCallerRole,
    PlantOperation,
    PlantReadPayload,
    PlantResponseStatus,
    PlantStateResponsePayload,
    SignedPlantCall,
)
from aegis_ot.segmented_capability_runtime import (
    CapabilityPlantRuntime,
    CapabilityRuntimeUnavailable,
)


@pytest.fixture(scope="module")
def artifacts() -> RuntimeArtifacts:
    factory = cast(
        Callable[[], RuntimeArtifacts],
        _runtime_artifacts_fixture.__wrapped__,
    )
    return factory()


def _checkpoint_path(tmp_path: Path) -> Path:
    directory = tmp_path / "plant-checkpoint"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory / "checkpoint.json"


def _required_runtime(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> tuple[
    CapabilityPlantRuntime,
    PandapowerCigreMVPlant,
    DurablePlantCheckpointStore,
]:
    plant = PandapowerCigreMVPlant(observed_at=NOW)
    assert plant.read_state() == artifacts.pre_state
    store = DurablePlantCheckpointStore(
        _checkpoint_path(tmp_path),
        plant_key_id=PLANT_KEY_ID,
        model_digest=plant.model_digest,
        initialize=True,
    )
    store.install_baseline(plant.read_state())
    runtime = CapabilityPlantRuntime(
        plant=plant,
        private_key=artifacts.plant_private,
        key_id=PLANT_KEY_ID,
        trusted_callers=_trusted_callers(artifacts),
        boot_epoch=PLANT_BOOT,
        clock=lambda: NOW,
        checkpoint_required=True,
        checkpoint_store=store,
    )
    return runtime, plant, store


def _battery_dispatch(command_id: str) -> PhysicalControlCommand:
    return PhysicalControlCommand(
        command_id=command_id,
        proposal_id=f"proposal-{command_id}",
        operation=Operation.DISPATCH_BATTERY,
        resource="battery-1",
        command_type=PhysicalCommandType.SET_BATTERY_INJECTION,
        target="Battery 1",
        target_index=0,
        setpoint=0.2,
        unit="MW",
    )


def _dynamic_apply_call(
    runtime: CapabilityPlantRuntime,
    *,
    caller_private: Ed25519PrivateKey,
    caller_key_id: str,
    command: PhysicalControlCommand,
    nonce: str,
    issued_at: datetime,
) -> SignedPlantCall:
    pre_state = runtime.plant.read_state()
    assessment = runtime.plant.simulate_candidate(command)
    deadline = issued_at + timedelta(seconds=10)
    return SignedPlantCall.issue(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=PlantApplyPayload(
            command=command,
            expected_pre_state_version=pre_state.state_version,
            expected_pre_state_digest=pre_state.state_digest,
            expected_pre_observation_digest=pre_state.observation_digest,
            expected_post_state_digest=assessment.post_state.state_digest,
            expected_post_topology_digest=assessment.post_state.topology_digest,
            authorization_expires_at=deadline,
        ),
        caller_key_id=caller_key_id,
        target_plant_key_id=runtime.key_id,
        target_plant_boot_epoch=runtime.boot_epoch,
        call_nonce=nonce,
        issued_at=issued_at,
        expires_at=deadline,
        private_key=caller_private,
        audience=PHYSICAL_PLANT_AUDIENCE,
    )


def _write_key_pair(
    directory: Path,
    name: str,
    private_key: Ed25519PrivateKey,
) -> tuple[Path, Path]:
    private_path = directory / f"{name}.private.raw"
    public_path = directory / f"{name}.public.raw"
    private_path.write_bytes(private_key.private_bytes_raw())
    public_path.write_bytes(private_key.public_key().public_bytes_raw())
    return private_path, public_path


def _configure_plant_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
    *,
    mode: str,
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setenv("AEGIS_EFFECT_COORDINATION_MODE", mode)
    roles = {
        "PLANT": (PLANT_KEY_ID, artifacts.plant_private),
        "OBSERVER": (OBSERVER_KEY_ID, artifacts.observer_private),
        "CANDIDATE": (CANDIDATE_KEY_ID, artifacts.candidate_private),
        "OT": (OT_KEY_ID, artifacts.ot_private),
    }
    for role, (key_id, private_key) in roles.items():
        private_path, public_path = _write_key_pair(
            tmp_path,
            role.lower(),
            private_key,
        )
        monkeypatch.setenv(f"AEGIS_{role}_KEY_ID", key_id)
        monkeypatch.setenv(f"AEGIS_{role}_PRIVATE_KEY_FILE", str(private_path))
        monkeypatch.setenv(f"AEGIS_{role}_PUBLIC_KEY_FILE", str(public_path))


def _assert_same_physical_state(
    left: PhysicalStateSnapshot,
    right: PhysicalStateSnapshot,
) -> None:
    assert left.model_digest == right.model_digest
    assert left.input_digest == right.input_digest
    assert left.topology_digest == right.topology_digest
    assert left.state_version == right.state_version
    assert left.state_digest == right.state_digest
    assert left.simulation_time_s == right.simulation_time_s


def test_required_apply_returns_success_only_after_exact_checkpoint_commit(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    runtime, plant, store = _required_runtime(tmp_path, artifacts)
    call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=_apply_payload(artifacts),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4i-checkpoint-runtime-apply-0001",
        private_key=artifacts.ot_private,
    )

    status, response = runtime.execute(call)

    assert status == 200
    assert response.status is PlantResponseStatus.OK
    assert isinstance(response.payload, PlantStateResponsePayload)
    assert store.current() == response.payload.snapshot == plant.read_state()
    assert runtime.health().commit_count == 1
    store.close()


def test_runtime_rejects_checkpoint_mode_and_identity_misconfiguration(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    plant = PandapowerCigreMVPlant(observed_at=NOW)
    common = {
        "plant": plant,
        "private_key": artifacts.plant_private,
        "key_id": PLANT_KEY_ID,
        "trusted_callers": _trusted_callers(artifacts),
    }
    with pytest.raises(ValueError, match="store is missing"):
        CapabilityPlantRuntime(**common, checkpoint_required=True)

    store = DurablePlantCheckpointStore(
        _checkpoint_path(tmp_path),
        plant_key_id="different-runtime-plant-key",
        model_digest=plant.model_digest,
        initialize=True,
    )
    with pytest.raises(ValueError, match="disabled plant checkpoint mode"):
        CapabilityPlantRuntime(**common, checkpoint_store=store)
    with pytest.raises(ValueError, match="identity does not match"):
        CapabilityPlantRuntime(
            **common,
            checkpoint_required=True,
            checkpoint_store=store,
        )
    store.close()


def test_disabled_builder_preserves_fresh_runtime_without_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifacts: RuntimeArtifacts,
) -> None:
    _configure_plant_environment(
        monkeypatch,
        tmp_path,
        artifacts,
        mode="disabled",
    )
    monkeypatch.delenv("AEGIS_PLANT_CHECKPOINT_FILE", raising=False)

    runtime = runtime_module._build_plant_runtime()

    assert not runtime.checkpoint_required
    assert runtime.checkpoint_store is None
    assert runtime.health().state_version == 0


def test_builder_restores_fresh_observation_and_next_call_advances_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifacts: RuntimeArtifacts,
) -> None:
    _configure_plant_environment(
        monkeypatch,
        tmp_path,
        artifacts,
        mode="required",
    )
    path = _checkpoint_path(tmp_path)
    model = PandapowerCigreMVPlant(observed_at=NOW)
    provisioner = DurablePlantCheckpointStore(
        path,
        plant_key_id=PLANT_KEY_ID,
        model_digest=model.model_digest,
        initialize=True,
    )
    provisioner.close()
    monkeypatch.setenv("AEGIS_PLANT_CHECKPOINT_FILE", str(path))

    first = runtime_module._build_plant_runtime()
    first_store = first.checkpoint_store
    assert first.checkpoint_required
    assert first_store is not None
    assert first_store.current() == first.plant.read_state()
    first_call = _dynamic_apply_call(
        first,
        caller_private=artifacts.ot_private,
        caller_key_id=OT_KEY_ID,
        command=artifacts.command,
        nonce="m4i-builder-first-apply-0001",
        issued_at=first.clock(),
    )
    first_status, first_response = first.execute(first_call)
    assert first_status == 200
    assert isinstance(first_response.payload, PlantStateResponsePayload)
    retained = first_store.current()
    assert retained == first_response.payload.snapshot
    first_source = retained.observation_source_id
    first_store.close()

    restarted = runtime_module._build_plant_runtime()
    restarted_store = restarted.checkpoint_store
    assert restarted_store is not None
    restored = restarted.plant.read_state()
    _assert_same_physical_state(restored, retained)
    assert restored.observation_source_id != first_source
    assert restored.observation_sequence == 0
    assert restored.observation_digest != retained.observation_digest
    assert restarted.health().state_version == retained.state_version

    next_call = _dynamic_apply_call(
        restarted,
        caller_private=artifacts.ot_private,
        caller_key_id=OT_KEY_ID,
        command=_battery_dispatch("m4i-builder-next-command-0001"),
        nonce="m4i-builder-next-apply-0001",
        issued_at=restarted.clock(),
    )
    next_status, next_response = restarted.execute(next_call)
    assert next_status == 200
    assert isinstance(next_response.payload, PlantStateResponsePayload)
    advanced = restarted_store.current()
    assert advanced == next_response.payload.snapshot
    assert advanced.state_version == retained.state_version + 1
    restarted_store.close()


def test_required_health_and_calls_fail_closed_on_live_checkpoint_drift(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    runtime, plant, store = _required_runtime(tmp_path, artifacts)
    plant.apply_authorized_command(artifacts.command)

    with pytest.raises(CapabilityRuntimeUnavailable, match="plant_checkpoint_unavailable"):
        runtime.health()

    call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.READ,
        payload=PlantReadPayload(correlation_id="m4i-checkpoint-drift-read"),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4i-checkpoint-drift-read-0001",
        private_key=artifacts.ot_private,
    )
    with pytest.raises(CapabilityRuntimeUnavailable, match="plant_checkpoint_unavailable"):
        runtime.execute(call)
    assert runtime._call_reservations == {}
    store.close()


@pytest.mark.parametrize("fault", ("missing", "corrupt", "identity_mismatch"))
def test_required_builder_rejects_untrusted_checkpoint_before_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifacts: RuntimeArtifacts,
    fault: str,
) -> None:
    _configure_plant_environment(
        monkeypatch,
        tmp_path,
        artifacts,
        mode="required",
    )
    path = _checkpoint_path(tmp_path)
    model = PandapowerCigreMVPlant(observed_at=NOW)
    if fault != "missing":
        provisioner = DurablePlantCheckpointStore(
            path,
            plant_key_id=(
                "different-plant-key-id" if fault == "identity_mismatch" else PLANT_KEY_ID
            ),
            model_digest=model.model_digest,
            initialize=True,
        )
        provisioner.close()
    if fault == "corrupt":
        path.write_bytes(b"{")
        path.chmod(0o600)
    monkeypatch.setenv("AEGIS_PLANT_CHECKPOINT_FILE", str(path))

    for _ in range(2):
        with pytest.raises(
            CapabilityRuntimeUnavailable,
            match="plant_checkpoint_unavailable",
        ):
            runtime_module._build_plant_runtime()

    if fault == "identity_mismatch":
        reopened = DurablePlantCheckpointStore(
            path,
            plant_key_id="different-plant-key-id",
            model_digest=model.model_digest,
        )
        reopened.close()


def test_post_replace_failure_is_unavailable_and_restart_restores_new_disk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifacts: RuntimeArtifacts,
) -> None:
    runtime, plant, store = _required_runtime(tmp_path, artifacts)
    baseline = plant.read_state()
    expected = plant.simulate_candidate(artifacts.command).post_state
    path = store.path
    real_fsync = os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected post-replace failure")
        real_fsync(descriptor)

    monkeypatch.setattr(checkpoint_module.os, "fsync", fail_directory_fsync)
    call = _plant_call(
        role=PlantCallerRole.PLC,
        operation=PlantOperation.APPLY,
        payload=_apply_payload(artifacts),
        caller_key_id=OT_KEY_ID,
        target_plant_key_id=PLANT_KEY_ID,
        target_plant_boot_epoch=PLANT_BOOT,
        nonce="m4i-checkpoint-uncertain-apply-0001",
        private_key=artifacts.ot_private,
    )

    with pytest.raises(CapabilityRuntimeUnavailable, match="plant_checkpoint_unavailable"):
        runtime.execute(call)
    assert plant.read_state() == baseline
    assert runtime.apply_requests == 1
    assert runtime.commit_count == 0
    with pytest.raises(PlantCheckpointError, match="uncertain update"):
        store.current()
    store.close()

    reopened = DurablePlantCheckpointStore(
        path,
        plant_key_id=PLANT_KEY_ID,
        model_digest=plant.model_digest,
    )
    retained = reopened.current()
    assert retained is not None
    _assert_same_physical_state(retained, expected)
    restored_plant = PandapowerCigreMVPlant(
        observed_at=NOW + timedelta(minutes=1),
        observation_source_id="m4i-restarted-after-uncertain-effect",
    )
    restored = restored_plant.restore_state(retained)
    _assert_same_physical_state(restored, retained)
    assert reopened.verify_current(restored).state_digest == retained.state_digest
    reopened.close()
