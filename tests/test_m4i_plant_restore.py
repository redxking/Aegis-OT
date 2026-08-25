from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis_ot.models import Operation
from aegis_ot.pandapower_plant import (
    PandapowerCigreMVPlant,
    PhysicalSimulationError,
)
from aegis_ot.physical_models import (
    PhysicalCommandType,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
)

CHECKPOINT_TIME = datetime(2026, 8, 25, 18, 0, tzinfo=UTC)
RESTORE_TIME = datetime(2026, 8, 25, 18, 5, tzinfo=UTC)


def _line_isolation(command_id: str = "restore-line-command") -> PhysicalControlCommand:
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
    command_id: str = "restore-battery-command",
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


def _checkpoint() -> PhysicalStateSnapshot:
    plant = PandapowerCigreMVPlant(
        observed_at=CHECKPOINT_TIME,
        observation_source_id="plant-before-restart",
    )
    plant.apply_authorized_command(_line_isolation())
    return plant.apply_authorized_command(_battery_dispatch())


def _rehash(snapshot: PhysicalStateSnapshot) -> PhysicalStateSnapshot:
    with_state_digest = snapshot.model_copy(
        update={"state_digest": canonical_digest(snapshot.digest_material())}
    )
    return with_state_digest.model_copy(
        update={
            "observation_digest": canonical_digest(
                with_state_digest.observation_material()
            )
        }
    )


def test_restore_rebuilds_registered_controls_with_fresh_observation() -> None:
    checkpoint = _checkpoint()
    restored_plant = PandapowerCigreMVPlant(
        observed_at=RESTORE_TIME,
        observation_source_id="plant-after-restart",
    )

    restored = restored_plant.restore_state(checkpoint)

    assert restored == restored_plant.read_state()
    assert restored.state_digest == checkpoint.state_digest
    assert restored.input_digest == checkpoint.input_digest
    assert restored.topology_digest == checkpoint.topology_digest
    assert restored.state_version == checkpoint.state_version == 2
    assert restored.simulation_time_s == checkpoint.simulation_time_s == 2.0
    assert restored.isolated_resources == ("feeder-1",)
    assert restored.battery_injection_mw["battery-1"] == pytest.approx(0.2)
    assert restored.observation_source_id == "plant-after-restart"
    assert restored.observation_sequence == 0
    assert restored.observed_at == RESTORE_TIME
    assert restored.observation_digest != checkpoint.observation_digest
    assert restored.verify_digest()


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("model", "restore_model_mismatch"),
        ("input", "restore_input_digest_mismatch"),
        ("topology", "restore_topology_digest_mismatch"),
        ("state", "restore_state_digest_mismatch"),
    ],
)
def test_restore_rejects_mismatch_without_mutating_live_plant(
    mutation: str,
    reason: str,
) -> None:
    checkpoint = _checkpoint()
    if mutation == "model":
        checkpoint = checkpoint.model_copy(update={"model_digest": "a" * 64})
    elif mutation == "input":
        checkpoint = checkpoint.model_copy(update={"input_digest": "b" * 64})
    elif mutation == "topology":
        checkpoint = checkpoint.model_copy(update={"topology_digest": "c" * 64})
    else:
        assert checkpoint.minimum_voltage_pu is not None
        checkpoint = checkpoint.model_copy(
            update={"minimum_voltage_pu": checkpoint.minimum_voltage_pu + 0.001}
        )
    checkpoint = _rehash(checkpoint)
    assert checkpoint.verify_digest()

    live = PandapowerCigreMVPlant(
        observed_at=RESTORE_TIME,
        observation_source_id="live-plant",
    )
    before = live.read_state()

    with pytest.raises(PhysicalSimulationError, match=reason):
        live.restore_state(checkpoint)

    assert live.read_state() == before


def test_restore_rejects_nonfresh_target_without_rolling_back() -> None:
    checkpoint = _checkpoint()
    live = PandapowerCigreMVPlant(
        observed_at=RESTORE_TIME,
        observation_source_id="live-plant",
    )
    live.apply_authorized_command(
        _battery_dispatch(-0.1, command_id="live-battery-command")
    )
    before = live.read_state()

    with pytest.raises(PhysicalSimulationError, match="restore_target_not_fresh"):
        live.restore_state(checkpoint)

    assert live.read_state() == before


def test_restore_rejects_unregistered_control_projection_atomically() -> None:
    checkpoint = _checkpoint().model_copy(
        update={"isolated_resources": ("feeder-1", "unregistered-feeder")}
    )
    checkpoint = _rehash(checkpoint)
    target = PandapowerCigreMVPlant(
        observed_at=RESTORE_TIME,
        observation_source_id="restore-target",
    )
    before = target.read_state()

    with pytest.raises(PhysicalSimulationError, match="restore_line_state_invalid"):
        target.restore_state(checkpoint)

    assert target.read_state() == before
