from __future__ import annotations

import ast
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_ot.models import ActionProposal, Operation
from aegis_ot.pandapower_plant import (
    CIGRE_MV_MODEL_ID,
    DEFAULT_RESOURCE_BINDINGS,
    PandapowerCigreMVPlant,
    PhysicalSimulationError,
)
from aegis_ot.physical_control import CommandTranslationError, TrustedCommandTranslator
from aegis_ot.physical_models import (
    PhysicalCommandType,
    PhysicalControlCommand,
    canonical_digest,
    proposal_digest,
)


def m3_proposal(
    now: datetime,
    *,
    resource: str = "feeder-1",
    operation: Operation = Operation.ISOLATE_ASSET,
    parameters: dict[str, float] | None = None,
    proposal_id: str = "m3-proposal-1",
) -> ActionProposal:
    return ActionProposal(
        proposal_id=proposal_id,
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource=resource,
        operation=operation,
        parameters=(
            parameters if parameters is not None else {"critical_load_impact_pct": 5.0}
        ),
        observed_state_version=0,
        observed_at=now,
        submitted_at=now,
        nonce=f"nonce-{proposal_id}-000000",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


def test_canonical_proposal_digest_is_stable_and_semantically_sensitive(now) -> None:
    proposal = m3_proposal(now)
    reordered = proposal.model_copy(update={"parameters": {"critical_load_impact_pct": 5.0}})
    changed = proposal.model_copy(update={"confidence": 0.94})
    assert proposal_digest(proposal) == proposal_digest(reordered)
    assert proposal_digest(proposal) != proposal_digest(changed)
    assert canonical_digest({"b": 2, "a": 1}) == canonical_digest({"a": 1, "b": 2})


def test_command_contract_rejects_inconsistent_shapes() -> None:
    with pytest.raises(ValidationError, match="boolean 0 or 1"):
        PhysicalControlCommand(
            proposal_id="p",
            operation=Operation.ISOLATE_ASSET,
            resource="feeder-1",
            command_type=PhysicalCommandType.SET_LINE_SERVICE,
            target="Line 5-6",
            target_index=4,
            setpoint=0.5,
            unit="boolean",
        )
    with pytest.raises(ValidationError, match="battery commands"):
        PhysicalControlCommand(
            proposal_id="p",
            operation=Operation.ISOLATE_ASSET,
            resource="battery-1",
            command_type=PhysicalCommandType.SET_BATTERY_INJECTION,
            target="Battery 1",
            target_index=0,
            setpoint=0.5,
            unit="MW",
        )


def test_translator_uses_fixed_resource_mapping_not_agent_consequence_estimates(now) -> None:
    translator = TrustedCommandTranslator()
    first = translator.translate(
        m3_proposal(now, parameters={"critical_load_impact_pct": 1.0})
    )
    second = translator.translate(
        m3_proposal(
            now,
            parameters={"critical_load_impact_pct": 20.0, "line_loading_delta_pct": 50.0},
            proposal_id="m3-proposal-2",
        )
    )
    assert first.target == second.target == "Line 5-6"
    assert first.target_index == second.target_index == 4
    assert first.setpoint == second.setpoint == 0.0


def test_translator_rejects_unmapped_mismatched_missing_and_out_of_range(now) -> None:
    translator = TrustedCommandTranslator()
    with pytest.raises(CommandTranslationError, match="resource_not_mapped"):
        translator.translate(m3_proposal(now, resource="unmapped-line"))
    with pytest.raises(CommandTranslationError, match="operation_resource_type_mismatch"):
        translator.translate(
            m3_proposal(
                now,
                resource="battery-1",
                operation=Operation.ISOLATE_ASSET,
            )
        )
    with pytest.raises(CommandTranslationError, match="battery_setpoint_missing"):
        translator.translate(
            m3_proposal(
                now,
                resource="battery-1",
                operation=Operation.DISPATCH_BATTERY,
                parameters={},
            )
        )
    with pytest.raises(CommandTranslationError, match="setpoint_out_of_bounds"):
        translator.translate(
            m3_proposal(
                now,
                resource="battery-1",
                operation=Operation.DISPATCH_BATTERY,
                parameters={"mw": 2.0},
            )
        )
    with pytest.raises(CommandTranslationError, match="operation_not_supported"):
        translator.translate(
            m3_proposal(
                now,
                operation=Operation.SHED_LOAD,
                parameters={"critical_load_impact_pct": 5.0},
            )
        )


def test_benchmark_baseline_is_converged_versioned_and_digest_verified(now) -> None:
    first = PandapowerCigreMVPlant(observed_at=now)
    second = PandapowerCigreMVPlant(observed_at=now + timedelta(seconds=1))
    state = first.read_state()
    assert state.model_id == CIGRE_MV_MODEL_ID
    assert state.simulator_version == "pandapower-3.5.4"
    assert state.converged
    assert state.state_version == 0
    assert state.simulation_time_s == 0.0
    assert state.total_load_served_pct == pytest.approx(100.0)
    assert state.priority_load_served_pct == pytest.approx(100.0)
    assert state.minimum_voltage_pu == pytest.approx(0.9438035447, abs=1e-9)
    assert state.maximum_line_loading_pct == pytest.approx(65.9722592930, abs=1e-8)
    assert state.verify_digest()
    assert state.model_digest == second.model_digest
    second_state = second.read_state()
    assert state.state_digest == second_state.state_digest
    assert state.observation_digest != second_state.observation_digest


def test_candidate_simulation_is_nonmutating_and_classifies_priority_loss(now) -> None:
    plant = PandapowerCigreMVPlant(observed_at=now)
    translator = TrustedCommandTranslator()
    safe_command = translator.translate(m3_proposal(now))
    unsafe_command = PhysicalControlCommand(
        proposal_id="root-feeder-2",
        operation=Operation.ISOLATE_ASSET,
        resource="feeder-2",
        command_type=PhysicalCommandType.SET_LINE_SERVICE,
        target="Line 8-9",
        target_index=6,
        setpoint=0.0,
        unit="boolean",
    )
    before = plant.read_state()
    safe = plant.simulate_candidate(safe_command)
    unsafe = plant.simulate_candidate(unsafe_command)
    after = plant.read_state()
    assert safe.safe
    assert safe.reasons == ()
    assert safe.post_state.total_load_served_pct < 100.0
    assert not unsafe.safe
    assert "priority_load_below_limit" in unsafe.reasons
    assert before.state_digest == after.state_digest
    assert after.state_version == 0


def test_authorized_apply_is_versioned_and_rejects_target_or_bounds(now) -> None:
    plant = PandapowerCigreMVPlant(observed_at=now)
    command = TrustedCommandTranslator().translate(m3_proposal(now))
    post = plant.apply_authorized_command(command)
    assert post.state_version == 1
    assert post.simulation_time_s == 1.0
    assert post.isolated_resources == ("feeder-1",)
    assert post.verify_digest()

    wrong_target = command.model_copy(update={"target_index": 5})
    with pytest.raises(PhysicalSimulationError, match="command_target_binding_mismatch"):
        plant.apply_authorized_command(wrong_target)
    out_of_bounds = PhysicalControlCommand(
        proposal_id="battery",
        operation=Operation.DISPATCH_BATTERY,
        resource="battery-1",
        command_type=PhysicalCommandType.SET_BATTERY_INJECTION,
        target="Battery 1",
        target_index=0,
        setpoint=2.0,
        unit="MW",
    )
    with pytest.raises(PhysicalSimulationError, match="command_setpoint_out_of_bounds"):
        plant.apply_authorized_command(out_of_bounds)


def test_authorized_apply_rejects_a_superseded_observation_envelope(now) -> None:
    plant = PandapowerCigreMVPlant(observed_at=now)
    command = TrustedCommandTranslator().translate(m3_proposal(now))
    pre = plant.capture_state()
    assessment = plant.simulate_candidate(command)
    superseding_observation = plant.capture_state()

    assert superseding_observation.state_digest == pre.state_digest
    assert superseding_observation.observation_digest != pre.observation_digest
    with pytest.raises(PhysicalSimulationError, match="precommit_observation_changed"):
        plant.apply_authorized_command(
            command,
            expected_pre_state_version=pre.state_version,
            expected_pre_state_digest=pre.state_digest,
            expected_pre_observation_digest=pre.observation_digest,
            expected_post_state_digest=assessment.post_state.state_digest,
            expected_post_topology_digest=assessment.post_state.topology_digest,
        )
    after = plant.read_state()
    assert after.state_version == pre.state_version
    assert after.isolated_resources == pre.isolated_resources


def test_invalid_plant_configuration_fails_before_simulation(now) -> None:
    with pytest.raises(ValueError, match="mission-priority"):
        PandapowerCigreMVPlant(observed_at=now, priority_load_indices=frozenset())
    with pytest.raises(ValueError, match="target name mismatch"):
        bad = dict(DEFAULT_RESOURCE_BINDINGS)
        bad["feeder-1"] = bad["feeder-1"].__class__(
            resource="feeder-1",
            command_type=PhysicalCommandType.SET_LINE_SERVICE,
            target="not-the-packaged-line",
            target_index=4,
            minimum_setpoint=0.0,
            maximum_setpoint=1.0,
        )
        PandapowerCigreMVPlant(observed_at=now, resource_bindings=bad)
    with pytest.raises(ValueError, match="step_seconds"):
        PandapowerCigreMVPlant(observed_at=now, step_seconds=0)
    with pytest.raises(ValueError, match="priority load indices"):
        PandapowerCigreMVPlant(observed_at=now, priority_load_indices=frozenset({999}))


def test_model_digest_covers_electrical_configuration_and_rejects_mutation(now) -> None:
    plant = PandapowerCigreMVPlant(observed_at=now)
    plant._net.trafo.at[0, "vk_percent"] += 0.1  # noqa: SLF001
    with pytest.raises(PhysicalSimulationError, match="model_configuration_changed"):
        plant.read_state()


def test_plant_module_has_no_gateway_safety_or_oracle_import() -> None:
    source_path = Path(__file__).parents[1] / "src" / "aegis_ot" / "pandapower_plant.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert "safety" not in imported
    assert "oracle" not in imported
