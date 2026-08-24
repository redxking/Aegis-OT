from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import datetime
from typing import Any, Never

import pytest

from aegis_ot.capability_factory import CapabilitySeparatedLab, start_capability_separated_lab
from aegis_ot.capability_ipc import IpcOutcomeUnknownError
from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopStatus,
    DispatchPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from aegis_ot.capability_plc import GatewayPlcClient
from aegis_ot.models import ActionProposal, DecisionOutcome, Operation
from aegis_ot.physical_models import CommandStatus


def _request_for(
    lab: CapabilitySeparatedLab,
    observation: SignedObservationEnvelope,
    *,
    suffix: str,
    actor_id: str = "agent:operator-1",
) -> CapabilityActionRequest:
    proposal = ActionProposal(
        proposal_id=f"capability-process-{suffix}",
        actor_id=actor_id,
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=observation.snapshot.state_version,
        observed_at=observation.snapshot.observed_at,
        submitted_at=observation.snapshot.observed_at,
        nonce=f"capability-process-{suffix}-nonce-0001",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )
    return lab.request_for(proposal, observation)


class _LosePlcResponse:
    """Deliver once to the real PLC, then model loss of its returned response."""

    def __init__(self, delegate: GatewayPlcClient) -> None:
        self.delegate = delegate
        self.calls = 0

    def execute(self, **kwargs: Any) -> Never:
        self.calls += 1
        self.delegate.execute(**kwargs)
        raise IpcOutcomeUnknownError("simulated PLC response loss after dispatch")


class _InterleaveTelemetryAfterPlc:
    """Capture unrelated telemetry after the PLC ACK but before controller post-capture."""

    def __init__(self, delegate: GatewayPlcClient, lab: CapabilitySeparatedLab) -> None:
        self.delegate = delegate
        self.lab = lab
        self.interleaved: SignedObservationEnvelope | None = None

    def execute(self, **kwargs: Any) -> PlcCommandAcknowledgment:
        acknowledgment = self.delegate.execute(**kwargs)
        self.interleaved = self.lab.capture_observation(
            correlation_id="interleaved-telemetry",
            challenge_nonce="interleaved-telemetry-challenge-0001",
        )
        return acknowledgment


@pytest.fixture
def capability_lab(now: datetime) -> Iterator[CapabilitySeparatedLab]:
    lab = start_capability_separated_lab(now)
    try:
        yield lab
    finally:
        lab.close()


def test_spawned_topology_keys_and_server_side_capability_denials(
    capability_lab: CapabilitySeparatedLab,
) -> None:
    lab = capability_lab
    stack = lab.processes
    pids = lab.topology_pids

    assert stack.context.get_start_method() == "spawn"
    assert pids["coordinator"] == os.getpid()
    assert len(set(pids.values())) == 4
    assert all(pid > 0 for pid in pids.values())
    assert stack.plant_process.pid == stack.plant_info.pid == pids["plant"]
    assert stack.observer_process.pid == stack.observer_info.pid == pids["observer"]
    assert stack.plc_process.pid == stack.plc_info.pid == pids["plc"]
    assert stack.plant_process.is_alive()
    assert stack.observer_process.is_alive()
    assert stack.plc_process.is_alive()

    assert stack.observer_info.plant_boot_epoch == stack.plant_info.boot_epoch
    assert stack.plc_info.plant_boot_epoch == stack.plant_info.boot_epoch
    assert stack.plc_info.observer_boot_epoch == stack.observer_info.boot_epoch
    assert len(
        {
            stack.permit_public_key_bytes,
            stack.observer_info.public_key_bytes,
            stack.plc_info.public_key_bytes,
        }
    ) == 3
    assert len(
        {
            stack.permit_key_id,
            stack.observer_info.key_id,
            stack.plc_info.key_id,
        }
    ) == 3

    request = _request_for(lab, lab.initial_observation, suffix="capability-probe")
    command = lab.controller.translator.translate(request.proposal)
    assert not hasattr(lab.controller, "plant")
    assert "capture_post" not in stack.observer_info.capabilities["telemetry"]
    assert stack.plant_info.capabilities["observer"] == ("capture_state", "health")
    assert "apply_authorized_command" not in stack.plant_info.capabilities["admin"]
    assert "apply_authorized_command" not in stack.plant_info.capabilities["simulation"]
    assert stack.telemetry.probe_forbidden_post_capture() == "capability_denied"
    assert stack.observer_admin.probe_forbidden_plant_apply(command) == "capability_denied"
    assert stack.plant_admin.probe_forbidden_apply(command) == "capability_denied"
    assert stack.simulator.probe_forbidden_apply(command) == "capability_denied"

    observer_health = stack.observer_admin.health()
    plant_health = stack.plant_admin.health()
    plc_health = stack.plc_admin.health()
    assert observer_health["status"] == plant_health["status"] == plc_health["status"] == "ready"
    assert observer_health["capture_count"] == 1
    assert plant_health["apply_requests"] == plant_health["commit_count"] == 0
    assert plc_health["execute_requests"] == plc_health["plc_scan"] == 0

    stack.telemetry._ipc._connection.send_bytes(b"{}")
    stack.simulator._ipc._connection.send_bytes(b"{}")
    stack.plc_gateway._ipc._connection.send_bytes(b"{}")
    assert stack.observer_admin.health()["status"] == "ready"
    assert stack.plant_admin.health()["status"] == "ready"
    assert stack.plc_admin.health()["status"] == "ready"


def test_nominal_completion_requires_both_signatures_and_exactly_one_effect(
    capability_lab: CapabilitySeparatedLab,
) -> None:
    lab = capability_lab
    result = lab.controller.execute(
        _request_for(lab, lab.initial_observation, suffix="nominal")
    )

    assert result.status is CapabilityClosedLoopStatus.COMPLETED
    assert result.decision is not None
    assert result.decision.outcome is DecisionOutcome.PERMIT
    assert result.pre_observation is not None
    assert result.permit is not None
    assert result.acknowledgment is not None
    assert result.post_observation is not None
    assert result.permit.verify(lab.permit_public_key)
    assert result.pre_observation.verify(lab.processes.observer_info.public_key)
    assert result.post_observation.verify(lab.processes.observer_info.public_key)
    assert result.acknowledgment.verify(lab.processes.plc_info.public_key)
    assert result.acknowledgment.verify_for_transaction(
        lab.processes.plc_info.public_key,
        request=result.request,
        permit=result.permit,
        pre_observation=result.pre_observation,
        expected_plc_id=lab.processes.plc_info.plc_id,
        expected_plc_key_id=lab.processes.plc_info.key_id,
        expected_plc_boot_epoch=lab.processes.plc_info.boot_epoch,
    )
    assert result.acknowledgment.status is CommandStatus.APPLIED
    assert result.acknowledgment.dispatch_phase is DispatchPhase.COMMITTED
    assert result.acknowledgment.dispatch_attempt == 1
    assert result.post_observation.plc_acknowledgment_digest == result.acknowledgment.digest
    assert (
        result.post_observation.previous_envelope_digest
        == result.pre_observation.envelope_digest
    )
    assert result.post_observation.snapshot.state_version == 1
    assert result.post_observation.snapshot.isolated_resources == ("feeder-1",)
    assert result.post_observation.snapshot.state_digest == result.acknowledgment.post_state_digest
    assert result.dispatch_attempts == 1
    assert result.automatic_retry_count == 0

    plant_health = lab.processes.plant_admin.health()
    observer_health = lab.processes.observer_admin.health()
    plc_health = lab.processes.plc_admin.health()
    assert plant_health["apply_requests"] == plant_health["commit_count"] == 1
    assert plant_health["state_version"] == 1
    assert observer_health["capture_count"] == 2
    assert observer_health["resolve_count"] == 1
    assert plc_health["execute_requests"] == plc_health["plc_scan"] == 1
    assert plc_health["replay_reservations"] == 1
    assert plc_health["automatic_retry_count"] == 0
    assert len(lab.authorization.gateway.evidence.records) == 2
    assert lab.authorization.gateway.evidence.verify()


def test_denied_proposal_has_zero_dispatch_and_zero_physical_effect(
    capability_lab: CapabilitySeparatedLab,
) -> None:
    lab = capability_lab
    initial_state = lab.initial_observation.snapshot
    result = lab.controller.execute(
        _request_for(
            lab,
            lab.initial_observation,
            suffix="identity-denied",
            actor_id="agent:unknown",
        )
    )

    assert result.status is CapabilityClosedLoopStatus.NOT_DISPATCHED
    assert result.decision is not None
    assert result.decision.outcome is DecisionOutcome.DENY
    assert "identity_not_verified" in result.reasons
    assert result.command is None
    assert result.permit is None
    assert result.acknowledgment is None
    assert result.post_observation is None
    assert result.dispatch_attempts == 0
    assert result.automatic_retry_count == 0

    plant_health = lab.processes.plant_admin.health()
    observer_health = lab.processes.observer_admin.health()
    plc_health = lab.processes.plc_admin.health()
    assert plant_health["state_version"] == initial_state.state_version
    assert plant_health["state_digest"] == initial_state.state_digest
    assert plant_health["apply_requests"] == plant_health["commit_count"] == 0
    assert observer_health["capture_count"] == observer_health["resolve_count"] == 1
    assert plc_health["execute_requests"] == plc_health["plc_scan"] == 0
    assert plc_health["replay_reservations"] == 0


def test_transaction_post_link_survives_unrelated_interleaved_telemetry(
    capability_lab: CapabilitySeparatedLab,
) -> None:
    lab = capability_lab
    interleaving_plc = _InterleaveTelemetryAfterPlc(lab.processes.plc_gateway, lab)
    lab.controller.plc = interleaving_plc

    result = lab.controller.execute(
        _request_for(lab, lab.initial_observation, suffix="interleaved-telemetry")
    )

    assert result.status is CapabilityClosedLoopStatus.COMPLETED
    assert interleaving_plc.interleaved is not None
    assert result.pre_observation is not None
    assert result.post_observation is not None
    assert interleaving_plc.interleaved.envelope_digest != result.pre_observation.envelope_digest
    assert (
        result.post_observation.previous_envelope_digest
        == result.pre_observation.envelope_digest
    )
    assert (
        result.post_observation.observer_sequence
        > interleaving_plc.interleaved.observer_sequence
    )


def test_lost_plc_response_is_unknown_without_retry_and_replay_survives_restart(
    capability_lab: CapabilitySeparatedLab,
) -> None:
    lab = capability_lab
    stack = lab.processes
    initial_state = lab.initial_observation.snapshot
    lost_response = _LosePlcResponse(stack.plc_gateway)
    lab.controller.plc = lost_response

    result = lab.controller.execute(
        _request_for(lab, lab.initial_observation, suffix="lost-plc-response")
    )

    assert result.status is CapabilityClosedLoopStatus.UNKNOWN_EFFECT
    assert result.reasons == ("plc_dispatch_outcome_unavailable", "IpcOutcomeUnknownError")
    assert result.acknowledgment is None
    assert result.post_observation is None
    assert result.dispatch_attempts == 1
    assert result.automatic_retry_count == 0
    assert lost_response.calls == 1
    assert result.pre_observation is not None
    assert result.decision is not None
    assert result.assessment is not None
    assert result.permit is not None

    post_loss_plant = stack.plant_admin.health()
    post_loss_observer = stack.observer_admin.health()
    post_loss_plc = stack.plc_admin.health()
    assert post_loss_plant["apply_requests"] == post_loss_plant["commit_count"] == 1
    assert post_loss_plant["state_version"] == initial_state.state_version + 1
    assert post_loss_observer["capture_count"] == post_loss_observer["resolve_count"] == 1
    assert post_loss_plc["execute_requests"] == post_loss_plc["plc_scan"] == 1
    assert post_loss_plc["automatic_retry_count"] == 0
    assert post_loss_plc["replay_reservations"] == 1
    assert stack.replay_ledger_path.is_file()
    assert stack.replay_ledger_path.stat().st_mode & 0o777 == 0o600

    prior_process = stack.plc_process
    prior_info = stack.plc_info
    restarted_info = lab.restart_plc()
    assert not prior_process.is_alive()
    assert restarted_info.pid != prior_info.pid
    assert restarted_info.boot_epoch != prior_info.boot_epoch
    assert restarted_info.public_key_bytes != prior_info.public_key_bytes

    replayed = stack.plc_gateway.execute(
        request=result.request,
        permit=result.permit,
        pre_observation=result.pre_observation,
        decision=result.decision,
        assessment=result.assessment,
    )
    assert replayed.status is CommandStatus.REJECTED
    assert replayed.dispatch_phase is DispatchPhase.PRE_DISPATCH
    assert replayed.reason == "transaction_replayed"
    assert replayed.verify(restarted_info.public_key)
    assert replayed.verify_for_transaction(
        restarted_info.public_key,
        request=result.request,
        permit=result.permit,
        pre_observation=result.pre_observation,
        expected_plc_id=restarted_info.plc_id,
        expected_plc_key_id=restarted_info.key_id,
        expected_plc_boot_epoch=restarted_info.boot_epoch,
    )

    final_plant = stack.plant_admin.health()
    restarted_plc = stack.plc_admin.health()
    assert final_plant["state_version"] == post_loss_plant["state_version"]
    assert final_plant["state_digest"] == post_loss_plant["state_digest"]
    assert final_plant["apply_requests"] == final_plant["commit_count"] == 1
    assert restarted_plc["execute_requests"] == restarted_plc["plc_scan"] == 1
    assert restarted_plc["automatic_retry_count"] == 0
    assert restarted_plc["replay_reservations"] == 1
