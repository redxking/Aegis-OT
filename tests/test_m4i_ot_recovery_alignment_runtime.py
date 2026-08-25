from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from test_m4g_runtime import (
    NOW,
    OT_BOOT,
    PLC_ID,
    RuntimeArtifacts,
    _observer_info,
    _plant_health,
)
from test_m4g_runtime import artifacts as runtime_artifacts_fixture
from test_m4i_ot_coordination_runtime import (
    CoordinatedDevice,
    CoordinationIdentities,
    CountingReplay,
    MutableClock,
    _dispatch,
    _identities,
    _open_journal,
)

from aegis_ot.capability_models import PlcCommandAcknowledgment
from aegis_ot.coordination_journal import (
    CommitAdmissionStatus,
    DurableEffectCoordinationJournal,
)
from aegis_ot.coordination_models import (
    CoordinationReceipt,
    CoordinationState,
    DurableCommitAcceptance,
    EffectDisposition,
    EffectIdentity,
    SignedEffectCommitRequest,
    SignedEffectOutcome,
    SignedEffectPrepareRequest,
    SignedEffectQueryRequest,
)
from aegis_ot.coordination_recovery import (
    CoordinationRecoveryReason,
    CoordinationRecoveryStatus,
)
from aegis_ot.segmented_capability_models import SegmentedCapabilityDispatch
from aegis_ot.segmented_capability_runtime import (
    CapabilityAdmissionRejected,
    CapabilityOtRuntime,
    CapabilityRuntimeUnavailable,
    create_ot_app,
)
from aegis_ot.segmented_capability_transport import PlantHealthMetadata

_ARTIFACT_FACTORY = cast(Callable[[], RuntimeArtifacts], runtime_artifacts_fixture.__wrapped__)


@pytest.fixture(scope="module")
def artifacts() -> RuntimeArtifacts:
    return _ARTIFACT_FACTORY()


@dataclass
class MutablePlantHealthLoader:
    current: PlantHealthMetadata
    calls: int = 0

    def __call__(self) -> PlantHealthMetadata:
        self.calls += 1
        return self.current


@dataclass
class RecoveryDevice(CoordinatedDevice):
    before_execute: Callable[[], None] | None = None
    after_execute: Callable[[], None] | None = None

    def execute(self, **kwargs: Any) -> PlcCommandAcknowledgment:
        if self.before_execute is not None:
            self.before_execute()
        acknowledgment = super().execute(**kwargs)
        if self.after_execute is not None:
            self.after_execute()
        return acknowledgment


@dataclass(frozen=True)
class RecoveryHarness:
    runtime: CapabilityOtRuntime
    device: RecoveryDevice
    journal: DurableEffectCoordinationJournal
    journal_path: Path
    identities: CoordinationIdentities
    dispatch: SegmentedCapabilityDispatch
    clock: MutableClock
    loader: MutablePlantHealthLoader
    pre_plant: PlantHealthMetadata
    post_plant: PlantHealthMetadata


def _post_plant(
    pre_plant: PlantHealthMetadata,
    artifacts: RuntimeArtifacts,
) -> PlantHealthMetadata:
    acknowledgment = artifacts.acknowledgment
    assert acknowledgment.post_state_version is not None
    assert acknowledgment.post_state_digest is not None
    return pre_plant.model_copy(
        update={
            "state_version": acknowledgment.post_state_version,
            "state_digest": acknowledgment.post_state_digest,
            "apply_requests": 1,
            "commit_count": 1,
        }
    )


def _device(
    artifacts: RuntimeArtifacts,
    identities: CoordinationIdentities,
    dispatch: SegmentedCapabilityDispatch,
    clock: MutableClock,
    *,
    boot_epoch: str = OT_BOOT,
) -> RecoveryDevice:
    return RecoveryDevice(
        artifacts=artifacts,
        dispatch=dispatch,
        acknowledgment_private_key=identities.local_signer.private_key,
        acknowledgment_key_id=identities.local_signer.credential.credential.key_id,
        boot_epoch=boot_epoch,
        clock=clock,
    )


def _runtime(
    artifacts: RuntimeArtifacts,
    identities: CoordinationIdentities,
    dispatch: SegmentedCapabilityDispatch,
    journal: DurableEffectCoordinationJournal,
    clock: MutableClock,
    loader: MutablePlantHealthLoader,
    device: RecoveryDevice,
    pre_plant: PlantHealthMetadata,
    *,
    coordination_required: bool = True,
    boot_epoch: str = OT_BOOT,
) -> CapabilityOtRuntime:
    return CapabilityOtRuntime(
        device=cast(Any, device),
        transport_replay=cast(Any, CountingReplay()),
        gateway_public_key=identities.gateway_signer.private_key.public_key(),
        gateway_key_id=identities.gateway_signer.credential.credential.key_id,
        observer_info=_observer_info(artifacts),
        permit_public_key=artifacts.permit_private.public_key(),
        permit_key_id=artifacts.permit_key_id,
        private_key=identities.local_signer.private_key,
        key_id=identities.local_signer.credential.credential.key_id,
        plc_id=PLC_ID,
        boot_epoch=boot_epoch,
        plant_info=pre_plant,
        semantic_replay=cast(Any, CountingReplay()),
        gateway_workload_identity=(identities.gateway_binding if coordination_required else None),
        local_workload_identity=(identities.local_identity if coordination_required else None),
        coordination_required=coordination_required,
        coordination_journal=journal if coordination_required else None,
        plant_health_loader=loader if coordination_required else None,
        clock=clock,
    )


def _harness(tmp_path: Path, artifacts: RuntimeArtifacts) -> RecoveryHarness:
    tmp_path.chmod(0o700)
    identities = _identities(tmp_path)
    dispatch = _dispatch(artifacts, identities)
    journal_path = tmp_path / "coordination" / "ot-coordination.json"
    journal = _open_journal(journal_path, initialize=True)
    clock = MutableClock(NOW + timedelta(milliseconds=250))
    pre_plant = _plant_health(artifacts)
    post_plant = _post_plant(pre_plant, artifacts)
    loader = MutablePlantHealthLoader(pre_plant)
    device = _device(artifacts, identities, dispatch, clock)
    device.after_execute = lambda: setattr(loader, "current", post_plant)
    runtime = _runtime(
        artifacts,
        identities,
        dispatch,
        journal,
        clock,
        loader,
        device,
        pre_plant,
    )
    return RecoveryHarness(
        runtime=runtime,
        device=device,
        journal=journal,
        journal_path=journal_path,
        identities=identities,
        dispatch=dispatch,
        clock=clock,
        loader=loader,
        pre_plant=pre_plant,
        post_plant=post_plant,
    )


def _restart(
    harness: RecoveryHarness,
    artifacts: RuntimeArtifacts,
    *,
    current_plant: PlantHealthMetadata,
) -> RecoveryHarness:
    journal = _open_journal(harness.journal_path, initialize=False)
    loader = MutablePlantHealthLoader(current_plant)
    device = _device(
        artifacts,
        harness.identities,
        harness.dispatch,
        harness.clock,
        boot_epoch=OT_BOOT,
    )
    runtime = _runtime(
        artifacts,
        harness.identities,
        harness.dispatch,
        journal,
        harness.clock,
        loader,
        device,
        harness.pre_plant,
        boot_epoch=device.boot_epoch,
    )
    return RecoveryHarness(
        runtime=runtime,
        device=device,
        journal=journal,
        journal_path=harness.journal_path,
        identities=harness.identities,
        dispatch=harness.dispatch,
        clock=harness.clock,
        loader=loader,
        pre_plant=harness.pre_plant,
        post_plant=harness.post_plant,
    )


def _prepare_request(harness: RecoveryHarness) -> SignedEffectPrepareRequest:
    return SignedEffectPrepareRequest.issue(
        dispatch=harness.dispatch,
        signer=harness.identities.gateway_signer,
        request_nonce="m4i-recovery-prepare-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=20),
    )


def _commit_request(
    harness: RecoveryHarness,
    receipt: CoordinationReceipt,
) -> SignedEffectCommitRequest:
    return SignedEffectCommitRequest.issue(
        receipt=receipt,
        signer=harness.identities.gateway_signer,
        request_nonce="m4i-recovery-commit-nonce-00001",
        issued_at=NOW + timedelta(milliseconds=500),
        expires_at=NOW + timedelta(seconds=20),
    )


def _query_request(
    harness: RecoveryHarness,
    *,
    sequence: int,
) -> SignedEffectQueryRequest:
    issued_at = harness.clock.value - timedelta(milliseconds=100)
    return SignedEffectQueryRequest.issue(
        effect=EffectIdentity.from_dispatch(harness.dispatch),
        signer=harness.identities.gateway_signer,
        request_nonce=f"m4i-recovery-query-nonce-{sequence:04d}",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=20),
    )


def _post_model(client: TestClient, path: str, value: Any) -> Any:
    return client.post(
        path,
        content=value.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


def _apply_once(harness: RecoveryHarness) -> SignedEffectOutcome:
    receipt = harness.runtime.prepare_effect(_prepare_request(harness))
    harness.clock.value = NOW + timedelta(milliseconds=750)
    outcome = harness.runtime.commit_effect(_commit_request(harness, receipt))
    assert outcome.disposition is EffectDisposition.APPLIED
    return outcome


def test_empty_baseline_and_health_expose_closed_recovery_projection(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    try:
        assert harness.loader.calls == 1

        health = harness.runtime.health()
        projection = health.coordination_recovery

        assert projection is not None
        assert projection.status is CoordinationRecoveryStatus.ALIGNED
        assert projection.reason is CoordinationRecoveryReason.ALIGNED_EMPTY_BASELINE
        assert projection.record_count == 0
        assert projection.applied_effect_count == 0
        assert projection.pending_effect_count == 0
        assert projection.plant_state_version == harness.pre_plant.state_version
        assert projection.plant_state_digest == harness.pre_plant.state_digest
        assert not projection.live_commit_armed
        assert projection.limitation == "ordinary_single_volume_alignment_only"

        response = TestClient(create_ot_app(lambda: harness.runtime)).get("/health")
        assert response.status_code == 200
        assert response.json()["coordination_recovery"] == projection.model_dump(mode="json")
        assert harness.loader.calls == 3
    finally:
        harness.journal.close()


def test_live_prepare_retry_and_commit_carveout_clear_before_execution_and_restart_aligned(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    prepare = _prepare_request(harness)
    receipt = harness.runtime.prepare_effect(prepare)
    repeated = harness.runtime.prepare_effect(prepare)
    assert repeated == receipt
    pending = harness.runtime.health().coordination_recovery
    assert pending is not None
    assert pending.status is CoordinationRecoveryStatus.RECOVERY_REQUIRED
    assert pending.reason is CoordinationRecoveryReason.PENDING_EFFECT_AT_PRE_STATE
    assert pending.live_commit_armed

    marker_was_cleared = False

    def observe_commit_boundary() -> None:
        nonlocal marker_was_cleared
        marker_was_cleared = harness.runtime._live_commit_marker is None

    harness.device.before_execute = observe_commit_boundary
    harness.clock.value = NOW + timedelta(milliseconds=750)
    outcome = harness.runtime.commit_effect(_commit_request(harness, receipt))

    assert outcome.disposition is EffectDisposition.APPLIED
    assert marker_was_cleared
    assert harness.device.calls == 1
    aligned = harness.runtime.health().coordination_recovery
    assert aligned is not None
    assert aligned.status is CoordinationRecoveryStatus.ALIGNED
    assert aligned.reason is CoordinationRecoveryReason.ALIGNED_APPLIED_CHAIN
    assert not aligned.live_commit_armed

    harness.journal.close()
    restarted = _restart(harness, artifacts, current_plant=harness.post_plant)
    try:
        assert restarted.loader.calls == 1
        assert restarted.device.calls == 0
        restarted.clock.value = NOW + timedelta(seconds=3)
        query_outcome = restarted.runtime.query_effect(_query_request(restarted, sequence=1))
        assert query_outcome.disposition is EffectDisposition.APPLIED
        assert restarted.device.calls == 0
        historical = restarted.runtime.health().coordination_recovery
        assert historical is not None
        assert historical.status is CoordinationRecoveryStatus.ALIGNED
        assert historical.reason is CoordinationRecoveryReason.ALIGNED_APPLIED_CHAIN
    finally:
        restarted.journal.close()


def test_live_marker_cannot_commit_when_current_plant_is_already_at_post_state(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    prepare = _prepare_request(harness)
    receipt = harness.runtime.prepare_effect(prepare)
    harness.loader.current = harness.post_plant
    harness.clock.value = NOW + timedelta(milliseconds=750)
    commit = _commit_request(harness, receipt)
    try:
        recovery = harness.runtime.health().coordination_recovery
        assert recovery is not None
        assert recovery.status is CoordinationRecoveryStatus.RECOVERY_REQUIRED
        assert recovery.reason is CoordinationRecoveryReason.PENDING_EFFECT_AT_POST_STATE
        assert not recovery.live_commit_armed

        with pytest.raises(
            CapabilityAdmissionRejected,
            match="effect_reconciliation_required",
        ):
            harness.runtime.commit_effect(commit)
        assert harness.device.calls == 0

        harness.clock.value = NOW + timedelta(seconds=3)
        with pytest.raises(
            CapabilityRuntimeUnavailable,
            match="effect_coordination_recovery_unavailable",
        ):
            harness.runtime.query_effect(_query_request(harness, sequence=8))
        record = harness.journal.get(prepare.effect)
        assert record is not None
        assert record.state is CoordinationState.NOT_DISPATCHED
        assert harness.device.calls == 0
    finally:
        harness.journal.close()


def test_pending_at_pre_restart_is_query_only_and_prepare_replay_stays_blocked(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    prepare = _prepare_request(harness)
    receipt = harness.runtime.prepare_effect(prepare)
    commit = _commit_request(harness, receipt)
    harness.clock.value = NOW + timedelta(milliseconds=750)
    harness.journal.close()
    restarted = _restart(harness, artifacts, current_plant=harness.pre_plant)
    try:
        recovery = restarted.runtime.health().coordination_recovery
        assert recovery is not None
        assert recovery.status is CoordinationRecoveryStatus.RECOVERY_REQUIRED
        assert recovery.reason is CoordinationRecoveryReason.PENDING_EFFECT_AT_PRE_STATE
        assert not recovery.live_commit_armed

        with pytest.raises(
            CapabilityAdmissionRejected,
            match="effect_reconciliation_required",
        ):
            restarted.runtime.prepare_effect(prepare)
        with pytest.raises(
            CapabilityAdmissionRejected,
            match="effect_reconciliation_required",
        ):
            restarted.runtime.commit_effect(commit)

        restarted.clock.value = NOW + timedelta(seconds=3)
        outcome = restarted.runtime.query_effect(_query_request(restarted, sequence=2))
        assert outcome.disposition is EffectDisposition.NOT_DISPATCHED
        assert restarted.device.calls == 0
        aligned = restarted.runtime.health().coordination_recovery
        assert aligned is not None
        assert aligned.status is CoordinationRecoveryStatus.ALIGNED
        assert aligned.reason is CoordinationRecoveryReason.ALIGNED_EMPTY_BASELINE
    finally:
        restarted.journal.close()


def test_pending_at_post_restart_is_query_only_and_remains_explicitly_unknown(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    prepare = _prepare_request(harness)
    receipt = harness.runtime.prepare_effect(prepare)
    harness.clock.value = NOW + timedelta(milliseconds=750)
    commit = _commit_request(harness, receipt)
    admission = harness.journal.begin_commit(
        commit,
        lambda exact_request, *, accepted_at, transition_sequence: DurableCommitAcceptance.issue(
            request=exact_request,
            signer=harness.identities.local_signer,
            accepted_at=accepted_at,
            transition_sequence=transition_sequence,
        ),
        recorded_at=harness.clock.value,
    )
    assert admission.status is CommitAdmissionStatus.NEW
    harness.journal.close()
    restarted = _restart(harness, artifacts, current_plant=harness.post_plant)
    try:
        recovery = restarted.runtime.health().coordination_recovery
        assert recovery is not None
        assert recovery.status is CoordinationRecoveryStatus.RECOVERY_REQUIRED
        assert recovery.reason is CoordinationRecoveryReason.PENDING_EFFECT_AT_POST_STATE
        assert not recovery.live_commit_armed

        with pytest.raises(
            CapabilityAdmissionRejected,
            match="effect_reconciliation_required",
        ):
            restarted.runtime.prepare_effect(prepare)
        with pytest.raises(
            CapabilityAdmissionRejected,
            match="effect_reconciliation_required",
        ):
            restarted.runtime.commit_effect(commit)

        restarted.clock.value = NOW + timedelta(seconds=3)
        outcome = restarted.runtime.query_effect(_query_request(restarted, sequence=3))
        assert outcome.disposition is EffectDisposition.UNKNOWN_EFFECT
        assert outcome.acceptance == admission.acceptance
        assert restarted.device.calls == 0
        still_pending = restarted.runtime.health().coordination_recovery
        assert still_pending is not None
        assert still_pending.status is CoordinationRecoveryStatus.RECOVERY_REQUIRED
        assert still_pending.reason is CoordinationRecoveryReason.PENDING_EFFECT_AT_POST_STATE
    finally:
        restarted.journal.close()


@pytest.mark.parametrize("failure", ["journal_rollback", "plant_rollback", "digest"])
def test_restart_detects_ordinary_store_misalignment_before_any_effect(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
    failure: str,
) -> None:
    harness = _harness(tmp_path, artifacts)
    _apply_once(harness)
    harness.journal.close()

    if failure == "journal_rollback":
        rolled_directory = tmp_path / "rolled-back"
        journal = _open_journal(
            rolled_directory / "ot-coordination.json",
            initialize=True,
        )
        current_plant = harness.post_plant
    else:
        journal = _open_journal(harness.journal_path, initialize=False)
        if failure == "plant_rollback":
            current_plant = harness.pre_plant
        else:
            mismatched_digest = (
                "e" * 64 if harness.post_plant.state_digest != "e" * 64 else "f" * 64
            )
            current_plant = harness.post_plant.model_copy(
                update={"state_digest": mismatched_digest}
            )

    loader = MutablePlantHealthLoader(current_plant)
    device = _device(
        artifacts,
        harness.identities,
        harness.dispatch,
        harness.clock,
        boot_epoch="m4i-recovery-failed-restart-boot-0003",
    )
    try:
        with pytest.raises(
            CapabilityRuntimeUnavailable,
            match="^effect_coordination_recovery_unavailable$",
        ):
            _runtime(
                artifacts,
                harness.identities,
                harness.dispatch,
                journal,
                harness.clock,
                loader,
                device,
                harness.pre_plant,
                boot_epoch=device.boot_epoch,
            )
        assert loader.calls == 1
        assert device.calls == 0
    finally:
        journal.close()


@pytest.mark.parametrize("drift", ["state", "identity"])
def test_current_plant_drift_fails_closed_with_stable_api_reason(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
    drift: str,
) -> None:
    harness = _harness(tmp_path, artifacts)
    prepare = _prepare_request(harness)
    if drift == "identity":
        harness.loader.current = harness.pre_plant.model_copy(
            update={"boot_epoch": "m4i-drifted-plant-boot-epoch-0002"}
        )
    else:
        harness.loader.current = harness.pre_plant.model_copy(
            update={"state_version": 1, "state_digest": "f" * 64}
        )
    client = TestClient(create_ot_app(lambda: harness.runtime))
    try:
        health = client.get("/health")
        rejected = _post_model(client, "/v1/effects/prepare", prepare)

        assert health.status_code == 503
        assert health.json()["reason"] == "effect_coordination_recovery_unavailable"
        assert rejected.status_code == 503
        assert rejected.json()["reason"] == ("effect_coordination_recovery_unavailable")
        assert harness.journal.records() == ()
        assert harness.device.calls == 0
    finally:
        harness.journal.close()


def test_required_loader_is_strict_and_disabled_direct_construction_is_unchanged(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    harness.journal.close()
    journal = _open_journal(harness.journal_path, initialize=False)
    strict_device = _device(
        artifacts,
        harness.identities,
        harness.dispatch,
        harness.clock,
    )
    try:
        with pytest.raises(ValueError, match="current plant-health loader"):
            CapabilityOtRuntime(
                device=cast(Any, strict_device),
                transport_replay=cast(Any, CountingReplay()),
                gateway_public_key=(harness.identities.gateway_signer.private_key.public_key()),
                gateway_key_id=(harness.identities.gateway_signer.credential.credential.key_id),
                observer_info=_observer_info(artifacts),
                permit_public_key=artifacts.permit_private.public_key(),
                permit_key_id=artifacts.permit_key_id,
                private_key=harness.identities.local_signer.private_key,
                key_id=harness.identities.local_signer.credential.credential.key_id,
                plc_id=PLC_ID,
                boot_epoch=OT_BOOT,
                plant_info=harness.pre_plant,
                semantic_replay=cast(Any, CountingReplay()),
                gateway_workload_identity=harness.identities.gateway_binding,
                local_workload_identity=harness.identities.local_identity,
                coordination_required=True,
                coordination_journal=journal,
                clock=harness.clock,
            )

        disabled_device = _device(
            artifacts,
            harness.identities,
            harness.dispatch,
            harness.clock,
        )
        unused_loader = MutablePlantHealthLoader(harness.pre_plant)
        disabled = _runtime(
            artifacts,
            harness.identities,
            harness.dispatch,
            journal,
            harness.clock,
            unused_loader,
            disabled_device,
            harness.pre_plant,
            coordination_required=False,
        )

        assert disabled.health().coordination_recovery is None
        assert unused_loader.calls == 0
        assert disabled_device.calls == 0
    finally:
        journal.close()


def test_lazy_startup_recovery_failure_preserves_stable_api_reason(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    prepare = _prepare_request(harness)

    def unavailable() -> CapabilityOtRuntime:
        raise CapabilityRuntimeUnavailable("effect_coordination_recovery_unavailable")

    client = TestClient(create_ot_app(unavailable))
    try:
        for path, request in (
            ("/v1/effects/prepare", prepare),
            (
                "/v1/effects/query",
                SignedEffectQueryRequest.issue(
                    effect=prepare.effect,
                    signer=harness.identities.gateway_signer,
                    request_nonce="m4i-recovery-unavailable-query-0001",
                    issued_at=NOW,
                    expires_at=NOW + timedelta(seconds=20),
                ),
            ),
        ):
            response = _post_model(client, path, request)
            assert response.status_code == 503
            assert response.json()["reason"] == ("effect_coordination_recovery_unavailable")
        assert harness.device.calls == 0
    finally:
        harness.journal.close()
