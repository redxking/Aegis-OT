from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from test_m4g_runtime import (
    NOW,
    OBSERVER_BOOT,
    OT_BOOT,
    PLC_ID,
    RuntimeArtifacts,
    _observer_info,
    _plant_health,
)
from test_m4g_runtime import artifacts as runtime_artifacts_fixture
from test_workload_identity import (
    TRUST_DOMAIN,
    _issue_bundle,
    _issue_credential,
    _write_identity_model,
)

from aegis_ot.capability_models import PlcCommandAcknowledgment
from aegis_ot.coordination_journal import (
    CommitAdmissionStatus,
    CoordinationJournalError,
    CoordinationJournalRecord,
    DurableEffectCoordinationJournal,
)
from aegis_ot.coordination_models import (
    EFFECT_COORDINATOR_AUDIENCE,
    GATEWAY_COORDINATION_AUDIENCE,
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
from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    OT_CAPABILITY_AUDIENCE,
    SegmentedCapabilityDispatch,
    WorkloadSignedCapabilityDispatch,
)
from aegis_ot.segmented_capability_runtime import (
    CapabilityAdmissionRejected,
    CapabilityOtRuntime,
    CapabilityRuntimeUnavailable,
    EffectCommitIndeterminate,
    create_ot_app,
    effect_coordination_enabled,
)
from aegis_ot.workload_identity import (
    WorkloadCredentialBinding,
    WorkloadIdentityVerifier,
    WorkloadRole,
    WorkloadSigner,
    workload_key_id,
)
from aegis_ot.workload_runtime import LocalWorkloadIdentity

GATEWAY_SUBJECT = "urn:aegis-ot:test:m4i:gateway"
OT_SUBJECT = "urn:aegis-ot:test:m4i:ot-adapter"
RESTARTED_OT_BOOT = "m4i-restarted-ot-boot-0002"
RESTARTED_OBSERVER_BOOT = "m4i-restarted-observer-boot-0002"

_ARTIFACT_FACTORY = cast(
    Any,
    runtime_artifacts_fixture,
).__wrapped__


@pytest.fixture(scope="module")
def artifacts() -> RuntimeArtifacts:
    return cast(RuntimeArtifacts, _ARTIFACT_FACTORY())


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


@dataclass
class CountingReplay:
    reservation_count: int = 0

    def reserve(self, *_: Any) -> bool:
        self.reservation_count += 1
        return True


@dataclass(frozen=True)
class CoordinationIdentities:
    authority: Ed25519PrivateKey
    bundle_path: Path
    gateway_path: Path
    local_path: Path
    gateway_signer: WorkloadSigner
    local_signer: WorkloadSigner
    gateway_binding: WorkloadCredentialBinding
    local_identity: LocalWorkloadIdentity


@dataclass
class CoordinatedDevice:
    artifacts: RuntimeArtifacts
    dispatch: SegmentedCapabilityDispatch
    acknowledgment_private_key: Ed25519PrivateKey
    acknowledgment_key_id: str
    boot_epoch: str
    clock: MutableClock
    plc_id: str = PLC_ID
    scan_counter: int = 0
    calls: int = 0
    fail_after_call: bool = False

    def execute(self, **_: Any) -> PlcCommandAcknowledgment:
        self.calls += 1
        self.scan_counter += 1
        if self.fail_after_call:
            raise OSError("synthetic post-acceptance device failure")
        return self.artifacts.acknowledgment.model_copy(
            update={
                "permit_digest": self.dispatch.permit.digest,
                "plc_key_id": self.acknowledgment_key_id,
                "plc_boot_epoch": self.boot_epoch,
                "plc_scan": self.scan_counter,
                "acknowledged_at": self.clock(),
                "signature": "",
            }
        ).signed(self.acknowledgment_private_key)


@dataclass(frozen=True)
class OtHarness:
    runtime: CapabilityOtRuntime
    device: CoordinatedDevice
    journal: DurableEffectCoordinationJournal
    journal_path: Path
    replay: CountingReplay
    identities: CoordinationIdentities
    dispatch: SegmentedCapabilityDispatch
    clock: MutableClock


def _identities(tmp_path: Path) -> CoordinationIdentities:
    authority = Ed25519PrivateKey.generate()
    gateway_private = Ed25519PrivateKey.generate()
    local_private = Ed25519PrivateKey.generate()
    gateway_credential = _issue_credential(
        authority,
        gateway_private,
        credential_id="credential-m4i-gateway-0001",
        subject=GATEWAY_SUBJECT,
        role=WorkloadRole.GATEWAY,
        audiences=(OT_CAPABILITY_AUDIENCE, EFFECT_COORDINATOR_AUDIENCE),
        issued_at=NOW - timedelta(minutes=5),
        not_before=NOW - timedelta(minutes=4),
        expires_at=NOW + timedelta(hours=1),
    )
    local_credential = _issue_credential(
        authority,
        local_private,
        credential_id="credential-m4i-ot-0001",
        subject=OT_SUBJECT,
        role=WorkloadRole.OT_ADAPTER,
        audiences=(GATEWAY_CAPABILITY_AUDIENCE, GATEWAY_COORDINATION_AUDIENCE),
        issued_at=NOW - timedelta(minutes=5),
        not_before=NOW - timedelta(minutes=4),
        expires_at=NOW + timedelta(hours=1),
    )
    bundle_path = tmp_path / "m4i-trust-bundle.json"
    gateway_path = tmp_path / "m4i-gateway-credential.json"
    local_path = tmp_path / "m4i-ot-credential.json"
    _write_identity_model(
        bundle_path,
        _issue_bundle(
            authority,
            sequence=1,
            bundle_id="m4i-runtime-bundle-0001",
            issued_at=NOW - timedelta(minutes=5),
            expires_at=NOW + timedelta(hours=1),
        ),
    )
    _write_identity_model(gateway_path, gateway_credential)
    _write_identity_model(local_path, local_credential)
    verifier = WorkloadIdentityVerifier(
        trust_root_public_key=authority.public_key(),
        trust_root_key_id=workload_key_id(authority.public_key()),
        trust_domain=TRUST_DOMAIN,
        trust_bundle_path=bundle_path,
    )
    gateway_binding = WorkloadCredentialBinding(
        verifier=verifier,
        credential_path=gateway_path,
        expected_role=WorkloadRole.GATEWAY,
        expected_audience=OT_CAPABILITY_AUDIENCE,
        expected_subject=GATEWAY_SUBJECT,
    )
    local_binding = WorkloadCredentialBinding(
        verifier=verifier,
        credential_path=local_path,
        expected_role=WorkloadRole.OT_ADAPTER,
        expected_audience=GATEWAY_CAPABILITY_AUDIENCE,
        expected_subject=OT_SUBJECT,
    )
    local_signer = WorkloadSigner(local_credential, local_private)
    return CoordinationIdentities(
        authority=authority,
        bundle_path=bundle_path,
        gateway_path=gateway_path,
        local_path=local_path,
        gateway_signer=WorkloadSigner(gateway_credential, gateway_private),
        local_signer=local_signer,
        gateway_binding=gateway_binding,
        local_identity=LocalWorkloadIdentity(
            binding=local_binding,
            signer=local_signer,
        ),
    )


def _rotate_leaf_credentials(
    identities: CoordinationIdentities,
) -> CoordinationIdentities:
    gateway_private = Ed25519PrivateKey.generate()
    local_private = Ed25519PrivateKey.generate()
    gateway_credential = _issue_credential(
        identities.authority,
        gateway_private,
        credential_id="credential-m4i-gateway-rotated-0002",
        subject=GATEWAY_SUBJECT,
        role=WorkloadRole.GATEWAY,
        audiences=(OT_CAPABILITY_AUDIENCE, EFFECT_COORDINATOR_AUDIENCE),
        issued_at=NOW + timedelta(seconds=2),
        not_before=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(hours=1),
    )
    local_credential = _issue_credential(
        identities.authority,
        local_private,
        credential_id="credential-m4i-ot-rotated-0002",
        subject=OT_SUBJECT,
        role=WorkloadRole.OT_ADAPTER,
        audiences=(GATEWAY_CAPABILITY_AUDIENCE, GATEWAY_COORDINATION_AUDIENCE),
        issued_at=NOW + timedelta(seconds=2),
        not_before=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(hours=1),
    )
    _write_identity_model(
        identities.bundle_path,
        _issue_bundle(
            identities.authority,
            sequence=2,
            bundle_id="m4i-runtime-bundle-rotated-0002",
            issued_at=NOW + timedelta(seconds=2),
            expires_at=NOW + timedelta(hours=1),
        ),
    )
    _write_identity_model(identities.gateway_path, gateway_credential)
    _write_identity_model(identities.local_path, local_credential)
    local_signer = WorkloadSigner(local_credential, local_private)
    return CoordinationIdentities(
        authority=identities.authority,
        bundle_path=identities.bundle_path,
        gateway_path=identities.gateway_path,
        local_path=identities.local_path,
        gateway_signer=WorkloadSigner(gateway_credential, gateway_private),
        local_signer=local_signer,
        gateway_binding=identities.gateway_binding,
        local_identity=LocalWorkloadIdentity(
            binding=identities.local_identity.binding,
            signer=local_signer,
        ),
    )


def _dispatch(
    artifacts: RuntimeArtifacts,
    identities: CoordinationIdentities,
) -> SegmentedCapabilityDispatch:
    permit = artifacts.permit.model_copy(
        update={
            "target_plc_key_id": identities.local_signer.credential.credential.key_id,
            "signature": "",
        }
    ).signed(artifacts.permit_private)
    return SegmentedCapabilityDispatch(
        request=artifacts.request,
        pre_observation=artifacts.pre_observation,
        decision=artifacts.decision,
        assessment=artifacts.assessment,
        permit=permit,
    )


def _open_journal(path: Path, *, initialize: bool) -> DurableEffectCoordinationJournal:
    if initialize:
        path.parent.mkdir(mode=0o700)
        path.parent.chmod(0o700)
    return DurableEffectCoordinationJournal(
        path,
        owner_subject=OT_SUBJECT,
        initialize=initialize,
    )


def _runtime(
    artifacts: RuntimeArtifacts,
    identities: CoordinationIdentities,
    dispatch: SegmentedCapabilityDispatch,
    journal: DurableEffectCoordinationJournal,
    clock: MutableClock,
    *,
    boot_epoch: str = OT_BOOT,
    observer_boot_epoch: str = OBSERVER_BOOT,
    plant_at_post: bool = False,
    hook: Any = None,
) -> tuple[CapabilityOtRuntime, CoordinatedDevice, CountingReplay]:
    device = CoordinatedDevice(
        artifacts=artifacts,
        dispatch=dispatch,
        acknowledgment_private_key=identities.local_signer.private_key,
        acknowledgment_key_id=identities.local_signer.credential.credential.key_id,
        boot_epoch=boot_epoch,
        clock=clock,
    )
    replay = CountingReplay()
    plant_info = _plant_health(artifacts)

    def load_current_plant_health() -> Any:
        at_post = plant_at_post or (device.calls > 0 and not device.fail_after_call)
        if not at_post:
            return plant_info
        acknowledgment = artifacts.acknowledgment
        assert acknowledgment.post_state_version is not None
        assert acknowledgment.post_state_digest is not None
        return plant_info.model_copy(
            update={
                "state_version": acknowledgment.post_state_version,
                "state_digest": acknowledgment.post_state_digest,
                "apply_requests": max(1, device.calls),
                "commit_count": 1,
            }
        )

    loader: Callable[[], Any] = load_current_plant_health
    observer = replace(
        _observer_info(artifacts),
        boot_epoch=observer_boot_epoch,
    )
    runtime = CapabilityOtRuntime(
        device=cast(Any, device),
        transport_replay=cast(Any, replay),
        gateway_public_key=identities.gateway_signer.private_key.public_key(),
        gateway_key_id=identities.gateway_signer.credential.credential.key_id,
        observer_info=observer,
        permit_public_key=artifacts.permit_private.public_key(),
        permit_key_id=artifacts.permit_key_id,
        private_key=identities.local_signer.private_key,
        key_id=identities.local_signer.credential.credential.key_id,
        plc_id=PLC_ID,
        boot_epoch=boot_epoch,
        plant_info=plant_info,
        semantic_replay=cast(Any, CountingReplay()),
        gateway_workload_identity=identities.gateway_binding,
        local_workload_identity=identities.local_identity,
        coordination_required=True,
        coordination_journal=journal,
        plant_health_loader=loader,
        after_coordination_terminal_persist=hook,
        clock=clock,
    )
    return runtime, device, replay


def _harness(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
    *,
    hook: Any = None,
) -> OtHarness:
    tmp_path.chmod(0o700)
    identities = _identities(tmp_path)
    dispatch = _dispatch(artifacts, identities)
    journal_path = tmp_path / "coordination" / "ot-coordination.json"
    journal = _open_journal(journal_path, initialize=True)
    clock = MutableClock(NOW + timedelta(milliseconds=250))
    runtime, device, replay = _runtime(
        artifacts,
        identities,
        dispatch,
        journal,
        clock,
        hook=hook,
    )
    return OtHarness(
        runtime=runtime,
        device=device,
        journal=journal,
        journal_path=journal_path,
        replay=replay,
        identities=identities,
        dispatch=dispatch,
        clock=clock,
    )


def _prepare_request(harness: OtHarness) -> SignedEffectPrepareRequest:
    return SignedEffectPrepareRequest.issue(
        dispatch=harness.dispatch,
        signer=harness.identities.gateway_signer,
        request_nonce="m4i-runtime-prepare-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=20),
    )


def _commit_request(
    harness: OtHarness,
    receipt: CoordinationReceipt,
) -> SignedEffectCommitRequest:
    return SignedEffectCommitRequest.issue(
        receipt=receipt,
        signer=harness.identities.gateway_signer,
        request_nonce="m4i-runtime-commit-nonce-00001",
        issued_at=NOW + timedelta(milliseconds=500),
        expires_at=NOW + timedelta(seconds=20),
    )


def _query_request(
    harness: OtHarness,
    *,
    sequence: int,
) -> SignedEffectQueryRequest:
    issued_at = harness.clock.value - timedelta(milliseconds=100)
    return SignedEffectQueryRequest.issue(
        effect=EffectIdentity.from_dispatch(harness.dispatch),
        signer=harness.identities.gateway_signer,
        request_nonce=f"m4i-runtime-query-nonce-{sequence:04d}",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=20),
    )


def _post_model(client: TestClient, path: str, value: Any) -> Any:
    return client.post(
        path,
        content=value.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


def test_required_mode_prepare_commit_retry_and_query_execute_once(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    client = TestClient(create_ot_app(lambda: harness.runtime))
    prepare = _prepare_request(harness)

    prepared_response = _post_model(client, "/v1/effects/prepare", prepare)
    assert prepared_response.status_code == 200, prepared_response.text
    receipt = CoordinationReceipt.model_validate_json(prepared_response.content)

    harness.clock.value = NOW + timedelta(milliseconds=750)
    commit = _commit_request(harness, receipt)
    committed_response = _post_model(client, "/v1/effects/commit", commit)
    assert committed_response.status_code == 200, committed_response.text
    committed = SignedEffectOutcome.model_validate_json(committed_response.content)
    retried_response = _post_model(client, "/v1/effects/commit", commit)
    assert retried_response.status_code == 200, retried_response.text
    assert SignedEffectOutcome.model_validate_json(retried_response.content) == committed
    assert committed.disposition is EffectDisposition.APPLIED
    assert committed.acceptance is not None
    assert harness.device.calls == 1
    assert harness.runtime.execute_requests == 1

    harness.clock.value = NOW + timedelta(milliseconds=1250)
    query = _query_request(harness, sequence=1)
    queried_response = _post_model(client, "/v1/effects/query", query)
    assert queried_response.status_code == 200, queried_response.text
    queried = SignedEffectOutcome.model_validate_json(queried_response.content)
    assert queried.request_kind == "query"
    assert queried.request_sha256 == query.digest
    assert queried.disposition is EffectDisposition.APPLIED
    assert queried.acceptance == committed.acceptance
    assert queried.acknowledgment == committed.acknowledgment
    post_query_retry = _post_model(client, "/v1/effects/commit", commit)
    assert post_query_retry.status_code == 200, post_query_retry.text
    assert SignedEffectOutcome.model_validate_json(post_query_retry.content) == committed
    assert harness.device.calls == 1
    record = harness.journal.get(prepare.effect)
    assert record is not None and record.state is CoordinationState.APPLIED


@pytest.mark.parametrize("invalid_layer", ["observer", "target"])
def test_prepare_rejects_invalid_inner_binding_before_journal(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
    invalid_layer: str,
) -> None:
    harness = _harness(tmp_path, artifacts)
    if invalid_layer == "observer":
        observation = harness.dispatch.pre_observation.model_copy(
            update={"signature": "invalid-observer-signature"}
        )
        dispatch = harness.dispatch.model_copy(update={"pre_observation": observation})
    else:
        permit = harness.dispatch.permit.model_copy(
            update={"target_plc_key_id": "untrusted-target-key", "signature": ""}
        ).signed(artifacts.permit_private)
        dispatch = harness.dispatch.model_copy(update={"permit": permit})
    prepare = SignedEffectPrepareRequest.issue(
        dispatch=dispatch,
        signer=harness.identities.gateway_signer,
        request_nonce=f"m4i-invalid-{invalid_layer}-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=20),
    )

    with pytest.raises(
        CapabilityAdmissionRejected,
        match="effect_prepare_authentication_rejected",
    ):
        harness.runtime.prepare_effect(prepare)

    assert harness.journal.records() == ()
    assert harness.device.calls == 0


def test_accepted_commit_retry_is_query_only_and_returns_unknown(
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
        lambda exact_request, *, accepted_at, transition_sequence: (
            DurableCommitAcceptance.issue(
                request=exact_request,
                signer=harness.identities.local_signer,
                accepted_at=accepted_at,
                transition_sequence=transition_sequence,
            )
        ),
        recorded_at=harness.clock.value,
    )
    assert admission.status is CommitAdmissionStatus.NEW

    with pytest.raises(
        EffectCommitIndeterminate,
        match="effect_commit_indeterminate_query_required",
    ):
        harness.runtime.commit_effect(commit)

    assert harness.device.calls == 0
    harness.clock.value = NOW + timedelta(seconds=3)
    outcome = harness.runtime.query_effect(_query_request(harness, sequence=2))
    assert outcome.disposition is EffectDisposition.UNKNOWN_EFFECT
    assert outcome.acceptance == admission.acceptance
    assert outcome.acknowledgment is None
    assert harness.device.calls == 0


def test_post_acceptance_device_failure_retains_signed_unknown_once(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    harness.device.fail_after_call = True
    prepare = _prepare_request(harness)
    receipt = harness.runtime.prepare_effect(prepare)
    harness.clock.value = NOW + timedelta(milliseconds=750)
    commit = _commit_request(harness, receipt)

    outcome = harness.runtime.commit_effect(commit)

    assert outcome.disposition is EffectDisposition.UNKNOWN_EFFECT
    assert outcome.acceptance is not None
    assert outcome.acknowledgment is None
    record = harness.journal.get(prepare.effect)
    assert record is not None and record.state is CoordinationState.UNKNOWN_EFFECT
    assert harness.device.calls == 1
    with pytest.raises(
        CapabilityAdmissionRejected,
        match="effect_reconciliation_required",
    ):
        harness.runtime.commit_effect(commit)
    assert harness.device.calls == 1


def test_finish_persistence_failure_reopens_without_reexecution(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness(tmp_path, artifacts)
    prepare = _prepare_request(harness)
    receipt = harness.runtime.prepare_effect(prepare)
    harness.clock.value = NOW + timedelta(milliseconds=750)
    commit = _commit_request(harness, receipt)
    persist = harness.journal._persist

    def fail_terminal_persist(
        records: dict[str, CoordinationJournalRecord],
    ) -> None:
        if any(record.state.terminal for record in records.values()):
            raise CoordinationJournalError("synthetic terminal persistence failure")
        persist(records)

    monkeypatch.setattr(harness.journal, "_persist", fail_terminal_persist)
    with pytest.raises(EffectCommitIndeterminate, match="query_required"):
        harness.runtime.commit_effect(commit)

    assert harness.device.calls == 1
    accepted = harness.journal.get(prepare.effect)
    assert accepted is not None and accepted.state is CoordinationState.COMMIT_ACCEPTED
    harness.journal.close()

    reopened = _open_journal(harness.journal_path, initialize=False)
    harness.clock.value = NOW + timedelta(milliseconds=900)
    restarted_runtime, restarted_device, _ = _runtime(
        artifacts,
        harness.identities,
        harness.dispatch,
        reopened,
        harness.clock,
        plant_at_post=True,
    )
    restarted_harness = replace(
        harness,
        runtime=restarted_runtime,
        device=restarted_device,
        journal=reopened,
    )
    with pytest.raises(
        CapabilityAdmissionRejected,
        match="effect_reconciliation_required",
    ):
        restarted_runtime.commit_effect(commit)
    harness.clock.value = NOW + timedelta(milliseconds=1250)
    queried = restarted_runtime.query_effect(
        _query_request(restarted_harness, sequence=5)
    )

    assert queried.disposition is EffectDisposition.UNKNOWN_EFFECT
    assert queried.acceptance == accepted.latest_acceptance
    assert restarted_device.calls == 0
    reopened.close()


def test_query_without_accepted_commit_closes_not_dispatched(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    prepare = _prepare_request(harness)
    harness.runtime.prepare_effect(prepare)
    harness.clock.value = NOW + timedelta(seconds=5)

    outcome = harness.runtime.query_effect(_query_request(harness, sequence=3))

    assert outcome.disposition is EffectDisposition.NOT_DISPATCHED
    assert outcome.acceptance is None
    assert outcome.acknowledgment is None
    record = harness.journal.get(prepare.effect)
    assert record is not None and record.state is CoordinationState.NOT_DISPATCHED
    assert harness.device.calls == 0


def test_terminal_fsync_hook_survives_restart_with_new_boots(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    retained: dict[str, DurableEffectCoordinationJournal] = {}

    class SyntheticCrash(RuntimeError):
        pass

    def crash_after_fsync() -> None:
        journal = retained["journal"]
        assert journal.records()[0].state is CoordinationState.APPLIED
        raise SyntheticCrash("synthetic crash after terminal fsync")

    harness = _harness(tmp_path, artifacts, hook=crash_after_fsync)
    retained["journal"] = harness.journal
    prepare = _prepare_request(harness)
    receipt = harness.runtime.prepare_effect(prepare)
    harness.clock.value = NOW + timedelta(milliseconds=750)
    commit = _commit_request(harness, receipt)

    with pytest.raises(SyntheticCrash, match="after terminal fsync"):
        harness.runtime.commit_effect(commit)

    assert harness.device.calls == 1
    terminal = harness.journal.get(prepare.effect)
    assert terminal is not None and terminal.state is CoordinationState.APPLIED
    acceptance = terminal.latest_acceptance
    acknowledgment = terminal.terminal_outcome
    harness.journal.close()

    reopened = _open_journal(harness.journal_path, initialize=False)
    harness.clock.value = NOW + timedelta(seconds=5)
    restarted_runtime, restarted_device, _ = _runtime(
        artifacts,
        harness.identities,
        harness.dispatch,
        reopened,
        harness.clock,
        boot_epoch=RESTARTED_OT_BOOT,
        observer_boot_epoch=RESTARTED_OBSERVER_BOOT,
        plant_at_post=True,
    )
    restarted_harness = replace(
        harness,
        runtime=restarted_runtime,
        device=restarted_device,
        journal=reopened,
    )
    outcome = restarted_runtime.query_effect(
        _query_request(restarted_harness, sequence=4)
    )

    assert outcome.disposition is EffectDisposition.APPLIED
    assert outcome.acceptance == acceptance
    assert acknowledgment is not None
    assert outcome.acknowledgment == acknowledgment.acknowledgment
    assert restarted_device.calls == 0
    reopened.close()


def test_restart_query_accepts_historical_effect_after_leaf_rotation(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    prepare = _prepare_request(harness)
    receipt = harness.runtime.prepare_effect(prepare)
    harness.clock.value = NOW + timedelta(milliseconds=750)
    commit = _commit_request(harness, receipt)
    committed = harness.runtime.commit_effect(commit)
    assert committed.acceptance is not None
    old_acceptance = committed.acceptance
    old_acknowledgment = committed.acknowledgment
    harness.journal.close()

    rotated = _rotate_leaf_credentials(harness.identities)
    reopened = _open_journal(harness.journal_path, initialize=False)
    harness.clock.value = NOW + timedelta(seconds=5)
    restarted_runtime, restarted_device, _ = _runtime(
        artifacts,
        rotated,
        harness.dispatch,
        reopened,
        harness.clock,
        boot_epoch=RESTARTED_OT_BOOT,
        observer_boot_epoch=RESTARTED_OBSERVER_BOOT,
        plant_at_post=True,
    )
    restarted_harness = replace(
        harness,
        runtime=restarted_runtime,
        device=restarted_device,
        journal=reopened,
        identities=rotated,
    )
    query = _query_request(restarted_harness, sequence=6)
    outcome = restarted_runtime.query_effect(query)

    assert outcome.disposition is EffectDisposition.APPLIED
    assert outcome.request_sha256 == query.digest
    assert outcome.coordinator_credential == rotated.local_signer.credential
    assert outcome.acceptance == old_acceptance
    assert outcome.acknowledgment == old_acknowledgment
    assert restarted_device.calls == 0
    reopened.close()


def test_required_mode_blocks_legacy_execute_before_replay_or_device(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    harness = _harness(tmp_path, artifacts)
    request = WorkloadSignedCapabilityDispatch.issue(
        dispatch=harness.dispatch,
        signer=harness.identities.gateway_signer,
        transport_nonce="m4i-legacy-transport-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=1),
    )
    client = TestClient(create_ot_app(lambda: harness.runtime))

    response = _post_model(client, "/v1/capability/execute", request)

    assert response.status_code == 403
    assert response.json()["reason"] == "effect_coordination_required"
    assert harness.replay.reservation_count == 0
    assert harness.device.calls == 0


def test_coordination_mode_is_explicit_and_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_EFFECT_COORDINATION_MODE", "required")
    assert effect_coordination_enabled()
    monkeypatch.setenv("AEGIS_EFFECT_COORDINATION_MODE", "disabled")
    assert not effect_coordination_enabled()
    monkeypatch.delenv("AEGIS_EFFECT_COORDINATION_MODE")
    with pytest.raises(CapabilityRuntimeUnavailable, match="configure it explicitly"):
        effect_coordination_enabled()
    monkeypatch.setenv("AEGIS_EFFECT_COORDINATION_MODE", "true")
    with pytest.raises(CapabilityRuntimeUnavailable, match="configure it explicitly"):
        effect_coordination_enabled()
