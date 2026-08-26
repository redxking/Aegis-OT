from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_m4i_models import (
    COORDINATOR_SUBJECT,
    GATEWAY_SUBJECT,
    NOW,
    M4iArtifacts,
    _issue_credential,
    _rejected_acknowledgment,
)
from test_m4i_models import (
    artifacts as m4i_artifacts_fixture,
)

from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityExecutionPermit,
    PlcCommandAcknowledgment,
)
from aegis_ot.coordination_journal import (
    CoordinationAttemptStatus,
    CoordinationJournalError,
    DurableGatewayCoordinationJournal,
    EffectCommitAttempt,
)
from aegis_ot.coordination_models import (
    EFFECT_COORDINATOR_AUDIENCE,
    GATEWAY_COORDINATION_AUDIENCE,
    CapabilityOutcomePending,
    CapabilityOutcomeResolution,
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
from aegis_ot.segmented_capability_transport import (
    CapabilityPreDispatchUnavailable,
    CapabilityTransportRejected,
    ConsequentialTransportOutcomeUnknown,
    CoordinatedWorkloadRemoteVirtualPlcPort,
    HttpExchangeResponse,
    ObserverHealthMetadata,
    OtHealthMetadata,
)
from aegis_ot.workload_identity import (
    SignedWorkloadCredential,
    WorkloadCredentialBinding,
    WorkloadRevocation,
    WorkloadRole,
    WorkloadSigner,
    WorkloadTrustBundle,
    canonical_json_file_bytes,
    public_key_base64,
    workload_key_id,
)
from aegis_ot.workload_runtime import LocalWorkloadIdentity

_ARTIFACT_FACTORY = cast(
    Callable[[Path], M4iArtifacts],
    cast(Any, m4i_artifacts_fixture).__wrapped__,
)


@pytest.fixture
def artifacts(tmp_path: Path) -> M4iArtifacts:
    return _ARTIFACT_FACTORY(tmp_path)


@dataclass
class MutableClock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> datetime:
        self.value += timedelta(seconds=seconds)
        return self.value


def _json_response(value: Any, *, status_code: int = 200) -> HttpExchangeResponse:
    return HttpExchangeResponse(
        status_code=status_code,
        content_type="application/json",
        body=value.model_dump_json().encode("utf-8"),
    )


class ScriptedCoordinationExchange:
    def __init__(
        self,
        artifacts: M4iArtifacts,
        clock: MutableClock,
        *,
        commit_disposition: EffectDisposition = EffectDisposition.APPLIED,
        lose_prepare: bool = False,
        lose_commit_response: bool = False,
        malformed_commit_response: bool = False,
        commit_response_attack: Literal["forged", "misbound"] | None = None,
    ) -> None:
        self.artifacts = artifacts
        self.clock = clock
        self.coordinator_signer = artifacts.coordinator_signer
        self.commit_disposition = commit_disposition
        self.lose_prepare = lose_prepare
        self.lose_commit_response = lose_commit_response
        self.malformed_commit_response = malformed_commit_response
        self.commit_response_attack = commit_response_attack
        self.paths: list[str] = []
        self.commit: SignedEffectCommitRequest | None = None
        self.acceptance: DurableCommitAcceptance | None = None
        self.acknowledgment: PlcCommandAcknowledgment | None = None

    def _outcome_evidence(
        self,
        disposition: EffectDisposition,
    ) -> tuple[DurableCommitAcceptance | None, PlcCommandAcknowledgment | None]:
        if disposition is EffectDisposition.NOT_DISPATCHED:
            return None, None
        acceptance = self.acceptance
        if acceptance is None:
            commit = self.commit
            assert commit is not None
            acceptance = DurableCommitAcceptance.issue(
                request=commit,
                signer=self.artifacts.coordinator_signer,
                accepted_at=self.clock.advance(0.25),
            )
            self.acceptance = acceptance
        if disposition is EffectDisposition.APPLIED:
            acknowledgment = self.artifacts.acknowledgment
        elif disposition is EffectDisposition.REJECTED:
            acknowledgment = _rejected_acknowledgment(
                self.artifacts,
                replay=False,
            )
        else:
            acknowledgment = None
        self.acknowledgment = acknowledgment
        return acceptance, acknowledgment

    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: Any,
        timeout_seconds: float,
    ) -> HttpExchangeResponse:
        del method, headers, timeout_seconds
        assert body is not None
        path = "/" + url.split("/", maxsplit=3)[-1]
        self.paths.append(path)
        if path == "/v1/effects/prepare":
            prepare_request = SignedEffectPrepareRequest.model_validate_json(body)
            if self.lose_prepare:
                raise TimeoutError("lost prepare response")
            receipt = CoordinationReceipt.issue(
                request=prepare_request,
                signer=self.coordinator_signer,
                prepared_at=self.clock.advance(0.25),
            )
            return _json_response(receipt)
        if path == "/v1/effects/commit":
            commit_request = SignedEffectCommitRequest.model_validate_json(body)
            self.commit = commit_request
            if (
                self.commit_disposition is EffectDisposition.NOT_DISPATCHED
                and self.lose_commit_response
            ):
                self.clock.advance(0.25)
                raise TimeoutError("lost commit before durable acceptance")
            acceptance, acknowledgment = self._outcome_evidence(self.commit_disposition)
            signed_at = max(
                self.clock.advance(0.25),
                acknowledgment.acknowledged_at if acknowledgment is not None else self.clock.value,
            )
            self.clock.value = signed_at
            outcome = SignedEffectOutcome.issue(
                request=commit_request,
                disposition=self.commit_disposition,
                reason=f"signed_{self.commit_disposition.value}",
                signer=self.coordinator_signer,
                signed_at=signed_at,
                acceptance=acceptance,
                acknowledgment=acknowledgment,
            )
            if self.lose_commit_response:
                raise TimeoutError("lost commit response")
            if self.malformed_commit_response:
                return HttpExchangeResponse(200, "application/json", b"{}")
            if self.commit_response_attack == "forged":
                outcome = outcome.model_copy(update={"signature": "forged"})
            elif self.commit_response_attack == "misbound":
                outcome = outcome.model_copy(update={"request_sha256": "0" * 64})
            return _json_response(outcome)
        if path == "/v1/effects/query":
            query_request = SignedEffectQueryRequest.model_validate_json(body)
            acceptance, acknowledgment = self._outcome_evidence(self.commit_disposition)
            signed_at = max(
                self.clock.advance(0.25),
                acknowledgment.acknowledged_at if acknowledgment is not None else self.clock.value,
            )
            self.clock.value = signed_at
            outcome = SignedEffectOutcome.issue(
                request=query_request,
                disposition=self.commit_disposition,
                reason=f"signed_{self.commit_disposition.value}",
                signer=self.coordinator_signer,
                signed_at=signed_at,
                acceptance=acceptance,
                acknowledgment=acknowledgment,
            )
            return _json_response(outcome)
        raise AssertionError(f"unexpected path {path}")


@dataclass(frozen=True)
class PortHarness:
    port: CoordinatedWorkloadRemoteVirtualPlcPort
    journal: DurableGatewayCoordinationJournal
    exchange: ScriptedCoordinationExchange
    gateway_credential_path: Path
    ot_credential_path: Path


def _port_harness(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    *,
    commit_disposition: EffectDisposition = EffectDisposition.APPLIED,
    lose_prepare: bool = False,
    lose_commit_response: bool = False,
    malformed_commit_response: bool = False,
    commit_response_attack: Literal["forged", "misbound"] | None = None,
    journal: DurableGatewayCoordinationJournal | None = None,
) -> PortHarness:
    clock = MutableClock()
    gateway_path = tmp_path / "gateway-credential.json"
    ot_path = tmp_path / "ot-credential.json"
    gateway_path.write_bytes(canonical_json_file_bytes(artifacts.gateway_signer.credential))
    ot_path.write_bytes(canonical_json_file_bytes(artifacts.coordinator_signer.credential))
    gateway_binding = WorkloadCredentialBinding(
        verifier=artifacts.verifier,
        credential_path=gateway_path,
        expected_role=WorkloadRole.GATEWAY,
        expected_audience=EFFECT_COORDINATOR_AUDIENCE,
        expected_subject=GATEWAY_SUBJECT,
    )
    ot_binding = WorkloadCredentialBinding(
        verifier=artifacts.verifier,
        credential_path=ot_path,
        expected_role=WorkloadRole.OT_ADAPTER,
        expected_audience=GATEWAY_COORDINATION_AUDIENCE,
        expected_subject=COORDINATOR_SUBJECT,
    )
    local = LocalWorkloadIdentity(
        binding=gateway_binding,
        signer=artifacts.gateway_signer,
    )
    dispatch = artifacts.dispatch
    plant_boot_epoch = "m4i-plant-boot-epoch-0001"
    observer = ObserverHealthMetadata(
        status="ready",
        role="observer",
        pid=101,
        observer_id=dispatch.pre_observation.observer_id,
        boot_epoch=dispatch.pre_observation.observer_boot_epoch,
        key_id=dispatch.pre_observation.observer_key_id,
        public_key_b64=public_key_base64(artifacts.observer_public_key),
        plant_boot_epoch=plant_boot_epoch,
        plant_model_digest=dispatch.pre_observation.snapshot.model_digest,
        capture_count=0,
        resolve_count=0,
        cached_observations=0,
    )
    ot = OtHealthMetadata(
        status="ready",
        role="ot-adapter",
        pid=102,
        plc_id=dispatch.permit.target_plc_id,
        boot_epoch=dispatch.permit.target_plc_boot_epoch,
        key_id=artifacts.coordinator_signer.credential.credential.key_id,
        public_key_b64=public_key_base64(artifacts.coordinator_signer.private_key.public_key()),
        gateway_key_id=artifacts.gateway_signer.credential.credential.key_id,
        gateway_public_key_b64=public_key_base64(artifacts.gateway_signer.private_key.public_key()),
        permit_key_id=dispatch.permit.signing_key_id,
        permit_public_key_b64=public_key_base64(artifacts.permit_public_key),
        plant_boot_epoch=plant_boot_epoch,
        plant_model_digest=dispatch.pre_observation.snapshot.model_digest,
        observer_boot_epoch=dispatch.pre_observation.observer_boot_epoch,
        transport_replay_reservations=0,
        semantic_replay_reservations=0,
        execute_requests=0,
        scan_counter=0,
    )
    if journal is None:
        directory = tmp_path / "journal"
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        journal = DurableGatewayCoordinationJournal(
            directory / "gateway.json",
            owner_subject=GATEWAY_SUBJECT,
            initialize=True,
        )
    exchange = ScriptedCoordinationExchange(
        artifacts,
        clock,
        commit_disposition=commit_disposition,
        lose_prepare=lose_prepare,
        lose_commit_response=lose_commit_response,
        malformed_commit_response=malformed_commit_response,
        commit_response_attack=commit_response_attack,
    )
    port = CoordinatedWorkloadRemoteVirtualPlcPort(
        "https://ot.test",
        ot=ot,
        observer=observer,
        gateway_identity=local,
        ot_identity=ot_binding,
        coordination_journal=journal,
        exchange=exchange,
        clock=clock,
        nonce_factory=lambda: "coordination-transport-nonce-0001",
    )
    return PortHarness(port, journal, exchange, gateway_path, ot_path)


def _execute(
    harness: PortHarness,
    artifacts: M4iArtifacts,
) -> PlcCommandAcknowledgment:
    dispatch = artifacts.dispatch
    return harness.port.execute(
        request=dispatch.request,
        permit=dispatch.permit,
        pre_observation=dispatch.pre_observation,
        decision=dispatch.decision,
        assessment=dispatch.assessment,
    )


def _regenerated_permit(
    artifacts: M4iArtifacts,
    *,
    request: CapabilityActionRequest,
    target_plc_id: str,
) -> CapabilityExecutionPermit:
    private_key = Ed25519PrivateKey.generate()
    signing_key_id = workload_key_id(private_key.public_key())
    base_permit = artifacts.dispatch.permit.base_permit.model_copy(
        update={
            "audience": target_plc_id,
            "signing_key_id": signing_key_id,
            "signature": "",
        }
    ).signed(private_key)
    return artifacts.dispatch.permit.model_copy(
        update={
            "base_permit": base_permit,
            "request_digest": request.digest,
            "target_plc_id": target_plc_id,
            "target_plc_key_id": "m4i-regenerated-plc-key-0002",
            "target_plc_boot_epoch": "m4i-regenerated-plc-boot-epoch-0002",
            "signing_key_id": signing_key_id,
            "signature": "",
        }
    ).signed(private_key)


def _restart_with_rotated_ot(
    harness: PortHarness,
    *,
    credential: SignedWorkloadCredential,
    private_key: Ed25519PrivateKey,
    suffix: str,
) -> tuple[
    CoordinatedWorkloadRemoteVirtualPlcPort,
    ObserverHealthMetadata,
    OtHealthMetadata,
]:
    harness.ot_credential_path.write_bytes(canonical_json_file_bytes(credential))
    harness.exchange.coordinator_signer = WorkloadSigner(credential, private_key)
    current_observer = harness.port.observer.model_copy(
        update={"boot_epoch": f"m4i-observer-boot-epoch-{suffix}"}
    )
    current_ot = harness.port.ot.model_copy(
        update={
            "boot_epoch": f"m4i-plc-boot-epoch-{suffix}",
            "key_id": credential.credential.key_id,
            "public_key_b64": public_key_base64(private_key.public_key()),
            "observer_boot_epoch": current_observer.boot_epoch,
        }
    )
    recovered_port = CoordinatedWorkloadRemoteVirtualPlcPort(
        "https://ot.test",
        ot=current_ot,
        observer=current_observer,
        gateway_identity=harness.port.gateway_identity,
        ot_identity=harness.port.ot_identity,
        coordination_journal=harness.journal,
        exchange=harness.exchange,
        clock=harness.exchange.clock,
        nonce_factory=lambda: f"rotated-recovery-query-nonce-{suffix}",
    )
    return recovered_port, current_observer, current_ot


def _write_bundle(
    artifacts: M4iArtifacts,
    *,
    sequence: int,
    revocations: tuple[WorkloadRevocation, ...],
) -> None:
    authority_public = artifacts.authority.public_key()
    credential = artifacts.gateway_signer.credential.credential
    bundle = WorkloadTrustBundle(
        bundle_id=f"m4i-transport-trust-bundle-{sequence:04d}",
        sequence=sequence,
        trust_domain=credential.trust_domain,
        authority_key_id=workload_key_id(authority_public),
        authority_public_key_b64=public_key_base64(authority_public),
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
        revocations=revocations,
    ).signed(artifacts.authority)
    artifacts.trust_bundle_path.write_bytes(canonical_json_file_bytes(bundle))


def test_prepare_commit_applied_response_is_durable_before_return(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts)

    acknowledgment = _execute(harness, artifacts)

    assert acknowledgment == artifacts.acknowledgment
    assert harness.exchange.paths == ["/v1/effects/prepare", "/v1/effects/commit"]
    record = harness.journal.records()[0]
    assert record.state is CoordinationState.APPLIED
    assert record.latest_acceptance is not None
    assert record.terminal_outcome is not None
    harness.journal.close()


def test_exact_retained_dispatch_resumes_without_effect_lookup_or_http(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _port_harness(tmp_path, artifacts)
    assert _execute(harness, artifacts) == artifacts.acknowledgment
    calls_before_duplicate = tuple(harness.exchange.paths)

    def reject_effect_lookup(*_: Any, **__: Any) -> Any:
        raise AssertionError("exact action replay must resume from the action index")

    monkeypatch.setattr(harness.journal, "get", reject_effect_lookup)
    acknowledgment = _execute(harness, artifacts)

    assert acknowledgment == artifacts.acknowledgment
    assert tuple(harness.exchange.paths) == calls_before_duplicate
    harness.journal.close()


def test_regenerated_permit_for_retained_action_does_not_expose_old_ack_or_send_http(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts, lose_commit_response=True)
    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)
    calls_before_replay = tuple(harness.exchange.paths)
    original = artifacts.dispatch
    regenerated_permit = _regenerated_permit(
        artifacts,
        request=original.request,
        target_plc_id="plc:m4i-regenerated-target-0002",
    )
    replay_effect = EffectIdentity.from_dispatch(
        original.model_copy(update={"permit": regenerated_permit})
    )
    assert replay_effect != harness.journal.records()[0].effect

    with pytest.raises(
        ConsequentialTransportOutcomeUnknown,
        match="differs from its retained full dispatch",
    ) as caught:
        harness.port.execute(
            request=original.request,
            permit=regenerated_permit,
            pre_observation=original.pre_observation,
            decision=original.decision,
            assessment=original.assessment,
        )

    assert getattr(caught.value, "known_no_effect", False) is False
    assert tuple(harness.exchange.paths) == calls_before_replay
    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    assert harness.exchange.paths.count("/v1/effects/query") == 0
    assert len(harness.journal.records()) == 1
    assert harness.journal.records()[0].latest_acceptance is None
    harness.journal.close()


def test_reused_actor_nonce_with_different_request_is_unknown_and_sends_zero_http(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts, lose_commit_response=True)
    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)
    calls_before_replay = tuple(harness.exchange.paths)
    original = artifacts.dispatch
    replay_request = original.request.model_copy(
        update={"request_id": "m4i-request-replayed-action-0002"}
    )
    assert replay_request.digest != original.request.digest
    assert replay_request.proposal.actor_id == original.request.proposal.actor_id
    assert replay_request.proposal.nonce == original.request.proposal.nonce
    regenerated_permit = _regenerated_permit(
        artifacts,
        request=replay_request,
        target_plc_id=original.permit.target_plc_id,
    )

    with pytest.raises(
        ConsequentialTransportOutcomeUnknown,
        match="conflicts with a retained coordination effect",
    ) as caught:
        harness.port.execute(
            request=replay_request,
            permit=regenerated_permit,
            pre_observation=original.pre_observation,
            decision=original.decision,
            assessment=original.assessment,
        )

    assert getattr(caught.value, "known_no_effect", False) is False
    assert tuple(harness.exchange.paths) == calls_before_replay
    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    assert harness.exchange.paths.count("/v1/effects/query") == 0
    assert len(harness.journal.records()) == 1
    assert harness.journal.records()[0].latest_acceptance is None
    harness.journal.close()


def test_retained_terminal_outcome_survives_original_request_ttl(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts)
    assert _execute(harness, artifacts) == artifacts.acknowledgment
    calls_before_duplicate = tuple(harness.exchange.paths)
    record = harness.journal.records()[0]
    outcome = record.terminal_outcome
    assert outcome is not None
    retained_request = next(
        item.request
        for item in record.attempts
        if isinstance(item, EffectCommitAttempt) and item.outcome == outcome
    )
    harness.exchange.clock.value = retained_request.expires_at + timedelta(seconds=1)
    evaluated_at = harness.exchange.clock.value
    _, current_target = harness.port._current_identities(
        evaluated_at=evaluated_at,
        require_pinned_target=False,
    )
    assert not harness.port._verify_outcome(
        outcome,
        request=retained_request,
        current_target=current_target,
        evaluated_at=evaluated_at,
    )

    acknowledgment = _execute(harness, artifacts)

    assert acknowledgment == artifacts.acknowledgment
    assert tuple(harness.exchange.paths) == calls_before_duplicate
    harness.journal.close()


def test_lost_prepare_closes_known_no_effect_and_never_commits(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts, lose_prepare=True)

    with pytest.raises(CapabilityPreDispatchUnavailable):
        _execute(harness, artifacts)

    assert harness.exchange.paths == ["/v1/effects/prepare"]
    assert harness.journal.records()[0].state is CoordinationState.NOT_DISPATCHED
    harness.journal.close()


def test_lost_commit_response_duplicate_execute_uses_one_query_and_no_retry(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts, lose_commit_response=True)

    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)
    harness.exchange.lose_commit_response = False
    acknowledgment = _execute(harness, artifacts)

    assert acknowledgment == artifacts.acknowledgment
    assert harness.exchange.paths == [
        "/v1/effects/prepare",
        "/v1/effects/commit",
        "/v1/effects/query",
    ]
    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    assert harness.journal.records()[0].state is CoordinationState.APPLIED
    harness.journal.close()


def test_reconciliation_evidence_queries_once_and_replays_byte_equivalently(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts, lose_commit_response=True)
    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)
    effect = harness.journal.records()[0].effect
    harness.exchange.lose_commit_response = False

    resolution = harness.port.reconcile_effect_evidence(effect)

    assert isinstance(resolution, CapabilityOutcomeResolution)
    assert resolution.prior_state is CoordinationState.DISPATCH_ARMED
    assert resolution.disposition is EffectDisposition.APPLIED
    assert resolution.outcome.acknowledgment == artifacts.acknowledgment
    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    assert harness.exchange.paths.count("/v1/effects/query") == 1
    calls_after_resolution = tuple(harness.exchange.paths)
    journal_path = harness.journal.path
    replay_time = harness.exchange.clock.advance(20)
    harness.journal.close()
    reopened = DurableGatewayCoordinationJournal(
        journal_path,
        owner_subject=GATEWAY_SUBJECT,
        initialize=False,
    )
    restarted = _port_harness(
        tmp_path,
        artifacts,
        journal=reopened,
    )
    restarted.exchange.clock.value = replay_time

    replay = restarted.port.reconcile_effect_evidence(effect)

    assert replay == resolution
    assert replay.model_dump_json() == resolution.model_dump_json()
    assert tuple(harness.exchange.paths) == calls_after_resolution
    assert restarted.exchange.paths == []
    restarted.journal.close()


def test_reconciliation_evidence_returns_exact_signed_pending_outcome(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(
        tmp_path,
        artifacts,
        commit_disposition=EffectDisposition.UNKNOWN_EFFECT,
        lose_commit_response=True,
    )
    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)
    effect = harness.journal.records()[0].effect
    harness.exchange.lose_commit_response = False

    pending = harness.port.reconcile_effect_evidence(effect)

    assert isinstance(pending, CapabilityOutcomePending)
    assert pending.prior_state is CoordinationState.DISPATCH_ARMED
    assert pending.disposition is EffectDisposition.UNKNOWN_EFFECT
    assert pending.outcome.request_kind == "query"
    assert pending.outcome.acceptance == pending.acceptance
    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    assert harness.exchange.paths.count("/v1/effects/query") == 1
    harness.journal.close()


def test_reconciliation_evidence_never_commits_prepared_effect(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts)
    receipt = harness.port._prepare(artifacts.dispatch)

    with pytest.raises(
        CapabilityTransportRejected,
        match="effect_was_not_committed",
    ) as caught:
        harness.port.reconcile_effect_evidence(receipt.effect)

    assert caught.value.known_no_effect
    assert harness.exchange.paths == ["/v1/effects/prepare"]
    assert harness.journal.records()[0].state is CoordinationState.NOT_DISPATCHED
    harness.journal.close()


def test_reconciliation_evidence_rejects_commit_bound_terminal_without_query(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts)
    assert _execute(harness, artifacts) == artifacts.acknowledgment
    effect = harness.journal.records()[0].effect
    calls_before_reconciliation = tuple(harness.exchange.paths)

    with pytest.raises(
        CapabilityTransportRejected,
        match="effect_not_query_resolved",
    ) as caught:
        harness.port.reconcile_effect_evidence(effect)

    assert not caught.value.known_no_effect
    assert tuple(harness.exchange.paths) == calls_before_reconciliation
    harness.journal.close()


@pytest.mark.parametrize(
    ("disposition", "expected"),
    [
        (EffectDisposition.REJECTED, "rejected"),
        (EffectDisposition.NOT_DISPATCHED, "not-dispatched"),
        (EffectDisposition.UNKNOWN_EFFECT, "unknown"),
    ],
)
def test_lost_commit_response_reconciles_without_commit_retry(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    disposition: EffectDisposition,
    expected: Literal["rejected", "not-dispatched", "unknown"],
) -> None:
    harness = _port_harness(
        tmp_path,
        artifacts,
        commit_disposition=disposition,
        lose_commit_response=True,
    )
    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)
    harness.exchange.lose_commit_response = False

    if expected == "rejected":
        acknowledgment = _execute(harness, artifacts)
        assert acknowledgment.status.value == "rejected"
    elif expected == "not-dispatched":
        with pytest.raises(CapabilityTransportRejected) as caught:
            _execute(harness, artifacts)
        assert caught.value.known_no_effect
    else:
        with pytest.raises(ConsequentialTransportOutcomeUnknown):
            _execute(harness, artifacts)

    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    assert harness.exchange.paths.count("/v1/effects/query") == 1
    harness.journal.close()


def test_malformed_commit_response_is_ambiguous_and_never_retried(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts, malformed_commit_response=True)

    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)

    record = harness.journal.records()[0]
    commit_attempt = next(item for item in record.attempts if isinstance(item, EffectCommitAttempt))
    assert commit_attempt.status is CoordinationAttemptStatus.OUTCOME_UNKNOWN
    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    harness.journal.close()


@pytest.mark.parametrize("attack", ["forged", "misbound"])
def test_forged_or_misbound_commit_response_never_resolves_effect(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    attack: Literal["forged", "misbound"],
) -> None:
    harness = _port_harness(tmp_path, artifacts, commit_response_attack=attack)

    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)

    record = harness.journal.records()[0]
    commit_attempt = next(item for item in record.attempts if isinstance(item, EffectCommitAttempt))
    assert commit_attempt.status is CoordinationAttemptStatus.OUTCOME_UNKNOWN
    assert record.latest_acceptance is None
    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    harness.journal.close()


def test_journal_failure_before_commit_sends_zero_consequential_posts(
    tmp_path: Path,
    artifacts: M4iArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _port_harness(tmp_path, artifacts)

    def fail_before_commit(*_: Any, **__: Any) -> Any:
        raise CoordinationJournalError("simulated fsync failure")

    monkeypatch.setattr(harness.journal, "begin_commit", fail_before_commit)
    with pytest.raises(CapabilityPreDispatchUnavailable):
        _execute(harness, artifacts)

    assert harness.exchange.paths == ["/v1/effects/prepare"]
    harness.journal.close()


def test_startup_recovery_after_durable_prepare_never_initiates_commit(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts)
    receipt = harness.port._prepare(artifacts.dispatch)
    assert receipt == harness.journal.records()[0].latest_receipt

    with pytest.raises(CapabilityTransportRejected) as caught:
        harness.port.reconcile_pending_once()

    assert caught.value.known_no_effect
    assert harness.exchange.paths == ["/v1/effects/prepare"]
    assert harness.journal.records()[0].state is CoordinationState.NOT_DISPATCHED
    harness.journal.close()


def test_recovery_query_accepts_current_rotated_ot_identity_with_old_acceptance(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts, lose_commit_response=True)
    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)

    rotated_private = Ed25519PrivateKey.generate()
    rotated_credential = _issue_credential(
        artifacts.authority,
        rotated_private,
        credential_id="credential-ot-coordinator-rotated-0002",
        subject=COORDINATOR_SUBJECT,
        role=WorkloadRole.OT_ADAPTER,
        actor_id=None,
        audience=GATEWAY_COORDINATION_AUDIENCE,
    )
    acceptance = harness.exchange.acceptance
    assert acceptance is not None
    _write_bundle(
        artifacts,
        sequence=2,
        revocations=(
            WorkloadRevocation(
                credential_id=acceptance.coordinator_credential.credential.credential_id,
                revoked_at=acceptance.accepted_at + timedelta(milliseconds=1),
                reason="old OT identity rotated after commit acceptance",
            ),
        ),
    )
    harness.exchange.lose_commit_response = False
    recovered_port, current_observer, current_ot = _restart_with_rotated_ot(
        harness,
        credential=rotated_credential,
        private_key=rotated_private,
        suffix="rotated-0002",
    )
    accepted_dispatch = acceptance.commit_request.receipt.prepare_request.dispatch
    assert current_ot.key_id != accepted_dispatch.permit.target_plc_key_id
    assert current_ot.boot_epoch != accepted_dispatch.permit.target_plc_boot_epoch
    assert current_observer.boot_epoch != accepted_dispatch.pre_observation.observer_boot_epoch

    acknowledgment = recovered_port.reconcile_pending_once()

    assert acknowledgment == artifacts.acknowledgment
    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    assert harness.exchange.paths[-1] == "/v1/effects/query"
    harness.journal.close()


def test_current_ot_revocation_blocks_query_without_repeating_commit(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts, lose_commit_response=True)
    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)
    _write_bundle(
        artifacts,
        sequence=2,
        revocations=(
            WorkloadRevocation(
                credential_id=(artifacts.coordinator_signer.credential.credential.credential_id),
                revoked_at=NOW,
                reason="current OT identity revoked before reconciliation",
            ),
        ),
    )

    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(harness, artifacts)

    assert harness.exchange.paths.count("/v1/effects/commit") == 1
    assert harness.exchange.paths.count("/v1/effects/query") == 0
    harness.journal.close()


def test_terminal_restart_reverifies_old_outcome_across_current_ot_rotation(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> None:
    harness = _port_harness(tmp_path, artifacts)
    assert _execute(harness, artifacts) == artifacts.acknowledgment
    calls_before_duplicate = tuple(harness.exchange.paths)
    record = harness.journal.records()[0]
    outcome = record.terminal_outcome
    assert outcome is not None
    old_credential_id = outcome.coordinator_credential.credential.credential_id
    rotated_private = Ed25519PrivateKey.generate()
    rotated_credential = _issue_credential(
        artifacts.authority,
        rotated_private,
        credential_id="credential-ot-terminal-restart-rotated-0003",
        subject=COORDINATOR_SUBJECT,
        role=WorkloadRole.OT_ADAPTER,
        actor_id=None,
        audience=GATEWAY_COORDINATION_AUDIENCE,
    )
    _write_bundle(
        artifacts,
        sequence=2,
        revocations=(
            WorkloadRevocation(
                credential_id=old_credential_id,
                revoked_at=outcome.signed_at + timedelta(milliseconds=1),
                reason="old OT identity rotated after terminal signing",
            ),
        ),
    )
    recovered_port, _, current_ot = _restart_with_rotated_ot(
        harness,
        credential=rotated_credential,
        private_key=rotated_private,
        suffix="terminal-rotated-0003",
    )
    assert current_ot.key_id != outcome.coordinator_credential.credential.key_id

    assert recovered_port.reconcile_effect(record.effect) == artifacts.acknowledgment
    assert tuple(harness.exchange.paths) == calls_before_duplicate

    _write_bundle(
        artifacts,
        sequence=3,
        revocations=(
            WorkloadRevocation(
                credential_id=old_credential_id,
                revoked_at=outcome.signed_at,
                reason="old OT identity compromised at terminal signing",
            ),
        ),
    )
    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        recovered_port.reconcile_effect(record.effect)
    assert tuple(harness.exchange.paths) == calls_before_duplicate
    harness.journal.close()
