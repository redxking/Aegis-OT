from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityExecutionPermit,
    DispatchPhase,
    ObservationPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from aegis_ot.coordination_models import (
    EFFECT_COORDINATOR_AUDIENCE,
    GATEWAY_COORDINATION_AUDIENCE,
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
from aegis_ot.crypto import generate_keypair, sign_bytes
from aegis_ot.models import ActionProposal, Operation
from aegis_ot.physical_control import (
    TrustedCommandTranslator,
    physical_state_to_gateway_state,
)
from aegis_ot.physical_factory import build_physical_local_lab
from aegis_ot.physical_models import CommandStatus, canonical_digest
from aegis_ot.segmented_capability_models import SegmentedCapabilityDispatch
from aegis_ot.workload_identity import (
    SignedWorkloadCredential,
    WorkloadCredential,
    WorkloadIdentityVerifier,
    WorkloadRevocation,
    WorkloadRole,
    WorkloadSigner,
    WorkloadTrustBundle,
    canonical_json_file_bytes,
    public_key_base64,
    workload_key_id,
)

NOW = datetime(2026, 8, 25, 15, 0, tzinfo=UTC)
GATEWAY_SUBJECT = "spiffe://aegis-ot.test/workload/gateway"
COORDINATOR_SUBJECT = "spiffe://aegis-ot.test/workload/ot-adapter"
TRUST_DOMAIN = "aegis-ot.test"
PLC_BOOT_EPOCH = "m4i-plc-boot-epoch-0001"


def _issue_credential(
    authority: Ed25519PrivateKey,
    leaf: Ed25519PrivateKey,
    *,
    credential_id: str,
    subject: str,
    role: WorkloadRole,
    audience: str,
    issued_at: datetime = NOW - timedelta(minutes=5),
    not_before: datetime = NOW - timedelta(minutes=4),
    expires_at: datetime = NOW + timedelta(minutes=5),
) -> SignedWorkloadCredential:
    authority_key_id = workload_key_id(authority.public_key())
    public_key = leaf.public_key()
    credential = WorkloadCredential(
        credential_id=credential_id,
        trust_domain=TRUST_DOMAIN,
        subject=subject,
        role=role,
        key_id=workload_key_id(public_key),
        public_key_b64=public_key_base64(public_key),
        authority_key_id=authority_key_id,
        audiences=(audience,),
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
    )
    return SignedWorkloadCredential.issue(credential, authority)


@dataclass(frozen=True)
class M4iArtifacts:
    authority: Ed25519PrivateKey
    dispatch: SegmentedCapabilityDispatch
    acknowledgment: PlcCommandAcknowledgment
    gateway_signer: WorkloadSigner
    coordinator_signer: WorkloadSigner
    verifier: WorkloadIdentityVerifier
    trust_bundle_path: Path
    observer_public_key: Ed25519PublicKey
    permit_public_key: Ed25519PublicKey


@pytest.fixture
def artifacts(tmp_path: Path) -> M4iArtifacts:
    authority = Ed25519PrivateKey.generate()
    gateway_private = Ed25519PrivateKey.generate()
    coordinator_private = Ed25519PrivateKey.generate()
    gateway_credential = _issue_credential(
        authority,
        gateway_private,
        credential_id="credential-gateway-m4i-0001",
        subject=GATEWAY_SUBJECT,
        role=WorkloadRole.GATEWAY,
        audience=EFFECT_COORDINATOR_AUDIENCE,
    )
    coordinator_credential = _issue_credential(
        authority,
        coordinator_private,
        credential_id="credential-ot-coordinator-0001",
        subject=COORDINATOR_SUBJECT,
        role=WorkloadRole.OT_ADAPTER,
        audience=GATEWAY_COORDINATION_AUDIENCE,
    )
    authority_key_id = workload_key_id(authority.public_key())
    bundle = WorkloadTrustBundle(
        bundle_id="trust-bundle-m4i-0001",
        sequence=1,
        trust_domain=TRUST_DOMAIN,
        authority_key_id=authority_key_id,
        authority_public_key_b64=public_key_base64(authority.public_key()),
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
    ).signed(authority)
    bundle_path = tmp_path / "trust-bundle.json"
    bundle_path.write_bytes(canonical_json_file_bytes(bundle))
    verifier = WorkloadIdentityVerifier(
        trust_root_public_key=authority.public_key(),
        trust_root_key_id=authority_key_id,
        trust_domain=TRUST_DOMAIN,
        trust_bundle_path=bundle_path,
    )

    lab = build_physical_local_lab(NOW)
    pre_state = lab.plant.read_state()
    proposal = ActionProposal(
        proposal_id="m4i-proposal-1",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=pre_state.state_version,
        observed_at=pre_state.observed_at,
        submitted_at=pre_state.observed_at,
        nonce="m4i-proposal-nonce-0001",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )
    decision = lab.authorization.gateway.decide(
        proposal,
        physical_state_to_gateway_state(pre_state),
        NOW,
    )
    command = TrustedCommandTranslator().translate(proposal)
    assessment = lab.plant.simulate_candidate(command)
    base_permit = lab.controller.permit_issuer.issue(
        proposal=proposal,
        decision=decision,
        command=command,
        assessment=assessment,
    )
    observer_private, _ = generate_keypair()
    pre_observation = SignedObservationEnvelope.issue(
        snapshot=pre_state,
        correlation_id="m4i-correlation-1",
        phase=ObservationPhase.PRE_AUTHORIZATION,
        challenge_nonce="m4i-observation-challenge-0001",
        observer_id="observer:m4i",
        observer_key_id="m4i-observer-key-1",
        observer_boot_epoch="m4i-observer-boot-epoch-0001",
        observer_sequence=1,
        previous_envelope_digest=None,
        private_key=observer_private,
    )
    request = CapabilityActionRequest(
        request_id="m4i-request-1",
        correlation_id=pre_observation.correlation_id,
        proposal=proposal,
        observation_id=pre_observation.observation_id,
        observation_envelope_digest=pre_observation.envelope_digest,
        observation_challenge_nonce=pre_observation.challenge_nonce,
    )
    permit = CapabilityExecutionPermit(
        base_permit=base_permit,
        request_digest=request.digest,
        observation_id=pre_observation.observation_id,
        observation_envelope_digest=pre_observation.envelope_digest,
        observer_id=pre_observation.observer_id,
        observer_key_id=pre_observation.observer_key_id,
        observer_boot_epoch=pre_observation.observer_boot_epoch,
        target_plc_id=base_permit.audience,
        target_plc_key_id=coordinator_credential.credential.key_id,
        target_plc_boot_epoch=PLC_BOOT_EPOCH,
        signing_key_id=base_permit.signing_key_id,
    ).signed(lab.controller.permit_issuer.private_key)
    dispatch = SegmentedCapabilityDispatch(
        request=request,
        pre_observation=pre_observation,
        decision=decision,
        assessment=assessment,
        permit=permit,
    )
    post_state = assessment.post_state
    acknowledgment = PlcCommandAcknowledgment(
        request_digest=request.digest,
        permit_digest=permit.digest,
        observation_envelope_digest=pre_observation.envelope_digest,
        permit_id=base_permit.permit_id,
        permit_nonce=base_permit.permit_nonce,
        command_id=command.command_id,
        command_digest=command.digest,
        assessment_digest=assessment.digest,
        proposal_id=proposal.proposal_id,
        decision_id=decision.decision_id,
        plc_id=permit.target_plc_id,
        plc_key_id=permit.target_plc_key_id,
        plc_boot_epoch=permit.target_plc_boot_epoch,
        plc_scan=1,
        status=CommandStatus.APPLIED,
        dispatch_phase=DispatchPhase.COMMITTED,
        reason="command_applied_and_plc_read_back",
        acknowledged_at=NOW + timedelta(milliseconds=1500),
        pre_state=pre_state,
        pre_state_digest=pre_state.state_digest,
        pre_state_version=pre_state.state_version,
        post_state_digest=post_state.state_digest,
        post_state_version=post_state.state_version,
        post_topology_digest=post_state.topology_digest,
        pre_actuator_setpoint=1.0,
        post_actuator_setpoint=command.setpoint,
        simulation_time_s=post_state.simulation_time_s,
    ).signed(coordinator_private)
    return M4iArtifacts(
        authority=authority,
        dispatch=dispatch,
        acknowledgment=acknowledgment,
        gateway_signer=WorkloadSigner(gateway_credential, gateway_private),
        coordinator_signer=WorkloadSigner(
            coordinator_credential,
            coordinator_private,
        ),
        verifier=verifier,
        trust_bundle_path=bundle_path,
        observer_public_key=observer_private.public_key(),
        permit_public_key=lab.controller.permit_issuer.private_key.public_key(),
    )


def _prepare(artifacts: M4iArtifacts) -> SignedEffectPrepareRequest:
    return SignedEffectPrepareRequest.issue(
        dispatch=artifacts.dispatch,
        signer=artifacts.gateway_signer,
        request_nonce="prepare-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )


def _receipt(
    artifacts: M4iArtifacts,
    prepare: SignedEffectPrepareRequest,
) -> CoordinationReceipt:
    return CoordinationReceipt.issue(
        request=prepare,
        signer=artifacts.coordinator_signer,
        prepared_at=NOW + timedelta(milliseconds=500),
    )


def _commit(
    artifacts: M4iArtifacts,
    receipt: CoordinationReceipt,
) -> SignedEffectCommitRequest:
    return SignedEffectCommitRequest.issue(
        receipt=receipt,
        signer=artifacts.gateway_signer,
        request_nonce="commit-nonce-00001",
        issued_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=31),
    )


def _acceptance(
    artifacts: M4iArtifacts,
    commit: SignedEffectCommitRequest,
) -> DurableCommitAcceptance:
    return DurableCommitAcceptance.issue(
        request=commit,
        signer=artifacts.coordinator_signer,
        accepted_at=NOW + timedelta(milliseconds=1250),
    )


def _prepare_verifies(
    artifacts: M4iArtifacts,
    request: SignedEffectPrepareRequest,
    *,
    evaluated_at: datetime,
) -> bool:
    dispatch = artifacts.dispatch
    return request.verify_complete_for_admission(
        artifacts.verifier,
        expected_gateway_subject=GATEWAY_SUBJECT,
        observer_public_key=artifacts.observer_public_key,
        expected_observer_id=dispatch.pre_observation.observer_id,
        expected_observer_key_id=dispatch.pre_observation.observer_key_id,
        expected_observer_boot_epoch=dispatch.pre_observation.observer_boot_epoch,
        permit_public_key=artifacts.permit_public_key,
        expected_permit_key_id=dispatch.permit.signing_key_id,
        expected_plc_id=dispatch.permit.target_plc_id,
        expected_plc_key_id=dispatch.permit.target_plc_key_id,
        expected_plc_boot_epoch=dispatch.permit.target_plc_boot_epoch,
        evaluated_at=evaluated_at,
    )


def _commit_verifies(
    artifacts: M4iArtifacts,
    request: SignedEffectCommitRequest,
    *,
    evaluated_at: datetime,
) -> bool:
    dispatch = artifacts.dispatch
    return request.verify_complete_for_admission(
        artifacts.verifier,
        expected_gateway_subject=GATEWAY_SUBJECT,
        expected_coordinator_subject=COORDINATOR_SUBJECT,
        observer_public_key=artifacts.observer_public_key,
        expected_observer_id=dispatch.pre_observation.observer_id,
        expected_observer_key_id=dispatch.pre_observation.observer_key_id,
        expected_observer_boot_epoch=dispatch.pre_observation.observer_boot_epoch,
        permit_public_key=artifacts.permit_public_key,
        expected_permit_key_id=dispatch.permit.signing_key_id,
        expected_plc_id=dispatch.permit.target_plc_id,
        expected_plc_key_id=dispatch.permit.target_plc_key_id,
        expected_plc_boot_epoch=dispatch.permit.target_plc_boot_epoch,
        evaluated_at=evaluated_at,
    )


def _outcome_verifies(
    artifacts: M4iArtifacts,
    outcome: SignedEffectOutcome,
    request: SignedEffectCommitRequest | SignedEffectQueryRequest,
    *,
    evaluated_at: datetime,
) -> bool:
    dispatch = artifacts.dispatch
    return outcome.verify_for_request(
        artifacts.verifier,
        request=request,
        expected_gateway_subject=GATEWAY_SUBJECT,
        expected_coordinator_subject=COORDINATOR_SUBJECT,
        observer_public_key=artifacts.observer_public_key,
        expected_observer_id=dispatch.pre_observation.observer_id,
        expected_observer_key_id=dispatch.pre_observation.observer_key_id,
        expected_observer_boot_epoch=dispatch.pre_observation.observer_boot_epoch,
        permit_public_key=artifacts.permit_public_key,
        expected_permit_key_id=dispatch.permit.signing_key_id,
        expected_plc_id=dispatch.permit.target_plc_id,
        expected_plc_key_id=dispatch.permit.target_plc_key_id,
        expected_plc_boot_epoch=dispatch.permit.target_plc_boot_epoch,
        evaluated_at=evaluated_at,
    )


def _acceptance_verifies(
    artifacts: M4iArtifacts,
    acceptance: DurableCommitAcceptance,
    *,
    evaluated_at: datetime,
) -> bool:
    dispatch = artifacts.dispatch
    return acceptance.verify_for_commit(
        artifacts.verifier,
        request=acceptance.commit_request,
        expected_gateway_subject=GATEWAY_SUBJECT,
        expected_coordinator_subject=COORDINATOR_SUBJECT,
        observer_public_key=artifacts.observer_public_key,
        expected_observer_id=dispatch.pre_observation.observer_id,
        expected_observer_key_id=dispatch.pre_observation.observer_key_id,
        expected_observer_boot_epoch=dispatch.pre_observation.observer_boot_epoch,
        permit_public_key=artifacts.permit_public_key,
        expected_permit_key_id=dispatch.permit.signing_key_id,
        expected_plc_id=dispatch.permit.target_plc_id,
        expected_plc_key_id=dispatch.permit.target_plc_key_id,
        expected_plc_boot_epoch=dispatch.permit.target_plc_boot_epoch,
        evaluated_at=evaluated_at,
    )


def _rejected_acknowledgment(
    artifacts: M4iArtifacts,
    *,
    replay: bool,
) -> PlcCommandAcknowledgment:
    original = artifacts.acknowledgment
    if replay:
        pre_state = original.pre_state
        reason = "transaction_replayed"
        pre_setpoint = original.pre_actuator_setpoint
        dispatch_phase = DispatchPhase.PRE_DISPATCH
    else:
        pre_state = artifacts.dispatch.assessment.post_state
        reason = "topology_digest_changed"
        pre_setpoint = 0.0
        dispatch_phase = DispatchPhase.KNOWN_NO_EFFECT
    unsigned = PlcCommandAcknowledgment.model_validate(
        {
            **original.model_dump(mode="python", exclude={"signature"}),
            "status": CommandStatus.REJECTED,
            "dispatch_phase": dispatch_phase,
            "reason": reason,
            "pre_state": pre_state,
            "pre_state_digest": pre_state.state_digest,
            "pre_state_version": pre_state.state_version,
            "post_state_digest": None,
            "post_state_version": None,
            "post_topology_digest": None,
            "pre_actuator_setpoint": pre_setpoint,
            "post_actuator_setpoint": pre_setpoint,
            "simulation_time_s": pre_state.simulation_time_s,
        }
    )
    return unsigned.signed(artifacts.coordinator_signer.private_key)


def test_effect_identity_is_deterministic_semantic_material(
    artifacts: M4iArtifacts,
) -> None:
    effect = EffectIdentity.from_dispatch(artifacts.dispatch)

    assert effect.effect_id == effect.derived_effect_id()
    assert effect.effect_id.startswith("sha256:")
    assert effect.request_sha256 == artifacts.dispatch.request.digest
    assert effect.command_semantics_sha256 == canonical_digest(
        artifacts.dispatch.permit.base_permit.command.model_dump(
            mode="json",
            exclude={"command_id", "proposal_id"},
        )
    )
    assert {
        "transport_nonce",
        "request_nonce",
        "issued_at",
        "expires_at",
        "credential_id",
        "sender_key_id",
        "target_plc_key_id",
        "target_plc_boot_epoch",
    }.isdisjoint(effect.stable_material())

    assert set(EffectIdentity.model_fields) == {"effect_id", *effect.stable_material()}
    with pytest.raises(ValidationError, match="Extra inputs"):
        EffectIdentity.model_validate(
            {**effect.model_dump(mode="python"), "command_id": "trace-alias"}
        )

    with pytest.raises(ValidationError, match="not derived"):
        EffectIdentity.model_validate(
            {**effect.model_dump(mode="python"), "target_id": "different-target"}
        )


def test_prepare_embeds_exact_dispatch_and_authority_credential(
    artifacts: M4iArtifacts,
) -> None:
    prepare = _prepare(artifacts)
    retried = SignedEffectPrepareRequest.issue(
        dispatch=artifacts.dispatch,
        signer=artifacts.gateway_signer,
        request_nonce="prepare-nonce-0002",
        issued_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=31),
    )

    assert prepare.dispatch == artifacts.dispatch
    assert prepare.dispatch_sha256 == artifacts.dispatch.digest
    assert prepare.effect == retried.effect
    assert prepare.digest != retried.digest
    assert prepare.verify_workload_envelope_for_admission(
        artifacts.verifier,
        expected_audience=EFFECT_COORDINATOR_AUDIENCE,
        expected_sender_subject=GATEWAY_SUBJECT,
        evaluated_at=NOW + timedelta(seconds=1),
    )
    assert _prepare_verifies(
        artifacts,
        prepare,
        evaluated_at=NOW + timedelta(seconds=1),
    )

    with pytest.raises(ValidationError, match="dispatch hash"):
        SignedEffectPrepareRequest.model_validate(
            {**prepare.model_dump(mode="python"), "dispatch_sha256": "b" * 64}
        )
    with pytest.raises(ValidationError, match="gateway workload credential"):
        SignedEffectPrepareRequest.issue(
            dispatch=artifacts.dispatch,
            signer=artifacts.coordinator_signer,
            request_nonce="wrong-role-nonce-0001",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
        )


def test_commit_acceptance_precedes_every_dispatched_outcome() -> None:
    assert CoordinationState.DISPATCH_ARMED.can_transition_to(CoordinationState.COMMIT_ACCEPTED)
    assert CoordinationState.DISPATCH_ARMED.can_transition_to(CoordinationState.NOT_DISPATCHED)
    assert not CoordinationState.DISPATCH_ARMED.can_transition_to(CoordinationState.UNKNOWN_EFFECT)
    assert not CoordinationState.DISPATCH_ARMED.can_transition_to(CoordinationState.APPLIED)
    assert not CoordinationState.DISPATCH_ARMED.can_transition_to(CoordinationState.REJECTED)
    assert CoordinationState.COMMIT_ACCEPTED.can_transition_to(CoordinationState.UNKNOWN_EFFECT)
    assert CoordinationState.COMMIT_ACCEPTED.can_transition_to(CoordinationState.APPLIED)
    assert CoordinationState.COMMIT_ACCEPTED.can_transition_to(CoordinationState.REJECTED)


def test_receipt_and_commit_verify_complete_workload_chain(
    artifacts: M4iArtifacts,
) -> None:
    prepare = _prepare(artifacts)
    receipt = _receipt(artifacts, prepare)
    commit = _commit(artifacts, receipt)

    assert receipt.prepare_request == prepare
    assert receipt.verify_for_request(
        artifacts.verifier,
        request=prepare,
        expected_gateway_subject=GATEWAY_SUBJECT,
        expected_coordinator_subject=COORDINATOR_SUBJECT,
        evaluated_at=NOW + timedelta(seconds=2),
    )
    assert _commit_verifies(
        artifacts,
        commit,
        evaluated_at=NOW + timedelta(milliseconds=1250),
    )

    forged_receipt = receipt.model_copy(update={"signature": "A" * 88})
    forged_commit = _commit(artifacts, forged_receipt)
    assert not _commit_verifies(
        artifacts,
        forged_commit,
        evaluated_at=NOW + timedelta(milliseconds=1250),
    )

    acceptance = _acceptance(artifacts, commit)
    assert acceptance.commit_request == commit
    assert acceptance.state is CoordinationState.COMMIT_ACCEPTED
    assert acceptance.transition_sequence == 3
    assert _acceptance_verifies(
        artifacts,
        acceptance,
        evaluated_at=NOW + timedelta(seconds=2),
    )
    assert not _acceptance_verifies(
        artifacts,
        acceptance.model_copy(update={"signature": "A" * 88}),
        evaluated_at=NOW + timedelta(seconds=2),
    )


def test_applied_outcome_embeds_and_verifies_exact_plc_acknowledgment(
    artifacts: M4iArtifacts,
) -> None:
    receipt = _receipt(artifacts, _prepare(artifacts))
    commit = _commit(artifacts, receipt)
    acceptance = _acceptance(artifacts, commit)
    outcome = SignedEffectOutcome.issue(
        request=commit,
        disposition=EffectDisposition.APPLIED,
        reason="effect_applied",
        signer=artifacts.coordinator_signer,
        signed_at=NOW + timedelta(seconds=4),
        acceptance=acceptance,
        acknowledgment=artifacts.acknowledgment,
    )

    assert outcome.receipt == receipt
    assert outcome.acknowledgment == artifacts.acknowledgment
    assert outcome.execution_evidence_sha256 == artifacts.acknowledgment.digest
    assert outcome.acceptance == acceptance
    assert _outcome_verifies(
        artifacts,
        outcome,
        commit,
        evaluated_at=NOW + timedelta(seconds=4),
    )

    with pytest.raises(ValidationError, match="matching PLC acknowledgment"):
        SignedEffectOutcome.issue(
            request=commit,
            disposition=EffectDisposition.APPLIED,
            reason="unsupported_applied_claim",
            signer=artifacts.coordinator_signer,
            signed_at=NOW + timedelta(seconds=4),
            acceptance=acceptance,
        )
    with pytest.raises(ValueError, match="outside the request window"):
        SignedEffectOutcome.issue(
            request=commit,
            disposition=EffectDisposition.APPLIED,
            reason="late_outcome",
            signer=artifacts.coordinator_signer,
            signed_at=commit.expires_at,
            acceptance=acceptance,
            acknowledgment=artifacts.acknowledgment,
        )
    late_acceptance = DurableCommitAcceptance.issue(
        request=commit,
        signer=artifacts.coordinator_signer,
        accepted_at=NOW + timedelta(milliseconds=1750),
    )
    with pytest.raises(ValidationError, match="chronology"):
        SignedEffectOutcome.issue(
            request=commit,
            disposition=EffectDisposition.APPLIED,
            reason="acceptance_after_ack",
            signer=artifacts.coordinator_signer,
            signed_at=NOW + timedelta(seconds=4),
            acceptance=late_acceptance,
            acknowledgment=artifacts.acknowledgment,
        )


def test_outcome_future_bound_and_exact_query_resolution(
    artifacts: M4iArtifacts,
) -> None:
    receipt = _receipt(artifacts, _prepare(artifacts))
    effect = receipt.effect
    commit = _commit(artifacts, receipt)
    acceptance = _acceptance(artifacts, commit)
    query = SignedEffectQueryRequest.issue(
        effect=effect,
        signer=artifacts.gateway_signer,
        request_nonce="query-nonce-000001",
        issued_at=NOW + timedelta(seconds=10),
        expires_at=NOW + timedelta(seconds=40),
    )
    outcome = SignedEffectOutcome.issue(
        request=query,
        disposition=EffectDisposition.APPLIED,
        reason="durable_terminal_record",
        signer=artifacts.coordinator_signer,
        signed_at=NOW + timedelta(seconds=11),
        acceptance=acceptance,
        acknowledgment=artifacts.acknowledgment,
    )
    resolution = CapabilityOutcomeResolution(
        effect=effect,
        disposition=EffectDisposition.APPLIED,
        query=query,
        acceptance=acceptance,
        outcome=outcome,
        resolved_at=NOW + timedelta(seconds=12),
    )

    assert resolution.query_request_sha256 == query.digest
    assert resolution.verify_complete(
        artifacts.verifier,
        expected_gateway_subject=GATEWAY_SUBJECT,
        expected_coordinator_subject=COORDINATOR_SUBJECT,
        observer_public_key=artifacts.observer_public_key,
        expected_observer_id=artifacts.dispatch.pre_observation.observer_id,
        expected_observer_key_id=artifacts.dispatch.pre_observation.observer_key_id,
        expected_observer_boot_epoch=artifacts.dispatch.pre_observation.observer_boot_epoch,
        permit_public_key=artifacts.permit_public_key,
        expected_permit_key_id=artifacts.dispatch.permit.signing_key_id,
        expected_plc_id=artifacts.dispatch.permit.target_plc_id,
        expected_plc_key_id=artifacts.dispatch.permit.target_plc_key_id,
        expected_plc_boot_epoch=artifacts.dispatch.permit.target_plc_boot_epoch,
        evaluated_at=NOW + timedelta(seconds=12),
    )
    assert not _outcome_verifies(
        artifacts,
        outcome,
        query,
        evaluated_at=NOW + timedelta(seconds=9),
    )

    different_query = SignedEffectQueryRequest.issue(
        effect=effect,
        signer=artifacts.gateway_signer,
        request_nonce="query-nonce-000002",
        issued_at=NOW + timedelta(seconds=10),
        expires_at=NOW + timedelta(seconds=40),
    )
    with pytest.raises(ValidationError, match="bindings"):
        CapabilityOutcomeResolution.model_validate(
            {**resolution.model_dump(mode="python"), "query": different_query}
        )


def test_reconciliation_uses_temporal_revocation_for_historical_chain(
    artifacts: M4iArtifacts,
) -> None:
    prepare = _prepare(artifacts)
    receipt = _receipt(artifacts, prepare)
    commit = _commit(artifacts, receipt)
    acceptance = _acceptance(artifacts, commit)
    rotated_gateway_private = Ed25519PrivateKey.generate()
    rotated_coordinator_private = Ed25519PrivateKey.generate()
    rotated_gateway = WorkloadSigner(
        _issue_credential(
            artifacts.authority,
            rotated_gateway_private,
            credential_id="credential-gateway-m4i-0002",
            subject=GATEWAY_SUBJECT,
            role=WorkloadRole.GATEWAY,
            audience=EFFECT_COORDINATOR_AUDIENCE,
            issued_at=NOW + timedelta(minutes=8),
            not_before=NOW + timedelta(minutes=9),
            expires_at=NOW + timedelta(minutes=30),
        ),
        rotated_gateway_private,
    )
    rotated_coordinator = WorkloadSigner(
        _issue_credential(
            artifacts.authority,
            rotated_coordinator_private,
            credential_id="credential-ot-coordinator-0002",
            subject=COORDINATOR_SUBJECT,
            role=WorkloadRole.OT_ADAPTER,
            audience=GATEWAY_COORDINATION_AUDIENCE,
            issued_at=NOW + timedelta(minutes=8),
            not_before=NOW + timedelta(minutes=9),
            expires_at=NOW + timedelta(minutes=30),
        ),
        rotated_coordinator_private,
    )
    query_time = NOW + timedelta(minutes=10)
    query = SignedEffectQueryRequest.issue(
        effect=receipt.effect,
        signer=rotated_gateway,
        request_nonce="rotated-query-nonce-0001",
        issued_at=query_time,
        expires_at=query_time + timedelta(seconds=30),
    )
    outcome = SignedEffectOutcome.issue(
        request=query,
        disposition=EffectDisposition.APPLIED,
        reason="durable_terminal_record",
        signer=rotated_coordinator,
        signed_at=query_time + timedelta(seconds=1),
        acceptance=acceptance,
        acknowledgment=artifacts.acknowledgment,
    )

    authority_key_id = workload_key_id(artifacts.authority.public_key())
    old_ids = (
        artifacts.gateway_signer.credential.credential.credential_id,
        artifacts.coordinator_signer.credential.credential.credential_id,
    )

    def install_bundle(sequence: int, revoked_at: datetime) -> None:
        revocations = tuple(
            sorted(
                (
                    WorkloadRevocation(
                        credential_id=credential_id,
                        revoked_at=revoked_at,
                        reason="m4i_test_rotation",
                    )
                    for credential_id in old_ids
                ),
                key=lambda item: item.credential_id,
            )
        )
        bundle = WorkloadTrustBundle(
            bundle_id=f"trust-bundle-m4i-{sequence:04d}",
            sequence=sequence,
            trust_domain=TRUST_DOMAIN,
            authority_key_id=authority_key_id,
            authority_public_key_b64=public_key_base64(artifacts.authority.public_key()),
            issued_at=query_time - timedelta(minutes=1),
            expires_at=query_time + timedelta(minutes=30),
            revocations=revocations,
        ).signed(artifacts.authority)
        artifacts.trust_bundle_path.write_bytes(canonical_json_file_bytes(bundle))

    install_bundle(2, NOW + timedelta(seconds=2))

    assert receipt.verify_for_request(
        artifacts.verifier,
        request=prepare,
        expected_gateway_subject=GATEWAY_SUBJECT,
        expected_coordinator_subject=COORDINATOR_SUBJECT,
        evaluated_at=query_time,
    )
    assert _outcome_verifies(
        artifacts,
        outcome,
        query,
        evaluated_at=query_time + timedelta(seconds=1),
    )
    install_bundle(3, NOW)
    assert not _outcome_verifies(
        artifacts,
        outcome,
        query,
        evaluated_at=query_time + timedelta(seconds=1),
    )


def test_dispatched_outcome_requires_exact_durable_commit_acceptance(
    artifacts: M4iArtifacts,
) -> None:
    receipt = _receipt(artifacts, _prepare(artifacts))
    commit = _commit(artifacts, receipt)
    with pytest.raises(ValueError, match="durable acceptance"):
        SignedEffectOutcome.issue(
            request=commit,
            disposition=EffectDisposition.APPLIED,
            reason="unsupported_applied_claim",
            signer=artifacts.coordinator_signer,
            signed_at=NOW + timedelta(seconds=4),
            acknowledgment=artifacts.acknowledgment,
        )

    acceptance = _acceptance(artifacts, commit)
    with pytest.raises(ValueError, match="acceptance signature is invalid"):
        SignedEffectOutcome.issue(
            request=commit,
            disposition=EffectDisposition.APPLIED,
            reason="forged_acceptance",
            signer=artifacts.coordinator_signer,
            signed_at=NOW + timedelta(seconds=4),
            acceptance=acceptance.model_copy(update={"signature": "A" * 88}),
            acknowledgment=artifacts.acknowledgment,
        )
    different_material = receipt.effect.stable_material()
    different_material["target_id"] = "different-target"
    different_effect = EffectIdentity.model_validate(
        {
            **receipt.effect.model_dump(mode="python"),
            "effect_id": f"sha256:{canonical_digest(different_material)}",
            "target_id": "different-target",
        }
    )
    query = SignedEffectQueryRequest.issue(
        effect=different_effect,
        signer=artifacts.gateway_signer,
        request_nonce="different-effect-query-0001",
        issued_at=NOW + timedelta(seconds=10),
        expires_at=NOW + timedelta(seconds=40),
    )
    with pytest.raises(ValueError, match="durable commit acceptance"):
        SignedEffectOutcome.issue(
            request=query,
            disposition=EffectDisposition.APPLIED,
            reason="unrelated_query_effect",
            signer=artifacts.coordinator_signer,
            signed_at=NOW + timedelta(seconds=11),
            acceptance=acceptance,
            acknowledgment=artifacts.acknowledgment,
        )


def test_complete_admission_rejects_forged_or_misbound_inner_dispatch(
    artifacts: M4iArtifacts,
) -> None:
    forged_permit = artifacts.dispatch.permit.model_copy(update={"signature": "A" * 88})
    forged_dispatch = artifacts.dispatch.model_copy(update={"permit": forged_permit})
    forged_prepare = SignedEffectPrepareRequest.issue(
        dispatch=forged_dispatch,
        signer=artifacts.gateway_signer,
        request_nonce="forged-inner-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    assert forged_prepare.verify_workload_envelope_for_admission(
        artifacts.verifier,
        expected_audience=EFFECT_COORDINATOR_AUDIENCE,
        expected_sender_subject=GATEWAY_SUBJECT,
        evaluated_at=NOW + timedelta(seconds=1),
    )
    assert not _prepare_verifies(
        artifacts,
        forged_prepare,
        evaluated_at=NOW + timedelta(seconds=1),
    )

    misbound_dispatch = artifacts.dispatch.model_copy(
        update={
            "decision": artifacts.dispatch.decision.model_copy(
                update={"proposal_id": "different-proposal"}
            )
        }
    )
    effect = EffectIdentity.from_dispatch(misbound_dispatch)
    misbound_prepare = _prepare(artifacts).model_copy(
        update={
            "effect": effect,
            "effect_sha256": effect.digest,
            "dispatch": misbound_dispatch,
            "dispatch_sha256": misbound_dispatch.digest,
        }
    )
    misbound_prepare = misbound_prepare.model_copy(
        update={
            "signature": sign_bytes(
                artifacts.gateway_signer.private_key,
                misbound_prepare.signing_payload(),
            )
        }
    )
    assert misbound_prepare.verify_workload_envelope_for_admission(
        artifacts.verifier,
        expected_audience=EFFECT_COORDINATOR_AUDIENCE,
        expected_sender_subject=GATEWAY_SUBJECT,
        evaluated_at=NOW + timedelta(seconds=1),
    )
    assert not _prepare_verifies(
        artifacts,
        misbound_prepare,
        evaluated_at=NOW + timedelta(seconds=1),
    )


@pytest.mark.parametrize("replay", [False, True])
def test_rejected_outcome_accepts_exact_cas_and_replay_evidence(
    artifacts: M4iArtifacts,
    replay: bool,
) -> None:
    receipt = _receipt(artifacts, _prepare(artifacts))
    commit = _commit(artifacts, receipt)
    acceptance = _acceptance(artifacts, commit)
    acknowledgment = _rejected_acknowledgment(artifacts, replay=replay)
    outcome = SignedEffectOutcome.issue(
        request=commit,
        disposition=EffectDisposition.REJECTED,
        reason=acknowledgment.reason,
        signer=artifacts.coordinator_signer,
        signed_at=NOW + timedelta(seconds=4),
        acceptance=acceptance,
        acknowledgment=acknowledgment,
    )
    assert _outcome_verifies(
        artifacts,
        outcome,
        commit,
        evaluated_at=NOW + timedelta(seconds=4),
    )


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "message"),
    [
        (NOW.replace(tzinfo=None), NOW + timedelta(seconds=1), "timezone-aware"),
        (NOW, NOW, "expiry must follow"),
        (NOW, NOW + timedelta(seconds=61), "lifetime"),
    ],
)
def test_signed_requests_reject_unsafe_lifetimes(
    artifacts: M4iArtifacts,
    issued_at: datetime,
    expires_at: datetime,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        SignedEffectPrepareRequest.issue(
            dispatch=artifacts.dispatch,
            signer=artifacts.gateway_signer,
            request_nonce="prepare-nonce-0001",
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_signed_request_rejects_credential_not_valid_at_asserted_issuance(
    artifacts: M4iArtifacts,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    future_credential = _issue_credential(
        artifacts.authority,
        private_key,
        credential_id="credential-gateway-future-0001",
        subject=GATEWAY_SUBJECT,
        role=WorkloadRole.GATEWAY,
        audience=EFFECT_COORDINATOR_AUDIENCE,
        issued_at=NOW,
        not_before=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=5),
    )
    with pytest.raises(ValidationError, match="credential is not valid at issuance"):
        SignedEffectPrepareRequest.issue(
            dispatch=artifacts.dispatch,
            signer=WorkloadSigner(future_credential, private_key),
            request_nonce="future-credential-nonce-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
        )
