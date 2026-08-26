from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from aegis_ot.m5_compromise import (
    AssuranceService,
    CompromiseSnapshot,
    MissionAdmissionRequest,
    MissionGateOutcome,
    MissionGateResult,
    RecoveryAuthorization,
    RecoveryAuthorizationVerifier,
    RecoveryOperation,
    RecoveryRequest,
    ServiceCondition,
    TelemetryCondition,
    evaluate_mission_admission,
)

NOW = datetime(2026, 8, 25, 20, 0, tzinfo=UTC)
AUTHORITY_ID = "recovery-authority"
SUBJECT_ID = "recovery-controller"
LEAF_ID = "agent-leaf"


def _healthy_services() -> dict[AssuranceService, ServiceCondition]:
    return {service: ServiceCondition.HEALTHY for service in AssuranceService}


def _snapshot(
    *,
    services: dict[AssuranceService, ServiceCondition] | None = None,
    telemetry: TelemetryCondition = TelemetryCondition.FRESH,
    compromised: frozenset[str] = frozenset(),
    revoked: frozenset[str] = frozenset(),
    quarantined: frozenset[str] = frozenset(),
    unresolved_effect: bool = False,
) -> CompromiseSnapshot:
    return CompromiseSnapshot(
        snapshot_id="snapshot-20260825-0001",
        captured_at=NOW,
        service_conditions=_healthy_services() if services is None else services,
        telemetry_condition=telemetry,
        compromised_principals=compromised,
        revoked_principals=revoked,
        quarantined_principals=quarantined,
        unresolved_effect=unresolved_effect,
    )


def _mission(
    *,
    actor_id: str = LEAF_ID,
    path: tuple[str, ...] = ("root", "supervisor-a", LEAF_ID),
) -> MissionAdmissionRequest:
    return MissionAdmissionRequest(
        request_id="mission-request-0001",
        actor_id=actor_id,
        delegation_principals=path,
        requested_at=NOW,
    )


def _authorization(
    private_key: Ed25519PrivateKey,
    snapshot: CompromiseSnapshot,
    *,
    sequence: int = 1,
    nonce: str = "recovery-nonce-0001",
    operation: RecoveryOperation = RecoveryOperation.RELEASE_QUARANTINE,
    target: str = LEAF_ID,
    reconciliation_complete: bool = True,
    authority_id: str = AUTHORITY_ID,
    evidence_sha256: str | None = None,
    issued_at: datetime = NOW - timedelta(seconds=30),
    expires_at: datetime = NOW + timedelta(minutes=5),
) -> RecoveryAuthorization:
    return RecoveryAuthorization(
        authorization_id=f"recovery-authorization-{sequence:04d}",
        sequence=sequence,
        authority_id=authority_id,
        subject_id=SUBJECT_ID,
        operation=operation,
        target=target,
        evidence_sha256=snapshot.digest if evidence_sha256 is None else evidence_sha256,
        reconciliation_complete=reconciliation_complete,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
    ).signed(private_key)


def _request(
    snapshot: CompromiseSnapshot,
    *,
    operation: RecoveryOperation = RecoveryOperation.RELEASE_QUARANTINE,
    target: str = LEAF_ID,
    reconciliation_complete: bool = True,
    evidence_sha256: str | None = None,
) -> RecoveryRequest:
    return RecoveryRequest(
        subject_id=SUBJECT_ID,
        operation=operation,
        target=target,
        evidence_sha256=snapshot.digest if evidence_sha256 is None else evidence_sha256,
        reconciliation_complete=reconciliation_complete,
    )


def test_compromised_leaf_is_quarantined_without_authorizing_execution() -> None:
    services = _healthy_services()
    services[AssuranceService.POLICY] = ServiceCondition.UNAVAILABLE
    result = evaluate_mission_admission(
        _mission(),
        _snapshot(services=services, compromised=frozenset({LEAF_ID})),
    )

    assert result.outcome is MissionGateOutcome.QUARANTINE
    assert result.reasons == ("actor_compromised", "policy_unavailable")
    assert not result.may_enter_primary_assurance
    assert not result.execution_authorized


@pytest.mark.parametrize(
    ("principal_state", "expected_reason"),
    [
        ("compromised", "delegation_ancestor_compromised"),
        ("revoked", "delegation_ancestor_revoked"),
        ("quarantined", "delegation_ancestor_quarantined"),
    ],
)
def test_affected_ancestor_blocks_descendant(
    principal_state: str,
    expected_reason: str,
) -> None:
    affected = frozenset({"supervisor-a"})
    snapshot = _snapshot(
        compromised=affected if principal_state == "compromised" else frozenset(),
        revoked=affected if principal_state == "revoked" else frozenset(),
        quarantined=affected if principal_state == "quarantined" else frozenset(),
    )

    result = evaluate_mission_admission(_mission(), snapshot)

    assert result.outcome is MissionGateOutcome.DENY
    assert result.reasons == (expected_reason,)
    assert not result.may_enter_primary_assurance


def test_unrelated_branch_may_continue_only_to_primary_assurance() -> None:
    snapshot = _snapshot(
        compromised=frozenset({"supervisor-b", "agent-other"}),
        revoked=frozenset({"retired-agent"}),
        quarantined=frozenset({"isolated-agent"}),
    )

    result = evaluate_mission_admission(_mission(), snapshot)

    assert result.outcome is MissionGateOutcome.CONTINUE_PRIMARY_ASSURANCE
    assert result.reasons == ("continue_to_primary_assurance",)
    assert result.may_enter_primary_assurance
    assert not result.execution_authorized


@pytest.mark.parametrize("service", list(AssuranceService))
@pytest.mark.parametrize(
    "condition",
    [ServiceCondition.UNAVAILABLE, ServiceCondition.UNTRUSTED],
)
def test_assurance_service_failure_fails_closed(
    service: AssuranceService,
    condition: ServiceCondition,
) -> None:
    services = _healthy_services()
    services[service] = condition

    result = evaluate_mission_admission(_mission(), _snapshot(services=services))

    assert result.outcome is MissionGateOutcome.DENY
    assert result.reasons == (f"{service.value}_{condition.value}",)


@pytest.mark.parametrize(
    "condition",
    [condition for condition in TelemetryCondition if condition is not TelemetryCondition.FRESH],
)
def test_non_fresh_telemetry_fails_closed(condition: TelemetryCondition) -> None:
    result = evaluate_mission_admission(
        _mission(),
        _snapshot(telemetry=condition),
    )

    assert result.outcome is MissionGateOutcome.DENY
    assert result.reasons == (f"telemetry_{condition.value}",)


def test_unresolved_effect_blocks_new_work() -> None:
    result = evaluate_mission_admission(
        _mission(),
        _snapshot(unresolved_effect=True),
    )

    assert result.outcome is MissionGateOutcome.DENY
    assert result.reasons == ("outcome_reconciliation_required",)


def test_stale_or_future_compromise_state_fails_closed() -> None:
    stale = _snapshot().model_copy(update={"captured_at": NOW - timedelta(seconds=6)})
    future = _snapshot().model_copy(update={"captured_at": NOW + timedelta(microseconds=1)})

    stale_result = evaluate_mission_admission(_mission(), stale)
    future_result = evaluate_mission_admission(_mission(), future)

    assert stale_result.outcome is MissionGateOutcome.DENY
    assert stale_result.reasons == ("compromise_snapshot_stale",)
    assert future_result.outcome is MissionGateOutcome.DENY
    assert future_result.reasons == ("compromise_snapshot_from_future",)


def test_future_request_and_invalid_snapshot_age_policy_fail_closed() -> None:
    request = _mission().model_copy(update={"requested_at": NOW + timedelta(seconds=1)})

    result = evaluate_mission_admission(request, _snapshot(), now=NOW)

    assert result.outcome is MissionGateOutcome.DENY
    assert result.reasons == ("mission_request_from_future",)
    with pytest.raises(ValueError, match="must not be negative"):
        evaluate_mission_admission(
            _mission(),
            _snapshot(),
            maximum_snapshot_age=timedelta(microseconds=-1),
        )


def test_snapshot_is_complete_immutable_and_canonical() -> None:
    external_services = _healthy_services()
    first = _snapshot(
        services=external_services,
        compromised=frozenset({"z-agent", "a-agent"}),
        quarantined=frozenset({"q-two", "q-one"}),
    )
    reversed_services = dict(reversed(tuple(_healthy_services().items())))
    second = _snapshot(
        services=reversed_services,
        compromised=frozenset({"a-agent", "z-agent"}),
        quarantined=frozenset({"q-one", "q-two"}),
    )

    external_services[AssuranceService.IDENTITY] = ServiceCondition.UNTRUSTED
    assert first.service_conditions[AssuranceService.IDENTITY] is ServiceCondition.HEALTHY
    with pytest.raises(TypeError):
        cast(Any, first.service_conditions)[AssuranceService.IDENTITY] = (
            ServiceCondition.UNTRUSTED
        )
    assert first.digest == second.digest

    incomplete = _healthy_services()
    del incomplete[AssuranceService.GATEWAY]
    with pytest.raises(ValidationError, match="every assurance service"):
        _snapshot(services=incomplete)


def test_mission_result_cannot_claim_execution() -> None:
    snapshot = _snapshot()
    with pytest.raises(ValidationError, match="cannot authorize execution"):
        MissionGateResult(
            outcome=MissionGateOutcome.CONTINUE_PRIMARY_ASSURANCE,
            reasons=("continue_to_primary_assurance",),
            evaluated_at=NOW,
            snapshot_sha256=snapshot.digest,
            may_enter_primary_assurance=True,
            execution_authorized=True,
        )


def test_signed_exact_evidence_authorizes_only_quarantine_release_step() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(quarantined=frozenset({LEAF_ID}))
    verifier = RecoveryAuthorizationVerifier(AUTHORITY_ID, private_key.public_key())

    result = verifier.evaluate(
        _request(snapshot),
        _authorization(private_key, snapshot),
        snapshot,
        now=NOW,
    )

    assert result.allowed
    assert result.reasons == ("authorized_recovery_step",)
    assert not result.plant_control_authorized


@pytest.mark.parametrize(
    ("reconciliation_complete", "unresolved_effect"),
    [(False, False), (True, True)],
)
def test_quarantine_release_requires_completed_reconciliation(
    reconciliation_complete: bool,
    unresolved_effect: bool,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(
        quarantined=frozenset({LEAF_ID}),
        unresolved_effect=unresolved_effect,
    )
    verifier = RecoveryAuthorizationVerifier(AUTHORITY_ID, private_key.public_key())
    authorization = _authorization(
        private_key,
        snapshot,
        reconciliation_complete=reconciliation_complete,
    )

    result = verifier.evaluate(
        _request(snapshot, reconciliation_complete=reconciliation_complete),
        authorization,
        snapshot,
        now=NOW,
    )

    assert not result.allowed
    assert "recovery_reconciliation_incomplete" in result.reasons


def test_reconciliation_claim_is_covered_by_signature_and_exact_match() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(quarantined=frozenset({LEAF_ID}))
    verifier = RecoveryAuthorizationVerifier(AUTHORITY_ID, private_key.public_key())
    authorization = _authorization(private_key, snapshot, reconciliation_complete=True)

    result = verifier.evaluate(
        _request(snapshot, reconciliation_complete=False),
        authorization,
        snapshot,
        now=NOW,
    )

    assert not result.allowed
    assert "recovery_reconciliation_claim_mismatch" in result.reasons


def test_wrong_key_and_tampering_fail_pinned_signature_check() -> None:
    pinned_private = Ed25519PrivateKey.generate()
    attacker_private = Ed25519PrivateKey.generate()
    snapshot = _snapshot(quarantined=frozenset({LEAF_ID}))
    verifier = RecoveryAuthorizationVerifier(AUTHORITY_ID, pinned_private.public_key())
    attacker_authorization = _authorization(attacker_private, snapshot)
    tampered_authorization = _authorization(pinned_private, snapshot).model_copy(
        update={"target": "different-agent"}
    )

    attacker_result = verifier.evaluate(
        _request(snapshot), attacker_authorization, snapshot, now=NOW
    )
    tampered_result = verifier.evaluate(
        _request(snapshot), tampered_authorization, snapshot, now=NOW
    )

    assert "recovery_authority_invalid" in attacker_result.reasons
    assert "recovery_authority_invalid" in tampered_result.reasons
    assert "recovery_target_mismatch" in tampered_result.reasons


def test_authorization_must_bind_request_and_current_snapshot_evidence() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(quarantined=frozenset({LEAF_ID}))
    changed_snapshot = _snapshot(
        quarantined=frozenset({LEAF_ID}),
        revoked=frozenset({"newly-revoked"}),
    )
    verifier = RecoveryAuthorizationVerifier(AUTHORITY_ID, private_key.public_key())
    authorization = _authorization(private_key, snapshot)

    request_mismatch = verifier.evaluate(
        _request(snapshot, evidence_sha256="0" * 64),
        authorization,
        snapshot,
        now=NOW,
    )
    snapshot_mismatch = verifier.evaluate(
        _request(snapshot),
        authorization,
        changed_snapshot,
        now=NOW,
    )

    assert "recovery_request_evidence_mismatch" in request_mismatch.reasons
    assert "recovery_snapshot_evidence_mismatch" in snapshot_mismatch.reasons


def test_sequence_and_nonce_replay_controls_are_strict() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(quarantined=frozenset({LEAF_ID}))
    verifier = RecoveryAuthorizationVerifier(AUTHORITY_ID, private_key.public_key())
    request = _request(snapshot)
    first = _authorization(private_key, snapshot, sequence=1, nonce="recovery-nonce-0001")

    assert verifier.evaluate(request, first, snapshot, now=NOW).allowed
    replay = verifier.evaluate(request, first, snapshot, now=NOW)
    stale = verifier.evaluate(
        request,
        _authorization(private_key, snapshot, sequence=1, nonce="recovery-nonce-0002"),
        snapshot,
        now=NOW,
    )
    reused_nonce = verifier.evaluate(
        request,
        _authorization(private_key, snapshot, sequence=2, nonce="recovery-nonce-0001"),
        snapshot,
        now=NOW,
    )
    next_valid = verifier.evaluate(
        request,
        _authorization(private_key, snapshot, sequence=2, nonce="recovery-nonce-0003"),
        snapshot,
        now=NOW,
    )

    assert "recovery_authorization_sequence_not_monotonic" in replay.reasons
    assert "recovery_authorization_replayed" in replay.reasons
    assert stale.reasons == ("recovery_authorization_sequence_not_monotonic",)
    assert reused_nonce.reasons == ("recovery_authorization_replayed",)
    assert next_valid.allowed


def test_rejected_high_sequence_does_not_poison_verifier_state() -> None:
    pinned_private = Ed25519PrivateKey.generate()
    attacker_private = Ed25519PrivateKey.generate()
    snapshot = _snapshot(quarantined=frozenset({LEAF_ID}))
    verifier = RecoveryAuthorizationVerifier(AUTHORITY_ID, pinned_private.public_key())
    request = _request(snapshot)

    rejected = verifier.evaluate(
        request,
        _authorization(attacker_private, snapshot, sequence=999),
        snapshot,
        now=NOW,
    )
    accepted = verifier.evaluate(
        request,
        _authorization(pinned_private, snapshot, sequence=1),
        snapshot,
        now=NOW,
    )

    assert not rejected.allowed
    assert accepted.allowed


def test_expired_and_overlong_authorizations_fail_closed() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(quarantined=frozenset({LEAF_ID}))
    verifier = RecoveryAuthorizationVerifier(
        AUTHORITY_ID,
        private_key.public_key(),
        maximum_lifetime_seconds=60,
    )
    authorization = _authorization(
        private_key,
        snapshot,
        issued_at=NOW - timedelta(minutes=3),
        expires_at=NOW - timedelta(minutes=1),
    )

    result = verifier.evaluate(_request(snapshot), authorization, snapshot, now=NOW)

    assert not result.allowed
    assert "recovery_authorization_inactive" in result.reasons
    assert "recovery_authorization_lifetime_exceeded" in result.reasons


def test_operation_contract_cannot_encode_plant_control() -> None:
    assert {operation.value for operation in RecoveryOperation} == {
        "publish_revocation",
        "rotate_credential",
        "reconcile_effect",
        "restore_assurance_service",
        "release_quarantine",
    }
    with pytest.raises(ValueError):
        RecoveryOperation("write_register")
    with pytest.raises(ValidationError):
        RecoveryRequest.model_validate(
            {
                "subject_id": SUBJECT_ID,
                "operation": "set_breaker",
                "target": "plc-1",
                "evidence_sha256": "0" * 64,
            }
        )


def test_operation_specific_recovery_preconditions_fail_closed() -> None:
    private_key = Ed25519PrivateKey.generate()
    healthy_snapshot = _snapshot()
    verifier = RecoveryAuthorizationVerifier(AUTHORITY_ID, private_key.public_key())

    healthy_service_restore = verifier.evaluate(
        _request(
            healthy_snapshot,
            operation=RecoveryOperation.RESTORE_ASSURANCE_SERVICE,
            target=AssuranceService.IDENTITY.value,
            reconciliation_complete=False,
        ),
        _authorization(
            private_key,
            healthy_snapshot,
            operation=RecoveryOperation.RESTORE_ASSURANCE_SERVICE,
            target=AssuranceService.IDENTITY.value,
            reconciliation_complete=False,
        ),
        healthy_snapshot,
        now=NOW,
    )

    assert not healthy_service_restore.allowed
    assert healthy_service_restore.reasons == ("recovery_service_already_healthy",)
