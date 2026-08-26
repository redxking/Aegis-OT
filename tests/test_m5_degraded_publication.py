from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_ot.m5_degraded import (
    DegradedAdmissionOutcome,
    DegradedBehavior,
    DegradedModeReversal,
    DegradedRole,
    DegradedRuntimeSnapshot,
    RoleCondition,
)
from aegis_ot.m5_degraded_publication import (
    AtomicDegradedPublicationSink,
    DegradedPublicationError,
    DegradedPublicationPublisher,
    DegradedPublisherCredential,
    DegradedRuntimePublication,
    DegradedStatusInput,
    FileDegradedConsumerStateStore,
    FileDegradedPublicationSource,
    FileDegradedPublisherStateStore,
    PublishedDegradedOperationGate,
    StableDegradedAuthorization,
    degraded_role_policy_sha256,
    main,
)
from aegis_ot.models import ActionProposal, Operation

NOW = datetime(2026, 8, 26, 14, 0, tzinfo=UTC)
AUTHORITY_ID = "m5-offline-authority"


def _key_id(private_key: Ed25519PrivateKey) -> str:
    return hashlib.sha256(private_key.public_key().public_bytes_raw()).hexdigest()


def _healthy_conditions() -> dict[DegradedRole, RoleCondition]:
    return {role: RoleCondition.HEALTHY for role in DegradedRole}


def _management_conditions() -> tuple[
    dict[DegradedRole, RoleCondition],
    dict[DegradedRole, RoleCondition],
]:
    services = _healthy_conditions()
    paths = _healthy_conditions()
    services[DegradedRole.MANAGEMENT] = RoleCondition.UNAVAILABLE
    return services, paths


@dataclass(frozen=True)
class TrustMaterial:
    root_private_key: Ed25519PrivateKey
    publisher_private_key: Ed25519PrivateKey
    credential: DegradedPublisherCredential
    authorization: StableDegradedAuthorization
    status_input: DegradedStatusInput


def _trust_material(
    *,
    at: datetime = NOW,
    maximum_publication_age_seconds: int = 10,
    maximum_status_input_age_seconds: int = 300,
    authorization_expires_at: datetime | None = None,
) -> TrustMaterial:
    root = Ed25519PrivateKey.generate()
    publisher = Ed25519PrivateKey.generate()
    root_key_id = _key_id(root)
    publisher_key_id = _key_id(publisher)
    credential = DegradedPublisherCredential(
        credential_id="publisher-credential-20260826-0001",
        authority_id=AUTHORITY_ID,
        authority_key_id=root_key_id,
        publisher_id="m5-online-health-publisher",
        publisher_key_id=publisher_key_id,
        publisher_public_key_b64=base64.b64encode(publisher.public_key().public_bytes_raw()).decode(
            "ascii"
        ),
        health_source_id="operator-condition-template",
        source_git_commit="1" * 40,
        source_fingerprint_sha256="2" * 64,
        issued_at=at - timedelta(minutes=1),
        expires_at=at + timedelta(hours=1),
        maximum_publication_age_seconds=maximum_publication_age_seconds,
        maximum_status_input_age_seconds=maximum_status_input_age_seconds,
    ).signed(root)
    services, paths = _management_conditions()
    authorization = StableDegradedAuthorization(
        authorization_id="stable-authorization-20260826-0001",
        sequence=1,
        authority_id=AUTHORITY_ID,
        authority_key_id=root_key_id,
        publisher_credential_sha256=credential.digest,
        publisher_key_id=publisher_key_id,
        mode_name="management-loss",
        behavior=DegradedBehavior.MISSION_PRESERVING,
        affected_roles=frozenset({DegradedRole.MANAGEMENT}),
        role_conditions=services,
        communication_conditions=paths,
        allowed_actor_ids=frozenset({"agent:operator-1"}),
        allowed_mission_ids=frozenset({"microgrid-containment"}),
        allowed_resources=frozenset({"feeder-1"}),
        allowed_operations=frozenset({Operation.ISOLATE_ASSET}),
        maximum_risk_score=65.0,
        role_policy_sha256=degraded_role_policy_sha256(),
        recovery_checkpoint_id="recovery-checkpoint-management-0001",
        nonce="stable-authorization-nonce-0001",
        issued_at=at - timedelta(seconds=30),
        expires_at=(
            at + timedelta(minutes=2)
            if authorization_expires_at is None
            else authorization_expires_at
        ),
    ).signed(root)
    status_input = DegradedStatusInput(
        status_input_id="status-input-20260826-0001",
        sequence=1,
        source_id=credential.health_source_id,
        observed_at=at,
        expires_at=at + timedelta(seconds=maximum_status_input_age_seconds),
        role_conditions=services,
        communication_conditions=paths,
    )
    return TrustMaterial(root, publisher, credential, authorization, status_input)


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _canonical_bytes(model: Any) -> bytes:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _write_model(path: Path, model: Any) -> None:
    path.write_bytes(_canonical_bytes(model))
    path.chmod(0o600)


def _write_key(path: Path, material: bytes) -> None:
    path.write_bytes(material)
    path.chmod(0o600)


def _proposal() -> ActionProposal:
    return ActionProposal(
        proposal_id="m5-publication-proposal-0001",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 2.0},
        observed_state_version=7,
        observed_at=NOW,
        submitted_at=NOW,
        nonce="m5-proposal-nonce-0001",
        confidence=0.99,
        risk_score=20.0,
        delegation_chain=("operator",),
    )


def _snapshot(
    status_input: DegradedStatusInput,
    *,
    captured_at: datetime,
    healthy: bool = False,
) -> DegradedRuntimeSnapshot:
    services = _healthy_conditions() if healthy else dict(status_input.role_conditions)
    paths = _healthy_conditions() if healthy else dict(status_input.communication_conditions)
    return DegradedRuntimeSnapshot(
        snapshot_id=f"runtime-snapshot-{captured_at.timestamp():.6f}",
        captured_at=captured_at,
        role_conditions=services,
        communication_conditions=paths,
        unresolved_effect=False,
    )


def _publication(
    trust: TrustMaterial,
    *,
    sequence: int,
    published_at: datetime,
    previous: str | None,
    healthy: bool = False,
    authorization: StableDegradedAuthorization | None = None,
    expires_at: datetime | None = None,
) -> DegradedRuntimePublication:
    selected_authorization = trust.authorization if authorization is None else authorization
    return DegradedRuntimePublication(
        publication_id=f"runtime-publication-{sequence:08d}",
        sequence=sequence,
        previous_publication_sha256=previous,
        publisher_credential_sha256=trust.credential.digest,
        publisher_key_id=trust.credential.publisher_key_id,
        health_source_id=trust.credential.health_source_id,
        status_input_sha256=trust.status_input.digest,
        published_at=published_at,
        expires_at=(
            published_at + timedelta(seconds=trust.credential.maximum_publication_age_seconds)
            if expires_at is None
            else expires_at
        ),
        snapshot=_snapshot(
            trust.status_input,
            captured_at=published_at,
            healthy=healthy,
        ),
        authorization=selected_authorization,
    ).signed(trust.publisher_private_key)


def _publisher(
    tmp_path: Path,
    trust: TrustMaterial,
    *,
    clock: list[datetime],
) -> tuple[
    DegradedPublicationPublisher,
    AtomicDegradedPublicationSink,
    FileDegradedPublisherStateStore,
    Path,
]:
    output = _private_directory(tmp_path / "publication") / "current.json"
    state_path = _private_directory(tmp_path / "publisher-state") / "state.json"
    FileDegradedPublisherStateStore.initialize(
        state_path,
        credential=trust.credential,
    )
    sink = AtomicDegradedPublicationSink(output)
    state_store = FileDegradedPublisherStateStore(state_path)
    publisher = DegradedPublicationPublisher(
        authority_public_key=trust.root_private_key.public_key(),
        credential=trust.credential,
        publisher_private_key=trust.publisher_private_key,
        status_source=lambda: trust.status_input,
        authorization_source=lambda: trust.authorization,
        sink=sink,
        state_store=state_store,
        clock=lambda: clock[0],
    )
    return publisher, sink, state_store, state_path


def _gate(
    tmp_path: Path,
    trust: TrustMaterial,
    current: dict[str, Any],
) -> tuple[PublishedDegradedOperationGate, FileDegradedConsumerStateStore, Path]:
    state_path = _private_directory(tmp_path / "consumer-state") / "state.json"
    FileDegradedConsumerStateStore.initialize(
        state_path,
        credential=trust.credential,
    )
    state_store = FileDegradedConsumerStateStore(state_path)
    gate = PublishedDegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=trust.root_private_key.public_key(),
        publisher_credential=trust.credential,
        stable_authorization=trust.authorization,
        publication_source=lambda: current["publication"],
        reversal_source=lambda: current.get("reversal"),
        state_store=state_store,
    )
    return gate, state_store, state_path


def _reversal(
    trust: TrustMaterial,
    *,
    issued_at: datetime,
    signer: Ed25519PrivateKey | None = None,
) -> DegradedModeReversal:
    authorization = trust.authorization
    return DegradedModeReversal(
        reversal_id="runtime-reversal-20260826-0001",
        sequence=1,
        authority_id=AUTHORITY_ID,
        authorization_id=authorization.authorization_id,
        authorization_sha256=authorization.digest,
        recovery_checkpoint_id=authorization.recovery_checkpoint_id,
        reason_code="runtime_dependencies_recovered",
        nonce="runtime-reversal-nonce-0001",
        issued_at=issued_at,
    ).signed(trust.root_private_key if signer is None else signer)


def test_offline_root_delegates_publication_but_not_authorization() -> None:
    trust = _trust_material()
    publication = _publication(
        trust,
        sequence=1,
        published_at=NOW,
        previous=None,
    )
    leaf_signed_authorization = trust.authorization.model_copy(update={"signature": ""}).signed(
        trust.publisher_private_key
    )

    assert trust.credential.verify(trust.root_private_key.public_key())
    assert not trust.credential.verify(trust.publisher_private_key.public_key())
    assert trust.authorization.verify(trust.root_private_key.public_key())
    assert not leaf_signed_authorization.verify(trust.root_private_key.public_key())
    assert publication.verify(trust.publisher_private_key.public_key())
    assert not publication.verify(trust.root_private_key.public_key())
    assert publication.expires_at == NOW + timedelta(
        seconds=trust.credential.maximum_publication_age_seconds
    )


def test_publisher_refreshes_template_and_durably_chains_generations(
    tmp_path: Path,
) -> None:
    trust = _trust_material()
    clock = [NOW]
    publisher, sink, state_store, _ = _publisher(tmp_path, trust, clock=clock)

    first = publisher.publish_once()
    clock[0] = NOW + timedelta(seconds=1)
    second = publisher.publish_once()

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_publication_sha256 == first.digest
    assert first.status_input_sha256 == second.status_input_sha256 == trust.status_input.digest
    assert first.snapshot.snapshot_id != second.snapshot.snapshot_id
    assert first.snapshot.captured_at == NOW
    assert second.snapshot.captured_at == NOW
    assert sink.current() == second
    assert FileDegradedPublicationSource(sink.path)() == second
    assert sink.path.stat().st_mode & 0o777 == 0o600
    assert sink.path.read_bytes() == _canonical_bytes(second)
    assert state_store.read().latest_publication_sha256 == second.digest

    clock[0] = NOW + timedelta(seconds=2)
    replacement = DegradedPublicationPublisher(
        authority_public_key=trust.root_private_key.public_key(),
        credential=trust.credential,
        publisher_private_key=trust.publisher_private_key,
        status_source=lambda: trust.status_input,
        authorization_source=lambda: trust.authorization,
        sink=AtomicDegradedPublicationSink(sink.path),
        state_store=FileDegradedPublisherStateStore(state_store.path),
        clock=lambda: clock[0],
    )
    assert replacement.publish_once().sequence == 3


def test_check_recovers_only_an_allocated_published_crash(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    live_now = datetime.now(UTC) - timedelta(seconds=1)
    trust = _trust_material(at=live_now)
    clock = [live_now]
    publisher, sink, state_store, state_path = _publisher(tmp_path, trust, clock=clock)
    first = publisher.publish_once()
    sequence, previous = state_store.allocate(
        first,
        credential=trust.credential,
        status_input=trust.status_input,
    )
    crashed_publication = _publication(
        trust,
        sequence=sequence,
        published_at=live_now + timedelta(milliseconds=500),
        previous=previous,
    )
    sink.publish(crashed_publication)

    inputs = _private_directory(tmp_path / "check-inputs")
    root_path = inputs / "root.pub"
    credential_path = inputs / "credential.json"
    authorization_path = inputs / "authorization.json"
    _write_key(root_path, trust.root_private_key.public_key().public_bytes_raw())
    _write_model(credential_path, trust.credential)
    _write_model(authorization_path, trust.authorization)

    assert (
        main(
            [
                "check",
                "--root-public-key-file",
                str(root_path),
                "--publisher-credential-file",
                str(credential_path),
                "--stable-authorization-file",
                str(authorization_path),
                "--publication-file",
                str(sink.path),
                "--publisher-state-file",
                str(state_path),
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["durable_state_continuous"] is True
    assert report["sequence"] == 2
    assert state_store.read().latest_publication_sha256 == crashed_publication.digest
    reconciled = state_store.read()
    assert state_store.commit(
        crashed_publication,
        credential=trust.credential,
    ) == reconciled

    equivocated = _publication(
        trust,
        sequence=sequence,
        published_at=live_now + timedelta(milliseconds=750),
        previous=previous,
    )
    with pytest.raises(
        DegradedPublicationError,
        match="equivocated at its committed sequence",
    ):
        state_store.commit(equivocated, credential=trust.credential)


def test_publisher_rejects_stale_status_and_durable_status_rollback(
    tmp_path: Path,
) -> None:
    trust = _trust_material(maximum_status_input_age_seconds=30)
    clock = [NOW]
    publisher, _, state_store, _ = _publisher(tmp_path, trust, clock=clock)
    current_status = {"value": trust.status_input}
    publisher.status_source = lambda: current_status["value"]

    publisher.publish_once()
    clock[0] = NOW + timedelta(seconds=1)
    current_status["value"] = trust.status_input.model_copy(
        update={
            "status_input_id": "status-input-future-20260826-0002",
            "sequence": 2,
            "observed_at": NOW + timedelta(seconds=2),
            "expires_at": NOW + timedelta(seconds=20),
        }
    )
    with pytest.raises(DegradedPublicationError, match="from the future"):
        publisher.publish_once()

    current_status["value"] = trust.status_input.model_copy(
        update={
            "status_input_id": "status-input-expired-20260826-0002",
            "sequence": 2,
            "observed_at": NOW - timedelta(seconds=1),
            "expires_at": NOW + timedelta(seconds=1),
        }
    )
    with pytest.raises(DegradedPublicationError, match="expired"):
        publisher.publish_once()

    current_status["value"] = trust.status_input.model_copy(
        update={
            "status_input_id": "status-input-fresh-20260826-0002",
            "sequence": 2,
            "observed_at": clock[0],
            "expires_at": clock[0] + timedelta(seconds=30),
        }
    )
    publisher.publish_once()
    assert state_store.read().highest_status_input_sequence == 2

    clock[0] = NOW + timedelta(seconds=2)
    current_status["value"] = trust.status_input
    with pytest.raises(DegradedPublicationError, match="sequence rolled back"):
        publisher.publish_once()

    current_status["value"] = trust.status_input.model_copy(
        update={
            "status_input_id": "status-input-equivocated-20260826-0002",
            "sequence": 2,
            "observed_at": clock[0],
            "expires_at": clock[0] + timedelta(seconds=30),
        }
    )
    with pytest.raises(DegradedPublicationError, match="equivocated at its sequence"):
        publisher.publish_once()


def test_gate_returns_non_execution_admission_and_pins_authorization(
    tmp_path: Path,
) -> None:
    trust = _trust_material()
    current = {
        "publication": _publication(
            trust,
            sequence=5,
            published_at=NOW,
            previous="0" * 64,
        )
    }
    gate, state_store, _ = _gate(tmp_path, trust, current)

    result = gate.evaluate(_proposal(), now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE
    assert result.may_enter_primary_assurance
    assert not result.execution_authorized
    assert state_store.read().highest_publication_sequence == 5
    assert state_store.read().active_authorization_sha256 == trust.authorization.digest

    alternate = trust.authorization.model_copy(
        update={
            "authorization_id": "stable-authorization-20260826-9999",
            "sequence": 2,
            "nonce": "stable-authorization-nonce-9999",
            "signature": "",
        }
    ).signed(trust.root_private_key)
    current["publication"] = _publication(
        trust,
        sequence=6,
        published_at=NOW + timedelta(seconds=1),
        previous=result.observable_event_sha256,
        authorization=alternate,
    )
    rejected = gate.evaluate(_proposal(), now=NOW + timedelta(seconds=1))
    assert rejected.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_publication_authorization_mismatch" in rejected.reasons


def test_readiness_accepts_gaps_but_rejects_contiguous_chain_breaks_and_equivocation(
    tmp_path: Path,
) -> None:
    trust = _trust_material()
    first = _publication(trust, sequence=1, published_at=NOW, previous=None)
    current: dict[str, Any] = {"publication": first}
    gate, state_store, _ = _gate(tmp_path, trust, current)

    first_status = gate.readiness(now=NOW)
    assert first_status["ready"] is True
    assert first_status["authorization_active"] is True
    assert state_store.read().highest_publication_sequence == 1

    skipped = _publication(
        trust,
        sequence=3,
        published_at=NOW + timedelta(seconds=2),
        previous="1" * 64,
    )
    current["publication"] = skipped
    assert gate.readiness(now=NOW + timedelta(seconds=2))["publication_sequence"] == 3
    assert state_store.read().highest_publication_sha256 == skipped.digest

    broken_contiguous = _publication(
        trust,
        sequence=4,
        published_at=NOW + timedelta(seconds=3),
        previous="2" * 64,
    )
    current["publication"] = broken_contiguous
    with pytest.raises(DegradedPublicationError, match="predecessor_mismatch"):
        gate.readiness(now=NOW + timedelta(seconds=3))

    equivocation = _publication(
        trust,
        sequence=3,
        published_at=NOW + timedelta(seconds=2, microseconds=1),
        previous="1" * 64,
    )
    current["publication"] = equivocation
    with pytest.raises(DegradedPublicationError, match="sequence_equivocation"):
        gate.readiness(now=NOW + timedelta(seconds=3))


def test_active_lease_clears_only_with_exact_root_reversal_after_expiry(
    tmp_path: Path,
) -> None:
    authorization_expiry = NOW + timedelta(seconds=2)
    trust = _trust_material(authorization_expires_at=authorization_expiry)
    first = _publication(trust, sequence=1, published_at=NOW, previous=None)
    current: dict[str, Any] = {"publication": first}
    gate, state_store, state_path = _gate(tmp_path, trust, current)
    gate.readiness(now=NOW)

    recovered_at = authorization_expiry + timedelta(seconds=1)
    recovered = _publication(
        trust,
        sequence=2,
        published_at=recovered_at,
        previous=first.digest,
        healthy=True,
    )
    current["publication"] = recovered
    held = gate.evaluate(_proposal(), now=recovered_at)
    assert held.outcome is DegradedAdmissionOutcome.HOLD_STATE
    assert "degraded_condition_cleared_reversal_required" in held.reasons
    assert state_store.read().active_authorization_sha256 == trust.authorization.digest

    current["reversal"] = _reversal(trust, issued_at=recovered_at)
    ready = gate.readiness(now=recovered_at)
    assert ready["reversal_applicable"] is True
    assert ready["authorization_active"] is False
    assert state_store.read().active_authorization_sha256 is None
    assert state_store.read().highest_reversal_sequence == 1

    replacement = PublishedDegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=trust.root_private_key.public_key(),
        publisher_credential=trust.credential,
        stable_authorization=trust.authorization,
        publication_source=lambda: current["publication"],
        reversal_source=lambda: current["reversal"],
        state_store=FileDegradedConsumerStateStore(state_path),
    )
    final = replacement.evaluate(_proposal(), now=recovered_at + timedelta(seconds=1))
    assert final.outcome is DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE
    assert "normal_runtime_dependencies_healthy_after_signed_reversal" in final.reasons


def test_publisher_signed_reversal_is_rejected_and_does_not_clear_lease(
    tmp_path: Path,
) -> None:
    trust = _trust_material()
    first = _publication(trust, sequence=1, published_at=NOW, previous=None)
    current: dict[str, Any] = {"publication": first}
    gate, state_store, _ = _gate(tmp_path, trust, current)
    gate.readiness(now=NOW)
    current["publication"] = _publication(
        trust,
        sequence=2,
        published_at=NOW + timedelta(seconds=1),
        previous=first.digest,
        healthy=True,
    )
    current["reversal"] = _reversal(
        trust,
        issued_at=NOW + timedelta(seconds=1),
        signer=trust.publisher_private_key,
    )

    result = gate.evaluate(_proposal(), now=NOW + timedelta(seconds=1))

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_reversal_signature_invalid" in result.reasons
    assert state_store.read().active_authorization_sha256 == trust.authorization.digest


def test_new_authorization_cannot_replace_an_unreversed_active_lease(
    tmp_path: Path,
) -> None:
    trust = _trust_material()
    first = _publication(trust, sequence=1, published_at=NOW, previous=None)
    current: dict[str, Any] = {"publication": first}
    gate, state_store, state_path = _gate(tmp_path, trust, current)
    gate.readiness(now=NOW)

    replacement_authorization = trust.authorization.model_copy(
        update={
            "authorization_id": "stable-authorization-20260826-0002",
            "sequence": 2,
            "nonce": "stable-authorization-nonce-0002",
            "signature": "",
        }
    ).signed(trust.root_private_key)
    replacement_trust = TrustMaterial(
        trust.root_private_key,
        trust.publisher_private_key,
        trust.credential,
        replacement_authorization,
        trust.status_input,
    )
    current["publication"] = _publication(
        replacement_trust,
        sequence=2,
        published_at=NOW + timedelta(seconds=1),
        previous=first.digest,
    )
    replacement_gate = PublishedDegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=trust.root_private_key.public_key(),
        publisher_credential=trust.credential,
        stable_authorization=replacement_authorization,
        publication_source=lambda: current["publication"],
        state_store=FileDegradedConsumerStateStore(state_path),
    )

    result = replacement_gate.evaluate(_proposal(), now=NOW + timedelta(seconds=1))

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_active_authorization_reversal_required" in result.reasons
    assert state_store.read().active_authorization_sha256 == trust.authorization.digest


@pytest.mark.parametrize(
    ("published_at", "expires_at", "reason"),
    [
        (
            NOW - timedelta(seconds=11),
            NOW - timedelta(seconds=1),
            "degraded_publication_stale",
        ),
        (
            NOW,
            NOW + timedelta(seconds=11),
            "degraded_publication_lifetime_exceeded",
        ),
        (
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=10),
            "degraded_publication_from_future",
        ),
    ],
)
def test_readiness_rejects_stale_overlong_and_future_publications(
    tmp_path: Path,
    published_at: datetime,
    expires_at: datetime,
    reason: str,
) -> None:
    trust = _trust_material()
    current = {
        "publication": _publication(
            trust,
            sequence=1,
            published_at=published_at,
            previous=None,
            expires_at=expires_at,
        )
    }
    gate, _, _ = _gate(tmp_path, trust, current)

    with pytest.raises(DegradedPublicationError, match=reason):
        gate.readiness(now=NOW)


def test_strict_file_source_and_durable_state_fail_closed(tmp_path: Path) -> None:
    trust = _trust_material()
    publication = _publication(trust, sequence=1, published_at=NOW, previous=None)
    source_dir = _private_directory(tmp_path / "source")
    source_path = source_dir / "current.json"
    _write_model(source_path, publication)
    assert FileDegradedPublicationSource(source_path)() == publication

    source_path.chmod(0o644)
    with pytest.raises(DegradedPublicationError, match="single-link 0600"):
        FileDegradedPublicationSource(source_path)()
    source_path.chmod(0o600)
    os.link(source_path, source_dir / "second-link.json")
    with pytest.raises(DegradedPublicationError, match="single-link 0600"):
        FileDegradedPublicationSource(source_path)()

    current: dict[str, Any] = {"publication": publication}
    gate, _, state_path = _gate(tmp_path, trust, current)
    gate.readiness(now=NOW)
    state_path.chmod(0o644)
    result = gate.evaluate(_proposal(), now=NOW)
    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert result.reasons == ("degraded_consumer_state_unavailable",)
    with pytest.raises(DegradedPublicationError, match="consumer state is unavailable"):
        gate.readiness(now=NOW)
