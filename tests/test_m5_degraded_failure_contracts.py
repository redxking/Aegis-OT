"""Behavior contracts for bounded degraded-mode failures and persistence."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import aegis_ot.m5_degraded as m5_degraded
from aegis_ot.m5_degraded import (
    MAX_DEGRADED_CONFIGURATION_BYTES,
    MAX_DEGRADED_STATE_ENTRIES,
    DegradedAdmissionOutcome,
    DegradedAdmissionResult,
    DegradedBehavior,
    DegradedModeAuthorization,
    DegradedModeReversal,
    DegradedOperationGate,
    DegradedOperationState,
    DegradedReversalResult,
    DegradedRole,
    DegradedRuntimeSnapshot,
    FileDegradedAuthorizationSource,
    FileDegradedOperationStateStore,
    FileDegradedSnapshotSource,
    InMemoryDegradedOperationStateStore,
    RoleCondition,
    RoleLossPolicy,
)
from aegis_ot.models import ActionProposal, Operation

NOW = datetime(2026, 8, 26, 14, 0, tzinfo=UTC)
AUTHORITY_ID = "m5-degraded-authority"


def _conditions() -> dict[DegradedRole, RoleCondition]:
    return {role: RoleCondition.HEALTHY for role in DegradedRole}


def _snapshot(
    *,
    role: DegradedRole | None = None,
    captured_at: datetime = NOW,
) -> DegradedRuntimeSnapshot:
    role_conditions = _conditions()
    if role is not None:
        role_conditions[role] = RoleCondition.UNAVAILABLE
    return DegradedRuntimeSnapshot(
        snapshot_id="degraded-snapshot-coverage-0001",
        captured_at=captured_at,
        role_conditions=role_conditions,
        communication_conditions=_conditions(),
    )


def _authorization(
    private_key: Ed25519PrivateKey,
    snapshot: DegradedRuntimeSnapshot,
    **updates: Any,
) -> DegradedModeAuthorization:
    material: dict[str, Any] = {
        "authorization_id": "degraded-authorization-coverage-0001",
        "sequence": 1,
        "authority_id": AUTHORITY_ID,
        "mode_name": "management-loss-degraded",
        "behavior": DegradedBehavior.MISSION_PRESERVING,
        "affected_roles": frozenset({DegradedRole.MANAGEMENT}),
        "allowed_actor_ids": frozenset({"agent:operator-1"}),
        "allowed_mission_ids": frozenset({"microgrid-containment"}),
        "allowed_resources": frozenset({"feeder-1"}),
        "allowed_operations": frozenset({Operation.ISOLATE_ASSET}),
        "maximum_risk_score": 65.0,
        "snapshot_sha256": snapshot.digest,
        "recovery_checkpoint_id": "recovery-checkpoint-coverage-0001",
        "nonce": "degraded-authorization-nonce-0001",
        "issued_at": NOW - timedelta(seconds=1),
        "expires_at": NOW + timedelta(minutes=1),
    }
    material.update(updates)
    return DegradedModeAuthorization.model_validate(material).signed(private_key)


def _reversal(
    private_key: Ed25519PrivateKey,
    authorization: DegradedModeAuthorization,
    **updates: Any,
) -> DegradedModeReversal:
    material: dict[str, Any] = {
        "reversal_id": "degraded-reversal-coverage-0001",
        "sequence": 1,
        "authority_id": AUTHORITY_ID,
        "authorization_id": authorization.authorization_id,
        "authorization_sha256": authorization.digest,
        "recovery_checkpoint_id": authorization.recovery_checkpoint_id,
        "reason_code": "runtime_dependencies_recovered",
        "nonce": "degraded-reversal-nonce-coverage-0001",
        "issued_at": NOW,
    }
    material.update(updates)
    return DegradedModeReversal.model_validate(material).signed(private_key)


def _gate(
    private_key: Ed25519PrivateKey,
    snapshot: DegradedRuntimeSnapshot,
    authorization: DegradedModeAuthorization | None,
    *,
    state_store: Any = None,
) -> DegradedOperationGate:
    return DegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=private_key.public_key(),
        snapshot_source=lambda: snapshot,
        authorization_source=lambda: authorization,
        state_store=state_store,
    )


def _write_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(mode)


class _ScriptedStateStore:
    def __init__(
        self,
        read_state: Any,
        *,
        update_state: Any | None = None,
        read_error: bool = False,
        update_error: bool = False,
    ) -> None:
        self.read_state = read_state
        self.update_state = update_state
        self.read_error = read_error
        self.update_error = update_error

    def read(self) -> Any:
        if self.read_error:
            raise OSError("state read failed")
        return self.read_state

    def update(self, transition: Callable[[Any], Any]) -> Any:
        if self.update_error:
            raise OSError("state update failed")
        state = self.read_state if self.update_state is None else self.update_state
        return transition(state)


def _raise_source_error() -> Any:
    raise OSError("configured source failed")


def test_model_invariants_reject_ambiguous_degraded_state() -> None:
    with pytest.raises(ValidationError, match="mission-preserving eligibility disagree"):
        RoleLossPolicy(
            behavior=DegradedBehavior.MISSION_PRESERVING,
            mission_preserving_eligible=False,
            effect="invalid policy",
        )

    valid_snapshot = _snapshot()
    snapshot_material = valid_snapshot.model_dump(mode="python")
    snapshot_material["role_conditions"] = {
        role: condition
        for role, condition in valid_snapshot.role_conditions.items()
        if role is not DegradedRole.IDENTITY
    }
    with pytest.raises(ValidationError, match="cover every runtime role"):
        DegradedRuntimeSnapshot.model_validate(snapshot_material)

    snapshot_material = valid_snapshot.model_dump(mode="python")
    snapshot_material["communication_conditions"] = {
        role: condition
        for role, condition in valid_snapshot.communication_conditions.items()
        if role is not DegradedRole.POLICY
    }
    with pytest.raises(ValidationError, match="communication path"):
        DegradedRuntimeSnapshot.model_validate(snapshot_material)

    snapshot_material = valid_snapshot.model_dump(mode="python")
    snapshot_material["captured_at"] = NOW.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="timezone-aware"):
        DegradedRuntimeSnapshot.model_validate(snapshot_material)


def test_authorization_and_reversal_models_reject_noncanonical_bounds() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(private_key, snapshot)
    material = authorization.model_dump(mode="python", exclude={"signature"})
    material["expires_at"] = material["issued_at"]
    with pytest.raises(ValidationError, match="expiry must follow issuance"):
        DegradedModeAuthorization.model_validate(material)

    material = authorization.model_dump(mode="python", exclude={"signature"})
    material["allowed_resources"] = frozenset({" feeder-1"})
    with pytest.raises(ValidationError, match="noncanonical text"):
        DegradedModeAuthorization.model_validate(material)

    reversal = _reversal(private_key, authorization)
    reversal_material = reversal.model_dump(mode="python", exclude={"signature"})
    reversal_material["authorization_id"] = " degraded-authorization-coverage-0001"
    with pytest.raises(ValidationError, match="noncanonical text"):
        DegradedModeReversal.model_validate(reversal_material)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"may_enter_primary_assurance": True}, "primary-assurance flag disagree"),
        ({"execution_authorized": True}, "cannot authorize execution"),
        ({"reasons": ("duplicate", "duplicate")}, "reasons must be unique"),
        (
            {"affected_roles": (DegradedRole.MANAGEMENT, DegradedRole.IDENTITY)},
            "roles must be sorted",
        ),
    ],
)
def test_admission_result_rejects_non_bypass_inconsistencies(
    updates: dict[str, Any],
    message: str,
) -> None:
    material: dict[str, Any] = {
        "outcome": DegradedAdmissionOutcome.SAFE_STATE,
        "reasons": ("bounded-denial",),
        "evaluated_at": NOW,
        "snapshot_sha256": "0" * 64,
        "affected_roles": (),
        "may_enter_primary_assurance": False,
        "observable_event_sha256": "1" * 64,
    }
    material.update(updates)
    with pytest.raises(ValidationError, match=message):
        DegradedAdmissionResult.model_validate(material)


def test_reversal_result_and_operation_state_reject_ambiguous_history() -> None:
    with pytest.raises(ValidationError, match="reversal reasons must be unique"):
        DegradedReversalResult(
            applied=False,
            reasons=("duplicate", "duplicate"),
            evaluated_at=NOW,
            authorization_sha256="a" * 64,
            reversal_sha256="b" * 64,
            observable_event_sha256="c" * 64,
        )

    with pytest.raises(ValidationError, match="malformed digest"):
        DegradedOperationState(
            authority_id=AUTHORITY_ID,
            highest_authorization_sequence=0,
            highest_reversal_sequence=0,
            accepted_reversal_nonce_sha256=("g" * 64,),
        )
    with pytest.raises(ValidationError, match="sorted and unique"):
        DegradedOperationState(
            authority_id=AUTHORITY_ID,
            highest_authorization_sequence=0,
            highest_reversal_sequence=0,
            revoked_authorization_sha256=("b" * 64, "a" * 64),
        )
    with pytest.raises(ValidationError, match="active digest disagree"):
        DegradedOperationState(
            authority_id=AUTHORITY_ID,
            highest_authorization_sequence=1,
            highest_reversal_sequence=0,
        )


def test_file_sources_reload_valid_material_and_treat_missing_lease_as_absent(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(private_key, snapshot)
    snapshot_path = tmp_path / "snapshot.json"
    authorization_path = tmp_path / "authorization.json"
    _write_json(snapshot_path, snapshot.model_dump(mode="json"))

    assert FileDegradedSnapshotSource(snapshot_path)() == snapshot
    assert FileDegradedAuthorizationSource(authorization_path)() is None

    _write_json(authorization_path, authorization.model_dump(mode="json"))
    assert FileDegradedAuthorizationSource(authorization_path)() == authorization

    with pytest.raises(FileNotFoundError):
        FileDegradedSnapshotSource(tmp_path / "missing-snapshot.json")()


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"\xef\xbb\xbf{}", "BOM is forbidden"),
        (b"\xff", "not strict UTF-8 JSON"),
        (b"{", "not strict UTF-8 JSON"),
        (b'{"lease": 1, "lease": 2}', "duplicate degraded configuration key"),
        (b'{"lease": NaN}', "forbidden degraded configuration constant"),
    ],
)
def test_file_sources_reject_ambiguous_json(
    tmp_path: Path,
    raw: bytes,
    message: str,
) -> None:
    path = tmp_path / "authorization.json"
    path.write_bytes(raw)
    path.chmod(0o600)

    with pytest.raises(ValueError, match=message):
        FileDegradedAuthorizationSource(path)()


def test_file_sources_enforce_type_ownership_mode_and_size(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot_path = tmp_path / "snapshot.json"
    _write_json(snapshot_path, snapshot.model_dump(mode="json"), mode=0o644)
    with pytest.raises(ValueError, match="mode must be 0600"):
        FileDegradedSnapshotSource(snapshot_path)()

    authorization_path = tmp_path / "authorization.json"
    authorization_path.write_text("{}", encoding="utf-8")
    authorization_path.chmod(0o666)
    with pytest.raises(ValueError, match="group/other writable"):
        FileDegradedAuthorizationSource(authorization_path)()

    directory_path = tmp_path / "configuration-directory"
    directory_path.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        FileDegradedAuthorizationSource(directory_path)()

    original_path = tmp_path / "original.json"
    linked_path = tmp_path / "linked.json"
    original_path.write_text("{}", encoding="utf-8")
    original_path.chmod(0o600)
    os.link(original_path, linked_path)
    with pytest.raises(ValueError, match="ownership is not trusted"):
        FileDegradedAuthorizationSource(linked_path)()

    empty_path = tmp_path / "empty.json"
    empty_path.touch(mode=0o600)
    with pytest.raises(ValueError, match="outside the size limit"):
        FileDegradedAuthorizationSource(empty_path)()

    oversized_path = tmp_path / "oversized.json"
    oversized_path.write_bytes(b"x" * (MAX_DEGRADED_CONFIGURATION_BYTES + 1))
    oversized_path.chmod(0o600)
    with pytest.raises(ValueError, match="outside the size limit"):
        FileDegradedAuthorizationSource(oversized_path)()


def test_file_source_rejects_content_changed_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "authorization.json"
    path.write_text("{}", encoding="utf-8")
    path.chmod(0o600)
    original_fstat = os.fstat

    class _ChangedStat:
        def __init__(self, descriptor: int) -> None:
            actual = original_fstat(descriptor)
            self.st_mode = actual.st_mode
            self.st_nlink = actual.st_nlink
            self.st_uid = actual.st_uid
            self.st_size = actual.st_size + 1

    monkeypatch.setattr(os, "fstat", _ChangedStat)
    with pytest.raises(ValueError, match="changed while it was read"):
        FileDegradedAuthorizationSource(path)()


def test_file_components_operate_without_optional_open_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(private_key, snapshot)
    authorization_path = tmp_path / "authorization.json"
    _write_json(authorization_path, authorization.model_dump(mode="json"))
    state_parent = tmp_path / "state-parent"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)

    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(os, "O_DIRECTORY", raising=False)
    monkeypatch.delattr(os, "O_CLOEXEC", raising=False)

    assert FileDegradedAuthorizationSource(authorization_path)() == authorization
    store = FileDegradedOperationStateStore(
        state_parent / "state.json",
        authority_id=AUTHORITY_ID,
    )
    assert store.update(lambda state: state) == DegradedOperationState.initial(AUTHORITY_ID)


def test_in_memory_store_rejects_invalid_transitions() -> None:
    store = InMemoryDegradedOperationStateStore(AUTHORITY_ID)

    with pytest.raises(TypeError, match="invalid value"):
        store.update(lambda _state: object())  # type: ignore[arg-type,return-value]
    with pytest.raises(ValueError, match="changed the authority"):
        store.update(lambda _state: DegradedOperationState.initial("other-authority"))


def test_file_state_store_rejects_unsafe_paths_and_lock_files(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute file path"):
        FileDegradedOperationStateStore(Path("state.json"), authority_id=AUTHORITY_ID)

    public_parent = tmp_path / "public-parent"
    public_parent.mkdir(mode=0o755)
    public_parent.chmod(0o755)
    with pytest.raises(ValueError, match="owned privately"):
        FileDegradedOperationStateStore(
            public_parent / "state.json",
            authority_id=AUTHORITY_ID,
        ).read()

    private_parent = tmp_path / "private-parent"
    private_parent.mkdir(mode=0o700)
    private_parent.chmod(0o700)
    lock_path = private_parent / ".state.json.lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o644)
    with pytest.raises(ValueError, match="lock is not a trusted private file"):
        FileDegradedOperationStateStore(
            private_parent / "state.json",
            authority_id=AUTHORITY_ID,
        ).read()

    target_parent = tmp_path / "target-parent"
    target_parent.mkdir(mode=0o700)
    target_parent.chmod(0o700)
    symlink_parent = tmp_path / "symlink-parent"
    symlink_parent.symlink_to(target_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink directory"):
        FileDegradedOperationStateStore(
            symlink_parent / "state.json",
            authority_id=AUTHORITY_ID,
        ).read()


def test_file_state_store_rejects_parent_changed_during_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_parent = tmp_path / "state-parent"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)
    store = FileDegradedOperationStateStore(
        state_parent / "state.json",
        authority_id=AUTHORITY_ID,
    )
    original_fstat = os.fstat

    def changed_parent(descriptor: int) -> SimpleNamespace:
        actual = original_fstat(descriptor)
        return SimpleNamespace(st_dev=actual.st_dev, st_ino=actual.st_ino + 1)

    monkeypatch.setattr(os, "fstat", changed_parent)
    with pytest.raises(ValueError, match="parent changed during open"):
        store.read()


def test_file_state_store_rejects_invalid_persisted_state(tmp_path: Path) -> None:
    state_parent = tmp_path / "state-parent"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)
    state_path = state_parent / "state.json"
    store = FileDegradedOperationStateStore(state_path, authority_id=AUTHORITY_ID)

    state_path.touch(mode=0o600)
    with pytest.raises(ValueError, match="outside the size limit"):
        store.read()

    _write_json(
        state_path,
        DegradedOperationState.initial("other-authority").model_dump(mode="json"),
    )
    with pytest.raises(ValueError, match="belongs to a different authority"):
        store.read()


def test_file_state_store_can_require_initialized_state(tmp_path: Path) -> None:
    state_parent = tmp_path / "state-parent"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)
    store = FileDegradedOperationStateStore(
        state_parent / "state.json",
        authority_id=AUTHORITY_ID,
        require_existing=True,
    )

    with pytest.raises(ValueError, match="degraded state is unavailable"):
        store.read()


def test_file_state_store_rejects_read_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_parent = tmp_path / "state-parent"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)
    state_path = state_parent / "state.json"
    _write_json(
        state_path,
        DegradedOperationState.initial(AUTHORITY_ID).model_dump(mode="json"),
    )
    store = FileDegradedOperationStateStore(state_path, authority_id=AUTHORITY_ID)
    original_read = os.read

    def short_read(descriptor: int, count: int) -> bytes:
        return original_read(descriptor, count)[:-1]

    monkeypatch.setattr(os, "read", short_read)
    with pytest.raises(ValueError, match="changed while it was read"):
        store.read()


def test_file_state_store_rejects_invalid_transition_results(tmp_path: Path) -> None:
    state_parent = tmp_path / "state-parent"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)
    store = FileDegradedOperationStateStore(
        state_parent / "state.json",
        authority_id=AUTHORITY_ID,
    )

    with pytest.raises(TypeError, match="invalid value"):
        store.update(lambda _state: object())  # type: ignore[arg-type,return-value]
    with pytest.raises(ValueError, match="changed the authority"):
        store.update(lambda _state: DegradedOperationState.initial("other-authority"))


def test_file_state_store_cleans_temporary_file_after_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_parent = tmp_path / "state-parent"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)
    store = FileDegradedOperationStateStore(
        state_parent / "state.json",
        authority_id=AUTHORITY_ID,
    )
    monkeypatch.setattr(os, "write", lambda _descriptor, _raw: 0)

    with pytest.raises(OSError, match="made no progress"):
        store.update(lambda state: state)
    assert not list(state_parent.glob("*.tmp"))


def test_file_state_store_handles_temporary_file_disappearing_during_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_parent = tmp_path / "state-parent"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)
    store = FileDegradedOperationStateStore(
        state_parent / "state.json",
        authority_id=AUTHORITY_ID,
    )

    def remove_temporary_file(_descriptor: int, _raw: bytes) -> int:
        temporary_files = list(state_parent.glob("*.tmp"))
        assert len(temporary_files) == 1
        temporary_files[0].unlink()
        return 0

    monkeypatch.setattr(os, "write", remove_temporary_file)
    with pytest.raises(OSError, match="made no progress"):
        store.update(lambda state: state)
    assert not list(state_parent.glob("*.tmp"))


def test_file_state_store_rejects_serialized_state_over_configured_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_parent = tmp_path / "state-parent"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)
    store = FileDegradedOperationStateStore(
        state_parent / "state.json",
        authority_id=AUTHORITY_ID,
    )
    monkeypatch.setattr(m5_degraded, "MAX_DEGRADED_CONFIGURATION_BYTES", 1)

    with pytest.raises(ValueError, match="state exceeds the size limit"):
        store.update(lambda state: state)


@pytest.mark.parametrize("already_removed", [False, True])
def test_file_state_store_cleans_temporary_file_after_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    already_removed: bool,
) -> None:
    state_parent = tmp_path / f"state-parent-{already_removed}"
    state_parent.mkdir(mode=0o700)
    state_parent.chmod(0o700)
    store = FileDegradedOperationStateStore(
        state_parent / "state.json",
        authority_id=AUTHORITY_ID,
    )
    original_unlink = os.unlink

    def fail_replace(
        source: str,
        _destination: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
    ) -> None:
        assert src_dir_fd == dst_dir_fd
        if already_removed:
            original_unlink(source, dir_fd=src_dir_fd)
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        store.update(lambda state: state)
    assert not list(state_parent.glob("*.tmp"))


@pytest.mark.parametrize(
    ("authority_id", "snapshot_age", "lifetime", "message"),
    [
        (" authority", timedelta(seconds=5), timedelta(minutes=5), "authority ID"),
        (AUTHORITY_ID, timedelta(seconds=-1), timedelta(minutes=5), "snapshot age"),
        (AUTHORITY_ID, timedelta(seconds=5), timedelta(0), "lifetime"),
    ],
)
def test_gate_rejects_unsafe_configuration(
    authority_id: str,
    snapshot_age: timedelta,
    lifetime: timedelta,
    message: str,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match=message):
        DegradedOperationGate(
            authority_id=authority_id,
            authority_public_key=private_key.public_key(),
            snapshot_source=_snapshot,
            authorization_source=lambda: None,
            maximum_snapshot_age=snapshot_age,
            maximum_authorization_lifetime=lifetime,
        )


@pytest.mark.parametrize(
    ("snapshot_source", "reason"),
    [
        (_raise_source_error, "degraded_snapshot_unavailable"),
        (lambda: object(), "degraded_snapshot_invalid"),
    ],
)
def test_gate_fails_safe_for_unavailable_or_invalid_snapshot_source(
    proposal: ActionProposal,
    snapshot_source: Callable[[], Any],
    reason: str,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    gate = DegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=private_key.public_key(),
        snapshot_source=snapshot_source,
        authorization_source=lambda: None,
    )

    result = gate.evaluate(proposal, now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert result.reasons == (reason,)


@pytest.mark.parametrize("authorization_source", [_raise_source_error, lambda: object()])
def test_gate_fails_safe_for_unavailable_or_invalid_authorization_source(
    proposal: ActionProposal,
    authorization_source: Callable[[], Any],
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    gate = DegradedOperationGate(
        authority_id=AUTHORITY_ID,
        authority_public_key=private_key.public_key(),
        snapshot_source=lambda: snapshot,
        authorization_source=authorization_source,
    )

    result = gate.evaluate(proposal, now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_authorization_source_unavailable" in result.reasons
    assert "degraded_mode_authorization_missing" in result.reasons


@pytest.mark.parametrize(
    "store",
    [
        _ScriptedStateStore(
            DegradedOperationState.initial(AUTHORITY_ID),
            read_error=True,
        ),
        _ScriptedStateStore(object()),
        _ScriptedStateStore(DegradedOperationState.initial("other-authority")),
    ],
)
def test_gate_fails_safe_for_unavailable_or_invalid_operation_state(
    proposal: ActionProposal,
    store: _ScriptedStateStore,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    result = _gate(private_key, snapshot, None, state_store=store).evaluate(
        proposal,
        now=NOW,
    )

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert result.reasons[0] in {
        "degraded_operation_state_unavailable",
        "degraded_operation_state_invalid",
    }


@pytest.mark.parametrize(
    ("captured_at", "reason"),
    [
        (NOW + timedelta(seconds=1), "degraded_snapshot_from_future"),
        (NOW - timedelta(seconds=6), "degraded_snapshot_stale"),
    ],
)
def test_gate_rejects_nonfresh_runtime_snapshots(
    proposal: ActionProposal,
    captured_at: datetime,
    reason: str,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT, captured_at=captured_at)

    result = _gate(private_key, snapshot, None).evaluate(proposal, now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert reason in result.reasons


def test_gate_rejects_authority_lifetime_and_role_scope_mismatches(
    proposal: ActionProposal,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(
        private_key,
        snapshot,
        authority_id="other-degraded-authority",
        affected_roles=frozenset({DegradedRole.EVIDENCE, DegradedRole.MANAGEMENT}),
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
    )

    result = _gate(private_key, snapshot, authorization).evaluate(proposal, now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_authority_mismatch" in result.reasons
    assert "degraded_authorization_lifetime_exceeded" in result.reasons
    assert "degraded_role_scope_mismatch" in result.reasons


@pytest.mark.parametrize("mode", ["authority-race", "revocation-race", "write-failure"])
def test_gate_fails_safe_when_persistent_state_changes_during_lease_acceptance(
    proposal: ActionProposal,
    mode: str,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(private_key, snapshot)
    initial = DegradedOperationState.initial(AUTHORITY_ID)
    if mode == "authority-race":
        store = _ScriptedStateStore(
            initial,
            update_state=DegradedOperationState.initial("other-authority"),
        )
        expected_reason = "degraded_operation_state_unavailable"
    elif mode == "revocation-race":
        store = _ScriptedStateStore(
            initial,
            update_state=DegradedOperationState(
                authority_id=AUTHORITY_ID,
                highest_authorization_sequence=0,
                highest_reversal_sequence=0,
                revoked_authorization_sha256=(authorization.digest,),
            ),
        )
        expected_reason = "degraded_authorization_revoked"
    else:
        store = _ScriptedStateStore(initial, update_error=True)
        expected_reason = "degraded_operation_state_unavailable"

    result = _gate(
        private_key,
        snapshot,
        authorization,
        state_store=store,
    ).evaluate(proposal, now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert expected_reason in result.reasons


def test_mission_preserving_lease_holds_every_unapproved_scope_dimension(
    proposal: ActionProposal,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(
        private_key,
        snapshot,
        allowed_mission_ids=frozenset({"different-mission"}),
        allowed_operations=frozenset({Operation.RESTORE_ASSET}),
        maximum_risk_score=50.0,
    )

    result = _gate(private_key, snapshot, authorization).evaluate(proposal, now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.HOLD_STATE
    assert "degraded_mission_out_of_scope" in result.reasons
    assert "degraded_operation_out_of_scope" in result.reasons
    assert "degraded_risk_out_of_scope" in result.reasons


def test_reversal_rejects_cross_bound_material_and_future_issue_time() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(private_key, snapshot)
    unsigned_authorization = authorization.model_copy(update={"signature": ""})
    reversal = _reversal(
        private_key,
        authorization,
        authority_id="other-degraded-authority",
        authorization_id="different-authorization-coverage-0001",
        authorization_sha256="f" * 64,
        recovery_checkpoint_id="different-recovery-checkpoint-0001",
        issued_at=NOW + timedelta(seconds=1),
    )

    result = _gate(private_key, snapshot, authorization).apply_reversal(
        reversal,
        unsigned_authorization,
        now=NOW,
    )

    assert not result.applied
    assert {
        "degraded_reversal_authority_mismatch",
        "degraded_reversal_authorization_invalid",
        "degraded_reversal_authorization_id_mismatch",
        "degraded_reversal_authorization_digest_mismatch",
        "degraded_reversal_checkpoint_mismatch",
        "degraded_reversal_from_future",
    }.issubset(result.reasons)


def test_reversal_rejects_stale_direction() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(private_key, snapshot)
    reversal = _reversal(
        private_key,
        authorization,
        issued_at=NOW - timedelta(minutes=6),
    )

    result = _gate(private_key, snapshot, authorization).apply_reversal(
        reversal,
        authorization,
        now=NOW,
    )

    assert not result.applied
    assert "degraded_reversal_stale" in result.reasons


def test_reversal_fails_safe_when_state_authority_changes_during_update() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(private_key, snapshot)
    store = _ScriptedStateStore(
        DegradedOperationState.initial(AUTHORITY_ID),
        update_state=DegradedOperationState.initial("other-authority"),
    )

    result = _gate(
        private_key,
        snapshot,
        authorization,
        state_store=store,
    ).apply_reversal(_reversal(private_key, authorization), authorization, now=NOW)

    assert not result.applied
    assert result.reasons == ("degraded_reversal_state_unavailable",)


def test_reversal_refuses_to_exceed_durable_replay_capacity() -> None:
    private_key = Ed25519PrivateKey.generate()
    snapshot = _snapshot(role=DegradedRole.MANAGEMENT)
    authorization = _authorization(private_key, snapshot)
    full_nonce_history = tuple(f"{index:064x}" for index in range(MAX_DEGRADED_STATE_ENTRIES))
    capacity_state = DegradedOperationState(
        authority_id=AUTHORITY_ID,
        highest_authorization_sequence=0,
        highest_reversal_sequence=0,
        accepted_reversal_nonce_sha256=full_nonce_history,
    )
    store = _ScriptedStateStore(capacity_state)

    result = _gate(
        private_key,
        snapshot,
        authorization,
        state_store=store,
    ).apply_reversal(_reversal(private_key, authorization), authorization, now=NOW)

    assert not result.applied
    assert result.reasons == ("degraded_reversal_state_capacity_exceeded",)
