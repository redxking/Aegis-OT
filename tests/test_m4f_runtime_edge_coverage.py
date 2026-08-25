from __future__ import annotations

import hashlib
import json
import os
import runpy
import stat
import warnings
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from pydantic import ValidationError

import aegis_ot.m4f_replay_init as replay_init
import aegis_ot.segmented_runtime as segmented
from aegis_ot.lab import nominal_state
from aegis_ot.models import ActionProposal, Decision, DecisionOutcome, ExecutionResult, Operation
from aegis_ot.transport_replay import TransportReplayLedgerError


def _proposal(state: segmented.SystemState | None = None) -> ActionProposal:
    observed = state or nominal_state(observed_at=datetime.now(UTC))
    return ActionProposal(
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=observed.version,
        observed_at=observed.observed_at,
        submitted_at=datetime.now(UTC),
        nonce=str(uuid4()),
        confidence=0.9,
        risk_score=60.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


def _permit(proposal: ActionProposal) -> Decision:
    return Decision(
        proposal_id=proposal.proposal_id,
        outcome=DecisionOutcome.PERMIT,
        reasons=("all_checks_passed",),
        policy_version="test-policy",
        safety_version="test-safety",
        state_version=proposal.observed_state_version,
    )


def _execution_request(
    state: segmented.SystemState | None = None,
) -> segmented.SegmentedExecutionRequest:
    proposal = _proposal(state)
    return segmented.SegmentedExecutionRequest(
        proposal=proposal,
        decision=_permit(proposal),
    )


def _signed_request(
    private_key: Ed25519PrivateKey,
    *,
    state: segmented.SystemState | None = None,
) -> segmented.SignedSegmentedExecutionRequest:
    now = datetime.now(UTC)
    return segmented.SignedSegmentedExecutionRequest(
        request=_execution_request(state),
        gateway_key_id="gateway-test-key",
        transport_nonce=str(uuid4()),
        issued_at=now,
        expires_at=now + timedelta(seconds=5),
    ).signed(private_key)


def _execution_result(
    request: segmented.SegmentedExecutionRequest,
    *,
    executed: bool = True,
) -> ExecutionResult:
    resulting_state = None
    if executed:
        resulting_state = nominal_state(observed_at=datetime.now(UTC)).model_copy(
            update={"version": request.decision.state_version + 1}
        )
    return ExecutionResult(
        proposal_id=request.proposal.proposal_id,
        decision_id=request.decision.decision_id,
        executed=executed,
        acknowledged_at=datetime.now(UTC),
        resulting_state=resulting_state,
        reason=None if executed else "controlled_nonexecution",
    )


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _configure_initializer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    public_key: bytes = b"k" * 32,
    runtime_uid: int | None = None,
    runtime_gid: int | None = None,
) -> tuple[Path, Path, Path]:
    ledger_directory = tmp_path / "ledger"
    probe_directory = tmp_path / "probe"
    ledger_directory.mkdir()
    probe_directory.mkdir()
    ledger_path = ledger_directory / "transport-replay.json"
    public_key_path = tmp_path / "gateway.public"
    public_key_path.write_bytes(public_key)
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_LEDGER_FILE", str(ledger_path))
    monkeypatch.setenv("AEGIS_TRANSPORT_PROBE_DIRECTORY", str(probe_directory))
    monkeypatch.setenv("AEGIS_GATEWAY_PUBLIC_KEY_FILE", str(public_key_path))
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-test-key")
    monkeypatch.setenv(
        "AEGIS_RUNTIME_UID",
        str(os.getuid() if runtime_uid is None else runtime_uid),
    )
    monkeypatch.setenv(
        "AEGIS_RUNTIME_GID",
        str(os.getgid() if runtime_gid is None else runtime_gid),
    )
    return ledger_path, probe_directory, public_key_path


@pytest.fixture(autouse=True)
def _reset_segmented_runtime_state() -> Any:
    prior = {
        "gateway_lab": segmented._gateway_lab,
        "gateway_lock": segmented._gateway_lock,
        "durable_ledger": segmented._durable_transport_replay,
        "durable_config": segmented._durable_transport_replay_config,
        "plant": segmented._plant,
        "max_cached": segmented._MAX_CACHED_OBSERVATIONS,
    }
    segmented._gateway_lab = None
    segmented._durable_transport_replay = None
    segmented._durable_transport_replay_config = None
    segmented._observation_cache.clear()
    segmented._ot_transport_nonces.clear()
    yield
    segmented._gateway_lab = prior["gateway_lab"]
    segmented._gateway_lock = prior["gateway_lock"]
    segmented._durable_transport_replay = prior["durable_ledger"]
    segmented._durable_transport_replay_config = prior["durable_config"]
    segmented._plant = prior["plant"]
    segmented._MAX_CACHED_OBSERVATIONS = prior["max_cached"]
    segmented._observation_cache.clear()
    segmented._ot_transport_nonces.clear()


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_initializer_rejects_non_directory_and_symlink_volume_paths(
    tmp_path: Path,
    kind: str,
) -> None:
    candidate = tmp_path / "volume"
    if kind == "file":
        candidate.write_text("not a directory", encoding="utf-8")
    else:
        target = tmp_path / "target"
        target.mkdir()
        candidate.symlink_to(target, target_is_directory=True)

    with pytest.raises(RuntimeError, match="volume path is not a directory"):
        replay_init._prepare_directory(candidate)


def test_initializer_rejects_directory_when_private_mode_cannot_be_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "volume"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    real_chmod = Path.chmod

    def ignore_target_chmod(path: Path, mode: int) -> None:
        if path != directory:
            real_chmod(path, mode)

    monkeypatch.setattr(Path, "chmod", ignore_target_chmod)

    with pytest.raises(RuntimeError, match="mode was not set to 0700"):
        replay_init._prepare_directory(directory)


def test_initializer_rejects_wrong_length_gateway_public_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_initializer(tmp_path, monkeypatch, public_key=b"short")

    with pytest.raises(RuntimeError, match="exactly 32 raw bytes"):
        replay_init.initialize()


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("ledger_owner", "ledger ownership"),
        ("ledger_mode", "ledger mode"),
        ("probe_owner", "probe volume ownership"),
        ("ledger_directory_owner", "replay volume ownership"),
    ],
)
def test_initializer_fails_closed_on_post_provisioning_identity_or_mode_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    message: str,
) -> None:
    target_uid = 42_424
    target_gid = 43_434
    ledger_path, probe_directory, _ = _configure_initializer(
        tmp_path,
        monkeypatch,
        runtime_uid=target_uid,
        runtime_gid=target_gid,
    )
    ledger_directory = ledger_path.parent
    chowned: set[Path] = set()
    real_stat = Path.stat

    def record_chown(path: str | bytes | os.PathLike[str], uid: int, gid: int) -> None:
        assert (uid, gid) == (target_uid, target_gid)
        chowned.add(Path(path))

    def reported_stat(path: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        result = real_stat(path, *args, **kwargs)
        if path not in chowned:
            return result
        values = list(result)
        values[stat.ST_UID] = target_uid
        values[stat.ST_GID] = target_gid
        if failure == "ledger_owner" and path == ledger_path:
            values[stat.ST_UID] = target_uid + 1
        elif failure == "ledger_mode" and path == ledger_path:
            values[stat.ST_MODE] = (values[stat.ST_MODE] & ~0o777) | 0o644
        elif failure == "probe_owner" and path == probe_directory:
            values[stat.ST_GID] = target_gid + 1
        elif failure == "ledger_directory_owner" and path == ledger_directory:
            values[stat.ST_UID] = target_uid + 1
        return os.stat_result(values)

    monkeypatch.setattr(replay_init.os, "chown", record_chown)
    monkeypatch.setattr(Path, "stat", reported_stat)

    with pytest.raises(RuntimeError, match=message):
        replay_init.initialize()


def test_initializer_main_emits_sorted_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = {"schema_version": "m4f-test-v1", "ledger_reservations": 0}
    monkeypatch.setattr(replay_init, "initialize", lambda: expected)

    replay_init.main()

    assert json.loads(capsys.readouterr().out) == expected


def test_initializer_module_entrypoint_provisions_and_reports_volume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ledger_path, _, _ = _configure_initializer(tmp_path, monkeypatch)

    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r".*aegis_ot\.m4f_replay_init.*found in sys\.modules.*",
            category=RuntimeWarning,
        )
        runpy.run_module("aegis_ot.m4f_replay_init", run_name="__main__")

    output = json.loads(capsys.readouterr().out)
    assert output["schema_version"] == "m4f-replay-volume-initialization-v1"
    assert output["ledger_reservations"] == 0
    assert ledger_path.exists()


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "message"),
    [
        (
            datetime(2026, 8, 25, 12, 0),
            datetime(2026, 8, 25, 12, 1),
            "timezone-aware",
        ),
        (
            datetime(2026, 8, 25, 12, 0, tzinfo=UTC),
            datetime(2026, 8, 25, 12, 0, tzinfo=UTC),
            "expiry must follow issuance",
        ),
    ],
)
def test_signed_request_rejects_ambiguous_or_empty_validity_windows(
    issued_at: datetime,
    expires_at: datetime,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        segmented.SignedSegmentedExecutionRequest(
            request=_execution_request(),
            gateway_key_id="gateway-test-key",
            transport_nonce=str(uuid4()),
            issued_at=issued_at,
            expires_at=expires_at,
        )


@pytest.mark.parametrize(
    ("loader_name", "message"),
    [
        ("_load_private_key", "private key file"),
        ("_load_public_key", "public key file"),
    ],
)
def test_ed25519_key_loaders_reject_non_raw_key_material(
    tmp_path: Path,
    loader_name: str,
    message: str,
) -> None:
    path = tmp_path / "invalid.key"
    path.write_bytes(b"x" * 31)

    with pytest.raises(RuntimeError, match=message):
        getattr(segmented, loader_name)(str(path))


def test_gateway_singleton_honors_double_checked_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = SimpleNamespace(name="built")
    raced = SimpleNamespace(name="raced")
    build_calls: list[str] = []
    monkeypatch.setattr(
        segmented,
        "build_gateway_lab",
        lambda url: build_calls.append(url) or built,
    )

    assert segmented._gateway() is built
    assert segmented._gateway() is built
    assert build_calls == ["http://opa:8181"]

    class RaceLock:
        def __enter__(self) -> None:
            segmented._gateway_lab = raced

        def __exit__(self, *args: object) -> None:
            del args

    segmented._gateway_lab = None
    segmented._gateway_lock = RaceLock()  # type: ignore[assignment]
    assert segmented._gateway() is raced
    assert build_calls == ["http://opa:8181"]


def test_observation_cache_evicts_oldest_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(segmented, "_MAX_CACHED_OBSERVATIONS", 2)
    states = [
        nominal_state(observed_at=datetime.now(UTC)).model_copy(update={"version": version})
        for version in (1, 2, 3)
    ]
    for state in states:
        segmented._cache_observation(state)

    assert segmented._resolve_observation(_proposal(states[0])) is None
    assert segmented._resolve_observation(_proposal(states[1])) == states[1]
    assert segmented._resolve_observation(_proposal(states[2])) == states[2]


def test_replay_mode_and_public_key_identity_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_MODE", "unexpected")
    with pytest.raises(TransportReplayLedgerError, match="mode is unsupported"):
        segmented._transport_replay_mode()

    missing = tmp_path / "missing.public"
    with pytest.raises(TransportReplayLedgerError, match="cannot be read"):
        segmented._gateway_public_key_sha256(str(missing))

    malformed = tmp_path / "malformed.public"
    malformed.write_bytes(b"short")
    with pytest.raises(TransportReplayLedgerError, match="exactly 32 raw bytes"):
        segmented._gateway_public_key_sha256(str(malformed))

    valid = tmp_path / "valid.public"
    valid.write_bytes(b"g" * 32)
    assert segmented._gateway_public_key_sha256(str(valid)) == hashlib.sha256(b"g" * 32).hexdigest()


def test_durable_replay_requires_authentication_and_complete_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "false")
    with pytest.raises(TransportReplayLedgerError, match="requires authenticated"):
        segmented._durable_replay_ledger()

    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "true")
    monkeypatch.delenv("AEGIS_TRANSPORT_REPLAY_LEDGER_FILE", raising=False)
    monkeypatch.delenv("AEGIS_GATEWAY_PUBLIC_KEY_FILE", raising=False)
    monkeypatch.delenv("AEGIS_GATEWAY_KEY_ID", raising=False)
    with pytest.raises(TransportReplayLedgerError, match="not fully configured"):
        segmented._durable_replay_ledger()


def test_durable_replay_cache_is_reused_and_rebound_when_identity_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_key_path = tmp_path / "gateway.public"
    public_key_path.write_bytes(b"g" * 32)
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "true")
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_LEDGER_FILE", str(tmp_path / "ledger.json"))
    monkeypatch.setenv("AEGIS_GATEWAY_PUBLIC_KEY_FILE", str(public_key_path))
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-key-a")
    created: list[SimpleNamespace] = []

    def ledger_factory(path: Path, **identity: str) -> SimpleNamespace:
        ledger = SimpleNamespace(path=path, identity=identity)
        created.append(ledger)
        return ledger

    monkeypatch.setattr(segmented, "DurableTransportReplayLedger", ledger_factory)

    first = segmented._durable_replay_ledger()
    assert segmented._durable_replay_ledger() is first
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-key-b")
    second = segmented._durable_replay_ledger()

    assert second is not first
    assert len(created) == 2
    assert created[0].identity["gateway_key_id"] == "gateway-key-a"
    assert created[1].identity["gateway_key_id"] == "gateway-key-b"


def test_memory_replay_reservation_rejects_duplicate_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_MODE", "memory")
    nonce = "memory-transport-nonce-0001"

    assert not segmented._transport_nonce_seen(nonce)
    assert segmented._reserve_transport_nonce(nonce, "a" * 64)
    assert segmented._transport_nonce_seen(nonce)
    assert not segmented._reserve_transport_nonce(nonce, "a" * 64)


def test_health_and_simulation_paths_report_and_mutate_the_surrogate() -> None:
    plant = segmented.MutableSurrogatePlant()
    segmented._plant = plant

    state = segmented.simulation_state()
    result = segmented.simulation_apply(_execution_request(state))

    assert segmented.simulation_health() == {
        "status": "ok",
        "role": "synthetic-simulation",
    }
    assert segmented.observer_health() == {"status": "ok", "role": "observer"}
    assert segmented.gateway_health() == {
        "status": "ok",
        "role": "gateway",
        "mode": "m4d-segmented-surrogate",
    }
    assert result.executed is True
    assert result.resulting_state is not None
    assert segmented.simulation_state().version == state.version + 1


@pytest.mark.parametrize("failure", ["exchange", "invalid_payload"])
def test_observer_translates_simulation_observation_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    if failure == "exchange":

        def exchange(*_args: object, **_kwargs: object) -> dict[str, Any]:
            raise segmented.ServiceExchangeError("offline")

    else:

        def exchange(*_args: object, **_kwargs: object) -> dict[str, Any]:
            return {"not": "a state"}

    monkeypatch.setattr(segmented, "request_json", exchange)

    with pytest.raises(HTTPException) as unavailable:
        segmented.observed_state()
    assert unavailable.value.status_code == 503
    assert unavailable.value.detail == "simulation observation unavailable"


def test_observer_returns_valid_simulation_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = nominal_state(observed_at=datetime.now(UTC))
    monkeypatch.setattr(
        segmented,
        "request_json",
        lambda *_args, **_kwargs: state.model_dump(mode="json"),
    )

    assert segmented.observed_state() == state


def test_memory_mode_ot_health_reports_process_local_replay_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_TRANSPORT_REPLAY_MODE", "memory")
    segmented._ot_transport_nonces.update({"nonce-a", "nonce-b"})

    health = segmented.ot_health()

    assert health["status"] == "ok"
    assert health["replay_mode"] == "memory"
    assert health["replay_reservations"] == 2
    assert health["replay_ledger_sha256"] == "not-durable"
    assert health["boot_epoch"] == segmented._ot_boot_epoch
    assert health["pid"] == os.getpid()


def test_signed_ot_request_is_rejected_when_authenticated_mode_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "false")
    request = _signed_request(Ed25519PrivateKey.generate())
    monkeypatch.setattr(
        segmented,
        "request_json",
        lambda *_args, **_kwargs: pytest.fail("simulation must not be contacted"),
    )

    with pytest.raises(HTTPException) as rejected:
        segmented.ot_execute(request)
    assert rejected.value.status_code == 403
    assert rejected.value.detail == "authenticated transport is disabled"


def test_unsigned_ot_request_returns_bound_simulation_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "false")
    request = _execution_request()
    expected = _execution_result(request)

    def exchange(
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        del kwargs
        assert method == "POST"
        assert url.endswith("/internal/apply")
        assert segmented.SegmentedExecutionRequest.model_validate(payload) == request
        return expected.model_dump(mode="json")

    monkeypatch.setattr(segmented, "request_json", exchange)

    assert segmented.ot_execute(request) == expected


@pytest.mark.parametrize("failure", ["exchange", "invalid_payload"])
def test_gateway_observation_translates_failure_without_caching(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    if failure == "exchange":

        def exchange(*_args: object, **_kwargs: object) -> dict[str, Any]:
            raise segmented.ServiceExchangeError("offline")

    else:

        def exchange(*_args: object, **_kwargs: object) -> dict[str, Any]:
            return {"not": "a state"}

    monkeypatch.setattr(segmented, "request_json", exchange)

    with pytest.raises(HTTPException) as unavailable:
        segmented.gateway_observation()
    assert unavailable.value.status_code == 503
    assert unavailable.value.detail == "trusted observation unavailable"
    assert not segmented._observation_cache


def test_gateway_observation_returns_and_caches_trusted_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = nominal_state(observed_at=datetime.now(UTC))
    monkeypatch.setattr(
        segmented,
        "request_json",
        lambda *_args, **_kwargs: state.model_dump(mode="json"),
    )

    observed = segmented.gateway_observation()

    assert observed == state
    assert segmented._resolve_observation(_proposal(state)) == state


def test_unauthenticated_gateway_action_returns_bound_ot_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "false")
    state = nominal_state(observed_at=datetime.now(UTC))
    proposal = _proposal(state)
    segmented._cache_observation(state)
    gateway = SimpleNamespace(
        gateway=SimpleNamespace(decide=lambda received, _state: _permit(received))
    )
    monkeypatch.setattr(segmented, "_gateway", lambda: gateway)

    def exchange(
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        del method, url, kwargs
        request = segmented.SegmentedExecutionRequest.model_validate(payload)
        return _execution_result(request).model_dump(mode="json")

    monkeypatch.setattr(segmented, "request_json", exchange)

    result = segmented.gateway_action(proposal)

    assert result.proposal_id == proposal.proposal_id
    assert result.decision.outcome is DecisionOutcome.PERMIT
    assert result.execution is not None
    assert result.execution.executed is True


def _configure_authenticated_gateway(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Ed25519PrivateKey, Ed25519PrivateKey]:
    gateway_private = Ed25519PrivateKey.generate()
    ot_private = Ed25519PrivateKey.generate()
    gateway_private_path = tmp_path / "gateway.private"
    ot_public_path = tmp_path / "ot.public"
    gateway_private_path.write_bytes(_raw_private(gateway_private))
    ot_public_path.write_bytes(_raw_public(ot_private))
    monkeypatch.setenv("AEGIS_AUTHENTICATED_MODE", "true")
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-test-key")
    monkeypatch.setenv("AEGIS_GATEWAY_PRIVATE_KEY_FILE", str(gateway_private_path))
    monkeypatch.setenv("AEGIS_OT_KEY_ID", "ot-test-key")
    monkeypatch.setenv("AEGIS_OT_PUBLIC_KEY_FILE", str(ot_public_path))
    return gateway_private, ot_private


@pytest.mark.parametrize("valid_response", [False, True])
def test_authenticated_gateway_verifies_ot_response_before_returning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    valid_response: bool,
) -> None:
    _, ot_private = _configure_authenticated_gateway(tmp_path, monkeypatch)
    state = nominal_state(observed_at=datetime.now(UTC))
    proposal = _proposal(state)
    segmented._cache_observation(state)
    gateway = SimpleNamespace(
        gateway=SimpleNamespace(decide=lambda received, _state: _permit(received))
    )
    monkeypatch.setattr(segmented, "_gateway", lambda: gateway)

    def exchange(
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        del method, url, kwargs
        signed = segmented.SignedSegmentedExecutionRequest.model_validate(payload)
        response = segmented.SignedSegmentedExecutionResponse(
            request_sha256=segmented._sha256(signed),
            execution=_execution_result(signed.request),
            ot_key_id="ot-test-key" if valid_response else "unexpected-ot-key",
            signed_at=datetime.now(UTC),
        ).signed(ot_private)
        return response.model_dump(mode="json")

    monkeypatch.setattr(segmented, "request_json", exchange)

    if not valid_response:
        with pytest.raises(HTTPException) as unavailable:
            segmented.gateway_action(proposal)
        assert unavailable.value.status_code == 503
        assert unavailable.value.detail == "OT execution outcome unavailable"
        return

    result = segmented.gateway_action(proposal)
    assert result.execution is not None
    assert result.execution.proposal_id == proposal.proposal_id
    assert result.execution.decision_id == result.decision.decision_id
