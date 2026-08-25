from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis_ot.m4f_transport_probe as probe
from aegis_ot.lab import nominal_state
from aegis_ot.models import ExecutionResult, SystemState
from aegis_ot.segmented_runtime import (
    SignedSegmentedExecutionRequest,
    SignedSegmentedExecutionResponse,
    _canonical_bytes,
    _sha256,
)


class _Response:
    def __init__(self, payload: bytes, *, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        del args

    def read(self, _size: int) -> bytes:
        return self.payload


@pytest.fixture
def probe_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Ed25519PrivateKey, Ed25519PrivateKey]:
    gateway_private = Ed25519PrivateKey.generate()
    ot_private = Ed25519PrivateKey.generate()
    gateway_private_path = tmp_path / "gateway.private"
    ot_public_path = tmp_path / "ot.public"
    gateway_private_path.write_bytes(
        gateway_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    ot_public_path.write_bytes(
        ot_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    monkeypatch.setenv("AEGIS_GATEWAY_KEY_ID", "gateway-test-key")
    monkeypatch.setenv("AEGIS_GATEWAY_PRIVATE_KEY_FILE", str(gateway_private_path))
    monkeypatch.setenv("AEGIS_OT_KEY_ID", "ot-test-key")
    monkeypatch.setenv("AEGIS_OT_PUBLIC_KEY_FILE", str(ot_public_path))
    monkeypatch.setattr(probe.socket, "gethostname", lambda: "m4f-unit-probe")
    return gateway_private, ot_private


def _response(
    request: SignedSegmentedExecutionRequest,
    signer: Ed25519PrivateKey,
    *,
    executed: bool,
    resulting_state: SystemState | None = None,
    reason: str | None = None,
    proposal_id: str | None = None,
    decision_id: str | None = None,
    request_sha256: str | None = None,
) -> SignedSegmentedExecutionResponse:
    execution = ExecutionResult(
        proposal_id=proposal_id or request.request.proposal.proposal_id,
        decision_id=decision_id or request.request.decision.decision_id,
        executed=executed,
        acknowledged_at=datetime.now(UTC),
        resulting_state=resulting_state,
        reason=reason,
    )
    return SignedSegmentedExecutionResponse(
        request_sha256=request_sha256 or _sha256(request),
        execution=execution,
        ot_key_id="ot-test-key",
        signed_at=datetime.now(UTC),
    ).signed(signer)


def _script_states(
    monkeypatch: pytest.MonkeyPatch,
    states: list[SystemState],
) -> None:
    state_iterator = iter(states)
    monkeypatch.setattr(probe, "_state", lambda: next(state_iterator))


def _script_health(
    monkeypatch: pytest.MonkeyPatch,
    health_values: list[dict[str, Any]],
) -> None:
    health_iterator = iter(health_values)

    def get_health(url: str) -> dict[str, Any]:
        assert url == probe.HEALTH
        return next(health_iterator)

    monkeypatch.setattr(probe, "_await_get", get_health)


def _exercise_full(
    monkeypatch: pytest.MonkeyPatch,
    gateway_private: Ed25519PrivateKey,
    ot_private: Ed25519PrivateKey,
    *,
    valid_response_proposal_id: str | None = None,
) -> dict[str, Any]:
    state_before = nominal_state(version=7)
    state_after_valid = nominal_state(version=8)
    state_after_replay = state_after_valid.model_copy(update={"observed_at": datetime.now(UTC)})
    state_after_resigned = state_after_valid.model_copy(update={"observed_at": datetime.now(UTC)})
    _script_states(
        monkeypatch,
        [state_before, state_after_valid, state_after_replay, state_after_resigned],
    )
    _script_health(
        monkeypatch,
        [
            {
                "replay_mode": "durable",
                "replay_reservations": 11,
                "boot_epoch": "boot-a",
                "pid": 17,
            },
            {
                "replay_mode": "durable",
                "replay_reservations": 13,
                "boot_epoch": "boot-a",
                "pid": 17,
            },
        ],
    )
    exchanges: list[dict[str, Any]] = []

    def exchange(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        exchanges.append(payload)
        call = len(exchanges)
        if call == 1:
            assert "signature" not in payload
            return 403, {"detail": "signed gateway request required"}
        request = SignedSegmentedExecutionRequest.model_validate(payload)
        if call == 2:
            assert not request.verify(gateway_private.public_key())
            return 403, {"detail": "gateway signature rejected"}
        if call == 3:
            assert request.verify(gateway_private.public_key())
            response = _response(
                request,
                ot_private,
                executed=True,
                resulting_state=state_after_valid,
                proposal_id=valid_response_proposal_id,
            )
            return 200, response.model_dump(mode="json")
        if call == 4:
            assert payload == exchanges[2]
            return 409, {"detail": "transport request replayed"}
        if call == 5:
            assert not request.verify(gateway_private.public_key())
            return 403, {"detail": "gateway signature rejected"}
        if call == 6:
            original = SignedSegmentedExecutionRequest.model_validate(exchanges[2])
            assert request.verify(gateway_private.public_key())
            assert request.transport_nonce != original.transport_nonce
            assert request.request == original.request
            response = _response(
                request,
                ot_private,
                executed=False,
                reason="time_of_check_time_of_use_state_change",
            )
            return 200, response.model_dump(mode="json")
        pytest.fail(f"unexpected exchange call {call}")

    monkeypatch.setattr(probe, "_exchange", exchange)
    output = probe._full()
    assert len(exchanges) == 6
    return output


def test_full_probe_accepts_only_bound_signed_transport_results(
    monkeypatch: pytest.MonkeyPatch,
    probe_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    gateway_private, ot_private = probe_keys

    output = _exercise_full(monkeypatch, gateway_private, ot_private)

    assert output["accepted"] is True
    valid = SignedSegmentedExecutionRequest.model_validate(
        output["valid_key_holder"]["signed_request"]
    )
    response = SignedSegmentedExecutionResponse.model_validate(
        output["valid_key_holder"]["signed_response"]
    )
    assert valid.verify(gateway_private.public_key())
    assert response.verify(ot_private.public_key())
    assert response.request_sha256 == output["valid_key_holder"]["request_sha256"]
    assert response.request_sha256 == _sha256(valid)
    assert response.execution.proposal_id == valid.request.proposal.proposal_id
    assert response.execution.decision_id == valid.request.decision.decision_id
    assert output["exact_same_boot_replay"]["http_status"] == 409


def test_full_probe_rejects_ot_signed_result_bound_to_another_proposal(
    monkeypatch: pytest.MonkeyPatch,
    probe_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    gateway_private, ot_private = probe_keys

    output = _exercise_full(
        monkeypatch,
        gateway_private,
        ot_private,
        valid_response_proposal_id="another-proposal",
    )

    response = SignedSegmentedExecutionResponse.model_validate(
        output["valid_key_holder"]["signed_response"]
    )
    assert response.verify(ot_private.public_key())
    assert output["valid_key_holder"]["response_signature_verified"] is False
    assert output["accepted"] is False


def _exercise_prepare_restart(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    gateway_private: Ed25519PrivateKey,
    response_signer: Ed25519PrivateKey,
) -> dict[str, Any]:
    state_before = nominal_state(version=20)
    state_after = nominal_state(version=21)
    _script_states(monkeypatch, [state_before, state_after])
    _script_health(
        monkeypatch,
        [
            {"replay_mode": "durable", "replay_reservations": 3},
            {"replay_mode": "durable", "replay_reservations": 4},
        ],
    )

    def exchange(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        request = SignedSegmentedExecutionRequest.model_validate(payload)
        assert request.verify(gateway_private.public_key())
        assert request.request.decision.state_version == state_before.version
        response = _response(
            request,
            response_signer,
            executed=True,
            resulting_state=state_after,
        )
        return 200, response.model_dump(mode="json")

    monkeypatch.setattr(probe, "_exchange", exchange)
    return probe._prepare_restart(path)


def test_prepare_restart_persists_the_exact_accepted_signed_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    gateway_private, ot_private = probe_keys
    path = tmp_path / "exact-request.json"

    output = _exercise_prepare_restart(
        monkeypatch,
        path,
        gateway_private,
        ot_private,
    )

    retained = probe._load_exact_request(path)
    reported = SignedSegmentedExecutionRequest.model_validate(
        output["prepared_request"]["signed_request"]
    )
    response = SignedSegmentedExecutionResponse.model_validate(
        output["prepared_request"]["signed_response"]
    )
    assert output["accepted"] is True
    assert path.read_bytes() == _canonical_bytes(reported)
    assert retained == reported
    assert retained.verify(gateway_private.public_key())
    assert response.verify(ot_private.public_key())
    assert response.request_sha256 == _sha256(retained)


def test_prepare_restart_rejects_response_from_untrusted_ot_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    gateway_private, ot_private = probe_keys
    untrusted_ot_private = Ed25519PrivateKey.generate()

    output = _exercise_prepare_restart(
        monkeypatch,
        tmp_path / "untrusted-response-request.json",
        gateway_private,
        untrusted_ot_private,
    )

    response = SignedSegmentedExecutionResponse.model_validate(
        output["prepared_request"]["signed_response"]
    )
    assert response.verify(untrusted_ot_private.public_key())
    assert not response.verify(ot_private.public_key())
    assert output["prepared_request"]["response_signature_verified"] is False
    assert output["accepted"] is False


def _exercise_restart(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    gateway_private: Ed25519PrivateKey,
    response_signer: Ed25519PrivateKey,
) -> tuple[dict[str, Any], SignedSegmentedExecutionRequest]:
    prepared_from = nominal_state(version=30)
    exact = probe._signed_request(prepared_from, ttl_seconds=60)
    probe._write_exact_request(path, exact)
    state_before = nominal_state(version=31)
    state_after_replay = state_before.model_copy(update={"observed_at": datetime.now(UTC)})
    state_after_fresh = nominal_state(version=32)
    _script_states(monkeypatch, [state_before, state_after_replay, state_after_fresh])
    _script_health(
        monkeypatch,
        [
            {"replay_mode": "durable", "replay_reservations": 8},
            {"replay_mode": "durable", "replay_reservations": 8},
            {"replay_mode": "durable", "replay_reservations": 9},
        ],
    )
    calls = 0

    def exchange(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal calls
        calls += 1
        request = SignedSegmentedExecutionRequest.model_validate(payload)
        if calls == 1:
            assert _sha256(request) == _sha256(exact)
            assert payload == exact.model_dump(mode="json")
            return 409, {"detail": "transport request replayed"}
        if calls == 2:
            assert request.verify(gateway_private.public_key())
            assert request.transport_nonce != exact.transport_nonce
            assert request.request.decision.state_version == state_after_replay.version
            response = _response(
                request,
                response_signer,
                executed=True,
                resulting_state=state_after_fresh,
            )
            return 200, response.model_dump(mode="json")
        pytest.fail(f"unexpected exchange call {calls}")

    monkeypatch.setattr(probe, "_exchange", exchange)
    output = probe._restart(path)
    assert calls == 2
    return output, exact


def test_restart_probe_rejects_exact_envelope_and_accepts_fresh_liveness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    gateway_private, ot_private = probe_keys

    output, exact = _exercise_restart(
        monkeypatch,
        tmp_path / "restart-request.json",
        gateway_private,
        ot_private,
    )

    replay = output["exact_restart_replay"]
    fresh = output["fresh_after_restart"]
    fresh_request = SignedSegmentedExecutionRequest.model_validate(fresh["signed_request"])
    fresh_response = SignedSegmentedExecutionResponse.model_validate(fresh["signed_response"])
    assert output["accepted"] is True
    assert replay["http_status"] == 409
    assert replay["request_sha256"] == _sha256(exact)
    assert replay["signed_request"] == exact.model_dump(mode="json")
    assert replay["response_within_original_validity_window"] is True
    assert fresh_request.verify(gateway_private.public_key())
    assert fresh_response.verify(ot_private.public_key())
    assert fresh_response.request_sha256 == _sha256(fresh_request)
    assert fresh_response.execution.proposal_id == fresh_request.request.proposal.proposal_id
    assert fresh_response.execution.decision_id == fresh_request.request.decision.decision_id


def test_restart_probe_rejects_fresh_result_from_untrusted_ot_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    gateway_private, ot_private = probe_keys
    untrusted_ot_private = Ed25519PrivateKey.generate()

    output, _ = _exercise_restart(
        monkeypatch,
        tmp_path / "restart-untrusted-response.json",
        gateway_private,
        untrusted_ot_private,
    )

    response = SignedSegmentedExecutionResponse.model_validate(
        output["fresh_after_restart"]["signed_response"]
    )
    assert response.verify(untrusted_ot_private.public_key())
    assert not response.verify(ot_private.public_key())
    assert output["fresh_after_restart"]["response_signature_verified"] is False
    assert output["accepted"] is False


def test_restart_probe_fails_closed_when_exact_request_is_missing(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="exact signed-request probe file is unavailable"):
        probe._restart(tmp_path / "missing-exact-request.json")


def _exercise_ledger_fault(
    monkeypatch: pytest.MonkeyPatch,
    gateway_private: Ed25519PrivateKey,
) -> dict[str, Any]:
    state_before = nominal_state(version=41)
    state_after = state_before.model_copy(update={"observed_at": datetime.now(UTC)})
    _script_states(monkeypatch, [state_before, state_after])

    def exchange(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        request = SignedSegmentedExecutionRequest.model_validate(payload)
        assert request.verify(gateway_private.public_key())
        assert request.request.decision.state_version == state_before.version
        return 503, {"detail": "transport replay ledger unavailable"}

    monkeypatch.setattr(probe, "_await_exchange", exchange)
    return probe._ledger_fault()


def test_ledger_fault_probe_accepts_only_valid_request_with_no_state_effect(
    monkeypatch: pytest.MonkeyPatch,
    probe_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    gateway_private, _ = probe_keys

    output = _exercise_ledger_fault(monkeypatch, gateway_private)

    request = SignedSegmentedExecutionRequest.model_validate(output["request"]["signed_request"])
    assert output["accepted"] is True
    assert output["request"]["http_status"] == 503
    assert output["request"]["request_sha256"] == _sha256(request)
    assert output["request"]["request_signature_verified"] is True
    assert request.verify(gateway_private.public_key())
    assert output["state_before"]["version"] == output["state_after"]["version"]


def test_ledger_fault_probe_rejects_unverifiable_gateway_identity(
    monkeypatch: pytest.MonkeyPatch,
    probe_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    gateway_private, _ = probe_keys
    untrusted_gateway_private = Ed25519PrivateKey.generate()
    calls = 0
    original_loader: Callable[[str], Ed25519PrivateKey] = probe._load_private_key

    def load_private_key(path: str) -> Ed25519PrivateKey:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_loader(path)
        return untrusted_gateway_private

    monkeypatch.setattr(probe, "_load_private_key", load_private_key)

    output = _exercise_ledger_fault(monkeypatch, gateway_private)

    request = SignedSegmentedExecutionRequest.model_validate(output["request"]["signed_request"])
    assert request.verify(gateway_private.public_key())
    assert output["request"]["request_signature_verified"] is False
    assert output["accepted"] is False


def test_probe_http_helpers_bound_and_validate_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        probe,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b'{"ok":true}', status=201),
    )
    assert probe._exchange({"x": 1}) == (201, {"ok": True})
    assert probe._get("http://service/health") == {"ok": True}

    http_error = HTTPError(
        probe.TARGET,
        409,
        "conflict",
        hdrs=None,
        fp=BytesIO(b'{"detail":"transport request replayed"}'),
    )

    def conflict(*_args: object, **_kwargs: object) -> _Response:
        raise http_error

    monkeypatch.setattr(probe, "urlopen", conflict)
    assert probe._exchange({}) == (
        409,
        {"detail": "transport request replayed"},
    )

    monkeypatch.setattr(
        probe,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"x" * 1_048_577),
    )
    with pytest.raises(RuntimeError, match="size bound"):
        probe._exchange({})
    with pytest.raises(RuntimeError, match="size bound"):
        probe._get("http://service/large")

    monkeypatch.setattr(
        probe,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"[]"),
    )
    with pytest.raises(RuntimeError, match="not an object"):
        probe._exchange({})
    with pytest.raises(RuntimeError, match="not an object"):
        probe._get("http://service/list")

    def unavailable(*_args: object, **_kwargs: object) -> _Response:
        raise URLError("offline")

    monkeypatch.setattr(probe, "urlopen", unavailable)
    with pytest.raises(RuntimeError, match="dependency unavailable"):
        probe._get("http://service/offline")


def test_probe_readiness_helpers_retry_and_fail_boundedly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exchange_attempts = 0

    def exchange(_payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal exchange_attempts
        exchange_attempts += 1
        if exchange_attempts == 1:
            raise URLError("starting")
        return 200, {"ok": True}

    get_attempts = 0

    def get(_url: str) -> dict[str, Any]:
        nonlocal get_attempts
        get_attempts += 1
        if get_attempts == 1:
            raise RuntimeError("starting")
        return {"ok": True}

    monkeypatch.setattr(probe, "_exchange", exchange)
    monkeypatch.setattr(probe, "_get", get)
    monkeypatch.setattr(probe.time, "sleep", lambda _seconds: None)
    assert probe._await_exchange({}) == (200, {"ok": True})
    assert probe._await_get("http://service/health") == {"ok": True}
    assert exchange_attempts == 2
    assert get_attempts == 2

    monkeypatch.setattr(
        probe,
        "_exchange",
        lambda _payload: (_ for _ in ()).throw(URLError("offline")),
    )
    monkeypatch.setattr(
        probe,
        "_get",
        lambda _url: (_ for _ in ()).throw(RuntimeError("offline")),
    )
    with pytest.raises(RuntimeError, match="did not become reachable"):
        probe._await_exchange({})
    with pytest.raises(RuntimeError, match="did not become ready"):
        probe._await_get("http://service/health")


def test_exact_request_file_rejects_write_stall_mode_and_noncanonical_encoding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey],
) -> None:
    del probe_keys
    request = probe._signed_request(nominal_state(version=1))
    stalled = tmp_path / "stalled.json"
    monkeypatch.setattr(probe.os, "write", lambda _descriptor, _material: 0)
    with pytest.raises(OSError, match="made no progress"):
        probe._write_exact_request(stalled, request)

    wrong_mode = tmp_path / "wrong-mode.json"
    wrong_mode.write_bytes(_canonical_bytes(request))
    wrong_mode.chmod(0o644)
    with pytest.raises(RuntimeError, match="mode is not 0600"):
        probe._load_exact_request(wrong_mode)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(
        json.dumps(request.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    noncanonical.chmod(0o600)
    with pytest.raises(RuntimeError, match="not canonical"):
        probe._load_exact_request(noncanonical)

    symlink = tmp_path / "request-link.json"
    symlink.symlink_to(noncanonical)
    with pytest.raises(RuntimeError, match="unavailable"):
        probe._load_exact_request(symlink)


@pytest.mark.parametrize(
    ("mode", "function_name"),
    [
        ("full", "_full"),
        ("prepare_restart", "_prepare_restart"),
        ("restart_replay", "_restart"),
        ("ledger_fault", "_ledger_fault"),
    ],
)
def test_probe_main_dispatches_each_supported_mode(
    mode: str,
    function_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AEGIS_TRANSPORT_PROBE_MODE", mode)
    monkeypatch.setenv("AEGIS_TRANSPORT_PROBE_FILE", str(tmp_path / "exact.json"))
    monkeypatch.setattr(
        probe,
        function_name,
        lambda *_args: {"accepted": True, "mode": mode},
    )

    probe.main()

    assert json.loads(capsys.readouterr().out) == {"accepted": True, "mode": mode}


def test_probe_main_rejects_failed_and_unsupported_modes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AEGIS_TRANSPORT_PROBE_MODE", "full")
    monkeypatch.setattr(probe, "_full", lambda: {"accepted": False})
    with pytest.raises(SystemExit) as rejected:
        probe.main()
    assert rejected.value.code == 1
    assert json.loads(capsys.readouterr().out) == {"accepted": False}

    monkeypatch.setenv("AEGIS_TRANSPORT_PROBE_MODE", "unsupported")
    with pytest.raises(RuntimeError, match="unsupported M4f transport probe mode"):
        probe.main()
