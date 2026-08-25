from __future__ import annotations

import json
from datetime import UTC, datetime
from io import BytesIO
from typing import Any
from urllib.error import HTTPError, URLError

import pytest

import aegis_ot.segmented_probe as probe_entrypoint
import aegis_ot.segmented_runtime as segmented
from aegis_ot.lab import nominal_state
from aegis_ot.models import ActionProposal, Decision, DecisionOutcome, ExecutionResult


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


def test_request_json_enforces_scheme_size_json_root_and_exchange_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        segmented,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b'{"accepted":true}'),
    )
    assert segmented.request_json("POST", "http://service/action", {"x": 1}) == {"accepted": True}

    with pytest.raises(segmented.ServiceExchangeError, match="must use HTTP"):
        segmented.request_json("GET", "file:///etc/passwd")

    monkeypatch.setattr(
        segmented,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"x" * 1_048_577),
    )
    with pytest.raises(segmented.ServiceExchangeError, match="size limit"):
        segmented.request_json("GET", "http://service/large")

    for payload, message in ((b"not-json", "was not JSON"), (b"[]", "not an object")):
        monkeypatch.setattr(
            segmented,
            "urlopen",
            lambda *_args, _payload=payload, **_kwargs: _Response(_payload),
        )
        with pytest.raises(segmented.ServiceExchangeError, match=message):
            segmented.request_json("GET", "http://service/invalid")

    def unavailable(*_args: object, **_kwargs: object) -> _Response:
        raise URLError("offline")

    monkeypatch.setattr(segmented, "urlopen", unavailable)
    with pytest.raises(segmented.ServiceExchangeError, match="exchange failed"):
        segmented.request_json("GET", "http://service/offline")

    http_error = HTTPError(
        "http://service/denied",
        503,
        "unavailable",
        hdrs=None,
        fp=BytesIO(b'{"detail":"down"}'),
    )

    def rejected(*_args: object, **_kwargs: object) -> _Response:
        raise http_error

    monkeypatch.setattr(segmented, "urlopen", rejected)
    with pytest.raises(segmented.ServiceExchangeError, match="exchange failed"):
        segmented.request_json("GET", "http://service/denied")


def test_run_segmented_probe_covers_denial_execution_replay_and_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = nominal_state(observed_at=datetime.now(UTC))
    final = initial.model_copy(
        update={
            "version": initial.version + 1,
            "observed_at": datetime.now(UTC),
            "isolated_assets": frozenset({"feeder-1"}),
        }
    )
    observation_reads = 0
    safe_proposal_id: str | None = None

    def exchange(
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        nonlocal observation_reads, safe_proposal_id
        del method, kwargs
        if url.startswith(("http://observer:", "http://ot-adapter:", "http://simulation:")):
            raise segmented.ServiceExchangeError("segmented")
        if url.endswith("/v1/observation"):
            observation_reads += 1
            state = initial if observation_reads == 1 else final
            return state.model_dump(mode="json")
        assert url.endswith("/v1/actions")
        assert payload is not None
        proposal = ActionProposal.model_validate(payload)
        impact = proposal.parameters["critical_load_impact_pct"]
        if impact == 30.0:
            decision = Decision(
                proposal_id=proposal.proposal_id,
                outcome=DecisionOutcome.DENY,
                reasons=("critical_load_below_limit",),
                policy_version="test",
                safety_version="test",
                state_version=initial.version,
            )
            execution = None
        elif safe_proposal_id is None:
            safe_proposal_id = proposal.proposal_id
            decision = Decision(
                proposal_id=proposal.proposal_id,
                outcome=DecisionOutcome.PERMIT,
                reasons=("all_checks_passed",),
                policy_version="test",
                safety_version="test",
                state_version=initial.version,
            )
            execution = ExecutionResult(
                proposal_id=proposal.proposal_id,
                decision_id=decision.decision_id,
                executed=True,
                acknowledged_at=datetime.now(UTC),
                resulting_state=final,
            )
        else:
            assert proposal.proposal_id == safe_proposal_id
            decision = Decision(
                proposal_id=proposal.proposal_id,
                outcome=DecisionOutcome.DENY,
                reasons=("replayed_nonce",),
                policy_version="test",
                safety_version="test",
                state_version=final.version,
            )
            execution = None
        return segmented.SegmentedActionResult(
            proposal_id=proposal.proposal_id,
            decision=decision,
            execution=execution,
        ).model_dump(mode="json")

    monkeypatch.setattr(segmented, "request_json", exchange)

    result = segmented.run_segmented_probe()

    assert result["accepted"] is True
    assert result["agent_network_direct_reachability"] == {
        "observer": False,
        "ot-adapter": False,
        "simulation": False,
    }
    assert result["safe"]["executed"] is True
    assert result["replay"]["dispatched"] is False


def test_run_segmented_probe_records_an_unexpected_direct_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_probe = segmented.run_segmented_probe
    calls = 0

    def direct_then_stop(*_args: object, **_kwargs: object) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"status": "ok"}
        raise RuntimeError("stop after direct-path branch")

    monkeypatch.setattr(segmented, "request_json", direct_then_stop)
    with pytest.raises(RuntimeError, match="stop"):
        real_probe()


@pytest.mark.parametrize("accepted", [True, False])
def test_segmented_probe_entrypoint_returns_only_on_acceptance(
    accepted: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        probe_entrypoint,
        "run_segmented_probe",
        lambda: {"accepted": accepted, "schema_version": "test"},
    )

    if accepted:
        probe_entrypoint.main()
    else:
        with pytest.raises(SystemExit) as exc:
            probe_entrypoint.main()
        assert exc.value.code == 1

    rendered = json.loads(capsys.readouterr().out)
    assert rendered["accepted"] is accepted
