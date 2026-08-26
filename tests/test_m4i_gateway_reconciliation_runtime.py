from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from test_m4g_runtime import RuntimeArtifacts
from test_m4g_runtime import artifacts as runtime_artifacts_fixture
from test_m4i_coordination_transport import (
    PortHarness,
    _execute,
    _port_harness,
)
from test_m4i_models import (
    AGENT_ACTOR_ID,
    AGENT_SUBJECT,
    GATEWAY_SUBJECT,
    NOW,
    M4iArtifacts,
    _issue_credential,
)
from test_m4i_models import artifacts as m4i_artifacts_fixture
from test_m4i_ot_coordination_runtime import (
    _harness as _ot_harness,
)
from test_m4i_ot_coordination_runtime import (
    _prepare_request as _ot_prepare_request,
)
from test_m4i_ot_coordination_runtime import (
    _query_request as _ot_query_request,
)

from aegis_ot.coordination_journal import DurableGatewayCoordinationJournal
from aegis_ot.coordination_models import (
    CapabilityOutcomePending,
    CapabilityOutcomeResolution,
    CoordinationState,
    EffectDisposition,
    SignedEffectPrepareRequest,
    WorkloadAuthenticatedEffectReconciliation,
)
from aegis_ot.factory import LocalLab, build_local_lab
from aegis_ot.physical_models import proposal_digest
from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    SegmentedCapabilityDispatch,
    WorkloadAuthenticatedCapabilityAction,
)
from aegis_ot.segmented_capability_runtime import (
    CapabilityAdmissionRejected,
    CapabilityGatewayRuntime,
    create_gateway_app,
)
from aegis_ot.segmented_capability_transport import ConsequentialTransportOutcomeUnknown
from aegis_ot.workload_identity import WorkloadRole, WorkloadSigner

_M4I_ARTIFACT_FACTORY = cast(
    Callable[[Path], M4iArtifacts],
    cast(Any, m4i_artifacts_fixture).__wrapped__,
)
_RUNTIME_ARTIFACT_FACTORY = cast(
    Callable[[], RuntimeArtifacts],
    runtime_artifacts_fixture.__wrapped__,
)


@pytest.fixture
def m4i_artifacts(tmp_path: Path) -> M4iArtifacts:
    return _M4I_ARTIFACT_FACTORY(tmp_path)


@pytest.fixture(scope="module")
def runtime_artifacts() -> RuntimeArtifacts:
    return _RUNTIME_ARTIFACT_FACTORY()


class ForbiddenDependency:
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls = 0

    def _called(self) -> Any:
        self.calls += 1
        raise AssertionError(f"reconciliation called forbidden dependency {self.name}")

    def evaluate(self, *_: Any, **__: Any) -> Any:
        return self._called()

    def translate(self, *_: Any, **__: Any) -> Any:
        return self._called()

    def simulate_candidate(self, *_: Any, **__: Any) -> Any:
        return self._called()

    def issue(self, *_: Any, **__: Any) -> Any:
        return self._called()

    def capture_pre(self, *_: Any, **__: Any) -> Any:
        return self._called()

    def capture_post(self, *_: Any, **__: Any) -> Any:
        return self._called()


class ForbiddenController:
    def __init__(self, plc: object) -> None:
        self.plc = plc
        self.calls = 0
        self.translator = ForbiddenDependency("translator")
        self.simulator = ForbiddenDependency("simulator")
        self.permit_issuer = ForbiddenDependency("permit issuer")

    def execute(self, *_: Any, **__: Any) -> Any:
        self.calls += 1
        raise AssertionError("reconciliation entered the controller")


@dataclass(frozen=True)
class GatewayHarness:
    runtime: CapabilityGatewayRuntime
    authorization: LocalLab
    controller: ForbiddenController
    observer: ForbiddenDependency
    policy: ForbiddenDependency

    def assert_reconciliation_only(self) -> None:
        assert self.controller.calls == 0
        assert self.observer.calls == 0
        assert self.policy.calls == 0
        assert self.controller.translator.calls == 0
        assert self.controller.simulator.calls == 0
        assert self.controller.permit_issuer.calls == 0


def _agent_signer(
    artifacts: M4iArtifacts,
    *,
    subject: str = AGENT_SUBJECT,
    actor_id: str = AGENT_ACTOR_ID,
    credential_id: str = "credential-agent-reconciliation-0001",
) -> WorkloadSigner:
    private_key = Ed25519PrivateKey.generate()
    credential = _issue_credential(
        artifacts.authority,
        private_key,
        credential_id=credential_id,
        subject=subject,
        role=WorkloadRole.AGENT,
        actor_id=actor_id,
        audience=GATEWAY_CAPABILITY_AUDIENCE,
    )
    return WorkloadSigner(credential, private_key)


def _reconciliation(
    artifacts: M4iArtifacts,
    signer: WorkloadSigner,
    *,
    nonce: str,
    issued_at: Any,
    action: Any | None = None,
) -> WorkloadAuthenticatedEffectReconciliation:
    request = action or artifacts.dispatch.request
    return WorkloadAuthenticatedEffectReconciliation.issue(
        request=request,
        signer=signer,
        request_nonce=nonce,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=30),
    )


def _gateway_harness(
    port_harness: PortHarness,
    artifacts: M4iArtifacts,
    *,
    agent_subject: str | None = AGENT_SUBJECT,
) -> GatewayHarness:
    authorization = build_local_lab(NOW)
    policy = ForbiddenDependency("policy")
    authorization.gateway.policy = cast(Any, policy)
    observer = ForbiddenDependency("observer")
    controller = ForbiddenController(port_harness.port)
    runtime = CapabilityGatewayRuntime(
        authorization=authorization,
        controller=cast(Any, controller),
        observer=cast(Any, observer),
        discovery=cast(Any, object()),
        gateway_key_id=artifacts.gateway_signer.credential.credential.key_id,
        agent_workload_verifier=(
            artifacts.verifier if agent_subject is not None else None
        ),
        agent_workload_subject=agent_subject,
        coordination_required=True,
        coordination_journal=port_harness.journal,
        clock=port_harness.exchange.clock,
    )
    return GatewayHarness(runtime, authorization, controller, observer, policy)


def _post_reconciliation(
    runtime: CapabilityGatewayRuntime,
    request: WorkloadAuthenticatedEffectReconciliation,
) -> Any:
    return TestClient(create_gateway_app(lambda: runtime)).post(
        "/v1/capability/effects/reconcile",
        content=request.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


def test_lost_commit_reconciles_once_records_exact_evidence_and_reopens(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
) -> None:
    port_harness = _port_harness(
        tmp_path,
        m4i_artifacts,
        lose_commit_response=True,
    )
    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(port_harness, m4i_artifacts)
    unknown_record = port_harness.journal.records()[0]
    assert unknown_record.state is CoordinationState.DISPATCH_ARMED
    retained_uncertainty_transition = unknown_record.transitions[-1]
    assert port_harness.exchange.paths.count("/v1/effects/commit") == 1

    port_harness.exchange.lose_commit_response = False
    gateway = _gateway_harness(port_harness, m4i_artifacts)
    signer = _agent_signer(m4i_artifacts)
    proof = _reconciliation(
        m4i_artifacts,
        signer,
        nonce="agent-reconciliation-request-nonce-0001",
        issued_at=port_harness.exchange.clock(),
    )

    response = _post_reconciliation(gateway.runtime, proof)

    assert response.status_code == 200, response.text
    resolution = CapabilityOutcomeResolution.model_validate_json(response.content)
    assert resolution.disposition is EffectDisposition.APPLIED
    assert resolution.prior_state is CoordinationState.DISPATCH_ARMED
    assert port_harness.exchange.paths.count("/v1/effects/prepare") == 1
    assert port_harness.exchange.paths.count("/v1/effects/commit") == 1
    assert port_harness.exchange.paths.count("/v1/effects/query") == 1
    final_record = port_harness.journal.records()[0]
    assert final_record.state is CoordinationState.APPLIED
    assert retained_uncertainty_transition in final_record.transitions
    assert final_record.latest_evidence_sha256 == resolution.outcome.digest
    gateway.assert_reconciliation_only()

    event = gateway.authorization.gateway.evidence.records[-1]
    assert event.payload == {
        "event_type": "capability_effect_reconciliation",
        "entrypoint": "agent-to-segmented-gateway",
        "proof_sha256": proof.digest,
        "action_request_sha256": proof.request.digest,
        "effect_sha256": resolution.effect.digest,
        "query_request_sha256": resolution.query.digest,
        "outcome_sha256": resolution.outcome.digest,
        "reconciliation_evidence_sha256": resolution.digest,
        "journal_evidence_sha256": resolution.outcome.digest,
        "prior_state": CoordinationState.DISPATCH_ARMED.value,
        "state_before_request": CoordinationState.DISPATCH_ARMED.value,
        "final_state": CoordinationState.APPLIED.value,
        "disposition": EffectDisposition.APPLIED.value,
        "commit_retry_count": 0,
        "post_observation_status": "not_attempted",
        **m4i_artifacts.verifier.verify_credential_with_receipt(
            signer.credential,
            expected_role=WorkloadRole.AGENT,
            expected_audience=GATEWAY_CAPABILITY_AUDIENCE,
            expected_subject=AGENT_SUBJECT,
            expected_actor_id=AGENT_ACTOR_ID,
            now=proof.issued_at,
        ).evidence_fields(),
    }

    original_response = response.content
    journal_path = port_harness.journal.path
    reopened_at = port_harness.exchange.clock.value + timedelta(minutes=1)
    port_harness.journal.close()
    reopened = DurableGatewayCoordinationJournal(
        journal_path,
        owner_subject=GATEWAY_SUBJECT,
    )
    reopened_directory = tmp_path / "reopened"
    reopened_directory.mkdir(mode=0o700)
    restarted_port = _port_harness(
        reopened_directory,
        m4i_artifacts,
        journal=reopened,
    )
    restarted_port.exchange.clock.value = reopened_at
    restarted_gateway = _gateway_harness(restarted_port, m4i_artifacts)
    restarted_proof = _reconciliation(
        m4i_artifacts,
        signer,
        nonce="agent-reconciliation-restart-nonce-0002",
        issued_at=reopened_at,
    )
    try:
        repeated = _post_reconciliation(restarted_gateway.runtime, restarted_proof)
        assert repeated.status_code == 200, repeated.text
        assert repeated.content == original_response
        assert restarted_port.exchange.paths == []
        restarted_gateway.assert_reconciliation_only()
    finally:
        reopened.close()


def test_unknown_query_returns_signed_pending_with_no_commit_retry(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
) -> None:
    port_harness = _port_harness(
        tmp_path,
        m4i_artifacts,
        commit_disposition=EffectDisposition.UNKNOWN_EFFECT,
        lose_commit_response=True,
    )
    try:
        with pytest.raises(ConsequentialTransportOutcomeUnknown):
            _execute(port_harness, m4i_artifacts)
        gateway = _gateway_harness(port_harness, m4i_artifacts)
        proof = _reconciliation(
            m4i_artifacts,
            _agent_signer(m4i_artifacts),
            nonce="agent-reconciliation-pending-nonce-0001",
            issued_at=port_harness.exchange.clock(),
        )

        response = _post_reconciliation(gateway.runtime, proof)

        assert response.status_code == 202, response.text
        pending = CapabilityOutcomePending.model_validate_json(response.content)
        assert pending.disposition is EffectDisposition.UNKNOWN_EFFECT
        assert pending.prior_state is CoordinationState.DISPATCH_ARMED
        assert port_harness.exchange.paths.count("/v1/effects/commit") == 1
        assert port_harness.exchange.paths.count("/v1/effects/query") == 1
        payload = gateway.authorization.gateway.evidence.records[-1].payload
        assert payload["commit_retry_count"] == 0
        assert payload["post_observation_status"] == "not_attempted"
        assert payload["query_request_sha256"] == pending.query.digest
        assert payload["outcome_sha256"] == pending.outcome.digest
        gateway.assert_reconciliation_only()
    finally:
        port_harness.journal.close()


def test_commit_terminal_without_query_evidence_is_a_conflict_with_zero_http(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
) -> None:
    port_harness = _port_harness(tmp_path, m4i_artifacts)
    try:
        assert _execute(port_harness, m4i_artifacts) == m4i_artifacts.acknowledgment
        gateway = _gateway_harness(port_harness, m4i_artifacts)
        proof = _reconciliation(
            m4i_artifacts,
            _agent_signer(m4i_artifacts),
            nonce="agent-reconciliation-no-query-nonce-0001",
            issued_at=port_harness.exchange.clock(),
        )
        paths_before = tuple(port_harness.exchange.paths)

        response = _post_reconciliation(gateway.runtime, proof)

        assert response.status_code == 409
        assert response.json()["reason"] == "effect_not_query_resolved"
        assert tuple(port_harness.exchange.paths) == paths_before
        assert gateway.authorization.gateway.evidence.records == ()
        gateway.assert_reconciliation_only()
    finally:
        port_harness.journal.close()


def test_reconciliation_api_is_strict_and_maps_identity_lookup_and_precommit(
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
) -> None:
    port_harness = _port_harness(tmp_path, m4i_artifacts)
    port_harness.port._prepare(m4i_artifacts.dispatch)
    gateway = _gateway_harness(port_harness, m4i_artifacts)
    signer = _agent_signer(m4i_artifacts)
    issued_at = port_harness.exchange.clock()
    proof = _reconciliation(
        m4i_artifacts,
        signer,
        nonce="agent-reconciliation-errors-nonce-0001",
        issued_at=issued_at,
    )
    client = TestClient(create_gateway_app(lambda: gateway.runtime))
    paths_before = tuple(port_harness.exchange.paths)

    extra = proof.model_dump(mode="json")
    extra["unexpected"] = True
    strict = client.post(
        "/v1/capability/effects/reconcile",
        json=extra,
    )
    assert strict.status_code == 400

    wrong_signer = _agent_signer(
        m4i_artifacts,
        subject="spiffe://aegis-ot.test/workload/different-agent",
        credential_id="credential-agent-wrong-subject-0002",
    )
    wrong_identity = _post_reconciliation(
        gateway.runtime,
        _reconciliation(
            m4i_artifacts,
            wrong_signer,
            nonce="agent-reconciliation-wrong-subject-0002",
            issued_at=issued_at,
        ),
    )
    assert wrong_identity.status_code == 403
    assert wrong_identity.json()["reason"] == "agent_reconciliation_identity_rejected"

    valid_other_signature = _reconciliation(
        m4i_artifacts,
        wrong_signer,
        nonce="agent-reconciliation-other-proof-0003",
        issued_at=issued_at,
    ).signature
    forged = proof.model_copy(update={"signature": valid_other_signature})
    proof_rejected = _post_reconciliation(gateway.runtime, forged)
    assert proof_rejected.status_code == 403
    assert proof_rejected.json()["reason"] == "agent_reconciliation_proof_rejected"

    retained_action = m4i_artifacts.dispatch.request
    conflicting_action = retained_action.model_copy(
        update={"request_id": "m4i-reconciliation-collision-request-0002"}
    )
    collision = _post_reconciliation(
        gateway.runtime,
        _reconciliation(
            m4i_artifacts,
            signer,
            nonce="agent-reconciliation-collision-nonce-0004",
            issued_at=issued_at,
            action=conflicting_action,
        ),
    )
    assert collision.status_code == 409
    assert collision.json()["reason"] == "agent_reconciliation_action_conflict"

    missing_proposal = retained_action.proposal.model_copy(
        update={
            "actor_id": "agent:unrecorded-operator",
            "nonce": "unrecorded-action-proposal-nonce-0002",
        }
    )
    missing_action = retained_action.model_copy(
        update={
            "request_id": "m4i-reconciliation-missing-request-0003",
            "proposal": missing_proposal,
        }
    )
    missing = _post_reconciliation(
        gateway.runtime,
        _reconciliation(
            m4i_artifacts,
            _agent_signer(
                m4i_artifacts,
                actor_id="agent:unrecorded-operator",
                credential_id="credential-agent-unrecorded-0003",
            ),
            nonce="agent-reconciliation-missing-nonce-0005",
            issued_at=issued_at,
            action=missing_action,
        ),
    )
    assert missing.status_code == 404
    assert missing.json()["reason"] == "coordinated_action_not_found"

    unconfigured = _gateway_harness(
        port_harness,
        m4i_artifacts,
        agent_subject=None,
    )
    missing_identity = _post_reconciliation(unconfigured.runtime, proof)
    assert missing_identity.status_code == 403
    assert missing_identity.json()["reason"] == (
        "agent_reconciliation_identity_rejected"
    )

    fresh_proposal = retained_action.proposal.model_copy(
        update={
            "actor_id": "agent:fresh-operator",
            "nonce": "fresh-gateway-action-proposal-nonce-0002",
        }
    )
    fresh_action = retained_action.model_copy(
        update={
            "request_id": "m4i-fresh-gateway-action-request-0004",
            "proposal": fresh_proposal,
        }
    )
    fresh_action_proof = WorkloadAuthenticatedCapabilityAction.issue(
        request=fresh_action,
        signer=_agent_signer(
            m4i_artifacts,
            actor_id="agent:fresh-operator",
            credential_id="credential-agent-fresh-operator-0004",
        ),
        request_nonce=fresh_proposal.nonce,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=30),
    )
    with pytest.raises(
        CapabilityAdmissionRejected,
        match="effect_reconciliation_required",
    ):
        gateway.runtime.execute(fresh_action_proof)
    assert gateway.controller.calls == 0

    precommit = _post_reconciliation(gateway.runtime, proof)
    assert precommit.status_code == 409
    assert precommit.json()["reason"] == "effect_was_not_committed"
    assert tuple(port_harness.exchange.paths) == paths_before
    assert port_harness.journal.records()[0].state is CoordinationState.NOT_DISPATCHED
    gateway.assert_reconciliation_only()

    port_harness.journal.close()
    unavailable = _post_reconciliation(gateway.runtime, proof)
    assert unavailable.status_code == 503
    assert unavailable.json()["reason"] == "gateway_coordination_journal_unavailable"


def test_disabled_reconciliation_is_a_conflict(
    m4i_artifacts: M4iArtifacts,
) -> None:
    authorization = build_local_lab(NOW)
    controller = ForbiddenController(object())
    runtime = CapabilityGatewayRuntime(
        authorization=authorization,
        controller=cast(Any, controller),
        observer=cast(Any, ForbiddenDependency("observer")),
        discovery=cast(Any, object()),
        gateway_key_id="disabled-gateway-key",
    )
    proof = _reconciliation(
        m4i_artifacts,
        _agent_signer(m4i_artifacts),
        nonce="agent-reconciliation-disabled-nonce-0001",
        issued_at=NOW,
    )

    response = _post_reconciliation(runtime, proof)

    assert response.status_code == 409
    assert response.json()["reason"] == "effect_coordination_is_disabled"
    assert controller.calls == 0


def test_ot_prepare_blocks_a_second_effect_but_query_remains_available(
    tmp_path: Path,
    runtime_artifacts: RuntimeArtifacts,
) -> None:
    harness = _ot_harness(tmp_path, runtime_artifacts)
    first_prepare = _ot_prepare_request(harness)
    harness.runtime.prepare_effect(first_prepare)

    second_proposal = harness.dispatch.request.proposal.model_copy(
        update={"nonce": "m4i-second-effect-action-nonce-0002"}
    )
    second_action = harness.dispatch.request.model_copy(
        update={
            "request_id": "m4i-second-effect-action-request-0002",
            "proposal": second_proposal,
        }
    )
    second_base_permit = harness.dispatch.permit.base_permit.model_copy(
        update={
            "proposal_digest": proposal_digest(second_proposal),
            "signature": "",
        }
    ).signed(runtime_artifacts.permit_private)
    second_permit = harness.dispatch.permit.model_copy(
        update={
            "base_permit": second_base_permit,
            "request_digest": second_action.digest,
            "signature": "",
        }
    ).signed(runtime_artifacts.permit_private)
    second_dispatch = SegmentedCapabilityDispatch(
        request=second_action,
        pre_observation=harness.dispatch.pre_observation,
        decision=harness.dispatch.decision,
        assessment=harness.dispatch.assessment,
        permit=second_permit,
    )
    second_issued_at = harness.clock.value - timedelta(milliseconds=100)
    second_prepare = SignedEffectPrepareRequest.issue(
        dispatch=second_dispatch,
        signer=harness.identities.gateway_signer,
        request_nonce="m4i-second-effect-prepare-nonce-0002",
        issued_at=second_issued_at,
        expires_at=second_issued_at + timedelta(seconds=20),
    )
    assert second_prepare.effect != first_prepare.effect

    try:
        with pytest.raises(
            CapabilityAdmissionRejected,
            match="effect_reconciliation_required",
        ):
            harness.runtime.prepare_effect(second_prepare)
        assert len(harness.journal.records()) == 1

        outcome = harness.runtime.query_effect(_ot_query_request(harness, sequence=91))
        assert outcome.disposition is EffectDisposition.NOT_DISPATCHED
        assert harness.journal.get(first_prepare.effect).state is (
            CoordinationState.NOT_DISPATCHED
        )

        receipt = harness.runtime.prepare_effect(second_prepare)
        assert receipt.effect == second_prepare.effect
        assert len(harness.journal.records()) == 2
        assert harness.device.calls == 0
    finally:
        harness.journal.close()
