from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_m4g_runtime import RuntimeArtifacts
from test_m4g_runtime import artifacts as runtime_artifacts_fixture
from test_m4i_models import (
    AGENT_SUBJECT,
    NOW,
    M4iArtifacts,
    _commit,
    _issue_credential,
    _prepare,
    _receipt,
)
from test_m4i_models import artifacts as m4i_artifacts_fixture

from aegis_ot.coordination_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    SignedEffectQueryRequest,
    WorkloadAuthenticatedEffectReconciliation,
)
from aegis_ot.segmented_capability_runtime import (
    CapabilityAdmissionRejected,
    CapabilityRuntimeUnavailable,
    EffectCommitIndeterminate,
    create_gateway_app,
    create_ot_app,
)
from aegis_ot.workload_identity import WorkloadRole, WorkloadSigner


@pytest.fixture
def artifacts(tmp_path: Path) -> M4iArtifacts:
    factory = cast(Callable[[Path], M4iArtifacts], cast(Any, m4i_artifacts_fixture).__wrapped__)
    return factory(tmp_path)


@pytest.fixture(scope="module")
def runtime_artifacts() -> RuntimeArtifacts:
    factory = cast(Callable[[], RuntimeArtifacts], cast(Any, runtime_artifacts_fixture).__wrapped__)
    return factory()


def _requests(artifacts: M4iArtifacts) -> dict[str, Any]:
    prepare = _prepare(artifacts)
    receipt = _receipt(artifacts, prepare)
    commit = _commit(artifacts, receipt)
    query = SignedEffectQueryRequest.issue(
        effect=prepare.effect,
        signer=artifacts.gateway_signer,
        request_nonce="runtime-http-query-nonce-0001",
        issued_at=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(seconds=32),
    )
    agent_private = Ed25519PrivateKey.generate()
    agent_signer = WorkloadSigner(
        _issue_credential(
            artifacts.authority,
            agent_private,
            credential_id="credential-runtime-http-agent-0001",
            subject=AGENT_SUBJECT,
            role=WorkloadRole.AGENT,
            audience=GATEWAY_CAPABILITY_AUDIENCE,
        ),
        agent_private,
    )
    reconciliation = WorkloadAuthenticatedEffectReconciliation.issue(
        request=artifacts.dispatch.request,
        signer=agent_signer,
        request_nonce="runtime-http-reconciliation-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    return {
        "prepare": prepare,
        "commit": commit,
        "query": query,
        "reconcile": reconciliation,
    }


class _FailingRuntime:
    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def health(self) -> None:
        raise self.failure

    def prepare_effect(self, _request: Any) -> None:
        raise self.failure

    def commit_effect(self, _request: Any) -> None:
        raise self.failure

    def query_effect(self, _request: Any) -> None:
        raise self.failure

    def reconcile_effect(self, _request: Any) -> None:
        raise self.failure


def _failure(status: str, reason: str) -> dict[str, str]:
    return {
        "schema_version": "m4g-transport-failure-v1",
        "status": status,
        "reason": reason,
    }


def _raising_provider(failure: Exception) -> Callable[[], Any]:
    def provider() -> Any:
        raise failure

    return provider


@pytest.mark.parametrize(
    ("app_factory", "path"),
    (
        (create_ot_app, "/v1/effects/prepare"),
        (create_ot_app, "/v1/effects/commit"),
        (create_ot_app, "/v1/effects/query"),
        (create_gateway_app, "/v1/capability/effects/reconcile"),
    ),
)
def test_coordination_routes_reject_non_strict_json_before_runtime(
    app_factory: Callable[[Callable[[], Any]], FastAPI],
    path: str,
) -> None:
    invoked = False

    def provider() -> Any:
        nonlocal invoked
        invoked = True
        return object()

    response = TestClient(app_factory(provider)).post(
        path,
        content=b'{"duplicate":1,"duplicate":2}',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json() == _failure("rejected", "duplicate_json_key")
    assert not invoked


@pytest.mark.parametrize(
    ("path", "failure", "reason"),
    (
        (
            "/v1/capability/execute",
            CapabilityRuntimeUnavailable("effect_coordination_recovery_unavailable"),
            "effect_coordination_recovery_unavailable",
        ),
        (
            "/v1/capability/execute",
            CapabilityRuntimeUnavailable("sensitive execute setup"),
            "ot_runtime_unavailable",
        ),
        (
            "/v1/capability/execute",
            RuntimeError("sensitive execute setup"),
            "ot_runtime_unavailable",
        ),
        (
            "/v1/effects/prepare",
            CapabilityRuntimeUnavailable("effect_coordination_recovery_unavailable"),
            "effect_coordination_recovery_unavailable",
        ),
        (
            "/v1/effects/prepare",
            CapabilityRuntimeUnavailable("sensitive prepare setup"),
            "ot_runtime_unavailable",
        ),
        ("/v1/effects/prepare", RuntimeError("sensitive prepare setup"), "ot_runtime_unavailable"),
        (
            "/v1/effects/commit",
            CapabilityRuntimeUnavailable("effect_coordination_recovery_unavailable"),
            "effect_coordination_recovery_unavailable",
        ),
        (
            "/v1/effects/commit",
            CapabilityRuntimeUnavailable("sensitive commit setup"),
            "ot_runtime_unavailable",
        ),
        ("/v1/effects/commit", RuntimeError("sensitive commit setup"), "ot_runtime_unavailable"),
        (
            "/v1/effects/query",
            CapabilityRuntimeUnavailable("effect_coordination_recovery_unavailable"),
            "effect_coordination_recovery_unavailable",
        ),
        (
            "/v1/effects/query",
            CapabilityRuntimeUnavailable("sensitive query setup"),
            "ot_runtime_unavailable",
        ),
        ("/v1/effects/query", RuntimeError("sensitive query setup"), "ot_runtime_unavailable"),
    ),
)
def test_ot_provider_failures_are_bounded_before_protocol_execution(
    artifacts: M4iArtifacts,
    runtime_artifacts: RuntimeArtifacts,
    path: str,
    failure: Exception,
    reason: str,
) -> None:
    requests = _requests(artifacts)
    payload = (
        runtime_artifacts.envelope
        if path == "/v1/capability/execute"
        else requests[path.rsplit("/", 1)[-1]]
    )

    response = TestClient(create_ot_app(_raising_provider(failure))).post(
        path,
        content=payload.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 503
    assert response.json() == _failure("error", reason)
    assert "sensitive" not in response.text


def test_ot_health_sanitizes_non_recovery_unavailability() -> None:
    response = TestClient(
        create_ot_app(_raising_provider(CapabilityRuntimeUnavailable("sensitive health")))
    ).get("/health")

    assert response.status_code == 503
    assert response.json() == _failure("error", "ot_runtime_unavailable")


@pytest.mark.parametrize(
    ("route", "failure", "status", "reason"),
    (
        (
            "prepare",
            CapabilityAdmissionRejected("effect_reconciliation_required"),
            409,
            "effect_reconciliation_required",
        ),
        ("prepare", CapabilityAdmissionRejected("identity_rejected"), 403, "identity_rejected"),
        (
            "prepare",
            CapabilityRuntimeUnavailable("effect_coordination_recovery_unavailable"),
            503,
            "effect_coordination_recovery_unavailable",
        ),
        (
            "prepare",
            CapabilityRuntimeUnavailable("sensitive prepare dependency"),
            503,
            "effect_prepare_unavailable",
        ),
        ("prepare", RuntimeError("sensitive prepare failure"), 503, "effect_prepare_unavailable"),
        ("commit", EffectCommitIndeterminate("query_required"), 409, "query_required"),
        (
            "commit",
            CapabilityAdmissionRejected("effect_reconciliation_required"),
            409,
            "effect_reconciliation_required",
        ),
        ("commit", CapabilityAdmissionRejected("identity_rejected"), 403, "identity_rejected"),
        (
            "commit",
            CapabilityRuntimeUnavailable("effect_coordination_recovery_unavailable"),
            503,
            "effect_coordination_recovery_unavailable",
        ),
        (
            "commit",
            CapabilityRuntimeUnavailable("sensitive commit dependency"),
            503,
            "effect_commit_unavailable",
        ),
        ("commit", RuntimeError("sensitive commit failure"), 503, "effect_commit_unavailable"),
        ("query", CapabilityAdmissionRejected("identity_rejected"), 403, "identity_rejected"),
        (
            "query",
            CapabilityRuntimeUnavailable("effect_coordination_recovery_unavailable"),
            503,
            "effect_coordination_recovery_unavailable",
        ),
        (
            "query",
            CapabilityRuntimeUnavailable("sensitive query dependency"),
            503,
            "effect_query_unavailable",
        ),
        ("query", RuntimeError("sensitive query failure"), 503, "effect_query_unavailable"),
    ),
)
def test_ot_coordination_failures_have_stable_consequential_dispositions(
    artifacts: M4iArtifacts,
    route: str,
    failure: Exception,
    status: int,
    reason: str,
) -> None:
    request = _requests(artifacts)[route]
    response = TestClient(create_ot_app(lambda: _FailingRuntime(failure))).post(
        f"/v1/effects/{route}",
        content=request.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == status
    disposition = "rejected" if status in {403, 409} and reason != "query_required" else "error"
    assert response.json() == _failure(disposition, reason)
    assert "sensitive" not in response.text


@pytest.mark.parametrize(
    ("path", "payload_key", "failure", "reason"),
    (
        (
            "/v1/capability/actions",
            "action",
            RuntimeError("sensitive gateway provider"),
            "gateway_runtime_unavailable",
        ),
        (
            "/v1/capability/effects/reconcile",
            "reconcile",
            RuntimeError("sensitive reconciliation provider"),
            "gateway_runtime_unavailable",
        ),
    ),
)
def test_gateway_provider_failures_are_sanitized(
    artifacts: M4iArtifacts,
    path: str,
    payload_key: str,
    failure: Exception,
    reason: str,
) -> None:
    requests = _requests(artifacts)
    payload = artifacts.dispatch.request if payload_key == "action" else requests[payload_key]

    response = TestClient(create_gateway_app(_raising_provider(failure))).post(
        path,
        content=payload.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 503
    assert response.json() == _failure("error", reason)
    assert "sensitive" not in response.text


def test_gateway_reconciliation_unexpected_failure_is_sanitized(
    artifacts: M4iArtifacts,
) -> None:
    request = _requests(artifacts)["reconcile"]
    response = TestClient(
        create_gateway_app(lambda: _FailingRuntime(RuntimeError("sensitive reconciliation")))
    ).post(
        "/v1/capability/effects/reconcile",
        content=request.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 503
    assert response.json() == _failure("error", "effect_reconciliation_unavailable")
    assert "sensitive" not in response.text
