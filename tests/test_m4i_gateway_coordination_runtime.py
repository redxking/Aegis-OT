from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from test_m4g_runtime import (
    GATEWAY_KEY_ID,
    OT_KEY_ID,
    RuntimeArtifacts,
)
from test_m4g_runtime import (
    artifacts as _runtime_artifacts_fixture,
)
from test_m4g_runtime_edges import (
    _configure_runtime_environment,
    _health_bundle,
)
from test_m4i_models import NOW, M4iArtifacts
from test_m4i_models import (
    artifacts as _m4i_artifacts_fixture,
)

import aegis_ot.segmented_capability_runtime as runtime_module
from aegis_ot.coordination_journal import DurableGatewayCoordinationJournal
from aegis_ot.coordination_models import (
    EFFECT_COORDINATOR_AUDIENCE,
    GATEWAY_COORDINATION_AUDIENCE,
    SignedEffectPrepareRequest,
)
from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    OT_CAPABILITY_AUDIENCE,
)
from aegis_ot.segmented_capability_runtime import (
    CapabilityAdmissionRejected,
    CapabilityGatewayRuntime,
    CapabilityRuntimeUnavailable,
    create_gateway_app,
)
from aegis_ot.segmented_capability_transport import (
    RemoteVirtualPlcPort,
    WorkloadRemoteVirtualPlcPort,
)
from aegis_ot.workload_identity import WorkloadRole

GATEWAY_SUBJECT = "spiffe://aegis-ot.test/workload/gateway"
OT_SUBJECT = "spiffe://aegis-ot.test/workload/ot-adapter"
AGENT_SUBJECT = "spiffe://aegis-ot.test/workload/agent"


@pytest.fixture(scope="module")
def artifacts() -> RuntimeArtifacts:
    factory = cast(
        Callable[[], RuntimeArtifacts],
        _runtime_artifacts_fixture.__wrapped__,
    )
    return factory()


@pytest.fixture
def m4i_artifacts(tmp_path: Path) -> M4iArtifacts:
    factory = cast(
        Callable[[Path], M4iArtifacts],
        cast(Any, _m4i_artifacts_fixture).__wrapped__,
    )
    return factory(tmp_path)


class RecordingCoordinatedPort(WorkloadRemoteVirtualPlcPort):
    def __init__(self, base_url: str, **kwargs: Any) -> None:
        self.base_url = base_url
        self.arguments = kwargs
        self.coordination_journal = cast(
            DurableGatewayCoordinationJournal,
            kwargs["coordination_journal"],
        )
        self.preflight_calls = 0
        self.recovery_calls = 0

    def preflight_identity(self) -> None:
        self.preflight_calls += 1

    def reconcile_pending_once(self) -> None:
        self.recovery_calls += 1
        raise AssertionError("builder and health must not initiate recovery")


class ForbiddenActionController:
    def __init__(self, plc: RecordingCoordinatedPort) -> None:
        self.plc = plc
        self.calls = 0
        self.translator_version = "drifted-translator-v2"
        self.target_boot_epoch = "drifted-target-boot-0002"

    def execute(self, _: object) -> object:
        self.calls += 1
        raise AssertionError("retained action crossed the gateway replay guard")


def _seed_gateway_journal(path: Path) -> None:
    journal = DurableGatewayCoordinationJournal(
        path,
        owner_subject=GATEWAY_SUBJECT,
        initialize=True,
    )
    journal.close()


def _retain_m4i_action(
    tmp_path: Path,
    artifacts: M4iArtifacts,
) -> tuple[Path, SignedEffectPrepareRequest]:
    directory = tmp_path / "retained-action"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "gateway-coordination.json"
    prepare = SignedEffectPrepareRequest.issue(
        dispatch=artifacts.dispatch,
        signer=artifacts.gateway_signer,
        request_nonce="gateway-action-guard-prepare-nonce-0001",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    with DurableGatewayCoordinationJournal(
        path,
        owner_subject=GATEWAY_SUBJECT,
        initialize=True,
    ) as journal:
        journal.begin(prepare, recorded_at=NOW)
    return path, prepare


def _restarted_guard_runtime(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
) -> tuple[
    CapabilityGatewayRuntime,
    ForbiddenActionController,
    DurableGatewayCoordinationJournal,
]:
    journal = DurableGatewayCoordinationJournal(
        path,
        owner_subject=GATEWAY_SUBJECT,
    )
    monkeypatch.setattr(
        runtime_module,
        "CoordinatedWorkloadRemoteVirtualPlcPort",
        RecordingCoordinatedPort,
    )
    port = RecordingCoordinatedPort(
        "https://drifted-ot.test",
        coordination_journal=journal,
    )
    controller = ForbiddenActionController(port)
    runtime = CapabilityGatewayRuntime(
        authorization=cast(Any, object()),
        controller=cast(Any, controller),
        observer=cast(Any, object()),
        discovery=cast(Any, object()),
        gateway_key_id=GATEWAY_KEY_ID,
        coordination_required=True,
        coordination_journal=journal,
    )
    return runtime, controller, journal


def _configure_required_gateway(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> tuple[object, list[tuple[str, WorkloadRole, str]]]:
    _configure_runtime_environment(monkeypatch, tmp_path, artifacts)
    monkeypatch.setenv("AEGIS_WORKLOAD_IDENTITY_MODE", "required")
    monkeypatch.setenv("AEGIS_EFFECT_COORDINATION_MODE", "required")
    monkeypatch.setenv("AEGIS_GATEWAY_WORKLOAD_SUBJECT", GATEWAY_SUBJECT)
    monkeypatch.setenv("AEGIS_OT_WORKLOAD_SUBJECT", OT_SUBJECT)
    monkeypatch.setenv("AEGIS_AGENT_WORKLOAD_SUBJECT", AGENT_SUBJECT)
    monkeypatch.setenv("AEGIS_AGENT_ACTOR_ID", "agent:operator-1")

    journal_directory = tmp_path / "gateway-coordination"
    journal_directory.mkdir(mode=0o700)
    journal_directory.chmod(0o700)
    journal_path = journal_directory / "gateway-coordination.json"
    _seed_gateway_journal(journal_path)
    monkeypatch.setenv(
        "AEGIS_GATEWAY_COORDINATION_JOURNAL_FILE",
        str(journal_path),
    )

    verifier = object()
    gateway_resolved = SimpleNamespace(key_id=GATEWAY_KEY_ID)
    gateway_identity = SimpleNamespace(
        binding=SimpleNamespace(expected_subject=GATEWAY_SUBJECT),
        signer=SimpleNamespace(private_key=artifacts.gateway_private),
        resolve=lambda: gateway_resolved,
    )
    ot_resolved = SimpleNamespace(
        key_id=OT_KEY_ID,
        public_key=artifacts.ot_private.public_key(),
    )
    ot_identity = SimpleNamespace(resolve=lambda: ot_resolved)
    bindings: list[tuple[str, WorkloadRole, str]] = []

    def local_identity(
        actual_verifier: object,
        prefix: str,
        *,
        role: WorkloadRole,
        audience: str,
    ) -> object:
        assert actual_verifier is verifier
        bindings.append((prefix, role, audience))
        return gateway_identity

    def credential_binding(
        actual_verifier: object,
        prefix: str,
        *,
        role: WorkloadRole,
        audience: str,
    ) -> object:
        assert actual_verifier is verifier
        bindings.append((prefix, role, audience))
        return ot_identity

    discovery = _health_bundle(artifacts)
    monkeypatch.setattr(runtime_module, "verifier_from_environment", lambda: verifier)
    monkeypatch.setattr(runtime_module, "local_identity_from_environment", local_identity)
    monkeypatch.setattr(
        runtime_module,
        "credential_binding_from_environment",
        credential_binding,
    )
    monkeypatch.setattr(
        runtime_module,
        "_discover_over_configured_transport",
        lambda **_: discovery,
    )
    monkeypatch.setattr(
        runtime_module,
        "CoordinatedWorkloadRemoteVirtualPlcPort",
        RecordingCoordinatedPort,
    )
    return discovery, bindings


def test_restarted_gateway_rejects_exact_retained_action_before_drifted_stack(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
) -> None:
    path, prepare = _retain_m4i_action(tmp_path, m4i_artifacts)
    runtime, controller, journal = _restarted_guard_runtime(monkeypatch, path)
    port = cast(RecordingCoordinatedPort, controller.plc)
    try:
        with pytest.raises(
            CapabilityAdmissionRejected,
            match="agent_action_already_coordinated",
        ):
            runtime.execute(prepare.dispatch.request)

        assert controller.translator_version == "drifted-translator-v2"
        assert controller.target_boot_epoch == "drifted-target-boot-0002"
        assert controller.calls == 0
        assert port.recovery_calls == 0
        assert len(journal.records()) == 1
    finally:
        journal.close()


def test_gateway_action_guard_rejects_replay_collision_and_journal_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    m4i_artifacts: M4iArtifacts,
) -> None:
    path, prepare = _retain_m4i_action(tmp_path, m4i_artifacts)
    runtime, controller, journal = _restarted_guard_runtime(monkeypatch, path)
    retained = prepare.dispatch.request
    conflicting = retained.model_copy(
        update={"request_id": "m4i-conflicting-action-request-0002"}
    )
    assert conflicting.digest != retained.digest
    assert conflicting.proposal.actor_id == retained.proposal.actor_id
    assert conflicting.proposal.nonce == retained.proposal.nonce
    try:
        with pytest.raises(
            CapabilityAdmissionRejected,
            match="agent_action_coordination_conflict",
        ):
            runtime.execute(conflicting)

        assert controller.calls == 0
        journal.close()
        fresh_proposal = retained.proposal.model_copy(
            update={
                "actor_id": "agent:operator-unrecorded",
                "nonce": "unrecorded-proposal-nonce-0001",
            }
        )
        fresh = retained.model_copy(
            update={
                "request_id": "m4i-unrecorded-action-request-0003",
                "proposal": fresh_proposal,
            }
        )
        with pytest.raises(
            CapabilityRuntimeUnavailable,
            match="gateway coordination journal is unavailable",
        ):
            runtime.execute(fresh)
        assert controller.calls == 0
    finally:
        journal.close()


@pytest.mark.parametrize("mode", (None, "unexpected"))
def test_gateway_builder_requires_an_explicit_closed_coordination_mode(
    monkeypatch: pytest.MonkeyPatch,
    mode: str | None,
) -> None:
    if mode is None:
        monkeypatch.delenv("AEGIS_EFFECT_COORDINATION_MODE", raising=False)
    else:
        monkeypatch.setenv("AEGIS_EFFECT_COORDINATION_MODE", mode)
    monkeypatch.setenv("AEGIS_WORKLOAD_IDENTITY_MODE", "disabled")

    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match="coordination mode must be required or disabled",
    ):
        runtime_module._build_gateway_runtime()


def test_required_gateway_coordination_requires_workload_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_EFFECT_COORDINATION_MODE", "required")
    monkeypatch.setenv("AEGIS_WORKLOAD_IDENTITY_MODE", "disabled")

    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match="required effect coordination needs workload identity",
    ):
        runtime_module._build_gateway_runtime()


def test_required_builder_wires_coordination_identities_journal_and_health(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    discovery, bindings = _configure_required_gateway(
        monkeypatch,
        tmp_path,
        artifacts,
    )

    runtime = runtime_module._build_gateway_runtime()
    journal = runtime.coordination_journal
    assert journal is not None
    try:
        port = cast(RecordingCoordinatedPort, runtime.controller.plc)
        assert isinstance(port, RecordingCoordinatedPort)
        assert port.arguments["observer"] == discovery.observer
        assert port.arguments["ot"] == discovery.ot
        assert port.arguments["coordination_journal"] is journal
        assert journal.owner_subject == GATEWAY_SUBJECT
        assert bindings == [
            ("GATEWAY", WorkloadRole.GATEWAY, EFFECT_COORDINATOR_AUDIENCE),
            ("OT", WorkloadRole.OT_ADAPTER, GATEWAY_COORDINATION_AUDIENCE),
        ]
        assert port.recovery_calls == 0

        health = runtime.health()
        assert health["schema_version"] == "m4g-gateway-health-v1"
        assert health["status"] == "ready"
        assert health["effect_coordination_mode"] == "required"
        assert health["coordination_backend"] == (
            "durable-prepare-commit-query-http-v1"
        )
        assert health["coordination_journal_records"] == 0
        assert health["coordination_pending_effects"] == 0
        assert health["coordination_startup_recovery"] == "not-attempted"
        assert port.preflight_calls == 1
        assert port.recovery_calls == 0

        journal.close()
        response = TestClient(create_gateway_app(lambda: runtime)).get("/health")
        assert response.status_code == 503
        assert response.json()["reason"] == "gateway_runtime_unavailable"
        assert port.recovery_calls == 0
    finally:
        journal.close()


def test_disabled_builder_preserves_the_m4g_ot_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    _configure_runtime_environment(monkeypatch, tmp_path, artifacts)
    discovery = _health_bundle(artifacts)
    monkeypatch.setattr(
        runtime_module,
        "_discover_over_configured_transport",
        lambda **_: discovery,
    )

    runtime = runtime_module._build_gateway_runtime()

    assert type(runtime.controller.plc) is RemoteVirtualPlcPort
    assert runtime.coordination_journal is None
    health = runtime.health()
    assert health["effect_coordination_mode"] == "disabled"
    assert health["coordination_backend"] == "segmented-compose-http-v1"
    assert health["coordination_journal_records"] == 0
    assert health["coordination_pending_effects"] == 0
    assert health["coordination_startup_recovery"] == "not-attempted"
    assert health["status"] == "ready"


def test_disabled_workload_builder_keeps_m4g_capability_audiences(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_EFFECT_COORDINATION_MODE", "disabled")
    monkeypatch.setenv("AEGIS_WORKLOAD_IDENTITY_MODE", "required")
    audiences: list[str] = []

    def stop_after_local_identity(
        *_: object,
        audience: str,
        **__: object,
    ) -> object:
        audiences.append(audience)
        return SimpleNamespace(resolve=lambda: SimpleNamespace(key_id=GATEWAY_KEY_ID))

    def stop_after_ot_binding(
        *_: object,
        audience: str,
        **__: object,
    ) -> object:
        audiences.append(audience)
        raise RuntimeError("stop after audience selection")

    monkeypatch.setattr(runtime_module, "verifier_from_environment", object)
    monkeypatch.setattr(
        runtime_module,
        "local_identity_from_environment",
        stop_after_local_identity,
    )
    monkeypatch.setattr(
        runtime_module,
        "credential_binding_from_environment",
        stop_after_ot_binding,
    )

    with pytest.raises(RuntimeError, match="stop after audience selection"):
        runtime_module._build_gateway_runtime()

    assert audiences == [OT_CAPABILITY_AUDIENCE, GATEWAY_CAPABILITY_AUDIENCE]
