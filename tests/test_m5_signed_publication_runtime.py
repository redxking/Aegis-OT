from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from test_m5_degraded_publication import (
    TrustMaterial,
    _private_directory,
    _publication,
    _trust_material,
    _write_key,
    _write_model,
)

import aegis_ot.segmented_capability_runtime as runtime_module
from aegis_ot.m5_degraded_publication import (
    FileDegradedConsumerStateStore,
    PublishedDegradedOperationGate,
)
from aegis_ot.segmented_capability_runtime import (
    CapabilityGatewayRuntime,
    CapabilityRuntimeUnavailable,
    create_gateway_app,
)

MODE_ENV = "AEGIS_M5_SIGNED_PUBLICATION_MODE"
SIGNED_ENV = (
    "AEGIS_M5_ROOT_PUBLIC_KEY_FILE",
    "AEGIS_M5_PUBLISHER_CREDENTIAL_FILE",
    "AEGIS_M5_STABLE_AUTHORIZATION_FILE",
    "AEGIS_M5_PUBLICATION_FILE",
    "AEGIS_M5_CONSUMER_STATE_FILE",
    "AEGIS_M5_REVERSAL_FILE",
)
LEGACY_ENV = (
    "AEGIS_M5_DEGRADED_AUTHORITY_ID",
    "AEGIS_M5_DEGRADED_AUTHORITY_PUBLIC_KEY_FILE",
    "AEGIS_M5_DEGRADED_SNAPSHOT_FILE",
    "AEGIS_M5_DEGRADED_AUTHORIZATION_FILE",
    "AEGIS_M5_DEGRADED_STATE_FILE",
)


@dataclass(frozen=True)
class SignedRuntimeFiles:
    trust: TrustMaterial
    publication_path: Path
    state_path: Path
    reversal_path: Path
    environment: dict[str, str]


def _clear_m5_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (MODE_ENV, *SIGNED_ENV, *LEGACY_ENV):
        monkeypatch.delenv(name, raising=False)


def _signed_runtime_files(tmp_path: Path) -> SignedRuntimeFiles:
    issued_at = datetime.now(UTC) - timedelta(seconds=2)
    trust = _trust_material(
        at=issued_at,
        maximum_publication_age_seconds=30,
    )
    inputs = _private_directory(tmp_path / "gateway-inputs")
    root_public_path = inputs / "operator-authority.public"
    credential_path = inputs / "publisher-credential.json"
    authorization_path = inputs / "stable-authorization.json"
    _write_key(
        root_public_path,
        trust.root_private_key.public_key().public_bytes_raw(),
    )
    _write_model(credential_path, trust.credential)
    _write_model(authorization_path, trust.authorization)

    publication_path = _private_directory(tmp_path / "publication") / "current.json"
    publication = _publication(
        trust,
        sequence=1,
        published_at=issued_at,
        previous=None,
    )
    _write_model(publication_path, publication)

    state_path = _private_directory(tmp_path / "consumer-state") / "state.json"
    FileDegradedConsumerStateStore.initialize(
        state_path,
        credential=trust.credential,
    )
    reversal_path = _private_directory(tmp_path / "reversal") / "current.json"
    environment = {
        "AEGIS_M5_ROOT_PUBLIC_KEY_FILE": str(root_public_path),
        "AEGIS_M5_PUBLISHER_CREDENTIAL_FILE": str(credential_path),
        "AEGIS_M5_STABLE_AUTHORIZATION_FILE": str(authorization_path),
        "AEGIS_M5_PUBLICATION_FILE": str(publication_path),
        "AEGIS_M5_CONSUMER_STATE_FILE": str(state_path),
        "AEGIS_M5_REVERSAL_FILE": str(reversal_path),
    }
    return SignedRuntimeFiles(
        trust=trust,
        publication_path=publication_path,
        state_path=state_path,
        reversal_path=reversal_path,
        environment=environment,
    )


def _configure_required(
    monkeypatch: pytest.MonkeyPatch,
    files: SignedRuntimeFiles,
) -> None:
    _clear_m5_environment(monkeypatch)
    monkeypatch.setenv(MODE_ENV, "required")
    for name, value in files.environment.items():
        monkeypatch.setenv(name, value)


class CountingController:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, _: object) -> object:
        self.calls += 1
        raise AssertionError("controller dispatch must not run during readiness")


def _gateway_runtime(
    gate: PublishedDegradedOperationGate,
    *,
    now: datetime,
) -> tuple[CapabilityGatewayRuntime, CountingController]:
    controller = CountingController()
    discovery = SimpleNamespace(
        plant=SimpleNamespace(boot_epoch="m5-plant-boot-0001"),
        observer=SimpleNamespace(boot_epoch="m5-observer-boot-0001"),
        candidate=SimpleNamespace(boot_epoch="m5-candidate-boot-0001"),
        ot=SimpleNamespace(boot_epoch="m5-ot-boot-0001"),
    )
    runtime = CapabilityGatewayRuntime(
        authorization=cast(
            Any,
            SimpleNamespace(
                gateway=SimpleNamespace(
                    evidence=SimpleNamespace(records=[]),
                )
            ),
        ),
        controller=cast(Any, controller),
        observer=cast(Any, SimpleNamespace()),
        discovery=cast(Any, discovery),
        gateway_key_id="m5-gateway-key-0001",
        degraded_operation=gate,
        clock=lambda: now,
    )
    return runtime, controller


def test_signed_settings_require_an_explicit_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_m5_environment(monkeypatch)
    monkeypatch.setenv("AEGIS_M5_PUBLICATION_FILE", "/runtime/publication.json")

    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match=f"required runtime setting is missing: {MODE_ENV}",
    ):
        runtime_module._configured_m5_degraded_gate()


def test_explicit_disabled_mode_rejects_retained_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_m5_environment(monkeypatch)
    monkeypatch.setenv(MODE_ENV, "disabled")
    assert runtime_module._configured_m5_degraded_gate() is None

    monkeypatch.setenv("AEGIS_M5_STABLE_AUTHORIZATION_FILE", "/retained/auth.json")
    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match="disabled M5 signed publication cannot retain M5 configuration",
    ):
        runtime_module._configured_m5_degraded_gate()


def test_invalid_signed_publication_mode_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_m5_environment(monkeypatch)
    monkeypatch.setenv(MODE_ENV, "optional")

    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match="M5 signed publication mode must be disabled or required",
    ):
        runtime_module._configured_m5_degraded_gate()


def test_required_mode_rejects_incomplete_relative_and_mixed_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_m5_environment(monkeypatch)
    monkeypatch.setenv(MODE_ENV, "required")
    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match="M5 signed publication configuration is incomplete",
    ):
        runtime_module._configured_m5_degraded_gate()

    for name in SIGNED_ENV:
        monkeypatch.setenv(name, f"relative/{name.lower()}")
    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match="M5 signed publication file paths must be absolute",
    ):
        runtime_module._configured_m5_degraded_gate()

    monkeypatch.setenv("AEGIS_M5_DEGRADED_AUTHORITY_ID", "legacy-authority")
    with pytest.raises(
        CapabilityRuntimeUnavailable,
        match="M5 legacy and signed publication configuration cannot be mixed",
    ):
        runtime_module._configured_m5_degraded_gate()


def test_valid_required_mode_builds_gate_and_advances_consumer_floor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    files = _signed_runtime_files(tmp_path)
    _configure_required(monkeypatch, files)
    before = FileDegradedConsumerStateStore(files.state_path).read()
    assert before.highest_publication_sequence == 0

    configured = runtime_module._configured_m5_degraded_gate()

    assert isinstance(configured, PublishedDegradedOperationGate)
    after = FileDegradedConsumerStateStore(files.state_path).read()
    assert after.highest_publication_sequence == 1
    assert after.active_authorization_sha256 == files.trust.authorization.digest


def test_gateway_health_revalidates_and_reports_current_readiness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    files = _signed_runtime_files(tmp_path)
    _configure_required(monkeypatch, files)
    configured = runtime_module._configured_m5_degraded_gate()
    assert isinstance(configured, PublishedDegradedOperationGate)
    first = configured.publication_source()
    health_time = datetime.now(UTC)
    second = _publication(
        files.trust,
        sequence=2,
        published_at=health_time,
        previous=first.digest,
    )
    _write_model(files.publication_path, second)
    runtime, controller = _gateway_runtime(configured, now=health_time)

    health = runtime.health()

    assert health["status"] == "ready"
    assert health["m5_signed_publication_mode"] == "required"
    assert health["m5_degraded_readiness"]["publication_sequence"] == 2
    assert health["m5_degraded_readiness"]["durable_publication_floor"] == 2
    assert FileDegradedConsumerStateStore(files.state_path).read().highest_publication_sequence == 2
    assert controller.calls == 0


def test_failed_readiness_makes_health_unavailable_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    files = _signed_runtime_files(tmp_path)
    _configure_required(monkeypatch, files)
    configured = runtime_module._configured_m5_degraded_gate()
    assert isinstance(configured, PublishedDegradedOperationGate)
    runtime, controller = _gateway_runtime(configured, now=datetime.now(UTC))
    files.publication_path.unlink()

    response = TestClient(create_gateway_app(lambda: runtime)).get("/health")

    assert response.status_code == 503
    assert response.json() == {
        "schema_version": "m4g-transport-failure-v1",
        "status": "error",
        "reason": "gateway_runtime_unavailable",
    }
    assert controller.calls == 0
