from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from test_m4g_runtime import GATEWAY_KEY_ID, OT_KEY_ID, RuntimeArtifacts
from test_m4g_runtime import artifacts as _runtime_artifacts_fixture
from test_m4g_runtime_edges import (
    _configure_runtime_environment,
    _health_bundle,
)

import aegis_ot.segmented_capability_runtime as runtime_module
from aegis_ot.segmented_capability_models import OT_CAPABILITY_AUDIENCE
from aegis_ot.segmented_capability_transport import (
    HttpExchangeResponse,
    urllib_http_exchange,
)
from aegis_ot.semantic_replay import OrderlyRestartReplayReservations
from aegis_ot.transport_replay import DurableTransportReplayLedger


@pytest.fixture(scope="module")  # type: ignore[untyped-decorator]
def artifacts() -> RuntimeArtifacts:
    factory = cast(
        Callable[[], RuntimeArtifacts],
        cast(Any, _runtime_artifacts_fixture).__wrapped__,
    )
    return factory()


def _mtls_exchange(
    *,
    method: str,
    url: str,
    body: bytes | None,
    headers: Mapping[str, str],
    timeout_seconds: float,
) -> HttpExchangeResponse:
    del method, url, body, headers, timeout_seconds
    raise AssertionError("the wiring test must not perform network I/O")


def test_runtime_exchange_selector_never_downgrades_selector_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_SPIRE_MTLS_MODE", "required")
    monkeypatch.setattr(
        runtime_module,
        "capability_http_exchange_from_environment",
        lambda: _mtls_exchange,
    )
    assert runtime_module._configured_capability_exchange() is _mtls_exchange

    def reject_invalid_mode() -> Any:
        raise ValueError("AEGIS_SPIRE_MTLS_MODE must be required")

    monkeypatch.setattr(
        runtime_module,
        "capability_http_exchange_from_environment",
        reject_invalid_mode,
    )
    with pytest.raises(ValueError, match="must be required"):
        runtime_module._configured_capability_exchange()


def test_observer_candidate_and_ot_builders_share_one_selected_exchange(
    artifacts: RuntimeArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _configure_runtime_environment(monkeypatch, tmp_path, artifacts)
    discovery = _health_bundle(artifacts)
    monkeypatch.setattr(
        runtime_module,
        "_configured_capability_exchange",
        lambda: _mtls_exchange,
    )

    plant_fetches: list[tuple[str, Any]] = []

    def fetch_plant(url: str, *, exchange: Any) -> Any:
        plant_fetches.append((url, exchange))
        return discovery.plant

    observer_fetches: list[tuple[str, Any]] = []

    def fetch_observer(url: str, *, exchange: Any) -> Any:
        observer_fetches.append((url, exchange))
        return discovery.observer

    monkeypatch.setattr(runtime_module, "fetch_plant_health", fetch_plant)
    monkeypatch.setattr(runtime_module, "fetch_observer_health", fetch_observer)

    observer = runtime_module._build_observer_runtime()
    candidate = runtime_module._build_candidate_runtime()
    assert observer.plant.exchange is _mtls_exchange
    assert candidate.plant.exchange is _mtls_exchange

    semantic = OrderlyRestartReplayReservations(paths["SEMANTIC"], initialize=True)
    semantic.close()
    replay = DurableTransportReplayLedger(
        paths["TRANSPORT"],
        audience=OT_CAPABILITY_AUDIENCE,
        gateway_key_id=GATEWAY_KEY_ID,
        gateway_public_key_sha256=hashlib.sha256(
            artifacts.gateway_private.public_key().public_bytes_raw()
        ).hexdigest(),
        initialize=True,
    )
    replay.close()

    ot = runtime_module._build_ot_runtime()
    try:
        assert cast(Any, ot.device.plant).exchange is _mtls_exchange
        assert all(exchange is _mtls_exchange for _, exchange in plant_fetches)
        assert observer_fetches == [
            ("http://observer:8080", _mtls_exchange),
        ]
    finally:
        ot.transport_replay.close()
        ot.semantic_replay.close()


def test_gateway_builder_keeps_application_workload_port_and_adds_mtls_exchange(
    artifacts: RuntimeArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_runtime_environment(monkeypatch, tmp_path, artifacts)
    discovery = _health_bundle(artifacts)
    monkeypatch.setenv(
        "AEGIS_AGENT_WORKLOAD_SUBJECT",
        "urn:aegis-ot:m4g:test:agent",
    )
    monkeypatch.setattr(runtime_module, "workload_identity_enabled", lambda: True)
    monkeypatch.setattr(
        runtime_module,
        "_configured_capability_exchange",
        lambda: _mtls_exchange,
    )

    verifier = object()
    gateway_identity = SimpleNamespace(
        signer=SimpleNamespace(private_key=artifacts.gateway_private),
        resolve=lambda: SimpleNamespace(
            key_id=GATEWAY_KEY_ID,
            public_key=artifacts.gateway_private.public_key(),
        ),
    )
    ot_identity = SimpleNamespace(
        resolve=lambda: SimpleNamespace(
            key_id=OT_KEY_ID,
            public_key=artifacts.ot_private.public_key(),
        )
    )
    monkeypatch.setattr(runtime_module, "verifier_from_environment", lambda: verifier)
    monkeypatch.setattr(
        runtime_module,
        "local_identity_from_environment",
        lambda *_args, **_kwargs: gateway_identity,
    )
    monkeypatch.setattr(
        runtime_module,
        "credential_binding_from_environment",
        lambda *_args, **_kwargs: ot_identity,
    )

    discovery_calls: list[dict[str, Any]] = []

    def discover(**kwargs: Any) -> Any:
        discovery_calls.append(kwargs)
        return discovery

    monkeypatch.setattr(
        runtime_module,
        "_discover_over_configured_transport",
        discover,
    )

    workload_port_calls: list[dict[str, Any]] = []

    class CapturingWorkloadPort:
        def __init__(self, base_url: str, **kwargs: Any) -> None:
            workload_port_calls.append({"base_url": base_url, **kwargs})

        def preflight_identity(self) -> None:
            return

    monkeypatch.setattr(
        runtime_module,
        "WorkloadRemoteVirtualPlcPort",
        CapturingWorkloadPort,
    )

    gateway = runtime_module._build_gateway_runtime()

    assert gateway.agent_workload_verifier is verifier
    assert discovery_calls == [
        {
            "observer_url": "http://observer:8080",
            "candidate_url": "http://candidate:8080",
            "ot_url": "http://ot:8080",
            "gateway_key_id": GATEWAY_KEY_ID,
            "exchange": _mtls_exchange,
        }
    ]
    assert workload_port_calls == [
        {
            "base_url": "http://ot:8080",
            "ot": discovery.ot,
            "gateway_identity": gateway_identity,
            "ot_identity": ot_identity,
            "exchange": _mtls_exchange,
        }
    ]
    assert gateway.observer.exchange is _mtls_exchange
    assert gateway.controller.simulator.exchange is _mtls_exchange
    assert cast(Any, gateway.controller.plc).__class__ is CapturingWorkloadPort


def test_plain_http_helpers_preserve_the_legacy_call_shape(
    artifacts: RuntimeArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = _health_bundle(artifacts)
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def fetch(name: str, result: Any) -> Callable[..., Any]:
        def invoke(*args: Any, **kwargs: Any) -> Any:
            calls.append((name, args, kwargs))
            return result

        return invoke

    monkeypatch.setattr(
        runtime_module,
        "fetch_plant_health",
        fetch("plant", discovery.plant),
    )
    monkeypatch.setattr(
        runtime_module,
        "fetch_observer_health",
        fetch("observer", discovery.observer),
    )

    assert (
        runtime_module._fetch_plant_over_configured_transport(
            "http://simulation:8084",
            urllib_http_exchange,
        )
        == discovery.plant
    )
    assert (
        runtime_module._fetch_observer_over_configured_transport(
            "http://observer:8082",
            urllib_http_exchange,
        )
        == discovery.observer
    )
    assert calls == [
        ("plant", ("http://simulation:8084",), {}),
        ("observer", ("http://observer:8082",), {}),
    ]
