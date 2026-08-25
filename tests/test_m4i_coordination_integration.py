from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from test_m4g_runtime import RuntimeArtifacts
from test_m4g_runtime import artifacts as runtime_artifacts_fixture
from test_m4i_ot_coordination_runtime import (
    GATEWAY_SUBJECT,
    OT_SUBJECT,
    RESTARTED_OBSERVER_BOOT,
    RESTARTED_OT_BOOT,
    CoordinationIdentities,
    _harness,
    _open_journal,
    _runtime,
)

from aegis_ot.coordination_journal import (
    DurableGatewayCoordinationJournal,
)
from aegis_ot.coordination_models import (
    EFFECT_COORDINATOR_AUDIENCE,
    GATEWAY_COORDINATION_AUDIENCE,
    CoordinationState,
    SignedEffectOutcome,
)
from aegis_ot.segmented_capability_models import SegmentedCapabilityDispatch
from aegis_ot.segmented_capability_runtime import create_ot_app
from aegis_ot.segmented_capability_transport import (
    ConsequentialTransportOutcomeUnknown,
    CoordinatedWorkloadRemoteVirtualPlcPort,
    HttpExchangeResponse,
    ObserverHealthMetadata,
    OtHealthMetadata,
)
from aegis_ot.workload_identity import (
    WorkloadCredentialBinding,
    WorkloadRole,
    public_key_base64,
)
from aegis_ot.workload_runtime import LocalWorkloadIdentity

_ARTIFACT_FACTORY = cast(Any, runtime_artifacts_fixture).__wrapped__


@pytest.fixture(scope="module")
def artifacts() -> RuntimeArtifacts:
    return cast(RuntimeArtifacts, _ARTIFACT_FACTORY())


@dataclass
class DroppingTestClientExchange:
    client: TestClient
    drop_commit_response_once: bool = True

    def __post_init__(self) -> None:
        self.calls: Counter[str] = Counter()
        self.dropped_outcome: SignedEffectOutcome | None = None

    def __call__(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> HttpExchangeResponse:
        del timeout_seconds
        path = urlsplit(url).path
        self.calls[path] += 1
        response = self.client.request(
            method,
            path,
            content=body,
            headers=dict(headers),
        )
        if path == "/v1/effects/commit" and self.drop_commit_response_once:
            assert response.status_code == 200, response.text
            self.dropped_outcome = SignedEffectOutcome.model_validate_json(response.content)
            self.drop_commit_response_once = False
            raise TimeoutError("synthetic loss after OT terminal persistence")
        return HttpExchangeResponse(
            status_code=response.status_code,
            content_type=response.headers.get("Content-Type", ""),
            body=response.content,
        )


def _gateway_identities(
    identities: CoordinationIdentities,
) -> tuple[LocalWorkloadIdentity, WorkloadCredentialBinding]:
    verifier = identities.gateway_binding.verifier
    gateway_binding = WorkloadCredentialBinding(
        verifier=verifier,
        credential_path=identities.gateway_path,
        expected_role=WorkloadRole.GATEWAY,
        expected_audience=EFFECT_COORDINATOR_AUDIENCE,
        expected_subject=GATEWAY_SUBJECT,
    )
    ot_binding = WorkloadCredentialBinding(
        verifier=verifier,
        credential_path=identities.local_path,
        expected_role=WorkloadRole.OT_ADAPTER,
        expected_audience=GATEWAY_COORDINATION_AUDIENCE,
        expected_subject=OT_SUBJECT,
    )
    return (
        LocalWorkloadIdentity(
            binding=gateway_binding,
            signer=identities.gateway_signer,
        ),
        ot_binding,
    )


def _observer_health(runtime: Any, ot: OtHealthMetadata) -> ObserverHealthMetadata:
    observer = runtime.observer_info
    return ObserverHealthMetadata(
        status="ready",
        role="observer",
        pid=201,
        observer_id=observer.observer_id,
        boot_epoch=observer.boot_epoch,
        key_id=observer.key_id,
        public_key_b64=public_key_base64(observer.public_key),
        plant_boot_epoch=ot.plant_boot_epoch,
        plant_model_digest=ot.plant_model_digest,
        capture_count=0,
        resolve_count=0,
        cached_observations=0,
    )


def _gateway_port(
    *,
    runtime: Any,
    identities: CoordinationIdentities,
    journal: DurableGatewayCoordinationJournal,
    exchange: DroppingTestClientExchange,
    clock: Any,
) -> CoordinatedWorkloadRemoteVirtualPlcPort:
    gateway_identity, ot_identity = _gateway_identities(identities)
    ot = cast(OtHealthMetadata, runtime.health())
    return CoordinatedWorkloadRemoteVirtualPlcPort(
        "https://ot.integration.test",
        ot=ot,
        observer=_observer_health(runtime, ot),
        gateway_identity=gateway_identity,
        ot_identity=ot_identity,
        coordination_journal=journal,
        exchange=exchange,
        clock=clock,
        nonce_factory=lambda: "m4i-integration-coordination-nonce-0001",
    )


def _execute(
    port: CoordinatedWorkloadRemoteVirtualPlcPort,
    dispatch: SegmentedCapabilityDispatch,
) -> Any:
    return port.execute(
        request=dispatch.request,
        permit=dispatch.permit,
        pre_observation=dispatch.pre_observation,
        decision=dispatch.decision,
        assessment=dispatch.assessment,
    )


def test_cross_side_lost_commit_response_reconciles_once_after_journal_reopen(
    tmp_path: Path,
    artifacts: RuntimeArtifacts,
) -> None:
    ot_harness = _harness(tmp_path, artifacts)
    gateway_directory = tmp_path / "gateway-coordination"
    gateway_directory.mkdir(mode=0o700)
    gateway_directory.chmod(0o700)
    gateway_path = gateway_directory / "gateway.json"
    gateway_journal = DurableGatewayCoordinationJournal(
        gateway_path,
        owner_subject=GATEWAY_SUBJECT,
        initialize=True,
    )
    client = TestClient(create_ot_app(lambda: ot_harness.runtime))
    exchange = DroppingTestClientExchange(client)
    gateway_port = _gateway_port(
        runtime=ot_harness.runtime,
        identities=ot_harness.identities,
        journal=gateway_journal,
        exchange=exchange,
        clock=ot_harness.clock,
    )

    with pytest.raises(ConsequentialTransportOutcomeUnknown):
        _execute(gateway_port, ot_harness.dispatch)

    dropped = exchange.dropped_outcome
    assert dropped is not None
    assert dropped.acknowledgment is not None
    assert exchange.calls["/v1/effects/prepare"] == 1
    assert exchange.calls["/v1/effects/commit"] == 1
    assert exchange.calls["/v1/effects/query"] == 0
    assert ot_harness.device.calls == 1
    gateway_record = gateway_journal.get(dropped.effect)
    ot_record = ot_harness.journal.get(dropped.effect)
    assert gateway_record is not None
    assert gateway_record.state is CoordinationState.DISPATCH_ARMED
    assert ot_record is not None
    assert ot_record.state is CoordinationState.APPLIED

    client.close()
    gateway_journal.close()
    ot_harness.journal.close()
    gateway_journal = DurableGatewayCoordinationJournal(
        gateway_path,
        owner_subject=GATEWAY_SUBJECT,
        initialize=False,
    )
    ot_journal = _open_journal(ot_harness.journal_path, initialize=False)
    restarted_runtime, restarted_device, _ = _runtime(
        artifacts,
        ot_harness.identities,
        ot_harness.dispatch,
        ot_journal,
        ot_harness.clock,
        boot_epoch=RESTARTED_OT_BOOT,
        observer_boot_epoch=RESTARTED_OBSERVER_BOOT,
    )
    restarted_client = TestClient(create_ot_app(lambda: restarted_runtime))
    exchange.client = restarted_client
    restarted_port = _gateway_port(
        runtime=restarted_runtime,
        identities=ot_harness.identities,
        journal=gateway_journal,
        exchange=exchange,
        clock=ot_harness.clock,
    )

    reconciled = _execute(restarted_port, ot_harness.dispatch)
    duplicate = _execute(restarted_port, ot_harness.dispatch)

    assert reconciled == dropped.acknowledgment
    assert duplicate == dropped.acknowledgment
    assert exchange.calls["/v1/effects/prepare"] == 1
    assert exchange.calls["/v1/effects/commit"] == 1
    assert exchange.calls["/v1/effects/query"] == 1
    assert ot_harness.device.calls == 1
    assert restarted_device.calls == 0
    reopened_gateway_record = gateway_journal.get(dropped.effect)
    reopened_ot_record = ot_journal.get(dropped.effect)
    assert reopened_gateway_record is not None
    assert reopened_gateway_record.state is CoordinationState.APPLIED
    assert reopened_gateway_record.terminal_outcome is not None
    assert reopened_gateway_record.terminal_outcome.acknowledgment == dropped.acknowledgment
    assert reopened_ot_record is not None
    assert reopened_ot_record.state is CoordinationState.APPLIED
    assert reopened_ot_record.terminal_outcome is not None
    assert reopened_ot_record.terminal_outcome.acknowledgment == dropped.acknowledgment

    restarted_client.close()
    gateway_journal.close()
    ot_journal.close()
