from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from test_workload_identity import (
    TRUST_DOMAIN,
    _issue_bundle,
    _issue_credential,
    _write_identity_model,
)

from aegis_ot.capability_models import (
    CapabilityClosedLoopStatus,
    PlcCommandAcknowledgment,
)
from aegis_ot.capability_plc import OrderlyRestartReplayReservations
from aegis_ot.evidence import EvidenceChain
from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    OT_CAPABILITY_AUDIENCE,
    SegmentedCapabilityClosedLoopResult,
    SegmentedCapabilityDispatch,
    WorkloadAuthenticatedCapabilityAction,
    WorkloadSignedCapabilityDispatch,
    WorkloadSignedCapabilityResponse,
)
from aegis_ot.segmented_capability_runtime import (
    CapabilityGatewayRuntime,
    CapabilityOtRuntime,
    create_gateway_app,
    create_ot_app,
)
from aegis_ot.segmented_capability_transport import WorkloadRemoteVirtualPlcPort
from aegis_ot.workload_identity import (
    SignedWorkloadCredential,
    WorkloadCredentialBinding,
    WorkloadIdentityVerifier,
    WorkloadRevocation,
    WorkloadRole,
    WorkloadSigner,
    workload_key_id,
)
from aegis_ot.workload_replay import DurableWorkloadReplayLedger
from aegis_ot.workload_runtime import LocalWorkloadIdentity

AGENT_SUBJECT = "urn:aegis-ot:test:workload:agent-probe"
GATEWAY_SUBJECT = "urn:aegis-ot:test:workload:gateway"
OT_SUBJECT = "urn:aegis-ot:test:workload:ot-adapter"

_runtime_fixtures = import_module("test_m4g_runtime")
NOW = cast(datetime, _runtime_fixtures.NOW)
PLC_ID = cast(str, _runtime_fixtures.PLC_ID)
OT_BOOT = cast(str, _runtime_fixtures.OT_BOOT)
_observer_info = cast(Callable[[Any], Any], _runtime_fixtures._observer_info)
_plant_health = cast(Callable[[Any], Any], _runtime_fixtures._plant_health)


@pytest.fixture(scope="module")
def artifacts() -> Any:
    factory = cast(
        Callable[[], Any],
        cast(Any, _runtime_fixtures.artifacts).__wrapped__,
    )
    return factory()


def _credential(
    authority: Ed25519PrivateKey,
    leaf: Ed25519PrivateKey,
    *,
    credential_id: str,
    subject: str,
    role: WorkloadRole,
    audience: str,
) -> SignedWorkloadCredential:
    return _issue_credential(
        authority,
        leaf,
        credential_id=credential_id,
        subject=subject,
        role=role,
        audiences=(audience,),
        issued_at=NOW - timedelta(minutes=10),
        not_before=NOW - timedelta(minutes=9),
        expires_at=NOW + timedelta(hours=1),
    )


@dataclass(frozen=True)
class CapabilityIdentities:
    authority: Ed25519PrivateKey
    authority_key_id: str
    bundle_path: Path
    agent_signer: WorkloadSigner
    agent_credential_path: Path
    gateway_signer: WorkloadSigner
    gateway_credential_path: Path
    ot_signer: WorkloadSigner
    ot_credential_path: Path

    def verifier(self) -> WorkloadIdentityVerifier:
        return WorkloadIdentityVerifier(
            trust_root_public_key=self.authority.public_key(),
            trust_root_key_id=self.authority_key_id,
            trust_domain=TRUST_DOMAIN,
            trust_bundle_path=self.bundle_path,
        )

    def write_bundle(
        self,
        *,
        sequence: int,
        bundle_id: str,
        revocations: tuple[WorkloadRevocation, ...] = (),
    ) -> None:
        _write_identity_model(
            self.bundle_path,
            _issue_bundle(
                self.authority,
                sequence=sequence,
                bundle_id=bundle_id,
                issued_at=NOW - timedelta(minutes=10),
                expires_at=NOW + timedelta(hours=1),
                revocations=revocations,
            ),
        )

    def rotate_gateway(self, credential_id: str) -> WorkloadSigner:
        private_key = Ed25519PrivateKey.generate()
        credential = _credential(
            self.authority,
            private_key,
            credential_id=credential_id,
            subject=GATEWAY_SUBJECT,
            role=WorkloadRole.GATEWAY,
            audience=OT_CAPABILITY_AUDIENCE,
        )
        _write_identity_model(self.gateway_credential_path, credential)
        return WorkloadSigner(credential=credential, private_key=private_key)


@pytest.fixture
def identities(tmp_path: Path) -> CapabilityIdentities:
    authority = Ed25519PrivateKey.generate()
    agent_private = Ed25519PrivateKey.generate()
    gateway_private = Ed25519PrivateKey.generate()
    ot_private = Ed25519PrivateKey.generate()
    bundle_path = tmp_path / "workload-trust-bundle.json"
    agent_path = tmp_path / "agent-credential.json"
    gateway_path = tmp_path / "gateway-credential.json"
    ot_path = tmp_path / "ot-credential.json"
    agent_credential = _credential(
        authority,
        agent_private,
        credential_id="capability-agent-credential-0001",
        subject=AGENT_SUBJECT,
        role=WorkloadRole.AGENT,
        audience=GATEWAY_CAPABILITY_AUDIENCE,
    )
    gateway_credential = _credential(
        authority,
        gateway_private,
        credential_id="capability-gateway-credential-0001",
        subject=GATEWAY_SUBJECT,
        role=WorkloadRole.GATEWAY,
        audience=OT_CAPABILITY_AUDIENCE,
    )
    ot_credential = _credential(
        authority,
        ot_private,
        credential_id="capability-ot-credential-0001",
        subject=OT_SUBJECT,
        role=WorkloadRole.OT_ADAPTER,
        audience=GATEWAY_CAPABILITY_AUDIENCE,
    )
    _write_identity_model(agent_path, agent_credential)
    _write_identity_model(gateway_path, gateway_credential)
    _write_identity_model(ot_path, ot_credential)
    harness = CapabilityIdentities(
        authority=authority,
        authority_key_id=workload_key_id(authority.public_key()),
        bundle_path=bundle_path,
        agent_signer=WorkloadSigner(
            credential=agent_credential,
            private_key=agent_private,
        ),
        agent_credential_path=agent_path,
        gateway_signer=WorkloadSigner(
            credential=gateway_credential,
            private_key=gateway_private,
        ),
        gateway_credential_path=gateway_path,
        ot_signer=WorkloadSigner(
            credential=ot_credential,
            private_key=ot_private,
        ),
        ot_credential_path=ot_path,
    )
    harness.write_bundle(sequence=1, bundle_id="capability-trust-bundle-0001")
    return harness


class CountingController:
    def __init__(self, artifacts: Any) -> None:
        self.calls = 0
        self.expected_request = artifacts.request
        self.result = SegmentedCapabilityClosedLoopResult(
            status=CapabilityClosedLoopStatus.NOT_DISPATCHED,
            reasons=("focused_workload_admission_test",),
            request=artifacts.request,
            dispatch_attempts=0,
            execution_evidence_hash="0" * 64,
        )

    def execute(self, request: Any) -> SegmentedCapabilityClosedLoopResult:
        assert request == self.expected_request
        self.calls += 1
        return self.result


class UnreadyWorkloadPort(WorkloadRemoteVirtualPlcPort):
    def __init__(self) -> None:
        pass

    def preflight_identity(self) -> None:
        raise RuntimeError("current workload trust is unavailable")


def _gateway_runtime(
    artifacts: Any,
    identities: CapabilityIdentities,
) -> tuple[CapabilityGatewayRuntime, CountingController]:
    controller = CountingController(artifacts)
    runtime = CapabilityGatewayRuntime(
        authorization=cast(
            Any,
            SimpleNamespace(gateway=SimpleNamespace(evidence=EvidenceChain())),
        ),
        controller=cast(Any, controller),
        observer=cast(Any, object()),
        discovery=cast(Any, object()),
        gateway_key_id=identities.gateway_signer.credential.credential.key_id,
        agent_workload_verifier=identities.verifier(),
        agent_workload_subject=AGENT_SUBJECT,
        clock=lambda: NOW,
    )
    return runtime, controller


def _agent_action(
    artifacts: Any,
    signer: WorkloadSigner,
) -> WorkloadAuthenticatedCapabilityAction:
    evaluated_at = NOW
    return WorkloadAuthenticatedCapabilityAction.issue(
        request=artifacts.request,
        signer=signer,
        request_nonce=artifacts.request.proposal.nonce,
        issued_at=evaluated_at - timedelta(seconds=1),
        expires_at=evaluated_at + timedelta(seconds=30),
    )


def _post_model(client: TestClient, path: str, value: Any) -> Any:
    return client.post(
        path,
        content=value.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


def test_gateway_endpoint_admits_valid_agent_workload_action(
    artifacts: Any,
    identities: CapabilityIdentities,
) -> None:
    runtime, controller = _gateway_runtime(artifacts, identities)
    client = TestClient(create_gateway_app(lambda: runtime))

    response = _post_model(
        client,
        "/v1/capability/actions",
        _agent_action(artifacts, identities.agent_signer),
    )

    assert response.status_code == 200, response.text
    assert SegmentedCapabilityClosedLoopResult.model_validate_json(response.content) == (
        controller.result
    )
    assert controller.calls == 1
    admission = runtime.authorization.gateway.evidence.records[0]
    assert admission.payload["event_type"] == "workload_identity_admission"
    assert admission.payload["subject"] == AGENT_SUBJECT
    assert admission.payload["trust_bundle_sequence"] == 1
    assert "private" not in str(admission.payload).lower()


@pytest.mark.parametrize("failure", ["invalid-proof", "revoked-credential"])
def test_gateway_endpoint_rejects_agent_before_controller(
    artifacts: Any,
    identities: CapabilityIdentities,
    failure: str,
) -> None:
    runtime, controller = _gateway_runtime(artifacts, identities)
    action = _agent_action(artifacts, identities.agent_signer)
    if failure == "invalid-proof":
        action = action.model_copy(update={"signature": "invalid-agent-proof"})
    else:
        identities.write_bundle(
            sequence=2,
            bundle_id="capability-agent-revocation-0002",
            revocations=(
                WorkloadRevocation(
                    credential_id=action.sender_credential.credential.credential_id,
                    revoked_at=NOW,
                    reason="agent credential revoked by test",
                ),
            ),
        )
    client = TestClient(create_gateway_app(lambda: runtime))

    response = _post_model(client, "/v1/capability/actions", action)

    assert response.status_code == 403
    assert controller.calls == 0


def test_gateway_endpoint_maps_unavailable_trust_bundle_to_503(
    artifacts: Any,
    identities: CapabilityIdentities,
) -> None:
    runtime, controller = _gateway_runtime(artifacts, identities)
    action = _agent_action(artifacts, identities.agent_signer)
    identities.bundle_path.unlink()
    client = TestClient(create_gateway_app(lambda: runtime))

    response = _post_model(client, "/v1/capability/actions", action)

    assert response.status_code == 503
    assert response.json()["reason"] == "gateway_runtime_unavailable"
    assert controller.calls == 0


def test_gateway_health_does_not_report_ready_when_workload_preflight_fails(
    artifacts: Any,
    identities: CapabilityIdentities,
) -> None:
    runtime, controller = _gateway_runtime(artifacts, identities)
    controller.plc = UnreadyWorkloadPort()
    client = TestClient(create_gateway_app(lambda: runtime))

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["reason"] == "gateway_runtime_unavailable"


@dataclass
class WorkloadDevice:
    acknowledgment_key_id: str
    acknowledgment_private_key: Ed25519PrivateKey
    acknowledgment: PlcCommandAcknowledgment
    plc_id: str = PLC_ID
    boot_epoch: str = OT_BOOT
    scan_counter: int = 0
    calls: int = 0

    def execute(self, **_: Any) -> PlcCommandAcknowledgment:
        self.calls += 1
        self.scan_counter += 1
        return self.acknowledgment


@dataclass(frozen=True)
class OtHarness:
    runtime: CapabilityOtRuntime
    device: WorkloadDevice
    replay: DurableWorkloadReplayLedger
    dispatch: SegmentedCapabilityDispatch


def _workload_transaction(
    artifacts: Any,
    identities: CapabilityIdentities,
) -> tuple[SegmentedCapabilityDispatch, PlcCommandAcknowledgment]:
    ot_key_id = identities.ot_signer.credential.credential.key_id
    permit = artifacts.permit.model_copy(
        update={"target_plc_key_id": ot_key_id, "signature": ""}
    ).signed(artifacts.permit_private)
    dispatch = SegmentedCapabilityDispatch(
        request=artifacts.request,
        pre_observation=artifacts.pre_observation,
        decision=artifacts.decision,
        assessment=artifacts.assessment,
        permit=permit,
    )
    acknowledgment = artifacts.acknowledgment.model_copy(
        update={
            "permit_digest": permit.digest,
            "plc_key_id": ot_key_id,
            "signature": "",
        }
    ).signed(identities.ot_signer.private_key)
    return dispatch, acknowledgment


def _ot_runtime(
    artifacts: Any,
    identities: CapabilityIdentities,
    tmp_path: Path,
) -> OtHarness:
    verifier = identities.verifier()
    gateway_binding = WorkloadCredentialBinding(
        verifier=verifier,
        credential_path=identities.gateway_credential_path,
        expected_role=WorkloadRole.GATEWAY,
        expected_audience=OT_CAPABILITY_AUDIENCE,
        expected_subject=GATEWAY_SUBJECT,
    )
    ot_binding = WorkloadCredentialBinding(
        verifier=verifier,
        credential_path=identities.ot_credential_path,
        expected_role=WorkloadRole.OT_ADAPTER,
        expected_audience=GATEWAY_CAPABILITY_AUDIENCE,
        expected_subject=OT_SUBJECT,
    )
    local_identity = LocalWorkloadIdentity(
        binding=ot_binding,
        signer=identities.ot_signer,
    )
    dispatch, acknowledgment = _workload_transaction(artifacts, identities)
    ot_key_id = identities.ot_signer.credential.credential.key_id
    gateway_key_id = identities.gateway_signer.credential.credential.key_id
    device = WorkloadDevice(
        acknowledgment_key_id=ot_key_id,
        acknowledgment_private_key=identities.ot_signer.private_key,
        acknowledgment=acknowledgment,
    )
    tmp_path.chmod(0o700)
    replay = DurableWorkloadReplayLedger(
        tmp_path / "workload-transport-replay.json",
        audience=OT_CAPABILITY_AUDIENCE,
        trust_domain=TRUST_DOMAIN,
        workload_subject=GATEWAY_SUBJECT,
        authority_key_id=identities.authority_key_id,
        initialize=True,
    )
    semantic = OrderlyRestartReplayReservations(
        tmp_path / "semantic-replay.json",
        initialize=True,
    )
    runtime = CapabilityOtRuntime(
        device=cast(Any, device),
        transport_replay=replay,
        gateway_public_key=identities.gateway_signer.private_key.public_key(),
        gateway_key_id=gateway_key_id,
        observer_info=_observer_info(artifacts),
        permit_public_key=artifacts.permit_private.public_key(),
        permit_key_id=artifacts.permit_key_id,
        private_key=identities.ot_signer.private_key,
        key_id=ot_key_id,
        plc_id=PLC_ID,
        boot_epoch=OT_BOOT,
        plant_info=_plant_health(artifacts),
        semantic_replay=semantic,
        gateway_workload_identity=gateway_binding,
        local_workload_identity=local_identity,
        clock=lambda: NOW,
    )
    return OtHarness(runtime=runtime, device=device, replay=replay, dispatch=dispatch)


def _gateway_dispatch(
    harness: OtHarness,
    signer: WorkloadSigner,
    *,
    nonce: str,
) -> WorkloadSignedCapabilityDispatch:
    return WorkloadSignedCapabilityDispatch.issue(
        dispatch=harness.dispatch,
        signer=signer,
        transport_nonce=nonce,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=10),
    )


def test_ot_endpoint_admits_dispatch_and_returns_verified_response_once(
    artifacts: Any,
    identities: CapabilityIdentities,
    tmp_path: Path,
) -> None:
    harness = _ot_runtime(artifacts, identities, tmp_path)
    request = _gateway_dispatch(
        harness,
        identities.gateway_signer,
        nonce="workload-ot-valid-transport-nonce-0001",
    )
    client = TestClient(create_ot_app(lambda: harness.runtime))

    response = _post_model(client, "/v1/capability/execute", request)
    replay = _post_model(client, "/v1/capability/execute", request)

    assert response.status_code == 200
    signed_response = WorkloadSignedCapabilityResponse.model_validate_json(response.content)
    assert signed_response.verify_for_request(
        identities.ot_signer.private_key.public_key(),
        request=request,
        expected_plc_id=PLC_ID,
        expected_plc_boot_epoch=OT_BOOT,
        evaluated_at=NOW,
    )
    assert replay.status_code == 409
    assert harness.replay.reservation_count == 1
    assert harness.device.calls == 1
    harness.replay.close()


def test_invalid_gateway_proof_does_not_poison_transport_nonce(
    artifacts: Any,
    identities: CapabilityIdentities,
    tmp_path: Path,
) -> None:
    harness = _ot_runtime(artifacts, identities, tmp_path)
    nonce = "workload-ot-invalid-proof-nonce-0001"
    valid = _gateway_dispatch(harness, identities.gateway_signer, nonce=nonce)
    invalid = valid.model_copy(update={"signature": "invalid-gateway-proof"})
    client = TestClient(create_ot_app(lambda: harness.runtime))

    rejected = _post_model(client, "/v1/capability/execute", invalid)
    admitted = _post_model(client, "/v1/capability/execute", valid)

    assert rejected.status_code == 403
    assert admitted.status_code == 200
    assert harness.replay.reservation_count == 1
    assert harness.device.calls == 1
    harness.replay.close()


def test_revoked_gateway_credential_does_not_poison_nonce_and_rotation_succeeds(
    artifacts: Any,
    identities: CapabilityIdentities,
    tmp_path: Path,
) -> None:
    harness = _ot_runtime(artifacts, identities, tmp_path)
    nonce = "workload-ot-revoked-gateway-nonce-0001"
    revoked = _gateway_dispatch(harness, identities.gateway_signer, nonce=nonce)
    identities.write_bundle(
        sequence=2,
        bundle_id="capability-gateway-revocation-0002",
        revocations=(
            WorkloadRevocation(
                credential_id=(
                    identities.gateway_signer.credential.credential.credential_id
                ),
                revoked_at=NOW,
                reason="gateway credential revoked by test",
            ),
        ),
    )
    client = TestClient(create_ot_app(lambda: harness.runtime))

    rejected = _post_model(client, "/v1/capability/execute", revoked)
    rotated_signer = identities.rotate_gateway("capability-gateway-rotated-credential-0002")
    valid = _gateway_dispatch(harness, rotated_signer, nonce=nonce)
    admitted = _post_model(client, "/v1/capability/execute", valid)

    assert rejected.status_code == 403
    assert admitted.status_code == 200
    assert harness.replay.reservation_count == 1
    assert harness.device.calls == 1
    harness.replay.close()


def test_gateway_leaf_rotation_cannot_reset_durable_transport_replay(
    artifacts: Any,
    identities: CapabilityIdentities,
    tmp_path: Path,
) -> None:
    harness = _ot_runtime(artifacts, identities, tmp_path)
    nonce = "workload-ot-leaf-rotation-replay-nonce-0001"
    original = _gateway_dispatch(harness, identities.gateway_signer, nonce=nonce)
    client = TestClient(create_ot_app(lambda: harness.runtime))
    first = _post_model(client, "/v1/capability/execute", original)

    rotated_signer = identities.rotate_gateway("capability-gateway-rotated-credential-0003")
    rotated_replay = _gateway_dispatch(harness, rotated_signer, nonce=nonce)
    second = _post_model(client, "/v1/capability/execute", rotated_replay)

    assert first.status_code == 200
    assert second.status_code == 409
    assert harness.replay.reservation_count == 1
    assert harness.device.calls == 1
    harness.replay.close()
