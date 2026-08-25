from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis_ot.crypto import decode_urlsafe_b64
from aegis_ot.segmented_runtime import (
    SignedSegmentedExecutionRequest,
    SignedSegmentedExecutionResponse,
)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATHS = (
    ROOT / "results" / "m4f-durable-transport-replay-evidence.json",
    ROOT / "results" / "m4f-durable-transport-replay-evidence-reproduction.json",
)
EXPECTED_COMMIT = "815712aa656905a28a3d4412137ba989506a7c3c"
EXPECTED_SEMANTIC_SHA256 = "447023e0541f7bc44e9f2c35421e19871b86b93e547abb23a779fc917eede1b4"
EXPECTED_ACCEPTANCE = {
    "adapter_boot_epoch_changed",
    "corrupt_ledger_failed_closed_without_effect",
    "durable_exact_replay_rejected_without_mutation",
    "exact_artifacts_verify_offline",
    "fresh_request_after_restart_preserved_liveness",
    "ledger_snapshot_canonical_and_bound",
    "only_ot_adapter_was_replaced",
    "replay_volume_initialized_closed_and_private",
    "restart_request_prepared_immediately_before_replacement",
    "same_boot_transport_campaign_accepted",
    "signed_agent_campaign_accepted",
}
EXPECTED_OFFLINE_VERIFICATION = {
    "corrupt_fault_request_audience_verified_offline",
    "corrupt_fault_request_key_id_verified_offline",
    "corrupt_fault_request_signature_verified_offline",
    "full_request_audience_verified_offline",
    "full_request_gateway_key_id_verified_offline",
    "full_request_signature_verified_offline",
    "full_response_decision_binding_verified_offline",
    "full_response_ot_key_id_verified_offline",
    "full_response_proposal_binding_verified_offline",
    "full_response_request_binding_verified_offline",
    "full_response_signature_verified_offline",
    "prepared_request_audience_verified_offline",
    "prepared_request_gateway_key_id_verified_offline",
    "prepared_request_signature_verified_offline",
    "prepared_response_decision_binding_verified_offline",
    "prepared_response_ot_key_id_verified_offline",
    "prepared_response_proposal_binding_verified_offline",
    "prepared_response_request_binding_verified_offline",
    "prepared_response_signature_verified_offline",
}
EXPECTED_BOUNDARIES = {
    "Durable at-most-once exact-envelope admission, not exactly-once effects",
    "A lost response after dispatch remains outcome-unknown until observation reconciliation",
    "One Uvicorn process and one OT-adapter writer; no multi-replica coordination",
    "Intact trusted Docker volume; no hostile-host rollback or external monotonic anchor",
    (
        "Process-exit fsync checks ran on the host filesystem; they are code-path evidence, "
        "not Docker-volume or power-loss durability evidence"
    ),
    "Ephemeral Ed25519 message authentication, not SPIFFE, TLS peer identity, or revocation",
    "Synthetic single-host execution, not production OT or independent external validation",
}
NON_TARGET_SERVICES = {"observer", "opa", "segmented-gateway", "simulation"}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _model_sha256(value: SignedSegmentedExecutionRequest) -> str:
    return hashlib.sha256(_canonical_bytes(value.model_dump(mode="json"))).hexdigest()


def _public_key(material: dict[str, Any], role: str) -> Ed25519PublicKey:
    encoded = material[f"{role}_public_key_base64"]
    raw = base64.b64decode(encoded, validate=True)
    assert len(raw) == 32
    assert base64.b64encode(raw).decode("ascii") == encoded
    assert hashlib.sha256(raw).hexdigest() == material[f"{role}_public_key_sha256"]
    return Ed25519PublicKey.from_public_bytes(raw)


def _verify_request(
    value: dict[str, Any],
    gateway_public: Ed25519PublicKey,
    material: dict[str, Any],
) -> SignedSegmentedExecutionRequest:
    request = SignedSegmentedExecutionRequest.model_validate(value)
    assert request.audience == "aegis-ot:ot-adapter"
    assert request.gateway_key_id == material["gateway_key_id"]
    gateway_public.verify(
        decode_urlsafe_b64(request.signature),
        _canonical_bytes(request.model_dump(mode="json", exclude={"signature"})),
    )
    assert request.request.decision.proposal_id == request.request.proposal.proposal_id
    return request


def _verify_response(
    value: dict[str, Any],
    request: SignedSegmentedExecutionRequest,
    ot_public: Ed25519PublicKey,
    material: dict[str, Any],
) -> SignedSegmentedExecutionResponse:
    response = SignedSegmentedExecutionResponse.model_validate(value)
    assert response.ot_key_id == material["ot_key_id"]
    ot_public.verify(
        decode_urlsafe_b64(response.signature),
        _canonical_bytes(response.model_dump(mode="json", exclude={"signature"})),
    )
    assert response.request_sha256 == _model_sha256(request)
    assert response.execution.proposal_id == request.request.proposal.proposal_id
    assert response.execution.decision_id == request.request.decision.decision_id
    return response


def _semantic_transport(value: dict[str, Any]) -> dict[str, Any]:
    valid = value["valid_key_holder"]
    resigned = value["resigned_same_inner_request"]
    return {
        "accepted": value["accepted"],
        "replay_mode": value["health_before"]["replay_mode"],
        "unsigned_status": value["unsigned"]["http_status"],
        "forged_status": value["forged_signature"]["http_status"],
        "valid_status": valid["http_status"],
        "valid_executed": valid["executed"],
        "valid_response_verified": valid["response_signature_verified"],
        "same_boot_replay_status": value["exact_same_boot_replay"]["http_status"],
        "tamper_status": value["post_signature_tamper"]["http_status"],
        "resigned_status": resigned["http_status"],
        "resigned_executed": resigned["executed"],
        "resigned_reason": resigned["reason"],
        "state_version_delta": (
            value["state_after_valid"]["version"] - value["state_before"]["version"]
        ),
        "reservation_delta": (
            value["health_after"]["replay_reservations"]
            - value["health_before"]["replay_reservations"]
        ),
    }


def _semantic_prepare(value: dict[str, Any]) -> dict[str, Any]:
    prepared = value["prepared_request"]
    return {
        "accepted": value["accepted"],
        "http_status": prepared["http_status"],
        "executed": prepared["executed"],
        "response_verified": prepared["response_signature_verified"],
        "reservation_delta": (
            value["health_after"]["replay_reservations"]
            - value["health_before"]["replay_reservations"]
        ),
        "state_version_delta": (value["state_after"]["version"] - value["state_before"]["version"]),
    }


def _semantic_restart(value: dict[str, Any]) -> dict[str, Any]:
    replay = value["exact_restart_replay"]
    fresh = value["fresh_after_restart"]
    return {
        "accepted": value["accepted"],
        "replay_status": replay["http_status"],
        "replay_within_window": replay["response_within_original_validity_window"],
        "fresh_status": fresh["http_status"],
        "fresh_executed": fresh["executed"],
        "fresh_response_verified": fresh["response_signature_verified"],
        "replay_reservation_delta": (
            value["health_after_replay"]["replay_reservations"]
            - value["health_before"]["replay_reservations"]
        ),
        "fresh_reservation_delta": (
            value["health_after_fresh"]["replay_reservations"]
            - value["health_after_replay"]["replay_reservations"]
        ),
        "fresh_state_version_delta": (
            value["state_after_fresh"]["version"] - value["state_after_replay"]["version"]
        ),
    }


def _normalized_networks(value: dict[str, Any]) -> dict[str, Any]:
    project_name = value["project_name"]
    return {
        network: [name.replace(project_name, "<compose-project>") for name in members]
        for network, members in value["network_inventory"].items()
    }


def _recomputed_semantic_sha256(value: dict[str, Any]) -> str:
    agent_probe = deepcopy(value["agent_probe"])
    agent_probe.pop("agent_hostname")
    fault = value["corrupt_ledger_probe"]
    semantic = {
        "git_commit": value["git_commit"],
        "normalized_compose_sha256": value["normalized_compose_sha256"],
        "source_package_directory": value["source_checkout_binding"]["package_directory"],
        "network_inventory": _normalized_networks(value),
        "agent_probe": agent_probe,
        "transport_probe": _semantic_transport(value["transport_probe"]),
        "prepare_restart_probe": _semantic_prepare(value["prepare_restart_probe"]),
        "restart_probe": _semantic_restart(value["restart_probe"]),
        "ledger_fault": {
            "accepted": fault["accepted"],
            "http_status": fault["request"]["http_status"],
            "state_version_delta": (
                fault["state_after"]["version"] - fault["state_before"]["version"]
            ),
        },
        "offline_verification": value["offline_artifact_verification"],
        "acceptance": value["acceptance"],
    }
    return hashlib.sha256(_canonical_bytes(semantic)).hexdigest()


def _semantic_state(value: dict[str, Any]) -> dict[str, Any]:
    state = dict(value)
    state.pop("observed_at")
    return state


def _assert_ledger_snapshot(
    snapshot: dict[str, Any],
    material: dict[str, Any],
) -> list[dict[str, str]]:
    raw = base64.b64decode(snapshot["bytes_base64"], validate=True)
    document = json.loads(raw)
    assert snapshot["canonical"] is True
    assert hashlib.sha256(raw).hexdigest() == snapshot["sha256"]
    assert raw == _canonical_bytes(document)
    assert document == snapshot["document"]
    assert document["schema_version"] == "m4f-transport-replay-ledger-v1"
    assert document["audience"] == "aegis-ot:ot-adapter"
    assert document["gateway_key_id"] == material["gateway_key_id"]
    assert document["gateway_public_key_sha256"] == material["gateway_public_key_sha256"]
    reservations = document["reservations"]
    assert reservations == sorted(reservations, key=lambda item: item["nonce"])
    assert len({item["nonce"] for item in reservations}) == len(reservations)
    assert len({item["signed_request_sha256"] for item in reservations}) == len(reservations)
    assert all(len(item["signed_request_sha256"]) == 64 for item in reservations)
    return reservations


@pytest.fixture(params=EVIDENCE_PATHS, ids=("primary", "reproduction"))
def evidence(request: pytest.FixtureRequest) -> dict[str, Any]:
    return _load(request.param)


def test_m4f_retained_pair_locks_execution_acceptance_and_semantics(
    evidence: dict[str, Any],
) -> None:
    assert evidence["schema_version"] == "m4f-durable-transport-replay-experiment-v1"
    assert evidence["analyst"] == "Angelis Pseftis"
    assert evidence["git_commit"] == EXPECTED_COMMIT
    assert evidence["clean_checkout_start"] is True
    assert evidence["clean_checkout_end"] is True
    assert evidence["source_checkout_binding"]["package_directory"] == "src/aegis_ot"
    assert evidence["accepted"] is True
    assert set(evidence["acceptance"]) == EXPECTED_ACCEPTANCE
    assert all(value is True for value in evidence["acceptance"].values())
    assert set(evidence["offline_artifact_verification"]) == EXPECTED_OFFLINE_VERIFICATION
    assert all(value is True for value in evidence["offline_artifact_verification"].values())
    assert evidence["semantic_outcome_sha256"] == EXPECTED_SEMANTIC_SHA256
    assert _recomputed_semantic_sha256(evidence) == EXPECTED_SEMANTIC_SHA256

    comparison = evidence["reproduction_comparison"]
    assert comparison["semantic_outcomes_match"] is True
    assert comparison["primary_semantic_outcome_sha256"] == EXPECTED_SEMANTIC_SHA256
    assert comparison["reproduction_semantic_outcome_sha256"] == EXPECTED_SEMANTIC_SHA256
    assert comparison["role"] in {"primary", "reproduction"}


def test_m4f_retained_public_artifacts_verify_independently(
    evidence: dict[str, Any],
) -> None:
    material = evidence["public_verification_material"]
    gateway_public = _public_key(material, "gateway")
    ot_public = _public_key(material, "ot")

    paired_records = (
        evidence["transport_probe"]["valid_key_holder"],
        evidence["transport_probe"]["resigned_same_inner_request"],
        evidence["prepare_restart_probe"]["prepared_request"],
        evidence["restart_probe"]["fresh_after_restart"],
    )
    for record in paired_records:
        signed_request = _verify_request(record["signed_request"], gateway_public, material)
        _verify_response(record["signed_response"], signed_request, ot_public, material)
        if "request_sha256" in record:
            assert record["request_sha256"] == _model_sha256(signed_request)

    request_only_records = (
        evidence["restart_probe"]["exact_restart_replay"],
        evidence["corrupt_ledger_probe"]["request"],
    )
    for record in request_only_records:
        signed_request = _verify_request(record["signed_request"], gateway_public, material)
        assert record["request_sha256"] == _model_sha256(signed_request)


def test_m4f_retained_ledger_and_restart_measurements_are_bound(
    evidence: dict[str, Any],
) -> None:
    material = evidence["public_verification_material"]
    prepared = evidence["prepare_restart_probe"]["prepared_request"]
    replay = evidence["restart_probe"]["exact_restart_replay"]
    fresh = evidence["restart_probe"]["fresh_after_restart"]
    prepared_request = SignedSegmentedExecutionRequest.model_validate(prepared["signed_request"])
    fresh_request = SignedSegmentedExecutionRequest.model_validate(fresh["signed_request"])

    before_reservations = _assert_ledger_snapshot(evidence["ledger_before_restart"], material)
    after_reservations = _assert_ledger_snapshot(
        evidence["ledger_after_fresh_request"],
        material,
    )
    prepared_reservation = {
        "nonce": prepared_request.transport_nonce,
        "signed_request_sha256": _model_sha256(prepared_request),
    }
    fresh_reservation = {
        "nonce": fresh_request.transport_nonce,
        "signed_request_sha256": _model_sha256(fresh_request),
    }
    assert len(before_reservations) == 4
    assert len(after_reservations) == 5
    assert prepared_reservation in before_reservations
    assert prepared_reservation in after_reservations
    assert fresh_reservation not in before_reservations
    assert fresh_reservation in after_reservations

    assert prepared["request_sha256"] == _model_sha256(prepared_request)
    assert replay["signed_request"] == prepared["signed_request"]
    assert replay["request_sha256"] == prepared["request_sha256"]
    assert replay["http_status"] == 409
    assert replay["response"] == {"detail": "transport request replayed"}
    assert replay["response_within_original_validity_window"] is True
    assert replay["validity_margin_at_send_seconds"] >= 5.0

    prepare_health = evidence["prepare_restart_probe"]["health_after"]
    restart = evidence["restart_probe"]
    replay_health = restart["health_after_replay"]
    fresh_health = restart["health_after_fresh"]
    assert prepare_health["replay_ledger_sha256"] == evidence["ledger_before_restart"]["sha256"]
    assert (
        restart["health_before"]["replay_ledger_sha256"] == prepare_health["replay_ledger_sha256"]
    )
    assert replay_health["replay_ledger_sha256"] == prepare_health["replay_ledger_sha256"]
    assert replay_health["replay_reservations"] == restart["health_before"]["replay_reservations"]
    assert fresh_health["replay_ledger_sha256"] == evidence["ledger_after_fresh_request"]["sha256"]
    assert restart["state_after_replay"]["version"] == restart["state_before"]["version"]
    assert _semantic_state(restart["state_after_replay"]) == _semantic_state(
        restart["state_before"]
    )
    assert restart["state_after_fresh"]["version"] == (restart["state_after_replay"]["version"] + 1)
    assert fresh_health["replay_reservations"] == replay_health["replay_reservations"] + 1

    fault = evidence["corrupt_ledger_probe"]
    assert fault["request"]["http_status"] == 503
    assert fault["request"]["response"] == {"detail": "transport replay ledger unavailable"}
    assert fault["state_after"]["version"] == fault["state_before"]["version"]
    assert _semantic_state(fault["state_after"]) == _semantic_state(fault["state_before"])


def test_m4f_retained_restart_replaced_only_the_ot_adapter(
    evidence: dict[str, Any],
) -> None:
    before = evidence["service_identities_before_replacement"]
    after = evidence["service_identities_after_replacement"]
    assert set(before) == NON_TARGET_SERVICES | {"ot-adapter"}
    assert set(after) == set(before)
    assert all(before[service] == after[service] for service in NON_TARGET_SERVICES)

    before_ot = before["ot-adapter"]
    after_ot = after["ot-adapter"]
    assert before_ot["container_id"] != after_ot["container_id"]
    assert before_ot["created"] != after_ot["created"]
    assert before_ot["started_at"] != after_ot["started_at"]
    assert before_ot["image_id"] == after_ot["image_id"]
    assert before_ot["volume_mounts"] == after_ot["volume_mounts"]
    assert before_ot["running"] is True
    assert after_ot["running"] is True
    assert evidence["prepare_restart_probe"]["health_after"]["boot_epoch"]
    assert evidence["restart_probe"]["health_before"]["boot_epoch"]
    assert (
        evidence["prepare_restart_probe"]["health_after"]["boot_epoch"]
        != evidence["restart_probe"]["health_before"]["boot_epoch"]
    )


def test_m4f_retained_cleanup_and_claim_boundaries_are_explicit(
    evidence: dict[str, Any],
) -> None:
    assert evidence["cleanup"] == {
        "compose_project_removed": True,
        "private_key_directory_removed": True,
        "probe_volume_removed": True,
        "replay_volume_removed": True,
    }
    assert evidence["private_key_material_retained"] is False
    assert set(evidence["evidence_boundary"]) == EXPECTED_BOUNDARIES

    boundaries = " ".join(evidence["evidence_boundary"]).lower()
    assert "at-most-once exact-envelope" in boundaries
    assert "one ot-adapter writer" in boundaries
    assert "intact trusted docker volume" in boundaries
    assert "host filesystem" in boundaries
    assert "not docker-volume or power-loss durability evidence" in boundaries
    assert "not production ot or independent external validation" in boundaries
