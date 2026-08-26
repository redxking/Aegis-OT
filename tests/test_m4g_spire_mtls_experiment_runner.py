from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("run_m4g_spire_mtls_experiment")


def _pinned(name: str) -> str:
    return f"example.invalid/{name}:1.0@sha256:" + hashlib.sha256(name.encode()).hexdigest()


def _volume() -> dict[str, Any]:
    return {
        "type": "volume",
        "source": "spire-agent-socket",
        "target": "/run/spire/agent/public",
        "read_only": True,
    }


def _compose(runner: Any) -> dict[str, Any]:
    services: dict[str, Any] = {
        "opa": {"image": _pinned("opa")},
        "spire-server": {"image": _pinned("spire-server")},
        "spire-agent": {"image": _pinned("spire-agent")},
        "spire-storage-init": {"image": _pinned("busybox")},
        "spire-bootstrap": {
            "build": {
                "args": {
                    "SPIRE_SERVER_IMAGE": _pinned("spire-server"),
                    "BUSYBOX_IMAGE": _pinned("busybox"),
                }
            }
        },
        "replay-init": {"environment": {"AEGIS_WORKLOAD_IDENTITY_MODE": "required"}},
        "identity-init": {
            "environment": {"AEGIS_AGENT_ACTOR_ID": "agent:operator-1"}
        },
        "agent-probe": {
            "environment": {
                "AEGIS_WORKLOAD_IDENTITY_MODE": "required",
                "AEGIS_GATEWAY_URL": "http://segmented-gateway:8081",
                "AEGIS_AGENT_ACTOR_ID": "agent:operator-1",
            }
        },
    }
    client_peers = {
        "segmented-gateway": {
            "observer": runner.WORKLOADS["observer"][1],
            "candidate": runner.WORKLOADS["candidate"][1],
            "ot-adapter": runner.WORKLOADS["ot-adapter"][1],
        },
        "observer": {"simulation": runner.WORKLOADS["simulation"][1]},
        "candidate": {"simulation": runner.WORKLOADS["simulation"][1]},
        "ot-adapter": {
            "observer": runner.WORKLOADS["observer"][1],
            "simulation": runner.WORKLOADS["simulation"][1],
        },
    }
    urls = {
        "segmented-gateway": {
            "AEGIS_OBSERVER_URL": "https://observer:8082",
            "AEGIS_CANDIDATE_URL": "https://candidate:8085",
            "AEGIS_OT_URL": "https://ot-adapter:8083",
        },
        "observer": {"AEGIS_PLANT_URL": "https://simulation:8084"},
        "candidate": {"AEGIS_PLANT_URL": "https://simulation:8084"},
        "ot-adapter": {
            "AEGIS_OBSERVER_URL": "https://observer:8082",
            "AEGIS_PLANT_URL": "https://simulation:8084",
        },
    }
    allowed = {
        "observer": [
            runner.WORKLOADS["segmented-gateway"][1],
            runner.WORKLOADS["ot-adapter"][1],
        ],
        "candidate": [runner.WORKLOADS["segmented-gateway"][1]],
        "ot-adapter": [runner.WORKLOADS["segmented-gateway"][1]],
        "simulation": [
            runner.WORKLOADS["observer"][1],
            runner.WORKLOADS["candidate"][1],
            runner.WORKLOADS["ot-adapter"][1],
        ],
    }
    for service, (user, spiffe_id) in runner.WORKLOADS.items():
        uid, gid = user.split(":", 1)
        if service == "segmented-gateway":
            entrypoint = [
                "python",
                "-m",
                "aegis_ot.spire_workload_identity",
                "--expected-spiffe-id",
                spiffe_id,
                "--",
            ]
        else:
            entrypoint = [
                "python",
                "-m",
                "aegis_ot.spire_mtls",
                "serve",
                "--expected-spiffe-id",
                spiffe_id,
            ]
            for client_id in allowed[service]:
                entrypoint.extend(("--allowed-client-spiffe-id", client_id))
        environment: dict[str, Any] = {
            "SPIFFE_ENDPOINT_SOCKET": "unix:///run/spire/agent/public/api.sock",
            "AEGIS_SPIFFE_ID": spiffe_id,
            "AEGIS_SPIRE_MTLS_TMPDIR": "/run/aegis-spire-mtls",
        }
        if service in runner.MTLS_CLIENT_SERVICES:
            environment.update(
                {
                    "AEGIS_SPIRE_MTLS_MODE": "required",
                    "AEGIS_SPIFFE_PEER_IDS": json.dumps(client_peers[service], sort_keys=True),
                    **urls[service],
                }
            )
        if service in runner.MTLS_SERVER_SERVICES:
            environment["AEGIS_SPIRE_MTLS_MODE"] = "required"
        if service in {"segmented-gateway", "ot-adapter"}:
            environment["AEGIS_WORKLOAD_IDENTITY_MODE"] = "required"
        if service == "segmented-gateway":
            environment["AEGIS_AGENT_ACTOR_ID"] = "agent:operator-1"
        services[service] = {
            "user": user,
            "entrypoint": entrypoint,
            "environment": environment,
            "volumes": [_volume()],
            "tmpfs": [
                "/run/aegis-spire-mtls:rw,noexec,nosuid,nodev,"
                f"size=1m,mode=0700,uid={uid},gid={gid}"
            ],
        }
    return {"services": services}


def _query(
    runner: Any,
    service: str,
    fingerprint: str,
    *,
    accepted: bool = True,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    user, expected_id = runner.WORKLOADS[service]
    uid, gid = user.split(":", 1)
    value: dict[str, Any] = {
        "schema_version": "m4g-spire-identity-query-v1",
        "expected_spiffe_id": expected_id,
        "accepted": accepted,
        "service": service,
        "configured_user": user,
        "unix_uid": uid,
        "primary_gid": gid,
    }
    if accepted:
        value.update(
            {
                "spiffe_id": expected_id,
                "fetched_at": now.isoformat(),
                "not_before": (now - timedelta(seconds=5)).isoformat(),
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                "certificate_sha256": fingerprint * 64,
            }
        )
    else:
        value.update(
            {
                "error_type": "WorkloadIdentityError",
                "reason": "SPIRE Workload API fetch failed",
            }
        )
    return value


def test_compose_prefix_closes_exact_six_overlay_order_and_project_scope(
    runner: Any,
) -> None:
    prefix = runner._compose_prefix("aegis-ot-m4g-spire-mtls-test")
    assert [prefix[index + 1] for index, item in enumerate(prefix) if item == "-f"] == [
        "docker-compose.yml",
        "docker-compose.auth.yml",
        "docker-compose.replay.yml",
        "docker-compose.capability.yml",
        "docker-compose.identity.yml",
        "docker-compose.spire.yml",
    ]
    assert len(runner.COMPOSE_OVERLAYS) == 6

    runner._validate_project_name("aegis-ot-m4g-spire-mtls-test")
    with pytest.raises(runner.m4d.ExperimentError, match="Compose name"):
        runner._validate_project_name("../../not-scoped")


def test_embedded_container_probes_are_valid_python(runner: Any) -> None:
    compile(runner._IDENTITY_QUERY_CODE, "<m4g-spire-identity-query>", "exec")
    compile(runner._PREPARE_FRESH_ACTION_CODE, "<m4g-spire-fresh-action>", "exec")
    compile(runner._MTLS_HEALTH_CODE, "<m4g-spire-mtls-health>", "exec")


def test_configuration_binding_requires_both_modes_exact_users_and_mtls(
    runner: Any,
) -> None:
    binding = runner._configuration_binding(_compose(runner))

    assert binding["all_critical_external_references_digest_pinned"] is True
    assert binding["application_workload_identity_required"] is True
    assert binding["all_workload_bindings_match"] is True
    assert binding["all_mtls_client_modes_required"] is True
    assert binding["all_internal_servers_require_spiffe_mtls"] is True
    assert binding["workload_bindings"]["observer"]["expected_user"] == "65532:65533"
    assert binding["workload_bindings"]["observer"]["mtls_private_tmpfs"] is True
    assert binding["agent_ingress_boundary"] == {
        "agent_probe_has_spire_svid": False,
        "agent_to_gateway_url": "http://segmented-gateway:8081",
        "agent_to_gateway_transport": "http",
        "agent_to_gateway_application_authentication": (
            "authority-signed M4g workload capability action"
        ),
        "credential_issuer_actor_id": "agent:operator-1",
        "agent_proposal_actor_id": "agent:operator-1",
        "gateway_authorized_actor_id": "agent:operator-1",
        "matches_expected": True,
    }

    wrong_mode = _compose(runner)
    wrong_mode["services"]["segmented-gateway"]["environment"]["AEGIS_SPIRE_MTLS_MODE"] = "disabled"
    assert runner._configuration_binding(wrong_mode)["all_mtls_client_modes_required"] is False

    wrong_peer = _compose(runner)
    wrong_peer["services"]["candidate"]["environment"]["AEGIS_SPIFFE_PEER_IDS"] = json.dumps(
        {"simulation": runner.WORKLOADS["observer"][1]}
    )
    assert runner._configuration_binding(wrong_peer)["all_mtls_client_modes_required"] is False

    wrong_user = _compose(runner)
    wrong_user["services"]["observer"]["user"] = "65532:65532"
    assert runner._configuration_binding(wrong_user)["all_workload_bindings_match"] is False

    wrong_actor = _compose(runner)
    wrong_actor["services"]["segmented-gateway"]["environment"][
        "AEGIS_AGENT_ACTOR_ID"
    ] = "agent:other-operator"
    assert (
        runner._configuration_binding(wrong_actor)["agent_ingress_boundary"][
            "matches_expected"
        ]
        is False
    )

    wrong_issuer_actor = _compose(runner)
    wrong_issuer_actor["services"]["identity-init"]["environment"][
        "AEGIS_AGENT_ACTOR_ID"
    ] = "agent:other-operator"
    assert (
        runner._configuration_binding(wrong_issuer_actor)["agent_ingress_boundary"][
            "matches_expected"
        ]
        is False
    )


def test_identity_query_uses_full_uid_gid_and_retains_no_certificate_body(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    value = _query(runner, "ot-adapter", "a")
    for key in ("service", "configured_user", "unix_uid", "primary_gid"):
        value.pop(key)

    def run(*args: str, **_kwargs: Any) -> SimpleNamespace:
        calls.append(args)
        return SimpleNamespace(stdout=runner._canonical_text(value), returncode=0)

    monkeypatch.setattr(runner.m4d, "_run", run)
    result = runner._query_identity(
        ("docker", "compose"),
        service="ot-adapter",
        user="65532:65535",
        expected_spiffe_id=runner.WORKLOADS["ot-adapter"][1],
    )

    assert result["accepted"] is True
    assert result["unix_uid"] == "65532"
    assert result["primary_gid"] == "65535"
    assert "--user" in calls[0]
    assert calls[0][calls[0].index("--user") + 1] == "65532:65535"
    assert "CERTIFICATE" not in json.dumps(result)


def test_identity_acceptance_requires_five_gid_distinguished_svids(
    runner: Any,
) -> None:
    identities = {
        service: _query(runner, service, f"{index + 1:x}")
        for index, service in enumerate(runner.WORKLOADS)
    }
    assert all(runner._identity_acceptance(identities).values())

    identities["observer"]["configured_user"] = "65532:65532"
    assert not runner._identity_acceptance(identities)[
        "five_gid_distinguished_svids_issued_and_verified"
    ]


def test_rotation_observation_is_real_issuance_but_bounded_claim(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = _query(runner, "segmented-gateway", "a")
    rotated = _query(runner, "segmented-gateway", "b")
    rotated["expires_at"] = (
        datetime.fromisoformat(initial["expires_at"]) + timedelta(minutes=2)
    ).isoformat()
    monkeypatch.setattr(runner, "_query_identity", lambda *_args, **_kwargs: rotated)
    ticks = iter((0.0, 0.0, 1.0))
    sleeps: list[float] = []

    evidence = runner._await_issued_rotation(
        ("docker", "compose"),
        initial,
        timeout_seconds=10,
        poll_seconds=0.25,
        monotonic=lambda: next(ticks),
        sleeper=sleeps.append,
    )

    assert evidence["issued_rotation_observed"] is True
    assert evidence["fingerprint_changed"] is True
    assert evidence["expiry_advanced"] is True
    assert evidence["measurement"] == "fresh same-selector Workload API query"
    assert evidence["long_running_process_consumption_directly_observed"] is False
    assert sleeps == [0.25]


def test_fetch_loss_does_not_claim_immediate_certificate_revocation(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rejected = _query(runner, "segmented-gateway", "a", accepted=False)
    monkeypatch.setattr(runner, "_query_identity", lambda *_args, **_kwargs: rejected)
    ticks = iter((0.0, 0.0, 0.2))

    evidence = runner._await_fresh_fetch_unavailable(
        ("docker", "compose"),
        timeout_seconds=2,
        poll_seconds=0.1,
        monotonic=lambda: next(ticks),
        sleeper=lambda _seconds: None,
    )

    assert evidence["fresh_fetch_unavailable"] is True
    assert evidence["already_issued_certificate_immediate_revocation_measured"] is False
    assert evidence["already_issued_certificate_immediate_revocation_proven"] is False
    assert "does not establish immediate rejection" in evidence["interpretation"]


def test_prepared_action_returns_wire_separately_from_retained_metadata(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = {
        "schema_version": "m4g-spire-prepared-action-v1",
        "wire_request": {"schema_version": "m4g-workload-capability-action-v1"},
        "wire_request_sha256": "a" * 64,
        "request_sha256": "b" * 64,
        "proposal_id": "fresh-proposal",
        "proposal_nonce": "fresh-nonce-00000000000000000000",
        "observation_id": "fresh-observation",
    }
    monkeypatch.setattr(
        runner.m4d,
        "_run",
        lambda *_args, **_kwargs: SimpleNamespace(
            stdout=runner._canonical_text(prepared), returncode=0
        ),
    )

    wire, metadata = runner._prepare_fresh_action(("docker", "compose"))

    assert wire == {"schema_version": "m4g-workload-capability-action-v1"}
    assert "wire_request" not in metadata
    assert metadata["wire_request_retained"] is False


def test_post_deletion_acceptance_requires_no_ot_dispatch_and_no_plant_effect(
    runner: Any,
) -> None:
    plant = {
        "document": {
            "state_version": 3,
            "state_digest": "a" * 64,
            "apply_requests": 2,
            "commit_count": 2,
        }
    }
    failed_closed = {
        "schema_version": "segmented-capability-closed-loop-result-v1",
        "status": "not_dispatched",
        "reasons": ["pre_observation_unavailable", "CapabilityTransportUnavailable"],
        "dispatch_attempts": 0,
        "acknowledgment": None,
    }
    accepted = runner._post_deletion_acceptance(
        response_status=200,
        response_document=failed_closed,
        fetch_loss={"fresh_fetch_unavailable": True},
        plant_before=plant,
        plant_after=json.loads(json.dumps(plant)),
        ot_before={"execute_endpoint_records": 2},
        ot_after={"execute_endpoint_records": 2},
    )
    assert all(accepted.values())

    assert not runner._post_deletion_acceptance(
        response_status=200,
        response_document=failed_closed,
        fetch_loss={"fresh_fetch_unavailable": True},
        plant_before=plant,
        plant_after=json.loads(json.dumps(plant)),
        ot_before={"execute_endpoint_records": 2},
        ot_after={"execute_endpoint_records": 3},
    )["no_ot_consequence_dispatch_observed"]

    for field, invalid in (
        ("schema_version", "unexpected-result-v1"),
        ("status", "completed"),
        ("reasons", ["pre_observation_unavailable"]),
        ("dispatch_attempts", 1),
        ("acknowledgment", {"executed": False}),
    ):
        response = {**failed_closed, field: invalid}
        assert not runner._post_deletion_acceptance(
            response_status=200,
            response_document=response,
            fetch_loss={"fresh_fetch_unavailable": True},
            plant_before=plant,
            plant_after=json.loads(json.dumps(plant)),
            ot_before={"execute_endpoint_records": 2},
            ot_after={"execute_endpoint_records": 2},
        )["fresh_action_failed_closed_before_dispatch"]

    assert not runner._post_deletion_acceptance(
        response_status=503,
        response_document=failed_closed,
        fetch_loss={"fresh_fetch_unavailable": True},
        plant_before=plant,
        plant_after=json.loads(json.dumps(plant)),
        ot_before={"execute_endpoint_records": 2},
        ot_after={"execute_endpoint_records": 2},
    )["fresh_action_failed_closed_before_dispatch"]


def test_failed_acceptance_checks_are_sorted_and_require_literal_true(
    runner: Any,
) -> None:
    assert runner._failed_acceptance_checks(
        {
            "passed": True,
            "failed_z": False,
            "failed_a": 1,
        }
    ) == ["failed_a", "failed_z"]


def test_retention_is_atomic_hashed_private_and_credential_free(
    runner: Any,
    tmp_path: Path,
) -> None:
    results = tmp_path / "spire-mtls-results"
    evidence = {
        "git_commit": "f" * 40,
        "accepted": True,
        "semantic_outcome_sha256": "a" * 64,
        "source_binding": {
            "git_commit": "f" * 40,
            "git_tree": "e" * 40,
            "source_fingerprint_sha256": "b" * 64,
            "files": {"source": "c" * 64},
        },
        "configuration_binding": {
            "application_workload_identity_required": True,
            "all_mtls_client_modes_required": True,
        },
        "primary_agent_probe": {"nominal": {"status": "completed"}},
        "registration_deletion": {"registration_entry_deleted": True},
        "fresh_fetch_loss": {
            "fresh_fetch_unavailable": True,
            "already_issued_certificate_immediate_revocation_proven": False,
        },
        "prepared_post_deletion_action": {
            "wire_request_sha256": "d" * 64,
            "wire_request_retained": False,
        },
        "post_deletion_action": {
            "http_status": 200,
            "acceptance": {"plant_effect_absent": True},
        },
        "credential_material_retained": False,
    }

    manifest = runner._retain_results(results, evidence)

    assert set(path.name for path in results.iterdir()) == {
        "source-binding.json",
        "configuration-binding.json",
        "nominal-probe.json",
        "post-deletion-fail-closed.json",
        "campaign.json",
        "manifest.json",
    }
    assert manifest["analyst"] == "Angelis Pseftis"
    assert manifest["source_fingerprint_sha256"] == "b" * 64
    assert manifest["credential_material_retained"] is False
    for name, metadata in manifest["files"].items():
        material = (results / name).read_bytes()
        assert metadata["bytes"] == len(material)
        assert metadata["sha256"] == hashlib.sha256(material).hexdigest()
        assert b"BEGIN PRIVATE KEY" not in material
        assert b"BEGIN CERTIFICATE" not in material
        assert stat.S_IMODE((results / name).stat().st_mode) == 0o600

    with pytest.raises(runner.m4d.ExperimentError, match="refusing to overwrite"):
        runner._retain_results(results, evidence)


def test_run_experiment_refuses_existing_output_before_docker(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "already-retained"
    results.mkdir()
    called = False

    def campaign(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(runner, "_campaign", campaign)
    with pytest.raises(runner.m4d.ExperimentError, match="refusing to overwrite"):
        runner.run_experiment(results, "aegis-ot-m4g-spire-mtls-test")
    assert called is False
