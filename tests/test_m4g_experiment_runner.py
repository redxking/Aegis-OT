from __future__ import annotations

import json
import os
import stat
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis_ot.workload_identity import workload_key_id


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("run_m4g_experiment")


def test_compose_prefix_closes_exact_five_overlay_order(runner: Any) -> None:
    assert runner._compose_prefix("m4g-test") == (
        "docker",
        "compose",
        "-p",
        "m4g-test",
        "-f",
        "docker-compose.yml",
        "-f",
        "docker-compose.auth.yml",
        "-f",
        "docker-compose.replay.yml",
        "-f",
        "docker-compose.capability.yml",
        "-f",
        "docker-compose.identity.yml",
    )


def test_embedded_container_probes_are_valid_python(runner: Any) -> None:
    compile(runner._ROTATION_FIXTURE_CODE, "<m4g-rotation-fixture>", "exec")
    compile(runner._IDENTITY_SNAPSHOT_CODE, "<m4g-identity-snapshot>", "exec")
    compile(runner._REPLAY_SNAPSHOT_CODE, "<m4g-replay-snapshot>", "exec")
    compile(runner._BUNDLE_MUTATOR_CODE, "<m4g-bundle-mutator>", "exec")
    compile(
        runner._TRUST_SEQUENCE_SNAPSHOT_CODE,
        "<m4g-trust-sequence-snapshot>",
        "exec",
    )
    compile(
        runner._LOCAL_TRUST_VERIFIER_PROBE_CODE,
        "<m4g-local-trust-verifier-probe>",
        "exec",
    )
    compile(
        runner._LOCAL_HEALTH_EXCHANGE_CODE,
        "<m4g-local-health-exchange>",
        "exec",
    )


def test_campaign_lifecycle_and_source_binding_cover_durable_trust_state(
    runner: Any,
) -> None:
    assert {
        "workload_trust_sequence_agent",
        "workload_trust_sequence_gateway",
        "workload_trust_sequence_ot",
    } <= set(runner.PROJECT_VOLUME_SUFFIXES)
    assert "src/aegis_ot/workload_trust_state.py" in runner.SOURCE_BINDING_FILES
    assert "docker-compose.identity.yml" in runner.SOURCE_BINDING_FILES
    assert "scripts/run_m4g_experiment.py" in runner.SOURCE_BINDING_FILES


def _trust_sequence_snapshot(sequence: int) -> dict[str, Any]:
    item = {
        "directory": {
            "path": "/var/lib/aegis-ot/trust-sequence",
            "entries": [".state.json.lock", "state.json"],
            "mode": "0700",
            "uid": 65532,
            "gid": 65532,
        },
        "files": {
            "state.json": {
                "mode": "0600",
                "uid": 65532,
                "gid": 65532,
                "regular": True,
                "links": 1,
                "document": {
                    "schema_version": "m4g-workload-trust-sequence-state-v1",
                    "trust_domain": "aegis-ot.m4g.local",
                    "highest_sequence": sequence,
                    "highest_bundle_sha256": "a" * 64,
                },
            },
            ".state.json.lock": {
                "mode": "0600",
                "uid": 65532,
                "gid": 65532,
                "regular": True,
                "links": 1,
            },
        },
    }
    return {
        "agent": json.loads(json.dumps(item)),
        "gateway": json.loads(json.dumps(item)),
        "ot-adapter": json.loads(json.dumps(item)),
    }


def test_trust_sequence_snapshot_acceptance_requires_every_private_floor(
    runner: Any,
) -> None:
    snapshot = _trust_sequence_snapshot(2)
    assert runner._trust_sequence_snapshot_at(snapshot, sequence=2)
    assert runner._trust_sequence_floors(snapshot) == {
        "agent": 2,
        "gateway": 2,
        "ot-adapter": 2,
    }

    snapshot["gateway"]["files"]["state.json"]["document"][
        "highest_sequence"
    ] = 1
    assert not runner._trust_sequence_snapshot_at(snapshot, sequence=2)
    snapshot["gateway"]["files"]["state.json"]["document"][
        "highest_sequence"
    ] = 2
    snapshot["ot-adapter"]["files"][".state.json.lock"]["links"] = 2
    assert not runner._trust_sequence_snapshot_at(snapshot, sequence=2)


def test_resolved_compose_binding_requires_isolated_rw_state_and_no_admin_mount(
    runner: Any,
) -> None:
    runtime_target = "/var/lib/aegis-ot/trust-sequence"
    state_file = f"{runtime_target}/state.json"
    compose: dict[str, Any] = {"services": {}}
    for service, source in {
        "agent-probe": "m4g_workload_trust_sequence_agent",
        "segmented-gateway": "m4g_workload_trust_sequence_gateway",
        "ot-adapter": "m4g_workload_trust_sequence_ot",
    }.items():
        compose["services"][service] = {
            "environment": {
                "AEGIS_WORKLOAD_TRUST_SEQUENCE_STATE_FILE": state_file,
            },
            "volumes": [
                {
                    "type": "volume",
                    "source": source,
                    "target": runtime_target,
                    "read_only": False,
                }
            ],
        }
    init_targets = {
        "agent": (
            "m4g_workload_trust_sequence_agent",
            "AEGIS_AGENT_TRUST_SEQUENCE_DIRECTORY",
        ),
        "gateway": (
            "m4g_workload_trust_sequence_gateway",
            "AEGIS_GATEWAY_TRUST_SEQUENCE_DIRECTORY",
        ),
        "ot": (
            "m4g_workload_trust_sequence_ot",
            "AEGIS_OT_TRUST_SEQUENCE_DIRECTORY",
        ),
    }
    compose["services"]["identity-init"] = {
        "environment": {
            setting: f"/var/lib/aegis-ot/trust-sequence-state/{role}"
            for role, (_, setting) in init_targets.items()
        },
        "volumes": [
            {
                "type": "volume",
                "source": source,
                "target": f"/var/lib/aegis-ot/trust-sequence-state/{role}",
                "read_only": False,
            }
            for role, (source, _) in init_targets.items()
        ],
    }
    compose["services"]["identity-admin"] = {"volumes": []}

    assert runner._trust_sequence_compose_bound(compose)
    compose["services"]["identity-admin"]["volumes"] = [
        {
            "type": "volume",
            "source": "m4g_workload_trust_sequence_agent",
            "target": runtime_target,
        }
    ]
    assert not runner._trust_sequence_compose_bound(compose)


def test_rollback_rejection_requires_exact_sequence_failure(runner: Any) -> None:
    rejected = SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="workload trust bundle sequence rolled back",
    )
    unrelated = SimpleNamespace(returncode=1, stdout="", stderr="connection failed")
    successful = SimpleNamespace(
        returncode=0,
        stdout="sequence rolled back appeared in a log",
        stderr="",
    )

    assert runner._rollback_rejected(rejected)
    assert not runner._rollback_rejected(unrelated)
    assert not runner._rollback_rejected(successful)


def test_rollback_helpers_use_one_shot_containers_when_runtimes_are_exited(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def command(*args: str, **_: Any) -> SimpleNamespace:
        calls.append(args)
        return SimpleNamespace(returncode=1, stdout="{}", stderr="sequence rolled back")

    monkeypatch.setattr(runner.m4d, "_run", command)
    runner._service_trust_sequence_snapshot(("docker", "compose"), "ot-adapter")
    runner._local_trust_verifier_probe(
        ("docker", "compose"),
        service="segmented-gateway",
        identity_prefix="GATEWAY",
        check=False,
    )
    runner._local_trust_verifier_probe(
        ("docker", "compose"),
        service="agent-probe",
        identity_prefix="AGENT",
        check=False,
    )

    for invocation in calls:
        assert "run" in invocation
        assert "--rm" in invocation
        assert "--no-deps" in invocation
        assert "--entrypoint" in invocation
        assert "exec" not in invocation
    agent_invocation = calls[-1]
    assert agent_invocation[2:4] == ("--profile", "experiment")
    assert "AEGIS_M4G_TRUST_TEST_PREFIX=AGENT" in agent_invocation


def test_rollback_recreation_requires_unavailable_health_not_ready_health(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {
        "segmented-gateway": {
            "container_id": "gateway-before",
            "started_at": "before",
            "running": True,
            "exit_code": 0,
        },
        "ot-adapter": {
            "container_id": "ot-before",
            "started_at": "before",
            "running": True,
            "exit_code": 0,
        },
    }
    stopped = {
        "segmented-gateway": {
            "container_id": "gateway-after",
            "started_at": "after",
            "running": True,
            "exit_code": 0,
        },
        "ot-adapter": {
            "container_id": "ot-after",
            "started_at": "after",
            "running": True,
            "exit_code": 0,
        },
    }
    unavailable = {
        "segmented-gateway": {
            "http_status": 503,
            "body": {"reason": "gateway_runtime_unavailable"},
        },
        "ot-adapter": {
            "http_status": 503,
            "body": {"reason": "ot_runtime_unavailable"},
        },
    }
    monkeypatch.setattr(
        runner,
        "_container_identity",
        lambda _prefix, service: before[service],
    )
    monkeypatch.setattr(runner.m4d, "_run", lambda *_args, **_kwargs: SimpleNamespace())
    monkeypatch.setattr(
        runner,
        "_await_gateway_ot_unavailable",
        lambda _prefix: (stopped, unavailable),
    )
    monkeypatch.setattr(
        runner,
        "_await_gateway",
        lambda: pytest.fail("rollback recreation must not await readiness"),
    )

    snapshots = runner._recreate_gateway_ot(
        ("docker", "compose"),
        await_ready=False,
    )

    assert runner._gateway_ot_recreated(snapshots)
    assert runner._gateway_ot_failed_closed(snapshots)


def test_rotation_fixture_prepares_without_predispatching_transaction(
    runner: Any,
) -> None:
    assert "runtime.controller.execute(action)" not in runner._ROTATION_FIXTURE_CODE
    assert "controller.permit_issuer.issue(" in runner._ROTATION_FIXTURE_CODE
    assert "response_verified" in runner._ROTATION_FIXTURE_CODE
    assert "post_observation_verified" in runner._ROTATION_FIXTURE_CODE
    assert (
        "WorkloadSignedCapabilityResponse.model_validate_json(material)"
        in runner._ROTATION_FIXTURE_CODE
    )
    assert (
        "from aegis_ot.capability_models import CapabilityActionRequest"
        in runner._ROTATION_FIXTURE_CODE
    )
    assert "ObservationCaptureRequest," in runner._ROTATION_FIXTURE_CODE


def test_ephemeral_key_provisioning_is_raw_private_and_derives_workload_ids(
    runner: Any,
    tmp_path: Path,
) -> None:
    paths, key_ids = runner._provision_key_material(tmp_path)

    assert set(key_ids) == {"workload_authority", "agent", "gateway", "ot"}
    assert len(paths) == 16
    for path in paths.values():
        assert path.read_bytes()
        assert len(path.read_bytes()) == 32
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700

    for role, key_id in key_ids.items():
        public_key = Ed25519PublicKey.from_public_bytes(
            paths[f"{role}_public"].read_bytes()
        )
        assert key_id == workload_key_id(public_key)
        assert paths[f"{role}_private"].read_bytes() != paths[
            f"{role}_public"
        ].read_bytes()


def test_campaign_environment_exports_revision_exact_paths_and_derived_ids(
    runner: Any,
    tmp_path: Path,
) -> None:
    paths, key_ids = runner._provision_key_material(tmp_path)
    environment = runner._campaign_environment(paths, key_ids, "a" * 40)

    assert environment["AEGIS_SOURCE_REVISION"] == "a" * 40
    assert environment["AEGIS_WORKLOAD_TRUST_ROOT_KEY_ID"] == key_ids[
        "workload_authority"
    ]
    assert environment["AEGIS_OT_WORKLOAD_KEY_ID"] == key_ids["ot"]
    assert environment["AEGIS_AGENT_ACTOR_ID"] == "agent:operator-1"
    assert environment["AEGIS_GATEWAY_WORKLOAD_SUBJECT"] == runner.GATEWAY_SUBJECT
    assert environment["AEGIS_WORKLOAD_AUTHORITY_PRIVATE_KEY_FILE"] == str(
        paths["workload_authority_private"]
    )
    assert environment["AEGIS_WORKLOAD_AUTHORITY_PUBLIC_KEY_FILE"] == str(
        paths["workload_authority_public"]
    )
    for role in (
        "agent",
        "gateway",
        "ot",
        "permit",
        "observer",
        "candidate",
        "plant",
    ):
        assert environment[f"AEGIS_{role.upper()}_PRIVATE_KEY_FILE"] == str(
            paths[f"{role}_private"]
        )
        assert environment[f"AEGIS_{role.upper()}_PUBLIC_KEY_FILE"] == str(
            paths[f"{role}_public"]
        )


def test_installed_environment_restores_prior_and_absent_values(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_TEST_EXISTING", "before")
    monkeypatch.delenv("AEGIS_TEST_NEW", raising=False)

    with runner._installed_environment(
        {"AEGIS_TEST_EXISTING": "during", "AEGIS_TEST_NEW": "new"}
    ):
        assert os.environ["AEGIS_TEST_EXISTING"] == "during"
        assert os.environ["AEGIS_TEST_NEW"] == "new"

    assert os.environ["AEGIS_TEST_EXISTING"] == "before"
    assert "AEGIS_TEST_NEW" not in os.environ


def test_retained_campaign_refuses_dirty_checkout_before_docker_work(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "_assert_source_checkout", lambda: {})

    def command(*args: str, **_: Any) -> SimpleNamespace:
        assert args == ("git", "status", "--porcelain")
        return SimpleNamespace(stdout=" M user-owned-file\n")

    monkeypatch.setattr(runner.m4d, "_run", command)
    monkeypatch.setattr(
        runner,
        "_campaign",
        lambda *_: pytest.fail("dirty checkout must not start Docker campaign"),
    )

    with pytest.raises(runner.m4d.ExperimentError, match="clean checkout"):
        runner.run_experiment(tmp_path / "evidence.json", "m4g-test")


def test_probe_acceptance_requires_capability_outcomes_and_no_bypass(
    runner: Any,
) -> None:
    accepted: dict[str, Any] = {
        "nominal": {"status": "completed", "dispatch_attempts": 1},
        "exact_gateway_request_replay": {
            "status": "not_dispatched",
            "dispatch_attempts": 0,
            "reasons": [
                "observation_sequence_regressed",
                "observation_challenge_replayed",
            ],
        },
        "unsafe": {
            "status": "not_dispatched",
            "dispatch_attempts": 0,
            "reasons": ["critical_load_below_limit"],
        },
        "agent_direct_reachability": {
            "observer": False,
            "candidate": False,
            "ot-adapter": False,
            "simulation": False,
        },
    }

    assert runner._probe_accepted(accepted)
    accepted["agent_direct_reachability"]["ot-adapter"] = True
    assert not runner._probe_accepted(accepted)
    accepted["agent_direct_reachability"]["ot-adapter"] = False
    accepted["unsafe"]["reasons"] = ["candidate_rejected_by_test_boundary"]
    assert not runner._probe_accepted(accepted)
    accepted["unsafe"]["reasons"] = ["critical_load_below_limit"]
    accepted["exact_gateway_request_replay"]["reasons"] = ["replayed_nonce"]
    assert not runner._probe_accepted(accepted)


def test_cross_leaf_acceptance_requires_same_nonce_new_proof_and_replay_reason(
    runner: Any,
) -> None:
    before = {
        "http_status": 200,
        "fresh_transaction_prepared": True,
        "direct_dispatch_attempted": True,
        "response_verified": True,
        "ack_status": "applied",
        "ack_dispatch_phase": "committed",
        "ack_reason": "command_applied_and_plc_read_back",
        "post_observation_verified": True,
        "post_observation_digest": "c" * 64,
        "fresh_transaction_request_digest": "d" * 64,
        "fresh_transaction_permit_id": "old-permit",
        "fresh_transaction_dispatch_digest": "e" * 64,
        "transport_nonce": runner.FIXED_ROTATION_NONCE,
        "gateway_key_id": "old-key",
        "gateway_credential_id": "old-credential",
        "signed_request_sha256": "a" * 64,
    }
    after = {
        "http_status": 409,
        "fresh_transaction_prepared": True,
        "direct_dispatch_attempted": True,
        "response_verified": False,
        "post_observation_verified": False,
        "fresh_transaction_request_digest": "f" * 64,
        "fresh_transaction_permit_id": "new-permit",
        "fresh_transaction_dispatch_digest": "1" * 64,
        "transport_nonce": runner.FIXED_ROTATION_NONCE,
        "gateway_key_id": "new-key",
        "gateway_credential_id": "new-credential",
        "signed_request_sha256": "b" * 64,
        "response": {"status": "rejected", "reason": "transport_request_replayed"},
    }

    assert runner._cross_leaf_accepted(before, after)
    after["fresh_transaction_permit_id"] = before["fresh_transaction_permit_id"]
    assert not runner._cross_leaf_accepted(before, after)
    after["fresh_transaction_permit_id"] = "new-permit"
    after["response"] = {"status": "rejected", "reason": "identity_rejected"}
    assert not runner._cross_leaf_accepted(before, after)


def test_failed_acceptance_names_are_stable_and_only_include_false_values(
    runner: Any,
) -> None:
    assert runner._failed_acceptance_names(
        {"zeta": False, "accepted": True, "alpha": False}
    ) == ("alpha", "zeta")


def test_only_gateway_recreated_rejects_any_dependency_replacement(runner: Any) -> None:
    before = {
        service: {"container_id": f"{service}-old", "started_at": f"{service}-time"}
        for service in runner.OPERATIONAL_SERVICES
    }
    after = {service: dict(value) for service, value in before.items()}
    after["segmented-gateway"]["container_id"] = "gateway-new"
    after["segmented-gateway"]["started_at"] = "gateway-new-time"

    assert runner._only_gateway_recreated(before, after)
    after["ot-adapter"]["container_id"] = "ot-new"
    assert not runner._only_gateway_recreated(before, after)


def test_image_provenance_requires_oci_revision_on_every_built_service(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision = "c" * 40
    compose = {
        "name": "m4g-test",
        "services": {
            "opa": {"image": "opa@sha256:external"},
            "segmented-gateway": {
                "build": {"context": str(runner.ROOT)},
            },
        }
    }

    def command(*args: str, **_: Any) -> SimpleNamespace:
        assert args == ("docker", "image", "inspect", "m4g-test-segmented-gateway")
        return SimpleNamespace(
            stdout=json.dumps(
                [
                    {
                        "Id": "sha256:image",
                        "RepoDigests": ["m4g-gateway@sha256:digest"],
                        "Created": "2026-08-25T00:00:00Z",
                        "Config": {
                            "Labels": {
                                "org.opencontainers.image.revision": revision,
                            }
                        },
                    }
                ]
            )
        )

    monkeypatch.setattr(runner.m4d, "_run", command)
    assert runner._image_provenance(
        compose,
        revision,
        ("segmented-gateway",),
    ) == {
        "segmented-gateway": {
            "image": "m4g-test-segmented-gateway",
            "image_id": "sha256:image",
            "repo_digests": ["m4g-gateway@sha256:digest"],
            "created": "2026-08-25T00:00:00Z",
            "oci_revision": revision,
        }
    }

    with pytest.raises(runner.m4d.ExperimentError, match="revision mismatch"):
        runner._image_provenance(
            compose,
            "d" * 40,
            ("segmented-gateway",),
        )


def test_rotation_uses_offline_admin_profile_and_external_new_public_key(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_key = tmp_path / "gateway-rotated.public"
    public_key.write_bytes(b"k" * 32)
    captured: tuple[str, ...] = ()

    def command(*args: str, **_: Any) -> SimpleNamespace:
        nonlocal captured
        captured = args
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "operation": "rotate",
                    "prior_sequence": 1,
                    "published_sequence": 2,
                }
            )
        )

    monkeypatch.setattr(runner.m4d, "_run", command)
    result = runner._rotate_gateway(("docker", "compose"), public_key)

    assert result["published_sequence"] == 2
    assert "identity-admin" in captured
    assert "--no-deps" in captured
    assert "--expected-sequence" in captured
    mount = captured[captured.index("--volume") + 1]
    assert mount == f"{public_key.resolve()}:/run/rotation/gateway.public:ro"


def test_bundle_mutator_sends_no_material_for_missing_and_base64_for_restore(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs: list[dict[str, Any]] = []

    def command(
        _args: tuple[str, ...],
        input_text: str,
        *,
        check: bool = True,
    ) -> SimpleNamespace:
        assert check is True
        inputs.append(json.loads(input_text))
        return SimpleNamespace(stdout='{"operation":"ok","present":true}\n')

    monkeypatch.setattr(runner, "_run_input", command)
    runner._mutate_bundle(("docker", "compose"), operation="missing")
    runner._mutate_bundle(
        ("docker", "compose"),
        operation="replace",
        material=b"bundle",
    )

    assert inputs == [
        {"operation": "missing"},
        {"bytes_base64": "YnVuZGxl", "operation": "replace"},
    ]


def test_compose_normalization_redacts_checkout_project_and_private_directory(
    runner: Any,
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    keys = tmp_path / "keys"
    checkout.mkdir()
    keys.mkdir()
    value = {
        "name": "m4g-project",
        "services": {
            "gateway": {
                "build": {"context": str(checkout)},
                "secret": str(keys / "gateway.private"),
                "volume": "m4g-project_workload_identity",
            }
        },
    }

    assert runner._normalize(value, keys, "m4g-project", checkout) == {
        "name": "<compose-project>",
        "services": {
            "gateway": {
                "build": {"context": "<checkout-root>"},
                "secret": "<ephemeral-key-dir>/gateway.private",
                "volume": "<compose-project>_workload_identity",
            }
        },
    }
