from __future__ import annotations

from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return import_module("run_m4i_experiment")


def _record(state: str, *kinds: str) -> dict[str, Any]:
    attempts = []
    for kind in kinds:
        item: dict[str, Any] = {
            "kind": kind,
            "status": (
                "outcome_unknown"
                if state == "dispatch_armed" and kind == "commit"
                else "response_retained"
            ),
        }
        if kind in {"commit", "query"} and state in {"applied", "rejected"}:
            item["outcome"] = {"disposition": state, "proof": "retained"}
        attempts.append(item)
    return {"transitions": [{"state": state}], "attempts": attempts}


def _private_snapshot(*, checkpoint: bool = False) -> dict[str, Any]:
    document: dict[str, Any] = {"entries": []}
    if checkpoint:
        document = {"checkpoint": {"state_digest": "d" * 64}}
    return {
        "bytes_base64": "ZXhhY3Q=",
        "sha256": "a" * 64,
        "document": document,
        "directory": {"mode": "0700", "symlink": False},
        "artifact": {"mode": "0600", "regular": True, "symlink": False},
        "writer_lock": {"mode": "0600", "regular": True, "symlink": False},
    }


def _aligned_recovery(*, applied: int, state_version: int) -> dict[str, Any]:
    return {
        "schema_version": "m4i-ot-coordination-recovery-v1",
        "status": "aligned",
        "reason": "aligned_empty_baseline" if applied == 0 else "aligned_applied_chain",
        "record_count": applied,
        "applied_effect_count": applied,
        "pending_effect_count": 0,
        "plant_state_version": state_version,
        "plant_state_digest": "d" * 64,
        "live_commit_armed": False,
        "limitation": "ordinary_single_volume_alignment_only",
    }


def _accepted_fixture(runner: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, bool]]:
    health: dict[str, dict[str, Any]] = {
        service: {"status": "ready"} for service in runner.m4g.AEGIS_HEALTH_PORTS
    }
    health["segmented-gateway"].update(
        {
            "effect_coordination_mode": "required",
            "coordination_backend": "durable-prepare-commit-query-http-v1",
        }
    )
    health["ot-adapter"]["coordination_recovery"] = _aligned_recovery(
        applied=0,
        state_version=0,
    )
    terminal = {
        "bytes_base64": "dGVybWluYWw=",
        "sha256": "b" * 64,
        "disposition": "applied",
    }
    observations = {
        "health_initial": health,
        "coordination_initialization": {
            "schema_version": "m4i-coordination-volume-initialization-v2",
            "state_artifact_count": 3,
            "directory_mode": "0700",
            "artifact_mode": "0600",
            "secrets_consumed": 0,
        },
        "nominal": {
            "result": {"status": "completed", "dispatch_attempts": 1},
            "gateway_record": _record("applied", "prepare", "commit"),
            "ot_record": _record("applied", "prepare", "commit"),
        },
        "lost_response": {
            "action_sha256": "c" * 64,
            "result": {
                "http_status": 200,
                "response": {"status": "unknown_effect", "dispatch_attempts": 1},
            },
            "relay": {
                "armed_action_sha256": "c" * 64,
                "commit_request_sha256": "e" * 64,
                "commit_response_sha256": "f" * 64,
                "commit_response_discarded": True,
                "path_counters": {
                    "health": 1,
                    "prepare": 1,
                    "commit": 1,
                    "query": 0,
                    "other": 0,
                },
                "violations": [],
            },
            "relay_teardown": {
                "relay_container_removed_before_reconciliation": True,
                "gateway_direct_ot_route_restored_before_reconciliation": True,
            },
            "gateway_before_reconciliation": _record(
                "dispatch_armed", "prepare", "commit"
            ),
            "ot_before_reconciliation": _record("applied", "prepare", "commit"),
            "fresh_action": {
                "http_status": 409,
                "response": {
                    "status": "rejected",
                    "reason": "effect_reconciliation_required",
                },
            },
            "ot_prepare_count_before_fresh": 1,
            "ot_prepare_count_after_fresh": 1,
            "gateway_record_count_before_fresh": 2,
            "gateway_record_count_after_fresh": 2,
            "reconciliation": {
                "http_status": 200,
                "credential_role": "agent",
                "request_nonce": "independent-reconciliation-nonce",
                "proposal_nonce": "original-proposal-nonce",
                "response": {
                    "schema_version": "m4i-capability-outcome-resolution-v1",
                    "disposition": "applied",
                },
            },
            "gateway_after_reconciliation": _record(
                "applied", "prepare", "commit", "query"
            ),
            "ot_after_reconciliation": _record(
                "applied", "prepare", "commit", "query"
            ),
        },
        "gateway_ot_restart": {
            "gateway_container_before": {"container_id": "gateway-before"},
            "gateway_container_after": {"container_id": "gateway-after"},
            "ot_container_before": {"container_id": "ot-before"},
            "ot_container_after": {"container_id": "ot-after"},
            "gateway_terminal_before": terminal,
            "gateway_terminal_after": terminal,
            "ot_terminal_before": terminal,
            "ot_terminal_after": terminal,
            "health_after": {"status": "ready"},
            "ot_health_after": {
                "status": "ready",
                "coordination_recovery": _aligned_recovery(
                    applied=2,
                    state_version=2,
                ),
            },
        },
        "plant_restart": {
            "health_before": {
                "boot_epoch": "plant-before-boot",
                "model_digest": "m" * 64,
                "state_version": 2,
                "state_digest": "d" * 64,
            },
            "health_after": {
                "boot_epoch": "plant-after-boot",
                "model_digest": "m" * 64,
                "state_version": 2,
                "state_digest": "d" * 64,
            },
            "checkpoint_before": _private_snapshot(checkpoint=True),
            "checkpoint_after": _private_snapshot(checkpoint=True),
            "stack_health_after": {
                "ot-adapter": {
                    "status": "ready",
                    "coordination_recovery": _aligned_recovery(
                        applied=2,
                        state_version=2,
                    ),
                }
            },
        },
        "storage": {
            "snapshots": {
                role: _private_snapshot(checkpoint=role == "plant")
                for role in ("gateway", "ot", "plant")
            }
        },
        "corruption": {
            role: {
                "startup_ready": False,
                "restored": True,
                "original_sha256": "a" * 64,
                "restored_sha256": "a" * 64,
            }
            for role in ("gateway", "ot", "plant")
        },
    }
    configuration = {
        "state_volumes": {
            "gateway": "gateway_coordination",
            "ot": "ot_coordination",
            "plant": "plant_checkpoint",
        },
        "state_paths": {
            "gateway": runner.GATEWAY_FILE,
            "ot": runner.OT_FILE,
            "plant": runner.PLANT_FILE,
        },
    }
    cleanup = {
        "compose_project_removed": True,
        "relay_container_removed": True,
        "private_key_directory_removed": True,
        "relay_evidence_directory_removed": True,
        "gateway_coordination_volume_removed": True,
        "ot_coordination_volume_removed": True,
        "plant_checkpoint_volume_removed": True,
    }
    return observations, configuration, cleanup


def test_acceptance_evaluator_closes_all_gates_and_rejects_commit_retry(
    runner: Any,
) -> None:
    observations, configuration, cleanup = _accepted_fixture(runner)

    accepted = runner._accepted_gates(observations, configuration, cleanup)

    assert tuple(accepted) == runner.ACCEPTANCE_GATE_NAMES
    assert all(accepted.values())
    observations["lost_response"]["relay"]["path_counters"]["commit"] = 2
    rejected = runner._accepted_gates(observations, configuration, cleanup)
    assert rejected["lost_commit_response_remains_unknown"] is False
    assert rejected["agent_reconciliation_one_query_zero_commit_retries"] is False


def test_acceptance_requires_live_ot_recovery_alignment(runner: Any) -> None:
    observations, configuration, cleanup = _accepted_fixture(runner)
    observations["health_initial"]["ot-adapter"].pop("coordination_recovery")

    rejected = runner._accepted_gates(observations, configuration, cleanup)

    assert rejected["required_coordination_health"] is False

    observations, configuration, cleanup = _accepted_fixture(runner)
    observations["gateway_ot_restart"]["ot_health_after"][
        "coordination_recovery"
    ]["status"] = "recovery_required"
    rejected = runner._accepted_gates(observations, configuration, cleanup)
    assert (
        rejected["gateway_ot_restart_preserves_byte_equivalent_resolution"]
        is False
    )


def test_nominal_action_uses_one_exact_prepare_and_submit(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action = {"proposal": {"proposal_id": "m4i-nominal"}}
    action_digest = runner._sha256(runner._canonical_bytes(action))
    calls: list[tuple[str, dict[str, Any] | None]] = []

    def exchange(
        prefix: tuple[str, ...],
        *,
        mode: str,
        material: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        assert prefix == ("docker", "compose")
        calls.append((mode, material))
        if mode == "prepare_action":
            return {
                "action_sha256": action_digest,
                "wire_request": {"signed": "exact"},
            }
        return {
            "http_status": 200,
            "action_sha256": action_digest,
            "response": {"request": action},
        }

    monkeypatch.setattr(runner, "_run_agent_exchange", exchange)

    result = runner._run_nominal_action(("docker", "compose"))

    assert result == {"request": action}
    assert calls == [
        ("prepare_action", None),
        ("submit_action", {"wire_request": {"signed": "exact"}}),
    ]


def test_scoped_relay_is_closed_and_records_commit_before_one_forward(
    runner: Any,
) -> None:
    agent_code = runner._AGENT_EXCHANGE_CODE
    assert "WorkloadAuthenticatedCapabilityAction.model_validate_json(" in agent_code
    assert "CapabilityActionRequest.model_validate_json(" in agent_code
    assert ".model_validate(material[" not in agent_code

    code = runner._COMMIT_RESPONSE_RELAY_CODE
    compile(code, "<m4i-scoped-relay>", "exec")
    assert "self.path == '/v1/effects/query'" in code
    assert "self.path not in {'/v1/effects/prepare', '/v1/effects/commit'}" in code
    assert "STATE['path_counters']['commit'] != 0" in code
    assert "request.effect.request_sha256 != expected_action" in code
    assert "STATE['violations'].append(reason)" in code
    assert "self.connection.shutdown(socket.SHUT_RDWR)" in code
    retained = code.index("STATE['commit_request_sha256'] = request_sha256")
    forwarded = code.index("status, content_type, material = forward(", retained)
    assert retained < forwarded
    assert "/fault" not in code


def test_scoped_relay_uses_explicit_gateway_route_without_alias_swap(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner._atomic_private_json(
        tmp_path / "arm.json",
        {
            "schema_version": "m4i-scoped-relay-arm-v1",
            "expected_action_sha256": "a" * 64,
        },
    )
    calls: list[tuple[str, ...]] = []

    def run(*args: str, **_: Any) -> SimpleNamespace:
        calls.append(args)
        if args[-3:] == ("ps", "-q", "ot-adapter"):
            return SimpleNamespace(returncode=0, stdout="ot-container\n", stderr="")
        if args == ("docker", "inspect", "ot-container"):
            return SimpleNamespace(
                returncode=0,
                stdout=runner.json.dumps(
                    [
                        {
                            "NetworkSettings": {
                                "Networks": {"m4i-test_control_dmz": {}}
                            }
                        }
                    ]
                ),
                stderr="",
            )
        if args[:3] == ("docker", "container", "inspect"):
            return SimpleNamespace(returncode=1, stdout="", stderr="not found")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(runner.m4d, "_run", run)
    monkeypatch.setattr(runner, "_await_relay_status", lambda *args, **kwargs: {})
    monkeypatch.setattr(runner.m4g, "_await_gateway", lambda: None)
    prefix = ("docker", "compose", "-p", "m4i-test")

    relay = runner._start_relay(
        prefix=prefix,
        project_name="m4i-test",
        image="sha256:" + "b" * 64,
        directory=tmp_path,
    )

    override_path = Path(relay["override_path"])
    override = runner.json.loads(override_path.read_text(encoding="utf-8"))
    assert override["services"]["segmented-gateway"]["environment"] == {
        "AEGIS_OT_URL": "http://m4i-test-m4i-commit-relay:8083"
    }
    flat = [value for call in calls for value in call]
    assert "disconnect" not in flat
    assert "connect" not in flat
    assert "--network-alias" not in flat
    assert "AEGIS_M4I_RELAY_TARGET_HOST=ot-adapter" in flat
    assert any(str(override_path) in call and "up" in call for call in calls)

    teardown = runner._stop_relay(prefix=prefix, relay=relay)

    assert teardown == {
        "relay_container_removed_before_reconciliation": True,
        "gateway_direct_ot_route_restored_before_reconciliation": True,
    }
    assert not override_path.exists()


def test_artifact_restore_attaches_stdin_and_reports_written_digest(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], str]] = []
    expected_sha256 = runner._sha256(b"exact")

    def run_input(
        args: tuple[str, ...],
        input_text: str,
        *,
        check: bool = True,
    ) -> SimpleNamespace:
        assert check is True
        calls.append((args, input_text))
        return SimpleNamespace(
            stdout=runner.json.dumps(
                {
                    "operation": "restore",
                    "sha256": expected_sha256,
                    "size_bytes": 5,
                }
            )
        )

    monkeypatch.setattr(runner, "_run_input", run_input)

    result = runner._mutate_artifact(
        image="sha256:" + "a" * 64,
        volume="bounded-state-volume",
        relative_path="gateway-coordination.json",
        uid="65532",
        gid="65532",
        operation="restore",
        material_base64="ZXhhY3Q=",
    )

    assert result["sha256"] == expected_sha256
    assert len(calls) == 1
    args, stdin = calls[0]
    assert "--interactive" in args
    assert stdin == "ZXhhY3Q="
    compile(runner._ARTIFACT_MUTATOR_CODE, "<m4i-artifact-mutator>", "exec")


def test_artifact_fault_case_rejects_nonexact_restoration(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutations = iter(
        (
            {"operation": "corrupt", "sha256": "b" * 64, "size_bytes": 18},
            {"operation": "restore", "sha256": "c" * 64, "size_bytes": 5},
        )
    )
    monkeypatch.setattr(runner, "_mutate_artifact", lambda **_: next(mutations))
    monkeypatch.setattr(
        runner.m4d,
        "_run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        runner,
        "_await_service_not_ready",
        lambda *args, **kwargs: {"startup_ready": False},
    )

    with pytest.raises(
        runner.m4d.ExperimentError,
        match="restoration did not reproduce",
    ):
        runner._artifact_fault_case(
            ("docker", "compose"),
            service="segmented-gateway",
            port=8081,
            image="sha256:" + "a" * 64,
            volume="bounded-state-volume",
            relative_path="gateway-coordination.json",
            uid="65532",
            gid="65532",
            snapshot={"sha256": "a" * 64, "bytes_base64": "ZXhhY3Q="},
        )


def test_source_binding_covers_clean_tree_lock_schemas_and_exact_files(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner.m4g,
        "_assert_source_checkout",
        lambda: {"package_directory": "src/aegis_ot", "checkout_root": "."},
    )
    monkeypatch.setattr(
        runner.m4d,
        "_run",
        lambda *args, **kwargs: SimpleNamespace(stdout="b" * 40 + "\n"),
    )
    monkeypatch.setattr(
        runner,
        "_file_sha256",
        lambda path: runner._sha256(path.encode("utf-8")),
    )

    binding = runner._source_binding("a" * 40)

    assert binding["git_commit"] == "a" * 40
    assert binding["git_tree"] == "b" * 40
    assert set(binding["source_files"]) == set(runner.SOURCE_BINDING_FILES)
    assert binding["dependency_lock"] == {
        "path": runner.LOCK_FILE,
        "sha256": runner._sha256(runner.LOCK_FILE.encode("utf-8")),
    }
    assert set(binding["schemas"]) == set(runner.M4I_SCHEMA_FILES)
    assert len(binding["source_binding_sha256"]) == 64


def test_compose_binding_requires_three_isolated_required_state_mounts(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {
        "segmented-gateway": (runner.GATEWAY_FILE, runner.GATEWAY_DIRECTORY, "gw"),
        "ot-adapter": (runner.OT_FILE, runner.OT_DIRECTORY, "ot"),
        "simulation": (runner.PLANT_FILE, runner.PLANT_DIRECTORY, "plant"),
    }
    services: dict[str, Any] = {
        "coordination-init": {
            "network_mode": "none",
            "environment": {
                "AEGIS_GATEWAY_RUNTIME_UID": "65532",
                "AEGIS_GATEWAY_RUNTIME_GID": "65532",
                "AEGIS_OT_RUNTIME_UID": "65532",
                "AEGIS_OT_RUNTIME_GID": "65535",
                "AEGIS_PLANT_RUNTIME_UID": "65532",
                "AEGIS_PLANT_RUNTIME_GID": "65536",
            },
        }
    }
    path_names = {
        "segmented-gateway": "AEGIS_GATEWAY_COORDINATION_JOURNAL_FILE",
        "ot-adapter": "AEGIS_OT_COORDINATION_JOURNAL_FILE",
        "simulation": "AEGIS_PLANT_CHECKPOINT_FILE",
    }
    for service, (path, directory, volume) in state.items():
        services[service] = {
            "environment": {
                "AEGIS_EFFECT_COORDINATION_MODE": "required",
                path_names[service]: path,
            },
            "volumes": [{"source": volume, "target": directory}],
            "depends_on": {
                "coordination-init": {"condition": "service_completed_successfully"}
            },
        }
    compose = {"name": "m4i-test", "services": services}
    monkeypatch.setattr(runner.m4g, "_normalize", lambda value, *_: value)
    monkeypatch.setattr(runner, "_file_sha256", lambda _: "a" * 64)

    binding = runner._configuration_binding(
        compose,
        key_directory=tmp_path,
        project_name="m4i-test",
    )

    assert binding["state_volumes"] == {
        "gateway": "gw",
        "ot": "ot",
        "plant": "plant",
    }
    assert binding["coordination_modes"] == {
        "gateway": "required",
        "ot": "required",
        "plant": "required",
    }
    assert len(binding["normalized_compose_sha256"]) == 64
    services["simulation"]["volumes"][0]["source"] = "ot"
    with pytest.raises(runner.m4d.ExperimentError, match="not isolated"):
        runner._configuration_binding(
            compose,
            key_directory=tmp_path,
            project_name="m4i-test",
        )
