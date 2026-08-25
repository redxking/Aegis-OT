"""Run paired clean-checkout M4f durable transport-replay experiments."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import multiprocessing
import os
import shutil
import stat
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from unittest.mock import patch

import run_m4d_experiment as m4d
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import aegis_ot
from aegis_ot.segmented_runtime import (
    SignedSegmentedExecutionRequest,
    SignedSegmentedExecutionResponse,
    _sha256,
)
from aegis_ot.transport_replay import DurableTransportReplayLedger

ROOT = Path(__file__).resolve().parents[1]
AUDIENCE = "aegis-ot:ot-adapter"
GATEWAY_KEY_ID = "m4e-gateway-key-v1"
CRASH_KEY_SHA256 = "d" * 64
OT_KEY_ID = "m4e-ot-key-v1"


def _assert_source_checkout() -> dict[str, str]:
    module_file = aegis_ot.__file__
    if module_file is None:
        raise m4d.ExperimentError("aegis_ot package has no filesystem source")
    actual = Path(module_file).resolve().parent
    expected = (ROOT / "src" / "aegis_ot").resolve()
    if actual != expected:
        raise m4d.ExperimentError(
            f"aegis_ot imported from stale source: expected {expected}, got {actual}"
        )
    return {
        "package_directory": str(actual.relative_to(ROOT)),
        "checkout_root": str(ROOT),
    }


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _replace_path_prefix(value: str, path: Path, marker: str) -> str:
    prefixes = sorted({str(path), str(path.absolute()), str(path.resolve())}, key=len, reverse=True)
    for prefix in prefixes:
        if value == prefix:
            return marker
        if value.startswith(f"{prefix}{os.sep}"):
            return f"{marker}{value[len(prefix):]}"
    return value


def _normalize(
    value: Any,
    key_directory: Path,
    project_name: str,
    checkout_root: Path = ROOT,
) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize(item, key_directory, project_name, checkout_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _normalize(item, key_directory, project_name, checkout_root)
            for item in value
        ]
    if isinstance(value, str):
        normalized = _replace_path_prefix(
            value,
            key_directory,
            "<ephemeral-key-dir>",
        )
        normalized = _replace_path_prefix(normalized, checkout_root, "<checkout-root>")
        return normalized.replace(project_name, "<compose-project>")
    return value


def _assert_project_absent(project_name: str) -> None:
    containers = m4d._run(
        "docker",
        "ps",
        "-a",
        "--filter",
        f"label=com.docker.compose.project={project_name}",
        "--format",
        "{{.ID}}",
    ).stdout.strip()
    volumes = []
    for suffix in ("transport_replay", "transport_probe"):
        name = f"{project_name}_{suffix}"
        if m4d._run("docker", "volume", "inspect", name, check=False).returncode == 0:
            volumes.append(name)
    if containers or volumes:
        raise m4d.ExperimentError(
            f"M4f project name is already in use; refusing cleanup: {project_name}"
        )


def _assert_checkout(commit: str) -> None:
    if m4d._run("git", "rev-parse", "HEAD").stdout.strip() != commit:
        raise m4d.ExperimentError("checkout HEAD changed during the M4f experiment")
    if m4d._run("git", "status", "--porcelain").stdout:
        raise m4d.ExperimentError("checkout changed during the M4f experiment")


def _await_gateway_stack() -> None:
    last_error: Exception | None = None
    for _ in range(60):
        try:
            status, _ = m4d._http_json(
                "GET",
                "http://127.0.0.1:8081/v1/observation",
            )
            if status == 200:
                return
        except m4d.ExperimentError as exc:
            last_error = exc
        time.sleep(0.25)
    raise m4d.ExperimentError(
        "segmented gateway stack did not become ready"
    ) from last_error


def _await_durable_ot_health(compose_prefix: tuple[str, ...]) -> None:
    command = (
        "import json; from urllib.request import urlopen; "
        "value=json.loads(urlopen('http://127.0.0.1:8083/health', timeout=1).read()); "
        "assert value.get('status') == 'ok'; "
        "assert value.get('replay_mode') == 'durable'"
    )
    for _ in range(60):
        completed = m4d._run(
            *compose_prefix,
            "exec",
            "-T",
            "ot-adapter",
            "python",
            "-c",
            command,
            check=False,
        )
        if completed.returncode == 0:
            return
        time.sleep(0.25)
    raise m4d.ExperimentError("durable OT-adapter health did not become ready")


def _container_identity(
    compose_prefix: tuple[str, ...],
    service: str,
) -> dict[str, Any]:
    container_id = m4d._run(*compose_prefix, "ps", "-q", service).stdout.strip()
    values = json.loads(m4d._run("docker", "inspect", container_id).stdout)
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise m4d.ExperimentError("OT-adapter container inspection was malformed")
    inspected = values[0]
    state = inspected.get("State", {})
    mounts = inspected.get("Mounts", [])
    if not isinstance(state, dict) or not isinstance(mounts, list):
        raise m4d.ExperimentError("OT-adapter identity fields were malformed")
    volume_mounts = [
        {
            "destination": item.get("Destination"),
            "name": item.get("Name"),
            "rw": item.get("RW"),
            "type": item.get("Type"),
        }
        for item in mounts
        if isinstance(item, dict) and item.get("Type") == "volume"
    ]
    return {
        "service": service,
        "container_id": inspected.get("Id"),
        "created": inspected.get("Created"),
        "started_at": state.get("StartedAt"),
        "image_id": inspected.get("Image"),
        "running": state.get("Running"),
        "volume_mounts": volume_mounts,
    }


def _service_identities(compose_prefix: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    return {
        service: _container_identity(compose_prefix, service)
        for service in (
            "opa",
            "simulation",
            "observer",
            "ot-adapter",
            "segmented-gateway",
        )
    }


def _replay_volume_name(identity: dict[str, Any]) -> str:
    for mount in identity.get("volume_mounts", []):
        if (
            isinstance(mount, dict)
            and mount.get("destination") == "/var/lib/aegis-ot"
            and isinstance(mount.get("name"), str)
        ):
            return str(mount["name"])
    raise m4d.ExperimentError("OT-adapter replay volume identity was not found")


def _ledger_snapshot(compose_prefix: tuple[str, ...]) -> dict[str, Any]:
    command = (
        "import base64; from pathlib import Path; "
        "print(base64.b64encode(Path('/var/lib/aegis-ot/transport-replay.json')"
        ".read_bytes()).decode('ascii'))"
    )
    encoded = m4d._run(
        *compose_prefix,
        "exec",
        "-T",
        "ot-adapter",
        "python",
        "-c",
        command,
    ).stdout.strip()
    try:
        material = base64.b64decode(encoded, validate=True)
        parsed = json.loads(material)
    except (ValueError, json.JSONDecodeError) as exc:
        raise m4d.ExperimentError("M4f ledger snapshot was malformed") from exc
    if not isinstance(parsed, dict):
        raise m4d.ExperimentError("M4f ledger snapshot root was not an object")
    canonical = json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return {
        "sha256": hashlib.sha256(material).hexdigest(),
        "canonical": material == canonical,
        "bytes_base64": encoded,
        "document": parsed,
    }


def _parse_init_log(compose_prefix: tuple[str, ...]) -> dict[str, Any]:
    raw = m4d._run(
        *compose_prefix,
        "logs",
        "--no-color",
        "--no-log-prefix",
        "replay-init",
    ).stdout
    for line in reversed(raw.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise m4d.ExperimentError("M4f replay initialization record was not found")


def _verify_artifact_record(
    record: dict[str, Any],
    gateway_public_raw: bytes,
    ot_public_raw: bytes,
) -> dict[str, bool]:
    if not isinstance(record, dict):
        raise m4d.ExperimentError("M4f exact artifact record was malformed")
    request = SignedSegmentedExecutionRequest.model_validate(record.get("signed_request"))
    response = SignedSegmentedExecutionResponse.model_validate(record.get("signed_response"))
    request_verified = request.verify(Ed25519PublicKey.from_public_bytes(gateway_public_raw))
    response_verified = response.verify(Ed25519PublicKey.from_public_bytes(ot_public_raw))
    return {
        "request_audience_verified_offline": request.audience == AUDIENCE,
        "request_gateway_key_id_verified_offline": (
            request.gateway_key_id == GATEWAY_KEY_ID
        ),
        "request_signature_verified_offline": request_verified,
        "response_ot_key_id_verified_offline": response.ot_key_id == OT_KEY_ID,
        "response_signature_verified_offline": response_verified,
        "response_request_binding_verified_offline": response.request_sha256 == _sha256(request),
        "response_proposal_binding_verified_offline": (
            response.execution.proposal_id == request.request.proposal.proposal_id
        ),
        "response_decision_binding_verified_offline": (
            response.execution.decision_id == request.request.decision.decision_id
        ),
    }


def _verify_exact_artifacts(
    transport: dict[str, Any],
    prepare: dict[str, Any],
    gateway_public_raw: bytes,
    ot_public_raw: bytes,
) -> dict[str, bool]:
    full = _verify_artifact_record(
        transport.get("valid_key_holder", {}),
        gateway_public_raw,
        ot_public_raw,
    )
    prepared = _verify_artifact_record(
        prepare.get("prepared_request", {}),
        gateway_public_raw,
        ot_public_raw,
    )
    return {
        f"full_{name}": accepted for name, accepted in full.items()
    } | {f"prepared_{name}": accepted for name, accepted in prepared.items()}


def _semantic_transport(value: dict[str, Any]) -> dict[str, Any]:
    valid = value.get("valid_key_holder", {})
    resigned = value.get("resigned_same_inner_request", {})
    return {
        "accepted": value.get("accepted"),
        "replay_mode": value.get("health_before", {}).get("replay_mode"),
        "unsigned_status": value.get("unsigned", {}).get("http_status"),
        "forged_status": value.get("forged_signature", {}).get("http_status"),
        "valid_status": valid.get("http_status"),
        "valid_executed": valid.get("executed"),
        "valid_response_verified": valid.get("response_signature_verified"),
        "same_boot_replay_status": value.get("exact_same_boot_replay", {}).get(
            "http_status"
        ),
        "tamper_status": value.get("post_signature_tamper", {}).get("http_status"),
        "resigned_status": resigned.get("http_status"),
        "resigned_executed": resigned.get("executed"),
        "resigned_reason": resigned.get("reason"),
        "state_version_delta": (
            value.get("state_after_valid", {}).get("version", 0)
            - value.get("state_before", {}).get("version", 0)
        ),
        "reservation_delta": (
            value.get("health_after", {}).get("replay_reservations", 0)
            - value.get("health_before", {}).get("replay_reservations", 0)
        ),
    }


def _semantic_restart(value: dict[str, Any]) -> dict[str, Any]:
    replay = value.get("exact_restart_replay", {})
    fresh = value.get("fresh_after_restart", {})
    return {
        "accepted": value.get("accepted"),
        "replay_status": replay.get("http_status"),
        "replay_within_window": replay.get(
            "response_within_original_validity_window"
        ),
        "fresh_status": fresh.get("http_status"),
        "fresh_executed": fresh.get("executed"),
        "fresh_response_verified": fresh.get("response_signature_verified"),
        "replay_reservation_delta": (
            value.get("health_after_replay", {}).get("replay_reservations", 0)
            - value.get("health_before", {}).get("replay_reservations", 0)
        ),
        "fresh_reservation_delta": (
            value.get("health_after_fresh", {}).get("replay_reservations", 0)
            - value.get("health_after_replay", {}).get("replay_reservations", 0)
        ),
        "fresh_state_version_delta": (
            value.get("state_after_fresh", {}).get("version", 0)
            - value.get("state_after_replay", {}).get("version", 0)
        ),
    }


def _first_semantic_difference(
    primary: Any,
    reproduction: Any,
    path: str = "$",
) -> tuple[str, Any, Any] | None:
    if type(primary) is not type(reproduction):
        return path, primary, reproduction
    if isinstance(primary, dict):
        primary_keys = set(primary)
        reproduction_keys = set(reproduction)
        if primary_keys != reproduction_keys:
            return f"{path}.__keys__", sorted(primary_keys), sorted(reproduction_keys)
        for key in sorted(primary):
            difference = _first_semantic_difference(
                primary[key],
                reproduction[key],
                f"{path}.{key}",
            )
            if difference is not None:
                return difference
        return None
    if isinstance(primary, list):
        if len(primary) != len(reproduction):
            return f"{path}.__length__", len(primary), len(reproduction)
        for index, (primary_item, reproduction_item) in enumerate(
            zip(primary, reproduction, strict=True)
        ):
            difference = _first_semantic_difference(
                primary_item,
                reproduction_item,
                f"{path}[{index}]",
            )
            if difference is not None:
                return difference
        return None
    if primary != reproduction:
        return path, primary, reproduction
    return None


def _semantic_prepare(value: dict[str, Any]) -> dict[str, Any]:
    prepared = value.get("prepared_request", {})
    return {
        "accepted": value.get("accepted"),
        "http_status": prepared.get("http_status"),
        "executed": prepared.get("executed"),
        "response_verified": prepared.get("response_signature_verified"),
        "reservation_delta": (
            value.get("health_after", {}).get("replay_reservations", 0)
            - value.get("health_before", {}).get("replay_reservations", 0)
        ),
        "state_version_delta": (
            value.get("state_after", {}).get("version", 0)
            - value.get("state_before", {}).get("version", 0)
        ),
    }


def _crash_worker(
    path: str,
    phase: Literal["before_replace", "after_replace"],
) -> None:
    ledger = DurableTransportReplayLedger(
        Path(path),
        audience=AUDIENCE,
        gateway_key_id=GATEWAY_KEY_ID,
        gateway_public_key_sha256=CRASH_KEY_SHA256,
    )
    if phase == "before_replace":

        def exit_before_replace(source: Path, destination: Path) -> None:
            del source, destination
            os._exit(91)

        with patch.object(os, "replace", exit_before_replace):
            ledger.reserve("transport-crash-new-0001", "e" * 64)
    else:
        real_fsync = os.fsync

        def exit_before_directory_fsync(descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                os._exit(92)
            real_fsync(descriptor)

        with patch.object(os, "fsync", exit_before_directory_fsync):
            ledger.reserve("transport-crash-new-0001", "e" * 64)
    os._exit(90)


def _crash_checks() -> dict[str, Any]:
    root = Path(tempfile.mkdtemp(prefix="aegis-ot-m4f-crash-"))
    context = multiprocessing.get_context("spawn")
    results: dict[str, Any] = {}
    try:
        for phase in ("before_replace", "after_replace"):
            directory = root / phase
            directory.mkdir(mode=0o700)
            path = directory / "transport-replay.json"
            ledger = DurableTransportReplayLedger(
                path,
                audience=AUDIENCE,
                gateway_key_id=GATEWAY_KEY_ID,
                gateway_public_key_sha256=CRASH_KEY_SHA256,
                initialize=True,
            )
            ledger.reserve("transport-crash-old-0001", "d" * 64)
            before = path.read_bytes()
            worker = context.Process(target=_crash_worker, args=(str(path), phase))
            worker.start()
            worker.join(10)
            if worker.is_alive():
                worker.terminate()
                worker.join(5)
                raise m4d.ExperimentError("M4f replay crash worker did not exit")
            reloaded = DurableTransportReplayLedger(
                path,
                audience=AUDIENCE,
                gateway_key_id=GATEWAY_KEY_ID,
                gateway_public_key_sha256=CRASH_KEY_SHA256,
            )
            results[phase] = {
                "exit_code": worker.exitcode,
                "old_reservation_present": reloaded.contains(
                    "transport-crash-old-0001"
                ),
                "new_reservation_present": reloaded.contains(
                    "transport-crash-new-0001"
                ),
                "old_bytes_preserved": path.read_bytes() == before,
                "ledger_valid": True,
            }
        results["accepted"] = (
            results["before_replace"]["exit_code"] == 91
            and results["before_replace"]["old_reservation_present"] is True
            and results["before_replace"]["new_reservation_present"] is False
            and results["before_replace"]["old_bytes_preserved"] is True
            and results["after_replace"]["exit_code"] == 92
            and results["after_replace"]["old_reservation_present"] is True
            and results["after_replace"]["new_reservation_present"] is True
            and results["after_replace"]["ledger_valid"] is True
        )
        return results
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _campaign(project_name: str, commit: str) -> dict[str, Any]:
    _assert_project_absent(project_name)
    _assert_checkout(commit)
    source_checkout_binding = _assert_source_checkout()
    key_directory = Path(tempfile.mkdtemp(prefix="aegis-ot-m4f-keys-"))
    key_material = {
        "AEGIS_GATEWAY_PRIVATE_KEY_FILE": key_directory / "gateway.private",
        "AEGIS_GATEWAY_PUBLIC_KEY_FILE": key_directory / "gateway.public",
        "AEGIS_OT_PRIVATE_KEY_FILE": key_directory / "ot.private",
        "AEGIS_OT_PUBLIC_KEY_FILE": key_directory / "ot.public",
    }
    prior_environment: dict[str, str | None] = {}
    prefix = (
        "docker",
        "compose",
        "-p",
        project_name,
        "-f",
        "docker-compose.yml",
        "-f",
        "docker-compose.auth.yml",
        "-f",
        "docker-compose.replay.yml",
    )
    project_created = False
    evidence: dict[str, Any] | None = None
    cleanup: dict[str, bool] = {}
    try:
        gateway_private = Ed25519PrivateKey.generate()
        ot_private = Ed25519PrivateKey.generate()
        gateway_public_raw = _raw_public(gateway_private)
        ot_public_raw = _raw_public(ot_private)
        key_material["AEGIS_GATEWAY_PRIVATE_KEY_FILE"].write_bytes(
            _raw_private(gateway_private)
        )
        key_material["AEGIS_GATEWAY_PUBLIC_KEY_FILE"].write_bytes(gateway_public_raw)
        key_material["AEGIS_OT_PRIVATE_KEY_FILE"].write_bytes(_raw_private(ot_private))
        key_material["AEGIS_OT_PUBLIC_KEY_FILE"].write_bytes(ot_public_raw)
        for path in key_material.values():
            path.chmod(0o600)
        prior_environment = {name: os.environ.get(name) for name in key_material}
        for name, path in key_material.items():
            os.environ[name] = str(path)
        compose = json.loads(
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "config",
                "--format",
                "json",
            ).stdout
        )
        normalized_compose = _normalize(compose, key_directory, project_name)
        normalized_compose_sha256 = m4d._canonical_sha256(normalized_compose)
        m4d._run(*prefix, "--profile", "experiment", "build")
        project_created = True
        m4d._run(
            *prefix,
            "up",
            "-d",
            "--force-recreate",
            "opa",
            "simulation",
            "observer",
            "ot-adapter",
            "segmented-gateway",
        )
        _await_gateway_stack()
        m4d._await_opa(prefix)
        _await_durable_ot_health(prefix)
        initialization = _parse_init_log(prefix)
        agent = json.loads(
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "run",
                "--rm",
                "--no-deps",
                "agent-probe",
            ).stdout
        )
        transport = json.loads(
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "run",
                "--rm",
                "--no-deps",
                "transport-probe",
            ).stdout
        )
        if not isinstance(agent, dict) or not isinstance(transport, dict):
            raise m4d.ExperimentError("M4f probe output was not an object")
        identities_before = _service_identities(prefix)
        identity_before = identities_before["ot-adapter"]
        prepare = json.loads(
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "run",
                "--rm",
                "--no-deps",
                "-e",
                "AEGIS_TRANSPORT_PROBE_MODE=prepare_restart",
                "transport-probe",
            ).stdout
        )
        if not isinstance(prepare, dict) or prepare.get("accepted") is not True:
            raise m4d.ExperimentError("M4f restart preparation was not accepted")
        ledger_before_restart = _ledger_snapshot(prefix)

        m4d._run(
            *prefix,
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "ot-adapter",
        )
        restart = json.loads(
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "run",
                "--rm",
                "--no-deps",
                "-e",
                "AEGIS_TRANSPORT_PROBE_MODE=restart_replay",
                "transport-probe",
            ).stdout
        )
        if not isinstance(restart, dict):
            raise m4d.ExperimentError("M4f restart probe output was not an object")
        identities_after = _service_identities(prefix)
        identity_after = identities_after["ot-adapter"]
        ledger_after_fresh = _ledger_snapshot(prefix)

        replay_volume = _replay_volume_name(identity_after)
        m4d._run(*prefix, "stop", "ot-adapter")
        corrupt_command = (
            "from pathlib import Path; "
            "Path('/var/lib/aegis-ot/transport-replay.json').write_bytes(b'{corrupt')"
        )
        m4d._run(
            *prefix,
            "run",
            "--rm",
            "--no-deps",
            "--user",
            "65532:65532",
            "ot-adapter",
            "python",
            "-c",
            corrupt_command,
        )
        fault_container_id = identity_after.get("container_id")
        if not isinstance(fault_container_id, str) or not fault_container_id:
            raise m4d.ExperimentError("OT-adapter container ID was unavailable")
        m4d._run("docker", "start", fault_container_id)
        ledger_fault = json.loads(
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "run",
                "--rm",
                "--no-deps",
                "-e",
                "AEGIS_TRANSPORT_PROBE_MODE=ledger_fault",
                "transport-probe",
            ).stdout
        )
        if not isinstance(ledger_fault, dict):
            raise m4d.ExperimentError("M4f ledger-fault probe output was not an object")

        networks = m4d._network_inventory(
            project_name,
            ["agent", "trust", "control_dmz", "simulation"],
        )
        images = m4d._json_records(
            m4d._run(
                *prefix,
                "--profile",
                "experiment",
                "images",
                "--format",
                "json",
            ).stdout
        )
        crash_checks = _crash_checks()
        offline_verification = _verify_exact_artifacts(
            transport,
            prepare,
            gateway_public_raw,
            ot_public_raw,
        )
        fault_request = SignedSegmentedExecutionRequest.model_validate(
            ledger_fault.get("request", {}).get("signed_request")
        )
        offline_verification.update(
            {
                "corrupt_fault_request_audience_verified_offline": (
                    fault_request.audience == AUDIENCE
                ),
                "corrupt_fault_request_key_id_verified_offline": (
                    fault_request.gateway_key_id == GATEWAY_KEY_ID
                ),
                "corrupt_fault_request_signature_verified_offline": (
                    fault_request.verify(
                        Ed25519PublicKey.from_public_bytes(gateway_public_raw)
                    )
                ),
            }
        )
        prepare_health = prepare.get("health_after", {})
        restart_health = restart.get("health_before", {})
        replay_health = restart.get("health_after_replay", {})
        fresh_health = restart.get("health_after_fresh", {})
        exact_prepared = prepare.get("prepared_request", {})
        exact_restart = restart.get("exact_restart_replay", {})
        prepared_request = SignedSegmentedExecutionRequest.model_validate(
            exact_prepared.get("signed_request")
        )
        prepared_reservation = {
            "nonce": prepared_request.transport_nonce,
            "signed_request_sha256": _sha256(prepared_request),
        }
        ledger_reservations = ledger_before_restart.get("document", {}).get(
            "reservations",
            [],
        )
        same_volume = _replay_volume_name(identity_before) == replay_volume
        unchanged_services = all(
            identities_before[service].get("container_id")
            == identities_after[service].get("container_id")
            and identities_before[service].get("started_at")
            == identities_after[service].get("started_at")
            for service in ("opa", "simulation", "observer", "segmented-gateway")
        )
        prior_boot_epoch = prepare_health.get("boot_epoch")
        restart_boot_epoch = restart_health.get("boot_epoch")
        acceptance = {
            "replay_volume_initialized_closed_and_private": (
                initialization.get("ledger_reservations") == 0
                and initialization.get("ledger_mode") == "0600"
                and initialization.get("directory_mode") == "0700"
            ),
            "signed_agent_campaign_accepted": agent.get("accepted") is True,
            "same_boot_transport_campaign_accepted": transport.get("accepted") is True,
            "restart_request_prepared_immediately_before_replacement": (
                prepare.get("accepted") is True
            ),
            "exact_artifacts_verify_offline": all(offline_verification.values()),
            "ledger_snapshot_canonical_and_bound": (
                ledger_before_restart.get("canonical") is True
                and ledger_before_restart.get("sha256")
                == prepare_health.get("replay_ledger_sha256")
                and ledger_before_restart.get("document", {}).get("gateway_key_id")
                == GATEWAY_KEY_ID
                and ledger_before_restart.get("document", {}).get(
                    "gateway_public_key_sha256"
                )
                == hashlib.sha256(gateway_public_raw).hexdigest()
                and prepared_reservation in ledger_reservations
            ),
            "only_ot_adapter_was_replaced": (
                identity_before.get("container_id") != identity_after.get("container_id")
                and same_volume
                and unchanged_services
            ),
            "adapter_boot_epoch_changed": (
                isinstance(prior_boot_epoch, str)
                and bool(prior_boot_epoch)
                and isinstance(restart_boot_epoch, str)
                and bool(restart_boot_epoch)
                and prior_boot_epoch != restart_boot_epoch
            ),
            "durable_exact_replay_rejected_without_mutation": (
                restart.get("accepted") is True
                and exact_prepared.get("request_sha256")
                == exact_restart.get("request_sha256")
                and prepare_health.get("replay_ledger_sha256")
                == restart_health.get("replay_ledger_sha256")
                == replay_health.get("replay_ledger_sha256")
            ),
            "fresh_request_after_restart_preserved_liveness": (
                fresh_health.get("replay_reservations")
                == replay_health.get("replay_reservations", 0) + 1
                and ledger_after_fresh.get("sha256")
                == fresh_health.get("replay_ledger_sha256")
            ),
            "corrupt_ledger_failed_closed_without_effect": (
                ledger_fault.get("accepted") is True
                and fault_request.request.decision.state_version
                == ledger_fault.get("state_before", {}).get("version")
                and all(
                    offline_verification[name]
                    for name in (
                        "corrupt_fault_request_audience_verified_offline",
                        "corrupt_fault_request_key_id_verified_offline",
                        "corrupt_fault_request_signature_verified_offline",
                    )
                )
            ),
        }
        semantic_agent = dict(agent)
        semantic_agent.pop("agent_hostname", None)
        semantic_material = {
            "git_commit": commit,
            "normalized_compose_sha256": normalized_compose_sha256,
            "source_package_directory": source_checkout_binding["package_directory"],
            "network_inventory": _normalize(networks, key_directory, project_name),
            "agent_probe": semantic_agent,
            "transport_probe": _semantic_transport(transport),
            "prepare_restart_probe": _semantic_prepare(prepare),
            "restart_probe": _semantic_restart(restart),
            "ledger_fault": {
                "accepted": ledger_fault.get("accepted"),
                "http_status": ledger_fault.get("request", {}).get("http_status"),
                "state_version_delta": (
                    ledger_fault.get("state_after", {}).get("version", 0)
                    - ledger_fault.get("state_before", {}).get("version", 0)
                ),
            },
            "offline_verification": offline_verification,
            "acceptance": acceptance,
        }
        evidence = {
            "schema_version": "m4f-durable-transport-replay-experiment-v1",
            "generated_at": datetime.now(UTC).isoformat(),
            "analyst": "Angelis Pseftis",
            "git_commit": commit,
            "clean_checkout_start": True,
            "project_name": project_name,
            "normalized_compose_sha256": normalized_compose_sha256,
            "source_checkout_binding": source_checkout_binding,
            "public_verification_material": {
                "gateway_key_id": GATEWAY_KEY_ID,
                "gateway_public_key_base64": base64.b64encode(gateway_public_raw).decode(),
                "gateway_public_key_sha256": hashlib.sha256(
                    gateway_public_raw
                ).hexdigest(),
                "ot_key_id": OT_KEY_ID,
                "ot_public_key_base64": base64.b64encode(ot_public_raw).decode(),
                "ot_public_key_sha256": hashlib.sha256(ot_public_raw).hexdigest(),
            },
            "private_key_material_retained": False,
            "replay_initialization": initialization,
            "images": images,
            "network_inventory": networks,
            "service_identities_before_replacement": identities_before,
            "service_identities_after_replacement": identities_after,
            "replay_volume_name": replay_volume,
            "agent_probe": agent,
            "transport_probe": transport,
            "prepare_restart_probe": prepare,
            "ledger_before_restart": ledger_before_restart,
            "restart_probe": restart,
            "ledger_after_fresh_request": ledger_after_fresh,
            "corrupt_ledger_probe": ledger_fault,
            "supplemental_host_replay_ledger_process_exit_checks": {
                "classification": (
                    "Host-filesystem code-path evidence; not Docker-volume or "
                    "power-loss durability evidence"
                ),
                "results": crash_checks,
            },
            "offline_artifact_verification": offline_verification,
            "acceptance": acceptance,
            "accepted": all(acceptance.values()),
            "semantic_projection": semantic_material,
            "semantic_outcome_sha256": m4d._canonical_sha256(semantic_material),
            "evidence_boundary": [
                "Durable at-most-once exact-envelope admission, not exactly-once effects",
                (
                    "A lost response after dispatch remains outcome-unknown until "
                    "observation reconciliation"
                ),
                "One Uvicorn process and one OT-adapter writer; no multi-replica coordination",
                (
                    "Intact trusted Docker volume; no hostile-host rollback or external "
                    "monotonic anchor"
                ),
                (
                    "Process-exit fsync checks ran on the host filesystem; they are "
                    "code-path evidence, not Docker-volume or power-loss durability evidence"
                ),
                (
                    "Ephemeral Ed25519 message authentication, not SPIFFE, TLS peer "
                    "identity, or revocation"
                ),
                (
                    "Synthetic single-host execution, not production OT or independent "
                    "external validation"
                ),
            ],
        }
        _assert_checkout(commit)
        if evidence["accepted"] is not True:
            raise m4d.ExperimentError("M4f acceptance criteria were not all satisfied")
    finally:
        if project_created:
            down = m4d._run(
                *prefix,
                "down",
                "-v",
                "--remove-orphans",
                check=False,
            )
            cleanup["compose_project_removed"] = down.returncode == 0
        for name, previous in prior_environment.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
        shutil.rmtree(key_directory, ignore_errors=True)
        cleanup["private_key_directory_removed"] = not key_directory.exists()
        cleanup["replay_volume_removed"] = (
            m4d._run(
                "docker",
                "volume",
                "inspect",
                f"{project_name}_transport_replay",
                check=False,
            ).returncode
            != 0
        )
        cleanup["probe_volume_removed"] = (
            m4d._run(
                "docker",
                "volume",
                "inspect",
                f"{project_name}_transport_probe",
                check=False,
            ).returncode
            != 0
        )
    if evidence is None:
        raise m4d.ExperimentError("M4f campaign ended without evidence")
    evidence["cleanup"] = cleanup
    if not all(cleanup.values()):
        raise m4d.ExperimentError("M4f scoped cleanup was incomplete")
    return evidence


def run_pair(
    output: Path,
    reproduction_output: Path,
    primary_project: str,
    reproduction_project: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _assert_source_checkout()
    if output.resolve() == reproduction_output.resolve():
        raise m4d.ExperimentError("M4f evidence outputs must resolve to distinct files")
    if (
        output.exists()
        or output.is_symlink()
        or reproduction_output.exists()
        or reproduction_output.is_symlink()
    ):
        raise m4d.ExperimentError("refusing to overwrite retained M4f evidence")
    if m4d._run("git", "status", "--porcelain").stdout:
        raise m4d.ExperimentError("M4f retained evidence requires a clean checkout")
    commit = m4d._run("git", "rev-parse", "HEAD").stdout.strip()
    _assert_checkout(commit)
    primary = _campaign(primary_project, commit)
    _assert_checkout(commit)
    reproduction = _campaign(reproduction_project, commit)
    _assert_checkout(commit)
    hashes_match = (
        primary["semantic_outcome_sha256"]
        == reproduction["semantic_outcome_sha256"]
    )
    if not hashes_match:
        difference = _first_semantic_difference(
            primary["semantic_projection"],
            reproduction["semantic_projection"],
        )
        raise m4d.ExperimentError(
            f"M4f paired semantic outcomes did not reproduce; first difference: {difference}"
        )
    _assert_checkout(commit)
    comparison = {
        "semantic_outcomes_match": True,
        "primary_semantic_outcome_sha256": primary["semantic_outcome_sha256"],
        "reproduction_semantic_outcome_sha256": reproduction[
            "semantic_outcome_sha256"
        ],
    }
    primary["clean_checkout_end"] = True
    reproduction["clean_checkout_end"] = True
    primary["reproduction_comparison"] = {**comparison, "role": "primary"}
    reproduction["reproduction_comparison"] = {**comparison, "role": "reproduction"}
    try:
        m4d._atomic_write_json(output, primary)
        m4d._atomic_write_json(reproduction_output, reproduction)
    except Exception:
        output.unlink(missing_ok=True)
        reproduction_output.unlink(missing_ok=True)
        raise
    return primary, reproduction


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reproduction-output", type=Path, required=True)
    parser.add_argument("--primary-project", default="aegis-ot-m4f-primary")
    parser.add_argument("--reproduction-project", default="aegis-ot-m4f-reproduction")
    arguments = parser.parse_args()
    primary, reproduction = run_pair(
        arguments.output,
        arguments.reproduction_output,
        arguments.primary_project,
        arguments.reproduction_project,
    )
    print(
        json.dumps(
            {
                "accepted": primary["accepted"] and reproduction["accepted"],
                "semantic_outcome_sha256": primary["semantic_outcome_sha256"],
                "outputs": [str(arguments.output), str(arguments.reproduction_output)],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
