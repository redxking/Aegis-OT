"""Controlled M4b retained-evidence experiment over the M4a local process stack.

This module runs a deliberately bounded same-host experiment, closes the M4a
stack, and only then invokes the separately implemented topology evaluator by
file.  It prepares canonical package artifacts; package finalization and
offline verification live in :mod:`aegis_ot.m4b_package`.

The resulting evidence is not HELICS, OpenPLC, a segmented deployment, a
physical-device result, independent sensing, or proof of WP4 completion.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from importlib import metadata
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, JsonValue

from aegis_ot_independent.canonical import strict_json_loads

from .capability_factory import CapabilitySeparatedLab, start_capability_separated_lab
from .capability_models import (
    CapabilityClosedLoopResult,
    CapabilityClosedLoopStatus,
    DispatchPhase,
)
from .evidence import EvidenceRecord
from .experiment import derive_master_seeds
from .m4b_models import (
    IndependentConsequenceReport,
    IndependentEvaluationRequest,
    IndependentEvaluationStatus,
    M4bCapabilityProbeBundle,
    M4bCapabilityProbeRecord,
    M4bComponentRegistration,
    M4bComponentRole,
    M4bOrderlyRestartReplayRecord,
    M4bTransactionRecord,
    canonical_json_bytes,
    public_key_base64,
    public_key_from_base64,
    sha256_bytes,
)
from .models import ActionProposal, Operation
from .physical_models import CommandStatus, canonical_digest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "fixtures/m4b/cigre-mv-topology-v1.json"
REFERENCE_TIME = datetime(2026, 8, 25, 16, 0, tzinfo=UTC)
EXPERIMENT_VERSION = "m4b-capability-evidence-v1"
OUTCOME_PROJECTION_VERSION = "m4b-outcome-projection-v1"
PROTOCOL_VERSION = "m4b-capability-protocol-v1"
MAX_M4B_SESSIONS = 100
CONDITION_ORDER = (
    "unknown_identity",
    "stale_observation",
    "nominal_permitted_execution",
)
EXPECTED_STATUSES = (
    CapabilityClosedLoopStatus.NOT_DISPATCHED,
    CapabilityClosedLoopStatus.NOT_DISPATCHED,
    CapabilityClosedLoopStatus.COMPLETED,
)
M4B_SCHEMA_NAMES = (
    "m4a-action-request.schema.json",
    "m4a-closed-loop-result.schema.json",
    "m4a-execution-permit.schema.json",
    "m4a-plc-acknowledgment.schema.json",
    "m4a-signed-observation.schema.json",
    "m3-physical-command.schema.json",
    "m3-physical-state.schema.json",
    "m4b-artifact-descriptor.schema.json",
    "m4b-capability-probe-bundle.schema.json",
    "m4b-component-registration.schema.json",
    "m4b-evidence-manifest.schema.json",
    "m4b-independent-consequence-report.schema.json",
    "m4b-independent-evaluation-request.schema.json",
    "m4b-manifest-signature.schema.json",
    "m4b-orderly-restart-replay.schema.json",
    "m4b-transaction-record.schema.json",
    "m4b-trust-anchor.schema.json",
)


@dataclass(frozen=True)
class CollectedM4bExperiment:
    """Canonical package inputs produced before root-key finalization."""

    artifacts: dict[str, bytes]
    started_at_utc: datetime
    completed_at_utc: datetime
    git: dict[str, JsonValue]
    root_seed: int
    master_seeds: tuple[int, ...]
    transaction_records: tuple[M4bTransactionRecord, ...]
    evidence_records: tuple[dict[str, JsonValue], ...]
    component_registrations: tuple[M4bComponentRegistration, ...]
    probe_bundles: tuple[M4bCapabilityProbeBundle, ...]
    replay_records: tuple[M4bOrderlyRestartReplayRecord, ...]
    evaluation_requests: tuple[IndependentEvaluationRequest, ...]
    evaluation_reports: tuple[IndependentConsequenceReport, ...]
    source_sha256: dict[str, str]
    schema_sha256: dict[str, str]
    configuration_sha256: dict[str, str]
    fixture_sha256: dict[str, str]
    host: dict[str, JsonValue]
    component_versions: dict[str, str]


@dataclass(frozen=True)
class _RawTransaction:
    condition: str
    expected_status: CapabilityClosedLoopStatus
    result: CapabilityClosedLoopResult
    first_sequence: int
    last_sequence: int
    chain_head: str


@dataclass(frozen=True)
class _LiveSession:
    session_id: str
    session_index: int
    master_seed: int
    runtime_registrations: tuple[M4bComponentRegistration, ...]
    evaluator_registration: M4bComponentRegistration
    transactions: tuple[M4bTransactionRecord, ...]
    evidence_records: tuple[dict[str, JsonValue], ...]
    health_bundles: tuple[dict[str, JsonValue], ...]
    probes: M4bCapabilityProbeBundle
    replay: M4bOrderlyRestartReplayRecord
    request: IndependentEvaluationRequest
    report: IndependentConsequenceReport


def _jsonl(records: tuple[BaseModel | dict[str, JsonValue], ...]) -> bytes:
    return b"".join(canonical_json_bytes(record) + b"\n" for record in records)


def _flatten_capabilities(capabilities: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    return tuple(
        sorted(
            f"{role}:{operation}"
            for role, operations in capabilities.items()
            for operation in operations
        )
    )


def _raw_public_key_sha256(public_key_bytes: bytes) -> str:
    return sha256_bytes(public_key_bytes)


def _health_bundle(
    *,
    session_id: str,
    session_index: int,
    master_seed: int,
    phase: str,
    captured_at: datetime,
    records: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    material: dict[str, JsonValue] = {
        "schema_version": "m4b-component-health-bundle-v1",
        "session_id": session_id,
        "session_index": session_index,
        "master_seed": master_seed,
        "phase": phase,
        "captured_at": captured_at.isoformat().replace("+00:00", "Z"),
        "records": {key: records[key] for key in sorted(records)},
    }
    return {
        **material,
        "bundle_sha256": sha256_bytes(canonical_json_bytes(material)),
    }


def _health_digest(bundle: dict[str, JsonValue]) -> str:
    return sha256_bytes(canonical_json_bytes(bundle))


def _runtime_registration_digest(
    registrations: tuple[M4bComponentRegistration, ...],
) -> str:
    return sha256_bytes(
        canonical_json_bytes([item.model_dump(mode="json") for item in registrations])
    )


def _pre_evaluation_transaction_digest(record: M4bTransactionRecord) -> str:
    return record.evaluation_binding_sha256


def _proposal(
    lab: CapabilitySeparatedLab,
    observation: Any,
    *,
    session_index: int,
    condition: str,
    actor_id: str,
) -> ActionProposal:
    return ActionProposal(
        proposal_id=f"m4b-{session_index:03d}-{condition}",
        actor_id=actor_id,
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=observation.snapshot.state_version,
        observed_at=observation.snapshot.observed_at,
        submitted_at=observation.snapshot.observed_at,
        nonce=f"m4b-{session_index:03d}-{condition}-nonce-0001",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=(
            lab.authorization.root_grant.grant_id,
            lab.authorization.leaf_grant.grant_id,
        ),
    )


def _execute_transaction(
    lab: CapabilitySeparatedLab,
    *,
    observation: Any,
    session_index: int,
    condition: str,
    actor_id: str,
    expected_status: CapabilityClosedLoopStatus,
) -> _RawTransaction:
    before = len(lab.authorization.gateway.evidence.records)
    proposal = _proposal(
        lab,
        observation,
        session_index=session_index,
        condition=condition,
        actor_id=actor_id,
    )
    result = lab.controller.execute(lab.request_for(proposal, observation))
    records = lab.authorization.gateway.evidence.records
    if result.status is not expected_status:
        raise RuntimeError(
            f"{condition} expected {expected_status.value}, observed {result.status.value}"
        )
    if len(records) <= before or records[-1].record_hash != result.execution_evidence_hash:
        raise RuntimeError(f"{condition} did not close on its retained evidence record")
    return _RawTransaction(
        condition=condition,
        expected_status=expected_status,
        result=result,
        first_sequence=before,
        last_sequence=len(records) - 1,
        chain_head=records[-1].record_hash,
    )


def _component_registrations_before_evaluation(
    lab: CapabilitySeparatedLab,
    *,
    session_id: str,
    session_index: int,
    master_seed: int,
    initial_plc: Any,
    replacement_plc: Any,
    registered_at: datetime,
) -> tuple[M4bComponentRegistration, ...]:
    stack = lab.processes
    observer_raw = stack.observer_info.public_key_bytes
    initial_plc_raw = initial_plc.public_key_bytes
    replacement_plc_raw = replacement_plc.public_key_bytes
    permit_raw = stack.permit_public_key_bytes
    values = (
        M4bComponentRegistration(
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            role=M4bComponentRole.PLANT,
            component_id="plant:deterministic-local",
            pid=stack.plant_info.pid,
            boot_epoch=stack.plant_info.boot_epoch,
            capabilities=_flatten_capabilities(stack.plant_info.capabilities),
            plant_boot_epoch=stack.plant_info.boot_epoch,
            model_digest=stack.plant_info.model_digest,
            registered_at=registered_at,
        ),
        M4bComponentRegistration(
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            role=M4bComponentRole.OBSERVER,
            component_id=stack.observer_info.observer_id,
            pid=stack.observer_info.pid,
            boot_epoch=stack.observer_info.boot_epoch,
            key_id=stack.observer_info.key_id,
            public_key_b64=public_key_base64(stack.observer_info.public_key),
            public_key_sha256=_raw_public_key_sha256(observer_raw),
            capabilities=_flatten_capabilities(stack.observer_info.capabilities),
            plant_boot_epoch=stack.observer_info.plant_boot_epoch,
            registered_at=registered_at,
        ),
        M4bComponentRegistration(
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            role=M4bComponentRole.PLC,
            component_id=initial_plc.plc_id,
            pid=initial_plc.pid,
            boot_epoch=initial_plc.boot_epoch,
            key_id=initial_plc.key_id,
            public_key_b64=public_key_base64(initial_plc.public_key),
            public_key_sha256=_raw_public_key_sha256(initial_plc_raw),
            capabilities=_flatten_capabilities(initial_plc.capabilities),
            plant_boot_epoch=initial_plc.plant_boot_epoch,
            registered_at=registered_at,
        ),
        M4bComponentRegistration(
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            role=M4bComponentRole.PERMIT_SIGNER,
            component_id="permit-signer:capability-controller",
            pid=os.getpid(),
            boot_epoch=f"permit-signer:{session_id}",
            key_id=stack.permit_key_id,
            public_key_b64=public_key_base64(lab.permit_public_key),
            public_key_sha256=_raw_public_key_sha256(permit_raw),
            capabilities=("issue:capability_execution_permit",),
            registered_at=registered_at,
        ),
        M4bComponentRegistration(
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            role=M4bComponentRole.REPLACEMENT_PLC,
            component_id=replacement_plc.plc_id,
            pid=replacement_plc.pid,
            boot_epoch=replacement_plc.boot_epoch,
            key_id=replacement_plc.key_id,
            public_key_b64=public_key_base64(replacement_plc.public_key),
            public_key_sha256=_raw_public_key_sha256(replacement_plc_raw),
            capabilities=_flatten_capabilities(replacement_plc.capabilities),
            plant_boot_epoch=replacement_plc.plant_boot_epoch,
            registered_at=registered_at,
        ),
    )
    if len({item.boot_epoch for item in values}) != len(values):
        raise RuntimeError("runtime component boot epochs are not distinct")
    keyed = tuple(item.public_key_sha256 for item in values if item.public_key_sha256)
    if len(set(keyed)) != len(keyed):
        raise RuntimeError("runtime component public keys are not distinct")
    if initial_plc.pid == replacement_plc.pid:
        raise RuntimeError("replacement PLC reused the initial PLC process")
    return values


def _probe_bundle(
    lab: CapabilitySeparatedLab,
    *,
    session_id: str,
    session_index: int,
    observed_at: datetime,
) -> M4bCapabilityProbeBundle:
    proposal = _proposal(
        lab,
        lab.initial_observation,
        session_index=session_index,
        condition="capability_probe",
        actor_id="agent:operator-1",
    )
    command = lab.controller.translator.translate(proposal)
    command_sha = canonical_digest(command)
    outcomes = (
        (
            M4bComponentRole.OBSERVER,
            "telemetry:capture_post",
            lab.processes.telemetry.probe_forbidden_post_capture(),
        ),
        (
            M4bComponentRole.OBSERVER,
            "admin->plant:apply_authorized_command",
            lab.processes.observer_admin.probe_forbidden_plant_apply(command),
        ),
        (
            M4bComponentRole.PLANT,
            "admin:apply_authorized_command",
            lab.processes.plant_admin.probe_forbidden_apply(command),
        ),
        (
            M4bComponentRole.PLANT,
            "simulation:apply_authorized_command",
            lab.processes.simulator.probe_forbidden_apply(command),
        ),
    )
    records = tuple(
        M4bCapabilityProbeRecord(
            session_id=session_id,
            ordinal=ordinal,
            endpoint_role=role,
            operation=operation,
            actual_disposition=outcome,
            request_payload_sha256=command_sha,
            observed_at=observed_at,
        )
        for ordinal, (role, operation, outcome) in enumerate(outcomes, start=1)
    )
    if not all(item.matched_expectation for item in records):
        raise RuntimeError("one or more capability probes did not fail closed")
    return M4bCapabilityProbeBundle.issue(session_id=session_id, records=records)


def _evidence_wrapper(
    record: EvidenceRecord,
    *,
    session_id: str,
    session_index: int,
    master_seed: int,
) -> dict[str, JsonValue]:
    return {
        "schema_version": "m4b-evidence-record-wrapper-v1",
        "session_id": session_id,
        "session_index": session_index,
        "master_seed": master_seed,
        "record": cast(JsonValue, record.model_dump(mode="json")),
    }


def load_fixture(path: Path = FIXTURE_PATH) -> dict[str, JsonValue]:
    """Load one regular, duplicate-key-free topology fixture without executing it."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("independent topology fixture must be a regular non-symlink file")
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("independent topology fixture root must be an object")
    fixture = cast(dict[str, JsonValue], value)
    if (
        fixture.get("fixture_id") != "pandapower-cigre-mv-all-neutral-topology-v1"
        or fixture.get("fixture_digest")
        != "58ed983e507811935c448e6d468e952ff34620958eae893d16d454a89651709f"
    ):
        raise ValueError("independent topology fixture is not the registered M4b fixture")
    return fixture


def build_independent_evaluation_request(
    *,
    record: M4bTransactionRecord,
    fixture: dict[str, JsonValue],
    observer_public_key: Ed25519PublicKey,
    request_id: str,
    nonce: str,
    absolute_tolerance_mw: Decimal = Decimal("0.000000001"),
    absolute_tolerance_pct: Decimal = Decimal("0.000000001"),
) -> IndependentEvaluationRequest:
    """Project a completed retained transaction into the neutral evaluator input."""

    result = record.result
    if (
        result.status is not CapabilityClosedLoopStatus.COMPLETED
        or result.pre_observation is None
        or result.post_observation is None
        or result.command is None
    ):
        raise ValueError("independent topology evaluation requires a completed transition")
    fixture_id = fixture.get("fixture_id")
    fixture_digest = fixture.get("fixture_digest")
    if not isinstance(fixture_id, str) or not isinstance(fixture_digest, str):
        raise ValueError("independent topology fixture identity is invalid")
    return IndependentEvaluationRequest(
        request_id=request_id,
        session_index=record.session_index,
        master_seed=record.master_seed,
        transaction_record_digest=record.evaluation_binding_sha256,
        fixture_id=fixture_id,
        fixture_digest=fixture_digest,
        nonce=nonce,
        pre_observation=result.pre_observation,
        post_observation=result.post_observation,
        command=result.command,
        observer_key_id=result.pre_observation.observer_key_id,
        observer_public_key_b64=public_key_base64(observer_public_key),
        absolute_tolerance_mw=absolute_tolerance_mw,
        absolute_tolerance_pct=absolute_tolerance_pct,
    )


def _write_exclusive(path: Path, material: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(material):
            offset += os.write(descriptor, material[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_independent_evaluator(
    *,
    request: IndependentEvaluationRequest,
    fixture_path: Path = FIXTURE_PATH,
    request_path: Path,
    report_path: Path,
) -> IndependentConsequenceReport:
    """Run the file-only evaluator process and verify its exact signed output."""

    _write_exclusive(request_path, request.canonical_bytes() + b"\n")
    environment = dict(os.environ)
    source_root = str(ROOT / "src")
    existing_path = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_root if not existing_path else os.pathsep.join((source_root, existing_path))
    )
    completed = subprocess.run(  # noqa: S603 - fixed module; controlled local paths
        [
            sys.executable,
            "-m",
            "aegis_ot_independent",
            "--request",
            str(request_path),
            "--fixture",
            str(fixture_path),
            "--output",
            str(report_path),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "independent evaluator did not agree: "
            f"exit={completed.returncode}, stdout={completed.stdout!r}, "
            f"stderr={completed.stderr!r}"
        )
    if not report_path.is_file() or report_path.is_symlink():
        raise RuntimeError("independent evaluator did not create a regular report")
    report_material = report_path.read_bytes()
    report = IndependentConsequenceReport.model_validate_json(report_material)
    expected_material = report.canonical_bytes() + b"\n"
    if report_material != expected_material:
        raise RuntimeError("independent evaluator report is not canonical JSON")
    if not report.verify_for_request(request):
        raise RuntimeError("independent evaluator report failed signature or request binding")
    if report.status is not IndependentEvaluationStatus.AGREE:
        raise RuntimeError(f"independent evaluator returned {report.status.value}")
    return report


def _run_independent_evaluator(
    request: IndependentEvaluationRequest,
) -> IndependentConsequenceReport:
    with tempfile.TemporaryDirectory(prefix="aegis-ot-m4b-evaluator-") as temporary:
        directory = Path(temporary)
        return run_independent_evaluator(
            request=request,
            fixture_path=FIXTURE_PATH,
            request_path=directory / "request.json",
            report_path=directory / "report.json",
        )


def _transaction_record(
    raw: _RawTransaction,
    *,
    session_id: str,
    session_index: int,
    master_seed: int,
    registrations_sha256: str,
    pre_health_sha256: str,
    post_health_sha256: str,
    report: IndependentConsequenceReport | None = None,
) -> M4bTransactionRecord:
    return M4bTransactionRecord(
        session_id=session_id,
        session_index=session_index,
        master_seed=master_seed,
        condition=raw.condition,
        expected_terminal_status=raw.expected_status,
        result=raw.result,
        result_sha256=canonical_digest(raw.result),
        evidence_first_sequence=raw.first_sequence,
        evidence_last_sequence=raw.last_sequence,
        evidence_chain_head=raw.chain_head,
        component_registration_sha256=registrations_sha256,
        pre_health_sha256=pre_health_sha256,
        post_health_sha256=post_health_sha256,
        independent_report_id=report.report_id if report is not None else None,
        independent_report_sha256=report.digest if report is not None else None,
    )


def _run_session(session_index: int, master_seed: int) -> _LiveSession:
    session_id = f"m4b-session-{session_index:03d}-{master_seed:016x}"
    reference_time = REFERENCE_TIME + timedelta(minutes=session_index)
    lab = start_capability_separated_lab(reference_time)
    closed = False
    try:
        initial_plc = lab.processes.plc_info
        probes = _probe_bundle(
            lab,
            session_id=session_id,
            session_index=session_index,
            observed_at=reference_time,
        )
        pre_health = _health_bundle(
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            phase="pre_transactions",
            captured_at=reference_time,
            records={
                "observer": cast(JsonValue, lab.processes.observer_admin.health()),
                "plant": cast(JsonValue, lab.processes.plant_admin.health()),
                "plc": cast(JsonValue, lab.processes.plc_admin.health()),
            },
        )

        unknown = _execute_transaction(
            lab,
            observation=lab.initial_observation,
            session_index=session_index,
            condition=CONDITION_ORDER[0],
            actor_id="agent:unknown",
            expected_status=EXPECTED_STATUSES[0],
        )

        stale_observation = lab.capture_observation(
            correlation_id=f"{session_id}:stale",
            challenge_nonce=f"{session_id}:stale-challenge-0001",
        )
        lab.controller.clock = lambda: reference_time + timedelta(seconds=6)
        stale = _execute_transaction(
            lab,
            observation=stale_observation,
            session_index=session_index,
            condition=CONDITION_ORDER[1],
            actor_id="agent:operator-1",
            expected_status=EXPECTED_STATUSES[1],
        )
        if "observation_stale" not in stale.result.reasons:
            raise RuntimeError("stale-observation condition did not retain its expected reason")
        lab.controller.clock = lambda: reference_time

        nominal_observation = lab.capture_observation(
            correlation_id=f"{session_id}:nominal",
            challenge_nonce=f"{session_id}:nominal-challenge-0001",
        )
        nominal = _execute_transaction(
            lab,
            observation=nominal_observation,
            session_index=session_index,
            condition=CONDITION_ORDER[2],
            actor_id="agent:operator-1",
            expected_status=EXPECTED_STATUSES[2],
        )
        if nominal.result.dispatch_attempts != 1 or nominal.result.automatic_retry_count != 0:
            raise RuntimeError("nominal transaction violated the one-dispatch/no-retry contract")
        if not all(
            (
                nominal.result.pre_observation,
                nominal.result.decision,
                nominal.result.command,
                nominal.result.assessment,
                nominal.result.permit,
                nominal.result.acknowledgment,
                nominal.result.post_observation,
            )
        ):
            raise RuntimeError("nominal transaction is missing a required signed artifact")

        post_health = _health_bundle(
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            phase="post_nominal",
            captured_at=reference_time,
            records={
                "observer": cast(JsonValue, lab.processes.observer_admin.health()),
                "plant": cast(JsonValue, lab.processes.plant_admin.health()),
                "plc": cast(JsonValue, lab.processes.plc_admin.health()),
            },
        )
        if not lab.authorization.gateway.evidence.verify():
            raise RuntimeError("session evidence hash chain is invalid")

        pre_replay_health = _health_bundle(
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            phase="pre_replay",
            captured_at=reference_time,
            records={
                "observer": cast(JsonValue, lab.processes.observer_admin.health()),
                "plant": cast(JsonValue, lab.processes.plant_admin.health()),
                "plc": cast(JsonValue, lab.processes.plc_admin.health()),
            },
        )
        replacement_plc = lab.restart_plc()
        result = nominal.result
        permit = result.permit
        pre_observation = result.pre_observation
        decision = result.decision
        assessment = result.assessment
        command = result.command
        post_observation = result.post_observation
        if any(
            item is None
            for item in (
                permit,
                pre_observation,
                decision,
                assessment,
                command,
                post_observation,
            )
        ):
            raise RuntimeError("nominal completion lost a required transaction artifact")
        assert permit is not None
        assert pre_observation is not None
        assert decision is not None
        assert assessment is not None
        assert command is not None
        assert post_observation is not None
        replay_acknowledgment = lab.processes.plc_gateway.execute(
            request=result.request,
            permit=permit,
            pre_observation=pre_observation,
            decision=decision,
            assessment=assessment,
        )
        if (
            replay_acknowledgment.status is not CommandStatus.REJECTED
            or replay_acknowledgment.dispatch_phase is not DispatchPhase.PRE_DISPATCH
            or replay_acknowledgment.reason != "transaction_replayed"
            or not replay_acknowledgment.verify_for_transaction(
                replacement_plc.public_key,
                request=result.request,
                permit=permit,
                pre_observation=pre_observation,
                expected_plc_id=replacement_plc.plc_id,
                expected_plc_key_id=replacement_plc.key_id,
                expected_plc_boot_epoch=replacement_plc.boot_epoch,
            )
        ):
            raise RuntimeError(
                "replacement PLC did not return the expected signed replay rejection"
            )
        replay_observation = lab.capture_observation(
            correlation_id=f"{session_id}:post-replay",
            challenge_nonce=f"{session_id}:post-replay-challenge-0001",
        )
        post_replay_health = _health_bundle(
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            phase="post_replay",
            captured_at=reference_time,
            records={
                "observer": cast(JsonValue, lab.processes.observer_admin.health()),
                "plant": cast(JsonValue, lab.processes.plant_admin.health()),
                "plc": cast(JsonValue, lab.processes.plc_admin.health()),
            },
        )
        runtime_registrations = _component_registrations_before_evaluation(
            lab,
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            initial_plc=initial_plc,
            replacement_plc=replacement_plc,
            registered_at=reference_time,
        )
        registration_digest = _runtime_registration_digest(runtime_registrations)
        pre_health_digest = _health_digest(pre_health)
        post_health_digest = _health_digest(post_health)
        raw_transactions = (unknown, stale, nominal)
        base_transactions = tuple(
            _transaction_record(
                raw,
                session_id=session_id,
                session_index=session_index,
                master_seed=master_seed,
                registrations_sha256=registration_digest,
                pre_health_sha256=pre_health_digest,
                post_health_sha256=post_health_digest,
            )
            for raw in raw_transactions
        )
        nominal_base = base_transactions[-1]
        request = IndependentEvaluationRequest(
            request_id=f"{session_id}:independent-evaluation",
            session_index=session_index,
            master_seed=master_seed,
            transaction_record_digest=_pre_evaluation_transaction_digest(nominal_base),
            fixture_id="pandapower-cigre-mv-all-neutral-topology-v1",
            fixture_digest=(
                "58ed983e507811935c448e6d468e952ff34620958eae893d16d454a89651709f"
            ),
            nonce=f"{session_id}:independent-evaluation-nonce-0001",
            pre_observation=pre_observation,
            post_observation=post_observation,
            command=command,
            observer_key_id=lab.processes.observer_info.key_id,
            observer_public_key_b64=public_key_base64(
                lab.processes.observer_info.public_key
            ),
            absolute_tolerance_mw=Decimal("0.000000001"),
            absolute_tolerance_pct=Decimal("0.000000001"),
        )
        evidence_records = tuple(
            _evidence_wrapper(
                item,
                session_id=session_id,
                session_index=session_index,
                master_seed=master_seed,
            )
            for item in lab.authorization.gateway.evidence.records
        )
        lab.close()
        closed = True
    finally:
        if not closed:
            lab.close()

    # The controller, plant, observer, and PLC processes are closed before this
    # filesystem-only evaluator process is started.
    report = _run_independent_evaluator(request)
    evaluator_raw = public_key_from_base64(report.public_key_b64).public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    evaluator_registration = M4bComponentRegistration(
        session_id=session_id,
        session_index=session_index,
        master_seed=master_seed,
        role=M4bComponentRole.INDEPENDENT_EVALUATOR,
        component_id=report.evaluator_id,
        pid=report.pid,
        boot_epoch=report.boot_epoch,
        key_id=report.key_id,
        public_key_b64=report.public_key_b64,
        public_key_sha256=sha256_bytes(evaluator_raw),
        capabilities=("evaluate:topology_connectivity",),
        registered_at=report.evaluated_at,
    )
    final_transactions = (
        base_transactions[0],
        base_transactions[1],
        _transaction_record(
            nominal,
            session_id=session_id,
            session_index=session_index,
            master_seed=master_seed,
            registrations_sha256=registration_digest,
            pre_health_sha256=pre_health_digest,
            post_health_sha256=post_health_digest,
            report=report,
        ),
    )
    final_nominal = final_transactions[-1]
    replay = M4bOrderlyRestartReplayRecord(
        session_id=session_id,
        original_transaction_sha256=final_nominal.digest,
        original_request_digest=result.request.digest,
        original_permit_digest=permit.digest,
        original_command_digest=command.digest,
        prior_plc_registration_sha256=runtime_registrations[2].digest,
        replacement_plc_registration_sha256=runtime_registrations[4].digest,
        replay_acknowledgment=replay_acknowledgment,
        before_plant_health_sha256=canonical_digest(
            cast(dict[str, Any], pre_replay_health["records"])["plant"]
        ),
        after_plant_health_sha256=canonical_digest(
            cast(dict[str, Any], post_replay_health["records"])["plant"]
        ),
        post_replay_observation=replay_observation,
        replay_state_unchanged=(
            cast(dict[str, Any], pre_replay_health["records"])["plant"].get(
                "state_digest"
            )
            == cast(dict[str, Any], post_replay_health["records"])["plant"].get(
                "state_digest"
            )
            == replay_observation.snapshot.state_digest
            == replay_acknowledgment.pre_state_digest
        ),
        recorded_at=reference_time,
    )
    if not replay.replay_state_unchanged:
        raise RuntimeError("replay changed the retained plant state")
    return _LiveSession(
        session_id=session_id,
        session_index=session_index,
        master_seed=master_seed,
        runtime_registrations=runtime_registrations,
        evaluator_registration=evaluator_registration,
        transactions=final_transactions,
        evidence_records=evidence_records,
        health_bundles=(pre_health, post_health, pre_replay_health, post_replay_health),
        probes=probes,
        replay=replay,
        request=request,
        report=report,
    )


def _git_value(*arguments: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed git executable/arguments
            ["/usr/bin/git", *arguments],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def _git_state() -> dict[str, JsonValue]:
    status = _git_value("status", "--porcelain")
    commit = _git_value("rev-parse", "HEAD")
    branch = _git_value("branch", "--show-current")
    if branch == "" and len(commit) == 40:
        branch = "DETACHED"
    return {
        "branch": branch,
        "commit": commit,
        "working_tree_dirty_at_start": status not in {"", "unknown"},
        "working_tree_dirty_at_end": status not in {"", "unknown"},
    }


def _version(distribution: str) -> str:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return "unavailable"


def _source_artifacts() -> dict[str, bytes]:
    artifacts: dict[str, bytes] = {}
    for package in (ROOT / "src/aegis_ot", ROOT / "src/aegis_ot_independent"):
        for path in sorted(package.glob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            artifacts[f"source/{relative}"] = path.read_bytes()
    artifacts["source/pyproject.toml"] = (ROOT / "pyproject.toml").read_bytes()
    lock_path = ROOT / "requirements.lock"
    if lock_path.is_file():
        artifacts["source/requirements.lock"] = lock_path.read_bytes()
    return artifacts


def _protocol_documents(seed_count: int) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    scenarios: dict[str, JsonValue] = {
        "schema_version": "m4b-scenario-catalog-v1",
        "protocol_version": PROTOCOL_VERSION,
        "session_count": seed_count,
        "transaction_order": list(CONDITION_ORDER),
        "conditions": [
            {
                "condition": "unknown_identity",
                "expected_status": "not_dispatched",
                "expected_dispatch_attempts": 0,
            },
            {
                "condition": "stale_observation",
                "expected_status": "not_dispatched",
                "expected_dispatch_attempts": 0,
                "required_reason": "observation_stale",
            },
            {
                "condition": "nominal_permitted_execution",
                "expected_status": "completed",
                "expected_dispatch_attempts": 1,
                "expected_automatic_retry_count": 0,
                "resource": "feeder-1",
            },
        ],
        "independent_evaluator": {
            "profile": "topology-connectivity-v1",
            "runs_after_stack_shutdown": True,
            "forbidden_inputs": [
                "candidate_assessment",
                "execution_permit",
                "plc_acknowledgment",
                "gateway_expected_post_state",
            ],
        },
    }
    acceptance: dict[str, JsonValue] = {
        "schema_version": "m4b-acceptance-criteria-v1",
        "protocol_version": PROTOCOL_VERSION,
        "criteria": {
            "sessions_complete": seed_count,
            "transactions_per_session": 3,
            "capability_probes_per_session": 4,
            "independent_agreements_per_session": 1,
            "orderly_restart_replays_rejected_per_session": 1,
            "nominal_dispatch_attempts": 1,
            "automatic_retries": 0,
        },
        "claim_boundary": (
            "Retained same-host deterministic-local evidence with a separately "
            "implemented topology-connectivity consequence check; not independent "
            "sensing, an independent AC solver, segmented deployment, HELICS, "
            "OpenPLC, hardware, external replication, or WP4 completion."
        ),
    }
    return scenarios, acceptance


def collect_m4b_experiment(
    *,
    root_seed: int = 20260825,
    seed_count: int = 30,
    progress: Callable[[int, int], None] | None = None,
    require_clean_checkout: bool = True,
) -> CollectedM4bExperiment:
    """Run sessions and return exact artifact bytes awaiting package finalization."""

    if not 1 <= seed_count <= MAX_M4B_SESSIONS:
        raise ValueError(f"seed_count must be between 1 and {MAX_M4B_SESSIONS}")
    started_at = datetime.now(UTC)
    git_start = _git_state()
    if require_clean_checkout and git_start["working_tree_dirty_at_start"] is not False:
        raise RuntimeError("controlled M4b evidence generation requires a clean checkout")
    master_seeds = derive_master_seeds(root_seed, seed_count)
    sessions: list[_LiveSession] = []
    for session_index, master_seed in enumerate(master_seeds):
        sessions.append(_run_session(session_index, master_seed))
        if progress is not None:
            progress(session_index + 1, seed_count)

    git_end = _git_state()
    git = {
        "branch": git_start["branch"],
        "commit": git_start["commit"],
        "working_tree_dirty_at_start": git_start["working_tree_dirty_at_start"],
        "working_tree_dirty_at_end": git_end["working_tree_dirty_at_end"],
    }
    if git_start["commit"] != git_end["commit"]:
        raise RuntimeError("checkout commit changed during M4b evidence generation")
    if require_clean_checkout and git["working_tree_dirty_at_end"] is not False:
        raise RuntimeError("checkout became dirty during M4b evidence generation")

    transactions = tuple(item for session in sessions for item in session.transactions)
    evidence = tuple(item for session in sessions for item in session.evidence_records)
    registrations = tuple(
        item
        for session in sessions
        for item in (*session.runtime_registrations, session.evaluator_registration)
    )
    probes = tuple(session.probes for session in sessions)
    replays = tuple(session.replay for session in sessions)
    requests = tuple(session.request for session in sessions)
    reports = tuple(session.report for session in sessions)
    health = tuple(item for session in sessions for item in session.health_bundles)

    scenarios, acceptance = _protocol_documents(seed_count)
    summary: dict[str, JsonValue] = {
        "schema_version": "m4b-summary-v1",
        "session_count": seed_count,
        "transaction_record_count": len(transactions),
        "evidence_record_count": len(evidence),
        "component_registration_count": len(registrations),
        "probe_record_count": sum(len(bundle.records) for bundle in probes),
        "independent_evaluation_count": len(reports),
        "terminal_status_counts": {
            status.value: sum(record.result.status is status for record in transactions)
            for status in CapabilityClosedLoopStatus
        },
        "capability_probe_match_count": sum(
            record.matched_expectation for bundle in probes for record in bundle.records
        ),
        "independent_status_counts": {
            status.value: sum(report.status is status for report in reports)
            for status in IndependentEvaluationStatus
        },
        "orderly_restart_replay_rejection_count": sum(
            item.replay_acknowledgment.reason == "transaction_replayed" for item in replays
        ),
        "orderly_restart_replay_unchanged_count": sum(
            item.replay_state_unchanged for item in replays
        ),
        "experiment_criteria_met": (
            len(transactions) == seed_count * 3
            and all(
                bundle.records
                and all(record.matched_expectation for record in bundle.records)
                for bundle in probes
            )
            and all(report.status is IndependentEvaluationStatus.AGREE for report in reports)
            and all(item.replay_state_unchanged for item in replays)
        ),
    }
    artifacts: dict[str, bytes] = {
        "protocol/scenarios.json": canonical_json_bytes(scenarios) + b"\n",
        "protocol/acceptance.json": canonical_json_bytes(acceptance) + b"\n",
        "transactions/results.jsonl": _jsonl(transactions),
        "transactions/evidence-records.jsonl": _jsonl(evidence),
        "sessions/component-registrations.jsonl": _jsonl(registrations),
        "sessions/component-health.jsonl": _jsonl(health),
        "topology/capability-probes.jsonl": _jsonl(probes),
        "lifecycle/orderly-restart-replay.jsonl": _jsonl(replays),
        "independent/requests.jsonl": _jsonl(requests),
        "independent/evaluations.jsonl": _jsonl(reports),
        "independent/topology-fixture.json": FIXTURE_PATH.read_bytes(),
        "summary.json": canonical_json_bytes(summary) + b"\n",
    }
    for name in M4B_SCHEMA_NAMES:
        path = ROOT / "schemas" / name
        if not path.is_file():
            raise RuntimeError(f"required M4b package schema is missing: {name}")
        artifacts[f"contracts/{name}"] = path.read_bytes()
    artifacts.update(_source_artifacts())

    source_sha256 = {
        path: sha256_bytes(material)
        for path, material in sorted(artifacts.items())
        if path.startswith("source/")
    }
    schema_sha256 = {
        path: sha256_bytes(material)
        for path, material in sorted(artifacts.items())
        if path.startswith("contracts/")
    }
    configuration_sha256 = {
        path: sha256_bytes(artifacts[path])
        for path in ("protocol/acceptance.json", "protocol/scenarios.json")
    }
    fixture_sha256 = {
        "independent/topology-fixture.json": sha256_bytes(
            artifacts["independent/topology-fixture.json"]
        )
    }
    completed_at = datetime.now(UTC)
    return CollectedM4bExperiment(
        artifacts={path: artifacts[path] for path in sorted(artifacts)},
        started_at_utc=started_at,
        completed_at_utc=completed_at,
        git=git,
        root_seed=root_seed,
        master_seeds=master_seeds,
        transaction_records=transactions,
        evidence_records=evidence,
        component_registrations=registrations,
        probe_bundles=probes,
        replay_records=replays,
        evaluation_requests=requests,
        evaluation_reports=reports,
        source_sha256=source_sha256,
        schema_sha256=schema_sha256,
        configuration_sha256=configuration_sha256,
        fixture_sha256=fixture_sha256,
        host={
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "system": platform.system(),
        },
        component_versions={
            key: value
            for key, value in sorted(
                {
                    "aegis-ot": _version("aegis-ot"),
                    "cryptography": _version("cryptography"),
                    "pandapower": _version("pandapower"),
                    "pydantic": _version("pydantic"),
                    "python": platform.python_version(),
                }.items()
            )
        },
    )


def collection_summary(collection: CollectedM4bExperiment) -> dict[str, JsonValue]:
    """Return the retained summary document from a completed collection."""

    value = json.loads(collection.artifacts["summary.json"])
    if not isinstance(value, dict):
        raise RuntimeError("M4b summary artifact is not an object")
    return cast(dict[str, JsonValue], value)
