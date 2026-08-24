"""Controlled M3 experiment over a separate pandapower/PyModbus device process.

The experiment is intentionally bounded to a localhost, steady-state, virtual-device
test.  It does not represent OpenPLC, HELICS, a field network, or a physical PLC.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import math
import os
import platform
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from importlib import metadata
from pathlib import Path
from statistics import mean, median, pstdev, stdev
from typing import Any, TypeVar

import pandapower as pp  # type: ignore[import-untyped]
import pandapower.networks as pn  # type: ignore[import-untyped]
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from .crypto import decode_urlsafe_b64
from .evidence import EvidenceRecord
from .experiment import derive_master_seeds
from .modbus_device import ModbusPhysicalDeviceClient
from .models import ActionProposal, Decision, DecisionOutcome, Operation
from .pandapower_plant import (
    CIGRE_MV_MODEL_ID,
    CIGRE_MV_SOURCE,
    DEFAULT_PRIORITY_LOAD_INDICES,
    DEFAULT_RESOURCE_BINDINGS,
    PANDAPOWER_LICENSE,
    PandapowerCigreMVPlant,
    PhysicalLimits,
)
from .physical_control import (
    ExecutionPermitIssuer,
    TrustedCommandTranslator,
    physical_state_to_gateway_state,
)
from .physical_modbus_factory import ModbusPhysicalLab, start_modbus_physical_lab
from .physical_models import (
    CandidateAssessment,
    ClosedLoopResult,
    ClosedLoopStatus,
    CommandAcknowledgment,
    CommandStatus,
    ExecutionPermit,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
    canonical_digest,
    proposal_digest,
)
from .safety import SafetyKernel

ROOT = Path(__file__).resolve().parents[2]
REFERENCE_TIME = datetime(2026, 8, 24, 18, 0, tzinfo=UTC)
EXPERIMENT_VERSION = "m3-physical-modbus-v1"
OUTCOME_PROJECTION_VERSION = "m3-outcome-projection-v1"
M3_POLICY_VERSION = "local-contextual-v1"
M3_SAFETY_VERSION = "surrogate-safety-v1-m3-supervisory-limits"
M3_PERMIT_KEY_ID = "m3-permit-key-1"
M3_DEVICE_KEY_ID = "m3-modbus-device-key-1"
M3_PROTOCOL_VERSION = 1
M3_LOOPBACK_HOST = "127.0.0.1"
MAX_PACKAGE_FILE_BYTES = 32 * 1024 * 1024
MAX_PACKAGE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_JSONL_RECORDS = 100_000
MAX_M3_SESSIONS = 100
MAX_VERIFIER_ERRORS = 100
EXPECTED_EVENT_RECORDS_PER_SESSION = 9
PACKAGE_STABILITY_ASSUMPTION = (
    "verification assumes the local package is not concurrently replaced or modified"
)
CONDITION_ORDER = (
    "unknown_identity",
    "stale_state",
    "wrong_audience_permit",
    "nominal_permitted_execution",
    "permit_replay",
)
REQUIRED_ARTIFACT_PATHS = (
    "trials.jsonl",
    "events.jsonl",
    "scenarios.json",
    "summary.json",
    "component-health.json",
    "evidence-verification.json",
    "benchmark/provenance.json",
    "solver/configuration.json",
)
M3_SCHEMA_PATHS = (
    "schemas/m3-candidate-assessment.schema.json",
    "schemas/m3-closed-loop-result.schema.json",
    "schemas/m3-command-acknowledgment.schema.json",
    "schemas/m3-execution-permit.schema.json",
    "schemas/m3-modbus-wire-request.schema.json",
    "schemas/m3-modbus-wire-response.schema.json",
    "schemas/m3-physical-command.schema.json",
    "schemas/m3-physical-state.schema.json",
)
M3_SOURCE_PATHS = tuple(
    str(path.relative_to(ROOT)) for path in sorted((ROOT / "src/aegis_ot").glob("*.py"))
)
MANIFEST_FIELDS = frozenset(
    {
        "experiment_id",
        "experiment_version",
        "outcome_projection_version",
        "scenario_version",
        "started_at_utc",
        "completed_at_utc",
        "git",
        "master_seed",
        "master_seeds",
        "individual_seeds",
        "master_seed_count",
        "session_count",
        "conditions_per_session",
        "trial_record_count",
        "event_record_count",
        "model_digest",
        "source_sha256",
        "configuration_sha256",
        "schema_sha256",
        "artifact_sha256",
        "deterministic_outcome_sha256",
        "host",
        "component_versions",
        "experiment_configuration",
        "raw_data_location",
        "known_failures",
        "boundary",
        "known_limitations",
        "analyst",
        "summary",
    }
)
TRIAL_FIELDS = frozenset(
    {
        "session_index",
        "master_seed",
        "condition",
        "terminal_status",
        "decision_outcome",
        "reasons",
        "device_status",
        "acknowledgment_reason",
        "state_changed",
        "device_applied",
        "trace_complete",
        "acknowledgment_verified",
        "pre_state",
        "post_state",
        "physical_metrics",
        "latency_ms",
        "artifacts",
    }
)
EVENT_WRAPPER_FIELDS = frozenset({"session_index", "master_seed", "sequence", "record"})
EVIDENCE_RECORD_FIELDS = frozenset(
    {
        "sequence",
        "recorded_at",
        "proposal_id",
        "decision_id",
        "previous_hash",
        "payload",
        "record_hash",
    }
)
COMPONENT_FIELDS = frozenset(
    {
        "session_index",
        "master_seed",
        "startup_ms",
        "process",
        "verified_health_payload",
        "permit_public_key_b64",
        "initial_state",
        "parent_pid",
        "separate_process_verified",
    }
)
PROCESS_FIELDS = frozenset(
    {
        "host",
        "port",
        "pid",
        "boot_epoch",
        "audience",
        "device_id",
        "device_key_id",
        "device_public_key_b64",
        "model_digest",
        "simulator_version",
        "protocol_version",
    }
)
HEALTH_FIELDS = frozenset(
    {
        "status",
        "protocol_version",
        "model_digest",
        "simulator_version",
        "device_id",
        "device_key_id",
        "boot_epoch",
        "state_version",
    }
)
VERIFICATION_FIELDS = frozenset(
    {
        "session_index",
        "master_seed",
        "evidence_chain_valid",
        "evidence_record_count",
        "condition_count",
        "trace_complete_count",
        "acknowledgment_verified_count",
    }
)
T = TypeVar("T")


class _StageRecorder:
    def __init__(self) -> None:
        self.values: dict[str, list[float]] = {}

    def call(self, stage: str, operation: Callable[[], T]) -> T:
        started = time.perf_counter_ns()
        try:
            return operation()
        finally:
            elapsed = (time.perf_counter_ns() - started) / 1_000_000
            self.values.setdefault(stage, []).append(elapsed)

    def flattened(self) -> dict[str, float]:
        return {
            (name if len(values) == 1 else f"{name}_{index + 1}"): value
            for name, values in self.values.items()
            for index, value in enumerate(values)
        }


class _TimedGateway:
    def __init__(self, gateway: Any, recorder: _StageRecorder) -> None:
        self._gateway = gateway
        self._recorder = recorder
        self.evidence = gateway.evidence

    def decide(self, proposal: ActionProposal, state: Any, now: datetime) -> Any:
        return self._recorder.call(
            "gateway_decision_ms",
            lambda: self._gateway.decide(proposal, state, now),
        )


class _TimedPermitIssuer:
    def __init__(self, issuer: ExecutionPermitIssuer, recorder: _StageRecorder) -> None:
        self._issuer = issuer
        self._recorder = recorder

    def issue(self, **kwargs: Any) -> ExecutionPermit:
        return self._recorder.call("permit_issuance_ms", lambda: self._issuer.issue(**kwargs))


class _TimedClient:
    def __init__(self, client: ModbusPhysicalDeviceClient, recorder: _StageRecorder) -> None:
        self._client = client
        self._recorder = recorder
        self.device_id = client.device_id
        self.acknowledgment_key_id = client.acknowledgment_key_id

    def read_state(self) -> PhysicalStateSnapshot:
        return self._recorder.call("state_read_ms", self._client.read_state)

    def capture_state(self) -> PhysicalStateSnapshot:
        return self.read_state()

    def simulate_candidate(
        self,
        command: PhysicalControlCommand,
    ) -> CandidateAssessment:
        return self._recorder.call(
            "candidate_simulation_ms",
            lambda: self._client.simulate_candidate(command),
        )

    def execute(
        self,
        permit: ExecutionPermit,
        *,
        proposal: ActionProposal,
        decision: Any,
        assessment: CandidateAssessment,
    ) -> CommandAcknowledgment:
        return self._recorder.call(
            "modbus_execute_ms",
            lambda: self._client.execute(
                permit,
                proposal=proposal,
                decision=decision,
                assessment=assessment,
            ),
        )


def _git_state() -> dict[str, str | bool]:
    def run(*args: str) -> str:
        try:
            return subprocess.check_output(  # noqa: S603 - fixed git executable and arguments
                args,
                text=True,
                stderr=subprocess.DEVNULL,
                cwd=ROOT,
            ).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return "unknown"

    status = run("git", "status", "--porcelain")
    return {
        "commit": run("git", "rev-parse", "HEAD"),
        "working_tree_dirty_at_start": bool(status and status != "unknown"),
    }


def _host_memory_bytes() -> int | None:
    try:
        return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
    except (OSError, TypeError, ValueError):
        return None


def _sha256_bytes(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _public_key_b64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _public_key_from_b64(value: str) -> Ed25519PublicKey:
    raw = decode_urlsafe_b64(value)
    return Ed25519PublicKey.from_public_bytes(raw)


def _valid_public_key_b64(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        _public_key_from_b64(value)
    except (TypeError, ValueError):
        return False
    return True


def _is_finite_nonnegative_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return math.isfinite(value) and value >= 0.0


def _json_exact_equal(left: Any, right: Any) -> bool:
    try:
        return json.dumps(
            left,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ) == json.dumps(
            right,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return False


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _parse_registered_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0) or parsed.isoformat() != value:
        return None
    return parsed


def _json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"


def _jsonl_text(values: list[dict[str, Any]]) -> str:
    return "".join(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        for value in values
    )


def _distribution_file_hash(distribution_name: str, filename: str) -> str | None:
    try:
        distribution = metadata.distribution(distribution_name)
    except metadata.PackageNotFoundError:
        return None
    for entry in distribution.files or ():
        if str(entry).lower().endswith(filename.lower()):
            path = Path(str(distribution.locate_file(entry)))
            if path.is_file():
                return _sha256_bytes(path.read_bytes())
    return None


def _proposal(
    state: PhysicalStateSnapshot,
    *,
    master_seed: int,
    condition: str,
    actor_id: str = "agent:operator-1",
) -> ActionProposal:
    token = f"{master_seed:016x}-{condition}"
    return ActionProposal(
        proposal_id=f"m3-{token}",
        actor_id=actor_id,
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=state.state_version,
        observed_at=state.observed_at,
        submitted_at=state.observed_at,
        nonce=f"m3-nonce-{token}",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


def _instrumented_execute(
    lab: ModbusPhysicalLab,
    proposal: ActionProposal,
) -> tuple[ClosedLoopResult, dict[str, float]]:
    recorder = _StageRecorder()
    controller = lab.controller
    raw_gateway = controller.gateway
    raw_plant = controller.plant
    raw_issuer = controller.permit_issuer
    raw_device = controller.control_device
    timed_client = _TimedClient(lab.client, recorder)
    controller.gateway = _TimedGateway(raw_gateway, recorder)  # type: ignore[assignment]
    controller.plant = timed_client
    controller.permit_issuer = _TimedPermitIssuer(raw_issuer, recorder)  # type: ignore[assignment]
    controller.control_device = timed_client
    started = time.perf_counter_ns()
    try:
        result = controller.execute(proposal)
    finally:
        controller.gateway = raw_gateway
        controller.plant = raw_plant
        controller.permit_issuer = raw_issuer
        controller.control_device = raw_device
    elapsed = (time.perf_counter_ns() - started) / 1_000_000
    latencies = recorder.flattened()
    latencies["end_to_end_ms"] = elapsed
    return result, latencies


def _state_changed(pre: PhysicalStateSnapshot, post: PhysicalStateSnapshot) -> bool:
    return pre.state_version != post.state_version or pre.state_digest != post.state_digest


def _state_metrics(state: PhysicalStateSnapshot) -> dict[str, Any]:
    return {
        "state_version": state.state_version,
        "simulation_time_s": state.simulation_time_s,
        "state_digest": state.state_digest,
        "topology_digest": state.topology_digest,
        "unsafe_state": state.unsafe_state,
        "converged": state.converged,
        "total_load_served_pct": state.total_load_served_pct,
        "priority_load_served_pct": state.priority_load_served_pct,
        "minimum_voltage_pu": state.minimum_voltage_pu,
        "maximum_voltage_pu": state.maximum_voltage_pu,
        "maximum_line_loading_pct": state.maximum_line_loading_pct,
        "voltage_violation_count": state.voltage_violation_count,
        "thermal_violation_count": state.thermal_violation_count,
        "isolated_resources": list(state.isolated_resources),
    }


def _record_from_result(
    *,
    lab: ModbusPhysicalLab,
    session_index: int,
    master_seed: int,
    condition: str,
    result: ClosedLoopResult,
    latencies: dict[str, float],
) -> dict[str, Any]:
    acknowledgment = result.acknowledgment
    post_state = result.post_state
    if post_state is None:
        raise RuntimeError(f"condition {condition} did not establish a post-state")
    trace_complete = (
        result.proposal is not None
        and result.decision is not None
        and bool(result.execution_evidence_hash)
    )
    acknowledgment_verified = acknowledgment is None
    if acknowledgment is not None and result.permit is not None:
        acknowledgment_verified = acknowledgment.verify_for_transaction(
            lab.client.acknowledgment_public_key,
            permit=result.permit,
            pre_state=result.pre_state,
            readback_state=post_state,
            expected_device_id=lab.client.device_id,
            expected_key_id=lab.client.acknowledgment_key_id,
        )
    return {
        "session_index": session_index,
        "master_seed": master_seed,
        "condition": condition,
        "terminal_status": result.status.value,
        "decision_outcome": result.decision.outcome.value,
        "reasons": list(result.reasons),
        "device_status": acknowledgment.status.value if acknowledgment else None,
        "acknowledgment_reason": acknowledgment.reason if acknowledgment else None,
        "state_changed": _state_changed(result.pre_state, post_state),
        "device_applied": bool(acknowledgment and acknowledgment.status is CommandStatus.APPLIED),
        "trace_complete": trace_complete,
        "acknowledgment_verified": acknowledgment_verified,
        "pre_state": result.pre_state.model_dump(mode="json"),
        "post_state": post_state.model_dump(mode="json"),
        "physical_metrics": _state_metrics(post_state),
        "latency_ms": latencies,
        "artifacts": result.model_dump(mode="json"),
    }


def _manual_record(
    *,
    lab: ModbusPhysicalLab,
    session_index: int,
    master_seed: int,
    condition: str,
    terminal_status: ClosedLoopStatus,
    proposal: ActionProposal,
    decision: Any,
    command: PhysicalControlCommand,
    assessment: CandidateAssessment,
    permit: ExecutionPermit,
    acknowledgment: CommandAcknowledgment,
    pre_state: PhysicalStateSnapshot,
    post_state: PhysicalStateSnapshot,
    latencies: dict[str, float],
) -> dict[str, Any]:
    acknowledgment_verified = acknowledgment.verify_for_transaction(
        lab.client.acknowledgment_public_key,
        permit=permit,
        pre_state=pre_state,
        readback_state=post_state,
        expected_device_id=lab.client.device_id,
        expected_key_id=lab.client.acknowledgment_key_id,
    )
    evidence_record = lab.authorization.gateway.evidence.append(
        proposal_id=proposal.proposal_id,
        decision_id=decision.decision_id,
        payload={
            "event_type": "physical_closed_loop_disposition",
            "condition": condition,
            "status": terminal_status.value,
            "proposal": proposal.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "command": command.model_dump(mode="json"),
            "assessment": assessment.model_dump(mode="json"),
            "permit": permit.model_dump(mode="json"),
            "acknowledgment": acknowledgment.model_dump(mode="json"),
            "pre_state": pre_state.model_dump(mode="json"),
            "post_state": post_state.model_dump(mode="json"),
        },
    )
    return {
        "session_index": session_index,
        "master_seed": master_seed,
        "condition": condition,
        "terminal_status": terminal_status.value,
        "decision_outcome": decision.outcome.value,
        "reasons": [acknowledgment.reason],
        "device_status": acknowledgment.status.value,
        "acknowledgment_reason": acknowledgment.reason,
        "state_changed": _state_changed(pre_state, post_state),
        "device_applied": acknowledgment.status is CommandStatus.APPLIED,
        "trace_complete": True,
        "acknowledgment_verified": acknowledgment_verified,
        "pre_state": pre_state.model_dump(mode="json"),
        "post_state": post_state.model_dump(mode="json"),
        "physical_metrics": _state_metrics(post_state),
        "latency_ms": latencies,
        "artifacts": {
            "proposal": proposal.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "command": command.model_dump(mode="json"),
            "assessment": assessment.model_dump(mode="json"),
            "permit": permit.model_dump(mode="json"),
            "acknowledgment": acknowledgment.model_dump(mode="json"),
            "execution_evidence_hash": evidence_record.record_hash,
        },
    }


def _assert_condition(record: dict[str, Any]) -> None:
    expected = {
        "unknown_identity": (ClosedLoopStatus.NOT_DISPATCHED.value, False),
        "stale_state": (ClosedLoopStatus.NOT_DISPATCHED.value, False),
        "wrong_audience_permit": (ClosedLoopStatus.DEVICE_REJECTED.value, False),
        "nominal_permitted_execution": (ClosedLoopStatus.COMPLETED.value, True),
        "permit_replay": (ClosedLoopStatus.DEVICE_REJECTED.value, False),
    }
    expected_status, expected_effect = expected[str(record["condition"])]
    if record["terminal_status"] != expected_status:
        raise RuntimeError(
            f"condition {record['condition']} returned {record['terminal_status']}, "
            f"expected {expected_status}"
        )
    if bool(record["state_changed"]) is not expected_effect:
        raise RuntimeError(f"condition {record['condition']} produced an unexpected state effect")
    if not record["trace_complete"] or not record["acknowledgment_verified"]:
        raise RuntimeError(f"condition {record['condition']} produced incomplete evidence")
    if record["physical_metrics"]["unsafe_state"]:
        raise RuntimeError(f"condition {record['condition']} ended in an unsafe model state")


def _run_session(
    session_index: int,
    master_seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    reference_time = REFERENCE_TIME + timedelta(seconds=session_index * 10)
    startup_started = time.perf_counter_ns()
    with start_modbus_physical_lab(reference_time) as lab:
        startup_ms = (time.perf_counter_ns() - startup_started) / 1_000_000
        health = lab.client.health()
        initial = lab.client.read_state()
        records: list[dict[str, Any]] = []

        pre = lab.client.read_state()
        proposal = _proposal(
            pre,
            master_seed=master_seed,
            condition="unknown_identity",
            actor_id="agent:untrusted",
        )
        result, latencies = _instrumented_execute(lab, proposal)
        record = _record_from_result(
            lab=lab,
            session_index=session_index,
            master_seed=master_seed,
            condition="unknown_identity",
            result=result,
            latencies=latencies,
        )
        record["acknowledgment_verified"] = result.acknowledgment is None
        _assert_condition(record)
        records.append(record)

        pre = lab.client.read_state()
        proposal = _proposal(pre, master_seed=master_seed, condition="stale_state")
        original_clock = lab.controller.clock
        lab.controller.clock = lambda: reference_time + timedelta(seconds=6)
        try:
            result, latencies = _instrumented_execute(lab, proposal)
        finally:
            lab.controller.clock = original_clock
        record = _record_from_result(
            lab=lab,
            session_index=session_index,
            master_seed=master_seed,
            condition="stale_state",
            result=result,
            latencies=latencies,
        )
        record["acknowledgment_verified"] = result.acknowledgment is None
        _assert_condition(record)
        records.append(record)

        pre = lab.client.read_state()
        proposal = _proposal(pre, master_seed=master_seed, condition="wrong_audience_permit")
        recorder = _StageRecorder()
        decision = recorder.call(
            "gateway_decision_ms",
            lambda: lab.authorization.gateway.decide(
                proposal,
                physical_state_to_gateway_state(pre),
                reference_time,
            ),
        )
        if decision.outcome is not DecisionOutcome.PERMIT:
            raise RuntimeError("wrong-audience fixture did not receive its prerequisite permit")
        command = recorder.call(
            "command_translation_ms",
            lambda: lab.controller.translator.translate(proposal),
        )
        assessment = recorder.call(
            "candidate_simulation_ms",
            lambda: lab.client.simulate_candidate(command),
        )
        permit = recorder.call(
            "permit_issuance_ms",
            lambda: lab.controller.permit_issuer.issue(
                proposal=proposal,
                decision=decision,
                command=command,
                assessment=assessment,
            ),
        )
        tampered_permit = permit.model_copy(update={"audience": "virtual-device:wrong-audience"})
        acknowledgment = recorder.call(
            "modbus_execute_ms",
            lambda: lab.client.execute(
                tampered_permit,
                proposal=proposal,
                decision=decision,
                assessment=assessment,
            ),
        )
        post = recorder.call("readback_ms", lab.client.read_state)
        record = _manual_record(
            lab=lab,
            session_index=session_index,
            master_seed=master_seed,
            condition="wrong_audience_permit",
            terminal_status=ClosedLoopStatus.DEVICE_REJECTED,
            proposal=proposal,
            decision=decision,
            command=command,
            assessment=assessment,
            permit=tampered_permit,
            acknowledgment=acknowledgment,
            pre_state=pre,
            post_state=post,
            latencies=recorder.flattened(),
        )
        _assert_condition(record)
        records.append(record)

        pre = lab.client.read_state()
        proposal = _proposal(
            pre,
            master_seed=master_seed,
            condition="nominal_permitted_execution",
        )
        result, latencies = _instrumented_execute(lab, proposal)
        record = _record_from_result(
            lab=lab,
            session_index=session_index,
            master_seed=master_seed,
            condition="nominal_permitted_execution",
            result=result,
            latencies=latencies,
        )
        if (
            result.acknowledgment is not None
            and result.permit is not None
            and result.post_state is not None
        ):
            record["acknowledgment_verified"] = result.acknowledgment.verify_for_transaction(
                lab.client.acknowledgment_public_key,
                permit=result.permit,
                pre_state=result.pre_state,
                readback_state=result.post_state,
                expected_device_id=lab.client.device_id,
                expected_key_id=lab.client.acknowledgment_key_id,
            )
        _assert_condition(record)
        records.append(record)

        if (
            result.permit is None
            or result.command is None
            or result.assessment is None
            or result.acknowledgment is None
        ):
            raise RuntimeError(
                "nominal execution did not produce replayable authorization artifacts"
            )
        replay_permit = result.permit
        replay_command = result.command
        replay_assessment = result.assessment
        replay_pre = lab.client.read_state()
        recorder = _StageRecorder()
        replay_ack = recorder.call(
            "modbus_execute_ms",
            lambda: lab.client.execute(
                replay_permit,
                proposal=result.proposal,
                decision=result.decision,
                assessment=replay_assessment,
            ),
        )
        replay_post = recorder.call("readback_ms", lab.client.read_state)
        record = _manual_record(
            lab=lab,
            session_index=session_index,
            master_seed=master_seed,
            condition="permit_replay",
            terminal_status=ClosedLoopStatus.DEVICE_REJECTED,
            proposal=result.proposal,
            decision=result.decision,
            command=replay_command,
            assessment=replay_assessment,
            permit=replay_permit,
            acknowledgment=replay_ack,
            pre_state=replay_pre,
            post_state=replay_post,
            latencies=recorder.flattened(),
        )
        _assert_condition(record)
        records.append(record)

        if tuple(item["condition"] for item in records) != CONDITION_ORDER:
            raise RuntimeError("session condition ordering drifted from the preregistered catalog")
        evidence_valid = lab.authorization.gateway.evidence.verify()
        if not evidence_valid:
            raise RuntimeError("session evidence chain failed verification")
        events = [
            {
                "session_index": session_index,
                "master_seed": master_seed,
                "sequence": event.sequence,
                "record": event.model_dump(mode="json"),
            }
            for event in lab.authorization.gateway.evidence.records
        ]
        component = {
            "session_index": session_index,
            "master_seed": master_seed,
            "startup_ms": startup_ms,
            "process": asdict(lab.info),
            "verified_health_payload": health,
            "permit_public_key_b64": _public_key_b64(lab.permit_public_key),
            "initial_state": initial.model_dump(mode="json"),
            "parent_pid": os.getpid(),
            "separate_process_verified": lab.info.pid != os.getpid(),
        }
        verification = {
            "session_index": session_index,
            "master_seed": master_seed,
            "evidence_chain_valid": evidence_valid,
            "evidence_record_count": len(events),
            "condition_count": len(records),
            "trace_complete_count": sum(bool(item["trace_complete"]) for item in records),
            "acknowledgment_verified_count": sum(
                bool(item["acknowledgment_verified"]) for item in records
            ),
        }
        return records, events, component, verification


def run_m3_experiment(
    master_seeds: tuple[int, ...],
    *,
    progress: Callable[[int, int], None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    if not master_seeds:
        raise ValueError("at least one master seed is required")
    if len(master_seeds) > MAX_M3_SESSIONS:
        raise ValueError(f"M3 supports at most {MAX_M3_SESSIONS} sessions per package")
    if any(type(seed) is not int for seed in master_seeds):
        raise TypeError("M3 master seeds must be integers")
    if len(set(master_seeds)) != len(master_seeds):
        raise ValueError("M3 master seeds must be unique")
    trials: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    verification: list[dict[str, Any]] = []
    total = len(master_seeds)
    for session_index, master_seed in enumerate(master_seeds):
        session_trials, session_events, component, checked = _run_session(
            session_index,
            master_seed,
        )
        trials.extend(session_trials)
        events.extend(session_events)
        components.append(component)
        verification.append(checked)
        if progress is not None:
            progress(session_index + 1, total)
    return trials, events, components, verification


def _wilson(successes: int, total: int) -> dict[str, float | int]:
    if total == 0:
        return {"estimate": 0.0, "lower": 0.0, "upper": 0.0, "denominator": 0}
    z = 1.959963984540054
    estimate = successes / total
    denominator = 1 + z**2 / total
    center = (estimate + z**2 / (2 * total)) / denominator
    margin = z * math.sqrt(estimate * (1 - estimate) / total + z**2 / (4 * total**2))
    margin /= denominator
    return {
        "estimate": estimate,
        "lower": 0.0 if successes == 0 else max(0.0, center - margin),
        "upper": 1.0 if successes == total else min(1.0, center + margin),
        "denominator": total,
    }


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _latency_statistics(values: list[float]) -> dict[str, Any]:
    average = mean(values)
    sample_stddev = stdev(values) if len(values) > 1 else 0.0
    mean_margin = 1.959963984540054 * sample_stddev / math.sqrt(len(values))
    return {
        "count": len(values),
        "mean_ms": average,
        "median_ms": median(values),
        "population_stddev_ms": pstdev(values),
        "sample_stddev_ms": sample_stddev,
        "mean_normal_ci95_ms": {
            "lower": max(0.0, average - mean_margin),
            "upper": average + mean_margin,
        },
        "minimum_ms": min(values),
        "p50_ms": _percentile(values, 0.50),
        "p95_ms": _percentile(values, 0.95),
        "p99_ms": _percentile(values, 0.99),
        "maximum_ms": max(values),
    }


def _value_statistics(values: list[float]) -> dict[str, Any]:
    average = mean(values)
    sample_stddev = stdev(values) if len(values) > 1 else 0.0
    mean_margin = 1.959963984540054 * sample_stddev / math.sqrt(len(values))
    return {
        "count": len(values),
        "mean": average,
        "median": median(values),
        "population_stddev": pstdev(values),
        "sample_stddev": sample_stddev,
        "mean_normal_ci95": {
            "lower": average - mean_margin,
            "upper": average + mean_margin,
        },
        "minimum": min(values),
        "p50": _percentile(values, 0.50),
        "p95": _percentile(values, 0.95),
        "p99": _percentile(values, 0.99),
        "maximum": max(values),
    }


def summarize_m3(trials: list[dict[str, Any]]) -> dict[str, Any]:
    if not trials:
        raise ValueError("M3 summary requires at least one trial")
    by_condition: dict[str, Any] = {}
    for condition in CONDITION_ORDER:
        subset = [item for item in trials if item["condition"] == condition]
        effects = sum(bool(item["state_changed"]) for item in subset)
        applied = sum(bool(item["device_applied"]) for item in subset)
        unknown = sum(
            item["terminal_status"] == ClosedLoopStatus.UNKNOWN_EFFECT.value for item in subset
        )
        complete = sum(bool(item["trace_complete"]) for item in subset)
        verified = sum(bool(item["acknowledgment_verified"]) for item in subset)
        stage_values: dict[str, list[float]] = {}
        for item in subset:
            for stage, value in item["latency_ms"].items():
                stage_values.setdefault(stage, []).append(float(value))
        by_condition[condition] = {
            "trials": len(subset),
            "state_effects": effects,
            "state_effect_rate_ci95": _wilson(effects, len(subset)),
            "device_applied": applied,
            "device_applied_rate_ci95": _wilson(applied, len(subset)),
            "unknown_effects": unknown,
            "trace_complete": complete,
            "acknowledgment_verified": verified,
            "latency": {
                stage: _latency_statistics(values) for stage, values in sorted(stage_values.items())
            },
        }

    denied = [item for item in trials if item["condition"] != "nominal_permitted_execution"]
    nominal = [item for item in trials if item["condition"] == "nominal_permitted_execution"]
    replay = [item for item in trials if item["condition"] == "permit_replay"]
    stale = [item for item in trials if item["condition"] == "stale_state"]
    physical = [item["physical_metrics"] for item in nominal]
    return {
        "experiment_version": EXPERIMENT_VERSION,
        "session_count": len(nominal),
        "condition_count": len(CONDITION_ORDER),
        "trial_record_count": len(trials),
        "by_condition": by_condition,
        "denied_command_effect_rate_ci95": _wilson(
            sum(bool(item["state_changed"]) for item in denied),
            len(denied),
        ),
        "unauthorized_device_acceptance_rate_ci95": _wilson(
            sum(bool(item["device_applied"]) for item in denied),
            len(denied),
        ),
        "stale_state_execution_rate_ci95": _wilson(
            sum(bool(item["state_changed"]) for item in stale),
            len(stale),
        ),
        "duplicate_replay_effect_rate_ci95": _wilson(
            sum(bool(item["state_changed"]) for item in replay),
            len(replay),
        ),
        "nominal_closed_loop_completion_rate_ci95": _wilson(
            sum(item["terminal_status"] == ClosedLoopStatus.COMPLETED.value for item in nominal),
            len(nominal),
        ),
        "unknown_effect_rate_ci95": _wilson(
            sum(
                item["terminal_status"] == ClosedLoopStatus.UNKNOWN_EFFECT.value for item in trials
            ),
            len(trials),
        ),
        "evidence_trace_completeness_rate_ci95": _wilson(
            sum(bool(item["trace_complete"]) for item in trials),
            len(trials),
        ),
        "nominal_post_state": {
            "minimum_voltage_pu": _value_statistics(
                [float(item["minimum_voltage_pu"]) for item in physical]
            ),
            "maximum_line_loading_pct": _value_statistics(
                [float(item["maximum_line_loading_pct"]) for item in physical]
            ),
            "priority_load_served_pct": _value_statistics(
                [float(item["priority_load_served_pct"]) for item in physical]
            ),
            "unsafe_state_count": sum(bool(item["unsafe_state"]) for item in physical),
            "voltage_violation_count": sum(
                int(item["voltage_violation_count"]) for item in physical
            ),
            "thermal_violation_count": sum(
                int(item["thermal_violation_count"]) for item in physical
            ),
        },
        "statistical_note": (
            "Two-sided 95 percent Wilson intervals are reported for observed proportions. "
            "Continuous summaries include descriptive distributions and two-sided 95 percent "
            "normal-approximation intervals for the sample mean. Zero observations do not "
            "establish an impossible event."
        ),
    }


def _deterministic_projection(trials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    projection: list[dict[str, Any]] = []
    for item in trials:
        metrics = item["physical_metrics"]
        projection.append(
            {
                "session_index": item["session_index"],
                "master_seed": item["master_seed"],
                "condition": item["condition"],
                "terminal_status": item["terminal_status"],
                "decision_outcome": item["decision_outcome"],
                "reasons": item["reasons"],
                "device_status": item["device_status"],
                "acknowledgment_reason": item["acknowledgment_reason"],
                "state_changed": item["state_changed"],
                "device_applied": item["device_applied"],
                "trace_complete": item["trace_complete"],
                "acknowledgment_verified": item["acknowledgment_verified"],
                "pre_state_version": item["pre_state"]["state_version"],
                "post_state_version": item["post_state"]["state_version"],
                "post_unsafe_state": metrics["unsafe_state"],
                "post_isolated_resources": metrics["isolated_resources"],
                "minimum_voltage_pu": round(float(metrics["minimum_voltage_pu"]), 12),
                "maximum_line_loading_pct": round(float(metrics["maximum_line_loading_pct"]), 12),
                "priority_load_served_pct": round(float(metrics["priority_load_served_pct"]), 12),
            }
        )
    return projection


def _scenario_catalog() -> dict[str, Any]:
    return {
        "catalog_version": "m3-scenarios-v1",
        "execution_order": list(CONDITION_ORDER),
        "sessions": "one fresh virtual-device process per master seed",
        "conditions": [
            {
                "name": "unknown_identity",
                "injection": "actor is absent from the configured identity allowlist",
                "expected": "gateway denial and no Modbus execute request or state effect",
            },
            {
                "name": "stale_state",
                "injection": "trusted controller clock is advanced to state age 6 seconds",
                "expected": "gateway denial at the configured 5-second freshness boundary",
            },
            {
                "name": "wrong_audience_permit",
                "injection": "a valid permit artifact is changed to a nonmatching device audience",
                "expected": "signed device rejection and unchanged actuator and plant state",
            },
            {
                "name": "nominal_permitted_execution",
                "injection": "none",
                "expected": "one accepted line-isolation command, acknowledgment, and readback",
            },
            {
                "name": "permit_replay",
                "injection": "the previously applied permit is submitted a second time",
                "expected": "signed replay rejection and no second physical effect",
            },
        ],
        "seed_role": (
            "Seeds create independent identifiers and process sessions; the packaged physical "
            "model and these conformance conditions are deterministic."
        ),
    }


def _benchmark_provenance(
    model_digest: str,
    *,
    implementation_sha256: str | None = None,
) -> dict[str, Any]:
    constructor_source = inspect.getsource(pn.create_cigre_network_mv).encode("utf-8")
    if implementation_sha256 is None:
        implementation_sha256 = _sha256_bytes(
            (ROOT / "src/aegis_ot/pandapower_plant.py").read_bytes()
        )
    return {
        "model_id": CIGRE_MV_MODEL_ID,
        "constructor": CIGRE_MV_SOURCE,
        "constructor_source_sha256": _sha256_bytes(constructor_source),
        "instantiated_model_digest": model_digest,
        "pandapower_version": pp.__version__,
        "pandapower_license": PANDAPOWER_LICENSE,
        "pandapower_license_file_sha256": _distribution_file_hash("pandapower", "license"),
        "source_documentation": "https://pandapower.readthedocs.io/en/latest/networks/cigre.html",
        "release_source": "https://github.com/e2nIEE/pandapower/releases/tag/v3.5.4",
        "transformation": {
            "mission_priority_load_indices": sorted(DEFAULT_PRIORITY_LOAD_INDICES),
            "meaning": "Aegis-OT synthetic mission-priority subset; not CIGRE semantics",
            "resource_bindings": {
                key: {
                    "resource": value.resource,
                    "command_type": value.command_type.value,
                    "target": value.target,
                    "target_index": value.target_index,
                    "minimum_setpoint": value.minimum_setpoint,
                    "maximum_setpoint": value.maximum_setpoint,
                }
                for key, value in sorted(DEFAULT_RESOURCE_BINDINGS.items())
            },
            "implementation_sha256": implementation_sha256,
        },
        "license_boundary": (
            "The packaged pandapower constructor and Aegis adapter are used under their "
            "software licenses. This record does not characterize separate rights in the "
            "underlying CIGRE benchmark publication."
        ),
    }


def _solver_configuration() -> dict[str, Any]:
    return {
        "simulator": f"pandapower-{pp.__version__}",
        "power_flow": dict(PandapowerCigreMVPlant.power_flow_options),
        "limits": asdict(PhysicalLimits()),
        "step_seconds": 1.0,
        "numeric_interpretation": "balanced steady-state AC Newton-Raphson power flow",
        "not_modeled": [
            "electromagnetic transients",
            "subcycle protection",
            "relay timing",
            "field equipment dynamics",
            "hardware I/O",
        ],
    }


def _experiment_configuration() -> dict[str, Any]:
    return {
        "baseline": "B3_assured_physical_conformance",
        "agent_type": "deterministic_fixture_driver",
        "model_identifier": None,
        "model_version": None,
        "prompt_hash": None,
        "policy_version": M3_POLICY_VERSION,
        "safety_kernel_version": M3_SAFETY_VERSION,
        "identity_configuration": {
            "implementation": "local_allowlist",
            "version": "local-allowlist-v1",
            "allowed_actor_ids": ["agent:operator-1"],
        },
        "protocol_version": M3_PROTOCOL_VERSION,
        "container_versions": None,
        "vm_versions": None,
    }


def _component_versions() -> dict[str, Any]:
    return {
        "pandapower": metadata.version("pandapower"),
        "pymodbus": metadata.version("pymodbus"),
        "pymodbus_license_file_sha256": _distribution_file_hash("pymodbus", "license"),
        "helics": None,
        "openplc": None,
    }


def _boundary_configuration() -> dict[str, Any]:
    return {
        "plant_and_device": "spawned child process",
        "transport": "Modbus TCP over host loopback",
        "controller": "parent Python process",
        "client_model": "one intended trusted loopback controller",
        "socket_session_ownership_enforced": False,
        "helics_exercised": False,
        "openplc_exercised": False,
        "containers_exercised": False,
    }


def _known_limitations() -> list[str]:
    return [
        "localhost process boundary, not segmented or multi-VM OT networking",
        "one intended trusted loopback controller; socket session ownership is not enforced",
        "PyModbus virtual device, not OpenPLC or a physical PLC",
        "steady-state balanced AC power flow, not transient or subcycle behavior",
        "deterministic conformance conditions; seeds vary sessions and identifiers, not physics",
        "single host and one macOS/Python environment",
        "no field data, hardware I/O, independent replication, or external validation",
        "wall-clock latency is host-specific and excluded from the deterministic outcome hash",
    ]


def write_m3_experiment(
    output_dir: Path,
    master_seeds: tuple[int, ...],
    *,
    root_seed: int | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    git = _git_state()
    started_at = datetime.now(UTC)
    trials, events, components, verification = run_m3_experiment(
        master_seeds,
        progress=progress,
    )
    completed_at = datetime.now(UTC)
    summary = summarize_m3(trials)
    scenarios = _scenario_catalog()
    model_digests = {item["process"]["model_digest"] for item in components}
    if len(model_digests) != 1:
        raise RuntimeError("fresh process sessions did not instantiate one stable model digest")
    model_digest = next(iter(model_digests))
    benchmark = _benchmark_provenance(model_digest)
    solver = _solver_configuration()
    deterministic_projection = _deterministic_projection(trials)
    deterministic_text = _jsonl_text(deterministic_projection)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "benchmark").mkdir(exist_ok=True)
    (output_dir / "solver").mkdir(exist_ok=True)
    payloads = {
        "trials.jsonl": _jsonl_text(trials),
        "events.jsonl": _jsonl_text(events),
        "scenarios.json": _json_text(scenarios),
        "summary.json": _json_text(summary),
        "component-health.json": _json_text({"sessions": components}),
        "evidence-verification.json": _json_text({"sessions": verification}),
        "benchmark/provenance.json": _json_text(benchmark),
        "solver/configuration.json": _json_text(solver),
    }
    for relative_path, material in payloads.items():
        (output_dir / relative_path).write_text(material, encoding="utf-8")

    manifest: dict[str, Any] = {
        "experiment_id": (f"{EXPERIMENT_VERSION}-{started_at.strftime('%Y%m%dT%H%M%S%fZ')}"),
        "experiment_version": EXPERIMENT_VERSION,
        "outcome_projection_version": OUTCOME_PROJECTION_VERSION,
        "scenario_version": scenarios["catalog_version"],
        "started_at_utc": started_at.isoformat(),
        "completed_at_utc": completed_at.isoformat(),
        "git": git,
        "master_seed": root_seed,
        "master_seeds": list(master_seeds),
        "individual_seeds": list(master_seeds),
        "master_seed_count": len(master_seeds),
        "session_count": len(components),
        "conditions_per_session": len(CONDITION_ORDER),
        "trial_record_count": len(trials),
        "event_record_count": len(events),
        "model_digest": model_digest,
        "source_sha256": {
            path: _sha256_bytes((ROOT / path).read_bytes()) for path in M3_SOURCE_PATHS
        },
        "configuration_sha256": {
            "pyproject.toml": _sha256_bytes((ROOT / "pyproject.toml").read_bytes()),
            "requirements.lock": _sha256_bytes((ROOT / "requirements.lock").read_bytes()),
            "scenarios": canonical_digest(scenarios),
            "solver": canonical_digest(solver),
            "benchmark": canonical_digest(benchmark),
        },
        "schema_sha256": {
            path: _sha256_bytes((ROOT / path).read_bytes()) for path in M3_SCHEMA_PATHS
        },
        "artifact_sha256": {
            path: _sha256_bytes(material.encode("utf-8"))
            for path, material in sorted(payloads.items())
        },
        "deterministic_outcome_sha256": _sha256_bytes(deterministic_text.encode("utf-8")),
        "host": {
            "os": platform.platform(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "logical_cpu_count": os.cpu_count(),
            "physical_memory_bytes": _host_memory_bytes(),
        },
        "component_versions": _component_versions(),
        "experiment_configuration": _experiment_configuration(),
        "raw_data_location": ".",
        "known_failures": [],
        "boundary": _boundary_configuration(),
        "known_limitations": _known_limitations(),
        "analyst": "Angelis Pseftis",
        "summary": summary,
    }
    (output_dir / "manifest.json").write_text(_json_text(manifest), encoding="utf-8")
    return manifest


def _package_path(output_dir: Path, relative_path: str) -> Path:
    """Resolve one manifest path without allowing traversal outside the package."""

    base = output_dir.resolve()
    unresolved = base / relative_path
    candidate = unresolved.resolve()
    if (
        Path(relative_path).is_absolute()
        or unresolved.is_symlink()
        or not candidate.is_relative_to(base)
    ):
        raise ValueError(f"unsafe artifact path: {relative_path}")
    return candidate


def _read_package_bytes(
    output_dir: Path,
    relative_path: str,
    *,
    maximum_bytes: int = MAX_PACKAGE_FILE_BYTES,
) -> bytes:
    path = _package_path(output_dir, relative_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"artifact is not a regular file: {relative_path}")
        if before.st_size > maximum_bytes:
            raise ValueError(f"artifact exceeds the byte limit: {relative_path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            material = handle.read(maximum_bytes + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(material) != after.st_size
        or len(material) > maximum_bytes
    ):
        raise ValueError(f"artifact changed while being read: {relative_path}")
    return material


def _strict_json_loads(material: str | bytes) -> Any:
    return json.loads(
        material,
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is prohibited: {value}")


def _load_json(path: Path) -> Any:
    return _strict_json_loads(path.read_bytes())


def _loads_jsonl(
    material: bytes,
    label: str,
    *,
    maximum_records: int = MAX_JSONL_RECORDS,
) -> list[dict[str, Any]]:
    maximum_records = min(maximum_records, MAX_JSONL_RECORDS)
    record_count = material.count(b"\n") + int(bool(material and not material.endswith(b"\n")))
    if record_count > maximum_records:
        raise ValueError(f"JSON Lines record limit exceeded for {label}")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(material.splitlines(), start=1):
        if not line.strip():
            raise ValueError(f"blank JSON Lines record at {label}:{line_number}")
        value = _strict_json_loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"non-object JSON Lines record at {label}:{line_number}")
        records.append(value)
    return records


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return _loads_jsonl(path.read_bytes(), path.name)


def _evidence_record_digest(record: EvidenceRecord) -> str:
    material = {
        "sequence": record.sequence,
        "recorded_at": record.recorded_at.isoformat(),
        "proposal_id": record.proposal_id,
        "decision_id": record.decision_id,
        "previous_hash": record.previous_hash,
        "payload": record.payload,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return _sha256_bytes(canonical.encode("utf-8"))


def _verify_event_records(
    events: list[dict[str, Any]],
    expected_sessions: dict[int, int],
) -> tuple[dict[int, dict[str, EvidenceRecord]], list[str]]:
    errors: list[str] = []
    events_by_session: dict[int, list[dict[str, Any]]] = {}
    for item in events:
        if set(item) != EVENT_WRAPPER_FIELDS:
            errors.append("event wrapper has missing or unknown fields")
        session_index = item.get("session_index")
        if type(session_index) is not int:
            errors.append("event record has no valid session_index")
            continue
        events_by_session.setdefault(session_index, []).append(item)

    records_by_hash: dict[int, dict[str, EvidenceRecord]] = {}
    global_record_hashes: set[str] = set()
    if set(events_by_session) != set(expected_sessions):
        errors.append("event-chain session indexes do not match the manifest")
    for session_index, master_seed in expected_sessions.items():
        previous_hash = "0" * 64
        session_hashes: dict[str, EvidenceRecord] = {}
        for expected_sequence, item in enumerate(events_by_session.get(session_index, [])):
            try:
                outer_master_seed = item["master_seed"]
                outer_sequence = item["sequence"]
                if type(outer_master_seed) is not int or outer_master_seed != master_seed:
                    errors.append(f"session {session_index} event master seed does not match")
                if type(outer_sequence) is not int or outer_sequence != expected_sequence:
                    errors.append(f"session {session_index} outer event sequence is discontinuous")
                raw_record = item["record"]
                if not isinstance(raw_record, dict):
                    raise TypeError("inner evidence record must be an object")
                if set(raw_record) != EVIDENCE_RECORD_FIELDS:
                    raise ValueError("inner evidence record has missing or unknown fields")
                if (
                    type(raw_record.get("sequence")) is not int
                    or not isinstance(raw_record.get("recorded_at"), str)
                    or not isinstance(raw_record.get("proposal_id"), str)
                    or not isinstance(raw_record.get("decision_id"), str)
                    or not isinstance(raw_record.get("previous_hash"), str)
                    or not isinstance(raw_record.get("payload"), dict)
                    or not isinstance(raw_record.get("record_hash"), str)
                ):
                    raise TypeError("inner evidence record fields have invalid JSON types")
                record = EvidenceRecord.model_validate(raw_record)
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
                errors.append(
                    f"session {session_index} event {expected_sequence} is invalid: {exc}"
                )
                continue
            if record.sequence != expected_sequence:
                errors.append(f"session {session_index} inner event sequence is discontinuous")
            if record.previous_hash != previous_hash:
                errors.append(f"session {session_index} event chain has a broken previous hash")
            if record.record_hash != _evidence_record_digest(record):
                errors.append(f"session {session_index} event chain has an invalid record hash")
            if record.record_hash in session_hashes:
                errors.append(f"session {session_index} event chain contains a duplicate hash")
            if record.record_hash in global_record_hashes:
                errors.append("event chains reuse an evidence record hash across sessions")
            session_hashes[record.record_hash] = record
            global_record_hashes.add(record.record_hash)
            previous_hash = record.record_hash
        records_by_hash[session_index] = session_hashes
    return records_by_hash, errors


def _trial_artifacts(
    item: dict[str, Any],
) -> tuple[
    ActionProposal,
    Decision,
    PhysicalControlCommand | None,
    CandidateAssessment | None,
    ExecutionPermit | None,
    CommandAcknowledgment | None,
    str,
]:
    artifacts = item["artifacts"]
    if not isinstance(artifacts, dict):
        raise ValueError("trial artifacts must be an object")
    if artifacts.get("schema_version") == "closed-loop-result-v1":
        result = ClosedLoopResult.model_validate(artifacts)
        return (
            result.proposal,
            result.decision,
            result.command,
            result.assessment,
            result.permit,
            result.acknowledgment,
            result.execution_evidence_hash,
        )
    proposal = ActionProposal.model_validate(artifacts["proposal"])
    decision = Decision.model_validate(artifacts["decision"])
    command = PhysicalControlCommand.model_validate(artifacts["command"])
    assessment = CandidateAssessment.model_validate(artifacts["assessment"])
    permit = ExecutionPermit.model_validate(artifacts["permit"])
    acknowledgment = CommandAcknowledgment.model_validate(artifacts["acknowledgment"])
    execution_evidence_hash = str(artifacts["execution_evidence_hash"])
    return (
        proposal,
        decision,
        command,
        assessment,
        permit,
        acknowledgment,
        execution_evidence_hash,
    )


def _verify_permit_bindings(
    *,
    proposal: ActionProposal,
    decision: Decision,
    command: PhysicalControlCommand,
    assessment: CandidateAssessment,
    permit: ExecutionPermit,
) -> bool:
    try:
        trusted_command = TrustedCommandTranslator().translate(proposal)
    except (KeyError, TypeError, ValueError):
        return False
    return all(
        (
            decision.outcome is DecisionOutcome.PERMIT,
            decision.reasons == ("all_checks_passed",),
            decision.policy_version == M3_POLICY_VERSION,
            decision.safety_version == M3_SAFETY_VERSION,
            decision.proposal_id == proposal.proposal_id == command.proposal_id,
            decision.state_version == assessment.pre_state.state_version,
            proposal.observed_state_version == assessment.pre_state.state_version,
            proposal.observed_at == assessment.pre_state.observed_at,
            assessment.safe,
            assessment.command_digest == command.digest,
            command.model_dump(mode="json", exclude={"command_id"})
            == trusted_command.model_dump(mode="json", exclude={"command_id"}),
            permit.proposal_id == proposal.proposal_id,
            permit.proposal_digest == proposal_digest(proposal),
            permit.decision_id == decision.decision_id,
            permit.decision_outcome is decision.outcome,
            permit.command == command,
            permit.command_digest == command.digest,
            permit.assessment_digest == assessment.digest,
            permit.state_version == assessment.pre_state.state_version,
            permit.state_digest == assessment.pre_state.state_digest,
            permit.observation_digest == assessment.pre_state.observation_digest,
            permit.topology_digest == assessment.pre_state.topology_digest,
            permit.model_digest == assessment.pre_state.model_digest,
            permit.expected_post_state_version == assessment.post_state.state_version,
            permit.expected_post_state_digest == assessment.post_state.state_digest,
            permit.expected_post_topology_digest == assessment.post_state.topology_digest,
            permit.evidence_record_hash == decision.evidence_record_hash,
            permit.policy_version == decision.policy_version,
            permit.safety_version == decision.safety_version,
            permit.signing_key_id == M3_PERMIT_KEY_ID,
            (permit.expires_at - permit.issued_at) == timedelta(seconds=2),
        )
    )


def _trial_envelope_errors(item: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(item) != TRIAL_FIELDS:
        errors.append("trial has missing or unknown top-level fields")
    if type(item.get("session_index")) is not int:
        errors.append("session_index must be an integer")
    if type(item.get("master_seed")) is not int:
        errors.append("master_seed must be an integer")
    if item.get("condition") not in CONDITION_ORDER:
        errors.append("condition is not registered")
    for field in (
        "state_changed",
        "device_applied",
        "trace_complete",
        "acknowledgment_verified",
    ):
        if type(item.get(field)) is not bool:
            errors.append(f"{field} must be a boolean")
    reasons = item.get("reasons")
    if not isinstance(reasons, list) or any(not isinstance(reason, str) for reason in reasons):
        errors.append("reasons must be a list of strings")
    for field in ("terminal_status", "decision_outcome"):
        if not isinstance(item.get(field), str):
            errors.append(f"{field} must be a string")
    for field in ("device_status", "acknowledgment_reason"):
        if item.get(field) is not None and not isinstance(item.get(field), str):
            errors.append(f"{field} must be a string or null")
    for field in ("pre_state", "post_state", "physical_metrics", "artifacts"):
        if not isinstance(item.get(field), dict):
            errors.append(f"{field} must be an object")
    latency = item.get("latency_ms")
    if not isinstance(latency, dict) or not latency:
        errors.append("latency_ms must be a nonempty object")
    elif any(
        not isinstance(name, str)
        or isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(float(value))
        or float(value) < 0.0
        for name, value in latency.items()
    ):
        errors.append("latency_ms values must be finite nonnegative numbers")
    return errors


def _verify_trial_record(
    item: dict[str, Any],
    *,
    component: dict[str, Any],
    event_records: dict[str, EvidenceRecord],
) -> list[str]:
    errors: list[str] = []
    label = f"session {item.get('session_index')} condition {item.get('condition')}"
    errors.extend(
        f"{label} has an invalid trial envelope: {message}"
        for message in _trial_envelope_errors(item)
    )
    try:
        _assert_condition(item)
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        errors.append(f"{label} violates the registered condition: {exc}")

    try:
        pre_state = PhysicalStateSnapshot.model_validate(item["pre_state"])
        post_state = PhysicalStateSnapshot.model_validate(item["post_state"])
        (
            proposal,
            decision,
            command,
            assessment,
            permit,
            acknowledgment,
            execution_evidence_hash,
        ) = _trial_artifacts(item)
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        errors.append(f"{label} has invalid retained artifacts: {exc}")
        return errors

    if not pre_state.verify_digest() or not post_state.verify_digest():
        errors.append(f"{label} has an invalid physical-state digest")
    try:
        process = component["process"]
        initial_state = PhysicalStateSnapshot.model_validate(component["initial_state"])
        correlated_states = [pre_state, post_state]
        if assessment is not None:
            correlated_states.extend((assessment.pre_state, assessment.post_state))
        if any(
            state.model_id != initial_state.model_id
            or state.model_digest != process["model_digest"]
            or state.simulator_version != process["simulator_version"]
            or state.observation_source_id != "pandapower-cigre-mv-process"
            or state.observation_clock_domain != "UTC"
            for state in correlated_states
        ):
            errors.append(f"{label} physical states do not match the session model")
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        errors.append(f"{label} session model correlation cannot be verified: {exc}")
    if bool(item.get("state_changed")) != _state_changed(pre_state, post_state):
        errors.append(f"{label} state_changed does not match retained states")
    if not _json_exact_equal(item.get("pre_state"), pre_state.model_dump(mode="json")):
        errors.append(f"{label} pre-state JSON types or fields are not canonical")
    if not _json_exact_equal(item.get("post_state"), post_state.model_dump(mode="json")):
        errors.append(f"{label} post-state JSON types or fields are not canonical")
    if not _json_exact_equal(item.get("physical_metrics"), _state_metrics(post_state)):
        errors.append(f"{label} physical metrics do not match the retained post-state")
    if item.get("decision_outcome") != decision.outcome.value:
        errors.append(f"{label} decision outcome does not match its decision artifact")
    if proposal.proposal_id != decision.proposal_id:
        errors.append(f"{label} proposal and decision identifiers do not match")
    condition = str(item.get("condition"))
    decision_physical_state = (
        assessment.pre_state
        if condition == "permit_replay" and assessment is not None
        else pre_state
    )
    if (
        decision.policy_version != M3_POLICY_VERSION
        or decision.safety_version != M3_SAFETY_VERSION
        or decision.state_version != decision_physical_state.state_version
    ):
        errors.append(f"{label} decision is not bound to the registered state and versions")
    if condition != "permit_replay":
        expected_actor = (
            "agent:untrusted" if condition == "unknown_identity" else "agent:operator-1"
        )
        try:
            expected_proposal = _proposal(
                pre_state,
                master_seed=int(item["master_seed"]),
                condition=condition,
                actor_id=expected_actor,
            )
            if proposal != expected_proposal:
                errors.append(f"{label} proposal does not match the registered fixture")
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"{label} registered proposal cannot be reconstructed: {exc}")
    if condition == "unknown_identity" and (
        decision.outcome is not DecisionOutcome.DENY
        or decision.reasons != ("identity_not_verified", "leaf_subject_mismatch")
    ):
        errors.append(f"{label} does not preserve the unknown-identity injection")
    if condition == "stale_state" and (
        decision.outcome is not DecisionOutcome.DENY or decision.reasons != ("state_not_fresh",)
    ):
        errors.append(f"{label} does not preserve the stale-state injection")
    expected_applied = bool(
        acknowledgment is not None and acknowledgment.status is CommandStatus.APPLIED
    )
    if bool(item.get("device_applied")) != expected_applied:
        errors.append(f"{label} device_applied does not match its acknowledgment")
    if acknowledgment is None and (
        item.get("device_status") is not None or item.get("acknowledgment_reason") is not None
    ):
        errors.append(f"{label} asserts device fields without an acknowledgment")
    raw_artifacts = item["artifacts"]
    expected_terminal_payload: dict[str, Any]
    if raw_artifacts.get("schema_version") == "closed-loop-result-v1":
        result = ClosedLoopResult.model_validate(raw_artifacts)
        if not _json_exact_equal(raw_artifacts, result.model_dump(mode="json")):
            errors.append(f"{label} closed-loop artifacts are not canonical typed JSON")
        if (
            item.get("terminal_status") != result.status.value
            or item.get("reasons") != list(result.reasons)
            or pre_state != result.pre_state
            or result.post_state is None
            or post_state != result.post_state
        ):
            errors.append(f"{label} trial fields do not match its closed-loop result")
        expected_terminal_payload = {
            "event_type": "physical_closed_loop_disposition",
            "status": result.status.value,
            "reasons": list(result.reasons),
            "proposal_digest": proposal_digest(result.proposal),
            "pre_state": result.pre_state.model_dump(mode="json"),
            "decision": result.decision.model_dump(mode="json"),
            "command": result.command.model_dump(mode="json") if result.command else None,
            "assessment": (
                result.assessment.model_dump(mode="json") if result.assessment else None
            ),
            "permit": result.permit.model_dump(mode="json") if result.permit else None,
            "acknowledgment": (
                result.acknowledgment.model_dump(mode="json") if result.acknowledgment else None
            ),
            "post_state": (
                result.post_state.model_dump(mode="json") if result.post_state else None
            ),
            "last_observed_state": result.last_observed_state.model_dump(mode="json"),
        }
    else:
        expected_manual_artifacts = {
            "proposal": proposal.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "command": command.model_dump(mode="json") if command else None,
            "assessment": assessment.model_dump(mode="json") if assessment else None,
            "permit": permit.model_dump(mode="json") if permit else None,
            "acknowledgment": (acknowledgment.model_dump(mode="json") if acknowledgment else None),
            "execution_evidence_hash": execution_evidence_hash,
        }
        if not _json_exact_equal(raw_artifacts, expected_manual_artifacts):
            errors.append(f"{label} manual artifacts are not canonical typed JSON")
        if item.get("reasons") != [acknowledgment.reason if acknowledgment else None]:
            errors.append(f"{label} trial reasons do not match its manual acknowledgment")
        expected_terminal_payload = {
            "event_type": "physical_closed_loop_disposition",
            "condition": condition,
            "status": str(item.get("terminal_status")),
            "proposal": proposal.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "command": command.model_dump(mode="json") if command else None,
            "assessment": assessment.model_dump(mode="json") if assessment else None,
            "permit": permit.model_dump(mode="json") if permit else None,
            "acknowledgment": (acknowledgment.model_dump(mode="json") if acknowledgment else None),
            "pre_state": pre_state.model_dump(mode="json"),
            "post_state": post_state.model_dump(mode="json"),
        }

    terminal_event = event_records.get(execution_evidence_hash)
    if terminal_event is None:
        errors.append(f"{label} execution evidence hash is absent from its event chain")
    else:
        if (
            terminal_event.proposal_id != proposal.proposal_id
            or terminal_event.decision_id != decision.decision_id
            or not _json_exact_equal(terminal_event.payload, expected_terminal_payload)
        ):
            errors.append(f"{label} execution evidence event is not transaction-correlated")

    decision_event = (
        event_records.get(decision.evidence_record_hash)
        if decision.evidence_record_hash is not None
        else None
    )
    if decision_event is None:
        errors.append(f"{label} decision evidence hash is absent from its event chain")
    else:
        gateway_state = physical_state_to_gateway_state(decision_physical_state)
        expected_decision_payload = {
            "proposal": proposal.model_dump(mode="json"),
            "decision": decision.model_copy(update={"evidence_record_hash": None}).model_dump(
                mode="json"
            ),
            "state": gateway_state.model_dump(mode="json"),
            "predicted_state": SafetyKernel()
            .evaluate(
                proposal,
                gateway_state,
            )
            .predicted_state.model_dump(mode="json"),
            "identity_version": "local-allowlist-v1",
        }
        if (
            decision_event.proposal_id != proposal.proposal_id
            or decision_event.decision_id != decision.decision_id
            or not _json_exact_equal(decision_event.payload, expected_decision_payload)
        ):
            errors.append(f"{label} decision evidence event is not transaction-correlated")

    if condition in {"unknown_identity", "stale_state"}:
        if any(artifact is not None for artifact in (command, assessment, permit, acknowledgment)):
            errors.append(f"{label} denial contains post-decision transaction artifacts")
        return errors
    if command is None or assessment is None or permit is None:
        errors.append(f"{label} is missing its authorization transaction artifacts")
        if acknowledgment is not None:
            errors.append(f"{label} contains an acknowledgment without a permit")
        return errors

    if not _verify_permit_bindings(
        proposal=proposal,
        decision=decision,
        command=command,
        assessment=assessment,
        permit=permit,
    ):
        errors.append(f"{label} execution permit bindings are inconsistent")

    try:
        permit_public_key = _public_key_from_b64(str(component["permit_public_key_b64"]))
        process = component["process"]
        device_public_key = _public_key_from_b64(str(process["device_public_key_b64"]))
        expected_audience = str(process["audience"])
        expected_device_id = str(process["device_id"])
        expected_key_id = str(process["device_key_id"])
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"{label} has invalid retained verification keys: {exc}")
        return errors

    permit_signature_valid = permit.verify(permit_public_key)
    if condition == "wrong_audience_permit":
        restored_permit = permit.model_copy(update={"audience": expected_audience})
        if (
            permit.audience == expected_audience
            or permit_signature_valid
            or not restored_permit.verify(permit_public_key)
        ):
            errors.append(f"{label} does not preserve the registered audience-tamper fixture")
    elif permit.audience != expected_audience or not permit_signature_valid:
        errors.append(f"{label} execution permit signature or audience is invalid")

    if acknowledgment is None:
        errors.append(f"{label} is missing its device acknowledgment")
        return errors
    if item.get("device_status") != acknowledgment.status.value:
        errors.append(f"{label} device status does not match its acknowledgment")
    if item.get("acknowledgment_reason") != acknowledgment.reason:
        errors.append(f"{label} acknowledgment reason does not match its acknowledgment")
    expected_dispositions = {
        "wrong_audience_permit": (CommandStatus.REJECTED, "permit_wrong_audience"),
        "nominal_permitted_execution": (
            CommandStatus.APPLIED,
            "command_applied_and_read_back",
        ),
        "permit_replay": (CommandStatus.REJECTED, "permit_replayed"),
    }
    if (acknowledgment.status, acknowledgment.reason) != expected_dispositions.get(condition):
        errors.append(f"{label} signed device disposition does not match the registered fixture")
    if not acknowledgment.verify_for_transaction(
        device_public_key,
        permit=permit,
        pre_state=pre_state,
        readback_state=post_state,
        expected_device_id=expected_device_id,
        expected_key_id=expected_key_id,
    ):
        errors.append(f"{label} retained acknowledgment signature or binding is invalid")
    return errors


def _verify_m3_package_checked(output_dir: Path) -> dict[str, Any]:
    checks: dict[str, bool | None] = {
        "manifest": None,
        "artifact_hashes": None,
        "record_counts": None,
        "event_chains": None,
        "trial_semantics": None,
        "deterministic_outcome": None,
        "summary": None,
        "configuration_bindings": None,
        "checkout_bindings": None,
    }
    errors: list[str] = []
    error_count = 0

    def fail(check: str, message: str) -> None:
        nonlocal error_count
        checks[check] = False
        error_count += 1
        if len(errors) < MAX_VERIFIER_ERRORS:
            errors.append(f"{check}: {message}")

    def reported_errors() -> list[str]:
        if error_count <= len(errors):
            return list(errors)
        return [
            *errors,
            f"error_limit: {error_count - len(errors)} additional errors omitted",
        ]

    def complete(check: str) -> None:
        if checks[check] is None:
            checks[check] = True

    try:
        manifest_value = _strict_json_loads(
            _read_package_bytes(output_dir, "manifest.json", maximum_bytes=4 * 1024 * 1024)
        )
        if not isinstance(manifest_value, dict):
            raise ValueError("manifest must be a JSON object")
        manifest: dict[str, Any] = manifest_value
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        fail("manifest", f"manifest cannot be read: {exc}")
        return {
            "valid": False,
            "errors": reported_errors(),
            "checks": checks,
            "claim_boundary": "internal consistency only; manifest is not externally signed",
            "verification_assumption": PACKAGE_STABILITY_ASSUMPTION,
        }

    if set(manifest) != MANIFEST_FIELDS:
        fail("manifest", "manifest has missing or unknown fields")
    if manifest.get("experiment_version") != EXPERIMENT_VERSION:
        fail("manifest", "experiment version is unsupported")
    if manifest.get("outcome_projection_version") != OUTCOME_PROJECTION_VERSION:
        fail("manifest", "outcome projection version is unsupported")
    experiment_id = manifest.get("experiment_id")
    started_at = _parse_registered_timestamp(manifest.get("started_at_utc"))
    completed_at = _parse_registered_timestamp(manifest.get("completed_at_utc"))
    expected_experiment_id = (
        f"{EXPERIMENT_VERSION}-{started_at.strftime('%Y%m%dT%H%M%S%fZ')}"
        if started_at is not None
        else None
    )
    if not isinstance(experiment_id, str) or experiment_id != expected_experiment_id:
        fail("manifest", "experiment identifier is missing or inconsistent")
    if started_at is None or completed_at is None or completed_at < started_at:
        fail("manifest", "experiment timestamps are invalid or inconsistent")
    git_metadata = manifest.get("git")
    if not isinstance(git_metadata, dict) or set(git_metadata) != {
        "commit",
        "working_tree_dirty_at_start",
    }:
        fail("manifest", "Git metadata has an invalid shape")
    else:
        commit = git_metadata.get("commit")
        if (
            not isinstance(commit, str)
            or not (
                commit == "unknown"
                or (
                    len(commit) == 40
                    and all(character in "0123456789abcdef" for character in commit)
                )
            )
            or type(git_metadata.get("working_tree_dirty_at_start")) is not bool
        ):
            fail("manifest", "Git metadata has invalid field types")
    host = manifest.get("host")
    if not isinstance(host, dict) or set(host) != {
        "os",
        "architecture",
        "python",
        "logical_cpu_count",
        "physical_memory_bytes",
    }:
        fail("manifest", "host metadata has an invalid shape")
    else:
        cpu_count = host.get("logical_cpu_count")
        memory_bytes = host.get("physical_memory_bytes")
        if (
            any(
                not isinstance(host.get(field), str) or not host.get(field)
                for field in ("os", "architecture", "python")
            )
            or (cpu_count is not None and (type(cpu_count) is not int or cpu_count <= 0))
            or (memory_bytes is not None and (type(memory_bytes) is not int or memory_bytes <= 0))
        ):
            fail("manifest", "host metadata has invalid field types")
    if not _is_sha256(manifest.get("model_digest")) or not _is_sha256(
        manifest.get("deterministic_outcome_sha256")
    ):
        fail("manifest", "manifest model or outcome digest is invalid")
    complete("manifest")

    artifact_hashes = manifest.get("artifact_sha256")
    if not isinstance(artifact_hashes, dict):
        fail("artifact_hashes", "manifest artifact hashes are missing")
        artifact_hashes = {}
    if set(artifact_hashes) != set(REQUIRED_ARTIFACT_PATHS):
        fail("artifact_hashes", "artifact hash paths differ from the registered package")
    artifact_materials: dict[str, bytes] = {}
    total_artifact_bytes = 0
    for relative_path in REQUIRED_ARTIFACT_PATHS:
        expected_hash = artifact_hashes.get(relative_path)
        try:
            material = _read_package_bytes(output_dir, relative_path)
            total_artifact_bytes += len(material)
            if total_artifact_bytes > MAX_PACKAGE_TOTAL_BYTES:
                raise ValueError("registered artifact package exceeds the aggregate byte limit")
            if not _is_sha256(expected_hash):
                raise ValueError("recorded artifact hash is not a lowercase SHA-256 value")
            artifact_materials[relative_path] = material
            actual_hash = _sha256_bytes(material)
            if actual_hash != expected_hash:
                fail("artifact_hashes", f"artifact hash mismatch for {relative_path}")
        except (OSError, ValueError) as exc:
            fail("artifact_hashes", f"artifact {relative_path} cannot be verified: {exc}")
    complete("artifact_hashes")

    try:
        trials = _loads_jsonl(
            artifact_materials["trials.jsonl"],
            "trials.jsonl",
            maximum_records=MAX_M3_SESSIONS * len(CONDITION_ORDER),
        )
        events = _loads_jsonl(
            artifact_materials["events.jsonl"],
            "events.jsonl",
            maximum_records=MAX_M3_SESSIONS * EXPECTED_EVENT_RECORDS_PER_SESSION,
        )
        scenarios = _strict_json_loads(artifact_materials["scenarios.json"])
        summary = _strict_json_loads(artifact_materials["summary.json"])
        component_health = _strict_json_loads(artifact_materials["component-health.json"])
        evidence_verification = _strict_json_loads(artifact_materials["evidence-verification.json"])
        benchmark = _strict_json_loads(artifact_materials["benchmark/provenance.json"])
        solver = _strict_json_loads(artifact_materials["solver/configuration.json"])
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
        fail("manifest", f"retained package cannot be parsed: {exc}")
        return {
            "valid": False,
            "errors": reported_errors(),
            "checks": checks,
            "claim_boundary": "internal consistency only; manifest is not externally signed",
            "verification_assumption": PACKAGE_STABILITY_ASSUMPTION,
        }

    seeds = manifest.get("master_seeds")
    if (
        not isinstance(seeds, list)
        or not seeds
        or len(seeds) > MAX_M3_SESSIONS
        or any(type(seed) is not int for seed in seeds)
        or len(set(seeds)) != len(seeds)
    ):
        fail("record_counts", "manifest master seeds are invalid")
        return {
            "valid": False,
            "errors": reported_errors(),
            "checks": checks,
            "session_count": 0,
            "trial_record_count": len(trials),
            "event_record_count": len(events),
            "deterministic_outcome_sha256": manifest.get("deterministic_outcome_sha256"),
            "claim_boundary": "internal consistency only; manifest is not externally signed",
            "verification_assumption": PACKAGE_STABILITY_ASSUMPTION,
        }
    expected_sessions = {index: seed for index, seed in enumerate(seeds)}
    root_seed = manifest.get("master_seed")
    individual_seeds = manifest.get("individual_seeds")
    if (
        (root_seed is not None and type(root_seed) is not int)
        or not isinstance(individual_seeds, list)
        or any(type(seed) is not int for seed in individual_seeds)
        or individual_seeds != seeds
    ):
        fail("record_counts", "root or individual seed metadata is inconsistent")
    if root_seed is not None and (
        not seeds or tuple(seeds) != derive_master_seeds(root_seed, len(seeds))
    ):
        fail("record_counts", "individual seeds do not derive from the recorded master seed")
    expected_manifest_counts = {
        "master_seed_count": len(seeds),
        "session_count": len(seeds),
        "conditions_per_session": len(CONDITION_ORDER),
        "trial_record_count": len(trials),
        "event_record_count": len(events),
    }
    if (
        any(
            type(manifest.get(field)) is not int or manifest.get(field) != expected
            for field, expected in expected_manifest_counts.items()
        )
        or len(trials) != len(seeds) * len(CONDITION_ORDER)
        or len(events) != len(seeds) * EXPECTED_EVENT_RECORDS_PER_SESSION
    ):
        fail("record_counts", "manifest counts do not match retained records")
        return {
            "valid": False,
            "errors": reported_errors(),
            "checks": checks,
            "session_count": len(seeds),
            "trial_record_count": len(trials),
            "event_record_count": len(events),
            "deterministic_outcome_sha256": manifest.get("deterministic_outcome_sha256"),
            "claim_boundary": "internal consistency only; manifest is not externally signed",
            "verification_assumption": PACKAGE_STABILITY_ASSUMPTION,
        }

    records_by_hash, event_errors = _verify_event_records(events, expected_sessions)
    for message in event_errors:
        fail("event_chains", message)
    complete("event_chains")

    component_sessions_value = (
        component_health.get("sessions") if isinstance(component_health, dict) else None
    )
    verification_sessions_value = (
        evidence_verification.get("sessions") if isinstance(evidence_verification, dict) else None
    )
    if not isinstance(component_health, dict) or set(component_health) != {"sessions"}:
        fail("record_counts", "component-health artifact has an invalid shape")
    if not isinstance(evidence_verification, dict) or set(evidence_verification) != {"sessions"}:
        fail("record_counts", "evidence-verification artifact has an invalid shape")
    if not isinstance(component_sessions_value, list):
        fail("record_counts", "component-health sessions must be a list")
        component_sessions: list[Any] = []
    else:
        component_sessions = component_sessions_value
    if not isinstance(verification_sessions_value, list):
        fail("record_counts", "evidence-verification sessions must be a list")
        verification_sessions: list[Any] = []
    else:
        verification_sessions = verification_sessions_value
    for name, sessions in (
        ("component-health", component_sessions),
        ("evidence-verification", verification_sessions),
    ):
        indexes = [
            item.get("session_index") if isinstance(item, dict) else None for item in sessions
        ]
        if (
            len(sessions) != len(seeds)
            or any(type(index) is not int for index in indexes)
            or len(set(indexes)) != len(indexes)
        ):
            fail("record_counts", f"{name} sessions are duplicated, malformed, or incomplete")
    if any(
        not isinstance(item, dict) or set(item) != COMPONENT_FIELDS for item in component_sessions
    ):
        fail("trial_semantics", "component-health session rows have invalid fields")
    if any(
        not isinstance(item, dict) or set(item) != VERIFICATION_FIELDS
        for item in verification_sessions
    ):
        fail("record_counts", "evidence-verification session rows have invalid fields")
    component_by_session = {
        item.get("session_index"): item for item in component_sessions if isinstance(item, dict)
    }
    verification_by_session = {
        item.get("session_index"): item for item in verification_sessions if isinstance(item, dict)
    }
    if set(component_by_session) != set(expected_sessions):
        fail("record_counts", "component-health sessions do not match the manifest")
    if set(verification_by_session) != set(expected_sessions):
        fail("record_counts", "evidence-verification sessions do not match the manifest")
    component_identity_values = {
        "boot epoch": [
            item.get("process", {}).get("boot_epoch")
            for item in component_sessions
            if isinstance(item, dict) and isinstance(item.get("process"), dict)
        ],
        "device identifier": [
            item.get("process", {}).get("device_id")
            for item in component_sessions
            if isinstance(item, dict) and isinstance(item.get("process"), dict)
        ],
        "device public key": [
            item.get("process", {}).get("device_public_key_b64")
            for item in component_sessions
            if isinstance(item, dict) and isinstance(item.get("process"), dict)
        ],
        "permit public key": [
            item.get("permit_public_key_b64")
            for item in component_sessions
            if isinstance(item, dict)
        ],
    }
    for identity_name, values in component_identity_values.items():
        if (
            len(values) != len(seeds)
            or any(not isinstance(value, str) for value in values)
            or len(set(values)) != len(values)
        ):
            fail(
                "trial_semantics",
                f"component sessions do not have unique {identity_name} values",
            )

    trials_by_session: dict[int, list[dict[str, Any]]] = {}
    for item in trials:
        session_index = item.get("session_index")
        if type(session_index) is not int:
            fail("trial_semantics", "trial has no valid session index")
            continue
        trials_by_session.setdefault(session_index, []).append(item)
    if set(trials_by_session) != set(expected_sessions):
        fail("record_counts", "trial sessions do not match the manifest")

    for session_index, master_seed in expected_sessions.items():
        session_trials = trials_by_session.get(session_index, [])
        if [item.get("condition") for item in session_trials] != list(CONDITION_ORDER):
            fail("trial_semantics", f"session {session_index} condition order is invalid")
        if any(item.get("master_seed") != master_seed for item in session_trials):
            fail("trial_semantics", f"session {session_index} master seed does not match")
        component = component_by_session.get(session_index)
        if component is None:
            fail(
                "trial_semantics",
                f"session {session_index} cannot be verified without component metadata",
            )
            continue
        process_value = component.get("process", {})
        initial_state_value = component.get("initial_state", {})
        health_payload_value = component.get("verified_health_payload", {})
        process = process_value if isinstance(process_value, dict) else {}
        initial_state = initial_state_value if isinstance(initial_state_value, dict) else {}
        health_payload = health_payload_value if isinstance(health_payload_value, dict) else {}
        process_pid = process.get("pid")
        parent_pid = component.get("parent_pid")
        process_port = process.get("port")
        startup_ms = component.get("startup_ms")
        boot_epoch = process.get("boot_epoch")
        device_id = process.get("device_id")
        if type(component.get("master_seed")) is not int:
            fail(
                "trial_semantics",
                f"session {session_index} component master seed must be an integer",
            )
        if (
            set(component) != COMPONENT_FIELDS
            or set(process) != PROCESS_FIELDS
            or set(health_payload) != HEALTH_FIELDS
            or type(component.get("master_seed")) is not int
            or component.get("master_seed") != master_seed
            or component.get("separate_process_verified") is not True
            or type(process_pid) is not int
            or process_pid <= 0
            or type(parent_pid) is not int
            or parent_pid <= 0
            or process_pid == parent_pid
            or process.get("host") != M3_LOOPBACK_HOST
            or type(process_port) is not int
            or not 1 <= process_port <= 65535
            or type(process.get("protocol_version")) is not int
            or process.get("protocol_version") != M3_PROTOCOL_VERSION
            or not _is_finite_nonnegative_number(startup_ms)
            or not isinstance(boot_epoch, str)
            or not isinstance(device_id, str)
            or device_id != f"virtual-modbus-device:m3:{boot_epoch}"
            or process.get("audience") != device_id
            or process.get("device_key_id") != M3_DEVICE_KEY_ID
            or not _valid_public_key_b64(process.get("device_public_key_b64"))
            or not _valid_public_key_b64(component.get("permit_public_key_b64"))
            or process.get("model_digest") != manifest.get("model_digest")
            or process.get("simulator_version") != _solver_configuration()["simulator"]
        ):
            fail("trial_semantics", f"session {session_index} process metadata is inconsistent")
        if (
            health_payload.get("status") != "ready"
            or type(health_payload.get("protocol_version")) is not int
            or health_payload.get("protocol_version") != process.get("protocol_version")
            or health_payload.get("model_digest") != process.get("model_digest")
            or health_payload.get("simulator_version") != process.get("simulator_version")
            or health_payload.get("device_id") != process.get("device_id")
            or health_payload.get("device_key_id") != process.get("device_key_id")
            or health_payload.get("boot_epoch") != process.get("boot_epoch")
            or type(health_payload.get("state_version")) is not int
            or health_payload.get("state_version") != initial_state.get("state_version")
        ):
            fail(
                "trial_semantics",
                f"session {session_index} verified health payload is inconsistent",
            )
        retained_initial_state: PhysicalStateSnapshot | None = None
        try:
            retained_initial_state = PhysicalStateSnapshot.model_validate(initial_state)
            if (
                not _json_exact_equal(
                    initial_state,
                    retained_initial_state.model_dump(mode="json"),
                )
                or not retained_initial_state.verify_digest()
                or retained_initial_state.model_id != CIGRE_MV_MODEL_ID
                or retained_initial_state.model_id != benchmark.get("model_id")
                or retained_initial_state.model_digest != process.get("model_digest")
                or retained_initial_state.simulator_version != process.get("simulator_version")
                or retained_initial_state.observation_source_id != "pandapower-cigre-mv-process"
                or retained_initial_state.observation_clock_domain != "UTC"
            ):
                raise ValueError("initial state digest or model binding is invalid")
        except (TypeError, ValueError, ValidationError) as exc:
            fail("trial_semantics", f"session {session_index} initial state is invalid: {exc}")
        for item in session_trials:
            for message in _verify_trial_record(
                item,
                component=component,
                event_records=records_by_hash.get(session_index, {}),
            ):
                fail("trial_semantics", message)

        referenced_event_hashes: set[str] = set()
        try:
            for item in session_trials:
                artifacts = _trial_artifacts(item)
                referenced_event_hashes.add(artifacts[6])
                if artifacts[1].evidence_record_hash is not None:
                    referenced_event_hashes.add(artifacts[1].evidence_record_hash)
            if set(records_by_hash.get(session_index, {})) != referenced_event_hashes:
                fail(
                    "event_chains",
                    f"session {session_index} has missing or unreferenced evidence records",
                )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            fail(
                "event_chains",
                f"session {session_index} evidence references cannot be reconstructed: {exc}",
            )

        if retained_initial_state is not None:
            state_cursor = retained_initial_state
            try:
                for item in session_trials:
                    trial_pre = PhysicalStateSnapshot.model_validate(item["pre_state"])
                    trial_post = PhysicalStateSnapshot.model_validate(item["post_state"])
                    if (
                        trial_pre.state_digest != state_cursor.state_digest
                        or trial_pre.state_version != state_cursor.state_version
                    ):
                        fail(
                            "trial_semantics",
                            f"session {session_index} physical-state sequence is discontinuous",
                        )
                    if (
                        trial_pre.observation_sequence < state_cursor.observation_sequence
                        or trial_pre.observed_at < state_cursor.observed_at
                        or trial_post.observation_sequence < trial_pre.observation_sequence
                        or trial_post.observed_at < trial_pre.observed_at
                    ):
                        fail(
                            "trial_semantics",
                            f"session {session_index} observation sequence is not monotonic",
                        )
                    state_cursor = trial_post
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
                fail(
                    "trial_semantics",
                    f"session {session_index} physical-state sequence is invalid: {exc}",
                )

        try:
            nominal_trial = next(
                item
                for item in session_trials
                if item.get("condition") == "nominal_permitted_execution"
            )
            replay_trial = next(
                item for item in session_trials if item.get("condition") == "permit_replay"
            )
            nominal_artifacts = _trial_artifacts(nominal_trial)
            replay_artifacts = _trial_artifacts(replay_trial)
            nominal_post = PhysicalStateSnapshot.model_validate(nominal_trial["post_state"])
            replay_pre = PhysicalStateSnapshot.model_validate(replay_trial["pre_state"])
            replay_post = PhysicalStateSnapshot.model_validate(replay_trial["post_state"])
            if (
                replay_artifacts[:5] != nominal_artifacts[:5]
                or replay_pre.state_digest != nominal_post.state_digest
                or replay_pre.state_version != nominal_post.state_version
                or replay_post.state_digest != replay_pre.state_digest
                or replay_post.state_version != replay_pre.state_version
            ):
                fail(
                    "trial_semantics",
                    f"session {session_index} replay does not reuse the nominal transaction",
                )
        except (KeyError, StopIteration, TypeError, ValueError, ValidationError) as exc:
            fail(
                "trial_semantics",
                f"session {session_index} replay relationship cannot be verified: {exc}",
            )

        verification = verification_by_session.get(session_index)
        if verification is not None:
            event_count = len(records_by_hash.get(session_index, {}))
            expected_verification_counts = {
                "evidence_record_count": event_count,
                "condition_count": len(session_trials),
                "trace_complete_count": sum(
                    bool(item.get("trace_complete")) for item in session_trials
                ),
                "acknowledgment_verified_count": sum(
                    bool(item.get("acknowledgment_verified")) for item in session_trials
                ),
            }
            if (
                set(verification) != VERIFICATION_FIELDS
                or type(verification.get("master_seed")) is not int
                or verification.get("master_seed") != master_seed
                or verification.get("evidence_chain_valid") is not True
                or any(
                    type(verification.get(field)) is not int or verification.get(field) != expected
                    for field, expected in expected_verification_counts.items()
                )
            ):
                fail(
                    "record_counts",
                    f"session {session_index} evidence-verification counts are inconsistent",
                )
    complete("record_counts")
    complete("trial_semantics")

    try:
        deterministic_text = _jsonl_text(_deterministic_projection(trials))
        if _sha256_bytes(deterministic_text.encode("utf-8")) != manifest.get(
            "deterministic_outcome_sha256"
        ):
            fail("deterministic_outcome", "timing-independent outcome hash does not match")
    except (KeyError, TypeError, ValueError) as exc:
        fail("deterministic_outcome", f"outcome projection cannot be recomputed: {exc}")
    complete("deterministic_outcome")

    try:
        recomputed_summary = summarize_m3(trials)
        if not _json_exact_equal(recomputed_summary, summary) or not _json_exact_equal(
            manifest.get("summary"), summary
        ):
            fail("summary", "retained or embedded summary does not match trial records")
    except (KeyError, TypeError, ValueError) as exc:
        fail("summary", f"summary cannot be recomputed: {exc}")
    complete("summary")

    configuration_hashes = manifest.get("configuration_sha256", {})
    expected_configuration = {
        "scenarios": canonical_digest(scenarios),
        "solver": canonical_digest(solver),
        "benchmark": canonical_digest(benchmark),
    }
    expected_configuration_paths = {
        "pyproject.toml",
        "requirements.lock",
        "scenarios",
        "solver",
        "benchmark",
    }
    if (
        not isinstance(configuration_hashes, dict)
        or set(configuration_hashes) != expected_configuration_paths
        or any(not _is_sha256(value) for value in configuration_hashes.values())
        or any(
            configuration_hashes.get(name) != digest
            for name, digest in expected_configuration.items()
        )
    ):
        fail("configuration_bindings", "artifact configuration hashes do not match")
    if not _json_exact_equal(scenarios, _scenario_catalog()):
        fail("configuration_bindings", "scenario catalog differs from the registered catalog")
    if not _json_exact_equal(solver, _solver_configuration()):
        fail("configuration_bindings", "solver configuration differs from the registered design")
    source_hashes = manifest.get("source_sha256")
    recorded_plant_sha256 = (
        source_hashes.get("src/aegis_ot/pandapower_plant.py")
        if isinstance(source_hashes, dict)
        else None
    )
    if not _json_exact_equal(
        benchmark,
        _benchmark_provenance(
            str(manifest.get("model_digest")),
            implementation_sha256=(
                recorded_plant_sha256 if isinstance(recorded_plant_sha256, str) else ""
            ),
        ),
    ):
        fail("configuration_bindings", "benchmark provenance or model binding is inconsistent")
    if (
        manifest.get("scenario_version") != _scenario_catalog()["catalog_version"]
        or not _json_exact_equal(
            manifest.get("experiment_configuration"),
            _experiment_configuration(),
        )
        or not _json_exact_equal(manifest.get("component_versions"), _component_versions())
        or not _json_exact_equal(manifest.get("boundary"), _boundary_configuration())
        or not _json_exact_equal(manifest.get("known_limitations"), _known_limitations())
        or manifest.get("raw_data_location") != "."
        or not _json_exact_equal(manifest.get("known_failures"), [])
        or manifest.get("analyst") != "Angelis Pseftis"
    ):
        fail("configuration_bindings", "experiment metadata differs from the registered design")
    complete("configuration_bindings")

    source_hashes = manifest.get("source_sha256", {})
    if not isinstance(configuration_hashes, dict):
        configuration_hashes = {}
    config_file_hashes = {
        "pyproject.toml": configuration_hashes.get("pyproject.toml"),
        "requirements.lock": configuration_hashes.get("requirements.lock"),
    }
    schema_hashes = manifest.get("schema_sha256", {})
    checkout_hashes: dict[str, Any] = {
        path: source_hashes.get(path) if isinstance(source_hashes, dict) else None
        for path in M3_SOURCE_PATHS
    }
    checkout_hashes.update(config_file_hashes)
    checkout_hashes.update(
        {
            path: schema_hashes.get(path) if isinstance(schema_hashes, dict) else None
            for path in M3_SCHEMA_PATHS
        }
    )
    if not isinstance(source_hashes, dict) or set(source_hashes) != set(M3_SOURCE_PATHS):
        fail("checkout_bindings", "manifest source hashes are missing or incomplete")
    if not isinstance(schema_hashes, dict) or set(schema_hashes) != set(M3_SCHEMA_PATHS):
        fail("checkout_bindings", "manifest schema hashes are missing or incomplete")
    for relative_path, expected_hash in checkout_hashes.items():
        try:
            if _sha256_bytes((ROOT / relative_path).read_bytes()) != expected_hash:
                fail("checkout_bindings", f"checkout hash mismatch for {relative_path}")
        except (OSError, TypeError):
            fail("checkout_bindings", f"checkout file cannot be verified: {relative_path}")
    complete("checkout_bindings")

    return {
        "valid": error_count == 0 and all(value is True for value in checks.values()),
        "errors": reported_errors(),
        "checks": checks,
        "session_count": len(seeds),
        "trial_record_count": len(trials),
        "event_record_count": len(events),
        "deterministic_outcome_sha256": manifest.get("deterministic_outcome_sha256"),
        "claim_boundary": "internal consistency only; manifest is not externally signed",
        "verification_assumption": PACKAGE_STABILITY_ASSUMPTION,
    }


def verify_m3_package(output_dir: Path) -> dict[str, Any]:
    """Verify retained M3 evidence without propagating malformed-package failures.

    The manifest is not externally signed, so a valid result is not third-party
    authenticity, independent replication, or validation of the physical model.
    """

    try:
        return _verify_m3_package_checked(output_dir)
    except Exception as exc:  # noqa: BLE001 - untrusted local evidence must fail closed
        return {
            "valid": False,
            "errors": [
                "defensive_boundary: malformed package could not be verified: "
                f"{type(exc).__name__}: {exc}"
            ],
            "checks": {"defensive_boundary": False},
            "claim_boundary": "internal consistency only; manifest is not externally signed",
            "verification_assumption": PACKAGE_STABILITY_ASSUMPTION,
        }


def default_master_seeds(seed: int = 20260824, count: int = 30) -> tuple[int, ...]:
    """Return the preregistered independent session seeds."""

    return derive_master_seeds(seed, count)
