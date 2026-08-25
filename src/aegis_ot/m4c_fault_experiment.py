"""Retained same-host fault campaign for the capability-separated control loop.

The campaign deliberately injects failures at the coordinator's existing typed
ports.  It does not add fault-control operations to the plant, observer, or PLC
services and therefore does not widen their production-shaped capabilities.
Each controller condition starts a fresh process stack.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, NoReturn, cast

from pydantic import JsonValue

from aegis_ot_independent.canonical import strict_json_loads
from aegis_ot_independent.evaluator import verify_report

from .capability_control import ObservationPort, VirtualPlcPort
from .capability_factory import CapabilitySeparatedLab, start_capability_separated_lab
from .capability_ipc import IpcOutcomeUnknownError
from .capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopResult,
    CapabilityClosedLoopStatus,
    CapabilityExecutionPermit,
    DispatchPhase,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from .capability_observer import ObserverServiceError
from .capability_plc import OrderlyRestartReplayReservations
from .m4b_models import (
    IndependentConsequenceReport,
    IndependentEvaluationRequest,
    IndependentEvaluationStatus,
    canonical_json_bytes,
    public_key_base64,
    sha256_bytes,
)
from .models import ActionProposal, Decision, DecisionOutcome, Operation
from .physical_control import physical_state_to_gateway_state
from .physical_models import CandidateAssessment, CommandStatus

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "fixtures/m4b/cigre-mv-topology-v1.json"
REFERENCE_TIME = datetime(2026, 8, 25, 18, 0, tzinfo=UTC)
CONDITION_ORDER = (
    "nominal_control",
    "plc_response_lost_after_commit",
    "post_observation_unavailable_after_commit",
    "post_observation_tampered_after_signing",
    "signed_post_observation_contradiction",
)


class _CommitThenLosePlcResponse:
    def __init__(self, delegate: VirtualPlcPort) -> None:
        self.delegate = delegate
        self.acknowledgment: PlcCommandAcknowledgment | None = None

    def execute(
        self,
        *,
        request: CapabilityActionRequest,
        permit: CapabilityExecutionPermit,
        pre_observation: SignedObservationEnvelope,
        decision: Decision,
        assessment: CandidateAssessment,
    ) -> PlcCommandAcknowledgment:
        self.acknowledgment = self.delegate.execute(
            request=request,
            permit=permit,
            pre_observation=pre_observation,
            decision=decision,
            assessment=assessment,
        )
        raise IpcOutcomeUnknownError("injected response loss after PLC commit")


class _PostObservationUnavailable:
    def __init__(self, delegate: ObservationPort) -> None:
        self.delegate = delegate

    def resolve(self, *, observation_id: str, envelope_digest: str) -> SignedObservationEnvelope:
        return self.delegate.resolve(
            observation_id=observation_id,
            envelope_digest=envelope_digest,
        )

    def capture_post(self, **_: str) -> SignedObservationEnvelope:
        raise ObserverServiceError("injected post-observation unavailability")


class _TamperPostObservationAfterSigning:
    def __init__(self, delegate: ObservationPort) -> None:
        self.delegate = delegate
        self.original: SignedObservationEnvelope | None = None
        self.tampered: SignedObservationEnvelope | None = None

    def resolve(self, *, observation_id: str, envelope_digest: str) -> SignedObservationEnvelope:
        return self.delegate.resolve(
            observation_id=observation_id,
            envelope_digest=envelope_digest,
        )

    def capture_post(self, **arguments: str) -> SignedObservationEnvelope:
        self.original = self.delegate.capture_post(**arguments)
        self.tampered = self.original.model_copy(
            update={"challenge_nonce": f"{self.original.challenge_nonce}-tampered"}
        )
        return self.tampered


def _proposal(
    lab: CapabilitySeparatedLab,
    observation: SignedObservationEnvelope,
    condition: str,
) -> ActionProposal:
    return ActionProposal(
        proposal_id=f"m4c-{condition}",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=observation.snapshot.state_version,
        observed_at=observation.snapshot.observed_at,
        submitted_at=observation.snapshot.observed_at,
        nonce=f"m4c-{condition}-nonce-0001",
        confidence=0.95,
        risk_score=40.0,
        delegation_chain=(
            lab.authorization.root_grant.grant_id,
            lab.authorization.leaf_grant.grant_id,
        ),
    )


def _expected_status(condition: str) -> CapabilityClosedLoopStatus:
    if condition == "nominal_control":
        return CapabilityClosedLoopStatus.COMPLETED
    if condition == "signed_post_observation_contradiction":
        return CapabilityClosedLoopStatus.OBSERVATION_DIVERGED
    return CapabilityClosedLoopStatus.UNKNOWN_EFFECT


def _evaluate_signed_contradiction(
    result: CapabilityClosedLoopResult,
    condition: str,
    observer_public_key_b64: str,
) -> dict[str, JsonValue]:
    if result.pre_observation is None or result.post_observation is None or result.command is None:
        raise RuntimeError("signed contradiction lacks evaluator inputs")
    request = IndependentEvaluationRequest(
        request_id=f"m4c:{condition}:independent-evaluation",
        session_index=4,
        master_seed=20260825,
        transaction_record_digest=sha256_bytes(canonical_json_bytes(result)),
        fixture_id="pandapower-cigre-mv-all-neutral-topology-v1",
        fixture_digest=(
            "58ed983e507811935c448e6d468e952ff34620958eae893d16d454a89651709f"
        ),
        nonce=f"m4c:{condition}:independent-evaluation-nonce-0001",
        pre_observation=result.pre_observation,
        post_observation=result.post_observation,
        command=result.command,
        observer_key_id=result.pre_observation.observer_key_id,
        observer_public_key_b64=observer_public_key_b64,
        absolute_tolerance_mw=Decimal("0.000000001"),
        absolute_tolerance_pct=Decimal("0.000000001"),
    )
    with tempfile.TemporaryDirectory(prefix="aegis-ot-m4c-contradiction-") as temporary:
        directory = Path(temporary)
        request_path = directory / "request.json"
        fixture_path = directory / "fixture.json"
        report_path = directory / "report.json"
        request_path.write_bytes(canonical_json_bytes(request))
        fixture_path.write_bytes(FIXTURE_PATH.read_bytes())
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        completed = subprocess.run(  # noqa: S603 - fixed interpreter/module, test-owned paths
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
            timeout=30,
        )
        if completed.returncode != 1 or not report_path.is_file():
            raise RuntimeError("signed contradiction did not produce evaluator contradiction")
        report = IndependentConsequenceReport.model_validate(
            strict_json_loads(report_path.read_bytes())
        )
    if (
        report.status is not IndependentEvaluationStatus.CONTRADICT
        or not report.verify_for_request(request)
    ):
        raise RuntimeError("signed evaluator contradiction failed authenticity or binding")
    mismatches = [
        item.metric.value
        for item in report.metric_comparisons
        if item.outcome == "mismatch"
    ]
    return {
        "status": report.status.value,
        "report_valid": True,
        "evaluator_process_separate": report.pid != os.getpid(),
        "metric_mismatches": cast(list[JsonValue], mismatches),
    }


def _evaluate_missing_independent_post(
    result: CapabilityClosedLoopResult,
    observer_public_key_b64: str,
) -> dict[str, JsonValue]:
    if result.pre_observation is None or result.command is None:
        raise RuntimeError("nominal control lacks missing-post evaluator inputs")
    request = IndependentEvaluationRequest(
        request_id="m4c:missing-post:independent-evaluation",
        session_index=0,
        master_seed=20260825,
        transaction_record_digest=sha256_bytes(canonical_json_bytes(result)),
        fixture_id="pandapower-cigre-mv-all-neutral-topology-v1",
        fixture_digest=(
            "58ed983e507811935c448e6d468e952ff34620958eae893d16d454a89651709f"
        ),
        nonce="m4c:missing-post:independent-evaluation-nonce-0001",
        pre_observation=result.pre_observation,
        post_observation=None,
        command=result.command,
        observer_key_id=result.pre_observation.observer_key_id,
        observer_public_key_b64=observer_public_key_b64,
        absolute_tolerance_mw=Decimal("0.000000001"),
        absolute_tolerance_pct=Decimal("0.000000001"),
    )
    with tempfile.TemporaryDirectory(prefix="aegis-ot-m4c-missing-post-") as temporary:
        directory = Path(temporary)
        request_path = directory / "request.json"
        fixture_path = directory / "fixture.json"
        report_path = directory / "report.json"
        request_path.write_bytes(canonical_json_bytes(request))
        fixture_path.write_bytes(FIXTURE_PATH.read_bytes())
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        completed = subprocess.run(  # noqa: S603 - fixed interpreter/module, test-owned paths
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
            timeout=30,
        )
        if completed.returncode != 1 or not report_path.is_file():
            raise RuntimeError("missing independent post did not produce indeterminate report")
        report = IndependentConsequenceReport.model_validate(
            strict_json_loads(report_path.read_bytes())
        )
    if (
        report.status is not IndependentEvaluationStatus.INDETERMINATE
        or report.reasons != ("post_observation_unavailable",)
        or not report.verify_for_request(request)
    ):
        raise RuntimeError("missing independent post failed authenticity or fail-closed status")
    return {
        "status": report.status.value,
        "reasons": list(report.reasons),
        "report_valid": True,
        "evaluator_process_separate": report.pid != os.getpid(),
    }


def _run_controller_condition(condition: str, index: int) -> dict[str, JsonValue]:
    reference_time = REFERENCE_TIME + timedelta(minutes=index)
    observer_source: Literal["plant", "predecessor"] = (
        "predecessor"
        if condition == "signed_post_observation_contradiction"
        else "plant"
    )
    with start_capability_separated_lab(
        reference_time,
        observer_post_snapshot_source=observer_source,
    ) as lab:
        lost_plc: _CommitThenLosePlcResponse | None = None
        tampered_observer: _TamperPostObservationAfterSigning | None = None
        if condition == "plc_response_lost_after_commit":
            lost_plc = _CommitThenLosePlcResponse(lab.controller.plc)
            lab.controller.plc = lost_plc
        elif condition == "post_observation_unavailable_after_commit":
            lab.controller.observer = _PostObservationUnavailable(lab.controller.observer)
        elif condition == "post_observation_tampered_after_signing":
            tampered_observer = _TamperPostObservationAfterSigning(lab.controller.observer)
            lab.controller.observer = tampered_observer
        elif condition != "nominal_control":
            if condition != "signed_post_observation_contradiction":
                raise ValueError(f"unsupported M4c controller condition: {condition}")

        observation = lab.capture_observation(
            correlation_id=f"m4c:{condition}:pre",
            challenge_nonce=f"m4c:{condition}:pre-challenge-0001",
        )
        proposal = _proposal(lab, observation, condition)
        result = lab.controller.execute(lab.request_for(proposal, observation))
        expected = _expected_status(condition)
        if result.status is not expected:
            raise RuntimeError(
                f"{condition} expected {expected.value}, observed {result.status.value}"
            )
        if result.dispatch_attempts != 1 or result.automatic_retry_count != 0:
            raise RuntimeError(f"{condition} violated the one-dispatch/no-retry contract")

        audit = lab.capture_observation(
            correlation_id=f"m4c:{condition}:audit",
            challenge_nonce=f"m4c:{condition}:audit-challenge-0001",
        )
        audit_valid = audit.verify(lab.processes.observer_info.public_key)
        effect_observed = audit.snapshot.isolated_resources == ("feeder-1",)
        if not audit_valid or not effect_observed:
            raise RuntimeError(f"{condition} did not retain a valid observed committed effect")
        if not lab.authorization.gateway.evidence.verify():
            raise RuntimeError(f"{condition} evidence chain is invalid")

        hidden_acknowledgment_valid = False
        if lost_plc is not None and lost_plc.acknowledgment is not None:
            hidden_acknowledgment_valid = bool(
                result.permit is not None
                and result.pre_observation is not None
                and result.decision is not None
                and lost_plc.acknowledgment.verify_for_transaction(
                    lab.processes.plc_info.public_key,
                    request=result.request,
                    permit=result.permit,
                    pre_observation=result.pre_observation,
                    expected_plc_id=lab.processes.plc_info.plc_id,
                    expected_plc_key_id=lab.processes.plc_info.key_id,
                    expected_plc_boot_epoch=lab.processes.plc_info.boot_epoch,
                )
            )
        original_tampered_observation_valid = bool(
            tampered_observer is not None
            and tampered_observer.original is not None
            and tampered_observer.original.verify(lab.processes.observer_info.public_key)
        )
        tampered_observation_rejected = bool(
            condition == "post_observation_tampered_after_signing"
            and tampered_observer is not None
            and tampered_observer.tampered is not None
            and not tampered_observer.tampered.verify(
                lab.processes.observer_info.public_key
            )
            and result.last_observation is not None
            and result.last_observation.verify(lab.processes.observer_info.public_key)
        )
        contradiction_evaluation: dict[str, JsonValue] | None = None
        missing_post_evaluation: dict[str, JsonValue] | None = None
        if condition == "signed_post_observation_contradiction":
            contradiction_evaluation = _evaluate_signed_contradiction(
                result,
                condition,
                public_key_base64(lab.processes.observer_info.public_key),
            )
        elif condition == "nominal_control":
            missing_post_evaluation = _evaluate_missing_independent_post(
                result,
                public_key_base64(lab.processes.observer_info.public_key),
            )
        return {
            "condition": condition,
            "expected_status": expected.value,
            "actual_status": result.status.value,
            "reasons": list(result.reasons),
            "dispatch_attempts": result.dispatch_attempts,
            "automatic_retry_count": result.automatic_retry_count,
            "acknowledgment_retained_by_controller": result.acknowledgment is not None,
            "post_observation_retained_by_controller": result.post_observation is not None,
            "effect_observed_by_followup_signed_capture": effect_observed,
            "followup_observation_signature_valid": audit_valid,
            "followup_state_version": audit.snapshot.state_version,
            "followup_isolated_resources": list(audit.snapshot.isolated_resources),
            "hidden_lost_response_acknowledgment_valid": hidden_acknowledgment_valid,
            "original_pre_tamper_observation_valid": original_tampered_observation_valid,
            "tampered_observation_rejected": tampered_observation_rejected,
            "independent_contradiction_evaluation": contradiction_evaluation,
            "independent_missing_post_evaluation": missing_post_evaluation,
            "evidence_chain_valid": True,
        }


def _run_evaluator_adversarial_checks() -> dict[str, JsonValue]:
    malformed = b'{"schema_version":"one","schema_version":"two"}'
    with tempfile.TemporaryDirectory(prefix="aegis-ot-m4c-evaluator-") as temporary:
        directory = Path(temporary)
        request_path = directory / "malformed-request.json"
        fixture_path = directory / "fixture.json"
        report_path = directory / "report.json"
        request_path.write_bytes(malformed)
        fixture_path.write_bytes(FIXTURE_PATH.read_bytes())
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        completed = subprocess.run(  # noqa: S603 - fixed interpreter/module, test-owned paths
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
            timeout=30,
        )
        if completed.returncode != 2 or not report_path.is_file():
            raise RuntimeError(
                "malformed evaluator input did not produce a retained input-rejected report"
            )
        report = strict_json_loads(report_path.read_bytes())
    if not isinstance(report, dict) or report.get("status") != "input_rejected":
        raise RuntimeError("malformed evaluator input did not fail closed")
    authentic_report_valid = verify_report(report)
    tampered = dict(report)
    tampered["reasons"] = ["tampered-after-signing"]
    tampered_report_valid = verify_report(tampered)
    if not authentic_report_valid or tampered_report_valid:
        raise RuntimeError("independent report authenticity check did not fail closed")
    return {
        "malformed_request_sha256": sha256_bytes(malformed),
        "evaluator_exit_code": 2,
        "signed_report_status": "input_rejected",
        "signed_report_valid": authentic_report_valid,
        "tampered_report_valid": tampered_report_valid,
        "evaluator_process_separate": report.get("pid") != os.getpid(),
    }


def _run_full_stack_restart_replay() -> dict[str, JsonValue]:
    with tempfile.TemporaryDirectory(prefix="aegis-ot-m4c-replay-") as temporary:
        replay_directory = Path(temporary) / "retained-ledger"
        replay_directory.mkdir(mode=0o700)
        first = start_capability_separated_lab(
            REFERENCE_TIME + timedelta(minutes=10),
            replay_directory=replay_directory,
        )
        first_closed = False
        try:
            observation = first.capture_observation(
                correlation_id="m4c:full-stack-replay:first",
                challenge_nonce="m4c:full-stack-replay:first-challenge-0001",
            )
            proposal = _proposal(first, observation, "full_stack_restart_replay")
            result = first.controller.execute(first.request_for(proposal, observation))
            if result.status is not CapabilityClosedLoopStatus.COMPLETED:
                raise RuntimeError("full-stack replay setup transaction did not complete")
            if any(
                item is None
                for item in (
                    result.permit,
                    result.pre_observation,
                    result.decision,
                    result.assessment,
                )
            ):
                raise RuntimeError("full-stack replay setup lost transaction artifacts")
            first_plc_boot = first.processes.plc_info.boot_epoch
            first_observer_boot = first.processes.observer_info.boot_epoch
            ledger_path = first.processes.replay_ledger_path
            if not ledger_path.is_file() or ledger_path.is_symlink():
                raise RuntimeError("full-stack replay ledger was not retained as a regular file")
            ledger_before = sha256_bytes(ledger_path.read_bytes())
            first.close()
            first_closed = True
            if not replay_directory.is_dir() or not ledger_path.is_file():
                raise RuntimeError("externally owned replay ledger was removed at stack shutdown")
        finally:
            if not first_closed:
                first.close()

        second = start_capability_separated_lab(
            REFERENCE_TIME + timedelta(minutes=11),
            replay_directory=replay_directory,
        )
        try:
            before = second.capture_observation(
                correlation_id="m4c:full-stack-replay:before",
                challenge_nonce="m4c:full-stack-replay:before-challenge-0001",
            )
            assert result.permit is not None
            assert result.pre_observation is not None
            assert result.decision is not None
            assert result.assessment is not None
            replay_acknowledgment = second.processes.plc_gateway.execute(
                request=result.request,
                permit=result.permit,
                pre_observation=result.pre_observation,
                decision=result.decision,
                assessment=result.assessment,
            )
            after = second.capture_observation(
                correlation_id="m4c:full-stack-replay:after",
                challenge_nonce="m4c:full-stack-replay:after-challenge-0001",
            )
            ledger_after = sha256_bytes(second.processes.replay_ledger_path.read_bytes())
            acknowledgment_valid = replay_acknowledgment.verify_for_transaction(
                second.processes.plc_info.public_key,
                request=result.request,
                permit=result.permit,
                pre_observation=result.pre_observation,
                expected_plc_id=second.processes.plc_info.plc_id,
                expected_plc_key_id=second.processes.plc_info.key_id,
                expected_plc_boot_epoch=second.processes.plc_info.boot_epoch,
            )
            state_unchanged = (
                before.snapshot.state_digest
                == after.snapshot.state_digest
                == replay_acknowledgment.pre_state_digest
            )
            criteria_met = all(
                (
                    replay_acknowledgment.status is CommandStatus.REJECTED,
                    replay_acknowledgment.dispatch_phase is DispatchPhase.PRE_DISPATCH,
                    replay_acknowledgment.reason == "transaction_replayed",
                    acknowledgment_valid,
                    state_unchanged,
                    ledger_before == ledger_after,
                    first_plc_boot != second.processes.plc_info.boot_epoch,
                    first_observer_boot != second.processes.observer_info.boot_epoch,
                )
            )
            if not criteria_met:
                raise RuntimeError("full-stack restart replay criteria were not met")
            return {
                "condition": "full_stack_restart_replay",
                "first_stack_closed": True,
                "plant_process_restarted": first.processes.plant_info.pid
                != second.processes.plant_info.pid,
                "observer_process_restarted": first.processes.observer_info.pid
                != second.processes.observer_info.pid,
                "plc_process_restarted": first.processes.plc_info.pid
                != second.processes.plc_info.pid,
                "plc_boot_epoch_changed": True,
                "observer_boot_epoch_changed": True,
                "ledger_retained_across_restart": True,
                "ledger_unchanged_by_replay": ledger_before == ledger_after,
                "replay_status": replay_acknowledgment.status.value,
                "replay_phase": replay_acknowledgment.dispatch_phase.value,
                "replay_reason": replay_acknowledgment.reason,
                "replay_acknowledgment_valid": acknowledgment_valid,
                "fresh_stack_state_unchanged": state_unchanged,
                "fresh_stack_isolated_resources": list(after.snapshot.isolated_resources),
                "criteria_met": criteria_met,
            }
        finally:
            second.close()


def _reserve_crash_probe(
    ledger: OrderlyRestartReplayReservations,
    suffix: str,
) -> None:
    ledger.reserve(
        request_digest=sha256_bytes(f"request:{suffix}".encode()),
        permit_id=f"permit-{suffix}",
        permit_nonce=f"permit-nonce-{suffix}",
        command_id=f"command-{suffix}",
    )


def _crash_replay_ledger_worker(
    path: str,
    phase: Literal["before_replace", "after_replace"],
) -> None:
    """Abruptly exit at one atomic-persistence boundary; called only by the campaign."""

    ledger = OrderlyRestartReplayReservations(Path(path))
    if phase == "before_replace":

        def exit_before_replace(_: object, __: object) -> NoReturn:
            os._exit(91)

        os.replace = exit_before_replace  # type: ignore[assignment]
    else:
        original_fsync = os.fsync
        fsync_calls = 0

        def exit_after_replace(descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                os._exit(92)
            original_fsync(descriptor)

        os.fsync = exit_after_replace  # type: ignore[assignment]
    _reserve_crash_probe(ledger, "new")
    os._exit(90)


def _join_crash_worker(process: Any, expected_exit: int) -> None:
    process.join(15)
    if process.is_alive():
        process.terminate()
        process.join(2)
        raise RuntimeError("replay-ledger crash worker did not terminate")
    if process.exitcode != expected_exit:
        raise RuntimeError(
            f"replay-ledger crash worker exited {process.exitcode}, expected {expected_exit}"
        )


def _run_replay_ledger_crash_checks() -> dict[str, JsonValue]:
    context = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="aegis-ot-m4c-ledger-crash-") as temporary:
        root = Path(temporary)

        before_directory = root / "before-replace"
        before_directory.mkdir(mode=0o700)
        before_path = before_directory / "ledger.json"
        with OrderlyRestartReplayReservations(
            before_path,
            initialize=True,
        ) as before_ledger:
            _reserve_crash_probe(before_ledger, "initial")
            before_digest = sha256_bytes(before_path.read_bytes())
        before_worker = context.Process(
            target=_crash_replay_ledger_worker,
            args=(str(before_path), "before_replace"),
        )
        before_worker.start()
        _join_crash_worker(before_worker, 91)
        with OrderlyRestartReplayReservations(before_path) as before_reloaded:
            before_old_preserved = before_reloaded.replay_reason(
                request_digest=sha256_bytes(b"request:initial"),
                permit_id="permit-initial",
                permit_nonce="permit-nonce-initial",
                command_id="command-initial",
            ) == "transaction_replayed"
            before_new_absent = before_reloaded.replay_reason(
                request_digest=sha256_bytes(b"request:new"),
                permit_id="permit-new",
                permit_nonce="permit-nonce-new",
                command_id="command-new",
            ) is None
            before_file_unchanged = (
                sha256_bytes(before_path.read_bytes()) == before_digest
            )

        after_directory = root / "after-replace"
        after_directory.mkdir(mode=0o700)
        after_path = after_directory / "ledger.json"
        with OrderlyRestartReplayReservations(
            after_path,
            initialize=True,
        ) as after_ledger:
            _reserve_crash_probe(after_ledger, "initial")
        after_worker = context.Process(
            target=_crash_replay_ledger_worker,
            args=(str(after_path), "after_replace"),
        )
        after_worker.start()
        _join_crash_worker(after_worker, 92)
        with OrderlyRestartReplayReservations(after_path) as after_reloaded:
            after_old_preserved = after_reloaded.replay_reason(
                request_digest=sha256_bytes(b"request:initial"),
                permit_id="permit-initial",
                permit_nonce="permit-nonce-initial",
                command_id="command-initial",
            ) == "transaction_replayed"
            after_new_present = after_reloaded.replay_reason(
                request_digest=sha256_bytes(b"request:new"),
                permit_id="permit-new",
                permit_nonce="permit-nonce-new",
                command_id="command-new",
            ) == "transaction_replayed"

        criteria_met = all(
            (
                before_old_preserved,
                before_new_absent,
                before_file_unchanged,
                after_old_preserved,
                after_new_present,
            )
        )
        if not criteria_met:
            raise RuntimeError("replay-ledger abrupt-exit consistency criteria were not met")
        return {
            "condition": "replay_ledger_abrupt_exit_consistency",
            "before_replace_exit_code": before_worker.exitcode,
            "before_replace_old_ledger_preserved": before_old_preserved,
            "before_replace_new_reservation_absent": before_new_absent,
            "before_replace_file_unchanged": before_file_unchanged,
            "after_replace_exit_code": after_worker.exitcode,
            "after_replace_old_reservation_preserved": after_old_preserved,
            "after_replace_new_reservation_present": after_new_present,
            "criteria_met": criteria_met,
        }


def _run_competing_prepared_transactions() -> dict[str, JsonValue]:
    with start_capability_separated_lab(
        REFERENCE_TIME + timedelta(minutes=20)
    ) as lab:
        common_observation = lab.capture_observation(
            correlation_id="m4c:competing:common",
            challenge_nonce="m4c:competing:common-challenge-0001",
        )
        prepared: list[
            tuple[
                CapabilityActionRequest,
                CapabilityExecutionPermit,
                SignedObservationEnvelope,
                Decision,
                CandidateAssessment,
            ]
        ] = []
        common_probe = _proposal(lab, common_observation, "competing_probe")
        common_request = lab.request_for(common_probe, common_observation)
        common_reasons = lab.controller.observation_verifier.verify_pre(
            common_observation,
            common_request,
            evaluated_at=lab.controller.clock(),
        )
        if common_reasons:
            raise RuntimeError(
                f"competing common pre-observation failed: {common_reasons}"
            )
        for ordinal in (1, 2):
            observation = common_observation
            condition = f"competing_prepared_{ordinal}"
            proposal = _proposal(lab, observation, condition)
            request = lab.request_for(proposal, observation)
            decision = lab.authorization.gateway.decide(
                proposal,
                physical_state_to_gateway_state(observation.snapshot),
                lab.controller.clock(),
            )
            if decision.outcome is not DecisionOutcome.PERMIT:
                raise RuntimeError(f"{condition} was not permitted")
            command = lab.controller.translator.translate(proposal)
            assessment = lab.processes.simulator.simulate_candidate(command)
            if (
                not assessment.safe
                or assessment.pre_state.state_digest != observation.snapshot.state_digest
            ):
                raise RuntimeError(f"{condition} candidate did not bind the common pre-state")
            permit = lab.controller.permit_issuer.issue(
                request=request,
                pre_observation=observation,
                decision=decision,
                command=command,
                assessment=assessment,
            )
            prepared.append((request, permit, observation, decision, assessment))

        first = lab.processes.plc_gateway.execute(
            request=prepared[0][0],
            permit=prepared[0][1],
            pre_observation=prepared[0][2],
            decision=prepared[0][3],
            assessment=prepared[0][4],
        )
        second = lab.processes.plc_gateway.execute(
            request=prepared[1][0],
            permit=prepared[1][1],
            pre_observation=prepared[1][2],
            decision=prepared[1][3],
            assessment=prepared[1][4],
        )
        after = lab.capture_observation(
            correlation_id="m4c:competing:after",
            challenge_nonce="m4c:competing:after-challenge-0001",
        )
        plc_health = lab.processes.plc_admin.health()
        first_valid = first.verify_for_transaction(
            lab.processes.plc_info.public_key,
            request=prepared[0][0],
            permit=prepared[0][1],
            pre_observation=prepared[0][2],
            expected_plc_id=lab.processes.plc_info.plc_id,
            expected_plc_key_id=lab.processes.plc_info.key_id,
            expected_plc_boot_epoch=lab.processes.plc_info.boot_epoch,
        )
        second_valid = second.verify_for_transaction(
            lab.processes.plc_info.public_key,
            request=prepared[1][0],
            permit=prepared[1][1],
            pre_observation=prepared[1][2],
            expected_plc_id=lab.processes.plc_info.plc_id,
            expected_plc_key_id=lab.processes.plc_info.key_id,
            expected_plc_boot_epoch=lab.processes.plc_info.boot_epoch,
        )
        stale_reasons = {
            "topology_digest_changed",
            "precommit_state_version_changed",
            "precommit_state_digest_changed",
            "precommit_observation_changed",
        }
        state_unchanged_by_second = (
            first.post_state_digest
            == second.pre_state_digest
            == after.snapshot.state_digest
        )
        criteria_met = all(
            (
                prepared[0][2].envelope_digest == prepared[1][2].envelope_digest,
                first.status is CommandStatus.APPLIED,
                first.dispatch_phase is DispatchPhase.COMMITTED,
                first_valid,
                second.status is CommandStatus.REJECTED,
                second.dispatch_phase is DispatchPhase.PRE_DISPATCH,
                second.reason in stale_reasons,
                second_valid,
                state_unchanged_by_second,
                after.snapshot.isolated_resources == ("feeder-1",),
                plc_health.get("execute_requests") == 2,
                plc_health.get("replay_reservations") == 1,
            )
        )
        if not criteria_met:
            raise RuntimeError("competing prepared transaction criteria were not met")
        return {
            "condition": "competing_prepared_transactions",
            "common_signed_pre_state": True,
            "first_status": first.status.value,
            "first_phase": first.dispatch_phase.value,
            "first_acknowledgment_valid": first_valid,
            "second_status": second.status.value,
            "second_phase": second.dispatch_phase.value,
            "second_reason": second.reason,
            "second_acknowledgment_valid": second_valid,
            "second_state_effect_absent": state_unchanged_by_second,
            "final_isolated_resources": list(after.snapshot.isolated_resources),
            "plc_execute_requests": plc_health.get("execute_requests"),
            "replay_reservation_count": plc_health.get("replay_reservations"),
            "criteria_met": criteria_met,
        }


def _git_value(*arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed git executable/arguments
        ["/usr/bin/git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def _git_state() -> dict[str, JsonValue]:
    commit = _git_value("rev-parse", "HEAD")
    branch = _git_value("branch", "--show-current")
    if branch == "" and len(commit) == 40:
        branch = "DETACHED"
    status = _git_value("status", "--porcelain")
    return {
        "branch": branch,
        "commit": commit,
        "working_tree_dirty": status not in {"", "unknown"},
    }


def run_fault_campaign(
    *,
    progress: Callable[[int, int], None] | None = None,
    require_clean_checkout: bool = True,
) -> dict[str, JsonValue]:
    """Run the bounded campaign and return a reproducible report."""

    started = datetime.now(UTC)
    git_start = _git_state()
    if require_clean_checkout and git_start["working_tree_dirty"] is not False:
        raise RuntimeError("controlled M4c fault campaign requires a clean checkout")
    cases: list[dict[str, JsonValue]] = []
    for index, condition in enumerate(CONDITION_ORDER):
        cases.append(_run_controller_condition(condition, index))
        if progress is not None:
            progress(index + 1, len(CONDITION_ORDER) + 3)
    restart_replay = _run_full_stack_restart_replay()
    if progress is not None:
        progress(len(CONDITION_ORDER) + 1, len(CONDITION_ORDER) + 3)
    replay_crash = _run_replay_ledger_crash_checks()
    if progress is not None:
        progress(len(CONDITION_ORDER) + 2, len(CONDITION_ORDER) + 3)
    competing = _run_competing_prepared_transactions()
    if progress is not None:
        progress(len(CONDITION_ORDER) + 3, len(CONDITION_ORDER) + 3)
    evaluator = _run_evaluator_adversarial_checks()
    git_end = _git_state()
    if git_start["commit"] != git_end["commit"]:
        raise RuntimeError("checkout commit changed during M4c fault campaign")
    if require_clean_checkout and git_end["working_tree_dirty"] is not False:
        raise RuntimeError("checkout became dirty during M4c fault campaign")

    projection: dict[str, JsonValue] = {
        "controller_cases": [
            {
                key: value
                for key, value in case.items()
                if key not in {"followup_state_version"}
            }
            for case in cases
        ],
        "evaluator": evaluator,
        "full_stack_restart_replay": restart_replay,
        "replay_ledger_crash_checks": replay_crash,
        "competing_prepared_transactions": competing,
    }
    missing_post = cases[0]["independent_missing_post_evaluation"]
    contradiction = cases[-1]["independent_contradiction_evaluation"]
    criteria_met = all(
        case["actual_status"] == case["expected_status"]
        and case["dispatch_attempts"] == 1
        and case["automatic_retry_count"] == 0
        and case["effect_observed_by_followup_signed_capture"] is True
        and case["evidence_chain_valid"] is True
        for case in cases
    ) and (
        isinstance(missing_post, dict)
        and missing_post.get("status") == "indeterminate"
        and missing_post.get("report_valid") is True
        and isinstance(contradiction, dict)
        and contradiction.get("status") == "contradict"
        and contradiction.get("report_valid") is True
    ) and restart_replay["criteria_met"] is True and (
        replay_crash["criteria_met"] is True
    ) and competing["criteria_met"] is True and all(
        (
            evaluator["signed_report_status"] == "input_rejected",
            evaluator["signed_report_valid"] is True,
            evaluator["tampered_report_valid"] is False,
            evaluator["evaluator_process_separate"] is True,
        )
    )
    return {
        "schema_version": "m4c-fault-campaign-v6",
        "started_at_utc": started.isoformat(),
        "completed_at_utc": datetime.now(UTC).isoformat(),
        "git": {
            "branch": git_start["branch"],
            "commit": git_start["commit"],
            "working_tree_dirty_at_start": git_start["working_tree_dirty"],
            "working_tree_dirty_at_end": git_end["working_tree_dirty"],
        },
        "controller_cases": cast(list[JsonValue], cases),
        "evaluator_adversarial_checks": evaluator,
        "full_stack_restart_replay": restart_replay,
        "replay_ledger_crash_checks": replay_crash,
        "competing_prepared_transactions": competing,
        "deterministic_projection_sha256": sha256_bytes(canonical_json_bytes(projection)),
        "experiment_criteria_met": criteria_met,
        "claim_boundary": (
            "same-host injected-port fault evidence over the deterministic local process lab; "
            "not fault-rate estimation, hostile-host isolation, segmented deployment, hardware, "
            "field evidence, or independent validation"
        ),
    }


def write_fault_campaign(
    output_path: Path,
    *,
    progress: Callable[[int, int], None] | None = None,
    require_clean_checkout: bool = True,
) -> dict[str, JsonValue]:
    """Run and exclusively retain one campaign report without overwriting evidence."""

    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError(f"refusing to overwrite M4c evidence: {output_path}")
    report = run_fault_campaign(
        progress=progress,
        require_clean_checkout=require_clean_checkout,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        material = json.dumps(report, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
        offset = 0
        while offset < len(material):
            offset += os.write(descriptor, material[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return report
