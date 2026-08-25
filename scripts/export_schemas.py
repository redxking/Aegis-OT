"""Generate or verify committed schemas from authoritative Pydantic models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from aegis_ot.capability_ipc import IpcRequestFrame, IpcResponseFrame
from aegis_ot.capability_models import (
    CapabilityActionRequest,
    CapabilityClosedLoopResult,
    CapabilityExecutionPermit,
    PlcCommandAcknowledgment,
    SignedObservationEnvelope,
)
from aegis_ot.m4b_models import (
    IndependentConsequenceReport,
    IndependentEvaluationRequest,
    M4bArtifactDescriptor,
    M4bCapabilityProbeBundle,
    M4bComponentRegistration,
    M4bEvidenceManifest,
    M4bManifestSignature,
    M4bOrderlyRestartReplayRecord,
    M4bTransactionRecord,
    M4bTrustAnchor,
)
from aegis_ot.modbus_wire import SignedWireResponse, WireRequest
from aegis_ot.physical_models import (
    CandidateAssessment,
    ClosedLoopResult,
    CommandAcknowledgment,
    ExecutionPermit,
    PhysicalControlCommand,
    PhysicalStateSnapshot,
)
from aegis_ot.schema import action_proposal_schema
from aegis_ot.segmented_capability_models import (
    SegmentedCapabilityClosedLoopResult,
    SegmentedCapabilityDispatch,
    SignedSegmentedCapabilityDispatch,
    SignedSegmentedCapabilityResponse,
    WorkloadAuthenticatedCapabilityAction,
    WorkloadSignedCapabilityDispatch,
    WorkloadSignedCapabilityResponse,
)
from aegis_ot.workload_identity import (
    SignedWorkloadCredential,
    WorkloadCredential,
    WorkloadTrustBundle,
)

ROOT = Path(__file__).resolve().parents[1]
ACTION_PROPOSAL_PATH = ROOT / "schemas" / "action-proposal.schema.json"
MODEL_SCHEMAS: dict[Path, type[BaseModel]] = {
    ROOT / "schemas" / "m4g-capability-dispatch.schema.json": (
        SegmentedCapabilityDispatch
    ),
    ROOT / "schemas" / "m4g-segmented-capability-result.schema.json": (
        SegmentedCapabilityClosedLoopResult
    ),
    ROOT / "schemas" / "m4g-signed-capability-dispatch.schema.json": (
        SignedSegmentedCapabilityDispatch
    ),
    ROOT / "schemas" / "m4g-signed-capability-response.schema.json": (
        SignedSegmentedCapabilityResponse
    ),
    ROOT / "schemas" / "m4g-workload-capability-action.schema.json": (
        WorkloadAuthenticatedCapabilityAction
    ),
    ROOT / "schemas" / "m4g-workload-credential-claims.schema.json": WorkloadCredential,
    ROOT / "schemas" / "m4g-workload-credential.schema.json": SignedWorkloadCredential,
    ROOT / "schemas" / "m4g-workload-capability-dispatch.schema.json": (
        WorkloadSignedCapabilityDispatch
    ),
    ROOT / "schemas" / "m4g-workload-capability-response.schema.json": (
        WorkloadSignedCapabilityResponse
    ),
    ROOT / "schemas" / "m4g-workload-trust-bundle.schema.json": WorkloadTrustBundle,
    ROOT / "schemas" / "m4b-artifact-descriptor.schema.json": M4bArtifactDescriptor,
    ROOT / "schemas" / "m4b-capability-probe-bundle.schema.json": M4bCapabilityProbeBundle,
    ROOT / "schemas" / "m4b-component-registration.schema.json": M4bComponentRegistration,
    ROOT / "schemas" / "m4b-evidence-manifest.schema.json": M4bEvidenceManifest,
    ROOT / "schemas" / "m4b-independent-consequence-report.schema.json": (
        IndependentConsequenceReport
    ),
    ROOT / "schemas" / "m4b-independent-evaluation-request.schema.json": (
        IndependentEvaluationRequest
    ),
    ROOT / "schemas" / "m4b-manifest-signature.schema.json": M4bManifestSignature,
    ROOT / "schemas" / "m4b-orderly-restart-replay.schema.json": (
        M4bOrderlyRestartReplayRecord
    ),
    ROOT / "schemas" / "m4b-transaction-record.schema.json": M4bTransactionRecord,
    ROOT / "schemas" / "m4b-trust-anchor.schema.json": M4bTrustAnchor,
    ROOT / "schemas" / "m4a-action-request.schema.json": CapabilityActionRequest,
    ROOT / "schemas" / "m4a-closed-loop-result.schema.json": CapabilityClosedLoopResult,
    ROOT / "schemas" / "m4a-execution-permit.schema.json": CapabilityExecutionPermit,
    ROOT / "schemas" / "m4a-ipc-request.schema.json": IpcRequestFrame,
    ROOT / "schemas" / "m4a-ipc-response.schema.json": IpcResponseFrame,
    ROOT / "schemas" / "m4a-plc-acknowledgment.schema.json": PlcCommandAcknowledgment,
    ROOT / "schemas" / "m4a-signed-observation.schema.json": SignedObservationEnvelope,
    ROOT / "schemas" / "m3-candidate-assessment.schema.json": CandidateAssessment,
    ROOT / "schemas" / "m3-closed-loop-result.schema.json": ClosedLoopResult,
    ROOT / "schemas" / "m3-command-acknowledgment.schema.json": CommandAcknowledgment,
    ROOT / "schemas" / "m3-execution-permit.schema.json": ExecutionPermit,
    ROOT / "schemas" / "m3-modbus-wire-request.schema.json": WireRequest,
    ROOT / "schemas" / "m3-modbus-wire-response.schema.json": SignedWireResponse,
    ROOT / "schemas" / "m3-physical-command.schema.json": PhysicalControlCommand,
    ROOT / "schemas" / "m3-physical-state.schema.json": PhysicalStateSnapshot,
}


def rendered_schemas() -> dict[Path, str]:
    schemas: dict[Path, dict[str, Any]] = {ACTION_PROPOSAL_PATH: action_proposal_schema()}
    schemas.update({path: model.model_json_schema() for path, model in MODEL_SCHEMAS.items()})
    return {
        path: json.dumps(schema, indent=2, sort_keys=True) + "\n"
        for path, schema in schemas.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed schema differs from the authoritative model",
    )
    args = parser.parse_args()
    rendered = rendered_schemas()
    if args.check:
        stale = [
            str(path.relative_to(ROOT))
            for path, expected in rendered.items()
            if not path.is_file() or path.read_text(encoding="utf-8") != expected
        ]
        if stale:
            raise SystemExit(f"committed schemas are stale: {', '.join(stale)}")
        return
    for path, material in rendered.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(material, encoding="utf-8")


if __name__ == "__main__":
    main()
