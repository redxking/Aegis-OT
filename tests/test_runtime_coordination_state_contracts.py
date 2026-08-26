from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_ot.coordination_anchor import (
    AnchoredRecoveryStatus,
    CoordinationAnchorAdmissionPhase,
)
from aegis_ot.coordination_journal import (
    CoordinationCollisionError,
    CoordinationJournalError,
)
from aegis_ot.segmented_capability_runtime import (
    CapabilityAdmissionRejected,
    CapabilityOtRuntime,
    CapabilityRuntimeUnavailable,
)
from aegis_ot.workload_identity import (
    WorkloadCredentialRejected,
    WorkloadIdentityUnavailable,
)

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)


class _AdmissionPort:
    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure

    def require_admission(self, **_: Any) -> Any:
        if self.failure is not None:
            raise self.failure
        return SimpleNamespace(
            status=AnchoredRecoveryStatus.RECOVERY_REQUIRED,
            admission_allowed=False,
        )


def _bare_runtime() -> CapabilityOtRuntime:
    return cast(CapabilityOtRuntime, object.__new__(CapabilityOtRuntime))


def test_anchor_guard_never_converts_missing_or_failed_authority_into_admission() -> None:
    runtime = _bare_runtime()
    runtime.coordination_anchor_required = False
    runtime.coordination_anchor_admission = None
    runtime._require_anchor_admission_locked(
        phase=CoordinationAnchorAdmissionPhase.PREPARE,
        effect_id="sha256:" + "1" * 64,
        request_sha256="2" * 64,
        evaluated_at=NOW,
    )

    runtime.coordination_anchor_required = True
    with pytest.raises(CapabilityRuntimeUnavailable, match="anchor_prepare_unavailable"):
        runtime._require_anchor_admission_locked(
            phase=CoordinationAnchorAdmissionPhase.PREPARE,
            effect_id="sha256:" + "1" * 64,
            request_sha256="2" * 64,
            evaluated_at=NOW,
        )

    runtime.coordination_anchor_admission = cast(
        Any,
        _AdmissionPort(failure=RuntimeError("authority unavailable")),
    )
    with pytest.raises(CapabilityRuntimeUnavailable, match="anchor_commit_unavailable"):
        runtime._require_anchor_admission_locked(
            phase=CoordinationAnchorAdmissionPhase.COMMIT,
            effect_id="sha256:" + "1" * 64,
            request_sha256="2" * 64,
            evaluated_at=NOW,
        )

    runtime.coordination_anchor_admission = cast(Any, _AdmissionPort())
    with pytest.raises(CapabilityRuntimeUnavailable, match="anchor_prepare_unavailable"):
        runtime._require_anchor_admission_locked(
            phase=CoordinationAnchorAdmissionPhase.PREPARE,
            effect_id="sha256:" + "1" * 64,
            request_sha256="2" * 64,
            evaluated_at=NOW,
        )


def test_coordination_configuration_and_journal_failures_keep_stable_dispositions() -> None:
    runtime = _bare_runtime()
    runtime.coordination_journal = None
    runtime._plant_health_loader = None
    with pytest.raises(CapabilityRuntimeUnavailable, match="recovery_unavailable"):
        runtime._refresh_coordination_recovery_locked()

    runtime._coordination_recovery = None
    runtime._coordination_recovery_plant = None
    with pytest.raises(CapabilityRuntimeUnavailable, match="recovery_unavailable"):
        runtime._coordination_recovery_projection_locked()

    runtime.coordination_required = False
    with pytest.raises(CapabilityAdmissionRejected, match="coordination_is_disabled"):
        runtime._coordination_context(evaluated_at=NOW)

    runtime.coordination_required = True
    runtime.gateway_workload_identity = None
    runtime.local_workload_identity = None
    with pytest.raises(CapabilityRuntimeUnavailable, match="coordination_is_unconfigured"):
        runtime._coordination_context(evaluated_at=NOW)

    with pytest.raises(CapabilityAdmissionRejected, match="coordination_state_rejected"):
        runtime._raise_coordination_journal_failure(
            CoordinationCollisionError("conflicting durable state")
        )
    with pytest.raises(CapabilityRuntimeUnavailable, match="journal_unavailable"):
        runtime._raise_coordination_journal_failure(
            CoordinationJournalError("journal unavailable")
        )


@pytest.mark.parametrize(
    ("failure", "error", "reason"),
    (
        (
            WorkloadCredentialRejected("credential rejected"),
            CapabilityAdmissionRejected,
            "workload_identity_rejected",
        ),
        (
            WorkloadIdentityUnavailable("trust unavailable"),
            CapabilityRuntimeUnavailable,
            "workload_trust_unavailable",
        ),
    ),
)
def test_coordination_identity_failure_keeps_rejection_distinct_from_unavailability(
    failure: Exception,
    error: type[Exception],
    reason: str,
) -> None:
    class _Binding:
        def resolve(self, **_: Any) -> Any:
            raise failure

    runtime = _bare_runtime()
    runtime.coordination_required = True
    runtime.gateway_workload_identity = cast(Any, _Binding())
    runtime.local_workload_identity = cast(Any, object())
    runtime.coordination_journal = cast(Any, object())

    with pytest.raises(error, match=reason):
        runtime._coordination_context(evaluated_at=NOW)


def _constructor_arguments() -> dict[str, Any]:
    return {
        "device": object(),
        "transport_replay": object(),
        "gateway_public_key": Ed25519PrivateKey.generate().public_key(),
        "gateway_key_id": "gateway-key",
        "observer_info": object(),
        "permit_public_key": Ed25519PrivateKey.generate().public_key(),
        "permit_key_id": "permit-key",
        "private_key": Ed25519PrivateKey.generate(),
        "key_id": "ot-key",
        "plc_id": "plc",
        "boot_epoch": "boot",
        "plant_info": object(),
        "semantic_replay": object(),
    }


def test_ot_runtime_constructor_rejects_partial_coordination_authority() -> None:
    common = _constructor_arguments()
    with pytest.raises(ValueError, match="identities must be configured together"):
        CapabilityOtRuntime(
            **common,
            gateway_workload_identity=cast(Any, object()),
        )

    with pytest.raises(ValueError, match="terminal hook require effect coordination"):
        CapabilityOtRuntime(
            **common,
            coordination_journal=cast(Any, object()),
        )

    with pytest.raises(ValueError, match="exactly one anchor admission port"):
        CapabilityOtRuntime(
            **common,
            gateway_workload_identity=cast(Any, object()),
            local_workload_identity=cast(Any, object()),
            coordination_required=True,
            coordination_journal=cast(Any, object()),
            plant_health_loader=lambda: cast(Any, object()),
            coordination_anchor_required=True,
        )
