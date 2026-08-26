from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis_ot.m5_degraded import (
    DegradedAdmissionOutcome,
    DegradedModeAuthorization,
    DegradedModeReversal,
    DegradedOperationGate,
    DegradedRole,
    FileDegradedAuthorizationSource,
    FileDegradedOperationStateStore,
    FileDegradedSnapshotSource,
    RoleCondition,
)
from aegis_ot.models import ActionProposal, Operation

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_m5_degraded_artifacts.py"
NOW = datetime(2026, 8, 26, 14, 0, tzinfo=UTC)


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("prepare_m5_degraded_artifacts", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _binding(module: ModuleType, *, commit: str = "b" * 40) -> dict[str, object]:
    files = [
        {
            "path": path,
            "size_bytes": 1,
            "sha256": "1" * 64,
            "git_mode": "100644",
            "git_blob": "a" * 40,
        }
        for path in module.SOURCE_PATHS
    ]
    material = {"git_commit": commit, "git_tree": "c" * 40, "source_files": files}
    fingerprint = hashlib.sha256(module._canonical_bytes(material)).hexdigest()
    return {
        **material,
        "clean_checkout": True,
        "source_fingerprint_sha256": fingerprint,
    }


@pytest.fixture
def generator(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = _load_generator()
    source_binding = _binding(module)
    monkeypatch.setattr(module, "_assert_clean_source", lambda _reference: source_binding)
    return module


def _proposal() -> ActionProposal:
    return ActionProposal(
        proposal_id="m5-admin-artifact-proposal",
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        parameters={"critical_load_impact_pct": 5.0},
        observed_state_version=1,
        observed_at=NOW,
        submitted_at=NOW,
        nonce="m5-admin-artifact-nonce",
        confidence=0.9,
        risk_score=60.0,
        delegation_chain=("grant-root", "grant-leaf"),
    )


def _create_authority_and_bundle(
    module: ModuleType,
    root: Path,
    *,
    role: DegradedRole = DegradedRole.MANAGEMENT,
) -> tuple[Path, Path]:
    authority = root / "authority"
    bundle = root / "runtime"
    module.create_authority(
        authority,
        authority_id="m5-degraded-authority",
    )
    module.create_runtime_bundle(
        bundle,
        authority_directory=authority,
        role=role,
        surface="service",
        condition=RoleCondition.UNAVAILABLE,
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        maximum_risk_score=65.0,
        lease_seconds=300,
        now=NOW,
    )
    return authority, bundle


def test_runtime_bundle_is_source_bound_private_and_fails_closed_when_stale(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    authority, bundle = _create_authority_and_bundle(generator, tmp_path)

    assert {path.name for path in authority.iterdir()} == generator.AUTHORITY_FILES
    assert {path.name for path in bundle.iterdir()} == generator.BUNDLE_FILES
    assert generator.AUTHORITY_PRIVATE_NAME not in generator.BUNDLE_FILES
    assert generator.REVERSAL_NAME not in generator.BUNDLE_FILES
    assert stat.S_IMODE(authority.stat().st_mode) == 0o700
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in bundle.iterdir())

    report = generator.verify_runtime_bundle(bundle)
    assert report["valid"]
    assert report["single_generation_artifact"]
    assert not report["continuous_refresh_provided"]
    manifest = json.loads((bundle / generator.MANIFEST_NAME).read_text())
    assert manifest["snapshot_freshness_contract"] == {
        "maximum_age_seconds": 5,
        "single_generation_artifact": True,
        "continuous_refresh_provided": False,
        "stale_snapshot_fails_closed": True,
        "external_trusted_monitor_required": True,
        "operator_assertion_is_not_compromise_detection": True,
    }

    public_key = Ed25519PublicKey.from_public_bytes(
        (bundle / generator.AUTHORITY_PUBLIC_NAME).read_bytes()
    )
    gate = DegradedOperationGate(
        authority_id="m5-degraded-authority",
        authority_public_key=public_key,
        snapshot_source=FileDegradedSnapshotSource(bundle / generator.SNAPSHOT_NAME),
        authorization_source=FileDegradedAuthorizationSource(
            bundle / generator.AUTHORIZATION_NAME
        ),
        state_store=FileDegradedOperationStateStore(
            bundle / generator.STATE_NAME,
            authority_id="m5-degraded-authority",
        ),
    )
    admitted = gate.evaluate(_proposal(), now=NOW)
    assert admitted.outcome is DegradedAdmissionOutcome.CONTINUE_PRIMARY_ASSURANCE
    assert admitted.may_enter_primary_assurance
    assert not admitted.execution_authorized

    stale = gate.evaluate(_proposal(), now=NOW + timedelta(seconds=6))
    assert stale.outcome is DegradedAdmissionOutcome.SAFE_STATE
    assert "degraded_snapshot_stale" in stale.reasons
    assert not stale.execution_authorized


def test_non_management_loss_never_enters_primary_assurance(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    _, bundle = _create_authority_and_bundle(
        generator,
        tmp_path,
        role=DegradedRole.OBSERVER,
    )
    public_key = Ed25519PublicKey.from_public_bytes(
        (bundle / generator.AUTHORITY_PUBLIC_NAME).read_bytes()
    )
    gate = DegradedOperationGate(
        authority_id="m5-degraded-authority",
        authority_public_key=public_key,
        snapshot_source=FileDegradedSnapshotSource(bundle / generator.SNAPSHOT_NAME),
        authorization_source=FileDegradedAuthorizationSource(
            bundle / generator.AUTHORIZATION_NAME
        ),
    )

    result = gate.evaluate(_proposal(), now=NOW)

    assert result.outcome is DegradedAdmissionOutcome.HOLD_STATE
    assert not result.may_enter_primary_assurance
    assert not result.execution_authorized


def test_reversal_is_a_separate_operator_package_and_applies_to_exact_lease(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    authority, bundle = _create_authority_and_bundle(generator, tmp_path)
    reversal_package = tmp_path / "reversal"
    report = generator.create_reversal_package(
        reversal_package,
        authority_directory=authority,
        runtime_bundle=bundle,
        now=NOW,
    )

    assert report["valid"]
    assert report["operator_application_required"]
    assert {path.name for path in reversal_package.iterdir()} == {
        generator.REVERSAL_NAME,
        generator.MANIFEST_NAME,
    }
    assert generator.REVERSAL_NAME not in {path.name for path in bundle.iterdir()}
    assert generator.AUTHORITY_PRIVATE_NAME not in {
        path.name for path in reversal_package.iterdir()
    }

    authorization = DegradedModeAuthorization.model_validate_json(
        (bundle / generator.AUTHORIZATION_NAME).read_text()
    )
    reversal = DegradedModeReversal.model_validate_json(
        (reversal_package / generator.REVERSAL_NAME).read_text()
    )
    public_key = Ed25519PublicKey.from_public_bytes(
        (bundle / generator.AUTHORITY_PUBLIC_NAME).read_bytes()
    )
    gate = DegradedOperationGate(
        authority_id="m5-degraded-authority",
        authority_public_key=public_key,
        snapshot_source=FileDegradedSnapshotSource(bundle / generator.SNAPSHOT_NAME),
        authorization_source=FileDegradedAuthorizationSource(
            bundle / generator.AUTHORIZATION_NAME
        ),
    )
    gate.evaluate(_proposal(), now=NOW)

    applied = gate.apply_reversal(reversal, authorization, now=NOW)

    assert applied.applied
    assert applied.reasons == ("degraded_authorization_revoked",)
    after = gate.evaluate(_proposal(), now=NOW)
    assert not after.may_enter_primary_assurance
    assert not after.execution_authorized


def test_generation_rejects_unbounded_or_overwritten_inputs_and_tampering(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    authority, bundle = _create_authority_and_bundle(generator, tmp_path)
    with pytest.raises(generator.M5ArtifactError, match="overwrite"):
        generator.create_authority(authority, authority_id="m5-degraded-authority")
    with pytest.raises(generator.M5ArtifactError, match="between 1 and 300"):
        generator.create_runtime_bundle(
            tmp_path / "too-long",
            authority_directory=authority,
            role=DegradedRole.MANAGEMENT,
            surface="service",
            condition=RoleCondition.UNAVAILABLE,
            actor_id="agent:operator-1",
            mission_id="microgrid-containment",
            resource="feeder-1",
            operation=Operation.ISOLATE_ASSET,
            maximum_risk_score=65.0,
            lease_seconds=301,
            now=NOW,
        )

    manifest_path = bundle / generator.MANIFEST_NAME
    manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
    with pytest.raises(generator.M5ArtifactError, match="canonical JSON"):
        generator.verify_runtime_bundle(bundle)


def test_cli_exposes_immutable_generation_and_does_not_repurpose_home(
    generator: ModuleType,
) -> None:
    parser = generator._parser()
    assert parser.parse_args(
        ["verify", "--bundle", "/opt/aegis/m5-runtime"]
    ).command == "verify"
    assert parser.parse_args(
        [
            "verify-reversal",
            "--package",
            "/opt/aegis/m5-reversal",
            "--runtime-bundle",
            "/opt/aegis/m5-runtime",
        ]
    ).command == "verify-reversal"
    assert "HOME" not in generator._git_environment()
    assert generator.MAX_LEASE_SECONDS == 300
    assert generator.MAX_SNAPSHOT_AGE_SECONDS == 5
