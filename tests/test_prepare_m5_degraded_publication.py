from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis_ot.m5_degraded import (
    DegradedBehavior,
    DegradedModeReversal,
    DegradedRole,
    RoleCondition,
)
from aegis_ot.m5_degraded_publication import (
    AtomicDegradedPublicationSink,
    DegradedPublicationPublisher,
    DegradedPublisherCredential,
    DegradedStatusInput,
    FileDegradedPublisherStateStore,
    FileDegradedStatusSource,
    FileStableDegradedAuthorizationSource,
    StableDegradedAuthorization,
    load_publisher_credential,
)
from aegis_ot.models import Operation

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_m5_degraded_publication.py"
NOW = datetime(2026, 8, 26, 14, 0, tzinfo=UTC)


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "prepare_m5_degraded_publication",
        SCRIPT,
    )
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
    monkeypatch.setattr(
        module,
        "_assert_clean_source",
        lambda _reference: source_binding,
    )
    return module


def _create_authority(
    module: ModuleType,
    root: Path,
    *,
    name: str = "authority",
    role: DegradedRole = DegradedRole.MANAGEMENT,
    surface: str = "service",
) -> Path:
    authority = root / name
    module.create_authority_package(
        authority,
        authority_id=f"m5-degraded-{name}",
        publisher_id=f"m5-health-publisher-{name}",
        health_source_id=f"m5-lab-health-{name}",
        role=role,
        surface=surface,
        condition=RoleCondition.UNAVAILABLE,
        actor_id="agent:operator-1",
        mission_id="microgrid-containment",
        resource="feeder-1",
        operation=Operation.ISOLATE_ASSET,
        maximum_risk_score=65.0,
        credential_seconds=600,
        authorization_seconds=300,
        maximum_publication_age_seconds=5,
        now=NOW,
    )
    return authority


def _load_models(
    module: ModuleType,
    package: Path,
) -> tuple[
    DegradedPublisherCredential,
    StableDegradedAuthorization,
    DegradedStatusInput,
]:
    credential = DegradedPublisherCredential.model_validate_json(
        (package / module.PUBLISHER_CREDENTIAL_NAME).read_bytes()
    )
    authorization = StableDegradedAuthorization.model_validate_json(
        (package / module.STABLE_AUTHORIZATION_NAME).read_bytes()
    )
    status_input = DegradedStatusInput.model_validate_json(
        (package / module.STATUS_INPUT_NAME).read_bytes()
    )
    return credential, authorization, status_input


def test_authority_creates_distinct_signed_root_and_leaf_material(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    source_report = generator.source_binding_report()
    assert source_report["schema_version"] == "aegis-ot-m5-degraded-source-binding-v1"
    assert source_report["execution_authorized"] is False
    authority = _create_authority(generator, tmp_path)

    assert {path.name for path in authority.iterdir()} == generator.AUTHORITY_FILES
    assert stat.S_IMODE(authority.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in authority.iterdir())

    root_private = Ed25519PrivateKey.from_private_bytes(
        (authority / generator.ROOT_PRIVATE_NAME).read_bytes()
    )
    publisher_private = Ed25519PrivateKey.from_private_bytes(
        (authority / generator.PUBLISHER_PRIVATE_NAME).read_bytes()
    )
    credential, authorization, status_input = _load_models(generator, authority)
    root_public = root_private.public_key()

    assert root_public.public_bytes_raw() != publisher_private.public_key().public_bytes_raw()
    assert publisher_private.public_key().public_bytes_raw() == (
        credential.publisher_public_key.public_bytes_raw()
    )
    assert credential.verify(root_public)
    assert authorization.verify(root_public)
    assert authorization.publisher_credential_sha256 == credential.digest
    assert authorization.publisher_key_id == credential.publisher_key_id
    assert authorization.expires_at - authorization.issued_at == timedelta(seconds=300)
    assert dict(status_input.role_conditions) == dict(authorization.role_conditions)
    assert dict(status_input.communication_conditions) == dict(
        authorization.communication_conditions
    )
    assert status_input.source_id == credential.health_source_id
    assert status_input.operator_asserted_not_detected
    assert set(status_input.role_conditions) == set(DegradedRole)
    assert set(status_input.communication_conditions) == set(DegradedRole)
    assert "captured_at" not in status_input.model_dump(mode="json")
    assert "snapshot_id" not in status_input.model_dump(mode="json")

    report = generator.verify_authority_package(authority)
    assert report["valid"]
    assert report["root_and_publisher_keys_distinct"]
    assert not report["execution_authorized"]


def test_runtime_and_publisher_packages_enforce_distribution_boundaries(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    authority = _create_authority(generator, tmp_path)
    runtime = tmp_path / "runtime"
    publisher = tmp_path / "publisher"

    runtime_report = generator.create_runtime_package(
        runtime,
        authority_directory=authority,
    )
    publisher_report = generator.create_publisher_package(
        publisher,
        authority_directory=authority,
    )

    assert {path.name for path in runtime.iterdir()} == generator.RUNTIME_FILES
    assert {path.name for path in publisher.iterdir()} == generator.PUBLISHER_FILES
    assert not {generator.ROOT_PRIVATE_NAME, generator.PUBLISHER_PRIVATE_NAME} & {
        path.name for path in runtime.iterdir()
    }
    assert {path.name for path in publisher.iterdir() if path.name.endswith(".private")} == {
        generator.PUBLISHER_PRIVATE_NAME
    }
    assert generator.ROOT_PRIVATE_NAME not in {path.name for path in publisher.iterdir()}
    assert generator.STATUS_INPUT_NAME not in {path.name for path in runtime.iterdir()}
    assert all("state" not in path.name for path in (*runtime.iterdir(), *publisher.iterdir()))
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in runtime.iterdir())
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in publisher.iterdir())
    for name in (
        generator.ROOT_PUBLIC_NAME,
        generator.PUBLISHER_CREDENTIAL_NAME,
        generator.STABLE_AUTHORIZATION_NAME,
    ):
        assert (runtime / name).read_bytes() == (publisher / name).read_bytes()
    assert (authority / generator.STATUS_INPUT_NAME).read_bytes() == (
        publisher / generator.STATUS_INPUT_NAME
    ).read_bytes()

    assert runtime_report["valid"]
    assert not runtime_report["private_key_material_included"]
    assert not runtime_report["mutable_state_included"]
    assert publisher_report["valid"]
    assert not publisher_report["root_private_key_included"]
    assert publisher_report["publisher_private_key_included"]
    assert not publisher_report["mutable_state_included"]


def test_publisher_package_drives_fresh_chained_core_publications(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    authority = _create_authority(generator, tmp_path)
    publisher_package = tmp_path / "publisher"
    generator.create_publisher_package(
        publisher_package,
        authority_directory=authority,
    )

    credential = load_publisher_credential(publisher_package / generator.PUBLISHER_CREDENTIAL_NAME)
    root_public = Ed25519PublicKey.from_public_bytes(
        (publisher_package / generator.ROOT_PUBLIC_NAME).read_bytes()
    )
    publisher_private = Ed25519PrivateKey.from_private_bytes(
        (publisher_package / generator.PUBLISHER_PRIVATE_NAME).read_bytes()
    )
    status_input = FileDegradedStatusSource(publisher_package / generator.STATUS_INPUT_NAME)()
    output_directory = tmp_path / "publication-output"
    state_directory = tmp_path / "publisher-state"
    output_directory.mkdir(mode=0o700)
    state_directory.mkdir(mode=0o700)
    output_directory.chmod(0o700)
    state_directory.chmod(0o700)
    output_path = output_directory / "publication.json"
    state_path = state_directory / "publisher-state.json"
    FileDegradedPublisherStateStore.initialize(state_path, credential=credential)
    times = iter((NOW + timedelta(seconds=1), NOW + timedelta(seconds=2)))
    publisher = DegradedPublicationPublisher(
        authority_public_key=root_public,
        credential=credential,
        publisher_private_key=publisher_private,
        status_source=FileDegradedStatusSource(publisher_package / generator.STATUS_INPUT_NAME),
        authorization_source=FileStableDegradedAuthorizationSource(
            publisher_package / generator.STABLE_AUTHORIZATION_NAME
        ),
        sink=AtomicDegradedPublicationSink(output_path),
        state_store=FileDegradedPublisherStateStore(state_path),
        clock=lambda: next(times),
    )

    first = publisher.publish_once()
    second = publisher.publish_once()

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_publication_sha256 == first.digest
    assert first.snapshot.snapshot_id != second.snapshot.snapshot_id
    assert first.snapshot.captured_at == NOW
    assert second.snapshot.captured_at == NOW
    assert first.published_at == NOW + timedelta(seconds=1)
    assert second.published_at == NOW + timedelta(seconds=2)
    assert first.expires_at - first.published_at == timedelta(seconds=5)
    assert second.expires_at - second.published_at == timedelta(seconds=5)
    assert first.status_input_sha256 == status_input.digest
    assert second.status_input_sha256 == status_input.digest
    assert first.verify(credential.publisher_public_key)
    assert second.verify(credential.publisher_public_key)
    assert output_path.read_bytes().endswith(b"\n")
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600


def test_reversal_is_exact_keyless_and_valid_after_authorization_expiry(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    authority = _create_authority(generator, tmp_path)
    runtime = tmp_path / "runtime"
    reversal_package = tmp_path / "reversal"
    generator.create_runtime_package(runtime, authority_directory=authority)

    report = generator.create_reversal_package(
        reversal_package,
        authority_directory=authority,
        runtime_package=runtime,
        sequence=7,
        now=NOW + timedelta(seconds=301),
    )

    assert {path.name for path in reversal_package.iterdir()} == generator.REVERSAL_FILES
    assert all("private" not in path.name for path in reversal_package.iterdir())
    reversal = DegradedModeReversal.model_validate_json(
        (reversal_package / generator.REVERSAL_NAME).read_bytes()
    )
    _, authorization, _ = _load_models(generator, authority)
    assert reversal.issued_at > authorization.expires_at
    assert reversal.authorization_id == authorization.authorization_id
    assert reversal.authorization_sha256 == authorization.digest
    assert reversal.recovery_checkpoint_id == authorization.recovery_checkpoint_id
    assert report["valid"]
    assert report["operator_application_required"]
    assert not report["root_private_key_included"]
    assert not report["publisher_private_key_included"]
    assert not report["mutable_state_included"]

    other_authority = _create_authority(generator, tmp_path, name="other-authority")
    other_runtime = tmp_path / "other-runtime"
    generator.create_runtime_package(
        other_runtime,
        authority_directory=other_authority,
    )
    with pytest.raises(generator.PublicationArtifactError, match="exact stable authorization"):
        generator.verify_reversal_package(
            reversal_package,
            runtime_package=other_runtime,
        )


def test_healthy_status_is_generated_from_public_runtime_trust(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    authority = _create_authority(generator, tmp_path)
    runtime = tmp_path / "runtime"
    generator.create_runtime_package(runtime, authority_directory=authority)
    healthy_package = tmp_path / "healthy-status"

    report = generator.create_healthy_status_package(
        healthy_package,
        runtime_package=runtime,
        sequence=2,
        valid_seconds=30,
        now=NOW + timedelta(seconds=1),
    )
    verified = generator.verify_healthy_status_package(
        healthy_package,
        runtime_package=runtime,
    )
    status_input = DegradedStatusInput.model_validate_json(
        (healthy_package / generator.STATUS_INPUT_NAME).read_bytes()
    )

    assert report == verified
    assert {path.name for path in healthy_package.iterdir()} == generator.HEALTHY_STATUS_FILES
    assert status_input.sequence == 2
    assert status_input.observed_at == NOW + timedelta(seconds=1)
    assert status_input.expires_at == NOW + timedelta(seconds=31)
    assert set(status_input.role_conditions.values()) == {RoleCondition.HEALTHY}
    assert set(status_input.communication_conditions.values()) == {RoleCondition.HEALTHY}
    assert not status_input.unresolved_effect
    assert report["private_key_material_included"] is False
    assert report["execution_authorized"] is False

    with pytest.raises(generator.PublicationArtifactError, match="at least two"):
        generator.create_healthy_status_package(
            tmp_path / "invalid-healthy-status",
            runtime_package=runtime,
            sequence=1,
            valid_seconds=30,
            now=NOW + timedelta(seconds=1),
        )


def test_generation_is_no_overwrite_source_bound_and_tamper_evident(
    generator: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority = _create_authority(generator, tmp_path)
    runtime = tmp_path / "runtime"
    generator.create_runtime_package(runtime, authority_directory=authority)

    with pytest.raises(generator.PublicationArtifactError, match="overwrite"):
        _create_authority(generator, tmp_path)
    with pytest.raises(generator.PublicationArtifactError, match="between 1 and 300"):
        generator.create_authority_package(
            tmp_path / "overlong",
            authority_id="m5-overlong-authority",
            publisher_id="m5-overlong-publisher",
            health_source_id="m5-overlong-health-source",
            role=DegradedRole.MANAGEMENT,
            surface="service",
            condition=RoleCondition.UNAVAILABLE,
            actor_id="agent:operator-1",
            mission_id="microgrid-containment",
            resource="feeder-1",
            operation=Operation.ISOLATE_ASSET,
            maximum_risk_score=65.0,
            credential_seconds=600,
            authorization_seconds=301,
            now=NOW,
        )

    manifest_path = runtime / generator.MANIFEST_NAME
    manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
    with pytest.raises(generator.PublicationArtifactError, match="canonical JSON"):
        generator.verify_runtime_package(runtime)

    parser = generator._parser()
    assert (
        parser.parse_args(["verify-runtime", "--package", "/opt/aegis/m5-runtime"]).command
        == "verify-runtime"
    )
    assert (
        parser.parse_args(
            [
                "verify-reversal",
                "--package",
                "/opt/aegis/m5-reversal",
                "--runtime",
                "/opt/aegis/m5-runtime",
            ]
        ).command
        == "verify-reversal"
    )
    assert "HOME" not in generator._git_environment()
    assert generator.MAX_AUTHORIZATION_SECONDS == 300
    assert generator.MAX_PUBLICATION_AGE_SECONDS == 30

    cli_output = tmp_path / "cli-authority"
    exit_code = generator.main(
        [
            "authority",
            "--output",
            str(cli_output),
            "--authority-id",
            "m5-cli-authority",
            "--publisher-id",
            "m5-cli-publisher",
            "--health-source-id",
            "m5-cli-health-source",
            "--role",
            DegradedRole.MANAGEMENT.value,
            "--surface",
            "service",
            "--condition",
            RoleCondition.UNAVAILABLE.value,
            "--actor-id",
            "agent:operator-1",
            "--mission-id",
            "microgrid-containment",
            "--resource",
            "feeder-1",
            "--operation",
            Operation.ISOLATE_ASSET.value,
            "--maximum-risk-score",
            "65",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert len(captured.out.splitlines()) == 1
    assert json.loads(captured.out)["valid"]
    assert {path.name for path in cli_output.iterdir()} == generator.AUTHORITY_FILES


def test_non_management_package_is_bounded_to_hold_state(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    authority = _create_authority(
        generator,
        tmp_path,
        role=DegradedRole.OBSERVER,
        surface="communication",
    )
    _, authorization, status_input = _load_models(generator, authority)

    assert authorization.affected_roles == frozenset({DegradedRole.OBSERVER})
    assert authorization.behavior is DegradedBehavior.HOLD_STATE
    assert authorization.role_conditions[DegradedRole.OBSERVER] is RoleCondition.HEALTHY
    assert (
        authorization.communication_conditions[DegradedRole.OBSERVER] is RoleCondition.UNAVAILABLE
    )
    assert dict(status_input.role_conditions) == dict(authorization.role_conditions)
    assert dict(status_input.communication_conditions) == dict(
        authorization.communication_conditions
    )
