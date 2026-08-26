"""Provision owner-matching M5 signed-publication volumes once."""

from __future__ import annotations

import json
import os
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel

from .m5_degraded import DegradedModeReversal
from .m5_degraded_publication import (
    DegradedPublicationError,
    DegradedPublisherCredential,
    DegradedStatusInput,
    FileDegradedConsumerStateStore,
    FileDegradedPublisherStateStore,
    FileDegradedStatusSource,
    FileStableDegradedAuthorizationSource,
    load_publisher_credential,
)

MAX_INPUT_BYTES = 1024 * 1024
ModelT = TypeVar("ModelT", bound=BaseModel)


@dataclass(frozen=True)
class _RuntimePaths:
    publication_file: Path
    publisher_state_file: Path
    consumer_state_file: Path
    reversal_file: Path
    status_input_file: Path
    publisher_input_directory: Path
    gateway_input_directory: Path


@dataclass(frozen=True)
class _DirectoryDefinition:
    label: str
    directory: Path


@dataclass(frozen=True)
class _DirectoryState:
    definition: _DirectoryDefinition
    state: str
    original_uid: int
    original_gid: int
    original_mode: int


@dataclass(frozen=True)
class _InputArtifact:
    label: str
    source: Path
    destinations: tuple[Path, ...]
    exact_bytes: int | None = None


def _required_environment(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"required M5 signed-publication setting is missing: {name}")
    return value


def _required_path(name: str) -> Path:
    path = Path(_required_environment(name))
    if not path.is_absolute():
        raise RuntimeError(f"{name} must be an absolute path")
    return path


def _runtime_id(name: str) -> int:
    try:
        value = int(_required_environment(name))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < 0:
        raise RuntimeError(f"{name} must not be negative")
    return value


def _runtime_paths() -> _RuntimePaths:
    paths = _RuntimePaths(
        publication_file=_required_path("AEGIS_M5_PUBLICATION_FILE"),
        publisher_state_file=_required_path("AEGIS_M5_PUBLISHER_STATE_FILE"),
        consumer_state_file=_required_path("AEGIS_M5_CONSUMER_STATE_FILE"),
        reversal_file=_required_path("AEGIS_M5_REVERSAL_FILE"),
        status_input_file=_required_path("AEGIS_M5_STATUS_INPUT_FILE"),
        publisher_input_directory=_required_path(
            "AEGIS_M5_PUBLISHER_INPUT_DIRECTORY"
        ),
        gateway_input_directory=_required_path("AEGIS_M5_GATEWAY_INPUT_DIRECTORY"),
    )
    for label, path in (
        ("M5 publication output", paths.publication_file),
        ("M5 publisher state", paths.publisher_state_file),
        ("M5 consumer state", paths.consumer_state_file),
        ("M5 reversal inbox", paths.reversal_file),
        ("M5 status input", paths.status_input_file),
    ):
        if not path.name or path.name in {".", ".."}:
            raise RuntimeError(f"{label} must name an artifact file")
    return paths


def _directory_definitions(paths: _RuntimePaths) -> tuple[_DirectoryDefinition, ...]:
    return (
        _DirectoryDefinition("M5 publication output", paths.publication_file.parent),
        _DirectoryDefinition("M5 publisher state", paths.publisher_state_file.parent),
        _DirectoryDefinition("M5 consumer state", paths.consumer_state_file.parent),
        _DirectoryDefinition("M5 reversal inbox", paths.reversal_file.parent),
        _DirectoryDefinition("M5 status input", paths.status_input_file.parent),
        _DirectoryDefinition(
            "M5 publisher trusted inputs", paths.publisher_input_directory
        ),
        _DirectoryDefinition("M5 gateway trusted inputs", paths.gateway_input_directory),
    )


def _require_isolated_directories(
    definitions: tuple[_DirectoryDefinition, ...],
) -> None:
    resolved: list[Path] = []
    identities: dict[tuple[int, int], str] = {}
    for definition in definitions:
        try:
            directory_stat = definition.directory.lstat()
            resolved_directory = definition.directory.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError(
                f"{definition.label} directory is unavailable: {definition.directory}"
            ) from exc
        if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(
            directory_stat.st_mode
        ):
            raise RuntimeError(
                f"{definition.label} path must be a non-symlink directory"
            )
        if resolved_directory != definition.directory:
            raise RuntimeError(f"{definition.label} directory must not contain symlinks")
        identity = (directory_stat.st_dev, directory_stat.st_ino)
        prior_label = identities.get(identity)
        if prior_label is not None:
            raise RuntimeError(
                "M5 runtime artifacts must use isolated directories: "
                f"{prior_label} and {definition.label} share storage"
            )
        identities[identity] = definition.label
        resolved.append(resolved_directory)
    for index, directory in enumerate(resolved):
        for other in resolved[index + 1 :]:
            if directory in other.parents or other in directory.parents:
                raise RuntimeError("M5 runtime directories must not overlap")


def _directory_state(
    definition: _DirectoryDefinition,
    *,
    runtime_uid: int,
    runtime_gid: int,
) -> _DirectoryState:
    directory_stat = definition.directory.lstat()
    directory_mode = stat.S_IMODE(directory_stat.st_mode)
    if (
        directory_stat.st_uid == runtime_uid
        and directory_stat.st_gid == runtime_gid
        and directory_mode == 0o700
    ):
        # A recreated initializer has CAP_CHOWN but not DAC read access. Exact
        # runtime-owned roots are preserved without inspection or mutation.
        state = "runtime_owned_preserved_uninspected"
    else:
        if (
            directory_stat.st_uid != os.geteuid()
            or directory_stat.st_gid != os.getegid()
            or directory_mode & 0o500 != 0o500
        ):
            raise RuntimeError(
                f"{definition.label} bootstrap directory has unexpected ownership "
                f"or mode: {definition.directory}"
            )
        try:
            populated = any(definition.directory.iterdir())
        except OSError as exc:
            raise RuntimeError(
                f"{definition.label} bootstrap directory cannot be inspected"
            ) from exc
        if populated:
            raise RuntimeError(
                f"{definition.label} directory must be empty before initialization"
            )
        state = "bootstrap_empty"
    return _DirectoryState(
        definition=definition,
        state=state,
        original_uid=directory_stat.st_uid,
        original_gid=directory_stat.st_gid,
        original_mode=directory_mode,
    )


def _read_source(artifact: _InputArtifact) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(artifact.source, flags)
    except OSError as exc:
        raise RuntimeError(f"{artifact.label} source is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_INPUT_BYTES:
            raise RuntimeError(f"{artifact.label} source must be a bounded regular file")
        material = bytearray()
        while len(material) <= MAX_INPUT_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_INPUT_BYTES + 1 - len(material)))
            if not chunk:
                break
            material.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(material) != before.st_size
            or len(material) > MAX_INPUT_BYTES
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise RuntimeError(f"{artifact.label} source changed while it was read")
        if artifact.exact_bytes is not None and len(material) != artifact.exact_bytes:
            raise RuntimeError(
                f"{artifact.label} source must contain exactly {artifact.exact_bytes} bytes"
            )
        return bytes(material)
    finally:
        os.close(descriptor)


def _create_private_file(path: Path, material: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, material)
        os.fsync(descriptor)
    except OSError as exc:
        raise RuntimeError(f"M5 trusted input could not be staged: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_all(descriptor: int, material: bytes) -> None:
    offset = 0
    while offset < len(material):
        written = os.write(descriptor, material[offset:])
        if written <= 0:
            raise RuntimeError("M5 artifact write made no forward progress")
        offset += written


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"duplicate M5 injector JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise RuntimeError(f"non-finite M5 injector value is forbidden: {value}")


def _validated_canonical_model(material: bytes, model: type[ModelT]) -> ModelT:
    if material.startswith(b"\xef\xbb\xbf"):
        raise RuntimeError("M5 injector input contains a UTF-8 BOM")
    try:
        value = json.loads(
            material.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("M5 injector input is not strict UTF-8 JSON") from exc
    validated = model.model_validate(value)
    canonical = (
        json.dumps(
            validated.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    if material != canonical:
        raise RuntimeError("M5 injector input is not canonical JSON")
    return validated


def _atomic_replace_private(path: Path, material: bytes) -> None:
    try:
        parent_stat = path.parent.lstat()
    except OSError as exc:
        raise RuntimeError("M5 injector target directory is unavailable") from exc
    if (
        stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or parent_stat.st_gid != os.getegid()
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
    ):
        raise RuntimeError(
            "M5 injector target must use an owner-matching 0700 directory"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(path.parent, flags)
    except OSError as exc:
        raise RuntimeError("M5 injector target directory cannot be opened safely") from exc
    temporary_name = f".{path.name}.inject-{os.getpid()}"
    descriptor = -1
    replaced = False
    try:
        try:
            existing = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_nlink != 1
            or existing.st_uid != os.geteuid()
            or existing.st_gid != os.getegid()
            or stat.S_IMODE(existing.st_mode) != 0o600
        ):
            raise RuntimeError("M5 injector refuses an unsafe existing target")
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        create_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary_name, create_flags, 0o600, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, material)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        replaced = True
        os.fsync(parent_fd)
    except OSError as exc:
        raise RuntimeError("M5 injector could not publish its target atomically") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not replaced:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_fd)
        os.close(parent_fd)


def inject_status() -> dict[str, str | int]:
    """Atomically replace only the publisher's canonical status input."""

    source = _required_path("AEGIS_M5_STATUS_INPUT_SOURCE_FILE")
    destination = _required_path("AEGIS_M5_STATUS_INPUT_FILE")
    material = _read_source(_InputArtifact("M5 status input", source, ()))
    status_input = _validated_canonical_model(material, DegradedStatusInput)
    _atomic_replace_private(destination, material)
    return {
        "schema_version": "m5-status-injection-v1",
        "status_input_file": str(destination),
        "status_input_sha256": status_input.digest,
        "private_key_material_consumed": 0,
    }


def inject_reversal() -> dict[str, str | int]:
    """Atomically publish one canonical signed reversal into its inbox."""

    source = _required_path("AEGIS_M5_REVERSAL_SOURCE_FILE")
    destination = _required_path("AEGIS_M5_REVERSAL_FILE")
    material = _read_source(_InputArtifact("M5 reversal", source, ()))
    reversal = _validated_canonical_model(material, DegradedModeReversal)
    _atomic_replace_private(destination, material)
    return {
        "schema_version": "m5-reversal-injection-v1",
        "reversal_file": str(destination),
        "reversal_sha256": reversal.digest,
        "reversal_sequence": reversal.sequence,
        "private_key_material_consumed": 0,
    }


def _input_artifacts(paths: _RuntimePaths) -> tuple[_InputArtifact, ...]:
    publisher = paths.publisher_input_directory
    gateway = paths.gateway_input_directory
    return (
        _InputArtifact(
            "M5 root public key",
            _required_path("AEGIS_M5_ROOT_PUBLIC_KEY_SOURCE_FILE"),
            (publisher / "operator-authority.public", gateway / "operator-authority.public"),
            32,
        ),
        _InputArtifact(
            "M5 publisher credential",
            _required_path("AEGIS_M5_PUBLISHER_CREDENTIAL_SOURCE_FILE"),
            (publisher / "publisher-credential.json", gateway / "publisher-credential.json"),
        ),
        _InputArtifact(
            "M5 stable authorization",
            _required_path("AEGIS_M5_STABLE_AUTHORIZATION_SOURCE_FILE"),
            (publisher / "stable-authorization.json", gateway / "stable-authorization.json"),
        ),
        _InputArtifact(
            "M5 publisher private key",
            _required_path("AEGIS_M5_PUBLISHER_PRIVATE_KEY_SOURCE_FILE"),
            (publisher / "publisher.private",),
            32,
        ),
        _InputArtifact(
            "M5 status input",
            _required_path("AEGIS_M5_STATUS_INPUT_SOURCE_FILE"),
            (paths.status_input_file,),
        ),
    )


def _validate_staged_trust(paths: _RuntimePaths) -> DegradedPublisherCredential:
    publisher = paths.publisher_input_directory
    root_material = (publisher / "operator-authority.public").read_bytes()
    authority_public_key = Ed25519PublicKey.from_public_bytes(root_material)
    credential = load_publisher_credential(publisher / "publisher-credential.json")
    if not credential.verify(authority_public_key):
        raise RuntimeError("M5 publisher credential signature is invalid")
    private_key = Ed25519PrivateKey.from_private_bytes(
        (publisher / "publisher.private").read_bytes()
    )
    if private_key.public_key().public_bytes_raw() != (
        credential.publisher_public_key.public_bytes_raw()
    ):
        raise RuntimeError("M5 publisher private key does not match its credential")
    authorization = FileStableDegradedAuthorizationSource(
        publisher / "stable-authorization.json"
    )()
    if (
        not authorization.verify(authority_public_key)
        or authorization.publisher_credential_sha256 != credential.digest
        or authorization.publisher_key_id != credential.publisher_key_id
    ):
        raise RuntimeError("M5 stable authorization is outside configured trust")
    FileDegradedStatusSource(paths.status_input_file)()
    return credential


def _state_artifacts(path: Path) -> tuple[Path, Path]:
    return path, path.with_name(f".{path.name}.lock")


def _restore_directory(directory_state: _DirectoryState) -> None:
    with suppress(OSError):
        os.chown(
            directory_state.definition.directory,
            directory_state.original_uid,
            directory_state.original_gid,
        )
        directory_state.definition.directory.chmod(directory_state.original_mode)


def _bootstrap(
    paths: _RuntimePaths,
    directory_states: tuple[_DirectoryState, ...],
    *,
    runtime_uid: int,
    runtime_gid: int,
) -> None:
    artifacts = _input_artifacts(paths)
    created: list[Path] = []
    try:
        for directory_state in directory_states:
            directory_state.definition.directory.chmod(0o700)
        for artifact in artifacts:
            material = _read_source(artifact)
            for destination in artifact.destinations:
                _create_private_file(destination, material)
                created.append(destination)
        credential = _validate_staged_trust(paths)
        FileDegradedPublisherStateStore.initialize(
            paths.publisher_state_file,
            credential=credential,
        )
        created.extend(_state_artifacts(paths.publisher_state_file))
        FileDegradedConsumerStateStore.initialize(
            paths.consumer_state_file,
            credential=credential,
        )
        created.extend(_state_artifacts(paths.consumer_state_file))

        for path in created:
            path.chmod(0o600)
            os.chown(path, runtime_uid, runtime_gid)
            artifact_stat = path.stat()
            if (
                artifact_stat.st_uid != runtime_uid
                or artifact_stat.st_gid != runtime_gid
                or stat.S_IMODE(artifact_stat.st_mode) != 0o600
            ):
                raise RuntimeError(f"M5 runtime artifact was not assigned privately: {path}")
        for directory_state in directory_states:
            directory = directory_state.definition.directory
            os.chown(directory, runtime_uid, runtime_gid)
            directory_stat = directory.stat()
            if (
                directory_stat.st_uid != runtime_uid
                or directory_stat.st_gid != runtime_gid
                or stat.S_IMODE(directory_stat.st_mode) != 0o700
            ):
                raise RuntimeError(
                    f"{directory_state.definition.label} was not assigned privately"
                )
    except Exception:
        for directory_state in reversed(directory_states):
            _restore_directory(directory_state)
        for path in reversed(created):
            with suppress(OSError):
                path.unlink()
        raise


def initialize() -> dict[str, str | int]:
    """Bootstrap all seven roots once or preserve the exact runtime-owned set."""

    paths = _runtime_paths()
    runtime_uid = _runtime_id("AEGIS_M5_RUNTIME_UID")
    runtime_gid = _runtime_id("AEGIS_M5_RUNTIME_GID")
    definitions = _directory_definitions(paths)
    _require_isolated_directories(definitions)
    directory_states = tuple(
        _directory_state(
            definition,
            runtime_uid=runtime_uid,
            runtime_gid=runtime_gid,
        )
        for definition in definitions
    )
    states = {directory_state.state for directory_state in directory_states}
    if len(states) != 1:
        raise RuntimeError(
            "M5 volume set is partially initialized; refusing to mix trust or state"
        )
    state = next(iter(states))
    if state == "bootstrap_empty":
        try:
            _bootstrap(
                paths,
                directory_states,
                runtime_uid=runtime_uid,
                runtime_gid=runtime_gid,
            )
        except (DegradedPublicationError, OSError, TypeError, ValueError) as exc:
            raise RuntimeError("M5 signed-publication bootstrap failed") from exc
        result = "bootstrap_prepared"
    else:
        result = "runtime_owned_preserved_uninspected"

    return {
        "schema_version": "m5-signed-publication-volume-initialization-v2",
        "directory_count": len(definitions),
        "publication_file": str(paths.publication_file),
        "publisher_state_file": str(paths.publisher_state_file),
        "consumer_state_file": str(paths.consumer_state_file),
        "reversal_file": str(paths.reversal_file),
        "status_input_file": str(paths.status_input_file),
        "publisher_input_directory": str(paths.publisher_input_directory),
        "gateway_input_directory": str(paths.gateway_input_directory),
        "runtime_uid": runtime_uid,
        "runtime_gid": runtime_gid,
        "directory_mode": "0700",
        "artifact_mode": "0600",
        "volume_set_state": result,
        "secrets_consumed": 5 if state == "bootstrap_empty" else 0,
    }


def main(argv: list[str] | None = None) -> None:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if not arguments:
            report = initialize()
        elif arguments == ["inject-status"]:
            report = inject_status()
        elif arguments == ["inject-reversal"]:
            report = inject_reversal()
        else:
            raise RuntimeError(
                "usage: python -m aegis_ot.m5_degraded_init "
                "[inject-status|inject-reversal]"
            )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"M5 degraded initialization error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
