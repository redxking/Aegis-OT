#!/usr/bin/env python3
"""Prepare one private, immutable M4j third-party image distribution bundle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, NoReturn, cast

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "aegis-ot-m4j-runtime-images-v1"
MANIFEST_NAME = "runtime-images-manifest.json"
TARGET_PLATFORM = "linux/amd64"
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
RUNTIME_IMAGES = {
    "spire-server": {
        "reference": (
            "ghcr.io/spiffe/spire-server:1.15.2@sha256:"
            "aa74ef1be86bc8e0684007d84a4d9859d294384d842c30425048d73429f3216e"
        ),
        "archive": "spire-server-image.tar",
    },
    "spire-agent": {
        "reference": (
            "ghcr.io/spiffe/spire-agent:1.15.2@sha256:"
            "1d042e4040466686e0ee46f74981ff2167c86adfadca19b3835946f4d6047536"
        ),
        "archive": "spire-agent-image.tar",
    },
    "opa": {
        "reference": (
            "openpolicyagent/opa:1.19.1-static@sha256:"
            "32bf41d914b1505fea13303f60587cc57bdd2902262177585fb208f5dde76d32"
        ),
        "archive": "opa-image.tar",
    },
}
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_REGISTRY_DOCUMENT_BYTES = 4 * 1024 * 1024
OCI_INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
OCI_MANIFEST_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
OCI_CONFIG_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.config.v1+json",
        "application/vnd.docker.container.image.v1+json",
    }
)
OCI_LAYER_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.docker.image.rootfs.diff.tar",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
    }
)


class RuntimeImageBundleError(RuntimeError):
    """The immutable runtime-image bundle could not be prepared safely."""


def _fail(message: str) -> NoReturn:
    raise RuntimeImageBundleError(message)


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON document contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise RuntimeImageBundleError(
        f"JSON document contains forbidden constant: {value}"
    )


def _load_json(material: bytes | str, *, label: str) -> Any:
    try:
        raw = material.decode("utf-8") if isinstance(material, bytes) else material
        return json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeImageBundleError(f"{label} is not strict JSON") from exc


def _load_archive_validator() -> ModuleType:
    path = ROOT / "scripts" / "build_m4j_bundle.py"
    spec = importlib.util.spec_from_file_location("_aegis_m4j_image_archive", path)
    if spec is None or spec.loader is None:
        _fail("M4j saved-image archive validator could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("docker")
    if executable is None:
        _fail("Docker executable is unavailable")
    completed = subprocess.run(  # noqa: S603 - resolved Docker and fixed argv
        (executable, *arguments),
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeImageBundleError(f"Docker command failed: {detail[-2000:]}")
    return completed


def _private_output(output: Path) -> Path:
    if output.exists() or output.is_symlink():
        _fail("refusing to overwrite a runtime-image bundle path")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise RuntimeImageBundleError("runtime-image bundle parent is unavailable") from exc
    destination = parent / output.name
    try:
        destination.relative_to(ROOT.resolve())
    except ValueError:
        return destination
    _fail("runtime-image bundles must remain outside the checkout")


def _write_private(path: Path, material: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(material):
            written = os.write(descriptor, material[offset:])
            if written <= 0:
                _fail("runtime-image manifest write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _file_evidence(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_ARCHIVE_BYTES
    ):
        _fail(f"runtime-image archive is unsafe: {path.name}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ARCHIVE_BYTES:
                _fail(f"runtime-image archive exceeds its limit: {path.name}")
            digest.update(chunk)
    if size != metadata.st_size:
        _fail(f"runtime-image archive changed while hashing: {path.name}")
    return {"path": path.name, "sha256": digest.hexdigest(), "size_bytes": size}


def _expected_repo_digest(reference: str) -> str:
    name, digest = reference.split("@", maxsplit=1)
    repository = name.rsplit(":", maxsplit=1)[0]
    return f"{repository}@{digest}"


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        _fail(f"{label} digest is malformed")
    return value


def _descriptor(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(f"{label} descriptor is malformed")
    digest = _digest(value.get("digest"), label=label)
    size = value.get("size")
    media_type = value.get("mediaType")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or size > MAX_ARCHIVE_BYTES
        or not isinstance(media_type, str)
        or not media_type
    ):
        _fail(f"{label} descriptor is malformed")
    return {"digest": digest, "size_bytes": size, "media_type": media_type}


def _registry_document(reference: str, expected_digest: str) -> dict[str, Any]:
    completed = _run("buildx", "imagetools", "inspect", "--raw", reference)
    try:
        raw = completed.stdout.encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - subprocess decoder invariant
        raise RuntimeImageBundleError("registry descriptor is not strict UTF-8") from exc
    candidates = [raw]
    if raw.endswith(b"\n"):
        candidates.append(raw[:-1])
    material = next(
        (
            candidate
            for candidate in candidates
            if 0 < len(candidate) <= MAX_REGISTRY_DOCUMENT_BYTES
            and "sha256:" + hashlib.sha256(candidate).hexdigest() == expected_digest
        ),
        None,
    )
    if material is None:
        _fail("registry descriptor bytes do not match the requested digest")
    document = _load_json(material, label="registry descriptor")
    if not isinstance(document, dict) or document.get("schemaVersion") != 2:
        _fail("registry descriptor is not an OCI/Docker schema-2 document")
    media_type = document.get("mediaType")
    if media_type not in OCI_INDEX_MEDIA_TYPES | OCI_MANIFEST_MEDIA_TYPES:
        _fail("registry descriptor media type is unsupported")
    return {
        "digest": expected_digest,
        "size_bytes": len(material),
        "media_type": media_type,
        "document_base64": base64.b64encode(material).decode("ascii"),
        "document": document,
    }


def _platform_matches(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    variant = value.get("variant")
    return (
        {"os", "architecture"}.issubset(value)
        and set(value).issubset({"os", "architecture", "variant"})
        and value.get("os") == "linux"
        and value.get("architecture") == "amd64"
        and (variant is None or variant == "")
    )


def _acquire_registry_binding(reference: str) -> dict[str, Any]:
    repository, root_digest = reference.split("@", maxsplit=1)
    root = _registry_document(reference, _digest(root_digest, label="registry root"))
    root_document = root.pop("document")
    if root["media_type"] in OCI_INDEX_MEDIA_TYPES:
        manifests = root_document.get("manifests")
        if not isinstance(manifests, list):
            _fail("registry image index manifest set is malformed")
        candidates = [
            _descriptor(value, label=f"registry index entry {index}")
            for index, value in enumerate(manifests)
            if isinstance(value, dict) and _platform_matches(value.get("platform"))
        ]
        if len(candidates) != 1 or candidates[0]["media_type"] not in OCI_MANIFEST_MEDIA_TYPES:
            _fail("registry image index does not select exactly one linux/amd64 manifest")
        selected_descriptor = candidates[0]
        selected = _registry_document(
            f"{repository}@{selected_descriptor['digest']}",
            selected_descriptor["digest"],
        )
        if (
            selected["size_bytes"] != selected_descriptor["size_bytes"]
            or selected["media_type"] != selected_descriptor["media_type"]
        ):
            _fail("selected registry manifest differs from its index descriptor")
        selected_document = selected.pop("document")
    else:
        selected = dict(root)
        selected_document = root_document
    config = _descriptor(selected_document.get("config"), label="registry config")
    if config["media_type"] not in OCI_CONFIG_MEDIA_TYPES:
        _fail("registry config media type is unsupported")
    raw_layers = selected_document.get("layers")
    if not isinstance(raw_layers, list):
        _fail("registry layer descriptor set is malformed")
    layers = [
        _descriptor(value, label=f"registry layer {index}")
        for index, value in enumerate(raw_layers)
    ]
    if any(layer["media_type"] not in OCI_LAYER_MEDIA_TYPES for layer in layers):
        _fail("registry layer media type is unsupported")
    return {
        "schema_version": "aegis-ot-oci-registry-archive-binding-v1",
        "registry_reference": reference,
        "target_platform": TARGET_PLATFORM,
        "root_descriptor": root,
        "selected_manifest": selected,
        "config_descriptor": config,
        "layer_descriptors": layers,
    }


def _decode_bound_document(value: object, *, label: str) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {
        "digest",
        "size_bytes",
        "media_type",
        "document_base64",
    }:
        _fail(f"{label} binding is malformed")
    digest = _digest(value["digest"], label=label)
    size = value["size_bytes"]
    encoded = value["document_base64"]
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_REGISTRY_DOCUMENT_BYTES
        or not isinstance(encoded, str)
    ):
        _fail(f"{label} binding is malformed")
    try:
        material = base64.b64decode(encoded, validate=True)
        document = _load_json(material, label=label)
    except (ValueError, RuntimeImageBundleError) as exc:
        raise RuntimeImageBundleError(f"{label} binding is not canonical JSON bytes") from exc
    if (
        len(material) != size
        or "sha256:" + hashlib.sha256(material).hexdigest() != digest
        or not isinstance(document, dict)
        or document.get("schemaVersion") != 2
        or document.get("mediaType") != value["media_type"]
    ):
        _fail(f"{label} document does not match its descriptor")
    return material, document


def _validate_registry_binding(reference: str, binding: object) -> dict[str, Any]:
    if not isinstance(binding, dict) or set(binding) != {
        "schema_version",
        "registry_reference",
        "target_platform",
        "root_descriptor",
        "selected_manifest",
        "config_descriptor",
        "layer_descriptors",
    }:
        _fail("registry/archive identity binding is malformed")
    if (
        binding["schema_version"] != "aegis-ot-oci-registry-archive-binding-v1"
        or binding["registry_reference"] != reference
        or binding["target_platform"] != TARGET_PLATFORM
    ):
        _fail("registry/archive identity binding differs from the exact request")
    _root_material, root_document = _decode_bound_document(
        binding["root_descriptor"], label="registry root"
    )
    expected_root_digest = _digest(reference.split("@", maxsplit=1)[1], label="registry root")
    if binding["root_descriptor"]["digest"] != expected_root_digest:
        _fail("registry root document does not bind the configured digest")
    root_media_type = binding["root_descriptor"]["media_type"]
    _selected_material, selected_document = _decode_bound_document(
        binding["selected_manifest"], label="selected registry manifest"
    )
    if root_media_type in OCI_INDEX_MEDIA_TYPES:
        manifests = root_document.get("manifests")
        if not isinstance(manifests, list):
            _fail("registry index manifest set is malformed")
        candidates = [
            _descriptor(value, label=f"bound registry index entry {index}")
            for index, value in enumerate(manifests)
            if isinstance(value, dict) and _platform_matches(value.get("platform"))
        ]
        selected = binding["selected_manifest"]
        if len(candidates) != 1 or candidates[0] != {
            "digest": selected["digest"],
            "size_bytes": selected["size_bytes"],
            "media_type": selected["media_type"],
        }:
            _fail("registry index does not bind the selected linux/amd64 manifest")
    elif root_media_type in OCI_MANIFEST_MEDIA_TYPES:
        if binding["selected_manifest"] != binding["root_descriptor"]:
            _fail("direct registry manifest binding is not singular")
    else:
        _fail("registry root media type is unsupported")
    config = _descriptor(selected_document.get("config"), label="bound registry config")
    raw_layers = selected_document.get("layers")
    if not isinstance(raw_layers, list):
        _fail("bound registry layer set is malformed")
    layers = [
        _descriptor(value, label=f"bound registry layer {index}")
        for index, value in enumerate(raw_layers)
    ]
    if (
        config != binding["config_descriptor"]
        or config["media_type"] not in OCI_CONFIG_MEDIA_TYPES
        or layers != binding["layer_descriptors"]
        or any(layer["media_type"] not in OCI_LAYER_MEDIA_TYPES for layer in layers)
    ):
        _fail("registry manifest descriptors differ from the retained binding")
    selected = cast(dict[str, Any], binding["selected_manifest"])
    return {
        "selected_manifest": {
            "digest": selected["digest"],
            "size_bytes": selected["size_bytes"],
            "media_type": selected["media_type"],
        },
        "config": config,
        "layers": layers,
    }


def _validate_saved_runtime_archive(
    archive_path: Path,
    *,
    reference: str,
    distribution_tag: str,
    image_id: str,
    registry_binding: object,
) -> dict[str, Any]:
    derived_registry = _validate_registry_binding(reference, registry_binding)
    archive_validator = _load_archive_validator()
    try:
        archive_binding = archive_validator._validate_saved_image_archive(
            archive_path,
            expected_image_id=image_id,
            expected_commit=None,
            expected_platform={
                "requested": TARGET_PLATFORM,
                "os": "linux",
                "architecture": "amd64",
                "variant": None,
            },
        )
    except Exception as exc:
        raise RuntimeImageBundleError(
            f"saved runtime image archive structure is invalid: {exc}"
        ) from exc
    if not isinstance(archive_binding, dict):
        _fail("saved runtime archive validation result is malformed")
    selected_manifest = derived_registry["selected_manifest"]
    config = derived_registry["config"]
    registry_layers = derived_registry["layers"]
    image_binding = archive_binding.get("image_id_binding")
    if not isinstance(image_binding, dict):
        _fail("saved runtime archive lacks an exact OCI descriptor closure")
    if image_binding.get("kind") != "oci_descriptor_chain":
        _fail(
            "saved runtime archive does not provide a supported exact OCI "
            "descriptor closure"
        )
    root_digest = image_binding.get("root_digest")
    image_manifest_digest = image_binding.get("image_manifest_digest")
    root_media_type = image_binding.get("root_media_type")
    layer_digests = image_binding.get("layer_digests")
    layer_media_types = image_binding.get("layer_media_types")
    verified_layers = image_binding.get("verified_layers")
    if (
        not isinstance(root_digest, str)
        or not isinstance(image_manifest_digest, str)
        or not isinstance(root_media_type, str)
        or not isinstance(layer_digests, list)
        or not all(isinstance(value, str) for value in layer_digests)
        or not isinstance(layer_media_types, list)
        or not all(isinstance(value, str) for value in layer_media_types)
        or not isinstance(verified_layers, list)
        or not all(isinstance(value, dict) for value in verified_layers)
    ):
        _fail("saved runtime archive exact OCI descriptor closure is malformed")
    archive_manifest_closure = {
        "digest": f"sha256:{root_digest}",
        "image_manifest_digest": f"sha256:{image_manifest_digest}",
        "media_type": root_media_type,
    }
    expected_manifest_closure = {
        "digest": selected_manifest["digest"],
        "image_manifest_digest": selected_manifest["digest"],
        "media_type": selected_manifest["media_type"],
    }
    try:
        archive_layer_closure = [
            {
                "digest": "sha256:" + digest,
                "media_type": media_type,
                "size_bytes": verified["size_bytes"],
                "path": verified["path"],
                "sha256": verified["sha256"],
                "digest_semantics": verified["digest_semantics"],
            }
            for digest, media_type, verified in zip(
                cast(list[str], layer_digests),
                cast(list[str], layer_media_types),
                cast(list[dict[str, Any]], verified_layers),
                strict=True,
            )
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeImageBundleError(
            "saved runtime archive OCI layer closure is malformed"
        ) from exc
    expected_layer_closure = [
        {
            "digest": layer["digest"],
            "media_type": layer["media_type"],
            "size_bytes": layer["size_bytes"],
            "path": f"blobs/sha256/{layer['digest'].removeprefix('sha256:')}",
            "sha256": layer["digest"].removeprefix("sha256:"),
            "digest_semantics": "stored_descriptor_digest",
        }
        for layer in registry_layers
    ]
    if (
        image_id != selected_manifest["digest"]
        or archive_manifest_closure != expected_manifest_closure
        or archive_layer_closure != expected_layer_closure
        or config["digest"] != "sha256:" + archive_binding["config_sha256"]
        or config["size_bytes"] != archive_binding["config_size_bytes"]
        or len(registry_layers) != archive_binding["layer_count"]
        or archive_binding["repo_tags"] != [distribution_tag]
        or archive_binding["platform"]
        != {"os": "linux", "architecture": "amd64", "variant": None}
    ):
        _fail(
            "saved runtime archive is not bound to the selected registry "
            "manifest/config/layers"
        )
    return cast(dict[str, Any], archive_binding)


def _inspect(reference: str) -> dict[str, Any] | None:
    completed = _run(
        "image",
        "inspect",
        "--platform",
        TARGET_PLATFORM,
        reference,
        check=False,
    )
    if completed.returncode != 0:
        return None
    try:
        documents = _load_json(completed.stdout, label="Docker inspection")
    except RuntimeImageBundleError as exc:
        raise RuntimeImageBundleError("Docker inspection did not return JSON") from exc
    if not isinstance(documents, list) or len(documents) != 1 or not isinstance(
        documents[0], dict
    ):
        _fail("Docker inspection returned an unexpected image set")
    inspected = documents[0]
    image_id = inspected.get("Id")
    repo_digests = inspected.get("RepoDigests") or []
    if (
        not isinstance(image_id, str)
        or IMAGE_ID.fullmatch(image_id) is None
        or inspected.get("Os") != "linux"
        or inspected.get("Architecture") != "amd64"
        or inspected.get("Variant") not in {None, ""}
        or not isinstance(repo_digests, list)
        or _expected_repo_digest(reference) not in repo_digests
    ):
        _fail("runtime image is not the exact linux/amd64 registry digest")
    return {"image_id": image_id, "repo_digests": sorted(set(repo_digests))}


def prepare_runtime_images(output: Path, *, pull: bool) -> dict[str, Any]:
    destination = _private_output(output)
    destination.mkdir(mode=0o700)
    destination.chmod(0o700)
    published = False
    temporary_tags: list[str] = []
    try:
        images: dict[str, Any] = {}
        for name, contract in RUNTIME_IMAGES.items():
            reference = contract["reference"]
            registry_binding = _acquire_registry_binding(reference)
            if pull:
                _run("pull", "--platform", TARGET_PLATFORM, reference)
            inspected = _inspect(reference)
            if inspected is None:
                if not pull:
                    _fail(f"runtime image is absent and --pull was not authorized: {name}")
                _fail(f"runtime image remained absent after pull: {name}")
            distribution_tag = (
                f"aegis-m4j-runtime/{name}:"
                f"{reference.rsplit('sha256:', maxsplit=1)[1][:16]}"
            )
            _run("image", "tag", reference, distribution_tag)
            temporary_tags.append(distribution_tag)
            tagged = _run(
                "image",
                "inspect",
                "--platform",
                TARGET_PLATFORM,
                distribution_tag,
            )
            tagged_document = _load_json(tagged.stdout, label="tagged Docker inspection")
            if (
                not isinstance(tagged_document, list)
                or len(tagged_document) != 1
                or not isinstance(tagged_document[0], dict)
                or tagged_document[0].get("Id") != inspected["image_id"]
            ):
                _fail(f"runtime image tag changed image identity: {name}")
            archive_path = destination / contract["archive"]
            _run(
                "image",
                "save",
                "--platform",
                TARGET_PLATFORM,
                "--output",
                str(archive_path),
                distribution_tag,
            )
            archive_path.chmod(0o600)
            archive_validator = _load_archive_validator()
            try:
                archive_validator._canonicalize_saved_image_archive(
                    archive_path,
                    expected_image_id=inspected["image_id"],
                    expected_commit=None,
                    expected_platform={
                        "requested": TARGET_PLATFORM,
                        "os": "linux",
                        "architecture": "amd64",
                        "variant": None,
                    },
                )
            except Exception as exc:
                raise RuntimeImageBundleError(
                    f"saved runtime image archive could not be canonicalized: {name}: {exc}"
                ) from exc
            archive_evidence = _file_evidence(archive_path)
            archive_binding = _validate_saved_runtime_archive(
                archive_path,
                reference=reference,
                distribution_tag=distribution_tag,
                image_id=inspected["image_id"],
                registry_binding=registry_binding,
            )
            if _file_evidence(archive_path) != archive_evidence:
                _fail(f"runtime-image archive changed during validation: {name}")
            images[name] = {
                "registry_reference": reference,
                "distribution_tag": distribution_tag,
                "image_id": inspected["image_id"],
                "platform": TARGET_PLATFORM,
                "registry_binding": registry_binding,
                "archive": archive_evidence,
                "archive_binding": archive_binding,
            }
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "target_platform": TARGET_PLATFORM,
            "images": images,
            "distribution_boundary": {
                "registry_acquisition": "authenticated_https_by_exact_digest",
                "mutable_tags_used_for_execution": False,
                "deployment_established": False,
            },
        }
        _write_private(destination / MANIFEST_NAME, _canonical_bytes(manifest))
        directory_descriptor = os.open(destination, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        published = True
        return manifest
    finally:
        for tag in reversed(temporary_tags):
            _run("image", "rm", tag, check=False)
        if not published and destination.exists() and not destination.is_symlink():
            shutil.rmtree(destination)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--pull",
        action="store_true",
        help=(
            "authorize authenticated registry pulls that refresh each exact digest "
            "for linux/amd64"
        ),
    )
    arguments = parser.parse_args()
    manifest = prepare_runtime_images(arguments.output, pull=arguments.pull)
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "schema_version": manifest["schema_version"],
                "image_count": len(manifest["images"]),
                "deployment_established": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
