#!/usr/bin/env python3
"""Validate M4j workload inputs and compile one closed host deployment plan."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, NoReturn, cast

import yaml  # type: ignore[import-untyped]
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis_ot.segmented_capability_models import (
    GATEWAY_CAPABILITY_AUDIENCE,
    OT_CAPABILITY_AUDIENCE,
)
from aegis_ot.workload_identity import (
    SignedWorkloadCredential,
    WorkloadRole,
    load_signed_workload_credential,
    load_workload_trust_bundle,
    workload_key_id,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TOPOLOGY = ROOT / "infra" / "m4j" / "topology.yml"
DEFAULT_DEPLOYMENT = ROOT / "infra" / "m4j" / "deployment.yml"
DEFAULT_WORKLOADS = ROOT / "infra" / "m4j" / "workloads.yml"
SECRET_MANIFEST_NAME = "secrets-manifest.json"  # noqa: S105 - filename, not credential
ROLES = ("management", "trust", "agents", "gateway", "ot", "simulation")
AGENT_ROLES = ROLES[1:]
SERVICE_NAMES = (
    "policy-relay",
    "opa",
    "observer",
    "candidate",
    "agent-probe",
    "segmented-gateway",
    "ot-adapter",
    "plant",
)
REGISTRATION_NAMES = tuple(name for name in SERVICE_NAMES if name != "opa")
EXPECTED_REGISTRATIONS = {
    "policy-relay": (
        "trust",
        "m4j-trust-policy-relay-v1",
        "spiffe://aegis-ot.m4g.local/workload/policy-relay",
        65537,
    ),
    "observer": (
        "trust",
        "m4j-trust-observer-v1",
        "spiffe://aegis-ot.m4g.local/workload/observer",
        65533,
    ),
    "candidate": (
        "trust",
        "m4j-trust-candidate-v1",
        "spiffe://aegis-ot.m4g.local/workload/candidate",
        65534,
    ),
    "agent-probe": (
        "agents",
        "m4j-agents-agent-probe-v1",
        "spiffe://aegis-ot.m4g.local/workload/agent-probe",
        65538,
    ),
    "segmented-gateway": (
        "gateway",
        "m4j-gateway-segmented-gateway-v1",
        "spiffe://aegis-ot.m4g.local/workload/gateway",
        65532,
    ),
    "ot-adapter": (
        "ot",
        "m4j-ot-ot-adapter-v1",
        "spiffe://aegis-ot.m4g.local/workload/ot-adapter",
        65535,
    ),
    "plant": (
        "simulation",
        "m4j-simulation-plant-v1",
        "spiffe://aegis-ot.m4g.local/workload/plant",
        65536,
    ),
}
RUNTIME_IMAGE_REFS = {
    "spire-server": (
        "ghcr.io/spiffe/spire-server:1.15.2@sha256:"
        "aa74ef1be86bc8e0684007d84a4d9859d294384d842c30425048d73429f3216e"
    ),
    "spire-agent": (
        "ghcr.io/spiffe/spire-agent:1.15.2@sha256:"
        "1d042e4040466686e0ee46f74981ff2167c86adfadca19b3835946f4d6047536"
    ),
    "opa": (
        "openpolicyagent/opa:1.19.1-static@sha256:"
        "32bf41d914b1505fea13303f60587cc57bdd2902262177585fb208f5dde76d32"
    ),
}
ORCHESTRATION_CONTRACT = {
    "engine": "ansible-core",
    "version": "2.19.12",
    "distribution": "ansible_core-2.19.12-py3-none-any.whl",
    "distribution_sha256": (
        "b6bbdf05952852ad908861d652a9009c8474f1fe9c63a77ec202979a329d7d99"
    ),
    "configuration": "infra/ansible/ansible.cfg",
    "inventory": "infra/ansible/inventory.ini",
    "playbook": "infra/ansible/workloads.yml",
    "transport": "ssh_over_management",
}
RUNTIME_IMAGE_BUNDLE_CONTRACT = {
    "schema_version": "aegis-ot-m4j-runtime-images-v1",
    "manifest": "runtime-images-manifest.json",
    "target_platform": "linux/amd64",
    "registry_acquisition": "authenticated_https_by_exact_digest",
    "mutable_tags_allowed": False,
    "archives": {
        "spire-server": "spire-server-image.tar",
        "spire-agent": "spire-agent-image.tar",
        "opa": "opa-image.tar",
    },
}
LIVE_PROBE_CONTRACT = {
    "schema_version": "aegis-ot-m4j-live-workload-probe-v1",
    "runner": "scripts/run_m4j_workload_probe.py",
    "playbook": "infra/ansible/probe.yml",
    "execution_mode": "apply_then_probe_only",
    "phases": ["initial", "after_bounded_restart"],
    "restart_order": [
        "plant",
        "observer",
        "candidate",
        "ot-adapter",
        "segmented-gateway",
    ],
    "result_handling": "private_controller_output_and_remote_cleanup",
    "evidence_signature": "controller_ed25519_with_explicit_external_trust_anchor",
    "verification_result": (
        "canonical_record_consistency_not_independent_execution_provenance"
    ),
    "claim_boundary": (
        "bounded_local_live_probe_not_production_or_independent_validation"
    ),
}
AGENT_PROBE_BYPASS_ALIASES = {
    "segmented-gateway.m4j.internal": "192.168.58.13",
    "observer": "192.168.59.11",
    "candidate": "192.168.59.11",
    "ot-adapter": "192.168.59.14",
    "simulation": "192.168.60.15",
}
EXPECTED_SECRET_FILES = frozenset(
    {
        *(f"{name}.{kind}" for name in (
            "workload_authority",
            "agent",
            "gateway",
            "ot",
            "permit",
            "observer",
            "candidate",
            "plant",
        ) for kind in ("private", "public")),
        "identity/authority.public",
        "identity/trust-bundle.json",
        "identity/agent.credential.json",
        "identity/gateway.credential.json",
        "identity/ot.credential.json",
    }
)
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
PINNED_IMAGE = re.compile(r"^[a-z0-9][A-Za-z0-9._/:@-]*@sha256:[0-9a-f]{64}$")
PLACEHOLDER = re.compile(r"^\$\{secrets\.key_ids\.([a-z_]+)\}$")
HOST_ALIAS = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
UNIT_ARGUMENT = re.compile(r"^[A-Za-z0-9_./:@=+-]+$")
LEAF_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
STATE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
ABSOLUTE_CONTAINER_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
EFFECT_COORDINATOR_AUDIENCE = "aegis-ot:m4i:effect-coordinator"
GATEWAY_COORDINATION_AUDIENCE = "aegis-ot:m4i:gateway"
MINIMUM_IDENTITY_REMAINING = timedelta(minutes=5)
TOKEN_CLEANUP_POLICY = (  # noqa: S105 - policy label, not a credential
    "always_local_delete_server_revoke_and_conditional_exact_auto_alias_cleanup"  # noqa: S105
)
OPA_POLICY_MAXIMUM = 4 * 1024 * 1024
MTLS_OUTBOUND_ENVIRONMENTS = {
    "segmented-gateway": {
        "policy-relay": "AEGIS_OPA_URL",
        "observer": "AEGIS_OBSERVER_URL",
        "candidate": "AEGIS_CANDIDATE_URL",
        "ot-adapter": "AEGIS_OT_URL",
    },
    "observer": {"plant": "AEGIS_PLANT_URL"},
    "candidate": {"plant": "AEGIS_PLANT_URL"},
    "ot-adapter": {
        "observer": "AEGIS_OBSERVER_URL",
        "plant": "AEGIS_PLANT_URL",
    },
}


class WorkloadContractError(ValueError):
    """The M4j workload configuration or a deployment input is not closed."""


def _fail(message: str) -> NoReturn:
    raise WorkloadContractError(message)


def _load_deployment_validator() -> ModuleType:
    path = ROOT / "scripts" / "validate_m4j_deployment.py"
    spec = importlib.util.spec_from_file_location("_aegis_m4j_deployment_validator", path)
    if spec is None or spec.loader is None:
        _fail("M4j deployment validator could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_bundle_validator() -> ModuleType:
    path = ROOT / "scripts" / "build_m4j_bundle.py"
    spec = importlib.util.spec_from_file_location("_aegis_m4j_bundle_validator", path)
    if spec is None or spec.loader is None:
        _fail("M4j application bundle validator could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_runtime_image_validator() -> ModuleType:
    path = ROOT / "scripts" / "prepare_m4j_runtime_images.py"
    spec = importlib.util.spec_from_file_location("_aegis_m4j_runtime_images", path)
    if spec is None or spec.loader is None:
        _fail("M4j runtime-image validator could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _read_trusted_builder_public_key(path: Path) -> bytes:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    except OSError as exc:
        raise WorkloadContractError("trusted-builder public key is unavailable") from exc
    else:
        _fail("trusted-builder public key must remain outside the checkout")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.absolute(), flags)
    except OSError as exc:
        raise WorkloadContractError(
            "trusted-builder public key could not be opened safely"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or metadata.st_size != 32
        ):
            _fail(
                "trusted-builder public key must be an owned, protected raw Ed25519 key"
            )
        material = os.read(descriptor, 33)
        if len(material) != metadata.st_size or os.read(descriptor, 1):
            _fail("trusted-builder public key changed while being read")
    finally:
        os.close(descriptor)
    return material


def _builder_provenance_statement(
    *,
    source: dict[str, Any],
    image: dict[str, Any],
    build_contract: dict[str, Any],
    tools: dict[str, Any],
    builder_helper: dict[str, Any],
    builder_profile: dict[str, Any],
    key_id: str,
) -> dict[str, Any]:
    context = {
        "archive": source["archive"],
        "archived_file_count": source["archived_file_count"],
        "archived_inputs": source["archived_inputs"],
        "tree_binding": source["tree_binding"],
    }
    return {
        "schema_version": "aegis-ot-m4j-builder-provenance-v1",
        "purpose": "aegis-ot-m4j-exact-source-application-image",
        "builder": {
            "identity": f"ed25519-sha256:{key_id}",
            "key_id": key_id,
            "helper": builder_helper,
            "execution_profile": builder_profile,
            "execution_profile_sha256": _canonical_sha256(builder_profile),
            "tool_versions": tools,
        },
        "source": {
            "git_commit": source["git_commit"],
            "git_tree": source["git_tree"],
            "git_object_format": source["git_object_format"],
            "context_sha256": _canonical_sha256(context),
            **context,
        },
        "build": {
            **build_contract,
            "build_arguments": {
                "AEGIS_INSTALL_TARGET": build_contract["install_target"],
                "AEGIS_SOURCE_REVISION": build_contract[
                    "source_revision_build_argument"
                ],
                "PYTHON_IMAGE": build_contract["pinned_base_image"],
            },
            "dockerignore": source["archived_inputs"][".dockerignore"],
            "dockerfile_input": source["archived_inputs"]["Dockerfile"],
            "lockfile_input": source["archived_inputs"]["requirements.lock"],
            "pyproject_input": source["archived_inputs"]["pyproject.toml"],
        },
        "subject": {
            "image_id": image["image_id"],
            "oci_revision": image["oci_revision"],
            "platform": image["platform"],
            "build_invocation": image["build_invocation"],
            "archive": image["archive"],
            "archive_binding": image["archive_binding"],
        },
    }


def _validate_builder_execution_profile(
    profile: object,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    if SHA256.fullmatch(expected_sha256) is None or not isinstance(profile, dict):
        _fail("an out-of-band expected builder profile SHA-256 is required")
    _exact_fields(
        profile,
        (
            "schema_version",
            "docker_client",
            "docker_buildx_plugin",
            "endpoint",
            "daemon",
            "buildkit",
            "environment_policy",
            "network_policy",
            "trusted_boundary",
        ),
        label="trusted-builder execution profile",
    )
    if (
        profile["schema_version"]
        != "aegis-ot-m4j-builder-execution-profile-v1"
        or _canonical_sha256(profile) != expected_sha256
        or profile["environment_policy"]
        != {
            "ambient_docker_variables": "excluded",
            "ambient_proxy_variables": "excluded",
            "ambient_path": "excluded",
            "docker_config": "fresh_private_single_pinned_buildx_plugin",
            "buildx_config": "fresh_private_empty",
            "credential_helpers": "excluded_by_empty_config",
            "extra_plugin_directories": "excluded",
            "process_environment_allowlist": [
                "BUILDX_CONFIG",
                "DOCKER_BUILDKIT",
                "DOCKER_CONFIG",
                "DOCKER_HOST",
                "HOME",
                "LANG",
                "LC_ALL",
                "PATH",
                "TMPDIR",
            ],
        }
        or profile["network_policy"]
        != {
            "client_endpoint": "explicit_unix_socket_only",
            "base_pull": "registry_network_for_exact_digest_pin_only",
            "build_network": "profiled_daemon_default_network",
        }
        or profile["trusted_boundary"]
        != (
            "The exact profiled Docker daemon and BuildKit worker are explicitly "
            "trusted to execute the signed build recipe correctly; this attestation "
            "does not independently derive or prove their behavior."
        )
    ):
        _fail("trusted-builder execution profile policy or digest differs")
    client = profile["docker_client"]
    buildx_plugin = profile["docker_buildx_plugin"]
    endpoint = profile["endpoint"]
    daemon = profile["daemon"]
    buildkit = profile["buildkit"]
    if not all(
        isinstance(value, dict)
        for value in (client, buildx_plugin, endpoint, daemon, buildkit)
    ):
        _fail("trusted-builder execution profile components are malformed")
    _exact_fields(
        cast(dict[str, Any], client),
        (
            "path",
            "sha256",
            "size_bytes",
            "uid",
            "gid",
            "mode",
            "execution",
            "reported_version",
            "reported_git_commit",
            "reported_os",
            "reported_architecture",
        ),
        label="trusted-builder Docker client",
    )
    _exact_fields(
        cast(dict[str, Any], buildx_plugin),
        ("path", "sha256", "size_bytes", "uid", "gid", "mode", "execution"),
        label="trusted-builder Docker Buildx plugin",
    )
    _exact_fields(
        cast(dict[str, Any], endpoint),
        ("transport", "path", "uid", "gid", "mode"),
        label="trusted-builder Docker endpoint",
    )
    _exact_fields(
        cast(dict[str, Any], daemon),
        (
            "id",
            "name",
            "driver",
            "version",
            "git_commit",
            "os",
            "architecture",
            "information_architecture",
            "platform_name",
            "security_options",
        ),
        label="trusted-builder Docker daemon",
    )
    _exact_fields(
        cast(dict[str, Any], buildkit),
        ("buildx_version", "builder_name", "driver", "nodes"),
        label="trusted-builder BuildKit profile",
    )
    nodes = cast(dict[str, Any], buildkit)["nodes"]
    if not isinstance(nodes, list) or not nodes:
        _fail("trusted-builder BuildKit node identities are absent")
    identities: set[tuple[str, str]] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            _fail("trusted-builder BuildKit node is malformed")
        _exact_fields(
            node,
            ("name", "endpoint", "status", "buildkit_version", "platforms"),
            label=f"trusted-builder BuildKit node {index}",
        )
        identity = (node.get("name"), node.get("endpoint"))
        status = node.get("status")
        if (
            not all(isinstance(value, str) and value for value in identity)
            or not isinstance(status, str)
            or status.casefold() != "running"
            or identity in identities
        ):
            _fail("trusted-builder BuildKit node identity or state is invalid")
        identities.add(cast(tuple[str, str], identity))
    if (
        cast(dict[str, Any], endpoint).get("transport") != "unix"
        or not Path(cast(str, cast(dict[str, Any], endpoint).get("path"))).is_absolute()
        or SHA256.fullmatch(cast(str, cast(dict[str, Any], client).get("sha256")))
        is None
        or cast(dict[str, Any], client).get("execution")
        != "private_exact_byte_copy"
        or SHA256.fullmatch(
            cast(str, cast(dict[str, Any], buildx_plugin).get("sha256"))
        )
        is None
        or cast(dict[str, Any], buildx_plugin).get("execution")
        != "private_exact_byte_copy"
    ):
        _fail("trusted-builder Docker client or endpoint identity is malformed")
    return cast(dict[str, Any], profile)


def _verify_builder_attestation(
    *,
    manifest: dict[str, Any],
    trusted_public_key: bytes,
    expected_builder_profile_sha256: str,
    builder_helper: dict[str, Any],
) -> tuple[str, str]:
    if len(trusted_public_key) != 32:
        _fail("an explicit raw Ed25519 trusted-builder public key is required")
    key_id = hashlib.sha256(trusted_public_key).hexdigest()
    attestation = manifest.get("builder_attestation")
    if not isinstance(attestation, dict):
        _fail("accepted bundle lacks trusted-builder provenance")
    _exact_fields(
        attestation,
        (
            "schema_version",
            "algorithm",
            "key_id",
            "statement_sha256",
            "statement",
            "signature_base64",
        ),
        label="trusted-builder attestation",
    )
    statement = attestation.get("statement")
    if not isinstance(statement, dict):
        _fail("trusted-builder provenance statement is malformed")
    statement_builder = statement.get("builder")
    if not isinstance(statement_builder, dict):
        _fail("trusted-builder provenance identity is malformed")
    builder_profile = _validate_builder_execution_profile(
        statement_builder.get("execution_profile"),
        expected_sha256=expected_builder_profile_sha256,
    )
    if (
        statement_builder.get("execution_profile_sha256")
        != expected_builder_profile_sha256
    ):
        _fail("trusted-builder provenance profile digest differs")
    expected_statement = _builder_provenance_statement(
        source=cast(dict[str, Any], manifest["source"]),
        image=cast(dict[str, Any], manifest["application_image"]),
        build_contract=cast(dict[str, Any], manifest["build_contract"]),
        tools=cast(dict[str, Any], manifest["tool_versions"]),
        builder_helper=builder_helper,
        builder_profile=builder_profile,
        key_id=key_id,
    )
    material = _canonical_bytes(expected_statement)
    if (
        attestation.get("schema_version")
        != "aegis-ot-m4j-builder-attestation-v1"
        or attestation.get("algorithm") != "Ed25519"
        or attestation.get("key_id") != key_id
        or attestation.get("statement_sha256")
        != hashlib.sha256(material).hexdigest()
        or statement != expected_statement
    ):
        _fail("trusted-builder provenance does not bind the exact bundle inputs/output")
    encoded_signature = attestation.get("signature_base64")
    if not isinstance(encoded_signature, str):
        _fail("trusted-builder provenance signature is malformed")
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except ValueError as exc:
        raise WorkloadContractError(
            "trusted-builder provenance signature is not canonical base64"
        ) from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded_signature:
        _fail("trusted-builder provenance signature is malformed")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
            signature,
            material,
        )
    except (InvalidSignature, ValueError) as exc:
        raise WorkloadContractError(
            "trusted-builder provenance signature is invalid"
        ) from exc
    return key_id, expected_builder_profile_sha256


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader rejecting duplicate keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise WorkloadContractError("YAML mapping key is not hashable") from exc
        if duplicate:
            _fail(f"duplicate YAML mapping key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_yaml(path: Path, *, label: str) -> dict[str, Any]:
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            _fail(f"{label} exceeds its size limit")
        loader = _UniqueKeyLoader(path.read_text(encoding="utf-8"))
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise WorkloadContractError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} root must be a string-keyed mapping")
    return cast(dict[str, Any], value)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_canonical_json(
    path: Path,
    *,
    label: str,
    maximum: int = 4 * 1024 * 1024,
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            _fail(f"{label} must be a regular non-symlink file")
        if metadata.st_size <= 0 or metadata.st_size > maximum:
            _fail(f"{label} size is invalid")
        material = path.read_bytes()
        value = json.loads(
            material.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda item: _fail(f"forbidden JSON constant: {item}"),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkloadContractError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        _fail(f"{label} root must be an object")
    if material != _canonical_bytes(value) + b"\n":
        _fail(f"{label} must use canonical JSON with one trailing newline")
    return cast(dict[str, Any], value)


def _exact_fields(value: dict[str, Any], fields: Sequence[str], *, label: str) -> None:
    if set(value) != set(fields):
        _fail(
            f"{label} fields differ: missing={sorted(set(fields) - set(value))}, "
            f"unknown={sorted(set(value) - set(fields))}"
        )


def _real_private_directory(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise WorkloadContractError(f"{label} is unavailable") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{label} must be a non-symlink directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        _fail(f"{label} must have mode 0700")
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    _fail(f"{label} must remain outside the checkout")


def _regular_evidence(path: Path, *, maximum: int) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WorkloadContractError(f"artifact is unavailable: {path.name}") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        _fail(f"artifact must be a regular non-symlink file: {path.name}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        _fail(f"artifact size is invalid: {path.name}")
    digest = hashlib.sha256()
    observed_size = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                observed_size += len(chunk)
                if observed_size > maximum:
                    _fail(f"artifact exceeds its size limit: {path.name}")
                digest.update(chunk)
    except OSError as exc:
        raise WorkloadContractError(f"artifact cannot be read: {path.name}") from exc
    if observed_size != metadata.st_size:
        _fail(f"artifact changed while it was hashed: {path.name}")
    return {
        "path": path.name,
        "sha256": digest.hexdigest(),
        "size_bytes": observed_size,
    }


def _validate_binding(
    binding: object,
    *,
    label: str,
    path: str,
    schema: str,
    digest: str,
) -> None:
    if not isinstance(binding, dict):
        _fail(f"{label} binding must be a mapping")
    value = cast(dict[str, Any], binding)
    _exact_fields(value, ("path", "schema_version", "canonical_sha256"), label=label)
    if value != {"path": path, "schema_version": schema, "canonical_sha256": digest}:
        _fail(f"{label} binding differs from the authoritative contract")


def _service_listener_check(
    name: str,
    service: dict[str, Any],
    deployment: dict[str, Any],
) -> None:
    listener_name = service["listener"]
    if listener_name is None:
        if name != "agent-probe":
            _fail(f"service {name} unexpectedly lacks a listener")
        return
    listeners = cast(dict[str, dict[str, Any]], deployment["listeners"])
    if listener_name not in listeners:
        _fail(f"service {name} references an unknown listener")
    listener = listeners[listener_name]
    if listener["role"] != service["role"] or listener["service"] != name:
        _fail(f"service {name} listener placement differs from deployment.yml")
    command = cast(list[str], service["command"])
    command_text = "\x00".join(command)
    if (
        str(listener["bind_address"]) not in command_text
        or str(listener["port"]) not in command_text
    ):
        _fail(f"service {name} command does not bind its exact contracted endpoint")


def _flag_values(command: list[str], flag: str) -> list[str]:
    values: list[str] = []
    for index, argument in enumerate(command):
        if argument != flag:
            continue
        if index + 1 >= len(command) or command[index + 1].startswith("--"):
            _fail(f"command flag {flag} lacks one value")
        values.append(command[index + 1])
    return values


def _validate_service_inputs(name: str, service: dict[str, Any]) -> None:
    command = cast(list[str], service["command"])
    environment = cast(dict[str, str], service["environment"])
    if any(UNIT_ARGUMENT.fullmatch(argument) is None for argument in command):
        _fail(f"service {name} contains a systemd-unsafe command argument")
    for key, value in environment.items():
        if ENVIRONMENT_NAME.fullmatch(key) is None:
            _fail(f"service {name} contains an unsafe environment name")
        if (
            not value
            or len(value) > 4096
            or any(ord(character) < 33 or ord(character) > 126 for character in value)
            or "%" in value
        ):
            _fail(f"service {name} contains an unsafe environment value")

    secret_files = service["secret_files"]
    identity_files = service["identity_files"]
    state_mounts = service["state_mounts"]
    if any(
        not isinstance(filename, str)
        or LEAF_NAME.fullmatch(filename) is None
        or filename not in EXPECTED_SECRET_FILES
        or filename.startswith("workload_authority.")
        for filename in secret_files
    ):
        _fail(f"service {name} secret input is outside the private package contract")
    if any(
        not isinstance(filename, str)
        or LEAF_NAME.fullmatch(filename) is None
        or f"identity/{filename}" not in EXPECTED_SECRET_FILES
        for filename in identity_files
    ):
        _fail(f"service {name} identity input is outside the public identity contract")
    if len(secret_files) != len(set(secret_files)) or len(identity_files) != len(
        set(identity_files)
    ):
        _fail(f"service {name} repeats a secret or identity input")
    if any(
        not isinstance(mount, dict)
        or set(mount) != {"host", "container"}
        or not isinstance(mount["host"], str)
        or STATE_NAME.fullmatch(mount["host"]) is None
        or not isinstance(mount["container"], str)
        or ABSOLUTE_CONTAINER_PATH.fullmatch(mount["container"]) is None
        or ".." in PurePosixPath(mount["container"]).parts
        for mount in state_mounts
    ):
        _fail(f"service {name} state mount is unsafe")
    if len({mount["host"] for mount in state_mounts}) != len(state_mounts) or len(
        {mount["container"] for mount in state_mounts}
    ) != len(state_mounts):
        _fail(f"service {name} repeats a state mount")

    supplied_paths = {
        *(f"/run/secrets/{filename}" for filename in secret_files),
        *(f"/run/aegis-identity/{filename}" for filename in identity_files),
    }
    state_roots = tuple(f"{mount['container']}/" for mount in state_mounts)
    for key, value in environment.items():
        if not key.endswith("_FILE"):
            continue
        if value in supplied_paths:
            continue
        if any(value.startswith(root) for root in state_roots):
            continue
        _fail(f"service {name} file input {key} is not backed by a declared mount")


def _validate_mtls_edges(
    services: dict[str, dict[str, Any]],
    registrations: dict[str, dict[str, Any]],
    deployment: dict[str, Any],
) -> None:
    listeners = cast(dict[str, dict[str, Any]], deployment["listeners"])
    mtls_edges = [
        edge
        for edge in cast(list[dict[str, Any]], deployment["peer_edges"])
        if edge["authentication"] == "spiffe_mtls"
    ]
    expected_outbound = {
        source: {
            cast(str, listeners[edge["destination_listener"]]["service"])
            for edge in mtls_edges
            if edge["source_service"] == source
        }
        for source in MTLS_OUTBOUND_ENVIRONMENTS
    }
    if any(
        expected_outbound[source] != set(destinations)
        for source, destinations in MTLS_OUTBOUND_ENVIRONMENTS.items()
    ):
        _fail("SPIRE-mTLS outbound services differ from deployment peer edges")

    for source, destinations in MTLS_OUTBOUND_ENVIRONMENTS.items():
        service = services[source]
        environment = cast(dict[str, str], service["environment"])
        aliases = cast(dict[str, str], service["host_aliases"])
        try:
            peer_ids = json.loads(
                environment["AEGIS_SPIFFE_PEER_IDS"],
                object_pairs_hook=_unique_json_object,
            )
        except (KeyError, json.JSONDecodeError) as exc:
            raise WorkloadContractError(
                f"service {source} lacks a valid SPIFFE peer map"
            ) from exc
        if not isinstance(peer_ids, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in peer_ids.items()
        ):
            _fail(f"service {source} SPIFFE peer map is malformed")
        if environment["AEGIS_SPIFFE_PEER_IDS"].encode("ascii") != _canonical_bytes(
            peer_ids
        ):
            _fail(f"service {source} SPIFFE peer map must be canonical JSON")
        expected_aliases: dict[str, str] = {}
        expected_peer_ids: dict[str, str] = {}
        for destination, variable in destinations.items():
            listener_name = cast(str, services[destination]["listener"])
            listener = listeners[listener_name]
            hostname = f"{destination}.m4j.internal"
            expected_url = f"https://{hostname}:{listener['port']}"
            if environment.get(variable) != expected_url:
                _fail(f"service {source} URL for {destination} differs from its edge")
            expected_aliases[hostname] = cast(str, listener["bind_address"])
            expected_peer_ids[hostname] = cast(str, registrations[destination]["spiffe_id"])
        if aliases != expected_aliases or peer_ids != expected_peer_ids:
            _fail(f"service {source} aliases or SPIFFE peer IDs differ from its edges")

    for destination in (
        "policy-relay",
        "observer",
        "candidate",
        "ot-adapter",
        "plant",
    ):
        command = cast(list[str], services[destination]["command"])
        registration = registrations[destination]
        if _flag_values(command, "--expected-spiffe-id") != [
            registration["spiffe_id"]
        ]:
            _fail(f"service {destination} does not require its exact SPIFFE ID")
        allowed = set(_flag_values(command, "--allowed-client-spiffe-id"))
        expected_allowed = {
            cast(str, registrations[edge["source_service"]]["spiffe_id"])
            for edge in mtls_edges
            if listeners[edge["destination_listener"]]["service"] == destination
        }
        if allowed != expected_allowed or len(allowed) != len(
            _flag_values(command, "--allowed-client-spiffe-id")
        ):
            _fail(f"service {destination} client SPIFFE allowlist differs from its edges")

    for name, registration in registrations.items():
        service = services[name]
        environment = cast(dict[str, str], service["environment"])
        command = cast(list[str], service["command"])
        if environment.get("SPIFFE_ENDPOINT_SOCKET") != (
            "unix:///run/spire/agent/public/api.sock"
        ):
            _fail(f"service {name} does not use its host-local SPIRE Workload API")
        if name != "agent-probe" and environment.get("AEGIS_SPIFFE_ID") != registration[
            "spiffe_id"
        ]:
            _fail(f"service {name} environment SPIFFE ID differs from registration")
        expected_values = _flag_values(command, "--expected-spiffe-id")
        expected_launch_ids = (
            [registration["spiffe_id"], registration["spiffe_id"]]
            if name == "segmented-gateway"
            else [registration["spiffe_id"]]
        )
        if expected_values != expected_launch_ids:
            _fail(f"service {name} launch identity differs from registration")

    agent = services["agent-probe"]
    agent_environment = cast(dict[str, str], agent["environment"])
    gateway = services["segmented-gateway"]
    if (
        agent_environment.get("AEGIS_GATEWAY_URL")
        != "https://segmented-gateway.m4j.internal:8081"
        or agent_environment.get("AEGIS_SPIFFE_ID")
        != registrations["agent-probe"]["spiffe_id"]
        or agent_environment.get("AEGIS_SPIRE_MTLS_MODE") != "required"
        or agent_environment.get("AEGIS_SPIRE_MTLS_TMPDIR")
        != "/run/aegis-spire-mtls"
        or agent_environment.get("AEGIS_SPIFFE_PEER_IDS")
        != _canonical_bytes(
            {
                "segmented-gateway.m4j.internal": registrations[
                    "segmented-gateway"
                ]["spiffe_id"]
            }
        ).decode("ascii")
        or _flag_values(
            cast(list[str], gateway["command"]),
            "--allowed-client-spiffe-id",
        )
        != [registrations["agent-probe"]["spiffe_id"]]
        or "aegis_ot.spire_mtls" not in gateway["command"]
    ):
        _fail("agent-to-gateway transport is not exact bidirectional SPIRE mTLS")


def _validate_contract(
    workload_path: Path,
    deployment_path: Path,
    topology_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, str]]:
    deployment_validator = _load_deployment_validator()
    try:
        bindings = cast(
            dict[str, str],
            deployment_validator.validate(deployment_path, topology_path),
        )
    except Exception as exc:
        raise WorkloadContractError(f"authoritative M4j contracts are invalid: {exc}") from exc
    topology = _load_yaml(topology_path, label="M4j topology")
    deployment = _load_yaml(deployment_path, label="M4j deployment")
    workload = _load_yaml(workload_path, label="M4j workload contract")
    _exact_fields(
        workload,
        (
            "schema_version",
            "deployment_status",
            "claim_boundary",
            "orchestration",
            "topology_binding",
            "deployment_binding",
            "bundle_contract",
            "runtime_image_bundle_contract",
            "live_probe_contract",
            "trust_domain",
            "runtime_images",
            "node_bootstrap",
            "registrations",
            "services",
        ),
        label="workload contract",
    )
    if (
        workload["schema_version"] != "aegis-ot-m4j-workloads-v1"
        or workload["deployment_status"] != "configuration_only"
        or workload["claim_boundary"]
        != "no_live_deployment_or_multi_host_isolation_evidence"
    ):
        _fail("workload contract claim boundary is unsupported")
    if workload["orchestration"] != ORCHESTRATION_CONTRACT:
        _fail("workload orchestration engine or distribution pin differs")
    _validate_binding(
        workload["topology_binding"],
        label="topology",
        path="infra/m4j/topology.yml",
        schema="aegis-ot-m4j-topology-v1",
        digest=bindings["topology_canonical_sha256"],
    )
    _validate_binding(
        workload["deployment_binding"],
        label="deployment",
        path="infra/m4j/deployment.yml",
        schema="aegis-ot-m4j-deployment-v2",
        digest=bindings["canonical_sha256"],
    )
    if workload["trust_domain"] != "aegis-ot.m4g.local":
        _fail("M4j trust domain differs from the closed identity contract")
    if not isinstance(workload["runtime_images"], dict) or workload[
        "runtime_images"
    ] != RUNTIME_IMAGE_REFS or any(
        PINNED_IMAGE.fullmatch(value) is None
        for value in cast(dict[str, str], workload["runtime_images"]).values()
    ):
        _fail("runtime images must retain exact name, version, and digest pins")
    bundle = cast(dict[str, Any], workload["bundle_contract"])
    if bundle != {
        "schema_version": "m4j-exact-source-application-image-bundle-v2",
        "accepted_deploy_bundle_required": True,
        "trusted_builder_public_key": "out_of_band_required",
        "source_archive": "source.tar",
        "application_image_archive": "application-image.tar",
        "manifest": "manifest.json",
        "mutable_worktree_allowed": False,
    }:
        _fail("exact-source application bundle contract differs")
    if workload["runtime_image_bundle_contract"] != RUNTIME_IMAGE_BUNDLE_CONTRACT:
        _fail("immutable third-party runtime image bundle contract differs")
    if workload["live_probe_contract"] != LIVE_PROBE_CONTRACT:
        _fail("bounded live workload probe contract differs")

    bootstrap = cast(dict[str, Any], workload["node_bootstrap"])
    _exact_fields(
        bootstrap,
        (
            "attestor",
            "token_ttl_seconds",
            "workload_svid_ttl_seconds",
            "delivery_path",
            "delivery_logging",
            "token_cleanup",
            "agent_state_sharing_allowed",
            "join_material_sharing_allowed",
            "agents",
        ),
        label="node_bootstrap",
    )
    if (
        bootstrap["attestor"] != "join_token"
        or bootstrap["token_ttl_seconds"] != 300
        or bootstrap["workload_svid_ttl_seconds"] != 300
        or bootstrap["delivery_path"] != "ansible_ssh_over_management"
        or bootstrap["delivery_logging"] != "suppressed"
        or bootstrap["token_cleanup"] != TOKEN_CLEANUP_POLICY
        or bootstrap["agent_state_sharing_allowed"] is not False
        or bootstrap["join_material_sharing_allowed"] is not False
    ):
        _fail("node bootstrap is not the closed one-time private contract")
    agents = cast(dict[str, dict[str, Any]], bootstrap["agents"])
    if tuple(agents) != AGENT_ROLES:
        _fail("exactly five non-management SPIRE agents are required")
    all_paths: set[str] = set()
    all_node_ids: set[str] = set()
    for role, agent in agents.items():
        _exact_fields(
            agent,
            ("spiffe_id", "data_directory", "socket_directory", "bootstrap_directory"),
            label=f"agent {role}",
        )
        expected_id = f"spiffe://aegis-ot.m4g.local/agent/{role}"
        if agent["spiffe_id"] != expected_id:
            _fail(f"agent {role} does not use its host-bound SPIFFE ID")
        paths = [
            agent[key]
            for key in ("data_directory", "socket_directory", "bootstrap_directory")
        ]
        if any(not isinstance(path, str) or f"/{role}" not in path for path in paths):
            _fail(f"agent {role} paths are not role-distinct")
        if any(
            ABSOLUTE_CONTAINER_PATH.fullmatch(cast(str, path)) is None
            or ".." in PurePosixPath(cast(str, path)).parts
            for path in paths
        ):
            _fail(f"agent {role} path is not a safe absolute host path")
        if any(path in all_paths for path in paths) or expected_id in all_node_ids:
            _fail("SPIRE agent state or identity is shared")
        all_paths.update(paths)
        all_node_ids.add(expected_id)

    registrations = cast(dict[str, dict[str, Any]], workload["registrations"])
    services = cast(dict[str, dict[str, Any]], workload["services"])
    if tuple(registrations) != REGISTRATION_NAMES or tuple(services) != SERVICE_NAMES:
        _fail("workload service or registration names differ from the closed contract")
    seen_entry_ids: set[str] = set()
    seen_spiffe_ids: set[str] = set()
    seen_selectors: set[tuple[str, int, int]] = set()
    for name, registration in registrations.items():
        _exact_fields(
            registration,
            ("role", "entry_id", "parent_id", "spiffe_id", "uid", "gid"),
            label=f"registration {name}",
        )
        role = registration["role"]
        expected_role, expected_entry_id, expected_spiffe_id, expected_gid = (
            EXPECTED_REGISTRATIONS[name]
        )
        if registration != {
            "role": expected_role,
            "entry_id": expected_entry_id,
            "parent_id": f"spiffe://aegis-ot.m4g.local/agent/{expected_role}",
            "spiffe_id": expected_spiffe_id,
            "uid": 65532,
            "gid": expected_gid,
        }:
            _fail(f"registration {name} differs from its exact host identity mapping")
        if role not in agents or registration["parent_id"] != agents[role]["spiffe_id"]:
            _fail(f"registration {name} is not parent-bound to its host agent")
        if (
            registration["entry_id"] in seen_entry_ids
            or registration["spiffe_id"] in seen_spiffe_ids
        ):
            _fail("workload registration identity is duplicated")
        selector = (cast(str, role), registration["uid"], registration["gid"])
        if selector in seen_selectors or registration["uid"] != 65532:
            _fail("workload Unix selector is duplicated or unexpected")
        if not isinstance(registration["gid"], int) or not 65532 <= registration["gid"] <= 65538:
            _fail("workload Unix GID selector is outside the closed range")
        seen_entry_ids.add(cast(str, registration["entry_id"]))
        seen_spiffe_ids.add(cast(str, registration["spiffe_id"]))
        seen_selectors.add(selector)

    deployment_roles = cast(dict[str, dict[str, Any]], deployment["roles"])
    for name, service in services.items():
        _exact_fields(
            service,
            (
                "role",
                "activation",
                "image",
                "listener",
                "registration",
                "command",
                "environment",
                "host_aliases",
                "secret_files",
                "identity_files",
                "state_mounts",
            ),
            label=f"service {name}",
        )
        role = service["role"]
        if role not in AGENT_ROLES or name not in deployment_roles[role]["workloads"]:
            _fail(f"service {name} placement differs from deployment.yml")
        if service["activation"] not in {"continuous", "manual_probe"}:
            _fail(f"service {name} activation is unsupported")
        if (name == "agent-probe") != (service["activation"] == "manual_probe"):
            _fail("agent-probe must be the sole manual service")
        if service["image"] not in {"application", "opa"}:
            _fail(f"service {name} image selector is unsupported")
        if (name == "opa") != (service["image"] == "opa"):
            _fail("OPA must be the sole non-application workload image")
        command = service["command"]
        environment = service["environment"]
        aliases = service["host_aliases"]
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(item, str) or not item for item in command)
            or not isinstance(environment, dict)
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in environment.items()
            )
            or not isinstance(aliases, dict)
        ):
            _fail(f"service {name} command, environment, or aliases are malformed")
        for field in ("secret_files", "identity_files", "state_mounts"):
            if not isinstance(service[field], list):
                _fail(f"service {name} {field} must be a list")
        for hostname, address in aliases.items():
            try:
                canonical_address = str(ipaddress.ip_address(cast(str, address)))
            except (TypeError, ValueError):
                canonical_address = ""
            if (
                not isinstance(hostname, str)
                or HOST_ALIAS.fullmatch(hostname) is None
                or not isinstance(address, str)
                or canonical_address != address
                or address not in {
                    ip
                    for node in cast(dict[str, dict[str, Any]], topology["nodes"]).values()
                    for ip in cast(dict[str, str], node["interfaces"]).values()
                }
            ):
                _fail(f"service {name} has an unsafe host alias")
        for value in cast(dict[str, str], environment).values():
            placeholder = PLACEHOLDER.fullmatch(value)
            if value.startswith("${") and placeholder is None:
                _fail(f"service {name} contains an unsupported environment placeholder")
        _validate_service_inputs(name, service)
        _service_listener_check(name, service, deployment)
        registration_name = service["registration"]
        if name == "opa":
            if registration_name is not None:
                _fail("loopback OPA must not receive a SPIFFE registration")
        elif registration_name != name or registrations[name]["role"] != role:
            _fail(f"service {name} registration differs from placement")
    if services["opa"]["command"] != [
        "run",
        "--server",
        "--addr=127.0.0.1:8182",
        "/policy",
    ]:
        _fail("OPA must bind only loopback port 8182")
    relay = services["policy-relay"]
    if (
        relay["environment"].get("AEGIS_OPA_BACKEND_URL") != "http://127.0.0.1:8182"
        or "aegis_ot.policy_relay:policy_relay_app" not in relay["command"]
    ):
        _fail("policy relay does not enforce the loopback OPA backend")
    for name in ("policy-relay", "observer", "candidate", "ot-adapter", "plant"):
        if "aegis_ot.spire_mtls" not in services[name]["command"]:
            _fail(f"service {name} is not externally wrapped by SPIRE mTLS")
    if "aegis_ot.spire_workload_identity" not in services["segmented-gateway"]["command"]:
        _fail("gateway does not verify its local SPIRE identity")
    if "aegis_ot.spire_workload_identity" not in services["agent-probe"]["command"]:
        _fail("agent probe does not verify its local SPIRE identity")
    if services["agent-probe"]["host_aliases"] != AGENT_PROBE_BYPASS_ALIASES:
        _fail("agent probe bypass targets differ from the closed topology")
    _validate_mtls_edges(services, registrations, deployment)
    return workload, deployment, topology, bindings


def _validate_bundle(
    bundle_directory: Path,
    expected_commit: str,
    trusted_builder_public_key: bytes,
    expected_builder_profile_sha256: str,
) -> dict[str, Any]:
    root = _real_private_directory(bundle_directory, label="M4j application bundle")
    manifest = _load_canonical_json(root / "manifest.json", label="bundle manifest")
    _exact_fields(
        manifest,
        (
            "schema_version",
            "mode",
            "accepted_deploy_bundle",
            "source",
            "application_image",
            "build_contract",
            "tool_versions",
            "builder_attestation",
            "distribution_boundary",
        ),
        label="application bundle manifest",
    )
    if (
        manifest.get("schema_version") != "m4j-exact-source-application-image-bundle-v2"
        or manifest.get("mode") != "build"
        or manifest.get("accepted_deploy_bundle") is not True
    ):
        _fail("bundle is not an accepted exact-source build bundle")
    source = manifest.get("source")
    image = manifest.get("application_image")
    if not isinstance(source, dict) or not isinstance(image, dict):
        _fail("bundle source or image evidence is malformed")
    _exact_fields(
        source,
        (
            "requested_reference",
            "git_commit",
            "git_tree",
            "git_object_format",
            "commit_object_base64",
            "committed_at",
            "context_origin",
            "mutable_worktree_used",
            "archive",
            "archived_file_count",
            "archived_inputs",
            "topology_contract",
            "secret_like_member_count",
            "tree_binding",
        ),
        label="application bundle source",
    )
    _exact_fields(
        image,
        (
            "image_built",
            "build_invocations",
            "tag",
            "image_id",
            "build_invocation",
            "repo_digests",
            "oci_revision",
            "platform",
            "archive",
            "archive_binding",
        ),
        label="application bundle image",
    )
    build_contract = manifest.get("build_contract")
    tools = manifest.get("tool_versions")
    if not isinstance(build_contract, dict) or not isinstance(tools, dict):
        _fail("bundle build contract or tool provenance is malformed")
    _exact_fields(
        build_contract,
        (
            "dockerfile",
            "install_target",
            "pinned_base_image",
            "source_revision_build_argument",
            "target_platform",
            "tag_policy",
            "buildkit_default_provenance",
            "docker_build_secret_mount_count",
            "docker_build_secret_mount_scope",
        ),
        label="application bundle build contract",
    )
    if (
        source.get("git_commit") != expected_commit
        or source.get("context_origin") != "git_archive_of_exact_commit"
        or source.get("mutable_worktree_used") is not False
        or image.get("image_built") is not True
        or not isinstance(image.get("build_invocations"), int)
        or isinstance(image.get("build_invocations"), bool)
        or image.get("build_invocations") != 1
        or image.get("tag") is not None
        or re.fullmatch(r"[0-9a-f]{64}", cast(str, image.get("build_invocation", "")))
        is None
        or not isinstance(image.get("repo_digests"), list)
        or any(
            not isinstance(value, str)
            or re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", value) is None
            for value in image.get("repo_digests", [])
        )
        or IMAGE_ID.fullmatch(cast(str, image.get("image_id", ""))) is None
        or image.get("oci_revision") != expected_commit
        or image.get("platform")
        != {"os": "linux", "architecture": "amd64", "variant": None}
        or not isinstance(source.get("archived_file_count"), int)
        or isinstance(source.get("archived_file_count"), bool)
        or source.get("archived_file_count", 0) <= 0
        or tools.get("builder")
        != "m4j-exact-source-application-image-bundle-v2"
        or not all(
            isinstance(key, str) and isinstance(value, str) and value
            for key, value in tools.items()
        )
    ):
        _fail("bundle source/image binding differs from the requested exact commit")
    expected_names = {"manifest.json", "source.tar", "application-image.tar"}
    if {path.name for path in root.iterdir()} != expected_names:
        _fail("bundle contains partial or extra artifacts")
    evidence: dict[str, dict[str, Any]] = {}
    for name, declared, maximum in (
        ("source.tar", source.get("archive"), 512 * 1024 * 1024),
        ("application-image.tar", image.get("archive"), 8 * 1024 * 1024 * 1024),
    ):
        observed = _regular_evidence(root / name, maximum=maximum)
        if observed != declared:
            _fail(f"bundle artifact evidence differs: {name}")
        evidence[name] = observed
    evidence["manifest.json"] = _regular_evidence(
        root / "manifest.json",
        maximum=4 * 1024 * 1024,
    )
    bundle_validator = _load_bundle_validator()
    source_context = Path(tempfile.mkdtemp(prefix="aegis-m4j-source-verify-"))
    source_context.chmod(0o700)
    try:
        tree_binding = bundle_validator._validate_source_archive_binding(
            root / "source.tar",
            expected_commit=expected_commit,
            source_binding=source,
        )
        archived_files = bundle_validator._safe_extract_source(
            root / "source.tar",
            source_context / "context",
        )
        archived_inputs = bundle_validator._archived_input_evidence(
            source_context / "context"
        )
        pinned_base_image = bundle_validator._pinned_base_image(
            source_context / "context" / "Dockerfile"
        )
        topology_contract = bundle_validator._validate_m4j_topology(
            source_context / "context" / "infra" / "m4j" / "topology.yml"
        )
        builder_helper = bundle_validator._builder_helper_binding(
            source_context / "context",
            object_format=source["git_object_format"],
        )
        image_binding = bundle_validator._validate_saved_image_archive(
            root / "application-image.tar",
            expected_image_id=image["image_id"],
            expected_commit=expected_commit,
            expected_platform={
                "requested": "linux/amd64",
                "os": "linux",
                "architecture": "amd64",
                "variant": None,
            },
        )
    except Exception as exc:
        raise WorkloadContractError(
            f"bundle cryptographic source/image binding is invalid: {exc}"
        ) from exc
    finally:
        if source_context.exists() and not source_context.is_symlink():
            shutil.rmtree(source_context)
    if (
        source.get("tree_binding") != tree_binding
        or source.get("archived_file_count") != len(archived_files)
        or source.get("archived_inputs") != archived_inputs
        or source.get("topology_contract") != topology_contract
        or source.get("secret_like_member_count") != 0
        or image.get("archive_binding") != image_binding
        or image_binding["repo_tags"] != []
        or image_binding["oci_revision"] != expected_commit
        or image_binding["build_invocation"] != image.get("build_invocation")
        or image_binding["platform"] != image["platform"]
        or image.get("build_invocations") != 1
        or build_contract.get("dockerfile") != "Dockerfile"
        or build_contract.get("install_target") != ".[simulation]"
        or build_contract.get("pinned_base_image") != pinned_base_image
        or build_contract.get("source_revision_build_argument") != expected_commit
        or build_contract.get("target_platform")
        != {
            "requested": "linux/amd64",
            "os": "linux",
            "architecture": "amd64",
            "variant": None,
        }
        or build_contract.get("docker_build_secret_mount_count") != 0
        or build_contract.get("buildkit_default_provenance")
        != "disabled_replaced_by_signed_aegis_attestation"
        or build_contract.get("tag_policy")
        != "untagged_load_saved_by_immutable_image_id"
    ):
        _fail("bundle independently derived source/image evidence differs")
    try:
        with tarfile.open(root / "source.tar", mode="r:") as archive:
            policy_members = [member for member in archive if member.name == "policy/aegis.rego"]
            if len(policy_members) != 1 or not policy_members[0].isfile():
                _fail("exact source archive lacks the regular OPA policy input")
            policy_member = policy_members[0]
            if policy_member.size <= 0 or policy_member.size > OPA_POLICY_MAXIMUM:
                _fail("exact-source OPA policy size is invalid")
            extracted = archive.extractfile(policy_member)
            if extracted is None:
                _fail("exact-source OPA policy could not be read")
            policy_material = extracted.read(OPA_POLICY_MAXIMUM + 1)
    except (OSError, tarfile.TarError) as exc:
        raise WorkloadContractError("source archive cannot be inspected") from exc
    if (
        len(policy_members) != 1
        or not policy_members[0].isfile()
        or PurePosixPath(policy_members[0].name).as_posix() != "policy/aegis.rego"
        or len(policy_material) != policy_members[0].size
    ):
        _fail("exact source archive lacks the regular OPA policy input")
    for name, maximum in (
        ("source.tar", 512 * 1024 * 1024),
        ("application-image.tar", 8 * 1024 * 1024 * 1024),
    ):
        if _regular_evidence(root / name, maximum=maximum) != evidence[name]:
            _fail(f"bundle artifact changed during independent validation: {name}")
    builder_key_id, builder_profile_sha256 = _verify_builder_attestation(
        manifest=manifest,
        trusted_public_key=trusted_builder_public_key,
        expected_builder_profile_sha256=expected_builder_profile_sha256,
        builder_helper=builder_helper,
    )
    return {
        "manifest": manifest,
        "root": str(root),
        "artifacts": evidence,
        "application_image_id": image["image_id"],
        "application_image_platform": image["platform"],
        "builder_attestation_key_id": builder_key_id,
        "builder_profile_sha256": builder_profile_sha256,
        "opa_policy": {
            "path": "policy/aegis.rego",
            "sha256": hashlib.sha256(policy_material).hexdigest(),
            "size_bytes": len(policy_material),
        },
    }


def _validate_runtime_images(runtime_image_directory: Path) -> dict[str, Any]:
    root = _real_private_directory(
        runtime_image_directory,
        label="M4j third-party runtime image bundle",
    )
    manifest_path = root / "runtime-images-manifest.json"
    manifest = _load_canonical_json(manifest_path, label="runtime image manifest")
    _exact_fields(
        manifest,
        (
            "schema_version",
            "created_at",
            "target_platform",
            "images",
            "distribution_boundary",
        ),
        label="runtime image manifest",
    )
    if (
        manifest["schema_version"] != "aegis-ot-m4j-runtime-images-v1"
        or manifest["target_platform"] != "linux/amd64"
        or manifest["distribution_boundary"]
        != {
            "registry_acquisition": "authenticated_https_by_exact_digest",
            "mutable_tags_used_for_execution": False,
            "deployment_established": False,
        }
    ):
        _fail("runtime image bundle claim or platform boundary differs")
    try:
        created_at = datetime.fromisoformat(cast(str, manifest["created_at"]))
    except (TypeError, ValueError) as exc:
        raise WorkloadContractError("runtime image bundle creation time is malformed") from exc
    if created_at.tzinfo is None or created_at > datetime.now(UTC) + timedelta(minutes=1):
        _fail("runtime image bundle creation time is not an established instant")
    archives = cast(dict[str, str], RUNTIME_IMAGE_BUNDLE_CONTRACT["archives"])
    expected_names = {"runtime-images-manifest.json", *archives.values()}
    if {path.name for path in root.iterdir()} != expected_names:
        _fail("runtime image bundle contains missing or extra artifacts")
    manifest_metadata = manifest_path.lstat()
    if stat.S_IMODE(manifest_metadata.st_mode) != 0o600:
        _fail("runtime image manifest must be private mode 0600")
    images = manifest["images"]
    if not isinstance(images, dict) or set(images) != set(RUNTIME_IMAGE_REFS):
        _fail("runtime image manifest names differ from the exact pins")
    runtime_image_validator = _load_runtime_image_validator()
    validated: dict[str, dict[str, Any]] = {}
    for name, reference in RUNTIME_IMAGE_REFS.items():
        value = images[name]
        if not isinstance(value, dict):
            _fail(f"runtime image evidence is malformed: {name}")
        _exact_fields(
            value,
            (
                "registry_reference",
                "distribution_tag",
                "image_id",
                "platform",
                "registry_binding",
                "archive",
                "archive_binding",
            ),
            label=f"runtime image {name}",
        )
        expected_tag = (
            f"aegis-m4j-runtime/{name}:"
            f"{reference.rsplit('sha256:', maxsplit=1)[1][:16]}"
        )
        if (
            value["registry_reference"] != reference
            or value["distribution_tag"] != expected_tag
            or IMAGE_ID.fullmatch(cast(str, value["image_id"])) is None
            or value["platform"] != "linux/amd64"
        ):
            _fail(f"runtime image {name} does not bind its exact registry digest")
        observed = _regular_evidence(
            root / archives[name],
            maximum=8 * 1024 * 1024 * 1024,
        )
        if (
            stat.S_IMODE((root / archives[name]).lstat().st_mode) != 0o600
            or observed != value["archive"]
        ):
            _fail(f"runtime image archive evidence differs: {name}")
        try:
            archive_binding = runtime_image_validator._validate_saved_runtime_archive(
                root / archives[name],
                reference=reference,
                distribution_tag=expected_tag,
                image_id=value["image_id"],
                registry_binding=value["registry_binding"],
            )
        except Exception as exc:
            raise WorkloadContractError(
                f"runtime image {name} registry/archive binding is invalid: {exc}"
            ) from exc
        if (
            archive_binding != value["archive_binding"]
            or _regular_evidence(
                root / archives[name],
                maximum=8 * 1024 * 1024 * 1024,
            )
            != observed
        ):
            _fail(f"runtime image {name} changed or has self-declared archive evidence")
        validated[name] = {
            "registry_reference": reference,
            "distribution_tag": expected_tag,
            "image_id": value["image_id"],
            "archive": observed,
            "registry_binding": value["registry_binding"],
            "archive_binding": archive_binding,
        }
    if len({value["image_id"] for value in validated.values()}) != len(validated):
        _fail("runtime image bundle repeats an image ID across distinct pins")
    return {"root": str(root), "manifest": manifest, "images": validated}


def _validate_raw_key_pair(secret_root: Path, name: str) -> Ed25519PublicKey:
    private_material = (secret_root / f"{name}.private").read_bytes()
    public_material = (secret_root / f"{name}.public").read_bytes()
    if len(private_material) != 32 or len(public_material) != 32:
        _fail(f"{name} key material must be raw Ed25519 bytes")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(private_material)
        public_key = Ed25519PublicKey.from_public_bytes(public_material)
    except ValueError as exc:
        raise WorkloadContractError(f"{name} key material is invalid") from exc
    if private_key.public_key().public_bytes_raw() != public_key.public_bytes_raw():
        _fail(f"{name} private/public key pair differs")
    return public_key


def _validate_credential(
    path: Path,
    *,
    authority: Ed25519PublicKey,
    public_key: Ed25519PublicKey,
    role: WorkloadRole,
    subject: str,
    audiences: tuple[str, ...],
    now: datetime,
) -> SignedWorkloadCredential:
    credential = load_signed_workload_credential(path)
    claims = credential.credential
    if (
        not credential.verify(authority)
        or claims.trust_domain != "aegis-ot.m4g.local"
        or claims.role is not role
        or claims.subject != subject
        or claims.audiences != tuple(sorted(audiences))
        or claims.key_id != workload_key_id(public_key)
        or claims.not_before > now
        or claims.expires_at - now < MINIMUM_IDENTITY_REMAINING
    ):
        _fail(f"{role.value} workload credential is not currently deployable")
    return credential


def _validate_secrets(secret_directory: Path, expected_commit: str) -> dict[str, Any]:
    root = _real_private_directory(secret_directory, label="M4j secret package")
    manifest_path = root / SECRET_MANIFEST_NAME
    manifest = _load_canonical_json(manifest_path, label="secret manifest")
    _exact_fields(
        manifest,
        (
            "schema_version",
            "source_git_commit",
            "created_at",
            "trust_domain",
            "key_ids",
            "identity",
            "files",
            "distribution_boundary",
        ),
        label="secret manifest",
    )
    if (
        manifest["schema_version"] != "aegis-ot-m4j-deployment-secrets-v1"
        or manifest["source_git_commit"] != expected_commit
        or manifest["trust_domain"] != "aegis-ot.m4g.local"
    ):
        _fail("secret package does not bind the requested source/trust domain")
    try:
        created_at = datetime.fromisoformat(cast(str, manifest["created_at"]))
    except (TypeError, ValueError) as exc:
        raise WorkloadContractError("secret package creation time is malformed") from exc
    if created_at.tzinfo is None or created_at > datetime.now(UTC) + timedelta(minutes=1):
        _fail("secret package creation time is not an established UTC instant")
    distribution = manifest["distribution_boundary"]
    if distribution != {
        "controller_only": ["workload_authority.private"],
        "host_delivery": "least_privilege_per_service_only",
        "join_tokens_included": False,
        "not_established": ["deployment", "runtime_acceptance"],
    }:
        _fail("secret distribution boundary differs from the closed contract")
    discovered = {path.relative_to(root).as_posix() for path in root.rglob("*")}
    expected_entries = {*EXPECTED_SECRET_FILES, "identity", SECRET_MANIFEST_NAME}
    if discovered != expected_entries:
        _fail("secret package contains missing or extra artifacts")
    manifest_metadata = manifest_path.lstat()
    if stat.S_IMODE(manifest_metadata.st_mode) != 0o600:
        _fail("secret manifest must be private mode 0600")
    declared_files = manifest["files"]
    if not isinstance(declared_files, dict) or set(declared_files) != EXPECTED_SECRET_FILES:
        _fail("secret manifest file inventory differs")
    for relative in sorted(EXPECTED_SECRET_FILES):
        path = root / relative
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            _fail(f"secret artifact is not a private regular file: {relative}")
        material = path.read_bytes()
        observed = {
            "path": relative,
            "sha256": hashlib.sha256(material).hexdigest(),
            "size_bytes": len(material),
        }
        if declared_files[relative] != observed:
            _fail(f"secret artifact evidence differs: {relative}")
    identity_dir = root / "identity"
    if identity_dir.is_symlink() or stat.S_IMODE(identity_dir.lstat().st_mode) != 0o700:
        _fail("secret identity directory must be private and non-symlink")

    keys = {
        name: _validate_raw_key_pair(root, name)
        for name in (
            "workload_authority",
            "agent",
            "gateway",
            "ot",
            "permit",
            "observer",
            "candidate",
            "plant",
        )
    }
    if len({key.public_bytes_raw() for key in keys.values()}) != len(keys):
        _fail("deployment signing keys must be distinct")
    key_ids = manifest["key_ids"]
    if not isinstance(key_ids, dict) or key_ids != {
        "workload_authority": workload_key_id(keys["workload_authority"]),
        "agent": workload_key_id(keys["agent"]),
        "gateway": workload_key_id(keys["gateway"]),
        "ot": workload_key_id(keys["ot"]),
        "permit": "m4g-permit-key-v1",
        "observer": "m4g-observer-key-v1",
        "candidate": "m4g-candidate-key-v1",
        "plant": "m4g-plant-key-v1",
    }:
        _fail("secret key identifiers differ from exact public keys or protocol pins")
    if (
        (identity_dir / "authority.public").read_bytes()
        != keys["workload_authority"].public_bytes_raw()
    ):
        _fail("identity authority copy differs from the retained authority key")
    now = datetime.now(UTC)
    trust_bundle = load_workload_trust_bundle(identity_dir / "trust-bundle.json")
    if (
        not trust_bundle.verify(keys["workload_authority"])
        or trust_bundle.trust_domain != "aegis-ot.m4g.local"
        or trust_bundle.authority_key_id != key_ids["workload_authority"]
        or trust_bundle.revocations
        or trust_bundle.issued_at > now
        or trust_bundle.expires_at - now < MINIMUM_IDENTITY_REMAINING
    ):
        _fail("workload trust bundle is not currently deployable")
    credentials = {
        "agent": _validate_credential(
            identity_dir / "agent.credential.json",
            authority=keys["workload_authority"],
            public_key=keys["agent"],
            role=WorkloadRole.AGENT,
            subject="urn:aegis-ot:m4g:workload:agent-probe",
            audiences=(GATEWAY_CAPABILITY_AUDIENCE,),
            now=now,
        ),
        "gateway": _validate_credential(
            identity_dir / "gateway.credential.json",
            authority=keys["workload_authority"],
            public_key=keys["gateway"],
            role=WorkloadRole.GATEWAY,
            subject="urn:aegis-ot:m4g:workload:gateway",
            audiences=(OT_CAPABILITY_AUDIENCE, EFFECT_COORDINATOR_AUDIENCE),
            now=now,
        ),
        "ot-adapter": _validate_credential(
            identity_dir / "ot.credential.json",
            authority=keys["workload_authority"],
            public_key=keys["ot"],
            role=WorkloadRole.OT_ADAPTER,
            subject="urn:aegis-ot:m4g:workload:ot-adapter",
            audiences=(GATEWAY_CAPABILITY_AUDIENCE, GATEWAY_COORDINATION_AUDIENCE),
            now=now,
        ),
    }
    identity_summary = manifest["identity"]
    expected_summary = {
        "authority_key_id": key_ids["workload_authority"],
        "trust_bundle_expires_at": trust_bundle.expires_at.isoformat(),
        "credential_expires_at": {
            name: credential.credential.expires_at.isoformat()
            for name, credential in credentials.items()
        },
    }
    if identity_summary != expected_summary:
        _fail("secret identity summary differs from signed artifacts")
    return {
        "root": str(root),
        "manifest": manifest,
        "key_ids": key_ids,
        "artifacts": declared_files,
    }


def _firewall_plan(
    role: str,
    deployment: dict[str, Any],
    topology: dict[str, Any],
) -> list[dict[str, Any]]:
    listeners = cast(dict[str, dict[str, Any]], deployment["listeners"])
    nodes = cast(dict[str, dict[str, Any]], topology["nodes"])
    rules: list[dict[str, Any]] = []
    for source_name, source in cast(
        dict[str, dict[str, Any]], deployment["external_control_sources"]
    ).items():
        for listener_name in source["destination_listeners"]:
            listener = listeners[listener_name]
            if listener["role"] != role:
                continue
            rules.append(
                {
                    "rule_id": f"external-{source_name}-to-{listener_name}",
                    "network": listener["network"],
                    "source_address": source["source_address"],
                    "destination_address": listener["bind_address"],
                    "port": listener["port"],
                    "protocol": "tcp",
                }
            )
    for edge in cast(list[dict[str, Any]], deployment["peer_edges"]):
        listener = listeners[edge["destination_listener"]]
        network = edge["network"]
        if listener["role"] != role or network == "local":
            continue
        source_role = cast(str, edge["source_role"])
        source_address = nodes[source_role]["interfaces"][network]
        rules.append(
            {
                "rule_id": edge["id"],
                "network": network,
                "source_address": source_address,
                "destination_address": listener["bind_address"],
                "port": listener["port"],
                "protocol": "tcp",
            }
        )
    rule_ids = [rule["rule_id"] for rule in rules]
    if len(rule_ids) != len(set(rule_ids)) or any(rule["port"] is None for rule in rules):
        _fail(f"derived firewall plan for {role} is ambiguous")
    return rules


def _render_environment(environment: dict[str, str], key_ids: dict[str, str]) -> dict[str, str]:
    rendered: dict[str, str] = {}
    for name, value in environment.items():
        placeholder = PLACEHOLDER.fullmatch(value)
        if placeholder is None:
            rendered[name] = value
            continue
        key_name = placeholder.group(1)
        replacement = key_ids.get(key_name)
        if replacement is None:
            _fail(f"secret manifest lacks environment key identifier: {key_name}")
        rendered[name] = replacement
    return rendered


def compile_plan(
    *,
    role: str,
    expected_commit: str,
    bundle_directory: Path,
    runtime_image_directory: Path,
    secret_directory: Path,
    trusted_builder_public_key: bytes,
    expected_builder_profile_sha256: str,
    workload_path: Path = DEFAULT_WORKLOADS,
    deployment_path: Path = DEFAULT_DEPLOYMENT,
    topology_path: Path = DEFAULT_TOPOLOGY,
) -> dict[str, Any]:
    if role not in ROLES:
        _fail("M4j role is unsupported")
    if GIT_OBJECT.fullmatch(expected_commit) is None:
        _fail("expected source commit must be a full lowercase Git object ID")
    workload, deployment, topology, bindings = _validate_contract(
        workload_path,
        deployment_path,
        topology_path,
    )
    bundle = _validate_bundle(
        bundle_directory,
        expected_commit,
        trusted_builder_public_key,
        expected_builder_profile_sha256,
    )
    runtime_images = _validate_runtime_images(runtime_image_directory)
    secrets = _validate_secrets(secret_directory, expected_commit)
    bootstrap = cast(dict[str, Any], workload["node_bootstrap"])
    registrations = cast(dict[str, dict[str, Any]], workload["registrations"])
    raw_services = cast(dict[str, dict[str, Any]], workload["services"])
    services: list[dict[str, Any]] = []
    for name, service in raw_services.items():
        if service["role"] != role:
            continue
        registration = registrations.get(cast(str, service["registration"]))
        image = (
            bundle["application_image_id"]
            if service["image"] == "application"
            else runtime_images["images"]["opa"]["image_id"]
        )
        services.append(
            {
                "name": name,
                "container_name": f"aegis-m4j-{name}",
                "activation": service["activation"],
                "image": image,
                "listener": (
                    cast(dict[str, Any], deployment["listeners"])[service["listener"]]
                    if service["listener"] is not None
                    else None
                ),
                "uid": registration["uid"] if registration else 65532,
                "gid": registration["gid"] if registration else 65532,
                "command": service["command"],
                "environment": _render_environment(
                    cast(dict[str, str], service["environment"]),
                    cast(dict[str, str], secrets["key_ids"]),
                ),
                "host_aliases": service["host_aliases"],
                "secret_files": service["secret_files"],
                "identity_files": [
                    f"identity/{filename}" for filename in service["identity_files"]
                ],
                "state_mounts": service["state_mounts"],
                "requires_spire": registration is not None,
            }
        )
    required_secret_paths = {
        relative
        for service in services
        for relative in (
            *cast(list[str], service["secret_files"]),
            *cast(list[str], service["identity_files"]),
        )
    }
    agent = cast(dict[str, Any], bootstrap["agents"].get(role, {})) or None
    role_registrations: list[dict[str, Any]] = []
    for name, registration in registrations.items():
        if registration["role"] != role:
            continue
        entry = {
            "entry_id": registration["entry_id"],
            "parent_id": registration["parent_id"],
            "spiffe_id": registration["spiffe_id"],
            "selectors": [
                {"type": "unix", "value": f"uid:{registration['uid']}"},
                {"type": "unix", "value": f"gid:{registration['gid']}"},
            ],
            "x509_svid_ttl": bootstrap["workload_svid_ttl_seconds"],
        }
        document = {"entries": [entry]}
        document_bytes = _canonical_bytes(document) + b"\n"
        role_registrations.append(
            {
                "name": name,
                "entry_id": registration["entry_id"],
                "parent_id": registration["parent_id"],
                "document": document_bytes.decode("ascii"),
                "sha256": hashlib.sha256(document_bytes).hexdigest(),
            }
        )
    return {
        "schema_version": "aegis-ot-m4j-host-workload-plan-v1",
        "deployment_status": "configuration_only",
        "claim_boundary": "no_live_deployment_or_multi_host_isolation_evidence",
        "role": role,
        "source_git_commit": expected_commit,
        "contract_bindings": {
            "topology_canonical_sha256": bindings["topology_canonical_sha256"],
            "deployment_canonical_sha256": bindings["canonical_sha256"],
            "workloads_canonical_sha256": _canonical_sha256(workload),
        },
        "orchestration": ORCHESTRATION_CONTRACT,
        "bundle": {
            "application_image_id": bundle["application_image_id"],
            "application_image_platform": bundle["application_image_platform"],
            "builder_attestation_key_id": bundle["builder_attestation_key_id"],
            "builder_profile_sha256": bundle["builder_profile_sha256"],
            "artifacts": bundle["artifacts"],
            "opa_policy": bundle["opa_policy"],
        },
        "runtime_images": runtime_images["images"],
        "trust_domain": workload["trust_domain"],
        "node_agent": agent,
        "node_bootstrap": {
            "attestor": bootstrap["attestor"],
            "token_ttl_seconds": bootstrap["token_ttl_seconds"],
            "delivery_path": bootstrap["delivery_path"],
            "token_cleanup": bootstrap["token_cleanup"],
        },
        "registrations": role_registrations,
        "services": services,
        "firewall_ingress": _firewall_plan(role, deployment, topology),
        "secret_artifacts": {
            relative: cast(dict[str, Any], secrets["artifacts"])[relative]
            for relative in sorted(required_secret_paths)
        },
        "secret_manifest_sha256": hashlib.sha256(
            (Path(cast(str, secrets["root"])) / SECRET_MANIFEST_NAME).read_bytes()
        ).hexdigest(),
        "controller_authority_private_key_distributed": False,
        "join_token_material_retained": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check-contract", action="store_true")
    modes.add_argument("--plan-role", choices=ROLES)
    parser.add_argument("--workloads", type=Path, default=DEFAULT_WORKLOADS)
    parser.add_argument("--deployment", type=Path, default=DEFAULT_DEPLOYMENT)
    parser.add_argument("--topology", type=Path, default=DEFAULT_TOPOLOGY)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--runtime-images", type=Path)
    parser.add_argument("--secrets", type=Path)
    parser.add_argument("--builder-trusted-public-key", type=Path)
    parser.add_argument("--expected-builder-profile-sha256")
    parser.add_argument("--expect-commit")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.check_contract:
            workload, _deployment, _topology, bindings = _validate_contract(
                arguments.workloads,
                arguments.deployment,
                arguments.topology,
            )
            result = {
                "schema_version": workload["schema_version"],
                "deployment_status": workload["deployment_status"],
                "claim_boundary": workload["claim_boundary"],
                "workloads_canonical_sha256": _canonical_sha256(workload),
                "deployment_canonical_sha256": bindings["canonical_sha256"],
                "topology_canonical_sha256": bindings["topology_canonical_sha256"],
                "valid": True,
            }
        else:
            if (
                arguments.bundle is None
                or arguments.runtime_images is None
                or arguments.secrets is None
                or arguments.builder_trusted_public_key is None
                or arguments.expected_builder_profile_sha256 is None
                or arguments.expect_commit is None
            ):
                _fail(
                    "--plan-role requires --bundle, --runtime-images, --secrets, "
                    "--builder-trusted-public-key, --expected-builder-profile-sha256, "
                    "and --expect-commit"
                )
            trusted_builder_public_key = _read_trusted_builder_public_key(
                arguments.builder_trusted_public_key
            )
            result = compile_plan(
                role=cast(str, arguments.plan_role),
                expected_commit=arguments.expect_commit,
                bundle_directory=arguments.bundle,
                runtime_image_directory=arguments.runtime_images,
                secret_directory=arguments.secrets,
                trusted_builder_public_key=trusted_builder_public_key,
                expected_builder_profile_sha256=(
                    arguments.expected_builder_profile_sha256
                ),
                workload_path=arguments.workloads,
                deployment_path=arguments.deployment,
                topology_path=arguments.topology,
            )
    except (WorkloadContractError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "valid": False}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
