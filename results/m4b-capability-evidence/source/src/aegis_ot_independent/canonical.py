"""Strict JSON, hashing, and Ed25519 helpers owned by the independent package."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json_bytes(value: Any) -> bytes:
    """Return the package's versioned canonical JSON byte representation."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8") + "\n"


def sha256_bytes(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def strict_json_loads(material: bytes | str) -> Any:
    """Parse UTF-8 JSON while rejecting duplicates and non-finite constants."""

    if isinstance(material, bytes):
        if material.startswith(b"\xef\xbb\xbf"):
            raise ValueError("UTF-8 BOM is forbidden")
        text = material.decode("utf-8")
    else:
        text = material
    return json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def public_key_b64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii")


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid evaluator public key encoding") from exc
    if len(raw) != 32:
        raise ValueError("evaluator public key must contain 32 raw bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_b64(private_key: Ed25519PrivateKey, material: bytes) -> str:
    return base64.urlsafe_b64encode(private_key.sign(material)).decode("ascii")


def verify_b64(public_key: Ed25519PublicKey, material: bytes, signature: str) -> bool:
    try:
        decoded = base64.urlsafe_b64decode(signature.encode("ascii"))
        public_key.verify(decoded, material)
    except (InvalidSignature, ValueError, UnicodeEncodeError):
        return False
    return True
