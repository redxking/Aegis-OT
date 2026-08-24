"""Established Ed25519 signing helpers; no custom cryptographic primitives."""

from __future__ import annotations

import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def sign_bytes(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii")


def decode_urlsafe_b64(value: str) -> bytes:
    """Decode one canonical padded URL-safe Base64 value."""

    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("invalid URL-safe Base64 encoding") from exc
    if base64.urlsafe_b64encode(decoded).decode("ascii") != value:
        raise ValueError("noncanonical URL-safe Base64 encoding")
    return decoded


def verify_bytes(public_key: Ed25519PublicKey, payload: bytes, signature: str) -> bool:
    try:
        decoded = decode_urlsafe_b64(signature)
        public_key.verify(decoded, payload)
    except (InvalidSignature, ValueError):
        return False
    return True
