"""Established Ed25519 signing helpers; no custom cryptographic primitives."""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def sign_bytes(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii")


def verify_bytes(public_key: Ed25519PublicKey, payload: bytes, signature: str) -> bool:
    try:
        decoded = base64.urlsafe_b64decode(signature.encode("ascii"))
        public_key.verify(decoded, payload)
    except (InvalidSignature, ValueError):
        return False
    return True
