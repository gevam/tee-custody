"""Identity and launcher nonce derivation (API.md §A)."""

import hashlib

_IDENTITY_KEY_BYTES = 32
_IDENTITY_NONCE_BYTES = 32


def identity_nonce(identity_public_key: bytes) -> bytes:
    """`H(IK_pub)`: SHA-256 of the raw 32-byte Ed25519 identity public key."""
    if len(identity_public_key) != _IDENTITY_KEY_BYTES:
        raise ValueError("IDENTITY_KEY_LENGTH")
    return hashlib.sha256(identity_public_key).digest()


def launcher_nonce(identity_nonce: bytes) -> str:
    """The launcher's custom nonce and the expected `eat_nonce`: 64 lowercase hex characters."""
    if len(identity_nonce) != _IDENTITY_NONCE_BYTES:
        raise ValueError("IDENTITY_NONCE_LENGTH")
    return identity_nonce.hex()
