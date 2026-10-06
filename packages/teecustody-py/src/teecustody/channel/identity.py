"""Workload identity key (IK)."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_DIGEST_LENGTH = 32


class IdentityKey:
    """Ed25519 identity key held in memory only; the private half is never exported (I1)."""

    __slots__ = ("_private_key",)

    def __init__(self) -> None:
        self._private_key = Ed25519PrivateKey.generate()

    @classmethod
    def generate(cls) -> "IdentityKey":
        return cls()

    def public_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        """Ed25519 PureEdDSA over a 32-byte digest only (D2-2; SR-14)."""
        if len(message) != _DIGEST_LENGTH:
            raise ValueError("MESSAGE_LENGTH")
        return self._private_key.sign(message)

    def __repr__(self) -> str:
        return "IdentityKey(<redacted>)"
