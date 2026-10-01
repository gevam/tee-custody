"""Workload identity key (IK)."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


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

    def __repr__(self) -> str:
        return "IdentityKey(<redacted>)"
