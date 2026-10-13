"""T-08: workload HPKE Base-mode receiver (`teecustody.channel.hpke`; INC-2-API §4.6, ADR 0011)."""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from teecustody.channel.hpke import generate_keypair


def _x25519_public(private_raw: bytes) -> bytes:
    key = X25519PrivateKey.from_private_bytes(private_raw)
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------- criterion 1
def test_generate_keypair_returns_matching_raw_x25519_pair() -> None:
    private, public = generate_keypair()

    assert len(public) == 32
    assert len(private) == 32
    assert public == _x25519_public(private.reveal())


def test_generate_keypair_calls_differ() -> None:
    first_private, first_public = generate_keypair()
    second_private, second_public = generate_keypair()

    assert first_public != second_public
    assert not first_private.equals(second_private)
