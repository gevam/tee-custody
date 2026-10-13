"""T-08: workload HPKE Base-mode receiver (`teecustody.channel.hpke`; INC-2-API §4.6, ADR 0011)."""

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from teecustody.channel.hpke import generate_keypair, open_base

SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
INFO = b"tee-custody test info"
AAD = b"tee-custody test aad"
PLAINTEXT = b"open-session payload"


@dataclass(frozen=True)
class Sealed:
    enc: bytes
    ct: bytes
    c2t: bytes
    t2c: bytes


def _seal(public: bytes, info: bytes = INFO, aad: bytes = AAD, pt: bytes = PLAINTEXT) -> Sealed:
    enc, sender = SUITE.create_sender_context(SUITE.kem.deserialize_public_key(public), info)
    ct = sender.seal(pt, aad=aad)
    return Sealed(enc, ct, sender.export(b"c2t", 32), sender.export(b"t2c", 32))


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


# ---------------------------------------------------------------- criterion 2
def test_open_base_returns_plaintext_and_both_exports_of_the_sender_context() -> None:
    private, public = generate_keypair()
    sealed = _seal(public)

    opened = open_base(private, sealed.enc, INFO, AAD, sealed.ct)

    assert opened.plaintext.reveal() == PLAINTEXT
    assert opened.sk_c2t.reveal() == sealed.c2t
    assert opened.sk_t2c.reveal() == sealed.t2c
    assert sealed.c2t != sealed.t2c
