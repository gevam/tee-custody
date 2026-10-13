"""T-08: workload HPKE Base-mode receiver (`teecustody.channel.hpke`; INC-2-API §4.6, ADR 0011)."""

import inspect
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from teecustody.channel.hpke import HpkeError, HpkeErrorCode, generate_keypair, open_base
from teecustody.secrets import Secret

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


# ---------------------------------------------------------------- criterion 3 (SR-11)
# RFC 7748 §6.1 low-order u-coordinates (and their non-reduced forms p-1, p, p+1); each makes the
# X25519 output all-zero, which `cryptography` rejects with its own ValueError, not pyhpke's.
LOW_ORDER_U = {
    "one": "01" + "00" * 31,
    "order-8-a": "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "order-8-b": "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "p-1": "ec" + "ff" * 30 + "7f",
    "p": "ed" + "ff" * 30 + "7f",
    "p+1": "ee" + "ff" * 30 + "7f",
}


def _flip_first_bit(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


Tamper = Callable[[Sealed], tuple[bytes, bytes, bytes, bytes]]

TAMPERED: dict[str, Tamper] = {
    "wrong-info": lambda s: (s.enc, INFO + b"!", AAD, s.ct),
    "modified-aad": lambda s: (s.enc, INFO, _flip_first_bit(AAD), s.ct),
    "ct-bit-flip": lambda s: (s.enc, INFO, AAD, _flip_first_bit(s.ct)),
    "enc-31-bytes": lambda s: (s.enc[:31], INFO, AAD, s.ct),
    "enc-all-zero": lambda s: (bytes(32), INFO, AAD, s.ct),
    **{
        f"enc-low-order-{name}": (lambda s, u=u: (bytes.fromhex(u), INFO, AAD, s.ct))
        for name, u in LOW_ORDER_U.items()
    },
}


def _assert_open_failed(err: pytest.ExceptionInfo[HpkeError]) -> None:
    assert err.value.code is HpkeErrorCode.OPEN_FAILED
    assert str(err.value) == "OPEN_FAILED"
    assert err.value.args == ("OPEN_FAILED",)
    assert err.value.__cause__ is None
    assert err.value.__context__ is None


@pytest.mark.parametrize("tamper", TAMPERED.values(), ids=TAMPERED.keys())
def test_tampered_input_fails_with_open_failed_and_no_cause(tamper: Tamper) -> None:
    private, public = generate_keypair()
    enc, info, aad, ct = tamper(_seal(public))

    with pytest.raises(HpkeError) as err:
        open_base(private, enc, info, aad, ct)

    _assert_open_failed(err)


# ---------------------------------------------------------------- criterion 4
def _wiped_key() -> Secret:
    private, _ = generate_keypair()
    private.wipe()
    return private


INVALID_KEYS: dict[str, Callable[[], Secret]] = {
    "wiped": _wiped_key,
    "31-bytes": lambda: Secret(bytes(range(1, 32))),
}


@pytest.mark.parametrize("make_key", INVALID_KEYS.values(), ids=INVALID_KEYS.keys())
def test_wiped_or_short_private_key_fails_with_invalid_key(make_key: Callable[[], Secret]) -> None:
    _, public = generate_keypair()
    sealed = _seal(public)

    with pytest.raises(HpkeError) as err:
        open_base(make_key(), sealed.enc, INFO, AAD, sealed.ct)

    assert err.value.code is HpkeErrorCode.INVALID_KEY
    assert str(err.value) == "INVALID_KEY"
    assert err.value.__cause__ is None
    assert err.value.__context__ is None


# ---------------------------------------------------------------- criterion 6 (ADR 0011 C5)
SEAM_PARAMETERS = {"eks", "psk", "psk_id", "sks", "pks"}


@pytest.mark.parametrize("function", [open_base, generate_keypair], ids=lambda f: f.__name__)
def test_no_hpke_seam_parameter_exists(function: Callable[..., object]) -> None:
    names = set(inspect.signature(function).parameters)

    assert names.isdisjoint(SEAM_PARAMETERS)


def test_open_base_parameters_are_exactly_the_contract() -> None:
    names = list(inspect.signature(open_base).parameters)

    assert names == ["private_key", "enc", "info", "aad", "ct"]
