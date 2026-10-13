"""HPKE Base mode receiver (INC-2-API §4.6; spec §5.3-§5.4; ADR 0011).

Constants, errors and `OpenedHpke` are frozen; function bodies belong to T-08, the only task that
adds the HPKE library import.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from teecustody.secrets import Secret

KEM_ID: Final = 0x0020
KDF_ID: Final = 0x0001
AEAD_ID: Final = 0x0002
EXPORT_C2T: Final = b"c2t"
EXPORT_T2C: Final = b"t2c"
EXPORT_LENGTH: Final = 32

_PRIVATE_KEY_LENGTH: Final = 32
_SUITE: Final = CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
)


class HpkeErrorCode(StrEnum):
    OPEN_FAILED = "OPEN_FAILED"
    INVALID_KEY = "INVALID_KEY"


class HpkeError(Exception):
    """Carries only a stable code; `str(err)` is the code value and nothing else."""

    code: HpkeErrorCode

    def __init__(self, code: HpkeErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


def generate_keypair() -> tuple[Secret, bytes]:
    """Fresh X25519 key pair as (raw private key, raw public key)."""
    key = X25519PrivateKey.generate()
    return Secret(key.private_bytes_raw()), key.public_key().public_bytes_raw()


@dataclass(frozen=True, slots=True, eq=False)
class OpenedHpke:
    plaintext: Secret
    sk_c2t: Secret
    sk_t2c: Secret


def open_base(private_key: Secret, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> OpenedHpke:
    """Base-mode receiver: Open once, then export both session keys from the same context.

    Every library failure becomes `HpkeError(OPEN_FAILED)` with no cause and no context: a
    low-order `enc` surfaces as `cryptography`'s ValueError, not pyhpke's OpenError (D-045).
    """
    if len(private_key) != _PRIVATE_KEY_LENGTH:  # a wiped Secret has length 0
        raise HpkeError(HpkeErrorCode.INVALID_KEY) from None
    try:
        recipient_key = _SUITE.kem.deserialize_private_key(private_key.reveal())
        context = _SUITE.create_recipient_context(enc, recipient_key, info)
        opened = OpenedHpke(
            plaintext=Secret(context.open(ct, aad=aad)),
            sk_c2t=Secret(context.export(EXPORT_C2T, EXPORT_LENGTH)),
            sk_t2c=Secret(context.export(EXPORT_T2C, EXPORT_LENGTH)),
        )
    except Exception:  # noqa: BLE001 - fail closed on anything the HPKE library raises
        opened = None
    if opened is None:
        # Raised outside the handler so neither __cause__ nor __context__ carries the library error.
        raise HpkeError(HpkeErrorCode.OPEN_FAILED) from None
    return opened
