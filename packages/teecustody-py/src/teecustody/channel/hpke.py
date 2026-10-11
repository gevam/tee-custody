"""HPKE Base mode receiver (INC-2-API §4.6; spec §5.3-§5.4; ADR 0011).

Constants, errors and `OpenedHpke` are frozen; function bodies belong to T-08, the only task that
adds the HPKE library import.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from teecustody.secrets import Secret

KEM_ID: Final = 0x0020
KDF_ID: Final = 0x0001
AEAD_ID: Final = 0x0002
EXPORT_C2T: Final = b"c2t"
EXPORT_T2C: Final = b"t2c"
EXPORT_LENGTH: Final = 32


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
    raise NotImplementedError("T-08")


@dataclass(frozen=True, slots=True, eq=False)
class OpenedHpke:
    plaintext: Secret
    sk_c2t: Secret
    sk_t2c: Secret


def open_base(private_key: Secret, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> OpenedHpke:
    raise NotImplementedError("T-08")
