"""Secret bytes in a private buffer: redacted everywhere, wiped explicitly (spec §11; NFR-3)."""

import hmac
from enum import StrEnum
from typing import NoReturn, SupportsIndex

_REDACTED = "Secret(<redacted>)"


class SecretErrorCode(StrEnum):
    WIPED = "WIPED"
    INVALID_LENGTH = "INVALID_LENGTH"
    FORBIDDEN = "FORBIDDEN"


class SecretError(Exception):
    """Carries only a stable code; `str(err)` is the code value and nothing else."""

    code: SecretErrorCode

    def __init__(self, code: SecretErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


class Secret:
    """Secret bytes in a private bytearray. Redacted everywhere; explicit wipe."""

    __slots__ = ("_buf",)

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self._buf = bytearray(data)

    def __len__(self) -> int:
        return len(self._buf)

    def reveal(self) -> bytes:
        return bytes(self._buf)

    def equals(self, other: "Secret | bytes") -> bool:
        theirs = other._buf if isinstance(other, Secret) else other
        return hmac.compare_digest(self._buf, theirs)

    @property
    def wiped(self) -> bool:
        return False

    def __repr__(self) -> str:
        return _REDACTED

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, format_spec: str) -> str:
        return _REDACTED

    def __eq__(self, other: object) -> NoReturn:
        raise SecretError(SecretErrorCode.FORBIDDEN)

    __hash__ = None  # type: ignore[assignment]

    def __bytes__(self) -> NoReturn:
        raise SecretError(SecretErrorCode.FORBIDDEN)

    def __reduce__(self) -> NoReturn:
        raise SecretError(SecretErrorCode.FORBIDDEN)

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise SecretError(SecretErrorCode.FORBIDDEN)

    def __iter__(self) -> NoReturn:
        raise SecretError(SecretErrorCode.FORBIDDEN)

    def __getitem__(self, index: object) -> NoReturn:
        raise SecretError(SecretErrorCode.FORBIDDEN)


__all__ = ["Secret", "SecretError", "SecretErrorCode"]
