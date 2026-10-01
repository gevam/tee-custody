"""Launcher port (ARCHITECTURE "Attestation and launcher")."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


class LauncherErrorCode(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    TOKEN_REJECTED = "TOKEN_REJECTED"  # noqa: S105 - an error code


class LauncherError(Exception):
    """Carries only a stable code; `str(err)` is the code value and nothing else."""

    code: LauncherErrorCode

    def __init__(self, code: LauncherErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True)
class AttestationToken:
    value: str = field(repr=False)  # compact JWS, never logged
    issued_at: int  # `iat`, Unix s, parsed locally, untrusted
    expires_at: int  # `exp`, Unix s, parsed locally, untrusted


class Launcher(Protocol):
    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken: ...
