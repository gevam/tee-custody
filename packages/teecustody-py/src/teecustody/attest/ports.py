"""Launcher port (ARCHITECTURE "Attestation and launcher")."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class LauncherErrorCode(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    TOKEN_REJECTED = "TOKEN_REJECTED"  # noqa: S105 - an error code


class LauncherError(Exception):
    code: LauncherErrorCode


@dataclass(frozen=True)
class AttestationToken:
    value: str
    issued_at: int
    expires_at: int


class Launcher(Protocol):
    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken: ...
