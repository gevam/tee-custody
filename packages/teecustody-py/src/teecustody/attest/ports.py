"""Launcher port (ARCHITECTURE "Attestation and launcher")."""

from dataclasses import dataclass
from enum import StrEnum, auto
from typing import Protocol


class LauncherErrorCode(StrEnum):
    UNAVAILABLE = auto()
    INVALID_CONFIGURATION = auto()
    TOKEN_REJECTED = auto()


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
