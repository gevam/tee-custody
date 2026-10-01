"""Attestation token lifecycle: start, current token and scheduled refresh."""

from collections.abc import Callable
from enum import StrEnum

from teecustody.attest.ports import AttestationToken, Launcher
from teecustody.obs import AllowListedLogger


class RefreshOutcome(StrEnum):
    NOT_DUE = "NOT_DUE"
    REFRESHED = "REFRESHED"
    FAILED_KEPT_CURRENT = "FAILED_KEPT_CURRENT"


class AttestationLifecycle:
    def __init__(
        self,
        launcher: Launcher,
        *,
        audience: str,
        token_type: str,
        identity_public_key: bytes,
        refresh_margin_s: int,
        clock: Callable[[], float],
        logger: AllowListedLogger,
    ) -> None:
        raise NotImplementedError("T-06")

    @property
    def identity_nonce(self) -> bytes:
        raise NotImplementedError("T-06")

    def start(self) -> AttestationToken:
        raise NotImplementedError("T-06")

    def current(self) -> AttestationToken:
        raise NotImplementedError("T-06")

    def refresh_if_due(self) -> RefreshOutcome:
        raise NotImplementedError("T-06")
