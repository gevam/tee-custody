"""Attestation token lifecycle: start, current token and scheduled refresh.

Every request carries the same identity nonce, `H(IK_pub)` (spec §5.1 steps 2 and 4). A failed
refresh never replaces a still-valid token. Log records carry outcome codes only (spec §11).
"""

from collections.abc import Callable
from enum import StrEnum

from teecustody.attest.nonce import identity_nonce
from teecustody.attest.ports import AttestationToken, Launcher, LauncherError, LauncherErrorCode
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
        if refresh_margin_s < 1:
            raise ValueError("REFRESH_MARGIN")
        self._identity_nonce = identity_nonce(identity_public_key)
        self._launcher = launcher
        self._audience = audience
        self._token_type = token_type
        self._refresh_margin_s = refresh_margin_s
        self._clock = clock
        self._logger = logger
        self._token: AttestationToken | None = None

    @property
    def identity_nonce(self) -> bytes:
        return self._identity_nonce

    def start(self) -> AttestationToken:
        try:
            self._token = self._request()
        except LauncherError:
            self._logger.error("ATTESTATION_TOKEN_FAILED")
            raise
        self._logger.info("ATTESTATION_TOKEN_OBTAINED")
        return self._token

    def current(self) -> AttestationToken:
        if self._token is None:
            raise RuntimeError("NOT_STARTED")
        return self._token

    def refresh_if_due(self) -> RefreshOutcome:
        expires_at = self.current().expires_at
        if self._clock() < expires_at - self._refresh_margin_s:
            return RefreshOutcome.NOT_DUE
        try:
            self._token = self._request()
        except LauncherError:
            if self._clock() < expires_at:
                self._logger.warning("ATTESTATION_REFRESH_FAILED")
                return RefreshOutcome.FAILED_KEPT_CURRENT
            self._logger.error("ATTESTATION_TOKEN_EXPIRED")
            raise
        self._logger.info("ATTESTATION_TOKEN_REFRESHED")
        return RefreshOutcome.REFRESHED

    def _request(self) -> AttestationToken:
        """Request a token with the identity nonce; one that is already expired is rejected."""
        token = self._launcher.get_attestation_token(
            self._audience, self._token_type, self._identity_nonce
        )
        if token.expires_at <= self._clock():
            raise LauncherError(LauncherErrorCode.TOKEN_REJECTED)
        return token
