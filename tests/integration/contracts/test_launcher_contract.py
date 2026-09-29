"""Contract: Launcher.get_attestation_token against the simulator launcher socket (FR-1, FR-3).

ARCHITECTURE "Attestation and launcher"; API.md §B attest; FACTS F-01..F-05, F-13.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest
from tc_contract_support import AUDIENCE, RunningSimulator, jws_payload

from teecustody.attest import (
    AttestationLifecycle,
    AttestationToken,
    ConfidentialSpaceLauncher,
    LauncherError,
    LauncherErrorCode,
    RefreshOutcome,
    identity_nonce,
    launcher_nonce,
)
from teecustody.channel import IdentityKey
from teecustody_sim import SIM_TOKEN_TTL_S


class _NullLogger:
    def info(self, outcome: str, **fields: str | int) -> None:
        del outcome, fields

    def warning(self, outcome: str, **fields: str | int) -> None:
        del outcome, fields

    def error(self, outcome: str, **fields: str | int) -> None:
        del outcome, fields


def _launcher(socket_path: Path) -> ConfidentialSpaceLauncher:
    return ConfidentialSpaceLauncher(str(socket_path), timeout_s=5.0, max_response_bytes=65536)


def test_identity_nonce_is_sha256_of_the_raw_public_key() -> None:
    public_key = IdentityKey.generate().public_bytes()
    assert len(public_key) == 32
    assert identity_nonce(public_key) == hashlib.sha256(public_key).digest()
    assert launcher_nonce(identity_nonce(public_key)) == hashlib.sha256(public_key).hexdigest()


def test_token_is_bound_to_audience_and_identity_nonce(
    running_simulator: RunningSimulator,
) -> None:
    public_key = IdentityKey.generate().public_bytes()
    launcher = _launcher(running_simulator.config.socket_path)

    token = launcher.get_attestation_token(AUDIENCE, "OIDC", identity_nonce(public_key))

    assert isinstance(token, AttestationToken)
    claims = jws_payload(token.value)
    assert claims["aud"] == AUDIENCE
    assert claims["eat_nonce"] == hashlib.sha256(public_key).hexdigest()
    assert token.issued_at == claims["iat"]
    assert token.expires_at == claims["exp"]
    assert token.expires_at - token.issued_at == SIM_TOKEN_TTL_S


def test_missing_socket_is_unavailable(short_dir: Path) -> None:
    launcher = _launcher(short_dir / "absent.sock")
    with pytest.raises(LauncherError) as caught:
        launcher.get_attestation_token(AUDIENCE, "OIDC", bytes(32))
    assert caught.value.code is LauncherErrorCode.UNAVAILABLE
    assert str(caught.value) == "UNAVAILABLE"


@pytest.mark.parametrize(
    ("audience", "token_type", "nonce"),
    [
        (AUDIENCE, "PKI", bytes(32)),
        (AUDIENCE, "OIDC", bytes(31)),
        ("", "OIDC", bytes(32)),
    ],
)
def test_invalid_request_is_rejected_locally(
    running_simulator: RunningSimulator, audience: str, token_type: str, nonce: bytes
) -> None:
    launcher = _launcher(running_simulator.config.socket_path)
    with pytest.raises(LauncherError) as caught:
        launcher.get_attestation_token(audience, token_type, nonce)
    assert caught.value.code is LauncherErrorCode.INVALID_CONFIGURATION
    assert str(caught.value) == "INVALID_CONFIGURATION"


def test_lifecycle_start_obtains_a_nonce_bound_token(running_simulator: RunningSimulator) -> None:
    public_key = IdentityKey.generate().public_bytes()
    lifecycle = AttestationLifecycle(
        _launcher(running_simulator.config.socket_path),
        audience=AUDIENCE,
        token_type="OIDC",
        identity_public_key=public_key,
        refresh_margin_s=300,
        clock=time.time,
        logger=_NullLogger(),
    )

    token = lifecycle.start()

    assert lifecycle.identity_nonce == hashlib.sha256(public_key).digest()
    assert lifecycle.current() == token
    assert jws_payload(token.value)["eat_nonce"] == hashlib.sha256(public_key).hexdigest()


def test_refresh_requests_a_new_token_with_the_same_nonce(
    running_simulator: RunningSimulator,
) -> None:
    public_key = IdentityKey.generate().public_bytes()
    now = [time.time()]
    lifecycle = AttestationLifecycle(
        _launcher(running_simulator.config.socket_path),
        audience=AUDIENCE,
        token_type="OIDC",
        identity_public_key=public_key,
        refresh_margin_s=300,
        clock=lambda: now[0],
        logger=_NullLogger(),
    )
    first = lifecycle.start()

    assert lifecycle.refresh_if_due() is RefreshOutcome.NOT_DUE
    now[0] = first.expires_at - 300
    assert lifecycle.refresh_if_due() is RefreshOutcome.REFRESHED

    refreshed = lifecycle.current()
    assert jws_payload(refreshed.value)["eat_nonce"] == jws_payload(first.value)["eat_nonce"]


def test_default_token_file_carries_no_custom_nonce(running_simulator: RunningSimulator) -> None:
    token = running_simulator.config.token_file_path.read_text().strip()
    claims = jws_payload(token)
    assert "eat_nonce" not in claims
    assert claims["aud"] == "https://sts.googleapis.com"
