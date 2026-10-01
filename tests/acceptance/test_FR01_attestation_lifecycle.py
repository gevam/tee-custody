"""FR-1 Workload attestation lifecycle (INC-1). Public interfaces only.

Expected failure on trunk: NotImplementedError('T-06' | 'T-07' | 'T-08') from stubs.
"""

import hashlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from acc_support import AUDIENCE, RunningSim, decode_jws
from teecustody.attest import (
    AttestationLifecycle,
    ConfidentialSpaceLauncher,
    LauncherError,
    LauncherErrorCode,
    RefreshOutcome,
    identity_nonce,
    launcher_nonce,
)
from teecustody.channel import IdentityKey
from teecustody.obs import get_logger

MARGIN_S = 600


def _launcher(sock: Path) -> ConfidentialSpaceLauncher:
    return ConfidentialSpaceLauncher(str(sock), timeout_s=5.0, max_response_bytes=65536)


def _lifecycle(rs: RunningSim, ik: IdentityKey) -> AttestationLifecycle:
    return AttestationLifecycle(
        _launcher(rs.config.socket_path),
        audience=AUDIENCE,
        token_type="OIDC",
        identity_public_key=ik.public_bytes(),
        refresh_margin_s=MARGIN_S,
        clock=rs.clock,
        logger=get_logger("acceptance.fr01"),
    )


def test_FR01_token_is_bound_to_audience_and_identity_key_nonce(running_sim: RunningSim) -> None:
    # Given the simulator launcher and a configured workload
    ik = IdentityKey.generate()
    lifecycle = _lifecycle(running_sim, ik)
    # When the workload starts and requests attestation
    token = lifecycle.start()
    # Then the token carries the configured audience and nonce = hex(SHA-256(IK_pub))
    _, claims = decode_jws(token.value)
    expected_nonce = hashlib.sha256(ik.public_bytes()).hexdigest()
    assert claims["aud"] == AUDIENCE
    nonce = claims["eat_nonce"]
    assert (nonce if isinstance(nonce, str) else nonce[0]) == expected_nonce
    assert lifecycle.identity_nonce == hashlib.sha256(ik.public_bytes()).digest()
    assert token.issued_at == claims["iat"]
    assert token.expires_at == claims["exp"]
    assert lifecycle.current() == token


def test_FR01_nonce_derivation_known_answer() -> None:
    # Given a 32-byte identity public key of zeros
    pub = bytes(32)
    # When deriving the identity nonce and the launcher nonce
    nonce = identity_nonce(pub)
    # Then they equal SHA-256 and its lowercase hex (API.md section A)
    assert nonce == hashlib.sha256(pub).digest()
    assert launcher_nonce(nonce) == hashlib.sha256(pub).hexdigest()
    with pytest.raises(ValueError, match="IDENTITY_KEY_LENGTH"):
        identity_nonce(bytes(31))
    with pytest.raises(ValueError, match="IDENTITY_NONCE_LENGTH"):
        launcher_nonce(bytes(31))


def test_FR01_attestation_needs_no_inbound_connection(running_sim: RunningSim) -> None:
    # Given a workload process in which any bind/listen is forbidden
    script = textwrap.dedent(
        """
        import json, socket, sys
        def deny(*a, **k):
            raise AssertionError("INBOUND_SOCKET")
        socket.socket.bind = deny
        socket.socket.listen = deny
        from teecustody.attest import AttestationLifecycle, ConfidentialSpaceLauncher
        from teecustody.channel import IdentityKey
        from teecustody.obs import get_logger
        ik = IdentityKey.generate()
        lc = AttestationLifecycle(
            ConfidentialSpaceLauncher(sys.argv[1], timeout_s=5.0, max_response_bytes=65536),
            audience=sys.argv[2], token_type="OIDC", identity_public_key=ik.public_bytes(),
            refresh_margin_s=600, clock=lambda: 1_900_000_000.0, logger=get_logger("x"))
        lc.start()
        print(json.dumps({"sim_loaded": any(m.startswith("teecustody_sim") for m in sys.modules)}))
        """
    )
    # When it obtains attestation through the launcher socket
    proc = subprocess.run(
        [sys.executable, "-c", script, str(running_sim.config.socket_path), AUDIENCE],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    # Then it succeeds with no inbound socket, and the workload never imports the simulator
    assert proc.returncode == 0, proc.stderr[-500:]
    assert json.loads(proc.stdout.strip().splitlines()[-1]) == {"sim_loaded": False}


def test_FR01_refresh_is_not_due_then_replaces_token_near_expiry(running_sim: RunningSim) -> None:
    # Given a started lifecycle
    lifecycle = _lifecycle(running_sim, IdentityKey.generate())
    first = lifecycle.start()
    # When the clock is well before expiry minus the margin
    running_sim.clock.now += 1000
    # Then no refresh happens
    assert lifecycle.refresh_if_due() == RefreshOutcome.NOT_DUE
    assert lifecycle.current() == first
    # When the clock passes expiry minus the margin
    running_sim.clock.now = first.expires_at - MARGIN_S + 60
    # Then the token is refreshed, keeping the same identity nonce
    assert lifecycle.refresh_if_due() == RefreshOutcome.REFRESHED
    second = lifecycle.current()
    assert second.value != first.value
    assert second.expires_at > first.expires_at
    _, claims = decode_jws(second.value)
    nonce = claims["eat_nonce"]
    assert (nonce if isinstance(nonce, str) else nonce[0]) == lifecycle.identity_nonce.hex()


def test_FR01_failed_refresh_keeps_current_token(running_sim: RunningSim) -> None:
    # Given a started lifecycle and a launcher that then disappears
    lifecycle = _lifecycle(running_sim, IdentityKey.generate())
    first = lifecycle.start()
    running_sim.sim.stop()
    running_sim.clock.now = first.expires_at - MARGIN_S + 60
    # When a refresh is due but fails
    outcome = lifecycle.refresh_if_due()
    # Then the outcome says so and the previous token is kept
    assert outcome == RefreshOutcome.FAILED_KEPT_CURRENT
    assert lifecycle.current() == first


def test_FR01_unavailable_launcher_fails_with_stable_error(workdir: Path) -> None:
    # Given a socket path nobody listens on
    launcher = _launcher(workdir / "missing.sock")
    # When requesting a token
    with pytest.raises(LauncherError) as excinfo:
        launcher.get_attestation_token(AUDIENCE, "OIDC", bytes(32))
    # Then the error is the stable UNAVAILABLE category with no other text
    assert excinfo.value.code == LauncherErrorCode.UNAVAILABLE
    assert str(excinfo.value) == "UNAVAILABLE"


def test_FR01_launcher_rejects_identity_nonce_of_wrong_length(
    running_sim: RunningSim,
) -> None:
    launcher = _launcher(running_sim.config.socket_path)
    # Given a nonce that is not 32 bytes (when requesting)
    # Then the request is refused before any token is accepted
    with pytest.raises((LauncherError, ValueError)):
        launcher.get_attestation_token(AUDIENCE, "OIDC", bytes(5))
