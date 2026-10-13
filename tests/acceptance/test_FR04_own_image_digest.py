"""FR-4 / spec §5.1 step 3: the workload reads its own image digest from its launcher-supplied token
(INC-2-API §4.3; owner T-13). The token's signature is not checked here: the launcher is the trusted
source (spec §11). Expected failure on trunk: NotImplementedError('T-13').
"""

import base64
import json
from typing import Any

import pytest

from acc_support import IMAGE_DIGEST, RunningSim
from teecustody.attest import AttestationToken, ConfidentialSpaceLauncher, LauncherError
from teecustody.attest.claims import own_image_digest

DIGEST = "sha256:" + "0123456789abcdef" * 4
LIMIT = 16384


def _b64(value: Any) -> str:
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token(
    payload: Any = None, *, digest: Any = DIGEST, signature: str = "c2ln"
) -> AttestationToken:
    claims = (
        payload if payload is not None else {"submods": {"container": {"image_digest": digest}}}
    )
    value = f"{_b64({'alg': 'RS256'})}.{_b64(claims)}.{signature}"
    return AttestationToken(value=value, issued_at=1, expires_at=2)


def test_FR04_digest_is_read_from_the_container_submodule_claim() -> None:
    assert own_image_digest(_token(), max_token_bytes=LIMIT) == DIGEST


def test_FR04_digest_matches_the_simulator_token(running_sim: RunningSim) -> None:
    # Given a real simulator launcher token
    launcher = ConfidentialSpaceLauncher(
        str(running_sim.config.socket_path), timeout_s=5.0, max_response_bytes=65536
    )
    token = launcher.get_attestation_token(
        "https://acceptance.teecustody.test/tee", "OIDC", bytes(32)
    )
    # Then the workload's own digest is the one the simulator was launched with
    assert own_image_digest(token, max_token_bytes=LIMIT) == IMAGE_DIGEST


def test_FR04_the_token_signature_is_not_the_digest_readers_concern() -> None:
    assert (
        own_image_digest(_token(signature="not-a-real-signature"), max_token_bytes=LIMIT) == DIGEST
    )


@pytest.mark.parametrize(
    "token",
    [
        _token(digest="sha256:" + "A" * 64),
        _token(digest="sha256:" + "a" * 63),
        _token(digest="sha256:" + "a" * 65),
        _token(digest="sha256:" + "a" * 64 + "\n"),
        _token(digest="sha1:" + "a" * 40),
        _token(digest=None),
        _token(digest=12345),
        _token({"submods": {"container": {}}}),
        _token({"submods": {}}),
        _token({}),
        _token([1, 2, 3]),
        _token("a string payload"),
        AttestationToken(value="only.two", issued_at=1, expires_at=2),
        AttestationToken(value="a.b.c.d", issued_at=1, expires_at=2),
        AttestationToken(value="", issued_at=1, expires_at=2),
        AttestationToken(value=f"x.{_b64(b'not json')}.y", issued_at=1, expires_at=2),
        AttestationToken(value="x.!!!!.y", issued_at=1, expires_at=2),
    ],
    ids=lambda t: t.value[:18],
)
def test_FR04_malformed_token_or_digest_claim_is_rejected(token: AttestationToken) -> None:
    # Given a token that does not carry a well-formed digest
    # When the workload reads its own digest
    with pytest.raises(LauncherError) as exc:
        own_image_digest(token, max_token_bytes=LIMIT)
    # Then it fails closed with TOKEN_REJECTED, and the message is the code only
    assert str(exc.value) == "TOKEN_REJECTED"


def test_FR04_token_over_the_size_limit_is_rejected_before_parsing() -> None:
    token = _token()
    with pytest.raises(LauncherError) as exc:
        own_image_digest(token, max_token_bytes=len(token.value) - 1)
    assert str(exc.value) == "TOKEN_REJECTED"
    assert own_image_digest(token, max_token_bytes=len(token.value)) == DIGEST
