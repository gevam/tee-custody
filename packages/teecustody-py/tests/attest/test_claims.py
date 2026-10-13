"""T-13: the workload's own image digest from its launcher-supplied token (FR-4, SR-3 R-7, SR-11)."""

import base64
import json

import pytest

from teecustody.attest import AttestationToken, LauncherError, LauncherErrorCode
from teecustody.attest.claims import own_image_digest

DIGEST = "sha256:" + "0123456789abcdef" * 4
LIMIT = 16384
HEADER = "eyJhbGciOiJSUzI1NiJ9"
SIGNATURE = "c2ln"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _claims(digest: object = DIGEST) -> dict[str, object]:
    return {
        "aud": "https://workload.teecustody.test/aud",
        "submods": {"container": {"image_digest": digest, "image_reference": "localhost/w:1"}},
    }


def _payload(claims: object) -> str:
    return _b64(json.dumps(claims).encode("utf-8"))


def _token(value: str) -> AttestationToken:
    return AttestationToken(value=value, issued_at=1_900_000_000, expires_at=1_900_003_600)


def _with_claims(claims: object) -> AttestationToken:
    return _token(f"{HEADER}.{_payload(claims)}.{SIGNATURE}")


def test_digest_is_read_from_submods_container_image_digest() -> None:
    assert own_image_digest(_with_claims(_claims()), max_token_bytes=LIMIT) == DIGEST


def _assert_rejected(token: AttestationToken, *, max_token_bytes: int = LIMIT) -> None:
    with pytest.raises(LauncherError) as caught:
        own_image_digest(token, max_token_bytes=max_token_bytes)
    assert caught.value.code is LauncherErrorCode.TOKEN_REJECTED
    assert str(caught.value) == "TOKEN_REJECTED"
    assert caught.value.args == ("TOKEN_REJECTED",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_token_one_byte_over_the_limit_is_rejected_before_any_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = _with_claims(_claims())
    calls: list[object] = []
    monkeypatch.setattr(json, "loads", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(base64, "urlsafe_b64decode", lambda *a, **k: calls.append(a))

    _assert_rejected(token, max_token_bytes=len(token.value) - 1)

    assert calls == []


def test_token_exactly_at_the_limit_is_accepted() -> None:
    token = _with_claims(_claims())
    assert own_image_digest(token, max_token_bytes=len(token.value)) == DIGEST
