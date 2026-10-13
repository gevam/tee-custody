"""T-13: the workload's own image digest from its launcher token (FR-4, SR-3 R-7, SR-11)."""

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


PAYLOAD = _payload(_claims())
HEX = "0123456789abcdef" * 4


def _padded(raw: bytes) -> str:
    segment = base64.urlsafe_b64encode(raw).decode("ascii")
    assert segment.endswith("=")
    return segment


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(f"{HEADER}.{PAYLOAD}", id="two-segments"),
        pytest.param(f"{HEADER}.{PAYLOAD}.{SIGNATURE}.{SIGNATURE}", id="four-segments"),
        pytest.param(f".{PAYLOAD}.{SIGNATURE}", id="empty-header"),
        pytest.param(f"{HEADER}..{SIGNATURE}", id="empty-payload"),
        pytest.param(f"{HEADER}.{PAYLOAD}.", id="empty-signature"),
        pytest.param(
            f"{HEADER}.{_padded(json.dumps(_claims()).encode() + b' ')}.{SIGNATURE}",
            id="padded-payload",
        ),
        pytest.param(f"{HEADER}.{PAYLOAD}.{_padded(b'sign')}", id="padded-signature"),
        pytest.param(f"{HEADER}.{PAYLOAD[:8]}+{PAYLOAD[9:]}.{SIGNATURE}", id="plus-in-payload"),
        pytest.param(f"{HEADER}.{PAYLOAD[:8]}/{PAYLOAD[9:]}.{SIGNATURE}", id="slash-in-payload"),
        pytest.param(f"{HEADER}.{PAYLOAD}.c2l!", id="bang-in-signature"),
        pytest.param(f"{HEADER[:4]}+{HEADER[5:]}.{PAYLOAD}.{SIGNATURE}", id="plus-in-header"),
        pytest.param(f"{HEADER}.{_b64(b'\xff\xfe{}')}.{SIGNATURE}", id="non-utf8-payload"),
        pytest.param(f"{HEADER}.{_b64(b'not json')}.{SIGNATURE}", id="non-json-payload"),
        pytest.param(f"{HEADER}.{_payload([1, 2, 3])}.{SIGNATURE}", id="array-payload"),
        pytest.param(f"{HEADER}.{_payload({'aud': 'a'})}.{SIGNATURE}", id="submods-missing"),
        pytest.param(f"{HEADER}.{_payload({'submods': 'x'})}.{SIGNATURE}", id="submods-string"),
        pytest.param(f"{HEADER}.{_payload({'submods': [1]})}.{SIGNATURE}", id="submods-array"),
        pytest.param(f"{HEADER}.{_payload({'submods': {}})}.{SIGNATURE}", id="container-missing"),
        pytest.param(
            f"{HEADER}.{_payload({'submods': {'container': {}}})}.{SIGNATURE}",
            id="image-digest-missing",
        ),
        pytest.param(
            f"{HEADER}.{_payload(_claims('sha256:' + HEX.upper()))}.{SIGNATURE}", id="uppercase-hex"
        ),
        pytest.param(
            f"{HEADER}.{_payload(_claims('sha256:' + HEX[:63]))}.{SIGNATURE}", id="63-hex"
        ),
        pytest.param(
            f"{HEADER}.{_payload(_claims('sha512:' + HEX))}.{SIGNATURE}", id="sha512-prefix"
        ),
        pytest.param(
            f"{HEADER}.{_payload(_claims('sha256:' + HEX + chr(10)))}.{SIGNATURE}",
            id="trailing-newline",
        ),
    ],
)
def test_malformed_token_or_digest_claim_is_token_rejected_with_no_chained_cause(
    value: str,
) -> None:
    _assert_rejected(_token(value))
