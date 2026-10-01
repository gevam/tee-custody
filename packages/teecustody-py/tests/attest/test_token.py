"""T-06 criterion 5: local, untrusted token metadata parsing (SR-3, FACTS F-05)."""

import base64
import json
import string

import pytest

from teecustody.attest import AttestationToken, LauncherError, LauncherErrorCode
from teecustody.attest import parse_token_metadata as parse

AUD = "https://workload.teecustody.test/aud"
NONCE = "ab" * 32
MAX = 4096
HEADER = "eyJhbGciOiJSUzI1NiJ9"
SIGNATURE = "c2ln"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": "https://confidentialcomputing.googleapis.com",
        "aud": AUD,
        "iat": 1_900_000_000,
        "exp": 1_900_003_600,
        "eat_nonce": NONCE,
    }
    claims.update(overrides)
    return claims


def _token(payload_segment: str) -> str:
    return f"{HEADER}.{payload_segment}.{SIGNATURE}"


def _json_token(claims: object) -> str:
    return _token(_b64(json.dumps(claims).encode("utf-8")))


def _without(name: str) -> dict[str, object]:
    claims = _claims()
    del claims[name]
    return claims


def _assert_rejected(token: str, *, max_token_bytes: int = MAX) -> None:
    with pytest.raises(LauncherError) as caught:
        parse(token, audience=AUD, expected_nonce=NONCE, max_token_bytes=max_token_bytes)
    assert caught.value.code is LauncherErrorCode.TOKEN_REJECTED
    assert str(caught.value) == "TOKEN_REJECTED"


def test_well_formed_token_yields_its_value_and_time_claims() -> None:
    token = _json_token(_claims())

    parsed = parse(token, audience=AUD, expected_nonce=NONCE, max_token_bytes=MAX)

    assert parsed == AttestationToken(
        value=token, issued_at=1_900_000_000, expires_at=1_900_003_600
    )


def test_one_element_nonce_array_is_accepted() -> None:
    token = _json_token(_claims(eat_nonce=[NONCE]))

    parsed = parse(token, audience=AUD, expected_nonce=NONCE, max_token_bytes=MAX)

    assert (parsed.issued_at, parsed.expires_at) == (1_900_000_000, 1_900_003_600)


def test_token_of_exactly_the_maximum_size_is_accepted() -> None:
    token = _json_token(_claims())

    parsed = parse(token, audience=AUD, expected_nonce=NONCE, max_token_bytes=len(token))

    assert parsed.value == token


def test_token_over_the_maximum_size_is_rejected() -> None:
    token = _json_token(_claims())
    _assert_rejected(token, max_token_bytes=len(token) - 1)


def test_size_limit_counts_utf8_bytes_not_characters() -> None:
    token = _json_token(_claims(sub="é" * 10))
    multibyte = token + "é"
    _assert_rejected(multibyte, max_token_bytes=len(multibyte))


def test_text_that_is_not_encodable_as_utf8_is_rejected() -> None:
    _assert_rejected(_json_token(_claims()) + "\ud800")


@pytest.mark.parametrize(
    "token",
    [
        "",
        "onlyonesegment",
        "two.segments",
        "a.b.c.d",
        f"{HEADER}.{_b64(b'{}')}.{SIGNATURE}.extra",
    ],
)
def test_token_without_exactly_three_segments_is_rejected(token: str) -> None:
    _assert_rejected(token)


@pytest.mark.parametrize(
    "token",
    [
        _json_token(_claims()) + ".extra",
        _json_token(_claims()) + ".e.f",
        _json_token(_claims()).rsplit(".", 1)[0],
    ],
    ids=["four-segments", "five-segments", "two-segments"],
)
def test_otherwise_valid_token_with_another_segment_count_is_rejected(token: str) -> None:
    _assert_rejected(token)


def _valid_payload_segment() -> str:
    return _b64(json.dumps(_claims()).encode("utf-8"))


def _segment_containing(char: str) -> str:
    """A valid payload segment whose base64url text contains `char` ("-" or "_")."""
    for pad in range(3):
        segment = _b64(json.dumps(_claims(sub="x" * pad + "~~~???~~~???")).encode("utf-8"))
        if char in segment:
            return segment
    raise AssertionError(char)


@pytest.mark.parametrize(("urlsafe", "standard"), [("-", "+"), ("_", "/")])
def test_standard_base64_alphabet_is_rejected(urlsafe: str, standard: str) -> None:
    segment = _segment_containing(urlsafe)
    parse(_token(segment), audience=AUD, expected_nonce=NONCE, max_token_bytes=MAX)
    _assert_rejected(_token(segment.replace(urlsafe, standard)))


_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"


def _segment_with_remainder(remainder: int) -> str:
    """A valid payload segment whose length is `remainder` mod 4."""
    for pad in range(4):
        segment = _b64(json.dumps(_claims(sub="x" * pad)).encode("utf-8"))
        if len(segment) % 4 == remainder:
            return segment
    raise AssertionError(remainder)


@pytest.mark.parametrize("remainder", [2, 3])
def test_payload_with_non_zero_trailing_bits_is_rejected(remainder: int) -> None:
    segment = _segment_with_remainder(remainder)
    parse(_token(segment), audience=AUD, expected_nonce=NONCE, max_token_bytes=MAX)
    bumped = segment[:-1] + _ALPHABET[_ALPHABET.index(segment[-1]) + 1]
    padded = bumped + "=" * (-len(bumped) % 4)
    assert base64.urlsafe_b64decode(padded) == base64.urlsafe_b64decode(
        segment + "=" * (4 - remainder)
    )

    _assert_rejected(_token(bumped))


@pytest.mark.parametrize(
    "segment",
    [
        _valid_payload_segment() + "=",
        _valid_payload_segment() + "==",
        _valid_payload_segment()[:10] + " " + _valid_payload_segment()[10:],
        _valid_payload_segment() + "*",
        _valid_payload_segment() + "é",
        "eyJ",  # length 3 is fine, but this does not decode to a JSON object
        "e",  # length = 1 mod 4 is never valid base64
        "",
    ],
)
def test_payload_that_is_not_strict_unpadded_base64url_json_is_rejected(segment: str) -> None:
    _assert_rejected(_token(segment))


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff\xfe\x00\x00",
        b"not json",
        b"[]",
        b'"string"',
        b"1",
        b"null",
        b'{"iat": 1, "exp": 2',
        '{"aud": "x"}'.encode("utf-16"),
        b"[" * 100_000 + b"]" * 100_000,
        b'{"iat": 1' + b"0" * 5000 + b"}",
    ],
)
def test_payload_that_is_not_a_utf8_json_object_is_rejected(payload: bytes) -> None:
    _assert_rejected(_token(_b64(payload)), max_token_bytes=1_000_000)


@pytest.mark.parametrize(
    "claims",
    [
        _without("iat"),
        _without("exp"),
        _claims(iat="1900000000"),
        _claims(exp="1900003600"),
        _claims(iat=1_900_000_000.0),
        _claims(exp=1_900_003_600.5),
        _claims(iat=None),
        _claims(iat=True, exp=2),
        _claims(iat=0, exp=True),
        _claims(exp=1_900_000_000),
        _claims(exp=1_899_999_999),
    ],
)
def test_time_claims_must_be_integers_with_exp_after_iat(claims: dict[str, object]) -> None:
    _assert_rejected(_json_token(claims))


@pytest.mark.parametrize(
    "claims",
    [
        _without("aud"),
        _claims(aud="https://other.teecustody.test/aud"),
        _claims(aud=AUD + "/"),
        _claims(aud=[AUD]),
        _claims(aud=""),
    ],
)
def test_audience_must_equal_the_requested_audience(claims: dict[str, object]) -> None:
    _assert_rejected(_json_token(claims))


@pytest.mark.parametrize(
    "claims",
    [
        _without("eat_nonce"),
        _claims(eat_nonce="cd" * 32),
        _claims(eat_nonce=NONCE.upper()),
        _claims(eat_nonce=[]),
        _claims(eat_nonce=[NONCE, NONCE]),
        _claims(eat_nonce=[NONCE, "cd" * 32]),
        _claims(eat_nonce=["cd" * 32]),
        _claims(eat_nonce=[[NONCE]]),
        _claims(eat_nonce={"nonce": NONCE}),
        _claims(eat_nonce=None),
    ],
)
def test_nonce_must_be_the_expected_string_or_a_one_element_array_of_it(
    claims: dict[str, object],
) -> None:
    _assert_rejected(_json_token(claims))
