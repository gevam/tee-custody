"""T-07: claim alterations and the API.md §G negative-case catalog (spec §15.3; SR-3, SR-12)."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from teecustody_sim import (
    NEGATIVE_CASES,
    AlterClaim,
    DropClaim,
    LaunchConfig,
    NamedCase,
    SimKeys,
    TokenMinter,
    image_signature_payload,
    parse_alteration,
)

AUDIENCE = "https://audience.teecustody.test/tee"
NONCE = "5a" * 32
NOW = 1_900_000_000
TTL_S = 3600
MAX_AGE_S = 1800
IMAGE_DIGEST = "sha256:" + hashlib.sha256(b"teecustody-sim alteration image").hexdigest()
IMAGE_REFERENCE = "registry.test/team/app:2"
LAUNCH = LaunchConfig(
    image_reference=IMAGE_REFERENCE,
    image_digest=IMAGE_DIGEST,
    args=("/app",),
    env=(("MODE", "test"),),
)
SIGNED_PAYLOAD = image_signature_payload(IMAGE_REFERENCE, IMAGE_DIGEST)
PSS_SALT_32 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
SIGS = ("submods", "container", "image_signatures")

Claims = dict[str, Any]


def b64url_decode(segment: str) -> bytes:
    assert "=" not in segment
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def split(token: str) -> tuple[bytes, Claims, str, bytes]:
    header, payload, signature = token.split(".")
    return (
        b64url_decode(header),
        json.loads(b64url_decode(payload)),
        f"{header}.{payload}",
        b64url_decode(signature),
    )


def _signed_by(keys: SimKeys, signature_b64: str) -> str:
    """Label an image signature by the key that produced it over the default payload."""
    signature = base64.b64decode(signature_b64, validate=True)
    for signer in [*keys.signers, keys.unknown_signer]:
        public = serialization.load_der_public_key(signer.spki_der)
        assert isinstance(public, rsa.RSAPublicKey)
        try:
            public.verify(signature, SIGNED_PAYLOAD, PSS_SALT_32, hashes.SHA256())
        except InvalidSignature:
            continue
        return f"signed-by:{signer.key_id}"
    return "signed-by:nobody"


def normalized(keys: SimKeys, claims: Claims) -> Claims:
    """Claims with each (randomized PSS) image signature replaced by the key that made it."""
    result = copy.deepcopy(claims)
    for entry in result["submods"]["container"]["image_signatures"]:
        entry["signature"] = _signed_by(keys, entry["signature"])
    return result


# Objects that group claims; every other value (including the `env` object) is one claim.
CLAIM_CONTAINERS = frozenset({"", "submods", "submods.container", "submods.confidential_space"})


def changed_paths(before: Any, after: Any, prefix: str = "") -> set[str]:
    """Dotted claim paths whose value differs, was added, or was removed."""
    if prefix in CLAIM_CONTAINERS:
        paths: set[str] = set()
        for name in before.keys() | after.keys():
            path = f"{prefix}.{name}" if prefix else name
            if name not in before or name not in after:
                paths.add(path)
            else:
                paths |= changed_paths(before[name], after[name], path)
        return paths
    return set() if before == after else {prefix}


def issuer_public_key(keys: SimKeys) -> rsa.RSAPublicKey:
    entries = keys.issuer_jwks()["keys"]
    assert isinstance(entries, list)
    jwk = entries[0]
    assert isinstance(jwk, dict)
    n, e = jwk["n"], jwk["e"]
    assert isinstance(n, str)
    assert isinstance(e, str)
    return rsa.RSAPublicNumbers(
        int.from_bytes(b64url_decode(e), "big"), int.from_bytes(b64url_decode(n), "big")
    ).public_key()


def issuer_signature(keys: SimKeys, signing_input: str) -> bytes:
    """The correct RS256 signature over `signing_input` (PKCS#1 v1.5 is deterministic)."""
    return keys.sign_jws(signing_input.encode("ascii"))


def _entry(keys: SimKeys, index: int) -> dict[str, str]:
    signer = keys.signers[index]
    return {
        "key_id": signer.key_id,
        "signature": f"signed-by:{signer.key_id}",
        "signature_algorithm": signer.algorithm,
    }


def _set(path: tuple[str, ...], value: Any) -> Callable[[Claims, SimKeys], None]:
    def apply(claims: Claims, keys: SimKeys) -> None:
        node = claims
        for name in path[:-1]:
            node = node[name]
        node[path[-1]] = value(keys) if callable(value) else value

    return apply


def _drop(name: str) -> Callable[[Claims, SimKeys], None]:
    def apply(claims: Claims, keys: SimKeys) -> None:
        del claims[name]

    return apply


def _both(*edits: Callable[[Claims, SimKeys], None]) -> Callable[[Claims, SimKeys], None]:
    def apply(claims: Claims, keys: SimKeys) -> None:
        for edit in edits:
            edit(claims, keys)

    return apply


def _unchanged(claims: Claims, keys: SimKeys) -> None:
    return None


def _all_but_last(keys: SimKeys) -> list[dict[str, str]]:
    return [_entry(keys, i) for i in range(len(keys.signers) - 1)]


def _unknown_last(keys: SimKeys) -> list[dict[str, str]]:
    unknown = keys.unknown_signer
    return [
        *_all_but_last(keys),
        {
            "key_id": unknown.key_id,
            "signature": f"signed-by:{unknown.key_id}",
            "signature_algorithm": unknown.algorithm,
        },
    ]


def _pkcs1_first(keys: SimKeys) -> list[dict[str, str]]:
    first = {**_entry(keys, 0), "signature_algorithm": "RSASSA_PKCS1V15_SHA256"}
    return [first, *(_entry(keys, i) for i in range(1, len(keys.signers)))]


def _first_duplicated_last(keys: SimKeys) -> list[dict[str, str]]:
    return [*_all_but_last(keys), _entry(keys, 0)]


# API.md §G "Produced from the valid token by", transcribed independently of the minter.
CLAIM_EDITS: dict[str, Callable[[Claims, SimKeys], None]] = {
    "alg_none": _unchanged,
    "token_signature_corrupted": _unchanged,
    "issuer_wrong": _set(("iss",), "https://issuer.invalid"),
    "issuer_missing": _drop("iss"),
    "audience_wrong": _set(("aud",), "https://audience.invalid"),
    "audience_missing": _drop("aud"),
    "expired": _both(_set(("iat",), NOW - 120), _set(("exp",), NOW - 60)),
    "exp_missing": _drop("exp"),
    "iat_stale": _set(("iat",), NOW - MAX_AGE_S - 60),
    "iat_future": _set(("iat",), NOW + MAX_AGE_S + 60),
    "nbf_future": _set(("nbf",), NOW + 600),
    "nonce_wrong": _set(("eat_nonce",), hashlib.sha256(b"teecustody-sim wrong nonce").hexdigest()),
    "nonce_missing": _drop("eat_nonce"),
    "hwmodel_unlisted": _set(("hwmodel",), "GCP_AMD_SEV"),
    "swname_wrong": _set(("swname",), "GCE"),
    "secboot_false": _set(("secboot",), False),
    "dbgstat_enabled": _set(("dbgstat",), "enabled"),
    "dbgstat_missing": _drop("dbgstat"),
    "stable_missing": _set(
        ("submods", "confidential_space", "support_attributes"), ["LATEST", "USABLE"]
    ),
    "digest_unknown": _set(
        ("submods", "container", "image_digest"),
        "sha256:" + hashlib.sha256(b"teecustody-sim unknown image").hexdigest(),
    ),
    "signatures_insufficient": _set(SIGS, _all_but_last),
    "signer_unknown": _set(SIGS, _unknown_last),
    "signature_algorithm_mismatch": _set(SIGS, _pkcs1_first),
    "args_altered": _set(("submods", "container", "args"), ["/app", "--debug"]),
    "env_altered": _set(
        ("submods", "container", "env"), {"MODE": "test", "TEECUSTODY_SIM_ALTERED": "1"}
    ),
    "debug_bad_signature": _set(("dbgstat",), "enabled"),
    "key_id_duplicated": _set(SIGS, _first_duplicated_last),
}
CORRUPTED_SIGNATURE = {"token_signature_corrupted", "debug_bad_signature"}
CASE_IDS = [case.case_id for case in NEGATIVE_CASES]


@pytest.fixture(scope="module", params=[2, 3], ids=["2-signers", "3-signers"])
def keys(request: pytest.FixtureRequest) -> SimKeys:
    count = request.param
    assert isinstance(count, int)
    return SimKeys.generate(count)


@pytest.fixture(scope="module")
def minter(keys: SimKeys) -> TokenMinter:
    return TokenMinter(keys, LAUNCH, ttl_s=TTL_S, token_max_age_s=MAX_AGE_S)


@pytest.fixture(scope="module")
def default(keys: SimKeys, minter: TokenMinter) -> tuple[bytes, Claims]:
    header, claims, _, _ = split(minter.mint(AUDIENCE, [NONCE], NOW))
    return header, normalized(keys, claims)


def test_catalog_covers_every_case_in_table_order() -> None:
    assert list(CLAIM_EDITS) == CASE_IDS


@pytest.mark.parametrize("case", NEGATIVE_CASES, ids=CASE_IDS)
def test_named_case_changes_exactly_the_altered_paths_as_specified(
    keys: SimKeys, minter: TokenMinter, default: tuple[bytes, Claims], case: Any
) -> None:
    _, default_claims = default

    _, claims, _, _ = split(minter.mint(AUDIENCE, [NONCE], NOW, NamedCase(case.case_id)))

    actual = normalized(keys, claims)
    expected = copy.deepcopy(default_claims)
    CLAIM_EDITS[case.case_id](expected, keys)
    assert actual == expected
    assert changed_paths(default_claims, actual) == set(case.altered)


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_named_case_header_and_token_signature_are_as_specified(
    keys: SimKeys, minter: TokenMinter, default: tuple[bytes, Claims], case_id: str
) -> None:
    default_header, _ = default

    header, _, signing_input, signature = split(
        minter.mint(AUDIENCE, [NONCE], NOW, NamedCase(case_id))
    )

    if case_id == "alg_none":
        assert header == b'{"alg":"none","typ":"JWT"}'
        assert signature == b""
        return
    assert header == default_header
    correct = issuer_signature(keys, signing_input)
    if case_id in CORRUPTED_SIGNATURE:
        assert signature == bytes([correct[0] ^ 0x01]) + correct[1:]
        with pytest.raises(InvalidSignature):
            issuer_public_key(keys).verify(
                signature, signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()
            )
    else:
        assert signature == correct
        issuer_public_key(keys).verify(
            signature, signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()
        )


def test_alg_none_token_ends_with_an_empty_signature_segment(minter: TokenMinter) -> None:
    token = minter.mint(AUDIENCE, [NONCE], NOW, NamedCase("alg_none"))
    assert token.count(".") == 2
    assert token.endswith(".")


def test_unknown_case_id_is_rejected(minter: TokenMinter) -> None:
    with pytest.raises(ValueError, match=r"^UNKNOWN_CASE$"):
        minter.mint(AUDIENCE, [NONCE], NOW, NamedCase("valid"))
    with pytest.raises(ValueError, match=r"^UNKNOWN_CASE$"):
        minter.mint(AUDIENCE, [NONCE], NOW, NamedCase("nope"))


def _verified_claims(keys: SimKeys, token: str) -> Claims:
    header, claims, signing_input, signature = split(token)
    assert json.loads(header) == {"alg": "RS256", "kid": keys.issuer_kid, "typ": "JWT"}
    issuer_public_key(keys).verify(
        signature, signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()
    )
    return claims


def test_alter_claim_sets_the_value_and_re_signs(
    keys: SimKeys, minter: TokenMinter, default: tuple[bytes, Claims]
) -> None:
    token = minter.mint(AUDIENCE, [NONCE], NOW, AlterClaim(("dbgstat",), "enabled"))

    claims = normalized(keys, _verified_claims(keys, token))
    assert claims["dbgstat"] == "enabled"
    assert changed_paths(default[1], claims) == {"dbgstat"}


def test_alter_claim_may_add_a_leaf_under_an_existing_parent(
    keys: SimKeys, minter: TokenMinter, default: tuple[bytes, Claims]
) -> None:
    token = minter.mint(
        AUDIENCE, [NONCE], NOW, AlterClaim(("submods", "container", "extra"), [1, "a", None])
    )

    claims = normalized(keys, _verified_claims(keys, token))
    assert claims["submods"]["container"]["extra"] == [1, "a", None]
    assert changed_paths(default[1], claims) == {"submods.container.extra"}


def test_drop_claim_removes_the_claim_and_re_signs(
    keys: SimKeys, minter: TokenMinter, default: tuple[bytes, Claims]
) -> None:
    token = minter.mint(AUDIENCE, [NONCE], NOW, DropClaim(("submods", "container", "args")))

    claims = normalized(keys, _verified_claims(keys, token))
    assert "args" not in claims["submods"]["container"]
    assert changed_paths(default[1], claims) == {"submods.container.args"}


@pytest.mark.parametrize(
    "alteration",
    [
        AlterClaim((), "x"),
        AlterClaim(("nope", "leaf"), "x"),
        AlterClaim(("submods", "nope", "leaf"), "x"),
        AlterClaim(("iss", "leaf"), "x"),
        AlterClaim(("submods", "container", "args", "leaf"), "x"),
        DropClaim(()),
        DropClaim(("nope",)),
        DropClaim(("submods", "container", "nope")),
        DropClaim(("nope", "leaf")),
        DropClaim(("aud", "leaf")),
    ],
    ids=repr,
)
def test_alteration_on_a_missing_path_is_rejected(
    minter: TokenMinter, alteration: AlterClaim | DropClaim
) -> None:
    with pytest.raises(ValueError, match=r"^PATH_NOT_FOUND$"):
        minter.mint(AUDIENCE, [NONCE], NOW, alteration)


def test_drop_of_an_absent_nonce_is_rejected(minter: TokenMinter) -> None:
    with pytest.raises(ValueError, match=r"^PATH_NOT_FOUND$"):
        minter.mint(AUDIENCE, [], NOW, DropClaim(("eat_nonce",)))


@pytest.mark.parametrize(
    ("kind", "text", "expected"),
    [
        ("alter", "secboot=false", AlterClaim(("secboot",), False)),
        ("alter", "dbgstat=enabled", AlterClaim(("dbgstat",), "enabled")),
        ("alter", "exp=123", AlterClaim(("exp",), 123)),
        ("alter", "eat_nonce=null", AlterClaim(("eat_nonce",), None)),
        ("alter", 'aud="quoted"', AlterClaim(("aud",), "quoted")),
        ("alter", "aud=", AlterClaim(("aud",), "")),
        ("alter", "iss=https://a.test/?x=1", AlterClaim(("iss",), "https://a.test/?x=1")),
        (
            "alter",
            'submods.container.args=["/app","--x"]',
            AlterClaim(("submods", "container", "args"), ["/app", "--x"]),
        ),
        (
            "alter",
            'submods.container.env={"K":"V"}',
            AlterClaim(("submods", "container", "env"), {"K": "V"}),
        ),
        ("alter", "_a.b_2=x", AlterClaim(("_a", "b_2"), "x")),
        ("drop", "submods.container.args", DropClaim(("submods", "container", "args"))),
        ("drop", "iss", DropClaim(("iss",))),
        ("case", "dbgstat_enabled", NamedCase("dbgstat_enabled")),
        ("case", "key_id_duplicated", NamedCase("key_id_duplicated")),
    ],
)
def test_parse_alteration_accepts_cli_text(kind: Any, text: str, expected: object) -> None:
    assert parse_alteration(kind, text) == expected


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_parse_alteration_accepts_every_catalog_case(case_id: str) -> None:
    assert parse_alteration("case", case_id) == NamedCase(case_id)


@pytest.mark.parametrize(
    "value", ["1.5", "1e3", "NaN", "Infinity", "-Infinity", "[1.5]", '{"a":2.0}']
)
def test_parse_alteration_keeps_non_integer_numbers_as_literal_text(value: str) -> None:
    assert parse_alteration("alter", f"iat={value}") == AlterClaim(("iat",), value)


@pytest.mark.parametrize(
    ("kind", "text"),
    [
        ("alter", "a..b=1"),
        ("alter", "A=1"),
        ("alter", "noequals"),
        ("alter", "=1"),
        ("alter", ".a=1"),
        ("alter", "a.=1"),
        ("alter", "1a=1"),
        ("alter", "a-b=1"),
        ("alter", "a\n=1"),
        ("alter", "é=1"),
        ("drop", ""),
        ("drop", "a.b."),
        ("drop", "a\n"),
        ("drop", "a=b"),
        ("drop", "a b"),
        ("case", "nope"),
        ("case", "valid"),
        ("case", "DBGSTAT_ENABLED"),
        ("case", ""),
        ("bogus", "iss"),
    ],
)
def test_parse_alteration_rejects_invalid_text(kind: Any, text: str) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_ALTERATION$"):
        parse_alteration(kind, text)


def test_parse_alteration_keeps_json_nested_beyond_the_parser_limit_as_literal_text() -> None:
    deep = "[" * 100_000 + "]" * 100_000
    assert parse_alteration("alter", f"aud={deep}") == AlterClaim(("aud",), deep)


@pytest.mark.parametrize("case_id", ["signature_algorithm_mismatch", "key_id_duplicated"])
def test_entry_editing_case_without_listed_signatures_is_rejected(
    keys: SimKeys, monkeypatch: pytest.MonkeyPatch, case_id: str
) -> None:
    for signer in keys.signers:
        monkeypatch.setattr(signer, "sign", lambda payload: b"\x00" * 256)
    minter = TokenMinter(keys, LAUNCH, ttl_s=TTL_S, token_max_age_s=MAX_AGE_S)

    with pytest.raises(ValueError, match=r"^PATH_NOT_FOUND$"):
        minter.mint(AUDIENCE, [NONCE], NOW, NamedCase(case_id))


@pytest.mark.parametrize("case_id", ["alg_none", "token_signature_corrupted"])
def test_signature_cases_keep_the_valid_payload_bytes(minter: TokenMinter, case_id: str) -> None:
    valid = minter.mint(AUDIENCE, [NONCE], NOW).split(".")[1]
    assert minter.mint(AUDIENCE, [NONCE], NOW, NamedCase(case_id)).split(".")[1] == valid


@pytest.mark.parametrize(
    "text",
    [
        "aud=\ud800",
        "aud=x\udcff",
        'aud="\\ud800"',
        'submods.container.args=["\\udfff"]',
        'submods.container.env={"\\ud800":"v"}',
    ],
    ids=["raw", "raw-surrogateescape", "json-escape", "json-in-array", "json-in-key"],
)
def test_parse_alteration_rejects_values_not_encodable_as_utf8(text: str) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_ALTERATION$"):
        parse_alteration("alter", text)
