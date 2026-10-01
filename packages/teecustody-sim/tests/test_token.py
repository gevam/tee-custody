"""T-07: simulator token minting (API.md §C token.py; spec §15.2-§15.3; ADR 0009; D-016)."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from teecustody_sim import (
    DBGSTAT_DISABLED,
    SIM_HWMODEL,
    SIM_ISSUER,
    SUPPORT_ATTRIBUTES,
    SWNAME,
    LaunchConfig,
    SimKeys,
    TokenMinter,
    frame_jws,
    image_signature_payload,
)

AUDIENCE = "https://audience.teecustody.test/tee"
NONCE = "c0ffee" * 10 + "abcd"
NOW = 1_900_000_000
TTL_S = 3600
IMAGE_DIGEST = "sha256:" + hashlib.sha256(b"teecustody-sim test image").hexdigest()
IMAGE_REFERENCE = f"registry.test:5000/team/app:1.2@{IMAGE_DIGEST}"
LAUNCH = LaunchConfig(
    image_reference=IMAGE_REFERENCE,
    image_digest=IMAGE_DIGEST,
    args=("/app", "--port=8080"),
    env=(("MODE", "test"), ("REGION", "eu")),
)
PSS_SALT_32 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def b64url_decode(segment: str) -> bytes:
    assert "=" not in segment
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decode(token: str) -> tuple[bytes, bytes, bytes]:
    header, payload, signature = token.split(".")
    return b64url_decode(header), b64url_decode(payload), b64url_decode(signature)


def jwk_public_key(keys: SimKeys) -> rsa.RSAPublicKey:
    jwks = keys.issuer_jwks()
    entries = jwks["keys"]
    assert isinstance(entries, list)
    jwk = entries[0]
    assert isinstance(jwk, dict)
    n, e = jwk["n"], jwk["e"]
    assert isinstance(n, str)
    assert isinstance(e, str)
    numbers = rsa.RSAPublicNumbers(
        int.from_bytes(b64url_decode(e), "big"), int.from_bytes(b64url_decode(n), "big")
    )
    return numbers.public_key()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def signature_verifies(spki_der: bytes, signature_b64: str, payload: bytes) -> bool:
    public = serialization.load_der_public_key(spki_der)
    assert isinstance(public, rsa.RSAPublicKey)
    try:
        public.verify(
            base64.b64decode(signature_b64, validate=True), payload, PSS_SALT_32, hashes.SHA256()
        )
    except InvalidSignature:
        return False
    return True


@pytest.fixture(scope="module")
def keys() -> SimKeys:
    return SimKeys.generate(2)


@pytest.fixture(scope="module")
def minter(keys: SimKeys) -> TokenMinter:
    return TokenMinter(keys, LAUNCH, ttl_s=TTL_S, token_max_age_s=3600)


def expected_claims_without_signatures() -> dict[str, Any]:
    return {
        "iss": SIM_ISSUER,
        "aud": AUDIENCE,
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + TTL_S,
        "eat_nonce": NONCE,
        "hwmodel": SIM_HWMODEL,
        "swname": SWNAME,
        "secboot": True,
        "dbgstat": DBGSTAT_DISABLED,
        "submods": {
            "confidential_space": {"support_attributes": list(SUPPORT_ATTRIBUTES)},
            "container": {
                "image_reference": IMAGE_REFERENCE,
                "image_digest": IMAGE_DIGEST,
                "args": ["/app", "--port=8080"],
                "env": {"MODE": "test", "REGION": "eu"},
            },
        },
    }


def test_default_token_header_is_rs256_with_issuer_kid(keys: SimKeys, minter: TokenMinter) -> None:
    header, _, _ = decode(minter.mint(AUDIENCE, [NONCE], NOW))
    assert header == canonical({"alg": "RS256", "kid": keys.issuer_kid, "typ": "JWT"})
    assert header == b'{"alg":"RS256","kid":"' + keys.issuer_kid.encode() + b'","typ":"JWT"}'


def test_default_token_verifies_under_the_jwks_key(keys: SimKeys, minter: TokenMinter) -> None:
    token = minter.mint(AUDIENCE, [NONCE], NOW)
    signing_input, _, signature = token.rpartition(".")
    jwk_public_key(keys).verify(
        b64url_decode(signature), signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )


def test_default_token_claims_and_types_are_production_shaped(minter: TokenMinter) -> None:
    _, payload, _ = decode(minter.mint(AUDIENCE, [NONCE], NOW))
    claims = json.loads(payload)

    assert payload == canonical(claims)
    container = claims["submods"]["container"]
    signatures = container.pop("image_signatures")
    assert isinstance(signatures, list)
    assert claims == expected_claims_without_signatures()
    for name in ("iat", "nbf", "exp"):
        assert type(claims[name]) is int
    assert claims["secboot"] is True
    assert "STABLE" in claims["submods"]["confidential_space"]["support_attributes"]


def test_default_token_lists_every_signer_in_order_with_spki_key_id_and_algorithm(
    keys: SimKeys, minter: TokenMinter
) -> None:
    _, payload, _ = decode(minter.mint(AUDIENCE, [NONCE], NOW))
    entries = json.loads(payload)["submods"]["container"]["image_signatures"]
    signed_payload = image_signature_payload(IMAGE_REFERENCE, IMAGE_DIGEST)

    assert len(entries) == len(keys.signers)
    for entry, signer in zip(entries, keys.signers, strict=True):
        assert set(entry) == {"key_id", "signature", "signature_algorithm"}
        assert entry["key_id"] == signer.key_id
        assert entry["key_id"] == hashlib.sha256(signer.spki_der).hexdigest()
        assert entry["signature_algorithm"] == signer.algorithm
        assert entry["signature"] == base64.b64encode(
            base64.b64decode(entry["signature"], validate=True)
        ).decode("ascii")
        assert signature_verifies(signer.spki_der, entry["signature"], signed_payload)


def test_claims_returns_the_minted_payload(minter: TokenMinter) -> None:
    claims = minter.claims(AUDIENCE, [NONCE], NOW)
    container = claims["submods"]
    assert isinstance(container, dict)
    inner = container["container"]
    assert isinstance(inner, dict)
    assert len(inner.pop("image_signatures")) == 2  # type: ignore[arg-type]
    assert claims == expected_claims_without_signatures()


def test_token_carries_an_explicit_issuer(keys: SimKeys) -> None:
    minter = TokenMinter(
        keys, LAUNCH, issuer="https://issuer.teecustody.test", ttl_s=60, token_max_age_s=60
    )
    _, payload, _ = decode(minter.mint(AUDIENCE, [NONCE], NOW))
    claims = json.loads(payload)
    assert claims["iss"] == "https://issuer.teecustody.test"
    assert claims["exp"] == NOW + 60


@pytest.mark.parametrize(
    ("reference", "expected_reference"),
    [
        (IMAGE_REFERENCE, "registry.test:5000/team/app"),
        ("registry.test:5000/team/app", "registry.test:5000/team/app"),
        ("registry.test:5000/team/app:1.2", "registry.test:5000/team/app"),
        (f"app@{IMAGE_DIGEST}", "app"),
        ("app:latest", "app"),
    ],
)
def test_image_signature_payload_is_the_simple_signing_shape(
    reference: str, expected_reference: str
) -> None:
    payload = image_signature_payload(reference, IMAGE_DIGEST)
    assert (
        payload
        == (
            '{"critical":{"identity":{"docker-reference":"'
            + expected_reference
            + '"},"image":{"docker-manifest-digest":"'
            + IMAGE_DIGEST
            + '"},"type":"cosign container image signature"},"optional":null}'
        ).encode()
    )


# RFC 7515 Appendix A.2 (RS256), transcribed from the RFC text. The private key is the RFC's
# published example key, not a secret; it exists only as the ADR 0009 known-answer oracle.
RFC7515_A2_JWK = {
    "n": (
        "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp"
        "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOW"
        "vG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs"
        "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9k"
        "G4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2"
        "PAcDTW9gb54h4FRWyuXpoQ"
    ),
    "e": "AQAB",
    "d": (
        "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_G"
        "Q5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKV"
        "RUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9J"
        "YanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoF"
        "aFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjn"
        "czT0QU91p1DhOVRuOopznQ"
    ),
    "p": (
        "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBds"
        "s1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ"
        "5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
    ),
    "q": (
        "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHA"
        "jLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLt"
        "XlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
    ),
    "dp": (
        "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE"
        "2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_"
        "YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"
    ),
    "dq": (
        "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDo"
        "RwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGN"
        "pmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"
    ),
    "qi": (
        "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0Em"
        "pScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1c"
        "q9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
    ),
}
RFC7515_A2_HEADER_OCTETS = bytes([123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 50, 53, 54, 34, 125])
RFC7515_A2_PAYLOAD_OCTETS = (
    b'{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
)
RFC7515_A2_COMPACT = (
    "eyJhbGciOiJSUzI1NiJ9"
    "."
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    "."
    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
    "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
    "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
    "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
    "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
    "p0igcN_IoypGlUPQGe77Rw"
)


def rfc7515_a2_private_key() -> rsa.RSAPrivateKey:
    def number(name: str) -> int:
        return int.from_bytes(b64url_decode(RFC7515_A2_JWK[name]), "big")

    public = rsa.RSAPublicNumbers(number("e"), number("n"))
    private = rsa.RSAPrivateNumbers(
        p=number("p"),
        q=number("q"),
        d=number("d"),
        dmp1=number("dp"),
        dmq1=number("dq"),
        iqmp=number("qi"),
        public_numbers=public,
    )
    return private.private_key()


def test_frame_jws_reproduces_rfc7515_appendix_a2_byte_for_byte() -> None:
    key = rfc7515_a2_private_key()
    signing_inputs: list[bytes] = []

    def sign(signing_input: bytes) -> bytes:
        signing_inputs.append(signing_input)
        return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    compact = frame_jws(RFC7515_A2_HEADER_OCTETS, RFC7515_A2_PAYLOAD_OCTETS, sign)

    assert compact == RFC7515_A2_COMPACT
    assert signing_inputs == [RFC7515_A2_COMPACT.rpartition(".")[0].encode("ascii")]


def _broken_sign(payload: bytes) -> bytes:
    return secrets.token_bytes(256)


def _listed_key_ids(minter: TokenMinter) -> list[str]:
    _, payload, _ = decode(minter.mint(AUDIENCE, [NONCE], NOW))
    entries = json.loads(payload)["submods"]["container"]["image_signatures"]
    return [entry["key_id"] for entry in entries]


def test_minter_omits_an_image_signature_that_does_not_verify(
    keys: SimKeys, minter: TokenMinter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(keys.signers[1], "sign", _broken_sign)

    assert _listed_key_ids(minter) == [keys.signers[0].key_id]


def test_minter_lists_no_image_signatures_when_every_signer_is_broken(
    keys: SimKeys, minter: TokenMinter, monkeypatch: pytest.MonkeyPatch
) -> None:
    for signer in keys.signers:
        monkeypatch.setattr(signer, "sign", _broken_sign)

    assert _listed_key_ids(minter) == []
