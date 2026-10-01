"""T-07: simulator token minting (API.md §C token.py; spec §15.2-§15.3; ADR 0009; D-016)."""

from __future__ import annotations

import base64
import hashlib
import json
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
