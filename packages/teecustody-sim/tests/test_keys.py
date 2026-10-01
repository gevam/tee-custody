"""T-07: simulator issuer key and development signer keys (API.md §C keys.py; SR-7)."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization

from teecustody_sim import DEV_SIGNER_ALGORITHM, SimKeys

PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi")
HEX64 = frozenset("0123456789abcdef")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def keys() -> SimKeys:
    return SimKeys.generate(2)


def test_generate_makes_requested_signers_and_an_unknown_signer_keyed_by_spki_sha256(
    keys: SimKeys,
) -> None:
    every = [*keys.signers, keys.unknown_signer]
    assert len(keys.signers) == 2
    key_ids = [signer.key_id for signer in every]
    assert len(set(key_ids)) == 3
    for signer in every:
        assert len(signer.key_id) == 64
        assert set(signer.key_id) <= HEX64
        assert signer.key_id == hashlib.sha256(signer.spki_der).hexdigest()
        assert signer.algorithm == DEV_SIGNER_ALGORITHM
        public = serialization.load_der_public_key(signer.spki_der)
        assert (
            public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            == signer.spki_der
        )


def test_issuer_jwks_is_one_public_rs256_key_with_rfc7638_thumbprint_kid(keys: SimKeys) -> None:
    jwks = keys.issuer_jwks()
    assert set(jwks) == {"keys"}
    entries = jwks["keys"]
    assert isinstance(entries, list)
    assert len(entries) == 1
    jwk = entries[0]
    assert isinstance(jwk, dict)
    assert set(jwk) == {"kty", "alg", "use", "kid", "n", "e"}
    for member in PRIVATE_JWK_MEMBERS:
        assert member not in jwk
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["e"] == "AQAB"
    n = jwk["n"]
    assert isinstance(n, str)
    assert "=" not in n
    assert len(base64.urlsafe_b64decode(n + "=" * (-len(n) % 4))) == 256
    thumbprint_input = json.dumps(
        {"e": jwk["e"], "kty": "RSA", "n": n}, sort_keys=True, separators=(",", ":")
    ).encode()
    assert keys.issuer_kid == _b64url(hashlib.sha256(thumbprint_input).digest())
    assert jwk["kid"] == keys.issuer_kid


def test_reprs_expose_no_key_material(keys: SimKeys) -> None:
    assert repr(keys) == "SimKeys(<redacted>)"
    assert str(keys) == "SimKeys(<redacted>)"
    for signer in [*keys.signers, keys.unknown_signer]:
        assert repr(signer) == f"SignerKeyMaterial(key_id={signer.key_id})"
        assert "PRIVATE" not in repr(signer)


@pytest.mark.parametrize("count", [0, -1, 17])
def test_generate_rejects_signer_count_out_of_range(count: int) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_SIGNERS_REQUIRED$"):
        SimKeys.generate(count)
