"""T-17: development trust profile (API.md §C profile.py, §A, §E; D-016; SR-1 (i))."""

from __future__ import annotations

import copy
import hashlib
import math
from collections.abc import Sequence
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from teecustody_sim import (
    DEV_SIGNER_ALGORITHM,
    SIM_HWMODEL,
    SIM_ISSUER,
    LaunchConfig,
    SignerKeyMaterial,
    SimKeys,
    build_trust_profile,
    launch_config_hashes,
)

DISCOVERY_URL = "http://127.0.0.1:8791/.well-known/openid-configuration"
JWKS_ORIGIN = "http://127.0.0.1:8791"
AUDIENCE = "https://example.test/tee"
IMAGE_DIGEST = "sha256:" + hashlib.sha256(b"teecustody-sim profile test image").hexdigest()
LAUNCH = LaunchConfig(
    image_reference="localhost/profile-test:1",
    image_digest=IMAGE_DIGEST,
    args=("/app/workload",),
    env=(("PYTHONUNBUFFERED", "1"),),
)
ARGS_HASH = "0d7b8d1aa29f148b5f78df8a6214175db1991281625e7727ce2ca5945f090c99"
ENV_HASH = "942fabd2e68b234f374ade89d81e9adf3414e9603216bb66b8252ceff35f3ecb"
RSA_ENCRYPTION_OID = bytes.fromhex("06092a864886f70d010101")
RSASSA_PSS_OID = bytes.fromhex("06092a864886f70d01010a")
DER_NULL = bytes.fromhex("0500")
UNKNOWN_ALGORITHM_OID = bytes.fromhex("06032a0304")


@pytest.fixture(scope="module")
def keys() -> SimKeys:
    return SimKeys.generate(2)


def _der(tag: int, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        return bytes([tag, size]) + content
    length = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def _spki(algorithm_identifier: bytes, subject_public_key: bytes) -> bytes:
    """SubjectPublicKeyInfo DER: SEQUENCE { AlgorithmIdentifier, BIT STRING (no unused bits) }."""
    return _der(0x30, _der(0x30, algorithm_identifier) + _der(0x03, b"\x00" + subject_public_key))


def _rsa_public_key_der(signer: SignerKeyMaterial) -> bytes:
    public_key = serialization.load_der_public_key(signer.spki_der)
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)


def _signer(public_key: PublicKeyTypes, algorithm: str) -> SignerKeyMaterial:
    """A signer as the profile builder sees it: canonical SPKI DER plus a declared algorithm."""
    signer = SignerKeyMaterial.__new__(SignerKeyMaterial)
    signer.spki_der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signer.algorithm = algorithm
    signer.key_id = hashlib.sha256(signer.spki_der).hexdigest()
    return signer


def _rsa_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _same_modulus(key: rsa.RSAPrivateKey, public_exponent: int) -> rsa.RSAPublicKey:
    return rsa.RSAPublicNumbers(public_exponent, key.public_key().public_numbers().n).public_key()


def _profile(signers: Sequence[SignerKeyMaterial], signers_required: int) -> dict[str, object]:
    return build_trust_profile(
        discovery_url=DISCOVERY_URL,
        jwks_origin=JWKS_ORIGIN,
        expected_audience=AUDIENCE,
        launch=LAUNCH,
        signers=signers,
        signers_required=signers_required,
    )


def test_launch_config_hashes_are_sha256_of_canonical_cbor_args_and_env() -> None:
    args_hash, env_hash = launch_config_hashes(["/app/workload"], [("PYTHONUNBUFFERED", "1")])

    assert args_hash == ARGS_HASH
    assert env_hash == ENV_HASH


def test_build_trust_profile_has_exactly_the_documented_keys_and_values(keys: SimKeys) -> None:
    profile = build_trust_profile(
        discovery_url=DISCOVERY_URL,
        jwks_origin=JWKS_ORIGIN,
        expected_audience=AUDIENCE,
        launch=LAUNCH,
        signers=keys.signers,
        signers_required=2,
        token_max_age_s=1800,
    )

    assert profile == {
        "profile_version": 1,
        "profile_kind": "development",
        "token_type": "OIDC",
        "issuer": SIM_ISSUER,
        "discovery_url": DISCOVERY_URL,
        "jwks_origin": JWKS_ORIGIN,
        "expected_audience": AUDIENCE,
        "token_max_age_s": 1800,
        "allowed_hwmodels": [SIM_HWMODEL],
        "allowed_digests": [IMAGE_DIGEST],
        "signer_keys": [
            {
                "key_id": hashlib.sha256(signer.spki_der).hexdigest(),
                "algorithm": DEV_SIGNER_ALGORITHM,
            }
            for signer in keys.signers
        ],
        "signers_required": 2,
        "expected_args_hash": ARGS_HASH,
        "expected_env_hash": ENV_HASH,
    }


def test_build_trust_profile_token_max_age_defaults_to_spec_value(keys: SimKeys) -> None:
    profile = build_trust_profile(
        discovery_url=DISCOVERY_URL,
        jwks_origin=JWKS_ORIGIN,
        expected_audience=AUDIENCE,
        launch=LAUNCH,
        signers=keys.signers,
        signers_required=2,
    )

    assert profile["token_max_age_s"] == 3600


def test_signer_key_id_is_computed_from_spki_never_copied(
    keys: SimKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    for signer in keys.signers:
        monkeypatch.setattr(signer, "key_id", "0" * 64)

    profile = build_trust_profile(
        discovery_url=DISCOVERY_URL,
        jwks_origin=JWKS_ORIGIN,
        expected_audience=AUDIENCE,
        launch=LAUNCH,
        signers=keys.signers,
        signers_required=2,
    )

    assert profile["signer_keys"] == [
        {"key_id": hashlib.sha256(signer.spki_der).hexdigest(), "algorithm": signer.algorithm}
        for signer in keys.signers
    ]


@pytest.mark.parametrize(
    "signers_required",
    [3, 0, -1, True, 1.0, "1", None],
    ids=["above-count", "zero", "negative", "bool", "float", "str", "none"],
)
def test_signers_required_outside_one_to_signer_count_is_rejected(
    keys: SimKeys, signers_required: object
) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_SIGNERS_REQUIRED$"):
        _profile(keys.signers, signers_required)  # type: ignore[arg-type]


def test_an_empty_signer_list_is_rejected() -> None:
    with pytest.raises(ValueError, match=r"^INVALID_SIGNERS_REQUIRED$"):
        _profile([], 1)


@pytest.mark.parametrize("signers_required", [1, 2])
def test_signers_required_from_one_to_signer_count_is_accepted(
    keys: SimKeys, signers_required: int
) -> None:
    assert _profile(keys.signers, signers_required)["signers_required"] == signers_required


def test_the_test_spki_builder_reproduces_the_canonical_encoding(keys: SimKeys) -> None:
    signer = keys.signers[0]
    rebuilt = _spki(RSA_ENCRYPTION_OID + DER_NULL, _rsa_public_key_der(signer))

    assert rebuilt == signer.spki_der


@pytest.mark.parametrize(
    "algorithm_identifier",
    [RSASSA_PSS_OID, RSA_ENCRYPTION_OID],
    ids=["id-RSASSA-PSS", "rsaEncryption-without-NULL-parameters"],
)
def test_re_encoded_spki_of_a_signer_key_is_rejected(
    keys: SimKeys, monkeypatch: pytest.MonkeyPatch, algorithm_identifier: bytes
) -> None:
    signer = keys.signers[1]
    monkeypatch.setattr(
        signer, "spki_der", _spki(algorithm_identifier, _rsa_public_key_der(signer))
    )

    with pytest.raises(ValueError, match=r"^NONCANONICAL_SIGNER_SPKI$"):
        _profile(keys.signers, 1)


@pytest.mark.parametrize(
    "spki_der",
    [b"", b"\x30\x00", _spki(UNKNOWN_ALGORITHM_OID, b"\x01\x02\x03")],
    ids=["empty", "empty-sequence", "unknown-algorithm"],
)
def test_unloadable_signer_spki_is_rejected(
    keys: SimKeys, monkeypatch: pytest.MonkeyPatch, spki_der: bytes
) -> None:
    monkeypatch.setattr(keys.signers[0], "spki_der", spki_der)

    with pytest.raises(ValueError, match=r"^NONCANONICAL_SIGNER_SPKI$"):
        _profile(keys.signers, 1)


def test_the_same_signer_twice_is_rejected_even_when_one_signature_is_required(
    keys: SimKeys,
) -> None:
    signer = keys.signers[0]

    with pytest.raises(ValueError, match=r"^DUPLICATE_SIGNER_KEY$"):
        _profile([signer, keys.signers[1], signer], 1)


def test_two_signer_objects_with_equal_key_material_are_rejected(keys: SimKeys) -> None:
    twin = copy.copy(keys.signers[1])
    assert twin is not keys.signers[1]

    with pytest.raises(ValueError, match=r"^DUPLICATE_SIGNER_KEY$"):
        _profile([*keys.signers, twin], 1)


def test_the_same_key_loaded_twice_from_state_is_rejected(tmp_path: Path) -> None:
    first = SimKeys.load_or_create(tmp_path / "state", 1)
    second = SimKeys.load_or_create(tmp_path / "state", 1)
    assert first.signers[0] is not second.signers[0]

    with pytest.raises(ValueError, match=r"^DUPLICATE_SIGNER_KEY$"):
        _profile([first.signers[0], second.signers[0]], 1)


def test_signer_checks_precede_the_signers_required_check(
    keys: SimKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = keys.signers[0]
    with pytest.raises(ValueError, match=r"^DUPLICATE_SIGNER_KEY$"):
        _profile([signer, signer], 3)

    monkeypatch.setattr(signer, "spki_der", b"")
    with pytest.raises(ValueError, match=r"^NONCANONICAL_SIGNER_SPKI$"):
        _profile([signer], 2)


def test_generated_signers_pass_with_distinct_key_ids(keys: SimKeys) -> None:
    profile = _profile(keys.signers, 2)

    signer_keys = profile["signer_keys"]
    assert isinstance(signer_keys, list)
    key_ids = [entry["key_id"] for entry in signer_keys]
    assert len(key_ids) == 2
    assert len(set(key_ids)) == 2


@pytest.mark.parametrize("other_exponent", ["3", "65537+lambda(n)"])
def test_rsa_signers_sharing_a_modulus_are_one_holder(other_exponent: str) -> None:
    key = _rsa_private_key()
    private = key.private_numbers()
    carmichael = math.lcm(private.p - 1, private.q - 1)
    exponent = 3 if other_exponent == "3" else 65537 + carmichael
    first = _signer(key.public_key(), "RSASSA_PSS_SHA256")
    second = _signer(_same_modulus(key, exponent), "RSASSA_PSS_SHA256")
    assert first.spki_der != second.spki_der

    with pytest.raises(ValueError, match=r"^DUPLICATE_SIGNER_KEY$"):
        _profile([first, second], 1)


def test_p256_signers_with_the_same_point_are_one_holder_whatever_they_declare() -> None:
    point = ec.generate_private_key(ec.SECP256R1()).public_key()

    with pytest.raises(ValueError, match=r"^DUPLICATE_SIGNER_KEY$"):
        _profile([_signer(point, "ECDSA_P256_SHA256"), _signer(point, "RSASSA_PSS_SHA256")], 1)


def test_distinct_rsa_and_p256_keys_are_distinct_holders() -> None:
    signers = [
        _signer(_rsa_private_key().public_key(), "RSASSA_PSS_SHA256"),
        _signer(_rsa_private_key().public_key(), "RSASSA_PKCS1V15_SHA256"),
        _signer(ec.generate_private_key(ec.SECP256R1()).public_key(), "ECDSA_P256_SHA256"),
        _signer(ec.generate_private_key(ec.SECP256R1()).public_key(), "ECDSA_P256_SHA256"),
    ]

    profile = _profile(signers, 4)

    assert profile["signer_keys"] == [
        {"key_id": signer.key_id, "algorithm": signer.algorithm} for signer in signers
    ]
