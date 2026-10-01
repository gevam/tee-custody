"""T-17: development trust profile (API.md §C profile.py, §A, §E; D-016; SR-1 (i))."""

from __future__ import annotations

import hashlib

import pytest

from teecustody_sim import (
    DEV_SIGNER_ALGORITHM,
    SIM_HWMODEL,
    SIM_ISSUER,
    LaunchConfig,
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


@pytest.fixture(scope="module")
def keys() -> SimKeys:
    return SimKeys.generate(2)


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


def test_signers_required_above_signer_count_is_rejected(keys: SimKeys) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_SIGNERS_REQUIRED$"):
        build_trust_profile(
            discovery_url=DISCOVERY_URL,
            jwks_origin=JWKS_ORIGIN,
            expected_audience=AUDIENCE,
            launch=LAUNCH,
            signers=keys.signers,
            signers_required=3,
        )
