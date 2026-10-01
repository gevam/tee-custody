"""FR-3 Simulator: issuer, discovery/JWKS, SIGNERS_REQUIRED, credential-free start (INC-1).

Expected failure on trunk: NotImplementedError('T-07' | 'T-08') from stubs.
"""

import json
import urllib.request
from collections.abc import Callable
from typing import Any

import pytest

from acc_support import IMAGE_DIGEST, RunningSim, decode_jws
from teecustody_sim import (
    SIM_HWMODEL,
    SIM_ISSUER,
    SimConfigError,
    SimConfigErrorCode,
    Simulator,
    SimulatorConfig,
    build_trust_profile,
    launch_config_hashes,
)

ConfigFactory = Callable[..., SimulatorConfig]


def _get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - loopback only
        assert resp.status == 200
        value = json.loads(resp.read())
    assert isinstance(value, dict)
    return value


def test_FR03_simulator_starts_without_cloud_credentials_and_serves_discovery(
    running_sim: RunningSim,
) -> None:
    # Given a simulator started with an empty environment (no credentials)
    sim = running_sim.sim
    # When fetching the OIDC discovery document on the loopback origin
    discovery = _get_json(sim.discovery_url)
    # Then it names the simulator issuer and a JWKS URI on the same loopback origin
    assert sim.issuer_origin.startswith("http://127.0.0.1:")
    assert sim.discovery_url == sim.issuer_origin + "/.well-known/openid-configuration"
    assert discovery["issuer"] == SIM_ISSUER
    assert discovery["jwks_uri"].startswith(sim.issuer_origin + "/")
    assert running_sim.config.socket_path.exists()


def test_FR03_jwks_contains_only_the_issuer_signing_key(running_sim: RunningSim) -> None:
    # Given a running simulator
    discovery = _get_json(running_sim.sim.discovery_url)
    # When fetching the JWKS
    jwks = _get_json(discovery["jwks_uri"])
    # Then it holds exactly the RS256 issuer key and no private members or signer keys
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "RSA" and key["alg"] == "RS256" and key["use"] == "sig"
    assert key["kid"] == running_sim.sim.keys.issuer_kid
    assert not {"d", "p", "q", "dp", "dq", "qi"} & set(key)


def test_FR03_minted_token_has_simulator_shape_and_signers_required_signatures(
    make_config: ConfigFactory,
) -> None:
    # Given SIGNERS_REQUIRED = 3
    config = make_config(signers_required=3)
    with Simulator(config, environ={}) as sim:
        # When the simulator launcher issues a token (via the minter exposed on keys/launch)
        from teecustody_sim import TokenMinter

        minter = TokenMinter(sim.keys, config.launch, ttl_s=3600, token_max_age_s=3600)
        token = minter.mint(config.audience, ["00" * 32], 1_900_000_000)
        header, claims = decode_jws(token)
        # Then it is an RS256 JWS from the simulator issuer with 3 distinct signer key_ids
        assert header["alg"] == "RS256" and header["kid"] == sim.keys.issuer_kid
        assert claims["iss"] == SIM_ISSUER
        assert claims["hwmodel"] == SIM_HWMODEL
        assert claims["swname"] == "CONFIDENTIAL_SPACE"
        assert claims["dbgstat"] == "disabled-since-boot"
        assert claims["secboot"] is True
        container = claims["submods"]["container"]
        assert container["image_digest"] == IMAGE_DIGEST
        sigs = container["image_signatures"]
        assert len({s["key_id"] for s in sigs}) == 3
        assert {s["key_id"] for s in sigs} == {s.key_id for s in sim.keys.signers}
        assert len(sim.keys.signers) == 3


@pytest.mark.parametrize("value", [0, -1, 17])
def test_FR03_signers_required_out_of_range_is_rejected(
    make_config: ConfigFactory, value: int
) -> None:
    # Given an out-of-range SIGNERS_REQUIRED
    config = make_config(signers_required=value)
    # When starting
    with pytest.raises(SimConfigError) as excinfo:
        Simulator(config, environ={}).start()
    # Then it fails with the stable code and nothing else
    assert excinfo.value.code == SimConfigErrorCode.INVALID_SIGNERS_REQUIRED
    assert str(excinfo.value) == "INVALID_SIGNERS_REQUIRED"


def test_FR03_non_loopback_bind_requires_explicit_flag(make_config: ConfigFactory) -> None:
    # Given a non-loopback issuer host without allow_non_loopback
    config = make_config(issuer_host="0.0.0.0")  # noqa: S104 - the point of the test
    # When starting
    with pytest.raises(SimConfigError) as excinfo:
        Simulator(config, environ={}).start()
    # Then it is refused
    assert excinfo.value.code == SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED


def test_FR03_production_credentials_in_environment_are_refused(
    make_config: ConfigFactory,
) -> None:
    # Given an environment carrying a Google credential path (spec section 15.5)
    environ = {"GOOGLE_APPLICATION_CREDENTIALS": "/synthetic/not-a-real-key.json"}
    # When starting the simulator
    with pytest.raises(SimConfigError) as excinfo:
        Simulator(make_config(), environ=environ).start()
    # Then it refuses, without echoing the value
    assert excinfo.value.code == SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT
    assert "synthetic" not in str(excinfo.value)


def test_FR03_development_profile_matches_running_simulator(running_sim: RunningSim) -> None:
    # Given a running simulator
    sim, config = running_sim.sim, running_sim.config
    # When building the development trust profile from it
    profile = build_trust_profile(
        discovery_url=sim.discovery_url,
        jwks_origin=sim.issuer_origin,
        expected_audience=config.audience,
        launch=config.launch,
        signers=sim.keys.signers,
        signers_required=config.signers_required,
    )
    # Then it pins the simulator issuer, hwmodel, digest, signer key_ids and launch hashes
    args_hash, env_hash = launch_config_hashes(config.launch.args, config.launch.env)
    assert profile["profile_kind"] == "development"
    assert profile["issuer"] == SIM_ISSUER
    assert profile["allowed_hwmodels"] == [SIM_HWMODEL]
    assert profile["allowed_digests"] == [IMAGE_DIGEST]
    assert profile["signers_required"] == config.signers_required
    assert [s["key_id"] for s in profile["signer_keys"]] == [  # type: ignore[union-attr,index]
        s.key_id for s in sim.keys.signers
    ]
    assert profile["expected_args_hash"] == args_hash
    assert profile["expected_env_hash"] == env_hash
    assert "jwk" not in json.dumps(profile) and "PRIVATE" not in json.dumps(profile)
