"""FR-3 Simulator: issuer, discovery/JWKS, SIGNERS_REQUIRED, credential-free start (INC-1).

Expected failure on trunk: NotImplementedError('T-07' | 'T-08') from stubs.
"""

import json
import urllib.error
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
    # And D-043: the pinned JWKS and attacker JWKS URIs are on the same origin
    assert sim.jwks_uri == sim.issuer_origin + "/jwks"
    assert sim.attacker_jwks_uri == sim.issuer_origin + "/attacker/jwks"


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
        jwks_uri=sim.jwks_uri,
        expected_audience=config.audience,
        launch=config.launch,
        signers=sim.keys.signers,
        signers_required=config.signers_required,
    )
    # Then it pins the simulator issuer, hwmodel, digest, signer key_ids and launch hashes
    args_hash, env_hash = launch_config_hashes(config.launch.args, config.launch.env)
    assert profile["profile_kind"] == "development"
    assert profile["profile_version"] == 2 and profile["jwks_uri"] == sim.jwks_uri
    assert "discovery_url" not in profile and "jwks_origin" not in profile
    assert profile["issuer"] == SIM_ISSUER
    assert profile["allowed_hwmodels"] == [SIM_HWMODEL]
    assert profile["allowed_digests"] == [IMAGE_DIGEST]
    assert profile["signers_required"] == config.signers_required
    assert [s["key_id"] for s in profile["signer_keys"]] == [  # type: ignore[union-attr,index]
        s.key_id for s in sim.keys.signers
    ]
    assert profile["expected_args_hash"] == args_hash
    assert profile["expected_env_hash"] == env_hash
    private_members = {"d", "p", "q", "dp", "dq", "qi", "k"}

    def keys_of(node: object) -> set[str]:
        if isinstance(node, dict):
            return set(node) | {k for v in node.values() for k in keys_of(v)}
        if isinstance(node, list):
            return {k for v in node for k in keys_of(v)}
        return set()

    assert not private_members & keys_of(profile)
    assert "PRIVATE KEY" not in json.dumps(profile)


@pytest.mark.parametrize(
    "bad",
    [
        "http://127.0.0.1:80/jwks",
        "http://127.0.0.1:08791/jwks",
        "http://127.0.0.1:8791/other",
        "http://127.0.0.1:8791/jwks/",
        "http://192.168.1.5:8791/jwks",
        "https://127.0.0.1:8791/jwks",
        "http://127.0.0.1/jwks",
    ],
)
def test_FR03_profile_builder_refuses_a_non_canonical_jwks_uri(
    running_sim: RunningSim, bad: str
) -> None:
    # Given a running simulator
    sim, config = running_sim.sim, running_sim.config
    # When building a profile with a jwks_uri that Core's canonical rule would reject
    with pytest.raises(ValueError, match="INVALID_JWKS_URI"):
        build_trust_profile(
            jwks_uri=bad,
            expected_audience=config.audience,
            launch=config.launch,
            signers=sim.keys.signers,
            signers_required=config.signers_required,
        )


def _head(url: str, origin: str | None = None, method: str = "GET") -> tuple[int, Any]:
    headers = {} if origin is None else {"Origin": origin}
    request = urllib.request.Request(url, headers=headers, method=method)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=5) as resp:  # noqa: S310 - loopback only
            return resp.status, resp.headers
    except urllib.error.HTTPError as error:
        return error.code, error.headers


def test_FR03_jwks_echoes_a_valid_origin_like_google_and_discovery_sends_no_cors(
    running_sim: RunningSim,
) -> None:
    # Given a running simulator and a browser origin
    sim = running_sim.sim
    origin = "http://127.0.0.1:5555"
    # When the page fetches /jwks and the attacker JWKS with and without Origin
    for url in (sim.jwks_uri, sim.attacker_jwks_uri):
        status, headers = _head(url, origin)
        # Then the origin is echoed exactly, Vary: Origin is set, credentials are never allowed
        assert status == 200
        assert headers["Access-Control-Allow-Origin"] == origin
        assert "Origin" in headers["Vary"]
        assert headers["Access-Control-Allow-Credentials"] is None
        _status, plain = _head(url)
        assert plain["Access-Control-Allow-Origin"] is None and "Origin" in plain["Vary"]
    # And discovery (as on Google) carries no Access-Control header at all
    status, headers = _head(sim.discovery_url, origin)
    assert status == 200
    assert [h for h in headers if h.lower().startswith("access-control-")] == []
    # And an invalid Origin is not echoed
    for bad in ("javascript:alert(1)", "HTTP://EXAMPLE.COM", "x" * 300):
        _status, rejected = _head(sim.jwks_uri, bad)
        assert rejected["Access-Control-Allow-Origin"] is None


def test_FR03_attacker_jwks_lists_a_second_key_under_two_kids_and_no_private_members(
    running_sim: RunningSim,
) -> None:
    # Given the simulator's issuer JWKS and its attacker JWKS
    sim = running_sim.sim
    issuer_key = _get_json(sim.jwks_uri)["keys"][0]
    attacker = _get_json(sim.attacker_jwks_uri)["keys"]
    # Then the attacker JWKS lists one key twice, under its own kid and under the issuer's kid
    assert len(attacker) == 2
    assert {k["kid"] for k in attacker} == {sim.keys.issuer_kid, sim.keys.attacker_issuer_kid}
    assert len({k["n"] for k in attacker}) == 1
    # And it is a different key from the issuer's, with no private members
    assert attacker[0]["n"] != issuer_key["n"]
    assert not {"d", "p", "q", "dp", "dq", "qi"} & set(attacker[0])
