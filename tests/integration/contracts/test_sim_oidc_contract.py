"""Contract: simulator OIDC discovery/JWKS surface, launcher socket and startup rules (FR-3).

ARCHITECTURE "Simulator HTTP/OIDC surface"; spec §15.2, §15.3, §15.5; API.md §C.
Amended T-21 (D-043; INC-2-API §16.3, §16.9 S1; CI-2-4): Google CORS parity on the JWKS routes,
no CORS on discovery, and the same-origin attacker JWKS of T-29.
"""

from __future__ import annotations

import base64
import http.client
import json
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from tc_contract_support import (
    AUDIENCE,
    RunningSimulator,
    jws_header,
    jws_payload,
    post_launcher,
    simulator_config,
)

from teecustody_sim import (
    SIM_ISSUER,
    SimConfigError,
    SimConfigErrorCode,
    Simulator,
)

PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi")
NONCE = "a" * 64
PAGE_ORIGIN = "http://127.0.0.1:5555"


def _exchange(url: str, method: str, headers: dict[str, str]) -> tuple[int, list[tuple[str, str]]]:
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname or "", parts.port, timeout=5.0)
    try:
        connection.request(method, parts.path, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status, response.getheaders()
    finally:
        connection.close()


def _named(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key.lower() == name.lower()]


def _cors(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(key, value) for key, value in headers if key.lower().startswith("access-control-")]


def _get_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=5.0) as response:  # noqa: S310 - loopback test URL
        assert response.status == 200
        body = json.loads(response.read())
    assert isinstance(body, dict)
    return body


def _b64url_int(value: object) -> int:
    assert isinstance(value, str)
    return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")


def _mint(running: RunningSimulator) -> str:
    request = json.dumps({"audience": AUDIENCE, "nonces": [NONCE], "token_type": "OIDC"})
    status, body = post_launcher(running.config.socket_path, request.encode())
    assert status == 200
    return body.decode()


def test_discovery_document_names_the_simulator_issuer_and_loopback_jwks(
    running_simulator: RunningSimulator,
) -> None:
    simulator = running_simulator.simulator
    assert urlsplit(simulator.issuer_origin).hostname == "127.0.0.1"
    assert simulator.discovery_url == simulator.issuer_origin + "/.well-known/openid-configuration"

    discovery = _get_json(simulator.discovery_url)

    assert discovery["issuer"] == SIM_ISSUER
    assert discovery["jwks_uri"] == simulator.issuer_origin + "/jwks"
    algorithms = discovery["id_token_signing_alg_values_supported"]
    assert isinstance(algorithms, list)
    assert "RS256" in algorithms


def test_jwks_serves_public_keys_only(running_simulator: RunningSimulator) -> None:
    jwks = _get_json(running_simulator.simulator.issuer_origin + "/jwks")
    keys = jwks["keys"]
    assert isinstance(keys, list)
    assert keys
    for key in keys:
        assert isinstance(key, dict)
        assert key["kty"] == "RSA"
        assert isinstance(key["kid"], str)
        for member in PRIVATE_JWK_MEMBERS:
            assert member not in key


def test_launcher_token_verifies_under_the_served_jwks(running_simulator: RunningSimulator) -> None:
    token = _mint(running_simulator)
    header = jws_header(token)
    jwks = _get_json(running_simulator.simulator.issuer_origin + "/jwks")
    keys = jwks["keys"]
    assert isinstance(keys, list)
    matching = [key for key in keys if isinstance(key, dict) and key.get("kid") == header["kid"]]
    assert len(matching) == 1
    assert header["alg"] == "RS256"

    public_key = rsa.RSAPublicNumbers(
        _b64url_int(matching[0]["e"]), _b64url_int(matching[0]["n"])
    ).public_key()
    signing_input, _, signature = token.rpartition(".")
    public_key.verify(
        base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
        signing_input.encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_token_carries_production_shaped_claims_and_simulator_anchors(
    running_simulator: RunningSimulator,
) -> None:
    claims = jws_payload(_mint(running_simulator))

    assert claims["iss"] == SIM_ISSUER
    assert claims["aud"] == AUDIENCE
    assert claims["eat_nonce"] == NONCE
    assert claims["hwmodel"] == "SIMULATED"
    assert claims["swname"] == "CONFIDENTIAL_SPACE"
    assert claims["secboot"] is True
    assert claims["dbgstat"] == "disabled-since-boot"
    submods = claims["submods"]
    assert isinstance(submods, dict)
    assert "STABLE" in submods["confidential_space"]["support_attributes"]
    container = submods["container"]
    assert container["image_digest"] == running_simulator.config.launch.image_digest
    assert container["args"] == list(running_simulator.config.launch.args)
    assert container["env"] == dict(running_simulator.config.launch.env)
    signatures = container["image_signatures"]
    assert len(signatures) == running_simulator.config.signers_required
    signer_ids = {signer.key_id for signer in running_simulator.simulator.keys.signers}
    assert {entry["key_id"] for entry in signatures} == signer_ids


@pytest.mark.parametrize(
    "body",
    [
        b'{"audience": "https://a.test", "nonces": ["short"], "token_type": "OIDC"}',
        b'{"audience": "https://a.test", "nonces": [], "token_type": "PKI"}',
        b'{"audience": "https://a.test", "nonces": [], "token_type": "OIDC", "extra": 1}',
        b"not json",
    ],
)
def test_launcher_rejects_invalid_requests(
    running_simulator: RunningSimulator, body: bytes
) -> None:
    status, _ = post_launcher(running_simulator.config.socket_path, body)
    assert status == 400


@pytest.mark.parametrize(
    ("overrides", "environ", "code"),
    [
        ({"issuer_host": "0.0.0.0"}, {}, SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED),  # noqa: S104
        ({"signers_required": 0}, {}, SimConfigErrorCode.INVALID_SIGNERS_REQUIRED),
        (
            {},
            {"GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent.json"},
            SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT,
        ),
    ],
)
def test_startup_rules_are_enforced_before_binding(
    short_dir: Path, overrides: dict[str, object], environ: dict[str, str], code: SimConfigErrorCode
) -> None:
    config = simulator_config(short_dir, **overrides)
    with pytest.raises(SimConfigError) as caught:
        Simulator(config, environ=environ).start()
    assert caught.value.code is code
    assert not config.socket_path.exists()


def test_simulator_names_its_pinned_and_attacker_jwks_uris(
    running_simulator: RunningSimulator,
) -> None:
    simulator = running_simulator.simulator
    assert simulator.jwks_uri == simulator.issuer_origin + "/jwks"
    assert simulator.attacker_jwks_uri == simulator.issuer_origin + "/attacker/jwks"


def test_jwks_routes_echo_a_valid_origin_like_google(running_simulator: RunningSimulator) -> None:
    """S1 (CI-2-4): exact echo, `Vary: Origin`, never `Access-Control-Allow-Credentials`."""
    simulator = running_simulator.simulator
    for url in (simulator.jwks_uri, simulator.attacker_jwks_uri):
        status, headers = _exchange(url, "GET", {"Origin": PAGE_ORIGIN})
        assert status == 200
        assert _cors(headers) == [("Access-Control-Allow-Origin", PAGE_ORIGIN)]
        assert _named(headers, "Vary") == ["Origin"]

        for request_headers in ({}, {"Origin": "javascript:x"}, {"Origin": "HTTP://A.TEST"}):
            status, headers = _exchange(url, "GET", request_headers)
            assert status == 200
            assert _cors(headers) == []
            assert _named(headers, "Vary") == ["Origin"]

        status, headers = _exchange(
            url, "OPTIONS", {"Origin": PAGE_ORIGIN, "Access-Control-Request-Method": "GET"}
        )
        assert status == 200
        assert sorted(_cors(headers)) == [
            ("Access-Control-Allow-Methods", "GET"),
            ("Access-Control-Allow-Origin", PAGE_ORIGIN),
        ]
        assert _named(headers, "Vary") == ["Origin"]
        assert _named(headers, "Content-Type") == []


def test_discovery_and_error_responses_carry_no_cors_header(
    running_simulator: RunningSimulator,
) -> None:
    """S1: discovery is CORS-free (Google parity, CI-2-1); so are 404 and 405."""
    simulator = running_simulator.simulator
    origin = simulator.issuer_origin
    for url, method, expected in (
        (simulator.discovery_url, "GET", 200),
        (simulator.discovery_url, "OPTIONS", 405),
        (origin + "/nope", "GET", 404),
        (simulator.jwks_uri, "POST", 405),
    ):
        status, headers = _exchange(url, method, {"Origin": PAGE_ORIGIN})
        assert status == expected
        assert _cors(headers) == []
        assert _named(headers, "Vary") == []


def test_attacker_jwks_never_verifies_a_launcher_token(running_simulator: RunningSimulator) -> None:
    """S6 (L-1): the attacker key is not the issuer key and is never served at `/jwks`."""
    simulator = running_simulator.simulator
    token = _mint(running_simulator)
    issuer_keys = _get_json(simulator.jwks_uri)["keys"]
    attacker_keys = _get_json(simulator.attacker_jwks_uri)["keys"]
    assert isinstance(issuer_keys, list)
    assert isinstance(attacker_keys, list)
    issuer_moduli = {key["n"] for key in issuer_keys if isinstance(key, dict)}
    attacker_moduli = {key["n"] for key in attacker_keys if isinstance(key, dict)}

    assert len(attacker_moduli) == 1
    assert not attacker_moduli & issuer_moduli
    signing_input, _, signature = token.rpartition(".")
    for key in attacker_keys:
        assert isinstance(key, dict)
        public_key = rsa.RSAPublicNumbers(_b64url_int(key["e"]), _b64url_int(key["n"])).public_key()
        with pytest.raises(InvalidSignature):
            public_key.verify(
                base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
                signing_input.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
