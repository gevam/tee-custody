"""T-17: attestation vector-suite generator (API.md §C vectors.py, §F, §G; spec §13.2, §13.9)."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from teecustody.wire import DecodeLimits, decode, encode
from teecustody_sim import NEGATIVE_CASES, generate_suite

NOW = 1_900_000_000
SUITE_LIMITS = DecodeLimits(max_bytes=1_048_576, max_depth=8, max_items=16_384)
SUITE_KEYS = {
    "suite",
    "suite_version",
    "proto",
    "generated_at",
    "verify_at_ms",
    "identity_public_key",
    "profile_json",
    "production_profile_json",
    "http",
    "cases",
}
CASE_KEYS = {"id", "token", "expect", "check", "error_code", "altered", "debug_event"}
AUDIENCE = "https://vectors.teecustody.test/tee"
UNSIGNED_CASES = {"alg_none", "token_signature_corrupted", "debug_bad_signature"}
_ABSENT = object()


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _jws_part(token: str, index: int) -> dict[str, Any]:
    decoded = json.loads(_b64url_decode(token.split(".")[index]))
    assert isinstance(decoded, dict)
    return decoded


def _value_at(payload: dict[str, Any], path: str) -> object:
    node: object = payload
    for name in path.split("."):
        if not isinstance(node, dict) or name not in node:
            return _ABSENT
        node = node[name]
    return node


def _without(payload: dict[str, Any], path: str) -> dict[str, Any]:
    pruned = copy.deepcopy(payload)
    *parents, leaf = path.split(".")
    node: Any = pruned
    for name in parents:
        node = node[name]
    node.pop(leaf, None)
    return pruned


def _served_json(suite: dict[str, Any], url: str) -> dict[str, Any]:
    body = suite["http"][url]
    decoded = json.loads(body)
    assert isinstance(decoded, dict)
    return decoded


def _issuer_key(suite: dict[str, Any], kid: str) -> rsa.RSAPublicKey:
    """The JWKS key a client reaches via profile discovery URL -> jwks_uri -> kid."""
    profile = json.loads(suite["profile_json"])
    discovery = _served_json(suite, profile["discovery_url"])
    (jwk,) = [
        key for key in _served_json(suite, discovery["jwks_uri"])["keys"] if key["kid"] == kid
    ]
    numbers = rsa.RSAPublicNumbers(
        int.from_bytes(_b64url_decode(jwk["e"]), "big"),
        int.from_bytes(_b64url_decode(jwk["n"]), "big"),
    )
    return numbers.public_key()


def _signature_verifies(suite: dict[str, Any], token: str) -> bool:
    header_segment, payload_segment, signature_segment = token.split(".")
    header = _jws_part(token, 0)
    if header.get("alg") != "RS256":
        return False
    try:
        _issuer_key(suite, header["kid"]).verify(
            _b64url_decode(signature_segment),
            f"{header_segment}.{payload_segment}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def _load(path: Path) -> dict[str, Any]:
    suite = decode(path.read_bytes(), SUITE_LIMITS)
    assert isinstance(suite, dict)
    return suite


@pytest.fixture(scope="module")
def suite_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return generate_suite(tmp_path_factory.mktemp("vectors"), now=NOW)


@pytest.fixture(scope="module")
def suite(suite_path: Path) -> dict[str, Any]:
    return _load(suite_path)


def test_suite_is_written_under_attestation_in_the_output_directory(suite_path: Path) -> None:
    assert suite_path.name == "suite.cbor"
    assert suite_path.parent.name == "attestation"
    assert suite_path.is_file()


def test_suite_bytes_are_canonical_cbor(suite_path: Path, suite: dict[str, Any]) -> None:
    assert encode(suite) == suite_path.read_bytes()


def test_suite_has_exactly_the_cddl_keys_and_constants(suite: dict[str, Any]) -> None:
    assert set(suite) == SUITE_KEYS
    assert suite["suite"] == "teecustody-attestation-vectors"
    assert type(suite["suite_version"]) is int
    assert suite["suite_version"] == 1
    assert suite["proto"] == "tee-chan-v1"
    assert type(suite["generated_at"]) is int
    assert suite["generated_at"] == NOW
    assert type(suite["verify_at_ms"]) is int
    assert suite["verify_at_ms"] == NOW * 1000
    assert type(suite["identity_public_key"]) is bytes
    assert len(suite["identity_public_key"]) == 32
    assert type(suite["profile_json"]) is str
    assert type(suite["production_profile_json"]) is str
    assert type(suite["http"]) is dict
    assert suite["http"]
    assert all(type(url) is str and type(body) is bytes for url, body in suite["http"].items())
    assert type(suite["cases"]) is list
    assert suite["cases"]
    for case in suite["cases"]:
        assert set(case) == CASE_KEYS
        assert type(case["token"]) is str
        assert type(case["altered"]) is list
        assert type(case["debug_event"]) is bool


def test_generated_at_defaults_to_the_current_time(tmp_path: Path) -> None:
    before = int(time.time())
    suite = _load(generate_suite(tmp_path / "nested" / "out"))
    after = int(time.time())

    assert before <= suite["generated_at"] <= after
    assert suite["verify_at_ms"] == suite["generated_at"] * 1000


def test_cases_are_valid_then_the_negative_catalog_in_order(suite: dict[str, Any]) -> None:
    expected = [
        {
            "id": "valid",
            "expect": "accept",
            "check": "none",
            "error_code": "none",
            "altered": [],
            "debug_event": False,
        },
        *(
            {
                "id": row.case_id,
                "expect": "reject",
                "check": row.check,
                "error_code": row.error_code,
                "altered": list(row.altered),
                "debug_event": row.debug_event,
            }
            for row in NEGATIVE_CASES
        ),
    ]

    assert [{k: v for k, v in case.items() if k != "token"} for case in suite["cases"]] == expected


def test_token_signatures_verify_under_the_suite_jwks_except_the_signature_cases(
    suite: dict[str, Any],
) -> None:
    verifying = {case["id"] for case in suite["cases"] if _signature_verifies(suite, case["token"])}

    assert verifying == {case["id"] for case in suite["cases"]} - UNSIGNED_CASES


def test_valid_token_is_bound_to_the_suite_identity_key_audience_and_time(
    suite: dict[str, Any],
) -> None:
    payload = _jws_part(suite["cases"][0]["token"], 1)

    assert payload["eat_nonce"] == hashlib.sha256(suite["identity_public_key"]).hexdigest()
    assert payload["aud"] == AUDIENCE
    assert payload["iat"] == NOW


def test_each_case_payload_differs_from_valid_exactly_at_its_altered_paths(
    suite: dict[str, Any],
) -> None:
    valid = _jws_part(suite["cases"][0]["token"], 1)
    for case in suite["cases"]:
        payload = _jws_part(case["token"], 1)
        expected, actual = valid, payload
        for path in case["altered"]:
            assert _value_at(payload, path) != _value_at(valid, path), (case["id"], path)
            expected, actual = _without(expected, path), _without(actual, path)
        assert actual == expected, case["id"]
