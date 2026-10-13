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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from teecustody.wire import DecodeLimits, decode, encode
from teecustody_sim import (
    NEGATIVE_CASES,
    SIM_ISSUER,
    LaunchConfig,
    NegativeCase,
    SimKeys,
    build_trust_profile,
    generate_suite,
)

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
ATTACKER_CASES = {"jwks_other_path", "jwks_other_path_same_kid"}  # INC-2-API §16.3 rows 38, 39
VECTOR_LAUNCH = LaunchConfig(
    "localhost/teecustody-vectors:1",
    "sha256:" + hashlib.sha256(b"teecustody-sim vector image").hexdigest(),
    ("/app/workload",),
    (("PYTHONUNBUFFERED", "1"),),
)
DEV_JWKS_URL = "http://127.0.0.1:8791/jwks"
DEV_ATTACKER_JWKS_URL = "http://127.0.0.1:8791/attacker/jwks"
GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com"
GOOGLE_JWKS_URI = (
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/"
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
)
PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi")
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


def _issuer_jwks(suite: dict[str, Any]) -> list[dict[str, Any]]:
    """The JWKS keys a client reaches via the development profile's pinned `jwks_uri`."""
    profile = json.loads(suite["profile_json"])
    keys = _served_json(suite, profile["jwks_uri"])["keys"]
    assert isinstance(keys, list)
    return keys


def _issuer_key(suite: dict[str, Any]) -> rsa.RSAPublicKey:
    """The suite's one JWKS key (CI-8: the JWKS holds the issuer key only)."""
    (jwk,) = _issuer_jwks(suite)
    numbers = rsa.RSAPublicNumbers(
        int.from_bytes(_b64url_decode(jwk["e"]), "big"),
        int.from_bytes(_b64url_decode(jwk["n"]), "big"),
    )
    return numbers.public_key()


def _signature_verifies(suite: dict[str, Any], token: str) -> bool:
    """RS256 signature check against the suite's JWKS key, whatever the header `kid` says."""
    header_segment, payload_segment, signature_segment = token.split(".")
    if _jws_part(token, 0).get("alg") != "RS256":
        return False
    try:
        _issuer_key(suite).verify(
            _b64url_decode(signature_segment),
            f"{header_segment}.{payload_segment}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def _load_bytes(data: bytes) -> dict[str, Any]:
    suite = decode(data, SUITE_LIMITS)
    assert isinstance(suite, dict)
    return suite


def _load(path: Path) -> dict[str, Any]:
    return _load_bytes(path.read_bytes())


@pytest.fixture(scope="module")
def suite_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return generate_suite(tmp_path_factory.mktemp("vectors"), now=NOW)


@pytest.fixture(scope="module")
def suite(suite_path: Path) -> dict[str, Any]:
    return _load(suite_path)


@pytest.fixture(scope="module")
def cases_by_id(suite: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {case["id"]: case for case in suite["cases"]}


class GeneratedSuite:
    def __init__(self, data: bytes, keys: list[SimKeys]) -> None:
        self.data = data
        self.suite = _load_bytes(data)
        self.keys = keys


@pytest.fixture(scope="module")
def observed(tmp_path_factory: pytest.TempPathFactory) -> GeneratedSuite:
    """A suite plus the `SimKeys` the generator created, in creation order."""
    created: list[SimKeys] = []
    real_generate = SimKeys.generate

    def spy(signers_required: int) -> SimKeys:
        keys = real_generate(signers_required)
        created.append(keys)
        return keys

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(SimKeys, "generate", spy)
        path = generate_suite(tmp_path_factory.mktemp("observed"), now=NOW)
    return GeneratedSuite(path.read_bytes(), created)


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


def test_generated_at_defaults_to_the_current_time_in_whole_seconds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(time, "time", lambda: 1_234_567_890.9)

    suite = _load(generate_suite(tmp_path / "nested" / "out"))

    assert suite["generated_at"] == 1_234_567_890
    assert suite["verify_at_ms"] == 1_234_567_890_000


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

    assert verifying == {case["id"] for case in suite["cases"]} - UNSIGNED_CASES - ATTACKER_CASES


def _verifies_under_kid(token: str, jwks: list[dict[str, Any]]) -> bool:
    """RS256 under the JWKS entry the token header's `kid` names (S3 positive control)."""
    header_segment, payload_segment, signature_segment = token.split(".")
    named = [jwk for jwk in jwks if jwk["kid"] == _jws_part(token, 0)["kid"]]
    if not named:
        return False
    public = rsa.RSAPublicNumbers(
        int.from_bytes(_b64url_decode(named[0]["e"]), "big"),
        int.from_bytes(_b64url_decode(named[0]["n"]), "big"),
    ).public_key()
    try:
        public.verify(
            _b64url_decode(signature_segment),
            f"{header_segment}.{payload_segment}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def test_attacker_rows_verify_only_under_the_attacker_jwks_by_header_kid(
    suite: dict[str, Any], cases_by_id: dict[str, dict[str, Any]]
) -> None:
    """S3 (T-29): rows 38 and 39 verify under `/attacker/jwks` and never under `/jwks`."""
    attacker_jwks = _served_json(suite, DEV_ATTACKER_JWKS_URL)["keys"]
    issuer_jwks = _issuer_jwks(suite)
    valid = cases_by_id["valid"]["token"]
    for case_id in sorted(ATTACKER_CASES):
        token = cases_by_id[case_id]["token"]
        assert _verifies_under_kid(token, attacker_jwks), case_id
        assert not _verifies_under_kid(token, issuer_jwks), case_id
        assert token.split(".")[1] == valid.split(".")[1]
    assert _verifies_under_kid(valid, issuer_jwks)
    assert not _verifies_under_kid(valid, attacker_jwks)
    assert cases_by_id["jwks_other_path_same_kid"]["token"].split(".")[0] == valid.split(".")[0]
    row_38_header = _jws_part(cases_by_id["jwks_other_path"]["token"], 0)
    assert row_38_header["kid"] != _jws_part(valid, 0)["kid"]
    assert row_38_header == {**_jws_part(valid, 0), "kid": row_38_header["kid"]}


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


def test_generator_uses_two_fresh_two_signer_key_sets(observed: GeneratedSuite) -> None:
    assert len(observed.keys) == 2
    assert [len(keys.signers) for keys in observed.keys] == [2, 2]


def test_profile_json_is_the_development_profile_for_the_suite_keys_and_launch(
    observed: GeneratedSuite,
) -> None:
    expected = build_trust_profile(
        jwks_uri=DEV_JWKS_URL,
        expected_audience=AUDIENCE,
        launch=VECTOR_LAUNCH,
        signers=observed.keys[0].signers,
        signers_required=2,
    )

    assert json.loads(observed.suite["profile_json"]) == expected


def test_development_profile_pins_the_signers_the_valid_token_lists(
    suite: dict[str, Any],
) -> None:
    profile = json.loads(suite["profile_json"])
    payload = _jws_part(suite["cases"][0]["token"], 1)
    listed = payload["submods"]["container"]["image_signatures"]

    assert [entry["key_id"] for entry in profile["signer_keys"]] == [
        entry["key_id"] for entry in listed
    ]


def test_http_is_exactly_the_three_jwks_urls_and_never_a_discovery_url(
    observed: GeneratedSuite,
) -> None:
    """Criterion 8 (INC-2-API §16.4): a verifier that fetches discovery fails `valid`."""
    http = observed.suite["http"]

    assert set(http) == {DEV_JWKS_URL, DEV_ATTACKER_JWKS_URL, GOOGLE_JWKS_URI}
    assert not [url for url in http if url.endswith("/.well-known/openid-configuration")]
    assert json.loads(observed.suite["profile_json"])["jwks_uri"] in http


def test_http_serves_the_issuer_and_attacker_jwks_of_the_suite_keys(
    observed: GeneratedSuite,
) -> None:
    http = observed.suite["http"]
    keys = observed.keys[0]

    assert (
        http[DEV_JWKS_URL]
        == json.dumps(keys.issuer_jwks(), sort_keys=True, separators=(",", ":")).encode()
    )
    assert (
        http[DEV_ATTACKER_JWKS_URL]
        == json.dumps(keys.attacker_jwks(), sort_keys=True, separators=(",", ":")).encode()
    )


def test_generate_suite_never_reads_a_state_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """L-1 (D-047): vectors use fresh keys only; the attacker key of a state dir never leaks."""

    def refuse(*args: object, **kwargs: object) -> SimKeys:
        raise AssertionError("generate_suite read a state directory")

    monkeypatch.setattr(SimKeys, "load_or_create", refuse)
    monkeypatch.chdir(tmp_path)

    suite = _load(generate_suite(tmp_path / "out", now=NOW))

    assert len(suite["cases"]) == 1 + len(NEGATIVE_CASES)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out"]


def test_production_profile_is_the_production_shaped_fixture(observed: GeneratedSuite) -> None:
    development = json.loads(observed.suite["profile_json"])
    fixture_signers = observed.keys[1].signers

    assert json.loads(observed.suite["production_profile_json"]) == {
        "profile_version": 2,
        "profile_kind": "production",
        "token_type": "OIDC",
        "issuer": GOOGLE_ISSUER,
        "jwks_uri": GOOGLE_JWKS_URI,
        "expected_audience": AUDIENCE,
        "token_max_age_s": 3600,
        "allowed_hwmodels": ["GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_INTEL_TDX"],
        "allowed_digests": [VECTOR_LAUNCH.image_digest],
        "signer_keys": [
            {"key_id": hashlib.sha256(signer.spki_der).hexdigest(), "algorithm": signer.algorithm}
            for signer in fixture_signers
        ],
        "signers_required": 2,
        "expected_args_hash": development["expected_args_hash"],
        "expected_env_hash": development["expected_env_hash"],
    }


def test_production_profile_contains_no_development_anchor(suite: dict[str, Any]) -> None:
    text = suite["production_profile_json"]
    development_key_ids = [
        entry["key_id"] for entry in json.loads(suite["profile_json"])["signer_keys"]
    ]

    assert SIM_ISSUER not in text
    assert "tee-sim" not in text
    assert "127.0.0.1" not in text
    assert "localhost" not in text
    assert "SIMULATED" not in text
    assert all(key_id not in text for key_id in development_key_ids)


def test_http_serves_a_public_fixture_jwks_at_the_google_jwks_uri(
    suite: dict[str, Any],
) -> None:
    (jwk,) = _served_json(suite, GOOGLE_JWKS_URI)["keys"]
    assert set(jwk) == {"kty", "alg", "use", "kid", "n", "e"}
    assert (jwk["kty"], jwk["alg"], jwk["use"], jwk["kid"]) == (
        "RSA",
        "RS256",
        "sig",
        "production-fixture",
    )
    assert int.from_bytes(_b64url_decode(jwk["n"]), "big").bit_length() == 2048
    assert int.from_bytes(_b64url_decode(jwk["e"]), "big") == 65537


def test_valid_token_does_not_verify_under_the_production_fixture_jwks(
    suite: dict[str, Any],
) -> None:
    token = suite["cases"][0]["token"]
    header_segment, payload_segment, signature_segment = token.split(".")
    (jwk,) = _served_json(suite, GOOGLE_JWKS_URI)["keys"]
    fixture_key = rsa.RSAPublicNumbers(
        int.from_bytes(_b64url_decode(jwk["e"]), "big"),
        int.from_bytes(_b64url_decode(jwk["n"]), "big"),
    ).public_key()

    assert _jws_part(token, 0)["kid"] != jwk["kid"]
    with pytest.raises(InvalidSignature):
        fixture_key.verify(
            _b64url_decode(signature_segment),
            f"{header_segment}.{payload_segment}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )


def _metadata(suite: dict[str, Any]) -> list[dict[str, Any]]:
    return [{k: v for k, v in case.items() if k != "token"} for case in suite["cases"]]


def _shape(value: object) -> object:
    """The structure of a decoded value: map keys and value types, recursively."""
    if isinstance(value, dict):
        return {key: _shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_shape(item) for item in value]
    return type(value).__name__


def test_two_runs_differ_in_keys_but_share_structure_and_case_metadata(
    tmp_path: Path, suite_path: Path, suite: dict[str, Any]
) -> None:
    other_path = generate_suite(tmp_path, now=NOW)
    other = _load(other_path)

    assert other_path.read_bytes() != suite_path.read_bytes()
    assert other["identity_public_key"] != suite["identity_public_key"]
    assert other["profile_json"] != suite["profile_json"]
    assert other["production_profile_json"] != suite["production_profile_json"]
    assert other["http"][DEV_JWKS_URL] != suite["http"][DEV_JWKS_URL]
    assert other["http"][DEV_ATTACKER_JWKS_URL] != suite["http"][DEV_ATTACKER_JWKS_URL]
    assert other["http"][GOOGLE_JWKS_URI] != suite["http"][GOOGLE_JWKS_URI]
    assert all(
        mine["token"] != theirs["token"]
        for mine, theirs in zip(suite["cases"], other["cases"], strict=True)
    )
    assert _shape(other) == _shape(suite)
    assert _metadata(other) == _metadata(suite)
    assert set(other["http"]) == set(suite["http"])
    fixed = ("suite", "suite_version", "proto", "generated_at", "verify_at_ms")
    assert [other[name] for name in fixed] == [suite[name] for name in fixed]


def _json_documents(suite: dict[str, Any]) -> list[object]:
    """Every JSON document in the suite: profiles, HTTP bodies, JWS headers and payloads."""
    documents: list[object] = [
        json.loads(suite["profile_json"]),
        json.loads(suite["production_profile_json"]),
        *(json.loads(body) for body in suite["http"].values()),
    ]
    for case in suite["cases"]:
        documents.extend((_jws_part(case["token"], 0), _jws_part(case["token"], 1)))
    return documents


def _member_names(value: object) -> set[str]:
    if isinstance(value, dict):
        names = set(value)
        for item in value.values():
            names |= _member_names(item)
        return names
    if isinstance(value, list):
        return set().union(*(_member_names(item) for item in value))
    return set()


def test_suite_contains_no_private_key_text_or_private_jwk_member(
    observed: GeneratedSuite,
) -> None:
    assert b"PRIVATE KEY" not in observed.data
    for member in PRIVATE_JWK_MEMBERS:
        assert f'"{member}"'.encode() not in observed.data
    for document in _json_documents(observed.suite):
        assert _member_names(document).isdisjoint(PRIVATE_JWK_MEMBERS)


def test_suite_contains_no_private_key_material_of_the_keys_it_used(
    observed: GeneratedSuite,
) -> None:
    private_keys = [
        key
        for keys in observed.keys
        for key in (
            keys._issuer_key,
            keys._attacker_key,
            keys.unknown_signer._private_key,
            *(signer._private_key for signer in keys.signers),
        )
    ]
    assert len(private_keys) == 10
    for key in private_keys:
        d = key.private_numbers().d
        d_bytes = d.to_bytes((d.bit_length() + 7) // 8, "big")
        pkcs8 = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        assert d_bytes not in observed.data
        assert base64.urlsafe_b64encode(d_bytes).rstrip(b"=") not in observed.data
        assert pkcs8 not in observed.data


CLAIM_MISSING_ROWS = [row for row in NEGATIVE_CASES if row.error_code == "CLAIM_MISSING"]


@pytest.mark.parametrize("row", CLAIM_MISSING_ROWS, ids=[row.case_id for row in CLAIM_MISSING_ROWS])
def test_claim_missing_case_lacks_its_altered_paths_and_keeps_every_other_claim(
    row: NegativeCase, cases_by_id: dict[str, dict[str, Any]]
) -> None:
    valid = _jws_part(cases_by_id["valid"]["token"], 1)
    payload = _jws_part(cases_by_id[row.case_id]["token"], 1)

    assert row.altered
    for path in row.altered:
        assert _value_at(payload, path) is _ABSENT, path
        assert _value_at(valid, path) is not _ABSENT, path
        valid = _without(valid, path)
    assert payload == valid


def test_kid_unknown_case_names_no_jwks_key_and_is_otherwise_the_valid_token(
    suite: dict[str, Any], cases_by_id: dict[str, dict[str, Any]]
) -> None:
    """Data-driven: holds vacuously until the catalog carries `kid_unknown` (API.md §G row 37)."""
    expected = [row.case_id for row in NEGATIVE_CASES if row.case_id == "kid_unknown"]
    assert [case_id for case_id in cases_by_id if case_id == "kid_unknown"] == expected
    for case_id in expected:
        token = cases_by_id[case_id]["token"]
        jwks_kids = {jwk["kid"] for jwk in _issuer_jwks(suite)}
        assert _jws_part(token, 0)["kid"] not in jwks_kids
        assert _jws_part(token, 1) == _jws_part(cases_by_id["valid"]["token"], 1)
        assert _signature_verifies(suite, token)
