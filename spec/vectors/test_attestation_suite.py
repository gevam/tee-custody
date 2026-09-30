"""INC-1 attestation vector suite conformance (spec/wire/attestation-vectors.cddl; NFR-7, FR-3).

The expected catalog below is transcribed from docs/tasks/INC-1/API.md §G and is deliberately not
imported from `teecustody_sim`: the suite is checked against the specification, not its generator.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any, NamedTuple

import pytest

from teecustody.wire import encode

SUITE_KEYS = frozenset(
    {
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
)
CASE_KEYS = frozenset({"id", "token", "expect", "check", "error_code", "altered", "debug_event"})
CHECK_IDS = frozenset(
    {
        "signature",
        "issuer",
        "audience",
        "time",
        "nonce",
        "platform",
        "support_attributes",
        "image",
        "launch_config",
    }
)
ERROR_CODES = frozenset(
    {
        "MALFORMED",
        "UNTRUSTED_SIGNER",
        "CLAIM_MISSING",
        "CLAIM_MISMATCH",
        "NOT_YET_VALID",
        "EXPIRED",
        "UNSUPPORTED_ALGORITHM",
    }
)
PROFILE_KEYS = frozenset(
    {
        "profile_version",
        "profile_kind",
        "token_type",
        "issuer",
        "discovery_url",
        "jwks_origin",
        "expected_audience",
        "token_max_age_s",
        "allowed_hwmodels",
        "allowed_digests",
        "signer_keys",
        "signers_required",
        "expected_args_hash",
        "expected_env_hash",
    }
)
PRODUCTION_ISSUER = "https://confidentialcomputing.googleapis.com"
IMAGE_SIGNATURES = "submods.container.image_signatures"


class CatalogRow(NamedTuple):
    id: str
    check: str
    error_code: str
    altered: tuple[str, ...]
    debug_event: bool

    @property
    def expect(self) -> str:
        return "accept" if self.check == "none" else "reject"


CATALOG: tuple[CatalogRow, ...] = (
    CatalogRow("valid", "none", "none", (), False),
    CatalogRow("alg_none", "signature", "UNSUPPORTED_ALGORITHM", (), False),
    CatalogRow("token_signature_corrupted", "signature", "UNTRUSTED_SIGNER", (), False),
    CatalogRow("issuer_wrong", "issuer", "CLAIM_MISMATCH", ("iss",), False),
    CatalogRow("issuer_missing", "issuer", "CLAIM_MISSING", ("iss",), False),
    CatalogRow("audience_wrong", "audience", "CLAIM_MISMATCH", ("aud",), False),
    CatalogRow("audience_missing", "audience", "CLAIM_MISSING", ("aud",), False),
    CatalogRow("expired", "time", "EXPIRED", ("exp", "iat"), False),
    CatalogRow("exp_missing", "time", "CLAIM_MISSING", ("exp",), False),
    CatalogRow("iat_stale", "time", "EXPIRED", ("iat",), False),
    CatalogRow("iat_future", "time", "NOT_YET_VALID", ("iat",), False),
    CatalogRow("nbf_future", "time", "NOT_YET_VALID", ("nbf",), False),
    CatalogRow("nonce_wrong", "nonce", "CLAIM_MISMATCH", ("eat_nonce",), False),
    CatalogRow("nonce_missing", "nonce", "CLAIM_MISSING", ("eat_nonce",), False),
    CatalogRow("hwmodel_unlisted", "platform", "CLAIM_MISMATCH", ("hwmodel",), False),
    CatalogRow("swname_wrong", "platform", "CLAIM_MISMATCH", ("swname",), False),
    CatalogRow("secboot_false", "platform", "CLAIM_MISMATCH", ("secboot",), False),
    CatalogRow("dbgstat_enabled", "platform", "CLAIM_MISMATCH", ("dbgstat",), True),
    CatalogRow("dbgstat_missing", "platform", "CLAIM_MISSING", ("dbgstat",), False),
    CatalogRow(
        "stable_missing",
        "support_attributes",
        "CLAIM_MISMATCH",
        ("submods.confidential_space.support_attributes",),
        False,
    ),
    CatalogRow(
        "digest_unknown", "image", "CLAIM_MISMATCH", ("submods.container.image_digest",), False
    ),
    CatalogRow("signatures_insufficient", "image", "UNTRUSTED_SIGNER", (IMAGE_SIGNATURES,), False),
    CatalogRow("signer_unknown", "image", "UNTRUSTED_SIGNER", (IMAGE_SIGNATURES,), False),
    CatalogRow(
        "signature_algorithm_mismatch", "image", "UNTRUSTED_SIGNER", (IMAGE_SIGNATURES,), False
    ),
    CatalogRow(
        "args_altered", "launch_config", "CLAIM_MISMATCH", ("submods.container.args",), False
    ),
    CatalogRow("env_altered", "launch_config", "CLAIM_MISMATCH", ("submods.container.env",), False),
    CatalogRow("debug_bad_signature", "signature", "UNTRUSTED_SIGNER", ("dbgstat",), False),
    CatalogRow("key_id_duplicated", "image", "UNTRUSTED_SIGNER", (IMAGE_SIGNATURES,), False),
)
CATALOG_IDS = [row.id for row in CATALOG]


@pytest.fixture(scope="module")
def cases_by_id(suite: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {case["id"]: case for case in suite["cases"]}


def _jws_payload(token: str) -> dict[str, Any]:
    segments = token.split(".")
    assert len(segments) == 3
    payload = segments[1]
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert isinstance(decoded, dict)
    return decoded


_ABSENT = object()


def _value_at(payload: dict[str, Any], path: str) -> object:
    node: object = payload
    for key in path.split("."):
        if not isinstance(node, dict) or key not in node:
            return _ABSENT
        node = node[key]
    return node


def _without(payload: dict[str, Any], path: str) -> dict[str, Any]:
    pruned = copy.deepcopy(payload)
    *parents, leaf = path.split(".")
    node: object = pruned
    for key in parents:
        node = node.get(key) if isinstance(node, dict) else None
    if isinstance(node, dict):
        node.pop(leaf, None)
    return pruned


def _same_json(left: object, right: object) -> bool:
    """Type-exact JSON equality: `true` differs from `1`, arrays compare whole."""
    if left is _ABSENT or right is _ABSENT:
        return left is right
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def _differs_exactly_at(case: dict[str, Any], valid: dict[str, Any], paths: list[str]) -> bool:
    """True iff the value (or presence) at every dotted path differs and the payloads are equal
    once those paths are removed from both. A path may name an object (for example
    `submods.container.env`); any change inside it is then covered by that path."""
    if any(_same_json(_value_at(case, path), _value_at(valid, path)) for path in paths):
        return False
    for path in paths:
        case, valid = _without(case, path), _without(valid, path)
    return _same_json(case, valid)


def _is_uint(value: object) -> bool:
    return type(value) is int and value >= 0


# Criterion 3: the suite is canonical CBOR with exactly the CDDL shape.


def test_suite_re_encodes_to_identical_bytes(suite_bytes: bytes, suite: dict[str, Any]) -> None:
    assert encode(suite) == suite_bytes


def test_suite_has_exactly_the_cddl_keys_and_fixed_values(suite: dict[str, Any]) -> None:
    assert set(suite) == SUITE_KEYS
    assert suite["suite"] == "teecustody-attestation-vectors"
    assert suite["suite_version"] == 1
    assert suite["proto"] == "tee-chan-v1"


def test_suite_fields_have_the_cddl_types(suite: dict[str, Any]) -> None:
    assert _is_uint(suite["generated_at"])
    assert _is_uint(suite["verify_at_ms"])
    assert type(suite["identity_public_key"]) is bytes
    assert len(suite["identity_public_key"]) == 32
    assert type(suite["profile_json"]) is str
    assert type(suite["production_profile_json"]) is str
    assert type(suite["http"]) is dict
    assert suite["http"]
    assert all(type(url) is str and type(body) is bytes for url, body in suite["http"].items())
    assert type(suite["cases"]) is list
    assert suite["cases"]


def test_verify_at_ms_is_generated_at_in_milliseconds(suite: dict[str, Any]) -> None:
    assert suite["verify_at_ms"] == suite["generated_at"] * 1000


def test_every_case_follows_the_vector_case_rule(suite: dict[str, Any]) -> None:
    for case in suite["cases"]:
        assert set(case) == CASE_KEYS, case.get("id")
        assert type(case["id"]) is str
        assert type(case["token"]) is str
        assert case["expect"] in {"accept", "reject"}
        assert case["check"] in CHECK_IDS | {"none"}
        assert case["error_code"] in ERROR_CODES | {"none"}
        accepted = case["expect"] == "accept"
        assert (case["check"] == "none") is accepted, case["id"]
        assert (case["error_code"] == "none") is accepted, case["id"]
        assert type(case["altered"]) is list
        assert all(type(path) is str for path in case["altered"])
        assert type(case["debug_event"]) is bool


# Criterion 4: the cases are the API.md §G catalog, in order.


def test_case_ids_follow_the_catalog_in_order(suite: dict[str, Any]) -> None:
    assert [case["id"] for case in suite["cases"]] == CATALOG_IDS


@pytest.mark.parametrize("row", CATALOG, ids=CATALOG_IDS)
def test_case_matches_its_catalog_row(
    row: CatalogRow, cases_by_id: dict[str, dict[str, Any]]
) -> None:
    case = cases_by_id[row.id]
    assert case["expect"] == row.expect
    assert case["check"] == row.check
    assert case["error_code"] == row.error_code
    assert case["altered"] == list(row.altered)
    assert case["debug_event"] is row.debug_event


# Criterion 5: each token differs from `valid` exactly at its `altered` paths.


@pytest.mark.parametrize("row", CATALOG, ids=CATALOG_IDS)
def test_payload_differs_from_valid_exactly_at_altered_paths(
    row: CatalogRow, cases_by_id: dict[str, dict[str, Any]]
) -> None:
    valid_payload = _jws_payload(cases_by_id["valid"]["token"])
    case = cases_by_id[row.id]
    assert _differs_exactly_at(_jws_payload(case["token"]), valid_payload, case["altered"])


@pytest.mark.parametrize("case_id", ["alg_none", "token_signature_corrupted"])
def test_signature_cases_keep_the_valid_payload(
    case_id: str, cases_by_id: dict[str, dict[str, Any]]
) -> None:
    valid_payload = _jws_payload(cases_by_id["valid"]["token"])
    assert _jws_payload(cases_by_id[case_id]["token"]) == valid_payload


# Criterion 6: the valid token is bound to the suite identity key.


def test_valid_nonce_is_hex_sha256_of_identity_public_key(
    suite: dict[str, Any], cases_by_id: dict[str, dict[str, Any]]
) -> None:
    expected = hashlib.sha256(suite["identity_public_key"]).hexdigest()
    assert _jws_payload(cases_by_id["valid"]["token"])["eat_nonce"] == expected


# Criterion 7: both embedded trust profiles have exactly the API.md §E shape.


@pytest.mark.parametrize(
    ("field", "kind"),
    [("profile_json", "development"), ("production_profile_json", "production")],
)
def test_profile_has_exactly_the_documented_keys(
    suite: dict[str, Any], field: str, kind: str
) -> None:
    profile = json.loads(suite[field])
    assert type(profile) is dict
    assert set(profile) == PROFILE_KEYS
    assert profile["profile_kind"] == kind
    assert type(profile["signer_keys"]) is list
    assert profile["signer_keys"]
    for signer in profile["signer_keys"]:
        assert type(signer) is dict
        assert set(signer) == {"key_id", "algorithm"}


def test_production_profile_names_the_confidential_space_issuer(suite: dict[str, Any]) -> None:
    assert json.loads(suite["production_profile_json"])["issuer"] == PRODUCTION_ISSUER
