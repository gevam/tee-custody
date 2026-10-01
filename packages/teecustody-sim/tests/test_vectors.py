"""T-17: attestation vector-suite generator (API.md §C vectors.py, §F, §G; spec §13.2, §13.9)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from teecustody.wire import DecodeLimits, decode, encode
from teecustody_sim import generate_suite

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
