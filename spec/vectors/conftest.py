"""Fixtures for the spec/vectors conformance harness (T-03).

The harness reads the committed vector files and exercises `teecustody.wire` only. It never imports
the simulator: the files, not the code that generated them, are the shared oracle (NFR-7).
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from teecustody.wire import DecodeLimits, decode

VECTORS_DIR = Path(__file__).parent
CANONICAL_CBOR_PATH = VECTORS_DIR / "wire" / "canonical-cbor.json"
ATTESTATION_SUITE_PATH = VECTORS_DIR / "attestation" / "suite.cbor"
SUITE_LIMITS = DecodeLimits(max_bytes=1_048_576, max_depth=8, max_items=16_384)


@cache
def _canonical_vectors() -> dict[str, Any]:
    loaded = json.loads(CANONICAL_CBOR_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    for group, fixture in (("valid", "valid_case"), ("invalid", "invalid_case")):
        if fixture in metafunc.fixturenames:
            cases = _canonical_vectors()[group]
            metafunc.parametrize(fixture, cases, ids=[case["id"] for case in cases])


@pytest.fixture(scope="session")
def canonical_vectors() -> dict[str, Any]:
    return _canonical_vectors()


@pytest.fixture(scope="session")
def canonical_limits(canonical_vectors: dict[str, Any]) -> DecodeLimits:
    return DecodeLimits(**canonical_vectors["limits"])


@pytest.fixture(scope="session")
def suite_bytes() -> bytes:
    return ATTESTATION_SUITE_PATH.read_bytes()


@pytest.fixture(scope="session")
def suite(suite_bytes: bytes) -> dict[str, Any]:
    decoded = decode(suite_bytes, SUITE_LIMITS)
    assert isinstance(decoded, dict)
    return decoded
