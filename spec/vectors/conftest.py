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

from teecustody.wire import DecodeLimits

VECTORS_DIR = Path(__file__).parent
CANONICAL_CBOR_PATH = VECTORS_DIR / "wire" / "canonical-cbor.json"


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
