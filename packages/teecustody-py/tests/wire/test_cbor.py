"""T-04: `teecustody.wire` canonical CBOR codec (spec/wire/README.md rules 1-5; NFR-7, SR-3)."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from teecustody.wire import DecodeLimits, decode, encode

VECTORS_PATH = (
    Path(__file__).resolve().parents[4] / "spec" / "vectors" / "wire" / "canonical-cbor.json"
)

# Python type of a decoded top-level item by its initial byte (major type; bool/None by full byte).
MAJOR_TYPE_TO_PYTHON = {0: int, 1: int, 2: bytes, 3: str, 4: list, 5: dict}
SIMPLE_TO_PYTHON = {0xF4: bool, 0xF5: bool, 0xF6: type(None)}


@cache
def _vectors() -> dict[str, Any]:
    loaded = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _cases(group: str) -> list[dict[str, str]]:
    cases: list[dict[str, str]] = _vectors()[group]
    return cases


def _ids(group: str) -> list[str]:
    return [case["id"] for case in _cases(group)]


@pytest.fixture(scope="module")
def vector_limits() -> DecodeLimits:
    return DecodeLimits(**_vectors()["limits"])


def _expected_type(data: bytes) -> type:
    initial = data[0]
    if initial >> 5 == 7:
        return SIMPLE_TO_PYTHON[initial]
    return MAJOR_TYPE_TO_PYTHON[initial >> 5]


@pytest.mark.parametrize("case", _cases("valid"), ids=_ids("valid"))
def test_valid_vector_round_trips_to_identical_bytes_with_the_expected_type(
    case: dict[str, str], vector_limits: DecodeLimits
) -> None:
    data = bytes.fromhex(case["hex"])
    value = decode(data, vector_limits)
    assert type(value) is _expected_type(data)
    assert encode(value) == data
