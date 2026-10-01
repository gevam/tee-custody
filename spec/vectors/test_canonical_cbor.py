"""Canonical-CBOR codec conformance (spec/wire/README.md rules 1-5; SR-3, ADR 0010)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from teecustody.wire import DecodeLimits, WireError, WireErrorCode, decode, encode


def test_valid_case_round_trips_byte_for_byte(
    valid_case: dict[str, str], canonical_limits: DecodeLimits
) -> None:
    data = bytes.fromhex(valid_case["hex"])
    assert encode(decode(data, canonical_limits)) == data


def test_invalid_case_fails_closed_with_its_error(
    invalid_case: dict[str, str], canonical_limits: DecodeLimits
) -> None:
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex(invalid_case["hex"]), canonical_limits)
    assert caught.value.code is WireErrorCode(invalid_case["error"])
    assert str(caught.value) == invalid_case["error"]


WIRE_ERROR_CODES = frozenset(
    {"TOO_LARGE", "MALFORMED", "NONCANONICAL", "UNSUPPORTED_TYPE", "LIMIT_EXCEEDED"}
)


def test_vector_file_has_the_documented_header(
    canonical_vectors: dict[str, Any], require_int: Callable[[object], int]
) -> None:
    assert set(canonical_vectors) == {"format", "version", "limits", "valid", "invalid"}
    assert canonical_vectors["format"] == "teecustody-canonical-cbor-vectors"
    assert require_int(canonical_vectors["version"]) == 1
    limits = canonical_vectors["limits"]
    assert {name: require_int(value) for name, value in limits.items()} == {
        "max_bytes": 1024,
        "max_depth": 4,
        "max_items": 64,
    }


def test_case_ids_are_unique(canonical_vectors: dict[str, list[dict[str, str]]]) -> None:
    ids = [case["id"] for group in ("valid", "invalid") for case in canonical_vectors[group]]
    assert len(ids) == len(set(ids))


def test_every_invalid_case_names_one_of_the_five_error_codes(
    canonical_vectors: dict[str, list[dict[str, str]]],
) -> None:
    assert {case["error"] for case in canonical_vectors["invalid"]} <= WIRE_ERROR_CODES
    assert all(set(case) == {"id", "hex", "error"} for case in canonical_vectors["invalid"])
    assert all(set(case) == {"id", "hex"} for case in canonical_vectors["valid"])


@pytest.mark.parametrize("value", [True, False, 1.0, 1024.0], ids=repr)
def test_require_int_rejects_bool_and_float(
    require_int: Callable[[object], int], value: object
) -> None:
    with pytest.raises(pytest.fail.Exception):
        require_int(value)


def test_require_int_returns_a_real_int(require_int: Callable[[object], int]) -> None:
    assert require_int(1) == 1
