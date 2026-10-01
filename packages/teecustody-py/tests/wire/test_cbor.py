"""T-04: `teecustody.wire` canonical CBOR codec (spec/wire/README.md rules 1-5; NFR-7, SR-3)."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from teecustody.wire import DecodeLimits, WireError, WireErrorCode, decode, encode

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


@pytest.mark.parametrize("case", _cases("invalid"), ids=_ids("invalid"))
def test_invalid_vector_fails_closed_with_exactly_its_code_and_no_input_in_the_text(
    case: dict[str, str], vector_limits: DecodeLimits
) -> None:
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex(case["hex"]), vector_limits)
    assert caught.value.code is WireErrorCode(case["error"])
    assert str(caught.value) == case["error"]
    assert caught.value.args == (case["error"],)


def test_input_over_max_bytes_is_too_large_before_cbor2_is_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_be_called(*_args: object, **_kwargs: object) -> object:
        pytest.fail("cbor2.loads called for oversized input")

    monkeypatch.setattr("teecustody.wire.cbor.cbor2.loads", must_not_be_called)
    limits = DecodeLimits(max_bytes=8, max_depth=4, max_items=64)
    oversized = bytes.fromhex("48") + bytes(8)  # a valid 8-byte bstr: 9 bytes, one over the limit
    with pytest.raises(WireError) as caught:
        decode(oversized, limits)
    assert caught.value.code is WireErrorCode.TOO_LARGE
    assert str(caught.value) == "TOO_LARGE"


@pytest.mark.parametrize(
    "value", [{"b": 1, "aa": 2}, {"aa": 2, "b": 1}], ids=["contract", "reversed_insertion"]
)
def test_encode_orders_text_keys_by_encoded_bytes(value: dict[str, int]) -> None:
    assert encode(value) == bytes.fromhex("a261620162616102")


@pytest.mark.parametrize(
    "value",
    [1.5, 2**64, -(2**64) - 1, {1: 2}, (1,), bytearray(b"x"), {"a": {1.0}}],
    ids=["float", "uint_2p64", "nint_below_min", "int_key", "tuple", "bytearray", "nested_set"],
)
def test_encode_rejects_values_outside_the_data_model(value: object) -> None:
    with pytest.raises(WireError) as caught:
        encode(value)  # type: ignore[arg-type]
    assert caught.value.code is WireErrorCode.UNSUPPORTED_TYPE
    assert str(caught.value) == "UNSUPPORTED_TYPE"


def test_encode_true_as_the_simple_value_not_the_integer_one() -> None:
    assert encode(True) == bytes.fromhex("f5")


def test_ten_thousand_nested_arrays_hit_the_depth_limit_without_recursion() -> None:
    deep = bytes.fromhex("81" * 10_000 + "00")
    limits = DecodeLimits(max_bytes=len(deep), max_depth=16, max_items=len(deep))
    with pytest.raises(WireError) as caught:
        decode(deep, limits)
    assert caught.value.code is WireErrorCode.LIMIT_EXCEEDED


@pytest.mark.parametrize(
    "limits",
    [DecodeLimits(0, 1, 1), DecodeLimits(1, 0, 1), DecodeLimits(1, 1, 0), DecodeLimits(1, 1, -1)],
    ids=["max_bytes_0", "max_depth_0", "max_items_0", "max_items_negative"],
)
def test_limits_below_one_are_invalid_before_any_parsing(limits: DecodeLimits) -> None:
    with pytest.raises(ValueError, match="^INVALID_LIMITS$") as caught:
        decode(b"\x00", limits)
    assert type(caught.value) is ValueError
