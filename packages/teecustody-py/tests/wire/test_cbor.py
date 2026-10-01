"""T-04: `teecustody.wire` canonical CBOR codec (spec/wire/README.md rules 1-5; NFR-7, SR-3)."""

from __future__ import annotations

import json
import threading
import tracemalloc
from enum import IntEnum, StrEnum
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
    # SR-11: no chained exception (e.g. UnicodeDecodeError.object) carries the input along.
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


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
    with pytest.raises(ValueError, match=r"^INVALID_LIMITS$") as caught:
        decode(b"\x00", limits)
    assert type(caught.value) is ValueError


DEPTH_CEILING = 64  # shared Python/TypeScript nesting ceiling (T-04 amendment 2026-10-01b)


def test_max_depth_above_the_ceiling_is_invalid_before_cbor2_is_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_be_called(*_args: object, **_kwargs: object) -> object:
        pytest.fail("cbor2.loads called with limits above the depth ceiling")

    monkeypatch.setattr("teecustody.wire.cbor.cbor2.loads", must_not_be_called)
    with pytest.raises(ValueError, match=r"^INVALID_LIMITS$"):
        decode(b"\x00", DecodeLimits(1024, DEPTH_CEILING + 1, 1024))


def test_max_depth_at_the_ceiling_is_accepted() -> None:
    assert decode(b"\x00", DecodeLimits(1024, DEPTH_CEILING, 1024)) == 0


ALLOCATION_BOUND_BYTES = 64 * 1024


@pytest.mark.parametrize(
    ("hex_input", "code"),
    [
        ("9b0000000100000000", WireErrorCode.LIMIT_EXCEEDED),
        ("bb8000000000000000", WireErrorCode.LIMIT_EXCEEDED),
        ("5bffffffffffffffff", WireErrorCode.MALFORMED),
    ],
    ids=["array_2p32_items", "map_2p63_entries", "bstr_2p64m1_bytes"],
)
def test_declared_sizes_fail_before_anything_is_allocated_for_them(
    hex_input: str, code: WireErrorCode, vector_limits: DecodeLimits
) -> None:
    data = bytes.fromhex(hex_input)
    caught: WireError | None = None
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        try:
            decode(data, vector_limits)
        except WireError as error:
            caught = error
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert caught is not None
    assert caught.code is code
    assert peak < ALLOCATION_BOUND_BYTES


def test_byte_string_longer_than_the_input_is_malformed(vector_limits: DecodeLimits) -> None:
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex("590100"), vector_limits)
    assert caught.value.code is WireErrorCode.MALFORMED


@pytest.mark.parametrize(
    ("hex_input", "expected"),
    [
        ("1b001fffffffffffff", 2**53 - 1),
        ("1b0020000000000000", 2**53),
        ("1bffffffffffffffff", 2**64 - 1),
        ("3bffffffffffffffff", -(2**64)),
    ],
    ids=["2p53m1", "2p53", "2p64m1", "minus_2p64"],
)
def test_integer_boundaries_decode_exactly(
    hex_input: str, expected: int, vector_limits: DecodeLimits
) -> None:
    value = decode(bytes.fromhex(hex_input), vector_limits)
    assert type(value) is int
    assert value == expected


def test_bignum_tag_is_unsupported(vector_limits: DecodeLimits) -> None:
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex("c249010000000000000000"), vector_limits)
    assert caught.value.code is WireErrorCode.UNSUPPORTED_TYPE


def test_any_foreign_exception_after_the_length_check_becomes_malformed(
    monkeypatch: pytest.MonkeyPatch, vector_limits: DecodeLimits
) -> None:
    def explode(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("SENTINEL-INPUT-6161")

    monkeypatch.setattr("teecustody.wire.cbor.cbor2.loads", explode)
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex("6161"), vector_limits)
    assert caught.value.code is WireErrorCode.MALFORMED
    assert "SENTINEL" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_materialised_value_that_does_not_re_encode_to_the_input_is_noncanonical(
    monkeypatch: pytest.MonkeyPatch, vector_limits: DecodeLimits
) -> None:
    monkeypatch.setattr("teecustody.wire.cbor.cbor2.loads", lambda _data: "b")
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex("6161"), vector_limits)
    assert caught.value.code is WireErrorCode.NONCANONICAL


def _value_of_depth(depth: int) -> list[Any] | int:
    """`0` inside `depth - 1` nested lists: rule-5 depth `depth`, built without recursion."""
    value: list[Any] | int = 0
    for _ in range(depth - 1):
        value = [value]
    return value


@pytest.fixture
def forbid_cbor2_dumps(monkeypatch: pytest.MonkeyPatch) -> None:
    def must_not_be_called(*_args: object, **_kwargs: object) -> object:
        pytest.fail("cbor2.dumps called with a value deeper than the ceiling")

    monkeypatch.setattr("teecustody.wire.cbor.cbor2.dumps", must_not_be_called)


def test_depth_at_the_ceiling_round_trips_on_a_128_kib_thread_stack() -> None:
    value = _value_of_depth(DEPTH_CEILING)
    expected = bytes.fromhex("81" * (DEPTH_CEILING - 1) + "00")
    results: list[object] = []

    def run() -> None:
        encoded = encode(value)
        results.extend([encoded, decode(encoded, DecodeLimits(1024, DEPTH_CEILING, 1024))])

    previous = threading.stack_size(128 * 1024)
    try:
        worker = threading.Thread(target=run)
        worker.start()
    finally:
        threading.stack_size(previous)
    worker.join(timeout=30)
    assert results == [expected, value]


@pytest.mark.usefixtures("forbid_cbor2_dumps")
@pytest.mark.parametrize("depth", [DEPTH_CEILING + 1, 100_000], ids=["ceiling_plus_1", "100k"])
def test_encode_refuses_depth_beyond_the_ceiling_before_cbor2(depth: int) -> None:
    with pytest.raises(WireError) as caught:
        encode(_value_of_depth(depth))
    assert caught.value.code is WireErrorCode.LIMIT_EXCEEDED


def test_decode_refuses_depth_beyond_the_ceiling() -> None:
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex("81" * DEPTH_CEILING + "00"), DecodeLimits(1024, DEPTH_CEILING, 1024))
    assert caught.value.code is WireErrorCode.LIMIT_EXCEEDED


def _self_referential_list() -> list[Any]:
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    return cyclic


def _self_referential_dict() -> dict[str, Any]:
    cyclic: dict[str, Any] = {}
    cyclic["a"] = cyclic
    return cyclic


@pytest.mark.parametrize(
    "make", [_self_referential_list, _self_referential_dict], ids=["list", "dict"]
)
def test_encode_of_a_cyclic_value_terminates_with_limit_exceeded(make: Any) -> None:
    outcome: list[BaseException] = []

    def run() -> None:
        try:
            encode(make())
        except BaseException as error:  # noqa: BLE001 - recorded and asserted below
            outcome.append(error)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "encode did not terminate"
    assert len(outcome) == 1
    assert isinstance(outcome[0], WireError)
    assert outcome[0].code is WireErrorCode.LIMIT_EXCEEDED


@pytest.mark.parametrize(
    ("hex_input", "code"),
    [
        # array declares 2 children with 1 byte left; the tag after it is never reached
        ("82c0", WireErrorCode.MALFORMED),
        # bstr runs past the end before the unsorted map ends
        ("a2616200616141", WireErrorCode.MALFORMED),
        # inner map ends unsorted before `undefined` is read
        ("82a2616200616100f7", WireErrorCode.NONCANONICAL),
        # invalid UTF-8 text precedes the tag
        ("8261ffc000", WireErrorCode.MALFORMED),
    ],
    ids=["children_beyond_input", "bstr_beyond_input", "map_order_at_map_end", "utf8_before_tag"],
)
def test_first_violation_in_byte_order_wins(
    hex_input: str, code: WireErrorCode, vector_limits: DecodeLimits
) -> None:
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex(hex_input), vector_limits)
    assert caught.value.code is code


class _Code(StrEnum):
    A = "a"


class _Number(IntEnum):
    ONE = 1


class _List(list[int]):
    pass


class _Dict(dict[str, int]):
    pass


class _Bytes(bytes):
    pass


@pytest.mark.parametrize(
    "value",
    [_Code.A, _Number.ONE, _List([1]), _Dict(a=1), _Bytes(b"x"), {"k": _Code.A}, {_Code.A: 1}],
    ids=[
        "str_enum",
        "int_enum",
        "list_subclass",
        "dict_subclass",
        "bytes_subclass",
        "nested",
        "key",
    ],
)
def test_encode_accepts_exact_types_only_never_subclasses(value: object) -> None:
    with pytest.raises(WireError) as caught:
        encode(value)  # type: ignore[arg-type]
    assert caught.value.code is WireErrorCode.UNSUPPORTED_TYPE
