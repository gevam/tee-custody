"""NFR-7 / SR-3 Canonical wire codec, Python side (INC-1). Hex vectors are hand-derived (RFC 8949 4.2).

Expected failure on trunk: NotImplementedError('T-04').
The TypeScript twin is NFR07.wire-canonical.test.ts; both tables must stay identical.
"""

import json
from pathlib import Path

import pytest

from teecustody.wire import DecodeLimits, WireError, WireErrorCode, decode, encode

LIMITS = DecodeLimits(max_bytes=1024, max_depth=8, max_items=256)

VALID: list[tuple[str, object, str]] = [
    ("zero", 0, "00"),
    ("uint24", 24, "1818"),
    ("uint64_max", 2**64 - 1, "1bffffffffffffffff"),
    ("nint64_min", -(2**64), "3bffffffffffffffff"),
    ("minus_one", -1, "20"),
    ("null", None, "f6"),
    ("true", True, "f5"),
    ("text", "a", "6161"),
    ("bytes", b"\x01", "4101"),
    ("array", [1, 2], "820102"),
    ("map", {"a": 1}, "a1616101"),
    ("map_sorted", {"b": 2, "aa": 1}, "a261620262616101"),
]
# (id, hex, expected code or None when only "some WireError" is required)
INVALID: list[tuple[str, str, str | None]] = [
    ("non_shortest_uint", "1800", "NONCANONICAL"),
    ("non_shortest_uint16", "1900ff", "NONCANONICAL"),
    ("float16", "f90000", "UNSUPPORTED_TYPE"),
    ("float64", "fb3ff0000000000000", "UNSUPPORTED_TYPE"),
    ("truncated_head", "18", "MALFORMED"),
    ("truncated_text", "6261", "MALFORMED"),
    ("trailing_bytes", "0000", None),
    ("indefinite_array", "9f01ff", None),
    ("indefinite_text", "7f6161ff", None),
    ("map_keys_unsorted", "a2616202616101", "NONCANONICAL"),
    ("map_duplicate_keys", "a2616101616102", None),
    ("empty_input", "", None),
]


@pytest.mark.parametrize(("name", "value", "hex_"), VALID, ids=[v[0] for v in VALID])
def test_NFR07_encode_decode_known_answers(name: str, value: object, hex_: str) -> None:
    # Given a value with a hand-derived canonical encoding
    # When encoding and decoding
    # Then bytes match exactly and decoding returns the value
    assert encode(value).hex() == hex_  # type: ignore[arg-type]
    assert decode(bytes.fromhex(hex_), LIMITS) == value


@pytest.mark.parametrize(("name", "hex_", "code"), INVALID, ids=[v[0] for v in INVALID])
def test_NFR07_noncanonical_and_malformed_inputs_are_rejected(
    name: str, hex_: str, code: str | None
) -> None:
    # Given a non-canonical, unsupported or malformed encoding
    # When decoding
    with pytest.raises(WireError) as excinfo:
        decode(bytes.fromhex(hex_), LIMITS)
    # Then it is rejected with the stable code
    assert str(excinfo.value) == excinfo.value.code.value
    if code is not None:
        assert excinfo.value.code == WireErrorCode(code)


def test_NFR07_limits_are_enforced_before_work() -> None:
    # Given tight limits
    # When input exceeds bytes, depth or item count
    with pytest.raises(WireError) as too_large:
        decode(bytes(2000), LIMITS)
    deep = bytes.fromhex("81" * 20 + "00")
    with pytest.raises(WireError) as too_deep:
        decode(deep, LIMITS)
    many = bytes([0x98, 0xFF]) + bytes(255)  # array of 255 zeros: 256 items with the container
    with pytest.raises(WireError):
        decode(many, DecodeLimits(max_bytes=1024, max_depth=8, max_items=100))
    # Then size is TOO_LARGE and depth is LIMIT_EXCEEDED
    assert too_large.value.code == WireErrorCode.TOO_LARGE
    assert too_deep.value.code == WireErrorCode.LIMIT_EXCEEDED


def test_NFR07_integers_outside_64_bit_range_cannot_be_encoded() -> None:
    # Given integers just outside the CBOR major-type 0/1 range
    for value in (2**64, -(2**64) - 1):
        # When encoding
        # Then it is refused (no bignum tags)
        with pytest.raises((WireError, ValueError, OverflowError)):
            encode(value)


def test_NFR07_booleans_are_not_integers() -> None:
    # Given True and 1, which differ in CBOR
    # Then they encode differently
    assert encode(True) == bytes.fromhex("f5")
    assert encode(1) == bytes.fromhex("01")


def test_NFR07_python_agrees_with_generated_differential_corpus(tmp_path: Path) -> None:
    # Given a freshly generated corpus (the committed one is T-18)
    from teecustody_sim import generate_corpus

    path = generate_corpus(tmp_path, seed=1, count=512)
    doc = json.loads(path.read_text())
    limits = DecodeLimits(**doc["limits"])
    # When decoding each mutated case with the corpus limits
    # Then the outcome matches and every accepted case re-encodes byte-identically
    assert len(doc["cases"]) >= 500
    for case in doc["cases"]:
        data = bytes.fromhex(case["hex"])
        if case["outcome"] == "accept":
            assert encode(decode(data, limits)) == data, case["id"]
        else:
            with pytest.raises(WireError) as excinfo:
                decode(data, limits)
            assert excinfo.value.code.value == case["outcome"], case["id"]
