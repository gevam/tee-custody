"""Contract: normative canonical-CBOR binding, Python side (API.md §B wire; spec/wire/README.md)."""

from __future__ import annotations

import pytest

from teecustody.wire import PROTO, DecodeLimits, WireError, WireErrorCode, decode, encode

LIMITS = DecodeLimits(max_bytes=1024, max_depth=8, max_items=256)


def test_proto_is_the_normative_protocol_identifier() -> None:
    assert PROTO == "tee-chan-v1"


def test_encode_orders_map_keys_canonically() -> None:
    assert encode({"b": 1, "aa": 2}) == bytes.fromhex("a261620162616102")


def test_round_trip_preserves_every_permitted_type() -> None:
    value = {
        "bytes": b"\x00\x01",
        "false": False,
        "list": [1, -1, 2**64 - 1, -(2**64)],
        "map": {"nested": "text"},
        "null": None,
        "true": True,
    }
    encoded = encode(value)
    assert decode(encoded, LIMITS) == value
    assert encode(decode(encoded, LIMITS)) == encoded


@pytest.mark.parametrize(
    ("hex_input", "code"),
    [
        ("1817", WireErrorCode.NONCANONICAL),
        ("9f0102ff", WireErrorCode.NONCANONICAL),
        ("a2616201616102", WireErrorCode.NONCANONICAL),
        ("f93c00", WireErrorCode.UNSUPPORTED_TYPE),
        ("a10102", WireErrorCode.UNSUPPORTED_TYPE),
        ("830102", WireErrorCode.MALFORMED),
        ("0000", WireErrorCode.MALFORMED),
    ],
)
def test_decode_fails_closed_with_stable_codes(hex_input: str, code: WireErrorCode) -> None:
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex(hex_input), LIMITS)
    assert caught.value.code is code
    assert str(caught.value) == code.value


def test_input_length_is_checked_before_parsing() -> None:
    with pytest.raises(WireError) as caught:
        decode(b"\x00" * 6, DecodeLimits(max_bytes=5, max_depth=8, max_items=256))
    assert caught.value.code is WireErrorCode.TOO_LARGE


def test_depth_limit_is_enforced() -> None:
    with pytest.raises(WireError) as caught:
        decode(bytes.fromhex("8181818100"), DecodeLimits(max_bytes=64, max_depth=4, max_items=64))
    assert caught.value.code is WireErrorCode.LIMIT_EXCEEDED


def test_encode_rejects_values_outside_the_data_model() -> None:
    for value in (1.5, 2**64, {1: 2}):
        with pytest.raises(WireError) as caught:
            encode(value)  # type: ignore[arg-type]
        assert caught.value.code is WireErrorCode.UNSUPPORTED_TYPE
