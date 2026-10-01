"""T-04 property tests: `teecustody.wire` round-trips every canonical value and fails closed (SR-3)."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from teecustody.wire import CanonicalValue, DecodeLimits, WireError, decode, encode

GENEROUS_LIMITS = DecodeLimits(max_bytes=1 << 24, max_depth=64, max_items=1 << 20)
VECTOR_LIMITS = DecodeLimits(max_bytes=1024, max_depth=4, max_items=64)
EXAMPLES = 500

scalars: st.SearchStrategy[CanonicalValue] = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**64), max_value=2**64 - 1),
    st.binary(max_size=64),
    st.text(max_size=32),
)
canonical_values: st.SearchStrategy[CanonicalValue] = st.recursive(
    scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=6),
        st.dictionaries(st.text(max_size=12), children, max_size=6),
    ),
    max_leaves=40,
)


@settings(max_examples=EXAMPLES)
@given(canonical_values)
def test_every_canonical_value_round_trips_and_encodes_deterministically(
    value: CanonicalValue,
) -> None:
    encoded = encode(value)
    assert encode(value) == encoded
    decoded = decode(encoded, GENEROUS_LIMITS)
    assert decoded == value
    assert type(decoded) is type(value)
    assert encode(decoded) == encoded


@settings(max_examples=EXAMPLES)
@given(st.binary(max_size=256))
def test_arbitrary_bytes_either_decode_or_raise_wire_error(data: bytes) -> None:
    for limits in (VECTOR_LIMITS, GENEROUS_LIMITS):
        try:
            value = decode(data, limits)
        except WireError:
            continue
        assert encode(value) == data
