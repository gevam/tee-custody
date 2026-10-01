"""Canonical CBOR encoder and the single CBOR decode entry point (SR-3)."""

from dataclasses import dataclass

import cbor2

from teecustody.wire.types import CanonicalValue, DecodeLimits, WireError, WireErrorCode

_MAJOR_UNSIGNED = 0
_MAJOR_NEGATIVE = 1
_MAJOR_BYTES = 2
_MAJOR_TEXT = 3
_MAJOR_ARRAY = 4
_MAJOR_MAP = 5
_MAJOR_TAG = 6
_MAJOR_SIMPLE = 7

_INFO_ONE_BYTE = 24
_INFO_EIGHT_BYTES = 27
_INFO_RESERVED = range(28, 31)
_INFO_INDEFINITE = 31
_INFO_31_IS_MALFORMED = frozenset({_MAJOR_UNSIGNED, _MAJOR_NEGATIVE, _MAJOR_TAG, _MAJOR_SIMPLE})
# Smallest argument that needs each additional-information width (shortest form, major types 0-6).
_SHORTEST_MIN = {24: 24, 25: 0x100, 26: 0x1_0000, 27: 0x1_0000_0000}
_SIMPLE_MIN_TWO_BYTE = 32
_PERMITTED_SIMPLE = frozenset({0xF4, 0xF5, 0xF6})  # false, true, null
_INT_MIN = -(2**64)
_INT_MAX = 2**64 - 1


@dataclass
class _Container:
    remaining: int
    depth: int
    is_map: bool
    previous_key: bytes | None = None
    keys_out_of_order: bool = False


def _scan(data: bytes, limits: DecodeLimits) -> None:
    """Iterative structural pre-scan enforcing rules 2, 3 and 5 in byte order, before cbor2."""
    end = len(data)
    pos = 0
    items = 0
    open_containers: list[_Container] = []
    while True:
        parent = open_containers[-1] if open_containers else None
        depth = parent.depth + 1 if parent else 1
        is_key = parent is not None and parent.is_map and parent.remaining % 2 == 0
        start = pos
        if pos >= end:
            raise WireError(WireErrorCode.MALFORMED)
        initial = data[pos]
        pos += 1
        major = initial >> 5
        info = initial & 0x1F
        # (a) reserved additional information; 31 where it cannot introduce an indefinite length.
        if info in _INFO_RESERVED or (info == _INFO_INDEFINITE and major in _INFO_31_IS_MALFORMED):
            raise WireError(WireErrorCode.MALFORMED)
        argument = info
        if _INFO_ONE_BYTE <= info <= _INFO_EIGHT_BYTES:
            width = 1 << (info - _INFO_ONE_BYTE)
            # (b) argument bytes present; a two-byte simple value below 32 is ill-formed.
            if width > end - pos:
                raise WireError(WireErrorCode.MALFORMED)
            argument = int.from_bytes(data[pos : pos + width], "big")
            pos += width
            if major == _MAJOR_SIMPLE:
                if info == _INFO_ONE_BYTE and argument < _SIMPLE_MIN_TWO_BYTE:
                    raise WireError(WireErrorCode.MALFORMED)
            # (c) shortest form, major types 0-6 only.
            elif argument < _SHORTEST_MIN[info]:
                raise WireError(WireErrorCode.NONCANONICAL)
        # (d) indefinite length, then anything outside the data model.
        if info == _INFO_INDEFINITE:
            raise WireError(WireErrorCode.NONCANONICAL)
        if major == _MAJOR_TAG or (major == _MAJOR_SIMPLE and initial not in _PERMITTED_SIMPLE):
            raise WireError(WireErrorCode.UNSUPPORTED_TYPE)
        if is_key and major != _MAJOR_TEXT:
            raise WireError(WireErrorCode.UNSUPPORTED_TYPE)
        # (e) depth.
        if depth > limits.max_depth:
            raise WireError(WireErrorCode.LIMIT_EXCEEDED)
        # (f) item budget, then declared sizes against the bytes left (ADR 0010 allocation guard).
        items += 1
        children = 0
        if major == _MAJOR_ARRAY:
            children = argument
        elif major == _MAJOR_MAP:
            children = 2 * argument
        if items + children > limits.max_items:
            raise WireError(WireErrorCode.LIMIT_EXCEEDED)
        if children > end - pos:
            raise WireError(WireErrorCode.MALFORMED)
        if major in (_MAJOR_BYTES, _MAJOR_TEXT):
            if argument > end - pos:
                raise WireError(WireErrorCode.MALFORMED)
            if major == _MAJOR_TEXT:
                try:
                    data[pos : pos + argument].decode("utf-8")
                except UnicodeDecodeError:
                    raise WireError(WireErrorCode.MALFORMED) from None
            pos += argument
        if is_key and parent is not None:
            key = data[start:pos]
            if parent.previous_key is not None and key <= parent.previous_key:
                parent.keys_out_of_order = True
            parent.previous_key = key
        if children:
            open_containers.append(_Container(children, depth, major == _MAJOR_MAP))
            continue
        # The item is complete: close every container it completes (key order is judged at map end).
        while open_containers:
            container = open_containers[-1]
            container.remaining -= 1
            if container.remaining:
                break
            open_containers.pop()
            if container.keys_out_of_order:
                raise WireError(WireErrorCode.NONCANONICAL)
        if not open_containers:
            break
    if pos != end:
        raise WireError(WireErrorCode.MALFORMED)


def _validate(value: object) -> None:
    """Iterative check that `value` is in the rule-2 data model (exact types; bool before int)."""
    pending = [value]
    while pending:
        item = pending.pop()
        kind = type(item)
        if item is None or kind in (bool, str, bytes):
            continue
        if isinstance(item, int) and kind is int:
            if not _INT_MIN <= item <= _INT_MAX:
                raise WireError(WireErrorCode.UNSUPPORTED_TYPE)
        elif isinstance(item, list) and kind is list:
            pending.extend(item)
        elif isinstance(item, dict) and kind is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise WireError(WireErrorCode.UNSUPPORTED_TYPE)
                pending.append(child)
        else:
            raise WireError(WireErrorCode.UNSUPPORTED_TYPE)


def encode(value: CanonicalValue) -> bytes:
    _validate(value)
    return cbor2.dumps(value, canonical=True)


def decode(data: bytes, limits: DecodeLimits) -> CanonicalValue:
    if min(limits.max_bytes, limits.max_depth, limits.max_items) < 1:
        raise ValueError("INVALID_LIMITS")
    if len(data) > limits.max_bytes:
        raise WireError(WireErrorCode.TOO_LARGE)
    _scan(data, limits)
    result: CanonicalValue = cbor2.loads(data)
    return result
