"""Canonical CBOR encoder and the single CBOR decode entry point (SR-3)."""

import cbor2

from teecustody.wire.types import CanonicalValue, DecodeLimits


def encode(value: CanonicalValue) -> bytes:
    return cbor2.dumps(value, canonical=True)


def decode(data: bytes, limits: DecodeLimits) -> CanonicalValue:
    result: CanonicalValue = cbor2.loads(data)
    return result
