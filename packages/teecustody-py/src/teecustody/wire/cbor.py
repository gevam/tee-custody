"""Canonical CBOR encoder and the single CBOR decode entry point (SR-3)."""

from teecustody.wire.types import CanonicalValue, DecodeLimits


def encode(value: CanonicalValue) -> bytes:
    raise NotImplementedError


def decode(data: bytes, limits: DecodeLimits) -> CanonicalValue:
    raise NotImplementedError
