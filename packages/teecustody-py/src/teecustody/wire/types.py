"""Canonical wire value types and errors."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

PROTO: Final = "tee-chan-v1"

type CanonicalValue = (
    bool | int | str | bytes | list[CanonicalValue] | dict[str, CanonicalValue] | None
)


@dataclass(frozen=True)
class DecodeLimits:
    max_bytes: int
    max_depth: int
    max_items: int


class WireErrorCode(StrEnum):
    TOO_LARGE = "TOO_LARGE"
    MALFORMED = "MALFORMED"
    NONCANONICAL = "NONCANONICAL"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"


class WireError(Exception):
    code: WireErrorCode
