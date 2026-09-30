"""Negative-case catalog (API.md §G; spec §13.2, §15.3; SR-12)."""

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class NegativeCase:
    case_id: str
    check: str
    error_code: str
    altered: tuple[str, ...]
    debug_event: bool


NEGATIVE_CASES: Final[tuple[NegativeCase, ...]] = ()
