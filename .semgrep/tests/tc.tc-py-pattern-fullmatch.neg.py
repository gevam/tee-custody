# Negative fixture: fullmatch, unanchored searches and a literal `\$` are allowed.
import re
from typing import Final

PATTERN: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
PREFIX = re.compile(r"sha256:")


def check(value: str) -> bool:
    if PATTERN.fullmatch(value) is not None:
        return True
    if re.fullmatch(r"[a-z]+$", value):
        return True
    if PREFIX.match(value) or re.search(r"price\$", value):
        return True
    return re.match(r"^[a-z]+", value) is not None
