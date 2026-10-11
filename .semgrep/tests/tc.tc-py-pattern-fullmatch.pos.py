# Positive fixture: `$` also matches before a trailing newline, so `…$` patterns use fullmatch (R-7).
import re
from typing import Final

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID: Final = re.compile("[a-z]+$", re.ASCII)


def check(value: str) -> bool:
    # ruleid: tc-py-pattern-fullmatch
    if re.match(r"^[A-Z_]+$", value):
        return True
    # ruleid: tc-py-pattern-fullmatch
    if re.search("[0-9]{1,5}$", value, re.ASCII) is not None:
        return True
    # ruleid: tc-py-pattern-fullmatch
    if DIGEST.match(value):
        return True
    # ruleid: tc-py-pattern-fullmatch
    return _ID.search(value) is not None
