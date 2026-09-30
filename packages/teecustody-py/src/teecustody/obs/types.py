"""Allow-listed structured logging types."""

import re
from typing import Final, Protocol

ALLOWED_FIELDS: Final = frozenset({"client_id", "request_id", "session_id", "prekey_id", "epoch"})
OUTCOME_PATTERN: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

type FieldValue = str | int


class AllowListedLogger(Protocol):
    def info(self, outcome: str, **fields: FieldValue) -> None: ...

    def warning(self, outcome: str, **fields: FieldValue) -> None: ...

    def error(self, outcome: str, **fields: FieldValue) -> None: ...
