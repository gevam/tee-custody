"""Allow-listed JSON logger."""

import json
import logging
from datetime import UTC, datetime
from typing import TextIO

from teecustody.obs.types import ALLOWED_FIELDS, OUTCOME_PATTERN, AllowListedLogger, FieldValue

_MAX_STR = 128
_INVALID_OUTCOME = "INVALID_OUTCOME_CODE"


class _Adapter:
    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def _log(self, level: int, outcome: str, fields: dict[str, FieldValue]) -> None:
        self._logger.log(level, outcome, extra={"tc_fields": fields})

    def info(self, outcome: str, **fields: FieldValue) -> None:
        self._log(logging.INFO, outcome, fields)

    def warning(self, outcome: str, **fields: FieldValue) -> None:
        self._log(logging.WARNING, outcome, fields)

    def error(self, outcome: str, **fields: FieldValue) -> None:
        self._log(logging.ERROR, outcome, fields)


def get_logger(name: str) -> AllowListedLogger:
    return _Adapter(logging.getLogger("teecustody." + name))


def _field_ok(key: object, value: object) -> bool:
    if key not in ALLOWED_FIELDS:
        return False
    if isinstance(value, str):
        return len(value) <= _MAX_STR
    return isinstance(value, int) and not isinstance(value, bool)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = record.msg
        outcome = msg if isinstance(msg, str) and OUTCOME_PATTERN.match(msg) else _INVALID_OUTCOME
        ts = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")
        obj: dict[str, FieldValue] = {
            "ts": ts.replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "outcome": outcome,
        }
        fields = getattr(record, "tc_fields", None)
        if isinstance(fields, dict):
            obj.update({k: v for k, v in fields.items() if _field_ok(k, v)})
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))


_handler: logging.Handler | None = None


def configure_logging(stream: TextIO, level: int = logging.INFO) -> None:
    global _handler
    base = logging.getLogger("teecustody")
    if _handler is not None:
        base.removeHandler(_handler)
    _handler = logging.StreamHandler(stream)
    _handler.setFormatter(JsonLogFormatter())
    base.addHandler(_handler)
    base.setLevel(level)
    base.propagate = False
