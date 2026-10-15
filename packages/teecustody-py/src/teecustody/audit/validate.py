"""Audit record validation and canonical JSON (INC-2-API §4.12; SR-6, SR-12, D-007, D-012).

Errors carry only `AuditErrorCode.INVALID_ARGUMENT`; no field value reaches the exception (SR-11).
"""

import json
import re
from dataclasses import fields
from typing import Final

from teecustody.audit.ports import (
    AUDIT_ID_PATTERN,
    MAX_COUNT,
    AuditClass,
    AuditError,
    AuditErrorCode,
    AuditKey,
    AuditRecord,
)
from teecustody.obs.types import OUTCOME_PATTERN

# Same pattern as `teecustody.channel.codec.HEX32_PATTERN` (pinned by a test); not imported because
# `channel` depends on `audit`, and the reverse import would make the two packages a cycle.
_HEX32_PATTERN: Final = re.compile(r"[0-9a-f]{32}")
_MAX_WIDE: Final = 2**53 - 1
_MAX_U32: Final = 2**32 - 1


def _invalid() -> AuditError:
    return AuditError(AuditErrorCode.INVALID_ARGUMENT)


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _in_range(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _check_optional_ints(record: AuditRecord) -> None:
    ranges = (
        (record.interval_start, _MAX_WIDE),
        (record.interval_end, _MAX_WIDE),
        (record.prekey_id, _MAX_U32),
        (record.epoch, _MAX_U32),
    )
    for value, high in ranges:
        if value is not None and not _in_range(value, 0, high):
            raise _invalid()


def _check_identifiers(record: AuditRecord) -> None:
    identifiers = (
        record.actor_client_id,
        record.subject_client_id,
        record.recovery_id,
        record.request_id,
        record.session_id,
    )
    for value in identifiers:
        if value is not None and not _matches(_HEX32_PATTERN, value):
            raise _invalid()


def _check_interval(record_class: AuditClass, record: AuditRecord) -> None:
    start, end = record.interval_start, record.interval_end
    if start is None and end is None:
        if record_class is AuditClass.AGGREGATE:
            raise _invalid()
        return
    if record_class not in (AuditClass.ALERT, AuditClass.AGGREGATE):
        raise _invalid()
    if start is None or end is None or start >= end:
        raise _invalid()


def _check_count(record_class: AuditClass, record: AuditRecord) -> None:
    if record_class is AuditClass.AGGREGATE:
        if not _in_range(record.count, 1, MAX_COUNT):
            raise _invalid()
    elif record.count is not None:
        raise _invalid()


def validate_audit(key: AuditKey, record: AuditRecord) -> None:
    if type(key) is not AuditKey or type(record) is not AuditRecord:
        raise _invalid()
    if not isinstance(key.record_class, AuditClass) or not _matches(AUDIT_ID_PATTERN, key.id):
        raise _invalid()
    if not _matches(OUTCOME_PATTERN, record.outcome):
        raise _invalid()
    if not _in_range(record.ts, 0, _MAX_WIDE):
        raise _invalid()
    _check_optional_ints(record)
    _check_identifiers(record)
    _check_interval(key.record_class, record)
    _check_count(key.record_class, record)


def audit_json(record: AuditRecord) -> bytes:
    if not isinstance(record, AuditRecord):
        raise _invalid()
    body = {f.name: getattr(record, f.name) for f in fields(AuditRecord)}
    present = {name: value for name, value in body.items() if value is not None}
    return json.dumps(present, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
