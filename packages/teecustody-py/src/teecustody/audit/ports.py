"""Audit sink port and record types (INC-2-API §4.12; SR-6, SR-12, D-007, D-012; ADR 0005)."""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol


class AuditClass(StrEnum):
    EVENT = "EVENT"
    ALERT = "ALERT"
    AGGREGATE = "AGGREGATE"
    RELEASE = "RELEASE"


AUDIT_ID_PATTERN: Final = re.compile(
    r"[A-Za-z0-9_-]{1,128}(/[A-Za-z0-9_-]{1,64}){0,2}"
)  # fullmatch only
MAX_COUNT: Final = 2**53 - 1


@dataclass(frozen=True, slots=True)
class AuditKey:
    record_class: AuditClass
    id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AuditRecord:
    outcome: str  # OUTCOME_PATTERN
    ts: int  # Unix ms
    interval_start: int | None = None  # ms; AGGREGATE (required) and ALERT only
    interval_end: int | None = None
    actor_client_id: str | None = None
    subject_client_id: str | None = None
    recovery_id: str | None = None
    request_id: str | None = None  # 32 hex
    session_id: str | None = None  # 32 hex
    prekey_id: int | None = None  # 0..2^32-1
    epoch: int | None = None  # 0..2^32-1
    count: int | None = None  # required iff AGGREGATE; 1..MAX_COUNT


class AppendResult(StrEnum):
    CREATED = "CREATED"
    ALREADY_EXISTS = "ALREADY_EXISTS"


class AuditErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    UNAVAILABLE = "UNAVAILABLE"


class AuditError(Exception):
    """Carries only a stable code; `str(err)` is the code value and nothing else."""

    code: AuditErrorCode

    def __init__(self, code: AuditErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


class AuditSink(Protocol):
    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult: ...
