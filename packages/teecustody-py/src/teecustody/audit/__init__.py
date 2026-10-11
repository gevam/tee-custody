"""Audit port, validation and emitter (INC-2-API §4.12)."""

from teecustody.audit.emitter import AggregateOutcome, AuditEmitter
from teecustody.audit.ports import (
    AUDIT_ID_PATTERN,
    MAX_COUNT,
    AppendResult,
    AuditClass,
    AuditError,
    AuditErrorCode,
    AuditKey,
    AuditRecord,
    AuditSink,
)
from teecustody.audit.validate import audit_json, validate_audit

__all__ = [
    "AUDIT_ID_PATTERN",
    "MAX_COUNT",
    "AggregateOutcome",
    "AppendResult",
    "AuditClass",
    "AuditEmitter",
    "AuditError",
    "AuditErrorCode",
    "AuditKey",
    "AuditRecord",
    "AuditSink",
    "audit_json",
    "validate_audit",
]
