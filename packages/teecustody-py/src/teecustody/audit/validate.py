"""Audit record validation and canonical JSON (INC-2-API §4.12). Bodies belong to T-11."""

from teecustody.audit.ports import AuditKey, AuditRecord


def validate_audit(key: AuditKey, record: AuditRecord) -> None:
    raise NotImplementedError("T-11")


def audit_json(record: AuditRecord) -> bytes:
    raise NotImplementedError("T-11")
