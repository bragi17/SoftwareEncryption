"""Audit-log persistence helpers."""

from typing import Any

from sqlalchemy.orm import Session

from skeyserver.models import AuditLog


def record_audit(
    session: Session,
    *,
    action: str,
    entity_type: str,
    entity_id: str,
    actor: str = "system",
    ip_hash: str | None = None,
    detail_json: dict[str, Any] | None = None,
) -> AuditLog:
    audit_log = AuditLog(
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        ip_hash=ip_hash,
        detail_json=detail_json or {},
    )
    session.add(audit_log)
    return audit_log
