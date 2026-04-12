"""Audit logging helper — write structured audit entries."""

import json
import logging
from datetime import datetime

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from models.audit_log import AuditLog

logger = logging.getLogger(__name__)


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


async def audit(
    db: AsyncSession,
    request: Request,
    action: str,
    resource_type: str,
    resource_id: int | None = None,
    resource_name: str | None = None,
    details: dict | None = None,
) -> None:
    """Write a single audit log entry. Never raises — failures are logged but swallowed."""
    try:
        user = getattr(request.state, "current_user", None)
        entry = AuditLog(
            user_id=user.id if user else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            details=json.dumps(details) if details else None,
            ip_address=_client_ip(request),
            created_at=datetime.utcnow(),
        )
        db.add(entry)
        # Flush without committing — caller commits the outer transaction
        await db.flush()
    except Exception as exc:
        logger.error("Audit log write failed: %s", exc, exc_info=True)
