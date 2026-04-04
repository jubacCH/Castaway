"""Session log viewer API routes."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.connection import SSHConnection
from models.session_log import SessionLog
from models.user import User

router = APIRouter(prefix="/api/sessions")


@router.get("")
async def list_sessions(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    user_id: int | None = None,
    connection_id: int | None = None,
    db: AsyncSession = Depends(get_db),
):
    current = getattr(request.state, "current_user", None)
    if not current:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    # Only admins can view all sessions; users see only their own
    q = select(SessionLog)
    if current.role != "admin":
        q = q.where(SessionLog.user_id == current.id)
    elif user_id is not None:
        q = q.where(SessionLog.user_id == user_id)

    if connection_id is not None:
        q = q.where(SessionLog.connection_id == connection_id)

    total = (await db.execute(
        select(func.count()).select_from(q.subquery())
    )).scalar() or 0

    result = await db.execute(
        q.order_by(desc(SessionLog.started_at)).offset(offset).limit(limit)
    )
    logs = result.scalars().all()

    # Resolve user/connection names
    items = []
    for log in logs:
        user_obj = await db.get(User, log.user_id) if log.user_id else None
        conn_obj = await db.get(SSHConnection, log.connection_id) if log.connection_id else None
        items.append({
            "id": log.id,
            "user": user_obj.username if user_obj else "deleted",
            "connection_name": conn_obj.name if conn_obj else "deleted",
            "connection_host": conn_obj.host if conn_obj else "",
            "started_at": str(log.started_at) if log.started_at else None,
            "ended_at": str(log.ended_at) if log.ended_at else None,
            "duration_sec": log.duration_sec,
            "ip_address": log.ip_address,
            "bytes_sent": log.bytes_sent,
            "bytes_recv": log.bytes_recv,
        })

    return {"sessions": items, "total": total}
