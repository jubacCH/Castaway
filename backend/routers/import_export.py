"""Export routes — JSON export of connections."""

import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.connection import SSHConnection
from models.tag import Tag, connection_tags

router = APIRouter(prefix="/api")


@router.get("/export/connections")
async def export_connections(request: Request, db: AsyncSession = Depends(get_db)):
    """Export all connections as JSON (passwords stripped)."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    result = await db.execute(
        select(SSHConnection).where(SSHConnection.user_id == user.id).order_by(SSHConnection.name)
    )
    connections = result.scalars().all()

    export = []
    for conn in connections:
        tag_rows = (await db.execute(
            select(Tag).join(connection_tags).where(connection_tags.c.connection_id == conn.id)
        )).scalars().all()

        export.append({
            "name": conn.name,
            "host": conn.host,
            "port": conn.port,
            "protocol": conn.protocol,
            "username": conn.username,
            "auth_method": conn.auth_method,
            "notes": conn.notes,
            "source": conn.source,
            "tags": [t.name for t in tag_rows],
        })

    content = json.dumps(export, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="castaway-connections.json"'},
    )
