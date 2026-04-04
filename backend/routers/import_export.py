"""Import/Export routes — Keeper CSV, JSON export."""

import json
import logging

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.connection import SSHConnection
from models.tag import Tag, connection_tags

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


@router.post("/import/keeper/preview")
async def preview_keeper(request: Request, file: UploadFile = File(...)):
    """Preview Keeper CSV import."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    content = (await file.read()).decode("utf-8", errors="replace")
    from services.keeper_import import preview_keeper_import
    records = preview_keeper_import(content)
    return {"records": records, "count": len(records)}


@router.post("/import/keeper")
async def import_keeper(
    request: Request,
    file: UploadFile = File(...),
    mode: str = Form(default="connections"),
    db: AsyncSession = Depends(get_db),
):
    """Import Keeper CSV. mode: 'connections' or 'credentials'."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    content = (await file.read()).decode("utf-8", errors="replace")
    from services.keeper_import import import_keeper_csv
    result = await import_keeper_csv(db, content, user.id, mode=mode)
    return result


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
