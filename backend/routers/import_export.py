"""Import/export routes for connections."""

import csv
import io
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
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


class ImportBody(BaseModel):
    content: str


@router.post("/import/connections")
async def import_connections(
    request: Request,
    body: ImportBody,
    format: str = "json",
    db: AsyncSession = Depends(get_db),
):
    """Import connections from JSON or CSV. Passwords are not imported."""
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    rows: list[dict] = []
    try:
        if format == "csv":
            reader = csv.DictReader(io.StringIO(body.content.strip()))
            for row in reader:
                rows.append({k.strip(): v.strip() for k, v in row.items()})
        else:
            parsed = json.loads(body.content)
            if not isinstance(parsed, list):
                return JSONResponse({"error": "JSON must be an array of connection objects"}, status_code=400)
            rows = parsed
    except (json.JSONDecodeError, csv.Error) as e:
        return JSONResponse({"error": f"Parse error: {e}"}, status_code=400)

    imported = 0
    skipped = 0
    for row in rows:
        name = str(row.get("name", "")).strip()
        host = str(row.get("host", "")).strip()
        if not name or not host:
            skipped += 1
            continue

        try:
            port = int(row.get("port", 22))
        except (ValueError, TypeError):
            port = 22

        protocol = str(row.get("protocol", "ssh")).lower()
        if protocol not in ("ssh", "rdp"):
            protocol = "ssh"

        conn = SSHConnection(
            user_id=user.id,
            name=name,
            host=host,
            port=port,
            protocol=protocol,
            username=str(row.get("username", "")).strip() or None,
            notes=str(row.get("notes", "")).strip() or None,
            source="import",
        )
        db.add(conn)
        imported += 1

    await db.commit()
    return {"imported": imported, "skipped": skipped}
