"""RDP file download endpoint."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.connection import SSHConnection
from services.rdp_generator import generate_rdp

router = APIRouter()


@router.get("/api/connections/{conn_id}/rdp-file")
async def download_rdp(request: Request, conn_id: int, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = await db.get(SSHConnection, conn_id)
    if not conn or (conn.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    if conn.protocol != "rdp":
        return JSONResponse({"error": "Not an RDP connection"}, status_code=400)

    rdp_content = generate_rdp(
        host=conn.host,
        port=conn.port or 3389,
        username=conn.username,
    )

    filename = f"{conn.name.replace(' ', '_')}.rdp"
    return Response(
        content=rdp_content,
        media_type="application/x-rdp",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
