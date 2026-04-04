"""Folder CRUD API routes."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.connection import SSHConnection
from models.folder import Folder
from schemas.folder import FolderCreate, FolderUpdate

router = APIRouter(prefix="/api/folders")


def _require_user(request: Request):
    user = getattr(request.state, "current_user", None)
    return user


@router.get("")
async def list_folders(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    result = await db.execute(
        select(Folder).where(Folder.user_id == user.id).order_by(Folder.sort_order, Folder.name)
    )
    folders = result.scalars().all()

    items = []
    for f in folders:
        count = (await db.execute(
            select(func.count()).select_from(SSHConnection)
            .where(SSHConnection.folder_id == f.id)
        )).scalar() or 0
        items.append({
            "id": f.id, "name": f.name, "parent_id": f.parent_id,
            "color": f.color, "sort_order": f.sort_order,
            "connection_count": count,
        })

    return {"folders": items}


@router.post("")
async def create_folder(request: Request, body: FolderCreate, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    folder = Folder(user_id=user.id, name=body.name, parent_id=body.parent_id,
                    color=body.color, sort_order=body.sort_order)
    db.add(folder)
    await db.commit()
    return {"id": folder.id, "name": folder.name, "parent_id": folder.parent_id,
            "color": folder.color, "sort_order": folder.sort_order, "connection_count": 0}


@router.put("/{folder_id}")
async def update_folder(request: Request, folder_id: int, body: FolderUpdate,
                        db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    folder = await db.get(Folder, folder_id)
    if not folder or (folder.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    for field in ("name", "parent_id", "color", "sort_order"):
        val = getattr(body, field, None)
        if val is not None:
            setattr(folder, field, val)

    await db.commit()
    return {"id": folder.id, "name": folder.name, "parent_id": folder.parent_id,
            "color": folder.color, "sort_order": folder.sort_order}


@router.delete("/{folder_id}")
async def delete_folder(request: Request, folder_id: int, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    folder = await db.get(Folder, folder_id)
    if not folder or (folder.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    await db.delete(folder)
    await db.commit()
    return {"ok": True}
