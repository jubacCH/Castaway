"""Tag CRUD API routes."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.tag import Tag
from schemas.tag import TagCreate

router = APIRouter(prefix="/api/tags")


@router.get("")
async def list_tags(request: Request, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    result = await db.execute(
        select(Tag).where(Tag.user_id == user.id).order_by(Tag.name)
    )
    tags = result.scalars().all()
    return {"tags": [{"id": t.id, "name": t.name, "color": t.color} for t in tags]}


@router.post("")
async def create_tag(request: Request, body: TagCreate, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    tag = Tag(user_id=user.id, name=body.name, color=body.color)
    db.add(tag)
    await db.commit()
    return {"id": tag.id, "name": tag.name, "color": tag.color}


@router.delete("/{tag_id}")
async def delete_tag(request: Request, tag_id: int, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    tag = await db.get(Tag, tag_id)
    if not tag or (tag.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    await db.delete(tag)
    await db.commit()
    return {"ok": True}
