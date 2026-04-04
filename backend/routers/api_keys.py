"""API Key management routes."""

import hashlib
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.api_key import ApiKey, generate_api_key
from models.base import get_db

router = APIRouter(prefix="/api/keys")


class KeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    role: str = Field(default="readonly", pattern="^(readonly|editor|admin)$")


@router.get("")
async def list_keys(request: Request, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    result = await db.execute(
        select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()
    return {"keys": [{
        "id": k.id,
        "name": k.name,
        "prefix": k.prefix,
        "role": k.role,
        "created_at": str(k.created_at) if k.created_at else None,
        "last_used_at": str(k.last_used_at) if k.last_used_at else None,
    } for k in keys]}


@router.post("")
async def create_key(request: Request, body: KeyCreate, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    raw_key, key_hash = generate_api_key()
    api_key = ApiKey(
        user_id=user.id,
        name=body.name,
        key_hash=key_hash,
        prefix=raw_key[:12],
        role=body.role,
    )
    db.add(api_key)
    await db.commit()

    # Return the raw key ONCE — it can never be retrieved again
    return {"id": api_key.id, "name": api_key.name, "key": raw_key, "role": api_key.role}


@router.delete("/{key_id}")
async def delete_key(request: Request, key_id: int, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    key = await db.get(ApiKey, key_id)
    if not key or key.user_id != user.id:
        return JSONResponse({"error": "Not found"}, status_code=404)

    await db.delete(key)
    await db.commit()
    return {"ok": True}
