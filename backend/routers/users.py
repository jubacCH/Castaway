"""User management API routes (admin only)."""

import bcrypt
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.user import User

router = APIRouter(prefix="/api/users")


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8)
    email: str | None = None
    role: str = Field(default="user", pattern="^(admin|user)$")


class UserUpdate(BaseModel):
    email: str | None = None
    role: str | None = Field(default=None, pattern="^(admin|user)$")
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8)


def _require_admin(request: Request):
    user = getattr(request.state, "current_user", None)
    if not user or user.role != "admin":
        return None
    return user


@router.get("")
async def list_users(request: Request, db: AsyncSession = Depends(get_db)):
    if not _require_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    result = await db.execute(select(User).order_by(User.username))
    users = result.scalars().all()
    return {"users": [{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": str(u.created_at) if u.created_at else None,
    } for u in users]}


@router.post("")
async def create_user(request: Request, body: UserCreate, db: AsyncSession = Depends(get_db)):
    if not _require_admin(request):
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    existing = (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    if existing:
        return JSONResponse({"error": "Username already taken"}, status_code=409)

    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt(rounds=12)).decode()
    user = User(username=body.username, email=body.email, password_hash=pw_hash, role=body.role)
    db.add(user)
    await db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}


@router.put("/{user_id}")
async def update_user(request: Request, user_id: int, body: UserUpdate,
                      db: AsyncSession = Depends(get_db)):
    admin = _require_admin(request)
    if not admin:
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    user = await db.get(User, user_id)
    if not user:
        return JSONResponse({"error": "Not found"}, status_code=404)

    if body.email is not None:
        user.email = body.email
    if body.role is not None:
        # Prevent demoting yourself
        if user.id == admin.id and body.role != "admin":
            return JSONResponse({"error": "Cannot demote yourself"}, status_code=400)
        user.role = body.role
    if body.is_active is not None:
        if user.id == admin.id and not body.is_active:
            return JSONResponse({"error": "Cannot deactivate yourself"}, status_code=400)
        user.is_active = body.is_active
    if body.password:
        user.password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt(rounds=12)).decode()

    await db.commit()
    return {"id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active}


@router.delete("/{user_id}")
async def delete_user(request: Request, user_id: int, db: AsyncSession = Depends(get_db)):
    admin = _require_admin(request)
    if not admin:
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    if user_id == admin.id:
        return JSONResponse({"error": "Cannot delete yourself"}, status_code=400)

    user = await db.get(User, user_id)
    if not user:
        return JSONResponse({"error": "Not found"}, status_code=404)

    await db.delete(user)
    await db.commit()
    return {"ok": True}
