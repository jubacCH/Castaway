"""Authentication routes: register, login, logout."""

import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta

import bcrypt
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.setting import Setting
from models.user import Session, User, hash_token
from schemas.auth import LoginRequest, RegisterRequest

logger = logging.getLogger(__name__)
router = APIRouter()

SESSION_DAYS = 7
_LOCKOUT_ATTEMPTS = 5
_LOCKOUT_WINDOW = 900  # 15 minutes


async def _get_failed_attempts(db: AsyncSession, username: str) -> list[float]:
    """Get failed login timestamps from DB settings."""
    row = await db.get(Setting, f"_lockout:{username}")
    if not row:
        return []
    try:
        return json.loads(row.value)
    except Exception:
        return []


async def _record_failed(db: AsyncSession, username: str):
    now = time.time()
    attempts = await _get_failed_attempts(db, username)
    attempts = [t for t in attempts if t > now - _LOCKOUT_WINDOW]
    attempts.append(now)
    row = await db.get(Setting, f"_lockout:{username}")
    if row:
        row.value = json.dumps(attempts)
    else:
        db.add(Setting(key=f"_lockout:{username}", value=json.dumps(attempts)))
    await db.flush()


async def _clear_failed(db: AsyncSession, username: str):
    row = await db.get(Setting, f"_lockout:{username}")
    if row:
        row.value = "[]"
        await db.flush()


async def _is_locked_out(db: AsyncSession, username: str) -> bool:
    now = time.time()
    attempts = await _get_failed_attempts(db, username)
    recent = [t for t in attempts if t > now - _LOCKOUT_WINDOW]
    return len(recent) >= _LOCKOUT_ATTEMPTS


def _session_response(user: User, token: str, request: Request) -> JSONResponse:
    response = JSONResponse({
        "ok": True,
        "user": {"id": user.id, "username": user.username, "role": user.role},
    })
    force_secure = os.environ.get("SECURE_COOKIES", "").lower() in ("1", "true", "yes")
    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        "castaway_session", token,
        max_age=SESSION_DAYS * 86400, httponly=True, samesite="strict",
        secure=force_secure or is_https,
    )
    return response


@router.post("/api/auth/register")
async def register(request: Request, body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Check if any users exist — first user becomes admin
    user_count = (await db.execute(select(func.count()).select_from(User))).scalar() or 0

    # Only admin can create additional users
    if user_count > 0:
        current = getattr(request.state, "current_user", None)
        if not current or current.role != "admin":
            return JSONResponse({"error": "Only admins can register new users"}, status_code=403)

    # Check username uniqueness
    existing = (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    if existing:
        return JSONResponse({"error": "Username already taken"}, status_code=409)

    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt(rounds=12)).decode()
    role = "admin" if user_count == 0 else "user"

    user = User(username=body.username, email=body.email, password_hash=pw_hash, role=role)
    db.add(user)
    await db.flush()

    token = secrets.token_hex(32)
    db.add(Session(token=hash_token(token), user_id=user.id,
                   expires_at=datetime.utcnow() + timedelta(days=SESSION_DAYS)))
    await db.commit()

    logger.info("User registered: %s (role=%s)", user.username, role)
    return _session_response(user, token, request)


@router.post("/api/auth/login")
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    if await _is_locked_out(db, body.username):
        return JSONResponse({"error": "Account temporarily locked. Try again later."}, status_code=429)

    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()

    _dummy_hash = b"$2b$12$000000000000000000000uGHEjmFMntPDYjXJPBT3V44YS5gL0nS"
    stored_hash = user.password_hash.encode() if user else _dummy_hash
    pw_ok = bcrypt.checkpw(body.password.encode(), stored_hash)

    if not user or not pw_ok:
        await _record_failed(db, body.username)
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)

    if not user.is_active:
        return JSONResponse({"error": "Account is disabled"}, status_code=403)

    await _clear_failed(db, body.username)
    token = secrets.token_hex(32)
    db.add(Session(token=hash_token(token), user_id=user.id,
                   expires_at=datetime.utcnow() + timedelta(days=SESSION_DAYS)))
    await db.commit()

    return _session_response(user, token, request)


@router.get("/api/auth/me")
async def me(request: Request):
    user = getattr(request.state, "current_user", None)
    if not user:
        return JSONResponse({"user": None}, status_code=401)
    return {"user": {"id": user.id, "username": user.username, "role": user.role or "admin"}}


@router.post("/api/auth/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("castaway_session")
    if token:
        session = await db.get(Session, hash_token(token))
        if session:
            await db.delete(session)
            await db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie("castaway_session")
    return response
