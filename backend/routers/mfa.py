"""MFA (TOTP) setup and management."""

import json
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.setting import Setting
from models.user import User
from services.mfa import generate_secret, verify_code, provisioning_uri, qr_code_png

_MFA_LOCKOUT_ATTEMPTS = 5
_MFA_LOCKOUT_WINDOW = 900  # 15 min


async def _get_mfa_attempts(db: AsyncSession, user_id: int) -> list[float]:
    row = await db.get(Setting, f"_mfa_lockout:{user_id}")
    if not row:
        return []
    try:
        return json.loads(row.value)
    except Exception:
        return []


async def _record_mfa_fail(db: AsyncSession, user_id: int):
    now = time.time()
    attempts = await _get_mfa_attempts(db, user_id)
    attempts = [t for t in attempts if t > now - _MFA_LOCKOUT_WINDOW]
    attempts.append(now)
    row = await db.get(Setting, f"_mfa_lockout:{user_id}")
    if row:
        row.value = json.dumps(attempts)
    else:
        db.add(Setting(key=f"_mfa_lockout:{user_id}", value=json.dumps(attempts)))
    await db.flush()


async def _is_mfa_locked(db: AsyncSession, user_id: int) -> bool:
    now = time.time()
    attempts = await _get_mfa_attempts(db, user_id)
    recent = [t for t in attempts if t > now - _MFA_LOCKOUT_WINDOW]
    return len(recent) >= _MFA_LOCKOUT_ATTEMPTS


async def _clear_mfa_fails(db: AsyncSession, user_id: int):
    row = await db.get(Setting, f"_mfa_lockout:{user_id}")
    if row:
        row.value = "[]"
        await db.flush()

router = APIRouter(prefix="/api/mfa")


class VerifyRequest(BaseModel):
    code: str


class DisableRequest(BaseModel):
    code: str


async def _get_user(request: Request, db: AsyncSession) -> User | None:
    """Re-load user from current DB session (middleware user is detached)."""
    ctx_user = getattr(request.state, "current_user", None)
    if not ctx_user:
        return None
    return await db.get(User, ctx_user.id)


@router.post("/setup")
async def setup_mfa(request: Request, db: AsyncSession = Depends(get_db)):
    """Start MFA setup — generate secret and return provisioning URI."""
    user = await _get_user(request, db)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    if user.mfa_enabled:
        return JSONResponse({"error": "MFA already enabled"}, status_code=400)

    secret = generate_secret()
    user.mfa_secret = secret
    user.mfa_enabled = False
    await db.commit()

    uri = provisioning_uri(secret, user.username)
    return {"secret": secret, "uri": uri}


@router.get("/qrcode.png")
async def mfa_qrcode(request: Request, db: AsyncSession = Depends(get_db)):
    """Return QR code PNG for current setup secret."""
    user = await _get_user(request, db)
    if not user or not user.mfa_secret:
        return JSONResponse({"error": "No MFA setup in progress"}, status_code=404)
    uri = provisioning_uri(user.mfa_secret, user.username)
    png = qr_code_png(uri)
    return Response(content=png, media_type="image/png")


@router.post("/verify")
async def verify_mfa(request: Request, body: VerifyRequest, db: AsyncSession = Depends(get_db)):
    """Verify TOTP code and enable MFA."""
    user = await _get_user(request, db)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    if await _is_mfa_locked(db, user.id):
        return JSONResponse({"error": "Too many failed attempts. Try again later."}, status_code=429)

    if not user.mfa_secret:
        return JSONResponse({"error": "No MFA setup in progress"}, status_code=400)

    if not verify_code(user.mfa_secret, body.code):
        await _record_mfa_fail(db, user.id)
        await db.commit()
        return JSONResponse({"error": "Invalid code"}, status_code=400)

    await _clear_mfa_fails(db, user.id)
    user.mfa_enabled = True
    await db.commit()
    return {"ok": True, "enabled": True}


@router.post("/disable")
async def disable_mfa(request: Request, body: DisableRequest, db: AsyncSession = Depends(get_db)):
    """Disable MFA — requires current TOTP code."""
    user = await _get_user(request, db)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    if await _is_mfa_locked(db, user.id):
        return JSONResponse({"error": "Too many failed attempts. Try again later."}, status_code=429)

    if not user.mfa_enabled:
        return JSONResponse({"error": "MFA not enabled"}, status_code=400)

    if not verify_code(user.mfa_secret, body.code):
        await _record_mfa_fail(db, user.id)
        await db.commit()
        return JSONResponse({"error": "Invalid code"}, status_code=400)

    await _clear_mfa_fails(db, user.id)
    user.mfa_enabled = False
    user.mfa_secret = None
    await db.commit()
    return {"ok": True, "enabled": False}


@router.get("/status")
async def mfa_status(request: Request, db: AsyncSession = Depends(get_db)):
    user = await _get_user(request, db)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return {"enabled": user.mfa_enabled}
