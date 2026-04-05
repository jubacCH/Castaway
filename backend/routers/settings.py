"""Settings API routes."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import get_db
from models.setting import Setting

router = APIRouter(prefix="/api/settings")

# Default settings
DEFAULTS = {
    "screenshot_interval_min": "120",
    "status_interval_min": "5",
    "proxy_domain": "",  # e.g. apps.b8n.ch
    "login_url": "",  # e.g. https://castaway.b8n.ch/login
}


class SettingUpdate(BaseModel):
    value: str


@router.get("")
async def get_all_settings(request: Request, db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user or user.role != "admin":
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    settings = {}
    for key, default in DEFAULTS.items():
        row = await db.get(Setting, key)
        settings[key] = row.value if row else default

    return {"settings": settings}


@router.put("/{key}")
async def update_setting(request: Request, key: str, body: SettingUpdate,
                         db: AsyncSession = Depends(get_db)):
    user = getattr(request.state, "current_user", None)
    if not user or user.role != "admin":
        return JSONResponse({"error": "Admin access required"}, status_code=403)

    if key not in DEFAULTS:
        return JSONResponse({"error": f"Unknown setting: {key}"}, status_code=400)

    row = await db.get(Setting, key)
    if row:
        row.value = body.value
    else:
        db.add(Setting(key=key, value=body.value))
    await db.commit()

    return {"ok": True, "key": key, "value": body.value}
