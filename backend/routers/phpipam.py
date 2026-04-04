"""phpIPAM integration routes — config CRUD, test, preview, sync."""

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import encrypt_value, get_db
from models.phpipam_config import PhpIpamConfig

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/phpipam/configs")


class PhpIpamConfigCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    url: str = Field(..., min_length=1)
    app_id: str = Field(..., min_length=1)
    app_secret: str | None = None
    username: str | None = None
    password: str | None = None
    verify_ssl: bool = True
    auto_sync: bool = False
    sync_interval_min: int = Field(default=15, ge=1, le=1440)


class PhpIpamConfigUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    url: str | None = None
    app_id: str | None = None
    app_secret: str | None = None
    username: str | None = None
    password: str | None = None
    verify_ssl: bool | None = None
    auto_sync: bool | None = None
    sync_interval_min: int | None = Field(default=None, ge=1, le=1440)


def _require_user(request: Request):
    return getattr(request.state, "current_user", None)


def _config_to_dict(cfg: PhpIpamConfig) -> dict:
    return {
        "id": cfg.id,
        "name": cfg.name,
        "url": cfg.url,
        "app_id": cfg.app_id,
        "has_app_secret": bool(cfg.encrypted_app_secret),
        "has_username": bool(cfg.encrypted_username),
        "verify_ssl": cfg.verify_ssl,
        "auto_sync": cfg.auto_sync,
        "sync_interval_min": cfg.sync_interval_min,
        "last_sync_at": str(cfg.last_sync_at) if cfg.last_sync_at else None,
        "created_at": str(cfg.created_at) if cfg.created_at else None,
    }


@router.get("")
async def list_configs(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    result = await db.execute(
        select(PhpIpamConfig).where(PhpIpamConfig.user_id == user.id).order_by(PhpIpamConfig.name)
    )
    return {"configs": [_config_to_dict(c) for c in result.scalars().all()]}


@router.post("")
async def create_config(request: Request, body: PhpIpamConfigCreate, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = PhpIpamConfig(
        user_id=user.id,
        name=body.name,
        url=body.url.rstrip("/"),
        app_id=body.app_id,
        verify_ssl=body.verify_ssl,
        auto_sync=body.auto_sync,
        sync_interval_min=body.sync_interval_min,
    )
    if body.app_secret:
        cfg.encrypted_app_secret = encrypt_value(body.app_secret)
    if body.username:
        cfg.encrypted_username = encrypt_value(body.username)
    if body.password:
        cfg.encrypted_password = encrypt_value(body.password)

    db.add(cfg)
    await db.commit()
    return _config_to_dict(cfg)


@router.put("/{config_id}")
async def update_config(request: Request, config_id: int, body: PhpIpamConfigUpdate,
                        db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(PhpIpamConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    for field in ("name", "url", "app_id", "verify_ssl", "auto_sync", "sync_interval_min"):
        val = getattr(body, field, None)
        if val is not None:
            if field == "url":
                val = val.rstrip("/")
            setattr(cfg, field, val)

    if body.app_secret is not None:
        cfg.encrypted_app_secret = encrypt_value(body.app_secret) if body.app_secret else None
    if body.username is not None:
        cfg.encrypted_username = encrypt_value(body.username) if body.username else None
    if body.password is not None:
        cfg.encrypted_password = encrypt_value(body.password) if body.password else None

    await db.commit()
    return _config_to_dict(cfg)


@router.delete("/{config_id}")
async def delete_config(request: Request, config_id: int, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(PhpIpamConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    await db.delete(cfg)
    await db.commit()
    return {"ok": True}


@router.post("/{config_id}/test")
async def test_config(request: Request, config_id: int, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(PhpIpamConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    from services.phpipam import client_from_config
    client = client_from_config(cfg)
    try:
        result = await client.test_connection()
        return result
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=200)


@router.get("/{config_id}/preview")
async def preview_sync(request: Request, config_id: int, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(PhpIpamConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    from services.phpipam import preview_hosts
    try:
        hosts = await preview_hosts(cfg)
        return {"hosts": hosts, "count": len(hosts)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@router.post("/{config_id}/sync")
async def sync_config(request: Request, config_id: int, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(PhpIpamConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    from services.phpipam import sync_hosts
    result = await sync_hosts(db, cfg, user.id)
    return result
