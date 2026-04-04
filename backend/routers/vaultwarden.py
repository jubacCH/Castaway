"""Vaultwarden integration routes — config CRUD, test, preview, assign."""

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import encrypt_value, get_db
from models.vaultwarden_config import VaultwardenConfig

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vaultwarden/configs")


def _safe_error(e: Exception, context: str) -> str:
    """Return a sanitized error message, log full details server-side."""
    logger.error("%s: %s", context, e, exc_info=True)
    msg = str(e).lower()
    if "auth" in msg or "password" in msg or "401" in msg or "403" in msg:
        return "Authentication failed"
    if "timeout" in msg or "timed out" in msg:
        return "Request timed out"
    if "ssl" in msg or "certificate" in msg:
        return "SSL/certificate error"
    if "resolve" in msg or "name or service" in msg or "getaddrinfo" in msg:
        return "Cannot resolve host"
    if "connection" in msg:
        return "Connection failed"
    return "Request failed"


class VaultwardenConfigCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    url: str = Field(..., min_length=1)
    email: str
    password: str


class VaultwardenConfigUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    url: str | None = None
    email: str | None = None
    password: str | None = None


class AssignRequest(BaseModel):
    connection_id: int
    credential_id: str


class BulkAssignRequest(BaseModel):
    assignments: list[AssignRequest]


def _require_user(request: Request):
    return getattr(request.state, "current_user", None)


def _config_to_dict(cfg: VaultwardenConfig) -> dict:
    return {
        "id": cfg.id,
        "name": cfg.name,
        "url": cfg.url,
        "has_email": bool(cfg.encrypted_email),
        "last_sync_at": str(cfg.last_sync_at) if cfg.last_sync_at else None,
        "created_at": str(cfg.created_at) if cfg.created_at else None,
    }


@router.get("")
async def list_configs(request: Request, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    result = await db.execute(
        select(VaultwardenConfig).where(VaultwardenConfig.user_id == user.id)
    )
    return {"configs": [_config_to_dict(c) for c in result.scalars().all()]}


@router.post("")
async def create_config(request: Request, body: VaultwardenConfigCreate,
                        db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = VaultwardenConfig(
        user_id=user.id,
        name=body.name,
        url=body.url.rstrip("/"),
        encrypted_email=encrypt_value(body.email),
        encrypted_password=encrypt_value(body.password),
    )
    db.add(cfg)
    await db.commit()
    return _config_to_dict(cfg)


@router.put("/{config_id}")
async def update_config(request: Request, config_id: int, body: VaultwardenConfigUpdate,
                        db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(VaultwardenConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    if body.name is not None:
        cfg.name = body.name
    if body.url is not None:
        cfg.url = body.url.rstrip("/")
    if body.email is not None:
        cfg.encrypted_email = encrypt_value(body.email) if body.email else None
    if body.password is not None:
        cfg.encrypted_password = encrypt_value(body.password) if body.password else None

    await db.commit()
    return _config_to_dict(cfg)


@router.delete("/{config_id}")
async def delete_config(request: Request, config_id: int, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(VaultwardenConfig, config_id)
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

    cfg = await db.get(VaultwardenConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    from services.vaultwarden import client_from_config
    client = client_from_config(cfg)
    try:
        result = await client.test_connection()
        return result
    except Exception as e:
        return JSONResponse({"ok": False, "error": _safe_error(e, "vaultwarden")}, status_code=200)


@router.get("/{config_id}/preview")
async def preview_credentials(request: Request, config_id: int,
                              db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(VaultwardenConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    from services.vaultwarden import preview_credentials as _preview
    try:
        creds = await _preview(cfg)
        return {"credentials": creds, "count": len(creds)}
    except Exception as e:
        return JSONResponse({"error": _safe_error(e, "vaultwarden")}, status_code=400)


@router.get("/{config_id}/auto-match")
async def auto_match(request: Request, config_id: int, db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(VaultwardenConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    from services.vaultwarden import auto_match_credentials
    try:
        matches = await auto_match_credentials(db, cfg, user.id)
        return {"matches": matches, "count": len(matches)}
    except Exception as e:
        return JSONResponse({"error": _safe_error(e, "vaultwarden")}, status_code=400)


@router.post("/{config_id}/assign")
async def assign_credential(request: Request, config_id: int, body: AssignRequest,
                            db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(VaultwardenConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    from services.vaultwarden import assign_credential as _assign
    try:
        result = await _assign(db, cfg, user.id, body.connection_id, body.credential_id)
        return result
    except Exception as e:
        return JSONResponse({"error": _safe_error(e, "vaultwarden")}, status_code=400)


@router.post("/{config_id}/bulk-assign")
async def bulk_assign_credentials(request: Request, config_id: int, body: BulkAssignRequest,
                                  db: AsyncSession = Depends(get_db)):
    user = _require_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cfg = await db.get(VaultwardenConfig, config_id)
    if not cfg or (cfg.user_id != user.id and user.role != "admin"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    from services.vaultwarden import bulk_assign
    try:
        result = await bulk_assign(db, cfg, user.id, [a.model_dump() for a in body.assignments])
        return result
    except Exception as e:
        return JSONResponse({"error": _safe_error(e, "vaultwarden")}, status_code=400)
