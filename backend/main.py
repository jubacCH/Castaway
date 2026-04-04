"""Castaway — SSH Session Manager."""

import os
import secrets
from contextlib import asynccontextmanager
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from models import init_db
from models.base import AsyncSessionLocal
from models.user import Session, User, hash_token


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run Alembic migrations on startup (in a thread to avoid async conflicts)
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    def _run_migrations():
        from alembic.config import Config
        from alembic import command
        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(ThreadPoolExecutor(1), _run_migrations)

    from services.scheduler import start_scheduler, stop_scheduler
    start_scheduler()
    yield
    stop_scheduler()


_debug = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
app = FastAPI(
    title="Castaway",
    version="0.1.0",
    description="Self-hosted SSH session manager",
    docs_url="/api/docs" if _debug else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if _debug else None,
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/health")
async def health():
    from sqlalchemy import text as sa_text
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(sa_text("SELECT 1"))
        return {"status": "ok", "db": "connected"}
    except (OSError, SQLAlchemyError):
        return {"status": "error", "db": "connection failed"}


async def _get_current_user(request: Request):
    """Resolve user from session cookie or API key."""
    from datetime import datetime
    import hashlib

    # Try API key first (X-API-Key header)
    api_key = request.headers.get("X-API-Key")
    if api_key:
        from models.api_key import ApiKey
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        async with AsyncSessionLocal() as db:
            ak = (await db.execute(
                select(ApiKey).where(ApiKey.key_hash == key_hash)
            )).scalar_one_or_none()
            if ak:
                ak.last_used_at = datetime.utcnow()
                await db.commit()
                return (await db.execute(
                    select(User).where(User.id == ak.user_id)
                )).scalar_one_or_none()
        return None

    # Fall back to session cookie
    token = request.cookies.get("castaway_session")
    if not token:
        return None
    async with AsyncSessionLocal() as db:
        session = (await db.execute(
            select(Session).where(Session.token == hash_token(token),
                                  Session.expires_at > datetime.utcnow())
        )).scalar_one_or_none()
        if not session:
            return None
        return (await db.execute(
            select(User).where(User.id == session.user_id)
        )).scalar_one_or_none()


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    _skip = (
        request.url.path.startswith("/static/")
        or request.url.path == "/health"
        or request.url.path.startswith("/api/docs")
        or request.url.path.startswith("/api/openapi")
    )
    if _skip:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    is_api = request.url.path.startswith("/api/")

    # CSRF for state-changing requests
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        content_type = request.headers.get("content-type", "")
        # Skip CSRF for:
        # - Auth endpoints (no cookie yet)
        # - JSON API requests with custom header (Same-Origin Policy protects these)
        # - Multipart uploads with CSRF header present
        skip_csrf = (
            request.url.path.startswith("/api/auth/")
            or (is_api and "json" in content_type)
            or (is_api and request.headers.get("x-csrf-token"))
        )
        if not skip_csrf:
            from csrf import validate_csrf, csrf_error_response
            form_data = None
            if "form" in content_type:
                body = await request.body()
                parsed = parse_qs(body.decode("utf-8", errors="replace"))
                form_data = {k: v[0] for k, v in parsed.items()}
            if not validate_csrf(request, form_data):
                return csrf_error_response(request)

    # Auth — resolve current user
    user = await _get_current_user(request)
    request.state.current_user = user

    # Public pages (login, register)
    public_paths = ("/login", "/register", "/api/auth/login", "/api/auth/register", "/favicon.ico")
    if not user and not any(request.url.path == p for p in public_paths):
        if is_api:
            from fastapi.responses import JSONResponse
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

    # Check first-user registration flow
    if not user and request.url.path == "/register":
        from sqlalchemy import func
        async with AsyncSessionLocal() as db:
            user_count = (await db.execute(select(func.count()).select_from(User))).scalar() or 0
        if user_count > 0:
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url="/login", status_code=302)

    # CSRF token generation
    from csrf import generate_csrf_token, set_csrf_cookie
    request.state.csrf_token = generate_csrf_token(request)

    # CSP nonce
    request.state.csp_nonce = secrets.token_urlsafe(16)

    response = await call_next(request)

    # Set CSRF cookie
    set_csrf_cookie(request, response)

    # Security headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    nonce = getattr(request.state, "csp_nonce", "")
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'unsafe-inline' 'nonce-{nonce}' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "img-src 'self' data: blob: https://lh3.googleusercontent.com; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self' data: https://cdn.jsdelivr.net https://fonts.gstatic.com; "
        "frame-ancestors 'none'"
    )

    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    return response


# ── Routers ──────────────────────────────────────────────────────────────────
from routers import auth, connections, folders, tags, pages, ws_ssh
from routers import phpipam as phpipam_router
from routers import vaultwarden as vaultwarden_router
from routers import sessions as sessions_router
from routers import users as users_router
from routers import rdp, import_export, api_keys
from routers import mfa as mfa_router
from routers import settings as settings_router

app.include_router(auth.router)
app.include_router(connections.router)
app.include_router(folders.router)
app.include_router(tags.router)
app.include_router(phpipam_router.router)
app.include_router(vaultwarden_router.router)
app.include_router(sessions_router.router)
app.include_router(users_router.router)
app.include_router(rdp.router)
app.include_router(import_export.router)
app.include_router(settings_router.router)
app.include_router(api_keys.router)
app.include_router(mfa_router.router)
app.include_router(pages.router)
app.include_router(ws_ssh.router)
