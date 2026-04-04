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
    await init_db()
    yield


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
    """Resolve user from session cookie."""
    from datetime import datetime
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

    # CSRF for state-changing requests (skip for API key auth)
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # Skip CSRF for auth endpoints (login/register send JSON, no cookie yet)
        skip_csrf = request.url.path.startswith("/api/auth/")
        if not skip_csrf:
            from csrf import validate_csrf, csrf_error_response
            content_type = request.headers.get("content-type", "")
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
        f"script-src 'self' 'nonce-{nonce}' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self' data: https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'"
    )

    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


# ── Routers ──────────────────────────────────────────────────────────────────
from routers import auth, connections, folders, tags, pages, ws_ssh
from routers import phpipam as phpipam_router
from routers import vaultwarden as vaultwarden_router
from routers import sessions as sessions_router
from routers import users as users_router
from routers import rdp, import_export

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
app.include_router(pages.router)
app.include_router(ws_ssh.router)
