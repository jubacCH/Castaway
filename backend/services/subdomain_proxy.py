"""Subdomain-based reverse proxy middleware.

Matches requests where Host header is <slug>.<proxy_domain> and forwards
them to the corresponding connection's web_url. Target apps see their
own root "/" so no path-rewriting is needed — only cookies, redirects,
and WebSockets need light handling.
"""

import logging
from datetime import datetime
from urllib.parse import urlparse

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from models.base import AsyncSessionLocal
from models.connection import SSHConnection
from models.setting import Setting
from models.user import Session, User, hash_token

logger = logging.getLogger(__name__)

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "host", "content-length", "accept-encoding",
}
_HOP_BY_HOP_RESPONSE = {
    "connection", "keep-alive", "transfer-encoding", "content-encoding",
    "content-length", "strict-transport-security", "x-frame-options",
    "content-security-policy", "content-security-policy-report-only",
}


async def _get_proxy_domain() -> str:
    async with AsyncSessionLocal() as db:
        row = await db.get(Setting, "proxy_domain")
        return (row.value if row else "").strip().lower()


def _extract_subdomain(host: str, proxy_domain: str) -> str | None:
    """If host ends with .{proxy_domain}, return the subdomain slug."""
    if not proxy_domain or not host:
        return None
    host = host.lower().split(":")[0]  # strip port
    suffix = "." + proxy_domain.lstrip(".")
    if host == proxy_domain or not host.endswith(suffix):
        return None
    slug = host[: -len(suffix)]
    # Take only the first segment (e.g. "proxmox" from "proxmox.apps.b8n.ch")
    return slug.split(".")[-1] if "." in slug else slug


async def _resolve_connection(subdomain: str) -> SSHConnection | None:
    async with AsyncSessionLocal() as db:
        return (await db.execute(
            select(SSHConnection).where(SSHConnection.subdomain == subdomain)
        )).scalar_one_or_none()


async def _authenticate(request: Request) -> User | None:
    """Authenticate via session cookie (same as main app)."""
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


def _rewrite_set_cookie(cookie: str) -> str:
    """Strip Domain= from cookies (let them scope to current subdomain)."""
    import re
    return re.sub(r"\s*Domain=[^;]+;?", "", cookie, flags=re.IGNORECASE)


async def handle_subdomain_request(request: Request) -> Response | None:
    """If the request matches a subdomain proxy, handle it. Otherwise return None."""
    host = request.headers.get("host", "")
    proxy_domain = await _get_proxy_domain()
    if not proxy_domain:
        return None

    subdomain = _extract_subdomain(host, proxy_domain)
    if not subdomain:
        return None

    # Authenticate
    user = await _authenticate(request)
    if not user:
        # Redirect to main login
        from fastapi.responses import RedirectResponse
        # Figure out castaway main URL — use HTTPS + parent domain's castaway subdomain?
        # Simplest: redirect to /login on same domain (will fail if no main app there).
        # Better: configurable login_url setting
        async with AsyncSessionLocal() as db:
            login_row = await db.get(Setting, "login_url")
            login_url = login_row.value if login_row and login_row.value else "/login"
        return RedirectResponse(url=login_url, status_code=302)

    conn = await _resolve_connection(subdomain)
    if not conn:
        return JSONResponse({"error": f"No connection found for subdomain '{subdomain}'"}, status_code=404)
    if conn.user_id != user.id and user.role != "admin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    if not conn.web_url:
        return JSONResponse({"error": "Connection has no web_url"}, status_code=400)

    # Build target URL
    target_parsed = urlparse(conn.web_url.rstrip("/"))
    path = request.url.path
    query = request.url.query
    target_url = f"{target_parsed.scheme}://{target_parsed.netloc}{path}"
    if query:
        target_url += "?" + query

    # Forward headers
    headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in _HOP_BY_HOP:
            continue
        if lk == "cookie":
            # Filter out castaway cookies
            filtered = "; ".join(
                c for c in v.split("; ")
                if not c.startswith(("castaway_session=", "cw_csrf="))
            )
            if filtered:
                headers[k] = filtered
            continue
        if lk in ("referer", "origin"):
            headers[k] = f"{target_parsed.scheme}://{target_parsed.netloc}"
            continue
        if lk == "host":
            continue
        headers[k] = v
    # Set Host header to target
    headers["host"] = target_parsed.netloc

    # Body (for POST/PUT/PATCH)
    body = await request.body()

    try:
        async with httpx.AsyncClient(verify=False, timeout=30, follow_redirects=False) as client:
            upstream = await client.request(
                method=request.method, url=target_url,
                headers=headers, content=body,
            )
    except httpx.ConnectError:
        return JSONResponse({"error": "Cannot connect to target"}, status_code=502)
    except httpx.TimeoutException:
        return JSONResponse({"error": "Target timed out"}, status_code=504)
    except Exception as e:
        logger.error("Subdomain proxy error for %s: %s", subdomain, e)
        return JSONResponse({"error": "Proxy error"}, status_code=502)

    # Build response headers
    response_headers = {}
    for k, v in upstream.headers.items():
        lk = k.lower()
        if lk in _HOP_BY_HOP_RESPONSE:
            continue
        if lk == "set-cookie":
            v = _rewrite_set_cookie(v)
        # Don't rewrite Location: Castaway subdomain == target root, so paths stay the same
        response_headers[k] = v

    # Rewrite body: replace target hostname with subdomain hostname
    # (apps embed absolute URLs like "https://target.example.com/" in HTML/JS/JSON)
    content = upstream.content
    content_type = upstream.headers.get("content-type", "").lower()
    if any(t in content_type for t in ("text/html", "text/css", "application/json", "javascript", "text/javascript")):
        try:
            text = content.decode("utf-8")
            target_host_with_port = target_parsed.netloc  # e.g. auth.b8n.ch:9443
            target_host = target_parsed.hostname  # e.g. auth.b8n.ch
            subdomain_host = host.split(":")[0]  # e.g. auth.apps.b8n.ch
            # Replace full URLs first (with scheme)
            text = text.replace(f"https://{target_host_with_port}", f"https://{subdomain_host}")
            text = text.replace(f"http://{target_host_with_port}", f"https://{subdomain_host}")
            if target_host != target_host_with_port:
                text = text.replace(f"https://{target_host}", f"https://{subdomain_host}")
                text = text.replace(f"http://{target_host}", f"https://{subdomain_host}")
            content = text.encode("utf-8")
            response_headers.pop("content-length", None)
        except UnicodeDecodeError:
            pass  # binary content, leave alone

    return Response(
        content=content,
        status_code=upstream.status_code,
        headers=response_headers,
    )
