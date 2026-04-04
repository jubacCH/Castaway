"""HTTP reverse proxy for connection web UIs.

Routes /web/{conn_id}/<path> -> connection.web_url/<path>
Handles request/response forwarding, cookie path rewriting, Location rewriting,
and WebSocket upgrades.
"""

import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response, StreamingResponse, JSONResponse
from sqlalchemy import select

from models.base import AsyncSessionLocal
from models.connection import SSHConnection
from models.user import Session, User, hash_token

logger = logging.getLogger(__name__)
router = APIRouter()

# Headers that should not be forwarded to the target
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "host", "content-length", "accept-encoding",
}

# Headers that should not be forwarded back to the client
_HOP_BY_HOP_RESPONSE = {
    "connection", "keep-alive", "transfer-encoding", "content-encoding",
    "content-length", "strict-transport-security", "x-frame-options",
    "content-security-policy",
}


async def _authenticate(request: Request) -> User | None:
    """Authenticate via session cookie."""
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


async def _load_connection(conn_id: int, user_id: int) -> SSHConnection | None:
    async with AsyncSessionLocal() as db:
        conn = await db.get(SSHConnection, conn_id)
        if not conn or (conn.user_id != user_id):
            return None
        return conn


def _build_target_url(web_url: str, path: str, query: str) -> str:
    """Build target URL from connection's web_url + requested path."""
    base = web_url.rstrip("/")
    # path may start with / or be empty
    if path and not path.startswith("/"):
        path = "/" + path
    target = f"{base}{path}"
    if query:
        target += "?" + query
    return target


def _rewrite_location(location: str, conn_id: int, target_base: str) -> str:
    """Rewrite Location header to route back through proxy."""
    if not location:
        return location
    # If absolute URL pointing to target, strip base and prepend proxy path
    target_parsed = urlparse(target_base)
    loc_parsed = urlparse(location)
    if loc_parsed.netloc and loc_parsed.netloc == target_parsed.netloc:
        # Absolute URL to same host — rewrite
        new_path = loc_parsed.path + ("?" + loc_parsed.query if loc_parsed.query else "")
        return f"/web/{conn_id}{new_path}"
    elif not loc_parsed.netloc:
        # Relative or path-only URL
        if location.startswith("/"):
            return f"/web/{conn_id}{location}"
    return location


def _rewrite_set_cookie(set_cookie: str, conn_id: int) -> str:
    """Rewrite cookie path so it scopes to /web/{conn_id}/."""
    # Replace Path=/... with Path=/web/{conn_id}/...
    def _replace_path(m):
        old_path = m.group(1).strip()
        if old_path.startswith("/"):
            return f"Path=/web/{conn_id}{old_path}"
        return f"Path=/web/{conn_id}/{old_path}"
    rewritten = re.sub(r"Path=([^;]+)", _replace_path, set_cookie, flags=re.IGNORECASE)
    if "Path=" not in rewritten:
        rewritten += f"; Path=/web/{conn_id}/"
    # Remove Domain= directive (cookie should be scoped to castaway host)
    rewritten = re.sub(r"\s*Domain=[^;]+;?", "", rewritten, flags=re.IGNORECASE)
    # Remove Secure if we're not on HTTPS? Actually keep it — NPM terminates HTTPS
    return rewritten


@router.api_route("/web/{conn_id}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_request(conn_id: int, path: str, request: Request):
    """Forward HTTP request to the connection's web_url."""
    user = await _authenticate(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = await _load_connection(conn_id, user.id)
    if not conn:
        return JSONResponse({"error": "Not found"}, status_code=404)
    if not conn.web_url:
        return JSONResponse({"error": "No web URL configured"}, status_code=400)

    target_url = _build_target_url(conn.web_url, path, request.url.query)

    # Build forwarded headers
    headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in _HOP_BY_HOP:
            continue
        if lk == "cookie":
            # Only forward non-castaway cookies
            filtered = "; ".join(
                c for c in v.split("; ")
                if not c.startswith(("castaway_session=", "cw_csrf="))
            )
            if filtered:
                headers[k] = filtered
            continue
        if lk in ("referer", "origin"):
            # Rewrite referer/origin to target
            parsed = urlparse(conn.web_url)
            headers[k] = f"{parsed.scheme}://{parsed.netloc}"
            continue
        headers[k] = v

    # Read body (for POST/PUT/PATCH)
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
        logger.error("Proxy error for conn %d %s: %s", conn_id, target_url, e)
        return JSONResponse({"error": "Proxy error"}, status_code=502)

    # Build response headers
    response_headers = {}
    for k, v in upstream.headers.items():
        lk = k.lower()
        if lk in _HOP_BY_HOP_RESPONSE:
            continue
        if lk == "location":
            v = _rewrite_location(v, conn_id, conn.web_url)
        if lk == "set-cookie":
            v = _rewrite_set_cookie(v, conn_id)
        response_headers[k] = v

    # Rewrite HTML/JS/CSS responses to inject /web/{conn_id} prefix for absolute paths
    content = upstream.content
    content_type = upstream.headers.get("content-type", "").lower()
    is_html = "text/html" in content_type
    is_css = "text/css" in content_type
    is_js = "javascript" in content_type
    if is_html or is_css or is_js:
        prefix = f"/web/{conn_id}"
        text = content.decode("utf-8", errors="replace")

        if is_html:
            # HTML attributes with absolute paths
            text = re.sub(r'(src|href|action|poster|data-url)="(/(?!/)[^"]*)"', rf'\1="{prefix}\2"', text)
            text = re.sub(r"(src|href|action|poster|data-url)='(/(?!/)[^']*)'", rf"\1='{prefix}\2'", text)

        if is_html or is_css:
            # CSS url() references
            text = re.sub(r'url\(([\'"]?)(/(?!/)[^\'")]*)\1\)', rf'url(\1{prefix}\2\1)', text)

        if is_js or is_html:
            # Rewrite ALL absolute path string literals ("/..." but not "//...")
            # Skip if already prefixed with /web/
            def _rewrite_js_path(m):
                quote = m.group(1)
                path = m.group(2)
                if path.startswith("/web/"):
                    return m.group(0)
                return f'{quote}{prefix}{path}{quote}'
            text = re.sub(r'(["\'])(/(?!/)[^"\'\s<>(){}]*?)\1', _rewrite_js_path, text)

        content = text.encode("utf-8")
        response_headers.pop("content-length", None)

    return Response(
        content=content,
        status_code=upstream.status_code,
        headers=response_headers,
    )


@router.websocket("/web/{conn_id}/{path:path}")
async def proxy_websocket(websocket: WebSocket, conn_id: int, path: str):
    """Forward WebSocket traffic to the target."""
    # Authenticate from cookie
    from datetime import datetime
    token = websocket.cookies.get("castaway_session")
    if not token:
        await websocket.close(code=4401)
        return

    async with AsyncSessionLocal() as db:
        session = (await db.execute(
            select(Session).where(Session.token == hash_token(token),
                                  Session.expires_at > datetime.utcnow())
        )).scalar_one_or_none()
        if not session:
            await websocket.close(code=4401)
            return
        user_id = session.user_id

    conn = await _load_connection(conn_id, user_id)
    if not conn or not conn.web_url:
        await websocket.close(code=4404)
        return

    # Build target WS URL (ws:// or wss://)
    parsed = urlparse(conn.web_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    query = "?" + websocket.url.query if websocket.url.query else ""
    target_ws = f"{scheme}://{parsed.netloc}/{path}{query}"

    await websocket.accept()

    # Bridge via websockets library
    try:
        import websockets
        import ssl as ssl_mod
        ssl_ctx = ssl_mod._create_unverified_context() if scheme == "wss" else None

        async with websockets.connect(target_ws, ssl=ssl_ctx, max_size=None) as upstream:
            import asyncio

            async def client_to_upstream():
                try:
                    while True:
                        msg = await websocket.receive()
                        if msg.get("type") == "websocket.disconnect":
                            break
                        if "text" in msg and msg["text"] is not None:
                            await upstream.send(msg["text"])
                        elif "bytes" in msg and msg["bytes"] is not None:
                            await upstream.send(msg["bytes"])
                except Exception:
                    pass

            async def upstream_to_client():
                try:
                    async for msg in upstream:
                        if isinstance(msg, str):
                            await websocket.send_text(msg)
                        else:
                            await websocket.send_bytes(msg)
                except Exception:
                    pass

            await asyncio.gather(client_to_upstream(), upstream_to_client())
    except Exception as e:
        logger.error("WebSocket proxy error: %s", e)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
