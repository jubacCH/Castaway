"""Catchall WebSocket route for subdomain proxy."""

import logging
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket
from sqlalchemy import select

from models.base import AsyncSessionLocal
from models.connection import SSHConnection
from models.setting import Setting
from models.user import Session, hash_token

logger = logging.getLogger(__name__)
router = APIRouter()


@router.websocket("/{full_path:path}")
async def subdomain_websocket(websocket: WebSocket, full_path: str):
    """WebSocket catchall for subdomain proxy. Only handles when Host matches proxy_domain."""
    host = websocket.headers.get("host", "").lower().split(":")[0]

    async with AsyncSessionLocal() as db:
        pd_row = await db.get(Setting, "proxy_domain")
        proxy_domain = (pd_row.value if pd_row else "").strip().lower()

    if not proxy_domain:
        await websocket.close(code=4404)
        return

    suffix = "." + proxy_domain.lstrip(".")
    if not host.endswith(suffix):
        # Not a subdomain request — this is probably /ws/ssh which has its own handler.
        # We shouldn't be here. Close.
        await websocket.close(code=4404)
        return

    slug = host[:-len(suffix)].split(".")[-1]

    # Authenticate
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
        conn = (await db.execute(
            select(SSHConnection).where(SSHConnection.subdomain == slug)
        )).scalar_one_or_none()
        if not conn or conn.user_id != session.user_id or not conn.web_url:
            await websocket.close(code=4404)
            return

    # Build target WS URL
    parsed = urlparse(conn.web_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    ws_path = "/" + full_path.lstrip("/") if full_path else "/"
    query = "?" + websocket.url.query if websocket.url.query else ""
    target_ws = f"{scheme}://{parsed.netloc}{ws_path}{query}"

    # Forward subprotocol (required for noVNC binary / Proxmox xtermjs)
    proto_header = websocket.headers.get("sec-websocket-protocol", "")
    requested_subprotocols = [p.strip() for p in proto_header.split(",") if p.strip()]

    # Forward cookies (Proxmox validates session via PVEAuthCookie)
    raw_cookies = websocket.headers.get("cookie", "")
    filtered_cookies = "; ".join(
        c for c in raw_cookies.split("; ")
        if not c.strip().startswith(("castaway_session=", "cw_csrf="))
    )

    extra_headers = {"Origin": f"{parsed.scheme}://{parsed.netloc}"}
    if filtered_cookies:
        extra_headers["Cookie"] = filtered_cookies

    logger.info("Subdomain WS proxy: %s -> %s (subprotocols=%s)", slug, target_ws, requested_subprotocols)

    try:
        import asyncio
        import ssl as ssl_mod
        import websockets

        ssl_ctx = ssl_mod._create_unverified_context() if scheme == "wss" else None

        async with websockets.connect(
            target_ws,
            ssl=ssl_ctx,
            max_size=None,
            subprotocols=requested_subprotocols or None,
            extra_headers=extra_headers,
            open_timeout=10,
        ) as upstream:
            # Accept client with the subprotocol upstream actually negotiated
            negotiated = upstream.subprotocol
            await websocket.accept(subprotocol=negotiated)
            logger.info("Subdomain WS connected: %s negotiated subprotocol=%s", target_ws, negotiated)

            async def c2u():
                try:
                    while True:
                        msg = await websocket.receive()
                        if msg.get("type") == "websocket.disconnect":
                            break
                        if "bytes" in msg and msg["bytes"] is not None:
                            await upstream.send(msg["bytes"])
                        elif "text" in msg and msg["text"] is not None:
                            await upstream.send(msg["text"])
                except Exception:
                    pass

            async def u2c():
                try:
                    async for msg in upstream:
                        if isinstance(msg, bytes):
                            await websocket.send_bytes(msg)
                        else:
                            await websocket.send_text(msg)
                except Exception:
                    pass

            await asyncio.gather(c2u(), u2c())

    except Exception as e:
        logger.error("Subdomain WS proxy error for %s -> %s: %s", slug, target_ws, e, exc_info=True)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
        return
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
