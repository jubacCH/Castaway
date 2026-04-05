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
    path = "/" + full_path
    query = "?" + websocket.url.query if websocket.url.query else ""
    target_ws = f"{scheme}://{parsed.netloc}{path}{query}"

    await websocket.accept(subprotocol=websocket.headers.get("sec-websocket-protocol"))

    try:
        import asyncio
        import ssl as ssl_mod
        import websockets

        ssl_ctx = ssl_mod._create_unverified_context() if scheme == "wss" else None
        subproto = websocket.headers.get("sec-websocket-protocol")
        subprotocols = [subproto] if subproto else None

        async with websockets.connect(
            target_ws, ssl=ssl_ctx, max_size=None,
            subprotocols=subprotocols,
            extra_headers={"Origin": f"{parsed.scheme}://{parsed.netloc}"},
        ) as upstream:
            async def c2u():
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

            async def u2c():
                try:
                    async for msg in upstream:
                        if isinstance(msg, str):
                            await websocket.send_text(msg)
                        else:
                            await websocket.send_bytes(msg)
                except Exception:
                    pass

            await asyncio.gather(c2u(), u2c())
    except Exception as e:
        logger.error("Subdomain WS proxy error: %s", e)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
