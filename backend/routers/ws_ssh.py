"""WebSocket SSH proxy — bridges xterm.js to asyncssh."""

import asyncio
import json
import logging
from datetime import datetime

import asyncssh
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from models.base import AsyncSessionLocal, decrypt_value
from models.connection import SSHConnection
from models.session_log import SessionLog
from models.user import Session, User, hash_token

logger = logging.getLogger(__name__)
router = APIRouter()


async def _authenticate_ws(websocket: WebSocket):
    """Authenticate WebSocket from session cookie. Returns User or None."""
    token = websocket.cookies.get("castaway_session")
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


def _client_ip(websocket: WebSocket) -> str:
    """Extract client IP from WebSocket."""
    if websocket.client:
        return websocket.client.host
    return ""


@router.websocket("/ws/ssh/{conn_id}")
async def ws_ssh(websocket: WebSocket, conn_id: int):
    user = await _authenticate_ws(websocket)
    if not user:
        await websocket.close(code=4401, reason="Unauthorized")
        return

    await websocket.accept()
    session_log_id = None
    bytes_sent = 0
    bytes_recv = 0
    started_at = datetime.utcnow()

    # Load connection
    async with AsyncSessionLocal() as db:
        conn = await db.get(SSHConnection, conn_id)
        if not conn or (conn.user_id != user.id and user.role != "admin"):
            await websocket.send_text(json.dumps({"type": "error", "message": "Connection not found"}))
            await websocket.close()
            return

        if conn.protocol != "ssh":
            await websocket.send_text(json.dumps({"type": "error", "message": "Not an SSH connection"}))
            await websocket.close()
            return

        # Create session log entry
        log_entry = SessionLog(
            user_id=user.id,
            connection_id=conn.id,
            started_at=started_at,
            ip_address=_client_ip(websocket),
        )
        db.add(log_entry)
        await db.commit()
        session_log_id = log_entry.id

        # Build SSH connection kwargs
        kwargs = {
            "host": conn.host,
            "port": conn.port,
            "username": conn.username or "root",
            "known_hosts": None,
        }
        try:
            if conn.auth_method == "password" and conn.encrypted_password:
                kwargs["password"] = decrypt_value(conn.encrypted_password)
            elif conn.auth_method == "key" and conn.encrypted_key:
                key_data = decrypt_value(conn.encrypted_key)
                passphrase = decrypt_value(conn.key_passphrase) if conn.key_passphrase else None
                kwargs["client_keys"] = [asyncssh.import_private_key(key_data, passphrase)]
        except Exception as e:
            await websocket.send_text(json.dumps({"type": "error", "message": f"Credential error: {e}"}))
            await websocket.close()
            await _finalize_log(session_log_id, started_at, bytes_sent, bytes_recv)
            return

    # Connect to SSH server
    try:
        ssh_conn = await asyncio.wait_for(asyncssh.connect(**kwargs), timeout=10)
    except asyncio.TimeoutError:
        await websocket.send_text(json.dumps({"type": "error", "message": "Connection timeout"}))
        await websocket.close()
        await _finalize_log(session_log_id, started_at, bytes_sent, bytes_recv)
        return
    except Exception as e:
        await websocket.send_text(json.dumps({"type": "error", "message": str(e)}))
        await websocket.close()
        await _finalize_log(session_log_id, started_at, bytes_sent, bytes_recv)
        return

    try:
        process = await ssh_conn.create_process(
            term_type="xterm-256color",
            term_size=(80, 24),
        )
        await websocket.send_text(json.dumps({"type": "connected"}))

        logger.info("SSH session opened: user=%s conn=%s host=%s log=%s",
                     user.username, conn_id, conn.host, session_log_id)

        async def read_ssh():
            """Read from SSH stdout and send to WebSocket."""
            nonlocal bytes_recv
            try:
                while not process.stdout.at_eof():
                    data = await process.stdout.read(4096)
                    if data:
                        bytes_recv += len(data)
                        await websocket.send_text(data)
            except (asyncssh.Error, ConnectionError):
                pass
            except Exception:
                pass

        read_task = asyncio.create_task(read_ssh())

        try:
            while True:
                data = await websocket.receive_text()
                # Check for control messages
                if data.startswith("{"):
                    try:
                        msg = json.loads(data)
                        if msg.get("type") == "resize":
                            cols = msg.get("cols", 80)
                            rows = msg.get("rows", 24)
                            process.channel.change_terminal_size(cols, rows)
                            continue
                    except json.JSONDecodeError:
                        pass
                # Regular input
                bytes_sent += len(data)
                process.stdin.write(data)
        except WebSocketDisconnect:
            pass
        finally:
            read_task.cancel()

    except Exception as e:
        logger.error("SSH session error: %s", e)
        try:
            await websocket.send_text(json.dumps({"type": "error", "message": str(e)}))
        except Exception:
            pass
    finally:
        ssh_conn.close()
        await _finalize_log(session_log_id, started_at, bytes_sent, bytes_recv)
        logger.info("SSH session closed: user=%s conn=%s log=%s", user.username, conn_id, session_log_id)


async def _finalize_log(log_id: int | None, started_at: datetime,
                        bytes_sent: int, bytes_recv: int):
    """Update session log with end time and stats."""
    if not log_id:
        return
    ended = datetime.utcnow()
    duration = int((ended - started_at).total_seconds())
    async with AsyncSessionLocal() as db:
        log_entry = await db.get(SessionLog, log_id)
        if log_entry:
            log_entry.ended_at = ended
            log_entry.duration_sec = duration
            log_entry.bytes_sent = bytes_sent
            log_entry.bytes_recv = bytes_recv
            await db.commit()
