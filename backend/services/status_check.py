"""TCP port check for connection online status."""

import asyncio
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.connection import SSHConnection

logger = logging.getLogger(__name__)


async def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """TCP connect check — returns True if port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def check_connection(db: AsyncSession, connection_id: int) -> bool:
    """Check a single connection and update status."""
    conn = await db.get(SSHConnection, connection_id)
    if not conn:
        return False
    online = await check_port(conn.host, conn.port or 22)
    conn.is_online = online
    conn.last_check_at = datetime.utcnow()
    await db.commit()
    return online


async def check_all_connections(db: AsyncSession, user_id: int) -> dict:
    """Check all connections for a user. Runs checks concurrently."""
    result = await db.execute(
        select(SSHConnection).where(SSHConnection.user_id == user_id)
    )
    connections = result.scalars().all()

    if not connections:
        return {"online": 0, "offline": 0, "total": 0}

    # Run checks concurrently (max 20 at a time)
    sem = asyncio.Semaphore(20)

    async def _check(conn):
        async with sem:
            return conn.id, await check_port(conn.host, conn.port or 22)

    tasks = [_check(conn) for conn in connections]
    results = await asyncio.gather(*tasks)

    online = offline = 0
    now = datetime.utcnow()
    for conn_id, is_online in results:
        conn = await db.get(SSHConnection, conn_id)
        if conn:
            conn.is_online = is_online
            conn.last_check_at = now
            if is_online:
                online += 1
            else:
                offline += 1

    await db.commit()
    logger.info("Status check: %d online, %d offline of %d", online, offline, len(connections))
    return {"online": online, "offline": offline, "total": len(connections)}
