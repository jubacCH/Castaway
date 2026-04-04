"""Background scheduler for periodic tasks (screenshot refresh)."""

import asyncio
import logging

from models.base import AsyncSessionLocal
from models.setting import Setting
from models.user import User
from sqlalchemy import select

logger = logging.getLogger(__name__)

_task: asyncio.Task | None = None


async def get_setting(key: str, default: str = "") -> str:
    async with AsyncSessionLocal() as db:
        row = await db.get(Setting, key)
        return row.value if row else default


async def set_setting(key: str, value: str):
    async with AsyncSessionLocal() as db:
        row = await db.get(Setting, key)
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))
        await db.commit()


async def _screenshot_loop():
    """Periodically refresh screenshots based on configured interval."""
    # Wait 30s after startup before first run
    await asyncio.sleep(30)

    while True:
        try:
            interval_str = await get_setting("screenshot_interval_min", "120")
            interval_min = int(interval_str)
            if interval_min <= 0:
                # Disabled
                await asyncio.sleep(60)
                continue

            logger.info("Screenshot refresh starting (interval=%dmin)", interval_min)

            from services.screenshots import refresh_all_screenshots

            # Refresh for all users
            async with AsyncSessionLocal() as db:
                users = (await db.execute(select(User))).scalars().all()

            for user in users:
                async with AsyncSessionLocal() as db:
                    result = await refresh_all_screenshots(db, user.id)
                    logger.info("Screenshots for user %s: captured=%d failed=%d",
                                user.username, result["captured"], result["failed"])

        except Exception as e:
            logger.error("Screenshot scheduler error: %s", e)

        # Sleep for the configured interval
        try:
            interval_str = await get_setting("screenshot_interval_min", "120")
            sleep_seconds = max(int(interval_str), 1) * 60
        except (ValueError, Exception):
            sleep_seconds = 7200
        await asyncio.sleep(sleep_seconds)


def start_scheduler():
    global _task
    _task = asyncio.create_task(_screenshot_loop())
    logger.info("Screenshot scheduler started")


def stop_scheduler():
    global _task
    if _task:
        _task.cancel()
        _task = None
