"""Screenshot service — captures web interface thumbnails via Playwright."""

import asyncio
import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import DATA_DIR
from models.connection import SSHConnection

logger = logging.getLogger(__name__)

SCREENSHOT_DIR = DATA_DIR / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


def screenshot_path(connection_id: int) -> Path:
    return SCREENSHOT_DIR / f"{connection_id}.jpg"


async def capture_screenshot(url: str, output: Path, timeout_ms: int = 10000) -> bool:
    """Capture a screenshot of a URL using Playwright headless Chromium."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.error("Playwright not installed — cannot capture screenshots")
        return False

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--ignore-certificate-errors"],
            )
            page = await browser.new_page(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
            )
            await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            await page.wait_for_timeout(1500)  # extra settle time
            await page.screenshot(path=str(output), type="jpeg", quality=60)
            await browser.close()
        logger.info("Screenshot captured: %s -> %s", url, output.name)
        return True
    except Exception as e:
        logger.warning("Screenshot failed for %s: %s", url, e)
        return False


async def capture_for_connection(db: AsyncSession, connection_id: int) -> bool:
    """Capture screenshot for a single connection."""
    conn = await db.get(SSHConnection, connection_id)
    if not conn or not conn.web_url:
        return False
    output = screenshot_path(conn.id)
    return await capture_screenshot(conn.web_url, output)


async def refresh_all_screenshots(db: AsyncSession, user_id: int) -> dict:
    """Refresh screenshots for all connections with web_url."""
    result = await db.execute(
        select(SSHConnection).where(
            SSHConnection.user_id == user_id,
            SSHConnection.web_url.isnot(None),
            SSHConnection.web_url != "",
        )
    )
    connections = result.scalars().all()

    captured = 0
    failed = 0
    for conn in connections:
        output = screenshot_path(conn.id)
        ok = await capture_screenshot(conn.web_url, output)
        if ok:
            captured += 1
        else:
            failed += 1

    return {"captured": captured, "failed": failed, "total": len(connections)}
