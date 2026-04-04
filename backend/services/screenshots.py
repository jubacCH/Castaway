"""Screenshot service — captures web interface thumbnails via Playwright."""

import asyncio
import logging
import os
import socket
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import DATA_DIR
from models.connection import SSHConnection

logger = logging.getLogger(__name__)

SCREENSHOT_DIR = DATA_DIR / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

# Allow screenshots of private/internal IPs (homelab use case)
ALLOW_PRIVATE = os.environ.get("SCREENSHOT_ALLOW_PRIVATE", "true").lower() == "true"
# But always block these dangerous ones
_ALWAYS_BLOCKED = ("169.254.169.254", "metadata.google.internal", "metadata.azure.com")


def _is_safe_url(url: str) -> bool:
    """Validate URL: allow private IPs for homelab, but block cloud metadata + loopback."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        host_lower = host.lower()
        if host_lower in _ALWAYS_BLOCKED:
            logger.warning("Blocked metadata endpoint: %s", host)
            return False
        # Resolve hostname to IP
        try:
            ip = ip_address(host)
        except ValueError:
            # It's a hostname — resolve
            try:
                resolved = socket.gethostbyname(host)
                ip = ip_address(resolved)
            except Exception:
                return False
        # Always block loopback + link-local (169.254.x.x)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
            logger.warning("Blocked dangerous IP %s for url %s", ip, url)
            return False
        # Block private IPs unless explicitly allowed
        if ip.is_private and not ALLOW_PRIVATE:
            return False
        return True
    except Exception as e:
        logger.warning("URL validation failed for %s: %s", url, e)
        return False


def screenshot_path(connection_id: int) -> Path:
    return SCREENSHOT_DIR / f"{connection_id}.jpg"


async def capture_screenshot(url: str, output: Path, timeout_ms: int = 10000) -> bool:
    """Capture a screenshot of a URL using Playwright headless Chromium."""
    if not _is_safe_url(url):
        logger.warning("Screenshot blocked for unsafe URL: %s", url)
        return False

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


_concurrency = asyncio.Semaphore(3)  # max 3 simultaneous browsers


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

    async def _capture(conn):
        async with _concurrency:
            return await capture_screenshot(conn.web_url, screenshot_path(conn.id))

    results = await asyncio.gather(*[_capture(c) for c in connections])
    captured = sum(1 for r in results if r)
    failed = len(results) - captured
    return {"captured": captured, "failed": failed, "total": len(connections)}
