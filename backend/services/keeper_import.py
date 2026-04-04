"""Keeper CSV import — parse exported Keeper password manager CSV."""

import csv
import io
import logging
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import encrypt_value
from models.connection import SSHConnection
from models.folder import Folder

logger = logging.getLogger(__name__)

# Keeper CSV format (no header):
# folder, title, username, password, url, notes, totp


def parse_keeper_csv(content: str) -> list[dict]:
    """Parse Keeper CSV content into structured records."""
    reader = csv.reader(io.StringIO(content))
    records = []
    for row in reader:
        if len(row) < 5:
            continue
        folder = row[0].strip() if row[0] else ""
        title = row[1].strip() if len(row) > 1 else ""
        username = row[2].strip() if len(row) > 2 else ""
        password = row[3].strip() if len(row) > 3 else ""
        url = row[4].strip() if len(row) > 4 else ""
        notes = row[5].strip() if len(row) > 5 else ""

        if not title:
            continue

        # Try to extract host from URL
        hostname = ""
        port = None
        if url:
            try:
                parsed = urlparse(url if "://" in url else f"http://{url}")
                hostname = parsed.hostname or ""
                if parsed.port:
                    port = parsed.port
            except Exception:
                pass

        records.append({
            "folder": folder,
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "hostname": hostname,
            "port": port,
            "notes": notes,
        })

    return records


def preview_keeper_import(content: str) -> list[dict]:
    """Preview parsed records (passwords masked)."""
    records = parse_keeper_csv(content)
    return [{
        "folder": r["folder"],
        "title": r["title"],
        "username": r["username"],
        "has_password": bool(r["password"]),
        "url": r["url"],
        "hostname": r["hostname"],
        "port": r["port"],
    } for r in records]


async def import_keeper_csv(
    db: AsyncSession, content: str, user_id: int,
    mode: str = "connections",
) -> dict:
    """Import Keeper CSV records.

    mode="connections": Create SSHConnection per record (with host from URL)
    mode="credentials": Only import as credentials (match to existing connections)
    """
    records = parse_keeper_csv(content)
    if not records:
        return {"imported": 0, "skipped": 0, "errors": ["No valid records found"]}

    imported = skipped = 0
    errors: list[str] = []

    # Cache folders
    folder_cache: dict[str, int] = {}

    for rec in records:
        try:
            if mode == "connections":
                # Need a hostname to create a connection
                if not rec["hostname"]:
                    skipped += 1
                    continue

                # Create or get folder
                folder_id = None
                if rec["folder"]:
                    if rec["folder"] not in folder_cache:
                        existing = (await db.execute(
                            select(Folder).where(
                                Folder.user_id == user_id,
                                Folder.name == rec["folder"][:128],
                            )
                        )).scalar_one_or_none()
                        if existing:
                            folder_cache[rec["folder"]] = existing.id
                        else:
                            f = Folder(user_id=user_id, name=rec["folder"][:128])
                            db.add(f)
                            await db.flush()
                            folder_cache[rec["folder"]] = f.id
                    folder_id = folder_cache[rec["folder"]]

                conn = SSHConnection(
                    user_id=user_id,
                    name=rec["title"][:128],
                    host=rec["hostname"],
                    port=rec["port"] or 22,
                    protocol="ssh",
                    username=rec["username"] or None,
                    auth_method="password" if rec["password"] else "agent",
                    folder_id=folder_id,
                    notes=rec["notes"] or None,
                    source="keeper",
                    source_id=f"keeper:{rec['title']}:{rec['hostname']}",
                )
                if rec["password"]:
                    conn.encrypted_password = encrypt_value(rec["password"])

                db.add(conn)
                imported += 1

            elif mode == "credentials":
                # Match to existing connections by hostname
                if not rec["hostname"] or not rec["password"]:
                    skipped += 1
                    continue

                result = await db.execute(
                    select(SSHConnection).where(
                        SSHConnection.user_id == user_id,
                        SSHConnection.host == rec["hostname"],
                    )
                )
                matches = result.scalars().all()
                if not matches:
                    skipped += 1
                    continue

                for conn in matches:
                    if rec["username"]:
                        conn.username = rec["username"]
                    conn.encrypted_password = encrypt_value(rec["password"])
                    conn.auth_method = "password"
                    imported += 1

        except Exception as exc:
            errors.append(f"{rec['title']}: {exc}")

    await db.commit()
    return {"imported": imported, "skipped": skipped, "errors": errors}
