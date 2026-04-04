"""Vaultwarden/Bitwarden API client and credential sync service."""

import logging
from datetime import datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import decrypt_value, encrypt_value
from models.connection import SSHConnection
from models.vaultwarden_config import VaultwardenConfig

logger = logging.getLogger(__name__)


class VaultwardenClient:
    """Async client for Bitwarden/Vaultwarden API."""

    def __init__(self, base_url: str, email: str, password: str):
        self.base = base_url.rstrip("/")
        self.email = email
        self.password = password
        self._access_token: str | None = None

    async def authenticate(self) -> None:
        """Authenticate via Bitwarden Identity API."""
        url = f"{self.base}/identity/connect/token"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, data={
                "grant_type": "password",
                "username": self.email,
                "password": self.password,
                "scope": "api offline_access",
                "client_id": "web",
                "deviceType": "10",
                "deviceIdentifier": "castaway-session-manager",
                "deviceName": "Castaway",
            }, headers={"Content-Type": "application/x-www-form-urlencoded"})
            if resp.status_code != 200:
                error_msg = resp.text[:200]
                raise ValueError(f"Auth failed ({resp.status_code}): {error_msg}")
            data = resp.json()
            self._access_token = data.get("access_token")
            if not self._access_token:
                raise ValueError("No access_token in response")

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._access_token}"}

    async def sync_vault(self) -> dict:
        """Fetch full vault sync data."""
        url = f"{self.base}/api/sync"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    async def get_login_items(self) -> list[dict]:
        """Get all login-type cipher items from vault."""
        sync_data = await self.sync_vault()
        ciphers = sync_data.get("ciphers") or sync_data.get("Ciphers") or []

        logins = []
        for cipher in ciphers:
            # Type 1 = Login
            cipher_type = cipher.get("type") or cipher.get("Type")
            if cipher_type != 1:
                continue

            login_data = cipher.get("login") or cipher.get("Login") or {}
            name = cipher.get("name") or cipher.get("Name") or ""
            username = login_data.get("username") or login_data.get("Username") or ""
            password = login_data.get("password") or login_data.get("Password") or ""

            # Extract URIs
            uris = login_data.get("uris") or login_data.get("Uris") or []
            uri_list = []
            for u in uris:
                uri = u.get("uri") or u.get("Uri") or ""
                if uri:
                    uri_list.append(uri)

            logins.append({
                "id": cipher.get("id") or cipher.get("Id") or "",
                "name": name,
                "username": username,
                "password": password,
                "uris": uri_list,
                "notes": cipher.get("notes") or cipher.get("Notes") or "",
            })

        return logins

    async def test_connection(self) -> dict:
        """Test auth and return vault summary."""
        await self.authenticate()
        items = await self.get_login_items()
        return {"ok": True, "login_items": len(items)}


def client_from_config(config: VaultwardenConfig) -> VaultwardenClient:
    """Build VaultwardenClient from config model."""
    email = decrypt_value(config.encrypted_email) if config.encrypted_email else ""
    password = decrypt_value(config.encrypted_password) if config.encrypted_password else ""
    return VaultwardenClient(base_url=config.url, email=email, password=password)


async def preview_credentials(config: VaultwardenConfig) -> list[dict]:
    """Preview available credentials from Vaultwarden."""
    client = client_from_config(config)
    await client.authenticate()
    items = await client.get_login_items()

    credentials = []
    for item in items:
        # Extract hostname from URIs for matching
        hostnames = []
        for uri in item["uris"]:
            try:
                parsed = urlparse(uri if "://" in uri else f"ssh://{uri}")
                if parsed.hostname:
                    hostnames.append(parsed.hostname)
            except Exception:
                pass

        credentials.append({
            "id": item["id"],
            "name": item["name"],
            "username": item["username"],
            "has_password": bool(item["password"]),
            "uris": item["uris"],
            "hostnames": hostnames,
        })

    return sorted(credentials, key=lambda c: c["name"].lower())


async def auto_match_credentials(
    db: AsyncSession, config: VaultwardenConfig, user_id: int
) -> list[dict]:
    """Auto-match vault credentials to connections by hostname.

    Returns list of suggested matches: [{connection_id, connection_name, credential_id, credential_name, match_type}]
    """
    credentials = await preview_credentials(config)

    # Load user's connections
    result = await db.execute(
        select(SSHConnection).where(SSHConnection.user_id == user_id)
    )
    connections = result.scalars().all()

    matches = []
    for conn in connections:
        for cred in credentials:
            match_type = None

            # Match by hostname in URI
            if conn.host in cred["hostnames"]:
                match_type = "hostname"
            # Match by connection name in credential name
            elif conn.name.lower() in cred["name"].lower():
                match_type = "name"
            # Match by credential name in connection host
            elif cred["name"].lower() in conn.host.lower():
                match_type = "name_in_host"

            if match_type:
                matches.append({
                    "connection_id": conn.id,
                    "connection_name": conn.name,
                    "connection_host": conn.host,
                    "credential_id": cred["id"],
                    "credential_name": cred["name"],
                    "credential_username": cred["username"],
                    "match_type": match_type,
                })

    return matches


async def assign_credential(
    db: AsyncSession, config: VaultwardenConfig, user_id: int,
    connection_id: int, credential_id: str
) -> dict:
    """Assign a Vaultwarden credential to a connection.

    Fetches the credential from Vault and stores username/password encrypted locally.
    """
    client = client_from_config(config)
    await client.authenticate()
    items = await client.get_login_items()

    # Find the credential
    cred = next((i for i in items if i["id"] == credential_id), None)
    if not cred:
        raise ValueError(f"Credential {credential_id} not found in vault")

    # Find the connection
    conn = await db.get(SSHConnection, connection_id)
    if not conn or (conn.user_id != user_id):
        raise ValueError("Connection not found")

    # Assign credentials
    if cred["username"]:
        conn.username = cred["username"]
    if cred["password"]:
        conn.encrypted_password = encrypt_value(cred["password"])
        conn.auth_method = "password"

    await db.commit()

    logger.info("Assigned credential '%s' to connection '%s' (id=%d)",
                cred["name"], conn.name, conn.id)

    return {
        "ok": True,
        "connection_id": conn.id,
        "connection_name": conn.name,
        "credential_name": cred["name"],
        "username_set": bool(cred["username"]),
        "password_set": bool(cred["password"]),
    }


async def bulk_assign(
    db: AsyncSession, config: VaultwardenConfig, user_id: int,
    assignments: list[dict]
) -> dict:
    """Bulk assign credentials. assignments = [{connection_id, credential_id}, ...]"""
    client = client_from_config(config)
    await client.authenticate()
    items = await client.get_login_items()
    cred_map = {i["id"]: i for i in items}

    assigned = 0
    errors = []

    for assignment in assignments:
        conn_id = assignment["connection_id"]
        cred_id = assignment["credential_id"]

        cred = cred_map.get(cred_id)
        if not cred:
            errors.append(f"Credential {cred_id} not found")
            continue

        conn = await db.get(SSHConnection, conn_id)
        if not conn or conn.user_id != user_id:
            errors.append(f"Connection {conn_id} not found")
            continue

        if cred["username"]:
            conn.username = cred["username"]
        if cred["password"]:
            conn.encrypted_password = encrypt_value(cred["password"])
            conn.auth_method = "password"

        assigned += 1

    config.last_sync_at = datetime.utcnow()
    await db.commit()

    return {"assigned": assigned, "errors": errors}
