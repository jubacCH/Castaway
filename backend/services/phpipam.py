"""phpIPAM API client and host sync service."""

import logging
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import decrypt_value
from models.connection import SSHConnection
from models.phpipam_config import PhpIpamConfig

logger = logging.getLogger(__name__)


class PhpIpamClient:
    """Async client for phpIPAM REST API."""

    def __init__(self, base_url: str, app_id: str, app_secret: str | None = None,
                 username: str | None = None, password: str | None = None,
                 verify_ssl: bool = True):
        self.base = base_url.rstrip("/")
        self.app_id = app_id
        self.app_secret = app_secret
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._token: str | None = None

    def _api(self, path: str) -> str:
        return f"{self.base}/api/{self.app_id}/{path.lstrip('/')}"

    async def authenticate(self) -> None:
        if self.app_secret:
            self._token = self.app_secret
            return
        if not self.username or not self.password:
            raise ValueError("Either app_secret or username/password required")
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10) as client:
            resp = await client.post(self._api("user/"), auth=(self.username, self.password))
            resp.raise_for_status()
            body = resp.json()
            if not body.get("success"):
                raise ValueError(f"phpIPAM auth failed: {body.get('message', 'unknown')}")
            self._token = body["data"]["token"]

    def _headers(self) -> dict:
        if self._token:
            return {"token": self._token, "phpipam-token": self._token}
        return {}

    async def get_addresses(self) -> list[dict]:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15) as client:
            resp = await client.get(self._api("addresses/all/"), headers=self._headers())
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            body = resp.json()
            if not body.get("success"):
                return []
            return body.get("data") or []

    async def get_subnets(self) -> list[dict]:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15) as client:
            resp = await client.get(self._api("subnets/"), headers=self._headers())
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            body = resp.json()
            if not body.get("success"):
                return []
            return body.get("data") or []

    async def test_connection(self) -> dict:
        """Test connectivity — returns summary."""
        await self.authenticate()
        addresses = await self.get_addresses()
        active = [a for a in addresses if str(a.get("active", "1")) != "0"]
        return {
            "ok": True,
            "addresses_total": len(addresses),
            "addresses_active": len(active),
        }


def client_from_config(config: PhpIpamConfig) -> PhpIpamClient:
    """Build PhpIpamClient from a PhpIpamConfig model instance."""
    app_secret = decrypt_value(config.encrypted_app_secret) if config.encrypted_app_secret else None
    username = decrypt_value(config.encrypted_username) if config.encrypted_username else None
    password = decrypt_value(config.encrypted_password) if config.encrypted_password else None

    return PhpIpamClient(
        base_url=config.url,
        app_id=config.app_id,
        app_secret=app_secret,
        username=username,
        password=password,
        verify_ssl=config.verify_ssl,
    )


async def preview_hosts(config: PhpIpamConfig) -> list[dict]:
    """Preview which hosts would be imported from phpIPAM."""
    client = client_from_config(config)
    await client.authenticate()
    addresses = await client.get_addresses()

    hosts = []
    for addr in addresses:
        if str(addr.get("active", "1")) == "0":
            continue
        ip = (addr.get("ip") or "").strip()
        if not ip:
            continue
        ssh_flag = str(addr.get("custom_SSH") or "").strip().lower()
        if ssh_flag not in ("yes", "1", "true"):
            continue
        name = (addr.get("hostname") or addr.get("description") or ip).strip() or ip
        port_web = str(addr.get("custom_Port_Web") or "").strip()
        hosts.append({
            "ip": ip,
            "hostname": name,
            "mac": addr.get("mac") or "",
            "subnet_id": addr.get("subnetId") or "",
            "last_seen": addr.get("lastSeen") or "",
            "source_id": str(addr.get("id", ip)),
            "ssh": True,
            "port_web": port_web,
        })
    return sorted(hosts, key=lambda h: h["ip"])


async def sync_hosts(db: AsyncSession, config: PhpIpamConfig, user_id: int) -> dict:
    """Sync phpIPAM addresses into SSHConnection table.

    - Creates new connections for new addresses
    - Updates existing phpipam-sourced connections (merge by source_id)
    - Does NOT delete connections that are no longer in phpIPAM
    """
    client = client_from_config(config)

    try:
        await client.authenticate()
        addresses = await client.get_addresses()
    except Exception as exc:
        logger.error("phpIPAM sync failed for config %s: %s", config.id, exc)
        return {"added": 0, "updated": 0, "skipped": 0, "errors": [str(exc)]}

    # Load existing phpipam-sourced connections for this user
    result = await db.execute(
        select(SSHConnection).where(
            SSHConnection.user_id == user_id,
            SSHConnection.source == "phpipam",
        )
    )
    existing: dict[str, SSHConnection] = {}
    for conn in result.scalars().all():
        if conn.source_id:
            existing[conn.source_id] = conn

    added = updated = skipped = 0
    errors: list[str] = []

    for addr in addresses:
        if str(addr.get("active", "1")) == "0":
            skipped += 1
            continue
        ip = (addr.get("ip") or "").strip()
        if not ip:
            skipped += 1
            continue

        # Only import hosts with custom_SSH = "Yes"
        ssh_flag = str(addr.get("custom_SSH") or "").strip().lower()
        if ssh_flag not in ("yes", "1", "true"):
            skipped += 1
            continue

        name = (addr.get("hostname") or addr.get("description") or ip).strip() or ip
        source_id = str(addr.get("id", ip))

        # Build web_url from hostname + custom_Port_Web
        web_url = None
        port_web = str(addr.get("custom_Port_Web") or "").strip()
        if port_web and name and not name.replace(".", "").isdigit() and "." in name:
            web_url = f"https://{name}:{port_web}"
        elif port_web and name:
            web_url = f"https://{ip}:{port_web}"

        try:
            if source_id in existing:
                conn = existing[source_id]
                changed = False
                if conn.host != ip:
                    conn.host = ip
                    changed = True
                if conn.name != name[:128]:
                    conn.name = name[:128]
                    changed = True
                # Update web_url from phpIPAM (always sync, not just when empty)
                new_web_url = web_url or conn.web_url
                if new_web_url != conn.web_url:
                    conn.web_url = new_web_url
                    changed = True
                if changed:
                    updated += 1
                else:
                    skipped += 1
            else:
                db.add(SSHConnection(
                    user_id=user_id,
                    name=name[:128],
                    host=ip,
                    port=22,
                    protocol="ssh",
                    auth_method="password",
                    source="phpipam",
                    source_id=source_id,
                    web_url=web_url,
                ))
                added += 1
        except Exception as exc:
            errors.append(f"{ip}: {exc}")

    config.last_sync_at = datetime.utcnow()
    await db.commit()

    logger.info("phpIPAM sync: added=%d updated=%d skipped=%d errors=%d",
                added, updated, skipped, len(errors))
    return {"added": added, "updated": updated, "skipped": skipped, "errors": errors}
