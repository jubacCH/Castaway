"""Vaultwarden/Bitwarden API client and credential sync service."""

import base64
import hashlib
import logging
import os
from datetime import datetime
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import decrypt_value, encrypt_value
from models.connection import SSHConnection
from models.vaultwarden_config import VaultwardenConfig

logger = logging.getLogger(__name__)


# ── Bitwarden Crypto ─────────────────────────────────────────────────────────

def _make_master_key(password: str, email: str, kdf_iterations: int) -> bytes:
    """PBKDF2-SHA256(password, lowercase(email), iterations) -> 32-byte master key."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=email.lower().encode("utf-8"), iterations=kdf_iterations)
    return kdf.derive(password.encode("utf-8"))


def _hash_password(password: str, email: str, kdf_iterations: int) -> str:
    """Hash password for auth: PBKDF2(masterKey, password, 1) -> base64."""
    master_key = _make_master_key(password, email, kdf_iterations)
    kdf2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                      salt=password.encode("utf-8"), iterations=1)
    return base64.b64encode(kdf2.derive(master_key)).decode("utf-8")


def _stretch_master_key(master_key: bytes) -> tuple[bytes, bytes]:
    """Stretch master key into enc_key (32 bytes) + mac_key (32 bytes) via HKDF."""
    enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                         info=b"enc").derive(master_key)
    mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                         info=b"mac").derive(master_key)
    return enc_key, mac_key


def _decrypt_aes_cbc(data: bytes, iv: bytes, key: bytes) -> bytes:
    """AES-256-CBC decrypt + PKCS7 unpad."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _decrypt_symmetric_key(encrypted_key_b64: str, master_key: bytes) -> tuple[bytes, bytes]:
    """Decrypt the user's symmetric key using the stretched master key.

    encrypted_key is: <type>.<iv_b64>|<data_b64>  (or with mac: <iv>|<data>|<mac>)
    Returns (enc_key, mac_key) — the 64-byte symmetric key split in half.
    """
    enc_key, mac_key = _stretch_master_key(master_key)

    # Parse: "2.iv_base64|data_base64" or "2.iv|data|mac"
    parts = encrypted_key_b64.split(".", 1)
    payload = parts[1] if len(parts) > 1 else parts[0]
    segments = payload.split("|")
    iv = base64.b64decode(segments[0])
    data = base64.b64decode(segments[1])

    decrypted = _decrypt_aes_cbc(data, iv, enc_key)

    # The decrypted key is 64 bytes: first 32 = enc_key, last 32 = mac_key
    if len(decrypted) == 64:
        return decrypted[:32], decrypted[32:]
    elif len(decrypted) == 32:
        return decrypted, decrypted
    else:
        raise ValueError(f"Unexpected decrypted key length: {len(decrypted)}")


def _decrypt_cipher_string(encrypted: str, enc_key: bytes, mac_key: bytes) -> str:
    """Decrypt a Bitwarden cipher string (type 2 = AES-256-CBC).

    Format: "2.iv_b64|data_b64|mac_b64" or "2.iv_b64|data_b64"
    """
    if not encrypted or not encrypted.startswith("2."):
        return encrypted or ""

    payload = encrypted[2:]
    segments = payload.split("|")
    if len(segments) < 2:
        return ""

    iv = base64.b64decode(segments[0])
    data = base64.b64decode(segments[1])

    try:
        decrypted = _decrypt_aes_cbc(data, iv, enc_key)
        return decrypted.decode("utf-8")
    except Exception as e:
        logger.debug("Cipher decrypt failed: %s", e)
        return ""


# ── Client ───────────────────────────────────────────────────────────────────

class VaultwardenClient:
    """Async client for Bitwarden/Vaultwarden API with client-side decryption."""

    def __init__(self, base_url: str, email: str, password: str):
        self.base = base_url.rstrip("/")
        self.email = email
        self.password = password
        self._access_token: str | None = None
        self._enc_key: bytes | None = None
        self._mac_key: bytes | None = None

    async def _get_kdf_iterations(self) -> int:
        url = f"{self.base}/api/accounts/prelogin"
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.post(url, json={"email": self.email})
            if resp.status_code != 200:
                return 600000
            data = resp.json()
            return data.get("kdfIterations") or data.get("KdfIterations") or 600000

    async def authenticate(self) -> None:
        """Authenticate and derive decryption keys."""
        iterations = await self._get_kdf_iterations()
        master_key = _make_master_key(self.password, self.email, iterations)
        hashed_password = _hash_password(self.password, self.email, iterations)

        url = f"{self.base}/identity/connect/token"
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.post(url, data={
                "grant_type": "password",
                "username": self.email,
                "password": hashed_password,
                "scope": "api offline_access",
                "client_id": "web",
                "deviceType": "10",
                "deviceIdentifier": "castaway-session-manager",
                "deviceName": "Castaway",
            }, headers={"Content-Type": "application/x-www-form-urlencoded"})
            if resp.status_code != 200:
                raise ValueError(f"Auth failed ({resp.status_code}): {resp.text[:200]}")
            data = resp.json()
            self._access_token = data.get("access_token")
            if not self._access_token:
                raise ValueError("No access_token in response")

            # Decrypt the symmetric key from the token response
            encrypted_key = data.get("Key") or data.get("key") or ""
            if encrypted_key:
                self._enc_key, self._mac_key = _decrypt_symmetric_key(encrypted_key, master_key)
                logger.info("Vault symmetric key decrypted successfully")
            else:
                # Try from profile sync
                logger.warning("No Key in token response, will try from sync")

    def _decrypt(self, value: str) -> str:
        """Decrypt a cipher string using the vault's symmetric key."""
        if not self._enc_key:
            return value or ""
        return _decrypt_cipher_string(value, self._enc_key, self._mac_key)

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._access_token}"}

    async def sync_vault(self) -> dict:
        url = f"{self.base}/api/sync"
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            resp = await client.get(url, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()

            # If we don't have keys yet, get from profile
            if not self._enc_key:
                profile = data.get("profile") or data.get("Profile") or {}
                encrypted_key = profile.get("key") or profile.get("Key") or ""
                if encrypted_key:
                    master_key = _make_master_key(self.password, self.email,
                                                  await self._get_kdf_iterations())
                    self._enc_key, self._mac_key = _decrypt_symmetric_key(encrypted_key, master_key)

            return data

    async def get_login_items(self) -> list[dict]:
        """Get all decrypted login-type cipher items."""
        sync_data = await self.sync_vault()
        ciphers = sync_data.get("ciphers") or sync_data.get("Ciphers") or []

        logins = []
        for cipher in ciphers:
            cipher_type = cipher.get("type") or cipher.get("Type")
            if cipher_type != 1:
                continue

            login_data = cipher.get("login") or cipher.get("Login") or {}
            name = self._decrypt(cipher.get("name") or cipher.get("Name") or "")
            username = self._decrypt(login_data.get("username") or login_data.get("Username") or "")
            password = self._decrypt(login_data.get("password") or login_data.get("Password") or "")

            uris = login_data.get("uris") or login_data.get("Uris") or []
            uri_list = []
            for u in uris:
                raw = u.get("uri") or u.get("Uri") or ""
                decrypted_uri = self._decrypt(raw)
                if decrypted_uri:
                    uri_list.append(decrypted_uri)

            logins.append({
                "id": cipher.get("id") or cipher.get("Id") or "",
                "name": name,
                "username": username,
                "password": password,
                "uris": uri_list,
                "notes": self._decrypt(cipher.get("notes") or cipher.get("Notes") or ""),
            })

        return logins

    async def test_connection(self) -> dict:
        await self.authenticate()
        items = await self.get_login_items()
        return {"ok": True, "login_items": len(items)}


# ── Helpers ──────────────────────────────────────────────────────────────────

def client_from_config(config: VaultwardenConfig) -> VaultwardenClient:
    email = decrypt_value(config.encrypted_email) if config.encrypted_email else ""
    password = decrypt_value(config.encrypted_password) if config.encrypted_password else ""
    return VaultwardenClient(base_url=config.url, email=email, password=password)


async def preview_credentials(config: VaultwardenConfig) -> list[dict]:
    client = client_from_config(config)
    await client.authenticate()
    items = await client.get_login_items()

    credentials = []
    for item in items:
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
    credentials = await preview_credentials(config)

    result = await db.execute(
        select(SSHConnection).where(SSHConnection.user_id == user_id)
    )
    connections = result.scalars().all()

    # Only consider credentials with "ssh" in the name
    ssh_creds = [c for c in credentials if "ssh" in c["name"].lower()]

    matches = []
    for conn in connections:
        conn_name_lower = conn.name.lower().strip()

        for cred in ssh_creds:
            match_type = None
            cred_name_lower = cred["name"].lower()

            # Check if connection FQDN appears in the vault entry name
            if conn_name_lower and conn_name_lower in cred_name_lower:
                match_type = "name"

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
    client = client_from_config(config)
    await client.authenticate()
    items = await client.get_login_items()

    cred = next((i for i in items if i["id"] == credential_id), None)
    if not cred:
        raise ValueError(f"Credential {credential_id} not found in vault")

    conn = await db.get(SSHConnection, connection_id)
    if not conn or conn.user_id != user_id:
        raise ValueError("Connection not found")

    if cred["username"]:
        conn.username = cred["username"]
    if cred["password"]:
        conn.encrypted_password = encrypt_value(cred["password"])
        conn.auth_method = "password"

    await db.commit()
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
