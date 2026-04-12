"""Database models package."""

from models.base import Base, engine, AsyncSessionLocal, get_db, encrypt_value, decrypt_value
from models.user import User, Session
from models.connection import SSHConnection
from models.folder import Folder
from models.tag import Tag, connection_tags
from models.session_log import SessionLog
from models.api_key import ApiKey
from models.audit_log import AuditLog
from models.phpipam_config import PhpIpamConfig
from models.vaultwarden_config import VaultwardenConfig
from models.setting import Setting

__all__ = [
    "Base", "engine", "AsyncSessionLocal", "get_db",
    "encrypt_value", "decrypt_value",
    "User", "Session",
    "SSHConnection", "Folder", "Tag", "connection_tags",
    "SessionLog", "ApiKey", "AuditLog",
    "PhpIpamConfig", "VaultwardenConfig", "Setting",
]


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
