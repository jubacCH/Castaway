"""API key model for REST API authentication."""

import hashlib
import secrets
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from models.base import Base

PREFIX = "cw_"


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(128), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False)  # SHA-256
    prefix = Column(String(16), nullable=False)  # first 8 chars for identification
    role = Column(String(16), default="readonly")  # readonly | editor | admin
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)  # None = never expires


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key. Returns (raw_key, sha256_hash)."""
    raw = PREFIX + secrets.token_hex(24)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, key_hash
