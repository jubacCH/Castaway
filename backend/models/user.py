"""User and auth session models."""

import hashlib
import hmac
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String

from config import SECRET_KEY
from models.base import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=True)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(16), default="user")  # admin | user
    is_active = Column(Boolean, default=True)
    mfa_secret = Column(String(64), nullable=True)  # TOTP secret (base32)
    mfa_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Session(Base):
    __tablename__ = "sessions"

    token = Column(String(128), primary_key=True)  # HMAC-SHA256 hashed
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime, nullable=False)


def hash_token(raw: str) -> str:
    """HMAC-SHA256 hash a session token for storage."""
    return hmac.new(SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
