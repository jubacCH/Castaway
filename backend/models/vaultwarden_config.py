"""Vaultwarden/Bitwarden integration configuration model."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from models.base import Base


class VaultwardenConfig(Base):
    __tablename__ = "vaultwarden_configs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), nullable=False)  # label
    url = Column(String(512), nullable=False)
    encrypted_email = Column(Text, nullable=True)
    encrypted_password = Column(Text, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
