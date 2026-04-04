"""phpIPAM integration configuration model."""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text

from models.base import Base


class PhpIpamConfig(Base):
    __tablename__ = "phpipam_configs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), nullable=False)  # label, e.g. "Production phpIPAM"
    url = Column(String(512), nullable=False)
    app_id = Column(String(128), nullable=False)
    encrypted_app_secret = Column(Text, nullable=True)
    encrypted_username = Column(Text, nullable=True)
    encrypted_password = Column(Text, nullable=True)
    verify_ssl = Column(Boolean, default=True)
    auto_sync = Column(Boolean, default=False)
    sync_interval_min = Column(Integer, default=15)
    last_sync_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
