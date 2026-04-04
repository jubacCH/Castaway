"""SSH/RDP connection model."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from models.base import Base


class SSHConnection(Base):
    __tablename__ = "connections"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    folder_id = Column(Integer, ForeignKey("folders.id", ondelete="SET NULL"), nullable=True)
    name = Column(String(128), nullable=False)
    host = Column(String(256), nullable=False)
    port = Column(Integer, default=22)
    protocol = Column(String(8), default="ssh")  # ssh | rdp
    username = Column(String(128), nullable=True)
    auth_method = Column(String(16), default="password")  # password | key | agent
    encrypted_password = Column(Text, nullable=True)
    encrypted_key = Column(Text, nullable=True)
    key_passphrase = Column(Text, nullable=True)  # Fernet-encrypted
    notes = Column(Text, nullable=True)
    jump_host_id = Column(Integer, ForeignKey("connections.id", ondelete="SET NULL"), nullable=True)
    web_url = Column(String(512), nullable=True)  # optional web interface URL
    source = Column(String(32), default="manual")  # manual | phpipam | vaultwarden
    source_id = Column(String(256), nullable=True)  # external ID for sync
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
