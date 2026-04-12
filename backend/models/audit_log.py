"""Audit log model — records create/update/delete events for connections, users, etc."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(32), nullable=False)           # create | update | delete | login | logout
    resource_type = Column(String(32), nullable=False)    # connection | user | folder | tag | api_key
    resource_id = Column(Integer, nullable=True)
    resource_name = Column(String(256), nullable=True)    # denormalized — survives deletion
    details = Column(Text, nullable=True)                 # JSON: changed fields or extra context
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
