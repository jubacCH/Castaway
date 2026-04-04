"""SSH session audit log model."""

from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String

from models.base import Base


class SessionLog(Base):
    __tablename__ = "session_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    connection_id = Column(Integer, ForeignKey("connections.id", ondelete="SET NULL"), nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    duration_sec = Column(Integer, nullable=True)
    recording_path = Column(String(512), nullable=True)
    ip_address = Column(String(45), nullable=True)
    bytes_sent = Column(BigInteger, default=0)
    bytes_recv = Column(BigInteger, default=0)
