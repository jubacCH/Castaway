"""Folder model for organizing connections."""

from sqlalchemy import Column, ForeignKey, Integer, String

from models.base import Base


class Folder(Base):
    __tablename__ = "folders"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    parent_id = Column(Integer, ForeignKey("folders.id", ondelete="CASCADE"), nullable=True)
    color = Column(String(7), nullable=True)  # hex color
    sort_order = Column(Integer, default=0)
