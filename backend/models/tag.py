"""Tag model and association table."""

from sqlalchemy import Column, ForeignKey, Integer, String, Table

from models.base import Base

connection_tags = Table(
    "connection_tags",
    Base.metadata,
    Column("connection_id", Integer, ForeignKey("connections.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class Tag(Base):
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(64), nullable=False)
    color = Column(String(7), nullable=True)
