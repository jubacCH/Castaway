"""Key-value settings store."""

from sqlalchemy import Column, String, Text

from models.base import Base


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(128), primary_key=True)
    value = Column(Text, default="")
