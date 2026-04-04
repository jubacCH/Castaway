"""Alembic environment — sync mode for compatibility."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from config import DATABASE_URL
from models.base import Base

# Import all models
import models.user
import models.connection
import models.folder
import models.tag
import models.session_log
import models.api_key
import models.phpipam_config
import models.vaultwarden_config
import models.setting

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Convert async URL to sync for Alembic
_sync_url = DATABASE_URL.replace("+asyncpg", "").replace("+aiosqlite", "")


def run_migrations_offline():
    context.configure(
        url=_sync_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = create_engine(_sync_url)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
