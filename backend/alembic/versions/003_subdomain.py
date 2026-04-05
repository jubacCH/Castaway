"""Add subdomain field to connections

Revision ID: 003
Revises: 002
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("connections", sa.Column("subdomain", sa.String(64), nullable=True))
    op.create_unique_constraint("uq_connections_subdomain", "connections", ["subdomain"])


def downgrade() -> None:
    op.drop_constraint("uq_connections_subdomain", "connections", type_="unique")
    op.drop_column("connections", "subdomain")
