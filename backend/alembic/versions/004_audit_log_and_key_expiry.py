"""Add audit_logs table and api_key expires_at

Revision ID: 004
Revises: 003
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Audit log table
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("resource_type", sa.String(32), nullable=False),
        sa.Column("resource_id", sa.Integer(), nullable=True),
        sa.Column("resource_name", sa.String(256), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # API key expiry
    op.add_column("api_keys", sa.Column("expires_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("api_keys", "expires_at")
    op.drop_index("ix_audit_logs_created_at", "audit_logs")
    op.drop_index("ix_audit_logs_user_id", "audit_logs")
    op.drop_table("audit_logs")
