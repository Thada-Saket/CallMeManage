"""add per-visit device access session identity

Revision ID: b7d9f3a61c20
Revises: 9c4e71a2d6f8
Create Date: 2026-10-02
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b7d9f3a61c20"
down_revision: Union[str, Sequence[str], None] = "9c4e71a2d6f8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Preserve any pre-existing rows from older deployments.  acc_id is already
    # globally unique, so it is a safe historical session marker during backfill.
    op.add_column("device_access", sa.Column("acc_session_id", sa.String(length=40), nullable=True))
    op.execute(sa.text("UPDATE device_access SET acc_session_id = acc_id WHERE acc_session_id IS NULL"))
    op.alter_column("device_access", "acc_session_id", existing_type=sa.String(length=40), nullable=False)
    op.create_unique_constraint(
        "uq_device_access_session_id", "device_access", ["acc_session_id"]
    )
    op.create_index(
        "ix_device_access_dev_lastseen_id",
        "device_access",
        ["acc_dev_id", "acc_lastseen", "acc_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_device_access_dev_lastseen_id", table_name="device_access")
    op.drop_constraint("uq_device_access_session_id", "device_access", type_="unique")
    op.drop_column("device_access", "acc_session_id")
