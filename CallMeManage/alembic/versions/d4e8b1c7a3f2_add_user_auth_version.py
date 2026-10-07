"""add durable per-user authentication version (CM-08)

Revision ID: d4e8b1c7a3f2
Revises: c2a84e1d7f90
Create Date: 2026-10-06

Every access token records the user's usr_auth_version and every request must
match the current value. Password reset increments it in the same transaction
as the password change, so old tokens stop working even when Redis is down.

Existing rows receive 1 through the server default. User rows, password hashes
and other columns are not modified.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d4e8b1c7a3f2"
down_revision: Union[str, Sequence[str], None] = "c2a84e1d7f90"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "user_table",
        sa.Column("usr_auth_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
    )


def downgrade() -> None:
    # Dropping the column removes durable revocation; only do this together with
    # rolling the backend back, and treat CM-08 as reopened.
    op.drop_column("user_table", "usr_auth_version")
