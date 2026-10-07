"""add Google identity and email verification metadata to users

Revision ID: 6e4c9a7d2f10
Revises: b7d9f3a61c20
Create Date: 2026-10-06

Phase 5 of the registration hardening work. Both columns are nullable so
existing username/password accounts retain their current behavior. The
migration does not modify password hashes, roles, email addresses, or existing
verification state.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "6e4c9a7d2f10"
down_revision: Union[str, Sequence[str], None] = "b7d9f3a61c20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


GOOGLE_SUB_INDEX = "uq_user_table_usr_google_sub_not_null"


def upgrade() -> None:
    op.add_column(
        "user_table",
        sa.Column("usr_google_sub", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "user_table",
        sa.Column("usr_email_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        GOOGLE_SUB_INDEX,
        "user_table",
        ["usr_google_sub"],
        unique=True,
        postgresql_where=sa.text("usr_google_sub IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(GOOGLE_SUB_INDEX, table_name="user_table")
    op.drop_column("user_table", "usr_email_verified_at")
    op.drop_column("user_table", "usr_google_sub")
