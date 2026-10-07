"""restore the Site Admin role

Revision ID: 9c4e71a2d6f8
Revises: 8b2f4d6a9c10
Create Date: 2026-10-02

Site membership has three effective levels: the owner is stored on
``site_table.site_owner_id`` while non-owner memberships may be ``admin`` or
``member``.  Admins can manage members; members can operate devices only.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "9c4e71a2d6f8"
down_revision: Union[str, Sequence[str], None] = "8b2f4d6a9c10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _role_constraint_exists() -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(
        constraint.get("name") == "check_site_member_role"
        for constraint in inspector.get_check_constraints("site_member")
    )


def upgrade() -> None:
    # d2c27e07f2d6 was intended to add this CHECK but its upgrade is a no-op.
    # Some databases created directly from metadata do have it while databases
    # built only through Alembic do not, so the migration must support both.
    if _role_constraint_exists():
        op.drop_constraint("check_site_member_role", "site_member", type_="check")
    op.create_check_constraint(
        "check_site_member_role",
        "site_member",
        "role IN ('admin', 'member')",
    )


def downgrade() -> None:
    # The previous model had no representation for Site Admin. Preserve access
    # to the Site by demoting those rows to member before restoring its CHECK.
    op.execute(sa.text("UPDATE site_member SET role = 'member' WHERE role = 'admin'"))
    if _role_constraint_exists():
        op.drop_constraint("check_site_member_role", "site_member", type_="check")
    op.create_check_constraint(
        "check_site_member_role",
        "site_member",
        "role IN ('member')",
    )
