"""remove unused device and site columns

Revision ID: 8b2f4d6a9c10
Revises: c7e91d3a5b20
Create Date: 2026-09-30

The application now uses one-time enrollment tokens plus the pinned SSH host
key fingerprint.  The removed inventory fields are no longer populated or
used.  This migration deliberately refuses to discard non-empty values or a
device which has no enrollment record.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8b2f4d6a9c10"
down_revision: Union[str, Sequence[str], None] = "c7e91d3a5b20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


OLD_PENDING_INDEX = "uq_device_token_pending_name"
SERIAL_FINGERPRINT_INDEX = "unique_serial_n_fingerprint"
NEW_PENDING_PREDICATE = "dev_status = 'pending' AND dev_fingerprint IS NULL"
OLD_PENDING_PREDICATE = (
    "dev_status = 'pending' AND dev_mac IS NULL "
    "AND dev_serial IS NULL AND dev_fingerprint IS NULL"
)


def _scalar(sql: str) -> int:
    return int(op.get_bind().execute(sa.text(sql)).scalar_one())


def upgrade() -> None:
    populated = _scalar(
        """
        SELECT count(*)
        FROM device_information
        WHERE dev_source_ip IS NOT NULL
           OR dev_mac IS NOT NULL
           OR dev_serial IS NOT NULL
           OR dev_behide_nat IS TRUE
           OR dev_cloned IS TRUE
        """
    )
    populated_locations = _scalar(
        "SELECT count(*) FROM site_table WHERE site_location IS NOT NULL"
    )
    legacy_devices = _scalar(
        """
        SELECT count(*)
        FROM device_information AS d
        WHERE NOT EXISTS (
            SELECT 1 FROM device_enrollment AS e WHERE e.device_id = d.dev_id
        )
        """
    )
    if populated or populated_locations or legacy_devices:
        raise RuntimeError(
            "Refusing to remove legacy columns: "
            f"device rows with legacy values={populated}, "
            f"site rows with location={populated_locations}, "
            f"devices without enrollment={legacy_devices}"
        )

    op.drop_index(OLD_PENDING_INDEX, table_name="device_information")
    op.drop_index(SERIAL_FINGERPRINT_INDEX, table_name="device_information")
    op.drop_index(op.f("ix_device_information_dev_mac"), table_name="device_information")
    op.drop_index(op.f("ix_device_information_dev_serial"), table_name="device_information")

    op.create_index(
        OLD_PENDING_INDEX,
        "device_information",
        ["site_id", "dev_name"],
        unique=True,
        postgresql_where=sa.text(NEW_PENDING_PREDICATE),
    )

    op.drop_column("device_information", "dev_source_ip")
    op.drop_column("device_information", "dev_mac")
    op.drop_column("device_information", "dev_serial")
    op.drop_column("device_information", "dev_behide_nat")
    op.drop_column("device_information", "dev_cloned")
    op.drop_column("site_table", "site_location")


def downgrade() -> None:
    op.add_column("site_table", sa.Column("site_location", sa.String(length=128), nullable=True))

    op.add_column("device_information", sa.Column("dev_source_ip", sa.String(), nullable=True))
    op.add_column("device_information", sa.Column("dev_mac", sa.String(), nullable=True))
    op.add_column("device_information", sa.Column("dev_serial", sa.String(), nullable=True))
    op.add_column(
        "device_information",
        sa.Column("dev_behide_nat", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "device_information",
        sa.Column("dev_cloned", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("device_information", "dev_behide_nat", server_default=None)
    op.alter_column("device_information", "dev_cloned", server_default=None)

    op.drop_index(OLD_PENDING_INDEX, table_name="device_information")
    op.create_index(
        op.f("ix_device_information_dev_mac"),
        "device_information",
        ["dev_mac"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_information_dev_serial"),
        "device_information",
        ["dev_serial"],
        unique=False,
    )
    op.create_index(
        SERIAL_FINGERPRINT_INDEX,
        "device_information",
        ["dev_serial", "dev_fingerprint"],
        unique=True,
        postgresql_nulls_not_distinct=True,
        postgresql_where=sa.text("dev_serial IS NOT NULL"),
    )
    op.create_index(
        OLD_PENDING_INDEX,
        "device_information",
        ["site_id", "dev_name"],
        unique=True,
        postgresql_where=sa.text(OLD_PENDING_PREDICATE),
    )
