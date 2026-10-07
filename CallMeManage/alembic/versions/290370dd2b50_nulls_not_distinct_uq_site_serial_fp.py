"""nulls_not_distinct_uq_site_serial_fp

Revision ID: 290370dd2b50
Revises: a1f4c9d02b7e
Create Date: 2026-08-08 23:24:23.832065

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '290370dd2b50'
down_revision: Union[str, Sequence[str], None] = 'a1f4c9d02b7e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    op.drop_constraint("uq_site_serial_fp", "device_information", type_="unique")
    op.create_unique_constraint(
        "uq_site_serial_fp",
        "device_information",
        ["site_id", "dev_serial", "dev_fingerprint"],
        postgresql_nulls_not_distinct=True,
    )

def downgrade():
    op.drop_constraint("uq_site_serial_fp", "device_information", type_="unique")
    op.create_unique_constraint(
        "uq_site_serial_fp",
        "device_information",
        ["site_id", "dev_serial", "dev_fingerprint"],
    )
