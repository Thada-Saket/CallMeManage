"""unique non-null dev_fingerprint with duplicate preflight

Revision ID: b4a15b8d49ec
Revises: 5cfb2d8b604c
Create Date: 2026-09-29 21:41:00.000000

Phase 2 ของ One-Time Call Home Token: Active Device จะ reconnect ด้วย dev_fingerprint อย่างเดียว
จึงต้องให้ fingerprint ที่ไม่ใช่ NULL ระบุอุปกรณ์ได้เพียงตัวเดียว (unique constraint ปกติของ PostgreSQL
ปล่อยให้ NULL ซ้ำได้ pending Device ที่ยังไม่มี fingerprint จึงไม่ชนกัน)

Full-token cutover: Device เดิมทุกแถวซึ่งไม่มี Device_Enrollment เป็น historical inventory เท่านั้น
จึงล้าง fingerprint เก่าก่อนสร้าง unique constraint โดยไม่ลบ Device/history/config records
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b4a15b8d49ec'
down_revision: Union[str, Sequence[str], None] = '5cfb2d8b604c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CONSTRAINT_NAME = 'uq_device_information_dev_fingerprint'

# read-only: นับกลุ่มที่ fingerprint (ไม่ใช่ NULL) ซ้ำกัน และจำนวนแถวรวมของกลุ่มเหล่านั้น
DUPLICATE_FINGERPRINT_SQL = """
SELECT COUNT(*) AS duplicate_groups, COALESCE(SUM(row_count), 0) AS duplicate_rows
FROM (
    SELECT COUNT(*) AS row_count
    FROM device_information
    WHERE dev_fingerprint IS NOT NULL
    GROUP BY dev_fingerprint
    HAVING COUNT(*) > 1
) AS duplicated
"""


def duplicate_fingerprint_summary(connection) -> tuple[int, int]:
    """(จำนวนกลุ่มที่ซ้ำ, จำนวนแถวในกลุ่มเหล่านั้น) - SELECT อย่างเดียว ไม่แก้ข้อมูล"""
    row = connection.execute(sa.text(DUPLICATE_FINGERPRINT_SQL)).one()
    return int(row.duplicate_groups), int(row.duplicate_rows)


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(sa.text("""
        UPDATE device_information AS d
        SET dev_fingerprint = NULL
        WHERE NOT EXISTS (
            SELECT 1 FROM device_enrollment AS e WHERE e.device_id = d.dev_id
        )
    """))
    groups, rows = duplicate_fingerprint_summary(op.get_bind())
    if groups:
        raise RuntimeError(
            f"Cannot create {CONSTRAINT_NAME}: device_information has {groups} duplicated non-NULL "
            f"dev_fingerprint value(s) across {rows} rows. Nothing was changed. Resolve the duplicates "
            "manually (decide which device owns each fingerprint) and run the upgrade again."
        )
    op.create_unique_constraint(CONSTRAINT_NAME, 'device_information', ['dev_fingerprint'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(CONSTRAINT_NAME, 'device_information', type_='unique')
