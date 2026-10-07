"""unique token-pending device name per site

Revision ID: c7e91d3a5b20
Revises: b4a15b8d49ec
Create Date: 2026-09-29 22:30:00.000000

Phase 5 ของ One-Time Call Home Token: ชื่อ pending Device ของ token flow (`<vendor>-pending-N`) ต้องไม่ซ้ำต่อ Site
เป็น defense-in-depth ของการ lock แถว Site ตอนจัดสรรชื่อ - partial unique index เฉพาะแถวที่ยังเป็น pending และไม่มี
MAC/Serial/fingerprint (legacy pending มี MAC/Serial จึงไม่ถูกกระทบ)

Preflight: ถ้าข้อมูลเดิมมีชื่อซ้ำตามเงื่อนไขนี้ migration หยุด (fail closed) โดยไม่แก้/ลบข้อมูลใด ๆ
ข้อความ error แสดงเฉพาะจำนวนกลุ่ม/แถว
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c7e91d3a5b20'
down_revision: Union[str, Sequence[str], None] = 'b4a15b8d49ec'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INDEX_NAME = 'uq_device_token_pending_name'
PREDICATE = "dev_status = 'pending' AND dev_mac IS NULL AND dev_serial IS NULL AND dev_fingerprint IS NULL"

DUPLICATE_NAME_SQL = f"""
SELECT COUNT(*) AS duplicate_groups, COALESCE(SUM(row_count), 0) AS duplicate_rows
FROM (
    SELECT COUNT(*) AS row_count
    FROM device_information
    WHERE {PREDICATE}
    GROUP BY site_id, dev_name
    HAVING COUNT(*) > 1
) AS duplicated
"""


def duplicate_pending_name_summary(connection) -> tuple[int, int]:
    """(กลุ่มที่ซ้ำ, แถวที่ซ้ำ) - SELECT อย่างเดียว"""
    row = connection.execute(sa.text(DUPLICATE_NAME_SQL)).one()
    return int(row.duplicate_groups), int(row.duplicate_rows)


def upgrade() -> None:
    groups, rows = duplicate_pending_name_summary(op.get_bind())
    if groups:
        raise RuntimeError(
            f"Cannot create {INDEX_NAME}: {groups} duplicated (site_id, dev_name) group(s) across {rows} pending "
            "token-style device rows. Nothing was changed. Resolve the duplicates manually and run the upgrade again."
        )
    op.create_index(
        INDEX_NAME, 'device_information', ['site_id', 'dev_name'], unique=True, postgresql_where=sa.text(PREDICATE)
    )


def downgrade() -> None:
    op.drop_index(INDEX_NAME, table_name='device_information')
