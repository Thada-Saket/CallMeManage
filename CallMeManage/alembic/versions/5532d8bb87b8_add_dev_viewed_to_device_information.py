"""add dev_viewed to device_information

Revision ID: 5532d8bb87b8
Revises: 429765f8c957
Create Date: 2026-08-03 17:55:00.679263

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5532d8bb87b8'
down_revision: Union[str, Sequence[str], None] = '429765f8c957'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # แถวเดิมที่มีอยู่แล้วทั้งหมดถือว่า "เคยเห็นแล้ว" (server_default=true ตอน
    # backfill) กันจุดแดงขึ้นพรึบทุกอุปกรณ์เดิมที่ user รู้จักอยู่แล้วทันทีหลัง
    # migrate - จุดแดงควรมีความหมายแค่ "อุปกรณ์ใหม่ที่เพิ่งเพิ่ม" เท่านั้น -
    # ตัด server_default ออกหลัง backfill เสร็จ ให้ INSERT ถัดไปพึ่ง default
    # ระดับ ORM (False) แทน ไม่ใช่ DB เขียน true ให้เองตลอดไป
    op.add_column(
        'device_information',
        sa.Column('dev_viewed', sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.alter_column('device_information', 'dev_viewed', server_default=None)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('device_information', 'dev_viewed')
