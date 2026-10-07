"""add device_enrollment table for one-time enrollment token

Revision ID: 5cfb2d8b604c
Revises: 7fc10b1e11ed
Create Date: 2026-09-29 21:40:00.000000

Phase 2 ของ One-Time Call Home Token (planning/callhome_enrollment_*.md)

1) เพิ่มตาราง device_enrollment (additive) - ไม่แตะข้อมูล Device เดิม
2) ผ่อน unique_serial_n_fingerprint จาก constraint บนทุกแถว เป็น unique index เฉพาะแถวที่ dev_serial IS NOT NULL
   (ยัง NULLS NOT DISTINCT เหมือนเดิม) เพราะ pending Device ของระบบ token มี serial และ fingerprint เป็น NULL
   ทั้งคู่ ถ้าคง constraint เดิม pending ตัวที่ 2 (NULL, NULL) จะชน การผ่อนไม่ทำให้ข้อมูลเดิมผิดกฎ (upgrade
   ไม่มีทางล้ม) และพฤติกรรมทุกแถวที่มี serial เหมือนเดิม
  Pending  : token_hash มีค่า, consumed_at NULL
  Consumed : token_hash NULL,  consumed_at มีค่า (แถวคงอยู่เป็น marker)
token_hash เก็บ SHA-256 hex digest (64 ตัวอักษร) เท่านั้น - ไม่เก็บ plaintext token

การบังคับ fingerprint ไม่ซ้ำอยู่ใน revision ถัดไป (b4a15b8d49ec) แยกกัน เพราะต้อง fail closed
เมื่อข้อมูลเดิมมี fingerprint ซ้ำ และไม่ควรทำให้ตารางนี้ค้างครึ่งทางหรือถูกบล็อกไปด้วย
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5cfb2d8b604c'
down_revision: Union[str, Sequence[str], None] = '7fc10b1e11ed'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LEGACY_CONSTRAINT = 'unique_serial_n_fingerprint'


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_constraint(LEGACY_CONSTRAINT, 'device_information', type_='unique')
    op.create_index(
        LEGACY_CONSTRAINT, 'device_information', ['dev_serial', 'dev_fingerprint'], unique=True,
        postgresql_nulls_not_distinct=True, postgresql_where=sa.text('dev_serial IS NOT NULL'),
    )
    op.create_table(
        'device_enrollment',
        sa.Column('enrollment_id', sa.String(), nullable=False),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ['device_id'], ['device_information.dev_id'],
            name=op.f('device_enrollment_device_id_fkey'), ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('enrollment_id'),
        # unique constraint สร้าง index ให้เองแล้ว (lookup ด้วย device_id / token_hash) จึงไม่สร้าง index เพิ่ม
        # token_hash เป็น NULL ซ้ำได้ (PostgreSQL ถือว่า NULL ไม่เท่ากัน) จึงเก็บ consumed marker ได้หลายแถว
        sa.UniqueConstraint('device_id', name='uq_device_enrollment_device_id'),
        sa.UniqueConstraint('token_hash', name='uq_device_enrollment_token_hash'),
        sa.CheckConstraint(
            '(token_hash IS NOT NULL AND consumed_at IS NULL) OR (token_hash IS NULL AND consumed_at IS NOT NULL)',
            name='ck_device_enrollment_state',
        ),
        sa.CheckConstraint(
            "token_hash IS NULL OR token_hash ~ '^[0-9a-f]{64}$'",
            name='ck_device_enrollment_token_hash_format',
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    # constraint เดิมบังคับ (serial, fingerprint) NULLS NOT DISTINCT กับทุกแถว จึงสร้างกลับไม่ได้ถ้ามี Device
    # ที่ serial และ fingerprint เป็น NULL มากกว่าหนึ่งแถว (pending ของระบบ token) - หยุดพร้อมข้อความชัดเจน
    # โดยไม่ลบ/แก้แถวใด ๆ ให้ผู้ดูแลตัดสินใจเอง
    null_pairs = op.get_bind().execute(sa.text(
        'SELECT COUNT(*) FROM device_information WHERE dev_serial IS NULL AND dev_fingerprint IS NULL'
    )).scalar()
    if null_pairs > 1:
        raise RuntimeError(
            f"Cannot restore {LEGACY_CONSTRAINT}: {null_pairs} devices have both dev_serial and dev_fingerprint "
            "NULL (pending token enrollments). Nothing was changed. Remove or complete those devices first."
        )
    op.drop_index(LEGACY_CONSTRAINT, table_name='device_information')
    op.create_unique_constraint(
        LEGACY_CONSTRAINT, 'device_information', ['dev_serial', 'dev_fingerprint'], postgresql_nulls_not_distinct=True,
    )
    # ตารางที่ revision นี้สร้าง - constraint ของตารางหายไปพร้อมกัน
    op.drop_table('device_enrollment')
