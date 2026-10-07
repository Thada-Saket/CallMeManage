"""user delete cascades and site owner membership backfill

Revision ID: a1f4c9d02b7e
Revises: e2579de9da29
Create Date: 2026-08-06 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1f4c9d02b7e'
down_revision: Union[str, Sequence[str], None] = 'e2579de9da29'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # เพิ่ม 2026-08-06 คู่กับ DELETE /users/me (User Management feature) - ก่อนหน้า
    # นี้ owner ไม่มีแถวใน site_member เลย (สิทธิ์มาจาก site_table.site_owner_id
    # ล้วนๆ ผ่าน get_effective_role) - เพิ่มแถวให้เจ้าของสาขาที่มีอยู่แล้วทุกแถว
    # เพื่อ (1) ให้โผล่ในรายชื่อสมาชิกเหมือน admin/member คนอื่น (2) มีแถวไว้
    # "ลดขั้น" ตอนใช้ PATCH /sites/{id}/transfer-owner ทันที ไม่ต้องเช็ค
    # กรณีพิเศษ "ไม่มีแถวเดิม" ที่ router - ใช้ sa.table()/sa.column() (lightweight
    # reflection ผ่าน Core) ตามธรรมเนียมเดียวกับ data migration ใน
    # e2579de9da29 กัน migration นี้พังถ้า model เปลี่ยนต่อในอนาคต
    connection = op.get_bind()

    site_table = sa.table(
        'site_table',
        sa.column('site_id', sa.String),
        sa.column('site_owner_id', sa.String),
        sa.column('site_created_date', sa.DateTime(timezone=True)),
    )
    site_member_table = sa.table(
        'site_member',
        sa.column('site_id', sa.String),
        sa.column('usr_id', sa.String),
        sa.column('role', sa.String),
        sa.column('status', sa.String),
        sa.column('joined_date', sa.DateTime(timezone=True)),
    )

    existing_owner_memberships = connection.execute(
        sa.select(site_member_table.c.site_id, site_member_table.c.usr_id)
    ).all()
    existing_pairs = {(row.site_id, row.usr_id) for row in existing_owner_memberships}

    for site in connection.execute(
        sa.select(site_table.c.site_id, site_table.c.site_owner_id, site_table.c.site_created_date)
    ).all():
        if (site.site_id, site.site_owner_id) in existing_pairs:
            continue
        connection.execute(
            site_member_table.insert().values(
                site_id=site.site_id,
                usr_id=site.site_owner_id,
                role="admin",
                status="approved",
                joined_date=site.site_created_date,
            )
        )

    # site_member.usr_id -> ON DELETE CASCADE: ลบบัญชีผู้ใช้แล้ว membership ของ
    # เขาทุกสาขาหายไปด้วย (เท่ากับออกจากทุกสาขาอัตโนมัติ)
    op.drop_constraint(op.f('site_member_usr_id_fkey'), 'site_member', type_='foreignkey')
    op.create_foreign_key(None, 'site_member', 'user_table', ['usr_id'], ['usr_id'], ondelete='CASCADE')

    # device_history.his_usr_id -> nullable + ON DELETE SET NULL: เป็น audit
    # trail ต้องอยู่รอดแม้ผู้สั่งคำสั่งลบบัญชีตัวเองไปแล้ว (โดยเฉพาะบนอุปกรณ์ใน
    # สาขาของคนอื่นที่ผู้ใช้นี้แค่เป็นสมาชิก) - null ผู้กระทำออก ไม่ลบทั้งแถว
    op.alter_column('device_history', 'his_usr_id', existing_type=sa.VARCHAR(), nullable=True)
    op.drop_constraint(op.f('device_history_his_usr_id_fkey'), 'device_history', type_='foreignkey')
    op.create_foreign_key(None, 'device_history', 'user_table', ['his_usr_id'], ['usr_id'], ondelete='SET NULL')

    # device_access.acc_usr_id -> nullable + ON DELETE SET NULL (เหตุผลเดียวกับ
    # device_history - เก็บแถวประวัติการเข้าถึงไว้ แค่ null ผู้กระทำ)
    op.alter_column('device_access', 'acc_usr_id', existing_type=sa.VARCHAR(), nullable=True)
    op.drop_constraint(op.f('device_access_acc_usr_id_fkey'), 'device_access', type_='foreignkey')
    op.create_foreign_key(None, 'device_access', 'user_table', ['acc_usr_id'], ['usr_id'], ondelete='SET NULL')

    # device_config_object.cfg_created_by_id -> nullable + ON DELETE SET NULL:
    # ตารางนี้เป็นโครงสร้างจริง (single source of truth ของสิ่งที่ตั้งค่าไว้บน
    # อุปกรณ์) ไม่ใช่แค่ log - ห้าม cascade ลบทั้งแถวทิ้งเด็ดขาด สมาชิกคนอื่นใน
    # สาขายังต้องใช้แถวนี้ทำ edit/delete ต่อได้แม้ผู้สร้างจะลบบัญชีไปแล้ว
    op.alter_column('device_config_object', 'cfg_created_by_id', existing_type=sa.VARCHAR(), nullable=True)
    op.drop_constraint(op.f('device_config_object_cfg_created_by_id_fkey'), 'device_config_object', type_='foreignkey')
    op.create_foreign_key(
        None, 'device_config_object', 'user_table', ['cfg_created_by_id'], ['usr_id'], ondelete='SET NULL'
    )

    # bootstrap_token.bst_usr_id -> ON DELETE CASCADE: token เป็นของส่วนตัวผู้ขอ
    # ล้วนๆ (ไม่ผูก site ไม่มีใครอื่นอ้างอิง) ลบบัญชีแล้วลบทิ้งไปเลยได้
    op.drop_constraint(op.f('bootstrap_token_bst_usr_id_fkey'), 'bootstrap_token', type_='foreignkey')
    op.create_foreign_key(None, 'bootstrap_token', 'user_table', ['bst_usr_id'], ['usr_id'], ondelete='CASCADE')


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(None, 'bootstrap_token', type_='foreignkey')
    op.create_foreign_key(
        op.f('bootstrap_token_bst_usr_id_fkey'), 'bootstrap_token', 'user_table', ['bst_usr_id'], ['usr_id']
    )

    op.drop_constraint(None, 'device_config_object', type_='foreignkey')
    op.create_foreign_key(
        op.f('device_config_object_cfg_created_by_id_fkey'),
        'device_config_object', 'user_table', ['cfg_created_by_id'], ['usr_id'],
    )
    op.alter_column('device_config_object', 'cfg_created_by_id', existing_type=sa.VARCHAR(), nullable=False)

    op.drop_constraint(None, 'device_access', type_='foreignkey')
    op.create_foreign_key(
        op.f('device_access_acc_usr_id_fkey'), 'device_access', 'user_table', ['acc_usr_id'], ['usr_id']
    )
    op.alter_column('device_access', 'acc_usr_id', existing_type=sa.VARCHAR(), nullable=False)

    op.drop_constraint(None, 'device_history', type_='foreignkey')
    op.create_foreign_key(
        op.f('device_history_his_usr_id_fkey'), 'device_history', 'user_table', ['his_usr_id'], ['usr_id']
    )
    op.alter_column('device_history', 'his_usr_id', existing_type=sa.VARCHAR(), nullable=False)

    op.drop_constraint(None, 'site_member', type_='foreignkey')
    op.create_foreign_key(
        op.f('site_member_usr_id_fkey'), 'site_member', 'user_table', ['usr_id'], ['usr_id']
    )

    # หมายเหตุ: ไม่ลบแถว site_member ที่ backfill ไว้ตอน upgrade() ออก (เหมือน
    # data migration ใน e2579de9da29 ที่ downgrade() ก็ไม่ reverse ข้อมูลเช่นกัน)
