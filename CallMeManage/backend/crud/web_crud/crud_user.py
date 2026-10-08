""" |======= CRUD User Management =======| """

from datetime import datetime
from typing import Optional

# sql tools
from sqlmodel import select, delete, update
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

# import validate schema and model
from backend.device_lifecycle import device_lifecycle
from backend.model.models import (
    Device_Information,
    Device_Capability,
    Device_Access,
    Device_History,
    Device_Config_Object,
    Site_Table,
    Site_Member, 
    User_Table
)
from backend.schema.user_schema import UserCreate
from backend.crud.web_crud.crud_site import list_owned_sites_id

# import password tools
from backend.core.account_password_policy import validate_account_password
from backend.core.passwd_security import dummy_verify, get_password_hash, verify_password

async def get_user(
    session: AsyncSession, 
    usr_id: str
) -> Optional[User_Table]:
    return await session.get(User_Table, usr_id)


async def get_user_by_username(
    session: AsyncSession, 
    usr_name: str
) -> Optional[User_Table]:
    statement = select(User_Table).where(User_Table.usr_name == usr_name)
    result = await session.exec(statement)
    return result.first()


async def get_user_by_email(
    session: AsyncSession, 
    usr_email: str
) -> Optional[User_Table]:
    statement = select(User_Table).where(User_Table.usr_email == usr_email)
    result = await session.exec(statement)
    return result.first()


# Registration only: verified emails are stored case-folded, but accounts
# created before verification may keep their original letter case. The
# database constraint is case-sensitive, so compare case-insensitively here
# to stop one mailbox from owning two accounts.
async def get_user_by_email_casefold(
    session: AsyncSession,
    usr_email: str,
) -> Optional[User_Table]:
    statement = select(User_Table).where(func.lower(User_Table.usr_email) == usr_email.lower())
    result = await session.exec(statement)
    return result.first()


async def get_user_by_google_sub(
    session: AsyncSession,
    google_sub: str,
) -> Optional[User_Table]:
    statement = select(User_Table).where(User_Table.usr_google_sub == google_sub)
    result = await session.exec(statement)
    return result.first()


# login: ช่องเดียวรับได้ทั้ง username หรืออีเมลที่สมัครไว้ - ถ้ามี "@" ลองหาเป็นอีเมล
# (ไม่สนตัวพิมพ์) ก่อน ไม่เจอค่อยลองเป็น username เผื่อ username เก่าที่มี "@"
async def authenticate_user(
    session: AsyncSession, 
    usr_name: str, 
    usr_passwd: str
) -> Optional[User_Table]:
    identifier = usr_name.strip()
    user = None
    if "@" in identifier:
        user = await get_user_by_email_casefold(session, identifier)
    if user is None:
        user = await get_user_by_username(session, identifier)
    # V2: ทำให้ใช้เวลาเท่ากันไม่ว่าจะมี user หรือไม่ - ถ้าไม่พบ user ก็ยัง verify กับแฮชหลอก
    # เพื่อกินเวลา Argon2 เท่าเดิม กัน username enumeration ผ่าน timing (ดู dummy_verify)
    if user is None:
        dummy_verify()
        return None
    if not verify_password(usr_passwd, user.usr_passwd):
        return None
    return user


# หน้าเว็บที่ 1 (Login.jsx): โหมด "สมัครสมาชิก" - เช็ค username/email ซ้ำเอง
# ก่อนสร้างจริง (ไม่ปล่อยให้ unique constraint ของ DB เป็นคนจับ) คืน None ถ้าซ้ำ
# แทนการ raise HTTPException ตรงๆ (layer นี้ไม่ควรผูกกับ FastAPI - pattern
# เดียวกับ crud อื่นใน crud_dev_info.py) ให้ router
# ตัดสินใจแปลงเป็น HTTP response เอง - usr_passwd แฮชด้วย Argon2
# (get_password_hash) ก่อนเก็บเสมอ ไม่เก็บ plaintext - usr_role เริ่มต้นเป็น
# "user" เสมอ (ไม่มีทางสมัครเป็น admin ผ่าน endpoint นี้ได้)
async def create_user(
    session: AsyncSession,
    user_create: UserCreate,
    *,
    google_sub: str | None = None,
    email_verified_at: datetime | None = None,
) -> Optional[User_Table]:
    # CM-09 defense-in-depth: caller ภายในที่สร้าง UserCreate แบบข้าม validation (เช่น model_construct)
    # ก็ยังสร้าง weak password ไม่ได้ - ตรวจ plaintext ก่อนแตะ DB/hash, raise ValueError ข้อความคงที่
    validate_account_password(user_create.usr_passwd)
    existing_by_name = await get_user_by_username(session, user_create.usr_name)
    if existing_by_name is not None:
        return None
    existing_by_email = await get_user_by_email_casefold(session, user_create.usr_email)
    if existing_by_email is not None:
        return None
    if google_sub is not None and await get_user_by_google_sub(session, google_sub) is not None:
        return None

    user = User_Table(
        usr_name=user_create.usr_name,
        usr_email=user_create.usr_email,
        usr_passwd=get_password_hash(user_create.usr_passwd),
        usr_role="user",
        usr_google_sub=google_sub,
        usr_email_verified_at=email_verified_at,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        # The pre-check improves the message, while DB uniqueness remains the
        # authority if two registrations race between check and commit.
        await session.rollback()
        return None
    await session.refresh(user)
    return user


# ตั้งรหัสผ่านใหม่ (กู้คืนรหัสผ่านทางอีเมล) และถอน token เดิมทุกใบในคำสั่งเดียว (CM-08)
#
# UPDATE เดียวเปลี่ยน hash + เพิ่ม usr_auth_version ฝั่ง database (ไม่อ่านมาบวกเอง กัน lost update
# ตอน reset พร้อมกัน) แล้ว commit ครั้งเดียว: ไม่มีทางที่รหัสเปลี่ยนแต่ version ไม่เพิ่มหรือกลับกัน
# commit ล้มเหลวต้อง rollback และ raise ให้ router คืน ticket เหมือนเดิม
# คืน version ใหม่ที่ commit แล้ว หรือ None ถ้า user ถูกลบไประหว่างทาง (ไม่มีอะไรเปลี่ยน)
async def update_user_password(session: AsyncSession, user: User_Table, new_password: str) -> Optional[int]:
    # CM-09: ตรวจ policy ก่อน hash และก่อนเริ่ม UPDATE - ไม่เปลี่ยน transaction เดียวของ CM-08
    validate_account_password(new_password)
    password_hash = get_password_hash(new_password)
    statement = (
        update(User_Table)
        .where(User_Table.usr_id == user.usr_id)
        .values(usr_passwd=password_hash, usr_auth_version=User_Table.usr_auth_version + 1)
        .returning(User_Table.usr_auth_version)
        .execution_options(synchronize_session=False)
    )
    try:
        new_version = (await session.exec(statement)).scalar_one_or_none()
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    if new_version is not None:
        # sync object ที่ caller ถืออยู่ให้ตรงกับค่าที่ commit แล้ว (ไม่ query ซ้ำ)
        user.usr_passwd = password_hash
        user.usr_auth_version = new_version
    return new_version


# หมายเหตุ: เดิมมี search_users_by_email() ที่ค้นแบบ ILIKE '%...%' อยู่ตรงนี้ - ถูกลบทิ้งแล้ว
# เพราะเปิดให้ส่ง "" มากวาด email ของ user ทุกคนในระบบได้ GET /users/lookup ใช้ get_user_by_email()
# (ค้นแบบตรงเป๊ะ ด้านบน) แทน ซึ่งเป็นฟังก์ชันตัวเดียวกับที่ flow เชิญสมาชิกจริงใช้อยู่แล้ว
# (site_router.py invite_member_by_email) - การใช้ฟังก์ชันเดียวกันทั้งตอน preview และตอนเชิญจริง
# การันตีว่าถ้า preview ขึ้นว่า "พบผู้ใช้" แล้วกดเชิญ จะต้องเจอ user คนเดิมเสมอ ไม่มีทางไม่ตรงกัน


# DELETE /users/me และ `sudo callmemanage user delete` - ลบ site ทุกแห่งที่ user
# เป็นเจ้าของพร้อมอุปกรณ์/ประวัติของ site นั้นก่อน แล้วลบ user - แถวอื่นที่เหลือ
# ไม่ต้องไล่ลบ child table เองทีละตารางเหมือน delete_device_full เพราะ FK ทุกตัวที่ชี้มาที่
# user_table (site_member/device_history/device_access/
# device_config_object/bootstrap_token) ถูกตั้ง ondelete=CASCADE หรือ
# SET NULL ไว้ที่ระดับ DB แล้ว (ดู alembic migration
# a1f4c9d02b7e_user_delete_cascades_and_site_owner_) - Postgres จัดการ
# cascade/null ให้เองทั้งหมดในทรานแซกชันเดียว
async def delete_user_full(
    session: AsyncSession, 
    usr_id: str
) -> bool:
    devices = []
    
    user = await session.get(User_Table, usr_id)
    if user is None:
        return False
    
    sites = await list_owned_sites_id(session, usr_id)
    if len(sites) > 0:
        get_devices_stmt = select(Device_Information.dev_id).where(Device_Information.site_id.in_(sites))
        devices = (await session.exec(get_devices_stmt)).all()

    # Phase 8: ลบ + ตัด session ภายใน lifecycle lock ของทุก dev_id ที่เกี่ยวข้อง (ชุดเดียวกับ activation/register) - ดู
    # backend/device_lifecycle.py ; hold() เรียง id ให้เอง จึงไม่ deadlock กับเส้นทางลบอื่น
    async with device_lifecycle.hold(*devices):
        if len(sites) > 0:
            if len(devices) > 0:
                await session.exec(delete(Device_Config_Object).where(Device_Config_Object.cfg_dev_id.in_(devices)))
                await session.exec(delete(Device_History).where(Device_History.his_dev_id.in_(devices)))
                await session.exec(delete(Device_Access).where(Device_Access.acc_dev_id.in_(devices)))
                await session.exec(delete(Device_Capability).where(Device_Capability.cap_dev_id.in_(devices)))

                await session.exec(delete(Device_Information).where(Device_Information.site_id.in_(sites)))

            await session.exec(delete(Site_Member).where(Site_Member.site_id.in_(sites)))
            await session.exec(delete(Site_Table).where(Site_Table.site_id.in_(sites)))

        await session.delete(user)
        await session.commit()

        # (bug 42) เส้นทางนี้ลบอุปกรณ์แบบ bulk (ไม่ผ่าน delete_device_full) จึงต้องตัด
        # call-home connection เองทีละตัว - เดิมใช้ sessions.pop() ซึ่งไม่ได้ปิด connection
        # จริง อุปกรณ์ยังเปิด SSH channel ค้างไว้และไม่ call-home ใหม่ (ดูเหตุผลเต็มใน
        # delete_device_full) - เรียกหลัง commit เสมอเพราะเป็น side-effect ที่ย้อนไม่ได้
        from backend.conn_socket import callhome_service
        for dev_id in devices:
            await callhome_service.close_session(dev_id, reason="ผู้ใช้ถูกลบ")

    return True
