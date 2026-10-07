""" |======= CRUD Site Information =======| """
import secrets
from typing import List, Optional, Tuple, Literal

from sqlalchemy import func
from sqlalchemy.orm import selectinload
from sqlmodel import delete, select
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

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
from backend.schema.site_schema import SiteCreate
from backend.crud.dev_crud.crud_dev_info import list_device_ids_for_site
from backend.device_lifecycle import device_lifecycle

def generate_org_id(length: int = 12) -> str:
    ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    suffix = "".join(secrets.choice(ALPHABET) for _ in range(length))
    return f"ORG-{suffix}"

# ฟังก์ชั่นสร้าง site งาน
async def create_site(
    session: AsyncSession, 
    usr_id: str, 
    site_in: SiteCreate
) -> Site_Table:
    # รับข้อมูลจาก schema SiteCreate มาใส่ตาราง site_table
    new_ord_id = generate_org_id()

    site = Site_Table(
        org_id=new_ord_id,
        site_name=site_in.site_name,
        site_owner_id=usr_id,
    )
    session.add(site)
    # apply ข้อมูลเข้า db ให้ข้อมูลปรากฏจริง แต่ยังไม่ commit
    await session.flush()

    # เพิ่มข้อมูล site ใหม่เข้าไปในตาราง site_member พร้อม id ผู้สร้างในฐานะ member
    session.add(
        Site_Member(
            site_id=site.site_id, 
            usr_id=usr_id, 
            role="member", 
            status="approved"
        )
    )
    # บันทึกการเปลี่ยนแปลงบน db
    await session.commit()
    await session.refresh(site)
    return site

# ฟังก์ชั่นดึงข้อมูล site ที่ระบุ โดยใช้ site_id
async def get_site(
    session: AsyncSession, 
    site_id: str
) -> Optional[Site_Table]:
    return await session.get(Site_Table, site_id)


async def rename_site(
    session: AsyncSession,
    site_id: str,
    site_name: str,
) -> Optional[Site_Table]:
    """Rename one site while holding a row lock until the transaction commits."""
    statement = select(Site_Table).where(Site_Table.site_id == site_id).with_for_update()
    result = await session.exec(statement)
    site = result.first()
    if site is None:
        return None

    site.site_name = site_name
    session.add(site)
    await session.commit()
    await session.refresh(site)
    return site

# ฟังก์ชั่นดึงข้อมูล site ที่ระบุ โดยใช้ org_id - เป็นการค้นแบบ "ตรงเป๊ะ" (ไม่สนตัวพิมพ์เล็ก/ใหญ่)
# ใช้เป็นกลไกหลักของ GET /sites/lookup แทนการค้นแบบ substring เดิม (search_sites ที่ถูกลบไปแล้ว)
# ปลอดภัยโดยธรรมชาติ: org_id เป็น unique+index อยู่แล้ว (models.py) จึงคืนได้สูงสุด 1 แถวเสมอ
# ไม่ว่าจะส่ง input อะไรเข้ามา และใช้ index ได้เต็มที่ (ต่างจาก ILIKE '%...%' ที่ต้อง scan ทั้งตาราง)
async def get_site_by_org_id(
    session: AsyncSession,
    org_id: str
) -> Optional[Site_Table]:
    statement = select(Site_Table).where(func.lower(Site_Table.org_id) == org_id.lower())
    result = await session.exec(statement)
    return result.first()

# ฟังก์ชั่นนับจำนวนอุปกรณ์ทั้งหมดที่อยู่ใน site ที่ระบุ (นับทีละ site - ใช้เมื่อมี site เดียว)
# ถ้าต้องนับหลาย site พร้อมกัน ให้ใช้ count_devices_for_sites() แทน ไม่งั้นจะกลายเป็น N+1 query
async def count_devices_for_site(
    session: AsyncSession,
    site_id: str
) -> int:
    statement = select(func.count()).select_from(Device_Information).where(
        Device_Information.site_id == site_id
    )
    result = await session.exec(statement)
    return result.first() or 0

# นับจำนวนอุปกรณ์ของหลาย site พร้อมกันด้วย query เดียว (GROUP BY) แล้วคืนเป็น dict {site_id: จำนวน}
# แก้ปัญหา N+1: เดิม list_my_sites วนเรียก count_devices_for_site ทีละ site (100 site = 101 query)
# สำคัญ: site ที่ยังไม่มีอุปกรณ์เลยจะ "ไม่มี key" ใน dict ที่คืนกลับ (GROUP BY ไม่สร้างแถวให้กลุ่มว่าง)
# ผู้เรียกต้องใช้ .get(site_id, 0) เสมอ ไม่ใช่ [site_id] ตรงๆ ไม่งั้นสาขาที่เพิ่งสร้างจะพังทันที
# {"site_id-123123": 6} output
async def count_devices_for_sites(
    session: AsyncSession,
    site_ids: List[str],
) -> dict[str, int]:
    if not site_ids:
        return {}
    statement = (
        select(Device_Information.site_id, func.count())
        .where(Device_Information.site_id.in_(site_ids))
        .group_by(Device_Information.site_id)                   # ยุบข้อมูลที่หน้าตาเหมือนกันไว้ในแถวเดียว
    )
    result = await session.exec(statement)
    return {site_id: count for site_id, count in result.all()}

# ฟังก์ชั่นแสดงรายการ site ทั้งหมดที่เป็นเจ้าของ
# ขอเกินมา 1 แถว (limit+1) ให้ผู้เรียกรู้ว่ายังมีหน้าถัดไปไหม โดยไม่ต้องยิง COUNT(*) แยกอีก query
async def list_owned_sites(
    session: AsyncSession,
    usr_id: str,
    skip: int = 0,
    limit: int = 12,
) -> List[Site_Table]:
    statement = (
        select(Site_Table)
        .where(Site_Table.site_owner_id == usr_id)
        .order_by(Site_Table.site_created_date.asc(), Site_Table.site_id.asc())
        .offset(skip)
        .limit(limit + 1)
    )
    result = await session.exec(statement)
    return result.all()

async def list_owned_sites_id(
    session: AsyncSession,
    usr_id: str,
) -> List[Site_Table]:
    statement = (
        select(Site_Table.site_id)
        .where(Site_Table.site_owner_id == usr_id)
        .order_by(Site_Table.site_created_date.asc(), Site_Table.site_id.asc())
    )
    result = await session.exec(statement)
    return result.all()


# ฟังก์ชั่นแสดงรายการ site ทั้งหมดที่เป็นที่เข้าร่วม (ขอเกิน 1 แถวแบบเดียวกับ list_owned_sites)
async def list_joined_site_memberships(
    session: AsyncSession,
    usr_id: str,
    skip: int = 0,
    limit: int = 12,
) -> List[Site_Member]:
    statement = (
        select(Site_Member)
        .join(Site_Table, Site_Member.site_id == Site_Table.site_id)
        .where(Site_Member.usr_id == usr_id, Site_Table.site_owner_id != usr_id)
        .options(selectinload(Site_Member.site))
        .order_by(Site_Member.joined_date.asc(), Site_Member.site_id.asc())
        .offset(skip)
        .limit(limit + 1)
    )
    result = await session.exec(statement)
    return result.all()

# ดึงข้อมูล user ที่อยู่ภายใน site
async def get_site_member(
    session: AsyncSession, 
    site_id: str, 
    usr_id: str
) -> Optional[Site_Member]:
    return await session.get(Site_Member, (site_id, usr_id))

# ฟังก์ชั่นสำหรับผู้ใช้ทั่วไป ขอเข้าร่วม site
async def create_join_request(
    session: AsyncSession, 
    site_id: str, 
    usr_id: str
) -> Tuple[str, Optional[Site_Member]]:
    # ตรวจสอบการมีอยู่ของ site
    site = await get_site(session, site_id)
    if site is None:
        return "site_not_found", None
    
    # ตรวจสอบว่ามีความเกี่ยวข้องกับ site อยู่แล้วไหม
    if site.site_owner_id == usr_id:
        return "already_owner", None
    existing = await get_site_member(session, site_id, usr_id)
    if existing is not None:
        return "already_requested", existing

    # ถ้าผ่านเงื่อนไขก่อนหน้ามาได้ จะทำการสร้างข้อมูลใหม่ในตาราง site_member
    membership = Site_Member(
        site_id=site_id, 
        usr_id=usr_id, 
        role="member", 
        status="pending"
    )
    session.add(membership)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return "already_member", existing
    await session.refresh(membership)
    return "created", membership

# แสดงข้อมูลผู้ใช้ทั้งหมดที่อยู่ภายใน site
async def list_site_members(
    session: AsyncSession, 
    site_id: str
) -> List[Site_Member]:
    statement = (
        select(Site_Member)
        .where(Site_Member.site_id == site_id)
        .options(selectinload(Site_Member.user))
        .order_by(Site_Member.joined_date.asc())
    )
    result = await session.exec(statement)
    return result.all()

# เชิญผู้ใช้คนอื่นโดยตรงผ่าน username ไม่ต้องรอให้อีกฝ่ายตอบรับ เชิญแล้วทำงานได้เลย
async def add_member_directly(
    session: AsyncSession, 
    site_id: str, 
    target_usr_id: str, 
    role: Literal["admin", "member"] = "member"
) -> Tuple[str, Optional[Site_Member]]:
    # ตรวจสอบว่าผู้ใช้คนนี้อยู่ใน site แล้วหรือไม่
    existing = await get_site_member(session, site_id, target_usr_id)
    if existing is not None:
        return "already_member", existing

    # เพิ่มผู้ใช้ใหม่เข้าไปใน site
    membership = Site_Member(
        site_id=site_id, 
        usr_id=target_usr_id, 
        role=role, 
        status="approved"
    )
    session.add(membership)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return "already_member", existing
    await session.refresh(membership)
    return "created", membership

# ขอข้อมูลผู้ใช้ด้วย username
async def get_user_by_username(
    session: AsyncSession, 
    usr_name: str
) -> Optional[User_Table]:
    statement = select(User_Table).where(User_Table.usr_name == usr_name)
    result = await session.exec(statement)
    return result.first()

# อัปเดตสิทธิและสถานะของสมาชิก site
async def update_site_member(
    session: AsyncSession,
    site_id: str,
    target_usr_id: str,
    role: Optional[Literal["admin", "member"]] = None,
    status: Literal["pending", "approved", "invited"]  = None,
) -> Optional[Site_Member]:
    # ตรวจสอบความเกี่ยวข้องกับ site
    statement = (
        select(Site_Member)
        .where(Site_Member.site_id == site_id, Site_Member.usr_id == target_usr_id)
        .with_for_update()
    )
    result = await session.exec(statement)
    membership = result.first()
    if membership is None:
        return None
    # ตรวจสอบว่าค่าสิทธิและสถานะว่าเปล่าไหม
    if role is not None:
        membership.role = role
    if status is not None:
        membership.status = status
    # นำข้อมูลที่แก้ไขแล้วเข้า session แล้ว commit
    session.add(membership)
    await session.commit()
    await session.refresh(membership, attribute_names=["user"])
    # ส่งกลับค่าออกไปเพื่อแสดงการเปลี่ยนแปลง
    return membership

# ลบสมาชิกออกจาก site
async def remove_site_member(
    session: AsyncSession,
    site_id: str,
    target_usr_id: str,
    *,
    expected_status: Optional[Literal["pending", "approved", "invited"]] = None,
) -> str:
    # ล็อกแถวจนจบ transaction เพื่อให้ action จากหน้าจอเก่าไม่ลบสมาชิกที่สถานะ
    # เปลี่ยนไปแล้ว เช่น ผู้รับตอบรับ invitation พร้อมกับ Admin กด Cancel
    statement = (
        select(Site_Member)
        .where(Site_Member.site_id == site_id, Site_Member.usr_id == target_usr_id)
        .with_for_update()
    )
    result = await session.exec(statement)
    membership = result.first()
    if membership is None:
        return "not_found"
    if expected_status is not None and membership.status != expected_status:
        await session.rollback()
        return "status_changed"
    await session.delete(membership)
    await session.commit()
    return "removed"

# นับจำนวนสาขาที่เป็นเจ้าของทั้งหมด
async def count_owned_sites(session: AsyncSession, usr_id: str) -> int:
    statement = select(func.count()).select_from(Site_Table).where(Site_Table.site_owner_id == usr_id)
    result = await session.exec(statement)
    return result.first() or 0

# นับจำนวนสาขาที่เข้าร่วมทั้งหมด (ไม่รวมสาขาที่ตนเองเป็นเจ้าของ)
async def count_joined_site_memberships(session: AsyncSession, usr_id: str) -> int:
    statement = (
        select(func.count())
        .select_from(Site_Member)
        .join(Site_Table, Site_Member.site_id == Site_Table.site_id)
        .where(Site_Member.usr_id == usr_id, Site_Table.site_owner_id != usr_id)
    )
    result = await session.exec(statement)
    return result.first() or 0

# สร้างคำเชิญผู้ใช้ให้มาเข้าร่วม site
async def create_invite(
    session: AsyncSession, 
    site_id: str, 
    target_usr_id: str, 
    role: Literal["admin", "member"] = "member"
) -> Tuple[str, Optional[Site_Member]]:
    # เช็คว่าเป็นเจ้าของไหม
    site = await get_site(session, site_id)
    if site is not None and site.site_owner_id == target_usr_id:
        return "already_owner", None
    
    # เช็คว่าเข้าร่วม site แล้วใช่ไหม
    existing = await get_site_member(session, site_id, target_usr_id)
    if existing is not None:
        return "already_member", existing
    # เพิ่มผู้ใช้ใหม่เข้าตาราง site_member
    membership = Site_Member(
        site_id=site_id, 
        usr_id=target_usr_id, 
        role=role, 
        status="invited"
    )
    session.add(membership)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return "already_member", existing
    await session.refresh(membership)
    return "created", membership


# แสดงคำเชิญให้มาเข้าร่วม site ที่ผู้ใช้ได้รับ
async def list_user_invitations(session: AsyncSession, usr_id: str) -> List[Site_Member]:
    statement = (
        select(Site_Member)
        .where(Site_Member.usr_id == usr_id, Site_Member.status == "invited")
        .options(selectinload(Site_Member.site))
        .order_by(Site_Member.joined_date.asc())
    )
    result = await session.exec(statement)
    return result.all()


# ตอบกลับคำเชิญว่าจะเข้าร่วมหรือปฏิเสธ
async def respond_to_invitation(
    session: AsyncSession, 
    site_id: str, 
    usr_id: str, 
    accept: bool
) -> str:
    statement = (
        select(Site_Member)
        .where(Site_Member.site_id == site_id, Site_Member.usr_id == usr_id)
        .with_for_update()
    )
    result = await session.exec(statement)
    membership = result.first()
    if membership is None or membership.status != "invited":
        return "not_found"

    if accept:
        membership.status = "approved"
        session.add(membership)
        await session.commit()
        return "accepted"

    await session.delete(membership)
    await session.commit()
    return "rejected"


# ยกสิทธิความเป็นเจ้าของ site ให้ผู้ใช้อื่น
async def transfer_ownership(
    session: AsyncSession, 
    site_id: str, 
    new_owner_id: str
) -> Tuple[str, Optional[Site_Table]]:
    # ค้นหาว่า site นั้นมีจริงไหม
    site = await get_site(session, site_id)
    if site is None:
        return "site_not_found", None

    # ตรวจสอบว่าคนที่เลือกมีสิทธิได้รับยศต่อไหม
    new_owner_membership = await get_site_member(session, site_id, new_owner_id)
    if new_owner_membership is None or new_owner_membership.status != "approved":
        return "target_not_member", None

    # เปลี่ยนยศเจ้าของ site ให้บัญชีอื่น
    old_owner_id = site.site_owner_id
    site.site_owner_id = new_owner_id
    session.add(site)

    new_owner_membership.role = "member"
    session.add(new_owner_membership)

    old_owner_membership = await get_site_member(session, site_id, old_owner_id)
    if old_owner_membership is None:
        # ป้องกันการเตะตัวเองออกจาก site หลังจากมอบสิทธิให้คนอื่นแล้ว
        session.add(Site_Member(site_id=site_id, usr_id=old_owner_id, role="admin", status="approved"))
    else:
        old_owner_membership.role = "admin"
        old_owner_membership.status = "approved"
        session.add(old_owner_membership)
    
    await session.commit()
    await session.refresh(site)
    return "transferred", site


# ลบ site ทิ้ง พร้อมกับลบอุปกรณ์ภายในทั้งหมด
async def delete_site_full(
    session: AsyncSession, 
    site_id: str,
) -> bool:
    # ค้นหาว่า site นั้นมีจริงไหม
    site = await get_site(session, site_id)
    if site is None:
        return False

    # ดึงรายการอุปกรณ์ทุกตัวออกมาจาก site ที่ระบุ
    all_devices = await list_device_ids_for_site(session, site_id)
    # Phase 8: lock ต่อ dev_id ชุดเดียวกับ activation/register (เรียงตาม id ใน hold) - ดู backend/device_lifecycle.py
    async with device_lifecycle.hold(*all_devices):

        # ลูปลบอุปกรณ์ทีละตัวแบบไม่บันทึก
        for dev_id in all_devices:
            device = await session.get(Device_Information, dev_id)
            if site is None:
                return False
        
            await session.exec(delete(Device_Config_Object).where(Device_Config_Object.cfg_dev_id == dev_id))
            await session.exec(delete(Device_History).where(Device_History.his_dev_id == dev_id))
            await session.exec(delete(Device_Access).where(Device_Access.acc_dev_id == dev_id))
            await session.exec(delete(Device_Capability).where(Device_Capability.cap_dev_id == dev_id))
            await session.delete(device)
        # ลบ site พร้อมยืนยันการลบอุปกรณ์ทั้งหมด
        await session.exec(delete(Site_Member).where(Site_Member.site_id == site_id))
        await session.delete(site)
        await session.commit()

        # (bug 42 - ส่วนที่แก้ไม่ครบ พบ 3 กันยายน 2026) เส้นทางนี้ลบอุปกรณ์แบบ bulk ด้วย
        # loop ของตัวเอง **ไม่ได้เรียก delete_device_full** จึงไม่มีใครตัด call-home
        # connection ให้ - ตอนแก้ bug 42 รอบแรกเข้าใจผิดว่า site_router วนเรียก
        # delete_device_full อยู่แล้ว (เขียนไว้ในรายงานด้วย) แต่ไม่ได้เปิดไฟล์นี้ตรวจจริง
        #
        # อาการที่ผู้ใช้เจอ: ลบ site แล้วอุปกรณ์หายจากฐานข้อมูล แต่ session ยังค้างอยู่ใน
        # callhome_service.sessions ทำให้ _poll_stats_loop ยัง poll ต่อ และขึ้น
        # "stats poll failed for dev_xxx" ของอุปกรณ์ที่ไม่มีอยู่ในระบบแล้ว
        #
        # นี่เป็นเส้นทางลบอุปกรณ์เส้นที่ 3 (อีก 2 เส้นคือ delete_device_full และ
        # delete_user_full ซึ่งแก้ไปแล้วทั้งคู่) - เรียกหลัง commit เสมอเพราะการตัด
        # connection ย้อนกลับไม่ได้ ถ้าตัดก่อนแล้ว transaction rollback จะได้อุปกรณ์ที่ยัง
        # อยู่ใน DB แต่โดนตัดการเชื่อมต่อฟรี ๆ
        from backend.conn_socket import callhome_service
        for dev_id in all_devices:
            await callhome_service.close_session(dev_id, reason="site ถูกลบ")

    return True
