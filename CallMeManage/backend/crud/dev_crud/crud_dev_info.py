""" |======= CRUD Device Information =======| """
# sql tools
import re

from sqlalchemy import func
from sqlmodel import select, or_, delete
from sqlmodel.ext.asyncio.session import AsyncSession

# import functions and table models
from backend.model.models import (
    Device_Information,
    Device_Capability,
    Device_Access,
    Device_History,
    Device_Config_Object,
    Site_Table,
    Site_Member,
    generate_timestamp,
)
from typing import List, Optional
from backend.schema.schema import DeviceUpdate
from backend.device_lifecycle import device_lifecycle
from backend.device_metadata_probe import MAX_FIELD_LENGTH, MAX_NAME_LENGTH, safe_display_value

# จำนวนสูงสุดที่สามารถเพิ่มอุปกรณ์ไว้รอได้
MAX_PENDING_DEVICES_PER_SITE = 200

async def update_device_connection_metadata(
    session: AsyncSession,
    dev_id: str,
    *,
    peer_ip: str | None,
    metadata,
) -> bool:
    """Refresh display metadata after an authenticated fingerprint reconnect.

    Authentication is already complete before this helper is called. Metadata
    is optional and never decides whether the device is accepted. Missing or
    unsafe values preserve the last known database value so a transient RPC
    failure cannot blank Device Info. MAC/serial are deliberately not read.
    """
    device = await session.get(Device_Information, dev_id)
    if device is None:
        return False

    if metadata is not None:
        hostname = safe_display_value(getattr(metadata, "hostname", None), MAX_NAME_LENGTH)
        model = safe_display_value(getattr(metadata, "model", None), MAX_FIELD_LENGTH)
        firmware = safe_display_value(getattr(metadata, "firmware", None), MAX_FIELD_LENGTH)
        if hostname:
            device.dev_name = hostname
        if model:
            device.dev_model = model
        if firmware:
            device.dev_firmware = firmware

    safe_ip = safe_display_value(peer_ip, MAX_FIELD_LENGTH)
    if safe_ip and safe_ip != "unknown":
        device.dev_ip = safe_ip
    device.dev_last_seen = generate_timestamp()
    session.add(device)
    await session.commit()
    return True


# ดึงข้อมูลอุปกรณ์ที่เก็บในฐานข้อมูลมาแสดง
async def get_device(
    session: AsyncSession, 
    dev_id: str
) -> Optional[Device_Information]:
    return await session.get(Device_Information, dev_id)

# ดึงรายการอุปกรณ์ทั้งหมดที่เชื่อมต่อเข้ามาในระบบ โดยไม่กรอง user สำหรับทำ debug (ไม่พบการเรียกใช้)
async def list_devices(
    session: AsyncSession, 
    skip: int = 0, 
    limit: int = 100
) -> List[Device_Information]:
    # ไม่กรอง owner - ใช้สำหรับ debug tool ที่ต้องเห็นอุปกรณ์ทุกตัวรวมถึงตัวที่
    # ยังเป็น pending ไม่มีเจ้าของด้วย
    statement = select(Device_Information).offset(skip).limit(limit)
    result = await session.exec(statement)
    return result.all()

# นับอุปกรณ์ที่ยังไม่ถูกเคลมที่ลงทะเบียนไว้ใน site
async def count_pending_by_site(
    session: AsyncSession, 
    site_id: str
) -> int:
    statement = select(func.count()).select_from(Device_Information).where(
        Device_Information.site_id == site_id,
        Device_Information.dev_status == "pending",
    )
    result = await session.exec(statement)
    return result.first() or 0

# แสดงรายการ id อุปกรณ์ทั้งหมดใน site นั้น (มีส่วนเกี่ยวข้องกับบัคของ api เรื่องลบและ commit อุปกรณ์ทีละตัว)
async def list_device_ids_for_site(
    session: AsyncSession, 
    site_id: str
) -> List[str]:
    # ใช้ตอน DELETE /sites/{id} (site_router.py) เพื่อรู้ว่าต้องเรียก delete_device_full ตัวไหนบ้างก่อนจะลบตัว Site_Table เอง (ตัวปัญหา)
    statement = select(Device_Information.dev_id).where(Device_Information.site_id == site_id)
    result = await session.exec(statement)
    return result.all()

# ดึงข้อมูล site แรกของ user ที่สร้างไว้ (ตัวปัญหาให้เกิดบัค)
async def get_first_owned_site(
    session: AsyncSession, 
    usr_id: str
) -> Optional[Site_Table]:
    statement = (
        select(Site_Table)
        .where(Site_Table.site_owner_id == usr_id)
        .order_by(Site_Table.site_created_date.asc())
        .limit(1)
    )
    result = await session.exec(statement)
    return result.first()

# ---------- One-Time Token flow (Phase 5) ----------
# ชื่อ pending ของ token flow: <vendor>-pending-N (counter ร่วมกันทั้ง Site ไม่แยกตาม vendor)
TOKEN_PENDING_NAME_PATTERN = re.compile(r"(?:cisco|juniper|huawei)-pending-([0-9]+)")


# เลขท้ายสูงสุดของชื่อรูปแบบ <vendor>-pending-N ใน Site (ทุก status - ชื่อชนกันได้ทุกแถว) 0 = ยังไม่มี
# ต้องเรียกหลัง lock แถว Site แล้วเท่านั้น (ดู device_enrollment_workflow) ไม่ใช้ COUNT เพราะลบหมายเลขกลางแล้วจะชนชื่อเดิม
async def get_max_token_pending_suffix(
    session: AsyncSession,
    site_id: str,
) -> int:
    statement = select(Device_Information.dev_name).where(
        Device_Information.site_id == site_id,
        Device_Information.dev_name.op("~")(r"^(cisco|juniper|huawei)-pending-[0-9]+$"),
    )
    result = await session.exec(statement)
    suffixes = [
        int(match.group(1))
        for name in result.all()
        if (match := TOKEN_PENDING_NAME_PATTERN.fullmatch(name))
    ]
    return max(suffixes, default=0)


# สร้าง pending Device ของ token flow: vendor จริง, MAC/Serial/fingerprint เป็น NULL (ไม่ใช้ placeholder)
# flush เพื่อให้ได้ dev_id แต่ไม่ commit - caller เป็นเจ้าของ transaction (ไม่แตะ pre_register_or_claim_device ของ legacy)
async def create_token_pending_device(
    session: AsyncSession,
    site_id: str,
    vendor: str,
    dev_name: str,
    commit: bool = False,
) -> Device_Information:
    device = Device_Information(
        dev_vendor=vendor,
        dev_model="",
        dev_firmware="",
        dev_name=dev_name,
        dev_ip="",
        dev_fingerprint=None,
        dev_status="pending",
        dev_registered=True,
        dev_viewed=False,
        site_id=site_id,
    )
    session.add(device)
    if commit:
        await session.commit()
        await session.refresh(device)
    else:
        await session.flush()
    return device


# ลบอุปกรณ์ตัวนั้นๆ และข้อมูลที่เกี่ยวข้องในตารางข้อมูลอื่นๆ (ลบทีละตัว เป็นปัญหาให้เกิดบัค)
async def delete_device_full(
    session: AsyncSession, 
    dev_id: str,
) -> bool:
    # Phase 8: ลบ + ตัด session ภายใน lifecycle lock ของ dev_id เดียวกับที่ activation/register ใช้ - กัน orphan session
    # (activation ที่ commit แล้วแต่ยังไม่ register จะได้ register ก่อนแล้วเราปิดให้ / ถ้าเราลบก่อน activation จะไม่พบ Device)
    async with device_lifecycle.hold(dev_id):
        return await _delete_device_full_locked(session, dev_id)


async def _delete_device_full_locked(
    session: AsyncSession,
    dev_id: str,
) -> bool:
    device = await session.get(Device_Information, dev_id)
    if device is None:
        return False

    await session.exec(delete(Device_Config_Object).where(Device_Config_Object.cfg_dev_id == dev_id))
    await session.exec(delete(Device_History).where(Device_History.his_dev_id == dev_id))
    await session.exec(delete(Device_Access).where(Device_Access.acc_dev_id == dev_id))
    await session.exec(delete(Device_Capability).where(Device_Capability.cap_dev_id == dev_id))
    await session.delete(device)
    await session.commit()

    # (bug 42) บังคับตัด call-home connection ทิ้งทันทีหลังลบอุปกรณ์สำเร็จ
    #
    # เดิมตรงนี้ใช้ sessions.pop()/stats.pop() ซึ่ง "ลืม" session ได้จริงแต่ไม่ได้ปิด
    # connection - อุปกรณ์ยังเปิด SSH channel ค้างไว้จึงไม่ call-home ใหม่ ลงทะเบียน
    # ตัวเดิมซ้ำแล้วค้าง pending นานไม่มีกำหนด และแย่กว่านั้นคือพอ pop ทิ้งแล้วก็ไม่
    # เหลือ reference ไปสั่งปิด connection ได้อีกเลย - เปลี่ยนมาเรียก close_session()
    # แทน แล้วปล่อยให้ finally ใน accept() ล้าง sessions/stats เองหลัง connection ปิด
    #
    # วางไว้ "หลัง" commit เสมอ: การตัด connection ย้อนกลับไม่ได้ ถ้าตัดก่อนแล้ว
    # transaction rollback จะได้อุปกรณ์ที่ยังอยู่ใน DB แต่โดนตัดการเชื่อมต่อฟรีๆ
    #
    # import ในฟังก์ชัน (ไม่ใช่หัวไฟล์) กัน circular import กับ callhome service
    from backend.conn_socket import callhome_service
    await callhome_service.close_session(dev_id, reason="อุปกรณ์ถูกลบออกจากระบบ")

    return True
    

# ดึงรายการข้อมูลอุปกรณ์ที่ผู้ใช้มีสิทธิในการเข้าถึงได้ โดยดึงข้อมูลเป็นชุด
# ใช้ device id ตัวสุดท้ายของชุดข้อมูลที่ดึงไปอ้างอิงในการดึงชุดต่อไป (None = ขอชุดแรกสุด)
# คืนมาไม่เกิน limit+1 ตัว เพื่อให้ผู้เรียกรู้ว่ามีต่ออีกไหมโดยไม่ต้อง COUNT ทั้งตาราง
async def list_devices_for_user(
    session: AsyncSession,
    usr_id: str,
    site_id: str,             # (add on bug 7) 
    after_dev_id: str | None = None,        # (add on bug 7)
    limit: int = 18,
) -> List[Device_Information]:
    # ดึง site id มาจากตาราง site_table กรณีเป็นเจ้าของ site
    owned_site_ids = select(Site_Table.site_id).where(Site_Table.site_owner_id == usr_id)
    # ดึง site id มาจากตาราง site_member กรณีที่เป็นสมาชิก site
    member_site_ids = select(Site_Member.site_id).where(
        Site_Member.usr_id == usr_id,
        Site_Member.status == "approved"
    )
    # ค้นหารายการอุปกรณ์โดยกรองด้วยข้อมูล site ที่ได้มา
    statement = select(Device_Information).where(
        or_(
            Device_Information.site_id.in_(owned_site_ids),
            Device_Information.site_id.in_(member_site_ids),
        )
    )

    # กรอง site_id จากชุดข้อมูลอุปกรณ์ทั้งหมดที่ผู้ใช้เข้าถึงได้ (add on bug 7)
    statement = statement.where(Device_Information.site_id == site_id)

    # ต้องมี ORDER BY ที่เสถียรและไม่ซ้ำ สำหรับชุดข้อมูลที่ดึงมา (add on bug 7)
    statement = statement.order_by(Device_Information.dev_name, Device_Information.dev_id)

    # cursor: ขอเฉพาะแถวที่ "มาหลัง" ตัวสุดท้ายของชุดก่อนหน้า ตาม sort key เดียวกัน (add on bug 7)
    if after_dev_id:
        cursor_device = await session.get(Device_Information, after_dev_id)
        if cursor_device is not None:
            statement = statement.where(
                or_(
                    Device_Information.dev_name > cursor_device.dev_name,
                    (Device_Information.dev_name == cursor_device.dev_name)
                    & (Device_Information.dev_id > cursor_device.dev_id),
                )
            )

    statement = statement.limit(limit + 1)  # ขอเกินมา 1 ตัว เพื่อเช็ค has_next (add on bug 7)
    result = await session.exec(statement)
    return result.all()

# update ข้อมูลอุปกรณ์ (ยังไม่เคยถูกเรียกใช้)
async def update_device(
    session: AsyncSession, 
    dev_id: str, 
    device_in: DeviceUpdate
) -> Optional[Device_Information]:
    device = await session.get(Device_Information, dev_id)
    if device is None:
        return None
    for field, value in device_in.model_dump(exclude_unset=True).items():
        setattr(device, field, value)
    session.add(device)
    await session.commit()
    await session.refresh(device)
    return device
