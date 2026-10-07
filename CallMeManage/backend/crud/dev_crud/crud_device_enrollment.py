""" |======= CRUD Device Enrollment (One-Time Enrollment Token) =======| """
# sql tools
import re
from datetime import datetime
from typing import Optional

from sqlmodel import or_, select, update, delete
from sqlmodel.ext.asyncio.session import AsyncSession

# import functions and table models
from backend.model.models import Device_Enrollment, Device_Information, generate_timestamp

# ชั้นนี้เป็นแค่ repository ของตาราง device_enrollment - ไม่สร้าง token, ไม่ hash, ไม่รู้จัก plaintext token
# token_hash ที่รับเข้ามาต้องเป็น SHA-256 hex digest (lowercase 64 ตัว) ที่ service ของ Phase 3 สร้างมาให้แล้ว
# ตรวจรูปแบบไว้เพื่อกัน caller ส่ง plaintext token ผ่านเข้ามาโดยไม่ตั้งใจ
#
# ทุกฟังก์ชันที่เขียนข้อมูลมี commit=False เป็นค่าเริ่มต้น: caller เป็นเจ้าของ transaction (Generate ต้องสร้าง
# Device + Enrollment ใน transaction เดียวกัน, activation ต้อง consume + pin fingerprint ใน transaction เดียวกัน)
# commit=False จะ flush เท่านั้น ให้ constraint ทำงานทันทีแต่ไม่ปิด transaction ของ caller
_TOKEN_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")


def _require_token_hash(token_hash: str) -> str:
    if not isinstance(token_hash, str) or not _TOKEN_HASH_PATTERN.fullmatch(token_hash):
        # ไม่ใส่ค่าที่รับเข้ามาในข้อความ error กัน plaintext token หลุดลง log
        raise ValueError("token_hash must be a lowercase SHA-256 hex digest (64 characters)")
    return token_hash


async def _finish(session: AsyncSession, commit: bool) -> None:
    if commit:
        await session.commit()
    else:
        await session.flush()


# สร้าง Pending Enrollment ให้ Device (token_hash มีค่า, consumed_at = NULL)
# device_id ซ้ำ / token_hash ซ้ำ จะโยน IntegrityError จาก unique constraint ให้ caller จัดการ (เช่น สุ่ม token ใหม่)
async def create_pending_enrollment(
    session: AsyncSession,
    device_id: str,
    token_hash: str,
    expires_at: Optional[datetime] = None,
    commit: bool = False,
) -> Device_Enrollment:
    enrollment = Device_Enrollment(
        device_id=device_id,
        token_hash=_require_token_hash(token_hash),
        expires_at=expires_at,
    )
    session.add(enrollment)
    await _finish(session, commit)
    return enrollment


# ดึง Enrollment ของ Device (ทั้ง pending และ consumed) - ใช้เป็น marker ว่า Device นี้ใช้ token authentication
async def get_enrollment_by_device_id(
    session: AsyncSession,
    device_id: str,
) -> Optional[Device_Enrollment]:
    statement = select(Device_Enrollment).where(Device_Enrollment.device_id == device_id)
    result = await session.exec(statement)
    return result.first()


async def get_pending_expirations_by_device_ids(
    session: AsyncSession,
    device_ids: list[str],
) -> dict[str, datetime]:
    """ดึงวันหมดอายุเป็นชุดเดียวสำหรับ Device list โดยไม่เกิด N+1 query"""
    if not device_ids:
        return {}
    statement = select(Device_Enrollment.device_id, Device_Enrollment.expires_at).where(
        Device_Enrollment.device_id.in_(device_ids),
        Device_Enrollment.token_hash.is_not(None),
        Device_Enrollment.consumed_at.is_(None),
        Device_Enrollment.expires_at.is_not(None),
    )
    result = await session.exec(statement)
    return {device_id: expires_at for device_id, expires_at in result.all()}


async def purge_long_expired_pending_devices(
    session: AsyncSession,
    *,
    expired_before: datetime,
    commit: bool = True,
) -> int:
    """ลบเฉพาะ token-pending Device ที่หมดอายุก่อน cutoff; FK cascade ลบ Enrollment"""
    expired_device_ids = select(Device_Enrollment.device_id).where(
        Device_Enrollment.token_hash.is_not(None),
        Device_Enrollment.consumed_at.is_(None),
        Device_Enrollment.expires_at.is_not(None),
        Device_Enrollment.expires_at <= expired_before,
    )
    statement = delete(Device_Information).where(
        Device_Information.dev_id.in_(expired_device_ids),
        Device_Information.dev_status == "pending",
        Device_Information.dev_fingerprint.is_(None),
    )
    result = await session.exec(statement)
    await _finish(session, commit)
    return int(result.rowcount or 0)


async def lock_enrollment_and_device_for_regeneration(
    session: AsyncSession,
    device_id: str,
) -> tuple[Optional[Device_Enrollment], Optional[Device_Information]]:
    """Lock ตามลำดับเดียวกับ activation และคืนค่าล่าสุดสำหรับตรวจ Regenerate"""
    enrollment = (await session.exec(
        select(Device_Enrollment)
        .where(Device_Enrollment.device_id == device_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )).first()
    device = (await session.exec(
        select(Device_Information)
        .where(Device_Information.dev_id == device_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )).first()
    return enrollment, device


async def replace_pending_enrollment_token(
    session: AsyncSession,
    enrollment_id: str,
    token_hash: str,
    expires_at: Optional[datetime] = None,
    commit: bool = False,
) -> bool:
    """แทน token ของ Enrollment แถวเดิม เฉพาะเมื่อยังไม่ถูก consume เท่านั้น"""
    statement = (
        update(Device_Enrollment)
        .where(
            Device_Enrollment.enrollment_id == enrollment_id,
            Device_Enrollment.token_hash.is_not(None),
            Device_Enrollment.consumed_at.is_(None),
        )
        .values(token_hash=_require_token_hash(token_hash), expires_at=expires_at)
        .execution_options(synchronize_session="fetch")
    )
    result = await session.exec(statement)
    await _finish(session, commit)
    return result.rowcount == 1


# ค้น Pending Enrollment ด้วย hash ของ token: คืนเฉพาะที่ token_hash ตรง, ยังไม่ถูก consume,
# Device ยังเป็น pending และยังไม่หมดอายุ (expires_at เป็น NULL = ไม่หมดอายุ)
async def get_pending_enrollment_by_token_hash(
    session: AsyncSession,
    token_hash: str,
    now: Optional[datetime] = None,
) -> Optional[Device_Enrollment]:
    now = now or generate_timestamp()
    statement = (
        select(Device_Enrollment)
        .join(Device_Information, Device_Information.dev_id == Device_Enrollment.device_id)
        .where(
            Device_Enrollment.token_hash == _require_token_hash(token_hash),
            Device_Enrollment.consumed_at.is_(None),
            Device_Information.dev_status == "pending",
            or_(Device_Enrollment.expires_at.is_(None), Device_Enrollment.expires_at > now),
        )
    )
    result = await session.exec(statement)
    return result.first()


# ค้น Pending Enrollments ด้วยกลุ่มของ token hashes: คืนเฉพาะที่ token_hash อยู่ในกลุ่ม, ยังไม่ถูก consume,
# Device ยังเป็น pending และยังไม่หมดอายุ (expires_at เป็น NULL = ไม่หมดอายุ)
async def get_pending_enrollments_by_token_hashes(
    session: AsyncSession,
    token_hashes: list[str] | set[str] | tuple[str, ...],
    now: Optional[datetime] = None,
) -> list[Device_Enrollment]:
    valid_hashes = [_require_token_hash(h) for h in set(token_hashes)]
    if not valid_hashes:
        return []
    now = now or generate_timestamp()
    statement = (
        select(Device_Enrollment)
        .join(Device_Information, Device_Information.dev_id == Device_Enrollment.device_id)
        .where(
            Device_Enrollment.token_hash.in_(valid_hashes),
            Device_Enrollment.consumed_at.is_(None),
            Device_Information.dev_status == "pending",
            or_(Device_Enrollment.expires_at.is_(None), Device_Enrollment.expires_at > now),
        )
    )
    result = await session.exec(statement)
    return list(result.all())


# consume แบบ conditional atomic: UPDATE เดียวที่เช็คเงื่อนไขและเปลี่ยนสถานะพร้อมกัน
# ถ้า 2 request consume พร้อมกัน ตัวที่สองจะรอ row lock แล้วประเมินเงื่อนไขใหม่หลังตัวแรก commit -> ไม่ตรง -> 0 แถว
# คืน True เฉพาะ request ที่ consume สำเร็จจริง (ไม่ใช่ "มีอยู่แล้ว")
# synchronize_session="fetch": object ที่ caller โหลดไว้ใน session เดียวกัน (โปรเจกต์ใช้ expire_on_commit=False) จะเห็นค่าใหม่ทันที
# ไม่ค้างเป็น token_hash เดิม
# ไม่แตะ Device_Information - การ pin fingerprint/เปลี่ยน Device เป็น active เป็นหน้าที่ของ caller ใน transaction เดียวกัน
async def mark_enrollment_consumed(
    session: AsyncSession,
    device_id: str,
    token_hash: str,
    now: Optional[datetime] = None,
    commit: bool = False,
) -> bool:
    now = now or generate_timestamp()
    still_pending_device = (
        select(Device_Information.dev_id)
        .where(Device_Information.dev_id == device_id, Device_Information.dev_status == "pending")
        .exists()
    )
    statement = (
        update(Device_Enrollment)
        .where(
            Device_Enrollment.device_id == device_id,
            Device_Enrollment.token_hash == _require_token_hash(token_hash),
            Device_Enrollment.consumed_at.is_(None),
            or_(Device_Enrollment.expires_at.is_(None), Device_Enrollment.expires_at > now),
            still_pending_device,
        )
        .values(token_hash=None, consumed_at=now)
        .execution_options(synchronize_session="fetch")
    )
    result = await session.exec(statement)
    await _finish(session, commit)
    return result.rowcount == 1


# ลบ/revoke Enrollment ของ Device (ใช้ตอนลบ pending card) คืน True ถ้ามีแถวถูกลบ
# การลบ Device เองไม่ต้องเรียกฟังก์ชันนี้ เพราะ FK เป็น ON DELETE CASCADE
async def delete_enrollment_for_device(
    session: AsyncSession,
    device_id: str,
    commit: bool = False,
) -> bool:
    statement = (
        delete(Device_Enrollment)
        .where(Device_Enrollment.device_id == device_id)
        .execution_options(synchronize_session="fetch")
    )
    result = await session.exec(statement)
    await _finish(session, commit)
    return result.rowcount > 0


# ---------- Call Home routing (Phase 7): read-only ----------

# Device ทุกตัวที่มี dev_fingerprint ตรงกับที่ transport ให้มา พร้อม Enrollment (ถ้ามี) - ให้ router ตัดสินแบบ fail closed
# (ไม่ใช้ .first(): พบมากกว่าหนึ่งต้อง reject ห้ามเลือกตัวแรก) fingerprint ว่าง/None = ไม่ query เลย
async def find_devices_by_fingerprint(
    session: AsyncSession,
    fingerprint: Optional[str],
) -> list[tuple[Device_Information, Optional[Device_Enrollment]]]:
    if not isinstance(fingerprint, str) or not fingerprint:
        return []
    statement = (
        select(Device_Information, Device_Enrollment)
        .join(Device_Enrollment, Device_Enrollment.device_id == Device_Information.dev_id, isouter=True)
        .where(Device_Information.dev_fingerprint == fingerprint)
        .limit(3)  # พอแยก 0/1/มากกว่า 1 - ไม่ดึงทั้งตารางถ้าข้อมูลเสีย
    )
    result = await session.exec(statement)
    return [(device, enrollment) for device, enrollment in result.all()]


# Device ตามหมายเลข (อ่านอย่างเดียว) ใช้ตอน resolve token
async def get_device_for_enrollment(session: AsyncSession, enrollment: Device_Enrollment) -> Optional[Device_Information]:
    return await session.get(Device_Information, enrollment.device_id)


# ตรวจสอบสถานะ active consumed enrollment สำหรับ session verification / reconnect guard
async def is_active_consumed_enrolled_device(
    session: AsyncSession,
    dev_id: str,
    vendor: str,
    fingerprint: str,
) -> bool:
    """ตรวจสอบว่า dev_id เป็นอุปกรณ์ active ที่ตรงกับ vendor, dev_fingerprint
    และมี Enrollment ในสถานะ consumed (token_hash is None, consumed_at is not None)
    """
    statement = (
        select(Device_Information, Device_Enrollment)
        .join(Device_Enrollment, Device_Information.dev_id == Device_Enrollment.device_id)
        .where(Device_Information.dev_id == dev_id)
    )
    result = await session.exec(statement)
    row = result.first()
    if not row:
        return False
    dev, enr = row
    if dev.dev_status != "active" or dev.dev_fingerprint != fingerprint or dev.dev_vendor != vendor:
        return False
    if enr.consumed_at is None or enr.token_hash is not None:
        return False
    return True
