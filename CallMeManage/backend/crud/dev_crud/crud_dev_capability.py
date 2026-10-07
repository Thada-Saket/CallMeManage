""" |======= CRUD Device Capability =======| """

import json
from typing import Optional

# import sql tools
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

# import table
from backend.model.models import Device_Capability, generate_timestamp

# key ใน cap_detail ที่เก็บโปรไฟล์ความสามารถของอุปกรณ์ (dynamic feature ขั้นที่ 3)
# hello ยังถูกเขียนทับทุกครั้งที่ call-home ตามเจตนาเดิม (เก็บสถานะล่าสุด ไม่ใช่ประวัติ) แต่โปรไฟล์
# ไม่ได้มาพร้อม hello - ได้จากคำสั่งแยกหลังเชื่อมต่อ และอาจข้ามการดึง schema เมื่อชุด schema
# ไม่เปลี่ยน จึงต้องคงไว้ข้ามการเขียน hello ใหม่
PROFILE_KEY = "profile"


def _load_detail(detail_json: Optional[str]) -> dict:
    try:
        detail = json.loads(detail_json) if detail_json else {}
    except (TypeError, ValueError):
        return {}
    return detail if isinstance(detail, dict) else {}


# รวม hello ใหม่เข้ากับ cap_detail เดิม: ข้อมูล hello ทับทั้งก้อน แต่คงโปรไฟล์เดิมไว้
def merge_hello_detail(existing_json: Optional[str], cap_detail: dict) -> str:
    detail = {key: value for key, value in cap_detail.items() if key != PROFILE_KEY}
    profile = _load_detail(existing_json).get(PROFILE_KEY)
    if isinstance(profile, dict):
        detail[PROFILE_KEY] = profile
    return json.dumps(detail, ensure_ascii=False)


# แทนเฉพาะโปรไฟล์ ไม่แตะข้อมูล hello
def merge_profile_detail(existing_json: Optional[str], profile: dict) -> str:
    detail = _load_detail(existing_json)
    detail[PROFILE_KEY] = profile
    return json.dumps(detail, ensure_ascii=False)


def extract_profile(detail_json: Optional[str]) -> Optional[dict]:
    profile = _load_detail(detail_json).get(PROFILE_KEY)
    return profile if isinstance(profile, dict) else None


# ดึงข้อมูลความสามารถของอุปกรณ์ที่เก็บในฐานข้อมูล
# for_update=True ล็อกแถวไว้จนจบทรานแซกชัน กันการเขียน hello กับการเขียนโปรไฟล์ทับกันเมื่ออุปกรณ์
# ต่อใหม่เร็ว ๆ ส่วน populate_existing ทำให้ได้ค่าล่าสุดจาก DB แม้ object จะอยู่ใน session แล้ว
async def get_capability(session: AsyncSession, dev_id: str, for_update: bool = False) -> Optional[Device_Capability]:
    statement = select(Device_Capability).where(Device_Capability.cap_dev_id == dev_id)
    if for_update:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    result = await session.exec(statement)
    return result.first()

# คำสั่งสำหรับเพิ่มหรืออัปเดต capability ใหม่
async def upsert_capability(
    session: AsyncSession, 
    dev_id: str, 
    vendor: str, 
    cap_detail: dict,
    commit: bool = True,
) -> Device_Capability:
    # รับค่า device id มาดึงข้อมูลเช็ค
    capability = await get_capability(session, dev_id, for_update=True)
    if capability is None:
        capability = Device_Capability(
            cap_dev_id=dev_id, 
            cap_vendor=vendor, 
            cap_detail=merge_hello_detail(None, cap_detail)
        )
    else:
        capability.cap_vendor = vendor
        capability.cap_detail = merge_hello_detail(capability.cap_detail, cap_detail)
        capability.cap_saved_date = generate_timestamp()

    # เพิ่มข้อมูล capability เข้าไปใน session ของ sqlAlchemy
    # sqlAlchemy .add มีระบบติดตาม object 
    # ถ้า add เข้ามาแล้วไม่เคยเห็นเลยจะเป็น insert แต่ถ้าเคยดึงมาแล้วจะเป็น update
    session.add(capability)
    # commit=False (Phase 8: activation เขียน capability ใน transaction เดียวกับ Device/Enrollment): flush อย่างเดียว
    # ไม่ commit/rollback transaction ของ caller - ค่าเริ่มต้น True คงพฤติกรรมเดิมของ caller ทุกตัว
    if commit:
        await session.commit()
        await session.refresh(capability)
    else:
        await session.flush()
    return capability

# อ่านโปรไฟล์ความสามารถ - None = ยังไม่เคยตรวจ หรือยังไม่มีแถว capability
async def get_capability_profile(session: AsyncSession, dev_id: str) -> Optional[dict]:
    capability = await get_capability(session, dev_id)
    return extract_profile(capability.cap_detail) if capability else None

# บันทึกโปรไฟล์โดยไม่แตะข้อมูล hello - คืน False ถ้ายังไม่มีแถว
# (ปกติแถวถูกสร้างตอน call-home ก่อนเริ่มตรวจเสมอ)
async def update_capability_profile(session: AsyncSession, dev_id: str, profile: dict) -> bool:
    capability = await get_capability(session, dev_id, for_update=True)
    if capability is None:
        return False
    capability.cap_detail = merge_profile_detail(capability.cap_detail, profile)
    session.add(capability)
    await session.commit()
    return True
