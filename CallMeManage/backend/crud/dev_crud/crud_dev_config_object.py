""" |======= CRUD Device Named Config =======| """

import json
from typing import List, Optional

# sql tools
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

# import table models
from backend.model.models import Device_Config_Object
from backend.schema.schema import DeviceConfigObjectCreate

# สร้างตารางชื่อให้กับ config ที่มีหลายค่าได้ แต่ตัวอุปกรณ์ไม่ได้มีการให้ตั้งชื่อ
async def create_config_object(
    session: AsyncSession, 
    dev_id: str, 
    usr_id: str, 
    object_in: DeviceConfigObjectCreate
) -> Device_Config_Object:
    entry = Device_Config_Object(
        cfg_dev_id=dev_id,
        cfg_created_by_id=usr_id,
        cfg_feature=object_in.cfg_feature,
        cfg_name=object_in.cfg_name,
        cfg_params=json.dumps(object_in.cfg_params),
    )
    session.add(entry)
    await session.flush()  # insert แถวนี้ก่อน ไม่งั้น FK ของ reference ที่จะเพิ่มต่อไปหาแถวที่ยังไม่มีจริงในตารางไม่ผ่าน

    await session.commit()
    await session.refresh(entry)
    return entry

# ดึงข้อมูล config (ยังไม่มีการเรียกใช้)
async def get_config_object(
        session: AsyncSession, 
        cfg_id: str
) -> Optional[Device_Config_Object]:
    return await session.get(Device_Config_Object, cfg_id)

# ดึงชื่อ config ที่ตั้ง
async def get_config_object_by_name(
    session: AsyncSession, 
    dev_id: str, 
    feature: str,
    name: str
) -> Optional[Device_Config_Object]:
    statement = select(Device_Config_Object).where(
        Device_Config_Object.cfg_dev_id == dev_id,
        Device_Config_Object.cfg_feature == feature,
        Device_Config_Object.cfg_name == name,
    )
    result = await session.exec(statement)
    return result.first()

# ดึงข้อมูลรายชื่อการ config ที่ตั้งไปทั้งหมด
async def list_config_objects(
    session: AsyncSession, 
    dev_id: str, 
    feature: Optional[str] = None
) -> List[Device_Config_Object]:
    statement = select(Device_Config_Object).where(Device_Config_Object.cfg_dev_id == dev_id)
    if feature is not None:
        statement = statement.where(Device_Config_Object.cfg_feature == feature)
    result = await session.exec(statement)
    return result.all()

# ลบ config ที่ตั้ง
async def delete_config_object(
    session: AsyncSession, 
    cfg_id: str
) -> bool:
    entry = await session.get(Device_Config_Object, cfg_id)
    if entry is None:
        return False
    await session.delete(entry)
    await session.commit()
    return True
