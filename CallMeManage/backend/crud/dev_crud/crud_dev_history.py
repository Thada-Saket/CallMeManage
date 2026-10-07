""" |======= CRUD Device Named Config =======| """

from typing import List

# sql tools
from sqlmodel import select, or_
from sqlmodel.ext.asyncio.session import AsyncSession

# import table model
from backend.model.models import Device_History
from tools.history_redaction import sanitize_history_detail

async def create_history(
    session: AsyncSession, 
    dev_id: str, 
    usr_id: str, 
    action: str, 
    detail: str,
    commit: bool = True,
) -> Device_History:
    entry = Device_History(
        his_dev_id=dev_id,
        his_usr_id=usr_id,
        his_action=action,
        # Final persistence boundary: every caller, including transactions and
        # future features, receives the same recursive secret-redaction policy.
        his_action_detail=sanitize_history_detail(action, detail),
    )
    session.add(entry)
    if commit:
        await session.commit()
        await session.refresh(entry)
    else:
        await session.flush()
    return entry

# ดึงข้อมูลรายการประวัติการสั่งคำสั่งอุปกรณ์
async def list_history_by_device(
    session: AsyncSession, 
    dev_id: str, 
    after_his_id: str | None = None, 
    limit: int = 80
) -> List[Device_History]:
    statement = (
        select(Device_History)
        .where(Device_History.his_dev_id == dev_id)
        .order_by(Device_History.his_action_time.desc(), Device_History.his_id.desc())
    )
    if after_his_id:
        cursor = await session.get(Device_History, after_his_id)
        if cursor is not None:
            statement = statement.where(
                or_(
                    Device_History.his_action_time < cursor.his_action_time,
                    (Device_History.his_action_time == cursor.his_action_time)
                    & (Device_History.his_id < cursor.his_id)
                )
            )
    statement = statement.limit(limit + 1)
    result = await session.exec(statement)
    return result.all()
