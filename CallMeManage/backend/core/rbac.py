""" |======= Role Management =======| """

from typing import Optional

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.model.models import Site_Table, Site_Member

# ระดับสิทธิมี owner, admin, member, unauthorized
# ถ้ากดขอเข้าร่วมหรือเชิญแล้วแต่ยังไม่ตอบรับ = unauthorized
# ถ้าอนุมัติการเข้าร่วมหรือตอบรับแล้ว = role ที่กำหนดไว้ (admin/member)
# ถ้าโดนโอนสิทธิแล้ว = owner
# ทำหน้าที่ในการดึง role ของผู้ใช่
async def get_effective_role(
    session: AsyncSession, 
    usr_id: str, 
    site_id: Optional[str]
) -> str:
    if not site_id:
        return "unauthorized"

    site = await session.get(Site_Table, site_id)
    if site is None:
        return "unauthorized"
    if site.site_owner_id == usr_id:
        return "owner"

    statement = select(Site_Member).where(
        Site_Member.site_id == site_id,
        Site_Member.usr_id == usr_id,
        Site_Member.status == "approved",
    )
    result = await session.exec(statement)
    membership = result.first()
    if membership is not None:
        return membership.role

    return "unauthorized"

# เฉพาะเจ้าของและ Site Admin เท่านั้นที่จัดการสมาชิกได้ ส่วน member เข้าถึงและ
# ตั้งค่าอุปกรณ์ภายใน Site ได้ แต่ไม่มีสิทธิ์เปลี่ยนสมาชิกหรือสิทธิ์ของผู้อื่น
def can_manage_site(role: str) -> bool:
    return role in ("owner", "admin")
