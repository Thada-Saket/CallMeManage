""" |======= API User Management =======| """

from typing import List, Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.core.security_audit import audit_security_event
from backend.api.user_deps import get_current_user, rate_limit_by_user
from backend.core.connect_database import get_session
from backend.crud.web_crud.crud_site import list_user_invitations, list_user_join_requests, respond_to_invitation
from backend.crud.web_crud.crud_user import delete_user_full, get_user_by_email
from backend.model.models import User_Table
from backend.schema.site_schema import InvitationRead
from backend.schema.user_schema import UserRead, UserSearchResult

router = APIRouter(prefix="/users", tags=["users"])

# จำกัดการยิง lookup ต่อผู้ใช้ 1 คน - กันไล่เดา email ทีละค่าเพื่อดูว่ามีบัญชีอยู่จริงไหม
# ตั้งไว้ 30 ครั้ง/นาที: เผื่อ SiteSettingsModal ที่ยิงเช็คอัตโนมัติระหว่างพิมพ์ (มี debounce อยู่แล้ว)
user_lookup_rate_limiter = rate_limit_by_user("ratelimit:user_lookup", limit=30, window_seconds=60)

# api สำหรับแสดงข้อมูลผู้ใช้
@router.get("/me", response_model=UserRead)
async def get_my_profile(current_user: User_Table = Depends(get_current_user)):
    return current_user

# api ตรวจสอบผู้ใช้จาก email แบบ "ตรงเป๊ะ" - คืน 0 หรือ 1 รายการ
# ใช้ตอนเชิญสมาชิกเข้าสาขา: ผู้เชิญพิมพ์ email ที่ตัวเองรู้อยู่แล้ว ระบบแค่ยืนยันว่ามีบัญชีนี้จริงไหม
# เดิมเป็น /search ที่ค้นแบบ substring ทำให้ส่ง "" หรือ "@gmail.com" มากวาด user ทั้งระบบได้
# ใช้ get_user_by_email() ตัวเดียวกับที่ flow เชิญจริงใช้ (site_router invite_member_by_email)
# เพื่อการันตีว่า preview ขึ้นว่า "พบผู้ใช้" แล้วกดเชิญจะต้องเจอคนเดิมเสมอ
@router.get(
    "/lookup",
    response_model=List[UserSearchResult],
    dependencies=[Depends(get_current_user), Depends(user_lookup_rate_limiter)],
)
async def lookup_user_route(
    email: Annotated[str, Query(min_length=1, max_length=100)],
    session: AsyncSession = Depends(get_session),
):
    # strip ก่อนค้นเสมอ - string ว่างตอบ "ไม่เจอ" ทันทีโดยไม่ต้องแตะ database
    cleaned = email.strip()
    if not cleaned:
        return []

    user = await get_user_by_email(session, cleaned)
    if user is None:
        return []

    return [UserSearchResult(usr_id=user.usr_id, usr_name=user.usr_name)]

# api ดึงรายการคำเชิญเข้าสาขาที่ยังไม่ได้ตอบรับ status="invited"
@router.get("/me/invitations", response_model=List[InvitationRead])
async def list_my_invitations_route(
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    memberships = await list_user_invitations(session, current_user.usr_id)
    return [
        InvitationRead(
            site_id=m.site.site_id,
            org_id=m.site.org_id,
            site_name=m.site.site_name,
            role=m.role,
            joined_date=m.joined_date,
        )
        for m in memberships
    ]

# api ดึงรายการคำขอเข้าร่วมสาขาที่ส่งไปแล้วและยังรออนุมัติ status="pending" - ใช้ schema
# เดียวกับคำเชิญ (field ชุดเดียวกัน: site/org/role/วันที่) ยกเลิกคำขอใช้ DELETE /sites/{id}/leave
@router.get("/me/join-requests", response_model=List[InvitationRead])
async def list_my_join_requests_route(
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    memberships = await list_user_join_requests(session, current_user.usr_id)
    return [
        InvitationRead(
            site_id=m.site.site_id,
            org_id=m.site.org_id,
            site_name=m.site.site_name,
            role=m.role,
            joined_date=m.joined_date,
        )
        for m in memberships
    ]

# api อัปเดต status ตอบรับคำเชิญเข้าสาขา
@router.patch("/me/invitations/{site_id}/accept")
async def accept_invitation_route(
    site_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    tag = await respond_to_invitation(session, site_id, current_user.usr_id, accept=True)
    if tag == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found")
    return {"detail": "Invitation accepted successfully"}

# api อัปเดต status ปฏิเสธคำเชิญเข้าสาขา
@router.patch("/me/invitations/{site_id}/reject")
async def reject_invitation_route(
    site_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    tag = await respond_to_invitation(session, site_id, current_user.usr_id, accept=False)
    if tag == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found")
    return {"detail": "Invitation rejected successfully"}

# api ลบบัญชีตัวเอง
@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_my_account_route(
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    await delete_user_full(session, current_user.usr_id)
    audit_security_event("user.account_delete", "SUCCEEDED", request=http_request,
                         actor_id=current_user.usr_id, user_id=current_user.usr_id)