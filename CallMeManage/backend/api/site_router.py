""" |======= API Site Management =======| """

# fastapi and related tools
from typing import List, Annotated, Literal
from fastapi import APIRouter, Depends, HTTPException, Request, status, Query

# sql tools
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

# import crud tools
from backend.api.user_deps import get_current_user, rate_limit_by_user
from backend.core.connect_database import get_session
from backend.core.rbac import can_manage_site, get_effective_role
from backend.core.security_audit import audit_security_event
from backend.crud.web_crud.crud_site import (
    add_member_directly,
    count_devices_for_site,
    count_devices_for_sites,
    count_joined_site_memberships,
    count_owned_sites,
    create_invite,
    create_join_request,
    create_site,
    delete_site_full,
    get_site,
    get_site_by_org_id,
    get_user_by_username,
    list_joined_site_memberships,
    list_owned_sites,
    list_site_members,
    remove_site_member,
    rename_site,
    transfer_ownership,
    update_site_member,
)
from backend.crud.web_crud.crud_user import get_user_by_email

# import database models and schema validation
from backend.model.models import User_Table
from backend.schema.site_schema import (
    JoinedSitesPage,
    MySitesResponse,
    OwnedSitesPage,
    SiteCreate,
    SiteJoinedSummary,
    SiteLookupResult,
    SiteMemberInvite,
    SiteMemberInviteByEmail,
    SiteMemberRead,
    SiteMemberRoleUpdate,
    SiteMemberUpdate,
    SiteOwnedSummary,
    SiteRenameRequest,
    SiteRenameResponse,
    TransferOwnerRequest,
)

# api path [127.0.0.1:8000/sites]
router = APIRouter(prefix="/sites", tags=["sites"])

# จำนวนสาขาต่อข้อมูล 1 ชุด 
SITE_PAGE_SIZE = 12

# จำกัดการยิง lookup ต่อผู้ใช้ 1 คน ผู้ใช้จริงกดค้นหาทีละครั้งหลังพิมพ์เสร็จ ไม่มีทางแตะเพดานนี้
site_lookup_rate_limiter = rate_limit_by_user(
    "ratelimit:site_lookup", 
    limit=5, 
    window_seconds=60
)

# [127.0.0.1:8000/sites?owned_page=0&joined_page=0]
# เป็น root path ของ site ทำหน้าที่แสดงรายการ site ที่เป็นเจ้าของและเข้าร่วม แบ่งเป็นหน้าๆ
# สองชุด (owned/joined) แบ่งหน้าแยกอิสระต่อกัน กดเปลี่ยนหน้าฝั่งหนึ่งไม่กระทบอีกฝั่ง
@router.get("/", response_model=MySitesResponse)
async def list_my_sites(
    owned_page: Annotated[int, Query(ge=0)] = 0,
    joined_page: Annotated[int, Query(ge=0)] = 0,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # ทั้งสอง query (owned, memberships) ขอเกินมา 1 แถว (limit+1) เพื่อรู้ว่ามีหน้าถัดไปไหม แล้วตัดตัวเกินทิ้งก่อนส่งออก
    owned = await list_owned_sites(
        session, 
        current_user.usr_id, 
        skip=owned_page * SITE_PAGE_SIZE, 
        limit=SITE_PAGE_SIZE
    )                                                       # (12 + 1)
    owned_has_next = len(owned) > SITE_PAGE_SIZE            # true/false
    owned = owned[:SITE_PAGE_SIZE]                          # กรองให้เหลือเท่า limit 12

    memberships = await list_joined_site_memberships(
        session, 
        current_user.usr_id, 
        skip=joined_page * SITE_PAGE_SIZE, 
        limit=SITE_PAGE_SIZE
    )                                                       # (12 + 1)
    joined_has_next = len(memberships) > SITE_PAGE_SIZE     # true/false
    memberships = memberships[:SITE_PAGE_SIZE]              # กรองให้เหลือเท่า limit 12

    # นำ list รายชื่อ site ที่เข้าถึงได้ทั้งเป็นเจ้าของและเข้าร่วม มารวมกัน
    site_ids = [s.site_id for s in owned] + [m.site.site_id for m in memberships]

    # นับจำนวนอุปกรณ์ทั้งหมดภายใน site - output = {"site_id-123123": 6} 
    device_counts = await count_devices_for_sites(session, site_ids)

    # loop ตามจำนวน site มาเป็นชุดข้อมูลเอาไว้แสดงผล
    owned_summaries = [
        SiteOwnedSummary(
            site_id=site.site_id,
            org_id=site.org_id,
            site_name=site.site_name,
            site_created_date=site.site_created_date,
            device_count=device_counts.get(site.site_id, 0),   # ดึงข้อมูลด้วย key site_id ถ้าไม่เจอ ให้ค่าเริ่มต้นเป็น 0
        )
        for site in owned
    ]

    joined_summaries = [
        SiteJoinedSummary(
            site_id=m.site.site_id,
            org_id=m.site.org_id,
            site_name=m.site.site_name,
            site_created_date=m.site.site_created_date,
            device_count=device_counts.get(m.site.site_id, 0),
            my_role=m.role,
            my_status=m.status,
        )
        for m in memberships
    ]

    # นับจำนวนสาขาทั้งหมดจริงจาก database ไม่ขึ้นกับ pagination
    owned_total_count = await count_owned_sites(session, current_user.usr_id)
    joined_total_count = await count_joined_site_memberships(session, current_user.usr_id)

    return MySitesResponse(
        owned_sites=OwnedSitesPage(
            items=owned_summaries,
            has_next=owned_has_next,
            total_count=owned_total_count,
        ),
        joined_sites=JoinedSitesPage(
            items=joined_summaries,
            has_next=joined_has_next,
            total_count=joined_total_count,
        ),
    )

# [127.0.0.1:8000/sites/lookup?org_id="value"]
# ค้นหาสาขาด้วย org_id แบบ "ตรงเป๊ะ" (ไม่สนตัวพิมพ์เล็ก/ใหญ่) เพื่อขอเข้าร่วม - คืน 0 หรือ 1 รายการ
# เดิมเป็น /search ที่ค้นแบบ substring ทั้ง org_id และ site_name ทำให้ส่ง "" มากวาดชื่อสาขาของ
# ทุกองค์กรในระบบได้ - เปลี่ยนมาใช้ตรงเป๊ะเพราะ use case จริงคือ "เจ้าของสาขาบอก org_id มาให้แล้ว"
# (org_id ทำหน้าที่เหมือน invite code) ไม่ใช่การเปิดสมุดหน้าเหลืองให้เดินดูสาขาของคนอื่น
# ยัง response_model เป็น List อยู่เพื่อให้ frontend แสดงผลเป็นการ์ดเหมือนเดิมได้ (แค่มีได้ 0/1 ใบ)
@router.get(
    "/lookup",
    response_model=List[SiteLookupResult],
    dependencies=[Depends(get_current_user), Depends(site_lookup_rate_limiter)],
)
async def lookup_site_route(
    org_id: Annotated[str, Query(min_length=1, max_length=16)],
    session: AsyncSession = Depends(get_session),
):
    # strip ก่อนค้นเสมอ ถ้าเหลือ string ว่างให้ตอบ "ไม่เจอ" ไปเลย 
    cleaned = org_id.strip()
    if not cleaned:
        return []

    # ค้นหา site โดยใช้ input ที่กรอกมาแบบตัดคำแล้ว
    site = await get_site_by_org_id(session, cleaned)
    if site is None:
        return []

    return [
        SiteLookupResult(
            site_id=site.site_id,
            org_id=site.org_id,
            site_name=site.site_name,
        )
    ]

# [127.0.0.1:8000/sites] 
# root path เมื่อเป็น post request จะทำหน้าที่ในการสร้าง site ให้ผู้ใช้คนนั้นเป็นเจ้าของ
@router.post("/", response_model=SiteOwnedSummary, status_code=status.HTTP_201_CREATED)
async def create_site_route(
    site_in: SiteCreate,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    try:
        site = await create_site(session, current_user.usr_id, site_in)
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to create site — Organization/Site code is already in use.",
        )
    return SiteOwnedSummary(
        site_id=site.site_id,
        org_id=site.org_id,
        site_name=site.site_name,
        site_created_date=site.site_created_date,
        device_count=0,
    )


@router.patch("/{site_id}", response_model=SiteRenameResponse)
async def rename_site_route(
    site_id: str,
    rename_in: SiteRenameRequest,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Rename a site without changing its identity, members, or devices."""
    await _require_site_manage(session, site_id, current_user.usr_id)
    site = await rename_site(session, site_id, rename_in.site_name)
    if site is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found.")
    return SiteRenameResponse(site_id=site.site_id, site_name=site.site_name)

# [127.0.0.1:8000/sites/site_idxxxxx/join] 
# เป็น path ที่เมื่อ post request จะทำหน้าที่ขอเข้าร่วม site 
@router.post("/{site_id}/join")
async def join_site_route(
    site_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # ปุ่ม "ขอเข้าร่วม (Request to Join)" ใน Search & Join Modal - สร้าง
    # Site_Member ด้วย status="pending" รอเจ้าของ/Admin อนุมัติ
    tag, membership = await create_join_request(session, site_id, current_user.usr_id)
    if tag == "site_not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found.")
    if tag == "already_owner":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="You are already the owner of this site."
        )
    detail = ""
    if tag == "already_requested":
        if membership.status == "approved":
            detail = "You are already a member of this site."
        elif membership.status == "pending":
            detail = "You have already requested to join this site and are awaiting approval."
        elif membership.status == "invited":
            detail = "You have been invited to join this site, please check your invitation list."
        else :
            detail = "Unknown"
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
    return {"detail": detail}


# ต้องเป็น owner/admin ของ site นี้ถึงจะดูรายชื่อสมาชิกได้
# การจัดการสมาชิก (invite/approve/promote/remove) ต้องเป็น owner/admin เท่านั้น
# การโอนย้ายสิทธิความเป็นเจ้าของ ต้องเป็น Site Owner เท่านั้น

# เป็น function ตรวจสอบสิทธิผู้ใช้ในการเข้าถึง site
async def _require_site_access(
    session: AsyncSession, 
    site_id: str, 
    usr_id: str
) -> str:
    role = await get_effective_role(session, usr_id, site_id)
    if role == "unauthorized":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found.")
    return role

# เป็น function ตรวจสอบสิทธิผู้ใช้ในการจัดการดูแล site
async def _require_site_manage(session: AsyncSession, site_id: str, usr_id: str) -> str:
    role = await _require_site_access(session, site_id, usr_id)
    if not can_manage_site(role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the Site Owner or Site Admin can manage members",
        )
    return role

# เป็น function ตรวจสอบสิทธิการเป็นเจ้าของ
async def _require_site_owner(session: AsyncSession, site_id: str, usr_id: str):
    site = await get_site(session, site_id)
    if site is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    if site.site_owner_id != usr_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the Site Owner can perform this action",
        )
    return site

# [127.0.0.1:8000/sites/site_idxxxxx/members] 
# เป็น path ที่ใช้ขอข้อมูลรายชื่อสมาชิกภายใน site
@router.get("/{site_id}/members", response_model=List[SiteMemberRead])
async def list_site_members_route(
    site_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    site = await get_site(session, site_id)
    if site is None:
        raise HTTPException(404, "Site not found.")
    await _require_site_manage(session, site_id, current_user.usr_id)
    members = await list_site_members(session, site_id)
    return [
        SiteMemberRead(
            usr_id=m.usr_id,
            usr_name=m.user.usr_name,
            role=m.role,
            status=m.status,
            joined_date=m.joined_date,
            is_owner=m.usr_id == site.site_owner_id,
            is_current_user=m.usr_id == current_user.usr_id,
        )
        for m in members
    ]

# [127.0.0.1:8000/sites/site_idxxxxx/members] 
# เป็น path ที่เมื่อ post request จะทำหน้าที่เชิญผู้ใช้อื่นมาเข้าร่วม site ทันทีโดย username ไม่ต้องรอการตอบรับ (มีการสร้าง api บนหน้าเว็บ react แต่ยังไม่มีการนำไปใช้)
@router.post("/{site_id}/members", response_model=SiteMemberRead, status_code=status.HTTP_201_CREATED)
async def add_site_member_route(
    site_id: str,
    member_in: SiteMemberInvite,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    await _require_site_manage(session, site_id, current_user.usr_id)

    target_user = await get_user_by_username(session, member_in.usr_name)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{member_in.usr_name}' not found in the system.",
        )

    tag, membership = await add_member_directly(
        session, site_id, target_user.usr_id, member_in.role
    )
    if tag == "already_member":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"'{member_in.usr_name}' is already a member of this site.",
        )
    audit_security_event("site.member_add", "SUCCEEDED", request=http_request, actor_id=current_user.usr_id,
                         site_id=site_id, user_id=target_user.usr_id, role=membership.role, status=membership.status)
    return SiteMemberRead(
        usr_id=target_user.usr_id,
        usr_name=target_user.usr_name,
        role=membership.role,
        status=membership.status,
        joined_date=membership.joined_date,
    )

# [127.0.0.1:8000/sites/site_idxxxxx/members/usr_idxxxxx] 
# เป็น path ที่เมื่อ patch request จะทำหน้าที่ตอบรับคำขอเข้าร่วม site ของผู้ส่งคำขอ
@router.patch("/{site_id}/members/{usr_id}", response_model=SiteMemberRead)
async def update_site_member_route(
    site_id: str,
    usr_id: str,
    update_in: SiteMemberUpdate,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    await _require_site_manage(session, site_id, current_user.usr_id)

    if usr_id == current_user.usr_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot modify your own membership. Use Leave Site instead.",
        )

    site = await get_site(session, site_id)
    if site is None:
        raise HTTPException(404, "Site not found.")
    if site.site_owner_id == usr_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify Site Owner role through this channel - use 'Transfer Site Ownership' instead",
        )

    membership = await update_site_member(
        session, site_id, usr_id, role=update_in.role, status=update_in.status
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this site")
    audit_security_event("site.member_update", "SUCCEEDED", request=http_request, actor_id=current_user.usr_id,
                         site_id=site_id, user_id=usr_id, role=membership.role, status=membership.status)

    return SiteMemberRead(
        usr_id=membership.usr_id,
        usr_name=membership.user.usr_name,
        role=membership.role,
        status=membership.status,
        joined_date=membership.joined_date,
    )

# [127.0.0.1:8000/sites/site_idxxxxx/members/usr_idxxxxx] 
# เป็น path ที่เมื่อ delete request จะทำหน้าที่ปฏิเสธคำขอเข้าร่วมหรือลบผู้ใช้ออกจาก site
@router.delete("/{site_id}/members/{usr_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_site_member_route(
    site_id: str,
    usr_id: str,
    expected_status: Annotated[Literal["pending", "approved", "invited"], Query()],
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    await _require_site_manage(session, site_id, current_user.usr_id)

    if usr_id == current_user.usr_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove yourself here. Use Leave Site instead.",
        )

    site = await get_site(session, site_id)
    if site is None:
        raise HTTPException(404, "Site not found.")
    if site.site_owner_id == usr_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove Site Owner - use 'Transfer Site Ownership' or 'Delete Site' instead",
        )

    result = await remove_site_member(
        session, site_id, usr_id, expected_status=expected_status
    )
    if result == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this site")
    if result == "status_changed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This membership has changed. The latest member list has been loaded; review it before trying again.",
        )
    audit_security_event("site.member_remove", "SUCCEEDED", request=http_request, actor_id=current_user.usr_id,
                         site_id=site_id, user_id=usr_id, status=expected_status)

@router.delete("/{site_id}/leave", status_code=status.HTTP_204_NO_CONTENT)
async def leave_site_member(
    site_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    site = await get_site(session, site_id)
    if site is None:
        raise HTTPException(404, "Site not found.")
    if site.site_owner_id == current_user.usr_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='The site owner cannot leave the site. Please use "Transfer Site Ownership" or "Delete Site" instead.',
        )
    result = await remove_site_member(session, site_id, current_user.usr_id)
    if result == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.")
    audit_security_event("site.member_leave", "SUCCEEDED", request=http_request,
                         actor_id=current_user.usr_id, site_id=site_id, user_id=current_user.usr_id)

# [127.0.0.1:8000/sites/site_idxxxxx/invite] 
# เป็น path ที่เมื่อ post request จะทำหน้าที่เชิญผู้ใช้อื่นมาเข้าร่วม site (รอการตอบรับ)
@router.post("/{site_id}/invite", response_model=SiteMemberRead, status_code=status.HTTP_201_CREATED)
async def invite_site_member_route(
    site_id: str,
    invite_in: SiteMemberInviteByEmail,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    await _require_site_manage(session, site_id, current_user.usr_id)

    target_user = await get_user_by_email(session, invite_in.email)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email '{invite_in.email}' not found in the system.",
        )
    new_usr = target_user.usr_name
    # Invitations always begin with the least-privileged role. An owner/admin can
    # promote the user only after the invitation has been accepted.
    tag, membership = await create_invite(session, site_id, target_user.usr_id, "member")
    if tag == "already_owner":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="This user is already the owner of this site."
        )
    if tag == "already_member":
        detail = {
            "pending": f"'{new_usr}' has already requested to join this site and is awaiting your approval.",
            "invited": f"'{new_usr}' has already been invited and is awaiting their response.",
            "approved": f"'{new_usr}' is already a member of this site.",
        }.get(membership.status if membership else
  "approved", f"'{new_usr}' is already associated with this site.")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

    audit_security_event("site.member_invite", "SUCCEEDED", request=http_request, actor_id=current_user.usr_id,
                         site_id=site_id, user_id=target_user.usr_id, role=membership.role, status=membership.status)
    return SiteMemberRead(
        usr_id=target_user.usr_id,
        usr_name=target_user.usr_name,
        role=membership.role,
        status=membership.status,
        joined_date=membership.joined_date,
    )

# [127.0.0.1:8000/sites/site_idxxxxx/members/usr_idxxxxx/role] 
# เป็น path ที่เมื่อ patch request จะทำหน้าที่เปลี่ยนสิทธิผู้ใช้สำหรับทำงานภายใน site
@router.patch("/{site_id}/members/{usr_id}/role", response_model=SiteMemberRead)
async def update_site_member_role_route(
    site_id: str,
    usr_id: str,
    role_in: SiteMemberRoleUpdate,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    await _require_site_manage(session, site_id, current_user.usr_id)

    if usr_id == current_user.usr_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role. Use Leave Site instead.",
        )

    site_row = await get_site(session, site_id)
    if site_row is not None and site_row.site_owner_id == usr_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify Site Owner role through this channel - use 'Transfer Site Ownership' instead",
        )

    membership = await update_site_member(session, site_id, usr_id, role=role_in.role)
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this site")
    audit_security_event("site.member_role_change", "SUCCEEDED", request=http_request,
                         actor_id=current_user.usr_id, site_id=site_id, user_id=usr_id, role=membership.role)

    return SiteMemberRead(
        usr_id=membership.usr_id,
        usr_name=membership.user.usr_name,
        role=membership.role,
        status=membership.status,
        joined_date=membership.joined_date,
    )

# [127.0.0.1:8000/sites/site_idxxxxx/members/transfer-owner] 
# เป็น path ที่เมื่อ patch request จะทำหน้าที่เปลี่ยนสิทธิความเป็นเจ้าของ site ให้ผู้ใช้อื่นภายใน site
@router.patch("/{site_id}/transfer-owner", response_model=SiteOwnedSummary)
async def transfer_site_owner_route(
    site_id: str,
    transfer_in: TransferOwnerRequest,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    await _require_site_owner(session, site_id, current_user.usr_id)

    tag, site = await transfer_ownership(session, site_id, transfer_in.new_owner_usr_id)
    if tag == "site_not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    if tag == "target_not_member":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ownership can only be transferred to an approved member of this site",
        )
    audit_security_event("site.owner_transfer", "SUCCEEDED", request=http_request, actor_id=current_user.usr_id,
                         site_id=site_id, user_id=transfer_in.new_owner_usr_id, previous_owner_id=current_user.usr_id)

    return SiteOwnedSummary(
        site_id=site.site_id,
        org_id=site.org_id,
        site_name=site.site_name,
        site_created_date=site.site_created_date,
        device_count=await count_devices_for_site(session, site.site_id),
    )

# [127.0.0.1:8000/sites/site_idxxxxx] 
# เป็น path ที่เมื่อ delete request จะทำหน้าที่ลบสาขาทิ้งพร้อมอุปกรณ์ภายใน
@router.delete("/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site_route(
    site_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    await _require_site_owner(session, site_id, current_user.usr_id)
    
    await delete_site_full(session, site_id)
    audit_security_event("site.delete", "SUCCEEDED", request=http_request,
                         actor_id=current_user.usr_id, site_id=site_id)
