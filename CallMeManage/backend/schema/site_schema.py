""" |======= Schema for site fetch and input data validation =======| """

from datetime import datetime
from typing import List, Optional, Literal

from pydantic import EmailStr, field_validator
from sqlmodel import SQLModel


# ตรวจสอบและตัดช่องว่างหัวท้ายของชื่อสาขา ต้องมีความยาวระหว่าง 5 ถึง 64 ตัวอักษร
def validate_site_name(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) < 5 or len(cleaned) > 64:
        raise ValueError("Site name must be between 5 and 64 characters")
    return cleaned


# schema สำหรับ validate input การสร้าง site
class SiteCreate(SQLModel):
    site_name: str

    @field_validator("site_name")
    @classmethod
    def validate_site_name_field(cls, value: str) -> str:
        return validate_site_name(value)


class SiteRenameRequest(SQLModel):
    site_name: str

    @field_validator("site_name")
    @classmethod
    def validate_site_name_field(cls, value: str) -> str:
        return validate_site_name(value)


class SiteRenameResponse(SQLModel):
    site_id: str
    site_name: str

# หน้า Sites.jsx แยก 2 หมวดชัดเจน (Owned/Joined) - ใช้คนละ schema กันเพราะ
# owned_sites ไม่มี my_role/my_status ให้แสดง (เป็นเจ้าของอยู่แล้ว ไม่ใช่สมาชิก)
# ต่างจาก joined_sites ที่ต้องรู้ role/status ของตัวเองในสาขานั้น

# schema สำหรับดำเนินการกับข้อมูล site ในฐานะเจ้าของ
class SiteOwnedSummary(SQLModel):
    site_id: str
    org_id: str
    site_name: str
    site_created_date: datetime
    device_count: int

# schema สำหรับดึงข้อมูล site ในฐานะสมาชิก
class SiteJoinedSummary(SQLModel):
    site_id: str
    org_id: str
    site_name: str
    site_created_date: datetime
    device_count: int
    my_role: str
    my_status: str

# schema สำหรับ 1 หน้าของรายการสาขาที่เป็นเจ้าของ - has_next บอกว่ายังมีหน้าถัดไปไหม
# total_count แสดงจำนวนสาขาที่เป็นเจ้าของทั้งหมดจริงที่นับจากฐานข้อมูล
class OwnedSitesPage(SQLModel):
    items: List[SiteOwnedSummary]
    has_next: bool = False
    total_count: int = 0

# schema สำหรับ 1 หน้าของรายการสาขาที่เข้าร่วม (แยก page กับ owned อิสระต่อกัน)
# total_count แสดงจำนวนสาขาที่เข้าร่วมทั้งหมดจริงที่นับจากฐานข้อมูล
class JoinedSitesPage(SQLModel):
    items: List[SiteJoinedSummary]
    has_next: bool = False
    total_count: int = 0

# schema สำหรับดึงข้อมูล site ที่มีความเกี่ยวข้องด้วยทั้งหมด (2 ชุด แบ่งหน้าแยกกัน)
class MySitesResponse(SQLModel):
    owned_sites: OwnedSitesPage
    joined_sites: JoinedSitesPage

# schema สำหรับแสดงข้อมูล site ที่ค้นเจอจาก org_id (ตรงเป๊ะ) - คืนได้สูงสุด 1 รายการเสมอ
class SiteLookupResult(SQLModel):
    site_id: str
    org_id: str
    site_name: str

# ---------- Site_Member ----------

# schema สำหรับ validate output ข้อมูลสมาชิกใน site
class SiteMemberRead(SQLModel):
    usr_id: str
    usr_name: str
    role: Literal["admin", "member"]
    status: Literal["pending", "approved", "invited"] 
    joined_date: datetime
    is_owner: bool = False
    is_current_user: bool = False

# schema สำหรับ validate input การเชิญเข้าร่วม site
class SiteMemberInvite(SQLModel):
    usr_name: str
    role: Literal["admin", "member"] = "member"

# schema สำหรับ validate input ข้อมูลการอัปเดตบทบาทใน site
class SiteMemberUpdate(SQLModel):
    role: Optional[Literal["admin", "member"]] = None
    status: Optional[Literal["pending", "approved", "invited"]] = None


# PATCH /sites/{id}/members/{usr_id}/role - endpoint แยกต่างหากสำหรับ
# เปลี่ยน role อย่างเดียว (ต่างจาก SiteMemberUpdate ด้านบนที่ทำได้ทั้ง
# role+status พร้อมกัน - ใช้ตอนอนุมัติ join request) ไม่รับ status เพราะจุดนี้
# มีไว้สลับ admin/member ของสมาชิกที่ approved อยู่แล้วเท่านั้น

# schema สำหรับ validate input ข้อมูลการอัปเดตบทบาทใน site
class SiteMemberRoleUpdate(SQLModel):
    role: Literal["admin", "member"]


# POST /sites/{id}/invite - ระบุด้วย email แทน username (SiteMemberInvite เดิม)
# เพราะ flow นี้คือ "ค้นหาแล้วเชิญ" ไม่ใช่ "รู้ username แน่ชัดแล้วเพิ่มตรงๆ" -
# สร้าง Site_Member สถานะ "invited" (ไม่ใช่ "approved" ทันทีเหมือน
# SiteMemberInvite) รอผู้ถูกเชิญกด accept/reject เอง (ดู planning เรื่อง
# invite-by-email flow ที่เอกสารเก่าพูดถึงไว้แต่ยังไม่เคย implement จริง)

# schema สำหรับ validate input การเชิญเข้าร่วม site ผ่าน email
class SiteMemberInviteByEmail(SQLModel):
    email: EmailStr


# PATCH /sites/{id}/transfer-owner - เฉพาะ Site Owner ปัจจุบันเรียกได้เท่านั้น
# (เข้มกว่า can_manage_site ที่ยอม admin ด้วย - ดู site_router.py's guard)

# schema สำหรับ validate input สำหรับแก้ไขความเป็นเจ้าของ site งาน
class TransferOwnerRequest(SQLModel):
    new_owner_usr_id: str


# GET /users/me/invitations - คำเชิญที่ผู้ใช้ล็อกอินยังไม่ได้ตอบรับ (status
# "invited" เท่านั้น - ไม่รวม "pending" ที่เป็นคำขอ join ที่ตัวเองส่งเองแล้วรอ
# owner/admin อนุมัติ ทิศทางตรงข้ามกัน)

# schema validate output สำหรับการดึงรายการ site ที่ถูกเชิญให้เข้าร่วม
class InvitationRead(SQLModel):
    site_id: str
    org_id: str
    site_name: str
    role: Literal["admin", "member"]
    joined_date: datetime
