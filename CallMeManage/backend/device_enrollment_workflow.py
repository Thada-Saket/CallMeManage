""" |======= Token Enrollment Workflow (Pending Device + Enrollment + Bootstrap payload, one transaction) =======| """
# Phase 5: /cli/generate ที่มี site_id ใช้ flow นี้ - ทุกอย่างอยู่ใน transaction เดียวของ caller:
#   lock Site -> quota -> ชื่อ pending -> Device (flush) -> Enrollment (Phase 3 service) -> Bootstrap Token (cisco/juniper)
#   -> token-aware CLI -> ตรวจ payload ไม่มี token -> เก็บ payload (flush)
# ไฟล์นี้ "ไม่ commit และไม่ rollback" เลย: caller (router) commit ครั้งเดียวเมื่อสำเร็จ และ rollback เมื่อล้มเหลว
# plaintext token ไม่ถูก log/print หรือใส่ใน error/pending name; สำหรับ Cisco/Juniper จะอยู่ใน Bootstrap payload
# ชั่วคราวตามข้อกำหนดเพื่อให้อุปกรณ์โหลด Call Home config พร้อม config ก้อนเดียว
# การตรวจสิทธิ์ Site (RBAC) ทำที่ router ก่อนเรียก - ที่นี่รับ site_id ที่ผ่านสิทธิ์แล้ว
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.cli_generator import CLOUD_SERVER_IP, generate_cli
from backend.core.load_environment import load_environment
from backend.crud.dev_crud.crud_dev_info import (
    MAX_PENDING_DEVICES_PER_SITE,
    count_pending_by_site,
    create_token_pending_device,
    get_max_token_pending_suffix,
)
from backend.crud.dev_crud.crud_device_enrollment import lock_enrollment_and_device_for_regeneration
from backend.crud.web_crud.crud_bootstrap_token import create_bootstrap_token, set_config_payload
from backend.enrollment_token_service import (
    EnrollmentTokenCollisionError,
    EnrollmentNotPendingError,
    create_unique_pending_enrollment,
    rotate_pending_enrollment_token,
)
from backend.model.models import Site_Table

# นโยบายอายุของ Pending Enrollment Token (ที่เดียว) - 24 ชม. ให้เวลาผู้ใช้เดินไปวาง CLI บนอุปกรณ์จริง
# ไม่ใช้ TTL 5 นาทีของ Bootstrap Token (คนละหน้าที่: อันนั้นคือดาวน์โหลด config ครั้งเดียว)
ENROLLMENT_PENDING_TTL_HOURS = 24

SUPPORTED_VENDORS = ("cisco", "juniper", "huawei")
# vendor ที่ generator ใช้ Bootstrap Token (ดาวน์โหลด boilerplate) - Huawei วาง CLI ตรงไม่ใช้
BOOTSTRAP_VENDORS = ("cisco", "juniper")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EnrollmentWorkflowError(Exception):
    """error ที่ sanitized แล้ว (ไม่มี token/hash/Bootstrap Token/SQL parameters) พร้อม HTTP status ที่แนะนำ"""

    status_code = 500
    detail = "Could not generate the CLI. Please try again."

    def __init__(self, detail: Optional[str] = None):
        if detail is not None:
            self.detail = detail
        super().__init__(self.detail)


class SiteNotFoundError(EnrollmentWorkflowError):
    status_code = 404
    detail = "Site not found."


class UnsupportedVendorError(EnrollmentWorkflowError):
    status_code = 400
    detail = "Unsupported vendor."


class PendingQuotaExceededError(EnrollmentWorkflowError):
    status_code = 400

    def __init__(self):
        super().__init__(
            f"This site has reached the maximum limit of {MAX_PENDING_DEVICES_PER_SITE} pending devices. "
            "Please complete the connection process for existing devices or remove unused devices."
        )


class CliGenerationError(EnrollmentWorkflowError):
    """input ที่ generator ปฏิเสธ (ValueError) - แก้ได้ที่ผู้ใช้ จึงเป็น 400 เหมือน legacy"""

    status_code = 400


class EnrollmentPersistenceError(EnrollmentWorkflowError):
    status_code = 500


class PendingDeviceNotFoundError(EnrollmentWorkflowError):
    status_code = 404
    detail = "Pending device not found. Generate a new device instead."


@dataclass(frozen=True)
class EnrollmentCliResult:
    # response: Huawei มี token ใน cli; Cisco/Juniper มี token ใน boilerplate ที่ใช้เป็น Bootstrap payload
    # ไม่แสดง response ใน repr เพื่อไม่ให้ secret หลุดจากการ debug object
    response: dict = field(repr=False)
    device_id: str
    device_name: str


async def _lock_site(session: AsyncSession, site_id: str) -> None:
    # row lock ของ Site: serialize Generate ภายใน Site เดียว (quota + ชื่อ pending) แต่ Site อื่นทำงานพร้อมกันได้
    result = await session.exec(select(Site_Table.site_id).where(Site_Table.site_id == site_id).with_for_update())
    if result.first() is None:
        raise SiteNotFoundError()


async def create_pending_enrollment_cli(
    session: AsyncSession,
    *,
    site_id: str,
    vendor: str,
    data: dict,
    user_id: str,
    pending_device_id: Optional[str] = None,
) -> EnrollmentCliResult:
    if vendor not in SUPPORTED_VENDORS:  # canonical เท่านั้น ไม่ normalize; ก่อนสร้างข้อมูลใด ๆ
        raise UnsupportedVendorError()

    await _lock_site(session, site_id)

    try:
        if pending_device_id:
            # Lock order ต้องตรง activation: Enrollment -> Device เพื่อไม่ deadlock เมื่ออุปกรณ์ Call Home
            enrollment, device = await lock_enrollment_and_device_for_regeneration(session, pending_device_id)
            if (
                enrollment is None
                or device is None
                or device.site_id != site_id
                or device.dev_status != "pending"
                or device.dev_fingerprint is not None
                or enrollment.token_hash is None
                or enrollment.consumed_at is not None
            ):
                raise PendingDeviceNotFoundError()
            # Vendor เป็น input ที่ผู้ใช้อาจเลือกผิดเช่นกัน จึงแก้บน Pending แถวเดิมได้
            # แต่ตั้งชื่อใหม่ด้วย counter ภายใต้ Site lock เพื่อไม่ชนชื่อเดิมใน brownfield
            if device.dev_vendor != vendor:
                device.dev_vendor = vendor
                device.dev_name = f"{vendor}-pending-{await get_max_token_pending_suffix(session, site_id) + 1}"
                session.add(device)
                await session.flush()
            generated = await rotate_pending_enrollment_token(
                session, enrollment, expires_at=_utcnow() + timedelta(hours=ENROLLMENT_PENDING_TTL_HOURS)
            )
        else:
            if await count_pending_by_site(session, site_id) >= MAX_PENDING_DEVICES_PER_SITE:
                raise PendingQuotaExceededError()
            name = f"{vendor}-pending-{await get_max_token_pending_suffix(session, site_id) + 1}"
            device = await create_token_pending_device(session, site_id, vendor, name)
            generated = await create_unique_pending_enrollment(
                session, device.dev_id, expires_at=_utcnow() + timedelta(hours=ENROLLMENT_PENDING_TTL_HOURS)
            )
    except EnrollmentTokenCollisionError:
        raise EnrollmentPersistenceError() from None
    except EnrollmentNotPendingError:
        raise PendingDeviceNotFoundError() from None
    except EnrollmentWorkflowError:
        raise
    except Exception:
        # ไม่ส่ง exception ต้นฉบับต่อ: SQL parameters ของ IntegrityError มี token hash ได้
        raise EnrollmentPersistenceError() from None

    render_data = dict(data)  # ไม่แตะ dict ของ caller; ไม่มี token/site_id ในนี้
    bootstrap_record = None
    try:
        if vendor in BOOTSTRAP_VENDORS:
            bootstrap_record = await create_bootstrap_token(session, user_id, commit=False)
            # BOOTSTRAP_BASE_URL from the config file, e.g. https://<site>/cmm/api behind a reverse
            # proxy at /cmm; empty = straight to this machine https://<call-home address>:<BACKEND_PORT>
            base_url = load_environment().bootstrap_base_url(CLOUD_SERVER_IP)
            render_data["bootstrap_config_url"] = f"{base_url}/bootstrap/{bootstrap_record.bst_token}/config.txt"

        rendered = generate_cli(vendor, render_data, enrollment_token=generated.token)

        if isinstance(rendered, dict):
            response = dict(rendered)
            boilerplate = response["boilerplate"]
            # Phase 10: Local Administrator password ห้ามอยู่ใน payload ที่ persist (generator ตรวจ hash ของ Juniper เอง)
            local_admin_password = render_data.get("local_admin_password")
            if local_admin_password and local_admin_password in boilerplate:
                raise EnrollmentPersistenceError()
            await set_config_payload(session, bootstrap_record, boilerplate, commit=False)
        else:
            response = {"cli": rendered}
    except EnrollmentWorkflowError:
        raise
    except ValueError as error:  # generator validation (ข้อความไม่มี token: ดู _validated_enrollment_token)
        raise CliGenerationError(str(error)) from None
    except Exception:
        raise EnrollmentPersistenceError() from None

    response["pending_device_id"] = device.dev_id
    response["pending_device_name"] = device.dev_name
    response["pending_device_status"] = device.dev_status
    response["pending_device_created_at"] = device.dev_added_date.isoformat()
    # Cisco และ Juniper มี bootstrap configuration url ที่มีอายุจำกัด (5 นาที) ส่งเวลาหมดอายุจริงให้ frontend นำไปนับถอยหลังเตือนผู้ใช้
    if bootstrap_record is not None and bootstrap_record.bst_expires_at is not None:
        response["bootstrap_expires_at"] = bootstrap_record.bst_expires_at.isoformat()
    return EnrollmentCliResult(response=response, device_id=device.dev_id, device_name=device.dev_name)
