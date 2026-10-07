""" |======= Device Identity Reset Service (One-Time Token Re-Arm) =======| """
# Phase 9: Reset Device Identity สำหรับ Device ที่ผ่าน Token Enrollment แล้ว
# - เปลี่ยนสถานะ: Device active -> pending, dev_fingerprint -> NULL, MAC/Serial -> NULL
#   (site_id, dev_id, dev_name, dev_model, dev_firmware, capability, config, history คงเดิม)
# - Re-arm Enrollment: token_hash = SHA-256(token ใหม่), consumed_at = NULL, expires_at = now + 24h
# - สองโหมด:
#   1. Online automatic (trusted session): เขียน marker ใหม่ลงอุปกรณ์ -> verify -> re-arm DB -> revoke session
#      (ถ้า DB ล้มหลัง writer สำเร็จ: compensate ลบเฉพาะ marker ใหม่ที่สร้าง -> verify; ถ้าชดเชยไม่ได้รายงาน unknown)
#   2. Offline recovery: คืน recovery CLI แสดงครั้งเดียว -> re-arm DB
# - Orchestration อยู่ใต้ device_lifecycle.hold(dev_id) เสมอ
# - ไม่ commit ใน helper ระดับล่าง; caller/orchestrator เป็นเจ้าของ transaction
# - Audit: action "reset_device_identity", detail มีแค่ mode+vendor (ห้าม token/hash/CLI/fingerprint/IP)

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.cli_generator import CLOUD_SERVER_IP, CLOUD_SERVER_PORT
from backend.callhome_identity_writer import (
    JUNIPER_VERIFY_WARNING,
    WriterError,
    compensate_marker_online,
    render_recovery_cli,
    write_marker_online,
)
from backend.conn_socket import callhome_service
from backend.core.connect_database import AsyncSessionFactory
from backend.core.redis_lock import DeviceLock, DeviceLockBusy
from backend.crud.dev_crud.crud_dev_history import create_history
from backend.crud.dev_crud.crud_device_enrollment import (
    get_enrollment_by_device_id,
    get_pending_enrollment_by_token_hash,
)
from backend.device_lifecycle import device_lifecycle
from backend.device_enrollment_workflow import ENROLLMENT_PENDING_TTL_HOURS
from backend.enrollment_token_service import (
    generate_enrollment_token,
    hash_enrollment_token,
)

from backend.model.models import Device_Enrollment, Device_Information

SUPPORTED_RESET_VENDORS = ("cisco", "juniper", "huawei")


class DeviceResetError(Exception):
    """Base exception สำหรับ Device Identity Reset"""
    def __init__(self, message: str = "Device identity reset failed"):
        super().__init__(message)


class DeviceNotFoundError(DeviceResetError):
    """ไม่พบอุปกรณ์ในระบบ (404)"""


class ResetEligibilityError(DeviceResetError):
    """อุปกรณ์ไม่อยู่ในเงื่อนไขที่สามารถ Reset Identity ได้ (400/409)"""


class ResetOnlineWriteError(DeviceResetError):
    """การเขียน marker ลงอุปกรณ์ผ่าน Call Home หรือการ verify ล้มเหลว (DB ยังคงเดิม)"""


class ResetDatabaseError(DeviceResetError):
    """การบันทึกฐานข้อมูลล้มเหลว (ในโหมด Online ได้ชดเชย marker กลับแล้ว)"""


class DeviceInconsistentStateError(DeviceResetError):
    """การบันทึก DB ล้มเหลวและไม่สามารถชดเชย marker บนอุปกรณ์ได้ (สถานะอุปกรณ์ unknown - 500)"""


@dataclass(frozen=True)
class ResetIdentityResult:
    mode: str  # "online" | "offline"
    device_id: str
    vendor: str
    expires_at: datetime
    cli: Optional[str] = None
    cli_steps: Optional[list] = None
    warning: Optional[str] = None


def _unwrap_row(row):
    if row is None:
        return None
    if isinstance(row, (tuple, list)) or hasattr(row, "_fields"):
        return row[0]
    if hasattr(row, "__getitem__") and not hasattr(row, "dev_status") and not hasattr(row, "enrollment_id"):
        try:
            return row[0]
        except (IndexError, TypeError, KeyError):
            pass
    return row


async def rearm_device_enrollment(
    session: AsyncSession,
    dev_id: str,
    expected_fingerprint: str,
    new_token_hash: str,
    expires_at: datetime,
    mode: str,
    usr_id: str,
) -> tuple[Device_Information, Device_Enrollment]:
    """Re-arm Device และ Enrollment ภายใน transaction โดยไม่ commit เอง
    Lock order: Enrollment -> Device -> audit
    Recheck: active, vendor, fingerprint == expected, consumed, token_hash NULL
    Mutate: dev pending + fingerprint NULL + MAC/Serial NULL; enr token_hash + consumed_at NULL + expires_at
    Audit: action='reset_device_identity', detail={'mode': mode, 'vendor': vendor}
    """
    # 1. Lock Enrollment row ก่อน
    enr_stmt = (
        select(Device_Enrollment)
        .where(Device_Enrollment.device_id == dev_id)
        .with_for_update()
    )
    enr_res = await session.exec(enr_stmt)
    enrollment = _unwrap_row(enr_res.first())
    if enrollment is None:
        raise ResetEligibilityError("Device has no enrollment record (cannot re-arm)")

    # 2. Lock Device row ตามลำดับ
    dev_stmt = (
        select(Device_Information)
        .where(Device_Information.dev_id == dev_id)
        .with_for_update()
    )
    dev_res = await session.exec(dev_stmt)
    device = _unwrap_row(dev_res.first())

    if device is None:
        raise DeviceNotFoundError("Device not found")


    # 3. Recheck Invariants
    if device.dev_status != "active":
        raise ResetEligibilityError(f"Device status is '{device.dev_status}', must be 'active'")
    if device.dev_vendor not in SUPPORTED_RESET_VENDORS:
        raise ResetEligibilityError(f"Vendor '{device.dev_vendor}' is not supported for reset identity")
    if device.dev_fingerprint != expected_fingerprint:
        raise ResetEligibilityError("Device fingerprint changed during reset operation")
    if enrollment.consumed_at is None or enrollment.token_hash is not None:
        raise ResetEligibilityError("Device enrollment is not in consumed state")

    # 4. Mutate State
    device.dev_status = "pending"
    device.dev_fingerprint = None

    enrollment.token_hash = new_token_hash
    enrollment.consumed_at = None
    enrollment.expires_at = expires_at

    # 5. Audit History (detail มีแค่ mode+vendor ห้าม token/hash/fingerprint/cli/ip)
    audit_detail = json.dumps(
        {"mode": mode, "vendor": device.dev_vendor},
        ensure_ascii=False,
    )
    await create_history(
        session,
        dev_id=dev_id,
        usr_id=usr_id,
        action="reset_device_identity",
        detail=audit_detail,
        commit=False,
    )

    await session.flush()
    return device, enrollment


async def reset_device_identity(
    dev_id: str,
    usr_id: str,
    session_factory=AsyncSessionFactory,
    *,
    force_offline: bool = False,
) -> ResetIdentityResult:
    """Orchestrate Device Identity Reset
    1. Lock dev_id ด้วย device_lifecycle.hold
    2. Pre-check device & enrollment eligibility ใน DB
    3. ตรวจสอบ trusted session:
       - ถ้า responsive + vendor ตรง + transport fingerprint ตรง + DB consumed -> Online Mode
       - ถ้าไม่มี session หรือ untrusted หรือ force_offline -> Offline Mode
    4. Online Mode:
       - Acquire Redis DeviceLock(dev_id)
       - สร้าง token ใหม่ + precheck hash
       - เขียน marker ใหม่ลงอุปกรณ์ + verify running config
       - re-arm DB transaction (ถ้าล้มเหลว -> compensate marker ลบเฉพาะ marker ใหม่)
       - revoke session (fail closed)
    5. Offline Mode:
       - สร้าง token ใหม่ + re-arm DB transaction (savepoint retry collision)
       - render recovery CLI แสดงครั้งเดียว
       - revoke any untrusted session
    """
    async with device_lifecycle.hold(dev_id):
        # step 1: Pre-check DB eligibility
        async with session_factory() as session:
            dev = await session.get(Device_Information, dev_id)
            if dev is None:
                raise DeviceNotFoundError("Device not found")
            if dev.dev_status != "active":
                raise ResetEligibilityError(
                    f"Device status is '{dev.dev_status}'. Only active devices can have their identity reset."
                )
            if dev.dev_vendor not in SUPPORTED_RESET_VENDORS:
                raise ResetEligibilityError(
                    f"Vendor '{dev.dev_vendor}' is not supported for reset identity (must be cisco, juniper, or huawei)."
                )
            if not dev.dev_fingerprint:
                raise ResetEligibilityError("Device does not have a pinned host key fingerprint.")

            enr = await get_enrollment_by_device_id(session, dev_id)
            if enr is None:
                raise ResetEligibilityError(
                    "Device has no enrollment record (legacy MAC/Serial devices cannot be reset via token)."
                )
            if enr.consumed_at is None or enr.token_hash is not None:
                raise ResetEligibilityError(
                    "Device enrollment is not in consumed state (token may already be pending)."
                )

            vendor = dev.dev_vendor
            fingerprint = dev.dev_fingerprint
            hostname = dev.dev_name or ""

        # step 2: Check trusted session
        is_online = False
        if not force_offline:
            is_online = await callhome_service.is_trusted_session(
                dev_id, expected_vendor=vendor, expected_fingerprint=fingerprint
            )

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=ENROLLMENT_PENDING_TTL_HOURS)

        if is_online:
            # ONLINE MODE
            async with DeviceLock(dev_id):
                token = generate_enrollment_token()
                token_hash = hash_enrollment_token(token)

                # precheck hash collision
                async with session_factory() as session:
                    existing = await get_pending_enrollment_by_token_hash(session, token_hash)
                    if existing is not None:
                        token = generate_enrollment_token()
                        token_hash = hash_enrollment_token(token)

                # write marker online & verify
                try:
                    await write_marker_online(
                        callhome_service,
                        dev_id,
                        vendor,
                        token,
                        cloud_ip=CLOUD_SERVER_IP,
                        cloud_port=CLOUD_SERVER_PORT,
                        hostname=hostname,
                    )
                except WriterError as exc:
                    # ถ้า write ถูกส่งไปแล้ว reply/verification อาจล้มทั้งที่ marker ถูก apply
                    # ต้องลบ marker ใหม่นี้กลับก่อนรายงาน failure เพื่อคง DB/session/config เดิม
                    if exc.marker_may_exist:
                        compensated = await compensate_marker_online(
                            callhome_service, dev_id, vendor, token
                        )
                        if not compensated:
                            raise DeviceInconsistentStateError(
                                "Online marker write could not be verified and compensation failed. Device state is unknown."
                            ) from exc
                    raise ResetOnlineWriteError(
                        "Online marker configuration failed; the existing identity was preserved."
                    ) from exc
                except Exception as exc:
                    # error ก่อน/นอก writer contract: DB และ session ยังไม่ถูกเปลี่ยน
                    raise ResetOnlineWriteError(
                        "Online marker configuration failed; the existing identity was preserved."
                    ) from exc

                # re-arm DB transaction
                try:
                    async with session_factory() as session:
                        try:
                            await rearm_device_enrollment(
                                session,
                                dev_id=dev_id,
                                expected_fingerprint=fingerprint,
                                new_token_hash=token_hash,
                                expires_at=expires_at,
                                mode="online",
                                usr_id=usr_id,
                            )
                            await session.commit()
                        except Exception:
                            await session.rollback()
                            raise
                except Exception as db_exc:
                    # DB commit failed -> MUST COMPENSATE
                    print(f"[!] DB rearm failed after online write for {dev_id}. Initiating compensation...")
                    compensated = await compensate_marker_online(
                        callhome_service, dev_id, vendor, token
                    )
                    if compensated:
                        raise ResetDatabaseError(
                            "Database update failed after writing marker. The marker was successfully rolled back from the device."
                        ) from db_exc
                    else:
                        raise DeviceInconsistentStateError(
                            "Database update failed and marker compensation also failed. Device state is unknown."
                        ) from db_exc

                # DB commit succeeded -> revoke session (fail closed)
                current_conn = callhome_service.sessions.get(dev_id, {}).get("connection")
                callhome_service.revoke_session(dev_id, connection=current_conn)

                warning = JUNIPER_VERIFY_WARNING if vendor == "juniper" else None
                return ResetIdentityResult(
                    mode="online",
                    device_id=dev_id,
                    vendor=vendor,
                    expires_at=expires_at,
                    warning=warning,
                )
        else:
            # OFFLINE MODE
            max_retries = 3
            token = ""
            token_hash = ""
            for attempt in range(max_retries):
                token = generate_enrollment_token()
                token_hash = hash_enrollment_token(token)
                try:
                    async with session_factory() as session:
                        try:
                            async with session.begin_nested():
                                await rearm_device_enrollment(
                                    session,
                                    dev_id=dev_id,
                                    expected_fingerprint=fingerprint,
                                    new_token_hash=token_hash,
                                    expires_at=expires_at,
                                    mode="offline",
                                    usr_id=usr_id,
                                )
                            await session.commit()
                            break
                        except IntegrityError:
                            await session.rollback()
                            if attempt == max_retries - 1:
                                raise
                except IntegrityError:
                    if attempt == max_retries - 1:
                        raise ResetDatabaseError("Failed to generate a unique token after multiple attempts.")

            # Revoke any untrusted session if exists in pool
            if dev_id in callhome_service.sessions:
                callhome_service.revoke_session(dev_id)

            recovery_data = render_recovery_cli(
                vendor=vendor,
                token=token,
                cloud_ip=CLOUD_SERVER_IP,
                cloud_port=CLOUD_SERVER_PORT,
                hostname=hostname,
            )

            return ResetIdentityResult(
                mode="offline",
                device_id=dev_id,
                vendor=vendor,
                expires_at=expires_at,
                cli=recovery_data.get("cli"),
                cli_steps=recovery_data.get("cli_steps"),
            )
