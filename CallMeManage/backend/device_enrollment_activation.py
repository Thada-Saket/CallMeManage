""" |======= Atomic One-Time Activation (Pending Device -> Active, consume token, pin fingerprint) =======| """
# Phase 8: เปลี่ยน pending Device "แถวเดิม" เป็น active ใน transaction ของ caller
#   lock Device_Enrollment -> lock Device_Information -> (capability ผ่าน upsert_capability(commit=False))
#   recheck ทุกเงื่อนไขจาก DB ล่าสุด (ไม่เชื่อ PendingEnrollmentCandidate เป็น source of truth) -> mutate -> flush
# ไฟล์นี้ "ไม่ commit, ไม่ rollback, ไม่ register session, ไม่แตะ session pool": caller (conn_socket) commit ครั้งเดียว
# แล้วจึง register session ; ถ้าล้มเหลวทุกแบบ caller rollback ทั้งก้อน (token hash/consumed_at/fingerprint/capability คืนหมด)
# whitelist field ที่เขียนเท่านั้น (ไม่ setattr ทั้งก้อน, ไม่รับ DeviceCreate/identity)
# fingerprint เต็ม/token hash/metadata ดิบ ไม่อยู่ใน repr และ error ; ข้อความสาธารณะเป็นข้อความเดียว
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.callhome_auth_router import PendingEnrollmentCandidate, short_id
from backend.crud.dev_crud.crud_dev_capability import upsert_capability
from backend.crud.dev_crud.crud_device_enrollment import mark_enrollment_consumed
from backend.device_metadata_probe import MAX_FIELD_LENGTH, MAX_NAME_LENGTH, DeviceMetadata, safe_display_value
from backend.model.models import Device_Enrollment, Device_Information, generate_timestamp

FINGERPRINT_UNIQUE_CONSTRAINT = "uq_device_information_dev_fingerprint"
MAX_FINGERPRINT_LENGTH = 200  # SHA256:<43 chars> ยาวราว 50 ; เผื่อ algorithm อื่นแต่จำกัดขอบเขต
PUBLIC_MESSAGE = "Enrollment credential was not accepted"


class ActivationReason(Enum):
    """เหตุผลภายใน (test/metric) - ห้ามส่งออกทางข้อความสาธารณะ"""
    INVALID_FINGERPRINT = "invalid_fingerprint"
    ENROLLMENT_NOT_FOUND = "enrollment_not_found"
    ENROLLMENT_MISMATCH = "enrollment_mismatch"
    TOKEN_CHANGED = "token_changed"
    EXPIRED = "expired"
    ALREADY_CONSUMED = "already_consumed"
    DEVICE_NOT_FOUND = "device_not_found"
    DEVICE_NOT_PENDING = "device_not_pending"
    VENDOR_MISMATCH = "vendor_mismatch"
    INVARIANT_VIOLATION = "invariant_violation"
    LOST_RACE = "lost_race"
    FINGERPRINT_IN_USE = "fingerprint_in_use"
    PERSISTENCE = "persistence"


class ActivationError(Exception):
    """base: ข้อความคงที่ ไม่มี token/hash/fingerprint/metadata"""
    event = "rejected"

    def __init__(self, reason: ActivationReason):
        self.reason = reason
        super().__init__(PUBLIC_MESSAGE)


class ActivationRejected(ActivationError):
    """credential/state ไม่ตรง (รวมค่าที่เปลี่ยนไประหว่าง Phase 7 resolve กับ claim)"""
    event = "rejected"


class ActivationConflict(ActivationError):
    """แพ้ race (อีก connection consume/เปลี่ยน state ไปก่อน)"""
    event = "conflict"


class FingerprintAlreadyUsed(ActivationError):
    """host key นี้ถูก pin ให้ Device อื่นแล้ว (unique constraint เป็นผู้ตัดสิน) - token ของผู้แพ้ยังใช้ได้กับ key ที่ถูกต้อง"""
    event = "conflict"


class ActivationPersistenceError(ActivationError):
    event = "persistence_error"


@dataclass(frozen=True)
class ActivationResult:
    device_id: str
    vendor: str
    fingerprint: str = field(repr=False)

    def __repr__(self) -> str:
        return f"ActivationResult(device_id={self.device_id!r}, vendor={self.vendor!r}, fingerprint_id={short_id(self.fingerprint)!r})"

    __str__ = __repr__


def validate_observed_fingerprint(value: object) -> str:
    """fingerprint ต้องเป็นสตริงไม่ว่างจาก transport (ไม่ trim/ไม่ normalize: key ต่างกันต้องไม่กลายเป็นค่าเดียวกัน)"""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_FINGERPRINT_LENGTH
        or any(unicodedata.category(c).startswith("C") or c.isspace() for c in value)
    ):
        raise ActivationRejected(ActivationReason.INVALID_FINGERPRINT)
    return value


def _locked(statement):
    # populate_existing: ได้ค่าล่าสุดจาก DB แม้ object อยู่ใน identity map แล้ว (ป้องกันเชื่อค่าเก่าหลังรอ lock)
    return statement.with_for_update().execution_options(populate_existing=True)


async def activate_pending_enrollment(
    session: AsyncSession,
    *,
    candidate: PendingEnrollmentCandidate,
    observed_fingerprint: object,
    detected_vendor: str,
    peer_ip: Optional[str],
    metadata: Optional[DeviceMetadata],
    capability_detail: dict,
    now: Optional[datetime] = None,
) -> ActivationResult:
    fingerprint = validate_observed_fingerprint(observed_fingerprint)
    now = now or generate_timestamp()
    try:
        # 1) lock Enrollment ก่อนเสมอ (ลำดับ lock เดียวทุก connection: Enrollment -> Device -> Capability)
        enrollment = (await session.exec(_locked(
            select(Device_Enrollment).where(Device_Enrollment.enrollment_id == candidate.enrollment_id)
        ))).first()
        _check_enrollment(enrollment, candidate, now)

        # 2) lock Device แล้ว recheck invariant ของ token-pending Device (Phase 5)
        device = (await session.exec(_locked(
            select(Device_Information).where(Device_Information.dev_id == enrollment.device_id)
        ))).first()
        _check_device(device, candidate, detected_vendor)

        # 3) consume แบบ conditional (UPDATE เดียว) - ต้องได้ 1 แถวจริง ไม่เช่นนั้นแพ้ race
        consumed = await mark_enrollment_consumed(
            session, device.dev_id, candidate.token_hash, now=now, commit=False
        )
        if not consumed:
            raise ActivationConflict(ActivationReason.LOST_RACE)

        # 4) Device เดิม: whitelist field เท่านั้น (ไม่แตะ dev_id/site_id/vendor/added_date/registered/viewed)
        device.dev_fingerprint = fingerprint
        device.dev_status = "active"
        device.dev_last_seen = now
        if peer_ip:
            device.dev_ip = str(peer_ip)  # contract เดิม: dev_ip = IP ต้นทางของ connection
        _apply_metadata(device, metadata)
        session.add(device)
        await session.flush()  # unique fingerprint ทำงานตรงนี้ - ชน = แพ้ ไม่ใช่ข้อมูลครึ่งเดียว (caller rollback ทั้งก้อน)

        # 5) capability จาก hello ใน transaction เดียวกัน (commit=False -> flush อย่างเดียว)
        await upsert_capability(session, device.dev_id, detected_vendor, capability_detail, commit=False)
    except ActivationError:
        raise
    except IntegrityError as error:
        # ข้อความเดิมของ driver/SQLAlchemy มี parameters ของ statement (fingerprint/hash) - ไม่ส่งต่อ
        if _is_fingerprint_conflict(error):
            raise FingerprintAlreadyUsed(ActivationReason.FINGERPRINT_IN_USE) from None
        raise ActivationPersistenceError(ActivationReason.PERSISTENCE) from None
    except Exception:
        raise ActivationPersistenceError(ActivationReason.PERSISTENCE) from None
    return ActivationResult(device_id=device.dev_id, vendor=device.dev_vendor, fingerprint=fingerprint)


def _check_enrollment(enrollment, candidate: PendingEnrollmentCandidate, now: datetime) -> None:
    if enrollment is None:
        raise ActivationRejected(ActivationReason.ENROLLMENT_NOT_FOUND)
    if enrollment.device_id != candidate.device_id or enrollment.enrollment_id != candidate.enrollment_id:
        raise ActivationRejected(ActivationReason.ENROLLMENT_MISMATCH)
    if enrollment.consumed_at is not None or enrollment.token_hash is None:
        raise ActivationConflict(ActivationReason.ALREADY_CONSUMED)  # อีก connection consume ไปก่อน
    if enrollment.token_hash != candidate.token_hash:
        raise ActivationRejected(ActivationReason.TOKEN_CHANGED)
    if enrollment.expires_at is not None and enrollment.expires_at <= now:
        raise ActivationRejected(ActivationReason.EXPIRED)


def _check_device(device, candidate: PendingEnrollmentCandidate, detected_vendor: str) -> None:
    if device is None:
        raise ActivationRejected(ActivationReason.DEVICE_NOT_FOUND)
    if device.dev_id != candidate.device_id:
        raise ActivationRejected(ActivationReason.ENROLLMENT_MISMATCH)
    if device.dev_status != "pending":
        raise ActivationRejected(ActivationReason.DEVICE_NOT_PENDING)
    if device.dev_vendor != detected_vendor or device.dev_vendor != candidate.vendor:
        raise ActivationRejected(ActivationReason.VENDOR_MISMATCH)
    if device.dev_fingerprint is not None:
        raise ActivationRejected(ActivationReason.INVARIANT_VIOLATION)


def _apply_metadata(device: Device_Information, metadata: Optional[DeviceMetadata]) -> None:
    """ค่าที่ปลอดภัยต่อการแสดงผลเท่านั้น (ตรวจซ้ำที่นี่ ไม่เชื่อ caller) - ค่าที่ขาด/ไม่ปลอดภัยคงค่าเดิม ไม่ normalize"""
    if metadata is None:
        return
    hostname = safe_display_value(metadata.hostname, MAX_NAME_LENGTH)
    model = safe_display_value(metadata.model, MAX_FIELD_LENGTH)
    firmware = safe_display_value(metadata.firmware, MAX_FIELD_LENGTH)
    if hostname:
        device.dev_name = hostname
    if model:
        device.dev_model = model
    if firmware:
        device.dev_firmware = firmware


def _is_fingerprint_conflict(error: IntegrityError) -> bool:
    for candidate in (error.orig, getattr(error.orig, "__cause__", None)):
        if getattr(candidate, "constraint_name", None) == FINGERPRINT_UNIQUE_CONSTRAINT:
            return True
    return False
