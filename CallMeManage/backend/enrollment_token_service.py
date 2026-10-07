""" |======= One-Time Enrollment Token Service =======| """
# Enrollment Token = credential ใช้ครั้งเดียวตอนอุปกรณ์ Call Home ครั้งแรก (Pending -> Active)
# module นี้แยกจาก token ชนิดอื่นโดยเจตนา (ไม่ import/ไม่ใช้ร่วมกัน): token สำหรับดาวน์โหลด bootstrap config,
# JWT ของผู้ใช้ และ Redis lock token ต่างก็มี lifecycle/รูปแบบของตัวเอง ห้ามนำ service นี้ไปใช้กับ token เหล่านั้น
#
# กติกา plaintext: plaintext token มีอยู่ใน memory ชั่วคราว (ค่าที่คืนจาก generate / GeneratedEnrollment.token)
# เพื่อให้ caller นำไปใส่ CLI เท่านั้น ห้าม persist, log, print หรือใส่ใน message ของ exception เด็ดขาด
# ฐานข้อมูลเก็บเฉพาะ SHA-256 hex digest (crud_device_enrollment.py) และ module นี้ไม่ใช้ logging/print เลย
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.crud.dev_crud import crud_device_enrollment as enrollment_crud
from backend.model.models import Device_Enrollment

TOKEN_LENGTH = 19  # ไม่เกินข้อจำกัดชื่อ endpoint ของ Huawei
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "1234567890"
ALPHABET = LOWERCASE + UPPERCASE + DIGITS  # 62 ตัว ไม่มีสัญลักษณ์/whitespace/Unicode

# ชื่อ constraint จริงจาก migration 5cfb2d8b604c - เป็น constraint เดียวที่ยอมให้ retry
TOKEN_HASH_UNIQUE_CONSTRAINT = "uq_device_enrollment_token_hash"
UNIQUE_VIOLATION_SQLSTATE = "23505"
DEFAULT_MAX_ATTEMPTS = 8

_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_LOWERCASE_SET = frozenset(LOWERCASE)
_UPPERCASE_SET = frozenset(UPPERCASE)
_DIGIT_SET = frozenset(DIGITS)
_ALPHABET_SET = frozenset(ALPHABET)

# ใช้ SystemRandom (os.urandom) เท่านั้น ห้ามใช้ module `random`
_secure_random = secrets.SystemRandom()


class EnrollmentTokenError(Exception):
    """Base error - message ต้องไม่มี token หรือ hash"""


class EnrollmentTokenCollisionError(EnrollmentTokenError):
    """สุ่ม token ชน token_hash ที่มีอยู่แล้วครบจำนวน attempt (ไม่ควรเกิดในทางปฏิบัติ)"""

    def __init__(self, attempts: int):
        self.attempts = attempts
        super().__init__(f"Could not create a unique enrollment token after {attempts} attempts")


class EnrollmentTokenPersistenceError(EnrollmentTokenError):
    """IntegrityError ที่ไม่ใช่ token collision แต่ข้อความเดิมมี hash ติดมา จึงห่อใหม่โดยไม่เปิดเผยค่า"""

    def __init__(self, constraint: Optional[str]):
        self.constraint = constraint
        super().__init__(f"Enrollment could not be stored (constraint: {constraint or 'unknown'})")


class EnrollmentNotPendingError(EnrollmentTokenError):
    """Enrollment ถูกใช้หรือถูกยกเลิกไประหว่างขอ Regenerate"""


# ผลลัพธ์ของการสร้าง Enrollment: token (plaintext, ชั่วคราว) + แถว Device_Enrollment ที่ flush แล้ว
# repr/str ไม่แสดง token และห้าม pickle/copy ผ่าน __reduce__ เพื่อกันหลุดเข้า cache/serialization โดยไม่ตั้งใจ
@dataclass(frozen=True)
class GeneratedEnrollment:
    token: str = field(repr=False)
    enrollment: Device_Enrollment = field(repr=False)

    def __repr__(self) -> str:
        return f"GeneratedEnrollment(enrollment_id={self.enrollment.enrollment_id!r}, token=<REDACTED>)"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("GeneratedEnrollment holds a plaintext token and cannot be serialized")


def generate_enrollment_token() -> str:
    """สุ่ม token 19 ตัวด้วย CSPRNG รับประกัน lowercase/uppercase/digit อย่างน้อยอย่างละตัว

    วิธี: บังคับ 1 ตัวต่อ class + สุ่มที่เหลือ 16 ตัวจาก alphabet รวม แล้ว shuffle ด้วย SystemRandom
    ไม่ขึ้นกับเวลา, Device, Site หรือ user
    """
    characters = [
        secrets.choice(LOWERCASE),
        secrets.choice(UPPERCASE),
        secrets.choice(DIGITS),
        *(secrets.choice(ALPHABET) for _ in range(TOKEN_LENGTH - 3)),
    ]
    _secure_random.shuffle(characters)
    return "".join(characters)


def validate_enrollment_token(token: object) -> bool:
    """ตรวจรูปแบบเท่านั้น (ไม่ trim/ไม่เปลี่ยน case) ค่าที่ไม่ถูกต้องไม่ถูกสะท้อนที่ไหน"""
    if not isinstance(token, str) or len(token) != TOKEN_LENGTH:
        return False
    characters = set(token)
    return (
        characters <= _ALPHABET_SET  # ตัดสัญลักษณ์ whitespace newline และ Unicode ทั้งหมด
        and not characters.isdisjoint(_LOWERCASE_SET)
        and not characters.isdisjoint(_UPPERCASE_SET)
        and not characters.isdisjoint(_DIGIT_SET)
    )


def is_valid_token_hash(value: object) -> bool:
    return isinstance(value, str) and _HASH_PATTERN.fullmatch(value) is not None


def hash_enrollment_token(token: str) -> str:
    """SHA-256 lowercase hex 64 ตัว (รูปแบบเดียวกับ Device_Enrollment.token_hash) - ใช้กับ Enrollment Token เท่านั้น"""
    if not validate_enrollment_token(token):
        raise ValueError("Invalid enrollment token")  # ไม่ใส่ค่าที่ผิดใน message
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def verify_enrollment_token(token: object, expected_hash: object) -> bool:
    """เทียบ token กับ hash ที่โหลดมาแล้วใน memory แบบ constant-time; input ผิดรูปแบบ = False

    การ lookup ใน DB ใช้ equality บน unique index (get_pending_enrollment_by_token_hash) ไม่ต้องวน compare ทุกแถว
    """
    if not validate_enrollment_token(token) or not is_valid_token_hash(expected_hash):
        return False
    return hmac.compare_digest(hash_enrollment_token(token), expected_hash)


def _constraint_and_sqlstate(error: IntegrityError) -> tuple[Optional[str], Optional[str]]:
    # SQLAlchemy ห่อ error ของ asyncpg: sqlstate อยู่ที่ orig แต่ constraint_name อยู่ที่ exception ต้นฉบับ
    # (orig.__cause__) จึงต้องเก็บค่าจากทั้งสองชั้น ไม่ใช่หยุดที่ชั้นแรกที่พบอย่างใดอย่างหนึ่ง
    constraint = sqlstate = None
    for candidate in (error.orig, getattr(error.orig, "__cause__", None)):
        constraint = constraint or getattr(candidate, "constraint_name", None)
        sqlstate = sqlstate or getattr(candidate, "sqlstate", None) or getattr(candidate, "pgcode", None)
    return constraint, sqlstate


def _is_token_hash_collision(error: IntegrityError) -> bool:
    constraint, sqlstate = _constraint_and_sqlstate(error)
    return sqlstate == UNIQUE_VIOLATION_SQLSTATE and constraint == TOKEN_HASH_UNIQUE_CONSTRAINT


def _reraise_without_secrets(error: IntegrityError, token_hash: str) -> None:
    # IntegrityError ของ SQLAlchemy พิมพ์ parameters ของ statement (รวม token_hash) และ DETAIL ของ PostgreSQL
    # อาจมีค่าแถวที่ผิด จึงซ่อน parameters ก่อน แล้วถ้าข้อความยังมี hash ให้ห่อเป็น error ที่ไม่มีค่า
    error.hide_parameters = True
    error.params = None
    if token_hash in str(error) or token_hash in str(error.orig):
        raise EnrollmentTokenPersistenceError(_constraint_and_sqlstate(error)[0]) from None
    raise error


async def create_unique_pending_enrollment(
    session: AsyncSession,
    device_id: str,
    expires_at: Optional[datetime] = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> GeneratedEnrollment:
    """สุ่ม token -> hash -> สร้าง Pending Enrollment (flush) ใน transaction ของ caller

    - caller เป็นเจ้าของ transaction: ฟังก์ชันนี้ไม่ commit และไม่ rollback transaction ภายนอก
    - แต่ละ attempt อยู่ใน savepoint (begin_nested) ถ้า token_hash ชน uq_device_enrollment_token_hash
      จะ rollback เฉพาะ savepoint แล้วสุ่ม token ใหม่ (Device/ข้อมูลอื่นที่ caller เพิ่มไว้ใน transaction ยังอยู่)
    - retry เฉพาะ unique violation ของ token_hash: device_id ซ้ำ, FK, check constraint และ error อื่นทั้งหมด
      (รวม connection error) ไม่ retry และถูกโยนต่อ
    - source of truth คือ unique constraint ใน DB ไม่ใช่การ SELECT ก่อน INSERT
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    for _ in range(max_attempts):
        token = generate_enrollment_token()
        token_hash = hash_enrollment_token(token)
        try:
            async with session.begin_nested():
                enrollment = await enrollment_crud.create_pending_enrollment(
                    session, device_id, token_hash, expires_at, commit=False
                )
        except IntegrityError as error:
            if _is_token_hash_collision(error):
                continue
            _reraise_without_secrets(error, token_hash)
        return GeneratedEnrollment(token=token, enrollment=enrollment)

    raise EnrollmentTokenCollisionError(max_attempts)


async def rotate_pending_enrollment_token(
    session: AsyncSession,
    enrollment: Device_Enrollment,
    expires_at: Optional[datetime] = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> GeneratedEnrollment:
    """หมุน one-time token โดยคง Enrollment/Device เดิมและไม่ persist plaintext token"""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    enrollment_id = enrollment.enrollment_id

    for _ in range(max_attempts):
        token = generate_enrollment_token()
        token_hash = hash_enrollment_token(token)
        try:
            async with session.begin_nested():
                replaced = await enrollment_crud.replace_pending_enrollment_token(
                    session, enrollment_id, token_hash, expires_at, commit=False
                )
                if not replaced:
                    raise EnrollmentNotPendingError()
        except IntegrityError as error:
            if _is_token_hash_collision(error):
                continue
            _reraise_without_secrets(error, token_hash)

        await session.refresh(enrollment)
        return GeneratedEnrollment(token=token, enrollment=enrollment)

    raise EnrollmentTokenCollisionError(max_attempts)
