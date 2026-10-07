""" |======= Full-token Call Home authentication + startup preflight =======| """
# preflight เป็น read-only: คืน "จำนวน" ของ blocker ตามประเภทเท่านั้น (ไม่ดึง/ไม่คืน token, hash, fingerprint, MAC, Serial)
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sqlalchemy import func, text
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.core.load_environment import load_environment
from backend.model.models import Device_Enrollment, Device_Information

TOKEN = "token"
VALID_MODES = (TOKEN,)

_ROOT = Path(__file__).resolve().parent.parent


class InvalidAuthMode(ValueError):
    """ค่าโหมดที่ไม่รู้จัก - fail closed (ไม่มีการ fallback เป็น hybrid/legacy)"""


def validate_mode(mode: object) -> str:
    if mode not in VALID_MODES:  # เทียบตรงตัว: ไม่ strip/lower เพื่อไม่ตีความค่าเพี้ยนเป็นโหมดที่ถูก
        raise InvalidAuthMode("CALLHOME_AUTH_MODE must be exactly 'token'")
    return mode  # type: ignore[return-value]


def get_auth_mode() -> str:
    """อ่านโหมดจาก configuration (ล้มเหลวเองถ้า config file/ENV มีค่าที่ไม่รู้จัก)"""
    return validate_mode(load_environment().CALLHOME_AUTH_MODE)


def alembic_head() -> Optional[str]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(_ROOT / "alembic"))
    return ScriptDirectory.from_config(config).get_current_head()


@dataclass(frozen=True)
class PreflightResult:
    blockers: dict = field(default_factory=dict)  # ชื่อประเภท -> จำนวน (> 0 เท่านั้น)

    @property
    def ok(self) -> bool:
        return not self.blockers

    def summary(self) -> str:
        return ", ".join(f"{name}={count}" for name, count in sorted(self.blockers.items())) or "none"


async def _count(session: AsyncSession, statement) -> int:
    return (await session.exec(statement)).first() or 0


async def token_mode_preflight(session: AsyncSession, expected_head: Optional[str] = None) -> PreflightResult:
    """ตรวจเงื่อนไขที่ตรวจจากข้อมูลได้ก่อนอนุญาต token mode (อ่านอย่างเดียว ไม่แก้ข้อมูล)

    ข้อที่ตรวจไม่ได้จากฐานข้อมูล (tests ผ่าน, แผน migrate/reset legacy, rollback) อยู่ใน planning/callhome_enrollment_progress.md
    """
    blockers: dict = {}
    def add(name: str, count: int) -> None:
        if count:
            blockers[name] = count

    base = select(func.count()).select_from(Device_Information)
    # 1) fingerprint (ไม่ใช่ NULL) ซ้ำ - นับจำนวนกลุ่มที่ซ้ำ
    duplicates = (
        select(Device_Information.dev_fingerprint)
        .where(Device_Information.dev_fingerprint.is_not(None))
        .group_by(Device_Information.dev_fingerprint)
        .having(func.count() > 1)
        .subquery()
    )
    add("duplicate_fingerprint_groups", await _count(session, select(func.count()).select_from(duplicates)))
    # 2) Device ที่ consume token แล้วต้องมี fingerprint ไม่ว่าสถานะปัจจุบันจะเป็นอะไร
    # (ถ้าจำกัดเฉพาะ active จะปล่อย consumed+pending ที่ reconnect ไม่ได้ให้ผ่าน preflight)
    consumed = select(Device_Enrollment.device_id).where(Device_Enrollment.consumed_at.is_not(None))
    add(
        "token_devices_without_fingerprint",
        await _count(session, base.where(
            Device_Information.dev_id.in_(consumed), Device_Information.dev_fingerprint.is_(None)
        )),
    )
    # 3) Consumed Enrollment ต้องผูกกับ Active Device เท่านั้น; สถานะ pending/offline/rejected
    # จะถูก fingerprint router ปฏิเสธและไม่มี token เหลือให้ activate ซ้ำ
    add(
        "consumed_devices_not_active",
        await _count(session, base.where(
            Device_Information.dev_id.in_(consumed), Device_Information.dev_status != "active"
        )),
    )
    # 4) Active Device ที่ Enrollment ยังเป็น pending (มี token_hash ค้าง) = สถานะผิดปกติ
    live = select(Device_Enrollment.device_id).where(Device_Enrollment.token_hash.is_not(None))
    add("active_devices_with_live_token", await _count(session, base.where(Device_Information.dev_id.in_(live), Device_Information.dev_status == "active")))
    # 5) Pending Token Device ต้องยังไม่มี fingerprint มิฉะนั้น router/activation
    # จะปฏิเสธด้วย ENROLLMENT_INVARIANT หลังเปิด token mode ทำให้อุปกรณ์ค้างถาวร
    add(
        "invalid_pending_token_devices",
        await _count(session, base.where(
            Device_Information.dev_id.in_(live),
            Device_Information.dev_status == "pending",
            Device_Information.dev_fingerprint.is_not(None),
        )),
    )
    # 6) migration อยู่ที่ head
    head = expected_head if expected_head is not None else alembic_head()
    try:
        connection = await session.connection()
        current = (await connection.execute(text("SELECT version_num FROM alembic_version"))).scalars().all()
    except Exception:
        await session.rollback()
        current = []
    if list(current) != [head]:
        blockers["migration_not_at_head"] = 1
    return PreflightResult(blockers)


async def enforce_startup_mode(session_factory, mode: str) -> None:
    """Full-token listener starts only after preflight; no hybrid fallback exists."""
    validate_mode(mode)
    async with session_factory() as session:
        result = await token_mode_preflight(session)
    if not result.ok:
        raise RuntimeError(f"Token mode preflight failed ({result.summary()})")
