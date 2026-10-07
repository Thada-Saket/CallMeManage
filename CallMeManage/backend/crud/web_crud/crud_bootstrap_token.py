""" |======= CRUD Bootstrap token =======| """

# time tools
from datetime import datetime, timedelta, timezone

# sql tools
from sqlalchemy import and_, delete, or_, update
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

# bootstrap token table model
from backend.model.models import Bootstrap_Token

TOKEN_TTL_MINUTES = 5

# generate token ส่งค่าออกมาทำงานและเก็บลงฐานข้อมูล
async def create_bootstrap_token(
    session: AsyncSession, 
    usr_id: str, 
    config_payload: str | None = None,
    commit: bool = True,
) -> Bootstrap_Token:
    token = Bootstrap_Token(
        bst_usr_id=usr_id,
        bst_expires_at=datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES),
        bst_config_payload=config_payload,
    )
    session.add(token)
    if commit:
        await session.commit()
        await session.refresh(token)
    else:
        await session.flush()
    return token


# นำ token ที่สร้างไปใช้งานจริง โดยผูกกับ config อุปกรณ์ที่สร้างขึ้น
# commit=False (Phase 5 จะรวมกับ Device + Enrollment ใน transaction เดียว): flush อย่างเดียว ไม่ commit/rollback
# transaction ของ caller - ค่าเริ่มต้น True คงพฤติกรรมเดิม
async def set_config_payload(
    session: AsyncSession, 
    token: Bootstrap_Token, 
    config_payload: str,
    commit: bool = True,
) -> Bootstrap_Token:
    token.bst_config_payload = config_payload
    session.add(token)
    if commit:
        await session.commit()
        await session.refresh(token)
    else:
        await session.flush()
    return token

# ช่วงเวลาที่ยอมให้ขอเชื่อมต่อผ่าน api เดิมซ้ำได้ เพื่อโหลด config (เนื่องจาก cisco ยิงการเชื่อมต่อ 2 ครั้ง)
REUSE_GRACE = timedelta(seconds=15)


async def purge_stale_bootstrap_tokens(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    commit: bool = True,
) -> int:
    """ลบ Bootstrap record ที่ไม่สามารถดาวน์โหลดได้อีกแล้ว

    Token ที่ยังไม่ใช้เก็บถึงเวลาหมดอายุ ส่วน token ที่ใช้แล้วเก็บต่อเฉพาะ
    grace period เพื่อรองรับอุปกรณ์ที่ดาวน์โหลดซ้ำจาก IP เดิม
    """
    now = now or datetime.now(timezone.utc)
    result = await session.exec(
        delete(Bootstrap_Token).where(
            or_(
                Bootstrap_Token.bst_expires_at <= now,
                and_(
                    Bootstrap_Token.bst_used.is_(True),
                    Bootstrap_Token.bst_used_at.is_not(None),
                    Bootstrap_Token.bst_used_at <= now - REUSE_GRACE,
                ),
            )
        )
    )
    if commit:
        await session.commit()
    else:
        await session.flush()
    return int(result.rowcount or 0)

# function กิน token
async def consume_bootstrap_token(
    session: AsyncSession, 
    token: str, 
    from_ip: str | None
) -> Bootstrap_Token | None:
    """Atomically claim a valid, unused bootstrap token.

    The conditional UPDATE is the one-time boundary. Concurrent requests cannot
    both change ``bst_used`` from false to true. Cisco may download the same URL
    twice, so the already-claimed row remains readable only from the exact same
    source IP for the short grace period.
    """
    now = datetime.now(timezone.utc)
    claim = (
        update(Bootstrap_Token)
        .where(
            Bootstrap_Token.bst_token == token,
            Bootstrap_Token.bst_used.is_(False),
            Bootstrap_Token.bst_expires_at > now,
        )
        .values(
            bst_used=True,
            bst_used_at=now,
            bst_used_from_ip=from_ip,
        )
        .returning(Bootstrap_Token)
    )
    claimed_result = await session.exec(claim)
    claimed = claimed_result.scalar_one_or_none()
    if claimed is not None:
        await session.commit()
        return claimed

    # Release the transaction opened by the unsuccessful conditional UPDATE
    # before checking the intentionally narrow duplicate-download exception.
    await session.rollback()
    if from_ip is None:
        return None

    duplicate = select(Bootstrap_Token).where(
        Bootstrap_Token.bst_token == token,
        Bootstrap_Token.bst_expires_at > now,
        Bootstrap_Token.bst_used.is_(True),
        Bootstrap_Token.bst_used_from_ip == from_ip,
        Bootstrap_Token.bst_used_at.is_not(None),
        Bootstrap_Token.bst_used_at > now - REUSE_GRACE,
    )
    record = (await session.exec(duplicate)).first()
    if record is None:
        return None

    # End the read-only transaction promptly; the returned ORM object keeps its
    # loaded scalar fields because AsyncSession is configured expire_on_commit=False.
    await session.commit()
    return record
