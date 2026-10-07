"""Persistence for per-visit device access sessions.

One Device_Access row represents one browser visit.  Repeated heartbeat calls
update acc_lastseen on that row; reopening the device with a new session UUID
creates another row, even for the same user and device.
"""

from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlmodel import or_, select
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.model.models import Device_Access, generate_timestamp


class AccessSessionConflictError(ValueError):
    """A globally unique session UUID is already owned by another actor."""


async def start_access_session(
    session: AsyncSession,
    *,
    session_id: str,
    dev_id: str,
    usr_id: str,
) -> Device_Access:
    """Create one access row, or return the same row for an idempotent retry."""
    result = await session.exec(
        select(Device_Access).where(Device_Access.acc_session_id == session_id)
    )
    existing = result.first()
    if existing is not None:
        if existing.acc_dev_id != dev_id or existing.acc_usr_id != usr_id:
            raise AccessSessionConflictError("Access session ID is already in use")
        return existing

    now = generate_timestamp()
    entry = Device_Access(
        acc_session_id=session_id,
        acc_date=now,
        acc_lastseen=now,
        acc_dev_id=dev_id,
        acc_usr_id=usr_id,
    )
    session.add(entry)
    try:
        await session.commit()
    except IntegrityError:
        # Two identical POST retries can pass the read above concurrently.  The
        # DB unique constraint chooses one winner; the loser resolves that same
        # row instead of creating a duplicate or returning a false failure.
        await session.rollback()
        result = await session.exec(
            select(Device_Access).where(Device_Access.acc_session_id == session_id)
        )
        existing = result.first()
        if existing is None:
            # The integrity failure was unrelated to the session UUID; preserve
            # the real database error instead of misreporting it as a collision.
            raise
        if existing.acc_dev_id != dev_id or existing.acc_usr_id != usr_id:
            raise AccessSessionConflictError("Access session ID is already in use")
        return existing
    await session.refresh(entry)
    return entry


async def touch_access_session(
    session: AsyncSession,
    *,
    session_id: str,
    dev_id: str,
    usr_id: str,
) -> Optional[Device_Access]:
    """Heartbeat an access session only when it belongs to this user/device."""
    result = await session.exec(
        select(Device_Access).where(
            Device_Access.acc_session_id == session_id,
            Device_Access.acc_dev_id == dev_id,
            Device_Access.acc_usr_id == usr_id,
        )
    )
    entry = result.first()
    if entry is None:
        return None
    entry.acc_lastseen = generate_timestamp()
    session.add(entry)
    await session.commit()
    await session.refresh(entry)
    return entry


async def list_access_sessions_by_device(
    session: AsyncSession,
    *,
    dev_id: str,
    after_acc_id: str | None = None,
    limit: int = 40,
) -> list[Device_Access]:
    """Return newest access sessions using stable keyset pagination."""
    statement = (
        select(Device_Access)
        .where(Device_Access.acc_dev_id == dev_id)
        .order_by(Device_Access.acc_lastseen.desc(), Device_Access.acc_id.desc())
    )
    if after_acc_id:
        cursor = await session.get(Device_Access, after_acc_id)
        # A cursor from another device must never influence this device's log.
        if cursor is None or cursor.acc_dev_id != dev_id:
            raise ValueError("Invalid access-log cursor")
        statement = statement.where(
            or_(
                Device_Access.acc_lastseen < cursor.acc_lastseen,
                (Device_Access.acc_lastseen == cursor.acc_lastseen)
                & (Device_Access.acc_id < cursor.acc_id),
            )
        )
    result = await session.exec(statement.limit(limit + 1))
    return list(result.all())
