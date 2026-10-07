"""Periodic cleanup for token-pending devices left expired for a long time."""

import asyncio
from datetime import timedelta

from backend.core.connect_database import AsyncSessionFactory
from backend.crud.dev_crud.crud_device_enrollment import purge_long_expired_pending_devices
from backend.model.models import generate_timestamp


ENROLLMENT_EXPIRED_RETENTION_DAYS = 30
ENROLLMENT_CLEANUP_INTERVAL_SECONDS = 60 * 60


async def run_enrollment_cleanup_loop(
    session_factory=AsyncSessionFactory,
    interval_seconds: float = ENROLLMENT_CLEANUP_INTERVAL_SECONDS,
) -> None:
    """เก็บ Expired card ไว้ 30 วันให้ผู้ใช้ Regenerate/Delete ก่อนลบอัตโนมัติ"""
    while True:
        try:
            cutoff = generate_timestamp() - timedelta(days=ENROLLMENT_EXPIRED_RETENTION_DAYS)
            async with session_factory() as session:
                await purge_long_expired_pending_devices(session, expired_before=cutoff)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # ห้ามแสดง SQL/token/hash จาก exception ใน log
            print(f"[!] Enrollment cleanup failed: {type(exc).__name__}")
        await asyncio.sleep(interval_seconds)
