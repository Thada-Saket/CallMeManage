"""Periodic cleanup for short-lived Bootstrap configuration downloads."""

import asyncio

from backend.core.connect_database import AsyncSessionFactory
from backend.crud.web_crud.crud_bootstrap_token import purge_stale_bootstrap_tokens


BOOTSTRAP_CLEANUP_INTERVAL_SECONDS = 60


async def run_bootstrap_cleanup_loop(
    session_factory=AsyncSessionFactory,
    interval_seconds: float = BOOTSTRAP_CLEANUP_INTERVAL_SECONDS,
) -> None:
    """ล้าง Bootstrap record ตอนเริ่มระบบและวนซ้ำจน task ถูก cancel."""
    while True:
        try:
            async with session_factory() as session:
                await purge_stale_bootstrap_tokens(session)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Cleanup ล้มไม่ควรหยุด API/Call Home และห้ามพิมพ์ payload/token
            print(f"[!] Bootstrap cleanup failed: {type(exc).__name__}")
        await asyncio.sleep(interval_seconds)
