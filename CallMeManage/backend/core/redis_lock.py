import asyncio
import time
import uuid

from backend.core.redis_client import get_redis

LOCK_PREFIX = "device:lock:"    # redis key name
# Must outlive the slowest supported NETCONF operation. Cisco compound NAT
# writes can wait 60 seconds for edit-config and candidate-capable devices may
# then need a separate commit reply. Normal exits still release immediately;
# this TTL is only the crash/release-failure safety net.
DEFAULT_LOCK_TTL_MS = 120_000
DEFAULT_ACQUIRE_TIMEOUT_S = 5.0 # 
ACQUIRE_RETRY_INTERVAL_S = 0.2

# ปลดล็อกแบบปลอดภัยผ่าน Lua script (atomic ที่ฝั่ง Redis) - เช็คว่า value ที่อยู่
# ใน key ยังเป็น token ของตัวเองจริงก่อนค่อยลบ กัน client A ที่ lock หลุดไปแล้วเอง
# (TTL หมดเพราะ process ค้าง/ตายกลางทาง) มาลบ lock ใหม่ของ client B ที่เพิ่งได้
# ไปพอดีทับโดยไม่ตั้งใจ (เขียนแบบ GET แล้วค่อย DEL แยก 2 คำสั่งจะมี race window
# ตรงนี้ - ต้องรวมเป็นคำสั่งเดียวที่อะตอมมิกจริง)
_RELEASE_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""

class DeviceLockBusy(Exception):
    """อุปกรณ์นี้กำลังมีคำสั่งอื่นทำงานค้างอยู่ (ยังไม่ปลด lock)"""

class DeviceLock:
    """Distributed mutex lock (`device:lock:<dev_id>`, `SET ... NX PX 10000`) คู่กับ
    asyncio.Lock ในความจำที่ conn_socket.py's session["lock"] ใช้อยู่แล้ว - ตัวนั้น
    คุมได้แค่ใน process เดียวกัน (พอสำหรับสถาปัตยกรรมปัจจุบันที่ callhome listener
    กับ web API อยู่ process เดียวกันเสมอตามกฎที่ห้ามแยก) ตัวนี้เผื่อไว้ล่วงหน้า
    สำหรับสถาปัตยกรรมในอนาคตที่อาจมีมากกว่า 1 worker/instance ยิงเข้าอุปกรณ์
    เดียวกัน - ใช้แบบ `async with DeviceLock(dev_id):`"""

    def __init__(
        self,
        dev_id: str,
        ttl_ms: int = DEFAULT_LOCK_TTL_MS,
        acquire_timeout_s: float = DEFAULT_ACQUIRE_TIMEOUT_S,
    ):
        self.key = f"{LOCK_PREFIX}{dev_id}"
        self.ttl_ms = ttl_ms
        self.acquire_timeout_s = acquire_timeout_s
        self.token = uuid.uuid4().hex

    async def acquire(self) -> bool:
        redis = get_redis()
        return bool(await redis.set(self.key, self.token, nx=True, px=self.ttl_ms))

    async def release(self) -> None:
        redis = get_redis()
        try:
            await redis.eval(_RELEASE_SCRIPT, 1, self.key, self.token)
        except Exception:
            pass  # best-effort - Redis หลุดตอนปลดล็อกก็ปล่อยให้ TTL หมดอายุเองแทน

    async def __aenter__(self) -> "DeviceLock":
        deadline = time.monotonic() + self.acquire_timeout_s
        while not await self.acquire():
            if time.monotonic() >= deadline:
                dev_id = self.key.removeprefix(LOCK_PREFIX)
                raise DeviceLockBusy(f"Device {dev_id} is currently busy processing another command. Please try again in a few seconds.")
            await asyncio.sleep(ACQUIRE_RETRY_INTERVAL_S)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.release()
