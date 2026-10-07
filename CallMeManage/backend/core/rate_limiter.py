""" |======= Rate Limiter =======| """

import time
import uuid

from fastapi import HTTPException, Request, status
from redis.exceptions import RedisError

from backend.core.redis_client import get_redis
from backend.core.security_audit import audit_security_event

# บันทึกการใช้งานของผู้ใช้ลง redis เพื่อจำกัดปริมาณการเรียกใช้งานต่อเวลาที่กำหนด โดยส่วนมากจะเขียนค่าไปเก็บลง redis แต่มีการดึงจำนวน key ที่บันทึกลงไปมาใช้งานเพื่อตรวจสอบจำนวน
async def _check_sliding_window(
    key: str,
    limit: int,
    window_seconds: float,
    *,
    fail_closed: bool = False,
) -> None:
    try:
        redis = get_redis()
        # บันทึกเวลาปัจจุบันของคำสั่ง
        now = time.time()
        # บันทึกเวลาย้อนกลับไปในอดีตตามวิที่กำหนดว่ามีข้อมูลอะไรบันทึกไว้บ้าง
        window_start = now - window_seconds

        async with redis.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, 0, window_start) # ล้าง list ตั้งแต่ 0 ถึงที่กำหนด
            pipe.zadd(key, {uuid.uuid4().hex: now})     # เพิ่ม key และ uuid ลงใน list
            pipe.zcard(key)                             # นับจำนวน key
            pipe.expire(key, int(window_seconds) + 1)   # ตั้งเวลาหมดอายุของ key

            # นำสิ่งที่เขียนก่อนหน้าไปทำงาน และรับค่า count มาทำงานต่อ
            _, _, count, _ = await pipe.execute()       
    except (RedisError, RuntimeError, OSError) as exc:
        print(f"[!] Redis rate limiter error: {exc}")
        if fail_closed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Security rate limiter is temporarily unavailable. Please try again later.",
            )
        return

    # ถ้าจำนวน key ที่นับได้ มากกว่า limit ให้ error 429
    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many requests (limited to {limit} requests per {window_seconds:.0f} seconds). Please try again later",
        )

# ตัวห่อสาธารณะของ _check_sliding_window ให้ชั้น api เรียกใช้ได้โดยไม่ต้องแตะฟังก์ชัน
# ภายในที่ขึ้นต้นด้วย _ (ใช้โดย rate_limit_by_user ใน backend/api/user_deps.py -
# ตัวนั้นต้องอยู่ชั้น api เพราะต้องพึ่ง get_current_user ซึ่ง core/ ไม่ควร import ย้อนทิศ)
async def enforce_rate_limit(key: str, limit: int, window_seconds: float) -> None:
    await _check_sliding_window(key, limit, window_seconds)


def client_ip(request: Request) -> str:
    # uvicorn already replaced this with the forwarded address when the request
    # came through a trusted proxy (--proxy-headers / --forwarded-allow-ips);
    # a client-supplied X-Forwarded-For is never read here directly.
    return request.client.host if request.client else "unknown"


class FailureCounter:
    """Counts only failed attempts per IP, e.g. bad OAuth callbacks.

    Unlike rate_limit_by_ip, successful requests cost nothing; once `limit`
    failures fall inside the window, further requests are refused until the
    oldest failure ages out. Fails closed: a Redis error counts as over limit.
    """

    def __init__(self, key_prefix: str, limit: int, window_seconds: float):
        self.key_prefix = key_prefix
        self.limit = limit
        self.window_seconds = window_seconds

    def _key(self, request: Request) -> str:
        return f"{self.key_prefix}:{client_ip(request)}"

    async def is_blocked(self, request: Request) -> bool:
        key = self._key(request)
        try:
            redis = get_redis()
            async with redis.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(key, 0, time.time() - self.window_seconds)
                pipe.zcard(key)
                _, count = await pipe.execute()
        except (RedisError, RuntimeError, OSError) as exc:
            print(f"[!] Redis failure counter error: {type(exc).__name__}")
            return True
        return count >= self.limit

    async def record_failure(self, request: Request) -> None:
        key = self._key(request)
        try:
            redis = get_redis()
            async with redis.pipeline(transaction=True) as pipe:
                pipe.zadd(key, {uuid.uuid4().hex: time.time()})
                pipe.expire(key, int(self.window_seconds) + 1)
                await pipe.execute()
        except (RedisError, RuntimeError, OSError) as exc:
            print(f"[!] Redis failure counter error: {type(exc).__name__}")


# จำกัดการเข้าถึงด้วย ip เพราะไม่มี uuid ให้ผูก
def rate_limit_by_ip(
    key_prefix: str,
    limit: int,
    window_seconds: float,
    *,
    fail_closed: bool = False,
):
    # fastapi dependency function ใช้ในการรับข้อ http request
    async def dependency(request: Request) -> None:
        try:
            await _check_sliding_window(
                f"{key_prefix}:{client_ip(request)}",
                limit,
                window_seconds,
                fail_closed=fail_closed,
            )
        except HTTPException as exc:
            if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                # CM-10: repeated login/sign-up/OTP/reset attempts become visible to operators
                # (limiter name + masked client only; never the key, body or identifier)
                audit_security_event("rate_limit.exceeded", "RATE_LIMITED", request=request,
                                     limiter=key_prefix.replace(":", "."))
            raise

    return dependency


# คำสั่งอ่านอย่างเดียว (ไม่แก้ config อุปกรณ์) - ปกติยกเว้นจาก write-command
# rate limit ด้านล่าง แต่ full running configuration เป็นข้อยกเว้น เพราะ reply มี
# ขนาดใหญ่และให้อุปกรณ์สร้าง configuration tree ทั้งก้อนทุกครั้ง จึงต้องจำกัด
# แยกจากคำสั่งอ่านราคาถูก โดยผูกต่อ device + command เพื่อป้องกันอุปกรณ์โดยตรง
# (ผู้ใช้ทุกคนที่เข้าถึงอุปกรณ์เดียวกันใช้ quota ร่วมกันโดยตั้งใจ)
READ_ONLY_COMMAND_PREFIXES = ("get_", "show_")

EXPENSIVE_READ_COMMAND_LIMITS = {
    # สอดคล้องกับ dedicated running-config snapshot endpoint: 3 ครั้ง/นาที
    "get_running_config": (3, 60.0),
}

# จำกัดการสั่งคำสั่งไปยังอุปกรณ์ โดยคำสั่งอ่านขนาดใหญ่ใช้ policy เฉพาะก่อนตรวจ
# read-only exemption และ fail closed เมื่อ Redis ล่ม เพื่อไม่ปล่อย full-config
# request วิ่งเข้าอุปกรณ์โดยไม่มีขีดจำกัดในช่วงที่ระบบป้องกันใช้การไม่ได้
def rate_limit_by_device_command(
    key_prefix: str,
    limit: int,
    window_seconds: float,
    *,
    enforce_expensive_reads: bool = True,
):
    async def dependency(dev_id: str, command: str) -> None:
        expensive_read_limit = EXPENSIVE_READ_COMMAND_LIMITS.get(command) if enforce_expensive_reads else None
        if expensive_read_limit is not None:
            read_limit, read_window = expensive_read_limit
            await _check_sliding_window(
                f"{key_prefix}:expensive-read:{command}:{dev_id}",
                read_limit,
                read_window,
                fail_closed=True,
            )
            return
        if command.startswith(READ_ONLY_COMMAND_PREFIXES):
            return
        await _check_sliding_window(f"{key_prefix}:{dev_id}", limit, window_seconds)

    return dependency


# เหมือนตัวบน แต่ใช้กับ endpoint ที่ไม่มี path parameter ชื่อ command (เช่นชุดคำสั่ง
# ของ C4) - ถ้าเอาตัวบนไปใช้ FastAPI จะถือว่า command เป็น query parameter ที่ต้อง
# ส่งมาด้วย แล้วตอบ 422 ทุก request ทั้งที่ body ถูกต้อง
def rate_limit_by_device(
    key_prefix: str,
    limit: int,
    window_seconds: float,
    *,
    fail_closed: bool = False,
):
    async def dependency(dev_id: str) -> None:
        await _check_sliding_window(
            f"{key_prefix}:{dev_id}",
            limit,
            window_seconds,
            fail_closed=fail_closed,
        )

    return dependency
