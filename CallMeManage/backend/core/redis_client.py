""" |======= Redis Session Initial =======| """

import redis.asyncio as redis
from redis.exceptions import RedisError

from backend.core.load_environment import load_environment

# สร้างตัวแปรเปล่าไว้เก็บ object redis
_redis_client: redis.Redis | None = None

# เริ่มการเชื่อมต่อไปยัง redis
async def init_redis() -> None:
    global _redis_client
    _redis_client = redis.from_url(
        load_environment().REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    await _redis_client.ping()

# ตัดการเชื่อมต่อกับ redis
async def close_redis() -> None:
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None

# ส่งการเชื่อมต่อ redis ออกไปทำงาน หาก function ไหนต้องการติดต่อกับ redis
def get_redis() -> redis.Redis:
    if _redis_client is None:
        raise RuntimeError("client has not connect to Redis - call init_redis()")
    return _redis_client