""" |======= Get Active Users on Device =======| """

from backend.core.redis_client import get_redis

# เวลาหมดอายุของสถานะ online
PRESENCE_TTL_SECONDS = 10

# สร้าง redis key ในการจำสถานะว่า online
def _presence_key(dev_id: str, usr_id: str) -> str:
    return f"device:presence:{dev_id}:{usr_id}"

# นำ key ที่สร้างไปให้ redis จำเอาไว้เพื่อเป็นสถานะว่า online
async def touch_presence(dev_id: str, usr_id: str, usr_name: str) -> None:
    try:
        await get_redis().set(_presence_key(dev_id, usr_id), usr_name, ex=PRESENCE_TTL_SECONDS)
    except Exception as exc:
        print(f"[!] failed to record presence for {usr_id} on device {dev_id}: {exc}")

# ดึงรายชื่อของผู้ใช้ที่ใช้งานอุปกรณ์ตัวนั้นอยู่
async def list_present_users(dev_id: str) -> list[str]:
    try:
        redis = get_redis()
        names: set[str] = set()
        async for key in redis.scan_iter(match=_presence_key(dev_id, "*")):
            value = await redis.get(key)
            if value:
                names.add(value)
        return sorted(names)
    except Exception as exc:
        print(f"[!] failed to list presence for device {dev_id}: {exc}")
        return []
