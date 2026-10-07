""" |======= Token Configuration =======| """

# import tools
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from redis.exceptions import RedisError
from fastapi import HTTPException, status

from jose import JWTError, jwt

# import function from other file
from backend.core.load_environment import load_environment
from backend.core.redis_client import get_redis

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 2  # 2 ชั่วโมง

REVOKED_JWT_PREFIX = "auth:revoked_jwt:"
REVOKED_USER_PREFIX = "auth:revoked_usr:"

# ตั้งให้อายุของ key ที่เก็บว่า token ถูกยกเลิกแล้ว มีอายุมากกว่าอายุของ token
REVOKED_USER_TTL_SECONDS = ACCESS_TOKEN_EXPIRE_MINUTES * 60


# CM-08: claim ที่บอกว่า token ออกตอน User_Table.usr_auth_version เป็นค่าไหน
AUTH_VERSION_CLAIM = "auth_version"


# auth_version ไม่ใส่ default โดยเจตนา - caller ใหม่ที่ลืมส่งต้องพังตั้งแต่ตอนเขียน ไม่ใช่ออก token ที่ revoke ไม่ได้
def create_access_token(usr_id: str, auth_version: int) -> str:
    if type(auth_version) is not int or auth_version < 1:
        raise ValueError("auth_version must be a positive integer")
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": usr_id,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": expire,
        AUTH_VERSION_CLAIM: auth_version,
    }
    return jwt.encode(payload, load_environment().JWT_SECRET_KEY, algorithm=ALGORITHM)


# ถอดรหัส token ว่าถูกต้องไหม
def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, load_environment().JWT_SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
    if "sub" not in payload:
        return None
    return payload


# คืน auth version จาก token เฉพาะเมื่อเป็น int จริง (ไม่รับ bool/str/float/None) - token
# รุ่นก่อน CM-08 ที่ไม่มี claim จะได้ None และต้องถูกปฏิเสธ ห้ามตีความเป็น version ปัจจุบัน
def token_auth_version(payload: dict) -> Optional[int]:
    value = payload.get(AUTH_VERSION_CLAIM)
    if type(value) is not int:
        return None
    return value


# ตรวจสอบว่า token นี้ถูกถอนไปหรือยัง มี 2 เงื่อนไข
# 1. เจอรายชื่อการถูกถอนใน redis
# 2. เจอชื่อ user ที่ถูกถอนใน redis
async def is_token_revoked(payload: dict) -> bool:
    try:
        redis = get_redis()
        jti = payload.get("jti")
        if jti and await redis.exists(f"{REVOKED_JWT_PREFIX}{jti}"):
            return True

        usr_id = payload.get("sub")
        revoked_at_raw = await redis.get(f"{REVOKED_USER_PREFIX}{usr_id}")
        if revoked_at_raw is not None:
            issued_at = payload.get("iat")
            if issued_at is None or float(issued_at) <= float(revoked_at_raw):
                return True
        return False
    except (RedisError, RuntimeError, OSError) as exc:
        print(f"[!] Redis token service is unavailable: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization failed",
        )

# ล้าง access token เมื่อค่าที่กรอกเข้ามาไม่ใช่ payload ว่างหรือหมดอายุแล้ว
async def revoke_access_token(payload: dict) -> None:
    redis = get_redis()
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or exp is None:
        return
    remaining = int(float(exp) - datetime.now(timezone.utc).timestamp())
    if remaining <= 0:
        return
    await redis.set(f"{REVOKED_JWT_PREFIX}{jti}", "1", ex=remaining)


# ล้าง token ทั้งหมดของ user ผ่าน Redis อย่างเดียว - ห้ามใช้เป็นหลักประกันการ revoke เพราะหายเงียบ
# ถ้า Redis ล่ม และ marker แบบ timestamp ปฏิเสธ token ที่ออกในวินาทีเดียวกันด้วย; reset password
# ใช้ usr_auth_version ใน PostgreSQL แทนแล้ว (CM-08)
async def revoke_all_user_tokens(usr_id: str) -> None:
    redis = get_redis()
    now_ts = datetime.now(timezone.utc).timestamp()
    await redis.set(f"{REVOKED_USER_PREFIX}{usr_id}", now_ts, ex=REVOKED_USER_TTL_SECONDS)