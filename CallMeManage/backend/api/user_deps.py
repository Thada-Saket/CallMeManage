""" |======= API User Authorization Check with BearerToken =======| """

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel.ext.asyncio.session import AsyncSession

# system configuration
from backend.core.connect_database import get_session
from backend.core.auth import decode_access_token, is_token_revoked, token_auth_version
from backend.core.rate_limiter import enforce_rate_limit
from backend.crud.web_crud.crud_user import get_user

# table models
from backend.model.models import User_Table

# get token from http request 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# ดึงข้อมูล user เจ้าของ session
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> User_Table:
    # กำหนดหัวข้อและรายละเอียดการ error 
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # ตรวจสอบ token ของผู้ใช้
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_error
    auth_version = token_auth_version(payload)
    if auth_version is None:
        raise credentials_error

    # ดึงข้อมูลผู้ใช้จากฐานข้อมูล (query เดิม ไม่ได้เพิ่ม)
    user = await get_user(session, payload["sub"])
    if user is None:
        raise credentials_error
    # CM-08: PostgreSQL เป็นตัวตัดสินหลัก - reset password เพิ่ม version แล้ว token เก่าทุกใบไม่ตรง
    # เทียบแบบเท่ากันเท่านั้น และใช้ข้อความกลางเดียวกับกรณีอื่นเพื่อไม่บอกว่าผิดเพราะอะไร
    if auth_version != user.usr_auth_version:
        raise credentials_error
    # denylist ราย token (logout) ใน Redis - Redis ล่มยังตอบ 503 (fail-closed) เหมือนเดิม
    if await is_token_revoked(payload):
        raise credentials_error
    return user


# จำกัดจำนวนครั้งที่ "ผู้ใช้คนหนึ่ง" เรียก endpoint ได้ ต่างจาก rate_limit_by_ip ที่ผูกกับ IP
# (IP เดียวกันอาจเป็นคนทั้งออฟฟิศหลัง NAT ร่วมกัน -> โดนลงโทษยกแผงทั้งที่ผิดคนเดียว)
# ใช้กับ endpoint ประเภท lookup ที่ยิงทีละค่าได้เรื่อยๆ เพื่อกันการไล่เดา org_id/email
# หมายเหตุ: _check_sliding_window fail-open ถ้า Redis ล่ม (ตามปรัชญาของระบบ) จึงเป็นแค่
# ตัวลดความถี่ ไม่ใช่หลักประกัน - การป้องกันหลักคือ exact match ที่คืนได้สูงสุด 1 แถวเสมอ
def rate_limit_by_user(key_prefix: str, limit: int, window_seconds: float):
    async def dependency(current_user: User_Table = Depends(get_current_user)) -> None:
        await enforce_rate_limit(f"{key_prefix}:{current_user.usr_id}", limit, window_seconds)

    return dependency
