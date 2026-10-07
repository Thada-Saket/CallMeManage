""" |======= Password Hash and Verify =======| """

from passlib.context import CryptContext

# กำหนด password algorithm
password_policy = CryptContext(schemes=["argon2"], deprecated="auto")

# hash รหัสผ่าน
def get_password_hash(
        password: str
) -> str:
    return password_policy.hash(password)

# ตรวจสอบรหัสผ่านว่าตรงกันไหม
def verify_password(
        plaintext: str,
        hashed: str,
) -> bool:
    return password_policy.verify(plaintext, hashed)


# แฮชหลอก (precompute ครั้งเดียวตอน import) สำหรับทำ login ให้ constant-time:
# เมื่อไม่พบ user ให้เรียก dummy_verify() เพื่อเสียเวลา Argon2 เท่ากับกรณีพบ user จริง
# กัน username enumeration ผ่าน timing (V2) - เดิมถ้าไม่พบ user จะ return ทันทีโดยไม่คำนวณ
# Argon2 ทำให้ตอบเร็วกว่าเคสมี user ~8 เท่า แยกออกได้ชัดเจน
_DUMMY_HASH = password_policy.hash("constant-time-placeholder-not-a-real-password")


def dummy_verify() -> None:
    # verify กับแฮชหลอกเพื่อกินเวลา Argon2 ให้เท่ากัน ผลลัพธ์ทิ้งเสมอ (รหัสไม่มีทางตรง)
    try:
        password_policy.verify("x", _DUMMY_HASH)
    except Exception:
        pass