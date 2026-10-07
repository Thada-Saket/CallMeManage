""" |======= Schema for user fetch and input data validation =======| """

from datetime import datetime

from typing import Optional

from pydantic import EmailStr, field_validator, model_validator
from sqlmodel import Field, SQLModel

from backend.core.account_password_policy import ACCOUNT_PASSWORD_MAX_LENGTH, validate_account_password

# schema สำหรับ validate output ข้อมูลการดึง user 
class UserRead(SQLModel):
    usr_id: str
    usr_name: str
    usr_email: str
    usr_role: str
    usr_created_date: datetime


# หน้าเว็บที่ 1 (Login.jsx): โหมด "สมัครสมาชิก" - จำกัด min_length ตรงนี้ (ระดับ
# request schema) ให้ FastAPI ปฏิเสธเป็น 422 อัตโนมัติก่อนแตะ CRUD/DB เลยด้วยซ้ำ -
# ตรงกับ constraint เดียวกับที่ User_Table.usr_name มีอยู่แล้ว (min_length=5,
# max_length=32 - ไม่ได้เพิ่มกฎใหม่ แค่ยกมา validate ที่ boundary ก่อนเข้าระบบ) -
# usr_email ใช้ EmailStr (Pydantic - ผ่าน email-validator ที่ติดตั้งอยู่แล้วใน
# venv) ตรวจรูปแบบอีเมลจริงแทน str เฉยๆ กันอีเมลรูปแบบผิดหลุดเข้า DB

# schema สำหรับ validate input การสร้าง user
class UserCreate(SQLModel):
    # CM-09: ไม่ echo password ที่กรอกใน ValidationError (repr/log)
    model_config = {"hide_input_in_errors": True}

    usr_name: str = Field(min_length=5, max_length=32)
    usr_email: EmailStr
    # ความยาวขั้นต่ำ/ชนิดอักขระตรวจใน validate_account_password (ข้อความเดียวทุกกรณี)
    usr_passwd: str = Field(max_length=ACCOUNT_PASSWORD_MAX_LENGTH)

    @field_validator("usr_passwd")
    @classmethod
    def _account_password_policy(cls, value: str) -> str:
        return validate_account_password(value)


class EmailRegistrationStart(SQLModel):
    email: EmailStr


class EmailRegistrationVerify(SQLModel):
    challenge_id: str = Field(min_length=20, max_length=128)
    otp: str = Field(min_length=6, max_length=6)

    @field_validator("otp")
    @classmethod
    def validate_otp(cls, value: str) -> str:
        if not value.isascii() or not value.isdigit():
            raise ValueError("Verification code must contain exactly 6 digits")
        return value


class EmailRegistrationResend(SQLModel):
    challenge_id: str = Field(min_length=20, max_length=128)


# ยกเลิกการสมัครที่ค้างอยู่ - ส่ง challenge (ก่อนยืนยัน OTP) และ/หรือ ticket (หลังยืนยันแล้ว)
class RegistrationCancel(SQLModel):
    challenge_id: Optional[str] = Field(default=None, min_length=20, max_length=128)
    registration_token: Optional[str] = Field(default=None, min_length=20, max_length=256)

    @model_validator(mode="after")
    def require_one_reference(self):
        if self.challenge_id is None and self.registration_token is None:
            raise ValueError("challenge_id or registration_token is required")
        return self


# กู้คืนรหัสผ่านทางอีเมล (POST /auth/password-reset/*)
class PasswordResetStart(SQLModel):
    email: EmailStr


class PasswordResetVerifyRead(SQLModel):
    reset_token: str
    email: EmailStr
    expires_in: int             # อายุของ ticket สำหรับขั้นตั้งรหัสผ่านใหม่


class PasswordResetComplete(SQLModel):
    model_config = {"hide_input_in_errors": True}

    reset_token: str = Field(min_length=20, max_length=256)
    new_password: str = Field(max_length=ACCOUNT_PASSWORD_MAX_LENGTH)

    @field_validator("new_password")
    @classmethod
    def _account_password_policy(cls, value: str) -> str:
        return validate_account_password(value)


class PasswordResetCancel(SQLModel):
    challenge_id: Optional[str] = Field(default=None, min_length=20, max_length=128)
    reset_token: Optional[str] = Field(default=None, min_length=20, max_length=256)

    @model_validator(mode="after")
    def require_one_reference(self):
        if self.challenge_id is None and self.reset_token is None:
            raise ValueError("challenge_id or reset_token is required")
        return self


class GoogleOAuthStartRead(SQLModel):
    authorization_url: str
    expires_in: int


class GoogleOAuthComplete(SQLModel):
    result_code: str = Field(min_length=20, max_length=512)


class SiteAccessVerify(SQLModel):
    turnstile_token: str = Field(min_length=1, max_length=2048)


class SiteAccessRead(SQLModel):
    site_access_token: str
    expires_in: int


# เวลาทั้งหมดเป็นวินาทีนับจากตอนตอบกลับ ให้หน้าเว็บนับถอยหลังตามค่าจริงของ server
class RegistrationChallengeRead(SQLModel):
    challenge_id: str
    expires_in: int             # อายุของรหัสปัจจุบัน
    flow_expires_in: int        # เวลาที่เหลือของทั้ง flow (หลังจากนี้ต้องเริ่มใหม่)
    resend_available_in: int    # ขอรหัสใหม่ได้อีกครั้งเมื่อไร


# CM-12: GET /auth/registration-status - สำหรับ UX เท่านั้น (route guard ฝั่ง backend คือผู้บังคับจริง)
class RegistrationStatusRead(SQLModel):
    enabled: bool
    # Google sign-up button is shown only when all Google settings are present
    google_enabled: bool = False


# The page's own address (window.location.origin). Used only when it is one of the
# SITE_URL addresses, so Google sends the user back to the address they started from.
class GoogleOAuthStartRequest(SQLModel):
    site_url: str | None = Field(default=None, max_length=256)


# Public settings the web page needs before anything else (no secrets).
class ClientConfigRead(SQLModel):
    turnstile_enabled: bool
    turnstile_site_key: str | None = None


class RegistrationVerificationRead(SQLModel):
    registration_token: str
    email: EmailStr
    expires_in: int             # อายุของ ticket สำหรับขั้นตั้ง username/password


class VerifiedUserCreate(SQLModel):
    model_config = {"hide_input_in_errors": True}

    usr_name: str = Field(min_length=5, max_length=32)
    usr_passwd: str = Field(max_length=ACCOUNT_PASSWORD_MAX_LENGTH)
    registration_token: str = Field(min_length=20, max_length=256)

    @field_validator("usr_passwd")
    @classmethod
    def _account_password_policy(cls, value: str) -> str:
        return validate_account_password(value)

# schema สำหรับ validate ความถูกต้องของ token
class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


# GET /users/lookup?email=... (Invite Member ใน SiteSettingsModal.jsx) - คืน
# แค่ usr_id/usr_name เท่านั้น ไม่ echo email กลับ (แม้จะเป็น email ที่ผู้ค้นหา
# พิมพ์เข้ามาเองก็ตาม) กันเผลอ leak PII ฝั่งอื่นถ้า component ถูกนำโค้ดไปใช้ซ้ำ
# ในบริบทอื่นที่ query อาจไม่ตรงกับ email ของผลลัพธ์เป๊ะ
# หมายเหตุ: endpoint นี้เดิมชื่อ /users/search และค้นแบบ substring (ส่ง "" มากวาด
# ผู้ใช้ทั้งระบบได้) เปลี่ยนเป็น lookup แบบตรงเป๊ะแล้ว จึงคืนได้สูงสุด 1 รายการเสมอ

# schema สำหรับ validate output การค้นหาผู้ใช้
class UserSearchResult(SQLModel):
    usr_id: str
    usr_name: str
