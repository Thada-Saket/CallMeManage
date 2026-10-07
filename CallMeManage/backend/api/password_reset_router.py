""" |======= API Password reset by email code =======|

start -> (resend) -> verify -> complete, then the user signs in again.
Every address gets a real code; whether it has an account is revealed only
after the code proves the caller owns the mailbox (same rule as sign-up).
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel.ext.asyncio.session import AsyncSession

from backend.api.auth_router import (
    _registration_error,
    email_send_rate_limiter,
    registration_cancel_rate_limiter,
    registration_verify_rate_limiter,
)
from backend.core.auth_audit import audit_auth_event
from backend.core.connect_database import get_session
from backend.crud.web_crud.crud_user import get_user, get_user_by_email_casefold, update_user_password
from backend.password_reset_service import (
    PASSWORD_RESET_TICKET_TTL_SECONDS,
    PasswordResetExpired,
    discard_password_reset_ticket,
    issue_password_reset_ticket,
    restore_password_reset_ticket,
    start_password_reset,
    take_password_reset_ticket,
    verify_password_reset_code,
)
from backend.registration_service import (
    OTP_FLOW_TTL_SECONDS,
    OTP_RESEND_COOLDOWN_SECONDS,
    RegistrationServiceUnavailable,
    RegistrationVerificationError,
    cancel_email_verification,
    resend_email_otp,
)
from backend.schema.user_schema import (
    EmailRegistrationResend,
    EmailRegistrationVerify,
    PasswordResetCancel,
    PasswordResetComplete,
    PasswordResetStart,
    PasswordResetVerifyRead,
    RegistrationChallengeRead,
)
from backend.turnstile_service import require_site_access

router = APIRouter(prefix="/auth/password-reset", tags=["auth"])


@router.post(
    "/start",
    response_model=RegistrationChallengeRead,
    dependencies=[Depends(email_send_rate_limiter), Depends(require_site_access)],
)
async def password_reset_start(
    request_data: PasswordResetStart,
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    event = "auth.password_reset_start"
    email = str(request_data.email).strip().casefold()
    has_account = await get_user_by_email_casefold(session, email) is not None
    try:
        challenge_id, expires_in = await start_password_reset(email)
    except (RegistrationVerificationError, RegistrationServiceUnavailable) as exc:
        raise _registration_error(exc, request=http_request, event=event) from exc
    # Logged for operators only; the response is identical either way.
    audit_auth_event(event, "PASSWORD_RESET_CODE_SENT" if has_account else "PASSWORD_RESET_NO_ACCOUNT", request=http_request)
    return RegistrationChallengeRead(
        challenge_id=challenge_id,
        expires_in=expires_in,
        flow_expires_in=OTP_FLOW_TTL_SECONDS,
        resend_available_in=OTP_RESEND_COOLDOWN_SECONDS,
    )


@router.post(
    "/resend",
    response_model=RegistrationChallengeRead,
    dependencies=[Depends(email_send_rate_limiter), Depends(require_site_access)],
)
async def password_reset_resend(request_data: EmailRegistrationResend, http_request: Request = None):
    try:
        expires_in, flow_expires_in = await resend_email_otp(request_data.challenge_id)
    except (RegistrationVerificationError, RegistrationServiceUnavailable) as exc:
        raise _registration_error(exc, request=http_request, event="auth.password_reset_resend") from exc
    audit_auth_event("auth.password_reset_resend", "OTP_RESENT", request=http_request)
    return RegistrationChallengeRead(
        challenge_id=request_data.challenge_id,
        expires_in=expires_in,
        flow_expires_in=flow_expires_in,
        resend_available_in=OTP_RESEND_COOLDOWN_SECONDS,
    )


@router.post(
    "/verify",
    response_model=PasswordResetVerifyRead,
    dependencies=[Depends(registration_verify_rate_limiter), Depends(require_site_access)],
)
async def password_reset_verify(
    request_data: EmailRegistrationVerify,
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    event = "auth.password_reset_verify"
    try:
        email = await verify_password_reset_code(request_data.challenge_id, request_data.otp)
    except (RegistrationVerificationError, RegistrationServiceUnavailable) as exc:
        raise _registration_error(exc, request=http_request, event=event) from exc
    user = await get_user_by_email_casefold(session, email)
    if user is None:
        # Safe to say now: the caller has just proven they own this mailbox.
        audit_auth_event(event, "PASSWORD_RESET_NO_ACCOUNT", request=http_request)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account uses this email. Sign up instead",
        )
    try:
        reset_token = await issue_password_reset_ticket(user.usr_id, email)
    except RegistrationServiceUnavailable as exc:
        raise _registration_error(exc, request=http_request, event=event) from exc
    audit_auth_event(event, "PASSWORD_RESET_VERIFIED", request=http_request, user_id=user.usr_id)
    return PasswordResetVerifyRead(reset_token=reset_token, email=email, expires_in=PASSWORD_RESET_TICKET_TTL_SECONDS)


@router.post(
    "/complete",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(registration_verify_rate_limiter), Depends(require_site_access)],
)
async def password_reset_complete(
    request_data: PasswordResetComplete,
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    event = "auth.password_reset_complete"
    try:
        ticket = await take_password_reset_ticket(request_data.reset_token)
    except (PasswordResetExpired, RegistrationServiceUnavailable) as exc:
        raise _registration_error(exc, request=http_request, event=event) from exc

    user = await get_user(session, ticket["user_id"])
    # The account must still own the address the code was sent to.
    if user is None or str(user.usr_email).casefold() != ticket["email"]:
        audit_auth_event(event, "PASSWORD_RESET_TICKET_INVALID", request=http_request)
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="This password reset has expired. Start again")
    # CM-08: password + usr_auth_version เปลี่ยนใน transaction เดียว commit แล้ว token เก่าทุกใบใช้ไม่ได้
    # ทันทีผ่านการเทียบ version ใน get_current_user - ไม่พึ่ง Redis จึงไม่มีช่องที่ Redis ล่มแล้ว session เดิมรอด
    # (เลิกเรียก revoke_all_user_tokens: marker แบบ timestamp ยังปฏิเสธ login ใหม่ในวินาทีเดียวกันด้วย)
    try:
        new_version = await update_user_password(session, user, request_data.new_password)
    except SQLAlchemyError as exc:
        await restore_password_reset_ticket(request_data.reset_token, ticket)
        audit_auth_event(event, "PASSWORD_RESET_DB_UNAVAILABLE", request=http_request)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password reset is temporarily unavailable. Please try again",
        ) from exc
    if new_version is None:
        # The account was deleted after the ticket was checked; nothing changed.
        audit_auth_event(event, "PASSWORD_RESET_TICKET_INVALID", request=http_request)
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="This password reset has expired. Start again")
    audit_auth_event(event, "PASSWORD_RESET_SESSIONS_INVALIDATED", request=http_request, user_id=user.usr_id)
    audit_auth_event(event, "PASSWORD_RESET_COMPLETED", request=http_request, user_id=user.usr_id)


@router.post(
    "/cancel",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(registration_cancel_rate_limiter), Depends(require_site_access)],
)
async def password_reset_cancel(request_data: PasswordResetCancel, http_request: Request = None):
    try:
        if request_data.challenge_id is not None:
            await cancel_email_verification(request_data.challenge_id)
        if request_data.reset_token is not None:
            await discard_password_reset_ticket(request_data.reset_token)
    except RegistrationServiceUnavailable as exc:
        raise _registration_error(exc, request=http_request, event="auth.password_reset_cancel") from exc
    audit_auth_event("auth.password_reset_cancel", "PASSWORD_RESET_CANCELLED", request=http_request)
