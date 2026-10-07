""" |======= API Authentication =======| """

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel.ext.asyncio.session import AsyncSession

# เรียกค่าตัวแปรและฟังก์ชั่นจากไฟล์อื่นมาทำงาน
from backend.api.user_deps import oauth2_scheme     # get bearer token จาก request
from backend.core.connect_database import get_session
from backend.core.load_environment import load_environment
from backend.core.auth import create_access_token, decode_access_token, revoke_access_token
from backend.core.auth_audit import audit_auth_event, failure_code
from backend.core.rate_limiter import FailureCounter, rate_limit_by_ip
from backend.core.signup_control import (
    SIGNUP_DISABLED_DETAIL,
    SIGNUP_DISABLED_OUTCOME,
    is_signup_enabled,
    require_signup_enabled,
)
from backend.crud.web_crud.crud_user import (
    authenticate_user,
    create_user,
    get_user_by_email_casefold,
    get_user_by_google_sub,
)
from backend.google_oauth_backend import (
    GoogleOAuthRejected,
    GoogleOAuthUnavailable,
    GOOGLE_ISSUERS,
    build_google_authorization_url,
    consume_google_callback_result,
    create_google_callback_result,
    exchange_code_and_verify_identity,
    frontend_callback_url,
    get_google_oauth_configuration,
)
from backend.google_oauth_state_service import (
    GoogleOAuthStateInvalid,
    GoogleOAuthStateUnavailable,
    consume_google_oauth_state,
    create_google_oauth_state,
)
from backend.registration_service import (
    OTP_FLOW_TTL_SECONDS,
    OTP_RESEND_COOLDOWN_SECONDS,
    REGISTRATION_TICKET_TTL_SECONDS,
    RegistrationFlowExpired,
    RegistrationRateLimited,
    RegistrationServiceUnavailable,
    RegistrationVerificationError,
    cancel_email_verification,
    discard_registration_ticket,
    issue_registration_ticket,
    resend_email_otp,
    restore_registration_ticket,
    start_email_verification,
    take_registration_ticket,
    verify_email_otp,
)
from backend.turnstile_service import (
    SITE_ACCESS_TTL_SECONDS,
    TurnstileRejected,
    TurnstileUnavailable,
    create_site_access_token,
    require_login_turnstile,
    require_site_access,
    verify_turnstile,
)
from backend.schema.user_schema import (
    EmailRegistrationResend,
    EmailRegistrationStart,
    EmailRegistrationVerify,
    GoogleOAuthComplete,
    GoogleOAuthStartRead,
    RegistrationCancel,
    RegistrationChallengeRead,
    RegistrationStatusRead,
    ClientConfigRead,
    RegistrationVerificationRead,
    SiteAccessRead,
    SiteAccessVerify,
    Token,
    UserCreate,
    VerifiedUserCreate,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Shown only after the caller has proven they own the address (correct email
# code, Google, or a registration ticket), so it does not enable enumeration.
# 409 tells the Sign Up page to switch to Sign In.
ACCOUNT_EXISTS_DETAIL = "This email is already in use"


def _account_exists_error() -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=ACCOUNT_EXISTS_DETAIL)

# ป้องกัน brute-force หน้า login
login_rate_limiter = rate_limit_by_ip("ratelimita:login", limit=5, window_seconds=60)

# กันสแปมสร้างบัญชีขยะ
register_rate_limiter = rate_limit_by_ip("ratelimit:register", limit=5, window_seconds=60)
registration_verify_rate_limiter = rate_limit_by_ip("ratelimit:register_verify", limit=10, window_seconds=60)
# Every verification email (start or resend) counts against one shared per-IP
# budget, separate from /register. It sends real email, so it fails closed.
# The per-address budget (6 per hour) lives in registration_service.
email_send_rate_limiter = rate_limit_by_ip(
    "ratelimit:register_email_send", limit=5, window_seconds=15 * 60, fail_closed=True
)
registration_cancel_rate_limiter = rate_limit_by_ip("ratelimit:register_cancel", limit=10, window_seconds=60)
# This endpoint calls an external verification service and is the public gate
# in front of every application route. Rate-limit before Siteverify and fail
# closed when Redis is unavailable so an outage cannot remove the abuse guard.
turnstile_verify_rate_limiter = rate_limit_by_ip(
    "ratelimit:turnstile_verify",
    limit=20,
    window_seconds=60,
    fail_closed=True,
)
google_oauth_start_rate_limiter = rate_limit_by_ip(
    "ratelimit:google_oauth_start", limit=5, window_seconds=15 * 60, fail_closed=True
)
# Flood guard for every callback, plus a stricter budget for failed ones only:
# a user who signs up normally never spends the failure budget.
google_oauth_callback_rate_limiter = rate_limit_by_ip(
    "ratelimit:google_oauth_callback", limit=20, window_seconds=60, fail_closed=True
)
google_callback_failures = FailureCounter(
    "ratelimit:google_callback_failures", limit=10, window_seconds=15 * 60
)
google_oauth_complete_rate_limiter = rate_limit_by_ip(
    "ratelimit:google_oauth_complete", limit=10, window_seconds=60, fail_closed=True
)

# เมื่อเรียกใช้ api นี้จะทำการตรวจสอบข้อมูลการเข้าสู่ระบบ โดยก่อนทำงานจะเรียกใข้เครื่องมือตรวจสอบ rate limit
# Order matters: rate limit before Siteverify (no free calls to Cloudflare),
# Turnstile before Argon2 (no password check without a fresh human token).
@router.post(
    "/login",
    response_model=Token,
    dependencies=[
        Depends(login_rate_limiter),
        Depends(require_site_access),
        Depends(require_login_turnstile),
    ],
)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    # ยืนยันตัวตนด้วย username/password ของบัญชีเจ้าของอุปกรณ์
    user = await authenticate_user(session, form_data.username, form_data.password)
    if user is None:
        # The username is deliberately not logged (it may be a mistyped password).
        audit_auth_event("auth.login", "LOGIN_FAILED", request=http_request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username, email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    audit_auth_event("auth.login", "LOGIN_SUCCEEDED", request=http_request, user_id=user.usr_id)
    # สร้าง token ให้กับ user
    return Token(access_token=create_access_token(user.usr_id, user.usr_auth_version))


async def _restore_ticket_quietly(token: str, ticket: dict) -> None:
    try:
        await restore_registration_ticket(token, ticket)
    except RegistrationServiceUnavailable:
        pass


def _registration_error(
    exc: Exception,
    *,
    request: Request | None = None,
    event: str | None = None,
) -> HTTPException:
    if event is not None:
        audit_auth_event(event, failure_code(exc), request=request)
    # 410 tells the Sign Up page the flow is over and it must start again;
    # 400 means the user can correct the input or request a new code.
    if isinstance(exc, RegistrationRateLimited):
        return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc))
    if isinstance(exc, RegistrationFlowExpired):
        return HTTPException(status_code=status.HTTP_410_GONE, detail=str(exc))
    if isinstance(exc, RegistrationVerificationError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))


# CM-12: บอกหน้าเว็บว่าเปิดสมัครไหม (UX เท่านั้น) - คืนแค่ boolean ไม่มีเหตุผล/ค่า environment
# ไม่ต้อง login/Turnstile เพราะหน้า Sign In ต้องรู้ก่อนผู้ใช้ทำอะไร; ห้าม cache เพื่อให้เห็นค่าใหม่ทันที
@router.get("/registration-status", response_model=RegistrationStatusRead)
async def registration_status(response: Response):
    response.headers["Cache-Control"] = "no-store"
    return RegistrationStatusRead(enabled=is_signup_enabled(), google_enabled=load_environment().google_configured)


# The page reads this on load, so switching Cloudflare on/off or changing its site key in
# the config file only needs a restart, not a rebuild of the website.
@router.get("/client-config", response_model=ClientConfigRead)
async def client_config(response: Response):
    response.headers["Cache-Control"] = "no-store"
    settings = load_environment()
    return ClientConfigRead(
        turnstile_enabled=settings.TURNSTILE_ENABLED,
        turnstile_site_key=settings.TURNSTILE_SITE_KEY if settings.TURNSTILE_ENABLED else None,
    )


@router.post(
    "/site-access/verify",
    response_model=SiteAccessRead,
    dependencies=[Depends(turnstile_verify_rate_limiter)],
)
async def site_access_verify(request_data: SiteAccessVerify, http_request: Request):
    try:
        await verify_turnstile(
            request_data.turnstile_token,
            http_request.client.host if http_request.client else None,
            action="site_access",
        )
    except TurnstileRejected as exc:
        audit_auth_event("auth.site_access", failure_code(exc), request=http_request)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except TurnstileUnavailable as exc:
        audit_auth_event("auth.site_access", failure_code(exc), request=http_request)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    audit_auth_event("auth.site_access", "SITE_ACCESS_GRANTED", request=http_request)
    return SiteAccessRead(
        site_access_token=create_site_access_token(),
        expires_in=SITE_ACCESS_TTL_SECONDS,
    )


@router.post(
    "/register/google/start",
    response_model=GoogleOAuthStartRead,
    dependencies=[
        Depends(require_signup_enabled("auth.google_start")),
        Depends(google_oauth_start_rate_limiter),
        Depends(require_site_access),
    ],
)
async def register_google_oauth_start(http_request: Request = None):
    try:
        # Validate provider configuration before allocating a Redis state so a
        # missing local secret does not leave unusable records behind.
        get_google_oauth_configuration()
        flow = await create_google_oauth_state(turnstile_verified=True)
        authorization_url = build_google_authorization_url(flow)
    except GoogleOAuthStateInvalid as exc:
        audit_auth_event("auth.google_start", failure_code(exc), request=http_request)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except (GoogleOAuthStateUnavailable, GoogleOAuthUnavailable) as exc:
        audit_auth_event("auth.google_start", failure_code(exc), request=http_request)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    audit_auth_event("auth.google_start", "GOOGLE_FLOW_STARTED", request=http_request)
    return GoogleOAuthStartRead(
        authorization_url=authorization_url,
        expires_in=flow.expires_in,
    )


def _google_callback_error_redirect(error: str, fallback_status: int):
    try:
        url = frontend_callback_url(error=error)
    except GoogleOAuthUnavailable as exc:
        # Without FRONTEND_BASE_URL there is no safe page to return to.
        raise HTTPException(status_code=fallback_status, detail="Google authorization session is invalid") from exc
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


@router.get(
    "/google/callback",
    dependencies=[Depends(google_oauth_callback_rate_limiter)],
)
async def google_oauth_callback(
    session: AsyncSession = Depends(get_session),
    state_value: str | None = Query(default=None, alias="state", max_length=512),
    code: str | None = Query(default=None, max_length=4096),
    provider_error: str | None = Query(default=None, alias="error", max_length=128),
    authorization_issuer: str | None = Query(default=None, alias="iss", max_length=128),
    http_request: Request = None,
):
    def audit(outcome: str) -> None:
        audit_auth_event("auth.google_callback", outcome, request=http_request)

    # CM-12: the browser is coming back from Google, so answer with the usual redirect
    # instead of JSON - and before the failure counter, state, code exchange or any lookup.
    # The unconsumed state simply expires with its TTL.
    if not is_signup_enabled():
        audit(SIGNUP_DISABLED_OUTCOME)
        try:
            url = frontend_callback_url(error="signup_disabled")
        except GoogleOAuthUnavailable as exc:
            # no safe page to return to - plain 503 with the same fixed text
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=SIGNUP_DISABLED_DETAIL) from exc
        return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)

    # Forged, replayed or expired callbacks are what an attacker produces;
    # consent cancellation, existing accounts and Google outages are not.
    async def record_failure(outcome: str) -> None:
        audit(outcome)
        if http_request is not None:
            await google_callback_failures.record_failure(http_request)

    if http_request is not None and await google_callback_failures.is_blocked(http_request):
        audit("GOOGLE_CALLBACK_RATE_LIMITED")
        return _google_callback_error_redirect("rate_limited", status.HTTP_429_TOO_MANY_REQUESTS)

    # The browser arrives here from Google, so state failures go back to the
    # Sign Up page (which already maps these codes) instead of a raw JSON body.
    if not state_value:
        await record_failure("OAUTH_STATE_INVALID")
        return _google_callback_error_redirect("invalid_state", status.HTTP_400_BAD_REQUEST)
    try:
        oauth_state = await consume_google_oauth_state(state_value)
    except GoogleOAuthStateInvalid as exc:
        await record_failure(failure_code(exc))
        return _google_callback_error_redirect("invalid_state", status.HTTP_400_BAD_REQUEST)
    except GoogleOAuthStateUnavailable as exc:
        audit(failure_code(exc))
        return _google_callback_error_redirect("unavailable", status.HTTP_503_SERVICE_UNAVAILABLE)

    if authorization_issuer is not None and authorization_issuer not in GOOGLE_ISSUERS:
        await record_failure("GOOGLE_ISSUER_MISMATCH")
        return RedirectResponse(frontend_callback_url(error="rejected"), status_code=status.HTTP_303_SEE_OTHER)
    if provider_error or not code:
        # Google's error value is attacker-controllable, so it is not logged.
        audit("GOOGLE_CONSENT_CANCELLED")
        return RedirectResponse(frontend_callback_url(error="cancelled"), status_code=status.HTTP_303_SEE_OTHER)

    try:
        identity = await exchange_code_and_verify_identity(
            code,
            code_verifier=oauth_state.code_verifier,
            expected_nonce=oauth_state.nonce,
        )
        if (
            await get_user_by_email_casefold(session, identity.email) is not None
            or await get_user_by_google_sub(session, identity.subject) is not None
        ):
            # Safe to tell this browser: Google just proved it owns that email.
            audit("REGISTRATION_EMAIL_EXISTS")
            return RedirectResponse(frontend_callback_url(error="account_exists"), status_code=status.HTTP_303_SEE_OTHER)
        result_code = await create_google_callback_result(identity)
        audit("GOOGLE_IDENTITY_VERIFIED")
        return RedirectResponse(
            frontend_callback_url(result_code=result_code),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except GoogleOAuthRejected as exc:
        await record_failure(failure_code(exc))
        return RedirectResponse(frontend_callback_url(error="rejected"), status_code=status.HTTP_303_SEE_OTHER)
    except GoogleOAuthUnavailable as exc:
        audit(failure_code(exc))
        return RedirectResponse(frontend_callback_url(error="unavailable"), status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/register/google/complete",
    response_model=RegistrationVerificationRead,
    dependencies=[
        Depends(require_signup_enabled("auth.google_complete")),
        Depends(google_oauth_complete_rate_limiter),
        Depends(require_site_access),
    ],
)
async def register_google_oauth_complete(
    request_data: GoogleOAuthComplete,
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    event = "auth.google_complete"
    try:
        identity = await consume_google_callback_result(request_data.result_code)
        if (
            await get_user_by_email_casefold(session, identity.email) is not None
            or await get_user_by_google_sub(session, identity.subject) is not None
        ):
            audit_auth_event(event, "REGISTRATION_EMAIL_EXISTS", request=http_request)
            raise _account_exists_error()
        ticket = await issue_registration_ticket(
            identity.email,
            "google",
            google_sub=identity.subject,
        )
    except GoogleOAuthRejected as exc:
        audit_auth_event(event, failure_code(exc), request=http_request)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except (GoogleOAuthUnavailable, RegistrationServiceUnavailable) as exc:
        audit_auth_event(event, failure_code(exc), request=http_request)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    audit_auth_event(event, "GOOGLE_TICKET_ISSUED", request=http_request)
    return RegistrationVerificationRead(
        registration_token=ticket,
        email=identity.email,
        expires_in=REGISTRATION_TICKET_TTL_SECONDS,
    )


@router.post(
    "/register/email/start",
    response_model=RegistrationChallengeRead,
    dependencies=[
        Depends(require_signup_enabled("auth.email_start")),
        Depends(email_send_rate_limiter),
        Depends(require_site_access),
    ],
)
async def register_email_start(
    request_data: EmailRegistrationStart,
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    event = "auth.email_start"
    email = str(request_data.email).strip().casefold()
    # Registered and unregistered addresses get the same response and a real
    # code; the difference is revealed only after the code is verified.
    account_exists = await get_user_by_email_casefold(session, email) is not None
    try:
        challenge_id, expires_in = await start_email_verification(email)
    except (RegistrationVerificationError, RegistrationServiceUnavailable) as exc:
        raise _registration_error(exc, request=http_request, event=event) from exc
    audit_auth_event(
        event,
        "REGISTRATION_EMAIL_EXISTS" if account_exists else "OTP_SENT",
        request=http_request,
    )
    return RegistrationChallengeRead(
        challenge_id=challenge_id,
        expires_in=expires_in,
        flow_expires_in=OTP_FLOW_TTL_SECONDS,
        resend_available_in=OTP_RESEND_COOLDOWN_SECONDS,
    )


@router.post(
    "/register/email/verify",
    response_model=RegistrationVerificationRead,
    dependencies=[
        Depends(require_signup_enabled("auth.email_verify")),
        Depends(registration_verify_rate_limiter),
        Depends(require_site_access),
    ],
)
async def register_email_verify(
    request: EmailRegistrationVerify,
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    try:
        ticket, email = await verify_email_otp(request.challenge_id, request.otp)
    except (RegistrationVerificationError, RegistrationServiceUnavailable) as exc:
        raise _registration_error(exc, request=http_request, event="auth.email_verify") from exc
    # Checked now, not at start, so the answer reflects the database at the
    # moment ownership is proven.
    if await get_user_by_email_casefold(session, email) is not None:
        try:
            await discard_registration_ticket(ticket)
        except RegistrationServiceUnavailable:
            pass  # the ticket still cannot create a second account (DB unique email)
        audit_auth_event("auth.email_verify", "REGISTRATION_EMAIL_EXISTS", request=http_request)
        raise _account_exists_error()
    audit_auth_event("auth.email_verify", "OTP_VERIFIED", request=http_request)
    return RegistrationVerificationRead(
        registration_token=ticket,
        email=email,
        expires_in=REGISTRATION_TICKET_TTL_SECONDS,
    )


@router.post(
    "/register/email/resend",
    response_model=RegistrationChallengeRead,
    dependencies=[
        Depends(require_signup_enabled("auth.email_resend")),
        Depends(email_send_rate_limiter),
        Depends(require_site_access),
    ],
)
async def register_email_resend(request_data: EmailRegistrationResend, http_request: Request = None):
    # The address comes from the stored challenge, never from this request.
    try:
        expires_in, flow_expires_in = await resend_email_otp(request_data.challenge_id)
    except (RegistrationVerificationError, RegistrationServiceUnavailable) as exc:
        raise _registration_error(exc, request=http_request, event="auth.email_resend") from exc
    audit_auth_event("auth.email_resend", "OTP_RESENT", request=http_request)
    return RegistrationChallengeRead(
        challenge_id=request_data.challenge_id,
        expires_in=expires_in,
        flow_expires_in=flow_expires_in,
        resend_available_in=OTP_RESEND_COOLDOWN_SECONDS,
    )


@router.post(
    "/register/cancel",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(registration_cancel_rate_limiter), Depends(require_site_access)],
)
async def register_cancel(request_data: RegistrationCancel, http_request: Request = None):
    # Idempotent: unknown or already-used references succeed silently, and no
    # user record or Google account is touched.
    try:
        if request_data.challenge_id is not None:
            await cancel_email_verification(request_data.challenge_id)
        if request_data.registration_token is not None:
            await discard_registration_ticket(request_data.registration_token)
    except RegistrationServiceUnavailable as exc:
        raise _registration_error(exc, request=http_request, event="auth.register_cancel") from exc
    audit_auth_event("auth.register_cancel", "REGISTRATION_CANCELLED", request=http_request)


# สมัครได้ต่อเมื่อ Email OTP หรือ Google ผ่านแล้วเท่านั้น และ auto-login เมื่อสำเร็จ
# CM-12: guard มาก่อน take_registration_ticket() เสมอ - ticket ที่ออกก่อนปิด signup ยังอยู่ครบและสร้าง user ไม่ได้
@router.post(
    "/register",
    response_model=Token,
    dependencies=[
        Depends(require_signup_enabled("auth.register")),
        Depends(register_rate_limiter),
        Depends(require_site_access),
    ],
)
async def register(
    request: VerifiedUserCreate,
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    event = "auth.register"

    def audit(outcome: str, user_id: str | None = None) -> None:
        audit_auth_event(event, outcome, request=http_request, user_id=user_id)

    try:
        ticket = await take_registration_ticket(request.registration_token)
    except RegistrationServiceUnavailable as exc:
        raise _registration_error(exc, request=http_request, event=event) from exc
    if ticket is None:
        audit("REGISTRATION_TICKET_EXPIRED")
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Registration verification has expired. Verify your email again",
        )
    user_create = UserCreate(
        usr_name=request.usr_name,
        usr_email=ticket["email"],
        usr_passwd=request.usr_passwd,
    )
    provider = ticket.get("provider")
    google_sub = ticket.get("google_sub")
    if provider not in {"email", "google"} or (
        provider == "google" and not isinstance(google_sub, str)
    ):
        audit("REGISTRATION_TICKET_INVALID")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration verification is invalid. Verify your email again",
        )
    try:
        user = await create_user(
            session,
            user_create,
            google_sub=google_sub if provider == "google" else None,
            email_verified_at=datetime.now(timezone.utc),
        )
    except SQLAlchemyError as exc:
        # Restoring is safe even if the commit actually landed: the email and
        # Google-sub unique constraints reject a second account on retry.
        await _restore_ticket_quietly(request.registration_token, ticket)
        audit("REGISTRATION_DB_UNAVAILABLE")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registration is temporarily unavailable. Please try again",
        ) from exc
    if user is None:
        email_taken = await get_user_by_email_casefold(session, ticket["email"]) is not None
        sub_taken = provider == "google" and await get_user_by_google_sub(session, google_sub) is not None
        if email_taken or sub_taken:
            # Retrying can never succeed, so the ticket stays consumed.
            audit("REGISTRATION_CONFLICT")
            raise _account_exists_error()
        # Only the chosen username clashed: keep the verification so the user
        # can pick another name without receiving a new code.
        await _restore_ticket_quietly(request.registration_token, ticket)
        audit("REGISTRATION_USERNAME_TAKEN")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This username is already taken",
        )
    audit("REGISTRATION_CREATED", user_id=user.usr_id)
    # สร้าง token ให้กับ user
    return Token(access_token=create_access_token(user.usr_id, user.usr_auth_version))

# api จัดการเกี่ยวกับการ logout ทำลายสิทธิการใช้งาน token แล้วจำเอาไว้ โดย token จะดึงมาจาก http req
@router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload is not None:
        await revoke_access_token(payload)
    return {"detail": "Logged out successfully"}
