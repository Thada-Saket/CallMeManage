"""Secure, short-lived registration verification state.

Email OTPs and registration tickets are deliberately kept in Redis rather than
the database. OTP values are never stored in plaintext and every successful
verification produces an opaque, one-time registration ticket.
"""

import asyncio
import hashlib
import hmac
import json
import secrets
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.headerregistry import Address

from pydantic import EmailStr, TypeAdapter, ValidationError
from redis.exceptions import RedisError

from backend.core.auth_audit import AuthFailure
from backend.core.load_environment import load_environment
from backend.core.redis_client import get_redis


OTP_TTL_SECONDS = 5 * 60
# Hard deadline for one email challenge, including every resend.
OTP_FLOW_TTL_SECONDS = 10 * 60
OTP_RESEND_COOLDOWN_SECONDS = 60
# Emails (codes or "account exists" notices) one address may receive per hour,
# so the sign-up form cannot be used to flood someone else's inbox.
EMAIL_SENDS_PER_HOUR = 6
EMAIL_SEND_WINDOW_SECONDS = 60 * 60
OTP_MAX_ATTEMPTS = 5
REGISTRATION_TICKET_TTL_SECONDS = 15 * 60

_EMAIL_ADAPTER = TypeAdapter(EmailStr)


class RegistrationServiceUnavailable(AuthFailure, RuntimeError):
    code = "REGISTRATION_STORE_UNAVAILABLE"


class RegistrationVerificationError(AuthFailure, ValueError):
    code = "REGISTRATION_REJECTED"


class RegistrationRateLimited(RegistrationVerificationError):
    """Too many emails for this address; the API answers 429."""

    code = "OTP_EMAIL_HOURLY_LIMIT"


class RegistrationFlowExpired(RegistrationVerificationError):
    """The challenge or ticket is gone; the user must start registration again."""

    code = "REGISTRATION_FLOW_EXPIRED"


def normalize_email(value: str) -> str:
    return str(_EMAIL_ADAPTER.validate_python(value)).strip().casefold()


def _otp_hmac_key() -> bytes:
    # Domain-separated from the JWT signing key so an OTP digest can never be
    # confused with, or help forge, any other value signed with that secret.
    secret = load_environment().JWT_SECRET_KEY.encode("utf-8")
    return hmac.new(secret, b"callmemanage:registration-otp:v1", hashlib.sha256).digest()


# What an email code is for. The purpose is part of the HMAC input, so a code
# issued for sign-up can never verify a password reset, or the other way round.
PURPOSE_REGISTRATION = "registration"
PURPOSE_PASSWORD_RESET = "password_reset"
_PURPOSES = (PURPOSE_REGISTRATION, PURPOSE_PASSWORD_RESET)


def _otp_digest(challenge_id: str, otp: str, purpose: str = PURPOSE_REGISTRATION) -> str:
    message = f"{purpose}:{challenge_id}:{otp}".encode("utf-8")
    return hmac.new(_otp_hmac_key(), message, hashlib.sha256).hexdigest()


def _generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _ticket_key(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"auth:registration:ticket:{digest}"


def _challenge_key(challenge_id: str) -> str:
    return f"auth:registration:otp:{challenge_id}"


def _cooldown_key(email: str) -> str:
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return f"auth:registration:email_cooldown:{digest}"


def _email_sends_key(email: str) -> str:
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return f"auth:registration:email_sends:{digest}"


def _active_challenge_key(email: str, purpose: str = PURPOSE_REGISTRATION) -> str:
    # One live challenge per address and purpose: a password reset does not
    # cancel a sign-up in progress for the same address.
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    if purpose == PURPOSE_PASSWORD_RESET:
        return f"auth:password_reset:email_active:{digest}"
    return f"auth:registration:email_active:{digest}"


# Each script below changes a challenge in one Redis step, so concurrent
# requests cannot interleave between a read and the write that depends on it.

# The challenge key lives until the flow deadline so an expired code can
# still be resent; each code's own lifetime is the otp_expires_at field.

# KEYS: new challenge, active pointer. ARGV: challenge prefix, new id, email,
# digest, code deadline, flow deadline (both epoch seconds), flow TTL, purpose.
# Starting a new challenge revokes the previous one for the same email.
_START_SCRIPT = """
local previous = redis.call('GET', KEYS[2])
if previous then
  redis.call('DEL', ARGV[1] .. previous)
end
redis.call('HSET', KEYS[1], 'email', ARGV[3], 'otp_digest', ARGV[4], 'attempts', '0',
  'otp_expires_at', ARGV[5], 'flow_expires_at', ARGV[6], 'purpose', ARGV[8])
redis.call('EXPIRE', KEYS[1], ARGV[7])
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[7])
return 1
"""

# KEYS: challenge. ARGV: new digest, new code deadline.
# Replaces the code in place: the old OTP stops matching immediately.
_RESEND_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
redis.call('HSET', KEYS[1], 'otp_digest', ARGV[1], 'attempts', '0', 'otp_expires_at', ARGV[2])
return 1
"""

# KEYS: challenge. ARGV: max attempts, now (epoch seconds).
# Returns {0} when the challenge is gone, {-1} when locked, {-2} when only the
# current code expired (resend still works). The attempt is counted before
# the code is compared, so parallel guesses can never compare more than
# OTP_MAX_ATTEMPTS codes against one challenge.
_ATTEMPT_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {0}
end
if tonumber(redis.call('HGET', KEYS[1], 'otp_expires_at') or '0') <= tonumber(ARGV[2]) then
  return {-2}
end
local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if attempts > tonumber(ARGV[1]) then
  redis.call('DEL', KEYS[1])
  return {-1}
end
return {attempts, redis.call('HGET', KEYS[1], 'otp_digest') or '', redis.call('HGET', KEYS[1], 'email') or ''}
"""

# KEYS: challenge, active pointer. ARGV: matched digest, challenge id.
# Only the request whose digest is still current may consume the challenge,
# so a correct code submitted twice issues at most one ticket.
_CONSUME_SCRIPT = """
if redis.call('HGET', KEYS[1], 'otp_digest') ~= ARGV[1] then
  return 0
end
redis.call('DEL', KEYS[1])
if redis.call('GET', KEYS[2]) == ARGV[2] then
  redis.call('DEL', KEYS[2])
end
return 1
"""

# KEYS: challenge, active pointer, cooldown, hourly sends. ARGV: challenge id,
# send id. Gives back the cooldown and the hourly slot of an email that was
# never delivered.
_DISCARD_SCRIPT = """
redis.call('DEL', KEYS[1], KEYS[3])
redis.call('ZREM', KEYS[4], ARGV[2])
if redis.call('GET', KEYS[2]) == ARGV[1] then
  redis.call('DEL', KEYS[2])
end
return 1
"""

# KEYS: cooldown, hourly sends. ARGV: now, window, hourly limit, send id,
# cooldown seconds. Returns 1 when a send is allowed (and records it),
# -1 during the cooldown, -2 when the hourly limit is reached.
_CLAIM_SEND_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 1 then
  return -1
end
redis.call('ZREMRANGEBYSCORE', KEYS[2], 0, tonumber(ARGV[1]) - tonumber(ARGV[2]))
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[3]) then
  return -2
end
redis.call('SET', KEYS[1], '1', 'EX', ARGV[5])
redis.call('ZADD', KEYS[2], ARGV[1], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[2])
return 1
"""

# KEYS: challenge, active pointer. ARGV: challenge id.
# Cancel keeps the cooldown so cancel + start cannot bypass the resend limit.
_CANCEL_SCRIPT = """
redis.call('DEL', KEYS[1])
if redis.call('GET', KEYS[2]) == ARGV[1] then
  redis.call('DEL', KEYS[2])
end
return 1
"""

_REDIS_ERRORS = (RedisError, RuntimeError, OSError)


def _send_otp_sync(recipient: str, otp: str, expires_in: int) -> None:
    settings = load_environment()
    message = EmailMessage()
    message["Subject"] = "Verify your CallMeManage account"
    message["From"] = Address(settings.SMTP_FROM_NAME, addr_spec=settings.SMTP_USERNAME)
    message["To"] = recipient
    message.set_content(
        f"Your verification code is: {otp}\n\n"
        f"This code expires in {max(1, expires_in // 60)} minutes.\n"
        "Do not share this code with anyone.\n"
        "If you did not request this code, you can ignore this email."
    )
    _deliver(settings, message)


def _send_password_reset_code_sync(recipient: str, otp: str, expires_in: int) -> None:
    settings = load_environment()
    message = EmailMessage()
    message["Subject"] = "Reset your CallMeManage password"
    message["From"] = Address(settings.SMTP_FROM_NAME, addr_spec=settings.SMTP_USERNAME)
    message["To"] = recipient
    message.set_content(
        f"Your password reset code is: {otp}\n\n"
        f"This code expires in {max(1, expires_in // 60)} minutes.\n"
        "Do not share this code with anyone.\n"
        "If you did not ask to reset your password, you can ignore this email. "
        "Your password has not been changed."
    )
    _deliver(settings, message)


def _deliver(settings, message: EmailMessage) -> None:
    if not settings.smtp_configured:
        # email switched off (EMAIL_ENABLED=no) in the config file: callers treat this like any delivery failure
        # (the code is discarded and the user sees "temporarily unavailable")
        raise RuntimeError("Email delivery is not configured")
    context = ssl.create_default_context()
    if settings.SMTP_PORT == 465:
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15, context=context) as smtp:
            smtp.login(settings.SMTP_USERNAME, settings.SMTP_APP_PASSWORD)
            smtp.send_message(message)
        return

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.ehlo()
        smtp.login(settings.SMTP_USERNAME, settings.SMTP_APP_PASSWORD)
        smtp.send_message(message)


# Every address, registered or not, receives a real code through the same
# path (same response, cooldown, limits and SMTP delay), so this step cannot
# reveal which emails have accounts. Whether the address is already registered
# is decided only after the code proves mailbox ownership (see the verify route).
async def _send_otp_or_discard(
    challenge_id: str,
    email: str,
    otp: str,
    expires_in: int,
    send_id: str = "",
    purpose: str = PURPOSE_REGISTRATION,
) -> None:
    try:
        if purpose == PURPOSE_PASSWORD_RESET:
            await asyncio.to_thread(_send_password_reset_code_sync, email, otp, expires_in)
        else:
            await asyncio.to_thread(_send_otp_sync, email, otp, expires_in)
    except Exception as exc:
        # The user never received this code, so it must not stay redeemable
        # and must not hold the resend cooldown.
        try:
            await get_redis().eval(
                _DISCARD_SCRIPT,
                4,
                _challenge_key(challenge_id),
                _active_challenge_key(email, purpose),
                _cooldown_key(email),
                _email_sends_key(email),
                challenge_id,
                send_id,
            )
        except _REDIS_ERRORS:
            pass
        raise RegistrationServiceUnavailable("The verification email could not be sent", code="SMTP_SEND_FAILED") from exc


async def _claim_send_slot(email: str) -> str:
    """Reserve one email for this address, or raise if it must wait."""
    send_id = secrets.token_hex(8)
    result = await get_redis().eval(
        _CLAIM_SEND_SCRIPT,
        2,
        _cooldown_key(email),
        _email_sends_key(email),
        time.time(),
        EMAIL_SEND_WINDOW_SECONDS,
        EMAIL_SENDS_PER_HOUR,
        send_id,
        OTP_RESEND_COOLDOWN_SECONDS,
    )
    if int(result) == -1:
        raise RegistrationVerificationError(
            "Please wait before requesting another verification code", code="OTP_RESEND_COOLDOWN"
        )
    if int(result) == -2:
        raise RegistrationRateLimited(
            "Too many verification emails were requested for this address. Try again later"
        )
    return send_id


async def start_email_verification(email: str, *, purpose: str = PURPOSE_REGISTRATION) -> tuple[str, int]:
    if purpose not in _PURPOSES:
        raise ValueError("Unknown email verification purpose")
    normalized = normalize_email(email)
    challenge_id = secrets.token_urlsafe(24)
    otp = _generate_otp()
    now = int(time.time())

    try:
        send_id = await _claim_send_slot(normalized)
        await get_redis().eval(
            _START_SCRIPT,
            2,
            _challenge_key(challenge_id),
            _active_challenge_key(normalized, purpose),
            _challenge_key(""),
            challenge_id,
            normalized,
            _otp_digest(challenge_id, otp, purpose),
            now + OTP_TTL_SECONDS,
            now + OTP_FLOW_TTL_SECONDS,
            OTP_FLOW_TTL_SECONDS,
            purpose,
        )
    except RegistrationVerificationError:
        raise
    except _REDIS_ERRORS as exc:
        raise RegistrationServiceUnavailable("Registration verification is temporarily unavailable") from exc

    await _send_otp_or_discard(challenge_id, normalized, otp, OTP_TTL_SECONDS, send_id, purpose)
    return challenge_id, OTP_TTL_SECONDS


async def resend_email_otp(challenge_id: str) -> tuple[int, int]:
    """Send a new code for an existing challenge to the same email only.

    Returns (code expires_in, flow remaining) in seconds.
    """
    key = _challenge_key(challenge_id)
    expired = RegistrationFlowExpired("The verification session has expired. Start again")
    try:
        record = await get_redis().hgetall(key)
        if not record:
            raise expired
        email = normalize_email(record["email"])
        now = int(time.time())
        remaining = int(record["flow_expires_at"]) - now
        if remaining <= 0:
            await get_redis().delete(key)
            raise expired
        purpose = record.get("purpose", PURPOSE_REGISTRATION)
        send_id = await _claim_send_slot(email)
        otp = _generate_otp()
        expires_in = min(OTP_TTL_SECONDS, remaining)
        replaced = await get_redis().eval(
            _RESEND_SCRIPT, 1, key, _otp_digest(challenge_id, otp, purpose), now + expires_in
        )
        if not replaced:
            raise expired
    except RegistrationVerificationError:
        raise
    except (*_REDIS_ERRORS, KeyError, ValueError, ValidationError) as exc:
        raise RegistrationServiceUnavailable("Registration verification is temporarily unavailable") from exc

    await _send_otp_or_discard(challenge_id, email, otp, expires_in, send_id, purpose)
    return expires_in, remaining


async def cancel_email_verification(challenge_id: str) -> None:
    """Idempotently revoke an email challenge; unknown ids are not an error."""
    key = _challenge_key(challenge_id)
    try:
        email, purpose = await get_redis().hmget(key, "email", "purpose")
        if not email:
            await get_redis().delete(key)
            return
        await get_redis().eval(
            _CANCEL_SCRIPT,
            2,
            key,
            _active_challenge_key(normalize_email(email), purpose or PURPOSE_REGISTRATION),
            challenge_id,
        )
    except (*_REDIS_ERRORS, ValidationError, ValueError) as exc:
        raise RegistrationServiceUnavailable("Registration verification is temporarily unavailable") from exc


async def discard_registration_ticket(token: str) -> None:
    """Idempotently revoke a verified-but-unused registration ticket."""
    try:
        await get_redis().delete(_ticket_key(token))
    except _REDIS_ERRORS as exc:
        raise RegistrationServiceUnavailable("Registration verification is temporarily unavailable") from exc


async def issue_registration_ticket(
    email: str,
    provider: str,
    *,
    google_sub: str | None = None,
) -> str:
    token = secrets.token_urlsafe(32)
    payload = {"email": normalize_email(email), "provider": provider}
    if google_sub is not None:
        if not google_sub.isascii() or not 1 <= len(google_sub) <= 255:
            raise RegistrationVerificationError("Google returned an invalid account identifier", code="GOOGLE_TOKEN_INVALID")
        payload["google_sub"] = google_sub
    try:
        await get_redis().set(
            _ticket_key(token),
            json.dumps(payload),
            ex=REGISTRATION_TICKET_TTL_SECONDS,
        )
    except (RedisError, RuntimeError, OSError) as exc:
        raise RegistrationServiceUnavailable("Registration verification is temporarily unavailable") from exc
    return token


# Compatibility for existing internal tests/callers. New code should use the
# public name because the Authorization Code callback also issues tickets.
async def _issue_registration_ticket(email: str, provider: str) -> str:
    return await issue_registration_ticket(email, provider)


async def verify_email_otp(challenge_id: str, otp: str) -> tuple[str, str]:
    """Sign-up: verify the code and issue a one-time registration ticket."""
    email = await verify_email_code(challenge_id, otp, purpose=PURPOSE_REGISTRATION)
    return await issue_registration_ticket(email, "email"), email


async def verify_email_code(challenge_id: str, otp: str, *, purpose: str) -> str:
    """Verify and consume an email code for `purpose`; return the address."""
    redis = get_redis()
    key = _challenge_key(challenge_id)
    try:
        result = await redis.eval(_ATTEMPT_SCRIPT, 1, key, OTP_MAX_ATTEMPTS, int(time.time()))
        attempts = int(result[0])
        if attempts == 0:
            raise RegistrationFlowExpired("The verification session has expired. Start again")
        if attempts == -1:
            raise RegistrationFlowExpired("Too many incorrect attempts. Start again", code="OTP_ATTEMPTS_EXCEEDED")
        if attempts == -2:
            raise RegistrationVerificationError("This code has expired. Request a new code", code="OTP_EXPIRED")
        stored_digest, stored_email = result[1], result[2]
        candidate = _otp_digest(challenge_id, otp, purpose)
        if not hmac.compare_digest(stored_digest, candidate):
            if attempts >= OTP_MAX_ATTEMPTS:
                await redis.delete(key)
                raise RegistrationFlowExpired("Too many incorrect attempts. Start again", code="OTP_ATTEMPTS_EXCEEDED")
            raise RegistrationVerificationError("Incorrect verification code", code="OTP_INVALID")
        email = normalize_email(stored_email)
        consumed = await redis.eval(
            _CONSUME_SCRIPT,
            2,
            key,
            _active_challenge_key(email, purpose),
            candidate,
            challenge_id,
        )
        if not consumed:
            # Another request consumed it first, or a resend replaced the code.
            raise RegistrationVerificationError("This code is no longer valid. Request a new code", code="OTP_INVALID")
    except RegistrationVerificationError:
        raise
    except (*_REDIS_ERRORS, IndexError, TypeError, ValueError, ValidationError) as exc:
        raise RegistrationServiceUnavailable("Registration verification is temporarily unavailable") from exc

    return email


async def read_registration_ticket(token: str) -> dict | None:
    try:
        raw = await get_redis().get(_ticket_key(token))
    except (RedisError, RuntimeError, OSError) as exc:
        raise RegistrationServiceUnavailable("Registration verification is temporarily unavailable") from exc
    if not raw:
        return None
    try:
        data = json.loads(raw)
        data["email"] = normalize_email(data["email"])
        return data
    except (json.JSONDecodeError, KeyError, ValidationError):
        return None


async def take_registration_ticket(token: str) -> dict | None:
    """Atomically consume a ticket so two requests cannot register with it."""
    try:
        raw = await get_redis().getdel(_ticket_key(token))
    except (RedisError, RuntimeError, OSError) as exc:
        raise RegistrationServiceUnavailable("Registration verification is temporarily unavailable") from exc
    if not raw:
        return None
    try:
        data = json.loads(raw)
        data["email"] = normalize_email(data["email"])
        return data
    except (json.JSONDecodeError, KeyError, ValidationError):
        return None


async def restore_registration_ticket(token: str, ticket: dict) -> None:
    """Restore a consumed ticket when only the chosen username was unavailable."""
    try:
        await get_redis().set(
            _ticket_key(token),
            json.dumps(ticket),
            ex=REGISTRATION_TICKET_TTL_SECONDS,
            nx=True,
        )
    except (RedisError, RuntimeError, OSError) as exc:
        raise RegistrationServiceUnavailable("Registration verification is temporarily unavailable") from exc
