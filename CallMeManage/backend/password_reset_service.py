"""Password reset by email code.

The email-code mechanics (send limits, attempts, expiry, resend) are shared
with sign-up in registration_service; the purpose "password_reset" is part of
each code's HMAC, so a sign-up code can never reset a password. A verified
code yields a one-time reset ticket bound to one user ID and address.
"""

import hashlib
import json
import secrets

from redis.exceptions import RedisError

from backend.core.redis_client import get_redis
from backend.registration_service import (
    PURPOSE_PASSWORD_RESET,
    RegistrationFlowExpired,
    RegistrationServiceUnavailable,
    normalize_email,
    start_email_verification,
    verify_email_code,
)

PASSWORD_RESET_TICKET_TTL_SECONDS = 10 * 60

_REDIS_ERRORS = (RedisError, RuntimeError, OSError)


class PasswordResetExpired(RegistrationFlowExpired):
    code = "PASSWORD_RESET_TICKET_EXPIRED"


def _ticket_key(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"auth:password_reset:ticket:{digest}"


def _unavailable(exc: Exception) -> RegistrationServiceUnavailable:
    error = RegistrationServiceUnavailable("Password reset is temporarily unavailable")
    error.__cause__ = exc
    return error


async def start_password_reset(email: str) -> tuple[str, int]:
    return await start_email_verification(email, purpose=PURPOSE_PASSWORD_RESET)


async def verify_password_reset_code(challenge_id: str, otp: str) -> str:
    return await verify_email_code(challenge_id, otp, purpose=PURPOSE_PASSWORD_RESET)


async def issue_password_reset_ticket(user_id: str, email: str) -> str:
    token = secrets.token_urlsafe(32)
    payload = json.dumps({"user_id": str(user_id), "email": normalize_email(email)})
    try:
        await get_redis().set(_ticket_key(token), payload, ex=PASSWORD_RESET_TICKET_TTL_SECONDS, nx=True)
    except _REDIS_ERRORS as exc:
        raise _unavailable(exc) from exc
    return token


async def take_password_reset_ticket(token: str) -> dict:
    """Atomically consume a ticket so it can change a password only once."""
    try:
        raw = await get_redis().getdel(_ticket_key(token))
    except _REDIS_ERRORS as exc:
        raise _unavailable(exc) from exc
    if not raw:
        raise PasswordResetExpired("This password reset has expired. Start again")
    try:
        data = json.loads(raw)
        return {"user_id": str(data["user_id"]), "email": normalize_email(data["email"])}
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise PasswordResetExpired("This password reset has expired. Start again") from exc


async def restore_password_reset_ticket(token: str, ticket: dict) -> None:
    """Give a ticket back when the password could not be saved (e.g. DB down)."""
    try:
        await get_redis().set(_ticket_key(token), json.dumps(ticket), ex=PASSWORD_RESET_TICKET_TTL_SECONDS, nx=True)
    except _REDIS_ERRORS:
        pass


async def discard_password_reset_ticket(token: str) -> None:
    try:
        await get_redis().delete(_ticket_key(token))
    except _REDIS_ERRORS as exc:
        raise _unavailable(exc) from exc
