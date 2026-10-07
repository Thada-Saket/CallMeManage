"""Server-side Cloudflare Turnstile verification for public auth endpoints."""

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Header, HTTPException, Request, status
from jose import JWTError, jwt
from redis.exceptions import RedisError

from backend.core.auth_audit import AuthFailure, audit_auth_event, failure_code
from backend.core.load_environment import load_environment
from backend.core.redis_client import get_redis


SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
VERIFY_TIMEOUT_SECONDS = 10
MAX_SITEVERIFY_RESPONSE_BYTES = 64 * 1024
SITE_ACCESS_TTL_SECONDS = 8 * 60 * 60
SITE_ACCESS_ALGORITHM = "HS256"
LOGIN_TURNSTILE_ACTION = "login"
# The first login right after the site check may use that check instead of a second
# challenge (see require_login_turnstile). Keep the frontend's copy in utils/siteAccess.js.
FIRST_LOGIN_GRACE_SECONDS = 10 * 60
TURNSTILE_ALWAYS_PASS_TEST_SECRET = "1x0000000000000000000000000000000AA"


class TurnstileRejected(AuthFailure, ValueError):
    code = "TURNSTILE_REJECTED"


class TurnstileUnavailable(AuthFailure, RuntimeError):
    code = "TURNSTILE_UNAVAILABLE"


def _verify_sync(token: str, remote_ip: str | None, expected_action: str) -> None:
    settings = load_environment()
    form = {
        "secret": settings.TURNSTILE_SECRET_KEY,
        "response": token,
        "idempotency_key": str(uuid.uuid4()),
    }
    if remote_ip:
        form["remoteip"] = remote_ip

    request = urllib.request.Request(
        SITEVERIFY_URL,
        data=urllib.parse.urlencode(form).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=VERIFY_TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_SITEVERIFY_RESPONSE_BYTES + 1)
        if len(raw) > MAX_SITEVERIFY_RESPONSE_BYTES:
            raise TurnstileUnavailable("Bot verification is temporarily unavailable")
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("Siteverify response must be an object")
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise TurnstileUnavailable("Bot verification is temporarily unavailable") from exc

    if result.get("success") is not True:
        raise TurnstileRejected("Complete the bot verification again")

    # Cloudflare's official always-pass testing pair returns testing hostname/action
    # values rather than the values supplied by the widget. It does not include a
    # reliable marker in the response. Skip those two checks only when this backend
    # is explicitly configured with that test secret outside production. Production
    # refuses all official testing secrets while loading settings.
    if settings.APP_ENV != "production" and settings.TURNSTILE_SECRET_KEY == TURNSTILE_ALWAYS_PASS_TEST_SECRET:
        return

    expected_hostname = settings.TURNSTILE_EXPECTED_HOSTNAME.strip().casefold()
    actual_hostname = str(result.get("hostname") or "").strip().casefold()
    if expected_hostname and actual_hostname != expected_hostname:
        raise TurnstileRejected("Complete the bot verification again", code="TURNSTILE_HOSTNAME_MISMATCH")

    # An omitted action is not equivalent to the expected action. Requiring an
    # exact match prevents a token minted for a different widget/flow from
    # being accepted here.
    actual_action = str(result.get("action") or "")
    if actual_action != expected_action:
        raise TurnstileRejected("Complete the bot verification again", code="TURNSTILE_ACTION_MISMATCH")


async def verify_turnstile(token: str, remote_ip: str | None, *, action: str = "register") -> None:
    # TURNSTILE_ENABLED=no: no bot check anywhere (production refuses this setting)
    if not load_environment().TURNSTILE_ENABLED:
        return
    if not isinstance(token, str) or not token or len(token) > 2048:
        raise TurnstileRejected("Complete the bot verification", code="TURNSTILE_MISSING")
    if not isinstance(action, str) or not action or len(action) > 32 or not action.isascii():
        raise TurnstileRejected("Complete the bot verification again", code="TURNSTILE_ACTION_MISMATCH")
    await asyncio.to_thread(_verify_sync, token, remote_ip, action)


def create_site_access_token() -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "purpose": "site_access",
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + timedelta(seconds=SITE_ACCESS_TTL_SECONDS),
        },
        load_environment().JWT_SECRET_KEY,
        algorithm=SITE_ACCESS_ALGORITHM,
    )


def site_access_payload(token: str) -> dict | None:
    try:
        payload = jwt.decode(
            token,
            load_environment().JWT_SECRET_KEY,
            algorithms=[SITE_ACCESS_ALGORITHM],
        )
    except JWTError:
        return None
    if payload.get("purpose") != "site_access" or not payload.get("jti"):
        return None
    return payload


def decode_site_access_token(token: str) -> bool:
    return site_access_payload(token) is not None


async def _claim_first_login(site_access_token: str | None) -> bool:
    """True once per solved site check, within FIRST_LOGIN_GRACE_SECONDS of solving it.

    The claim is recorded in Redis by the token's jti, so one solved challenge still buys
    exactly one login attempt - the same as a fresh login token. Redis unavailable means
    no grace (the caller then asks for a fresh token).
    """
    payload = site_access_payload(site_access_token) if site_access_token else None
    if payload is None:
        return False
    issued_at = payload.get("iat")
    now = datetime.now(timezone.utc).timestamp()
    if not isinstance(issued_at, (int, float)) or not 0 <= now - issued_at <= FIRST_LOGIN_GRACE_SECONDS:
        return False
    try:
        return bool(await get_redis().set(
            f"auth:site_access:first_login:{payload['jti']}", "1", nx=True, ex=FIRST_LOGIN_GRACE_SECONDS,
        ))
    except (RedisError, RuntimeError):
        return False


async def require_site_access(
    token: str | None = Header(default=None, alias="X-Site-Access-Token"),
) -> None:
    if not load_environment().TURNSTILE_ENABLED:
        return
    if not token or not decode_site_access_token(token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Site access verification required",
        )


# The site-access proof is reusable for hours and not bound to a client, so on
# its own one solved challenge could be shared to brute-force logins from many
# IPs. Each login attempt therefore also needs a fresh single-use token, which
# Cloudflare refuses to validate twice - except the first attempt within
# FIRST_LOGIN_GRACE_SECONDS of the site check, which uses up that check once.
async def require_login_turnstile(
    request: Request,
    token: str | None = Header(default=None, alias="X-Turnstile-Token"),
    site_access_token: str | None = Header(default=None, alias="X-Site-Access-Token"),
) -> None:
    # Users just passed the site check; asking for a second challenge on the very first
    # login made some of them click twice. That first attempt spends the site check instead.
    if not token and await _claim_first_login(site_access_token):
        return
    try:
        await verify_turnstile(
            token or "",
            request.client.host if request.client else None,
            action=LOGIN_TURNSTILE_ACTION,
        )
    except TurnstileRejected as exc:
        audit_auth_event("auth.login", failure_code(exc), request=request)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except TurnstileUnavailable as exc:
        audit_auth_event("auth.login", failure_code(exc), request=request)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
