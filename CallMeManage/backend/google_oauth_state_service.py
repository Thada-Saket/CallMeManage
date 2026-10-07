"""One-time Google OAuth state, nonce, and PKCE storage backed by Redis.

This module deliberately has no HTTP or Google API behavior. A later endpoint
must verify Turnstile first, call :func:`create_google_oauth_state`, and include
the returned protocol values in Google's authorization URL. The callback then
uses :func:`consume_google_oauth_state` exactly once before exchanging a code.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from redis.exceptions import RedisError

from backend.core.auth_audit import AuthFailure
from backend.core.load_environment import load_environment
from backend.core.redis_client import get_redis


STATE_PREFIX = "auth:registration:google_state:"
STATE_CREATE_ATTEMPTS = 3
PKCE_METHOD = "S256"
STATE_PURPOSE = "google_registration"


class GoogleOAuthStateInvalid(AuthFailure, ValueError):
    """The state is missing, expired, replayed, or internally malformed."""

    code = "OAUTH_STATE_INVALID"


class GoogleOAuthStateUnavailable(AuthFailure, RuntimeError):
    """The state store is unavailable; OAuth must fail closed."""

    code = "OAUTH_STATE_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class GoogleOAuthStart:
    state: str
    nonce: str
    code_challenge: str
    code_challenge_method: str
    expires_in: int


@dataclass(frozen=True, slots=True)
class ConsumedGoogleOAuthState:
    nonce: str
    code_verifier: str
    created_at: int
    turnstile_verified: bool


def _state_key(state: str) -> str:
    # State travels through the browser and Google. Hashing the Redis key keeps
    # the raw protocol value out of Redis key listings and infrastructure logs.
    digest = hashlib.sha256(state.encode("ascii")).hexdigest()
    return f"{STATE_PREFIX}{digest}"


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _validate_state_input(state: str) -> str:
    if not isinstance(state, str) or not 20 <= len(state) <= 512 or not state.isascii():
        raise GoogleOAuthStateInvalid("Google authorization session is invalid")
    return state


async def create_google_oauth_state(*, turnstile_verified: bool) -> GoogleOAuthStart:
    """Create a short-lived state record after server-side Turnstile success.

    Only the challenge is returned to the browser. The PKCE verifier remains in
    Redis until the callback atomically consumes the state.
    """

    if turnstile_verified is not True:
        raise GoogleOAuthStateInvalid("Bot verification is required before Google registration")

    ttl = load_environment().REGISTRATION_FLOW_TTL_SECONDS
    try:
        redis = get_redis()
    except (RedisError, RuntimeError, OSError) as exc:
        raise GoogleOAuthStateUnavailable(
            "Google registration is temporarily unavailable"
        ) from exc

    for _ in range(STATE_CREATE_ATTEMPTS):
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)
        record = json.dumps(
            {
                "purpose": STATE_PURPOSE,
                "nonce": nonce,
                "code_verifier": code_verifier,
                "created_at": int(time.time()),
                "turnstile_verified": True,
            },
            separators=(",", ":"),
        )
        try:
            created = await redis.set(_state_key(state), record, nx=True, ex=ttl)
        except (RedisError, RuntimeError, OSError) as exc:
            raise GoogleOAuthStateUnavailable(
                "Google registration is temporarily unavailable"
            ) from exc
        if created:
            return GoogleOAuthStart(
                state=state,
                nonce=nonce,
                code_challenge=_pkce_challenge(code_verifier),
                code_challenge_method=PKCE_METHOD,
                expires_in=ttl,
            )

    # A collision is extraordinarily unlikely. Treat repeated NX failures as
    # unavailable rather than overwriting another in-flight registration.
    raise GoogleOAuthStateUnavailable("Google registration is temporarily unavailable")


async def consume_google_oauth_state(state: str) -> ConsumedGoogleOAuthState:
    """Atomically take an OAuth state so callback replay is impossible."""

    state = _validate_state_input(state)
    try:
        raw = await get_redis().getdel(_state_key(state))
    except (RedisError, RuntimeError, OSError) as exc:
        raise GoogleOAuthStateUnavailable(
            "Google registration is temporarily unavailable"
        ) from exc

    if not raw:
        raise GoogleOAuthStateInvalid(
            "Google authorization session has expired or was already used"
        )

    try:
        record = json.loads(raw)
        nonce = record["nonce"]
        code_verifier = record["code_verifier"]
        created_at = record["created_at"]
        marker = record["turnstile_verified"]
        purpose = record["purpose"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise GoogleOAuthStateInvalid("Google authorization session is invalid") from exc

    now = int(time.time())
    ttl = load_environment().REGISTRATION_FLOW_TTL_SECONDS
    valid_record = (
        purpose == STATE_PURPOSE
        and marker is True
        and isinstance(nonce, str)
        and 20 <= len(nonce) <= 512
        and nonce.isascii()
        and isinstance(code_verifier, str)
        and 43 <= len(code_verifier) <= 128
        and code_verifier.isascii()
        and type(created_at) is int
        and now - ttl <= created_at <= now + 30
    )
    if not valid_record:
        raise GoogleOAuthStateInvalid("Google authorization session is invalid")

    return ConsumedGoogleOAuthState(
        nonce=nonce,
        code_verifier=code_verifier,
        created_at=created_at,
        turnstile_verified=True,
    )
