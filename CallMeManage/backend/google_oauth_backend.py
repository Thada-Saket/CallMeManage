"""Google OpenID Connect Authorization Code + PKCE backend operations."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from pydantic import ValidationError
from redis.exceptions import RedisError

from backend.core.auth_audit import AuthFailure
from backend.core.load_environment import load_environment
from backend.core.redis_client import get_redis
from backend.google_oauth_state_service import GoogleOAuthStart
from backend.registration_service import normalize_email


GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
GOOGLE_HTTP_TIMEOUT_SECONDS = 10
MAX_GOOGLE_RESPONSE_BYTES = 64 * 1024
CALLBACK_RESULT_PREFIX = "auth:registration:google_result:"
CALLBACK_RESULT_TTL_SECONDS = 5 * 60


class GoogleOAuthRejected(AuthFailure, ValueError):
    code = "GOOGLE_TOKEN_INVALID"


class GoogleOAuthUnavailable(AuthFailure, RuntimeError):
    code = "GOOGLE_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class GoogleOAuthConfiguration:
    client_id: str
    client_secret: str
    redirect_uri: str
    frontend_base_url: str


@dataclass(frozen=True, slots=True)
class VerifiedGoogleIdentity:
    subject: str
    email: str


def get_google_oauth_configuration() -> GoogleOAuthConfiguration:
    settings = load_environment()
    if not settings.google_configured:
        raise GoogleOAuthUnavailable("Google registration is not configured", code="GOOGLE_NOT_CONFIGURED")
    return GoogleOAuthConfiguration(
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        redirect_uri=settings.GOOGLE_REDIRECT_URI,
        frontend_base_url=settings.FRONTEND_BASE_URL,
    )


def build_google_authorization_url(flow: GoogleOAuthStart) -> str:
    config = get_google_oauth_configuration()
    query = urllib.parse.urlencode(
        {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": flow.state,
            "nonce": flow.nonce,
            "code_challenge": flow.code_challenge,
            "code_challenge_method": flow.code_challenge_method,
            "prompt": "select_account",
        }
    )
    return f"{GOOGLE_AUTHORIZATION_ENDPOINT}?{query}"


# OAuth error values from the token endpoint (RFC 6749 section 5.2) that mean
# this server is misconfigured, not that the visitor did anything wrong.
_SERVER_SIDE_TOKEN_ERRORS = {
    "invalid_client": "GOOGLE_CLIENT_INVALID",
    "unauthorized_client": "GOOGLE_CLIENT_INVALID",
    "redirect_uri_mismatch": "GOOGLE_REDIRECT_MISMATCH",
}


def _classify_token_error(exc: urllib.error.HTTPError) -> Exception:
    """Map a 4xx token response to an exception; only the `error` field is read.

    A misconfigured client secret or redirect URI is reported as "temporarily
    unavailable" so the visitor is not told their Google account failed.
    A bad, expired or replayed code (invalid_grant) stays a rejection.
    The provider's error_description is never exposed or logged.
    """
    error = ""
    try:
        raw = exc.read(MAX_GOOGLE_RESPONSE_BYTES + 1)
        if len(raw) <= MAX_GOOGLE_RESPONSE_BYTES:
            payload = json.loads(raw.decode("utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("error"), str):
                error = payload["error"]
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        pass
    if error in _SERVER_SIDE_TOKEN_ERRORS:
        return GoogleOAuthUnavailable(
            "Google registration is temporarily unavailable",
            code=_SERVER_SIDE_TOKEN_ERRORS[error],
        )
    return GoogleOAuthRejected(
        "Google authorization code was rejected. Start again",
        code="GOOGLE_CODE_REJECTED",
    )


def _exchange_code_sync(code: str, code_verifier: str) -> dict:
    config = get_google_oauth_configuration()
    body = urllib.parse.urlencode(
        {
            "code": code,
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "redirect_uri": config.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        GOOGLE_TOKEN_ENDPOINT,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=GOOGLE_HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_GOOGLE_RESPONSE_BYTES + 1)
        if len(raw) > MAX_GOOGLE_RESPONSE_BYTES:
            raise GoogleOAuthUnavailable("Google registration is temporarily unavailable")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Token response must be an object")
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500:
            raise _classify_token_error(exc) from exc
        raise GoogleOAuthUnavailable("Google registration is temporarily unavailable") from exc
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise GoogleOAuthUnavailable("Google registration is temporarily unavailable") from exc

    id_token_value = payload.get("id_token")
    if not isinstance(id_token_value, str) or not id_token_value:
        raise GoogleOAuthRejected("Google did not return a valid identity token")
    return payload


def _verify_id_token_sync(id_token_value: str, expected_nonce: str) -> VerifiedGoogleIdentity:
    try:
        from google.auth.exceptions import GoogleAuthError, TransportError
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token
    except ImportError as exc:
        raise GoogleOAuthUnavailable("Google registration support is not installed") from exc

    config = get_google_oauth_configuration()
    try:
        claims = id_token.verify_oauth2_token(
            id_token_value,
            google_requests.Request(),
            config.client_id,
            clock_skew_in_seconds=30,
        )
    except TransportError as exc:
        raise GoogleOAuthUnavailable("Google registration is temporarily unavailable") from exc
    except (GoogleAuthError, ValueError) as exc:
        raise GoogleOAuthRejected("Google returned an invalid identity token") from exc

    subject = claims.get("sub")
    nonce = claims.get("nonce")
    issuer = claims.get("iss")
    if issuer not in GOOGLE_ISSUERS:
        raise GoogleOAuthRejected("Google returned an invalid identity token")
    authorized_party = claims.get("azp")
    if authorized_party is not None and authorized_party != config.client_id:
        raise GoogleOAuthRejected("Google returned an invalid identity token")
    if nonce != expected_nonce:
        raise GoogleOAuthRejected("Google authorization session did not match", code="OAUTH_NONCE_MISMATCH")
    if claims.get("email_verified") is not True or not claims.get("email"):
        raise GoogleOAuthRejected("Google has not verified this email address", code="GOOGLE_EMAIL_NOT_VERIFIED")
    if not isinstance(subject, str) or not subject.isascii() or not 1 <= len(subject) <= 255:
        raise GoogleOAuthRejected("Google returned an invalid account identifier")
    try:
        email = normalize_email(claims["email"])
    except (ValidationError, ValueError) as exc:
        raise GoogleOAuthRejected("Google returned an invalid email address") from exc
    return VerifiedGoogleIdentity(subject=subject, email=email)


async def exchange_code_and_verify_identity(
    code: str,
    *,
    code_verifier: str,
    expected_nonce: str,
) -> VerifiedGoogleIdentity:
    if not isinstance(code, str) or not 1 <= len(code) <= 4096:
        raise GoogleOAuthRejected("Google authorization code is invalid")
    token_payload = await asyncio.to_thread(_exchange_code_sync, code, code_verifier)
    return await asyncio.to_thread(
        _verify_id_token_sync,
        token_payload["id_token"],
        expected_nonce,
    )


def _callback_result_key(result_code: str) -> str:
    digest = hashlib.sha256(result_code.encode("ascii")).hexdigest()
    return f"{CALLBACK_RESULT_PREFIX}{digest}"


async def create_google_callback_result(identity: VerifiedGoogleIdentity) -> str:
    result_code = secrets.token_urlsafe(32)
    record = json.dumps(
        {"email": identity.email, "google_sub": identity.subject},
        separators=(",", ":"),
    )
    try:
        created = await get_redis().set(
            _callback_result_key(result_code),
            record,
            nx=True,
            ex=CALLBACK_RESULT_TTL_SECONDS,
        )
    except (RedisError, RuntimeError, OSError) as exc:
        raise GoogleOAuthUnavailable("Google registration is temporarily unavailable") from exc
    if not created:
        raise GoogleOAuthUnavailable("Google registration is temporarily unavailable")
    return result_code


async def consume_google_callback_result(result_code: str) -> VerifiedGoogleIdentity:
    if not isinstance(result_code, str) or not 20 <= len(result_code) <= 512 or not result_code.isascii():
        raise GoogleOAuthRejected("Google registration result is invalid", code="GOOGLE_RESULT_INVALID")
    try:
        raw = await get_redis().getdel(_callback_result_key(result_code))
    except (RedisError, RuntimeError, OSError) as exc:
        raise GoogleOAuthUnavailable("Google registration is temporarily unavailable") from exc
    if not raw:
        raise GoogleOAuthRejected("Google registration result has expired or was already used", code="GOOGLE_RESULT_INVALID")
    try:
        data = json.loads(raw)
        identity = VerifiedGoogleIdentity(
            subject=data["google_sub"],
            email=normalize_email(data["email"]),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValidationError, ValueError) as exc:
        raise GoogleOAuthRejected("Google registration result is invalid", code="GOOGLE_RESULT_INVALID") from exc
    if not identity.subject.isascii() or not 1 <= len(identity.subject) <= 255:
        raise GoogleOAuthRejected("Google registration result is invalid", code="GOOGLE_RESULT_INVALID")
    return identity


def frontend_callback_url(*, result_code: str | None = None, error: str | None = None) -> str:
    base = get_google_oauth_configuration().frontend_base_url
    fragment = urllib.parse.urlencode(
        {"google_result": result_code} if result_code else {"google_error": error or "failed"}
    )
    # Fragment values are handled by the browser and are not sent in HTTP
    # requests to the frontend host, keeping the opaque handoff out of access logs.
    return f"{base}/login#{fragment}"
