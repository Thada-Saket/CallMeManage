""" |======= Signup kill switch (CM-12) =======|

The backend decides whether new accounts may be created; the frontend only
mirrors it through GET /auth/registration-status. Guarded: every step that can
lead to a new account (Email start/verify/resend, Google start/callback/complete
and the final POST /auth/register). Not guarded: login, logout, password reset,
site access and POST /auth/register/cancel (cleanup must always work).

The value comes from SIGNUP_ENABLED (default False). load_environment() reads it
on every call, so a change in the config file applies to the next request; a value set in
the process environment by the service manager needs a backend restart.
"""

from fastapi import HTTPException, Request, status

from backend.core.auth_audit import audit_auth_event
from backend.core.load_environment import load_environment

SIGNUP_DISABLED_DETAIL = "Sign up is temporarily unavailable"
SIGNUP_DISABLED_OUTCOME = "REGISTRATION_DISABLED"


def is_signup_enabled() -> bool:
    return load_environment().SIGNUP_ENABLED is True


def require_signup_enabled(event: str):
    """Dependency factory: put it first so a disabled signup touches no rate limit, Redis, SMTP or Google."""

    async def dependency(request: Request) -> None:
        if is_signup_enabled():
            return
        # fixed codes only - no request body, email, OTP, code, state or token
        audit_auth_event(event, SIGNUP_DISABLED_OUTCOME, request=request)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=SIGNUP_DISABLED_DETAIL)

    return dependency
