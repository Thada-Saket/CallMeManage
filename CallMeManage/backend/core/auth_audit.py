""" |======= Authentication audit log =======|

One JSON line per authentication event. The function only accepts an event
name, an outcome code, the request (for correlation ID and a masked client
address) and a user ID, so OTPs, passwords, tokens, secrets, emails and raw
provider messages cannot reach the log through this path.
"""

import ipaddress
import json
import logging
import re
import sys
import uuid
from datetime import datetime, timezone

from fastapi import Request


_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_.]{1,63}$")
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{8,64}$")

_logger = logging.getLogger("callmemanage.auth.audit")
if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("[auth-audit] %(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


class AuthFailure:
    """Mixin giving an auth exception a stable outcome code for the audit log.

    The message is what the browser sees and must stay generic; the code is
    what operators see and may be specific.
    """

    code = "AUTH_FAILED"

    def __init__(self, message: str = "", *, code: str | None = None):
        super().__init__(message)
        if code is not None:
            self.code = code


def mask_ip(value: str | None) -> str:
    """Keep the network, drop the host: IPv4 /24, IPv6 /48."""
    try:
        address = ipaddress.ip_address(value or "")
    except ValueError:
        return "unknown"
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def correlation_id(request: Request | None) -> str:
    """Reuse a well-formed X-Request-ID from the proxy, else mint one per request."""
    if request is None:
        return uuid.uuid4().hex
    existing = getattr(request.state, "auth_correlation_id", None)
    if existing:
        return existing
    incoming = request.headers.get("x-request-id", "")
    value = incoming if _REQUEST_ID_PATTERN.fullmatch(incoming) else uuid.uuid4().hex
    request.state.auth_correlation_id = value
    return value


def audit_auth_event(
    event: str,
    outcome: str,
    *,
    request: Request | None = None,
    user_id: str | None = None,
) -> None:
    if not _EVENT_PATTERN.fullmatch(event) or not _CODE_PATTERN.fullmatch(outcome):
        raise ValueError("Audit event and outcome must be fixed identifiers")
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        "outcome": outcome,
        "correlation_id": correlation_id(request),
        "client": mask_ip(request.client.host if request is not None and request.client else None),
    }
    if user_id is not None:
        record["user_id"] = str(user_id)
    _logger.info(json.dumps(record, separators=(",", ":")))


def failure_code(exc: BaseException, default: str = "AUTH_FAILED") -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and _CODE_PATTERN.fullmatch(code) else default
