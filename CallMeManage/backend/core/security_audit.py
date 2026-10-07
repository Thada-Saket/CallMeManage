""" |======= Security audit log for privileged / destructive actions (CM-10) =======|

One JSON line per event, same shape as the auth audit log (UTC timestamp,
correlation ID, masked client) plus who did it and what it was done to:

  {"ts": ..., "event": "site.member_role_change", "outcome": "SUCCEEDED",
   "correlation_id": ..., "client": "203.0.113.0/24", "actor_id": "usr_...",
   "target": {"site_id": "site_...", "user_id": "usr_...", "role": "admin"}}

The function only takes fixed identifiers. Target keys come from an allowlist
and values must look like IDs or role/status words, so passwords, hashes,
tokens, OTPs, PSKs, emails, usernames, raw XML or configuration cannot be
written through this path; anything else is replaced with "redacted".
"""

import json
import logging
import re
import sys
from datetime import datetime, timezone

from fastapi import Request

from backend.core.auth_audit import correlation_id, mask_ip

_EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_.]{1,63}$")
_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_TARGET_KEYS = frozenset({"site_id", "dev_id", "user_id", "role", "status", "previous_owner_id", "limiter"})

_logger = logging.getLogger("callmemanage.security.audit")
if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("[security-audit] %(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def audit_security_event(
    event: str,
    outcome: str,
    *,
    request: Request | None = None,
    actor_id: str | None = None,
    **target: str | None,
) -> None:
    if not _EVENT_PATTERN.fullmatch(event) or not _CODE_PATTERN.fullmatch(outcome):
        raise ValueError("Audit event and outcome must be fixed identifiers")
    unknown = set(target) - _TARGET_KEYS
    if unknown:
        raise ValueError(f"Unsupported audit target field: {sorted(unknown)}")

    def clean(value) -> str:
        text = str(value)
        return text if _ID_PATTERN.fullmatch(text) else "redacted"

    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        "outcome": outcome,
        "correlation_id": correlation_id(request),
        "client": mask_ip(request.client.host if request is not None and request.client else None),
    }
    if actor_id is not None:
        record["actor_id"] = clean(actor_id)
    values = {key: clean(value) for key, value in target.items() if value is not None}
    if values:
        record["target"] = values
    _logger.info(json.dumps(record, separators=(",", ":")))
