"""Remove credentials from Device History while retaining change status.

This module is intentionally independent from FastAPI and database code so the
same policy can be applied both before serialization and again at the final
CRUD boundary. Values are never masked with a reversible/recognisable fragment:
the sensitive key and value are removed completely and replaced by a boolean.
"""

from __future__ import annotations

import json
import re
from typing import Any


_KEY_NORMALIZER = re.compile(r"[^a-z0-9]")
_PASSWORD_MARKERS = {"passwordchanged"}
_SECRET_MARKERS = {"secretchanged"}

# Match normalized suffixes so psk, pre_shared_key and pre-shared-key are handled
# identically and vendor prefixes such as root_password/enrollment_token work,
# while non-secret metadata such as psk_type/password_policy remains visible.
_PASSWORD_KEY_SUFFIXES = ("password", "passwd", "passphrase")
_SECRET_KEY_SUFFIXES = (
    "psk", "presharedkey", "secret", "token", "privatekey", "community", "communitystring",
)

# These commands can legitimately omit the credential during Edit. Record an
# explicit No so the history tells the user whether that credential changed.
_PASSWORD_STATUS_COMMANDS = {"set_new_local_user", "edit_local_user"}
_SECRET_STATUS_COMMANDS = {"create_security_profile"}


def _normalized_key(key: object) -> str:
    return _KEY_NORMALIZER.sub("", str(key).casefold())


def _key_kind(key: object) -> str | None:
    normalized = _normalized_key(key)
    if normalized in _PASSWORD_MARKERS or normalized in _SECRET_MARKERS:
        return None
    if normalized.endswith(_PASSWORD_KEY_SUFFIXES) or normalized == "pwd":
        return "password"
    if normalized.endswith(_SECRET_KEY_SUFFIXES):
        return "secret"
    return None


def _changed(value: Any) -> bool:
    return value not in (None, "", False, [], {})


def _redact(value: Any) -> tuple[Any, bool, bool, bool, bool]:
    """Return value, password-found/changed, secret-found/changed."""
    if isinstance(value, dict):
        safe: dict[Any, Any] = {}
        password_found = password_changed = False
        secret_found = secret_changed = False

        for key, child in value.items():
            normalized = _normalized_key(key)
            if normalized in _PASSWORD_MARKERS or normalized in _SECRET_MARKERS:
                # Preserve an existing boolean marker and keep this function
                # idempotent when the API layer and CRUD boundary both apply it.
                safe[key] = bool(child)
                continue

            kind = _key_kind(key)
            if kind == "password":
                password_found = True
                password_changed = password_changed or _changed(child)
                continue
            if kind == "secret":
                secret_found = True
                secret_changed = secret_changed or _changed(child)
                continue

            redacted_child, child_pf, child_pc, child_sf, child_sc = _redact(child)
            safe[key] = redacted_child
            password_found = password_found or child_pf
            password_changed = password_changed or child_pc
            secret_found = secret_found or child_sf
            secret_changed = secret_changed or child_sc

        if password_found:
            safe["password_changed"] = password_changed
        if secret_found:
            safe["secret_changed"] = secret_changed
        return safe, password_found, password_changed, secret_found, secret_changed

    if isinstance(value, list):
        safe_list = []
        password_found = password_changed = False
        secret_found = secret_changed = False
        for child in value:
            redacted_child, child_pf, child_pc, child_sf, child_sc = _redact(child)
            safe_list.append(redacted_child)
            password_found = password_found or child_pf
            password_changed = password_changed or child_pc
            secret_found = secret_found or child_sf
            secret_changed = secret_changed or child_sc
        return safe_list, password_found, password_changed, secret_found, secret_changed

    return value, False, False, False, False


def sanitize_history_parameters(command: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """Return a deep, redacted copy suitable for Device History."""
    if not isinstance(parameters, dict):
        return {"detail_redacted": True}
    safe, _pf, _pc, _sf, _sc = _redact(parameters)
    if command in _PASSWORD_STATUS_COMMANDS:
        safe.setdefault("password_changed", False)
    if command in _SECRET_STATUS_COMMANDS:
        safe.setdefault("secret_changed", False)
    return safe


def sanitize_history_detail(action: str, detail: str) -> str:
    """Sanitize serialized history, including every step of a transaction.

    Invalid/primitive legacy detail cannot be proven safe, so it is replaced
    with a marker instead of being persisted verbatim.
    """
    try:
        parsed = json.loads(detail)
    except (TypeError, ValueError, json.JSONDecodeError):
        return json.dumps({"legacy_detail_redacted": True})

    if not isinstance(parsed, dict):
        return json.dumps({"legacy_detail_redacted": True})

    steps = parsed.get("steps")
    if isinstance(steps, list):
        safe_steps = []
        for step in steps:
            if not isinstance(step, dict):
                safe_steps.append({"detail_redacted": True})
                continue
            command = step.get("command") if isinstance(step.get("command"), str) else action
            parameters = step.get("parameters")
            safe_step = {
                key: value for key, value in step.items() if key != "parameters"
            }
            safe_step["parameters"] = sanitize_history_parameters(command, parameters)
            safe_steps.append(safe_step)
        safe_parsed = {
            key: value for key, value in parsed.items() if key != "steps"
        }
        safe_parsed["steps"] = safe_steps
        safe_parsed, *_ = _redact(safe_parsed)
    else:
        safe_parsed = sanitize_history_parameters(action, parsed)

    return json.dumps(safe_parsed, ensure_ascii=False)
