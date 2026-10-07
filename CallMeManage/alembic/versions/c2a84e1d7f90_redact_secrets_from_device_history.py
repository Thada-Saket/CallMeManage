"""redact secrets from existing device history

Revision ID: c2a84e1d7f90
Revises: 6e4c9a7d2f10
Create Date: 2026-10-06

Device History is an audit trail, not a credential store. This data migration
removes password/PSK/token/private-key/community values already persisted and
retains only changed/not-changed booleans. Downgrade is intentionally a no-op:
discarded credentials must never be reconstructed.
"""

from __future__ import annotations

import json
import re
from typing import Any, Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c2a84e1d7f90"
down_revision: Union[str, Sequence[str], None] = "6e4c9a7d2f10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_NORMALIZER = re.compile(r"[^a-z0-9]")
_PASSWORD_SUFFIXES = ("password", "passwd", "passphrase")
_SECRET_SUFFIXES = (
    "psk", "presharedkey", "secret", "token", "privatekey", "community", "communitystring",
)
_PASSWORD_MARKER = "passwordchanged"
_SECRET_MARKER = "secretchanged"
_PASSWORD_STATUS_COMMANDS = {"set_new_local_user", "edit_local_user"}
_SECRET_STATUS_COMMANDS = {"create_security_profile"}


def _normalized(key: object) -> str:
    return _NORMALIZER.sub("", str(key).casefold())


def _kind(key: object) -> str | None:
    normalized = _normalized(key)
    if normalized in {_PASSWORD_MARKER, _SECRET_MARKER}:
        return None
    if normalized.endswith(_PASSWORD_SUFFIXES) or normalized == "pwd":
        return "password"
    if normalized.endswith(_SECRET_SUFFIXES):
        return "secret"
    return None


def _changed(value: Any) -> bool:
    return value not in (None, "", False, [], {})


def _clean(value: Any) -> tuple[Any, bool, bool, bool, bool]:
    if isinstance(value, dict):
        safe = {}
        password_found = password_changed = False
        secret_found = secret_changed = False
        for key, child in value.items():
            normalized = _normalized(key)
            if normalized in {_PASSWORD_MARKER, _SECRET_MARKER}:
                safe[key] = bool(child)
                continue
            kind = _kind(key)
            if kind == "password":
                password_found = True
                password_changed = password_changed or _changed(child)
                continue
            if kind == "secret":
                secret_found = True
                secret_changed = secret_changed or _changed(child)
                continue
            cleaned, child_pf, child_pc, child_sf, child_sc = _clean(child)
            safe[key] = cleaned
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
        safe = []
        password_found = password_changed = False
        secret_found = secret_changed = False
        for child in value:
            cleaned, child_pf, child_pc, child_sf, child_sc = _clean(child)
            safe.append(cleaned)
            password_found = password_found or child_pf
            password_changed = password_changed or child_pc
            secret_found = secret_found or child_sf
            secret_changed = secret_changed or child_sc
        return safe, password_found, password_changed, secret_found, secret_changed
    return value, False, False, False, False


def _parameters(command: str, value: object) -> dict:
    if not isinstance(value, dict):
        return {"detail_redacted": True}
    safe, *_ = _clean(value)
    if command in _PASSWORD_STATUS_COMMANDS:
        safe.setdefault("password_changed", False)
    if command in _SECRET_STATUS_COMMANDS:
        safe.setdefault("secret_changed", False)
    return safe


def _sanitize_detail(action: str, detail: str) -> str:
    try:
        parsed = json.loads(detail)
    except (TypeError, ValueError, json.JSONDecodeError):
        return json.dumps({"legacy_detail_redacted": True})
    if not isinstance(parsed, dict):
        return json.dumps({"legacy_detail_redacted": True})

    if isinstance(parsed.get("steps"), list):
        safe_steps = []
        for step in parsed["steps"]:
            if not isinstance(step, dict):
                safe_steps.append({"detail_redacted": True})
                continue
            command = step.get("command") if isinstance(step.get("command"), str) else action
            safe_step = {key: value for key, value in step.items() if key != "parameters"}
            safe_step["parameters"] = _parameters(command, step.get("parameters"))
            safe_steps.append(safe_step)
        safe = {key: value for key, value in parsed.items() if key != "steps"}
        safe["steps"] = safe_steps
        safe, *_ = _clean(safe)
    else:
        safe = _parameters(action, parsed)
    return json.dumps(safe, ensure_ascii=False)


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT his_id, his_action, his_action_detail "
            "FROM device_history"
        )
    ).mappings().all()
    update = sa.text(
        "UPDATE device_history "
        "SET his_action_detail = :detail "
        "WHERE his_id = :his_id"
    )
    for row in rows:
        safe_detail = _sanitize_detail(row["his_action"], row["his_action_detail"])
        if safe_detail != row["his_action_detail"]:
            bind.execute(update, {"his_id": row["his_id"], "detail": safe_detail})


def downgrade() -> None:
    # Security redaction is deliberately irreversible.
    pass
