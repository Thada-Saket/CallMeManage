"""Short-lived, sanitized running-configuration snapshots stored in Redis."""

from __future__ import annotations

import json
import re
import secrets
from datetime import timedelta
from typing import Any

from backend.core.redis_client import get_redis
from backend.model.models import generate_timestamp


SNAPSHOT_TTL_SECONDS = 15 * 60
MAX_NORMALIZED_BYTES = 5 * 1024 * 1024
REDACTED_VALUE = "•••••• (hidden)"
_KEY_PREFIX = "running-config-snapshot:"

_SENSITIVE_KEY = re.compile(
    r"(?:^|[-_])(?:password|passwd|secret|private[-_]?key|pre[-_]?shared[-_]?key|"
    r"shared[-_]?key|authentication[-_]?key|key[-_]?string|community|cipher)(?:$|[-_])",
    re.IGNORECASE,
)


def _humanize(value: str) -> str:
    acronyms = {"acl", "aaa", "bgp", "dhcp", "dns", "ip", "nat", "ntp", "ospf", "vpn", "vlan"}
    words = re.sub(r"[_-]+", " ", str(value)).strip().split()
    return " ".join(word.upper() if word.lower() in acronyms else word.capitalize() for word in words)


def _is_sensitive(key: str, ancestors: tuple[str, ...]) -> bool:
    if _SENSITIVE_KEY.search(key):
        return True
    parent_path = "/".join(ancestors).lower()
    # A leaf literally named "key" is common in both harmless list keys and
    # credentials. Only hide it when its surrounding path proves it belongs to
    # authentication/security configuration, otherwise interface/list names
    # would disappear from the viewer as well.
    if key.lower() == "key" and any(
        marker in parent_path
        for marker in (
            "authentication", "credential", "ike", "ipsec", "login", "radius",
            "snmp", "tacacs", "user", "wpa",
        )
    ):
        return True
    return key.lower() in {"name", "value"} and any(
        marker in parent_path for marker in ("ssh-rsa", "ssh-key", "private-key")
    )


def redact_configuration(value: Any, ancestors: tuple[str, ...] = ()) -> tuple[Any, int]:
    """Deep-copy structured configuration while replacing sensitive leaves."""
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        redacted = 0
        for key, child in value.items():
            key_text = str(key)
            if _is_sensitive(key_text, ancestors):
                output[key_text] = REDACTED_VALUE
                redacted += 1
                continue
            safe_child, child_count = redact_configuration(child, ancestors + (key_text,))
            output[key_text] = safe_child
            redacted += child_count
        return output, redacted
    if isinstance(value, list):
        output = []
        redacted = 0
        for child in value:
            safe_child, child_count = redact_configuration(child, ancestors)
            output.append(safe_child)
            redacted += child_count
        return output, redacted
    return value, 0


def extract_configuration_sections(normalized: dict) -> tuple[list[dict], int]:
    """Extract rpc-reply/data and turn vendor roots into display sections."""
    payload = normalized.get("payload", {}) if isinstance(normalized, dict) else {}
    reply = payload.get("rpc-reply", payload) if isinstance(payload, dict) else {}
    data = reply.get("data", reply) if isinstance(reply, dict) else {}
    if not isinstance(data, dict) or not data:
        raise ValueError("The device returned no running configuration data")

    # Cisco and Junos wrap actual sections once. Huawei generally returns
    # several top-level YANG module containers directly below <data>.
    for root_name in ("native", "configuration"):
        root = data.get(root_name)
        if isinstance(root, dict):
            data = root
            break

    safe_data, redacted_count = redact_configuration(data)
    serialized_size = len(json.dumps(safe_data, ensure_ascii=False).encode("utf-8"))
    if serialized_size > MAX_NORMALIZED_BYTES:
        raise ValueError("Running configuration is too large to display safely")

    sections = [
        {
            "id": f"section-{index}",
            "key": str(key),
            "label": _humanize(str(key)),
            "data": value,
        }
        for index, (key, value) in enumerate(safe_data.items(), start=1)
    ]
    return sections, redacted_count


def _key(snapshot_id: str) -> str:
    return f"{_KEY_PREFIX}{snapshot_id}"


async def store_running_config_snapshot(
    *,
    usr_id: str,
    dev_id: str,
    dev_name: str,
    vendor: str,
    sections: list[dict],
    redacted_count: int,
) -> dict:
    created_at = generate_timestamp()
    expires_at = created_at + timedelta(seconds=SNAPSHOT_TTL_SECONDS)
    snapshot_id = secrets.token_urlsafe(24)
    snapshot = {
        "snapshot_id": snapshot_id,
        "usr_id": usr_id,
        "dev_id": dev_id,
        "dev_name": dev_name,
        "vendor": vendor,
        "source": "running",
        "created_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "redacted_count": redacted_count,
        "sections": sections,
    }
    await get_redis().set(
        _key(snapshot_id),
        json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")),
        ex=SNAPSHOT_TTL_SECONDS,
    )
    return snapshot


async def get_running_config_snapshot(snapshot_id: str) -> dict | None:
    raw = await get_redis().get(_key(snapshot_id))
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def public_snapshot(snapshot: dict) -> dict:
    """Never expose the Redis ownership field to the browser."""
    return {key: value for key, value in snapshot.items() if key != "usr_id"}
