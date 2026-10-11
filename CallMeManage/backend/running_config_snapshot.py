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


# ---------- config รูปแบบของอุปกรณ์ (CLI ของ IOS / ข้อความของ Junos) ----------
# ผู้ใช้เลือกให้ "ซ่อนค่าลับเหมือนเดิม" ในรูปแบบนี้ด้วย - บรรทัดที่มีค่าลับยังอยู่ครบแต่ค่าถูก
# แทนด้วย <hidden> ส่วนที่เหลือวางกลับลงอุปกรณ์ได้ทันที บรรทัด <hidden> ต้องเติมเองก่อนวาง
# (หน้าเว็บบอกจำนวนไว้) · ปิดก่อนเก็บลง Redis เหมือนแบบ structured - ค่าลับไม่เคยถึง browser
NATIVE_HIDDEN = "<hidden>"
MAX_NATIVE_BYTES = 2 * 1024 * 1024

_CISCO_SECRET_PATTERNS = [
    # username X privilege 15 secret 9 $9$... / enable secret 9 ... / password 7 ...
    re.compile(r"(\b(?:secret|password)\s+(?:\d+\s+)?)(\S+)"),
    # crypto ikev2 keyring: pre-shared-key [local|remote] [0|6] VALUE
    re.compile(r"(\bpre-shared-key\s+(?:(?:local|remote)\s+)?(?:\d\s+)?)(\S+)"),
    # crypto isakmp key [0|6] VALUE address ...
    re.compile(r"(^\s*crypto isakmp key\s+(?:\d\s+)?)(\S+)"),
    # tacacs/radius server: key [0|6|7] VALUE หรือ key VALUE - แต่ "key 1" ใน key chain คือ ID
    # ไม่ใช่ค่าลับ: มีเลข type ต้องตามด้วยค่า ไม่มีเลข type ค่าต้องไม่ขึ้นต้นด้วยตัวเลข
    re.compile(r"(^\s*(?:server-private\s+\S+\s+)?key\s+\d\s+)(\S+)\s*$"),
    re.compile(r"(^\s*(?:server-private\s+\S+\s+)?key\s+)(\D\S*)\s*$"),
    # ntp authentication-key N md5 VALUE [7] / ip ospf message-digest-key N md5 [7] VALUE
    re.compile(r"(\b(?:authentication-key\s+\d+\s+md5|message-digest-key\s+\d+\s+md5)\s+(?:\d\s+)?)(\S+)"),
    re.compile(r"(\bip ospf authentication-key\s+(?:\d\s+)?)(\S+)"),
    # snmp-server community NAME RO|RW - ชื่อ community คือรหัสผ่านเอง
    re.compile(r"(^\s*snmp-server community\s+)(\S+)"),
    # key chain: key-string VALUE (บรรทัดเดียว - ไม่ใช่ ssh pubkey block)
    re.compile(r"(^\s*key-string\s+(?:\d\s+)?)(\S+)\s*$"),
]

# ค่าที่ตามหลังคำเหล่านี้เป็นค่าลับเสมอ (ไม่ว่าจะมีเครื่องหมายคำพูดหรือไม่)
_JUNOS_SECRET_PATTERN = re.compile(
    r'(\b(?:encrypted-password|secret|ascii-text|hexadecimal|simple-password|'
    r'ssh-rsa|ssh-ecdsa|ssh-ed25519|ssh-dss)\s+)("(?:[^"\\]|\\.)*"|[^;\s]+)'
)
# คำเหล่านี้ตามด้วยค่าลับเฉพาะตอนเป็นสตริงในเครื่องหมายคำพูด - ที่ไม่มี (เช่น ntp
# "authentication-key 1 type md5 value ..." / OSPF "md5 1 key ...") คือ ID ห้ามซ่อน
_JUNOS_QUOTED_SECRET_PATTERN = re.compile(r'(\b(?:authentication-key|key|value)\s+)("(?:[^"\\]|\\.)*")')
_JUNOS_COMMUNITY = re.compile(r'(^\s*community\s+)("(?:[^"\\]|\\.)*"|\S+)(\s*\{|\s*;)')


def _redact_cisco_cli(text: str) -> tuple[str, int]:
    lines = text.splitlines()
    output = []
    hidden = 0
    in_pubkey_block = False
    for line in lines:
        stripped = line.strip()
        # ip ssh pubkey-chain: key-string ตามด้วยบรรทัด key หลายบรรทัดจนถึง exit/quit
        if in_pubkey_block:
            if stripped in ("exit", "quit"):
                in_pubkey_block = False
                output.append(line)
            else:
                indent = line[: len(line) - len(line.lstrip())]
                output.append(f"{indent}{NATIVE_HIDDEN}")
                hidden += 1
            continue
        if stripped == "key-string":
            in_pubkey_block = True
            output.append(line)
            continue
        new_line = line
        for pattern in _CISCO_SECRET_PATTERNS:
            new_line, count = pattern.subn(lambda m: f"{m.group(1)}{NATIVE_HIDDEN}", new_line)
            hidden += count
        output.append(new_line)
    return "\n".join(output), hidden


def _redact_junos_text(text: str) -> tuple[str, int]:
    output = []
    hidden = 0
    for line in text.splitlines():
        line, count = _JUNOS_SECRET_PATTERN.subn(lambda m: f'{m.group(1)}"{NATIVE_HIDDEN}"', line)
        hidden += count
        line, count = _JUNOS_QUOTED_SECRET_PATTERN.subn(
            lambda m: m.group(0) if m.group(2) == f'"{NATIVE_HIDDEN}"' else f'{m.group(1)}"{NATIVE_HIDDEN}"', line
        )
        hidden += count
        line, count = _JUNOS_COMMUNITY.subn(lambda m: f'{m.group(1)}"{NATIVE_HIDDEN}"{m.group(3)}', line)
        hidden += count
        # ชั้นกันพลาด: Junos ติด "## SECRET-DATA" ท้ายบรรทัดที่มีค่าลับให้เอง - ถ้ายังเหลือสตริง
        # ที่ไม่ได้ปิด (รูปแบบที่ pattern ข้างบนไม่รู้จัก) ปิดทุกสตริงในบรรทัดนั้นทิ้ง
        if "## SECRET-DATA" in line:
            extra = 0

            def hide_any(match):
                nonlocal extra
                if match.group(0) == f'"{NATIVE_HIDDEN}"':
                    return match.group(0)
                extra += 1
                return f'"{NATIVE_HIDDEN}"'

            line = re.sub(r'"(?:[^"\\]|\\.)*"', hide_any, line)
            hidden += extra
        output.append(line)
    return "\n".join(output), hidden


def redact_native_configuration(vendor: str, text: str) -> tuple[str, int]:
    if vendor == "cisco":
        return _redact_cisco_cli(text)
    if vendor == "juniper":
        return _redact_junos_text(text)
    raise ValueError(f"Native configuration format is not supported for {vendor}")


def extract_native_configuration_text(vendor: str, xml_reply: str) -> str:
    """ดึงข้อความ config ออกจาก rpc-reply (Cisco <result>, Junos <configuration-text>)"""
    from tools.safe_xml import safe_fromstring

    root = safe_fromstring(xml_reply)
    local = lambda element: element.tag.rsplit("}", 1)[-1]
    for element in root.iter():
        if local(element) == "rpc-error":
            message = next((child.text for child in element.iter() if local(child) == "error-message" and child.text), "")
            raise ValueError(message.strip() or "Device rejected the configuration text query")
    wanted = "result" if vendor == "cisco" else "configuration-text"
    for element in root.iter():
        if local(element) == "error-message" and (element.text or "").strip():
            raise ValueError(element.text.strip())
    for element in root.iter():
        if local(element) == wanted and element.text and element.text.strip():
            text = element.text.strip("\n")
            if len(text.encode("utf-8")) > MAX_NATIVE_BYTES:
                raise ValueError("Running configuration is too large to display safely")
            return text
    raise ValueError("The device returned no configuration text")


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
    native_text: str | None = None,
    native_redacted_count: int = 0,
    native_error: str | None = None,
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
        # config รูปแบบของอุปกรณ์ (ปิดค่าลับแล้ว) - None = ยี่ห้อนี้ไม่รองรับหรืออ่านไม่สำเร็จ
        "native_text": native_text,
        "native_redacted_count": native_redacted_count,
        "native_error": native_error,
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
