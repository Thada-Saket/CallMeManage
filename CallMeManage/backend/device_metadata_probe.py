""" |======= Read-only Device Metadata Probe (hostname / model / firmware) =======| """
# Phase 8: ข้อมูลแสดงผลของอุปกรณ์ที่ activate ด้วย token (ไม่ใช้ยืนยันตัวตนเด็ดขาด - authentication มาจาก token/fingerprint เท่านั้น)
# Serial เป็นค่า debug ชั่วคราวจาก hardware RPC เดิมเท่านั้น ไม่ใช้ auth และ activation ไม่ persist ลง DB; ไม่มี MAC
# ใช้ NETCONF read-only เท่านั้น (<get>/<get-config>/RPC อ่านข้อมูล) ห้าม writer ; ไม่ log/print ; ไม่คืนเนื้อ reply
import asyncio
import unicodedata
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional
from xml.etree import ElementTree as ET

from backend.callhome_token_probe import NETCONF_END, NS_RPC, ProbeError, parse_reply
from backend.device_identity import _queries  # serial debug เท่านั้น; display metadata ใช้ query เฉพาะด้านล่าง

METADATA_RPC_TIMEOUT = 8.0      # ต่อ RPC
METADATA_TOTAL_TIMEOUT = 20.0   # รวมทุก RPC ก่อนเปิด transaction (ห้ามถือ DB lock ระหว่างรอ NETCONF)
MAX_NAME_LENGTH = 64            # hostname ที่ใช้เป็นชื่อการ์ด
MAX_FIELD_LENGTH = 128          # model / firmware

_HOSTNAME_TAGS = ("host-name", "hostname", "sysName")
_MODEL_TAGS = ("product-model", "model-number", "model", "chassis-type", "productName")
_FIRMWARE_TAGS = ("software-version", "productVer", "os-version", "junos-version")
_SERIAL_TAGS = ("serial-number", "serialNumber", "esn")

# One compact read-only RPC per vendor.  Cisco combines three supported subtree
# filters in one <get>; Junos get-software-information already returns hostname,
# product model and Junos version together.  This avoids adding latency to the
# authentication path and avoids the very large unfiltered hardware reply.
_METADATA_QUERIES = {
    "cisco": (
        "metadata",
        '<get><filter type="subtree">'
        '<device-hardware-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-device-hardware-oper">'
        '<device-hardware><device-inventory><hw-type>hw-type-chassis</hw-type><hw-dev-index/><dev-name/><hw-description/><part-number/>'
        '</device-inventory><device-system-data><software-version/></device-system-data></device-hardware>'
        '</device-hardware-data>'
        '<components xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-platform-oper"><component><cname/><state>'
        '<type>comp-chassis</type><description/><part-no/></state></component><component><cname/><state>'
        '<type>comp-operating-system</type><version/><firmware-ver/></state></component></components>'
        '<native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native"><hostname/><version/></native>'
        '</filter></get>',
    ),
    "juniper": (
        "metadata",
        '<get-software-information xmlns="http://yang.juniper.net/junos-es/rpc/version"/>',
    ),
    "huawei": (
        "metadata",
        '<get><filter type="subtree"><system xmlns="http://www.huawei.com/netconf/vrp/huawei-system">'
        '<systemInfo/></system></filter></get>',
    ),
}


@dataclass(frozen=True)
class DeviceMetadata:
    """Metadata; serial is ephemeral debug data and must never be persisted or used for authentication."""
    hostname: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    # Keep the debug-only value out of accidental dataclass repr/log output.  The
    # dedicated callhome_debug module is the only place allowed to print it.
    serial: Optional[str] = field(default=None, repr=False)


class MetadataConnectionLost(Exception):
    """connection ปิดระหว่าง probe: ห้าม activate (จะ consume token ให้ connection ที่ตายแล้ว)"""

    def __init__(self):
        super().__init__("Call Home connection closed during metadata probe")


def safe_display_value(value: object, max_length: int) -> Optional[str]:
    """คืนค่าเดิมเมื่อปลอดภัยต่อการแสดงผล (ไม่ normalize/ไม่เปลี่ยน case/ไม่ reject เพราะรูปแบบ brownfield)
    ตัดเฉพาะช่องว่างหัวท้ายจาก XML; ว่าง, ยาวเกินกำหนด หรือมี control character -> None (caller คงค่าเดิม)"""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > max_length:
        return None
    if any(unicodedata.category(character).startswith("C") for character in text):
        return None
    return text


def _first_text(root: ET.Element, names: tuple[str, ...]) -> Optional[str]:
    for element in root.iter():
        if element.tag.split("}", 1)[-1] in names and element.text and element.text.strip():
            return element.text
    return None


def _child_text(element: ET.Element, *names: str) -> Optional[str]:
    wanted = set(names)
    for child in element:
        if child.tag.split("}", 1)[-1] in wanted and child.text and child.text.strip():
            return child.text.strip()
    return None


def _cisco_chassis_model(root: ET.Element) -> Optional[str]:
    """Read only a chassis component; never mistake a fan/CPU/port for the model."""
    candidates: list[Optional[str]] = []
    for element in root.iter():
        local = element.tag.split("}", 1)[-1]
        if local == "component":
            state = next((child for child in element if child.tag.split("}", 1)[-1] == "state"), None)
            if state is not None and (_child_text(state, "type") or "").lower() == "comp-chassis":
                candidates.append(_child_text(state, "description", "part-no"))
        elif local == "device-inventory":
            hw_type = (_child_text(element, "hw-type") or "").lower()
            if hw_type in {"hw-type-chassis", "chassis"}:
                candidates.append(_child_text(element, "dev-name", "hw-description", "part-number"))
    for value in candidates:
        safe = safe_display_value(value, MAX_FIELD_LENGTH)
        if safe:
            return safe
    return None


def _cisco_operating_system_version(root: ET.Element) -> Optional[str]:
    """Fallbacks for IOS XE releases which omit device-system-data/software-version."""
    for element in root.iter():
        if element.tag.split("}", 1)[-1] != "component":
            continue
        state = next((child for child in element if child.tag.split("}", 1)[-1] == "state"), None)
        if state is None or (_child_text(state, "type") or "").lower() != "comp-operating-system":
            continue
        value = safe_display_value(_child_text(state, "version", "firmware-ver"), MAX_FIELD_LENGTH)
        if value:
            return value

    # IOS XE native/version is the running-config version statement.  It is
    # less descriptive than platform state, but is stable and still better
    # than leaving firmware blank on platforms without operational version.
    for element in root.iter():
        if element.tag.split("}", 1)[-1] == "native":
            value = safe_display_value(_child_text(element, "version"), MAX_FIELD_LENGTH)
            if value:
                return value
    return None


def parse_metadata(replies: list[str]) -> DeviceMetadata:
    hostname = model = firmware = serial = None
    for reply in replies:
        try:
            root = parse_reply(reply)
        except ProbeError:
            continue  # ค่านี้ optional: reply เสีย/rpc-error = ไม่มีข้อมูลจาก query นั้น
        hostname = hostname or safe_display_value(_first_text(root, _HOSTNAME_TAGS), MAX_NAME_LENGTH)
        model = model or _cisco_chassis_model(root) or safe_display_value(_first_text(root, _MODEL_TAGS), MAX_FIELD_LENGTH)
        firmware = (
            firmware
            or safe_display_value(_first_text(root, _FIRMWARE_TAGS), MAX_FIELD_LENGTH)
            or _cisco_operating_system_version(root)
        )
        serial = serial or safe_display_value(_first_text(root, _SERIAL_TAGS), MAX_FIELD_LENGTH)
    return DeviceMetadata(hostname=hostname, model=model, firmware=firmware, serial=serial)


Send = Callable[[int, str], Awaitable[str]]


def metadata_steps(vendor: str) -> list[tuple[str, str]]:
    query = _METADATA_QUERIES.get(vendor)
    return [query] if query else []


async def read_device_metadata(send: Send, vendor: str, first_message_id: int) -> DeviceMetadata:
    """RPC ล้มเหลว/timeout เป็นรายตัว -> ข้ามค่านั้น (ไม่ทำให้ credential ที่ถูกต้องเสีย) ; connection ปิด -> MetadataConnectionLost"""
    replies = []
    for offset, (_, inner) in enumerate(metadata_steps(vendor)):
        message_id = first_message_id + offset
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<rpc xmlns="{NS_RPC}" message-id="{message_id}">{inner}</rpc>{NETCONF_END}'
        )
        try:
            replies.append(await send(message_id, payload))
        except (ConnectionError, EOFError):
            raise MetadataConnectionLost() from None
        except asyncio.TimeoutError:
            continue
        except Exception:
            continue
    return parse_metadata(replies)


async def read_device_serial(send: Send, vendor: str, message_id: int) -> Optional[str]:
    """Optional debug-only probe: issue at most one hardware RPC and return only serial.

    This is deliberately separate from authentication.  A failure always means
    "unavailable" to the caller and must never accept or reject a connection.
    """
    # Serial remains an explicitly enabled diagnostic.  Keep using the proven
    # legacy hardware RPC instead of expanding the fast display-metadata RPC.
    hardware = next((inner for name, inner in _queries(vendor) if name == "hardware"), None)
    if hardware is None:
        return None
    payload = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<rpc xmlns="{NS_RPC}" message-id="{message_id}">{hardware}</rpc>{NETCONF_END}'
    )
    reply = await send(message_id, payload)
    return parse_metadata([reply]).serial
