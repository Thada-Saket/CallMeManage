""" |======= Read-only Call Home Enrollment Marker Probe (Cisco / Huawei / Juniper) =======| """
# Phase 7: อ่านชื่อ endpoint/client ของ Call Home ที่ "เป็นของ connection นี้" ด้วย NETCONF read-only เท่านั้น
#   Cisco   : endpoint name ใต้ client CLOUD_MANAGEMENT           (get-config + get oper connected-endpoint)
#   Huawei  : endpointName ใต้ callHomeName CLOUD_MANAGEMENT       (get-config)
#   Juniper : outbound-ssh client name ที่ status Up ชี้ Cloud Manager (get-config + get-outbound-ssh-service-information)
# ห้ามเลือกตัวแรกโดยเดา: ถ้าพิสูจน์ไม่ได้ว่าตัวใดเป็น connection นี้ -> AMBIGUOUS / PROBE_FAILED (caller ต้อง reject)
# ไฟล์นี้ไม่รู้จัก DB/session pool; ไม่ log/print; ไม่คืน raw XML หรือค่าที่อ่านได้ใน exception (ค่า token อยู่ใน
# TokenProbeResult ที่ repr ถูกซ่อน และเฉพาะกรณี PRESENT_VALID_FORMAT)
# payload ที่ส่งมีแค่ <get>, <get-config> และ RPC อ่านข้อมูล (get-outbound-ssh-service-information) ห้ามมี writer
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable, Optional
from xml.etree import ElementTree as ET

from tools.safe_xml import safe_fromstring
from backend.enrollment_token_service import validate_enrollment_token

NETCONF_END = "]]>]]>"
NS_RPC = "urn:ietf:params:xml:ns:netconf:base:1.0"
CALLHOME_PARENT_NAME = "CLOUD_MANAGEMENT"  # ชื่อ parent คงที่ของ Cisco/Huawei (ดู cli_generator.py)
LEGACY_NAMES = {"cisco": "callhome-server", "huawei": "callhome-server", "juniper": "cloud-manager"}
MAX_REPLY_CHARS = 256 * 1024  # reply ใหญ่เกินนี้ = ผิดปกติ (ข้อมูล call-home มีไม่กี่ร้อยไบต์)
MAX_MARKER_CANDIDATES = 16    # จำนวน marker candidate สูงสุดที่ยอมรับได้
_TOKEN_LIKE = re.compile(r"[A-Za-z0-9]{19}")  # หน้าตาเหมือน token (ยาว 19 alnum) -> ห้ามตกไป legacy ถ้าไม่ผ่าน validation


class ProbeStatus(Enum):
    ABSENT = "absent"                          # ใช้ชื่อ legacy/ไม่ใช่ marker: ลอง legacy flow ได้
    PRESENT_VALID_FORMAT = "present_valid"     # token รูปแบบถูก: hash + lookup ต่อ (ห้าม fallback legacy)
    PRESENT_INVALID = "present_invalid"        # หน้าตาเหมือน token แต่ผิดรูปแบบ: reject
    AMBIGUOUS = "ambiguous"                    # หลาย endpoint/client เป็นไปได้: reject
    PROBE_FAILED = "probe_failed"              # timeout/rpc-error/XML เสีย/ผูก connection ไม่ได้: reject


@dataclass(frozen=True)
class TokenProbeResult:
    status: ProbeStatus
    tokens: tuple[str, ...] = field(default=(), repr=False)

    def __init__(
        self,
        status: ProbeStatus,
        tokens: tuple[str, ...] = (),
        token: Optional[str] = None,
    ):
        object.__setattr__(self, "status", status)
        if token is not None and not tokens:
            object.__setattr__(self, "tokens", (token,))
        else:
            object.__setattr__(self, "tokens", tuple(tokens))

    @property
    def token(self) -> Optional[str]:
        if len(self.tokens) == 1:
            return self.tokens[0]
        return None

    def __repr__(self) -> str:
        return f"TokenProbeResult(status={self.status.name})"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("TokenProbeResult may hold a plaintext token and cannot be serialized")


class ProbeError(Exception):
    """อ่าน/parse ไม่ได้ - ข้อความคงที่ ไม่มีเนื้อหาของ reply"""

    def __init__(self):
        super().__init__("Call Home probe failed")


# ---------- payloads (read-only) ----------

def _rpc(message_id: int, inner: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<rpc xmlns="{NS_RPC}" message-id="{message_id}">{inner}</rpc>{NETCONF_END}'
    )


_CISCO_CONFIG = (
    "<get-config><source><running/></source><filter type=\"subtree\">"
    '<netconf-callhome-config xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ncch-cfg"><ncch-clients><ncch-client>'
    "<name/><ncch-client-endpoints><ncch-client-endpoint><name/><ssh><tcpc-remote-ipaddr/><tcpc-remote-port/></ssh>"
    "</ncch-client-endpoint></ncch-client-endpoints></ncch-client></ncch-clients></netconf-callhome-config>"
    "</filter></get-config>"
)
_CISCO_OPER = (
    '<get><filter type="subtree"><netconf-callhome-oper xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ncch-oper">'
    "<ncch-client><name/><state/><connected-endpoint/></ncch-client></netconf-callhome-oper></filter></get>"
)
_HUAWEI_CONFIG = (
    '<get-config><source><running/></source><filter type="subtree">'
    '<sshs xmlns="http://www.huawei.com/netconf/vrp/huawei-sshs"><callHomes><callHome><callHomeName/><sshEndpoints>'
    "<sshEndpoint><endpointName/><address/><port/></sshEndpoint></sshEndpoints></callHome></callHomes></sshs>"
    "</filter></get-config>"
)
_JUNIPER_CONFIG = (
    '<get-config><source><running/></source><filter type="subtree">'
    '<configuration xmlns="http://yang.juniper.net/junos-es/conf/root">'
    '<system xmlns="http://yang.juniper.net/junos-es/conf/system"><services><outbound-ssh><client><name/></client>'
    "</outbound-ssh></services></system></configuration></filter></get-config>"
)
_JUNIPER_OPER = (
    '<get-outbound-ssh-service-information xmlns="http://yang.juniper.net/junos-es/rpc/system">'
    "<verbosity>detail</verbosity></get-outbound-ssh-service-information>"
)

# (ชื่อขั้น, inner XML) ต่อ vendor - ลำดับตายตัว
PROBE_STEPS = {
    "cisco": (("config", _CISCO_CONFIG), ("oper", _CISCO_OPER)),
    "huawei": (("config", _HUAWEI_CONFIG),),
    "juniper": (("config", _JUNIPER_CONFIG), ("oper", _JUNIPER_OPER)),
}


# ---------- XML helpers (namespace-tolerant, parent/child preserving) ----------

def _local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _children(element, name: str) -> list:
    return [child for child in element if _local(child.tag) == name]


def _child_text(element, name: str) -> Optional[str]:
    for child in _children(element, name):
        return (child.text or "").strip()
    return None


def _descendants(root, name: str) -> list:
    return [element for element in root.iter() if _local(element.tag) == name]


def parse_reply(reply: object, expected_message_id: Optional[int] = None) -> ET.Element:
    """parse reply อย่างปลอดภัย: ปฏิเสธ DTD/entity (ป้องกัน entity expansion จากอุปกรณ์ที่ยังไม่ authenticate),
    reply ใหญ่เกินกำหนด, XML เสีย, rpc-error และ message-id ที่ไม่ตรงกัน"""
    if not isinstance(reply, str) or not reply.strip() or len(reply) > MAX_REPLY_CHARS:
        raise ProbeError()
    if "<!DOCTYPE" in reply or "<!ENTITY" in reply:
        raise ProbeError()
    try:
        root = safe_fromstring(reply)
    except ET.ParseError:
        raise ProbeError() from None
    if _local(root.tag) != "rpc-reply":
        raise ProbeError()
    if any(_local(element.tag) == "rpc-error" for element in root.iter()):
        raise ProbeError()
    if expected_message_id is not None and root.get("message-id") != str(expected_message_id):
        raise ProbeError()
    return root


def _same_ip(value: Optional[str], expected_ip: str) -> bool:
    try:
        return ipaddress.ip_address((value or "").strip()) == ipaddress.ip_address(expected_ip)
    except ValueError:
        return False


def _same_port(value: Optional[str], expected_port: int, *, missing_ok: bool) -> bool:
    if value is None or value == "":
        return missing_ok  # Cisco: CLI ไม่กำหนด port (ใช้ค่า default) จึงไม่มี node port
    return value.strip().isdigit() and int(value.strip()) == int(expected_port)


class _Ambiguous(Exception):
    pass


# ---------- per-vendor candidate selection: คืน (candidates, primary) หรือโยน ProbeError/_Ambiguous ----------

def _candidates_cisco(config_reply: str, oper_reply: str, expected_ip: str, expected_port: int) -> tuple[list[str], Optional[str]]:
    config = parse_reply(config_reply)
    clients = [c for c in _descendants(config, "ncch-client") if _child_text(c, "name") == CALLHOME_PARENT_NAME]
    if not clients:
        raise ProbeError()
    if len(clients) > 1:
        raise _Ambiguous()
    raw_candidates = []
    for holder in _children(clients[0], "ncch-client-endpoints"):
        for endpoint in _children(holder, "ncch-client-endpoint"):
            name = _child_text(endpoint, "name")
            ssh = _children(endpoint, "ssh")
            if not name or len(ssh) != 1:
                continue
            if _same_ip(_child_text(ssh[0], "tcpc-remote-ipaddr"), expected_ip) and _same_port(
                    _child_text(ssh[0], "tcpc-remote-port"), expected_port, missing_ok=True):
                raw_candidates.append(name)
    if not raw_candidates:
        raise ProbeError()

    candidates = list(dict.fromkeys(raw_candidates))
    if len(candidates) > MAX_MARKER_CANDIDATES:
        raise _Ambiguous()

    oper = parse_reply(oper_reply)
    connected = [
        c for c in _descendants(oper, "ncch-client") if _child_text(c, "name") == CALLHOME_PARENT_NAME
    ]
    primary = None
    if len(connected) == 1:
        endpoint_name = _child_text(connected[0], "connected-endpoint")
        state = (_child_text(connected[0], "state") or "").lower()
        if endpoint_name and "connected" in state and "disconnected" not in state:
            # oper state บอกชัดว่า endpoint ไหนกำลังต่ออยู่ - ต้องอยู่ในกลุ่ม endpoint ที่ชี้ Cloud Manager
            if endpoint_name in candidates:
                primary = endpoint_name
            else:
                raise ProbeError()
    elif len(connected) > 1:
        raise _Ambiguous()

    return candidates, primary


def _candidates_huawei(config_reply: str, expected_ip: str, expected_port: int) -> tuple[list[str], Optional[str]]:
    config = parse_reply(config_reply)
    parents = [c for c in _descendants(config, "callHome") if _child_text(c, "callHomeName") == CALLHOME_PARENT_NAME]
    if not parents:
        raise ProbeError()
    if len(parents) > 1:
        raise _Ambiguous()
    raw_candidates = []
    for holder in _children(parents[0], "sshEndpoints"):
        for endpoint in _children(holder, "sshEndpoint"):
            name = _child_text(endpoint, "endpointName")
            if name and _same_ip(_child_text(endpoint, "address"), expected_ip) and _same_port(
                    _child_text(endpoint, "port"), expected_port, missing_ok=False):
                raw_candidates.append(name)
    if not raw_candidates:
        raise ProbeError()

    candidates = list(dict.fromkeys(raw_candidates))
    if len(candidates) > MAX_MARKER_CANDIDATES:
        raise _Ambiguous()

    primary = candidates[0] if len(candidates) == 1 else None
    return candidates, primary


def _server_matches(server_info: Optional[str], expected_ip: str, expected_port: int) -> bool:
    for entry in (server_info or "").split(","):
        host, separator, port = entry.strip().rpartition(":")
        if separator and _same_ip(host, expected_ip) and _same_port(port, expected_port, missing_ok=False):
            return True
    return False


def _candidates_juniper(config_reply: str, oper_reply: str, expected_ip: str, expected_port: int) -> tuple[list[str], Optional[str]]:
    config = parse_reply(config_reply)
    configured = []
    for outbound in _descendants(config, "outbound-ssh"):
        for client in _children(outbound, "client"):
            name = _child_text(client, "name")
            if name:
                configured.append(name)
    configured_unique = list(dict.fromkeys(configured))

    oper = parse_reply(oper_reply)
    active = []
    for client in _descendants(oper, "outbound-ssh-client"):
        name = _child_text(client, "outbound-ssh-client-name")
        status = (_child_text(client, "outbound-ssh-connection-status") or "").strip().lower()
        if name and status == "up" and _server_matches(_child_text(client, "outbound-ssh-server-info"), expected_ip, expected_port):
            active.append(name)
    if not active:
        raise ProbeError()

    active_unique = list(dict.fromkeys(active))
    for act in active_unique:
        if act not in configured_unique:
            raise ProbeError()  # oper กับ running config ไม่สอดคล้องกัน

    candidates = active_unique
    if len(candidates) > MAX_MARKER_CANDIDATES:
        raise _Ambiguous()

    primary = active_unique[0] if len(active_unique) == 1 else None
    return candidates, primary


def get_marker_candidates(vendor: str, replies: dict, expected_ip: str, expected_port: int) -> tuple[list[str], Optional[str]]:
    if vendor == "cisco":
        return _candidates_cisco(replies["config"], replies["oper"], expected_ip, expected_port)
    if vendor == "huawei":
        return _candidates_huawei(replies["config"], expected_ip, expected_port)
    if vendor == "juniper":
        return _candidates_juniper(replies["config"], replies["oper"], expected_ip, expected_port)
    raise ProbeError()


def classify_candidates(vendor: str, candidates: list[str], primary: Optional[str]) -> TokenProbeResult:
    """ประเมิน candidates ทั้งหมด:
    - ถ้า oper พิสูจน์ชัดเจนว่า connection นี้ต่อผ่าน legacy endpoint -> ABSENT
    - ถ้ามี token-shaped ที่ validate ได้ -> ส่งทุกตัวไป resolve ด้วย pending hash (PRESENT_VALID_FORMAT)
    - ถ้าไม่มี valid token แต่มี token-like ที่ไม่ผ่าน validation -> PRESENT_INVALID (ห้ามตก legacy)
    - ถ้าไม่มี token-shaped ใด ๆ เลย -> พฤติกรรมเดิม (primary/ตัวเดียว/ambiguous)
    """
    deduped = list(dict.fromkeys(candidates))
    if len(deduped) > MAX_MARKER_CANDIDATES:
        return TokenProbeResult(ProbeStatus.AMBIGUOUS)

    legacy_name = LEGACY_NAMES.get(vendor)
    # ถ้า oper พิสูจน์ชัดเจนว่า connection ปัจจุบันต่อผ่าน legacy endpoint
    if primary is not None and primary == legacy_name:
        return TokenProbeResult(ProbeStatus.ABSENT)

    valid_tokens = [name for name in deduped if validate_enrollment_token(name)]
    if valid_tokens:
        return TokenProbeResult(ProbeStatus.PRESENT_VALID_FORMAT, tokens=tuple(valid_tokens))

    token_like = [name for name in deduped if _TOKEN_LIKE.fullmatch(name)]
    if token_like:
        return TokenProbeResult(ProbeStatus.PRESENT_INVALID)

    if primary is not None:
        if primary == legacy_name:
            return TokenProbeResult(ProbeStatus.ABSENT)
        return TokenProbeResult(ProbeStatus.ABSENT)

    if len(deduped) == 1:
        if deduped[0] == legacy_name:
            return TokenProbeResult(ProbeStatus.ABSENT)
        return TokenProbeResult(ProbeStatus.ABSENT)

    if len(deduped) > 1:
        if all(name == legacy_name for name in deduped):
            return TokenProbeResult(ProbeStatus.ABSENT)
        return TokenProbeResult(ProbeStatus.AMBIGUOUS)

    return TokenProbeResult(ProbeStatus.PROBE_FAILED)


def classify_marker_name(vendor: str, name: str) -> TokenProbeResult:
    """ชื่อที่ถูกเลือกแล้ว -> ABSENT (ชื่อ legacy / ไม่ใช่ marker) | PRESENT_VALID_FORMAT | PRESENT_INVALID"""
    return classify_candidates(vendor, [name], name)


def select_marker_name(vendor: str, replies: dict, expected_ip: str, expected_port: int) -> str:
    """replies: {"config": xml, "oper": xml} (เฉพาะขั้นที่ vendor นั้นใช้)"""
    candidates, primary = get_marker_candidates(vendor, replies, expected_ip, expected_port)
    if primary is not None:
        return primary
    if len(candidates) == 1:
        return candidates[0]
    raise _Ambiguous()


def evaluate_replies(vendor: str, replies: dict, expected_ip: str, expected_port: int) -> TokenProbeResult:
    try:
        candidates, primary = get_marker_candidates(vendor, replies, expected_ip, expected_port)
        return classify_candidates(vendor, candidates, primary)
    except _Ambiguous:
        return TokenProbeResult(ProbeStatus.AMBIGUOUS)
    except (ProbeError, KeyError):
        return TokenProbeResult(ProbeStatus.PROBE_FAILED)


# ---------- orchestration ----------

# send(message_id, payload_with_terminator) -> reply xml ; timeout ต่อ RPC อยู่ที่ผู้เรียก (conn_socket ใช้ QUARANTINE_RPC_TIMEOUT)
Send = Callable[[int, str], Awaitable[str]]


async def read_token_marker(send: Send, vendor: str, expected_ip: str, expected_port: int, first_message_id: int) -> TokenProbeResult:
    steps = PROBE_STEPS.get(vendor)
    if steps is None:
        return TokenProbeResult(ProbeStatus.PROBE_FAILED)  # vendor unknown: พิสูจน์ไม่ได้ว่าเป็น legacy
    replies = {}
    try:
        for offset, (name, inner) in enumerate(steps):
            message_id = first_message_id + offset
            reply = await send(message_id, _rpc(message_id, inner))
            parse_reply(reply, message_id)  # ตรวจ rpc-error/XML เสี้ยน/message-id ทันที แล้วเก็บ reply ไว้ให้ parser เลือก
            replies[name] = reply
    except ProbeError:
        return TokenProbeResult(ProbeStatus.PROBE_FAILED)
    except Exception:  # timeout, connection ปิด ฯลฯ - ไม่ส่งข้อความต้นฉบับต่อ
        return TokenProbeResult(ProbeStatus.PROBE_FAILED)
    return evaluate_replies(vendor, replies, expected_ip, expected_port)
