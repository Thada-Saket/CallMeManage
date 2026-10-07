"""ระบบตรวจความสามารถอุปกรณ์ - resolver (dynamic feature ขั้นที่ 2)

ตัดสินจากโปรไฟล์ของอุปกรณ์ว่าคำสั่งไหนควรซ่อนจากหน้าเว็บ และคำสั่งเขียนไหนควรถูกปฏิเสธ
ดีไซน์: planning/capability_detection_notes.txt หัวข้อ 9-10 · ความคืบหน้า: planning/dynamic_feature_progress.md

ไฟล์นี้เป็นฟังก์ชันล้วน ไม่ต่ออุปกรณ์และไม่แตะ DB ณ ขั้นที่ 2 ยังไม่มีโค้ดส่วนไหนเรียกใช้

หลัก 3 ข้อที่ห้ามเปลี่ยนโดยไม่ทบทวน:
  1. ซ่อนเฉพาะเมื่อมีหลักฐานว่าทำไม่ได้ - ไม่มีโปรไฟล์ ชั้นไหนตรวจไม่สำเร็จ หรือกฎยังไม่มีข้อมูล = ไม่ซ่อน
  2. คำสั่งอ่าน (get_*) ซ่อนจากเมนูได้แต่ไม่ถูกปฏิเสธ - หลายหน้าเรียกคำสั่งอ่านของฟีเจอร์อื่นประกอบ
     (เช่นฟอร์ม NAT เรียก get_security_zone_information) การปฏิเสธจะทำให้หน้าที่ใช้ได้อยู่พัง
     ส่วนคำสั่งอ่านที่อุปกรณ์ไม่รองรับ อุปกรณ์ตอบ error เองได้โดยไม่เปลี่ยน config
  3. ห้ามคืนรายการคำสั่งว่างสำหรับอุปกรณ์ที่มีคำสั่ง - หน้าเว็บตีความรายการว่างว่า "ยังไม่รู้"
     (DeviceDetail.jsx: capabilityKnown = commands.length > 0) แล้วแสดงทุกเมนู
"""
import ast
import inspect
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable

from backend.translator_service import COMPOSITE_FUNCTIONS, PUBLIC_FUNCTIONS, module_for_vendor

# namespace ของตัวโปรโตคอล NETCONF เอง ไม่ใช่ YANG module จึงไม่อยู่ในรายการ schema ของอุปกรณ์
_PROTOCOL_NAMESPACE_MARKERS = ("urn:ietf:params:xml:ns:netconf:base:", "/netconf/capability/")
_LITERAL_XMLNS = re.compile(r'xmlns(?::\w+)?\s*=\s*["\']((?:http|urn)[^"\'{}]+)["\']')
_CONSTANT_XMLNS = re.compile(r'xmlns(?::\w+)?\s*=\s*["\']\{(\w+)\}')
# คำใน payload ที่กฎข้อยกเว้นใช้เลือกคำสั่ง (namespace แยกไม่ได้ เช่น Junos ใช้ interfaces ร่วมกัน)
_BODY_MARKERS = ("ethernet-switching",)

NS_CISCO_ZONE = "http://cisco.com/ns/yang/Cisco-IOS-XE-zone"
NS_CISCO_CRYPTO = "http://cisco.com/ns/yang/Cisco-IOS-XE-crypto"


@dataclass(frozen=True)
class FunctionInfo:
    namespaces: frozenset
    markers: frozenset


def _is_protocol_namespace(namespace: str) -> bool:
    return any(marker in namespace for marker in _PROTOCOL_NAMESPACE_MARKERS)


def _short_namespace(namespace: str) -> str:
    return re.split(r"[/:]", namespace.rstrip("/"))[-1]


@lru_cache(maxsize=None)
def function_map(vendor: str) -> dict[str, FunctionInfo]:
    """แผนที่คำสั่ง -> namespace ที่ payload ใช้ อ่านจาก source ของ translator (ไม่เรียกฟังก์ชันจริง
    เพราะส่วนใหญ่ต้องมีพารามิเตอร์) รวม helper ในไฟล์เดียวกันและค่าคงที่ NS_* ระดับ module
    ข้อจำกัด: payload ที่เลือก namespace ตามพารามิเตอร์จะนับทุกทางเลือกรวมกัน"""
    module = module_for_vendor(vendor)
    if module is None:
        return {}
    source = inspect.getsource(module)
    tree = ast.parse(source)
    constants = {
        target.id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}

    def collect(name: str, seen: set) -> tuple[set, str]:
        if name in seen or name not in functions:
            return set(), ""
        seen.add(name)
        segment = ast.get_source_segment(source, functions[name]) or ""
        namespaces = set(_LITERAL_XMLNS.findall(segment))
        namespaces |= {constants[ref] for ref in _CONSTANT_XMLNS.findall(segment) if ref in constants}
        body = segment
        for call in ast.walk(functions[name]):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                called_namespaces, called_body = collect(call.func.id, seen)
                namespaces |= called_namespaces
                body += called_body
        return namespaces, body

    result = {}
    for name in sorted(PUBLIC_FUNCTIONS | COMPOSITE_FUNCTIONS):
        if name not in functions:
            continue
        namespaces, body = collect(name, set())
        result[name] = FunctionInfo(
            namespaces=frozenset(ns for ns in namespaces if not _is_protocol_namespace(ns)),
            markers=frozenset(marker for marker in _BODY_MARKERS if marker in body),
        )
    return result


# ---------------------------------------------------------------------------
# ตารางข้อยกเว้น: กรณีที่ schema ไม่บอกความจริง ใส่ข้อมูลเฉพาะที่ทดสอบกับอุปกรณ์แล้วเท่านั้น
# ---------------------------------------------------------------------------

# ชุด (level, addon) ของ Cisco license boot level ที่ทดสอบแล้วว่าใช้กลุ่มคำสั่งนั้น "ไม่ได้"
# ผลทดสอบของผู้ใช้บน c8000 (แก้ 15 ก.ย. 2026): zone / ZBF / VPN สั่งไม่ได้เฉพาะตอนไม่ตั้ง license boot level
# เลย ตั้งเป็น essentials / advantage / premier แล้วใช้ได้ทันที (ผู้ใช้กำหนดให้ซ่อนทั้งหมวด VPN เมื่อสั่งไม่ได้)
# ใช้แบบ "ห้าม" แทน "อนุญาต" เพื่อไม่ให้ license ที่ยังไม่เคยทดสอบถูกซ่อนไปด้วย
# กฎ license ใช้เฉพาะ router (feature routing-platform) เพราะ c9000 รับ ikev2 / IPsec ได้ทุก license
_CISCO_NO_LICENSE = frozenset({("not_configured", None)})
CISCO_LICENSE_DENIED: dict[str, set] = {
    "stateful_firewall": set(_CISCO_NO_LICENSE),
    "ipsec_vpn": set(_CISCO_NO_LICENSE),
}

# ค่า route-engine/model ของ Juniper ที่ทดสอบแล้วว่าใช้ family ethernet-switching ไม่ได้
# ว่างโดยตั้งใจ: ทดสอบ 15 ก.ย. 2026 แล้ว vSRX (model "VSRX RE") สร้าง VLAN และใส่ interface access
# เข้า VLAN ได้ ทำหน้าที่เป็น switch ได้ (หลักฐานเดิมใน HANDOFF ที่ apply_switchport ได้ syntax error ใช้ไม่ได้แล้ว)
JUNIPER_MODELS_WITHOUT_SWITCHING: set = set()

# กฎ VLAN ของ Cisco - ผลทดสอบ 15 ก.ย. 2026 บน c8000: ไม่รับ "vlan 10" และ "switchport" ส่วน interface Vlan
# สร้างได้แต่ไม่มีความหมายเมื่อตั้ง VLAN และ switchport ไม่ได้ ผู้ใช้จึงให้ตัดทั้งกลุ่ม
# ตาม YANG feature "vlan" คุมแค่ private-vlan และ mdns-sd แต่จากผลทดสอบใช้เป็นเครื่องบอกแพลตฟอร์มได้:
# c9000 มี feature นี้ c8000 ไม่มี
# ไม่ซ่อน get_switchport_information เพราะหน้า Interfaces ใช้แยก Layer 2/3 ของทุกพอร์ต
# set_interface_l3_none ใช้ล้าง IPv4/DHCP/MTU บนพอร์ต routed ได้ด้วย ไม่ต้องรองรับ VLAN
# translator จะส่ง switchport เฉพาะเมื่อระบุ switchport_capable เท่านั้น
CISCO_VLAN_COMMANDS = frozenset({
    "get_vlan_information",
    "set_vlan",
    "remove_vlan",
    "set_interface_vlan",
    "set_switchport",
    "apply_interface_to_vlan",
    "remove_switchport",
})

# กฎ IPsec แบบ tunnel interface ของ Cisco - ตรวจ CLI บน c9000 (C9KV, IOS XE 17.15.01) 15 ก.ย. 2026:
# "tunnel mode ?" มีแค่ gre / sdwan และ "tunnel protection ?" มีแค่ psk จึงทำ IPsec แบบ tunnel interface ไม่ได้
# (รองรับเฉพาะ crypto map + access list ซึ่งระบบยังไม่มี) ส่วน GRE ใช้ได้ปกติ ผู้ใช้ให้ซ่อนส่วน VPN อื่นแต่คง GRE ไว้
# schema บอกไม่ได้เพราะ c9000 ประกาศทั้ง Cisco-IOS-XE-crypto และ feature crypto จึงตัดสินจากการไม่มี
# feature routing-platform (มีบน c8000 ไม่มีบน c9000)
# คำสั่ง tunnel ที่ GRE ต้องใช้ไม่ถูกซ่อนทั้งคำสั่ง แต่ create_security_tunnel ถูกห้ามค่า tunnel_type=ipsec แทน
CISCO_TUNNEL_COMMANDS_FOR_GRE = frozenset({
    "create_security_tunnel",
    "get_security_tunnel_information",
    "remove_tunnel_interface",
})

# สองคำสั่งนี้เป็นโหมด forwarding ของ Cisco switch ไม่ใช่หน้าตั้งค่าของ router:
# router (routing-platform) เปิด routing โดยธรรมชาติและไม่มี ip default-gateway;
# switch ใช้ ip routing/no ip routing สลับระหว่าง L3 forwarding กับ management
# default gateway. รวม read/write เพื่อให้ทั้งเมนูและ API ใช้กฎเดียวกัน
CISCO_SWITCH_ROUTE_MODE_COMMANDS = frozenset({
    "get_ip_routing",
    "set_ip_routing",
    "get_ip_default_gateway",
    "set_ip_default_gateway",
})


@dataclass(frozen=True)
class ExceptionRule:
    rule_id: str
    vendor: str
    select: Callable[[str, FunctionInfo], bool]
    decide: Callable[[dict], str | None]


def _cisco_features(profile: dict) -> set | None:
    """feature ใน Cisco-IOS-XE-features จากชั้น schema - None = ไม่รู้ (schema ล้มเหลวหรือไม่มี module นี้)"""
    schema = profile.get("schema") or {}
    if schema.get("status") != "ok":
        return None
    features = (schema.get("features") or {}).get("Cisco-IOS-XE-features")
    return set(features) if features else None


def _platform_role(vendor: str, profile: dict) -> str | None:
    if vendor != "cisco":
        return None
    features = _cisco_features(profile)
    if features is None:
        return None
    return "router" if "routing-platform" in features else "switch"


def _cisco_license_rule(group: str, label: str) -> Callable[[dict], str | None]:
    def decide(profile: dict) -> str | None:
        features = _cisco_features(profile)
        if features is None or "routing-platform" not in features:
            return None
        license_info = profile.get("license") or {}
        status = license_info.get("status")
        if status == "ok":
            key = (license_info.get("level"), license_info.get("addon"))
        elif status == "not_configured":
            key = ("not_configured", None)
        else:
            return None
        if key in CISCO_LICENSE_DENIED.get(group, set()):
            if key[0] == "not_configured":
                return f"License boot level is not configured, cannot use {label}"
            level = key[0] if key[1] is None else f"{key[0]} + {key[1]}"
            return f"License {level} cannot use {label}"
        return None
    return decide


def _cisco_vlan_rule(profile: dict) -> str | None:
    features = _cisco_features(profile)
    if features is None or "vlan" in features:
        return None
    return "This platform does not support VLAN and switchport"


def _cisco_no_tunnel_ipsec_rule(profile: dict) -> str | None:
    features = _cisco_features(profile)
    if features is None or "routing-platform" in features:
        return None
    return "This platform does not support tunnel interface IPsec (GRE only)"


def _juniper_model_rule(profile: dict) -> str | None:
    model = profile.get("model") or {}
    if model.get("status") == "ok" and model.get("value") in JUNIPER_MODELS_WITHOUT_SWITCHING:
        return f"Model {model['value']} does not support ethernet-switching"
    return None


EXCEPTION_RULES = (
    ExceptionRule(
        rule_id="cisco_license_stateful_firewall",
        vendor="cisco",
        select=lambda name, info: NS_CISCO_ZONE in info.namespaces or name == "get_security_status",
        decide=_cisco_license_rule("stateful_firewall", " Stateful Firewall "),
    ),
    ExceptionRule(
        rule_id="cisco_license_ipsec_vpn",
        vendor="cisco",
        select=lambda name, info: NS_CISCO_CRYPTO in info.namespaces or name == "get_security_tunnel_information",
        decide=_cisco_license_rule("ipsec_vpn", " IPsec VPN "),
    ),
    ExceptionRule(
        rule_id="cisco_platform_no_vlan",
        vendor="cisco",
        select=lambda name, info: name in CISCO_VLAN_COMMANDS,
        decide=_cisco_vlan_rule,
    ),
    ExceptionRule(
        rule_id="cisco_switch_no_tunnel_ipsec",
        vendor="cisco",
        select=lambda name, info: NS_CISCO_CRYPTO in info.namespaces and name not in CISCO_TUNNEL_COMMANDS_FOR_GRE,
        decide=_cisco_no_tunnel_ipsec_rule,
    ),
    ExceptionRule(
        rule_id="juniper_model_no_switching",
        vendor="juniper",
        select=lambda name, info: "ethernet-switching" in info.markers,
        decide=_juniper_model_rule,
    ),
)


# กฎระดับค่าพารามิเตอร์: คำสั่งยังใช้ได้ แต่บางค่าอุปกรณ์ทำไม่ได้ - ไม่ถูกซ่อนจาก /commands
# หน้าเว็บซ่อนเฉพาะตัวเลือกนั้น และ API ปฏิเสธเมื่อส่งค่านั้นมา
@dataclass(frozen=True)
class ParameterRule:
    rule_id: str
    vendor: str
    function: str
    parameter: str
    values: frozenset
    decide: Callable[[dict], str | None]


PARAMETER_RULES = (
    ParameterRule(
        rule_id="cisco_switch_no_tunnel_ipsec_option",
        vendor="cisco",
        function="create_security_tunnel",
        parameter="tunnel_type",
        values=frozenset({"ipsec"}),
        decide=_cisco_no_tunnel_ipsec_rule,
    ),
)


# ---------------------------------------------------------------------------
# resolver
# ---------------------------------------------------------------------------

def resolve(vendor: str, profile: dict | None) -> dict:
    """ผลตัดสินต่อคำสั่ง: hidden = {คำสั่ง: [เหตุผล]} ครอบคำสั่งใน PUBLIC_FUNCTIONS รวม composite
    hidden_options = {คำสั่ง: {พารามิเตอร์: {ค่า: [เหตุผล]}}} สำหรับคำสั่งที่ใช้ได้แต่บางค่าทำไม่ได้
    known = False เมื่อไม่มีโปรไฟล์หรือโปรไฟล์เป็นของยี่ห้ออื่น (ไม่ซ่อนอะไรเลย)"""
    decision = {"vendor": vendor, "known": False, "platform_role": None,
                "hidden": {}, "hidden_options": {}, "skipped_layers": []}
    if not isinstance(profile, dict):
        return decision
    # โปรไฟล์ของยี่ห้ออื่นจะทำให้ namespace ไม่ตรงทั้งหมดและซ่อนทุกคำสั่ง
    if profile.get("vendor") not in (None, vendor):
        return decision
    functions = function_map(vendor)
    if not functions:
        return decision
    decision["known"] = True
    decision["platform_role"] = _platform_role(vendor, profile)

    hidden: dict[str, list[str]] = {}
    schema = profile.get("schema") or {}
    if schema.get("status") == "ok" and schema.get("namespaces"):
        device_namespaces = set(schema["namespaces"])
        for name, info in functions.items():
            missing = sorted(info.namespaces - device_namespaces)
            if missing:
                modules = ", ".join(_short_namespace(namespace) for namespace in missing)
                hidden.setdefault(name, []).append(f"Device lacks YANG module {modules}")
    else:
        decision["skipped_layers"].append("schema")

    if (profile.get("license") or {}).get("status") not in ("ok", "not_configured") and vendor == "cisco":
        decision["skipped_layers"].append("license")
    if (profile.get("model") or {}).get("status") != "ok" and vendor == "juniper":
        decision["skipped_layers"].append("model")

    for rule in EXCEPTION_RULES:
        if rule.vendor != vendor:
            continue
        reason = rule.decide(profile)
        if not reason:
            continue
        for name, info in functions.items():
            if rule.select(name, info) and reason not in hidden.get(name, []):
                hidden.setdefault(name, []).append(reason)

    platform_role = decision["platform_role"]
    if vendor == "cisco" and platform_role == "router":
        reason = "Cisco routers do not use ip routing toggle or ip default-gateway"
        for name in CISCO_SWITCH_ROUTE_MODE_COMMANDS:
            if name in functions:
                hidden.setdefault(name, []).append(reason)
    elif vendor == "cisco" and platform_role == "switch":
        # c9000 ใช้คำสั่งชุดนี้ได้จริง แม้ schema resolver บางรุ่นจะซ่อน node
        # ตาม feature จึงให้ผลจำแนก platform ที่เจาะจงกว่าชนะเหตุผลระดับ schema
        for name in CISCO_SWITCH_ROUTE_MODE_COMMANDS:
            hidden.pop(name, None)

    # คำสั่งที่ถูกซ่อนทั้งคำสั่งแล้วไม่ต้องมีกฎระดับค่า
    hidden_options: dict[str, dict[str, dict[str, list[str]]]] = {}
    for rule in PARAMETER_RULES:
        if rule.vendor != vendor or rule.function not in functions or rule.function in hidden:
            continue
        reason = rule.decide(profile)
        if not reason:
            continue
        values = hidden_options.setdefault(rule.function, {}).setdefault(rule.parameter, {})
        for value in sorted(rule.values):
            values.setdefault(value, []).append(reason)

    decision["hidden"] = hidden
    decision["hidden_options"] = hidden_options
    return decision


def filter_commands(vendor: str, profile: dict | None, commands: list[dict]) -> list[dict]:
    """กรองผลของ functions_for_vendor (ใช้ในขั้นที่ 4) - ถ้ากรองแล้วว่างทั้งที่มีคำสั่ง
    คืนรายการเดิมตามหลักข้อ 3 เพราะแปลว่าโปรไฟล์ผิดปกติมากกว่าอุปกรณ์ทำอะไรไม่ได้เลย"""
    hidden = resolve(vendor, profile)["hidden"]
    kept = [command for command in commands if command.get("name") not in hidden]
    return kept if kept or not commands else list(commands)


def blocked_reason(
    vendor: str, profile: dict | None, function_name: str, parameters: dict | None = None
) -> str | None:
    """เหตุผลที่ต้องปฏิเสธคำสั่งเขียน (ใช้ในขั้นที่ 4) - คำสั่งอ่านคืน None เสมอตามหลักข้อ 2
    ตรวจทั้งคำสั่งที่ถูกซ่อนและค่าพารามิเตอร์ที่ถูกห้าม (เช่น tunnel_type=ipsec บน c9000)"""
    if function_name.startswith("get_"):
        return None
    decision = resolve(vendor, profile)
    reasons = list(decision["hidden"].get(function_name) or [])
    if not reasons and isinstance(parameters, dict):
        for parameter, denied in decision["hidden_options"].get(function_name, {}).items():
            value = parameters.get(parameter)
            if value is not None and str(value) in denied:
                reasons.extend(denied[str(value)])
    return "; ".join(reasons) if reasons else None
