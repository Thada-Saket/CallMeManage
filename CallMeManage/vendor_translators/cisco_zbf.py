"""Authoritative Cisco Zone-Based Firewall (ZBF) reference graph, revision
(fingerprint) computation, and live safety guards for Edit/Delete.

พอร์ตตรรกะการเดิน reference chain มาจาก
`frontend/cloud_management/src/components/cmdGroups/firewall/ciscoZbfParser.js`
(ดู tests/test_cisco_zbf_parser_parity.py สำหรับ parity test ระหว่างสองฝั่ง) - โมดูล
นี้ทำงานบน raw NETCONF XML โดยตรง (ไม่ใช่ normalized JSON) เพื่อให้ revision hash
ครอบคลุมทุก field รวม Brownfield field ที่ระบบไม่รู้จัก และไม่ขึ้นกับการ
normalize_generic ที่อาจสูญเสียรายละเอียดบางอย่างไปกับการแปลง JSON

ห้ามเชื่อ editable/sharedObjects/revision ที่ frontend ส่งมา - โมดูลนี้คือแหล่งความ
จริงเดียว (authoritative) ที่ backend ต้องอ่าน running config สดแล้วคำนวณเองใหม่ทุก
ครั้งก่อน Edit/Delete/ACL mutation ภายใน DeviceLock เดียวกับที่อ่าน+เขียน
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import re
from xml.etree import ElementTree as ET
from tools.safe_xml import safe_fromstring
from xml.sax.saxutils import escape

# --- Writer v2 (Application support, 2026-09) NETCONF namespaces --------------
# ซ้ำกับค่าคงที่ใน vendor_translators/cisco_iosxe.py โดยตั้งใจ (เหมือนที่
# juniper_security_policy.py มี NS ของตัวเองแยกจาก juniper_junos.py) - โมดูลนี้ต้อง
# import ได้อิสระโดยไม่ต้อง import cisco_iosxe.py กลับ (กัน circular import เพราะ
# cisco_iosxe.py เป็นฝ่าย import จากโมดูลนี้)
NS_RPC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NS_NATIVE = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
NS_ZONE = "http://cisco.com/ns/yang/Cisco-IOS-XE-zone"
NS_POLICY = "http://cisco.com/ns/yang/Cisco-IOS-XE-policy"
NS_ACL = "http://cisco.com/ns/yang/Cisco-IOS-XE-acl"

KNOWN_MATCH_KEYS = {"access-group", "protocol", "class-map"}
MAX_NESTED_CLASS_MAP_DEPTH = 8
KNOWN_CLASS_ENTRY_KEYS = {"name", "type", "policy"}
KNOWN_POLICY_ACTION_KEYS = {"action", "log", "parameter-map"}


class CiscoZbfError(ValueError):
    """Structured error สำหรับ guard ทุกจุดในไฟล์นี้ - device_router.py map เป็น
    HTTPException ตาม status_code/code/identity/object_kind/object_name/shared_with"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        identity: dict | None = None,
        object_kind: str | None = None,
        object_name: str | None = None,
        shared_with: list[str] | None = None,
        source_zone: str | None = None,
        destination_zone: str | None = None,
        existing_zone_pair: str | None = None,
        references: dict | None = None,
    ):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status_code = status_code
        self.identity = identity or {}
        self.object_kind = object_kind
        self.object_name = object_name
        self.shared_with = shared_with or []
        self.source_zone = source_zone
        self.destination_zone = destination_zone
        self.existing_zone_pair = existing_zone_pair
        self.references = references

    def to_dict(self) -> dict:
        d: dict = {"code": self.code, "message": self.message}
        if self.identity:
            d["identity"] = self.identity
        if self.object_kind:
            d["objectKind"] = self.object_kind
        if self.object_name:
            d["objectName"] = self.object_name
        if self.shared_with:
            d["sharedWith"] = self.shared_with
        if self.source_zone is not None:
            d["sourceZone"] = self.source_zone
        if self.destination_zone is not None:
            d["destinationZone"] = self.destination_zone
        if self.existing_zone_pair is not None:
            d["existingZonePair"] = self.existing_zone_pair
        if self.references is not None:
            d["references"] = self.references
        return d


# ---------------------------------------------------------------------------
# XML helpers (local-name based - ไม่สนใจ namespace prefix ตรงกับ pattern เดียวกับ
# vendor_translators/juniper_security_policy.py::_local_name)
# ---------------------------------------------------------------------------

def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _children_by_local_name(el: ET.Element | None, name: str) -> list[ET.Element]:
    if el is None:
        return []
    return [c for c in el if isinstance(c.tag, str) and _local_name(c.tag) == name]


def _child_by_local_name(el: ET.Element | None, name: str) -> ET.Element | None:
    children = _children_by_local_name(el, name)
    return children[0] if children else None


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def _child_text(el: ET.Element | None, name: str) -> str:
    return _text(_child_by_local_name(el, name))


def _find_by_local_name(root: ET.Element, name: str) -> ET.Element | None:
    for el in root.iter():
        if isinstance(el.tag, str) and _local_name(el.tag) == name:
            return el
    return None


def parse_cisco_zbf_reference(reply: str) -> ET.Element | None:
    """ยืนยันว่าอ่าน Cisco ZBF configuration จากอุปกรณ์สำเร็จก่อนนำไปคำนวณ safety
    guard ใดๆ - ถ้าอุปกรณ์ตอบ rpc-error หรือ XML เสียต้องหยุดทันที ห้ามตีความเป็น
    "ไม่มี Policy" แล้วปล่อยให้เขียนทับแบบไม่มีการป้องกัน คืน None เมื่อไม่มี
    <native> เลย (สถานะว่างที่ถูกต้อง - อุปกรณ์ไม่มี ZBF object ใดเลย)"""
    try:
        root = safe_fromstring(reply)
    except (ET.ParseError, TypeError) as exc:
        raise CiscoZbfError(
            "CISCO_ZBF_READ_FAILED",
            f"Failed to read Cisco ZBF configuration from device (invalid XML: {exc})",
            status_code=502,
        )
    for error_el in root.iter():
        if not isinstance(error_el.tag, str) or _local_name(error_el.tag) != "rpc-error":
            continue
        severity = _child_text(error_el, "error-severity") or "error"
        if severity.strip().lower() == "warning":
            continue
        message = _child_text(error_el, "error-message")
        raise CiscoZbfError(
            "CISCO_ZBF_READ_FAILED",
            "Device rejected reading Cisco ZBF configuration" + (f": {message}" if message else ""),
            status_code=502,
        )
    return _find_by_local_name(root, "native")


# ---------------------------------------------------------------------------
# Canonicalization + revision (mirror juniper_security_policy.compute_policy_fingerprint)
# ---------------------------------------------------------------------------

def _canon_element(el: ET.Element):
    tag = _local_name(el.tag)
    text = (el.text or "").strip()
    attrs = tuple(
        sorted(
            (_local_name(k), v.strip())
            for k, v in el.attrib.items()
            if not k.startswith("xmlns") and _local_name(k) != "operation"
        )
    )
    children = tuple(
        _canon_element(c)
        for c in el
        if isinstance(c.tag, str) and not c.tag.startswith("{http://www.w3.org/")
    )
    return (tag, text, attrs, children)


def compute_cisco_zbf_revision_from_policy(policy: dict, reachability: dict) -> str:
    """คำนวณ sha256 revision ของ Zone Pair หนึ่งตัว ครอบคลุม: zone-pair element
    ทั้งก้อน, policy-map ที่อ้างถึง, ทุก class-map ที่ reachable (รวม nested), ทุก
    ACL ที่ reachable, และรายชื่อ Zone Pair owner ของแต่ละ object ที่ reachable
    (object ที่ไม่เกี่ยวกับ Policy นี้ไม่ถูกรวมเข้ามาเลย จึงไม่ทำให้ revision เปลี่ยน
    เมื่อ Zone Pair/object อื่นถูกแก้ - แต่ถ้ามี Zone Pair อื่นมาแชร์ object เดียวกัน
    owner list ของ object นั้นจะเปลี่ยน -> revision เปลี่ยนตาม)"""
    parts = [_canon_element(policy["zone_pair_element"])]
    if policy["policy_map_element"] is not None:
        parts.append(_canon_element(policy["policy_map_element"]))
    # ลำดับของ collection ที่ไม่มี semantic order (class-map/ACL ที่ reachable ไม่ใช่
    # child ตามลำดับของ policy-map/zone-pair) - sort ตามชื่อให้ deterministic เสมอ
    class_map_els = sorted(policy["reachable_class_map_elements"], key=lambda e: _child_text(e, "name"))
    for el in class_map_els:
        parts.append(_canon_element(el))
    acl_els = sorted(policy["reachable_acl_elements"], key=lambda e: _child_text(e, "name"))
    for el in acl_els:
        parts.append(_canon_element(el))
    reached_keys = set(policy["reached_objects"])
    owners_repr = tuple(
        sorted(
            (kind, name, tuple(sorted(owners)))
            for (kind, name), owners in reachability.items()
            if (kind, name) in reached_keys
        )
    )
    combined = (policy["name"], tuple(parts), owners_repr)
    raw_hash = hashlib.sha256(repr(combined).encode("utf-8")).hexdigest()[:32]
    return f"sha256:{raw_hash}"


def compute_cisco_acl_revision(acl_el: ET.Element) -> str:
    """Fingerprint ของ ACL หนึ่งตัว (ทุก ACE/sequence/field) - ใช้กัน Edit/Delete
    ผ่านหน้า Stateless ACL ด้วยหน้าจอ/ข้อมูลเก่า (ดู resolve_cisco_acl_safe_mutation)"""
    raw_hash = hashlib.sha256(repr(_canon_element(acl_el)).encode("utf-8")).hexdigest()[:32]
    return f"sha256:{raw_hash}"


def _valid_revision_set(current: str) -> set[str]:
    return {current, current.replace("sha256:", ""), current[:23]}


# ---------------------------------------------------------------------------
# Indexing (ชื่อจริงเท่านั้น - ห้าม join ด้วยชื่อที่เดา เช่น FW_<name>)
# ---------------------------------------------------------------------------

def _index_by(elements: list[ET.Element], name_tag: str = "name") -> tuple[dict, set]:
    by_name: dict[str, ET.Element] = {}
    duplicates: set[str] = set()
    for el in elements:
        name = _child_text(el, name_tag)
        if not name:
            continue
        if name in by_name:
            duplicates.add(name)
        else:
            by_name[name] = el
    return by_name, duplicates


def _build_indexes(native: ET.Element | None) -> dict:
    zone_el = _child_by_local_name(native, "zone")
    zone_pair_el = _child_by_local_name(native, "zone-pair")
    policy_el = _child_by_local_name(native, "policy")
    ip_el = _child_by_local_name(native, "ip")
    access_list_el = _child_by_local_name(ip_el, "access-list")
    interface_el = _child_by_local_name(native, "interface")

    zones = _children_by_local_name(zone_el, "security")
    zone_pairs = _children_by_local_name(zone_pair_el, "security")
    policy_maps = _children_by_local_name(policy_el, "policy-map")
    class_maps = _children_by_local_name(policy_el, "class-map")
    acls = _children_by_local_name(access_list_el, "extended") + _children_by_local_name(access_list_el, "standard")

    members_by_zone: dict[str, list[str]] = {}
    if interface_el is not None:
        for iface_el in interface_el:
            if not isinstance(iface_el.tag, str):
                continue
            iface_type = _local_name(iface_el.tag)
            iface_name = _child_text(iface_el, "name")
            zone_member_el = _child_by_local_name(iface_el, "zone-member")
            zone_name = _child_text(zone_member_el, "security") if zone_member_el is not None else ""
            if zone_name and iface_name:
                members_by_zone.setdefault(zone_name, []).append(f"{iface_type}{iface_name}")

    return {
        "zone_index": _index_by(zones, "id"),
        "zone_pairs": zone_pairs,
        "zone_pair_index": _index_by(zone_pairs, "id"),
        "policy_map_index": _index_by(policy_maps, "name"),
        "class_map_index": _index_by(class_maps, "name"),
        "acl_index": _index_by(acls, "name"),
        "members_by_zone": members_by_zone,
    }


# ---------------------------------------------------------------------------
# ACL parsing (mirror ciscoZbfParser.js parseAclDetail)
# ---------------------------------------------------------------------------

def _wildcard_to_prefix(mask: str) -> int | None:
    parts = (mask or "").split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in octets):
        return None
    bits = "".join(format(255 - n, "08b") for n in octets)
    if not re.fullmatch(r"1*0*", bits):
        return None
    idx = bits.find("0")
    return 32 if idx == -1 else idx


def _parse_acl_detail(acl_el: ET.Element) -> dict:
    entries = []
    scopes = []
    details = []
    for seq_rule_el in _children_by_local_name(acl_el, "access-list-seq-rule"):
        sequence = _child_text(seq_rule_el, "sequence") or "?"
        ace_el = _child_by_local_name(seq_rule_el, "ace-rule")
        ace: dict[str, str] = {}
        if ace_el is not None:
            for child in ace_el:
                if isinstance(child.tag, str):
                    ace[_local_name(child.tag)] = (child.text or "").strip()
        entries.append({
            "sequence": sequence,
            "action": ace.get("action", ""),
            "protocol": ace.get("protocol", ""),
            "log": "log" in ace,
        })
        if ace.get("action") != "permit" or ace.get("protocol") != "ip" or "dst-any" not in ace:
            details.append(f"sequence {sequence}: only permit ip <source> any is supported")
            continue
        if "any" in ace:
            scopes.append("any")
        elif ace.get("host-address"):
            scopes.append(ace["host-address"] + "/32")
        elif ace.get("ipv4-address") and ace.get("mask"):
            prefix = _wildcard_to_prefix(ace["mask"])
            if prefix is None:
                details.append(f"sequence {sequence}: non-contiguous wildcard mask")
            else:
                scopes.append(f'{ace["ipv4-address"]}/{prefix}')
        else:
            details.append(f"sequence {sequence}: source address is not in a form maintainable by the form")
    if scopes.count("any") and len(scopes) > 1:
        details.append("ACL contains 'any' mixed with other scopes, which cannot be preserved by the form")
    readable = len(details) == 0 and len(scopes) > 0
    return {"readable": readable, "scopes": scopes, "details": details, "entries": entries}


def _resolve_class_map(name: str, class_map_index: tuple[dict, set]):
    by_name, dup = class_map_index
    if name in dup:
        return None, None, f'Class Map "{name}" has more than 1 entry on device (ambiguous)'
    cm = by_name.get(name)
    if cm is None:
        return None, None, f'Class Map "{name}" not found on device'
    cm_type = _child_text(cm, "type")
    if cm_type != "inspect":
        return None, None, f'Class Map "{name}" is not type inspect (found type="{cm_type or "-"}") and therefore not Zone-Based Firewall'
    return cm, cm_type, None


def _resolve_acl(name: str, acl_index: tuple[dict, set]):
    by_name, dup = acl_index
    if name in dup:
        return None, f'ACL "{name}" has more than 1 entry on device (ambiguous)'
    acl = by_name.get(name)
    if acl is None:
        return None, f'ACL "{name}" not found on device'
    return acl, None


def _walk_class_map(name: str, class_map_index, acl_index, visited_path: list[str]) -> dict:
    chain_reasons: list[str] = []
    unsupported_reasons: list[str] = []

    def empty_result():
        return {
            "class_map_model": None, "acls": [],
            "chain_reasons": chain_reasons, "unsupported_reasons": unsupported_reasons,
            "reachable_class_map_elements": [], "reachable_acl_elements": [],
        }

    if name in visited_path:
        chain_reasons.append(f'Circular reference (cycle) detected in Class Map: {" → ".join([*visited_path, name])}')
        return empty_result()
    if len(visited_path) >= MAX_NESTED_CLASS_MAP_DEPTH:
        chain_reasons.append(f'Class Map nesting depth exceeds {MAX_NESTED_CLASS_MAP_DEPTH} levels ("{name}") and is not supported')
        return empty_result()

    cm_el, cm_type, reason = _resolve_class_map(name, class_map_index)
    if cm_el is None:
        chain_reasons.append(reason)
        return empty_result()

    reachable_class_map_els = [cm_el]
    match_el = _child_by_local_name(cm_el, "match")
    acl_names: list[str] = []
    protocols: list[str] = []
    nested_names: list[str] = []
    unknown_match_keys: list[str] = []
    if match_el is not None:
        ag_el = _child_by_local_name(match_el, "access-group")
        if ag_el is not None:
            for n_el in _children_by_local_name(ag_el, "name"):
                if (n_el.text or "").strip():
                    acl_names.append(n_el.text.strip())
        proto_el = _child_by_local_name(match_el, "protocol")
        if proto_el is not None:
            for pl_el in _children_by_local_name(proto_el, "protocols-list"):
                p_text = _child_text(pl_el, "protocols")
                if p_text:
                    protocols.append(p_text)
        for cm_ref_el in _children_by_local_name(match_el, "class-map"):
            if (cm_ref_el.text or "").strip():
                nested_names.append(cm_ref_el.text.strip())
        for child in match_el:
            if isinstance(child.tag, str):
                tag = _local_name(child.tag)
                if tag not in KNOWN_MATCH_KEYS:
                    unknown_match_keys.append(tag)

    if unknown_match_keys:
        unsupported_reasons.append(f'Class Map "{name}" has unsupported match types: {", ".join(unknown_match_keys)}')
    # หมายเหตุ (2026-09): protocol/nested class-map ไม่ใช่ "unsupported" เสมอไปอีกแล้ว
    # ตั้งแต่ Writer v2 รองรับ Application (Any/Single/Multiple topology) - การจะถือว่า
    # เป็นรูปแบบที่ Writer จัดการได้หรือไม่ต้องดูทั้ง Policy Map Class (ไม่ใช่แค่
    # Class Map เดี่ยวๆ) จึงย้ายไปตัดสินที่ _classify_cisco_zbf_writer_topology() +
    # _compute_editable() แทน (ใส่เหตุผลเฉพาะเมื่อจำแนก topology ไม่ได้จริงๆ)

    acls = []
    reachable_acl_els: list[ET.Element] = []
    for acl_name in acl_names:
        acl_el, reason = _resolve_acl(acl_name, acl_index)
        if acl_el is None:
            chain_reasons.append(f'Class Map "{name}" references ACL "{acl_name}" but {reason}')
            continue
        reachable_acl_els.append(acl_el)
        parsed = _parse_acl_detail(acl_el)
        acls.append({"name": acl_name, "acl_element": acl_el, **parsed})
        if not parsed["readable"]:
            unsupported_reasons.extend(f'ACL "{acl_name}" (via Class Map "{name}"): {d}' for d in parsed["details"])

    nested_results = []
    nested_path = [*visited_path, name]
    for nested_name in nested_names:
        result = _walk_class_map(nested_name, class_map_index, acl_index, nested_path)
        nested_results.append(result)
        chain_reasons.extend(f'(nested "{nested_name}" of "{name}") {r}' for r in result["chain_reasons"])
        unsupported_reasons.extend(f'(nested "{nested_name}" of "{name}") {r}' for r in result["unsupported_reasons"])
        reachable_class_map_els.extend(result["reachable_class_map_elements"])
        reachable_acl_els.extend(result["reachable_acl_elements"])

    class_map_model = {
        "name": name,
        "type": cm_type or "",
        "prematch": _child_text(cm_el, "prematch"),
        "acl_names": acl_names,
        "protocols": protocols,
        "nested_class_map_names": nested_names,
        "nested_class_maps": [r["class_map_model"] for r in nested_results if r["class_map_model"]],
        "unknown_match_keys": unknown_match_keys,
        "class_map_element": cm_el,
    }
    return {
        "class_map_model": class_map_model,
        "acls": acls,
        "chain_reasons": chain_reasons,
        "unsupported_reasons": unsupported_reasons,
        "reachable_class_map_elements": reachable_class_map_els,
        "reachable_acl_elements": reachable_acl_els,
    }


def _build_class_model(class_entry_el: ET.Element, class_map_index, acl_index) -> dict:
    raw_name = _child_text(class_entry_el, "name")
    is_class_default = raw_name == "class-default"
    policy_block_el = _child_by_local_name(class_entry_el, "policy")
    action = _child_text(policy_block_el, "action") if policy_block_el is not None else ""
    action = action or None
    log = policy_block_el is not None and _child_by_local_name(policy_block_el, "log") is not None
    parameter_map_el = _child_by_local_name(policy_block_el, "parameter-map") if policy_block_el is not None else None
    parameter_map = _text(parameter_map_el) or None if parameter_map_el is not None else None

    unknown_class_keys = [
        _local_name(c.tag) for c in class_entry_el
        if isinstance(c.tag, str) and _local_name(c.tag) not in KNOWN_CLASS_ENTRY_KEYS
    ]
    unknown_policy_keys = [
        _local_name(c.tag) for c in policy_block_el
        if isinstance(c.tag, str) and _local_name(c.tag) not in KNOWN_POLICY_ACTION_KEYS
    ] if policy_block_el is not None else []

    chain_reasons: list[str] = []
    unsupported_reasons: list[str] = []
    label = raw_name or "(unnamed)"
    for k in unknown_class_keys:
        unsupported_reasons.append(f'Policy Map Class "{label}" has unsupported field: {k}')
    for k in unknown_policy_keys:
        unsupported_reasons.append(f'Policy Map Class "{label}" has unsupported policy field: {k}')
    if parameter_map:
        unsupported_reasons.append(f'Policy Map Class "{raw_name}" has parameter-map ("{parameter_map}") which is not supported by the current form')

    class_map_model = None
    acls: list[dict] = []
    reachable_class_map_els: list[ET.Element] = []
    reachable_acl_els: list[ET.Element] = []
    if not is_class_default:
        if not raw_name:
            chain_reasons.append("Found non-default class without name (empty name)")
        else:
            walked = _walk_class_map(raw_name, class_map_index, acl_index, [])
            class_map_model = walked["class_map_model"]
            acls = walked["acls"]
            chain_reasons.extend(walked["chain_reasons"])
            unsupported_reasons.extend(walked["unsupported_reasons"])
            reachable_class_map_els = walked["reachable_class_map_elements"]
            reachable_acl_els = walked["reachable_acl_elements"]
            entry_type = _child_text(class_entry_el, "type")
            if entry_type and class_map_model and entry_type != class_map_model["type"]:
                chain_reasons.append(
                    f'Policy Map Class "{raw_name}" specifies type="{entry_type}" but actual Class Map is type="{class_map_model["type"]}"'
                )

    return {
        "name": raw_name or ("class-default" if is_class_default else ""),
        "is_class_default": is_class_default,
        "type": None if is_class_default else (_child_text(class_entry_el, "type") or None),
        "action": action,
        "log": log,
        "parameter_map": parameter_map,
        "class_map_name": None if is_class_default else (raw_name or None),
        "class_map": class_map_model,
        "acls": acls,
        "unknown_class_keys": unknown_class_keys,
        "unknown_policy_keys": unknown_policy_keys,
        "chain_reasons": chain_reasons,
        "unsupported_reasons": unsupported_reasons,
        "reachable_class_map_elements": reachable_class_map_els,
        "reachable_acl_elements": reachable_acl_els,
    }


def _build_raw_policy(zone_pair_el: ET.Element, indexes: dict) -> dict:
    chain_reasons: list[str] = []
    unsupported_reasons: list[str] = []
    name = _child_text(zone_pair_el, "id")
    source = _child_text(zone_pair_el, "source")
    destination = _child_text(zone_pair_el, "destination")
    reached_objects: list[tuple[str, str]] = []

    _, zp_dup = indexes["zone_pair_index"]
    if name and name in zp_dup:
        chain_reasons.append(f'Zone Pair "{name}" has more than 1 entry on device (ambiguous)')

    service_policy_el = _child_by_local_name(zone_pair_el, "service-policy")
    type_el = _child_by_local_name(service_policy_el, "type") if service_policy_el is not None else None
    policy_map_name = _child_text(type_el, "inspect") if type_el is not None else ""

    policy_map_el = None
    if not policy_map_name:
        chain_reasons.append(f'Zone Pair "{name}" has no service-policy type inspect attached')
    else:
        pm_by_name, pm_dup = indexes["policy_map_index"]
        if policy_map_name in pm_dup:
            chain_reasons.append(f'Policy Map "{policy_map_name}" has more than 1 entry on device (ambiguous)')
        else:
            policy_map_el = pm_by_name.get(policy_map_name)
            if policy_map_el is None:
                chain_reasons.append(f'Zone Pair "{name}" references Policy Map "{policy_map_name}" but this Policy Map was not found on device')
            else:
                reached_objects.append(("policy-map", policy_map_name))
                pm_type = _child_text(policy_map_el, "type")
                if pm_type and pm_type != "inspect":
                    chain_reasons.append(f'Policy Map "{policy_map_name}" is not type inspect (type="{pm_type}")')

    class_entries = _children_by_local_name(policy_map_el, "class") if policy_map_el is not None else []
    if policy_map_el is not None and not class_entries:
        chain_reasons.append(f'Policy Map "{policy_map_name}" has no classes')

    classes = [_build_class_model(entry, indexes["class_map_index"], indexes["acl_index"]) for entry in class_entries]
    reachable_class_map_elements: list[ET.Element] = []
    reachable_acl_elements: list[ET.Element] = []
    for cls in classes:
        chain_reasons.extend(cls["chain_reasons"])
        unsupported_reasons.extend(cls["unsupported_reasons"])
        if cls["class_map_name"]:
            reached_objects.append(("class-map", cls["class_map_name"]))
        # ใช้ reachable_acl_elements (ไม่ใช่ cls["acls"]) เพราะรวม ACL ที่ถูกอ้างผ่าน
        # nested Class Map ด้วย - ACL ที่ ZBF ใช้งานผ่านทางอ้อมแบบนี้ต้องนับเป็น
        # "in use"/"shared" เหมือนกับที่ถูกอ้างตรงๆ (ดู resolve_cisco_acl_mutation_guard)
        for acl_el in cls["reachable_acl_elements"]:
            acl_name = _child_text(acl_el, "name")
            if acl_name:
                reached_objects.append(("acl", acl_name))
        reachable_class_map_elements.extend(cls["reachable_class_map_elements"])
        reachable_acl_elements.extend(cls["reachable_acl_elements"])

        def _collect_nested(cm):
            if not cm:
                return
            for nested_name in cm.get("nested_class_map_names", []):
                reached_objects.append(("class-map", nested_name))
            for nested in cm.get("nested_class_maps", []):
                _collect_nested(nested)

        _collect_nested(cls["class_map"])

    class_default = next((c for c in classes if c["is_class_default"]), None)
    non_default_classes = [c for c in classes if not c["is_class_default"]]

    return {
        "name": name,
        "source": source,
        "destination": destination,
        "policy_map_name": policy_map_name or None,
        "policy_map_element": policy_map_el,
        "zone_pair_element": zone_pair_el,
        "classes": classes,
        "class_default": class_default,
        "non_default_classes": non_default_classes,
        "chain_reasons": chain_reasons,
        "unsupported_reasons": unsupported_reasons,
        "reached_objects": reached_objects,
        "reachable_class_map_elements": reachable_class_map_elements,
        "reachable_acl_elements": reachable_acl_elements,
        "source_members": indexes["members_by_zone"].get(source, []),
        "destination_members": indexes["members_by_zone"].get(destination, []),
    }


CISCO_ZBF_APP_CLASS_SUFFIX = "_APP"


def _class_map_has_no_unknown(cm: dict | None) -> bool:
    return bool(cm) and not cm.get("unknown_match_keys")


def _class_entry_has_no_unknown(cls: dict) -> bool:
    return not cls.get("unknown_class_keys") and not cls.get("unknown_policy_keys")


def _acls_are_writer_clean(cls: dict) -> bool:
    """ACL ที่ class นี้อ้างตรงๆ (ไม่รวม nested) ต้องอ่านได้สะอาดทุกตัว (ACE ทุกอันเป็น
    permit ip <source> any ที่ Writer สร้างได้พอดี) และมีอย่างน้อย 1 ตัว"""
    return len(cls["acls"]) >= 1 and all(a["readable"] for a in cls["acls"])


def _classify_cisco_zbf_writer_topology(raw: dict) -> dict | None:
    """จำแนกว่า Policy นี้ตรงกับรูปแบบที่ Writer (เก่าหรือใหม่) สร้าง/แก้ได้อย่าง
    ปลอดภัยเป๊ะหรือไม่ (round-trip ได้โดยไม่เสียข้อมูล เพราะไม่มี field อื่นให้เสีย) -
    คืน None เมื่อเป็น Brownfield ที่ยังพิสูจน์ไม่ได้ (ใช้ "จำแนกรูปแบบ" เท่านั้น ห้าม
    ใช้เป็น join/lookup key - ดูหมายเหตุใน ciscoZbfParser.js)

    - legacy: 1 non-default class, ACL-only (match-any), ไม่มี class-default ชัดเจน -
      รูปแบบเดิมก่อนงาน Applications (2026-09)
    - v2/any, v2/single, v2/multiple: รูปแบบใหม่ที่ create_firewall_policy() (Writer
      v2) สร้างเอง - match-all เสมอ มี explicit class-default action=drop เสมอ"""
    if len(raw["non_default_classes"]) != 1:
        return None
    expected_base = f'FW_{raw["name"]}'
    expected_app = f'{expected_base}{CISCO_ZBF_APP_CLASS_SUFFIX}'
    cls = raw["non_default_classes"][0]

    if raw["policy_map_name"] != expected_base:
        return None
    if cls["class_map_name"] != expected_base:
        return None
    if not _class_entry_has_no_unknown(cls):
        return None
    cm = cls["class_map"]
    if not cm:
        return None
    if len(cls["acls"]) != 1 or cls["acls"][0]["name"] != expected_base:
        return None
    if not _acls_are_writer_clean(cls):
        return None

    names = {
        "zone_pair": raw["name"], "acl": expected_base,
        "outer_class_map": expected_base, "policy_map": expected_base,
        "inner_application_class_map": expected_app,
    }

    # --- legacy shape: match-any, ACL เดียว, ไม่มี protocol/nested, ไม่มี class-default ---
    if (
        cm["prematch"] == "match-any"
        and not cm["protocols"]
        and not cm["nested_class_map_names"]
        and _class_map_has_no_unknown(cm)
        and raw["class_default"] is None
    ):
        return {"writer_version": "legacy", "mode": "legacy", "names": names}

    # --- v2 shapes: match-all เสมอ + explicit class-default drop เป๊ะ ---
    if cm["prematch"] != "match-all" or not _class_map_has_no_unknown(cm):
        return None
    class_default = raw["class_default"]
    if (
        class_default is None
        or class_default["action"] != "drop"
        or class_default["log"]
        or class_default["parameter_map"]
        or class_default["unknown_class_keys"]
        or class_default["unknown_policy_keys"]
    ):
        return None

    if not cm["protocols"] and not cm["nested_class_map_names"]:
        return {"writer_version": "v2", "mode": "any", "names": names}

    if cm["protocols"] and not cm["nested_class_map_names"]:
        if len(cm["protocols"]) != 1:
            return None  # Outer ห้ามมีหลาย protocol ตรงๆ (ต้องผ่าน nested match-any)
        return {"writer_version": "v2", "mode": "single", "names": names}

    if cm["nested_class_map_names"] and not cm["protocols"]:
        if len(cm["nested_class_map_names"]) != 1 or cm["nested_class_map_names"][0] != expected_app:
            return None
        nested = cm["nested_class_maps"][0] if cm["nested_class_maps"] else None
        if not nested or nested["name"] != expected_app or nested["prematch"] != "match-any":
            return None
        if nested["acl_names"] or nested["nested_class_map_names"] or nested["unknown_match_keys"]:
            return None
        if not nested["protocols"]:
            return None
        return {"writer_version": "v2", "mode": "multiple", "names": names}

    return None  # มีทั้ง protocol ตรงๆ และ nested พร้อมกัน = ไม่ใช่รูปแบบที่ Writer สร้าง


def _compute_editable(raw: dict, topology: dict | None, shared_objects: list[dict]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if topology is None:
        reasons.append(
            "Object names (Policy Map/Class Map/ACL) or structure do not match the format that current "
            "Writer can safely modify (Brownfield)"
        )
        # ให้เหตุผลเจาะจงเพิ่มเติมเมื่อพอบอกได้ว่าอะไรทำให้จำแนก topology ไม่ได้ (ไม่ทำ
        # ให้ Class Map ที่มี protocol/nested ถูกตราหน้าว่า unsupported เสมอไปอีกต่อไป -
        # เฉพาะตอนไม่เข้ารูปแบบ Any/Single/Multiple ที่ Writer รองรับเท่านั้น)
        for cls in raw["non_default_classes"]:
            cm = cls.get("class_map")
            if not cm:
                continue
            if cm.get("protocols"):
                reasons.append(
                    f'Class Map "{cm["name"]}" has match protocol ("{", ".join(cm["protocols"])}") '
                    "in a format not currently supported by Writer"
                )
            if cm.get("nested_class_map_names"):
                reasons.append(
                    f'Class Map "{cm["name"]}" references nested Class Map '
                    f'({", ".join(cm["nested_class_map_names"])}) in a format not currently supported by Writer'
                )
        if raw["class_default"] and (
            len(raw["non_default_classes"]) != 1
            or raw["class_default"]["action"] != "drop"
            or raw["class_default"]["log"]
            or raw["class_default"]["parameter_map"]
            or raw["class_default"]["unknown_class_keys"]
            or raw["class_default"]["unknown_policy_keys"]
        ):
            reasons.append(
                "Policy Map has class-default configured differently than expected by Writer "
                "(action=drop, no log/parameter-map/other fields). Saving via this form might unintentionally delete/overwrite it"
            )
    if len(raw["non_default_classes"]) == 0:
        reasons.append("No usable classes found (excluding class-default)")
    elif len(raw["non_default_classes"]) > 1:
        reasons.append(
            f'Has more than 1 non-default class ({len(raw["non_default_classes"])} classes), '
            "whereas current form supports only 1 class"
        )
    for shared in shared_objects:
        kind_label = {"policy-map": "Policy Map", "class-map": "Class Map", "acl": "ACL"}.get(shared["kind"], shared["kind"])
        reasons.append(f'{kind_label} "{shared["name"]}" is shared with other Zone Pairs: {", ".join(shared["shared_with"])}')
    reasons.extend(raw["chain_reasons"])
    reasons.extend(raw["unsupported_reasons"])
    valid_actions = {"inspect", "pass", "drop"}
    if len(raw["non_default_classes"]) == 1:
        action = raw["non_default_classes"][0]["action"]
        if action is None:
            reasons.append("class has no action specified")
        elif action not in valid_actions:
            reasons.append(f'action "{action}" is not supported by current form')
    seen: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.append(r)
    return len(seen) == 0, seen


def _collect_protocols_from_class_map(cm: dict | None) -> list[str]:
    """ดึง protocols/applications ทั้งหมดจาก Class Map รวมถึง nested Class Maps
    รักษาลำดับการปรากฏครั้งแรก (insertion order) และตัดตัวซ้ำ"""
    if not cm:
        return []
    result = []
    seen = set()

    def _walk(curr: dict | None):
        if not curr:
            return
        for p in curr.get("protocols", []):
            if p and p not in seen:
                seen.add(p)
                result.append(p)
        for nested in curr.get("nested_class_maps", []):
            _walk(nested)

    _walk(cm)
    return result


def build_cisco_zbf_graph(native: ET.Element | None) -> dict:
    """สร้าง graph เต็มของอุปกรณ์: index ทุกชนิด object, เดิน reference ของทุก Zone
    Pair, และคำนวณ shared-object reachability ข้าม Zone Pair ทั้งหมด - เป็นจุดเดียว
    ที่ backend guard ทุกจุด (edit/delete/ACL mutation) ต้องเรียกผ่าน"""
    indexes = _build_indexes(native)
    raw_policies = [_build_raw_policy(zp, indexes) for zp in indexes["zone_pairs"]]

    reachability: dict[tuple[str, str], set[str]] = {}
    for raw in raw_policies:
        seen = set()
        for key in raw["reached_objects"]:
            if key in seen:
                continue
            seen.add(key)
            reachability.setdefault(key, set()).add(raw["name"])

    policies = []
    for raw in raw_policies:
        shared_objects = []
        seen = set()
        for kind, obj_name in raw["reached_objects"]:
            key = (kind, obj_name)
            if key in seen:
                continue
            seen.add(key)
            owners = reachability.get(key, set())
            if len(owners) > 1:
                shared_objects.append({
                    "kind": kind,
                    "name": obj_name,
                    "shared_with": sorted(o for o in owners if o != raw["name"]),
                })
        topology = _classify_cisco_zbf_writer_topology(raw)
        editable, reasons = _compute_editable(raw, topology, shared_objects)

        if topology is not None:
            topo_mode = topology["mode"]
            if topo_mode in ("legacy", "any"):
                app_mode = "any"
                apps = []
                apps_known = True
            elif topo_mode == "single":
                cm = raw["non_default_classes"][0]["class_map"]
                app_mode = "single"
                apps = list(cm.get("protocols", [])) if cm else []
                apps_known = True
            elif topo_mode == "multiple":
                cm = raw["non_default_classes"][0]["class_map"]
                nested = cm["nested_class_maps"][0] if cm and cm.get("nested_class_maps") else None
                app_mode = "multiple"
                apps = list(nested.get("protocols", [])) if nested else []
                apps_known = True
            else:
                app_mode = "unknown"
                apps = []
                apps_known = False
        else:
            if len(raw["chain_reasons"]) > 0 or len(raw["non_default_classes"]) != 1:
                app_mode = "unknown"
                apps = []
                apps_known = False
            else:
                cls = raw["non_default_classes"][0]
                cm = cls.get("class_map")
                if not cm:
                    app_mode = "unknown"
                    apps = []
                    apps_known = False
                elif cm.get("unknown_match_keys"):
                    app_mode = "unknown"
                    apps = _collect_protocols_from_class_map(cm)
                    apps_known = False
                elif len(cm.get("nested_class_map_names", [])) > len(cm.get("nested_class_maps", [])):
                    app_mode = "unknown"
                    apps = _collect_protocols_from_class_map(cm)
                    apps_known = False
                else:
                    collected = _collect_protocols_from_class_map(cm)
                    if not collected:
                        app_mode = "any"
                        apps = []
                        apps_known = True
                    elif len(collected) == 1:
                        app_mode = "single"
                        apps = collected
                        apps_known = True
                    else:
                        app_mode = "multiple"
                        apps = collected
                        apps_known = True

        blocking_errors = list(raw["chain_reasons"])
        if len(raw["non_default_classes"]) == 0:
            blocking_errors.append("No usable classes found (excluding class-default)")

        preserved_fields = []
        if topology is None:
            preserved_fields.append("Object names on device (Brownfield)")
        if len(raw["non_default_classes"]) > 1:
            other_classes = [c["name"] for c in raw["non_default_classes"][1:] if c.get("name")]
            preserved_fields.append(f"Additional classes in Policy Map: {', '.join(other_classes)}")
        if raw.get("class_default") is not None:
            preserved_fields.append("class-default configuration")
        for cls in raw["non_default_classes"]:
            cm = cls.get("class_map")
            if cm:
                for k in cm.get("unknown_match_keys", []):
                    preserved_fields.append(f"match {k}")
                if len(cm.get("nested_class_maps", [])) > 0 and topology is None:
                    preserved_fields.append("nested Class Maps")
        for unsupp in raw.get("unsupported_reasons", []):
            if unsupp not in preserved_fields:
                preserved_fields.append(unsupp)

        can_edit = len(blocking_errors) == 0
        can_delete = len(blocking_errors) == 0
        capabilities = {
            "can_edit": can_edit,
            "can_delete": can_delete,
            "can_open": can_edit,
            "can_modify_action": can_edit,
            "can_modify_source": can_edit,
            "can_modify_destination": can_edit,
            "can_modify_applications": can_edit,
            "can_modify_source_scopes": can_edit,
            "can_modify_log": can_edit,
        }

        policies.append({
            **raw,
            "shared_objects": shared_objects,
            "system_managed_shape": topology is not None,
            "writer_topology": topology,
            "editable": can_edit,
            "capabilities": capabilities,
            "blocking_errors": blocking_errors,
            "preserved_fields": preserved_fields,
            "read_only_reasons": blocking_errors,
            "chain_complete": len(raw["chain_reasons"]) == 0,
            "application_mode": app_mode,
            "applications": apps,
            "applications_known": apps_known,
        })
    return {"indexes": indexes, "policies": policies, "reachability": reachability}


def inspect_cisco_zbf_policy(reference_config: str, zone_pair_name: str) -> dict | None:
    """คืน policy dict (พร้อม revision) ของ Zone Pair ตัวเดียว หรือ None ถ้าไม่พบ -
    ใช้โดย get_firewall_information metadata endpoint และโดย resolver ด้านล่าง"""
    native = parse_cisco_zbf_reference(reference_config)
    graph = build_cisco_zbf_graph(native)
    policy = next((p for p in graph["policies"] if p["name"] == zone_pair_name), None)
    if policy is None:
        return None
    revision = compute_cisco_zbf_revision_from_policy(policy, graph["reachability"])
    return {**policy, "revision": revision}


def list_cisco_zbf_policies(reference_config: str) -> list[dict]:
    """คืน policy dict (พร้อม revision) ของทุก Zone Pair บนอุปกรณ์ - ใช้ประกอบ
    metadata ให้ frontend join กับ generic normalized payload ด้วยชื่อ Zone Pair"""
    native = parse_cisco_zbf_reference(reference_config)
    graph = build_cisco_zbf_graph(native)
    return [
        {**p, "revision": compute_cisco_zbf_revision_from_policy(p, graph["reachability"])}
        for p in graph["policies"]
    ]


def _json_safe(value):
    """ตัด field ที่เก็บ xml.etree.ElementTree.Element ดิบออก (ลงท้ายด้วย
    _element/_elements) - field พวกนี้มีไว้ให้ revision hash/guard ใช้ภายในเท่านั้น
    ไม่ควรและไม่จำเป็นต้องส่งออกไป frontend (ส่งไม่ได้ด้วย - Element ไม่ใช่ JSON)"""
    if isinstance(value, dict):
        return {
            k: _json_safe(v) for k, v in value.items()
            if not k.endswith("_element") and not k.endswith("_elements")
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, set):
        return sorted(_json_safe(v) for v in value)
    return value


def list_cisco_zbf_policies_for_api(reference_config: str) -> list[dict]:
    """เหมือน list_cisco_zbf_policies แต่ตัด field ที่ serialize เป็น JSON ไม่ได้ออก -
    ใช้แนบเป็น metadata คู่กับผลของ get_firewall_information ให้ ciscoZbfParser.js
    join ด้วยชื่อ Zone Pair จริง (ไม่ต้องคำนวณ revision เองฝั่ง frontend อีกต่อไป -
    ห้าม frontend สร้าง revision คนละ algorithm กับ backend)"""
    return [_json_safe(p) for p in list_cisco_zbf_policies(reference_config)]


# ---------------------------------------------------------------------------
# Live safety guards - เรียกจาก backend/api/device_router.py ภายใน DeviceLock
# หลังอ่าน get_firewall_information() สดเสมอ ห้ามเชื่อค่าจาก frontend
# ---------------------------------------------------------------------------

def _raise_for_unsafe_policy(policy: dict, identity: dict) -> None:
    if not policy.get("chain_complete", True) or policy.get("blocking_errors"):
        errors = policy.get("blocking_errors") or policy.get("chain_reasons") or ["Reference chain of this Zone Pair is incomplete"]
        raise CiscoZbfError(
            "CISCO_ZBF_REFERENCE_INCOMPLETE",
            "; ".join(errors),
            status_code=400, identity=identity,
        )


def _check_revision(policy: dict, expected_revision: str | None, identity: dict) -> None:
    if not expected_revision or not str(expected_revision).strip():
        raise CiscoZbfError(
            "CISCO_ZBF_REVISION_REQUIRED",
            "Missing revision information for the Policy you are viewing. Please refresh and try again. No command has been sent to the device yet",
            status_code=400, identity=identity,
        )
    exp = str(expected_revision).strip()
    if exp not in _valid_revision_set(policy["revision"]):
        raise CiscoZbfError(
            "CISCO_ZBF_CONCURRENT_MODIFICATION",
            f'Policy "{identity.get("name")}" was modified after you opened this page. Please reload the latest data and review again. '
            "The Policy has not been saved or deleted",
            status_code=409, identity=identity,
        )


def resolve_cisco_zbf_safe_edit(
    reference_config: str,
    zone_pair_name: str,
    expected_revision: str | None,
    *,
    is_new: bool,
) -> dict:
    """ตรวจก่อน create_firewall_policy() เขียนจริง - New ตรวจแค่ชื่อ Zone Pair ยัง
    ไม่ถูกใช้ (กัน New เขียนทับ Policy ที่ผู้อื่นสร้างหลังหน้าเว็บโหลด) Edit ตรวจ
    revision + reference chain ครบ + systemManagedShape + ไม่ shared - โยน
    CiscoZbfError ทันทีที่พบปัญหาแรก (ไม่สร้าง write payload ต่อ)"""
    native = parse_cisco_zbf_reference(reference_config)
    graph = build_cisco_zbf_graph(native)
    identity = {"name": zone_pair_name}
    policy = next((p for p in graph["policies"] if p["name"] == zone_pair_name), None)

    if is_new:
        if policy is not None:
            raise CiscoZbfError(
                "CISCO_ZBF_DESTINATION_EXISTS",
                f'Zone Pair "{zone_pair_name}" already exists on device and cannot be overwritten. Please reload the latest data',
                status_code=409, identity=identity,
            )
        return {"exists": False}

    if policy is None:
        raise CiscoZbfError(
            "CISCO_ZBF_POLICY_NOT_FOUND",
            f'Zone Pair "{zone_pair_name}" not found on device; it may have been deleted after you opened this page',
            status_code=404, identity=identity,
        )
    revision = compute_cisco_zbf_revision_from_policy(policy, graph["reachability"])
    policy = {**policy, "revision": revision}
    _check_revision(policy, expected_revision, identity)
    _raise_for_unsafe_policy(policy, identity)
    return policy


def resolve_cisco_zbf_safe_delete(
    reference_config: str,
    zone_pair_name: str,
    expected_revision: str | None,
) -> dict:
    """ตรวจก่อน remove_firewall_policy() ลบจริง - เกณฑ์เดียวกับ Edit เพราะ
    remove_firewall_policy ยัง derive ชื่อ FW_<name> เหมือนกันทุกประการ (ถ้าไม่ใช่
    systemManagedShape การลบจะเสี่ยงลบ object ผิดตัว/ทิ้ง object จริงเป็น orphan)"""
    native = parse_cisco_zbf_reference(reference_config)
    graph = build_cisco_zbf_graph(native)
    identity = {"name": zone_pair_name}
    policy = next((p for p in graph["policies"] if p["name"] == zone_pair_name), None)
    if policy is None:
        raise CiscoZbfError(
            "CISCO_ZBF_POLICY_NOT_FOUND",
            f'Zone Pair "{zone_pair_name}" not found on device; it may have been deleted',
            status_code=404, identity=identity,
        )
    revision = compute_cisco_zbf_revision_from_policy(policy, graph["reachability"])
    policy = {**policy, "revision": revision}
    _check_revision(policy, expected_revision, identity)
    _raise_for_unsafe_policy(policy, identity)
    return policy


# ---------------------------------------------------------------------------
# ACL-in-use guard (ป้องกันหน้า Stateless ACL/API แก้ ACL ที่ ZBF active ใช้งานอยู่)
# ---------------------------------------------------------------------------

def find_cisco_acl_zbf_usage(native: ET.Element | None, acl_name: str) -> list[dict]:
    """คืนรายการ Zone Pair ที่ reachable ไปถึง ACL ชื่อนี้จริงผ่าน reference graph
    (ตรง หรือผ่าน nested Class Map) - ใช้ตัดสิน "in use" ไม่ใช้การเดาจาก prefix
    ชื่อ ACL (ACL ชื่อขึ้นต้น FW_ ที่ไม่มีใครอ้างอยู่จริงต้องไม่ถูกนับว่า in use)"""
    graph = build_cisco_zbf_graph(native)
    usage = []
    for policy in graph["policies"]:
        if ("acl", acl_name) in policy["reached_objects"]:
            usage.append({
                "zone_pair": policy["name"],
                "policy_map": policy["policy_map_name"],
                "source": policy["source"],
                "destination": policy["destination"],
            })
    return usage


def find_cisco_acl_orphan_class_map_references(native: ET.Element | None, acl_name: str) -> list[str]:
    """Class Map ที่ match access-group ชี้มาที่ ACL นี้ตรงๆ แต่ตัว Class Map เองไม่
    reachable จาก Zone Pair ใดเลย (orphan) - รายงานแยกจาก active reference เสมอ
    ห้ามเอาไปปนกับ find_cisco_acl_zbf_usage (คนละความหมาย: orphan ไม่ได้ enforce
    traffic จริง)"""
    indexes = _build_indexes(native)
    class_map_by_name, _dup = indexes["class_map_index"]
    graph = build_cisco_zbf_graph(native)
    reachable_class_map_names = {
        name for policy in graph["policies"] for kind, name in policy["reached_objects"] if kind == "class-map"
    }
    orphans = []
    for name, cm_el in class_map_by_name.items():
        if name in reachable_class_map_names:
            continue
        match_el = _child_by_local_name(cm_el, "match")
        if match_el is None:
            continue
        ag_el = _child_by_local_name(match_el, "access-group")
        if ag_el is None:
            continue
        for n_el in _children_by_local_name(ag_el, "name"):
            if (n_el.text or "").strip() == acl_name:
                orphans.append(name)
                break
    return orphans


def _extract_access_group_acl(direction_el: ET.Element | None) -> str | None:
    if direction_el is None:
        return None
    name = _child_text(direction_el, "acl-name")
    if name:
        return name
    acl_el = _child_by_local_name(direction_el, "acl")
    if acl_el is not None:
        name = _child_text(acl_el, "acl-name")
        if name:
            return name
    return None


def find_cisco_acl_nat_usage(native: ET.Element | None, acl_name: str) -> list[dict]:
    """ตรวจว่า ACL ถูกใช้งานโดย NAT inside source list หรือไม่"""
    if native is None or not acl_name:
        return []
    nat_usage = []
    for nat_el in native.iter():
        if not isinstance(nat_el.tag, str) or _local_name(nat_el.tag) != "nat":
            continue
        for list_el in nat_el.iter():
            if not isinstance(list_el.tag, str) or _local_name(list_el.tag) != "list":
                continue
            id_text = _child_text(list_el, "id")
            if id_text == acl_name:
                iface = _child_text(list_el, "interface")
                pool = _child_text(list_el, "pool")
                if iface:
                    detail = f"NAT Policy (inside source interface {iface})"
                elif pool:
                    detail = f"NAT Policy (inside source pool {pool})"
                else:
                    detail = f"NAT Policy ({acl_name})"
                nat_usage.append({
                    "type": "nat",
                    "detail": detail,
                    "interface": iface or None,
                    "pool": pool or None,
                })
    return nat_usage


def find_cisco_acl_interface_usage(native: ET.Element | None, acl_name: str) -> list[dict]:
    """ตรวจว่า ACL ถูกผูกกับ interface ใดๆ (inbound หรือ outbound) หรือไม่"""
    if native is None or not acl_name:
        return []
    intf_usage = []
    for iface_root in native.iter():
        if not isinstance(iface_root.tag, str) or _local_name(iface_root.tag) != "interface" or _child_text(iface_root, "name"):
            continue
        for type_el in iface_root:
            if not isinstance(type_el.tag, str):
                continue
            type_name = _local_name(type_el.tag)
            name = _child_text(type_el, "name")
            if not name:
                continue
            full_name = name if name.startswith(type_name) else f"{type_name}{name}"
            for ip_el in _children_by_local_name(type_el, "ip"):
                for ag_el in _children_by_local_name(ip_el, "access-group"):
                    in_acl = _extract_access_group_acl(_child_by_local_name(ag_el, "in"))
                    out_acl = _extract_access_group_acl(_child_by_local_name(ag_el, "out"))
                    if in_acl == acl_name:
                        intf_usage.append({"interface": full_name, "direction": "in"})
                    if out_acl == acl_name:
                        intf_usage.append({"interface": full_name, "direction": "out"})
    return intf_usage


def find_cisco_acl_zbf_references(native: ET.Element | None, acl_name: str) -> list[dict]:
    """ตรวจ Zone-Based Firewall references ในรูปแบบ structured: class_map, policy_map, zone_pair"""
    if native is None or not acl_name:
        return []
    graph = build_cisco_zbf_graph(native)
    zbf_refs = []
    for policy in graph["policies"]:
        if ("acl", acl_name) in policy.get("reached_objects", []):
            matching_cm = None
            for cls in policy.get("classes", []):
                for acl_el in cls.get("reachable_acl_elements", []):
                    if _child_text(acl_el, "name") == acl_name:
                        matching_cm = cls.get("class_map_name")
                        break
                if matching_cm:
                    break
            zbf_refs.append({
                "class_map": matching_cm or policy.get("policy_map_name"),
                "policy_map": policy.get("policy_map_name"),
                "zone_pair": policy.get("name"),
            })
    return zbf_refs


def inspect_cisco_acl_references(
    reference_config: str | ET.Element,
    target_acl_name: str | None = None,
    target_acl_type: str | None = None,
) -> dict:
    """วิเคราะห์การอ้างอิงของ Cisco ACL จาก snapshot เดียว:
    ตรวจ NAT, interface access-group, และ ZBF reference graph
    พร้อมคำนวณ revision และข้อมูลกฎของ ACL"""
    if isinstance(reference_config, str):
        try:
            native = parse_cisco_zbf_reference(reference_config)
        except CiscoZbfError as exc:
            return {
                "known": False,
                "in_use": False,
                "references": {"nat": [], "interfaces": [], "zbf": []},
                "revision": None,
                "acl": None,
                "error": exc.message,
            }
        except Exception as exc:
            return {
                "known": False,
                "in_use": False,
                "references": {"nat": [], "interfaces": [], "zbf": []},
                "revision": None,
                "acl": None,
                "error": f"Failed to read configuration from device: {exc}",
            }
    else:
        native = reference_config

    if not target_acl_name:
        return {
            "known": True,
            "in_use": False,
            "references": {"nat": [], "interfaces": [], "zbf": []},
            "revision": None,
            "acl": None,
        }

    nat_refs = find_cisco_acl_nat_usage(native, target_acl_name)
    intf_refs = find_cisco_acl_interface_usage(native, target_acl_name)
    zbf_refs = find_cisco_acl_zbf_references(native, target_acl_name)

    acl_info = None
    revision = None
    known = True
    reasons = []
    if native is not None:
        indexes = _build_indexes(native)
        by_name, dup = indexes["acl_index"]
        acl_el = by_name.get(target_acl_name)
        if acl_el is not None:
            a_type = "standard" if _local_name(acl_el.tag) == "standard" else "extended"
            seq_rules = _children_by_local_name(acl_el, "access-list-seq-rule")
            seqs = [int(_child_text(sr, "sequence")) for sr in seq_rules if _child_text(sr, "sequence").isdigit()]
            revision = compute_cisco_acl_revision(acl_el)
            acl_info = {
                "name": target_acl_name,
                "type": a_type,
                "rules_count": len(seqs),
                "sequences": sorted(seqs),
            }
        elif target_acl_name:
            known = False
            reasons.append(f'ACL "{target_acl_name}" not found on device')

    if nat_refs:
        reasons.extend(r.get("detail", "NAT") for r in nat_refs)
    if intf_refs:
        for ir in intf_refs:
            reasons.append(f'Interface {ir.get("interface")} ({ir.get("direction", "in/out")})')
    if zbf_refs:
        for zr in zbf_refs:
            reasons.append(f'ZBF Zone Pair ({zr.get("zone_pair")})')

    in_use = bool(nat_refs or intf_refs or zbf_refs)
    return {
        "known": known,
        "in_use": in_use,
        "reasons": reasons,
        "references": {
            "nat": nat_refs,
            "interfaces": intf_refs,
            "zbf": zbf_refs,
        },
        "revision": revision,
        "acl": acl_info,
    }


def resolve_cisco_acl_mutation_guard(reference_config: str, acl_name: str) -> None:
    """โยน CISCO_ACL_IN_USE_BY_ZBF ถ้า ACL นี้ active ถูก Zone Pair ใดอ้างอิงอยู่จริง
    - ต้องเรียกก่อน mutate ACL ใดๆ จากหน้า Stateless ACL/API เสมอ (remove_acl,
    remove_acl_rule, replace_acl, set_acl_rule, create_acl_rule, replace_acl_rule,
    create_acl เมื่อชื่อชนกับของเดิม) ไม่ block เพียงเพราะ Class Map orphan อ้างถึง"""
    native = parse_cisco_zbf_reference(reference_config)
    usage = find_cisco_acl_zbf_usage(native, acl_name)
    if usage:
        owners = sorted({u["zone_pair"] for u in usage})
        raise CiscoZbfError(
            "CISCO_ACL_IN_USE_BY_ZBF",
            f'ACL "{acl_name}" is in use by Zone-Based Firewall (Zone Pair: {", ".join(owners)}) '
            "and cannot be deleted or modified directly via Stateless ACL or API. Please modify it via the Stateful Firewall form instead",
            status_code=409,
            object_kind="acl", object_name=acl_name, shared_with=owners,
        )


def resolve_cisco_acl_safe_deletion(
    reference_config: str,
    acl_name: str,
    expected_revision: str | None = None,
    sequence: int | None = None,
    acl_type: str | None = None,
) -> tuple[ET.Element, bool]:
    """Authoritative pre-delete validation under DeviceLock:
    1. Check ZBF reference graph
    2. Check NAT inside source references
    3. Check Interface inbound/outbound access-group references
    4. Check duplicate ACL names on device
    5. Check ACL existence (404 if not found)
    6. Check expected revision (409 if modified)
    7. If sequence is specified, check ACE existence (404 if not found)
    8. Check if sequence is the last remaining ACE in the ACL -> is_last_rule
    Returns (acl_el, is_last_rule).
    """
    native = parse_cisco_zbf_reference(reference_config)

    # 1. ZBF Guard
    zbf_usage = find_cisco_acl_zbf_references(native, acl_name)
    if zbf_usage:
        zp_names = sorted({u["zone_pair"] for u in zbf_usage})
        raise CiscoZbfError(
            "CISCO_ACL_IN_USE_BY_ZBF",
            f'ACL "{acl_name}" is in use by Zone-Based Firewall (Zone Pair: {", ".join(zp_names)}) '
            "and cannot be deleted or modified directly via Stateless ACL or API. Please modify it via the Stateful Firewall form instead",
            status_code=409,
            object_kind="acl", object_name=acl_name, shared_with=zp_names,
            references={"nat": [], "interfaces": [], "zbf": zbf_usage},
        )

    # 2. NAT Guard
    nat_usage = find_cisco_acl_nat_usage(native, acl_name)
    if nat_usage:
        details = ", ".join(u["detail"] for u in nat_usage)
        raise CiscoZbfError(
            "CISCO_ACL_IN_USE_BY_NAT",
            f'ACL "{acl_name}" is currently in use by {details} and cannot be deleted. Please remove the binding in NAT first',
            status_code=409,
            object_kind="acl", object_name=acl_name,
            references={"nat": nat_usage, "interfaces": [], "zbf": []},
        )

    # 3. Interface Guard
    intf_usage = find_cisco_acl_interface_usage(native, acl_name)
    if intf_usage:
        ifaces_str = ", ".join(f'{u["interface"]} ({u["direction"]})' for u in intf_usage)
        raise CiscoZbfError(
            "CISCO_ACL_IN_USE_BY_INTERFACE",
            f'ACL "{acl_name}" is currently in use by Interface ({ifaces_str}) and cannot be deleted. Please remove the binding on Interface first',
            status_code=409,
            object_kind="acl", object_name=acl_name,
            references={"nat": [], "interfaces": intf_usage, "zbf": []},
        )

    # 4. Duplicate ACL names
    indexes = _build_indexes(native)
    by_name, dup = indexes["acl_index"]
    if acl_name in dup:
        raise CiscoZbfError(
            "CISCO_ACL_REFERENCE_UNKNOWN",
            f'ACL "{acl_name}" has more than 1 entry on device (ambiguous)',
            status_code=409, object_kind="acl", object_name=acl_name,
        )

    # 5. ACL Existence
    acl_el = by_name.get(acl_name)
    if acl_el is None:
        raise CiscoZbfError(
            "CISCO_ACL_NOT_FOUND",
            f'ACL "{acl_name}" not found on device (may have been deleted)',
            status_code=404, object_kind="acl", object_name=acl_name,
        )

    # 6. Revision Check
    if expected_revision and str(expected_revision).strip():
        current = compute_cisco_acl_revision(acl_el)
        exp = str(expected_revision).strip()
        if exp not in _valid_revision_set(current):
            raise CiscoZbfError(
                "CISCO_ACL_CONCURRENT_MODIFICATION",
                f'ACL "{acl_name}" was modified after you opened this page. Please reload the latest data and review again',
                status_code=409, object_kind="acl", object_name=acl_name,
            )

    # 7. Check Sequence Existence & Last Rule
    seq_rules = _children_by_local_name(acl_el, "access-list-seq-rule")
    rule_seqs = [int(_child_text(sr, "sequence")) for sr in seq_rules if _child_text(sr, "sequence").isdigit()]

    is_last_rule = False
    if sequence is not None:
        if sequence not in rule_seqs:
            raise CiscoZbfError(
                "CISCO_ACE_NOT_FOUND",
                f'Rule sequence {sequence} in ACL "{acl_name}" not found on device (may have been deleted)',
                status_code=404, object_kind="acl", object_name=acl_name,
            )
        if len(rule_seqs) == 1 and rule_seqs[0] == sequence:
            is_last_rule = True
    elif len(rule_seqs) <= 1:
        is_last_rule = True

    return acl_el, is_last_rule


def resolve_cisco_acl_safe_mutation(
    reference_config: str,
    acl_name: str,
    expected_revision: str | None = None,
    is_deletion: bool = False,
    sequence: int | None = None,
    acl_type: str | None = None,
) -> ET.Element | None:
    """รวม ACL-in-use guard + ACL revision check เป็นจุดเดียวที่ device_router.py
    ต้องเรียกก่อน mutate ACL ใดๆ ของ Cisco - คืน element ของ ACL ปัจจุบัน (หรือ None
    ถ้าไม่มีอยู่จริง เช่นตอน create_acl ที่ชื่อยังไม่เคยมี) expected_revision เป็น
    optional (create ใหม่ไม่มี revision ให้เทียบ)"""
    if is_deletion:
        acl_el, _ = resolve_cisco_acl_safe_deletion(
            reference_config,
            acl_name,
            expected_revision=expected_revision,
            sequence=sequence,
            acl_type=acl_type,
        )
        return acl_el

    native = parse_cisco_zbf_reference(reference_config)
    resolve_cisco_acl_mutation_guard(reference_config, acl_name)
    indexes = _build_indexes(native)
    by_name, dup = indexes["acl_index"]
    if acl_name in dup:
        raise CiscoZbfError(
            "CISCO_ACL_REFERENCE_UNKNOWN",
            f'ACL "{acl_name}" has more than 1 entry on device (ambiguous)',
            status_code=409, object_kind="acl", object_name=acl_name,
        )
    acl_el = by_name.get(acl_name)
    if expected_revision and str(expected_revision).strip():
        if acl_el is None:
            raise CiscoZbfError(
                "CISCO_ACL_REFERENCE_UNKNOWN",
                f'ACL "{acl_name}" not found on device (may have been deleted)',
                status_code=404, object_kind="acl", object_name=acl_name,
            )
        current = compute_cisco_acl_revision(acl_el)
        exp = str(expected_revision).strip()
        if exp not in _valid_revision_set(current):
            raise CiscoZbfError(
                "CISCO_ACL_CONCURRENT_MODIFICATION",
                f'ACL "{acl_name}" was modified after you opened this page. Please reload the latest data and review again',
                status_code=409, object_kind="acl", object_name=acl_name,
            )
    return acl_el


# ===========================================================================
# Writer v2 (Application support, 2026-09)
#
# รองรับ semantics ที่ปิดข้อกำหนดไว้แล้ว (planning/cisco_zbf_survey_2026-09.md
# section 4):
#   - IP/CIDR หลายค่า = OR (ACE แยกใน ACL เดียว)
#   - Application หลายค่า = OR (nested match-any)
#   - มีทั้ง IP และ Application: (IP1 OR IP2..) AND (APP1 OR APP2..)
#   - Application = Any -> ACL อย่างเดียว ไม่มี match protocol เลย
#   - Application เดียว -> Outer class-map match-all มี ACL + protocol ตรงๆ
#   - Application หลายตัว -> Inner class-map match-any (protocol เท่านั้น) แล้ว
#     Outer class-map match-all อ้าง ACL + nested class-map ของ Inner
#
# ทุก object (ACL/Inner/Outer/Policy Map/Zone Pair) เขียนใน <edit-config> เดียว
# เสมอ (ดู build_cisco_zbf_write_fragment) - ไม่มี API call แยก ไม่มีการลบก่อนสร้าง
# ===========================================================================

CISCO_ZBF_MAX_NAME_LENGTH = 64

# ยืนยันผ่าน CLI completion โดยผู้ใช้จริงบนอุปกรณ์ 23 ก.ย. 2026 (ดู
# planning/cisco_zbf_survey_2026-09.md section 5) - เป็น "IOS CLI parser ยอมรับ
# keyword นี้" เท่านั้น "NETCONF round-trip" ยังไม่ยืนยันกับอุปกรณ์จริงจนกว่าจะทำ
# ตามหัวข้อ 14 ของงาน Writer นี้ - ห้ามประกาศรายการนี้ซ้ำที่อื่น (single source of
# truth ระหว่าง validation/test/UI ในอนาคต)
CISCO_ZBF_APPLICATION_CATALOG: tuple[str, ...] = (
    "bgp", "ddns-v3", "dhcp-failover", "dns", "hsrp", "http", "https", "icmp",
    "imap", "imap3", "imaps", "isakmp", "ldap", "ldap-admin", "ldaps", "mysql",
    "ntp", "pop3", "pop3s", "radius", "smtp", "snmp", "sqlserv", "ssh", "syslog",
    "tacacs", "tacacs-ds", "tcp", "telnet", "tftp", "udp",
)
CISCO_ZBF_APPLICATION_CATALOG_SET = frozenset(CISCO_ZBF_APPLICATION_CATALOG)
# tcp/udp เป็น protocol กว้าง - เอกสาร Cisco เตือนว่าถ้าวางไว้ก่อน protocol เฉพาะ
# เจาะจงกว่า (เช่น http) จะ "ชิง" จับ traffic ก่อน ทำให้ protocol เฉพาะทำงานผิดปกติ
CISCO_ZBF_GENERIC_APPLICATIONS = frozenset({"tcp", "udp"})


def order_cisco_zbf_applications(applications: list[str]) -> list[str]:
    """คงลำดับสัมพัทธ์เดิมของผู้ใช้ แต่ดัน tcp/udp (generic) ไปท้ายสุดเสมอ"""
    specific = [a for a in applications if a not in CISCO_ZBF_GENERIC_APPLICATIONS]
    generic = [a for a in applications if a in CISCO_ZBF_GENERIC_APPLICATIONS]
    return specific + generic


def validate_cisco_zbf_applications(
    applications: list[str] | None,
    allow_custom: bool = False,
) -> tuple[str, list[str]]:
    """คืน (mode, ordered_applications) - mode เป็น "any"/"single"/"multiple"
    None/[] = Any (ไม่มี match protocol เลย) - dedupe รักษาลำดับที่พบครั้งแรกก่อน
    จัดลำดับ generic ไปท้าย - ถ้า allow_custom เป็น True (เช่น โหมด Edit) ยอมรับ
    protocol ชื่อใดๆ ที่เป็น valid identifier เพื่อรองรับ Brownfield โดยไม่สูญหาย"""
    if applications is None:
        return "any", []
    if not isinstance(applications, list):
        raise CiscoZbfError("CISCO_ZBF_INVALID_APPLICATIONS", "applications must be a list or None (Any)")
    seen: list[str] = []
    for app in applications:
        if not isinstance(app, str) or not app.strip():
            raise CiscoZbfError("CISCO_ZBF_INVALID_APPLICATIONS", "Each application must be a non-empty string")
        normalized = app.strip().lower()
        if normalized not in CISCO_ZBF_APPLICATION_CATALOG_SET:
            if allow_custom and re.match(r"^[a-zA-Z0-9_\-]+$", normalized):
                pass
            else:
                raise CiscoZbfError(
                    "CISCO_ZBF_UNSUPPORTED_APPLICATION",
                    f'application "{app}" is not in the catalog supported for create/edit by Writer at this time '
                    "(see CISCO_ZBF_APPLICATION_CATALOG)",
                )
        if normalized not in seen:
            seen.append(normalized)
    if not seen:
        return "any", []
    ordered = order_cisco_zbf_applications(seen)
    return ("single" if len(ordered) == 1 else "multiple"), ordered


def validate_cisco_zbf_source_scopes(source_scopes: str | list[str]) -> list[tuple[str, str | None]]:
    """คืนรายการ (network_address, wildcard_mask) ต่อ ACE หนึ่งเส้น - ("any", None)
    เส้นเดียวสำหรับ "any" - CIDR หลายตัว = ACE แยก (OR) ห้ามปนกับ "any" - dedupe
    รักษาลำดับที่พบครั้งแรก (canonical network address เทียบกัน ไม่ใช่ string ดิบ)"""
    scopes = [source_scopes] if isinstance(source_scopes, str) else list(source_scopes or [])
    scopes = [s.strip() for s in scopes if isinstance(s, str) and s.strip()]
    if not scopes:
        raise CiscoZbfError(
            "CISCO_ZBF_INVALID_SOURCE_SCOPES",
            'source_scopes must have at least 1 value ("any" or IPv4/prefix)',
        )
    has_any = any(s.lower() == "any" for s in scopes)
    if has_any:
        if len(scopes) > 1:
            raise CiscoZbfError("CISCO_ZBF_INVALID_SOURCE_SCOPES", '"any" must not be mixed with other CIDRs in the same list')
        return [("any", None)]
    seen: set[str] = set()
    result: list[tuple[str, str | None]] = []
    for s in scopes:
        try:
            network = ipaddress.IPv4Network(s, strict=False)
        except ValueError as exc:
            raise CiscoZbfError("CISCO_ZBF_INVALID_SOURCE_SCOPES", f'"{s}" is not a valid IPv4/prefix: {exc}')
        key = str(network)
        if key in seen:
            continue
        seen.add(key)
        result.append((str(network.network_address), str(network.hostmask)))
    return result


def derive_cisco_zbf_object_names(name: str) -> dict[str, str]:
    """ชื่อ object สำหรับ Greenfield Policy (Writer v2) - ทุกชนิดใช้ฐาน
    "FW_<name>" เดียวกัน (รักษา naming convention เดิม) ยกเว้น Inner Application
    Class Map ที่เติม "_APP" ต่อท้าย - ปฏิเสธก่อนสร้างถ้าชื่อที่ได้ยาวเกินขีดจำกัด
    (ห้าม truncate เงียบๆ จนชื่อชนกัน)"""
    base = f"FW_{name}"
    app = f"{base}{CISCO_ZBF_APP_CLASS_SUFFIX}"
    names = {
        "zone_pair": name, "acl": base, "outer_class_map": base,
        "policy_map": base, "inner_application_class_map": app,
    }
    for key, value in names.items():
        if len(value) > CISCO_ZBF_MAX_NAME_LENGTH:
            raise CiscoZbfError(
                "CISCO_ZBF_NAME_TOO_LONG",
                f'Policy name "{name}" causes object name to be created ("{value}", {key}) to exceed '
                f"{CISCO_ZBF_MAX_NAME_LENGTH} characters. Please choose a shorter Policy name",
                status_code=400,
            )
    return names


def check_cisco_zbf_new_zone_pair(
    native: ET.Element | None,
    source_zone: str,
    destination_zone: str,
    *,
    exclude_name: str | None = None,
) -> None:
    """New Policy เสมอ, Edit เรียกเฉพาะตอนเปลี่ยนคู่ Zone (ดู build_cisco_zbf_write_fragment):
    Source/Destination Zone ต้องมีอยู่จริงบนอุปกรณ์ (Writer v2 ไม่สร้าง Zone ให้เองอีกต่อไป -
    ผู้ใช้ต้องสร้างผ่านหน้า Zone Interfaces ก่อน), ต้องไม่ใช่ Zone เดียวกัน, และคู่
    (source, destination) นี้ต้องไม่ถูกใช้โดย Zone Pair อื่นอยู่แล้ว - Cisco ไม่อนุญาตให้มี
    Zone Pair สองตัวที่คู่ source/destination ซ้ำกัน (ต้องเพิ่มเงื่อนไขใน Policy Map เดิม
    แทน ไม่ใช่สร้าง Zone Pair ใหม่ด้วยคู่เดิม) - exclude_name = ชื่อ Zone Pair ที่กำลังแก้ไข
    เอง (Edit) กันไม่ให้ถือคู่เดิมของตัวเองเป็น collision"""
    if source_zone == destination_zone:
        raise CiscoZbfError(
            "CISCO_ZBF_SAME_ZONE_PAIR", "Source and destination zones cannot be the same zone",
            status_code=400, source_zone=source_zone, destination_zone=destination_zone,
        )
    indexes = _build_indexes(native)
    zone_by_name, _ = indexes["zone_index"]
    for zone_name, label in ((source_zone, "source"), (destination_zone, "destination")):
        if zone_name not in zone_by_name:
            raise CiscoZbfError(
                "CISCO_ZBF_ZONE_NOT_FOUND",
                f'Zone "{zone_name}" ({label}) not found on device. Please create the Zone and bind Interfaces '
                "via the Zone Interfaces page first",
                status_code=400,
            )
    # ตรวจคู่ซ้ำจาก graph จริงทั้งหมด (รวม Brownfield ที่ชื่อ Zone Pair อิสระ/reference
    # chain ไม่ครบก็ตาม - source/destination มาจาก <zone-pair> element ตรงๆ ไม่ต้องพึ่ง
    # chain) ข้าม record ที่ source/destination ว่างเพราะพิสูจน์คู่ไม่ได้ และข้ามตัวเอง
    # เมื่อเป็น Edit (exclude_name)
    graph = build_cisco_zbf_graph(native)
    for policy in graph["policies"]:
        if not policy["source"] or not policy["destination"]:
            continue
        if exclude_name is not None and policy["name"] == exclude_name:
            continue
        if policy["source"] == source_zone and policy["destination"] == destination_zone:
            raise CiscoZbfError(
                "CISCO_ZBF_ZONE_PAIR_DUPLICATE",
                f'A Zone Pair from "{source_zone}" to "{destination_zone}" already exists '
                f'(name "{policy["name"]}"). Duplicate Zone Pairs cannot be created. Please add conditions to the '
                "existing Policy or select a different Zone pair",
                status_code=409,
                source_zone=source_zone, destination_zone=destination_zone,
                existing_zone_pair=policy["name"],
            )


def check_cisco_zbf_new_object_names(native: ET.Element | None, names: dict[str, str], application_mode: str) -> None:
    """New Policy เท่านั้น: derived object name (ACL/Outer/Policy Map/Inner ถ้า
    ต้องใช้) ต้องไม่ชนกับ object ที่มีอยู่แล้วบนอุปกรณ์ (คนละ Policy/ไม่เกี่ยวข้องกัน
    เลย) - เทียบเฉพาะ namespace เดียวกัน (ACL เทียบกับ ACL, Class Map เทียบกับ
    Class Map ฯลฯ) ตาม YANG list key จริง"""
    indexes = _build_indexes(native)
    acl_by_name, _ = indexes["acl_index"]
    class_map_by_name, _ = indexes["class_map_index"]
    policy_map_by_name, _ = indexes["policy_map_index"]
    checks = [
        ("ACL", names["acl"], acl_by_name),
        ("Class Map", names["outer_class_map"], class_map_by_name),
        ("Policy Map", names["policy_map"], policy_map_by_name),
    ]
    if application_mode == "multiple":
        checks.append(("Class Map", names["inner_application_class_map"], class_map_by_name))
    for kind_label, obj_name, by_name in checks:
        if obj_name in by_name:
            raise CiscoZbfError(
                "CISCO_ZBF_NAME_COLLISION",
                f'Cannot create this Policy: the required {kind_label} name "{obj_name}" already exists on the device '
                "(belongs to an unrelated object). Please choose a new Policy name",
                status_code=409,
                object_kind=kind_label.lower().replace(" ", "-"), object_name=obj_name,
            )


# --- XML fragment builders (pure string building - ไม่มี rpc-message-id ที่นี่) --

def _op_attr(operation: str | None) -> str:
    return f' xmlns:nc="{NS_RPC}" nc:operation="{operation}"' if operation else ""


def _element_to_xml(el: ET.Element, default_ns: str, operation: str | None = None) -> str:
    """แปลง ET.Element เป็น XML string ใน default_ns พร้อม nc:operation ที่ root element
    รักษา tag ลูกทั้งหมดใน default namespace โดยไม่มี prefix ns0: ปะปน
    และรักษา text/tail/attributes ทั้งหมด"""
    def serialize(node: ET.Element, is_root: bool = False) -> str:
        tag = _local_name(node.tag)
        attrs = []
        if is_root:
            attrs.append(f'xmlns="{default_ns}"')
            if operation:
                attrs.append(f'xmlns:nc="{NS_RPC}" nc:operation="{operation}"')
        for k, v in node.attrib.items():
            if not k.startswith("xmlns") and "operation" not in k:
                local_k = _local_name(k)
                attrs.append(f'{local_k}="{escape(v)}"')
        attr_str = (" " + " ".join(attrs)) if attrs else ""
        children_str = "".join(serialize(c) for c in node)
        text = escape(node.text) if node.text else ""
        tail = escape(node.tail) if node.tail else ""
        if children_str:
            return f"<{tag}{attr_str}>{text}{children_str}</{tag}>{tail}"
        elif text:
            return f"<{tag}{attr_str}>{text}</{tag}>{tail}"
        else:
            return f"<{tag}{attr_str}/>{tail}"
    return serialize(el, is_root=True)


def _generate_clone_name(base_name: str, suffix: str, existing_names: set[str], max_len: int = 64) -> str:
    candidate = f"FW_{base_name}_{suffix}"
    if len(candidate) <= max_len and candidate not in existing_names:
        return candidate
    h = hashlib.sha256(f"{base_name}_{suffix}".encode("utf-8")).hexdigest()[:8]
    prefix = candidate[: max_len - 9]
    return f"{prefix}_{h}"


def _build_zbf_acl_xml(acl_name: str, scopes: list[tuple[str, str | None]], *, operation: str | None = None) -> str:
    aces = []
    for index, (address, wildcard) in enumerate(scopes):
        sequence = (index + 1) * 10
        source_xml = "<any/>" if address == "any" else f"<ipv4-address>{escape(address)}</ipv4-address><mask>{escape(wildcard)}</mask>"
        aces.append(
            f"<access-list-seq-rule><sequence>{sequence}</sequence><ace-rule><action>permit</action>"
            f"<protocol>ip</protocol>{source_xml}<dst-any/></ace-rule></access-list-seq-rule>"
        )
    return f'<extended xmlns="{NS_ACL}"{_op_attr(operation)}><name>{escape(acl_name)}</name>{"".join(aces)}</extended>'


def _build_zbf_inner_application_class_map_xml(name: str, applications: list[str], *, operation: str | None = None) -> str:
    protocols_xml = "".join(f"<protocols-list><protocols>{escape(a)}</protocols></protocols-list>" for a in applications)
    return (
        f'<class-map xmlns="{NS_POLICY}"{_op_attr(operation)}><name>{escape(name)}</name><type>inspect</type>'
        f"<prematch>match-any</prematch><match><protocol>{protocols_xml}</protocol></match></class-map>"
    )


def _build_zbf_outer_class_map_xml(
    name: str, acl_name: str, application_mode: str,
    *, single_application: str | None = None, inner_class_map_name: str | None = None,
    operation: str | None = None,
) -> str:
    match_xml = f"<access-group><name>{escape(acl_name)}</name></access-group>"
    if application_mode == "single":
        match_xml += f"<protocol><protocols-list><protocols>{escape(single_application)}</protocols></protocols-list></protocol>"
    elif application_mode == "multiple":
        match_xml += f"<class-map>{escape(inner_class_map_name)}</class-map>"
    return (
        f'<class-map xmlns="{NS_POLICY}"{_op_attr(operation)}><name>{escape(name)}</name><type>inspect</type>'
        f"<prematch>match-all</prematch><match>{match_xml}</match></class-map>"
    )


def _build_zbf_policy_map_xml(name: str, outer_class_map_name: str, action: str, log: bool, *, operation: str | None = None) -> str:
    log_xml = "<log/>" if log and action in ("drop", "pass") else ""
    return (
        f'<policy-map xmlns="{NS_POLICY}"{_op_attr(operation)}><name>{escape(name)}</name><type>inspect</type>'
        f"<class><name>{escape(outer_class_map_name)}</name><type>inspect</type>"
        f"<policy><action>{escape(action)}</action>{log_xml}</policy></class>"
        f"<class><name>class-default</name><policy><action>drop</action></policy></class>"
        f"</policy-map>"
    )


def _build_zbf_zone_pair_xml(
    name: str, source_zone: str, destination_zone: str, policy_map_name: str, *, operation: str | None = None
) -> str:
    return (
        f'<security xmlns="{NS_ZONE}"{_op_attr(operation)}><id>{escape(name)}</id>'
        f"<source>{escape(source_zone)}</source><destination>{escape(destination_zone)}</destination>"
        f"<service-policy><type><inspect>{escape(policy_map_name)}</inspect></type></service-policy></security>"
    )


def build_cisco_zbf_create_native_fragment(
    names: dict[str, str], source_zone: str, destination_zone: str, action: str,
    application_mode: str, applications: list[str], scopes: list[tuple[str, str | None]], log: bool,
) -> str:
    """New Policy: ประกอบ <native> ฉบับเต็มสำหรับ Greenfield - เรียง ACL -> Inner
    (ถ้ามี) -> Outer -> Policy Map -> Zone Pair ตามที่ item 10 กำหนด (ให้อุปกรณ์ตรวจ
    reference ระหว่าง object ที่เพิ่งสร้างในชุดเดียวกันได้) - ไม่มี <zone> หรือ
    <interface><zone-member> เลย (Writer v2 ไม่สร้าง Zone/ผูก Interface ให้เอง)"""
    acl_xml = _build_zbf_acl_xml(names["acl"], scopes)
    inner_xml = ""
    if application_mode == "multiple":
        inner_xml = _build_zbf_inner_application_class_map_xml(names["inner_application_class_map"], applications)
    outer_xml = _build_zbf_outer_class_map_xml(
        names["outer_class_map"], names["acl"], application_mode,
        single_application=applications[0] if application_mode == "single" else None,
        inner_class_map_name=names["inner_application_class_map"] if application_mode == "multiple" else None,
    )
    policy_map_xml = _build_zbf_policy_map_xml(names["policy_map"], names["outer_class_map"], action, log)
    zone_pair_xml = _build_zbf_zone_pair_xml(names["zone_pair"], source_zone, destination_zone, names["policy_map"])
    return (
        f'<native xmlns="{NS_NATIVE}">'
        f"<ip><access-list>{acl_xml}</access-list></ip>"
        f"<policy>{inner_xml}{outer_xml}{policy_map_xml}</policy>"
        f"<zone-pair>{zone_pair_xml}</zone-pair>"
        f"</native>"
    )


def build_cisco_zbf_edit_native_fragment(
    policy: dict,
    source_zone: str,
    destination_zone: str,
    action: str,
    application_mode: str,
    applications: list[str],
    scopes: list[tuple[str, str | None]],
    log: bool,
    reachability: dict[tuple[str, str], set[str]] | None = None,
    indexes: dict | None = None,
) -> str:
    """Edit Policy: แก้ไข Policy แบบ Lossless รองรับทั้ง Greenfield และ Brownfield
    รวมถึงการจัดการวัตถุที่ใช้ร่วมกัน (Shared Objects) ด้วยกลยุทธ์ Copy-on-Write (CoW):
    - ใช้วัตถุจริงจาก running config (ไม่ derive ชื่อใหม่ถ้าไม่มีความจำเป็น)
    - รักษา match keys อื่นๆ (เช่น unknown match keys, parameters) และ class อื่นๆ ใน Policy Map
    - หาก Policy Map, Class Map หรือ ACL ถูกใช้ร่วมกับ Zone Pair อื่น จะทำการ Clone วัตถุนั้น
      ด้วยชื่อใหม่ที่ไม่ชนกับวัตถุเดิม แก้ไขที่ตัว Clone และ repoint อ้างอิง โดยปล่อยวัตถุเดิมไว้ไม่กระทบ Zone Pair อื่น
    - ปล่อยผลลัพธ์ทั้งหมดเป็น XML ในธุรกรรม <edit-config> เดียวกันแบบ atomic"""
    zp_name = policy["name"]
    pm_name = policy.get("policy_map_name") or f"FW_{zp_name}"

    target_class_dict = policy["non_default_classes"][0] if policy.get("non_default_classes") else None
    cm_name = target_class_dict.get("class_map_name") if target_class_dict else f"FW_{zp_name}"
    target_class_map_dict = target_class_dict.get("class_map") if target_class_dict else None

    acls = target_class_dict.get("acls", []) if target_class_dict else []
    acl_name = acls[0]["name"] if acls else f"FW_{zp_name}"

    old_nested_names = target_class_map_dict.get("nested_class_map_names", []) if target_class_map_dict else []
    old_inner_name = old_nested_names[0] if old_nested_names else None

    # ตรวจสอบการ share
    pm_is_shared = reachability is not None and len(reachability.get(("policy-map", pm_name), set())) > 1
    cm_is_shared = reachability is not None and len(reachability.get(("class-map", cm_name), set())) > 1
    acl_is_shared = reachability is not None and len(reachability.get(("acl", acl_name), set())) > 1
    inner_is_shared = bool(reachability is not None and old_inner_name and len(reachability.get(("class-map", old_inner_name), set())) > 1)

    existing_pms = set(indexes["policy_map_index"][0].keys()) if indexes else set()
    existing_cms = set(indexes["class_map_index"][0].keys()) if indexes else set()
    existing_acls = set(indexes["acl_index"][0].keys()) if indexes else set()

    # ถ้าวัตถุลูกถูก clone หรือตัวมันเองถูก share จะ trigger CoW
    target_acl_name = _generate_clone_name(zp_name, "ACL", existing_acls) if acl_is_shared else acl_name
    target_cm_name = _generate_clone_name(zp_name, "CM", existing_cms) if (cm_is_shared or (acl_is_shared and not cm_is_shared)) else cm_name
    target_pm_name = _generate_clone_name(zp_name, "PM", existing_pms) if (pm_is_shared or target_cm_name != cm_name) else pm_name

    if application_mode == "multiple":
        if old_inner_name and not inner_is_shared:
            target_inner_name = old_inner_name
        else:
            target_inner_name = _generate_clone_name(zp_name, "APP", existing_cms)
    else:
        target_inner_name = None

    # 1. ACL XML
    acl_xml = _build_zbf_acl_xml(target_acl_name, scopes, operation=None if target_acl_name != acl_name else "replace")

    # 2. Inner Application Class Map XML
    inner_xml = ""
    if application_mode == "multiple":
        inner_xml = _build_zbf_inner_application_class_map_xml(
            target_inner_name, applications,
            operation=None if target_inner_name != old_inner_name else "replace",
        )
    elif old_inner_name and not inner_is_shared:
        # Multiple -> Any/Single: ลบ inner class map ที่ไม่ได้ใช้แล้วและไม่แชร์กับใคร
        inner_xml = (
            f'<class-map xmlns="{NS_POLICY}"{_op_attr("remove")}>'
            f'<name>{escape(old_inner_name)}</name><type>inspect</type></class-map>'
        )

    # 3. Outer Class Map XML
    if target_class_map_dict and target_class_map_dict.get("class_map_element") is not None:
        cm_el = copy.deepcopy(target_class_map_dict["class_map_element"])
        name_el = _child_by_local_name(cm_el, "name")
        if name_el is not None:
            name_el.text = target_cm_name
        match_el = _child_by_local_name(cm_el, "match")
        if match_el is None:
            match_el = ET.SubElement(cm_el, f"{{{NS_POLICY}}}match")
        ag_el = _child_by_local_name(match_el, "access-group")
        if ag_el is None:
            ag_el = ET.SubElement(match_el, f"{{{NS_POLICY}}}access-group")
        ag_name_el = _child_by_local_name(ag_el, "name")
        if ag_name_el is None:
            ag_name_el = ET.SubElement(ag_el, f"{{{NS_POLICY}}}name")
        ag_name_el.text = target_acl_name

        for proto_child in _children_by_local_name(match_el, "protocol"):
            match_el.remove(proto_child)
        for nested_child in _children_by_local_name(match_el, "class-map"):
            match_el.remove(nested_child)

        if application_mode == "single":
            proto_el = ET.SubElement(match_el, f"{{{NS_POLICY}}}protocol")
            plist_el = ET.SubElement(proto_el, f"{{{NS_POLICY}}}protocols-list")
            p_el = ET.SubElement(plist_el, f"{{{NS_POLICY}}}protocols")
            p_el.text = applications[0]
            prematch_el = _child_by_local_name(cm_el, "prematch")
            if prematch_el is not None:
                prematch_el.text = "match-all"
        elif application_mode == "multiple":
            cm_ref_el = ET.SubElement(match_el, f"{{{NS_POLICY}}}class-map")
            cm_ref_el.text = target_inner_name
            prematch_el = _child_by_local_name(cm_el, "prematch")
            if prematch_el is not None:
                prematch_el.text = "match-all"

        outer_xml = _element_to_xml(cm_el, NS_POLICY, operation=None if target_cm_name != cm_name else "replace")
    else:
        outer_xml = _build_zbf_outer_class_map_xml(
            target_cm_name, target_acl_name, application_mode,
            single_application=applications[0] if application_mode == "single" else None,
            inner_class_map_name=target_inner_name if application_mode == "multiple" else None,
            operation=None if target_cm_name != cm_name else "replace",
        )

    # 4. Policy Map XML
    if policy.get("policy_map_element") is not None:
        pm_el = copy.deepcopy(policy["policy_map_element"])
        name_el = _child_by_local_name(pm_el, "name")
        if name_el is not None:
            name_el.text = target_pm_name
        target_orig_cm_name = target_class_dict.get("name") if target_class_dict else None
        for c_el in _children_by_local_name(pm_el, "class"):
            if _child_text(c_el, "name") == target_orig_cm_name:
                c_name_el = _child_by_local_name(c_el, "name")
                if c_name_el is not None:
                    c_name_el.text = target_cm_name
                pol_child = _child_by_local_name(c_el, "policy")
                action_container = pol_child if pol_child is not None else c_el
                act_el = _child_by_local_name(action_container, "action")
                if act_el is None:
                    act_el = ET.SubElement(action_container, f"{{{NS_POLICY}}}action")
                act_el.text = action
                log_child = _child_by_local_name(action_container, "log")
                if log and action in ("pass", "drop"):
                    if log_child is None:
                        ET.SubElement(action_container, f"{{{NS_POLICY}}}log")
                else:
                    if log_child is not None:
                        action_container.remove(log_child)
        policy_map_xml = _element_to_xml(pm_el, NS_POLICY, operation=None if target_pm_name != pm_name else "replace")
    else:
        policy_map_xml = _build_zbf_policy_map_xml(
            target_pm_name, target_cm_name, action, log,
            operation=None if target_pm_name != pm_name else "replace",
        )

    # 5. Zone Pair XML
    if policy.get("zone_pair_element") is not None:
        zp_el = copy.deepcopy(policy["zone_pair_element"])
        src_el = _child_by_local_name(zp_el, "source")
        if src_el is not None:
            src_el.text = source_zone
        dst_el = _child_by_local_name(zp_el, "destination")
        if dst_el is not None:
            dst_el.text = destination_zone
        sp_el = _child_by_local_name(zp_el, "service-policy")
        if sp_el is None:
            sp_el = ET.SubElement(zp_el, f"{{{NS_ZONE}}}service-policy")
        t_el = _child_by_local_name(sp_el, "type")
        if t_el is None:
            t_el = ET.SubElement(sp_el, f"{{{NS_ZONE}}}type")
        insp_el = _child_by_local_name(t_el, "inspect")
        if insp_el is None:
            insp_el = ET.SubElement(t_el, f"{{{NS_ZONE}}}inspect")
        insp_el.text = target_pm_name
        zone_pair_xml = _element_to_xml(zp_el, NS_ZONE, operation="replace")
    else:
        zone_pair_xml = _build_zbf_zone_pair_xml(
            zp_name, source_zone, destination_zone, target_pm_name, operation="replace",
        )

    return (
        f'<native xmlns="{NS_NATIVE}">'
        f"<ip><access-list>{acl_xml}</access-list></ip>"
        f"<policy>{inner_xml}{outer_xml}{policy_map_xml}</policy>"
        f"<zone-pair>{zone_pair_xml}</zone-pair>"
        f"</native>"
    )


def build_cisco_zbf_delete_fragment(
    *,
    reference_config: str,
    name: str,
    expected_revision: str | None,
) -> str:
    """Delete Policy: ลบ Zone Pair และลบเฉพาะ object ที่เป็นของ Zone Pair นี้เพียง
    ผู้เดียว (orphan หลังลบ Zone Pair) โดยรักษา object ที่ถูกใช้ร่วมกับ Zone Pair อื่น
    (shared objects) ไว้เสมอ และไม่ลบ Zone หรือ Interface memberships"""
    policy = resolve_cisco_zbf_safe_delete(reference_config, name, expected_revision)
    native = parse_cisco_zbf_reference(reference_config)
    graph = build_cisco_zbf_graph(native)
    reachability = graph["reachability"]

    zp_xml = f'<security xmlns="{NS_ZONE}"{_op_attr("remove")}><id>{escape(name)}</id></security>'

    pm_name = policy.get("policy_map_name")
    pm_xml = ""
    if pm_name:
        pm_owners = reachability.get(("policy-map", pm_name), set())
        if len(pm_owners) <= 1:
            pm_xml = f'<policy-map xmlns="{NS_POLICY}"{_op_attr("remove")}><name>{escape(pm_name)}</name><type>inspect</type></policy-map>'

    cm_xml_parts = []
    seen_cms = set()
    for kind, cm_name in policy.get("reached_objects", []):
        if kind == "class-map" and cm_name not in seen_cms:
            seen_cms.add(cm_name)
            cm_owners = reachability.get(("class-map", cm_name), set())
            if len(cm_owners) <= 1:
                cm_xml_parts.append(
                    f'<class-map xmlns="{NS_POLICY}"{_op_attr("remove")}><name>{escape(cm_name)}</name><type>inspect</type></class-map>'
                )

    acl_xml_parts = []
    seen_acls = set()
    for kind, acl_name in policy.get("reached_objects", []):
        if kind == "acl" and acl_name not in seen_acls:
            seen_acls.add(acl_name)
            acl_owners = reachability.get(("acl", acl_name), set())
            if len(acl_owners) <= 1:
                acl_xml_parts.append(
                    f'<extended xmlns="{NS_ACL}"{_op_attr("remove")}><name>{escape(acl_name)}</name></extended>'
                )

    acl_section = f"<ip><access-list>{''.join(acl_xml_parts)}</access-list></ip>" if acl_xml_parts else ""
    policy_section = f"<policy>{''.join(cm_xml_parts)}{pm_xml}</policy>" if (cm_xml_parts or pm_xml) else ""
    zone_pair_section = f"<zone-pair>{zp_xml}</zone-pair>"
    return (
        f'<native xmlns="{NS_NATIVE}">'
        f"{acl_section}"
        f"{policy_section}"
        f"{zone_pair_section}"
        f"</native>"
    )


def build_cisco_zbf_write_fragment(
    *,
    reference_config: str,
    name: str,
    source_zone: str,
    destination_zone: str,
    action: str,
    source_scopes: str | list[str],
    applications: list[str] | None,
    log: bool = False,
    replace_name: str | None,
    expected_revision: str | None,
) -> str:
    """จุดเดียวที่ create_firewall_policy() (Writer v2) เรียกเพื่อได้ <native>
    fragment ที่ผ่านการตรวจครบแล้ว - guard (revision/reference/shared/ownership)
    และการสร้าง payload ใช้ reference_config ชุดเดียวกันเสมอ (ห้าม guard ด้วย
    config ชุดหนึ่งแล้ว build จาก config อีกชุดหนึ่ง) โยน CiscoZbfError ทันทีที่พบ
    ปัญหาแรก - ไม่ถึงขั้นสร้าง XML เลยถ้าตรวจไม่ผ่าน"""
    is_new = replace_name is None
    if action not in ("inspect", "pass", "drop"):
        raise CiscoZbfError("CISCO_ZBF_INVALID_FIELD", f'action "{action}" is invalid (must be inspect/pass/drop)')

    application_mode, ordered_applications = validate_cisco_zbf_applications(applications, allow_custom=not is_new)
    scopes = validate_cisco_zbf_source_scopes(source_scopes)

    native = parse_cisco_zbf_reference(reference_config)

    if is_new:
        check_cisco_zbf_new_zone_pair(native, source_zone, destination_zone)
        names = derive_cisco_zbf_object_names(name)
        check_cisco_zbf_new_object_names(native, names, application_mode)
        return build_cisco_zbf_create_native_fragment(
            names, source_zone, destination_zone, action, application_mode,
            ordered_applications, scopes, log,
        )

    # Edit: ต้อง resolve ผ่าน authoritative graph จริงเสมอ (ใช้ resolve_cisco_zbf_safe_edit
    # ตัวเดียวกับที่ backend guard เรียกอยู่แล้ว - รวม revision/reference/shared/
    # editable check ครบในที่เดียว ไม่มีทาง bypass)
    policy = resolve_cisco_zbf_safe_edit(reference_config, replace_name, expected_revision, is_new=False)
    if source_zone != policy["source"] or destination_zone != policy["destination"]:
        check_cisco_zbf_new_zone_pair(native, source_zone, destination_zone, exclude_name=policy["name"])
    graph = build_cisco_zbf_graph(native)
    return build_cisco_zbf_edit_native_fragment(
        policy, source_zone, destination_zone, action, application_mode,
        ordered_applications, scopes, log,
        reachability=graph["reachability"], indexes=graph["indexes"],
    )


def validate_cisco_firewall_policy_request(parameters: dict) -> dict:
    """ตรวจ syntax ของคำขอ create_firewall_policy (New/Edit) ก่อนแตะอุปกรณ์ - ใช้ทั้ง
    /command (ก่อนอ่าน config สด) และ /validate (ไม่มี config สดให้เลย) เพราะคำสั่งนี้
    ต้องอ่าน running config สดเพื่อสร้าง payload จริงเสมอ (ชื่อ object ตอน Edit มาจาก
    authoritative graph ไม่ใช่ derive เอง) จึง build payload แบบ offline เต็มไม่ได้ -
    ตรวจได้แค่รูปแบบพารามิเตอร์และ applications/source_scopes ที่ไม่ต้องอาศัยข้อมูล
    จากอุปกรณ์ (ห้ามรายงานว่า zone/ownership/revision ปลอดภัยจากที่นี่)"""
    params = parameters or {}
    name = params.get("name")
    if not isinstance(name, str) or not name.strip():
        raise CiscoZbfError("CISCO_ZBF_INVALID_FIELD", "name is required")
    source_zone = params.get("source_zone")
    destination_zone = params.get("destination_zone")
    if not isinstance(source_zone, str) or not source_zone.strip():
        raise CiscoZbfError("CISCO_ZBF_INVALID_FIELD", "source_zone is required")
    if not isinstance(destination_zone, str) or not destination_zone.strip():
        raise CiscoZbfError("CISCO_ZBF_INVALID_FIELD", "destination_zone is required")
    action = params.get("action", "inspect")
    if action not in ("inspect", "pass", "drop"):
        raise CiscoZbfError("CISCO_ZBF_INVALID_FIELD", f'action "{action}" is invalid (must be inspect/pass/drop)')
    replace_name = params.get("replace_name")
    validate_cisco_zbf_applications(params.get("applications"), allow_custom=bool(replace_name))
    validate_cisco_zbf_source_scopes(params.get("source_scopes", "any"))
    if replace_name is not None and (not isinstance(replace_name, str) or not replace_name.strip()):
        raise CiscoZbfError("CISCO_ZBF_INVALID_FIELD", "replace_name must be a non-empty string if provided")
    expected_revision = params.get("expected_revision")
    if expected_revision is not None and not isinstance(expected_revision, str):
        raise CiscoZbfError("CISCO_ZBF_INVALID_FIELD", "expected_revision must be a string")
    return {
        "name": name.strip(),
        "source_zone": source_zone.strip(),
        "destination_zone": destination_zone.strip(),
        "action": action,
        "source_scopes": params.get("source_scopes", "any"),
        "applications": params.get("applications"),
        "log": bool(params.get("log", False)),
        "replace_name": replace_name.strip() if isinstance(replace_name, str) else None,
        "expected_revision": expected_revision,
    }
