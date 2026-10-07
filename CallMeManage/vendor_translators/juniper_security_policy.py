import copy
import hashlib
from xml.etree import ElementTree as ET
from tools.safe_xml import safe_fromstring
from xml.sax.saxutils import escape

NS_RPC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NS_ROOT = "http://yang.juniper.net/junos-es/conf/root"
NS_SECURITY = "http://yang.juniper.net/junos-es/conf/security"

ET.register_namespace("", NS_SECURITY)
ET.register_namespace("nc", NS_RPC)


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _get_tag_ns(element: ET.Element) -> str:
    if element.tag.startswith("{"):
        return element.tag.split("}", 1)[0] + "}"
    return f"{{{NS_SECURITY}}}"


def compute_policy_fingerprint(
    policy_el: ET.Element, from_zone: str = "", to_zone: str = ""
) -> str:
    """Compute a deterministic SHA-256 revision hash of the canonical policy XML element."""
    def _canon(el: ET.Element):
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
            _canon(c)
            for c in el
            if isinstance(c.tag, str) and not c.tag.startswith("{http://www.w3.org/")
        )
        return (tag, text, attrs, children)

    canon_tuple = (from_zone.strip(), to_zone.strip(), _canon(policy_el))
    normalized = repr(canon_tuple)
    raw_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]
    return f"sha256:{raw_hash}"


def _policy_revision_matches(
    policy_el: ET.Element, from_zone: str, to_zone: str, expected_revision: str | None
) -> bool:
    """เทียบ revision ของ Policy หนึ่งตัวกับที่ client คาดไว้ (ยอมรับหลายรูปแบบย่อ
    เหมือนกับ build_juniper_security_policy_edit_payload/remove_payload) - ไม่มี
    expected_revision ส่งมา = ไม่เช็ค (ตาม flow เดิม)"""
    if not expected_revision or not expected_revision.strip():
        return True
    exp = expected_revision.strip()
    current = compute_policy_fingerprint(policy_el, from_zone=from_zone, to_zone=to_zone)
    legacy = compute_policy_fingerprint(policy_el)
    valid = {
        current, legacy,
        current.replace("sha256:", ""), legacy.replace("sha256:", ""),
        current[:23], current.replace("sha256:", "")[:16], legacy.replace("sha256:", "")[:16],
    }
    return exp in valid


def find_juniper_security_policy(
    root: ET.Element, from_zone: str, to_zone: str, policy_name: str
) -> ET.Element | None:
    """Find the exact inner <policy> element within <from-zone-name> and <to-zone-name>."""
    for pair in root.iter():
        if _local_name(pair.tag) != "policy":
            continue
        fz_el = None
        tz_el = None
        for child in pair:
            tag = _local_name(child.tag)
            if tag == "from-zone-name":
                fz_el = child
            elif tag == "to-zone-name":
                tz_el = child
        if fz_el is not None and tz_el is not None:
            if (fz_el.text or "").strip() == from_zone and (tz_el.text or "").strip() == to_zone:
                for child in pair:
                    if _local_name(child.tag) == "policy":
                        name_el = None
                        for p_child in child:
                            if _local_name(p_child.tag) == "name":
                                name_el = p_child
                                break
                        if name_el is not None and (name_el.text or "").strip() == policy_name:
                            return child
    return None


def inspect_juniper_security_policy(
    policy_el: ET.Element, from_zone: str = "", to_zone: str = ""
) -> dict:
    """Inspect a Juniper <policy> element for representability, brownfield fields, and values."""
    name = ""
    description = None
    scheduler_name = None
    log_info = None
    count_name = None
    action = "unknown"
    action_sub_options = []
    source_addresses: list[str] = []
    destination_addresses: list[str] = []
    applications: list[str] = []

    preserved_fields: list[str] = []
    unsupported_reasons: list[str] = []

    for child in policy_el:
        tag = _local_name(child.tag)
        if tag == "name":
            name = (child.text or "").strip()
        elif tag == "description":
            description = (child.text or "").strip()
            preserved_fields.append("description")
        elif tag == "scheduler-name":
            scheduler_name = (child.text or "").strip()
            preserved_fields.append("scheduler-name")
        elif tag == "report-skip":
            preserved_fields.append("report-skip")
        elif tag in ("apply-groups", "apply-groups-except"):
            preserved_fields.append(tag)
        elif tag == "match":
            for m_child in child:
                m_tag = _local_name(m_child.tag)
                if m_tag == "source-address":
                    val = (m_child.text or "").strip()
                    if val:
                        source_addresses.append(val)
                elif m_tag == "destination-address":
                    val = (m_child.text or "").strip()
                    if val:
                        destination_addresses.append(val)
                elif m_tag == "application":
                    val = (m_child.text or "").strip()
                    if val:
                        applications.append(val)
                elif m_tag in ("source-address-excluded", "destination-address-excluded"):
                    preserved_fields.append(m_tag)
                    unsupported_reasons.append(f"Policy contains {m_tag} which cannot be edited via form")
                else:
                    preserved_fields.append(f"match/{m_tag}")
        elif tag == "then":
            for t_child in child:
                t_tag = _local_name(t_child.tag)
                if t_tag == "permit":
                    action = "permit"
                    for p_sub in t_child:
                        sub_tag = _local_name(p_sub.tag)
                        action_sub_options.append(sub_tag)
                        preserved_fields.append(f"permit/{sub_tag}")
                elif t_tag == "deny":
                    action = "deny"
                    for d_sub in t_child:
                        sub_tag = _local_name(d_sub.tag)
                        action_sub_options.append(sub_tag)
                        preserved_fields.append(f"deny/{sub_tag}")
                elif t_tag == "reject":
                    action = "reject"
                    for r_sub in t_child:
                        sub_tag = _local_name(r_sub.tag)
                        action_sub_options.append(sub_tag)
                        preserved_fields.append(f"reject/{sub_tag}")
                    unsupported_reasons.append("Action reject is not supported by this form")
                elif t_tag == "log":
                    log_opts = [_local_name(l_c.tag) for l_c in t_child]
                    log_info = log_opts if log_opts else True
                    preserved_fields.append("log")
                elif t_tag == "count":
                    count_name = (t_child.text or "").strip() or True
                    preserved_fields.append("count")
                else:
                    preserved_fields.append(f"then/{t_tag}")
        else:
            preserved_fields.append(tag)

    if action == "unknown":
        unsupported_reasons.append("Unknown action is not supported by this form")

    revision = compute_policy_fingerprint(policy_el, from_zone=from_zone, to_zone=to_zone)
    editable = len(unsupported_reasons) == 0

    return {
        "name": name,
        "action": action,
        "action_sub_options": action_sub_options,
        "source_addresses": source_addresses or ["any"],
        "destination_addresses": destination_addresses or ["any"],
        "applications": applications or ["any"],
        "description": description,
        "scheduler_name": scheduler_name,
        "log": log_info,
        "count": count_name,
        "preserved_fields": preserved_fields,
        "unsupported_reasons": unsupported_reasons,
        "has_brownfield_fields": len(preserved_fields) > 0,
        "editable": editable,
        "revision": revision,
    }


def overlay_juniper_security_policy(
    policy_el: ET.Element,
    *,
    action: str | None = None,
    source_addresses: list[str] | None = None,
    destination_addresses: list[str] | None = None,
    applications: list[str] | None = None,
) -> ET.Element:
    """Clone an existing <policy> element and overlay managed fields while preserving all brownfield fields."""
    inspected = inspect_juniper_security_policy(policy_el)
    if not inspected["editable"]:
        raise ValueError(
            f"POLICY_UNSUPPORTED_BROWNFIELD_ACTION: {'; '.join(inspected['unsupported_reasons'])}"
        )

    if action is not None and action != inspected["action"]:
        if action not in ("permit", "deny"):
            raise ValueError(f"POLICY_INVALID_FIELD: Action '{action}' is not supported")
        if inspected["action_sub_options"]:
            sub_names = ", ".join(inspected["action_sub_options"])
            raise ValueError(
                f"POLICY_UNSAFE_EDIT: Cannot change action from '{inspected['action']}' to '{action}' "
                f"because existing policy has options ({sub_names}) that cannot be converted."
            )

    cloned = copy.deepcopy(policy_el)
    ns = _get_tag_ns(policy_el)

    match_el = None
    for child in cloned:
        if _local_name(child.tag) == "match":
            match_el = child
            break
    if match_el is None:
        match_el = ET.SubElement(cloned, f"{ns}match")

    if source_addresses is not None:
        srcs = [a for a in source_addresses if a] or ["any"]
        to_remove = [c for c in match_el if _local_name(c.tag) == "source-address"]
        for c in to_remove:
            match_el.remove(c)
        for addr in srcs:
            new_src = ET.Element(f"{ns}source-address")
            new_src.text = addr
            match_el.append(new_src)

    if destination_addresses is not None:
        dsts = [a for a in destination_addresses if a] or ["any"]
        to_remove = [c for c in match_el if _local_name(c.tag) == "destination-address"]
        for c in to_remove:
            match_el.remove(c)
        for addr in dsts:
            new_dst = ET.Element(f"{ns}destination-address")
            new_dst.text = addr
            match_el.append(new_dst)

    if applications is not None:
        apps = [a for a in applications if a] or ["any"]
        to_remove = [c for c in match_el if _local_name(c.tag) == "application"]
        for c in to_remove:
            match_el.remove(c)
        for app in apps:
            new_app = ET.Element(f"{ns}application")
            new_app.text = app
            match_el.append(new_app)

    if action is not None:
        then_el = None
        for child in cloned:
            if _local_name(child.tag) == "then":
                then_el = child
                break
        if then_el is None:
            then_el = ET.SubElement(cloned, f"{ns}then")

        if action != inspected["action"]:
            action_tags = {"permit", "deny", "reject"}
            to_remove = [c for c in then_el if _local_name(c.tag) in action_tags]
            for c in to_remove:
                then_el.remove(c)
            new_act_el = ET.Element(f"{ns}{action}")
            then_el.append(new_act_el)

    cloned.attrib[f"{{{NS_RPC}}}operation"] = "replace"
    return cloned


def build_juniper_security_policy_edit_payload(
    reference_config: str,
    from_zone: str,
    to_zone: str,
    policy_name: str,
    action: str,
    source_addresses: list[str] | None = None,
    destination_addresses: list[str] | None = None,
    applications: list[str] | None = None,
    expected_revision: str | None = None,
) -> str:
    """Authoritative backend builder for editing a Juniper security policy with Brownfield preservation."""
    root = safe_fromstring(reference_config)
    target_policy_el = find_juniper_security_policy(root, from_zone, to_zone, policy_name)

    if target_policy_el is None:
        raise ValueError(
            f"POLICY_NOT_FOUND: Policy '{policy_name}' not found in Zone pair '{from_zone}' → '{to_zone}' on device"
        )

    current_rev = compute_policy_fingerprint(target_policy_el, from_zone=from_zone, to_zone=to_zone)
    current_rev_legacy = compute_policy_fingerprint(target_policy_el)
    if expected_revision and expected_revision.strip():
        exp = expected_revision.strip()
        valid_revisions = {
            current_rev,
            current_rev_legacy,
            current_rev.replace("sha256:", ""),
            current_rev_legacy.replace("sha256:", ""),
            current_rev[:23],
            current_rev.replace("sha256:", "")[:16],
            current_rev_legacy.replace("sha256:", "")[:16],
        }
        if exp not in valid_revisions:
            raise ValueError(
                f"POLICY_CONCURRENT_MODIFICATION: Policy '{policy_name}' ({from_zone} → {to_zone}) "
                f"was modified after you opened this page. Please refresh and review. The policy has not been saved or deleted"
            )

    updated_policy_el = overlay_juniper_security_policy(
        target_policy_el,
        action=action,
        source_addresses=source_addresses,
        destination_addresses=destination_addresses,
        applications=applications,
    )

    raw_inner_xml = ET.tostring(updated_policy_el, encoding="unicode").strip()

    return f"""<rpc xmlns="{NS_RPC}">
  <edit-config>
    <target>
      <candidate/>
    </target>
    <config>
      <configuration xmlns="{NS_ROOT}">
        <security xmlns="{NS_SECURITY}">
          <policies>
            <policy>
              <from-zone-name>{escape(from_zone)}</from-zone-name>
              <to-zone-name>{escape(to_zone)}</to-zone-name>
              {raw_inner_xml}
            </policy>
          </policies>
        </security>
      </configuration>
    </config>
  </edit-config>
</rpc>"""


def build_juniper_security_policy_remove_payload(
    reference_config: str,
    from_zone: str,
    to_zone: str,
    policy_name: str,
    expected_revision: str | None = None,
) -> str:
    """Authoritative backend builder for removing a Juniper security policy with revision check."""
    root = safe_fromstring(reference_config)
    target_policy_el = find_juniper_security_policy(root, from_zone, to_zone, policy_name)

    if target_policy_el is None:
        raise ValueError(
            f"POLICY_NOT_FOUND: Policy '{policy_name}' not found in Zone pair '{from_zone}' → '{to_zone}' on device"
        )

    current_rev = compute_policy_fingerprint(target_policy_el, from_zone=from_zone, to_zone=to_zone)
    current_rev_legacy = compute_policy_fingerprint(target_policy_el)
    if expected_revision and expected_revision.strip():
        exp = expected_revision.strip()
        valid_revisions = {
            current_rev,
            current_rev_legacy,
            current_rev.replace("sha256:", ""),
            current_rev_legacy.replace("sha256:", ""),
            current_rev[:23],
            current_rev.replace("sha256:", "")[:16],
            current_rev_legacy.replace("sha256:", "")[:16],
        }
        if exp not in valid_revisions:
            raise ValueError(
                f"POLICY_CONCURRENT_MODIFICATION: Policy '{policy_name}' ({from_zone} → {to_zone}) "
                f"was modified after you opened this page. Please refresh and review. The policy has not been saved or deleted"
            )

    return f"""<rpc xmlns="{NS_RPC}">
  <edit-config>
    <target>
      <candidate/>
    </target>
    <config>
      <configuration xmlns="{NS_ROOT}">
        <security xmlns="{NS_SECURITY}">
          <policies>
            <policy>
              <from-zone-name>{escape(from_zone)}</from-zone-name>
              <to-zone-name>{escape(to_zone)}</to-zone-name>
              <policy xmlns:nc="{NS_RPC}" nc:operation="remove">
                <name>{escape(policy_name)}</name>
              </policy>
            </policy>
          </policies>
        </security>
      </configuration>
    </config>
  </edit-config>
</rpc>"""


def compute_zone_pair_order_revision(
    policy_names: list[str], from_zone: str = "", to_zone: str = ""
) -> str:
    """Compute a deterministic hash representing the exact ordering of policies in a zone pair."""
    token = f"{from_zone.strip()}->{to_zone.strip()}:" + "|".join(name.strip() for name in policy_names if name.strip())
    raw_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]
    return f"order:{raw_hash}"


def get_juniper_security_policies_in_zone(
    root: ET.Element, from_zone: str, to_zone: str
) -> list[str]:
    """Return an ordered list of policy names in the given (from_zone, to_zone) pair."""
    for pair in root.iter():
        if _local_name(pair.tag) != "policy":
            continue
        fz_el = None
        tz_el = None
        for child in pair:
            tag = _local_name(child.tag)
            if tag == "from-zone-name":
                fz_el = child
            elif tag == "to-zone-name":
                tz_el = child
        if fz_el is not None and tz_el is not None:
            if (fz_el.text or "").strip() == from_zone and (tz_el.text or "").strip() == to_zone:
                names: list[str] = []
                for child in pair:
                    if _local_name(child.tag) == "policy":
                        for p_child in child:
                            if _local_name(p_child.tag) == "name":
                                name = (p_child.text or "").strip()
                                if name:
                                    names.append(name)
                                break
                return names
    return []


POLICY_MOVE_DIRECTIONS = ("up", "down")


def parse_security_policy_reference(reply: str) -> ET.Element:
    """ยืนยันว่าอ่าน Security Policy จากอุปกรณ์สำเร็จจริงก่อนนำไปคำนวณลำดับ

    ลำดับ Policy มีผลกับ Traffic - ถ้าอุปกรณ์ตอบ rpc-error หรือ XML เสีย ต้องหยุด
    ห้ามตีความเป็น "ไม่มี Policy" แล้วไปคำนวณตำแหน่งจาก config ว่าง"""
    try:
        root = safe_fromstring(reply)
    except (ET.ParseError, TypeError) as exc:
        raise ValueError(f"POLICY_READ_FAILED: Failed to read Security Policy from device (invalid XML: {exc})")
    for error in root.iter():
        if _local_name(error.tag) != "rpc-error":
            continue
        severity = next((c.text or "" for c in error if _local_name(c.tag) == "error-severity"), "error")
        if severity.strip().lower() == "warning":
            continue
        message = next((c.text or "" for c in error if _local_name(c.tag) == "error-message"), "").strip()
        raise ValueError(
            "POLICY_READ_FAILED: Device rejected reading Security Policy" + (f": {message}" if message else "")
        )
    if not any(_local_name(el.tag) == "data" for el in root.iter()):
        raise ValueError("POLICY_READ_FAILED: Reply from device contains no configuration data")
    return root


def validate_juniper_security_policy_move_request(parameters: dict) -> dict:
    """ตรวจ request ของปุ่มเลื่อนก่อนแตะอุปกรณ์ (ใช้ทั้ง /command และ /validate)

    หน้าเว็บส่งแค่ identity + ทิศ + revision ที่เห็นอยู่ ส่วน Policy ข้างเคียงต้อง
    คำนวณจาก Running Configuration ล่าสุดภายใน DeviceLock เท่านั้น จึงรับเฉพาะ up/down
    และไม่รับ before_policy/after_policy/reference_config จาก client
    ไม่มี order revision = ไม่รู้ว่าผู้ใช้เห็นลำดับไหน ต้องปฏิเสธ ไม่ข้ามการตรวจเงียบ ๆ"""
    params = parameters or {}
    identity = {}
    for key in ("from_zone", "to_zone", "policy_name"):
        value = params.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"POLICY_MOVE_INVALID: {key} is required")
        identity[key] = value.strip()
    direction = str(params.get("direction") or "").strip().lower()
    if direction not in POLICY_MOVE_DIRECTIONS:
        raise ValueError(
            f"POLICY_ORDER_UNSUPPORTED: Invalid move direction '{params.get('direction')}' (supported: up, down)"
        )
    order_revision = params.get("expected_order_revision") or params.get("revision")
    if not isinstance(order_revision, str) or not order_revision.strip():
        raise ValueError(
            "POLICY_ORDER_REVISION_REQUIRED: Missing current policy order information. "
            "Please refresh and try moving again. No commands were sent to the device."
        )
    expected_revision = params.get("expected_revision")
    if expected_revision is not None and not isinstance(expected_revision, str):
        raise ValueError("POLICY_MOVE_INVALID: expected_revision must be a string")
    return {
        **identity,
        "direction": direction,
        "expected_order_revision": order_revision.strip(),
        "expected_revision": (expected_revision or "").strip() or None,
    }


def juniper_security_policy_move_fragment(
    reference_config: str,
    from_zone: str,
    to_zone: str,
    policy_name: str,
    direction: str = "up",
    before_policy: str | None = None,
    after_policy: str | None = None,
    expected_order_revision: str | None = None,
    expected_revision: str | None = None,
) -> str:
    """คำนวณตำแหน่งใหม่จาก Running Configuration ล่าสุด แล้วคืน <security> fragment
    ที่ย้าย "เฉพาะลำดับ" (insert before/after) - ไม่มี match/then จึงไม่แตะ body ของ Policy
    และระบุคู่ Zone ครบทุกครั้งจึงย้ายข้ามคู่ Zone ไม่ได้"""
    root = parse_security_policy_reference(reference_config)
    policies = get_juniper_security_policies_in_zone(root, from_zone, to_zone)

    if policy_name not in policies:
        raise ValueError(
            f"POLICY_NOT_FOUND: Policy '{policy_name}' not found in Zone pair '{from_zone}' → '{to_zone}' on device"
        )

    current_order_rev = compute_zone_pair_order_revision(policies, from_zone, to_zone)
    if expected_order_revision and expected_order_revision.strip():
        exp = expected_order_revision.strip()
        valid_revisions = {
            current_order_rev,
            current_order_rev.replace("order:", ""),
            current_order_rev[:23],
            current_order_rev.replace("order:", "")[:16],
        }
        if exp not in valid_revisions:
            raise ValueError(
                f"POLICY_ORDER_CONCURRENT_MODIFICATION: Policy order in Zone pair '{from_zone}' → '{to_zone}' "
                f"was modified after you opened this page. Please refresh before moving"
            )

    if expected_revision and expected_revision.strip():
        target_el = find_juniper_security_policy(root, from_zone, to_zone, policy_name)
        if target_el is not None:
            cur_p_rev = compute_policy_fingerprint(target_el, from_zone=from_zone, to_zone=to_zone)
            cur_p_legacy = compute_policy_fingerprint(target_el)
            exp_p = expected_revision.strip()
            valid_p_revs = {
                cur_p_rev,
                cur_p_legacy,
                cur_p_rev.replace("sha256:", ""),
                cur_p_legacy.replace("sha256:", ""),
                cur_p_rev[:23],
                cur_p_rev.replace("sha256:", "")[:16],
            }
            if exp_p not in valid_p_revs:
                raise ValueError(
                    f"POLICY_ORDER_CONCURRENT_MODIFICATION: Policy '{policy_name}' ({from_zone} → {to_zone}) "
                    f"was modified after you opened this page. Please refresh before moving"
                )

    idx = policies.index(policy_name)
    dir_norm = direction.lower().strip()

    if dir_norm == "up":
        if idx == 0:
            raise ValueError(
                f"POLICY_MOVE_NOT_POSSIBLE: Policy '{policy_name}' is already at the first position in Zone pair '{from_zone}' → '{to_zone}' and cannot be moved up"
            )
        neighbor = policies[idx - 1]
        insert_attr = "before"
        ref_name = neighbor
    elif dir_norm == "down":
        if idx == len(policies) - 1:
            raise ValueError(
                f"POLICY_MOVE_NOT_POSSIBLE: Policy '{policy_name}' is already at the last position in Zone pair '{from_zone}' → '{to_zone}' and cannot be moved down"
            )
        neighbor = policies[idx + 1]
        insert_attr = "after"
        ref_name = neighbor
    elif dir_norm == "before":
        ref = before_policy
        if not ref or ref not in policies:
            raise ValueError(f"POLICY_MOVE_NOT_POSSIBLE: Reference policy '{ref}' not found in the same Zone pair")
        if ref == policy_name:
            raise ValueError("POLICY_MOVE_NOT_POSSIBLE: Cannot move policy relative to itself")
        insert_attr = "before"
        ref_name = ref
    elif dir_norm == "after":
        ref = after_policy
        if not ref or ref not in policies:
            raise ValueError(f"POLICY_MOVE_NOT_POSSIBLE: Reference policy '{ref}' not found in the same Zone pair")
        if ref == policy_name:
            raise ValueError("POLICY_MOVE_NOT_POSSIBLE: Cannot move policy relative to itself")
        insert_attr = "after"
        ref_name = ref
    else:
        raise ValueError(f"POLICY_ORDER_UNSUPPORTED: Invalid move direction '{direction}' (supported: up, down, before, after)")

    return f"""<security xmlns="{NS_SECURITY}">
  <policies>
    <policy>
      <from-zone-name>{escape(from_zone)}</from-zone-name>
      <to-zone-name>{escape(to_zone)}</to-zone-name>
      <policy insert="{insert_attr}" name="{escape(ref_name, {'"': '&quot;'})}">
        <name>{escape(policy_name)}</name>
      </policy>
    </policy>
  </policies>
</security>"""


def build_juniper_security_policy_move_payload(reference_config: str, *args, **kwargs) -> str:
    """ห่อ fragment เป็น edit-config เต็ม (ใช้ในชุดทดสอบ) - คำสั่งจริงผ่าน
    juniper_junos.move_security_policy ซึ่งห่อด้วย _edit_configuration ที่มี message-id"""
    fragment = juniper_security_policy_move_fragment(reference_config, *args, **kwargs)
    return f"""<rpc xmlns="{NS_RPC}">
  <edit-config>
    <target>
      <candidate/>
    </target>
    <config>
      <configuration xmlns="{NS_ROOT}">
        {fragment}
      </configuration>
    </config>
  </edit-config>
</rpc>"""


def validate_juniper_security_policy_zone_move_request(parameters: dict) -> dict:
    """ตรวจ request ของ Edit ที่เปลี่ยนคู่ Zone (ย้าย Policy ข้ามคู่ Zone) ก่อนแตะอุปกรณ์
    เหมือน validate_juniper_security_policy_move_request (คำสั่งเลื่อนลำดับ) แต่ตรวจ
    identity ปลายทางเพิ่ม และ field ที่แก้ไปพร้อมกันได้ (action/addresses/applications)
    ไม่มี confirm_replace_existing เพราะปลายทางชนชื่อ Policy เดิมต้องถูกปฏิเสธเสมอ
    ห้ามเขียนทับอัตโนมัติ (ต่างจาก set_security_policy ที่ยืนยันแล้วเขียนทับได้)"""
    params = parameters or {}
    identity = {}
    for key in ("from_zone", "to_zone", "policy_name", "new_from_zone", "new_to_zone"):
        value = params.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"POLICY_MOVE_INVALID: {key} is required")
        identity[key] = value.strip()
    if (identity["from_zone"], identity["to_zone"]) == (identity["new_from_zone"], identity["new_to_zone"]):
        raise ValueError(
            "POLICY_MOVE_SAME_ZONE_PAIR: Destination Zone pair is identical to source Zone pair; not a move"
        )
    action = params.get("action")
    if action not in ("permit", "deny"):
        raise ValueError(f"POLICY_INVALID_FIELD: Action '{action}' is not supported")

    def _str_list(value, field):
        if value is None:
            return None
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"POLICY_MOVE_INVALID: {field} must be a list of strings")
        return value

    expected_revision = params.get("expected_revision")
    if expected_revision is not None and not isinstance(expected_revision, str):
        raise ValueError("POLICY_MOVE_INVALID: expected_revision must be a string")
    return {
        **identity,
        "action": action,
        "source_addresses": _str_list(params.get("source_addresses"), "source_addresses"),
        "destination_addresses": _str_list(params.get("destination_addresses"), "destination_addresses"),
        "applications": _str_list(params.get("applications"), "applications"),
        "expected_revision": (expected_revision or "").strip() or None,
    }


def build_juniper_security_policy_zone_move_fragment(
    reference_config: str,
    from_zone: str,
    to_zone: str,
    policy_name: str,
    new_from_zone: str,
    new_to_zone: str,
    action: str,
    source_addresses: list[str] | None = None,
    destination_addresses: list[str] | None = None,
    applications: list[str] | None = None,
    expected_revision: str | None = None,
) -> str:
    """ย้าย Policy ข้ามคู่ Zone แบบ atomic เดียว - ลบ entry เดิมและสร้าง entry ใหม่ใน
    edit-config เดียวกัน (candidate + commit ครั้งเดียวตาม flow เดิมของ conn_socket.py)
    ป้องกันเคส "ลบสำเร็จแต่สร้างล้มเหลว" ที่จะทำให้ Policy หายถ้ายิง 2 API call แยกกัน
    (ลบก่อนแล้วค่อยสร้าง) - ทั้งสอง <policy> (zone-pair container) เป็น list entry คนละ
    ตัวกันอยู่แล้วตาม YANG (คีย์คือ from-zone-name+to-zone-name) จึงส่งมาด้วยกันใน
    <policies> เดียวได้โดยไม่ต้อง replace container ไหนทั้งคู่ - ฝั่งต้นทางใช้
    nc:operation="remove" กับ entry ชื่อ policy_name เท่านั้น (ไม่กระทบ Policy อื่นใน
    zone pair เดิม) ฝั่งปลายทางเป็น merge/create entry ใหม่ (ไม่กระทบ Policy อื่นที่มี
    อยู่แล้วใน zone pair ปลายทาง) - Policy ที่ย้ายจะไปอยู่ท้ายลำดับของ zone pair ปลายทาง
    เสมอ (เหมือน Policy ที่สร้างใหม่ทุกตัว) ผู้ใช้ใช้ปุ่มเลื่อนลำดับจัดตำแหน่งเองทีหลังได้

    body ของ Policy (match/then/Brownfield) clone มาจากต้นทางทั้งหมดแล้ว overlay เฉพาะ
    field ที่ผู้ใช้แก้ในฟอร์ม (เหมือน build_juniper_security_policy_edit_payload) จึงไม่
    สูญเสีย log/count/description/scheduler-name หรือ configuration ชั้นในอื่นที่ฟอร์ม
    ไม่ได้แสดง/แก้"""
    root = parse_security_policy_reference(reference_config)

    source_el = find_juniper_security_policy(root, from_zone, to_zone, policy_name)
    if source_el is None:
        raise ValueError(
            f"POLICY_NOT_FOUND: Policy '{policy_name}' not found in Zone pair '{from_zone}' → '{to_zone}' on device"
        )

    # Policy ที่ parser ระบุว่าแก้ผ่านฟอร์มไม่ได้ (เช่น action=reject/unknown) ต้องยังล็อกไว้
    # เหมือนเดิม - ห้ามใช้การย้ายข้ามคู่ Zone เป็นทางอ้อมเพื่อ "แก้" field ที่ฟอร์มไม่รองรับ
    inspected = inspect_juniper_security_policy(source_el, from_zone=from_zone, to_zone=to_zone)
    if not inspected["editable"]:
        raise ValueError(
            f"POLICY_UNSUPPORTED_BROWNFIELD_ACTION: {'; '.join(inspected['unsupported_reasons'])}"
        )

    if not _policy_revision_matches(source_el, from_zone, to_zone, expected_revision):
        raise ValueError(
            f"POLICY_CONCURRENT_MODIFICATION: Policy '{policy_name}' ({from_zone} → {to_zone}) "
            f"was modified after you opened this page. Please refresh and review. The policy has not been moved"
        )

    if find_juniper_security_policy(root, new_from_zone, new_to_zone, policy_name) is not None:
        raise ValueError(
            f"POLICY_MOVE_DESTINATION_EXISTS: Policy '{policy_name}' already exists in destination Zone pair "
            f"'{new_from_zone}' → '{new_to_zone}' on device and cannot be overwritten"
        )

    new_policy_el = overlay_juniper_security_policy(
        source_el,
        action=action,
        source_addresses=source_addresses,
        destination_addresses=destination_addresses,
        applications=applications,
    )
    # overlay_juniper_security_policy ใส่ nc:operation="replace" มาด้วยเสมอ (ไว้แทนที่
    # entry เดิมตอน edit ธรรมดาในคู่ Zone เดียวกัน) - ปลายทางของการย้ายไม่มี entry เดิมให้
    # แทนที่ (เพิ่งเช็ค collision ไปแล้วว่าไม่มี) จึงตัด attribute ออกให้เป็น merge/create
    # รายการใหม่ตามปกติ
    op_key = f"{{{NS_RPC}}}operation"
    if op_key in new_policy_el.attrib:
        del new_policy_el.attrib[op_key]
    raw_new_xml = ET.tostring(new_policy_el, encoding="unicode").strip()

    return f"""<security xmlns="{NS_SECURITY}">
  <policies>
    <policy>
      <from-zone-name>{escape(from_zone)}</from-zone-name>
      <to-zone-name>{escape(to_zone)}</to-zone-name>
      <policy xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(policy_name)}</name>
      </policy>
    </policy>
    <policy>
      <from-zone-name>{escape(new_from_zone)}</from-zone-name>
      <to-zone-name>{escape(new_to_zone)}</to-zone-name>
      {raw_new_xml}
    </policy>
  </policies>
</security>"""
