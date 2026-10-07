import re
from xml.etree import ElementTree as ET


from tools.safe_xml import safe_fromstring
def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _child_text(element, *names: str) -> str:
    wanted = set(names)
    for child in element:
        if _local_name(child.tag) in wanted and child.text:
            return child.text.strip()
    return ""


def _deep_text(element, *names: str) -> str:
    """เหมือน _child_text แต่ค้นลึกกว่าลูกตรง 1 ชั้น - Huawei get_ip_interface_brief
    ห่อ ifIpAddr ไว้ใน <ipv4Config> อีกชั้น เลย _child_text ธรรมดาหาไม่เจอ"""
    wanted = set(names)
    for descendant in element.iter():
        if descendant is element:
            continue
        if _local_name(descendant.tag) in wanted and descendant.text and descendant.text.strip():
            return descendant.text.strip()
    return ""


def _first_element(root, name: str):
    """Return the first descendant whose local XML name matches ``name``."""
    return next((element for element in root.iter() if _local_name(element.tag) == name), None)


def _readable_state(value: str) -> str:
    """Turn vendor enum values such as reg-state-not-registered into UI text."""
    value = (value or "").strip()
    for prefix in ("reg-state-", "auth-state-", "license-state-"):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
            break
    return " ".join(part.capitalize() for part in value.replace("_", "-").split("-") if part)


def normalize_device_version(vendor: str, xml_response: str) -> dict:
    """Normalize the live software identity verified in z*Version.txt.

    Only the two concepts genuinely shared by all three replies are exposed:
    operating system/platform and software version. The full Cisco banner is
    retained for diagnostics, but the UI uses its concise ``Version x.y`` part.
    """
    root = safe_fromstring(xml_response)
    platform = ""
    software_version = ""
    full_version = ""

    if vendor == "cisco":
        system_data = _first_element(root, "device-system-data")
        full_version = _child_text(system_data, "software-version") if system_data is not None else ""
        match = re.search(r"\bVersion\s+([^,\s]+)", full_version, flags=re.IGNORECASE)
        software_version = match.group(1) if match else full_version.splitlines()[0] if full_version else ""
        platform = "Cisco IOS XE"
    elif vendor == "huawei":
        system_info = _first_element(root, "systemInfo")
        if system_info is not None:
            platform = _child_text(system_info, "platformName") or "Huawei VRP"
            software_version = (
                _child_text(system_info, "productVer")
                or _child_text(system_info, "platformVer")
            )
            full_version = _child_text(system_info, "sysDesc")
    elif vendor == "juniper":
        software_info = _first_element(root, "software-information")
        if software_info is not None:
            raw_os = _child_text(software_info, "os-name")
            platform = "Juniper Junos" if raw_os.lower().startswith("junos") else raw_os
            software_version = _child_text(software_info, "junos-version")

    return {
        "vendor": vendor,
        "platform": platform,
        "software_version": software_version,
        "full_version": full_version,
    }


def normalize_device_license(vendor: str, xml_response: str) -> dict:
    """Normalize common product/license inventory fields from real replies.

    Huawei's captured RPC does not expose license state; it exposes only
    product/version/ESN. Status therefore remains blank rather than guessed.
    """
    root = safe_fromstring(xml_response)
    rows = []

    if vendor == "cisco":
        state = _first_element(root, "state")
        udi = _first_element(state, "udi") if state is not None else None
        registration = _deep_text(state, "registration-state") if state is not None else ""
        authorization = _deep_text(state, "authorization-state") if state is not None else ""
        status_parts = [_readable_state(value) for value in (registration, authorization) if value]
        if udi is not None or state is not None:
            rows.append({
                "name": _child_text(udi, "pid") if udi is not None else "Smart Licensing",
                "version": _child_text(state, "version") if state is not None else "",
                "serial_number": _child_text(udi, "sn") if udi is not None else "",
                "status": " / ".join(status_parts),
            })
    elif vendor == "huawei":
        system_info = _first_element(root, "systemInfo")
        if system_info is not None:
            rows.append({
                "name": _child_text(system_info, "productName"),
                "version": _child_text(system_info, "productVer"),
                "serial_number": _child_text(system_info, "esn"),
                "status": "",
            })
    elif vendor == "juniper":
        for license_element in root.iter():
            if _local_name(license_element.tag) != "license":
                continue
            rows.append({
                "name": _child_text(license_element, "name"),
                "version": _child_text(license_element, "license-version"),
                "serial_number": _child_text(license_element, "software-sn"),
                "status": _readable_state(_child_text(license_element, "license-state")),
            })

    return {"vendor": vendor, "licenses": rows}


def _cidr_to_netmask(cidr_ip: str) -> str:
    """Junos ifa-local ตามธรรมเนียมมาเป็น CIDR เช่น "10.0.0.5/24" (ไม่มี leaf
    subnet-mask แยกต่างหากใน schema เลย) - แยก prefix length ออกมาคำนวณเป็น
    dotted netmask ด้วยคณิตศาสตร์ล้วนๆ ไม่ได้เดาชื่อ tag ใดๆ เพิ่ม แต่ยัง
    "ไม่เคยเทียบกับอุปกรณ์ Junos จริง" ว่า ifa-local จะมี /prefix ต่อท้ายมาจริง
    ไหม (ไม่มีเครื่อง Junos ให้ทดสอบในเซสชันนี้) - คืน "" ถ้า parse ไม่ได้"""
    if "/" not in cidr_ip:
        return ""
    try:
        prefix_length = int(cidr_ip.rsplit("/", 1)[1])
        if not 0 <= prefix_length <= 32:
            return ""
    except ValueError:
        return ""
    mask_bits = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF
    return ".".join(str((mask_bits >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def normalize_interfaces(vendor: str, xml_response: str) -> list[dict]:
    """Parse a get_interface_information / get_ip_interface_brief NETCONF
    reply into the shared vendor-neutral interface format.

    Field names verified per vendor against the real YANG schema in
    device_capability/ (not guessed):
    - Cisco IOS-XE (Cisco-IOS-XE-interfaces-oper.yang / ietf-interfaces.yang):
      ipv4 (leaf), ipv4-subnet-mask (leaf - note the HYPHEN; an earlier version
      of this function searched "ipv4_subnet-mask" with an underscore, which
      never matched anything and silently left "subnet" blank for Cisco),
      admin-status/oper-status, last-change.
    - Huawei VRP (huawei-ifm.yang, ipv4Config/am4CfgAddrs/am4CfgAddr): ifIpAddr,
      subnetMask (camelCase, different convention from Cisco's), ifAdminStatus.
      ifOperStatus/lineProtocolUpTime อยู่ใต้ ifDynamicInfo; query ขอทั้งสองค่า
      และ branch Huawei อ่านแบบ deep เพื่อส่ง operational status ให้หน้าเว็บ.
    - Junos (junos-es-rpc-interfaces.yang): each physical-interface can contain
      multiple logical-interface children (one per configured unit, e.g.
      ge-0/0/0.0, ge-0/0/0.16) each with its own "name" (already carries the
      unit suffix, same convention as Cisco's GigabitEthernet1.10), and - in
      most of the several near-identical logical-interface list variants
      found in this schema file - its own admin-status/oper-status too. To
      avoid a physical-interface row picking up one arbitrary child unit's
      IP, physical rows are retained with a blank IP and logical units remain
      separate rows. ifa-local is the per-unit IP; Junos has no separate subnet-
      mask leaf, but ifa-local conventionally carries the address as CIDR
      (e.g. "10.0.0.5/24") - _cidr_to_netmask() converts that suffix into a
      dotted mask. last-change equivalent is "interface-flapped" (a free-form
      string, not a structured timestamp), and logical rows inherit that
      physical timestamp because Junos does not report a separate unit flap.
      CAVEAT: none of the Junos-specific field names/behavior above have been
      verified against a live Junos device in this session (no Junos device
      was available to test against, unlike the Cisco/Huawei fields, which
      were checked against real device replies) - schema-based best effort.
    """
    root = safe_fromstring(xml_response)
    interfaces = []
    parents = {child: parent for parent in root.iter() for child in parent} if vendor == "juniper" else {}
    for element in root.iter():
        tag = _local_name(element.tag)
        if tag not in {"interface", "physical-interface", "logical-interface"}:
            continue
        name = _child_text(element, "name", "interface-name", "ifName")
        if not name:
            continue

        # Junos physical-interface contains logical-interface descendants. Its
        # IP must stay blank instead of borrowing the first unit's ifa-local.
        ip = ("" if vendor == "juniper" and tag == "physical-interface"
              else _deep_text(element, "ipv4", "ip-address", "address", "ifIpAddr", "ifa-local"))
        subnet = _deep_text(element, "ipv4-subnet-mask", "subnetMask")
        if not subnet and "/" in ip:
            subnet = _cidr_to_netmask(ip)
            ip = ip.split("/", 1)[0]

        row = {
            "name": name,
            "ip": ip,
            "subnet": subnet,
            "admin_status": _child_text(element, "admin-status", "ifAdminStatus"),
            # Huawei วาง ifOperStatus ไว้ใต้ ifDynamicInfo ต่างจาก Cisco/Juniper
            # ที่เป็นลูกตรงของ interface; หน้าเว็บใช้ oper_status เป็น Status เสมอ.
            "oper_status": (_deep_text(element, "ifOperStatus") if vendor == "huawei"
                            else _child_text(element, "oper-status", "ifOperStatus")),
            "last_change": (_child_text(element, "interface-flapped") if vendor == "juniper"
                            else _deep_text(element, "last-change", "lineProtocolUpTime")),
            "description": _child_text(element, "description", "ifDescr"),
        }
        if vendor == "juniper" and tag == "logical-interface":
            parent = parents.get(element)
            if parent is not None and _local_name(parent.tag) == "physical-interface":
                parent_admin = _child_text(parent, "admin-status")
                # A logical unit cannot be administratively enabled while its
                # physical parent is disabled; retain unit-specific down state.
                if parent_admin.lower() == "down" or not row["admin_status"]:
                    row["admin_status"] = parent_admin or row["admin_status"]
                # Last flapped is physical state in Junos extensive output.
                # Logical units inherit it so every displayed child has a
                # meaningful Last Change value without a second RPC.
                if not row["last_change"]:
                    row["last_change"] = _child_text(parent, "interface-flapped")
        # ifMtu เป็น field ของ huawei-ifm เท่านั้น; ไม่เพิ่ม key ให้ Cisco/Juniper
        # เพื่อคง response shape เดิมของสองยี่ห้อที่ผ่านอุปกรณ์จริงแล้ว.
        if vendor == "huawei":
            row["mtu"] = _child_text(element, "ifMtu")
            # Preserve every configured IPv4 key for destructive transitions
            # such as routed port -> switchport. The legacy ip/subnet fields
            # above intentionally remain the first address for table display.
            row["addresses"] = [
                address
                for entry in element.iter()
                if _local_name(entry.tag) == "am4CfgAddr"
                for address in [_child_text(entry, "ifIpAddr")]
                if address
            ]
        interfaces.append(row)
    return interfaces



# Huawei get_interface_list ใช้ dropdown ร่วมกับ Cisco/Juniper จึงคง row format
# จาก normalize_interfaces เดิมทั้งหมด แล้วกรองเฉพาะ NULL0 ที่ huawei-ifm.yang
# ระบุเป็นชื่อ interface ได้แต่ใช้งานเป็น next-hop/physical port ไม่ได้. MEth และ
# Vlanif คงไว้ตามผู้ใช้เลือก เพราะเป็น interface ที่อาจต้องเลือกใน static route.
def normalize_interface_list(vendor: str, xml_response: str) -> list[dict]:
    rows = normalize_interfaces(vendor, xml_response)
    if vendor != "huawei":
        return rows
    return [row for row in rows if (row.get("name") or "").strip().upper() != "NULL0"]


def normalize_arp(vendor: str, xml_response: str) -> list[dict]:
    """Parse a get_arp_table NETCONF reply into the shared vendor-neutral ARP
    format. Cisco replies with the deprecated arp-vrf/arp-oper list (NOT the
    newer arp-entry list the YANG model recommends - confirmed against a real
    IOS-XE device, the schema's "arp-entry" is defined but the device doesn't
    actually emit it) with address/interface/hardware/type/time. Junos: arp-
    table-information/arp-table-entry (ip-address/mac-address/interface-name/
    state/time-to-expire). Huawei: arpTables/arpTable (ipAddr/macAddr/ifName/
    styleType/expireTime)."""
    root = safe_fromstring(xml_response)
    entries = []
    for element in root.iter():
        if _local_name(element.tag) not in {"arp-oper", "arp-entry", "arpTable", "arp-table-entry"}:
            continue
        ip = _child_text(element, "address", "ip-address", "ipAddr")
        if not ip:
            continue
        entries.append({
            "ip": ip,
            "mac": _child_text(element, "hardware", "mac-address", "macAddr"),
            "interface": _child_text(element, "interface", "interface-name", "ifName"),
            "type": _child_text(element, "type", "state", "styleType"),
            "age": _child_text(element, "time", "time-to-expire", "expireTime"),
        })
    return entries


def normalize_ospf(vendor: str, xml_response: str) -> dict:
    """Parse a get_ospf_information NETCONF reply - Cisco only, verified
    against a real IOS-XE device with live OSPF config. Juniper models OSPF
    completely differently (area/interface-based, no process-id concept) and
    Huawei has no OSPF YANG module over NETCONF at all (confirmed earlier
    this session via live CLI testing) so other vendors fall back to the
    generic structural dump instead of guessing field names untested."""
    if vendor != "cisco":
        return normalize_generic(vendor, xml_response)

    root = safe_fromstring(xml_response)
    process_element = None
    for element in root.iter():
        if _local_name(element.tag) == "process-id":
            process_element = element
            break
    if process_element is None:
        return {
            "process_id": None,
            "router_id": "",
            "default_information_originate": False,
            "passive_interface_default": False,
            "redistribute_static": False,
            "redistribute_rip": False,
            "networks": [],
            "active_interfaces": [],
        }

    child_names = {_local_name(child.tag) for child in process_element}

    networks = [
        {
            "network": _child_text(child, "ip"),
            "wildcard": _child_text(child, "wildcard"),
            "area": _child_text(child, "area"),
        }
        for child in process_element
        if _local_name(child.tag) == "network"
    ]

    # passive-interface-config/disable-interface คือ interface ที่ "ไม่ passive"
    # (เพราะ passive-interface default เป็น true ทั้ง process - อันไหนอยู่ใน
    # disable-interface list แปลว่าเปิด OSPF ใช้งานจริงบน interface นั้น)
    active_interfaces = []
    for element in process_element.iter():
        if _local_name(element.tag) != "disable-interface":
            continue
        for interface_el in element:
            name = _child_text(interface_el, "name")
            if name:
                active_interfaces.append(f"{_local_name(interface_el.tag)}{name}")

    passive_default = False
    for element in process_element.iter():
        if _local_name(element.tag) == "passive-interface":
            passive_default = _child_text(element, "default").lower() == "true"
            break

    # redistribute/static + redistribute/rip เป็น presence container ซ้อนอยู่ใต้
    # <redistribute> ตัวเดียวกัน (ดู set_ospf_redistribute_static/
    # set_ospf_redistribute_rip) - เช็คว่ามี <static>/<rip> ลูกอยู่ไหม ไม่ใช่แค่
    # เช็ค "redistribute" in child_names เฉยๆ เพราะ <redistribute> เองก็เป็น
    # presence container ที่มี route-type ลูกอื่นได้ในอนาคต (bgp เป็นต้น)
    redistribute_static = False
    redistribute_rip = False
    for element in process_element:
        if _local_name(element.tag) != "redistribute":
            continue
        redist_children = {_local_name(child.tag) for child in element}
        redistribute_static = "static" in redist_children
        redistribute_rip = "rip" in redist_children
        break

    return {
        "process_id": _child_text(process_element, "id"),
        "router_id": _child_text(process_element, "router-id"),
        "default_information_originate": "default-information" in child_names,
        "passive_interface_default": passive_default,
        "redistribute_static": redistribute_static,
        "redistribute_rip": redistribute_rip,
        "networks": networks,
        "active_interfaces": active_interfaces,
    }


# get_ospf_dashboard รวม 3 query (ospf/routing-table/interface-brief) ไว้ใน
# XML reply เดียว - เรียก normalize_ospf/normalize_interfaces ซ้ำบน XML เดียวกัน
# ได้ตรงๆ เพราะทั้งคู่เดินด้วย root.iter() (หา element ที่ต้องการได้จากที่ไหนก็
# ได้ในทรี ไม่สนใจว่ามี sibling อื่นปนมาด้วยหรือไม่ - ไม่ต้องพึ่ง path ตายตัว)
# ส่วน routing table ยังไม่มี normalizer เฉพาะ (ของเดิม get_routing_table ก็ตก
# ไปใช้ normalize_generic เหมือนกัน) เลยคง raw payload ไว้ให้ frontend parse เอง
# ตามที่เคยทำอยู่แล้ว (ospf_route.jsx's extractCiscoOspfRoutes)
def normalize_ospf_dashboard(vendor: str, xml_response: str) -> dict:
    if vendor != "cisco":
        return normalize_generic(vendor, xml_response)
    return {
        "vendor": vendor,
        "ospf": normalize_ospf(vendor, xml_response),
        "interfaces": normalize_interfaces(vendor, xml_response),
        "routes": normalize_generic(vendor, xml_response)["payload"],
    }


# get_rip_dashboard รวม 3 query (rip/routing-table/interface-brief) ไว้ใน XML
# reply เดียว (เหมือน get_ospf_dashboard) - get_rip_information เองไม่มี
# normalizer เฉพาะอยู่แล้ว (ตกไป normalize_generic - rip_route.jsx's
# parseRipSummary/extractRipRoutes parse raw payload เองอยู่แล้ว) เลยส่ง
# "payload" ก้อนเดียวกลับไปให้ frontend ใช้ path เดิมทุกอย่าง (native/router/rip
# กับ routing-state เป็น sibling อยู่ใน payload.data เดียวกันพอดีอยู่แล้ว) มีแค่
# "interfaces" ที่ต้องแปลงเป็น array สะอาดแยกต่างหาก (normalize_interfaces เดิน
# root.iter() หา element ชื่อ "interface" ได้จากที่ไหนก็ได้ในทรี ไม่สนใจ sibling
# อื่นที่ปนมาด้วย)
def normalize_rip_dashboard(vendor: str, xml_response: str) -> dict:
    if vendor != "cisco":
        return normalize_generic(vendor, xml_response)
    return {
        "vendor": vendor,
        "payload": normalize_generic(vendor, xml_response)["payload"],
        "interfaces": normalize_interfaces(vendor, xml_response),
    }


# get_nat_dashboard รวม 3 query (nat/switchport/interface-brief) ไว้ใน XML
# reply เดียว (เหมือน get_ospf_dashboard/get_rip_dashboard) - get_nat_information
# ไม่มี normalizer เฉพาะ (ตกไป normalize_generic เหมือน rip) เลยคง "payload" ไว้
# ให้ nat.jsx's parseNatRules ใช้ path เดิมทุกอย่าง (native/ip/nat อยู่ใน
# payload.data เดียวกับที่เคย) - switchport/interfaces แยกเรียก normalizer
# เฉพาะของมันเองซ้ำบน XML เดียวกัน (root.iter()-based ทั้งคู่ ทนต่อ sibling อื่น
# ที่ปนมา - ดู comment ที่ normalize_ospf_dashboard)
def normalize_nat_dashboard(vendor: str, xml_response: str) -> dict:
    if vendor != "cisco":
        return normalize_generic(vendor, xml_response)
    return {
        "vendor": vendor,
        "payload": normalize_generic(vendor, xml_response)["payload"],
        "switchport": normalize_switchport_layer(vendor, xml_response),
        "interfaces": normalize_interfaces(vendor, xml_response),
    }


# (2026-09) get_nat_dashboard บนอุปกรณ์ Cisco ตอนนี้ยิง 2 RPC เล็กแทน RPC เดียวก้อน
# ใหญ่ (ดู comment ที่ cisco_iosxe.py's get_nat_dashboard_bindings/get_nat_dashboard_acl
# และ device_router.py's get_nat_dashboard branch) - 3 ฟังก์ชันข้างล่างนี้เป็นตัวช่วย
# ต่อผลทั้งสอง RPC กลับเป็น XML เดียวก่อนเข้า normalize_nat_dashboard ด้านบน (ซึ่งไม่
# ต้องแก้อะไรเลย เพราะมันแค่ parse XML ที่ได้รับมาเหมือนเดิมทุกประการ)
def extract_cisco_nat_bound_acl_name(xml_response: str) -> str | None:
    """อ่านชื่อ ACL ที่ NAT rule "ตัวแรก" อ้างถึงจาก get_nat_dashboard_bindings reply
    - เดินลำดับเดียวกับ parseNatRules ฝั่ง frontend (nat.jsx): list-interface ก่อน
    แล้วค่อย list-pool เพราะ currentRule ที่หน้าเว็บใช้คือ rows[0] ของลำดับนั้น (Cisco
    NAT เป็นค่าเดียวทั้งอุปกรณ์ หน้าเว็บแสดง/แก้แค่ rule แรกเสมอ)"""
    try:
        root = safe_fromstring(xml_response)
    except ET.ParseError:
        return None
    for wanted in ("list-interface", "list-pool"):
        for container in root.iter():
            if _local_name(container.tag) != wanted:
                continue
            for list_el in container:
                if _local_name(list_el.tag) != "list":
                    continue
                name = _child_text(list_el, "id")
                if name:
                    return name
    return None


def cisco_acl_reply_has_name(xml_response: str, acl_name: str) -> bool:
    """True เมื่อ reply ของ get_nat_dashboard_acl มี standard/extended ACL ที่ name
    ตรงกับที่ขอจริง - ใช้แยก "อ่านสำเร็จแต่ ACL ไม่มีอยู่แล้ว" (Brownfield NAT ที่ยัง
    อ้างถึง ACL ที่ถูกลบไปนอกระบบ - reply เปล่าแต่ไม่ error) ออกจากกรณีปกติ เพื่อให้
    ผู้เรียก fail-closed แทนที่จะคืน [] เงียบๆ แล้วให้ Save เขียนทับ ACL เดิมด้วย Any"""
    try:
        root = safe_fromstring(xml_response)
    except ET.ParseError:
        return False
    for element in root.iter():
        if _local_name(element.tag) not in ("standard", "extended"):
            continue
        if _child_text(element, "name") == acl_name:
            return True
    return False


def merge_nat_dashboard_replies(replies: list[str]) -> str:
    """ต่อผล get_nat_dashboard_bindings (+ get_nat_dashboard_acl ถ้ามี NAT rule อยู่)
    เป็น <rpc-reply> เดียวก่อนส่งเข้า normalize_nat_dashboard

    เหตุผลที่ต้อง merge (ไม่ใช่แค่ต่อ string XML สองก้อนเข้าด้วยกันเฉยๆ): native/ip/nat
    (RPC แรก) กับ native/ip/access-list (RPC สอง) ต้องอยู่ใต้ <native> เดียวกันเป๊ะ
    ไม่ใช่ native ซ้ำสองตัวเป็น sibling กัน - _element_to_json ที่ normalize_generic
    ใช้จะเห็น native เป็น list 2 ตัวถ้าซ้ำ ทำให้ path เดิมที่ nat.jsx/natFormModal.jsx
    ใช้อยู่ (payload.data.native.ip.nat / payload.data.native.ip["access-list"]) พัง
    เพราะกลายเป็น native[0]/native[1] แทนที่จะเป็น native เดียวที่มีทั้งสอง key เป็น
    sibling กัน - merge เจาะเฉพาะ tag ที่ปรากฏครั้งเดียวพอดีทั้งสองฝั่ง (native, ip)
    ส่วน tag อื่นที่ไม่ชนกัน (interface, access-list, OC interfaces ฯลฯ) แค่ต่อท้าย
    เข้าไปเป็น sibling ใหม่ตามปกติ"""
    if not replies:
        raise ValueError("merge_nat_dashboard_replies requires at least one reply")
    if len(replies) == 1:
        return replies[0]

    roots = [safe_fromstring(reply) for reply in replies]

    def data_of(root):
        return next((child for child in root if _local_name(child.tag) == "data"), root)

    def merge_into(target_parent, source_parent):
        for child in list(source_parent):
            local = _local_name(child.tag)
            target_siblings = [t for t in target_parent if _local_name(t.tag) == local]
            source_siblings = [s for s in source_parent if _local_name(s.tag) == local]
            if len(target_siblings) == 1 and len(source_siblings) == 1:
                merge_into(target_siblings[0], child)
            else:
                target_parent.append(child)

    merged_data = data_of(roots[0])
    for extra_root in roots[1:]:
        merge_into(merged_data, data_of(extra_root))

    return ET.tostring(roots[0], encoding="unicode")


def _native_switchport_mode(switchport_config):
    """อ่าน access/trunk จาก native/switchport-config - แยกออกมาเพราะตอนนี้มีสอง
    ทางที่สรุปว่าเป็น Layer 2 ได้ คือ native/switchport-conf กับ OpenConfig
    ethernet/config/switchport ทั้งสองทางต้องได้ mode จากที่เดียวกัน

    **เรียกได้เฉพาะเมื่อสรุปแล้วว่าพอร์ตเป็น Layer 2** เพราะค่า default ที่คืนคือ
    Access ซึ่งถูกต้องเฉพาะกับพอร์ตที่เป็น switchport จริง พอร์ต Layer 3 ต้องได้
    "-" จากผู้เรียกโดยไม่ผ่านฟังก์ชันนี้

    IOS-XE ไม่ได้เขียนคีย์ `mode` ลงมาทุกกรณี รูปร่างที่เจอจริงจากอุปกรณ์:
    - `mode/trunk`                    -> Trunk
    - `mode/access`                   -> Access (ไม่มี access/vlan ก็คือ VLAN 1)
    - ไม่มี `mode` แต่มี `access`     -> Access (พิมพ์แค่ `switchport access vlan X`
                                        อุปกรณ์ไม่เขียนบรรทัด mode ลงมาด้วย)
    - ไม่มี `switchport-config` เลย   -> Access (พอร์ต default ที่ยังไม่มีใครตั้งค่า)
    """
    if switchport_config is None:
        return "Access"

    for child in switchport_config.iter():
        if _local_name(child.tag) != "mode":
            continue
        for choice in child:
            choice_name = _local_name(choice.tag)
            if choice_name == "trunk":
                return "Trunk"
            if choice_name == "access":
                return "Access"
    # ไม่มีคีย์ mode: จะมี access/vlan หรือไม่มีอะไรเลยก็ตาม พอร์ตที่เป็น switchport
    # และไม่ได้สั่ง trunk คือ access ตามค่าเริ่มต้นของอุปกรณ์
    return "Access"


def _native_switchport_config(type_el):
    for child in type_el:
        if _local_name(child.tag) == "switchport-config":
            return child
    return None


def _classify_switchport_layer(type_el):
    """ตัดสิน Layer 2/3 ของ native/interface/<type> หนึ่งตัว - ใช้
    switchport-conf/switchport (leaf boolean เดี่ยวๆ ไม่มี if-feature กำกับ
    เลยมีให้เช็คได้ทุก platform) แทน OpenConfig ethernet/switched-vlan แบบเดิม
    (path นั้นไม่เคยเจอข้อมูลจริงเลยทั้ง HQ-R1 และ TestSWonWLC)

    Verified จริงกับ 2 เครื่อง (2026-07-27):
    - TestSWonWLC (switch จริง): ทุก physical port มี key switchport-conf
      true/false ปนกัน (TwoGigabitEthernet0/0/2 = false เพราะตั้ง
      `no switchport` ไว้ ที่เหลือ = true เพราะเป็น default L2 switchport)
    - HQ-R1 (CSR1000v/C8000v, router ล้วน): ไม่มี key switchport-conf โผล่มา
      เลยสักตัวบน interface ไหนเลย (หายไปทั้ง key ไม่ใช่ false)

    เกณฑ์ (3 ทาง แยกกันชัดเจน ไม่ใช่พึ่ง <ip> ทุกกรณี):
    - switchport-conf/switchport == "true" -> Layer 2 (อ่าน mode/vlan เพิ่ม
      จาก switchport-config/switchport ถ้ามีคนพิมพ์ access/trunk ไว้ชัดเจน)
    - switchport-conf/switchport == "false" -> Layer 3 ทันที (เป็น signal ที่
      ชัดเจนอยู่แล้วว่ามีคนตั้ง `no switchport` ไว้จริง ไม่ต้องรอเช็ค <ip> อีก)
    - ไม่มี key switchport-conf เลย (เช่น router ที่ไม่รองรับ switching, หรือ
      Vlan/Tunnel) -> เช็ค <ip> แทน: มี -> Layer 3, ไม่มี -> Unknown (เช่น Gi4
      ที่เป็นแค่ physical trunk carrier ของ sub-interface .10/.20/.30/.31 โดย
      ตัวมันเองไม่มี ip เลย)
    """
    switchport_conf = None
    switchport_config = None
    has_ip = False
    for child in type_el:
        local = _local_name(child.tag)
        if local == "switchport-conf":
            switchport_conf = child
        elif local == "switchport-config":
            switchport_config = child
        elif local == "ip":
            has_ip = True

    switchport_value = _child_text(switchport_conf, "switchport") if switchport_conf is not None else None

    if switchport_value == "false":
        return {"layer": "Layer 3", "mode": "-"}

    if switchport_value == "true":
        return {"layer": "Layer 2", "mode": _native_switchport_mode(switchport_config)}

    if has_ip:
        return {"layer": "Layer 3", "mode": "-"}

    return {"layer": "Unknown", "mode": "-"}


def _openconfig_switchport_map(root):
    """อ่านฝั่ง OpenConfig ของ reply เดียวกัน คืน {ชื่อ interface: "true"/"false"}

    `get_switchport_information` ของ Cisco ขอสอง subtree ในคำสั่งเดียว: native
    (ใช้ทำ mode/helpers/raw เหมือนเดิม) และ openconfig-interfaces ที่ให้
    `ethernet/config/switchport` ซึ่งเป็นสัญญาณ Layer 2/3 ที่ตรงกว่า เพราะ
    router จะไม่มีคีย์นี้เลย ส่วน switch จะมี true/false ชัดเจนรายพอร์ต

    แยกสองฝั่งจากรูปร่าง: element ของ OpenConfig มี <name> เป็นลูกตรง ส่วน
    native เป็น wrapper ที่แตกเป็นชนิด interface อีกชั้น (ลูปหลักด้านล่างใช้
    สัญญาณเดียวกันนี้ข้าม OpenConfig อยู่แล้ว)
    """
    switchports = {}
    for element in root.iter():
        if _local_name(element.tag) != "interface":
            continue
        name = _child_text(element, "name")
        if not name:
            continue
        has_ethernet = any(_local_name(child.tag) == "ethernet" for child in element)
        if not has_ethernet:
            continue
        value = _deep_text(element, "switchport")
        # เก็บทุกตัวที่มี ethernet container แม้ไม่มีคีย์ switchport เพราะ "ไม่มีคีย์"
        # คือคำตอบอยู่แล้วว่าพอร์ตนี้ไม่ใช่ switchport (router ไม่มีคีย์นี้เลย) ต่างจาก
        # ชื่อที่ไม่อยู่ในแผนที่เลยอย่าง Vlan/Loopback ซึ่งต้องตกไปใช้กฎเดิม
        switchports[name] = (value or "").strip().lower()
    return switchports


def normalize_switchport_layer(vendor: str, xml_response: str):
    """Parse a get_switchport_information reply into a unified Layer 2/3 table.

    Cisco และ Huawei มี query นี้จริง แต่โครงสร้าง native ต่างกัน จึง map เป็น
    row รูปแบบเดียวกันก่อนส่งหน้า Interfaces/VLAN; Juniper ยังใช้ generic
    เพราะไม่มี query คู่กันใน translator.

    cisco_iosxe.py's get_switchport_information() requests the whole
    native/interface subtree (ไม่มี OpenConfig sibling อีกต่อไป - ดู
    _classify_switchport_layer ด้านบนสำหรับเกณฑ์ตัดสิน Layer 2/3 ตัวใหม่).
    """
    if vendor == "huawei":
        root = safe_fromstring(xml_response)
        rows = []
        # Huawei CE12800 คืน ethernet/ethernetIfs/ethernetIf จาก module
        # huawei-ethernet: linkType เป็น access/trunk และรายการ VLAN อยู่ใน
        # portActiveVlanInfos; l2Enable=disable คือ signal Layer 3 ที่อุปกรณ์
        # คืนมาเอง ส่วนที่ไม่มีทั้งสองค่าให้แสดง Unknown โดยไม่เดาเพิ่ม.
        for entry in root.iter():
            if _local_name(entry.tag) != "ethernetIf":
                continue
            name = _child_text(entry, "ifName")
            if not name:
                continue
            l2_enabled = (_child_text(entry, "l2Enable") or "").lower()
            attribute = next((child for child in entry if _local_name(child.tag) == "l2Attribute"), None)
            link_type = (_child_text(attribute, "linkType") or "").lower() if attribute is not None else ""
            if l2_enabled == "disable":
                layer_info = {"layer": "Layer 3", "mode": "-"}
            elif link_type == "access":
                layer_info = {"layer": "Layer 2", "mode": "Access"}
            elif link_type == "trunk":
                layer_info = {"layer": "Layer 2", "mode": "Trunk"}
            else:
                layer_info = {"layer": "Unknown", "mode": "-"}
            rows.append({
                "name": name,
                "layer": layer_info["layer"],
                "mode": layer_info["mode"],
                "helpers": [],
                "raw": _element_to_json(entry),
            })
        return rows

    if vendor != "cisco":
        return normalize_generic(vendor, xml_response)

    root = safe_fromstring(xml_response)
    openconfig_switchports = _openconfig_switchport_map(root)

    rows = []
    for iface_root in root.iter():
        if _local_name(iface_root.tag) != "interface" or _child_text(iface_root, "name"):
            continue  # กันเหนียวไว้เผื่อมี element ชื่อ "interface" อื่นปนมา (มี <name> ตรงๆ ไม่ใช่ native wrapper)
        for type_el in iface_root:
            type_name = _local_name(type_el.tag)
            name = _child_text(type_el, "name")
            if not name:
                continue
            full_name = f"{type_name}{name}"
            helpers = [
                _child_text(helper, "address")
                for ip_el in type_el if _local_name(ip_el.tag) == "ip"
                for helper in ip_el if _local_name(helper.tag) == "helper-address"
            ]
            layer_info = _classify_switchport_layer(type_el)
            # OpenConfig เป็นแหล่งที่แม่นกว่าสำหรับ "พอร์ตนี้เป็น switchport ไหม":
            # true -> Layer 2 (mode ยังอ่านจาก native เหมือนเดิม), false -> Layer 3
            # ชื่อที่ไม่มีในฝั่ง OpenConfig เช่น Vlan/Loopback/Tunnel ใช้ผลของกฎเดิม
            # ที่อ่าน switchport-conf แล้วดู <ip> ต่อไปตามเดิม
            openconfig_value = openconfig_switchports.get(full_name)
            if openconfig_value == "true":
                layer_info = {"layer": "Layer 2", "mode": _native_switchport_mode(_native_switchport_config(type_el))}
            elif openconfig_value is not None:
                # "false" หรือไม่มีคีย์ switchport เลย = ไม่ได้เป็น switchport
                layer_info = {"layer": "Layer 3", "mode": "-"}

            # พอร์ตนี้ "สลับเป็น switchport ได้ไหม" ต่างจาก "ตอนนี้เป็น Layer อะไร"
            # อุปกรณ์ที่เป็นสวิตช์จะมี leaf switchport ของ OpenConfig ทุกพอร์ตไม่ว่า
            # ค่าจะเป็น true หรือ false ส่วน router จะไม่มี leaf นี้เลย หน้าเว็บใช้ค่านี้
            # ตัดสินว่าปุ่ม Reset จะคืนพอร์ตเป็น access VLAN 1 หรือแค่ล้าง IP
            # อุปกรณ์ที่ไม่คืนฝั่ง OpenConfig มาเลยให้ดูจาก switchport-conf ของ native แทน
            switchport_capable = openconfig_value in ("true", "false") or any(
                _local_name(child.tag) == "switchport-conf" for child in type_el
            )
            rows.append({
                "name": full_name,
                "layer": layer_info["layer"],
                "mode": layer_info["mode"],
                "switchport_capable": switchport_capable,
                "helpers": [h for h in helpers if h],
                # เก็บ native entry ดิบไว้ด้วย (แปลงเป็น JSON แล้ว) - ใช้ pre-fill
                # ฟอร์ม Edit (shutdown/switchport/native-vlan ที่ layer/mode/helpers
                # ที่ unify แล้วไม่มีรายละเอียดพอ) เดิม frontend เก็บ raw element
                # เองก่อน normalizer ตัวนี้จะมาแทนที่ normalize_generic
                "raw": _element_to_json(type_el),
            })
    return rows


def _element_to_json(element, *, preserve_inactive: bool = False):
    """แปลง XML element เป็น dict/list/string แบบทั่วไป (ไม่รู้จัก field เฉพาะ
    ยี่ห้อ) - tag ที่ซ้ำกันในระดับเดียวกันจะรวมเป็น list, tag ที่ไม่มีลูกจะ
    คืนเป็น string ของ text ตรงๆ ใช้กับ query ที่โครงสร้างต่างกันมากเกินจะเขียน
    parser เฉพาะให้ทุกยี่ห้อได้ (running-config, routing table)"""
    children = list(element)
    if not children:
        return (element.text or "").strip()
    result: dict = {}
    for child in children:
        name = _local_name(child.tag)
        value = _element_to_json(child, preserve_inactive=preserve_inactive)
        if name in result:
            if not isinstance(result[name], list):
                result[name] = [result[name]]
            result[name].append(value)
        else:
            result[name] = value
    if preserve_inactive and "inactive" in element.attrib:
        result["@attributes"] = {"inactive": element.attrib["inactive"]}
    return result


def collect_rpc_errors(root) -> list[dict]:
    """ดึง <rpc-error> ทุกตัวออกมาเป็น list ของ dict (มีได้หลายตัวใน reply เดียว)

    แยกออกมาเป็นฟังก์ชันร่วมตอนแก้ปัญหาที่ 1 ใน planning/transaction_review.md -
    เดิมตรรกะนี้ฝังอยู่ใน normalize_edit_result ตัวเดียว ทำให้ "คำสั่งเขียนที่ล้มเหลว"
    ถูกตรวจจับได้ แต่ "คำสั่งอ่านที่ล้มเหลว" หลุดไปเงียบๆ เพราะ get_* วิ่งไป
    normalize_generic/normalizer เฉพาะทาง ซึ่งไม่เคยมองหา rpc-error เลย ผลคือผู้ใช้
    เห็นตารางว่างเปล่าโดยไม่มีอะไรบอกว่าคำสั่งล้มเหลว - ตอนนี้ normalize() เรียกตัวนี้
    เป็นด่านแรกให้ทุกคำสั่งเหมือนกันหมด
    """
    errors = []
    for element in root.iter():
        if _local_name(element.tag) != "rpc-error":
            continue
        # bad-element อยู่ลึกใน error-info อีกชั้น เลยใช้ _deep_text
        errors.append({
            "type": _child_text(element, "error-type"),
            "tag": _child_text(element, "error-tag"),
            "severity": _child_text(element, "error-severity"),
            "message": _child_text(element, "error-message"),
            "path": _child_text(element, "error-path"),
            "bad_element": _deep_text(element, "bad-element"),
        })
    return errors


# (bug 99) ตอบคำถามเดียว: "อุปกรณ์ปฏิเสธคำสั่งนี้จริงหรือเปล่า"
#
# ที่ต้องมีเพราะ device_router เขียน Device_History ทันทีที่ send_payload ไม่ throw
# ซึ่งไม่ตรงกับความจริง - edit-config ที่โดน rpc-error ไม่ throw (ตั้งใจ ดูคอมเมนต์ใน
# conn_socket.send_payload) ประวัติจึงบันทึกคำสั่งที่ไม่เคยเกิดขึ้นบนอุปกรณ์เป็น "สำเร็จ"
# เจอจริงจากการไล่ BUG-98: ประวัติมี create_security_tunnel แบบ gre ของ Juniper 4 ครั้ง
# แต่ show configuration บนอุปกรณ์ว่างเปล่าและไม่มีคำสั่งลบตามหลังเลยสักครั้ง
#
# **ห้ามใช้แค่ "มี <rpc-error> ไหม" เป็นเกณฑ์** - ยืนยันกับ vSRX จริงแล้วว่าบางคำสั่งที่
# สำเร็จ (เช่นเปลี่ยน family ของ interface) อุปกรณ์ตอบ rpc-error ที่ severity เป็น
# "warning" มาคู่กับ <ok/> ในเรพลายเดียวกัน ถ้าตัดสินจากการมี rpc-error ลอย ๆ จะกลาย
# เป็นทิ้งประวัติของคำสั่งที่สำเร็จจริง (RFC 6241 §4.3 อนุญาตให้มี rpc-error เป็น
# warning ปนมาโดยที่ operation ยังสำเร็จ) - conn_socket ก็ใช้หลักเดียวกันนี้กับ commit
def reply_rejected(xml_response: str) -> bool:
    try:
        root = safe_fromstring(xml_response)
    except Exception:
        # parse ไม่ได้ = ไม่มีข้อมูลพอจะฟันธง - คืน False ไว้ก่อนเพื่อคงพฤติกรรมเดิม
        # (ยอมให้มีประวัติเกินดีกว่าทิ้งประวัติของคำสั่งที่อาจ apply จริงไปแล้ว)
        return False

    errors = collect_rpc_errors(root)
    if not errors:
        return False
    if any((error.get("severity") or "").lower() == "error" for error in errors):
        return True
    # เหลือแต่ warning - เชื่อ <ok/> ว่าสำเร็จ ถ้าไม่มีก็ถือว่าถูกปฏิเสธ
    return not any(_local_name(element.tag) == "ok" for element in root.iter())


def normalize_generic(vendor: str, xml_response: str) -> dict:
    """ใช้กับ get_running_config และ get_routing_table - โครงสร้าง native
    ของแต่ละยี่ห้อต่างกันเกินกว่าจะ map field เป็นชื่อกลางได้อย่างมั่นใจโดยไม่มี
    sample จากอุปกรณ์จริงครบทั้ง 3 ยี่ห้อ (Huawei get_routing_table ใช้ YANG
    module staticrt ที่ query แค่ static route ด้วยซ้ำ ไม่ใช่ full RIB เหมือน
    Cisco/Junos) เลยแปลงแบบทั่วไป (structural) แทน - ได้ JSON format เดียวกัน
    ทุกยี่ห้อ (nested dict/list) แต่ชื่อ field ยังเป็นของยี่ห้อนั้นๆ อยู่ ไม่ได้
    unify ความหมายระดับ field เหมือน normalize_interfaces"""
    root = safe_fromstring(xml_response)
    # ใช้ key "payload" แทน "data" กันสับสนกับ tag <data> ที่ NETCONF rpc-reply
    # ห่ออยู่แล้วเป็นปกติ (ไม่งั้นจะได้ {"data": {"data": {...}}} ซ้อนกันดูงง)
    return {"vendor": vendor, "payload": _element_to_json(root)}


# key ที่เป็นความลับ - ห้ามส่งถึง browser ไม่ว่าอุปกรณ์จะคืนมาเป็นข้อความชัดหรือเข้ารหัสไว้
# (Cisco keyring peer/pre-shared-key/key · Junos ike policy/pre-shared-key/ascii-text)
_SECRET_KEYS = {"pre-shared-key"}


def _blank_leaves(node):
    # ล้าง "ค่า" ทุกใบแต่คง "โครงสร้าง" ไว้ - หน้าเว็บต้องรู้ว่า PSK ของ peer เป็นแบบไหน
    # (key เดียว หรือแยก local/remote) จึงจะรู้ว่าแก้ผ่านฟอร์มได้หรือไม่ แต่ไม่ต้องรู้ค่า
    if isinstance(node, dict):
        return {k: _blank_leaves(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_blank_leaves(item) for item in node]
    return "" if isinstance(node, str) else node


def _scrub_secrets(node):
    if isinstance(node, dict):
        return {
            k: (_blank_leaves(v) if k in _SECRET_KEYS else _scrub_secrets(v))
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [_scrub_secrets(item) for item in node]
    return node


def normalize_security_profile_information(vendor: str, xml_response: str) -> dict:
    """get_security_profile_information = normalize_generic + ตัด PSK ทิ้งก่อนส่งต่อ

    ต้องมีเพราะหน้า Security Profile ต้องอ่าน keyring ของ Cisco (ชื่อ keyring + peer + address)
    เพื่อแก้/ลบ peer ตัวจริงของ profile ที่ไม่ได้สร้างจากระบบ ซึ่ง `<keyring>` ที่อุปกรณ์ตอบมา
    มี pre-shared-key ติดมาด้วย - หน้าเว็บไม่เคยต้องใช้ค่านั้น (แก้ PSK ทำโดยส่งค่าใหม่ไป
    ไม่ใช่อ่านค่าเดิมกลับมา) จึงล้างค่าที่ backend (คงไว้แค่โครงสร้าง) ไม่ให้ถึง browser และไม่ไปอยู่ใน network log
    ตัดทั้ง 2 ยี่ห้อ: ฝั่ง Junos เดิมส่ง `$9$…` ที่เข้ารหัสไว้ไปด้วยอยู่แล้ว ไม่มีที่ไหนใช้เช่นกัน"""
    result = normalize_generic(vendor, xml_response)
    result["payload"] = _scrub_secrets(result["payload"])
    return result


def normalize_vlan_information(vendor: str, xml_response: str) -> dict:
    # Scope metadata preservation to Juniper VLAN reads only; all other
    # queries/vendors retain the existing generic JSON representation.
    if vendor != "juniper":
        return normalize_generic(vendor, xml_response)
    root = safe_fromstring(xml_response)
    return {"vendor": vendor, "payload": _element_to_json(root, preserve_inactive=True)}


def normalize_edit_result(vendor: str, xml_response: str) -> dict:
    """ใช้กับคำสั่งเขียน (set_/apply_/remove_/create_) ที่ตอบกลับตาม RFC 6241:
    สำเร็จ = <rpc-reply><ok/></rpc-reply>, ล้มเหลว = <rpc-reply><rpc-error>...
    - เป็นมาตรฐาน NETCONF กลาง ใช้ได้เหมือนกันทั้ง 3 ยี่ห้อ (verify ได้ ไม่ต้อง
    เดา field เฉพาะยี่ห้อ) - คืน {ok: True} ถ้าสำเร็จ, {ok: False, errors: [...]}
    ถ้ามี rpc-error (มีได้หลายตัวใน reply เดียว)"""
    root = safe_fromstring(xml_response)

    has_ok = any(_local_name(el.tag) == "ok" for el in root.iter())
    errors = collect_rpc_errors(root)

    if errors:
        return {"ok": False, "errors": errors}
    # ไม่มี rpc-error - ถือว่าสำเร็จ (has_ok เป็น True ตามปกติ แต่บางยี่ห้อ/บาง
    # กรณีอาจตอบ data เปล่าๆ โดยไม่มี <ok/> ก็ยังนับว่าไม่ error)
    return {"ok": True, "acknowledged": has_ok}


def normalize_capabilities(vendor: str, xml_response: str) -> dict:
    """Parse the <hello> exchange (ทำตอน call-home ก่อนรู้ vendor ด้วยซ้ำ) ให้เป็น
    JSON format กลาง เก็บ capability URI ทั้งหมดที่อุปกรณ์ประกาศไว้ - นี่คือ
    raw capability list เท่านั้น ยังไม่ได้ cross-reference กับ PUBLIC_FUNCTIONS
    ว่าคำสั่งไหนใช้ได้จริง (ข้อ 6.3 ของ proposal) เอาไว้ทำเป็นขั้นถัดไป"""
    root = safe_fromstring(xml_response)
    capabilities = [
        element.text.strip()
        for element in root.iter()
        if _local_name(element.tag) == "capability" and element.text and element.text.strip()
    ]
    session_id = _child_text(root, "session-id")
    return {
        "vendor": vendor,
        "capabilities": capabilities,
        "session_id": session_id or None,
    }


def normalize_acl_information(vendor: str, xml_response: str) -> dict:
    if vendor == "juniper":
        from vendor_translators.juniper_acl import normalize_juniper_acl_information
        return normalize_juniper_acl_information(xml_response, _element_to_json)
    return normalize_generic(vendor, xml_response)


def _attach_policy_metadata(generic: dict, fz: str, tz: str, p_name: str, inspected: dict, order_rev: str = "") -> None:
    data = generic.get("payload", {}).get("data", {})
    if not isinstance(data, dict):
        return
    policies = data.get("configuration", {}).get("security", {}).get("policies", {})
    if not isinstance(policies, dict):
        return
    raw_pairs = policies.get("policy", [])
    pairs = raw_pairs if isinstance(raw_pairs, list) else [raw_pairs] if isinstance(raw_pairs, dict) else []
    for pair in pairs:
        if not isinstance(pair, dict):
            continue
        if pair.get("from-zone-name") == fz and pair.get("to-zone-name") == tz:
            if order_rev:
                pair["order_revision"] = order_rev
            raw_rules = pair.get("policy", [])
            rules = raw_rules if isinstance(raw_rules, list) else [raw_rules] if isinstance(raw_rules, dict) else []
            for r in rules:
                if isinstance(r, dict) and r.get("name") == p_name:
                    r["revision"] = inspected["revision"]
                    if order_rev:
                        r["order_revision"] = order_rev
                    r["hasBrownfieldFields"] = inspected["has_brownfield_fields"]
                    r["preservedFields"] = inspected["preserved_fields"]
                    r["unsupportedReasons"] = inspected["unsupported_reasons"]
                    r["editable"] = inspected["editable"]
                    r["rawAction"] = inspected["action"]


def normalize_security_policy_information(vendor: str, xml_response: str) -> dict:
    if vendor != "juniper":
        return normalize_generic(vendor, xml_response)
    generic = normalize_generic(vendor, xml_response)
    try:
        from vendor_translators.juniper_security_policy import (
            inspect_juniper_security_policy,
            get_juniper_security_policies_in_zone,
            compute_zone_pair_order_revision,
        )
        root = safe_fromstring(xml_response)
        for pair in root.iter():
            if _local_name(pair.tag) != "policy":
                continue
            fz = None
            tz = None
            for child in pair:
                tag = _local_name(child.tag)
                if tag == "from-zone-name":
                    fz = (child.text or "").strip()
                elif tag == "to-zone-name":
                    tz = (child.text or "").strip()
            if fz and tz:
                zone_policy_names = get_juniper_security_policies_in_zone(root, fz, tz)
                order_rev = compute_zone_pair_order_revision(zone_policy_names, from_zone=fz, to_zone=tz)
                for child in pair:
                    if _local_name(child.tag) == "policy":
                        name_el = None
                        for p_child in child:
                            if _local_name(p_child.tag) == "name":
                                name_el = p_child
                                break
                        if name_el is not None and (name_el.text or "").strip():
                            p_name = (name_el.text or "").strip()
                            inspected = inspect_juniper_security_policy(child, from_zone=fz, to_zone=tz)
                            _attach_policy_metadata(generic, fz, tz, p_name, inspected, order_rev=order_rev)
    except Exception:
        pass
    return generic


def parse_local_usernames(vendor: str, xml_response: str) -> list[str]:
    """Every local username on the device, including the reserved account.

    Used by the backend existence guard only - never sent to the browser.
    """
    return [user["username"] for user in _local_user_entries(vendor, safe_fromstring(xml_response))]


def _local_user_entries(vendor: str, root) -> list[dict]:
    # Only the identity and the privilege leaf are read; password, secret,
    # encrypted-password, SSH keys and every other leaf stay on the server.
    if vendor == "cisco":
        # native/username list entries
        entries = _children_of(root, "native", "username")
        name_tag, level_tag = "name", "privilege"
    elif vendor == "juniper":
        # configuration/system/login/user
        entries = _children_of(root, "login", "user")
        name_tag, level_tag = "name", "class"
    elif vendor == "huawei":
        # aaa/lam/users/user
        entries = _children_of(root, "users", "user")
        name_tag, level_tag = "userName", "userLevel"
    else:
        return []
    users = []
    for entry in entries:
        name = _child_text(entry, name_tag)
        if name:
            users.append({"username": name, "raw_privilege": _child_text(entry, level_tag)})
    return users


def _children_of(root, parent_tag: str, child_tag: str) -> list:
    return [
        child
        for parent in root.iter()
        if _local_name(parent.tag) == parent_tag
        for child in parent
        if _local_name(child.tag) == child_tag
    ]


def normalize_local_users(vendor: str, xml_response: str) -> dict:
    """get_local_user -> {"vendor", "users": [{"username", "privilege"}]}.

    privilege is "monitor" / "admin", or None for a Brownfield level this page
    does not manage (e.g. Cisco 7, Junos read-only, Huawei 2). An unknown
    level is never guessed - a higher one shown as Monitor Only would hide
    real access. The reserved management account is removed here, before the
    reply leaves the server.
    """
    from tools.local_user_policy import canonical_privilege, is_reserved_username

    users = []
    for entry in _local_user_entries(vendor, safe_fromstring(xml_response)):
        if is_reserved_username(entry["username"]):
            continue
        users.append({
            "username": entry["username"],
            "privilege": canonical_privilege(vendor, entry["raw_privilege"]),
        })
    return {"vendor": vendor, "users": users}


def normalize_acl_reference_information(vendor: str, xml_response: str):
    if vendor == "cisco":
        from vendor_translators.cisco_zbf import inspect_cisco_acl_references
        return inspect_cisco_acl_references(xml_response)
    return normalize_generic(vendor, xml_response)


# parser เฉพาะทาง (unify field ข้ามยี่ห้อ) - ตัวที่ verify กับอุปกรณ์จริงแล้ว
# เท่านั้น เพิ่ม entry ใหม่ที่นี่เมื่อ upgrade คำสั่งจาก generic เป็น field-unified
# (ต้องมี output จากอุปกรณ์จริงมาเทียบก่อนเสมอ - บทเรียนจาก arp-entry/arp-oper)
NORMALIZERS = {
    "get_acl_information": normalize_acl_information,
    "get_acl_reference_information": normalize_acl_reference_information,
    "get_security_policy_information": normalize_security_policy_information,
    "get_interface_information": normalize_interfaces,
    "get_ip_interface_brief": normalize_interfaces,
    # get_interface_list คืนแค่ <name/> ต่อ interface (ไม่มี mac/ip/status) -
    # normalize_interfaces ใช้ร่วมได้เลยเพราะ field อื่นแค่ได้ "" ว่างเปล่า ไม่ error
    "get_interface_list": normalize_interface_list,
    "get_arp_table": normalize_arp,
    "get_ospf_information": normalize_ospf,
    "get_ospf_dashboard": normalize_ospf_dashboard,
    "get_rip_dashboard": normalize_rip_dashboard,
    "get_nat_dashboard": normalize_nat_dashboard,
    "get_switchport_information": normalize_switchport_layer,
    "get_vlan_information": normalize_vlan_information,
    "get_security_profile_information": normalize_security_profile_information,
    "get_local_user": normalize_local_users,
    "get_device_version": normalize_device_version,
    "get_device_license": normalize_device_license,
    "hello": normalize_capabilities,
    # get_running_config/get_routing_table เคยลงทะเบียนตรงนี้ตอนที่ normalize()
    # ยัง raise ValueError กับคำสั่งที่ไม่รู้จัก - ตอนนี้ get_* ที่ไม่มี parser
    # เฉพาะ fallback เป็น normalize_generic เองอัตโนมัติแล้ว (ดูข้างล่าง) เลย
    # ไม่ต้องลิสต์ซ้ำ
}


def normalize(vendor: str, function_name: str, xml_response: str):
    """จุดเรียกใช้กลาง: แปลง NETCONF XML reply เป็น JSON format กลาง - ทุกคำสั่ง
    มี normalizer เสมอ (ไม่ raise แล้ว):
    1. คำสั่งที่มี parser เฉพาะใน NORMALIZERS (unify field ข้ามยี่ห้อ) -> ใช้ตัวนั้น
    2. คำสั่งอ่าน get_* อื่นๆ -> normalize_generic (structured JSON ปลอดภัย ไม่เดา
       field เฉพาะยี่ห้อ - field ยังเป็นชื่อดิบของแต่ละยี่ห้อ ยังไม่ unify)
    3. คำสั่งเขียน (set_/apply_/remove_/create_) -> normalize_edit_result
       (ตีความ <ok/>/<rpc-error> ตาม RFC 6241 กลางทุกยี่ห้อ)"""
    # ด่านแรก: ตรวจ rpc-error ให้ "ทุกคำสั่ง" เหมือนกันหมดก่อน dispatch
    #
    # แผนเดิม (transaction_review.md ขั้น A1) เขียนไว้แค่ว่าให้ normalize_generic
    # ตรวจ rpc-error แต่พอมาดูโค้ดจริงพบว่าแก้ตรงนั้นยังไม่พอ - get_* ที่มี parser
    # เฉพาะทางใน NORMALIZERS (get_interface_information, get_arp_table, get_ospf_*
    # ฯลฯ) จะไม่ผ่าน normalize_generic เลย มันวิ่งเข้า parser ของตัวเองซึ่งเจอ XML
    # ที่ไม่มี data ที่คาดไว้ก็คืน [] หรือ {} เปล่าๆ ออกมาเงียบๆ ผู้ใช้เห็นตารางว่าง
    # โดยไม่รู้ว่าคำสั่งล้มเหลว - ยกด่านขึ้นมาไว้ที่นี่จึงครอบทุกคำสั่งด้วยโค้ดจุดเดียว
    #
    # คืน shape เดียวกับ normalize_edit_result ({ok: False, errors: [...]}) เพื่อให้
    # ฝั่ง frontend มีด่านตรวจแบบเดียวกันทั้งคำสั่งอ่านและเขียน ไม่ต้องแยกกรณี
    root = safe_fromstring(xml_response)
    errors = collect_rpc_errors(root)
    if errors:
        return {"ok": False, "errors": errors}

    parser = NORMALIZERS.get(function_name)
    if parser is not None:
        return parser(vendor, xml_response)
    if function_name.startswith("get_"):
        return normalize_generic(vendor, xml_response)
    return normalize_edit_result(vendor, xml_response)
