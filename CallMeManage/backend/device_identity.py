import itertools
from xml.etree import ElementTree as ET


from tools.safe_xml import safe_fromstring
NETCONF_END = "]]>]]>"
_message_ids = itertools.count(1000)

# ฟังก์ชั่นดึงชื่อ xml tags
# payload ที่รับมาทำงาน = "{http://www.huawei.com}interface"
def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1]

# ค้นหาและดึง xml tag ที่ต้องการ มาแค่ส่วนที่ต่ำกว่า 1 ระดับ
def _child_text(element, *names: str) -> str:
    wanted = set(names)
    for child in element:
        if _local_name(child.tag) in wanted and child.text:
            return child.text.strip()
    return ""


def _descendant_text(element, *names: str) -> str:
    """Return the first non-empty matching value below an interface node.

    Cisco operational data commonly exposes values as direct children, while
    Junos places an address below logical-interface/address-family.  Keeping
    this helper local to the selected interface node lets both layouts be
    parsed without searching the whole reply and accidentally borrowing data
    from a different interface.
    """
    direct = _child_text(element, *names)
    if direct:
        return direct
    wanted = set(names)
    for child in element.iter():
        if child is element:
            continue
        if _local_name(child.tag) in wanted and child.text and child.text.strip():
            return child.text.strip()
    return ""


def _address_only(value: str) -> str:
    """Normalize an operational address for comparison with a TCP peer IP."""
    return value.split("/", 1)[0].strip() if value else ""


def _collect_identity_macs(
    interfaces: list[dict], chassis_macs: list[str] | None = None
) -> list[str]:
    """Collect every interface MAC, using a chassis MAC only as a fallback.

    Interface state is deliberately ignored.  A user may pre-register a MAC
    from a currently down physical port or SVI, so limiting identity to the
    active path would make the same device fail authentication later.
    """
    interface_macs = [item.get("mac", "") for item in interfaces]
    values = interface_macs if any(interface_macs) else (chassis_macs or [])
    result = []
    seen = set()
    for raw_value in values:
        value = (raw_value or "").strip()
        key = value.lower()
        if value and key not in seen:
            result.append(value)
            seen.add(key)
    return result


# ค้นหาและดึง xml tag ที่ต้องการ จาก xml ทั้งหมดทุกระดับ
def _all_text(root, *names: str) -> list[str]:
    wanted = set(names)
    return [
        element.text.strip()
        for element in root.iter()
        if _local_name(element.tag) in wanted and element.text and element.text.strip()
    ]

# ค้นหา interface เฉพาะของ huawei
def _parse_huawei_ifm(root) -> list[dict]:
    interfaces = []
    for element in root.iter():
        if _local_name(element.tag) != "interface":
            continue
        name = _child_text(element, "ifName")
        if not name:
            continue
        oper_mac = ""
        cfg_mac = ""
        ip = ""
        # BUG-19: admin กับ oper ต้องแยกตัวแปรกัน ก่อนหน้านี้ ifAdminStatus ถูก
        # อ่านมาก่อนแล้ว ifOperStatus ถึงจะ fallback เฉพาะตอนค่าว่าง ซึ่งไม่เคย
        # เกิดเพราะ interface ของ VRP มี ifAdminStatus เสมอ คีย์ oper_status จึง
        # เก็บ admin status ตลอด ทำให้ _choose_wan นับ interface ที่สายหลุดว่าใช้ได้
        admin_raw = _child_text(element, "ifAdminStatus")
        oper_raw = ""
        for child in element.iter():
            local = _local_name(child.tag)
            if local == "ifOperMac" and child.text and not oper_mac:
                oper_mac = child.text.strip()
            elif local == "ifCfgMac" and child.text and not cfg_mac:
                cfg_mac = child.text.strip()
            elif local == "ifIpAddr" and child.text and not ip:
                ip = child.text.strip()
            elif local == "ifOperStatus" and child.text and not oper_raw:
                oper_raw = child.text.strip()
        desc = _child_text(element, "ifDescr", "description")
        mac = oper_mac or cfg_mac
        interfaces.append({
            "name": name,
            "mac": mac,
            "ip": _address_only(ip),
            "oper_status": oper_raw,
            "admin_status": admin_raw,
            "description": desc,
        })
    return interfaces

# ค้นหา interface สำหรับ cisco และ juniper
def _parse_interfaces(root) -> list[dict]:
    has_ifm = any(
        "huawei-ifm" in element.tag
        for element in root.iter()
        if element.tag
    )
    if has_ifm:
        result = _parse_huawei_ifm(root)
        if result:
            return result

    interfaces = []
    parents = {
        child: parent
        for parent in root.iter()
        for child in parent
    }
    for element in root.iter():
        tag = _local_name(element.tag)
        if tag not in {"interface", "physical-interface", "logical-interface"}:
            continue
        name = _child_text(element, "name", "interface-name", "ifName")
        mac_names = (
            "phys-address", "bia-address", "current-physical-address",
            "hardware-physical-address", "mac-address", "ifPhyAddress",
        )
        # Junos logical-interface often omits its MAC because it inherits the
        # address of the containing physical-interface (including irb units).
        # Inherit only from its direct parent; do not let a physical-interface
        # borrow the first logical unit's IP/MAC by recursively scanning down.
        if tag == "logical-interface":
            mac = _descendant_text(element, *mac_names)
            parent = parents.get(element)
            if not mac and parent is not None and _local_name(parent.tag) == "physical-interface":
                mac = _child_text(parent, *mac_names)
            ip = _address_only(_descendant_text(
                element, "ipv4", "ip-address", "address", "ifIpAddr", "ifa-local"
            ))
        elif tag == "physical-interface":
            mac = _child_text(element, *mac_names)
            ip = _address_only(_child_text(
                element, "ipv4", "ip-address", "address", "ifIpAddr", "ifa-local"
            ))
        else:
            mac = _descendant_text(element, *mac_names)
            ip = _address_only(_descendant_text(
                element, "ipv4", "ip-address", "address", "ifIpAddr", "ifa-local"
            ))
        if name and mac:
            interfaces.append(
                {
                    "name": name,
                    "mac": mac,
                    "ip": ip,
                    "oper_status": _child_text(element, "oper-status", "oper-state"),
                    "description": _child_text(element, "description", "ifDescr"),
                }
            )
    return interfaces

# ค้นหา interface ที่น่าจะเป็น wan interface
#
# เจอบั๊กจริง (user รายงาน): ทดสอบ switch ตั้ง GigabitEthernet0/0/0 เป็น access
# vlan1 ให้ interface Vlan1 รับ DHCP ออกเน็ต - ระบบกลับไปเลือก MAC ของ
# GigabitEthernet0/0 (mgmt port ที่ไม่ได้ใช้งานเลย, VRF Mgmt-intf) แทน - สาเหตุ:
# เดิม heuristic ตัดสินจากแค่ "มี IP + oper_status up/ready" ซึ่งทั้ง mgmt port
# และ Vlan1 (SVI) เข้าเงื่อนไขพร้อมกัน แล้วหยิบตัวแรกในลิสต์แบบไม่สนความหมาย
# (ลำดับที่อุปกรณ์รายงานกลับมา physical interface มักมาก่อน SVI เสมอ)
#
# แก้ 2 ชั้น:
# (1) peer_ip (ถ้ามี) - IP ต้นทางจริงของ TCP connection ที่ต่อเข้ามา (จาก
#     conn_socket.py's connection.get_extra_info("peername")) คือหลักฐานตรงที่สุด
#     ว่า interface ไหนกำลังคุยกับเราอยู่จริง ไม่ใช่แค่เดา - เช็คกับ interfaces
#     ดิบทั้งหมด (ไม่ผ่าน excluded filter ด้านล่าง) เพราะ ground truth ระดับนี้
#     เชื่อถือได้กว่า heuristic ชื่อ interface เสมอ แม้จะบังเอิญตรงกับ interface
#     ที่ปกติจัดเป็น mgmt-only ก็ตาม (ถ้าคุยจริงจากพอร์ตนั้นจริงๆ ก็ควรเชื่อว่าใช้
#     พอร์ตนั้นจริง) - ใช้ไม่ได้ถ้าอุปกรณ์อยู่หลัง NAT (peer_ip ที่ server เห็นจะ
#     เป็น IP ของตัว NAT ไม่ใช่ของ interface บนอุปกรณ์เอง) - ตกไปข้อ (2) แทน
# (2) ไม่เจอ peer_ip match (หรือไม่ได้ส่ง peer_ip มาเลย) - fallback เป็น
#     heuristic เดิม แต่เพิ่ม tiebreaker ใหม่: ให้ Vlan interface (SVI) ได้
#     ลำดับความสำคัญเหนือ physical interface เสมอในกลุ่ม "preferred" เดียวกัน
#     (มี IP+up ทั้งคู่) เพราะ SVI มักเป็นทางออกเน็ตจริงมากกว่า physical port ที่
#     อาจเป็นแค่ access port ของ switch (ไม่มี IP ของตัวเองด้วยซ้ำถ้าเป็น L2)
def _choose_wan(interfaces: list[dict], peer_ip: str | None = None) -> dict:
    if peer_ip:
        for item in interfaces:
            if _address_only(item.get("ip", "")) == peer_ip:
                return item

    excluded = ("loopback", "null", "irb", "lo", "fxp", "em", "me", "meth", "imeth")
    candidates = [
        item for item in interfaces if not item["name"].lower().startswith(excluded)
    ]
    labelled = [item for item in candidates if "wan" in item.get("description", "").lower()]
    preferred = sorted(
        (
            item
            for item in candidates
            if item.get("ip") and item.get("oper_status", "").lower() in {"up", "ready"}
        ),
        # False (เป็น vlan) เรียงมาก่อน True (ไม่ใช่ vlan) - sorted() เป็น stable
        # sort เลยยังรักษาลำดับเดิมภายในกลุ่มเดียวกันไว้ (ไม่ได้สลับมั่ว แค่ดัน
        # กลุ่ม vlan ขึ้นมาก่อนทั้งกลุ่ม)
        key=lambda item: not item["name"].lower().startswith("vlan"),
    )
    return (labelled or preferred or candidates or interfaces or [{}])[0]

#  เลือกยี่ห้ออุปกรณ์และคืนค่า payload ขอสำหรับขอข้อมูล hardware และ interface
def _queries(vendor: str) -> list[tuple[str, str]]:
    if vendor == "cisco":
        return [
            ("hardware", '<get><filter type="subtree"><device-hardware-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-device-hardware-oper"/></filter></get>'),
            ("interfaces", '<get><filter type="subtree"><interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper"/></filter></get>'),
            # ทั้ง hardware/interfaces oper model ข้างบนไม่มี tag hostname เลย (เจอบั๊กจริง:
            # dev_name เก็บ serial แทน hostname เพราะ names list ว่างเปล่าตลอด) hostname เป็น
            # config data อยู่ใต้ native model แยกต่างหาก ต้อง query เพิ่มเอง
            ("hostname", '<get><filter type="subtree"><native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native"><hostname/></native></filter></get>'),
        ]
    if vendor == "juniper":
        return [
            ("hardware", '<get-chassis-inventory xmlns="http://yang.juniper.net/junos-es/rpc/chassis"/>'),
            ("interfaces", '<get-interface-information xmlns="http://yang.juniper.net/junos-es/rpc/interfaces"/>'),
            # เหมือน cisco: host-name เป็น config data (system/host-name) ไม่ใช่ operational
            # data เลยต้องใช้ get-config แยก - ยังไม่เคยทดสอบกับอุปกรณ์ Juniper จริง
            ("hostname", '<get-config><source><running/></source><filter type="subtree"><configuration><system xmlns="http://yang.juniper.net/junos-es/conf/system"><host-name/></system></configuration></filter></get-config>'),
        ]
    if vendor == "huawei":
        return [
            # <systemInfo/> ไม่มีลูกเลยตาม RFC 6241 6.2.5 ถือเป็น "selection node" คืนทั้ง
            # subtree (รวม sysName ด้วย) อยู่แล้ว ไม่ต้อง query hostname แยกเหมือน cisco/juniper
            ("hardware", '<get><filter type="subtree"><system xmlns="http://www.huawei.com/netconf/vrp/huawei-system"><systemInfo/></system></filter></get>'),
            # อย่าใช้ <ifDynamicInfo/> / <mainIpAddr/> เป็น selection node แบบกว้าง:
            # VRP บางรุ่นคืน subtree ทั้งหมด (เครื่องที่ใช้สร้าง fixture เดิม) แต่
            # บางรุ่นคืน container ว่าง ทำให้ parser เห็นชื่อ interface แต่ไม่มี MAC
            # ระบุ leaf ที่ต้องใช้โดยตรง และขอ ifCfgMac เป็น fallback สำหรับ SVI
            # ที่ไม่มี operational MAC.
            ("interfaces", '<get><filter type="subtree"><ifm xmlns="http://www.huawei.com/netconf/vrp/huawei-ifm"><interfaces><interface><ifName/><ifAdminStatus/><ifCfgMac/><ifDynamicInfo><ifOperStatus/><ifOperMac/></ifDynamicInfo><mainIpAddr><ifIpAddr/></mainIpAddr><ifDescr/></interface></interfaces></ifm></filter></get>'),
        ]
    return []

# รับข้อมูล process, buffer, ฟังก์ชั่นอ่านการตอบกลับอุปกรณ์, ชื่อยี่ห้อ เพื่อส่งข้อมูลและรับค่าข้อมูล hardware และ interface ของอุปกรณ์
# peer_ip (ใหม่ - optional): IP ต้นทางจริงของ TCP connection ที่ต่อเข้ามา (ดู
# conn_socket.py's accept()) ส่งต่อให้ _choose_wan() ใช้เป็นหลักฐานอันดับแรกสุด
# ก่อนเดาด้วย heuristic อื่น - ไม่ส่งมาก็ยังทำงานได้ปกติ (แค่ข้าม shortcut นี้ไป)
async def probe_identity(
    process, buffer: list[str], read_dev_response, vendor: str, peer_ip: str | None = None
) -> dict:
    debug = []
    roots = []
    for name, inner_xml in _queries(vendor):
        message_id = next(_message_ids)
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{message_id}">'
            f"{inner_xml}</rpc>{NETCONF_END}"
        )
        try:
            process.stdin.write(payload)
            reply = await read_dev_response(process, buffer, timeout=15)
            root = safe_fromstring(reply)
            roots.append(root)
            rpc_error = any(_local_name(item.tag) == "rpc-error" for item in root.iter())
            debug.append({"query": name, "ok": not rpc_error, "reply_size": len(reply), "reply_excerpt": reply[:1000]})
        except Exception as exc:
            debug.append({"query": name, "ok": False, "error": str(exc)})

    interfaces = []
    serials = []
    chassis_macs = []
    names = []
    models = []
    for root in roots:
        interfaces.extend(_parse_interfaces(root))
        serials.extend(_all_text(root, "serial-number", "serial-num", "esn"))
        chassis_macs.extend(_all_text(root, "mac-address", "mac"))
        names.extend(_all_text(root, "host-name", "hostname", "sysName"))
        models.extend(_all_text(root, "model-number", "model", "chassis-type", "productName"))

    wan = _choose_wan(interfaces, peer_ip)
    # ใช้ model list เดียวกันทุกยี่ห้อ: `_choose_wan()` ยังคงคืนค่า MAC เดียวตาม
    # พฤติกรรมเดิมเพื่อ compatibility แต่การลงทะเบียนต้องไม่ผูกกับขาแรกนั้นอีก
    # รวบรวม MAC ของ physical interface, VLAN/SVI และ logical interface ทุกตัว
    # ที่ parser อ่านได้ รวม chassis MAC เป็น fallback สำหรับข้อมูลเก่า/บางรุ่น
    # ที่ไม่ประกาศ MAC ไว้ใต้ interface แล้วค่อย normalize ที่ชั้น CRUD.
    identity_macs = _collect_identity_macs(interfaces, chassis_macs)
    return {
        "serial": serials[0] if serials else "",
        # Keep the original single-MAC field for callers that still use it.
        # Authentication itself uses identity_macs below.
        "mac": wan.get("mac") or (chassis_macs[0] if chassis_macs else ""),
        "wan_interface": wan.get("name", ""),
        # บอกว่า peer IP ตรงกับ address ของ interface ที่เลือกหรือไม่
        # peer_ip มาจริง "และ" เจอ interface ที่ IP ตรงกันเป๊ะเท่านั้น (ไม่ใช่แค่
        # "ส่ง peer_ip มาไหม") - ถ้า False แปลว่าตกไปใช้ heuristic เดา (ข้อ 2)
        # ซึ่งเป็นสัญญาณอ้อมว่าน่าจะอยู่หลัง NAT (peer_ip ที่ server เห็นไม่ตรงกับ
        # interface ไหนบนอุปกรณ์เองเลยสักตัว)
        "wan_matched_peer_ip": bool(peer_ip) and _address_only(wan.get("ip", "")) == peer_ip,
        "name": names[0] if names else "",
        "model": models[0] if models else "",
        "identity_interfaces": interfaces,
        "identity_macs": identity_macs,
        "identity_probe": debug,
    }
