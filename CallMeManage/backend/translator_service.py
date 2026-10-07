import inspect
import types
import typing
from importlib import import_module
from tools.ipv4_input import validate_prefix

_UNION_ORIGINS = (typing.Union, types.UnionType)


PUBLIC_FUNCTIONS = {
    # get_interface_status ที่เคยอยู่ในนี้ถูกตัดออกแล้ว — ไม่มีฟังก์ชันชื่อนี้อยู่
    # จริงในทั้ง 3 ไฟล์ vendor_translators เลย (เช็คด้วย grep แล้ว) เป็น entry ค้าง
    #
    # ---------- อ่านค่า (get_*) ----------
    "get_running_config",
    "get_routing_table",
    "get_static_route_configuration",
    "get_arp_table",
    "get_interface_list",
    "get_interface_information",
    "get_ip_interface_brief",
    "get_device_version",
    "get_cpu_memory_information",
    "get_uptime",
    "get_device_license",
    "get_rip_information",
    "get_rip_dashboard",
    "get_ospf_information",
    "get_ospf_dashboard",
    "get_dns_information",
    "get_ntp_information",
    "get_dhcp_pool_information",
    "get_acl_information",
    "get_acl_reference_information",
    "get_nat_pool_information",
    "get_nat_information",
    "get_nat_dashboard",
    "get_nat_dashboard_bindings",
    "get_nat_dashboard_acl",
    "get_static_nat_information",
    "get_port_forward_information",
    "get_firewall_information",
    "get_security_zone_information",
    "get_security_policy_information",
    "get_security_status",
    "get_security_profile_information",
    "get_security_tunnel_information",
    "get_vlan_information",
    "get_switchport_information",
    "get_hostname",
    "get_address_book_information",
    "get_local_user",
    # ---------- พื้นฐานอุปกรณ์/interface ----------
    "set_hostname",
    "set_switchport",
    "set_interface_static_ip",
    "set_interface_ip_dhcp",
    "set_sub_interface_ip",
    "set_no_shutdown",
    "set_shutdown",
    "remove_interface_unit",
    "remove_interface_mtu",
    "clear_interface_ip",
    "prepare_interface_for_l2",
    "remove_vlan_tagging",
    "set_static_route",
    "remove_static_route",
    "set_dns_lookup",
    "remove_dns_lookup",
    "set_dns_config",
    "remove_dns_name_server",
    "set_dns_server_interface",
    "remove_dns_server_interface",
    "set_dns_relay_forwarder",
    "remove_dns_relay_forwarder",
    "set_ntp_server",
    "remove_ntp_server",
    "get_ip_routing",
    "set_ip_routing",
    "get_ip_default_gateway",
    "set_ip_default_gateway",
    # ---------- VLAN / switchport ----------
    "set_vlan",
    "remove_vlan",
    "set_interface_vlan",
    "set_interface_l3_none",
    "apply_interface_to_vlan",
    "remove_switchport",
    # ---------- Routing protocol ----------
    "set_rip_routing",
    "remove_rip_routing",
    "set_rip_redistribute_static",
    "set_ospf_network",
    "set_ospf_passive_interface",
    "remove_ospf_interface",
    "remove_ospf_process",
    "remove_ospf_routing",
    "replace_ospf_process",
    "replace_ospf_area",
    "set_ospf_default_originate",
    "set_ospf_redistribute_static",
    "set_ospf_redistribute_rip",
    # ---------- DHCP ----------
    "set_dhcp_pool",
    "remove_dhcp_pool",
    "set_dhcp_relay",
    "remove_dhcp_relay",
    "remove_dhcp_relay_interface",
    "set_dhcp_server_interface",
    "remove_dhcp_server_interface",
    "set_dhcp_local_interfaces",
    # ---------- ACL ----------
    "create_acl",
    "replace_acl",
    "create_acl_rule",
    "replace_acl_rule",
    "set_acl_rule",
    "remove_acl_rule",
    "remove_acl",
    "apply_acl_interface",
    "replace_acl_interface_bindings",
    # ---------- NAT ----------
    "create_nat_pool",
    "remove_nat_pool",
    "set_nat",
    "remove_nat",
    "create_nat_policy",
    "remove_nat_policy",
    "apply_nat_interface",
    "remove_nat_interface",
    "set_nat_proxy_arp",
    "remove_nat_proxy_arp",
    "get_nat_proxy_arp_information",
    "set_static_nat",
    "remove_static_nat",
    "remove_static_nat_ruleset",
    "set_port_forward",
    "remove_port_forward",
    "remove_port_forward_ruleset",
    # ---------- Stateful firewall / security-zone (ZBF) ----------
    "set_address_book_entry",
    "remove_address_book_entry",
    "set_security_zone",
    "remove_security_zone",
    "remove_security_zone_service",
    "remove_security_zone_protocol",
    "remove_zone_interface_service",
    "remove_zone_interface_protocol",
    "apply_zone_member",
    "remove_zone_member",
    "remove_dhcp_relay_member",
    "set_inspect_class_map",
    "remove_inspect_class_map",
    "set_inspect_policy_map",
    "remove_inspect_policy_map",
    "set_zone_pair",
    "remove_zone_pair",
    "create_firewall_policy",
    "remove_firewall_policy",
    "set_security_policy",
    "remove_security_policy",
    "move_security_policy",
    "move_security_policy_zone",
    # ---------- VPN (IKEv2/IPsec security profile) ----------
    "set_ikev2_proposal",
    "set_ikev2_policy",
    "create_security_profile",
    "remove_security_profile",
    # profile ที่ไม่ได้สร้างจากระบบ: ทำงานกับ "ชื่อ object จริง" ที่อ่านมาจากอุปกรณ์ (ไม่ derive ชื่อ)
    "modify_security_profile",
    "remove_security_profile_objects",
    "remove_ipsec_profile",
    "remove_ipsec_transform_set",
    "remove_ikev2_profile",
    "remove_ikev2_keyring",
    "remove_ikev2_policy",
    "remove_ikev2_proposal",
    "create_security_tunnel",
    "remove_tunnel_interface",
    # ---------- System Setting > User Info (local users) ----------
    "set_new_local_user",
    "edit_local_user",
    "delete_local_user",
    # ---------- System Management > Device Setting ----------
    # All three vendor translators expose a vendor-specific NETCONF reboot RPC.
    "reboot",
}


# (ระลอก C ข้อ 8 ใน planning/transaction_review.md) คำสั่ง composite ที่ตั้งค่าทั้งก้อน
# ใน RPC เดียว - ยิงผ่าน API ได้ปกติ แต่ **ซ่อนจากรายการฟอร์มกลาง** ที่ DeviceDetail.jsx
# ใช้ DynamicCommandForm สร้างให้อัตโนมัติ
#
# เหตุผล: _classify_parameter() แปลง type เป็น widget ได้แค่ 4 แบบ (bool/list/select/
# text) แต่คำสั่งพวกนี้รับ list ของ object (เช่น networks=[{network, wildcard, area}])
# ซึ่ง render เป็นช่องกรอกไม่ได้เลย ถ้าปล่อยให้โผล่ในรายการ ผู้ใช้จะเห็นฟอร์มที่กรอก
# แล้วพัง - เลือกทางนี้แทนการบิด parameter ให้แบนพอจะ render ได้ เพราะการบิด API ให้
# อ่านยากเพื่อเอาใจฟอร์มที่ไม่ได้ตั้งใจให้ใช้กับคำสั่งแบบนี้อยู่แล้วไม่คุ้ม
#
# คำสั่งเหล่านี้ถูกเรียกจากฟอร์มเฉพาะทางที่เขียนมือไว้แล้ว (OspfRouteFormModal ฯลฯ)
COMPOSITE_FUNCTIONS = {
    "create_acl",
    "replace_acl",
    "replace_acl_interface_bindings",
    "replace_ospf_process",
    "replace_ospf_area",
    # (ระลอก C3 / bug 65) create_nat_policy กลับมาใช้แล้วและตอนนี้รับ inside_interfaces/
    # release_interfaces เพิ่ม - เป็นคำสั่งระดับ "เจตนา" ที่ frontend ประกอบพารามิเตอร์ให้
    # (คำนวณ network+prefix จาก interface ที่ผู้ใช้ติ๊ก, อ่านขาที่มี nat ติดอยู่จริงมาส่ง
    # เป็น release_interfaces) ไม่ใช่ค่าที่กรอกมือได้ในฟอร์มกลาง จึงซ่อนเหมือน replace_ospf_*
    "create_nat_policy",
    "remove_nat_policy",
    # (2026-09) เรียกจาก backend/api/device_router.py's get_nat_dashboard branch เอง
    # เท่านั้น (2 RPC เล็กแทนที่ get_nat_dashboard เดิม - ดู cisco_iosxe.py) ไม่ใช่คำสั่ง
    # ที่ผู้ใช้กดตรงๆ ผ่านฟอร์มกลางได้ - get_nat_dashboard_acl ยังต้องรู้ชื่อ ACL จริง
    # จากอุปกรณ์ก่อนเสมอ กรอกมือไม่ได้อยู่แล้ว
    "get_nat_dashboard_bindings",
    "get_nat_dashboard_acl",
    # รับชื่อ object จริงหลายตัวที่หน้า Security Profile อ่านมาจากอุปกรณ์แล้วประกอบให้ - กรอกมือในฟอร์มกลางไม่ได้
    "modify_security_profile",
    "remove_security_profile_objects",
    "set_ikev2_proposal",
    "set_ikev2_policy",
    "move_security_policy",
    "move_security_policy_zone",
    # (2026-09) members/previous_members เป็น list ของ {name, upto, exclude} -
    # _classify_parameter() จำแนก list[dict] เป็น widget "list" เดียวกับ list[str]
    # แต่ coerce_parameters()'s list-coercion แยกจากสตริง comma-separated เท่านั้น
    # (ใช้ไม่ได้กับ dict) - dhcpLocalInterfaceForm.jsx ประกอบพารามิเตอร์ให้เองอยู่
    # แล้ว ไม่ผ่านฟอร์มกลาง จึงซ่อนเหมือน create_nat_policy/create_acl ด้านบน
    "set_dhcp_local_interfaces",
    # (User Info) เรียกจากหน้า user_info.jsx เท่านั้น - ต้องผ่าน guard ใน device_router
    # (ตรวจ policy, อ่าน user สดก่อนเขียน, ตัดรหัสผ่านออกจากประวัติ) ห้ามโผล่ในฟอร์มกลาง
    "set_new_local_user",
    "edit_local_user",
    "delete_local_user",
    # Invoked only by the dedicated, confirmed action in Device Setting.
    "reboot",
}


def module_for_vendor(vendor: str):
    modules = {
        "cisco": "vendor_translators.cisco_iosxe",
        "juniper": "vendor_translators.juniper_junos",
        "huawei": "vendor_translators.huawei_vrp",
    }
    if vendor not in modules:
        return None
    return import_module(modules[vendor])


def has_translator(vendor: str) -> bool:
    return module_for_vendor(vendor) is not None

def _classify_parameter(parameter: inspect.Parameter) -> dict:
    annotation = parameter.annotation
    base_type = _unwrap_optional(annotation)
    origin = typing.get_origin(base_type)

    if base_type is bool:
        return {"type": "bool"}
    if origin is list or base_type in (list, "list[str]"):
        return {"type": "list"}
    if origin is typing.Literal:
        # Literal ล้วนๆ (ไม่ผสมกับ type อื่นแบบ `Literal[...] | int`) -> โชว์เป็น
        # dropdown ให้เลือกตรงๆ ดีกว่าให้พิมพ์เอง (เช่น action: permit/deny,
        # mode: access/trunk) — ค่าที่ frontend เลือกส่งกลับมาเป็น string เสมอ
        # coerce_parameters() จัดการแปลงกลับเป็น int ให้เองถ้า choices เป็นตัวเลข
        return {"type": "select", "choices": list(typing.get_args(base_type))}
    return {"type": "text"}


def functions_for_vendor(vendor: str) -> list[dict]:
    module = module_for_vendor(vendor)
    if not module:
        return []
    result = []
    for name in sorted(PUBLIC_FUNCTIONS):
        # composite ซ่อนจากฟอร์มกลาง (ดู COMPOSITE_FUNCTIONS) - ยังเรียกผ่าน
        # build_payload/API ได้ตามปกติ แค่ไม่โผล่ในรายการให้ผู้ใช้กดเอง
        if name in COMPOSITE_FUNCTIONS:
            continue
        function = getattr(module, name, None)
        if function:
            result.append(
                {
                    "name": name,
                    "parameters": [
                        {
                            "name": parameter.name,
                            "required": parameter.default is inspect.Parameter.empty,
                            "default": None
                            if parameter.default is inspect.Parameter.empty
                            else parameter.default,
                            **_classify_parameter(parameter),
                        }
                        for parameter in inspect.signature(function).parameters.values()
                    ],
                }
            )
    return result


def _unwrap_optional(annotation):
    # BUG ที่เจอทีหลัง: "X | None" แบบ PEP 604 (เขียนด้วย |, ที่ vendor_translators
    # ทุกไฟล์ใช้กันเกือบหมด) กับ Optional[X]/typing.Union[X, None] (บบเก่าเขียนด้วย
    # bracket) get_origin() คืนคนละ object กัน — PEP 604 คืน types.UnionType ส่วน
    # แบบเก่าคืน typing.Union ถ้าเช็คแค่ typing.Union อย่างเดียว (โค้ดเดิมก่อนแก้)
    # จะ unwrap ไม่สำเร็จเลยสักตัวสำหรับ "X | None" ทำให้ list[str] | None ไม่ถูก
    # coerce เป็น list ("ping" กลายเป็น iterate ทีละตัวอักษรในฟังก์ชันที่รับ list)
    if typing.get_origin(annotation) in _UNION_ORIGINS:
        args = [arg for arg in typing.get_args(annotation) if arg is not type(None)]
        if len(args) == 1:
            return args[0]
    return annotation


def coerce_parameters(function, raw: dict) -> dict:
    # ค่าที่ frontend ส่งมาเป็น JSON string ล้วน (input/checkbox/textarea ธรรมดา)
    # ต้องแปลงให้ตรงกับ type annotation จริงของฟังก์ชันก่อนเรียก เพราะฟังก์ชันพวกนี้
    # ทำ arithmetic/range check ตรงๆ (เช่น "if not 1 <= vlan_id <= 4094") ซึ่งพังทันที
    # ถ้าค่าที่ส่งมายังเป็น str อยู่ ไม่ใช่ int จริง — schema แบบ bool/list/text จาก
    # functions_for_vendor() แค่พอสำหรับเลือกว่าจะ render input แบบไหน ไม่ได้ coerce
    # type จริงให้
    signature = inspect.signature(function)
    coerced = dict(raw)
    for name, parameter in signature.parameters.items():
        if name not in coerced:
            continue
        value = coerced[name]
        if value is None:
            continue
        base_type = _unwrap_optional(parameter.annotation)
        origin = typing.get_origin(base_type)
        literal_args = typing.get_args(base_type) if origin is typing.Literal else ()
        if base_type is bool:
            if isinstance(value, str):
                coerced[name] = value.strip().lower() in ("1", "true", "yes", "on")
        elif base_type is int:
            if name in ("prefix", "mask"):
                coerced[name] = validate_prefix(value, name)
                continue
            if name in ("lease_minutes", "lease_seconds") and (isinstance(value, bool) or (isinstance(value, float) and not value.is_integer())):
                raise ValueError(f"{name} must be a whole number")
            if not isinstance(value, int) or isinstance(value, bool):
                coerced[name] = int(value)
        elif origin is list or base_type is list:
            if isinstance(value, str):
                coerced[name] = [item.strip() for item in value.split(",") if item.strip()]
        elif literal_args and all(isinstance(arg, int) and not isinstance(arg, bool) for arg in literal_args):
            # Literal[1, 2] แบบ set_rip_routing's version — ตัวเลือกเป็น int ล้วน
            # ต้อง coerce ด้วย ไม่งั้น "2" (str) == 2 (int) จะเทียบไม่ตรงเงียบๆ ข้างใน
            if not isinstance(value, int):
                coerced[name] = int(value)
        # str / Literal[str, ...] / อย่างอื่น -> ปล่อยผ่านตามเดิม (ค่าที่ frontend
        # ส่งมาตรงกับ choice string อยู่แล้ว)
    return coerced


def build_payload(vendor: str, function_name: str, parameters: dict) -> str:
    module = module_for_vendor(vendor)
    if not module or function_name not in PUBLIC_FUNCTIONS:
        raise ValueError("Feature is under development")
    function = getattr(module, function_name, None)
    if not function:
        raise ValueError("Feature is not supported by this translator")
    return function(**coerce_parameters(function, parameters))


def commit_payload(vendor: str, *, candidate_override: bool = False) -> str | None:
    # (C4) Huawei เขียนลง candidate เหมือน Juniper แล้ว จึงต้อง commit ตามทุกครั้ง
    if vendor not in ("juniper", "huawei") and not candidate_override:
        return None
    module = module_for_vendor(vendor)
    return module.open_rpc_tag("<commit/>")


# เรียกตอน commit ล้มเหลวจริง (severity="error") เพื่อล้าง candidate กลับไปตรงกับ
# running ทันที (RFC 6241 §8.3.4) - เดิมไม่มีขั้นตอนนี้เลย ทำให้ edit-config ที่
# สำเร็จไปแล้ว (แค่ commit ล้มเหลวทีหลัง) ค้างอยู่ใน candidate ตลอดไป สะสมทับกัน
# ไปเรื่อยๆ ทุกครั้งที่ commit ล้มเหลว (ยืนยันจริง: เจอ address ซ้อนกัน 2 ชุดบน
# unit เดียวจาก 2 ความพยายามที่ fail คนละรอบ ค้างรวมกันอยู่ใน candidate เดียว)
def discard_changes_payload(vendor: str, *, candidate_override: bool = False) -> str | None:
    if vendor not in ("juniper", "huawei") and not candidate_override:
        return None
    module = module_for_vendor(vendor)
    return module.open_rpc_tag("<discard-changes/>")
