import ipaddress
import re
import itertools
import xml.etree.ElementTree as ET
from tools.safe_xml import safe_fromstring
from xml.sax.saxutils import escape, quoteattr
from tools.hostname_policy import validate_hostname
from tools.dhcp_range import range_exclusions, validate_dhcp_network_gateway
from tools.dhcp_lease import lease_seconds_value
from tools.dhcp_edit import named_removals
from tools.net_input_policy import (
    validate_config_name,
    validate_distance,
    validate_domain_name,
    validate_host_in_network,
    validate_ipv4,
    validate_object_ref,
    validate_ospf_area,
    validate_psk,
    UINT32_MAX,
)
from tools.password_hash import hash_password_sha512

from pydantic import StrictInt, validate_call
from typing import Awaitable, Callable, Literal

from vendor_translators.juniper_acl import (
    build_juniper_replace_acl_payload,
    build_juniper_replace_interface_bindings_payload,
)
from vendor_translators.juniper_security_policy import (
    build_juniper_security_policy_edit_payload,
    juniper_security_policy_move_fragment,
    build_juniper_security_policy_zone_move_fragment,
)


NS_RPC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NS_ROOT = "http://yang.juniper.net/junos-es/conf/root"
NS_SYSTEM = "http://yang.juniper.net/junos-es/conf/system"
NS_INTERFACES = "http://yang.juniper.net/junos-es/conf/interfaces"
NS_ROUTING_OPTIONS = "http://yang.juniper.net/junos-es/conf/routing-options"
NS_PROTOCOLS = "http://yang.juniper.net/junos-es/conf/protocols"
NS_POLICY_OPTIONS = "http://yang.juniper.net/junos-es/conf/policy-options"
NS_FIREWALL = "http://yang.juniper.net/junos-es/conf/firewall"
NS_VLANS = "http://yang.juniper.net/junos-es/conf/vlans"
NS_SECURITY = "http://yang.juniper.net/junos-es/conf/security"
NS_RPC_INTERFACES = "http://yang.juniper.net/junos-es/rpc/interfaces"
NS_RPC_ROUTE = "http://yang.juniper.net/junos-es/rpc/route"
NS_RPC_VERSION = "http://yang.juniper.net/junos-es/rpc/version"
NS_RPC_SYSTEM = "http://yang.juniper.net/junos-es/rpc/system"
NS_RPC_ARP = "http://yang.juniper.net/junos-es/rpc/arp"
NS_FORWARDING_OPTIONS = "http://yang.juniper.net/junos-es/conf/forwarding-options"
NS_ACCESS = "http://yang.juniper.net/junos-es/conf/access"
NS_RPC_PING = "http://yang.juniper.net/junos-es/rpc/ping"
NS_RPC_CHASSIS = "http://yang.juniper.net/junos-es/rpc/chassis"


_msg_counter = itertools.count(1)


def next_msg_id() -> str:
    return str(next(_msg_counter))


def open_rpc_tag(
    xmltags: str,
    version: str = "1.0",
    xmlns: str = NS_RPC,
    encoding: str = "UTF-8",
):
    return f'''
<?xml version="{version}" encoding="{encoding}"?>
<rpc message-id="{next_msg_id()}" xmlns="{xmlns}">
    {xmltags}
</rpc>
'''


@validate_call
def datastore_tag(
    datastore: Literal["running", "candidate", "startup"] = "running",
):
    return f'''
    <target>
        <{datastore}/>
    </target>
    '''


def _interface_name(interface_type: str, interface_id: str) -> str:
    interface_type = (interface_type or "").strip()
    interface_id = (interface_id or "").strip()
    # ยืนยันจริงกับอุปกรณ์ (vSRX): interface_id ว่างไม่ใช่ error เสมอไป - Junos
    # มี interface ที่ชื่อสมบูรณ์ในตัวเองอยู่แล้วไม่มีเลขต่อท้ายเลย (irb, lo0,
    # dsc, gre, ipip, lsi, mtun, tap ฯลฯ - เห็นจาก `show interfaces terse` จริง)
    # เดิม raise ทันทีถ้า interface_id ว่าง ทำให้ remove_interface_unit/
    # set_no_shutdown/set_shutdown เรียกด้วย interface_type="irb" ไม่ได้เลย (เช่น
    # ตอนลบ irb.<vlan_id> SVI ที่ resolveDeleteParams ส่ง interface_id ว่างมา
    # เพราะ irb ไม่มีส่วน id แยกจาก type แบบ ge-/xe- ที่ต้องมีเลขสล็อตต่อท้ายเสมอ)
    if not interface_type:
        raise ValueError("interface_type is required")
    return escape(f"{interface_type}{interface_id}")


def _description_xml(description: str | None) -> str:
    if description is None:
        return ""
    if description == "":
        return f'<description xmlns:nc="{NS_RPC}" nc:operation="remove"/>'
    if not 1 <= len(description) <= 200:
        raise ValueError("description must be between 1 and 200 characters")
    if any(not (0x20 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD
                or 0x10000 <= ord(char) <= 0x10FFFF) for char in description):
        raise ValueError("description contains an invalid XML/control character")
    return f"<description>{escape(description)}</description>"

# MTU: optional - ไม่ส่งมา (None) = ไม่สร้าง <mtu> เลย ใช้ค่า default ของอุปกรณ์
# ต่อไป (68-9216 ตาม valid range ทั่วไป) - แก้ปัญหา OSPF neighbor ค้าง EXSTART/
# EXCHANGE ข้ามยี่ห้อ (DBD packet MTU mismatch) - Junos ตั้ง mtu ที่ระดับ
# physical <interface> เสมอ (sibling ของ <name>) ไม่ใช่ต่อ <unit> เหมือน
# family/address (ยืนยันตาม Junos CLI hierarchy: `interfaces { ge-0/0/1 { mtu
# 1500; unit 0 {...} } }`)
def _removed_addresses_xml(values: list[str] | None, keep: str | None = None) -> str:
    addresses = dict.fromkeys(str(ipaddress.IPv4Interface(value)) for value in values or [])
    return "".join(
        f'<address xmlns:nc="{NS_RPC}" nc:operation="remove"><name>{address}</name></address>'
        for address in addresses if address != keep
    )


def _mtu_xml(mtu: int | None) -> str:
    if mtu is None:
        return ""
    if not 68 <= mtu <= 9216:
        raise ValueError("MTU must be between 68 and 9216")
    return f"<mtu>{mtu}</mtu>"


def _edit_configuration(configuration: str) -> str:
    return open_rpc_tag(f'''
<edit-config>
  {datastore_tag("candidate")}
  <config>
    <configuration xmlns="{NS_ROOT}">
      {configuration}
    </configuration>
  </config>
</edit-config>
    ''')

# show running-configuration
def get_running_config():
    return open_rpc_tag('''
<get-config>
  <source>
    <running/>
  </source>
</get-config>
    ''')


# show routing table
def get_routing_table():
    return open_rpc_tag(f'<get-route-information xmlns="{NS_RPC_ROUTE}"/>')

# show arp table
# เดิมยิงเปล่าๆ ไม่มี flag เลย - ยืนยันจริงกับอุปกรณ์ว่า Junos "show arp" เฉยๆ
# **ไม่คืน state/time-to-expire มาเลย** (ต่างจาก Cisco/Huawei ที่ข้อมูลนี้มาเป็น
# ค่า default) ต้องระบุ flag `<expiration-time/>`/`<state/>` ใน RPC input ตรงๆ
# ถึงจะได้มา (ยืนยันจาก junos-es-rpc-arp.yang's input leaves + ทดสอบจริงผ่าน
# `show arp expiration-time state | display xml` ว่ารวม flag พร้อมกันได้ในคำขอเดียว
# ได้ทั้ง <time-to-expire>/<state> มาพร้อมกัน ไม่ต้องยิงหลายรอบแยก) -
# response_normalizer.py's normalize_arp รอ field "time-to-expire"/"state" อยู่แล้ว
# (unify เป็น age/type)
#
# <no-resolve/>: จำเป็นอย่างยิ่งเพื่อป้องกัน Junos พยายาม reverse DNS resolve IP
# address เป็น hostname แบบ symbolic ซึ่งถ้าไม่ส่ง flag นี้ อุปกรณ์จะติด timeout
# การ resolve ประมาณ 6 วินาทีก่อนตอบกลับ - ผลทดสอบจริงบนอุปกรณ์ Juniper ยืนยันว่า
# การเพิ่ม <no-resolve/> ลดเวลาตอบกลับจากประมาณ 6.1 วินาทีเหลือประมาณ 0.12 วินาที
# โดยได้รายการ ARP ครบถ้วนตามเดิม รักษาทั้ง <expiration-time/> และ <state/>
# และเป็น read-only operational RPC โดยสิ้นเชิง ไม่มีการเปลี่ยนแปลง configuration ใดๆ
def get_arp_table():
    return open_rpc_tag(f'''
<get-arp-table-information xmlns="{NS_RPC_ARP}">
  <no-resolve/>
  <expiration-time/>
  <state/>
</get-arp-table-information>
    ''')

# show interface list (แค่ชื่อ ใช้เติม dropdown เลือก interface ในฟอร์มต่างๆ) -
# Junos ไม่มี oper query แบบ "ชื่อ interface ล้วนๆ" เหมือน Cisco's ietf-interfaces
# oper minimal query โดยตรง เลย reuse RPC เดียวกับ get_ip_interface_brief (terse)
# ไปเลย - normalize_interfaces() (response_normalizer.py) parse ออกมาเป็น
# {name, ip, subnet, ...} เหมือนกันอยู่แล้ว ฝั่ง frontend ที่ใช้ทำ dropdown ก็
# หยิบแค่ row.name ไปใช้อยู่แล้วไม่สนใจ field อื่น (ดู natFormModal.jsx เป็นต้น)
def get_interface_list():
    return open_rpc_tag(f'''
<get-interface-information xmlns="{NS_RPC_INTERFACES}">
  <level-extra>terse</level-extra>
</get-interface-information>
    ''')


# หน้า ping.jsx - Cisco ใช้ IP SLA (config entry -> รอ -> query ผล -> ลบทิ้ง)
# เพราะ IOS-XE ไม่มี native ping RPC ที่ทดสอบแล้วว่าใช้ได้จริงตรงๆ - Junos มี
# `<ping>` operational RPC ของตัวเองที่ **ส่งคำขอครั้งเดียวได้ผลลัพธ์กลับมาทันที
# แบบ synchronous ในเรพลายเดียว** (ยืนยัน schema จาก junos-es-rpc-ping.yang) ไม่
# ต้องมี config/wait/cleanup แบบ Cisco เลย - รับ `send` callback เหมือนกับ
# Cisco's version เพื่อให้ device_router.py เรียกใช้ผ่าน interface เดียวกันได้
# (`await run_ping_test(send, destination, source_interface=...)`) แม้ภายในจะ
# เป็นแค่ RPC เดียวก็ตาม - ผลลัพธ์ (<ping-results>) ผ่าน normalize_generic ปกติ
# (ไม่มี parser เฉพาะใน NORMALIZERS ให้ "get_ping_result" - ไม่ต้องเพิ่มเพราะ
# generic ก็พอสำหรับ frontend ที่ parse เอง เหมือนฟีเจอร์อื่นๆ ในเซสชันนี้)
async def run_ping_test(
    send: Callable[[str], Awaitable[str]],
    destination: str,
    source_interface: str = None,
    count: int = 5,
) -> str:
    if not 1 <= count <= 20:
        raise ValueError("count must be between 1 and 20")
    interface_xml = f"<interface>{escape(source_interface)}</interface>" if source_interface else ""
    payload = open_rpc_tag(f'''
      <ping xmlns="{NS_RPC_PING}">
        <host>{escape(destination)}</host>
        <count>{count}</count>
        {interface_xml}
      </ping>
    ''')
    return await send(payload)

# show interface information and status
def get_interface_information():
    return open_rpc_tag(
        f'<get-interface-information xmlns="{NS_RPC_INTERFACES}"/>'
    )

# show interface information in short
# def get_ip_interface_brief():
#     return open_rpc_tag(f'''
#       <get-interface-information xmlns="{NS_RPC_INTERFACES}">
#         <level-extra>terse</level-extra>
#       </get-interface-information>
#     ''')

def get_ip_interface_brief():
    return open_rpc_tag(f'''
      <get-interface-information xmlns="{NS_RPC_INTERFACES}"/>
    ''')

# show device version
def get_device_version():
    return open_rpc_tag(f'<get-software-information xmlns="{NS_RPC_VERSION}"/>')

# CPU/RAM สำหรับ Basic Info dashboard (poll ทุก 10 วิจาก backend background
# poller - ดู conn_socket.py) - ยืนยัน RPC/response shape จริงกับอุปกรณ์แล้ว
# (2026-07-30, BR1-Firewall-1): `<get-route-engine-information/>` ตรงกับ
# `show chassis routing-engine` เป๊ะ คืน route-engine-information/route-engine
# มี cpu-user/cpu-background/cpu-system/cpu-interrupt/cpu-idle (percent แยกส่วน
# ไม่ใช่ single "cpu usage" - คำนวณ used = 100 - cpu-idle เอาเอง) กับ
# memory-system-total/-total-used/-total-util (มี percent ให้ตรงๆ อยู่แล้ว)
def get_cpu_memory_information():
    return open_rpc_tag(f'<get-route-engine-information xmlns="{NS_RPC_CHASSIS}"/>')

# show device license
def get_device_license():
    return open_rpc_tag(f'<get-license-information xmlns="{NS_RPC_SYSTEM}"/>')

# set hostname
@validate_call
def set_hostname(hostname: str):
    # (bug 12) เดิมเช็ค "0 <= len <= 255" ซึ่งขอบล่างเป็น 0 แปลว่า string ว่างผ่านได้
    # (เงื่อนไขที่เป็นจริงเสมอสำหรับ str ทุกตัวที่ไม่ยาวเกิน 255) - ย้ายมาใช้นโยบายกลาง
    hostname = validate_hostname(hostname)
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <host-name>{escape(hostname)}</host-name>
</system>
    ''')

# set interface static ip
@validate_call
def set_interface_static_ip(
    interface_type: str,
    interface_id: str,
    ip: str,
    mask: int,
    description: str | None = None,
    shutdown: bool = True,
    mtu: int | None = None,
    previous_addresses: list[str] | None = None,
):
    interface = _interface_name(interface_type, interface_id)
    address = ipaddress.IPv4Interface(f"{ip}/{mask}")
    addresses_xml = _removed_addresses_xml(previous_addresses, str(address))
    mtu_xml = _mtu_xml(mtu)
    description_xml = _description_xml(description)
    disable_xml = (
        "<disable/>" if shutdown else f'<disable xmlns:nc="{NS_RPC}" nc:operation="remove"/>'
    )
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    {disable_xml}
    {mtu_xml}
    <unit>
      <name>0</name>
      {description_xml}
      <family>
        <inet>
          <dhcp xmlns:nc="{NS_RPC}" nc:operation="remove"/>
          {addresses_xml}
          <address>
            <name>{address}</name>
          </address>
        </inet>
      </family>
    </unit>
  </interface>
</interfaces>
''')

@validate_call
def set_interface_l3_none(
    interface_type: str, 
    interface_id: str, 
    unit: int = 0,
    previous_addresses: list[str] | None = None,
    vlan_name: str | None = None,
    shutdown: bool | None = None, 
    description: str | None = None
):
    interface = _interface_name(interface_type, interface_id)
    if not 0 <= unit <= 16384:
        raise ValueError("unit must be between 0 and 16384")
    if interface == "irb" and not 1 <= unit <= 4094:
        raise ValueError("irb unit must be between 1 and 4094")
    if vlan_name is not None and interface != "irb":
        raise ValueError("vlan_name is only supported for irb")
    addresses_xml = _removed_addresses_xml(previous_addresses)
    binding_xml = _vlan_l3_binding_xml(vlan_name, unit) if vlan_name is not None else ""
    tagged = unit > 0 and interface != "irb"
    tagging_xml = "<vlan-tagging/>" if tagged else ""
    vlan_xml = f"<vlan-id>{unit}</vlan-id>" if tagged else ""
    # family ethernet-switching is valid for switch-capable physical units,
    # but it is not a valid family on an IRB unit.  Sending even a remove
    # operation for that node makes Junos reject the whole edit with a syntax
    # error.  An IRB set to None only needs its inet children cleared while the
    # unit and VLAN l3-interface binding remain in place.
    switching_remove_xml = "" if interface == "irb" else f'<ethernet-switching xmlns:nc="{NS_RPC}" nc:operation="remove"/>'
    admin_xml = "" if shutdown is None else "<disable/>" if shutdown else f'<disable xmlns:nc="{NS_RPC}" nc:operation="remove"/>'
    desc_xml = _description_xml(description)
    parent_admin = admin_xml if interface != "irb" and unit == 0 else ""
    unit_admin = admin_xml if interface == "irb" or unit != 0 else ""
    return _edit_configuration(f'''
      <interfaces xmlns="{NS_INTERFACES}"><interface>
        <name>{interface}</name>{tagging_xml}{parent_admin}
        <mtu xmlns:nc="{NS_RPC}" nc:operation="remove"/>
        <unit><name>{unit}</name>{vlan_xml}{unit_admin}{desc_xml}<family>
          {switching_remove_xml}
          <inet><dhcp xmlns:nc="{NS_RPC}" nc:operation="remove"/>{addresses_xml}</inet>
        </family></unit>
      </interface></interfaces>
      {binding_xml}
    ''')


# set interface get dhcp ip
@validate_call
def set_interface_ip_dhcp(
    interface_type: str, interface_id: str, mtu: int | None = None,
    shutdown: bool | None = None,
    static_addresses: list[str] | None = None,
    description: str | None = None,
):
    interface = _interface_name(interface_type, interface_id)
    mtu_xml = _mtu_xml(mtu)
    # Delete each keyed address read from configuration, not the unit/family:
    # this retains filters and other unrelated inet settings.
    addresses_xml = _removed_addresses_xml(static_addresses)
    # Preserve admin state for existing callers that omit shutdown.
    description_xml = _description_xml(description)
    disable_xml = "" if shutdown is None else (
        "<disable/>" if shutdown else f'<disable xmlns:nc="{NS_RPC}" nc:operation="remove"/>'
    )
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    {mtu_xml}
    {disable_xml}
    <unit>
      <name>0</name>
      {description_xml}
      <family>
        <inet>
          {addresses_xml}
          <dhcp/>
        </inet>
      </family>
    </unit>
  </interface>
</interfaces>
''')

# set sub-interface ip
@validate_call
def set_sub_interface_ip(
    interface_type: str,
    interface_id: str,
    vlan_id: int,
    ip: str,
    prefix: int,
    description: str | None = None,
    native: bool = False,
    mtu: int | None = None,
    previous_addresses: list[str] | None = None,
):
    if not 0 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 0 and 4094")
    native_xml = f"<native-vlan-id>{vlan_id}</native-vlan-id>" if native else ""
    interface = _interface_name(interface_type, interface_id)
    address = ipaddress.IPv4Interface(f"{ip}/{prefix}")
    addresses_xml = _removed_addresses_xml(previous_addresses, str(address))
    description_xml = _description_xml(description)
    mtu_xml = _mtu_xml(mtu)
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    {native_xml}
    {mtu_xml}
    <vlan-tagging/>
    <unit>
      <name>{vlan_id}</name>
      {description_xml}
      <vlan-id>{vlan_id}</vlan-id>
      <family>
        <inet>
          {addresses_xml}
          <address>
            <name>{address}</name>
          </address>
        </inet>
      </family>
    </unit>
  </interface>
</interfaces>
''')

@validate_call
def remove_interface_mtu(interface_type: str, interface_id: str):
    """Remove configured physical MTU and let Junos use its platform default."""
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <mtu xmlns:nc="{NS_RPC}" nc:operation="remove"/>
  </interface>
</interfaces>
    ''')


# set no shutdown interface
@validate_call
def set_no_shutdown(interface_type: str, interface_id: str):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <disable xmlns:nc="{NS_RPC}" nc:operation="remove"/>
  </interface>
</interfaces>
    ''')

# set shutdown interface
@validate_call
def set_shutdown(interface_type: str, interface_id: str):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <disable/>
  </interface>
</interfaces>
''')

# set static routing
@validate_call
def set_static_route(
    prefix: str,
    mask: int,
    next_hop: str = None,
    interface_type: str = None,
    interface_id: str = None,
    distance: int | None = None,
    replace_prefix: str | None = None,
    replace_mask: int | None = None,
):
    network = ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
    next_hops = []
    if next_hop:
        next_hops.append(str(ipaddress.IPv4Address(next_hop)))
    if interface_type and interface_id:
        next_hops.append(_interface_name(interface_type, interface_id))
    if not next_hops:
        raise ValueError("next_hop or interface_type/interface_id is required")

    next_hop_xml = "\n".join(
        f"<next-hop>{value}</next-hop>" for value in next_hops
    )
    # (bug 13) เดิมเช็คแค่ขอบล่าง (preference < 0) ซึ่งไม่มีขอบบน - <preference>
    # <metric-value> ของ Junos ใช้ grouping rib_static_metric_type ที่เป็น uint32
    # และ "ไม่ได้จำกัด range ไว้เอง" (ยืนยันจาก
    # device_capability/juniper/junos-es-conf-routing-options.yang:9976-9984) ขอบบน
    # จริงจึงเป็นค่าสูงสุดของ uint32 - กว้างกว่า Cisco/Huawei (1-255) มาก จึงห้ามเอา
    # ช่วงของยี่ห้ออื่นมาใช้ เพราะจะไปปฏิเสธค่าที่อุปกรณ์รับได้จริง
    preference_xml = ""
    if distance is not None:
        preference = validate_distance(distance, 0, UINT32_MAX)
        preference_xml = (
            f"<preference><metric-value>{preference}</metric-value></preference>"
        )

    # Junos เขียนลง candidate แล้ว commit ภายหลัง การรวม key เดิมกับค่าใหม่ไว้ใน
    # edit-config เดียวทำให้ commit สำเร็จทั้งก้อนหรือ discard ทั้งก้อน ไม่มีช่วงที่
    # route เดิมถูกลบออกจาก running ก่อนสร้างค่าใหม่
    replace_values = (replace_prefix, replace_mask)
    old_route_xml = ""
    route_operation = ""
    if any(value is not None for value in replace_values):
        if any(value is None for value in replace_values):
            raise ValueError("replace_prefix and replace_mask must be provided together")
        old_network = ipaddress.IPv4Network(f"{replace_prefix}/{replace_mask}", strict=False)
        if old_network == network:
            route_operation = f' xmlns:nc="{NS_RPC}" nc:operation="replace"'
        else:
            old_route_xml = f'''
    <route xmlns:nc="{NS_RPC}" nc:operation="delete">
      <name>{old_network}</name>
    </route>'''

    return _edit_configuration(f'''
<routing-options xmlns="{NS_ROUTING_OPTIONS}">
  <static>
    {old_route_xml}
    <route{route_operation}>
      <name>{network}</name>
      {next_hop_xml}
      {preference_xml}
    </route>
  </static>
</routing-options>
    ''')


# ลบ route ทิ้งทั้งตัว - routing-options/static/route keyed ด้วย name (=network
# CIDR) ตรงๆ ตัวเดียว (ไม่มี fwd-list ซ้อนแบบ Cisco) ลบ <route> ทั้งก้อนพอ
@validate_call
def remove_static_route(prefix: str, mask: int):
    network = ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
    return _edit_configuration(f'''
<routing-options xmlns="{NS_ROUTING_OPTIONS}">
  <static>
    <route xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{network}</name>
    </route>
  </static>
</routing-options>
    ''')


# ตาราง "static route ทุกตัว (ตั้งค่าไว้ ไม่ว่าจะ active หรือไม่)" - อ่านจาก config
# ตรงๆ (routing-options/static) เหมือนฝั่ง Cisco - Junos ก็มี concept "route
# resolve ไม่ได้เลยไม่ active" เหมือนกัน (next-hop unreachable) แต่ get-route-
# information (ที่ get_routing_table ใช้) โชว์แค่ route ที่ active เท่านั้นเช่นกัน
def get_static_route_configuration():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <routing-options xmlns="{NS_ROUTING_OPTIONS}">
        <static/>
      </routing-options>
    </configuration>
  </filter>
</get-config>
    ''')


def _vlan_l3_binding_xml(vlan_name: str, unit: int, *, remove: bool = False) -> str:
    vlan_name = vlan_name.strip()
    if not vlan_name or len(vlan_name) > 64:
        raise ValueError("vlan_name must be between 1 and 64 characters and not blank")
    if any(not (0x20 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD
                or 0x10000 <= ord(char) <= 0x10FFFF) for char in vlan_name):
        raise ValueError("vlan_name contains an invalid XML/control character")
    operation = f' xmlns:nc="{NS_RPC}" nc:operation="remove"' if remove else ""
    return f'''<vlans xmlns="{NS_VLANS}">
      <vlan><name>{escape(vlan_name)}</name>
        <l3-interface{operation}>irb.{unit}</l3-interface>
      </vlan>
    </vlans>'''


# remove interface unit and its VLAN references in the same edit-config
@validate_call
def remove_interface_unit(interface_type: str, interface_id: str, unit: int,
                          vlan_names: list[str] | None = None):
    interface = _interface_name(interface_type, interface_id)
    if vlan_names and interface != "irb":
        raise ValueError("vlan_names is only supported for irb")
    bindings_xml = "".join(_vlan_l3_binding_xml(name, unit, remove=True)
                           for name in dict.fromkeys(vlan_names or []))
    return _edit_configuration(f'''
{bindings_xml}
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <unit xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{unit}</name>
    </unit>
  </interface>
</interfaces>
    ''')


# ยืนยันจริงกับอุปกรณ์ (vSRX): set_sub_interface_ip เขียน <vlan-tagging/> ไว้บน
# physical interface เสมอ (จำเป็นสำหรับ 802.1Q sub-interface) แต่ remove_interface_unit
# ด้านบนลบแค่ <unit> ตัวที่ระบุ ไม่เคยแตะ <vlan-tagging/> เลย - ลบ sub-interface
# ตัวสุดท้ายบน parent port ทิ้งไปแล้ว vlan-tagging ยังค้างอยู่ ทำให้ port นั้นใช้
# unit 0 แบบ untagged (Interface ธรรมดา/L2 switchport) ไม่ได้อีกต่อไป - Junos ปฏิเสธ
# ด้วย "VLAN-ID must be specified on tagged ethernet interfaces" ทันที (ยืนยันจริง)
# แถมยัง auto-generate unit 32767 ผีๆ ให้เห็นใน show interfaces terse ทำให้ port
# หายไปจาก dropdown เลือก interface เปล่าๆ ในหน้าเว็บด้วย - ต้องเรียกฟังก์ชันนี้
# แยกต่างหาก (ฝั่งเรียกต้องเช็คเองว่าเป็น sub-interface ตัวสุดท้ายบน parent นั้น
# จริงๆ ก่อน ไม่งั้นจะไปลบ vlan-tagging ทั้งที่ยังมี sub-interface อื่นต้องใช้อยู่)
@validate_call
def remove_vlan_tagging(interface_type: str, interface_id: str):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <vlan-tagging xmlns:nc="{NS_RPC}" nc:operation="remove"/>
  </interface>
</interfaces>
    ''')


# เดิมฟังก์ชันนี้เขียนลง system/services/dhcp/pool (subsystem เก่า/เรียบง่าย
# ของ Junos) แต่ subsystem นั้น**ห้ามอยู่ร่วมกับ DHCP client ตัวไหนก็ตามบน
# อุปกรณ์เดียวกันเด็ดขาด** (ยืนยันจริง: ge-0/0/0 เป็น DHCP client เดิมของ
# อุปกรณ์นี้ ทำให้สร้าง DHCP server ไม่ได้เลยสักครั้ง โดน error "Incompatible
# with the dhcp server configured under 'system services dhcp'" - เข้าใจผิดไป
# ก่อนหน้านี้ว่าเป็นข้อจำกัดจริงของอุปกรณ์ที่แก้ไม่ได้) - user ชี้ทางที่ถูกต้อง
# มาว่า SRX/vSRX ควรใช้ subsystem ใหม่กว่าคือ access/address-assignment/pool
# (นิยาม pool) คู่กับ system/services/dhcp-local-server/group/interface (สั่งให้
# interface ไหนแจก DHCP จริง - ดู set_dhcp_server_interface ด้านล่าง) ซึ่ง**ไม่มี
# ข้อจำกัดเรื่อง DHCP client ร่วมอุปกรณ์แบบ subsystem เก่าเลย** เป็นวิธีที่ Junos
# แนะนำจริงสำหรับ SRX-series - ยืนยัน schema จาก junos-es-conf-access.yang
# (grouping dhcp-attribute-type: router/name-server เป็น list คีย์ name เหมือน
# เดิมเป๊ะ ไม่เปลี่ยน - เปลี่ยนแค่ container ที่ห่ออยู่ข้างนอก) - "name" ตอนนี้เป็น
# key จริงของ pool แล้ว (ต่างจาก subsystem เก่าที่ key คือ network CIDR ตรงๆ
# ไม่ใช้ name param ที่ผู้ใช้ตั้งเลย)
def _configured_dhcp_ranges_xml(network, ranges, addresses, excluded_ranges):
    """Preserve explicitly configured Junos ranges and exclusions on pool edits."""
    def nodes(entries, tag):
        if not isinstance(entries, list):
            raise ValueError(f"{tag} must be a list")
        names = set()
        result = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"{tag} entries must be objects")
            name = entry.get("name")
            if not isinstance(name, str) or not 1 <= len(name) <= 63 or name in names:
                raise ValueError(f"{tag} requires unique names containing 1-63 characters")
            names.add(name)
            low = ipaddress.IPv4Address(entry.get("low", ""))
            high = ipaddress.IPv4Address(entry.get("high", ""))
            if low not in network or high not in network or low > high:
                raise ValueError(f"{tag} must be ordered and inside the DHCP network")
            result.append(f"<{tag}><name>{escape(name)}</name><low>{low}</low><high>{high}</high></{tag}>")
        return "".join(result)

    if len(addresses) > 20 or len(excluded_ranges) > 20:
        raise ValueError("Junos supports at most 20 excluded-address and 20 excluded-range entries")
    excluded_xml = []
    for address in addresses:
        ip = ipaddress.IPv4Address(address)
        if ip not in network:
            raise ValueError("Excluded address must be inside the DHCP network")
        excluded_xml.append(f"<excluded-address><name>{ip}</name></excluded-address>")
    return nodes(ranges, "range"), "".join(excluded_xml) + nodes(excluded_ranges, "excluded-range")

@validate_call
def set_dhcp_pool(
    name: str,
    network: str,
    gateway: str | None,
    dns: str | list[str] | None,
    exclude: str | list[str] | None = None,
    lease_days: int | None = None,
    replace_name: str | None = None,
    start_address: str | None = None,
    end_address: str | None = None,
    lease_minutes: int | None = None,
    lease_seconds: int | None = None,
    configured_ranges: list[dict] | None = None,
    configured_excluded_ranges: list[dict] | None = None,
    previous: dict | None = None,
):
    if not 1 <= len(name) <= 63:
        raise ValueError("DHCP pool name must contain 1-63 characters")
    if previous is not None and replace_name:
        raise ValueError("Use in-place pool edit, not replace_name")

    # (bug 78 / ระลอก C) replace_name: ใส่เมื่อเปลี่ยนวง DHCP pool เพื่อลบ pool เดิมออก
    # ใน edit-config เดียวกัน (Atomic 1 action = 1 RPC)
    removal_xml = ""
    old = (replace_name or "").strip()
    if old and old != name:
        if not 1 <= len(old) <= 63:
            raise ValueError("Previous DHCP pool name must be between 1 and 63 characters")
        removal_xml = f'''
    <pool xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(old)}</name>
    </pool>'''

    # None explicitly omits DHCP option 3; keep strict network validation.
    validation_gateway = gateway if gateway is not None else str(ipaddress.IPv4Network(network, strict=True).network_address + 1)
    dhcp_network, validated_gateway = validate_dhcp_network_gateway(network, validation_gateway)
    gateway_ip = validated_gateway if gateway is not None else None
    if configured_excluded_ranges is not None and configured_ranges is None:
        raise ValueError("configured_excluded_ranges requires configured_ranges")
    range_exclude = range_exclusions(dhcp_network, start_address, end_address)

    dns_servers = [dns] if isinstance(dns, str) else (dns or [])
    if isinstance(dns, str) and not dns.strip():
        raise ValueError("At least one DNS server is required")
    dns_servers = list(dict.fromkeys(str(ipaddress.IPv4Address(server)) for server in dns_servers))
    if len(dns_servers) > 3:
        raise ValueError("At most 3 DNS servers are supported")
    dns_xml = "\n".join(
        f"<name-server><name>{ipaddress.IPv4Address(server)}</name></name-server>"
        for server in dns_servers
    )

    excluded_addresses = [exclude] if isinstance(exclude, str) else (exclude or [])
    excluded_addresses = [*excluded_addresses, *range_exclude]
    if configured_ranges is not None:
        if start_address or end_address:
            raise ValueError("Specify configured_ranges or start/end addresses, not both")
        range_xml, exclude_xml = _configured_dhcp_ranges_xml(
            dhcp_network, configured_ranges, excluded_addresses, configured_excluded_ranges or []
        )
    else:
        excluded = set()
        for item in excluded_addresses:
            parts = item.split("-", maxsplit=1)
            low = ipaddress.IPv4Address(parts[0].strip())
            high = ipaddress.IPv4Address(parts[-1].strip())
            if low not in dhcp_network or high not in dhcp_network:
                raise ValueError(f"Excluded range {item} must be inside the DHCP network")
            if low > high:
                raise ValueError(f"Excluded range start {low} must not exceed end {high}")
            excluded.update(
                ipaddress.IPv4Address(value)
                for value in range(int(low), int(high) + 1)
            )

        usable = [
            address
            for address in dhcp_network.hosts()
            if address != gateway_ip
            and address not in excluded
        ]
        if not usable:
            raise ValueError("DHCP pool has no usable client addresses")

        # access/address-assignment/pool/family/inet ใช้ "excluded-address" (มี "d")
        # ต่างจาก subsystem เก่าที่ใช้ "exclude-address" - คนละ list กันจริง ยืนยันจาก
        # junos-es-conf-access.yang (list excluded-address) เทียบกับ
        # junos-es-conf-system.yang (list exclude-address ของ dhcp เก่า) - แถมยังมี
        # max-elements 20 กำกับไว้ (ยืนยันจริงจากอุปกรณ์: ส่ง excluded-address 98
        # รายการ - ขยายจาก exclude range .2-.99 ตรงๆ ทีละ address - โดน "number of
        # elements exceeds limit of 20" ทันทีตอน commit) ต่างจาก subsystem เก่าที่ไม่
        # มีข้อจำกัดนี้ - ที่จริงแล้วไม่จำเป็นต้องแจกแจง exclude ทุกตัวเลย เพราะ
        # low/high ด้านล่างถูกแคบมาเหลือแค่ [usable[0], usable[-1]] อยู่แล้ว (ตัด
        # ส่วนที่ไม่ต้องการทั้งซ้าย-ขวาออกไปเรียบร้อย) - excluded ที่อยู่ "นอก" ช่วง
        # แคบนี้ไปแล้วซ้ำซ้อน ไม่ต้องประกาศซ้ำอีก เหลือแค่ "รู" ที่ตกอยู่ตรงกลาง
        # [usable[0], usable[-1]] จริงๆ เท่านั้นที่ยังต้องกันออกด้วย excluded-address
        internal_gaps = sorted(
            address for address in excluded if usable[0] <= address <= usable[-1]
        )
        if len(internal_gaps) > 20:
            raise ValueError(
                "DHCP pool has too many excluded addresses inside the usable range "
                "(Junos allows at most 20 excluded-address entries per pool)"
            )
        exclude_xml = "\n".join(
            f"<excluded-address><name>{address}</name></excluded-address>"
            for address in internal_gaps
        )

        range_xml = f"<range><name>RANGE-1</name><low>{usable[0]}</low><high>{usable[-1]}</high></range>"
    seconds = lease_seconds_value(lease_minutes, lease_seconds, lease_days)
    lease_xml = f"<maximum-lease-time>{seconds}</maximum-lease-time>" if seconds is not None and seconds > 0 else ""
    source_name = name
    pool_attributes = ""
    router_removals = ""
    if previous is not None:
        old_pool = previous.get("pool", {})
        source_name = old_pool.get("name", "")
        if not isinstance(source_name, str) or not 1 <= len(source_name) <= 63:
            raise ValueError("Existing Juniper pool name is required")
        if source_name != name:
            pool_attributes = f' rename="rename" name={quoteattr(name)}'
        old_inet = old_pool.get("family", {}).get("inet", {})
        old_attrs = old_inet.get("dhcp-attributes", {})
        new_ranges = configured_ranges if configured_ranges is not None else [{"name": "RANGE-1"}]
        range_xml = named_removals(old_inet.get("range"), new_ranges, "range", NS_RPC) + range_xml
        # Every originally configured exclusion remains unless explicitly changed.
        exclude_xml = (named_removals(old_inet.get("excluded-address"), excluded_addresses, "excluded-address", NS_RPC)
                       + named_removals(old_inet.get("excluded-range"), configured_excluded_ranges or [], "excluded-range", NS_RPC)
                       + exclude_xml)
        router_removals = named_removals(old_attrs.get("router"), [str(gateway_ip)] if gateway_ip is not None else [], "router", NS_RPC)
        dns_xml = named_removals(old_attrs.get("name-server"), dns_servers, "name-server", NS_RPC) + dns_xml
        if not lease_xml and "maximum-lease-time" in old_attrs:
            lease_xml = f'<maximum-lease-time xmlns:nc="{NS_RPC}" nc:operation="remove"/>'

    router_xml = f"<router><name>{gateway_ip}</name></router>" if gateway_ip is not None else ""
    return _edit_configuration(f'''
<access xmlns="{NS_ACCESS}">
  <address-assignment>
    {removal_xml}
    <pool{pool_attributes}>
      <name>{escape(source_name)}</name>
      <family>
        <inet>
          <network>{dhcp_network}</network>
          {range_xml}
          {exclude_xml}
          <dhcp-attributes>
            {router_removals}
            {router_xml}
            {dns_xml}
            {lease_xml}
          </dhcp-attributes>
        </inet>
      </family>
    </pool>
  </address-assignment>
</access>
    ''')


# ลบ pool ทิ้ง - key ของ access/address-assignment/pool คือ "name" ตรงๆ (ต่าง
# จาก subsystem เก่าที่ key เป็น network CIDR) รับ network/exclude ไว้ให้
# signature ตรงกับ Cisco เฉยๆ ไม่ได้ใช้จริง (exclude ซ้อนอยู่ข้างใน <pool> เอง
# ลบทั้งก้อนก็หายไปด้วยอัตโนมัติเหมือน subsystem เก่า)
@validate_call
def remove_dhcp_pool(name: str, network: str | None = None, exclude: str | list[str] | None = None):
    if not 1 <= len(name) <= 63:
        raise ValueError("DHCP pool name must contain 1-63 characters")
    return _edit_configuration(f'''
<access xmlns="{NS_ACCESS}">
  <address-assignment>
    <pool xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(name)}</name>
    </pool>
  </address-assignment>
</access>
    ''')


# บังคับให้ interface ไหนแจก DHCP จริง (access/address-assignment/pool เฉยๆ
# ไม่ทำงานเองถ้าไม่มีขั้นตอนนี้ - pool ถูกเลือกอัตโนมัติจาก subnet ของ interface
# ที่ match กับ pool's network เอง ไม่ต้องระบุชื่อ pool ตรงๆ ที่นี่) ยืนยัน
# schema จาก junos-es-conf-system.yang (grouping dhcp-local-server-group: list
# interface คีย์ name) "group" เป็น container รวม interface หลายตัวได้ - ใช้ชื่อ
# กลุ่มเดียวกันตายตัวสำหรับทุก interface ที่แอปนี้จัดการ (ไม่ต้องสร้าง group
# ใหม่แยกทุกครั้ง - เพิ่ม interface เข้า group เดิมเรื่อยๆ ได้เลย)
@validate_call
def set_dhcp_server_interface(interface_type: str, interface_id: str, unit: int = 0, group: str = "CM-DHCP"):
    interface = _interface_name(interface_type, interface_id)
    if not 1 <= len(group) <= 64:
        raise ValueError("group name must contain 1-64 characters")
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <services>
    <dhcp-local-server>
      <group>
        <name>{escape(group)}</name>
        <interface>
          <name>{interface}.{unit}</name>
        </interface>
      </group>
    </dhcp-local-server>
  </services>
</system>
    ''')


# ถอด interface ออกจาก dhcp-local-server group (ไม่ได้ลบ group ทั้งก้อน - เผื่อ
# interface อื่นใน group เดียวกันยังใช้อยู่) เรียกคู่กับ remove_dhcp_pool เสมอ
# ตอนปิด DHCP Server ของ interface ใดๆ ไม่งั้น group จะยังอ้างอิง interface ที่
# pool ผูกอยู่ถูกลบไปแล้วค้างอยู่เฉยๆ (ไม่ error แต่ก็ไม่มีความหมายอะไรอีกต่อไป)
@validate_call
def remove_dhcp_server_interface(interface_type: str, interface_id: str, unit: int = 0, group: str = "CM-DHCP"):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <services>
    <dhcp-local-server>
      <group>
        <name>{escape(group)}</name>
        <interface xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{interface}.{unit}</name>
        </interface>
      </group>
    </dhcp-local-server>
  </services>
</system>
    ''')


_LOCAL_DHCP_INTERFACE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_/-]*\.\d+")


def _checked_local_dhcp_interface_name(name, *, field="Local DHCP interface"):
    if not isinstance(name, str) or not _LOCAL_DHCP_INTERFACE_RE.fullmatch(name) or name.startswith("all."):
        raise ValueError(f"{field} must include a logical unit, e.g. ge-0/0/1.0")
    if int(name.rsplit(".", 1)[1]) > 4294967295:
        raise ValueError("Interface unit is out of range")
    return name


# ยอมรับทั้งสตริงชื่อ interface ล้วนๆ (signature เดิม) และ {name, upto, exclude}
# (ใหม่ - รองรับ Range/Exclude) แปลงทั้งคู่ให้เป็น canonical member dict ชุดเดียวกัน
# ก่อนคำนวณ delta - ปฏิเสธ key (name) ซ้ำเหมือนพฤติกรรมเดิมทุกประการ
def _checked_local_dhcp_members(entries):
    result = []
    seen = set()
    for entry in entries:
        if isinstance(entry, str):
            member = {"name": entry, "upto": None, "exclude": False}
        elif isinstance(entry, dict):
            member = {
                "name": entry.get("name"),
                "upto": entry.get("upto") or None,
                "exclude": bool(entry.get("exclude")),
            }
        else:
            raise ValueError("Local DHCP interface entries must be a string or an object")
        name = _checked_local_dhcp_interface_name(member["name"])
        if member["upto"] is not None:
            member["upto"] = _checked_local_dhcp_interface_name(member["upto"], field="Up To interface")
        if member["upto"] and member["exclude"]:
            raise ValueError("A local DHCP interface entry cannot combine upto and exclude")
        if name in seen:
            raise ValueError("Local DHCP interfaces must not be duplicated")
        seen.add(name)
        result.append(member)
    return result


def _local_dhcp_member_xml(member, *, operation=None):
    op_attr = f' xmlns:nc="{NS_RPC}" nc:operation="{operation}"' if operation else ""
    inner = ""
    if member.get("upto"):
        inner = f"<upto>{escape(member['upto'])}</upto>"
    elif member.get("exclude"):
        inner = "<exclude/>"
    return f"<interface{op_attr}><name>{escape(member['name'])}</name>{inner}</interface>"


# (2026-09) รองรับ Brownfield dhcp-local-server group ทุกชื่อ (ไม่บังคับย้ายเข้า
# CM-DHCP) และสมาชิกแบบ Range (upto) กับ Exclude - ดู frontend's
# utils/dhcpLocalServer.js สำหรับ data model ฝั่งเว็บที่ตรงกัน
#
# รองรับ parameter 2 รูปแบบพร้อมกัน (เลือกอย่างใดอย่างหนึ่ง ห้ามผสม):
#   - interfaces/previous_interfaces (ของเดิม) - list ของสตริงชื่อ interface ล้วนๆ
#     ยังใช้ได้เหมือนเดิมทุกประการไม่ให้ caller เก่าพัง (ไม่มี upto/exclude)
#   - members/previous_members (ใหม่) - list ของ {name, upto, exclude} รองรับ
#     Range/Exclude ด้วย
#
# diff โดยจับคู่ด้วย "name" (list key จริงตาม junos-es-conf-system.yang - grouping
# dhcp-local-server-group: list interface { key name; leaf upto; leaf exclude }):
#   - key หายไปจาก desired -> nc:operation="remove" (ตัดออกจาก group)
#   - key ใหม่ที่ไม่เคยมีใน old -> เพิ่มธรรมดา (merge - ไม่มี operation attribute)
#   - key เดิมแต่ upto/exclude เปลี่ยน -> nc:operation="replace" เจาะเฉพาะ
#     <interface> entry นั้น (ไม่ใช่ <group> ทั้งก้อน) - replace ของ NETCONF ล้าง
#     leaf ที่ไม่ได้ระบุมาให้เอง (เช่น เปลี่ยนจาก Range เป็น Single แค่ไม่ใส่ <upto>
#     ก็หายไปเอง) โดยไม่กระทบ sibling <interface> อื่นหรือ group-level options เลย
#   - key เดิมไม่เปลี่ยนอะไรเลย -> ไม่ส่งอะไรสำหรับ key นั้น (minimal delta)
#
# ไม่เคยแตะ <group> เอง (ไม่ replace/ไม่ลบ) เลยสักครั้ง - group-level options และ
# group เองไม่มีทางหายแม้ลบสมาชิกตัวสุดท้ายออกหมด (เหลือ group ว่างเปล่าบนอุปกรณ์
# ตามที่ควรเป็น ไม่ใช่ลบ group ทิ้งอัตโนมัติ)
@validate_call
def set_dhcp_local_interfaces(
    interfaces: list[str] | None = None,
    previous_interfaces: list[str] | None = None,
    members: list[dict] | None = None,
    previous_members: list[dict] | None = None,
    group: str = "CM-DHCP",
) -> str:
    """Apply local-server group membership deltas in one edit-config, retaining
    the group's own name and any other configuration under it untouched."""
    group = group.strip()
    if not 1 <= len(group) <= 64:
        raise ValueError("group name must contain 1-64 characters")

    using_members = members is not None or previous_members is not None
    using_legacy = interfaces is not None or previous_interfaces is not None
    if using_members and using_legacy:
        raise ValueError("specify either interfaces/previous_interfaces or members/previous_members, not both")

    if using_members:
        desired = _checked_local_dhcp_members(members or [])
        old = _checked_local_dhcp_members(previous_members or [])
    else:
        desired = _checked_local_dhcp_members(interfaces or [])
        old = _checked_local_dhcp_members(previous_interfaces or [])

    old_by_name = {member["name"]: member for member in old}
    desired_by_name = {member["name"]: member for member in desired}

    removed_xml = "".join(
        f'<interface xmlns:nc="{NS_RPC}" nc:operation="remove"><name>{escape(name)}</name></interface>'
        for name in old_by_name if name not in desired_by_name
    )
    added_xml = "".join(
        _local_dhcp_member_xml(desired_by_name[name])
        for name in desired_by_name if name not in old_by_name
    )
    replaced_xml = "".join(
        _local_dhcp_member_xml(desired_by_name[name], operation="replace")
        for name in desired_by_name
        if name in old_by_name and desired_by_name[name] != old_by_name[name]
    )

    if not removed_xml and not added_xml and not replaced_xml:
        raise ValueError("No local DHCP interface membership changes")

    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <services>
    <dhcp-local-server>
      <group>
        <name>{escape(group)}</name>
        {removed_xml}
        {replaced_xml}
        {added_xml}
      </group>
    </dhcp-local-server>
  </services>
</system>
    ''')

def get_dhcp_pool_information():
    return open_rpc_tag(f'''
      <get-config>
        <source>
          <running/>
        </source>
        <filter type="subtree">
          <configuration xmlns="{NS_ROOT}">
            <access xmlns="{NS_ACCESS}">
              <address-assignment>
                <pool/>
              </address-assignment>
            </access>
            <system xmlns="{NS_SYSTEM}">
              <services>
                <dhcp-local-server>
                  <group/>
                </dhcp-local-server>
              </services> 
            </system>
            <forwarding-options xmlns="{NS_FORWARDING_OPTIONS}">
              <dhcp-relay/>
            </forwarding-options>
          </configuration>
        </filter>
      </get-config>
    ''')


def _dhcp_local_entries(value):
    return [] if value is None else value if isinstance(value, list) else [value]


def _dhcp_local_entry_name(entry):
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return entry.get("name")
    return None


# _element_to_json() แปลง element ที่ไม่มีลูกเลย (เช่น <dhcp-relay/> ที่ยังไม่เคย
# ตั้งอะไรเลย) เป็นสตริงว่าง "" ไม่ใช่ {} - .get() ต่อบน dict ธรรมดาจึงพังถ้าไม่กัน
# ไว้ (AttributeError: 'str' object has no attribute 'get') ใช้ตัวช่วยนี้แทนทุกจุด
def _dhcp_local_dict_get(value, key, default=None):
    return value.get(key, default) if isinstance(value, dict) else default


# (2026-09) backend/api/device_router.py's set_dhcp_local_interfaces branch เรียก
# 3 ฟังก์ชันนี้เพื่ออ่าน running config สดภายใน DeviceLock ก่อน apply เสมอ (ไม่เชื่อ
# baseline จาก browser เป็น authority) - ทำงานบน dict ที่ normalize_generic()
# แปลงมาแล้ว (payload.data ตรงๆ) ไม่ใช่ raw XML - โครงสร้างเดียวกับที่ frontend's
# utils/dhcpLocalServer.js เดินอยู่แล้ว (payload.data.configuration...) เพราะเป็น
# JSON mirror ของ XML tag เดียวกันเป๊ะ
def dhcp_local_server_group_members(normalized_payload, group_name):
    """สมาชิกปัจจุบันจริงของ dhcp-local-server group หนึ่งกลุ่ม (ชื่อ group_name) -
    คืน [] ถ้าไม่มี group นี้อยู่เลย (เช่น greenfield ที่ยังไม่เคยสร้าง)"""
    config = _dhcp_local_dict_get(_dhcp_local_dict_get(normalized_payload, "data", normalized_payload), "configuration", {})
    services = _dhcp_local_dict_get(_dhcp_local_dict_get(config, "system", {}), "services", {})
    groups = _dhcp_local_dict_get(_dhcp_local_dict_get(services, "dhcp-local-server", {}), "group")
    for group in _dhcp_local_entries(groups):
        if not isinstance(group, dict) or group.get("name") != group_name:
            continue
        members = []
        for entry in _dhcp_local_entries(group.get("interface")):
            name = _dhcp_local_entry_name(entry)
            if not name:
                continue
            if isinstance(entry, dict):
                members.append({"name": name, "upto": entry.get("upto") or None, "exclude": "exclude" in entry})
            else:
                members.append({"name": name, "upto": None, "exclude": False})
        return members
    return []


def dhcp_local_server_interface_owners(normalized_payload):
    """{interface_name: group_name} ข้ามทุก dhcp-local-server group บนอุปกรณ์ -
    ใช้ปฏิเสธการเพิ่ม interface ที่เป็นสมาชิกของ group อื่นอยู่แล้วเข้า group ที่
    กำลังแก้ (DHCP_LOCAL_INTERFACE_CONFLICT) - **ยังไม่เคยยืนยันกับอุปกรณ์จริงว่า
    Junos ห้าม interface เดียวอยู่หลาย group จริงหรือไม่** เลือก fail-closed (กันไว้
    ก่อน) เป็นค่าเริ่มต้นที่ปลอดภัยกว่า ดู planning/HANDOFF.md สำหรับรายละเอียด"""
    config = _dhcp_local_dict_get(_dhcp_local_dict_get(normalized_payload, "data", normalized_payload), "configuration", {})
    services = _dhcp_local_dict_get(_dhcp_local_dict_get(config, "system", {}), "services", {})
    groups = _dhcp_local_dict_get(_dhcp_local_dict_get(services, "dhcp-local-server", {}), "group")
    owners = {}
    for group in _dhcp_local_entries(groups):
        if not isinstance(group, dict):
            continue
        group_name = group.get("name")
        for entry in _dhcp_local_entries(group.get("interface")):
            name = _dhcp_local_entry_name(entry)
            if name:
                owners[name] = group_name
    return owners


def dhcp_relay_bound_interfaces(normalized_payload):
    """ทุก interface ที่ผูกกับ forwarding-options/dhcp-relay/group อยู่แล้ว - ใช้
    ปฏิเสธการเพิ่มเข้า dhcp-local-server (mutual exclusion จริงของ Junos ที่ยืนยัน
    แล้วก่อนหน้านี้ - ดู planning/HANDOFF.md "DHCP Local Server" - "Interface X
    already configured")"""
    config = _dhcp_local_dict_get(_dhcp_local_dict_get(normalized_payload, "data", normalized_payload), "configuration", {})
    forwarding = _dhcp_local_dict_get(_dhcp_local_dict_get(config, "forwarding-options", {}), "dhcp-relay", {})
    groups = _dhcp_local_dict_get(forwarding, "group")
    bound = set()
    for group in _dhcp_local_entries(groups):
        if not isinstance(group, dict):
            continue
        for entry in _dhcp_local_entries(group.get("interface")):
            name = _dhcp_local_entry_name(entry)
            if name:
                bound.add(name)
    return bound


@validate_call
# เดิมเขียนที่ forwarding-options/helpers/bootp/server (BOOTP relay แบบดั้งเดิม)
# ซึ่งเป็น global scope ทั้งอุปกรณ์ ไม่ผูกกับ interface ใดโดยเฉพาะเลย (ยืนยันจาก
# junos-es-conf-forwarding-options.yang - "helpers/bootp/server" ไม่มี key เป็น
# interface) - user ชี้ทางที่ถูกต้องมาว่าควรใช้ forwarding-options/dhcp-relay
# (server-group + group + interface) แทน ซึ่ง**ผูกกับ interface จริงได้** ตรงกับ
# Cisco's "ip helper-address" มากกว่า (ยืนยัน schema จาก junos-es-conf-
# forwarding-options.yang: grouping jdhcp-relay-type มี server-group [list ของ
# server IP คีย์ด้วยชื่อ] + group [list ผูก active-server-group + interface list
# คีย์ด้วยชื่อ] - ทั้งคู่เป็น container ที่ห่อ list ชื่อเดียวกับตัวเองอีกชั้น
# ตาม pattern ที่ YANG นี้ใช้ซ้ำๆ ทั่วทั้งไฟล์) ตั้งชื่อ server-group/group จาก
# ชื่อ interface เอง (SG-<if>/RELAY-<if>) ให้แต่ละ interface มี relay setup
# ของตัวเองแยกกัน ไม่ต้องเดาว่าจะแชร์ group กับ interface อื่นไหม - เรียกซ้ำด้วย
# helper_ip ใหม่บน interface เดิมจะ merge เพิ่ม <address> เข้า server-group เดิม
# (รองรับหลาย relay server ต่อ interface เดียวเหมือน Cisco ที่ตั้ง helper-address
# ได้หลายบรรทัด)
@validate_call
def set_dhcp_relay(interface_type: str, interface_id: str, helper_ip: str, unit: int = 0, previous: dict | None = None):
    def binding(kind, identity, logical_unit):
        if not isinstance(logical_unit, int) or isinstance(logical_unit, bool) or logical_unit < 0:
            raise ValueError("unit must be a non-negative integer")
        full = f"{_interface_name(kind, identity)}.{logical_unit}"
        safe = full.replace("/", "-").replace(".", "-")
        return full, f"SG-{safe}", f"RELAY-{safe}"

    full_interface, server_group, group = binding(interface_type, interface_id, unit)
    helper_ip = str(ipaddress.IPv4Address(helper_ip))
    server_nodes = {}
    old_group_xml = ""
    if previous is not None:
        old_full, old_server, old_group = binding(
            previous.get("interface_type", ""), previous.get("interface_id", ""), previous.get("unit", 0)
        )
        old_ip = previous.get("helper_ip", "")
        if old_ip:
            old_ip = str(ipaddress.IPv4Address(old_ip))
            if (old_server, old_ip) != (server_group, helper_ip):
                server_nodes.setdefault(old_server, []).append(
                    f'<address xmlns:nc="{NS_RPC}" nc:operation="remove"><name>{old_ip}</name></address>'
                )
        if old_full != full_interface:
            # Unbind only the old interface; do not delete referenced parent groups.
            old_group_xml = (
                f'<group><name>{escape(old_group)}</name>'
                f'<interface xmlns:nc="{NS_RPC}" nc:operation="remove"><name>{old_full}</name></interface></group>'
            )
    server_nodes.setdefault(server_group, []).append(f"<address><name>{helper_ip}</name></address>")
    servers = "".join(
        f"<server-group><name>{escape(name)}</name>{''.join(changes)}</server-group>"
        for name, changes in server_nodes.items()
    )
    return _edit_configuration(f'''
<forwarding-options xmlns="{NS_FORWARDING_OPTIONS}">
  <dhcp-relay>
    <server-group>{servers}</server-group>
    {old_group_xml}
    <group>
      <name>{escape(group)}</name>
      <active-server-group>
        <active-server-group>{escape(server_group)}</active-server-group>
      </active-server-group>
      <interface><name>{full_interface}</name></interface>
    </group>
  </dhcp-relay>
</forwarding-options>
    ''')


# ลบ relay server ตัวเดียวออกจาก server-group ของ interface นั้น (ไม่ลบทั้ง
# group/server-group ทิ้ง - เผื่อ interface เดียวกันยังมี relay server ตัวอื่น
# ผูกอยู่ใน server-group เดียวกัน) ชื่อ group/server-group ต้อง derive แบบเดียว
# กับ set_dhcp_relay เป๊ะ (ไม่งั้นหาตัวที่จะลบไม่เจอ)
@validate_call
def remove_dhcp_relay(interface_type: str, interface_id: str, helper_ip: str, unit: int = 0):
    interface = _interface_name(interface_type, interface_id)
    ipaddress.IPv4Address(helper_ip)
    full_interface = f"{interface}.{unit}"
    safe_id = full_interface.replace("/", "-").replace(".", "-")
    server_group = f"SG-{safe_id}"
    return _edit_configuration(f'''
<forwarding-options xmlns="{NS_FORWARDING_OPTIONS}">
  <dhcp-relay>
    <server-group>
      <server-group>
        <name>{escape(server_group)}</name>
        <address xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{helper_ip}</name>
        </address>
      </server-group>
    </server-group>
  </dhcp-relay>
</forwarding-options>
    ''')


# ลบทั้ง group + server-group ของ interface นั้นทิ้งทั้งก้อน (ไม่ใช่แค่ address
# เดียวแบบ remove_dhcp_relay ด้านบน) - เจอจริงว่า remove_dhcp_relay ใช้ไม่ได้เลย
# กับ relay ที่ server-group ไม่มี address เหลืออยู่แล้ว (ว่างเปล่า - เคยเกิดจาก
# ลบ address ตัวสุดท้ายออกไปแล้วไม่ได้ลบ group/server-group ตามไปด้วย ค้างเป็น
# "orphan" ที่ interface ยังผูกกับ dhcp-relay อยู่จริง (มีผลกับ mutual exclusion
# ของ dhcp-local-server เต็มๆ) แต่ remove_dhcp_relay ต้องการ helper_ip มา match
# ซึ่งไม่มีอะไรให้ match แล้ว - ก่อนหน้านี้ต้องลบด้วยมือผ่าน CLI ตรงๆ ทุกครั้ง)
# ฟังก์ชันนี้ลบด้วย "interface" อย่างเดียว ไม่ต้องมี helper_ip เลย ใช้ได้ทั้งกรณี
# ปกติ (มี address อยู่) และกรณี orphan (ไม่มี address เหลือ) เหมือนกัน - ชื่อ
# group/server-group derive แบบเดียวกับ set_dhcp_relay เป๊ะ
@validate_call
def remove_dhcp_relay_member(interface_type: str, interface_id: str, group: str, unit: int = 0):
    """Detach one interface without deleting shared relay groups/server addresses."""
    interface = _interface_name(interface_type, interface_id)
    if not group.strip() or not 1 <= len(group) <= 64:
        raise ValueError("group name must contain 1-64 characters")
    return _edit_configuration(f'''
<forwarding-options xmlns="{NS_FORWARDING_OPTIONS}">
  <dhcp-relay><group><name>{escape(group)}</name>
    <interface xmlns:nc="{NS_RPC}" nc:operation="remove"><name>{interface}.{unit}</name></interface>
  </group></dhcp-relay>
</forwarding-options>
    ''')


@validate_call
def remove_dhcp_relay_interface(interface_type: str, interface_id: str, unit: int = 0):
    interface = _interface_name(interface_type, interface_id)
    full_interface = f"{interface}.{unit}"
    safe_id = full_interface.replace("/", "-").replace(".", "-")
    server_group = f"SG-{safe_id}"
    group = f"RELAY-{safe_id}"
    return _edit_configuration(f'''
<forwarding-options xmlns="{NS_FORWARDING_OPTIONS}">
  <dhcp-relay>
    <server-group>
      <server-group xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(server_group)}</name>
      </server-group>
    </server-group>
    <group xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(group)}</name>
    </group>
  </dhcp-relay>
</forwarding-options>
    ''')


# ทั้ง "เปิดใช้ครั้งแรก" และ "แก้ไขของเดิม" ได้ RPC เดียวเสมอ: ทุก subtree ที่ RIP
# ใช้ (protocols/rip กับ policy-statement อีกสองตัว) เขียนด้วย nc:operation="replace"
# ในก้อนเดียวกัน ของเดิมที่ไม่ได้ส่งมาด้วยจึงหายไปเองโดยไม่ต้องยิง
# remove_rip_routing นำหน้า - แพทเทิร์นเดียวกับ set_ospf_network ในไฟล์นี้
#
# redistribute static รวมเข้ามาใน RPC เดียวกันแล้ว (เดิมเป็นคำสั่งที่ 3 แยก
# ต่างหาก) - เป็นแค่สมาชิกตัวหนึ่งของ protocol list ใน term 1 ของ RIP-POLICY
# อยู่แล้ว การ replace ทั้ง policy-statement จึงเปิด/ปิดได้ครบโดยไม่ต้องมีคำสั่ง
# "ปิด" แยก
@validate_call
def set_rip_routing(
    networks: list[str],
    version: Literal[1, 2] = 2,
    auto_summary: bool = False,
    default_information_originate: bool = False,
    redistribute_static: bool = False,
) -> str:
    if auto_summary:
        raise ValueError("Junos RIP does not support Cisco auto-summary semantics")
    if not networks:
        raise ValueError("At least one RIP interface is required")

    # เดิมใส่ <send>/<receive> ไว้ที่ระดับ group ตรงๆ - ยืนยันจริงกับอุปกรณ์ผ่าน
    # CLI `set protocols rip group default ?` ว่า **group ไม่มี send/receive
    # leaf เลย** (โดน "syntax error" ตรงๆ ตอน commit) ต้องอยู่ระดับ**neighbor**
    # ต่างหาก (`neighbor <interface> send/receive`) ยืนยัน schema จาก
    # junos-es-conf-protocols.yang (list group -> list neighbor -> container
    # send/receive แต่ละตัวเป็น choice ของ empty-leaf) - ต้องใส่ send/receive
    # ซ้ำในทุก <neighbor> entry ไม่ใช่ตั้งครั้งเดียวที่ group แล้วใช้ร่วมกัน
    receive_mode = "version-1" if version == 1 else "version-2"
    send_mode = "version-1" if version == 1 else "multicast"
    neighbors_xml = "\n".join(
        f'''<neighbor>
      <name>{escape(interface)}</name>
      <send><{send_mode}/></send>
      <receive><{receive_mode}/></receive>
    </neighbor>'''
        for interface in networks
    )

    # เจอบั๊กจริง (2026-07-29): set_rip_routing เดิมไม่เคยผูก export policy ให้
    # group เลยตั้งแต่แรก (ไม่มี <export> อะไรทั้งสิ้น) - RIP เลยรับ route จาก
    # neighbor ได้ปกติ (ผูก neighbor ครบ) แต่ไม่เคยประกาศ subnet ของตัวเองออกไป
    # เลยสักเส้น เพราะ Junos routing protocol ทุกตัว default deny-all export (ไม่มี
    # export policy = ไม่ export อะไรเลย) - ทำให้แลก routing กับอุปกรณ์อื่นได้แค่
    # ทางเดียว (รับได้ ให้ไม่ได้) ตรงกับที่ user รายงาน "ไม่ยอมบอก routing ของตัวเอง"
    # แก้โดยสร้าง export policy "RIP-POLICY" (baseline, ไม่ใช่ toggle แยก -
    # ผูกทุกครั้งที่ set_rip_routing ถูกเรียก) term 1: from protocol direct ->
    # accept (ประกาศ subnet ที่ interface ผูก RIP อยู่จริงออกไปเสมอ) -
    # set_rip_redistribute_static ด้านล่าง merge/remove "static" เข้า/ออกจาก
    # protocol list ของ term เดียวกันนี้ต่อ (from protocol [direct static] ตามที่
    # user ระบุ ไม่ใช่ policy แยกอีกตัวแบบเดิม)
    redistribute_static_xml = "<protocol>static</protocol>" if redistribute_static else ""
    export_subnets_xml = f'''
  <policy-statement xmlns:nc="{NS_RPC}" nc:operation="replace">
    <name>RIP-POLICY</name>
    <term>
      <name>1</name>
      <from>
        <protocol>direct</protocol>
        <protocol>rip</protocol>
        {redistribute_static_xml}
      </from>
      <then>
        <accept/>
      </then>
    </term>
  </policy-statement>'''

    # default_information_originate: เดิม raise ValueError ตายตัวเสมอ (ยังไม่
    # implement) - user ขอให้ทำจริง ใช้ pattern เดียวกับ set_ospf_default_originate
    # ที่มีอยู่แล้ว (policy-statement แยกต่างหาก matching route-filter 0.0.0.0/0
    # exact) แต่ตั้งชื่อ "EXPORT-DEFAULT-RIP" แยกจาก OSPF's "EXPORT-DEFAULT" กันชน
    # กันถ้าเปิดทั้งคู่พร้อมกัน - ผูกเป็น <export> เส้นที่ 2 ของ group (Junos
    # export เป็น leaf-list รับได้หลาย policy-statement จริง ประเมินตามลำดับจนกว่า
    # จะเจอ term ที่ accept - เหมือน policy chain)
    #
    # ปิด default-information ต้อง "ลบ policy ทิ้ง" ไม่ใช่แค่ไม่ส่งมา เพราะมันเป็น
    # policy-statement คนละตัวกับ RIP-POLICY การ replace RIP-POLICY ไม่แตะมันเลย -
    # ใช้ remove ซึ่งเป็น no-op ถ้าไม่เคยมีอยู่ (ต่างจาก delete ที่ error) จึงส่งไป
    # ได้เสมอโดยไม่ต้องอ่าน config มาเช็คก่อน
    default_route_export_xml = ""
    if default_information_originate:
        default_route_xml = '''
  <policy-statement xmlns:nc="{NS_RPC}" nc:operation="replace">
    <name>EXPORT-DEFAULT-RIP</name>
    <term>
      <name>1</name>
      <from>
        <route-filter>
          <address>0.0.0.0/0</address>
          <choice-ident>exact</choice-ident>
          <choice-value></choice-value>
        </route-filter>
      </from>
      <then>
        <accept/>
      </then>
    </term>
  </policy-statement>'''.format(NS_RPC=NS_RPC)
        default_route_export_xml = "<export>EXPORT-DEFAULT-RIP</export>"
    else:
        default_route_xml = f'''
  <policy-statement xmlns:nc="{NS_RPC}" nc:operation="remove">
    <name>EXPORT-DEFAULT-RIP</name>
  </policy-statement>'''

    # policy-statement ทั้งสองตัวต้องอยู่ใน <policy-options> ก้อนเดียวกัน - container
    # เดียวกันห้ามโผล่สองครั้งใน edit-config เดียว (เดิมแยกเป็นสองก้อนซ้อนกัน)
    return _edit_configuration(f'''
<policy-options xmlns="{NS_POLICY_OPTIONS}">
{export_subnets_xml}
{default_route_xml}
</policy-options>
<protocols xmlns="{NS_PROTOCOLS}">
  <rip xmlns:nc="{NS_RPC}" nc:operation="replace">
    <group>
      <name>default</name>
      <export>RIP-POLICY</export>
      {default_route_export_xml}
      {neighbors_xml}
    </group>
  </rip>
</protocols>
    ''')


# อ่าน RIP config กลับมา - path ตรงกับที่ set_rip_routing เขียน (protocols/rip)
# เพิ่ม policy-options/policy-statement เข้าไปในนี้ด้วย (2026-07-29 - เดิมขอแค่
# protocols/rip อย่างเดียว) เพราะ redistributeStatic/defaultInformationOriginate
# ตอนนี้ต้องอ่านเนื้อหาจริงของ RIP-POLICY's term 1 protocol list (ไม่ใช่แค่
# เช็คว่ามีชื่อ policy อยู่ใน <export> ของ group เฉยๆ แบบเดิม - ดู comment ยาวใน
# set_rip_routing/set_rip_redistribute_static อธิบายว่าทำไมเปลี่ยน) ให้ rip_route.jsx
# ฝั่ง frontend ตรวจสอบได้ตรงๆ ไม่ต้อง query แยกรอบ
def get_rip_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <protocols xmlns="{NS_PROTOCOLS}">
        <rip/>
      </protocols>
      <policy-options xmlns="{NS_POLICY_OPTIONS}">
        <policy-statement/>
      </policy-options>
    </configuration>
  </filter>
</get-config>
    ''')


# ลบ RIP process ทั้งก้อน (เทียบเท่า Cisco's remove_rip_routing) - ลบ
# protocols/rip ตรงๆ (รวม group "default" กับ neighbor ทุกตัวข้างในไปด้วย) พ่วง
# ลบ policy-statement "RIP-POLICY"/"EXPORT-DEFAULT-RIP" (คนละ container กัน
# ไม่ได้ซ้อนอยู่ใต้ protocols/rip เลย) ไปด้วยเสมอ กันเป็น orphan ค้าง - ยืนยันจริง
# กับอุปกรณ์แล้วว่า Junos ไม่ error ถ้า policy-statement ไหนไม่มีอยู่จริง (เช่นไม่
# เคยเปิด default-information-originate เลย) แค่เป็น no-op เฉยๆ ปลอดภัยที่จะลบ
# เสมอไม่ต้องเช็คก่อน (ชื่อเปลี่ยนจาก "EXPORT-STATIC" เดิมเป็น "RIP-POLICY"
# 2026-07-29 - ดู comment ยาวใน set_rip_routing อธิบายว่าทำไม)
@validate_call
def remove_rip_routing():
    return _edit_configuration(f'''
<protocols xmlns="{NS_PROTOCOLS}">
  <rip xmlns:nc="{NS_RPC}" nc:operation="remove">
  </rip>
</protocols>
<policy-options xmlns="{NS_POLICY_OPTIONS}">
  <policy-statement xmlns:nc="{NS_RPC}" nc:operation="remove">
    <name>RIP-POLICY</name>
  </policy-statement>
  <policy-statement xmlns:nc="{NS_RPC}" nc:operation="remove">
    <name>EXPORT-DEFAULT-RIP</name>
  </policy-statement>
</policy-options>
    ''')


@validate_call
def set_rip_redistribute_static(enabled: bool = True) -> str:
    # เจอบั๊กจริง (2026-07-29): เดิมสร้าง policy-statement "EXPORT-STATIC" แยก
    # เป็นของตัวเองต่างหาก (from protocol static -> accept) แล้วผูกเป็น <export>
    # เส้นที่ 2 คู่กับของ set_rip_routing - user ระบุตรงๆ ว่าต้องการรวมเข้า term
    # เดียวกับ RIP-POLICY แทน (from protocol [ direct static ] ไม่ใช่แยก
    # policy) - เปลี่ยนมา merge/remove leaf-list "protocol" ของ RIP-POLICY's
    # term 1 โดยตรง (protocol เป็น leaf-list รับได้หลายค่า - merge แบบ NETCONF
    # default operation เป็น additive อยู่แล้ว ไม่ต้องรู้ค่าที่มีอยู่ก่อนก็เพิ่มได้
    # ปลอดภัย ส่วน disable ใช้ nc:operation="remove" ถอดแค่ค่า "static" ออกจาก list
    # โดยไม่กระทบ "direct" ที่ต้องอยู่ตลอด) - ไม่ต้องแตะ <export> ที่ group เลย
    # เพราะ RIP-POLICY ผูกอยู่แล้วตั้งแต่ set_rip_routing (ไม่ใช่ toggle แยก
    # อีกต่อไป)
    if not enabled:
        return _edit_configuration(f'''
<policy-options xmlns="{NS_POLICY_OPTIONS}">
  <policy-statement>
    <name>RIP-POLICY</name>
    <term>
      <name>1</name>
      <from>
        <protocol xmlns:nc="{NS_RPC}" nc:operation="remove">static</protocol>
      </from>
    </term>
  </policy-statement>
</policy-options>
        ''')
    return _edit_configuration(f'''
<policy-options xmlns="{NS_POLICY_OPTIONS}">
  <policy-statement>
    <name>RIP-POLICY</name>
    <term>
      <name>1</name>
      <from>
        <protocol>static</protocol>
      </from>
    </term>
  </policy-statement>
</policy-options>
    ''')


# อ่าน OSPF config กลับมา - protocols/ospf ตรงกับที่ set_ospf_network เขียน และ
# routing-options/router-id เป็นค่าระดับอุปกรณ์ที่ replace_ospf_area เขียนแยกมา
# คู่กัน (bug 86) ต้องขอใน RPC เดียวกันเพื่อให้ฟอร์มแสดงค่าจริง ไม่เพิ่ม query ที่ 4
def get_ospf_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <protocols xmlns="{NS_PROTOCOLS}">
        <ospf/>
      </protocols>
      <routing-options xmlns="{NS_ROUTING_OPTIONS}">
        <router-id/>
      </routing-options>
    </configuration>
  </filter>
</get-config>
    ''')


@validate_call
def set_ospf_redistribute_static(process_id: int, enabled: bool = True) -> str:
    # Junos OSPF ไม่มี "process-id" แบบ Cisco (instance เดียวต่อ routing-instance
    # โดย default) รับ process_id ไว้เฉยๆ ให้ signature ตรงกับ Cisco เท่านั้น
    # ไม่ได้ใช้จริง - ใช้ export policy เดียวกับ RIP ข้างบน (reuse EXPORT-STATIC
    # เดียวกันได้เลยถ้าทั้งคู่ต้องการ - แต่แยก policy-statement ชื่อของตัวเองไว้
    # กันชนกับ RIP export ถ้าเปิดพร้อมกันทั้งคู่)
    if not enabled:
        return _edit_configuration(f'''
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf>
    <export xmlns:nc="{NS_RPC}" nc:operation="remove">EXPORT-STATIC-OSPF</export>
  </ospf>
</protocols>
        ''')
    return _edit_configuration(f'''
<policy-options xmlns="{NS_POLICY_OPTIONS}">
  <policy-statement>
    <name>EXPORT-STATIC-OSPF</name>
    <term>
      <name>1</name>
      <from>
        <protocol>static</protocol>
      </from>
      <then>
        <accept/>
      </then>
    </term>
  </policy-statement>
</policy-options>
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf>
    <export>EXPORT-STATIC-OSPF</export>
  </ospf>
</protocols>
    ''')


# เดิมไม่มีฟังก์ชันนี้เลยสำหรับ Juniper (frontend เรียก set_ospf_redistribute_rip
# ตรงๆ อยู่แล้วจาก OspfRouteFormModal.jsx แต่ไม่มีให้เรียกจริง - จะโดน "Feature
# is not supported by this translator" ทันที) - รูปแบบเดียวกับ
# set_ospf_redistribute_static ข้างบนเป๊ะ แค่เปลี่ยน protocol เป็น "rip" และตั้ง
# ชื่อ policy-statement แยกกัน (EXPORT-RIP-OSPF) ไม่ให้ชนกับ EXPORT-STATIC-OSPF
# ถ้าเปิดพร้อมกันทั้งคู่
@validate_call
def set_ospf_redistribute_rip(process_id: int, enabled: bool = True) -> str:
    if not enabled:
        return _edit_configuration(f'''
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf>
    <export xmlns:nc="{NS_RPC}" nc:operation="remove">EXPORT-RIP-OSPF</export>
  </ospf>
</protocols>
        ''')
    return _edit_configuration(f'''
<policy-options xmlns="{NS_POLICY_OPTIONS}">
  <policy-statement>
    <name>EXPORT-RIP-OSPF</name>
    <term>
      <name>1</name>
      <from>
        <protocol>rip</protocol>
      </from>
      <then>
        <accept/>
      </then>
    </term>
  </policy-statement>
</policy-options>
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf>
    <export>EXPORT-RIP-OSPF</export>
  </ospf>
</protocols>
    ''')

# Junos ปฏิเสธ router-id ที่ตกอยู่ในช่วง martian ของตัวเอง โดยตรวจตอน **commit**
# ไม่ใช่ตอนโหลดเข้า candidate - อุปกรณ์ตอบว่า "address 0.0.0.3 invalid for
# router-id (martian address)" แล้ว commit ทั้งก้อนล้ม ทำให้ OSPF ที่อยู่ใน
# edit-config เดียวกันถูก discard ไปด้วยทั้งหมด (ยืนยันจากผู้ใช้ทดสอบจริง:
# 0.0.0.3 ไม่ผ่าน แต่ 1.0.0.3 ผ่าน - และ CLI ดูเหมือนรับ 0.0.0.3 เพราะ `set`
# ไม่ได้ตรวจ ด่านนี้ทำงานตอน commit เท่านั้น)
#
# กันไว้ตั้งแต่ต้นทางแทนที่จะปล่อยให้เสียการกด Apply ทั้งรอบไปเพราะช่องเดียว -
# รายการนี้คือ martian ที่ Junos ตั้งมาให้เองตั้งแต่ต้น (ผู้ใช้เพิ่ม/ยกเว้นเองได้
# ผ่าน `routing-options martians` ซึ่งระบบนี้ไม่แตะ) **ยืนยันกับอุปกรณ์จริงแล้ว
# เฉพาะ 0.0.0.0/8** ตัวอื่นอ้างจากค่าเริ่มต้นที่ Junos ประกาศไว้ ถ้าเจอว่าตัวไหน
# อุปกรณ์รับจริงให้ตัดออกจากลิสต์นี้
JUNOS_DEFAULT_MARTIANS = (
    "0.0.0.0/8",
    "127.0.0.0/8",
    "128.0.0.0/16",
    "191.255.0.0/16",
    "192.0.0.0/24",
    "223.255.255.0/24",
    "240.0.0.0/4",
)


def _validate_router_id(router_id: str) -> str:
    address = ipaddress.IPv4Address(router_id)
    for martian in JUNOS_DEFAULT_MARTIANS:
        if address in ipaddress.IPv4Network(martian):
            raise ValueError(
                f"Juniper does not accept {address} as Router ID because the device considers it a martian address "
                "- please use another value"
            )
    return str(address)


def _validate_junos_ospf_area_key(area: StrictInt | str) -> str:
    """Validate an Area key read from Junos without changing its representation.

    User-facing OSPF forms intentionally accept decimal uint32 only, but Junos
    returns the list key in dotted form (for example ``0.0.0.0``). A minimal
    delete must address that existing parent list entry by its actual key; it
    does not create, replace, or rename the Area.
    """
    if isinstance(area, bool):
        raise ValueError(f"area must be a valid OSPF Area ID (received: {area!r})")
    if isinstance(area, int):
        return str(validate_ospf_area(area))
    text = str(area).strip()
    if text.isdigit():
        return str(validate_ospf_area(text))
    try:
        address = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError:
        raise ValueError(f"area must be a valid OSPF Area ID (received: {area!r})")
    # Preserve the Junos list key exactly in its canonical dotted representation.
    return str(address)


@validate_call
def set_ospf_network(
    area: StrictInt | str,
    interface_type: str,
    interface_id: str,
    router_id: str | None = None,
):
    interface = _interface_name(interface_type, interface_id)
    router_id_xml = ""
    if router_id:
        router_id_xml = f'''
<routing-options xmlns="{NS_ROUTING_OPTIONS}">
  <router-id>{_validate_router_id(router_id)}</router-id>
</routing-options>'''
    return _edit_configuration(f'''
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf>
    <area>
      <name>{validate_ospf_area(area)}</name>
      <interface>
        <name>{interface}</name>
      </interface>
    </area>
  </ospf>
</protocols>
{router_id_xml}
    ''')


# (ระลอก C2 ใน planning/transaction_review.md) ตั้งค่า OSPF ทั้งก้อนใน RPC เดียว
#
# เดิม flow "แก้ไข OSPF" ยิงได้ถึง 12 RPC: remove_ospf_routing 1 ครั้ง แล้ววน
# set_ospf_network + set_ospf_passive_interface ทีละ interface - จำนวนคำสั่งแปรผันตาม
# จำนวน interface ที่เลือก และเพราะ Junos commit ทุก edit-config จึงกลายเป็น 12 commit
# ด้วย (ช้ามาก และมีช่วงที่ routing หายไปกลางทางจริง)
#
# Junos วาง OSPF ทั้งหมดไว้ใต้ <protocols><ospf> จึงยุบเป็น nc:operation="replace" ที่
# ระดับ <ospf> ก้อนเดียวได้ - แทนที่เนื้อหาทั้งหมดใต้ ospf ด้วยสิ่งที่ส่งไป ตรงกับที่
# flow ต้องการพอดี และได้ atomicity จริงจาก candidate + commit ครั้งเดียว
#
# router-id อยู่คนละ subtree (routing-options ไม่ใช่ protocols) จึงส่งไปคู่กันใน
# edit-config เดียวกันแต่ไม่ได้อยู่ใต้ replace - ตั้งใจ เพราะ router-id เป็นค่าระดับ
# อุปกรณ์ที่ protocol อื่นใช้ร่วมด้วย ไม่ควรถูกล้างไปพร้อม OSPF
#
# เดิมไม่รับ default_originate/redistribute_* เลย ทั้งที่ฟอร์มมี toggle ทั้ง 3 ตัว
# ให้ Juniper - กดเปิดแล้ว Apply ไม่มีผลอะไร และแย่กว่านั้นคือ replace ที่ระดับ <ospf>
# ลบ <export> ที่ตั้งไว้เดิมทิ้งเงียบ ๆ ทุกครั้งที่ Apply (แม้แค่เปลี่ยน area) - ตอนนี้
# เขียน <export> ไว้ใน replace ก้อนเดียวกันเลย ส่วน policy-statement อยู่คนละ
# subtree (policy-options) จึงสร้าง (merge) ตัวที่เปิด และลบตัวที่ปิดใน edit-config
# เดียวกัน กันเป็น orphan เหมือน remove_ospf_routing - ทั้ง 3 ชื่อใช้กับ OSPF เท่านั้น
# (RIP ใช้ EXPORT-DEFAULT-RIP/EXPORT-STATIC แยกอยู่แล้ว) ลบได้โดยไม่กระทบ protocol อื่น
_OSPF_EXPORT_POLICY_TERMS = {
    "EXPORT-DEFAULT": '''
      <from>
        <route-filter>
          <address>0.0.0.0/0</address>
          <choice-ident>exact</choice-ident>
          <choice-value></choice-value>
        </route-filter>
      </from>''',
    "EXPORT-STATIC-OSPF": "<from><protocol>static</protocol></from>",
    "EXPORT-RIP-OSPF": "<from><protocol>rip</protocol></from>",
}

@validate_call
def replace_ospf_area(
    area: StrictInt | str,
    interfaces: list[str],
    passive_interfaces: list[str] | None = None,
    router_id: str | None = None,
    default_originate: bool = False,
    redistribute_static: bool = False,
    redistribute_rip: bool = False,
) -> str:
    if not interfaces:
        raise ValueError("At least 1 interface must be specified")

    enabled_exports = {
        "EXPORT-DEFAULT": default_originate,
        "EXPORT-STATIC-OSPF": redistribute_static,
        "EXPORT-RIP-OSPF": redistribute_rip,
    }
    export_xml = ""
    policy_xml = ""
    for name, enabled in enabled_exports.items():
        if enabled:
            export_xml += f"<export>{name}</export>"
            policy_xml += f'''
  <policy-statement>
    <name>{name}</name>
    <term>
      <name>1</name>
      {_OSPF_EXPORT_POLICY_TERMS[name]}
      <then>
        <accept/>
      </then>
    </term>
  </policy-statement>'''
        else:
            policy_xml += f'''
  <policy-statement xmlns:nc="{NS_RPC}" nc:operation="remove">
    <name>{name}</name>
  </policy-statement>'''

    passive = set(passive_interfaces or [])
    interface_xml = ""
    for name in interfaces:
        if not name:
            continue
        passive_tag = "<passive/>" if name in passive else ""
        interface_xml += f"<interface><name>{escape(name)}</name>{passive_tag}</interface>"

    router_id_xml = ""
    if router_id:
        router_id_xml = f'''
<routing-options xmlns="{NS_ROUTING_OPTIONS}">
  <router-id>{_validate_router_id(router_id)}</router-id>
</routing-options>'''

    return _edit_configuration(f'''
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf xmlns:nc="{NS_RPC}" nc:operation="replace">
    {export_xml}
    <area>
      <name>{validate_ospf_area(area)}</name>
      {interface_xml}
    </area>
  </ospf>
</protocols>
<policy-options xmlns="{NS_POLICY_OPTIONS}">{policy_xml}
</policy-options>
{router_id_xml}
    ''')

@validate_call
def set_ospf_passive_interface(
    area: StrictInt | str,
    interface_type: str,
    interface_id: str,
):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf>
    <area>
      <name>{validate_ospf_area(area)}</name>
      <interface>
        <name>{interface}</name>
        <passive/>
      </interface>
    </area>
  </ospf>
</protocols>
    ''')

@validate_call
def remove_ospf_interface(area: StrictInt | str, interface_type: str, interface_id: str):
    # ใช้ตอน interface เดิมที่เคยผูกเข้า OSPF area ถูกลบ/แทนที่ (เช่นตอนแปลง flat
    # unit เป็น vlan-tagging sub-interface) — ถ้าไม่ลบ entry เก่าออก OSPF จะยังชี้ไปที่
    # unit ที่ไม่มีอยู่จริงแล้ว ทำให้ subnet ที่ควรถูก advertise หายไปเงียบๆ โดยไม่มี error
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf>
    <area>
      <name>{_validate_junos_ospf_area_key(area)}</name>
      <interface xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{interface}</name>
      </interface>
    </area>
  </ospf>
</protocols>
    ''')


# ลบ OSPF process ทั้งก้อน - Cisco ใช้ remove_ospf_process (มี process-id เป็น
# key) แต่ Junos OSPF ไม่มี process-id concept เลย (instance เดียวต่อ
# routing-instance) เลยไม่มีฟังก์ชันเทียบเท่ากันมาก่อน - หน้า ospf_route.jsx เดิม
# เรียก remove_ospf_process แบบไม่แยก vendor เลย (ปุ่ม Delete โผล่ให้ Juniper กด
# ได้ด้วย) กดแล้วโดน "Feature is not supported by this translator" ทันทีเพราะ
# ไม่มีฟังก์ชันชื่อนี้ในไฟล์นี้เลย - เพิ่มฟังก์ชันนี้ให้ Juniper โดยเฉพาะ (ลบ
# protocols/ospf ทั้งก้อน + policy-statement ที่ set_ospf_redistribute_static/
# set_ospf_default_originate อาจสร้างไว้ - EXPORT-STATIC-OSPF/EXPORT-DEFAULT -
# กันเป็น orphan เหมือนที่แก้ไปแล้วกับ RIP's EXPORT-STATIC)
@validate_call
def remove_ospf_routing():
    return _edit_configuration(f'''
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf xmlns:nc="{NS_RPC}" nc:operation="remove">
  </ospf>
</protocols>
<policy-options xmlns="{NS_POLICY_OPTIONS}">
  <policy-statement xmlns:nc="{NS_RPC}" nc:operation="remove">
    <name>EXPORT-STATIC-OSPF</name>
  </policy-statement>
  <policy-statement xmlns:nc="{NS_RPC}" nc:operation="remove">
    <name>EXPORT-RIP-OSPF</name>
  </policy-statement>
  <policy-statement xmlns:nc="{NS_RPC}" nc:operation="remove">
    <name>EXPORT-DEFAULT</name>
  </policy-statement>
</policy-options>
    ''')

@validate_call
def set_ospf_default_originate():
    # หมายเหตุ: Junos ไม่มี leaf เดียวแบบ Cisco "default-information originate"
    # ต้องสร้าง routing-policy แยกแล้ว export เข้า ospf — โครงสร้าง route-filter/then
    # นี้อ้างอิงจาก junos-es-conf-policy-options.yang (control_route_filter_type)
    # แต่ยังไม่เคยทดสอบกับอุปกรณ์จริง ต้อง verify/แก้ตาม rpc-error ถ้าเจอ
    return _edit_configuration(f'''
<policy-options xmlns="{NS_POLICY_OPTIONS}">
  <policy-statement>
    <name>EXPORT-DEFAULT</name>
    <term>
      <name>1</name>
      <from>
        <route-filter>
          <address>0.0.0.0/0</address>
          <choice-ident>exact</choice-ident>
          <choice-value></choice-value>
        </route-filter>
      </from>
      <then>
        <accept/>
      </then>
    </term>
  </policy-statement>
</policy-options>
<protocols xmlns="{NS_PROTOCOLS}">
  <ospf>
    <export>EXPORT-DEFAULT</export>
  </ospf>
</protocols>
    ''')


def _build_juniper_term_xml(
    term_name: str,
    action: Literal["permit", "deny"],
    protocol: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    log: bool = False,
    operation: str | None = None,
) -> str:
    from vendor_translators.juniper_acl import build_juniper_term_xml
    return build_juniper_term_xml(
        term_name=term_name,
        action=action,
        protocol=protocol,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        log=log,
        operation=operation,
    )


@validate_call
def set_acl_rule(
    name: str,
    term_name: str,
    action: Literal["permit", "deny"],
    protocol: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    log: bool = False,
):
    term_xml = _build_juniper_term_xml(
        term_name, action, protocol, source, destination, source_port, destination_port, log
    )
    return _edit_configuration(f'''
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter>
        <name>{escape(name)}</name>
        {term_xml}
      </filter>
    </inet>
  </family>
</firewall>
    ''')


@validate_call
def create_acl_rule(
    name: str,
    term_name: str,
    action: Literal["permit", "deny"],
    protocol: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    log: bool = False,
):
    term_xml = _build_juniper_term_xml(
        term_name, action, protocol, source, destination, source_port, destination_port, log, operation="create"
    )
    return _edit_configuration(f'''
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter>
        <name>{escape(name)}</name>
        {term_xml}
      </filter>
    </inet>
  </family>
</firewall>
    ''')


@validate_call
def replace_acl_rule(
    name: str,
    term_name: str,
    action: Literal["permit", "deny"],
    protocol: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    log: bool = False,
    original_name: str | None = None,
    original_term_name: str | None = None,
):
    if original_name is None:
        original_name = name
    if original_term_name is None:
        original_term_name = term_name

    identity_unchanged = (original_name == name and original_term_name == term_name)

    if identity_unchanged:
        term_xml = _build_juniper_term_xml(
            term_name, action, protocol, source, destination, source_port, destination_port, log, operation="replace"
        )
        return _edit_configuration(f'''
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter>
        <name>{escape(name)}</name>
        {term_xml}
      </filter>
    </inet>
  </family>
</firewall>
        ''')
    else:
        delete_term_xml = f'''
        <term xmlns:nc="{NS_RPC}" nc:operation="delete">
          <name>{escape(original_term_name)}</name>
        </term>'''

        create_term_xml = _build_juniper_term_xml(
            term_name, action, protocol, source, destination, source_port, destination_port, log, operation="create"
        )

        if original_name == name:
            return _edit_configuration(f'''
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter>
        <name>{escape(name)}</name>
        {delete_term_xml}
        {create_term_xml}
      </filter>
    </inet>
  </family>
</firewall>
            ''')
        else:
            return _edit_configuration(f'''
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter>
        <name>{escape(original_name)}</name>
        {delete_term_xml}
      </filter>
      <filter>
        <name>{escape(name)}</name>
        {create_term_xml}
      </filter>
    </inet>
  </family>
</firewall>
            ''')


# ลบ term เดียวออกจาก filter - key ของ filter/term ทั้งคู่คือ "name" (list ปกติ
# ของ Junos) - เทียบเท่า Cisco's remove_acl_rule(name, sequence) แค่ key ของ
# Junos เป็นชื่อ term ไม่ใช่เลข sequence - verify แล้วผ่าน UI จริง (Create->Edit->
# Delete cycle) 2026-07-28
@validate_call
def remove_acl_rule(name: str, term_name: str):
    return _edit_configuration(f'''
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter>
        <name>{escape(name)}</name>
        <term xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(term_name)}</name>
        </term>
      </filter>
    </inet>
  </family>
</firewall>
    ''')


@validate_call
def create_acl(
    name: str,
    rules: list[dict] = ...,
    mode: str | None = None,
    reference_config: str | None = None,
) -> str:
    name = validate_object_ref(name, "ACL name")
    from vendor_translators.juniper_acl import validate_juniper_acl_request, build_juniper_term_xml
    validated = validate_juniper_acl_request(
        name=name,
        rules=rules,
        mode=mode,
        is_edit=False,
        live_config=reference_config,
    )

    terms_xml_parts = []
    for r in validated["rules"]:
        terms_xml_parts.append(build_juniper_term_xml(
            term_name=r["term_name"],
            action=r["action"],
            protocol=r["protocol"],
            source=r["source"],
            destination=r["destination"],
            source_port=r["source_port"],
            destination_port=r["destination_port"],
            log=r["log"],
            established=r["established"],
            mode=validated["mode"],
        ))

    terms_xml = "".join(terms_xml_parts)

    return _edit_configuration(f'''
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter xmlns:nc="{NS_RPC}" nc:operation="create">
        <name>{escape(name)}</name>
        {terms_xml}
      </filter>
    </inet>
  </family>
</firewall>
    ''')


@validate_call
def replace_acl(
    name: str,
    rules: list[dict] = ...,
    mode: str | None = None,
    revision: str | None = None,
    deleted_terms: list[str] | None = None,
    reference_config: str | None = None,
) -> str:
    name = validate_object_ref(name, "ACL name")
    payload = build_juniper_replace_acl_payload(
        name=name,
        rules=rules,
        mode=mode,
        revision=revision,
        deleted_terms=deleted_terms,
        reference_config=reference_config,
    )
    return _edit_configuration(payload)


@validate_call
def remove_acl(name: str):
    name = validate_object_ref(name, "ACL name")
    return _edit_configuration(f'''
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(name)}</name>
      </filter>
    </inet>
  </family>
</firewall>
    ''')


# อ่าน ACL (firewall filter) กลับมา - path ตรงกับที่ set_acl_rule เขียน
@validate_call
def get_acl_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <firewall xmlns="{NS_FIREWALL}">
        <family>
          <inet>
            <filter/>
          </inet>
        </family>
      </firewall>
    </configuration>
  </filter>
</get-config>
''')

@validate_call
def apply_acl_interface(
    interface_type: str,
    interface_id: str,
    acl_name: str,
    direction: Literal["in", "out"] = "in",
    unit: int = 0,
):
    interface = _interface_name(interface_type, interface_id)
    direction_tag = "input" if direction == "in" else "output"
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <unit>
      <name>{unit}</name>
      <family>
        <inet>
          <filter>
            <{direction_tag}>
              <filter-name>{escape(acl_name)}</filter-name>
            </{direction_tag}>
          </filter>
        </inet>
      </family>
    </unit>
  </interface>
</interfaces>
    ''')


@validate_call
def replace_acl_interface_bindings(
    acl_name: str,
    inbound_interfaces: list[str] = ...,
    outbound_interfaces: list[str] = ...,
    reference_config: str | None = None,
    revision: str | None = None,
) -> str:
    acl_name = validate_object_ref(acl_name, "ACL name")
    payload = build_juniper_replace_interface_bindings_payload(
        acl_name=acl_name,
        inbound_interfaces=inbound_interfaces,
        outbound_interfaces=outbound_interfaces,
        reference_config=reference_config,
        revision=revision,
    )
    return _edit_configuration(payload)

# อ่าน VLAN database กลับมา - path ตรงกับที่ set_vlan เขียน (vlans/vlan)
def get_vlan_information():
    return open_rpc_tag(f'''
      <get-config>
        <source>
          <running/>
        </source>
        <filter type="subtree">
          <configuration xmlns="{NS_ROOT}">
            <vlans xmlns="{NS_VLANS}">
              <vlan/>
            </vlans>
          </configuration>
        </filter>
      </get-config>
    ''')

@validate_call
def set_vlan(
    vlan_name: str,
    vlan_id: int | None = None,
    shutdown: bool | None = False,
    old_name: str | None = None,
):
    """Create/update a VLAN, optionally rename it or change its active state.

    vlan_id=None preserves the ID; shutdown=None preserves the active state.
    old_name identifies an existing VLAN to rename to vlan_name. Device-side
    validation still rejects missing sources, name collisions and invalid refs.
    """
    if vlan_id is not None and not 1 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 1 and 4094")

    def validate_name(value: str, field: str) -> str:
        value = value.strip()
        if not value or len(value) > 64:
            raise ValueError(f"{field} must be between 1 and 64 characters and not blank")
        if any(
            not (0x20 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD
                 or 0x10000 <= ord(char) <= 0x10FFFF)
            for char in value
        ):
            raise ValueError(f"{field} contains an invalid XML/control character")
        return value

    vlan_name = validate_name(vlan_name, "vlan_name")
    if old_name is not None:
        old_name = validate_name(old_name, "old_name")

    rename = old_name is not None and old_name != vlan_name
    if vlan_id is None and shutdown is None and not rename:
        raise ValueError("Provide vlan_id, shutdown or a different old_name")

    attributes = []
    if rename:
        attributes.extend(['rename="rename"', f"name={quoteattr(vlan_name)}"])
    if shutdown is not None:
        attributes.append('inactive="inactive"' if shutdown else 'active="active"')

    vlan_xml = "<vlan" + (" " + " ".join(attributes) if attributes else "") + ">"
    source_name = old_name if rename else vlan_name
    vlan_id_xml = f"<vlan-id>{vlan_id}</vlan-id>" if vlan_id is not None else ""

    return _edit_configuration(f'''
      <vlans xmlns="{NS_VLANS}">
        {vlan_xml}
          <name>{escape(source_name)}</name>
          {vlan_id_xml}
        </vlan>
      </vlans>
    ''')

@validate_call
def remove_vlan(vlan_name: str) -> str:
    # Junos vlans/vlan ใช้ name เป็น key ไม่ใช่ vlan-id
    # ลบเฉพาะ VLAN นี้ ไม่ลบ interface หรือ VLAN อื่นที่ไม่เกี่ยวข้อง
    if not vlan_name.strip() or len(vlan_name) > 64:
        raise ValueError("vlan_name must be between 1 and 64 characters and not blank")
    return _edit_configuration(f'''
      <vlans xmlns="{NS_VLANS}">
        <vlan xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(vlan_name)}</name>
        </vlan>
      </vlans>
    ''')

# อ่าน switchport (ethernet-switching) config กลับมาทั้งหมด - path ตรงกับที่
# apply_switchport/apply_interface_to_vlan เขียน (interfaces/interface/unit/
# family/ethernet-switching) ขอทั้ง interfaces subtree มาเลยเหมือนที่ Cisco's
# get_switchport_information ขอทั้ง native/interface (ระบุ interface ทีละตัว
# ในนี้ไม่ได้เพราะไม่รู้ล่วงหน้าว่ามี interface อะไรบ้าง)
def get_switchport_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <interfaces xmlns="{NS_INTERFACES}">
        <interface/>
      </interfaces>
    </configuration>
  </filter>
</get-config>
    ''')


@validate_call
def apply_interface_to_vlan(
    interface_type: str,
    interface_id: str,
    mode: Literal["access", "trunk"],
    vlan_id: int | None = None,
    trunk_allowed_vlans: str | None = None,
    description: str | None = None,
) -> str:
    # signature ตรงกับ Cisco's apply_interface_to_vlan เป๊ะ - แปลงเป็น
    # apply_switchport ที่มีอยู่แล้วในไฟล์นี้ภายใน (Junos's ethernet-switching
    # members leaf-list รับได้ทั้งชื่อ VLAN หรือเลข VLAN ID ตรงๆ - ยืนยันจาก
    # junos-es-conf-interfaces.yang:15518-15522 description "Membership for
    # this interface (name or id)" เลยส่งเลข vlan_id ดิบๆ เป็น member ได้เลย
    # ไม่ต้องรู้ชื่อ VLAN ที่ set_vlan ตั้งไว้)
    # user ขอทำ optional ไปก่อนหน้านี้ (2026-08-06) แล้วพบว่าใช้จริงกับอุปกรณ์ไม่
    # ได้ - ยืนยันจาก rpc-error จริง: "For trunk interface, please ensure either
    # vlan members is configured or inner-vlan-id-list is configured" - Junos
    # ปฏิเสธ trunk mode ที่ไม่มี vlan members เลยจริงๆ (สมมติฐานเดิมที่ว่า "ของ
    # จริงไม่เลือกก็ได้" ผิด) - revert กลับมาบังคับเหมือนเดิมทั้งหมดตามที่ user
    # ระบุ ("เอากลับมาเหมือนเดิมที่บังคับ vlan")
    if mode == "access" and vlan_id is None:
        raise ValueError("vlan_id is required when mode is access")
    if mode == "trunk" and vlan_id is not None:
        raise ValueError("vlan_id only applies to access mode, use trunk_allowed_vlans for trunk")
    if vlan_id is not None and not 1 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 1 and 4094")

    if mode == "access":
        members = [str(vlan_id)]
    else:
        if not trunk_allowed_vlans:
            raise ValueError("trunk_allowed_vlans is required when mode is trunk")
        members = [v.strip() for v in trunk_allowed_vlans.split(",") if v.strip()]

    return apply_switchport(
        interface_type=interface_type,
        interface_id=interface_id,
        mode=mode,
        vlan_members=members,
        description=description,
    )

@validate_call
def set_interface_vlan(
    vlan_id: int,
    ip: str,
    mask: int,
    shutdown: bool = True,
    description: str | None = None,
    mtu: int | None = None,
    previous_addresses: list[str] | None = None,
    vlan_name: str | None = None,
):
    if not 1 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 1 and 4094")
    address = ipaddress.IPv4Interface(f"{ip}/{mask}")
    addresses_xml = _removed_addresses_xml(previous_addresses, str(address))
    description_xml = _description_xml(description)
    # mtu ที่ระดับ <interface><name>irb</name> เป็น physical-level property ของ
    # Junos เสมอ (เหมือน set_interface_static_ip/set_sub_interface_ip) - ทุก
    # VLAN SVI (irb.10, irb.20, ...) แชร์ "irb" เป็น interface เดียวกัน เลยแชร์
    # ค่า mtu เดียวกันด้วย ไม่ใช่ต่อ unit แยก (ตรงกับ Junos config hierarchy จริง:
    # `interfaces irb { mtu 1500; unit 10 {...} unit 20 {...} }`)
    mtu_xml = _mtu_xml(mtu)
    # ยืนยันจริงกับอุปกรณ์ (vSRX) แล้วว่าจะยิง set_no_shutdown/set_shutdown
    # (interface_type="irb", interface_id=str(vlan_id)) แยกทีหลังแบบ physical
    # interface ไม่ได้เลย - ฟังก์ชันนั้นต่อ interface_type+interface_id เป็นชื่อ
    # เดียว ("irb"+"999"="irb999") ซึ่งไม่มีอยู่จริง (irb เป็น "irb" เฉยๆ ต่อด้วย
    # <unit> คนละ level ไม่ใช่ต่อกันเป็น string เดียว) โดน rpc-error "invalid
    # trailing input" ทันที - ต้องฝัง <disable/> ไว้ใน <unit> ของ call นี้เลย
    # (เหมือน pattern เดียวกับ nc:operation="remove" ที่ set_interface_static_ip
    # ใช้ - ไม่งั้น merge จะไม่มีทางลบ <disable/> เดิมออกได้เลยเหมือนกัน)
    disable_xml = (
        "<disable/>" if shutdown else f'<disable xmlns:nc="{NS_RPC}" nc:operation="remove"/>'
    )
    # VLANs are keyed by name, not ID. The caller resolves the existing name
    # from current configuration; do not invent a new VLAN from the unit ID.
    binding_xml = _vlan_l3_binding_xml(vlan_name, vlan_id) if vlan_name is not None else ""
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>irb</name>
    {mtu_xml}
    <unit>
      <name>{vlan_id}</name>
      {disable_xml}
      {description_xml}
      <family>
        <inet>
          {addresses_xml}
          <address>
            <name>{address}</name>
          </address>
        </inet>
      </family>
    </unit>
  </interface>
</interfaces>
{binding_xml}
    ''')


# อ่าน NAT pool/rule-set/static-nat กลับมา - path เดียวกับที่ create_nat_pool/
# set_nat/set_static_nat/set_port_forward เขียน (security/nat/...)
def get_nat_pool_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <nat>
          <source>
            <pool/>
          </source>
        </nat>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')


def get_nat_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <nat>
          <source>
            <rule-set/>
          </source>
        </nat>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')


def get_static_nat_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <nat>
          <static>
            <rule-set/>
          </static>
          <proxy-arp/>
        </nat>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')


# เจอบั๊กจริง (2026-07-30): เดิมคิดว่า Junos ไม่แยก static-nat กับ port-forward
# เป็นคนละ container (ใช้ security/nat/static/rule-set ร่วมกันทั้งคู่ ต่างกันแค่
# มี destination-port หรือไม่) - user ชี้ตรงๆ ว่าผิด: Junos มี **security/nat/
# destination** แยกต่างหากสำหรับ destination NAT/port-forward โดยเฉพาะ (pool-
# based - แปลง destination port ให้ต่างจาก local port ได้อิสระผ่าน pool object)
# เป็นวิธีที่ถูกต้อง/idiomatic กว่า "static NAT with port" ที่ใช้อยู่เดิม (ยังมี
# อยู่จริงใน Junos แต่ไม่ใช่ทางที่ตั้งใจไว้สำหรับ port-forward) - ย้ายมาใช้
# container นี้แทนทั้งหมด (ดู set_port_forward/remove_port_forward ด้านล่าง)
def get_port_forward_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <nat>
          <destination/>
          <proxy-arp/>
        </nat>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')


# เจอบั๊กจริง (2026-07-30 รอบ 4 - user ชี้): security/nat/proxy-arp ไม่เคยถูกลบ
# เลยตอนลบ static NAT/port forward (ตั้งใจไว้แต่แรกว่าคนละ concern - อาจถูกใช้
# ร่วมกับ rule อื่นที่มี public IP เดียวกันได้ ลบตามไม่ปลอดภัยถ้าไม่เช็คก่อน) แต่
# ผลคือ entry ค้างเป็น orphan ถาวรไม่มีทางลบออกได้เลยผ่านหน้าเว็บ - ต้องอ่านมาก่อน
# เพื่อให้ caller เช็คว่า address ที่จะลบยังถูกใช้จาก rule อื่น (ทั้ง static NAT
# และ port forward) อยู่หรือไม่ ก่อนตัดสินใจเรียก remove_nat_proxy_arp จริง
def get_nat_proxy_arp_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <nat>
          <proxy-arp/>
        </nat>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')


@validate_call
def create_nat_policy(
    name: str,
    via_type: str,
    via_id: str,
    translate_mode: Literal["interface", "pool"] = "interface",
    pool_name: str | None = None,
    source_scopes: str | list[str] = "any",
) -> str:
    # Cisco's create_nat_policy คิดแบบ "interface-centric" (ระบุแค่ขา outbound
    # เดียว ไม่ต้องรู้จัก zone) แต่ Junos SRX's NAT ผูกกับ zone เสมอ (จาก
    # set_nat ที่มีอยู่แล้วในไฟล์นี้ - ต้องมี from_zone/to_zone) - เพื่อให้
    # signature ตรงกับ Cisco (ผู้ใช้กรอกแค่ interface ไม่ต้องรู้จัก zone) จึง
    # derive zone ปลายทางจาก via interface เอง (ตั้งชื่อ Z-<interface> แล้ว
    # auto-assign interface นั้นเข้า zone ให้ในคำสั่งเดียวกัน) ส่วน zone ต้นทาง
    # ใช้ชื่อ "trust" ตายตัว (ข้อสมมติฐาน - ชื่อ zone ภายในที่พบบ่อยที่สุดใน Junos
    # SRX design ทั่วไป แต่ไม่ได้การันตีว่าตรงกับที่มีอยู่จริงในทุกอุปกรณ์ - ยังไม่
    # เคยทดสอบกับอุปกรณ์จริง ต้อง verify/ปรับตาม rpc-error ถ้า "trust" zone ไม่มี
    # อยู่จริงบนอุปกรณ์เป้าหมาย)
    if translate_mode == "pool" and not pool_name:
        raise ValueError("pool_name is required when translate_mode is 'pool'")

    interface = _interface_name(via_type, via_id)
    zone_name = f"Z-{via_type}{via_id}".replace("/", "-").replace(".", "-")

    scopes = [source_scopes] if isinstance(source_scopes, str) else source_scopes
    scopes = [s.strip() for s in scopes if s and s.strip()]
    if not scopes:
        scopes = ["any"]
    match_xml = "\n".join(
        f"<source-address>{'0.0.0.0/0' if s.lower() == 'any' else ipaddress.IPv4Network(s, strict=False)}</source-address>"
        for s in scopes
    )

    then_xml = (
        f"<pool><pool-name>{escape(pool_name)}</pool-name></pool>"
        if translate_mode == "pool" else "<interface/>"
    )

    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <zones>
    <security-zone>
      <name>{escape(zone_name)}</name>
      <interfaces>
        <name>{interface}</name>
      </interfaces>
    </security-zone>
  </zones>
  <nat>
    <source>
      <rule-set>
        <name>{escape(name)}</name>
        <from><zone>trust</zone></from>
        <to><zone>{escape(zone_name)}</zone></to>
        <rule>
          <name>{escape(name)}</name>
          <src-nat-rule-match>
            {match_xml}
          </src-nat-rule-match>
          <then>
            <source-nat>
              {then_xml}
            </source-nat>
          </then>
        </rule>
      </rule-set>
    </source>
  </nat>
</security>
    ''')


@validate_call
def apply_nat_interface(
    interface_type: str,
    interface_name: str,
    direction: Literal["inside", "outside"] = "inside",
) -> str:
    # Cisco's "ip nat inside/outside" เป็น flag ต่อ interface ตรงๆ ไม่มี concept
    # เทียบเท่าใน Junos SRX เลย (Junos ใช้ zone assignment แทนทั้งหมด - interface
    # ไหนอยู่ zone ไหนก็กำหนดทิศทาง NAT ผ่าน from-zone/to-zone ของ rule-set แทน
    # ไม่มี flag แยกต่างหากที่ตัว interface) - เก็บฟังก์ชันนี้ไว้ให้ signature
    # ตรงกับ Cisco (ไม่ error ถ้าถูกเรียก) แต่ไม่มีอะไรให้ทำจริง เพราะ
    # create_nat_policy ข้างบนจัดการ zone assignment ให้ครบอยู่แล้วในตัว
    raise ValueError(
        "Junos has no concept of 'ip nat inside/outside' separate from zone assignment - "
        "create_nat_policy manages zones internally; no need to call this function"
    )


# (bug 61) เดิมไม่มี @validate_call จึงไม่มีอะไรบังคับว่าค่าที่รับมาต้องเป็น str -
# และ ipaddress.IPv4Address() ที่ใช้เป็นตัวตรวจอยู่ "รับ int ได้ด้วย" (IPv4Address(
# 3232235777) = 192.168.1.1 ไม่ error) แต่โค้ดทิ้งค่าที่ parse แล้วไปแปะ "สตริงดิบ"
# ลง XML ผลคือส่ง int เข้ามาผ่านฉลุยแล้วได้ <local-ip>3232235777</local-ip> บนอุปกรณ์
# จริง - ยืนยันด้วยการรันจริงแล้ว เป็นอาการเดียวกับ bug 13/14 ที่ตกฟังก์ชันกลุ่มนี้ไป
@validate_call
def create_nat_pool(
    name: str,
    start: str | None = None,
    end: str | None = None,
    description: str | None = None,
    replace_name: str | None = None,
    replace_start: str | None = None,
    address_starts: list[str] | None = None,
    address_ends: list[str] | None = None,
    replace_starts: list[str] | None = None,
):
    uses_address_lists = any(
        value is not None for value in (address_starts, address_ends, replace_starts)
    )
    if uses_address_lists and (start is not None or end is not None or replace_start is not None):
        raise ValueError("use either start/end or address_starts/address_ends, not both")

    if replace_name is None:
        if replace_start is not None or replace_starts is not None:
            raise ValueError("replacement address keys require replace_name")
        name = validate_config_name(name, "NAT pool name")
    else:
        name = validate_object_ref(name, "NAT pool name")
        replace_name = validate_object_ref(replace_name, "Previous NAT pool name")
        if replace_name != name:
            raise ValueError("NAT pool name cannot be changed during edit")
        if not replace_start and replace_starts is None:
            raise ValueError("replacement address keys are required when editing a Juniper NAT pool")

    if uses_address_lists:
        if not address_starts:
            raise ValueError("address_starts must contain at least one address")
        if len(address_starts) > 64:
            raise ValueError("Juniper NAT pool supports at most 64 address entries")
        ends = address_ends if address_ends is not None else [""] * len(address_starts)
        if len(ends) != len(address_starts):
            raise ValueError("address_ends must have the same length as address_starts")
        raw_ranges = list(zip(address_starts, ends))
        original_keys = replace_starts or []
    else:
        if not start:
            raise ValueError("start is required")
        raw_ranges = [(start, end or "")]
        original_keys = [replace_start] if replace_start else []

    ranges = []
    seen_starts = set()
    for range_start, range_end in raw_ranges:
        start_address = ipaddress.IPv4Address(range_start)
        normalized_start = str(start_address)
        if normalized_start in seen_starts:
            raise ValueError(f"duplicate NAT pool start address: {normalized_start}")
        seen_starts.add(normalized_start)
        normalized_end = ""
        if range_end:
            end_address = ipaddress.IPv4Address(range_end)
            if int(end_address) < int(start_address):
                raise ValueError("NAT pool end address must not be lower than start address")
            normalized_end = str(end_address)
        ranges.append((normalized_start, normalized_end))

    old_keys = {}
    for original_key in original_keys:
        try:
            old_network = ipaddress.IPv4Network(original_key, strict=False)
        except ValueError:
            raise ValueError("replacement address key must be a valid IPv4 host address")
        if old_network.prefixlen != 32:
            raise ValueError("replacement address key must be an IPv4 host address or /32")
        logical_key = str(old_network.network_address)
        if logical_key in old_keys:
            raise ValueError(f"duplicate replacement address key: {logical_key}")
        old_keys[logical_key] = str(old_network) if "/" in original_key else logical_key

    description_xml = f"<description>{escape(description)}</description>" if description else ""

    pool_attribute = f' xmlns:nc="{NS_RPC}" nc:operation="create"' if replace_name is None else ""
    if replace_name is None:
        address_xml = "\n".join(
            f'''<address>
          <name>{range_start}</name>
          {f"<to><ipaddr>{range_end}</ipaddr></to>" if range_end else ""}
        </address>'''
            for range_start, range_end in ranges
        )
    else:
        address_parts = [
            f'''<address xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{old_key}</name>
        </address>'''
            for logical_key, old_key in old_keys.items()
            if logical_key not in seen_starts
        ]
        for range_start, range_end in ranges:
            operation = "replace" if range_start in old_keys else "create"
            address_key = old_keys.get(range_start, range_start)
            to_xml = f"<to><ipaddr>{range_end}</ipaddr></to>" if range_end else ""
            address_parts.append(f'''<address xmlns:nc="{NS_RPC}" nc:operation="{operation}">
          <name>{address_key}</name>
          {to_xml}
        </address>''')
        address_xml = "\n".join(address_parts)

    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <source>
      <pool{pool_attribute}>
        <name>{escape(name)}</name>
        {description_xml}
        {address_xml}
      </pool>
    </source>
  </nat>
</security>
    ''')


# ลบ NAT pool ทั้งตัว - key ของ pool คือ "name" (list ปกติของ Junos) - ยืนยันจริง
# แล้วผ่านอุปกรณ์ (2026-07-28, ระหว่างทดสอบ Address Pool - เจอว่า create_nat_pool
# เดิมมี XML พัง (`</security>` ปิดไม่ครบ) แก้ไปด้วยพร้อมกัน) - ถ้า pool ยังถูก
# อ้างอิงอยู่โดย rule-set ที่ใช้งานจริง Junos ปฏิเสธเองด้วย commit error
@validate_call
def remove_nat_pool(name: str):
    # ชื่อนี้อ่านกลับมาจากอุปกรณ์ จึงใช้กฎ object reference ที่ยอมรับชื่อ brownfield
    # แต่ยังปฏิเสธค่าว่าง อักขระควบคุม และอักขระที่เสี่ยงทำ XML ผิดรูป ไม่ใช้
    # validate_config_name() เพราะกฎสำหรับชื่อใหม่เข้มกว่า syntax ที่ Junos ยอมรับ
    name = validate_object_ref(name, "NAT pool name")
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <source>
      <pool xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(name)}</name>
      </pool>
    </source>
  </nat>
</security>
    ''')


@validate_call
def set_nat(
    rule_set: str,
    rule_name: str,
    from_zones: list[str],
    to_zones: list[str] | None = None,
    to_zone: str | None = None,
    pool_name: str | None = None,
    use_interface: bool = False,
    source_addresses: list[str] | None = None,
    replace_rule_set: str | None = None,
    replace_rule_name: str | None = None,
):
    if bool(pool_name) == bool(use_interface):
        raise ValueError("specify exactly one of pool_name or use_interface")
    replace_values = (replace_rule_set, replace_rule_name)
    if any(value is not None for value in replace_values) and not all(value is not None for value in replace_values):
        raise ValueError("replace source NAT requires replace_rule_set and replace_rule_name together")
    replacing = all(value is not None for value in replace_values)

    rule_set = validate_object_ref(rule_set, "rule_set")
    rule_name = validate_object_ref(rule_name, "rule_name")
    if replacing:
        replace_rule_set = validate_object_ref(replace_rule_set, "replace_rule_set")
        replace_rule_name = validate_object_ref(replace_rule_name, "replace_rule_name")
        if replace_rule_set != rule_set or replace_rule_name != rule_name:
            raise ValueError("Source NAT rule name and rule-set cannot be changed during edit")
    else:
        rule_set = validate_config_name(rule_set, "rule_set")
        rule_name = validate_config_name(rule_name, "rule_name")

    from_zones = list(dict.fromkeys(zone.strip() for zone in from_zones if zone and zone.strip()))
    if not from_zones:
        raise ValueError("from_zones must have at least 1 zone")
    destinations = [zone.strip() for zone in (to_zones or []) if zone and zone.strip()]
    if to_zone and to_zone.strip():
        legacy_destination = to_zone.strip()
        if destinations and legacy_destination not in destinations:
            raise ValueError("Conflicting to_zone and to_zones values provided")
        if not destinations:
            destinations = [legacy_destination]
    destinations = list(dict.fromkeys(destinations))
    if not destinations:
        raise ValueError("to_zones must have at least 1 zone")
    if len(from_zones) > 8 or len(destinations) > 8:
        raise ValueError("Junos supports a maximum of 8 zones for from_zones and to_zones each")
    from_zones = [validate_object_ref(zone, "from_zone") for zone in from_zones]
    destinations = [validate_object_ref(zone, "to_zone") for zone in destinations]
    if pool_name:
        pool_name = validate_object_ref(pool_name, "pool_name")

    # Junos บังคับว่า src-nat-rule-match (แสดงเป็น "match" ตอน commit error) ต้องมีเสมอ
    # ทดสอบจริงแล้วว่าถ้าไม่ใส่เลย commit จะ fail ทั้ง transaction (Junos commit เป็น atomic)
    # default ["0.0.0.0/0"] = match ทุก source เทียบเท่า Cisco "permit ip any any"
    addresses = [a.strip() for a in (source_addresses or ["0.0.0.0/0"]) if a and a.strip()]
    if not addresses:
        addresses = ["0.0.0.0/0"]
    addresses = [str(ipaddress.IPv4Network(addr, strict=False)) for addr in addresses]
    # source-address เป็น leaf-list รับได้หลายอันจริง (ยืนยันจาก commit check บน
    # อุปกรณ์จริง 2026-07-29) - match ถ้าตรงกับอันใดอันหนึ่ง (OR กัน) ส่วน
    # destination-address ใส่ "0.0.0.0/0" ตายตัวเสมอ (ไม่มี field ให้ user กรอกเอง
    # ตามที่ตกลง - ฟอร์มนี้ทำ source NAT ออก internet เท่านั้น ไม่ใช่ policy-based
    # routing ที่ต้อง match destination เจาะจง)
    source_xml = "\n".join(f"<source-address>{addr}</source-address>" for addr in addresses)
    match_xml = f'''<src-nat-rule-match>
      {source_xml}
      <destination-address>0.0.0.0/0</destination-address>
    </src-nat-rule-match>'''
    # from zone รับได้หลาย zone เหมือนกัน (leaf-list, ยืนยันจาก commit check บน
    # อุปกรณ์จริงเช่นกัน: "from zone [ Backbone LAN ];") - match traffic จากขา
    # zone ไหนก็ได้ในรายการนี้ (OR กัน); ฝั่ง to เป็น leaf-list แบบเดียวกันและ
    # รองรับได้สูงสุด 8 zone ตาม junos-es-conf-security.yang
    from_xml = "\n".join(f"<zone>{escape(z)}</zone>" for z in from_zones)
    to_xml = "\n".join(f"<zone>{escape(z)}</zone>" for z in destinations)
    then_xml = (
        f"<pool><pool-name>{escape(pool_name)}</pool-name></pool>"
        if pool_name else "<interface/>"
    )

    rule_set_attribute = (
        ""
        if replacing
        else f' xmlns:nc="{NS_RPC}" nc:operation="create"'
    )
    replace_attribute = f' xmlns:nc="{NS_RPC}" nc:operation="replace"' if replacing else ""

    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <source>
      <rule-set{rule_set_attribute}>
        <name>{escape(rule_set)}</name>
        <from{replace_attribute}>{from_xml}</from>
        <to{replace_attribute}>{to_xml}</to>
        <rule{replace_attribute}>
          <name>{escape(rule_name)}</name>
          {match_xml}
          <then>
            <source-nat>
              {then_xml}
            </source-nat>
          </then>
        </rule>
      </rule-set>
    </source>
  </nat>
</security>
    ''')


# Brownfield rule-set อาจมีหลาย rule: ถ้าระบุ rule_name ให้ลบเฉพาะ rule นั้น;
# ถ้าไม่ระบุแปลว่าเป็น rule สุดท้ายและ caller ตั้งใจลบทั้ง rule-set เพื่อไม่ทิ้ง
# shell ว่างที่ยังครอง context อยู่
@validate_call
def remove_nat(rule_set: str, rule_name: str | None = None):
    rule_set = validate_object_ref(rule_set, "rule_set")
    if rule_name is not None:
        rule_name = validate_object_ref(rule_name, "rule_name")
        target_xml = f'''<rule-set>
        <name>{escape(rule_set)}</name>
        <rule xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(rule_name)}</name>
        </rule>
      </rule-set>'''
    else:
        target_xml = f'''<rule-set xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(rule_set)}</name>
      </rule-set>'''
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <source>
      {target_xml}
    </source>
  </nat>
</security>
    ''')


# (bug 61) เดิมไม่มี @validate_call จึงไม่มีอะไรบังคับว่าค่าที่รับมาต้องเป็น str -
# และ ipaddress.IPv4Network() ที่ใช้เป็นตัวตรวจอยู่ "รับ int ได้ด้วย" (ไม่ error) แต่โค้ด
# ทิ้งค่าที่ parse แล้วไปแปะ "สตริงดิบ" ลง XML ผลคือส่ง int เข้ามาผ่านฉลุยแล้วได้
# <dst-addr>3232235777</dst-addr> บนอุปกรณ์จริง - ยืนยันด้วยการรันจริงแล้ว
# (ตัวนี้ตกจากการสแกนรอบแรกเพราะเรียกแบบ IPv4Network(x, strict=False) ซึ่งมี arg ที่สอง)
@validate_call
def set_static_nat(
    rule_set: str,
    rule_name: str,
    from_zone: str,
    destination_address: str,
    local_address: str,
    description: str | None = None,
    interface_type: str | None = None,
    interface_id: str | None = None,
    proxy_arp_address: str | None = None,
    replace_rule_set: str | None = None,
    replace_rule_name: str | None = None,
    replace_whole_ruleset: bool = False,
):
    try:
        destination_address = str(ipaddress.IPv4Network(destination_address, strict=False))
    except ValueError:
        raise ValueError("destination_address must be a valid IPv4 address or prefix")
    try:
        local_address = str(ipaddress.IPv4Network(local_address, strict=False))
    except ValueError:
        raise ValueError("local_address must be a valid IPv4 address or prefix")

    replace_values = (replace_rule_set, replace_rule_name)
    if any(value is not None for value in replace_values) and not all(value is not None for value in replace_values):
        raise ValueError("replace static NAT requires replace_rule_set and replace_rule_name together")

    replacing = all(value is not None for value in replace_values)
    rule_set = validate_object_ref(rule_set, "rule_set")
    from_zone = validate_object_ref(from_zone, "from_zone")
    if replacing:
        replace_rule_set = validate_object_ref(replace_rule_set, "replace_rule_set")
        replace_rule_name = validate_object_ref(replace_rule_name, "replace_rule_name")
    if replace_whole_ruleset and not replacing:
        raise ValueError("replace_whole_ruleset requires replace_rule_set and replace_rule_name")

    # ชื่อเดิมจาก brownfield config อาจอยู่นอก naming policy ของระบบ จึงยอมให้
    # edit identity เดิมผ่านแบบ object reference; create/rename ใหม่ต้องใช้กฎเข้ม
    rule_name = validate_object_ref(rule_name, "rule_name")
    keeps_rule_identity = replacing and replace_rule_set == rule_set and replace_rule_name == rule_name
    if not keeps_rule_identity:
        rule_name = validate_config_name(rule_name, "rule_name")
    creates_new_rule = not replacing or replace_rule_set != rule_set
    description_xml = "" if description == "" and creates_new_rule else _description_xml(description)

    proxy_values = (interface_type, interface_id, proxy_arp_address)
    if any(value is not None for value in proxy_values) and not all(value is not None for value in proxy_values):
        raise ValueError("proxy-arp requires interface_type, interface_id and proxy_arp_address together")
    proxy_arp_xml = ""
    if all(value is not None for value in proxy_values):
        validate_object_ref(f"{interface_type}{interface_id}", "proxy_arp_interface")
        interface = _interface_name(interface_type, interface_id)
        try:
            proxy_network = ipaddress.IPv4Network(proxy_arp_address, strict=False)
        except ValueError:
            raise ValueError("proxy_arp_address must be a valid IPv4 address or prefix")
        proxy_arp_xml = f'''    <proxy-arp>
      <interface>
        <name>{interface}</name>
        <address><name>{proxy_network}</name></address>
      </interface>
    </proxy-arp>
'''

    old_config_xml = ""
    # A plain NETCONF merge on a new list key silently edits an existing rule
    # when the user reuses its name. Use create for every genuinely new target
    # identity so Junos returns data-exists and the candidate is discarded.
    rule_attributes = (
        ""
        if keeps_rule_identity
        else f' xmlns:nc="{NS_RPC}" nc:operation="create"'
    )
    source_rule_name = rule_name
    if replacing:
        if replace_rule_set == rule_set:
            # rename rule-set STATIC-WAN rule OLD to rule NEW
            if replace_rule_name != rule_name:
                # Junos rename is atomic and rejects an existing destination;
                # it must not be combined with nc:operation=create.
                rule_attributes = f' rename="rename" name={quoteattr(rule_name)}'
                source_rule_name = replace_rule_name
        elif replace_whole_ruleset:
            old_config_xml = f'''      <rule-set xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(replace_rule_set)}</name>
      </rule-set>
'''
        else:
            old_config_xml = f'''      <rule-set>
        <name>{escape(replace_rule_set)}</name>
        <rule xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(replace_rule_name)}</name>
        </rule>
      </rule-set>
'''

    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <static>
{old_config_xml}
      <rule-set>
        <name>{escape(rule_set)}</name>
        <from><zone>{escape(from_zone)}</zone></from>
        <rule{rule_attributes}>
          <name>{escape(source_rule_name)}</name>
          {description_xml}
          <static-nat-rule-match>
            <destination-address>
              <dst-addr>{destination_address}</dst-addr>
            </destination-address>
          </static-nat-rule-match>
          <then>
            <static-nat>
              <prefix>
                <addr-prefix>{local_address}</addr-prefix>
              </prefix>
            </static-nat>
          </then>
        </rule>
      </rule-set>
    </static>
{proxy_arp_xml}
  </nat>
</security>
    ''')

@validate_call
def set_nat_proxy_arp(interface_type: str, interface_id: str, address: str):
    # Junos ไม่ตอบ ARP แทนที่อยู่ static-NAT (destination NAT) เองอัตโนมัติ ต่างจาก
    # Cisco ที่ NAT ทำงานได้เลยหลัง config — ต้องเปิด proxy-arp ให้ ingress interface
    # (ปกติคือ WAN) ตอบ ARP แทน public IP ที่ใช้ใน set_static_nat/set_port_forward
    # ไม่งั้น upstream router/switch ไม่รู้ว่าจะส่ง traffic มาที่ vSRX เลย แม้ NAT rule
    # + security policy จะถูกต้องครบก็ตาม (ทดสอบจริง: static NAT/port forward ยังไม่ทำงาน
    # แม้มี WAN->trust policy แล้ว จนกว่าจะเพิ่ม proxy-arp)
    validate_object_ref(f"{interface_type}{interface_id}", "proxy_arp_interface")
    interface = _interface_name(interface_type, interface_id)
    try:
        network = ipaddress.IPv4Network(address, strict=False)
    except ValueError:
        raise ValueError("address must be a valid IPv4 address or prefix")
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <proxy-arp>
      <interface>
        <name>{interface}</name>
        <address>
          <name>{network}</name>
        </address>
      </interface>
    </proxy-arp>
  </nat>
</security>
    ''')


def _nat_proxy_arp_remove_xml(
    interface_type: str | None,
    interface_id: str | None,
    proxy_arp_address: str | None,
) -> str:
    values = (interface_type, interface_id, proxy_arp_address)
    if not any(value is not None for value in values):
        return ""
    if not all(value is not None for value in values):
        raise ValueError(
            "proxy-arp removal requires interface_type, interface_id and "
            "proxy_arp_address together"
        )
    validate_object_ref(f"{interface_type}{interface_id}", "proxy_arp_interface")
    interface = _interface_name(interface_type, interface_id)
    try:
        network = ipaddress.IPv4Network(proxy_arp_address, strict=False)
    except ValueError:
        raise ValueError("proxy_arp_address must be a valid IPv4 address or prefix")
    return f'''    <proxy-arp>
      <interface>
        <name>{interface}</name>
        <address xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{network}</name>
        </address>
      </interface>
    </proxy-arp>
'''


# เจอบั๊กจริง (2026-07-30 รอบ 4 - user ชี้): ลบ static NAT/port forward ไปแล้ว
# แต่ proxy-arp entry ของ public IP นั้นยังไม่ถูกลบตาม - ค้างเป็น orphan (เดิม
# ตั้งใจไม่แตะเพราะกลัวมี rule อื่นแชร์ public IP เดียวกันอยู่ - ตอนนี้ให้ caller
# เป็นคนเช็คก่อน (ผ่าน get_nat_proxy_arp_information + get_static_nat_information
# + get_port_forward_information) ว่าไม่มี rule อื่นใช้ address นี้อยู่แล้วค่อย
# เรียกฟังก์ชันนี้) - ลบแค่ address entry เดียว ไม่ลบทั้ง interface (interface
# อาจมี public IP อื่นของ rule อื่นผูกอยู่ด้วย)
@validate_call
def remove_nat_proxy_arp(interface_type: str, interface_id: str, address: str):
    validate_object_ref(f"{interface_type}{interface_id}", "proxy_arp_interface")
    interface = _interface_name(interface_type, interface_id)
    try:
        network = ipaddress.IPv4Network(address, strict=False)
    except ValueError:
        raise ValueError("address must be a valid IPv4 address or prefix")
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <proxy-arp>
      <interface>
        <name>{interface}</name>
        <address xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{network}</name>
        </address>
      </interface>
    </proxy-arp>
  </nat>
</security>
    ''')


# เจอบั๊กจริง (2026-07-30 รอบ 2): เดิมเขียนลง security/nat/static (แบบเดียวกับ
# static NAT ธรรมดา ต่างกันแค่มี destination-port/mapped-port) - user ชี้ว่า
# ไม่ใช่วิธีที่ถูกต้อง: Junos มี **security/nat/destination** แยกต่างหากสำหรับ
# port-forward โดยเฉพาะ (pool-based) ยืนยันจริงกับอุปกรณ์แล้วว่า syntax ที่ user
# ให้มาถูกต้อง (`commit check` ผ่าน) - ย้ายมาใช้ container นี้แทน:
#   1. สร้าง destination-nat pool ชื่อ "<rule_name>-POOL" (address+port ปลายทาง
#      จริง - derive ชื่อจาก rule_name เอง ไม่ต้องให้ user กรอกชื่อ pool แยก)
#   2. สร้าง rule-set/rule match destination-address/port แล้ว then ชี้ไปที่
#      pool นั้น
# rule-set ยัง**ต้อง**รวมเป็น 1 ต่อ 1 from-zone เหมือน static NAT (ยืนยันจริงว่า
# security/nat/destination/rule-set มี "same context" constraint เดียวกันเป๊ะ -
# commit check ปฏิเสธ 2 rule-set ต่างชื่อที่ from-zone เดียวกัน) แต่เป็นคนละ
# namespace จาก static NAT โดยสิ้นเชิง (ไม่ต้องแชร์ rule-set กับ static NAT อีก
# ต่อไป - ดู destinationNatRuleSet() ฝั่ง frontend) - XML tag บางตัวต่างจาก
# static NAT (ยืนยันจาก `show ... | display xml` บนอุปกรณ์จริง ไม่ได้เดา):
# `dest-nat-rule-match` (ไม่ใช่ static-nat-rule-match), destination-port ใช้
# `<name>` เป็น tag ตัวเลข (ไม่ใช่ `<low>`), pool's address ใช้ `<port>` ตรงๆ
# เป็น leaf เดี่ยว (ไม่ใช่ nested single-port/port-number แบบที่เดาไว้ตอนแรก)
# (bug 61) เดิมไม่มี @validate_call จึงไม่มีอะไรบังคับว่าค่าที่รับมาต้องเป็น str -
# และ ipaddress.IPv4Network() ที่ใช้เป็นตัวตรวจอยู่ "รับ int ได้ด้วย" (ไม่ error) แต่โค้ด
# ทิ้งค่าที่ parse แล้วไปแปะ "สตริงดิบ" ลง XML ผลคือส่ง int เข้ามาผ่านฉลุยแล้วได้
# <dst-addr>3232235777</dst-addr> บนอุปกรณ์จริง - ยืนยันด้วยการรันจริงแล้ว
# (ตัวนี้ตกจากการสแกนรอบแรกเพราะเรียกแบบ IPv4Network(x, strict=False) ซึ่งมี arg ที่สอง)
@validate_call
def set_port_forward(
    rule_set: str,
    rule_name: str,
    from_zone: str,
    destination_address: str,
    destination_port: StrictInt,
    local_address: str,
    local_port: StrictInt,
    pool_name: str | None = None,
    description: str | None = None,
    interface_type: str | None = None,
    interface_id: str | None = None,
    proxy_arp_address: str | None = None,
    replace_rule_set: str | None = None,
    replace_rule_name: str | None = None,
    replace_pool_name: str | None = None,
    replace_destination_ports: list[StrictInt] | None = None,
    replace_whole_ruleset: bool = False,
):
    # ค่า address ของ Junos leaf นี้รับได้ทั้ง host เดี่ยวและ CIDR; parse แล้วต้อง
    # ใช้ค่าที่ normalize กลับไปประกอบ XML ด้วย ห้ามตรวจเสร็จแล้วส่งค่าดิบต่อเหมือน
    # โค้ดเดิม เพราะ host-bit/รูปแบบแปลกจะทำให้สิ่งที่บันทึกไม่ตรงกับสิ่งที่ validate
    try:
        destination_address = str(ipaddress.IPv4Network(destination_address, strict=False))
    except ValueError:
        raise ValueError("destination_address must be a valid IPv4 address or prefix")
    try:
        local_address = str(ipaddress.IPv4Network(local_address, strict=False))
    except ValueError:
        raise ValueError("local_address must be a valid IPv4 address or prefix")
    if not 1 <= destination_port <= 65535:
        raise ValueError("destination_port must be between 1 and 65535")
    if not 1 <= local_port <= 65535:
        raise ValueError("local_port must be between 1 and 65535")

    replace_values = (replace_rule_set, replace_rule_name)
    if any(value is not None for value in replace_values) and not all(value is not None for value in replace_values):
        raise ValueError("replace port-forward requires replace_rule_set and replace_rule_name together")
    if replace_pool_name is not None and not all(value is not None for value in replace_values):
        raise ValueError("replace_pool_name requires replace_rule_set and replace_rule_name")
    if replace_destination_ports is not None and not all(value is not None for value in replace_values):
        raise ValueError("replace_destination_ports requires replace_rule_set and replace_rule_name")
    old_destination_ports = list(dict.fromkeys(replace_destination_ports or []))
    if any(not 1 <= port <= 65535 for port in old_destination_ports):
        raise ValueError("replace_destination_ports must contain ports between 1 and 65535")

    # rule-set/zone เป็น reference ที่อาจมาจาก brownfield config จึงใช้กฎแบบ
    # reference (ปลอดภัยแต่ไม่บังคับรูปแบบชื่อใหม่ของเรา) ส่วน rule ที่สร้างใหม่หรือ
    # rename ต้องผ่านกฎชื่อใหม่; edit ชื่อเดิมยอมรับชื่อ brownfield ตามจริง
    rule_set = validate_object_ref(rule_set, "rule_set")
    from_zone = validate_object_ref(from_zone, "from_zone")
    replacing = all(value is not None for value in replace_values)
    if replacing:
        replace_rule_set = validate_object_ref(replace_rule_set, "replace_rule_set")
        replace_rule_name = validate_object_ref(replace_rule_name, "replace_rule_name")
    if replace_whole_ruleset and not replacing:
        raise ValueError("replace_whole_ruleset requires replace_rule_set and replace_rule_name")
    # normalize แบบ reference ก่อนเทียบ identity เพื่อไม่ให้ช่องว่างรอบชื่อทำให้
    # edit ชื่อเดิมถูกเข้าใจผิดว่าเป็น rename แล้วชน operation=create
    rule_name = validate_object_ref(rule_name, "rule_name")
    keeps_rule_identity = replacing and replace_rule_set == rule_set and replace_rule_name == rule_name
    if not keeps_rule_identity:
        rule_name = validate_config_name(rule_name, "rule_name")

    # Config ที่ระบบสร้างเองใช้ <rule>-POOL แต่ brownfield config อาจตั้งชื่อ pool
    # อะไรก็ได้ ต้องรับและใช้ชื่อจริงจาก get_port_forward_information แทนการเดา
    pool_name = pool_name or f"{rule_name}-POOL"
    old_pool_name = None
    if replacing:
        old_pool_name = replace_pool_name or f"{replace_rule_name}-POOL"
        old_pool_name = validate_object_ref(old_pool_name, "replace_pool_name")
    pool_name = (
        validate_object_ref(pool_name, "pool_name")
        if old_pool_name == pool_name
        else validate_config_name(pool_name, "pool_name")
    )
    # create ใหม่ไม่มี leaf เดิมให้ remove; ค่าว่างจึงหมายถึงไม่สร้าง description
    # ส่วน edit identity เดิมค่าว่างหมายถึงลบ description ที่มีอยู่
    description_xml = "" if description == "" and not keeps_rule_identity else _description_xml(description)

    proxy_values = (interface_type, interface_id, proxy_arp_address)
    if any(value is not None for value in proxy_values) and not all(value is not None for value in proxy_values):
        raise ValueError("proxy-arp requires interface_type, interface_id and proxy_arp_address together")
    old_pool_remove_xml = old_rule_remove_xml = old_ruleset_remove_xml = ""
    if replacing:
        if old_pool_name != pool_name:
            old_pool_remove_xml = f'''      <pool xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(old_pool_name)}</name>
      </pool>
'''
        if not (replace_rule_set == rule_set and replace_rule_name == rule_name):
            # same rule-set + whole=true ต้องลดระดับเป็น rule; ห้ามลบ rule-set ที่กำลัง set
            if replace_whole_ruleset and replace_rule_set != rule_set:
                old_ruleset_remove_xml = f'''      <rule-set xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(replace_rule_set)}</name>
      </rule-set>
'''
            else:
                old_rule_remove_xml = f'''      <rule-set>
        <name>{escape(replace_rule_set)}</name>
        <rule xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(replace_rule_name)}</name>
        </rule>
      </rule-set>
'''
    # NETCONF merge เป็นพฤติกรรมที่อันตรายสำหรับ target ใหม่: ถ้าชื่อ rule/pool
    # ซ้ำ มันจะเขียนทับ object เดิมเงียบ ๆ แทนที่จะบอกผู้ใช้ จึงใช้ operation=create
    # เฉพาะตอนสร้าง identity ใหม่ ให้ data-exists หยุดทั้ง edit และ discard candidate
    # ได้ ส่วน edit identity เดิมยังใช้ merge เพื่อแก้ค่าได้ตามปกติ
    pool_create_attribute = (
        ""
        if old_pool_name == pool_name
        else f' xmlns:nc="{NS_RPC}" nc:operation="create"'
    )
    rule_create_attribute = (
        ""
        if keeps_rule_identity
        else f' xmlns:nc="{NS_RPC}" nc:operation="create"'
    )
    # destination-port is a keyed list (name is its key).  A merge appends a
    # new list entry, while operation=replace on the *new entry* still cannot
    # identify and remove an entry with the old key.  Remove each old list
    # entry that differs from the desired port and add the desired entry in the
    # same edit-config.  This is atomic and only touches the edited match field,
    # preserving unsupported Brownfield children elsewhere in the rule.
    removed_destination_ports_xml = "".join(
        f'''<destination-port xmlns:nc="{NS_RPC}" nc:operation="remove">
              <name>{port}</name>
            </destination-port>'''
        for port in old_destination_ports if port != destination_port
    )
    proxy_arp_xml = ""
    if all(value is not None for value in proxy_values):
        # normalize เหมือน set_nat_proxy_arp เพื่อให้ cleanupOrphanedProxyArp จับ /32 เดิมได้
        validate_object_ref(f"{interface_type}{interface_id}", "proxy_arp_interface")
        interface = _interface_name(interface_type, interface_id)
        try:
            network = ipaddress.IPv4Network(proxy_arp_address, strict=False)
        except ValueError:
            raise ValueError("proxy_arp_address must be a valid IPv4 address or prefix")
        proxy_arp_xml = f'''    <proxy-arp>
      <interface>
        <name>{interface}</name>
        <address><name>{network}</name></address>
      </interface>
    </proxy-arp>
'''

    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <destination>
{old_pool_remove_xml}{old_ruleset_remove_xml}{old_rule_remove_xml}      <pool{pool_create_attribute}>
        <name>{escape(pool_name)}</name>
        <address>
          <ipaddr>{local_address}</ipaddr>
          <port>{local_port}</port>
        </address>
      </pool>
      <rule-set>
        <name>{escape(rule_set)}</name>
        <from><zone>{escape(from_zone)}</zone></from>
        <rule{rule_create_attribute}>
          <name>{escape(rule_name)}</name>
          {description_xml}
          <dest-nat-rule-match>
            <destination-address>
              <dst-addr>{destination_address}</dst-addr>
            </destination-address>
            {removed_destination_ports_xml}<destination-port>
              <name>{destination_port}</name>
            </destination-port>
          </dest-nat-rule-match>
          <then>
            <destination-nat>
              <pool>
                <pool-name>{escape(pool_name)}</pool-name>
              </pool>
            </destination-nat>
          </then>
        </rule>
      </rule-set>
    </destination>
{proxy_arp_xml}  </nat>
</security>
    ''')


# เจอบั๊กจริง (2026-07-30): เดิมลบทั้ง rule-set ทิ้ง (สมมติ 1 rule-set ต่อ 1
# rule เสมอ) - แต่ Junos's security/nat/static/rule-set ถูก scope ด้วย
# "context" (from-zone/interface/routing-instance) และ**ปฏิเสธถ้ามี 2 rule-set
# คนละชื่อแต่ context เดียวกัน** (ยืนยันจริงจากอุปกรณ์: "rule-set X and rule-set
# Y have same context" - เจอตอน user สร้าง static NAT ตัวที่ 2 ในวง WAN
# เดียวกับตัวแรก) แก้แล้วโดยรวมเป็น **1 rule-set ต่อ 1 from-zone** เสมอ (ไม่ใช่
# 1 ต่อ 1 entry แบบเดิม - ดู staticNatRuleSet() ฝั่ง frontend) แต่ละ entry เป็น
# แค่ "rule" แยกกันข้างในรุ่นเดียวกัน - ลบแค่ rule เดียวด้วย
# nc:operation="remove" ที่ระดับ rule ไม่ใช่ rule-set อีกต่อไป (ไม่กระทบ rule
# อื่นที่แชร์ rule-set/context เดียวกันอยู่) rule-set ที่เหลือว่างเปล่าหลังลบ
# rule สุดท้ายออกไปจะค้างอยู่แบบไม่มีอะไรข้างใน (ยืนยันแล้วว่าไม่ error แค่รก
# เปล่าๆ - เหมือนที่เคยเจอกับ policy-statement ว่างของ RIP) แต่จำเป็นต้องเก็บ
# ไว้เพื่อ "จอง" context ของ zone นั้นไว้ให้ entry ถัดไปใน zone เดียวกันใช้ต่อ
# caller สามารถแนบ Proxy ARP ที่ตรวจแล้วว่าไม่มี rule อื่นใช้เข้า payload เดียวกัน
# ได้ ส่วน port-forward ใช้ security/nat/destination แยกต่างหากด้านล่าง
@validate_call
def remove_static_nat(
    rule_set: str,
    rule_name: str,
    interface_type: str | None = None,
    interface_id: str | None = None,
    proxy_arp_address: str | None = None,
):
    rule_set = validate_object_ref(rule_set, "rule_set")
    rule_name = validate_object_ref(rule_name, "rule_name")
    proxy_arp_xml = _nat_proxy_arp_remove_xml(
        interface_type, interface_id, proxy_arp_address
    )
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <static>
      <rule-set>
        <name>{escape(rule_set)}</name>
        <rule xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(rule_name)}</name>
        </rule>
      </rule-set>
    </static>
{proxy_arp_xml}
  </nat>
</security>
    ''')


# เจอบั๊กจริง (2026-07-30 รอบ 4 - user ชี้): comment เดิมข้างบน (remove_static_nat)
# ที่บอกว่า rule-set ว่างเปล่าที่ค้างอยู่ "ไม่ error แค่รก" เป็นข้อสรุปที่ผิด - มัน
# ยัง**จอง context (from-zone) ไว้ถาวร**จริงๆ กันไม่ให้สร้าง rule-set ชื่ออื่นที่
# zone เดียวกันได้อีกเลย (ยืนยันจริง: user ลบ static NAT ตัวสุดท้ายใน "WEB-1"
# rule-set ออกจนหมด rule-set เปล่ากลายเป็น `rule-set WEB-1 { from zone WAN; }`
# ค้างอยู่ - พอจะสร้าง static NAT ใหม่ในชื่อ "STATIC-WAN" ที่ zone WAN เดียวกัน
# อุปกรณ์ปฏิเสธ "rule-set STATIC-WAN and rule-set WEB-1 have same context" ทั้งที่
# WEB-1 ไม่มี rule เหลืออยู่เลยสักตัว) - ต้องลบทั้ง rule-set (ไม่ใช่แค่ rule) เมื่อ
# rule ที่ลบเป็นตัวสุดท้ายในรุ่นนั้น เพื่อคืน context ให้ zone นั้นใช้ต่อได้ - แยก
# เป็นฟังก์ชันต่างหาก (ไม่รวมเข้า remove_static_nat) เพราะฝั่ง caller
# (natStatic.jsx) เป็นคนตัดสินใจว่าจะเรียกตัวไหน โดยเช็คจากตารางที่โหลดมาแล้วว่า
# entry นี้เป็น rule เดียวที่เหลือใน rule-set นั้นหรือไม่ (ดู isLastRuleInSet ใน
# staticNatRuleSet.js)
@validate_call
def remove_static_nat_ruleset(
    rule_set: str,
    interface_type: str | None = None,
    interface_id: str | None = None,
    proxy_arp_address: str | None = None,
):
    rule_set = validate_object_ref(rule_set, "rule_set")
    proxy_arp_xml = _nat_proxy_arp_remove_xml(
        interface_type, interface_id, proxy_arp_address
    )
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <static>
      <rule-set xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(rule_set)}</name>
      </rule-set>
    </static>
{proxy_arp_xml}
  </nat>
</security>
    ''')


# ลบ port-forward - ย้ายไปใช้ security/nat/destination แล้ว (ดู set_port_forward)
# ไม่ใช่ alias ของ remove_static_nat อีกต่อไป - ต้องลบทั้ง rule (ในรุ่นเดียวกับ
# entry อื่นที่ zone เดียวกันอาจแชร์อยู่ - ไม่ลบทั้ง rule-set) และ pool ที่ rule
# อ้างถึง ชื่อ pool ที่อ่านจากอุปกรณ์ถูกส่งมาตรงๆ เพื่อรองรับ brownfield config;
# fallback "<rule_name>-POOL" มีไว้เฉพาะ caller เก่าหรือ config ที่ระบบสร้างเอง
@validate_call
def remove_port_forward(
    rule_set: str,
    rule_name: str,
    pool_name: str | None = None,
    interface_type: str | None = None,
    interface_id: str | None = None,
    proxy_arp_address: str | None = None,
):
    rule_set = validate_object_ref(rule_set, "rule_set")
    rule_name = validate_object_ref(rule_name, "rule_name")
    pool_name = pool_name or f"{rule_name}-POOL"
    pool_name = validate_object_ref(pool_name, "pool_name")
    proxy_arp_xml = _nat_proxy_arp_remove_xml(
        interface_type, interface_id, proxy_arp_address
    )
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <destination>
      <pool xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(pool_name)}</name>
      </pool>
      <rule-set>
        <name>{escape(rule_set)}</name>
        <rule xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(rule_name)}</name>
        </rule>
      </rule-set>
    </destination>
{proxy_arp_xml}
  </nat>
</security>
    ''')


# คู่กับ remove_static_nat_ruleset - บั๊กเดียวกันเป๊ะ (rule-set เปล่าจอง context
# ค้างถาวร) เกิดกับ security/nat/destination ด้วย (ยืนยันแล้วว่ามี "same context"
# constraint เดียวกัน) ใช้ตอน rule ที่ลบเป็นตัวสุดท้ายในรุ่นนั้น - ต้องลบทั้ง pool
# (เหมือน remove_port_forward ปกติ) และทั้ง rule-set (ไม่ใช่แค่ rule)
@validate_call
def remove_port_forward_ruleset(
    rule_set: str,
    rule_name: str,
    pool_name: str | None = None,
    interface_type: str | None = None,
    interface_id: str | None = None,
    proxy_arp_address: str | None = None,
):
    rule_set = validate_object_ref(rule_set, "rule_set")
    rule_name = validate_object_ref(rule_name, "rule_name")
    pool_name = pool_name or f"{rule_name}-POOL"
    pool_name = validate_object_ref(pool_name, "pool_name")
    proxy_arp_xml = _nat_proxy_arp_remove_xml(
        interface_type, interface_id, proxy_arp_address
    )
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <nat>
    <destination>
      <pool xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(pool_name)}</name>
      </pool>
      <rule-set xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(rule_set)}</name>
      </rule-set>
    </destination>
{proxy_arp_xml}
  </nat>
</security>
    ''')


# Global address book (แยกจาก per-zone address-book ที่ security-zone-type
# grouping มีในตัวเอง) - security/address-book เป็น list keyed by name แต่ใน
# ทางปฏิบัติ Junos ใช้ชื่อ "global" เสมอสำหรับ address book ที่มองเห็นได้จากทุก
# zone (ยืนยัน path จริงผ่าน CLI: `set security address-book global address
# <name> <ip/prefix>` -> commit -> `show configuration security address-book`
# คืน `global { address <name> <ip/prefix>; }` ตรงกับ named-address-book-type
# grouping ใน junos-es-conf-security.yang:1733/20556 - "global" คือค่าของ
# leaf "name" ของ list address-book ไม่ใช่ container พิเศษ) รับ address เปล่า
# แบบไม่มี prefix ได้ แต่ normalize เป็น /32 หรือ /128 ที่ backend ให้ชัดเจนก่อน
# เขียน เพื่อให้ payload และค่าที่อุปกรณ์อ่านกลับใช้ representation เดียวกัน
@validate_call
def set_address_book_entry(
    name: str,
    address: str,
    replace_name: str | None = None,
):
    if replace_name is None:
        name = validate_config_name(name, "Address Book entry name")
        operation = "create"
    else:
        name = validate_object_ref(name, "Address Book entry name")
        replace_name = validate_object_ref(replace_name, "Previous Address Book entry name")
        if replace_name != name:
            raise ValueError("Address Book entry name cannot be changed during edit")
        operation = "merge"
    try:
        address = str(ipaddress.ip_network(address.strip(), strict=False))
    except ValueError as exc:
        raise ValueError(
            "Address Book address must be a valid IPv4 or IPv6 address/prefix"
        ) from exc
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <address-book>
    <name>global</name>
    <address xmlns:nc="{NS_RPC}" nc:operation="{operation}">
      <name>{escape(name)}</name>
      <ip-prefix>{escape(address)}</ip-prefix>
    </address>
  </address-book>
</security>
    ''')

@validate_call
def remove_address_book_entry(name: str):
    # Delete อ้าง key ที่อ่านมาจากอุปกรณ์ จึงต้องยอมรับชื่อ brownfield แต่ยัง
    # ปฏิเสธค่าว่าง อักขระควบคุม และอักขระที่ทำให้ XML/reference ไม่ปลอดภัย
    name = validate_object_ref(name, "Address Book entry name")
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <address-book>
    <name>global</name>
    <address xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(name)}</name>
    </address>
  </address-book>
</security>
    ''')


# อ่าน global address book กลับมา - path ตรงกับที่ set_address_book_entry เขียน
def get_address_book_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <address-book/>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')

@validate_call
def set_security_zone(
    zone_name: str,
    allowed_protocols: list[str] | None = None,
    allowed_services: list[str] | None = None,
):
    protocols_xml = "\n".join(
        f"<protocols><name>{escape(p)}</name></protocols>" for p in (allowed_protocols or [])
    )
    services_xml = "\n".join(
        f"<system-services><name>{escape(s)}</name></system-services>" for s in (allowed_services or [])
    )
    host_inbound_xml = ""
    if protocols_xml or services_xml:
        host_inbound_xml = f"<host-inbound-traffic>{services_xml}{protocols_xml}</host-inbound-traffic>"

    return _edit_configuration(f'''
      <security xmlns="{NS_SECURITY}">
        <zones>
          <security-zone>
            <name>{escape(zone_name)}</name>
            {host_inbound_xml}
          </security-zone>
        </zones>
      </security>
    ''')

@validate_call
def remove_security_zone(
    zone_name: str,
    reference_config: str | None = None,
):
    zone_name = validate_object_ref(zone_name, "zone_name")
    if reference_config:
        try:
            root = safe_fromstring(reference_config)
        except ET.ParseError as exc:
            raise ValueError("ZONE_REFERENCE_CONFIG_INVALID: Could not parse the current device configuration") from exc

        def local(element):
            return element.tag.rsplit("}", 1)[-1]

        def children(element, name):
            return [item for item in list(element) if local(item) == name] if element is not None else []

        def child(element, name):
            return next(iter(children(element, name)), None)

        def text(element, name):
            node = child(element, name)
            return (node.text or "").strip() if node is not None else ""

        if any(local(node) == "rpc-error" for node in root.iter()):
            raise ValueError("ZONE_REFERENCE_CONFIG_INVALID: The device rejected the running configuration read")
        configuration = next((node for node in root.iter() if local(node) == "configuration"), None)
        security = child(configuration, "security")
        if security is None:
            raise ValueError("ZONE_REFERENCE_CONFIG_INVALID: The running configuration has no security hierarchy")
        zones = child(security, "zones")
        zone_exists = any(text(zone, "name") == zone_name for zone in children(zones, "security-zone"))
        if not zone_exists:
            raise ValueError(f"ZONE_NOT_FOUND: Zone '{zone_name}' does not exist on the device")

        # A policy pair is keyed by both zones.  If either key references the
        # deleted zone the complete pair must go; leaving even an empty pair
        # makes Junos require the missing zone during commit.
        policy_pair_xml = []
        global_policy_xml = []
        policies = child(security, "policies")
        for pair in children(policies, "policy"):
            from_zone = text(pair, "from-zone-name")
            to_zone = text(pair, "to-zone-name")
            if zone_name in (from_zone, to_zone):
                policy_pair_xml.append(f'''<policy xmlns:nc="{NS_RPC}" nc:operation="remove">
          <from-zone-name>{escape(from_zone)}</from-zone-name>
          <to-zone-name>{escape(to_zone)}</to-zone-name>
        </policy>''')
        global_node = child(policies, "global")
        for policy in children(global_node, "policy"):
            match = child(policy, "match")
            referenced = {
                (node.text or "").strip()
                for key in ("from-zone", "to-zone")
                for node in children(match, key)
            }
            if zone_name in referenced and text(policy, "name"):
                global_policy_xml.append(f'''<policy xmlns:nc="{NS_RPC}" nc:operation="remove">
            <name>{escape(text(policy, "name"))}</name>
          </policy>''')

        # NAT rule-set context can contain one or several zone keys.  Remove
        # only the matching key when other zones remain; remove the whole
        # rule-set when deleting the key would leave an invalid empty context.
        nat_xml_by_family = {}
        nat = child(security, "nat")
        for family_name in ("source", "static", "destination"):
            family = child(nat, family_name)
            fragments = []
            for rule_set in children(family, "rule-set"):
                rule_set_name = text(rule_set, "name")
                if not rule_set_name:
                    continue
                from_node = child(rule_set, "from")
                to_node = child(rule_set, "to")
                from_zones = [text(node, "name") or (node.text or "").strip() for node in children(from_node, "zone")]
                to_zones = [text(node, "name") or (node.text or "").strip() for node in children(to_node, "zone")]
                from_hit = zone_name in from_zones
                to_hit = zone_name in to_zones
                if not from_hit and not to_hit:
                    continue
                if (from_hit and len(from_zones) == 1) or (to_hit and len(to_zones) == 1):
                    fragments.append(f'''<rule-set xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(rule_set_name)}</name>
        </rule-set>''')
                    continue
                from_remove = (f'''<from><zone xmlns:nc="{NS_RPC}" nc:operation="remove">{escape(zone_name)}</zone></from>'''
                               if from_hit else "")
                to_remove = (f'''<to><zone xmlns:nc="{NS_RPC}" nc:operation="remove">{escape(zone_name)}</zone></to>'''
                             if to_hit else "")
                fragments.append(f'''<rule-set>
          <name>{escape(rule_set_name)}</name>{from_remove}{to_remove}
        </rule-set>''')
            if fragments:
                nat_xml_by_family[family_name] = "".join(fragments)

        # Per-zone address-book attachments are references too.  Preserve the
        # address book and remove only its attachment to the deleted zone.
        address_book_xml = []
        for book in children(security, "address-book"):
            book_name = text(book, "name")
            attach = child(book, "attach")
            attached_zones = [((node.text or "").strip()) for node in children(attach, "zone")]
            if book_name and zone_name in attached_zones:
                address_book_xml.append(f'''<address-book>
        <name>{escape(book_name)}</name>
        <attach><zone xmlns:nc="{NS_RPC}" nc:operation="remove">{escape(zone_name)}</zone></attach>
      </address-book>''')

        policies_xml = ""
        if policy_pair_xml or global_policy_xml:
            global_xml = f"<global>{''.join(global_policy_xml)}</global>" if global_policy_xml else ""
            policies_xml = f"<policies>{''.join(policy_pair_xml)}{global_xml}</policies>"
        nat_xml = ""
        if nat_xml_by_family:
            nat_xml = "<nat>" + "".join(
                f"<{family}>{fragments}</{family}>"
                for family, fragments in nat_xml_by_family.items()
            ) + "</nat>"

        return _edit_configuration(f'''
      <security xmlns="{NS_SECURITY}">
        {policies_xml}{nat_xml}{''.join(address_book_xml)}
        <zones>
          <security-zone xmlns:nc="{NS_RPC}" nc:operation="remove">
            <name>{escape(zone_name)}</name>
          </security-zone>
        </zones>
      </security>
    ''')

    return _edit_configuration(f'''
      <security xmlns="{NS_SECURITY}">
        <zones>
          <security-zone xmlns:nc="{NS_RPC}" nc:operation="remove">
            <name>{escape(zone_name)}</name>
          </security-zone>
        </zones>
      </security>
    ''')

# host-inbound-traffic/system-services เป็น NETCONF leaf-list เดียวกับที่เจอ
# ปัญหา merge-only มาแล้วหลายจุดในแอปนี้ (DHCP pool gateway/dns, IKE gateway
# address ฯลฯ) - set_security_zone มีแต่ "เพิ่ม" (merge) ไม่มีทาง "ถอด" ทีละตัว
# ได้เลย ทำให้ฟอร์ม Edit เดิมไม่กล้า pre-check ค่าที่ตั้งไว้แล้ว (เกรงว่า uncheck
# แล้วจะดูเหมือนลบได้ทั้งที่ไม่ได้ลบจริง) - user ชี้ตรงๆ ว่าต้องดึงค่าปัจจุบันมา
# ใส่ฟอร์มให้แก้ไขได้จริง ไม่ใช่แค่โชว์เฉยๆ เลยเพิ่มฟังก์ชันถอดทีละ
# service/protocol คู่กับ set_security_zone (เหมือน apply_zone_member/
# remove_zone_member ที่มีอยู่แล้วสำหรับ interfaces) ให้ frontend diff
# เก่า-ใหม่แล้วเรียก add/remove ตรงตามจริงได้
@validate_call
def remove_security_zone_service(zone_name: str, service: str):
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <zones>
    <security-zone>
      <name>{escape(zone_name)}</name>
      <host-inbound-traffic>
        <system-services xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(service)}</name>
        </system-services>
      </host-inbound-traffic>
    </security-zone>
  </zones>
</security>
    ''')

@validate_call
def remove_security_zone_protocol(zone_name: str, protocol: str):
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <zones>
    <security-zone>
      <name>{escape(zone_name)}</name>
      <host-inbound-traffic>
        <protocols xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(protocol)}</name>
        </protocols>
      </host-inbound-traffic>
    </security-zone>
  </zones>
</security>
    ''')


# เจอจริงบน zone "WAN" ของแล็บนี้: host-inbound-traffic ถูกตั้งไว้ระดับ
# per-interface (security-zone/interfaces/<name>/host-inbound-traffic) ไม่ใช่
# ระดับ zone (sibling ของ "interfaces" ที่ set_security_zone/
# remove_security_zone_service เขียน/ลบ) - เป็น config style ที่ตั้งมาด้วยมือ
# ก่อนหน้านี้ (ไม่ผ่านแอป) ยืนยันจริงว่า remove_security_zone_service ที่ระดับ
# zone กับ service ที่อยู่ระดับ interface แบบนี้ "สำเร็จ" เงียบๆ (ok:true, commit
# ผ่าน) แต่ไม่ได้ลบอะไรออกจริงเลย (ยืนยันด้วย show config หลังเรียก) เพราะไม่มี
# node ตรงกับ path ที่ remove กำหนดไว้ - เลยต้องมีฟังก์ชันลบระดับ interface แยก
# ต่างหากคู่กับของระดับ zone เพื่อให้ฟอร์ม edit ที่ diff จากค่าที่ merge มาจากทั้ง
# 2 ระดับ (ดู parseJuniperZones ฝั่ง frontend) ลบได้ตรงตามที่อยู่จริงบนอุปกรณ์
@validate_call
def remove_zone_interface_service(interface_type: str, interface_id: str, zone_name: str, service: str):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <zones>
    <security-zone>
      <name>{escape(zone_name)}</name>
      <interfaces>
        <name>{interface}</name>
        <host-inbound-traffic>
          <system-services xmlns:nc="{NS_RPC}" nc:operation="remove">
            <name>{escape(service)}</name>
          </system-services>
        </host-inbound-traffic>
      </interfaces>
    </security-zone>
  </zones>
</security>
    ''')

@validate_call
def remove_zone_interface_protocol(interface_type: str, interface_id: str, zone_name: str, protocol: str):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <zones>
    <security-zone>
      <name>{escape(zone_name)}</name>
      <interfaces>
        <name>{interface}</name>
        <host-inbound-traffic>
          <protocols xmlns:nc="{NS_RPC}" nc:operation="remove">
            <name>{escape(protocol)}</name>
          </protocols>
        </host-inbound-traffic>
      </interfaces>
    </security-zone>
  </zones>
</security>
    ''')

@validate_call
def apply_zone_member(interface_type: str, interface_id: str, zone_name: str):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <zones>
    <security-zone>
      <name>{escape(zone_name)}</name>
      <interfaces>
        <name>{interface}</name>
      </interfaces>
    </security-zone>
  </zones>
</security>
    ''')

@validate_call
def remove_zone_member(interface_type: str, interface_id: str, zone_name: str):
    # ต้องเรียกก่อนย้าย interface ไป zone อื่นเสมอ — Junos ไม่ยอมให้ interface เดียว
    # อยู่ 2 zone พร้อมกัน (ยืนยันจริง: "Interface X already assigned to another zone")
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <zones>
    <security-zone>
      <name>{escape(zone_name)}</name>
      <interfaces xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{interface}</name>
      </interfaces>
    </security-zone>
  </zones>
</security>
    ''')

@validate_call
def set_inspect_class_map(
    from_zone: str,
    to_zone: str,
    policy_name: str,
    source_address: str = "any",
    destination_address: str = "any",
    application: str = "any",
):
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <policies>
    <policy>
      <from-zone-name>{escape(from_zone)}</from-zone-name>
      <to-zone-name>{escape(to_zone)}</to-zone-name>
      <policy>
        <name>{escape(policy_name)}</name>
        <match>
          <source-address>{escape(source_address)}</source-address>
          <destination-address>{escape(destination_address)}</destination-address>
          <application>{escape(application)}</application>
        </match>
      </policy>
    </policy>
  </policies>
</security>
    ''')


@validate_call
def set_inspect_policy_map(
    from_zone: str,
    to_zone: str,
    policy_name: str,
    action: Literal["permit", "deny", "reject"],
    log: bool = False,
):
    action_xml = f"<{action}/>"
    log_xml = "<log><session-init/></log>" if log else ""
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <policies>
    <policy>
      <from-zone-name>{escape(from_zone)}</from-zone-name>
      <to-zone-name>{escape(to_zone)}</to-zone-name>
      <policy>
        <name>{escape(policy_name)}</name>
        <then>
          {action_xml}
          {log_xml}
        </then>
      </policy>
    </policy>
  </policies>
</security>
    ''')

@validate_call
def set_zone_pair(
    from_zone: str,
    to_zone: str,
    policy_name: str,
    description: str | None = None,
):
    description_xml = f"<description>{escape(description)}</description>" if description else ""
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <policies>
    <policy>
      <from-zone-name>{escape(from_zone)}</from-zone-name>
      <to-zone-name>{escape(to_zone)}</to-zone-name>
      <policy>
        <name>{escape(policy_name)}</name>
        {description_xml}
      </policy>
    </policy>
  </policies>
</security>
    ''')

# อ่าน DNS config กลับมา - path ตรงกับที่ set_dns_config เขียน (system/domain-name,
# system/name-server) พ่วง system/services/dns มาด้วย (DNS Server/Relay/lookup ip
# ทั้ง 3 ฟีเจอร์ - forwarders/dns-proxy's interface+cache) ในคำสั่งเดียวให้หน้า
# DNS โชว์ได้ครบไม่ต้อง query เพิ่ม
def get_dns_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <system xmlns="{NS_SYSTEM}">
        <domain-name/>
        <name-server/>
        <services>
          <dns/>
        </services>
      </system>
    </configuration>
  </filter>
</get-config>
    ''')


@validate_call
def set_dns_config(
    domain_lookup: bool = True,
    dns_server: bool = False,
    domain_name: str | None = None,
    name_servers: list[str] | None = None,
    previous_name_servers: list[str] | None = None,
    previous_forwarders: list[str] | None = None,
) -> str:
    # Junos ไม่มี toggle "ip domain-lookup"/"ip dns server" แยกแบบ Cisco -
    # hostname resolution ทำงานอัตโนมัติถ้ามี name-server ตั้งไว้ ไม่มี concept
    # "ปิด lookup แต่ยังมี name-server อยู่" หรือ "เปิด dns server โดยไม่ผูกกับ
    # name-server" เลย - รับ 2 flag นี้ไว้เฉยๆ ไม่แปลงเป็น XML (ไม่ raise เพราะ
    # ไม่ใช่ความขัดแย้งที่ทำไม่ได้จริงแบบ RIP auto-summary แค่ไม่มี toggle แยกให้)
    # Snapshot ทั้งสองรายการเปิด composite mode สำหรับหน้า Network > DNS:
    # ลบเฉพาะ key ที่ไม่ต้องการ และ merge key ใหม่ใน candidate edit-config เดียว
    # จากนั้น socket layer commit ครั้งเดียว (หรือ discard เมื่อเกิด error)
    # ไม่ replace parent เพื่อรักษา config DNS proxy/interface ที่ไม่เกี่ยวข้อง
    # Caller เดิมที่ไม่ส่ง snapshot ยังคงได้พฤติกรรม merge name-server เท่านั้น
    composite = previous_name_servers is not None or previous_forwarders is not None
    if composite and (previous_name_servers is None or previous_forwarders is None):
        raise ValueError("previous_name_servers and previous_forwarders must be supplied together")
    # (bug 12 - ส่วนที่ตกไป) ใช้นโยบายกลางตัวเดียวกับ cisco และกับ CLI generator
    if domain_name:
        domain_name = validate_domain_name(domain_name, "domain_name")
    # ช่อง Domain Name ว่าง = ลบชื่อเดิม (เดิมไม่ส่งอะไรเลย ชื่อเดิมค้างหลัง Apply) - remove
    # เป็น no-op ถ้าไม่มีอยู่แล้ว · ผู้เรียกมีหน้า DNS ที่เดียวซึ่งส่งค่าทั้งฟอร์มเสมอ
    domain_xml = (
        f"<domain-name>{escape(domain_name)}</domain-name>" if domain_name
        else f'<domain-name xmlns:nc="{NS_RPC}" nc:operation="remove"/>'
    )

    # Validate ทุกค่าให้ครบก่อนคืน payload เพื่อไม่ให้ลบของเดิมก่อนพบ IP ผิด
    servers = list(dict.fromkeys(str(ipaddress.IPv4Address(server)) for server in (name_servers or [])))
    old_servers = list(dict.fromkeys(str(ipaddress.IPv4Address(server)) for server in (previous_name_servers or [])))
    old_forwarders = list(dict.fromkeys(str(ipaddress.IPv4Address(server)) for server in (previous_forwarders or [])))
    ns_xml = "\n".join(
        f"<name-server><name>{server}</name></name-server>"
        for server in servers
    )
    removed_ns_xml = "\n".join(
        f'<name-server xmlns:nc="{NS_RPC}" nc:operation="remove"><name>{server}</name></name-server>'
        for server in old_servers if server not in servers
    )
    relay_xml = ""
    if composite:
        forwarders_xml = "\n".join(
            f'<forwarders xmlns:nc="{NS_RPC}" nc:operation="remove"><name>{server}</name></forwarders>'
            for server in old_forwarders if server not in servers
        )
        forwarders_xml += "\n" + "\n".join(
            f"<forwarders><name>{server}</name></forwarders>" for server in servers
        )
        # ไม่สร้าง services/dns เปล่าเมื่อไม่มีรายการให้แก้
        if forwarders_xml.strip():
            relay_xml = f"<services><dns>{forwarders_xml}</dns></services>"

    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  {domain_xml}
  {removed_ns_xml}
  {ns_xml}
  {relay_xml}
</system>
    ''')


# ลบ name-server (ตัวที่ firewall ใช้ resolve เอง - system/name-server) ทีละตัว
# ด้วยค่า IP จริง สำหรับ caller ที่ต้องการลบรายการเดียว
# หน้า Network > DNS ใช้ composite set_dns_config แทนการเรียกแยกแล้ว
@validate_call
def remove_dns_name_server(ip: str):
    address = ipaddress.IPv4Address(ip)
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <name-server xmlns:nc="{NS_RPC}" nc:operation="remove">
    <name>{address}</name>
  </name-server>
</system>
    ''')


# หน้า zoneInterfaces.jsx (แท็บ "Zone Interfaces") อ่านเฉพาะ zones กลับมา (ไม่
# เอา policies มาด้วยแบบ get_firewall_information - ไม่เกี่ยวกับหน้านี้) path
# ตรงกับที่ set_security_zone/apply_zone_member เขียน (security/zones/
# security-zone: name, interfaces (list), host-inbound-traffic/system-services
# + protocols - ยืนยันจริงผ่าน CLI 2026-07-28: host-inbound-traffic ที่
# set_security_zone เขียนอยู่ระดับ zone ตรงๆ เป็น sibling ของ "interfaces" ไม่ใช่
# ซ้อนอยู่ใต้ interfaces แต่ละตัว - ต่างจาก legacy per-interface
# host-inbound-traffic ที่อาจเจอบนอุปกรณ์จริงที่ตั้งมาด้วยมือ (เช่น zone "WAN"
# ตัวอย่างบนแล็บนี้) ซึ่งหน้านี้จะไม่โชว์ services/protocols ให้ (แสดงแค่ที่
# app นี้เขียนเองเท่านั้น ไม่ใช่ bug - เป็น scope ที่ตั้งใจไว้)
def get_security_zone_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <zones/>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')


# อ่าน security policy กลับมา - path ตรงกับที่ set_security_zone/set_zone_pair
# เขียน (security/zones, security/policies)
def get_firewall_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <zones/>
        <policies/>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')


# Cisco's get_security_status อ่าน oper hit-count จริง (ACL match-counter +
# ZBF pkts-counter จาก oper module คนละตัวกับ config) - Junos มี RPC
# operational แยกสำหรับสถิติ policy (get-security-policies-information พร้อม
# <statistics/>) แต่ยังไม่เคยตรวจสอบ schema/verify กับอุปกรณ์จริงว่า path/leaf
# ตรงกับที่คาดหรือไม่ - ตอนนี้คืนแค่ config view เดียวกับ get_firewall_information
# ไปก่อน (ไม่มี hit count จริง) ดีกว่าให้ error หรือเดา RPC ที่ไม่มั่นใจ
def get_security_status():
    return get_firewall_information()


@validate_call
def create_firewall_policy(
    name: str,
    source_zone: str,
    destination_zone: str,
    action: Literal["inspect", "pass", "drop"] = "inspect",
    source_members: list[str] | None = None,
    destination_members: list[str] | None = None,
    source_scopes: str | list[str] = "any",
    log: bool = False,
) -> str:
    # รวม primitive ที่มีอยู่แล้วในไฟล์นี้ (set_security_zone/apply_zone_member/
    # set_inspect_policy_map ผ่าน security/policies) เข้า edit-config เดียว
    # ให้ signature ตรงกับ Cisco's create_firewall_policy เป๊ะ - แปลง action:
    # Cisco inspect/pass/drop -> Junos permit/deny (Junos policy เป็น stateful
    # โดย default อยู่แล้วไม่มี "inspect" แยกจาก "permit" เหมือน Cisco - ทั้ง
    # inspect และ pass จึง map ไป permit เหมือนกัน, drop -> deny)
    action_map = {"inspect": "permit", "pass": "permit", "drop": "deny"}
    junos_action = action_map[action]
    action_xml = f"<{junos_action}/>"
    log_xml = "<log><session-init/><session-close/></log>" if log else ""

    member_blocks = []
    for iface_full in (source_members or []):
        member_blocks.append((iface_full, source_zone))
    for iface_full in (destination_members or []):
        member_blocks.append((iface_full, destination_zone))
    interfaces_xml_by_zone: dict[str, list[str]] = {}
    for iface_full, zone in member_blocks:
        interfaces_xml_by_zone.setdefault(zone, []).append(
            f"<interfaces><name>{escape(iface_full)}</name></interfaces>"
        )

    def zone_block(zone_name: str) -> str:
        members_xml = "".join(interfaces_xml_by_zone.get(zone_name, []))
        return f'''
    <security-zone>
      <name>{escape(zone_name)}</name>
      {members_xml}
    </security-zone>'''

    scopes = [source_scopes] if isinstance(source_scopes, str) else source_scopes
    scopes = [s.strip() for s in scopes if s and s.strip()]
    if not scopes:
        scopes = ["any"]
    # Junos policy match source-address ต้องอ้าง address-book entry ที่มีอยู่แล้ว
    # หรือคำว่า "any" ตรงๆ (ไม่รับ raw CIDR ตรงๆ แบบ Cisco ACL) - ใช้ "any" เสมอ
    # ถ้า scope ไม่ใช่ "any" ทั้งหมด (ยังไม่รองรับสร้าง address-book entry ให้ใน
    # ฟังก์ชันนี้ - จำกัดขอบเขตไว้ก่อน ต้องขยายทีหลังถ้าต้องการ scope เฉพาะเจาะจง)
    source_address_xml = "<source-address>any</source-address>"
    if len(scopes) == 1 and scopes[0].lower() == "any":
        source_address_xml = "<source-address>any</source-address>"

    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <zones>
    {zone_block(source_zone)}
    {zone_block(destination_zone)}
  </zones>
  <policies>
    <policy>
      <from-zone-name>{escape(source_zone)}</from-zone-name>
      <to-zone-name>{escape(destination_zone)}</to-zone-name>
      <policy>
        <name>{escape(name)}</name>
        <match>
          {source_address_xml}
          <destination-address>any</destination-address>
          <application>any</application>
        </match>
        <then>
          {action_xml}
          {log_xml}
        </then>
      </policy>
    </policy>
  </policies>
</security>
    ''')


# หน้า stateful.jsx เวอร์ชัน Juniper (rework 2026-07-28) - user ขอให้แยกจาก
# create_firewall_policy เดิม (bundle zone creation + membership ไว้ในตัวเดียว
# เกินไป, ไม่รองรับ application match เลย, destination-address hardcode "any"
# เสมอ) เพราะตอนนี้ zone/interface membership จัดการแยกที่หน้า Zone Interfaces
# แล้ว (set_security_zone/apply_zone_member) หน้านี้จึงโฟกัสแค่ตัว policy
# (match source/destination-address + application, then permit/deny) ตรงกับ
# junos-es-conf-security.yang:21453 (policy_type grouping) - source-address/
# destination-address/application ทั้ง 3 เป็น**leaf-list ธรรมดา**ไม่ใช่ list ซ้อน
# obj แบบที่ ACL's source-address ใช้ (ยืนยันจาก schema + live commit จริง
# 2026-07-28: `<application>junos-http</application><application>junos-https</
# application>` เป็น sibling element ธรรมดา ไม่ต้องห่อ container เพิ่ม) -
# source_addresses รับได้หลายอันจริง (ยืนยันเพิ่มจาก commit check บนอุปกรณ์จริง
# 2026-07-29: `source-address [ A-ADDR B-ADDR ];` - additive กัน ไม่ใช่ AND -
# เดิมรับได้แค่ 1 ค่า) แต่ละอันต้องเป็น "any" หรือชื่อ address-book entry ที่มี
# อยู่แล้วเท่านั้น - Junos ปฏิเสธถ้าไม่มีจริงตอน commit, ไม่ validate ล่วงหน้าใน
# นี้ เหมือน pattern อื่นๆ ในไฟล์นี้ที่ปล่อยให้ device เป็นคน validate เอง -
# destination_addresses รับได้หลายอันแล้วเหมือน source_addresses (2026-07-30 -
# user ขอ) - ใช้ pattern เดียวกันเป๊ะ (leaf-list ธรรมดา additive กัน ยืนยันแล้ว
# จาก commit check ตอนแก้ source_addresses รอบก่อน ว่า Junos merge เป็น sibling
# element ธรรมดา ไม่ต้อง validate ล่วงหน้าเหมือนกัน - แต่ละอันต้องเป็น "any" หรือ
# ชื่อ address-book entry ที่มีอยู่แล้วเท่านั้น ปล่อยให้ device validate เอง)
@validate_call
def set_security_policy(
    from_zone: str,
    to_zone: str,
    policy_name: str,
    action: Literal["permit", "deny"],
    source_addresses: list[str] | None = None,
    destination_addresses: list[str] | None = None,
    applications: list[str] | None = None,
    replace_name: str | None = None,
    reference_config: str | None = None,
    expected_revision: str | None = None,
    revision: str | None = None,
    confirm_replace_existing: bool = False,
):
    if reference_config and (replace_name is not None or confirm_replace_existing):
        target_name = replace_name or policy_name
        return build_juniper_security_policy_edit_payload(
            reference_config=reference_config,
            from_zone=from_zone,
            to_zone=to_zone,
            policy_name=target_name,
            action=action,
            source_addresses=source_addresses,
            destination_addresses=destination_addresses,
            applications=applications,
            expected_revision=expected_revision or revision,
        )

    # replace ที่ policy ชั้นในเท่านั้น: ชั้นนอกเป็น container รวมทุก policy ของ zone pair
    # ห้าม replace ชั้นนอกเด็ดขาด เพราะจะล้าง default-permit และ policy อื่น
    replace_xml = (
        f" xmlns:nc=\"{NS_RPC}\" nc:operation=\"replace\""
        if (replace_name is not None or confirm_replace_existing)
        else ""
    )
    action_xml = "<permit/>" if action == "permit" else "<deny/>"
    source_addresses = [a for a in (source_addresses or ["any"]) if a] or ["any"]
    source_address_xml = "".join(
        f"<source-address>{escape(addr)}</source-address>" for addr in source_addresses
    )
    destination_addresses = [a for a in (destination_addresses or ["any"]) if a] or ["any"]
    destination_address_xml = "".join(
        f"<destination-address>{escape(addr)}</destination-address>" for addr in destination_addresses
    )
    application_xml = "".join(
        f"<application>{escape(app)}</application>" for app in (applications or ["any"])
    )

    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <policies>
    <policy>
      <from-zone-name>{escape(from_zone)}</from-zone-name>
      <to-zone-name>{escape(to_zone)}</to-zone-name>
      <policy{replace_xml}>
        <name>{escape(policy_name)}</name>
        <match>
          {source_address_xml}
          {destination_address_xml}
          {application_xml}
        </match>
        <then>
          {action_xml}
        </then>
      </policy>
    </policy>
  </policies>
</security>
    ''')


# ลบ policy เดียวออกจากคู่ from-zone/to-zone - key ของ policy list ชั้นในคือ
# "name" (from-zone-name/to-zone-name เป็นแค่ key ของ list ชั้นนอกที่ใช้หาตำแหน่ง
# ไม่ใช่สิ่งที่ถูกลบ) ยืนยันจริงผ่าน CLI ว่า `delete ... policy X` ลบแค่ policy
# X ตัวเดียว ไม่กระทบ policy อื่นในคู่ zone เดียวกัน (เช่น "default-permit" ที่มี
# มาก่อนตั้งแต่ต้น)
@validate_call
def remove_security_policy(
    from_zone: str,
    to_zone: str,
    policy_name: str,
    expected_revision: str | None = None,
    revision: str | None = None,
    reference_config: str | None = None,
):
    if reference_config:
        from vendor_translators.juniper_security_policy import (
            build_juniper_security_policy_remove_payload,
        )
        return build_juniper_security_policy_remove_payload(
            reference_config=reference_config,
            from_zone=from_zone,
            to_zone=to_zone,
            policy_name=policy_name,
            expected_revision=expected_revision or revision,
        )

    return _edit_configuration(f'''
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
    ''')


# เลื่อนลำดับ Policy ภายในคู่ Zone เดียวกัน - ต้องมี reference_config ที่ API อ่านสดภายใน
# DeviceLock เสมอ (Policy ข้างเคียงคำนวณจากลำดับจริงบนอุปกรณ์ ไม่ใช่ข้อมูลเก่าในหน้าเว็บ)
# เดิมมีทางหนีให้ส่ง before_policy/after_policy มาเองโดยไม่อ่าน config ซึ่งข้ามการตรวจ
# order revision ได้ จึงตัดออก - เรียกโดยไม่มี reference_config จะถูกปฏิเสธทุกกรณี
@validate_call
def move_security_policy(
    from_zone: str,
    to_zone: str,
    policy_name: str,
    direction: Literal["up", "down", "before", "after"] = "up",
    before_policy: str | None = None,
    after_policy: str | None = None,
    reference_config: str | None = None,
    expected_order_revision: str | None = None,
    expected_revision: str | None = None,
    revision: str | None = None,
) -> str:
    if not reference_config:
        raise ValueError(
            "POLICY_MOVE_REQUIRES_DEVICE_READ: Policy reordering requires reading latest order from device"
        )
    return _edit_configuration(juniper_security_policy_move_fragment(
        reference_config=reference_config,
        from_zone=from_zone,
        to_zone=to_zone,
        policy_name=policy_name,
        direction=direction,
        before_policy=before_policy,
        after_policy=after_policy,
        expected_order_revision=expected_order_revision or revision,
        expected_revision=expected_revision,
    ))


# ย้าย Policy ข้ามคู่ Zone (Edit ที่เปลี่ยน From/To Zone) - atomic เดียว (ลบต้นทาง+สร้าง
# ปลายทางใน edit-config/commit เดียวกัน) ต้องมี reference_config เสมอเหมือน
# move_security_policy (คำสั่งเลื่อนลำดับ) - ไม่มีทางหนีให้ frontend ส่ง before/after
# หรือข้าม reference_config มาเอง (บทเรียนเดียวกับปุ่มเลื่อนที่เคยพังเพราะข้ามการอ่าน
# config สด)
@validate_call
def move_security_policy_zone(
    from_zone: str,
    to_zone: str,
    policy_name: str,
    new_from_zone: str,
    new_to_zone: str,
    action: str,
    source_addresses: list[str] | None = None,
    destination_addresses: list[str] | None = None,
    applications: list[str] | None = None,
    reference_config: str | None = None,
    expected_revision: str | None = None,
) -> str:
    if not reference_config:
        raise ValueError(
            "POLICY_MOVE_REQUIRES_DEVICE_READ: Moving policy across zone pairs requires reading latest data from device"
        )
    return _edit_configuration(build_juniper_security_policy_zone_move_fragment(
        reference_config=reference_config,
        from_zone=from_zone,
        to_zone=to_zone,
        policy_name=policy_name,
        new_from_zone=new_from_zone,
        new_to_zone=new_to_zone,
        action=action,
        source_addresses=source_addresses,
        destination_addresses=destination_addresses,
        applications=applications,
        expected_revision=expected_revision,
    ))


# หน้า stateful.jsx อ่านเฉพาะ policies กลับมา (ไม่เอา zones มาด้วยแบบ
# get_firewall_information - ไม่เกี่ยวกับหน้านี้อีกต่อไปหลัง rework ตัดที่จัดการ
# zone/interface ออกไปหมดแล้ว) path ตรงกับที่ set_security_policy เขียน
def get_security_policy_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <policies/>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')


# เดิม set_dns_lookup ทำซ้ำกับ set_dns_config (ตั้ง name-server/domain-name
# เฉยๆ) แถมไม่เคยถูกเรียกจาก frontend จริงเลยสักที่ (dead code) - user ต้องการ
# "lookup ip" เป็นฟีเจอร์คนละแบบ: static hostname->IP entry (เหมือน hosts file
# เดี่ยว) ยืนยัน path จริงกับอุปกรณ์ผ่าน CLI `?` completion แบบ interactive
# (pexpect) เพราะ bundled YANG เขียน path ผิดไปนิดเดียว - ของจริงมี container
# "dns" คั่นกลางอีกชั้นที่ YANG ไม่ได้ระบุชัดตรงจุดที่อ่านตอนแรก:
# **system/services/dns/dns-proxy/cache** (ไม่ใช่ system/services/dns-proxy/
# cache ตรงๆ) - ยืนยันด้วย `set system services dns-proxy ?` โดนปฏิเสธ
# "syntax error" ตรงๆ บนอุปกรณ์จริง แต่ `set system services dns dns-proxy ?`
# ผ่านและเห็น cache/interface/default-domain/view ครบ เปลี่ยนความหมายฟังก์ชันนี้
# ให้ตรงกับที่ user ต้องการจริงแทน (ชื่อเดิม "lookup" สื่อความหมายตรงกับ static
# entry อยู่แล้วพอดี - ไม่ต้องเปลี่ยนชื่อฟังก์ชัน)
@validate_call
def set_dns_lookup(hostname: str, ip: str):
    ipaddress.IPv4Address(ip)
    if not 1 <= len(hostname) <= 253:
        raise ValueError("hostname must contain 1-253 characters")
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <services>
    <dns>
      <dns-proxy>
        <cache>
          <name>{escape(hostname)}</name>
          <inet>{ip}</inet>
        </cache>
      </dns-proxy>
    </dns>
  </services>
</system>
    ''')


@validate_call
def remove_dns_lookup(hostname: str):
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <services>
    <dns>
      <dns-proxy>
        <cache xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(hostname)}</name>
        </cache>
      </dns-proxy>
    </dns>
  </services>
</system>
    ''')


# DNS Server: เปิด dns-proxy ให้ interface ไหนรับ query จาก client ได้บ้าง (path
# จริง: system/services/dns/dns-proxy/interface - list ธรรมดา คีย์ด้วยชื่อ
# interface เต็มๆ ไม่มี double-nesting แบบที่เจอใน DHCP relay's server-group -
# ยืนยันจาก CLI ตรงๆ เหมือนกับ cache ด้านบน)
@validate_call
def set_dns_server_interface(interface_type: str, interface_id: str, unit: int = 0):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <services>
    <dns>
      <dns-proxy>
        <interface>
          <name>{interface}.{unit}</name>
        </interface>
      </dns-proxy>
    </dns>
  </services>
</system>
    ''')


@validate_call
def remove_dns_server_interface(interface_type: str, interface_id: str, unit: int = 0):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <services>
    <dns>
      <dns-proxy>
        <interface xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{interface}.{unit}</name>
        </interface>
      </dns-proxy>
    </dns>
  </services>
</system>
    ''')


# DNS Relay: forward query ไปหา DNS server ต้นทาง (เหมือน DHCP relay concept) -
# เดิมออกแบบผ่าน dns-proxy/default-domain/forwarders (รองรับ split-DNS ตามโดเมน)
# แต่เจอจาก CLI ว่ามีทางที่ง่ายกว่ามาก: **system/services/dns/forwarders** เป็น
# list แบนๆ ของ IP ตรงๆ ไม่ผ่าน dns-proxy เลย (ยืนยันจาก `set system services
# dns forwarders ?` -> "<forwarder> IP address" ตรงๆ) ไม่ต้องคิดเรื่อง domain
# splitting เลย ตรงกับที่ user ต้องการ (relay ทุก query ไป upstream เฉยๆ) และ
# เรียบง่ายกว่าของเดิมที่ออกแบบไว้เยอะ - เปลี่ยนมาใช้ path นี้แทน
@validate_call
def set_dns_relay_forwarder(server_ip: str):
    ipaddress.IPv4Address(server_ip)
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <services>
    <dns>
      <forwarders>
        <name>{server_ip}</name>
      </forwarders>
    </dns>
  </services>
</system>
    ''')


@validate_call
def remove_dns_relay_forwarder(server_ip: str):
    ipaddress.IPv4Address(server_ip)
    return _edit_configuration(f'''
<system xmlns="{NS_SYSTEM}">
  <services>
    <dns>
      <forwarders xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{server_ip}</name>
      </forwarders>
    </dns>
  </services>
</system>
    ''')


@validate_call
def apply_switchport(
    interface_type: str,
    interface_id: str,
    mode: Literal["access", "trunk"],
    vlan_members: list[str] | str,
    unit: int = 0,
    description: str | None = None,
):
    interface = _interface_name(interface_type, interface_id)
    members = [vlan_members] if isinstance(vlan_members, str) else vlan_members
    if not members:
        raise ValueError("vlan_members must contain at least one VLAN name/id")
    members_xml = "\n".join(f"<members>{escape(m)}</members>" for m in dict.fromkeys(members))

    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <unit>
      <name>{unit}</name>
      {_description_xml(description)}
      <family>
        <inet xmlns:nc="{NS_RPC}" nc:operation="remove"/>
        <ethernet-switching>
          <interface-mode>{mode}</interface-mode>
          <vlan xmlns:nc="{NS_RPC}" nc:operation="replace">
            {members_xml}
          </vlan>
        </ethernet-switching>
      </family>
    </unit>
  </interface>
</interfaces>
    ''')

@validate_call
def remove_switchport(interface_type: str, interface_id: str, unit: int = 0):
    interface = _interface_name(interface_type, interface_id)
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <unit>
      <name>{unit}</name>
      <family>
        <ethernet-switching xmlns:nc="{NS_RPC}" nc:operation="remove"/>
      </family>
    </unit>
  </interface>
</interfaces>
    ''')

# หมายเหตุ: ไม่มี set_ip_routing() สำหรับ Junos โดยตั้งใจ — Junos ไม่มี global toggle
# แบบ Cisco "ip routing"/"no ip routing" เลย (routing เปิดอยู่ในตัวเสมอ, L3 forwarding
# เกิดจากการ config "family inet" บน unit ตรงๆ ไม่ต้องเปิด/ปิดระดับ global ก่อน)


# ---------- VPN (IKE/IPsec security profile) ----------
# ตาราง map ค่า enum ของ Cisco -> ชื่อ algorithm จริงใน junos-es-conf-security.yang
# (grouping ike-proposal บรรทัด ~25951, grouping ipsec-proposal บรรทัด ~26320)
_IKEV2_ENCRYPTION_MAP = {
    "en-3des": "3des-cbc",
    "aes-cbc-128": "aes-128-cbc",
    "aes-cbc-192": "aes-192-cbc",
    "aes-cbc-256": "aes-256-cbc",
    "aes-gcm-128": "aes-128-gcm",
    "aes-gcm-256": "aes-256-gcm",
    "des": "des-cbc",
}
_IKEV2_INTEGRITY_MAP = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha-256",
    "sha384": "sha-384",
    "sha512": "sha-512",
}
_IKEV2_GROUP_MAP = {
    "one": "group1", "two": "group2", "five": "group5", "fourteen": "group14",
    "fifteen": "group15", "sixteen": "group16", "nineteen": "group19",
    "twenty": "group20", "twenty-one": "group21", "twenty-four": "group24",
}
_IPSEC_INTEGRITY_MAP = {
    "esp-md5-hmac": "hmac-md5-96",
    "esp-sha-hmac": "hmac-sha1-96",
    "esp-sha256-hmac": "hmac-sha-256-128",
    "esp-sha384-hmac": "hmac-sha-384",
    "esp-sha512-hmac": "hmac-sha-512",
}
_IPSEC_FIXED_ENCRYPTION_MAP = {
    "esp-3des": "3des-cbc",
    "esp-des": "des-cbc",
    "esp-192-aes": "aes-192-cbc",
    "esp-256-aes": "aes-256-cbc",
}
_IPSEC_KEYED_ENCRYPTION_MAP = {
    ("esp-aes", "128"): "aes-128-cbc",
    ("esp-aes", "192"): "aes-192-cbc",
    ("esp-aes", "256"): "aes-256-cbc",
    ("esp-gcm", "128"): "aes-128-gcm",
    ("esp-gcm", "192"): "aes-192-gcm",
    ("esp-gcm", "256"): "aes-256-gcm",
}
# esp-gmac/esp-null/esp-seal ไม่มี encryption-algorithm ที่มั่นใจว่าตรงกันใน
# ipsec-proposal ของ junos-es-conf-security.yang - raise ValueError แทนการเดา
_IPSEC_UNSUPPORTED_ESP = {"esp-gmac", "esp-null", "esp-seal"}
# (bug 90) AES-GCM เป็น combined-mode cipher ที่มี authentication อยู่ในตัวแล้ว Junos จึง
# ห้ามตั้ง authentication-algorithm คู่กัน - อุปกรณ์ตอบตรง ๆ ว่า "When using aes-gcm for
# Encryption the Authentication Algorithm must not be set" (เจอจริงจากผลทดสอบผู้ใช้)
# กฎเดียวกับที่ฝั่ง ipsec proposal จัดการอยู่แล้วผ่าน esp-gcm แต่ฝั่ง ike ตกไป
# ต่างจาก Cisco ตรงที่ Junos ไม่มี prf ให้ใส่แทน - ตัด authentication-algorithm ทิ้งอย่างเดียว
_IKEV2_COMBINED_MODE_ENCRYPTION = {"aes-gcm-128", "aes-gcm-256"}


# (bug 89) ตัวเลือกด้านล่างจำกัดไว้เท่าที่ **vSRX รับจริง** ไม่ใช่เท่าที่ YANG ประกาศ
# ที่มา: ผู้ใช้กด "?" บนอุปกรณ์จริง (6 ก.ย. 2026)
#   security ike proposal authentication-algorithm  -> md5, sha1, sha-256, sha-384 (ไม่มี sha-512)
#   security ike proposal dh-group                  -> group1/2/5/14/19/20/24      (ไม่มี 15/16/21)
#   security ipsec proposal authentication-algorithm-> hmac-md5-96, hmac-sha1-96,
#                                                      hmac-sha-256-128            (ไม่มี 384/512)
#   perfect-forward-secrecy keys                    -> เหมือน dh-group
#
# **junos-es-conf-security.yang ประกาศค่าพวกนี้ไว้ครบ แต่ vSRX ไม่รับ** - YANG เป็น schema
# รวมของ SRX ทั้ง family ตอนไล่ bug 71 เคยตรวจ YANG แล้วสรุปว่าค่าที่ map ถูกทุกตัว
# ซึ่งตรวจถูกแต่สรุปผิด **YANG พิสูจน์ได้แค่ว่าชื่อถูก ไม่ได้พิสูจน์ว่ารุ่นนี้รองรับ**
#
# group15/16 อันตรายที่สุด - commit ผ่านแต่อุปกรณ์ขึ้น "Warning: statement ignored:
# unsupported platform (vsrx)" คือค่าไม่ถูกใช้จริงโดยไม่มีอะไรเตือนผู้ใช้เลย
@validate_call
def create_security_profile(
    name: str,
    peer_ip: str,
    wan_interface: str,
    ikev2_encryption: Literal["en-3des", "aes-cbc-128", "aes-cbc-192", "aes-cbc-256", "aes-gcm-128", "aes-gcm-256", "des"],
    ikev2_integrity: Literal["md5", "sha1", "sha256", "sha384"],
    ikev2_group: Literal["one", "two", "five", "fourteen", "nineteen", "twenty", "twenty-four"],
    ipsec_encryption: Literal["esp-3des", "esp-aes", "esp-des", "esp-gcm", "esp-gmac", "esp-null", "esp-seal", "esp-192-aes", "esp-256-aes"],
    ipsec_integrity: Literal["esp-md5-hmac", "esp-sha-hmac", "esp-sha256-hmac"] | None = None,
    ipsec_key_size: Literal["128", "192", "256"] | None = None,
    pfs_group: Literal["group1", "group2", "group5", "group14", "group19", "group20", "group24"] | None = None,
    tunnel_mode: Literal["tunnel", "transport"] = "tunnel",
    # (C3) ชื่อเดิมตอนเปลี่ยนชื่อ profile - หลักเดียวกับฝั่ง Cisco: replace ทำงานกับ key
    # เดิม ถ้าเปลี่ยนชื่อแล้วไม่บอก object ชื่อเก่าจะกลายเป็นขยะค้าง
    replace_name: str | None = None,
    # (bug 93) PSK ย้ายมาท้ายและเป็น optional - **ไม่ส่ง = คงค่าเดิมบนอุปกรณ์**
    # เหตุผลเดียวกับฝั่ง Cisco (ดูคอมเมนต์ใน cisco_iosxe.create_security_profile)
    psk: str | None = None,
) -> str:
    # สร้าง security/ike/proposal+policy+gateway (peer_ip+psk+wan_interface) กับ
    # security/ipsec/proposal+policy - **เดิมไม่ใส่ external-interface ตรงนี้**
    # (คิดว่า leaf ไม่ mandatory ใน YANG เลยไม่จำเป็น) แต่ยืนยันจริงผ่าน commit
    # บนอุปกรณ์แล้วว่า Junos (kmd - key management daemon) **ปฏิเสธ commit ทันที
    # ถ้า gateway ไม่มี external-interface** ("The IKE gateway X must configure
    # the external-interface") แม้ YANG จะไม่บังคับก็ตาม - เป็น validation ที่
    # kmd ทำเองนอกเหนือจาก YANG schema ต่างจาก Cisco's create_security_profile ที่
    # ไม่ต้องรู้จัก WAN interface เลย (profile = crypto material ล้วนๆ) - Junos
    # ผูก gateway เข้ากับ WAN interface ตั้งแต่ตอนสร้างเสมอ เลยต้องรับ
    # wan_interface เป็น required param (ต่างจาก Cisco's signature - เป็นคนละ
    # ฟังก์ชันคนละไฟล์กันอยู่แล้ว ไม่กระทบ Cisco) - create_security_tunnel ยังคง
    # merge ทับ external-interface เดิมด้วยค่าล่าสุดได้ตามปกติถ้าต้องการเปลี่ยน
    # WAN interface ตอนสร้าง tunnel จริง - gateway ใส่ <version>v2-only</version>
    # ตายตัวเสมอด้วย (user ขอ 2026-07-29 - ไม่ใช่ toggle แยก) proposal ทั้งชุดที่
    # ฟังก์ชันนี้สร้าง (ikev2_encryption/ikev2_integrity/ikev2_group ตามชื่อ
    # param) ตั้งใจให้เป็น IKEv2 อยู่แล้วตั้งแต่แรก แต่ Junos gateway default รับ
    # ได้ทั้ง v1/v2 พร้อมกัน (auto-detect) - ใส่ version ชัดเจนให้ปฏิเสธ v1 ไปเลย
    # ตรงกับชื่อ param ที่ตั้งไว้แต่แรก
    if tunnel_mode == "transport":
        raise ValueError(
            "Junos route-based VPN (bind-interface) does not support transport mode "
            "- use tunnel_mode='tunnel' only"
        )
    if ipsec_encryption in _IPSEC_UNSUPPORTED_ESP:
        raise ValueError(
            f"ipsec_encryption '{ipsec_encryption}' has no matching encryption-algorithm in "
            "Junos ipsec-proposal - choose another value"
        )

    # (bug 69) เดิม psk มีแค่ escape() ไม่มีการตรวจความยาว - Cisco ยืนยันเพดาน 127
    # ตัวอักษรจาก console จริง ใช้เกณฑ์เดียวกันกับ Junos ไปก่อน (ยังไม่เคยวัดของ Junos)
    # (bug 93) ตรวจเฉพาะตอนที่ส่งมาจริง - ไม่ส่ง = ไม่แตะ ike policy เดิมที่เก็บ PSK อยู่
    if psk:
        psk = validate_psk(psk, "pre-shared key")
    junos_ike_encryption = _IKEV2_ENCRYPTION_MAP[ikev2_encryption]
    junos_ike_group = _IKEV2_GROUP_MAP[ikev2_group]

    # (bug 90) GCM มี authentication ในตัวแล้ว ห้ามใส่ authentication-algorithm ซ้ำ
    if ikev2_encryption in _IKEV2_COMBINED_MODE_ENCRYPTION:
        ike_auth_xml = ""
    else:
        ike_auth_xml = (
            f"<authentication-algorithm>{_IKEV2_INTEGRITY_MAP[ikev2_integrity]}"
            f"</authentication-algorithm>"
        )

    if ipsec_encryption in _IPSEC_FIXED_ENCRYPTION_MAP:
        junos_ipsec_encryption = _IPSEC_FIXED_ENCRYPTION_MAP[ipsec_encryption]
    else:
        if not ipsec_key_size:
            raise ValueError(f"ipsec_key_size is required when ipsec_encryption is {ipsec_encryption}")
        junos_ipsec_encryption = _IPSEC_KEYED_ENCRYPTION_MAP[(ipsec_encryption, ipsec_key_size)]

    # esp-gcm เป็น combined-mode cipher (มี authentication ในตัวอยู่แล้ว) - ไม่ต้อง
    # มี ipsec_integrity ซ้ำ เหมือนที่ Cisco's _IPSEC_COMBINED_MODE_ESP กันไว้
    if ipsec_encryption == "esp-gcm":
        ipsec_integrity_xml = ""
    else:
        if not ipsec_integrity:
            raise ValueError("ipsec_integrity is required unless ipsec_encryption is esp-gcm")
        ipsec_integrity_xml = f"<authentication-algorithm>{_IPSEC_INTEGRITY_MAP[ipsec_integrity]}</authentication-algorithm>"

    pfs_xml = f"<perfect-forward-secrecy><keys>{pfs_group}</keys></perfect-forward-secrecy>" if pfs_group else ""

    ike_proposal_name = f"{name}-IKE-PROP"
    ike_policy_name = f"{name}-IKE-POLICY"
    gateway_name = f"{name}-GATEWAY"
    ipsec_proposal_name = f"{name}-IPSEC-PROP"
    ipsec_policy_name = f"{name}-IPSEC-POLICY"

    # (C3 + bug 93) เดิมฟอร์ม "แก้ไข" ต้องยิง 2 RPC คือ remove_security_profile ทิ้ง
    # ทั้งชุดก่อน แล้วค่อย create ใหม่ ซึ่งมีปัญหา 2 อย่างซ้อนกัน
    #
    #   1. PSK หายทุกครั้ง - ike policy ที่เก็บ PSK ถูกลบไปด้วย ผู้ใช้จึงต้องพิมพ์ PSK
    #      เดิมกลับมาใหม่ทุกครั้งที่แก้แค่ algorithm พิมพ์ผิดเมื่อไหร่ tunnel พังทันที
    #   2. commit แรกล้มถ้ามี tunnel ผูกอยู่ - ipsec vpn ของ tunnel อ้าง gateway กับ
    #      ipsec-policy ตัวนี้ การลบทิ้งก่อนคือการทำให้ config ชี้ไปที่ของที่ไม่มีอยู่
    #
    # ทั้งสองข้อหายไปพร้อมกันด้วยการ "เลิกลบ" แล้วใช้ nc:operation="replace" ตาม
    # RFC 6241 §7.2 แทน (แพทเทิร์นเดียวกับที่ฝั่ง Cisco ใช้อยู่แล้ว) - ชื่อ object ไม่
    # เปลี่ยน reference จาก tunnel จึงไม่เคยขาด และ replace ล้าง leaf เก่าที่ไม่ได้ส่ง
    # มารอบนี้ให้ด้วย (เช่น authentication-algorithm ตอนเปลี่ยนจาก CBC ไป GCM ซึ่ง
    # merge ธรรมดาจะทิ้งค้างไว้แล้ว commit ไม่ผ่าน)
    replace = f'''xmlns:nc="{NS_RPC}" nc:operation="replace"'''

    # (bug 93) ike policy เป็น object เดียวที่เก็บ PSK - ต่างจาก Cisco ตรงที่ไม่มีอะไร
    # ในนี้เปลี่ยนตามฟอร์มเลย (มีแค่ proposals ที่ derive จากชื่อ profile กับตัว PSK เอง)
    # ถ้าไม่ได้ส่ง PSK มาจึง **ข้ามทั้งก้อนไปเลย** ปลอดภัยกว่า merge เพราะไม่ต้องแตะ node
    # ที่มีความลับอยู่ข้างในเลยสักนิด - peer IP ที่แก้ได้จากฟอร์มอยู่ใน gateway ไม่ใช่ที่นี่
    if psk:
        ike_policy_xml = f'''<policy {replace}>
      <name>{escape(ike_policy_name)}</name>
      <proposals>{escape(ike_proposal_name)}</proposals>
      <pre-shared-key>
        <ascii-text>{escape(psk)}</ascii-text>
      </pre-shared-key>
    </policy>'''
    else:
        ike_policy_xml = ""

    # เปลี่ยนชื่อ profile: รื้อ object ชื่อเก่าใน edit-config เดียวกัน - remove กับ replace
    # อยู่คนละ key จึงไม่แย่ง node กัน (ห้าม remove แล้วสร้าง node เดียวกันใน RPC เดียว
    # RFC ไม่รับประกันลำดับ) ใช้ remove ไม่ใช่ delete เพราะ remove ไม่ error ถ้าไม่มีของเดิม
    old = (replace_name or "").strip()
    if old and old != name and not psk:
        raise ValueError("Renaming security profile requires entering a new PSK (existing PSK cannot be copied)")
    if old and old != name:
        old = validate_object_ref(old, "Previous security profile name")
        remove = f'''xmlns:nc="{NS_RPC}" nc:operation="remove"'''
        removals_ike = f'''
    <gateway {remove}><name>{escape(f"{old}-GATEWAY")}</name></gateway>
    <policy {remove}><name>{escape(f"{old}-IKE-POLICY")}</name></policy>
    <proposal {remove}><name>{escape(f"{old}-IKE-PROP")}</name></proposal>'''
        removals_ipsec = f'''
    <policy {remove}><name>{escape(f"{old}-IPSEC-POLICY")}</name></policy>
    <proposal {remove}><name>{escape(f"{old}-IPSEC-PROP")}</name></proposal>'''
    else:
        removals_ike = ""
        removals_ipsec = ""

    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <ike>{removals_ike}
    <proposal {replace}>
      <name>{escape(ike_proposal_name)}</name>
      <authentication-method>pre-shared-keys</authentication-method>
      <dh-group>{junos_ike_group}</dh-group>
      {ike_auth_xml}
      <encryption-algorithm>{junos_ike_encryption}</encryption-algorithm>
    </proposal>
    {ike_policy_xml}
    <gateway {replace}>
      <name>{escape(gateway_name)}</name>
      <ike-policy>{escape(ike_policy_name)}</ike-policy>
      <address>{peer_ip}</address>
      <external-interface>{escape(wan_interface)}</external-interface>
      <version>v2-only</version>
    </gateway>
  </ike>
  <ipsec>{removals_ipsec}
    <proposal {replace}>
      <name>{escape(ipsec_proposal_name)}</name>
      <protocol>esp</protocol>
      <encryption-algorithm>{junos_ipsec_encryption}</encryption-algorithm>
      {ipsec_integrity_xml}
    </proposal>
    <policy {replace}>
      <name>{escape(ipsec_policy_name)}</name>
      <proposals>{escape(ipsec_proposal_name)}</proposals>
      {pfs_xml}
    </policy>
  </ipsec>
</security>
    ''')


def get_security_profile_information():
    # หน้า security_profile.jsx ต้องการภาพรวม profile ที่สร้างไว้แล้ว - ดึงทั้ง
    # security/ike กับ security/ipsec (proposal/policy/gateway ฝั่ง ike,
    # proposal/policy ฝั่ง ipsec) เหมือนที่ Cisco ดึง ikev2/profile +
    # ipsec/transform-set + ipsec/profile มารวมกัน
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <security xmlns="{NS_SECURITY}">
        <ike/>
        <ipsec/>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')


# ลบทั้ง 5 object ที่ create_security_profile สร้างไว้ (gateway/ike-policy/
# ike-proposal/ipsec-policy/ipsec-proposal) ในคำสั่งเดียว - Cisco มี 6 remove_*
# แยกเพราะไม่มีฟังก์ชัน "สร้างรวม" ให้ตรงกันมาก่อน ส่วน Juniper's
# create_security_profile รวมเป็นก้อนเดียวอยู่แล้ว เลยให้ remove รวมเป็นก้อน
# เดียวคู่กันไปด้วย (ตั้งชื่อใหม่ ไม่ต้องเลียนแบบชื่อ Cisco - เรียกจาก vendor
# branch แยกอยู่แล้วฝั่ง frontend) ลำดับ: gateway ก่อน (ตัวที่ policy/vpn อื่น
# อาจอ้างอิง - ถ้ายังมี tunnel ใช้อยู่ Junos จะปฏิเสธตรงนี้ก่อนเลย ไม่ทันไปลบ
# proposal ตัวอื่นที่ policy ยังอ้างอิงอยู่) ตามด้วย ike policy/proposal แล้วค่อย
# ipsec policy/proposal
@validate_call
def remove_security_profile(name: str):
    gateway_name = f"{name}-GATEWAY"
    ike_policy_name = f"{name}-IKE-POLICY"
    ike_proposal_name = f"{name}-IKE-PROP"
    ipsec_policy_name = f"{name}-IPSEC-POLICY"
    ipsec_proposal_name = f"{name}-IPSEC-PROP"

    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <ike>
    <gateway xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(gateway_name)}</name>
    </gateway>
    <policy xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(ike_policy_name)}</name>
    </policy>
    <proposal xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(ike_proposal_name)}</name>
    </proposal>
  </ike>
  <ipsec>
    <policy xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(ipsec_policy_name)}</name>
    </policy>
    <proposal xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(ipsec_proposal_name)}</name>
    </proposal>
  </ipsec>
</security>
    ''')


# ---------------------------------------------------------------------------
# Security Profile ที่ "ไม่ได้สร้างจากระบบ" (ตั้งจาก CLI / ติดมาก่อน onboard)
#
# create_security_profile / remove_security_profile ข้างบน derive ชื่อ object ทั้ง 5 ตัวจากชื่อ
# profile (`{name}-GATEWAY`/`-IKE-POLICY`/…) ซึ่งถูกเสมอสำหรับของที่ระบบสร้างเอง แต่ของที่มีอยู่แล้ว
# บนอุปกรณ์ตั้งชื่อตามใจผู้ตั้ง 2 ฟังก์ชันด้านล่างจึงทำงานกับ **ชื่อจริงที่อ่านมาจากอุปกรณ์**
# (parseSecurityProfiles ไล่ gateway -> ike policy -> proposal และ vpn -> ipsec policy -> proposal)
# ไม่มีการ derive ชื่อที่นี่เลย
# ---------------------------------------------------------------------------

@validate_call
def remove_security_profile_objects(
    gateway: str,
    ike_policy: str | None = None,
    ike_proposal: str | None = None,
    ipsec_policy: str | None = None,
    ipsec_proposal: str | None = None,
):
    # ลบเฉพาะ object ที่ระบุมา - ตัวที่ profile อื่นอ้างอยู่ถูกตัดออกที่ frontend ก่อนแล้ว ที่นี่ไม่เดาเพิ่ม
    # ลำดับเหมือน remove_security_profile: gateway ก่อน (ถ้ายังมี vpn/tunnel อ้างอยู่ Junos ปฏิเสธที่ตัวนี้
    # ตั้งแต่แรก ไม่ทันไปรื้อ policy/proposal ที่ยังมีคนอ้าง)
    gateway = validate_object_ref(gateway, "IKE gateway name")

    def removal(tag: str, name: str, label: str) -> str:
        name = validate_object_ref(name, label)
        return f'<{tag} xmlns:nc="{NS_RPC}" nc:operation="remove"><name>{escape(name)}</name></{tag}>'

    ike_parts = [removal("gateway", gateway, "IKE gateway name")]
    if ike_policy:
        ike_parts.append(removal("policy", ike_policy, "IKE policy name"))
    if ike_proposal:
        ike_parts.append(removal("proposal", ike_proposal, "IKE proposal name"))
    ipsec_parts = []
    if ipsec_policy:
        ipsec_parts.append(removal("policy", ipsec_policy, "IPsec policy name"))
    if ipsec_proposal:
        ipsec_parts.append(removal("proposal", ipsec_proposal, "IPsec proposal name"))
    ipsec_xml = f"<ipsec>{''.join(ipsec_parts)}</ipsec>" if ipsec_parts else ""
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  <ike>{''.join(ike_parts)}</ike>
  {ipsec_xml}
</security>
    ''')


@validate_call
def modify_security_profile(
    gateway: str,
    # ---- ชื่อ object จริง (ระบุเฉพาะตัวที่ต้องแตะ) ----
    ike_policy: str | None = None,
    ike_proposal: str | None = None,
    ipsec_policy: str | None = None,
    ipsec_proposal: str | None = None,
    # ---- ค่าที่เปลี่ยน: None = ไม่แตะ ----
    peer_ip: str | None = None,
    old_peer_ip: str | None = None,
    wan_interface: str | None = None,
    psk: str | None = None,
    ikev2_encryption: Literal["en-3des", "aes-cbc-128", "aes-cbc-192", "aes-cbc-256", "aes-gcm-128", "aes-gcm-256", "des"] | None = None,
    ikev2_integrity: Literal["md5", "sha1", "sha256", "sha384"] | None = None,
    ikev2_group: Literal["one", "two", "five", "fourteen", "nineteen", "twenty", "twenty-four"] | None = None,
    ipsec_encryption: Literal["esp-3des", "esp-aes", "esp-des", "esp-gcm", "esp-gmac", "esp-null", "esp-seal", "esp-192-aes", "esp-256-aes"] | None = None,
    ipsec_integrity: Literal["esp-md5-hmac", "esp-sha-hmac", "esp-sha256-hmac"] | None = None,
    ipsec_key_size: Literal["128", "192", "256"] | None = None,
    # "none" = เอา PFS ออก
    pfs_group: Literal["group1", "group2", "group5", "group14", "group19", "group20", "group24", "none"] | None = None,
):
    # แก้ไข "ในที่เดิม" ของ profile ที่ไม่ได้สร้างจากระบบ - **ส่งเฉพาะ field ที่ผู้ใช้เปลี่ยน** เป็น merge ระดับ
    # leaf ไม่ replace ทั้ง object เหมือน create_security_profile เพราะ object ของ brownfield มีค่าอื่นที่ฟอร์ม
    # ไม่รู้จัก (dead-peer-detection, nat-keepalive, version, หลาย address ฯลฯ) ที่ต้องรอดหลังบันทึก
    # ชื่อ object ไม่ถูกแตะเลย และ **ไม่แตะ version ของ gateway** (ของเดิมอาจเป็น v1 หรือ v2)
    #
    # เปลี่ยน peer = ลบ address เก่า + เพิ่มใหม่ (gateway/address เป็น leaf-list เพิ่มอย่างเดียวจะได้ 2 peer)
    gateway = validate_object_ref(gateway, "IKE gateway name")
    changed = (
        peer_ip, wan_interface, psk, ikev2_encryption, ikev2_integrity, ikev2_group,
        ipsec_encryption, ipsec_integrity, ipsec_key_size, pfs_group,
    )
    if all(value is None for value in changed):
        raise ValueError("No changes detected - no command to send")

    remove = f'xmlns:nc="{NS_RPC}" nc:operation="remove"'
    ike_parts: list[str] = []
    ipsec_parts: list[str] = []

    # ---- gateway: peer + external-interface ----
    gateway_children = ""
    if peer_ip is not None:
        peer_ip = validate_ipv4(peer_ip, "peer_ip")
        if not old_peer_ip:
            raise ValueError("Changing Peer IP requires specifying old_peer_ip (existing value on device)")
        old_peer_ip = validate_ipv4(old_peer_ip, "old_peer_ip")
        if old_peer_ip == peer_ip:
            raise ValueError("New Peer IP is identical to existing value")
        gateway_children += f"<address {remove}>{old_peer_ip}</address><address>{peer_ip}</address>"
    if wan_interface is not None:
        gateway_children += f"<external-interface>{escape(wan_interface)}</external-interface>"
    if gateway_children:
        ike_parts.append(f"<gateway><name>{escape(gateway)}</name>{gateway_children}</gateway>")

    # ---- PSK อยู่ที่ ike policy (ไม่แตะ proposals ของ policy) ----
    if psk is not None:
        if not ike_policy:
            raise ValueError("Modifying PSK requires specifying ike_policy")
        psk = validate_psk(psk, "pre-shared key")
        ike_policy = validate_object_ref(ike_policy, "IKE policy name")
        ike_parts.append(
            f"<policy><name>{escape(ike_policy)}</name>"
            f"<pre-shared-key><ascii-text>{escape(psk)}</ascii-text></pre-shared-key></policy>"
        )

    # ---- IKE proposal ----
    if ikev2_encryption is not None or ikev2_integrity is not None or ikev2_group is not None:
        if not ike_proposal:
            raise ValueError("Modifying IKE algorithm requires specifying ike_proposal")
        if (ikev2_encryption is None) != (ikev2_integrity is None):
            # GCM ห้ามมี authentication-algorithm ส่วน CBC ต้องมี - สองค่านี้พึ่งกัน ต้องส่งคู่กันเสมอ
            raise ValueError("Modifying IKE encryption or integrity requires providing both values")
        ike_proposal = validate_object_ref(ike_proposal, "IKE proposal name")
        proposal_children = ""
        if ikev2_encryption is not None:
            proposal_children += f"<encryption-algorithm>{_IKEV2_ENCRYPTION_MAP[ikev2_encryption]}</encryption-algorithm>"
            if ikev2_encryption in _IKEV2_COMBINED_MODE_ENCRYPTION:
                proposal_children += f"<authentication-algorithm {remove}/>"
            else:
                proposal_children += (
                    f"<authentication-algorithm>{_IKEV2_INTEGRITY_MAP[ikev2_integrity]}</authentication-algorithm>"
                )
        if ikev2_group is not None:
            proposal_children += f"<dh-group>{_IKEV2_GROUP_MAP[ikev2_group]}</dh-group>"
        ike_parts.append(f"<proposal><name>{escape(ike_proposal)}</name>{proposal_children}</proposal>")

    # ---- IPsec proposal ----
    esp_fields = (ipsec_encryption, ipsec_integrity, ipsec_key_size)
    if any(value is not None for value in esp_fields):
        if not ipsec_proposal:
            raise ValueError("Modifying IPsec algorithm requires specifying ipsec_proposal")
        if ipsec_encryption is None:
            raise ValueError("Modifying IPsec integrity/key size requires providing ipsec_encryption")
        if ipsec_encryption in _IPSEC_UNSUPPORTED_ESP:
            raise ValueError(
                f"ipsec_encryption '{ipsec_encryption}' has no matching encryption-algorithm in "
                "Junos ipsec-proposal - choose another value"
            )
        ipsec_proposal = validate_object_ref(ipsec_proposal, "IPsec proposal name")
        if ipsec_encryption in _IPSEC_FIXED_ENCRYPTION_MAP:
            junos_encryption = _IPSEC_FIXED_ENCRYPTION_MAP[ipsec_encryption]
        else:
            if not ipsec_key_size:
                raise ValueError(f"ipsec_key_size is required when ipsec_encryption is {ipsec_encryption}")
            junos_encryption = _IPSEC_KEYED_ENCRYPTION_MAP[(ipsec_encryption, ipsec_key_size)]
        proposal_children = f"<encryption-algorithm>{junos_encryption}</encryption-algorithm>"
        if ipsec_encryption == "esp-gcm":
            proposal_children += f"<authentication-algorithm {remove}/>"
        else:
            if not ipsec_integrity:
                raise ValueError("ipsec_integrity is required unless ipsec_encryption is esp-gcm")
            proposal_children += (
                f"<authentication-algorithm>{_IPSEC_INTEGRITY_MAP[ipsec_integrity]}</authentication-algorithm>"
            )
        ipsec_parts.append(f"<proposal><name>{escape(ipsec_proposal)}</name>{proposal_children}</proposal>")

    # ---- PFS อยู่ที่ ipsec policy ----
    if pfs_group is not None:
        if not ipsec_policy:
            raise ValueError("Modifying PFS requires specifying ipsec_policy")
        ipsec_policy = validate_object_ref(ipsec_policy, "IPsec policy name")
        pfs_xml = (
            f"<perfect-forward-secrecy {remove}/>" if pfs_group == "none"
            else f"<perfect-forward-secrecy><keys>{pfs_group}</keys></perfect-forward-secrecy>"
        )
        ipsec_parts.append(f"<policy><name>{escape(ipsec_policy)}</name>{pfs_xml}</policy>")

    ike_xml = f"<ike>{''.join(ike_parts)}</ike>" if ike_parts else ""
    ipsec_xml = f"<ipsec>{''.join(ipsec_parts)}</ipsec>" if ipsec_parts else ""
    return _edit_configuration(f'''
<security xmlns="{NS_SECURITY}">
  {ike_xml}
  {ipsec_xml}
</security>
    ''')


@validate_call
def create_security_tunnel(
    tunnel_type: Literal["ipsec", "gre"],
    interface_number: str,
    tun_ip: str,
    tun_subnet: str,
    wan_interface: str,
    remote_ip: str,
    old_remote_ip: str | None = None,
    ipsec_profile: str | None = None,
    mtu: int | None = None,
    vpn_name: str | None = None,
    gateway_name: str | None = None,
    ipsec_policy_name: str | None = None,
    bind_interface: str | None = None,
    gre_interface: str | None = None,
    gre_unit: str | None = None,
) -> str:
    # ipsec: ผูก tunnel interface เข้ากับ gateway/policy ที่
    # create_security_profile สร้างไว้แล้ว (ipsec_profile ในนี้คือ `name` เดิม
    # ตอนเรียก create_security_profile - derive ชื่อ gateway/policy กลับแบบ
    # เดียวกับที่ create_security_profile ตั้งไว้) ทำ 3 อย่างในคำสั่งเดียว:
    #   1. สร้าง st0 unit (secure tunnel interface, route-based VPN) พร้อม
    #      family inet address จาก tun_ip/tun_subnet
    #   2. merge external-interface (จาก wan_interface) ทับ gateway ที่มีอยู่แล้ว
    #      (create_security_profile ใส่ไว้ตั้งแต่ตอนสร้างแล้วเช่นกัน - ยืนยันจริง
    #      ว่า commit ครั้งแรกของ create_security_profile จะ fail ทันทีถ้าไม่มี
    #      leaf นี้ ("must configure the external-interface") แม้ YANG จะไม่บังคับ
    #      ก็ตาม - ตรงนี้แค่ให้เปลี่ยน WAN interface ทีหลังได้ถ้าต้องการ)
    #   3. สร้าง security/ipsec/vpn ผูก bind-interface=st0.X เข้ากับ gateway+
    #      ipsec-policy คู่นั้น (ipsec-vpn-template's case_2 "ike", บรรทัด 26770)
    #
    # gre: **ยืนยันจริงแล้วว่ามี schema** - เดิมเข้าใจผิดว่าไม่มี (หา "source"/
    # "destination" ใน `container tunnel` ไม่เจอเพราะหยุดอ่านแค่ตรง vxlan-gpe
    # encapsulation block ก่อนหน้า ไม่ได้อ่านลึกพอ) ตัว container tunnel เดียวกัน
    # นั้นมี leaf source/destination (choice source_type/destination_type,
    # junos-es-conf-interfaces.yang:26747-26785) อยู่ต่อจาก encapsulation block
    # พอดี - user ยืนยัน CLI จริงด้วย (`set interfaces gr-0/0/0 unit 0 tunnel
    # source <ip> / tunnel destination <ip>`) ทดสอบ commit จริงแล้วผ่าน -
    # ต่างจาก ipsec ตรงที่ **ไม่มี concept "unit" แยกจาก physical interface
    # เหมือน st0** (gr- เป็น physical/pseudo interface จริงที่มีได้หลายตัวต่อ
    # อุปกรณ์ เช่น gr-0/0/0, gr-0/0/1) - ใช้ interface_number เป็น**เลข slot ของ
    # gr- interface** (เช่น "0/0/0") ไม่ใช่เลข unit แบบ ipsec (unit fix เป็น "0"
    # เสมอ - ยังไม่รองรับหลาย unit ต่อ gr- interface เดียว) wan_interface ใน
    # โหมดนี้หมายถึง**tunnel source IP** ตรงๆ (ต่างจาก ipsec mode ที่เป็นชื่อ
    # interface - Junos GRE's "tunnel source" ตาม YANG เป็น IP address ไม่ใช่
    # ชื่อ interface เหมือนที่ user ใช้ในตัวอย่างจริง) ไม่ต้องมี ipsec_profile
    # (bug 32/98) เดิมเข้าใจว่า mtu ของ gr-*/st0 อยู่ระดับ physical เหมือน
    # set_interface_static_ip/set_sub_interface_ip แต่ผลทดสอบ vSRX ยืนยันว่า
    # tunnel ทั้งสองชนิดต้องวางใต้ unit/family/inet แทน (ดูผล 4 ตำแหน่งด้านล่าง)
    # _mtu_xml ยังทำหน้าที่ตรวจค่าและสร้าง leaf เหมือนเดิม ตำแหน่งที่แทรก XML
    # เป็นหน้าที่ของแต่ละ branch ไม่เปลี่ยนพฤติกรรม interface ปกติที่ใช้ร่วมกัน
    mtu_xml = _mtu_xml(mtu)

    # (bug 70) ตรวจว่า tun_ip ใช้เป็น host address ใน prefix นั้นได้จริง ไม่ใช่แค่
    # "เป็น IPv4 ที่ถูกรูปแบบ" - เจอจริงฝั่ง Cisco ว่า 169.254.1.255/30 ผ่านได้แล้ว
    # อุปกรณ์ปฏิเสธจน tunnel หายทั้งตัว ฝั่งนี้มีช่องเดียวกันเพราะตรวจแบบเดียวกัน
    tun_ip = validate_host_in_network(tun_ip, tun_subnet, "Tunnel IP")

    if tunnel_type == "gre":
        interface = validate_object_ref(gre_interface, "GRE interface name") if gre_interface else _interface_name("gr-", interface_number)
        unit_name = validate_object_ref(gre_unit, "GRE unit") if gre_unit is not None else "0"
        tunnel_address = ipaddress.IPv4Interface(f"{tun_ip}/{tun_subnet}")
        ipaddress.IPv4Address(wan_interface)
        ipaddress.IPv4Address(remote_ip)
        # (bug 91) replace ที่ระดับ unit - ไม่แตะ physical interface entry เพราะ gr- เป็น
        # pseudo interface ที่มีอยู่บนอุปกรณ์อยู่แล้วและอาจมี unit อื่นอยู่
        # (bug 98) เดิมเข้าใจว่า MTU อยู่ระดับ physical จึงเพิ่ม remove ใน bug 91
        # เพื่อกันค่าเก่าค้าง แต่ element นั้นเองถูก vSRX ปฏิเสธ ทำให้แม้ไม่กรอก
        # MTU ก็สร้าง GRE ไม่ได้ (ส่วนกรอก MTU พังอยู่ก่อนแล้ว) ย้าย MTU เข้า
        # family inet ในขอบเขต replace ของ unit จึงล้างค่าเก่าให้เองเมื่อไม่ส่งมา
        return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <unit xmlns:nc="{NS_RPC}" nc:operation="replace">
      <name>{escape(unit_name)}</name>
      <tunnel>
        <source>{wan_interface}</source>
        <destination>{remote_ip}</destination>
      </tunnel>
      <family>
        <inet>
          {mtu_xml}
          <address>
            <name>{tunnel_address}</name>
          </address>
        </inet>
      </family>
    </unit>
  </interface>
</interfaces>
    ''')

    if not ipsec_profile:
        raise ValueError("ipsec_profile is required when tunnel_type is 'ipsec'")

    tunnel_address = ipaddress.IPv4Interface(f"{tun_ip}/{tun_subnet}")
    remote_ip = str(ipaddress.IPv4Address(remote_ip))

    # โหมด Edit ส่ง old_remote_ip มาเพื่อเปลี่ยน peer ของ IKE gateway ใน RPC
    # เดียวกับ st0/VPN ด้านล่าง Gateway address เป็น leaf-list: ถ้า merge ค่าใหม่
    # อย่างเดียวจะเหลือ peer เดิมค้างและกลายเป็นหลาย address จึงต้อง remove เฉพาะ
    # ค่าเดิมแล้วเพิ่มค่าใหม่ ห้าม replace ทั้ง gateway เพราะ Brownfield อาจมีค่า
    # อื่นที่ฟอร์มไม่รู้จักและต้องคงอยู่ครบถ้วน
    gateway_address_xml = ""
    if old_remote_ip is not None:
        old_remote_ip = str(ipaddress.IPv4Address(old_remote_ip))
        if old_remote_ip != remote_ip:
            remove = f'xmlns:nc="{NS_RPC}" nc:operation="remove"'
            gateway_address_xml = (
                f"<address {remove}>{old_remote_ip}</address>"
                f"<address>{remote_ip}</address>"
            )

    # user ขอ (2026-07-29) establish-tunnels immediately ตายตัวเสมอ (ไม่ใช่
    # toggle แยก) - Junos route-based VPN ของ vpn ที่ไม่ตั้งค่านี้ default เป็น
    # on-traffic (รอ traffic จริงก่อนถึงจะเริ่ม negotiate IKE/IPsec SA) ทำให้
    # tunnel ขึ้นช้า/ไม่ขึ้นเลยจนกว่าจะมี traffic ยิงผ่านจริงก่อน - immediately
    # บังคับให้เริ่ม negotiate ทันทีตอน commit เลยโดยไม่ต้องรอ traffic
    # (bug 32) st0 เป็นข้อยกเว้นของกฎ "Junos ตั้ง mtu ที่ระดับ physical interface เสมอ"
    # ที่ _mtu_xml() เขียนไว้ - กฎนั้นถูกสำหรับ interface ทางกายภาพ (ge-0/0/1 ฯลฯ) แต่ st0
    # ต้องใช้ MTU leaf ที่อยู่ใต้ family inet ของแต่ละ unit แทน เพราะ st0 ตัวเดียวมีได้หลาย
    # unit (หลาย tunnel) ที่ต้องการ MTU ต่างกันตาม IPsec overhead ของแต่ละ peer
    # ยืนยันจาก junos-es-conf-interfaces.yang: leaf mtu มี 2 ตำแหน่งคนละความหมาย
    #   L16218        leaf mtu  "Maximum transmit packet size"          <- ระดับ physical
    #   L26981-27070  family/inet/leaf mtu  "Protocol family MTU"       <- ที่ st0 ต้องใช้
    # ผู้ใช้ทดสอบ A/B เองแล้ว: ไม่กรอก MTU -> st0 ขึ้นปกติ · กรอก MTU -> interface ไม่ปรากฏ
    # บนอุปกรณ์เลย เพราะ Junos ปฏิเสธทั้ง unit - จึงย้าย {mtu_xml} ลงไปใน <family><inet>
    #
    # (bug 98) แก้ข้อสันนิษฐานเดิมที่ว่า gr- เป็น tunnel PIC จึงวาง MTU ระดับ
    # physical ได้เหมือน interface ปกติ: ทดสอบจริงกับ vSRX 24.4R1.9 แล้วได้ผลดังนี้
    #   ระดับ physical interface (YANG L16218) -> syntax error, bad-element mtu
    #   ใต้ unit โดยตรง (YANG L26000)         -> syntax error, bad-element mtu
    #   ใต้ unit/family/inet (YANG L27070)    -> อุปกรณ์รับ
    #   ไม่ส่ง element mtu เลย               -> อุปกรณ์รับ
    # gr- จึงต้องใช้ตำแหน่งเดียวกับ st0 โดยวาง mtu ก่อน address ใน inet
    # YANG มี leaf ไม่ได้แปลว่า interface ทุกชนิดบนรุ่นนี้รับ (บทเรียน BUG-89/71)
    gateway_name = validate_object_ref(gateway_name, "IKE gateway name") if gateway_name else f"{ipsec_profile}-GATEWAY"
    ipsec_policy_name = validate_object_ref(ipsec_policy_name, "IPsec policy name") if ipsec_policy_name else f"{ipsec_profile}-IPSEC-POLICY"
    vpn_name = validate_object_ref(vpn_name, "IPsec VPN name") if vpn_name else f"{ipsec_profile}-VPN"
    bind_interface = validate_object_ref(bind_interface, "bind-interface") if bind_interface else f"st0.{interface_number}"
    bind_unit = bind_interface.split(".")[-1]

    # (bug 91) เดิมฟอร์ม "แก้ไข tunnel" ยิง remove_tunnel_interface ก่อนแล้วค่อยสร้างใหม่
    # ซึ่งฝั่ง Junos อุปกรณ์ปฏิเสธตั้งแต่คำสั่งแรก:
    #
    #   'remove_tunnel_interface': Interface st0.0 must be configured under interfaces
    #
    # เพราะ security/ipsec/vpn ยัง bind-interface มาที่ st0.0 อยู่ Junos ตรวจ referential
    # integrity ตอน commit จึงไม่ยอมให้ unit หายไปทั้งที่ยังมีคนผูกอยู่ - ทางแก้เดียวกับ
    # ฝั่ง Cisco คือ "เลิกลบ" ใช้ nc:operation="replace" แทน node ไม่เคยหาย reference จึง
    # ไม่เคยขาด และ leaf เก่าที่ไม่ได้ส่งมารอบนี้ (mtu ใต้ family inet) ถูกล้างให้อยู่ดี
    #
    # ส่วน <gateway> ยังเป็น merge เหมือนเดิมโดยเจตนา - external-interface เป็น shared
    # infrastructure ของ security profile ที่ tunnel ตัวอื่นอาจอ้างอยู่ ห้าม replace ทิ้ง
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>st0</name>
    <unit xmlns:nc="{NS_RPC}" nc:operation="replace">
      <name>{escape(bind_unit)}</name>
      <family>
        <inet>
          {mtu_xml}
          <address>
            <name>{tunnel_address}</name>
          </address>
        </inet>
      </family>
    </unit>
  </interface>
</interfaces>
<security xmlns="{NS_SECURITY}">
  <ike>
    <gateway>
      <name>{escape(gateway_name)}</name>
      {gateway_address_xml}
      <external-interface>{escape(wan_interface)}</external-interface>
    </gateway>
  </ike>
  <ipsec>
    <vpn xmlns:nc="{NS_RPC}" nc:operation="replace">
      <name>{escape(vpn_name)}</name>
      <bind-interface>{escape(bind_interface)}</bind-interface>
      <ike>
        <gateway>{escape(gateway_name)}</gateway>
        <ipsec-policy>{escape(ipsec_policy_name)}</ipsec-policy>
      </ike>
      <establish-tunnels>immediately</establish-tunnels>
    </vpn>
  </ipsec>
</security>
    ''')


# ลบ tunnel เดียว - ลบแค่ st0 unit + ipsec/vpn entry ที่คำสั่งนี้สร้างไว้เอง
# **ไม่แตะ** gateway/external-interface (ตั้งใจ - เป็น shared infrastructure ของ
# security profile ที่ tunnel อื่นอาจอ้างอิง external-interface เดียวกันอยู่ก็ได้
# ทำนองเดียวกับที่ NAT/ZBF ไม่แตะ zone/zone-member ตอน teardown) ต้องรู้
# ipsec_profile (base name เดิมตอนสร้าง) เพื่อ derive ชื่อ vpn กลับ - frontend
# มีอยู่แล้วจาก parseJuniperSecurityTunnels's securityProfile field
# tunnel_type แยก path ให้ตรงกับที่ create_security_tunnel สร้าง - ipsec ลบ st0
# unit (interface_number = unit number) + ipsec/vpn entry (ต้องมี ipsec_profile
# มา derive ชื่อ vpn กลับ) / gre ลบแค่ unit 0 ของ gr- interface (interface_number
# = slot เช่น "0/0/0" ไม่ใช่ unit number - ตัว unit fix เป็น "0" เสมอตามที่
# create_security_tunnel สร้าง) ไม่แตะ physical interface entry เอง (gr-0/0/0
# เป็น physical/pseudo resource ที่มีอยู่แล้วบนอุปกรณ์โดยไม่ขึ้นกับ config -
# ยืนยันจริงว่าลบแค่ unit แล้ว `show configuration interfaces gr-0/0/0` ว่างสนิท
# ไม่มี config เหลือเลย ไม่ error อะไร) ไม่มี security object ให้ลบเลยสำหรับ GRE
# (ไม่ได้ผูกกับ security profile/policy อะไรทั้งสิ้น)
@validate_call
def remove_tunnel_interface(
    interface_number: str,
    tunnel_type: Literal["ipsec", "gre"] = "ipsec",
    ipsec_profile: str | None = None,
    vpn_name: str | None = None,
    bind_interface: str | None = None,
    gre_interface: str | None = None,
    gre_unit: str | None = None,
):
    if tunnel_type == "gre":
        interface = validate_object_ref(gre_interface, "GRE interface name") if gre_interface else _interface_name("gr-", interface_number)
        unit_name = validate_object_ref(gre_unit, "GRE unit") if gre_unit is not None else "0"
        return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>{interface}</name>
    <unit xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(unit_name)}</name>
    </unit>
  </interface>
</interfaces>
    ''')

    if not vpn_name and not ipsec_profile:
        raise ValueError("ipsec_profile or vpn_name is required when tunnel_type is 'ipsec'")
    vpn_name = validate_object_ref(vpn_name, "IPsec VPN name") if vpn_name else f"{ipsec_profile}-VPN"
    bind_interface = validate_object_ref(bind_interface, "bind-interface") if bind_interface else f"st0.{interface_number}"
    bind_unit = bind_interface.split(".")[-1]
    return _edit_configuration(f'''
<interfaces xmlns="{NS_INTERFACES}">
  <interface>
    <name>st0</name>
    <unit xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(bind_unit)}</name>
    </unit>
  </interface>
</interfaces>
<security xmlns="{NS_SECURITY}">
  <ipsec>
    <vpn xmlns:nc="{NS_RPC}" nc:operation="remove">
      <name>{escape(vpn_name)}</name>
    </vpn>
  </ipsec>
</security>
    ''')


def get_security_tunnel_information():
    # หน้า security_tunnel.jsx ดึงทั้ง st0 (secure tunnel/IPsec) กับ gr-*
    # (GRE) interface มาแสดงรวมกัน กับ security/ipsec/vpn (bind-interface +
    # gateway/policy ที่ผูกไว้ - เฉพาะ IPsec) - ขอทั้ง interfaces subtree มาเลย
    # (ไม่ระบุชื่อ interface เจาะจงแบบเดิมที่จำกัดแค่ "st0") เพราะไม่รู้ล่วงหน้าว่า
    # อุปกรณ์มี gr- physical interface กี่ตัว/ชื่ออะไรบ้าง (เหมือน
    # get_switchport_information ที่ขอทั้ง subtree เลยด้วยเหตุผลเดียวกัน) แล้วให้
    # frontend กรองเอาเฉพาะ st0.*/gr-*.* เอง - เพิ่ม security/ike/gateway เข้ามา
    # ด้วยเพราะ frontend ต้องอ่าน external-interface (ออกทาง)/address (peer IP)
    # ของ gateway ที่ vpn ผูกไว้ มาโชว์เป็นคอลัมน์ "ออกทาง"/"Peer IP" เหมือนหน้า
    # Cisco (เฉพาะแถว IPsec - แถว GRE ไม่มี gateway ให้ join)
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <interfaces xmlns="{NS_INTERFACES}">
        <interface/>
      </interfaces>
      <security xmlns="{NS_SECURITY}">
        <ike>
          <gateway/>
        </ike>
        <ipsec>
          <vpn/>
        </ipsec>
      </security>
    </configuration>
  </filter>
</get-config>
    ''')



def get_ntp_information():
    return open_rpc_tag(f'''
<get-config>
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <configuration xmlns="{NS_ROOT}">
      <system xmlns="{NS_SYSTEM}">
        <ntp/>
      </system>
    </configuration>
  </filter>
</get-config>
''')

@validate_call
def set_ntp_server(
    ntp_ip: str,
):
    ntp_ip = str(ipaddress.IPv4Address(ntp_ip))
    return _edit_configuration(f'''
      <system xmlns="{NS_SYSTEM}">
        <ntp>
          <server>
            <name>{ntp_ip}</name>
          </server>
        </ntp>
      </system>
''')

@validate_call
def remove_ntp_server(
    ntp_ip: str,
):
    ntp_ip = str(ipaddress.IPv4Address(ntp_ip))
    return _edit_configuration(f'''
      <system xmlns="{NS_SYSTEM}">
        <ntp>
          <server xmlns:nc="{NS_RPC}" nc:operation="remove">
            <name>{ntp_ip}</name>
          </server>
        </ntp>
      </system>
''')

def commit():
    return open_rpc_tag('''<commit/>''')

def get_capability_schema():
    return open_rpc_tag('''
    <get>
      <filter type="subtree">
        <netconf-state xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
          <schemas/>
        </netconf-state>
      </filter>
    </get>
''')

def reboot():
    return open_rpc_tag('''
      <request-reboot/>
    ''')

def get_local_user():
    return open_rpc_tag('''
     <get-config>
      <source>
        <running/>
      </source>
      <filter type="subtree">
        <configuration>
          <system>
            <login/>
          </system>
        </configuration>
      </filter>
    </get-config>
    ''')

@validate_call
def set_new_local_user(
    username: str,
    privilege: Literal["operator", "super-user"],
    passwd: str,
):
    if not username.strip():
        raise ValueError("Username is required")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in username):
        raise ValueError("Username contains control characters")
    if not passwd:
        raise ValueError("Password is required")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in passwd):
        raise ValueError("Password contains control characters")
    encrypted_password = hash_password_sha512(passwd)

    return _edit_configuration(f'''
      <system xmlns="{NS_SYSTEM}">
          <login>
            <user xmlns:nc="{NS_RPC}" nc:operation="create">
              <name>{escape(username)}</name>
              <class>{privilege}</class>
              <authentication>
                <encrypted-password>{escape(encrypted_password)}</encrypted-password>
              </authentication>
            </user>
          </login>
        </system>
''')


@validate_call
def edit_local_user(
    username: str,
    privilege: Literal["operator", "super-user"] | None = None,
    passwd: str | None = None,
):
    """Update selected fields without replacing the Junos user subtree.

    Username is the immutable list key. Omitting privilege or passwd preserves
    the corresponding current value and all unmodelled Brownfield fields such
    as SSH public keys, full-name and uid.
    """
    if not username.strip():
        raise ValueError("Username is required")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in username):
        raise ValueError("Username contains control characters")
    if privilege is None and passwd is None:
        raise ValueError("At least one of privilege or password must be provided")
    if passwd is not None:
        if not passwd:
            raise ValueError("Password cannot be empty")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in passwd):
            raise ValueError("Password contains control characters")

    privilege_xml = "" if privilege is None else f"<class>{privilege}</class>"
    password_xml = ""
    if passwd is not None:
        encrypted_password = hash_password_sha512(passwd)
        password_xml = f'''
          <authentication>
            <encrypted-password xmlns:nc="{NS_RPC}" nc:operation="replace">{escape(encrypted_password)}</encrypted-password>
          </authentication>
        '''

    return _edit_configuration(f'''
      <system xmlns="{NS_SYSTEM}">
        <login>
          <user>
            <name>{escape(username)}</name>
            {privilege_xml}
            {password_xml}
          </user>
        </login>
      </system>
    ''')


@validate_call
def delete_local_user(username: str):
    """Delete exactly one Junos local user from candidate configuration.

    The surrounding transaction layer commits this candidate change, or
    discards it if Junos rejects the edit/commit.  ``delete`` also makes a
    stale deletion fail instead of silently succeeding for a missing user.
    """
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username is required")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in username):
        raise ValueError("Username contains control characters")

    return _edit_configuration(f'''
      <system xmlns="{NS_SYSTEM}">
        <login>
          <user xmlns:nc="{NS_RPC}" nc:operation="delete">
            <name>{escape(username)}</name>
          </user>
        </login>
      </system>
    ''')

def factory_reset(encrypted_password: str):
    """Replace candidate with a minimal bootable config retaining root access.

    The project Junos image accepts ``action=factory-default`` as a no-op and
    has no ``/etc/config/factory.conf`` file. Supplying the complete XML config
    with ``action=override`` is deterministic and does not depend on a
    platform-specific filesystem path. The caller commits this candidate as a
    separate RPC.
    """
    if not isinstance(encrypted_password, str) or not encrypted_password.startswith("$6$"):
        raise ValueError("The current Juniper root password uses an unsupported hash format")
    return open_rpc_tag(f'''
      <load-configuration action="override" format="xml">
        <configuration xmlns="{NS_ROOT}">
          <system xmlns="{NS_SYSTEM}">
            <root-authentication>
              <encrypted-password>{escape(encrypted_password)}</encrypted-password>
            </root-authentication>
          </system>
        </configuration>
      </load-configuration>
    ''')


def get_root_authentication_for_factory_reset():
    """Read only the current root password hash for an in-lock reset check.

    This helper is deliberately not exposed through PUBLIC_FUNCTIONS because
    the encrypted credential must never be returned to a browser.
    """
    return open_rpc_tag(f'''
      <get-config>
        <source><running/></source>
        <filter type="subtree">
          <configuration xmlns="{NS_ROOT}">
            <system xmlns="{NS_SYSTEM}">
              <root-authentication>
                <encrypted-password/>
              </root-authentication>
            </system>
          </configuration>
        </filter>
      </get-config>
    ''')


def set_factory_reset_root_hash(encrypted_password: str):
    """Put the verified existing root hash back into factory-default candidate."""
    if not isinstance(encrypted_password, str) or not encrypted_password.startswith("$6$"):
        raise ValueError("The current Juniper root password uses an unsupported hash format")
    return _edit_configuration(f'''
      <system xmlns="{NS_SYSTEM}">
        <root-authentication>
          <encrypted-password>{escape(encrypted_password)}</encrypted-password>
        </root-authentication>
      </system>
    ''')
