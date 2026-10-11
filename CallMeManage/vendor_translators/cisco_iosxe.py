import asyncio
import itertools
import ipaddress
import re
import xml.etree.ElementTree as ET
from tools.safe_xml import safe_fromstring
from xml.sax.saxutils import escape
from tools.prefix_to_netmask import prefix_translator, prefix_to_wildcard
from tools.ipv4_input import validate_prefix
from tools.hostname_policy import validate_hostname
from tools.dhcp_range import range_exclusions, validate_dhcp_network_gateway
from tools.dhcp_lease import lease_seconds_value
from tools.net_input_policy import (
    validate_ipv4,
    validate_ipv4_network,
    validate_ospf_area,
    validate_ospf_process_id,
    validate_distance,
    validate_netmask,
    validate_address_range,
    validate_config_name,
    validate_domain_name,
    validate_host_in_network,
    validate_object_ref,
    validate_psk,
)

from pydantic import StrictInt, validate_call
from typing import Awaitable, Callable, Literal


NS_RPC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NS_IETF_IF = "urn:ietf:params:xml:ns:yang:ietf-interfaces"
NS_OC_IF = "http://openconfig.net/yang/interfaces"
NS_OC_ETH = "http://openconfig.net/yang/interfaces/ethernet"
NS_OC_VLAN = "http://openconfig.net/yang/vlan"
NS_OC_SYS = "http://openconfig.net/yang/system"
NS_OC_LOCAL_ROUTING = "http://openconfig.net/yang/local-routing"
NS_NATIVE = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
NS_ACL = "http://cisco.com/ns/yang/Cisco-IOS-XE-acl"
NS_NAT = "http://cisco.com/ns/yang/Cisco-IOS-XE-nat"
NS_ZONE = "http://cisco.com/ns/yang/Cisco-IOS-XE-zone"
NS_POLICY = "http://cisco.com/ns/yang/Cisco-IOS-XE-policy"
NS_VLAN = "http://cisco.com/ns/yang/Cisco-IOS-XE-vlan"
NS_DHCP = "http://cisco.com/ns/yang/Cisco-IOS-XE-dhcp"
NS_ACL_OPER = "http://cisco.com/ns/yang/Cisco-IOS-XE-acl-oper"
NS_FW_OPER = "http://cisco.com/ns/yang/Cisco-IOS-XE-fw-oper"
NS_CRYPTO = "http://cisco.com/ns/yang/Cisco-IOS-XE-crypto"
NS_OSPF = "http://cisco.com/ns/yang/Cisco-IOS-XE-ospf"
NS_TUNNEL = "http://cisco.com/ns/yang/Cisco-IOS-XE-tunnel"
NS_SWITCH = "http://cisco.com/ns/yang/Cisco-IOS-XE-switch"
NS_SLA = "http://cisco.com/ns/yang/Cisco-IOS-XE-sla"
NS_SLA_OPER = "http://cisco.com/ns/yang/Cisco-IOS-XE-ip-sla-oper"


_msg_counter = itertools.count(1)


def next_msg_id() -> str:
    return str(next(_msg_counter))


def open_rpc_tag(
        xmltags: str,
        version: str = "1.0",
        xmlns: str = NS_RPC,
        encoding: str = "UTF-8"
):
    return F'''
<?xml version="{version}" encoding="{encoding}"?>
<rpc message-id="{next_msg_id()}" xmlns="{xmlns}">
    {xmltags}
</rpc>
'''


# (ปัญหาที่ 2 ขั้น B1 ใน planning/transaction_review.md) บอกอุปกรณ์ให้ "ย้อนกลับ
# ทั้งหมด" ถ้ามี element ไหนใน edit-config เดียวกันล้มเหลว
#
# ค่า default ของ <error-option> ตาม RFC 6241 §7.2 คือ "stop-on-error" ซึ่งหยุดตอน
# เจอ error ก็จริง แต่ "สิ่งที่ apply ไปแล้วยังอยู่" - แปลว่าคำสั่งที่รวมหลาย object
# ไว้ใน RPC เดียว (เช่น create_security_profile ที่มี 6 object) ที่ดูเหมือน atomic
# จริง ๆ แล้วไม่ atomic เลย ถ้าพังที่ object ที่ 4 จะเหลือ object 1-3 ค้างบนอุปกรณ์
#
# ใช้ได้เพราะอุปกรณ์จริงประกาศ capability นี้มาใน hello (ยืนยันจาก
# device_capability/ciscoHello.txt: urn:ietf:params:netconf:capability:
# rollback-on-error:1.0) - Huawei ก็ประกาศเหมือนกัน ส่วน Juniper ไม่ประกาศ แต่ไม่
# ต้องใช้อยู่แล้วเพราะมี candidate datastore + commit ที่ให้ atomicity อยู่แล้ว
#
# ลำดับ element ใน <edit-config> ตาม RFC 6241 §7.2 คือ
# target -> default-operation -> test-option -> error-option -> config
# จึงต้องวางไว้หลัง <target> และก่อน <config> เสมอ
ERROR_OPTION = "<error-option>rollback-on-error</error-option>"

# attribute ประกาศ namespace ของ NETCONF base ที่ต้องแปะบน element ที่ใช้ nc:operation
# (มีตัวแปร local ชื่อ nc ใน set_dns_config อยู่ก่อนแล้ว - ตัวนี้เป็นระดับโมดูลเพื่อให้
# ฟังก์ชันอื่นใช้ร่วมกันได้ ไม่ต้องประกาศซ้ำทุกที่)
NC = 'xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"' 


@validate_call
def datastore_tag(
        datastore: Literal["running", "candidate", "startup"] = "running"
):
    return f'''
    <target>
        <{datastore}/>
    </target>
    '''

def edit_config_tag(xmltags: str):
    return F'''
        <edit-config>
            <target>
                <running/>
            </target>
            {ERROR_OPTION}
            <config>
                {xmltags}
            </config>
        </edit-config>
'''

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
    return  open_rpc_tag('''
<get>
    <filter type="subtree">
        <routing-state xmlns="urn:ietf:params:xml:ns:yang:ietf-routing">
            <routing-instance>
                <ribs>
                    <rib>
                        <routes/>
                    </rib>
                </ribs>
            </routing-instance>
        </routing-state>
    </filter>
</get>
''')

# show arp table
def get_arp_table():
    return open_rpc_tag('''
<get>
    <filter type="subtree">
          <arp-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-arp-oper"/>
    </filter>                   
</get>
''')

def get_mac_table():
    return open_rpc_tag('''
        <get>
            <filter type="subtree">
                <matm-oper-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-matm-oper">
                    <matm-table>
                        <table-type>mat-vlan</table-type>
                        <vlan-id-number/>
                        <matm-mac-entry>
                            <mac/>
                            <mat-addr-type/>
                            <port/>
                        </matm-mac-entry>
                    </matm-table>
                </matm-oper-data>
            </filter>
        </get>
    ''')

def get_interface_list():
    return  open_rpc_tag('''
<get>
    <filter type="subtree">
        <interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
            <interface>
                <name/>
            </interface>
        </interfaces-state>
    </filter>
</get>
''')

# show interface information and status
def get_interface_information():
    return  open_rpc_tag('''
<get>
    <filter type="subtree">
        <interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
            <interface/>
        </interfaces-state>
    </filter>
</get>
''')

# show interface information in short (อยู่ในเกณฑ์ตัด)
def get_ip_interface_brief():
    return  open_rpc_tag('''
<get>
  <filter type="subtree">
    <interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">
      <interface>
        <name/>
        <admin-status/>
        <oper-status/>
        <ipv4/>
        <ipv4-subnet-mask/>
        <last-change/>
      </interface>
    </interfaces>
  </filter>
</get>
    ''')

# show device version
def get_device_version():
    return open_rpc_tag('''
<get>
  <filter type="subtree">
    <device-hardware-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-device-hardware-oper">
      <device-hardware>
        <device-system-data>
        </device-system-data>
      </device-hardware>
    </device-hardware-data>
  </filter>
</get>
    ''')

# CPU/RAM สำหรับ Basic Info dashboard (poll ทุก 10 วิจาก backend background
# poller - ดู conn_socket.py) - **ยังไม่เคยทดสอบกับอุปกรณ์จริง** (ไม่มี Cisco
# device ต่ออยู่ตอนที่เขียน - มีแค่ Juniper ให้ verify ได้) อ้างอิงจาก YANG module
# ที่รู้จักกันทั่วไป: memory จาก Cisco-IOS-XE-device-hardware-oper (module
# เดียวกับที่ get_device_version ใช้อยู่แล้วสำหรับ device-system-data - ขอ
# memory-statistics เพิ่มในคำขอเดียวกัน) ส่วน CPU แยกคนละ module
# (Cisco-IOS-XE-process-cpu-oper's cpu-usage/cpu-utilization) ต้อง verify/ปรับ
# ตาม rpc-error ถ้า path ไม่ตรงจริงตอนมีอุปกรณ์ Cisco ให้ทดสอบ
def get_cpu_memory_information():
    return open_rpc_tag('''
<get>
  <filter type="subtree">
    <device-hardware-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-device-hardware-oper">
        <device-hardware>
            <device-system-data>
                <current-time/>
                <boot-time/>
                <software-version/>
                <rommon-version/>
            </device-system-data>
        </device-hardware>
    </device-hardware-data>
    <cpu-usage xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-process-cpu-oper">
        <cpu-utilization>
        </cpu-utilization>
    </cpu-usage>
    <memory-statistics xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-memory-oper">
            <memory-statistic>
                <total-memory/>
                <used-memory/>
            </memory-statistic>
        </memory-statistics>
  </filter>
</get>
    ''')


# show device license
def get_device_license():
    return open_rpc_tag('''
<get>
  <filter type="subtree">
    <licensing xmlns="http://cisco.com/ns/yang/cisco-smart-license">
    </licensing>
  </filter>
</get>
    ''')

# set hostname
# (bug 12) เดิม interpolate hostname ลง XML ตรง ๆ ไม่ผ่าน escape() และไม่ตรวจอะไรเลย
# ทั้งที่ escape ถูก import ไว้แล้วตั้งแต่บรรทัด 5 และใช้อยู่ 35+ จุดในไฟล์นี้ - ผลคือ
# hostname ที่มี "<" ปิด element ได้จริง แล้วแทรก config อะไรก็ได้ที่อยู่ใต้ <native>
# (ทดสอบยืนยันแล้วว่าได้ XML ที่ valid สมบูรณ์ ส่งเข้าอุปกรณ์ได้ทันที) ตอนนี้กันไว้ 2 ชั้น:
# validate_hostname() ตัดอักขระอันตรายทิ้งตั้งแต่ต้นทาง (ด่านหลัก) แล้ว escape() เป็น
# ด่านสำรองเผื่อวันหนึ่งนโยบายถูกผ่อนให้กว้างขึ้น
@validate_call
def set_hostname(hostname: str):
    hostname = validate_hostname(hostname)
    return open_rpc_tag(F'''
<edit-config>
    {datastore_tag()}
    {ERROR_OPTION}
    <config>
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <hostname>{escape(hostname)}</hostname>
        </native>
    </config>
</edit-config>
    ''')

# |===== ตรวจชื่อ interface ของ Cisco (bug 13 - ส่วนเพิ่มเติม) =====|
#
# Cisco ต่างจาก Huawei/Juniper ตรงที่เอา interface_type ไปใช้เป็น "ชื่อ XML tag"
# (<GigabitEthernet><name>1</name></GigabitEthernet>) ไม่ใช่ text node แบบอีก 2 ยี่ห้อ
# ที่ต่อเป็นสตริงเดียว (<name>ge-0/0/1</name>) ผลที่ตามมาคือ:
#
#   escape() ใช้กับตำแหน่งชื่อ tag ไม่ได้เลย
#
# เพราะถ้าค่ามี < > แล้ว escape เป็น &lt; &gt; จะได้ tag ชื่อ "&lt;..." ซึ่ง XML พังทันที
# ด่านเดียวที่ใช้ได้ตรงนี้จึงเป็น "จำกัดรูปแบบตั้งแต่ต้นทาง" (เหตุผลเดียวกับที่ bug 12
# ต้องจำกัด charset ของ hostname แทนที่จะพึ่ง escape อย่างเดียว)
#
# ยืนยันของจริงก่อนแก้: ส่ง interface_type="GigabitEthernet><evil/><GigabitEthernet"
# ได้ payload ที่มี <GigabitEthernet><evil/><GigabitEthernet> จริง (parse แล้ว
# mismatched tag - ยิงเข้าอุปกรณ์ก็ได้แค่ error ไม่ได้ apply แต่เป็นการส่ง XML พังๆ
# ออกไปโดยไม่มีใครดักเลย และไม่มีอะไรบอกผู้ใช้ว่าผิดตรงไหน)
#
# รูปแบบที่ยอมรับตั้งตามที่ระบบใช้กันอยู่แล้วทั้ง frontend และ backend คือ
# _split_interface() / splitInterfaceName() ที่แยกด้วย r"^([A-Za-z-]+)(.*)$"
# (type = ตัวอักษรกับขีดกลาง เช่น GigabitEthernet, Port-channel, Vlan, Loopback,
# Tunnel ส่วน id = ส่วนที่เหลือ เช่น 1, 0/0/1, 1.100)
_INTERFACE_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z-]*$")
_INTERFACE_ID_RE = re.compile(r"^[0-9]+(?:[/.][0-9]+)*$")
_INTERFACE_FULLNAME_RE = re.compile(r"^[A-Za-z][A-Za-z-]*[0-9]+(?:[/.][0-9]+)*$")


def _interface_type_tag(interface_type: str) -> str:
    """ตรวจ interface_type ที่จะถูกใช้เป็นชื่อ XML tag - ต้องเข้มเป็นพิเศษเพราะ escape() ช่วยไม่ได้"""
    value = (interface_type or "").strip()
    if not _INTERFACE_TYPE_RE.fullmatch(value):
        raise ValueError(
            f"interface_type must contain only letters A-Z, a-z, and hyphens, "
            f"such as GigabitEthernet, Port-channel, Vlan (received: {interface_type!r})"
        )
    return value


def _interface_id_value(interface_id: str, field: str = "interface_id") -> str:
    """ตรวจส่วนหมายเลขของ interface (ค่าที่ลงใน <name>) เช่น 1, 0/0/1, 1.100"""
    value = (interface_id or "").strip()
    if not _INTERFACE_ID_RE.fullmatch(value):
        raise ValueError(
            f"{field} must contain only numbers separated by / or ., "
            f"such as 1, 0/0/1, 1.100 (received: {interface_id!r})"
        )
    return value


def _interface_fullname(interface_name: str, field: str = "interface_name") -> str:
    """ตรวจชื่อ interface แบบเต็ม (type+id ติดกัน) เช่น GigabitEthernet1, Vlan10"""
    value = (interface_name or "").strip()
    if not _INTERFACE_FULLNAME_RE.fullmatch(value):
        raise ValueError(
            f"{field} must be a full interface name, such as GigabitEthernet1, Vlan10 "
            f"(received: {interface_name!r})"
        )
    return value


def _interface_name(interface_type: str, interface_id: str) -> str:
    """ประกอบชื่อ interface เต็มจาก type+id หลังตรวจแล้ว - เทียบเท่า _interface_name()
    ของ huawei_vrp.py / juniper_junos.py ที่ Cisco ขาดมาตลอด"""
    return f"{_interface_type_tag(interface_type)}{_interface_id_value(interface_id)}"


# description function
def _description_xml(description: str | None) -> str:
    if not description:
        return ""
    if not 1 <= len(description) <= 200:
        raise ValueError("description must be between 1 and 200 characters")
    return f"<description>{escape(description)}</description>"


def _interface_description_xml(description: str | None) -> str:
    if description == "":
        return f'<description {NC} nc:operation="remove"/>'
    if description is not None and any(
        not (0x20 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD
             or 0x10000 <= ord(char) <= 0x10FFFF) for char in description
    ):
        raise ValueError("description contains an invalid XML/control character")
    return _description_xml(description)

# **รอบ 4 - user ชี้ว่าใช้ leaf ผิดตัวตั้งแต่ต้น**: 2 รอบก่อนหน้าตั้งค่า "system
# MTU" (<GigabitEthernet><mtu>, CLI: `mtu <value>`) แต่ตัวที่ OSPF ใช้เทียบตอน
# DBD exchange จริงๆ คือ **"IP MTU"** (`<GigabitEthernet><ip><mtu>`, CLI: `ip mtu
# <value>`) - คนละ leaf กันโดยสิ้นเชิงแม้ชื่อ XML tag จะเป็น "mtu" เหมือนกัน
# (ยืนยันจาก schema จริง: device_capability/cisco/Cisco-IOS-XE-interfaces.yang -
# leaf mtu ที่ line 3125 อยู่ใต้ "container ip" ตรงๆ, description ระบุชัดว่า
# "Set IP Maximum Transmission Unit" ต่างจากตัวเดิมที่ line 3825 ซึ่งอยู่ระดับ
# top-level ของ interface และ description เป็นแค่ "Set the interface Maximum
# Transmission Unit (MTU)" เฉยๆ) - เปลี่ยนมาเขียน <ip><mtu> แทนตามที่ user ยืนยัน
# ให้สลับไปใช้ตัวนี้แทนของเดิมไปเลย (ไม่ใช่เพิ่มเป็น field ที่ 2)
#
# ไม่ส่งมา (None) = ไม่สร้าง <mtu> เลย ใช้ค่า default ของอุปกรณ์ต่อไป
#
# **ยืนยันช่วงจริงสดกับ `BR2-Router` อีกรอบ** (ip mtu เป็นคนละ leaf จาก system
# mtu เดิม ต้องทดสอบใหม่ ไม่ใช้ 1500-9000 ที่เคยยืนยันไว้ของ system mtu ต่อ):
# ip mtu=68 -> สำเร็จ, 100/500/1499/1500/2000 -> สำเร็จทั้งหมด, 4000/8000/9000/
# 9216/18000 -> fail หมด - **root cause ของฝั่ง fail ไม่ใช่ขอบเขตของ ip mtu เอง
# แต่เป็น cross-field constraint จริงของ Cisco**: ip mtu ต้อง <= system mtu ของ
# interface นั้นเสมอ (`show interface` มาตรฐาน) - ยืนยันจริง: interface ทดสอบมี
# system mtu ค้างอยู่ที่ 2000 (จากการทดสอบ system-mtu รอบก่อนของ mtu feature นี้)
# พอดี ip mtu<=2000 สำเร็จหมด ip mtu>2000 fail หมด ตรงเป๊ะ - ไม่ใช่ปัญหาโค้ด
# floor 68 คือค่าจริงที่ยืนยันแล้วว่าอุปกรณ์รับ (ต่างจาก system mtu ที่ floor
# 1500 - ip mtu ไม่ถูกบังคับ floor แบบ Ethernet L2) ceiling ใช้ 9216 ตามช่วงที่
# YANG ประกาศไว้ (leaf mtu ใต้ container ip, Cisco-IOS-XE-interfaces.yang:3125)
# เพราะทดสอบ ceiling จริงไม่ได้ (ติด system mtu ของ interface ทดสอบที่ต่ำกว่า) -
# **ผู้ใช้ที่ตั้ง ip mtu สูงแล้วโดนอุปกรณ์ปฏิเสธ ให้เช็ค system mtu ของ interface
# นั้นก่อนว่าสูงพอหรือยัง** (หน้าเว็บนี้ไม่มีช่องตั้ง system mtu แยกแล้วตาม
# decision ที่ให้เปลี่ยนไปใช้ ip mtu แทนทั้งหมด)
def _mtu_xml(mtu: int | None) -> str:
    if mtu is None:
        return ""
    if not 68 <= mtu <= 9216:
        raise ValueError("MTU must be between 68 and 9216")
    return f"<mtu>{mtu}</mtu>"

# set interface static ip
@validate_call
def set_interface_static_ip(
        interface_type: str,
        interface_id: str,
        ip: str,
        mask: int,
        shutdown: bool = True,
        description: str | None = None,
        mtu: int | None = None,
        switchport_capable: bool = False,
):
     interface_type = _interface_type_tag(interface_type)
     interface_id = _interface_id_value(interface_id)
     ip = validate_ipv4(ip, "Interface IP")
     shutdown_xml = "<shutdown/>" if shutdown else '<shutdown xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"/>'
     description_xml = _interface_description_xml(description)
     mtu_xml = _mtu_xml(mtu)
     # อุปกรณ์ปฏิเสธการตั้ง IP บนพอร์ตที่ยังเป็น switchport ตรง ๆ ("To configure ip
     # address, set switchport to false 1st") ใส่ switchport-conf=false ไว้ในก้อน
     # เดียวกับ address จึงจบใน edit-config เดียวและได้ atomic จาก rollback-on-error
     # แทนที่จะให้หน้าเว็บยิง set_switchport นำหน้าอีกหนึ่ง RPC
     # Capability must come from the selected port, not its Ethernet name:
     # routed-only platforms/management ports reject the switchport subtree.
     switchport_off_xml = (
         "<switchport-conf><switchport>false</switchport></switchport-conf>"
         if switchport_capable and "Ethernet" in interface_type and "." not in interface_id else ""
     )
     return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <interface>
            <{interface_type}>
                <name>{interface_id}</name>
                {switchport_off_xml}
                {description_xml}
                <ip>
                {mtu_xml}
                <address>
                    <primary>
                    <address>{ip}</address>
                    <mask>{prefix_translator(mask)}</mask>
                    </primary>
                </address>
                </ip>
                {shutdown_xml}
            </{interface_type}>
            </interface>
        </native>
    '''))

# set interface get dhcp ip
@validate_call
def set_interface_ip_dhcp(
        interface_type: str,
        interface_id: str,
        description: str | None = None,
        mtu: int | None = None,
        shutdown: bool | None = None,
        switchport_capable: bool = False,
):
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    description_xml = _interface_description_xml(description)
    mtu_xml = _mtu_xml(mtu)
    # Omission preserves admin state for existing callers; the form sends it.
    shutdown_xml = "" if shutdown is None else (
        "<shutdown/>" if shutdown else '<shutdown xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"/>'
    )
    # Only switchable Ethernet ports need switchport=false; routed-only ports
    # must not receive this subtree.
    switchport_off_xml = (
        "<switchport-conf><switchport>false</switchport></switchport-conf>"
        if switchport_capable and "Ethernet" in interface_type and "." not in interface_id else ""
    )
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
          <interface>
            <{interface_type}>
              <name>{interface_id}</name>
              {switchport_off_xml}
              {description_xml}
              {shutdown_xml}
              <ip>
                {mtu_xml}
                <address>
                  <dhcp/>
                </address>
              </ip>
            </{interface_type}>
          </interface>
        </native>
    '''))

# set sub-interface ip
@validate_call
def set_sub_interface_ip(
        interface_type: str,
        interface_id: str,
        vlan_id: int,
        ip: str,
        prefix: int,
        native: bool = False,
        description: str | None = None,
        mtu: int | None = None,
):
    if not 1 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 1 and 4094")
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    ip = validate_ipv4(ip, "Sub-interface IP")
    native_xml = "<native/>" if native else ""
    description_xml = _interface_description_xml(description)
    mtu_xml = _mtu_xml(mtu)
    subinterface_id = f"{interface_id}.{vlan_id}"
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <interface>
            <{interface_type}>
                <name>{subinterface_id}</name>
                {description_xml}
                <encapsulation>
                    <dot1Q>
                        <vlan-id>{vlan_id}</vlan-id>
                        {native_xml}
                    </dot1Q>
                </encapsulation>
                <ip>
                    {mtu_xml}
                    <address>
                        <primary>
                            <address>{ip}</address>
                            <mask>{prefix_translator(prefix)}</mask>
                        </primary>
                    </address>
                </ip>
            </{interface_type}>
        </interface>
        </native>
    '''))

# ลบ logical interface ทั้งตัว (sub-interface/VLAN SVI) - ใช้ signature เดียวกับ
# juniper_junos.py's remove_interface_unit (whitelist ไว้แล้วใน PUBLIC_FUNCTIONS -
# แค่เพิ่มฝั่ง Cisco ให้ generic dispatch ใช้ได้ ไม่ต้องแก้ translator_service.py)
# Cisco ต่างจาก Juniper ตรงที่ VLAN SVI ใช้ interface_id เป็นเลข VLAN ตรงๆอยู่แล้ว
# (ไม่มี ".unit" ต่อท้ายแบบ sub-interface - "no interface Vlan10" ไม่ใช่
# "no interface Vlan10.10") เลย ignore unit ไปเลยถ้า interface_type เป็น "Vlan"
def remove_interface_unit(interface_type: str, interface_id: str, unit: int):
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    full_id = interface_id if interface_type == "Vlan" else f"{interface_id}.{unit}"
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <interface xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
            <{interface_type} nc:operation="remove">
              <name>{full_id}</name>
            </{interface_type}>
          </interface>
        </native>
    '''))

# เจอบั๊กจริง (user รายงาน): "ตั้งค่าผิดเป็น static/dhcp บน physical interface
# แล้วอยากเปลี่ยนไปใช้เป็น trunk สำหรับ sub-interface ล้วนๆ" แต่ไม่มีทางล้าง IP
# ออกจาก physical interface ให้กลับไปเหมือนไม่เคยตั้งค่าเลย - remove_interface_unit
# ข้างบนใช้ไม่ได้กับกรณีนี้เพราะลบทั้ง entry ของ interface ทิ้ง (nc:operation=
# "remove" ที่ระดับ <{interface_type}> เอง) ใช้ได้แค่กับ logical interface (sub-
# interface/VLAN SVI) ที่ไม่มี hardware ผูกอยู่จริง - physical interface (เช่น
# GigabitEthernet4) เป็น hardware port ที่มีอยู่ถาวร Cisco ไม่ยอมให้ลบ entry
# ทั้งก้อนทิ้งแน่นอน - ต้องล้างเฉพาะ <ip><address> (ครอบคลุมทั้ง <primary> แบบ
# static และ <dhcp/>) แทน **ไม่ใช่ nc:operation="remove" ที่ <ip> เอง** เพราะ NAT
# (ip nat inside/outside - apply_nat_interface) และ ACL (ip access-group -
# apply_acl_interface) ก็เป็น sibling ของ <address> อยู่ใต้ <ip> เหมือนกันทั้งหมด - ถ้าลบทั้ง <ip> จะ
# เผลอล้าง config พวกนั้นไปด้วยโดยไม่ตั้งใจ - สำหรับ DHCP relay (ip helper-address)
# หากส่ง helper_ips มาด้วย จะทำการล้าง helper-address ออกใน edit-config ก้อนเดียวกัน
# แบบ atomic ตามความต้องการของผู้ใช้ (ล้าง IP interface แล้ว helper-address ต้องหายไปด้วย)
# ไม่แตะ <shutdown>/<description> เลย เพราะ physical interface ที่จะใช้เป็น trunk
# รองรับ sub-interface ต้องยังคง "no shutdown" อยู่เสมอ (shutdown ทับจะพา sub-interface ทั้งหมดที่พ่วงอยู่ล่มไปด้วย)
def clear_interface_ip(
    interface_type: str,
    interface_id: str,
    helper_ips: list[str] | None = None,
    dhcp_pool_name: str | None = None,
    dhcp_pool_exclude: str | list[str] | None = None,
    layer3: bool = False,
    vlan_id: int | None = None,
    native: bool = False,
    shutdown: bool | None = None,
    description: str | None = None,
    reset_mtu: bool = False,
):
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    helpers_xml = ""
    if helper_ips:
        for hip in helper_ips:
            hip_str = (hip or "").strip()
            if not hip_str:
                continue
            ipaddress.IPv4Address(hip_str)  # validate
            helpers_xml += f'''
            <helper-address xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
              <address>{hip_str}</address>
            </helper-address>'''
    # pool ที่ผูกกับวงของ interface นี้อยู่คนละ subtree (native/ip/dhcp) แต่ราก
    # <native> เดียวกัน จึงลบไปพร้อมกันใน edit-config เดียวได้ ทำให้การกด Reset
    # หนึ่งครั้งเป็น RPC เดียวและ atomic จาก rollback-on-error แทนที่จะยิงล้าง IP
    # แล้วตามด้วยลบ pool เป็นคนละคำสั่ง ไม่ส่งชื่อ pool มาก็ได้ XML เท่าเดิมทุกไบต์
    pool_xml = _dhcp_pool_removal_xml(dhcp_pool_name, dhcp_pool_exclude) if dhcp_pool_name else ""
    switchport_xml = "<switchport-conf><switchport>false</switchport></switchport-conf>" if layer3 and "Ethernet" in interface_type and "." not in interface_id else ""
    if vlan_id is not None and not 1 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 1 and 4094")
    encapsulation_xml = f'<encapsulation><dot1Q><vlan-id>{vlan_id}</vlan-id>{"<native/>" if native else ""}</dot1Q></encapsulation>' if vlan_id is not None else ""
    admin_xml = "" if shutdown is None else "<shutdown/>" if shutdown else f'<shutdown {NC} nc:operation="remove"/>'
    desc_xml = _interface_description_xml(description)
    reset_mtu_xml = f'<mtu {NC} nc:operation="remove"/>' if reset_mtu else ""
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
        <interface>
            <{interface_type}>
                <name>{interface_id}</name>
                {switchport_xml}{encapsulation_xml}{admin_xml}{desc_xml}
                <ip>
                    {reset_mtu_xml}
                    <address xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"/>{helpers_xml}
                </ip>
            </{interface_type}>
        </interface>{pool_xml}
        </native>
    '''))

@validate_call
def remove_interface_mtu(interface_type: str, interface_id: str):
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <interface>
            <{interface_type}>
              <name>{escape(interface_id)}</name>
              <ip><mtu {NC} nc:operation="remove"/></ip>
            </{interface_type}>
          </interface>
        </native>
    '''))

@validate_call
def set_interface_l3_none(interface_type: str, interface_id: str,
                          helper_ips: list[str] | None = None,
                          dhcp_pool_name: str | None = None,
                          dhcp_pool_exclude: str | list[str] | None = None,
                          vlan_id: int | None = None, native: bool = False,
                          switchport_capable: bool = False,
                          shutdown: bool | None = None, description: str | None = None):
    return clear_interface_ip(interface_type, interface_id, helper_ips,
                              dhcp_pool_name, dhcp_pool_exclude, layer3=switchport_capable,
                              vlan_id=vlan_id, native=native, shutdown=shutdown, description=description, reset_mtu=True)


# set no shutdown interface
@validate_call
def set_no_shutdown(
        interface_type: str,
        interface_id: str,
        description: str | None = None,
):
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    description_xml = _description_xml(description)
    return open_rpc_tag(edit_config_tag(f'''
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
      <interface>
        <{interface_type}>
          <name>{interface_id}</name>
          {description_xml}
          <shutdown xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"/>
        </{interface_type}>
      </interface>
    </native>
    '''))

# set shutdown interface
@validate_call
def set_shutdown(
        interface_type: str,
        interface_id: str,
        description: str | None = None,
):
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    description_xml = _description_xml(description)
    return open_rpc_tag(edit_config_tag(f'''
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
      <interface>
        <{interface_type}>
          <name>{interface_id}</name>
          {description_xml}
          <shutdown/>
        </{interface_type}>
      </interface>
    </native>
'''))

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
    # administrative distance เป็น leaf "metric" (ไม่ใช่ "distance-admin" - element
    # นั้นไม่มีอยู่จริงใน Cisco-IOS-XE-ip.yang เลย ยืนยันจาก grep เปล่า) และอยู่
    # *ข้างใน* fwd-list เอง (ip-route-options-no-track-grouping ที่ fwd-list uses)
    # ไม่ใช่ sibling ของ fwd-list ใน ip-route-interface-forwarding-list แบบเดิม -
    # เจอจริงตอนทดสอบ live: ส่ง distance ไปแล้วอุปกรณ์ตอบ unknown-element
    # "distance-admin" กลับมาทันที
    # (bug 13) เดิมไม่ validate อะไรเลยสักฟิลด์ ต่างจาก Huawei/Juniper ที่ฟังก์ชัน
    # เดียวกันเรียก ipaddress ก่อนใช้งานเสมอ - ผลคือ prefix/next_hop/distance แทรก
    # XML element เข้าไปได้จริงทั้ง 3 ฟิลด์ (ยืนยันด้วยการรันจริง) และค่าที่ไม่ใช่ IP
    # อย่าง "999.999.999.999" หรือ distance="abc" หลุดไปตายเอาที่อุปกรณ์ด้วย rpc-error
    # ที่อ่านไม่รู้เรื่อง แทนที่จะ fail เร็วตั้งแต่ฝั่งเรา
    network = validate_ipv4_network(prefix, mask)

    # บังคับให้ต้องมีปลายทางอย่างน้อยหนึ่งอย่าง - เดิมไม่มีเงื่อนไขนี้ ปล่อยให้สร้าง
    # XML ที่ไม่มี <fwd-list> เลยได้ (route ที่ไม่มีปลายทาง) ทั้งที่ Huawei และ Juniper
    # ทั้งคู่ raise ValueError ข้อความเดียวกันนี้อยู่แล้ว
    if not next_hop and not (interface_type and interface_id):
        raise ValueError("next_hop or interface_type/interface_id is required")

    # administrative distance ของ Cisco เป็น uint8 range 1..255 (ยืนยันจาก
    # device_capability/cisco/Cisco-IOS-XE-ip.yang:1876-1881) - ช่วงนี้ไม่เท่ากับของ
    # Huawei/Juniper จึงส่งช่วงเข้าไปเองทุกครั้ง ไม่ใช้ค่า default ร่วมกัน
    distance_xml = ""
    if distance:
        distance_xml = f"<metric>{validate_distance(distance, 1, 255)}</metric>"

    next_hop_xml = ""
    if next_hop:
        next_hop_xml = f"<fwd-list><fwd>{validate_ipv4(next_hop, 'next_hop')}</fwd>{distance_xml}</fwd-list>"

    interface_xml = ""
    if interface_type and interface_id:
        # ใช้ _interface_name() ตัวเดียวกับที่ huawei/juniper มีอยู่แล้ว (Cisco เพิ่งมี
        # ตอนแก้ bug 13 ส่วนเพิ่มเติม) - ตรวจรูปแบบตั้งแต่ต้นทางแทนการพึ่ง escape() อย่างเดียว
        interface_xml = f"<fwd-list><fwd>{_interface_name(interface_type, interface_id)}</fwd>{distance_xml}</fwd-list>"

    # Edit ต้องไม่ให้ frontend ยิง remove แล้วค่อย set เป็นคนละ RPC เพราะถ้า set
    # ล้มเหลว route เดิมจะหายไปแล้ว รับ key เดิมเข้ามาและรวมการเปลี่ยนไว้ใน
    # edit-config เดียวซึ่งมี rollback-on-error:
    # - key เดิมเท่ากับ key ใหม่: replace list entry ทั้งก้อน (ล้าง next-hop เก่า)
    # - key เปลี่ยน: delete entry เดิมและสร้าง entry ใหม่ใน RPC เดียว
    replace_values = (replace_prefix, replace_mask)
    old_route_xml = ""
    route_operation = ""
    if any(value is not None for value in replace_values):
        if any(value is None for value in replace_values):
            raise ValueError("replace_prefix and replace_mask must be provided together")
        old_network = validate_ipv4_network(replace_prefix, replace_mask)
        if old_network == network:
            route_operation = f' {NC} nc:operation="replace"'
        else:
            old_route_xml = f'''
          <ip-route-interface-forwarding-list {NC} nc:operation="delete">
            <prefix>{old_network.network_address}</prefix>
            <mask>{old_network.netmask}</mask>
          </ip-route-interface-forwarding-list>'''

    return open_rpc_tag(edit_config_tag(f'''
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
      <ip>
        <route>
          {old_route_xml}
          <ip-route-interface-forwarding-list{route_operation}>
            <prefix>{network.network_address}</prefix>
            <mask>{network.netmask}</mask>
            {next_hop_xml}
            {interface_xml}
          </ip-route-interface-forwarding-list>
        </route>
      </ip>
    </native>
    '''))

# ลบ route ทิ้งทั้งตัว (ตรงกับ CLI `no ip route <prefix> <mask> ...`) -
# ip-route-interface-forwarding-list keyed ด้วย "prefix mask" เท่านั้น (ยืนยันจาก
# Cisco-IOS-XE-ip.yang) ลบด้วย key คู่นี้พอ ไม่ต้องระบุ next-hop/interface - ลบทั้ง
# entry รวมทุก fwd-list (next-hop) ที่ผูกกับ prefix/mask นี้ไปด้วย
# (bug 13) เดิมฟังก์ชันนี้ไม่มีแม้แต่ @validate_call (ต่างจาก set_static_route ที่มี)
# จึงไม่มี type check ของ pydantic เลย และ prefix ถูก interpolate ดิบ ๆ แทรก XML ได้
@validate_call
def remove_static_route(prefix: str, mask: int):
    network = validate_ipv4_network(prefix, mask)
    return open_rpc_tag(edit_config_tag(f'''
    <native xmlns="{NS_NATIVE}">
      <ip>
        <route>
          <ip-route-interface-forwarding-list xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
            <prefix>{network.network_address}</prefix>
            <mask>{network.netmask}</mask>
          </ip-route-interface-forwarding-list>
        </route>
      </ip>
    </native>
    '''))

# (ระลอก C2 ใน planning/transaction_review.md) ตั้งค่า OSPF process ทั้งก้อนใน RPC เดียว
#
# เดิม flow "แก้ไข OSPF" ยิงได้ถึง 12 RPC แยกกัน: remove_ospf_process 1 ครั้ง แล้ววน
# set_ospf_network ทีละ network + set_ospf_default_originate + redistribute อีก 2 +
# passive_interface - จำนวนคำสั่งแปรผันตามจำนวน network ที่ผู้ใช้กรอก ยิ่งเยอะยิ่งมี
# โอกาสพังกลางทาง และเมื่อพังจะได้ routing ที่ครึ่ง ๆ กลาง ๆ (บาง network เข้า OSPF
# แล้ว บางตัวยัง) ซึ่งบน production คือ routing loop หรือเส้นทางหาย
#
# ทุกอย่างที่ flow นี้ตั้งอยู่ใต้ <process-id> เดียวกันหมด (network / router-id /
# default-information / redistribute / passive-interface-config) จึงยุบเป็น
# nc:operation="replace" ที่ระดับ <process-id> ก้อนเดียวได้ - "replace" แปลว่าอุปกรณ์
# จะแทนที่เนื้อหาทั้งหมดใต้ process-id นั้นด้วยสิ่งที่ส่งไป ซึ่งตรงกับที่ flow ต้องการ
# พอดี (เดิมต้อง remove ทั้ง process ก่อนเพราะ network/passive list merge แบบ "เพิ่ม"
# ไม่ใช่แทนที่ - replace แก้ปัญหานั้นโดยไม่ต้องลบ)
#
# ไม่ได้ใช้ set_ospf_* ตัวเดิมแทน เพราะแต่ละตัวยังจำเป็นอยู่สำหรับการแก้ทีละส่วน
# (เช่นเปิด/ปิด redistribute เฉย ๆ โดยไม่แตะ network) - ตัวนี้เป็นคำสั่งระดับ "ตั้งทั้ง
# process" ที่ฟอร์มใช้ ไม่ใช่ตัวแทนของทุกตัว
@validate_call
def replace_ospf_process(
    process_id: StrictInt | str,
    networks: list[dict],
    router_id: str | None = None,
    default_originate: bool = False,
    redistribute_static: bool = False,
    redistribute_rip: bool = False,
    passive_default: bool = False,
    no_passive: list[str] | None = None,
) -> str:
    if not networks:
        raise ValueError("At least 1 network must be specified")

    network_xml = ""
    for entry in networks:
        ip = validate_ipv4(entry.get("network"), "network")
        wildcard = validate_ipv4(entry.get("wildcard"), "wildcard")
        area_value = validate_ospf_area(entry.get("area"))
        network_xml += (
            f"<network><ip>{ip}</ip><wildcard>{wildcard}</wildcard>"
            f"<area>{area_value}</area></network>"
        )

    router_id_xml = ""
    if router_id:
        router_id_xml = f"<router-id>{validate_ipv4(router_id, 'router_id')}</router-id>"

    default_xml = ""
    if default_originate:
        # (bug 73) เดิมใส่ <always> ตายตัว ทั้งที่ฟอร์มเขียนแค่ "Default Originate"
        # ผู้ใช้ไม่ได้เลือกและไม่รู้ตัว - always ประกาศ default route ออกไปแม้ตัวเองไม่มี
        # default route อยู่จริง ความหมายต่างกันมาก ผู้ใช้ยืนยันให้ตัดออกเหลือ originate เฉย ๆ
        default_xml = "<default-information><originate/></default-information>"

    redistribute_parts = ""
    if redistribute_static:
        redistribute_parts += "<static></static>"
    if redistribute_rip:
        redistribute_parts += "<rip></rip>"
    redistribute_xml = f"<redistribute>{redistribute_parts}</redistribute>" if redistribute_parts else ""

    passive_xml = ""
    if passive_default:
        blocks = "".join(
            f"<{_interface_type_tag(iface_type)}><name>{_interface_id_value(iface_id)}</name></{_interface_type_tag(iface_type)}>"
            for iface_type, iface_id in (_split_interface(n) for n in (no_passive or []) if n)
        )
        disable_xml = f"<disable-interface>{blocks}</disable-interface>" if blocks else ""
        passive_xml = f"<passive-interface-config><default></default>{disable_xml}</passive-interface-config>"

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <router>
                <router-ospf xmlns="{NS_OSPF}">
                    <ospf>
                        <process-id {NC} nc:operation="replace">
                            <id>{validate_ospf_process_id(process_id)}</id>
                            {router_id_xml}
                            {network_xml}
                            {default_xml}
                            {redistribute_xml}
                            {passive_xml}
                        </process-id>
                    </ospf>
                </router-ospf>
            </router>
        </native>
    '''))


# ตาราง "static route ทุกตัว (ตั้งค่าไว้ ไม่ว่าจะ active หรือไม่)" - ต่างจาก
# get_routing_table ที่อ่านจาก RIB จริง (ietf-routing) ซึ่งมีแค่ route ที่ active
# เท่านั้น (เจอจริงบน HQ-R1: route ที่ next-hop resolve ไม่ได้ผ่าน path ที่ไม่ใช่
# default route เอง จะไม่ active เลย - "show ip static route" ขึ้น [N] แต่
# get_routing_table ไม่เห็นเลย) query นี้อ่านจาก config ตรงๆ (native/ip/route)
# ซึ่งมีครบทุก route ที่เคยตั้งไว้ไม่ว่าจะ active จริงหรือเปล่า
def get_static_route_configuration():
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <ip>
                <route>
                    <ip-route-interface-forwarding-list></ip-route-interface-forwarding-list>
                </route>
            </ip>
        </native>
    </filter>
</get>
''')

def get_dhcp_pool_information():
    return open_rpc_tag(F'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <ip>
                <dhcp>
                    <excluded-address xmlns="{NS_DHCP}">
                    </excluded-address>
                    <pool xmlns="{NS_DHCP}">
                    </pool>
                </dhcp>
            </ip>
        </native>         
    </filter>                        
</get>
''')

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
        lease_infinite: bool = False,
        previous: dict | None = None,
):
    if not 1 <= len(name) <= 236:
        raise ValueError("DHCP pool name must contain 1-236 characters")
    if previous is not None and (previous.get("pool", {}).get("id") != name or replace_name):
        raise ValueError("Cisco DHCP pool edit must retain the existing pool name")

    # (bug 78 / ระลอก C) replace_name: ใส่เมื่อเปลี่ยนวง DHCP pool เพื่อลบ pool เดิมออก
    # ใน edit-config เดียวกัน (Atomic 1 action = 1 RPC)
    # remove กับ merge/create อยู่คนละ key (id) จึงไม่แย่ง node กัน
    removal_xml = ""
    old = (replace_name or "").strip()
    if old and old != name:
        if not 1 <= len(old) <= 236:
            raise ValueError("Previous DHCP pool name must be between 1 and 236 characters")
        removal_xml = f'''
          <pool xmlns="{NS_DHCP}" {NC} nc:operation="remove">
            <id>{escape(old)}</id>
          </pool>'''

    validation_gateway = gateway if gateway is not None else str(ipaddress.IPv4Network(network, strict=True).network_address + 1)
    dhcp_network, validated_gateway = validate_dhcp_network_gateway(network, validation_gateway)
    gateway_ip = validated_gateway if gateway is not None else None
    range_exclude = range_exclusions(dhcp_network, start_address, end_address)

    # IOS-XE represents durations using days/hours/minutes, not seconds.
    seconds = lease_seconds_value(lease_minutes, lease_seconds, lease_days)
    lease_xml = ""
    if lease_infinite:
        if seconds is not None:
            raise ValueError("Infinite lease cannot be combined with a duration")
        lease_xml = "<lease><infinite/></lease>"
    elif seconds is not None:
        if seconds % 60:
            raise ValueError("Cisco lease time must be a whole number of minutes")
        days, remainder = divmod(seconds // 60, 1440)
        hours, minutes = divmod(remainder, 60)
        if days > 365:
            raise ValueError("Cisco lease time exceeds 365 days 23 hours 59 minutes")
        lease_xml = (
            "<lease><lease-value>"
            f"<days>{days}</days><hours>{hours}</hours><minutes>{minutes}</minutes>"
            "</lease-value></lease>"
        )

    dns_servers = [dns] if isinstance(dns, str) else (dns or [])
    if isinstance(dns, str) and not dns.strip():
        raise ValueError("At least one DNS server is required")
    dns_servers = list(dict.fromkeys(str(ipaddress.IPv4Address(server)) for server in dns_servers))
    if len(dns_servers) > 3:
        raise ValueError("At most 3 DNS servers are supported")
    dns_xml = "\n".join(
        f"<dns-server-list>{ipaddress.IPv4Address(server)}</dns-server-list>"
        for server in dns_servers
    )

    def _parse_interval(item: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
        parts = item.split("-", maxsplit=1)
        low_addr = ipaddress.IPv4Address(parts[0].strip())
        if low_addr not in dhcp_network:
            raise ValueError(f"Excluded address {low_addr} must be inside the DHCP network")
        high_addr = ipaddress.IPv4Address(parts[1].strip()) if len(parts) > 1 else low_addr
        if high_addr not in dhcp_network:
            raise ValueError(f"Excluded address {high_addr} must be inside the DHCP network")
        if int(low_addr) > int(high_addr):
            raise ValueError(f"Excluded range start {low_addr} must not exceed end {high_addr}")
        return low_addr, high_addr

    exclusions_configured = exclude is not None or start_address is not None or end_address is not None

    exclude_xml_parts = []
    if exclusions_configured or previous is None:
        explicit_items = [exclude] if isinstance(exclude, str) else list(exclude or [])
        explicit_intervals = [_parse_interval(x) for x in explicit_items]
        range_intervals = [_parse_interval(x) for x in range_exclude]

        # รวม overlapping/adjacent ranges เฉพาะใน desired state
        all_desired_raw = [*explicit_intervals, *range_intervals]
        desired_merged = []
        if all_desired_raw:
            int_intervals = [(int(low), int(high)) for low, high in all_desired_raw]
            for low, high in sorted(int_intervals):
                if desired_merged and low <= desired_merged[-1][1] + 1:
                    desired_merged[-1] = (desired_merged[-1][0], max(desired_merged[-1][1], high))
                else:
                    desired_merged.append((low, high))

        desired_keys = {(low, high) for low, high in desired_merged}

        stale_removals = []
        prev_keys = set()
        first_host = int(dhcp_network.network_address) + 1
        last_host = int(dhcp_network.broadcast_address) - 1

        if previous is not None:
            prev_exclude_raw = previous.get("exclude", [])
            if isinstance(prev_exclude_raw, str):
                prev_exclude_raw = [prev_exclude_raw]
            prev_exclude_list = list(prev_exclude_raw or [])

            prev_start = previous.get("start_address")
            prev_end = previous.get("end_address")
            old_derived_keys = None
            if prev_start and prev_end:
                try:
                    old_derived_strs = range_exclusions(dhcp_network, prev_start, prev_end)
                    old_derived_keys = {
                        (int(low), int(high)) for low, high in [_parse_interval(s) for s in old_derived_strs]
                    }
                except ValueError:
                    old_derived_keys = None

            for item in prev_exclude_list:
                parts = item.split("-", maxsplit=1)
                low_addr = ipaddress.IPv4Address(parts[0].strip())
                high_addr = ipaddress.IPv4Address(parts[1].strip()) if len(parts) > 1 else low_addr
                low, high = int(low_addr), int(high_addr)
                if low > high:
                    raise ValueError("Excluded range start must not exceed end")
                prev_keys.add((low, high))

                if (low, high) in desired_keys:
                    continue

                # Check ownership: only derived exclusions of this pool may be removed.
                # Explicit or unowned brownfield exclusions must be preserved.
                is_owned = False
                if low_addr not in dhcp_network or high_addr not in dhcp_network or low < first_host or high > last_host:
                    is_owned = False
                elif old_derived_keys is not None:
                    if (low, high) in old_derived_keys:
                        is_owned = True
                else:
                    if (start_address or end_address or exclude is not None) and (low == first_host or high == last_host):
                        is_owned = True

                if is_owned:
                    stale_removals.append(item)

        desired_to_merge = []
        if previous is not None:
            for low, high in desired_merged:
                if (low, high) not in prev_keys:
                    desired_to_merge.append((low, high))
        else:
            desired_to_merge = desired_merged

        if stale_removals:
            exclude_xml_parts.append(_dhcp_exclusion_removal_entries(stale_removals))

        for low, high in desired_to_merge:
            low_addr = ipaddress.IPv4Address(low)
            high_addr = ipaddress.IPv4Address(high)
            if low == high:
                exclude_xml_parts.append(
                    f"<low-address-list><low-address>{low_addr}</low-address></low-address-list>"
                )
            else:
                exclude_xml_parts.append(
                    "<low-high-address-list>"
                    f"<low-address>{low_addr}</low-address>"
                    f"<high-address>{high_addr}</high-address>"
                    "</low-high-address-list>"
                )

    excluded_xml = ""
    if previous is not None:
        if lease_xml:
            lease_xml = lease_xml.replace("<lease>", f'<lease {NC} nc:operation="replace">', 1)
        elif previous.get("pool", {}).get("lease") is not None:
            lease_xml = f'<lease {NC} nc:operation="remove"/>'
    managed_replace = f' {NC} nc:operation="replace"' if previous is not None else ""
    if exclude_xml_parts:
        excluded_xml = (
            f'<excluded-address xmlns="{NS_DHCP}">'
            + "".join(exclude_xml_parts)
            + "</excluded-address>"
        )

    router_xml = (f'<default-router {NC} nc:operation="replace"><default-router-list>{gateway_ip}</default-router-list></default-router>'
                  if gateway_ip is not None else f'<default-router {NC} nc:operation="remove"/>')
    dns_option_xml = (f'<dns-server {NC} nc:operation="replace">{dns_xml}</dns-server>'
                      if dns_servers else f'<dns-server {NC} nc:operation="remove"/>')
    return open_rpc_tag(edit_config_tag(f'''
    <native xmlns="{NS_NATIVE}">
      <ip>
        <dhcp>
          {excluded_xml}
          {removal_xml}
          <pool xmlns="{NS_DHCP}">
            <id>{escape(name)}</id>
            {router_xml}
            {dns_option_xml}
            <network>
              <primary-network{managed_replace}>
                <number>{dhcp_network.network_address}</number>
                <mask>{dhcp_network.netmask}</mask>
              </primary-network>
            </network>
            {lease_xml}
          </pool>
        </dhcp>
      </ip>
    </native>
  '''))

# ลบ pool ทิ้ง (ตรงกับ CLI `no ip dhcp pool <name>`) - pool list keyed ด้วย
# "id" (=name) ตรงกับ set_dhcp_pool ข้างบน - network ไม่ได้ใช้ฝั่ง Cisco (รับไว้
# ให้ signature ตรงกับ Juniper ที่ต้องใช้ network เป็น key แทน)
# แยกส่วนสร้าง XML ของการลบ pool ออกมาเพื่อให้ clear_interface_ip เอาไปประกอบใน
# edit-config เดียวกับการล้าง IP ได้ (ทั้ง interface และ pool อยู่ใต้ <native>
# เดียวกัน) เนื้อในเหมือนเดิมทุกบรรทัด ไม่ได้เปลี่ยนพฤติกรรมของ remove_dhcp_pool
def _dhcp_exclusion_removal_entries(exclude):
    excluded_addresses = []
    if exclude:
        excluded_addresses = [exclude] if isinstance(exclude, str) else exclude
    exclude_xml_parts = []
    for excluded in excluded_addresses:
        addresses = excluded.split("-", maxsplit=1)
        low = ipaddress.IPv4Address(addresses[0].strip())
        if len(addresses) == 1:
            exclude_xml_parts.append(
                '<low-address-list xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">'
                f"<low-address>{low}</low-address></low-address-list>"
            )
            continue
        high = ipaddress.IPv4Address(addresses[1].strip())
        if low == high:
            exclude_xml_parts.append(
                '<low-address-list xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">'
                f"<low-address>{low}</low-address></low-address-list>"
            )
            continue
        exclude_xml_parts.append(
            '<low-high-address-list xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">'
            f"<low-address>{low}</low-address><high-address>{high}</high-address></low-high-address-list>"
        )
    return "".join(exclude_xml_parts)

def _dhcp_pool_removal_xml(name: str, exclude: str | list[str] | None = None) -> str:
    if not 1 <= len(name) <= 236:
        raise ValueError("DHCP pool name must contain 1-236 characters")

    # excluded-address เป็น global บน Cisco (พี่น้องของ pool ใน <dhcp> ไม่ได้ซ้อน
    # อยู่ข้างในตัว pool - ยืนยันจริงจาก HQ-R1: ลบ pool ทิ้งแล้ว "ip dhcp
    # excluded-address ..." ยังค้างอยู่ ไม่ได้ถูกลบไปด้วย) เลยต้องระบุ exclude ที่
    # เคยตั้งไว้มาลบทิ้งเองตรงๆด้วย ถ้าไม่ระบุ (None) จะไม่แตะ exclude เลย -
    # frontend (dhcpFormModal.jsx's edit flow) ต้องส่ง exclude เดิมของ pool นี้มา
    # เสมอตอนแก้ไข ไม่งั้น exclude เก่าจะค้าง + exclude ใหม่ (ถ้ามี) มาซ้อนกัน
    excluded_addresses = []
    if exclude:
        excluded_addresses = [exclude] if isinstance(exclude, str) else exclude
    exclude_xml_parts = []
    for excluded in excluded_addresses:
        addresses = excluded.split("-", maxsplit=1)
        low = ipaddress.IPv4Address(addresses[0].strip())
        if len(addresses) == 1:
            exclude_xml_parts.append(
                '<low-address-list xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">'
                f"<low-address>{low}</low-address></low-address-list>"
            )
            continue
        high = ipaddress.IPv4Address(addresses[1].strip())
        if low == high:
            exclude_xml_parts.append(
                '<low-address-list xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">'
                f"<low-address>{low}</low-address></low-address-list>"
            )
            continue
        exclude_xml_parts.append(
            '<low-high-address-list xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">'
            f"<low-address>{low}</low-address><high-address>{high}</high-address></low-high-address-list>"
        )
    excluded_xml = ""
    if exclude_xml_parts:
        excluded_xml = f'<excluded-address xmlns="{NS_DHCP}">' + "".join(exclude_xml_parts) + "</excluded-address>"

    return f'''
          <ip>
            <dhcp>
              {excluded_xml}
              <pool xmlns="{NS_DHCP}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                <id>{escape(name)}</id>
              </pool>
            </dhcp>
          </ip>'''


def remove_dhcp_pool(name: str, network: str | None = None, exclude: str | list[str] | None = None):
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">{_dhcp_pool_removal_xml(name, exclude)}
        </native>
    '''))

# DHCP relay = ip helper-address บน interface (คนละกลไกกับ dhcp pool - ส่ง broadcast
# DHCP ของ client ต่อไปยัง DHCP server จริงที่อยู่ต่าง subnet) - path คือ
# native/interface/<type>/ip/helper-address/address (list, key=address; Cisco-IOS-XE-
# interfaces.yang:2816) - ยังไม่ได้ทดสอบกับอุปกรณ์จริง
def set_dhcp_relay(interface_type: str, interface_id: str, helper_ip: str, previous: dict | None = None):
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    helper_ip = str(ipaddress.IPv4Address(helper_ip))
    targets = {}
    if previous is not None:
        old_type = _interface_type_tag(previous.get("interface_type", ""))
        old_id = _interface_id_value(previous.get("interface_id", ""))
        old_ip = str(ipaddress.IPv4Address(previous.get("helper_ip", "")))
        if (old_type, old_id, old_ip) != (interface_type, interface_id, helper_ip):
            targets.setdefault((old_type, old_id), []).append(
                f'<helper-address {NC} nc:operation="remove"><address>{old_ip}</address></helper-address>'
            )
    targets.setdefault((interface_type, interface_id), []).append(
        f"<helper-address><address>{helper_ip}</address></helper-address>"
    )
    nodes = "".join(
        f"<{kind}><name>{identity}</name><ip>{''.join(changes)}</ip></{kind}>"
        for (kind, identity), changes in targets.items()
    )
    return open_rpc_tag(edit_config_tag(f'<native xmlns="{NS_NATIVE}"><interface>{nodes}</interface></native>'))

# ลบ helper-address ตัวเดียวออกจาก interface (interface หนึ่งมีได้หลาย helper-
# address พร้อมกัน - list keyed ด้วย "address" เอง) nc:operation="remove" ต้อง
# อยู่ที่ <helper-address> (list item) ไม่ใช่ <address> (key leaf ข้างใน)
def remove_dhcp_relay(interface_type: str, interface_id: str, helper_ip: str):
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    ipaddress.IPv4Address(helper_ip)  # validate

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <interface>
            <{interface_type}>
              <name>{interface_id}</name>
              <ip>
                <helper-address xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                  <address>{helper_ip}</address>
                </helper-address>
              </ip>
            </{interface_type}>
          </interface>
        </native>
    '''))

def get_dns_information():
    return open_rpc_tag('''
        <get>
            <filter type="subtree">
                <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
                    <ip>
                        <domain>
                            <lookup/>
                            <name/>
                        </domain>
                        <dns>
                            <server/>
                        </dns>
                        <name-server/>
                    </ip>
                </native>
            </filter>
        </get>
    ''')

# (bug 15 - เจอเพิ่มตอนสแกนฟิลด์ IP ทั้งไฟล์) เดิมไม่มีทั้ง validate และ escape เลย
# lookup_ip เป็น DNS server address ที่ต้องเป็น IPv4 จริง ส่วน your_domain ลงไปใน
# <name> ตรง ๆ แทรก XML ได้
# หมายเหตุ: lookup_interface รับเข้ามาแต่ไม่เคยถูกใช้ในฟังก์ชันนี้เลย (ฟอร์มฝั่งหน้าเว็บ
# จึงมีช่องที่กรอกไปก็ไม่มีผล) - ไม่ลบออกในรอบนี้เพราะการเปลี่ยน signature กระทบ schema
# ที่ functions_for_vendor() ส่งให้ frontend ใช้สร้างฟอร์ม ควรแก้พร้อมฝั่งหน้าเว็บทีเดียว
@validate_call
def set_dns_lookup(
    lookup_interface: str,
    your_domain: str,
    lookup_ip: str
):
    lookup_ip = validate_ipv4(lookup_ip, "lookup_ip")
    your_domain = validate_domain_name(your_domain, "your_domain")

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <ip>
                <domain>
                    <name>{escape(your_domain)}</name>
                    <lookup></lookup> 
                </domain>
                <dns>
                    <server/> 
                </dns>
                <name-server>
                    <no-vrf>{lookup_ip}</no-vrf>
                </name-server>
            </ip>
        </native>
    '''))

# ตั้งค่า DNS ทั้งชุดใน edit-config เดียว (สำหรับหน้า DNS ที่กด Apply ทีเดียวส่งหมด)
# path ตรงกับที่ get_dns_information() query มา (native/ip/domain|dns|name-server)
# ยืนยันแล้วว่าทั้ง domain/dns/name-server เป็นลูกตรงของ ip (Cisco-IOS-XE-ip.yang)
# - ยังไม่ได้ทดสอบกับอุปกรณ์จริง จุดที่ต้องระวังตอนทดสอบ:
#   1. domain_name ใช้ leaf <name> (deprecated ใน schema แต่ตรงกับที่ get อ่าน) -
#      ถ้าอุปกรณ์ปฏิเสธ (แบบ obsolete leaf ของ ipsec-profile ที่เคยเจอ) ให้ย้ายไป
#      ใช้ name-container/name-no-vrf แทน
#   2. dns_server เป็น presence container - เปิด=ส่ง tag เปล่า, ปิด=ต้อง remove
#      (nc:operation) ไม่ใช่ส่งค่า false
#   3. name-server เป็น leaf-list - ใช้ nc:operation="replace" เพื่อให้ทั้ง list
#      ตรงกับที่กรอกมาเป๊ะ (ไม่ merge/ต่อท้ายของเดิม) กรอกว่างหมด=ลบทุกตัว
def set_dns_config(
    domain_lookup: bool = True,
    dns_server: bool = False,
    domain_name: str | None = None,
    name_servers: list[str] | None = None,
):
    nc = 'xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"'

    lookup_xml = f"<lookup>{str(domain_lookup).lower()}</lookup>"
    if domain_name:
        domain_name = validate_domain_name(domain_name, "domain_name")
    # ช่อง Domain Name ว่าง = ลบชื่อเดิมออก (ผู้เรียกมีหน้า DNS ที่เดียว ซึ่งส่งค่าทั้งฟอร์มเสมอ)
    # เดิมไม่ส่ง <name> เลยแล้ว merge ทำให้ชื่อเดิมค้าง - ล้างช่องแล้ว Apply ชื่อเดิมกลับมา
    # remove เป็น no-op ถ้าไม่มีชื่ออยู่แล้ว จึงส่งได้เสมอ
    name_xml = (
        f"<name>{escape(domain_name)}</name>" if domain_name
        else f'<name {nc} nc:operation="remove"/>'
    )
    domain_xml = f"<domain>{lookup_xml}{name_xml}</domain>"

    if dns_server:
        dns_xml = "<dns><server/></dns>"
    else:
        dns_xml = f'<dns><server {nc} nc:operation="remove"/></dns>'

    servers = name_servers or []
    if len(servers) > 6:
        raise ValueError("Cisco supports a maximum of 6 name servers")
    for server in servers:
        ipaddress.IPv4Address(server)  # validate ทุกตัวก่อนส่ง
    ns_entries = "".join(f"<no-vrf>{server}</no-vrf>" for server in servers)
    name_server_xml = f'<name-server {nc} nc:operation="replace">{ns_entries}</name-server>'

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            {domain_xml}
            {dns_xml}
            {name_server_xml}
          </ip>
        </native>
    '''))

# ========= RIP Routing =========
def get_rip_information():
    return open_rpc_tag('''
<get>
    <filter type="subtree">
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <rip xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rip">
                </rip>
            </router>
        </native>
    </filter>
</get>
''')

# rip_route.jsx ต้องใช้ get_rip_information + get_routing_table +
# get_ip_interface_brief พร้อมกันเสมอ - รวมเป็น request เดียวเหมือน
# get_ospf_dashboard (ดู comment ที่นั่นสำหรับเหตุผลเต็มๆ) ลด round-trip จาก 3
# เหลือ 1
def get_rip_dashboard():
    return open_rpc_tag('''
<get>
    <filter type="subtree">
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <rip xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rip">
                </rip>
            </router>
        </native>
        <routing-state xmlns="urn:ietf:params:xml:ns:yang:ietf-routing">
            <routing-instance>
                <ribs>
                    <rib>
                        <routes/>
                    </rib>
                </ribs>
            </routing-instance>
        </routing-state>
        <interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">
            <interface>
                <name/>
                <admin-status/>
                <oper-status/>
                <ipv4/>
                <ipv4-subnet-mask/>
                <last-change/>
            </interface>
        </interfaces>
    </filter>
</get>
''')

# ลบทั้ง RIP process ทีเดียว (เทียบเท่า "no router rip") - rip เป็น presence
# container เดี่ยว ไม่ใช่ list แบบ OSPF's process-id เลยไม่มี key ให้ระบุ ลบ
# container ตัวเองตรงๆพอ (ใช้เป็นขั้นตอนแรกของ edit flow เหมือน remove_ospf_process)
def remove_rip_routing():
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <router>
            <rip xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rip" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
            </rip>
          </router>
        </native>
    '''))

# ทั้ง "เปิดใช้ครั้งแรก" และ "แก้ไขของเดิม" ใช้ฟังก์ชันนี้ตัวเดียวและได้ RPC เดียว
# เสมอ เพราะ <rip> ถูกเขียนด้วย nc:operation="replace" ซึ่งตาม RFC 6241 §7.2 แปลว่า
# "เนื้อในของ node นี้เท่ากับที่ส่งมาเป๊ะ" - ของเดิมที่ไม่ได้ส่งมาด้วยหายไปเองใน
# RPC เดียวกัน และถ้า node ยังไม่มีอยู่ก็สร้างให้ จึงไม่ต้องยิง remove_rip_routing
# นำหน้าอีกต่อไป
#
# เดิมหน้าเว็บยิง 3 คำสั่งเรียงกัน (remove -> set -> set_rip_redistribute_static)
# ซึ่งไม่ atomic เลย ถ้าคำสั่งที่ 2 ล้มหลังคำสั่งที่ 1 สำเร็จ RIP จะหายทั้งก้อน
# โดยไม่มีอะไรมาแทน และผู้ใช้กู้เองไม่ได้ - ใช้ /transaction แทนก็ไม่ได้เพราะตัวรวม
# edit ของ Cisco รับเฉพาะ interface กับ ip (ดู backend/interface_atomic.py)
# ทางเดียวที่เหลือจึงเป็น replace ตามข้อตกลงออกแบบเดียวกับ replace_ospf_process
# และ set_static_route
#
# redistribute static ถูกดึงเข้ามาอยู่ใน RPC เดียวกันด้วย (เดิมเป็นคำสั่งที่ 3
# แยกต่างหาก) - ไม่ติ๊ก = ไม่ส่ง <redistribute> มาเลย แล้ว replace ล้างของเดิมให้
# เอง จึงปิดได้จริงโดยไม่ต้องมีคำสั่ง "ปิด" แยก
@validate_call
def set_rip_routing(
    networks: list[str],
    version: Literal[1, 2] = 2,
    auto_summary: bool = False,
    default_information_originate: bool = False,
    redistribute_static: bool = False,
    passive_default: bool = False,
    no_passive: list[str] | None = None,
    passive_interfaces: list[str] | None = None,
) -> str:
    validated_networks = [ipaddress.IPv4Address(network) for network in networks]
    network_xml = "\n".join(
        f"<network><ip>{network}</ip></network>" for network in validated_networks
    )
    auto_summary_xml = f"<auto-summary-fix>{str(auto_summary).lower()}</auto-summary-fix>"
    default_info_xml = "<default-information><originate/></default-information>" if default_information_originate else ""
    redistribute_xml = "<redistribute><static></static></redistribute>" if redistribute_static else ""
    passive_xml = ""
    if passive_interfaces is not None:
        # ยืนยันกับ IOS-XE จริงด้วย edit-config test-only แล้ว: interfaces leaf-list
        # ผ่าน แต่ disable/passive-interface ถูก reject เป็น unknown-element แม้ CLI
        # จะแสดง `no passive-interface`. จึงแปล UI default+exception เป็นรายชื่อขา
        # passive แบบ explicit ซึ่งมีผลต่อ RIP เหมือนกันและอ่านกลับผ่าน NETCONF ได้
        interfaces_xml = "".join(
            f"<interfaces>{escape(name.strip())}</interfaces>"
            for name in passive_interfaces
            if name and name.strip()
        )
        passive_xml = f"<passive-interface>{interfaces_xml}</passive-interface>" if interfaces_xml else ""
    elif passive_default:
        # Compatibility สำหรับ caller เก่าที่เปิด default โดยไม่มี exception เท่านั้น
        # (หากมี exception ต้องส่ง passive_interfaces ที่คำนวณครบแล้ว)
        if no_passive:
            raise ValueError("Cisco RIP no-passive exceptions require passive_interfaces")
        passive_xml = "<passive-interface><default-all-interfaces/></passive-interface>"
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
          <router>
            <rip xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rip" {NC} nc:operation="replace">
              <version>{version}</version>
              {network_xml}
              {auto_summary_xml}
              {default_info_xml}
              {redistribute_xml}
              {passive_xml}
            </rip>
          </router>
        </native>
    '''))

# redistribute/static เป็น presence container (Cisco-IOS-XE-rip.yang:957-961,
# grouping default-redistribute-grouping ที่ container redistribute ของ router
# rip เรียกใช้ตรงๆ) - ส่ง tag ว่างเพื่อเปิด, nc:operation="remove" เพื่อปิด
# (pattern เดียวกับ presence container อื่นๆ ที่ verify แล้วในไฟล์นี้)
@validate_call
def set_rip_redistribute_static(enabled: bool = True) -> str:
    static_xml = (
        "<static></static>"
        if enabled
        else '<static xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"></static>'
    )
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
          <router>
            <rip xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rip">
              <redistribute>
                {static_xml}
              </redistribute>
            </rip>
          </router>
        </native>
    '''))

# ========= OSPF Routing =========
def get_ospf_information():
    return open_rpc_tag('''
<get>
    <filter type="subtree">
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                    <ospf>
                    </ospf>
                </router-ospf>
            </router>
        </native>
    </filter>
</get>
''')

# ospf_route.jsx ต้องใช้ get_ospf_information + get_routing_table +
# get_ip_interface_brief พร้อมกันเสมอ (3 round-trip ทุกครั้งที่เปิด/รีเฟรชหน้า) -
# NETCONF filter เดียวใส่หลาย top-level container ต่างโมดูลกันเป็น sibling ได้
# อยู่แล้ว (ตัวอย่างเดิมที่มีอยู่แล้ว: get_switchport_information รวม native+
# OpenConfig) รวม 3 อย่างนี้เป็น request เดียวลด round-trip เหลือ 1 - ตัด
# processing time ที่ backend/อุปกรณ์ประมวลผลตามลำดับ (asyncio.Lock ต่อ session
# ใน conn_socket.py ทำให้คำสั่งที่ยิงพร้อมกันจาก frontend ก็ยังถูกคิวทีละคำสั่ง
# อยู่ดี - ยิ่งเน็ตช้า/latency สูงยิ่งคูณเข้าไปอีก) ลงจาก 3 เหลือ 1 เท่านั้น
def get_ospf_dashboard():
    return open_rpc_tag('''
<get>
    <filter type="subtree">
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                    <ospf>
                    </ospf>
                </router-ospf>
            </router>
        </native>
        <routing-state xmlns="urn:ietf:params:xml:ns:yang:ietf-routing">
            <routing-instance>
                <ribs>
                    <rib>
                        <routes/>
                    </rib>
                </ribs>
            </routing-instance>
        </routing-state>
        <interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">
            <interface>
                <name/>
                <admin-status/>
                <oper-status/>
                <ipv4/>
                <ipv4-subnet-mask/>
                <last-change/>
            </interface>
        </interfaces>
    </filter>
</get>
''')

# ลบทั้ง OSPF process ทีเดียว (เทียบเท่า "no router ospf <id>") - ใช้เป็นขั้นตอน
# แรกของ edit flow: ลบ process เดิมทิ้งทั้งก้อนก่อน แล้วค่อยสร้างใหม่ทั้งหมดด้วยค่า
# ที่แก้ไข (pattern เดียวกับ remove_dhcp_pool/remove_static_route ที่ผ่านมา)
# key ของ process-id list คือ "id" ยืนยันจาก Cisco-IOS-XE-ospf.yang (บรรทัด
# 3538/3845: `list process-id { key "id"; ... }`)
def remove_ospf_process(process_id: StrictInt | str):
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <router>
                <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                    <ospf>
                        <process-id xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                            <id>{validate_ospf_process_id(process_id)}</id>
                        </process-id>
                    </ospf>
                </router-ospf>
            </router>
        </native>
    '''))

# (bug 15 - เจอเพิ่มตอนสแกนฟิลด์ IP ทั้งไฟล์) เดิมทั้ง router_id, network และ wildcard
# ถูก interpolate ดิบ ๆ ไม่มีการตรวจเลย ทั้งที่ทั้งสามเป็นค่ารูปแบบ IPv4 - router-id เป็น
# dotted quad ตามรูปแบบ IPv4 (แม้ความหมายจะไม่ใช่ address จริง) ส่วน wildcard เป็น
# inverse mask ซึ่งตรวจรูปแบบด้วยตัวเดียวกันได้
@validate_call
def set_ospf_network(
    process_id: StrictInt | str,
    router_id: str,
    network: str,
    wildcard: str,
    area: StrictInt | str
):
    area = validate_ospf_area(area)
    router_id = validate_ipv4(router_id, "router_id")
    network = validate_ipv4(network, "network")
    wildcard = validate_ipv4(wildcard, "wildcard")

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                    <ospf>
                        <process-id>
                            <id>{validate_ospf_process_id(process_id)}</id>
                            <router-id>{router_id}</router-id>
                            <network>
                                <ip>{network}</ip>
                                <wildcard>{wildcard}</wildcard>
                                <area>{area}</area>
                            </network>
                        </process-id>
                    </ospf>      
                </router-ospf>     
            </router>
        </native>
    '''))


def set_ospf_passive_interface(
        process_id: StrictInt | str,
        no_passive: list[str] = None,
):
  # disable-interface ใช้ ios:multiple-interfaces-with-dependency-grouping (YANG
  # list ต่อ interface type คนละ container - list GigabitEthernet {key name},
  # list Vlan {key name}, ...) - ตัวแทน "หลาย interface" ที่ถูกต้องคือ sibling
  # element ซ้ำ <GigabitEthernet><name>2</name></GigabitEthernet><GigabitEthernet>
  # <name>3</name></GigabitEthernet> คนละตัว ไม่ใช่ <name> หลายอันซ้อนใน container
  # เดียว - รับ full interface name (เช่น "GigabitEthernet2") แล้วแยก type/id เอง
  # ด้วย _split_interface() รองรับได้ทุก interface type ไม่ผูกกับ GigabitEthernet
  # แบบเดิม
  no_pass_interface = ""
  if no_passive:
    blocks = "".join(
        f"<{iface_type}><name>{iface_id}</name></{iface_type}>"
        for iface_type, iface_id in (_split_interface(name) for name in no_passive if name)
    )
    no_pass_interface = f"<disable-interface>{blocks}</disable-interface>"

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                    <ospf>
                        <process-id>
                            <id>{validate_ospf_process_id(process_id)}</id>
                            <passive-interface-config>
                            <default></default>
                            {no_pass_interface}
                            </passive-interface-config>
                        </process-id>
                    </ospf>      
                </router-ospf>     
            </router>
        </native>
    '''))

def set_ospf_default_originate(
    process_id: StrictInt | str,
    value: bool = False
):
    if value:
      return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                    <ospf>
                        <process-id>
                            <id>{validate_ospf_process_id(process_id)}</id>
                            <default-information>
                                <originate>
                                    <always></always>
                                </originate>
                            </default-information>
                        </process-id>
                    </ospf>
                </router-ospf>
            </router>
        </native>
    '''))

# redistribute/static เป็น presence container (Cisco-IOS-XE-ospf.yang:2782-2789,
# grouping config-ospf-redist-static-grouping ที่ config-ospf-redistribute-
# grouping เรียกใช้ - อยู่ใต้ process-id เดียวกับ router-id/network/default-
# information ที่ set_ospf_network/set_ospf_default_originate ใช้อยู่แล้ว) -
# ส่ง tag ว่างเพื่อเปิด, nc:operation="remove" เพื่อปิด
@validate_call
def set_ospf_redistribute_static(process_id: StrictInt | str, enabled: bool = True) -> str:
    static_xml = (
        "<static></static>"
        if enabled
        else '<static xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"></static>'
    )
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                    <ospf>
                        <process-id>
                            <id>{validate_ospf_process_id(process_id)}</id>
                            <redistribute>
                            {static_xml}
                            </redistribute>
                        </process-id>
                    </ospf>
                </router-ospf>
            </router>
        </native>
    '''))

# redistribute/rip เป็น presence container เดียวกับ redistribute/static
# (Cisco-IOS-XE-ospf.yang:2773-2780, grouping config-ospf-redist-rip-grouping
# ที่ config-ospf-redistribute-grouping เรียกใช้ - ใช้ config-ospf-redist-common-
# grouping ตัวเดียวกับ static ด้วย) - ส่ง tag ว่างเพื่อเปิด, nc:operation="remove"
# เพื่อปิด ตรงกับ pattern ของ set_ospf_redistribute_static เป๊ะ
@validate_call
def set_ospf_redistribute_rip(process_id: StrictInt | str, enabled: bool = True) -> str:
    rip_xml = (
        "<rip></rip>"
        if enabled
        else '<rip xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"></rip>'
    )
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                    <ospf>
                        <process-id>
                            <id>{validate_ospf_process_id(process_id)}</id>
                            <redistribute>
                            {rip_xml}
                            </redistribute>
                        </process-id>
                    </ospf>
                </router-ospf>
            </router>
        </native>
    '''))

# ========= Access Control List =========
_ACL_NAMED_PROTOCOLS = Literal[
    "ahp", "eigrp", "esp", "gre", "icmp", "igmp", "ip",
    "ipinip", "nos", "ospf", "pcp", "pim", "tcp", "udp",
]
_ACL_TCP_PROTOCOL_VALUES = ("tcp", 6)
_ACL_PORT_PROTOCOL_VALUES = ("tcp", "udp", 6, 17)

def _acl_source_xml(address: str, wildcard: str | None):
    if address == "any":
        return "<any/>"
    if wildcard:
        return f"<ipv4-address>{address}</ipv4-address><mask>{wildcard}</mask>"
    return f"<host-address>{address}</host-address>"

def _acl_std_source_xml(address: str, wildcard: str | None):
    if address == "any":
        return "<any/>"
    if wildcard:
        return f"<ipv4-address-prefix>{address}</ipv4-address-prefix><mask>{wildcard}</mask>"
    return f"<host-address>{address}</host-address>"

def _acl_destination_xml(address: str, wildcard: str | None):
    if address == "any":
        return "<dst-any/>"
    if wildcard:
        return f"<dest-ipv4-address>{address}</dest-ipv4-address><dest-mask>{wildcard}</dest-mask>"
    return f"<dst-host-address>{address}</dst-host-address>"

def get_acl_information():
    return open_rpc_tag(F'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <ip>
                <access-list></access-list>
            </ip>
        </native>
    </filter>
</get>
''')

def get_acl_reference_information(
    name: str | None = None,
    acl_type: Literal["standard", "extended"] | None = None,
):
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <interface></interface>
            <zone>
                <security xmlns="{NS_ZONE}"></security>
            </zone>
            <zone-pair>
                <security xmlns="{NS_ZONE}"></security>
            </zone-pair>
            <ip>
                <access-list></access-list>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            <list-interface>
                                <list></list>
                            </list-interface>
                            <list-pool>
                                <list></list>
                            </list-pool>
                        </source>
                    </inside>
                </nat>
            </ip>
            <policy>
                <class-map xmlns="{NS_POLICY}"></class-map>
                <policy-map xmlns="{NS_POLICY}"></policy-map>
            </policy>
        </native>
    </filter>
</get>
''')


def _build_cisco_std_seq_rule_xml(
    sequence: int,
    action: Literal["permit", "deny"],
    source: str = "any",
    source_wildcard: str | None = None,
    log: bool = False,
    remark: str | None = None,
    operation: str | None = None,
) -> str:
    source_xml = _acl_std_source_xml(source, source_wildcard)
    log_xml = "<log/>" if log else ""
    remark_xml = f"<remark>{escape(remark)}</remark>" if remark else ""
    op_attr = f' xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="{operation}"' if operation else ""
    return f'''
                <access-list-seq-rule{op_attr}>
                  <sequence>{sequence}</sequence>
                  {remark_xml}
                  <{action}>
                    <std-ace>
                      {source_xml}
                      {log_xml}
                    </std-ace>
                  </{action}>
                </access-list-seq-rule>'''


def _build_cisco_ext_seq_rule_xml(
    sequence: int,
    action: Literal["permit", "deny"],
    protocol: _ACL_NAMED_PROTOCOLS | int = "ip",
    source: str = "any",
    source_wildcard: str | None = None,
    destination: str = "any",
    destination_wildcard: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    established: bool = False,
    log: bool = False,
    remark: str | None = None,
    operation: str | None = None,
) -> str:
    source_xml = _acl_source_xml(source, source_wildcard)
    destination_xml = _acl_destination_xml(destination, destination_wildcard)
    src_port_xml = f"<src-eq>{source_port}</src-eq>" if source_port is not None else ""
    dst_port_xml = f"<dst-eq>{destination_port}</dst-eq>" if destination_port is not None else ""
    established_xml = "<established/>" if established else ""
    log_xml = "<log/>" if log else ""
    remark_xml = f"<remark>{escape(remark)}</remark>" if remark else ""
    op_attr = f' xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="{operation}"' if operation else ""
    return f'''
                <access-list-seq-rule{op_attr}>
                  <sequence>{sequence}</sequence>
                  {remark_xml}
                  <ace-rule>
                    <action>{action}</action>
                    <protocol>{protocol}</protocol>
                    {source_xml}
                    {src_port_xml}
                    {destination_xml}
                    {dst_port_xml}
                    {established_xml}
                    {log_xml}
                  </ace-rule>
                </access-list-seq-rule>'''


def _validate_cisco_acl_args(
    name: str,
    sequence: int,
    action: Literal["permit", "deny"],
    protocol: _ACL_NAMED_PROTOCOLS | int,
    source: str,
    source_wildcard: str | None,
    destination: str,
    destination_wildcard: str | None,
    source_port: int | None,
    destination_port: int | None,
    established: bool,
    remark: str | None,
    acl_type: Literal["standard", "extended"],
    source_prefix: int | None = None,
    destination_prefix: int | None = None,
) -> tuple[str, str | None, str | None]:
    name = validate_object_ref(name, "ACL name")
    if not 1 <= sequence <= 2147483647:
        raise ValueError("sequence must be between 1 and 2147483647")
    if remark is not None and not 1 <= len(remark) <= 100:
        raise ValueError("remark must be between 1 and 100 characters")

    # Mutual exclusivity of prefix and wildcard
    if source_prefix is not None and source_wildcard is not None:
        raise ValueError("source_prefix and source_wildcard cannot be used together")
    if destination_prefix is not None and destination_wildcard is not None:
        raise ValueError("destination_prefix and destination_wildcard cannot be used together")

    if source == "any" and (source_prefix is not None or source_wildcard is not None):
        raise ValueError("source_prefix/source_wildcard are not allowed when source is 'any'")

    if acl_type == "standard":
        if destination != "any" or destination_wildcard is not None or destination_prefix is not None:
            raise ValueError("destination is not supported for standard ACL")
        if source_port is not None or destination_port is not None:
            raise ValueError("source_port/destination_port are not supported for standard ACL")
        if established:
            raise ValueError("established is not supported for standard ACL")
        if protocol != "ip":
            raise ValueError("protocol is not supported for standard ACL")
    else:
        if destination == "any" and (destination_prefix is not None or destination_wildcard is not None):
            raise ValueError("destination_prefix/destination_wildcard are not allowed when destination is 'any'")
        if isinstance(protocol, int) and not 0 <= protocol <= 255:
            raise ValueError("protocol number must be between 0 and 255")

        ports_allowed = protocol in _ACL_PORT_PROTOCOL_VALUES
        if (source_port is not None or destination_port is not None) and not ports_allowed:
            raise ValueError("source_port/destination_port only apply to tcp or udp")
        if established and protocol not in _ACL_TCP_PROTOCOL_VALUES:
            raise ValueError("established only applies to tcp")

    if source != "any":
        ipaddress.IPv4Address(source)
    if destination != "any":
        ipaddress.IPv4Address(destination)

    # Resolve source wildcard
    if source_prefix is not None:
        val_pfx = validate_prefix(source_prefix, "source_prefix")
        final_source_wildcard = None if val_pfx == 32 else prefix_to_wildcard(val_pfx)
    else:
        final_source_wildcard = source_wildcard
        if final_source_wildcard:
            ipaddress.IPv4Address(final_source_wildcard)

    # Resolve destination wildcard
    if destination_prefix is not None:
        val_pfx = validate_prefix(destination_prefix, "destination_prefix")
        final_destination_wildcard = None if val_pfx == 32 else prefix_to_wildcard(val_pfx)
    else:
        final_destination_wildcard = destination_wildcard
        if final_destination_wildcard:
            ipaddress.IPv4Address(final_destination_wildcard)

    return name, final_source_wildcard, final_destination_wildcard


@validate_call
def set_acl_rule(
        name: str,
        sequence: int,
        action: Literal["permit", "deny"],
        protocol: _ACL_NAMED_PROTOCOLS | int = "ip",
        source: str = "any",
        source_wildcard: str | None = None,
        destination: str = "any",
        destination_wildcard: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        established: bool = False,
        log: bool = False,
        remark: str | None = None,
        acl_type: Literal["standard", "extended"] = "extended",
        source_prefix: int | None = None,
        destination_prefix: int | None = None,
        reference_config: str | None = None,
        expected_revision: str | None = None,
) -> str:
    # reference_config (2026-09, ดู vendor_translators/cisco_zbf.py) - กัน ACE ที่
    # ZBF ใช้งานอยู่ (ผ่าน match access-group ตรงๆ หรือผ่าน nested Class Map) ถูกแก้
    # จากหน้า Stateless ACL/API โดยไม่ผ่าน ZBF Writer ซึ่งจะเปลี่ยน enforcement ของ
    # Firewall โดยที่ผู้ใช้ไม่รู้ตัว - ไม่มีค่า = ข้ามการตรวจ (ใช้กับ /validate เท่านั้น)
    if reference_config is not None:
        from vendor_translators.cisco_zbf import resolve_cisco_acl_safe_mutation
        resolve_cisco_acl_safe_mutation(reference_config, name, expected_revision)

    name, source_wildcard, destination_wildcard = _validate_cisco_acl_args(
        name, sequence, action, protocol, source, source_wildcard,
        destination, destination_wildcard, source_port, destination_port,
        established, remark, acl_type, source_prefix, destination_prefix
    )

    if acl_type == "standard":
        seq_rule_xml = _build_cisco_std_seq_rule_xml(sequence, action, source, source_wildcard, log, remark)
        type_tag = "standard"
    else:
        seq_rule_xml = _build_cisco_ext_seq_rule_xml(
            sequence, action, protocol, source, source_wildcard,
            destination, destination_wildcard, source_port, destination_port,
            established, log, remark
        )
        type_tag = "extended"

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <access-list>
              <{type_tag} xmlns="{NS_ACL}">
                <name>{escape(name)}</name>
                {seq_rule_xml}
              </{type_tag}>
            </access-list>
          </ip>
        </native>
    '''))


@validate_call
def create_acl_rule(
        name: str,
        sequence: int,
        action: Literal["permit", "deny"],
        protocol: _ACL_NAMED_PROTOCOLS | int = "ip",
        source: str = "any",
        source_wildcard: str | None = None,
        destination: str = "any",
        destination_wildcard: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        established: bool = False,
        log: bool = False,
        remark: str | None = None,
        acl_type: Literal["standard", "extended"] = "extended",
        source_prefix: int | None = None,
        destination_prefix: int | None = None,
        reference_config: str | None = None,
        expected_revision: str | None = None,
) -> str:
    # reference_config (2026-09) - ดู set_acl_rule ด้านบน (เหตุผลเดียวกัน)
    if reference_config is not None:
        from vendor_translators.cisco_zbf import resolve_cisco_acl_safe_mutation
        resolve_cisco_acl_safe_mutation(reference_config, name, expected_revision)

    name, source_wildcard, destination_wildcard = _validate_cisco_acl_args(
        name, sequence, action, protocol, source, source_wildcard,
        destination, destination_wildcard, source_port, destination_port,
        established, remark, acl_type, source_prefix, destination_prefix
    )

    if acl_type == "standard":
        seq_rule_xml = _build_cisco_std_seq_rule_xml(
            sequence, action, source, source_wildcard, log, remark, operation="create"
        )
        type_tag = "standard"
    else:
        seq_rule_xml = _build_cisco_ext_seq_rule_xml(
            sequence, action, protocol, source, source_wildcard,
            destination, destination_wildcard, source_port, destination_port,
            established, log, remark, operation="create"
        )
        type_tag = "extended"

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <access-list>
              <{type_tag} xmlns="{NS_ACL}">
                <name>{escape(name)}</name>
                {seq_rule_xml}
              </{type_tag}>
            </access-list>
          </ip>
        </native>
    '''))


@validate_call
def replace_acl_rule(
        name: str,
        sequence: int,
        action: Literal["permit", "deny"],
        protocol: _ACL_NAMED_PROTOCOLS | int = "ip",
        source: str = "any",
        source_wildcard: str | None = None,
        destination: str = "any",
        destination_wildcard: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        established: bool = False,
        log: bool = False,
        remark: str | None = None,
        acl_type: Literal["standard", "extended"] = "extended",
        original_name: str | None = None,
        original_sequence: int | None = None,
        original_acl_type: Literal["standard", "extended"] | None = None,
        source_prefix: int | None = None,
        destination_prefix: int | None = None,
        reference_config: str | None = None,
        expected_revision: str | None = None,
) -> str:
    name, source_wildcard, destination_wildcard = _validate_cisco_acl_args(
        name, sequence, action, protocol, source, source_wildcard,
        destination, destination_wildcard, source_port, destination_port,
        established, remark, acl_type, source_prefix, destination_prefix
    )
    if original_name is None:
        original_name = name
    else:
        original_name = validate_object_ref(original_name, "Previous ACL name")
    if original_sequence is None:
        original_sequence = sequence
    elif not 1 <= original_sequence <= 2147483647:
        raise ValueError("original_sequence must be between 1 and 2147483647")
    if original_acl_type is None:
        original_acl_type = acl_type

    # reference_config (2026-09) - ตรวจทั้ง ACL ต้นทาง (ถูกลบ ACE ออก) และปลายทาง
    # (ถูกเพิ่ม ACE เข้า) เมื่อ identity เปลี่ยน ACL คนละตัว - เกณฑ์เดียวกับ
    # set_acl_rule ทุกประการ (revision เทียบเฉพาะ original_name ที่เป็นตัวเดิมจริง)
    if reference_config is not None:
        from vendor_translators.cisco_zbf import resolve_cisco_acl_safe_mutation
        resolve_cisco_acl_safe_mutation(reference_config, original_name, expected_revision)
        if name != original_name:
            resolve_cisco_acl_safe_mutation(reference_config, name, None)

    identity_unchanged = (
        original_name == name and
        original_sequence == sequence and
        original_acl_type == acl_type
    )

    if identity_unchanged:
        if acl_type == "standard":
            seq_rule_xml = _build_cisco_std_seq_rule_xml(
                sequence, action, source, source_wildcard, log, remark, operation="replace"
            )
            type_tag = "standard"
        else:
            seq_rule_xml = _build_cisco_ext_seq_rule_xml(
                sequence, action, protocol, source, source_wildcard,
                destination, destination_wildcard, source_port, destination_port,
                established, log, remark, operation="replace"
            )
            type_tag = "extended"

        return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <access-list>
              <{type_tag} xmlns="{NS_ACL}">
                <name>{escape(name)}</name>
                {seq_rule_xml}
              </{type_tag}>
            </access-list>
          </ip>
        </native>
    '''))
    else:
        if acl_type == "standard":
            create_rule_xml = _build_cisco_std_seq_rule_xml(
                sequence, action, source, source_wildcard, log, remark, operation="create"
            )
        else:
            create_rule_xml = _build_cisco_ext_seq_rule_xml(
                sequence, action, protocol, source, source_wildcard,
                destination, destination_wildcard, source_port, destination_port,
                established, log, remark, operation="create"
            )

        delete_rule_xml = f'''
                <access-list-seq-rule xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="delete">
                  <sequence>{original_sequence}</sequence>
                </access-list-seq-rule>'''

        if original_name == name and original_acl_type == acl_type:
            return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <access-list>
              <{acl_type} xmlns="{NS_ACL}">
                <name>{escape(name)}</name>
                {delete_rule_xml}
                {create_rule_xml}
              </{acl_type}>
            </access-list>
          </ip>
        </native>
    '''))
        else:
            return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <access-list>
              <{original_acl_type} xmlns="{NS_ACL}">
                <name>{escape(original_name)}</name>
                {delete_rule_xml}
              </{original_acl_type}>
              <{acl_type} xmlns="{NS_ACL}">
                <name>{escape(name)}</name>
                {create_rule_xml}
              </{acl_type}>
            </access-list>
          </ip>
        </native>
    '''))


@validate_call
def create_acl(
    name: str,
    rules: list[dict],
    acl_type: Literal["standard", "extended"] = "extended",
    reference_config: str | None = None,
) -> str:
    # reference_config (2026-09) - ปกติ nc:operation="create" จะถูกอุปกรณ์ปฏิเสธเองถ้า
    # ชื่อนี้มีอยู่แล้ว แต่ตรวจล่วงหน้าเพื่อให้ error ชัดเจนกว่า (แยกกรณี "มี ACL นี้อยู่
    # แล้วและ ZBF กำลังใช้งาน" ออกจาก error ทั่วไปของอุปกรณ์)
    if reference_config is not None:
        from vendor_translators.cisco_zbf import resolve_cisco_acl_mutation_guard
        resolve_cisco_acl_mutation_guard(reference_config, name)

    name = validate_object_ref(name, "ACL name")
    if not rules:
        raise ValueError("rules list cannot be empty")

    seen_seqs = set()
    for rule in rules:
        seq_raw = rule.get("sequence")
        if seq_raw is None or str(seq_raw).strip() == "":
            raise ValueError("each rule must have a sequence")
        try:
            seq = int(seq_raw)
        except (ValueError, TypeError):
            raise ValueError("sequence must be an integer")
        if not 1 <= seq <= 2147483647:
            raise ValueError("sequence must be between 1 and 2147483647")
        if seq in seen_seqs:
            raise ValueError(f"duplicate sequence {seq} in rules")
        seen_seqs.add(seq)

    sorted_rules = sorted(rules, key=lambda r: int(r["sequence"]))

    rules_xml_parts = []
    for r in sorted_rules:
        seq = int(r["sequence"])
        action = r.get("action")
        if action not in ("permit", "deny"):
            raise ValueError("action must be 'permit' or 'deny'")
        protocol = r.get("protocol", "ip")
        source = r.get("source", "any")
        source_wildcard = r.get("source_wildcard")
        source_prefix = r.get("source_prefix")
        if source_prefix is not None and str(source_prefix).strip() != "":
            source_prefix = int(source_prefix)
        else:
            source_prefix = None
        destination = r.get("destination", "any")
        destination_wildcard = r.get("destination_wildcard")
        destination_prefix = r.get("destination_prefix")
        if destination_prefix is not None and str(destination_prefix).strip() != "":
            destination_prefix = int(destination_prefix)
        else:
            destination_prefix = None
        source_port = r.get("source_port")
        if source_port is not None and str(source_port).strip() != "":
            source_port = int(source_port)
        else:
            source_port = None
        destination_port = r.get("destination_port")
        if destination_port is not None and str(destination_port).strip() != "":
            destination_port = int(destination_port)
        else:
            destination_port = None
        established = bool(r.get("established", False))
        log = bool(r.get("log", False))
        remark = r.get("remark")
        if remark is not None and not str(remark).strip():
            remark = None

        _, resolved_src_wc, resolved_dst_wc = _validate_cisco_acl_args(
            name, seq, action, protocol, source, source_wildcard,
            destination, destination_wildcard, source_port, destination_port,
            established, remark, acl_type, source_prefix, destination_prefix
        )

        if acl_type == "standard":
            rules_xml_parts.append(_build_cisco_std_seq_rule_xml(
                seq, action, source, resolved_src_wc, log, remark
            ))
        else:
            rules_xml_parts.append(_build_cisco_ext_seq_rule_xml(
                seq, action, protocol, source, resolved_src_wc,
                destination, resolved_dst_wc, source_port, destination_port,
                established, log, remark
            ))

    rules_xml = "".join(rules_xml_parts)
    type_tag = "standard" if acl_type == "standard" else "extended"

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <access-list>
              <{type_tag} xmlns="{NS_ACL}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="create">
                <name>{escape(name)}</name>
                {rules_xml}
              </{type_tag}>
            </access-list>
          </ip>
        </native>
    '''))


@validate_call
def replace_acl(
    name: str,
    rules: list[dict],
    acl_type: Literal["standard", "extended"] = "extended",
    reference_config: str | None = None,
    expected_revision: str | None = None,
) -> str:
    # reference_config (2026-09) - replace ทั้ง ACL ก้อนมีความเสี่ยงเท่ากับ remove_acl
    # ถ้า ZBF กำลังใช้งานอยู่ ดู set_acl_rule ด้านบน
    if reference_config is not None:
        from vendor_translators.cisco_zbf import resolve_cisco_acl_safe_mutation
        resolve_cisco_acl_safe_mutation(reference_config, name, expected_revision)

    name = validate_object_ref(name, "ACL name")
    if not rules:
        raise ValueError("rules list cannot be empty")

    seen_seqs = set()
    for rule in rules:
        seq_raw = rule.get("sequence")
        if seq_raw is None or str(seq_raw).strip() == "":
            raise ValueError("each rule must have a sequence")
        try:
            seq = int(seq_raw)
        except (ValueError, TypeError):
            raise ValueError("sequence must be an integer")
        if not 1 <= seq <= 2147483647:
            raise ValueError("sequence must be between 1 and 2147483647")
        if seq in seen_seqs:
            raise ValueError(f"duplicate sequence {seq} in rules")
        seen_seqs.add(seq)

    sorted_rules = sorted(rules, key=lambda r: int(r["sequence"]))

    rules_xml_parts = []
    for r in sorted_rules:
        seq = int(r["sequence"])
        action = r.get("action")
        if action not in ("permit", "deny"):
            raise ValueError("action must be 'permit' or 'deny'")
        protocol = r.get("protocol", "ip")
        source = r.get("source", "any")
        source_wildcard = r.get("source_wildcard")
        source_prefix = r.get("source_prefix")
        if source_prefix is not None and str(source_prefix).strip() != "":
            source_prefix = int(source_prefix)
        else:
            source_prefix = None
        destination = r.get("destination", "any")
        destination_wildcard = r.get("destination_wildcard")
        destination_prefix = r.get("destination_prefix")
        if destination_prefix is not None and str(destination_prefix).strip() != "":
            destination_prefix = int(destination_prefix)
        else:
            destination_prefix = None
        source_port = r.get("source_port")
        if source_port is not None and str(source_port).strip() != "":
            source_port = int(source_port)
        else:
            source_port = None
        destination_port = r.get("destination_port")
        if destination_port is not None and str(destination_port).strip() != "":
            destination_port = int(destination_port)
        else:
            destination_port = None
        established = bool(r.get("established", False))
        log = bool(r.get("log", False))
        remark = r.get("remark")
        if remark is not None and not str(remark).strip():
            remark = None

        _, resolved_src_wc, resolved_dst_wc = _validate_cisco_acl_args(
            name, seq, action, protocol, source, source_wildcard,
            destination, destination_wildcard, source_port, destination_port,
            established, remark, acl_type, source_prefix, destination_prefix
        )

        if acl_type == "standard":
            rules_xml_parts.append(_build_cisco_std_seq_rule_xml(
                seq, action, source, resolved_src_wc, log, remark
            ))
        else:
            rules_xml_parts.append(_build_cisco_ext_seq_rule_xml(
                seq, action, protocol, source, resolved_src_wc,
                destination, resolved_dst_wc, source_port, destination_port,
                established, log, remark
            ))

    rules_xml = "".join(rules_xml_parts)
    type_tag = "standard" if acl_type == "standard" else "extended"

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <access-list>
              <{type_tag} xmlns="{NS_ACL}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="replace">
                <name>{escape(name)}</name>
                {rules_xml}
              </{type_tag}>
            </access-list>
          </ip>
        </native>
    '''))

# ลบ ACE เดียว (1 sequence) ออกจาก ACL - key ของ access-list-seq-rule คือ
# "sequence" (ยืนยันจาก Cisco-IOS-XE-acl.yang: `list access-list-seq-rule { key
# "sequence"; ... }`) - ใช้เป็นขั้นตอนแรกของ edit flow เหมือน static route/OSPF/
# RIP (merge ทับ ace-rule เฉยๆไม่พอ เพราะ source/destination เป็น choice ระหว่าง
# <any/>/<host-address>/<ipv4-address>+<mask> - ถ้า edit เปลี่ยนรูปแบบ address
# merge จะไม่ลบ element เดิมที่ไม่ได้ส่งมาใหม่ ทำให้ค้างทั้งสองแบบพร้อมกัน)
@validate_call
def remove_acl_rule(
    name: str,
    sequence: int,
    acl_type: Literal["standard", "extended"] = "extended",
    reference_config: str | None = None,
    expected_revision: str | None = None,
):
    # reference_config (2026-09) - ตรวจสอบความปลอดภัยก่อนลบ:
    # 1. ZBF reference graph
    # 2. NAT inside source references
    # 3. Interface access-group references
    # 4. Revision check ป้องกัน concurrent modification
    # 5. หากเป็น ACE สุดท้ายของ ACL จะลบทั้ง ACL container ให้อัตโนมัติใน operation เดียว
    if reference_config is not None:
        from vendor_translators.cisco_zbf import resolve_cisco_acl_safe_deletion
        acl_el, is_last_rule = resolve_cisco_acl_safe_deletion(
            reference_config,
            name,
            expected_revision=expected_revision,
            sequence=sequence,
            acl_type=acl_type,
        )
        if is_last_rule:
            return remove_acl(name, acl_type=acl_type)

    # (bug 63) ชื่อ ACL เป็นทั้งชื่อ access-list และ id ของ NAT rule ที่เขียนลงอุปกรณ์จริง
    # เดิมมีแค่ escape() ไม่ผ่านการตรวจอะไรเลย (ชื่อยาว 500 ตัว/มีช่องว่างผ่านได้) สวนทาง
    # กับ pool_name ที่อยู่ในฟังก์ชันเดียวกันซึ่งตรวจเข้ม - ใช้ "ด่านอ้างอิง" ไม่ใช่ด่านสร้าง
    # เพราะชื่อนี้ถูกอ่านกลับมาจากอุปกรณ์แล้วส่งกลับเข้ามา (natTeardown.js ส่ง
    # currentRule.name / stateful.jsx ส่ง derived name ที่มาจาก get_acl_information)
    # ถ้าใช้ด่านสร้างจะเกิดปัญหาเดียวกับ NAT pool คือ ACL ที่ตั้งจาก CLI ลบไม่ได้
    name = validate_object_ref(name, "ACL name")
    type_tag = "standard" if acl_type == "standard" else "extended"
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <access-list>
              <{type_tag} xmlns="{NS_ACL}">
                <name>{escape(name)}</name>
                <access-list-seq-rule xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                  <sequence>{sequence}</sequence>
                </access-list-seq-rule>
              </{type_tag}>
            </access-list>
          </ip>
        </native>
    '''))

# ลบทั้ง ACL (ทุก sequence) - ใช้เป็นขั้นตอน teardown ของ NAT Policy Edit/Delete
# (ACL name = NAT name เสมอ ดู create_nat_policy) - ต่างจาก remove_acl_rule ตรงที่
# remove_acl_rule ลบทีละ ACE แล้วทิ้ง "ip access-list extended <name>" เปล่าไว้
# (ยืนยันจริงบน HQ-R1 ตอนทดสอบ ACL Edit/Delete ก่อนหน้า) - ฟังก์ชันนี้ลบ "extended"
# หรือ "standard" ทั้งก้อนเลย key คือ "name" (ยืนยันจาก Cisco-IOS-XE-acl.yang: list extended/standard {
# key "name"; })
@validate_call
def remove_acl(
    name: str,
    acl_type: Literal["standard", "extended"] = "extended",
    reference_config: str | None = None,
    expected_revision: str | None = None,
):
    # reference_config (2026-09) - ตรวจสอบความปลอดภัยก่อนลบ ACL ทั้งก้อน:
    # 1. ZBF reference graph
    # 2. NAT inside source references
    # 3. Interface access-group references
    # 4. Revision check
    if reference_config is not None:
        from vendor_translators.cisco_zbf import resolve_cisco_acl_safe_deletion
        resolve_cisco_acl_safe_deletion(
            reference_config,
            name,
            expected_revision=expected_revision,
            acl_type=acl_type,
        )

    # (bug 63) ชื่อ ACL เป็นทั้งชื่อ access-list และ id ของ NAT rule ที่เขียนลงอุปกรณ์จริง
    # เดิมมีแค่ escape() ไม่ผ่านการตรวจอะไรเลย (ชื่อยาว 500 ตัว/มีช่องว่างผ่านได้) สวนทาง
    # กับ pool_name ที่อยู่ในฟังก์ชันเดียวกันซึ่งตรวจเข้ม - ใช้ "ด่านอ้างอิง" ไม่ใช่ด่านสร้าง
    # เพราะชื่อนี้ถูกอ่านกลับมาจากอุปกรณ์แล้วส่งกลับเข้ามา (natTeardown.js ส่ง
    # currentRule.name / stateful.jsx ส่ง derived name ที่มาจาก get_acl_information)
    # ถ้าใช้ด่านสร้างจะเกิดปัญหาเดียวกับ NAT pool คือ ACL ที่ตั้งจาก CLI ลบไม่ได้
    name = validate_object_ref(name, "ACL name")
    type_tag = "standard" if acl_type == "standard" else "extended"
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <access-list>
              <{type_tag} xmlns="{NS_ACL}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                <name>{escape(name)}</name>
              </{type_tag}>
            </access-list>
          </ip>
        </native>
    '''))

@validate_call
def apply_acl_interface(
        interface_type: str,
        interface_id: str,
        acl_name: str,
        direction: Literal["in", "out"] = "in",
        description: str | None = None,
) -> str:
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    # (bug 63) acl_name อ้างถึง ACL ที่มีอยู่บนอุปกรณ์ - ใช้ด่านอ้างอิงเหมือน set_acl_rule
    acl_name = validate_object_ref(acl_name, "ACL name")
    description_xml = _description_xml(description)

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <interface>
            <{interface_type}>
              <name>{interface_id}</name>
              {description_xml}
              <ip>
                <access-group>
                  <{direction}>
                    <acl>
                      <acl-name>{escape(acl_name)}</acl-name>
                      <{direction}/>
                    </acl>
                  </{direction}>
                </access-group>
              </ip>
            </{interface_type}>
          </interface>
        </native>
    '''))

def parse_cisco_interface_acl_bindings(config_xml: str) -> dict[str, dict[str, str]]:
    """แยกข้อมูลการผูก Inbound และ Outbound ACL กับ Interface ต่างๆ จาก Cisco configuration XML

    คืนค่าเป็น dict ในรูปแบบ:
    {
        "GigabitEthernet1": {"in": "ACL_NAME", "out": "ACL_NAME"},
        ...
    }
    """
    if not config_xml or not config_xml.strip():
        return {}

    try:
        root = safe_fromstring(config_xml.strip())
    except ET.ParseError as exc:
        raise ValueError("Cannot parse Cisco interface configuration: invalid XML") from exc

    def _local_tag(el) -> str:
        return el.tag.split("}")[-1] if "}" in el.tag else el.tag

    if any(_local_tag(el) == "rpc-error" for el in root.iter()):
        raise ValueError("Device rejected reading Cisco interface configuration")

    bindings: dict[str, dict[str, str]] = {}
    for interface_container in root.iter():
        if _local_tag(interface_container) != "interface":
            continue
        for if_el in interface_container:
            if_type = _local_tag(if_el)
            name_el = None
            ip_el = None
            for child in if_el:
                tag = _local_tag(child)
                if tag == "name":
                    name_el = child
                elif tag == "ip":
                    ip_el = child
            if name_el is None or not name_el.text:
                continue
            if_id = name_el.text.strip()
            if_name = f"{if_type}{if_id}"

            if ip_el is None:
                continue
            ag_el = None
            for child in ip_el:
                if _local_tag(child) == "access-group":
                    ag_el = child
                    break
            if ag_el is None:
                continue

            dirs: dict[str, str] = {}
            for dir_el in ag_el:
                dir_name = _local_tag(dir_el)
                if dir_name in ("in", "out"):
                    acl_name = None
                    for c in dir_el.iter():
                        if _local_tag(c) == "acl-name" and c.text:
                            acl_name = c.text.strip()
                            break
                    if acl_name:
                        dirs[dir_name] = acl_name
            if dirs:
                bindings[if_name] = dirs
    return bindings


@validate_call
def replace_acl_interface_bindings(
    acl_name: str,
    inbound_interfaces: list[str] = [],
    outbound_interfaces: list[str] = [],
    reference_config: str | None = None,
) -> str:
    """ผูกหรือปลด ACL เข้ากับ interface หลายรายการแบบ atomic ใน RPC เดียว

    - ตรวจสอบชื่อ ACL และชื่อ interface
    - ตรวจสอบ conflict กับ reference_config (ห้ามผูกซ้ำทิศทางเดียวกันกับ ACL อื่น)
    - คำนวณส่วนต่าง (additions/removals)
    - ปลดเฉพาะ <in> หรือ <out> ภายใต้ <access-group> โดยไม่แตะต้อง container <ip>
    - หากไม่มีการเปลี่ยนแปลง คืนค่า no-op edit-config ที่ปลอดภัย
    """
    acl_name = validate_object_ref(acl_name, "ACL name")

    clean_inbound = list(dict.fromkeys(intf.strip() for intf in inbound_interfaces if intf and intf.strip()))
    clean_outbound = list(dict.fromkeys(intf.strip() for intf in outbound_interfaces if intf and intf.strip()))

    for intf in clean_inbound:
        _interface_fullname(intf, "Inbound Interface")
    for intf in clean_outbound:
        _interface_fullname(intf, "Outbound Interface")

    if reference_config is not None:
        current_bindings = parse_cisco_interface_acl_bindings(reference_config)

        # ตรวจสอบว่าไม่มี interface ใดในรายการที่ร้องขอ ถูกแย่งผูกโดย ACL อื่นไปแล้ว
        for intf in clean_inbound:
            bound_in = current_bindings.get(intf, {}).get("in")
            if bound_in and bound_in != acl_name:
                raise ValueError(f"Cannot use {intf} (inbound) because it is already used by ACL {bound_in}")

        for intf in clean_outbound:
            bound_out = current_bindings.get(intf, {}).get("out")
            if bound_out and bound_out != acl_name:
                raise ValueError(f"Cannot use {intf} (outbound) because it is already used by ACL {bound_out}")

        current_inbound = {intf for intf, dirs in current_bindings.items() if dirs.get("in") == acl_name}
        current_outbound = {intf for intf, dirs in current_bindings.items() if dirs.get("out") == acl_name}
    else:
        current_inbound = set()
        current_outbound = set()

    inbound_to_add = set(clean_inbound) - current_inbound
    inbound_to_remove = current_inbound - set(clean_inbound)
    outbound_to_add = set(clean_outbound) - current_outbound
    outbound_to_remove = current_outbound - set(clean_outbound)

    all_affected = sorted(inbound_to_add | inbound_to_remove | outbound_to_add | outbound_to_remove)
    if not all_affected:
        return open_rpc_tag(edit_config_tag(f'<native xmlns="{NS_NATIVE}"/>'))

    interface_snippets = []
    for intf in all_affected:
        if_type, if_id = _split_interface(intf)
        if_type = _interface_type_tag(if_type)
        if_id = _interface_id_value(if_id)

        dir_snippets = []
        if intf in inbound_to_add:
            dir_snippets.append(
                f"<in><acl><acl-name>{escape(acl_name)}</acl-name><in/></acl></in>"
            )
        elif intf in inbound_to_remove:
            dir_snippets.append(
                '<in xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"/>'
            )

        if intf in outbound_to_add:
            dir_snippets.append(
                f"<out><acl><acl-name>{escape(acl_name)}</acl-name><out/></acl></out>"
            )
        elif intf in outbound_to_remove:
            dir_snippets.append(
                '<out xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"/>'
            )

        if dir_snippets:
            ag_xml = "".join(dir_snippets)
            interface_snippets.append(f"""
            <{if_type}>
              <name>{if_id}</name>
              <ip>
                <access-group>
                  {ag_xml}
                </access-group>
              </ip>
            </{if_type}>
            """)

    interfaces_xml = "".join(interface_snippets)
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <interface>
            {interfaces_xml}
          </interface>
        </native>
    '''))

# ========= NAT =========
def get_nat_pool_information():
    return open_rpc_tag(F'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <ip>
                <nat xmlns="{NS_NAT}">
                    <pool>
                    </pool>
                </nat>
            </ip>
        </native>
    </filter>
</get>
''')

# (bug 14) เดิมไม่ escape และไม่ validate อะไรเลยสักฟิลด์เดียว ทั้งที่ฟังก์ชัน NAT/DHCP
# ตัวอื่นในไฟล์เดียวกันทำอย่างน้อยหนึ่งอย่างเสมอ (set_dhcp_pool/create_nat_policy escape
# ชื่อ, set_static_nat validate IP) และ Juniper ก็ทำถูกทั้ง create/remove - ยืนยันด้วยการ
# รันจริงว่าแทรก XML element ได้ 3 ใน 4 ฟิลด์ (name/start/netmask) และค่าอย่างชื่อยาว 500
# ตัวอักษร, start ที่ไม่ใช่ IP, netmask ที่ส่ง "24" มาแทน dotted ผ่านได้หมด
#
# ตาม Cisco-IOS-XE-nat.yang:1223-1250: leaf id เป็น "type string" เฉย ๆ ไม่จำกัดรูปแบบ
# เลยในระดับ schema จึงต้องตั้งนโยบายชื่อเอง ส่วน mask เป็น choice ระหว่าง netmask
# แบบ dotted กับ prefix-length 1..30; ตอน Edit ต้องคงชนิดเดิมไว้เพื่อรองรับ config
# ที่สร้างจาก CLI/ระบบอื่นโดยไม่เปลี่ยน representation ของ brownfield โดยไม่จำเป็น
@validate_call
def create_nat_pool(
    name: str,
    start: str,
    end: str,
    netmask: str,
    replace_name: str | None = None,
    replace_mask_mode: Literal["netmask", "prefix-length"] | None = None,
):
    if replace_name is None:
        if replace_mask_mode is not None:
            raise ValueError("replace_mask_mode requires replace_name")
        name = validate_config_name(name, "NAT pool name")
    else:
        name = validate_object_ref(name, "NAT pool name")
        replace_name = validate_object_ref(replace_name, "Previous NAT pool name")
        if replace_name != name:
            raise ValueError("NAT pool name cannot be changed during edit")
    # ตรวจ start/end คู่กันเพื่อเช็คลำดับด้วย - เดิม start > end ผ่านได้ สร้าง pool ที่
    # ช่วงกลับหัวแล้วไปตายเอาที่อุปกรณ์
    start, end = validate_address_range(start, end, "NAT pool")
    netmask = validate_netmask(netmask)
    operation = "merge" if replace_name is not None else "create"
    if replace_mask_mode == "prefix-length":
        prefix_length = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
        if not 1 <= prefix_length <= 30:
            raise ValueError("Cisco NAT pool prefix-length must be between 1 and 30")
        mask_xml = f"<prefix-length>{prefix_length}</prefix-length>"
    else:
        mask_xml = f"<netmask>{netmask}</netmask>"
    return open_rpc_tag(edit_config_tag(f'''
<native xmlns="{NS_NATIVE}">
    <ip>
        <nat xmlns="{NS_NAT}">
            <pool xmlns:nc="{NS_RPC}" nc:operation="{operation}">
                <id>{escape(name)}</id>
                <start-address>{start}</start-address>
                <end-address>{end}</end-address>
                {mask_xml}
            </pool>
        </nat>
    </ip>
</native>
'''))

# ลบ NAT pool ทั้งตัว - key ของ pool คือ "id" (ยืนยันจริงจาก get_nat_pool_information
# ตอนทดสอบก่อนหน้านี้ในเซสชันนี้: อ่านกลับมาเป็น "id" ตรงกับที่ create_nat_pool
# เขียน ไม่ใช่ "name" ตาม Cisco-IOS-XE-nat.yang's เก่า/obsolete grouping) - ถ้า
# pool นี้ยังถูกอ้างอิงอยู่จริงโดย NAT rule ที่ใช้งานอยู่ (translate_mode=pool)
# อุปกรณ์จะปฏิเสธเองด้วย rpc-error (Cisco ไม่ให้ลบ pool ที่ยังถูกใช้งานอยู่) -
# ไม่ต้องเช็คเองฝั่งนี้ ปล่อยให้ error message จากอุปกรณ์ขึ้นตรงๆ
# (bug 14) เดิมไม่มีแม้แต่ @validate_call (ต่างจาก create_nat_pool ที่มี) จึงไม่มี type
# check ของ pydantic เลย ส่ง name=123 เป็น int ยังผ่าน และ name ถูก interpolate ดิบ ๆ
# แทรก XML ได้ - อาการเดียวกับ remove_static_route ตอน bug 13
@validate_call
def remove_nat_pool(name: str):
    # (bug 63) ชื่อนี้ "อ่านกลับมาจากอุปกรณ์" ไม่ใช่ผู้ใช้พิมพ์เอง (ผู้ใช้กดจากตารางที่
    # เรนเดอร์จาก get_*) จึงใช้ด่านอ้างอิงที่ตรวจแค่ความปลอดภัย ไม่บังคับสไตล์การตั้งชื่อ -
    # เดิมใช้ validate_config_name ซึ่งเข้มกว่าที่อุปกรณ์ยอมรับจริง ทำให้ของที่มีอยู่จริง
    # บนอุปกรณ์ (ตั้งจาก CLI / ติดมาก่อน onboard) โชว์บนหน้าเว็บแต่กดลบไม่ได้ -
    # escape() ยังคงไว้ทุกจุดเป็นด่านที่สอง
    name = validate_object_ref(name, "NAT pool name")
    return open_rpc_tag(edit_config_tag(f'''
<native xmlns="{NS_NATIVE}">
    <ip>
        <nat xmlns="{NS_NAT}">
            <pool xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                <id>{escape(name)}</id>
            </pool>
        </nat>
    </ip>
</native>
'''))

def get_nat_information():
    return open_rpc_tag(F'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <ip>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            <list-interface>
                                <list></list>
                            </list-interface>
                            <list-pool>
                                <list></list>
                            </list-pool>
                        </source>
                    </inside>
                </nat>
            </ip>
        </native>
    </filter>
</get>
''')

# nat.jsx's CiscoNatPage ต้องใช้ get_nat_information + get_switchport_information
# (หา interface ที่ ip nat inside/outside อยู่ตอนนี้) + get_ip_interface_brief
# (คำนวณ network สำหรับ toggle list) พร้อมกันเสมอ - รวมเป็น request เดียว
# เหมือน get_ospf_dashboard/get_rip_dashboard - native/interface (ว่าง = ทั้งก้อน,
# มี ip/nat/inside|outside ต่อ interface ติดมาด้วยอยู่แล้ว) กับ native/ip/nat
# (nat rule binding) เป็น sibling กันได้ใน <native> เดียว, รวม OpenConfig
# interfaces (switchport L2/L3) และ interfaces-oper (ip brief) เป็น sibling
# top-level เพิ่มอีก 2 อัน
def get_nat_dashboard():
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <interface></interface>
            <ip>
                <access-list></access-list>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            <list-interface>
                                <list></list>
                            </list-interface>
                            <list-pool>
                                <list></list>
                            </list-pool>
                        </source>
                    </inside>
                </nat>
            </ip>
        </native>
        <interfaces xmlns="{NS_OC_IF}">
            <interface>
                <name/>
                <ethernet xmlns="{NS_OC_ETH}">
                    <switched-vlan xmlns="{NS_OC_VLAN}"/>
                </ethernet>
                <subinterfaces/>
            </interface>
        </interfaces>
        <interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">
            <interface>
                <name/>
                <admin-status/>
                <oper-status/>
                <ipv4/>
                <ipv4-subnet-mask/>
                <last-change/>
            </interface>
        </interfaces>
    </filter>
</get>
''')

# (2026-09) get_nat_dashboard() ด้านบนไม่ถูกเรียกจากหน้า NAT อีกแล้ว - เก็บไว้เพื่อ
# ความเข้ากันได้ย้อนหลังของชื่อ command เท่านั้น (ยังอยู่ใน PUBLIC_FUNCTIONS ให้
# catalog/capability listing เรียกดู signature ได้) backend/api/device_router.py's
# get_nat_dashboard branch เรียก 2 ฟังก์ชันด้านล่างนี้แทน เพราะ RPC เดียวเดิมขอ
# <native><ip><access-list></access-list></ip></native> "ทุก ACL บนอุปกรณ์" เพื่อ
# หา source scope ของ Brownfield NAT ทั้งที่หน้า NAT ใช้ ACL แค่ 1 ตัว (ตัวที่ NAT
# rule ปัจจุบันอ้างถึง) - บนอุปกรณ์ production ที่มีหลาย ACL/interface ทำให้ reply
# ใหญ่และช้าโดยไม่จำเป็น เป็นต้นเหตุของ get_nat_dashboard timeout ที่พบจริง
#
# <native><interface></native> (ว่าง = ทั้งก้อน) ยังคงไว้เหมือนเดิมโดยเจตนา - IOS-XE
# ไม่มีทาง select field ข้ามทุก interface type ("GigabitEthernet"/"Vlan"/"Loopback"/
# "Tunnel"/... คนละ container ชื่อคนละอัน) แบบ generic ใน subtree filter เลย ไม่มี
# รายชื่อ type ที่ hardcode ได้อย่างปลอดภัยครบทุกรุ่น/ทุกอุปกรณ์ - ต่างจาก access-list
# ที่มี "name" เป็น key ให้ทำ content-match filter ได้ตรงๆ ตาม RFC 6241 §6.2.5
def get_nat_dashboard_bindings():
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <interface></interface>
            <ip>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            <list-interface>
                                <list></list>
                            </list-interface>
                            <list-pool>
                                <list></list>
                            </list-pool>
                        </source>
                    </inside>
                </nat>
            </ip>
        </native>
        <interfaces xmlns="{NS_OC_IF}">
            <interface>
                <name/>
                <ethernet xmlns="{NS_OC_ETH}">
                    <switched-vlan xmlns="{NS_OC_VLAN}"/>
                </ethernet>
                <subinterfaces/>
            </interface>
        </interfaces>
        <interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">
            <interface>
                <name/>
                <admin-status/>
                <oper-status/>
                <ipv4/>
                <ipv4-subnet-mask/>
                <last-change/>
            </interface>
        </interfaces>
    </filter>
</get>
''')

# อ่านเฉพาะ ACL ชื่อที่ get_nat_dashboard_bindings บอกว่า NAT rule ปัจจุบันอ้างถึง -
# <name>{acl_name}</name> เป็น content-match selection node (RFC 6241 §6.2.5) อุปกรณ์
# จึงคืนเฉพาะ list entry ที่ name ตรงกันเท่านั้น ไม่ใช่ ACL ทุกตัว - ขอทั้ง standard
# และ extended เพราะ Brownfield NAT (ตั้งจาก CLI มาก่อนใช้ระบบนี้) อ้าง ACL แบบไหนก็
# ได้ ไม่ได้บังคับว่าต้องเป็น extended เหมือนที่ create_nat_policy สร้างขึ้นเอง
@validate_call
def get_nat_dashboard_acl(acl_name: str):
    # (bug 63 pattern) ชื่อนี้อ่านกลับมาจาก get_nat_dashboard_bindings เอง (ด่าน
    # อ้างอิง ไม่ใช่ด่านสร้าง) - escape() อย่างเดียวไม่พอกันชื่อที่มีอักขระ XML พิเศษ
    acl_name = validate_object_ref(acl_name, "ACL name")
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <ip>
                <access-list>
                    <standard xmlns="{NS_ACL}">
                        <name>{escape(acl_name)}</name>
                    </standard>
                    <extended xmlns="{NS_ACL}">
                        <name>{escape(acl_name)}</name>
                    </extended>
                </access-list>
            </ip>
        </native>
    </filter>
</get>
''')

@validate_call
def set_nat(
    acl_name: str,
    interface_name: str | None = None,
    pool_name: str | None = None,
    overload: bool = True,
) -> str:
    if bool(interface_name) == bool(pool_name):
        raise ValueError("specify exactly one of interface_name or pool_name")
    # (bug 63) ชื่อ ACL เป็นทั้งชื่อ access-list และ id ของ NAT rule ที่เขียนลงอุปกรณ์จริง
    # เดิมมีแค่ escape() ไม่ผ่านการตรวจอะไรเลย (ชื่อยาว 500 ตัว/มีช่องว่างผ่านได้) สวนทาง
    # กับ pool_name ที่อยู่ในฟังก์ชันเดียวกันซึ่งตรวจเข้ม - ใช้ "ด่านอ้างอิง" ไม่ใช่ด่านสร้าง
    # เพราะชื่อนี้ถูกอ่านกลับมาจากอุปกรณ์แล้วส่งกลับเข้ามา (natTeardown.js ส่ง
    # currentRule.name / stateful.jsx ส่ง derived name ที่มาจาก get_acl_information)
    # ถ้าใช้ด่านสร้างจะเกิดปัญหาเดียวกับ NAT pool คือ ACL ที่ตั้งจาก CLI ลบไม่ได้
    acl_name = validate_object_ref(acl_name, "ACL name")
    # (bug 14) ชื่อ pool ที่อ้างถึงต้องผ่านการตรวจ ไม่ใช่ escape อย่างเดียว
    # (bug 63) แต่ใช้ "ด่านอ้างอิง" ไม่ใช่ด่านสร้าง - ชื่อนี้อ่านกลับมาจากอุปกรณ์
    # (ผู้ใช้เลือก pool จาก dropdown ที่มาจาก get_nat_pool_information) ถ้าบังคับด้วย
    # นโยบายตอนสร้าง pool ที่ตั้งชื่อจาก CLI ไว้จะเลือกใช้ไม่ได้เลย - escape() ยังคงไว้
    if pool_name:
        pool_name = validate_object_ref(pool_name, "NAT pool name")
    if interface_name:
        interface_name = _interface_fullname(interface_name)

    overload_xml = "<overload-new></overload-new>" if overload else ""

    if interface_name:
        source_xml = f'''
                            <list-interface>
                                <list>
                                    <id>{escape(acl_name)}</id>
                                    <interface>
                                        <name>{interface_name}</name>
                                        {overload_xml}
                                    </interface>
                                </list>
                            </list-interface>'''
    else:
        source_xml = f'''
                            <list-pool>
                                <list>
                                    <id>{escape(acl_name)}</id>
                                    <pool>
                                        <name>{escape(pool_name)}</name>
                                        {overload_xml}
                                    </pool>
                                </list>
                            </list-pool>'''

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <ip>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            {source_xml}
                        </source>
                    </inside>
                </nat>
            </ip>
        </native>
    '''))

# ลบ nat rule เดียว (1 ACL name) ออกจาก inside source list - key ของ list-interface/
# list-pool ทั้งคู่คือ "id" (ยืนยันจาก Cisco-IOS-XE-nat.yang บรรทัด 1287/1311:
# `list list { key "id"; }`) - ต้องรู้ mode เดิม (interface/pool) เหมือน set_nat
# เพราะแค่ acl_name อย่างเดียวไม่พอจะรู้ว่าอยู่ใน list-interface หรือ list-pool -
# ใช้เป็นขั้นตอน teardown ของ NAT Policy Edit/Delete คู่กับ remove_acl
@validate_call
def remove_nat(
    acl_name: str,
    interface_name: str | None = None,
    pool_name: str | None = None,
) -> str:
    if bool(interface_name) == bool(pool_name):
        raise ValueError("specify exactly one of interface_name or pool_name")
    # (bug 63) ชื่อ ACL เป็นทั้งชื่อ access-list และ id ของ NAT rule ที่เขียนลงอุปกรณ์จริง
    # เดิมมีแค่ escape() ไม่ผ่านการตรวจอะไรเลย (ชื่อยาว 500 ตัว/มีช่องว่างผ่านได้) สวนทาง
    # กับ pool_name ที่อยู่ในฟังก์ชันเดียวกันซึ่งตรวจเข้ม - ใช้ "ด่านอ้างอิง" ไม่ใช่ด่านสร้าง
    # เพราะชื่อนี้ถูกอ่านกลับมาจากอุปกรณ์แล้วส่งกลับเข้ามา (natTeardown.js ส่ง
    # currentRule.name / stateful.jsx ส่ง derived name ที่มาจาก get_acl_information)
    # ถ้าใช้ด่านสร้างจะเกิดปัญหาเดียวกับ NAT pool คือ ACL ที่ตั้งจาก CLI ลบไม่ได้
    acl_name = validate_object_ref(acl_name, "ACL name")
    # (bug 14) ชื่อ pool ที่อ้างถึงต้องผ่านการตรวจ ไม่ใช่ escape อย่างเดียว
    # (bug 63) แต่ใช้ "ด่านอ้างอิง" ไม่ใช่ด่านสร้าง - ชื่อนี้อ่านกลับมาจากอุปกรณ์
    # (ผู้ใช้เลือก pool จาก dropdown ที่มาจาก get_nat_pool_information) ถ้าบังคับด้วย
    # นโยบายตอนสร้าง pool ที่ตั้งชื่อจาก CLI ไว้จะเลือกใช้ไม่ได้เลย - escape() ยังคงไว้
    if pool_name:
        pool_name = validate_object_ref(pool_name, "NAT pool name")
    if interface_name:
        interface_name = _interface_fullname(interface_name)

    nc_remove = 'xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"'
    if interface_name:
        source_xml = f'''
                            <list-interface>
                                <list {nc_remove}>
                                    <id>{escape(acl_name)}</id>
                                </list>
                            </list-interface>'''
    else:
        source_xml = f'''
                            <list-pool>
                                <list {nc_remove}>
                                    <id>{escape(acl_name)}</id>
                                </list>
                            </list-pool>'''

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <ip>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            {source_xml}
                        </source>
                    </inside>
                </nat>
            </ip>
        </native>
    '''))

# (bug 62) เดิมไม่มี @validate_call ทำให้ Literal["inside","outside"] ที่เขียนไว้ใน
# signature เป็นแค่คำอธิบาย ไม่ได้บังคับอะไรเลย - ค่านี้ถูกใช้เป็น "ชื่อ XML tag" ตรงๆ
# (<{direction}/>) ซึ่ง escape() ช่วยไม่ได้ ยืนยันด้วยการรันจริงว่าส่ง
# direction="outside/><evil" แล้วได้ <outside/><evil/> โผล่ใน payload - อาการเดียวกับ
# ที่ bug 12 เจอกับ interface_type แล้วแก้ด้วย _interface_type_tag()
@validate_call
def apply_nat_interface(
    interface_type: str,
    interface_name: str,
    direction: Literal["inside", "outside"] = "inside"
):
    interface_type = _interface_type_tag(interface_type)
    interface_name = _interface_id_value(interface_name, 'interface_name')
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <interface>
                <{interface_type}>
                    <name>{interface_name}</name>
                    <ip>
                        <nat xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-nat">
                            <{direction}/>
                        </nat>
                    </ip>
                </{interface_type}>
            </interface>
        </native>
    '''))

# ปลด "ip nat inside/outside" ออกจาก interface - apply_nat_interface เดิม set
# ได้อย่างเดียว ไม่มี remove - ต้องมีคู่กันสำหรับ NAT Policy Edit/Delete
# (bug 65) แก้คำอธิบายที่ผิด: เดิมเขียนว่า "ปลด inside บนขาที่เคย auto-apply ไว้ตอน
# scope=specific" ซึ่งไม่เคยมีการ auto-apply เกิดขึ้นจริง - ปัจจุบัน frontend
# (natFormModal.jsx / natTeardown.js) เป็นคนสั่ง apply/remove inside-outside เองทุกขา
# (bug 62) เดิมไม่มี @validate_call ทำให้ Literal["inside","outside"] ที่เขียนไว้ใน
# signature เป็นแค่คำอธิบาย ไม่ได้บังคับอะไรเลย - ค่านี้ถูกใช้เป็น "ชื่อ XML tag" ตรงๆ
# (<{direction}/>) ซึ่ง escape() ช่วยไม่ได้ ยืนยันด้วยการรันจริงว่าส่ง
# direction="outside/><evil" แล้วได้ <outside/><evil/> โผล่ใน payload - อาการเดียวกับ
# ที่ bug 12 เจอกับ interface_type แล้วแก้ด้วย _interface_type_tag()
@validate_call
def remove_nat_interface(
    interface_type: str,
    interface_name: str,
    direction: Literal["inside", "outside"] = "inside"
):
    interface_type = _interface_type_tag(interface_type)
    interface_name = _interface_id_value(interface_name, 'interface_name')
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <interface>
                <{interface_type}>
                    <name>{interface_name}</name>
                    <ip>
                        <nat xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-nat">
                            <{direction} xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"/>
                        </nat>
                    </ip>
                </{interface_type}>
            </interface>
        </native>
    '''))

# ✅ (ระลอก C3 / bug 65) กลับมาใช้แล้ว และตอนนี้ครบทั้ง 4 ส่วนในคำสั่งเดียว
#
# เดิม frontend ยิงทีละคำสั่ง (set_acl_rule × N + set_nat + apply_nat_interface × M)
# ทำให้ 1 Apply = 12 RPC และถ้าเป็นการแก้ไขจะเป็น 20 RPC + หน่วง 2.5 วินาที โดยมีช่วงที่
# NAT บนอุปกรณ์ดับสนิทกลางทาง (ACL ถูกลบ / nat rule ถูกลบ / inside-outside ถูกปลดหมด
# ทุกขา แล้วค่อยทยอยสร้างกลับ) - ผู้ใช้จับได้จาก Command History จริงว่าได้ 12-20 แถว
# ต่อ 1 การกระทำ และเจอ bug 80 ตามมาคือยิงเยอะจนติด rate limit แล้วระบบไปปิด NAT ให้เอง
#
# ตอนนี้ทุกอย่างอยู่ใต้ <native> ก้อนเดียวจึงยิงได้ใน edit-config เดียว:
#   ACL (replace)  +  nat rule (replace + remove อีกโหมด)  +  ip nat outside/inside/remove
# ไม่ต้องมี teardown เลย เพราะ replace แทนที่เนื้อหาเดิมให้เองโดยไม่มีช่วงที่ของหายไป
#
# Policy-Based NAT: ระดับ "เจตนา" ที่ใช้ได้ทุกยี่ห้อในหน้าเว็บเดียวกัน - ผู้ใช้กรอก
# แค่ 3 อย่าง (1) name (2) source_scopes (any หรือรายการ CIDR ของฝั่งที่ให้ NAT ได้ -
# เพิ่มได้หลายอันเหมือนช่อง DNS server) (3) via (interface ขาออกเน็ต) - ที่เหลือ
# (ACL หลายบรรทัดถ้ามีหลาย scope, nat inside source, ip nat outside) backend
# จัดการเองหมด ไม่โผล่มาให้ผู้ใช้เห็นเลย - ยี่ห้อ zone-based (Juniper/Huawei) ต้องมี
# function ชื่อเดียวกันนี้ในไฟล์ตัวเอง (ยังไม่ได้ทำ - รอ verify rule-set/zone จริง
# ก่อน) ไม่งั้น build_payload จะแจ้ง "Feature is not supported by this translator"
# ให้เองโดย frontend ไม่ต้องแก้อะไร
@validate_call
def create_nat_policy(
    name: str,
    via_type: str,
    via_id: str,
    translate_mode: Literal["interface", "pool"] = "interface",
    pool_name: str | None = None,
    source_scopes: str | list[str] = "any",
    inside_interfaces: list[str] | None = None,
    release_interfaces: list[str] | None = None,
) -> str:
    via_type = _interface_type_tag(via_type)
    via_id = _interface_id_value(via_id, 'via_id')
    # (bug 63) ชื่อ ACL เป็นทั้งชื่อ access-list และ id ของ NAT rule ที่เขียนลงอุปกรณ์จริง
    # เดิมมีแค่ escape() ไม่ผ่านการตรวจอะไรเลย (ชื่อยาว 500 ตัว/มีช่องว่างผ่านได้) สวนทาง
    # กับ pool_name ที่อยู่ในฟังก์ชันเดียวกันซึ่งตรวจเข้ม - ใช้ "ด่านอ้างอิง" ไม่ใช่ด่านสร้าง
    # เพราะชื่อนี้ถูกอ่านกลับมาจากอุปกรณ์แล้วส่งกลับเข้ามา (natTeardown.js ส่ง
    # currentRule.name / stateful.jsx ส่ง derived name ที่มาจาก get_acl_information)
    # ถ้าใช้ด่านสร้างจะเกิดปัญหาเดียวกับ NAT pool คือ ACL ที่ตั้งจาก CLI ลบไม่ได้
    name = validate_object_ref(name, "NAT policy name")
    if translate_mode == "pool" and not pool_name:
        raise ValueError("pool_name is required when translate_mode is 'pool'")
    # (bug 14) ชื่อ pool ที่อ้างถึงต้องผ่านการตรวจ ไม่ใช่ escape อย่างเดียว
    # (bug 63) แต่ใช้ "ด่านอ้างอิง" ไม่ใช่ด่านสร้าง - ชื่อนี้อ่านกลับมาจากอุปกรณ์
    # (ผู้ใช้เลือก pool จาก dropdown ที่มาจาก get_nat_pool_information) ถ้าบังคับด้วย
    # นโยบายตอนสร้าง pool ที่ตั้งชื่อจาก CLI ไว้จะเลือกใช้ไม่ได้เลย - escape() ยังคงไว้
    if pool_name:
        pool_name = validate_object_ref(pool_name, "NAT pool name")

    scopes = [source_scopes] if isinstance(source_scopes, str) else source_scopes
    scopes = [scope.strip() for scope in scopes if scope and scope.strip()]
    if not scopes:
        scopes = ["any"]

    ace_rule_parts = []
    for index, scope in enumerate(scopes):
        if scope.lower() == "any":
            match_xml = "<any/>"
        else:
            network = ipaddress.IPv4Network(scope, strict=False)
            match_xml = (
                f"<ipv4-address>{network.network_address}</ipv4-address>"
                f"<mask>{network.hostmask}</mask>"
            )
        sequence = (index + 1) * 10
        ace_rule_parts.append(f'''
                        <access-list-seq-rule>
                            <sequence>{sequence}</sequence>
                            <ace-rule>
                                <action>permit</action>
                                <protocol>ip</protocol>
                                {match_xml}
                                <dst-any/>
                            </ace-rule>
                        </access-list-seq-rule>''')
    ace_rules_xml = "".join(ace_rule_parts)

    via_name = f"{via_type}{via_id}"
    # overload (PAT) เปิดเสมอ - เป็นสิ่งที่ใช้กันเป็นค่า default อยู่แล้วในทางปฏิบัติ
    # ไม่ต้องให้ผู้ใช้เลือก
    # (ระลอก C3 / bug 65) nat rule - ใช้ replace บน <list> ที่ id เดียวกัน แทนการลบก่อนสร้าง
    # และสั่ง remove อีกโหมดหนึ่งไปด้วยเสมอ เพราะ replace ที่ list-interface ไม่แตะ list-pool
    # (คนละ container) ถ้าผู้ใช้สลับโหมด ของเก่าอีกฝั่งจะค้าง - remove เป็น operation ที่
    # ไม่ error ถ้าของไม่มีอยู่ (ต่างจาก delete) จึงใส่ไปได้เสมอโดยไม่ต้องรู้สถานะเดิม
    if translate_mode == "interface":
        source_xml = f"""
                            <list-interface>
                                <list {NC} nc:operation="replace">
                                    <id>{escape(name)}</id>
                                    <interface>
                                        <name>{via_name}</name>
                                        <overload-new></overload-new>
                                    </interface>
                                </list>
                            </list-interface>
                            <list-pool>
                                <list {NC} nc:operation="remove">
                                    <id>{escape(name)}</id>
                                </list>
                            </list-pool>"""
    else:
        source_xml = f"""
                            <list-pool>
                                <list {NC} nc:operation="replace">
                                    <id>{escape(name)}</id>
                                    <pool>
                                        <name>{escape(pool_name)}</name>
                                        <overload-new></overload-new>
                                    </pool>
                                </list>
                            </list-pool>
                            <list-interface>
                                <list {NC} nc:operation="remove">
                                    <id>{escape(name)}</id>
                                </list>
                            </list-interface>"""

    # (ระลอก C3) ขา inside ทั้งหมด + ขาที่ต้องปลด nat ออก อยู่ใน edit-config เดียวกับ ACL
    # และ nat rule - เดิม frontend ยิง apply_nat_interface ทีละขา ทำให้ 1 Apply กลายเป็น
    # 12-20 RPC (ดู bug 65) และมีช่วงที่ NAT ดับกลางทางจริง
    #
    # **ห้ามใช้ replace กับ <interface>** - จะล้าง IP/description/ทุกอย่างบนขานั้นทิ้ง
    # ต้อง remove เจาะเฉพาะ container <nat> ของ interface ที่ไม่ได้อยู่ในชุดนี้แล้วเท่านั้น
    interface_parts = [f"""
                <{via_type}>
                    <name>{via_id}</name>
                    <ip>
                        <nat xmlns="{NS_NAT}">
                            <outside/>
                        </nat>
                    </ip>
                </{via_type}>"""]

    via_full = f"{via_type}{via_id}"
    seen = {via_full}
    for full_name in inside_interfaces or []:
        if not full_name or full_name.strip() in seen:
            continue
        iface_type, iface_id = _split_interface(full_name)
        iface_type = _interface_type_tag(iface_type)
        iface_id = _interface_id_value(iface_id, "inside_interfaces")
        seen.add(f"{iface_type}{iface_id}")
        interface_parts.append(f"""
                <{iface_type}>
                    <name>{iface_id}</name>
                    <ip>
                        <nat xmlns="{NS_NAT}">
                            <inside/>
                        </nat>
                    </ip>
                </{iface_type}>""")

    for full_name in release_interfaces or []:
        if not full_name:
            continue
        iface_type, iface_id = _split_interface(full_name)
        iface_type = _interface_type_tag(iface_type)
        iface_id = _interface_id_value(iface_id, "release_interfaces")
        if f"{iface_type}{iface_id}" in seen:
            continue  # ขานี้ยังใช้อยู่ในรอบนี้ อย่าไปปลด
        interface_parts.append(f"""
                <{iface_type}>
                    <name>{iface_id}</name>
                    <ip>
                        <nat xmlns="{NS_NAT}" {NC} nc:operation="remove"/>
                    </ip>
                </{iface_type}>""")

    interfaces_xml = "".join(interface_parts)

    # (ระลอก C3) ACL ใช้ replace ทั้ง <extended> - ตัดกฎเก่าที่ไม่ได้ส่งมารอบนี้ทิ้งให้เอง
    # เดิมต้อง remove_acl ก่อนแล้วค่อยวน set_acl_rule ทีละบรรทัด ซึ่งมีช่วงที่ ACL ว่าง
    return open_rpc_tag(edit_config_tag(f"""
        <native xmlns="{NS_NATIVE}">
            <ip>
                <access-list>
                    <extended xmlns="{NS_ACL}" {NC} nc:operation="replace">
                        <name>{escape(name)}</name>
                        {ace_rules_xml}
                    </extended>
                </access-list>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            {source_xml}
                        </source>
                    </inside>
                </nat>
            </ip>
            <interface>{interfaces_xml}
            </interface>
        </native>
    """))

# (ระลอก C3 / bug 80) รื้อ NAT ทั้งชุดในคำสั่งเดียว - คู่กับ create_nat_policy
#
# เดิมหน้าเว็บรื้อทีละคำสั่ง (remove_nat + remove_acl + remove_nat_interface ทีละขา)
# ซึ่งเป็น 6 RPC ขึ้นไป ผู้ใช้เจอจริงว่าติด rate limit (5 ครั้ง/3 วินาที) ตั้งแต่คำสั่งที่ 6
# ทำให้ขาที่เหลือไม่ถูกปลด เหลือ "ip nat inside" ค้างบนอุปกรณ์ทั้งที่หน้าเว็บบอกว่าปิด NAT แล้ว
#
# ตรงนี้ใช้ nc:operation="remove" ล้วน ๆ ทุกจุด (ไม่ใช่ delete) เพราะ remove ไม่ error ถ้าของ
# ไม่มีอยู่ จึงสั่งลบทั้ง list-interface และ list-pool ไปพร้อมกันได้โดยไม่ต้องรู้ว่าตอนนี้
# ใช้โหมดไหนอยู่ - และเช่นเดียวกับ create_nat_policy คือ **ห้าม replace ที่ <interface>**
# ต้อง remove เจาะเฉพาะ container <nat> ไม่งั้น IP/description บนขานั้นจะหายไปด้วย
@validate_call
def remove_nat_policy(
    name: str,
    interfaces: list[str] | None = None,
) -> str:
    name = validate_object_ref(name, "NAT policy name")

    interface_parts = []
    seen = set()
    for full_name in interfaces or []:
        if not full_name:
            continue
        iface_type, iface_id = _split_interface(full_name)
        iface_type = _interface_type_tag(iface_type)
        iface_id = _interface_id_value(iface_id, "interfaces")
        key = f"{iface_type}{iface_id}"
        if key in seen:
            continue
        seen.add(key)
        interface_parts.append(f"""
                <{iface_type}>
                    <name>{iface_id}</name>
                    <ip>
                        <nat xmlns="{NS_NAT}" {NC} nc:operation="remove"/>
                    </ip>
                </{iface_type}>""")

    interfaces_xml = f"""
            <interface>{"".join(interface_parts)}
            </interface>""" if interface_parts else ""

    return open_rpc_tag(edit_config_tag(f"""
        <native xmlns="{NS_NATIVE}">
            <ip>
                <access-list>
                    <extended xmlns="{NS_ACL}" {NC} nc:operation="remove">
                        <name>{escape(name)}</name>
                    </extended>
                </access-list>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            <list-interface>
                                <list {NC} nc:operation="remove">
                                    <id>{escape(name)}</id>
                                </list>
                            </list-interface>
                            <list-pool>
                                <list {NC} nc:operation="remove">
                                    <id>{escape(name)}</id>
                                </list>
                            </list-pool>
                        </source>
                    </inside>
                </nat>
            </ip>{interfaces_xml}
        </native>
    """))


def get_static_nat_information():
    return open_rpc_tag(F'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <ip>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            <static>
                                <nat-static-transport-list></nat-static-transport-list>
                            </static>
                        </source>
                    </inside>
                </nat>
            </ip>
        </native>
    </filter>                        
</get>
''')

# (bug 61) เดิมไม่มี @validate_call จึงไม่มีอะไรบังคับว่าค่าที่รับมาต้องเป็น str -
# และ ipaddress.IPv4Address() ที่ใช้เป็นตัวตรวจอยู่ "รับ int ได้ด้วย" (IPv4Address(
# 3232235777) = 192.168.1.1 ไม่ error) แต่โค้ดทิ้งค่าที่ parse แล้วไปแปะ "สตริงดิบ"
# ลง XML ผลคือส่ง int เข้ามาผ่านฉลุยแล้วได้ <local-ip>3232235777</local-ip> บนอุปกรณ์
# จริง - ยืนยันด้วยการรันจริงแล้ว เป็นอาการเดียวกับ bug 13/14 ที่ตกฟังก์ชันกลุ่มนี้ไป
@validate_call
def set_static_nat(
        name: str,
        local_ip: str,
        global_ip: str,
        replace_local_ip: str | None = None,
        replace_global_ip: str | None = None,
):
    # name ไม่มีที่เก็บบนอุปกรณ์ (static NAT ของ Cisco เป็นแค่คู่ local/global IP
    # ไม่มี concept ชื่อ) รับไว้เฉยๆ ไม่ใส่ลง XML - ใช้เป็น label ฝั่งเว็บเราเอง
    # เท่านั้น (เก็บผ่าน Device_Config_Object ตอน track ใน device_router.py)
    # (bug 64) ชื่อนี้ไม่ไปอุปกรณ์เลย แต่ลง cfg_name ของ Device_Config_Object ซึ่งเป็น
    # indexed field ที่ใช้ค้น object กลับ (ดู TRACKED_FEATURES ใน device_router.py) -
    # static NAT กับ port forward เป็น "สองตัวเดียวในระบบ" ที่ชื่อถูกเก็บใน DB ของเรา
    # ที่เหลือ (NAT pool / security profile / ACL) ตั้งและอ่านจากอุปกรณ์ล้วน
    #
    # เดิมกลับหัวกันพอดี: ตัวที่ไม่ลง DB กลับ validate เข้มมาก ส่วนตัวที่ลง DB จริง
    # กลับไม่ตรวจอะไรเลย ชื่อยาว 10000 ตัว/ช่องว่างล้วน/มี HTML ลง indexed field ได้หมด
    # แล้วเด้งกลับไปแสดงบนหน้าเว็บ - ใช้ด่านสร้าง (เข้ม) เพราะผู้ใช้พิมพ์เองจริง ๆ
    name = validate_config_name(name, "Item name")
    ipaddress.IPv4Address(local_ip)
    ipaddress.IPv4Address(global_ip)

    replace_values = (replace_local_ip, replace_global_ip)
    if any(value is not None for value in replace_values) and not all(value is not None for value in replace_values):
        raise ValueError("replace static NAT key must include local_ip and global_ip")
    remove_xml = ""
    if all(value is not None for value in replace_values):
        ipaddress.IPv4Address(replace_local_ip)
        ipaddress.IPv4Address(replace_global_ip)
        if (replace_local_ip, replace_global_ip) != (local_ip, global_ip):
            remove_xml = f'''                                <nat-static-transport-list xmlns:nc="{NS_RPC}" nc:operation="remove">
                                    <local-ip>{replace_local_ip}</local-ip>
                                    <global-ip>{replace_global_ip}</global-ip>
                                </nat-static-transport-list>
'''

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <ip>
                <nat xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-nat">
                    <inside>
                        <source>
                            <static>
{remove_xml}
                                <nat-static-transport-list>
                                    <local-ip>{local_ip}</local-ip>
                                    <global-ip>{global_ip}</global-ip>
                                </nat-static-transport-list>
                            </static>
                        </source>
                    </inside>
                </nat>
            </ip>
        </native>
    '''))

# ลบ static NAT entry เดียว - key คือ "local-ip global-ip" คู่กัน (ยืนยันจาก
# Cisco-IOS-XE-nat.yang: `list nat-static-transport-list { key "local-ip
# global-ip"; }`)
# (bug 61) เดิมไม่มี @validate_call จึงไม่มีอะไรบังคับว่าค่าที่รับมาต้องเป็น str -
# และ ipaddress.IPv4Address() ที่ใช้เป็นตัวตรวจอยู่ "รับ int ได้ด้วย" (IPv4Address(
# 3232235777) = 192.168.1.1 ไม่ error) แต่โค้ดทิ้งค่าที่ parse แล้วไปแปะ "สตริงดิบ"
# ลง XML ผลคือส่ง int เข้ามาผ่านฉลุยแล้วได้ <local-ip>3232235777</local-ip> บนอุปกรณ์
# จริง - ยืนยันด้วยการรันจริงแล้ว เป็นอาการเดียวกับ bug 13/14 ที่ตกฟังก์ชันกลุ่มนี้ไป
@validate_call
def remove_static_nat(local_ip: str, global_ip: str):
    ipaddress.IPv4Address(local_ip)
    ipaddress.IPv4Address(global_ip)

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <ip>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            <static>
                                <nat-static-transport-list xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                                    <local-ip>{local_ip}</local-ip>
                                    <global-ip>{global_ip}</global-ip>
                                </nat-static-transport-list>
                            </static>
                        </source>
                    </inside>
                </nat>
            </ip>
        </native>
    '''))

def get_port_forward_information():
    return open_rpc_tag(F'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <ip>
                <nat xmlns="{NS_NAT}">
                    <inside>
                        <source>
                            <static>
                                <nat-static-transport-list-port-fwd>
                                </nat-static-transport-list-port-fwd>
                            </static>
                        </source>
                    </inside>
                </nat>
            </ip>
        </native>
    </filter>                        
</get>
''')

@validate_call
def set_port_forward(
        name: str,
        protocol: Literal["tcp", "udp"],
        local_ip: str,
        local_port: int,
        global_ip: str,
        global_port: int,
        replace_protocol: Literal["tcp", "udp"] | None = None,
        replace_local_ip: str | None = None,
        replace_local_port: int | None = None,
        replace_global_ip: str | None = None,
        replace_global_port: int | None = None,
):
    # name ไม่มีที่เก็บบนอุปกรณ์ (เหมือน set_static_nat) รับไว้เฉยๆ ไม่ใส่ลง XML -
    # ใช้เป็น label ฝั่งเว็บเราเอง (เก็บผ่าน Device_Config_Object)
    # (bug 64) ชื่อนี้ไม่ไปอุปกรณ์เลย แต่ลง cfg_name ของ Device_Config_Object ซึ่งเป็น
    # indexed field ที่ใช้ค้น object กลับ (ดู TRACKED_FEATURES ใน device_router.py) -
    # static NAT กับ port forward เป็น "สองตัวเดียวในระบบ" ที่ชื่อถูกเก็บใน DB ของเรา
    # ที่เหลือ (NAT pool / security profile / ACL) ตั้งและอ่านจากอุปกรณ์ล้วน
    #
    # เดิมกลับหัวกันพอดี: ตัวที่ไม่ลง DB กลับ validate เข้มมาก ส่วนตัวที่ลง DB จริง
    # กลับไม่ตรวจอะไรเลย ชื่อยาว 10000 ตัว/ช่องว่างล้วน/มี HTML ลง indexed field ได้หมด
    # แล้วเด้งกลับไปแสดงบนหน้าเว็บ - ใช้ด่านสร้าง (เข้ม) เพราะผู้ใช้พิมพ์เองจริง ๆ
    name = validate_config_name(name, "Item name")
    ipaddress.IPv4Address(local_ip)
    ipaddress.IPv4Address(global_ip)
    if not 1 <= local_port <= 65535:
        raise ValueError("local_port must be between 1 and 65535")
    if not 1 <= global_port <= 65535:
        raise ValueError("global_port must be between 1 and 65535")

    # ทั้งห้าค่าคือ key ของ list เดียวกัน จึงต้องมีครบหรือไม่มีเลย; รับมาไม่ครบ
    # หมายถึงเสี่ยงลบคนละ entry ห้ามเดาเติมค่าให้เอง
    replace_values = (replace_protocol, replace_local_ip, replace_local_port, replace_global_ip, replace_global_port)
    if any(value is not None for value in replace_values) and not all(value is not None for value in replace_values):
        raise ValueError("replace port-forward key must include all 5 fields")
    remove_xml = ""
    if all(value is not None for value in replace_values):
        ipaddress.IPv4Address(replace_local_ip)
        ipaddress.IPv4Address(replace_global_ip)
        if not 1 <= replace_local_port <= 65535 or not 1 <= replace_global_port <= 65535:
            raise ValueError("replace ports must be between 1 and 65535")
        # เปลี่ยน key = คนละ entry จึงลบและสร้างใน RPC เดียว; key เดิมเท่ากันห้าม
        # remove เพราะ RFC 6241 ไม่รับประกันลำดับ remove/create ของ node เดียวกัน
        if (replace_protocol, replace_local_ip, replace_local_port, replace_global_ip, replace_global_port) != (protocol, local_ip, local_port, global_ip, global_port):
            remove_xml = F'''                        <nat-static-transport-list-port-fwd xmlns:nc="{NS_RPC}" nc:operation="remove">
                            <protocol>{replace_protocol}</protocol>
                            <local-ip>{replace_local_ip}</local-ip>
                            <local-port>{replace_local_port}</local-port>
                            <global-ip>{replace_global_ip}</global-ip>
                            <global-port>{replace_global_port}</global-port>
                        </nat-static-transport-list-port-fwd>
'''

    # แก้จาก <overload/> (ผิด - verify กับอุปกรณ์จริงแล้วว่า "overload" ไม่ใช่
    # keyword ที่ใช้ได้เลยสำหรับ "ip nat inside source static tcp/udp ..." -
    # CLI ตอบ "Invalid input detected" ตรงตำแหน่งนั้นทันที เจอผ่าน "?" บนอุปกรณ์
    # จริงว่า option ที่ใช้ได้จริงคือ egress-interface/extendable/mapping-id/
    # no-alias/no-payload/pool/redundancy/route-map/stateless/vrf เท่านั้น) เป็น
    # <extendable/> แทน - ยืนยันจากอุปกรณ์จริง (HQ-R1, 2026-07-24): พิมพ์คำสั่งฐาน
    # เปล่าๆ (ไม่มี keyword ต่อท้ายเลย) ผ่าน CLI ตรงๆ แล้วอุปกรณ์ "เติม extendable
    # ให้เองอัตโนมัติ" ใน running-config (เพราะ global_ip:global_port เดียวกันถูก
    # ใช้อยู่แล้วโดย "ip nat inside source list ... overload" ที่ set_nat/
    # create_nat_policy ตั้งไว้ก่อนหน้า - extendable คือ keyword ที่ทำให้ global
    # address:port เดียวกันถูก "share" ข้าม mapping ได้ ตรงกับ use case ของ
    # port-forward ที่ต้องแชร์ WAN IP เดียวกับ pool ที่ overload อยู่แล้วเป๊ะ)
    return open_rpc_tag(edit_config_tag(F'''
<native xmlns="{NS_NATIVE}">
    <ip>
        <nat xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-nat">
            <inside>
                <source>
                    <static>
{remove_xml}                        <nat-static-transport-list-port-fwd>
                            <protocol>{protocol}</protocol>
                            <local-ip>{local_ip}</local-ip>
                            <local-port>{local_port}</local-port>
                            <global-ip>{global_ip}</global-ip>
                            <global-port>{global_port}</global-port>
                            <extendable></extendable>
                        </nat-static-transport-list-port-fwd>
                    </static>
                </source>
            </inside>
        </nat>
    </ip>
</native>
'''))

# ลบ port forward entry เดียว - key คือ 5 leaf รวมกัน "protocol local-ip
# local-port global-ip global-port" (ยืนยันจาก Cisco-IOS-XE-nat.yang: `list
# nat-static-transport-list-port-fwd { key "protocol local-ip local-port
# global-ip global-port"; }`) ต้องระบุครบทั้ง 5 ตัวถึงจะลบถูก entry
@validate_call
def remove_port_forward(
        protocol: Literal["tcp", "udp"],
        local_ip: str,
        local_port: int,
        global_ip: str,
        global_port: int,
):
    ipaddress.IPv4Address(local_ip)
    ipaddress.IPv4Address(global_ip)
    return open_rpc_tag(edit_config_tag(F'''
<native xmlns="{NS_NATIVE}">
    <ip>
        <nat xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-nat">
            <inside>
                <source>
                    <static>
                        <nat-static-transport-list-port-fwd xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                            <protocol>{protocol}</protocol>
                            <local-ip>{local_ip}</local-ip>
                            <local-port>{local_port}</local-port>
                            <global-ip>{global_ip}</global-ip>
                            <global-port>{global_port}</global-port>
                        </nat-static-transport-list-port-fwd>
                    </static>
                </source>
            </inside>
        </nat>
    </ip>
</native>
'''))

# ชนิด interface ที่ Cisco native ซ้อน subinterface ไว้ใต้ wrapper ชื่อ
# "<type>-subinterface" อีกชั้น - ยืนยันจาก Cisco-IOS-XE-native.yang (มีแค่
# ATM-ACR/L2LISP/LISP/Port-channel/Serial) ส่วน GigabitEthernet และพวก Ethernet
# ทั้งหมด subinterface อยู่ใน list เดียวกับ physical โดยใช้ name "1.10" ตรงๆ
# ไม่มี wrapper - Cisco-IOS-XE-zone.yang augment zone-member เข้า
# Port-channel-subinterface/Port-channel และ LISP-subinterface/LISP ให้ด้วย
_SUBINTERFACE_WRAPPER_TYPES = {"Port-channel", "LISP", "L2LISP", "Serial", "ATM", "MFR"}


def _zone_member_interface_block(full_name: str, member_xml: str) -> str:
    """ประกอบ <type><name>id</name>{member_xml}</type> ของ interface หนึ่งตัว

    ใส่เฉพาะ <name> ที่เป็น key กับ <zone-member> เท่านั้น ไม่แตะ element อื่นของ
    interface (ip/description/shutdown) เลย - ทั้งขาเพิ่มและขาถอดสมาชิกใช้ตัวนี้
    ร่วมกัน เพื่อให้กฎ subinterface wrapper กับการ validate ชื่อเป็นชุดเดียวกัน
    """
    interface_type, interface_id = _split_interface(_interface_fullname(full_name))
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    block = f'<{interface_type}><name>{interface_id}</name>{member_xml}</{interface_type}>'
    if "." in interface_id and interface_type in _SUBINTERFACE_WRAPPER_TYPES:
        block = f'<{interface_type}-subinterface>{block}</{interface_type}-subinterface>'
    return block


@validate_call
def set_security_zone(
    zone_id: str,
    interfaces: list[str] | None = None,
    previous_interfaces: list[str] | None = None,
) -> str:
    # previous_interfaces แยกความหมาย "เพิ่มสมาชิก" ออกจาก "แก้ไขรายชื่อสมาชิก"
    # ให้ชัด โดยไม่ทำให้ผู้เรียกเดิมเปลี่ยนพฤติกรรม:
    #   - ไม่ส่งมาเลย (None) -> merge อย่างเดียวเหมือนเดิม ไม่ถอดอะไรทั้งนั้น
    #   - ส่งมา (รวม []) -> เทียบกับ interfaces แล้วถอดตัวที่หายไปจากรายชื่อใหม่
    # ผลลัพธ์อยู่ใน edit-config เดียวเสมอ (rollback-on-error ตาม ERROR_OPTION) จึง
    # ไม่มีสถานะกลางที่ interface ตัวหนึ่งถูกถอดแล้วอีกตัวเพิ่มไม่สำเร็จ
    #
    # interfaces=[] คู่กับ previous_interfaces ที่มีสมาชิก = "ถอดสมาชิกทั้งหมด"
    # ไม่ใช่ no-op และ zone ตัวเองยังอยู่ (ไม่มี nc:operation ที่ <security>)
    if not 1 <= len(zone_id) <= 64:
        raise ValueError("zone_id must be between 1 and 64 characters")

    members = list(dict.fromkeys((name or "").strip() for name in (interfaces or [])))
    member_xml = f'<zone-member xmlns="{NS_ZONE}"><security>{escape(zone_id)}</security></zone-member>'
    blocks = [_zone_member_interface_block(name, member_xml) for name in members]

    if previous_interfaces is not None:
        # ถอดด้วย nc:operation="remove" ที่ <zone-member> เท่านั้น ไม่ใช่ที่ตัว
        # interface - ถ้า remove ทั้ง interface จะพา ip/description หายไปด้วย
        keep = set(members)
        removal_xml = f'<zone-member xmlns="{NS_ZONE}" {NC} nc:operation="remove"/>'
        for name in dict.fromkeys((name or "").strip() for name in previous_interfaces):
            if name in keep:
                continue
            blocks.append(_zone_member_interface_block(name, removal_xml))

    interface_xml = f"<interface>{''.join(blocks)}</interface>" if blocks else ""
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <zone>
                <security xmlns="{NS_ZONE}">
                    <id>{escape(zone_id)}</id>
                </security>
            </zone>
            {interface_xml}
        </native>
    '''))

@validate_call
def remove_security_zone(
    zone_id: str,
    reference_config: str | None = None,
) -> str:
    if not 1 <= len(zone_id) <= 64:
        raise ValueError("zone_id must be between 1 and 64 characters")

    from tools.cisco_zone_delete import zone_reference_removals
    references_xml = zone_reference_removals(reference_config, zone_id) if reference_config is not None else ""
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            {references_xml}
            <zone>
                <security xmlns="{NS_ZONE}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                    <id>{escape(zone_id)}</id>
                </security>
            </zone>
        </native>
    '''))

@validate_call
def apply_zone_member(
    interface_type: str,
    interface_id: str,
    zone_id: str,
) -> str:
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <interface>
                <{interface_type}>
                    <name>{interface_id}</name>
                    <zone-member xmlns="{NS_ZONE}">
                        <security>{escape(zone_id)}</security>
                    </zone-member>
                </{interface_type}>
            </interface>
        </native>
    '''))

@validate_call
def remove_zone_member(
    interface_type: str,
    interface_id: str,
    zone_name: str,
) -> str:
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <interface>
                <{interface_type}>
                    <name>{interface_id}</name>
                    <zone-member xmlns="{NS_ZONE}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"/>
                </{interface_type}>
            </interface>
        </native>
    '''))

@validate_call
def set_inspect_class_map(
    name: str,
    prematch: Literal["match-all", "match-any", "match-none"],
    match_acl_names: list[str],
    description: str | None = None,
) -> str:
    if not 1 <= len(name) <= 205:
        raise ValueError("name must be between 1 and 205 characters")
    if not match_acl_names:
        raise ValueError("match_acl_names must contain at least one ACL name")

    description_xml = _description_xml(description)
    match_xml = "\n".join(
        f"<name>{escape(acl_name)}</name>" for acl_name in match_acl_names
    )

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <policy>
                <class-map xmlns="{NS_POLICY}">
                    <name>{escape(name)}</name>
                    <type>inspect</type>
                    <prematch>{prematch}</prematch>
                    {description_xml}
                    <match>
                        <access-group>
                            {match_xml}
                        </access-group>
                    </match>
                </class-map>
            </policy>
        </native>
    '''))

# ลบ inspect class-map ทั้งตัว - key คือ "name" (Cisco IOS-XE class-map/policy-map
# convention ทั่วไป - ใช้เป็นขั้นตอน teardown ของ Firewall Policy Edit/Delete)
@validate_call
def remove_inspect_class_map(name: str) -> str:
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <policy>
                <class-map xmlns="{NS_POLICY}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                    <name>{escape(name)}</name>
                </class-map>
            </policy>
        </native>
    '''))

@validate_call
def set_inspect_policy_map(
    policy_name: str,
    class_name: str,
    action: Literal["inspect", "pass", "drop", "cxsc"],
    log: bool = False,
    parameter_map: str | None = None,
    description: str | None = None,
) -> str:
    if log and action not in ("drop", "pass"):
        raise ValueError("log only applies to drop or pass actions")
    if parameter_map and action not in ("inspect", "cxsc"):
        raise ValueError("parameter_map only applies to inspect or cxsc actions")

    description_xml = _description_xml(description)
    log_xml = "<log/>" if log else ""
    parameter_map_xml = (
        f"<parameter-map>{escape(parameter_map)}</parameter-map>" if parameter_map else ""
    )

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <policy>
                <policy-map xmlns="{NS_POLICY}">
                    <name>{escape(policy_name)}</name>
                    <type>inspect</type>
                    {description_xml}
                    <class>
                        <name>{escape(class_name)}</name>
                        <type>inspect</type>
                        <policy>
                            <action>{action}</action>
                            {log_xml}
                            {parameter_map_xml}
                        </policy>
                    </class>
                </policy-map>
            </policy>
        </native>
    '''))

# ลบ inspect policy-map ทั้งตัว - key คือ "name" เหมือน class-map
@validate_call
def remove_inspect_policy_map(policy_name: str) -> str:
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <policy>
                <policy-map xmlns="{NS_POLICY}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                    <name>{escape(policy_name)}</name>
                </policy-map>
            </policy>
        </native>
    '''))

@validate_call
def set_zone_pair(
    pair_id: str,
    source_zone: str,
    destination_zone: str,
    policy_map_name: str,
    description: str | None = None,
) -> str:
    if not 1 <= len(pair_id) <= 128:
        raise ValueError("pair_id must be between 1 and 128 characters")
    if not 1 <= len(source_zone) <= 64:
        raise ValueError("source_zone must be between 1 and 64 characters")
    if not 1 <= len(destination_zone) <= 64:
        raise ValueError("destination_zone must be between 1 and 64 characters")

    description_xml = _description_xml(description)

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <zone-pair>
                <security xmlns="{NS_ZONE}">
                    <id>{escape(pair_id)}</id>
                    <source>{escape(source_zone)}</source>
                    <destination>{escape(destination_zone)}</destination>
                    {description_xml}
                    <service-policy>
                        <type>
                            <inspect>{escape(policy_map_name)}</inspect>
                        </type>
                    </service-policy>
                </security>
            </zone-pair>
        </native>
    '''))

# ลบ zone-pair ทั้งตัว - key คือ "id" (ยืนยันจาก Cisco-IOS-XE-zone.yang: `list
# security { key "id"; }` ใต้ zone-pair) - ไม่ลบ zone/zone-member ของ interface
# ด้วย เพราะเป็น shared infrastructure ที่ policy อื่นอาจใช้ zone เดียวกันอยู่
# (เหตุผลเดียวกับที่ NAT's teardown ไม่แตะ ip nat inside/outside)
@validate_call
def remove_zone_pair(pair_id: str) -> str:
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <zone-pair>
                <security xmlns="{NS_ZONE}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                    <id>{escape(pair_id)}</id>
                </security>
            </zone-pair>
        </native>
    '''))

def _split_interface(full_name: str) -> tuple[str, str]:
    # "GigabitEthernet1" -> ("GigabitEthernet", "1") เหมือน splitInterfaceName ฝั่ง
    # frontend / _split_interface_name ใน device_router - ต้องแยกเพราะ Cisco native
    # ซ้อน interface ไว้ใต้ element ชื่อ type ของมัน (<GigabitEthernet><name>1</name>)
    match = re.match(r"^([A-Za-z-]+)(.*)$", full_name.strip())
    if not match:
        return full_name.strip(), ""
    return match.group(1), match.group(2)


@validate_call
def create_firewall_policy(
    name: str,
    source_zone: str,
    destination_zone: str,
    action: Literal["inspect", "pass", "drop"] = "inspect",
    source_members: list[str] = [],
    destination_members: list[str] = [],
    source_scopes: str | list[str] = "any",
    applications: list[str] | None = None,
    log: bool = False,
    replace_name: str | None = None,
    release_members: list[str] | None = None,
    reference_config: str | None = None,
    expected_revision: str | None = None,
) -> str:
    # Writer v2 (2026-09, ดู vendor_translators/cisco_zbf.py) - เมื่อมี reference_config
    # (ส่งมาจาก device_router.py หลังอ่าน get_firewall_information สดภายใน DeviceLock
    # เดียวกับที่เขียน) ทุกอย่างเปลี่ยนไปที่ build_cisco_zbf_write_fragment ทั้งหมด:
    # ตรวจ revision/reference-chain/shared-object/Brownfield safety ก่อนเสมอ (เหมือน
    # set_security_policy ของ Juniper) รองรับ applications (Any/Single/Multiple
    # topology ตาม Boolean semantics ที่ปิดข้อกำหนดไว้แล้ว) และ **ไม่สร้าง Zone หรือ
    # ผูก Interface ให้เองอีกต่อไป** (source_members/destination_members/
    # release_members คงพารามิเตอร์ไว้เพื่อไม่ให้ caller เดิมพัง แต่ Writer v2 ไม่อ่าน/
    # ไม่ใช้ค่าเหล่านี้เลย - ผู้ใช้ต้องสร้าง Zone และผูก Interface ผ่านหน้า Zone
    # Interfaces ก่อน แล้วฟอร์ม ZBF เลือกเฉพาะ Zone ที่มีอยู่จริง)
    #
    # ไม่มี reference_config (เช่น caller เก่าที่ยังไม่ผ่าน device_router.py's live
    # guard เลย หรือการเรียกตรงแบบทดสอบ) ยังคง fallback ไปที่โค้ด Writer เดิมด้านล่าง
    # ทั้งหมด (สร้าง Zone/ผูก Interface/ไม่รองรับ applications) เพื่อ backward
    # compatibility - เส้นทางจริงผ่าน API ตอนนี้ส่ง reference_config เสมอจึงไม่ผ่าน
    # โค้ดเดิมนี้อีกแล้วในทางปฏิบัติ (deprecated - จะลบเมื่อยืนยันไม่มี caller อื่นเหลือ)
    if reference_config is not None:
        from vendor_translators.cisco_zbf import build_cisco_zbf_write_fragment
        fragment = build_cisco_zbf_write_fragment(
            reference_config=reference_config,
            name=name, source_zone=source_zone, destination_zone=destination_zone,
            action=action, source_scopes=source_scopes, applications=applications, log=log,
            replace_name=replace_name, expected_revision=expected_revision,
        )
        return open_rpc_tag(edit_config_tag(fragment))

    if not 1 <= len(name) <= 64:
        raise ValueError("name must be between 1 and 64 characters")

    if replace_name is not None and not 1 <= len(replace_name) <= 64:
        raise ValueError("replace_name must be between 1 and 64 characters")

    derived = f"FW_{name}"
    # replace_name มีค่าเฉพาะจากทางแก้ไข: เปิด replace ที่ object ของ policy นี้
    # ผู้เรียกเดิมที่ไม่ส่งค่านี้ยังสร้าง XML แบบเดิมทุกไบต์
    acl_open = f'<extended xmlns="{NS_ACL}" {NC} nc:operation="replace">' if replace_name is not None else f'<extended xmlns="{NS_ACL}">'
    class_open = f'<class-map xmlns="{NS_POLICY}" {NC} nc:operation="replace">' if replace_name is not None else f'<class-map xmlns="{NS_POLICY}">'
    policy_open = f'<policy-map xmlns="{NS_POLICY}" {NC} nc:operation="replace">' if replace_name is not None else f'<policy-map xmlns="{NS_POLICY}">'
    pair_open = f'<security xmlns="{NS_ZONE}" {NC} nc:operation="replace">' if replace_name is not None else f'<security xmlns="{NS_ZONE}">'
    # log ใช้ได้เฉพาะ action drop/pass (inspect ไม่มี log ใน YANG - ดู
    # set_inspect_policy_map) - ถ้าเลือก inspect ก็เมิน log ไปเงียบๆ ไม่ error
    log_xml = "<log/>" if log and action in ("drop", "pass") else ""

    scopes = [source_scopes] if isinstance(source_scopes, str) else source_scopes
    scopes = [scope.strip() for scope in scopes if scope and scope.strip()]
    if not scopes:
        scopes = ["any"]

    ace_rule_parts = []
    for index, scope in enumerate(scopes):
        if scope.lower() == "any":
            match_xml = "<any/>"
        else:
            network = ipaddress.IPv4Network(scope, strict=False)
            match_xml = (
                f"<ipv4-address>{network.network_address}</ipv4-address>"
                f"<mask>{network.hostmask}</mask>"
            )
        sequence = (index + 1) * 10
        ace_rule_parts.append(f'''
                        <access-list-seq-rule>
                            <sequence>{sequence}</sequence>
                            <ace-rule>
                                <action>permit</action>
                                <protocol>ip</protocol>
                                {match_xml}
                                <dst-any/>
                            </ace-rule>
                        </access-list-seq-rule>''')
    ace_rules_xml = "".join(ace_rule_parts)

    member_blocks = []
    active_members = set()
    for iface, zone in (
        [(member, source_zone) for member in source_members]
        + [(member, destination_zone) for member in destination_members]
    ):
        interface_type, interface_id = _split_interface(iface)
        if not interface_id:
            continue
        active_members.add(f"{interface_type}{interface_id}")
        member_blocks.append(f'''
                <{interface_type}>
                    <name>{interface_id}</name>
                    <zone-member xmlns="{NS_ZONE}">
                        <security>{escape(zone)}</security>
                    </zone-member>
                </{interface_type}>''')
    # release_members คือสมาชิกเดิมที่ฟอร์มอ่านจากอุปกรณ์แล้วผู้ใช้เอาติ๊กออก
    # remove เฉพาะ zone-member จึงไม่กระทบ IP/description ของ interface
    for iface in release_members or []:
        interface_type, interface_id = _split_interface(iface)
        if not interface_id or f"{interface_type}{interface_id}" in active_members:
            continue
        member_blocks.append(f'''
                <{interface_type}>
                    <name>{interface_id}</name>
                    <zone-member xmlns="{NS_ZONE}" {NC} nc:operation="remove"/>
                </{interface_type}>''')
    interface_xml = (
        f"<interface>{''.join(member_blocks)}</interface>" if member_blocks else ""
    )

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <zone>
                <security xmlns="{NS_ZONE}">
                    <id>{escape(source_zone)}</id>
                </security>
                <security xmlns="{NS_ZONE}">
                    <id>{escape(destination_zone)}</id>
                </security>
            </zone>
            {interface_xml}
            <ip>
                <access-list>
                    {acl_open}
                        <name>{escape(derived)}</name>
                        {ace_rules_xml}
                    </extended>
                </access-list>
            </ip>
            <policy>
                {class_open}
                    <name>{escape(derived)}</name>
                    <type>inspect</type>
                    <prematch>match-any</prematch>
                    <match>
                        <access-group>
                            <name>{escape(derived)}</name>
                        </access-group>
                    </match>
                </class-map>
                {policy_open}
                    <name>{escape(derived)}</name>
                    <type>inspect</type>
                    <class>
                        <name>{escape(derived)}</name>
                        <type>inspect</type>
                        <policy>
                            <action>{action}</action>
                            {log_xml}
                        </policy>
                    </class>
                </policy-map>
            </policy>
            <zone-pair>
                {pair_open}
                    <id>{escape(name)}</id>
                    <source>{escape(source_zone)}</source>
                    <destination>{escape(destination_zone)}</destination>
                    <service-policy>
                        <type>
                            <inspect>{escape(derived)}</inspect>
                        </type>
                    </service-policy>
                </security>
            </zone-pair>
        </native>
    '''))


@validate_call
def remove_firewall_policy(
    name: str,
    reference_config: str | None = None,
    expected_revision: str | None = None,
) -> str:
    # รื้อ ACL/class-map/policy-map/zone-pair ที่ derive จาก policy เดียวพร้อมกัน
    # ใช้กฎชื่อเดียวกับ create_firewall_policy จึงรองรับชื่อที่ escape ใน XML ได้
    #
    # reference_config (2026-09, ดู vendor_translators/cisco_zbf.py) - เกณฑ์เดียวกับ
    # create_firewall_policy เพราะ derive ชื่อ FW_<name> เหมือนกันทุกประการ - ถ้าไม่ใช่
    # systemManagedShape จริง การลบตามชื่อ derive จะเสี่ยงลบ object ผิดตัว/ทิ้ง
    # Brownfield จริงเป็น orphan ไม่มีค่า = ข้ามการตรวจ (ใช้กับ /validate เท่านั้น)
    if reference_config is not None:
        from vendor_translators.cisco_zbf import build_cisco_zbf_delete_fragment
        fragment = build_cisco_zbf_delete_fragment(
            reference_config=reference_config,
            name=name,
            expected_revision=expected_revision,
        )
        return open_rpc_tag(edit_config_tag(fragment))

    if not 1 <= len(name) <= 64:
        raise ValueError("name must be between 1 and 64 characters")
    derived = f"FW_{name}"
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <ip>
                <access-list>
                    <extended xmlns="{NS_ACL}" {NC} nc:operation="remove">
                        <name>{escape(derived)}</name>
                    </extended>
                </access-list>
            </ip>
            <policy>
                <class-map xmlns="{NS_POLICY}" {NC} nc:operation="remove">
                    <name>{escape(derived)}</name>
                    <type>inspect</type>
                </class-map>
                <policy-map xmlns="{NS_POLICY}" {NC} nc:operation="remove">
                    <name>{escape(derived)}</name>
                    <type>inspect</type>
                </policy-map>
            </policy>
            <zone-pair>
                <security xmlns="{NS_ZONE}" {NC} nc:operation="remove">
                    <id>{escape(name)}</id>
                </security>
            </zone-pair>
        </native>
    '''))


def get_firewall_information():
    # ดึง zone/zone-pair/policy-map/class-map/ACL/interface มาใน RPC เดียว:
    # ciscoZbfParser.js เดินตาม reference จริง (ไม่เดาชื่อ join)
    # ค่า action, log, Traffic ACL และ zone-member จริงเพื่อ pre-fill โดยไม่เดา
    # ค่าใดที่ ACL แปลงกลับเป็นฟอร์มไม่ได้จะถูกแสดงอ่านอย่างเดียวและห้าม Apply
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <interface></interface>
            <zone>
                <security xmlns="{NS_ZONE}"></security>
            </zone>
            <zone-pair>
                <security xmlns="{NS_ZONE}"></security>
            </zone-pair>
            <ip>
                <access-list>
                    <extended xmlns="{NS_ACL}"></extended>
                </access-list>
            </ip>
            <policy>
                <class-map xmlns="{NS_POLICY}"></class-map>
                <policy-map xmlns="{NS_POLICY}"></policy-map>
            </policy>
        </native>
    </filter>
</get>
''')


# หน้า zoneInterfaces.jsx (แท็บ "Zone Interfaces") อ่านรายชื่อ zone กลับมา -
# path ตรงกับที่ set_security_zone เขียน (native/zone/security, key "id") คนละ
# query กับ get_firewall_information (หน้า Stateful อ่าน zone-pair/policy-map/ACL และ
# interface เพื่อ pre-fill policy ส่วนหน้านี้ใช้ข้อมูล zone ของตัวเอง) - สมาชิก interface ของแต่ละ zone ไม่ได้อยู่ตรงนี้ (zone-member เป็น
# leaf ใต้ native/interface/<type> เอง ไม่ใช่ list ย้อนกลับใต้ zone) frontend
# join กับ get_switchport_information (ขอ native/interface ทั้งก้อนอยู่แล้ว -
# ครอบคลุม zone-member ไปในตัวโดยไม่ต้อง query เพิ่ม) เอาเอง
def get_security_zone_information():
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <zone>
                <security xmlns="{NS_ZONE}"></security>
            </zone>
        </native>
    </filter>
</get>
''')


def get_security_status():
    # หน้า dashboard "Security Status" ต้องการ hit-count จริง ซึ่งไม่ได้อยู่ใน
    # config model (get_acl_information/get_firewall_information อ่านแค่ค่าที่
    # ตั้งไว้ ไม่มีตัวนับ) แต่เป็น oper (config false) data คนละ module กันเลย -
    # ยืนยันจาก YANG แล้ว:
    #   - Cisco-IOS-XE-acl-oper.yang: container access-lists (top-level, ไม่ได้
    #     อยู่ใต้ native) -> access-list-entries-oper-data/match-counter ต่อ ACE
    #     พร้อม access-list-entries-rule-data (action/protocol/port) ในตัว ไม่ต้อง
    #     join กับ get_acl_information แยก
    #   - Cisco-IOS-XE-fw-oper.yang: container zbfw (top-level เช่นกัน) ->
    #     zonepair-statistics มี src/dst zone + policy-name และ list
    #     fw-traffic-class-entry ต่อ class ที่มี class-action + pkts-counter
    # ทั้งสอง container เป็น top-level ของ module ตัวเอง (ไม่ได้ augment เข้า
    # native เหมือน config path ปกติ) - รวม subtree filter เดียวกันได้เพราะเป็น
    # sibling กันใต้ <filter>
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <access-lists xmlns="{NS_ACL_OPER}"/>
        <zbfw xmlns="{NS_FW_OPER}"/>
    </filter>
</get>
''')


def get_vlan_information():
    # หน้า vlan.jsx (list) อ่าน VLAN database กลับมา - path ตรงกับที่ set_vlan
    # เขียน (native/vlan/vlan-list) ยืนยันจาก Cisco-IOS-XE-vlan.yang:936-1013
    # แล้วว่า list นี้ key ด้วย id มี name/state(active|suspend, read-only)/
    # shutdown (empty leaf - มี = ปิดอยู่, ไม่มี = เปิดอยู่ ตรงกับ set_vlan)
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <interface/>
            <vlan/>
        </native>
        
    </filter>
</get>
''')


@validate_call
def set_vlan(
    vlan_id: int,
    name: str | None = None,
    shutdown: bool = False,
) -> str:
    if not 1 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 1 and 4094")
    if name is not None and not 1 <= len(name) <= 128:
        raise ValueError("name must be between 1 and 128 characters")

    name_xml = f"<name>{escape(name)}</name>" if name else ""
    shutdown_xml = "<shutdown/>" if shutdown else ""

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <vlan>
                <vlan-list xmlns="{NS_VLAN}">
                    <id>{vlan_id}</id>
                    {name_xml}
                    {shutdown_xml}
                </vlan-list>
            </vlan>
        </native>
    '''))

# ลบ VLAN ออกจาก VLAN database ทั้งตัว - key คือ "id" (ยืนยันจาก
# Cisco-IOS-XE-vlan.yang:936-1013 เดียวกับที่ get_vlan_information/set_vlan
# ใช้อยู่แล้ว) - ไม่แตะ switchport membership ของ interface ใดๆ เลย (คนละ
# concern กัน - interface ที่เคยเป็นสมาชิกยังคงตั้งค่าไว้เหมือนเดิม จัดการแยก
# ผ่านหน้า Interfaces เอง)
@validate_call
def remove_vlan(vlan_id: int) -> str:
    if not 1 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 1 and 4094")
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <vlan>
                <vlan-list xmlns="{NS_VLAN}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                    <id>{vlan_id}</id>
                </vlan-list>
            </vlan>
        </native>
    '''))

@validate_call
def set_interface_vlan(
    vlan_id: int,
    ip: str,
    mask: int,
    shutdown: bool = True,
    description: str | None = None,
    mtu: int | None = None,
) -> str:
    if not 1 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 1 and 4094")
    return set_interface_static_ip(
        interface_type="Vlan",
        interface_id=str(vlan_id),
        ip=ip,
        mask=mask,
        shutdown=shutdown,
        description=description,
        mtu=mtu,
    )

def get_ip_default_gateway():
    return open_rpc_tag(f'''
    <get>
      <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
          <ip>
            <default-gateway/>
          </ip>
        </native>
      </filter>
    </get>
    ''')

@validate_call
def set_ip_default_gateway(
    ip: str
):
    # เดิมใส่ค่าลง XML ตรง ๆ ไม่ตรวจอะไรเลย (ปัญหาเดียวกับ bug 15 ที่ไล่แก้ฟิลด์ IP
    # ทั้งไฟล์ไปแล้ว) ตรวจว่าเป็น IPv4 จริงก่อน ค่าผิดจะถูกปฏิเสธที่ backend แทนที่จะ
    # ไปถึงอุปกรณ์ แล้ว escape เป็นด่านสำรองกันการแทรก XML
    address = str(ipaddress.IPv4Address(ip.strip()))
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <ip>
                <default-gateway>{escape(address)}</default-gateway>
            </ip>
        </native>
    '''))

def get_ip_routing():
    return open_rpc_tag(f'''
        <get>
            <filter type="subtree">
                <native xmlns="{NS_NATIVE}">
                    <ip>
                        <routing-conf/>
                    </ip>
                </native>
            </filter>
        </get>
    ''')

@validate_call
def set_ip_routing(
    enabled: Literal[True, False] = True
) -> str:
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <ip>
                <routing-conf>
                    <routing>{str(enabled).lower()}</routing>
                </routing-conf>
            </ip>
        </native>
    '''))

def get_switchport_information():
    return open_rpc_tag('''
    <get>
        <filter type="subtree">
            <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
                <interface/>
            </native>
            <interfaces xmlns="http://openconfig.net/yang/interfaces">
                <interface>
                    <name/>
                    <ethernet xmlns="http://openconfig.net/yang/interfaces/ethernet">
                        <config/>
                    </ethernet>
                </interface>
            </interfaces>
        </filter>
    </get>
''')

@validate_call
def set_switchport(
  interface_type: str,
  interface_id: str,
  switchport: Literal[True, False] = True,
):
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)

    if switchport:
        state="true"
    else:
        state="false"

    # อุปกรณ์ปฏิเสธการเปิด switchport ขณะที่ยังมี IP อยู่ ("To change switchport from
    # false to true, delete ip address 1st") จึงลบ ip ไปในก้อนเดียวกัน ใช้ operation
    # "remove" เพื่อให้ยิงซ้ำกับพอร์ตที่ไม่มี IP ได้โดยไม่เกิด data-missing
    # ทิศตรงข้าม (ปิด switchport) ไม่ต้องแตะ ip เพราะการตั้ง IP เป็นหน้าที่ของ
    # set_interface_static_ip ซึ่งปิด switchport ให้ในก้อนเดียวกันอยู่แล้ว
    clear_ip_xml = (
        '<ip xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove"/>'
        if switchport else ""
    )

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
             <interface>
                <{interface_type}>
                    <name>{interface_id}</name>
                    {clear_ip_xml}
                    <switchport-conf>
                        <switchport>{state}</switchport>
                    </switchport-conf>
                </{interface_type}>
            </interface>
        </native>
    '''))
    

@validate_call
def apply_interface_to_vlan(
    interface_type: str,
    interface_id: str,
    mode: Literal["access", "trunk"],
    vlan_id: int | None = None,
    trunk_allowed_vlans: list | Literal["1-4094"] | None = None,
    switchport: bool | None = None,
    shutdown: bool | None = None,
    description: str | None = None,
) -> str:
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    if mode == "access":
        if vlan_id is None:
            raise ValueError("vlan_id is required when mode is 'access'")
        if trunk_allowed_vlans is not None:
            raise ValueError("trunk_allowed_vlans is not valid for access mode")
        if not 1 <= vlan_id <= 4094:
            raise ValueError("vlan_id must be between 1 and 4094")

        mode_xml = f"<mode xmlns=\"{NS_SWITCH}\"><{mode}></{mode}></mode>"
        mode_config_xml = f"<access xmlns=\"{NS_SWITCH}\"><vlan><vlan>{vlan_id}</vlan></vlan></access>"
    else:
        if vlan_id is not None:
            raise ValueError("vlan_id is not valid for trunk mode, use trunk_allowed_vlans")
        if not trunk_allowed_vlans:
            raise ValueError("trunk_allowed_vlans is required when mode is 'trunk'")
        if trunk_allowed_vlans == "1-4094":
            vlan_range_str = "1-4094"
        elif isinstance(trunk_allowed_vlans, list):
            vlan_ids = []
            for value in trunk_allowed_vlans:
                if isinstance(value, bool) or not isinstance(value, (int, str)):
                    raise ValueError("trunk_allowed_vlans must be a list of VLAN numbers")
                try:
                    vlan = int(value)
                except ValueError as exc:
                    raise ValueError("trunk_allowed_vlans must be a list of VLAN numbers") from exc
                if not 1 <= vlan <= 4094:
                    raise ValueError("trunk_allowed_vlans entries must be between 1 and 4094")
                vlan_ids.append(vlan)
            vlan_range_str = ",".join(str(vlan) for vlan in sorted(set(vlan_ids)))
        else:
            raise ValueError("trunk_allowed_vlans must be 1-4094 or a list of VLAN IDs")
        mode_xml = f"<mode xmlns=\"{NS_SWITCH}\"><{mode}></{mode}></mode>"
        mode_config_xml = (
            f"<trunk xmlns=\"{NS_SWITCH}\"><allowed><vlan-v2><vlan-choices>"
            f"<vlans>{escape(vlan_range_str)}</vlans>"
            f"</vlan-choices></vlan-v2></allowed></trunk>"
        )

    # การตั้ง VLAN ให้พอร์ตที่ยังเป็น Layer 3 ต้องทำสามอย่าง คือเปิด switchport
    # ลบ IP เดิม แล้วเขียน mode/VLAN ซึ่งอยู่ใน element ของ interface เดียวกันหมด
    # จึงใส่ไว้ใน edit-config เดียวได้ ทำให้การกด Save หนึ่งครั้งเป็น RPC เดียวและ
    # atomic จาก rollback-on-error แทนที่จะยิงสามคำสั่งเรียงกัน
    #
    # ทั้งสองพารามิเตอร์เป็นตัวเลือก ถ้าไม่ส่งมาจะได้ XML เท่าเดิมทุกไบต์ ผู้เรียกเดิม
    # ที่ตั้ง VLAN บนพอร์ตที่เป็น Layer 2 อยู่แล้วจึงไม่เปลี่ยนพฤติกรรม
    switchport_xml = ""
    if switchport is not None:
        # เปิด switchport ต้องลบ ip ในก้อนเดียวกัน ("To change switchport from false
        # to true, delete ip address 1st") ใช้ remove เพื่อให้พอร์ตที่ไม่มี IP ผ่านด้วย
        clear_ip_xml = f'<ip {NC} nc:operation="remove"/>' if switchport else ""
        switchport_xml = (
            f"{clear_ip_xml}"
            f"<switchport-conf><switchport>{'true' if switchport else 'false'}</switchport></switchport-conf>"
        )

    # Cisco เก็บสถานะพอร์ตเป็น presence leaf: ปิดคือใส่ <shutdown/> เปล่า ส่วนเปิด
    # ต้องสั่ง remove ต่างจาก Huawei ที่เขียนค่า up/down ตรง ๆ
    shutdown_xml = ""
    if shutdown is not None:
        shutdown_xml = "<shutdown/>" if shutdown else f'<shutdown {NC} nc:operation="remove"/>'

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <interface>
                <{interface_type}>
                    <name>{interface_id}</name>
                    {switchport_xml}
                    <switchport-config>
                        <switchport>
                            {mode_xml}
                            {mode_config_xml}
                        </switchport>
                    </switchport-config>
                    {shutdown_xml}{_interface_description_xml(description)}
                </{interface_type}>
            </interface>
        </native>
    '''))

@validate_call
def remove_switchport(
    interface_type: str,
    interface_id: str,
) -> str:
    interface_type = _interface_type_tag(interface_type)
    interface_id = _interface_id_value(interface_id)
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <interface>
                <{interface_type}>
                    <name>{interface_id}</name>
                    <switchport-conf>
                        <switchport>false</switchport>
                    </switchport-conf>
                </{interface_type}>
            </interface>
        </native>
    '''))


@validate_call
def set_ikev2_proposal(
    proposal_name: str,
    encryption: Literal["aes-cbc-128", "aes-cbc-192", "aes-cbc-256", "aes-gcm-128", "aes-gcm-256"],
    integrity: Literal["sha1", "sha256", "sha384", "sha512"],
    dh_group: Literal["fourteen", "fifteen", "sixteen", "nineteen", "twenty", "twenty-one"],
    existing: bool = False,
):
    proposal_name = (
        validate_object_ref(proposal_name, "IKEv2 proposal name")
        if existing else validate_config_name(proposal_name, "IKEv2 proposal name")
    )
    hash_xml = (
        f"<prf><{integrity}/></prf>"
        if encryption in _IKEV2_COMBINED_MODE_ENCRYPTION
        else f"<integrity><{integrity}/></integrity>"
    )
    return open_rpc_tag(edit_config_tag(f'''
<native xmlns="{NS_NATIVE}">
    <crypto>
        <ikev2 xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
            <proposal {NC} nc:operation="replace">
                <name>{escape(proposal_name)}</name>
                <encryption><{encryption}/></encryption>
                <group><{dh_group}/></group>
                {hash_xml}
            </proposal>
        </ikev2>
    </crypto>
</native>
'''))

@validate_call
def set_ikev2_policy(
    policy_name: str,
    ikev2_proposals: list[str],
    local_ip: str | None = None,
    existing: bool = False,
):
    policy_name = (
        validate_object_ref(policy_name, "IKEv2 policy name")
        if existing else validate_config_name(policy_name, "IKEv2 policy name")
    )
    if not ikev2_proposals:
        raise ValueError("IKEv2 policy must have at least 1 proposal")
    proposals = [validate_object_ref(name, "IKEv2 proposal name") for name in ikev2_proposals]
    if len(set(proposals)) != len(proposals):
        raise ValueError("IKEv2 policy has duplicate proposals")
    match_xml = ""
    if local_ip:
        local_ip = validate_ipv4(local_ip, "local_ip")
        match_xml = f"<match><address><local-ip>{local_ip}</local-ip></address></match>"
    proposal_xml = "".join(
        f"<proposal><proposals>{escape(name)}</proposals></proposal>" for name in proposals
    )
    return open_rpc_tag(edit_config_tag(f'''
<native xmlns="{NS_NATIVE}">
    <crypto>
            <ikev2 xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <policy {NC} nc:operation="replace">
                    <name>{escape(policy_name)}</name>
                    {match_xml}
                    {proposal_xml}
                </policy>
            </ikev2>
        </crypto>
</native>
'''))

# for psk only
def set_ikev2_keyring(
    keyring_name: str,
    peer_name: str,
    destination_ip: str,
    pre_shared_key: str
):
    return open_rpc_tag(edit_config_tag(F'''
<native xmlns="{NS_NATIVE}">
    <crypto>
            <ikev2 xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <keyring>
                    <name>{keyring_name}</name>
                    <peer>
                        <name>{peer_name}</name>
                        <address>
                            <ipv4>
                                <ipv4-address>{destination_ip}</ipv4-address>
                            </ipv4>
                        </address>
                        <pre-shared-key>
                            <key>{pre_shared_key}</key>
                        </pre-shared-key>
                    </peer>
                </keyring>
            </ikev2>
        </crypto>
</native>
'''))

def set_ikev2_profile(
    profile_name: str,
    remote_address: str,
    remote_subnet: str,
    keyring_name: str
):
    return open_rpc_tag(edit_config_tag(F'''
<native xmlns="{NS_NATIVE}">
    <crypto>
            <ikev2 xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <profile>
                    <name>{profile_name}</name>
                    <match>
                        <identity>
                            <remote>
                                <address>
                                    <ipv4>
                                        <ipv4-address>{remote_address}</ipv4-address>
                                        <ipv4-mask>{remote_subnet}</ipv4-mask>
                                    </ipv4>
                                </address>
                            </remote>
                        </identity>
                    </match>
                    <authentication>
                        <remote>
                            <pre-share></pre-share>
                        </remote>
                        <local>
                            <pre-share></pre-share>
                        </local>
                    </authentication>
                    <keyring>
                        <local>
                            <name>{keyring_name}</name>
                        </local>
                    </keyring>
                </profile>
            </ikev2>
        </crypto>
</native>
'''))

def set_ipsec_transform_set(
    transform_name: str,
    encryption_method: str,
    integrity_method: str,
    key_size: Literal["128", "192", "256"] = "256"
):
    return open_rpc_tag(edit_config_tag(F'''
<native xmlns="{NS_NATIVE}">
    <crypto>
            <ipsec xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <transform-set>
                    <tag>{transform_name}</tag>
                    <esp>{encryption_method}</esp>
                    <esp-hmac>{integrity_method}</esp-hmac>
                    <key-bit>{key_size}</key-bit>
                    <mode>
                        <tunnel></tunnel>
                    </mode>
                </transform-set>
            </ipsec>
        </crypto>
</native>
'''))

def set_ipsec_profile(
    profile_name: str,
    transform_set_name: str,
    ikev2_profile_name: str
):
    return open_rpc_tag(edit_config_tag(F'''
<native xmlns="{NS_NATIVE}">
    <crypto>
            <ipsec xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <profile>
                    <name>{profile_name}</name>
                    <set>
                        <transform-set>{transform_set_name}</transform-set>
                        <ikev2-profile>{ikev2_profile_name}</ikev2-profile>
                    </set>
                </profile>
            </ipsec>
        </crypto>
</native>
'''))

def set_tunnel_interface(
    interface_number: str,
    tun_ip: str,
    tun_subnet: str,
    wan_interface: str,
    remote_ip: str,
    ipsec_profile: str
):
    return open_rpc_tag(edit_config_tag(F'''
<native xmlns="{NS_NATIVE}">
    <interface>
        <Tunnel>
            <name>{interface_number}</name>
            <ip>
                <address>
                    <primary>
                        <address>{tun_ip}</address>
                        <mask>{tun_subnet}</mask>
                    </primary>
                </address>
            </ip>
            <tunnel xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-tunnel">
                <source>{wan_interface}</source>
                <mode>
                    <ipsec>
                        <ipv4-mode></ipv4-mode>
                    </ipsec>
                </mode>
                <destination-config>
                    <ipv4>{remote_ip}</ipv4>
                </destination-config>
                <protection>
                    <ipsec xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                        <profile-option>
                            <name>{ipsec_profile}</name>
                        </profile-option>
                    </ipsec>
                </protection>
            </tunnel>
        </Tunnel>
    </interface>
</native>
'''))

# ipsec ที่ต้องการ integrity hash แยก (combined-mode cipher อย่าง esp-gcm/esp-gmac
# มี authentication ในตัวอยู่แล้ว ไม่ต้องมี esp-hmac ซ้ำ - ยืนยันจาก YANG `when`
# constraint: Cisco-IOS-XE-crypto.yang esp-hmac leaf `when "../esp != 'esp-gcm'
# and ../esp != 'esp-gmac'"`)
_IPSEC_COMBINED_MODE_ESP = {"esp-gcm", "esp-gmac"}
# (bug 90) ฝั่ง IKEv2 ก็มีกฎเดียวกัน แต่เดิมไม่มีใครดูแล - AES-GCM เป็น combined-mode
# cipher ที่มี authentication อยู่ในตัวแล้ว Cisco จึงห้ามใส่ <integrity> คู่กัน และ
# **บังคับให้ใส่ <prf> แทน** ถ้าไม่ใส่ proposal จะถูกมองว่าไม่สมบูรณ์ อุปกรณ์ตอบว่า
# "IKEv2 policy MUST have only complete proposals attached" (เจอจริงจากผลทดสอบผู้ใช้)
# ยืนยันจาก Cisco-IOS-XE-crypto.yang: container prf (L5182) อยู่ถัดจาก container
# integrity ในกลุ่มเดียวกันของ ikev2 proposal มี leaf ชุดเดียวกัน (md5/sha1/sha256/
# sha384/sha512) จึงเอาค่าที่ผู้ใช้เลือกไว้สำหรับ integrity มาใส่ prf ได้ตรง ๆ
_IKEV2_COMBINED_MODE_ENCRYPTION = {"aes-gcm-128", "aes-gcm-256"}
# ipsec cipher ที่ต้องระบุ key-bit (128/192/256) แยก เพราะชื่อ cipher เองไม่ได้
# ล็อคขนาด key ไว้ (esp-192-aes/esp-256-aes ล็อคขนาดในชื่ออยู่แล้ว ไม่ต้องมี
# key-bit ซ้ำ) - ยืนยันจาก YANG `when` constraint ของ leaf key-bit เช่นกัน
_IPSEC_KEY_SIZE_REQUIRED_ESP = {"esp-aes", "esp-gcm", "esp-gmac"}


# (ระลอก C1) ลบ security profile ทั้งก้อนใน RPC เดียว - ฝั่ง Juniper มีคำสั่งนี้อยู่แล้ว
# แต่ Cisco ไม่มี ทำให้ security_profile.jsx ต้องยิง remove ทีละตัว 6 คำสั่ง ถ้าพังกลางทาง
# จะเหลือ object ค้างที่ผู้ใช้มองไม่เห็นและลบต่อไม่ได้ (ตารางอ่านจาก ipsec profile เป็นหลัก
# พอตัวนั้นถูกลบไปแล้ว object ที่เหลือกลายเป็นขยะที่ไม่มี UI ไหนเข้าถึงได้อีก)
#
# ลำดับใน XML ไล่จากตัวที่ถูกอ้างอิงมากสุดไปหาน้อยสุดเหมือนที่ frontend เคยทำ แต่เมื่ออยู่
# ใน edit-config เดียวกันแล้ว อุปกรณ์เป็นคนจัดการ dependency เอง ลำดับจึงไม่ใช่ประเด็นอีก
@validate_call
def remove_security_profile(name: str) -> str:
    # (bug 63) ชื่อนี้ "อ่านกลับมาจากอุปกรณ์" ไม่ใช่ผู้ใช้พิมพ์เอง (ผู้ใช้กดจากตารางที่
    # เรนเดอร์จาก get_*) จึงใช้ด่านอ้างอิงที่ตรวจแค่ความปลอดภัย ไม่บังคับสไตล์การตั้งชื่อ -
    # เดิมใช้ validate_config_name ซึ่งเข้มกว่าที่อุปกรณ์ยอมรับจริง ทำให้ของที่มีอยู่จริง
    # บนอุปกรณ์ (ตั้งจาก CLI / ติดมาก่อน onboard) โชว์บนหน้าเว็บแต่กดลบไม่ได้ -
    # escape() ยังคงไว้ทุกจุดเป็นด่านที่สอง
    name = validate_object_ref(name, "Security profile name")
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                <ikev2 xmlns="{NS_CRYPTO}">
                    <profile {NC} nc:operation="remove"><name>{escape(f"{name}-IKEV2-PROFILE")}</name></profile>
                    <keyring {NC} nc:operation="remove"><name>{escape(f"{name}-KEYRING")}</name></keyring>
                </ikev2>
                <ipsec xmlns="{NS_CRYPTO}">
                    <profile {NC} nc:operation="remove"><name>{escape(f"{name}-IPSEC-PROFILE")}</name></profile>
                    <transform-set {NC} nc:operation="remove"><tag>{escape(f"{name}-IPSEC-PROP")}</tag></transform-set>
                </ipsec>
            </crypto>
        </native>
    '''))


# (bug 89) ตัวเลือกด้านล่างจำกัดไว้เท่าที่ **C8000v รับจริง** ไม่ใช่เท่าที่ YANG ประกาศ
# ที่มา: ผู้ใช้กด "?" บนอุปกรณ์จริง (6 ก.ย. 2026) แล้วพบว่าค่าที่เราเคยเสนอเกินไปถูกปฏิเสธ
# ด้วย "inconsistent value: Device refused one or more commands" ทุกครั้ง
#   crypto ikev2 proposal encryption -> aes-cbc-128/192/256, aes-gcm-128/256 (ไม่มี 3des/des)
#   crypto ikev2 proposal integrity  -> sha1, sha256, sha384, sha512        (ไม่มี md5)
#   crypto ikev2 proposal group      -> 14, 15, 16, 19, 20, 21              (ไม่มี 1/2/5/24)
#   crypto ipsec transform-set esp   -> esp-aes, esp-192-aes, esp-256-aes, esp-gcm, esp-seal
#   crypto ipsec transform-set hmac  -> ไม่รับ esp-md5-hmac
# ถ้าเปลี่ยนไปใช้อุปกรณ์รุ่นอื่น ให้กด "?" บนรุ่นนั้นแล้วอัปเดตทั้งที่นี่และ
# UNSUPPORTED_BY_PLATFORM ใน security_profileFormModal.jsx ให้ตรงกัน
@validate_call
def create_security_profile(
    name: str,
    peer_ip: str,
    ipsec_encryption: Literal["esp-aes", "esp-gcm", "esp-seal", "esp-192-aes", "esp-256-aes"],
    ipsec_integrity: Literal["esp-sha-hmac", "esp-sha256-hmac", "esp-sha384-hmac", "esp-sha512-hmac"] | None = None,
    ipsec_key_size: Literal["128", "192", "256"] | None = None,
    pfs_group: Literal["group14", "group15", "group16", "group19", "group20", "group21"] | None = None,
    tunnel_mode: Literal["tunnel", "transport"] = "tunnel",
    replace_name: str | None = None,
    # (bug 93) PSK ย้ายมาท้ายสุดและกลายเป็น optional - **ไม่ส่ง = คงค่าเดิมบนอุปกรณ์**
    # เพราะอ่านค่ากลับมาไม่ได้ (อุปกรณ์ไม่คืน PSK) การบังคับให้กรอกใหม่ทุกครั้งที่แก้ไข
    # แปลว่าผู้ใช้ที่อยากแก้แค่ algorithm ต้องจำ PSK เดิมมาพิมพ์ใหม่ พิมพ์ผิดเมื่อไหร่
    # tunnel พังทั้งที่ไม่ได้ตั้งใจแตะ - ตำแหน่งพารามิเตอร์ย้ายได้เพราะทุกที่เรียกด้วย
    # keyword (build_payload ใช้ function(**params)) ไม่มีที่ไหนเรียกแบบ positional
    psk: str | None = None,
) -> str:
    # รวม primitive ที่มีอยู่แล้ว (set_ikev2_proposal/policy/keyring/profile,
    # set_ipsec_transform_set/profile) เข้า edit-config เดียว - รูปแบบ XML ของ
    # แต่ละส่วนตรงกับฟังก์ชันเดิมเป๊ะ (verify แล้วจากอุปกรณ์จริง โดยผู้ใช้ทดสอบว่า
    # tunnel ขึ้นและส่งข้อมูลได้จริง) แค่เอามาต่อกันเป็นก้อนเดียวแทนที่จะยิงทีละคำสั่ง
    # และ derive ชื่อ object ย่อยทั้งหมดจาก `name` ตัวเดียว (ผู้ใช้ไม่ต้องตั้งชื่อเอง
    # ทีละอัน) - psk ผูกกับ peer_ip ตัวเดียว (ออกแบบมาสำหรับ site-to-site
    # point-to-point ตรงกับที่ set_tunnel_interface รับ remote_ip เดียวอยู่แล้ว)
    # (bug 15) peer_ip เป็นฟิลด์เดียวในฟังก์ชันนี้ที่หลุดการตรวจ ทุกฟิลด์อื่นถูก escape()
    # ถูกต้องหมดอยู่แล้ว แต่ peer_ip ถูกใช้ raw ถึง 2 จุด (keyring peer + ikev2 profile
    # match address) - ยืนยันด้วยการรันจริงว่าแทรก XML element ได้ และค่าว่างก็ผ่าน
    # ค่าที่ผิดรูปแบบจะทำให้ RPC เดียวที่ครอบคลุม 6 object พังพร้อมกันหมด
    peer_ip = validate_ipv4(peer_ip, "peer_ip")
    # name ถูก derive เป็นชื่อ object ย่อยถึง 7 ตัวด้านล่าง จึงต้องผ่านนโยบายชื่อเดียวกับ
    # NAT pool ที่ตั้งไว้ตอน bug 14 (เดิม escape อย่างเดียว ชื่อยาว 500 ตัวหรือมีช่องว่าง
    # ผ่านได้ ทั้งที่ Cisco ไม่รับ) - escape() ยังคงไว้ทุกจุดเป็นด่านที่สอง
    name = validate_config_name(name, "Security profile name")
    # (bug 69) อุปกรณ์รับ PSK ได้สูงสุด 127 ตัวอักษร (ยืนยันจาก console จริง)
    # (bug 93) ตรวจเฉพาะตอนที่ส่งมาจริง - ไม่ส่ง = ไม่แตะ keyring เดิม
    if psk:
        psk = validate_psk(psk, "pre-shared key")
    # (bug 66) <authentication> ข้างล่างต้องเป็น "ก้อนเดียว" ที่มีทั้ง remote และ local
    # อยู่ข้างใน - Cisco-IOS-XE-crypto.yang:3308 ประกาศไว้เป็น container ตัวเดียว (local
    # อยู่ L3311, remote อยู่ L3359) ไม่ใช่ list เดิมโค้ดส่งมาเป็น 2 element พี่น้องกัน
    # อุปกรณ์จึงเก็บอันสุดท้าย (local) แล้วทิ้ง remote ทิ้งไปเงียบ ๆ **ไม่มี rpc-error**
    # ผลคือ running-config ขึ้น "! Profile incomplete (no local and/or remote
    # authentication method specified)" ทุกครั้งที่สร้าง profile และ tunnel ขึ้นไม่ได้เลย -
    # เจอจากผลทดสอบกลุ่ม 5 ของผู้ใช้ (บรรทัดนี้อยู่ในทุก config dump แต่ไม่มีใครสังเกต
    # เพราะ Cisco เตือนเป็นคอมเมนต์ใน running-config ไม่ใช่ error)

    if ipsec_encryption in _IPSEC_COMBINED_MODE_ESP:
        esp_hmac_xml = ""
    else:
        if not ipsec_integrity:
            raise ValueError("ipsec_integrity is required unless ipsec_encryption is esp-gcm/esp-gmac")
        esp_hmac_xml = f"<esp-hmac>{ipsec_integrity}</esp-hmac>"

    if ipsec_encryption in _IPSEC_KEY_SIZE_REQUIRED_ESP:
        if not ipsec_key_size:
            raise ValueError(f"ipsec_key_size is required when ipsec_encryption is {ipsec_encryption}")
        key_bit_xml = f"<key-bit>{ipsec_key_size}</key-bit>"
    else:
        key_bit_xml = ""

    # tunnel-choice/transport-choice คือ path ปัจจุบัน (ไม่ deprecated) ของ
    # Cisco-IOS-XE-crypto.yang's transform-set/mode/mode-type choice
    mode_tag = "tunnel-choice" if tunnel_mode == "tunnel" else "transport-choice"
    pfs_xml = f"<pfs><group>{pfs_group}</group></pfs>" if pfs_group else ""

    # (ระลอก C1 ใน planning/transaction_review.md) เดิม flow "แก้ไข profile" ยิง 7 RPC
    # แยกกัน: รื้อ 6 object เดิมทีละคำสั่ง แล้วค่อยสร้างใหม่ - ถ้าขั้นสร้างพัง VPN ที่
    # ใช้งานอยู่จะถูกรื้อทิ้งหมดโดยไม่มีอะไรมาแทน และไม่มีปุ่มไหนกู้กลับได้
    #
    # แก้ที่ต้นตอด้วยการ "เลิกลบ" - ใช้ nc:operation="replace" ตาม RFC 6241 §7.2 ซึ่ง
    # แปลว่า "ข้อมูลนี้แทนที่ของเดิมในจุดนั้นทั้งหมด ถ้าไม่มีอยู่ก็สร้างให้" อุปกรณ์
    # คำนวณ diff เองแล้วเปลี่ยนในก้าวเดียว จึงไม่มีช่วงที่ของเดิมหายไปแล้วของใหม่ยังไม่มา
    # ข้อดีที่สำคัญคือ**ไม่ต้องพึ่ง rollback-on-error** ซึ่งยังไม่ยืนยันว่าอุปกรณ์ทำได้จริง
    # (แพทเทิร์นเดียวกับที่ใช้อยู่แล้วกับ name-server ของ Cisco ในไฟล์นี้)
    #
    # replace_name: ใส่เมื่อ "เปลี่ยนชื่อ profile" เท่านั้น - replace ทำงานกับ key เดิม
    # ถ้าผู้ใช้เปลี่ยนชื่อ object ของชื่อเก่าจะกลายเป็นขยะค้าง จึงต้องสั่ง remove ของชื่อ
    # เก่าด้วย แต่ยัดไว้ใน edit-config เดียวกันได้ เพราะ remove กับ replace อยู่คนละ key
    # ไม่ได้แย่ง node เดียวกัน (ต่างจากการ remove แล้ว create node เดียวกันใน RPC เดียว
    # ซึ่ง RFC ไม่รับประกันลำดับ - ห้ามทำ)
    keyring_name = f"{name}-KEYRING"
    peer_name = f"{name}-PEER"
    ikev2_profile_name = f"{name}-IKEV2-PROFILE"
    transform_set_name = f"{name}-IPSEC-PROP"
    ipsec_profile_name = f"{name}-IPSEC-PROFILE"

    # ชื่อเก่าที่ต้องรื้อทิ้งพร้อมกัน (เฉพาะตอนเปลี่ยนชื่อ) - ถ้าชื่อเดิมเท่ากับชื่อใหม่
    # ก็ไม่ต้องรื้ออะไรเลย replace จัดการให้เอง
    old = (replace_name or "").strip()
    if old and old != name and not psk:
        # (bug 93) เปลี่ยนชื่อ = สร้าง object ชุดใหม่ทั้งชุดแล้วรื้อของเก่าทิ้ง keyring
        # ใหม่จึงเป็นของว่างเปล่าที่ยังไม่มี PSK - คัดลอกของเก่ามาไม่ได้เพราะอุปกรณ์
        # ไม่คืนค่า PSK กลับมา จึงต้องให้ผู้ใช้กรอก (ฟอร์มปลดล็อกช่องให้เองเมื่อชื่อเปลี่ยน)
        raise ValueError("Renaming security profile requires entering a new PSK (existing PSK cannot be copied)")
    if old and old != name:
        # (bug 63) ชื่อ "เดิม" มาจากอุปกรณ์ (แถวที่ผู้ใช้เลือกแก้ไข) ใช้ด่านอ้างอิง
        # ต่างจาก name ข้างบนที่เป็นชื่อใหม่ที่ผู้ใช้พิมพ์เอง - ยังใช้ด่านสร้างตามเดิม
        old = validate_object_ref(old, "Previous security profile name")
        removals_ikev2 = f'''
                    <keyring {NC} nc:operation="remove"><name>{escape(f"{old}-KEYRING")}</name></keyring>
                    <profile {NC} nc:operation="remove"><name>{escape(f"{old}-IKEV2-PROFILE")}</name></profile>'''
        removals_ipsec = f'''
                    <transform-set {NC} nc:operation="remove"><tag>{escape(f"{old}-IPSEC-PROP")}</tag></transform-set>
                    <profile {NC} nc:operation="remove"><name>{escape(f"{old}-IPSEC-PROFILE")}</name></profile>'''
    else:
        removals_ikev2 = ""
        removals_ipsec = ""

    # (bug 93) keyring เป็น object เดียวในชุดนี้ที่เก็บ PSK - แยกทางเดินตามว่าส่ง PSK มาไหม
    #
    #   มี PSK  -> replace ทั้งก้อนเหมือนเดิม (สร้างใหม่ / ตั้งใจเปลี่ยน PSK / เปลี่ยนชื่อ)
    #   ไม่มี   -> **merge เฉพาะ address** ไม่ใส่ nc:operation และไม่ใส่ <pre-shared-key>
    #             merge แปลว่า "ทับเฉพาะ node ที่ระบุ ที่ไม่ได้ระบุคงเดิม" PSK ที่อยู่ใต้
    #             peer เดียวกันจึงรอด ต่างจาก replace ที่จะล้าง peer ทั้งก้อนทิ้งก่อน
    #
    # ที่ยังต้องส่ง address ไปแม้ไม่แตะ PSK เพราะ peer IP แก้ได้จากฟอร์ม ถ้าข้าม keyring
    # ไปทั้งก้อน keyring จะยังชี้ peer เก่า ทั้งที่ ikev2 profile ย้ายไป peer ใหม่แล้ว
    # = หา key ไม่เจอ tunnel ขึ้นไม่ได้ แบบเงียบ ๆ ไม่มี error ให้เห็น
    peer_address_xml = f"""<address>
                                <ipv4>
                                    <ipv4-address>{peer_ip}</ipv4-address>
                                </ipv4>
                            </address>"""
    if psk:
        keyring_xml = f"""<keyring {NC} nc:operation="replace">
                        <name>{escape(keyring_name)}</name>
                        <peer>
                            <name>{escape(peer_name)}</name>
                            {peer_address_xml}
                            <pre-shared-key>
                                <key>{escape(psk)}</key>
                            </pre-shared-key>
                        </peer>
                    </keyring>"""
    else:
        keyring_xml = f"""<keyring>
                        <name>{escape(keyring_name)}</name>
                        <peer>
                            <name>{escape(peer_name)}</name>
                            {peer_address_xml}
                        </peer>
                    </keyring>"""

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                <ikev2 xmlns="{NS_CRYPTO}">{removals_ikev2}
                    {keyring_xml}
                    <profile {NC} nc:operation="replace">
                        <name>{escape(ikev2_profile_name)}</name>
                        <match>
                            <identity>
                                <remote>
                                    <address>
                                        <ipv4>
                                            <ipv4-address>{peer_ip}</ipv4-address>
                                            <ipv4-mask>255.255.255.255</ipv4-mask>
                                        </ipv4>
                                    </address>
                                </remote>
                            </identity>
                        </match>
                        <authentication>
                            <remote>
                                <pre-share></pre-share>
                            </remote>
                            <local>
                                <pre-share></pre-share>
                            </local>
                        </authentication>
                        <keyring>
                            <local>
                                <name>{escape(keyring_name)}</name>
                            </local>
                        </keyring>
                    </profile>
                </ikev2>
                <ipsec xmlns="{NS_CRYPTO}">{removals_ipsec}
                    <transform-set {NC} nc:operation="replace">
                        <tag>{escape(transform_set_name)}</tag>
                        <esp>{ipsec_encryption}</esp>
                        {esp_hmac_xml}
                        {key_bit_xml}
                        <mode>
                            <{mode_tag}></{mode_tag}>
                        </mode>
                    </transform-set>
                    <profile {NC} nc:operation="replace">
                        <name>{escape(ipsec_profile_name)}</name>
                        <set>
                            <transform-set>{escape(transform_set_name)}</transform-set>
                            <ikev2-profile>{escape(ikev2_profile_name)}</ikev2-profile>
                            {pfs_xml}
                        </set>
                    </profile>
                </ipsec>
            </crypto>
        </native>
    '''))


# รื้อ Security Profile ทั้งชุด (6 object ที่ create_security_profile สร้างจาก
# name เดียว) - ต้องลบตามลำดับ dependency (ตัวที่ถูกอ้างอิงมากที่สุดก่อน) ไม่งั้น
# อุปกรณ์จะปฏิเสธเพราะยังมีของอื่นอ้างอิงอยู่: ipsec profile (อ้าง transform-set+
# ikev2-profile) -> transform-set + ikev2 profile (อ้าง keyring) -> keyring ->
# ikev2 policy (อ้าง proposal) -> ikev2 proposal - key ของแต่ละ list ยืนยันจาก
# Cisco-IOS-XE-crypto.yang: ikev2 proposal/policy/keyring/profile คีย์ "name"
# ทั้งหมด, ipsec transform-set คีย์ "tag", ipsec profile คีย์ "name"
def remove_ipsec_profile(name: str) -> str:
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                <ipsec xmlns="{NS_CRYPTO}">
                    <profile xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                        <name>{escape(name)}</name>
                    </profile>
                </ipsec>
            </crypto>
        </native>
    '''))

def remove_ipsec_transform_set(tag: str) -> str:
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                <ipsec xmlns="{NS_CRYPTO}">
                    <transform-set xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                        <tag>{escape(tag)}</tag>
                    </transform-set>
                </ipsec>
            </crypto>
        </native>
    '''))

def remove_ikev2_profile(name: str) -> str:
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                <ikev2 xmlns="{NS_CRYPTO}">
                    <profile xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                        <name>{escape(name)}</name>
                    </profile>
                </ikev2>
            </crypto>
        </native>
    '''))

def remove_ikev2_keyring(name: str) -> str:
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                <ikev2 xmlns="{NS_CRYPTO}">
                    <keyring xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                        <name>{escape(name)}</name>
                    </keyring>
                </ikev2>
            </crypto>
        </native>
    '''))

def remove_ikev2_policy(name: str) -> str:
    name = validate_object_ref(name, "IKEv2 policy name")
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                <ikev2 xmlns="{NS_CRYPTO}">
                    <policy xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                        <name>{escape(name)}</name>
                    </policy>
                </ikev2>
            </crypto>
        </native>
    '''))

def remove_ikev2_proposal(name: str) -> str:
    name = validate_object_ref(name, "IKEv2 proposal name")
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                <ikev2 xmlns="{NS_CRYPTO}">
                    <proposal xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                        <name>{escape(name)}</name>
                    </proposal>
                </ikev2>
            </crypto>
        </native>
    '''))


# (bug 92) ดึง ikev2 proposal/policy มาด้วย - เดิมดึงแค่ profile เพราะตารางสรุปไม่ได้โชว์
# ค่าชั้นใน แต่ฟอร์ม "แก้ไข" ต้องใช้ค่าจริงมา pre-fill ไม่งั้นทุกครั้งที่กดแก้ไขจะขึ้นค่า
# default ของระบบ พอกด Save ค่า IKEv2 ที่ผู้ใช้เคยตั้งไว้จะถูกเขียนทับด้วยค่า default
# ทั้งที่ผู้ใช้ตั้งใจแก้แค่ฝั่ง IPsec (เจอจริงจากผลทดสอบผู้ใช้)
def get_security_profile_information():
    # keyring ถูกดึงมาด้วย (ชื่อ + peer + address) เพื่อให้แก้/ลบ peer ตัวจริงของ profile ที่ไม่ได้
    # สร้างจากระบบได้ - reply ตัวนี้มี PSK ติดมา แต่ response_normalizer ล้างค่าทิ้งก่อนถึง browser
    # (normalize_security_profile_information)
    return open_rpc_tag(f'''
        <get>
            <filter type="subtree">
                <native xmlns="{NS_NATIVE}">
                    <crypto>
                        <ikev2 xmlns="{NS_CRYPTO}">
                            <profile></profile>
                            <policy></policy>
                            <proposal></proposal>
                            <keyring></keyring>
                        </ikev2>
                        <ipsec xmlns="{NS_CRYPTO}">
                            <transform-set></transform-set>
                            <profile></profile>
                        </ipsec>
                    </crypto>
                </native>
            </filter>
        </get>
    ''')


# ---------------------------------------------------------------------------
# Security Profile ที่ "ไม่ได้สร้างจากระบบ" (ตั้งจาก CLI / ติดมาก่อน onboard)
#
# create_security_profile / remove_security_profile ข้างบน derive ชื่อ object ทุกตัวจากชื่อ
# profile (`{name}-IKEV2-PROP` ฯลฯ) ซึ่งถูกต้องเสมอสำหรับของที่ระบบสร้างเอง แต่ profile ที่มีอยู่
# แล้วบนอุปกรณ์ตั้งชื่อตามใจผู้ตั้ง 2 ฟังก์ชันด้านล่างจึงทำงานกับ **ชื่อจริงที่อ่านมาจากอุปกรณ์**
# แทนการเดา - ชื่อจริงทุกตัวมาจาก frontend (parseSecurityProfiles) ไม่มีการ derive ที่นี่เลย
# ---------------------------------------------------------------------------

@validate_call
def remove_security_profile_objects(
    ipsec_profile: str,
    transform_set: str | None = None,
    ikev2_profile: str | None = None,
    keyring: str | None = None,
    # ชื่อ peer ใน keyring - ระบุคู่กับ keyring แล้วไม่สั่ง remove_keyring = ลบเฉพาะ peer นี้
    # (keyring เดียวมีได้หลาย peer ของหลาย profile ห้ามรื้อทั้งก้อนถ้ายังมีคนอื่นใช้อยู่)
    keyring_peer: str | None = None,
    remove_keyring: bool = False,
    ikev2_policy: str | None = None,
    ikev2_proposal: str | None = None,
) -> str:
    # ลบเฉพาะ object ที่ระบุมา - **ตัดสินใจไว้แล้วที่ frontend ว่าตัวไหนไม่มีใครใช้ร่วม** (transform-set/
    # ikev2 profile/proposal ที่ profile อื่นอ้างอยู่ต้องไม่ถูกส่งมาที่นี่) ที่นี่ไม่เดาเพิ่ม
    # ลำดับใน XML เหมือน remove_security_profile (ตัวที่ถูกอ้างอิงมากสุดก่อน) และอยู่ใน edit-config
    # เดียวกัน อุปกรณ์จัดการ dependency เอง
    ipsec_profile = validate_object_ref(ipsec_profile, "IPsec profile name")
    if remove_keyring and not keyring:
        raise ValueError("remove_keyring requires specifying keyring")
    if keyring_peer and not keyring:
        raise ValueError("keyring_peer requires specifying keyring")

    ikev2_parts = []
    if ikev2_profile:
        ikev2_profile = validate_object_ref(ikev2_profile, "IKEv2 profile name")
        ikev2_parts.append(f'<profile {NC} nc:operation="remove"><name>{escape(ikev2_profile)}</name></profile>')
    if keyring:
        keyring = validate_object_ref(keyring, "IKEv2 keyring name")
        if remove_keyring:
            ikev2_parts.append(f'<keyring {NC} nc:operation="remove"><name>{escape(keyring)}</name></keyring>')
        elif keyring_peer:
            keyring_peer = validate_object_ref(keyring_peer, "Keyring peer name")
            ikev2_parts.append(
                f'<keyring><name>{escape(keyring)}</name>'
                f'<peer {NC} nc:operation="remove"><name>{escape(keyring_peer)}</name></peer></keyring>'
            )
    if ikev2_policy:
        ikev2_policy = validate_object_ref(ikev2_policy, "IKEv2 policy name")
        ikev2_parts.append(f'<policy {NC} nc:operation="remove"><name>{escape(ikev2_policy)}</name></policy>')
    if ikev2_proposal:
        ikev2_proposal = validate_object_ref(ikev2_proposal, "IKEv2 proposal name")
        ikev2_parts.append(f'<proposal {NC} nc:operation="remove"><name>{escape(ikev2_proposal)}</name></proposal>')

    ipsec_parts = [f'<profile {NC} nc:operation="remove"><name>{escape(ipsec_profile)}</name></profile>']
    if transform_set:
        transform_set = validate_object_ref(transform_set, "Transform set name")
        ipsec_parts.append(f'<transform-set {NC} nc:operation="remove"><tag>{escape(transform_set)}</tag></transform-set>')

    ikev2_xml = f'<ikev2 xmlns="{NS_CRYPTO}">{"".join(ikev2_parts)}</ikev2>' if ikev2_parts else ""
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                {ikev2_xml}
                <ipsec xmlns="{NS_CRYPTO}">{"".join(ipsec_parts)}</ipsec>
            </crypto>
        </native>
    '''))


@validate_call
def modify_security_profile(
    ipsec_profile: str,
    # ---- ชื่อ object จริง (ระบุเฉพาะตัวที่ต้องแตะ) ----
    transform_set: str | None = None,
    ikev2_profile: str | None = None,
    keyring: str | None = None,
    keyring_peer: str | None = None,
    ikev2_proposal: str | None = None,
    # ---- ค่าที่เปลี่ยน: None = ไม่แตะ ----
    peer_ip: str | None = None,
    old_peer_ip: str | None = None,
    psk: str | None = None,
    psk_type: Literal["key", "local", "remote"] = "key",
    ikev2_encryption: Literal["aes-cbc-128", "aes-cbc-192", "aes-cbc-256", "aes-gcm-128", "aes-gcm-256"] | None = None,
    ikev2_integrity: Literal["sha1", "sha256", "sha384", "sha512"] | None = None,
    ikev2_group: Literal["fourteen", "fifteen", "sixteen", "nineteen", "twenty", "twenty-one"] | None = None,
    ipsec_encryption: Literal["esp-aes", "esp-gcm", "esp-seal", "esp-192-aes", "esp-256-aes"] | None = None,
    ipsec_integrity: Literal["esp-sha-hmac", "esp-sha256-hmac", "esp-sha384-hmac", "esp-sha512-hmac"] | None = None,
    ipsec_key_size: Literal["128", "192", "256"] | None = None,
    tunnel_mode: Literal["tunnel", "transport"] | None = None,
    # "none" = เอา PFS ออก
    pfs_group: Literal["group14", "group15", "group16", "group19", "group20", "group21", "none"] | None = None,
) -> str:
    # แก้ไข "ในที่เดิม" ของ profile ที่ไม่ได้สร้างจากระบบ - **ส่งเฉพาะ field ที่ผู้ใช้เปลี่ยน** และแต่ละ
    # field เขียนเป็น operation ระดับ leaf/container ที่ตรงตัว ไม่ replace ทั้ง object เหมือน
    # create_security_profile เพราะ object ของ brownfield มีค่าอื่นที่ฟอร์มไม่รู้จัก (dpd, nat,
    # identity local, หลาย algorithm ฯลฯ) ที่ต้องรอดหลังบันทึก และชื่อ object ไม่ถูกแตะเลย
    #
    # ทำไมเปลี่ยน peer ต้อง "ลบเก่า + เพิ่มใหม่": ikev2 profile match/identity/remote/address/ipv4
    # เป็น list ที่ key คือตัว IP เอง (Cisco-IOS-XE-crypto.yang) เปลี่ยน key ตรง ๆ ไม่ได้ - remove กับ
    # create อยู่คนละ list entry จึงอยู่ใน edit-config เดียวกันได้ (ต่างจากการ remove แล้ว create
    # node เดียวกัน ซึ่ง RFC ไม่รับประกันลำดับ) ส่วน peer ใน keyring แก้ leaf ipv4-address ด้วย merge
    ipsec_profile = validate_object_ref(ipsec_profile, "IPsec profile name")
    changed = (
        peer_ip, psk, ikev2_encryption, ikev2_integrity, ikev2_group,
        ipsec_encryption, ipsec_integrity, ipsec_key_size, tunnel_mode, pfs_group,
    )
    if all(value is None for value in changed):
        raise ValueError("No changed values - no command needed")

    ikev2_parts: list[str] = []
    ipsec_parts: list[str] = []

    # ---- peer IP: ikev2 profile (list key) + peer ใน keyring ----
    if peer_ip is not None:
        peer_ip = validate_ipv4(peer_ip, "peer_ip")
        if not ikev2_profile:
            raise ValueError("Changing Peer IP requires specifying ikev2_profile")
        if not old_peer_ip:
            raise ValueError("Changing Peer IP requires specifying old_peer_ip (existing value on device)")
        old_peer_ip = validate_ipv4(old_peer_ip, "old_peer_ip")
        if old_peer_ip == peer_ip:
            raise ValueError("New Peer IP is equal to existing value")
        if keyring and not keyring_peer:
            raise ValueError("Keyring exists but cannot determine which peer in keyring belongs to this profile - cannot change Peer IP")
        ikev2_profile = validate_object_ref(ikev2_profile, "IKEv2 profile name")
        ikev2_parts.append(f"""<profile>
                        <name>{escape(ikev2_profile)}</name>
                        <match><identity><remote><address>
                            <ipv4 {NC} nc:operation="remove"><ipv4-address>{old_peer_ip}</ipv4-address></ipv4>
                            <ipv4>
                                <ipv4-address>{peer_ip}</ipv4-address>
                                <ipv4-mask>255.255.255.255</ipv4-mask>
                            </ipv4>
                        </address></remote></identity></match>
                    </profile>""")

    # ---- keyring peer: address + PSK (merge เฉพาะ leaf ที่เปลี่ยน) ----
    if peer_ip is not None or psk is not None:
        if peer_ip is not None and not keyring:
            pass  # ikev2 profile ไม่ได้ใช้ keyring (เช่น cert auth) - แก้เฉพาะ match address
        else:
            if not keyring or not keyring_peer:
                raise ValueError("Changing PSK requires specifying keyring and keyring_peer")
            keyring = validate_object_ref(keyring, "IKEv2 keyring name")
            keyring_peer = validate_object_ref(keyring_peer, "Keyring peer name")
            peer_children = ""
            if peer_ip is not None:
                peer_children += f"<address><ipv4><ipv4-address>{peer_ip}</ipv4-address></ipv4></address>"
            if psk is not None:
                psk = validate_psk(psk, "pre-shared key")
                if psk_type == "local":
                    psk_xml = f"<local-option><key>{escape(psk)}</key></local-option>"
                elif psk_type == "remote":
                    psk_xml = f"<remote-option><key>{escape(psk)}</key></remote-option>"
                else:
                    psk_xml = f"<key>{escape(psk)}</key>"
                peer_children += f"<pre-shared-key>{psk_xml}</pre-shared-key>"
            ikev2_parts.append(
                f"<keyring><name>{escape(keyring)}</name>"
                f"<peer><name>{escape(keyring_peer)}</name>{peer_children}</peer></keyring>"
            )

    # ---- IKEv2 proposal: encryption/integrity(prf)/group ----
    if ikev2_encryption is not None or ikev2_integrity is not None or ikev2_group is not None:
        if not ikev2_proposal:
            raise ValueError("Changing IKEv2 algorithm requires specifying ikev2_proposal")
        if (ikev2_encryption is None) != (ikev2_integrity is None):
            # encryption กับ integrity/prf พึ่งกัน (GCM ห้ามมี integrity) ต้องส่งคู่กันเสมอ
            raise ValueError("Changing IKEv2 encryption or integrity requires providing both values together")
        ikev2_proposal = validate_object_ref(ikev2_proposal, "IKEv2 proposal name")
        proposal_children = ""
        if ikev2_encryption is not None:
            proposal_children += f'<encryption {NC} nc:operation="replace"><{ikev2_encryption}/></encryption>'
            if ikev2_encryption in _IKEV2_COMBINED_MODE_ENCRYPTION:
                # GCM มี authentication ในตัว: integrity ต้องไม่มี ใช้ prf แทน (bug 90)
                proposal_children += f'<integrity {NC} nc:operation="remove"/>'
                proposal_children += f'<prf {NC} nc:operation="replace"><{ikev2_integrity}/></prf>'
            else:
                proposal_children += f'<integrity {NC} nc:operation="replace"><{ikev2_integrity}/></integrity>'
        if ikev2_group is not None:
            proposal_children += f'<group {NC} nc:operation="replace"><{ikev2_group}/></group>'
        ikev2_parts.append(f"<proposal><name>{escape(ikev2_proposal)}</name>{proposal_children}</proposal>")

    # ---- transform-set: esp/key-bit/esp-hmac/mode ----
    esp_fields = (ipsec_encryption, ipsec_integrity, ipsec_key_size)
    if any(value is not None for value in esp_fields) or tunnel_mode is not None:
        if not transform_set:
            raise ValueError("Changing IPsec algorithm/mode requires specifying transform_set")
        transform_set = validate_object_ref(transform_set, "Transform set name")
        ts_children = ""
        if any(value is not None for value in esp_fields):
            if ipsec_encryption is None:
                raise ValueError("Changing IPsec integrity/key size requires providing ipsec_encryption")
            ts_children += f'<esp {NC} nc:operation="replace">{ipsec_encryption}</esp>'
            # key-bit / esp-hmac มี `when` ผูกกับชนิด esp - ต้องเขียนหรือถอดให้สอดคล้องกันใน RPC เดียว
            # ไม่งั้นค่าเก่าค้างแล้วอุปกรณ์ปฏิเสธ (เช่น esp-256-aes ห้ามมี key-bit, esp-gcm ห้ามมี esp-hmac)
            if ipsec_encryption in _IPSEC_KEY_SIZE_REQUIRED_ESP:
                if not ipsec_key_size:
                    raise ValueError(f"ipsec_key_size is required when ipsec_encryption is {ipsec_encryption}")
                ts_children += f'<key-bit {NC} nc:operation="replace">{ipsec_key_size}</key-bit>'
            else:
                ts_children += f'<key-bit {NC} nc:operation="remove"/>'
            if ipsec_encryption in _IPSEC_COMBINED_MODE_ESP:
                ts_children += f'<esp-hmac {NC} nc:operation="remove"/>'
            else:
                if not ipsec_integrity:
                    raise ValueError("ipsec_integrity is required unless ipsec_encryption is esp-gcm/esp-gmac")
                ts_children += f'<esp-hmac {NC} nc:operation="replace">{ipsec_integrity}</esp-hmac>'
        if tunnel_mode is not None:
            mode_tag = "tunnel-choice" if tunnel_mode == "tunnel" else "transport-choice"
            ts_children += f'<mode {NC} nc:operation="replace"><{mode_tag}></{mode_tag}></mode>'
        ipsec_parts.append(f"<transform-set><tag>{escape(transform_set)}</tag>{ts_children}</transform-set>")

    # ---- PFS อยู่ที่ ipsec profile เอง ----
    if pfs_group is not None:
        pfs_xml = (
            f'<pfs {NC} nc:operation="remove"/>' if pfs_group == "none"
            else f'<pfs {NC} nc:operation="replace"><group>{pfs_group}</group></pfs>'
        )
        ipsec_parts.append(f"<profile><name>{escape(ipsec_profile)}</name><set>{pfs_xml}</set></profile>")

    ikev2_xml = f'<ikev2 xmlns="{NS_CRYPTO}">{"".join(ikev2_parts)}</ikev2>' if ikev2_parts else ""
    ipsec_xml = f'<ipsec xmlns="{NS_CRYPTO}">{"".join(ipsec_parts)}</ipsec>' if ipsec_parts else ""
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <crypto>
                {ikev2_xml}
                {ipsec_xml}
            </crypto>
        </native>
    '''))


@validate_call
def create_security_tunnel(
    tunnel_type: Literal["ipsec", "gre"],
    interface_number: str,
    tun_ip: str,
    tun_subnet: str,
    wan_interface: str,
    remote_ip: str,
    ipsec_profile: str | None = None,
    mtu: int | None = None,
) -> str:
    if tunnel_type == "ipsec" and not ipsec_profile:
        raise ValueError("ipsec_profile is required when tunnel_type is 'ipsec'")
    interface_number = _interface_id_value(interface_number, 'interface_number')
    wan_interface = _interface_fullname(wan_interface, 'wan_interface')

    # (bug 70) เดิมตรวจแค่ว่าเป็น IPv4 ที่ถูกรูปแบบ - ตั้ง 169.254.1.255/30 (broadcast
    # ของ subnet ตัวเอง) ผ่านได้ อุปกรณ์ปฏิเสธแล้ว tunnel หายทั้งตัว
    tun_ip = validate_host_in_network(tun_ip, tun_subnet, "Tunnel IP")
    tun_subnet = validate_ipv4(tun_subnet, "Tunnel subnet mask")
    remote_ip = validate_ipv4(remote_ip, "remote_ip")
    # Tunnel interface ใช้ interface-common-grouping เดียวกันกับ physical/sub-
    # interface (uses ผ่าน grouping เดียวกันตาม YANG) - <ip><mtu> (ip mtu) ใช้
    # ได้เหมือนกันทุกประการ (ดู _mtu_xml's comment สำหรับที่มาของ leaf/ช่วงค่า -
    # OSPF/routing protocol ที่วิ่งผ่าน tunnel ก็เทียบ ip mtu ตัวนี้เหมือนกับ
    # physical interface ทุกประการ)
    mtu_xml = _mtu_xml(mtu)

    if tunnel_type == "ipsec":
        mode_protection_xml = f'''
            <mode>
                <ipsec>
                    <ipv4-mode></ipv4-mode>
                </ipsec>
            </mode>
            <destination-config>
                <ipv4>{remote_ip}</ipv4>
            </destination-config>
            <protection>
                <ipsec xmlns="{NS_CRYPTO}">
                    <profile-option>
                        <name>{escape(ipsec_profile)}</name>
                    </profile-option>
                </ipsec>
            </protection>'''
    else:
        mode_protection_xml = f'''
            <mode>
                <gre-config>
                    <ip>true</ip>
                </gre-config>
            </mode>
            <destination-config>
                <ipv4>{remote_ip}</ipv4>
            </destination-config>'''

    # (bug 91/79) เดิมฟอร์ม "แก้ไข tunnel" ต้องยิง remove_tunnel_interface ทิ้งทั้ง
    # interface ก่อนแล้วค่อยสร้างใหม่ ซึ่งพังทันทีถ้ามีใครอ้าง interface นี้อยู่:
    #
    #   illegal reference /native/router/ios-ospf:router-ospf/ospf/process-id[id='1']/
    #                     passive-interface-config/disable-interface/Tunnel[name='0']/name
    #
    # `no passive-interface Tunnel0` เป็น leafref ชี้มาที่ interface ตัวนี้ตรง ๆ อุปกรณ์
    # จึงไม่ยอมให้ลบของที่ยังมีคนชี้อยู่ ผู้ใช้ที่แค่อยากเพิ่ม ip mtu จึงต้องไปรื้อ OSPF
    # ออกก่อนทั้งที่ทำผ่าน CLI ตรง ๆ ได้ไม่มีปัญหาเลย
    #
    # ทางแก้คือ "เลิกลบ" - nc:operation="replace" แปลว่าเนื้อหานี้แทนที่ของเดิมในจุดนั้น
    # ทั้งหมด อุปกรณ์คำนวณ diff เอง **node <Tunnel> ไม่เคยหายไปจาก config เลยแม้แต่
    # ชั่วขณะ** leafref ของ OSPF จึงไม่เคยขาด ในขณะที่ leaf เก่าที่ไม่ได้ส่งมารอบนี้
    # (เช่น ip mtu ที่ผู้ใช้ลบค่าออก หรือ protection ตอนสลับ ipsec -> gre) ถูกล้างให้
    # เหมือนที่การลบแล้วสร้างใหม่เคยทำ - ได้ผลลัพธ์เดิมโดยไม่ต้องแตะ reference ของใคร
    # แพทเทิร์นเดียวกับ create_security_profile และ create_nat_policy ในไฟล์นี้
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <interface>
                <Tunnel {NC} nc:operation="replace">
                    <name>{interface_number}</name>
                    <ip>
                        {mtu_xml}
                        <address>
                            <primary>
                                <address>{tun_ip}</address>
                                <mask>{tun_subnet}</mask>
                            </primary>
                        </address>
                    </ip>
                    <tunnel xmlns="{NS_TUNNEL}">
                        <source>{wan_interface}</source>
                        {mode_protection_xml}
                    </tunnel>
                </Tunnel>
            </interface>
        </native>
    '''))


# ลบ Tunnel interface ทั้งตัว (ทั้ง IPsec Tunnel และ GRE Tunnel ใช้ฟังก์ชันนี้
# ร่วมกันได้ - ต่างกันแค่ mode/protection ตอน create แต่ตอน remove ลบทั้ง
# interface entry เหมือนกันหมด) - key คือ "name" ของ Tunnel list เอง (เลขลำดับ
# tunnel ตรงๆ ไม่มี ".unit" ต่อท้ายแบบ sub-interface - remove_interface_unit เดิม
# ใช้ไม่ได้เพราะมันบวก ".{unit}" ต่อท้ายเสมอยกเว้น Vlan)
def remove_tunnel_interface(interface_number: str) -> str:
    interface_number = _interface_id_value(interface_number, 'interface_number')
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <interface xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
            <Tunnel nc:operation="remove">
              <name>{interface_number}</name>
            </Tunnel>
          </interface>
        </native>
    '''))

def get_security_tunnel_information():
    # หน้า security_tunnel.jsx (list) ดึง Tunnel interface ทั้งหมดมาแสดง -
    # ไม่แยก query GRE/IPsec (ดึงทุก Tunnel มาทีเดียว แล้วให้ frontend แยกประเภท
    # เองจาก mode/protection ที่ตอบกลับมา เหมือนที่ parseNatRules แยก interface
    # vs pool จาก key ที่มีอยู่)
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <native xmlns="{NS_NATIVE}">
            <interface>
                <Tunnel></Tunnel>
            </interface>
        </native>
    </filter>
</get>
''')


# IOS-XE ไม่มี native ping RPC เลย (ต่างจาก IOS-XR ที่มี Cisco-IOS-XR-ping-act.yang
# โดยเฉพาะ) และ config-ios-cli-rpc (Cisco-IOS-XE-cli-rpc.yang) ที่ลองมาก่อนหน้าก็ยิง
# "do ping" ผ่านได้จริง (ping ทำงานจริงบนอุปกรณ์) แต่ result ที่ตอบกลับมาเป็นแค่
# "RPC request successful" คงที่เสมอ ไม่ relay stdout ของ EXEC command กลับมาเลย
# (RPC นี้ออกแบบมาไว้รายงานสถานะ apply config ไม่ใช่ terminal passthrough) เลย
# เปลี่ยนมาใช้ IP SLA แทน (Cisco-IOS-XE-sla.yang + Cisco-IOS-XE-ip-sla-oper.yang) -
# เป็น native NETCONF pattern เดียวกับที่ไฟล์นี้ใช้ทุกที่อยู่แล้ว (edit-config ตั้ง
# ค่า -> get อ่าน operational data กลับ) ไม่ต้องพึ่ง CLI passthrough เลย
def send_ping(
    destination: str,
    entry_number: int = 999,
    source_interface: str = None,
    life: str = "forever",
):
    # F1: escape ค่าที่มาจากผู้ใช้ก่อนยัดลง XML เสมอ (ด่านสองเสริมกับ validation ที่ PingTestRequest)
    # กัน XML/NETCONF injection แบบเดียวกับที่ฟังก์ชันอื่นใน Cisco และ run_ping_test ของ Juniper ทำอยู่แล้ว
    source_xml = (
        f"<source-interface>{escape(source_interface)}</source-interface>"
        if source_interface else ""
    )
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <sla xmlns="{NS_SLA}">
              <entry>
                <number>{entry_number}</number>
                <icmp-echo>
                  <destination>{escape(destination)}</destination>
                  {source_xml}
                </icmp-echo>
              </entry>
              <schedule>
                <entry-number>{entry_number}</entry-number>
                <life>{life}</life>
                <start-time>
                  <now-config/>
                </start-time>
              </schedule>
            </sla>
          </ip>
        </native>
    '''))

# อ่านผล ping กลับ - latest-return-code (ret-code-ok/ret-code-timeout/...) คือผล
# reachable จริง, rtt-info/latest-rtt/rtt คือ round-trip time - ต้องรอให้ probe
# รันรอบแรกก่อน (ตาม frequency ของ entry) ถึงจะมีข้อมูลจริงให้อ่าน
def get_ping_result(entry_number: int = 999):
    return open_rpc_tag(f'''
<get>
    <filter type="subtree">
        <ip-sla-stats xmlns="{NS_SLA_OPER}">
            <sla-oper-entry>
                <oper-id>{entry_number}</oper-id>
            </sla-oper-entry>
        </ip-sla-stats>
    </filter>
</get>
''')


# ลบ probe entry ทิ้งหลังทดสอบเสร็จ (ตรงกับ CLI `no ip sla <N>`) - ทดสอบจริงแล้วพบ
# ว่า schedule ไม่ได้ถูกลบตามอัตโนมัติจาก leafref แบบที่คาดไว้ (ยิงจริงบน HQ-R1
# แล้วได้ rpc-error data-missing/instance-required - schedule[entry-number=N]
# ยังเหลือ dangling reference ไปหา entry ที่ลบไปแล้ว) เลยต้องลบ schedule เองก่อน/
# พร้อมกันเสมอ ไม่งั้น validate ไม่ผ่าน
def remove_ping(entry_number: int = 999):
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
          <ip>
            <sla xmlns="{NS_SLA}">
              <schedule xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                <entry-number>{entry_number}</entry-number>
              </schedule>
              <entry xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
                <number>{entry_number}</number>
              </entry>
            </sla>
          </ip>
        </native>
    '''))

# ping test แบบ "สั่งครั้งเดียวจบ" - ห่อ 3 round-trip ของ IP SLA (สร้าง probe+
# schedule -> รอให้รันรอบแรก -> อ่านผล -> ลบ probe ทิ้งเสมอ) ไว้ในฟังก์ชันเดียว
# ไม่ผูกกับ transport ไหนโดยเฉพาะ (ไม่ import callhome_service/asyncssh ตรงๆ) รับ
# `send` เป็น async callable ที่รับ payload string แล้วคืน reply string กลับมา
# แทน - ให้ทั้งเว็บ (callhome_service.send_payload) และ testXMLpayload.py
# (send_netconf_rpc) เรียกใช้ฟังก์ชันเดียวกันนี้ได้ ผ่านการห่อ signature ให้ตรงกัน
# เอง (เหมือน pattern เดียวกับ probe_identity ใน device_identity.py ที่รับ
# read_dev_response เป็น parameter) - ทดสอบจริงบน HQ-R1 แล้วว่าใช้ได้
# (192.168.239.1 -> ret-code-ok, rtt=19ms)
async def run_ping_test(
    send: Callable[[str], Awaitable[str]],
    destination: str,
    source_interface: str = None,
    entry_number: int = 909,
    wait_seconds: float = 5.0,
) -> str:
    await send(send_ping(destination, entry_number=entry_number, source_interface=source_interface, life=60))
    await asyncio.sleep(wait_seconds)
    try:
        return await send(get_ping_result(entry_number))
    finally:
        try:
            await send(remove_ping(entry_number))
        except Exception as cleanup_err:
            print(f"[!] ping test: ลบ sla entry {entry_number} ไม่สำเร็จ: {cleanup_err}")

def get_ntp_information():
    return open_rpc_tag(f'''
    <get>
        <filter type="subtree">
            <native xmlns="{NS_NATIVE}">
                <ntp/>
            </native>
        </filter>
    </get>
''')

@validate_call
def set_ntp_server(
    ntp_ip: str,
):
    ntp_ip = str(ipaddress.IPv4Address(ntp_ip))
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <ntp>
                <server xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ntp">
                    <server-list>
                        <ip-address>{ntp_ip}</ip-address>
                    </server-list>
                </server>
            </ntp>
        </native>
    '''))

def remove_ntp_server(
    ntp_ip: str,
):
    ntp_ip = str(ipaddress.IPv4Address(ntp_ip))
    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}">
            <ntp>
                <server xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ntp">
                    <server-list
    xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
    nc:operation="remove">
                        <ip-address>{ntp_ip}</ip-address>
                    </server-list>
                </server>
            </ntp>
        </native>
    '''))


# def get_rpc_library():
#     return open_rpc_tag(f'''
#     <get>
#         <filter type="subtree">
#             <yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library"/>
#         </filter>
#     </get>
# ''')

def get_rpc_library():
    return open_rpc_tag('''
    <get>
        <filter type="subtree">
            <netconf-state xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
                <schemas/>
            </netconf-state>
        </filter>
    </get>
''')

def get_dna_lic():
    return open_rpc_tag('''
    <get-config>
        <source>
            <running/>
        </source>
        <filter type="xpath" select="/native/license"/>
    </get-config>
    ''')

# ตรวจความสามารถอุปกรณ์ (planning/capability_detection_notes.txt หัวข้อ 9) - ใช้ภายใน
# ระบบตรวจตอน call-home เท่านั้น ห้ามลงทะเบียนใน PUBLIC_FUNCTIONS ไม่งั้นจะโผล่ใน /commands
# Cisco ใช้ yang-library แทน netconf-monitoring (get_rpc_library) เพราะได้ feature มาด้วย
# ตรวจแล้วว่าผลกรองฟังก์ชันจาก namespace ของทั้งสองแหล่งตรงกันบน c8000/c9000
def get_capability_schema():
    return open_rpc_tag('''
    <get>
        <filter type="subtree">
            <yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library"/>
        </filter>
    </get>
''')

# ระดับ license ที่ config ไว้ (license boot level) ไม่ใช่ค่าที่ active - ถ้าเพิ่งเปลี่ยนแต่ยังไม่
# reload จะได้ค่าใหม่แล้ว; get_device_license() อ่าน cisco-smart-license ซึ่งไม่มี field บอก tier
def get_boot_license():
    return open_rpc_tag(f'''
    <get>
        <filter type="subtree">
            <native xmlns="{NS_NATIVE}">
                <license>
                    <boot/>
                </license>
            </native>
        </filter>
    </get>
''')

def reboot():
    return open_rpc_tag('''
    <reload xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rpc">
        <force>true</force>
        <reason>Forced reboot requested by controller</reason>
    </reload>
    ''')

def get_local_user():
    return open_rpc_tag('''
     <get-config>
    <source>
      <running/>
    </source>
    <filter type="subtree">
      <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <username>
          <name/>
          <privilege/>
          <aaa xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-aaa">
            <attribute>
              <list/>
            </attribute>
          </aaa>
        </username>
      </native>
    </filter>
  </get-config>
    ''')

@validate_call
def set_new_local_user(
    username: str,
    privilege: Literal[1, 15],
    passwd: str,
):
    return open_rpc_tag(f'''
    <edit-config>
            <target>
                <running/>
            </target>
            <default-operation>merge</default-operation>
            <error-option>rollback-on-error</error-option>
            <config>
                <native xmlns="{NS_NATIVE}" {NC}>
                    <username nc:operation="create">
                        <name>{escape(username)}</name>
                        <privilege>{privilege}</privilege>
                        <secret>
                            <encryption>5</encryption>
                            <secret>{escape(passwd)}</secret>
                        </secret>
                    </username>
                </native>
            </config>
        </edit-config>
''')

@validate_call
def edit_local_user(
    username: str,
    privilege: Literal[1, 15] | None = None,
    passwd: str | None = None,
):
    """Update only the selected fields of an existing Cisco local user.

    ``username`` is the immutable YANG list key; there is deliberately no
    new/previous username parameter.  Omitting ``privilege`` preserves the
    current privilege, while omitting ``passwd`` preserves the current
    password/secret and every unknown Brownfield field below the user.

    Existence must be checked from a fresh get_local_user reply by the caller
    before sending this payload.  NETCONF merge alone cannot distinguish an
    update from creating a missing list entry.
    """
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username is required")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in username):
        raise ValueError("Username contains control characters")
    if privilege is None and passwd is None:
        raise ValueError("At least one of privilege or password must be provided")
    if passwd is not None:
        if not isinstance(passwd, str) or not passwd:
            raise ValueError("Password cannot be empty")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in passwd):
            raise ValueError("Password contains control characters")

    privilege_xml = "" if privilege is None else f"<privilege>{privilege}</privilege>"
    password_xml = ""
    if passwd is not None:
        # Brownfield may use the weaker `username ... password` branch. Remove
        # it idempotently and replace only the secret subtree in the same
        # rollback-on-error RPC; never replace the whole username list entry.
        password_xml = f'''
            <password nc:operation="remove"/>
            <secret nc:operation="replace">
                <encryption>0</encryption>
                <secret>{escape(passwd)}</secret>
            </secret>
        '''

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}" {NC}>
            <username>
                <name>{escape(username)}</name>
                {privilege_xml}
                {password_xml}
            </username>
        </native>
    '''))


@validate_call
def delete_local_user(username: str):
    """Delete exactly one Cisco local user identified by its immutable name.

    ``delete`` is intentional rather than ``remove``: a stale request for a
    user which no longer exists must fail instead of being reported as a
    successful deletion.  IOS XE applies this to running configuration in one
    rollback-on-error edit-config operation.
    """
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username is required")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in username):
        raise ValueError("Username contains control characters")

    return open_rpc_tag(edit_config_tag(f'''
        <native xmlns="{NS_NATIVE}" {NC}>
            <username nc:operation="delete">
                <name>{escape(username)}</name>
            </username>
        </native>
    '''))

def factory_reset():
    return open_rpc_tag('''
        <factory-reset xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rpc">
            <all/>
        </factory-reset>
    ''')
