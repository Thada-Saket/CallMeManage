import ipaddress
import itertools
from xml.sax.saxutils import escape
from tools.hostname_policy import validate_hostname
from tools.net_input_policy import validate_distance

from pydantic import validate_call
from typing import Literal


NS_RPC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NS_SYSTEM = "http://www.huawei.com/netconf/vrp/huawei-system"
NS_IFM = "http://www.huawei.com/netconf/vrp/huawei-ifm"
NS_DEVM = "http://www.huawei.com/netconf/vrp/huawei-devm"
NS_STATICRT = "http://www.huawei.com/netconf/vrp/huawei-staticrt"
NS_IETF_SYS = "urn:ietf:params:xml:ns:yang:ietf-system"
NS_IETF_IF = "urn:ietf:params:xml:ns:yang:ietf-interfaces"
NS_IETF_ROUTING = "urn:ietf:params:xml:ns:yang:ietf-routing"
NS_ARP = "http://www.huawei.com/netconf/vrp/huawei-arp"
NS_MAC = "http://www.huawei.com/netconf/vrp/huawei-mac"
NS_VLAN = "http://www.huawei.com/netconf/vrp/huawei-vlan"
NS_AAA = "http://www.huawei.com/netconf/vrp/huawei-aaa"
NS_IF = "http://openconfig.net/yang/interfaces"
NS_ETH = "http://www.huawei.com/netconf/vrp/huawei-ethernet"
NS_EXECUTE_CLI = "http://www.huawei.com/netconf/capability/base/1.0"

_msg_counter = itertools.count(1)


def next_msg_id() -> str:
    return str(next(_msg_counter))


# (ปัญหาที่ 2 ขั้น B1) ดูคำอธิบายเต็มที่ ERROR_OPTION ใน cisco_iosxe.py - Huawei
# ประกาศ rollback-on-error:1.0 มาใน hello เหมือนกัน (device_capability/huaweiHello.txt)
# แม้จะมี candidate datastore ด้วย แต่โค้ดชุดนี้เขียนลง <running/> ตรง ๆ จึงต้องพึ่ง
# error-option เหมือน Cisco
ERROR_OPTION = "<error-option>rollback-on-error</error-option>"


def open_rpc_tag(
    xmltags: str,
    version: str = "1.0",
    xmlns: str = NS_RPC,
    encoding: str = "UTF-8",
):
    return f'''<?xml version="{version}" encoding="{encoding}"?>
<rpc message-id="{next_msg_id()}" xmlns="{xmlns}">
    {xmltags}
</rpc>
'''

# (C4) Huawei ประกาศ candidate:1.0 กับ confirmed-commit:1.1 มาใน hello ตั้งแต่ต้น
# แต่โค้ดชุดนี้เคยเขียนลง <running/> ตรง ๆ ผลคือทุก edit-config ถูกตรวจกับสภาพจริง
# ของอุปกรณ์ทันที ลำดับคำสั่งที่ต้องพึ่งผลของคำสั่งก่อนหน้าจึงทำในรอบเดียวไม่ได้เลย
# (เคสจริง: คืนพอร์ตเป็น access VLAN 1 แล้วสลับเป็น Layer 3 ในก้อนเดียวกันไม่ได้)
# เขียนลง <candidate/> แล้ว commit ทำให้ edit-config ตัวถัดไปถูกตรวจกับ candidate
# ที่มีผลของตัวก่อนหน้าอยู่แล้ว และ commit ครั้งเดียวปิดท้ายได้ atomic จริง
def edit_config_tag(xmltags: str):
    return F'''
<edit-config>
    <target>
        <candidate/>
    </target>
    {ERROR_OPTION}
    <config>
        {xmltags}
    </config>
</edit-config>
'''

def _interface_name(interface_type: str, interface_id: str) -> str:
    interface_type = (interface_type or "").strip()
    interface_id = (interface_id or "").strip()
    if not interface_id:
        raise ValueError("interface_id is required")
    return escape(f"{interface_type}{interface_id}")


def _netmask(prefix_len: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)

# MTU: optional - ไม่ส่งมา (None) = ไม่สร้าง tag เลย ใช้ค่า default ของอุปกรณ์
# ต่อไป (68-9216 ตาม valid range ทั่วไป - อยู่ในขอบเขต 0..64000 ของ huawei-ifm.
# yang's ifMtu leaf ที่ verify จริงจาก device_capability/huawei/huawei-ifm.yang:554
# แล้ว) แก้ปัญหา OSPF neighbor ค้าง EXSTART/EXCHANGE ข้ามยี่ห้อ (DBD packet MTU
# mismatch) - **tag ชื่อ "ifMtu" ไม่ใช่ "mtu"** ต่างจาก Cisco/Juniper เพราะ Huawei
# ใช้ huawei-ifm module ของตัวเอง (ifName/ifAdminStatus/ifDescr/ifMtu ล้วน
# prefix "if" ตาม schema จริง ไม่ใช่เดา)
def _interface_description_xml(description: str | None) -> str:
    if description is None:
        return ""
    if description == "":
        return f'<ifDescr xmlns:nc="{NS_RPC}" nc:operation="delete"/>'
    if not 1 <= len(description) <= 242:
        raise ValueError("description must be between 1 and 242 characters")
    if any(not (0x20 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD
                or 0x10000 <= ord(char) <= 0x10FFFF) for char in description):
        raise ValueError("description contains an invalid XML/control character")
    return f"<ifDescr>{escape(description)}</ifDescr>"


def _ifmtu_xml(mtu: int | None) -> str:
    if mtu is None:
        return ""
    if not 68 <= mtu <= 9216:
        raise ValueError("MTU must be between 68 and 9216")
    return f"<ifMtu>{mtu}</ifMtu>"

# show running-configuration and all supported netconf capability
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
    return open_rpc_tag(f'''
<get>
  <filter type="subtree">
    <staticrt xmlns="{NS_STATICRT}">
      <staticrtbase>
        <srRoutes/>
      </staticrtbase>
    </staticrt>
  </filter>
</get>
''')

# show arp table
def get_arp_table():
    return open_rpc_tag(f'''
<get>
  <filter type="subtree">
    <arp xmlns="{NS_ARP}">
      <arpTables>
        <arpTable/>
      </arpTables>
    </arp>
  </filter>
</get>
''')

# show all interface information and status by open rpc
def get_interface_information():
    return open_rpc_tag(f'''
<get>
  <filter type="subtree">
    <interfaces-state xmlns="{NS_IETF_IF}">
      <interface>
      </interface>
    </interfaces-state>
  </filter>
</get>
''')

# <get>
#   <filter type="subtree">
#     <interfaces-state xmlns="{NS_IETF_IF}">
#       <interface>
#         <name/>
#         <oper-status/>
#         <phys-address/>
#         <speed/>
#       </interface>
#     </interfaces-state>
#   </filter>
# </get>

# แสดงข้อมูล interface แบบย่อของ Huawei. huawei-ifm.yang กำหนด
# ifDynamicInfo/ifOperStatus เป็นสถานะใช้งานจริง จึงขอแยกจาก ifAdminStatus
# เพื่อให้คอลัมน์ Status ใช้ operational state เช่นเดียวกับ Cisco/Juniper.
def get_ip_interface_brief():
    return open_rpc_tag(f'''
<get>
  <filter type="subtree">
    <ifm xmlns="{NS_IFM}">
      <interfaces>
        <interface>
          <ifName/>
          <ifAdminStatus/>
          <ifDescr/>
          <ifMtu/>
          <ipv4Config>
            <am4CfgAddrs>
              <am4CfgAddr>
                <ifIpAddr/>
                <subnetMask/>
              </am4CfgAddr>
            </am4CfgAddrs>
          </ipv4Config>
          <ifDynamicInfo>
            <ifOperStatus/>
            <lineProtocolUpTime/>
          </ifDynamicInfo>
        </interface>
      </interfaces>
    </ifm>
  </filter>
</get>
''')

# <get>
#   <filter type="subtree">
#     <ifm xmlns="{NS_IFM}">
#       <interfaces>
#         <interface>
#           <ifName/>
#           <ifAdminStatus/>
#           <ipv4Config/>
#           <ifDescr/>
#         </interface>
#       </interfaces>
#     </ifm>
#   </filter>
# </get>

# get_interface_list ใช้ dropdown เท่านั้น จึงขอเฉพาะชื่อจาก huawei-ifm.yang:
# 430 container interfaces -> 433 list interface -> 437 leaf ifName; ไม่ขอ
# ipv4Config/ifDynamicInfo เพื่อไม่ดึงข้อมูลสถานะที่ฟอร์มนี้ไม่ใช้.
def get_interface_list():
    return open_rpc_tag(f'''
<get>
  <filter type="subtree">
    <ifm xmlns="{NS_IFM}">
      <interfaces>
        <interface>
          <ifName/>
        </interface>
      </interfaces>
    </ifm>
  </filter>
</get>
''')


# show all device information
def get_device_version():
    return open_rpc_tag(f'''
      <get>
        <filter type="subtree">
          <system xmlns="{NS_SYSTEM}">
            <systemInfo/>
          </system>
        </filter>
      </get>
    ''')

def get_ntp():
    return open_rpc_tag('''
        <get>
          <filter type="subtree">
            <ntp xmlns="http://www.huawei.com/netconf/vrp/huawei-ntp"/>
          </filter>
        </get>
    ''')

# CPU/RAM ของ CE12800 มีหลายบอร์ด; boardResStates จาก huawei-devm.yang
# คืน boardName/cpuUsage/memoryUsage ในแถวเดียวกัน เพื่อให้ poller เลือก MPU ตาม
# ชื่อบอร์ดแทนการ hardcode position. memoryInfos ยังจำเป็นสำหรับ osMemoryUsage
# ที่ผู้ใช้เลือกเป็นค่า RAM.
def get_cpu_memory_information():
    return open_rpc_tag(f'''
      <get>
        <filter type="subtree">
          <devm xmlns="{NS_DEVM}">
            <cpuInfos/>
            <memoryInfos/>
            <boardResStates>
              <boardResState/>
            </boardResStates>
          </devm>
        </filter>
      </get>
    ''')

# sysUpTime เป็น timeTick (1/100 วินาที) ของ system ที่หน้า Basic Info แสดงเป็น
# uptime เดียวกับ Cisco/Juniper; แยก RPC จาก devm CPU/RAM เพื่อคง filter เดิมไว้.
def get_uptime():
    return open_rpc_tag(f'''
      <get>
        <filter type="subtree">
          <system xmlns="{NS_SYSTEM}">
            <systemInfo>
              <sysUpTime/>
            </systemInfo>
          </system>
        </filter>
      </get>
    ''')

# show device license filter from device information
def get_device_license():
    return open_rpc_tag(f'''
      <get>
        <filter type="subtree">
          <system xmlns="{NS_SYSTEM}">
            <systemInfo>
              <esn/>
              <sysName/>
              <productName/>
              <productVer/>
            </systemInfo>
          </system>
        </filter>
      </get>
    ''')

# คง XML probe ไว้สำหรับตรวจสอบภายในเท่านั้น; ไม่ลงทะเบียนใน PUBLIC_FUNCTIONS
# และไม่มีหน้าเว็บผูกอยู่ตามคำสั่งผู้ใช้ จึงห้ามเปิดผ่าน API โดยไม่ทบทวนใหม่.
def get_mac_table_information():
    return '''<rpc message-id="102"
     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
    <identifier>huawei-mac</identifier>
    <format>yang</format>
  </get-schema>
</rpc>'''

def get_lcs():
    return open_rpc_tag('''
      <get>
        <filter type="subtree">
          <lcs xmlns="http://www.huawei.com/netconf/vrp/huawei-lcs">
             
          </lcs>
        </filter>
      </get>
    ''')

# show hostname filter from device information
def get_hostname():
    return open_rpc_tag(f'''
<get>
  <filter type="subtree">
    <system xmlns="{NS_SYSTEM}">
      <systemInfo>
        <sysName/>
      </systemInfo>
    </system>
  </filter>
</get>
''')

# set hostname
@validate_call
def set_hostname(hostname: str):
  # (bug 12) เดิมเช็คแค่ความยาว 1-246 ซึ่งปล่อยให้เว้นวรรค/ภาษาไทย/ขึ้นบรรทัดใหม่
  # ผ่านได้หมด - ย้ายมาใช้นโยบายกลางเพื่อให้กฎตรงกับอีก 2 ยี่ห้อและกับ CLI generator
  hostname = validate_hostname(hostname)
  return open_rpc_tag(edit_config_tag(f'''
    <system xmlns="{NS_SYSTEM}">
      <systemInfo>
        <sysName>{escape(hostname)}</sysName>
      </systemInfo>
    </system>
    '''))

# get interface switchport information
def get_switchport_information():
  return open_rpc_tag(f'''
    <get>
      <filter type="subtree">
        <ethernet xmlns="{NS_ETH}">
          <ethernetIfs>
            <ethernetIf/>
          </ethernetIfs>
        </ethernet>
      </filter>
    </get>
    ''')

def run_cli():
    return open_rpc_tag(edit_config_tag(F'''
    <ethernet xmlns="{NS_ETH}">
      <ethernetIfs>
        <ethernetIf>
          <ifName>GE1/0/7</ifName>
          <l2Attribute>
            <linkType>trunk</linkType>
            <trunkVlans>1,10,20</trunkVlans>
          </l2Attribute>
        </ethernetIf>          
      </ethernetIfs>            
    </ethernet>
    <ifm xmlns="{NS_IFM}">
      <interfaces>
        <interface>
          <ifName>GE1/0/7</ifName>
          <ifAdminStatus>up</ifAdminStatus>
        </interface>
      </interfaces>
    </ifm>
'''))

# set interface switchport / no switchport
@validate_call
def set_switchport(
  interface_type: str,
  interface_id: str,
  switchport: Literal[True, False] = True,
):
  # ifName ของ VRP เป็น GE1/0/1 ไม่ใช่ "GE 1/0/1"; ใช้ helper เดียวกับ
  # set_interface_static_ip เพื่อให้การเปลี่ยน L2/L3 กระทบ interface เดียวกันจริง.
  interface = _interface_name(interface_type, interface_id)
  status = ""
  if switchport:
      status = "enable"
  else:
      status = "disable"
  return open_rpc_tag(edit_config_tag(f'''
    <ethernet xmlns="http://www.huawei.com/netconf/vrp/huawei-ethernet">
      <ethernetIfs>
        <ethernetIf>
          <ifName>{interface}</ifName>
          <l2Enable>{status}</l2Enable>
        </ethernetIf>          
      </ethernetIfs>            
    </ethernet>
  '''))


# get vlan information
@validate_call
def get_vlan_information():
  return open_rpc_tag(f'''
    <get>
      <filter type="subtree">
        <vlan xmlns="{NS_VLAN}">
          <vlans/>
        </vlan>
      </filter>
    </get>
    ''')

# set vlan
@validate_call
def set_vlan(
    vlan_id: int,
    name: str | None = None,
    description: str | None = None,
    shutdown: bool = False,
):
  if not 1 <= vlan_id <= 4094:
      raise ValueError("vlan_id must be between 1 and 4094")
  if name is not None and not 1 <= len(name) <= 31:
      raise ValueError("name must be between 1 and 31 characters")
  if description is not None and not 1 <= len(description) <= 80:
      raise ValueError("description must be between 1 and 80 characters")

  name_xml = f"<vlanName>{escape(name)}</vlanName>" if name else ""
  desc_xml = f"<vlanDesc>{escape(description)}</vlanDesc>" if description else ""
  admin_status = "down" if shutdown else "up"

  return open_rpc_tag(edit_config_tag(f'''
    <vlan xmlns="{NS_VLAN}">
      <vlans>
        <vlan>
          <vlanId>{vlan_id}</vlanId>
          {name_xml}
          {desc_xml}
          <adminStatus>{admin_status}</adminStatus>
        </vlan>
      </vlans>
    </vlan>
  '''))

# remove vlan
@validate_call
def remove_vlan(vlan_id: int) -> str:
  if not 1 <= vlan_id <= 4094:
    raise ValueError("vlan_id must be between 1 and 4094")
  return open_rpc_tag(edit_config_tag(f'''
    <vlan xmlns="{NS_VLAN}">
      <vlans>
        <vlan xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0" xc:operation="delete">
          <vlanId>{vlan_id}</vlanId>
        </vlan>
      </vlans>
    </vlan>
  '''))

# set switchport mode "access" / "trunk"
# set access vlan
# set/remove trunk allow vlan (1>[1,2,3] 2>[2,3] = remove vlan 1 from allow)
@validate_call
def apply_interface_to_vlan(
    interface_type: str,
    interface_id: str,
    mode: Literal["access", "trunk"],
    vlan_id: int | None = None,
    trunk_allowed_vlans: list | Literal["1-4094"] | None = None,
    shutdown: bool | None = None,
    description: str | None = None,
):
    interface = _interface_name(interface_type, interface_id)

    if mode == "access":
        if vlan_id is None:
            raise ValueError("vlan_id is required when mode is 'access'")
        if trunk_allowed_vlans is not None:
            raise ValueError("trunk_allowed_vlans is not valid for access mode")
        if not 1 <= vlan_id <= 4094:
            raise ValueError("vlan_id must be between 1 and 4094")
        mode_config_xml = f"<pvid>{vlan_id}</pvid>"
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
        mode_config_xml = f"<trunkVlans>{vlan_range_str}</trunkVlans>"

    admin_status_xml = ""
    description_xml = _interface_description_xml(description)
    if shutdown is not None or description is not None:
        admin_status = "" if shutdown is None else f'<ifAdminStatus>{"down" if shutdown else "up"}</ifAdminStatus>'
        admin_status_xml = f'''
      <ifm xmlns="{NS_IFM}">
        <interfaces>
          <interface>
            <ifName>{interface}</ifName>
            {admin_status}{description_xml}
          </interface>
        </interfaces>
      </ifm>'''

    return open_rpc_tag(edit_config_tag(f'''
      <ethernet xmlns="{NS_ETH}">
        <ethernetIfs>
          <ethernetIf>
            <ifName>{interface}</ifName>
            <l2Attribute>
              <linkType>{mode}</linkType>
              {mode_config_xml}
            </l2Attribute>
          </ethernetIf>          
        </ethernetIfs>            
      </ethernet>{admin_status_xml}
    '''))

# set interface vlan
def set_interface_vlan(
    vlan_id: int,
    ip: str,
    mask: int,
    shutdown: bool = False,
    description: str | None = None,
    mtu: int | None = None,
):
    if not 1 <= vlan_id <= 4094:
        raise ValueError("vlan_id must be between 1 and 4094")
    interface = f"Vlanif{vlan_id}"
    ipaddress.IPv4Address(ip)
    netmask = _netmask(mask)
    admin_status = "down" if shutdown else "up"
    desc_xml = _interface_description_xml(description)
    ifmtu_xml = _ifmtu_xml(mtu)

    return open_rpc_tag(edit_config_tag(f'''
      <ifm xmlns="{NS_IFM}">
        <interfaces>
          <interface>
            <ifName>{interface}</ifName>
            <ifPhyType>Vlanif</ifPhyType>
            <ifAdminStatus>{admin_status}</ifAdminStatus>
            {desc_xml}
            {ifmtu_xml}
            <ipv4Config>
              <am4CfgAddrs>
                <am4CfgAddr>
                  <ifIpAddr>{ip}</ifIpAddr>
                  <subnetMask>{netmask}</subnetMask>
                  <addrType>main</addrType>
                </am4CfgAddr>
              </am4CfgAddrs>
            </ipv4Config>
          </interface>
        </interfaces>
      </ifm>
    '''))

# ลบ SVI ของ VRP ผ่านชื่อกลางเดียวกับ Cisco/Juniper; CE12800 ไม่มี sub-interface
@validate_call
def remove_interface_unit(interface_type: str, interface_id: str, unit: int):
  if interface_type.strip().lower() != "vlanif":
    raise ValueError("CE12800 does not support removing sub-interfaces; only interface_type Vlanif can be removed")
  try:
    vlan_id = int(interface_id)
  except (TypeError, ValueError) as exc:
    raise ValueError("interface_id of Vlanif must be a VLAN number") from exc
  if not 1 <= vlan_id <= 4094:
    raise ValueError("interface_id of Vlanif must be between 1 and 4094")
  return open_rpc_tag(edit_config_tag(f'''
    <ifm xmlns="{NS_IFM}">
      <interfaces>
        <interface xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0" xc:operation="delete">
          <ifName>Vlanif{vlan_id}</ifName>
        </interface>
      </interfaces>
    </ifm>
  '''))

# set interface static ip
@validate_call
def set_interface_static_ip(
  interface_type: str,
  interface_id: str,
  ip: str,
  mask: int,
  shutdown: bool = False,
  description: str | None = None,
  mtu: int | None = None,
):
  interface = _interface_name(interface_type, interface_id)
  ipaddress.IPv4Address(ip)
  netmask = _netmask(mask)
  admin_status = "up" if not shutdown else "down"
  # None preserves the existing description; empty explicitly removes it.
  desc_xml = _interface_description_xml(description)
  ifmtu_xml = _ifmtu_xml(mtu)
  # พอร์ต Ethernet จริงต้องออกจากโหมด Layer 2 ก่อนถึงจะรับ ifIpAddr ได้ และ VRP
  # ปฏิเสธการสลับถ้ายังมีค่า Layer 2 ค้างอยู่ (อุปกรณ์ตอบ "Please delete the
  # commands that are not supported after the switching") จึงล้าง trunkVlans/pvid
  # แล้วสั่ง l2Enable=disable ไว้ในก้อนเดียวกับการตั้ง IP: edit-config เดียวที่มี
  # error-option rollback-on-error อยู่แล้ว จึงได้ทั้งชุดหรือไม่ได้เลย ไม่มีพอร์ต
  # ที่ค้างเป็น Layer 3 แบบไม่มี IP แบบตอนแยกสองคำสั่ง
  # กฎของ CE12800 ที่ยืนยันจากอุปกรณ์จริง: พอร์ตจะสลับเป็น Layer 3 ได้ก็ต่อเมื่อ
  # เป็น access VLAN 1 อยู่ก่อนแล้ว ถ้าเป็น access VLAN อื่น หรือ trunk จะตอบ
  # "Please delete the commands that are not supported after the switching"
  #
  # และการล้างค่า Layer 2 กับการสลับโหมดอยู่ใน edit-config เดียวกันไม่ได้ ทุกแบบที่
  # ลองแล้วถูกปฏิเสธหมด: xc:operation="remove" เป็นค่าที่ไม่ถูกต้อง, replace ทั้ง
  # l2Attribute ตอบ "Objects do not support this operation", เขียน linkType=access
  # อย่างเดียวยังได้ข้อความ "Please delete the commands...", และเขียน linkType กับ
  # pvid คู่กับ l2Enable=disable ตอบ "The interface is not a L2 interface" เพราะ
  # อุปกรณ์ไม่ได้ทำตามลำดับในก้อนเดียวกัน มันมองว่าพอร์ตไม่ใช่ L2 แล้วจึงเขียน
  # l2Attribute ไม่ได้
  #
  # คำสั่งนี้จึงสั่งแค่ l2Enable=disable คู่กับการตั้ง IP ซึ่งใช้ได้เมื่อพอร์ตเป็น
  # access VLAN 1 อยู่แล้วหรือเป็น Layer 3 อยู่แล้ว ส่วนการคืนค่าพอร์ตที่เป็น trunk
  # หรือ access VLAN อื่นต้องทำเป็นคำสั่งแยกก่อนหน้า
  # Vlanif และ MEth ไม่ใช่ switchport จึงไม่เข้าเงื่อนไขและได้ XML เท่าเดิมทุกไบต์
  exit_switchport_xml = ""
  if interface_type.strip().upper().endswith("GE"):
    exit_switchport_xml = f'''
    <ethernet xmlns="{NS_ETH}">
      <ethernetIfs>
        <ethernetIf>
          <ifName>{interface}</ifName>
          <l2Enable>disable</l2Enable>
        </ethernetIf>
      </ethernetIfs>
    </ethernet>'''
  return open_rpc_tag(edit_config_tag(f'''{exit_switchport_xml}
    <ifm xmlns="{NS_IFM}">
      <interfaces>
        <interface>
          <ifName>{interface}</ifName>
          <ifAdminStatus>{admin_status}</ifAdminStatus>
          {desc_xml}
          {ifmtu_xml}
          <ipv4Config>
            <am4CfgAddrs>
              <am4CfgAddr>
                <ifIpAddr>{ip}</ifIpAddr>
                <subnetMask>{netmask}</subnetMask>
                <addrType>main</addrType>
              </am4CfgAddr>
            </am4CfgAddrs>
          </ipv4Config>
        </interface>
      </interfaces>
    </ifm>
  '''))

# Huawei ไม่มี DHCP relay จึงรับ helper_ips เพื่อให้ signature กลางตรงกันแต่ไม่ใช้ค่า
@validate_call
def clear_interface_ip(
  interface_type: str,
  interface_id: str,
  helper_ips: list[str] | None = None,
  ip: str | None = None,
):
  interface = _interface_name(interface_type, interface_id)
  # CE12800 ไม่มี DHCP relay จึงเมิน helper_ips ที่รับมาเพื่อให้ signature ตรงกับ
  # ยี่ห้ออื่น
  #
  # `am4CfgAddr` เป็น list ที่มี key เป็น `ifIpAddr` (huawei-ifm.yang:1760) การลบ
  # จึงต้องระบุ IP ที่จะลบเสมอ ถ้าส่ง element เปล่าอุปกรณ์ตอบ "Missing element:
  # ifIpAddr" หน้าเว็บมี IP เดิมของ interface อยู่แล้วจาก get_ip_interface_brief
  # จึงส่งมาให้ ส่วน subnetMask ไม่ต้องส่งเพราะไม่ใช่ key
  # ไม่ลบ ifAdminStatus กับ ifDescr อีกแล้ว: ทั้งสองไม่ใช่ส่วนหนึ่งของ "ล้าง IP"
  # และถ้า interface ไม่มี description อยู่ การสั่ง delete จะได้ data-missing ซึ่ง
  # ทำให้ทั้งชุดคำสั่ง (C4) ถูกยกเลิกทั้งที่ตั้งใจแค่ล้าง IP
  if ip is not None:
    ipaddress.IPv4Address(ip)
  address_key_xml = f"<ifIpAddr>{ip}</ifIpAddr>" if ip else ""
  return open_rpc_tag(edit_config_tag(f'''
    <ifm xmlns="{NS_IFM}">
      <interfaces>
        <interface>
          <ifName>{interface}</ifName>
          <ipv4Config>
            <am4CfgAddrs>
              <am4CfgAddr xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0" xc:operation="delete">
                {address_key_xml}
              </am4CfgAddr>
            </am4CfgAddrs>
          </ipv4Config>
        </interface>
      </interfaces>
    </ifm>
  '''))


@validate_call
def prepare_interface_for_l2(
  interface_type: str,
  interface_id: str,
  previous_addresses: list[str] | None = None,
  reset_description: bool = False,
  reset_mtu: bool = False,
  reset_admin_status: bool = False,
):
  """Restore app-managed L3 leaves before enabling Huawei Layer 2 mode.

  CE12800 rejects l2Enable=enable while non-default IFM configuration remains
  on a routed port. This command is deliberately separate from set_switchport:
  Huawei validates consecutive edit-config requests against the same candidate,
  while putting both changes in one XML document does not give them an order.
  The form reapplies description/admin status after the layer switch.
  """
  interface = _interface_name(interface_type, interface_id)
  if not interface_type.strip().upper().endswith("GE"):
    raise ValueError("prepare_interface_for_l2 supports only physical Ethernet interfaces")

  addresses_xml = ""
  for address in dict.fromkeys(previous_addresses or []):
    ipaddress.IPv4Address(address)
    addresses_xml += (
      f'<am4CfgAddr xmlns:nc="{NS_RPC}" nc:operation="delete">'
      f'<ifIpAddr>{address}</ifIpAddr></am4CfgAddr>'
    )
  ipv4_xml = (
    f"<ipv4Config><am4CfgAddrs>{addresses_xml}</am4CfgAddrs></ipv4Config>"
    if addresses_xml else ""
  )
  description_xml = f'<ifDescr xmlns:nc="{NS_RPC}" nc:operation="delete"/>' if reset_description else ""
  mtu_xml = f'<ifMtu xmlns:nc="{NS_RPC}" nc:operation="delete"/>' if reset_mtu else ""
  admin_xml = f'<ifAdminStatus xmlns:nc="{NS_RPC}" nc:operation="delete"/>' if reset_admin_status else ""

  if not (ipv4_xml or description_xml or mtu_xml or admin_xml):
    raise ValueError("No existing Layer 3 configuration to clear before switching to Layer 2")

  return open_rpc_tag(edit_config_tag(f'''
    <ifm xmlns="{NS_IFM}">
      <interfaces>
        <interface>
          <ifName>{interface}</ifName>
          {ipv4_xml}
          {description_xml}
          {mtu_xml}
          {admin_xml}
        </interface>
      </interfaces>
    </ifm>
  '''))

@validate_call
def remove_interface_mtu(interface_type: str, interface_id: str):
  interface = _interface_name(interface_type, interface_id)
  return open_rpc_tag(edit_config_tag(f'''
    <ifm xmlns="{NS_IFM}"><interfaces><interface>
      <ifName>{interface}</ifName>
      <ifMtu xmlns:nc="{NS_RPC}" nc:operation="delete"/>
    </interface></interfaces></ifm>
  '''))

@validate_call
def set_interface_l3_none(interface_type: str, interface_id: str,
                          previous_addresses: list[str] | None = None,
                          shutdown: bool | None = None, description: str | None = None,
                          reset_mtu: bool = False):
  interface = _interface_name(interface_type, interface_id)
  ethernet_xml = ""
  if interface_type.strip().upper().endswith("GE"):
    ethernet_xml = f'''<ethernet xmlns="{NS_ETH}"><ethernetIfs><ethernetIf>
      <ifName>{interface}</ifName><l2Enable>disable</l2Enable>
    </ethernetIf></ethernetIfs></ethernet>'''
  phy_xml = "<ifPhyType>Vlanif</ifPhyType>" if interface_type.lower() == "vlanif" else ""
  addresses_xml = ""
  for ip in dict.fromkeys(previous_addresses or []):
    ipaddress.IPv4Address(ip)
    addresses_xml += f'<am4CfgAddr xmlns:nc="{NS_RPC}" nc:operation="delete"><ifIpAddr>{ip}</ifIpAddr></am4CfgAddr>'
  ipv4_xml = f'<ipv4Config><am4CfgAddrs>{addresses_xml}</am4CfgAddrs></ipv4Config>' if addresses_xml else ""
  admin_xml = "" if shutdown is None else f'<ifAdminStatus>{"down" if shutdown else "up"}</ifAdminStatus>'
  desc_xml = _interface_description_xml(description)
  mtu_xml = f'<ifMtu xmlns:nc="{NS_RPC}" nc:operation="delete"/>' if reset_mtu else ""
  return open_rpc_tag(edit_config_tag(f'''
    {ethernet_xml}
    <ifm xmlns="{NS_IFM}"><interfaces><interface>
      <ifName>{interface}</ifName>{phy_xml}{ipv4_xml}{admin_xml}{desc_xml}
      {mtu_xml}
    </interface></interfaces></ifm>
  '''))


# แยกชื่อคำสั่งให้ตรงกับ API กลาง; description รับไว้ให้หน้า Interfaces ส่งได้
@validate_call
def set_no_shutdown(
  interface_type: str,
  interface_id: str,
  description: str | None = None,
):
  interface = _interface_name(interface_type, interface_id)
  return open_rpc_tag(edit_config_tag(f'''
    <ifm xmlns="{NS_IFM}">
      <interfaces>
        <interface>
          <ifName>{interface}</ifName>
          <ifAdminStatus>up</ifAdminStatus>
        </interface>
      </interfaces>
    </ifm>
  '''))

@validate_call
def set_shutdown(
  interface_type: str,
  interface_id: str,
  description: str | None = None,
):
  # รับ description เพื่อให้ signature ตรงกับ Cisco; XML ที่ผ่านอุปกรณ์จริงเดิม
  # ตั้งเฉพาะสถานะ down จึงไม่เขียน description ทับโดยไม่จำเป็น
  interface = _interface_name(interface_type, interface_id)
  return open_rpc_tag(edit_config_tag(f'''
    <ifm xmlns="{NS_IFM}">
      <interfaces>
        <interface>
          <ifName>{interface}</ifName>
          <ifAdminStatus>down</ifAdminStatus>
        </interface>
      </interfaces>
    </ifm>
  '''))

def get_static_route_configuration():
    return open_rpc_tag(f'''
      <get>
        <filter type="subtree">
          <staticrt xmlns="{NS_STATICRT}">
            <staticrtbase>
              <srRoutes/>
            </staticrtbase>
          </staticrt>
        </filter>
      </get>
    ''')

# |=========== ของเดิม 12 ก.ย. 2026: set_static_route สร้างอย่างเดียว โดยหน้าเว็บยิง remove_static_route นำหน้าตอนแก้ไข ===========|
# เก็บไว้เพื่อ rollback ถ้าผลทดสอบกับ CE12800 ไม่ผ่าน ลบทิ้งเมื่อกลุ่ม 48 ผ่านครบ
# # set static routing
# @validate_call
# def set_static_route(
#     prefix: str,
#     mask: int,
#     next_hop: str = None,
#     interface_type: str = None,
#     interface_id: str = None,
#     distance: str = None,
# ):
#     network = ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
#     if next_hop:
#         ipaddress.IPv4Address(next_hop)
#         nexthop_value = next_hop
#         ifname_value = "Invalid0"
#     elif interface_type is not None and interface_id is not None:
#         nexthop_value = "0.0.0.0"
#         ifname_value = _interface_name(interface_type, interface_id)
#     else:
#         raise ValueError("next_hop or interface_type/interface_id is required")
#
#     # (bug 13) เดิมเช็คแค่ขอบล่าง (pref < 1) ไม่มีขอบบน ค่าอย่าง 9999 จึงหลุดไปตายที่
#     # อุปกรณ์ - <preference> ของ Huawei เป็น uint32 range 1..255 (ยืนยันจาก
#     # device_capability/huawei/huawei-staticrt-staticrtbase.yang:302-305) ซึ่งบังเอิญ
#     # ตรงกับ Cisco แต่ไม่ตรงกับ Juniper จึงยังต้องส่งช่วงเข้าไปเองไม่ใช้ค่าร่วม
#     preference_xml = ""
#     if distance is not None:
#         preference_xml = f"<preference>{validate_distance(distance, 1, 255)}</preference>"
#
#     return open_rpc_tag(edit_config_tag(f'''
#       <staticrt xmlns="{NS_STATICRT}">
#         <staticrtbase>
#           <srRoutes>
#             <srRoute>
#               <vrfName>_public_</vrfName>
#               <afType>ipv4unicast</afType>
#               <topologyName>base</topologyName>
#               <prefix>{network.network_address}</prefix>
#               <maskLength>{mask}</maskLength>
#               <ifName>{ifname_value}</ifName>
#               <destVrfName>_public_</destVrfName>
#               <nexthop>{nexthop_value}</nexthop>
#               {preference_xml}
#             </srRoute>
#           </srRoutes>
#         </staticrtbase>
#       </staticrt>
#     '''))
# |=============================|

# set static routing
# replace_* (optional) = key ของ route เดิมตอนแก้ไข: VRP ใช้ prefix + mask + nexthop
# เป็น key จึงแก้ค่าในที่เดิมไม่ได้ ต้องลบของเก่าแล้วสร้างใหม่ เดิมหน้าเว็บยิง
# remove_static_route แล้วตามด้วย set_static_route เป็นคนละ RPC ถ้าตัวหลังล้ม route
# เดิมหายไปเลย - รวมทั้งสอง operation ไว้ใน edit-config เดียว โดยวาง delete ก่อน
# create ตามลำดับใน document แพทเทิร์นเดียวกับ replace_* ของ set_port_forward (Cisco)
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
    replace_next_hop: str | None = None,
):
    network = ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
    if next_hop:
        ipaddress.IPv4Address(next_hop)
        nexthop_value = next_hop
        ifname_value = "Invalid0"
    elif interface_type is not None and interface_id is not None:
        nexthop_value = "0.0.0.0"
        ifname_value = _interface_name(interface_type, interface_id)
    else:
        raise ValueError("next_hop or interface_type/interface_id is required")

    # (bug 13) เดิมเช็คแค่ขอบล่าง (pref < 1) ไม่มีขอบบน ค่าอย่าง 9999 จึงหลุดไปตายที่
    # อุปกรณ์ - <preference> ของ Huawei เป็น uint32 range 1..255 (ยืนยันจาก
    # device_capability/huawei/huawei-staticrt-staticrtbase.yang:302-305) ซึ่งบังเอิญ
    # ตรงกับ Cisco แต่ไม่ตรงกับ Juniper จึงยังต้องส่งช่วงเข้าไปเองไม่ใช้ค่าร่วม
    preference_xml = ""
    if distance is not None:
        preference_xml = f"<preference>{validate_distance(distance, 1, 255)}</preference>"

    # ต้องครบทั้งสามค่าเสมอ ถ้าส่งมาไม่ครบแปลว่า key ของ route เดิมไม่สมบูรณ์ ซึ่ง
    # จะลบผิดตัวหรือลบไม่โดน จึงหยุดตั้งแต่ต้นทางแทนที่จะปล่อยให้อุปกรณ์ตัดสิน
    replace_values = (replace_prefix, replace_mask, replace_next_hop)
    replace_xml = ""
    if any(value is not None for value in replace_values):
        if any(value is None for value in replace_values):
            raise ValueError("replace_prefix, replace_mask, and replace_next_hop must all be provided together")
        old_network = ipaddress.IPv4Network(f"{replace_prefix}/{replace_mask}", strict=False)
        ipaddress.IPv4Address(replace_next_hop)
        replace_xml = f'''
            <srRoute xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0" xc:operation="delete">
              <vrfName>_public_</vrfName>
              <afType>ipv4unicast</afType>
              <topologyName>base</topologyName>
              <prefix>{old_network.network_address}</prefix>
              <maskLength>{replace_mask}</maskLength>
              <ifName/>
              <destVrfName>_public_</destVrfName>
              <nexthop>{replace_next_hop}</nexthop>
            </srRoute>'''

    return open_rpc_tag(edit_config_tag(f'''
      <staticrt xmlns="{NS_STATICRT}">
        <staticrtbase>
          <srRoutes>{replace_xml}
            <srRoute>
              <vrfName>_public_</vrfName>
              <afType>ipv4unicast</afType>
              <topologyName>base</topologyName>
              <prefix>{network.network_address}</prefix>
              <maskLength>{mask}</maskLength>
              <ifName>{ifname_value}</ifName>
              <destVrfName>_public_</destVrfName>
              <nexthop>{nexthop_value}</nexthop>
              {preference_xml}
            </srRoute>
          </srRoutes>
        </staticrtbase>
      </staticrt>
    '''))


def remove_static_route(
    prefix: str,
    mask: int,
    next_hop: str = None,
):
    network = ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
    if next_hop:
        ipaddress.IPv4Address(next_hop)
        nexthop_value = next_hop
    else:
        raise ValueError("next_hop is required")
    return open_rpc_tag(edit_config_tag(f'''
      <staticrt xmlns="{NS_STATICRT}">
        <staticrtbase>
          <srRoutes>
            <srRoute xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0" xc:operation="delete">
              <vrfName>_public_</vrfName>
              <afType>ipv4unicast</afType>
              <topologyName>base</topologyName>
              <prefix>{network.network_address}</prefix>
              <maskLength>{mask}</maskLength>
              <ifName/>
              <destVrfName>_public_</destVrfName>
              <nexthop>{nexthop_value}</nexthop>
            </srRoute>
          </srRoutes>
        </staticrtbase>
      </staticrt>
    '''))

# ietf-yang-library

def get_ntp_information():
    return open_rpc_tag('''
    <get>
      <filter type="subtree">
        <ntp xmlns="http://www.huawei.com/netconf/vrp/huawei-ntp"/>
      </filter>
    </get>
    ''')

@validate_call
def set_ntp_server(
    ntp_ip: str,
):
    ntp_ip = str(ipaddress.IPv4Address(ntp_ip))
    return open_rpc_tag(edit_config_tag(f'''
      <ntp xmlns="http://www.huawei.com/netconf/vrp/huawei-ntp">
        <ntpUCastCfgs>
          <ntpUCastCfg>
            <addrFamily>IPv4</addrFamily>
            <ipv4Addr>{ntp_ip}</ipv4Addr>
            <ipv6Addr>::</ipv6Addr>
            <type>Server</type>
            <vpnName>_public_</vpnName>
            <neid>0-0</neid>
          </ntpUCastCfg>
        </ntpUCastCfgs>
      </ntp>
'''))

@validate_call
def remove_ntp_server(
    ntp_ip: str,
    addr_family: str = "IPv4",
    ipv6_addr: str = "::",
    ntp_type: str = "Server",
    vpn_name: str = "_public_",
    neid: str = "0-0",
):
    ntp_ip = str(ipaddress.IPv4Address(ntp_ip))
    if addr_family != "IPv4":
        raise ValueError("addr_family must be IPv4")
    ipv6_addr = str(ipaddress.IPv6Address(ipv6_addr))
    if ntp_type != "Server":
        raise ValueError("ntp_type must be Server")
    if not vpn_name:
        raise ValueError("vpn_name is required")
    if len(neid) > 50:
        raise ValueError("neid must contain at most 50 characters")

    safe_vpn_name = escape(vpn_name)
    safe_neid = escape(neid)
    # Huawei rejects operation="remove" on ntpUCastCfg. Delete the exact
    # instance using all six keys returned by get_ntp_information; do not
    # delete the parent container or other NTP servers.
    return open_rpc_tag(edit_config_tag(f'''
      <ntp xmlns="http://www.huawei.com/netconf/vrp/huawei-ntp">
        <ntpUCastCfgs>
          <ntpUCastCfg xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="delete">
            <addrFamily>{addr_family}</addrFamily>
            <ipv4Addr>{ntp_ip}</ipv4Addr>
            <ipv6Addr>{ipv6_addr}</ipv6Addr>
            <type>{ntp_type}</type>
            <vpnName>{safe_vpn_name}</vpnName>
            <neid>{safe_neid}</neid>
          </ntpUCastCfg>
        </ntpUCastCfgs>
      </ntp>
'''))

# ตรวจความสามารถอุปกรณ์ - ใช้ภายในระบบตรวจตอน call-home เท่านั้น ห้ามลงทะเบียนใน
# PUBLIC_FUNCTIONS; hello ของ CE12800 มีแค่ 207 capability จาก schema 386 ตัว จึงต้องขอแยก
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
    <reboot xmlns="http://www.huawei.com/netconf/vrp/huawei-devm">
      <saveConfig>true</saveConfig>
    </reboot>
''')

def get_local_user():
   return open_rpc_tag(f'''
  <get>
    <filter type="subtree">
      <aaa xmlns="{NS_AAA}">
        <lam>
          <users>
            <user/>
          </users>
        </lam>
      </aaa>
    </filter>
  </get>
''')


def _validate_local_username(username: str) -> str:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username is required")
    if len(username) > 253:
        raise ValueError("Username must contain at most 253 characters")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in username):
        raise ValueError("Username contains control characters")
    return escape(username)


def _validate_local_password(passwd: str) -> str:
    if not isinstance(passwd, str) or not passwd:
        raise ValueError("Password is required")
    # huawei-aaa-lam.yang accepts a plaintext input between 1 and 128
    # characters. The device stores it as irreversible-cipher.
    if len(passwd) > 128:
        raise ValueError("Password must contain at most 128 characters")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in passwd):
        raise ValueError("Password contains control characters")
    return escape(passwd)


@validate_call
def set_new_local_user(
    username: str,
    privilege: Literal[0, 3],
    passwd: str,
):
    """Create a Huawei SSH/terminal local user without overwriting a duplicate.

    privilege: 0 = Monitor Only, 3 = Network Admin (huawei-aaa-lam.yang userLevel 0..15).
    """
    safe_username = _validate_local_username(username)
    safe_password = _validate_local_password(passwd)

    return open_rpc_tag(edit_config_tag(f'''
      <aaa xmlns="{NS_AAA}">
        <lam>
          <users>
            <user xmlns:nc="{NS_RPC}" nc:operation="create">
              <userName>{safe_username}</userName>
              <passwordType>irreversible-cipher</passwordType>
              <password>{safe_password}</password>
              <userLevel>{privilege}</userLevel>
              <serviceTerminal>true</serviceTerminal>
              <serviceSsh>true</serviceSsh>
            </user>
          </users>
        </lam>
      </aaa>
    '''))


@validate_call
def edit_local_user(
    username: str,
    privilege: Literal[0, 3] | None = None,
    passwd: str | None = None,
):
    """Update selected Huawei local-user leaves and preserve Brownfield fields."""
    safe_username = _validate_local_username(username)
    if privilege is None and passwd is None:
        raise ValueError("At least one of privilege or password must be provided")

    privilege_xml = "" if privilege is None else f"<userLevel>{privilege}</userLevel>"
    password_xml = ""
    if passwd is not None:
        safe_password = _validate_local_password(passwd)
        password_xml = f'''
          <passwordType>irreversible-cipher</passwordType>
          <password>{safe_password}</password>
        '''

    return open_rpc_tag(edit_config_tag(f'''
      <aaa xmlns="{NS_AAA}">
        <lam>
          <users>
            <user>
              <userName>{safe_username}</userName>
              {privilege_xml}
              {password_xml}
            </user>
          </users>
        </lam>
      </aaa>
    '''))


@validate_call
def delete_local_user(username: str):
    """Delete exactly one Huawei local user from candidate configuration."""
    safe_username = _validate_local_username(username)

    return open_rpc_tag(edit_config_tag(f'''
      <aaa xmlns="{NS_AAA}">
        <lam>
          <users>
            <user xmlns:nc="{NS_RPC}" nc:operation="delete">
              <userName>{safe_username}</userName>
            </user>
          </users>
        </lam>
      </aaa>
    '''))

def factory_reset():
    return open_rpc_tag('''
        <delete-config>
          <target>
            <startup/>
          </target>
        </delete-config>
    ''')


def factory_reset_reboot():
    """Reboot without saving running config after startup was deleted.

    The ordinary ``reboot()`` intentionally uses ``saveConfig=true``. Reusing
    it in the factory-reset flow would write the current running configuration
    back to startup and undo the reset.
    """
    return open_rpc_tag('''
      <reboot xmlns="http://www.huawei.com/netconf/vrp/huawei-devm">
        <saveConfig>false</saveConfig>
      </reboot>
    ''')
