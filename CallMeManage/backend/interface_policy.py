"""Validation policy for interface names used by the CLI generator.

Interface names are interpolated into commands that users paste into a device
CLI. Keep the accepted prefixes and shapes explicit so arbitrary text cannot
become another command.
"""

import re
from typing import Optional


_CISCO_INTERFACE_RE = re.compile(
    r"(?:Ethernet|FastEthernet|GigabitEthernet|TwoGigabitEthernet|"
    r"FiveGigabitEthernet|TenGigabitEthernet|FortyGigabitEthernet)"
    r"\d+(?:/\d+)*"
)
_JUNIPER_INTERFACE_RE = re.compile(r"(?:fe|ge|xe|et)-\d+/\d+/\d+")
_HUAWEI_INTERFACE_RE = re.compile(r"(?:GE|10GE|25GE|40GE)\d+/\d+/\d+", re.IGNORECASE)

# ขา bootstrap ของ switch เลือกได้ 2 แบบเหมือนกันทุกยี่ห้อแล้ว (ดู
# resolve_bootstrap_plan ใน backend/cli_generator.py): วาง IP บน SVI ของ VLAN
# หรือวางบน physical port ตรง ๆ - เดิม Cisco/Juniper ถูกบังคับให้เป็น SVI ของ
# VLAN 1 อย่างเดียว (ค่าคงที่ด้านล่าง) ตอนนี้เหลือไว้เป็นค่าเริ่มต้นของโหมด
# "access + default" เท่านั้น
DEFAULT_SWITCH_SVI = {"cisco": "Vlan1", "juniper": "irb.1"}


def _validate_physical_interface(vendor: str, value: str, field_name: str) -> None:
    patterns = {
        "cisco": (_CISCO_INTERFACE_RE, "GigabitEthernet1/0/1"),
        "juniper": (_JUNIPER_INTERFACE_RE, "ge-0/0/0"),
    }
    pattern, example = patterns[vendor]
    if not pattern.fullmatch(value):
        raise ValueError(
            f"Invalid {vendor} {field_name}; expected a value like {example}"
        )


def validate_cli_interfaces(
    *,
    vendor: str,
    device_mode: str,
    device_role: str,
    wan_interface: Optional[str],
) -> None:
    """Validate the Cisco/Juniper WAN interface that can enter generated CLI."""

    # Existing deployments do not generate interface config. Huawei already
    # has its own VLAN/Layer-3 interface validation in schema and generator.
    if device_mode == "existing" or vendor == "huawei":
        return
    if vendor not in ("cisco", "juniper"):
        return

    # โหมด switch ไม่ตรวจ wan_interface ที่นี่แล้ว - ชื่อขาที่ใช้จริงขึ้นกับแผน
    # bootstrap (SVI หรือ physical port) ซึ่ง validate_bootstrap_port() เป็นคน
    # ตรวจให้ครบทุกยี่ห้อในที่เดียว ดู resolve_bootstrap_plan
    if device_role == "switch":
        return

    wan = str(wan_interface or "").strip()
    if not wan:
        raise ValueError("WAN interface is required")

    _validate_physical_interface(vendor, wan, "WAN interface")


def validate_bootstrap_port(vendor: str, value) -> str:
    """ตรวจชื่อ physical port ที่ใช้เป็นขา bootstrap ของ switch - ที่เดียวทุกยี่ห้อ

    เดิมกฎนี้อยู่ 2 ที่ที่เขียนคนละแบบ: Cisco/Juniper ใช้ _validate_physical_interface
    ในไฟล์นี้ ส่วน Huawei เขียน regex ซ้ำเองทั้งใน schema.py และ cli_generator.py
    """
    port = str(value or "").strip()
    if not port:
        raise ValueError("Bootstrap interface is required")
    if vendor == "huawei":
        if not _HUAWEI_INTERFACE_RE.fullmatch(port):
            raise ValueError("Huawei interface must look like GE1/0/1")
        return port
    _validate_physical_interface(vendor, port, "bootstrap interface")
    return port
