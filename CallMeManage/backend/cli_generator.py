""" |=======  Cli Generator ======= | """

import ipaddress
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
    load_ssh_public_key,
)

from backend.core.load_environment import load_environment
from backend.enrollment_token_service import validate_enrollment_token
from backend.interface_policy import validate_bootstrap_port, validate_cli_interfaces
from tools.local_admin_policy import validate_local_admin_password, validate_local_admin_username
from tools.random_passwd import rand_passwd
from tools.server_interface_ip import get_interface_ip
from tools.password_hash import hash_password_sha512 as _hash_password_sha512

# field validate
def _required(data: dict, *fields: str):
    # use field to get value for data-list, if data.get(field) value is none - raise error
    missing = [field for field in fields if not str(data.get(field, "")).strip()]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

ADMIN_USERNAME = load_environment().MNG_USER
def _callhome_address() -> str | None:
    # set by install_service.sh: a fixed IPv4 (CALLHOME_ADDRESS) or an interface whose IPv4 is used
    settings = load_environment()
    return settings.CALLHOME_ADDRESS or get_interface_ip(settings.CALLHOME_INTERFACE)


CLOUD_SERVER_IP = _callhome_address()
CLOUD_SERVER_PORT = str(load_environment().CALLHOME_PORT)
SSH_PUBLIC_KEY_PATH = Path(__file__).resolve().parent.parent / "tools" / "keys" / "rsa_public_key.pem"


def _load_ssh_public_key() -> str:
    """Load and validate the management RSA public key for each CLI render.

    The file may contain either an OpenSSH key or a PEM public key. Returning a
    canonical OpenSSH value also strips any accidental comment after the key.
    It is intentionally read for every generation so key rotation does not
    require a source-code change or backend restart.
    """

    try:
        raw_key = SSH_PUBLIC_KEY_PATH.read_bytes().strip()
    except OSError as exc:
        raise RuntimeError(f"SSH public key file is unavailable: {SSH_PUBLIC_KEY_PATH}") from exc
    if not raw_key:
        raise RuntimeError(f"SSH public key file is empty: {SSH_PUBLIC_KEY_PATH}")

    try:
        public_key = load_pem_public_key(raw_key) if raw_key.startswith(b"-----BEGIN") else load_ssh_public_key(raw_key)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise RuntimeError(f"SSH public key file is invalid: {SSH_PUBLIC_KEY_PATH}") from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise RuntimeError(f"SSH public key must be RSA: {SSH_PUBLIC_KEY_PATH}")

    return public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")


def _cisco_key_string(public_key: str) -> str:
    """Wrap the dynamic OpenSSH key for an IOS-XE ``key-string`` block."""

    algorithm, key_body = public_key.split(" ", 1)
    chunks = _chunk(key_body, 120)
    lines = [f"        {algorithm} {chunks[0]}"]
    lines.extend(f"        {chunk}" for chunk in chunks[1:])
    return "\n".join(lines)

# One-Time Enrollment Token (Phase 4): renderer รับ token เป็น keyword argument ที่ validate แล้วเท่านั้น
# - ไม่สร้าง/ไม่ hash token ที่นี่ และไม่ยัด token เข้า data dict (dict อาจถูก reuse/persist)
# - Cisco/Juniper เขียน token ลง boilerplate โดยตรง เพื่อให้อุปกรณ์รับพร้อม Load Config ก้อนเดียว
#   ตามข้อกำหนดปัจจุบัน (จึงถูกเก็บชั่วคราวใน Bootstrap_Token.bst_config_payload จน payload หมดอายุ)
# - Huawei ไม่มี bootstrap payload จึงยังฝัง token ใน CLI ที่คืนให้ผู้ใช้โดยตรง
# - ไม่ใส่ค่า token ลงใน error message
def _validated_enrollment_token(token):
    if token is None:
        return None
    if not validate_enrollment_token(token):
        raise ValueError("Invalid enrollment token")
    return token


# Phase 10: Local Administrator (Existing Device เท่านั้น, toggle เปิดเท่านั้น) - คำสั่งอยู่ใน manual CLI step ที่ส่งกลับครั้งเดียว
# ห้ามเข้า boilerplate (ที่ persist ใน Bootstrap_Token) ทั้งรหัสผ่าน, hash และชื่อ user ; ข้อความ error ไม่มีค่าที่กรอก
def _local_admin(data: dict, vendor: str):
    """คืน (username, password) เมื่อขอสร้าง Local Administrator ไม่เช่นนั้น None ; ตรวจซ้ำแม้ schema ตรวจแล้ว"""
    enabled = bool(data.get("add_local_administrator"))
    provided = data.get("local_admin_username") is not None or data.get("local_admin_password") is not None
    if not enabled:
        if provided:
            raise ValueError("Local administrator credentials are only accepted when it is enabled")
        return None
    if data.get("device_mode", "new") != "existing":
        raise ValueError("Local administrator can only be added to an Existing Device")
    username = validate_local_admin_username(vendor, data.get("local_admin_username"), ADMIN_USERNAME)
    password = validate_local_admin_password(data.get("local_admin_password"))
    return username, password


def _ensure_local_admin_not_in_payload(boilerplate: str, secrets_: list) -> None:
    for secret in secrets_:
        if secret and secret in boilerplate:
            raise RuntimeError("Local administrator credentials must not be part of the persisted bootstrap payload")


# crop input text to the specified width
def _chunk(text: str, width: int) -> list[str]:
    return [text[i : i + width] for i in range(0, len(text), width)]

# |======= แผนขา bootstrap ของ switch (ใช้ร่วมกันทุกยี่ห้อ) =======|
#
# เดิมมีแต่ Huawei ที่เลือกได้ว่าจะวาง IP bootstrap ไว้ที่ไหน ส่วน Cisco/Juniper
# ถูกบังคับเป็น SVI ของ VLAN 1 อย่างเดียว (ค่าคงที่ "Vlan1"/"vlan" ใน
# interface_policy.py) ผู้ใช้ขอให้ทั้งสามยี่ห้อมีตัวเลือกชุดเดียวกัน จึงยกกฎของ
# Huawei ขึ้นมาเป็นกฎกลาง แล้วให้แต่ละยี่ห้อ "เรนเดอร์" เป็น CLI ของตัวเอง
#
# 4 ทางเลือกที่รองรับ (เหมือนกันทุกยี่ห้อ):
#   layer3                    วาง IP บน physical port ตรง ๆ
#   vlan + access + default   SVI ของ VLAN 1 ไม่แตะ port เลย (port อยู่ VLAN 1 อยู่แล้ว)
#   vlan + access + specific  สร้าง VLAN, ตั้ง port เป็น access ของ VLAN นั้น, SVI
#   vlan + trunk              สร้าง VLAN, ตั้ง port เป็น trunk ที่ยอมให้ VLAN นั้นผ่าน, SVI
#
# คืน dict เดียวที่ทุกยี่ห้ออ่านเหมือนกัน: mode / vlan_id / port
# (port เป็น None เฉพาะกรณี access+default ซึ่งไม่ต้องแตะ port)
def resolve_bootstrap_plan(vendor: str, data: dict) -> dict:
    interface_type = data.get("bootstrap_interface_type")
    if interface_type == "layer3":
        return {"mode": "layer3", "vlan_id": None, "port": validate_bootstrap_port(vendor, data.get("bootstrap_interface"))}
    if interface_type != "vlan":
        raise ValueError("Bootstrap interface type must be vlan or layer3")

    vlan_mode = data.get("bootstrap_vlan_mode")
    if vlan_mode not in ("access", "trunk"):
        raise ValueError("Bootstrap VLAN mode must be access or trunk")

    if vlan_mode == "access":
        selection = data.get("bootstrap_vlan_selection")
        if selection == "default":
            return {"mode": "access", "vlan_id": 1, "port": None}
        if selection != "specific":
            raise ValueError("Bootstrap access VLAN selection must be default or specific")

    return {
        "mode": vlan_mode,
        "vlan_id": _bootstrap_vlan_id(data),
        "port": validate_bootstrap_port(vendor, data.get("bootstrap_interface")),
    }


def _bootstrap_vlan_id(data: dict) -> int:
    raw_vlan_id = data.get("bootstrap_vlan_id")
    try:
        vlan_id = int(raw_vlan_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Bootstrap VLAN ID must be between 1 and 4094") from exc
    if str(vlan_id) != str(raw_vlan_id).strip() or not 1 <= vlan_id <= 4094:
        raise ValueError("Bootstrap VLAN ID must be between 1 and 4094")
    return vlan_id


# hostname ไม่บังคับกรอกทุกยี่ห้อแล้ว (ผู้ใช้กำหนด) - ไม่กรอก = ไม่ออกคำสั่งตั้งชื่อ
# เลย อุปกรณ์คงชื่อเดิมของตัวเองไว้ เหมือนที่โหมด existing ทำอยู่แล้ว
def _hostname(data: dict) -> str:
    return str(data.get("hostname") or "").strip()


CISCO_CONFIG_FLASH_FILENAME = "cloud-manager-config.cfg"

def generate_cisco(data: dict, enrollment_token: str | None = None) -> dict:
    enrollment_token = _validated_enrollment_token(enrollment_token)
    ssh_public_key = _load_ssh_public_key()
    cisco_key_string = _cisco_key_string(ssh_public_key)
    local_admin = _local_admin(data, "cisco")
    _required(
        data,
        "cloud_server_ip",
        "cloud_server_port",
        "bootstrap_config_url",
    )
    # bool - check device existing
    is_existing = data.get("device_mode", "new") == "existing"
    # get device role from user input
    device_role = data.get("device_role", "router")
    # bool - check device is switch or not
    is_switch = device_role == "switch"
    # if device is not existing, must input these fields
    # hostname อยู่ในกลุ่มนี้ด้วย (ไม่ใช่ _required ชุดบนสุด) เพราะโหมด existing ไม่ตั้ง
    # hostname ให้เลย - ถ้าบังคับไว้ข้างบนจะกลายเป็นบังคับกรอกค่าที่ตัวเองไม่ได้ใช้
    if not is_existing:
        required = ["console_username", "console_password", "domain_name"]
        # switch ใช้ขาจากแผน bootstrap (resolve_bootstrap_plan) ไม่ใช่ wan_interface
        if not is_switch:
            required.append("wan_interface")
        _required(data, *required)

    # ใช้ .get() ไม่ใช่ data[...] เพราะโหมด existing ไม่บังคับส่ง wan_interface มาแล้ว
    # (ไม่มีจุดไหนในโหมดนั้นใช้ค่านี้จริง - ดู comment ด้านบน) ถ้าใช้ [] จะได้ KeyError
    # หลุดออกไปเป็น 500 แทนที่จะเป็น error ที่บอกได้ว่าขาด field ไหน
    wan = data.get("wan_interface")
    wan_mode = data.get("wan_mode", "dhcp")
    validate_cli_interfaces(
        vendor="cisco",
        device_mode=data.get("device_mode", "new"),
        device_role=device_role,
        wan_interface=wan,
    )

    interface_and_routing = ""
    if not is_existing:
        # if device is switch
        if is_switch:
            # ตัวเลือกขา bootstrap ชุดเดียวกับ Huawei แล้ว (ดู resolve_bootstrap_plan)
            plan = resolve_bootstrap_plan("cisco", data)
            wan_dns_cmd = ""
            if wan_mode == "static":
                _required(data, "wan_ip", "wan_mask", "wan_gateway")
                wan_address = f" ip address {data['wan_ip']} {data['wan_mask']}"
                # ไม่เปิด `ip routing` และไม่ใช้ `ip route` - switch bootstrap ต้องการแค่
                # ส่ง traffic ของตัวเองออกไปหา cloud server ซึ่ง `ip default-gateway`
                # ทำได้โดยไม่ต้องเปิด routing (และใช้ได้กับทั้ง SVI และ routed port)
                default_route = f"ip default-gateway {data['wan_gateway']}"
                if data.get("wan_dns"):
                    wan_dns_cmd = f"ip name-server {data['wan_dns']}"
            else:
                wan_address = " ip address dhcp"
                default_route = ""

            if plan["mode"] == "layer3":
                ip_interface = f"""interface {plan['port']}
 no switchport
{wan_address}
 no shutdown
exit"""
                vlan_and_port = ""
            else:
                vlan_id = plan["vlan_id"]
                # VLAN 1 มีอยู่แล้วทุกเครื่อง ไม่ต้องสร้าง
                vlan_block = "" if vlan_id == 1 else f"vlan {vlan_id}\nexit\n"
                port_block = ""
                if plan["port"]:
                    member = (f" switchport access vlan {vlan_id}" if plan["mode"] == "access"
                              else f" switchport trunk allowed vlan {vlan_id}")
                    port_block = f"""interface {plan['port']}
 switchport mode {"access" if plan["mode"] == "access" else "trunk"}
{member}
 no shutdown
exit
"""
                vlan_and_port = f"{vlan_block}{port_block}"
                ip_interface = f"""interface Vlan{vlan_id}
{wan_address}
 no shutdown
exit"""

            # generate interface command for switch
            # เยื้องบรรทัดย่อยใต้ interface ให้ตรงกับฝั่ง router (IOS ไม่สนใจการเยื้อง แต่
            # ผู้ใช้เอาไปเทียบกับ show running-config ได้ตรงกว่า)
            interface_and_routing = f"""{vlan_and_port}{ip_interface}
{default_route}
{wan_dns_cmd}"""
        else:
            wan_dns_cmd = ""
            if wan_mode == "static":
                _required(data, "wan_ip", "wan_mask", "wan_gateway")
                wan_address = f" ip address {data['wan_ip']} {data['wan_mask']}"
                default_route = f"ip route 0.0.0.0 0.0.0.0 {data['wan_gateway']}"
                if data.get("wan_dns"):
                    wan_dns_cmd = f"ip name-server {data['wan_dns']}"
            else:
                wan_address = " ip address dhcp"
                default_route = ""
            interface_and_routing = f"""{wan_dns_cmd}
!
 interface {wan}
 description CLOUD-WAN
 {wan_address}
 no shutdown
!
{default_route}"""

    cli_steps = []

    if not is_existing:
        hostname_line = f"hostname {_hostname(data)}\n" if _hostname(data) else ""
        initial_commands = f"""configure terminal

{hostname_line}ip domain name {data['domain_name']}

{interface_and_routing}

username {data['console_username']} privilege 15 secret {data['console_password']}
end""".strip()
        cli_steps.append({
            "id": "initial-config",
            "label": "Initial Device Configuration",
            "commands": initial_commands,
            "can_view_payload": False,
            "requires_manual_commit_before_next": False,
        })

    download_cmd = f"copy {data['bootstrap_config_url']} flash:{CISCO_CONFIG_FLASH_FILENAME}"
    cli_steps.append({
        "id": "load-config-file",
        "label": "Load Configuration File",
        "commands": download_cmd,
        "can_view_payload": True,
        "requires_manual_commit_before_next": False,
    })

    apply_cmd = f"copy flash:{CISCO_CONFIG_FLASH_FILENAME} running-config"
    cli_steps.append({
        "id": "copy-config-running",
        "label": "Copy Configuration to Running",
        "commands": apply_cmd,
        "can_view_payload": False,
        "requires_manual_commit_before_next": False,
    })

    if local_admin is not None:
        # manual step แยกท้ายสุด (ไม่แตะลำดับ load/apply/token เดิม) ; ไม่สั่ง write memory - ผู้ใช้ตัดสินใจ save เอง
        cli_steps.append({
            "id": "local-administrator",
            "label": "Create Local Administrator",
            "commands": f"""configure terminal
username {local_admin[0]} privilege 15 secret {local_admin[1]}
end""",
            "can_view_payload": False,
            "requires_manual_commit_before_next": False,
        })

    cli_segments = [step["commands"] for step in cli_steps]
    manual = "\n\n".join(cli_segments)

    # Call Home อยู่ในไฟล์ Load Config ก้อนเดียวทั้ง legacy และ token-aware
    endpoint_name = enrollment_token if enrollment_token is not None else "callhome-server"
    callhome_config = f"""netconf-yang callhome client CLOUD_MANAGEMENT
 endpoint {endpoint_name}
  ssh
  tcp-client-remote-address ip {data['cloud_server_ip']}
 exit
exit
"""

    boilerplate = f"""username {ADMIN_USERNAME} privilege 15
aaa new-model
aaa authentication login default local
aaa authorization exec default local
ip ssh version 2
ip ssh server algorithm publickey ssh-rsa rsa-sha2-256 rsa-sha2-512
ip ssh pubkey-chain
 username {ADMIN_USERNAME}
    key-string
{cisco_key_string}
        exit
    exit
exit
!
line vty 0 4
 transport input ssh
!
netconf-yang
{callhome_config}!"""
    if local_admin is not None:
        _ensure_local_admin_not_in_payload(boilerplate, [local_admin[1], f"username {local_admin[0]} "])

    return {
        "cli": manual,
        "cli_segments": cli_segments,
        "cli_steps": cli_steps,
        "boilerplate": boilerplate,
    }


JUNIPER_CONFIG_FILE_PATH = "/var/tmp/cloud-manager-config.txt"


def generate_juniper(data: dict, enrollment_token: str | None = None) -> dict:
    enrollment_token = _validated_enrollment_token(enrollment_token)
    ssh_public_key = _load_ssh_public_key()
    local_admin = _local_admin(data, "juniper")
    local_admin_hash = None
    _required(
        data,
        "cloud_server_ip",
        "cloud_server_port",
        "bootstrap_config_url",
    )
    # "existing" = brownfield ที่ WAN ใช้งานอยู่จริงแล้ว - ห้ามแตะ addressing เดิม
    # (ดู comment เดียวกันใน generate_cisco) - root_passwd ไม่บังคับอีกต่อไปใน
    # โหมดนี้ เพราะ segment_wan_interface (จุดเดียวที่ใช้ค่านี้) ไม่ถูกสร้างเลย -
    # อุปกรณ์ brownfield ผ่าน commit ครั้งแรกมาแล้วจริง (ไม่ใช่ factory-default)
    # เลยมี root authentication ตั้งไว้แล้วเสมอ ไม่ต้องตั้งซ้ำ - เจอบั๊กจริงเดียวกับ
    # Cisco (user ชี้เอง): `wan_interface` ก็ใช้แค่ใน `wan_config`/segment_wan_zone
    # ที่ถูกข้ามไปแล้วทั้งคู่เมื่อ existing (ดู comment ใน segment ด้านล่าง) เลย
    # ไม่มีที่ใช้จริงในโหมดนี้เหมือนกัน - ย้ายไปบังคับพร้อม root_passwd แทน
    is_existing = data.get("device_mode", "new") == "existing"
    # "switch" = Network Switch (EX/QFX, L2/L3) - in-band management ผ่าน
    # interface "vlan" (ล็อกค่าจาก frontend) แทน WAN physical interface -
    # `wan_config`/`default_route` ที่ประกอบด้านล่างใช้ร่วมกับ router ได้เลย
    # โดยไม่ต้องแก้อะไร (แค่ `wan`="vlan" แทน "ge-0/0/0" ฯลฯ) - จุดที่ต้องแยก
    # จริงๆ มีแค่ (1) DNS ไม่ optional เหมือน router (ดูด้านล่าง) และ (2)
    # **ห้ามสร้าง security-zone/NAT เด็ดขาด** (EX/QFX ไม่มี security-zone
    # แบบ SRX เลย - ข้าม segment_wan_zone ทั้งก้อน ดูจุดประกอบ cli_segments)
    device_role = data.get("device_role", "router")
    is_switch = device_role == "switch"
    sha512_pwd = ""
    console_pwd_hash = ""
    if not is_existing:
        required = ["root_passwd", "console_username", "console_password"]
        # switch ใช้ขาจากแผน bootstrap (resolve_bootstrap_plan) ไม่ใช่ wan_interface
        if not is_switch:
            required.append("wan_interface")
        _required(data, *required)
        sha512_pwd = _hash_password_sha512(data["root_passwd"])
        # console user (บัญชีสำรองกัน console ล็อกตาย - แนวเดียวกับ Cisco ที่ออกคำสั่ง
        # `username X privilege 15 secret Y`) - ใช้ _hash_password_sha512 ตัวเดียวกับ
        # root password เพราะ Junos รับ hash รูปแบบเดียวกันทั้งคู่ ($6$... ของ SHA-512
        # crypt) จึงไม่ต้องมีกลไก hash แยก
        console_pwd_hash = _hash_password_sha512(data["console_password"])

    # ใช้ .get() ไม่ใช่ data[...] เพราะโหมด existing ไม่บังคับส่ง wan_interface มาแล้ว
    # (wan_config/segment_wan_zone ที่เป็นจุดเดียวที่ใช้ค่านี้ ถูกข้ามไปทั้งคู่เมื่อ
    # existing) ถ้าใช้ [] จะได้ KeyError หลุดไปเป็น 500 แทน error ที่บอกได้ว่าขาดอะไร
    wan = data.get("wan_interface")
    wan_mode = data.get("wan_mode", "dhcp")
    validate_cli_interfaces(
        vendor="juniper",
        device_mode=data.get("device_mode", "new"),
        device_role=device_role,
        wan_interface=wan,
    )
    # switch: ขา bootstrap เลือกได้ชุดเดียวกับ Huawei แล้ว (ดู resolve_bootstrap_plan)
    # - SVI ใช้ irb.<vlan-id> ตาม ELS ของ Junos รุ่นใหม่ ส่วน layer3 วาง IP บน port ตรง ๆ
    switch_prefix_lines = ""
    if is_switch and not is_existing:
        plan = resolve_bootstrap_plan("juniper", data)
        if plan["mode"] == "layer3":
            address_target = f"{plan['port']} unit 0"
        else:
            vlan_id = plan["vlan_id"]
            # VLAN 1 คือ vlan "default" ที่ Junos มีมาให้อยู่แล้ว สร้างซ้ำไม่ได้
            # (vlan-id ชนกัน) จึงผูก l3-interface เข้ากับชื่อเดิมแทน
            vlan_name = "default" if vlan_id == 1 else f"BOOTSTRAP-{vlan_id}"
            lines = [] if vlan_id == 1 else [f"set vlans {vlan_name} vlan-id {vlan_id}"]
            if plan["port"]:
                interface_mode = "access" if plan["mode"] == "access" else "trunk"
                lines.append(
                    f"set interfaces {plan['port']} unit 0 family ethernet-switching "
                    f"interface-mode {interface_mode} vlan members {vlan_id}"
                )
            lines.append(f"set vlans {vlan_name} l3-interface irb.{vlan_id}")
            switch_prefix_lines = "\n".join(lines) + "\n"
            address_target = f"irb unit {vlan_id}"
    else:
        address_target = f"{wan} unit 0"

    wan_dns_cmd = ""
    if wan_mode == "static":
        _required(data, "wan_ip", "wan_prefix", "wan_gateway")
        ipaddress.IPv4Interface(f"{data['wan_ip']}/{data['wan_prefix']}")
        wan_config = (
            f"{switch_prefix_lines}set interfaces {address_target} family inet address "
            f"{data['wan_ip']}/{data['wan_prefix']}"
        )
        default_route = (
            "set routing-options static route 0.0.0.0/0 next-hop "
            f"{data['wan_gateway']}"
        )
        if data.get("wan_dns"):
            wan_dns_cmd = f"set system name-server {data['wan_dns']}"
    else:
        wan_config = f"{switch_prefix_lines}set interfaces {address_target} family inet dhcp"
        default_route = ""
        # DNS ไม่บังคับกรอกแล้ว (ผู้ใช้กำหนด) - เดิม switch ที่ไม่กรอกจะถูกยัด
        # 8.8.8.8 ให้เองเงียบ ๆ ซึ่งขัดกับความหมายของคำว่า "ไม่บังคับ" (ผู้ใช้เว้น
        # ว่างเพราะไม่อยากให้ไปตั้ง DNS ไม่ใช่เพราะอยากได้ค่า default ที่ไม่ได้เลือก)
        # และ bootstrap ไม่ต้องใช้ DNS อยู่แล้ว เพราะ bootstrap_config_url เป็น IP
        if data.get("wan_dns"):
            wan_dns_cmd = f"set system name-server {data['wan_dns']}"

    # รอบแรก: เดิมยัด SSH_PUBLIC_KEY ทั้งเส้น (base64 ~700 ตัวอักษร) เข้า "set
    # system login user ... authentication ssh-rsa" เป็นบรรทัดเดียว - บรรทัดยาว
    # ขนาดนี้ paste เข้า terminal client บางตัว (PuTTY/MobaXterm) แล้ว buffer ล้น
    # พิมพ์ผิด/หลุดบางส่วนได้ (ต่างจาก Cisco ที่ตัดเป็นหลายบรรทัดใน key-string ได้
    # เอง) แก้ด้วยการให้อุปกรณ์ไปดึงไฟล์ key เองผ่าน `file copy` แทนการพิมพ์ตรงๆ
    #
    # รอบสอง (หลังคุยออกแบบเพิ่ม): ขยายแนวคิดเดียวกันไปทั้งส่วน "boilerplate" ที่
    # ยาว/ซ้ำทุกครั้งเหมือนกันหมด (เปิด ssh/netconf/callhome, ผูก ssh key,
    # boilerplate ที่ซ้ำกัน) ย้ายไปให้อุปกรณ์ fetch + `load set` เองด้วย - เหลือให้
    # user paste เองแค่ส่วนที่ต้อง "เลือกเอง" จริงๆ (WAN interface/mode) กับ
    # ส่วนที่อ่อนไหว (root password - ไม่ใส่ในไฟล์ที่ fetch ได้เด็ดขาด) แล้วปิด
    # ท้ายด้วย fetch+load สั้นๆ - คืนเป็น 2 ก้อนแยกกัน: "cli" (ให้ user paste เอง)
    # กับ "boilerplate" (เก็บใน bst_config_payload ให้อุปกรณ์ fetch เอง - โชว์
    # ในหน้าเว็บด้วยเผื่ออยาก review ก่อน แต่ไม่ต้อง paste เอง) - ใช้ `run <cmd>`
    # เรียก operational command (file copy) จากข้างใน config mode ได้โดยไม่ต้อง
    # exit ออกมาก่อน
    #
    # รอบ 2.1: เดิมแยก SSH key เป็นไฟล์ของตัวเอง (key.pub) ดึงผ่าน `file copy`
    # แล้วผูกด้วย `authentication load-key-file` ต่างหากจาก boilerplate - แต่นั่น
    # แก้ปัญหา "พิมพ์ผ่าน terminal" ผิดจุด เพราะ boilerplate ทั้งก้อนโหลดผ่าน
    # `load set <file>` (fetch มาเป็นไฟล์ ไม่มีใครพิมพ์ผ่าน terminal เลย) เส้น
    # ssh-rsa ยาวแค่ไหนก็ไม่กระทบ - ฝัง SSH_PUBLIC_KEY ตรงๆ เป็นอีก `set` line
    # หนึ่งในไฟล์เดียวกันได้เลย ไม่ต้องมี key.pub/load-key-file/endpoint แยกอีก
    #
    # รอบ 2.2: security-zone WAN (+ host-inbound-traffic dhcp/ping/dns/ssh/
    # netconf) ย้ายจาก boilerplate ออกมาไว้ใน manual แทน - จุดนี้ deadlock กันเอง
    # ถ้าปล่อยไว้ใน boilerplate: อินเทอร์เฟซที่ยังไม่ได้อยู่ใน security zone ไหน
    # เลยจะไม่ผ่าน DHCP handshake ของตัวเองด้วยซ้ำ (host-inbound-traffic ที่ผูก
    # กับ zone เป็นตัวคุม DHCP client traffic ของ RE เอง ไม่ใช่แค่ traffic ปลายทาง
    # อื่น) เท่ากับต้องมี WAN ก่อนถึงจะ fetch ไฟล์ config ที่มี WAN อยู่ข้างในได้ -
    # แก้โดย commit ส่วน WAN (root password/hostname/interface+dhcp/security
    # zone) ให้ effective ก่อนหนึ่งรอบ แล้วค่อย `run file copy`/`load set` ส่วน
    # ที่เหลือ (ssh service/ssh key/netconf/outbound-ssh callhome/management)
    # เป็น commit รอบที่สอง - `commit` ไม่ออกจาก configuration mode เอง ใช้ `run`
    # เรียก operational command (file copy) ต่อจากในนั้นได้เลยไม่ต้อง exit ก่อน
    # Junos บังคับให้บล็อก outbound-ssh client ต้องมี device-id เสมอ (commit ไม่ผ่านถ้าขาด)
    # แต่ server ไม่เคยอ่านค่านี้เลย - ระบุตัวตนอุปกรณ์ด้วย one-time enrollment token
    # และ pinned SSH host-key fingerprint (ดู conn_socket.py's accept())
    # จึงไม่ต้องบังคับผู้ใช้กรอก hostname เพียงเพื่อเติมช่องนี้ ใช้ค่าคงที่แทนได้
    # (อุปกรณ์ brownfield มี hostname ของตัวเองอยู่แล้ว และเราไม่ควรไปเขียนทับ)
    device_id = _hostname(data) or "cloud-managed-device"

    # outbound-ssh อยู่ในไฟล์ Load Config ก้อนเดียวทั้ง legacy และ token-aware
    client_name = enrollment_token if enrollment_token is not None else "cloud-manager"
    outbound_ssh_config = f"""set system services outbound-ssh client {client_name} device-id {device_id}
set system services outbound-ssh client {client_name} services netconf
set system services outbound-ssh client {client_name} keep-alive timeout 20
set system services outbound-ssh client {client_name} keep-alive retry 5
set system services outbound-ssh client {client_name} reconnect-strategy sticky
set system services outbound-ssh client {client_name} {data['cloud_server_ip']} port {data['cloud_server_port']}
set system services outbound-ssh client {client_name} {data['cloud_server_ip']} retry 10
"""

    boilerplate = f"""set system login user {ADMIN_USERNAME} class super-user
set system login user {ADMIN_USERNAME} authentication ssh-rsa "{ssh_public_key}"
set system services ssh
set system services netconf ssh
set system services ssh protocol-version v2
{outbound_ssh_config}"""

    # รอบ 2.3: ต้นเหตุจริงของ "paste รวดเดียวไม่ได้" ไม่ใช่ DHCP race (ที่แก้ไป
    # รอบ 2.2) แต่คือ TTY/CLI input buffer ของอุปกรณ์ล้นตอน paste วอลุ่มรวมทั้ง
    # ก้อนเร็วเกินไป (คนละกลไกกับปัญหาเส้น ssh-key ยาวรอบแรก - รอบนี้ถึงบรรทัด
    # จะสั้นก็ล้นได้ถ้าจำนวนบรรทัด/ตัวอักษรรวมต่อการ paste ครั้งเดียวเยอะไป) ทาง
    # แก้ที่ตัวสคริปต์ทำได้คือลดจำนวนบรรทัดต่อการ paste แต่ละครั้งเท่านั้น (ทาง
    # แก้จริงคือปรับ paste-delay ที่ terminal client ฝั่ง user เอง ซึ่งควบคุมจาก
    # ที่นี่ไม่ได้) - เลยแตกเป็น "cli_segments" 3 ท่อนให้ paste ทีละท่อนแทนก้อน
    # เดียว (เว้นจังหวะให้อุปกรณ์ตามทันได้) แทนที่จะฝัง "# === part n ===" เป็น
    # comment ในสตริงเดียว (ไม่ชัวร์ว่า "#" ที่พิมพ์ตรงๆ ผ่าน interactive CLI จะ
    # ถูก parse เป็น comment เหมือนตอนอยู่ใน loaded file เสมอไป) ให้หน้าเว็บ
    # แสดง label ของแต่ละท่อนแทน ไม่ต้องฝังลงในเนื้อ CLI ที่จะ paste จริง - ทุก
    # ท่อนยัง paste ต่อกันในเซสชันเดียวกันได้เลย (ไม่มีท่อนไหน exit/reconnect
    # ระหว่างทาง) segment 1-2 ยังไม่ commit จนกว่าจะจบ segment 2 (WAN พร้อมใช้
    # งานจริงหลัง commit นี้) segment 3 ถึง fetch+load boilerplate ต่อได้
    # existing mode: ข้าม segment_wan_interface (root password/hostname/WAN
    # address/default-route) และ segment_wan_zone (ผูก WAN เข้า security-zone -
    # WAN เดิมของ brownfield ต้องอยู่ใน zone ที่ใช้งานได้จริงอยู่แล้ว ไม่งั้น
    # traffic ปกติของอุปกรณ์จะพังไปตั้งนานแล้วก่อนหน้านี้) ไปเลยทั้งคู่ - เหลือ
    # แค่ fetch+load boilerplate (ssh/netconf/outbound-ssh callhome) - ต้องเปิด
    # `configure` เองในนี้แทน เพราะปกติ segment_wan_interface เป็นคนเปิดค้างไว้
    # ให้ (ไม่ `exit` ออกก่อนจบ) ให้ segment ถัดๆ ไปยังอยู่ใน config mode ต่อเนื่อง
    cli_steps = []

    if not is_existing:
        host_name_line = f"set system host-name {_hostname(data)}\n" if _hostname(data) else ""
        segment_wan_interface = f"""configure
set system root-authentication encrypted-password "{sha512_pwd}"
set system login user {data['console_username']} class super-user authentication encrypted-password "{console_pwd_hash}"
{host_name_line}{wan_config}
{default_route}
{wan_dns_cmd}""".strip()

        if is_switch:
            cli_steps.append({
                "id": "initial-config",
                "label": "Initial Device Configuration",
                "commands": segment_wan_interface,
                "can_view_payload": False,
                "requires_manual_commit_before_next": True,
                "warning_message": "Review and commit the initial network configuration before downloading the bootstrap configuration. The system does not commit configuration automatically.",
            })
        else:
            cli_steps.append({
                "id": "initial-config",
                "label": "Initial Device Configuration",
                "commands": segment_wan_interface,
                "can_view_payload": False,
                "requires_manual_commit_before_next": False,
            })

            segment_wan_zone = f"""edit security zones security-zone WAN
set interfaces {wan}.0
set host-inbound-traffic system-services dhcp
set host-inbound-traffic system-services ping
set host-inbound-traffic system-services dns
set host-inbound-traffic system-services ssh
set host-inbound-traffic system-services netconf
top""".strip()
            cli_steps.append({
                "id": "wan-security-zone",
                "label": "Configure WAN Security Zone",
                "commands": segment_wan_zone,
                "can_view_payload": False,
                "requires_manual_commit_before_next": True,
                "warning_message": "Review and commit the initial network configuration before downloading the bootstrap configuration. The system does not commit configuration automatically.",
            })

    # ทุก Mode / Role แยกเป็น Load Configuration File, Load Configuration into Candidate และ Commit Check
    download_cmd = f"run file copy {data['bootstrap_config_url']} {JUNIPER_CONFIG_FILE_PATH}"
    cli_steps.append({
        "id": "load-config-file",
        "label": "Load Configuration File",
        "commands": download_cmd,
        "can_view_payload": True,
        "requires_manual_commit_before_next": False,
    })

    candidate_cmd = f"load set {JUNIPER_CONFIG_FILE_PATH}"
    cli_steps.append({
        "id": "load-config-candidate",
        "label": "Load Configuration into Candidate",
        "commands": candidate_cmd,
        "can_view_payload": False,
        "requires_manual_commit_before_next": False,
    })

    if local_admin is not None:
        # hash SHA-512 ตัวเดียวกับ console user (ไม่ส่ง plaintext) ; hash ยังเป็น credential จึงอยู่ใน manual step เท่านั้น
        # ห้ามเข้า boilerplate ; วางก่อน commit check (ยังเป็นการแก้ candidate เดียวกัน) ไม่ commit อัตโนมัติ
        # ไม่ใส่ `configure` เพราะ step ข้างเคียง (load set/commit check) ก็ทำงานใน config mode ที่ผู้ใช้เปิดอยู่แล้ว
        local_admin_hash = _hash_password_sha512(local_admin[1])
        cli_steps.append({
            "id": "local-administrator",
            "label": "Create Local Administrator",
            "commands": (
                f'set system login user {local_admin[0]} class super-user '
                f'authentication encrypted-password "{local_admin_hash}"'
            ),
            "can_view_payload": False,
            "requires_manual_commit_before_next": False,
        })

    commit_check_cmd = "commit check"
    cli_steps.append({
        "id": "commit-check",
        "label": "Commit Check",
        "commands": commit_check_cmd,
        "can_view_payload": False,
        "requires_manual_commit_before_next": False,
    })

    cli_segments = [step["commands"] for step in cli_steps]
    manual = "\n\n".join(cli_segments)

    if local_admin is not None:
        _ensure_local_admin_not_in_payload(
            boilerplate, [local_admin[1], local_admin_hash, f"login user {local_admin[0]} "]
        )

    return {
        "cli": manual,
        "cli_segments": cli_segments,
        "cli_steps": cli_steps,
        "boilerplate": boilerplate,
    }



def generate_huawei(data: dict, enrollment_token: str | None = None) -> str:
    enrollment_token = _validated_enrollment_token(enrollment_token)
    ssh_public_key = _load_ssh_public_key()
    local_admin = _local_admin(data, "huawei")
    # Huawei CE12800 เลือก bootstrap ได้ระหว่าง physical Layer 3 กับ SVI.
    # Access/default อาศัย VLAN 1 เดิม; access specific/trunk ผูก physical port
    # เข้ากับ VLAN ที่ระบุ แล้วใช้ Vlanif ของ VLAN นั้นรับ IP/call-home.
    _required(data, "cloud_server_ip", "cloud_server_port")
    is_existing = data.get("device_mode", "new") == "existing"

    wan_dns_cmd = ""
    wan_interface_block = ""
    if not is_existing:
        _required(
            data,
            "console_username",
            "console_password",
            "wan_ip",
            "wan_mask",
            "wan_gateway",
            "bootstrap_interface_type",
        )
        if len(data["console_username"].strip()) < 6:
            raise ValueError("Huawei Console Username must be at least 6 characters long")
        try:
            ipaddress.IPv4Interface(f"{data['wan_ip']}/{data['wan_mask']}")
        except ValueError as exc:
            raise ValueError(f"Invalid WAN IP/mask: {exc}") from exc
        if data.get("wan_dns"):
            wan_dns_cmd = f"dns server {data['wan_dns']}"

        plan = resolve_bootstrap_plan("huawei", data)
        if plan["mode"] == "layer3":
            interface_config = f"""interface {plan['port']}
 undo portswitch
 ip address {data['wan_ip']} {data['wan_mask']}
 undo shutdown
#
"""
        else:
            vlan_id = plan["vlan_id"]
            port_config = ""
            if plan["port"]:
                link_type = "access" if plan["mode"] == "access" else "trunk"
                member = f"port default vlan {vlan_id}" if plan["mode"] == "access" else f"port trunk allow-pass vlan {vlan_id}"
                port_config = f"""interface {plan['port']}
 port link-type {link_type}
 {member}
 undo shutdown
#
"""
            vlan_config = "" if vlan_id == 1 else f"vlan batch {vlan_id}\n#\n"
            interface_config = f"""{vlan_config}{port_config}interface Vlanif{vlan_id}
 ip address {data['wan_ip']} {data['wan_mask']}
 undo shutdown
#
"""

        wan_interface_block = f"""{interface_config}ip route-static 0.0.0.0 0.0.0.0 {data['wan_gateway']}
dns resolve
{wan_dns_cmd}
#
aaa
 local-user {data['console_username']} password irreversible-cipher {data['console_password']}
 local-user {data['console_username']} level 3
 local-user {data['console_username']} service-type ssh terminal
"""

    # Huawei VRP ไม่รับ key แบบ OpenSSH ("ssh-rsa AAAA...") ตรงๆ เหมือน Cisco/
    # Juniper - ต้องผ่าน `rsa peer-public-key`/`public-key-code begin/end` ที่
    # รับ base64 body เดียวกัน (ไม่มี "ssh-rsa " prefix) แค่ chunk ความกว้างบรรทัด
    # ต่างไป (64 ตัวอักษร/บรรทัด ตามรูปแบบเอกสาร Huawei ทั่วไป) แล้วผูกเข้า
    # local-user ผ่าน `assign rsa-key` - ยังไม่เคย verify กับอุปกรณ์ Huawei จริง

    key_lines = ssh_public_key
    key_name = f"{ADMIN_USERNAME}-key"
    # brownfield มีบัญชีเดิมอยู่แล้ว; โหมด existing ห้ามเขียนทับหรือเดารหัสผ่าน
    # ส่วนโหมด new สร้างบัญชี Netconf-MGMT พร้อมรหัสที่ผู้ใช้กรอกในฟอร์ม
    netconf_user_block = f"""aaa
 local-user {ADMIN_USERNAME} password irreversible-cipher {rand_passwd()}
 local-user {ADMIN_USERNAME} level 3
 local-user {ADMIN_USERNAME} service-type ssh
#
"""

    # existing mode: ไม่ตั้ง sysname ให้เลย (brownfield มีชื่อของตัวเองอยู่แล้ว -
    # เขียนทับจะทำ identity เดิมพัง เหมือนเหตุผลเดียวกับที่ Cisco/Juniper ข้าม
    # hostname ในโหมดนี้)
    sysname_line = f"sysname {_hostname(data)}\n" if not is_existing and _hostname(data) else ""

    # token-aware: token เป็นชื่อ endpoint ใต้ callhome CLOUD_MANAGEMENT (ไม่เหลือ callhome-server)
    # output ของ Huawei คืนตรงใน response ไม่ผ่าน Bootstrap_Token จึงไม่ถูก persist
    endpoint_name = enrollment_token if enrollment_token is not None else "callhome-server"

    # Phase 10: Local Administrator (Existing Device + toggle เปิดเท่านั้น) - อยู่ใน CLI ที่คืนตรง ๆ (Huawei ไม่ผ่าน Bootstrap)
    # ต่อท้ายบล็อก Call Home ก่อน user-interface โดยไม่แตะลำดับ NETCONF/RSA/Call Home/token เดิม ; ไม่สั่ง save
    local_admin_block = ""
    if local_admin is not None:
        local_admin_block = f"""aaa
 local-user {local_admin[0]} password irreversible-cipher {local_admin[1]}
 local-user {local_admin[0]} level 3
 local-user {local_admin[0]} service-type ssh terminal
#
"""

    return f"""system-view
{sysname_line}#
{wan_interface_block}rsa peer-public-key {key_name} encoding-type openssh
 public-key-code begin
{key_lines}
 public-key-code end
 peer-public-key end
#
{netconf_user_block}stelnet server enable
snetconf server enable
ssh user {ADMIN_USERNAME}
ssh user {ADMIN_USERNAME} authentication-type rsa
ssh user {ADMIN_USERNAME} assign rsa-key {key_name}
ssh user {ADMIN_USERNAME} service-type snetconf
#
netconf
 idle-timeout 5
 callhome CLOUD_MANAGEMENT
  endpoint {endpoint_name}
   peer-ip {data['cloud_server_ip']} port {data['cloud_server_port']}
#
{local_admin_block}user-interface vty 0 4
 authentication-mode aaa
 protocol inbound ssh
display configuration candidate
"""


# คืนค่าไม่เหมือนกันทุกยี่ห้อโดยตั้งใจ - juniper คืน dict (ต้องแยก manual/
# boilerplate ให้ cli_router.py เอา boilerplate ไปเก็บเป็น bst_config_payload)
# ส่วนที่เหลือยังคืน str เดิม (paste รวดเดียวจบ ไม่มีส่วนที่ยาวจนต้อง fetch แยก)
def generate_cli(vendor: str, data: dict, *, enrollment_token: str | None = None) -> str | dict:
    # เจอบั๊กจริง: `data.cloud_server_ip = ...` เป็น attribute assignment ใช้กับ
    # dict ธรรมดาไม่ได้ (dict ไม่มี __dict__ ให้ set attribute เอง) - โยน
    # AttributeError ทันทีทุกครั้งที่เรียก ยืนยันจาก curl จริงแล้วว่าได้ 500
    # Internal Server Error ก่อนแก้ - ต้องใช้ item assignment (`data[...] = ...`)
    data["cloud_server_ip"] = CLOUD_SERVER_IP
    # enrollment_token=None = legacy output (ไม่เปลี่ยนแม้แต่ byte เดียว); ค่าต้องมาจาก service ภายในเท่านั้น
    # (Phase 5) - /cli/generate ยังไม่ส่งค่านี้ และ CliGenerateRequest ไม่มี field นี้ให้ client ส่งเอง
    if vendor == "cisco":
        return generate_cisco(data, enrollment_token)
    if vendor == "juniper":
        return generate_juniper(data, enrollment_token)
    if vendor == "huawei":
        return generate_huawei(data, enrollment_token)
    raise ValueError("CLI generator for this vendor is under development")
