""" |======= Call Home Device Identity Writer (Add Marker / Verify / Compensate / Recovery CLI) =======| """
# Phase 9: จัดการการเขียน marker (token endpoint/client) ใหม่ลงอุปกรณ์สำหรับ Reset Device Identity
# - Writer: เพิ่ม marker ใหม่เท่านั้น (ห้ามลบเก่า ห้าม wildcard) ผ่าน send_transaction (candidate) หรือ send_payload (running)
# - Verifier: อ่าน running config กลับมาตรวจสอบว่า marker ใหม่อยู่ใน running config จริง
#   (ข้อจำกัด: Juniper filter อ่านได้เฉพาะ client name ไม่สามารถ verify IP/port ได้จาก running config filter นี้)
# - Compensation: ถ้า DB ล้มหลัง writer สำเร็จ ให้ลบ "เฉพาะ marker ใหม่ที่ระบบสร้างเอง" แล้ว verify ก่อนรายงาน
# - Recovery CLI: คืนคำสั่งสำหรับผู้ใช้วางเองที่อุปกรณ์ แสดงครั้งเดียว ไม่เก็บลง DB/Bootstrap payload
# ไฟล์นี้ไม่มี DB/UI logic ไม่ log/print secret (token/hash/IP/fingerprint) และไม่คืน token ใน exception
import itertools
from typing import Optional
from xml.etree import ElementTree as ET

from backend.callhome_token_probe import (
    CALLHOME_PARENT_NAME,
    _child_text,
    _children,
    _descendants,
    _local,
    _same_ip,
    _same_port,
    parse_reply,
    ProbeError,
)
from backend.enrollment_token_service import validate_enrollment_token

NETCONF_END = "]]>]]>"
NS_RPC = "urn:ietf:params:xml:ns:netconf:base:1.0"
_writer_message_ids = itertools.count(40000, 10)

JUNIPER_VERIFY_WARNING = (
    "Juniper Junos get-config filter can only verify outbound-ssh client name, "
    "not server IP/port from the running configuration."
)



class WriterError(Exception):
    """Base exception สำหรับ writer - ข้อความคงที่ ไม่มีค่าลับ"""
    def __init__(
        self,
        message: str = "Call Home identity write failed",
        *,
        marker_may_exist: bool = False,
    ):
        super().__init__(message)
        # ให้ orchestrator ตัดสินใจทำ compensation ได้โดยไม่ต้องเดาจากข้อความ error
        # True หมายถึง RPC เขียนถูกส่งไปแล้วและอุปกรณ์อาจ apply สำเร็จ แม้ reply/verify จะล้มเหลว
        self.marker_may_exist = marker_may_exist


class WriterVerificationError(WriterError):
    def __init__(self, message: str = "Call Home identity verification failed"):
        super().__init__(message, marker_may_exist=True)


class WriterOutcomeUnknownError(WriterError):
    """การส่ง write เริ่มแล้ว แต่ไม่สามารถยืนยันได้ว่าอุปกรณ์ apply หรือไม่"""
    def __init__(self, message: str = "Call Home identity write result is unknown"):
        super().__init__(message, marker_may_exist=True)


class CompensationFailedError(WriterError):
    def __init__(self, message: str = "Call Home compensation failed: device state unknown"):
        super().__init__(message)


def _rpc(message_id: int, inner: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<rpc xmlns="{NS_RPC}" message-id="{message_id}">{inner}</rpc>{NETCONF_END}'
    )


# ---------- Payload Builders (Add Marker) ----------

def build_add_marker_payload(
    vendor: str,
    token: str,
    cloud_ip: str,
    cloud_port: int | str,
    *,
    datastore: str = "candidate",
    device_id: str = "cloud-managed-device",
) -> str:
    if not validate_enrollment_token(token):
        raise ValueError("Invalid enrollment token")

    target_tag = f"<{datastore}/>"
    if vendor == "cisco":
        inner = (
            f"<edit-config><target>{target_tag}</target><config>"
            '<netconf-callhome-config xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ncch-cfg"><ncch-clients><ncch-client>'
            f"<name>{CALLHOME_PARENT_NAME}</name><ncch-client-endpoints><ncch-client-endpoint>"
            f"<name>{token}</name><ssh><tcpc-remote-ipaddr>{cloud_ip}</tcpc-remote-ipaddr>"
            f"<tcpc-remote-port>{cloud_port}</tcpc-remote-port></ssh>"
            "</ncch-client-endpoint></ncch-client-endpoints></ncch-client></ncch-clients></netconf-callhome-config>"
            "</config></edit-config>"
        )
    elif vendor == "huawei":
        inner = (
            f"<edit-config><target>{target_tag}</target><config>"
            '<sshs xmlns="http://www.huawei.com/netconf/vrp/huawei-sshs"><callHomes><callHome>'
            f"<callHomeName>{CALLHOME_PARENT_NAME}</callHomeName><sshEndpoints><sshEndpoint>"
            f"<endpointName>{token}</endpointName><address>{cloud_ip}</address><port>{cloud_port}</port>"
            "</sshEndpoint></sshEndpoints></callHome></callHomes></sshs>"
            "</config></edit-config>"
        )
    elif vendor == "juniper":
        inner = (
            f"<edit-config><target>{target_tag}</target><config>"
            '<configuration xmlns="http://yang.juniper.net/junos-es/conf/root">'
            '<system xmlns="http://yang.juniper.net/junos-es/conf/system"><services><outbound-ssh><client>'
            f"<name>{token}</name><device-id>{device_id}</device-id><services><netconf/></services>"
            "<keep-alive><timeout>20</timeout><retry>5</retry></keep-alive>"
            "<reconnect-strategy>sticky</reconnect-strategy>"
            f"<server-info><name>{cloud_ip}</name><port>{cloud_port}</port><retry>10</retry></server-info>"
            "</client></outbound-ssh></services></system></configuration>"
            "</config></edit-config>"
        )
    else:
        raise ValueError("Unsupported vendor for Call Home identity writer")

    return _rpc(next(_writer_message_ids), inner)


# ---------- Payload Builders (Delete Marker - Compensation Only) ----------

def build_delete_marker_payload(
    vendor: str,
    token: str,
    *,
    datastore: str = "candidate",
) -> str:
    if not validate_enrollment_token(token):
        raise ValueError("Invalid enrollment token")

    target_tag = f"<{datastore}/>"
    if vendor == "cisco":
        inner = (
            f"<edit-config><target>{target_tag}</target><config>"
            '<netconf-callhome-config xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ncch-cfg"><ncch-clients><ncch-client>'
            f"<name>{CALLHOME_PARENT_NAME}</name><ncch-client-endpoints><ncch-client-endpoint operation=\"delete\">"
            f"<name>{token}</name>"
            "</ncch-client-endpoint></ncch-client-endpoints></ncch-client></ncch-clients></netconf-callhome-config>"
            "</config></edit-config>"
        )
    elif vendor == "huawei":
        inner = (
            f"<edit-config><target>{target_tag}</target><config>"
            '<sshs xmlns="http://www.huawei.com/netconf/vrp/huawei-sshs"><callHomes><callHome>'
            f"<callHomeName>{CALLHOME_PARENT_NAME}</callHomeName><sshEndpoints><sshEndpoint operation=\"delete\">"
            f"<endpointName>{token}</endpointName>"
            "</sshEndpoint></sshEndpoints></callHome></callHomes></sshs>"
            "</config></edit-config>"
        )
    elif vendor == "juniper":
        inner = (
            f"<edit-config><target>{target_tag}</target><config>"
            '<configuration xmlns="http://yang.juniper.net/junos-es/conf/root">'
            '<system xmlns="http://yang.juniper.net/junos-es/conf/system"><services><outbound-ssh><client operation="delete">'
            f"<name>{token}</name>"
            "</client></outbound-ssh></services></system></configuration>"
            "</config></edit-config>"
        )
    else:
        raise ValueError("Unsupported vendor for Call Home identity writer")

    return _rpc(next(_writer_message_ids), inner)


# ---------- Payload Builders (Verify Marker) ----------

def build_verify_marker_payload(vendor: str) -> str:
    if vendor == "cisco":
        inner = (
            '<get-config><source><running/></source><filter type="subtree">'
            '<netconf-callhome-config xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ncch-cfg"><ncch-clients><ncch-client>'
            '<name/><ncch-client-endpoints><ncch-client-endpoint><name/><ssh><tcpc-remote-ipaddr/><tcpc-remote-port/></ssh>'
            '</ncch-client-endpoint></ncch-client-endpoints></ncch-client></ncch-clients></netconf-callhome-config>'
            '</filter></get-config>'
        )
    elif vendor == "huawei":
        inner = (
            '<get-config><source><running/></source><filter type="subtree">'
            '<sshs xmlns="http://www.huawei.com/netconf/vrp/huawei-sshs"><callHomes><callHome><callHomeName/><sshEndpoints>'
            '<sshEndpoint><endpointName/><address/><port/></sshEndpoint></sshEndpoints></callHome></callHomes></sshs>'
            '</filter></get-config>'
        )
    elif vendor == "juniper":
        inner = (
            '<get-config><source><running/></source><filter type="subtree">'
            '<configuration xmlns="http://yang.juniper.net/junos-es/conf/root">'
            '<system xmlns="http://yang.juniper.net/junos-es/conf/system"><services><outbound-ssh><client><name/></client>'
            '</outbound-ssh></services></system></configuration></filter></get-config>'
        )
    else:
        raise ValueError("Unsupported vendor for Call Home identity writer")

    return _rpc(next(_writer_message_ids), inner)


# ---------- Verifiers (Running Config Check) ----------

def _clean_reply(raw: object) -> str:
    if isinstance(raw, str):
        return raw.replace(NETCONF_END, "").strip()
    return str(raw or "")


def verify_marker_in_running_config(
    vendor: str,
    running_config_reply: str,
    token: str,
    cloud_ip: str,
    cloud_port: int | str,
) -> bool:
    try:
        root = parse_reply(_clean_reply(running_config_reply))
    except ProbeError:
        return False

    if vendor == "cisco":
        clients = [c for c in _descendants(root, "ncch-client") if _child_text(c, "name") == CALLHOME_PARENT_NAME]
        if len(clients) != 1:
            return False
        for holder in _children(clients[0], "ncch-client-endpoints"):
            for endpoint in _children(holder, "ncch-client-endpoint"):
                name = _child_text(endpoint, "name")
                ssh = _children(endpoint, "ssh")
                if name == token and len(ssh) == 1:
                    ip_match = _same_ip(_child_text(ssh[0], "tcpc-remote-ipaddr"), cloud_ip)
                    port_match = _same_port(_child_text(ssh[0], "tcpc-remote-port"), int(cloud_port), missing_ok=True)
                    if ip_match and port_match:
                        return True
        return False

    if vendor == "huawei":
        parents = [c for c in _descendants(root, "callHome") if _child_text(c, "callHomeName") == CALLHOME_PARENT_NAME]
        if len(parents) != 1:
            return False
        for holder in _children(parents[0], "sshEndpoints"):
            for endpoint in _children(holder, "sshEndpoint"):
                name = _child_text(endpoint, "endpointName")
                if name == token:
                    ip_match = _same_ip(_child_text(endpoint, "address"), cloud_ip)
                    port_match = _same_port(_child_text(endpoint, "port"), int(cloud_port), missing_ok=False)
                    if ip_match and port_match:
                        return True
        return False

    if vendor == "juniper":
        # ข้อจำกัดของ Juniper: get-config subtree filter อ่านได้เฉพาะ client name ไม่สามารถ verify IP/port ได้จาก running config
        for outbound in _descendants(root, "outbound-ssh"):
            for client in _children(outbound, "client"):
                if _child_text(client, "name") == token:
                    return True
        return False

    return False


def verify_marker_not_in_running_config(
    vendor: str,
    running_config_reply: str,
    token: str,
) -> bool:
    try:
        root = parse_reply(_clean_reply(running_config_reply))
    except ProbeError:
        return False


    if vendor == "cisco":
        for endpoint in _descendants(root, "ncch-client-endpoint"):
            if _child_text(endpoint, "name") == token:
                return False
        return True

    if vendor == "huawei":
        for endpoint in _descendants(root, "sshEndpoint"):
            if _child_text(endpoint, "endpointName") == token:
                return False
        return True

    if vendor == "juniper":
        for client in _descendants(root, "client"):
            if _child_text(client, "name") == token:
                return False
        return True

    return False


# ---------- Online Writer & Compensation Orchestration ----------

async def write_marker_online(
    callhome_service,
    dev_id: str,
    vendor: str,
    token: str,
    cloud_ip: str,
    cloud_port: int | str,
    device_id: str = "cloud-managed-device",
) -> None:
    session = callhome_service.sessions.get(dev_id)
    if not session:
        raise WriterError("No active Call Home session for device")

    uses_candidate = callhome_service._uses_candidate(session)
    datastore = "candidate" if uses_candidate else "running"

    add_payload = build_add_marker_payload(
        vendor, token, cloud_ip, cloud_port, datastore=datastore, device_id=device_id
    )

    if uses_candidate:
        try:
            idx, reply = await callhome_service.send_transaction(dev_id, [add_payload])
        except Exception as exc:
            # commit reply อาจหายหลังอุปกรณ์ apply แล้ว จึงต้องให้ caller ชดเชยแบบ fail closed
            raise WriterOutcomeUnknownError() from exc
        if idx != -1:
            raise WriterError("Device rejected add marker payload in transaction")
    else:
        try:
            reply = await callhome_service.send_payload(dev_id, add_payload)
        except Exception as exc:
            # writable-running อาจ apply ก่อน reply timeout/connection loss
            raise WriterOutcomeUnknownError() from exc
        if "<rpc-error" in reply and "<ok/>" not in reply:
            raise WriterError("Device rejected add marker payload")

    verify_payload = build_verify_marker_payload(vendor)
    try:
        verify_reply = await callhome_service.send_payload(dev_id, verify_payload)
    except Exception as exc:
        # add ได้รับการตอบรับแล้ว แต่ read-back ล้มเหลว จึงถือว่า marker อาจอยู่จริง
        raise WriterVerificationError() from exc
    if not verify_marker_in_running_config(vendor, verify_reply, token, cloud_ip, cloud_port):
        raise WriterVerificationError("Marker verification failed after online write")


async def compensate_marker_online(
    callhome_service,
    dev_id: str,
    vendor: str,
    token: str,
) -> bool:
    """ชดเชยเมื่อ DB ล้มหลัง writer สำเร็จ: ลบเฉพาะ marker ใหม่ที่เพิ่งสร้าง แล้ว verify
    คืน True ถ้าลบและ verify แล้วว่าหายจริง
    คืน False ถ้าชดเชยไม่ได้ (สถานะอุปกรณ์ unknown - ห้ามรายงาน success)"""
    session = callhome_service.sessions.get(dev_id)
    if not session:
        return False

    uses_candidate = callhome_service._uses_candidate(session)
    datastore = "candidate" if uses_candidate else "running"

    try:
        delete_payload = build_delete_marker_payload(vendor, token, datastore=datastore)
        if uses_candidate:
            idx, _ = await callhome_service.send_transaction(dev_id, [delete_payload])
            if idx != -1:
                return False
        else:
            reply = await callhome_service.send_payload(dev_id, delete_payload)
            if "<rpc-error" in reply and "<ok/>" not in reply:
                return False

        verify_payload = build_verify_marker_payload(vendor)
        verify_reply = await callhome_service.send_payload(dev_id, verify_payload)
        return verify_marker_not_in_running_config(vendor, verify_reply, token)
    except Exception:
        return False


# ---------- Recovery CLI Renderer ----------

def render_recovery_cli(
    vendor: str,
    token: str,
    cloud_ip: str,
    cloud_port: int | str,
    hostname: str = "",
) -> dict:
    if not validate_enrollment_token(token):
        raise ValueError("Invalid enrollment token")

    if vendor == "cisco":
        cli_commands = f"""configure terminal
netconf-yang callhome client {CALLHOME_PARENT_NAME}
 endpoint {token}
  ssh
  tcp-client-remote-address ip {cloud_ip}
 exit
exit
end"""
        steps = [{
            "id": "recovery-callhome-endpoint",
            "label": "Configure Recovery Call Home Endpoint",
            "commands": cli_commands,
            "requires_manual_commit_before_next": False,
        }]
        return {"cli": cli_commands, "cli_steps": steps}

    if vendor == "juniper":
        device_id = hostname.strip() or "cloud-managed-device"
        client = f"set system services outbound-ssh client {token}"
        config_commands = f"""{client} device-id {device_id}
{client} services netconf
{client} keep-alive timeout 20
{client} keep-alive retry 5
{client} reconnect-strategy sticky
{client} {cloud_ip} port {cloud_port}
{client} {cloud_ip} retry 10"""

        steps = [
            {
                "id": "recovery-outbound-ssh-client",
                "label": "Configure Recovery Outbound SSH Client",
                "commands": config_commands,
                "requires_manual_commit_before_next": True,
                "warning_message": "The system does not commit configuration automatically. You must run 'commit' manually on the device after applying this configuration.",
            },
            {
                "id": "commit-check",
                "label": "Commit Check",
                "commands": "commit check",
                "requires_manual_commit_before_next": False,
            },
        ]
        full_cli = f"{config_commands}\n\ncommit check"
        return {"cli": full_cli, "cli_steps": steps}

    if vendor == "huawei":
        cli_commands = f"""system-view
netconf
 callhome {CALLHOME_PARENT_NAME}
  endpoint {token}
   peer-ip {cloud_ip} port {cloud_port}
#
display configuration candidate"""
        steps = [{
            "id": "recovery-callhome-endpoint",
            "label": "Configure Recovery Call Home Endpoint",
            "commands": cli_commands,
            "requires_manual_commit_before_next": False,
        }]
        return {"cli": cli_commands, "cli_steps": steps}

    raise ValueError("Unsupported vendor for recovery CLI")
