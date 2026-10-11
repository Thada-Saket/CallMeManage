""" |======= API Device Management =======| """

# python tools
import json
import re
from xml.etree import ElementTree as ET
from tools.safe_xml import safe_fromstring
from functools import lru_cache
from typing import List
from uuid import UUID

# async tools
import asyncssh
import asyncio

# fastapi tools
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status

# sql tools
# from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from redis.exceptions import RedisError
from passlib.hash import sha512_crypt

# function and variable from other files
from backend.conn_socket import callhome_service, NetconfDesync, NetconfDead
from backend.core.connect_database import get_session
from backend.core.load_environment import load_environment
from backend.core.rate_limiter import rate_limit_by_device, rate_limit_by_device_command
from backend.core.presence import list_present_users, touch_presence
from backend.core.rbac import can_manage_site, get_effective_role
from backend.core.security_audit import audit_security_event
from backend.core.redis_client import get_redis
from backend.core.redis_lock import DeviceLock, DeviceLockBusy
from backend.api.user_deps import get_current_user
from backend.capability_service import blocked_reason, filter_commands, resolve
from backend.crud.dev_crud.crud_dev_capability import get_capability_profile
from backend.crud.dev_crud.crud_dev_history import create_history, list_history_by_device
from backend.crud.dev_crud.crud_dev_access import (
    AccessSessionConflictError,
    list_access_sessions_by_device,
    start_access_session,
    touch_access_session,
)
from backend.crud.dev_crud.crud_device_enrollment import get_pending_expirations_by_device_ids
from backend.crud.dev_crud.crud_dev_info import (
    delete_device_full,
    get_device,
    list_devices_for_user,
)
from backend.crud.dev_crud.crud_dev_config_object import (
    create_config_object,
    delete_config_object,
    get_config_object_by_name,
    list_config_objects,
)
from backend.running_config_snapshot import (
    extract_configuration_sections,
    extract_native_configuration_text,
    get_running_config_snapshot,
    public_snapshot,
    redact_native_configuration,
    store_running_config_snapshot,
)

# schemas and models
from backend.model.models import Device_Information, User_Table, generate_timestamp
from backend.schema.schema import (
    DeviceCommandRequest,
    DeviceCommandResult,
    DeviceFactoryResetRequest,
    DeviceFactoryResetResponse,
    DeviceAccessListPage,
    DeviceAccessRead,
    DeviceAccessSessionStart,
    DeviceConfigObjectCreate,
    DeviceConfigObjectRead,
    DeviceHistoryRead,
    DeviceHistoryListPage,
    DeviceListPage,
    DeviceRead,
    DeviceResetIdentityResponse,
    DeviceSummary,
    DeviceTransactionRequest,
    PingTestRequest,
    RunningConfigSnapshotCreated,
    RunningConfigSnapshotRead,
)
from backend.core.connect_database import AsyncSessionFactory
from backend.device_identity_reset import (
    DeviceInconsistentStateError,
    DeviceNotFoundError,
    ResetDatabaseError,
    ResetEligibilityError,
    ResetOnlineWriteError,
    reset_device_identity,
)

from backend.translator_service import build_payload, functions_for_vendor, module_for_vendor
from vendor_translators.response_normalizer import (
    normalize,
    reply_rejected,
    extract_cisco_nat_bound_acl_name,
    cisco_acl_reply_has_name,
    merge_nat_dashboard_replies,
    parse_local_usernames,
)
from tools.local_user_policy import (
    LOCAL_USER_WRITE_COMMANDS,
    check_target_against_device,
    history_parameters,
    redact_secret,
    validate_local_user_request,
)

# api path [127.0.0.1:8000/devices]
router = APIRouter(prefix="/devices", tags=["devices"])

# จำนวนอุปกรณ์ต่อชุดของ keyset pagination (ต้องตรงกับ PAGE_SIZE ฝั่ง frontend)
DEVICE_PAGE_SIZE = 18
HISTORY_PAGE_SIZE = 80
ACCESS_LOG_PAGE_SIZE = 40

# Cisco IOS XE can apply a compound NAT edit (ACL + NAT binding + interface
# roles) to writable-running before its NETCONF agent sends the rpc-reply. The
# normal 20-second reply timeout is deliberately kept for every other command;
# only the two compound NAT writes get a larger budget - this is a *separate*,
# narrower set from CISCO_NAT_WRITE_COMMANDS below (2026-09: Static NAT/Port
# Forwarding joined the "NAT write" family for quarantine/error-code purposes,
# but their writers are plain single-entry edit-configs with no measured
# evidence on this device that they need more than the default 20s - do not
# fold them into this timeout set without real capture evidence). Their Redis
# lease must also outlive both that read and a possible candidate commit on
# Cisco models which do not expose writable-running.
CISCO_NAT_WRITE_TIMEOUT_SECONDS = 60
CISCO_NAT_EXTENDED_TIMEOUT_COMMANDS = frozenset({"create_nat_policy", "remove_nat_policy"})

# (2026-09) Cisco NAT family ทั้งหมด (Source NAT + Static NAT + Port Forwarding) ใช้
# NETCONF session เดียวกันของอุปกรณ์เดียวกันเสมอ - จัดกลุ่มไว้ที่เดียวกันนี้แทนการ
# hardcode รายชื่อคำสั่งซ้ำหลายจุด (เดิม CISCO_NAT_WRITE_COMMANDS มีแค่ 2 ตัวปนกับ
# concept "ใครได้ timeout ยาว" - แยกออกจากกันแล้วเป็น CISCO_NAT_EXTENDED_TIMEOUT_COMMANDS
# ด้านบน เพราะ Static NAT/Port Forwarding ต้องการ error-code แยก read/write เหมือนกัน
# แต่ยังไม่มีหลักฐานว่าต้องการ timeout ยาวกว่า 20 วิ)
CISCO_NAT_READ_COMMANDS = frozenset({
    "get_nat_dashboard", "get_static_nat_information", "get_port_forward_information",
})
CISCO_NAT_WRITE_COMMANDS = frozenset({
    "create_nat_policy", "remove_nat_policy",
    "set_static_nat", "remove_static_nat",
    "set_port_forward", "remove_port_forward",
})

# session["nat_quarantine_until"] (conn_socket.py) กันคำสั่งใน family นี้ทั้งหมดไม่ให้
# ยิงซ้อนเข้า session เดิมขณะที่ผลของคำสั่งใดคำสั่งหนึ่งในกลุ่มเดียวกันยังไม่รู้ผล -
# timeout จาก Source NAT ป้องกัน Static NAT/Port Forwarding ได้ด้วยและกลับกัน เพราะ
# quarantine เป็น per-session (ต่อ dev_id) ไม่ใช่ per-command (ดู
# CISCO_NAT_QUARANTINE_SECONDS ใน conn_socket.py) ไม่กระทบคำสั่งอื่นของอุปกรณ์เดียวกัน
# เลย (คุมด้วย DeviceLock/session lock ตามปกติอยู่แล้ว) และไม่มีทาง Juniper/Huawei
# เข้ามาปนเพราะทุกจุด dispatch เช็ค device.dev_vendor == "cisco" เสมอ (Static NAT/Port
# Forwarding ใช้ชื่อคำสั่งเดียวกันข้ามยี่ห้อ - get_static_nat_information ฯลฯ เดินสาย
# Juniper ได้ด้วย จึงต้องเช็ค vendor ทุกจุดเสมอ ห้ามพึ่งแค่ชื่อคำสั่ง)
CISCO_NAT_QUARANTINE_COMMANDS = CISCO_NAT_READ_COMMANDS | CISCO_NAT_WRITE_COMMANDS

# Cisco IOS XE ปิดช่อง NETCONF ทิ้งตอน apply คำสั่งเขียน NAT (เปิด/ปิด NAT ก็เป็น) แทนที่จะตอบ
# rpc-reply - หน้าเว็บเคยขึ้น "Channel closed" ทั้งที่ config ลงไปแล้ว ทำให้ผู้ใช้ตกใจ ตอนนี้ปิด
# session เก่าแล้วรอให้อุปกรณ์ call-home กลับมาเงียบ ๆ (ปกติ 30-40 วิ) ก่อนตอบว่าสำเร็จ
# ผู้ใช้เห็นแค่ปุ่ม Save หมุนนานขึ้น ส่วนรายการ NAT ที่โหลดใหม่หลังบันทึกเป็นตัวยืนยันผลจริง
CISCO_NAT_RECONNECT_WAIT_SECONDS = 90

# คำสั่งที่เพิ่ม/ถอด "ip nat outside" และ ACL ของ NAT rule หลัก - ยืนยันจากอุปกรณ์จริง
# (HQ-Router-1, 2026-10-10): scope "any" ทำให้ ACL ครอบ IP ของขา WAN ที่ call-home วิ่งอยู่
# router จึงเอา PAT ไปใช้กับ session call-home ของตัวเอง (show ip nat translations เห็น
# 22.22.22.190:61435 -> 22.22.22.190:5062 ไปหา server:4334) port เปลี่ยนกลางทาง session เดิม
# ตายเงียบ ๆ ทั้งตอนเปิดและตอนปิด NAT แล้วอุปกรณ์ call-home ใหม่เองหลัง 0-17 วิแบบสุ่ม
# ไม่กรอง ACL บนอุปกรณ์ (any ต้องเป็น any ตามที่ผู้ใช้เลือก) - ฝั่งเราถือว่า session "จะตายแน่"
# หลังคำสั่งพวกนี้สำเร็จ ปิดเองทันทีแล้วรอตัวใหม่ก่อนตอบ ผู้ใช้เห็นแค่ปุ่มหมุนแล้วสำเร็จ
# ไม่ต้องเจอ refetch ค้าง 15 วิแล้ว 409 บนท่อที่ตายแล้ว
CISCO_NAT_SESSION_RESET_COMMANDS = frozenset({"create_nat_policy", "remove_nat_policy"})


def _netconf_channel_dropped(exc: BaseException) -> bool:
    # ConnectionError อื่น (เช่น "Device does not have a live Call Home session") ไม่ใช่เคสนี้
    return isinstance(exc, asyncssh.misc.ConnectionLost) or (
        isinstance(exc, ConnectionError) and str(exc) == "Channel closed"
    )


# "มีการแก้ไขที่ยังไม่ได้ save" ของ Cisco/Huawei (หน้า DeviceDetail ใช้เปลี่ยนปุ่ม Save Configuration
# เป็นสีหลัก + จุดเหลืองกระพริบ) - ทุกคำสั่งเขียนของระบบแก้ running อย่างเดียว ตั้ง flag เมื่อ
# คำสั่งเขียนสำเร็จจริง (อุปกรณ์ไม่ปฏิเสธ) และล้างเมื่อ save_running_config สำเร็จ
# เก็บใน Redis ต่ออุปกรณ์ (ไม่ใช่ browser) ทุกแท็บ/ผู้ใช้/การเปิดหน้าใหม่เห็นตรงกัน และไม่หาย
# ตอน restart backend - ข้อจำกัด: แก้จาก CLI ตรง ๆ ระบบไม่รู้ · best-effort ล้วน Redis ล่มไม่
# ทำให้คำสั่งพัง
CONFIG_UNSAVED_KEY = "device:config_unsaved:{dev_id}"
_READ_ONLY_PREFIXES = ("get_", "show_")
# ยี่ห้อที่ commit/edit-config แก้แค่ running ต้อง save ลง startup เอง (Juniper ไม่อยู่ในนี้
# เพราะ commit ของ Junos บันทึกถาวรอยู่แล้ว)
SAVE_CONFIG_VENDORS = frozenset({"cisco", "huawei"})
NETCONF_STARTUP_CAPABILITY = "urn:ietf:params:netconf:capability:startup:1.0"


async def _note_config_write(dev_id: str, vendor: str, command: str) -> None:
    if vendor not in SAVE_CONFIG_VENDORS or command.startswith(_READ_ONLY_PREFIXES):
        return
    key = CONFIG_UNSAVED_KEY.format(dev_id=dev_id)
    try:
        if command == "save_running_config":
            await get_redis().delete(key)
        else:
            await get_redis().set(key, "1")
    except Exception as exc:
        print(f"[!] failed to update unsaved-config flag for {dev_id}: {exc}")


# save-config เขียน startup-config ลง flash - อุปกรณ์ใหญ่/config ยาวใช้เวลาเกิน 20 วิ
# (timeout default ของ transport) ได้ ถ้าตัดก่อนจะได้ error ทั้งที่อุปกรณ์ save สำเร็จ
CISCO_SAVE_CONFIG_TIMEOUT_SECONDS = 60


def _command_reply_timeout(vendor: str, command: str) -> float | None:
    if vendor == "cisco" and command in CISCO_NAT_EXTENDED_TIMEOUT_COMMANDS:
        return CISCO_NAT_WRITE_TIMEOUT_SECONDS
    if vendor in SAVE_CONFIG_VENDORS and command == "save_running_config":
        return CISCO_SAVE_CONFIG_TIMEOUT_SECONDS
    return None


# จำกัดสแปมคำสั่งแก้ จำกัด 5 ครั้ง/ 3 วินาที/อุปกรณ์
device_command_rate_limiter = rate_limit_by_device_command("ratelimit:cmd", limit=5, window_seconds=3)
# /validate ไม่ติดต่ออุปกรณ์และไม่ดึง running config จริง จึงห้ามกิน quota ของ
# expensive read; quota ดังกล่าวนับเฉพาะ POST /command/{command} ที่แตะอุปกรณ์
device_command_validation_rate_limiter = rate_limit_by_device_command(
    "ratelimit:cmd", limit=5, window_seconds=3, enforce_expensive_reads=False,
)
# ชุดคำสั่ง (C4) ใช้ counter เดียวกับคำสั่งเดี่ยว แต่ไม่มี path parameter ชื่อ command
device_transaction_rate_limiter = rate_limit_by_device("ratelimit:cmd", limit=5, window_seconds=3)
# ปุ่มตรวจความสามารถใหม่ใช้ key แยก ไม่แย่งโควตาคำสั่งของผู้ใช้
capability_refresh_rate_limiter = rate_limit_by_device("ratelimit:capability", limit=1, window_seconds=10)
# Full running config is substantially heavier than ordinary read commands.
# Keep this quota separate so it cannot consume configuration-command quota.
running_config_snapshot_rate_limiter = rate_limit_by_device(
    "ratelimit:running-config-snapshot", limit=3, window_seconds=60
)
# Factory reset is destructive and never needs burst traffic. Allow a small
# number of attempts so a Juniper operator can correct a mistyped root password
# without waiting a full minute; Redis failure still fails closed.
factory_reset_rate_limiter = rate_limit_by_device(
    "ratelimit:factory-reset", limit=5, window_seconds=60, fail_closed=True
)

# ผูก Static NAT กับ Port Forwarding เข้ากับ Device_Config_Object เพื่ออ้างอิงชื่อ
TRACKED_FEATURES = {
    "set_static_nat": "static_nat",
    "set_port_forward": "port_forward",

    # "create_nat_pool": "nat_pool",
    # "create_nat_policy": "nat_policy",
    # "create_firewall_policy": "firewall_policy",
}

# ผูก key จริงของ config ที่อุปกรณ์ไม่มีชื่อเข้ากับแถวชื่อในฐานข้อมูล
TRACKED_REMOVALS = {
    "remove_static_nat": ("static_nat", ("local_ip", "global_ip")),
    "remove_port_forward": ("port_forward", ("protocol", "local_ip", "local_port", "global_ip", "global_port")),
}


def _stage_device_metadata_after_success(device, command: str, parameters: dict) -> None:
    """Keep display metadata aligned with a device change that was acknowledged.

    This only stages the in-memory ORM object. The existing history commit below
    persists the device name and history row together; rejected/timeout commands
    never reach this helper.
    """
    if command == "set_hostname":
        device.dev_name = parameters["hostname"]


def _same_config_key(saved, params, keys):
    return all(str(saved.get(key)) == str(params.get(key)) for key in keys)
async def _untrack_config_object(session, dev_id, command, parameters):
    item = TRACKED_REMOVALS.get(command)
    if item is None: return
    feature, keys = item
    try:
        for entry in await list_config_objects(session, dev_id, feature=feature):
            try: saved = json.loads(entry.cfg_params)
            except (TypeError, json.JSONDecodeError): continue
            if _same_config_key(saved, parameters, keys):
                await delete_config_object(session, entry.cfg_id)
    except Exception:
        await session.rollback()
async def _track_config_object(session, dev_id, usr_id, command, parameters):
    feature = TRACKED_FEATURES.get(command)
    if feature is None: return
    name = parameters.get("name")
    if not name: return
    try:
        if command == "set_static_nat" and parameters.get("replace_local_ip") is not None:
            old = {key: parameters.get("replace_" + key) for key in ("local_ip", "global_ip")}
            for entry in await list_config_objects(session, dev_id, feature=feature):
                try: saved = json.loads(entry.cfg_params)
                except (TypeError, json.JSONDecodeError): continue
                if _same_config_key(saved, old, tuple(old)):
                    # Cisco ไม่มีชื่อบนอุปกรณ์ การแก้ชื่อจึงอัปเดต object เดิมใน DB
                    # ส่วนการเปลี่ยน key ถูก translator รวม remove/create ใน RPC เดียว
                    entry.cfg_name, entry.cfg_params = name, json.dumps(parameters)
                    session.add(entry); await session.commit(); return
        if command == "set_port_forward" and parameters.get("replace_protocol") is not None:
            old = {key: parameters.get("replace_" + key) for key in ("protocol", "local_ip", "local_port", "global_ip", "global_port")}
            for entry in await list_config_objects(session, dev_id, feature=feature):
                try: saved = json.loads(entry.cfg_params)
                except (TypeError, json.JSONDecodeError): continue
                if _same_config_key(saved, old, tuple(old)):
                    # แก้ชื่อหรือ key ต้องอัปเดตแถวเดิม ไม่สร้างแถวซ้ำที่ชี้ของเก่า
                    entry.cfg_name, entry.cfg_params = name, json.dumps(parameters)
                    session.add(entry); await session.commit(); return
        existing = await get_config_object_by_name(session, dev_id, feature, name)
        if existing is not None:
            existing.cfg_params = json.dumps(parameters)
            session.add(existing); await session.commit(); return
        await create_config_object(session, dev_id, usr_id, DeviceConfigObjectCreate(cfg_feature=feature, cfg_name=name, cfg_params=parameters))
    except Exception:
        await session.rollback()


# # |====================== ลบได้ ======================|
# # ---------- นำเข้า NAT ที่ตั้งค่าไว้แล้วบนอุปกรณ์ (ก่อน/นอกเว็บนี้) เข้า DB ----------
# # หน้า NAT อ่านจาก Device_Config_Object อย่างเดียวตอนนี้ (ดู _track_nat_object) -
# # อุปกรณ์ที่ตั้งค่าไว้ก่อนแล้วจะไม่มีอะไรขึ้นเลยถ้าไม่ทำตรงนี้ เป็นการ "reverse-
# # compile" ค่าที่อ่านจากอุปกรณ์จริงกลับมาเป็น object ที่ track ได้ - best-effort
# # ยึด "ชื่อ" เป็น key เทียบกับที่ track ไว้แล้ว ไม่ทับของเดิม รองรับ Cisco เท่านั้น
# # ตอนนี้ (field เฉพาะยี่ห้อ verify แล้วจาก write-path ของ create_nat_policy/
# # create_nat_pool/set_acl_rule เอง ไม่ใช่การเดาใหม่)

# # ทุกข้อมูลที่วิ่งผ่าน function นี้จะ return ออกมาเป็น list ทั้งหมด
# def _ensure_list(value):
#     if value is None:
#         return []
#     return value if isinstance(value, list) else [value]

# # ถ้าผ่าน function นี้ไปชื่อ interface จะถูกแยกออกจากเลข interface
# def _split_interface_name(full_name: str) -> tuple[str, str]:
#     # แบ่งข้อมูลเป็น 2 ชุด จากตัวแปร full_name
#     # ชุดแรกจับตัวอักษรและ - 
#     # ชุดที่สองจับทั้งหมดทุกชนิดตัวอักษร
#     match = re.match(r"^([A-Za-z-]+)(.*)$", full_name.strip())
#     if not match:
#         return full_name.strip(), ""
#     return match.group(1), match.group(2)

# # แปลง wildcard ให้กลายเป็น subnet
# def _wildcard_to_cidr(network: str, wildcard: str) -> str:
#     # แปลง wildcard เป็นจำนวน host - 1
#     wildcard_int = int(ipaddress.IPv4Address(wildcard))

#     # เอาค่า host ที่ได้มากลับด้านเป็นค่าลบด้วย ~ จากนั้นนำไป and กับ 0xFFFFFFFF เพื่อจำกัดให้เหลือแค่ 32 bit
#     # 0xFFFFFFFF = 11111111.11111111.11111111.11111111 / 255.255.255.255
#     netmask_int = (~wildcard_int) & 0xFFFFFFFF

#     # แปลงค่าที่ได้ก่อนหน้าให้กลายเป็น subnetmask
#     netmask = str(ipaddress.IPv4Address(netmask_int))

#     # นำค่า IP ที่ได้มาไปเทียบกับ subnet เพื่อหาวง IP
#     net = ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)

#     # ส่งออกค่าวง IP พร้อม subnet (192.168.0.0/16)
#     return f"{net.network_address}/{net.prefixlen}"


# def _acl_source_scopes(
#     acl_entries, 
#     acl_name: str
# ) -> list[str]:
#     # เดินโครงสร้างเดียวกับ describeAddress ใน stateless.jsx (any / host-address /
#     # ipv4-address+mask) แต่คืนเป็น CIDR string ให้ตรงกับ source_scopes ที่
#     # create_nat_policy ใช้อยู่แล้ว
#     for acl in _ensure_list(acl_entries):
#         if not isinstance(acl, dict) or acl.get("name") != acl_name:
#             continue
#         scopes = []
#         for seq_rule in _ensure_list(acl.get("access-list-seq-rule")):
#             ace = seq_rule.get("ace-rule") or {}
#             if "any" in ace:
#                 scopes.append("any")
#             elif ace.get("ipv4-address") and ace.get("mask"):
#                 scopes.append(_wildcard_to_cidr(ace["ipv4-address"], ace["mask"]))
#             elif ace.get("host-address"):
#                 scopes.append(f"{ace['host-address']}/32")
#         return scopes
#     return []


# def _parse_live_nat_rules(nat_payload: dict) -> list[dict]:
#     source = nat_payload.get("native", {}).get("ip", {}).get("nat", {}).get("inside", {}).get("source", {})
#     rules = []
#     for entry in _ensure_list(source.get("list-interface", {}).get("list")):
#         target = entry.get("interface") or {}
#         rules.append({"name": entry.get("id", ""), "mode": "interface", "target": target.get("name", "")})
#     for entry in _ensure_list(source.get("list-pool", {}).get("list")):
#         target = entry.get("pool") or {}
#         rules.append({"name": entry.get("id", ""), "mode": "pool", "target": target.get("name", "")})
#     return rules


# def _parse_live_nat_pools(pool_payload: dict) -> list[dict]:
#     pool = pool_payload.get("native", {}).get("ip", {}).get("nat", {}).get("pool")
#     return [
#         {
#             "name": p.get("id", ""),
#             "start": p.get("start-address", ""),
#             "end": p.get("end-address", ""),
#             "netmask": p.get("netmask", ""),
#         }
#         for p in _ensure_list(pool)
#         if isinstance(p, dict)
#     ]


# async def _get_normalized_data(dev_id: str, vendor: str, command: str) -> dict:
#     payload = build_payload(vendor, command, {})
#     reply = await callhome_service.send_payload(dev_id, payload)
#     result = normalize(vendor, command, reply)
#     return result.get("payload", {}).get("data", {}) if isinstance(result, dict) else {}


# async def _reconcile_nat_objects_from_data(
#     session: AsyncSession, dev_id: str, usr_id: str, nat_data: dict, acl_data: dict, pool_data: dict
# ) -> dict:
#     # sync สองทิศทางระหว่างอุปกรณ์จริงกับ DB - (1) มีอยู่จริงแต่ยังไม่ track ->
#     # import เข้า DB (2) เคย track ไว้แต่ไม่มีอยู่จริงบนอุปกรณ์แล้ว (ลบผ่าน CLI
#     # ตรงๆ) -> ลบออกจาก DB กันข้อมูลค้าง - เป็น pure function รับข้อมูลที่ normalize
#     # แล้วเข้ามา ไม่ยิงคำสั่งหาอุปกรณ์เอง (ผู้เรียกจัดการเรื่อง fetch)
#     acl_entries = acl_data.get("native", {}).get("ip", {}).get("access-list", {}).get("extended")
#     live_pools = _parse_live_nat_pools(pool_data)
#     live_rules = _parse_live_nat_rules(nat_data)
#     live_pool_names = {p["name"] for p in live_pools if p["name"]}
#     live_policy_names = {r["name"] for r in live_rules if r["name"]}

#     imported_pools = 0
#     for pool in live_pools:
#         if not pool["name"]:
#             continue
#         if await get_config_object_by_name(session, dev_id, "nat_pool", pool["name"]) is not None:
#             continue
#         await create_config_object(
#             session, dev_id, usr_id,
#             DeviceConfigObjectCreate(cfg_feature="nat_pool", cfg_name=pool["name"], cfg_params=pool),
#         )
#         imported_pools += 1

#     imported_policies = 0
#     for rule in live_rules:
#         if not rule["name"]:
#             continue
#         if await get_config_object_by_name(session, dev_id, "nat_policy", rule["name"]) is not None:
#             continue

#         params = {
#             "name": rule["name"],
#             "translate_mode": rule["mode"],
#             "source_scopes": _acl_source_scopes(acl_entries, rule["name"]) or ["any"],
#         }
#         references = []
#         if rule["mode"] == "interface":
#             via_type, via_id = _split_interface_name(rule["target"])
#             params["via_type"] = via_type
#             params["via_id"] = via_id
#         else:
#             params["pool_name"] = rule["target"]
#             params["via_type"] = ""
#             params["via_id"] = ""
#             # หา "ขา via" (interface ที่เป็น ip nat outside) จากอุปกรณ์ไม่ได้ตอนนี้
#             # (ยังไม่มี query เช็ค ip/nat/outside ต่อ interface) - flag ไว้ตรงๆ
#             # ไม่เดา ให้ frontend โชว์ "ไม่ทราบ" แทน
#             params["via_unknown"] = True
#             pool_obj = await get_config_object_by_name(session, dev_id, "nat_pool", rule["target"])
#             if pool_obj is not None:
#                 references = [pool_obj.cfg_id]

#         await create_config_object(
#             session, dev_id, usr_id,
#             DeviceConfigObjectCreate(cfg_feature="nat_policy", cfg_name=rule["name"], cfg_params=params, references=references),
#         )
#         imported_policies += 1

#     # ทิศตรงข้าม: เคย track ไว้แต่หายไปจากอุปกรณ์แล้ว (เช่นลบผ่าน CLI ตรงๆ) - ลบ
#     # nat_policy (ฝั่ง CASCADE) ก่อนเสมอ แล้วค่อยลบ nat_pool (ฝั่ง RESTRICT) เพราะถ้า
#     # policy ที่เคยอ้างอิง pool นั้นถูกลบไปแล้วในรอบนี้ pool จะว่างจาก reference
#     # พอดี ลบต่อได้เลยไม่ติด constraint
#     removed_policies = 0
#     for obj in await list_config_objects(session, dev_id, feature="nat_policy"):
#         if obj.cfg_name in live_policy_names:
#             continue
#         await delete_config_object(session, obj.cfg_id)
#         removed_policies += 1

#     removed_pools = 0
#     for obj in await list_config_objects(session, dev_id, feature="nat_pool"):
#         if obj.cfg_name in live_pool_names:
#             continue
#         try:
#             await delete_config_object(session, obj.cfg_id)
#             removed_pools += 1
#         except IntegrityError:
#             # ยังมี object อื่นอ้างอิงอยู่จริง (เช่น policy ที่ยัง track อยู่และยัง
#             # live อยู่ แต่ pool มันอ้างหายไปจากอุปกรณ์แล้ว - config ไม่สอดคล้องกัน
#             # เองบนอุปกรณ์) ปล่อยไว้ก่อนแทนที่จะบังคับลบ
#             await session.rollback()

#     return {
#         "imported_pools": imported_pools,
#         "imported_policies": imported_policies,
#         "removed_pools": removed_pools,
#         "removed_policies": removed_policies,
#     }


# async def _reconcile_nat_objects(session: AsyncSession, dev_id: str, usr_id: str, vendor: str) -> dict:
#     if vendor != "cisco":
#         raise ValueError(f"ยังไม่รองรับการนำเข้า NAT ที่มีอยู่แล้วสำหรับยี่ห้อ {vendor}")

#     nat_data = await _get_normalized_data(dev_id, vendor, "get_nat_information")
#     acl_data = await _get_normalized_data(dev_id, vendor, "get_acl_information")
#     pool_data = await _get_normalized_data(dev_id, vendor, "get_nat_pool_information")
#     return await _reconcile_nat_objects_from_data(session, dev_id, usr_id, nat_data, acl_data, pool_data)
# # |=====================================================|

# ส่วนคืนค่าสถานะของอุปกรณณ์ โดยรับค่า status และ device id มาทำงาน 
def _live_status(
    dev_status: str, 
    dev_id: str
) -> str:
    # ถ้า status ที่เข้ามาไม่ใช่ active ให้ส่งคืนค่าเดิม
    if dev_status != "active":
        return dev_status

    # (bug 55) เดิมตัดสินแค่ "มี session ไหม" ซึ่งเป็นจริงตราบใดที่ TCP ยังต่ออยู่
    # แต่จาก log จริงพบว่าอุปกรณ์ต่ออยู่แต่ไม่ตอบ NETCONF เลยนาน ~14 นาที ระหว่างนั้น
    # ป้ายในหน้ารายการอุปกรณ์ขึ้น "Online" ตลอด ผู้ใช้เห็นแล้วกดสั่งงานก็ไปเจอ timeout
    # เอาเอง - เพิ่มสถานะที่ 3 "unresponsive" (ต่ออยู่แต่ไม่ตอบ) โดยใช้ตัวนับ
    # ความล้มเหลวของ stats poll ที่มีอยู่แล้วเป็นตัวตัดสิน
    health = callhome_service.device_health(dev_id)
    if not health["connected"]:
        return "offline"
    return "active" if health["responsive"] else "unresponsive"


# ดึงข้อมูลอุปกรณ์ที่มีสิทธิเข้าถึงเท่านั้น ถ้าไม่ใช่จะ return error 404 ให้ไม่รู้ว่าอุปกรณ์นั้นมีอยู่จริงไหม
async def _get_authorized_device(
    session: AsyncSession,
    dev_id: str, 
    usr_id: str
) -> Device_Information:
    # ดึงข้อมูลอุปกรณ์จาก id ของอุปกรณ์
    device = await get_device(session, dev_id)

    # ตรวจสอบว่าเจออุปกรณ์ไหม
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    # ตรวจสอบสิทธิเข้าถึงภายใน site
    role = await get_effective_role(session, usr_id, device.site_id)
    if role == "unauthorized":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    # ส่งออกผลลัพธ์
    return device

async def _require_site_access(
    session: AsyncSession, 
    site_id: str, 
    usr_id: str
) -> str:
    role = await get_effective_role(session, usr_id, site_id)
    if role == "unauthorized":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found.")
    return role

# เป็น function ตรวจสอบสิทธิผู้ใช้ในการจัดการดูแล site
async def _require_site_manage(session: AsyncSession, site_id: str, usr_id: str) -> str:
    role = await _require_site_access(session, site_id, usr_id)
    if not can_manage_site(role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the Site Owner or Site Admin can manage this resource",
        )
    return role


def _juniper_root_password_hash(reply: str) -> str:
    """Extract the live Junos root hash without exposing it outside backend."""
    try:
        root = safe_fromstring(reply)
    except (ET.ParseError, TypeError) as exc:
        raise ValueError("The device returned an unreadable root authentication response") from exc

    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "encrypted-password":
            continue
        encrypted_password = (element.text or "").strip()
        if encrypted_password:
            return encrypted_password
    raise ValueError("The device did not return its current root password hash")


def _device_rejection_message(reply: str, vendor: str, command: str) -> str:
    normalized = normalize(vendor, command, reply)
    messages = [
        item.get("message")
        for item in normalized.get("errors", [])
        if isinstance(item, dict) and item.get("message")
    ] if isinstance(normalized, dict) else []
    if not messages:
        try:
            root = safe_fromstring(reply)
            messages = [
                (element.text or "").strip()
                for element in root.iter()
                if element.tag.rsplit("}", 1)[-1] == "message" and (element.text or "").strip()
            ]
        except (ET.ParseError, TypeError):
            messages = []
    return "; ".join(dict.fromkeys(messages)) or "The device rejected the factory reset command"


def _cisco_factory_reset_inconsistent_reply(reply: str) -> bool:
    """IOS XE can start factory reset, then return this known false-negative."""
    try:
        normalized = normalize("cisco", "factory_reset", reply)
    except (ET.ParseError, TypeError, ValueError):
        return False
    errors = normalized.get("errors", []) if isinstance(normalized, dict) else []
    return any(
        isinstance(item, dict)
        and (item.get("tag") or "").lower() == "invalid-value"
        and "inconsistent value" in (item.get("message") or "").lower()
        for item in errors
    )


# Phase 9: ตรวจสอบสิทธิ์เฉพาะ Site Owner สำหรับ Reset Device Identity
# (ไม่มี role Site Admin ในระบบ; unauthorized หรือ device ไม่มี -> 404 เหมือนกัน; member -> 403)
async def _require_site_owner_for_device(
    session: AsyncSession,
    dev_id: str,
    usr_id: str,
) -> Device_Information:
    device = await get_device(session, dev_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    role = await get_effective_role(session, usr_id, device.site_id)
    if role == "unauthorized":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the Site Owner can reset device identity",
        )
    return device


# (dynamic feature ขั้นที่ 4) กรองคำสั่งตามความสามารถจริงของอุปกรณ์ - ดู backend/capability_service.py
# สวิตช์ค่าเริ่มต้นปิด: /commands และการสั่งงานทำงานเหมือนเดิมทุกอย่าง แต่ GET /capability ยังบอกได้ว่า
# ถ้าเปิดจะซ่อนอะไร ใช้ตรวจโปรไฟล์กับระบบจริงก่อนให้ผู้ใช้เห็นผล
# เปิดด้วย CAPABILITY_FILTER_ENABLED=true ใน callmemanage.conf แล้ว restart backend (อ่านค่าครั้งเดียวแล้ว cache)
@lru_cache(maxsize=1)
def _capability_filter_enabled() -> bool:
    try:
        return bool(load_environment().CAPABILITY_FILTER_ENABLED)
    except Exception:
        return False

# CM-10: commit failures carry the device's whole rpc-reply (see conn_socket send_payload /
# send_transaction). Show the user only the device's <error-message>; when there is none,
# never fall back to the raw reply - it can contain configuration from the candidate.
_DEVICE_REJECTED_FALLBACK = "The device rejected the change without an error message"


def _device_rejection_reason(exc: BaseException) -> str:
    match = re.search(r"<error-message>\s*(.*?)\s*</error-message>", str(exc), re.DOTALL)
    reason = match.group(1).strip() if match else ""
    return reason or _DEVICE_REJECTED_FALLBACK


# อ่านโปรไฟล์แบบไม่ทำให้ endpoint ล้ม - อ่านไม่ได้ถือว่ายังไม่รู้ ซึ่ง resolver จะไม่ซ่อนอะไร
async def _load_capability_profile(session: AsyncSession, dev_id: str) -> dict | None:
    try:
        return await get_capability_profile(session, dev_id)
    except Exception as exc:
        print(f"[!] [capability] อ่านโปรไฟล์ของ {dev_id} ไม่ได้: {exc}")
        await session.rollback()
        return None

# ข้อความปฏิเสธถ้ามีคำสั่งเขียนที่อุปกรณ์ทำไม่ได้ - คำสั่งอ่าน (get_*) ไม่ถูกปฏิเสธและไม่ต้องอ่านโปรไฟล์
# เพราะหลายหน้าเรียกคำสั่งอ่านของฟีเจอร์อื่นประกอบ · commands เป็นคู่ (คำสั่ง, พารามิเตอร์) เพื่อตรวจค่าที่ถูกห้าม
# เช่น create_security_tunnel ที่ tunnel_type=ipsec บนอุปกรณ์ที่ทำได้แค่ GRE
async def _capability_block_detail(
    session: AsyncSession, device: Device_Information, commands: list[tuple[str, dict]]
) -> str | None:
    if not _capability_filter_enabled():
        return None
    writes = [(command, parameters) for command, parameters in commands if not command.startswith("get_")]
    if not writes:
        return None
    profile = await _load_capability_profile(session, device.dev_id)
    for command, parameters in writes:
        reason = blocked_reason(device.dev_vendor, profile, command, parameters)
        if reason:
            return f"This device does not support command '{command}' ({reason})"
    return None

# แสดงรายการอุปกรณ์ทั้งหมดใน site แบบ keyset pagination (ไม่มีเลขหน้า/total)
# after_dev_id = cursor จาก next_cursor ของชุดก่อนหน้า (ไม่ส่ง = ขอชุดแรกสุด)
@router.get("/", response_model=DeviceListPage)
async def list_my_devices(
    site_id: str,
    after_dev_id: str | None = None,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    site_role = await _require_site_access(session, site_id, current_user.usr_id)
    # ดึงรายการอุปกรณ์ 1 ชุด (กรอง site_id ที่ระดับ SQL แล้ว) มาเกิน 1 ตัวเพื่อเช็คว่ามีต่อไหม
    devices = await list_devices_for_user(
        session,
        current_user.usr_id,
        site_id=site_id,                # (add on bug 7)
        after_dev_id=after_dev_id,      # (add on bug 7)
        limit=DEVICE_PAGE_SIZE,
    )

    has_next = len(devices) > DEVICE_PAGE_SIZE  # คืนค่า true/false ว่ามีข้อมูลให้โหลดต่อไหม (add on bug 7)
    devices = devices[:DEVICE_PAGE_SIZE]  # ตัดตัวที่ขอเกินมาทิ้ง ไม่ส่งออกไป (add on bug 7)

    # นำ devices มา loop validate ผ่าน schema DeviceSummary ก่อน
    # ตรวจสอบสถานะอุปกรณ์ว่าออนไลน์จริงไหม ถ้าไม่ให้อัปเดตเป็น offline (ยังไม่ได้ใช้จริง เพราะไปใช้ redis เก็บสถานะแทน)
    expirations = await get_pending_expirations_by_device_ids(session, [device.dev_id for device in devices])
    now = generate_timestamp()
    summaries = []
    for device in devices:
        expires_at = expirations.get(device.dev_id)
        summaries.append(
            DeviceSummary.model_validate(device, from_attributes=True).model_copy(
                update={
                    "dev_status": _live_status(device.dev_status, device.dev_id),
                    "enrollment_expires_at": expires_at,
                    "enrollment_expired": bool(expires_at and expires_at <= now),
                }
            )
        )

    return DeviceListPage(
        items=summaries,
        next_cursor=devices[-1].dev_id if has_next else None,
        has_next=has_next,
        site_role=site_role,
    )

# ฟังก์ชั่นสำหรับลบอุปกรณ์ตามที่เลือก
@router.delete("/{dev_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_my_device(
    dev_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    # ตรวจสอบสิทธิผู้ใช้ก่อนว่ามีสิทธิไหม
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)
    await _require_site_manage(session, device.site_id, current_user.usr_id)

    # ตรวจผ่านสิทธิผ่านแล้วก็ลบ
    await delete_device_full(session, dev_id)
    audit_security_event("device.delete", "SUCCEEDED", request=http_request,
                         actor_id=current_user.usr_id, dev_id=dev_id, site_id=device.site_id)

# ขอข้อมูล
@router.get("/{dev_id}", response_model=DeviceRead)
async def get_my_device(
    dev_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # ตรวจสอบสิทธิในการกระทำ
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)

    # เปลี่ยนปุ่มจุดแดงให้หายไปหลังจากการเปิดครั้งแรก
    if not device.dev_viewed:
        device.dev_viewed = True
        session.add(device)
        await session.commit()
        await session.refresh(device)

    return DeviceRead.model_validate(device, from_attributes=True).model_copy(
        update={"dev_status": _live_status(device.dev_status, device.dev_id)}
    )


@router.get("/{dev_id}/stats")
async def get_device_stats(
    dev_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # ตรวจสอบสิทธิในการส่งข้อมูล
    await _get_authorized_device(session, dev_id, current_user.usr_id)

    # อ่านจาก Redis (device:stats:<dev_id>, TTL 15s) 
    stats = None
    try:
        cached = await get_redis().get(f"device:stats:{dev_id}")
        if cached:
            stats = json.loads(cached)
    except Exception:
        stats = None

    # (bug 55) fallback มาที่ in-memory ได้ **แต่ต้องเช็คอายุก่อน**
    #
    # เดิมอ่าน callhome_service.stats.get(dev_id) ตรง ๆ ซึ่งไม่มี TTL เลย (ล้างเฉพาะ
    # ตอน session ปิด) ค่าเก่าจึงค้างไม่มีกำหนดระหว่างที่อุปกรณ์ไม่ตอบ - หน้าเว็บโชว์
    # CPU/RAM ของเมื่อ 14 นาทีที่แล้วเป็นค่าปัจจุบันโดยไม่มีอะไรบอกผู้ใช้
    #
    # ที่แสบคือ Redis TTL 15 วิ ถูกตั้งไว้ด้วยเจตนา "ไม่ให้โชว์ค่าเก่าค้างไม่มีกำหนด"
    # พอดี แต่ fallback บรรทัดถัดมาล้มเจตนานั้นทิ้ง
    #
    # และการแก้ bug 53 (backoff ถอยห่างได้ถึง 300 วิ) ยิ่งทำให้ Redis ว่างบ่อยขึ้น =
    # ตกมาใช้ fallback บ่อยขึ้น ปัญหานี้จึงโผล่ถี่กว่าเดิมถ้าไม่แก้
    stats_age = None
    if stats is None:
        stats, stats_age = callhome_service.fresh_stats(dev_id)

    # (bug 55) คืนสุขภาพจริง 3 สถานะ แทนที่จะบอกแค่ต่อ/ไม่ต่อ - ให้หน้าเว็บบอกผู้ใช้
    # ได้ตรง ๆ ว่า "ต่ออยู่แต่ไม่ตอบ" ซึ่งเดิมไม่มีทางแสดงได้เลย
    health = callhome_service.device_health(dev_id)
    return {
        "connected": health["connected"],
        "responsive": health["responsive"],
        "failed_polls": health["failed_polls"],
        # อายุของข้อมูลที่ "เก่าเกินจะโชว์" - ให้หน้าเว็บบอกได้ว่าล่าสุดเมื่อกี่วินาทีที่แล้ว
        "stale_age_seconds": round(stats_age) if (stats is None and stats_age is not None) else None,
        "stats": stats,
    }

# ส่งข้อมูลเพื่อบอกสถานะว่าออนไลน์อยู่
@router.post("/{dev_id}/presence/ping")
async def ping_device_presence(
    dev_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # ตรวจสอบสิทธิเข้าถึง
    await _get_authorized_device(session, dev_id, current_user.usr_id)

    # ส่งข้อมูลไปบันทึกชั่วคราวไว้ว่าออนไลน์อยู่
    await touch_presence(dev_id, current_user.usr_id, current_user.usr_name)
    return {
        "users": await list_present_users(dev_id),
        "current_user_name": current_user.usr_name
    }


def _access_read(entry, usr_name: str | None) -> DeviceAccessRead:
    return DeviceAccessRead(
        acc_id=entry.acc_id,
        acc_session_id=entry.acc_session_id,
        acc_date=entry.acc_date,
        acc_lastseen=entry.acc_lastseen,
        acc_dev_id=entry.acc_dev_id,
        acc_usr_id=entry.acc_usr_id,
        usr_name=usr_name,
    )


# Access-session API แยกจาก presence เดิมโดยตั้งใจ: backend พร้อมก่อน แต่ browser
# รุ่นปัจจุบันยังเรียก /presence/ping ได้เหมือนเดิมทุกอย่าง จนกว่า frontend จะสร้าง
# UUID หนึ่งครั้งตอนเปิด Device Detail แล้วเปลี่ยนมาเรียกสอง endpoint ด้านล่าง
@router.post(
    "/{dev_id}/access-sessions",
    response_model=DeviceAccessRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_device_access_session(
    dev_id: str,
    body: DeviceAccessSessionStart,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # start_access_session() commits. Depending on how this User ORM instance
    # entered the session, that commit may expire its attributes; reading them
    # afterwards can trigger synchronous lazy I/O and MissingGreenlet. Snapshot
    # every scalar needed by the response before the first database write.
    usr_id = current_user.usr_id
    usr_name = current_user.usr_name
    await _get_authorized_device(session, dev_id, usr_id)
    try:
        entry = await start_access_session(
            session,
            session_id=str(body.session_id),
            dev_id=dev_id,
            usr_id=usr_id,
        )
    except AccessSessionConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return _access_read(entry, usr_name)


@router.post(
    "/{dev_id}/access-sessions/{session_id}/heartbeat",
    response_model=DeviceAccessRead,
)
async def heartbeat_device_access_session(
    dev_id: str,
    session_id: UUID,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # touch_access_session() also commits, so use the same pre-commit snapshot
    # rule as session creation instead of touching an expired User afterwards.
    usr_id = current_user.usr_id
    usr_name = current_user.usr_name
    await _get_authorized_device(session, dev_id, usr_id)
    entry = await touch_access_session(
        session,
        session_id=str(session_id),
        dev_id=dev_id,
        usr_id=usr_id,
    )
    if entry is None:
        # ไม่บอกว่า UUID นี้เป็นของ user/device อื่นหรือไม่มีจริง เพื่อไม่เปิดเผย
        # access session ข้ามสิทธิ์
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access session not found")
    return _access_read(entry, usr_name)


@router.get("/{dev_id}/access-log", response_model=DeviceAccessListPage)
async def get_device_access_log(
    dev_id: str,
    response: Response,
    after_acc_id: str | None = None,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # This is the shared usage log of this device.  Every Site role that can
    # access the device may read it; _get_authorized_device still prevents any
    # user outside the Site from learning that the device/log exists.
    await _get_authorized_device(session, dev_id, current_user.usr_id)
    response.headers["Cache-Control"] = "no-store"

    try:
        entries = await list_access_sessions_by_device(
            session,
            dev_id=dev_id,
            after_acc_id=after_acc_id,
            limit=ACCESS_LOG_PAGE_SIZE,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    has_next = len(entries) > ACCESS_LOG_PAGE_SIZE
    entries = entries[:ACCESS_LOG_PAGE_SIZE]
    user_ids = {entry.acc_usr_id for entry in entries if entry.acc_usr_id}
    user_names: dict[str, str] = {}
    if user_ids:
        result = await session.exec(
            select(User_Table.usr_id, User_Table.usr_name).where(User_Table.usr_id.in_(user_ids))
        )
        user_names = {usr_id: usr_name for usr_id, usr_name in result.all()}

    return DeviceAccessListPage(
        items=[_access_read(entry, user_names.get(entry.acc_usr_id)) for entry in entries],
        next_cursor=entries[-1].acc_id if has_next else None,
        has_next=has_next,
    )


# ยี่ห้อที่ดึง running config เป็นรูปแบบของอุปกรณ์ได้ (ดู get_running_config_cli)
NATIVE_CONFIG_VENDORS = frozenset({"cisco", "juniper"})


@router.post(
    "/{dev_id}/running-config-snapshots",
    response_model=RunningConfigSnapshotCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(running_config_snapshot_rate_limiter)],
)
async def create_running_config_snapshot(
    dev_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Read running config once, sanitize it, and cache it for 15 minutes.

    This intentionally bypasses Device History because it is a read-only
    snapshot, and it has a separate rate-limit so it cannot consume the quota
    used by normal configuration commands.
    """
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)
    if dev_id not in callhome_service.sessions:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This device is not currently connected (call-home session is closed)",
        )

    try:
        payload = build_payload(device.dev_vendor, "get_running_config", {})
        native_text = None
        native_redacted_count = 0
        native_error = None
        async with DeviceLock(dev_id):
            reply = await callhome_service.send_payload(dev_id, payload, timeout=60)
            # config รูปแบบของอุปกรณ์ (พร้อมวางกลับลงอุปกรณ์) - Cisco/Juniper เท่านั้น
            # (Huawei ไม่มี RPC ส่ง config เป็น CLI ผ่าน NETCONF) อ่านใน DeviceLock เดียวกับ
            # XML ด้านบน = snapshot เดียวกัน · best-effort: อ่านไม่ได้ก็ยังแสดงแบบ structured
            # ได้ตามเดิม ค่าลับถูกปิดก่อนเก็บลง Redis เสมอ (ไม่ถึง browser)
            if device.dev_vendor in NATIVE_CONFIG_VENDORS:
                try:
                    native_payload = module_for_vendor(device.dev_vendor).get_running_config_cli()
                    native_reply = await callhome_service.send_payload(dev_id, native_payload, timeout=60)
                    native_text, native_redacted_count = redact_native_configuration(
                        device.dev_vendor,
                        extract_native_configuration_text(device.dev_vendor, native_reply),
                    )
                except (ValueError, SyntaxError) as exc:
                    native_error = str(exc) or "The device could not return its configuration in device format"
        normalized = normalize(device.dev_vendor, "get_running_config", reply)
        if normalized.get("ok") is False:
            messages = [
                item.get("message")
                for item in normalized.get("errors", [])
                if isinstance(item, dict) and item.get("message")
            ]
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="; ".join(dict.fromkeys(messages)) or "Device rejected the running configuration query",
            )
        sections, redacted_count = extract_configuration_sections(normalized)
        snapshot = await store_running_config_snapshot(
            usr_id=current_user.usr_id,
            dev_id=dev_id,
            dev_name=device.dev_name,
            vendor=device.dev_vendor,
            sections=sections,
            redacted_count=redacted_count,
            native_text=native_text,
            native_redacted_count=native_redacted_count,
            native_error=native_error,
        )
    except HTTPException:
        raise
    except DeviceLockBusy as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ConnectionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except NetconfDesync as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The NETCONF session is still synchronizing. Please wait and try again: {exc}",
        )
    except (asyncssh.misc.ConnectionLost, asyncio.TimeoutError, NetconfDead) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"The device did not return its running configuration: {exc}",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    except (RuntimeError, RedisError):
        # Redis/config service details may contain deployment information. Keep
        # the browser-facing error useful without returning internals.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The temporary configuration viewer is unavailable. Please try again shortly.",
        )

    return RunningConfigSnapshotCreated(
        snapshot_id=snapshot["snapshot_id"],
        dev_id=snapshot["dev_id"],
        expires_at=snapshot["expires_at"],
    )


@router.get(
    "/{dev_id}/running-config-snapshots/{snapshot_id}",
    response_model=RunningConfigSnapshotRead,
)
async def read_running_config_snapshot(
    dev_id: str,
    snapshot_id: str,
    response: Response,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_authorized_device(session, dev_id, current_user.usr_id)
    response.headers["Cache-Control"] = "no-store"
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", snapshot_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Configuration snapshot not found")

    try:
        snapshot = await get_running_config_snapshot(snapshot_id)
    except (RuntimeError, RedisError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The temporary configuration viewer is unavailable. Please try again shortly.",
        )
    if snapshot is None:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This running configuration snapshot has expired. Load it again from Device Info.",
        )
    # Snapshot URLs are deliberately creator-only. Return 404 for a mismatch
    # so the endpoint cannot be used to discover another user's snapshot.
    if snapshot.get("dev_id") != dev_id or snapshot.get("usr_id") != current_user.usr_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Configuration snapshot not found")
    return public_snapshot(snapshot)


@router.post(
    "/{dev_id}/factory-reset",
    response_model=DeviceFactoryResetResponse,
    dependencies=[Depends(factory_reset_rate_limiter)],
)
async def factory_reset_device(
    dev_id: str,
    body: DeviceFactoryResetRequest,
    response: Response,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    http_request: Request = None,
):
    """Run the safe, vendor-specific factory-reset lifecycle."""
    # CM-10: every attempt is audited with its real outcome - including denied and failed
    # ones - without the request body (Juniper root password) or any device reply.
    outcome = "ERROR"
    try:
        result = await _run_factory_reset(dev_id, body, response, current_user, session)
        outcome = result.status.upper()
        return result
    except HTTPException as exc:
        outcome = f"FAILED_{exc.status_code}"
        raise
    finally:
        audit_security_event("device.factory_reset", outcome, request=http_request,
                             actor_id=current_user.usr_id, dev_id=dev_id)


async def _run_factory_reset(
    dev_id: str,
    body: DeviceFactoryResetRequest,
    response: Response,
    current_user: User_Table,
    session: AsyncSession,
):
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)
    vendor = device.dev_vendor
    if vendor not in {"cisco", "juniper", "huawei"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Factory reset is not supported for this vendor")
    if dev_id not in callhome_service.sessions:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This device is not currently connected (call-home session is closed)",
        )

    module = module_for_vendor(vendor)
    response.headers["Cache-Control"] = "no-store"

    try:
        async with DeviceLock(dev_id):
            if vendor == "juniper":
                if body.root_password is None or not body.root_password.get_secret_value():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="The current Juniper root password is required",
                    )

                authentication_reply = await callhome_service.send_payload(
                    dev_id,
                    module.get_root_authentication_for_factory_reset(),
                )
                if reply_rejected(authentication_reply):
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=_device_rejection_message(
                            authentication_reply, vendor, "get_root_authentication_for_factory_reset"
                        ),
                    )
                try:
                    encrypted_password = _juniper_root_password_hash(authentication_reply)
                    password_matches = sha512_crypt.verify(
                        body.root_password.get_secret_value(), encrypted_password
                    )
                except (ValueError, TypeError) as exc:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="The device's current root password hash cannot be verified safely",
                    ) from exc
                if not password_matches:
                    # 401 would make api_client sign the web operator out.
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Root password is incorrect",
                    )

                # The root hash is part of the complete override. Junos then
                # validates and commits one candidate change; no intermediate
                # candidate can exist without a root password.
                payloads = [module.factory_reset(encrypted_password)]
                failed_index, reset_reply = await callhome_service.send_transaction(dev_id, payloads)
                if failed_index >= 0 or reply_rejected(reset_reply):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=_device_rejection_message(reset_reply, vendor, "factory_reset"),
                    )
                result_status = "completed"
                message = "Factory reset completed. The Juniper device was not rebooted."

            elif vendor == "huawei":
                delete_reply = await callhome_service.send_payload(dev_id, module.factory_reset())
                if reply_rejected(delete_reply):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=_device_rejection_message(delete_reply, vendor, "factory_reset"),
                    )
                try:
                    reboot_reply = await callhome_service.send_payload(
                        dev_id, module.factory_reset_reboot()
                    )
                    if reply_rejected(reboot_reply):
                        await create_history(
                            session,
                            dev_id,
                            current_user.usr_id,
                            "factory_reset",
                            json.dumps({"vendor": vendor, "outcome": "startup-deleted-reboot-rejected"}),
                        )
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=(
                                "Startup configuration was deleted, but the reboot was rejected. "
                                "Reboot the device manually to complete the factory reset."
                            ),
                        )
                except (asyncssh.misc.ConnectionLost, asyncio.TimeoutError):
                    # A reboot commonly closes NETCONF before returning a reply.
                    pass
                except ConnectionError as exc:
                    if str(exc) != "Channel closed":
                        raise
                result_status = "accepted"
                message = "Factory reset was accepted. The Huawei device is rebooting."

            else:  # Cisco IOS XE
                try:
                    reset_reply = await callhome_service.send_payload(dev_id, module.factory_reset())
                    if reply_rejected(reset_reply):
                        if not _cisco_factory_reset_inconsistent_reply(reset_reply):
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=_device_rejection_message(reset_reply, vendor, "factory_reset"),
                            )
                except (asyncssh.misc.ConnectionLost, asyncio.TimeoutError):
                    # IOS XE may erase and reboot before emitting an rpc-reply.
                    pass
                except ConnectionError as exc:
                    if str(exc) != "Channel closed":
                        raise
                result_status = "accepted"
                message = "Factory reset was accepted. The Cisco device is rebooting."

            await create_history(
                session,
                dev_id,
                current_user.usr_id,
                "factory_reset",
                json.dumps({"vendor": vendor, "outcome": result_status}),
            )

        # Factory defaults remove Call Home configuration. Close any surviving
        # controller-side session so the UI cannot incorrectly keep it online.
        await callhome_service.close_session(dev_id, reason="Factory reset completed or accepted")

    except HTTPException:
        raise
    except DeviceLockBusy as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ConnectionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except NetconfDesync as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The NETCONF session is still synchronizing. Please wait and try again: {exc}",
        )
    except (asyncssh.misc.ConnectionLost, asyncio.TimeoutError, NetconfDead) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"The device did not acknowledge the factory reset safely: {exc}",
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The device rejected the factory reset commit") from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if result_status == "accepted":
        response.status_code = status.HTTP_202_ACCEPTED
    return DeviceFactoryResetResponse(status=result_status, vendor=vendor, message=message)


# ดึงรายการคำสั่งทั้งหมดที่อุปกรณ์สามารถทำงานได้
@router.get("/{dev_id}/commands")
async def get_device_commands(
    dev_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)

    # ส่งออกรายการคำสั่ง
    commands = functions_for_vendor(device.dev_vendor)
    if not _capability_filter_enabled():
        return commands
    profile = await _load_capability_profile(session, dev_id)
    return filter_commands(device.dev_vendor, profile, commands)

# (dynamic feature ขั้นที่ 4) สรุปความสามารถจากโปรไฟล์ที่ตรวจไว้ตอน call-home - อ่านจาก DB จึงตอบได้แม้
# อุปกรณ์ offline และตอบผลของ resolver เสมอแม้ปิดสวิตช์ (enforced บอกว่ากรองจริงอยู่หรือไม่)
# ไม่ส่งรายชื่อ namespace ออกไป เพราะใหญ่และหน้าเว็บไม่ต้องใช้
@router.get("/{dev_id}/capability")
async def get_device_capability(
    dev_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)
    profile = await _load_capability_profile(session, dev_id)
    decision = resolve(device.dev_vendor, profile)

    layers = {}
    for layer in ("schema", "license", "model"):
        data = (profile or {}).get(layer)
        if isinstance(data, dict):
            layers[layer] = {
                key: data[key]
                for key in ("status", "message", "source", "cached", "module_count", "level", "addon", "value")
                if data.get(key) is not None
            }

    return {
        "dev_id": dev_id,
        "vendor": device.dev_vendor,
        "enforced": _capability_filter_enabled(),
        "checked": profile is not None,
        "probing": callhome_service.capability_probe_running(dev_id),
        "status": (profile or {}).get("status"),
        "platform_role": decision.get("platform_role"),
        "checked_at": (profile or {}).get("checked_at"),
        "layers": layers,
        "skipped_layers": decision["skipped_layers"],
        "hidden": [
            {"command": name, "kind": "read" if name.startswith("get_") else "write", "reasons": reasons}
            for name, reasons in sorted(decision["hidden"].items())
        ],
        "hidden_options": decision["hidden_options"],
    }

# (dynamic feature ขั้นที่ 4) ตรวจความสามารถใหม่ทันทีโดยไม่ใช้ schema จาก cache - งานรันเบื้องหลัง
# ตอบกลับทันที หน้าเว็บดู GET /capability จนกว่า probing เป็น false
@router.post(
    "/{dev_id}/capability/refresh",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(capability_refresh_rate_limiter)],
)
async def refresh_device_capability(
    dev_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)
    await _require_site_manage(session, device.site_id, current_user.usr_id)

    state = callhome_service.refresh_capability(dev_id)
    if state == "offline":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This device is not currently connected (call-home session is closed)",
        )
    return {"dev_id": dev_id, "state": state}

# แสดงประวัติการสั่งการอุปกรณ์ทั้งหมด
@router.get("/{dev_id}/history", response_model=DeviceHistoryListPage)
async def get_device_history(
    dev_id: str,
    after_his_id: str | None = None,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_authorized_device(session, dev_id, current_user.usr_id)

    history = await list_history_by_device(
        session, 
        dev_id,
        after_his_id=after_his_id,
        limit=HISTORY_PAGE_SIZE,
    )
    has_next = len(history) > HISTORY_PAGE_SIZE
    history = history[:HISTORY_PAGE_SIZE]

    # Resolve all actors in one query (not one query per history row).  The
    # foreign key uses SET NULL when an account is deleted, so old audit rows
    # remain readable even when there is no longer a username to display.
    user_ids = {row.his_usr_id for row in history if row.his_usr_id}
    user_names: dict[str, str] = {}
    if user_ids:
        result = await session.exec(
            select(User_Table.usr_id, User_Table.usr_name).where(User_Table.usr_id.in_(user_ids))
        )
        user_names = {usr_id: usr_name for usr_id, usr_name in result.all()}

    items = [
        DeviceHistoryRead(
            his_id=row.his_id,
            his_action=row.his_action,
            his_action_detail=row.his_action_detail,
            his_action_time=row.his_action_time,
            his_dev_id=row.his_dev_id,
            his_usr_id=row.his_usr_id,
            his_usr_name=user_names.get(row.his_usr_id),
        )
        for row in history
    ]

    return DeviceHistoryListPage(
        items=items,
        next_cursor=history[-1].his_id if has_next else None,
        has_next=has_next,
    )

# ดึงรายการ config ที่ตั้งชื่อไว้ใน database ทั้งหมด
# สถานะ "มีการแก้ไขที่ยังไม่ได้ save ลง startup-config" (Cisco/Huawei - ดู
# _note_config_write) · unsaved=None = อ่าน Redis ไม่ได้ (หน้าเว็บแสดงแบบปกติ)
@router.get("/{dev_id}/config-save-status")
async def get_config_save_status(
    dev_id: str,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)
    if device.dev_vendor not in SAVE_CONFIG_VENDORS:
        return {"supported": False, "unsaved": False}
    try:
        unsaved = bool(await get_redis().exists(CONFIG_UNSAVED_KEY.format(dev_id=dev_id)))
    except Exception:
        return {"supported": True, "unsaved": None}
    return {"supported": True, "unsaved": unsaved}


@router.get("/{dev_id}/config-objects", response_model=List[DeviceConfigObjectRead])
async def list_device_config_objects(
    dev_id: str,
    feature: str | None = None,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_authorized_device(session, dev_id, current_user.usr_id)
    objects = await list_config_objects(session, dev_id, feature=feature)
    return [
        DeviceConfigObjectRead(
            cfg_id=obj.cfg_id,
            cfg_feature=obj.cfg_feature,
            cfg_name=obj.cfg_name,
            cfg_params=json.loads(obj.cfg_params),
            cfg_created_date=obj.cfg_created_date,
            cfg_dev_id=obj.cfg_dev_id,
            cfg_created_by_id=obj.cfg_created_by_id,
        )
        for obj in objects
    ]


# # |====================== ลบได้ ======================|
# @router.post("/{dev_id}/config-objects/reconcile-nat")
# async def reconcile_nat_config_objects(
#     dev_id: str,
#     current_user: User_Table = Depends(get_current_user),
#     session: AsyncSession = Depends(get_session),
# ):
#     # ปุ่ม "นำเข้า NAT ที่มีอยู่แล้ว" บนหน้า NAT - ดึงค่าจากอุปกรณ์จริงมา track
#     # เพิ่มใน DB (ไม่ทับของเดิม) กันเคสอุปกรณ์ตั้งค่าไว้ก่อนแล้วไม่ขึ้นในตาราง
#     device = await _get_authorized_device(session, dev_id, current_user.usr_id)
#     if dev_id not in callhome_service.sessions:
#         raise HTTPException(
#             status_code=status.HTTP_409_CONFLICT,
#             detail="อุปกรณ์นี้ไม่ได้เชื่อมต่ออยู่ตอนนี้ (call-home session ปิดไปแล้ว)",
#         )
#     try:
#         # ดึงข้อมูลจากอุปกรณ์หลายคำสั่งติดกัน (get_nat_information/get_acl_information/
#         # get_nat_pool_information ผ่าน _get_normalized_data) - ล็อกทั้งก้อนกันชน
#         # กับคำสั่ง NETCONF อื่นที่ผู้ใช้อาจกดพร้อมกันบนอุปกรณ์เดียวกัน (ดู
#         # backend/core/redis_lock.py - เหมือน run_device_command)
#         async with DeviceLock(dev_id):
#             return await _reconcile_nat_objects(session, dev_id, current_user.usr_id, device.dev_vendor)
#     except DeviceLockBusy as exc:
#         raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
#     except ValueError as exc:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
#     except ConnectionError as exc:
#         raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
# # |=====================================================|


@router.post("/{dev_id}/ping-test", response_model=DeviceCommandResult)
async def run_ping_test_route(
    dev_id: str,
    body: PingTestRequest,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)
    # F1: ping-test เขียน config ชั่วคราวลงอุปกรณ์ (SLA entry) จึงต้องเป็น Owner/Admin ของ Site เท่านั้น
    # เหมือน endpoint อื่นที่แก้ค่าอุปกรณ์ - เดิมสมาชิก Site สิทธิ์ใดก็เรียกได้
    await _require_site_manage(session, device.site_id, current_user.usr_id)

    # ตรวจสอบยี่ห้อของอุปกรณ์
    if device.dev_vendor not in ("cisco", "juniper"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ping test is not supported for vendor {device.dev_vendor}",
        )

    # ตรวจสอบว่า session netconf ยังอยู่ไหม
    if dev_id not in callhome_service.sessions:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This device is not currently connected (call-home session is closed)",
        )

    # เรียกใช้เครื่องมือ ping ตามยี่ห้อ
    if device.dev_vendor == "juniper":
        from vendor_translators.juniper_junos import run_ping_test
    else:
        from vendor_translators.cisco_iosxe import run_ping_test

    # คำสั่งในการส่ง ping
    async def send(payload: str) -> str:
        return await callhome_service.send_payload(dev_id, payload)

    try:
        # ส่งคำสั่ง ping และล็อก session ไม่ให้ส่งคำสั่งอื่นซ้ำ
        async with DeviceLock(dev_id):
            raw_result = await run_ping_test(send, body.destination, source_interface=body.source_interface)
    # ดัก error คำสั่งชน
    except DeviceLockBusy as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    # ดัก error connection มีปัญหาตั้งแต่ต้น
    except ConnectionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    # ดัก error connection หายระหว่างทาง
    except (asyncssh.misc.ConnectionLost, asyncio.TimeoutError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Connection lost during ping test: {exc}",
        )
    # ส่งผลลัพธ์การ ping
    return DeviceCommandResult(
        command="ping_test",
        normalized=True,
        result=normalize(device.dev_vendor, "get_ping_result", raw_result),
    )

# ยิงคำสั่งไปยังอุปกรณ์ โดยรับค่าไปแปลงด้วยตัวแปลภาษา
# (ปัญหาที่ 2 ขั้น B0 ใน planning/transaction_review.md) ตรวจพารามิเตอร์ของคำสั่ง
# โดย "ไม่ส่งอะไรไปที่อุปกรณ์เลย"
#
# มีไว้ให้ flow ที่ใช้แพทเทิร์น "ลบของเดิมทิ้งก่อนแล้วค่อยสร้างใหม่" (17 จุดใน 13 ไฟล์)
# เรียกตรวจค่าที่ผู้ใช้กรอกก่อนจะเริ่มลบ - เดิมถ้าค่าผิด ระบบจะลบของเดิมสำเร็จไปแล้ว
# ทั้งหมดก่อนจะมาโดนปฏิเสธที่ขั้นสร้าง ผลคือของเดิมหายโดยไม่มีอะไรมาแทน เคสที่แย่สุด
# คือแก้ไข IPsec profile ที่รื้อ 6 object ก่อนสร้างใหม่ = VPN ที่ใช้งานอยู่ล่ม
#
# ความเสี่ยงนี้เพิ่งสูงขึ้นจากการแก้ BUG-15 ที่ทำให้ create_security_profile validate
# เข้มขึ้น - fail เร็วขึ้นก็จริง แต่ "fail หลังจากลบไปแล้ว"
#
# ตรวจด้วย build_payload() ตัวเดียวกับที่ run_device_command ใช้จริง จึงการันตีว่า
# ถ้าผ่านที่นี่แล้วจะผ่านตอนสร้างจริงด้วย (ไม่ใช่การเขียนกฎซ้ำอีกชุดฝั่ง frontend
# ซึ่งจะเพี้ยนออกจากกันแน่นอน - บทเรียนเดียวกับ BUG-12/13/14/15)
#
# ไม่เช็ค call-home session เพราะไม่ได้คุยกับอุปกรณ์ - ตรวจได้แม้อุปกรณ์ออฟไลน์
# ยังคง _get_authorized_device ไว้ เพราะต้องรู้ vendor และต้องไม่ให้คนนอกใช้
# endpoint นี้ probe ว่าอุปกรณ์ตัวไหนมีตัวตนบ้าง
# คำสั่งที่สร้าง payload ได้ก็ต่อเมื่ออ่าน Running Configuration สดภายใน DeviceLock แล้ว
# เท่านั้น - ห้ามเรียก build_payload() ล่วงหน้าเหมือนคำสั่งอื่น (เคยพังจริง: ปุ่มเลื่อน
# Policy ส่งแค่ direction=up/down ตัว builder จึงโยน "Either reference_config ..." ออกไป
# เป็น 400 ก่อนถึงโค้ดอ่าน config ในบล็อก DeviceLock เลย ปุ่มจึงใช้งานไม่ได้สักครั้ง)
# ตรวจได้เฉพาะ syntax ก่อนแตะอุปกรณ์ ส่วนตำแหน่ง/revision ตรวจกับ config จริงใน lock
DEFERRED_PAYLOAD_COMMANDS = {
    ("juniper", "move_security_policy"),
    ("juniper", "move_security_policy_zone"),
}

# คำสั่งที่ build_payload() สร้าง syntax ได้ล้วนๆ โดยไม่ต้องอ่านอุปกรณ์ (จึงยังผ่าน
# /validate ตามปกติ - ต่างจาก DEFERRED_PAYLOAD_COMMANDS ด้านบน) แต่ "การเขียนจริง"
# ต้องอ่าน get_firewall_information สดภายใน DeviceLock ก่อนเสมอ (ดู
# vendor_translators/cisco_zbf.py) - ใช้แค่กัน /transaction (ซึ่งสร้าง payload
# ล่วงหน้าก่อนเข้า DeviceLock เดียวเลยไม่มี branch คอยอ่านสดให้) เป็นช่องทางข้าม
# revision/reference/shared-object/ACL-in-use guard พวกนี้ไปได้
CISCO_ZBF_LIVE_GUARD_COMMANDS = {
    ("cisco", "create_firewall_policy"),
    ("cisco", "remove_firewall_policy"),
    ("cisco", "remove_acl"),
    ("cisco", "remove_acl_rule"),
    ("cisco", "replace_acl"),
    ("cisco", "set_acl_rule"),
    ("cisco", "create_acl_rule"),
    ("cisco", "replace_acl_rule"),
    ("cisco", "create_acl"),
}


def _deferred_command_error(exc: ValueError) -> HTTPException:
    detail = str(exc)
    code = detail.split(":", 1)[0].strip() if ":" in detail else "INVALID_REQUEST"
    message = detail.split(":", 1)[1].strip() if ":" in detail else detail
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"code": code, "message": message})


def _validate_deferred_command(vendor: str, command: str, parameters: dict) -> dict:
    from vendor_translators.juniper_security_policy import (
        validate_juniper_security_policy_move_request,
        validate_juniper_security_policy_zone_move_request,
    )

    validator = {
        "move_security_policy": validate_juniper_security_policy_move_request,
        "move_security_policy_zone": validate_juniper_security_policy_zone_move_request,
    }[command]
    try:
        return validator(parameters)
    except ValueError as exc:
        raise _deferred_command_error(exc)


@router.post(
    "/{dev_id}/command/{command}/validate",
    dependencies=[Depends(device_command_validation_rate_limiter)],
)
async def validate_device_command(
    dev_id: str,
    command: str,
    body: DeviceCommandRequest = Body(default_factory=DeviceCommandRequest),
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)
    if command in LOCAL_USER_WRITE_COMMANDS:
        # ตรวจ/ส่งผ่าน /command เท่านั้น (guard อ่าน user สด + ตัดรหัสผ่านออกจาก error)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Local user commands must be sent through /command",
        )
    # (dynamic feature ขั้นที่ 4) ปฏิเสธคำสั่งเขียนที่อุปกรณ์ทำไม่ได้ก่อนส่ง - ทำงานเฉพาะเมื่อเปิดสวิตช์
    capability_detail = await _capability_block_detail(session, device, [(command, body.parameters)])
    if capability_detail:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=capability_detail)

    if (device.dev_vendor, command) in DEFERRED_PAYLOAD_COMMANDS:
        _validate_deferred_command(device.dev_vendor, command, body.parameters)
        return {"ok": True, "command": command}

    try:
        build_payload(device.dev_vendor, command, body.parameters)
    except ValueError as exc:
        if hasattr(exc, "to_dict"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.to_dict())
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        # pydantic ValidationError จาก @validate_call ไม่ใช่ ValueError ลูกโดยตรง
        # เสมอไป - แปลงเป็น 400 เหมือนกันเพื่อให้ผู้ใช้เห็นว่ากรอกค่าผิด ไม่ใช่ 500
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return {"ok": True, "command": command}


# (C4) ยิงหลายคำสั่งเข้า candidate เดียวแล้ว commit ครั้งเดียว
#
# มีไว้สำหรับงานที่คำสั่งหลังต้องเห็นผลของคำสั่งหน้า ซึ่งทำในคำสั่งเดียวไม่ได้เพราะ
# อุปกรณ์ตรวจ edit-config กับสภาพของ datastore ปลายทางทันที (เคสจริงของ CE12800:
# ต้องคืนพอร์ตเป็น access VLAN 1 ก่อนถึงจะสลับเป็น Layer 3 ได้) ทั้งชุดสำเร็จหรือ
# ไม่เกิดอะไรเลย เพราะ commit ครั้งเดียวปิดท้ายและ discard ทิ้งทั้งชุดเมื่อมีตัวใดล้ม
#
# ประวัติบันทึกแยกแถวตามคำสั่งย่อย เขียนหลัง commit ผ่านแล้วเท่านั้น จึงไม่มีแถวของ
# สิ่งที่ไม่ได้เกิดขึ้นจริงบนอุปกรณ์ (กฎเดียวกับ bug 99)
@router.post(
    "/{dev_id}/transaction",
    response_model=DeviceCommandResult,
    dependencies=[Depends(device_transaction_rate_limiter)],
)
async def run_device_transaction(
    dev_id: str,
    body: DeviceTransactionRequest = Body(default_factory=DeviceTransactionRequest),
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)

    if not body.commands:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No commands in this batch")
    if any((device.dev_vendor, step.command) in DEFERRED_PAYLOAD_COMMANDS for step in body.commands):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy reordering requires reading latest order from device and cannot be used in a batch",
        )
    if any((device.dev_vendor, step.command) in CISCO_ZBF_LIVE_GUARD_COMMANDS for step in body.commands):
        # /transaction สร้าง payload ทุก step ล่วงหน้าก่อนเข้า DeviceLock เดียว (ไม่มี
        # branch คอยอ่าน get_firewall_information สดแทรกระหว่างกลางแบบ /command) จึง
        # ไม่มีทางรัน revision/reference/shared-object/ACL-in-use guard ของคำสั่งกลุ่มนี้
        # ได้ถูกต้อง - ปฏิเสธให้ไปใช้ /command ที่มี guard แทน (ห้ามให้ endpoint นี้เป็น
        # ช่องทางข้าม guard)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This command requires reading latest configuration from device for safety validation and cannot be used in /transaction. Please send individually via /command.",
        )
    if any(step.command in LOCAL_USER_WRITE_COMMANDS for step in body.commands):
        # ต้องอ่าน user สดจากอุปกรณ์ก่อนเขียนและห้ามเก็บรหัสผ่านในประวัติ - /transaction ทำไม่ได้
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Local user commands cannot be used in /transaction. Please send individually via /command.",
        )
    if any(step.command.startswith("get_") for step in body.commands):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch commands only accept configuration-changing commands",
        )
    if dev_id not in callhome_service.sessions:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This device is not currently connected (call-home session is closed)",
        )

    # (dynamic feature ขั้นที่ 4) ปฏิเสธคำสั่งเขียนที่อุปกรณ์ทำไม่ได้ก่อนส่ง - ทำงานเฉพาะเมื่อเปิดสวิตช์
    capability_detail = await _capability_block_detail(
        session, device, [(step.command, step.parameters) for step in body.commands]
    )
    if capability_detail:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=capability_detail)

    # สร้าง payload ให้ครบก่อนส่งสักตัว - ค่าที่กรอกผิดต้องถูกปฏิเสธตั้งแต่ยังไม่แตะอุปกรณ์
    payloads = []
    try:
        for step in body.commands:
            payloads.append(build_payload(device.dev_vendor, step.command, step.parameters))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    try:
        async with DeviceLock(dev_id):
            failed_index, reply = await callhome_service.send_transaction(dev_id, payloads)
    except DeviceLockBusy as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ConnectionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except RuntimeError as exc:
        reason = _device_rejection_reason(exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Device rejected this command batch during commit: {reason}",
        )

    if failed_index >= 0:
        failed = body.commands[failed_index]
        try:
            result = normalize(device.dev_vendor, failed.command, reply)
        except Exception:
            return DeviceCommandResult(command=failed.command, normalized=False, result=reply)
        print(f"[!] {dev_id} ปฏิเสธคำสั่ง '{failed.command}' ในชุด - ยกเลิกทั้งชุด ไม่บันทึกประวัติ")
        return DeviceCommandResult(command=failed.command, normalized=True, result=result)

    for step in body.commands:
        await _track_config_object(session, dev_id, current_user.usr_id, step.command, step.parameters)
        await _untrack_config_object(session, dev_id, step.command, step.parameters)

    # ชุดนี้ใช้ candidate + commit เดียว หรือ Cisco running edit-config เดียว
    # พร้อม rollback-on-error (send_transaction) ประวัติจึงต้องเป็น
    # **1 รายการ** ให้ตรงกับความจริง - เดิมวน create_history ทีละ step ทำให้ผู้ใช้
    # เห็น N แถวซึ่งอ่านแล้วเหมือนยิง N ครั้งแยกกัน แยกไม่ออกเลยจากการยิงทีละคำสั่ง
    # ผ่าน /command จริงๆ (ผู้ใช้ใช้หน้าประวัติเป็นเครื่องมือตรวจว่า atomic จริงไหม
    # การบันทึกแยกแถวจึงทำลายเครื่องมือตรวจสอบนั้นไปเลย)
    #
    # action = คำสั่งแรกของชุด (สื่อเจตนาหลักและยังใช้ filter/อ่านได้เหมือนเดิม)
    # ส่วนรายละเอียดครบทุก step อยู่ใน detail.steps ซึ่ง history.jsx แตกออกมาแสดง
    # เป็น badge + คำอธิบายเรียงแนวตั้งภายในแถวเดียว
    for step in body.commands:
        await _note_config_write(dev_id, device.dev_vendor, step.command)
    await create_history(
        session,
        dev_id=dev_id,
        usr_id=current_user.usr_id,
        action=body.commands[0].command,
        detail=json.dumps(
            {"steps": [{"command": step.command, "parameters": step.parameters} for step in body.commands]},
            ensure_ascii=False,
        ),
    )

    last = body.commands[-1]
    try:
        result = normalize(device.dev_vendor, last.command, reply)
    except Exception:
        return DeviceCommandResult(command=last.command, normalized=False, result=reply)
    return DeviceCommandResult(command=last.command, normalized=True, result=result)


@router.post(
    "/{dev_id}/command/{command}",
    response_model=DeviceCommandResult,
    dependencies=[Depends(device_command_rate_limiter)],
)
async def run_device_command_endpoint(
    dev_id: str,
    command: str,
    body: DeviceCommandRequest = Body(default_factory=DeviceCommandRequest),
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if command not in LOCAL_USER_WRITE_COMMANDS:
        return await run_device_command(dev_id, command, body, current_user, session)

    # User Info: whatever path fails (validation, device rpc-error, commit
    # failure), the plaintext password must not come back to the browser
    secret = body.parameters.get("passwd") if isinstance(body.parameters, dict) else None
    secret = secret if isinstance(secret, str) else None
    try:
        result = await run_device_command(dev_id, command, body, current_user, session)
    except HTTPException as exc:
        raise HTTPException(
            status_code=exc.status_code, detail=_redact_detail(exc.detail, secret), headers=exc.headers,
        ) from None
    if isinstance(result, DeviceCommandResult):
        result.result = _redact_detail(result.result, secret)
    return result


def _redact_detail(value, secret: str | None):
    if isinstance(value, str):
        return redact_secret(value, secret)
    if isinstance(value, dict):
        return {key: _redact_detail(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_detail(item, secret) for item in value]
    return value


# ตัวงานจริงของ POST /{dev_id}/command/{command} (route คือ run_device_command_endpoint
# ด้านบน) - คงชื่อนี้ไว้เพราะเทสต์หลายตัวดึง body ของฟังก์ชันนี้ด้วย AST ตามชื่อ
async def run_device_command(
    dev_id: str,
    command: str,
    body: DeviceCommandRequest,
    current_user: User_Table,
    session: AsyncSession,
):
    device = await _get_authorized_device(session, dev_id, current_user.usr_id)

    # ตรวจสอบว่า netconf connection ไม่หลุด
    if dev_id not in callhome_service.sessions:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This device is not currently connected (call-home session is closed)",
        )

    # (dynamic feature ขั้นที่ 4) ปฏิเสธคำสั่งเขียนที่อุปกรณ์ทำไม่ได้ก่อนส่ง - ทำงานเฉพาะเมื่อเปิดสวิตช์
    capability_detail = await _capability_block_detail(session, device, [(command, body.parameters)])
    if capability_detail:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=capability_detail)

    if command in LOCAL_USER_WRITE_COMMANDS:
        # Same policy as the CLI Generator, enforced here even for direct API calls
        # (Netconf-MGMT, username format, password rules, no extra fields)
        try:
            body.parameters = validate_local_user_request(device.dev_vendor, command, body.parameters)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    deferred_params = None
    if (device.dev_vendor, command) in DEFERRED_PAYLOAD_COMMANDS:
        deferred_params = _validate_deferred_command(device.dev_vendor, command, body.parameters)
        payload = None
    else:
        try:
            payload = build_payload(device.dev_vendor, command, body.parameters)
        except ValueError as exc:
            if hasattr(exc, "to_dict"):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.to_dict())
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # ตั้งไว้เฉพาะตอน command == "get_nat_dashboard" ประมวลผลเสร็จข้างใน DeviceLock
    # แล้ว (2 RPC เล็กแทนที่จะยิงซ้ำผ่าน payload ตัวเดียวด้านล่างเหมือนคำสั่งอื่น)
    precomputed_reply = None
    nat_dashboard_acl_missing = False
    # ตั้งเมื่อ Cisco ตัดช่อง NETCONF ระหว่างคำสั่งเขียน NAT (ดู CISCO_NAT_RECONNECT_WAIT_SECONDS)
    nat_dropped_connection = None
    # connection เดิมที่ต้องรอให้อุปกรณ์ call-home ใหม่แทน ก่อนตอบผู้ใช้ - ตั้งทั้งตอนท่อตาย
    # กลางคำสั่ง (nat_dropped_connection) และตอนได้ reply สำเร็จแล้ว (ดู CISCO_NAT_SESSION_RESET_COMMANDS)
    nat_reconnect_connection = None

    try:
        # อุปกรณ์กำลัง call-home กลับมา (ท่อเดิมเพิ่งตาย) - ต่อคิวรอ session ใหม่ "ก่อน" จับ
        # DeviceLock ไม่งั้น request ที่ตามมาจะได้ 409 busy หลัง 5 วิทั้งที่แค่ต้องรออุปกรณ์
        await callhome_service.wait_for_live_session(dev_id)
        # Redis distributed lock (device:lock:<dev_id>, NX PX 10000) คู่กับ
        # asyncio.Lock ในความจำที่ session["lock"] ใน conn_socket.py คุมอยู่แล้ว
        # (ตัวนั้นยังเป็นตัวหลักที่รับประกันความถูกต้องจริงใน process เดียวนี้ -
        # เสริมชั้นนี้ไว้ล่วงหน้าสำหรับสถาปัตยกรรมในอนาคตที่อาจมีมากกว่า 1 worker/
        # process ยิงเข้า callhome_service เดียวกัน ดู planning/redisPlan.md ข้อ
        # 2.4 และ 3.3) ถ้าอุปกรณ์มีคำสั่งอื่นถือ lock ค้างอยู่ (เช่น request ก่อน
        # หน้ายังไม่ตอบกลับ) ปฏิเสธทันทีด้วย 409 แทนที่จะรอต่อคิว
        async with DeviceLock(dev_id):
            if command in CISCO_NAT_QUARANTINE_COMMANDS and device.dev_vendor == "cisco":
                # (2026-09) ดู CISCO_NAT_QUARANTINE_COMMANDS/conn_socket.py's
                # CISCO_NAT_QUARANTINE_SECONDS - reply ของคำสั่ง NAT ก่อนหน้ายังไม่รู้
                # ผล (timeout/desync) อย่าส่ง payload ใหม่ซ้อนเข้า session เดิม ตอบ
                # สถานะที่ชัดเจนแทนโดยไม่แตะ wire เลย
                quarantine_remaining = callhome_service.cisco_nat_quarantine_remaining(dev_id)
                if quarantine_remaining > 0:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail={
                            "code": "NETCONF_SESSION_RECOVERING",
                            "message": (
                                f"System is still waiting to confirm the previous NAT command's result "
                                f"on this device. No new command was sent - please wait about "
                                f"{int(quarantine_remaining) + 1}s and try again."
                            ),
                        },
                    )
            if command == "get_nat_dashboard" and device.dev_vendor == "cisco":
                # (2026-09) แทนที่ get_nat_dashboard() เดิม (RPC เดียว ขอ native/
                # interface ทั้งก้อน + native/ip/access-list ทั้งก้อน = ทุก ACL บน
                # อุปกรณ์) ด้วย 2 RPC เล็กภายใน DeviceLock เดียวกัน (snapshot เดียว
                # ไม่มี request อื่นแทรกกลางทาง): อ่าน NAT binding + interface context
                # ก่อนเพื่อรู้ชื่อ ACL จริงที่ NAT rule ปัจจุบันอ้างถึง แล้วค่อยอ่าน
                # เฉพาะ ACL ชื่อนั้น (ไม่มี NAT เลย = ข้ามการอ่าน ACL ไปเลย)
                bindings_reply = await callhome_service.send_payload(
                    dev_id, build_payload("cisco", "get_nat_dashboard_bindings", {}),
                    nat_quarantine=True,
                )
                replies = [bindings_reply]
                acl_name = extract_cisco_nat_bound_acl_name(bindings_reply)
                if acl_name:
                    acl_reply = await callhome_service.send_payload(
                        dev_id, build_payload("cisco", "get_nat_dashboard_acl", {"acl_name": acl_name}),
                        nat_quarantine=True,
                    )
                    replies.append(acl_reply)
                    if not cisco_acl_reply_has_name(acl_reply, acl_name):
                        # Brownfield NAT ยังอ้างถึง ACL ที่ไม่มีอยู่บนอุปกรณ์แล้ว (ถูก
                        # ลบไปนอกระบบ) - fail closed แทนที่จะคืน scopes ว่างเงียบๆ
                        # ซึ่งฝั่งฟอร์มจะตีความเป็น "Any" แล้วเสี่ยง Save ทับ ACL เดิม
                        nat_dashboard_acl_missing = True
                precomputed_reply = merge_nat_dashboard_replies(replies)
            # (= LOCAL_USER_WRITE_COMMANDS - literal ไว้เพราะเทสต์ NAT/zone/DHCP exec body ของ
            # บล็อกนี้ด้วย scope ที่กำหนดเอง ไม่มีชื่อ import ใหม่)
            if command in ("set_new_local_user", "edit_local_user", "delete_local_user"):
                # Fresh user list inside the same DeviceLock as the write: Create
                # must not overwrite a user, Edit must not re-create a deleted one
                # through merge, and Delete must not report a no-op as success.
                users_reply = await callhome_service.send_payload(
                    dev_id, build_payload(device.dev_vendor, "get_local_user", {})
                )
                try:
                    if reply_rejected(users_reply):
                        raise ValueError("rejected")
                    device_usernames = parse_local_usernames(device.dev_vendor, users_reply)
                except (ValueError, SyntaxError):  # SyntaxError = ElementTree ParseError
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="Could not read the current local users from the device. Nothing was changed.",
                    )
                try:
                    check_target_against_device(command, body.parameters["username"], device_usernames)
                except FileExistsError as exc:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
                except LookupError as exc:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
            if command == "remove_security_zone" and device.dev_vendor == "cisco":
                # Fresh references, not browser state. Only the final RPC writes config.
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("cisco", "get_running_config", {})
                )
                try:
                    payload = build_payload("cisco", command, {
                        "zone_id": body.parameters["zone_id"],
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
            elif command == "remove_security_zone" and device.dev_vendor == "juniper":
                # Brownfield zones are commonly referenced by policy pairs and
                # NAT rule-set contexts.  Deleting only security-zone makes
                # Junos reject commit with "Zone must be defined".  Read the
                # authoritative running config inside the same DeviceLock and
                # build one candidate edit that removes those references and
                # the zone atomically.
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_running_config", {})
                )
                try:
                    payload = build_payload("juniper", command, {
                        "zone_name": body.parameters["zone_name"],
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    detail = str(exc)
                    http_status = status.HTTP_404_NOT_FOUND if "ZONE_NOT_FOUND" in detail else status.HTTP_400_BAD_REQUEST
                    raise HTTPException(status_code=http_status, detail=detail)
            elif command == "replace_acl_interface_bindings" and device.dev_vendor in ("cisco", "juniper"):
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload(device.dev_vendor, "get_switchport_information", {})
                )
                try:
                    payload = build_payload(device.dev_vendor, command, {
                        **body.parameters,
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    detail = str(exc)
                    if "ACL_BINDING_CONCURRENT_MODIFICATION" in detail:
                        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
            elif command == "set_dhcp_local_interfaces" and device.dev_vendor == "juniper":
                # (2026-09) Brownfield dhcp-local-server group ทุกชื่อ - อ่าน running
                # config สดภายใน DeviceLock เดียวกับที่เขียนเสมอ (ไม่เชื่อ baseline
                # จาก browser เป็น authority) เทียบกับ previous_members/
                # previous_interfaces ที่ frontend ส่งมา ถ้าไม่ตรงกันแปลว่ามีคนอื่น
                # แก้ group นี้ไปแล้วตั้งแต่โหลดหน้า - ปฏิเสธก่อนเขียนเสมอ (ไม่เขียนทับ
                # การแก้ของคนอื่น) แล้วตรวจ conflict ข้าม group/relay จากข้อมูลสดชุด
                # เดียวกันก่อนสร้าง payload จริง
                from vendor_translators.response_normalizer import normalize_generic
                from vendor_translators.juniper_junos import (
                    dhcp_local_server_group_members,
                    dhcp_local_server_interface_owners,
                    dhcp_relay_bound_interfaces,
                )

                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_dhcp_pool_information", {})
                )
                normalized_payload = normalize_generic("juniper", config_reply)["payload"]
                target_group = (body.parameters.get("group") or "CM-DHCP").strip()
                live_members = dhcp_local_server_group_members(normalized_payload, target_group)

                using_members = "previous_members" in body.parameters or "members" in body.parameters
                if using_members:
                    baseline_raw = body.parameters.get("previous_members") or []
                    baseline_canon = sorted(
                        (entry.get("name"), entry.get("upto") or None, bool(entry.get("exclude")))
                        for entry in baseline_raw if isinstance(entry, dict) and entry.get("name")
                    )
                    desired_raw = body.parameters.get("members") or []
                    desired_names = {
                        entry.get("name") for entry in desired_raw
                        if isinstance(entry, dict) and entry.get("name")
                    }
                else:
                    baseline_raw = body.parameters.get("previous_interfaces") or []
                    baseline_canon = sorted((name, None, False) for name in baseline_raw)
                    desired_names = set(body.parameters.get("interfaces") or [])

                live_canon = sorted((m["name"], m["upto"], m["exclude"]) for m in live_members)

                if baseline_canon != live_canon:
                    live_names = {m["name"] for m in live_members}
                    missing = sorted({name for (name, *_rest) in baseline_canon if name not in live_names})
                    if missing:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail={
                                "code": "DHCP_LOCAL_MEMBER_NOT_FOUND",
                                "message": (
                                    f"Interface(s) {', '.join(missing)} are no longer members of group "
                                    f"'{target_group}' on the device - someone else may have changed it. "
                                    "Please refresh and try again."
                                ),
                                "group": target_group,
                                "missing": missing,
                            },
                        )
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail={
                            "code": "DHCP_LOCAL_GROUP_CHANGED",
                            "message": (
                                f"Group '{target_group}' was changed by someone else since you loaded this "
                                "page. Please refresh and review before applying again."
                            ),
                            "group": target_group,
                        },
                    )

                baseline_names = {name for (name, *_rest) in baseline_canon}
                owners = dhcp_local_server_interface_owners(normalized_payload)
                relay_bound = dhcp_relay_bound_interfaces(normalized_payload)
                for name in sorted(desired_names - baseline_names):
                    if name in relay_bound:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail={
                                "code": "DHCP_LOCAL_RELAY_CONFLICT",
                                "message": (
                                    f"Interface {name} is already configured as a DHCP Relay leg and cannot "
                                    "also be a DHCP local-server member."
                                ),
                                "interface": name,
                            },
                        )
                    owner = owners.get(name)
                    if owner and owner != target_group:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail={
                                "code": "DHCP_LOCAL_INTERFACE_CONFLICT",
                                "message": (
                                    f"Interface {name} is already a member of a different DHCP local-server "
                                    f"group ('{owner}')."
                                ),
                                "interface": name,
                                "group": owner,
                            },
                        )

                try:
                    payload = build_payload("juniper", command, body.parameters)
                except ValueError as exc:
                    if hasattr(exc, "to_dict"):
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.to_dict())
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
            elif command == "create_acl" and device.dev_vendor == "juniper":
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_acl_information", {})
                )
                try:
                    payload = build_payload("juniper", command, {
                        **body.parameters,
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    detail = str(exc)
                    if hasattr(exc, "to_dict"):
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.to_dict())
                    if "ACL_FILTER_ALREADY_EXISTS" in detail:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
            elif command == "replace_acl" and device.dev_vendor == "juniper":
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_acl_information", {})
                )
                try:
                    payload = build_payload("juniper", command, {
                        **body.parameters,
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    detail = str(exc)
                    if "ACL_CONCURRENT_MODIFICATION" in detail:
                        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
                    if hasattr(exc, "to_dict"):
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.to_dict())
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
            elif command == "set_security_policy" and device.dev_vendor == "juniper":
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_security_policy_information", {})
                )
                from vendor_translators.juniper_security_policy import find_juniper_security_policy

                from_zone = body.parameters.get("from_zone", "")
                to_zone = body.parameters.get("to_zone", "")
                policy_name = body.parameters.get("policy_name", "")
                replace_name = body.parameters.get("replace_name")
                confirm_replace = body.parameters.get("confirm_replace_existing", False)
                is_confirmed = bool(confirm_replace) or str(confirm_replace).lower() in ("true", "1")

                existing_el = None
                try:
                    root = safe_fromstring(config_reply)
                    existing_el = find_juniper_security_policy(root, from_zone, to_zone, policy_name)
                except Exception:
                    existing_el = None

                if existing_el is not None and replace_name is None and not is_confirmed:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            f"POLICY_ALREADY_EXISTS: Policy '{policy_name}' already exists in Zone pair "
                            f"{from_zone} → {to_zone} on device. Please confirm before replacing"
                        ),
                    )

                try:
                    if existing_el is not None or replace_name is not None or is_confirmed:
                        target_name = replace_name or policy_name
                        payload = build_payload("juniper", command, {
                            **body.parameters,
                            "replace_name": target_name,
                            "reference_config": config_reply,
                        })
                    else:
                        payload = build_payload("juniper", command, body.parameters)
                except ValueError as exc:
                    detail = str(exc)
                    if "POLICY_CONCURRENT_MODIFICATION" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail={
                                "code": "POLICY_CONCURRENT_MODIFICATION",
                                "message": f"Policy '{policy_name}' ({from_zone} → {to_zone}) was modified after you opened this page. Please refresh and review. The policy has not been saved or deleted",
                                "identity": {
                                    "fromZone": from_zone,
                                    "toZone": to_zone,
                                    "name": policy_name,
                                },
                            },
                        )
                    if "POLICY_NOT_FOUND" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND,
                            detail={
                                "code": "POLICY_NOT_FOUND",
                                "message": f"Policy '{policy_name}' not found in Zone pair '{from_zone}' → '{to_zone}' on device",
                                "identity": {
                                    "fromZone": from_zone,
                                    "toZone": to_zone,
                                    "name": policy_name,
                                },
                            },
                        )
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
            elif command == "remove_security_policy" and device.dev_vendor == "juniper":
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_security_policy_information", {})
                )
                from_zone = body.parameters.get("from_zone", "")
                to_zone = body.parameters.get("to_zone", "")
                policy_name = body.parameters.get("policy_name", "")

                try:
                    payload = build_payload("juniper", command, {
                        **body.parameters,
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    detail = str(exc)
                    if "POLICY_CONCURRENT_MODIFICATION" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail={
                                "code": "POLICY_CONCURRENT_MODIFICATION",
                                "message": f"Policy '{policy_name}' ({from_zone} → {to_zone}) was modified after you opened this page. Please refresh and review. The policy has not been saved or deleted",
                                "identity": {
                                    "fromZone": from_zone,
                                    "toZone": to_zone,
                                    "name": policy_name,
                                },
                            },
                        )
                    if "POLICY_NOT_FOUND" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND,
                            detail={
                                "code": "POLICY_NOT_FOUND",
                                "message": f"Policy '{policy_name}' not found in Zone pair '{from_zone}' → '{to_zone}' on device",
                                "identity": {
                                    "fromZone": from_zone,
                                    "toZone": to_zone,
                                    "name": policy_name,
                                },
                            },
                        )
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
            elif command == "move_security_policy" and device.dev_vendor == "juniper":
                # อ่านลำดับจริงภายใน lock แล้วค่อยคำนวณ Policy ข้างเคียง - ใช้เฉพาะค่าที่
                # ผ่าน _validate_deferred_command (ไม่ส่ง before/after/reference จาก client ต่อ)
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_security_policy_information", {})
                )
                from_zone = deferred_params["from_zone"]
                to_zone = deferred_params["to_zone"]
                policy_name = deferred_params["policy_name"]
                identity = {"fromZone": from_zone, "toZone": to_zone, "name": policy_name}

                try:
                    payload = build_payload("juniper", command, {
                        **deferred_params,
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    detail = str(exc)
                    if "POLICY_READ_FAILED" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail={
                                "code": "POLICY_READ_FAILED",
                                "message": detail.split(":", 1)[1].strip() + " - Policy move was not performed",
                                "identity": identity,
                            },
                        )
                    if "POLICY_ORDER_CONCURRENT_MODIFICATION" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail={
                                "code": "POLICY_ORDER_CONCURRENT_MODIFICATION",
                                "message": f"Policy order in Zone pair '{from_zone}' → '{to_zone}' was modified after you opened this page. Please refresh before moving",
                                "identity": identity,
                            },
                        )
                    if "POLICY_MOVE_NOT_POSSIBLE" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail={
                                "code": "POLICY_MOVE_NOT_POSSIBLE",
                                "message": detail.split(":", 1)[1].strip(),
                                "identity": identity,
                            },
                        )
                    if "POLICY_NOT_FOUND" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND,
                            detail={
                                "code": "POLICY_NOT_FOUND",
                                "message": f"Policy '{policy_name}' not found in Zone pair '{from_zone}' → '{to_zone}' on device",
                                "identity": identity,
                            },
                        )
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
            elif command == "move_security_policy_zone" and device.dev_vendor == "juniper":
                # Edit ที่เปลี่ยนคู่ Zone - อ่านสดภายใน lock แล้วสร้าง edit-config เดียวที่
                # ลบต้นทาง+สร้างปลายทางพร้อมกัน (atomic) ใช้เฉพาะค่าที่ผ่าน
                # _validate_deferred_command เท่านั้น (ไม่ส่งพารามิเตอร์อื่นจาก client ต่อ)
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_security_policy_information", {})
                )
                from_zone = deferred_params["from_zone"]
                to_zone = deferred_params["to_zone"]
                policy_name = deferred_params["policy_name"]
                new_from_zone = deferred_params["new_from_zone"]
                new_to_zone = deferred_params["new_to_zone"]
                identity = {"fromZone": from_zone, "toZone": to_zone, "name": policy_name}
                new_identity = {"fromZone": new_from_zone, "toZone": new_to_zone, "name": policy_name}

                try:
                    payload = build_payload("juniper", command, {
                        **deferred_params,
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    detail = str(exc)
                    if "POLICY_READ_FAILED" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail={
                                "code": "POLICY_READ_FAILED",
                                "message": detail.split(":", 1)[1].strip() + " - Policy move was not performed",
                                "identity": identity,
                            },
                        )
                    if "POLICY_MOVE_DESTINATION_EXISTS" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail={
                                "code": "POLICY_MOVE_DESTINATION_EXISTS",
                                "message": f"Policy '{policy_name}' already exists in destination Zone pair '{new_from_zone}' → '{new_to_zone}' on device and cannot be overwritten",
                                "identity": identity,
                                "newIdentity": new_identity,
                            },
                        )
                    if "POLICY_CONCURRENT_MODIFICATION" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail={
                                "code": "POLICY_CONCURRENT_MODIFICATION",
                                "message": f"Policy '{policy_name}' ({from_zone} → {to_zone}) was modified after you opened this page. Please refresh and review. The policy has not been moved",
                                "identity": identity,
                            },
                        )
                    if "POLICY_UNSUPPORTED_BROWNFIELD_ACTION" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail={
                                "code": "POLICY_UNSUPPORTED_BROWNFIELD_ACTION",
                                "message": detail.split(":", 1)[1].strip(),
                                "identity": identity,
                            },
                        )
                    if "POLICY_NOT_FOUND" in detail:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND,
                            detail={
                                "code": "POLICY_NOT_FOUND",
                                "message": f"Policy '{policy_name}' not found in Zone pair '{from_zone}' → '{to_zone}' on device",
                                "identity": identity,
                            },
                        )
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
            elif command in ("remove_acl_rule", "remove_acl") and device.dev_vendor == "juniper":
                acl_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_acl_information", {})
                )
                iface_reply = await callhome_service.send_payload(
                    dev_id, build_payload("juniper", "get_switchport_information", {})
                )
                from vendor_translators.juniper_acl import resolve_juniper_safe_delete
                name = body.parameters.get("name") or body.parameters.get("acl_name")
                term_name = body.parameters.get("term_name")
                revision = body.parameters.get("revision")
                try:
                    plan = resolve_juniper_safe_delete(name, term_name, acl_reply, iface_reply, revision=revision)
                    module = module_for_vendor("juniper")
                    payload = module._edit_configuration(plan["payload_xml"])
                except ValueError as exc:
                    detail = str(exc)
                    if "ACL_CONCURRENT_MODIFICATION" in detail:
                        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
                    if hasattr(exc, "to_dict"):
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.to_dict())
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
            elif command in ("create_firewall_policy", "remove_firewall_policy") and device.dev_vendor == "cisco":
                # Cisco ZBF Edit/Delete (2026-09, ดู vendor_translators/cisco_zbf.py) -
                # อ่าน running config สดภายใน DeviceLock เดียวกับที่เขียนเสมอ ไม่เชื่อ
                # editable/sharedObjects/revision ที่ frontend ส่งมาเลย - resolve_cisco_zbf_safe_edit/
                # _delete (เรียกจากข้างใน create_firewall_policy/remove_firewall_policy เอง
                # ผ่าน reference_config) ตรวจ revision + reference chain + shared object +
                # Brownfield safety ให้ครบก่อนสร้าง write payload เท่านั้น
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("cisco", "get_firewall_information", {})
                )
                try:
                    payload = build_payload("cisco", command, {
                        **body.parameters,
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    if hasattr(exc, "to_dict"):
                        raise HTTPException(status_code=getattr(exc, "status_code", 400), detail=exc.to_dict())
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
            elif command in (
                "remove_acl", "remove_acl_rule", "replace_acl", "set_acl_rule",
                "create_acl_rule", "replace_acl_rule", "create_acl",
            ) and device.dev_vendor == "cisco":
                # Cisco ACL reference & safety guard (2026-09) - ตรวจสอบการใช้งาน ACL
                # โดย NAT, Interface access-group และ Zone-Based Firewall ผ่าน snapshot เดียว
                # ภายใน DeviceLock เดียวกับที่เขียนเสมอ เพื่อไม่ให้เกิด TOCTOU race
                config_reply = await callhome_service.send_payload(
                    dev_id, build_payload("cisco", "get_acl_reference_information", {})
                )
                try:
                    payload = build_payload("cisco", command, {
                        **body.parameters,
                        "reference_config": config_reply,
                    })
                except ValueError as exc:
                    if hasattr(exc, "to_dict"):
                        raise HTTPException(status_code=getattr(exc, "status_code", 400), detail=exc.to_dict())
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
            # Keep the long wait local to Cisco's compound NAT writer. The
            # ordinary path remains byte-for-byte the same call so unrelated
            # commands retain the shared 20-second transport default.
            if precomputed_reply is not None:
                # get_nat_dashboard บน Cisco - ได้ reply ที่ merge จาก 2 RPC เล็ก
                # ข้างบนแล้ว ไม่ต้องยิง payload (ของเดิม/ไม่ได้ใช้) ซ้ำอีกรอบ
                reply = precomputed_reply
            elif command in CISCO_NAT_QUARANTINE_COMMANDS and device.dev_vendor == "cisco":
                # (2026-09) ครอบคลุมทั้ง Cisco NAT family (get_static_nat_information,
                # set_static_nat, remove_static_nat, get_port_forward_information,
                # set_port_forward, remove_port_forward, create_nat_policy,
                # remove_nat_policy) - get_nat_dashboard ไม่มีทางมาถึง branch นี้เพราะ
                # precomputed_reply ถูกตั้งไว้แล้วเสมอด้านบน timeout ยาวขึ้น (60 วิ)
                # ยังจำกัดเฉพาะ CISCO_NAT_EXTENDED_TIMEOUT_COMMANDS เท่านั้น
                # (_command_reply_timeout คืน None ให้คำสั่งอื่นในกลุ่มนี้ = ใช้
                # default 20 วิเหมือนเดิมทุกประการ ไม่มีการเพิ่ม timeout แบบกว้างๆ)
                connection_before = callhome_service.session_connection(dev_id)
                try:
                    reply = await callhome_service.send_payload(
                        dev_id,
                        payload,
                        timeout=_command_reply_timeout(device.dev_vendor, command),
                        nat_quarantine=True,
                    )
                except (ConnectionError, asyncssh.misc.ConnectionLost) as exc:
                    if command not in CISCO_NAT_WRITE_COMMANDS or not _netconf_channel_dropped(exc):
                        raise
                    # รอนอก DeviceLock (ด้านล่าง) - ไม่ถือ lock ค้างระหว่างรออุปกรณ์ต่อใหม่
                    nat_dropped_connection = connection_before
                    nat_reconnect_connection = connection_before
                    reply = ""
                    print(f"[*] {dev_id} closed NETCONF during '{command}' - waiting for call-home")
                else:
                    if command in CISCO_NAT_SESSION_RESET_COMMANDS and not reply_rejected(reply):
                        # ได้ reply แล้วก็จริง แต่ session นี้กำลังจะตาย (ดู
                        # CISCO_NAT_SESSION_RESET_COMMANDS) - ปิดเองแล้วรอตัวใหม่ก่อนตอบ
                        nat_reconnect_connection = connection_before
                        print(f"[*] {dev_id} applied '{command}' - resetting call-home session")
            elif command == "save_running_config" and device.dev_vendor in SAVE_CONFIG_VENDORS:
                # Huawei ใช้ copy-config -> startup ซึ่งต้องมี :startup ใน hello ของ session
                # จริง - ไม่มี = อุปกรณ์จะตอบ rpc-error ที่อ่านยาก ปฏิเสธก่อนแตะอุปกรณ์แทน
                if device.dev_vendor == "huawei" and NETCONF_STARTUP_CAPABILITY not in (
                    (callhome_service.sessions.get(dev_id) or {}).get("capabilities") or set()
                ):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="This device does not advertise the NETCONF :startup capability, so the configuration cannot be saved to startup over NETCONF.",
                    )
                reply = await callhome_service.send_payload(
                    dev_id, payload, timeout=_command_reply_timeout(device.dev_vendor, command),
                )
            else:
                reply = await callhome_service.send_payload(dev_id, payload)
    except DeviceLockBusy as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ConnectionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except (asyncssh.misc.ConnectionLost, asyncio.TimeoutError) as exc:
        # เจอจริง: NETCONF SSH session หลุดกลางคันระหว่างรอ rpc-reply (ไม่ใช่
        # rpc-error ปกติที่ callhome_service.send_payload คืนมาเป็น string -
        # กรณีนี้ exception หลุดออกมาจาก read_dev_response ตรงๆ) เคย escape ไป
        # เป็น raw 500 ไม่มี detail ให้ frontend เห็นเลย (err.detail จะว่างเปล่า
        # ฝั่ง React) log ให้เห็นชัดๆ ใน terminal/api.log แทนที่จะจมอยู่ใน
        # traceback ยาวๆ ด้วย - อุปกรณ์อาจได้ apply edit-config บางส่วนไปแล้วก่อน
        # session หลุดก็ได้ (ไม่รู้แน่ชัด) ผู้ใช้ต้องเช็ค running-config เองว่า
        # คำสั่งนี้ apply จริงไปแค่ไหน
        print(f"[!] NETCONF session lost while running '{command}' on device {dev_id}: {exc}")
        # เจอบั๊กจริงเพิ่มเติม: session ที่ตายไปแล้ว (channel หลุดจริง หรือ read
        # timeout ซ้ำๆ) ไม่เคยถูกลบออกจาก callhome_service.sessions เลย - ทำให้
        # ทุก request ถัดไปของอุปกรณ์นี้ (ไม่ว่าจะเป็นคำสั่งอะไรก็ตาม แม้แต่
        # get_* อ่านเฉยๆ) ไปเขียน/อ่านซ้ำกับ pipe ที่ตายแล้ว แล้วต้องรอ timeout
        # 20 วิเต็มๆ ซ้ำไปเรื่อยๆ ไม่มีทางฟื้นเองได้เลยจนกว่าจะ restart backend
        # (เจอจริงกับ HQ-R1: get_device_version ธรรมดาก็ hang/error เหมือนกันหมด
        # หลังจาก edit-config บางคำสั่งก่อนหน้า timeout) - ลบ session ทิ้งทันทีที่
        # เจอ error กลุ่มนี้ ให้ request ถัดไปได้ 409 "ไม่ได้เชื่อมต่ออยู่" ที่ชัดเจน
        # แทน แล้วรอ call-home เชื่อมต่อใหม่จริงๆ แทนที่จะ hang ซ้ำไปเรื่อยๆ
        # (bug 57) เดิมใช้ sessions.pop() ซึ่งเป็นการ "ลืม" ไม่ใช่ "ปิด" - asyncssh
        # connection ยังเปิดอยู่ อุปกรณ์ยังคิดว่าตัวเองเชื่อมต่ออยู่จึงไม่ call-home
        # ใหม่ ผลคืออุปกรณ์หายจากระบบถาวรจนกว่า TCP จะขาดเอง เป็นบั๊กเดียวกับ BUG-42
        # ที่แก้ไปแล้ว 3 เส้นทาง (delete_device_full / delete_user_full /
        # delete_site_full) แต่เส้นนี้ตกค้าง - close_session() ปิดจริง แล้วปล่อยให้
        # finally ใน accept() ล้าง sessions/stats ตามปกติ
        # (bug 68) แยก "ท่อขาดจริง" ออกจาก "อุปกรณ์กำลังคิดเรื่อง config ที่ผิด"
        #
        # เดิมตัด session ทิ้งทุกกรณีที่ timeout ซึ่งลงโทษผู้ใช้ที่แค่กรอกค่าผิดหนักเกินไป -
        # ผู้ใช้ทดสอบเจอจริง (ข้อ 5.6.1): ตั้ง OSPF router-id ซ้ำกับ router ตัวหน้า อุปกรณ์
        # เงียบ 20 วินาที -> เราตัด session -> 503 -> คำสั่งถัดไปได้ 409 วนไม่จบจนกว่า
        # อุปกรณ์จะ call-home กลับมาใหม่ ทั้งที่อุปกรณ์ยังมีชีวิตดีอยู่ แค่ปฏิเสธ config
        #
        # เหตุผลเดิมที่ต้องตัดคือ "คำตอบที่มาช้าจะค้างในท่อแล้วไปปนกับคำสั่งถัดไป" ซึ่ง
        # (bug 57) แก้ไปแล้ว - _read_matching_reply ทิ้ง reply เก่าที่ค้างได้ไม่จำกัดจำนวน
        # ภายในงบเวลา (conn_socket.py) คำตอบที่มาช้าจึงไม่ทำให้ท่อเสียอีกแล้ว
        #
        # ที่ยังต้องตัดคือ ConnectionLost - ท่อขาดจริง ถ้าไม่ปิดอุปกรณ์จะคิดว่าตัวเองยัง
        # ต่ออยู่แล้วไม่ call-home ใหม่ (เหตุผลเดิมของ bug 57 ที่ยังใช้ได้อยู่)
        # ส่วน timeout เฉย ๆ ปล่อยให้ probe ของ (bug 58) เป็นคนตัดสินว่าอุปกรณ์ยังมีชีวิต
        # ไหม - ยืนยันแล้วว่าเชื่อถือได้จากการทดสอบข้อ 9.1.2b (offline 8 ชั่วโมงแล้วกลับมา
        # ใช้งานได้ใน 30-40 วินาที)
        # (bug 100) เงียบสนิทนานเกินกำหนด - conn_socket ปิด session ให้แล้ว
        #
        # ต้องดักก่อน handler ของ timeout ทั่วไปด้านล่าง เพราะข้อความของอันนั้นบอกว่า
        # "การเชื่อมต่อยังไม่ถูกตัด ใช้งานคำสั่งอื่นต่อได้ทันที" ซึ่งจะกลายเป็นคำโกหก
        # ทันทีถ้าเอามาใช้กับเคสนี้ - หน้าจอต้องตรงกับสิ่งที่เกิดขึ้นจริงเสมอ
        if isinstance(exc, NetconfDead):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"Device timed out without any response during command '{command}' - "
                    "The previous connection was closed so the device can call-home again "
                    "(usually takes 30-60 seconds). Please wait until the device is online and try again, "
                    "and check running-config on the device to verify if this command was applied."
                ),
            )

        if isinstance(exc, asyncssh.misc.ConnectionLost):
            await callhome_service.close_session(
                dev_id, reason=f"SSH connection lost while waiting for reply to command '{command}'"
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"Connection to device was lost while waiting for command '{command}' result - "
                    "This session has been closed. Please check running-config on the device to verify if this command "
                    "was applied, and wait for the device to reconnect via call-home before trying again."
                ),
            )

        print(f"[!] {dev_id} ไม่ตอบคำสั่ง '{command}' ในเวลาที่กำหนด - ไม่ตัด session (ท่อยังไม่ขาด)")
        # (2026-09) Cisco NAT เท่านั้น: แยกข้อความ timeout ของคำสั่งอ่านออกจากคำสั่ง
        # เขียนอย่างชัดเจน (ใช้ structured error code แทนการค้น substring ข้อความ) -
        # ทุกคำสั่งอื่นยังได้ข้อความเดิมด้านล่างทุกตัวอักษรเหมือนก่อนแก้
        if command in CISCO_NAT_READ_COMMANDS and device.dev_vendor == "cisco":
            # ทุกคำสั่งในกลุ่มนี้ (get_nat_dashboard, get_static_nat_information,
            # get_port_forward_information) เป็นคำสั่งอ่านล้วนๆ (<get> ไม่มี
            # edit-config เลยสักตัว) ข้อความ "อาจ apply configuration ไปแล้ว" ของ
            # คำสั่งเขียนด้านล่างไม่จริงกับเคสนี้และทำให้ผู้ใช้ตื่นตระหนกเกินจำเป็น
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "NETCONF_READ_TIMEOUT",
                    "message": (
                        f"Device did not respond to the read-only query '{command}' within the timeout. "
                        "No configuration was sent by this command. The system is waiting for the NETCONF "
                        "session to respond or reconnect - please try again shortly."
                    ),
                },
            )
        if command in CISCO_NAT_WRITE_COMMANDS and device.dev_vendor == "cisco":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "NETCONF_WRITE_OUTCOME_UNKNOWN",
                    "message": (
                        f"Device did not acknowledge command '{command}' within the timeout. "
                        "The result is unknown: the device may already have applied the configuration. "
                        "Wait for the NETCONF session to respond, then refresh and verify the running "
                        "configuration before trying the command again. Do not retry immediately."
                    ),
                },
            )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"Device did not acknowledge command '{command}' within the timeout. "
                "The result is unknown: the device may already have applied the configuration. "
                "Wait for the NETCONF session to respond, then refresh and verify the running configuration "
                "before trying the command again."
            ),
        )
    except NetconfDesync as exc:
        # (bug 57) ต้องดักก่อน RuntimeError ทั่วไป เพราะ NetconfDesync สืบทอด
        # RuntimeError - ถ้าปล่อยให้ตกไป handler ข้างล่าง ผู้ใช้จะเห็นข้อความว่า
        # "อุปกรณ์ปฏิเสธคำสั่ง" ซึ่งไม่จริงเลย อุปกรณ์ไม่ได้ปฏิเสธอะไร แค่ระบบยังไล่
        # reply เก่าที่ค้างในท่อไม่หมด
        #
        # **ห้ามปิด session ในเคสนี้** - การที่ได้รับข้อมูลกลับมาแปลว่าอุปกรณ์ยังมีชีวิต
        # ตัดทิ้งตอนนี้คือทำลายการฟื้นตัวที่กำลังจะสำเร็จ (ต่างจาก NetconfSilent ที่
        # ไม่ได้รับอะไรเลย ซึ่งไปเข้า handler ของ TimeoutError ด้านบนแล้วปิด session)
        print(f"[!] NETCONF desync while running '{command}' on device {dev_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"System is synchronizing connection state with the device. Command '{command}' "
                "was not sent - please wait a moment and try again (device is still normally connected)."
            ),
        )
    except RuntimeError as exc:
        # เจอบั๊กจริง: callhome_service.send_payload โยน RuntimeError("Juniper
        # commit failed: <rpc-reply>...</rpc-reply>") เวลา commit ล้มเหลวจริง
        # (severity="error" - เช่น "Interface ge-0/0/2.10 already configured"
        # ตอนพยายามตั้ง DHCP Relay บน interface ที่เป็น DHCP local server อยู่
        # แล้ว) ไม่เคยถูก catch ที่นี่เลย - หลุดขึ้นไปเป็น unhandled exception
        # กลายเป็น 500 เปล่าๆ ไม่มี detail (frontend เห็นแค่ "Internal Server
        # Error" ทั่วไป ไม่รู้เหตุผลจริงจากอุปกรณ์เลย) - ดึง <error-message> ตัว
        # แรกจาก rpc-reply มาแสดงแทน raw XML ทั้งก้อน ถ้า parse ไม่ได้ (รูปแบบ
        # ข้อความไม่ตรงคาด) ก็ fallback ไปแสดงข้อความเดิมทั้งหมด
        reason = _device_rejection_reason(exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Device rejected command '{command}': {reason}",
        )

    # (bug 99) อุปกรณ์ปฏิเสธคำสั่ง = ไม่มีอะไรเกิดขึ้นบนอุปกรณ์ ห้ามบันทึกอะไรทั้งนั้น
    #
    # มาถึงบรรทัดนี้ได้ไม่ได้แปลว่าคำสั่งสำเร็จ - send_payload **จงใจไม่ throw** เมื่อ
    # edit-config โดน rpc-error (ปล่อย reply ให้ normalize แปลงเป็น {ok:false,errors}
    # ส่งถึงหน้าจอตามระลอก A) โค้ดเดิมจึงเขียนประวัติทุกครั้งที่ไม่มี exception
    #
    # ผลจริงที่เจอตอนไล่ BUG-98: ประวัติมี create_security_tunnel แบบ gre ของ Juniper
    # 4 ครั้ง แต่บนอุปกรณ์ `show configuration interfaces gr-0/0/0` ว่างเปล่า และไม่มี
    # คำสั่งลบตามหลังเลย - ประวัติโกหกว่ามีการตั้งค่าไปแล้ว
    #
    # เรื่องนี้สำคัญกว่าที่เห็น เพราะประวัติคำสั่งเป็นหลักฐานที่ใช้ไล่ปัญหาจริง (เคยใช้
    # จับได้ว่าเบราว์เซอร์แท็บไหนรันโค้ดเก่าอยู่จากลำดับ key ใน detail) ถ้ามันบันทึกของ
    # ที่ไม่เคยเกิดขึ้น จะพาไล่ผิดทางทุกครั้ง และผู้ใช้ที่เปิดดูก็เข้าใจผิดตามไปด้วย
    #
    # **ไม่เปลี่ยน HTTP status และไม่เปลี่ยนรูปร่าง response** - ยังคืน 200 พร้อม
    # {ok:false, errors:[...]} เหมือนเดิมทุกประการ ฝั่ง frontend จึงไม่ต้องแก้อะไรเลย
    # ที่เปลี่ยนคือ "ไม่เขียนลงฐานข้อมูล" อย่างเดียว
    if nat_reconnect_connection is not None:
        reconnected = await callhome_service.wait_for_reconnect(
            dev_id, nat_reconnect_connection, CISCO_NAT_RECONNECT_WAIT_SECONDS
        )
        # ได้ reply ยืนยันแล้ว (nat_dropped_connection เป็น None) = config ลงจริงแน่นอน ตอบตาม
        # reply ได้เลยแม้อุปกรณ์ยังไม่กลับมา - หน้าเว็บที่โหลดต่อจะรอ session ใหม่เอง
        if not reconnected and nat_dropped_connection is not None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "NETCONF_WRITE_OUTCOME_UNKNOWN",
                    "message": (
                        "The device restarted its management connection while applying this NAT change "
                        "and has not reconnected yet. Wait until it is online, then refresh to check the result."
                    ),
                },
            )

    rejected = reply_rejected(reply)

    if not rejected:
        await _track_config_object(session, dev_id, current_user.usr_id, command, body.parameters)
        await _untrack_config_object(session, dev_id, command, body.parameters)

        # set_hostname changes both the actual device hostname and the name shown
        # on Device/Site pages. Stage it only after the device acknowledged the
        # write; create_history() commits both values in the same DB transaction.
        _stage_device_metadata_after_success(device, command, body.parameters)

        # เก็บ log เฉพาะคำสั่งที่แก้ config จริง (ไม่ใช่ get_* query อ่านอย่างเดียว) -
        # ตรงกับที่ระบบ config management ทั่วไปทำ (log การเปลี่ยนแปลง ไม่ log การอ่าน)
        await _note_config_write(dev_id, device.dev_vendor, command)
        if not command.startswith("get_"):
            await create_history(
                session,
                dev_id=dev_id,
                usr_id=current_user.usr_id,
                action=command,
                # All credentials are removed and replaced by changed/not-changed flags.
                detail=json.dumps(history_parameters(command, body.parameters), ensure_ascii=False),
            )
    elif not command.startswith("get_"):
        # ให้เห็นใน log ฝั่ง server ว่าทำไมประวัติถึงไม่มีแถวนี้ - ไม่งั้นเวลาไล่ปัญหา
        # ทีหลังจะงงว่าผู้ใช้บอกว่ากดแล้วแต่ประวัติไม่ขึ้น
        print(f"[!] {dev_id} ปฏิเสธคำสั่ง '{command}' - ไม่บันทึกลงประวัติ (bug 99)")

    if nat_dropped_connection is not None:
        # ไม่มี rpc-reply ให้ normalize - อุปกรณ์กลับมาแล้ว รายการที่หน้าเว็บโหลดใหม่คือผลจริง
        return DeviceCommandResult(command=command, normalized=True, result={"ok": True})

    try:
        result = normalize(device.dev_vendor, command, reply)
    except Exception:
        # normalize() ตอนนี้มี normalizer ให้ทุกคำสั่งแล้ว (ไม่ raise ValueError
        # กับคำสั่งที่ไม่รู้จักอีก) - เหลือแค่กรณี parser พังจริงๆ เช่น XML ที่
        # อุปกรณ์ตอบมา parse ไม่ได้ (ParseError ไม่ใช่ ValueError) - เผื่อไว้ไม่ให้
        # 500 ส่ง XML ดิบกลับไปแทน degrade แบบนุ่มนวล
        return DeviceCommandResult(command=command, normalized=False, result=reply)

    # # |====================== ลบได้ ======================|
    # # ทุกครั้งที่หน้าเว็บดึง NAT สดจากอุปกรณ์ (get_nat_information) แอบ sync DB
    # # ให้ตรงกับของจริงไปด้วยเลยเงียบๆ เบื้องหลัง (ทั้ง import ตัวที่ยังไม่ track
    # # และลบตัวที่หายไปจากอุปกรณ์แล้ว) - ผู้ใช้ไม่ต้องกดอะไรเพิ่ม ไม่มีปุ่มให้เห็น
    # # เลย ถ้า sync พังก็แค่ rollback เงียบๆ ไม่ทำให้การดึง NAT สดที่ผู้ใช้รอ
    # # อยู่พังตาม
    # if command == "get_nat_information" and device.dev_vendor == "cisco":
    #     try:
    #         nat_data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else {}
    #         acl_data = await _get_normalized_data(dev_id, device.dev_vendor, "get_acl_information")
    #         pool_data = await _get_normalized_data(dev_id, device.dev_vendor, "get_nat_pool_information")
    #         await _reconcile_nat_objects_from_data(
    #             session, dev_id, current_user.usr_id, nat_data, acl_data, pool_data
    #         )
    #     except Exception:
    #         await session.rollback()
    # # |=====================================================|

    if command == "get_nat_dashboard" and device.dev_vendor == "cisco" and nat_dashboard_acl_missing:
        # (2026-09) NAT rule ปัจจุบันอ้างถึง ACL ที่หาไม่พบบนอุปกรณ์แล้ว (ดู branch
        # ที่ตั้ง nat_dashboard_acl_missing ด้านบน) - แนบสัญญาณนี้ไปกับ result แบบ
        # additive (key ใหม่เฉยๆ ไม่แก้ key เดิมเลย) ให้ nat.jsx/natFormModal.jsx
        # fail-closed แทนที่จะอ่าน [] แล้วเข้าใจผิดว่าเป็น "Any" แล้วปล่อยให้ Save
        # เขียนทับ ACL เดิมด้วย permit any
        if isinstance(result, dict):
            result["aclLookupFailed"] = True

    if command == "get_acl_reference_information" and device.dev_vendor == "cisco":
        target_name = body.parameters.get("name")
        target_type = body.parameters.get("acl_type")
        from vendor_translators.cisco_zbf import inspect_cisco_acl_references
        ref_result = inspect_cisco_acl_references(reply, target_name, target_type)
        return DeviceCommandResult(command=command, normalized=True, result=ref_result)

    zbf_metadata = None
    if command == "get_firewall_information" and device.dev_vendor == "cisco":
        # (2026-09) แนบ revision/editable/readOnlyReasons/sharedObjects ที่คำนวณจริง
        # จาก raw XML นี้เอง (authoritative - คนละครั้งกับที่ resolve_cisco_zbf_safe_edit/
        # _delete จะคำนวณใหม่อีกทีตอน Edit/Delete จริงเสมอ) ให้ ciscoZbfParser.js
        # join ด้วยชื่อ Zone Pair แทนที่จะคำนวณเองฝั่ง frontend - ล้มเหลวไม่ทำให้การ
        # อ่านตารางทั้งหน้าพัง (เช่น XML ผิดรูปที่ normalize() ยังพอแปลงได้บางส่วน)
        # แค่ไม่มี metadata แนบมา (ciscoZbfParser.js/stateful.jsx ต้อง fail-closed
        # เป็น editable=false เมื่อไม่มี revision ให้ ไม่ใช่คำนวณเองแทน)
        try:
            from vendor_translators.cisco_zbf import list_cisco_zbf_policies_for_api
            zbf_metadata = list_cisco_zbf_policies_for_api(reply)
        except Exception as exc:
            print(f"[!] {dev_id} คำนวณ Cisco ZBF metadata ไม่สำเร็จ (ตารางยังแสดงได้ปกติ แค่ไม่มี revision): {exc}")
            zbf_metadata = None

    return DeviceCommandResult(command=command, normalized=True, result=result, zbf_metadata=zbf_metadata)


# Phase 9: Reset Device Identity Endpoint
@router.post(
    "/{dev_id}/reset-identity",
    response_model=DeviceResetIdentityResponse,
    dependencies=[Depends(rate_limit_by_device("device_reset_identity", 3, 60.0, fail_closed=True))],
)
async def reset_device_identity_endpoint(
    dev_id: str,
    response: Response,
    force_offline: bool = False,
    session: AsyncSession = Depends(get_session),
    current_user: User_Table = Depends(get_current_user),
    http_request: Request = None,
):
    """Reset Device Identity (Phase 9)
    - สิทธิ์: เฉพาะ Site Owner เท่านั้น (member -> 403, unauthorized/device ไม่มี -> 404)
    - Rate limit: 3 requests ต่อ 60 วินาทีต่ออุปกรณ์
    - Cache-Control: no-store (offline recovery CLI มี one-time token ฝังอยู่)
    """
    # 1. ตรวจสอบสิทธิ์เฉพาะ Site Owner
    await _require_site_owner_for_device(session, dev_id, current_user.usr_id)

    # 2. ประมวลผล Reset Identity ผ่าน service
    try:
        result = await reset_device_identity(
            dev_id=dev_id,
            usr_id=current_user.usr_id,
            session_factory=AsyncSessionFactory,
            force_offline=force_offline,
        )
    except DeviceNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    except ResetEligibilityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except DeviceLockBusy as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ResetOnlineWriteError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    except ResetDatabaseError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
    except DeviceInconsistentStateError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Device identity reset failed")
    audit_security_event("device.identity_reset", "SUCCEEDED", request=http_request,
                         actor_id=current_user.usr_id, dev_id=dev_id)

    # 3. Security Header: Cache-Control: no-store
    response.headers["Cache-Control"] = "no-store"

    return DeviceResetIdentityResponse(
        mode=result.mode,
        device_id=result.device_id,
        vendor=result.vendor,
        expires_at=result.expires_at,
        cli=result.cli,
        cli_steps=result.cli_steps,
        warning=result.warning,
    )
