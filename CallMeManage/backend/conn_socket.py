"""|======= Main Netconf Connection Socket =======|"""

import asyncio
import itertools
import time
import asyncssh
import json
import re
from xml.etree import ElementTree as ET

from tools.safe_xml import safe_fromstring
from datetime import datetime, timezone

from backend.core.load_environment import load_environment
from backend.core.connect_database import AsyncSessionFactory
from backend.core.redis_client import get_redis

from backend.vendor_detector import vender_detector
from backend.capability_probe import ProbeAborted, build_profile

from backend.crud.dev_crud.crud_dev_info import update_device_connection_metadata
from backend.callhome_debug import identity_debug_enabled, log_connected_device, log_identity, log_verbose, verbose_enabled
from backend.device_lifecycle import device_lifecycle
from backend.device_metadata_probe import (
    METADATA_TOTAL_TIMEOUT,
    METADATA_RPC_TIMEOUT,
    MetadataConnectionLost,
    read_device_metadata,
    read_device_serial,
)
from backend.device_enrollment_activation import ActivationError, activate_pending_enrollment
from backend.callhome_auth_mode import enforce_startup_mode
from backend.callhome_auth_router import (
    CallhomeAuthRouter,
    FingerprintReconnect,
    PendingEnrollmentCandidate,
    QUARANTINE_RPC_TIMEOUT,
    QUARANTINE_TOTAL_TIMEOUT,
    RejectReason,
    RejectedConnection,
    short_id,
)
from backend.crud.dev_crud.crud_dev_capability import (
    get_capability_profile,
    update_capability_profile,
    upsert_capability,
)
from backend.model.models import Device_Information

from backend.translator_service import build_payload, commit_payload, discard_changes_payload
from backend.ntp_atomic import combine_cisco_running_edits

from vendor_translators.response_normalizer import normalize, normalize_capabilities, reply_rejected

# message-id ของ metadata probe (แยกจาก token probe 20000+ และ identity probe 1000+)
_metadata_message_ids = itertools.count(30000, 10)

# CALLHOME_LISTEN_ADDRESS from the config file: 0.0.0.0 (all interfaces) or one IPv4 of this machine
HOST = load_environment().CALLHOME_LISTEN_ADDRESS
PORT = load_environment().CALLHOME_PORT
# time for fetch cpu/ram information from device
STATS_POLL_INTERVAL = 10
# shutdown: how long to wait for call-home connections to close (see stop())
STOP_WAIT_SECONDS = 5

# (bug 53) timeout ของ stats poll ต้อง "สั้นกว่ารอบ poll" เสมอ
#
# เดิม stats ใช้ timeout เดียวกับคำสั่งของผู้ใช้ (20 วิ) ทั้งที่ poll ทุก 10 วิ -
# timeout ครั้งเดียวก็กินเวลาทับรอบถัดไปแล้ว และเพราะ send_payload ถือ
# session["lock"] ตัวเดียวกับที่คำสั่งผู้ใช้ใช้ ผู้ใช้ที่กดสั่งงานตอนนั้นจะรอ lock
# เงียบ ๆ นานเป็นนาที ทั้งที่ stats เป็นแค่ข้อมูลประกอบที่พลาดได้
#
# 6 วิพอสำหรับ get_cpu_memory_information บนอุปกรณ์ที่ปกติ (probe_identity ตอน
# call-home ซึ่งยิงหลายคำสั่งติดกันยังจบได้เร็วกว่านั้น) - ถ้าอุปกรณ์ช้ากว่านี้
# แปลว่ามันมีปัญหาจริง ซึ่งเป็นสัญญาณที่เราอยากรู้ ไม่ใช่สิ่งที่ควรรอต่อไป
STATS_POLL_TIMEOUT = 6
CANDIDATE_CAPABILITY = "urn:ietf:params:netconf:capability:candidate:1.0"
WRITABLE_RUNNING_CAPABILITY = "urn:ietf:params:netconf:capability:writable-running:1.0"

# (bug 53) ถอยห่างเมื่อ poll ล้มเหลวติดกัน - ทุกครั้งที่ timeout แปลว่าคำสั่ง
# "ถูกส่งออกไปแล้วแต่ไม่มีใครอ่าน reply" ถ้ายิงซ้ำทุก 10 วิโดยไม่ถอย คำสั่งค้างจะ
# สะสมเพิ่มทีละ 1 ทุกรอบ (เจอจริง: อุปกรณ์เงียบ ~14 นาที ระบบสะสมคำสั่งค้าง 29 ตัว
# ขึ้นมาเอง พอกลับมาตอบต้องไล่ทิ้งอยู่ ~3.5 นาทีถึงจะปกติ)
#
# ตัวคูณ 2 เท่าจาก STATS_POLL_INTERVAL: 10 → 20 → 40 → 80 → 160 → 300 (เพดาน)
# ทำให้ช่วงอุปกรณ์เงียบ 14 นาที ยิงแค่ ~8 ครั้งแทน ~28 ครั้ง
#
# หมายเหตุ: การลด timeout ลงเหลือ 6 วิ (ข้างบน) ทำให้รอบ poll เร็วขึ้น = ยิ่งยิงถี่
# ขึ้นตอนอุปกรณ์เงียบ ถ้าไม่มี backoff คู่กัน backlog จะแย่กว่าเดิม - 2 ค่านี้ต้อง
# มาคู่กันเสมอ
STATS_BACKOFF_MAX = 300

# (bug 55) เกณฑ์ "ข้อมูลสดพอที่จะโชว์ให้ผู้ใช้เห็นได้"
#
# 30 วิ = 3 เท่าของรอบ poll ปกติ - ทนได้ถ้าพลาด 1-2 รอบ (เช่นถูกข้ามเพราะผู้ใช้
# กำลังสั่งงานอยู่ ซึ่งเป็นเรื่องปกติ) แต่ไม่ปล่อยให้ค่าเก่าค้างนานกว่านั้น
#
# user เลือกเอง: "เน้นข้อมูลใหม่ดีกว่า" - ถ้าไม่แน่ใจว่าสดพอ ให้บอกว่าไม่มีข้อมูล
# ดีกว่าโชว์ตัวเลขที่อาจไม่จริง
STATS_FRESH_SECONDS = 30

# (bug 55) ล้มเหลวติดกันกี่ครั้งถึงจะถือว่า "เชื่อมต่ออยู่แต่ไม่ตอบ"
#
# 2 ครั้ง (ประมาณ 30 วิ นับรวม backoff รอบแรก) - ครั้งเดียวอาจเป็นแค่จังหวะไม่ดี
# แต่ 2 ครั้งติดแปลว่าอุปกรณ์มีปัญหาจริง ผู้ใช้ควรรู้ก่อนจะกดสั่งงานแล้วไปเจอ timeout
STATS_UNRESPONSIVE_FAILURES = 2

# (bug 58) เวลาที่ยอมรอตอน "แอบดู" ว่าอุปกรณ์กลับมาแล้วหรือยังระหว่างช่วง backoff
#
# สั้นมากโดยเจตนา เพราะถ้าอุปกรณ์กลับมาจริง ข้อมูลจะ "นอนรออยู่ในบัฟเฟอร์ของ asyncssh
# แล้ว" ตั้งแต่วินาทีที่มันฟื้น (data_received() ทำงานอัตโนมัติไม่ว่าแอปจะอ่านหรือไม่)
# การอ่านจึงคืนค่าทันทีไม่ต้องรอ - 0.2 วิเผื่อไว้แค่กรณีข้อความมาไม่ครบก้อน
#
# ถ้ายังเงียบอยู่ก็เสียเวลาแค่ 0.2 วิต่อรอบ poll (10 วิ) และถือ lock สั้นมาก
STATS_IDLE_PROBE_TIMEOUT = 0.2


# (bug 100) นานแค่ไหนที่ "ไม่ได้รับไบต์ใดจากอุปกรณ์เลยแม้แต่ไบต์เดียว" ถึงจะถือว่าท่อตาย
#
# bug 68 เลิกตัด session ทุกครั้งที่ timeout ซึ่งถูกแล้ว (ผู้ใช้กรอกค่าที่ชนกับ config เดิม
# แล้วอุปกรณ์เงียบไป 20 วิ ไม่ควรโดนตัดการเชื่อมต่อ) แต่ยกหน้าที่ตัดสินให้ "probe ของ
# bug 58" ทั้งที่ probe ตัวนั้นตัดสินได้แค่ว่าจะเลิกถอยห่างไหม **ไม่เคยปิด session เลย**
# ผลคือถ้าท่อตายจริง ๆ (เจอจริง: C8000 อยู่หลัง edge router ที่ทำ NAT พอ NAT ทิ้ง state
# ฝั่งเราไม่ได้ FIN/RST อะไรเลย asyncssh จึงไม่เคยโยน ConnectionLost) session จะค้าง
# ตลอดกาล ทุกคำสั่งเสียเวลา 20 วิแล้ว 503 และอุปกรณ์ก็ไม่ call-home กลับมาเพราะยังคิดว่า
# ตัวเองต่ออยู่ - ผู้ใช้ติดตายจนกว่าจะ restart backend
#
# เกณฑ์ที่ใช้แยก 2 กรณีคือ **"มีไบต์เข้ามาไหม" ไม่ใช่ "timeout กี่ครั้ง"**
#   อุปกรณ์แค่ยุ่ง/กำลังคิดเรื่อง config -> เดี๋ยวก็ส่งอะไรกลับมา (จะกลายเป็น
#                                          NetconfDesync ซึ่งแปลว่ายังมีชีวิต) -> ล้างตัวจับเวลา
#   ท่อตายจริง                          -> เงียบสนิทไปเรื่อย ๆ -> ครบเวลาแล้วตัดทิ้ง
#
# 90 วิ = ยาวพอให้เคสของ bug 68 (เงียบ 20 วิแล้วตอบ) ผ่านไปได้สบาย ๆ และสั้นพอที่ผู้ใช้
# ยังรอไหว เพราะหลังตัดแล้ว call-home กลับมาใน 30-40 วิ (ยืนยันจากผลทดสอบข้อ 9.1.2b)
SILENCE_CUTOFF_SECONDS = 90

# (2026-09) Cisco NAT family ทั้งหมด (Source NAT: get_nat_dashboard/create_nat_policy/
# remove_nat_policy, Static NAT: get_static_nat_information/set_static_nat/
# remove_static_nat, Port Forwarding: get_port_forward_information/set_port_forward/
# remove_port_forward - ดู CISCO_NAT_QUARANTINE_COMMANDS ใน device_router.py) ที่
# timeout (NetconfSilent) หรือ desync (NetconfDesync) ทิ้งคำตอบที่ยังไม่รู้ผลไว้ในท่อ
# ของ session เดียวกัน - ถ้าคำสั่ง NAT ถัดไป (แม้จากผู้ใช้คนละแท็บ/รีเฟรชอัตโนมัติ)
# ยิงเข้าไปทันทีโดยไม่รู้ว่ายังมีคำตอบเก่าค้างอยู่ จะไปต่อคิวอยู่หลัง backlog นั้นแล้ว
# timeout ซ้ำอีก ซ้อนกันเรื่อยๆ - "quarantine" นี้ไม่ได้บล็อกคำสั่งอื่นของอุปกรณ์เดียวกัน
# เลย (session["lock"]/DeviceLock ทำหน้าที่นั้นอยู่แล้ว) แค่ปฏิเสธ "คำสั่ง NAT ใหม่"
# ทันทีแบบไม่แตะ wire จนกว่าคำตอบของคำสั่ง NAT ก่อนหน้าจะได้รับแล้วจริงๆ (เคลียร์เมื่อ
# ส่งสำเร็จ) หรือหมดเวลา quarantine เอง (กันไม่ให้ค้างตลอดไปถ้า reply หายจริง) - เคลียร์
# อัตโนมัติตอน session ปิด/call-home ใหม่ด้วยเพราะ _register_session สร้าง dict ใหม่
# ทั้งก้อนเสมอ (ดู _register_session) ไม่มีทางเหลือค้างข้าม session
CISCO_NAT_QUARANTINE_SECONDS = 25

def load_auth_keys() -> asyncssh.SSHKey | None:
    key_path = load_environment().SSH_KEY_PATH
    try:
        return asyncssh.read_private_key(str(key_path))
    except Exception as e:
        # None = no key is offered to devices (public_key_auth_requested returns None)
        print(f"WARNING: could not load rsa key: {e}")
        return None

MNG_USER = load_environment().MNG_USER
SSH_KEY = load_auth_keys()

NETCONF_END = "]]>]]>"
HELLO_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
    "<capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities>"
    f"</hello>{NETCONF_END}"
)


def _configuration_reply_rejected(reply: str) -> bool:
    """Detect both NETCONF rpc-error and Junos load-configuration failures.

    Junos reports a failed load through load-error-count/xnm:error rather than
    necessarily returning rpc-error. The old string check therefore committed
    the unchanged candidate and reported success.
    """
    if reply_rejected(reply):
        return True
    try:
        root = safe_fromstring(reply)
    except (ET.ParseError, TypeError):
        return True
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name == "load-error-count":
            try:
                if int((element.text or "0").strip()) > 0:
                    return True
            except ValueError:
                return True
        if local_name == "error" and element.tag.startswith("{http://xml.juniper.net/xnm/"):
            return True
    return False


def get_host_key_fingerprint(connection) -> str | None:
    try:
        host_key = connection.get_server_host_key()
        return host_key.get_fingerprint() if host_key else None
    except Exception:
        return None


async def read_dev_response(process, buf: list[str], timeout: float = 40) -> str:
    while NETCONF_END not in buf[0]:
        response = await asyncio.wait_for(
            process.stdout.read(65535),
            timeout=timeout,
        )
        if not response:
            raise ConnectionError("Channel closed")
        buf[0] += response
    msg, buf[0] = buf[0].split(NETCONF_END, 1)
    return msg.strip()


def _extract_message_id(xml: str) -> str | None:
    match = re.search(r'message-id\s*=\s*"([^"]+)"', xml)
    return match.group(1) if match else None


# (bug 57) เพดานกันการอ่านวนไม่จบ - ใช้กับ "reply ที่ระบุตัวตนไม่ได้" เท่านั้น
# ไม่ได้ใช้กับ reply เก่าของเราเองแล้ว (ดูเหตุผลใน _read_matching_reply)
MAX_UNKNOWN_REPLY_DISCARDS = 5


# (bug 57) แยกความล้มเหลว 2 แบบที่เดิมปนกันเป็นก้อนเดียว
#
# ทั้งคู่เคยโยนออกมาเป็น TimeoutError/RuntimeError ปนกัน ทำให้ทุกชั้นที่รับต่อ
# ปฏิบัติเหมือนกันหมด ทั้งที่ความหมายต่างกันสิ้นเชิงและควรตอบสนองคนละแบบ:
#
#   NetconfSilent  - ไม่ได้รับไบต์ใดเลยจนหมดเวลา = อุปกรณ์เงียบจริง
#                    → ควรถอยห่าง / ตัด session ให้ต่อใหม่
#   NetconfDesync  - ได้รับข้อมูลแล้วแต่ยังไล่ reply เก่าไม่หมด = อุปกรณ์ยังมีชีวิต
#                    → ห้ามถอยห่าง ห้ามตัด รอบหน้าจะไล่หมดเอง
#
# NetconfSilent สืบทอด TimeoutError เพื่อให้โค้ดเดิมที่ดัก asyncio.TimeoutError
# ยังทำงานเหมือนเดิม (asyncio.TimeoutError เป็น alias ของ TimeoutError ตั้งแต่ 3.11)
class NetconfSilent(TimeoutError):
    """อุปกรณ์ไม่ส่งข้อมูลใดกลับมาเลยจนหมดเวลา"""


class NetconfDesync(RuntimeError):
    """อุปกรณ์ยังส่งข้อมูลอยู่ แต่เป็น reply ของ request เก่าที่ค้างในท่อ"""


# (bug 100) เงียบสนิทนานเกิน SILENCE_CUTOFF_SECONDS = ถือว่าท่อตาย ปิด session ไปแล้ว
# แยกชนิดออกมาเพื่อให้ device_router ตอบผู้ใช้ให้ตรงความจริง - ข้อความของ NetconfSilent
# ธรรมดาบอกว่า "การเชื่อมต่อยังไม่ถูกตัด ใช้คำสั่งอื่นต่อได้ทันที" ซึ่งใช้กับเคสนี้ไม่ได้
class NetconfDead(NetconfSilent):
    """เงียบสนิทนานเกินกำหนด - session ถูกปิดทิ้งแล้ว รอ call-home ใหม่"""


def _is_stale_reply(reply_id: str, expected_id: str) -> bool:
    """reply นี้เป็นของ request เก่าของเราเองแน่นอนหรือไม่

    message-id ที่เราสร้างมาจาก itertools.count() ซึ่งเพิ่มขึ้นอย่างเดียว และ NETCONF
    over SSH เป็น stream ที่เรียงลำดับ - reply ที่มี id "น้อยกว่า" ตัวที่เรากำลังรอ
    จึงเป็นของ request เก่าของเราเองแน่นอน 100% ไม่ต้องจดจำอะไรไว้เลย

    เดิมออกแบบไว้ว่าจะเก็บ set ของ id ที่ค้าง แต่วิธีนั้นต้องบันทึกให้ครบทั้ง 3 จุดใน
    send_payload (คำสั่งหลัก / commit ของ Junos / discard-changes) พลาดจุดใดจุดหนึ่ง
    ก็เหลือขยะที่ระบบไม่รู้จัก และ set เองก็โตไม่มีขอบเขต - การเทียบเลขตรง ๆ
    ให้ผลเหมือนกันโดยไม่ต้องมี state อะไรเลย
    """
    try:
        return int(reply_id) < int(expected_id)
    except (TypeError, ValueError):
        return False


async def _read_matching_reply(process, buf: list[str], expected_id: str, timeout: float = 20) -> str:
    # แก้บั๊กจริงที่เจอ: send_payload เดิมเชื่อว่า reply ถัดไปที่อ่านได้จาก buffer
    # เป็นของ request ที่เพิ่งส่งไปเสมอ ไม่เคยเช็ค message-id เลย - ถ้า request
    # ก่อนหน้า timeout ไปแล้ว (read_dev_response โยน TimeoutError ออกมา ปล่อย
    # lock คืน) แต่อุปกรณ์ตอบกลับมาช้าทีหลัง reply เก่านั้นจะยังค้างอยู่ใน buffer/
    # pipe รอ request ถัดไปมาอ่านต่อ - request ถัดไปเลยได้ reply ผิดตัว (ยืนยันจริง:
    # get_vlan_information เคยได้ arp-data/routing-state ของ request อื่นกลับมา
    # แทน) วนอ่านทิ้งจน message-id ตรงกับที่คาดไว้ก่อนค่อยคืนค่า
    #
    # (bug 57) เดิมจำกัดการอ่านทิ้งไว้ที่ 5 ครั้งแบบตาบอด ซึ่งพิสูจน์จาก log จริงแล้วว่า
    # น้อยเกินไป: backoff ของ stats poll ผลิต request ค้างได้ 6 ตัว แต่โควตาอ่านทิ้ง
    # 5 ครั้งรับได้จริงแค่ 4 ตัว (ครั้งที่ 5 ต้องเป็นตัวที่ใช่) - poll แรกหลังอุปกรณ์ฟื้น
    # จึงล้มเหลวเสมอ แล้วถอยต่ออีก 300 วิ ทำให้ฟื้นช้ากว่าที่ควร ~5 นาที
    #
    # และที่สำคัญกว่านั้น: โควตานี้ใช้ร่วมกับ "คำสั่งของผู้ใช้" ด้วย (send_payload ตัว
    # เดียวกัน) - ขยะที่ stats poll ทิ้งไว้จึงทำให้คำสั่งของผู้ใช้ล้มเหลวได้ ซึ่งขัดกับ
    # หลักที่ว่างานของผู้ใช้สำคัญสูงสุด ส่วน stats เป็นแค่ของเสริม
    #
    # เปลี่ยนเป็น: reply ที่ id น้อยกว่าที่รอ = ของเราเองแน่นอน ทิ้งได้ไม่จำกัดจำนวน
    # โดยคุมด้วย "เวลา" แทน "จำนวนครั้ง" - ซึ่งจำกัดเวลาถือ lock ให้เหลือ timeout
    # เดียวด้วย (เดิมอ่านแต่ละครั้งได้ timeout เต็ม รวมได้ถึง 5 เท่า)
    deadline = time.monotonic() + timeout
    drained: list[str] = []
    unknown = 0
    received_any = False

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            reply = await read_dev_response(process, buf, timeout=remaining)
        except asyncio.TimeoutError:
            break

        received_any = True
        reply_id = _extract_message_id(reply)

        if reply_id is None:
            # (bug 57) reply ที่ไม่มี message-id - เดิมถูกรับเป็นคำตอบของเราทันทีโดยไม่มี
            # ร่องรอยอะไรเลย ซึ่งเป็นกับดักถ้าวันหนึ่งใช้ notification (Cisco ประกาศ
            # notification:1.0 + interleave:1.0 ไว้ และ notification ไม่มี message-id)
            # ยังไม่เปลี่ยนพฤติกรรมเพราะยังไม่รู้ว่ามีรุ่นไหนตอบแบบนี้จริงไหม - log ไว้
            # ก่อนเพื่อเก็บหลักฐาน ถ้ารันไปนาน ๆ แล้วไม่เคยขึ้นเลยค่อยเปลี่ยนเป็นทิ้ง
            print(
                f"[!] ได้รับ reply ที่ไม่มี message-id ({len(reply)} bytes) - "
                f"รับเป็นคำตอบของ message-id={expected_id} ตามพฤติกรรมเดิม"
            )
            return reply

        if reply_id == expected_id:
            if drained:
                print(
                    f"[!] ล้าง reply เก่าที่ค้างในท่อ {len(drained)} ตัว "
                    f"(message-id {drained[0]}-{drained[-1]}) ก่อนอ่านคำตอบของ {expected_id}"
                )
            return reply

        if _is_stale_reply(reply_id, expected_id):
            drained.append(reply_id)
            continue

        # id ที่ "มากกว่า" ตัวที่รอ หรือแปลงเป็นเลขไม่ได้ - ไม่ควรเกิดกับ stream ที่
        # เรียงลำดับ ถ้าเกิดแปลว่ามีอะไรผิดปกติที่เราไม่เข้าใจ จำกัดจำนวนไว้กันวนไม่จบ
        unknown += 1
        print(f"[!] ได้รับ reply ที่ระบุตัวตนไม่ได้ (message-id={reply_id}, กำลังรอ {expected_id})")
        if unknown >= MAX_UNKNOWN_REPLY_DISCARDS:
            break

    # หมดเวลาแล้ว - แยกให้ชัดว่าเงียบสนิทหรือแค่ไล่ไม่ทัน
    if drained or received_any:
        raise NetconfDesync(
            f"ยังไล่ reply เก่าไม่หมด (ล้างไปแล้ว {len(drained)} ตัว) ยังไม่เจอคำตอบของ "
            f"message-id={expected_id} - อุปกรณ์ยังส่งข้อมูลอยู่ ลองใหม่อีกครั้ง"
        )
    raise NetconfSilent(
        f"อุปกรณ์ไม่ส่งข้อมูลใดกลับมาเลยภายใน {timeout} วินาที (รอคำตอบของ message-id={expected_id})"
    )


def _to_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# Cisco ไม่ให้ up-time สำเร็จรูปเหมือน Juniper (ดู get_cpu_memory_information
# ใน cisco_iosxe.py) มีแค่ boot-time/current-time เป็น ISO timestamp สอง
# ค่าแยกกัน - คำนวณผลต่างแล้ว format เป็นสตริงรูปแบบเดียวกับ Juniper's up-time
# เป๊ะ ("1 hour, 39 minutes, 47 seconds" - ยืนยันจาก re10.txt) ให้หน้าเว็บไม่ต้อง
# รู้เลยว่ายี่ห้อไหนคำนวณเองยี่ห้อไหนอุปกรณ์ให้มาสำเร็จรูป
def _parse_cisco_uptime(boot_str: str | None, curr_str: str | None) -> str | None:
    if not boot_str or not curr_str:
        return None
    try:
        dt_boot = datetime.fromisoformat(boot_str)
        dt_curr = datetime.fromisoformat(curr_str)
        total_seconds = int((dt_curr - dt_boot).total_seconds())
        if total_seconds < 0:
            return None
        hours, rem = divmod(total_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        parts = []
        if hours > 0:
            parts.append(f"{hours} hour{'s' if hours > 1 else ''}")
        if minutes > 0:
            parts.append(f"{minutes} minute{'s' if minutes > 1 else ''}")
        if seconds > 0 or not parts:
            parts.append(f"{seconds} second{'s' if seconds > 1 else ''}")
        return ", ".join(parts)
    except Exception:
        return None


# Huawei sysUpTime เป็น SNMP TimeTicks หน่วย 1/100 วินาที; format ให้เหมือน Cisco
# เพื่อให้ Basic Info ใช้แถว Uptime เดิมโดยไม่ต้องรู้จักยี่ห้อ. ค่าไม่ถูกต้องคืน None
# เพราะ uptime เป็นข้อมูลประกอบ ห้ามทำให้ stats poller เข้า backoff.
def _parse_huawei_uptime(ticks: object) -> str | None:
    value = int(ticks)
    if value is None or value < 0:
        return None
    hours, rem = divmod(value, 3600)
    minutes, seconds = divmod(rem, 60)
    parts = []
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours > 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes > 1 else ''}")
    if seconds > 0 or not parts:
        parts.append(f"{seconds} second{'s' if seconds > 1 else ''}")
    return ", ".join(parts)


def _extract_huawei_uptime(normalized: dict) -> str | None:
    try:
        payload = normalized.get("payload", {})
        data = payload.get("data", payload)
        ticks = data.get("system", {}).get("systemInfo", {}).get("sysUpTime")
        return _parse_huawei_uptime(ticks)
    except Exception:
        return None


# แปลงผล get_cpu_memory_information ที่ normalize แล้ว (JSON mirror โครงสร้าง
# XML - ดู normalize_generic) ให้เป็นรูปร่างเดียวกันไม่ว่ายี่ห้อไหน เพราะ
# frontend/endpoint ที่อ่าน self.stats ต่อไม่ควรต้องรู้จัก path เฉพาะยี่ห้อเลย -
# คืน None ถ้า parse ไม่ได้ (ไม่ raise - _poll_one_stat กันไว้ให้แล้วแต่กันเหนียว
# อีกชั้น ไม่ให้ path ผิดของยี่ห้อหนึ่งทำอีกยี่ห้อพังไปด้วย)
def _extract_stats(vendor: str, normalized: dict) -> dict | None:
    try:
        payload = normalized.get("payload", {})
        if vendor == "juniper":
            # ยืนยันจริงกับอุปกรณ์แล้ว (BR1-Firewall-1, 2026-07-30 + Test-Junos-FW/
            # test-junos-sw ใน re10.txt) - get-route-engine-information ไม่ผ่าน
            # <get>/<filter> เลยไม่ถูกห่อด้วย <data> เหมือน Cisco - route-engine
            # เป็นลูกตรงของ rpc-reply เสมอ
            re_data = payload.get("route-engine-information", {}).get("route-engine", {})
            if isinstance(re_data, list):  # หลาย routing-engine (คลัสเตอร์/dual RE) - เอาตัวแรกพอ
                re_data = re_data[0] if re_data else {}
            cpu_idle = _to_float(re_data.get("cpu-idle"))
            # RAM มาตรฐานกลาง = Control Plane memory ก่อนเสมอ (ดึงได้ทุกรุ่น
            # ตามข้อจำกัดสถาปัตยกรรมที่ user ระบุ) - fallback chain ตามรุ่นที่
            # ไม่มี field นี้: system-total-util (รุ่นที่ไม่แยก control/data
            # plane) -> buffer-utilization (Juniper Switch/EX - ยืนยันจาก
            # re10.txt's test-junos-sw ที่มีแค่ tag นี้ตัวเดียว ไม่มี
            # memory-control-plane-util/memory-system-total-util เลย)
            mem_util = _to_float(re_data.get("memory-control-plane-util"))
            if mem_util is None:
                mem_util = _to_float(re_data.get("memory-system-total-util"))
            if mem_util is None:
                mem_util = _to_float(re_data.get("memory-buffer-utilization"))
            return {
                "cpu_percent": round(100 - cpu_idle, 1) if cpu_idle is not None else None,
                "memory_percent": round(mem_util, 1) if mem_util is not None else None,
                "uptime": re_data.get("up-time") or None,
                "model": re_data.get("model") or None,
            }
        if vendor == "cisco":
            # ยืนยันจริงจาก re11.txt (Cisco Virtual XE ตัวจริง 2026-08-02): RPC
            # นี้เป็น <get> ธรรมดา (ไม่ใช่ custom RPC เหมือน Juniper) ตาม RFC 6241
            # ผลลัพธ์เลยถูกห่อด้วย <data> เสมอ - เดิม**ไม่เคย unwrap ชั้นนี้เลย**
            # (เข้าใจผิดคิดว่า payload คือ data โดยตรง) ทำให้ .get() ทุกจุดพลาด
            # หมดกลายเป็น None ทั้งก้อน - นี่คือ root cause จริงที่ Cisco ไม่ขึ้น
            # อะไรบนหน้าเว็บเลยสักตัว (ไม่ใช่แค่ path field ผิด)
            data = payload.get("data", payload)
            cpu_util = data.get("cpu-usage", {}).get("cpu-utilization", {})
            hw_sys = (
                data.get("device-hardware-data", {})
                .get("device-hardware", {})
                .get("device-system-data", {})
            )

            # memory-statistic เป็น list เสมอ (3 รายการ: processor/IOS/หน่วยความจำ
            # ย่อยอื่นๆ - ยืนยันจาก re11.txt) รายการแรกคือ Processor/Control Plane
            # RAM ตรงกับมาตรฐานกลางที่ใช้ - อยู่ใต้ "data" ตรงๆ (sibling ของ
            # device-hardware-data) ไม่ใช่ลูกของ device-system-data แบบที่โค้ด
            # เดิมเข้าใจผิด
            mem_stats = data.get("memory-statistics", {}).get("memory-statistic", [])
            if isinstance(mem_stats, list) and mem_stats:
                mem_item = mem_stats[0]
            elif isinstance(mem_stats, dict):
                mem_item = mem_stats
            else:
                mem_item = {}
            total_mem = _to_float(mem_item.get("total-memory"))
            used_mem = _to_float(mem_item.get("used-memory"))
            mem_percent = (
                round((used_mem / total_mem) * 100, 1) if total_mem and used_mem is not None else None
            )

            cpu_percent = _to_float(cpu_util.get("five-seconds"))
            uptime_str = _parse_cisco_uptime(hw_sys.get("boot-time"), hw_sys.get("current-time"))

            return {
                "cpu_percent": round(cpu_percent, 1) if cpu_percent is not None else None,
                "memory_percent": mem_percent,
                "uptime": uptime_str,
                "model": None,
            }
        if vendor == "huawei":
            # CE12800 คืน CPU/RAM หลายบอร์ด; ห้ามเดา slot เพราะตำแหน่ง MPU
            # เปลี่ยนตามรุ่น/การเสียบบอร์ดได้. boardResState มี boardName อยู่แถว
            # เดียวกับ resource จึงเลือกเฉพาะชื่อที่มี MPU ก่อน แล้วใช้ position
            # เดียวกันจับคู่ memoryInfos. ผู้ใช้เลือก osMemoryUsage เป็น RAM เพราะ
            # เป็นหน่วยความจำ OS; ไม่ใช้ memoryUsage แบบรวมของ boardResState.
            data = payload.get("data", payload)
            devm = data.get("devm", {})
            board_rows = devm.get("boardResStates", {}).get("boardResState", [])
            if isinstance(board_rows, dict):
                board_rows = [board_rows]
            if not isinstance(board_rows, list):
                return None

            mpu = next(
                (
                    row for row in board_rows
                    if isinstance(row, dict) and "MPU" in str(row.get("boardName", "")).upper()
                ),
                None,
            )
            if not mpu or mpu.get("boardPosition") in (None, ""):
                return None

            memory_rows = devm.get("memoryInfos", {}).get("memoryInfo", [])
            if isinstance(memory_rows, dict):
                memory_rows = [memory_rows]
            if not isinstance(memory_rows, list):
                return None
            mpu_position = str(mpu["boardPosition"])
            memory = next(
                (
                    row for row in memory_rows
                    if isinstance(row, dict) and str(row.get("position", "")) == mpu_position
                ),
                None,
            )
            cpu_percent = _to_float(mpu.get("cpuUsage"))
            memory_percent = _to_float(memory.get("osMemoryUsage")) if memory else None
            # payload ขาด field หรือไม่พบ MPU ต้องคืน None เพื่อไม่ให้ poller
            # เข้า backoff จากข้อมูล monitoring ที่อ่านไม่ครบ
            if cpu_percent is None or memory_percent is None:
                return None
            return {
                "cpu_percent": round(cpu_percent, 1),
                "memory_percent": round(memory_percent, 1),
            }
        return None
    except Exception:
        return None


# (2026-09-19) keypair ต้องเป็นของใครของมัน ต่อ connection - ห้ามส่ง client_keys= ให้ listen_reverse
#
# อาการที่เจอจริง: Huawei call-home เข้าไม่ได้เลยถ้า Cisco เข้ามาก่อน (pcap: KEX ผ่าน,
# NEWKEYS ผ่าน, พอเราส่ง publickey request Huawei ตอบแล้ว RST ทันที วนใหม่ทุก 1.5 วิ
# ไม่หยุด) แต่ถ้า Huawei เข้าก่อนกลับปกติ และ Cisco/Juniper ตามเข้ามาได้ไม่มีปัญหา
# log ฝั่งเราไม่เห็นอะไรเลยเพราะ acceptor ถูกเรียกหลัง auth สำเร็จเท่านั้น
#
# ต้นเหตุ (asyncssh 2.23.0, ยืนยันจาก source):
#   - listen_reverse() สร้าง SSHClientConnectionOptions ครั้งเดียว ทุก connection ได้
#     SSHLocalKeyPair "ตัวเดียวกัน" (connection copy แค่ list ไม่ได้ copy สมาชิก)
#   - ตอน auth ถ้าอุปกรณ์ส่ง server-sig-algs (ext-info) มา asyncssh จะเรียก
#     keypair.set_sig_algorithm() ซึ่ง "เขียนทับ object ร่วม" เป็น rsa-sha2-256
#   - ถ้าอุปกรณ์ไม่ส่งมา asyncssh จะ "ไม่รีเซ็ต" แต่ใช้ค่าที่ค้างอยู่
#   - Huawei ประกาศแค่ ssh-dss,ssh-rsa,ecdsa-sha2-nistp521 ไม่มี ext-info-s
#     -> รับเฉพาะ ssh-rsa (SHA-1) ซึ่งเป็นเพดานของอุปกรณ์แล้ว
#   ผล: Cisco เข้าก่อนตั้งค่าค้างเป็น rsa-sha2-256, Huawei เข้าทีหลังถูกเซ็นด้วย alg
#   ที่มันไม่รู้จัก -> ปฏิเสธ
#
# ทางแก้: คืน key ผ่าน public_key_auth_requested() ซึ่ง asyncssh เรียก "ต่อ connection"
# และห่อผลด้วย load_keypairs() เป็น object ใหม่ทุกครั้ง -> ค่าเริ่มต้น ssh-rsa เสมอ แล้วค่อย
# เลือกตามที่อุปกรณ์นั้นประกาศ (Cisco/Juniper ได้ rsa-sha2, Huawei ได้ ssh-rsa) ไม่ว่าใคร
# เข้าก่อนหลัง และไม่ลดความปลอดภัยของอุปกรณ์อื่น
#
# อย่าย้ายกลับไปใช้ client_keys=SSH_KEY เพื่อ "ทำให้ง่ายขึ้น" - บั๊กจะกลับมาแบบเงียบ ๆ และ
# เกิดเฉพาะบางลำดับการเชื่อมต่อ (เป็นบั๊กของ asyncssh ฝั่ง listen_reverse ยังไม่ได้แก้ upstream)
class _CallhomeClient(asyncssh.SSHClient):
    def __init__(self):
        # asyncssh จะเรียก public_key_auth_requested() ซ้ำไปเรื่อย ๆ จนกว่าจะได้ None
        # ถ้าคืน SSH_KEY ทุกครั้ง อุปกรณ์ที่ปฏิเสธ key จะโดนยิงดอกเดิมซ้ำจนชน
        # authentication-retries และอาจโดน IP-block (Huawei) / login block-for (Cisco)
        # -> เสนอครั้งเดียวต่อ connection แล้วจบ พฤติกรรมตอนถูกปฏิเสธจึงเหมือนเดิมเป๊ะ
        self._offered = False

    def public_key_auth_requested(self):
        if self._offered:
            return None
        self._offered = True
        return SSH_KEY


class CallhomeService:
    def __init__(self):
        self.listener = None
        self.sessions = {}
        self.stats = {}  # dev_id -> {cpu_percent, memory_percent, uptime, model, polled_at} ล่าสุด (ดู _poll_stats_loop)
        self._stats_task = None
        # (dynamic feature ขั้นที่ 3) dev_id -> (connection, task) ของงานตรวจความสามารถ ดู _start_capability_probe
        self._capability_tasks = {}
        # (bug 53/54) นับความล้มเหลวติดกันต่ออุปกรณ์ ใช้ทั้งคำนวณ backoff และยุบ
        # บรรทัด log ซ้ำ - ล้างทิ้งทันทีที่ poll สำเร็จ หรือตอน session ปิด
        self._stats_failures = {}   # dev_id -> จำนวนครั้งที่ล้มเหลวติดกัน
        self._stats_skip_until = {} # dev_id -> เวลา (monotonic) ที่จะกลับมา poll อีกครั้ง
        # ตัวจำแนก connection (fingerprint reconnect / first-enrollment token) + quarantine limiter
        # เท่านั้น (อ้าง AsyncSessionFactory ตอนเรียก ไม่ผูกไว้ตอนสร้าง)
        self.auth_router = CallhomeAuthRouter(lambda: AsyncSessionFactory())

    async def start(self, host: str = HOST, port: int = PORT):
        # Phase 11: token mode ต้องผ่าน preflight (อ่านอย่างเดียว) ก่อนเปิด listener - ไม่ผ่านให้ raise ไม่เปิดรับ connection
        await enforce_startup_mode(lambda: AsyncSessionFactory(), self.auth_router.mode)
        try:

            # (2026-09-19) เลิกส่ง client_keys= ให้ listen_reverse - ดูเหตุผลยาวที่ _CallhomeClient
            
            # client_keys=None (ห้ามใช้ []) - list ว่างจะทำให้ asyncssh ไปโหลด key เริ่มต้น
            # จาก ~/.ssh (เครื่องนี้มี id_ed25519) มาลองก่อน เสียโควตา authentication-retries
            # ของอุปกรณ์ไปเปล่า ๆ ส่วน None ปิดทั้ง key เริ่มต้นและ ssh-agent แต่ยังเปิด
            # publickey auth และยังเรียก public_key_auth_requested() ตามปกติ
            self.listener = await asyncssh.listen_reverse(
                host=host,
                port=port,
                username=MNG_USER,
                client_factory=_CallhomeClient,
                client_keys=None,
                # known_hosts=None: ไม่ใช้ไฟล์ known_hosts ของ asyncssh เพราะ callhome ไม่มี known_hosts
                # ที่แจกล่วงหน้าให้ pin ได้ - ระบบทำ host-key pinning เองที่ชั้น application แบบ TOFU แทน:
                # ครั้งแรก (activation) pin fingerprint ของ host key อุปกรณ์ลง Device_Information.dev_fingerprint
                # (ดู device_enrollment_activation.py) จากนั้นทุก reconnect ต้องโชว์ host key ที่ fingerprint
                # ตรงเป๊ะ (route_by_fingerprint แม็ปอุปกรณ์ด้วย fingerprint + is_trusted_session ตรวจซ้ำ fail-closed)
                # ความเสี่ยงที่เหลือคือ MITM เฉพาะ "ครั้งแรก" ซึ่งเป็นข้อจำกัดของ TOFU - กันที่ชั้น network
                # (Tailscale ACL + egress ของ VM ดู planning/deployment_security.md) ไม่ใช่ที่โค้ด
                known_hosts=None,
                reuse_address=True,
                acceptor=self.accept,
                signature_algs=['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519'],
            )
            print(f"[*] Call-home listener on {host}:{port}")
            self._stats_task = asyncio.create_task(self._poll_stats_loop())
        except OSError as oserr:
            print(f"Call-home listener unavailable on {host}:{port}: due to -> {oserr}")

    async def stop(self):
        if self._stats_task:
            self._stats_task.cancel()
            try:
                await self._stats_task
            except asyncio.CancelledError:
                pass
            self._stats_task = None
        await self._cancel_all_capability_probes()
        if self.listener:
            self.listener.close()
            # Python 3.12+: wait_closed() รอจน "ทุก connection" ปิด ไม่ใช่แค่ socket ที่ listen -
            # call-home ของอุปกรณ์เปิดค้างตลอด จึงรอไม่จบจน systemd ฆ่าทิ้งที่ 90 วิ (stop/restart/
            # install.sh ช้าจนนึกว่าค้าง) ปิดทุก session เองก่อน แล้วรอไม่เกิน STOP_WAIT_SECONDS
            # (เผื่อ connection ที่ยังไม่เข้า sessions เช่นกำลัง enroll) - อุปกรณ์จะ call-home กลับเองหลังเริ่มใหม่
            for session in list(self.sessions.values()):
                connection = session.get("connection")
                if connection is not None:
                    try:
                        connection.close()
                    except Exception as exc:
                        print(f"[!] Failed to close call-home connection on shutdown: {exc}")
            try:
                await asyncio.wait_for(self.listener.wait_closed(), STOP_WAIT_SECONDS)
            except asyncio.TimeoutError:
                print(f"[!] Call-home connections still open after {STOP_WAIT_SECONDS}s - stopping anyway")

    # (bug 42) บังคับตัด call-home connection ของอุปกรณ์ที่ระบุทันที - ใช้ตอนลบอุปกรณ์
    # ออกจากระบบ (delete_device_full / delete_user_full) เพราะการลบแถวใน database
    # อย่างเดียวไม่ได้ทำให้อุปกรณ์รู้ตัว มันยังเปิด SSH channel ค้างไว้เหมือนเดิมและไม่
    # call-home ใหม่ ทำให้ลงทะเบียนอุปกรณ์ตัวเดิมซ้ำแล้วค้าง "pending" จนกว่า TCP
    # keepalive จะ timeout เอง (ไม่มีกำหนดแน่นอน ขึ้นกับ network/NAT)
    #
    # ไม่ pop sessions/stats ที่นี่ - ปล่อยให้ finally ใน accept() เป็นคนล้างตามปกติ
    # หลัง wait_closed() คืนค่า (จุดเดียวจบ ไม่ต้องล้างซ้ำหลายที่ให้หลุดกันเอง)
    #
    # ครอบ try/except ไว้เพราะเป็นการเก็บกวาด - ห้ามทำให้การลบอุปกรณ์ล้มเหลวตามไปด้วย
    # (bug 55) สรุป "สุขภาพจริง" ของอุปกรณ์ให้ API ใช้ตอบผู้ใช้
    #
    # เดิมทั้งระบบตัดสินว่าอุปกรณ์ออนไลน์จาก "มี session อยู่ใน dict ไหม" อย่างเดียว
    # ซึ่งเป็นจริงตราบใดที่ TCP ยังต่ออยู่ - แต่จาก log จริงพบว่าอุปกรณ์ TCP ต่ออยู่
    # แต่ไม่ตอบ NETCONF เลยนาน ~14 นาที ระหว่างนั้นหน้าเว็บขึ้น "Online" และโชว์
    # CPU/RAM ค่าเก่าเป็นค่าปัจจุบัน โดยไม่มีอะไรบอกผู้ใช้เลย
    #
    # ตัวนับ _stats_failures ที่เพิ่มไปตอนแก้ bug 53 คือสัญญาณที่ต้องการพอดี -
    # ไม่ต้องคำนวณอะไรใหม่ แค่เอามาใช้
    #
    # คืน 3 สถานะแทน 2:
    #   connected=False              -> ไม่มี session (TCP ขาด)
    #   connected=True,  responsive=False -> ต่ออยู่แต่ไม่ตอบ (สถานะที่หายไปเดิม)
    #   connected=True,  responsive=True  -> ปกติ
    def device_health(self, dev_id: str) -> dict:
        connected = dev_id in self.sessions
        failures = self._stats_failures.get(dev_id, 0)
        return {
            "connected": connected,
            "responsive": connected and failures < STATS_UNRESPONSIVE_FAILURES,
            "failed_polls": failures,
        }

    # (bug 55) คืน stats เฉพาะที่ "สดพอ" - ถ้าเก่ากว่าเกณฑ์คืน None พร้อมบอกอายุ
    #
    # เดิม get_device_stats fallback มาอ่าน self.stats ตรง ๆ ซึ่งไม่มี TTL เลย
    # (ล้างเฉพาะตอน session ปิด) ค่าเก่าจึงค้างอยู่ไม่มีกำหนดระหว่างที่อุปกรณ์ไม่ตอบ
    # - ตรงข้ามกับเจตนาของ Redis TTL 15 วิ ที่ตั้งไว้เพื่อ "ไม่ให้โชว์ค่าเก่าค้าง"
    # พอดี (คอมเมนต์เดิมเขียนเจตนานั้นไว้ห่างจากบรรทัดที่ล้มมันแค่ 4 บรรทัด)
    def fresh_stats(self, dev_id: str) -> tuple[dict | None, float | None]:
        stat = self.stats.get(dev_id)
        if not stat:
            return None, None
        polled_at = stat.get("polled_at")
        if not polled_at:
            return None, None
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(polled_at)).total_seconds()
        except (TypeError, ValueError):
            return None, None
        return (stat if age <= STATS_FRESH_SECONDS else None), age

    # (bug 59) ลงทะเบียน session ใหม่ + ไล่ตัวเก่าที่ค้างอยู่ออก
    #
    # อุปกรณ์เดิมต่อ call-home เข้ามาใหม่ทั้งที่ session เก่ายังค้างอยู่ในตารางได้
    # (เจอจริงจาก pcap: สายขาด -> TCP เก่าไม่มีใครบอกว่าตาย -> อุปกรณ์ต่อเข้ามาใหม่)
    # เดิมโค้ดทับ self.sessions[dev_id] ทิ้งเฉยๆ ทำให้ connection เก่ายังเปิดค้างโดยไม่มี
    # ใครอ้างถึงได้อีกเลย - ต้องจับตัวเก่าไว้แล้วสั่งปิดเอง
    #
    # ลำดับสำคัญมาก: ลงทะเบียนตัวใหม่ให้เสร็จ *ก่อน* แล้วค่อยปิดตัวเก่า เพราะการปิดจะ
    # ปลุก handler ของตัวเก่าให้วิ่งเข้า _release_session() ซึ่งต้องเห็นตารางที่มีตัวใหม่
    # อยู่แล้วถึงจะรู้ว่าไม่ใช่ของตัวเองและไม่ไปล้างทิ้ง
    def _register_session(
        self, dev_id: str, connection, process, buffer, vendor: str,
        capabilities: list[str] | None = None,
    ):
        previous = self.sessions.get(dev_id)

        self.sessions[dev_id] = {
            "connection": connection,
            "process": process,
            "buffer": buffer,
            "lock": asyncio.Lock(),
            "vendor": vendor,
            "capabilities": set(capabilities or []),
            # (bug 100) เวลาที่เริ่ม "ไม่ได้ยินอะไรจากอุปกรณ์เลย" - None = ปกติ
            "silent_since": None,
        }

        # (bug 60) connection ใหม่ = ตั้งต้นใหม่หมด ประวัติความล้มเหลวของ session ที่ตาย
        # ไปแล้วใช้ตัดสิน session นี้ไม่ได้เลย
        #
        # เจอจริงหลังแก้ bug 59: อุปกรณ์ถูกถอดสาย 30 นาที ตัวนับไต่ไปถึง 11 ครั้ง
        # (backoff ตันที่ 300 วิ) พอเสียบกลับ call-home เข้ามาใหม่สำเร็จทันที แต่หน้าเว็บ
        # ยังขึ้นค้างอีก ~3 นาทีเพราะ 2 อย่างนี้ข้ามมาจาก session เก่า:
        #   1. _stats_skip_until -> poll ตัวใหม่ถูกข้ามจนกว่า backoff เดิมจะหมด
        #   2. _stats_failures   -> device_health() เห็น 11 >= 2 จึงตอบ unresponsive
        # ที่น่าสังเกตคือโค้ด "ก่อนแก้ bug 59" ล้างสองตัวนี้ให้พอดี แต่ล้างจากที่ผิด คือ
        # ล้างใน finally ของ session เก่าซึ่งเป็นบรรทัดเดียวกับที่ไปลบ session ใหม่ทิ้ง
        # พอปิดรูนั้นการล้างจึงหายไปด้วย - ที่ถูกคือล้างตอน "ลงทะเบียนตัวใหม่" แบบนี้
        self._reset_stats_failure(dev_id)
        self.stats.pop(dev_id, None)  # ค่า CPU/RAM ของ session เก่าไม่ใช่ของตัวใหม่

        if previous is not None and previous.get("connection") is not connection:
            print(f"[!] {dev_id} ต่อเข้ามาใหม่ทั้งที่ session เก่ายังค้างอยู่ - ปิด session เก่าทิ้ง")
            try:
                previous["connection"].close()
            except Exception as exc:
                print(f"[!] ปิด session เก่าของ {dev_id} ไม่สำเร็จ: {exc}")

    # (bug 59) ล้าง session ตอน connection ปิด - แต่ล้างเฉพาะที่เป็น "ของตัวเอง" จริงๆ
    #
    # เดิม pop ตาม dev_id ดื้อๆ ซึ่งผิดทันทีที่มี session ใหม่เข้ามาแทนที่แล้ว
    # เคสจริงที่จับได้จาก pcap: อุปกรณ์ call-home ใหม่สำเร็จตอน t=988.0 แล้ว handler ของ
    # connection เก่าตื่นขึ้นมาตอน t=988.1 (ห่างกันแค่ 0.1 วินาที) ไปลบ session ของตัวใหม่
    # ทิ้ง ผลคือ SSH ต่ออยู่จริง (pcap เห็น keepalive 68/72 ไบต์ทุก 20 วิ) แต่ไม่มีใคร poll
    # ได้เลย และอุปกรณ์ก็ไม่ call-home ใหม่เพราะฝั่งมันคิดว่าต่ออยู่ดีๆ -> อุปกรณ์ขึ้น
    # offline ถาวรจนกว่าจะ restart backend
    def _release_session(self, dev_id: str, connection, ip: str):
        current = self.sessions.get(dev_id)
        if current is not None and current.get("connection") is not connection:
            print(f"[-] session เก่าของ {dev_id} ปิดแล้ว ({ip}) - มีตัวใหม่ใช้งานอยู่ ไม่ล้างของตัวใหม่")
            return

        # เดิมไม่ print อะไรตอน session หลุด/ปิดเลย - ผู้ใช้เห็นแค่คำสั่งถัดไปตอบ 409
        # Conflict มาเงียบๆ ไม่รู้ว่า "ตอนไหน"/"ทำไม" session หลุด
        self._cancel_capability_probe(dev_id, connection)
        self.sessions.pop(dev_id, None)
        self.stats.pop(dev_id, None)  # กัน Basic Info โชว์ค่าเก่าค้างของ session ที่หลุดไปแล้ว
        self._reset_stats_failure(dev_id)  # (bug 53) ล้างตัวนับ/backoff ไม่ให้ค้างข้าม session
        print(f"[-] Call Home session closed for device {dev_id or '(unidentified)'} ({ip})")

    # (bug 59) เดิมข้อความ log เขียนว่า "for deleted device" ตายตัว ตั้งแต่ตอนที่มีผู้
    # เรียกที่เดียวคือตอนลบอุปกรณ์ - ตอนนี้ถูกเรียกจาก 4 ที่ และมีที่หนึ่ง (คำสั่งของ
    # ผู้ใช้ timeout ใน device_router) ที่ "ไม่ได้ลบอะไรเลย" ข้อความจึงโกหกและทำให้
    # ไล่ log ผิดทาง - รับ reason เข้ามาบอกสาเหตุจริงแทน
    # (dynamic feature ขั้นที่ 3) ตรวจความสามารถอุปกรณ์หลัง call-home - ลำดับการยิงคำสั่งอยู่ใน
    # backend/capability_probe.py ส่วนนี้ดูแลแค่อายุของงานกับการบันทึกผล
    #
    # รันเป็นงานเบื้องหลังเพื่อไม่ให้ call-home ช้าลง และผูกงานกับ connection object ไม่ใช่แค่ dev_id
    # เพราะ send_payload หา session จาก dev_id - ถ้าอุปกรณ์ต่อใหม่ระหว่างตรวจ งานของ connection เก่า
    # จะยิงคำสั่งเข้า session ใหม่ หรือบันทึกโปรไฟล์เก่าทับของใหม่ได้
    # ขั้นนี้แค่เก็บโปรไฟล์ ยังไม่มีการกรองคำสั่งใด (ขั้นที่ 4)
    def _start_capability_probe(
        self, dev_id: str, connection, vendor: str, hello_capabilities: list[str], force: bool = False,
    ):
        self._cancel_capability_probe(dev_id)
        task = asyncio.create_task(
            self._run_capability_probe(dev_id, connection, vendor, list(hello_capabilities or []), force)
        )
        self._capability_tasks[dev_id] = (connection, task)
        task.add_done_callback(lambda done, dev_id=dev_id: self._forget_capability_probe(dev_id, done))

    def _forget_capability_probe(self, dev_id: str, task) -> None:
        current = self._capability_tasks.get(dev_id)
        if current is not None and current[1] is task:
            self._capability_tasks.pop(dev_id, None)

    # connection=None ยกเลิกงานของ dev_id นี้เสมอ (ตอนเริ่มงานใหม่) ถ้าระบุ connection จะยกเลิกเฉพาะ
    # งานของ connection ตัวนั้น ไม่แตะงานของ session ใหม่
    def _cancel_capability_probe(self, dev_id: str, connection=None) -> None:
        current = self._capability_tasks.get(dev_id)
        if current is None or (connection is not None and current[0] is not connection):
            return
        self._capability_tasks.pop(dev_id, None)
        if not current[1].done():
            current[1].cancel()

    async def _cancel_all_capability_probes(self) -> None:
        tasks = [task for _, task in self._capability_tasks.values()]
        self._capability_tasks.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _is_current_connection(self, dev_id: str, connection) -> bool:
        session = self.sessions.get(dev_id)
        return session is not None and session.get("connection") is connection

    # force=True ไม่อ่านโปรไฟล์เดิม จึงไม่ใช้ schema จาก cache (ปุ่มตรวจใหม่ของผู้ใช้)
    async def _run_capability_probe(
        self, dev_id: str, connection, vendor: str, hello_capabilities: list[str], force: bool = False,
    ):
        try:
            previous = None
            if not force:
                async with AsyncSessionFactory() as db_session:
                    previous = await get_capability_profile(db_session, dev_id)

            async def send(payload: str, timeout: float) -> str:
                if not self._is_current_connection(dev_id, connection):
                    raise ProbeAborted("session ถูกแทนที่หรือปิดไปแล้ว")
                try:
                    return await self.send_payload(dev_id, payload, timeout=timeout)
                except (NetconfDead, ConnectionError) as exc:
                    raise ProbeAborted(str(exc)) from exc

            profile = await build_profile(vendor, hello_capabilities, send, previous)
            if profile.get("aborted") or not self._is_current_connection(dev_id, connection):
                reason = profile.get("abort_reason") or "session เปลี่ยนระหว่างตรวจ"
                log_verbose(f"[capability] {dev_id} หยุดตรวจ ไม่บันทึกโปรไฟล์ - {reason}")
                return

            async with AsyncSessionFactory() as db_session:
                saved = await update_capability_profile(db_session, dev_id, profile)
            schema = profile.get("schema") or {}
            log_verbose(
                f"[capability] {dev_id} ตรวจเสร็จ status={profile['status']} "
                f"schema={schema.get('status')}{' (cache)' if schema.get('cached') else ''} "
                f"บันทึก={'สำเร็จ' if saved else 'ไม่พบแถว capability'}"
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # งานเสริม - ล้มแล้วต้องไม่กระทบ call-home หรือ session ใด ๆ
            print(f"[!] [capability] {dev_id} ตรวจไม่สำเร็จ: {type(exc).__name__}: {exc}")

    def capability_probe_running(self, dev_id: str) -> bool:
        current = self._capability_tasks.get(dev_id)
        return current is not None and not current[1].done()

    # (dynamic feature ขั้นที่ 4) ให้ API สั่งตรวจใหม่โดยไม่ใช้ schema จาก cache
    # คืน "offline" (ไม่มี session), "running" (กำลังตรวจอยู่ ไม่เริ่มซ้ำ) หรือ "started"
    def refresh_capability(self, dev_id: str) -> str:
        session = self.sessions.get(dev_id)
        if session is None:
            return "offline"
        if self.capability_probe_running(dev_id):
            return "running"
        self._start_capability_probe(
            dev_id,
            session["connection"],
            session["vendor"],
            sorted(session.get("capabilities") or []),
            force=True,
        )
        return "started"

    async def close_session(self, dev_id: str, reason: str = "ไม่ระบุสาเหตุ"):
        session = self.sessions.get(dev_id)
        if not session:
            return
        connection = session.get("connection")
        if connection is None:
            return
        try:
            connection.close()
            print(f"[-] สั่งตัด call-home ของ {dev_id} - สาเหตุ: {reason}")
        except Exception as exc:
            print(f"[!] Failed to close call-home connection for {dev_id}: {exc}")

    def session_connection(self, dev_id: str):
        session = self.sessions.get(dev_id)
        return session.get("connection") if session else None

    # อุปกรณ์ปิดช่อง NETCONF แต่ SSH อาจยังเปิดค้าง (มันจะไม่ call-home ใหม่เอง) - ปิด connection
    # เก่าถ้ายังเป็นตัวปัจจุบัน แล้วรอจนมี session ใหม่ (connection คนละตัว) เข้ามาแทน
    async def wait_for_reconnect(self, dev_id: str, old_connection, timeout: float) -> bool:
        if old_connection is not None and self.session_connection(dev_id) is old_connection:
            await self.close_session(dev_id, reason="อุปกรณ์ปิดช่อง NETCONF ระหว่างคำสั่ง - รอ call-home ใหม่")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self.session_connection(dev_id)
            if current is not None and current is not old_connection:
                return True
            await asyncio.sleep(1)
        return False

    def revoke_session(self, dev_id: str, connection=None) -> bool:
        """เพิกถอน Call Home session ของ dev_id
        - เทียบ identity ของ connection (แบบ bug 59): ถ้า connection ระบุไว้ และไม่ตรงกับ session ปัจจุบัน -> คืน False
        - cancel capability probe, ล้าง stats, reset stats failure
        - ปิด connection (ถ้าปิดไม่ได้ หรือ exception -> เอา session ออกจาก pool: fail closed)
        - pop session ออกจาก pool เสมอ
        """
        current = self.sessions.get(dev_id)
        if current is None:
            return False
        target_conn = current.get("connection")
        if connection is not None and target_conn is not connection:
            print(f"[!] revoke_session: connection mismatch for {dev_id} (มี session ใหม่อยู่แล้ว)")
            return False

        self._cancel_capability_probe(dev_id, target_conn)
        self.stats.pop(dev_id, None)
        self._reset_stats_failure(dev_id)

        try:
            if target_conn is not None:
                target_conn.close()
        except Exception as exc:
            print(f"[!] revoke_session: error closing connection for {dev_id}: {exc}")
        finally:
            self.sessions.pop(dev_id, None)
        print(f"[-] revoke_session: session revoked for {dev_id}")
        return True

    async def is_trusted_session(
        self,
        dev_id: str,
        expected_vendor: str,
        expected_fingerprint: str,
        *,
        session=None,
    ) -> bool:
        """ตรวจสอบว่า dev_id มี active NETCONF session ที่เชื่อถือได้และตรงกับ DB หรือไม่ (สำหรับ Online Reset Identity)
        เงื่อนไข:
        1. มี session ใน self.sessions
        2. device_health(dev_id)['responsive'] เป็น True
        3. session['vendor'] == expected_vendor
        4. connection ยังเปิดอยู่ (not is_closing() และ not is_closed())
        5. host key fingerprint จาก connection ตรงกับ expected_fingerprint
        6. ตรวจ DB ผ่าน is_active_consumed_enrolled_device
        """
        conn_dict = self.sessions.get(dev_id)
        if not conn_dict:
            return False
        health = self.device_health(dev_id)
        if not health.get("responsive", False):
            return False
        if conn_dict.get("vendor") != expected_vendor:
            return False
        connection = conn_dict.get("connection")
        if connection is None:
            return False
        if hasattr(connection, "is_closing") and connection.is_closing():
            return False
        if hasattr(connection, "is_closed") and connection.is_closed():
            return False
        try:
            actual_fingerprint = get_host_key_fingerprint(connection)
            if actual_fingerprint != expected_fingerprint:
                return False
        except Exception:
            return False

        from backend.crud.dev_crud.crud_device_enrollment import is_active_consumed_enrolled_device
        try:
            if session is not None:
                return await is_active_consumed_enrolled_device(session, dev_id, expected_vendor, expected_fingerprint)
            async with AsyncSessionFactory() as s:
                return await is_active_consumed_enrolled_device(s, dev_id, expected_vendor, expected_fingerprint)
        except Exception as exc:
            print(f"[!] is_trusted_session DB check error for {dev_id}: {exc}")
            return False

    # (bug 100) 2 ตัวนี้คือหัวใจของการแยก "อุปกรณ์ยุ่ง" ออกจาก "ท่อตาย"
    #
    # เรียกจากทุกที่ที่รู้ผลการอ่านท่อ - ได้ยินอะไรก็ตาม (แม้แต่ reply ของ request เก่า
    # ที่ค้างอยู่ ซึ่งกลายเป็น NetconfDesync) แปลว่าอุปกรณ์ยังมีชีวิต ล้างตัวจับเวลาทิ้ง
    def _mark_alive(self, dev_id: str) -> None:
        session = self.sessions.get(dev_id)
        if session is not None and session.get("silent_since") is not None:
            session["silent_since"] = None

    # คืน True เมื่อ "เงียบมานานเกินกำหนดแล้ว" - ผู้เรียกต้องปิด session เอง
    # ครั้งแรกที่เงียบจะแค่จดเวลาไว้แล้วคืน False (นี่คือเคสของ bug 68 ที่ห้ามตัด)
    def _note_silence(self, dev_id: str) -> bool:
        session = self.sessions.get(dev_id)
        if session is None:
            return False
        started = session.get("silent_since")
        if started is None:
            session["silent_since"] = time.monotonic()
            return False
        return (time.monotonic() - started) >= SILENCE_CUTOFF_SECONDS

    # (2026-09) Cisco NAT quarantine - ดู comment ที่ CISCO_NAT_QUARANTINE_SECONDS
    # ด้านบนสำหรับเหตุผลทั้งหมด ทั้ง 3 ฟังก์ชันนี้ไม่แตะ wire เลย แค่จัดการ state
    # ในตัวแปร session dict เดียวกับที่ silent_since ใช้อยู่แล้ว
    def cisco_nat_quarantine_remaining(self, dev_id: str) -> float:
        session = self.sessions.get(dev_id)
        if not session:
            return 0.0
        until = session.get("nat_quarantine_until")
        if not until:
            return 0.0
        remaining = until - time.monotonic()
        if remaining <= 0:
            session["nat_quarantine_until"] = None
            return 0.0
        return remaining

    def _set_cisco_nat_quarantine(self, dev_id: str) -> None:
        session = self.sessions.get(dev_id)
        if session is not None:
            session["nat_quarantine_until"] = time.monotonic() + CISCO_NAT_QUARANTINE_SECONDS

    def _clear_cisco_nat_quarantine(self, dev_id: str) -> None:
        session = self.sessions.get(dev_id)
        if session is not None:
            session["nat_quarantine_until"] = None

    # background loop ยิง get_cpu_memory_information ผ่านทุก session ที่ยังต่อ
    # อยู่ทุก STATS_POLL_INTERVAL วิ - ทำงานอิสระจาก HTTP request ใดๆ (ไม่ต้องมี
    # ใครเปิดหน้าเว็บดูก็ยังรันอยู่) ใช้ send_payload() ตัวเดียวกับที่ device_router
    # เรียก (ผ่าน lock เดียวกัน - ปลอดภัยถ้ามี user สั่งคำสั่งพร้อมกันพอดี) แต่ละ
    # device แยก try/except ของตัวเอง กัน 1 อุปกรณ์ error/hang ไม่ให้กระทบ
    # อุปกรณ์อื่นในรอบเดียวกัน (ยิงพร้อมกันด้วย asyncio.gather ไม่ใช่ทีละตัว)
    async def _poll_stats_loop(self):
        while True:
            await asyncio.sleep(STATS_POLL_INTERVAL)
            dev_ids = list(self.sessions.keys())
            if not dev_ids:
                continue
            await asyncio.gather(*(self._poll_one_stat(dev_id) for dev_id in dev_ids), return_exceptions=True)

    # (bug 53) เคลียร์ตัวนับตอน poll สำเร็จ - แยกออกมาเพราะถูกเรียกจาก 2 ที่
    # (ตอนสำเร็จ และตอน session ปิดใน accept()'s finally)
    def _reset_stats_failure(self, dev_id: str, recovered: bool = False):
        failures = self._stats_failures.pop(dev_id, 0)
        self._stats_skip_until.pop(dev_id, None)
        if recovered and failures:
            print(f"[+] stats poll ของ {dev_id} กลับมาปกติแล้ว (ล้มเหลวติดกัน {failures} ครั้งก่อนหน้า)")

    # (bug 53/54) บันทึกความล้มเหลว + คำนวณว่าจะถอยห่างไปอีกกี่วินาที
    #
    # log แค่ 2 จังหวะเท่านั้น: ครั้งแรกที่เริ่มพัง และทุกครั้งที่ระยะถอยเปลี่ยน -
    # เดิมพิมพ์ทุกครั้งที่ล้มเหลว ทำให้ได้ 29 บรรทัดซ้ำกันจนอ่านไม่ไหว และพิมพ์แค่
    # {exc} ซึ่ง TimeoutError มี str() เป็นค่าว่าง บรรทัดจึงว่างเปล่าไม่บอกอะไรเลย
    def _record_stats_failure(self, dev_id: str, exc: Exception):
        # (bug 57) NetconfDesync = อุปกรณ์ยังส่งข้อมูลอยู่ แค่ยังไล่ reply เก่าไม่หมด
        # **ห้ามถอยห่าง** เพราะเป็นหลักฐานว่าอุปกรณ์ฟื้นแล้ว - ถ้าถอยตอนนี้จะกลายเป็น
        # ยิ่งฟื้นยิ่งรอนาน ซึ่งเป็นอาการที่วัดได้จริงจาก log (อุปกรณ์ฟื้นนาทีที่ 4 แต่
        # ระบบไปรู้ตอนนาทีที่ 9 เพราะ poll ที่เจอ stale reply ถูกนับเป็นความล้มเหลว
        # แล้วถอยต่ออีก 300 วิ) - รอบถัดไปในอีก 10 วิจะไล่ต่อจนหมดเอง
        if isinstance(exc, NetconfDesync):
            print(f"[~] stats poll ของ {dev_id} กำลังไล่ reply เก่าที่ค้างอยู่ - ลองใหม่รอบหน้า")
            self._stats_skip_until.pop(dev_id, None)
            return

        failures = self._stats_failures.get(dev_id, 0) + 1
        self._stats_failures[dev_id] = failures

        # (bug 57) ไม่ถอยตั้งแต่ครั้งแรก - จาก log จริง "timeout ครั้งเดียวแล้วฟื้นทันที"
        # เป็นเรื่องปกติของอุปกรณ์ตัวนี้ (เห็นหลายครั้ง: fail 1 ครั้ง → Discarding stale
        # gap=1 → กลับมาปกติ) การถอยตั้งแต่ครั้งแรกจึงเป็นการลงโทษเกินเหตุ
        #
        # เลือกวิธีนี้แทนการเพิ่ม STATS_POLL_TIMEOUT เพราะ timeout ที่ยาวขึ้นแปลว่า
        # ผู้ใช้อาจต้องรอ lock นานขึ้น ซึ่งขัดกับหลักที่ว่างานของผู้ใช้สำคัญสูงสุด
        # (และตัวเลข timeout ที่ "พอดี" ก็ยังไม่มีหลักฐานว่าควรเป็นเท่าไหร่)
        backoff = 0 if failures == 1 else min(STATS_POLL_INTERVAL * (2 ** (failures - 2)), STATS_BACKOFF_MAX)
        prev_backoff = (
            0 if failures <= 2
            else min(STATS_POLL_INTERVAL * (2 ** (failures - 3)), STATS_BACKOFF_MAX)
        )
        if backoff:
            self._stats_skip_until[dev_id] = time.monotonic() + backoff
        else:
            self._stats_skip_until.pop(dev_id, None)

        if failures == 1 or backoff != prev_backoff:
            # พิมพ์ชนิด exception เสมอ - TimeoutError กับ ConnectionError ต้องการ
            # การตอบสนองคนละแบบ แต่เดิมแยกไม่ออกจาก log
            detail = f"{type(exc).__name__}" + (f": {exc}" if str(exc) else "")
            wait_text = f"หยุด poll ชั่วคราว {backoff} วินาที" if backoff else "ลองใหม่รอบหน้า"
            print(f"[!] stats poll failed for {dev_id}: {detail} (ครั้งที่ {failures} ติดกัน - {wait_text})")

    async def _poll_one_stat(self, dev_id: str):
        session = self.sessions.get(dev_id)
        if not session:
            return

        # (bug 53) ยังอยู่ในช่วงถอยห่าง - ไม่ยิงคำสั่งใหม่ทับของเก่า
        skip_until = self._stats_skip_until.get(dev_id)
        if skip_until is not None and time.monotonic() < skip_until:
            # ===== โค้ดเดิมก่อนแก้ bug 58 - เก็บไว้เผื่อ rollback =====
            # เดิมข้ามไปเงียบ ๆ ไม่ดูอะไรเลยจนกว่า backoff จะหมด
            # return
            # ==========================================================

            # (bug 58) "หยุดยิง" ไม่จำเป็นต้องแปลว่า "หยุดดู"
            #
            # ยืนยันด้วย Wireshark จากการทดสอบจริงของผู้ใช้: ตอนอุปกรณ์เลิก suspend
            # มันส่ง SSH packet ออกมาและ server ก็ตอบกลับตามปกติ - แปลว่าข้อมูล
            # "มาถึงเราแล้ว" และ asyncssh เก็บไว้ใน _recv_buf ให้เรียบร้อยแล้วด้วย
            # (data_received() ทำงานอัตโนมัติไม่ว่าแอปจะอ่านหรือไม่) แต่โค้ดเดิม
            # return ออกไปตั้งแต่บรรทัดแรกจึงไม่มีใครไปหยิบ ต้องรอจน backoff หมด
            # (สูงสุด 300 วิ) ถึงจะรู้ว่าอุปกรณ์ฟื้นไปตั้งนานแล้ว
            #
            # สิ่งที่ทำให้ขยะสะสมคือ "การยิงคำสั่งใหม่" ไม่ใช่ "การอ่าน" - จึงแยก 2
            # อย่างนี้ออกจากกัน: ระหว่าง backoff ยังไม่ยิงอะไรเลย แต่แอบอ่านสั้น ๆ
            # ถ้าอ่านได้แปลว่าอุปกรณ์ฟื้นแล้ว ล้าง backoff ทิ้งให้รอบหน้า poll ตามปกติ
            # ได้ผลพลอยได้คือล้างขยะไปในตัวด้วยโดยไม่เพิ่มขยะใหม่เลย
            if session["lock"].locked():
                return          # ผู้ใช้กำลังใช้ท่ออยู่ - ไม่แตะ (งานผู้ใช้สำคัญกว่า)

            buf = session["buffer"]
            before = len(buf[0])
            try:
                async with session["lock"]:
                    await read_dev_response(
                        session["process"], buf, timeout=STATS_IDLE_PROBE_TIMEOUT
                    )
            except asyncio.TimeoutError:
                # ยังเงียบอยู่ - แต่ถ้าบัฟเฟอร์โตขึ้นแปลว่าได้ข้อมูลมาบางส่วนแล้ว
                # (ข้อความยังมาไม่ครบก้อน) ก็ถือว่าอุปกรณ์ฟื้นแล้วเหมือนกัน
                if len(buf[0]) <= before:
                    # (bug 100) ระหว่างถอยห่างจะไม่มีใครยิงคำสั่งเลย ถ้ารอให้ผู้ใช้กด
                    # คำสั่งถัดไปมาเป็นคนกระตุ้นการตัด อุปกรณ์ที่ท่อตายตอนไม่มีใครใช้งาน
                    # จะค้างอยู่อย่างนั้นตลอดไป - probe รอบนี้จึงเป็นตัวเฝ้าให้ด้วย
                    if self._note_silence(dev_id):
                        await self.close_session(
                            dev_id,
                            reason=f"เงียบสนิทเกิน {SILENCE_CUTOFF_SECONDS} วินาที (ตรวจพบจาก probe ระหว่างถอยห่าง)",
                        )
                    return
            except Exception:
                # ConnectionError / channel ปิด ฯลฯ - ปล่อยให้ accept()'s finally
                # จัดการ cleanup ตามปกติ ไม่ต้องทำอะไรที่นี่
                return

            print(
                f"[+] {dev_id} ส่งข้อมูลกลับมาแล้วระหว่างช่วงหยุด poll - "
                f"ยกเลิกการถอยห่าง กลับไป poll ตามปกติรอบหน้า"
            )
            self._reset_stats_failure(dev_id)
            return

        # (bug 53) มีคำสั่งของผู้ใช้ทำงานอยู่ - ข้ามรอบนี้ไปเลย
        #
        # send_payload ถือ session["lock"] ตัวเดียวกับที่คำสั่งผู้ใช้ใช้ ถ้า stats
        # เข้าไปต่อคิว ผู้ใช้จะรอนานขึ้นโดยไม่จำเป็น - stats เป็น best-effort
        # พลาดรอบเดียวไม่มีผลอะไร (Redis TTL 15 วิ ออกแบบมารองรับการพลาดอยู่แล้ว)
        # แต่การไปขวางคำสั่งผู้ใช้มีผลมาก
        if session["lock"].locked():
            return

        vendor = session["vendor"]
        try:
            payload = build_payload(vendor, "get_cpu_memory_information", {})
            reply = await self.send_payload(dev_id, payload, timeout=STATS_POLL_TIMEOUT)
            normalized = normalize(vendor, "get_cpu_memory_information", reply)
            stat = _extract_stats(vendor, normalized)
            if stat:
                # Huawei แยก sysUpTime ออกจาก devm CPU/RAM. อ่านเพิ่มเฉพาะ Huawei
                # และ best-effort: ถ้า RPC นี้พลาดยังเก็บ CPU/RAM รอบเดิมได้ ไม่เพิ่ม
                # failure/backoff ของ poller ที่ผ่าน BUG-53/54/55/56/58 มาแล้ว.
                if vendor == "huawei":
                    try:
                        uptime_payload = build_payload(vendor, "get_uptime", {})
                        uptime_reply = await self.send_payload(
                            dev_id, uptime_payload, timeout=STATS_POLL_TIMEOUT
                        )
                        uptime_normalized = normalize(vendor, "get_uptime", uptime_reply)
                        uptime = _extract_huawei_uptime(uptime_normalized)
                        if uptime is not None:
                            stat["uptime"] = uptime
                    except Exception:
                        pass
                stat["polled_at"] = datetime.now(timezone.utc).isoformat()
                self.stats[dev_id] = stat
                # External cache คู่กับ in-memory dict (ดู planning/redisPlan.md
                # ข้อ 5.2 เสาหลักที่ 3) - TTL 15s (สั้นกว่ารอบ poll 10s เจตนา -
                # ถ้าค่าเก่ากว่า 15s แปลว่า poll รอบถัดไปพลาดไป 1 รอบ ให้ key
                # หมดอายุไปเองแทนที่จะโชว์ค่าเก่าค้างไม่มีกำหนด) best-effort ล้วนๆ
                # Redis ล่มไม่ควรทำให้ keep-alive poll (จุดประสงค์หลักของ loop นี้)
                # พังตาม - self.stats (in-memory) ยังเป็น fallback เสมอ
                try:
                    await get_redis().set(f"device:stats:{dev_id}", json.dumps(stat), ex=15)
                except Exception as cache_exc:
                    print(f"[!] failed to cache stats in redis for {dev_id}: {cache_exc}")
            self._reset_stats_failure(dev_id, recovered=True)
        except Exception as exc:
            # best-effort เฉยๆ - ไม่ raise ต่อ ไม่ log รบกวนถ้าแค่ session หลุด
            # ปกติ (accept()'s finally จัดการ cleanup ของมันเองอยู่แล้ว) log ไว้
            # เฉพาะกรณีที่ยังมี session อยู่จริงแต่ query ล้มเหลว (เช่น path ของ
            # get_cpu_memory_information ผิดสำหรับรุ่นนั้นจริงๆ)
            if dev_id in self.sessions:
                self._record_stats_failure(dev_id, exc)

    # timeout: None = ใช้ค่า default ของ _read_matching_reply (20 วิ) สำหรับคำสั่ง
    # ของผู้ใช้ที่อาจใช้เวลานานจริง (edit-config หนัก ๆ / commit ของ Junos) -
    # stats poll ส่ง STATS_POLL_TIMEOUT (6 วิ) เข้ามาแทน เพราะต้องจบก่อนรอบถัดไป
    # และต้องไม่ถือ lock นานจนขวางคำสั่งผู้ใช้ (bug 53)
    # (bug 88) ล้าง candidate ที่ค้างอยู่ทิ้ง - ใช้ทั้งตอน edit-config ล้ม และตอน commit ล้ม
    #
    # ต้องเรียกใน lock ของ session เดิมเสมอ (ผู้เรียกทั้ง 2 จุดอยู่ใน `async with session["lock"]`
    # อยู่แล้ว) ไม่งั้นจะไปแทรกกลางคำสั่งอื่น - best-effort ล้วน ๆ ถ้า discard เองก็ล้มก็แค่ log
    # เพราะเรากำลังจะ raise error ของเดิมออกไปอยู่แล้ว การกลบด้วย error ใหม่จะทำให้ผู้ใช้
    # ไม่รู้ว่าต้นตอคืออะไร
    @staticmethod
    def _uses_candidate(session) -> bool:
        if session["vendor"] in ("juniper", "huawei"):
            return True
        capabilities = session.get("capabilities", set())
        return (
            session["vendor"] == "cisco"
            and CANDIDATE_CAPABILITY in capabilities
            and WRITABLE_RUNNING_CAPABILITY not in capabilities
        )

    def _prepare_payload(self, session, payload: str) -> str:
        # IOS XE มีทั้ง writable-running และ candidate-only ปรับเฉพาะ target ของ
        # edit-config ตอนส่ง โดยยึด capability จาก hello ของ session จริง
        if session["vendor"] != "cisco" or not self._uses_candidate(session) or "<edit-config>" not in payload:
            return payload
        return re.sub(
            r"(<target>\s*)<running/>(\s*</target>)",
            r"\1<candidate/>\2",
            payload,
            count=1,
        )

    async def _discard_candidate(self, session, reason: str) -> None:
        discard = discard_changes_payload(
            session["vendor"], candidate_override=self._uses_candidate(session)
        )
        if not discard:
            return  # session นี้ไม่มี candidate datastore - ไม่มีอะไรต้องล้าง
        try:
            session["process"].stdin.write(discard.rstrip() + NETCONF_END)
            await read_dev_response(session["process"], session["buffer"])
            print(f"[+] ล้าง candidate ที่ค้างทิ้งแล้ว - {reason}")
        except Exception as exc:
            print(f"[!] ล้าง candidate ไม่สำเร็จ ({reason}): {exc}")

    # (C4) ส่ง edit-config หลายตัวเข้า candidate เดียวแล้ว commit ครั้งเดียว
    #
    # เหตุผลที่ต้องมี: CE12800 ตรวจ edit-config กับสภาพปัจจุบันของ datastore ปลายทาง
    # งานที่ต้องพึ่งผลของคำสั่งก่อนหน้าจึงทำในคำสั่งเดียวไม่ได้ (เคสจริง: คืนพอร์ตเป็น
    # access VLAN 1 ก่อน แล้วถึงจะสลับเป็น Layer 3 ได้) พอเขียนลง candidate ตัวถัดไป
    # จะเห็นผลของตัวแรกแล้ว และ commit ครั้งเดียวปิดท้ายทำให้ทั้งชุดเป็น atomic จริง
    #
    # ใช้ lock ตัวเดียวคลุมทั้งชุด ไม่ให้คำสั่งของคนอื่นแทรกเข้า candidate ระหว่างทาง
    # ถ้าตัวใดถูกปฏิเสธ จะ discard ทั้ง candidate แล้วคืน reply ของตัวที่ล้มให้ผู้เรียก
    # ไปแปลงเป็นข้อความเดียวกับเส้นทางคำสั่งเดี่ยว (ไม่ raise เพื่อให้ระลอก A ทำงานเหมือนเดิม)
    async def send_transaction(self, dev_id: str, payloads: list[str]) -> tuple[int, str]:
        if not payloads:
            raise ValueError("Transaction must contain at least one command")
        session = self.sessions.get(dev_id)
        if not session:
            raise ConnectionError("Device does not have a live Call Home session")
        if session["vendor"] == "cisco" and not self._uses_candidate(session):
            if "urn:ietf:params:netconf:capability:rollback-on-error:1.0" not in session.get("capabilities", set()):
                raise ValueError("Cisco ไม่ประกาศ rollback-on-error จึงยังทำ transaction แบบ atomic (เช่น NTP update) ไม่ได้")
            combined = combine_cisco_running_edits(payloads)
            async with session["lock"]:
                reply = await self._exchange(dev_id, session, combined)
            return (0 if "<rpc-error" in reply or ":rpc-error" in reply else -1), reply
        if not commit_payload(session["vendor"], candidate_override=self._uses_candidate(session)):
            raise ValueError("อุปกรณ์ยี่ห้อนี้ไม่มี candidate datastore จึงส่งเป็นชุดเดียวไม่ได้")
        async with session["lock"]:
            for index, payload in enumerate(payloads):
                try:
                    payload = self._prepare_payload(session, payload)
                    reply = await self._exchange(dev_id, session, payload)
                except Exception:
                    await self._discard_candidate(session, "ส่งคำสั่งในชุดไม่สำเร็จ")
                    raise
                if _configuration_reply_rejected(reply):
                    await self._discard_candidate(session, "คำสั่งในชุดถูกอุปกรณ์ปฏิเสธ")
                    return index, reply

            commit = commit_payload(session["vendor"], candidate_override=self._uses_candidate(session))
            try:
                commit_reply = await self._exchange(dev_id, session, commit)
            except Exception:
                # A lost commit reply does not prove that running was unchanged.
                # Clear any remaining candidate changes and report the failure.
                await self._discard_candidate(session, "ไม่ได้รับผล commit ของชุดคำสั่ง")
                raise
            if _configuration_reply_rejected(commit_reply):
                await self._discard_candidate(session, "commit ของชุดคำสั่งล้มเหลว")
                raise RuntimeError(f"{session['vendor']} commit failed: {commit_reply}")
            return -1, reply

    # เขียน payload หนึ่งตัวแล้วอ่าน reply ที่ message-id ตรงกัน พร้อมจัดการเรื่อง
    # "ท่อยังมีชีวิตไหม" แบบเดียวกับ send_payload - ต้องเรียกใน lock ของ session เสมอ
    async def _exchange(self, dev_id: str, session, payload: str, **read_kwargs) -> str:
        expected_id = _extract_message_id(payload)
        session["process"].stdin.write(payload.rstrip() + NETCONF_END)
        try:
            if expected_id:
                reply = await _read_matching_reply(session["process"], session["buffer"], expected_id, **read_kwargs)
            else:
                reply = await read_dev_response(session["process"], session["buffer"], **read_kwargs)
        except NetconfSilent:
            if self._note_silence(dev_id):
                await self.close_session(
                    dev_id,
                    reason=f"เงียบสนิทเกิน {SILENCE_CUTOFF_SECONDS} วินาที - ถือว่าท่อตาย",
                )
                raise NetconfDead(
                    f"อุปกรณ์ไม่ส่งข้อมูลใดกลับมาเลยนานเกิน {SILENCE_CUTOFF_SECONDS} วินาที "
                    "- ปิด session ทิ้งเพื่อให้อุปกรณ์ call-home กลับเข้ามาใหม่"
                )
            raise
        except NetconfDesync:
            self._mark_alive(dev_id)
            raise
        self._mark_alive(dev_id)
        return reply

    async def send_payload(
        self, dev_id: str, payload: str, timeout: float | None = None, nat_quarantine: bool = False,
    ) -> str:
        session = self.sessions.get(dev_id)
        if not session:
            raise ConnectionError("Device does not have a live Call Home session")
        payload = self._prepare_payload(session, payload)
        async with session["lock"]:
            expected_id = _extract_message_id(payload)
            session["process"].stdin.write(payload.rstrip() + NETCONF_END)
            read_kwargs = {"timeout": timeout} if timeout is not None else {}
            # (bug 100) จุดนี้คือคอขวดเดียวที่ทราฟฟิก NETCONF ทุกเส้นวิ่งผ่าน (ทั้งคำสั่ง
            # ของผู้ใช้และ stats poll) จึงเป็นที่เดียวที่ตัดสินได้ว่า "ท่อยังมีชีวิตไหม"
            # โดยไม่ต้องไปไล่ดักตามที่เรียกทีละจุด
            try:
                if expected_id:
                    reply = await _read_matching_reply(session["process"], session["buffer"], expected_id, **read_kwargs)
                else:
                    reply = await read_dev_response(session["process"], session["buffer"], **read_kwargs)
            except NetconfSilent:
                # เงียบสนิท - ครั้งแรกแค่จดเวลาไว้แล้วโยนต่อตามเดิม (เคสของ bug 68:
                # ผู้ใช้กรอกค่าที่ชนกับ config เดิม อุปกรณ์เงียบไปพักหนึ่งแล้วก็กลับมา
                # ห้ามตัดการเชื่อมต่อเด็ดขาด) จะตัดก็ต่อเมื่อเงียบยาวเกิน cutoff เท่านั้น
                if nat_quarantine:
                    self._set_cisco_nat_quarantine(dev_id)
                if self._note_silence(dev_id):
                    await self.close_session(
                        dev_id,
                        reason=f"เงียบสนิทเกิน {SILENCE_CUTOFF_SECONDS} วินาที - ถือว่าท่อตาย",
                    )
                    raise NetconfDead(
                        f"อุปกรณ์ไม่ส่งข้อมูลใดกลับมาเลยนานเกิน {SILENCE_CUTOFF_SECONDS} วินาที "
                        "- ปิด session ทิ้งเพื่อให้อุปกรณ์ call-home กลับเข้ามาใหม่"
                    )
                raise
            except NetconfDesync:
                # ได้ยินเสียงแล้ว แม้จะเป็น reply ของ request เก่าที่ค้างอยู่ก็ตาม -
                # แปลว่าอุปกรณ์ยังมีชีวิต ล้างตัวจับเวลาก่อนโยนต่อ - แต่ reply ของเรา
                # เองยังไม่มาจริงๆ (ยังไล่ backlog ไม่ทัน) ต้อง quarantine ต่อไว้เหมือนกัน
                self._mark_alive(dev_id)
                if nat_quarantine:
                    self._set_cisco_nat_quarantine(dev_id)
                raise

            self._mark_alive(dev_id)
            if nat_quarantine:
                self._clear_cisco_nat_quarantine(dev_id)

            # (bug 88) edit-config ล้มเหลว - ต้องล้าง candidate ทิ้งทันที
            #
            # Junos apply edit-config เข้า candidate "ทีละ element" แล้วหยุดตรงที่เจอ error
            # ของที่ผ่านไปแล้วก่อนหน้านั้นยังค้างอยู่ใน candidate เสมอ เดิมโค้ดแค่ข้ามการ commit
            # (ถูกแล้ว) แต่ไม่ได้ล้าง candidate ทิ้ง ผลคือเศษ config ค้างรอ แล้ว "คำสั่งถัดไปที่
            # สำเร็จ" จะ commit มันไปด้วย และสะสมเพิ่มขึ้นทุกครั้งที่ fail
            #
            # ยืนยันจากผลทดสอบจริงของผู้ใช้ (6 ก.ย. 2026) - เทียบลำดับ element ใน XML ที่เราส่ง
            # กับเศษที่ค้างบนอุปกรณ์ตรงกันเป๊ะ:
            #   IKE integrity sha-512 ล้ม  -> เหลือ authentication-method + dh-group (2 ตัวแรก)
            #   IKE dh-group 21 ล้ม        -> เหลือ authentication-method อย่างเดียว (1 ตัวแรก)
            # ผู้ใช้เห็นเป็น "invalid value ทั้งที่ไม่ควรสร้าง แต่กลับมี config เกิดไปแล้วบางส่วน"
            #
            # ไม่ raise ที่นี่ - ปล่อยให้ reply ที่มี rpc-error กลับไปให้ response_normalizer
            # จัดการตามเดิม (ระลอก A ทำให้ error ถึงหน้าผู้ใช้อยู่แล้ว) เราแค่ต้องแน่ใจว่า
            # อุปกรณ์ไม่มีขยะค้างก่อนที่ผู้ใช้จะกดคำสั่งถัดไป
            if "<edit-config>" in payload and "<rpc-error>" in reply:
                await self._discard_candidate(session, "edit-config ถูกอุปกรณ์ปฏิเสธ")

            # Juniper/Huawei และ Cisco candidate-only ต้อง commit หลัง edit-config
            # ส่วน Cisco ที่ประกาศ writable-running เขียนลง running ตรง ๆ
            elif "<edit-config>" in payload:
                commit = commit_payload(session["vendor"], candidate_override=self._uses_candidate(session))
                if commit:
                    commit_expected_id = _extract_message_id(commit)
                    session["process"].stdin.write(commit.rstrip() + NETCONF_END)
                    if commit_expected_id:
                        commit_reply = await _read_matching_reply(
                            session["process"], session["buffer"], commit_expected_id
                        )
                    else:
                        commit_reply = await read_dev_response(session["process"], session["buffer"])
                    # ยืนยันจริงกับอุปกรณ์ (vSRX): commit ที่เปลี่ยน family ของ
                    # interface (route mode -> ethernet-switching "mix mode")
                    # ครั้งแรก อุปกรณ์ตอบ <rpc-error> ที่ <error-severity>
                    # เป็น "warning" (ไม่ใช่ "error") คู่กับ <ok/> ในเรพลายเดียวกัน
                    # เสมอ - ตาม RFC 6241 §4.3 rpc-reply มี rpc-error หลายอันเป็น
                    # warning ปนมาได้โดยที่ operation ยังสำเร็จจริง (มี <ok/> ยืนยัน)
                    # เดิมเช็คแค่ "<rpc-error>" ลอยๆ เลย throw ทิ้งทั้งที่ config
                    # apply ผ่านจริงแล้ว (ยืนยันด้วย show configuration หลัง commit)
                    if "<rpc-error>" in commit_reply and "<ok/>" not in commit_reply:
                        # commit ล้มเหลวจริง - edit-config ก่อนหน้านี้สำเร็จไปแล้ว
                        # และยังค้างอยู่ใน candidate ต้อง discard ทิ้งทันที ไม่งั้น
                        # ความพยายามครั้งต่อไปจะเจอ candidate ที่ยังมีขยะจากรอบนี้
                        # ปนอยู่ (สะสมพังเพิ่มขึ้นเรื่อยๆ ทุกครั้งที่ fail)
                        await self._discard_candidate(session, "commit ล้มเหลว")
                        raise RuntimeError(f"{session['vendor']} commit failed: {commit_reply}")

            return reply

    # async def refresh_identity(self, dev_id: str) -> dict:


    # (bug 42) ต้องมี try/finally ครอบทั้งฟังก์ชันเพื่อ "ปิด connection เสมอไม่ว่าจะออก
    # ทางไหน" - asyncssh.listen_reverse() ไม่ได้ปิด connection ให้อัตโนมัติเมื่อ acceptor
    # callback นี้คืนค่า ถ้าเราไม่ปิดเอง connection จะค้างเปิดอยู่บน server แบบไม่มีใคร
    # ถืออ้างอิงเลย และที่ร้ายกว่านั้นคือ "อุปกรณ์ยังคิดว่าตัวเองเชื่อมต่ออยู่ จึงไม่
    # call-home เข้ามาใหม่อีกเลย"
    #
    # จุดรั่วที่เจอจริง (ไม่ใช่แค่จุดเดียว):
    #   1. `return` ตอน device is None (ยังไม่ได้ pre-register) - เจอบ่อยที่สุด เพราะ
    #      หลังลบอุปกรณ์แล้วลงทะเบียนใหม่ อุปกรณ์จะ reconnect เข้ามาก่อนที่ผู้ใช้จะกด
    #      ลงทะเบียนเสร็จเสมอ พอโดนปฏิเสธรอบเดียวก็ค้างตายไม่ retry อีกเลย
    #   2. ทุก exception ก่อนถึงจุดสร้าง session (hello exchange ล้มเหลว, token/metadata
    #      timeout, DB error, detect vendor ไม่ออก) - `except` ชั้นนอกแค่ print แล้วจบ
    #
    # ทั้ง 2 กรณีข้ามบล็อก `try: await connection.wait_closed()` ที่เป็นจุดเดียวที่จัดการ
    # วงจรชีวิตของ connection ไปทั้งหมด - ปิดที่ finally ชั้นนอกนี้จึงครอบคลุมทุกเส้นทาง
    # ผลคืออุปกรณ์ที่ยังไม่ลงทะเบียนจะโดนตัดทันทีแล้ว retry เข้ามาใหม่เรื่อยๆ พอผู้ใช้
    # ลงทะเบียนเสร็จ รอบถัดไปก็ผ่านและขึ้น active เองตามที่ระบบตั้งใจไว้แต่แรก
    # Phase 7: ทุก connection อยู่ใน quarantine จนกว่าจะผ่านเส้นทาง authentication ที่เหมาะสม - ห้ามเรียก
    # _register_session/_start_capability_probe และห้ามแตะ sessions/stats ก่อนถึงจุดนั้น (ดู callhome_auth_router.py)
    #   1) fingerprint reconnect (Device ที่มี consumed Enrollment): ไม่อ่าน token ไม่ probe MAC/Serial
    #   2) first enrollment: อ่าน token แบบ read-only -> resolve pending Enrollment (Phase 8 ค่อย consume/pin/activate)
    #      Phase 7 จึงปิด connection หลัง resolve สำเร็จ (ไม่ register) เพื่อให้อุปกรณ์ retry เมื่อ Phase 8 พร้อม
    # ไม่มี legacy fallback: marker/token/fingerprint ไม่ผ่านต้องถูกปฏิเสธ
    # ข้อความ log เป็น event code ที่ sanitized: ไม่มี token/hash/raw XML และไม่แยกเหตุผลของ token ที่ไม่ผ่าน
    def _log_auth(self, event: str, ip: str, fingerprint, *, detail: bool = False) -> None:
        # detail=True: success/progress lines, shown only with CALLHOME_VERBOSE_LOG; rejections always shown
        if detail and not verbose_enabled():
            return
        print(f"[auth] callhome_auth={event} ip={ip} fp={short_id(fingerprint)}")

    def _reject(self, decision: RejectedConnection, ip: str, fingerprint, *, count: bool = True) -> None:
        self._log_auth(f"rejected reason={decision.reason.value}", ip, fingerprint)
        if count and decision.reason not in (RejectReason.RATE_LIMITED, RejectReason.BUSY):
            # Historical devices may keep retrying an old endpoint forever. Rate-limit that
            # host key, but do not let it consume the shared NAT/IP budget and block a new
            # token device at the same Site.
            self.auth_router.record_failure(
                ip, fingerprint, count_ip=decision.reason is not RejectReason.LEGACY_DISABLED
            )

    # metadata (hostname/model/firmware) ก่อนเปิด transaction: read-only, มี timeout แยก, ไม่ถือ DB lock ระหว่างรอ NETCONF
    # ไม่ใช่ส่วนของ authentication - ค่าที่ขาด/timeout คงค่าเดิมใน DB ; connection ปิดกลางทาง -> ไม่ activate
    async def _read_metadata(self, process, buffer, vendor: str):
        async def send(message_id: int, payload: str) -> str:
            process.stdin.write(payload)
            return await read_dev_response(process, buffer, timeout=METADATA_RPC_TIMEOUT)

        try:
            return await asyncio.wait_for(
                read_device_metadata(send, vendor, next(_metadata_message_ids)), METADATA_TOTAL_TIMEOUT
            )
        except asyncio.TimeoutError:
            return None  # metadata เป็น optional - ไม่ทำให้ credential ที่ถูกต้องเสีย

    async def _debug_connection_identity(self, process, buffer, vendor: str, ip: str) -> None:
        """When explicitly enabled, read one serial RPC and log IP+serial only.

        Debug failure/timeout is non-fatal and never changes authentication.
        With the default disabled value this sends no extra RPC at all.
        """
        if not (identity_debug_enabled() or verbose_enabled()):
            return None

        async def send(message_id: int, payload: str) -> str:
            process.stdin.write(payload)
            return await read_dev_response(process, buffer, timeout=METADATA_RPC_TIMEOUT)

        serial = None
        try:
            serial = await asyncio.wait_for(
                read_device_serial(send, vendor, next(_metadata_message_ids)), METADATA_RPC_TIMEOUT
            )
        except Exception:
            pass
        log_identity(ip, serial)
        return serial

    # attach session เข้า pool: ภายใน lifecycle lock ของ dev_id (กัน orphan session เมื่อแข่งกับการลบ Device/Site/User)
    # activate (ถ้ามี) = coroutine ที่ commit transaction ของ activation เสร็จแล้วคืน True - register เกิดหลัง commit เสมอ
    # ถ้าขั้น in-memory หลัง commit ล้ม: DB ไม่ถูกย้อน (Device ยัง active+consumed+pinned; retry ด้วย fingerprint ได้)
    async def _attach_session(
        self, dev_id, connection, process, buffer, vendor, capabilities, ip, fingerprint,
        *, activate=None, is_fingerprint_route: bool = False
    ):
        async with device_lifecycle.hold(dev_id):
            committed = False
            if activate is not None:
                if not await activate():
                    return False
                committed = True
            elif is_fingerprint_route:
                if not await self._verify_fingerprint_reconnect_target(dev_id, vendor, fingerprint):
                    self._log_auth("rejected reason=stale_fingerprint_reconnect", ip, fingerprint)
                    return False
            elif not await self._device_exists(dev_id):
                self._log_auth("rejected reason=device_gone", ip, fingerprint)
                return False
            try:
                self._register_session(dev_id, connection, process, buffer, vendor, capabilities)
                self._start_capability_probe(dev_id, connection, vendor, capabilities)
            except Exception:
                self._release_session(dev_id, connection, ip)
                if committed:
                    self._log_auth("token_activation committed_session_attach_failed", ip, fingerprint)
                else:
                    self._log_auth("session_attach_failed", ip, fingerprint)
                return False
        return True

    async def _verify_fingerprint_reconnect_target(self, dev_id: str, vendor: str, fingerprint: str) -> bool:
        from backend.crud.dev_crud.crud_device_enrollment import is_active_consumed_enrolled_device
        try:
            async with AsyncSessionFactory() as session:
                return await is_active_consumed_enrolled_device(session, dev_id, vendor, fingerprint)
        except Exception as exc:
            print(f"[!] _verify_fingerprint_reconnect_target DB error for {dev_id}: {exc}")
            return False

    async def _device_exists(self, dev_id: str) -> bool:
        async with AsyncSessionFactory() as session:
            return await session.get(Device_Information, dev_id) is not None

    async def accept(self, connection):
        peer = connection.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        fingerprint = get_host_key_fingerprint(connection)
        dev_id = ""
        is_fingerprint_route = False
        # the one line always shown per connection; details need CALLHOME_VERBOSE_LOG=true
        print(f"[+] Call Home from {ip}  host-key: {fingerprint or 'none'}")
        try:
            # F3: host-key pinning พึ่ง fingerprint ของ host key อุปกรณ์เป็นตัวระบุตัวตน ถ้าอ่านไม่ได้เลย
            # (ไม่มี host key) ก็ pin/เทียบไม่ได้ - ปฏิเสธตั้งแต่ต้นก่อนเปิด NETCONF subsystem (fail closed)
            # กรณีนี้ไม่เกิดกับอุปกรณ์ SSH ปกติที่มี host key เสมอ
            if not fingerprint:
                self._reject(RejectedConnection(RejectReason.NO_HOST_KEY), ip, fingerprint)
                return
            if self.auth_router.is_rate_limited(ip, fingerprint):
                self._reject(RejectedConnection(RejectReason.RATE_LIMITED), ip, fingerprint)
                return

            # step 0: จำแนกด้วย fingerprint จาก transport จริง "ก่อน" เปิด NETCONF (อ่าน DB อย่างเดียว)
            try:
                route = await asyncio.wait_for(self.auth_router.route_by_fingerprint(fingerprint), QUARANTINE_TOTAL_TIMEOUT)
            except asyncio.TimeoutError:
                route = RejectedConnection(RejectReason.TIMEOUT)
            if isinstance(route, RejectedConnection):
                self._reject(route, ip, fingerprint)
                return

            # step 1: SSH + netconf subsystem ผ่านแล้ว (login ด้วย key กลาง)
            process = await connection.create_process(
                subsystem="netconf",
                encoding="utf-8",
            )
            buffer = [""]

            # step 2: hello exchange -> ได้ vendor + capability
            process.stdin.write(HELLO_PAYLOAD)
            hello = await read_dev_response(process, buffer)
            raw_capabilities = normalize_capabilities("unknown", hello)["capabilities"]
            vendor = vender_detector(raw_capabilities)
            capability_json = normalize_capabilities(vendor, hello)

            if isinstance(route, FingerprintReconnect):
                # เส้นทาง 1: Device เดิมที่ผ่าน token enrollment แล้ว - ตรวจ vendor ให้ตรงก่อน register เท่านั้น
                # ไม่อ่าน token และไม่เรียก identity/MAC/Serial authentication เดิม
                mismatch = self.auth_router.check_vendor(route, vendor)
                if mismatch is not None:
                    self._reject(mismatch, ip, fingerprint)
                    return
                serial = await self._debug_connection_identity(process, buffer, vendor, ip)
                # อ่านเฉพาะ hostname/model/firmware หลังยืนยัน fingerprint+vendor แล้ว
                # และก่อน register session จึงไม่มี NETCONF reader/poller ตัวอื่นมาแย่ง
                # reply บน process เดียวกัน ค่าเหล่านี้เป็น display metadata เท่านั้น:
                # timeout/rpc-error คงค่าฐานข้อมูลเดิมและไม่ทำให้ auth ล้มเหลว
                try:
                    metadata = await self._read_metadata(process, buffer, vendor)
                except MetadataConnectionLost:
                    self._log_auth("fingerprint_reconnect aborted reason=connection_lost", ip, fingerprint)
                    return
                async with AsyncSessionFactory() as session:
                    if not await update_device_connection_metadata(
                        session,
                        route.device_id,
                        peer_ip=ip if ip != "unknown" else None,
                        metadata=metadata,
                    ):
                        self._log_auth("rejected reason=device_gone", ip, fingerprint)
                        return
                    await upsert_capability(session, route.device_id, vendor, capability_json)
                dev_id = route.device_id
                is_fingerprint_route = True
                self._log_auth("fingerprint_reconnect accepted", ip, fingerprint, detail=True)
            else:
                # เส้นทาง 2/3: first-enrollment quarantine - อ่าน marker ของ endpoint/client แบบ read-only
                async def send(message_id: int, payload: str) -> str:
                    process.stdin.write(payload)
                    return await read_dev_response(process, buffer, timeout=QUARANTINE_RPC_TIMEOUT)

                decision = await self.auth_router.quarantine_token_stage(send, vendor)
                if isinstance(decision, RejectedConnection):
                    self._reject(decision, ip, fingerprint)  # ห้าม fallback legacy ทุกกรณี
                    return
                if isinstance(decision, PendingEnrollmentCandidate):
                    # Phase 8: atomic activation ของ pending Device เดิม (ไม่สร้างแถวใหม่, ไม่ probe/บันทึก MAC/Serial)
                    #   metadata (read-only, ก่อน transaction) -> [lifecycle lock] transaction เดียว: lock/recheck/consume/pin/
                    #   activate/capability -> commit ครั้งเดียว -> register session ; fingerprint มาจาก transport เท่านั้น
                    # Diagnostic serial is a separate opt-in RPC.  Display
                    # metadata stays one compact RPC and never carries the
                    # performance cost when debugging is disabled.
                    serial = await self._debug_connection_identity(process, buffer, vendor, ip)
                    try:
                        metadata = await self._read_metadata(process, buffer, vendor)
                    except MetadataConnectionLost:
                        self._log_auth("token_activation aborted reason=connection_lost", ip, fingerprint)
                        return
                    async def activate() -> bool:
                        try:
                            async with AsyncSessionFactory() as session:
                                try:
                                    await activate_pending_enrollment(
                                        session,
                                        candidate=decision,
                                        observed_fingerprint=fingerprint,
                                        detected_vendor=vendor,
                                        peer_ip=ip if ip != "unknown" else None,
                                        metadata=metadata,
                                        capability_detail=capability_json,
                                    )
                                    await session.commit()  # commit เพียงครั้งเดียวของ activation
                                except Exception:
                                    await session.rollback()
                                    raise
                        except ActivationError as error:
                            self._log_auth(f"token_activation {error.event} reason={error.reason.value}", ip, fingerprint)
                            if error.event != "conflict":
                                self.auth_router.record_failure(ip, fingerprint)
                            return False
                        except Exception:
                            self._log_auth("token_activation persistence_error", ip, fingerprint)
                            return False
                        self._log_auth("token_activation accepted", ip, fingerprint, detail=True)
                        return True

                    dev_id = decision.device_id
                    if not await self._attach_session(
                        dev_id, connection, process, buffer, vendor, raw_capabilities, ip, fingerprint, activate=activate
                    ):
                        dev_id = ""
                        return
                    log_connected_device(ip=ip, fingerprint=fingerprint, vendor=vendor, dev_id=dev_id,
                                         route="first enrollment", metadata=metadata, serial=serial)
                    try:
                        await connection.wait_closed()
                    finally:
                        self._release_session(dev_id, connection, ip)
                    return

                # Full-token mode must never reach a MAC/Serial authentication path.
                self._reject(RejectedConnection(RejectReason.LEGACY_DISABLED), ip, fingerprint)
                return

            # step 5: เก็บ session ไว้ให้ send_payload() เรียกใช้ได้ตราบเท่าที่ connection ยังเปิดอยู่ - "จุดเดียว"
            # ที่ connection เข้า sessions pool (หลังผ่านเส้นทาง authentication ที่ถูกต้องแล้วเท่านั้น)
            # (bug 42) เก็บ "connection" ไว้ด้วย ไม่ใช่แค่ process - ดู close_session()
            if not await self._attach_session(
                dev_id, connection, process, buffer, vendor, raw_capabilities, ip, fingerprint,
                is_fingerprint_route=is_fingerprint_route
            ):
                return
            log_connected_device(ip=ip, fingerprint=fingerprint, vendor=vendor, dev_id=dev_id,
                                 route="fingerprint reconnect", metadata=metadata, serial=serial)

            try:
                await connection.wait_closed()
            finally:
                self._release_session(dev_id, connection, ip)
        except Exception as exc:
            # ไม่พิมพ์ exc ที่อาจมี reply/ค่าจากอุปกรณ์ที่ยังไม่ authenticate ในเส้นทาง quarantine: ใช้ชื่อชนิดเท่านั้น
            print(f"[-] Session error from {ip}: {type(exc).__name__}")
        finally:
            # ปิด connection เสมอไม่ว่าจะออกจากฟังก์ชันทางไหน (return ตอนถูกปฏิเสธ / exception / จบ session ปกติ)
            try:
                connection.close()
            except Exception as exc:
                print(f"[!] Failed to close call-home connection from {ip}: {exc}")


callhome_service = CallhomeService()


if __name__ == "__main__":
    async def main():
        await callhome_service.start()
        print("[*] Waiting for Call Home connections... (Ctrl+C to stop)")
        try:
            await asyncio.get_event_loop().create_future()
        except KeyboardInterrupt:
            pass
        finally:
            await callhome_service.stop()
            print("[*] Stopped.")

    asyncio.run(main())
