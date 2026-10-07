"""งานตรวจความสามารถอุปกรณ์ตอน call-home (dynamic feature ขั้นที่ 3)

สร้างโปรไฟล์ที่ backend/capability_service.py ใช้ตัดสิน ด้วยคำสั่งอ่านอย่างเดียว (<get>)
ดีไซน์: planning/capability_detection_notes.txt หัวข้อ 9-10 · ความคืบหน้า: planning/dynamic_feature_progress.md

ไฟล์นี้ไม่คุยกับ NETCONF session เอง ผู้เรียก (conn_socket.py) ส่งฟังก์ชัน send เข้ามา จึงไม่ต้อง
import conn_socket (กัน import วน) และทดสอบได้โดยไม่ต้องต่ออุปกรณ์

กติกาของ send: รับ (payload, timeout) คืน reply XML
  - โยน ProbeAborted เมื่อต้องหยุดตรวจทั้งหมด (connection ถูกแทนที่ หรือท่อตาย)
  - exception อื่น (timeout, desync ฯลฯ) นับเป็นความล้มเหลวของชั้นนั้นชั้นเดียว แล้วตรวจชั้นถัดไปต่อ
"""
from datetime import datetime, timezone
from typing import Awaitable, Callable
from xml.etree import ElementTree as ET

from tools.safe_xml import safe_fromstring
from backend.translator_service import module_for_vendor
from vendor_translators import capability_normalizer

# เพิ่มค่านี้ทุกครั้งที่แก้ parser, ลำดับการตรวจ หรือรูปแบบโปรไฟล์ - โปรไฟล์เดิมที่ version ไม่ตรงจะไม่ถูก
# ใช้เป็น cache อุปกรณ์ทุกเครื่องจึงดึง schema ใหม่ใน call-home ครั้งถัดไปโดยไม่ต้องแก้ฐานข้อมูลเอง
PROFILE_VERSION = 1

# วัดจริง 15 ก.ย. 2026 (zCapability/time_*): c8000 0.22-0.27 วิ, c9000 0.74 วิ, CE12800 0.72 วิ, vSRX 0.14 วิ
# ตั้ง 20 วิเท่ากับ timeout ตั้งต้นของคำสั่งทั่วไป (เกินค่าที่วัดได้ราว 27 เท่า) ไม่ตั้งยาวกว่านี้เพราะระหว่างรอ
# lock ของอุปกรณ์ถูกถือไว้และคำสั่งของผู้ใช้ต้องรอ · timeout ระหว่างที่ข้อมูลยังมาไม่ครบถูกนับเป็น NetconfSilent
# และเริ่มนับเวลาตัด session (SILENCE_CUTOFF_SECONDS ใน conn_socket.py) - ไม่ retry เพื่อไม่ให้ซ้ำเติม
SCHEMA_TIMEOUT_SECONDS = 20
SMALL_READ_TIMEOUT_SECONDS = 20

# ชั้นที่แต่ละยี่ห้อต้องมีจึงถือว่าตรวจครบ
_LAYERS_BY_VENDOR = {
    "cisco": ("license", "schema"),
    "juniper": ("model", "schema"),
    "huawei": ("schema",),
}
_USABLE_STATUSES = {"ok", "not_configured", "not_found"}

Send = Callable[[str, float], Awaitable[str]]


class ProbeAborted(Exception):
    """หยุดตรวจทั้งหมดทันที - connection ถูกแทนที่หรือท่อตาย ผู้เรียกไม่ควรบันทึกผล"""


def _failed(message: str) -> dict:
    return {"status": "failed", "message": message, "errors": []}


async def _run_layer(send: Send, module, function_name: str, parse: Callable[[str], dict], timeout: float) -> dict:
    try:
        payload = getattr(module, function_name)()
        safe_fromstring(payload.strip())
    except Exception as exc:
        # บทเรียน BUG-109: XML ที่พังทำให้ Huawei ตอบโดยไม่มี message-id จึงห้ามส่งออกไป
        return _failed(f"Payload of {function_name} is invalid: {exc}")
    try:
        reply = await send(payload, timeout)
    except ProbeAborted:
        raise
    except Exception as exc:
        return _failed(f"{type(exc).__name__}: {exc}")
    return parse(reply)


def _cached_schema(previous: dict | None, schema_id: str | None) -> dict | None:
    """ใช้ schema เดิมได้เฉพาะเมื่อตัวระบุชุด schema จาก hello ตรงกัน ของเดิมตรวจสำเร็จ และสร้างด้วย
    PROFILE_VERSION เดียวกัน
    ดึงไม่สำเร็จจะไม่ถอยไปใช้ของเดิมที่ตัวระบุไม่ตรง เพราะอาจล้าสมัย - failed ปลอดภัยกว่า
    เนื่องจาก resolver ไม่ซ่อนอะไรเมื่อชั้น schema ล้มเหลว"""
    if not schema_id or not previous or previous.get("schema_id") != schema_id:
        return None
    # โปรไฟล์จากโค้ดรุ่นอื่นอาจเก็บ namespace ผิด ถ้ายอมใช้ต่อ ของผิดจะติดค้างไปจนกว่า firmware
    # หรือชุด schema ของอุปกรณ์จะเปลี่ยน แม้แก้ parser แล้วก็ตาม
    if previous.get("version") != PROFILE_VERSION:
        return None
    schema = previous.get("schema")
    if not isinstance(schema, dict) or schema.get("status") != "ok":
        return None
    return {**schema, "cached": True}


def _overall_status(profile: dict) -> str:
    layers = _LAYERS_BY_VENDOR.get(profile["vendor"], ("schema",))
    usable = [(profile.get(layer) or {}).get("status") in _USABLE_STATUSES for layer in layers]
    if all(usable):
        return "ok"
    return "partial" if any(usable) else "failed"


async def build_profile(
    vendor: str,
    hello_capabilities: list[str] | None,
    send: Send,
    previous_profile: dict | None = None,
) -> dict:
    """คืนโปรไฟล์เสมอและไม่ raise (ยกเว้น asyncio.CancelledError) - ชั้นที่ยังไม่ได้ตรวจเป็น None
    ลำดับ: รุ่นเครื่อง (Juniper) / license (Cisco) ก่อนเพราะ reply เล็ก แล้วค่อย schema"""
    profile = {
        "version": PROFILE_VERSION,
        "vendor": vendor,
        "checked_at": None,
        "status": "failed",
        "schema_id": capability_normalizer.extract_content_id(hello_capabilities or []),
        "schema": None,
        "license": None,
        "model": None,
        "aborted": False,
    }
    module = module_for_vendor(vendor)
    if module is None:
        profile["schema"] = _failed(f"Unknown vendor {vendor}")
    else:
        previous = previous_profile if isinstance(previous_profile, dict) and previous_profile.get("vendor") == vendor else None
        try:
            if vendor == "juniper":
                profile["model"] = await _run_layer(
                    send, module, "get_cpu_memory_information",
                    capability_normalizer.parse_route_engine_model, SMALL_READ_TIMEOUT_SECONDS,
                )
            if vendor == "cisco":
                profile["license"] = await _run_layer(
                    send, module, "get_boot_license",
                    capability_normalizer.parse_boot_license, SMALL_READ_TIMEOUT_SECONDS,
                )
            cached = _cached_schema(previous, profile["schema_id"])
            if cached is not None:
                profile["schema"] = cached
            else:
                profile["schema"] = await _run_layer(
                    send, module, "get_capability_schema",
                    capability_normalizer.parse_capability_schema, SCHEMA_TIMEOUT_SECONDS,
                )
        except ProbeAborted as exc:
            profile["aborted"] = True
            profile["abort_reason"] = str(exc)

    profile["checked_at"] = datetime.now(timezone.utc).isoformat()
    profile["status"] = _overall_status(profile)
    return profile
