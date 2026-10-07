""" |======= Call Home Authentication Router (fingerprint / first-enrollment token) =======| """
# Phase 7: จำแนก inbound Call Home connection ก่อนเข้า session pool
#   1) fingerprint reconnect : Active Device ที่มี consumed Enrollment marker + dev_fingerprint ตรง (ห้ามอ่าน token/MAC/Serial)
#   2) first enrollment      : อ่าน token จาก endpoint/client แบบ read-only -> validate/hash/lookup pending Enrollment
#                              (Phase 7 ไม่ consume/ไม่ pin fingerprint/ไม่ activate - ส่ง PendingEnrollmentCandidate ให้ Phase 8)
# Connection ที่ไม่ตรงสองเส้นทางข้างบนถูกปฏิเสธ ไม่มี MAC/Serial fallback
# ไฟล์นี้อ่านฐานข้อมูลอย่างเดียว (session สั้น ๆ ที่ปิดก่อนไปทำ network) ไม่ register session และไม่แก้ Device/Enrollment
# ห้าม log/print token, hash, raw XML: result ทุกชนิดซ่อนค่าลับใน repr และเหตุผลภายใน (RejectReason) แยกจากข้อความสาธารณะ
import asyncio
import itertools
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Callable, Optional, Union

from backend.callhome_auth_mode import TOKEN, get_auth_mode, validate_mode
from backend.callhome_token_probe import PROBE_STEPS, ProbeStatus, read_token_marker
from backend.crud.dev_crud.crud_device_enrollment import (
    find_devices_by_fingerprint,
    get_device_for_enrollment,
    get_pending_enrollment_by_token_hash,
    get_pending_enrollments_by_token_hashes,
)
from backend.enrollment_token_service import hash_enrollment_token, validate_enrollment_token

# ---------- นโยบาย quarantine (ค่าคงที่ที่เดียว แยกจาก timeout ของ command/session ปกติใน conn_socket) ----------
# ต่อ RPC ของ token probe: อุปกรณ์จริงตอบใน ~0.1-0.3 วิ (zCapability/ressss) 8 วิเผื่อ CPU สูง/Cisco ที่ช้า
QUARANTINE_RPC_TIMEOUT = 8.0
# เวลารวมของขั้น token probe + DB lookup (สูงสุด 2 RPC + DB) - ตัดเมื่อเกินเพื่อไม่ค้างทรัพยากรก่อน authenticate
QUARANTINE_TOTAL_TIMEOUT = 30.0
# จำนวน token probe พร้อมกันทั้งระบบ (probe เป็น NETCONF สด ๆ จาก anonymous device) - ที่เหลือรอคิวได้สั้น ๆ แล้วถูกปิด
QUARANTINE_MAX_CONCURRENT = 8
QUARANTINE_QUEUE_TIMEOUT = 5.0
# ความล้มเหลวที่นับต่อ (IP + fingerprint ย่อ) และต่อ IP ในหน้าต่างเวลา: ต่อ IP กว้างกว่าเพราะหลายอุปกรณ์ใน Site เดียว
# อาจอยู่หลัง NAT เดียวกัน (deploy พร้อมกันหลายเครื่องต้องไม่ถูกบล็อกทั้ง Site)
QUARANTINE_ATTEMPTS_PER_DEVICE = 10
QUARANTINE_ATTEMPTS_PER_IP = 60
QUARANTINE_RATE_WINDOW = 60.0
QUARANTINE_RATE_MAX_KEYS = 4096  # ขอบเขตหน่วยความจำของ limiter


class RejectReason(Enum):
    """เหตุผลภายใน (เพื่อ test/metric) - ห้ามส่งออกทางข้อความสาธารณะ ดู public_message()"""
    DB_ERROR = "db_error"
    FINGERPRINT_AMBIGUOUS = "fingerprint_ambiguous"
    FINGERPRINT_INVALID_STATE = "fingerprint_invalid_state"
    VENDOR_MISMATCH = "vendor_mismatch"
    AMBIGUOUS_ENDPOINT = "ambiguous_endpoint"
    PROBE_FAILED = "probe_failed"
    TOKEN_INVALID = "token_invalid"
    TOKEN_NOT_ACCEPTED = "token_not_accepted"  # ไม่พบ/หมดอายุ/ถูกลบ/ถูก consume/hash ไม่ตรง (แยกไม่ได้โดยเจตนา)
    ENROLLMENT_INVARIANT = "enrollment_invariant"
    RATE_LIMITED = "rate_limited"
    BUSY = "busy"
    TIMEOUT = "timeout"
    UNKNOWN_VENDOR = "unknown_vendor"
    LEGACY_DISABLED = "legacy_disabled"  # token mode: connection ที่ไม่มี marker/fingerprint ที่รู้จักถูกปฏิเสธ (ไม่ fallback)
    NO_HOST_KEY = "no_host_key"  # F3: connection ที่อ่าน host key (fingerprint) ไม่ได้เลย - ปฏิเสธก่อนเปิด NETCONF (host-key pinning ต้องมี fingerprint เสมอ)


_TOKEN_PUBLIC = "Enrollment credential was not accepted"
_PUBLIC_MESSAGES = {
    RejectReason.TOKEN_INVALID: _TOKEN_PUBLIC,
    RejectReason.TOKEN_NOT_ACCEPTED: _TOKEN_PUBLIC,
    RejectReason.ENROLLMENT_INVARIANT: _TOKEN_PUBLIC,
    RejectReason.VENDOR_MISMATCH: _TOKEN_PUBLIC,
    RejectReason.RATE_LIMITED: "Too many attempts",
    RejectReason.BUSY: "Too many attempts",
}


def public_message(reason: "RejectReason") -> str:
    return _PUBLIC_MESSAGES.get(reason, "Call Home authentication failed")


def short_id(value: Optional[str]) -> str:
    """ตัวระบุย่อของ fingerprint สำหรับ log/rate key (ไม่ใช่ secret และไม่ใช้เทียบ credential)"""
    if not value:
        return "none"
    return sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


# ---------- ผลการตัดสินใจ ----------

@dataclass(frozen=True)
class FingerprintReconnect:
    device_id: str
    vendor: str


@dataclass(frozen=True)
class PendingEnrollmentCandidate:
    """ข้อมูลขั้นต่ำที่ Phase 8 ต้องใช้ทำ conditional claim (ไม่มี plaintext token; hash ถูกซ่อนจาก repr)"""
    device_id: str
    enrollment_id: str
    vendor: str
    token_hash: str = field(repr=False)

    def __repr__(self) -> str:
        return f"PendingEnrollmentCandidate(device_id={self.device_id!r}, vendor={self.vendor!r})"

    __str__ = __repr__


@dataclass(frozen=True)
class NotFingerprintRoute:
    """fingerprint ไม่ตรง Device ที่ใช้ token authentication - เข้า first-enrollment quarantine"""


@dataclass(frozen=True)
class RejectedConnection:
    reason: RejectReason

    @property
    def message(self) -> str:
        return public_message(self.reason)


Decision = Union[FingerprintReconnect, PendingEnrollmentCandidate, NotFingerprintRoute, RejectedConnection]


# ---------- rate limiter (in-memory, bounded, มี TTL) ----------

class FailureRateLimiter:
    def __init__(self, max_attempts: int, window: float, max_keys: int = QUARANTINE_RATE_MAX_KEYS,
                 clock: Callable[[], float] = time.monotonic):
        self.max_attempts = max_attempts
        self.window = window
        self.max_keys = max_keys
        self._clock = clock
        self._entries: "OrderedDict[str, tuple[float, int]]" = OrderedDict()  # key -> (window_start, count)

    def _purge(self, now: float) -> None:
        while self._entries:
            key, (start, _) = next(iter(self._entries.items()))
            if now - start < self.window:
                break
            del self._entries[key]  # เรียงตามเวลาเริ่ม: ตัวหน้าสุดเก่าสุด
        while len(self._entries) > self.max_keys:
            self._entries.popitem(last=False)

    def is_limited(self, key: str) -> bool:
        now = self._clock()
        self._purge(now)
        entry = self._entries.get(key)
        return entry is not None and entry[1] >= self.max_attempts

    def record_failure(self, key: str) -> None:
        now = self._clock()
        self._purge(now)
        entry = self._entries.get(key)
        if entry is None or now - entry[0] >= self.window:
            self._entries[key] = (now, 1)
            self._entries.move_to_end(key)
        else:
            self._entries[key] = (entry[0], entry[1] + 1)
        self._purge(now)

    def __len__(self) -> int:
        return len(self._entries)


class CallhomeAuthRouter:
    def __init__(self, session_factory: Callable, clock: Callable[[], float] = time.monotonic, mode: Optional[str] = None):
        # โหมดถูก resolve ครั้งเดียวตอนสร้าง (เปลี่ยนโหมด = restart) ค่าไม่รู้จัก raise InvalidAuthMode (fail closed)
        self.mode = validate_mode(mode if mode is not None else get_auth_mode())
        self._session_factory = session_factory  # callable -> AsyncSession (เรียกตอนใช้ ไม่ถือค้าง)
        self._semaphore = asyncio.Semaphore(QUARANTINE_MAX_CONCURRENT)
        self.device_limiter = FailureRateLimiter(QUARANTINE_ATTEMPTS_PER_DEVICE, QUARANTINE_RATE_WINDOW, clock=clock)
        self.ip_limiter = FailureRateLimiter(QUARANTINE_ATTEMPTS_PER_IP, QUARANTINE_RATE_WINDOW, clock=clock)

    # --- rate limit (เฉพาะ connection ที่ต้องใช้ token probe/ล้มเหลว; fingerprint reconnect ที่ถูกต้องไม่ถูกนับ) ---
    @staticmethod
    def _keys(ip: str, fingerprint: Optional[str]) -> tuple[str, str]:
        return f"{ip}|{short_id(fingerprint)}", str(ip)

    def is_rate_limited(self, ip: str, fingerprint: Optional[str]) -> bool:
        device_key, ip_key = self._keys(ip, fingerprint)
        return self.device_limiter.is_limited(device_key) or self.ip_limiter.is_limited(ip_key)

    def record_failure(self, ip: str, fingerprint: Optional[str], *, count_ip: bool = True) -> None:
        device_key, ip_key = self._keys(ip, fingerprint)
        self.device_limiter.record_failure(device_key)
        if count_ip:
            self.ip_limiter.record_failure(ip_key)

    # --- concurrency ---
    @asynccontextmanager
    async def quarantine_slot(self):
        """จำกัด token probe พร้อมกัน: รอคิวได้สั้น ๆ ไม่ได้ -> BusyError (caller ปิด connection); release เสมอแม้ถูก cancel"""
        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=QUARANTINE_QUEUE_TIMEOUT)
        except asyncio.TimeoutError:
            raise QuarantineBusy() from None
        try:
            yield
        finally:
            self._semaphore.release()

    # --- 1) fingerprint route (DB read-only; ก่อนเปิด NETCONF) ---
    async def route_by_fingerprint(self, fingerprint: Optional[str]) -> Decision:
        """FingerprintReconnect | NotFingerprintRoute | RejectedConnection (fail closed: DB error/กำกวม/state ผิด)"""
        if not fingerprint:
            return NotFingerprintRoute()  # อ่านไม่ได้/ว่าง: ห้ามผ่าน fingerprint reconnect
        try:
            async with self._session_factory() as session:
                rows = await find_devices_by_fingerprint(session, fingerprint)
        except Exception:
            return RejectedConnection(RejectReason.DB_ERROR)
        if not any(enrollment is not None for _, enrollment in rows):
            return NotFingerprintRoute()  # ไม่มี Device ที่ใช้ token authentication ตรงกับ fingerprint นี้
        if len(rows) != 1:
            return RejectedConnection(RejectReason.FINGERPRINT_AMBIGUOUS)  # ห้ามเลือกตัวแรก
        device, enrollment = rows[0]
        # reconnect ได้เฉพาะ Active Device + Enrollment ที่ consume แล้ว (token_hash NULL, consumed_at มีค่า)
        if device.dev_status != "active" or enrollment.token_hash is not None or enrollment.consumed_at is None:
            return RejectedConnection(RejectReason.FINGERPRINT_INVALID_STATE)
        return FingerprintReconnect(device_id=device.dev_id, vendor=device.dev_vendor)

    @staticmethod
    def check_vendor(route: FingerprintReconnect, detected_vendor: str) -> Optional[RejectedConnection]:
        return None if detected_vendor == route.vendor else RejectedConnection(RejectReason.VENDOR_MISMATCH)

    # --- 2) resolve token -> Pending Enrollment (อ่านอย่างเดียว; ไม่ consume/ไม่ pin/ไม่ activate) ---
    async def resolve_pending_enrollment(self, tokens: Union[object, tuple, list], detected_vendor: str) -> Decision:
        if isinstance(tokens, str):
            token_list = [tokens]
        elif isinstance(tokens, (tuple, list, set)):
            token_list = list(tokens)
        else:
            return RejectedConnection(RejectReason.TOKEN_INVALID)

        valid_tokens = [t for t in token_list if validate_enrollment_token(t)]
        if not valid_tokens:
            return RejectedConnection(RejectReason.TOKEN_INVALID)  # ไม่มี token ใดผ่านรูปแบบ -> ไม่ lookup

        hash_to_token = {}
        for t in valid_tokens:
            h = hash_enrollment_token(t)
            hash_to_token[h] = t

        try:
            async with self._session_factory() as session:
                enrollments = await get_pending_enrollments_by_token_hashes(session, list(hash_to_token.keys()))
                if len(enrollments) == 0:
                    return RejectedConnection(RejectReason.TOKEN_NOT_ACCEPTED)
                if len(enrollments) > 1:
                    return RejectedConnection(RejectReason.AMBIGUOUS_ENDPOINT)
                enrollment = enrollments[0]
                device = await get_device_for_enrollment(session, enrollment)
                if device is None:
                    return RejectedConnection(RejectReason.TOKEN_NOT_ACCEPTED)
                candidate = self._candidate_or_reject(device, enrollment, enrollment.token_hash, detected_vendor)
        except Exception:
            return RejectedConnection(RejectReason.DB_ERROR)
        return candidate

    @staticmethod
    def _candidate_or_reject(device, enrollment, token_hash: str, detected_vendor: str) -> Decision:
        if detected_vendor != device.dev_vendor:
            return RejectedConnection(RejectReason.VENDOR_MISMATCH)
        # invariant ของ pending Device ที่ Phase 5 สร้าง: ยังไม่มี fingerprint - ผิดจากนี้ fail closed
        if (
            device.dev_status != "pending"
            or device.dev_fingerprint is not None
            or enrollment.consumed_at is not None
            or enrollment.token_hash != token_hash
        ):
            return RejectedConnection(RejectReason.ENROLLMENT_INVARIANT)
        return PendingEnrollmentCandidate(
            device_id=device.dev_id, enrollment_id=enrollment.enrollment_id, vendor=device.dev_vendor, token_hash=token_hash,
        )


    # --- first-enrollment quarantine: token probe (network) -> ปิดขั้น network -> DB session สั้น ๆ ---
    async def quarantine_token_stage(self, send, vendor: str) -> Decision:
        """PendingEnrollmentCandidate | RejectedConnection (ไม่ register session, ไม่แก้ DB)"""
        if vendor not in PROBE_STEPS:
            return RejectedConnection(RejectReason.UNKNOWN_VENDOR)
        expected_ip, expected_port = expected_cloud_target()
        first_message_id = next(_message_ids)
        try:
            async with self.quarantine_slot():
                return await asyncio.wait_for(
                    self._token_stage(send, vendor, expected_ip, expected_port, first_message_id), QUARANTINE_TOTAL_TIMEOUT
                )
        except QuarantineBusy:
            return RejectedConnection(RejectReason.BUSY)
        except asyncio.TimeoutError:
            return RejectedConnection(RejectReason.TIMEOUT)

    async def _token_stage(self, send, vendor: str, expected_ip: str, expected_port: int, first_message_id: int) -> Decision:
        result = await read_token_marker(send, vendor, expected_ip, expected_port, first_message_id)
        status = result.status
        if status is ProbeStatus.ABSENT:
            return RejectedConnection(RejectReason.LEGACY_DISABLED)
        if status is ProbeStatus.PRESENT_VALID_FORMAT:
            tokens_to_resolve = result.token if result.token is not None else result.tokens
            decision = await self.resolve_pending_enrollment(tokens_to_resolve, vendor)
            return decision
        if status is ProbeStatus.PRESENT_INVALID:
            return RejectedConnection(RejectReason.TOKEN_INVALID)
        if status is ProbeStatus.AMBIGUOUS:
            return RejectedConnection(RejectReason.AMBIGUOUS_ENDPOINT)
        return RejectedConnection(RejectReason.PROBE_FAILED)


def expected_cloud_target() -> tuple[str, int]:
    """ปลายทาง Cloud Manager ที่ CLI Generator ใส่ให้อุปกรณ์ (source of truth เดียวกับ cli_generator.py)"""
    from backend.cli_generator import CLOUD_SERVER_IP, CLOUD_SERVER_PORT
    return CLOUD_SERVER_IP, int(CLOUD_SERVER_PORT)


# message-id ของ token probe (แยกจาก 1000+ ของ identity probe และของคำสั่งผู้ใช้) เว้นช่วงละ 10 สำหรับสูงสุด 2 RPC ต่อ vendor
_message_ids = itertools.count(20000, 10)


class QuarantineBusy(Exception):
    def __init__(self):
        super().__init__("Call Home quarantine is busy")
