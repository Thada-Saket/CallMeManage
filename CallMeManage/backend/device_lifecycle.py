""" |======= Device Lifecycle Lock (activation/register vs delete) =======| """
# Phase 8: กัน orphan in-memory session เมื่อ "การ activate/register session" แข่งกับ "การลบ Device/Site/User"
#   activation ชนะ : commit -> register session (ทั้งหมดใน lock) -> delete รอ -> ลบ DB -> close_session ปิด session ที่ register แล้ว
#   delete ชนะ     : ลบ DB + commit + close_session (ใน lock) -> activation ได้ lock แล้วอ่าน DB ไม่พบ Device -> reject ไม่ register
# ใช้ lock ต่อ dev_id ในโปรเซสเดียว (callhome listener กับ web API อยู่ process เดียวกัน ดู app.py) ไม่พึ่ง Redis จึงไม่มี
# กรณี Redis ล่มแล้วการลบเงียบ ๆ ใช้ไม่ได้ ; ห้ามใช้ session["lock"] เพราะก่อน register ยังไม่มี session entry
# lock ถูกลบทิ้งเมื่อไม่มีใครถือ/รอ (refcount) จึงไม่รั่วหน่วยความจำ ; ขอ lock หลายตัวเรียงตาม dev_id เพื่อไม่ deadlock
import asyncio
from contextlib import asynccontextmanager


class DeviceLifecycle:
    def __init__(self):
        self._entries: dict[str, list] = {}  # dev_id -> [asyncio.Lock, จำนวนผู้ถือ/รอ]

    def __len__(self) -> int:
        return len(self._entries)

    @asynccontextmanager
    async def hold(self, *device_ids: str):
        counted: list[str] = []  # ลงทะเบียนรอ/ถือแล้ว (ต้องคืนตัวนับ)
        held: list[str] = []     # acquire สำเร็จจริง (ต้อง release)
        try:
            for device_id in sorted(set(device_ids)):
                entry = self._entries.setdefault(device_id, [asyncio.Lock(), 0])
                entry[1] += 1
                counted.append(device_id)  # นับก่อนรอ: ถูก cancel ระหว่างรอก็ยังคืนตัวนับ ไม่ปล่อย entry ค้าง
                await entry[0].acquire()
                held.append(device_id)
            yield
        finally:
            for device_id in held:
                self._entries[device_id][0].release()
            for device_id in counted:
                entry = self._entries[device_id]
                entry[1] -= 1
                if entry[1] <= 0:
                    del self._entries[device_id]


device_lifecycle = DeviceLifecycle()
