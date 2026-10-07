"""|===== ตัวช่วย parse XML อย่างปลอดภัย (กัน billion-laughs / XXE จาก reply ของอุปกรณ์) =====|

reply ที่อุปกรณ์ส่งกลับมาถูก parse ด้วย xml.etree.ElementTree หลายสิบจุดทั่วระบบ
ElementTree ของ Python "ไม่" ขยาย external entity (อ่านไฟล์ server ไม่ได้ - ทดสอบยืนยันแล้ว)
แต่ "ขยาย internal entity ได้" จึงโดน billion-laughs (entity ซ้อน entity แบบ 2^n) ทำ RAM
ระเบิดได้ถ้าอุปกรณ์ถูกยึดหรือมี MITM บนช่อง device<->server (ดู security_findings F2)

internal entity ประกาศได้เฉพาะใน DTD (`<!DOCTYPE ... [ <!ENTITY ...> ]>`) เท่านั้น และ reply
NETCONF ที่ถูกต้อง "ไม่มี DTD เลย" จึงปฏิเสธ payload ที่มี DOCTYPE/ENTITY ตั้งแต่ก่อน parse
= ปิดทั้ง billion-laughs และ XXE โดยไม่ต้องพึ่ง dependency ภายนอก (ระบบใช้ system Python ไม่มี venv)
และไม่กระทบ reply ปกติแม้แต่น้อย

หมายเหตุ: regex จับเฉพาะ `<!DOCTYPE`/`<!ENTITY` จึงไม่ชนกับ comment (`<!--`) หรือ CDATA (`<![CDATA[`)
โยนเป็น xml.etree.ElementTree.ParseError เพื่อให้ `except ET.ParseError` เดิมทั่วระบบจับได้เหมือน
XML พังทั่วไป (fail closed - reject ไม่ขยาย)
"""

import re
from xml.etree import ElementTree as _ET

# จับ "<!" ตามด้วย (ช่องว่างได้) DOCTYPE หรือ ENTITY ที่ขอบเขตคำ - ไม่ชน <!-- และ <![CDATA[
_FORBIDDEN_DECL = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def safe_fromstring(text):
    """parse XML string/bytes แบบปฏิเสธ DTD/entity ก่อนเสมอ - drop-in แทน ET.fromstring()"""
    if text is None:
        raise _ET.ParseError("empty XML payload")
    probe = text.decode("utf-8", "replace") if isinstance(text, (bytes, bytearray)) else text
    if _FORBIDDEN_DECL.search(probe):
        raise _ET.ParseError("XML DOCTYPE/ENTITY declarations are not allowed")
    return _ET.fromstring(text)
