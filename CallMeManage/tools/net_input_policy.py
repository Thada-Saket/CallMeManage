"""|===== นโยบายตรวจค่า network ที่ผู้ใช้กรอก (IP / prefix / administrative distance) =====|

แยกออกมาเป็นไฟล์กลางด้วยเหตุผลเดียวกับ tools/hostname_policy.py (bug 12) คือ
ค่าพวกนี้ถูกกรอกจากหน้าเว็บแล้วส่งตรงไปประกอบเป็น XML ที่ยิงเข้าอุปกรณ์จริง ถ้าปล่อยให้
แต่ละ vendor_translators เขียนกฎเอง กฎจะเพี้ยนออกจากกันแน่นอน - ซึ่งเกิดขึ้นจริงแล้วใน
bug 13: Huawei/Juniper validate ด้วย ipaddress ทั้งคู่ แต่ Cisco ไม่ validate อะไรเลย
สักฟิลด์ ทำให้ prefix/next_hop/distance แทรก XML element เข้าไปได้จริงทั้ง 3 ฟิลด์

--- ทำไมต้อง validate ไม่ใช่แค่ escape ---

escape() กัน injection ได้ก็จริง แต่ไม่ได้ทำให้ค่าที่ส่งไป "ถูกต้อง" ค่าอย่าง
"999.999.999.999" หรือ distance="abc" ผ่าน escape() ไปได้สบาย แล้วไปตายเอาที่อุปกรณ์
ด้วย rpc-error ที่อ่านไม่รู้เรื่อง แทนที่จะ fail เร็วตั้งแต่ฝั่งเราพร้อมข้อความที่บอกได้ว่า
ผิดตรงไหน - ทั้งสองอย่างจึงต้องทำคู่กัน validate เพื่อความถูกต้อง escape เพื่อความปลอดภัย

--- ⚠️ ช่วง distance ของแต่ละยี่ห้อไม่เท่ากัน ห้ามรวบเป็นค่าเดียว ---

validate_distance() จึงบังคับให้ผู้เรียก "ส่งช่วงของยี่ห้อตัวเองมา" เสมอ ไม่มี default
เพื่อกันการเผลอใช้ช่วงของยี่ห้ออื่น (ยืนยันจาก YANG schema ที่อยู่ใน device_capability/):

  * Cisco   <metric>                      uint8  range 1..255
            Cisco-IOS-XE-ip.yang:1876-1881
  * Huawei  <preference>                  uint32 range 1..255
            huawei-staticrt-staticrtbase.yang:302-305
  * Juniper <preference><metric-value>    uint32 ไม่จำกัดช่วง -> 0..4294967295
            junos-es-conf-routing-options.yang:9976-9984 (grouping rib_static_metric_type)
"""

import ipaddress
import re
from tools.ipv4_input import validate_address, validate_subnet

# ค่าสูงสุดของ uint32 - ใช้เป็นขอบบนของ Juniper ที่ YANG ไม่ได้จำกัดช่วงไว้เอง
UINT32_MAX = 4294967295


def validate_ipv4(value: str, field: str = "IP address") -> str:
    """ตรวจว่าเป็น IPv4 address จริง - คืน canonical form กลับมา

    คืนค่าที่ผ่าน str(IPv4Address(...)) แล้วเสมอ ไม่ใช่ค่าดิบที่ผู้ใช้กรอก เพื่อกัน
    รูปแบบแปลก ๆ ที่ ipaddress ยอมรับแต่หน้าตาไม่เหมือนกัน (เช่น "010.0.0.1") หลุดไปถึง
    อุปกรณ์ - ผลพลอยได้คือค่าที่คืนมาไม่มีทางมีอักขระ XML อยู่เลย
    """
    try:
        return validate_address(value, field)
    except ValueError:
        raise ValueError(f"{field} ต้องเป็น IPv4 address ที่ถูกต้อง (ได้รับ: {value!r})")


def validate_ipv4_network(prefix: str, mask: int, field: str = "prefix") -> ipaddress.IPv4Network:
    """ตรวจ prefix/mask แล้วคืน IPv4Network ที่ normalize แล้ว

    ใช้ strict=False ตั้งใจ เพื่อให้ผู้ใช้กรอก host address มาได้ (เช่น 10.0.0.5/24)
    แล้วระบบ normalize ให้เป็น network address (10.0.0.0/24) เอง - พฤติกรรมเดียวกับที่
    Huawei/Juniper ทำอยู่แล้ว ถ้าไม่ normalize อุปกรณ์จะปฏิเสธ route ที่มี host bit ติดมา
    """
    try:
        return ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
    except ValueError:
        raise ValueError(
            f"{field} ต้องเป็น IPv4 network ที่ถูกต้อง (ได้รับ: {prefix!r}/{mask!r})"
        )


def validate_distance(value, minimum: int, maximum: int, field: str = "distance") -> int:
    """ตรวจ administrative distance / route preference แล้วคืนเป็น int

    ไม่มีค่า default ให้ minimum/maximum โดยเจตนา - ผู้เรียกต้องระบุช่วงของยี่ห้อตัวเอง
    เสมอ เพราะช่วงของ 3 ยี่ห้อไม่เท่ากันจริง (ดูคอมเมนต์หัวไฟล์) การใส่ default ไว้จะ
    เปิดช่องให้เผลอใช้ช่วงของยี่ห้ออื่นโดยไม่รู้ตัว
    """
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} ต้องเป็นตัวเลข (ได้รับ: {value!r})")
    if not minimum <= number <= maximum:
        raise ValueError(f"{field} ต้องอยู่ในช่วง {minimum}-{maximum} (ได้รับ: {number})")
    return number


def validate_netmask(value: str, field: str = "netmask") -> str:
    """ตรวจ subnet mask แบบ dotted notation (255.255.255.0) - คืน canonical form

    ต้องแยกจาก validate_ipv4() เพราะ "เป็น IPv4 ที่ถูกต้อง" ยังไม่พอ - netmask ต้องมี
    bit 1 ต่อเนื่องกันจากซ้ายเท่านั้น (255.255.0.255 เป็น IPv4 ที่ถูกต้องแต่เป็น mask
    ไม่ได้) ตรวจด้วยการให้ ipaddress ลองแปลงเป็น prefix length ถ้าไม่ต่อเนื่องจะโยน error

    เจอบั๊กจริงตอน bug 14: ฟิลด์นี้รับ "24" (prefix length) ได้ด้วยเพราะไม่มีการตรวจ
    อะไรเลย ซึ่งเป็นความสับสนที่เกิดง่ายมากเพราะที่อื่นในระบบใช้ prefix length เป็น int
    (mask: int) แต่ leaf netmask ของ Cisco-IOS-XE-nat.yang:1241 เป็น inet:ipv4-address
    คือต้องเป็น dotted เท่านั้น
    """
    text = str(value).strip()
    try:
        validate_subnet(text, field)
    except ValueError:
        raise ValueError(
            f"{field} ต้องเป็น subnet mask แบบเต็ม เช่น 255.255.255.0 (ได้รับ: {value!r})"
        )
    # กันเคส "24" ที่ IPv4Network ยอมรับในฐานะ prefix length - ฟิลด์นี้ต้องเป็น dotted เท่านั้น
    if text.count(".") != 3:
        raise ValueError(
            f"{field} ต้องเขียนแบบเต็ม 4 ชุด เช่น 255.255.255.0 ไม่ใช่ prefix length (ได้รับ: {value!r})"
        )
    return str(ipaddress.IPv4Address(text))


def validate_address_range(start: str, end: str, field: str = "address range") -> tuple[str, str]:
    """ตรวจว่า start/end เป็น IPv4 จริงและ start ต้องไม่มากกว่า end - คืนคู่ที่ canonical แล้ว

    เดิมไม่มีใครเช็คลำดับเลย สร้าง pool ที่ช่วงกลับหัว (start=10.0.0.9 end=10.0.0.1) ได้
    แล้วไปตายเอาที่อุปกรณ์
    """
    start_ip = validate_ipv4(start, f"{field} start")
    end_ip = validate_ipv4(end, f"{field} end")
    if ipaddress.IPv4Address(start_ip) > ipaddress.IPv4Address(end_ip):
        raise ValueError(
            f"{field}: start ({start_ip}) ต้องไม่มากกว่า end ({end_ip})"
        )
    return start_ip, end_ip


# ความยาวสูงสุดของชื่อ config object (NAT pool / security profile ฯลฯ) - YANG ของ Cisco
# กำหนด leaf id ของ pool ไว้แค่ "type string" ไม่จำกัดรูปแบบเลย จึงต้องตั้งนโยบายเอง
# 63 ตัวอักษรกว้างพอสำหรับชื่อที่สื่อความหมายจริง แต่ยังกันชื่อยาวผิดปกติ (เจอจริงตอน
# bug 14 ว่าชื่อยาว 500 ตัวอักษรผ่านได้)
#
# (bug 64) แก้คำอธิบายที่ผิด: เดิมเขียนว่า "ชื่อพวกนี้ยังถูกเก็บเป็น cfg_name ใน
# Device_Config_Object ซึ่งเป็น indexed field" ซึ่งไม่จริงสำหรับ NAT pool - ตรวจ
# TRACKED_FEATURES ใน device_router.py แล้วพบว่ามีแค่ set_static_nat กับ
# set_port_forward เท่านั้นที่ชื่อถูกเก็บลง DB ของเรา ที่เหลือตั้งและอ่านจากอุปกรณ์ล้วน
# เหตุผลที่ยกมารองรับความยาว 63 จึงไปตรงกับสองตัวนั้นแทน (ซึ่งตอนนั้นกลับไม่ validate
# อะไรเลย - แก้ไปพร้อมกันแล้ว) ส่วนเหตุผลที่ยังจำกัดความยาวตรงนี้คือกัน payload ผิดปกติ
# และให้ชื่อที่ผู้ใช้ตั้งเองอ่านรู้เรื่องบนอุปกรณ์จริง
CONFIG_NAME_MAX_LENGTH = 63

# อนุญาต A-Z a-z 0-9 - _ . โดยต้องขึ้นต้นด้วยตัวอักษรหรือตัวเลข - ห้ามเว้นวรรคและ
# ห้ามขึ้นบรรทัดใหม่ (เหตุผลเดียวกับ hostname ใน bug 12: ค่าพวกนี้ไปโผล่ทั้งใน XML และ
# ในคำสั่ง CLI ที่ผู้ใช้อ่าน) - Cisco CLI เองก็ไม่รับชื่อ object ที่มีช่องว่างอยู่แล้ว
_CONFIG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def validate_config_name(value: str, field: str = "name") -> str:
    """ตรวจชื่อ config object (NAT pool ฯลฯ) ที่ "ผู้ใช้ตั้งเอง" - ใช้กับ create_* เท่านั้น

    ถ้าชื่อนั้น "อ่านกลับมาจากอุปกรณ์" (ตอนลบ/อ้างอิง) ให้ใช้ validate_object_ref()
    แทน ดูเหตุผลที่ comment ของฟังก์ชันนั้น
    """
    text = (value or "").strip() if isinstance(value, str) else ""
    if len(text) > CONFIG_NAME_MAX_LENGTH or not _CONFIG_NAME_RE.fullmatch(text):
        raise ValueError(
            f"{field} ต้องยาว 1-{CONFIG_NAME_MAX_LENGTH} ตัวอักษร ใช้ได้เฉพาะ A-Z a-z 0-9 "
            f"ขีดกลาง (-) ขีดล่าง (_) จุด (.) และต้องขึ้นต้นด้วยตัวอักษรหรือตัวเลข "
            f"(ได้รับ: {value!r})"
        )
    return text


# --- นโยบายชื่อที่ "อ้างอิงของที่มีอยู่แล้วบนอุปกรณ์" -------------------------
#
# (bug 63) นโยบายชื่อมี 2 ด่านที่คนละหน้าที่กัน และเดิมเราใช้ด่านเดียวกับทั้งสองทาง
#
#   ตอนสร้าง (create_*)    : ค่ามาจากผู้ใช้พิมพ์ -> เราเป็นคนกำหนดกติกาได้เต็มที่
#                            บังคับให้ชื่อสวยและปลอดภัยได้ ใช้ validate_config_name()
#   ตอนอ้างอิง (remove_*)  : ค่ามาจาก "อุปกรณ์" (อ่านผ่าน get_* แล้วผู้ใช้กดจากตาราง)
#                            ของมันมีอยู่จริงบนอุปกรณ์แล้ว เราไม่มีสิทธิ์บอกว่าชื่อผิด
#
# เจอจริง 4 ก.ย. 2026 หลังไล่ NAT ของ Cisco: กฎ _CONFIG_NAME_RE เข้มกว่าที่อุปกรณ์
# ยอมรับจริง (Cisco รับ "VPN@HQ" / "_INTERNAL" / ชื่อยาวเกิน 63 ได้สบาย) ผลคือ object
# ที่มีอยู่จริงบนอุปกรณ์ - ตั้งจาก CLI, ติดมาก่อน onboard, หรือชื่อ VPN ที่มีอักขระ
# พิเศษ - จะโชว์บนหน้าเว็บแต่กดลบ/แก้ไม่ได้เลย ขัดหลักที่ยึดไว้ว่าหน้าจอต้องตรงกับ
# ความจริงบนอุปกรณ์ (5 จุดใน 2 ฟีเจอร์: NAT pool 3 จุด, security profile 2 จุด)
#
# ด่านนี้จึงตรวจแค่ "ความปลอดภัย" ไม่ตรวจ "ความสวยงาม":
#   * ห้ามอักขระควบคุม/ขึ้นบรรทัดใหม่ - เหตุผลเดียวกับ bug 12 คือค่าพวกนี้ไปโผล่ใน
#     คำสั่ง CLI ที่ผู้ใช้ copy ไปวางเองด้วย ที่ escape() ช่วยไม่ได้
#   * ห้าม < > & " ' - กัน XML injection ไว้เป็นด่านแรก (escape() ยังคงไว้เป็นด่านสอง)
#   * จำกัดความยาวไว้กว้าง ๆ กัน payload ผิดปกติ ไม่ใช่เพื่อบังคับสไตล์การตั้งชื่อ
OBJECT_REF_MAX_LENGTH = 255

_OBJECT_REF_FORBIDDEN = set('<>&"\'')


def validate_object_ref(value: str, field: str = "name") -> str:
    """ตรวจชื่อ object ที่ "อ่านกลับมาจากอุปกรณ์" - ใช้กับ remove_*/อ้างอิง"""
    if not isinstance(value, str):
        raise ValueError(f"{field} ต้องเป็นข้อความ (ได้รับ: {value!r})")
    text = value.strip()
    if not text or len(text) > OBJECT_REF_MAX_LENGTH:
        raise ValueError(
            f"{field} ต้องยาว 1-{OBJECT_REF_MAX_LENGTH} ตัวอักษร (ได้รับความยาว {len(text)})"
        )
    bad = sorted({ch for ch in text if ch in _OBJECT_REF_FORBIDDEN or ord(ch) < 32 or ord(ch) == 127})
    if bad:
        raise ValueError(
            f"{field} มีอักขระที่ใช้ไม่ได้: {bad!r} "
            f"(ห้ามอักขระควบคุม ขึ้นบรรทัดใหม่ และ < > & \" ') (ได้รับ: {value!r})"
        )
    return text


# --- นโยบายชื่อโดเมน ---------------------------------------------------------
#
# เจอตอน 3 ก.ย. 2026 หลังแก้ bug 12 ไปแล้ว: ตอนนั้นจำกัด charset ให้ hostname แต่
# "domain_name" ที่อยู่ในฟอร์มเดียวกันและไปลงไฟล์ config เดียวกันกลับตกไป - ผลคือ
# backend/cli_generator.py บรรทัด "ip domain name {domain_name}" ยังแทรกคำสั่ง CLI
# ได้อยู่ (ยืนยันด้วยการรันจริง: ใส่ \n แล้วได้ "username hacker privilege 15 ..."
# โผล่ในไฟล์ config ที่ผู้ใช้จะ copy ไปวางบน console) เป็นช่องเดียวกับ bug 12 เป๊ะ
#
# ทำไมต้องมีนโยบาย ไม่ใช่ escape() พอ: เหตุผลเดียวกับ hostname - เส้นทาง CLI
# generator ให้ผลลัพธ์เป็นข้อความ CLI ธรรมดาที่ผู้ใช้ copy ไปวางเอง ไม่มี escape
# ให้ใช้ ตัวอักษรที่อันตรายที่สุดคือขึ้นบรรทัดใหม่
#
# ที่มาของกฎ (RFC 1035 §2.3.1 / RFC 1123 §2.1):
#   * ทั้งชื่อยาวรวมไม่เกิน 253 ตัวอักษร
#   * แต่ละ label (ส่วนที่คั่นด้วยจุด) ยาว 1-63 ตัวอักษร
#   * label ใช้ได้เฉพาะ A-Z a-z 0-9 และขีดกลาง ห้ามขึ้นต้น/ลงท้ายด้วยขีดกลาง
#   * ยอมรับชื่อชั้นเดียว ("lab") เพราะ `ip domain name lab` ใช้ได้จริงบน Cisco
#   * ไม่ยอมรับ trailing dot ("lab.local.") เพราะอุปกรณ์รับรูปแบบนั้นไม่ได้
#   * ไม่ยอมรับ IDN/ภาษาไทย - ต้องแปลงเป็น punycode (xn--...) มาก่อน ซึ่งผ่านกฎนี้อยู่แล้ว
DOMAIN_NAME_MAX_LENGTH = 253
DOMAIN_LABEL_MAX_LENGTH = 63
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")

DOMAIN_RULE_TEXT = (
    f"ชื่อโดเมนต้องยาวไม่เกิน {DOMAIN_NAME_MAX_LENGTH} ตัวอักษร "
    f"แต่ละส่วนที่คั่นด้วยจุดยาว 1-{DOMAIN_LABEL_MAX_LENGTH} ตัวอักษร "
    "ใช้ได้เฉพาะ A-Z a-z 0-9 และขีดกลาง (-) ห้ามขึ้นต้น/ลงท้ายด้วยขีดกลาง "
    "ห้ามเว้นวรรค ห้ามขึ้นบรรทัดใหม่ ห้ามลงท้ายด้วยจุด และห้ามภาษาอื่น"
)


def validate_domain_name(value: str, field: str = "domain name") -> str:
    """ตรวจชื่อโดเมน (เช่น lab.local) - คืนค่าเดิมถ้าผ่าน, โยน ValueError ถ้าไม่ผ่าน"""
    text = value if isinstance(value, str) else ""
    if not text or len(text) > DOMAIN_NAME_MAX_LENGTH:
        raise ValueError(f"{field}: {DOMAIN_RULE_TEXT} (ได้รับ: {value!r})")
    labels = text.split(".")
    for label in labels:
        if not 1 <= len(label) <= DOMAIN_LABEL_MAX_LENGTH or not _DOMAIN_LABEL_RE.fullmatch(label):
            raise ValueError(f"{field}: {DOMAIN_RULE_TEXT} (ได้รับ: {value!r})")
    return text

# --- นโยบาย pre-shared key -----------------------------------------------
#
# (bug 69) เดิม psk มีแค่ escape() ไม่มีการตรวจความยาวเลย - ผู้ใช้ทดสอบด้วย key
# ยาว ๆ แล้วอุปกรณ์ตอบ "inconsistent value: Device refused one or more commands"
# ซึ่งอ่านไม่ออกว่าผิดตรงไหน ทั้งที่เรารู้ล่วงหน้าได้
#
# **ยืนยันเพดานจริงจากอุปกรณ์แล้ว** (ผู้ใช้พิมพ์ผ่าน console ของ 8000-BR-1):
#   8000-BR-1(config-ikev2-keyring-peer)#$sssss...word@123
#   Pre-shared key length exceeds 127 characters.   Key not added.
# -> Cisco รับได้สูงสุด 127 ตัวอักษร (ไม่ใช่ 128)
#
# Juniper ยังไม่เคยวัด ใช้เพดานเดียวกันไปก่อนเพราะเป็นค่าที่ใช้ได้จริงแน่ ๆ ทั้งคู่
# (ถ้าวันหนึ่งเจอว่า Junos รับได้มากกว่านี้ค่อยแยกค่าคงที่ต่อยี่ห้อ)
#
# ไม่บังคับ charset เพราะ PSK ที่ดีควรสุ่มได้อิสระ - ตรวจแค่สิ่งที่ทำให้ payload พัง
# หรือทำให้ผู้ใช้เจอปัญหาที่หาสาเหตุไม่เจอ:
#   * ห้ามอักขระควบคุม/ขึ้นบรรทัดใหม่ - พังทั้ง XML และคำสั่ง CLI
#   * ห้ามช่องว่างหัวท้าย - ผู้ใช้ copy มาแล้วติดมาโดยไม่รู้ตัว แล้วงงว่าทำไม tunnel ไม่ขึ้น
#     (ไม่ strip ให้เอง เพราะ PSK ที่มีช่องว่างจริง ๆ ก็เป็นไปได้ ต้องให้ผู้ใช้ตัดสินเอง)
PSK_MAX_LENGTH = 127


def validate_psk(value: str, field: str = "pre-shared key") -> str:
    """ตรวจ pre-shared key - ไม่บังคับ charset ตรวจแค่ที่ทำให้พังหรือหาสาเหตุไม่เจอ"""
    if not isinstance(value, str):
        raise ValueError(f"{field} ต้องเป็นข้อความ (ได้รับ: {value!r})")
    if not value:
        raise ValueError(f"{field} ต้องไม่เป็นค่าว่าง")
    if len(value) > PSK_MAX_LENGTH:
        raise ValueError(
            f"{field} ยาวเกินไป - อุปกรณ์รับได้สูงสุด {PSK_MAX_LENGTH} ตัวอักษร "
            f"(ได้รับ {len(value)} ตัวอักษร)"
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{field} ห้ามมีอักขระควบคุมหรือการขึ้นบรรทัดใหม่")
    if value != value.strip():
        raise ValueError(f"{field} มีช่องว่างอยู่หัวหรือท้าย - ตรวจดูอีกทีว่าตั้งใจหรือติดมาจากการคัดลอก")
    return value


# --- ตรวจว่า IP ใช้เป็น host address ใน prefix นั้นได้จริง --------------------
#
# (bug 70) เดิมตรวจแค่ว่า "เป็น IPv4 ที่ถูกรูปแบบไหม" ซึ่งไม่พอสำหรับ IP ที่ต้องผูก
# กับ subnet - ผู้ใช้ตั้ง tunnel IP เป็น 169.254.1.255/30 ซึ่งเป็น broadcast ของ
# 169.254.1.252/30 อุปกรณ์ปฏิเสธด้วย "inconsistent value" แล้ว tunnel 0 หายไปจาก
# ระบบทั้งตัว (เพราะ tunnel ยังใช้แพทเทิร์นลบก่อนสร้างอยู่ - งาน C3)
#
# /31 กับ /32 ต้องยกเว้น: /31 เป็น point-to-point ตาม RFC 3021 ใช้ได้ทั้งสอง address
# ส่วน /32 เป็น host route เดี่ยว ๆ ซึ่ง ipaddress มองว่า network==broadcast==ตัวมันเอง
def validate_host_in_network(ip: str, mask: str, field: str = "IP address") -> str:
    """ตรวจว่า ip ใช้เป็น host address ใน subnet ที่ระบุได้จริง - คืน canonical form"""
    address = validate_ipv4(ip, field)
    try:
        network = ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
    except ValueError:
        raise ValueError(f"{field}: subnet mask/prefix ไม่ถูกต้อง (ได้รับ: {mask!r})")
    if network.prefixlen < 31 and ipaddress.IPv4Address(address) in (
        network.network_address,
        network.broadcast_address,
    ):
        which = "network address" if ipaddress.IPv4Address(address) == network.network_address else "broadcast address"
        raise ValueError(
            f"{field} ใช้ไม่ได้ - {address} เป็น {which} ของ {network} "
            f"(ช่วงที่ใช้ได้: {network.network_address + 1} ถึง {network.broadcast_address - 1})"
        )
    return address


def validate_ospf_area(value, field: str = "area") -> int:
    """ตรวจ OSPF area id แล้วคืนเป็น int

    area id เป็นค่า 32 บิตตามมาตรฐาน OSPF (RFC 2328) ช่วงจึงเป็น 0-4294967295
    เท่ากันทุกยี่ห้อ ไม่ใช่ข้อจำกัดเฉพาะอุปกรณ์ - ระบบนี้รับเป็น "เลขล้วน" อย่าง
    เดียวทุกยี่ห้อตามที่ผู้ใช้กำหนด ไม่รับรูปแบบ dotted quad

    Cisco เขียน <area> เป็นเลขอยู่แล้ว ส่วน Junos รับเลขแล้วแปลงเป็น dotted quad
    ให้เอง (ยืนยันกับอุปกรณ์จริงแล้ว: กรอก 1 ไป อุปกรณ์เก็บเป็น 0.0.0.1) การส่ง
    เลขล้วนจึงใช้ได้กับทั้งสองยี่ห้อโดยไม่ต้องแปลงเองฝั่งเรา

    ปฏิเสธ bool ทิ้งไปตรง ๆ เพราะ int(True) เป็น 1 ซึ่งจะกลายเป็น area 1 เงียบ ๆ
    """
    if isinstance(value, bool):
        raise ValueError(f"{field} ต้องเป็นตัวเลข (ได้รับ: {value!r})")
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{field} ต้องเป็นจำนวนเต็ม (ได้รับ: {value!r})")
    if isinstance(value, str) and not value.strip().isdigit():
        raise ValueError(f"{field} ต้องเป็นตัวเลข (ได้รับ: {value!r})")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} ต้องเป็นตัวเลข (ได้รับ: {value!r})")
    if not 0 <= number <= UINT32_MAX:
        raise ValueError(f"{field} ต้องอยู่ในช่วง 0-{UINT32_MAX} (ได้รับ: {number})")
    return number


# ช่วงของ process-id มาจาก schema จริง ไม่ได้เดา: Cisco-IOS-XE-ospf.yang:3841-3850
# (list process-id -> leaf id เป็น uint16 range "1..65535") - เป็นของ Cisco
# เท่านั้น Junos ไม่มี concept นี้เลย (instance เดียวต่อ routing-instance) จึงไม่มี
# ผู้เรียกฝั่ง Juniper
def validate_ospf_process_id(value, field: str = "process_id") -> int:
    """ตรวจ OSPF process id ของ Cisco แล้วคืนเป็น int (1-65535)"""
    if isinstance(value, bool):
        raise ValueError(f"{field} ต้องเป็นตัวเลข (ได้รับ: {value!r})")
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{field} ต้องเป็นจำนวนเต็ม (ได้รับ: {value!r})")
    if isinstance(value, str) and not value.strip().isdigit():
        raise ValueError(f"{field} ต้องเป็นตัวเลข (ได้รับ: {value!r})")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} ต้องเป็นตัวเลข (ได้รับ: {value!r})")
    if not 1 <= number <= 65535:
        raise ValueError(f"{field} ต้องอยู่ในช่วง 1-65535 (ได้รับ: {number})")
    return number
