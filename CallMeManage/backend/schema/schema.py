""" |======= Schema for device fetch and input data validation =======| """

import re
from typing import Any, Literal, Optional
from datetime import datetime
from uuid import UUID

from pydantic import ConfigDict, SecretStr, field_validator, model_validator
from sqlmodel import SQLModel

from tools.hostname_policy import validate_hostname
from backend.interface_policy import validate_bootstrap_port, validate_cli_interfaces
from tools.net_input_policy import validate_domain_name
from tools.local_admin_policy import validate_local_admin_password, validate_local_admin_username
from backend.core.load_environment import load_environment


# ---------- Device_Information ----------

# schema ข้อมูลพื้นฐานของอุปกรณ์ class อื่นๆจะได้ข้อมูลพวกนี้หากสืบทอดไป
class DeviceBase(SQLModel):
    dev_vendor: str
    dev_model: str
    dev_firmware: str
    dev_name: str
    dev_ip: str # เตรียมลบ เพราะแก้ใน erd แล้ว
    dev_fingerprint: Optional[str] = None

# schema ดึงข้อมูลชื่ออุปกรณ์และสถานะ (ยังไม่ถูกเรียกใช้งาน)
class DeviceUpdate(SQLModel):
    dev_name: Optional[str] = None
    dev_status: Optional[str] = None

# schema อ่านข้อมูลความเป็นเจ้าของและสถานะของอุปกรณ์ โดยสืบทอดข้อมูลจาก class DeviceBase มาด้วย
class DeviceRead(DeviceBase):
    dev_id: str
    site_id: str
    dev_status: str
    dev_registered: bool
    dev_added_date: datetime
    dev_last_seen: Optional[datetime] = None
    dev_viewed: bool = False

# schema แสดงข้อมูลอุปกรณ์แบบย่อ
class DeviceSummary(SQLModel):
    dev_id: str
    dev_name: str
    dev_vendor: str
    dev_model: str
    dev_status: str
    dev_last_seen: Optional[datetime] = None
    dev_viewed: bool = False
    site_id: str
    enrollment_expires_at: Optional[datetime] = None
    enrollment_expired: bool = False


# schema สำหรับ keyset pagination ของรายการอุปกรณ์ - ไม่มี total/page number
# เพราะฝั่ง frontend ใช้ prefetch แบบ cursor แทนเลขหน้า
class DeviceListPage(SQLModel):
    items: list[DeviceSummary]
    next_cursor: Optional[str] = None  # dev_id ตัวสุดท้ายของชุดนี้ ใช้เป็น after_dev_id รอบถัดไป
    has_next: bool = False
    site_role: Literal["owner", "admin", "member"]

# ---------- Device_Capability ----------

# schema สำหรับดึงข้อมูลความสามารถของอุปกรณ์
class DeviceCapabilityRead(SQLModel):
    cap_id: str
    cap_vendor: str  # เตรียมลบ เพราะแก้ใน erd แล้ว
    cap_detail: str
    cap_saved_date: datetime
    cap_dev_id: str


# ---------- Device_Access ----------

# schema สำหรับดึงข้อมูลว่าใครเป็นคนใช้งานอุปกรณ์
class DeviceAccessRead(SQLModel):
    acc_id: str
    acc_session_id: str
    acc_date: datetime
    acc_lastseen: datetime
    acc_dev_id: str
    acc_usr_id: Optional[str] = None
    usr_name: Optional[str] = None


class DeviceAccessSessionStart(SQLModel):
    # Client-generated UUID makes POST idempotent if a browser retries the same
    # request, while a later page visit creates a different access-log row.
    session_id: UUID


class DeviceAccessListPage(SQLModel):
    items: list[DeviceAccessRead]
    next_cursor: Optional[str] = None
    has_next: bool = False


# ---------- Temporary Running Configuration Snapshot ----------

class RunningConfigSnapshotCreated(SQLModel):
    snapshot_id: str
    dev_id: str
    expires_at: datetime


class RunningConfigSection(SQLModel):
    id: str
    key: str
    label: str
    data: Any


class RunningConfigSnapshotRead(RunningConfigSnapshotCreated):
    dev_name: str
    vendor: str
    source: Literal["running"]
    created_at: datetime
    redacted_count: int
    sections: list[RunningConfigSection]


# ---------- Device Command (หน้าเว็บที่ 3 config GUI) ----------

# schema สำหรับ validate ข้อมูล command ที่กรอกค่ามา
class DeviceCommandRequest(SQLModel):
    parameters: dict[str, Any] = {}

# (C4) ชุดคำสั่งที่ต้อง commit ครั้งเดียว - ใช้กับยี่ห้อที่มี candidate datastore
# เท่านั้น ลำดับใน list คือลำดับที่เขียนเข้า candidate จริง
class DeviceCommandStep(SQLModel):
    command: str
    parameters: dict[str, Any] = {}


class DeviceTransactionRequest(SQLModel):
    commands: list[DeviceCommandStep] = []


# schema สำหรับ validate กำหนดหน้าตาผลลัพธ์ที่นำไปทำงานต่อ
class DeviceCommandResult(SQLModel):
    command: str
    normalized: bool  # False = ยังไม่มี response normalizer ของ query นี้ -> result เป็น XML ดิบ
    result: Any
    # (2026-09) authoritative metadata จาก vendor_translators/cisco_zbf.py แนบคู่กับ
    # ผลของ get_firewall_information ของ Cisco เท่านั้น (None ทุกคำสั่ง/vendor อื่น) -
    # ciscoZbfParser.js join ด้วยชื่อ Zone Pair แทนการคำนวณ revision/editable/
    # sharedObjects เองฝั่ง frontend เพื่อไม่ให้ frontend/backend ตัดสินไม่ตรงกัน
    zbf_metadata: list[dict] | None = None


class DeviceFactoryResetRequest(SQLModel):
    # Required only for Juniper. SecretStr keeps the value out of repr/logging
    # when request validation or an unexpected exception is reported.
    root_password: Optional[SecretStr] = None


class DeviceFactoryResetResponse(SQLModel):
    status: Literal["accepted", "completed"]
    vendor: Literal["cisco", "juniper", "huawei"]
    message: str

# schema สำหรับ validate คำสั่ง ping
class PingTestRequest(SQLModel):
    destination: str
    source_interface: str | None = None

    # F1: destination/source_interface ถูกยัดลง XML ของคำสั่ง ping (Cisco edit-config) โดยตรง จึงต้องจำกัด
    # charset ตั้งแต่ boundary นี้ (ด่านแรก) ร่วมกับ escape() ในตัวแปลภาษา (ด่านสอง) - อักขระ < > / ช่องว่าง
    # ขึ้นบรรทัดใหม่ ถูกตัดทิ้งทั้งหมด จึง inject โครง XML/คำสั่งเพิ่มไม่ได้ ; รับเฉพาะ IPv4/hostname (รวม IPv6)
    @field_validator("destination")
    @classmethod
    def _validate_destination(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9.:_-]{1,253}", cleaned):
            raise ValueError("Destination must be a valid IPv4 address or hostname")
        return cleaned

    # source_interface เป็น optional - อนุญาตเฉพาะอักขระของชื่อ interface (เช่น GigabitEthernet0/0/0, Loopback0)
    @field_validator("source_interface")
    @classmethod
    def _validate_source_interface(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if not re.fullmatch(r"[A-Za-z0-9./_-]{1,63}", cleaned):
            raise ValueError("Source interface contains invalid characters")
        return cleaned


# ---------- Device_History ----------

# schema สำหรับกรอง output การดึงประวัติอุปกรณ์ว่าต้องส่งออกตาม field เหล่านี้
class DeviceHistoryRead(SQLModel):
    his_id: str
    his_action: str
    his_action_detail: str
    his_action_time: datetime
    his_dev_id: str
    his_usr_id: Optional[str] = None
    # Resolved when history is read.  Keep the ID as the durable audit key while
    # giving the UI a human-readable name without storing duplicate user data.
    his_usr_name: Optional[str] = None

class DeviceHistoryListPage(SQLModel):
    items: list[DeviceHistoryRead]
    next_cursor: Optional[str] = None
    has_next: bool = False

# ---------- Device_Config_Object / Device_Config_Reference ----------
# ระบบจดจำ "สิ่งที่สั่งสร้างไปแล้ว" ต่ออุปกรณ์ (Static NAT, Port Forward)

# schema สำหรับ validate input สำหรับการสร้าง config ที่ตั้งชื่อไม่ได้
class DeviceConfigObjectCreate(SQLModel):
    cfg_feature: str
    cfg_name: str
    cfg_params: dict[str, Any]  # แปลงเป็น JSON string ตอนเก็บจริง (ดู crud_dev_config_object.py)
    references: list[str] = []  # cfg_id ของ object อื่นที่ตัว สำหรับทำ link table (field ตาย)

# schema สำหรับ validate output ดึงค่า config ที่ตั้งเอาไว้
class DeviceConfigObjectRead(SQLModel):
    cfg_id: str
    cfg_feature: str
    cfg_name: str
    cfg_params: dict[str, Any]
    cfg_created_date: datetime
    cfg_dev_id: str
    cfg_created_by_id: Optional[str] = None


# ---------- CLI Generator (backend/cli_generator.py) ----------
# สร้าง CLI ให้ไปวางบนอุปกรณ์เปล่าๆ (ยังไม่ได้ลงทะเบียน) ให้มัน call-home มาหา
# server นี้เอง - Generate ครั้งแรกสร้าง pending dev_id; Regenerate ส่ง ID เดิมกลับมาเพื่อแก้ CLI - ไม่มี
# username/password แล้ว (auth เปลี่ยนเป็น SSH public key คงที่ทั้งหมด ดู
# ADMIN_USERNAME และ tools/keys/rsa_public_key.pem ใน cli_generator.py)

# schema สำหรับ validate input การสร้าง cli ให้อุปกรณ์เอาไปใช้
class CliGenerateRequest(SQLModel):
    # Phase 10: ไม่ใส่ input ทั้งก้อนใน str(ValidationError) (มี local_admin_password/console_password ดิบอยู่ใน input) กันรั่วลง log/traceback
    model_config = ConfigDict(hide_input_in_errors=True)

    vendor: str
    # Site ที่ผู้ใช้กด Generate จากหน้านั้น (Phase 4 - backward-compatible): ถ้าส่งมา router ตรวจสิทธิ์ (RBAC) จริงก่อน
    # ไม่เชื่อค่าจาก frontend เฉย ๆ และ **ไม่ส่งต่อเข้า CLI data** (ไม่ฝังลง CLI/token)
    # TODO Phase 5/6: ให้ site_id เป็น required สำหรับ flow Enrollment Token (ตอนนี้ optional เพื่อให้ frontend
    # ปัจจุบันที่ยังไม่ส่ง site_id ทำงานต่อได้) - ไม่มี field ให้ client ส่ง Enrollment Token เอง
    site_id: Optional[str] = None
    # ส่งเฉพาะตอน Regenerate: backend ตรวจว่าเป็น token-pending Device ของ Site/vendor เดียวกัน
    # แล้วหมุน one-time token บน Enrollment แถวเดิม แทนการสร้าง Device เพิ่ม
    pending_device_id: Optional[str] = None
    wan_interface: Optional[str] = None
    hostname: Optional[str] = None
    cloud_server_ip: str
    cloud_server_port: int
    domain_name: Optional[str] = None  # cisco เท่านั้นที่บังคับ (ดู generate_cisco)
    wan_mode: str = "dhcp"  # "dhcp" | "static"
    wan_ip: Optional[str] = None
    wan_mask: Optional[str] = None  # cisco/huawei ใช้ subnet mask จุด (255.255.255.0)
    wan_prefix: Optional[int] = None  # juniper ใช้ prefix length (24)
    wan_gateway: Optional[str] = None
    wan_dns: Optional[str] = None  # เฉพาะ wan_mode="static" - ตั้ง global DNS ให้ resolve ได้ก่อน callhome
    root_passwd: Optional[str] = None  # juniper เท่านั้นที่บังคับ (ดู generate_juniper) - ไม่บังคับถ้า device_mode="existing"
    console_username: Optional[str] = None
    console_password: Optional[str] = None

    # Phase 10: Local Administrator บนอุปกรณ์ (ไม่ใช่ Site Member) - เฉพาะ Existing Device และเปิด toggle เท่านั้น
    # แยกจาก console_username/console_password ของ New Device โดยตั้งใจ (ไม่ reuse); Confirm Password ไม่ส่งมา backend
    # password เป็น SecretStr: repr/model_dump_json/error ไม่แสดงค่า - router เปิดค่าเฉพาะตอนส่งเข้า generator
    add_local_administrator: bool = False
    local_admin_username: Optional[str] = None
    local_admin_password: Optional[SecretStr] = None

    device_mode: str = "new"  # "new" (greenfield, ตั้ง WAN/bootstrap เต็ม) | "existing" (brownfield, แค่เปิด NETCONF/SSH+Callhome)
    device_role: str = "router"  # "router" (WAN Router/Firewall, เดิม) | "switch" (L2/L3 Switch - in-band mgmt ผ่าน SVI, cisco/juniper เท่านั้น - ดู generate_cisco/generate_juniper)

    # ขา bootstrap ของ switch - ใช้ชุดเดียวกันทุกยี่ห้อแล้ว (เดิมมีแต่ Huawei ชื่อ
    # huawei_*): default access ใช้ VLAN 1 โดยไม่แตะ physical port; access
    # specific/trunk ต้องระบุ VLAN และ port ส่วน layer3 วาง IP บน port โดยตรง
    # ดู resolve_bootstrap_plan ใน backend/cli_generator.py
    bootstrap_interface_type: Optional[str] = None  # "vlan" | "layer3"
    bootstrap_vlan_mode: Optional[str] = None  # "access" | "trunk"
    bootstrap_vlan_selection: Optional[str] = None  # access เท่านั้น: "default" | "specific"
    bootstrap_vlan_id: Optional[int] = None
    bootstrap_interface: Optional[str] = None

    @model_validator(mode="after")
    def _validate_local_administrator(self):
        # ข้อความ error เป็นข้อความคงที่ทั้งหมด ไม่มี username/password ที่ผู้ใช้กรอก
        provided = self.local_admin_username is not None or self.local_admin_password is not None
        if not self.add_local_administrator:
            if provided:
                raise ValueError("Local administrator credentials are only accepted when it is enabled")
            return self
        if self.device_mode != "existing":
            raise ValueError("Local administrator can only be added to an Existing Device")
        password = self.local_admin_password.get_secret_value() if self.local_admin_password is not None else None
        validate_local_admin_username(self.vendor, self.local_admin_username, load_environment().MNG_USER)
        validate_local_admin_password(password)
        return self

    @model_validator(mode="after")
    def _validate_cli_interfaces(self):
        # ตรวจที่ request boundary ก่อนสร้าง bootstrap token หรือประกอบข้อความ CLI
        # และใช้ policy เดียวกับ cli_generator เพื่อไม่ให้กฎสองจุดคลาดเคลื่อนกัน
        validate_cli_interfaces(
            vendor=self.vendor,
            device_mode=self.device_mode,
            device_role=self.device_role,
            wan_interface=self.wan_interface,
        )
        return self

    @model_validator(mode="after")
    def _validate_bootstrap_interface(self):
        # Huawei ใช้ชุดนี้เสมอในโหมด new (CE12800 เป็นสวิตช์อยู่แล้ว) ส่วน
        # Cisco/Juniper ใช้เฉพาะตอนเลือก role เป็น switch - router ยังผูก IP กับ
        # WAN interface ตรง ๆ เหมือนเดิม ไม่มี VLAN มาเกี่ยว
        needs_plan = self.device_mode != "existing" and (
            self.vendor == "huawei" or (self.vendor in ("cisco", "juniper") and self.device_role == "switch")
        )
        if not needs_plan:
            return self

        if self.bootstrap_interface_type not in ("vlan", "layer3"):
            raise ValueError("Bootstrap interface type must be vlan or layer3")

        def validate_port():
            validate_bootstrap_port(self.vendor, self.bootstrap_interface)

        if self.bootstrap_interface_type == "layer3":
            validate_port()
            return self

        if self.bootstrap_vlan_mode not in ("access", "trunk"):
            raise ValueError("Bootstrap VLAN mode must be access or trunk")

        needs_specific_vlan = self.bootstrap_vlan_mode == "trunk"
        if self.bootstrap_vlan_mode == "access":
            if self.bootstrap_vlan_selection not in ("default", "specific"):
                raise ValueError("Bootstrap access VLAN selection must be default or specific")
            needs_specific_vlan = self.bootstrap_vlan_selection == "specific"

        if needs_specific_vlan:
            if self.bootstrap_vlan_id is None or not 1 <= self.bootstrap_vlan_id <= 4094:
                raise ValueError("Bootstrap VLAN ID must be between 1 and 4094")
            validate_port()

        return self

    # นโยบายรหัสผ่านของ console user (บัญชีสำรองกัน console ล็อกตาย - ดู
    # generate_cisco ที่ออกคำสั่ง `username X privilege 15 secret <password>`)
    # บัญชีนี้เป็น privilege 15 จริงบนอุปกรณ์ จึงต้องมีนโยบายบังคับ ไม่ปล่อยให้ตั้ง
    # อะไรก็ได้ - ฝั่ง frontend มีเช็ครายการเดียวกันแบบ real-time ให้ผู้ใช้เห็น
    # ระหว่างพิมพ์ แต่ต้องเช็คซ้ำที่นี่ด้วยเสมอ เพราะ validation ฝั่ง browser ข้ามได้
    # ด้วยการยิง API ตรง
    #
    # ใช้ model_validator (ไม่ใช่ field_validator) เพราะต้องอ่าน device_mode ประกอบ
    # ด้วย - โหมด existing ไม่ได้สร้าง console user เลย (ดู generate_cisco ที่ block1
    # ถูกข้ามทั้งก้อน) จึงปล่อยผ่านทุกกรณีโดยไม่ตรวจอะไร ส่วน field_validator จะเห็น
    # เฉพาะค่าของ field ตัวเองเท่านั้น ตัดสินตามโหมดไม่ได้
    @model_validator(mode="after")
    def _validate_console_password(self):
        # โหมด existing: ไม่ใช้ console user เลย ปล่อยผ่านไม่ต้องตรวจ
        if self.device_mode == "existing":
            return self
        # ยังไม่กรอกมา: ปล่อยให้ _required() ใน cli_generator เป็นคนบอกว่าขาด field ไหน
        # (จะได้ error รวมกับ field อื่นที่ขาดในข้อความเดียว ไม่แยกกันคนละที่)
        if not self.console_password:
            return self

        value = self.console_password
        unmet = []
        if len(value) < 8:
            unmet.append("be at least 8 characters long")
        if not re.search(r"[a-z]", value):
            unmet.append("contain lowercase letter (a-z)")
        if not re.search(r"[A-Z]", value):
            unmet.append("contain uppercase letter (A-Z)")
        if not re.search(r"[0-9]", value):
            unmet.append("contain a number (0-9)")
        if not re.search(r"[^A-Za-z0-9]", value):
            unmet.append("contain special character (!@#$%^&* etc.)")

        if unmet:
            raise ValueError("Console password must: " + ", ".join(unmet))
        return self

    # (bug 12) เดิม hostname เป็น Optional[str] เปล่า ๆ ไม่มี constraint ใด ๆ เลย
    # ผู้ใช้จึงกรอกได้ทุกอย่าง: ยาว 500 ตัว, ภาษาไทย, emoji, เว้นวรรค รวมถึง "ขึ้นบรรทัด
    # ใหม่" ซึ่งอันตรายที่สุดในเส้นทางนี้ เพราะผลลัพธ์ของ cli_generator เป็น "ข้อความ CLI"
    # ที่ผู้ใช้ copy ไปวางบน console อุปกรณ์เอง - ทุกอย่างหลัง \n จึงกลายเป็นคำสั่ง
    # บรรทัดถัดไปทันที (ยืนยันแล้วว่าแทรก `username ... privilege 15` เข้า config ได้จริง)
    # ต่างจากเส้นทาง NETCONF ที่ยังมี escape() ช่วยได้ - ตรงนี้ไม่มีอะไรช่วยเลยนอกจาก
    # ตรวจตั้งแต่ต้นทาง จึงใช้นโยบายกลางตัวเดียวกับ vendor_translators (tools/hostname_policy.py)
    #
    # ใช้ model_validator เหมือน _validate_console_password เพราะต้องอ่าน device_mode
    # ประกอบ - โหมด existing ไม่ตั้ง hostname ให้อุปกรณ์เลย (generate_cisco/generate_juniper
    # ข้ามทั้งบล็อก และ generate_juniper ใช้ค่าคงที่ "cloud-managed-device" แทน) จึงไม่ต้อง
    # บังคับรูปแบบของค่าที่ไม่ได้ถูกใช้
    @model_validator(mode="after")
    def _validate_hostname(self):
        if self.device_mode == "existing":
            return self
        # ไม่กรอกมา = ไม่เปลี่ยนชื่ออุปกรณ์ (hostname ไม่บังคับแล้วทุกยี่ห้อ ดู
        # _hostname() ใน cli_generator.py ที่ข้ามคำสั่งตั้งชื่อไปเลยเมื่อค่าว่าง) -
        # ตรวจรูปแบบเฉพาะตอนที่กรอกมาจริงเท่านั้น
        if not self.hostname:
            return self
        validate_hostname(self.hostname)
        return self

    # (bug 12 - ส่วนที่ตกไป พบ 3 ก.ย. 2026) ตอนแก้ bug 12 จำกัด charset ให้ hostname
    # แต่ domain_name ที่อยู่ในฟอร์มเดียวกันและไปลงไฟล์ config เดียวกันกลับตกไป -
    # ยืนยันด้วยการรันจริงว่า cli_generator.py บรรทัด "ip domain name {domain_name}"
    # ยังแทรกคำสั่งได้อยู่ ("username hacker privilege 15 ..." โผล่ในไฟล์ที่ผู้ใช้จะ
    # copy ไปวางบน console) เป็นช่องเดียวกับ hostname เป๊ะ
    #
    # ใช้ model_validator เหมือนตัวอื่นเพราะต้องอ่าน device_mode ประกอบ - โหมด existing
    # ไม่ตั้ง domain name ให้อุปกรณ์เลย (generate_cisco ข้ามทั้งบล็อก) และ domain_name
    # บังคับเฉพาะ cisco เท่านั้น (ดู _required ใน generate_cisco)
    @model_validator(mode="after")
    def _validate_domain_name(self):
        if self.device_mode == "existing":
            return self
        if not self.domain_name:
            return self
        validate_domain_name(self.domain_name, "Domain Name")
        return self


# Phase 9: Reset Device Identity Response
class DeviceResetIdentityResponse(SQLModel):
    mode: str  # "online" | "offline"
    device_id: str
    vendor: str
    expires_at: datetime
    cli: Optional[str] = None
    cli_steps: Optional[list[dict[str, Any]]] = None
    warning: Optional[str] = None
