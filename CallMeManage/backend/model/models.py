""" |======= Table Model for PostgreSQL =======| """

import secrets
from typing import List, Optional
from sqlmodel import Field, Relationship, SQLModel, UniqueConstraint, CheckConstraint
from sqlalchemy import DateTime, Index, text
from datetime import datetime, timezone

from tools.uuid_generate import uuid7

def generate_timestamp():
    return datetime.now(timezone.utc)

# timestamp ที่เก็บบนตารางต้องเป็นชนิด timezone เท่านั้น ซึ่งก็คือ timestamptz
UTC_TIMESTAMP = DateTime(timezone=True)


""" ตารางร่วม (Link Table) ระหว่าง Site_Table กับ User_Table สำหรับจัดการสมาชิกและคำขอ Join """
class Site_Member(SQLModel, table=True):
    # cooperatate primary key
    site_id: str = Field(foreign_key="site_table.site_id", primary_key=True)
    usr_id: str = Field(foreign_key="user_table.usr_id", primary_key=True, ondelete="CASCADE", index=True)

    # table value
    role: str = Field(default="member")     # member role
    status: str = Field(default="pending")  # member status (pending/approved)
    joined_date: datetime = Field(default_factory=generate_timestamp, sa_type=UTC_TIMESTAMP)    # member joined date timestamp

    # related table
    site: "Site_Table" = Relationship(back_populates="memberships")
    user: "User_Table" = Relationship(back_populates="site_memberships")

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'approved', 'invited')",
            name="check_site_member_status"
        ),
        CheckConstraint(
            "role IN ('admin', 'member')",
            name="check_site_member_role"
        )
    )

# ตารางสาขากายภาพ/ศูนย์ข้อมูล - Container หลักที่อุปกรณ์ (Device_Information)
# สังกัดอยู่แทนที่จะผูกกับ user คนเดียวแบบเดิม (dev_owner_id) - org_id ใช้ค้นหา/
# ขอ Join สาขา (Request to Join workflow - ดู planning/rbac.md ข้อ 8.4)

""" ตารางเก็บข้อมูล site งาน """
class Site_Table(SQLModel, table=True):
    # primary key
    site_id: str = Field(default_factory=lambda: f"site_{uuid7()}", primary_key=True)

    # site information
    org_id: str = Field(max_length=16, index=True, unique=True)
    site_name: str = Field(max_length=64, index=True)
    site_owner_id: str = Field(foreign_key="user_table.usr_id", index=True)  # Admin เจ้าของไซต์
    site_created_date: datetime = Field(default_factory=generate_timestamp, sa_type=UTC_TIMESTAMP)

    # related table
    owner: "User_Table" = Relationship(back_populates="owned_sites")
    devices: List["Device_Information"] = Relationship(back_populates="site")
    memberships: List["Site_Member"] = Relationship(back_populates="site")

""" ตารางเก็บข้อมูลผู้ใช้ """
# default=None มีค่าเป็น NULL ใน database
class User_Table(SQLModel, table=True):
    # primary key
    usr_id: str = Field(default_factory=lambda: F"usr_{uuid7()}", primary_key=True)

    # user information
    usr_name: str = Field(index=True, unique=True, min_length=5, max_length=32)
    usr_email: str = Field(unique=True)
    usr_passwd: str
    usr_role: str # field ตาย เตรียมลบ
    # Optional for backward compatibility: existing accounts remain usable and
    # are not silently treated as verified by the new registration flow.
    usr_google_sub: Optional[str] = Field(default=None, max_length=255)
    usr_email_verified_at: Optional[datetime] = Field(default=None, sa_type=UTC_TIMESTAMP)
    usr_created_date: datetime = Field(default_factory=generate_timestamp, sa_type=UTC_TIMESTAMP)
    # CM-08: JWT ทุกใบเก็บค่านี้ตอนออก ทุก request ต้องตรงกับค่าปัจจุบันเป๊ะ - reset password
    # เพิ่มค่าใน transaction เดียวกับการเปลี่ยนรหัส token เก่าทุกใบจึงใช้ไม่ได้ทันทีแม้ Redis ล่ม
    usr_auth_version: int = Field(default=1, nullable=False, sa_column_kwargs={"server_default": text("1")})

    # related table
    usr_acc_dev_date: List["Device_Access"] = Relationship(
        back_populates="acc_usr", sa_relationship_kwargs={"passive_deletes": True}
    )
    usr_dev_his: List["Device_History"] = Relationship(
        back_populates="his_usr", sa_relationship_kwargs={"passive_deletes": True}
    )
    usr_cfg_objects: List["Device_Config_Object"] = Relationship(
        back_populates="cfg_created_by", sa_relationship_kwargs={"passive_deletes": True}
    )
    owned_sites: List["Site_Table"] = Relationship(back_populates="owner")
    site_memberships: List["Site_Member"] = Relationship(
        back_populates="user", sa_relationship_kwargs={"passive_deletes": True}
    )

    __table_args__ = (
        # A Google subject identifies one Google account. PostgreSQL's partial
        # index keeps legacy/non-Google NULL rows unrestricted.
        Index(
            "uq_user_table_usr_google_sub_not_null",
            "usr_google_sub",
            unique=True,
            postgresql_where=text("usr_google_sub IS NOT NULL"),
        ),
    )

""" ตารางเก็บข้อมูลอุปกรณ์ """
class Device_Information(SQLModel, table=True):
    # primary key
    dev_id: str = Field(default_factory=lambda: F"dev_{uuid7()}", primary_key=True)

    # device information
    dev_vendor: str
    dev_model: str
    dev_firmware: str
    dev_name: str
    dev_ip: str
    dev_fingerprint: Optional[str] = Field(default=None, index=True)
    dev_status: str = Field(default="pending", index=True)  # pending|active|rejected|offline
    dev_registered: bool = Field(default=False)
    dev_viewed: bool = Field(default=False)
    dev_added_date: datetime = Field(default_factory=generate_timestamp, sa_type=UTC_TIMESTAMP)
    dev_last_seen: Optional[datetime] = Field(default=None, sa_type=UTC_TIMESTAMP)

    # foreign  key
    site_id: str = Field(foreign_key="site_table.site_id", index=True)

    # related table
    site: "Site_Table" = Relationship(back_populates="devices")
    dev_cap: "Device_Capability" = Relationship(back_populates="cap_dev_name")
    dev_acc_date: List["Device_Access"] = Relationship(back_populates="acc_dev")
    dev_his: List["Device_History"] = Relationship(back_populates="his_dev")
    dev_cfg_objects: List["Device_Config_Object"] = Relationship(back_populates="cfg_dev")
    # marker ของระบบ One-Time Token (1 Device มีได้ไม่เกิน 1 แถว) - DB เป็นคนลบให้ตอนลบ Device
    dev_enrollment: Optional["Device_Enrollment"] = Relationship(
        back_populates="enr_dev", sa_relationship_kwargs={"passive_deletes": True, "uselist": False}
    )

    # force these values to be unique
    __table_args__ = (
        # defense-in-depth: ชื่อ pending ของ token flow (ยังไม่มี fingerprint) ห้ามซ้ำต่อ Site
        Index(
            "uq_device_token_pending_name",
            "site_id",
            "dev_name",
            unique=True,
            postgresql_where=text(
                "dev_status = 'pending' AND dev_fingerprint IS NULL"
            ),
        ),
        # fingerprint ที่ไม่ใช่ NULL ต้องระบุอุปกรณ์ได้เพียงตัวเดียว (ใช้กับ reconnect ด้วย fingerprint)
        # PostgreSQL ปล่อยให้ NULL ซ้ำกันได้ตามปกติ (pending Device ยังไม่มี fingerprint)
        UniqueConstraint("dev_fingerprint", name="uq_device_information_dev_fingerprint"),
    )

""" ตารางเก็บสถานะ One-Time Enrollment Token ของอุปกรณ์ """
# Pending  : token_hash มีค่า และ consumed_at = NULL
# Consumed : token_hash = NULL และ consumed_at มีค่า (แถวคงอยู่เพื่อยืนยันว่า Device นี้ activate ด้วย token
#            และมีสิทธิ์ reconnect ด้วย pinned fingerprint)
# เก็บเฉพาะ SHA-256 hex digest ของ token (ห้ามเก็บ plaintext) และไม่เก็บ site/vendor/fingerprint/MAC/Serial ซ้ำ
class Device_Enrollment(SQLModel, table=True):
    # primary key
    enrollment_id: str = Field(default_factory=lambda: f"enr_{uuid7()}", primary_key=True)

    # foreign key - ลบ Device แล้ว DB ลบแถวนี้ตาม
    device_id: str = Field(foreign_key="device_information.dev_id", ondelete="CASCADE")

    # enrollment information
    token_hash: Optional[str] = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=generate_timestamp, sa_type=UTC_TIMESTAMP)
    expires_at: Optional[datetime] = Field(default=None, sa_type=UTC_TIMESTAMP)  # หมดอายุของ Pending เท่านั้น
    consumed_at: Optional[datetime] = Field(default=None, sa_type=UTC_TIMESTAMP)

    # related table
    enr_dev: "Device_Information" = Relationship(back_populates="dev_enrollment")

    # ไม่แสดง token_hash ใน repr (กัน hash หลุดลง log เมื่อมีการ print/log ตัว object)
    def __repr_args__(self):
        return [(name, "<REDACTED>" if name == "token_hash" and value is not None else value)
                for name, value in super().__repr_args__()]

    __table_args__ = (
        UniqueConstraint("device_id", name="uq_device_enrollment_device_id"),
        # NULL หลายแถวอยู่ร่วมกันได้ (consumed marker) แต่ hash ที่มีค่าห้ามซ้ำ
        UniqueConstraint("token_hash", name="uq_device_enrollment_token_hash"),
        CheckConstraint(
            "(token_hash IS NOT NULL AND consumed_at IS NULL) OR (token_hash IS NULL AND consumed_at IS NOT NULL)",
            name="ck_device_enrollment_state",
        ),
        CheckConstraint(
            "token_hash IS NULL OR token_hash ~ '^[0-9a-f]{64}$'",
            name="ck_device_enrollment_token_hash_format",
        ),
    )

""" ตารางเก็บข้อมูลความสามารถของอุปกรณ์ """
class Device_Capability(SQLModel, table=True):
    # primary key
    cap_id: str = Field(default_factory=lambda: F"cap_{uuid7()}", primary_key=True)

    # device capability information
    cap_vendor: str
    cap_detail: str # เก็บเป็นแบบแปลงอ่านได้ง่าย ค่อย map ใส่ xml
    cap_saved_date: datetime = Field(default_factory=generate_timestamp, sa_type=UTC_TIMESTAMP)

    # foreign  key
    cap_dev_id: str = Field(foreign_key="device_information.dev_id", unique=True)

    # related table
    cap_dev_name: "Device_Information" = Relationship(back_populates="dev_cap")

""" ตารางเก็บข้อมูลการเข้าใช้งานอุปกรณ์ """
class Device_Access(SQLModel, table=True):
    # primary key
    acc_id: str = Field(default_factory=lambda: F"acc_{uuid7()}", primary_key=True)

    # device access information
    # UUID ที่ browser สร้างใหม่ทุกครั้งที่เปิดหน้าอุปกรณ์ ใช้ให้ heartbeat
    # หลายครั้งอัปเดตแถว session เดิมโดยไม่ยุบ session คนละรอบเข้าด้วยกัน
    # UUID ใหม่ยาว 36 ตัว; migration ใช้ acc_id เดิม (prefix acc_ + UUID = 40)
    # backfill แถวประวัติเก่าจึงเผื่อไว้ 40 ตัวโดยไม่เปลี่ยนค่าของเดิม
    acc_session_id: str = Field(max_length=40)
    acc_date: datetime = Field(sa_type=UTC_TIMESTAMP)
    acc_lastseen: datetime = Field(sa_type=UTC_TIMESTAMP)

    # foreign  keys
    acc_dev_id: str = Field(foreign_key="device_information.dev_id", index=True)
    acc_usr_id: Optional[str] = Field(default=None, foreign_key="user_table.usr_id", ondelete="SET NULL", index=True)

    # related table
    acc_dev: "Device_Information" = Relationship(back_populates="dev_acc_date")
    acc_usr: Optional["User_Table"] = Relationship(back_populates="usr_acc_dev_date")

    __table_args__ = (
        UniqueConstraint("acc_session_id", name="uq_device_access_session_id"),
        Index("ix_device_access_dev_lastseen_id", "acc_dev_id", "acc_lastseen", "acc_id"),
    )

""" ตารางเก็บประวัติการสั่งการอุปกรณ์ """
class Device_History(SQLModel, table=True):
    # primary key
    his_id: str = Field(default_factory=lambda: F"his_{uuid7()}", primary_key=True)

    # history information
    his_action: str
    his_action_detail: str
    his_action_time: datetime = Field(default_factory=generate_timestamp, sa_type=UTC_TIMESTAMP)

    # foreign  keys
    his_dev_id: str = Field(foreign_key="device_information.dev_id", index=True)
    his_usr_id: Optional[str] = Field(default=None, foreign_key="user_table.usr_id", ondelete="SET NULL", index=True)

    # related table
    his_dev: "Device_Information" = Relationship(back_populates="dev_his")
    his_usr: Optional["User_Table"] = Relationship(back_populates="usr_dev_his")


""" ตารางเก็บ bootstrap token """
class Bootstrap_Token(SQLModel, table=True):
    # primary key
    bst_token: str = Field(default_factory=lambda: secrets.token_urlsafe(32), primary_key=True)

    # bootstrap information
    bst_created_date: datetime = Field(default_factory=generate_timestamp, sa_type=UTC_TIMESTAMP)
    bst_expires_at: datetime = Field(sa_type=UTC_TIMESTAMP)
    bst_config_payload: Optional[str] = Field(default=None)

    bst_used: bool = Field(default=False)
    bst_used_at: Optional[datetime] = Field(default=None, sa_type=UTC_TIMESTAMP)
    bst_used_from_ip: Optional[str] = Field(default=None)

    # foreign  key
    bst_usr_id: str = Field(foreign_key="user_table.usr_id", ondelete="CASCADE")


# ระบบจดจำ "สิ่งที่เราสั่งสร้างไปแล้ว" ต่ออุปกรณ์ - เป็น single source of truth
# แทนการ re-parse XML สดจากอุปกรณ์ทุกครั้งตอนจะ edit/delete config ที่พ่วงหลาย
# ส่วนเข้าด้วยกัน (เช่น NAT Policy ผูก ACL + nat rule + interface flag พร้อมกัน -
# ถ้า derive จาก live state อย่างเดียวจะไม่รู้ว่าต้องแก้/ลบกี่จุด) cfg_feature เป็น
# string อิสระ (เช่น "nat_policy", "nat_pool", "acl_rule", "static_nat",
# "port_forward") ไม่ผูก enum ตายตัว - เพิ่ม feature ใหม่ทำได้โดยไม่ต้อง migrate
# schema เพิ่ม cfg_params เก็บ JSON string ของ parameter ที่ใช้สร้างจริง (รูปแบบ
# เดียวกับ Device_History.his_action_detail) ไว้คำนวณตอน edit/delete

""" ตารางเก็บ config ที่สร้างได้หลายตัวแต่ไม่สามารถตั้งชื่อได้ """
class Device_Config_Object(SQLModel, table=True):
    # primary key
    cfg_id: str = Field(default_factory=lambda: F"cfg_{uuid7()}", primary_key=True)

    # config information
    cfg_feature: str = Field(index=True)
    cfg_name: str = Field(index=True)
    cfg_params: str
    cfg_created_date: datetime = Field(default_factory=generate_timestamp, sa_type=UTC_TIMESTAMP)

    # foreign keys
    cfg_dev_id: str = Field(foreign_key="device_information.dev_id", index=True)
    cfg_created_by_id: Optional[str] = Field(
        default=None, foreign_key="user_table.usr_id", ondelete="SET NULL", index=True
    )

    # related table
    cfg_dev: "Device_Information" = Relationship(back_populates="dev_cfg_objects")
    cfg_created_by: Optional["User_Table"] = Relationship(back_populates="usr_cfg_objects")

    # these value is force to be unique
    __table_args__ = (
        UniqueConstraint("cfg_dev_id", "cfg_feature", "cfg_name", name="uq_cfg_dev_feature_name"),
    )
