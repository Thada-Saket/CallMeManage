import DismissibleError from "../components/DismissibleError";
import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import TopBar from "../components/TopBar";
import DynamicCommandForm from "../components/DynamicCommandForm";
import BasicInfo from "../components/cmdGroups/dashboard/basic_info";
import ArpStatus from "../components/cmdGroups/dashboard/arp_status";
import NetworkStatus from "../components/cmdGroups/dashboard/network_status";
import SecurityStatus from "../components/cmdGroups/dashboard/security_status";
import History from "../components/cmdGroups/dashboard/history";
import DeviceInfo from "../components/cmdGroups/system/device_info";
import UserInfo from "../components/cmdGroups/system/user_info";
import AccessLog from "../components/cmdGroups/system/log";
import Interfaces from "../components/cmdGroups/network/interfaces";
import ZoneInterfaces from "../components/cmdGroups/network/zoneInterfaces";
import Vlan from "../components/cmdGroups/network/vlan";
import Dns from "../components/cmdGroups/network/dns";
import Ntp from "../components/cmdGroups/network/ntp";
import Dhcp from "../components/cmdGroups/network/dhcp";
import Ping from "../components/cmdGroups/network/ping";
import IPRouting from "../components/cmdGroups/route/ip_routing";
import IPDefaultGateway from "../components/cmdGroups/route/ip_defaultgateway";
import StaticRoute from "../components/cmdGroups/route/static_route";
import RipRoute from "../components/cmdGroups/route/rip_route";
import OspfRoute from "../components/cmdGroups/route/ospf_route";
import AddressBook from "../components/cmdGroups/addresses/addressBook";
import AddressPool from "../components/cmdGroups/addresses/addressPool";
import Stateless from "../components/cmdGroups/firewall/stateless";
import Stateful from "../components/cmdGroups/firewall/stateful";
import Nat from "../components/cmdGroups/nat/nat";
import NatStatic from "../components/cmdGroups/nat/natStatic";
import Pf from "../components/cmdGroups/nat/pf";
import SecurityProfile from "../components/cmdGroups/vpn/security_profile";
import SecurityTunnel from "../components/cmdGroups/vpn/security_tunnel";

import {
  getConfigSaveStatus,
  getDevice,
  getDeviceCapability,
  getDeviceCommands,
  heartbeatDeviceAccessSession,
  pingDevicePresence,
  runDeviceCommand,
  startDeviceAccessSession,
} from "../api/api_devices";
import { DeviceCapabilityContext, hiddenCommandsFrom, hiddenOptionsFrom } from "../hooks/deviceCapability";
import { parseIpRouting, showCiscoRouteModeItem } from "../utils/ciscoRouteMode";

// เทียบเท่า basic_info.jsx/Devices.jsx (10 วิ) - GET /devices/{id} query DB เบาๆ
// ไม่ใช่ NETCONF RPC เลย poll ถี่ขนาดนี้ได้อย่างปลอดภัย ทำให้ badge สถานะ +
// Offline Alert Modal/read-only lock/banner อัปเดตเองแบบ real-time (ทั้งตอนหลุด
// การเชื่อมต่อและตอนกลับมาออนไลน์) โดยไม่ต้องกด refresh หน้าเลย
const POLL_INTERVAL_MS = 10000;
// ยี่ห้อที่ต้อง save running -> startup เอง (ตรงกับ SAVE_CONFIG_VENDORS ใน device_router.py)
const SAVE_CONFIG_VENDORS = new Set(["cisco", "huawei"]);
// (dynamic feature ขั้นที่ 5) ระหว่างที่ backend กำลังตรวจความสามารถ ถามผลซ้ำถี่กว่ารอบปกติ
const CAPABILITY_PROBE_POLL_MS = 3000;
const HOSTNAME_MAX_LENGTH = 32;
const HOSTNAME_PATTERN = /^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$/;
const HOSTNAME_HINT = "Use 1-32 characters: A-Z, a-z, 0-9, hyphen (-), or underscore (_). A hyphen cannot be the first or last character.";

function createAccessSessionId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  if (!globalThis.crypto?.getRandomValues) return null;
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
}

// เมนูซ่อนตัวเองอัตโนมัติตามความสามารถจริงของอุปกรณ์ (ไม่ hardcode ชื่อยี่ห้อ)
//
// แต่ละรายการประกาศ `requires` = รายชื่อคำสั่งที่หน้านั้นต้องใช้ **อย่างน้อย 1 ตัว**
// (ไม่ใช่ต้องมีครบทุกตัว) แล้วเอาไปกรองกับรายการคำสั่งจริงของอุปกรณ์ที่หน้านี้
// โหลดมาอยู่แล้วผ่าน getDeviceCommands() -> GET /devices/{id}/commands ซึ่ง backend
// สร้างจาก functions_for_vendor() ที่ใช้ getattr(module, name) จึงคืนเฉพาะคำสั่งที่
// ยี่ห้อนั้น "มีจริง" ในโมดูล translator ของตัวเอง
//
// ทำไมใช้ any-of ไม่ใช่ all: บางหน้าเลือกคำสั่งตามยี่ห้อ (เช่น Stateful ใช้
// get_firewall_information บน Cisco แต่ get_security_policy_information บน Junos)
// ถ้าบังคับให้มีครบทุกตัวจะซ่อนหน้านั้นจากทั้ง 2 ยี่ห้อพร้อมกัน
//
// requires: [] = โชว์เสมอ ใช้กับ 2 กรณี
//   1. หน้าที่ไม่ได้ยิงคำสั่ง translator เลย (Basic Info/History/Device Info อ่าน
//      จาก props หรือ endpoint ของ server เอง)
//   2. หน้าที่ยังไม่ได้ทำ (VPN Status ถูกถอดออกจากเมนูตามคำสั่งผู้ใช้)
//
// unsupportedVendors เป็นข้อยกเว้นแคบๆ สำหรับหน้าที่ความสามารถไม่ได้แทนด้วยชื่อ
// translator (เช่น PING ใช้ endpoint คนละเส้น, NTP ยังไม่มี component) จึงต้อง
// ระบุยี่ห้อที่ใช้ไม่ได้ตรงๆ; ห้ามใช้แทน requires ในกรณีทั่วไป เพราะ requires
// ทำให้ยี่ห้อใหม่ได้รับเมนูอัตโนมัติตาม translator โดยไม่สร้าง hardcode เพิ่ม
//
// เพิ่มยี่ห้อใหม่ในอนาคตไม่ต้องแก้ไฟล์นี้เลยเมื่อหน้ามี translator - เขียน
// translator ให้ครบแล้วเมนูจะโผล่เอง และถ้าลบคำสั่งออกเมนูก็หายเอง
const MENU = [
  {
    id: "dashboard",
    label: "Dashboard",
    items: [
      { name: "Basic Info", requires: [] },
      { name: "ARP Status", requires: ["get_arp_table"] },
      { name: "Routing Status", requires: ["get_routing_table"], requiresIpRouting: true },
      { name: "Security Status", requires: ["get_security_status"] },
      { name: "History", requires: [] },
    ]
  },
  {
    id: "network",
    label: "Network",
    items: [
      { name: "Interfaces", requires: ["get_ip_interface_brief"] },
      { name: "VLAN", requires: ["get_vlan_information"] },
      { name: "DNS", requires: ["get_dns_information"] },
      { name: "DHCP", requires: ["get_dhcp_pool_information"] },
      { name: "NTP", requires: ["get_ntp_information"] },
      // PING ไม่ได้ยิงผ่าน translator (ใช้ POST /devices/{id}/ping-test) จึงไม่มี
      // ชื่อคำสั่งให้ requires กรอง; backend รองรับแค่ Cisco/Juniper จึงซ่อน
      // Huawei ด้วย unsupportedVendors แทน ไม่ปล่อยให้กดแล้วเจอ error
      { name: "PING", requires: [], unsupportedVendors: ["huawei"] },
    ]
  },
  {
    id: "addresses",
    label: "Addresses",
    items: [
      // Address book รองรับเฉพาะ Juniper (SRX address-book) เท่านั้น
      // Cisco และ Huawei ไม่มีฟีเจอร์นี้ จึงซ่อนด้วย unsupportedVendors
      { name: "Address book", requires: [], unsupportedVendors: ["cisco", "huawei"] },
      { name: "Address pool", requires: ["get_nat_pool_information"] },
    ]
  },
  {
    id: "route",
    label: "Route",
    items: [
      // global toggle ของ Cisco switch เท่านั้น ส่วน router ถูก capability จำแนกจาก
      // routing-platform แล้วซ่อนทั้งคู่ ด้านล่าง visibleMenu ยังสลับ Default-Gateway
      // ตามสถานะ ip routing จริงอีกชั้น; unsupportedVendors กันยี่ห้ออื่นไม่ให้กระพริบ
      // ขึ้นระหว่างที่รายการ capability ยังโหลดไม่เสร็จ
      { name: "IP Routing", requires: ["get_ip_routing"], unsupportedVendors: ["huawei", "juniper"] },
      { name: "IP Default-Gateway", requires: ["get_ip_default_gateway"], unsupportedVendors: ["huawei", "juniper"] },
      { name: "Static Routes", requires: ["get_static_route_configuration"], requiresIpRouting: true },
      { name: "RIP Routes", requires: ["get_rip_information"], requiresIpRouting: true },
      { name: "OSPF Routes", requires: ["get_ospf_information"], requiresIpRouting: true },
    ]
  },
  {
    id: "nat",
    label: "NAT",
    items: [
      // Cisco อ่านผ่าน get_nat_dashboard / Juniper ใช้ get_nat_information (ดู nat.jsx)
      { name: "NAT", requires: ["get_nat_dashboard", "get_nat_information"] },
      { name: "Static NAT", requires: ["get_static_nat_information"] },
      { name: "Port Forwarding", requires: ["get_port_forward_information"] },
    ]
  },
  {
    id: "firewall",
    label: "Firewall",
    items: [
      { name: "Interface Zone", requires: ["get_security_zone_information"], requiresIpRouting: true },
      { name: "Access Control List", requires: ["get_acl_information"], requiresIpRouting: true },
      { name: "Stateful Firewall", requires: ["get_firewall_information", "get_security_policy_information"], requiresIpRouting: true },
    ]
  },
  {
    id: "vpn",
    label: "VPN",
    items: [
      { name: "Security Profile", requires: ["get_security_profile_information"], requiresIpRouting: true },
      { name: "Security Tunnel", requires: ["get_security_tunnel_information"], requiresIpRouting: true },
    ]
  },
  {
    id: "system",
    label: "System Management",
    items: [
      { name: "Device Setting", requires: [] },
      // local user บนอุปกรณ์ - โผล่เฉพาะยี่ห้อที่ translator มี get_local_user (Cisco/Juniper/Huawei)
      { name: "User Management", requires: ["get_local_user"] },
      { name: "Access Log", requires: [] },
    ]
  },
]

// ผูกตัวเลือกใน MENU เข้ากับไฟล์คำสั่งจริงใน components/cmdGroups/<groupId>/ -
// ไฟล์คำสั่งแต่ละตัวรู้เองว่าต้องยิงคำสั่งอะไรไปที่อุปกรณ์ (ดู arp_status.jsx)
// เพิ่มเมนูใหม่ = เขียนไฟล์ใหม่ใน cmdGroups/ แล้วมาลงทะเบียนตรงนี้อีกบรรทัดเดียว
const COMMAND_COMPONENTS = {
  "Basic Info": BasicInfo,
  "ARP Status": ArpStatus,
  "Routing Status": NetworkStatus,
  "Security Status": SecurityStatus,
  "History": History,
  "Interfaces": Interfaces,
  "VLAN": Vlan,
  "Address book": AddressBook,
  "Address pool": AddressPool,
  "DNS": Dns,
  "NTP": Ntp,
  "DHCP": Dhcp,
  "PING": Ping,
  "IP Routing": IPRouting,
  "IP Default-Gateway": IPDefaultGateway,
  "Static Routes": StaticRoute,
  "RIP Routes": RipRoute,
  "OSPF Routes": OspfRoute,
  "Interface Zone": ZoneInterfaces,
  "Access Control List": Stateless,
  "Stateful Firewall": Stateful,
  "NAT": Nat,
  "Static NAT": NatStatic,
  "Port Forwarding": Pf,
  "Security Profile": SecurityProfile,
  "Security Tunnel": SecurityTunnel,
  "Device Setting": DeviceInfo,
  "User Management": UserInfo,
  "Access Log": AccessLog,
}

export default function DeviceDetail() {
  const { devId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const [device, setDevice] = useState(null);
  const [error, setError] = useState("");
  const [commands, setCommands] = useState([]);
  const [commandsError, setCommandsError] = useState("");
  // useRef ทำให้ React StrictMode ที่จำลอง cleanup/setup effect ซ้ำใน development
  // ใช้ UUID เดิมและ POST start ซ้ำแบบ idempotent แทนการสร้าง log ปลอมสองแถว
  const accessSessionRef = useRef(null);
  if (accessSessionRef.current?.devId !== devId) {
    accessSessionRef.current = { devId, sessionId: createAccessSessionId() };
  }
  // (dynamic feature ขั้นที่ 5) สรุปความสามารถจาก GET /devices/{id}/capability - ใช้ส่งคำสั่งที่ถูกซ่อนผ่าน
  // DeviceCapabilityContext ให้ hook/ฟอร์มข้ามสิ่งที่อุปกรณ์ทำไม่ได้ ไม่แสดงให้ผู้ใช้เห็นโดยตั้งใจ
  // (ผู้ใช้กำหนด: สิ่งที่ถูกซ่อนต้องไม่ถูกบอก ไม่งั้นไม่ใช่การซ่อน)
  const [capability, setCapability] = useState(null);
  const [ipRoutingEnabled, setIpRoutingEnabled] = useState(null);
  const [selectedCommand, setSelectedCommand] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [commandResult, setCommandResult] = useState(null);
  const [commandError, setCommandError] = useState("");
  const [showHostnameModal, setShowHostnameModal] = useState(false);
  const [hostnameDraft, setHostnameDraft] = useState("");
  const [hostnameError, setHostnameError] = useState("");
  const [hostnameSaving, setHostnameSaving] = useState(false);
  // user ขอ (2026-08-06): เปิดหน้าจัดการอุปกรณ์มาแล้วให้เจอ "Basic Info" เป็น
  // แท็บแรกทันทีเลย (เดิม active/openGroup เริ่มเป็น null - ต้องกดเลือกเมนูเอง
  // ก่อนถึงจะเห็นอะไร) - ค่าเริ่มต้นนี้ยังถูก override ได้ปกติถ้า navigate มา
  // พร้อม location.state.openHistory (ดู effect ด้านล่างที่เรียก
  // handleViewHistory() หลัง mount - รันทีหลังจึงชนะค่าเริ่มต้นนี้เสมอ)
  const [openGroup, setOpenGroup] = useState("dashboard");
  const [active, setActive] = useState("Basic Info");
  // Hybrid UX ตอนอุปกรณ์ offline - showOfflineModal เด้งทุกครั้งที่ device
  // transition เข้า offline ใหม่ (ทั้งตอนโหลดหน้าครั้งแรก และตอน real-time poll
  // เจอว่าหลุดการเชื่อมต่อระหว่างดูอยู่) readOnlyHistoryMode ค้างอยู่จนกว่าจะ
  // กลับมาออนไลน์เอง (auto-reset) หรือผู้ใช้ navigate ออกจากหน้านี้
  const [showOfflineModal, setShowOfflineModal] = useState(false);
  const [readOnlyHistoryMode, setReadOnlyHistoryMode] = useState(false);

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  // "ผู้ใช้ที่ใช้งานอยู่" ใน Basic Info (basic_info.jsx) - heartbeat ระดับหน้า
  // ทั้งหน้า (ไม่ผูกกับแท็บ Basic Info เฉยๆ - เปิดหน้าไหนของอุปกรณ์นี้ก็นับว่า
  // "กำลังใช้งานอยู่") ดู effect ที่ poll ทุก POLL_INTERVAL_MS ด้านล่าง
  const [presentUsers, setPresentUsers] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  // track "เปิด Offline Alert Modal ให้ offline รอบนี้ไปแล้วหรือยัง" กัน modal
  // เด้งซ้ำทุกรอบ poll (10 วิ) ตราบเท่าที่อุปกรณ์ยัง offline ต่อเนื่อง - ต้อง
  // trigger ใหม่แค่ตอน "transition เข้า offline" เท่านั้น ไม่ใช่ทุกครั้งที่ device
  // state อัปเดต - ใช้ ref เพราะไม่ต้อง re-render ตาม
  const offlineHandledRef = useRef(false);

  const toggle = (id) => setOpenGroup((prev) => (prev === id ? null : id));

  // จัดการการปิด drawer ด้วยปุ่ม Escape และป้องกันการเลื่อนหน้าเว็บด้านล่าง drawer บนมือถือ
  useEffect(() => {
    if (!mobileMenuOpen) return;
    const handleKeyDown = (e) => {
      if (e.key === "Escape") setMobileMenuOpen(false);
    };
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [mobileMenuOpen]);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const result = await getDevice(devId);
        if (!cancelled) {
          setDevice(result);
          setError("");
        }
      } catch (err) {
        if (!cancelled) setError(err.detail || "Failed to load device details");
      }
    }

    poll();
    const timer = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [devId]);

  // Persistent access log แยกจาก Redis presence เดิม: ตัวเดิมยังใช้แสดงรายชื่อ
  // คนออนไลน์ ส่วนตัวนี้สร้างหนึ่ง DB row ต่อการเปิดหน้าและเลื่อน Last Seen เท่านั้น
  useEffect(() => {
    const sessionId = accessSessionRef.current?.devId === devId
      ? accessSessionRef.current.sessionId
      : null;
    if (!devId || !sessionId) return undefined;
    let cancelled = false;
    let started = false;

    async function begin() {
      try {
        await startDeviceAccessSession(devId, sessionId);
        if (!cancelled) started = true;
      } catch {
        // Audit logging must never block an otherwise valid device workflow.
      }
    }

    async function heartbeat() {
      if (!started) return;
      try {
        await heartbeatDeviceAccessSession(devId, sessionId);
      } catch {
        // Best effort; a later heartbeat may recover after a transient failure.
      }
    }

    begin();
    const timer = setInterval(heartbeat, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [devId]);

  // Heartbeat "ผู้ใช้ที่ใช้งานอยู่" - แยก effect ของตัวเอง (ไม่รวมกับ poll
  // getDevice ด้านบน) เพราะเป็นคนละ concern กัน ยิงตราบเท่าที่หน้านี้ mount อยู่
  // เท่านั้น (ไม่ต้องรอ device โหลดเสร็จก่อน - ใช้แค่ devId จาก URL) ปิดหน้า/
  // navigate ออกไปแค่หยุด interval เฉยๆ ไม่ต้องแจ้ง backend ว่า "ออกแล้ว" เลย
  // (ปล่อยให้ Redis key หมดอายุเองตาม PRESENCE_TTL_SECONDS - ดู
  // backend/core/presence.py)
  useEffect(() => {
    let cancelled = false;

    async function ping() {
      try {
        const result = await pingDevicePresence(devId);
        if (!cancelled) {
          setPresentUsers(result.users || []);
          setCurrentUser(result.current_user_name || null);
        }
      } catch {
        /* best-effort เหมือน stats polling - พลาดรอบเดียวไม่ต้องโชว์ error รบกวน */
      }
    }

    ping();
    const timer = setInterval(ping, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [devId]);

  useEffect(() => {
    if (!device) return;
    if (device.dev_status === "offline") {
      if (!offlineHandledRef.current) {
        offlineHandledRef.current = true;
        setShowOfflineModal(true);
      }
    } else {
      // อุปกรณ์กลับมาออนไลน์ระหว่างที่ผู้ใช้กำลังดูหน้านี้อยู่ - เลิก read-only
      // mode + ปิด modal อัตโนมัติทันที (ปลดล็อกเมนูให้ใช้งานได้ปกติ) โดยไม่ต้อง
      // ให้ผู้ใช้กด refresh เอง แล้วรีเซ็ต flag ไว้ให้รอบ offline ถัดไป trigger
      // modal ใหม่ได้อีก
      offlineHandledRef.current = false;
      setShowOfflineModal(false);
      setReadOnlyHistoryMode(false);
    }
  }, [device]);

  function handleViewHistory() {
    setShowOfflineModal(false);
    setReadOnlyHistoryMode(true);
    setOpenGroup("dashboard");
    setActive("History");
  }

  function handleBackToDevices() {
    if (device?.site_id) {
      navigate(`/devices?site_id=${encodeURIComponent(device.site_id)}`);
    } else {
      navigate("/sites");
    }
  } 

  function openHostnameModal() {
    if (!device || !["active", "online"].includes(device.dev_status)) return;
    setHostnameDraft(device.dev_name || "");
    setHostnameError("");
    setShowHostnameModal(true);
  }

  function closeHostnameModal() {
    if (hostnameSaving) return;
    setShowHostnameModal(false);
    setHostnameError("");
  }

  async function handleHostnameApply(event) {
    event.preventDefault();
    if (hostnameSaving) return;

    const hostname = hostnameDraft.trim();
    if (!HOSTNAME_PATTERN.test(hostname) || hostname.length > HOSTNAME_MAX_LENGTH) {
      setHostnameError(HOSTNAME_HINT);
      return;
    }
    if (hostname === device?.dev_name) {
      return;
    }

    setHostnameError("");
    setHostnameSaving(true);
    try {
      await runDeviceCommand(devId, "set_hostname", { hostname });
      setDevice((current) => current ? { ...current, dev_name: hostname } : current);
      setShowHostnameModal(false);
    } catch (err) {
      setHostnameError(typeof err.detail === "string" ? err.detail : "Failed to change device hostname");
    } finally {
      setHostnameSaving(false);
    }
  }

  // user ขอ (2026-08-03): DeviceCard's action dropdown เพิ่มตัวเลือก "ดูประวัติ"
  // ที่ต้องพาตรงมาที่หน้านี้แล้วเปิด History tab ให้เลยทันที (ไม่ต้องให้ user
  // กดเลือกเมนูเอง) - navigate มาพร้อม location.state.openHistory - เรียก
  // handleViewHistory() ตัวเดิมเป๊ะ (ใช้ mechanism เดียวกับ Offline Alert
  // Modal's "เข้าดูประวัติคำสั่ง") ทั้งอุปกรณ์ online/offline: ถ้า offline จริง
  // effect ด้านบน ([device]) จะคง readOnlyHistoryMode ไว้ตามปกติ (ล็อกเมนูอื่น
  // เพราะยิงคำสั่งสดไม่ได้จริง) ถ้า online effect นั้นจะ auto-reset
  // readOnlyHistoryMode กลับเป็น false เอง (ปลดล็อกเมนูปกติ - ถูกต้องแล้วเพราะ
  // อุปกรณ์ online ยิงคำสั่งสดได้จริง) แต่ active/openGroup ยังคงเป็น "History"
  // อยู่ (effect นั้นไม่แตะ 2 ค่านี้) เลยยังเปิด History tab ค้างไว้ให้เหมือนกัน
  // ทั้ง 2 กรณี - offlineHandledRef ต้องตั้งเป็น true ไว้ก่อนด้วย กัน effect
  // ตรวจ offline (ที่ยังไม่ทันรันเพราะ device ยังไม่โหลดตอน mount effect นี้ทำงาน)
  // เด้ง showOfflineModal ซ้อนทับ History tab ที่เพิ่งเปิดไปแล้วโดยไม่จำเป็น
  useEffect(() => {
    if (location.state?.openHistory) {
      offlineHandledRef.current = true;
      handleViewHistory();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function loadCommands() {
    return getDeviceCommands(devId)
      .then((result) => {
        setCommands(result);
        setCommandsError("");
      })
      .catch((err) => setCommandsError(err.detail || "Failed to load device commands"));
  }

  // capability เป็นข้อมูลเสริม - โหลดไม่ได้ต้องไม่กระทบเมนูหรือการสั่งงาน (backend ตัดสินเองอยู่แล้ว)
  // จึงไม่แสดง error และคงค่าเดิมไว้
  function loadCapability() {
    return getDeviceCapability(devId)
      .then(setCapability)
      .catch(() => {});
  }

  useEffect(() => {
    if (!device) return;
    loadCommands();
    loadCapability();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [Boolean(device), devId]);
  // (dynamic feature ขั้นที่ 5) อุปกรณ์กลับจาก offline เป็นออนไลน์ = call-home ใหม่และ backend ตรวจความสามารถ
  // ใหม่ ต้องโหลดรายการคำสั่งกับ capability ใหม่ ไม่งั้นเมนูจะค้างตามโปรไฟล์ก่อนหลุด
  const previousStatusRef = useRef(null);
  useEffect(() => {
    const status = device?.dev_status;
    const previous = previousStatusRef.current;
    previousStatusRef.current = status;
    if (previous === "offline" && status && status !== "offline") {
      loadCommands();
      loadCapability();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device?.dev_status]);

  // ระหว่างที่ backend กำลังตรวจ ถามผลซ้ำทุก CAPABILITY_PROBE_POLL_MS พอตรวจเสร็จโหลดรายการคำสั่งใหม่
  // เพราะเมนูอาจเปลี่ยน (เมื่อเปิดการกรอง)
  const wasProbingRef = useRef(false);
  useEffect(() => {
    const probing = Boolean(capability?.probing);
    const finished = wasProbingRef.current && !probing;
    wasProbingRef.current = probing;
    if (finished) loadCommands();
    if (!probing) return undefined;
    const timer = setTimeout(loadCapability, CAPABILITY_PROBE_POLL_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [capability]);

  // dependency ใช้ Boolean(device) แทน device ตรงๆ โดยตั้งใจ - ตอนนี้ device
  // poll ใหม่ทุก 10 วิ (ดู effect ด้านบน) กลายเป็น object reference ใหม่ทุกรอบ
  // ถ้า deps เป็น device ตรงๆ effect นี้จะยิง GET /devices/{id}/commands ซ้ำทุก
  // 10 วิโดยไม่จำเป็น (schema คำสั่งของอุปกรณ์ไม่ได้เปลี่ยนบ่อยขนาดนั้น) -
  // Boolean(device) เปลี่ยนแค่ตอน null -> object ครั้งแรกเท่านั้น (คงที่ true
  // ตลอดไปหลังจากนั้นไม่ว่า device จะ poll ใหม่กี่รอบ)

  const configCommands = commands.filter((cmd) => !cmd.name.startsWith("get_"));
  // get_* ไม่ต้องมีฟอร์ม (ไม่มี parameter ให้กรอกอยู่แล้ว) กดปุ่มแล้วดึงผลมาโชว์
  // เลยทันที ต่างจาก config command ที่ต้องเลือกก่อนแล้วค่อยกรอกฟอร์ม
  const activeConfigCommand = configCommands.find((cmd) => cmd.name === selectedCommand) || null;
  // เมนู sidebar (MENU/active) เลือกอะไรอยู่ -> หาไฟล์คำสั่งที่ผูกไว้ใน
  // COMMAND_COMPONENTS ให้ตรงกัน ยังไม่ได้ผูกไฟล์ = ไม่ render อะไร (undefined)
  const ActiveCommandComponent = COMMAND_COMPONENTS[active] || null;

  // กรองเมนูตามคำสั่งที่อุปกรณ์ตัวนี้ทำได้จริง (ดู comment ยาวที่ MENU ด้านบน)
  //
  // **ต้องปล่อยผ่านทั้งหมดถ้ายังไม่รู้ความสามารถ** - `commands` เริ่มต้นเป็น []
  // (ยังโหลดไม่เสร็จ) ถ้ากรองทันทีเมนูจะว่างเปล่าทุกครั้งที่เปิดหน้าแล้วค่อยเด้ง
  // ขึ้นมา ส่วน commandsError คือ "โหลดรายการคำสั่งไม่สำเร็จ" ซึ่งแปลว่าเราไม่รู้
  // ความสามารถของอุปกรณ์ ไม่ใช่แปลว่าอุปกรณ์ทำอะไรไม่ได้ - ทั้ง 2 กรณีต้องโชว์
  // ทุกอย่างไว้ก่อน ไม่ใช่ซ่อนหมด
  const capabilityKnown = commands.length > 0 && !commandsError;
  const availableCommands = useMemo(
    () => new Set(commands.map((cmd) => cmd.name)),
    [commands]
  );
  const capabilityContext = useMemo(
    () => ({ hiddenCommands: hiddenCommandsFrom(capability), hiddenOptions: hiddenOptionsFrom(capability) }),
    [capability]
  );
  const deviceVendor = device?.dev_vendor;
  const platformRole = capability?.platform_role || null;

  // Cisco/Huawei: ทุกคำสั่งของระบบแก้แค่ running-config - รีบูตก่อน save ค่าที่ตั้งผ่านเว็บหายหมด
  // ปุ่มนี้สั่ง save_running_config (cisco-ia:save-config = write memory) ให้ผู้ใช้กดเองเมื่อ
  // ตั้งค่าเสร็จ ไม่ save อัตโนมัติทุกคำสั่ง (ไม่เพิ่มเวลาทุกคำสั่ง และไม่บันทึก config กลางทาง)
  // ซ่อนเมื่ออุปกรณ์ไม่มี cisco-ia (capability ตัดสิน) หรืออยู่โหมดอ่านอย่างเดียว (offline)
  const [savingConfig, setSavingConfig] = useState(false);
  const [saveConfigResult, setSaveConfigResult] = useState(null); // {ok, message, at}
  // true = มีคำสั่งเขียนสำเร็จหลังการ save ครั้งล่าสุด (ปุ่มเป็นสีหลัก + จุดเหลืองกระพริบ)
  // false/null = ปกติ (ปุ่ม ghost) · ค่าตั้งต้นอ่านจาก backend (Redis) แล้วอัปเดตทันทีจาก event
  // device:config-written ที่ api_devices.js ยิงหลังคำสั่งเขียนสำเร็จทุกครั้ง
  const [configUnsaved, setConfigUnsaved] = useState(null);

  useEffect(() => {
    if (!SAVE_CONFIG_VENDORS.has(deviceVendor)) {
      setConfigUnsaved(null);
      return undefined;
    }
    let cancelled = false;
    getConfigSaveStatus(devId)
      .then((res) => { if (!cancelled && res?.supported) setConfigUnsaved(res.unsaved); })
      .catch(() => {});
    function handleWritten(event) {
      if (event.detail?.devId !== devId) return;
      setConfigUnsaved(event.detail.command !== "save_running_config");
    }
    window.addEventListener("device:config-written", handleWritten);
    return () => {
      cancelled = true;
      window.removeEventListener("device:config-written", handleWritten);
    };
  }, [devId, deviceVendor]);
  // Huawei อยู่สถานการณ์เดียวกัน (commit เขียนแค่ running) - save ด้วย copy-config ->
  // startup ส่วน Juniper ไม่ต้องมีปุ่ม เพราะ commit ของ Junos บันทึกถาวรอยู่แล้ว
  const canSaveConfig = SAVE_CONFIG_VENDORS.has(deviceVendor)
    && (!capabilityKnown || availableCommands.has("save_running_config"))
    && !capabilityContext.hiddenCommands.has("save_running_config");

  async function handleSaveConfig() {
    if (savingConfig) return;
    setSavingConfig(true);
    setSaveConfigResult(null);
    try {
      await runDeviceCommand(devId, "save_running_config", {});
      setSaveConfigResult({ ok: true, at: new Date() });
      setConfigUnsaved(false);
    } catch (err) {
      const detail = err?.detail;
      const message = (detail && typeof detail === "object" ? detail.message : detail) || "Failed to save configuration";
      setSaveConfigResult({ ok: false, message });
    } finally {
      setSavingConfig(false);
    }
  }

  // Cisco switch ต้องรู้สถานะ global routing ตั้งแต่เปิดหน้า เพราะค่านี้ควบคุม
  // ทั้ง Routing Status และเมนู Route ไม่ใช่แค่ Default-Gateway ภายในกลุ่ม Route
  // หลัง toggle สำเร็จ IPRouting ส่งค่ากลับผ่าน onRoutingStateChange โดยตรง
  useEffect(() => {
    if (deviceVendor !== "cisco" || platformRole !== "switch") {
      if (platformRole !== "switch") setIpRoutingEnabled(null);
      return undefined;
    }
    setIpRoutingEnabled(null);
    let cancelled = false;
    let retryTimer;
    let attempts = 0;
    async function loadIpRouting() {
      try {
        const response = await runDeviceCommand(devId, "get_ip_routing", {});
        const enabled = response?.normalized ? parseIpRouting(response.result) : null;
        if (!cancelled) setIpRoutingEnabled(enabled);
      } catch {
        attempts += 1;
        if (!cancelled && attempts < 3) retryTimer = setTimeout(loadIpRouting, 750);
      }
    }
    loadIpRouting();
    return () => {
      cancelled = true;
      clearTimeout(retryTimer);
    };
  }, [devId, deviceVendor, platformRole]);

  const visibleMenu = useMemo(() => {
    // รู้ vendor ทันทีหลัง getDevice สำเร็จ จึงซ่อน unsupportedVendors ได้เลยแม้
    // commands ยังโหลดอยู่/ล้มเหลว ต่างจาก requires ที่ต้องปล่อยผ่านจนรู้ความสามารถ
    const supportsItem = (item) => (
      !(item.unsupportedVendors || []).includes(deviceVendor)
      && showCiscoRouteModeItem(
        item.name,
        deviceVendor,
        platformRole,
        ipRoutingEnabled,
        item.requiresIpRouting,
      )
    );
    const menuForVendor = MENU.map((group) => ({
      ...group,
      items: group.items.filter(supportsItem),
    }));
    if (!capabilityKnown) return menuForVendor.filter((group) => group.items.length > 0);
    return menuForVendor
      .map((group) => ({
        ...group,
        items: group.items.filter(
          (item) => item.requires.length === 0 || item.requires.some((cmd) => availableCommands.has(cmd))
        ),
      }))
      // กลุ่มที่ไม่เหลือรายการเลยไม่ต้องโชว์หัวข้อกลุ่มค้างไว้ให้กดแล้วว่างเปล่า
      .filter((group) => group.items.length > 0);
  }, [capabilityKnown, availableCommands, deviceVendor, platformRole, ipRoutingEnabled]);

  // ถ้าแท็บที่เปิดค้างอยู่ถูกกรองหายไป (ทั้งตอนรู้ vendor และตอนเพิ่งโหลด
  // ความสามารถเสร็จ) ให้เด้งไปรายการแรกที่เหลือแทนการปล่อยจอว่าง
  useEffect(() => {
    if (!active) return;
    const stillVisible = visibleMenu.some((group) => group.items.some((item) => item.name === active));
    if (stillVisible) return;
    const firstGroup = visibleMenu[0];
    if (!firstGroup) return;
    setOpenGroup(firstGroup.id);
    setActive(firstGroup.items[0].name);
  }, [capabilityKnown, visibleMenu, active]);

  async function runCommand(name, parameters) {
    setSelectedCommand(name);
    setSubmitting(true);
    setCommandError("");
    setCommandResult(null);
    try {
      setCommandResult(await runDeviceCommand(devId, name, parameters));
    } catch (err) {
      setCommandError(err.detail || "Failed to execute command");
    } finally {
      setSubmitting(false);
    }
  }

  function handleSubmitConfigCommand(parameters) {
    runCommand(selectedCommand, parameters);
  }

  return (
    <div className="app-shell">
      <TopBar />
      {readOnlyHistoryMode && (
        <div className="offline-readonly-banner">
          ⚠️ Device is offline — running in read-only mode (Command History only)
        </div>
      )}
      <main className="main-content">
        <div className="page-header">
          <h1>{device?.dev_name}</h1>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap" }}>
            {canSaveConfig && !readOnlyHistoryMode && (
              <>
                {saveConfigResult?.ok && (
                  <span className="save-config-status" role="status">
                    Saved to startup-config at {saveConfigResult.at.toLocaleTimeString()}
                  </span>
                )}
                <button
                  type="button"
                  className={`btn ${configUnsaved ? "btn-primary" : "btn-ghost"} save-config-btn`}
                  onClick={handleSaveConfig}
                  disabled={savingConfig}
                  title={configUnsaved
                    ? "There are changes not saved to startup-config yet - they are lost if the device reboots"
                    : "Copy running-config to startup-config (write memory) so the settings survive a reboot"}
                >
                  {configUnsaved && <span className="unsaved-dot" aria-hidden="true" />}
                  {savingConfig ? "Saving..." : "Save Configuration"}
                  {configUnsaved && <span className="visually-hidden"> (unsaved changes)</span>}
                </button>
              </>
            )}
            <button type="button" className="btn btn-primary" onClick={handleBackToDevices}>
              &larr; Back to Devices
            </button>
          </div>
        </div>

        
        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
        {saveConfigResult && !saveConfigResult.ok && (
          <DismissibleError message={saveConfigResult.message} onDismiss={() => setSaveConfigResult(null)} />
        )}

        {!device && !error && <div className="center-loading">Loading...</div>}

        {device && (
          <>
            <div className="mobile-config-bar">
              <button
                type="button"
                className="mobile-burger-btn"
                onClick={() => setMobileMenuOpen((prev) => !prev)}
                aria-label="Toggle Configuration Menu"
                aria-expanded={mobileMenuOpen}
                aria-controls="device-commands-container"
              >
                &#9776; Configuration
              </button>
            </div>

            <div className="device-panel-controls">
              {mobileMenuOpen && (
                <div
                  className="mobile-menu-overlay"
                  onClick={() => setMobileMenuOpen(false)}
                />
              )}
              <div
                className={`detail-panel ${mobileMenuOpen ? "mobile-drawer-open" : ""}`}
                id="device-commands-container"
              >
                <div className="drawer-header-mobile">
                  <h2>Configuration</h2>
                  <button
                    type="button"
                    className="drawer-close-btn"
                    onClick={() => setMobileMenuOpen(false)}
                    aria-label="Close menu"
                  >
                    &times;
                  </button>
                </div>
                <div className="commands-group-container">
                  {visibleMenu.map((group) => {
                    const isOpen = openGroup === group.id;
                    return (
                      <div key={group.id} className={`group ${isOpen ? "open" : ""}`}>
                        <div className="group-header" onClick={() => toggle(group.id)}>
                          {group.label}
                          <span className="arrow">›</span>
                        </div>
                        <div className="submenu">
                          {group.items.map(({ name: item }) => {
                            const isLocked = readOnlyHistoryMode && item !== "History" && item !== "Access Log";
                            return (
                              <a
                                key={item}
                                className={`submenu-item ${active === item ? "active" : ""} ${
                                  isLocked ? "submenu-item-locked" : ""
                                }`}
                                aria-disabled={isLocked}
                                onClick={() => {
                                  if (!isLocked) {
                                    setActive(item);
                                    setMobileMenuOpen(false);
                                  }
                                }}
                              >
                                {item}
                                {isLocked && (
                                  <span className="lock-icon" aria-hidden="true">
                                    {" "}
                                    🔒
                                  </span>
                                )}
                              </a>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {commandsError && <DismissibleError message={commandsError} onDismiss={() => setCommandsError("")} />}
              </div>

              <div className="detail-panel" id="device-get-results">
                {/* user ขอ (2026-08-06): เดิมบล็อกนี้ปักหมุด MAC/Serial/IP/
                Firmware/Added/Last seen ไว้เหนือทุกแท็บตลอดเวลา (ไม่ว่าจะกด
                Interfaces/VLAN/DNS ก็ยังเห็นค้าง) - MAC/Serial เป็นข้อมูล inventory
                ของอุปกรณ์ legacy (Phase 11: อุปกรณ์ใหม่ยืนยันตัวตนด้วย One-Time Token +
                host-key fingerprint ไม่ใช้ MAC/Serial) ไม่ควรโชว์ลอยตัวทุกจอ -
                ย้าย field ทั้งหมดออกจากตรงนี้: metadata อุปกรณ์ → "Device Setting"
                (System Management), MAC/Serial → ไม่โชว์ที่ไหนเลย
                ในเว็บอีกต่อไป (ให้ผู้ใช้ไปดูจากตัวอุปกรณ์จริงเอง), IP/Added/
                Last seen → ย้ายเข้า "Basic Info" (เป็นแท็บแรกที่เห็นตอนเปิด
                จัดการอุปกรณ์อยู่แล้ว), Firmware → ไปอยู่ "Device Setting" */}
                {commandError && <DismissibleError message={commandError} onDismiss={() => setCommandError("")} />}

                {ActiveCommandComponent && (
                  <DeviceCapabilityContext.Provider value={capabilityContext}>
                    <ActiveCommandComponent
                      key={`${devId}:${active}`}
                      devId={devId}
                      vendor={device.dev_vendor}
                      model={device.dev_model}
                      device={device}
                      presentUsers={presentUsers}
                      currentUser={currentUser}
                      onRoutingStateChange={setIpRoutingEnabled}
                      onEditHostname={openHostnameModal}
                    />
                  </DeviceCapabilityContext.Provider>
                )}

                {activeConfigCommand && (
                  <div className="command-form-wrapper">
                    <DynamicCommandForm
                      key={activeConfigCommand.name}
                      command={activeConfigCommand}
                      submitting={submitting}
                      onSubmit={handleSubmitConfigCommand}
                    />
                  </div>
                )}

                {commandResult && (
                  <div className="command-output">
                    <div className="command-output-title">
                      {commandResult.command}
                      {!commandResult.normalized && " (raw XML — no normalizer available for this command)"}
                    </div>
                    <pre>
                      {typeof commandResult.result === "string"
                        ? commandResult.result
                        : JSON.stringify(commandResult.result, null, 2)}
                    </pre>
                  </div>
                )}

                {!activeConfigCommand && !commandResult && !commandError && !active && (
                  <div className="config-placeholder">Select a command above to view or configure device live</div>
                )}

                {active && !ActiveCommandComponent && (
                  <div className="config-placeholder">Menu item "{active}" has no bound command component</div>
                )}
              </div>
            </div>
          </>
        )}
      </main>

      {showHostnameModal && (
        <div className="modal-overlay" onClick={closeHostnameModal}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Change Device Hostname</h2>
              <button
                type="button"
                className="modal-close"
                onClick={closeHostnameModal}
                disabled={hostnameSaving}
                aria-label="Close"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleHostnameApply}>
              <div className="field">
                <div className="field-label-with-hint">
                  <label htmlFor="device-hostname-input">Hostname</label>
                  <span className={`field-help${hostnameError === HOSTNAME_HINT ? " field-help-invalid" : ""}`}>
                    <button
                      type="button"
                      className="field-help-trigger"
                      aria-label="Show hostname requirements"
                      aria-describedby="device-hostname-help"
                    >
                      ?
                    </button>
                    <span id="device-hostname-help" className="field-help-tooltip" role="tooltip">
                      {HOSTNAME_HINT}
                    </span>
                  </span>
                </div>
                <input
                  id="device-hostname-input"
                  type="text"
                  value={hostnameDraft}
                  onChange={(event) => {
                    setHostnameDraft(event.target.value);
                    if (hostnameError) setHostnameError("");
                  }}
                  maxLength={HOSTNAME_MAX_LENGTH}
                  autoFocus
                  required
                  disabled={hostnameSaving}
                />
              </div>

              {hostnameError && (
                <DismissibleError message={hostnameError} onDismiss={() => setHostnameError("")} />
              )}

              <div className="modal-actions">
                <button type="button" className="btn btn-ghost" onClick={closeHostnameModal} disabled={hostnameSaving}>
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={
                    hostnameSaving
                    || !hostnameDraft.trim()
                    || hostnameDraft.trim() === (device?.dev_name || "")
                  }
                >
                  {hostnameSaving ? "Applying..." : "Apply"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showOfflineModal && (
        <div className="modal-overlay">
          <div className="modal-card modal-card-offline">
            <div className="modal-header">
              <h2>⚠️ Device is Offline</h2>
            </div>
            <p>
              The device is not currently connected to the Call-home system. Real-time status and live configuration are temporarily unavailable.
            </p>
            <p>Would you like to enter Command History mode?</p>
            <div className="modal-actions">
              <button type="button" className="btn btn-ghost" onClick={handleBackToDevices}>
                ⬅️ Back to Devices
              </button>
              <button type="button" className="btn btn-primary" onClick={handleViewHistory}>
                📜 View Command History
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
