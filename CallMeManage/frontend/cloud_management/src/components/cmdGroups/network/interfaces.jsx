import DismissibleError from "../../DismissibleError";
import { Fragment, useState } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { normalizeStatus } from "../../../utils/normalizeStatus";
import { normalizeIP } from "../../../utils/normalizeIP";
import { formatInterfaceLastChange } from "../../../utils/formatInterfaceLastChange";
import { splitInterfaceName } from "../../../utils/interfaceName";
import {
  isJuniperManagementInterface,
  isJuniperSystemServiceInterface,
  isTunnelInterfaceName,
} from "../../../utils/interfaceKind.js";
import { runDeviceCommand, runDeviceTransaction } from "../../../api/api_devices";
import InterfaceFormModal, { findExistingPoolForNetwork } from "./InterfacesFormModal";
import Edit_Result from "../../commandResult/edit_command_result";
import { parseDhcpRelay, parsePools } from "./dhcp";
import { maskToPrefix } from "../../../utils/dhcpRange";
import { buildLayerLookup, displayLayer, displaySwitchportMode } from "../../../utils/interfaceLayerDisplay";
import { juniperInterfaceDeleteSteps, juniperInterfacePoolCleanup } from "../../../utils/juniperInterfaceTransaction";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

const POST_INTERFACE_COMMIT_DELAY_MS = 300;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Junos: interfaces/interface/unit/family - ตัดสิน Layer 2/3 จาก presence ของ
// family/ethernet-switching (L2, มี port-mode ตรงๆ ไม่ต้องเดา - ตรงกับที่
// apply_switchport เขียน) vs family/inet (L3) - ต่อคนละแถวต่อ unit (หนึ่ง
// physical interface มีได้หลาย unit คนละ layer/VLAN กัน ต่างจาก Cisco ที่ 1
// interface = 1 แถว) ยังไม่เคย verify กับอุปกรณ์ Juniper จริง (เขียนตาม
// โครงสร้างที่ apply_switchport/set_interface_static_ip เขียนเอง)
function classifyJuniperLayer(unit) {
  const family = unit?.family;
  if (family && Object.hasOwn(family, "ethernet-switching")) {
    const portMode = family["ethernet-switching"]?.["interface-mode"] ?? family["ethernet-switching"]?.["port-mode"];
    let mode = "-";
    if (portMode === "access") mode = "Access";
    else if (portMode === "trunk") mode = "Trunk";
    return { layer: "Layer 2", mode };
  }
  if (family && Object.hasOwn(family, "inet")) return { layer: "Layer 3", mode: "-" };
  return { layer: "Unknown", mode: "-" };
}

function parseJuniperInterfaceLayers(result) {
  const interfaces = ensureArray(result?.payload?.data?.configuration?.interfaces?.interface);
  const rows = [];
  for (const iface of interfaces) {
    if (!iface?.name) continue;
    const units = ensureArray(iface.unit);
    // เจอบั๊กจริง (user รายงาน): เปิดฟอร์ม Edit บน Juniper แล้วช่อง MTU ว่างเปล่า
    // เสมอทั้งที่ตั้งไว้แล้วจริง - InterfacesFormModal.jsx's buildInitialValues
    // อ่าน mtu จาก editTarget.layer.raw?.mtu (pattern เดียวกับ Cisco ที่ผูกไว้
    // ก่อนหน้านี้) แต่แถวของ Juniper ที่ฟังก์ชันนี้สร้างไม่เคยมี field "raw" เลย
    // สักตัว - เพิ่ม raw: iface (physical interface object ทั้งก้อนที่ parse มา
    // จาก normalize_generic แล้ว มี mtu อยู่ตรงๆ ถ้าเคยตั้งไว้ - ยืนยันจาก XML
    // shape ที่ set_interface_static_ip/set_sub_interface_ip เขียนจริง: <mtu>
    // อยู่ระดับ <interface> เดียวกับ <name> ไม่ใช่ใต้ <unit>) ให้ทุกแถวของ
    // physical interface เดียวกัน (ไม่ว่าจะกี่ unit/sub-interface) เพราะ mtu
    // เป็นคุณสมบัติร่วมของ physical port ไม่ใช่ต่อ unit
    // Junos configures traffic under logical units, but the physical parent is
    // still useful context in the UI. Keep one explicit parent row regardless
    // of whether units exist; it is rendered read-only in the main table.
    rows.push({ name: iface.name, layer: "Unknown", mode: "-", helpers: [], raw: iface, physicalParent: true });
    if (units.length === 0) continue;
    for (const unit of units) {
      const suffix = unit?.name !== undefined && unit?.name !== "" ? `.${unit.name}` : "";
      // set_dhcp_relay ฝั่ง Juniper เป็น global scope เสมอ (forwarding-options/
      // helpers/bootp - ไม่ผูกกับ interface ใดโดยเฉพาะ ตามที่ backend เขียนไว้ชัดเจน)
      // เลยไม่มี helper address ต่อ interface ให้โชว์เหมือน Cisco
      rows.push({ name: `${iface.name}${suffix}`, ...classifyJuniperLayer(unit), helpers: [], raw: iface });
    }
  }
  return rows;
}

// Cisco: backend (normalize_switchport_layer ใน response_normalizer.py) unify
// ให้แล้วเป็น [{name, layer, mode, helpers, raw}] ตรงๆ ไม่ต้อง parse client-side
// เอง - ตัดสิน Layer 2/3 จาก OpenConfig (ethernet/switched-vlan) แทน native
// switchport container ล้วนๆ แบบเดิม (ไม่มี Unknown อีกต่อไปสำหรับ Cisco - ดู
// docstring ของ normalize_switchport_layer) Juniper ยังไม่มี query แบบนี้ ต้อง
// parse client-side ต่อไปเหมือนเดิม (normalize_generic fallback)
function parseInterfaceLayers(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperInterfaceLayers(result);
    } catch {
      return null;
    }
  }
  return Array.isArray(result) ? result : null;
}

// logical interface (sub-interface/VLAN SVI) ลบทั้ง entry ได้จริง (remove_
// interface_unit) - physical interface ลบทั้ง entry ไม่ได้ (เป็น hardware port
// ที่มีอยู่ถาวร Cisco ปฏิเสธแน่นอน) แต่ **Cisco เท่านั้น** มีทางล้างแค่ IP address
// ออกกลับไปเป็นเหมือนไม่เคยตั้งค่าได้ (clear_interface_ip - ดู
// vendor_translators/cisco_iosxe.py) ใช้ตอนตั้ง static/dhcp ผิดบน physical
// interface แล้วอยากเปลี่ยนไปใช้เป็น trunk สำหรับ sub-interface ล้วนๆ - Juniper
// physical interface ยังไม่มีทางนี้ (ยังไม่ verify behavior จริงกับอุปกรณ์ Juniper -
// ไม่ใช่ scope ของบั๊กที่เจอ) เลย fallback เป็น null (ปุ่ม disabled) เหมือนเดิม
// คืน null ถ้าล้าง/ลบไม่ได้เลย (ปุ่มจะ disabled)
// Cisco Tunnel interface (Tunnel0, Tunnel1, ...) - ตั้งใจกันไว้ไม่ให้แก้/ล้าง IP
// ผ่านฟอร์มทั่วไปของหน้านี้เลย เพราะเป็นเหตุที่ทำให้เกิดบั๊กจริง (user รายงาน):
// ช่อง "Interface" ในฟอร์ม (dropdown ที่มาจาก candidateInterfaceNames ใน
// InterfacesFormModal.jsx) กรองชื่อที่ขึ้นต้นด้วย "tunnel"/"vlan" ทิ้งไปเสมอ
// (ตั้งใจกันไม่ให้เลือก Tunnel/VLAN เป็น parent port ตอนสร้าง sub-interface) -
// พอ Tunnel0 เองก็ถูกกรองออกจาก dropdown ไปด้วย ตอน Edit ค่า "Tunnel0" ที่ตั้ง
// ไว้ใน state เลยไม่ match option ไหนใน <select> เลย เบราว์เซอร์เลย fallback
// ไปโชว์ตัวเลือกแรกของ dropdown แทน (มักเป็น GigabitEthernet1) - ถ้า user กด
// Save ไปโดยไม่ทันสังเกต จะไปเขียนทับ GigabitEthernet1 แทน Tunnel0 จริง (ตรงกับ
// ที่ user อธิบาย "ไปชน int g 1") - Tunnel interface มีหน้าจัดการของตัวเองอยู่
// แล้วด้วย (VPN > Security Tunnel - security_tunnelFormModal.jsx ที่รองรับ
// Edit/Delete ถูกต้องครบผ่าน remove_tunnel_interface+create_security_tunnel)
// เลยตัดสินใจกันไม่ให้เข้าฟอร์มนี้เลยแทนที่จะพยายามแก้ dropdown ให้ครอบคลุม
// Tunnel (ฟอร์มนี้ไม่มี field สำหรับ tunnel source/destination/ipsec profile
// อยู่แล้ว ต่อให้แก้ dropdown ก็ยังใช้งานไม่ได้จริงอยู่ดี)
// แคบกว่า isTunnelInterfaceName ของ utils/interfaceKind.js โดยตั้งใจ - ตัวนี้
// ถามว่า "เป็น Tunnel ของ Cisco ไหม" (ตัวที่ต้องกันไม่ให้เข้าฟอร์มนี้) ไม่ใช่
// "เป็น tunnel ไหม" ของทุกยี่ห้อ อย่ารวมสองอันเข้าด้วยกัน
function isCiscoTunnelInterfaceName(fullName) {
  return /^Tunnel\d+$/i.test(fullName.trim());
}

// จัดกลุ่มตารางหลักตามหมวดหมู่ (แทน flat list เดิม) - เดินตามลำดับความสัมพันธ์
// ที่ user ระบุ: Physical & Sub-interfaces (parent + sub เยื้องต่อท้าย) -> VLAN/
// SVI -> Tunnel -> Loopback & Virtual - ใช้ splitInterfaceName เดิม (มีอยู่แล้ว
// ใช้กับ resolveDeleteParams) แยก type/id แทนการเขียน parser ใหม่
function classifyInterfaceCategory(fullName) {
  const { interfaceType } = splitInterfaceName(fullName);
  const type = interfaceType.toLowerCase();
  if (type === "vlan" || type === "irb") return "vlan";
  // Cisco: Tunnel0 - Juniper: gr-0/0/0 (GRE) / st0.1 (IPsec) - กฎย้ายไปไว้ที่
  // utils/interfaceKind.js แล้ว (zoneProtection.js ใช้กฎเดียวกันนี้ตัดสินว่าอะไร
  // ไม่ใช่ขา WAN จริง) รายละเอียดว่าทำไมต้องเทียบชื่อเต็มอยู่ในไฟล์นั้น
  if (isTunnelInterfaceName(fullName)) return "tunnel";
  if (type === "loopback" || type === "lo") return "loopback";
  if (isJuniperSystemServiceInterface(fullName)) return "system";
  if (isJuniperManagementInterface(fullName)) return "management";
  return "physical";
}

function isJuniperPhysicalInterface(fullName, vendor) {
  if (vendor !== "juniper" || typeof fullName !== "string" || !fullName.trim() || fullName.includes(".")) {
    return false;
  }
  // การแยก fxp0/system-service ไปคนละหมวดเป็นเรื่องการแสดงผลเท่านั้น ไม่ควร
  // เปลี่ยนสิทธิ์เดิมของ physical parent ให้กลับมา Edit/Delete ได้โดยบังเอิญ
  return ["physical", "system", "management"].includes(classifyInterfaceCategory(fullName));
}

function baseInterfaceName(fullName) {
  const dotIndex = fullName.indexOf(".");
  return dotIndex === -1 ? fullName : fullName.slice(0, dotIndex);
}

const CATEGORY_SECTIONS = [
  { key: "physical", title: "Physical & Sub-Interfaces" },
  { key: "vlan", title: "VLAN Interfaces / SVI" },
  { key: "tunnel", title: "Tunnel Interfaces" },
  { key: "loopback", title: "Loopback & Virtual Interfaces" },
  { key: "system", title: "SYSTEM SERVICE INTERFACE" },
  { key: "management", title: "MANAGEMENT INTERFACE" },
];

function groupInterfaceBriefRows(rows, vendor) {
  const buckets = { physical: [], vlan: [], tunnel: [], loopback: [], system: [], management: [] };
  rows.forEach((row) => buckets[classifyInterfaceCategory(row.name)].push(row));

  // Physical: จัดกลุ่มตาม base name (ส่วนก่อนจุด) รักษาลำดับที่เจอครั้งแรกไว้ -
  // parent (ไม่มีจุด) ขึ้นก่อนเสมอ แล้วตามด้วย sub-interface (มีจุด) ที่ทำ
  // เครื่องหมาย isSub ไว้ให้ render เยื้อง
  const physicalGroups = new Map();
  buckets.physical.forEach((row) => {
    const base = baseInterfaceName(row.name);
    if (!physicalGroups.has(base)) physicalGroups.set(base, []);
    physicalGroups.get(base).push(row);
  });
  const physicalRows = [];
  const groups = [...physicalGroups.entries()];
  if (vendor === "juniper") {
    const ethernet = (name) => /^(?:ge|fe|xe|et|mge)-\d+\/\d+\/\d+(?::\d+)?$/i.test(name);
    // Stable sort: real Ethernet ports first; preserve device order inside
    // Ethernet and non-Ethernet groups. Parent/sub-interface stay together.
    groups.sort(([left], [right]) => Number(ethernet(right)) - Number(ethernet(left)));
  }
  for (const [, groupRows] of groups) {
    const sorted = [...groupRows].sort((a, b) => Number(a.name.includes(".")) - Number(b.name.includes(".")));
    sorted.forEach((row) => physicalRows.push({ ...row, isSub: row.name.includes(".") }));
  }

  return CATEGORY_SECTIONS.map((section) => ({
    ...section,
    rows: section.key === "physical" ? physicalRows : buckets[section.key],
  })).filter((section) => section.rows.length > 0);
}

function mergeJuniperConfiguredInterfaces(briefRows, layerRows, vendor) {
  if (vendor !== "juniper" || !Array.isArray(layerRows)) return briefRows;
  const merged = [...briefRows];
  const known = new Set(briefRows.map((row) => row.name));
  for (const row of layerRows) {
    // get-interface-information may omit a configured logical unit when it has
    // no L3 address (notably an ethernet-switching access unit such as .0).
    // The running configuration is authoritative for its existence, so retain
    // every missing configured interface. Existing brief rows still win and
    // keep their real address/status/last-change values.
    if (!row?.name || known.has(row.name)) continue;
    known.add(row.name);
    merged.push({
      name: row.name,
      ip: "-",
      subnet: "-",
      oper_status: "-",
      last_change: null,
      physicalParent: true,
    });
  }
  return merged;
}

function resolveDeleteParams(fullName, vendor) {
  if (isJuniperPhysicalInterface(fullName, vendor)) return null;
  if (isCiscoTunnelInterfaceName(fullName)) return null;
  const { interfaceType, interfaceId } = splitInterfaceName(fullName);
  if (interfaceType === "Vlan" || (vendor === "huawei" && interfaceType === "Vlanif")) {
    // VRP เรียก SVI ว่า Vlanif20 และ translator รับ Vlanif โดยตรง; เดิมรู้จัก
    // แค่ Vlan ของ Cisco จึงคืน null แล้วไม่เคยยิง remove_interface_unit เลย.
    const sviType = vendor === "huawei" ? "Vlanif" : "Vlan";
    return { kind: "remove-unit", interface_type: sviType, interface_id: interfaceId, unit: Number(interfaceId) || 0 };
  }
  if (interfaceId.includes(".")) {
    const [parent, unit] = interfaceId.split(".");
    return { kind: "remove-unit", interface_type: interfaceType, interface_id: parent, unit: Number(unit) };
  }
  if (vendor === "cisco") {
    return { kind: "clear-ip", interface_type: interfaceType, interface_id: interfaceId };
  }
  // Huawei เป็นสวิตช์: สภาพ "เปล่า" ของพอร์ตจริงคือ access VLAN 1 ปุ่มจึงคืนพอร์ต
  // กลับไปสถานะนั้นไม่ว่าตอนนี้จะเป็น trunk, access VLAN อื่น หรือถูกสลับเป็น
  // Layer 3 ไปแล้ว (Vlanif ใช้เส้นทางลบด้านบนตามเดิม)
  // Juniper ตั้งค่าบน sub-interface เสมอ ไม่ได้ใช้ physical interface ทำงานจริง
  // จึงไม่มีอะไรให้รีเซ็ต คืน null ให้ปุ่ม disabled ตามเดิม
  if (vendor === "huawei") {
    return { kind: "reset-switchport", interface_type: interfaceType, interface_id: interfaceId };
  }
  return null;
}

// เจอบั๊กจริง: resolveDeleteParams(name, vendor) เดิมใช้ layerData?.result?.vendor
// เป็นแหล่งที่มาของ vendor - ใช้ได้แค่กับ Juniper เท่านั้น เพราะ
// get_switchport_information ของ Juniper fallback ไป normalize_generic (คืน
// {vendor, payload}) แต่ของ Cisco ใช้ normalize_switchport_layer เฉพาะทาง (คืน
// array เปล่าๆ [{name, layer, mode, ...}] ไม่มี key "vendor" เลย) - ผลคือ
// layerData.result.vendor เป็น undefined เสมอสำหรับ Cisco ทำให้เงื่อนไข
// `vendor === "cisco"` ใน resolveDeleteParams ไม่ true ไม่ว่ากรณีไหน ปุ่ม "Clear
// IP" เลย disabled อยู่ตลอด (คนละดูไม่ออกว่ามีปุ่มอยู่ เพราะโชว์ "Delete" เฉยๆ
// แบบ disabled) - DeviceDetail.jsx ส่ง `vendor={device.dev_vendor}` (มาจาก DB
// ตรงๆ ผ่าน dev_vendor เชื่อถือได้เสมอ) เข้ามาให้ทุก cmdGroup component อยู่แล้ว
// (ดู COMMAND_COMPONENTS[active] render) แค่ไฟล์นี้ไม่เคยรับ prop นี้ไว้ใช้เลย -
// รับมาใช้แทน layerData?.result?.vendor เฉพาะจุดที่ต้องแยก Cisco/Juniper แบบ
// สมมาตร (จุดอื่นที่เช็คแค่ === "juniper" อยู่แล้วยังทำงานถูกต้องปกติ ไม่ต้องแก้)
export default function Interfaces({ devId, vendor, model }) {
  const isHuawei = vendor === "huawei";
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_ip_interface_brief");
  const {
    data: layerData,
    loading: layerLoading,
    error: layerError,
    clearError: clearLayerError,
    refetch: refetchLayers,
  } = getDeviceInformation(devId, "get_switchport_information");
  // ใช้แค่ตอนลบ interface - หา DHCP local-server binding/relay ที่ยังผูกกับ
  // interface ที่กำลังจะลบอยู่ (ดู handleConfirmDelete) เพื่อเคลียร์ทิ้งไปด้วย
  // ไม่งั้น config จะอ้างอิง interface ที่ไม่มีตัวตนแล้วค้างอยู่ตลอดไป (เจอจริง:
  // ลบ ge-0/0/2.10 ทิ้งแล้ว dhcp-local-server group ยังอ้างอิงชื่อเดิมค้างอยู่)
  // Huawei ไม่มี DHCP ผ่าน NETCONF จึงไม่ fetch pool ที่อุปกรณ์ไม่รองรับตั้งแต่ต้น
  // hook ยังถูกเรียกทุก render ตามกฎ React แต่ auto=false ปิด RPC เฉพาะ Huawei
  const { data: dhcpData, refetch: refetchDhcp } = getDeviceInformation(
    devId,
    "get_dhcp_pool_information",
    { auto: !isHuawei }
  );
  const [showForm, setShowForm] = useState(false);
  const [formMode, setFormMode] = useState("create"); // create | edit
  const [selectedName, setSelectedName] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  function handleSaved() {
    setShowForm(false);
    setSelectedName(null);
    refetch();
    refetchLayers();
  }

  function handleRefresh() {
    refetch();
    refetchLayers();
    // Huawei ไม่มี DHCP ผ่าน NETCONF จึงไม่ refetch คำสั่งที่อุปกรณ์ไม่รองรับ
    if (!isHuawei) refetchDhcp();
  }

  function handleRowClick(name) {
    setSelectedName((prev) => (prev === name ? null : name));
  }

  function handleEditClick() {
    if (!selectedName || isCiscoTunnelInterfaceName(selectedName) || isJuniperPhysicalInterface(selectedName, vendor)) return;
    setFormMode("edit");
    setShowForm(true);
  }

  // ลบ DHCP relay ที่ผูกกับ interface นี้ (ทั้ง Cisco's ip helper-address และ Juniper's
  // forwarding-options dhcp-relay) - ทำทั้งตอนลบ interface (remove-unit) และตอนล้าง IP
  // physical interface (clear-ip) ตามคำสั่งของผู้ใช้ เพื่อไม่ให้ relay config ค้างสะสม
  async function cleanupDhcpRelayFor(targetName, params) {
    // Huawei ไม่มี DHCP relay ผ่าน NETCONF จึงข้ามทั้งการอ่านและลบ ไม่ให้ RPC/ประวัติรก
    if (isHuawei) return;
    if (!targetName || !params) return;

    let currentLayerResult = layerData?.normalized ? layerData.result : null;
    let currentDhcpResult = dhcpData?.normalized ? dhcpData.result : null;

    // ถ้ายังไม่มี switchport data (สำหรับ Cisco helper-address) ให้ fetch สด
    if (!currentLayerResult && vendor === "cisco") {
      try {
        await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
        const res = await runDeviceCommand(devId, "get_switchport_information", {}, { allowFailure: true });
        if (res?.normalized) currentLayerResult = res.result;
      } catch (err) {
        console.warn("ดึงข้อมูล switchport สดสำหรับ cleanup DHCP relay ไม่สำเร็จ:", err);
      }
    }
    // ถ้ายังไม่มี DHCP data (สำหรับ Juniper relay) ให้ fetch สด
    if (!currentDhcpResult && vendor === "juniper") {
      try {
        await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
        const res = await runDeviceCommand(devId, "get_dhcp_pool_information", {}, { allowFailure: true });
        if (res?.normalized) currentDhcpResult = res.result;
      } catch (err) {
        console.warn("ดึงข้อมูล DHCP pool สดสำหรับ cleanup DHCP relay ไม่สำเร็จ:", err);
      }
    }

    const relayRows = parseDhcpRelay(currentDhcpResult, currentLayerResult) || [];
    let orphanedRelays = relayRows.filter((row) => row.interface === targetName);
    // กรณี Cisco: เสริม helper IP จาก layerData โดยตรงเผื่อ parseDhcpRelay ตกหล่น
    if (vendor === "cisco" && orphanedRelays.length === 0 && Array.isArray(currentLayerResult)) {
      const matchRow = currentLayerResult.find((r) => r.name === targetName);
      if (matchRow?.helpers && matchRow.helpers.length > 0) {
        orphanedRelays = matchRow.helpers.map((hip) => ({ interface: targetName, server: hip }));
      }
    }
    for (const relay of orphanedRelays) {
      try {
        await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
        await runDeviceCommand(devId, "remove_dhcp_relay", {
          interface_type: params.interface_type,
          interface_id: params.interface_id,
          ...(params.interface_type !== "Vlan" && vendor === "juniper" ? { unit: params.unit } : {}),
          helper_ip: relay.server,
        }, { allowFailure: true });
      } catch (cleanupErr) {
        console.error("remove_dhcp_relay cleanup failed:", cleanupErr);
      }
    }
  }

  // ลบ DHCP pool ที่ subnet ตรงกับ interface ที่กำลังจะลบ/ล้าง IP ทิ้ง - pool ผูก
  // กับ interface ทางอ้อมผ่าน subnet เท่านั้น (ไม่มี direct binding แบบ relay/
  // dhcp-local-server) เลยต้อง match เอง (ใช้ findExistingPoolForNetwork ตัวเดียว
  // กับที่ InterfacesFormModal ใช้ตอน prefill toggle ตอน Edit)
  // หากข้อมูล dhcpData ใน state ยังไม่โหลดหรือ stale จะดึงข้อมูลสดจากอุปกรณ์ทันที
  // และมี fallback retry กรณีลบแบบส่ง exclude แล้วอุปกรณ์ฟ้อง error (data-missing)
  // หา pool ที่ผูกกับวงของ interface นี้ โดยยังไม่ยิงคำสั่งลบ - ใช้ตอนรวมการลบ pool
  // เข้าไปใน clear_interface_ip ให้เป็น RPC เดียว คืน null เมื่อหาไม่เจอหรืออ่านไม่ได้
  async function findDhcpPoolFor(brief) {
    if (isHuawei || !brief?.ip) return null;
    let prefix = null;
    let ipOnly = brief.ip;
    if (brief.ip.includes("/")) {
      const [cleanIp, prefixStr] = brief.ip.split("/");
      ipOnly = cleanIp;
      prefix = Number(prefixStr);
    } else if (brief.subnet) {
      prefix = maskToPrefix(brief.subnet);
    }
    if (prefix === null || !Number.isInteger(prefix)) return null;

    let currentDhcpResult = dhcpData?.normalized ? dhcpData.result : null;
    if (vendor === "cisco") {
      const latest = await runDeviceCommand(devId, "get_dhcp_pool_information", {});
      if (!latest?.normalized || !Array.isArray(parsePools(latest.result))) {
        throw new Error("Failed to read latest DHCP pools; interface delete/reset aborted");
      }
      currentDhcpResult = latest.result;
    }
    if (!currentDhcpResult) {
      try {
        const res = await runDeviceCommand(devId, "get_dhcp_pool_information", {}, { allowFailure: true });
        if (res?.normalized) currentDhcpResult = res.result;
      } catch (err) {
        console.warn("ดึงข้อมูล DHCP pool ก่อน reset ไม่สำเร็จ:", err);
      }
    }
    if (!currentDhcpResult) return null;
    return findExistingPoolForNetwork(parsePools(currentDhcpResult) || [], ipOnly, prefix) || null;
  }

  async function cleanupDhcpPoolFor(brief) {
    // Huawei ไม่มี DHCP pool ผ่าน NETCONF จึงข้ามทั้งการอ่านและลบ ไม่ให้ RPC/ประวัติรก
    if (isHuawei) return;
    if (!brief?.ip) return;
    let prefix = null;
    let ipOnly = brief.ip;
    if (brief.ip.includes("/")) {
      const [cleanIp, prefixStr] = brief.ip.split("/");
      ipOnly = cleanIp;
      prefix = Number(prefixStr);
    } else if (brief.subnet) {
      prefix = maskToPrefix(brief.subnet);
    }
    if (prefix === null || !Number.isInteger(prefix)) return;

    let currentDhcpResult = dhcpData?.normalized ? dhcpData.result : null;
    if (!currentDhcpResult) {
      try {
        await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
        const res = await runDeviceCommand(devId, "get_dhcp_pool_information", {}, { allowFailure: true });
        if (res?.normalized) {
          currentDhcpResult = res.result;
        }
      } catch (err) {
        console.warn("ดึงข้อมูล DHCP pool สดสำหรับ cleanup ไม่สำเร็จ:", err);
      }
    }
    if (!currentDhcpResult) return;

    const pools = parsePools(currentDhcpResult) || [];
    const pool = findExistingPoolForNetwork(pools, ipOnly, prefix);
    if (!pool) return;

    try {
      await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
      const res = await runDeviceCommand(devId, "remove_dhcp_pool", {
        name: pool.name,
        network: pool.network,
        exclude: pool.excludeRanges,
      }, { allowFailure: true });
      // หากอุปกรณ์ reject เช่น Cisco data-missing จาก exclude เก่าที่ไม่ตรง ให้ retry ลบเฉพาะ pool
      if (res?.result?.ok === false) {
        await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
        await runDeviceCommand(devId, "remove_dhcp_pool", {
          name: pool.name,
          network: pool.network,
        }, { allowFailure: true });
      }
    } catch (cleanupErr) {
      try {
        await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
        await runDeviceCommand(devId, "remove_dhcp_pool", {
          name: pool.name,
          network: pool.network,
        }, { allowFailure: true });
      } catch (retryErr) {
        console.error("remove_dhcp_pool cleanup fallback failed:", retryErr);
      }
    }
  }

  async function handleConfirmDelete() {
    const params = resolveDeleteParams(selectedName, vendor);
    if (!params) return;
    setDeleting(true);
    setDeleteError("");
    try {
      if (vendor === "juniper") {
        const {kind: _kind, ...removeParams} = params;
        const latest = await runDeviceCommand(devId, "get_running_config", {});
        const configuration = latest?.normalized ? latest.result?.payload?.data?.configuration : null;
        const pools = juniperInterfacePoolCleanup({configuration, binding: removeParams, pools: parsePools(latest.result)});
        const commands = juniperInterfaceDeleteSteps({configuration, params: removeParams, pools});
        await runDeviceTransaction(devId, commands);
        setShowDeleteConfirm(false);
        setSelectedName(null);
        handleRefresh();
        return;
      }
      // physical interface (Huawei) - คืนพอร์ตเป็น access VLAN 1
      //
      // พอร์ต Layer 3 ต้องล้างค่า IFM ที่ไม่ใช่ default ทั้งหมดที่ระบบจัดการก่อน
      // เปิด l2Enable ไม่ใช่แค่ IP ตัวแรก ไม่งั้น CE12800 ตอบ "Please delete the
      // existing non-default configurations on the interface first". ใช้ cleanup
      // เดียวกับฟอร์ม Edit แล้วคืน description/admin status ในคำสั่งสุดท้าย ทั้งชุด
      // อยู่ใน candidate เดียวและ commit ครั้งเดียว จึงสำเร็จทั้งหมดหรือไม่เกิดอะไรเลย
      if (params.kind === "reset-switchport") {
        const isLayer3Now = selectedLayer?.layer === "Layer 3";
        const currentIp = (selectedBrief?.ip || "").split("/")[0].trim();
        const previousAddresses = [...new Set([
          ...(Array.isArray(selectedBrief?.addresses) ? selectedBrief.addresses : []),
          ...(currentIp && currentIp !== "-" ? [currentIp] : []),
        ].filter(Boolean))];
        const adminStatus = String(selectedBrief?.admin_status || "").toLowerCase();
        const description = String(selectedBrief?.description || "").trim();
        const steps = [];
        if (isLayer3Now) {
          const resetParameters = {
            interface_type: params.interface_type,
            interface_id: params.interface_id,
            previous_addresses: previousAddresses,
            reset_description: Boolean(description),
            reset_mtu: Boolean(selectedBrief?.mtu),
            reset_admin_status: Boolean(adminStatus),
          };
          if (previousAddresses.length || resetParameters.reset_description
              || resetParameters.reset_mtu || resetParameters.reset_admin_status) {
            steps.push({command: "prepare_interface_for_l2", parameters: resetParameters});
          }
          steps.push({
            command: "set_switchport",
            parameters: {
              interface_type: params.interface_type,
              interface_id: params.interface_id,
              switchport: true,
            },
          });
        }
        steps.push({
          command: "apply_interface_to_vlan",
          parameters: {
            interface_type: params.interface_type,
            interface_id: params.interface_id,
            mode: "access",
            vlan_id: 1,
            ...(description ? {description} : {}),
            ...(adminStatus ? {shutdown: !adminStatus.includes("up")} : {}),
          },
        });

        // พอร์ตที่เป็น Layer 2 อยู่แล้วเหลือขั้นเดียว ไม่ต้องใช้ชุดคำสั่งให้เปลือง
        if (steps.length === 1) {
          await runDeviceCommand(devId, steps[0].command, steps[0].parameters);
        } else {
          await runDeviceTransaction(devId, steps);
        }
        setShowDeleteConfirm(false);
        setSelectedName(null);
        handleRefresh();
        return;
      }

      // Cisco ที่เป็นสวิตช์ - คืนพอร์ตเป็น access VLAN 1 ในคำสั่งเดียว
      //
      // apply_interface_to_vlan ของ Cisco เขียน switchport-conf=true, ลบ <ip> เดิม
      // และตั้ง mode/VLAN ไว้ใน edit-config เดียวกัน จึงจบใน RPC เดียวและ atomic จาก
      // rollback-on-error ไม่ต้องตามล้าง DHCP เพราะพอร์ตกลับเป็น Layer 2 ที่ไม่มี IP
      // ให้ pool ผูกอยู่แล้ว
      //
      // ตัดสินจาก switchport_capable ที่ normalizer อ่านจากอุปกรณ์จริง (สวิตช์มี leaf
      // switchport ของ OpenConfig ทุกพอร์ต ส่วน router ไม่มีเลย) ไม่ได้เดาจากชื่อพอร์ต
      // พอร์ตของ router จึงตกไปใช้เส้นทางล้าง IP เดิมด้านล่างครบทุกขั้นตามเดิม
      if (params.kind === "clear-ip" && ciscoPortIsSwitchCapable) {
        const pool = await findDhcpPoolFor(selectedBrief);
        const commands = [{command: "apply_interface_to_vlan", parameters: {
          interface_type: params.interface_type,
          interface_id: params.interface_id,
          mode: "access",
          vlan_id: 1,
          switchport: true,
        }}];
        if (pool) commands.push({command: "remove_dhcp_pool", parameters: {
          name: pool.name, network: pool.network, exclude: pool.excludeRanges ?? pool.exclude,
        }});
        await runDeviceTransaction(devId, commands);
        setShowDeleteConfirm(false);
        setSelectedName(null);
        handleRefresh();
        return;
      }

      // physical interface (Cisco router) - ล้าง IP address ออก
      // พร้อม cleanup ทั้ง DHCP relay และ DHCP pool ที่ผูกอยู่กับ interface นี้ออกไปด้วย
      if (params.kind === "clear-ip") {
        // หา helper-address ทั้งหมดที่ผูกกับ interface นี้เพื่อลบพร้อมกันแบบ atomic 1-RPC บน Cisco
        const knownHelpers = selectedLayer?.helpers && selectedLayer.helpers.length > 0
          ? selectedLayer.helpers
          : (Array.isArray(layerData?.result)
              ? layerData.result.find((r) => r.name === selectedName)?.helpers || []
              : []);

        // Huawei: `am4CfgAddr` มี key เป็น ifIpAddr จึงต้องบอกว่าจะลบ IP ตัวไหน
        // ไม่งั้นอุปกรณ์ตอบ "Missing element: ifIpAddr" - Cisco/Juniper ไม่รับ
        // พารามิเตอร์นี้จึงส่งเฉพาะ Huawei
        const currentIp = (selectedBrief?.ip || "").split("/")[0].trim();

        // Cisco: pool ที่ผูกกับวงของ interface นี้ลบไปพร้อมกันใน edit-config เดียวได้
        // เพราะอยู่ใต้ <native> เดียวกัน จึงหาไว้ก่อนแล้วส่งไปกับคำสั่งเดียว ทำให้
        // การกด Reset เป็น RPC เดียวและ atomic ส่วน helper-address ก็อยู่ในคำสั่ง
        // เดียวกันอยู่แล้วผ่าน helper_ips
        const poolToRemove = vendor === "cisco" ? await findDhcpPoolFor(selectedBrief) : null;

        const resetParams = {
          interface_type: params.interface_type,
          interface_id: params.interface_id,
          ...(knownHelpers.length > 0 ? { helper_ips: knownHelpers } : {}),
          ...(vendor === "huawei" && currentIp && currentIp !== "-" ? { ip: currentIp } : {}),
          ...(poolToRemove
            ? {
              dhcp_pool_name: poolToRemove.name,
              ...(poolToRemove.excludeRanges && poolToRemove.excludeRanges.length > 0
                ? { dhcp_pool_exclude: poolToRemove.excludeRanges }
                : {}),
            }
            : {}),
        };
        if (vendor === "cisco") await runDeviceTransaction(devId, [{command: "clear_interface_ip", parameters: resetParams}]);
        else await runDeviceCommand(devId, "clear_interface_ip", resetParams);
        // Juniper ยังต้องเก็บกวาดแยกเพราะ relay/pool อยู่คนละ subtree ที่รวมใน
        // edit-config เดียวกับ interface ไม่ได้ ส่วน Cisco จบไปกับคำสั่งข้างบนแล้ว
        if (vendor !== "cisco") {
          await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
          await cleanupDhcpRelayFor(selectedName, params);
          await cleanupDhcpPoolFor(selectedBrief);
        }
        setShowDeleteConfirm(false);
        setSelectedName(null);
        handleRefresh();
        return;
      }

      // เจอบั๊กจริง (user รายงาน): params ตอนนี้มี key "kind" ปนอยู่ด้วย (เพิ่มมา
      // ตอนทำ clear-ip แยกจาก remove-unit) ถ้าส่ง params ทั้งก้อนตรงๆ เป็น
      // parameters ของคำสั่งจะหลุดเข้าไปเป็น keyword argument "kind" ที่
      // remove_interface_unit() ไม่รู้จักเลย - พัง TypeError 500 ทุกครั้ง (ยืนยัน
      // จาก logs/api.log จริง) ต้องแยก kind ออกก่อนส่งเสมอ
      const { kind: _kind, ...removeParams } = params;
      if (vendor === "cisco") {
        const pool = await findDhcpPoolFor(selectedBrief);
        const commands = [{command: "remove_interface_unit", parameters: removeParams}];
        // Removing the interface also removes its helper-address children.
        if (pool) commands.push({command: "remove_dhcp_pool", parameters: {
          name: pool.name, network: pool.network, exclude: pool.excludeRanges ?? pool.exclude,
        }});
        await runDeviceTransaction(devId, commands);
        setShowDeleteConfirm(false);
        setSelectedName(null);
        handleRefresh();
        return;
      }
      await runDeviceCommand(devId, "remove_interface_unit", removeParams);
      // Juniper เท่านั้น: set_sub_interface_ip เปิด <vlan-tagging/> ไว้บน parent
      // physical port ทุกครั้งที่สร้าง sub-interface (unit != 0) - ถ้าตัวที่เพิ่งลบ
      // ไปเป็น sub-interface ตัวสุดท้ายที่เหลืออยู่บน parent port นี้ (เช็คจาก rows
      // ก่อนลบ - รายการอื่นที่ขึ้นต้นด้วย "<parent>." เหมือนกัน) ต้องลบ
      // vlan-tagging ทิ้งด้วย ไม่งั้น port จะติดค้างเปิด vlan-tagging ตลอดไป ใช้เป็น
      // Interface ธรรมดา/L2 switchport ต่อไม่ได้อีกเลย (ยืนยันจริง: Junos ปฏิเสธ
      // "VLAN-ID must be specified on tagged ethernet interfaces" ทันทีที่ลองตั้ง
      // unit 0 บน port ที่ vlan-tagging ค้างอยู่ - เจอจริงจากการทดสอบในเซสชันนี้)
      if (
        layerData?.result?.vendor === "juniper" &&
        params.interface_type !== "Vlan" &&
        params.unit !== 0
      ) {
        // หน่วย .32767 เป็น phantom unit ที่ Junos auto-generate เองทันทีที่
        // vlan-tagging เปิดอยู่บน interface (ไม่ว่าจะมี unit อื่นจริงหรือไม่ก็ตาม)
        // ต้องกันออกจากการนับ "sibling" ไม่งั้นจะเข้าใจผิดว่ายังมี sub-interface
        // อื่นเหลืออยู่เสมอ (เจอ debug จริง: ลบ unit สุดท้ายไปแล้ว rows ยังมี
        // "<parent>.32767" ค้างเป็น false positive ทำให้ไม่ยอม cleanup vlan-tagging
        // ทั้งที่ควรจะทำ)
        const parentPrefix = `${params.interface_type}${params.interface_id}.`;
        const hasOtherSiblingUnit = rows.some(
          (row) =>
            row.name !== selectedName &&
            row.name.startsWith(parentPrefix) &&
            !row.name.endsWith(".32767")
        );
        if (!hasOtherSiblingUnit) {
          try {
            await runDeviceCommand(devId, "remove_vlan_tagging", {
              interface_type: params.interface_type,
              interface_id: params.interface_id,
            }, { allowFailure: true });
          } catch (cleanupErr) {
            console.error("remove_vlan_tagging cleanup after last sub-interface delete failed:", cleanupErr);
          }
        }
      }
      // ลบ interface นี้ไปแล้ว = ไม่มีตัวตนแล้ว - เคลียร์ DHCP ทุกอย่างที่ยังอ้างอิง
      // ชื่อนี้อยู่ทิ้งไปด้วย (best-effort ทั้งคู่ - หาไม่เจอ/ลบไม่ได้ก็แค่ log เฉยๆ
      // ไม่ block การลบ interface ที่สำเร็จไปแล้ว): (1) Juniper เท่านั้น -
      // dhcp-local-server group binding (2) ทั้งสองยี่ห้อ - dhcp-relay ที่ผูกกับ
      // interface นี้
      if (layerData?.result?.vendor === "juniper" && params.interface_type !== "Vlan") {
        try {
          await runDeviceCommand(devId, "remove_dhcp_server_interface", {
            interface_type: params.interface_type,
            interface_id: params.interface_id,
            unit: params.unit,
          }, { allowFailure: true });
        } catch (cleanupErr) {
          console.error("remove_dhcp_server_interface cleanup after interface delete failed:", cleanupErr);
        }
        // 6.1: interface หายไปแล้ว = ต้องถอดออกจาก Junos DNS Proxy ด้วยเสมอ (ถ้า
        // เคยผูกไว้ - ดู InterfacesFormModal.jsx's dnsProxyBinding) best-effort
        // เหมือน cleanup อื่นๆ ในฟังก์ชันนี้
        try {
          await runDeviceCommand(devId, "remove_dns_server_interface", {
            interface_type: params.interface_type,
            interface_id: params.interface_id,
            unit: params.unit,
          }, { allowFailure: true });
        } catch (cleanupErr) {
          console.error("remove_dns_server_interface cleanup after interface delete failed:", cleanupErr);
        }
      }
      await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
      await cleanupDhcpRelayFor(selectedName, params);
      await cleanupDhcpPoolFor(selectedBrief);
      setShowDeleteConfirm(false);
      setSelectedName(null);
      handleRefresh();
    } catch (err) {
      setDeleteError(
        err.detail || err.message ||
          (params.kind === "clear-ip"
            ? "Failed to clear interface IP address"
            : params.kind === "reset-switchport"
            ? "Failed to reset interface"
            : "Failed to delete interface")
      );
    } finally {
      setDeleting(false);
    }
  }

  // รอทั้ง 2 query ให้เสร็จก่อนโชว์อะไรเลย (ไม่ใช่แค่ query แรก) - กันตาราง
  // Layer 2/3 โผล่ทีหลังตาราง interface brief เพราะ query คนละอันคนละเวลา resolve
  if ((loading && !data) || (layerLoading && !layerData)) {
    return <div className="center-loading">Loading interface data...</div>;
  }

  const briefRows = data?.normalized && Array.isArray(data.result) ? data.result : [];
  const layerRows = layerData?.normalized ? parseInterfaceLayers(layerData.result) : null;
  const rows = mergeJuniperConfiguredInterfaces(briefRows, layerRows, vendor);
  const groupedSections = groupInterfaceBriefRows(rows, vendor);
  const layerByName = buildLayerLookup(layerRows);
  const selectedBrief = rows.find((row) => row.name === selectedName) || null;
  const selectedLayer = layerRows?.find((row) => row.name === selectedName) || null;
  const editTarget = selectedName ? { name: selectedName, brief: selectedBrief, layer: selectedLayer } : null;
  const selectedDeleteParams = selectedName
    ? resolveDeleteParams(selectedName, vendor)
    : null;
  const canDeleteSelected = !!selectedDeleteParams;
  const isClearIpTarget = selectedDeleteParams?.kind === "clear-ip";
  const isSwitchportReset = selectedDeleteParams?.kind === "reset-switchport";
  // Cisco: พอร์ตที่อุปกรณ์บอกว่าเป็น switchport ได้ จะถูกคืนเป็น access VLAN 1
  // ส่วนพอร์ตของ router ที่ไม่มีความสามารถนี้ยังเป็นการล้าง IP เหมือนเดิม
  const ciscoPortIsSwitchCapable = isClearIpTarget && !!selectedLayer?.switchport_capable;
  const isTunnelSelected = !!selectedName && isCiscoTunnelInterfaceName(selectedName);
  const isJuniperPhysicalSelected = isJuniperPhysicalInterface(selectedName, vendor);

  return (
    <div className="command-configuration">

      {error && <DismissibleError message={error} onDismiss={clearError} />}
      {layerError && <DismissibleError message={layerError} onDismiss={clearLayerError} />}

      {showForm ? (
        <InterfaceFormModal
          devId={devId}
          vendor={vendor}
          model={model}
          mode={formMode}
          editTarget={formMode === "edit" ? editTarget : null}
          briefRows={rows}
          layerRows={layerRows || []}
          onClose={() => setShowForm(false)}
          onSaved={handleSaved}
        />
      ) : (data && !data.normalized ? (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        ) : rows.length === 0 ? (
          <div className="config-placeholder">No interface data</div>
        ) : (
          <>
            <div className="command-output-title">
              <Edit_Result
                featureName={isClearIpTarget && !ciscoPortIsSwitchCapable ? "IP configuration" : isSwitchportReset || ciscoPortIsSwitchCapable ? "interface configuration" : "interface"}
                selectedLabel={selectedName}
                extraWarning={
                  ciscoPortIsSwitchCapable
                    ? "This will reset the port back to access VLAN 1, clearing its IP address and Layer 3 configuration. The physical interface itself will not be deleted."
                    : isClearIpTarget
                    ? "This will clear the IP address from this physical interface and remove associated DHCP pool and relay configuration. The physical interface itself will not be deleted."
                    : isSwitchportReset
                    ? "This will reset the port back to access VLAN 1, clearing its trunk, other access VLAN, or Layer 3 configuration. The physical interface itself will not be deleted."
                    : "This action will delete interface from the device, Are you sure?"
                }
                canEdit={!!selectedName && !isTunnelSelected && !isJuniperPhysicalSelected}
                canDelete={canDeleteSelected}
                showDeleteConfirm={showDeleteConfirm}
                deleting={deleting}
                deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
                deleteLabel={isClearIpTarget || isSwitchportReset ? "Reset" : "Delete"}
                deletingLabel={isClearIpTarget || isSwitchportReset ? "Resetting..." : "Deleting..."}
                confirmLabel={isClearIpTarget || isSwitchportReset ? "Reset" : "Delete"}
                onNew={() => {
                  setFormMode("create");
                  setShowForm(true);
                }}
                onEditClick={handleEditClick}
                onOpenDeleteConfirm={() => {
                  if (canDeleteSelected) setShowDeleteConfirm(true);
                }}
                onCancelDelete={() => setShowDeleteConfirm(false)}
                onConfirmDelete={handleConfirmDelete}
                refreshing={loading || layerLoading}
                onRefresh={handleRefresh}
              />
            </div>

            {isJuniperPhysicalSelected && (
              <div className="config-placeholder">
                Juniper physical interfaces cannot be edited or deleted here. Please select a logical interface such as {selectedName}.0 instead.
              </div>
            )}

            {isTunnelSelected && (
              <div className="config-placeholder">
                Tunnel interfaces are managed exclusively under VPN &gt; Security Tunnel (with full
                Edit/Delete support for tunnel source/destination/IPsec profile). Edit/Delete buttons
                are disabled here for Tunnel interfaces to prevent accidental misconfiguration of other interfaces.
              </div>
            )}

            {showDeleteConfirm && (
              <div className="modal-overlay" onClick={() => !deleting && setShowDeleteConfirm(false)}>
                <div className="modal-card" onClick={(event) => event.stopPropagation()}>
                  <div className="modal-header">
                    <h2>{isClearIpTarget ? "Confirm clearing interface IP" : isSwitchportReset ? "Confirm interface reset" : "Confirm interface deletion"}</h2>
                    <button
                      type="button"
                      className="modal-close"
                      onClick={() => setShowDeleteConfirm(false)}
                      aria-label="close"
                      disabled={deleting}
                    >
                      &times;
                    </button>
                  </div>
                  <p>
                    {ciscoPortIsSwitchCapable ? (
                      <>
                        This will reset <strong>{selectedName}</strong> back to access VLAN 1 and clear its IP
                        address. The physical interface itself will remain. Are you sure?
                      </>
                    ) : isClearIpTarget ? (
                      <>
                        This will clear the IP address from <strong>{selectedName}</strong> and remove its
                        associated DHCP pool and relay configuration. The physical interface itself will remain. Are you sure?
                      </>
                    ) : isSwitchportReset ? (
                      <>
                        This will reset <strong>{selectedName}</strong> back to access VLAN 1, clearing its trunk,
                        other access VLAN, or Layer 3 configuration. The physical interface itself will remain. Are you sure?
                      </>
                    ) : (
                      <>
                        This action will delete <strong>{selectedName}</strong>, Are you sure?
                      </>
                    )}
                  </p>
                  {deleteError && <DismissibleError message={deleteError} onDismiss={() => setDeleteError("")} />}
                  <div className="modal-actions">
                    <button type="button" className="btn btn-ghost" onClick={() => setShowDeleteConfirm(false)} disabled={deleting}>
                      Cancel
                    </button>
                    <button type="button" className="btn btn-primary" onClick={handleConfirmDelete} disabled={deleting}>
                      {deleting
                        ? isClearIpTarget || isSwitchportReset
                          ? "Resetting..."
                          : "Deleting..."
                        : isClearIpTarget || isSwitchportReset
                        ? "Reset"
                        : "Confirm"}
                    </button>
                  </div>
                </div>
              </div>
            )}

            <table className="data-table interfaces-brief-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>IP Address</th>
                  <th>Subnet</th>
                  <th>Layer</th>
                  <th>Switchport Mode</th>
                  <th>Status</th>
                  <th>Last Change</th>
                </tr>
              </thead>
              <tbody>
                {groupedSections.map((section) => (
                  <Fragment key={section.key}>
                    <tr className="table-section-header">
                      <td colSpan={7}>{section.title}</td>
                    </tr>
                    {section.rows.map((row, index) => {
                      const physicalReadOnly = isJuniperPhysicalInterface(row.name, vendor);
                      return <tr
                        key={`${row.name}-${index}`}
                        className={`${physicalReadOnly ? "interface-row-readonly" : "row-clickable"} ${row.name === selectedName ? "row-selected" : ""}`}
                        onClick={physicalReadOnly ? undefined : () => handleRowClick(row.name)}
                        aria-disabled={physicalReadOnly || undefined}
                        title={physicalReadOnly ? "Juniper physical interfaces are shown for reference only" : undefined}
                      >
                        <td className={row.isSub ? "interface-row-sub" : undefined}>
                          {row.isSub ? "↳ " : ""}
                          {row.name}
                        </td>
                        <td>{normalizeIP(row.ip) || "-"}</td>
                        <td>{normalizeIP(row.subnet) || "-"}</td>
                        <td>{displayLayer(layerByName.get(row.name))}</td>
                        <td>{displaySwitchportMode(layerByName.get(row.name))}</td>
                        <td>{normalizeStatus(row.oper_status) || "-"}</td>
                        <td>{formatInterfaceLastChange(row.last_change, vendor)}</td>
                      </tr>;
                    })}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </>
        )
      )}
    </div>
  );
}
