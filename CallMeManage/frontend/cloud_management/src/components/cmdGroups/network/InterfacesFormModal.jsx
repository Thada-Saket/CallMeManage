import DismissibleError from "../../DismissibleError";
import { useEffect, useRef, useState } from "react";
import { runDeviceCommand, runDeviceTransaction } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { useDeviceCapability } from "../../../hooks/deviceCapability";
import { splitInterfaceName } from "../../../utils/interfaceName";
import { JUNIPER_ETHERNET_PREFIXES } from "../../../utils/interfaceKind";
import { normalizeSubnet } from "../../../utils/normalizeSubnet";
import { normalizeIP } from "../../../utils/normalizeIP";
import { maskToPrefix, computeDhcpExclusions, filterExplicitExclusions } from "../../../utils/dhcpRange";
import { computeAdaptiveDhcpRange } from "../../../utils/dhcpDefaults";
import { hoursToLeaseMinutes, leaseHoursInput } from "../../../utils/dhcpLease";
import { juniperInterfaceSaveSteps, juniperInterfacePoolCleanup } from "../../../utils/juniperInterfaceTransaction";
import { parseIpCidr } from "../../../utils/parseCidr";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { VLAN_ID_MAX, VLAN_ID_MIN, acceptsVlanIdDraft, validateVlanId } from "../../../utils/vlanId";
import IPv4Input from "../../common/IPv4Input";
import { parseVlans } from "./vlan";
import { parsePools, parseDhcpRelay, parseJuniperDhcpServerInterfaces } from "./dhcp";
import CheckboxDropdown from "../../common/CheckboxDropdown";

const LAYER = { L2: "layer2", L3: "layer3" };
const SWITCHPORT_MODE = { ACCESS: "access", TRUNK: "trunk" };
const IF_TYPE = { INTERFACE: "interface", SUB_INTERFACE: "sub-interface", VLAN: "vlan" };
const IP_MODE = { STATIC: "static", DHCP: "dhcp", NONE: "none" };
// ทุก VLAN ส่งเป็นช่วง exact นี้ให้ทั้งสองยี่ห้อ: CE12800 ไม่รับ token "all"
// ส่วน Cisco รับได้ทั้งคู่แต่ให้ส่งค่าเดียวกันเพื่อให้ payload ของทั้งสองยี่ห้อ
// เหมือนกันทั้งหมด (translator ทั้งคู่รับ list ของเลข VLAN หรือสตริงนี้เท่านั้น)
const ALL_TRUNK_VLAN_RANGE = "1-4094";

// ยิง edit-config สร้าง/ตั้งค่า interface แล้วต่อด้วย DHCP relay/pool ทันที (2
// edit-config ติดกัน) - บนอุปกรณ์บางแพลตฟอร์ม (ยืนยันจริง: Cisco C8000v/CSR1000v
// 17.16.1a) interface ที่เพิ่งสร้าง/แก้ยังไม่ "นิ่ง" พอให้ edit-config ที่ 2 รับผล
// ทันที (ไม่มี rpc-error เลย แต่ config ที่ 2 ไม่ apply จริง - เช็คแล้วผ่าน CLI
// ตรงๆ) ต่างจากแพลตฟอร์มอื่น (ยืนยัน: Catalyst 9800/WLC) ที่ทำติดกันได้ปกติ -
// ไม่มีทางตรวจสอบจาก frontend ว่าอุปกรณ์ไหนต้องรอ เลยใส่ delay คงที่ก่อนยิงคำสั่ง
// ที่ 2 เสมอ (ปลอดภัยกับเครื่องที่เร็วอยู่แล้วด้วย แค่รอเพิ่มอีกนิดหน่อย)
const POST_INTERFACE_COMMIT_DELAY_MS = 300;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// เจอบั๊กจริง (Juniper DHCP pool ชื่อมี "." ค้าง - ดู comment ใน
// buildDhcpPoolParams): edit-config ที่ถูกอุปกรณ์ปฏิเสธด้วย rpc-error (เช่น
// pool name ผิด syntax) ตอบกลับเป็น HTTP 200 ปกติพร้อม {ok: false, errors:
// [...]} ไม่ใช่ exception (ต่างจาก commit ล้มเหลวที่ throw จริง) -
// runDeviceCommand เลย resolve เฉยๆ ไม่ throw ทำให้โค้ดเดิมเข้าใจว่าสำเร็จ
// ทั้งที่จริงไม่มีอะไรถูกสร้างเลย (pattern เดียวกับที่เจอใน security_tunnel.jsx
// มาก่อนแล้ว - ยืมมาใช้ที่นี่ด้วย) โยน error ที่มี .detail ให้ catch block เดิม
// จับได้เหมือน exception ทั่วไป
function assertCommandOk(response, fallbackMessage) {
  const result = response?.result;
  if (result && result.ok === false) {
    const message = (result.errors || []).map((e) => e.message).filter(Boolean).join("; ") || fallbackMessage;
    const err = new Error(message);
    err.detail = message;
    throw err;
  }
  return response;
}

function ipToInt(ip) {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}
function intToIp(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

// pool.network จาก parsePools() มา 2 แบบ (dhcp.jsx): Cisco = "ip mask" คั่นด้วย
// space (dotted mask ธรรมดา ไม่ใช่ wildcard), Juniper = CIDR ตรงๆอยู่แล้ว (pool
// name คือ network เอง) - แปลงทั้งคู่เป็น {ip, prefix} รูปแบบเดียวกันเพื่อเทียบ
// กับ network ของ interface ที่กำลังแก้ไข
function parsePoolNetwork(networkStr) {
  if (!networkStr) return null;
  if (networkStr.includes("/")) {
    const [ip, prefixStr] = networkStr.split("/");
    const prefix = Number(prefixStr);
    return ip && Number.isInteger(prefix) ? { ip: ip.trim(), prefix } : null;
  }
  const [ip, mask] = networkStr.trim().split(/\s+/);
  const prefix = maskToPrefix(mask);
  return ip && prefix !== null ? { ip, prefix } : null;
}

// หา pool ที่ network ตรงกับ interface ที่กำลังแก้ไขเป๊ะ (ทั้ง network address
// และ prefix ต้องตรงกัน ไม่ใช่แค่ IP ตกอยู่ในวงเดียวกัน) - ใช้แก้บั๊ก: เดิมฟอร์ม
// Edit ไม่เคยเช็คเลยว่ามี pool ผูกกับ interface นี้อยู่แล้วหรือเปล่า เลยขึ้น
// "DHCP Server" toggle เป็นปิดเสมอทั้งที่ตั้งไว้จริงแล้วผ่าน pool หน้า DHCP
export function findExistingPoolForNetwork(pools, ip, prefix) {
  if (!ip || prefix === null || prefix === undefined) return null;
  const ipInt = ipToInt(ip);
  if (ipInt === null) return null;
  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const targetNetwork = (ipInt & maskInt) >>> 0;
  for (const pool of pools || []) {
    const parsed = parsePoolNetwork(pool.network);
    if (!parsed || parsed.prefix !== prefix) continue;
    const poolIpInt = ipToInt(parsed.ip);
    if (poolIpInt !== null && (poolIpInt >>> 0) === targetNetwork) return pool;
  }
  return null;
}

// คำนวณ network address จาก host IP + prefix (ip AND mask) - ใช้หา network ของ
// DHCP pool ตรงๆ จาก IP ที่กำลังตั้งให้ interface นี้ (ไม่ต้องให้ผู้ใช้กรอกซ้ำ
// เพราะ pool ที่ผูกกับ interface ต้องอยู่ในวงเดียวกับ interface เท่านั้นอยู่แล้ว)
function networkAddressOf(ip, prefix) {
  const ipInt = ipToInt(ip);
  if (ipInt === null) return null;
  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return intToIp((ipInt & maskInt) >>> 0);
}


// เจอบั๊กจริงกับ Cisco (BR2-Router): gateway มักจะตกอยู่ "นอก" ช่วงที่จะแจก
// (เช่น range แจก .11-.200, gateway = .1) ซึ่ง computeDhcpExclusions() ข้างบน
// คำนวณ exclude ครอบ .1 ไปแล้วเป็นช่วง (เช่น "x.x.x.1-x.x.x.10") - ถ้ายังเติม
// gateway (".1") ต่อท้ายเป็น entry แยกอีกตัวแบบเดิม จะได้ exclude 2 entry ที่
// ค่าเริ่มต้นซ้ำกัน (ทับกันเอง) ซึ่ง Cisco IOS-XE ปฏิเสธด้วย "inconsistent
// value: Device refused one or more commands" เหมือนกับกรณี low==high (คนละ
// สาเหตุ แต่ error message เดียวกันเพราะเป็น validation รวมของ excluded-address
// list ทั้งก้อน) - เช็คก่อนเสมอว่า gateway ตกอยู่ใน exclude entry ไหนอยู่แล้ว
// หรือไม่ (ทั้งแบบ single IP และแบบ range) ถ้าใช่ไม่ต้องเติมซ้ำ
function isIpAlreadyExcluded(ip, excludeList) {
  const target = ipToInt(ip);
  if (target === null) return false;
  return excludeList.some((entry) => {
    const [lowRaw, highRaw] = entry.split("-");
    const low = ipToInt(lowRaw);
    const high = highRaw !== undefined ? ipToInt(highRaw) : low;
    if (low === null || high === null) return false;
    return target >= low && target <= high;
  });
}

// Juniper description belongs to the selected logical unit. Empty explicitly removes it.
function resolveCommand(ifType, ipMode, values, isJuniper, preserveEmptyDescription = false) {
  const description = values.description.trim() || (preserveEmptyDescription ? undefined : "");
  if (ipMode === IP_MODE.NONE) {
    const parent = ifType === IF_TYPE.VLAN ? {interfaceType: isJuniper ? "irb" : "Vlan", interfaceId: isJuniper ? "" : String(values.vlanId)} : splitInterfaceName(values.interfaceName);
    return {command: "set_interface_l3_none", parameters: {
      interface_type: parent.interfaceType,
      interface_id: !isJuniper && ifType === IF_TYPE.SUB_INTERFACE ? `${parent.interfaceId}.${values.vlanId}` : parent.interfaceId,
      ...(isJuniper ? {unit: ifType === IF_TYPE.INTERFACE ? 0 : Number(values.vlanId), previous_addresses: values.staticAddresses || []} : {}),
      ...(!isJuniper && ifType === IF_TYPE.SUB_INTERFACE ? {vlan_id: Number(values.vlanId), native: values.native} : {}),
      ...(ifType !== IF_TYPE.SUB_INTERFACE ? {shutdown: values.shutdown} : {}),
      description,
    }};
  }
  // Blank MTU is omitted here; Edit plans its explicit removal in the transaction.
  const mtu = values.mtu ? Number(values.mtu) : undefined;

  if (ifType === IF_TYPE.INTERFACE) {
    const { interfaceType, interfaceId } = splitInterfaceName(values.interfaceName);
    if (ipMode === IP_MODE.STATIC) {
      const parameters = {
        interface_type: interfaceType,
        interface_id: interfaceId,
        ip: values.ip.trim(),
        mask: Number(values.mask),
        shutdown: values.shutdown,
        mtu,
      };
      parameters.description = description;
      if (isJuniper) parameters.previous_addresses = values.staticAddresses || [];
      return { command: "set_interface_static_ip", parameters };
    }
    const parameters = { interface_type: interfaceType, interface_id: interfaceId, mtu };
    parameters.shutdown = values.shutdown;
    if (isJuniper) parameters.static_addresses = values.staticAddresses || [];
    parameters.description = description;
    return { command: "set_interface_ip_dhcp", parameters };
  }

  if (ifType === IF_TYPE.SUB_INTERFACE) {
    const { interfaceType, interfaceId } = splitInterfaceName(values.interfaceName);
    const parameters = {
      interface_type: interfaceType,
      interface_id: interfaceId,
      vlan_id: Number(values.vlanId),
      ip: values.ip.trim(),
      prefix: Number(values.mask),
      native: values.native,
      mtu,
    };
    parameters.description = description;
    if (isJuniper) parameters.previous_addresses = values.staticAddresses || [];
    return { command: "set_sub_interface_ip", parameters };
  }

  // VLAN Interface (SVI) - Juniper's set_interface_vlan เขียนลง "irb" เสมอ
  // (hardcode ไว้ในฟังก์ชันเอง ไม่รับ interface name) แต่มี shutdown/description
  // param ครบเหมือน Cisco (ทดสอบจริงกับอุปกรณ์แล้วว่าต้องฝัง <disable/> ไว้ใน
  // <unit> ของ call เดียวกันนี้เลย - แยกยิง set_no_shutdown ทีหลังบน
  // interface_type="irb" ใช้ไม่ได้เพราะฟังก์ชันนั้นต่อ "irb"+vlan_id เป็นชื่อ
  // เดียว ("irb999") ซึ่งไม่มีอยู่จริงบนอุปกรณ์)
  if (ipMode === IP_MODE.STATIC) {
    return {
      command: "set_interface_vlan",
      parameters: {
        vlan_id: Number(values.vlanId),
        ip: values.ip.trim(),
        mask: Number(values.mask),
        shutdown: values.shutdown,
        description,
        mtu,
        ...(isJuniper ? {previous_addresses: values.staticAddresses || []} : {}),
      },
    };
  }
  // DHCP mode ของ VLAN(SVI) ยังไม่รองรับ Juniper เลย (ไม่มีฟังก์ชัน irb+dhcp
  // ให้เรียก - ซ่อน option นี้ไว้ใน UI แล้วสำหรับ Juniper ไม่ควรมาถึง branch
  // นี้ได้เลยถ้าเป็น Juniper)
  return {
    command: "set_interface_ip_dhcp",
    parameters: { interface_type: "Vlan", interface_id: String(values.vlanId), description, mtu, shutdown: values.shutdown },
  };
}

function toDisplayText(value) {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

// Huawei trunkVlans เป็น vlan-range เช่น "1,10,20" หรือ "1-3". แปลงเป็น
// รายการเลขเรียงลำดับเพื่อ pre-fill form; ไม่ใช้ tagVlanList เป็นแหล่งหลักเพราะ
// เป็น operational state ไม่ใช่ configuration ที่ผู้ใช้บันทึกไว้.
function parseTrunkVlanRange(value) {
  const text = toDisplayText(value).trim();
  if (!text || text === "-") return [];
  const ids = new Set();
  for (const token of text.split(/[\s,]+/)) {
    const bounds = token.split("-");
    const start = Number(bounds[0]);
    const end = bounds.length === 2 ? Number(bounds[1]) : start;
    if (bounds.length > 2 || !Number.isInteger(start) || !Number.isInteger(end)) continue;
    const low = Math.min(start, end);
    const high = Math.max(start, end);
    if (low < 1 || high > 4094) continue;
    for (let vlan = low; vlan <= high; vlan += 1) ids.add(vlan);
  }
  return [...ids].sort((a, b) => a - b);
}

const DEFAULT_VALUES = {
  interfaceName: "",
  vlanId: "",
  ip: "",
  mask: "",
  native: false,
  shutdown: true,
  description: "",
  // ค่าว่าง = ไม่ส่ง mtu เลย ใช้ default ของอุปกรณ์เอง (optional - แก้ปัญหา OSPF
  // neighbor ค้าง EXSTART/EXCHANGE ข้ามยี่ห้อจาก MTU ไม่ตรงกัน)
  mtu: "",
  // ---- DHCP server (ทำงานเฉพาะโหมด Static เพราะต้องมี IP คงที่เป็น gateway) ----
  dhcpServer: false,
  dhcpMode: "server", // server | relay (relay ยังไม่รองรับ - ดู handleSubmit)
  dhcpRelayIp: "",
  dhcpStartAddress: "",
  dhcpEndAddress: "",
  dhcpGatewayMode: "interface", // interface = ใช้ IP ของ interface นี้ | specific
  dhcpGatewayIp: "",
  dhcpDnsMode: "interface",
  dhcpDnsIp: "",
  dhcpDnsIps: [""],
  dhcpNtpMode: "interface",
  dhcpNtpIp: "",
  dhcpLease: "168", // ชั่วโมง (7 วัน)
  // ---- Layer 2 (switchport) ----
  switchportMode: SWITCHPORT_MODE.ACCESS,
  switchportVlan: "",
  // Trunk รับ VLAN ได้หลายค่า ต่างจาก access ที่ใช้ค่าเดียวจาก dropdown
  trunkVlans: [""],
  switchportEnabled: true,
};

// physical Ethernet interface prefix ที่ switch-class อุปกรณ์ใช้ (Cisco จาก
// IF_PREFIXES.cisco ใน CliGenerator.jsx, Juniper จาก IF_PREFIXES.juniper) - ใช้
// เดา Layer 2 (switchport) capability เฉพาะตอน backend classify ไม่ได้เท่านั้น
// (ดู inferSwitchportCapable)
const SWITCHPORT_CAPABLE_PREFIXES = {
  cisco: ["ethernet", "fastethernet", "gigabitethernet", "twogigabitethernet", "fivegigabitethernet", "tengigabitethernet", "fortygigabitethernet"],
  // ชนิด ethernet ของ Juniper มีแหล่งเดียวที่ utils/interfaceKind.js (หน้า RIP
  // ใช้ลิสต์เดียวกันตัดสินว่าขาไหนผูก routing protocol ได้)
  juniper: JUNIPER_ETHERNET_PREFIXES,
};

// เจอจริงจากการไล่โค้ด (ไม่ใช่ "disabled" ตามที่เคยรายงาน - ไม่มี disabled={...}
// บนปุ่ม Layer 2/3 เลยสักจุด): ปัญหาจริงคือ classifyJuniperLayer/
// normalize_switchport_layer คืน "Unknown" ได้ (Juniper: unit ที่ไม่มี family
// ethernet-switching/inet เลย, Cisco: ยืนยันสดกับ TestSWonWLC จริงว่า
// GigabitEthernet0 - ช่อง OOB management, VRF "Mgmt-intf" - ก็ได้ "Unknown"
// เหมือนกัน เพราะไม่มี switchport-conf container เลย ต่างจาก docstring เดิมของ
// normalize_switchport_layer ที่เข้าใจว่า Cisco "ไม่มี Unknown อีกต่อไป" - จริง
// แล้วยังมีสำหรับ management port โดยเฉพาะ) แล้ว buildInitialValues เดิม
// fallback เป็น Layer 3 เสมอแบบไม่มีทางเลือกที่ดีกว่า - เพิ่ม heuristic เดาจาก
// vendor+ชื่อ interface แทน (ตามข้อ 4.2 ของสเปก) เฉพาะตอน "Unknown"/ไม่มีค่า
// เท่านั้น ไม่แตะกรณีที่ backend classify ได้ชัดเจนแล้วเลย
//
// **เจอจริงระหว่าง live-verify กับ TestSWonWLC**: ถ้าเดาจาก prefix อย่างเดียว
// (ไม่เช็ค slot notation) จะเดา GigabitEthernet0 (mgmt port, id="0" ไม่มี "/"
// เลย) ผิดเป็น Layer 2 ทันที ทั้งที่จริงเป็นพอร์ต L3-only ตามธรรมชาติ (ไม่มี
// concept switchport เลยด้วยซ้ำ) - Cisco data-plane port ตัวจริงมี slot
// notation เสมอ (เช่น "0/0/0", "1/0/1") ต่างจาก management port ที่เป็นเลขเดี่ยว
// ไม่มี "/" - ใช้ presence ของ "/" ใน interfaceId แยกจริง/mgmt ออกจากกัน
// (Juniper ไม่มีปัญหานี้ - ge-/xe-/fe-/et- มี "/" ในชื่อเสมออยู่แล้วตาม
// convention, ช่อง mgmt ของ Juniper ชื่อ "fxp0"/"em0" ไม่ตรงกับ prefix กลุ่มนี้
// อยู่แล้วตั้งแต่แรก) - **หมายเหตุสำคัญ**: เป็น heuristic เดาล้วนๆ ยังไม่เคย
// verify กับอุปกรณ์ WLC จริง (Cisco Catalyst 9800) เพราะไม่มีอุปกรณ์ในแล็บให้
// ทดสอบตอนนี้ - ถ้าพังให้กลับมาปรับ list/เงื่อนไขนี้
function inferSwitchportCapable(vendor, interfaceFullName) {
  const { interfaceType, interfaceId } = splitInterfaceName(interfaceFullName);
  const prefixes = SWITCHPORT_CAPABLE_PREFIXES[vendor];
  // Huawei มี Layer 2/3 จาก normalize_switchport_layer แล้ว; ถ้า backend
  // คืน Unknown ก็ไม่เดาจาก prefix เพิ่ม เพราะ CE12800 มีทั้ง management/SVI
  // ที่ชื่อไม่บอก capability ชัดเจน
  if (!prefixes) return false;
  if (!prefixes.includes(interfaceType.toLowerCase())) return false;
  if (vendor === "cisco" && !interfaceId.includes("/")) return false; // mgmt port (เช่น "GigabitEthernet0") - ไม่ใช่ data port
  return true;
}

// โหมด Edit: ดึงค่าปัจจุบันของ interface ที่เลือกจาก interfaces.jsx (brief row
// จาก get_ip_interface_brief + raw entry จาก get_switchport_information) มา
// pre-fill ฟอร์ม - ไม่ pre-fill DHCP (pool/relay ที่ผูกกับ interface นี้ไม่ได้
// อ่านกลับมาจาก query ที่มีอยู่ตอนนี้ง่ายๆ ผู้ใช้ต้องกรอกใหม่เองถ้าต้องการแก้ไข
// DHCP - แก้ IP/shutdown/VLAN/switchport ได้ปกติ)
function interfaceLayerOptions({vendor, name, row, layer2Allowed}) {
  // Prefer explicit per-interface capability; current layer alone is not proof
  // that a port cannot switch to another layer.
  if (Array.isArray(row?.supported_layers)) {
    const supported = [...new Set(row.supported_layers.map(value =>
      value === 2 || value === "Layer 2" || value === LAYER.L2 ? LAYER.L2
        : value === 3 || value === "Layer 3" || value === LAYER.L3 ? LAYER.L3 : null).filter(Boolean))];
    if (supported.length) return supported;
  }
  if (vendor === "cisco" && typeof row?.switchport_capable === "boolean") {
    return row.switchport_capable && layer2Allowed ? [LAYER.L3, LAYER.L2] : [LAYER.L3];
  }
  if (!name) return layer2Allowed ? [LAYER.L3, LAYER.L2] : [LAYER.L3];
  const {interfaceType} = splitInterfaceName(name);
  const type = interfaceType.toLowerCase();
  const switchable = vendor === "juniper" ? /^(ge-|xe-|fe-|et-|mge-|ae|reth)$/.test(type)
    : vendor === "huawei" ? type.endsWith("ge") : inferSwitchportCapable(vendor, name);
  if (switchable && layer2Allowed) return [LAYER.L3, LAYER.L2];
  return [row?.layer === "Layer 2" ? LAYER.L2 : LAYER.L3];
}

function buildInitialValues(mode, editTarget, vendor) {
  if (mode !== "edit" || !editTarget) {
    return { layer: LAYER.L3, ifType: IF_TYPE.INTERFACE, ipMode: IP_MODE.STATIC, values: DEFAULT_VALUES };
  }

  const { name, brief, layer: layerInfo } = editTarget;
  const raw = layerInfo?.raw || {};
  const layer =
    layerInfo?.layer === "Layer 2"
      ? LAYER.L2
      : layerInfo?.layer === "Layer 3"
      ? LAYER.L3
      : inferSwitchportCapable(vendor, name)
      ? LAYER.L2
      : LAYER.L3;
  const isJuniper = vendor === "juniper";
  const isHuawei = vendor === "huawei";

  let ifType = IF_TYPE.INTERFACE;
  let interfaceName = name;
  let vlanId = "";
  // VRP เรียก SVI ว่า Vlanif20; แยกก่อน prefix Vlan ทั่วไป ไม่เช่นนั้นจะ
  // ตัดชื่อเหลือ "if20" และฟอร์ม Edit ชี้ VLAN ผิด.
  if (isHuawei && name.toLowerCase().startsWith("vlanif")) {
    ifType = IF_TYPE.VLAN;
    vlanId = name.replace(/^Vlanif/i, "");
    interfaceName = "";
  } else if (name.startsWith("Vlan")) {
    ifType = IF_TYPE.VLAN;
    vlanId = name.replace(/^Vlan/, "");
    interfaceName = "";
  } else if (name.startsWith("irb.")) {
    // Juniper's SVI ชื่อ "irb.<vlan_id>" เสมอ (parseJuniperInterfaceLayers ต่อ
    // ".{unit}" เข้ากับ "irb" - unit ของ irb คือ vlan_id ตรงๆ ตามที่
    // set_interface_vlan เขียน) ต้องเช็คก่อน branch "." ทั่วไปด้านล่าง ไม่งั้น
    // จะโดนตีความเป็น Sub-interface ผิดประเภท (parent "irb" ว่างๆ)
    ifType = IF_TYPE.VLAN;
    vlanId = name.replace(/^irb\./, "");
    interfaceName = "";
  } else if (name.includes(".")) {
    // ยืนยันจริงกับอุปกรณ์ (vSRX): Juniper ทุก logical interface ต้องมี unit
    // เสมอแม้แต่ "Interface" ธรรมดา (set_interface_static_ip เขียนลง unit 0
    // hardcode ไว้เสมอ) ทำให้ "ge-0/0/2.0" หน้าตาเหมือน Sub-interface เป๊ะทั้งที่
    // จริงคือ "Interface" ธรรมดา - unit "0" ของ Juniper เท่านั้นที่ถือเป็น
    // "Interface" เฉยๆ (unit อื่นถือเป็น Sub-interface จริง) Cisco ไม่มีความ
    // กำกวมนี้เลย (ไม่มีทางมี ".0" ที่ไม่ใช่ sub-interface จริง) เดิมไม่เช็ค
    // vendor เลยตีความ "ge-0/0/2.0" เป็น Sub-interface เสมอ ทำให้ edit ผิด
    // ประเภท (โชว์ VLAN ID/parent port แทนที่จะเป็นฟอร์ม Interface ธรรมดา)
    const { interfaceType, interfaceId } = splitInterfaceName(name);
    const [parentId, unit] = interfaceId.split(".");
    if (isJuniper && unit === "0") {
      ifType = IF_TYPE.INTERFACE;
      interfaceName = `${interfaceType}${parentId}`;
    } else {
      ifType = IF_TYPE.SUB_INTERFACE;
      interfaceName = `${interfaceType}${parentId}`;
      vlanId = unit || "";
    }
  }

  const ipValue = normalizeIP(brief?.ip || "");
  const subnet = normalizeSubnet(brief?.subnet);
  let ip = ipValue && ipValue !== "-" && subnet ? `${ipValue}/${subnet.prefix}` : "";

  const adminStatus = toDisplayText(brief?.admin_status).toLowerCase();
  let shutdown = adminStatus ? !adminStatus.includes("up") : true;
  let ipMode = IP_MODE.STATIC;
  if (layer === LAYER.L3 && !ip) ipMode = IP_MODE.NONE;
  if (!isJuniper && raw?.ip?.address && Object.hasOwn(raw.ip.address, "dhcp")) ipMode = IP_MODE.DHCP;
  if (isJuniper && raw?.name) {
    // The terse logical-unit status can remain up while its parent is disabled.
    // Read the empty disable leaf by presence (its parsed value may be null).
    const units = Array.isArray(raw.unit) ? raw.unit : raw.unit ? [raw.unit] : [];
    const unitName = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : "0";
    const selectedUnit = units.find(unit => String(unit.name) === unitName);
    if (layer === LAYER.L3 && selectedUnit?.family && Object.hasOwn(selectedUnit.family, "inet")) {
      const addresses = selectedUnit.family.inet?.address;
      const configuredAddress = (Array.isArray(addresses) ? addresses : addresses ? [addresses] : [])[0]?.name;
      ipMode = configuredAddress ? IP_MODE.STATIC : IP_MODE.NONE;
      ip = configuredAddress || "";
    }
    if (ifType === IF_TYPE.INTERFACE && selectedUnit?.family?.inet && Object.hasOwn(selectedUnit.family.inet, "dhcp")) {
      ipMode = IP_MODE.DHCP;
    }
    shutdown = Object.hasOwn(raw, "disable") || Boolean(selectedUnit && Object.hasOwn(selectedUnit, "disable"));
  }

  const native = "native" in (raw?.encapsulation?.dot1Q || {});

  // Cisco/Juniper คง path เดิมที่ผ่านอุปกรณ์จริงแล้ว. Huawei ใช้ huawei-ethernet
  // l2Attribute และ portActiveVlanInfo แทน จึงแยก branch เพื่อไม่ให้ schema ปนกัน.
  const swp = raw?.switchport || raw?.["switchport-config"]?.switchport;
  const huaweiL2 = isHuawei ? raw?.l2Attribute : null;
  const huaweiActiveVlan = huaweiL2?.portActiveVlanInfos?.portActiveVlanInfo;
  let switchportMode = SWITCHPORT_MODE.ACCESS;
  let switchportVlan = "";
  let trunkVlans = [""];
  if (isJuniper) {
    const units = Array.isArray(raw.unit) ? raw.unit : raw.unit ? [raw.unit] : [];
    const unitName = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : "0";
    const switching = units.find(unit => String(unit.name) === unitName)?.family?.["ethernet-switching"];
    switchportMode = (switching?.["interface-mode"] ?? switching?.["port-mode"]) === "trunk" ? SWITCHPORT_MODE.TRUNK : SWITCHPORT_MODE.ACCESS;
    const members = switching?.vlan?.members;
    const list = Array.isArray(members) ? members.map(String) : members == null ? [] : [String(members)];
    if (switchportMode === SWITCHPORT_MODE.TRUNK) trunkVlans = list.length ? list : [""];
    else switchportVlan = list[0] || "";
  } else if (isHuawei) {
    const linkType = toDisplayText(huaweiL2?.linkType).toLowerCase();
    const accessVlan = huaweiL2?.pvid ?? huaweiActiveVlan?.unTagVlanList;
    const configuredTrunkVlans = huaweiL2?.trunkVlans ?? huaweiActiveVlan?.tagVlanList;
    if (linkType === "trunk") {
      switchportMode = SWITCHPORT_MODE.TRUNK;
      const configuredText = toDisplayText(configuredTrunkVlans).trim();
      trunkVlans = configuredText === ALL_TRUNK_VLAN_RANGE
        ? ["all"]
        : parseTrunkVlanRange(configuredTrunkVlans).map(String);
      if (trunkVlans.length === 0) trunkVlans = [""];
    } else if (accessVlan) {
      switchportVlan = toDisplayText(accessVlan);
    }
  } else {
    // โครงสร้างเดียวกับที่ verify จริงแล้วใน vlan.jsx's parseVlanMembership
    const accessVlan = swp?.access?.vlan?.vlan ?? swp?.access?.vlan;
    const configuredTrunkVlans = swp?.trunk?.allowed?.vlan?.vlans ?? swp?.trunk?.allowed?.vlan?.vlan;
    // ใช้ตัวแยกเดียวกับ Huawei: รองรับช่วงอย่าง 10-20 ที่อุปกรณ์คืนมา และ map ค่า
    // ที่ตรงกับ 1-4094 เป๊ะกลับเป็น All เพื่อให้ทั้งสองยี่ห้อใช้ UI ชุดเดียวกันได้
    const configuredTrunkText = toDisplayText(configuredTrunkVlans).trim();
    trunkVlans = configuredTrunkVlans
      ? (configuredTrunkText === ALL_TRUNK_VLAN_RANGE
        ? ["all"]
        : parseTrunkVlanRange(configuredTrunkVlans).map(String))
      : [""];
    if (trunkVlans.length === 0) trunkVlans = [""];
    const modeTrunk = !!swp?.mode?.trunk || (swp?.mode && "trunk" in swp.mode);
    if (accessVlan) {
      switchportMode = SWITCHPORT_MODE.ACCESS;
      switchportVlan = toDisplayText(accessVlan);
    } else if (configuredTrunkVlans || modeTrunk) {
      switchportMode = SWITCHPORT_MODE.TRUNK;
    } else if (vendor === "cisco") {
      // ไม่มีทั้ง access/vlan และ trunk = พอร์ต access ที่ใช้ VLAN 1 ตามค่าเริ่มต้น
      // อุปกรณ์ไม่เขียนบรรทัดนี้ลง config จึงต้องเติมให้เองไม่งั้นช่องจะว่าง
      switchportMode = SWITCHPORT_MODE.ACCESS;
      switchportVlan = "1";
    }
  }

  // แก้บั๊กเดียวกับ DHCP pool: helper-address (relay) ที่ผูกกับ interface นี้
  // อยู่แล้วมาพร้อมกับ layerInfo.helpers อยู่แล้ว (normalize_switchport_layer
  // ฝั่ง backend ใส่มาให้เป็น array เสมอ) ไม่ต้อง query เพิ่มแบบ pool เลย - เอา
  // ตัวแรกมาพอ (ฟอร์มนี้รองรับ helper address เดียวต่อ interface ถึงแม้อุปกรณ์
  // จะตั้ง ip helper-address ได้หลายบรรทัดก็ตาม)
  const existingRelay = layerInfo?.helpers?.[0] || "";
  // Huawei reads brief, Cisco reads native interface, Juniper reads the selected unit.
  const descriptionUnits = isJuniper ? (Array.isArray(raw?.unit) ? raw.unit : raw?.unit ? [raw.unit] : []) : [];
  const descriptionUnitName = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : "0";
  const description = isHuawei ? toDisplayText(brief?.description)
    : isJuniper ? toDisplayText(descriptionUnits.find(unit => String(unit.name) === descriptionUnitName)?.description)
    : toDisplayText(raw?.description);
  const mtu = isHuawei
    ? toDisplayText(brief?.mtu)
    : ((isJuniper ? raw?.mtu : raw?.ip?.mtu)
      ? String(isJuniper ? raw.mtu : raw.ip.mtu)
      : "");

  return {
    layer,
    ifType,
    ipMode,
    values: {
      ...DEFAULT_VALUES,
      interfaceName,
      vlanId,
      ip,
      native,
      shutdown,
      description,
      mtu,
      switchportMode,
      switchportVlan,
      trunkVlans,
      switchportEnabled: !shutdown,
      ...(existingRelay
        ? { dhcpServer: true, dhcpMode: "relay", dhcpRelayIp: existingRelay }
        : {}),
    },
  };
}

export default function InterfaceFormModal({
  devId,
  vendor,
  // dev_model ของอุปกรณ์ (เช่น "9800"/WLC) - ยังไม่ได้ใช้ตัดสินอะไรจริงจัง
  // เพราะไม่มีอุปกรณ์ WLC ในแล็บให้ verify behavior จริง (ดู
  // inferSwitchportCapable) - รับไว้เผื่ออนาคตต้องแยก heuristic ตามรุ่นเพิ่ม
  model = "",
  mode = "create",
  editTarget = null,
  briefRows = [],
  layerRows = [],
  onClose,
  onSaved,
}) {
  const isJuniper = vendor === "juniper";
  // CE12800 ไม่รองรับ DHCP ผ่าน NETCONF และไม่รองรับ sub-interface; guard นี้
  // ใช้ซ่อนทางเลือกที่ยิงคำสั่งไม่ได้ โดยไม่เปลี่ยน branch Cisco/Juniper เดิม
  const isHuawei = vendor === "huawei";
  const isCisco = vendor === "cisco";
  const initial = buildInitialValues(mode, editTarget, vendor);
  const [layer, setLayer] = useState(initial.layer);
  // (dynamic feature ขั้นที่ 5) ซ่อนตัวเลือก Layer 2 เมื่อ backend ตัดสินว่าอุปกรณ์ทำ switchport ไม่ได้
  // (มีผลเฉพาะตอนเปิดการกรอง) แต่พอร์ตที่เป็น Layer 2 อยู่แล้วบนอุปกรณ์จริงยังต้องเลือกได้ เพราะหน้าจอ
  // ต้องตรงกับอุปกรณ์ - ค่าเริ่มต้นตอนสร้างใหม่เป็น Layer 3 อยู่แล้ว
  const { hiddenCommands } = useDeviceCapability();
  const layer2Allowed = !hiddenCommands.has("apply_interface_to_vlan");
  // VLAN Interface ไม่มีความหมายบนอุปกรณ์ที่ตั้ง VLAN และ switchport ไม่ได้ (c8000) จึงซ่อนตัวเลือกด้วย
  // ยกเว้นกำลังแก้ VLAN Interface ที่มีอยู่แล้วบนอุปกรณ์
  const vlanInterfaceSelectable = !hiddenCommands.has("set_interface_vlan") || initial.ifType === IF_TYPE.VLAN;
  const [ifType, setIfType] = useState(initial.ifType);
  const [ipMode, setIpMode] = useState(initial.ipMode);
  const [values, setValues] = useState(initial.values);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  // เจอบั๊กจริง (user รายงาน): กดปิด "DHCP Server" ตอน Edit interface ที่มี
  // pool/relay ผูกอยู่แล้วจริง แล้วกด Save - ไม่มีอะไรถูกลบออกจากอุปกรณ์เลย (pool
  // ยังอยู่เหมือนเดิม) เพราะ handleSubmit เดิมสร้าง dhcpAction แค่ตอน
  // dhcpServer===true (โหมด "เปิด") ไม่เคยมี path "ปิด" ที่ไปลบของเดิมทิ้งเลย -
  // originalDhcp เก็บว่า "ตอนโหลดฟอร์มมา มี DHCP ผูกอยู่จริงไหม ถ้ามีต้องลบอะไร
  // ถ้า user ปิด toggle" - ตั้งต้นจาก initial.values ตรงๆ (ครอบคลุมเฉพาะ Cisco
  // relay ที่ buildInitialValues prefill แบบ synchronous ผ่าน editTarget.layer.
  // helpers ได้อยู่แล้ว) ส่วน pool (server mode ทั้ง 2 ยี่ห้อ) และ Juniper relay
  // จะถูกเติมทีหลังผ่าน useEffect ที่ตรวจจาก dhcpPoolData (ดูด้านล่าง) เพราะต้อง
  // รอ query มาก่อนถึงจะรู้
  const [originalDhcp, setOriginalDhcp] = useState(() => {
    if (mode === "edit" && initial.values.dhcpServer && initial.values.dhcpMode === "relay" && initial.values.dhcpRelayIp) {
      return { mode: "relay", relayIp: initial.values.dhcpRelayIp };
    }
    return null;
  });
  const [showDhcpOffConfirm, setShowDhcpOffConfirm] = useState(false);
  const [vlanIdError, setVlanIdError] = useState("");

  const { data: ifListData, loading: ifListLoading, error: ifListError } = getDeviceInformation(
    devId,
    "get_interface_list"
  );
  const interfaceOptions = ifListData?.normalized
    ? ifListData.result.map((row) => row.name).filter(Boolean)
    : [];

  // State-Aware Filtering (เฉพาะหน้า Create New): พอร์ตที่ตั้งค่าเป็น L2
  // (switchport) หรือ L3 (มี static IP) "บริบูรณ์" แล้ว ไม่ควรโผล่ให้เลือกซ้ำอีก -
  // มาจาก briefRows/layerRows ที่ interfaces.jsx ดึงมาแสดงตารางอยู่แล้ว (ไม่ต้อง
  // query เพิ่ม) ข้อยกเว้นตามที่กำหนด: พอร์ตที่มี static IP (L3) อยู่แล้วยังเลือก
  // เป็น parent port ของ Sub-interface ได้ (พอร์ตหลักรับ untagged, sub-interface
  // รับ tagged VLAN แยกกันคนละ layer ของ 802.1Q - อยู่ร่วมกันได้จริง)
  const configuredPortState = new Map();
  for (const row of briefRows || []) {
    const ip = normalizeIP(row?.ip);
    if (ip && ip !== "-") configuredPortState.set(row.name, { ...configuredPortState.get(row.name), hasStaticIp: true });
  }
  for (const row of layerRows || []) {
    if (row?.layer === "Layer 2") {
      configuredPortState.set(row.name, { ...configuredPortState.get(row.name), isL2: true });
    }
  }

  // Juniper: get_interface_list คืนชื่อ interface ต่อ "unit" เสมอ ไม่มีทาง
  // ได้ชื่อ bare (ไม่มี unit ต่อท้าย) กลับมาเลยถ้า physical port นั้นมี unit
  // ตั้งค่าอยู่แล้วแม้แต่ตัวเดียว (ยืนยันจริง: "ge-0/0/6" หายจาก get_interface_list
  // ทันทีที่มี "ge-0/0/6.40" - ต่างจาก Cisco ที่ชื่อ interface ไม่มี unit concept
  // เลย) ทำให้ port ที่เคยสร้าง sub-interface/Interface ไปแล้วสักตัวหนึ่ง **ไม่มี
  // ทางถูกเลือกเป็น parent ซ้ำได้อีกเลยในทางปฏิบัติ** เพราะตัวเลือก bare หายไปจาก
  // dropdown ทั้งที่ยังสร้าง unit เพิ่มบน port เดิมได้จริงตามปกติของ Junos - ต้อง
  // เดา parent name จากชื่อที่มี "." (unit) ด้วยเสมอ ไม่ใช่พึ่งชื่อ bare ที่มาจาก
  // backend อย่างเดียว (ยกเว้น "irb" ที่มีชื่อ bare ของตัวเองอยู่แล้วในทุกกรณี -
  // "irb.30" ไม่ใช่ physical parent ให้สร้าง sub-interface ต่อได้)
  function physicalParentOf(name) {
    if (!name.includes(".")) return null;
    const { interfaceType, interfaceId } = splitInterfaceName(name);
    if (/^irb$/i.test(interfaceType) || /^(vlan|tunnel)/i.test(interfaceType)) return null;
    const parentId = interfaceId.slice(0, interfaceId.lastIndexOf("."));
    return `${interfaceType}${parentId}`;
  }
  const derivedParents = new Set();
  for (const name of interfaceOptions) {
    const parent = physicalParentOf(name);
    if (parent) derivedParents.add(parent);
  }
  const bareNames = interfaceOptions.filter((name) => !name.includes(".") && !/^(vlan|tunnel)/i.test(name));
  const candidateInterfaceNames = Array.from(new Set([...bareNames, ...derivedParents])).filter((name) => (
    vendor !== "juniper"
    || JUNIPER_ETHERNET_PREFIXES.some((prefix) => name.toLowerCase().startsWith(prefix))
  ));

  // configuredPortState คีย์ด้วยชื่อเต็มพร้อม unit เสมอ (ตรงกับที่ briefRows/
  // layerRows ให้มา) - ชื่อ parent ที่ derive ขึ้นมาเองด้านบนไม่มีทาง match ตรงๆ
  // ได้เลย ต้องไล่เช็ค state จากทุก unit ที่เป็นลูกของ parent นั้นแทน (รวม state
  // ถ้า unit ไหนของ parent เป็น L2/มี static IP ให้ถือว่า parent นั้น "มีสถานะนี้"
  // ไปด้วย) ส่วนชื่อ bare ตรงๆ (Cisco ไม่มี unit concept เลย)ยัง match ตรงได้ปกติ
  function stateForPort(name) {
    const direct = configuredPortState.get(name);
    if (direct) return direct;
    const merged = {};
    for (const [rowName, state] of configuredPortState.entries()) {
      if (rowName.startsWith(`${name}.`)) {
        if (state.isL2) merged.isL2 = true;
        if (state.hasStaticIp) merged.hasStaticIp = true;
      }
    }
    return Object.keys(merged).length ? merged : null;
  }

  // ช่อง "Interface" คือตัวเลือก physical/trunk interface เสมอ ไม่ว่าจะอยู่โหมดไหน:
  // L2 switchport ก็ต้องเป็น physical/trunk port, โหมด "Interface" เฉยๆ ก็ตั้งใจ
  // ให้เป็น physical เท่านั้น (แก้ IP ของ sub-interface/VLAN ที่มีอยู่แล้วให้ไปใช้
  // โหมด Sub-interface [parent+VLAN ID] หรือ VLAN [VLAN ID อย่างเดียว] แทน - สอง
  // โหมดนั้นสร้างชื่อ target ขึ้นเองจากช่องอื่น ไม่ได้พึ่งช่องนี้เป็นชื่อตรงๆอยู่แล้ว)
  // และโหมด Sub-interface เองก็ต้องเลือก parent ทางกายภาพเท่านั้น (ต่อ
  // ".${vlanId}" เข้ากับชื่อที่เลือก - เลือก sub-interface เดิมมาจะได้ชื่อเพี้ยน
  // เป็น "4.10.20", เลือก Vlan/Tunnel มาก็ไม่มี dot1q sub-interface ได้จริง) เลย
  // กรองออก "." (sub-interface เดิม) และชื่อที่ขึ้นต้นด้วย Vlan/Tunnel เสมอ ไม่ผูก
  // กับ ifType เจาะจงโหมดใดโหมดหนึ่ง - ต่อด้วย state-aware filter เฉพาะตอน
  // create เท่านั้น (edit mode ไม่กรอง - ผู้ใช้กำลังแก้ interface ที่เลือกอยู่แล้ว)
  const pickableInterfaceOptions = candidateInterfaceNames.filter((name) => {
    if (name.includes(".") || /^(vlan|tunnel)/i.test(name)) return false;
    if (mode !== "create") return true;
    const state = stateForPort(name);
    if (!state) return true;
    if (ifType === IF_TYPE.SUB_INTERFACE) return !state.isL2; // ข้อยกเว้น: static IP ยังเลือกได้
    return !state.hasStaticIp;
  });
  const canPickInterface = !ifListError && pickableInterfaceOptions.length > 0;
  const capabilityRow = layerRows.find(row => row.name === values.interfaceName
    || (isJuniper && row.name === `${values.interfaceName}.0`)) || (mode === "edit" ? editTarget?.layer : null);
  const selectableLayers = ifType === IF_TYPE.INTERFACE
    ? interfaceLayerOptions({vendor, name: values.interfaceName, row: capabilityRow, layer2Allowed}) : [LAYER.L3];
  const layer2Selectable = selectableLayers.includes(LAYER.L2);
  useEffect(() => {
    if (selectableLayers.length === 1 && layer !== selectableLayers[0]) setLayer(selectableLayers[0]);
  }, [vendor, ifType, values.interfaceName, selectableLayers.join(","), layer]);
  // VLAN Interface (SVI) ไม่ผูกกับ physical interface ใดๆ เลย (resolveCommand ใช้
  // แค่ values.vlanId ไม่แตะ values.interfaceName) เลยไม่ต้องบังคับเลือก/โชว์ช่องนี้
  const needsInterfacePicker = ifType !== IF_TYPE.VLAN;

  // VLAN dropdown สำหรับโหมด Layer 2 เท่านั้น - ดึงเฉพาะตอน layer===L2 ก็พอ แต่
  // hook ต้องเรียกแบบ unconditional (กฎ hooks) เลย fetch ไว้เสมอ ไม่ได้เสียอะไร
  // มาก (แค่ query เดียว ไม่ได้ผูกกับฟอร์มอื่น)
  const { data: vlanData, loading: vlanLoading } = getDeviceInformation(devId, "get_vlan_information");
  const deviceVlans = vlanData?.normalized ? parseVlans(vlanData.result) || [] : [];
  const juniperL2Prefilled = useRef(false);
  useEffect(() => {
    if (!isJuniper || mode !== "edit" || initial.layer !== LAYER.L2 || !vlanData?.normalized || juniperL2Prefilled.current) return;
    const resolveMember = member => {
      if (member === "all" || member === ALL_TRUNK_VLAN_RANGE) return ["all"];
      const named = deviceVlans.find(vlan => vlan.name === member);
      if (named) return [String(named.id)];
      return /^\d+(?:-\d+)?$/.test(member) ? parseTrunkVlanRange(member).map(String) : [member];
    };
    setValues(prev => ({...prev,
      switchportVlan: resolveMember(initial.values.switchportVlan)[0] || "",
      trunkVlans: initial.values.trunkVlans.flatMap(resolveMember),
    }));
    juniperL2Prefilled.current = true;
  }, [vlanData, isJuniper, mode]);
  // Cisco/Juniper may omit default VLAN 1 from configuration. Supply a UI option
  // without inventing a device VLAN entry or overriding an actual returned name.
  const vlanOptions = (isCisco || isJuniper) && !deviceVlans.some((vlan) => String(vlan.id) === "1")
    ? [{ id: "1", name: "default", state: "", enabled: true }, ...deviceVlans]
        .sort((left, right) => Number(left.id) - Number(right.id))
    : deviceVlans;
  const canPickVlan = Array.isArray(vlanOptions) && vlanOptions.length > 0;

  // selected VLAN ที่ device คืนมาแต่ไม่มีใน get_vlan_information ยังต้องมี option
  // ของตัวเอง มิฉะนั้น controlled select จะแสดงเป็นช่องว่าง ทุกยี่ห้อใช้ dropdown เดียวกัน
  const trunkVlanOptions = (() => {
    const byId = new Map(vlanOptions.map((vlan) => [String(vlan.id), vlan]));
    for (const vlan of values.trunkVlans) {
      const id = String(vlan).trim();
      const numericId = Number(id);
      if (id && id !== "all" && Number.isInteger(numericId) && !byId.has(id)) {
        byId.set(id, { id, name: "" });
      }
    }
    return [...byId.values()].sort((left, right) => Number(left.id) - Number(right.id));
  })();
  const canPickTrunkVlan = trunkVlanOptions.length > 0;
  const trunkAllowsAllInForm = values.trunkVlans.length === 1
    && (values.trunkVlans[0] === "all" || values.trunkVlans[0] === ALL_TRUNK_VLAN_RANGE);
  const selectedTrunkVlans = new Set(
    values.trunkVlans.filter((vlan) => vlan && vlan !== "all").map(String)
  );

  // แก้บั๊ก: ตอน Edit interface ที่มี DHCP pool ผูกกับวงของมันอยู่แล้ว (สร้างผ่าน
  // หน้า DHCP หรือ CLI) toggle "DHCP Server" เดิมขึ้นปิดเสมอเพราะไม่เคยเช็คย้อนกลับ
  // เลยว่ามี pool อยู่ในวงนี้หรือเปล่า - ดึง get_dhcp_pool_information มาเทียบ
  // network กับ interface ที่กำลังแก้ไข (ทั้ง ip และ prefix ต้องตรงกัน) ถ้าเจอ
  // sync toggle + pre-fill field ที่เกี่ยวข้องให้ตรงกับ pool จริงบนอุปกรณ์
  // Huawei ไม่มี DHCP ผ่าน NETCONF จึงไม่ fetch pool ตั้งแต่ต้น; hook ยังถูก
  // เรียกทุก render ตามกฎ React แต่ auto=false ปิด RPC เฉพาะยี่ห้อนี้
  const { data: dhcpPoolData } = getDeviceInformation(
    devId,
    "get_dhcp_pool_information",
    { auto: !isHuawei }
  );
  useEffect(() => {
    if (mode !== "edit" || !editTarget) return;
    if (!initial.values.ip) return;
    if (!dhcpPoolData?.normalized) return;
    if (isJuniper) {
      // A local-server binding is authoritative; a matching pool alone is not.
      if (!parseJuniperDhcpServerInterfaces(dhcpPoolData.result).includes(editTarget.name)) return;
      setOriginalDhcp(prev => prev || {mode: "server"});
    }
    const pools = parsePools(dhcpPoolData.result);
    if (!Array.isArray(pools)) return;
    const parsedIp = parseIpCidr(initial.values.ip);
    if (!parsedIp) return;
    const raw = editTarget.layer?.raw;
    const units = Array.isArray(raw?.unit) ? raw.unit : raw?.unit ? [raw.unit] : [];
    const unitName = editTarget.name.includes(".") ? editTarget.name.slice(editTarget.name.lastIndexOf(".") + 1) : "0";
    const unit = units.find(entry => String(entry.name) === unitName);
    const addresses = unit?.family?.inet?.address;
    const candidates = (Array.isArray(addresses) ? addresses : addresses ? [addresses] : [])
      .map(entry => parseIpCidr(entry.name)).filter(Boolean);
    const existing = isJuniper
      ? candidates.map(candidate => findExistingPoolForNetwork(pools, candidate.ip, candidate.prefix)).find(Boolean)
      : findExistingPoolForNetwork(pools, parsedIp.ip, parsedIp.prefix);
    if (!existing) {
      if (isJuniper) setValues(prev => prev.dhcpServer ? prev : {...prev, dhcpServer: true, dhcpMode: "server"});
      return;
    }
    const existingNetwork = parsePoolNetwork(existing.network); // network address จริงของ pool (ไม่ใช่ host IP ของ interface)
    if (!existingNetwork) return;
    const interfaceIp = parsedIp.ip;
    // เก็บไว้เผื่อ user กดปิด toggle ทีหลัง - ต้องรู้ name/network/exclude เดิม
    // เป๊ะถึงจะเรียก remove_dhcp_pool ถูก (ดู handleSubmit)
    setOriginalDhcp((prev) => prev && (!isJuniper || prev.mode === "relay") ? prev : { mode: "server", pool: {...existing, exclude: existing.excludeRanges} });
    setValues((prev) => {
      if (prev.dhcpServer) return prev; // ผู้ใช้เปิด/แก้เองแล้วระหว่างนี้ อย่าทับ
      return {
        ...prev,
        dhcpServer: true,
        dhcpStartAddress: existing.startAddress || "",
        dhcpEndAddress: existing.endAddress || "",
        dhcpGatewayMode: !existing.gateway ? "none" : existing.gateway && existing.gateway !== interfaceIp ? "specific" : "interface",
        dhcpGatewayIp: existing.gateway && existing.gateway !== interfaceIp ? existing.gateway : "",
        dhcpDnsMode: !existing.dns ? "none" : existing.dns && (existing.dns.split(",").filter(item => item.trim()).length !== 1 || existing.dns.trim() !== interfaceIp) ? "specific" : "interface",
        dhcpDnsIp: existing.dns && existing.dns.split(",")[0].trim() !== interfaceIp ? existing.dns.split(",")[0].trim() : "",
        dhcpDnsIps: existing.dns ? existing.dns.split(",").map(item => item.trim()).filter(Boolean) : [""],
        dhcpLease: leaseHoursInput(existing),
      };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dhcpPoolData]);

  // แก้บั๊กเดียวกันอีกจุด (Juniper เท่านั้น): toggle "DHCP Server" โหมด relay ก็
  // ขึ้นปิดเสมอตอน Edit เหมือนกัน แต่คนละสาเหตุกับ pool ด้านบน - buildInitialValues
  // เดิมพึ่ง `layerInfo?.helpers?.[0]` (มาจาก editTarget.layer ที่ interfaces.jsx
  // ส่งมา) ซึ่งสำหรับ Juniper คือ `parseJuniperInterfaceLayers()` ที่ hardcode
  // `helpers: []` ตายตัวเสมอ (comment เดิมเข้าใจผิดว่า Juniper's dhcp-relay เป็น
  // global scope ไม่ผูก interface - จริงๆ อัปเดตให้ผูก interface ได้แล้วตั้งแต่
  // รอบก่อนหน้า ดู comment ยาวใน dhcp.jsx's parseJuniperDhcpRelay) เลยไม่มีทาง
  // เจอ relay ที่ผูกอยู่จริงเลยสำหรับ Juniper (Cisco ไม่เจอปัญหานี้ - backend เอง
  // normalize helpers ต่อ interface มาให้ตรงอยู่แล้ว) - ใช้ dhcpPoolData เดิม
  // (ดึงมาแล้วด้านบน) ผ่าน parseDhcpRelay() หา relay ที่ interface ตรงกับตัวที่
  // กำลังแก้อยู่แทน
  useEffect(() => {
    if (!isJuniper || mode !== "edit" || !editTarget) return;
    if (!dhcpPoolData?.normalized) return;
    const relayRows = parseDhcpRelay(dhcpPoolData.result, null) || [];
    const existing = relayRows.find((row) => row.interface === editTarget.name);
    if (!existing) return;
    setOriginalDhcp((prev) => prev || { mode: "relay", relayIp: existing.server });
    setValues((prev) => {
      if (prev.dhcpServer) return prev; // ผู้ใช้เปิด/แก้เองแล้วระหว่างนี้ หรือ pool effect ตั้งไปแล้ว อย่าทับ
      return { ...prev, dhcpServer: true, dhcpMode: "relay", dhcpRelayIp: existing.server };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dhcpPoolData]);

  // auto-fill "Address range" ด้วย Adaptive Reservation (ดู computeAdaptiveDhcpRange
  // ด้านบน) - คำนวณใหม่ "ทุกครั้ง" ที่ IP เปลี่ยน (ไม่ใช่แค่ครั้งแรกตอนช่องว่าง)
  // ตราบใดที่ผู้ใช้ยังไม่เคยพิมพ์เองในช่องนี้ (track ด้วย ref แยก ไม่ใช่เช็คแค่
  // "ช่องว่างไหม") - เดิมเช็คแค่ "ว่างไหม" มีบั๊กจริง: ช่อง IP เป็น text input
  // ธรรมดายิง onChange ทุกตัวอักษร ถ้า parse ผ่านตอนพิมพ์ยังไม่ครบ (เช่นได้
  // network ผิดเป็น 0.0.0.0) ค่าที่คำนวณผิดจะค้างอยู่ตลอดไปเพราะช่องไม่ว่างแล้ว
  // ไม่มีทางคำนวณใหม่ให้ถูกอีกเลยแม้พิมพ์ IP จริงเสร็จสมบูรณ์แล้วก็ตาม - เปลี่ยน
  // เป็น "ยังไม่เคยแก้เอง" แทน "ว่าง" แก้ปัญหานี้ตรงจุด
  const dhcpRangeUserEditedRef = useRef({start: false, end: false});
  useEffect(() => {
    if (isHuawei || layer !== LAYER.L3 || ipMode !== IP_MODE.STATIC
        || !values.dhcpServer || values.dhcpMode !== "server") return;
    // An existing pool's real range is authoritative, including multi-ranges.
    // Edit without a server pool is a new DHCP enable and needs defaults too.
    if (mode === "edit" && originalDhcp?.mode === "server" && originalDhcp.pool) return;
    const parsed = parseIpCidr(values.ip);
    const networkIp = parsed ? networkAddressOf(parsed.ip, parsed.prefix) : null;
    const range = networkIp ? computeAdaptiveDhcpRange(networkIp, parsed.prefix) : null;
    setValues((prev) => ({ ...prev,
      dhcpStartAddress: dhcpRangeUserEditedRef.current.start ? prev.dhcpStartAddress : range?.start || "",
      dhcpEndAddress: dhcpRangeUserEditedRef.current.end ? prev.dhcpEndAddress : range?.end || "",
    }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [values.ip, ipMode, values.dhcpServer, values.dhcpMode, layer, mode, originalDhcp, isHuawei]);

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  function toggleTrunkVlan(vlan) {
    setValues((prev) => {
      const selected = [...new Set(prev.trunkVlans.filter(value => value && value !== "all" && value !== ALL_TRUNK_VLAN_RANGE).map(String))];
      const id = String(vlan);
      return { ...prev, trunkVlans: selected.includes(id)
        ? selected.filter(value => value !== id) : [...selected, id] };
    });
  }

  // All uses the vendor's all-VLAN representation; Specific uses VLAN dropdowns.
  function setTrunkAllowMode(mode) {
    setValues((prev) => {
      if (mode === "all") return { ...prev, trunkVlans: ["all"] };
      const selected = prev.trunkVlans.filter((vlan) => vlan && vlan !== "all" && vlan !== ALL_TRUNK_VLAN_RANGE);
      return { ...prev, trunkVlans: selected.length ? selected : [""] };
    });
  }

  // ปิด toggle "DHCP Server" ตรงๆ ได้เฉพาะตอนที่ไม่เคยมี pool/relay ผูกอยู่จริง
  // (originalDhcp เป็น null) - ถ้ามีจริง ต้องเด้ง confirm ก่อนเสมอ (ล้อ pattern
  // เดียวกับ toggle "Enable OSPF" ที่ ospf_route.jsx ใช้ - เปลี่ยน state ทันทีไม่ได้
  // ถ้ามีผลลบล้าง config จริงบนอุปกรณ์ ต้องให้ user ยืนยันก่อนเสมอ) เปิด toggle
  // (checked=true) ไม่ต้องยืนยันอะไร (ไม่มีอะไรถูกลบ)
  function handleDhcpToggle(checked) {
    if (!checked && originalDhcp) {
      setShowDhcpOffConfirm(true);
      return;
    }
    setField("dhcpServer", checked);
  }

  function confirmDhcpOff() {
    setField("dhcpServer", false);
    setShowDhcpOffConfirm(false);
  }

  function handleIfTypeChange(nextType) {
    setIfType(nextType);
    // Sub-interface และ VLAN Interface (SVI/irb) เป็น Layer 3 โดยธรรมชาติเสมอ
    // (ไม่มี concept L2 switchport สำหรับสองแบบนี้เลย) - บังคับทันที ไม่ต้องถาม
    // Layer 2/3 ซ้ำอีกรอบ (ตัวเลือก Layer จะไม่โผล่ให้เห็นด้วยตอนไม่ใช่ "Interface")
    if (nextType !== IF_TYPE.INTERFACE) {
      setLayer(LAYER.L3);
    }
    // Juniper ไม่มีฟังก์ชัน irb+dhcp เลย (set_interface_vlan รองรับแค่ static) -
    // บังคับ static ทันทีเหมือนที่ทำกับ Sub-interface อยู่แล้ว
    if (nextType === IF_TYPE.SUB_INTERFACE || ((isJuniper || isHuawei) && nextType === IF_TYPE.VLAN)) {
      setIpMode(IP_MODE.STATIC);
    }
  }

  // หา {interface_type, interface_id} ของ interface ที่ฟอร์มกำลังตั้ง (ใช้กับ
  // DHCP relay ที่ต้องผูก helper-address บน interface) - ล้อ logic เดียวกับ
  // resolveCommand: VLAN -> Vlan<id>, sub-interface -> <parent>.<vlan>
  function resolveInterfaceTypeId(v) {
    if (ifType === IF_TYPE.VLAN) {
      return { interfaceType: "Vlan", interfaceId: String(v.vlanId) };
    }
    const { interfaceType, interfaceId } = splitInterfaceName(v.interfaceName);
    if (ifType === IF_TYPE.SUB_INTERFACE) {
      return { interfaceType, interfaceId: `${interfaceId}.${v.vlanId}` };
    }
    return { interfaceType, interfaceId };
  }

  // แกะ {interface_type, interface_id, unit} ของ interface ที่ฟอร์มกำลังตั้งไว้
  // ใช้ผูก DHCP local-server (Juniper เท่านั้น - ดู set_dhcp_server_interface)
  // ต้องแยก unit ออกมาต่างหาก ไม่ฝังเป็นส่วนหนึ่งของ interfaceId แบบที่
  // resolveInterfaceTypeId ทำ (ฟังก์ชันนั้นออกแบบมาให้ nc:interface_id ที่มีจุด
  // อยู่แล้วสำหรับ relay ที่ไม่ได้ใช้ unit จริง - set_dhcp_server_interface รับ
  // unit เป็น int แยกต่างหากเหมือน apply_acl_interface)
  function resolveDhcpServerBinding(v) {
    if (ifType === IF_TYPE.VLAN) {
      return { interfaceType: "irb", interfaceId: "", unit: Number(v.vlanId) };
    }
    const { interfaceType, interfaceId } = splitInterfaceName(v.interfaceName);
    if (ifType === IF_TYPE.SUB_INTERFACE) {
      return { interfaceType, interfaceId, unit: Number(v.vlanId) };
    }
    return { interfaceType, interfaceId, unit: 0 };
  }

  // เตรียม params ของ set_dhcp_pool (โหมด server) + validate ทั้งหมดก่อน (คืน
  // {error} ถ้าไม่ผ่าน) - interfaceIp/interfacePrefix คือ IP/prefix ของ interface
  // ที่เพิ่งตั้ง - Network ของ pool ต้องเป็นวงเดียวกับ interface นี้เสมอ (pool ที่
  // ผูกกับ interface จะอยู่วงอื่นไปไม่ได้อยู่แล้ว) เลยคำนวณจาก IP/prefix ที่กรอกไว้
  // ให้ interface โดยตรง ไม่ต้องให้ผู้ใช้พิมพ์ Network/Address range ซ้ำเองอีกที -
  // exclude แค่ gateway address เดียวพอ (Juniper's set_dhcp_pool กัน gateway ออก
  // จาก usable range ให้เองอัตโนมัติอยู่แล้ว แต่ Cisco ไม่กันเอง - ส่ง exclude ให้
  // ทั้งคู่เผื่อไว้ ไม่กระทบ Juniper เพราะกันซ้ำแค่ไม่เกิดอะไรขึ้น)
  function buildDhcpPoolParams(v, interfaceIp, interfacePrefix, isJuniper) {
    const networkIp = networkAddressOf(interfaceIp, interfacePrefix);
    if (!networkIp) return { error: "Invalid interface IP/Subnet; unable to compute DHCP network" };
    const network = `${networkIp}/${interfacePrefix}`;

    // แปลง "ช่วงที่จะแจก" (auto-fill ไว้แล้วเป็น host .11-.200 - แก้เองได้) เป็น
    // exclude แบบกลับด้าน (ดู computeDhcpExclusions) แล้วเติม gateway address
    // เข้าไปเผื่อไว้อีกทีเสมอ (เผื่อผู้ใช้แก้ range เองจนครอบคลุม gateway พอดี -
    // ไม่อยากแจก IP ทับ gateway ออกไปไม่ว่ากรณีไหน)
    const startAddress = v.dhcpStartAddress.trim();
    const endAddress = v.dhcpEndAddress.trim();
    if (![startAddress, endAddress].every(value => validateIPv4Input(value, {required: false}).valid)) return {error: "Start and End addresses must be valid IPv4 addresses"};
    if (Boolean(startAddress) !== Boolean(endAddress)) return {error: "Please fill in both Start and End addresses, or leave both blank"};
    const exclude = computeDhcpExclusions(network, startAddress ? `${startAddress}-${endAddress}` : "");
    if (exclude === null) {
      return { error: "Invalid Start or End address: out of network range or Start address is greater than End address" };
    }

    const gateway = v.dhcpGatewayMode === "none" ? null : v.dhcpGatewayMode === "interface" ? interfaceIp : v.dhcpGatewayIp.trim();
    const dns = v.dhcpDnsMode === "none" ? [] : v.dhcpDnsMode === "interface" ? [interfaceIp]
      : (v.dhcpDnsIps || [v.dhcpDnsIp]).map(item => item.trim());
    if (gateway !== null && !gateway) return { error: "Please enter Gateway IP" };
    if (gateway !== null && !validateIPv4Input(gateway).valid) return {error: "Gateway must be a valid IPv4 address"};
    if (v.dhcpDnsMode !== "none" && (!dns.length || dns.some(item => !item))) return { error: "Please fill in all DNS IP fields" };
    if (dns.length > 3) return {error: "A maximum of 3 DNS servers can be specified"};
    if (dns.some(item => !validateIPv4Input(item).valid)) return {error: "DNS must be a valid IPv4 address"};

    // ตั้งชื่อ pool จาก network/prefix แทนชื่อ interface - เดิมใช้ v.interfaceName
    // แต่โหมด Sub-interface ช่อง "Interface" เก็บแค่ physical parent เท่านั้น (เช่น
    // "GigabitEthernet4") ไม่มี VLAN ID ต่อท้าย ทำให้ sub-interface ทุกตัวที่แชร์
    // parent เดียวกัน (Gi4.10/4.20/4.30) ได้ pool name ซ้ำกันหมด -> ตั้งค่าทับกัน
    // บนอุปกรณ์จริง (pool name เป็น key) - network+prefix ไม่มีทางซ้ำกันได้อยู่แล้ว
    // เพราะแต่ละ pool ต้องคนละ network เสมอ - เจอบั๊กจริง (Juniper): เดิม replace
    // แค่ "/" ตัวเดียว เหลือจุดจาก octet ของ IP ค้างอยู่เต็มๆ (เช่น
    // "POOL_10.1.2.0-24") ซึ่ง Junos ปฏิเสธชื่อ pool ที่มี "." ทันที ("Must be a
    // string beginning with a number or letter and consisting of no more than 63
    // total letters, numbers, dashes and underscores") - ยืนยันจริงจากอุปกรณ์ว่า
    // นี่คือสาเหตุที่ enable DHCP Server พร้อมสร้าง interface แล้ว pool ไม่ถูก
    // สร้างเลย (edit-config ตอบ rpc-error กลับมา ไม่ใช่ exception - ดู result.ok
    // check ด้านล่างที่เพิ่งเพิ่มด้วย) - แทนที่ "." ทุกตัวด้วย "-" ไปด้วยเลย
    const params = {
      name: `POOL_${network.replace(/[./]/g, "-")}`,
      network,
      gateway,
      dns,
      // เติม gateway เข้า exclude เสมอ (กัน DHCP แจก IP ทับ gateway) แต่**เฉพาะ
      // ตอนที่ยังไม่ถูก exclude คลุมอยู่แล้ว** (ดู isIpAlreadyExcluded) - ส่งเป็น
      // IP เดี่ยว ไม่ใช่ "gateway-gateway" (เจอบั๊กจริงรอบแรก: low==high ใน
      // <low-high-address-list> โดน Cisco YANG schema ปฏิเสธ) - **เจอบั๊กจริงรอบ
      // 2 ต่อ (BR2-Router)**: แก้รอบแรกแล้ว error เดิมยังไม่หาย เพราะ gateway
      // (เช่น .1) มักตกอยู่ "นอก" ช่วงที่จะแจก (เช่น .11-.200) ซึ่ง
      // computeDhcpExclusions() คำนวณ exclude ครอบ .1 ไปเป็นช่วงอยู่แล้ว (เช่น
      // "x.1-x.10") เติม gateway ซ้ำเป็น entry เดี่ยวอีกตัวเลยกลายเป็น 2 entry
      // ที่ค่าเริ่มต้นซ้ำ/ทับกันเอง - Cisco ปฏิเสธด้วย error เดียวกัน
      // ("inconsistent value") แต่คนละสาเหตุกับรอบแรก
      exclude: !gateway || isIpAlreadyExcluded(gateway, exclude) ? exclude : [...exclude, gateway],
    };
    if (startAddress) {
      params.start_address = startAddress;
      params.end_address = endAddress;
    }
    const lease = v.dhcpLease.trim();
    const oldPool = originalDhcp?.mode === "server" ? originalDhcp.pool : null;
    if (oldPool) {
      if (oldPool.rangeDataValid === false) return {error: "Incomplete original IP range data; pool update aborted to prevent data loss"};
      const oldNetwork = parsePoolNetwork(oldPool.network);
      const sameNetwork = oldNetwork && oldNetwork.prefix === interfacePrefix && oldNetwork.ip === networkIp;
      if (sameNetwork) {
        params.name = oldPool.name;
        params.previous = {
          pool: oldPool.poolConfig || {name: oldPool.name, id: oldPool.name},
          exclude: oldPool.excludeRanges || oldPool.exclude || [],
          ...(oldPool.startAddress ? {start_address: oldPool.startAddress} : {}),
          ...(oldPool.endAddress ? {end_address: oldPool.endAddress} : {}),
        };
        const unchanged = startAddress === oldPool.startAddress && endAddress === oldPool.endAddress;
        if (isJuniper && oldPool.configuredRanges) {
          params.configured_ranges = unchanged ? oldPool.configuredRanges : startAddress ? [{name: "RANGE-1", low: startAddress, high: endAddress}] : [];
          params.configured_excluded_ranges = oldPool.excludedRangeEntries || [];
          delete params.start_address;
          delete params.end_address;
        } else if (unchanged) {
          delete params.start_address;
          delete params.end_address;
        }
        if (isJuniper) {
          if (oldPool.excludeRanges) params.exclude = oldPool.excludeRanges;
        } else {
          const explicitExclusions = filterExplicitExclusions(
            oldPool.excludeRanges || oldPool.exclude,
            oldPool.network,
            oldPool.startAddress,
            oldPool.endAddress
          );
          const newDerived = startAddress && endAddress
            ? computeDhcpExclusions(network, `${startAddress}-${endAddress}`) || []
            : [];
          const gatewayNeeded = gateway && !isIpAlreadyExcluded(gateway, newDerived) && !isIpAlreadyExcluded(gateway, explicitExclusions);
          const desiredExplicit = gatewayNeeded ? [...explicitExclusions, gateway] : explicitExclusions;
          if (desiredExplicit.length > 0) {
            params.exclude = desiredExplicit;
          } else {
            delete params.exclude;
          }
        }
      }
    }
    if (!isJuniper && oldPool?.leaseInfinite && lease === "infinite") params.lease_infinite = true;
    else if (isJuniper && oldPool?.leaseSeconds > 0 && oldPool.leaseSeconds % 60 !== 0 && lease === leaseHoursInput(oldPool)) {
      params.lease_seconds = oldPool.leaseSeconds;
    } else if (lease) {
      const minutes = hoursToLeaseMinutes(lease);
      if (minutes === null) return {error: "Lease time must be greater than 0 hours and convert cleanly to minutes, e.g. 0.5, 1.5, or 24"};
      params.lease_minutes = minutes;
    }
    return { params };
  }

  async function ciscoSwitchportCapability() {
    if (!isCisco || ifType !== IF_TYPE.INTERFACE) return false;
    let row = layerRows.find(entry => entry.name === values.interfaceName)
      || (mode === "edit" ? editTarget?.layer : null);
    if (typeof row?.switchport_capable !== "boolean") {
      const latest = await runDeviceCommand(devId, "get_switchport_information", {});
      if (!latest?.normalized || !Array.isArray(latest.result)) throw new Error("Failed to read Cisco port capability; IP configuration aborted");
      row = latest.result.find(entry => entry.name === values.interfaceName);
    }
    if (typeof row?.switchport_capable !== "boolean") throw new Error("Cisco port switchport capability is unknown; please reload data");
    return row.switchport_capable;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    // Interface identity is immutable in Edit mode.  Keep this check in the
    // submit path as well as disabling the field below so a stale render or a
    // value changed through the DOM cannot redirect an edit to another port.
    if (mode === "edit" && (
      ifType !== initial.ifType
      || (needsInterfacePicker && values.interfaceName !== initial.values.interfaceName)
    )) {
      setError("Interface cannot be changed in Edit mode. Please close this form and select the interface you want to edit.");
      return;
    }

    // VLAN ID ต้องผ่าน validator กลางก่อน logic อื่นทั้งหมด (edit guard, duplicate guard,
    // สร้างชื่อ interface, DHCP binding) - ไม่พึ่ง UI และห้ามแต่ละ branch แปลง Number() เอง
    // ทุกที่ต่อจากนี้ใช้ค่า canonical จาก submitVlanId เท่านั้น (Layer 2 ไม่มี VLAN ID ของ interface)
    const needsVlanId = layer !== LAYER.L2 && (ifType === IF_TYPE.SUB_INTERFACE || ifType === IF_TYPE.VLAN);
    const checkedVlan = validateVlanId(values.vlanId, { required: needsVlanId });
    if (needsVlanId && !checkedVlan.valid) {
      setVlanIdError(checkedVlan.error);
      setError(checkedVlan.error);
      return;
    }
    setVlanIdError("");
    const vlanIdText = checkedVlan.text;

    if (mode === "edit"
        && (initial.ifType === IF_TYPE.SUB_INTERFACE || (initial.ifType === IF_TYPE.VLAN))
        && vlanIdText !== String(initial.values.vlanId)) {
      setError("VLAN ID cannot be changed in Edit mode. Please delete and recreate.");
      return;
    }

    if (isJuniper && mode === "edit" && (!dhcpPoolData?.normalized || !dhcpPoolData.result?.payload?.data?.configuration)) {
      setError("Failed to read original DHCP data. Please wait or reload before editing.");
      return;
    }
    if (isJuniper && mode === "edit" && !editTarget?.layer?.raw?.name) {
      setError("Failed to read original interface configuration. Please reload before editing.");
      return;
    }

    // กัน state ที่อาจค้างจาก render เก่า/การแก้ DOM: Huawei ห้ามไปถึงคำสั่ง
    // DHCP หรือ sub-interface แม้ UI จะซ่อนตัวเลือกไว้แล้ว
    if (isHuawei && (ifType === IF_TYPE.SUB_INTERFACE || ipMode === IP_MODE.DHCP)) {
      setError("Huawei CE12800 does not support DHCP and sub-interfaces via NETCONF");
      return;
    }

    // Layer 2 (switchport): ตัด field ทั้งหมดที่เกี่ยวกับ IP/DHCP/sub-interface
    // ออกไป เหลือแค่ interface + mode (access/trunk) + VLAN ที่จะเข้า - ยิง
    // apply_interface_to_vlan ตัวเดียวจบ ไม่ผ่าน resolveCommand/DHCP logic ของ
    // Layer 3 เลย
    if (layer === LAYER.L2) {
      if (!values.interfaceName) {
        setError("Please select an interface");
        return;
      }
      // ทั้งสองยี่ห้อรับค่าชุดเดียวกันแล้ว: list ของเลข VLAN หรือ exact "1-4094"
      // สำหรับทุก VLAN (เดิม Cisco รวมเป็นสตริงคั่นจุลภาคส่งไป ซึ่งตกด่าน validate
      // หลัง annotation ฝั่ง translator เปลี่ยนเป็น list)
      const trunkAllowedVlans = values.trunkVlans
        .map((vlan) => vlan.trim())
        .filter(Boolean);
      const trunkAllowsAll =
        trunkAllowedVlans.length === 1 &&
        (trunkAllowedVlans[0] === "all" || trunkAllowedVlans[0] === ALL_TRUNK_VLAN_RANGE);
      const specificTrunkVlans = trunkAllowedVlans
        .filter((vlan) => vlan !== "all" && vlan !== ALL_TRUNK_VLAN_RANGE);
      if (values.switchportMode === SWITCHPORT_MODE.ACCESS && !values.switchportVlan) {
        setError("Please select a VLAN to join");
        return;
      }
      const checkedAccessVlan = validateVlanId(values.switchportVlan, { required: false });
      if (values.switchportMode === SWITCHPORT_MODE.ACCESS && !checkedAccessVlan.valid) {
        setError(`Access VLAN must be between ${VLAN_ID_MIN} and ${VLAN_ID_MAX}`);
        return;
      }
      const missingTrunkVlans = !trunkAllowsAll && !specificTrunkVlans.length;
      if (values.switchportMode === SWITCHPORT_MODE.TRUNK && missingTrunkVlans) {
        setError("Please enter at least one VLAN for Trunk");
        return;
      }
      if (trunkAllowedVlans.includes("all") && trunkAllowedVlans.length !== 1) {
        setError("All VLANs cannot be combined with other VLAN numbers");
        return;
      }
      // Specific: ทุกค่าต้องเป็น VLAN ID เดี่ยว 1-4094 (all/1-4094 ของโหมด All ไม่ผ่านทางนี้)
      // และห้ามซ้ำ - ช่วงอย่าง 10-20 ไม่รองรับใน Specific เหมือนเดิม
      let checkedTrunk = { ok: true, list: [] };
      if (values.switchportMode === SWITCHPORT_MODE.TRUNK && !trunkAllowsAll) {
        const seenTrunk = new Set();
        for (const vlan of specificTrunkVlans) {
          const checked = validateVlanId(vlan);
          if (!checked.valid) {
            setError(/^\d+-\d+$/.test(vlan)
              ? "Trunk VLANs must be individual numbers; ranges such as 10-20 are not supported"
              : `Trunk VLAN "${vlan}" is invalid: VLAN ID must be between ${VLAN_ID_MIN} and ${VLAN_ID_MAX}`);
            return;
          }
          if (seenTrunk.has(checked.value)) {
            setError(`Trunk VLAN ${checked.value} is selected more than once`);
            return;
          }
          seenTrunk.add(checked.value);
          checkedTrunk.list.push(checked.value);
        }
      }
      const { interfaceType, interfaceId } = splitInterfaceName(values.interfaceName);
      const params = {
        interface_type: interfaceType,
        interface_id: interfaceId,
        mode: values.switchportMode,
        description: values.description.trim() || (isHuawei && !initial.values.description ? undefined : ""),
      };
      if (values.switchportMode === SWITCHPORT_MODE.ACCESS) {
        params.vlan_id = checkedAccessVlan.value;
      } else {
        // Juniper คงรูปแบบเดิมคือสตริงคั่นจุลภาค เพราะ translator ของมันแตกสตริง
        // เป็น members เองและรองรับ token "all" ของ Junos ตรง ๆ ส่วน Cisco กับ
        // Huawei ใช้สัญญาเดียวกันแล้วคือ list ของเลข VLAN หรือ exact "1-4094"
        if (isJuniper) {
          params.trunk_allowed_vlans = trunkAllowsAll ? trunkAllowedVlans.join(",") : checkedTrunk.list.join(",");
        } else {
          params.trunk_allowed_vlans = trunkAllowsAll
            ? ALL_TRUNK_VLAN_RANGE
            : checkedTrunk.list;
        }
      }

      // 12 ก.ย. 2026: ข้อสรุปเดิมที่ว่า CE12800 ไม่รับ container ของสองโมดูลใน
      // edit-config เดียวนั้นผิด ต้นตอของ "Invalid RPC request" รอบนั้นคือ XML ของ
      // get_vlan_information ที่ไม่ well-formed (BUG-109) ซึ่งแก้แล้ว และผู้ใช้ยิง
      // payload สองโมดูลตรงกับอุปกรณ์แล้วผ่าน Huawei จึงส่ง shutdown ไปกับ
      // apply_interface_to_vlan ให้เป็น RPC เดียวที่ atomic จาก rollback-on-error
      // Cisco/Juniper ยังแยกสองคำสั่งตามเดิมเพราะ translator ของสองยี่ห้อไม่รับ
      // shutdown ในฟังก์ชันนี้
      if (isHuawei) params.shutdown = !values.switchportEnabled;
      // Cisco: เปิด switchport, ลบ IP เดิม, เขียน mode/VLAN และตั้งสถานะพอร์ต อยู่ใน
      // element ของ interface เดียวกันทั้งหมด จึงส่งไปกับคำสั่งเดียวแล้วได้ RPC เดียว
      // ที่ atomic แทนที่จะยิง set_switchport, apply_interface_to_vlan และ
      // set_no_shutdown เรียงกันสามครั้ง
      //
      // create: ยังไม่รู้สถานะจริงของพอร์ตที่เพิ่งเลือกจาก dropdown จึงสั่งเปิด
      // switchport ไว้ก่อนเสมอ (เขียนค่าเดิมซ้ำได้ ไม่มีผลข้างเคียง) ส่วน edit รู้
      // สถานะจาก prefill แล้ว จึงสั่งเฉพาะตอนพอร์ตยังเป็น Layer 3
      const ciscoNeedsL2Entry = isCisco && (mode !== "edit" || initial.layer === LAYER.L3);
      if (isCisco) {
        params.shutdown = !values.switchportEnabled;
        if (ciscoNeedsL2Entry) params.switchport = true;
      }

      // ขากลับ Layer 3 -> Layer 2 ก็ติดกฎเดียวกันแต่คนละทิศ: เขียน l2Attribute ใส่
      // พอร์ตที่ยังเป็น Layer 3 ไม่ได้ อุปกรณ์ตอบ "The interface is not a L2 interface"
      // และ IP ที่ตั้งไว้ก็ใช้ในโหมด Layer 2 ไม่ได้ ต้องล้างก่อน ทั้งสามขั้นจึงส่งเป็น
      // ชุดเดียวเข้า candidate แล้ว commit ครั้งเดียว ขั้นหลังเห็นผลของขั้นหน้าแล้ว
      // และถ้าล้มกลางทางพอร์ตยังเป็น Layer 3 พร้อม IP เดิมครบ
      const huaweiNeedsL3Exit = isHuawei && mode === "edit" && initial.layer === LAYER.L3;

      setSubmitting(true);
      try {
        if (isCisco) {
          const commands = [{command: "apply_interface_to_vlan", parameters: params}];
          if (originalDhcp?.mode === "server" && originalDhcp.pool) commands.push({command: "remove_dhcp_pool", parameters: {
            name: originalDhcp.pool.name, network: originalDhcp.pool.network,
            exclude: originalDhcp.pool.excludeRanges ?? originalDhcp.pool.exclude,
          }});
          assertCommandOk(await runDeviceTransaction(devId, commands), "Failed to configure Layer 2; entire batch cancelled");
          onSaved();
          return;
        }
        if (huaweiNeedsL3Exit) {
          const currentBrief = briefRows.find(row => row.name === values.interfaceName) || editTarget?.brief || {};
          const fallbackIp = parseIpCidr(initial.values.ip)?.ip;
          const previousAddresses = [...new Set([
            ...(Array.isArray(currentBrief.addresses) ? currentBrief.addresses : []),
            ...(fallbackIp ? [fallbackIp] : []),
          ].filter(Boolean))];
          const resetParameters = {
            interface_type: interfaceType,
            interface_id: interfaceId,
            previous_addresses: previousAddresses,
            reset_description: Boolean(initial.values.description),
            reset_mtu: Boolean(initial.values.mtu),
            reset_admin_status: Boolean(toDisplayText(currentBrief.admin_status)),
          };
          const commands = [];
          // Huawei refuses portswitch while routed IFM leaves remain. Remove
          // every app-managed L3 value first; the final command restores the
          // requested description/admin status after entering Layer 2.
          if (previousAddresses.length || resetParameters.reset_description
              || resetParameters.reset_mtu || resetParameters.reset_admin_status) {
            commands.push({command: "prepare_interface_for_l2", parameters: resetParameters});
          }
          // The cleanup already deleted the old description. If the user also
          // wants it blank, omitting it here avoids deleting the same leaf a
          // second time (Huawei returns data-missing for duplicate delete).
          if (resetParameters.reset_description && !values.description.trim()) {
            params.description = undefined;
          }
          commands.push(
            {
              command: "set_switchport",
              parameters: { interface_type: interfaceType, interface_id: interfaceId, switchport: true },
            },
            { command: "apply_interface_to_vlan", parameters: params },
          );
          assertCommandOk(
            await runDeviceTransaction(devId, commands),
            "Failed to change interface to Layer 2; entire batch cancelled"
          );
          onSaved();
          return;
        }
        if (isJuniper) {
          const shutdownCommand = values.switchportEnabled ? "set_no_shutdown" : "set_shutdown";
          const binding = resolveDhcpServerBinding(values);
          const apiBinding = {interface_type: binding.interfaceType, interface_id: binding.interfaceId, unit: binding.unit};
          const latest = await runDeviceCommand(devId, "get_running_config", {});
          const configuration = latest?.normalized ? latest.result?.payload?.data?.configuration : null;
          if (!configuration || (mode === "edit" && !configuration.interfaces)) throw new Error("Failed to read latest Interface/DHCP configuration; changes not saved");
          const poolCleanup = mode === "edit" ? juniperInterfacePoolCleanup({configuration, binding: apiBinding, pools: parsePools(latest.result), requirePool: originalDhcp?.mode === "server"}) : [];
          const commands = juniperInterfaceSaveSteps({
            interfaceStep: {command: "apply_interface_to_vlan", parameters: params},
            binding: apiBinding,
            originalDhcp, dhcpAction: null,
            configuration, poolCleanup,
          });
          await runDeviceTransaction(devId, [...commands,
            {command: shutdownCommand, parameters: {interface_type: interfaceType, interface_id: interfaceId}},
          ]);
          onSaved();
          return;
        }
        await runDeviceCommand(devId, "apply_interface_to_vlan", params);
        onSaved();
      } catch (err) {
        setError(err.detail || err.message || "Failed to configure switchport");
      } finally {
        setSubmitting(false);
      }
      return;
    }

    // Guardrail: ห้ามสร้าง/แก้ Sub-interface ให้ VLAN ID ซ้ำกับ unit ที่มีอยู่แล้ว
    // บน parent port เดียวกัน (เช่น Gi4.10 มีอยู่แล้ว ห้ามสร้าง Gi4.10 ซ้ำอีกตัว) -
    // เช็คจาก interfaceOptions ดิบ (ยังไม่ผ่าน filter ตัด "." ทิ้ง) ไม่ต้อง query
    // เพิ่ม - ยกเว้นกรณีกำลังแก้ไข sub-interface ตัวเดิมโดยไม่ได้เปลี่ยน VLAN ID
    // เลย (เทียบกับ editTarget.name ตรงๆ ไม่ให้ชนกับตัวเอง)
    if (ifType === IF_TYPE.SUB_INTERFACE) {
      const candidateName = `${values.interfaceName}.${vlanIdText}`;
      const isSameAsEditTarget = mode === "edit" && editTarget?.name === candidateName;
      if (!isSameAsEditTarget && interfaceOptions.includes(candidateName)) {
        setError(`VLAN ID ${vlanIdText} is already in use as a sub-interface on ${values.interfaceName} - please choose another VLAN ID`);
        return;
      }
    }

    // โหมด static ต้องกรอก ip มาพร้อม /subnet หรือ /prefix ในช่องเดียวกัน
    // ค่าที่เหลือทั้งหมดใช้ submitValues ซึ่งพก VLAN ID canonical ที่ตรวจแล้วเท่านั้น
    let submitValues = needsVlanId ? { ...values, vlanId: vlanIdText } : values;
    if (ipMode === IP_MODE.STATIC) {
      const parsed = validateIPv4Input(values.ip, {mode: "cidr"});
      if (!parsed.valid) {
        setError(parsed.error);
        return;
      }
      submitValues = { ...submitValues, ip: parsed.address, mask: parsed.prefix };
    }

    // Juniper detaches conflicting bindings before adding the new service in
    // the transaction below; users do not need a separate disable/save cycle.

    // DHCP เปิดได้เฉพาะโหมด static (ต้องมี IP คงที่) - validate ก่อนส่งอะไรไป
    // อุปกรณ์ ถ้าไม่ผ่านจะได้ไม่ตั้ง interface ไปแล้วค้าง - server=set_dhcp_pool,
    // relay=set_dhcp_relay (helper-address บน interface)
    let dhcpAction = null;
    if (submitValues.dhcpServer && ipMode === IP_MODE.STATIC) {
      if (submitValues.dhcpMode === "relay") {
        const helper = submitValues.dhcpRelayIp.trim();
        if (!validateIPv4Input(helper).valid) {
          setError("Please enter a valid IPv4 address for DHCP Server (helper address)");
          return;
        }
        // Juniper's set_dhcp_relay ผูก interface จริงแล้ว (forwarding-options/
        // dhcp-relay/group/interface) ต้องส่ง unit แยกต่างหากเหมือน
        // set_dhcp_server_interface (resolveDhcpServerBinding แกะ unit แยกให้ +
        // ใช้ "irb" ถูกต้องสำหรับ Juniper's VLAN Interface) - Cisco ยังใช้
        // resolveInterfaceTypeId เดิม (ไม่มี unit concept + VLAN Interface ต้อง
        // เป็น "Vlan<id>" ไม่ใช่ "irb")
        const binding = isJuniper ? resolveDhcpServerBinding(submitValues) : resolveInterfaceTypeId(submitValues);
        dhcpAction = {
          command: "set_dhcp_relay",
          parameters: {
            interface_type: binding.interfaceType,
            interface_id: binding.interfaceId,
            helper_ip: helper,
            ...(isJuniper ? { unit: binding.unit } : {}),
          },
        };
      } else {
        const result = buildDhcpPoolParams(submitValues, submitValues.ip, submitValues.mask, isJuniper);
        if (result.error) {
          setError(result.error);
          return;
        }

        // (BUG-78 / ระลอก C) ถ้าแก้ไข interface ที่ IP เปลี่ยนวง (Subnet เปลี่ยน) โดยยังเปิด DHCP Server
        // และเดิมมี pool เก่าอยู่จริง ให้ส่ง replace_name เพื่อให้ translator ทำการลบ pool เก่า
        // และสร้าง pool ใหม่ใน edit-config ก้อนเดียวกันอย่าง Atomic (1 action = 1 RPC)
        // **ห้ามส่ง replace_name ถ้าเป็นวงเดิม** (เปลี่ยนแค่ host IP) เพื่อป้องกันการลบ pool เดิมทิ้ง
        if (mode === "edit" && originalDhcp?.mode === "server" && originalDhcp?.pool) {
          const oldNetwork = originalDhcp.pool.network;
          const newNetwork = result.params.network;
          if (oldNetwork && oldNetwork !== newNetwork && originalDhcp.pool.name !== result.params.name) {
            result.params.replace_name = originalDhcp.pool.name;
          }
        }

        dhcpAction = { command: "set_dhcp_pool", parameters: result.params };
        // Juniper: access/address-assignment/pool เฉยๆ ไม่แจก DHCP จริง - ต้องสั่ง
        // ให้ interface นี้เปิด dhcp-local-server ด้วยอีกคำสั่งนึงเสมอ (ดู
        // set_dhcp_server_interface - pool ถูกเลือกอัตโนมัติจาก subnet ที่ match
        // ไม่ต้องระบุชื่อ pool ตรงๆ ตอนผูก interface)
        if (isJuniper) {
          const binding = resolveDhcpServerBinding(submitValues);
          dhcpAction.followUp = {
            command: "set_dhcp_server_interface",
            parameters: {
              interface_type: binding.interfaceType,
              interface_id: binding.interfaceId,
              unit: binding.unit,
            },
          };
          // 6.1: เลือกให้ interface ตัวเองเป็น DNS Server ของ DHCP client
          // (dhcpDnsMode==="interface") แปลว่า client จะถูกบอกให้ถาม DNS ที่ IP
          // ของ interface นี้ - ต้องผูกเข้า Junos DNS Proxy ด้วยเสมอ ไม่งั้น
          // อุปกรณ์ไม่ตอบ DNS query จริง (แค่แจก IP ไปเฉยๆ ไม่มีอะไรฟังอยู่จริง)
          if (submitValues.dhcpDnsMode === "interface") {
            dhcpAction.dnsProxyBinding = {
              interface_type: binding.interfaceType,
              interface_id: binding.interfaceId,
              unit: binding.unit,
            };
          }
        }
      }
    }

    if (isJuniper) {
      setSubmitting(true);
      try {
        const binding = resolveDhcpServerBinding(submitValues);
        const apiBinding = {interface_type: binding.interfaceType, interface_id: binding.interfaceId, unit: binding.unit};
        const latest = await runDeviceCommand(devId, "get_running_config", {});
        const configuration = latest?.normalized ? latest.result?.payload?.data?.configuration : null;
        if (!configuration || (mode === "edit" && !configuration.interfaces)) throw new Error("Failed to read latest Interface/DHCP configuration; changes not saved");
        const allInterfaces = Array.isArray(configuration.interfaces?.interface) ? configuration.interfaces.interface : configuration.interfaces?.interface ? [configuration.interfaces.interface] : [];
        const raw = allInterfaces.find(entry => entry.name === `${binding.interfaceType}${binding.interfaceId}`);
        const units = Array.isArray(raw?.unit) ? raw.unit : raw?.unit ? [raw.unit] : [];
        const unit = units.find(entry => String(entry.name) === String(binding.unit));
        const addresses = unit?.family?.inet?.address;
        const staticAddresses = (Array.isArray(addresses) ? addresses : addresses ? [addresses] : [])
          .map(entry => entry.name).filter(name => typeof name === "string" && name);
        const resolved = resolveCommand(ifType, ipMode, {...submitValues, staticAddresses}, true);
        if (ifType === IF_TYPE.VLAN) {
          const configuredVlans = configuration.vlans?.vlan;
          const matchingVlans = (Array.isArray(configuredVlans) ? configuredVlans : configuredVlans ? [configuredVlans] : [])
            .filter(entry => String(entry["vlan-id"]) === String(Number(submitValues.vlanId)));
          if (matchingVlans.length !== 1 || !matchingVlans[0].name) {
            throw new Error("Selected VLAN was not found in the latest configuration. Please create the VLAN or reload.");
          }
          const vlan = matchingVlans[0];
          if (vlan["l3-interface"] && vlan["l3-interface"] !== `irb.${submitValues.vlanId}`) {
            throw new Error(`This VLAN is already bound to ${vlan["l3-interface"]}; binding not changed`);
          }
          resolved.parameters.vlan_name = vlan.name;
        }
        const freshPools = parsePools(latest.result);
        const poolCleanup = mode === "edit" || unit ? juniperInterfacePoolCleanup({configuration, binding: apiBinding, pools: freshPools, requirePool: originalDhcp?.mode === "server"}) : [];
        if (dhcpAction?.command === "set_dhcp_pool") {
          if (!Array.isArray(freshPools)) throw new Error("Failed to read latest DHCP pools; changes not saved");
          const matching = freshPools.filter(pool => pool.network === dhcpAction.parameters.network);
          const existing = matching.find(pool => pool.name === dhcpAction.parameters.name) || (matching.length === 1 ? matching[0] : null);
          if (matching.length && !existing) throw new Error("Multiple DHCP pools found in the same subnet; changes aborted");
          if (existing) {
            if (!existing.poolConfig) throw new Error("Failed to read original DHCP pool configuration; DNS/Gateway not updated");
            dhcpAction.parameters.name = existing.name;
            dhcpAction.parameters.previous = {pool: existing.poolConfig};
          }
        }
        // Cleanup is explicitly planned from fresh ownership information.
        // Do not let a stale replace_name delete a pool shared by another unit.
        if (dhcpAction) delete dhcpAction.parameters.replace_name;
        const commands = juniperInterfaceSaveSteps({
          interfaceStep: resolved,
          binding: apiBinding,
          originalDhcp, dhcpAction,
          configuration, poolCleanup,
          resetMtu: ipMode !== IP_MODE.NONE && mode === "edit" && Boolean(initial.values.mtu) && !submitValues.mtu.trim(),
        });
        assertCommandOk(await runDeviceTransaction(devId, commands), "Failed to configure Interface and DHCP; entire batch cancelled");
        onSaved();
      } catch (err) {
        setError(err.detail || err.message || "Failed to configure Interface; entire batch cancelled");
      } finally {
        setSubmitting(false);
      }
      return;
    }

    if (isCisco && ipMode !== IP_MODE.NONE) {
      setSubmitting(true);
      try {
        const resolved = resolveCommand(ifType, ipMode, submitValues, false);
        if (ifType === IF_TYPE.INTERFACE) resolved.parameters.switchport_capable = await ciscoSwitchportCapability();
        const commands = [resolved];
        const binding = resolveInterfaceTypeId(submitValues);
        if (mode === "edit" && initial.values.mtu && !submitValues.mtu.trim()) {
          commands.push({command: "remove_interface_mtu", parameters: {
            interface_type: binding.interfaceType, interface_id: binding.interfaceId,
          }});
        }
        const oldHelpers = editTarget?.layer?.helpers || layerRows.find(row => row.name === editTarget?.name)?.helpers
          || (originalDhcp?.mode === "relay" && originalDhcp.relayIp ? [originalDhcp.relayIp] : []);
        const newHelper = dhcpAction?.command === "set_dhcp_relay" ? dhcpAction.parameters.helper_ip : null;
        for (const helper of oldHelpers) if (helper !== newHelper) commands.push({command: "remove_dhcp_relay", parameters: {
          interface_type: binding.interfaceType, interface_id: binding.interfaceId, helper_ip: helper,
        }});
        if (originalDhcp?.mode === "server" && originalDhcp.pool
            && (dhcpAction?.command !== "set_dhcp_pool" || dhcpAction.parameters.name !== originalDhcp.pool.name)) {
          commands.push({command: "remove_dhcp_pool", parameters: {name: originalDhcp.pool.name,
            network: originalDhcp.pool.network, exclude: originalDhcp.pool.excludeRanges ?? originalDhcp.pool.exclude}});
        }
        if (dhcpAction) {
          delete dhcpAction.parameters.replace_name;
          commands.push({command: dhcpAction.command, parameters: dhcpAction.parameters});
        }
        assertCommandOk(await runDeviceTransaction(devId, commands), "Failed to configure Interface/DHCP; entire batch cancelled");
        onSaved();
      } catch (err) {
        setError(err.detail || err.message || "Failed to configure Interface/DHCP; entire batch cancelled");
      } finally {
        setSubmitting(false);
      }
      return;
    }

    if (ipMode === IP_MODE.NONE) {
      setSubmitting(true);
      try {
        const resolved = resolveCommand(ifType, ipMode, submitValues, false, isHuawei && !initial.values.description);
        if (isHuawei) resolved.parameters.reset_mtu = Boolean(initial.values.mtu);
        if (isCisco) resolved.parameters.switchport_capable = await ciscoSwitchportCapability();
        if (isHuawei && ifType === IF_TYPE.VLAN) resolved.parameters.interface_type = "Vlanif";
        const fullName = `${resolved.parameters.interface_type}${resolved.parameters.interface_id}`;
        const currentLayer = layerRows.find(row => row.name === fullName) || editTarget?.layer;
        const currentBrief = briefRows.find(row => row.name === fullName) || editTarget?.brief;
        if (isCisco) {
          const pools = dhcpPoolData?.normalized ? parsePools(dhcpPoolData.result) : null;
          if (!Array.isArray(pools)) throw new Error("Failed to read original DHCP pools; None mode not saved");
          const subnet = normalizeSubnet(currentBrief?.subnet);
          const previous = parseIpCidr(initial.values.ip) || parseIpCidr(currentBrief?.ip || "")
            || (subnet && currentBrief?.ip ? {ip: currentBrief.ip, prefix: subnet.prefix} : null);
          const pool = originalDhcp?.pool || (previous ? findExistingPoolForNetwork(pools, previous.ip, previous.prefix) : null);
          resolved.parameters.helper_ips = currentLayer?.helpers || (originalDhcp?.relayIp ? [originalDhcp.relayIp] : []);
          if (pool) {
            resolved.parameters.dhcp_pool_name = pool.name;
            resolved.parameters.dhcp_pool_exclude = pool.excludeRanges ?? pool.exclude;
          }
        }
        const commands = [];
        if (isHuawei) {
          const addresses = currentLayer?.raw?.ipv4Config?.am4CfgAddrs?.am4CfgAddr;
          const list = Array.isArray(addresses) ? addresses : addresses ? [addresses] : [];
          const previousIp = parseIpCidr(initial.values.ip)?.ip || (currentBrief?.ip || "").split("/")[0];
          resolved.parameters.previous_addresses = [...new Set([...list.map(entry => entry.ifIpAddr),
            ...(previousIp && previousIp !== "-" ? [previousIp] : [])])];
          if (ifType === IF_TYPE.INTERFACE && currentLayer?.layer === "Layer 2") {
            commands.push({command: "apply_interface_to_vlan", parameters: {
              interface_type: resolved.parameters.interface_type, interface_id: resolved.parameters.interface_id,
              mode: "access", vlan_id: 1,
            }});
          }
        }
        commands.push(resolved);
        const result = commands.length > 1 || isCisco ? await runDeviceTransaction(devId, commands)
          : await runDeviceCommand(devId, resolved.command, resolved.parameters);
        assertCommandOk(result, "Failed to change interface to Layer 3 with no IP");
        onSaved();
      } catch (err) {
        setError(err.detail || err.message || "Failed to configure None mode");
      } finally {
        setSubmitting(false);
      }
      return;
    }

    setSubmitting(true);
    try {
      // CE12800 ยอมให้พอร์ตสลับเป็น Layer 3 เฉพาะตอนที่เป็น access VLAN 1 อยู่แล้ว
      // ถ้าเป็น trunk หรือ access VLAN อื่น ต้องคืนค่าก่อนหนึ่งคำสั่ง ซึ่งรวมเข้า
      // edit-config เดียวกับการสลับไม่ได้ (อุปกรณ์ตอบ "The interface is not a L2
      // interface" เพราะไม่ได้ใช้การเปลี่ยนแปลงตามลำดับในก้อนเดียวกัน)
      // ทางออกคือ C4: Huawei เขียนลง candidate แล้ว ชุดคำสั่งจึงส่งสองคำสั่งเข้า
      // candidate เดียวแล้ว commit ครั้งเดียว ได้ atomic เต็มและคำสั่งที่สองเห็นผล
      // ของคำสั่งแรกแล้ว - พอร์ตที่เป็น access VLAN 1 หรือเป็น Layer 3 อยู่แล้ว
      // ไม่ต้องคืนค่า จึงยังยิงคำสั่งเดียวเหมือนเดิม
      const { command, parameters } = resolveCommand(ifType, ipMode, submitValues, isJuniper, isHuawei && !initial.values.description);
      if (isCisco && ifType === IF_TYPE.INTERFACE) parameters.switchport_capable = await ciscoSwitchportCapability();
      const currentAccessVlan = String(initial.values.switchportVlan || "").trim();
      const huaweiNeedsL2Reset =
        isHuawei &&
        ifType === IF_TYPE.INTERFACE &&
        layer === LAYER.L3 &&
        (initial.values.switchportMode === SWITCHPORT_MODE.TRUNK ||
          (currentAccessVlan !== "" && currentAccessVlan !== "1"));

      // `am4CfgAddr` เป็น list ที่มี key เป็น ifIpAddr การ merge IP ใหม่จึงเป็นการ
      // "เพิ่มสมาชิก" ไม่ใช่แก้ค่าเดิม พอมีสอง entry ที่ addrType=main อุปกรณ์ตอบ
      // "The main address already exists" ต้องลบ IP เดิมก่อนเสมอ - รวมเข้าชุดเดียว
      // กับการตั้ง IP ใหม่ จึง atomic และไม่มีจังหวะที่พอร์ตไม่มี IP เลย
      const previousIp = parseIpCidr(initial.values.ip)?.ip || "";
      const huaweiNeedsIpReplace =
        isHuawei &&
        mode === "edit" &&
        ipMode === IP_MODE.STATIC &&
        ifType !== IF_TYPE.SUB_INTERFACE &&
        !!previousIp &&
        !!parameters.ip &&
        previousIp !== parameters.ip;

      // ตัวระบุ interface ของคำสั่งล้าง IP: physical ใช้ชื่อที่เลือก ส่วน SVI ของ
      // Huawei คือ Vlanif<vlan_id> (คำสั่งตั้งค่า SVI รับมาเป็น vlan_id จึงประกอบเอง)
      const clearTarget =
        ifType === IF_TYPE.INTERFACE
          ? splitInterfaceName(submitValues.interfaceName)
          : { interfaceType: "Vlanif", interfaceId: String(submitValues.vlanId) };

      // Cisco ไม่ต้องยิง set_switchport นำหน้าอีกแล้ว: set_interface_static_ip ของ
      // ยี่ห้อนี้ใส่ switchport-conf=false ไว้ในก้อนเดียวกับ address แล้ว การสลับ
      // เป็น Layer 3 พร้อมตั้ง IP จึงเป็น RPC เดียวและ atomic จาก rollback-on-error
      const steps = [];
      if (huaweiNeedsL2Reset) {
        const { interfaceType, interfaceId } = splitInterfaceName(submitValues.interfaceName);
        steps.push({
          command: "apply_interface_to_vlan",
          parameters: {
            interface_type: interfaceType,
            interface_id: interfaceId,
            mode: SWITCHPORT_MODE.ACCESS,
            vlan_id: 1,
          },
        });
      }
      if (huaweiNeedsIpReplace) {
        steps.push({
          command: "clear_interface_ip",
          parameters: {
            interface_type: clearTarget.interfaceType,
            interface_id: clearTarget.interfaceId,
            ip: previousIp,
          },
        });
      }

      if (isHuawei && mode === "edit" && initial.values.mtu && !submitValues.mtu.trim()) {
        steps.push({command: "remove_interface_mtu", parameters: {
          interface_type: clearTarget.interfaceType, interface_id: clearTarget.interfaceId,
        }});
      }

      if (steps.length > 0) {
        steps.push({ command, parameters });
        assertCommandOk(
          await runDeviceTransaction(devId, steps),
          huaweiNeedsL2Reset ? "Failed to change interface to Layer 3" : "Failed to configure interface"
        );
      } else {
        assertCommandOk(await runDeviceCommand(devId, command, parameters), "Failed to configure interface");
      }
    } catch (err) {
      setError(err.detail || "Failed to configure interface");
      setSubmitting(false);
      return;
    }

    // ถึงตรงนี้ interface ตั้งสำเร็จแล้วจริง (commit ผ่านไปแล้ว) - DHCP เป็นคนละ
    // command แยกต่างหาก (Cisco แยก interface config กับ dhcp pool/relay เป็นคนละ
    // ส่วน, Juniper แยก commit) ต้องแยก try/catch ออกจากกัน ไม่งั้นถ้า DHCP ล้มเหลว
    // จะโดน catch เดียวกันแล้วขึ้น "ตั้งค่า interface ไม่สำเร็จ" ทั้งที่ interface
    // สร้างจริงแล้ว ทำให้ผู้ใช้เข้าใจผิดว่าไม่มีอะไรสำเร็จเลยสักอย่าง (ไม่เรียก
    // onSaved() ในกรณีนี้เพราะมันจะปิดฟอร์มทันทีจน error message ค้างนี้ไม่ทันได้
    // เห็น - ปล่อยฟอร์มเปิดค้างไว้ให้เห็นข้อความ ผู้ใช้ปิดเองแล้ว list จะ refresh
    // ทีหลังตามปกติ)
    if (dhcpAction) {
      try {
        await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
        assertCommandOk(await runDeviceCommand(devId, dhcpAction.command, dhcpAction.parameters), "Failed to configure DHCP");
        if (dhcpAction.followUp) {
          await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
          assertCommandOk(
            await runDeviceCommand(devId, dhcpAction.followUp.command, dhcpAction.followUp.parameters),
            "Failed to bind DHCP Server to interface"
          );
        }
        // 6.1: ผูก interface เข้า Junos DNS Proxy (dns-proxy/interface) เท่านั้น -
        // best-effort (ไม่ block การตั้ง DHCP ที่สำเร็จไปแล้ว) - **ไม่ sync
        // forwarders จากจุดนี้อีกต่อไป** (เดิมเคยเรียก syncJuniperDnsProxyForwarders
        // ด้วย) - user ระบุว่า forwarders ต้องอ้างอิงกับ system name-server
        // (dns.jsx) เพียงจุดเดียวเท่านั้น ไม่ใช่ผูก/ลบตาม interface create/delete -
        // ลบ syncJuniperDnsProxyForwarders() ออกจากไฟล์นี้ทั้งฟังก์ชัน (ไม่มีจุด
        // เรียกอื่นแล้ว) sync ทิศทางเดียวที่เหลืออยู่คือใน dns.jsx's handleApply
        // ตอน user แก้ name-server เอง
        if (dhcpAction.dnsProxyBinding) {
          try {
            await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
            // best-effort: ผูก DNS Proxy ล้มเหลวไม่กระทบ DHCP ที่ตั้งสำเร็จไปแล้ว
            await runDeviceCommand(devId, "set_dns_server_interface", dhcpAction.dnsProxyBinding, { allowFailure: true });
          } catch (dnsProxyErr) {
            console.error("set_dns_server_interface failed:", dnsProxyErr);
          }
        }
      } catch (err) {
        const dhcpLabel = submitValues.dhcpMode === "relay" ? "DHCP Relay" : "DHCP Server";
        setError(`Interface configured successfully, but ${dhcpLabel} configuration failed: ${err.detail || "Unknown reason"}`);
        setSubmitting(false);
        return;
      }
    }

    // ปิด DHCP Server/Relay ที่เคยผูกอยู่จริง (originalDhcp ถูก set ไว้ตอน prefill
    // เจอ pool/relay เดิมของ interface นี้ - ดู useEffect ด้านบน) ต้องลบทิ้งจริงตอน
    // Save ไม่ใช่แค่ปล่อยให้ dhcpServer=false เฉยๆ เพราะ pool/relay เดิมยังอยู่บน
    // อุปกรณ์ - นี่คือบั๊กเดิมที่ user รายงาน (ปิด toggle กด Save แล้วไม่ได้ลบอะไร
    // หรือสลับโหมดจาก Server เป็น Relay, สลับโหมดจาก Relay เป็น Server, หรือเปลี่ยน Relay IP
    // ต้องลบ pool/relay เดิมออกด้วยเพื่อไม่ให้ config ค้างสะสมบนอุปกรณ์)
    const isDhcpToggledOff = Boolean(originalDhcp && !submitValues.dhcpServer);
    const isSwitchedServerToRelay = Boolean(
      originalDhcp?.mode === "server" && submitValues.dhcpServer && submitValues.dhcpMode === "relay"
    );
    const isSwitchedRelayToServer = Boolean(
      originalDhcp?.mode === "relay" && submitValues.dhcpServer && submitValues.dhcpMode === "server"
    );
    const isRelayIpChanged = Boolean(
      originalDhcp?.mode === "relay" &&
        submitValues.dhcpServer &&
        submitValues.dhcpMode === "relay" &&
        originalDhcp.relayIp &&
        originalDhcp.relayIp !== submitValues.dhcpRelayIp.trim()
    );
    if (isDhcpToggledOff || isSwitchedServerToRelay || isSwitchedRelayToServer || isRelayIpChanged) {
      try {
        await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
        if (originalDhcp.mode === "relay") {
          const binding = isJuniper ? resolveDhcpServerBinding(submitValues) : resolveInterfaceTypeId(submitValues);
          assertCommandOk(
            await runDeviceCommand(devId, "remove_dhcp_relay", {
              interface_type: binding.interfaceType,
              interface_id: binding.interfaceId,
              helper_ip: originalDhcp.relayIp,
              ...(isJuniper ? { unit: binding.unit } : {}),
            }),
            "Failed to delete DHCP Relay"
          );
        } else {
          let removeRes = await runDeviceCommand(devId, "remove_dhcp_pool", {
            name: originalDhcp.pool.name,
            network: originalDhcp.pool.network,
            exclude: originalDhcp.pool.exclude,
          }, { allowFailure: true });
          if (removeRes?.result?.ok === false) {
            removeRes = await runDeviceCommand(devId, "remove_dhcp_pool", {
              name: originalDhcp.pool.name,
              network: originalDhcp.pool.network,
            });
          }
          assertCommandOk(removeRes, "Failed to delete DHCP pool");
          // Juniper ต้องปลด dhcp-local-server binding ออกจาก interface ด้วย ไม่งั้น
          // pool หายแต่ interface ยังชี้ไปหา pool ที่ไม่มีอยู่แล้ว (ผูกแยกกันคนละ
          // คำสั่งเหมือนตอน set - ดู set_dhcp_server_interface ด้านบน)
          if (isJuniper) {
            await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
            const binding = resolveDhcpServerBinding(submitValues);
            assertCommandOk(
              await runDeviceCommand(devId, "remove_dhcp_server_interface", {
                interface_type: binding.interfaceType,
                interface_id: binding.interfaceId,
                unit: binding.unit,
              }),
              "Failed to unbind DHCP Server from interface"
            );
            // 6.1: ปิด DHCP Server แล้วต้องถอด interface นี้ออกจาก Junos DNS
            // Proxy ด้วยเสมอ (ถ้าเคยผูกไว้ตอนเปิด - ดู dnsProxyBinding ด้านล่าง) -
            // best-effort เงียบๆ (ไม่ block การปิด DHCP ที่สำเร็จไปแล้ว) เพราะไม่รู้
            // แน่ชัดจาก originalDhcp ว่าตอนเปิดไว้เลือก dhcpDnsMode แบบไหน
            try {
              await sleep(POST_INTERFACE_COMMIT_DELAY_MS);
              // best-effort: ถอด DNS Proxy ล้มเหลวไม่กระทบการปิด DHCP ที่สำเร็จไปแล้ว
              await runDeviceCommand(devId, "remove_dns_server_interface", {
                interface_type: binding.interfaceType,
                interface_id: binding.interfaceId,
                unit: binding.unit,
              }, { allowFailure: true });
            } catch (dnsProxyErr) {
              console.error("remove_dns_server_interface cleanup after DHCP off failed:", dnsProxyErr);
            }
          }
        }
      } catch (err) {
        setError(`Interface configured successfully, but failed to remove original DHCP: ${err.detail || "Unknown reason"}`);
        setSubmitting(false);
        return;
      }
    }

    onSaved();
    setSubmitting(false);
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {mode === "edit" && editTarget && (
        <div className="command-output-title">Edit: {editTarget.name}</div>
      )}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      {showDhcpOffConfirm && (
        <div className="modal-overlay" onClick={() => setShowDhcpOffConfirm(false)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Confirm Disabling DHCP {originalDhcp?.mode === "relay" ? "Relay" : "Server"}</h2>
              <button
                type="button"
                className="modal-close"
                onClick={() => setShowDhcpOffConfirm(false)}
                aria-label="Close"
              >
                &times;
              </button>
            </div>
            <p>
              {originalDhcp?.mode === "relay" ? (
                <>
                  Disabling DHCP Relay will remove helper address <strong>{originalDhcp.relayIp}</strong> bound to this interface.
                </>
              ) : (
                <>
                  Disabling DHCP Server will remove DHCP pool <strong>{originalDhcp?.pool?.name}</strong> bound to this subnet.
                </>
              )}{" "}
              (Will not take effect until Save is clicked on this form). Confirm?
            </p>
            <div className="modal-actions">
              <button type="button" className="btn btn-ghost" onClick={() => setShowDhcpOffConfirm(false)}>
                Cancel
              </button>
              <button type="button" className="btn btn-primary" onClick={confirmDhcpOff}>
                Disable DHCP
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Interface Type ก่อนเป็นอันดับแรก (ตัดสิน flow ที่เหลือทั้งหมด) - Sub-
          interface/VLAN Interface บังคับ Layer 3 อัตโนมัติทันทีที่เลือก (ดู
          handleIfTypeChange) เลยไม่ต้องถามคำถาม Layer 2/3 ซ้ำสำหรับ 2 แบบนี้ -
          ตอน Edit ล็อกไว้ห้ามเปลี่ยนเสมอ (ยึดตามที่ buildInitialValues จำแนกจาก
          ตัว editTarget เองเท่านั้น) เพราะสลับ type ระหว่างแก้ไขไม่ได้แปลว่าย้าย
          identity ของ interface จริงบนอุปกรณ์ (เช่น ge-0/0/2.0 กด "Sub-interface"
          แล้วกรอก VLAN ID ใหม่ จะไม่ได้ทำให้มันกลายเป็น ge-0/0/2.20 จริงๆ - ยัง
          PATCH เป้าหมายเดิม ge-0/0/2.0 อยู่ดี ทำให้ค่าที่กรอกไปไม่ตรงกับสิ่งที่
          เกิดขึ้นจริงบนอุปกรณ์เลย) ถ้าจะเปลี่ยนประเภทจริงๆ ต้องลบตัวเดิมแล้วสร้าง
          ใหม่แทน (ไปหน้า Create New) */}
      <div className="interface-configuration-form-field">
        <label className="data-label">Interface Type</label>
        <div
          className={`segmented-control${mode === "edit" ? " locked-choice" : ""}`}
          title={mode === "edit" ? "Interface type is fixed after creation" : undefined}
        >
          <input
            type="radio"
            id="iftype-interface"
            name="if-type"
            value={IF_TYPE.INTERFACE}
            checked={ifType === IF_TYPE.INTERFACE}
            onChange={(event) => handleIfTypeChange(event.target.value)}
            disabled={mode === "edit"}
          />
          <label htmlFor="iftype-interface">Interface</label>

          {!isHuawei && (
            <>
              <input
                type="radio"
                id="iftype-sub"
                name="if-type"
                value={IF_TYPE.SUB_INTERFACE}
                checked={ifType === IF_TYPE.SUB_INTERFACE}
                onChange={(event) => handleIfTypeChange(event.target.value)}
                disabled={mode === "edit"}
              />
              <label htmlFor="iftype-sub">Sub-interface</label>
            </>
          )}
          {vlanInterfaceSelectable && (
            <>
              <input
                type="radio"
                id="iftype-vlan"
                name="if-type"
                value={IF_TYPE.VLAN}
                checked={ifType === IF_TYPE.VLAN}
                onChange={(event) => handleIfTypeChange(event.target.value)}
                disabled={mode === "edit"}
              />
              <label htmlFor="iftype-vlan">VLAN Interface</label>
            </>
          )}
        </div>
      </div>

      {/* VLAN Interface (SVI/irb) ไม่ผูกกับ physical port เลย - ข้ามขั้นตอนนี้ไปตรงๆ */}
      {needsInterfacePicker && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Interface</label>
          {ifListLoading ? (
            <select disabled value="">
              <option value="">Loading interface information...</option>
            </select>
          ) : canPickInterface ? (
            <select
              value={values.interfaceName}
              onChange={(event) => setField("interfaceName", event.target.value)}
              disabled={mode === "edit"}
              required
            >
              <option value="" disabled>-- Choose interface --</option>
              {pickableInterfaceOptions.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          ) : (
            <>
              <input
                type="text"
                placeholder="e.g. GigabitEthernet1"
                value={values.interfaceName}
                onChange={(event) => setField("interfaceName", event.target.value)}
                readOnly={mode === "edit"}
                required
              />
              <span className="">
                Unable to retrieve interface list from device (not supported). Please enter manually.
              </span>
            </>
          )}
        </div>
      )}

      {ifType === IF_TYPE.INTERFACE && selectableLayers.length > 1 && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Layer</label>
          <div className="segmented-control">
            <input
              type="radio"
              id="layer-l3"
              name="layer"
              value={LAYER.L3}
              checked={layer === LAYER.L3}
              onChange={(event) => setLayer(event.target.value)}
            />
            <label htmlFor="layer-l3">Layer 3</label>
            {layer2Selectable && (
              <>
                <input
                  type="radio"
                  id="layer-l2"
                  name="layer"
                  value={LAYER.L2}
                  checked={layer === LAYER.L2}
                  onChange={(event) => setLayer(event.target.value)}
                />
                <label htmlFor="layer-l2">Layer 2</label>
              </>
            )}
          </div>
        </div>
      )}

      {ifType === IF_TYPE.INTERFACE && layer === LAYER.L2 ? (
        <>
          <div className="interface-configuration-form-field">
            <label className="data-label">Description</label>
            <input type="text" maxLength={isHuawei ? 242 : 200} value={values.description}
              onChange={event => setField("description", event.target.value)} />
          </div>
          <div className="interface-configuration-form-field">
            <label className="data-label">Enable Interface</label>
            <div className="toggle-switch-container">
              <input type="checkbox" checked={values.switchportEnabled}
                onChange={event => setField("switchportEnabled", event.target.checked)}
                id="switchport-shutdown-toggle" />
              <label className="toggleSwitch" htmlFor="switchport-shutdown-toggle"></label>
            </div>
          </div>
          <div className="interface-configuration-form-field">
            <label className="data-label">Mode</label>
            <div className="segmented-control">
              <input
                type="radio"
                id="sw-access"
                name="switchport-mode"
                value={SWITCHPORT_MODE.ACCESS}
                checked={values.switchportMode === SWITCHPORT_MODE.ACCESS}
                onChange={(event) => setField("switchportMode", event.target.value)}
              />
              <label htmlFor="sw-access">Access</label>
              <input
                type="radio"
                id="sw-trunk"
                name="switchport-mode"
                value={SWITCHPORT_MODE.TRUNK}
                checked={values.switchportMode === SWITCHPORT_MODE.TRUNK}
                onChange={(event) => setField("switchportMode", event.target.value)}
              />
              <label htmlFor="sw-trunk">Trunk</label>
            </div>
          </div>

          {values.switchportMode === SWITCHPORT_MODE.ACCESS ? (
            <div className="interface-configuration-form-field">
              <label className="data-label">VLAN</label>
              {vlanLoading ? (
                <select disabled value="">
                  <option value="">Loading VLAN list...</option>
                </select>
              ) : canPickVlan ? (
                <select value={values.switchportVlan} onChange={(event) => setField("switchportVlan", event.target.value)}>
                  <option value="">-- Select VLAN --</option>
                  {vlanOptions.map((vlan) => (
                    <option key={vlan.id} value={vlan.id}
                      disabled={!validateVlanId(String(vlan.id)).valid && String(vlan.id) !== values.switchportVlan}>
                      {vlan.id}
                      {vlan.name ? ` (${vlan.name})` : ""}
                      {validateVlanId(String(vlan.id)).valid ? "" : " - unsupported VLAN ID"}
                    </option>
                  ))}
                </select>
              ) : (
                <span>No VLANs found on this device - create one on the VLAN page first</span>
              )}
            </div>
          ) : (
            <>
              <div className="interface-configuration-form-field">
                <label className="data-label">Trunk Allow VLAN</label>
                <div className="segmented-control">
                  <input
                    type="radio"
                    id="trunk-allow-all"
                    name="trunk-allow-mode"
                    value="all"
                    checked={trunkAllowsAllInForm}
                    onChange={() => setTrunkAllowMode("all")}
                  />
                  <label htmlFor="trunk-allow-all">All</label>
                  <input
                    type="radio"
                    id="trunk-allow-specific"
                    name="trunk-allow-mode"
                    value="specific"
                    checked={!trunkAllowsAllInForm}
                    onChange={() => setTrunkAllowMode("specific")}
                  />
                  <label htmlFor="trunk-allow-specific">Specific</label>
                </div>
              </div>

              {/* Use the same anchored checkbox dropdown as Zone interface members. */}
              {!trunkAllowsAllInForm && (
                <div className="interface-configuration-form-field">
                  <span aria-hidden="true" />
                  <CheckboxDropdown className="trunk-vlan-picker" ariaLabel="Select VLANs for Trunk" summary={<>
                      <input type="text" readOnly tabIndex={-1} aria-label="Selected VLANs"
                        placeholder="-- Select VLAN --" value={[...selectedTrunkVlans].join(", ")} />
                    </>}>
                    <div className="zone-interface-picker-options">
                      {vlanLoading && <div className="field-hint">Loading VLAN list...</div>}
                      {!vlanLoading && !canPickTrunkVlan && <div className="field-hint">No VLANs found on this device - create one on the VLAN page first</div>}
                      {trunkVlanOptions.map(option => (
                        <label key={option.id} className="zone-interface-picker-option">
                          <input type="checkbox" value={String(option.id)} checked={selectedTrunkVlans.has(String(option.id))}
                            disabled={vlanLoading || submitting || (!validateVlanId(String(option.id)).valid && !selectedTrunkVlans.has(String(option.id)))}
                            onChange={() => toggleTrunkVlan(option.id)} />
                          {option.id}{option.name ? ` (${option.name})` : ""}{validateVlanId(String(option.id)).valid ? "" : " - unsupported VLAN ID"}
                        </label>
                      ))}
                    </div>
                  </CheckboxDropdown>
                  </div>
              )}
            </>
          )}

        </>
      ) : (
        <>
          {(ifType === IF_TYPE.SUB_INTERFACE || ifType === IF_TYPE.VLAN) && (
            <div className="interface-configuration-form-field">
              <label className="data-label" htmlFor="interface-vlan-id">VLAN ID ({VLAN_ID_MIN}-{VLAN_ID_MAX})</label>
              <input
                id="interface-vlan-id"
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={4}
                autoComplete="off"
                value={values.vlanId}
                disabled={mode === "edit"
                  && (initial.ifType === IF_TYPE.SUB_INTERFACE || initial.ifType === IF_TYPE.VLAN)}
                onChange={(event) => {
                  const next = event.target.value;
                  if (acceptsVlanIdDraft(next)) {
                    setField("vlanId", next);
                    setVlanIdError("");
                  } else {
                    setVlanIdError(validateVlanId(next).error);
                  }
                }}
                aria-invalid={Boolean(vlanIdError)}
                aria-describedby="interface-vlan-id-hint"
                placeholder="10"
                required
              />
            </div>
          )}

          {/* Native VLAN: Cisco เท่านั้น - Juniper/Huawei ตั้ง untagged ที่พอร์ต
              หลัก ไม่ใช่ที่ sub-interface เลย ตัวเลือกนี้ไม่มีความหมายกับ 2
              ยี่ห้อนั้นจึงซ่อนไปตรงๆ */}
          {ifType === IF_TYPE.SUB_INTERFACE && vendor === "cisco" && (
            <div className="interface-configuration-form-field">
              <label className="data-label">
                Native VLAN
              </label>
              <div className="toggle-switch-container">
                <input
                  type="checkbox"
                  checked={values.native}
                  onChange={(event) => setField("native", event.target.checked)}
                  id="toggle"
                />
                <label className="toggleSwitch" htmlFor="toggle"></label>
              </div>
            </div>
          )}
          {(
            <div className="interface-configuration-form-field">
              <label className="data-label">Description</label>
              <input type="text" maxLength={isJuniper ? 200 : undefined} value={values.description} onChange={event => setField("description", event.target.value)} />
            </div>
          )}

          {ifType !== IF_TYPE.SUB_INTERFACE && (
            <div className="interface-configuration-form-field">
              <label className="data-label">Enable Interface</label>
              <div className="toggle-switch-container">
                <input type="checkbox" checked={!values.shutdown}
                  onChange={event => setField("shutdown", !event.target.checked)} id="shutdown-toggle" />
                <label className="toggleSwitch" htmlFor="shutdown-toggle"></label>
              </div>
            </div>
          )}

          {(
            <div className="interface-configuration-form-field">
              <label className="data-label">Addressing Mode</label>

              <div className="segmented-control">
                <input
                  type="radio"
                  id="mode-static"
                  name="addressing_mode"
                  value={IP_MODE.STATIC}
                  checked={ipMode === IP_MODE.STATIC}
                  onChange={(event) => setIpMode(event.target.value)}
                />
                <label htmlFor="mode-static">Static</label>

                {!isHuawei && ifType !== IF_TYPE.SUB_INTERFACE && !(isJuniper && ifType === IF_TYPE.VLAN) && (
                  <>
                    <input
                      type="radio"
                      id="mode-dhcp"
                      name="addressing_mode"
                      value={IP_MODE.DHCP}
                      checked={ipMode === IP_MODE.DHCP}
                      onChange={(event) => setIpMode(event.target.value)}
                      disabled={ifType === IF_TYPE.SUB_INTERFACE}
                    />
                    <label htmlFor="mode-dhcp">DHCP</label>
                  </>
                )}
                <input type="radio" id="mode-none" name="addressing_mode" value={IP_MODE.NONE}
                  checked={ipMode === IP_MODE.NONE} onChange={event => setIpMode(event.target.value)} />
                <label htmlFor="mode-none">None</label>
              </div>
            </div>
          )}

          {/* MTU - optional, ทั้ง Cisco และ Juniper (L3 Interface/Sub-interface/
              VLAN Interface) - ไม่กรอก = ใช้ default ของอุปกรณ์ต่อไป แก้ปัญหา
              OSPF neighbor ค้าง EXSTART/EXCHANGE ข้ามยี่ห้อจาก MTU ไม่ตรงกัน -
              แสดงใน Static/DHCP; None ซ่อนและไม่เปลี่ยนค่าเดิม
              ไม่ใช่ของ addressing mode - **label ต่างกันตามยี่ห้อ**: Cisco ส่งค่า
              นี้ไปเป็น "ip mtu" (คนละ leaf จาก system mtu - เปลี่ยนมาใช้ตัวนี้
              เพราะเป็นค่าที่ OSPF เทียบจริงตอน DBD exchange) ส่วน Juniper ยังเป็น
              physical mtu ตามเดิม (Junos ไม่มี concept แยก ip mtu ต่างหาก) */}
          {ipMode !== IP_MODE.NONE && (
          <>
          <div className="interface-configuration-form-field">
            <label className="data-label">{isJuniper ? "MTU (bytes)" : "IP MTU (bytes)"}</label>
            <input
              type="number"
              min="68"
              max="9216"
              placeholder="e.g. 1500 (Device default - optional)"
              value={values.mtu}
              onChange={(event) => setField("mtu", event.target.value)}
            />
          </div>

          {ipMode === IP_MODE.STATIC && (
            <>
              <div className="interface-configuration-form-field">
                <div className="data-label">Interface IPv4</div>
                <IPv4Input id="interface-ip" label="Interface IP" mode="cidr"
                  value={values.ip}
                  onChange={(value) => setField("ip", value)}
                  required
                />
              </div>
            </>
          )}

          {/* Huawei ไม่รองรับ DHCP ผ่าน NETCONF จึงซ่อนทั้ง Server/Relay รวม
              pool, range, gateway, DNS และ lease ไม่ให้เกิดคำสั่งที่รองรับไม่ได้ */}
          {!isHuawei && ipMode === IP_MODE.STATIC && (
            <>
              <div className="interface-configuration-form-field">
                <label className="data-label">DHCP Server</label>
                <div className="toggle-switch-container">
                  <input
                    type="checkbox"
                    id="dhcp-toggle"
                    checked={values.dhcpServer}
                    onChange={(event) => handleDhcpToggle(event.target.checked)}
                  />
                  <label className="toggleSwitch" htmlFor="dhcp-toggle"></label>
                </div>
              </div>

              {values.dhcpServer && (
                <>
                  <div className="interface-configuration-form-field">
                    <label className="data-label">DHCP Mode</label>
                    <div className="segmented-control">
                      <input
                        type="radio"
                        id="dhcp-server"
                        name="dhcp-mode"
                        value="server"
                        checked={values.dhcpMode === "server"}
                        onChange={(event) => setField("dhcpMode", event.target.value)}
                      />
                      <label htmlFor="dhcp-server">Server</label>

                      <input
                        type="radio"
                        id="dhcp-relay"
                        name="dhcp-mode"
                        value="relay"
                        checked={values.dhcpMode === "relay"}
                        onChange={(event) => setField("dhcpMode", event.target.value)}
                      />
                      <label htmlFor="dhcp-relay">Relay</label>
                    </div>
                  </div>

                  {values.dhcpMode === "relay" ? (
                    <div className="interface-configuration-form-field">
                      <label className="data-label">DHCP Server IP</label>
                      <IPv4Input label="DHCP Server IP" required
                        value={values.dhcpRelayIp}
                        onChange={(value) => setField("dhcpRelayIp", value)}
                      />
                    </div>
                  ) : (
                    <>
                      {/* Network คำนวณจาก IP/Subnet ของ interface ที่ตั้งไว้ด้านบนตรงๆ
                          เสมอ (ไม่ต้องกรอกซ้ำ) - Address range auto-fill เป็น host
                          .11-.200 ของวงนี้ให้แล้ว (ดู useEffect) ยังแก้เองได้ */}
                      <div className="interface-configuration-form-field">
                        <label className="data-label" htmlFor="dhcp-start-address">Start address</label>
                        <IPv4Input
                          id="dhcp-start-address"
                          label="Start address"
                          value={values.dhcpStartAddress}
                          onChange={(value) => {
                            dhcpRangeUserEditedRef.current.start = true;
                            setField("dhcpStartAddress", value);
                          }}
                        />
                      </div>
                      <div className="interface-configuration-form-field">
                        <label className="data-label" htmlFor="dhcp-end-address">End address</label>
                        <IPv4Input
                          id="dhcp-end-address"
                          label="End address"
                          value={values.dhcpEndAddress}
                          onChange={(value) => {
                            dhcpRangeUserEditedRef.current.end = true;
                            setField("dhcpEndAddress", value);
                          }}
                        />
                      </div>

                      <div className="interface-configuration-form-field">
                        <label className="data-label">Gateway</label>
                        <div className="segmented-control">
                          <input
                            type="radio"
                            id="gw-int"
                            name="gateway-ip"
                            value="interface"
                            checked={values.dhcpGatewayMode === "interface"}
                            onChange={(event) => setField("dhcpGatewayMode", event.target.value)}
                          />
                          <label htmlFor="gw-int">Interface IP</label>
                          <input
                            type="radio"
                            id="gw-specific"
                            name="gateway-ip"
                            value="specific"
                            checked={values.dhcpGatewayMode === "specific"}
                            onChange={(event) => setField("dhcpGatewayMode", event.target.value)}
                          />
                          <label htmlFor="gw-specific">Specific IP</label>
                          <>
                            <input type="radio" id="gw-none" name="gateway-ip" value="none"
                              checked={values.dhcpGatewayMode === "none"} onChange={event => setField("dhcpGatewayMode", event.target.value)} />
                            <label htmlFor="gw-none">None</label>
                          </>
                        </div>
                      </div>

                      {values.dhcpGatewayMode === "specific" && (
                        <div className="interface-configuration-form-field">
                          <label className="data-label">Gateway IP</label>
                          <IPv4Input label="Gateway IP" required
                            value={values.dhcpGatewayIp}
                            onChange={(value) => setField("dhcpGatewayIp", value)}
                          />
                        </div>
                      )}

                      <div className="interface-configuration-form-field">
                        <label className="data-label">DNS</label>
                        <div className="segmented-control">
                          <input
                            type="radio"
                            id="dns-int"
                            name="dns-ip"
                            value="interface"
                            checked={values.dhcpDnsMode === "interface"}
                            onChange={(event) => setField("dhcpDnsMode", event.target.value)}
                          />
                          <label htmlFor="dns-int">Interface IP</label>
                          <input
                            type="radio"
                            id="dns-specific"
                            name="dns-ip"
                            value="specific"
                            checked={values.dhcpDnsMode === "specific"}
                            onChange={(event) => setField("dhcpDnsMode", event.target.value)}
                          />
                          <label htmlFor="dns-specific">Specific IP</label>
                          <>
                            <input type="radio" id="dns-none" name="dns-ip" value="none"
                              checked={values.dhcpDnsMode === "none"} onChange={event => setField("dhcpDnsMode", event.target.value)} />
                            <label htmlFor="dns-none">None</label>
                          </>
                        </div>
                      </div>

                      {values.dhcpDnsMode === "specific" && (
                        <div className="interface-configuration-form-field">
                          <label className="data-label">DNS IP (Max 3)</label>
                          <div>
                            {(values.dhcpDnsIps || [""]).map((dns, index) => (
                              <div className="interface-picker" key={`dhcp-dns-${index}`}>
                                <IPv4Input label={`DNS IP ${index + 1}`} value={dns} required
                                  onChange={next => setValues(prev => ({...prev, dhcpDnsIps: prev.dhcpDnsIps.map((value, position) => position === index ? next : value)}))} />
                                {index === 0 ? (
                                  <button type="button" className="mini-btn btn-ghost" disabled={values.dhcpDnsIps.length >= 3}
                                    onClick={() => setValues(prev => ({...prev, dhcpDnsIps: prev.dhcpDnsIps.length < 3 ? [...prev.dhcpDnsIps, ""] : prev.dhcpDnsIps}))}>+</button>
                                ) : (
                                  <button type="button" className="mini-btn btn-ghost"
                                    onClick={() => setValues(prev => ({...prev, dhcpDnsIps: prev.dhcpDnsIps.filter((_, position) => position !== index)}))}>−</button>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="interface-configuration-form-field">
                        <label className="data-label" htmlFor="dhcp-lease-hours">Lease time (hours)</label>
                        <input
                          id="dhcp-lease-hours"
                          type="text"
                          inputMode="decimal"
                          value={values.dhcpLease}
                          onChange={(event) => setField("dhcpLease", event.target.value)}
                        />
                      </div>
                    </>
                  )}
                </>
              )}
            </>
          )}
          </>
          )}
        </>
      )}

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Sending..." : mode === "edit" ? "Save" : "OK"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}
