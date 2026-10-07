// |====== DHCP Utilities ======|

// Translate IP to Int : แปลง ip ให้กลายเป็นตัวเลข 32-bit เช่นจาก 192.168.1.1 = 3232235777
function ipToInt(ip) {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

// Translate Int to IP : แปลงตัวเลข 32-bit ให้กลายเป็น ip เช่นจาก 3232235777 = 192.168.1.1
function intToIp(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

// Cisco DHCP pool ไม่มี concept "ช่วง IP ที่แจก" ตรงๆ - แจกทั้ง network แล้วกัน
// เฉพาะที่ excluded ออก แบบ FortiGate ผู้ใช้กรอก "ช่วงที่จะแจก" (เช่น
// x.x.x.11-x.x.x.200) เลยต้อง "กลับด้าน" เป็น excluded = ทุก IP ที่อยู่ "นอก"
// ช่วงนั้นภายใน network (host แรกถึง start-1 และ end+1 ถึง host สุดท้าย) -
// คืน [] ถ้าไม่กรอก range (แจกทั้ง network), null ถ้า range/network ไม่ valid
// ใช้ร่วมกันทั้งฟอร์ม DHCP บน interface (InterfacesFormModal) และหน้า DHCP pool
// เดี่ยว (dhcpFormModal)
// ใช้หา dhcp exclude โดยแปลงจาก dhcp range ที่ผู้ใช้กรอกมาจากหน้าเว็บ เรียกใช้ใน InterfacesFormModal.jsx และ dhcpFormModal.jsx
export function computeDhcpExclusions(networkCidr, rangeStr) {
  const slash = networkCidr.indexOf("/");
  if (slash === -1) return null;
  const netInt = ipToInt(networkCidr.slice(0, slash));
  const prefix = Number(networkCidr.slice(slash + 1));
  if (netInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;

  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const networkAddr = (netInt & maskInt) >>> 0;
  const broadcast = (networkAddr | (~maskInt >>> 0)) >>> 0;
  const firstHost = (networkAddr + 1) >>> 0;
  const lastHost = (broadcast - 1) >>> 0;

  const trimmed = rangeStr.trim();
  if (!trimmed) return []; // ไม่กรอก = แจกทั้ง network ไม่ต้อง exclude อะไร

  const [startRaw, endRaw] = trimmed.split("-");
  const startInt = ipToInt(startRaw || "");
  const endInt = ipToInt(endRaw || "");
  if (startInt === null || endInt === null || startInt > endInt) return null;
  if (startInt < firstHost || endInt > lastHost) return null; // ช่วงต้องอยู่ใน network

  const excludes = [];
  if (startInt > firstHost) excludes.push(`${intToIp(firstHost)}-${intToIp((startInt - 1) >>> 0)}`);
  if (endInt < lastHost) excludes.push(`${intToIp((endInt + 1) >>> 0)}-${intToIp(lastHost)}`);
  return excludes;
}

// ทำให้ข้อมูลที่ผ่าน function นี้เป็น array อย่างแน่นอนไม่ว่างจะกรอกค่าอะไร
function ensureArrayLocal(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// เช็คว่า mask (dotted decimal เช่น "255.255.255.0") เป็น mask ที่ถูกต้อง (bit 1
// ต่อกันจากซ้ายล้วนๆ) แล้วคืน prefix length - คืน null ถ้าไม่ใช่ mask ที่ถูกต้อง
// แปลงเลข subnet ให้กลายเป็น prefix เรียกใช้ใน interface.jsx, InterfacesFormModal.jsx, dhcpRange.js
export function maskToPrefix(maskStr) {
  const maskInt = ipToInt(maskStr || "");
  if (maskInt === null) return null;
  let ones = 0;
  while (ones < 32 && (maskInt >>> (31 - ones)) & 1) ones++;
  const rebuilt = ones === 0 ? 0 : (0xffffffff << (32 - ones)) >>> 0;
  return rebuilt === maskInt ? ones : null;
}

// อ่าน <excluded-address> ตรงกับโครงสร้างที่ set_dhcp_pool เขียน (สองแบบ: ip เดี่ยว
// low-address-list กับช่วง low-high-address-list) - excluded-address เป็น global
// (พี่น้องของ pool ใน <dhcp> ไม่ได้ผูกกับ pool ไหนโดยเฉพาะ - ตรงกับพฤติกรรมจริงของ
// Cisco "ip dhcp excluded-address") ต้องเอามากรองเอาเฉพาะที่ตกในช่วง network ของ
// แต่ละ pool เองอีกที (ดู computeUsableRange)
// อ่านค่าว่าห้ามแจก ip range ไหน เรียกใช้ใน dhcp.jsx
export function parseExcludedRanges(excludedAddressNode) {
  if (!excludedAddressNode) return [];
  const ranges = [];
  for (const single of ensureArrayLocal(excludedAddressNode["low-address-list"])) {
    const ip = ipToInt(single?.["low-address"] || "");
    if (ip !== null) ranges.push({ start: ip, end: ip });
  }
  for (const pair of ensureArrayLocal(excludedAddressNode["low-high-address-list"])) {
    const low = ipToInt(pair?.["low-address"] || "");
    const high = ipToInt(pair?.["high-address"] || "");
    if (low !== null && high !== null) ranges.push({ start: low, end: high });
  }
  return ranges;
}

// คืน excluded-address ranges (string "low-high" หรือ "low" เดี่ยว) ที่ตกอยู่ใน
// ช่วง network ของ pool นี้เป๊ะๆ - ต่างจาก computeUsableRange ที่คืน "ช่วงที่แจก
// ได้" (ช่องว่างระหว่าง exclude) ตัวนี้คืนตัว exclude เอง ใช้ตอน "แก้ไข" pool
// เพราะ excluded-address เป็น global บน Cisco (ไม่ผูกกับ pool ไหนโดยเฉพาะ) -
// remove_dhcp_pool ต้องรู้ค่าที่แน่นอนถึงจะลบทิ้งได้ตรงตัว ไม่ใช่แค่รู้ network
// ตัวกรองและค้นหาเป้าหมาย dhcp exclude ใช้สำหรับตอนที่ต้องการแก้ไข dhcp range เรียกใช้ใน dhcp.jsx
export function relevantExcludeStrings(network, excludedRanges) {
  let networkAddr;
  let maskInt;
  if (typeof network === "string") {
    const slash = network.indexOf("/");
    if (slash === -1) return [];
    const netInt = ipToInt(network.slice(0, slash));
    const prefix = Number(network.slice(slash + 1));
    if (netInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return [];
    maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    networkAddr = (netInt & maskInt) >>> 0;
  } else {
    const netInt = ipToInt(network?.number || "");
    const prefix = maskToPrefix(network?.mask || "");
    if (netInt === null || prefix === null) return [];
    maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    networkAddr = (netInt & maskInt) >>> 0;
  }
  const broadcast = (networkAddr | (~maskInt >>> 0)) >>> 0;
  const start = (networkAddr + 1) >>> 0;
  const end = (broadcast - 1) >>> 0;
  return (excludedRanges || [])
    .filter((r) => r.end >= start && r.start <= end)
    .map((r) => (r.start === r.end ? intToIp(r.start) : `${intToIp(r.start)}-${intToIp(r.end)}`));
}

// ด้านตรงข้ามของ computeDhcpExclusions: มี network + excluded ranges (จากอุปกรณ์
// จริง) อยากได้ "ช่วงที่แจกได้จริง" กลับมาแสดงในตาราง รองรับ network เป็น CIDR
// string ("x.x.x.x/nn") หรือ object {number, mask} แบบที่ Cisco คืนมา (dotted mask)
// - รองรับเฉพาะรูปแบบง่าย (exclusion ชนขอบซ้าย/ขวาของ usable range เท่านั้น ตรงกับ
// ที่ฟอร์มของเราสร้างเอง) ถ้า exclusion อยู่กลาง usable range (มาจากการตั้งค่าเอง
// ผ่าน CLI แบบซับซ้อนกว่านี้) คืน null แทนการเดา
// ใช้คำนวณหา dhcp range โดยหาจาก exclude เรียกใช้ใน dhcp.jsx
export function computeUsableRange(network, excludedRanges) {
  let networkAddr;
  let maskInt;
  if (typeof network === "string") {
    const slash = network.indexOf("/");
    if (slash === -1) return null;
    const netInt = ipToInt(network.slice(0, slash));
    const prefix = Number(network.slice(slash + 1));
    if (netInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
    maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    networkAddr = (netInt & maskInt) >>> 0;
  } else {
    const netInt = ipToInt(network?.number || "");
    const prefix = maskToPrefix(network?.mask || "");
    if (netInt === null || prefix === null) return null;
    maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    networkAddr = (netInt & maskInt) >>> 0;
  }

  const broadcast = (networkAddr | (~maskInt >>> 0)) >>> 0;
  let start = (networkAddr + 1) >>> 0;
  let end = (broadcast - 1) >>> 0;
  if (start > end) return null;

  const relevant = (excludedRanges || [])
    .filter((r) => r.end >= start && r.start <= end)
    .sort((a, b) => a.start - b.start);

  for (const range of relevant) {
    if (range.start <= start) {
      start = Math.max(start, (range.end + 1) >>> 0);
    } else if (range.end >= end) {
      end = Math.min(end, (range.start - 1) >>> 0);
    } else {
      return null;
    }
  }
  if (start > end) return null;
  return `${intToIp(start)}-${intToIp(end)}`;
}

export function parseRangeEndpoints(str) {
  if (!str) return "";
  const parts = str.split("-").map((s) => s.trim());
  return parts.length > 1 ? `${parts[0]}-${parts[1]}` : `${parts[0]}-${parts[0]}`;
}

export function filterExplicitExclusions(excludeRanges, originalNetwork, originalStartAddress, originalEndAddress) {
  if (!excludeRanges || !excludeRanges.length) return [];
  if (!originalStartAddress || !originalEndAddress || !originalNetwork) return [...excludeRanges];
  let cidr = originalNetwork;
  if (typeof cidr === "string" && cidr.includes(" ") && !cidr.includes("/")) {
    const [ip, mask] = cidr.trim().split(/\s+/);
    const prefix = maskToPrefix(mask);
    if (prefix !== null) cidr = `${ip}/${prefix}`;
  } else if (typeof cidr === "object" && cidr?.number && cidr?.mask) {
    const prefix = maskToPrefix(cidr.mask);
    if (prefix !== null) cidr = `${cidr.number}/${prefix}`;
  }
  const oldDerived = computeDhcpExclusions(cidr, `${originalStartAddress}-${originalEndAddress}`) || [];
  const oldDerivedNormalized = new Set(oldDerived.map(parseRangeEndpoints));
  return excludeRanges.filter((entry) => !oldDerivedNormalized.has(parseRangeEndpoints(entry)));
}
