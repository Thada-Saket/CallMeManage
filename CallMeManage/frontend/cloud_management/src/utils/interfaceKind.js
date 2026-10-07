// |====== Interface kind (tunnel หรือไม่) ======|

// "อะไรคือ tunnel interface" เคยถูกเขียนซ้ำอยู่ 3 ที่ด้วยรูปแบบที่ต่างกันเล็กน้อย
// (interfaces.jsx's classifyInterfaceCategory, security_tunnel.jsx's ตัวแยก
// st0/gr- ตอน derive interface_number, security_tunnelFormModal.jsx's ตัวกรอง
// ขา Outbound) - รวมมาไว้ที่เดียวตามบทเรียน BUG-12→15 ใน
// planning/PENDING_DECISIONS.md ข้อ 1 ("กฎของของชนิดเดียวกันต้องอยู่ที่เดียว
// ทุกครั้งที่ปล่อยให้แต่ละไฟล์เขียนกฎเอง กฎเพี้ยนออกจากกันเสมอ")
//
// ชื่อที่นับเป็น tunnel (ยืนยันจากโค้ดที่สร้างมันเองใน vendor_translators):
//   Cisco   - Tunnel0, Tunnel1, ...        (create_security_tunnel)
//   Juniper - st0.0, st0.1, ...            (IPsec route-based, bind-interface)
//             gr-0/0/0.0, ...              (GRE, gr- เป็น pseudo physical)
//
// **ต้องเทียบกับชื่อเต็ม ไม่ใช่ interfaceType ที่ splitInterfaceName ตัดมาให้**
// เพราะ splitInterfaceName ตัดที่ตัวเลขตัวแรก ทำให้ "st0.1" ได้ type="st" เฉยๆ
// ไม่ตรงกับ "st0" ที่ต้องการ (เจอบั๊กจริงตอนทดสอบ - comment เดิมใน interfaces.jsx)
export function isTunnelInterfaceName(fullName) {
  if (typeof fullName !== "string") return false;
  return /^(tunnel|gre|gr-|st0)/.test(fullName.trim().toLowerCase());
}

// |====== Juniper: ขาที่ใช้เป็น routing leg ได้จริง ======|

// ชนิด ethernet ที่รองรับ - แหล่งเดียวของกฎนี้ (InterfacesFormModal.jsx's
// SWITCHPORT_CAPABLE_PREFIXES import ไปใช้ ไม่ประกาศซ้ำ ตามกฎ "กฎของของชนิด
// เดียวกันต้องอยู่ที่เดียว" ที่หัวไฟล์นี้อธิบายไว้)
export const JUNIPER_ETHERNET_PREFIXES = ["ge-", "xe-", "fe-", "et-", "mge-", "ae", "reth"];

export const JUNIPER_SYSTEM_SERVICE_INTERFACES = [
  "ip", "lsq", "lt", "mt", "sp", "dsc", "fti", "ipip", "lsi", "mtun",
  "pime", "pp0", "ppd0", "ppe0", "tap", "fti0", "pimd"
];

function juniperParentName(fullName) {
  return String(fullName || "").trim().toLowerCase().split(".")[0];
}

function matchesJuniperFamily(parent, family) {
  if (parent === family) return true;
  // Hardware-backed pseudo interfaces normally use family-0/0/0, while some
  // service interfaces are numbered directly (pp0, ppd0, ppe0).
  return parent.startsWith(`${family}-`);
}

export function isJuniperSystemServiceInterface(fullName) {
  const parent = juniperParentName(fullName);
  return JUNIPER_SYSTEM_SERVICE_INTERFACES.some((family) => matchesJuniperFamily(parent, family));
}

export function isJuniperManagementInterface(fullName) {
  return juniperParentName(fullName) === "fxp0";
}

// Junos ให้ตั้ง unit ได้ถึง 16385 แต่เลขตั้งแต่ 16383 ขึ้นไปเป็นของที่อุปกรณ์
// สร้างใช้เองภายใน ไม่ใช่ขาที่ผู้ใช้ตั้ง (ยืนยันจากอุปกรณ์จริง: sp-0/0/0.16383,
// lo0.16384, lo0.16385, lo0.32768, ge-0/0/2.32767 โผล่มาเองทั้งหมดโดยไม่มีใคร
// สั่ง) - ระบบนี้สร้าง unit แค่ 0 กับเลข VLAN (1-4094) เท่านั้นอยู่แล้ว จึงตัด
// ทุกอย่างที่เกินช่วงนั้นทิ้ง
const JUNIPER_MAX_CONFIGURABLE_UNIT = 4094;

// "ขาที่ใช้งานได้จริง" ของ Junos สำหรับ routing protocol = ต้องเป็น unit เสมอ
// (physical เปล่า ๆ ผูก protocol ไม่ได้) และต้องเป็นชนิดใดชนิดหนึ่งใน 4 กลุ่มนี้:
// ethernet interface, VLAN interface (irb), sub-interface (ก็คือ unit ของ
// ethernet ที่ไม่ใช่ 0) และ tunnel
//
// ที่ถูกตัดทิ้งจากอุปกรณ์จริง: physical ทุกตัว · fxp0.0 (ช่อง management) ·
// lo0.* (loopback รวม unit ภายใน) · sp-0/0/0.* (services PIC) · ge-0/0/2.32767
// (unit ภายในของ Junos บนขาที่เปิด vlan-tagging)
export function isJuniperRoutableUnit(fullName) {
  if (typeof fullName !== "string") return false;
  const name = fullName.trim();
  const dotIndex = name.lastIndexOf(".");
  if (dotIndex === -1) return false;
  const unit = name.slice(dotIndex + 1);
  if (!/^\d+$/.test(unit) || Number(unit) > JUNIPER_MAX_CONFIGURABLE_UNIT) return false;
  const parent = name.slice(0, dotIndex).toLowerCase();
  if (isJuniperSystemServiceInterface(name) || isJuniperManagementInterface(name)) return false;
  if (isTunnelInterfaceName(name)) return true;
  if (parent === "irb" || parent === "vlan") return true;
  return JUNIPER_ETHERNET_PREFIXES.some((prefix) => parent.startsWith(prefix));
}


// Dropdown กลางของ Juniper ใช้ได้เฉพาะ logical unit จากสามหมวดที่ผู้ใช้จัดการได้:
// Physical/Sub-interface, VLAN/SVI และ Tunnel เท่านั้น ชื่อ alias นี้สื่อ intent
// ของ UI ชัดกว่า isJuniperRoutableUnit แต่คงฟังก์ชันเดิมไว้ให้ routing callers
// ที่ใช้อยู่แล้วไม่ต้องแตกกฎออกเป็นสองชุดอีกครั้ง
export const isJuniperSelectableInterfaceUnit = isJuniperRoutableUnit;
