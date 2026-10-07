import { parseJuniperZones, parseCiscoZoneList, parseCiscoZoneMembership } from "../components/cmdGroups/network/zoneInterfaces";

// |====== Auto Select WAN zone/interface ======|

// หลายฟอร์ม (NAT Static/Port Forward's From Zone+WAN Interface, Security
// Profile's WAN Interface, Security Tunnel's ขา Outbound) ต้อง default-select
// interface ที่เป็นสมาชิกของ security zone ชื่อ "WAN" (ตาม convention เดียวกับ
// natFormModal.jsx's "default To Zone = WAN ถ้ามี zone ชื่อนี้อยู่จริง") - รวม
// การ derive รายชื่อ interface ของ zone นั้นไว้ที่เดียวกันกันเขียนซ้ำ 4 ที่
//
// Juniper: security-zone/interfaces เก็บชื่อ interface เต็มพร้อม unit ไว้ตรงๆ
// อยู่แล้ว (เช่น "ge-0/0/0.0") - อ่านจาก parseJuniperZones ตรงๆ
//
// Cisco: zone-member เป็น leaf ใต้ native/interface/<type>/<entry> เอง (ไม่ใช่
// list ย้อนกลับใต้ zone) - ต้อง join กับ get_switchport_information ผ่าน
// parseCiscoZoneMembership (pattern เดียวกับที่ zoneInterfaces.jsx ใช้อยู่แล้ว)
// - ถ้าไม่มี switchportResult (ยังโหลดไม่เสร็จ/ไม่ได้ query) คืน [] เฉยๆ (ไม่ error)
export function getWanZoneInterfaces({ vendor, zoneResult, switchportResult, zoneName = "WAN" }) {
  if (!zoneResult?.normalized) return [];
  const isJuniper = vendor === "juniper";

  if (isJuniper) {
    const zones = parseJuniperZones(zoneResult.result) || [];
    return zones.find((zone) => zone.name === zoneName)?.interfaces || [];
  }

  const zones = parseCiscoZoneList(zoneResult.result) || [];
  if (!zones.some((zone) => zone.name === zoneName)) return [];
  const membership = switchportResult?.normalized ? parseCiscoZoneMembership(switchportResult.result) : {};
  return membership[zoneName] || [];
}
