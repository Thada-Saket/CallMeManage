/**
 * Zone-name-only parsers ใช้เติม dropdown From/To Zone ของฟอร์ม Stateful Firewall
 * (ทั้ง Cisco และ Juniper) - แยกออกมาจาก zoneInterfaces.jsx โดยตั้งใจ (2026-09)
 * เพราะไฟล์นั้นเป็น React component เต็มตัว การ import แค่ helper เดียวจากไฟล์
 * component ทำให้ dependency สับสน (แม้จะไม่มีปัญหา runtime จริงเพราะ ES module
 * import แค่ named export ที่ใช้ ไม่ execute component) - โมดูลนี้เป็น pure
 * function ล้วน ไม่มี hook/side effect
 *
 * ต่างจาก parseJuniperZones()/parseCiscoZoneList() ใน zoneInterfaces.jsx ตรงที่
 * ไฟล์นั้นอ่านครบทั้ง interfaces/services/protocols (ใช้แสดงตาราง Zone Interfaces)
 * ส่วนที่นี่อ่านแค่ "รายชื่อ Zone" เพื่อเติม dropdown เท่านั้น
 */

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// security/zones/security-zone/name - Junos ปฏิเสธตอน commit ถ้า zone ไม่มีจริง
// (ยืนยันจริงตอนทดสอบ set_security_policy - "Security zone must be defined")
// คืน null เมื่อ parse ไม่สำเร็จหรือ response ไม่ครบ (แยกจาก [] ที่แปลว่า "อ่านสำเร็จแต่ยังไม่มี Zone เลย")
export function parseJuniperZoneNames(result) {
  try {
    const raw = result && typeof result === "object" && "result" in result && result.result ? result.result : result;
    if (!raw || typeof raw !== "object") return null;
    const payload = raw.payload;
    if (!payload || typeof payload !== "object") return null;
    const data = payload.data;
    if (!data || typeof data !== "object") return null;
    const configuration = data.configuration;
    if (configuration === undefined || (configuration !== "" && typeof configuration !== "object")) return null;
    if (configuration === "") return [];
    const security = configuration.security;
    if (security === undefined || (security !== "" && typeof security !== "object")) return null;
    if (security === "") return [];
    const zonesContainer = security.zones;
    if (zonesContainer === undefined || zonesContainer === null || zonesContainer === "") return [];
    if (typeof zonesContainer !== "object") return null;
    const secZone = zonesContainer["security-zone"];
    if (secZone === undefined || secZone === null || secZone === "") return [];
    const zones = ensureArray(secZone);
    return zones.map((zone) => (typeof zone === "object" && zone !== null ? zone?.name : zone)).filter(Boolean);
  } catch {
    return null;
  }
}

// native/zone/security/id - Cisco IOS-XE เก็บชื่อ Zone ไว้ที่ id (ตรงกับที่
// set_security_zone เขียน และ ciscoZbfParser.js ใช้ join reference จริง)
// คืน null เมื่อ response ไม่ครบหรือ parse ไม่ได้ (แยกจาก [] เมื่ออ่านสำเร็จแต่ไม่มี Zone)
export function parseCiscoZoneNames(result) {
  try {
    const raw = result && typeof result === "object" && "result" in result && result.result ? result.result : result;
    if (!raw || typeof raw !== "object") return null;
    const payload = raw.payload;
    if (!payload || typeof payload !== "object") return null;
    const data = payload.data;
    if (!data || typeof data !== "object") return null;
    if (!("native" in data)) return null;
    const native = data.native;
    if (native === "") return [];
    if (!native || typeof native !== "object") return null;
    if (!("zone" in native)) return [];
    const zoneContainer = native.zone;
    if (zoneContainer === "" || zoneContainer === null || zoneContainer === undefined) return [];
    if (typeof zoneContainer !== "object") return null;
    if (!("security" in zoneContainer)) return [];
    const sec = zoneContainer.security;
    if (sec === "" || sec === null || sec === undefined) return [];
    if (typeof sec !== "object") return null;
    const zones = ensureArray(sec);
    return zones.map((zone) => (typeof zone === "object" && zone !== null ? zone?.id : zone)).filter(Boolean);
  } catch {
    return null;
  }
}

