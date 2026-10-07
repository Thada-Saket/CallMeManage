/**
 * Utility functions for Stateful Firewall Policy identity and selection.
 * Juniper policies have scope within (fromZone, toZone), so their identity
 * is the composite tuple (fromZone, toZone, name).
 * Cisco policies are identified uniquely by their name (zone-pair id).
 */

export function getJuniperPolicyKey(policy) {
  if (!policy) return "";
  const fromZone = policy.fromZone ?? "";
  const toZone = policy.toZone ?? "";
  const name = policy.name ?? "";
  return JSON.stringify([fromZone, toZone, name]);
}

export function getPolicyIdentityKey(policy, isJuniper = false) {
  if (!policy) return "";
  if (isJuniper) {
    return getJuniperPolicyKey(policy);
  }
  return String(policy.name ?? "");
}

export function arePoliciesEqual(policyA, policyB, isJuniper = false) {
  if (!policyA || !policyB) return false;
  if (isJuniper) {
    return (
      (policyA.fromZone ?? "") === (policyB.fromZone ?? "") &&
      (policyA.toZone ?? "") === (policyB.toZone ?? "") &&
      (policyA.name ?? "") === (policyB.name ?? "")
    );
  }
  return (policyA.name ?? "") === (policyB.name ?? "");
}

export function findPolicyByIdentity(policies, keyOrPolicy, isJuniper = false) {
  if (!Array.isArray(policies)) return null;
  const targetKey =
    typeof keyOrPolicy === "string"
      ? keyOrPolicy
      : getPolicyIdentityKey(keyOrPolicy, isJuniper);
  if (!targetKey) return null;
  return (
    policies.find((p) => getPolicyIdentityKey(p, isJuniper) === targetKey) || null
  );
}

export function formatPolicyLabel(policy, isJuniper = false) {
  if (!policy) return "";
  if (isJuniper) {
    return `${policy.name || ""} (${policy.fromZone || ""} → ${policy.toZone || ""})`;
  }
  return `${policy.name || ""} (${policy.source || ""} → ${policy.destination || ""})`;
}

/**
 * Predefined Junos applications for Juniper Stateful Firewall policy.
 * Excludes 'any', which is controlled via the 'Any' / 'Specific' mode switch.
 */
export const JUNIPER_APPLICATIONS = [
  "junos-bgp",
  "junos-dhcp-client",
  "junos-dhcp-relay",
  "junos-dhcp-server",
  "junos-dns-tcp",
  "junos-dns-udp",
  "junos-ftp",
  "junos-ftp-data",
  "junos-gre",
  "junos-http",
  "junos-https",
  "junos-icmp-all",
  "junos-icmp-ping",
  "junos-ike",
  "junos-ike-nat",
  "junos-imap",
  "junos-imaps",
  "junos-ldap",
  "junos-ntp",
  "junos-ospf",
  "junos-pop3",
  "junos-pop3s",
  "junos-radacct",
  "junos-radius",
  "junos-rdp",
  "junos-rip",
  "junos-smtp",
  "junos-smtps",
  "junos-ssh",
  "junos-syslog",
  "junos-tacacs",
  "junos-tacacs-ds",
  "junos-tcp-any",
  "junos-telnet",
  "junos-tftp",
  "junos-udp-any",
  "junos-vnc",
  "junos-vxlan",
  "junos-whois",
];

/**
 * รายการ Application ของ Cisco ZBF (2026-09) - ต้องตรงกับ
 * vendor_translators/cisco_zbf.py::CISCO_ZBF_APPLICATION_CATALOG ทุกตัวอักษรและ
 * ลำดับ (มี automated parity test คู่กันใน tests/) ยืนยันผ่าน CLI completion บน
 * อุปกรณ์จริงโดยผู้ใช้ 23 ก.ย. 2026 (ดู planning/cisco_zbf_survey_2026-09.md
 * section 5) - รายการ explicit ที่ผู้ใช้ให้มามี 31 ค่า ไม่ใช่ 28 ตามที่ requirement
 * เดิมเคยเรียก (ความคลาดเคลื่อนนี้บันทึกไว้แล้ว ไม่ได้ตัดออกเพื่อบังคับให้เหลือ 28)
 *
 * ห้าม reuse JUNIPER_APPLICATIONS - ของ Juniper มี prefix "junos-" และเป็นคนละ
 * namespace โดยสิ้นเชิง (Application ของ Junos ผูกกับ port/protocol combination
 * ที่ config ไว้ล่วงหน้า ส่วนของ Cisco ผูกกับ NBAR protocol ตรงๆ)
 */
export const CISCO_ZBF_APPLICATIONS = [
  "bgp", "ddns-v3", "dhcp-failover", "dns", "hsrp", "http", "https", "icmp",
  "imap", "imap3", "imaps", "isakmp", "ldap", "ldap-admin", "ldaps", "mysql",
  "ntp", "pop3", "pop3s", "radius", "smtp", "snmp", "sqlserv", "ssh", "syslog",
  "tacacs", "tacacs-ds", "tcp", "telnet", "tftp", "udp",
];

/**
 * Format ค่า Cisco ZBF application ดิบ (เช่น "tacacs-ds") ให้อ่านง่าย
 * ("TACACS-DS") - เป็นแค่ uppercase ตรงๆ (ต่างจาก Juniper ที่ต้องตัด prefix
 * "junos-" ออกก่อน) ค่าที่ส่งไป backend ต้องยังเป็นตัวพิมพ์เล็กเดิมเสมอ ห้ามใช้ค่าที่
 * format แล้วนี้ไปสร้าง payload
 */
export function formatCiscoApplicationDisplay(app) {
  if (!app) return "";
  return String(app).trim().toUpperCase();
}

/**
 * Format a raw application string (e.g. "junos-icmp-ping") into a readable display label ("ICMP-PING").
 * "any" becomes "Any". Strips "junos-" prefix and uppercases.
 */
export function formatApplicationDisplay(app) {
  if (!app) return "";
  const trimmed = String(app).trim();
  if (!trimmed) return "";
  if (trimmed.toLowerCase() === "any") return "Any";
  if (trimmed.toLowerCase().startsWith("junos-")) {
    return trimmed.slice(6).toUpperCase();
  }
  return trimmed.toUpperCase();
}

/**
 * Format an array of applications for display in summaries or table columns.
 * Returns emptyText (defaults to "Any") when empty or only containing "any".
 */
export function formatApplicationList(apps, emptyText = "Any") {
  if (!Array.isArray(apps) || apps.length === 0) return emptyText;
  const filtered = apps.filter((a) => a && String(a).trim().toLowerCase() !== "any");
  if (filtered.length === 0) return emptyText;
  return filtered.map((app) => formatApplicationDisplay(app)).join(", ");
}

/**
 * รายการ Services สำหรับ cell ในตาราง Juniper - คืนเป็น array เพื่อ render เป็น <li>
 * ทีละรายการ (หนึ่ง Application ต่อหนึ่งบรรทัด เหมือนช่อง Interface ของหน้า Zone)
 * คงลำดับตามที่อ่านจากอุปกรณ์ ค่าที่ไม่อยู่ใน JUNIPER_APPLICATIONS (Brownfield) ยังแสดง
 * ชื่อจริงแบบอ่านง่าย ส่วน "any" หรือไม่มี application เลย = ["Any"] รายการเดียว
 * known=false (อ่านไม่ได้ว่ามี application อะไร) คืน [] ห้ามเดาเป็น Any
 */
export function getApplicationDisplayItems(apps, known = true) {
  if (!known) return [];
  const filtered = (Array.isArray(apps) ? apps : [])
    .filter((a) => a && String(a).trim() && String(a).trim().toLowerCase() !== "any");
  if (filtered.length === 0) return ["Any"];
  return filtered.map((app) => formatApplicationDisplay(app));
}

/**
 * Parameters ที่ปุ่ม ↑/↓ ส่งไป move_security_policy - ส่งแค่ identity + ทิศ + revision ที่เห็น
 * ไม่ส่ง Policy ข้างเคียง (backend คำนวณจาก Running Configuration ล่าสุดภายใน DeviceLock)
 */
export function buildMovePolicyParameters(policy, direction) {
  return {
    from_zone: policy.fromZone,
    to_zone: policy.toZone,
    policy_name: policy.name,
    direction,
    expected_order_revision: policy.orderRevision || undefined,
    expected_revision: policy.revision || undefined,
  };
}

// "any" (leaf-list value ปกติของ Junos) และ "0.0.0.0/0" (บาง config เขียน address
// แบบ prefix เต็มตรงๆ แทน keyword any) มีความหมายเดียวกันคือ "ไม่จำกัด" - แสดงผลเป็น
// "Any" เหมือนกันทั้งคู่ เทียบแบบ case-insensitive เผื่อ Brownfield พิมพ์ "ANY"/"Any"
const ANY_ADDRESS_VALUES = new Set(["any", "0.0.0.0/0"]);

/**
 * รายการ Source/Destination Address สำหรับ cell ในตาราง Juniper - คู่กับ
 * getApplicationDisplayItems ใช้กับ Services คืนเป็น array เพื่อ render เป็น <li>
 * ทีละรายการ หนึ่ง address ต่อหนึ่งบรรทัด คงลำดับตามที่อ่านจากอุปกรณ์ ไม่ตัด/ไม่แสดง
 * เพียงตัวแรก
 *
 * เป็นแค่ display mapping เท่านั้น - "any"/"0.0.0.0/0" แสดงเป็น "Any" แต่ค่าดิบใน
 * policy.sourceAddresses/destinationAddresses (state/payload/ข้อมูลสำหรับ Edit) ยัง
 * เป็นค่าเดิมเป๊ะ ไม่ถูกเขียนทับ - ค่าอื่นเช่นชื่อ Address Book หรือ prefix อื่นแสดง
 * ตามจริงเสมอ ไม่เดาว่าเป็น Any และไม่แก้ไขชื่อใดๆ
 *
 * known=false (อ่านไม่ได้ว่ามี address อะไร) คืน [] ห้ามเดาเป็น Any
 */
export function getAddressDisplayItems(addresses, known = true) {
  if (!known) return [];
  const filtered = (Array.isArray(addresses) ? addresses : [])
    .filter((a) => a && String(a).trim());
  if (filtered.length === 0) return ["Any"];
  return filtered.map((addr) => {
    const trimmed = String(addr).trim();
    return ANY_ADDRESS_VALUES.has(trimmed.toLowerCase()) ? "Any" : trimmed;
  });
}

const UNSPECIFIED_ZONE_LABEL = "Unspecified Zone";

/**
 * จัดกลุ่ม Policy ตามคู่ (From Zone, To Zone) สำหรับแทรกแถวหัวข้อในตาราง (ทั้ง Cisco
 * และ Juniper) - Cisco ใช้ source/destination, Juniper ใช้ fromZone/toZone
 *
 * ใช้ Map คีย์ JSON.stringify([from, to]) (ค่าจริง ไม่ใช่ label ที่แสดง) จึงไม่จับคู่ผิด
 * เมื่อ Zone ว่าง และ policy ของคู่เดียวกันที่กระจายอยู่คนละตำแหน่งใน array (Cisco)
 * จะถูกรวบเข้ากลุ่มเดียวกันโดยอัตโนมัติ - ลำดับกลุ่มคือลำดับที่ "พบครั้งแรก" ในข้อมูล
 * (Map รักษา insertion order) และลำดับ policy ภายในกลุ่มคือลำดับที่พบในข้อมูลต้นทาง
 * ไม่มีการ sort ใด ๆ ทั้งสิ้น - Juniper ลำดับมีผลกับ Traffic จริงจึงห้ามสลับ
 */
export function groupPoliciesByZonePair(policies, isJuniper = false) {
  if (!Array.isArray(policies)) return [];
  const groups = new Map();
  for (const policy of policies) {
    const from = (isJuniper ? policy?.fromZone : policy?.source) ?? "";
    const to = (isJuniper ? policy?.toZone : policy?.destination) ?? "";
    const key = JSON.stringify([from, to]);
    let group = groups.get(key);
    if (!group) {
      group = { key, title: `${from || UNSPECIFIED_ZONE_LABEL} → ${to || UNSPECIFIED_ZONE_LABEL}`, rows: [] };
      groups.set(key, group);
    }
    group.rows.push(policy);
  }
  return [...groups.values()];
}

/**
 * Cisco ZBF เท่านั้น (2026-09) - Cisco ไม่อนุญาตให้มี Zone Pair สองตัวที่คู่
 * (source, destination) ซ้ำกัน (ต่างจาก Juniper ที่มีหลาย Policy ในคู่ Zone เดียวกันได้
 * ปกติ) - ดึงคู่ Zone ที่ "ใช้งานแล้ว" จาก policy.source/policy.destination ที่
 * ciscoZbfParser.js เดินตาม reference จริงจากอุปกรณ์มาให้เท่านั้น (ห้าม derive จากชื่อ
 * Policy หรือชื่อ FW_<name> - ชื่อ Policy ไม่ใช่ตัวตัดสินคู่ซ้ำ)
 *
 * - เทียบชื่อ Zone แบบ exact string (ชื่อ Zone เป็นค่าจริงบนอุปกรณ์ ห้าม lowercase เอง)
 * - ข้าม record ที่ source หรือ destination ว่าง (พิสูจน์คู่ไม่ได้)
 * - currentPolicyName = ชื่อ Zone Pair ที่กำลังแก้ไขเอง (Edit) - ไม่นับคู่เดิมของตัวเอง
 *   เป็น collision กับตัวเอง (New ส่ง null)
 * - Deduplicate คู่ซ้ำสำหรับคำนวณ dropdown
 */
export function getCiscoUsedZonePairs(existingPolicies, currentPolicyName = null) {
  if (!Array.isArray(existingPolicies)) return [];
  const seen = new Set();
  const pairs = [];
  for (const policy of existingPolicies) {
    const source = policy?.source;
    const destination = policy?.destination;
    if (!source || !destination) continue;
    if (currentPolicyName && policy?.name === currentPolicyName) continue;
    const key = JSON.stringify([source, destination]);
    if (seen.has(key)) continue;
    seen.add(key);
    pairs.push({ source, destination, name: policy?.name || "" });
  }
  return pairs;
}

/**
 * Cisco From Zone dropdown: ตัด Zone เดียวกับ To Zone ที่เลือกไว้ออก และตัด Source Zone
 * ที่มีคู่กับ To Zone นี้อยู่แล้วใน Zone Pair อื่นออก - ถ้ายังไม่เลือก To Zone (toZone ว่าง)
 * แสดง Zone ทั้งหมดโดยไม่กรองคู่ (ยังพิสูจน์ collision ไม่ได้จนกว่าจะรู้ทั้งสองฝั่ง)
 */
export function computeCiscoFromZoneOptions(allZones, toZone, usedZonePairs) {
  if (!Array.isArray(allZones)) return [];
  return allZones.filter((zone) => {
    if (zone === toZone) return false;
    if (!toZone) return true;
    return !usedZonePairs.some((pair) => pair.source === zone && pair.destination === toZone);
  });
}

/** เหมือน computeCiscoFromZoneOptions แต่กรอง To Zone ตาม From Zone ที่เลือกไว้ */
export function computeCiscoToZoneOptions(allZones, fromZone, usedZonePairs) {
  if (!Array.isArray(allZones)) return [];
  return allZones.filter((zone) => {
    if (zone === fromZone) return false;
    if (!fromZone) return true;
    return !usedZonePairs.some((pair) => pair.source === fromZone && pair.destination === zone);
  });
}

/** ข้อความ error ของการเลื่อน + ควร refetch ไหม (ลำดับบนอุปกรณ์อาจไม่ตรงกับที่เห็นอยู่) */
export function describeMovePolicyError(err) {
  const detail = err?.detail;
  const message =
    typeof detail === "object" && detail?.message
      ? detail.message
      : typeof detail === "string" && detail
      ? detail
      : "Failed to move Firewall policy order";
  const code = typeof detail === "object" ? detail?.code || "" : "";
  const text = typeof detail === "string" ? detail : "";
  const stale =
    err?.status === 409 ||
    err?.status === 404 ||
    ["POLICY_ORDER_CONCURRENT_MODIFICATION", "POLICY_NOT_FOUND", "POLICY_ORDER_REVISION_REQUIRED"].includes(code) ||
    text.includes("POLICY_ORDER_CONCURRENT_MODIFICATION") ||
    text.includes("POLICY_NOT_FOUND");
  return { message, refetch: stale };
}
