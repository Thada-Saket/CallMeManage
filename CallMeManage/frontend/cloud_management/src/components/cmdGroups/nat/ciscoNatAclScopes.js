function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// แปลง wildcard mask ของ Cisco เป็น prefix length สำหรับแสดงวง ACL ในฟอร์ม NAT
function wildcardToPrefix(wildcard) {
  const parts = String(wildcard || "").trim().split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  const mask = parts.map((part) => 255 - part);
  const bits = mask.map((part) => part.toString(2).padStart(8, "0")).join("");
  if (!/^1*0*$/.test(bits)) return null;
  return bits.indexOf("0") < 0 ? 32 : bits.indexOf("0");
}

function ipToInt(ip) {
  const parts = String(ip ?? "").trim().split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function intToIp(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

// (2026-09) แยกออกมาจาก nat.jsx เพื่อ unit test ได้ตรงๆ (เดิม unexported อยู่ในไฟล์
// component) - ระหว่างทางแก้ 2 ช่องโหว่ที่พบจริง (ทั้งคู่เข้าข่าย "ACL ที่ระบบไม่
// รองรับต้องไม่ถูกแปลงเป็น Any หรือรายการว่างเงียบๆ"):
//
// 1. เดิมอ่านแค่ native/ip/access-list/extended - ACL แบบ standard (Brownfield NAT
//    อ้างถึงได้จริง ดู get_nat_dashboard_acl ที่ backend ตอนนี้ขอทั้งสองแบบ) หาไม่เจอ
//    ใน .extended เลย ได้ [] แล้วฟอร์มตีความเป็น "Any" เงียบๆ - standard ACL ACE field
//    ("host"/"network-wildcard" หรือชื่ออื่น) ยังไม่เคยยืนยันจากอุปกรณ์จริงในโปรเจกต์
//    นี้ (ต่างจาก extended ที่ verify แล้ว) จึง fail-closed แทนการเดา schema
// 2. permit rule ที่ match รูปแบบอื่นที่ parser นี้ไม่รู้จัก (object-group/port/
//    protocol เฉพาะ ฯลฯ) เดิมถูกข้ามเงียบๆ ในลูป - ตอนนี้ทำให้ unreadable=true แทน
//
// คืน { scopes, unreadable } เสมอ - ผู้เรียก (nat.jsx) ต้อง fail-closed (ห้ามเปิด
// ฟอร์มให้ Save ทับ) เมื่อ unreadable=true เหมือนกับตอน ACL หาไม่เจอบนอุปกรณ์เลย
export function parseCiscoNatScopes(result, aclName) {
  try {
    const accessList = result?.payload?.data?.native?.ip?.["access-list"] || {};
    const standardMatch = ensureArray(accessList.standard).find((entry) => entry?.name === aclName);
    if (standardMatch) {
      return { scopes: [], unreadable: true };
    }

    const extendedMatch = ensureArray(accessList.extended).find((entry) => entry?.name === aclName);
    if (!extendedMatch) return { scopes: [], unreadable: false };

    const scopes = [];
    let unreadable = false;
    for (const seqRule of ensureArray(extendedMatch["access-list-seq-rule"])) {
      const ace = seqRule?.["ace-rule"] || {};
      if (ace.action && ace.action !== "permit") continue;

      if ("any" in ace) {
        scopes.push("any");
        continue;
      }
      if (ace["host-address"]) {
        scopes.push(`${ace["host-address"]}/32`);
        continue;
      }
      if (ace["ipv4-address"] && ace.mask) {
        const prefix = wildcardToPrefix(ace.mask);
        const ip = ipToInt(ace["ipv4-address"]);
        if (prefix !== null && ip !== null) {
          const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
          scopes.push(`${intToIp(ip & mask)}/${prefix}`);
          continue;
        }
      }
      unreadable = true;
    }
    return { scopes: [...new Set(scopes)], unreadable };
  } catch {
    return { scopes: [], unreadable: true };
  }
}
