const CISCO_ROUTE_MODE_ITEMS = new Set(["IP Routing", "IP Default-Gateway"]);

export function parseIpRouting(result) {
  // Cisco-IOS-XE-ip.yang กำหนด leaf routing เป็น boolean default "true" อุปกรณ์
  // จึง omit ทั้ง leaf/container ได้เมื่อใช้ ip routing ค่า default; normalized
  // reply ที่มี payload แต่หา leaf ไม่พบต้องแปลเป็น true ไม่ใช่ "อ่านไม่ได้"
  if (!result || !Object.hasOwn(result, "payload")) return null;
  const value = result?.payload?.data?.native?.ip?.["routing-conf"]?.routing;
  if (value === true || value === "true") return true;
  if (value === false || value === "false") return false;
  return true;
}

// Cisco router ใช้ routing อยู่ตลอดและไม่มี use-case ของสองเมนูนี้ ส่วน switch
// ต้องเห็น toggle เสมอ แต่ default-gateway มีผลเฉพาะตอน no ip routing เท่านั้น
export function showCiscoRouteModeItem(
  itemName,
  vendor,
  platformRole,
  routingEnabled,
  requiresIpRouting = false,
) {
  if (!CISCO_ROUTE_MODE_ITEMS.has(itemName) && !requiresIpRouting) return true;
  // กฎ runtime นี้ใช้เฉพาะ Cisco switch; router และยี่ห้ออื่นมีวิธี routing
  // ของตัวเองและต้องไม่ถูกสถานะ toggle ของ Cisco มากรองเมนู
  if (requiresIpRouting) {
    if (vendor !== "cisco" || platformRole !== "switch") return true;
    return routingEnabled === true;
  }
  if (vendor !== "cisco" || platformRole !== "switch") return false;
  if (itemName === "IP Default-Gateway") return routingEnabled === false;
  return true;
}
