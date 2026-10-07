// ใส่นามสกุล .js ไว้ตั้งใจ (แบบเดียวกับ aclReferenceCheck.js) - Vite เติมให้เองก็จริง
// แต่ Node ESM ไม่เติม ชุดทดสอบ tests/test_zone_render.mjs โหลดไฟล์นี้ตรงๆ จาก path
// จริงเพื่อทดสอบกฎ guard เลยต้องเขียนให้ Node resolve ได้ด้วย
import { isTunnelInterfaceName } from "./interfaceKind.js";

// Match the WAN-zone convention used by NAT/VPN forms, not NETCONF services.
//
// guard นี้มีเหตุผลเดียว: กันผู้ใช้เผลอถอด **ขาที่ NETCONF callhome วิ่งผ่าน**
// ออกจาก zone WAN แล้วคุยกับอุปกรณ์ไม่ได้อีกจนต้องไปแก้ทาง console (เคสจริงที่
// ทำให้เกิด guard ตัวนี้ - ผู้ใช้เผลอถอด ge-0/0/0.0 ออกจาก zone "WAN" ที่เปิด
// netconf/ssh/dhcp/ping ไว้ผ่าน host-inbound-traffic)
//
// tunnel ที่อยู่ใน zone WAN ด้วย (st0.x ของ IPsec / gr-* ของ GRE) **ไม่ใช่ขานั้น**
// - มันเป็น overlay ที่วิ่งทับขา WAN อีกที ถอดออกจาก zone แล้วการเชื่อมต่อจัดการ
// ไม่ขาด การล็อกไว้ด้วยจึงไม่ได้ป้องกันอะไรเพิ่มเลย มีแต่ห้ามงานปกติอย่างการย้าย
// tunnel ไป zone อื่น (ผู้ใช้รายงานตรงๆ ว่าล็อกทั้ง WAN และ tunnel)
export function protectedWanInterfaces(zones) {
  return new Set((zones || []).filter((zone) => zone.name === "WAN")
    .flatMap((zone) => zone.interfaces || [])
    .filter((name) => !isTunnelInterfaceName(name)
      && !/^(?:(?:ip|lt|mt)-|(?:st|ip|lt|mt)\d)/i.test(String(name).trim())));
}
