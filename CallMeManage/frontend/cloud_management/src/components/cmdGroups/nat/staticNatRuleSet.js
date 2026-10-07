// เจอบั๊กจริง (2026-07-30): Junos's security/nat/static/rule-set ถูก scope
// ด้วย "context" (from-zone ในที่นี้) - อุปกรณ์ปฏิเสธถ้ามี 2 rule-set คนละชื่อ
// แต่ context เดียวกัน (ยืนยันจริง: "rule-set X and rule-set Y have same
// context") - รวมเป็น 1 rule-set ต่อ 1 from-zone เสมอ (ไม่ใช่ 1 ต่อ 1 entry
// แบบเดิม) แต่ละ entry (static NAT) เป็นแค่ "rule" แยกกันข้างในรุ่นเดียวกัน
// (rule name = "ชื่อ" ที่ user กรอกในฟอร์ม - ยังเป็น identity จริงของแต่ละ
// entry อยู่ แค่ไม่ใช่ identity ของ rule-set อีกต่อไป)
//
// **ต้อง import ใช้ตัวเดียวกันนี้ทุกที่ที่เขียน static NAT** (natStatic.jsx,
// natStaticFormModal.jsx) - ห้าม derive ชื่อ rule-set เองแยกไฟล์ พลาดสะกด/
// รูปแบบต่างกันแค่นิดเดียวจะกลับไปชนกันเหมือนเดิม
//
// รอบ 2 (2026-07-30): เดิม Port Forward ใช้ container เดียวกับ static NAT
// (security/nat/static ต่างกันแค่มี destination-port) เลยต้องแชร์ฟังก์ชันนี้
// ด้วย - user ชี้ว่าไม่ถูก: Junos มี **security/nat/destination** แยกต่างหาก
// สำหรับ port-forward โดยเฉพาะ (pool-based) ย้าย Port Forward ไปใช้ container
// นั้นแล้ว (ดู destinationNatRuleSet() ด้านล่าง) **ไม่แชร์ rule-set กับ static
// NAT อีกต่อไป** - แต่ security/nat/destination/rule-set ก็มี "same context"
// constraint เดียวกันเป๊ะ (ยืนยันจาก commit check บนอุปกรณ์จริง) เลยยังต้องรวม
// เป็น 1 rule-set ต่อ 1 from-zone เหมือนกัน แค่เป็นคนละ namespace จาก static
// NAT โดยสิ้นเชิง
export function staticNatRuleSet(fromZone) {
  return `STATIC-${fromZone}`;
}

// Brownfield Junos may already use any rule-set name for a from-zone. Reuse
// that real identity instead of creating STATIC-<zone>, which would be rejected
// by Junos because two static NAT rule-sets cannot share the same context.
export function resolveStaticNatRuleSet(rows, fromZone, currentRuleSet = "") {
  if (currentRuleSet) return currentRuleSet;
  const existing = (rows || []).find(
    (row) => row?.fromZone === fromZone && row?.ruleSet,
  );
  return existing?.ruleSet || staticNatRuleSet(fromZone);
}

// ใช้กับ Port Forward เท่านั้น (pf.jsx, pfFormModal.jsx) - security/nat/
// destination/rule-set คนละ namespace จาก staticNatRuleSet() ข้างบนโดยสิ้นเชิง
// (คนละ container ใน Junos เลย) ห้ามใช้ปนกัน
export function destinationNatRuleSet(fromZone) {
  return `DNAT-${fromZone}`;
}

// Brownfield Junos อาจมี rule-set ชื่ออะไรก็ได้อยู่ก่อนระบบเข้ามาจัดการ และ Junos
// อนุญาต context (from-zone) เดียวกันได้เพียง rule-set เดียว จึงต้องใช้ชื่อจริงที่
// อ่านจากอุปกรณ์ต่อ ห้ามสร้าง DNAT-<zone> ซ้อนขึ้นมาเอง ส่วน Edit ให้คง rule-set
// ของแถวเดิมไว้ตราบใดที่ from-zone ยังไม่เปลี่ยน
export function resolveDestinationNatRuleSet(rows, fromZone, currentRuleSet = "") {
  if (currentRuleSet) return currentRuleSet;
  const existing = (rows || []).find(
    (row) => row?.fromZone === fromZone && row?.ruleSet,
  );
  return existing?.ruleSet || destinationNatRuleSet(fromZone);
}

// เจอบั๊กจริง (2026-07-30 รอบ 4 - user ชี้): rule-set ที่เหลือว่างเปล่าหลังลบ
// rule สุดท้ายออก **ไม่ได้แค่ "รก" อย่างที่เข้าใจผิดไว้** - มันยังจอง context
// (from-zone) ไว้ถาวร กันไม่ให้สร้าง rule-set ชื่ออื่นที่ zone เดียวกันได้อีกเลย
// (ยืนยันจริง: user ลบ entry สุดท้ายใน "WEB-1" จนว่าง แล้วสร้าง static NAT ใหม่
// ("STATIC-WAN") ที่ zone WAN เดียวกันไม่ได้ อุปกรณ์ปฏิเสธ "same context" ทั้งที่
// WEB-1 ไม่มี rule เหลือแล้ว) - ต้องเช็คก่อนลบว่า rule ที่จะลบเป็นตัวสุดท้ายใน
// rule-set นั้นหรือไม่ (จากตารางที่โหลดมาแล้ว - rows ทั้งหมดของหน้านั้น) ถ้าใช่
// ต้องลบทั้ง rule-set (remove_static_nat_ruleset/remove_port_forward_ruleset)
// แทนลบแค่ rule เดียว (remove_static_nat/remove_port_forward) เพื่อคืน context
// ให้ zone นั้นใช้สร้าง rule-set ใหม่ต่อได้จริง
export function isLastRuleInSet(rows, target) {
  // Parser บางหน้ากรอง rule คนละชนิดออกจากตาราง แต่ส่งจำนวน rule จริงทั้งหมดมา
  // ด้วย ห้ามดูแค่ visible rows แล้วลบ rule-set ที่ยังมี hidden rule อยู่
  if (Number.isInteger(target?.ruleSetRuleCount)) return target.ruleSetRuleCount <= 1;
  return !rows.some((row) => row !== target && row.ruleSet === target.ruleSet);
}
