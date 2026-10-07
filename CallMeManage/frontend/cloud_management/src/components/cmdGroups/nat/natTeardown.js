import { runDeviceCommand } from "../../../api/api_devices";

// หา interface ที่มี "ip nat inside"/"outside" อยู่ตอนนี้ - อ่านจาก
// get_switchport_information (Cisco เท่านั้น) ที่ normalize_switchport_layer
// ฝัง native interface entry ดิบไว้ในฟิลด์ "raw" ต่อแถวอยู่แล้ว (เดิมทำไว้ให้
// InterfacesFormModal.jsx ใช้ pre-fill - ใช้ซ้ำได้เลย ไม่ต้องเพิ่ม query ใหม่)
// ip/nat เป็น presence container เช็คด้วย "in" (key อยู่ = เปิด) ไม่ใช่ค่าข้างใน
export function parseNatInterfaceState(switchportRows) {
  const insideNames = [];
  let outsideName = null;
  for (const row of switchportRows || []) {
    const nat = row?.raw?.ip?.nat;
    if (!nat || typeof nat !== "object") continue;
    if ("inside" in nat) insideNames.push(row.name);
    if ("outside" in nat) outsideName = row.name;
  }
  return { insideNames, outsideName };
}

// (ระลอก C3 / bug 80) รื้อ NAT ทั้งชุดในคำสั่งเดียว
//
// เดิมฟังก์ชันนี้ยิงทีละคำสั่ง: remove_nat + remove_acl + remove_nat_interface ทีละขา
// = 6 RPC ขึ้นไป ผู้ใช้เจอจริงว่าติด rate limit (5 ครั้ง/3 วินาที) ตั้งแต่คำสั่งที่ 6
// ขาที่เหลือจึงไม่ถูกปลด เหลือ "ip nat inside" ค้างบนอุปกรณ์ทั้งที่หน้าเว็บบอกว่าปิด NAT แล้ว
//
// remove_nat_policy ลบ ACL + nat rule (ทั้งสองโหมด) + ปลด nat ออกจากทุกขาในคำสั่งเดียว
// ไม่ต้องรู้ด้วยซ้ำว่าตอนนี้ใช้โหมด interface หรือ pool เพราะ nc:operation="remove"
// ไม่ error ถ้าของไม่มีอยู่
//
// ยังใช้ทั้งตอนปิด toggle "Enable NAT" (nat.jsx) - ตอนนี้เหลือผู้เรียกที่เดียว เพราะ
// natFormModal.jsx เลิกใช้ teardown แล้ว (create_nat_policy ใช้ replace แทนการลบก่อนสร้าง)
export async function teardownCurrentNat(devId, { currentRule, insideNames, outsideName }) {
  const name = currentRule?.name;
  if (!name) return;   // ไม่มี NAT rule อยู่แล้ว ไม่มีอะไรต้องรื้อ

  await runDeviceCommand(devId, "remove_nat_policy", {
    name,
    interfaces: [...(insideNames || []), outsideName].filter(Boolean),
  });
}
