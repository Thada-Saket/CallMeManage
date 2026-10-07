// |====== Interface Status Format ======|

// รวม admin_status/oper_status ให้เหลือแค่ "up"/"down" - เจอว่า Cisco เองมี 2
// ชุด enum คนละคำกันเลยสำหรับคนละ query: get_interface_information ใช้
// ietf-interfaces มาตรฐาน (up/down/testing/...) แต่ get_ip_interface_brief ใช้
// Cisco-IOS-XE-interfaces-oper.yang ของตัวเอง (admin-status: if-state-up/
// if-state-down, oper-status: if-oper-state-ready/if-oper-state-no-pass/...)
// - ไม่มีคำไหนเท่ากับ "up" เป๊ะๆ เลยสักตัว เช็คแค่ === "up" อย่างเดียวเลยพลาด
// ต้องรู้จักทั้ง 2 ชุดคำ (Huawei/Juniper ยังคงส่ง "up" ธรรมดาเหมือนเดิม)

// เปลี่ยนคำแจ้งสถานะ ให้กลายเป็นแค่ up หรือ down
const UP_VALUES = new Set(["up", "if-state-up", "if-oper-state-ready"]);

export function normalizeStatus(value) {
  if (!value) return "down";
  return UP_VALUES.has(value.trim().toLowerCase()) ? "up" : "down";
}
