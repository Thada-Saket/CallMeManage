// กฎ VLAN ID ชุดเดียวของระบบ (VLAN form + Interface form ใช้ร่วมกัน เพื่อไม่ให้สองไฟล์
// ตรวจไม่ตรงกัน) - รับเฉพาะเลขฐานสิบจำนวนเต็ม 1-4094 ไม่มี 0 นำหน้า/เครื่องหมาย/
// ช่องว่าง/ทศนิยม/exponent และห้าม clamp ค่าเกินช่วงเงียบ ๆ
// "all" และ "1-4094" ของ Trunk Allow VLAN เป็นค่าภายในของโหมด All ไม่ใช่ VLAN ID
// เดี่ยว - โหมดนั้นไม่ผ่าน validator นี้
export const VLAN_ID_MIN = 1;
export const VLAN_ID_MAX = 4094;
export const VLAN_ID_ERROR = `VLAN ID must be an integer between ${VLAN_ID_MIN} and ${VLAN_ID_MAX}`;

const CANONICAL = /^[1-9][0-9]{0,3}$/;

function inRange(text) {
  return CANONICAL.test(text) && Number(text) <= VLAN_ID_MAX;
}

// ใช้ตอนพิมพ์/paste: "" ผ่านเป็น draft ชั่วคราว นอกนั้นต้องเป็น VLAN ID ที่ถูกต้องแล้วเท่านั้น
// (ค่าที่ไม่ผ่านต้องไม่เข้า state - ผู้เรียกคงค่าเดิมไว้)
export function acceptsVlanIdDraft(value) {
  return typeof value === "string" && (value === "" || inRange(value));
}

// ใช้ตอน submit - ค่าจาก state/prefill/การเรียก handler ตรง ๆ ต้องผ่านที่นี่ทุกครั้ง
// ไม่ trim: ช่องว่างหรือค่าไม่ canonical (001, +10, 1e3) ถือว่าไม่ถูกต้อง
export function validateVlanId(value, { required = true } = {}) {
  const text = typeof value === "number" && Number.isInteger(value) ? String(value) : value;
  if (text === "" || text === undefined || text === null) {
    return required
      ? { valid: false, value: null, text: "", error: `VLAN ID is required (${VLAN_ID_MIN}-${VLAN_ID_MAX})` }
      : { valid: true, value: null, text: "", error: "" };
  }
  if (typeof text !== "string" || !inRange(text)) {
    return { valid: false, value: null, text: "", error: VLAN_ID_ERROR };
  }
  return { valid: true, value: Number(text), text, error: "" };
}
