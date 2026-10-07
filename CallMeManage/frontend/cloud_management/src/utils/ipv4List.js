import { validateIPv4Input } from "./ipv4Input.js";

// ตรวจรายการช่อง IPv4 เดี่ยวหลายแถว (NTP/DNS ฯลฯ) ตอน submit ซ้ำจาก IPv4Input
// แถวว่างข้ามได้ (optional) แต่แถวที่กรอกไม่ครบ/ผิดต้องไม่ถูกส่ง และห้ามถูก
// filter(Boolean) ทิ้งเงียบ ๆ - คืนค่า canonical จาก validator เท่านั้น
export function checkIPv4List(values, { label, duplicateMessage }) {
  const result = [];
  for (let index = 0; index < values.length; index += 1) {
    const raw = typeof values[index] === "string" ? values[index].trim() : values[index];
    if (raw === "") continue;
    const checked = validateIPv4Input(raw, { mode: "address", required: true });
    if (!checked.valid) return { ok: false, values: [], error: `${label(index)}: ${checked.error}` };
    result.push(checked.value);
  }
  if (new Set(result).size !== result.length) {
    return { ok: false, values: [], error: duplicateMessage };
  }
  return { ok: true, values: result, error: "" };
}
