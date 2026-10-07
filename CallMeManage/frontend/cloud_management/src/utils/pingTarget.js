import { validateIPv4Input } from "./ipv4Input.js";

// hostname/FQDN ทั่วไป - แต่ละ label ต้องขึ้นต้น/ลงท้ายด้วยตัวอักษร-ตัวเลข (ขีดกลาง
// อยู่ตรงกลางได้เท่านั้น) คั่นด้วยจุด - YANG ของ icmp-echo destination เป็น
// `union { string; inet:ip-address }` รองรับ hostname อยู่แล้วจริงๆ (เช็คจาก
// Cisco-IOS-XE-sla.yang) ไม่มี scheme/port/path/ช่องว่าง
export function isValidHostname(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 253) return false;
  const labels = value.split(".");
  if (!labels.every((label) => /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))) return false;
  // ตัวเลขล้วนคั่นจุด (เช่น 256.1.1.1, 1.2.3) คือ IP ที่พิมพ์ผิด ไม่ใช่ hostname -
  // ต้องไปตรวจด้วยโหมด IP Address ห้ามใช้ hostname เป็นทางลัดข้าม IPv4 validator
  return !labels.every((label) => /^[0-9]+$/.test(label));
}

// คืน { ok, value, error } - value เป็นค่า canonical (IP จาก validator / hostname ที่ trim แล้ว)
export function resolvePingTarget(mode, destination) {
  if (mode === "hostname") {
    const hostname = typeof destination === "string" ? destination.trim() : "";
    if (!isValidHostname(hostname)) {
      return { ok: false, value: "", error: "Please enter a valid hostname, e.g. example.com (no http://, spaces, slashes or ports)" };
    }
    return { ok: true, value: hostname, error: "" };
  }
  const checked = validateIPv4Input(destination, { mode: "address", required: true });
  if (!checked.valid) return { ok: false, value: "", error: `Destination IP: ${checked.error}` };
  return { ok: true, value: checked.value, error: "" };
}
