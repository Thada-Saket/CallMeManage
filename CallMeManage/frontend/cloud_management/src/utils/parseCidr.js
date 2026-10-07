import { normalizeSubnet } from "./normalizeSubnet.js";
import { validateIPv4Input } from "./ipv4Input.js";

// |====== User IP input Format ======|

// ยกออกมาจาก InterfacesFormModal.jsx (เดิม local ไม่ export) ให้ FormModal อื่น
// (StaticRouteFormModal.jsx) ใช้ร่วมกันได้ - รับ "ip/prefix" หรือ "ip/subnet mask"
// ในช่องเดียว (normalizeSubnet เดิมรองรับทั้ง prefix length/subnet mask/wildcard
// mask อยู่แล้ว) คืน {ip, prefix} หรือ null ถ้า parse ไม่ผ่าน
// ใช้หั่นและจัดระเบียบ IP Address ถ้าผู้ใช้พิมพ์มั่ว พิมพ์ผิดฟอร์แมต หรือลืมใส่เครื่องหมาย / ฟังก์ชันจะเตะทิ้งและตอบ null

export function parseIpCidr(raw) {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  const slashIndex = trimmed.indexOf("/");
  if (slashIndex === -1) return null;

  const ip = trimmed.slice(0, slashIndex).trim();
  const subnetPart = trimmed.slice(slashIndex + 1).trim();
  if (!ip || !subnetPart) return null;
  if (!validateIPv4Input(ip).valid) return null;

  const subnet = normalizeSubnet(subnetPart);
  if (!subnet) return null;

  return { ip, prefix: subnet.prefix };
}
