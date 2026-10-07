// |====== OSPF Area ID ======|

// area id เป็นค่า 32 บิตตามมาตรฐาน OSPF (RFC 2328) ช่วงจึงเท่ากันทุกยี่ห้อ
// ไม่ใช่ข้อจำกัดเฉพาะอุปกรณ์ - ระบบนี้กรอกเป็น "เลขล้วน" อย่างเดียวทุกยี่ห้อ
//
// Cisco เขียน <area> เป็นเลขอยู่แล้ว ส่วน Junos รับเลขแล้วแปลงเป็น dotted quad
// ให้เอง (ยืนยันกับอุปกรณ์จริงแล้ว: กรอก 1 ไป อุปกรณ์เก็บเป็น 0.0.0.1) จึงส่ง
// เลขล้วนได้ทั้งสองยี่ห้อโดยไม่ต้องแปลงเองฝั่งเรา
//
// ด่านจริงอยู่ที่ tools/net_input_policy.py's validate_ospf_area ฝั่ง backend
// ตัวนี้มีไว้กันไม่ให้ "พิมพ์" ค่าที่เกินช่วงลงไปได้ตั้งแต่แรกเท่านั้น
export const OSPF_AREA_MAX = 4294967295;

// ใช้กับ onChange ของช่อง Area: คืน false = ไม่รับคีย์นั้น (ค่าเดิมคงอยู่)
export function acceptsOspfAreaInput(value) {
  if (typeof value !== "string") return false;
  if (value === "") return true;
  if (!/^[0-9]+$/.test(value)) return false;
  if (value.length > 1 && value[0] === "0") return false; // กันเลขศูนย์นำหน้า
  return Number(value) <= OSPF_AREA_MAX;
}

// แปลงค่าที่อ่านกลับมาจากอุปกรณ์ให้เป็นเลขสำหรับเติมลงช่อง - Junos คืนเป็น
// dotted quad เสมอ ("0.0.0.3") ส่วน Cisco คืนเป็นเลขอยู่แล้ว คืน "" ถ้าอ่านไม่ออก
export function ospfAreaToNumber(value) {
  const text = String(value ?? "").trim();
  if (text === "") return "";
  if (/^[0-9]+$/.test(text)) return Number(text) <= OSPF_AREA_MAX ? String(Number(text)) : "";
  const octets = text.split(".");
  if (octets.length !== 4) return "";
  if (octets.some((octet) => !/^(0|[1-9][0-9]{0,2})$/.test(octet) || Number(octet) > 255)) return "";
  return String(octets.reduce((total, octet) => total * 256 + Number(octet), 0));
}


// |====== OSPF Process ID (Cisco เท่านั้น) ======|

// ช่วงมาจาก schema จริง ไม่ได้เดา: Cisco-IOS-XE-ospf.yang:3841-3850 กำหนด
// leaf id ของ list process-id เป็น uint16 range "1..65535"
// Junos ไม่มี concept นี้ (instance เดียวต่อ routing-instance) ฟอร์มจึงซ่อนช่องนี้
// ให้ Juniper อยู่แล้ว - ด่านจริงอยู่ที่ validate_ospf_process_id ฝั่ง backend
export const OSPF_PROCESS_ID_MIN = 1;
export const OSPF_PROCESS_ID_MAX = 65535;

export function acceptsOspfProcessIdInput(value) {
  if (typeof value !== "string") return false;
  if (value === "") return true;
  if (!/^[0-9]+$/.test(value)) return false;
  if (value[0] === "0") return false; // 0 ใช้ไม่ได้ และกันเลขศูนย์นำหน้าไปด้วยในตัว
  return Number(value) <= OSPF_PROCESS_ID_MAX;
}
