// |====== ช่องกรอกชื่อโดเมน ======|

// กฎตาม RFC 1035/1123 - ต้องตรงกับ validate_domain_name ใน
// tools/net_input_policy.py เสมอ (backend ยังเป็นด่านจริง ฝั่งนี้แค่กันไม่ให้
// พิมพ์ของที่ผิดแน่ ๆ ลงไปได้ตั้งแต่แรก)
export const DOMAIN_NAME_MAX_LENGTH = 253;
const LABEL_MAX_LENGTH = 63;

// ใช้กับ onChange: คืน false = ไม่รับคีย์นั้น (ค่าเดิมในช่องคงอยู่)
//
// บังคับเฉพาะสิ่งที่ "ไม่มีทางกลายเป็นค่าที่ถูกต้องได้อีกแล้ว" เท่านั้น - ขีดกลาง
// หรือจุดท้ายสุดยังพิมพ์ต่อได้ เพราะเป็นสถานะระหว่างพิมพ์ปกติ (กำลังจะพิมพ์
// "a-b" หรือ "corp.local") ถ้าบล็อกด้วยจะพิมพ์ชื่อที่ถูกต้องไม่ได้เลย ส่วนค่าที่
// ค้างผิดตอนกด Generate ยังถูกปฏิเสธที่ backend เหมือนเดิม
export function acceptsDomainNameInput(value) {
  if (typeof value !== "string") return false;
  if (value === "") return true;
  if (value.length > DOMAIN_NAME_MAX_LENGTH) return false;
  if (!/^[A-Za-z0-9.-]+$/.test(value)) return false;

  const labels = value.split(".");
  for (const [index, label] of labels.entries()) {
    if (label.length > LABEL_MAX_LENGTH) return false;
    // label ว่างยอมได้เฉพาะตัวสุดท้าย (เพิ่งพิมพ์จุดคั่น ยังไม่ได้พิมพ์ชั้นถัดไป)
    if (label === "") {
      if (index !== labels.length - 1) return false;
      continue;
    }
    if (label.startsWith("-")) return false; // ขึ้นต้นด้วยขีดกลางไม่มีวันถูก
  }
  return true;
}
