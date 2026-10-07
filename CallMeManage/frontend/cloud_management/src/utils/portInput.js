// |====== ช่องกรอกหมายเลข port ======|

// ผู้ใช้กำหนดช่วงของช่องกรอกไว้ที่ 0-65535 (ขนาดของ uint16 เต็มช่วง) - ตัวนี้
// คุมแค่ "พิมพ์อะไรลงไปได้บ้าง" เท่านั้น ไม่ใช่กฎว่า port ไหนใช้งานได้จริง
//
// **หมายเหตุ** port 0 พิมพ์ลงไปได้ตามที่กำหนด แต่ใช้จริงไม่ได้ - ตัวแปลคำสั่ง
// ของทั้ง Cisco และ Juniper บังคับ 1-65535 (`if not 1 <= local_port <= 65535`)
// ด่านตอนกด Apply จึงยังปฏิเสธ 0 อยู่เหมือนเดิม
export const PORT_INPUT_MIN = 0;
export const PORT_INPUT_MAX = 65535;

// ใช้กับ onChange: คืน false = ไม่รับคีย์นั้น (ค่าเดิมในช่องคงอยู่)
export function acceptsPortInput(value) {
  if (typeof value !== "string") return false;
  if (value === "") return true;
  if (!/^[0-9]+$/.test(value)) return false;
  if (value.length > 1 && value[0] === "0") return false; // กันเลขศูนย์นำหน้า
  const port = Number(value);
  return port >= PORT_INPUT_MIN && port <= PORT_INPUT_MAX;
}

export const PORT_PROTOCOLS = ["tcp", "udp"];
export const DEFAULT_PORT_PROTOCOL = "tcp";
