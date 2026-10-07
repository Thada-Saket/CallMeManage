// |====== คัดลอกข้อความลงคลิปบอร์ด ======|

// เจอบั๊กจริง (ผู้ใช้รายงาน): ปุ่มคัดลอกในหน้า CLI Generator ขึ้น "Failed to copy"
// ทุกครั้ง ต้นเหตุคือ `navigator.clipboard` มีให้ใช้เฉพาะใน **secure context**
// เท่านั้น (HTTPS หรือ localhost) - ระบบนี้เสิร์ฟผ่าน HTTP ธรรมดาและผู้ใช้เปิดด้วย
// IP ของเครื่อง ไม่ใช่ localhost `navigator.clipboard` จึงเป็น undefined แล้ว
// `.writeText(...)` โยน TypeError เข้า catch ที่แสดงข้อความนั้นทันที
//
// ทางแก้ที่ไม่ต้องรอ HTTPS: ถ้าไม่มี Clipboard API ให้ใช้ textarea ชั่วคราวคู่กับ
// document.execCommand("copy") ซึ่งทำงานได้บน origin ที่ไม่ปลอดภัย (deprecated
// แต่เบราว์เซอร์ทุกตัวยังรองรับ และเป็นทางเดียวที่ใช้ได้บน HTTP)
//
// คืน true/false ไม่โยน error - ผู้เรียกตัดสินใจเองว่าจะแสดงอะไร
export async function copyText(text) {
  const value = String(text ?? "");
  if (!value) return false;

  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      // ถึงจะมี API อยู่ก็ยังถูกปฏิเสธได้ (ผู้ใช้ไม่ให้สิทธิ์/หน้าไม่ได้ focus)
      // จึงไม่ return ทันที ปล่อยให้ตกไปใช้ทางสำรองด้านล่าง
    }
  }

  try {
    const area = document.createElement("textarea");
    area.value = value;
    // ต้องอยู่ใน DOM จริงถึงจะ select ได้ แต่ห้ามให้ผู้ใช้เห็นหรือทำให้หน้าเลื่อน
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.top = "0";
    area.style.left = "0";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    area.setSelectionRange(0, value.length);
    const copied = document.execCommand("copy");
    document.body.removeChild(area);
    return copied;
  } catch {
    return false;
  }
}
