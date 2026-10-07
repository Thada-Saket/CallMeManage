import { useCallback, useEffect, useRef } from "react";

// |====== textarea ที่สูงพอดีเนื้อหาจริง ไม่มีแถบเลื่อนเลย ======|
//
// รอบแรกคำนวณ `rows` จากจำนวนบรรทัดแล้วคิดว่าจบ - ไม่จบ เพราะ `rows` บอกได้แค่
// "กี่บรรทัดตรรกะ" ไม่ได้บอกความสูงจริงที่เบราว์เซอร์ใช้วาด สองอย่างนี้ต่างกันเมื่อ:
//   1. บรรทัดยาวเกินความกว้างกล่อง แล้วถูกตัดขึ้นบรรทัดใหม่ (1 บรรทัดตรรกะ กิน
//      2-3 บรรทัดจริง) - boilerplate ของ Cisco มีบรรทัด ssh-rsa ยาว ~120 ตัวอักษร
//   2. มีแถบเลื่อนแนวนอนโผล่ ซึ่ง "กิน" ความสูงด้านในไปอีกราว 15px ทำให้บรรทัด
//      สุดท้ายตกขอบ แล้วเกิดแถบเลื่อนแนวตั้งตามมาทันที
//
// ทางแก้ที่แน่นอนคือวัดจากของจริง: ปล่อยความสูงเป็น auto แล้วอ่าน scrollHeight
// บวกส่วนที่ไม่ใช่เนื้อหา (ขอบ + แถบเลื่อนแนวนอนถ้ามี) แล้วตั้งกลับเป็นความสูงคงที่
//
// ต้องวัดใหม่เมื่อ "ความกว้างเปลี่ยน" ด้วย ไม่ใช่แค่ตอนเนื้อหาเปลี่ยน เพราะการ
// ตัดบรรทัดขึ้นกับความกว้างของกล่อง
export default function AutoSizeTextarea({ value = "", minRows = 3, ...props }) {
  const ref = useRef(null);

  const resize = useCallback(() => {
    const node = ref.current;
    if (!node) return;
    node.style.height = "auto";
    // offsetHeight - clientHeight = ขอบบน/ล่าง + แถบเลื่อนแนวนอน (ถ้ามี)
    // scrollHeight นับ padding ให้แล้วแต่ไม่นับสองอย่างนั้น
    const extra = node.offsetHeight - node.clientHeight;
    node.style.height = `${node.scrollHeight + extra}px`;
  }, []);

  useEffect(() => {
    resize();
  }, [resize, value, minRows]);

  useEffect(() => {
    const node = ref.current;
    if (!node) return undefined;
    // ResizeObserver จับการเปลี่ยนความกว้างของตัวกล่องเองได้ตรงกว่า window resize
    // (พาเนลยืด/หดจาก layout ได้โดยที่ขนาดหน้าต่างไม่เปลี่ยน) - เผื่อเบราว์เซอร์เก่า
    // ที่ไม่มีให้ fallback ไปฟัง window resize แทน
    if (typeof ResizeObserver === "function") {
      const observer = new ResizeObserver(resize);
      observer.observe(node);
      return () => observer.disconnect();
    }
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, [resize]);

  return <textarea ref={ref} rows={minRows} value={value} {...props} />;
}
