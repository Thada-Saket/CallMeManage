import { useEffect, useRef, useState } from "react";

// Non-blocking success toast - trigger จาก window CustomEvent "toast:success"
// (ตาม pattern เดียวกับ "auth:unauthorized" ใน api/client.js - คนละ layer กัน
// แต่ใช้กลไกเดียวกันสื่อสารข้าม React tree โดยไม่ต้องพึ่ง Context) - จุดยิง event
// จริงอยู่ที่ api/devices.js's runDeviceCommand() หลังคำสั่งที่ไม่ใช่ get_* สำเร็จ
// เท่านั้น (นับเป็น "บันทึกการตั้งค่าสำเร็จ" ครอบคลุมทุกฟอร์ม Interface/Routing/
// NAT/Firewall ที่ผ่าน runDeviceCommand ทั้งหมด โดยไม่ต้องแก้ onSaved() ของ list
// component แต่ละไฟล์เลยสักไฟล์ - จุดเดียวครอบคลุมทั้งแอป)
let toastIdCounter = 0;
const TOAST_DURATION_MS = 1000;

export default function ToastContainer() {
  const [toasts, setToasts] = useState([]);
  const timersRef = useRef({});

  useEffect(() => {
    function handleToast(event) {
      const id = ++toastIdCounter;
      const message = event.detail || "✓ Changes applied successfully";
      setToasts((prev) => [...prev, { id, message }]);
      timersRef.current[id] = setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
        delete timersRef.current[id];
      }, TOAST_DURATION_MS);
    }
    window.addEventListener("toast:success", handleToast);
    return () => {
      window.removeEventListener("toast:success", handleToast);
      Object.values(timersRef.current).forEach(clearTimeout);
    };
  }, []);

  if (toasts.length === 0) return null;

  // fixed + pointer-events: none บน container เอง (non-blocking - คลิกทะลุผ่าน
  // ได้เสมอ ไม่ล็อกอะไรเลย) ตัว toast แต่ละอันไม่มีปุ่มปิด/ไม่มี overlay ตามที่ระบุ
  return (
    <div className="toast-container" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} className="toast-item">
          {toast.message}
        </div>
      ))}
    </div>
  );
}
