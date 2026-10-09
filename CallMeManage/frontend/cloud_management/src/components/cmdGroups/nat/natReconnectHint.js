// Cisco ตัดการเชื่อมต่อ NETCONF ชั่วครู่ทุกครั้งที่แก้ NAT - backend รอให้อุปกรณ์ call-home
// กลับมาก่อนตอบ (ดู CISCO_NAT_RECONNECT_WAIT_SECONDS ใน device_router.py) ปุ่มจึงหมุนนาน
// 30-60 วิ ข้อความนี้บอกว่านานเป็นเรื่องปกติ ผู้ใช้จะได้ไม่กดซ้ำหรือปิดหน้าต่าง
export const NAT_RECONNECT_HINT =
  "Applying NAT. The device reconnects briefly after a NAT change, so this can take up to a minute.";
