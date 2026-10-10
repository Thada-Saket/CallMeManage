// Cisco: เปิด/ปิด NAT ทำให้ call-home session ของ router เองตาย (PAT เปลี่ยน port ของ session
// นั้นกลางทาง) backend จึงปิด session เดิมเองแล้วรอให้อุปกรณ์ call-home กลับมาก่อนตอบ (ดู
// CISCO_NAT_SESSION_RESET_COMMANDS ใน device_router.py) ปุ่มจึงหมุนนานกว่าคำสั่งอื่น - ปกติไม่กี่
// วินาที นานสุดราวหนึ่งนาที ข้อความนี้บอกว่าเป็นเรื่องปกติ ผู้ใช้จะได้ไม่กดซ้ำหรือปิดหน้าต่าง
export const NAT_RECONNECT_HINT =
  "Applying NAT - the device is reconnecting its management session. This usually takes a few seconds (up to a minute).";
