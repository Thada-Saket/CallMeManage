// Cisco: เปิด/ปิด NAT ทำให้ call-home session ของ router เองตาย (PAT เปลี่ยน port ของ session
// นั้นกลางทาง) backend จึงปิด session เดิมเองแล้วรอให้อุปกรณ์ call-home กลับมาก่อนตอบ (ดู
// CISCO_NAT_SESSION_RESET_COMMANDS ใน device_router.py) ปุ่มจึงหมุนนานกว่าคำสั่งอื่น
//
// ผู้ใช้เจอจริงว่า "การเชื่อมต่อหลุดทันที" ตอนกดทำให้ตกใจว่าอุปกรณ์ล่ม/คำสั่งพัง และบางครั้ง
// กดซ้ำหรือปิดหน้าต่าง ข้อความชุดนี้จึงเน้นย้ำว่า **เป็นเรื่องปกติของการเปลี่ยน NAT และอุปกรณ์
// จะต่อกลับเอง** ไม่ใช่การเชื่อมต่อหลุดถาวร

// แสดงระหว่างปุ่มกำลังหมุน (หลังกดยืนยันแล้ว)
export const NAT_RECONNECT_HINT =
  "Applying NAT… the device briefly drops and re-establishes its management connection automatically. " +
  "This is expected for a NAT change — please wait (usually a few seconds, up to about a minute) and don't close this page or press the button again.";

// หัวข้อ/เนื้อหากล่องยืนยัน "ก่อน" ลงมือ เพื่อให้ผู้ใช้รู้ล่วงหน้าว่าจะเห็นอุปกรณ์หลุดชั่วคราว
export const NAT_RESET_TITLE = "This will briefly reset the device connection";
export const NAT_RESET_WARNING =
  "Changing NAT resets this device's management connection. The device will show as offline for a moment, " +
  "then reconnect on its own (usually a few seconds, up to about a minute). " +
  "This is normal for a NAT change and does not mean the device went down — just wait for it to come back online. " +
  "If it hasn't returned after a minute, refresh to check its status.";
