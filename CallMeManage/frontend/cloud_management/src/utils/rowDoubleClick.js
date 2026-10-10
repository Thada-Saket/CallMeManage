// |====== Double-click แถวในตาราง config เพื่อเปิดหน้าแก้ไข ======|

// ทุกตารางที่เลือกแถวได้ (row-clickable) คลิกแถวแบบ toggle: คลิกซ้ำแถวเดิม = ยกเลิก
// การเลือก - double-click คือคลิก 2 ครั้งติดกัน ถ้าปล่อย toggle ตามเดิม คลิกที่ 2 จะ
// ยกเลิกการเลือกก่อนถึง dblclick แล้วปุ่ม Edit (ที่ผูกกับแถวที่เลือก) ก็ใช้ไม่ได้
//
// ใช้คู่กัน 2 ตัว:
// - rowClickSelection: ค่าที่จะตั้งเป็น "แถวที่เลือก" ตอน onClick - คลิกที่ 2 ขึ้นไป
//   ของการคลิกติดกัน (event.detail > 1) เลือกแถวนี้ค้างไว้เสมอ ไม่ toggle ออก
// - rowDoubleClick: handler ของ onDoubleClick - เรียก handler เดียวกับปุ่ม Edit
//   ภายใต้เงื่อนไข canEdit เดียวกับปุ่ม (แถวที่ปุ่ม Edit กดไม่ได้ double-click ก็ไม่เปิด)
//   React อ่าน props ล่าสุดตอน dispatch event จึงเห็นแถวที่คลิกที่ 2 เพิ่งเลือกแล้ว

export function rowClickSelection(event, rowKey, selectedKey) {
  if (event?.detail > 1) return rowKey;
  return rowKey === selectedKey ? null : rowKey;
}

export function rowDoubleClick(canOpen, open) {
  return () => {
    if (!canOpen) return;
    // double-click เลือกคำในเซลล์ไว้ด้วย (พฤติกรรม browser) - ล้างทิ้งก่อนเปิดฟอร์ม
    window.getSelection?.()?.removeAllRanges();
    open();
  };
}
