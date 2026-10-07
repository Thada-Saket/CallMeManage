// |====== Date Format ======|

const THAI_MONTHS = [
  "January", "Febuary", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];

// ไม่ถึง 1 ชม -> "X นาทีที่แล้ว", ถึง 1 ชม (แต่ยังไม่ถึง 1 วัน) -> "X ชั่วโมงที่แล้ว",
// ถึง 1 วันขึ้นไป -> โชว์วันที่จริงไปเลย (วัน เดือน ปี) แทนตัวเลขนับถอยหลัง เพราะ
// นับเป็นวันแล้วดูยากกว่าดูวันที่ตรงๆ - คืน "-" ถ้าไม่มีค่า/parse ไม่ออก ไม่พึ่ง
// || ที่ฝั่งเรียก (เคยพังตอนผลลัพธ์เป็น 0 เพราะ 0 เป็น falsy ใน JS)
export function formatDate(timestamp) {
  if (!timestamp) return "-";
  const parsed = Date.parse(timestamp);
  if (Number.isNaN(parsed)) return "-";

  const diffMs = Math.max(0, Date.now() - parsed);
  const diffMinutes = Math.floor(diffMs / (60 * 1000));
  const diffHours = Math.floor(diffMs / (60 * 60 * 1000));
  const diffDays = Math.floor(diffMs / (24 * 60 * 60 * 1000));

  if (diffHours < 1) {
    return diffMinutes < 1 ? "current" : diffMinutes === 1 ? `${diffMinutes} minute ago` : `${diffMinutes} minutes ago`;
  }
  if (diffDays < 1) {
    return diffHours === 1 ? `${diffHours} hour ago` : `${diffHours} hours ago`;
  }
  const date = new Date(parsed);
  return `${date.getDate()} ${THAI_MONTHS[date.getMonth()]} ${date.getFullYear()}`;
}
