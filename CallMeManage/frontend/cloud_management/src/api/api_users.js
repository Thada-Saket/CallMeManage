import { request } from "./api_client";

// |====== CRUD User API ======|

// โหลดข้อมูลบัญชีตัวเอง (username/email/role/วันที่สร้าง) เรียกใช้ใน AccountSettings.jsx
export function getMyProfile() {
  return request("/users/me");
}

// ตรวจสอบว่า email ที่กำลังจะเชิญมีบัญชีในระบบจริงไหม เรียกใช้ใน SiteSettingsModal.jsx
// ค้นแบบ "ตรงเป๊ะ" คืน array ที่มีสมาชิก 0 หรือ 1 ตัวเสมอ (คืนแค่ usr_id/usr_name ไม่มี email
// - ดู UserSearchResult ฝั่ง backend) เดิมเป็น /users/search ที่ค้นแบบ substring ซึ่งส่ง ""
// หรือ "@gmail.com" เข้าไปกวาดรายชื่อผู้ใช้ทั้งระบบได้ จึงเปลี่ยนมาเป็น lookup ด้วย email เต็ม
export function lookupUserByEmail(email) {
  return request(`/users/lookup?email=${encodeURIComponent(email)}`);
}

// แสดงรายการคำเชิญเข้าร่วม site ที่ยังไม่ได้ตอบรับ เรียกใช้ใน Site.jsx
export function getMyInvitations() {
  return request("/users/me/invitations");
}

// ตอบรับคำเชิญเข้าร่วม site เรียกใช้ใน Site.jsx
export function acceptInvitation(siteId) {
  return request(`/users/me/invitations/${siteId}/accept`, { method: "PATCH" });
}

// ใช้ปฏิเสธตอบรับคำเชิญเข้าร่วม site เรียกใช้ใน Site.jsx
export function rejectInvitation(siteId) {
  return request(`/users/me/invitations/${siteId}/reject`, { method: "PATCH" });
}

// ปุ่ม "ลบบัญชี" ใน AccountSettings.jsx - backend คืน 400 พร้อมข้อความอธิบาย เรียกใช้ใน AccountSettings.jsx
// ถ้ายังเป็นเจ้าของสาขาอยู่ (ApiError.detail อ่านได้ตรงๆ ที่ผู้เรียก) 
export function deleteMyAccount() {
  return request("/users/me", { method: "DELETE" });
}
