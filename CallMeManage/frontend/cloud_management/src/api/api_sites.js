import { request } from "./api_client";

// |====== CRUD Site API ======|

// ดึงรายการ site ของผู้ใช้มาแสดงผล ใช้ในไฟล์ Sites.jsx - แบ่งหน้าแยกกัน 2 ชุด
// (สาขาที่เป็นเจ้าของ / สาขาที่เข้าร่วม) กดเปลี่ยนหน้าชุดหนึ่งไม่กระทบอีกชุด
// คืนกลับเป็น { owned_sites: {items, has_next}, joined_sites: {items, has_next} }
export function listMySites(ownedPage = 0, joinedPage = 0) {
  const params = new URLSearchParams({
    owned_page: String(ownedPage),
    joined_page: String(joinedPage),
  });
  return request(`/sites/?${params.toString()}`);
}

// ค้นหาสาขาด้วย Org ID แบบตรงเป๊ะ (ไม่สนตัวพิมพ์เล็ก/ใหญ่) ใช้ใน SearchJoinSiteModal.jsx
// คืนเป็น array ที่มีสมาชิก 0 หรือ 1 ตัวเสมอ - เดิมเป็น /sites/search ที่ค้นแบบ substring
// ซึ่งเปิดให้กวาดรายชื่อสาขาของทุกองค์กรในระบบได้ จึงเปลี่ยนมาเป็น lookup ด้วย Org ID เท่านั้น
export function lookupSiteByOrgId(orgId) {
  return request(`/sites/lookup?org_id=${encodeURIComponent(orgId)}`);
}

// ใช้สำหรับสร้าง site ใหม่ เรียกใช้ใน CreateSiteModal.jsx
export function createSite(siteName) {
  return request("/sites/", {
    method: "POST",
    body: {
      site_name: siteName
    },
  });
}

export function renameSite(siteId, siteName) {
  return request(`/sites/${siteId}`, {
    method: "PATCH",
    body: { site_name: siteName },
  });
}

// ใช้สำหรับขอเข้าร่วม site เรียกใช้ใน SearchJoinSiteModal.jsx
export function joinSite(siteId) {
  return request(`/sites/${siteId}/join`, { method: "POST" });
}

// ใช้ในการแสดงรายชื่อสมาชิกทั้งหมดที่อยู่ใน site นั้น เรียกใช้ใน SiteSettingsModal.jsx
export function listSiteMembers(siteId) {
  return request(`/sites/${siteId}/members`);
}

// เจ้าของ/Admin site เพิ่มสมาชิกโดยระบุด้วย username
export function addSiteMember(siteId, usrName, role = "member") {
  return request(`/sites/${siteId}/members`, {
    method: "POST",
    body: { usr_name: usrName, role },
  });
}

// ใช้อนุมัติคำขอและเลื่อนขั้นเป็น admin เรียกใช้ใน SiteSettingsModal.jsx
export function updateSiteMember(siteId, usrId, { role, status } = {}) {
  return request(`/sites/${siteId}/members/${usrId}`, {
    method: "PATCH",
    body: { role, status },
  });
}

// ใช้ลบผู้ใช้ออกจาก site เรียกใช้ใน SiteSettingsModal.jsx
export function removeSiteMember(siteId, usrId, expectedStatus) {
  const params = new URLSearchParams({ expected_status: expectedStatus });
  return request(`/sites/${siteId}/members/${usrId}?${params.toString()}`, { method: "DELETE" });
}

export function leaveSiteMember(siteId) {
  return request(`/sites/${siteId}/leave`, { method: "DELETE" });
}

// ใช้เชิญสมาชิกเข้าร่วม site ด้วย email-based เรียกใช้ใน SiteSettingsModal.jsx
export function inviteSiteMember(siteId, email) {
  return request(`/sites/${siteId}/invite`, {
    method: "POST",
    body: { email },
  });
}

// Dropdown เปลี่ยนสิทธิ์สมาชิกให้เป็น admin/member เรียกใช้ใน SiteSettingsModal.jsx
export function updateMemberRole(siteId, usrId, role) {
  return request(`/sites/${siteId}/members/${usrId}/role`, {
    method: "PATCH",
    body: { role },
  });
}

// ย้ายสิทธิความเป็นเจ้าของ site ให้สมาชิกที่เลือก เรียกใช้ใน SiteSettingsModal.jsx
export function transferSiteOwnership(siteId, newOwnerUsrId) {
  return request(`/sites/${siteId}/transfer-owner`, {
    method: "PATCH",
    body: { new_owner_usr_id: newOwnerUsrId },
  });
}

// ลบ site  เรียกใช้ใน SiteSettingsModal.jsx
export function deleteSite(siteId) {
  return request(`/sites/${siteId}`, { method: "DELETE" });
}
