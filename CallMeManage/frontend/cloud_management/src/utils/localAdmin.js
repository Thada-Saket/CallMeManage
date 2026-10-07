// |====== Local Administrator (Existing Device เท่านั้น) - ตรรกะบริสุทธิ์ที่ทดสอบได้ ======|
// กฎต้องตรงกับ tools/local_admin_policy.py ฝั่ง backend (backend ตรวจซ้ำเสมอ) ; ข้อความ error ไม่ใส่ค่าที่ผู้ใช้กรอก
// ค่าลับอยู่ใน React state ของหน้าเดียว - ไม่เก็บ storage/cookie/URL/log

export const LOCAL_ADMIN_RESET = { addLocalAdmin: false, localAdminUser: "", localAdminPass: "" };

const USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
const PASSWORD_MAX = 25;
const PASSWORD_FORBIDDEN = /[^\x21-\x7E]|[?"'\\`]/;
const USERNAME_MIN = 6;

export const PASSWORD_RULES = [
  { label: "At least 8 characters long", test: (v) => v.length >= 8 },
  { label: "Contains lowercase letter (a-z)", test: (v) => /[a-z]/.test(v) },
  { label: "Contains uppercase letter (A-Z)", test: (v) => /[A-Z]/.test(v) },
  { label: "Contains number (0-9)", test: (v) => /[0-9]/.test(v) },
  { label: "Contains special character (!@#$%^&* etc.)", test: (v) => /[^A-Za-z0-9]/.test(v) },
];

export function passwordChecks(password) {
  return PASSWORD_RULES.map((rule) => ({ label: rule.label, passed: rule.test(password) }));
}

export function isPasswordValid(password) {
  return passwordChecks(password).every((check) => check.passed)
    && password.length <= PASSWORD_MAX
    && !PASSWORD_FORBIDDEN.test(password);
}

// คืนข้อความ error หรือ null ; เรียกเมื่อเปิด toggle เท่านั้น
export function validateLocalAdmin({ username, password, reservedUsername }) {
  const name = (username || "").trim();
  if (!name) return "Enter the Local Administrator Username.";
  if (!USERNAME_PATTERN.test(name)) {
    return "Local Administrator Username may only contain letters, digits, '.', '_' and '-' (up to 32 characters).";
  }
  if (name.length < USERNAME_MIN) {
    return "Local Administrator Username must be at least 6 characters long.";
  }
  if (reservedUsername && name.toLowerCase() === reservedUsername.toLowerCase()) {
    return "Local Administrator Username is reserved by the system.";
  }
  if (!isPasswordValid(password || "")) return "Local Administrator Password does not meet the requirements.";
  return null;
}

// เพิ่ม field ลง payload เฉพาะเมื่อเปิด toggle ใน Existing Device: flag + username + password (ไม่มี confirm)
export function applyLocalAdminPayload(payload, { enabled, username, password }) {
  if (!enabled) return payload;
  payload.add_local_administrator = true;
  payload.local_admin_username = username.trim();
  payload.local_admin_password = password;
  return payload;
}

// ค่าที่ต้องล้างเมื่อเปลี่ยน field ที่ทำให้ฟีเจอร์นี้ไม่ใช้ได้ (deviceMode ไม่ใช่ existing)
export function localAdminResetFor(name, value) {
  return name === "deviceMode" && value !== "existing" ? LOCAL_ADMIN_RESET : {};
}
