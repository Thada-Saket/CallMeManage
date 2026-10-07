// |====== System Management > User Management - ตรรกะบริสุทธิ์ที่ทดสอบได้ ======|
// กฎต้องตรงกับ tools/local_user_policy.py (backend ตรวจซ้ำเสมอ) ; รหัสผ่านใช้กฎชุดเดียวกับ
// CLI Generator (utils/localAdmin.js) ไม่ประกาศ regex ใหม่ ; ข้อความ error ไม่ใส่รหัสผ่านที่กรอก
// รหัสผ่านอยู่ใน React state ของฟอร์มเท่านั้น - ไม่เก็บ storage/cookie/URL/log
import { isPasswordValid, passwordChecks } from "./localAdmin.js";

export { isPasswordValid, passwordChecks };

export const USERNAME_HINT =
  "Use 6-32 characters. Start with a letter or number. Only letters, numbers, period (.), underscore (_), and hyphen (-) are allowed.";

// บัญชีจัดการ NETCONF - backend กรองออกแล้ว กรองซ้ำที่นี่กันหลุดถ้า backend เปลี่ยน
export const RESERVED_USERNAME = "Netconf-MGMT";

const USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{5,31}$/;

export const PRIVILEGE_OPTIONS = [
  { value: "monitor", label: "Monitor Only" },
  { value: "admin", label: "Network Admin" },
];

// ค่ากลาง -> ค่าที่ translator ของแต่ละยี่ห้อรับ (ตรงกับ VENDOR_PRIVILEGES ฝั่ง backend)
const VENDOR_PRIVILEGES = {
  cisco: { monitor: 1, admin: 15 },
  juniper: { monitor: "operator", admin: "super-user" },
  huawei: { monitor: 0, admin: 3 },
};

export const SUPPORTED_VENDORS = Object.keys(VENDOR_PRIVILEGES);

export function toVendorPrivilege(vendor, privilege) {
  const value = VENDOR_PRIVILEGES[vendor]?.[privilege];
  if (value === undefined) throw new Error("Unsupported privilege for this device");
  return value;
}

// privilege เป็น null = ระดับ Brownfield ที่หน้านี้ไม่ได้จัดการ (backend ไม่เดาให้)
export function privilegeLabel(privilege) {
  return PRIVILEGE_OPTIONS.find((option) => option.value === privilege)?.label || "Unrecognized privilege";
}

export function isReservedUsername(name) {
  return typeof name === "string" && name.trim().toLowerCase() === RESERVED_USERNAME.toLowerCase();
}

// อ่านเฉพาะ {username, privilege} จากผลที่ backend normalize แล้ว ; คืน null ถ้ารูปร่างไม่ตรง
export function parseLocalUsers(result) {
  if (!result || !Array.isArray(result.users)) return null;
  return result.users
    .filter((user) => user && typeof user.username === "string" && user.username && !isReservedUsername(user.username))
    .map((user) => ({
      username: user.username,
      privilege: user.privilege === "monitor" || user.privilege === "admin" ? user.privilege : null,
    }));
}

export function validateNewUsername(username, existingUsers = []) {
  if (!username) return "Enter a username.";
  if (!USERNAME_PATTERN.test(username)) return USERNAME_HINT;
  if (isReservedUsername(username)) return "This username is reserved by the system.";
  const wanted = username.toLowerCase();
  if (existingUsers.some((user) => user.username.toLowerCase() === wanted)) {
    return "This username already exists on the device.";
  }
  return null;
}

export const EMPTY_USER_FORM = { username: "", privilege: "", password: "", confirmPassword: "" };

export function initialUserForm(mode, target) {
  if (mode === "edit" && target) {
    return { ...EMPTY_USER_FORM, username: target.username, privilege: target.privilege || "" };
  }
  return { ...EMPTY_USER_FORM, privilege: "monitor" };
}

// สถานะของฟอร์มทั้งหมดในที่เดียว: error ต่อ field + ปุ่ม Apply กดได้ไหม
export function evaluateUserForm({ mode, target, values, existingUsers = [] }) {
  const errors = {};
  const isEdit = mode === "edit";
  const passwordEntered = values.password !== "" || values.confirmPassword !== "";

  if (!isEdit) {
    const usernameError = validateNewUsername(values.username, existingUsers);
    if (usernameError) errors.username = usernameError;
  }

  if (!isEdit && !values.privilege) errors.privilege = "Select a privilege.";
  if (values.privilege && !PRIVILEGE_OPTIONS.some((option) => option.value === values.privilege)) {
    errors.privilege = "Select a privilege.";
  }

  if (!isEdit || passwordEntered) {
    if (!values.password) errors.password = "Enter a password.";
    else if (!isPasswordValid(values.password)) errors.password = "Password does not meet all requirements.";
    if (!values.confirmPassword) errors.confirmPassword = "Confirm the password.";
    else if (values.confirmPassword !== values.password) errors.confirmPassword = "Passwords do not match.";
  }

  const privilegeChanged = isEdit && Boolean(values.privilege) && values.privilege !== (target?.privilege || "");
  const hasChange = !isEdit || privilegeChanged || passwordEntered;
  return { errors, hasChange, canSubmit: hasChange && Object.keys(errors).length === 0 };
}

// สร้าง {command, parameters} ที่จะส่งจริง - ส่งเฉพาะค่าที่เปลี่ยน ไม่มี confirmPassword/undefined/label
export function buildUserCommand({ mode, vendor, target, values }) {
  if (mode === "create") {
    return {
      command: "set_new_local_user",
      parameters: {
        username: values.username,
        privilege: toVendorPrivilege(vendor, values.privilege),
        passwd: values.password,
      },
    };
  }
  if (mode === "edit") {
    const parameters = { username: target.username };
    if (values.privilege && values.privilege !== (target.privilege || "")) {
      parameters.privilege = toVendorPrivilege(vendor, values.privilege);
    }
    if (values.password) parameters.passwd = values.password;
    return { command: "edit_local_user", parameters };
  }
  return { command: "delete_local_user", parameters: { username: target.username } };
}
