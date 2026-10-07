// |====== Connect To Backend & Token Management ======|

// เส้นทาง api อยู่ใต้ ROOT_PATH ของเว็บเสมอ (/api หรือ /cmm/api) ซึ่ง Vite ฝังมาตอน build
// vite preview / vite dev ส่งต่อ <ROOT_PATH>api/... ไปที่ backend (ดู vite.config.js)
// same-origin: หน้าเว็บ HTTPS จึงเรียก API ผ่าน HTTPS เสมอ
import { appUrl } from "../utils/appBase";

const API_BASE = appUrl("api");

// สร้างตัวแปรเก็บว่า token ที่จะใช้งานบน frontend คือ access_token
const TOKEN_KEY = "access_token";
const SITE_ACCESS_TOKEN_KEY = "site_access_token";

// ใช้สำหรับการดึง access_token ออกมาจาก localStorage ของผู้ใช้เพื่อตรวจสอบ
export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

// ใช้สำหรับตั้ง access_token ให้กับ user
export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

// ใช้สำหรับลบล้าง token ของผู้ใช้ ให้ไม่สามารถใช้งานได้ เมื่อ logout หรือเกิดข้อผิดพลาด
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export function getSiteAccessToken() {
  return sessionStorage.getItem(SITE_ACCESS_TOKEN_KEY);
}

export function setSiteAccessToken(token) {
  sessionStorage.setItem(SITE_ACCESS_TOKEN_KEY, token);
}

export function clearSiteAccessToken() {
  sessionStorage.removeItem(SITE_ACCESS_TOKEN_KEY);
}

// class สำหรับส่งออกค่า error เมื่อมีการเรียกใช้งาน api ที่ผิดพลาด
class ApiError extends Error {
  constructor(status, detail) {
    super(detail || `Request failed with status ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

// *** Function หลักสำหรับการ fetch ข้อมูลไปยัง backend
async function request(path, { method = "GET", body, form = false, auth = true, headers: extraHeaders = {} } = {}) {
  // ตรวจว่าเป็น user ที่ authenticate ไหม ถ้าไม่ก็จะทิ้ง header ว่างเปล่า ใช้สำหรับ public api เช่นหน้า register/login
  const headers = { ...extraHeaders };
  const siteAccessToken = getSiteAccessToken();
  if (siteAccessToken) headers["X-Site-Access-Token"] = siteAccessToken;
  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  // ใช้แยกประเภทการห่อข้อมูลส่งไปยัง backend โดยถ้าข้อมูลที่ส่งมาเป็นข้อมูล text ธรรมดาจะเข้าเงื่อนไข เพราะค่า form = false แต่ถ้าเป็นจำพวกไฟล์ค่า form = true แล้วไปใช้ multipart/form-data แทน
  let payload = body;
  if (body && !form) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  // ยิง api ไปหลังบ้าน
  const response = await fetch(`${API_BASE}${path}`, { method, headers, body: payload });

  // กรณี error 401 no authorized จะล้าง token
  if (response.status === 401) {
    clearToken();
    window.dispatchEvent(new Event("auth:unauthorized"));
  }

  if (response.status === 403) {
    let requiresSiteAccess = false;
    try {
      const clone = response.clone();
      const data = await clone.json();
      requiresSiteAccess = data.detail === "Site access verification required";
    } catch {
      /* non-JSON 403 belongs to the requested feature, not the site gate */
    }
    if (requiresSiteAccess) {
      clearSiteAccessToken();
      window.dispatchEvent(new Event("site-access:required"));
    }
  }

  // ถ้าไม่มีการ response จะส่งออก error โดยใช้ class ApiError
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const data = await response.json();
      if (data.detail) {
        detail = data.detail;
      } else if (Array.isArray(data.validation_issues) && data.validation_issues.length > 0) {
        // หากไม่มี detail แต่มี validation_issues (เช่น HTTP 422 จาก FastAPI) ให้ประกอบข้อความอ่านง่าย
        // รูปแบบ "field1: message1; field2: message2" โดยตัด prefix "body -> " ออก
        const issuesText = data.validation_issues
          .map((issue) => {
            const rawField = issue.field || "";
            const field = rawField.startsWith("body -> ") ? rawField.slice(8) : rawField;
            return field ? `${field}: ${issue.message}` : (issue.message || "");
          })
          .filter(Boolean)
          .join("; ");
        if (issuesText) {
          detail = issuesText;
        }
      }
    } catch {
      /* body ไม่ใช่ JSON ก็ใช้ statusText ต่อไป */
    }
    throw new ApiError(response.status, detail);
  }

  // ถ้าทุกอย่างปกติ จะส่ง response.json ออกไปทำงาน
  if (response.status === 204) return null;
  return response.json();
}

export { request, ApiError };
