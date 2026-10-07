import { request, setToken, clearToken } from "./api_client";

// |====== CRUD Auth API ======|

// ใช้ในการ login ของ user เรียกใช้ใน AuthContext.jsx
// turnstileToken ใช้ได้ครั้งเดียวต่อการ login หนึ่งครั้ง (server ตรวจกับ Cloudflare action=login)
export async function login(username, password, turnstileToken) {
  const form = new URLSearchParams();
  form.set("username", username);
  form.set("password", password);

  const data = await request("/auth/login", {
    method: "POST",
    body: form,
    form: true,
    auth: false,
    // no token when Cloudflare is switched off on the server (TURNSTILE_ENABLED=no)
    headers: turnstileToken ? { "X-Turnstile-Token": turnstileToken } : {},
  });
  setToken(data.access_token);
  return data;
}

// CM-12: เปิดสมัครอยู่ไหม (UX เท่านั้น - backend ปฏิเสธ signup เองเมื่อปิด) ไม่เก็บค่านี้ไว้ที่ไหน
export async function getRegistrationStatus() {
  const data = await request("/auth/registration-status", { auth: false });
  // googleEnabled: false when the server has no Google OAuth settings (button is hidden)
  return { enabled: data?.enabled === true, googleEnabled: data?.google_enabled === true };
}

export async function startEmailRegistration(email) {
  return request("/auth/register/email/start", {
    method: "POST",
    body: { email },
    auth: false,
  });
}

export async function verifyEmailRegistration(challengeId, otp) {
  return request("/auth/register/email/verify", {
    method: "POST",
    body: { challenge_id: challengeId, otp },
    auth: false,
  });
}

// ส่งรหัสใหม่ไปอีเมลเดิมของ challenge (server ไม่รับอีเมลจาก request นี้)
export async function resendEmailRegistration(challengeId) {
  return request("/auth/register/email/resend", {
    method: "POST",
    body: { challenge_id: challengeId },
    auth: false,
  });
}

// ยกเลิกการสมัครที่ค้างอยู่ ส่งซ้ำได้ไม่ error (server ตอบ 204)
export async function cancelRegistration({ challengeId, registrationToken }) {
  const body = {};
  if (challengeId) body.challenge_id = challengeId;
  if (registrationToken) body.registration_token = registrationToken;
  return request("/auth/register/cancel", {
    method: "POST",
    body,
    auth: false,
  });
}

// |====== Password reset by email code ======|
export async function startPasswordReset(email) {
  return request("/auth/password-reset/start", { method: "POST", body: { email }, auth: false });
}

export async function resendPasswordReset(challengeId) {
  return request("/auth/password-reset/resend", { method: "POST", body: { challenge_id: challengeId }, auth: false });
}

export async function verifyPasswordReset(challengeId, otp) {
  return request("/auth/password-reset/verify", { method: "POST", body: { challenge_id: challengeId, otp }, auth: false });
}

export async function completePasswordReset(resetToken, newPassword) {
  return request("/auth/password-reset/complete", {
    method: "POST",
    body: { reset_token: resetToken, new_password: newPassword },
    auth: false,
  });
}

// ส่งซ้ำได้ไม่ error (server ตอบ 204)
export async function cancelPasswordReset({ challengeId, resetToken }) {
  const body = {};
  if (challengeId) body.challenge_id = challengeId;
  if (resetToken) body.reset_token = resetToken;
  return request("/auth/password-reset/cancel", { method: "POST", body, auth: false });
}

export async function startGoogleOAuthRegistration() {
  return request("/auth/register/google/start", {
    method: "POST",
    // Google returns the user to this same address when it is one of the server's SITE_URL
    // addresses (the server checks it; any other value means the main address)
    body: { site_url: window.location.origin },
    auth: false,
  });
}

export async function completeGoogleOAuthRegistration(resultCode) {
  return request("/auth/register/google/complete", {
    method: "POST",
    body: { result_code: resultCode },
    auth: false,
  });
}

export async function register(username, password, registrationToken) {
  const data = await request("/auth/register", {
    method: "POST",
    body: {
      usr_name: username,
      usr_passwd: password,
      registration_token: registrationToken,
    },
    auth: false,
  });
  setToken(data.access_token);
  return data;
}

export async function logout() {
  // เพิกถอน token ฝั่ง server ผ่าน Redis denylist (POST /auth/logout) ก่อนเสมอ
  // แล้วค่อย clearToken() - เดิมยิงแบบ fire-and-forget แล้ว clearToken() ทันที
  // แบบ synchronous เป็น race condition จริง: ถ้า request() ยังไม่ทันส่ง header
  // Authorization ออกไป (หรือ route เปลี่ยนหน้าไปก่อน fetch เสร็จ) backend จะไม่ได้
  // jti ไปเพิกถอนใน Redis denylist เลย ต้อง await ให้ request จบให้แน่ใจก่อน -
  // ห่อ try/finally ให้ clearToken() ถูกเรียกเสมอไม่ว่า API จะสำเร็จ ล้มเหลว หรือ
  // offline (ผู้ใช้ต้อง logout ได้ฝั่ง client เสมอ ไม่ขึ้นกับผลของ API)
  try {
    await request("/auth/logout", { method: "POST" });
  } catch {
    /* best-effort - เช่น offline หรือ token หมดอายุไปแล้วก่อนกด logout */
  } finally {
    clearToken();
  }
}
