import { createContext, useContext, useState, useCallback, useEffect } from "react";
import { login as loginRequest, logout as logoutRequest, register as registerRequest } from "../api/api_auth";
import { getToken } from "../api/api_client";

const AuthContext = createContext(null);

// ใช้ตรวจสอบว่าผู้ใช้คนนี้ล็อกอินหรือยัง มีสิทธิ์เข้าหน้านี้ไหม เรียกใช้ใน App.jsx
export function AuthProvider({ children }) {
  const [token, setTokenState] = useState(getToken());

  const login = useCallback(async (username, password, turnstileToken) => {
    const data = await loginRequest(username, password, turnstileToken);
    setTokenState(data.access_token);
  }, []);

  // หน้าเว็บที่ 1: โหมด "สมัครสมาชิก" - สมัครสำเร็จแล้ว auto-login ทันที (update
  // token state เหมือน login() เป๊ะ - Component อื่นที่ใช้ isAuthenticated เห็น
  // ผลทันทีไม่ต้องรอ reload)
  const register = useCallback(async (username, password, registrationToken) => {
    const data = await registerRequest(username, password, registrationToken);
    setTokenState(data.access_token);
  }, []);

  const logout = useCallback(async () => {
    try {
      await logoutRequest();
    } finally {
      setTokenState(null);
    }
  }, []);

  // token หมดอายุ/ไม่ถูกต้องระหว่างใช้งาน (401 จาก api ไหนก็ได้) ต้อง sync state
  // ตรงนี้ด้วย ไม่งั้น ProtectedRoute ยังคิดว่า login อยู่ทั้งที่ token ถูกลบไปแล้ว
  useEffect(() => {
    function handleUnauthorized() {
      setTokenState(null);
    }
    window.addEventListener("auth:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("auth:unauthorized", handleUnauthorized);
  }, []);

  const value = { token, isAuthenticated: Boolean(token), login, register, logout };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// สะพานเชื่อมจากองค์ประกอบต่างๆของหน้าเว็บไปยัง function AuthProvider
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within an <AuthProvider>");
  return context;
}
