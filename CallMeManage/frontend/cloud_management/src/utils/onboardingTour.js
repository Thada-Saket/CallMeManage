// |====== Onboarding Tour (สอนเพิ่มอุปกรณ์ตัวแรก) ======|

// หลัง login หน้า Sites ถามผู้ใช้ว่าอยากดูขั้นตอนไหม (TourPromptModal) ตอบ OK แล้ว tour
// พาไปทีละขั้นข้าม 3 หน้า - Sites -> Devices -> CLI Generator - แต่ละหน้าอ่านว่าตอนนี้
// อยู่ขั้นไหนจาก hook ด้านล่าง แล้วแสดง TourTooltip ชี้ปุ่มของตัวเอง และเลื่อนไปขั้นถัด
// ไปเองเมื่อผู้ใช้ทำสิ่งที่ขั้นนั้นบอกสำเร็จ (เช่นสร้าง site เสร็จ -> ขั้น add-device)
//
// เก็บใน localStorage (คงอยู่ข้ามการเปลี่ยนหน้า/รีเฟรช) แยกตามผู้ใช้ (sub ใน JWT) - เป็น
// แค่ความสะดวกของผู้ใช้คนนั้นในเบราว์เซอร์นั้น ไม่ต้องลง database · ทุกการอ่าน/เขียน
// ครอบ try/catch เพราะ storage อาจถูกปิด (private mode) - tour แค่ไม่ทำงาน หน้าไม่พัง
import { useEffect, useState } from "react";
import { getToken } from "../api/api_client";

export const TOUR_STEPS = ["create-site", "add-device", "fill-form", "generate", "copy", "finish"];

const CHANGE_EVENT = "tour:change";
const PROMPTED_KEY = "onboarding_tour_prompted"; // sessionStorage: ถามแล้วสำหรับ login ครั้งนี้

function userKey() {
  try {
    const part = getToken().split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(part.padEnd(Math.ceil(part.length / 4) * 4, "=")));
    return payload.sub || payload.usr_id || "anonymous";
  } catch {
    return "anonymous";
  }
}

const stepKey = () => `onboarding_tour_step:${userKey()}`;
const dontAskKey = () => `onboarding_tour_dont_ask:${userKey()}`;

function read(storage, key) {
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
}

function write(storage, key, value) {
  try {
    if (value === null) storage.removeItem(key);
    else storage.setItem(key, value);
  } catch {
    // storage ใช้ไม่ได้ - ไม่เป็นไร tour แค่ไม่จำค่า
  }
}

export function getTourStep() {
  const step = read(localStorage, stepKey());
  return TOUR_STEPS.includes(step) ? step : null;
}

export function setTourStep(step) {
  write(localStorage, stepKey(), TOUR_STEPS.includes(step) ? step : null);
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT));
}

// เลื่อนไปขั้นถัดไปเฉพาะเมื่อตอนนี้อยู่ขั้น `from` จริง - หน้าต่าง ๆ เรียกได้เลยหลังทำ
// action สำเร็จโดยไม่ต้องเช็คเองว่า tour เปิดอยู่ไหม (ไม่ได้อยู่ขั้นนั้น = ไม่ทำอะไร)
export function advanceTour(from, to) {
  if (getTourStep() === from) setTourStep(to);
}

export function endTour() {
  setTourStep(null);
}

// ถามครั้งเดียวต่อการ login (token ใหม่) และไม่ถามเลยถ้าติ๊ก "Don't ask me again" ไว้
// หรือกำลังอยู่ระหว่าง tour อยู่แล้ว
export function shouldPromptTour() {
  const token = getToken();
  if (!token) return false;
  if (read(localStorage, dontAskKey()) === "1") return false;
  if (getTourStep()) return false;
  return read(sessionStorage, PROMPTED_KEY) !== token.slice(-32);
}

export function markTourPrompted({ dontAskAgain = false } = {}) {
  const token = getToken();
  if (token) write(sessionStorage, PROMPTED_KEY, token.slice(-32));
  if (dontAskAgain) write(localStorage, dontAskKey(), "1");
}

// ขั้นปัจจุบันของ tour (null = ไม่ได้อยู่ใน tour) - re-render เมื่อหน้าไหนเปลี่ยนขั้น
export function useTourStep() {
  const [step, setStep] = useState(getTourStep);
  useEffect(() => {
    const sync = () => setStep(getTourStep());
    window.addEventListener(CHANGE_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(CHANGE_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);
  return step;
}
