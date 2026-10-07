import { useCallback, useEffect, useRef, useState } from "react";
import { runDeviceCommand } from "../api/api_devices";
import { useDeviceCapability } from "./deviceCapability";

// |====== Hook for Fetching Device Information ======|

export const inFlightRequests = new Map();

// (2026-09) err.detail is normally a plain string, but a few Cisco NAT timeouts
// (get_nat_dashboard) now send a structured {code, message} object instead (see
// backend/api/device_router.py's NETCONF_READ_TIMEOUT/NETCONF_WRITE_OUTCOME_UNKNOWN)
// so callers can branch on `code` without parsing English text. Rendering that
// object directly in JSX would throw ("Objects are not valid as a React child") -
// this extraction is backward compatible: a string detail passes through unchanged.
function errorMessage(err, fallback) {
  const detail = err?.detail;
  if (detail && typeof detail === "object") return detail.message || fallback;
  return detail || fallback;
}

// ส่งออก function ใช้ดึงข้อมูลจากตัวอุปกรณ์
export default function useGetDeviceInformation(devId, command, { auto = true, dedupeInFlight = false } = {}) {
  // เรียกใช้ useState ให้เมื่อมีการเปลี่ยนแปลงค่าตัวแปรจะ re-render หน้าเว็บใหม่
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // (dynamic feature ขั้นที่ 5) ข้ามคำสั่งอ่านที่ backend ตัดสินว่าอุปกรณ์นี้ทำไม่ได้ (มีผลเฉพาะตอนเปิดการกรอง)
  // หลายฟอร์มดึงข้อมูลของฟีเจอร์อื่นมาประกอบ เช่นรายชื่อ zone - ไม่ต้องยิงไปให้อุปกรณ์ตอบ error กลับมา
  // data จึงคงเป็น null เหมือนกรณีที่ส่ง command เป็น null อยู่แล้ว ส่วนคำสั่งที่ไม่ถูกข้ามทำงานเหมือนเดิมทุกอย่าง
  const { hiddenCommands } = useDeviceCapability();
  const skipped = Boolean(command) && hiddenCommands.has(command);
  const activeCommand = skipped ? null : command;
  const scope = JSON.stringify([devId, activeCommand]);
  const currentScope = useRef(scope);
  currentScope.current = scope;
  const requestVersion = useRef(0);

  useEffect(() => {
    setData(null);
    setError("");
    setLoading(false);
    return () => { requestVersion.current += 1; };
  }, [scope]);

  // ดึงข้อมูลอุปกรณ์มาใหม่ทุกครั้งถัด dev_id หรือ command เปลี่ยน
  const runGetCommand = useCallback(async () => {
    if (!devId || !activeCommand) return;
    const version = ++requestVersion.current;
    const isCurrent = () => version === requestVersion.current && scope === currentScope.current;
    setLoading(true);
    setError("");
    try {
      let requestPromise;
      if (dedupeInFlight) {
        const key = `${devId}:${activeCommand}`;
        requestPromise = inFlightRequests.get(key);
        if (!requestPromise) {
          requestPromise = runDeviceCommand(devId, activeCommand, {});
          inFlightRequests.set(key, requestPromise);
          const cleanup = () => {
            if (inFlightRequests.get(key) === requestPromise) {
              inFlightRequests.delete(key);
            }
          };
          requestPromise.then(cleanup, cleanup);
        }
      } else {
        requestPromise = runDeviceCommand(devId, activeCommand, {});
      }

      const result = await requestPromise;
      if (isCurrent()) setData({scope, value: result});
    } catch (err) {
      if (isCurrent()) setError(errorMessage(err, "Failed to fetch data"));
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [devId, activeCommand, scope, dedupeInFlight]);

  // Error is owned by this hook. Consumers must be able to dismiss it at the
  // source; merely hiding an error banner leaves `error` truthy and pages that
  // branch on it can remain stuck without rendering their form again.
  const clearError = useCallback(() => {
    setError("");
  }, []);

  // ให้เรียกใช้ function runGetCommand เมื่อค่าที่กำหนดใน [] มีการเปลียนแปลง
  useEffect(() => {
    if (auto && devId && activeCommand) runGetCommand();
  }, [auto, devId, activeCommand, runGetCommand]);

  // (ปัญหาที่ 1 ขั้น A4 ใน planning/transaction_review.md) ดึงข้อมูลใหม่ทันทีที่มี
  // คำสั่งเขียนของอุปกรณ์ตัวนี้ล้มเหลว - เพราะคำสั่งที่ล้มเหลวกลางชุดแปลว่าคำสั่ง
  // ก่อนหน้าอาจ apply ไปแล้วบางส่วน หน้าจอที่ค้างอยู่จึงไม่ตรงกับอุปกรณ์จริง ถ้าไม่
  // โหลดใหม่ ผู้ใช้จะเห็นข้อมูลเก่าแล้วกดซ้ำบนสมมติฐานที่ผิด
  //
  // ฟังที่นี่จุดเดียวแทนการไล่ใส่ refetch ใน catch ของทุก flow - จุดยิง event อยู่ที่
  // runDeviceCommand ใน api/api_devices.js (แพทเทิร์นเดียวกับ toast:success)
  // เช็ค devId ก่อนเสมอ เผื่อมีหลาย hook ของคนละอุปกรณ์ mount อยู่พร้อมกัน
  useEffect(() => {
    // auto=false ต้องปิดทั้งโหลดครั้งแรกและ refetch จาก event ด้วย; ไม่เช่นนั้น
    // Huawei ที่ตั้งใจไม่รองรับ DHCP ยังถูก device:state-changed ดึง DHCP pool
    // หลัง Save แล้วเกิด 400 แม้ hook แรกจะไม่ยิงเลย.
    if (!auto || !devId || !activeCommand) return undefined;
    function handleStateChanged(event) {
      if (event.detail?.devId !== devId) return;
      runGetCommand();
    }
    window.addEventListener("device:state-changed", handleStateChanged);
    return () => window.removeEventListener("device:state-changed", handleStateChanged);
  }, [auto, devId, activeCommand, runGetCommand]);

  return {
    data: data?.scope === scope ? data.value : null,
    loading,
    error,
    clearError,
    refetch: runGetCommand,
  };
}
