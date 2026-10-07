import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import { getDeviceStats } from "../../../api/api_devices";
import { Reload_Result } from "../../commandResult/reload_command_result";

// 10 วิ - ตรงกับ backend's STATS_POLL_INTERVAL (conn_socket.py's
// _poll_stats_loop) พอดี - endpoint /devices/{id}/stats อ่านจาก cache ที่
// background poller เก็บไว้เท่านั้น ไม่ยิงไปอุปกรณ์เองเลย เลย poll ถี่ขนาดนี้
// จาก frontend ได้อย่างปลอดภัย (ไม่ได้เพิ่ม load ให้อุปกรณ์เลยสักครั้ง)
const POLL_INTERVAL_MS = 10000;

function formatPercent(value) {
  return typeof value === "number" ? `${value.toFixed(1)}%` : "-";
}

function formatDateTime(iso) {
  return iso ? new Date(iso).toLocaleString("en-US") : "-";
}

// หน้า "Basic Info" ของ dashboard (2026-07-30, ปรับใหญ่ 2026-08-06) - user ขอ
// ให้เป็นแท็บแรกที่เห็นตอนเปิดจัดการอุปกรณ์ (ดู DeviceDetail.jsx's default
// active state) และรวมข้อมูลภาพรวมอุปกรณ์ทั้งหมดไว้ที่นี่จุดเดียว (ย้ายมาจาก
// บล็อกที่เคยปักหมุดอยู่เหนือทุกแท็บใน DeviceDetail.jsx เดิม): ชื่ออุปกรณ์, IP,
// สถานะการเชื่อมต่อปัจจุบัน, Uptime, CPU, RAM, Last seen, Added date - **ไม่มี
// MAC/Serial ที่นี่** (MAC ย้ายไปซ่อนไว้ที่ "Device Setting" ใต้ System Management,
// Serial ไม่โชว์ที่ไหนในเว็บเลยตามที่ user ระบุ - ทั้งคู่เป็น credential ที่
// ระบบใช้จับคู่ตัวตนอุปกรณ์ตอน call-home)
export default function BasicInfo({ devId, device, presentUsers, currentUser }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const result = await getDeviceStats(devId);
        if (!cancelled) {
          setData(result);
          setError("");
        }
      } catch (err) {
        if (!cancelled) setError(err.detail || "Failed to fetch device data");
      }
    }

    poll();
    const timer = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [devId]);

  const connected = data?.connected;
  const stats = data?.stats;
  // (bug 55) สถานะที่ 3 - ต่ออยู่แต่ไม่ตอบ
  //
  // เดิมหน้านี้มีข้อความเตือน 2 แบบ (ไม่ได้เชื่อมต่อ / กำลังรอข้อมูลรอบแรก) แต่ไม่มี
  // แบบ "เชื่อมต่ออยู่แต่ไม่ตอบ" ซึ่งเป็นสถานะที่เกิดจริง - พอ connected เป็น true
  // และ stats มีค่า (ค่าเก่า) จึงไม่มีข้อความเตือนอะไรขึ้นเลย ผู้ใช้เห็นทุกอย่างปกติ
  //
  // ตอนนี้ backend คืน responsive/failed_polls/stale_age_seconds มาให้แล้ว และจะ
  // "ไม่คืน stats ที่เก่าเกิน 30 วิ" ด้วย (user เลือก: เน้นข้อมูลใหม่ดีกว่า) - หน้านี้
  // จึงบอกได้ตรง ๆ ว่าไม่มีข้อมูลสด แทนที่จะโชว์ตัวเลขเก่าเงียบ ๆ
  const responsive = data?.responsive;
  const failedPolls = data?.failed_polls ?? 0;
  const staleAge = data?.stale_age_seconds;

  return (
    <div className="command-output">
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      {/* user ขอ (2026-08-06): "อย่าเอามาเรียงแบบนี้ เอามันไว้ในตาราง มี 2
      column พอ" - เดิมเป็น .detail-grid (การ์ดเรียงเป็นแถวๆ กระจายเต็มความกว้าง)
      เปลี่ยนเป็นตาราง 2 คอลัมน์ (label/value) ตรงๆ - reuse .data-table เดิม
      (ใช้ทั่วแอปอยู่แล้ว) + scoped class .basic-info-table override สัดส่วน
      คอลัมน์ (ตาม pattern เดียวกับ .interfaces-brief-table - ไม่แก้ rule
      .data-table เดิมตรงๆ กันกระทบตารางอื่น) */}
      <table className="data-table basic-info-table">
        <tbody>
          <tr>
            <td>Device Name</td>
            <td>{device?.dev_name || "-"}</td>
          </tr>
          <tr>
            <td>Device Vendor</td>
            <td>{(device?.dev_vendor).toUpperCase() || "-"}</td>
          </tr>
          <tr>
            <td>Device IP</td>
            <td>{device?.dev_ip || "-"}</td>
          </tr>
          <tr>
            <td>Status</td>
            <td>
              {!data
                ? "-"
                : !connected
                ? "Offline"
                : responsive
                ? "Online"
                : "Not Response"}
            </td>
          </tr>
          <tr className="basic-info-users-row">
            <td>Active User</td>
            <td>
              {presentUsers && presentUsers.length > 0 ? (
                presentUsers.map((usrName) => (
                  <div key={usrName}>{usrName} {usrName === currentUser ? "(You)" : ""}</div>
                ))
              ) : (
                <span>-</span>
              )}
            </td>
          </tr>
          <tr>
            <td>Uptime</td>
            <td>{stats?.uptime || "-"}</td>
          </tr>
          <tr>
            <td>CPU</td>
            <td>{formatPercent(stats?.cpu_percent)}</td>
          </tr>
          <tr>
            <td>RAM</td>
            <td>{formatPercent(stats?.memory_percent)}</td>
          </tr>
          <tr>
            <td>Last seen</td>
            <td>{formatDateTime(device?.dev_last_seen)}</td>
          </tr>
          <tr>
            <td>Added</td>
            <td>{formatDateTime(device?.dev_added_date)}</td>
          </tr>
        </tbody>
      </table>

      {!data && !error && <div className="center-loading">Fetching device data...</div>}
      {data && !connected && (
        <div className="config-placeholder">Device is currently offline — live Uptime/CPU/RAM data unavailable</div>
      )}
      {/* (bug 55) ต่ออยู่แต่ไม่ตอบ - บอกให้ชัดว่าตัวเลขที่เห็น (ถ้ามี) ไม่ใช่ค่าปัจจุบัน
          และบอกด้วยว่าข้อมูลล่าสุดเก่าแค่ไหน ไม่ปล่อยให้ผู้ใช้เดาเอง */}
      {data && connected && !responsive && (
        <div className="form-error">
          Device is connected, but has been unresponsive for {failedPolls} consecutive polls
          {staleAge != null && ` - latest CPU/RAM data is ${staleAge}s old and not displayed`}
          {" "}— commands may fail
        </div>
      )}
      {data && connected && responsive && !stats && (
        <div className="config-placeholder">
          {staleAge != null
            ? `Latest data is ${staleAge}s old (stale) - waiting for next polling cycle`
            : "Waiting for initial data from background poller (every 10s)..."}
        </div>
      )}
    </div>
  );
}
