import DismissibleError from "../../DismissibleError";
import { useCallback } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { Reload_Result } from "../../commandResult/reload_command_result";

// Cisco ส่งเวลาที่ ARP entry เปลี่ยนล่าสุดเป็น ISO timestamp ไม่ได้ส่งเวลาคงเหลือ
// มาโดยตรง จึงคำนวณจาก timeout 4 ชั่วโมงตามนโยบายที่ใช้กับอุปกรณ์ชุดนี้
const CISCO_ARP_TIMEOUT_MS = 4 * 60 * 60 * 1000;

function formatCiscoArpRemaining(timestamp) {
  const lastUpdatedMs = Date.parse(timestamp);
  if (Number.isNaN(lastUpdatedMs)) return "-";

  const remainingMs = lastUpdatedMs + CISCO_ARP_TIMEOUT_MS - Date.now();
  if (remainingMs <= 0) return "-";

  const totalMinutes = Math.ceil(remainingMs / (60 * 1000));
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;

  if (hours > 0) return `${hours} hours ${minutes} minutes`;
  return `${minutes} minutes`;
}

// Juniper's "age" field (จาก normalize_arp) มาจาก <time-to-expire> ของ Junos -
// เป็น**วินาทีที่เหลือก่อนหมดอายุ** (นับถอยหลัง) ไม่ใช่ timestamp/"เวลาที่ผ่านมา
// แล้ว" แบบที่ Cisco ส่งมา (ยืนยันจริงจากอุปกรณ์: `show arp expiration-time |
// display xml` คืน <time-to-expire>1330</time-to-expire> เป็นตัวเลขวินาทีดิบๆ)
// ส่งค่านี้เข้า formatDate() ตรงๆ (ออกแบบมาสำหรับ timestamp) จะพัง: Date.parse
// ตีความ "1330" เป็นปี ค.ศ. 1330 กลายเป็น "1 มกราคม 1330" - เจอ bug นี้จริงตอน
// ทดสอบผ่าน browser ต้อง format แยกเป็น "นับถอยหลัง" ต่างหาก ไม่ผ่าน formatDate
function formatArpAge(row, vendor) {
  if (vendor === "cisco") {
    return formatCiscoArpRemaining(row.age);
  }
  if (vendor === "juniper") {
    const seconds = Number(row.age);
    if (!Number.isFinite(seconds) || seconds < 0) return "-";
    const minutes = Math.floor(seconds / 60);
    return minutes > 0 ? `${minutes} minutes` : `-`;
  }
  if (vendor === "huawei") {
    const minutes = Number(row.age);
    if (!Number.isFinite(minutes) || minutes <= 0) return "-";
    return `${minutes} minutes`;
  }
  return "-";
}

export default function ArpStatus({ devId, vendor }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_arp_table", { dedupeInFlight: true });

  const handleRefresh = useCallback(() => {
    if (loading) return;
    refetch();
  }, [loading, refetch]);

  if (loading && !data) return <div className="center-loading">Fetching ARP data...</div>;
  if (error) return (
    <div className="command-output">
      <div className="command-output-title">
        <Reload_Result loading={loading} onRefresh={handleRefresh}/>
      </div>
      <DismissibleError message={error} onDismiss={clearError} />
    </div>
  );
  if (!data) return null;

  const rows = data.normalized ? data.result : [];

  return (
    <div className="command-output">
      <div className="command-output-title">
        <Reload_Result loading={loading} onRefresh={handleRefresh}/>
      </div>

      {!data.normalized ? (
        <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
      ) : rows.length === 0 ? (
        <div className="config-placeholder">No ARP data available</div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>No</th>
              <th>IP Address</th>
              <th>MAC Address</th>
              <th>Expire In</th>
              <th>Interface</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={`${row.ip}-${row.interface}-${index}`}>
                <td>{index + 1}</td>
                <td>{row.ip}</td>
                <td>{row.mac || "-"}</td>
                <td>{formatArpAge(row, vendor)}</td>
                <td>{row.interface || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
