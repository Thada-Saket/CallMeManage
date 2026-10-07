import DismissibleError from "../../DismissibleError";
import { useEffect, useRef, useState } from "react";
import { runPingTest } from "../../../api/api_devices";
import { resolvePingTarget } from "../../../utils/pingTarget";
import IPv4Input from "../../common/IPv4Input";

// mapping จาก key ของ common-stats (Cisco-IOS-XE-ip-sla-oper.yang) เป็นคำอธิบาย
// ภาษาไทย - เลือกตัวแรกที่ไม่ใช่ "0" มาโชว์เป็นสาเหตุตอน fail
const FAILURE_REASONS = {
  "no-of-disconnects": "Disconnected during test (Disconnected)",
  "no-of-timeouts": "Destination timed out (Timeout)",
  "no-of-busies": "Destination busy (Busy)",
  "no-of-no-connections": "Unable to connect to destination (No Connection)",
  "no-of-internal-errors": "Device internal error (Internal Error)",
  "no-of-sequence-errors": "Packet sequence error (Sequence Error)",
  "no-of-verify-errors": "Response verification error (Verify Error)",
  "no-of-ctrl-enable-errors": "Probe control enable error (Control Enable Error)",
  "no-of-stats-retrieve-errors": "Failed to retrieve statistics from device (Stats Retrieve Error)",
};

function toDisplayText(value) {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

// Juniper: `<ping>` เป็น operational RPC ของตัวเอง (synchronous, ตอบผลกลับมาใน
// เรพลายเดียว - ดู comment ยาวใน juniper_junos.py's run_ping_test) ผลลัพธ์อยู่ที่
// payload["ping-results"] ตรงๆ (ไม่มี "data" คั่นแบบ get-config เพราะเป็น
// operational reply ไม่ใช่ config) - ยืนยันจาก curl จริง: "ping-success" เป็น
// empty-presence leaf (มี key = สำเร็จ) "ping-failure" เป็น string บอกสาเหตุ -
// rtt-average เป็นหน่วย microseconds (ยืนยันจาก junos-es-rpc-ping.yang) ต้องหาร
// 1000 แปลงเป็น ms ให้ตรงกับที่ UI แสดง "X ms" เหมือน Cisco
function parseJuniperPingResult(result) {
  const pingResults = result?.payload?.["ping-results"];
  if (!pingResults) return null;

  const success = "ping-success" in pingResults;
  const summary = pingResults["probe-results-summary"] || {};
  const rttMicros = summary["rtt-average"];
  const rtt = rttMicros ? String(Math.round(Number(rttMicros) / 1000)) : "";

  const reason = !success
    ? toDisplayText(pingResults["ping-failure"]) || toDisplayText(pingResults["ping-error-message"]) || ""
    : "";

  return { success, returnCode: "", rtt, reason };
}

// ผล ping_test มาจาก normalize_generic (ยังไม่มี normalizer เฉพาะของ
// get_ping_result) เลยเป็น raw structure ตรงกับ YANG: payload.data.ip-sla-stats.
// sla-oper-entry (normalize_generic ตัด wrapper <rpc-reply> ออกไปแล้วก่อนถึง
// frontend - verified จริงกับ HQ-R1 ผ่าน curl ตรงๆ ไม่ใช่ payload.rpc-reply.data
// แบบที่ทดสอบผ่าน testXMLpayload.py ก่อนหน้า เพราะ xml_to_json ที่นั่นเป็นคนละ
// ตัวกับ _element_to_json ที่ normalize_generic ใช้จริง) - success-count/
// failure-count เป็น "1"/"0" เสมอ (ping ครั้งเดียวต่อรอบ) ไม่ใช่ percentage
function parsePingResult(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperPingResult(result);
    } catch {
      return null;
    }
  }
  try {
    const entry = result?.payload?.data?.["ip-sla-stats"]?.["sla-oper-entry"];
    if (!entry) return null;

    const success = toDisplayText(entry["success-count"]) === "1";
    const returnCode = toDisplayText(entry["latest-return-code"]);
    const rtt = entry["rtt-info"]?.["latest-rtt"]?.rtt;

    let reason = "";
    if (!success) {
      const stats = entry["common-stats"] || {};
      const hit = Object.entries(stats).find(([, v]) => {
        const text = toDisplayText(v);
        return text !== "" && text !== "0";
      });
      reason = hit ? FAILURE_REASONS[hit[0]] || hit[0] : "";
    }

    return { success, returnCode, rtt: toDisplayText(rtt), reason };
  } catch {
    return null;
  }
}

export default function Ping({ devId }) {
  // ปลายทางมี 2 ชนิด: IP (IPv4Input) กับ Hostname (text input) - เก็บค่าแยกกัน
  // สลับ mode แล้วค่าของอีกชนิดยังอยู่แต่ไม่ถูกส่ง (ส่งเฉพาะ mode ปัจจุบันเสมอ)
  const [targetMode, setTargetMode] = useState("ip");
  const [ipDestination, setIpDestination] = useState("");
  const [hostnameDestination, setHostnameDestination] = useState("");
  const [phase, setPhase] = useState("idle"); // idle | loading | done | error
  const [elapsed, setElapsed] = useState(0);
  const [result, setResult] = useState(null);
  const [testedDestination, setTestedDestination] = useState("");
  const [error, setError] = useState("");
  const timerRef = useRef(null);

  useEffect(() => () => clearInterval(timerRef.current), []);

  // กันเคส user มึนแล้วพิมพ์ URL ใหม่/กด refresh/ปิดแท็บระหว่าง ping ยังไม่เสร็จ -
  // request เดิมยังวิ่งอยู่ฝั่ง backend เต็มเวลา (ping ถือ DeviceLock ทั้งอุปกรณ์
  // ไว้ตลอด - ดู HANDOFF.md) ถ้าออกจากหน้าไปกลางทางจริงๆ คำสั่งอื่นที่ยิงเข้า
  // อุปกรณ์เดียวกันจะค้างรอ lock แล้วโดน 409 - overlay ด้านล่างกันคลิกเปลี่ยนหน้า
  // ในแอปได้อยู่แล้ว แต่กันการพิมพ์ URL ใหม่/refresh/ปิดแท็บ (full navigation ไม่
  // ผ่าน React Router เลย) ต้องพึ่ง beforeunload เท่านั้น - ข้อความ custom ที่ใส่ใน
  // returnValue เบราว์เซอร์สมัยใหม่ไม่โชว์ให้แล้ว (security) แต่ยังคง native
  // confirm dialog ให้เองอัตโนมัติ
  useEffect(() => {
    if (phase !== "loading") return undefined;
    function handleBeforeUnload(event) {
      event.preventDefault();
      event.returnValue = "";
    }
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [phase]);

  async function handleSubmit(event) {
    event.preventDefault();
    const target = resolvePingTarget(targetMode, targetMode === "hostname" ? hostnameDestination : ipDestination);
    if (!target.ok) {
      setError(target.error);
      return;
    }
    const dest = target.value;

    setError("");
    setResult(null);
    setTestedDestination(dest);
    setPhase("loading");
    setElapsed(0);
    timerRef.current = setInterval(() => setElapsed((s) => s + 1), 1000);

    try {
      const response = await runPingTest(devId, dest);
      const parsed = parsePingResult(response.result);
      if (!parsed) {
        setError("Failed to read response from device");
        setPhase("error");
      } else {
        setResult(parsed);
        setPhase("done");
      }
    } catch (err) {
      setError(err.detail || "Connectivity test failed");
      setPhase("error");
    } finally {
      clearInterval(timerRef.current);
    }
  }

  function switchTargetMode(mode) {
    setTargetMode(mode);
    setError("");
  }

  function handleReset() {
    setPhase("idle");
    setResult(null);
    setError("");
  }

  return (
    <div className="command-configuration">
      <div className="command-output-title">Ping Test</div>

      {phase === "idle" && (
        <form className="interface-configuration-form" onSubmit={handleSubmit}>
          <div className="interface-configuration-form-field">
            <label>Destination Type</label>
            <div className="segmented-control">
              <input type="radio" id="ping-target-ip" name="ping-target-mode" value="ip"
                checked={targetMode === "ip"} onChange={() => switchTargetMode("ip")} />
              <label htmlFor="ping-target-ip">IP Address</label>
              <input type="radio" id="ping-target-hostname" name="ping-target-mode" value="hostname"
                checked={targetMode === "hostname"} onChange={() => switchTargetMode("hostname")} />
              <label htmlFor="ping-target-hostname">Hostname</label>
            </div>
          </div>
          <div className="interface-configuration-form-field">
            {targetMode === "ip" ? (
              <>
                <label htmlFor="ping-destination-ip">Destination IP</label>
                <IPv4Input
                  id="ping-destination-ip"
                  label="Destination IP"
                  value={ipDestination}
                  onChange={setIpDestination}
                  required
                />
              </>
            ) : (
              <>
                <label htmlFor="ping-destination-hostname">Destination Hostname</label>
                <input
                  id="ping-destination-hostname"
                  type="text"
                  placeholder="e.g. example.com"
                  value={hostnameDestination}
                  onChange={(event) => setHostnameDestination(event.target.value)}
                  required
                />
              </>
            )}
          </div>
          {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
          <button type="submit" className="btn btn-primary">
            Start Test
          </button>
        </form>
      )}

      {phase === "loading" && (
        // popup ลอยเต็มจอบัง UI ทั้งหมด (ไม่มี onClick ปิด - ตั้งใจกดอะไรไม่ได้
        // เลยระหว่าง ping ทำงาน) กันไม่ให้ user คลิกเปลี่ยนหน้า/สั่งคำสั่งอื่นเข้า
        // อุปกรณ์เดียวกันซ้อนระหว่าง DeviceLock ยังถูกถืออยู่ - ดู comment ที่
        // beforeunload effect ด้านบนสำหรับเคส full navigation (พิมพ์ URL/refresh)
        <div className="modal-overlay ping-block-overlay">
          <div className="modal-card ping-block-card">
            <div className="ping-spinner" />
            <div className="ping-block-title">Testing connectivity to {testedDestination}...</div>
            <div className="ping-loading-timer">{elapsed} seconds</div>
          </div>
        </div>
      )}

      {phase === "done" && result && (
        <div className="command-output">
          <span className={`badge ping-result-badge ${result.success ? "badge-active" : "badge-rejected"}`}>
            {result.success ? "Success" : "Fail"}
          </span>
          <div className="detail-grid" style={{ marginTop: "16px" }}>
            <div className="detail-item">
              <span className="label">Destination</span>
              <span className="value">{testedDestination}</span>
            </div>
            {result.success ? (
              <div className="detail-item">
                <span className="label">Round-trip time</span>
                <span className="value">{result.rtt ? `${result.rtt} ms` : "-"}</span>
              </div>
            ) : (
              <div className="detail-item">
                <span className="label">Reason</span>
                <span className="value">{result.reason || result.returnCode || "Unknown reason"}</span>
              </div>
            )}
          </div>
          <button type="button" className="btn btn-ghost" style={{ marginTop: "16px" }} onClick={handleReset}>
            Test Again
          </button>
        </div>
      )}

      {phase === "error" && (
        <div className="command-output">
          <DismissibleError message={error} onDismiss={() => setError("")} />
          <button type="button" className="btn btn-ghost" onClick={handleReset}>
            Try Again
          </button>
        </div>
      )}
    </div>
  );
}
