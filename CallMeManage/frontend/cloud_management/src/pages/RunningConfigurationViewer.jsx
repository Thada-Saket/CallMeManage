import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { getRunningConfigSnapshot } from "../api/api_devices";
import { copyText } from "../utils/copyText";
import "../assets/css/runningConfiguration.css";

function readableError(error) {
  if (typeof error?.detail === "string") return error.detail;
  if (error?.detail?.message) return error.detail.message;
  return "The running configuration could not be displayed.";
}

function formatKey(key) {
  return String(key)
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function flattenConfiguration(value, path = []) {
  if (Array.isArray(value)) {
    if (value.length === 0) return [{ path: path.length ? path : ["Value"], value: "—" }];
    return value.flatMap((item, index) => (
      flattenConfiguration(item, [...path, `Entry ${index + 1}`])
    ));
  }

  if (value && typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length === 0) return [{ path: path.length ? path : ["Value"], value: "—" }];
    return entries.flatMap(([key, child]) => (
      flattenConfiguration(child, [...path, formatKey(key)])
    ));
  }

  return [{
    path: path.length ? path : ["Value"],
    value: value === null || value === undefined || value === "" ? "—" : String(value),
  }];
}

function ConfigurationTable({ data, label }) {
  const rows = flattenConfiguration(data);
  return (
    <div className="running-config-table-wrap">
      <table className="running-config-table">
        <thead>
          <tr>
            <th scope="col">Configuration Path</th>
            <th scope="col">Value</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={`${label}-${row.path.join("/")}-${rowIndex}`}>
              <td className="running-config-path">
                {row.path.map((segment, index) => (
                  <span className="running-config-path-part" key={`${segment}-${index}`}>
                    {index > 0 && <span className="running-config-path-separator" aria-hidden="true">›</span>}
                    <span>{segment}</span>
                  </span>
                ))}
              </td>
              <td className="running-config-value">{row.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// วิธีวาง config กลับลงอุปกรณ์ตามยี่ห้อ - แสดงใต้หัวข้อ Device Format
const PASTE_HINT = {
  cisco: <>Paste in <code>configure terminal</code>.</>,
  juniper: <>In configuration mode run <code>load merge terminal</code>, paste, press <kbd>Ctrl+D</kbd>, then <code>commit</code>.</>,
};

// config รูปแบบของอุปกรณ์ (Cisco CLI / Junos text) - ค่าลับถูกแทนด้วย <hidden> ตั้งแต่ backend
// ก่อนเก็บ snapshot (ผู้ใช้เลือกให้ซ่อนเหมือนเดิม) บรรทัดพวกนั้นต้องเติมเองก่อนวาง
function NativeConfiguration({ snapshot }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState("");

  async function handleCopy() {
    setCopyError("");
    if (await copyText(snapshot.native_text)) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } else {
      setCopyError("Failed to copy. Please select the text manually and copy it.");
    }
  }

  return (
    <section className="running-config-section">
      <div className="running-config-native-header">
        <div>
          <h2>Device Format</h2>
          <p className="running-config-native-hint">{PASTE_HINT[snapshot.vendor]}</p>
        </div>
        <button type="button" className="btn btn-primary" onClick={handleCopy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      {snapshot.native_redacted_count > 0 && (
        <p className="running-config-native-warning" role="note">
          <strong>{snapshot.native_redacted_count} secret value{snapshot.native_redacted_count === 1 ? " is" : "s are"} shown as <code>&lt;hidden&gt;</code>.</strong>{" "}
          Replace them with the real values (or remove those lines) before pasting, otherwise the device rejects them.
        </p>
      )}
      {copyError && <p className="running-config-native-warning" role="alert">{copyError}</p>}
      <pre className="running-config-native-text">{snapshot.native_text}</pre>
    </section>
  );
}

function formatRemaining(seconds) {
  const safe = Math.max(0, seconds);
  const minutes = Math.floor(safe / 60);
  return `${String(minutes).padStart(2, "0")}:${String(safe % 60).padStart(2, "0")}`;
}

export default function RunningConfigurationViewer() {
  const { devId, snapshotId } = useParams();
  const isReservationPage = snapshotId === "loading";
  const [snapshot, setSnapshot] = useState(null);
  const [error, setError] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const [view, setView] = useState("native"); // native | structured

  useEffect(() => {
    if (isReservationPage) return undefined;
    let active = true;
    getRunningConfigSnapshot(devId, snapshotId)
      .then((data) => { if (active) setSnapshot(data); })
      .catch((err) => { if (active) setError(readableError(err)); });
    return () => { active = false; };
  }, [devId, snapshotId, isReservationPage]);

  useEffect(() => {
    if (!snapshot) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [snapshot]);

  const remaining = useMemo(() => {
    if (!snapshot) return 0;
    return Math.max(0, Math.ceil((new Date(snapshot.expires_at).getTime() - now) / 1000));
  }, [snapshot, now]);
  const expired = Boolean(snapshot) && remaining <= 0;
  const hasNative = Boolean(snapshot?.native_text);

  if (isReservationPage || (!snapshot && !error)) {
    return <main className="running-config-viewer running-config-centered"><div className="running-config-spinner" /><h1>Preparing Configuration View</h1><p>The device is still returning its running configuration.</p></main>;
  }

  if (error || expired) {
    return <main className="running-config-viewer running-config-centered"><div className="running-config-expired-icon">!</div><h1>Snapshot Unavailable</h1><p>{expired ? "This snapshot has expired after 15 minutes. Load it again from Device Setting." : error}</p></main>;
  }

  return (
    <main className="running-config-viewer">
      <header className="running-config-header">
        <div>
          <div className="running-config-eyebrow">{snapshot.vendor} · Running datastore</div>
          <h1>
            Running Configuration
            <span className="field-help">
              <button type="button" className="field-help-trigger" aria-label="About this view">?</button>
              <span className="field-help-tooltip" role="tooltip">Read-only configuration returned through NETCONF. Device Format is the device's own syntax, ready to paste back; Structured is the YANG data. Secret values are hidden before the snapshot is stored or displayed.</span>
            </span>
          </h1>
          <p>{snapshot.dev_name}</p>
        </div>
        <div className="running-config-expiry">
          <span>Expires in</span>
          <strong>{formatRemaining(remaining)}</strong>
          <span className="field-help">
            <button type="button" className="field-help-trigger" aria-label="About snapshot expiry">?</button>
            <span className="field-help-tooltip" role="tooltip">This view reads a Redis snapshot and never queries the device again. Refreshing this tab does not extend its 15-minute lifetime.</span>
          </span>
        </div>
      </header>

      <section className="running-config-meta" aria-label="Snapshot information">
        <span>Loaded {new Date(snapshot.created_at).toLocaleString()}</span>
        <span>{snapshot.sections.length} sections</span>
        <span>{snapshot.redacted_count} sensitive values hidden</span>
      </section>

      {/* Cisco/Juniper มี config รูปแบบของอุปกรณ์ให้ (พร้อมวาง) เป็นค่าเริ่มต้น ส่วน Huawei
          ไม่มี RPC แบบนี้ผ่าน NETCONF จึงเห็นแบบ structured อย่างเดียวเหมือนเดิม */}
      {hasNative && (
        <div className="segmented-control running-config-view-switch" role="tablist" aria-label="Configuration view">
          <input type="radio" id="rc-view-native" name="rc-view" checked={view === "native"} onChange={() => setView("native")} />
          <label htmlFor="rc-view-native">Device Format</label>
          <input type="radio" id="rc-view-structured" name="rc-view" checked={view === "structured"} onChange={() => setView("structured")} />
          <label htmlFor="rc-view-structured">Structured</label>
        </div>
      )}
      {!hasNative && snapshot.native_error && (
        <p className="running-config-native-warning" role="note">
          Device format is unavailable for this snapshot: {snapshot.native_error}
        </p>
      )}

      {hasNative && view === "native" ? (
        <div className="running-config-sections">
          <NativeConfiguration snapshot={snapshot} />
        </div>
      ) : (
        <div className="running-config-sections">
          {snapshot.sections.map((section) => (
            <section className="running-config-section" key={section.id}>
              <h2>{section.label}</h2>
              <ConfigurationTable data={section.data} label={section.label} />
            </section>
          ))}
        </div>
      )}
    </main>
  );
}
