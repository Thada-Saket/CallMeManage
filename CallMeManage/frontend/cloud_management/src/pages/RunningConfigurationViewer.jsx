import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { getRunningConfigSnapshot } from "../api/api_devices";
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
              <span className="field-help-tooltip" role="tooltip">Read-only structured data returned through NETCONF/YANG. Secret values are hidden before the snapshot is stored or displayed.</span>
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

      <div className="running-config-sections">
        {snapshot.sections.map((section) => (
          <section className="running-config-section" key={section.id}>
            <h2>{section.label}</h2>
            <ConfigurationTable data={section.data} label={section.label} />
          </section>
        ))}
      </div>
    </main>
  );
}
