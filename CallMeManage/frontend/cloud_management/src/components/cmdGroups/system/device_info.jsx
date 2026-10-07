import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { createRunningConfigSnapshot, factoryResetDevice, runDeviceCommand } from "../../../api/api_devices";
import DismissibleError from "../../DismissibleError";
import { formatDate } from "../../../utils/formatDate";
import { appUrl } from "../../../utils/appBase";
import "../../../assets/css/runningConfiguration.css";

const VENDOR_LABELS = {
  cisco: "Cisco IOS XE",
  juniper: "Juniper Junos",
  huawei: "Huawei VRP",
};

const STATUS_LABELS = {
  active: { text: "Online", className: "badge-active" },
  online: { text: "Online", className: "badge-active" },
  pending: { text: "Pending", className: "badge-pending" },
  offline: { text: "Offline", className: "badge-offline" },
  rejected: { text: "Rejected", className: "badge-rejected" },
};

function errorMessage(error, fallback = "Could not load the running configuration. Please try again.") {
  if (typeof error?.detail === "string") return error.detail;
  if (error?.detail?.message) return error.detail.message;
  return error?.message || fallback;
}

function InfoItem({ label, value, children, mono = false, title }) {
  return (
    <div className="device-info-item">
      <span className="device-info-label">{label}</span>
      {children || <span className={`device-info-value${mono ? " is-mono" : ""}`} title={title}>{value || "-"}</span>}
    </div>
  );
}

function exactDate(value) {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toLocaleString("en-US");
}

// Device metadata collected during token activation. Hardware identity is
// represented by the pinned SSH host-key fingerprint on the backend, not by
// legacy MAC/serial inventory fields.
export default function DeviceInfo({ device, devId, onEditHostname }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [pendingAction, setPendingAction] = useState(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [rebootRequested, setRebootRequested] = useState(false);
  const [factoryResetRequested, setFactoryResetRequested] = useState(false);
  const [rootPassword, setRootPassword] = useState("");
  const [liveVersion, setLiveVersion] = useState(null);
  const [licenses, setLicenses] = useState([]);
  const [deviceDetailsLoading, setDeviceDetailsLoading] = useState(false);
  const [deviceDetailsError, setDeviceDetailsError] = useState("");
  const status = STATUS_LABELS[device?.dev_status] || { text: device?.dev_status || "Unknown", className: "badge-offline" };
  const isOnline = Boolean(device && ["active", "online"].includes(device.dev_status));

  useEffect(() => {
    if (!isOnline) setRebootRequested(false);
  }, [isOnline]);

  useEffect(() => {
    let cancelled = false;

    if (!devId || !isOnline) {
      setLiveVersion(null);
      setLicenses([]);
      setDeviceDetailsError("");
      setDeviceDetailsLoading(false);
      return () => { cancelled = true; };
    }

    async function loadDeviceDetails() {
      setDeviceDetailsLoading(true);
      setDeviceDetailsError("");
      const readErrors = [];
      try {
        // One device owns one NETCONF command lock. Keep these reads
        // sequential so the second request cannot fail with a lock conflict.
        const versionResponse = await runDeviceCommand(devId, "get_device_version", {});
        if (cancelled) return;
        setLiveVersion(versionResponse?.result || null);
      } catch (err) {
        if (!cancelled) {
          setLiveVersion(null);
          readErrors.push(errorMessage(err, "Could not load live version information."));
        }
      }

      try {
        const licenseResponse = await runDeviceCommand(devId, "get_device_license", {});
        if (cancelled) return;
        setLicenses(Array.isArray(licenseResponse?.result?.licenses) ? licenseResponse.result.licenses : []);
      } catch (err) {
        if (!cancelled) {
          setLicenses([]);
          readErrors.push(errorMessage(err, "Could not load license information."));
        }
      } finally {
        if (!cancelled) {
          setDeviceDetailsError(readErrors.join(" "));
          setDeviceDetailsLoading(false);
        }
      }
    }

    loadDeviceDetails();
    return () => { cancelled = true; };
  }, [devId, isOnline]);

  async function handleLoadConfiguration() {
    if (loading) return;
    setError("");

    // Reserve the tab during the user gesture. Opening it after awaiting the
    // device would be blocked by popup protection in most desktop browsers.
    const loadingUrl = appUrl(`devices/${encodeURIComponent(devId)}/running-configuration/loading`);
    const viewer = window.open(loadingUrl, "_blank");
    if (!viewer) {
      setError("The browser blocked the new tab. Allow pop-ups for this site, then try again.");
      return;
    }
    viewer.opener = null;

    setLoading(true);
    try {
      const snapshot = await createRunningConfigSnapshot(devId);
      if (viewer.closed) {
        setError("The configuration tab was closed before loading finished. Please load it again.");
        return;
      }
      viewer.location.replace(
        appUrl(`devices/${encodeURIComponent(devId)}/running-configuration/${encodeURIComponent(snapshot.snapshot_id)}`),
      );
    } catch (err) {
      if (!viewer.closed) viewer.close();
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  function openDeviceAction(action) {
    if (!isOnline || actionBusy) return;
    setActionError("");
    setRootPassword("");
    setPendingAction(action);
  }

  function closeDeviceAction() {
    if (actionBusy) return;
    setPendingAction(null);
    setActionError("");
    setRootPassword("");
  }

  async function handleConfirmDeviceAction() {
    if (!pendingAction || actionBusy) return;
    if (pendingAction === "factory-reset" && device?.dev_vendor === "juniper" && !rootPassword) return;
    setActionBusy(true);
    setActionError("");
    try {
      if (pendingAction === "reboot") {
        await runDeviceCommand(devId, "reboot", {});
        setRebootRequested(true);
      } else {
        await factoryResetDevice(
          devId,
          device?.dev_vendor === "juniper" ? rootPassword : null,
        );
        setFactoryResetRequested(true);
      }
      setPendingAction(null);
      setRootPassword("");
    } catch (err) {
      setActionError(
        typeof err?.detail === "string"
          ? err.detail
          : err?.detail?.message || err?.message || `Could not ${pendingAction === "reboot" ? "reboot" : "factory reset"} the device. Please try again.`,
      );
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <div className="command-output device-info-page">
      <div className="command-output-title device-info-title">
        <div>
          <span>Device Setting</span>
          <p>Identity, software, and connection details reported by this device.</p>
        </div>
      </div>

      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="device-info-sections">
        <section className="device-info-section" aria-labelledby="device-identity-heading">
          <div className="device-info-section-heading">
            <span className="device-info-section-icon" aria-hidden="true">ID</span>
            <div>
              <h3 id="device-identity-heading">Device Identity</h3>
              <p>Hardware and software details read from the device.</p>
            </div>
          </div>
          <div className="device-info-grid">
            <InfoItem label="Device Name">
              <span className="device-info-value device-info-name-value">
                <span>{device?.dev_name || "-"}</span>
                <button
                  type="button"
                  className="device-hostname-edit-button"
                  onClick={onEditHostname}
                  disabled={!isOnline || !onEditHostname}
                  aria-label={`Change hostname for ${device?.dev_name || "device"}`}
                  title={isOnline
                    ? "Change device hostname"
                    : "Device must be online to change its hostname"}
                >
                  &#128393;
                </button>
              </span>
            </InfoItem>
            <InfoItem label="Vendor" value={VENDOR_LABELS[device?.dev_vendor] || device?.dev_vendor} />
            <InfoItem label="Model" value={device?.dev_model} />
            <InfoItem label="Firmware" value={device?.dev_firmware} />
            <InfoItem label="Operating System" value={liveVersion?.platform} />
            <InfoItem label="Software Version" value={liveVersion?.software_version} />
          </div>
        </section>

        <section className="device-info-section" aria-labelledby="device-license-heading">
          <div className="device-info-section-heading">
            <span className="device-info-section-icon" aria-hidden="true">LIC</span>
            <div>
              <h3 id="device-license-heading">Device License</h3>
              <p>License and product identity reported directly by the device.</p>
            </div>
          </div>
          {deviceDetailsError && (
            <DismissibleError message={deviceDetailsError} onDismiss={() => setDeviceDetailsError("")} />
          )}
          <div className="device-license-table-wrap">
            <table className="data-table basic-info-table device-license-table">
              <thead>
                <tr>
                  <th>Product / License</th>
                  <th>Version</th>
                  <th>Serial Number</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {deviceDetailsLoading && licenses.length === 0 ? (
                  <tr><td colSpan="4" className="device-license-empty">Loading license information...</td></tr>
                ) : licenses.length > 0 ? licenses.map((license, index) => (
                  <tr key={`${license.name || "license"}-${license.serial_number || index}`}>
                    <td>{license.name || "-"}</td>
                    <td>{license.version || "-"}</td>
                    <td className="is-mono">{license.serial_number || "-"}</td>
                    <td>{license.status || "Not reported"}</td>
                  </tr>
                )) : (
                  <tr><td colSpan="4" className="device-license-empty">No license information was reported by this device.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="device-info-section" aria-labelledby="device-connection-heading">
          <div className="device-info-section-heading">
            <span className="device-info-section-icon" aria-hidden="true">NET</span>
            <div>
              <h3 id="device-connection-heading">Connection</h3>
              <p>Latest NETCONF Call Home connection recorded by the system.</p>
            </div>
          </div>
          <div className="device-info-grid">
            <InfoItem label="Status">
              <span className={`badge ${status.className}`}>{status.text}</span>
            </InfoItem>
            <InfoItem label="Call-home IP" value={device?.dev_ip} mono />
            <InfoItem label="Last Seen" value={formatDate(device?.dev_last_seen)} title={exactDate(device?.dev_last_seen)} />
            <InfoItem label="Enrolled" value={formatDate(device?.dev_added_date)} title={exactDate(device?.dev_added_date)} />
            <InfoItem label="Authentication">
              <span className={`device-info-verified${device?.dev_fingerprint ? " is-verified" : ""}`}>
                {device?.dev_fingerprint ? "SSH identity verified" : "Pending verification"}
              </span>
            </InfoItem>
          </div>
        </section>

        <section className="device-info-section" aria-labelledby="device-configuration-heading">
          <div className="device-info-section-heading">
            <span className="device-info-section-icon" aria-hidden="true">CFG</span>
            <div>
              <h3 id="device-configuration-heading">Configuration</h3>
              <p>Load configuration or perform device maintenance actions.</p>
            </div>
          </div>
          <table className="data-table basic-info-table device-configuration-table">
            <tbody>
              <tr>
                <td>
                  <span className="field-label-with-hint">
                    <span>Load Device Configuration</span>
                    <span className="field-help">
                      <button type="button" className="field-help-trigger" aria-label="About loading device configuration">?</button>
                      <span className="field-help-tooltip" role="tooltip">
                        Loads the current running configuration on demand into a temporary snapshot that expires after 15 minutes.
                      </span>
                    </span>
                  </span>
                </td>
                <td>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={handleLoadConfiguration}
                    disabled={loading || !devId || !isOnline}
                  >
                    {loading ? "Loading..." : "Load Configuration"}
                  </button>
                </td>
              </tr>
              <tr>
                <td>Reboot Device</td>
                <td>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => openDeviceAction("reboot")}
                    disabled={!isOnline || actionBusy || rebootRequested}
                  >
                    {rebootRequested ? "Rebooting..." : "Reboot"}
                  </button>
                </td>
              </tr>
              <tr>
                <td>Factory Reset</td>
                <td>
                  <button
                    type="button"
                    className="btn btn-danger"
                    onClick={() => openDeviceAction("factory-reset")}
                    disabled={!isOnline || actionBusy || factoryResetRequested}
                  >
                    {factoryResetRequested
                      ? device?.dev_vendor === "juniper" ? "Reset Complete" : "Resetting..."
                      : "Factory Reset"}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
      </div>

      {pendingAction && createPortal(
        <div className="modal-overlay" onClick={closeDeviceAction} role="presentation">
          <div
            className="modal-card modal-card-danger-confirm"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="device-action-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="modal-header modal-header-danger">
              <h2 id="device-action-title">
                {pendingAction === "reboot" ? "Confirm Device Reboot" : "Confirm Factory Reset"}
              </h2>
              <button
                type="button"
                className="modal-close"
                onClick={closeDeviceAction}
                aria-label="Close"
                disabled={actionBusy}
              >
                &times;
              </button>
            </div>
            <div className="danger-confirm-message">
              {pendingAction === "reboot" ? (
                <>
                  Reboot <strong>{device?.dev_name}</strong>? The device will temporarily go offline and reconnect through NETCONF Call Home after it starts again.
                </>
              ) : (
                <>
                  <strong>Warning:</strong> Factory Reset permanently removes the device configuration and its NETCONF Call Home settings. The device will remain offline until it is configured and enrolled again.
                </>
              )}
            </div>
            {pendingAction === "factory-reset" && device?.dev_vendor === "juniper" && (
              <div className="factory-reset-password-field">
                <label htmlFor="factory-reset-root-password">Current Root Password</label>
                <input
                  id="factory-reset-root-password"
                  type="password"
                  value={rootPassword}
                  onChange={(event) => setRootPassword(event.target.value)}
                  autoComplete="current-password"
                  disabled={actionBusy}
                  required
                  autoFocus
                />
                <p>The password is verified against the current device configuration and is not stored.</p>
              </div>
            )}
            {actionError && <DismissibleError message={actionError} onDismiss={() => setActionError("")} />}
            <div className="modal-actions">
              <button type="button" className="btn btn-ghost" onClick={closeDeviceAction} disabled={actionBusy}>
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger"
                onClick={handleConfirmDeviceAction}
                disabled={actionBusy || (pendingAction === "factory-reset" && device?.dev_vendor === "juniper" && !rootPassword)}
              >
                {pendingAction === "factory-reset"
                  ? actionBusy ? "Resetting..." : "Factory Reset"
                  : actionBusy ? "Rebooting..." : "Reboot"}
              </button>
            </div>
          </div>
        </div>,
        document.body,
      )}

      {loading && createPortal(
        <div className="modal-overlay running-config-loading-overlay" role="presentation">
          <div className="modal-card running-config-loading-card" role="dialog" aria-modal="true" aria-labelledby="running-config-loading-title">
            <div className="running-config-spinner" aria-hidden="true" />
            <h2 id="running-config-loading-title">Loading Running Configuration</h2>
            <p>Waiting for the device to return the complete configuration. Keep this page open.</p>
          </div>
        </div>,
        document.body,
      )}
    </div>
  );
}
