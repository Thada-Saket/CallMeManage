import { useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { resetDeviceIdentity } from "../api/api_devices";
import { copyText } from "../utils/copyText";
import { createSingleFlight } from "../utils/singleFlight";
import DismissibleError from "./DismissibleError";

export default function ResetIdentityModal({ isOpen, onClose, device, onResetSuccess }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [forceOffline, setForceOffline] = useState(false);
  const [copiedStepIndex, setCopiedStepIndex] = useState(null);
  const [copiedAllCli, setCopiedAllCli] = useState(false);

  const flight = useMemo(() => createSingleFlight(), []);

  if (!isOpen) return null;

  async function handleConfirmReset(e) {
    e.preventDefault();
    if (loading || flight.busy) return;
    setError("");

    await flight.run(async () => {
      setLoading(true);
      try {
        const data = await resetDeviceIdentity(device.dev_id, forceOffline);
        setResult(data);
        if (onResetSuccess) {
          onResetSuccess(data);
        }
      } catch (err) {
        setError(err.detail || "Failed to prepare device reconnection");
      } finally {
        setLoading(false);
      }
    });
  }

  async function handleCopyStep(commands, index) {
    const success = await copyText(commands);
    if (success) {
      setCopiedStepIndex(index);
      setTimeout(() => setCopiedStepIndex(null), 2000);
    }
  }

  async function handleCopyAllCli(cli) {
    const success = await copyText(cli);
    if (success) {
      setCopiedAllCli(true);
      setTimeout(() => setCopiedAllCli(false), 2000);
    }
  }

  function handleCloseModal() {
    if (loading) return;
    setResult(null);
    setError("");
    setForceOffline(false);
    onClose();
  }

  return createPortal(
    <div
      className="modal-overlay"
      onClick={(event) => {
        event.stopPropagation();
        handleCloseModal();
      }}
    >
      <div
        className="modal-card"
        style={{ maxWidth: result ? "720px" : "540px", width: "95%" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h2>{result ? "Device Reconnection Ready" : "Reconnect Device"}</h2>
          <button
            type="button"
            className="modal-close"
            onClick={handleCloseModal}
            aria-label="Close"
            disabled={loading}
          >
            &times;
          </button>
        </div>

        {!result ? (
          <form onSubmit={handleConfirmReset}>
            {error && <DismissibleError message={error} onDismiss={() => setError("")} style={{ marginBottom: "1rem" }} />}

            <div style={{ marginBottom: "1.25rem", color: "#475569", lineHeight: "1.5" }}>
              <p style={{ marginTop: 0 }}>
                Reconnect <strong>{device?.dev_name}</strong> to this workspace?
              </p>
              <div
                style={{
                  background: "#fef2f2",
                  borderLeft: "4px solid #ef4444",
                  padding: "0.75rem 1rem",
                  borderRadius: "4px",
                  fontSize: "0.875rem",
                  color: "#991b1b",
                  marginBottom: "1rem",
                }}
              >
                <strong>Important:</strong> The current connection identity will be replaced and the device will return
                to <em>Pending</em> until it connects again.
              </div>
              <ul style={{ margin: "0.5rem 0", paddingLeft: "1.25rem", fontSize: "0.875rem" }}>
                <li>
                  <strong>Online:</strong> The system updates the connection settings and reconnects the device automatically.
                </li>
                <li style={{ marginTop: "0.25rem" }}>
                  <strong>Offline:</strong> The system provides commands to reconnect the device from its console.
                </li>
              </ul>
            </div>

            <div className="field" style={{ marginBottom: "1.25rem" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={forceOffline}
                  onChange={(e) => setForceOffline(e.target.checked)}
                  disabled={loading}
                />
                <span style={{ fontSize: "0.875rem" }}>
                  Generate manual reconnection commands
                </span>
              </label>
            </div>

            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={handleCloseModal}
                disabled={loading}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn btn-danger"
                disabled={loading}
              >
                {loading ? "Preparing..." : "Reconnect Device"}
              </button>
            </div>
          </form>
        ) : (
          <div>
            {result.mode === "online" ? (
              <div
                style={{
                  background: "#f0fdf4",
                  borderLeft: "4px solid #22c55e",
                  padding: "0.75rem 1rem",
                  borderRadius: "4px",
                  fontSize: "0.875rem",
                  color: "#166534",
                  marginBottom: "1.25rem",
                }}
              >
                <strong>Reconnection Started:</strong> The device connection settings were updated and verified. The
                current session was closed so the device can connect again.
              </div>
            ) : (
              <div
                style={{
                  background: "#eff6ff",
                  borderLeft: "4px solid #3b82f6",
                  padding: "0.75rem 1rem",
                  borderRadius: "4px",
                  fontSize: "0.875rem",
                  color: "#1e40af",
                  marginBottom: "1.25rem",
                }}
              >
                <strong>Manual Reconnection:</strong> Apply the Call Home configuration commands below on the device console.
              </div>
            )}

            {result.warning && (
              <div
                style={{
                  background: "#fffbeb",
                  borderLeft: "4px solid #f59e0b",
                  padding: "0.75rem 1rem",
                  borderRadius: "4px",
                  fontSize: "0.875rem",
                  color: "#92400e",
                  marginBottom: "1.25rem",
                }}
              >
                <strong>Notice:</strong> {result.warning}
              </div>
            )}

            <div style={{ fontSize: "0.75rem", color: "#64748b", marginBottom: "1.25rem" }}>
              Enrollment expires: {new Date(result.expires_at).toLocaleString()}
            </div>

            {result.mode === "offline" && result.cli && (
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                  <h3 style={{ margin: 0, fontSize: "1rem" }}>Recovery Configuration Commands</h3>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => handleCopyAllCli(result.cli)}
                    style={{ fontSize: "0.875rem" }}
                  >
                    {copiedAllCli ? "All Copied! ✓" : "Copy All Commands"}
                  </button>
                </div>

                {result.cli_steps && result.cli_steps.length > 0 ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                    {result.cli_steps.map((step, idx) => (
                      <div
                        key={step.id || idx}
                        style={{
                          border: "1px solid #e2e8f0",
                          borderRadius: "6px",
                          overflow: "hidden",
                          background: "#ffffff",
                        }}
                      >
                        <div
                          style={{
                            background: "#f1f5f9",
                            padding: "0.5rem 0.75rem",
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            fontSize: "0.875rem",
                            fontWeight: 600,
                          }}
                        >
                          <span>Step {idx + 1}: {step.label}</span>
                          <button
                            type="button"
                            className="btn btn-ghost"
                            onClick={() => handleCopyStep(step.commands, idx)}
                            style={{ padding: "0.25rem 0.5rem", fontSize: "0.75rem" }}
                          >
                            {copiedStepIndex === idx ? "Copied! ✓" : "Copy Step"}
                          </button>
                        </div>
                        {step.warning_message && (
                          <div
                            style={{
                              background: "#fffbeb",
                              color: "#b45309",
                              padding: "0.5rem 0.75rem",
                              fontSize: "0.8125rem",
                              borderBottom: "1px solid #fef3c7",
                            }}
                          >
                            ⚠️ {step.warning_message}
                          </div>
                        )}
                        <pre
                          style={{
                            margin: 0,
                            padding: "0.75rem",
                            background: "#0f172a",
                            color: "#f8fafc",
                            fontSize: "0.8125rem",
                            overflowX: "auto",
                            whiteSpace: "pre-wrap",
                          }}
                        >
                          {step.commands}
                        </pre>
                      </div>
                    ))}
                  </div>
                ) : (
                  <pre
                    style={{
                      margin: 0,
                      padding: "0.75rem",
                      background: "#0f172a",
                      color: "#f8fafc",
                      fontSize: "0.8125rem",
                      borderRadius: "6px",
                      overflowX: "auto",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {result.cli}
                  </pre>
                )}
              </div>
            )}

            <div className="modal-actions" style={{ marginTop: "1.5rem" }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleCloseModal}
              >
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>,
    document.body
  );
}
