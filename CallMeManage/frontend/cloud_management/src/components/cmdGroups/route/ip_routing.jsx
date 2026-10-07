import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { parseIpRouting } from "../../../utils/ciscoRouteMode";

// Cisco เท่านั้น - เมนูซ่อนหน้านี้จาก Huawei/Juniper ทั้งด้วย requires และ
// unsupportedVendors (ดู DeviceDetail.jsx) เพราะทั้งสองยี่ห้อไม่มี global toggle นี้
//
// toggle ผูกกับค่าที่อ่านจากอุปกรณ์ตรง ๆ ไม่เก็บ state ของตัวเอง หลังสั่งเปลี่ยน
// จะโหลดค่าใหม่จากอุปกรณ์เสมอ หน้าจอจึงตรงกับความจริงไม่ใช่ตรงกับสิ่งที่กด
export default function IPRouting({ devId, onRoutingStateChange }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_ip_routing");
  const [showDisableConfirm, setShowDisableConfirm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");

  const routingEnabled = data?.normalized ? parseIpRouting(data.result) : null;

  useEffect(() => {
    if (routingEnabled !== null) onRoutingStateChange?.(routingEnabled);
  }, [routingEnabled, onRoutingStateChange]);

  async function applyRouting(enabled) {
    setSaving(true);
    setSaveError("");
    try {
      await runDeviceCommand(devId, "set_ip_routing", { enabled });
      onRoutingStateChange?.(enabled);
      setShowDisableConfirm(false);
      refetch();
    } catch (err) {
      setSaveError(err.detail || (enabled ? "Failed to enable IP Routing" : "Failed to disable IP Routing"));
    } finally {
      setSaving(false);
    }
  }

  function handleToggle() {
    if (routingEnabled === null || saving) return;
    if (routingEnabled) {
      // ปิด = อุปกรณ์เลิกทำหน้าที่ router ทันที ต้องยืนยันก่อนเสมอ
      setShowDisableConfirm(true);
      return;
    }
    // เปิดไม่มีผลเสียกับของที่ทำงานอยู่ ยิงได้เลย
    applyRouting(true);
  }

  if (loading && !data) {
    return <div className="center-loading">Loading IP Routing data...</div>;
  }

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}
      {saveError && !showDisableConfirm && <DismissibleError message={saveError} onDismiss={() => setSaveError("")} />}

      {data && routingEnabled === null ? (
        <div className="config-placeholder">Unable to read IP Routing status from device</div>
      ) : (
        <div className="interface-configuration-form">
          <div className="interface-configuration-form-field">
            <label className="data-label">Enable IP Routing</label>
            <div className="toggle-switch-container">
              <input
                type="checkbox"
                id="ip-routing-toggle"
                checked={routingEnabled === true}
                onChange={handleToggle}
                disabled={routingEnabled === null || saving || loading}
              />
              <label className="toggleSwitch" htmlFor="ip-routing-toggle"></label>
            </div>
          </div>
        </div>
      )}

      {showDisableConfirm && (
        <div className="modal-overlay" onClick={() => !saving && setShowDisableConfirm(false)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Confirm Disabling IP Routing</h2>
              <button
                type="button"
                className="modal-close"
                onClick={() => setShowDisableConfirm(false)}
                aria-label="Close"
                disabled={saving}
              >
                &times;
              </button>
            </div>
            <p>
              Disabling IP Routing will disable routing capabilities on this device, operating as a Layer 2 switch only. Traffic across VLANs or Layer 3 interfaces will stop immediately, and configured Static Route, RIP, and OSPF will have no effect. Confirm disabling?
            </p>
            {saveError && <DismissibleError message={saveError} onDismiss={() => setSaveError("")} />}
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setShowDisableConfirm(false)}
                disabled={saving}
              >
                Cancel
              </button>
              <button type="button" className="btn btn-primary" onClick={() => applyRouting(false)} disabled={saving}>
                {saving ? "Disabling..." : "Disable IP Routing"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
