import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import { VLAN_ID_MAX, VLAN_ID_MIN, acceptsVlanIdDraft, validateVlanId } from "../../../utils/vlanId";

// โหมด Edit: pre-fill จาก editTarget (แถวที่เลือกจาก vlan.jsx - {id, name, enabled})
function buildInitialValues(mode, editTarget) {
  if (mode !== "edit" || !editTarget) {
    return { vlanId: "", name: "", enabled: true };
  }
  return {
    vlanId: editTarget.id != null ? String(editTarget.id) : "",
    name: editTarget.name || "",
    enabled: editTarget.enabled !== false,
  };
}

// Cisco: set_vlan(vlan_id, name=None, shutdown=False) - shutdown เป็น polarity
// ปกติ (shutdown=true = ปิดจริง) ต่างจาก set_interface_static_ip ที่
// shutdown=true กลับหมายถึง "เปิด" - เก็บ state เป็น "enabled" ตรงๆ กันสับสน
// แล้วค่อยกลับด้าน (shutdown: !enabled) ตอน submit
// Juniper ใช้ vlan_name เป็น key: เมื่อแก้ชื่อส่ง old_name ให้ backend rename
// ส่วน enabled แปลงเป็น shutdown เหมือน vendor อื่น (Junos active/inactive)
export default function VlanFormModal({ devId, vendor, mode = "create", editTarget = null, onClose, onSaved }) {
  const isJuniper = vendor === "juniper";
  const isEdit = mode === "edit" && !!editTarget;
  const [values, setValues] = useState(buildInitialValues(mode, editTarget));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [vlanIdError, setVlanIdError] = useState("");

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    // Edit ต้องใช้ ID เดิมทุก vendor; ถ้าต้องการเปลี่ยน ID ให้ลบแล้วสร้างใหม่
    // validate ซ้ำแม้ Edit (ช่อง disabled) เพราะ editTarget มาจาก parser ของอุปกรณ์
    const checkedVlan = validateVlanId(isEdit ? editTarget.id : values.vlanId);
    if (!checkedVlan.valid) {
      setVlanIdError(checkedVlan.error);
      return setError(checkedVlan.error);
    }
    setVlanIdError("");
    const vlanId = checkedVlan.value;

    const name = values.name.trim();
    let params;
    if (isJuniper) {
      if (!name) return setError("Name is required (required for Juniper - used directly as VLAN name on device)");
      if (name.length > 64) return setError("Name must not exceed 64 characters");
      params = { vlan_name: name, vlan_id: vlanId, shutdown: !values.enabled };
      if (isEdit && name !== editTarget.name) params.old_name = editTarget.name;
    } else {
      params = { vlan_id: vlanId, shutdown: !values.enabled };
      if (name) params.name = name;
    }

    setSubmitting(true);
    try {
      // ใช้ ID เดิม และแก้ชื่อ/สถานะโดยไม่ลบ VLAN ก่อน
      await runDeviceCommand(devId, "set_vlan", params);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit VLAN" : "Failed to create VLAN"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && <div className="command-output-title">Edit: VLAN {editTarget.id}</div>}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label" htmlFor="vlan-id-input">
          VLAN ID ({VLAN_ID_MIN}-{VLAN_ID_MAX})
        </label>
        <input
          id="vlan-id-input"
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={4}
          autoComplete="off"
          placeholder="10"
          value={values.vlanId}
          onChange={(event) => {
            const next = event.target.value;
            if (acceptsVlanIdDraft(next)) {
              setField("vlanId", next);
              setVlanIdError("");
            } else {
              setVlanIdError(validateVlanId(next).error);
            }
          }}
          aria-invalid={Boolean(vlanIdError)}
          aria-describedby="vlan-id-hint"
          disabled={isEdit}
          required
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Name{isJuniper ? "" : " (Optional)"}</label>
        <input
          type="text"
          placeholder="LAN"
          value={values.name}
          onChange={(event) => setField("name", event.target.value)}
          required={isJuniper}
        />
      </div>
      
      <div className="interface-configuration-form-field">
        <label className="data-label">Enable VLAN</label>
        <div className="toggle-switch-container">
          <input
            type="checkbox"
            checked={values.enabled}
            onChange={(event) => setField("enabled", event.target.checked)}
            id="vlan-enable-toggle"
          />
          <label className="toggleSwitch" htmlFor="vlan-enable-toggle"></label>
        </div>
      </div>

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Sending..." : isEdit ? "Save" : "OK"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}
