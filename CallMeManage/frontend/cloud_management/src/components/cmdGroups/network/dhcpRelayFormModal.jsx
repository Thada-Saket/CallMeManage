import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { splitInterfaceName } from "../../../utils/interfaceName";
import { isJuniperSelectableInterfaceUnit } from "../../../utils/interfaceKind.js";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import IPv4Input from "../../common/IPv4Input";

// เจอบั๊กจริง (Juniper): edit-config ที่ถูกอุปกรณ์ปฏิเสธด้วย rpc-error ตอบกลับ
// เป็น HTTP 200 ปกติพร้อม {ok: false, errors: [...]} ไม่ใช่ exception -
// runDeviceCommand เลย resolve เฉยๆ ไม่ throw (ดู pattern เดียวกันใน
// dhcpFormModal.jsx/InterfacesFormModal.jsx/security_tunnel.jsx)
function assertCommandOk(response, fallbackMessage) {
  const result = response?.result;
  if (result && result.ok === false) {
    const message = (result.errors || []).map((e) => e.message).filter(Boolean).join("; ") || fallbackMessage;
    const err = new Error(message);
    err.detail = message;
    throw err;
  }
  return response;
}

// แยกชื่อ interface เต็มๆ (เช่น "ge-0/0/1.0") ออกเป็น {interfaceType,
// interfaceId, unit} - Juniper's set_dhcp_relay/remove_dhcp_relay รับ unit เป็น
// int แยกต่างหาก (เหมือน set_dhcp_server_interface/apply_acl_interface) ไม่ได้
// ฝังไว้ใน interfaceId - ชื่อ bare (ไม่มีจุด) ถือเป็น unit 0
function splitBoundInterfaceName(fullName) {
  const { interfaceType, interfaceId } = splitInterfaceName(fullName || "");
  const lastDot = interfaceId.lastIndexOf(".");
  if (lastDot === -1) return { interfaceType, interfaceId, unit: 0 };
  return {
    interfaceType,
    interfaceId: interfaceId.slice(0, lastDot),
    unit: Number(interfaceId.slice(lastDot + 1)) || 0,
  };
}

// ฟอร์มสร้าง/แก้ไข DHCP relay เดี่ยว (ไม่ผ่าน interface form) - เลือก interface
// จาก dropdown (get_interface_list เหมือน InterfacesFormModal) + กรอก DHCP
// server IP แล้วยิง set_dhcp_relay ตรงๆ - Juniper's set_dhcp_relay ผูก interface
// จริงแล้ว (forwarding-options/dhcp-relay/group/interface - ย้ายมาจาก
// forwarding-options/helpers เดิมที่เป็น global scope ดู comment ยาวใน
// juniper_junos.py) interface ที่เลือกในฟอร์มนี้มีผลจริงกับ Juniper แล้ว
//
// โหมด Edit: helper-address (Cisco) และ server name (Juniper) เป็น**list key
// ของตัวเอง** ทั้งคู่ (ไม่ใช่แค่ field ธรรมดา) - เปลี่ยน interface หรือ IP ระหว่าง
// set_dhcp_relay receives the original keys in previous, and updates the IP or
// interface membership in a single edit-config without deleting parent objects.
export default function DhcpRelayFormModal({ devId, vendor, mode = "create", editTarget = null, onClose, onSaved }) {
  const isEdit = mode === "edit" && !!editTarget;
  const [interfaceName, setInterfaceName] = useState(isEdit ? editTarget.interface : "");
  const [helperIp, setHelperIp] = useState(isEdit ? editTarget.server || "" : "");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const { data: ifListData, loading: ifListLoading, error: ifListError } = getDeviceInformation(
    devId,
    "get_interface_list"
  );
  const interfaceOptions = ifListData?.normalized
    ? ifListData.result.map((row) => row.name).filter((name) => (
        vendor !== "juniper" || isJuniperSelectableInterfaceUnit(name)
      ))
    : [];
  const canPickInterface = !ifListError && interfaceOptions.length > 0;

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    if (!interfaceName.trim()) return setError("Please select an interface");
    // IPv4Input ช่วย UX ระหว่างกรอก - ตรวจซ้ำตอน submit แล้วส่งค่า canonical เท่านั้น
    const checkedHelper = validateIPv4Input(helperIp, { mode: "address", required: true });
    if (!checkedHelper.valid) return setError(`DHCP Server IP: ${checkedHelper.error}`);
    const helper = checkedHelper.value;

    const isJuniper = vendor === "juniper";
    const target = isJuniper
      ? splitBoundInterfaceName(interfaceName.trim())
      : splitInterfaceName(interfaceName.trim());

    setSubmitting(true);
    try {
      // (ปัญหาที่ 2 ขั้น B0) ตรวจค่าที่จะใช้สร้างใหม่ให้ผ่านก่อน "แล้วค่อยเริ่มลบ"
      // ไม่งั้นถ้าค่าผิด relay เดิมจะถูกลบไปแล้วโดยไม่มีอะไรมาแทน
      const relayParams = {
        interface_type: target.interfaceType,
        interface_id: target.interfaceId,
        ...(isJuniper ? { unit: target.unit } : {}),
        helper_ip: helper,
      };
      if (isEdit) {
        const old = isJuniper
          ? splitBoundInterfaceName(editTarget.interface)
          : splitInterfaceName(editTarget.interface);
        relayParams.previous = {
          interface_type: old.interfaceType,
          interface_id: old.interfaceId,
          ...(isJuniper ? { unit: old.unit } : {}),
          helper_ip: editTarget.server || "",
        };
      }
      await validateDeviceCommand(devId, "set_dhcp_relay", relayParams);

      assertCommandOk(
        await runDeviceCommand(devId, "set_dhcp_relay", relayParams),
        isEdit ? "Failed to update DHCP relay" : "Failed to create DHCP relay"
      );
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to update DHCP relay" : "Failed to create DHCP relay"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && (
        <div className="command-output-title">
          Edit: {editTarget.interface} -&gt; {editTarget.server || "(no server bound - enter new one below)"}
        </div>
      )}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Interface</label>
        {ifListLoading ? (
          <select disabled value="">
            <option value="">Loading interface list...</option>
          </select>
        ) : canPickInterface ? (
          <select value={interfaceName} onChange={(event) => setInterfaceName(event.target.value)} required>
            <option value="" disabled>-- Select Interface --</option>
            {interfaceOptions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        ) : (
          <input
            type="text"
            placeholder="e.g. GigabitEthernet1"
            value={interfaceName}
            onChange={(event) => setInterfaceName(event.target.value)}
            required
          />
        )}
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label" htmlFor="dhcp-relay-server-ip">DHCP Server IP</label>
        <IPv4Input
          id="dhcp-relay-server-ip"
          label="DHCP Server IP"
          value={helperIp}
          onChange={setHelperIp}
          required
        />
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
