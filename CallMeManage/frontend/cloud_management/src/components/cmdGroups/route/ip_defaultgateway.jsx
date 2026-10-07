import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";

// อ่านค่า ip default-gateway จาก reply ของ get_ip_default_gateway ที่
// native/ip/default-gateway คืนสตริงว่างเมื่ออุปกรณ์ยังไม่ได้ตั้งค่านี้ไว้
function parseDefaultGateway(result) {
  const value = result?.payload?.data?.native?.ip?.["default-gateway"];
  return typeof value === "string" ? value.trim() : "";
}

function isValidIpv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

// Cisco เท่านั้น - เมนูซ่อนหน้านี้จาก Huawei/Juniper ด้วย unsupportedVendors
//
// ip default-gateway เป็นค่า global ค่าเดียวทั้งอุปกรณ์ จึงเป็นแถวเดียว: ชื่อค่า,
// ช่องกรอกที่ดึงค่าปัจจุบันจากอุปกรณ์มาใส่ไว้ และปุ่ม Apply หลังบันทึกจะโหลดค่าใหม่
// จากอุปกรณ์เสมอ ช่องกรอกจึงสะท้อนสิ่งที่อยู่บนอุปกรณ์จริง
export default function IPDefaultGateway({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_ip_default_gateway");
  const deviceGateway = data?.normalized ? parseDefaultGateway(data.result) : "";
  const [gateway, setGateway] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");

  // เติมค่าจากอุปกรณ์ลงช่องทุกครั้งที่โหลดเสร็จ รวมถึงหลัง Apply
  useEffect(() => {
    setGateway(deviceGateway);
  }, [deviceGateway]);

  const trimmed = gateway.trim();
  const unchanged = trimmed === deviceGateway;
  const invalid = trimmed !== "" && !isValidIpv4(trimmed);

  async function handleApply(event) {
    event.preventDefault();
    setSaveError("");
    if (!trimmed) {
      setSaveError("Please enter default-gateway");
      return;
    }
    if (invalid) {
      setSaveError("default-gateway must be an IPv4 address, e.g. 192.168.1.1");
      return;
    }
    setSaving(true);
    try {
      await runDeviceCommand(devId, "set_ip_default_gateway", { ip: trimmed });
      refetch();
    } catch (err) {
      setSaveError(err.detail || "Failed to configure default-gateway");
    } finally {
      setSaving(false);
    }
  }

  if (loading && !data) {
    return <div className="center-loading">Loading default-gateway data...</div>;
  }

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}
      {saveError && <DismissibleError message={saveError} onDismiss={() => setSaveError("")} />}

      <form className="interface-configuration-form" onSubmit={handleApply}>
        <div className="interface-configuration-form-field-third">
          <label className="data-label" htmlFor="ip-default-gateway">default-gateway</label>
          <input
            id="ip-default-gateway"
            type="text"
            placeholder="192.168.1.1"
            value={gateway}
            onChange={(event) => setGateway(event.target.value)}
            disabled={saving}
          />
          <button type="submit" className="btn btn-primary" disabled={saving || loading || unchanged || invalid}>
            {saving ? "Applying..." : "Apply"}
          </button>
        </div>
      </form>
    </div>
  );
}
