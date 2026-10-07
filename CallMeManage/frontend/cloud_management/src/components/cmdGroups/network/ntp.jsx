import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { runDeviceTransaction } from "../../../api/api_devices";
import { applyNtpChanges, parseNtpResult } from "../../../utils/ntpCommands";
import { checkIPv4List } from "../../../utils/ipv4List";
import NtpForm from "./ntpFormModal";

const MAX_NTP_SERVERS = 5;

export default function Ntp({ devId, vendor }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_ntp_information");
  const [values, setValues] = useState(null);
  const [applying, setApplying] = useState(false);
  const [applyError, setApplyError] = useState("");
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    // A background reconciliation after a failed write may return while the
    // user is correcting the form. Keep that draft intact; only hydrate from
    // the device initially, after success, or after an explicit Refresh.
    if (data?.normalized) {
      setValues((current) => (
        current === null || !dirty
          ? { servers: parseNtpResult(data.result) }
          : current
      ));
    }
  }, [data, dirty]);

  async function handleApply() {
    setApplyError("");

    // IPv4Input ช่วย UX ระหว่างกรอก - ตรวจซ้ำตอน submit กัน state จาก prefill/เรียก handler ตรง
    // ช่องว่างทั้งหมด = ลบ NTP ทั้งหมด (optional) แต่แถวที่กรอกไม่ครบต้องไม่ถูกส่ง
    const checked = checkIPv4List(values.servers, {
      label: (index) => `NTP Server ${index + 1}`,
      duplicateMessage: "NTP servers must be unique",
    });
    if (!checked.ok) {
      setApplyError(checked.error);
      return;
    }
    const requestedServers = checked.values;
    if (requestedServers.length > MAX_NTP_SERVERS) {
      setApplyError(`Can configure up to ${MAX_NTP_SERVERS} NTP servers`);
      return;
    }

    setApplying(true);
    try {
      await applyNtpChanges({
        devId,
        vendor,
        result: data?.result,
        requestedServers,
        runTransaction: runDeviceTransaction,
      });

      await refetch();
      setDirty(false);
    } catch (err) {
      setApplyError(err.detail || "Failed to configure NTP");
      // runDeviceTransaction ส่ง device:state-changed เมื่อ write ล้มเหลว และ
      // getDeviceInformation จะ refetch ให้ครั้งเดียวอยู่แล้ว ห้ามเรียกซ้ำตรงนี้
      // เพราะสองคำสั่งอ่านพร้อมกันอาจแย่ง DeviceLock และทำให้ request ล่าสุดได้ 409
    } finally {
      setApplying(false);
    }
  }

  function handleRefresh() {
    setApplyError("");
    setDirty(false);
    refetch();
  }

  if (loading && !data) return <div className="center-loading">Fetching NTP data...</div>;
  if (error && !data) {
    return (
      <div className="command-configuration">
        <DismissibleError message={error} onDismiss={() => { clearError(); refetch(); }} />
        <button type="button" className="btn btn-ghost" onClick={refetch}>Retry</button>
      </div>
    );
  }

  if (data && !data.normalized) {
    return (
      <div className="command-configuration">
        <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
      </div>
    );
  }

  if (!values) return null;

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}
      <NtpForm
        values={values}
        setServers={(servers) => {
          setDirty(true);
          setValues({ servers });
        }}
        onApply={handleApply}
        applying={applying}
        error={applyError}
        onDismissError={() => setApplyError("")}
        loading={loading}
        onRefresh={handleRefresh}
      />
    </div>
  );
}
