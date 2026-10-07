import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import IPv4Input from "../../common/IPv4Input";
import { validateIPv4Input } from "../../../utils/ipv4Input";

function ipv4Number(value) {
  return value.split(".").reduce((number, octet) => ((number << 8) | Number(octet)) >>> 0, 0);
}

// โหมด Edit: pre-fill จาก editTarget (แถวที่เลือกจาก addressPool.jsx - {name,
// start, end, netmask})
function buildInitialValues(mode, editTarget) {
  if (mode !== "edit" || !editTarget) {
    return { name: "", start: "", end: "", netmask: "", ranges: [{ start: "", end: "" }] };
  }
  return {
    name: editTarget.name || "",
    start: editTarget.start || "",
    end: editTarget.end || "",
    netmask: editTarget.netmask || "",
    ranges: editTarget.ranges?.length
      ? editTarget.ranges.map((range) => ({ start: range.start || "", end: range.end || "" }))
      : [{ start: editTarget.start || "", end: editTarget.end || "" }],
  };
}

// ฟอร์มสร้าง/แก้ไข NAT pool เดี่ยว (ไม่ผูก interface) - map ไป create_nat_pool
// - netmask เป็นพารามิเตอร์ของ Cisco เท่านั้น (Junos's create_nat_pool ไม่มี
// param นี้เลย) ซ่อนช่อง Netmask ให้ Juniper ไปในตัว
export default function AddressPoolFormModal({ devId, mode = "create", editTarget = null, vendor, onClose, onSaved }) {
  const isEdit = mode === "edit" && !!editTarget;
  const isJuniper = vendor === "juniper";
  const [values, setValues] = useState(buildInitialValues(mode, editTarget));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  function setRangeField(index, field, value) {
    setValues((prev) => ({
      ...prev,
      ranges: prev.ranges.map((range, rangeIndex) => (
        rangeIndex === index ? { ...range, [field]: value } : range
      )),
    }));
  }

  function addRange() {
    setValues((prev) => prev.ranges.length >= 64
      ? prev
      : { ...prev, ranges: [...prev.ranges, { start: "", end: "" }] });
  }

  function removeRange(index) {
    setValues((prev) => ({
      ...prev,
      ranges: prev.ranges.filter((_, rangeIndex) => rangeIndex !== index),
    }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    if (!values.name.trim()) return setError("Please enter a Pool Name");
    if (isJuniper) {
      const starts = new Set();
      for (const [index, range] of values.ranges.entries()) {
        const startResult = validateIPv4Input(range.start, { mode: "address" });
        const endResult = validateIPv4Input(range.end, { mode: "address", required: false });
        if (!startResult.valid) {
          return setError(`Please enter a valid Start Address for range ${index + 1}`);
        }
        if (!endResult.valid) {
          return setError(`Please enter a valid End Address for range ${index + 1}`);
        }
        if (endResult.value && ipv4Number(endResult.value) < ipv4Number(startResult.value)) {
          return setError(`End Address for range ${index + 1} must be greater than or equal to Start Address`);
        }
        const start = startResult.value;
        if (starts.has(start)) return setError(`Duplicate Start Address ${start}`);
        starts.add(start);
      }
    } else {
      const startResult = validateIPv4Input(values.start, { mode: "address" });
      const endResult = validateIPv4Input(values.end, { mode: "address" });
      if (!startResult.valid) return setError("Please enter a valid Start Address, e.g. 203.0.113.10");
      if (!endResult.valid) return setError("Please enter a valid End Address, e.g. 203.0.113.20");
      if (ipv4Number(endResult.value) < ipv4Number(startResult.value)) {
        return setError("End Address must be greater than or equal to Start Address");
      }
    }
    const maskResult = isJuniper
      ? null
      : validateIPv4Input(values.netmask, { mode: "subnet" });
    if (maskResult && !maskResult.valid) return setError("Please enter a valid Netmask, e.g. 255.255.255.0");

    const params = { name: values.name.trim() };
    if (isJuniper) {
      params.address_starts = values.ranges.map((range) => (
        validateIPv4Input(range.start, { mode: "address" }).value
      ));
      params.address_ends = values.ranges.map((range) => (
        validateIPv4Input(range.end, { mode: "address", required: false }).value
      ));
    } else {
      params.start = validateIPv4Input(values.start, { mode: "address" }).value;
      params.end = validateIPv4Input(values.end, { mode: "address" }).value;
      params.netmask = maskResult.value;
    }
    if (isEdit) {
      params.replace_name = editTarget.name;
      if (isJuniper) {
        const originalRanges = editTarget.ranges?.length
          ? editTarget.ranges
          : [{ start: editTarget.start, startKey: editTarget.startKey }];
        params.replace_starts = originalRanges.map((range) => range.startKey || range.start);
      } else {
        params.replace_mask_mode = editTarget.maskMode || "netmask";
      }
    }

    setSubmitting(true);
    try {
      // ชื่อ pool เป็น key และอาจถูก NAT rule อ้างอิงอยู่ จึงล็อกชื่อระหว่าง Edit
      // แล้วให้ translator แทนค่าภายใน pool เดิมใน RPC เดียว
      await validateDeviceCommand(devId, "create_nat_pool", params);
      await runDeviceCommand(devId, "create_nat_pool", params);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit NAT pool" : "Failed to create NAT pool"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && <div className="command-output-title">Edit: {editTarget.name}</div>}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Pool Name</label>
        <input
          type="text"
          placeholder="NAT_POOL_1"
          value={values.name}
          onChange={(event) => setField("name", event.target.value)}
          disabled={isEdit}
          required
        />
      </div>

      {isJuniper ? values.ranges.map((range, index) => (
        <div className="interface-configuration-form-field-third" key={index}>
          <label className="data-label">Address Range {index + 1}</label>
          <div className="nat-pool-range-inputs">
            <IPv4Input
              label={`Start Address ${index + 1}`}
              value={range.start}
              onChange={(value) => setRangeField(index, "start", value)}
              required
            />
            <IPv4Input
              label={`End Address ${index + 1}`}
              value={range.end}
              onChange={(value) => setRangeField(index, "end", value)}
            />
          </div>
          {index === 0 ? (
            <button
              type="button"
              className="mini-btn btn-ghost"
              disabled={values.ranges.length >= 64}
              onClick={addRange}
              aria-label="Add Address Range"
            >+</button>
          ) : (
            <button
              type="button"
              className="mini-btn btn-ghost"
              onClick={() => removeRange(index)}
              aria-label={`Delete Address Range ${index + 1}`}
            >-</button>
          )}
        </div>
      )) : (
        <>
          <div className="interface-configuration-form-field">
            <label className="data-label">Start Address</label>
            <IPv4Input
              label="Start Address"
              value={values.start}
              onChange={(value) => setField("start", value)}
              required
            />
          </div>

          <div className="interface-configuration-form-field">
            <label className="data-label">End Address</label>
            <IPv4Input
              label="End Address"
              value={values.end}
              onChange={(value) => setField("end", value)}
              required
            />
          </div>
        </>
      )}

      {!isJuniper && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Netmask</label>
          <IPv4Input
            label="Netmask"
            mode="subnet"
            value={values.netmask}
            onChange={(value) => setField("netmask", value)}
            required
          />
        </div>
      )}

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
