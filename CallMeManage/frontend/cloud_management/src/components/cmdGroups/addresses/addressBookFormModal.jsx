import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import IPv4Input from "../../common/IPv4Input";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { validateIPPrefixInput } from "../../../utils/ipPrefixInput";

// โหมด Edit: pre-fill จาก editTarget (แถวที่เลือกจาก addressBook.jsx - {name, ip})
function buildInitialValues(mode, editTarget) {
  if (mode !== "edit" || !editTarget) {
    return { name: "", address: "" };
  }
  return { name: editTarget.name || "", address: editTarget.ip || "" };
}

// set_address_book_entry(name, address) - "name" เป็น key จริงของ list
// security/address-book[global]/address (ตรงกับ VLAN's vlan_name) - ล็อกแก้ไม่ได้
// ตอน edit เหมือน pattern เดียวกับ vlanFormModal.jsx (เปลี่ยนชื่อ = สร้างใหม่
// ตัวเก่าค้างเป็น orphan) ต่างจาก VLAN ตรงที่ merge เข้า IP เดิมได้ตรงๆ ไม่ต้อง
// remove ก่อน (leaf ip-prefix เดี่ยวๆ ใต้ key เดิม overwrite ได้เลย)
export default function AddressBookFormModal({ devId, mode = "create", editTarget = null, onClose, onSaved }) {
  const isEdit = mode === "edit" && !!editTarget;
  const [values, setValues] = useState(buildInitialValues(mode, editTarget));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [addressTouched, setAddressTouched] = useState(false);

  // ช่อง IP Address/CIDR ใช้ IPv4Input (address/prefix ตัวเดียวกับหน้า Interfaces/Tunnel) - กรอกได้เฉพาะ IPv4
  // + prefix 0-32 ตั้งแต่พิมพ์ **ยกเว้น entry เดิมบนอุปกรณ์ที่เป็น IPv6** (ตั้งจาก CLI/ติดมาก่อน onboard): ต้องแก้ต่อได้
  // ตามจริง จึงเก็บช่องข้อความ + ตัวตรวจ IPv6 ไว้เฉพาะกรณีนั้น ส่วน entry ใหม่สร้างได้เฉพาะ IPv4/prefix
  const isLegacyIpv6 = isEdit && String(editTarget.ip || "").includes(":");
  const addressValidation = validateIPPrefixInput(values.address);

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    const name = values.name.trim();
    if (!name) return setError("Please enter a Name");

    // IPv4: ต้องมี prefix ครบ (IPv4Input cidr) แล้ว normalize เป็น network address เหมือนเดิม (10.0.0.5/24 -> 10.0.0.0/24)
    // ก่อนส่ง ซึ่งตรงกับที่ backend ทำอยู่ - ประวัติจึงบันทึกค่าเดียวกับที่ลงอุปกรณ์จริง
    const typed = isLegacyIpv6
      ? validateIPPrefixInput(values.address)
      : validateIPv4Input(values.address, { mode: "cidr" });
    if (!typed.valid) {
      setAddressTouched(true);
      return setError(typed.error);
    }
    const checkedAddress = validateIPPrefixInput(typed.value);

    const params = { name, address: checkedAddress.value };
    if (isEdit) params.replace_name = editTarget.name;

    setSubmitting(true);
    try {
      await runDeviceCommand(devId, "set_address_book_entry", params);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit Address" : "Failed to create Address"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && <div className="command-output-title">Edit: {editTarget.name}</div>}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Name</label>
        <input
          type="text"
          placeholder="SERVER-1"
          value={values.name}
          onChange={(event) => setField("name", event.target.value)}
          disabled={isEdit}
          required
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">IP Address/CIDR</label>
        {isLegacyIpv6 ? (
          <>
            <input
              type="text"
              placeholder="2001:db8::/64"
              value={values.address}
              onChange={(event) => setField("address", event.target.value)}
              onBlur={() => setAddressTouched(true)}
              onInvalid={() => setAddressTouched(true)}
              aria-invalid={addressTouched && !addressValidation.valid}
              className={addressTouched && !addressValidation.valid ? "ip-input-invalid" : ""}
              title={addressTouched && !addressValidation.valid ? addressValidation.error : ""}
              required
            />
            <span className="field-hint">
              This entry is an existing IPv6 address on the device and can be edited as IPv6/prefix - this form only creates new entries as IPv4/prefix.
            </span>
          </>
        ) : (
          <IPv4Input
            id="address-book-address"
            mode="cidr"
            label="IP Address/CIDR"
            value={values.address}
            onChange={(value) => setField("address", value)}
            required
          />
        )}
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
