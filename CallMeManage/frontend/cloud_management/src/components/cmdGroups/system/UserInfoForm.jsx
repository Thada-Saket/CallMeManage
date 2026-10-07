import DismissibleError from "../../DismissibleError";
import { useRef, useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import { HelpHint, PasswordPolicyHint } from "../../FieldHelp";
import {
  PRIVILEGE_OPTIONS,
  USERNAME_HINT,
  buildUserCommand,
  evaluateUserForm,
  initialUserForm,
  passwordChecks,
} from "../../../utils/localUsers.js";

function errorMessage(err, fallback) {
  const detail = err?.detail;
  if (detail && typeof detail === "object") return detail.message || fallback;
  return detail || fallback;
}

// New/Edit ของ User Info - username เป็น identity ที่แก้ไม่ได้ตอน Edit ; รหัสผ่านอยู่ใน state นี้เท่านั้น
// (ไม่ prefill, ไม่อ่านจากอุปกรณ์, หายไปพร้อม component เมื่อปิดฟอร์ม)
export default function UserInfoForm({ devId, vendor, mode, target, existingUsers, onSaved, onClose }) {
  const isEdit = mode === "edit";
  const [values, setValues] = useState(() => initialUserForm(mode, target));
  const [touched, setTouched] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const inFlight = useRef(false);

  const { errors, canSubmit } = evaluateUserForm({ mode, target, values, existingUsers });
  const showError = (field) => (touched[field] || touched.submit) && errors[field];
  const checks = passwordChecks(values.password);
  const passwordInvalid = Boolean(values.password) && Boolean(errors.password);

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
    setTouched((prev) => ({ ...prev, [name]: true }));
  }

  function handleCancel() {
    setValues((prev) => ({ ...prev, password: "", confirmPassword: "" }));
    onClose();
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setTouched((prev) => ({ ...prev, submit: true }));
    if (!canSubmit || inFlight.current) return;
    inFlight.current = true;
    setSubmitting(true);
    setError("");
    try {
      const { command, parameters } = buildUserCommand({ mode, vendor, target, values });
      await runDeviceCommand(devId, command, parameters);
      setValues((prev) => ({ ...prev, password: "", confirmPassword: "" }));
      onSaved();
    } catch (err) {
      setError(errorMessage(err, isEdit ? "Failed to update local user" : "Failed to create local user"));
    } finally {
      inFlight.current = false;
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form user-info-form" onSubmit={handleSubmit} noValidate>
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
      {isEdit && <div className="command-output-title">Edit: {target?.username}</div>}

      <div className="interface-configuration-form-field">
        <div className="field-label-with-hint data-label">
          <label htmlFor="user-info-username">Username</label>
          <HelpHint label="Show username requirements" invalid={Boolean(showError("username"))}>
            {USERNAME_HINT}
          </HelpHint>
        </div>
        <div className="user-info-input">
          <input
            id="user-info-username"
            type="text"
            value={values.username}
            onChange={(event) => setField("username", event.target.value)}
            readOnly={isEdit}
            disabled={isEdit || submitting}
            autoComplete="off"
            maxLength={32}
            required={!isEdit}
          />
          {!isEdit && showError("username") && <div className="user-info-field-error">{errors.username}</div>}
        </div>
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label" htmlFor="user-info-privilege">Privilege</label>
        <div className="user-info-input">
          <select
            id="user-info-privilege"
            value={values.privilege}
            onChange={(event) => setField("privilege", event.target.value)}
            disabled={submitting}
            required={!isEdit}
          >
            {isEdit && !target?.privilege && <option value="">Keep current (unrecognized)</option>}
            {PRIVILEGE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
          {showError("privilege") && <div className="user-info-field-error">{errors.privilege}</div>}
        </div>
      </div>

      <div className="interface-configuration-form-field">
        <div className="field-label-with-hint data-label">
          <label htmlFor="user-info-password">Password</label>
          <PasswordPolicyHint checks={checks} invalid={passwordInvalid} />
        </div>
        <div className="user-info-input">
          <input
            id="user-info-password"
            type="password"
            value={values.password}
            onChange={(event) => setField("password", event.target.value)}
            placeholder={isEdit ? "Leave blank to keep current" : ""}
            autoComplete="new-password"
            disabled={submitting}
            required={!isEdit}
          />
          {showError("password") && <div className="user-info-field-error">{errors.password}</div>}
        </div>
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label" htmlFor="user-info-confirm-password">Confirm Password</label>
        <div className="user-info-input">
          <input
            id="user-info-confirm-password"
            type="password"
            value={values.confirmPassword}
            onChange={(event) => setField("confirmPassword", event.target.value)}
            placeholder={isEdit ? "Leave blank to keep current" : ""}
            autoComplete="new-password"
            disabled={submitting}
            required={!isEdit || Boolean(values.password)}
          />
          {showError("confirmPassword") && <div className="user-info-field-error">{errors.confirmPassword}</div>}
        </div>
      </div>

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={!canSubmit || submitting}>
          {submitting ? "Applying..." : "Apply"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={handleCancel} disabled={submitting}>
          Cancel
        </button>
      </div>
    </form>
  );
}
