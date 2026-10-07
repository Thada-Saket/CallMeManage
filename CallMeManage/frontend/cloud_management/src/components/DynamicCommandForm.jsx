import { useState } from "react";

function defaultValueFor(parameter) {
  if (parameter.type === "bool") return Boolean(parameter.default);
  if (parameter.default === null || parameter.default === undefined) {
    // select ไม่มี default มาให้ -> ตั้งเป็นตัวเลือกแรกไปก่อน กัน <select> โผล่ค่าว่าง
    if (parameter.type === "select" && parameter.choices?.length) {
      return String(parameter.choices[0]);
    }
    return "";
  }
  return Array.isArray(parameter.default) ? parameter.default.join(", ") : String(parameter.default);
}

// ฟอร์ม config แบบ auto-generate จาก schema ที่ backend introspect มาให้
// (GET /devices/{dev_id}/commands -> translator_service.functions_for_vendor()) -
// เรียก key={command.name} ตอน render จาก parent เพื่อให้ state รีเซ็ตทุกครั้งที่
// สลับคำสั่ง ไม่งั้นค่าจากฟอร์มก่อนหน้าจะค้างอยู่
export default function DynamicCommandForm({ command, onSubmit, submitting }) {
  const [values, setValues] = useState(() => {
    const initial = {};
    for (const parameter of command.parameters) {
      initial[parameter.name] = defaultValueFor(parameter);
    }
    return initial;
  });

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  function handleSubmit(event) {
    event.preventDefault();
    const payload = {};
    for (const parameter of command.parameters) {
      const raw = values[parameter.name];
      if (parameter.type === "bool") {
        payload[parameter.name] = Boolean(raw);
        continue;
      }
      if (raw === "" || raw === undefined || raw === null) {
        // ไม่กรอก -> ไม่ส่ง key นี้เลย ปล่อยให้ default ของฟังก์ชันฝั่ง backend ทำงานแทน
        continue;
      }
      if (parameter.type === "list") {
        payload[parameter.name] = raw
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean);
        continue;
      }
      payload[parameter.name] = raw;
    }
    onSubmit(payload);
  }

  return (
    <form className="form" onSubmit={handleSubmit}>
      {command.parameters.length === 0 && (
        <div className="config-placeholder">This command does not require any additional parameters.</div>
      )}

      {command.parameters.map((parameter) => (
        <div className="field" key={parameter.name}>
          <label htmlFor={`param-${command.name}-${parameter.name}`}>
            {parameter.name}
            {parameter.required && " *"}
            {parameter.type === "list" && " (comma-separated)"}
          </label>
          {parameter.type === "bool" ? (
            <input
              id={`param-${command.name}-${parameter.name}`}
              type="checkbox"
              checked={Boolean(values[parameter.name])}
              onChange={(event) => setField(parameter.name, event.target.checked)}
            />
          ) : parameter.type === "select" ? (
            <select
              id={`param-${command.name}-${parameter.name}`}
              value={values[parameter.name] ?? ""}
              onChange={(event) => setField(parameter.name, event.target.value)}
              required={parameter.required}
            >
              {!parameter.required && <option value="">(None)</option>}
              {parameter.choices.map((choice) => (
                <option key={choice} value={choice}>
                  {choice}
                </option>
              ))}
            </select>
          ) : (
            <input
              id={`param-${command.name}-${parameter.name}`}
              type="text"
              value={values[parameter.name] ?? ""}
              placeholder={
                parameter.default !== null && parameter.default !== undefined
                  ? String(parameter.default)
                  : ""
              }
              onChange={(event) => setField(parameter.name, event.target.value)}
              required={parameter.required}
            />
          )}
        </div>
      ))}

      <div className="modal-actions">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Submitting..." : "OK"}
        </button>
      </div>
    </form>
  );
}
