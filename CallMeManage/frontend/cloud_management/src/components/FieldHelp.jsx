// "?" hint หลัง label (hover/focus เปิด tooltip ทางขวา) - markup เดียวกับ HelpHint/PasswordPolicyHint
// ใน pages/CliGenerator.jsx (ไม่ย้ายของเดิมมาที่นี่เพราะ test_local_administrator_ui.mjs ตรวจ source หน้านั้นตรง ๆ)
// สไตล์อยู่ที่ .field-help* ใน App.css
export function HelpHint({ label, invalid = false, children }) {
  return (
    <span className={`field-help${invalid ? " field-help-invalid" : ""}`}>
      <button type="button" className="field-help-trigger" aria-label={label}>?</button>
      <span className="field-help-tooltip" role="tooltip">{children}</span>
    </span>
  );
}

// checks = passwordChecks(password) จาก utils/localAdmin.js
export function PasswordPolicyHint({ checks, invalid = false }) {
  return (
    <HelpHint
      label={invalid ? "Password does not meet all requirements" : "Show password requirements"}
      invalid={invalid}
    >
      <strong>{invalid ? "Password does not meet all requirements" : "Password requirements"}</strong>
      <ul className="field-help-list">
        {checks.map((check) => (
          <li key={check.label} className={check.passed ? "hint-rule-pass" : "hint-rule-fail"}>
            <span aria-hidden="true">{check.passed ? "✓" : "○"}</span> {check.label}
          </li>
        ))}
      </ul>
    </HelpHint>
  );
}
