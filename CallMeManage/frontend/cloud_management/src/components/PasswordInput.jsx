import { useState } from "react";

const EYE = (
  <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
    <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
    <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" strokeWidth="1.8" />
  </svg>
);

const EYE_OFF = (
  <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
    <path d="M10.6 5.1A10.4 10.4 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.1M6.6 6.6C3.7 8.4 2 12 2 12s3.6 7 10 7a9.7 9.7 0 0 0 5.4-1.6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2M3 3l18 18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
  </svg>
);

/**
 * Password field with an eye button that shows or hides what was typed.
 * All other props (id, value, onChange, autoComplete, ref, ...) go to the input.
 */
export default function PasswordInput({ className = "", ...inputProps }) {
  const [visible, setVisible] = useState(false);

  return (
    <div className="password-input">
      <input {...inputProps} className={className} type={visible ? "text" : "password"} />
      <button
        type="button"
        className="password-input-toggle"
        onClick={() => setVisible((current) => !current)}
        aria-label={visible ? "Hide password" : "Show password"}
        aria-pressed={visible}
        title={visible ? "Hide password" : "Show password"}
      >
        {visible ? EYE_OFF : EYE}
      </button>
    </div>
  );
}
