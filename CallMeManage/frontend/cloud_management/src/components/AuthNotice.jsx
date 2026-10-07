import { useEffect, useRef } from "react";

const ICONS = {
  warning: (
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
      <path d="M12 3 2 21h20L12 3Z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
      <path d="M12 10v5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <circle cx="12" cy="18" r="1.2" fill="currentColor" />
    </svg>
  ),
  success: (
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
      <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="2" />
      <path d="m7.5 12.5 3 3 6-6.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
};

/**
 * Prominent notice shown when the page changes because of what happened
 * (e.g. "This email is already in use" moves the user to Sign In). It slides
 * in, glows once, and is announced to screen readers so the change of page
 * is not missed. `noticeKey` replays the animation for a repeated notice.
 */
export default function AuthNotice({ tone = "warning", title, children, onDismiss, noticeKey }) {
  const ref = useRef(null);

  useEffect(() => {
    ref.current?.scrollIntoView?.({ block: "nearest", behavior: "smooth" });
  }, [noticeKey]);

  return (
    <div
      key={noticeKey}
      ref={ref}
      className={`auth-notice auth-notice-${tone}`}
      role={tone === "warning" ? "alert" : "status"}
    >
      <span className="auth-notice-icon">{ICONS[tone]}</span>
      <div className="auth-notice-body">
        <strong className="auth-notice-title">{title}</strong>
        {children && <p className="auth-notice-text">{children}</p>}
      </div>
      {onDismiss && (
        <button type="button" className="auth-notice-close" aria-label="Dismiss notice" onClick={onDismiss}>
          &times;
        </button>
      )}
    </div>
  );
}
