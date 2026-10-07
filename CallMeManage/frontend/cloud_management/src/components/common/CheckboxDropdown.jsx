import { useEffect, useRef, useState } from "react";

/**
 * Multi-select checkbox dropdown (native <details> markup, open state controlled).
 * Owns only open/close behaviour: the parent keeps the selected values and the checkbox
 * onChange. Closes on outside pointer-down, focus moving outside, or Escape (focus returns
 * to the summary). Document listeners exist only while open and are removed on close/unmount.
 * Children are the options container, e.g. <div className="zone-interface-picker-options">.
 */
export default function CheckboxDropdown({ ariaLabel, summary, className = "", disabled = false, title, children }) {
  const rootRef = useRef(null);
  const summaryRef = useRef(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (disabled && open) setOpen(false);
  }, [disabled, open]);

  useEffect(() => {
    if (!open) return undefined;
    const isOutside = (event) => !rootRef.current?.contains(event.target);
    const closeIfOutside = (event) => {
      if (isOutside(event)) setOpen(false);
    };
    const closeOnEscape = (event) => {
      if (event.key !== "Escape") return;
      setOpen(false);
      summaryRef.current?.focus();
    };
    document.addEventListener("pointerdown", closeIfOutside);
    document.addEventListener("focusin", closeIfOutside);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeIfOutside);
      document.removeEventListener("focusin", closeIfOutside);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [open]);

  return (
    <details
      ref={rootRef}
      className={`zone-interface-picker${disabled ? " is-disabled" : ""} ${className}`.trim()}
      open={disabled ? false : open}
      title={title}
    >
      <summary
        ref={summaryRef}
        aria-label={ariaLabel}
        aria-expanded={disabled ? false : open}
        aria-disabled={disabled || undefined}
        tabIndex={disabled ? -1 : undefined}
        onClick={(event) => {
          // native toggle is replaced by controlled state (keyboard Enter/Space also fire click)
          event.preventDefault();
          if (disabled) return;
          setOpen((current) => !current);
        }}
      >
        {summary}
      </summary>
      {children}
    </details>
  );
}
