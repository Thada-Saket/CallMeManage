/**
 * Shared error banner that can be dismissed without leaving the current page.
 * Dismissal is controlled by the owner of the error so hiding the banner also
 * clears the state that may be gating a form. Safety/blocking errors can omit
 * onDismiss and remain visible without presenting a misleading close button.
 */
export default function DismissibleError({ message, onDismiss, className = "", style }) {
  if (message === null || message === undefined || message === "") {
    return null;
  }

  return (
    <div
      className={`form-error dismissible-error ${className}`.trim()}
      style={style}
      role="alert"
    >
      <span className="dismissible-error-message">{message}</span>
      {onDismiss && (
        <button
          type="button"
          className="dismissible-error-close"
          aria-label="Dismiss error"
          title="Dismiss"
          onClick={onDismiss}
        >
          &times;
        </button>
      )}
    </div>
  );
}
