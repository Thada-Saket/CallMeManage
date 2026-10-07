import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";

export default function SignOutConfirmModal({ signingOut, onCancel, onConfirm }) {
  const cancelBtnRef = useRef(null);

  useEffect(() => {
    // Focus Cancel button by default on open for safety
    if (cancelBtnRef.current) {
      cancelBtnRef.current.focus();
    }
  }, []);

  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === "Escape" && !signingOut) {
        onCancel();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [signingOut, onCancel]);

  function handleBackdropClick(event) {
    if (event.target === event.currentTarget && !signingOut) {
      onCancel();
    }
  }

  function handleClose() {
    if (!signingOut) {
      onCancel();
    }
  }

  const modalContent = (
    <div className="modal-overlay" onClick={handleBackdropClick} role="presentation">
      <div
        className="modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="sign-out-dialog-title"
        aria-describedby="sign-out-dialog-desc"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-header">
          <h2 id="sign-out-dialog-title">Confirm Sign Out</h2>
          <button
            type="button"
            className="modal-close"
            onClick={handleClose}
            aria-label="Close"
            disabled={signingOut}
          >
            &times;
          </button>
        </div>

        <p id="sign-out-dialog-desc">
          Are you sure you want to sign out?
        </p>

        <div className="modal-actions">
          <button
            type="button"
            ref={cancelBtnRef}
            className="btn btn-ghost"
            onClick={handleClose}
            disabled={signingOut}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={onConfirm}
            disabled={signingOut}
          >
            {signingOut ? "Signing Out..." : "Sign Out"}
          </button>
        </div>
      </div>
    </div>
  );

  if (typeof document !== "undefined" && document.body) {
    return createPortal(modalContent, document.body);
  }

  return modalContent;
}
