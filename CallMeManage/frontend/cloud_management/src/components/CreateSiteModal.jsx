import DismissibleError from "./DismissibleError";
import { useState } from "react";
import { createSite } from "../api/api_sites";

// หน้า Sites.jsx - ปุ่ม "+ สร้างสาขาใหม่" เปิด modal นี้ - ผู้สร้างได้เป็น Site
// Owner ทันที (backend ผูก site_owner_id = current_user เอง) - org_id ต้อง
// unique ทั้งระบบ (ใช้ค้นหา/ขอ Join - ดู SearchJoinSiteModal.jsx)
export default function CreateSiteModal({ onClose, onCreated }) {
  const [siteName, setSiteName] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    const trimmed = siteName.trim();
    if (trimmed.length < 5 || trimmed.length > 64) {
      setError("Site name must be between 5 and 64 characters");
      return;
    }
    setError("");
    setSubmitting(true);
    try {
      const site = await createSite(trimmed);
      onCreated(site);
    } catch (err) {
      setError(err.detail || "Failed to create site");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <h2>Create New Site</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            &times;
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

          <div className="field">
            <label htmlFor="site-name">Site Name</label>
            <input
              id="site-name"
              type="text"
              placeholder="HQ - Bangkok Data Center"
              value={siteName}
              onChange={(event) => setSiteName(event.target.value)}
              required
              minLength={5}
              maxLength={64}
            />
          </div>

          <div className="modal-actions">
            <button type="button" className="btn btn-ghost" onClick={onClose} disabled={submitting}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? "Creating..." : "Create Site"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
