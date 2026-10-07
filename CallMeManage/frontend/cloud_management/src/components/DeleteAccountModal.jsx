import DismissibleError from "./DismissibleError";
import { useState } from "react";
import { deleteMyAccount } from "../api/api_users";

// ปุ่ม "ลบบัญชี" ใน AccountSettings.jsx - ยืนยันซ้ำก่อนลบจริงเสมอ (การกระทำ
// ย้อนกลับไม่ได้) - backend คืน 400 พร้อมข้อความอธิบายชัดเจนถ้ายังเป็นเจ้าของ
// สาขาอยู่ (ApiError.detail) - โชว์ inline แทนที่จะปิด modal ทันที ให้ผู้ใช้
// เห็นเหตุผลและไปจัดการสาขาก่อนได้
export default function DeleteAccountModal({ onClose, onDeleted }) {
  const [error, setError] = useState("");
  const [deleting, setDeleting] = useState(false);

  async function handleConfirm() {
    setError("");
    setDeleting(true);
    try {
      await deleteMyAccount();
      onDeleted();
    } catch (err) {
      setError(err.detail || "Failed to delete account");
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <h1 style={{color: "red"}}>Irreversible Action</h1>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            &times;
          </button>
        </div>

        <p>
          Deleting your account is <strong>irreversible</strong>. All site memberships, registered devices, and workspaces associated with your account will be permanently deleted and become inaccessible. You will no longer be able to sign in with this account.
        </p>

        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

        <div className="modal-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose} disabled={deleting}>
            Cancel
          </button>
          <button type="button" className="btn btn-danger" onClick={handleConfirm} disabled={deleting}>
            {deleting ? "Deleting..." : "Confirm Delete Account"}
          </button>
        </div>
      </div>
    </div>
  );
}
