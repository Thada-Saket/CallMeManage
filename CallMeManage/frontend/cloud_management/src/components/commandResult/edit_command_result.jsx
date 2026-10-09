import DismissibleError from "../DismissibleError";
import { Reload_Result } from "./reload_command_result"
// ปุ่ม New/Edit/Delete + confirm-delete modal ที่ทุกหน้า (VLAN/Static NAT/Port
// Forward/Firewall/Security Profile/Security Tunnel/Interfaces ฯลฯ) มีโครง
// เหมือนกันทุกตัวอักษร (className="modal-overlay"/"modal-card"/"modal-header"
// เดิม) ต่างกันแค่ชื่อฟีเจอร์ในหัวข้อ, สิ่งที่กำลังจะถูกลบ, ข้อความเตือนเพิ่ม
// (ถ้ามี), และ handler ที่แต่ละหน้าผูก logic ของตัวเอง (เรียก remove_*
// คนละฟังก์ชันคนละ param) - component นี้ไม่รู้เลยว่าหน้าไหนลบอะไรจริงๆ
// รับแค่ค่า/callback มาแสดงผล
function Edit_Result({
  featureName,
  selectedLabel,
  extraWarning,
  canEdit,
  editDisabledReason = "",
  canDelete,
  deleteDisabledReason = "",
  showDeleteConfirm,
  deleting,
  deleteError,
  onDismissDeleteError,
  onNew,
  onEditClick,
  onOpenDeleteConfirm,
  onCancelDelete,
  onConfirmDelete,
  refreshing = false,
  onRefresh,
  // ปุ่ม/ปุ่มยืนยันปกติเขียนว่า "Delete"/"กำลังลบ.../ลบ" ตรงตัว - บาง caller
  // (เช่น interfaces.jsx's clear-IP บน physical interface Cisco) ใช้ handler
  // เดียวกันนี้กับ action ที่ไม่ใช่การลบจริงๆ (แค่ล้างค่า ไม่ลบ interface) เลย
  // เปิดให้ override ข้อความได้ - default เดิมทุกตัวไม่ต้องแก้อะไร
  deleteLabel = "Delete",
  deletingLabel = "Deleting...",
  confirmLabel = "Delete",
  // ข้อความใต้ปุ่มระหว่างลบ (เช่น Cisco NAT ที่อุปกรณ์ต่อใหม่ชั่วครู่ ทำให้รอนาน)
  deletingHint = "",
}) {
  return (
    <>
      <div className="command-action-buttons">
        <button type="button" className="btn btn-primary" onClick={onNew}>
          New
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={!canEdit}
          onClick={onEditClick}
          title={!canEdit ? editDisabledReason : undefined}
        >
          Edit
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={!canDelete}
          onClick={onOpenDeleteConfirm}
          title={!canDelete ? deleteDisabledReason : undefined}
        >
          {deleteLabel}
        </button>
      </div>

      <Reload_Result loading={refreshing} onRefresh={onRefresh}/>

      {showDeleteConfirm && (
        <div className="modal-overlay" onClick={() => !deleting && onCancelDelete()}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Confirm Deletion of {featureName}</h2>
              <button
                type="button"
                className="modal-close"
                onClick={onCancelDelete}
                aria-label="Close"
                disabled={deleting}
              >
                &times;
              </button>
            </div>
            <p>
              Are you sure you want to delete <strong>{selectedLabel}</strong>?{extraWarning ? <> - {extraWarning}</> : null}
            </p>
            {deleteError && <DismissibleError message={deleteError} onDismiss={onDismissDeleteError} />}
            <div className="modal-actions">
              <button type="button" className="btn btn-ghost" onClick={onCancelDelete} disabled={deleting}>
                Cancel
              </button>
              <button type="button" className="btn btn-primary" onClick={onConfirmDelete} disabled={deleting}>
                {deleting ? deletingLabel : confirmLabel}
              </button>
            </div>
            {deleting && deletingHint && <p className="nat-reconnect-hint" role="status">{deletingHint}</p>}
          </div>
        </div>
      )}
    </>
  );
}

// named + default export ทั้งคู่ (import ผิดแบบเป็น { Edit_Result } เคยทำให้
// ได้ undefined เงียบๆ แล้วพังทั้งหน้าขาวตอน render มาแล้ว - เผื่อไว้ทั้ง 2 แบบ
// กันพังซ้ำไม่ว่าจะ import แบบไหน)
export { Edit_Result };
export default Edit_Result;
