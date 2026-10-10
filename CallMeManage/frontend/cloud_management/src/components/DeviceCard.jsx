import DismissibleError from "./DismissibleError";
// |====== Device Cards (Device Page Component) ======|

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";

// import api function
import { deleteDevice } from "../api/api_devices";
import ResetIdentityModal from "./ResetIdentityModal";
import { cliGeneratorUrl } from "../utils/deviceEnrollmentRoutes";

// import device logo images
import ciscoLogo from "../assets/images/ciscoLogo.png";
import juniperLogo from "../assets/images/juniperLogo.png";
import huaweiLogo from "../assets/images/huaweiLogo.png";

// สถานะอุปกรณ์
const STATUS_LABEL = {
  active: { text: "Online", cls: "badge-active" },
  online: { text: "Online", cls: "badge-active" },
  pending: { text: "Pending", cls: "badge-pending" },
  expired: { text: "Expired", cls: "badge-expired" },
  offline: { text: "Offline", cls: "badge-offline" },
  rejected: { text: "Rejected", cls: "badge-rejected" },
  // (bug 55) สถานะที่ 3 - TCP ยังต่ออยู่แต่อุปกรณ์ไม่ตอบ NETCONF
  //
  // เดิมมีแค่ Online/Offline ตัดสินจาก "มี session ไหม" ซึ่งเป็นจริงตราบใดที่ TCP
  // ยังต่อ - ช่วงที่อุปกรณ์ค้างไม่ตอบ (เจอจริงนาน ~14 นาที) ป้ายขึ้น Online ตลอด
  // ผู้ใช้เห็นแล้วกดสั่งงานก็ไปเจอ timeout เอาเอง ทั้งที่ระบบรู้อยู่แล้วว่ามันไม่ตอบ
  //
  // ใช้สีเดียวกับ pending เพราะความหมายใกล้กัน (ยังไม่พร้อมใช้งาน แต่ไม่ถึงกับตาย)
  unresponsive: { text: "Unresponsive", cls: "badge-pending" },
};

// โลโก้ยี่ห้ออุปกรณ์
const VENDOR_LOGO = {
  cisco: ciscoLogo,
  juniper: juniperLogo,
  huawei: huaweiLogo,
};

// ชื่อ vendor ที่อ่านง่าย (pending ของ token flow ใช้ vendor จริง; legacy pending ใช้ "pending" ซึ่งไม่มีใน map นี้)
const VENDOR_LABEL = {
  cisco: "Cisco",
  juniper: "Juniper",
  huawei: "Huawei",
};

// คำอธิบายว่ากำลังรออุปกรณ์เชื่อมต่อ - ตัดสินจากสถานะ pending ไม่ใช่ vendor (เดิมเช็ค dev_vendor === "pending"
// ซึ่งไม่ตรงกับ pending ของ token flow ที่ใช้ vendor จริง) ไม่แสดง token/MAC/Serial ใด ๆ บน card
function pendingHint(device) {
  if (device.dev_status !== "pending") return null;
  if (device.enrollment_expired) return "Enrollment expired · Regenerate or delete";
  const vendor = VENDOR_LABEL[device.dev_vendor];
  return vendor ? `${vendor} · Waiting for device` : "Waiting for device";
}

// การทำงานของส่วนประกอบการ์ดแสดงผลอุปกรณ์
export default function DeviceCard({ device, siteRole, onDeleted, onChanged }) {
  // เครื่องมือสำหรับ redirect ไปยัง path ที่กำหนด
  const navigate = useNavigate();

  // ข้อมูลสถานะอุปกรณ์
  const statusKey = device.dev_status === "pending" && device.enrollment_expired ? "expired" : device.dev_status;
  const status = STATUS_LABEL[statusKey] || STATUS_LABEL.offline;

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);  // แสดง popup ถามยืนยันว่าจะลบอุปกรณ์ไหม
  const [deleting, setDeleting] = useState(false);                    // ตัวแปรเก็บค่ายืนยันการลบ
  const [deleteError, setDeleteError] = useState("");                 // ตัวแปรเก็บค่า error การลบ
  const [showReconnectModal, setShowReconnectModal] = useState(false);
  const cardRef = useRef(null);                                       // ตัวแปรเก็บค่า element ของการ์ดอุปกรณ์
  const [flipped, setFlipped] = useState(false);                      // ตัวแปรเก็บด้านของการ์ด

  // หลังจาก render หน้าเว็บเสร็จ ถ้าค่า flipped เปลี่ยนไป จะให้กลับด้านการ์ด
  useEffect(() => {
    // ถ้าค่า flipped = false ไม่ต้องทำอะไร
    if (!flipped) return;
    
    // รับค่า event มาสำหรับหมุนการ์ด
    function handleOutsideClick(event) {

      // ถ้า cardRef ปัจจุบันมีค่าอยู่ไม่ใช่ null และจุดที่เมาส์คลิ๊กเป็นพื้นที่นอก element ของการ์ด
      if (cardRef.current && !cardRef.current.contains(event.target)) { 
        setFlipped(false);      // หมุนการ์ดกลับด้าน
      }
    }
    document.addEventListener("mousedown", handleOutsideClick);                   // รอจับจังหวะที่เมาส์คลิ๊ก
    return () => document.removeEventListener("mousedown", handleOutsideClick);   // ลบตัวดักจับทิ้ง
  }, [flipped]);

  // ฟังก์ชั่นรับหน้าที่จัดการการลบ
  async function handleConfirmDelete() {
    setDeleting(true);
    setDeleteError("");
    try {
      await deleteDevice(device.dev_id);
      setShowDeleteConfirm(false);
      onDeleted?.();
    } catch (err) {
      setDeleteError(err.detail || "Failed to delete device");
    } finally {
      setDeleting(false);
    }
  }

  // ฟังก์ชั่นพาไปยังหน้าจัดการอุปกร์เมื่อกดปุ่มบนการ์ด
  function handleManageClick(event) {
    event.stopPropagation();
    setFlipped(false);
    navigate(`/devices/${device.dev_id}`);
  }

  // ฟังก์ชั่นพาไปยังหน้าประวัติการจัดการอุปกร์เมื่อกดปุ่มบนการ์ด
  function handleHistoryClick(event) {
    event.stopPropagation();
    setFlipped(false);
    navigate(`/devices/${device.dev_id}`, { state: { openHistory: true } });
  }

  function handleReconnectClick(event) {
    event.stopPropagation();
    setFlipped(false);
    setShowReconnectModal(true);
  }

  function handleRegenerateClick(event) {
    event.stopPropagation();
    setFlipped(false);
    navigate(cliGeneratorUrl(device.site_id, device.dev_id));
  }

  // ฟังก์ชั่นรับมือกับการกดปุ่มลบอุปกรณ์
  function handleDeleteClick(event) {
    event.stopPropagation();
    setFlipped(false);
    setShowDeleteConfirm(true);
  }

  const logo = VENDOR_LOGO[device.dev_vendor];            // ตัวแปรเก็บรูปยี่ห้ออุปกรณ์
  const hint = pendingHint(device);                       // ตัวแปรเก็บคำอธิบายว่ากำลังรอการเชื่อมต่อ
  const isPending = device.dev_status === "pending";      // ตัวแปรเก็บค่า true/false ว่ากำลังรอลงทะเบียน
  // (bug 55) "unresponsive" ไม่นับเป็น online - ปุ่มสั่งงานที่ผูกกับ isOnline จะได้ไม่
  // ชวนให้ผู้ใช้กดไปเจอ timeout ทั้งที่ระบบรู้อยู่แล้วว่าอุปกรณ์ไม่ตอบ
  const isOnline = device.dev_status === "active" || device.dev_status === "online";  // ตัวแปรเก็บค่า true/false ว่าออนไลน์อยู่ไหม
  const canReconnect = ["active", "online", "offline", "unresponsive"].includes(device.dev_status);
  const canManageSite = siteRole === "owner" || siteRole === "admin";
  const canResetIdentity = siteRole === "owner";
  // ปุ่ม "Back" ถูกเอาออกแล้ว (ซ้ำกับการคลิกการ์ด/คลิกนอกการ์ดที่พลิกกลับอยู่แล้ว)
  // การ์ด pending ที่ผู้ใช้ไม่มีสิทธิ์จัดการ site จึงไม่เหลือปุ่มด้านหลังเลย - ไม่
  // ให้พลิกไปเจอหน้าว่าง
  const hasBackActions = !isPending || canManageSite;

  return (
    <div
      className={`device-card${flipped ? " flipped" : ""}`}
      ref={cardRef}
      onClick={() => {
        if (hasBackActions) setFlipped((prev) => !prev);
      }}
    >
      {!device.dev_viewed && <span className="device-unseen-dot" title="Unviewed device" />}
      <div className="device-card-flip-inner">
        <div className="device-card-face device-card-face-front">
          {/* the logo area is always there (empty for pending devices), so the name and
              status sit at the same height on every card */}
          <div className="device-logo" aria-hidden={isPending || !logo}>
            {!isPending && logo && (
              <img src={logo} alt={`${device.dev_vendor} logo`} className={`${device.dev_vendor}`}/>
            )}
          </div>

          <div className="device-info-container">
            <div className="device-card-head">
              {/* one line each, cut with "..." - the full text shows on hover */}
              <div className="device-card-title">
                <div className="device-name" title={device.dev_name}>{device.dev_name}</div>
                {hint && <div className="device-vendor" title={hint}>{hint}</div>}
              </div>
              <span className={`badge ${status.cls}`}>{status.text}</span>
            </div>

            <div className="device-meta">
              <div>
                <span className="label">Last seen</span>
                <span className="meta-value">
                  {device.dev_last_seen ? new Date(device.dev_last_seen).toLocaleString() : "-"}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div className="device-card-face device-card-face-back">
          {isPending ? (
            <>
              {canManageSite && (
                <>
                  <button type="button" className="btn btn-ghost btn-block" onClick={handleRegenerateClick}>
                    Regenerate CLI
                  </button>
                  <button type="button" className="btn btn-ghost btn-block" onClick={handleDeleteClick}>
                    Delete
                  </button>
                </>
              )}
            </>
          ) : (
            <>
              {isOnline ? (
                <button type="button" className="btn btn-ghost btn-block" onClick={handleManageClick}>
                  Configuration
                </button>
              ) : (
                <button type="button" className="btn btn-ghost btn-block" onClick={handleHistoryClick}>
                  History
                </button>
              )}
              {canReconnect && canResetIdentity && (
                <button type="button" className="btn btn-ghost btn-block" onClick={handleReconnectClick}>
                  Reconnect Device
                </button>
              )}
              {canManageSite && (
                <button type="button" className="btn btn-ghost btn-block" onClick={handleDeleteClick}>
                  Delete
                </button>
              )}
            </>
          )}
        </div>
      </div>

      {showDeleteConfirm &&
        createPortal(
          <div
            className="modal-overlay"
            onClick={(event) => {
              event.stopPropagation();
              if (!deleting) setShowDeleteConfirm(false);
            }}
          >
            <div
              className="modal-card modal-card-danger-confirm"
              role="alertdialog"
              aria-modal="true"
              aria-labelledby="device-delete-title"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="modal-header modal-header-danger">
                <h2 id="device-delete-title">Delete Device?</h2>
                <button
                  type="button"
                  className="modal-close"
                  onClick={() => setShowDeleteConfirm(false)}
                  aria-label="Close"
                  disabled={deleting}
                >
                  &times;
                </button>
              </div>
              <div className="danger-confirm-message">
                {device.dev_status === "pending" ? (
                  <><strong>Warning:</strong> Remove <strong>{device.dev_name}</strong> from the pending list? If the physical device calls home later, it will not be paired with this workspace and must be registered again.</>
                ) : (
                  <><strong>Warning:</strong> Delete <strong>{device.dev_name}</strong> and all associated system records, including history, saved configuration, and capabilities. <strong>This action cannot be undone.</strong></>
                )}
              </div>
              {deleteError && <DismissibleError message={deleteError} onDismiss={() => setDeleteError("")} />}
              <div className="modal-actions">
                <button type="button" className="btn btn-ghost" onClick={() => setShowDeleteConfirm(false)} disabled={deleting}>
                  Cancel
                </button>
                <button type="button" className="btn btn-danger" onClick={handleConfirmDelete} disabled={deleting}>
                  {deleting ? "Deleting..." : "Delete Device"}
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}

      <ResetIdentityModal
        isOpen={showReconnectModal}
        onClose={() => setShowReconnectModal(false)}
        device={device}
        onResetSuccess={() => onChanged?.()}
      />
    </div>
  );
}
