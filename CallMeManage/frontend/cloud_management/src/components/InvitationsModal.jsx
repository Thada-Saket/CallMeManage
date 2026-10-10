// |====== Invitations Modal (กระดิ่งแจ้งเตือนหน้า Sites) ======|

// หน้า Sites.jsx - เดิมแสดงคำเชิญเป็นการ์ดเรียงลงมาตรง ๆ บนหน้าหลัก ซึ่งความสูงยืดตาม
// จำนวนคำเชิญไม่จำกัด ถ้ามีคนสร้าง site จำนวนมากแล้วเชิญรัว ๆ (สร้าง site ได้ไม่จำกัด
// และ endpoint เชิญยังไม่มี rate limit) หน้า Sites จะถูกดันลงไปจนใช้งานไม่ได้
//
// ย้ายมาไว้ใน modal แทน เปิดจากกระดิ่งที่หัวหน้า - รวม 2 อย่างที่ "ยังเข้า site ไม่ได้":
// คำเชิญที่ต้องตอบ (invited) และคำขอเข้าร่วมที่ส่งไปแล้วรออนุมัติ (pending - เดิมเป็น
// การ์ดใน Joined Sites ตอนนี้ Joined Sites แสดงเฉพาะที่อนุมัติแล้ว)
function NotificationRow({ children, actions }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "12px",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm)",
        padding: "10px 14px",
        flexShrink: 0, // กันไม่ให้แถวถูกบีบให้เตี้ยลงเมื่อรายการล้นกรอบ
      }}
    >
      <span>{children}</span>
      <div style={{ display: "flex", gap: "6px", flexShrink: 0 }}>{actions}</div>
    </div>
  );
}

export default function InvitationsModal({
  invitations,
  joinRequests = [],
  busyInviteSiteId,
  onAccept,
  onReject,
  onCancelRequest,
  onClose,
}) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card modal-card-wide" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <h2>Site Notifications</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            &times;
          </button>
        </div>

        {/* ความสูงตายตัว (height ไม่ใช่ maxHeight) แล้วเลื่อนดูข้างในแทน - กรอบ modal
            จึงมีขนาดเท่าเดิมเสมอไม่ว่าจะมีคำเชิญ 0 หรือ 1,000 รายการ ไม่ยืดทะลุจอ
            และไม่กระโดดเปลี่ยนขนาดตอนตอบรับ/ปฏิเสธไปทีละใบ */}
        <div
          style={{
            height: "420px",
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
            gap: "10px",
            marginTop: "16px",
          }}
        >
          <h3 className="site-notification-section-title">
            Invitations
            {invitations.length > 0 && <span className="site-notification-badge is-inline">{invitations.length}</span>}
          </h3>
          {invitations.length === 0 ? (
            <div className="config-placeholder">
              No pending invitations. When a site owner invites you, the invitation will appear here.
            </div>
          ) : (
            invitations.map((inv) => (
              <NotificationRow
                key={`invite:${inv.site_id}`}
                actions={(
                  <>
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={busyInviteSiteId === inv.site_id}
                      onClick={() => onAccept(inv.site_id)}
                    >
                      Accept
                    </button>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      disabled={busyInviteSiteId === inv.site_id}
                      onClick={() => onReject(inv.site_id)}
                    >
                      Decline
                    </button>
                  </>
                )}
              >
                <strong>{inv.site_name}</strong> ({inv.org_id}) - Invited as{" "}
                {inv.role === "admin" ? "Admin" : "Member"}
              </NotificationRow>
            ))
          )}

          <h3 className="site-notification-section-title">Pending Join Requests</h3>
          {joinRequests.length === 0 ? (
            <div className="config-placeholder">
              No pending join requests. Requests you send with "Search & Join Site" appear here until they are approved.
            </div>
          ) : (
            joinRequests.map((req) => (
              <NotificationRow
                key={`request:${req.site_id}`}
                actions={(
                  <button
                    type="button"
                    className="btn btn-ghost"
                    disabled={busyInviteSiteId === req.site_id}
                    onClick={() => onCancelRequest?.(req.site_id)}
                  >
                    Cancel Request
                  </button>
                )}
              >
                <strong>{req.site_name}</strong> ({req.org_id}) - <span className="badge badge-pending">Waiting for approval</span>
              </NotificationRow>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
