// |====== Invitations Modal (คำเชิญเข้าร่วมสาขา) ======|

// หน้า Sites.jsx - เดิมแสดงคำเชิญเป็นการ์ดเรียงลงมาตรง ๆ บนหน้าหลัก ซึ่งความสูงยืดตาม
// จำนวนคำเชิญไม่จำกัด ถ้ามีคนสร้าง site จำนวนมากแล้วเชิญรัว ๆ (สร้าง site ได้ไม่จำกัด
// และ endpoint เชิญยังไม่มี rate limit) หน้า Sites จะถูกดันลงไปจนใช้งานไม่ได้
//
// ย้ายมาไว้ใน modal แทน - หน้าหลักเหลือแค่แถบสรุปบรรทัดเดียวที่ "ความสูงคงที่เสมอ"
// ไม่ว่าจะมีคำเชิญ 1 หรือ 1,000 รายการ
export default function InvitationsModal({
  invitations,
  busyInviteSiteId,
  onAccept,
  onReject,
  onClose,
}) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card modal-card-wide" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <h2>Site Invitations ({invitations.length})</h2>
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
          {invitations.length === 0 ? (
            <div className="config-placeholder">
              No pending invitations. When a site owner invites you, the invitation will appear here.
            </div>
          ) : (
            invitations.map((inv) => (
              <div
                key={inv.site_id}
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
                <span>
                  <strong>{inv.site_name}</strong> ({inv.org_id}) - Invited as{" "}
                  {inv.role === "admin" ? "Admin" : "Member"}
                </span>
                <div style={{ display: "flex", gap: "6px", flexShrink: 0 }}>
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
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
