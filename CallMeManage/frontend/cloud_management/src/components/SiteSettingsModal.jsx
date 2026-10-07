import DismissibleError from "./DismissibleError";
import { useEffect, useRef, useState } from "react";
import {
  deleteSite,
  inviteSiteMember,
  listSiteMembers,
  removeSiteMember,
  renameSite,
  transferSiteOwnership,
  updateMemberRole,
  updateSiteMember,
} from "../api/api_sites";
import { lookupUserByEmail } from "../api/api_users";

// หน้า Sites.jsx - ปุ่ม "จัดการสมาชิก"/site card เปิด modal นี้ (เดิมชื่อ
// SiteMemberModal.jsx - ขยายเป็น "Site Settings" เต็มรูปแบบตาม spec ข้อ 3.3:
// เชิญสมาชิกด้วยอีเมล + จัดการ role + โอนกรรมสิทธิ์ + ยุบสาขา (2 อย่างหลัง
// เฉพาะ isOwner - Site Admin ทำแทนไม่ได้ ตรงกับ guard ฝั่ง backend)
export default function SiteSettingsModal({ site, isOwner, onClose, onSiteChanged }) {
  const [savedSiteName, setSavedSiteName] = useState(site.site_name);
  const [siteNameDraft, setSiteNameDraft] = useState(site.site_name);
  const [renameError, setRenameError] = useState("");
  const [renaming, setRenaming] = useState(false);
  const [members, setMembers] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("pending"); // 'pending' | 'invited' | 'active'
  const [busyUsrId, setBusyUsrId] = useState(null);

  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteError, setInviteError] = useState("");
  const [inviting, setInviting] = useState(false);
  const [confirmingInvite, setConfirmingInvite] = useState(false);
  const [emailPreview, setEmailPreview] = useState(""); // "✓ พบผู้ใช้: xxx" / "ไม่พบผู้ใช้" / ""

  const [transferTarget, setTransferTarget] = useState("");
  const [transferError, setTransferError] = useState("");
  const [transferring, setTransferring] = useState(false);
  const [confirmingTransfer, setConfirmingTransfer] = useState(false);

  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [confirmRemoval, setConfirmRemoval] = useState(null);
  const refreshRequestId = useRef(0);
  const refreshRef = useRef(null);

  useEffect(() => {
    setSavedSiteName(site.site_name);
    setSiteNameDraft(site.site_name);
    setRenameError("");
  }, [site.site_id, site.site_name]);

  async function refresh() {
    const requestId = ++refreshRequestId.current;
    try {
      const latestMembers = await listSiteMembers(site.site_id);
      if (requestId === refreshRequestId.current) setMembers(latestMembers);
    } catch (err) {
      if (requestId === refreshRequestId.current) {
        setError(err.detail || "Failed to load members");
      }
    }
  }

  refreshRef.current = refresh;

  useEffect(() => {
    refresh();
    let pollInFlight = false;
    const refreshVisible = async () => {
      if (document.visibilityState !== "visible" || pollInFlight) return;
      pollInFlight = true;
      try {
        await refreshRef.current?.();
      } finally {
        pollInFlight = false;
      }
    };
    const intervalId = window.setInterval(refreshVisible, 2500);
    window.addEventListener("focus", refreshVisible);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      window.clearInterval(intervalId);
      window.removeEventListener("focus", refreshVisible);
      document.removeEventListener("visibilitychange", refreshVisible);
      refreshRequestId.current += 1;
    };
  }, [site.site_id]);

  // preview เบาๆ ว่าอีเมลที่พิมพ์อยู่มีผู้ใช้จริงไหมก่อนกดเชิญ (debounce กัน
  // ยิง request ทุกตัวอักษร) - ไม่ได้เอาผลลัพธ์มา "เลือก" (response ไม่มี email
  // ให้เติมกลับอยู่แล้ว ตั้งใจปิดบัง PII) แค่โชว์ชื่อ user เป็น hint - ปุ่ม
  // "ส่งคำเชิญ" ยังส่งข้อความอีเมลที่พิมพ์ไว้ตรงๆ อยู่ดี ไม่ใช่ผลจาก lookup
  //
  // lookup ค้นแบบ "ตรงเป๊ะ" จึงต้องพิมพ์อีเมลเต็มถึงจะขึ้นว่าพบ (พิมพ์ค้างกลางทาง
  // จะขึ้น "ไม่พบ" ไปก่อนเป็นเรื่องปกติ) - ใช้ฟังก์ชันเดียวกับที่ backend ใช้ตอน
  // ส่งคำเชิญจริง จึงการันตีว่าถ้าตรงนี้ขึ้น "พบผู้ใช้" แล้วกดเชิญจะไม่มีทางพลาด
  useEffect(() => {
    const trimmed = inviteEmail.trim();
    if (trimmed.length < 3) {
      setEmailPreview("");
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const results = await lookupUserByEmail(trimmed);
        setEmailPreview(
          results.length > 0 ? `✓ User found: ${results[0].usr_name}` : "No user found with this email"
        );
      } catch {
        setEmailPreview("");
      }
    }, 400);
    return () => clearTimeout(timer);
  }, [inviteEmail]);

  async function handleApprove(usrId) {
    setBusyUsrId(usrId);
    setError("");
    try {
      await updateSiteMember(site.site_id, usrId, { status: "approved" });
      await refresh();
    } catch (err) {
      setError(err.detail || "Failed to approve request");
    } finally {
      setBusyUsrId(null);
    }
  }

  async function handleRenameSite(event) {
    event.preventDefault();
    const cleanedName = siteNameDraft.trim();
    if (!cleanedName || cleanedName === savedSiteName || renaming) return;

    setRenameError("");
    setRenaming(true);
    try {
      const updatedSite = await renameSite(site.site_id, cleanedName);
      setSavedSiteName(updatedSite.site_name);
      setSiteNameDraft(updatedSite.site_name);
      await onSiteChanged?.();
    } catch (err) {
      setRenameError(err.detail || "Failed to rename site");
    } finally {
      setRenaming(false);
    }
  }

  async function handleRoleChange(usrId, role) {
    setBusyUsrId(usrId);
    setError("");
    try {
      await updateMemberRole(site.site_id, usrId, role);
      await refresh();
    } catch (err) {
      setError(err.detail || "Failed to update role");
    } finally {
      setBusyUsrId(null);
    }
  }

  async function handleRemoveConfirmed() {
    if (!confirmRemoval) return;
    const { member } = confirmRemoval;
    setBusyUsrId(member.usr_id);
    setError("");
    try {
      await removeSiteMember(site.site_id, member.usr_id, member.status);
      setConfirmRemoval(null);
      await refresh();
    } catch (err) {
      setError(err.detail || "Action failed");
      if (err.status === 409) {
        setConfirmRemoval(null);
        await refresh();
      }
    } finally {
      setBusyUsrId(null);
    }
  }

  function requestInvite(event) {
    event.preventDefault();
    if (!inviteEmail.trim()) return;
    setInviteError("");
    setConfirmingInvite(true);
  }

  async function handleInvite() {
    if (!inviteEmail.trim()) return;
    setInviteError("");
    setInviting(true);
    try {
      await inviteSiteMember(site.site_id, inviteEmail.trim());
      setConfirmingInvite(false);
      setInviteEmail("");
      setEmailPreview("");
      await refresh();
    } catch (err) {
      setInviteError(err.detail || "Failed to send invitation");
    } finally {
      setInviting(false);
    }
  }

  async function handleTransfer() {
    if (!transferTarget) return;
    setTransferError("");
    setTransferring(true);
    try {
      await transferSiteOwnership(site.site_id, transferTarget);
      setConfirmingTransfer(false);
      await refresh();
      onSiteChanged?.();
    } catch (err) {
      setTransferError(err.detail || "Failed to transfer ownership");
    } finally {
      setTransferring(false);
    }
  }

  async function handleDeleteSite() {
    setDeleteError("");
    setDeleting(true);
    try {
      await deleteSite(site.site_id);
      onSiteChanged?.();
      onClose();
    } catch (err) {
      setDeleteError(err.detail || "Failed to delete site");
      setDeleting(false);
    }
  }

  const pending = members ? members.filter((m) => m.status === "pending") : [];
  const invited = members ? members.filter((m) => m.status === "invited") : [];
  const active = members ? members.filter((m) => m.status === "approved") : [];
  const transferCandidates = active.filter((m) => !m.is_owner);

  function requestRemoval(member, action) {
    if (member.is_current_user) return;
    setConfirmRemoval({ member, action });
  }

  function removalText() {
    if (!confirmRemoval) return { title: "", message: "", button: "" };
    const { member, action } = confirmRemoval;
    if (action === "reject") {
      return {
        title: "Reject Join Request?",
        message: `Reject the join request from "${member.usr_name}"?`,
        button: "Reject Request",
      };
    }
    if (action === "cancel-invitation") {
      return {
        title: "Cancel Invitation?",
        message: `Cancel the invitation sent to "${member.usr_name}"? If they have already accepted it, no membership will be removed.`,
        button: "Cancel Invitation",
      };
    }
    return {
      title: "Remove Member?",
      message: `Remove "${member.usr_name}" from this site? They will immediately lose access to all devices in this site.`,
      button: "Remove Member",
    };
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" style={{ maxWidth: "520px" }} onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <h2>Site Settings: {savedSiteName}</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            &times;
          </button>
        </div>

        <form onSubmit={handleRenameSite} className="site-rename-form">
          <div className="field">
            <label htmlFor="site-settings-name">Site Name</label>
            <div className="site-rename-controls">
              <input
                id="site-settings-name"
                type="text"
                value={siteNameDraft}
                onChange={(event) => setSiteNameDraft(event.target.value)}
                maxLength={64}
                required
                disabled={renaming}
              />
              <button
                type="submit"
                className="btn btn-primary"
                disabled={renaming || !siteNameDraft.trim() || siteNameDraft.trim() === savedSiteName}
              >
                {renaming ? "Saving..." : "Save Name"}
              </button>
            </div>
            <span className="field-hint">Changing the name does not change the Org ID, devices, or members.</span>
          </div>
          {renameError && <DismissibleError message={renameError} onDismiss={() => setRenameError("")} />}
        </form>

        <form onSubmit={requestInvite} style={{ marginBottom: "16px" }}>
          <div className="field">
            <label htmlFor="invite-email">Invite Member by Email</label>
            <div style={{ display: "flex", gap: "8px" }}>
              <input
                id="invite-email"
                type="email"
                placeholder="someone@example.com"
                value={inviteEmail}
                onChange={(event) => setInviteEmail(event.target.value)}
                style={{ flex: 1 }}
                required
              />
              <button type="submit" className="btn btn-primary" disabled={inviting}>
                Send Invitation
              </button>
            </div>
            {emailPreview && <span className="field-hint">{emailPreview}</span>}
          </div>
          {inviteError && <DismissibleError message={inviteError} onDismiss={() => setInviteError("")} />}
        </form>

        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

        <div className="segmented-control" style={{ marginBottom: "14px" }}>
          <input
            type="radio"
            id="member-tab-pending"
            name="member-tab"
            checked={tab === "pending"}
            onChange={() => setTab("pending")}
          />
          <label htmlFor="member-tab-pending">Pending Requests ({pending.length})</label>

          <input
            type="radio"
            id="member-tab-invited"
            name="member-tab"
            checked={tab === "invited"}
            onChange={() => setTab("invited")}
          />
          <label htmlFor="member-tab-invited">Invited ({invited.length})</label>

          <input
            type="radio"
            id="member-tab-active"
            name="member-tab"
            checked={tab === "active"}
            onChange={() => setTab("active")}
          />
          <label htmlFor="member-tab-active">Members ({active.length})</label>
        </div>

        {members === null && <div className="center-loading">Loading...</div>}

        {members !== null && tab === "pending" && (
          <div className="site-member-list">
            {pending.length === 0 && <div className="config-placeholder">No pending requests</div>}
            {pending.map((m) => (
              <div key={m.usr_id} className="member-row">
                <span>{m.usr_name}</span>
                <div style={{ display: "flex", gap: "6px" }}>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={busyUsrId === m.usr_id}
                    onClick={() => handleApprove(m.usr_id)}
                  >
                    Approve
                  </button>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    disabled={busyUsrId === m.usr_id}
                    onClick={() => requestRemoval(m, "reject")}
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {members !== null && tab === "invited" && (
          <div className="site-member-list">
            {invited.length === 0 && <div className="config-placeholder">No pending invitations</div>}
            {invited.map((m) => (
              <div key={m.usr_id} className="member-row">
                <span>
                  {m.usr_name}{" "}
                  <span className="badge badge-pending">Invited ({m.role === "admin" ? "Admin" : "Member"})</span>
                </span>
                <button
                  type="button"
                  className="btn btn-ghost"
                  disabled={busyUsrId === m.usr_id}
                  onClick={() => requestRemoval(m, "cancel-invitation")}
                >
                  Cancel Invitation
                </button>
              </div>
            ))}
          </div>
        )}

        {members !== null && tab === "active" && (
          <div className="site-member-list">
            {active.length === 0 && <div className="config-placeholder">No active members</div>}
            {active.map((m) => (
              <div key={m.usr_id} className="member-row">
                <span>
                  {m.usr_name}{" "}
                  {m.is_owner ? (
                    <span className="badge badge-active">Owner</span>
                  ) : (
                    <span className={`badge ${m.role === "admin" ? "badge-active" : "badge-offline"}`}>
                      {m.role === "admin" ? "Admin" : "Member"}
                    </span>
                  )}
                  {m.is_current_user && <span className="badge badge-active">You</span>}
                </span>
                {!m.is_owner && !m.is_current_user && (
                  <div style={{ display: "flex", gap: "6px" }}>
                    <select
                      value={m.role}
                      disabled={busyUsrId === m.usr_id}
                      onChange={(event) => handleRoleChange(m.usr_id, event.target.value)}
                    >
                      <option value="member">Member</option>
                      <option value="admin">Admin</option>
                    </select>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      disabled={busyUsrId === m.usr_id}
                      onClick={() => requestRemoval(m, "remove")}
                    >
                      Remove
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {isOwner && (
          <div style={{ marginTop: "20px", paddingTop: "16px", borderTop: "1px solid var(--border)" }}>
            <h3 style={{ fontSize: "14px", color: "var(--danger, #e05a4e)", margin: "0 0 10px" }}>Danger Zone</h3>

            <div className="field">
              <label htmlFor="transfer-target">Transfer Site Ownership To</label>
              <div style={{ display: "flex", gap: "8px" }}>
                <select
                  id="transfer-target"
                  value={transferTarget}
                  onChange={(event) => setTransferTarget(event.target.value)}
                  style={{ flex: 1 }}
                >
                  <option value="">-- Select Member --</option>
                  {transferCandidates.map((m) => (
                    <option key={m.usr_id} value={m.usr_id}>
                      {m.usr_name} ({m.role === "admin" ? "Admin" : "Member"})
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  className="btn btn-danger"
                  disabled={!transferTarget}
                  onClick={() => setConfirmingTransfer(true)}
                >
                  Transfer Ownership
                </button>
              </div>
              {transferCandidates.length === 0 && (
                <span className="field-hint">At least one approved member is required before ownership can be transferred.</span>
              )}
              {transferError && <DismissibleError message={transferError} onDismiss={() => setTransferError("")} />}
            </div>

            <div className="field">
              <label>Delete Site</label>
              <button type="button" className="btn btn-danger btn-block" onClick={() => setConfirmingDelete(true)}>
                Delete Site
              </button>
              <span className="field-hint">Permanently delete this site, all its members, and associated devices.</span>
              {deleteError && <DismissibleError message={deleteError} onDismiss={() => setDeleteError("")} />}
            </div>
          </div>
        )}
      </div>

      {confirmingInvite && (
        <div
          className="modal-overlay"
          onClick={(event) => {
            event.stopPropagation();
            if (!inviting) setConfirmingInvite(false);
          }}
        >
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Send Invitation?</h2>
            </div>
            <p>
              Invite <strong>{inviteEmail.trim()}</strong> to join "{savedSiteName}" as a Member? You can change
              their role after they accept the invitation.
            </p>
            {inviteError && <DismissibleError message={inviteError} onDismiss={() => setInviteError("")} />}
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setConfirmingInvite(false)}
                disabled={inviting}
              >
                Back
              </button>
              <button type="button" className="btn btn-primary" onClick={handleInvite} disabled={inviting}>
                {inviting ? "Sending..." : "Confirm Invitation"}
              </button>
            </div>
          </div>
        </div>
      )}

      {confirmingTransfer && (
        <div className="modal-overlay" onClick={() => !transferring && setConfirmingTransfer(false)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Confirm Ownership Transfer</h2>
            </div>
            <p>
              You will no longer be the owner of "{savedSiteName}" (you will become an Admin instead). This action cannot be undone. Are you sure?
            </p>
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setConfirmingTransfer(false)}
                disabled={transferring}
              >
                Cancel
              </button>
              <button type="button" className="btn btn-danger" onClick={handleTransfer} disabled={transferring}>
                {transferring ? "Transferring..." : "Confirm Transfer"}
              </button>
            </div>
          </div>
        </div>
      )}

      {confirmingDelete && (
        <div className="modal-overlay" onClick={() => !deleting && setConfirmingDelete(false)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Confirm Site Deletion</h2>
            </div>
            <p>
              Site "{savedSiteName}" and all members and devices ({site.device_count ?? 0} devices) will be permanently deleted. This action cannot be undone. Are you sure?
            </p>
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setConfirmingDelete(false)}
                disabled={deleting}
              >
                Cancel
              </button>
              <button type="button" className="btn btn-danger" onClick={handleDeleteSite} disabled={deleting}>
                {deleting ? "Deleting Site..." : "Confirm Delete Site"}
              </button>
            </div>
          </div>
        </div>
      )}

      {confirmRemoval && (() => {
        const copy = removalText();
        return (
          <div
            className="modal-overlay"
            onClick={(event) => {
              event.stopPropagation();
              if (!busyUsrId) setConfirmRemoval(null);
            }}
          >
            <div className="modal-card modal-card-danger-confirm" onClick={(event) => event.stopPropagation()}>
              <div className="modal-header">
                <h2>{copy.title}</h2>
              </div>
              <p>{copy.message}</p>
              <div className="modal-actions">
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => setConfirmRemoval(null)}
                  disabled={Boolean(busyUsrId)}
                >
                  Back
                </button>
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={handleRemoveConfirmed}
                  disabled={Boolean(busyUsrId)}
                >
                  {busyUsrId ? "Processing..." : copy.button}
                </button>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
