import DismissibleError from "../components/DismissibleError";
// |====== Site Page Render on Browser ======|

import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

// import global component
import TopBar from "../components/TopBar";

// import site components
import CreateSiteModal from "../components/CreateSiteModal";
import SearchJoinSiteModal from "../components/SearchJoinSiteModal";
import SiteSettingsModal from "../components/SiteSettingsModal";
import { Pagination } from "../components/Pagination";

// import api functions
import { listMySites } from "../api/api_sites";
import { acceptInvitation, getMyInvitations, rejectInvitation } from "../api/api_users";
import LeaveSiteModal from "../components/LeaveSiteModal";
import InvitationsModal from "../components/InvitationsModal";
import { copyText } from "../utils/copyText";

// หน้าศูนย์รวมสาขา (spec ข้อ 3.1) - แยก 2 ส่วนชัดเจน: สาขาที่เป็นเจ้าของ (Owned)
// กับสาขาที่ขอเข้าร่วม (Joined - ทั้ง pending และ approved, badge บอกสถานะ) -
// คลิก Site Card แล้วพาไปหน้า /devices?site_id=... (Devices.jsx อ่านจาก
// useSearchParams อยู่แล้ว)
function formatDate(iso) {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

// user ขอ (2026-08-06): "ให้ site card flip ได้เหมือน device card" - reuse
// กลไก 3D flip เดิมของ DeviceCard.jsx ตรงๆ (`.device-card-flip-inner`/
// `.device-card-face-front`/`.device-card-face-back` เป็น CSS generic ไม่ได้
// ผูกกับอุปกรณ์เลย - ดู App.css) หน้า front คือเนื้อหาเดิมทั้งหมด (ชื่อ/badge/
// meta) หน้า back เป็นปุ่ม action 3 ปุ่ม: "เข้าทำงาน" (แทนที่การคลิกการ์ด
// ทั้งใบเพื่อเปิดตรงๆ แบบเดิม), "จัดการสมาชิก" (ย้ายมาจากปุ่มท้ายการ์ดเดิม),
// "ยกเลิก" (พลิกกลับหน้า front - เทียบเท่าปุ่ม "Back" ของ DeviceCard)
function SiteCard({ site, badge, canEnter, onEnter, onCopyOrgId, onManageMembers, showManage, showLeave, onLeaveModal }) {
  const cardRef = useRef(null);
  const [flipped, setFlipped] = useState(false);

  // คลิกนอกการ์ดขณะพลิกโชว์ด้านหลังอยู่ -> พลิกกลับหน้าเดิมอัตโนมัติ (pattern
  // เดียวกับ DeviceCard.jsx เป๊ะ)
  useEffect(() => {
    if (!flipped) return;
    function handleOutsideClick(event) {
      if (cardRef.current && !cardRef.current.contains(event.target)) {
        setFlipped(false);
      }
    }
    document.addEventListener("mousedown", handleOutsideClick);
    return () => document.removeEventListener("mousedown", handleOutsideClick);
  }, [flipped]);

  function handleEnterClick(event) {
    event.stopPropagation();
    setFlipped(false);
    onEnter();
  }

  function handleManageClick(event) {
    event.stopPropagation();
    setFlipped(false);
    onManageMembers(site);
  }

  function handleCopyClick(event) {
    event.stopPropagation();
    setFlipped(false);
    onCopyOrgId(site.org_id);
  }

  function handleLeaveClick(event) {
    event.stopPropagation();
    setFlipped(false);
    onLeaveModal(site);
  }

  return (
    // user รายงาน (2026-08-06): เหมือนกับ DeviceCard.jsx - onClick เดิมจำกัดไว้
    // แค่ .device-card-face-front ทำให้ padding รอบการ์ด/พื้นที่ว่างของหน้า
    // back คลิกไม่โดน - ย้ายมาไว้ที่ .device-card ชั้นนอกสุดแทนให้กดได้ทั้งการ์ด
    // จริงๆ ไม่ว่าจะโชว์หน้าไหน (ปุ่ม action ทุกปุ่มยัง stopPropagation กันไม่ให้
    // toggle ซ้อนอยู่เหมือนเดิม)
    <div
      className={`device-card${flipped ? " flipped" : ""}`}
      ref={cardRef}
      onClick={() => setFlipped((prev) => !prev)}
      onKeyDown={(event) => {
        if (event.target !== event.currentTarget) return;
        if (event.key === "Configure Devices" || event.key === " ") {
          event.preventDefault();
          setFlipped((prev) => !prev);
        }
      }}
      role="button"
      tabIndex={0}
      aria-label={`${site.site_name} site actions`}
      title={flipped ? undefined : "Click to show site actions"}
      aria-expanded={flipped}
    >
      <div className="device-card-flip-inner">
        <div className="device-card-face device-card-face-front">
          {/* same one-line rules as DeviceCard: long text is cut with "..." (full text on hover) */}
          <div className="device-card-head">
            <h3 className="site-name" title={site.site_name}>{site.site_name}</h3>
            {badge}
          </div>
          <div className="device-meta">
            <div>
              <span className="label">Created Date:</span>
              <span className="meta-value">{formatDate(site.site_created_date)}</span>
            </div>
            <div>
              <span className="label">Total Devices:</span>
              <span className="meta-value">{site.device_count}</span>
            </div>
            <div>
              <span className="label">Org ID :</span>
              <span className="meta-value" title={site.org_id}>{site.org_id}</span>
            </div>
          </div>
          {/* บอกผู้ใช้ว่าการ์ดนี้กดเพื่อพลิกดูปุ่ม action ด้านหลังได้ - เดิมมีแค่
              ขอบเขียว/ขยายตอน hover ซึ่งไม่ได้บอกว่าคลิกแล้วจะเกิดอะไร */}
          <div className="site-card-flip-hint" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12a9 9 0 1 1-3-6.7" />
              <polyline points="21 3 21 9 15 9" />
            </svg>
            Click here for actions
          </div>
        </div>

        <div className="device-card-face device-card-face-back">
          {/* canEnter=false เฉพาะสาขาที่เข้าร่วมแล้วยังไม่ได้รับอนุมัติ
              (status="pending") - เดิมคลิกการ์ดพวกนี้ไม่ทำอะไรเลย (onOpen เช็ค
              เงื่อนไขเงียบๆ) ตอนนี้ซ่อนปุ่มไปเลยให้ชัดเจนกว่าเดิมว่ายังเข้าไม่ได้ */}
          {canEnter && (
            <button type="button" className="btn btn-ghost btn-block" onClick={handleEnterClick}>
              Enter
            </button>
          )}
          {showManage && (
            <button type="button" className="btn btn-ghost btn-block" onClick={handleManageClick}>
              Site Management
            </button>
          )}
          {showLeave && (
            <button type="button" className="btn btn-ghost btn-block" onClick={handleLeaveClick}>
              {site.my_status === "pending"
                ? "Cancel Request"
                : site.my_status === "invited"
                  ? "Decline Invitation"
                  : "Leave Site"}
            </button>
          )}
          {/* แทนที่ปุ่ม "Back" เดิม (ซ้ำกับการคลิกการ์ด/คลิกนอกการ์ดที่พลิกกลับ
              อยู่แล้ว) - ย้าย Copy จากหน้า front มาเป็นปุ่มเต็มความกว้างตรงนี้ */}
          <button type="button" className="btn btn-ghost btn-block" onClick={handleCopyClick}>
            Copy Org ID
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Sites() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showJoinModal, setShowJoinModal] = useState(false);
  const [manageSite, setManageSite] = useState(null);
  const [invitations, setInvitations] = useState([]);
  const [busyInviteSiteId, setBusyInviteSiteId] = useState(null);
  const [showInvitationsModal, setShowInvitationsModal] = useState(false);
  const refreshRequestId = useRef(0);
  const refreshRef = useRef(null);

  // หน้าปัจจุบันของแต่ละชุด (เริ่มที่ 0) - แยกกันคนละตัวเพื่อให้กดเปลี่ยนหน้าชุดหนึ่ง
  // ไม่ไปรีเซ็ตอีกชุด backend รับเป็น owned_page/joined_page แยกกันอยู่แล้ว
  const [ownedPage, setOwnedPage] = useState(0);
  const [joinedPage, setJoinedPage] = useState(0);

  const [leaveSite, setLeaveSite] = useState(null);

  async function refresh(nextOwnedPage = ownedPage, nextJoinedPage = joinedPage) {
    const requestId = ++refreshRequestId.current;
    const [sitesResult, invitationsResult] = await Promise.allSettled([
      listMySites(nextOwnedPage, nextJoinedPage),
      getMyInvitations(),
    ]);
    if (requestId !== refreshRequestId.current) return;

    if (sitesResult.status === "fulfilled") {
      setData(sitesResult.value);
      setManageSite((current) => {
        if (!current) return current;
        const allSites = [
          ...sitesResult.value.owned_sites.items,
          ...sitesResult.value.joined_sites.items,
        ];
        const latestSite = allSites.find((item) => item.site_id === current.site.site_id);
        return latestSite ? { ...current, site: latestSite } : current;
      });
      setError("");
    } else {
      const err = sitesResult.reason;
      setError(err?.detail || "Failed to load sites");
    }
    if (invitationsResult.status === "fulfilled") {
      setInvitations(invitationsResult.value);
    }
  }

  refreshRef.current = refresh;

  // โหลดใหม่ทุกครั้งที่เปลี่ยนหน้าของชุดใดชุดหนึ่ง (การแบ่งหน้าทำที่ database
  // ไม่ใช่ตัดอาร์เรย์ฝั่ง browser จึงต้องยิงขอข้อมูลชุดใหม่จริงทุกครั้ง)
  useEffect(() => {
    refresh(ownedPage, joinedPage);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ownedPage, joinedPage]);

  // Site/member events are database-backed and do not have a browser push channel.
  // Poll only while the tab is visible, plus refresh immediately when the user
  // returns to the tab. This removes the need for a manual browser refresh while
  // avoiding overlapping responses overwriting newer state.
  useEffect(() => {
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
    const intervalId = window.setInterval(refreshVisible, 3000);
    window.addEventListener("focus", refreshVisible);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      window.clearInterval(intervalId);
      window.removeEventListener("focus", refreshVisible);
      document.removeEventListener("visibilitychange", refreshVisible);
      refreshRequestId.current += 1;
    };
  }, []);

  async function handleAcceptInvitation(siteId) {
    setBusyInviteSiteId(siteId);
    try {
      await acceptInvitation(siteId);
      await refresh();
    } catch (err) {
      setError(err.detail || "Failed to accept invitation");
    } finally {
      setBusyInviteSiteId(null);
    }
  }

  async function handleRejectInvitation(siteId) {
    setBusyInviteSiteId(siteId);
    try {
      await rejectInvitation(siteId);
      await refresh();
    } catch (err) {
      setError(err.detail || "Failed to reject invitation");
    } finally {
      setBusyInviteSiteId(null);
    }
  }

  function handleOpen(siteId) {
    navigate(`/devices?site_id=${encodeURIComponent(siteId)}`);
  }

  // สร้างเสร็จแล้วพาเข้า site ใหม่ทันที (ผู้สร้างเป็น Owner เข้าได้เลยไม่ต้องรออนุมัติ)
  // แทนที่จะกลับมาให้หาการ์ดแล้วพลิกกด Enter เอง - toast อยู่ที่ระดับ App
  // (ToastContainer) จึงยังโชว์ต่อหลังเปลี่ยนหน้า · ถ้า response ไม่มี site_id
  // (ไม่ควรเกิด) ถอยไปพฤติกรรมเดิมคือรีเฟรชรายการอยู่หน้านี้
  function handleCreated(site) {
    setShowCreateModal(false);
    window.dispatchEvent(new CustomEvent("toast:success", {
      detail: { message: `Site "${site?.site_name || ""}" created successfully`, duration: 3000 },
    }));
    if (site?.site_id) {
      handleOpen(site.site_id);
      return;
    }
    setOwnedPage(0);
    refresh(0, joinedPage);
  }

  async function handleCopyOrgId(orgId) {
    if (await copyText(orgId)) {
      window.dispatchEvent(new CustomEvent("toast:success", {
        detail: `Copied "${orgId}" to clipboard`,
      }));
    } else {
      setError("Failed to copy Org ID to clipboard");
    }
  }

  function statusBadge(status) {
    if (status === "approved") return <span className="badge badge-active">Active</span>;
    if (status === "invited") return <span className="badge badge-pending">Invited</span>;
    return <span className="badge badge-pending">Pending</span>;
  }

  return (
    <div className="app-shell">
      <TopBar />
      <main className="main-content">
        <div className="page-header">
          <div>
            <h1>Site Management</h1>
          </div>
          <div className="page-header-buttons">
            <button type="button" className="btn btn-ghost" onClick={() => setShowJoinModal(true)}>
              Search & Join Site
            </button>
            <button type="button" className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
              + Create New Site
            </button>
          </div>
        </div>

        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

        {data === null && !error && <div className="center-loading">Loading...</div>}


        {data && (
          <>
            <section className="site-section">
              <div className="site-section-header">
                <h2>Owned Sites</h2>
                <Pagination
                  hasPrev={ownedPage > 0}
                  hasNext={data.owned_sites.has_next}
                  onPrev={() => setOwnedPage((page) => Math.max(0, page - 1))}
                  onNext={() => setOwnedPage((page) => page + 1)}
                />
              </div>

              {data.owned_sites.items.length === 0 ? (
                <div className="empty-state">
                  <h3>{ownedPage > 0 ? "No more sites on this page" : "No owned sites yet"}</h3>
                  <p>
                    {ownedPage > 0
                      ? 'Click "←" to go to the previous page'
                      : 'Click "+ Create New Site" to create your first site'}
                  </p>
                </div>
              ) : (
                <div className="device-grid">
                  {data.owned_sites.items.map((site) => (
                    <SiteCard
                      key={site.site_id}
                      site={site}
                      badge={<span className="badge badge-active">Owner</span>}
                      canEnter
                      onEnter={() => handleOpen(site.site_id)}
                      onCopyOrgId={handleCopyOrgId}
                      onManageMembers={(s) => setManageSite({ site: s, isOwner: true })}
                      showManage
                    />
                  ))}
                </div>
              )}
            </section>

            {/* หมวดนี้ backend กรอง site ที่ตัวเองเป็นเจ้าของออกให้แล้ว (ดู
            list_joined_site_memberships ใน crud_site.py - เจอบั๊กจริงว่า
            สาขาที่เป็นเจ้าของโผล่ซ้ำที่นี่ด้วย ตั้งแต่ create_site() เริ่มเพิ่ม
            แถว Site_Member ให้เจ้าของเองด้วย) ไม่ต้องกรองซ้ำฝั่ง frontend อีก */}
            <section className="site-section">
              <div className="site-section-header">
                <h2>Joined Sites</h2>
                <Pagination
                  hasPrev={joinedPage > 0}
                  hasNext={data.joined_sites.has_next}
                  onPrev={() => setJoinedPage((page) => Math.max(0, page - 1))}
                  onNext={() => setJoinedPage((page) => page + 1)}
                />
              </div>

              {data.joined_sites.items.length === 0 ? (
                <div className="empty-state">
                  <h3>{joinedPage > 0 ? "No more sites on this page" : "No joined sites yet"}</h3>
                  <p>
                    {joinedPage > 0
                      ? 'Click "←" to go to the previous page'
                      : 'Click "Search & Join Site" to find and join sites using Org ID'}
                  </p>
                </div>
              ) : (
                <div className="device-grid">
                  {data.joined_sites.items.map((site) => (
                    <SiteCard
                      key={site.site_id}
                      site={site}
                      badge={site.my_status === "approved" && site.my_role === "admin"
                        ? <span className="badge badge-active">Admin</span>
                        : statusBadge(site.my_status)}
                      canEnter={site.my_status === "approved"}
                      onEnter={() => handleOpen(site.site_id)}
                      onCopyOrgId={handleCopyOrgId}
                      onManageMembers={(s) => setManageSite({ site: s, isOwner: false })}
                      showManage={site.my_status === "approved" && site.my_role === "admin"}
                      showLeave
                      onLeaveModal={(s) => setLeaveSite({ site: s })}
                    />
                  ))}
                </div>
              )}
            </section>
          </>
        )}

        {/* แถบสรุปคำเชิญ - ย้ายมาไว้ล่างสุดต่อจาก Joined Site และแสดงตลอดเวลาแม้ไม่มีคำเชิญ
            อยู่นอกบล็อก {data && ...} เพราะคำเชิญมาคนละ API กับรายการสาขา จึงยังแสดงได้
            แม้ตอนที่รายการสาขายังโหลดไม่เสร็จ - ความสูงคงที่ 1 บรรทัดเสมอไม่ว่าจะมีคำเชิญ
            กี่รายการ รายละเอียด/ปุ่มตอบรับ-ปฏิเสธ อยู่ใน InvitationsModal */}
        <div className="site-invitations-summary">
          <span>
            {invitations.length > 0 ? (
              <>
                You have <strong>{invitations.length}</strong> pending site {invitations.length === 1 ? "invitation" : "invitations"}
              </>
            ) : (
              "No pending site invitations"
            )}
          </span>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setShowInvitationsModal(true)}
          >
            View Invitations
          </button>
        </div>
      </main>

      {showCreateModal && (
        <CreateSiteModal onClose={() => setShowCreateModal(false)} onCreated={handleCreated} />
      )}
      {showJoinModal && (
        <SearchJoinSiteModal 
          onClose={() => setShowJoinModal(false)} 
          onRefresh={refresh}
        />
      )}
      {manageSite && (
        <SiteSettingsModal
          site={manageSite.site}
          isOwner={manageSite.isOwner}
          onClose={() => setManageSite(null)}
          onSiteChanged={refresh}
        />
      )}
      {leaveSite && (
        <LeaveSiteModal
          site={leaveSite.site}
          onClose={() => setLeaveSite(null)}
          onSiteLeave={refresh}
        />
      )}
      {showInvitationsModal && (
        <InvitationsModal
          invitations={invitations}
          busyInviteSiteId={busyInviteSiteId}
          onAccept={handleAcceptInvitation}
          onReject={handleRejectInvitation}
          onClose={() => setShowInvitationsModal(false)}
        />
      )}
    </div>
  );
}
