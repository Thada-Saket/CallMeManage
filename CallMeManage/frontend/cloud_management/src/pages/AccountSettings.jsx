import DismissibleError from "../components/DismissibleError";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import TopBar from "../components/TopBar";
import DeleteAccountModal from "../components/DeleteAccountModal";
import { Pagination } from "../components/Pagination";
import { useAuth } from "../context/AuthContext";
import { getMyProfile } from "../api/api_users";
import { listMySites } from "../api/api_sites";
import "../assets/css/accountSettings.css";

// |====== Account Setting Page ======|

// แปลงเวลา iso เป็นเวลาของไทย
function formatDate(iso) {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}

// ส่งออกเป็น html แถบ site ในหน้า profile ว่าเป็น site เข้าร่วมหรือเป็นเจ้าของ และมีแต่ละชนิดทั้งหมดกี่ site สามารถ dropdown เพื่อดูได้
function SiteCountRow({
  label,
  sites,
  items: itemsProp,
  totalCount: totalCountProp,
  expanded,
  onToggle,
  emptyText,
  hasPrev = false,
  hasNext = false,
  onPrev,
  onNext,
}) {
  // รองรับทั้งแบบส่ง items + totalCount หรือส่ง pagination object ผ่าน sites
  let items = itemsProp;
  let totalCount = totalCountProp;
  if (items === undefined && sites !== undefined) {
    if (Array.isArray(sites)) {
      items = sites;
      totalCount = sites.length;
    } else if (sites && typeof sites === "object") {
      items = sites.items;
      totalCount = sites.total_count ?? (Array.isArray(sites.items) ? sites.items.length : 0);
    }
  }

  const count = typeof totalCount === "number"
    ? totalCount
    : (Array.isArray(items) ? items.length : 0);

  const isMalformed = items !== undefined && !Array.isArray(items);

  return (
    <div className="account-sites-group">
      <button
        type="button"
        className="account-sites-row"
        onClick={onToggle}
        aria-expanded={expanded}
      >
        <span className={`account-sites-arrow${expanded ? " expanded" : ""}`} aria-hidden="true" />
        <span className="account-sites-label">{label}</span>
        <span className="account-sites-count">{count}</span>
      </button>
      {expanded && (
        <>
          <ul className="account-sites-list">
            {isMalformed ? (
              <li className="account-sites-empty">Invalid site list format</li>
            ) : !items || items.length === 0 ? (
              <li className="account-sites-empty">{emptyText}</li>
            ) : (
              items.map((site) => (
                <li key={site.site_id || site.org_id || site.site_name}>
                  {site.site_name}
                </li>
              ))
            )}
          </ul>
          {(hasPrev || hasNext) && (
            <div className="account-sites-pagination">
              <Pagination
                hasPrev={hasPrev}
                hasNext={hasNext}
                onPrev={onPrev}
                onNext={onNext}
              />
            </div>
          )}
        </>
      )}
    </div>
  );
}

// หน้าตั้งค่าบัญชี (spec ข้อ 3.1) - user ขอ (2026-08-06): ออกแบบใหม่ทั้งหมดให้
// หน้าตาเหมือนหน้า User Management ทั่วไป (avatar+ชื่อ/อีเมลด้านบน, panel
// ข้อมูลบัญชีแบบ label/value, โซนอันตรายแยกเป็น panel สีแดงจางๆ ของตัวเอง) -
// ใช้ CSS ใหม่ทั้งไฟล์ (accountSettings.css) แทนการ reuse .device-card/
// .page-header เดิม - อ่านอย่างเดียว ไม่มีฟอร์มแก้ไขในรอบนี้

// เรียกใช้ใน App.jsx
export default function AccountSettings() {
  const navigate = useNavigate(); // redirect หน้า
  const { logout } = useAuth(); // logout function
  const [profile, setProfile] = useState(null); // ตัวแปรเก็บค่า profile
  const [error, setError] = useState(""); // ตัวแปรเก็บค่า error
  const [showDeleteModal, setShowDeleteModal] = useState(false); // ตัวแปร boolean แสดงผล popup การลบบัญชี
  const [sites, setSites] = useState(null); // ตัวแปรเก็บ site ที่เกี่ยวข้องทั้งหมด
  const [sitesLoading, setSitesLoading] = useState(false); // สถานะกำลังโหลดรายการ site
  const [sitesError, setSitesError] = useState(""); // error จากการโหลดรายการ site
  const [ownedPage, setOwnedPage] = useState(0); // หน้าของ site ที่เป็นเจ้าของ
  const [joinedPage, setJoinedPage] = useState(0); // หน้าของ site ที่เข้าร่วม
  const [expandedOwned, setExpandedOwned] = useState(false); // ตัวแปร boolean เก็บสถานะการย่อขยายดูรายชื่อ site ที่เป็นเจ้าของ
  const [expandedJoined, setExpandedJoined] = useState(false); // ตัวแปร boolean เก็บสถานะการย่อขยายดูรายชื่อ site ที่เป็นเข้าร่วม

  const sitesReqSeqRef = useRef(0);

  // ฟังก์ชั่นดึงรายการ site แยกตามหน้าที่ระบุ พร้อมป้องกัน race condition เมื่อผู้ใช้กดเปลี่ยนหน้าเร็ว
  const loadSites = (oPage = ownedPage, jPage = joinedPage) => {
    const seq = ++sitesReqSeqRef.current;
    setSitesLoading(true);
    setSitesError("");
    listMySites(oPage, jPage)
      .then((res) => {
        if (seq === sitesReqSeqRef.current) {
          setSites(res);
          setSitesLoading(false);
        }
      })
      .catch((err) => {
        if (seq === sitesReqSeqRef.current) {
          setSitesError(err.detail || "Failed to load sites");
          setSitesLoading(false);
        }
      });
  };

  useEffect(() => {
    // ดึง profile ของตัวเองมาจากหลังบ้าน แล้วเก็บไว้ในตัวแปร profile
    getMyProfile()
      .then(setProfile)
      .catch((err) => setError(err.detail || "Failed to load account profile"));
  }, []);

  useEffect(() => {
    loadSites(ownedPage, joinedPage);
  }, [ownedPage, joinedPage]);

  // ฟังก์ชั่นที่จะทำงานหลังจากผู้ใช้ลบบัญชีผู้ใช้
  function handleDeleted() {
    setShowDeleteModal(false);
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="app-shell">
      <TopBar />
      <main className="main-content">
        <div className="account-page">
          {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

          {profile === null && !error && <div className="center-loading">Loading...</div>}

          {profile && (
            <>
              <div className="account-header">
                <div className="account-avatar">{profile.usr_name.charAt(0).toUpperCase()}</div>
                <div className="account-header-info">
                  <div className="account-name">{profile.usr_name}</div>
                  <div className="account-email">{profile.usr_email}</div>
                </div>
              </div>

              <section className="account-panel">
                <h2 className="account-panel-title">Account Information</h2>
                <dl className="account-info-list">
                  <div className="account-info-row">
                    <dt>Username</dt>
                    <dd>{profile.usr_name}</dd>
                  </div>
                  <div className="account-info-row">
                    <dt>Email</dt>
                    <dd>{profile.usr_email}</dd>
                  </div>
                  <div className="account-info-row">
                    <dt>Member Since</dt>
                    <dd>{formatDate(profile.usr_created_date)}</dd>
                  </div>
                </dl>
              </section>

              <section className="account-panel">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
                  <h2 className="account-panel-title" style={{ margin: 0 }}>My Sites</h2>
                  {sitesLoading && <span className="account-sites-loading-indicator">Loading...</span>}
                </div>
                {sitesError ? (
                  <div className="account-sites-error">
                    <span>{sitesError}</span>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      style={{ padding: "4px 10px", fontSize: "12px" }}
                      onClick={() => loadSites(ownedPage, joinedPage)}
                    >
                      Retry
                    </button>
                  </div>
                ) : !sites && sitesLoading ? (
                  <div className="center-loading" style={{ padding: "16px 0", fontSize: "13px" }}>
                    Loading site data...
                  </div>
                ) : sites ? (
                  <div className="account-sites-summary">
                    <SiteCountRow
                      label="Owned Sites"
                      items={sites.owned_sites?.items}
                      totalCount={sites.owned_sites?.total_count}
                      expanded={expandedOwned}
                      onToggle={() => setExpandedOwned((prev) => !prev)}
                      emptyText="No owned sites yet"
                      hasPrev={ownedPage > 0}
                      hasNext={Boolean(sites.owned_sites?.has_next)}
                      onPrev={() => setOwnedPage((prev) => Math.max(0, prev - 1))}
                      onNext={() => setOwnedPage((prev) => prev + 1)}
                    />
                    <SiteCountRow
                      label="Joined Sites"
                      items={sites.joined_sites?.items}
                      totalCount={sites.joined_sites?.total_count}
                      expanded={expandedJoined}
                      onToggle={() => setExpandedJoined((prev) => !prev)}
                      emptyText="No joined sites yet"
                      hasPrev={joinedPage > 0}
                      hasNext={Boolean(sites.joined_sites?.has_next)}
                      onPrev={() => setJoinedPage((prev) => Math.max(0, prev - 1))}
                      onNext={() => setJoinedPage((prev) => prev + 1)}
                    />
                  </div>
                ) : null}
              </section>

              <section className="account-panel account-panel-danger">
                <h2 className="account-panel-title">Danger Zone</h2>
                <div className="account-danger-row">
                  <div>
                    <div className="account-danger-title">Delete Account</div>
                    <p className="account-danger-desc">
                      Deleting your account is permanent and cannot be undone. If you own any sites, you must transfer ownership or delete them first.
                    </p>
                  </div>
                  <button type="button" className="btn btn-danger" onClick={() => setShowDeleteModal(true)}>
                    Delete
                  </button>
                </div>
              </section>
            </>
          )}
        </div>
      </main>

      {showDeleteModal && (
        <DeleteAccountModal onClose={() => setShowDeleteModal(false)} onDeleted={handleDeleted} />
      )}
    </div>
  );
}
