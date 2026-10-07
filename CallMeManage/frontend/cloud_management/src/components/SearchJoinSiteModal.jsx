import DismissibleError from "./DismissibleError";
import { useState } from "react";
import { joinSite, lookupSiteByOrgId } from "../api/api_sites";

// หน้า Sites.jsx - ปุ่ม "ค้นหาและเข้าร่วมไซต์ (Join Site)" เปิด modal นี้ -
// พิมพ์ Org ID (ต้องตรงเป๊ะ) แล้วกดค้นหา โชว์ผลลัพธ์เป็น card ย่อ (ชื่อ/วันที่
// สร้าง/จำนวนอุปกรณ์) แล้วกด "ขอเข้าร่วม" (สร้าง Site_Member status="pending"
// รอเจ้าของ/Admin อนุมัติ - ดู planning/rbac.md ข้อ 8.4)
//
// เดิมค้นได้ทั้ง org_id และชื่อสาขาแบบ "มีคำนี้อยู่ตรงไหนก็ได้" ซึ่งทำให้ผู้ใช้คนไหน
// ก็กวาดรายชื่อสาขาของทุกองค์กรในระบบออกมาดูได้ - เปลี่ยนเป็นค้นด้วย Org ID ตรงเป๊ะ
// อย่างเดียว โดย Org ID ทำหน้าที่เหมือนรหัสเชิญที่เจ้าของสาขาส่งให้คนที่ต้องการชวนเข้าร่วม
export default function SearchJoinSiteModal({ onClose, onRefresh }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState(null);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState("");
  const [joiningSiteId, setJoiningSiteId] = useState(null);
  const [joinedSiteIds, setJoinedSiteIds] = useState(new Set());
  const [joinMessage, setJoinMessage] = useState("");

  async function handleSearch(event) {
    event.preventDefault();
    if (!query.trim()) return;
    setError("");
    setJoinMessage("");
    setSearching(true);
    try {
      setResults(await lookupSiteByOrgId(query.trim()));
    } catch (err) {
      setError(err.detail || "Failed to search site");
      setResults(null);
    } finally {
      setSearching(false);
    }
  }

  async function handleJoin(siteId) {
    setJoiningSiteId(siteId);
    setError("");
    setJoinMessage("");
    try {
      const result = await joinSite(siteId);
      setJoinMessage(result.detail || "Join request sent successfully");
      setJoinedSiteIds((prev) => new Set(prev).add(siteId));
      onRefresh()
    } catch (err) {
      setError(err.detail || "Failed to send join request");
    } finally {
      setJoiningSiteId(null);
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <h2>Search & Join Site</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            &times;
          </button>
        </div>

        <form onSubmit={handleSearch}>
          <div className="field">
            <label htmlFor="site-search-query">Organization ID (Org ID)</label>
            <input
              id="site-search-query"
              type="text"
              placeholder="ORG-8821"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              autoFocus
            />
          </div>
          <button type="submit" className="btn btn-primary btn-block" disabled={searching}>
            {searching ? "Searching..." : "Search"}
          </button>
        </form>

        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
        {joinMessage && <div className="config-placeholder">{joinMessage}</div>}

        {results !== null && (
          <div style={{ marginTop: "16px", display: "flex", flexDirection: "column", gap: "10px" }}>
            {results.length === 0 ? (
              <div className="config-placeholder">No site found with this Org ID. Please check the spelling and try again.</div>
            ) : (
              results.map((site) => (
                <div key={site.site_id} className="device-meta" style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "10px 12px" }}>
                  <div>
                    <span className="label">Name : </span>
                    {site.site_name}
                  </div>
                  <div>
                    <span className="label">Org ID : </span>
                    {site.org_id}
                  </div>
                  <button
                    type="button"
                    className="btn btn-ghost btn-block"
                    disabled={joiningSiteId === site.site_id || joinedSiteIds.has(site.site_id)}
                    onClick={() => handleJoin(site.site_id)}
                    style={{ marginTop: "8px" }}
                  >
                    {joinedSiteIds.has(site.site_id)
                      ? "Request Sent"
                      : joiningSiteId === site.site_id
                        ? "Sending Request..."
                        : "Request to Join"}
                  </button>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
