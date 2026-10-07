import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { runDeviceCommand } from "../../../api/api_devices";
import NatFormModal from "./natFormModal";
import { ciscoNatOutboundInterfaces } from "./ciscoNatInterfaces";
import Edit_Result from "../../commandResult/edit_command_result";
import { teardownCurrentNat, parseNatInterfaceState } from "./natTeardown";
import { isLastRuleInSet } from "./staticNatRuleSet";
import { juniperSourceNatKey, parseJuniperSourceNat } from "./juniperSourceNatParser";
import { parseCiscoNatScopes } from "./ciscoNatAclScopes";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// (2026-09) err.detail ของ get_nat_dashboard/create_nat_policy/remove_nat_policy
// timeout เปลี่ยนเป็น {code, message} แทนสตริงเปล่า (ดู device_router.py's
// NETCONF_READ_TIMEOUT/NETCONF_WRITE_OUTCOME_UNKNOWN) - เรนเดอร์ object ตรงๆ ใน
// JSX จะ throw ("Objects are not valid as a React child") ต้องดึง .message ออกมา
// ก่อนเสมอ - คำสั่งอื่นที่ detail ยังเป็นสตริงปกติผ่านไม่เปลี่ยนพฤติกรรม
function errorMessage(err, fallback) {
  const detail = err?.detail;
  if (detail && typeof detail === "object") return detail.message || fallback;
  return detail || fallback;
}

// Junos: security/nat/source/rule-set - ตรงกับที่ set_nat เขียน (rewrite รอบนี้
// เลิกใช้ create_nat_policy แล้ว - ดู comment ที่ JuniperNatPage ด้านล่าง) -
// then/source-nat มี "pool" (pool mode) หรือ "interface" (interface mode,
// presence tag) - Junos ไม่มี concept "overload" แยก toggle (source NAT ผ่าน
// interface/pool เป็น PAT/overload เสมอโดย default ไม่มีทางเลือกอื่น) เลยโชว์
// overload=true เสมอ - target ของ interface mode โชว์ชื่อ to-zone แทนชื่อ
// interface ตรงๆ เพราะ rule ไม่ได้อ้างอิง interface name โดยตรง (Junos NAT ผูก
// กับ zone เสมอ ไม่ใช่ interface) - config ที่ระบบสร้างเองยังใช้ชื่อ rule-set กับ
// rule เหมือนกัน แต่ brownfield config สามารถมีหลาย rule อยู่ใต้ rule-set เดียวได้
// จึงต้องเก็บ identity จริงเป็นคู่ ruleSet+rule name; parser แยกไว้ใน
// juniperSourceNatParser.js แบบเดียวกับ Static NAT/Port Forwarding
// อ่านสดจากอุปกรณ์ตรงๆ (get_nat_information) - โครงสร้างตรงกับที่ create_nat_policy/
// set_nat เขียน: inside/source มีได้ 2 แบบคู่กัน (list-interface กับ list-pool)
// แต่ละแบบมี list (ปกติมีแค่ 1 ตัวเพราะ NAT เป็นค่าเดียวทั้งอุปกรณ์) -> interface
// หรือ pool ปลายทาง + overload-new (presence tag - เช็ค key ไม่ใช่ value)
function parseNatRules(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperSourceNat(result);
    } catch {
      return null;
    }
  }
  try {
    const source = result?.payload?.data?.native?.ip?.nat?.inside?.source;
    if (!source) return [];
    const rows = [];
    for (const entry of ensureArray(source["list-interface"]?.list)) {
      const target = entry?.interface || {};
      rows.push({
        name: entry?.id || "",
        mode: "interface",
        target: target?.name || "",
        overload: "overload-new" in target,
      });
    }
    for (const entry of ensureArray(source["list-pool"]?.list)) {
      const target = entry?.pool || {};
      rows.push({
        name: entry?.id || "",
        mode: "pool",
        target: target?.name || "",
        overload: "overload-new" in target,
      });
    }
    return rows;
  } catch {
    return null;
  }
}

// ---------- Juniper: List + New/Edit/Delete ที่ใช้งานได้จริง ----------
// รอบนี้เลิกใช้ create_nat_policy แล้ว (เคย derive zone ปลายทางเองจาก via
// interface + สมมติ "trust" เป็น from-zone ตายตัว - ไม่ตรงกับวิธีที่ user ใช้
// zone-based NAT จริง (from/to zone ที่สร้างเองผ่านหน้า Zone Interfaces) เลย
// เปลี่ยนไปใช้ set_nat ตรงๆ (รองรับ from zone หลายอัน + to zone เดียว ตาม
// pattern rule-set/rule ของ Junos จริง - ยืนยัน multi from-zone ผ่าน commit
// check บนอุปกรณ์จริงแล้ว 2026-07-29) ตาราง/ปุ่ม New คงเดิมตามที่ตกลง เพิ่มแค่
// Edit/Delete ที่ใช้งานได้จริง โดย Edit ใช้ replace เฉพาะ rule ใน RPC เดียว และ
// Delete ลบเฉพาะ rule จนกว่าจะเหลือตัวสุดท้ายจึงลบทั้ง rule-set
function JuniperNatPage({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_nat_information");
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedKey, setSelectedKey] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  if (loading && !data) return <div className="center-loading">Loading NAT data...</div>;

  function handleSaved() {
    setFormMode(null);
    setSelectedKey(null);
    refetch();
  }

  const rules = data?.normalized ? parseNatRules(data.result) : null;
  const selectedRule = rules?.find((rule) => juniperSourceNatKey(rule) === selectedKey) || null;

  async function handleConfirmDelete() {
    if (!selectedRule) return;
    setDeleting(true);
    setDeleteError("");
    try {
      await runDeviceCommand(devId, "remove_nat", {
        rule_set: selectedRule.ruleSet,
        ...(isLastRuleInSet(rules, selectedRule) ? {} : { rule_name: selectedRule.name }),
      });
      setShowDeleteConfirm(false);
      setSelectedKey(null);
      refetch();
    } catch (err) {
      setDeleteError(err.detail || "Failed to delete NAT");
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {formMode ? (
        <NatFormModal
          devId={devId}
          vendor="juniper"
          mode={formMode}
          editTarget={formMode === "edit" ? selectedRule : null}
          allRows={rules || []}
          onSaved={handleSaved}
          onClose={() => setFormMode(null)}
        />
      ) : rules === null ? (
        data && <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
      ) : (
        <>
          <div className="command-output-title">
            <Edit_Result
              featureName="NAT"
              selectedLabel={selectedRule?.name || ""}
              canEdit={!!selectedRule}
              canDelete={!!selectedRule}
              showDeleteConfirm={showDeleteConfirm}
              deleting={deleting}
              deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
              onNew={() => setFormMode("create")}
              onEditClick={() => setFormMode("edit")}
              onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
              onCancelDelete={() => setShowDeleteConfirm(false)}
              onConfirmDelete={handleConfirmDelete}
              refreshing={loading}
              onRefresh={refetch}
            />
          </div>

          {rules.length === 0 ? (
            <div className="config-placeholder">No NAT configured</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>NAT Name</th>
                  <th>Translate Via</th>
                  <th>Target</th>
                  <th>Overload</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, index) => (
                  <tr
                    key={`${juniperSourceNatKey(rule)}-${index}`}
                    className={`row-clickable ${juniperSourceNatKey(rule) === selectedKey ? "row-selected" : ""}`}
                    onClick={() => {
                      const key = juniperSourceNatKey(rule);
                      setSelectedKey(key === selectedKey ? null : key);
                    }}
                  >
                    <td>{rule.name || "-"}</td>
                    <td>{rule.mode === "interface" ? "WAN IP" : "NAT Pool"}</td>
                    <td>{rule.target || "-"}</td>
                    <td>{rule.overload ? "Yes" : "No"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}

// ---------- Cisco: หน้าใหม่ - toggle "Enable NAT" เดียว ไม่มีตาราง/New/Edit/
// Delete อีกแล้ว (NAT เป็นค่าเดียวทั้งอุปกรณ์ - เหมือน dns.jsx) ----------
// ดึงข้อมูลด้วย get_nat_dashboard เดียว (รวม nat/switchport/interface-brief ที่
// เคยเป็น 3 round-trip แยกไว้ในคำขอเดียว - ลด latency ลงประมาณ 3 เท่า โดยเฉพาะ
// ตอนเน็ตช้า/latency สูง ที่แต่ละ round-trip โดนคูณเต็มๆ)
function CiscoNatPage({ devId }) {
  // (2026-09) dedupeInFlight: true - หลาย trigger ยิง refetch พร้อมกันได้ (auto-load
  // แรก, device:state-changed จาก write ที่ล้มเหลว, ปุ่ม Refresh ของผู้ใช้) โดยไม่
  // ต้องยิง get_nat_dashboard ซ้อนกันหลาย request ที่ backend/อุปกรณ์ตัวเดียวกัน -
  // ใช้ inFlightRequests ที่ hook มีอยู่แล้ว (เดิมเป็น opt-in ที่ไม่มีใครเปิดใช้)
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_nat_dashboard", { dedupeInFlight: true });

  const [formOpen, setFormOpen] = useState(false);
  const [showDisableConfirm, setShowDisableConfirm] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [disableError, setDisableError] = useState("");

  const rules = data?.normalized ? parseNatRules(data.result) : null;
  const hasNat = Array.isArray(rules) && rules.length > 0;
  const currentRule = hasNat ? rules[0] : null;

  const switchportRows = data?.normalized && Array.isArray(data.result?.switchport) ? data.result.switchport : [];
  const { insideNames, outsideName } = parseNatInterfaceState(switchportRows);
  const outboundInterfaces = ciscoNatOutboundInterfaces(switchportRows, outsideName);
  const ifaceRows = data?.normalized ? data.result?.interfaces || [] : [];
  // (2026-09) ห้ามเปิดฟอร์มให้ Save ทับ ACL เดิมถ้าอ่านค่าจริงมาไม่ครบ - 2 เหตุผลที่
  // ทำให้ "อ่านไม่ครบ": (1) backend หาไม่เจอ ACL ที่ NAT rule อ้างถึงบนอุปกรณ์เลย (ดู
  // device_router.py's nat_dashboard_acl_missing) (2) parseCiscoNatScopes เจอ ACL
  // แบบ standard หรือ permit rule ที่ parser ไม่รู้จักรูปแบบ (ดู ciscoNatAclScopes.js)
  const aclLookupFailed = Boolean(data?.normalized && data.result?.aclLookupFailed);
  const parsedAclScopes = data?.normalized && currentRule?.name && !aclLookupFailed
    ? parseCiscoNatScopes(data.result, currentRule.name)
    : { scopes: [], unreadable: false };
  const aclUnreadable = aclLookupFailed || parsedAclScopes.unreadable;
  const aclScopes = parsedAclScopes.scopes;

  // sync toggle ให้ตรงกับสถานะจริงเสมอตอนโหลด/รีเฟรช (เหมือน dns.jsx) - เปิดฟอร์ม
  // ให้เองถ้ามี NAT อยู่แล้ว ไม่ต้องกดเปิดซ้ำ - ทำงานแค่ตอน hasNat เปลี่ยนค่าจริง
  // (ไม่ทับ state ตอน user เปิดฟอร์มเองเพื่อสร้างใหม่ระหว่างที่ยังไม่มี NAT)
  useEffect(() => {
    if (Array.isArray(rules)) setFormOpen(hasNat);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasNat]);

  function handleSaved() {
    refetch();
  }

  function handleToggleClick() {
    if (!formOpen) {
      // ปิด -> เปิด: แค่โชว์ฟอร์มให้กรอก ยังไม่ยิงอะไรจนกว่าจะกด Apply
      setFormOpen(true);
      return;
    }
    if (!hasNat) {
      // ฟอร์มเปิดอยู่แต่ยังไม่เคย Apply จริง (ไม่มี NAT อยู่จริง) - กดปิดก็แค่ซ่อนฟอร์ม
      setFormOpen(false);
      return;
    }
    // มี NAT จริงอยู่ - กดปิด = ต้องการรื้อทิ้งจริง กระทบ traffic ทันที ต้องยืนยันก่อน
    setShowDisableConfirm(true);
  }

  async function handleConfirmDisable() {
    setDisabling(true);
    setDisableError("");
    try {
      await teardownCurrentNat(devId, { currentRule, insideNames, outsideName });
      setShowDisableConfirm(false);
      refetch();
    } catch (err) {
      setDisableError(errorMessage(err, "Failed to disable NAT"));
    } finally {
      setDisabling(false);
    }
  }

  if (loading && !data) return <div className="center-loading">Loading NAT data...</div>;

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      <div className="interface-configuration-form">
        <div className="interface-configuration-form-field">
          <label className="data-label">Enable NAT</label>
          <div className="toggle-switch-container">
            <input type="checkbox" id="nat-enable-toggle" checked={formOpen} onChange={handleToggleClick} />
            <label className="toggleSwitch" htmlFor="nat-enable-toggle"></label>
          </div>
        </div>
        {formOpen &&
            (rules === null ? (
              data && <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
            ) : aclUnreadable ? (
              // (2026-09) fail closed - ห้ามเปิดฟอร์มแก้ไขจนกว่าจะอ่าน ACL เดิมได้
              // ครบ ไม่งั้น Save จะเขียนทับ ACL เดิม (ที่อ่านไม่ครบตอนนี้) ด้วย ACL
              // ใหม่ที่ backend สร้างจากค่าที่ฟอร์มเห็น (ว่างเปล่า = ตีความเป็น Any)
              <div className="form-error">
                Cannot reliably read this NAT rule's existing ACL ({currentRule?.name || "unknown"}) from the device -
                it may have been removed outside this system, or it uses an ACL format this page does not support
                yet (e.g. a standard ACL, or match criteria other than any/host/network). Editing is disabled until
                this is resolved, to avoid overwriting the existing ACL. Please verify the ACL on the device.
              </div>
            ) : (
              <NatFormModal
                devId={devId}
                vendor="cisco"
                currentRule={currentRule}
                insideNames={insideNames}
                outsideName={outsideName}
                outboundInterfaces={outboundInterfaces}
                ifaceRows={ifaceRows}
                aclScopes={aclScopes}
                onSaved={handleSaved}
              />
            ))}
      </div>

      {showDisableConfirm && (
        <div className="modal-overlay" onClick={() => !disabling && setShowDisableConfirm(false)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Confirm Disabling NAT</h2>
              <button
                type="button"
                className="modal-close"
                onClick={() => setShowDisableConfirm(false)}
                aria-label="Close"
                disabled={disabling}
              >
                &times;
              </button>
            </div>
            <p>Are you sure you want to disable NAT? (This will remove ACL + NAT rule + ip nat inside/outside on all associated interfaces)</p>
            {disableError && <DismissibleError message={disableError} onDismiss={() => setDisableError("")} />}
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setShowDisableConfirm(false)}
                disabled={disabling}
              >
                Cancel
              </button>
              <button type="button" className="btn btn-primary" onClick={handleConfirmDisable} disabled={disabling}>
                {disabling ? "Disabling..." : "Disable NAT"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Nat({ devId, vendor }) {
  if (vendor === "juniper") return <JuniperNatPage devId={devId} />;
  return <CiscoNatPage devId={devId} />;
}
