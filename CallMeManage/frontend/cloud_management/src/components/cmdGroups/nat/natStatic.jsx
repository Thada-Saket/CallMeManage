import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { getDeviceConfigObjects, runDeviceCommand } from "../../../api/api_devices";
import NatStaticFormModal from "./natStaticFormModal";
import Edit_Result from "../../commandResult/edit_command_result";
import { isLastRuleInSet } from "./staticNatRuleSet";
import { orphanedProxyArpRemoval } from "./proxyArpCleanup";
import { parseJuniperPortForwards } from "./juniperPortForwardParser";
import { buildImportedNameMap } from "./importedConfigNames";
import {
  juniperStaticNatKey,
  parseJuniperStaticNat,
  parseJuniperStaticRuleSets,
} from "./juniperStaticNatParser";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// (2026-09) err.detail ของ Cisco NAT family (Source/Static/Port Forward) timeout
// เปลี่ยนเป็น {code, message} แทนสตริงเปล่าสำหรับบาง error (ดู device_router.py's
// NETCONF_READ_TIMEOUT/NETCONF_WRITE_OUTCOME_UNKNOWN/NETCONF_SESSION_RECOVERING) -
// เรนเดอร์ object ตรงๆ ใน JSX จะ throw ต้องดึง .message ออกมาก่อนเสมอ - คำสั่งอื่น/
// Juniper ที่ detail ยังเป็นสตริงปกติผ่านไม่เปลี่ยนพฤติกรรม
function errorMessage(err, fallback) {
  const detail = err?.detail;
  if (detail && typeof detail === "object") return detail.message || fallback;
  return detail || fallback;
}

// Junos: security/nat/static/rule-set - ตรงกับที่ set_static_nat เขียน
// (destination-address/dst-addr = public IP ที่ traffic ขาเข้าเจอ ตรงกับ
// Cisco's global-ip, then/static-nat/prefix/addr-prefix = internal IP จริง
// ตรงกับ Cisco's local-ip) - กรอง rule ที่มี destination-port ออก (เผื่อมี
// legacy port-forward entry ที่สร้างไว้ก่อนรอบแก้ล่าสุดตกค้างอยู่ - ตอนนี้
// Port Forward ย้ายไปใช้ security/nat/destination แยกต่างหากแล้ว ไม่เขียนลง
// container นี้อีกต่อไป แต่ entry เก่าอาจยังมีอยู่จริงบนอุปกรณ์บางตัว กรองไว้
// กันโชว์ผิดที่ - ดู pf.jsx) - เจอบั๊กจริง (2026-07-30): เดิมสมมติ 1 rule-set
// ต่อ 1 rule (rule_set == rule_name == ชื่อที่ user กรอก) ใช้ `rs.name` เป็น
// identity - แต่ Junos ปฏิเสธถ้ามี 2 rule-set คนละชื่อแต่ from-zone (context)
// เดียวกัน ("rule-set X and rule-set Y have same context") เลยต้องรวมเป็น 1
// rule-set ต่อ 1 from-zone แทน (ดู staticNatRuleSet()) - identity จริงของแต่ละ
// entry ตอนนี้คือ **rule.name** (ไม่ใช่ rs.name อีกต่อไป - หลาย rule แชร์
// rs.name เดียวกันได้ปกติถ้าอยู่ zone เดียวกัน)
//
// เจอบั๊กแทรกซ้อนจากรอบแก้ก่อนหน้า (2026-07-30 รอบ 2): entry เก่าที่สร้างไว้
// ก่อนแก้ (ยุค "1 rule-set ต่อ 1 entry" - rule-set ชื่อเดียวกับ entry ตรงๆ เช่น
// "WEB-1") ยัง**อยู่ในอุปกรณ์จริงด้วยชื่อ rule-set เดิม** - ถ้า delete/edit
// handler เดา rule-set จาก `staticNatRuleSet(fromZone)` ตรงๆ (ไม่สนใจว่า
// rule-set จริงชื่ออะไร) จะได้ชื่อผิด (เช่น "STATIC-WAN") ที่ไม่ตรงกับของจริง
// บนอุปกรณ์ ("WEB-1") เลยกลายเป็น remove path ที่ไม่มีอยู่จริง - Junos "สำเร็จ"
// เงียบๆ (ok:true, no-op) แต่ไม่ได้ลบอะไรออกจริงเลย (เจอ error class เดียวกับ
// ที่เจอมาแล้วหลายรอบในเซสชันนี้ - remove path ผิดไม่ error แค่เงียบ) - แก้โดย
// เก็บ **rule-set name จริงบนอุปกรณ์** ไว้ในแต่ละแถวด้วย (`ruleSet`) ให้ทั้ง
// Delete/Edit ใช้ค่านี้ตรงๆ และส่ง context ของทุก rule-set ให้หน้า New นำชื่อจริง
// กลับมาใช้ด้วย ห้าม derive STATIC-<zone> ถ้า zone นั้นมี brownfield rule-set แล้ว
// อ่านสดจากอุปกรณ์ (get_static_nat_information) เหมือนหน้า NAT - static NAT ของ
// Cisco เป็นแค่คู่ local/global IP ไม่มี concept "ชื่อ" บนอุปกรณ์เลย ชื่อที่โชว์
// เป็นแค่ label ฝั่งเว็บเรา (เก็บผ่าน Device_Config_Object ตอนสร้างผ่านเว็บนี้ -
// ดู _track_nat_object ใน device_router.py) เลยต้อง cross-reference กับ DB แยก
// อีกที โดยจับคู่ local_ip+global_ip เป็น key - คู่ที่ตั้งผ่าน CLI ตรงๆ หรือหา
// ชื่อไม่เจอจะแสดงชื่อชั่วคราว import-static-N โดยไม่เขียนลงฐานข้อมูล
function parseStaticNat(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperStaticNat(result);
    } catch {
      return null;
    }
  }
  try {
    const list = result?.payload?.data?.native?.ip?.nat?.inside?.source?.static?.["nat-static-transport-list"];
    return ensureArray(list).map((entry) => ({
      localIp: entry?.["local-ip"] || "",
      globalIp: entry?.["global-ip"] || "",
    }));
  } catch {
    return null;
  }
}

function staticNatKey(row, isJuniper) {
  return isJuniper ? juniperStaticNatKey(row) : `${row.localIp}|${row.globalIp}`;
}

export default function NatStatic({ devId, vendor }) {
  const isJuniper = vendor === "juniper";
  // dedupeInFlight: true - initial load, React StrictMode remount, ปุ่ม Refresh
  // และ device:state-changed event (จาก write อื่นของอุปกรณ์เดียวกันที่ล้มเหลว) ที่
  // ยิงมาซ้อนกันระหว่าง request เดิมยังไม่จบ ใช้ promise เดียวกัน (ดู inFlightRequests
  // ใน getDeviceInformation.js) ไม่ยิง NETCONF ซ้ำเข้า session เดิม
  const { data, loading, error, clearError, refetch } = getDeviceInformation(
    devId, "get_static_nat_information", { dedupeInFlight: true },
  );
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedKey, setSelectedKey] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [nameMap, setNameMap] = useState(null);
  const [nameRevision, setNameRevision] = useState(0);

  useEffect(() => {
    if (!devId || isJuniper) return; // Juniper มีชื่อจริงบนอุปกรณ์อยู่แล้ว ไม่ต้อง cross-reference กับ DB
    setNameMap(null);
    getDeviceConfigObjects(devId, "static_nat")
      .then((objects) => {
        const map = {};
        for (const obj of objects) {
          const params = obj.cfg_params || {};
          if (params.local_ip && params.global_ip) {
            map[`${params.local_ip}|${params.global_ip}`] = obj.cfg_name;
          }
        }
        setNameMap(map);
      })
      .catch(() => setNameMap({})); // อ่าน DB ไม่ได้ก็ยังแสดงชื่อ import ชั่วคราวได้
  }, [devId, isJuniper, nameRevision]);

  function handleSaved() {
    setFormMode(null);
    setSelectedKey(null);
    if (!isJuniper) setNameRevision((revision) => revision + 1);
    refetch();
  }

  // Juniper: ลบทั้ง rule-set ด้วย name เดียว (identity จริงบนอุปกรณ์) / Cisco:
  // ลบด้วยคู่ local/global IP (key จริงตาม YANG)
  async function handleConfirmDelete(row) {
    setDeleting(true);
    setDeleteError("");
    try {
      if (isJuniper) {
        // ใช้ rule-set name จริงที่อ่านมาจากอุปกรณ์ (row.ruleSet) ไม่ใช่เดาจาก
        // staticNatRuleSet(fromZone) - entry เก่าที่สร้างก่อนแก้ bug "same
        // context" ยังอยู่ใน rule-set ชื่อเดิม (เช่น "WEB-1" ไม่ใช่
        // "STATIC-WAN") เดาผิดจะ remove path ที่ไม่มีจริง เงียบๆ ไม่ error แต่
        // ไม่ได้ลบอะไรออกเลย (เจอบั๊กจริงจากตรงนี้)
        //
        // เจอบั๊กจริง (รอบ 4): ถ้า row นี้เป็น rule เดียวที่เหลือใน rule-set
        // ต้องลบทั้ง rule-set (ไม่ใช่แค่ rule) ไม่งั้นจะเหลือ shell ว่างเปล่าที่
        // ยังจอง context (from-zone) ไว้ถาวร กันไม่ให้สร้าง rule-set ชื่ออื่นที่
        // zone เดียวกันได้อีกเลย (ดู isLastRuleInSet)
        // ตรวจฝั่ง Port Forward ก่อนเริ่มลบ ถ้าอ่านไม่ได้ให้คง Proxy ARP ไว้
        // อย่างปลอดภัย; ห้ามเดาว่าไม่ถูกใช้งานแล้วจนไปตัด rule อื่น
        let proxyArpRemoval = {};
        try {
          const pfResult = await runDeviceCommand(devId, "get_port_forward_information", {});
          if (pfResult?.normalized) {
            const remainingStaticRows = rows.filter((candidate) =>
              juniperStaticNatKey(candidate) !== juniperStaticNatKey(row)
            );
            proxyArpRemoval = orphanedProxyArpRemoval(
              row.globalIp,
              remainingStaticRows,
              parseJuniperPortForwards(pfResult.result),
              data.result,
            );
          }
        } catch { /* ถ้าอ่าน cross-feature ไม่ได้ ให้ลบเฉพาะ NAT โดยไม่เสี่ยงลบ Proxy ARP */ }

        if (isLastRuleInSet(rows, row)) {
          await runDeviceCommand(devId, "remove_static_nat_ruleset", {
            rule_set: row.ruleSet,
            ...proxyArpRemoval,
          });
        } else {
          await runDeviceCommand(devId, "remove_static_nat", {
            rule_set: row.ruleSet,
            rule_name: row.name,
            ...proxyArpRemoval,
          });
        }
      } else {
        await runDeviceCommand(devId, "remove_static_nat", { local_ip: row.localIp, global_ip: row.globalIp });
      }
      setShowDeleteConfirm(false);
      setSelectedKey(null);
      if (!isJuniper) setNameRevision((revision) => revision + 1);
      refetch();
    } catch (err) {
      setDeleteError(errorMessage(err, "Failed to delete Static NAT"));
    } finally {
      setDeleting(false);
    }
  }

  if (loading && !data) return <div className="center-loading">Loading Static NAT data...</div>;

  const rows = data?.normalized ? parseStaticNat(data.result) : null;
  const selectedRow = rows?.find((row) => staticNatKey(row, isJuniper) === selectedKey) || null;
  const displayNameMap = !isJuniper && rows && nameMap !== null
    ? buildImportedNameMap(rows, nameMap, (row) => staticNatKey(row, false), "import-static")
    : {};
  const selectedName = isJuniper
    ? selectedRow?.name
    : selectedRow ? displayNameMap[staticNatKey(selectedRow, false)] : undefined;

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {formMode ? (
        <NatStaticFormModal
          devId={devId}
          vendor={vendor}
          mode={formMode}
          editTarget={formMode === "edit" && selectedRow ? { ...selectedRow, name: selectedName } : null}
          allRows={rows || []}
          ruleSetContexts={
            isJuniper && data?.normalized
              ? parseJuniperStaticRuleSets(data.result)
              : []
          }
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : rows === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : (
        <>
          <div className="command-output-title">
            <Edit_Result
              featureName="Static NAT"
              selectedLabel={selectedRow ? `${selectedRow.globalIp} → ${selectedRow.localIp}` : ""}
              canEdit={!!selectedKey && (isJuniper || nameMap !== null)}
              canDelete={!!selectedKey}
              showDeleteConfirm={showDeleteConfirm}
              deleting={deleting}
              deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
              onNew={() => setFormMode("create")}
              onEditClick={() => setFormMode("edit")}
              onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
              onCancelDelete={() => setShowDeleteConfirm(false)}
              onConfirmDelete={() => handleConfirmDelete(selectedRow)}
              refreshing={loading}
              onRefresh={refetch}
            />
          </div>

          {rows.length === 0 ? (
            <div className="config-placeholder">No Static NAT configured</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Local IP</th>
                  <th>Public IP</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => {
                  const key = staticNatKey(row, isJuniper);
                  return (
                    <tr
                      key={`${key}-${index}`}
                      className={`row-clickable ${key === selectedKey ? "row-selected" : ""}`}
                      onClick={() => setSelectedKey(key === selectedKey ? null : key)}
                    >
                      <td>{isJuniper ? row.name : nameMap === null ? "-" : displayNameMap[key]}</td>
                      <td>{row.localIp || "-"}</td>
                      <td>{row.globalIp || "-"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
