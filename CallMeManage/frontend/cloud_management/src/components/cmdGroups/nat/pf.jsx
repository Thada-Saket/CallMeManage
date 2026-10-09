import DismissibleError from "../../DismissibleError";
import { NAT_RECONNECT_HINT } from "./natReconnectHint";
import { useEffect, useState } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { getDeviceConfigObjects, runDeviceCommand } from "../../../api/api_devices";
import PfFormModal from "./pfFormModal";
import Edit_Result from "../../commandResult/edit_command_result";
import { isLastRuleInSet } from "./staticNatRuleSet";
import { orphanedProxyArpRemoval } from "./proxyArpCleanup";
import { parseJuniperStaticNat } from "./juniperStaticNatParser";
import { buildImportedNameMap } from "./importedConfigNames";
import {
  parseJuniperDestinationRuleSets,
  parseJuniperPortForwards,
} from "./juniperPortForwardParser";

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

// เจอบั๊กจริง (2026-07-30 รอบ 2 - user ชี้): เดิมคิดว่า Junos ไม่แยก static NAT
// กับ port-forward เป็นคนละ container (ใช้ security/nat/static/rule-set ร่วม
// กัน ต่างกันแค่มี destination-port) - ผิด: Junos มี **security/nat/
// destination** แยกต่างหากสำหรับ port-forward โดยเฉพาะ (pool-based - แปลง
// destination port ให้ต่างจาก local port ได้อิสระผ่าน pool object) เป็นวิธีที่
// ถูกต้อง/idiomatic กว่า "static NAT with port" ที่ใช้อยู่เดิม - ยืนยันจริงกับ
// อุปกรณ์แล้วว่า syntax ที่ user ให้มาถูกต้อง (`commit check` ผ่าน) ย้ายมาใช้
// container นี้แทนทั้งหมด (ดู set_port_forward/get_port_forward_information ใน
// juniper_junos.py) - ไม่มี protocol แยกใน match เลย (ทำงานทุก protocol บน
// port นั้นๆ ไม่ระบุ tcp/udp ชัดเจนแบบ Cisco) เลยโชว์ protocol ว่างเสมอ
// เหมือนเดิม
//
// เหมือน static NAT ตรงที่ rule-set ยังถูก scope ด้วย from-zone context
// เดียวกัน (ยืนยันจริงจาก commit check บนอุปกรณ์: "rule-set X and rule-set Y
// have same context" เจอ error เดียวกันเป๊ะกับฝั่ง static NAT) เลยยังต้องรวม
// เป็น 1 rule-set ต่อ 1 from-zone เหมือนเดิม (ดู destinationNatRuleSet() -
// **คนละ namespace จาก staticNatRuleSet() โดยสิ้นเชิง** ไม่แชร์ rule-set กับ
// static NAT อีกต่อไป เพราะเป็นคนละ container กันแล้วจริงๆ) - เก็บ `ruleSet`
// (ชื่อ rule-set จริง) และ `poolName` (ชื่อ destination-nat pool ที่ผูกอยู่)
// ไว้ในแต่ละแถวด้วย ให้ Delete/Edit ใช้ค่าจริงตรงๆ ไม่เดา (บทเรียนจาก bug
// migration ที่เจอกับ static NAT รอบก่อน - เดา rule-set ผิดจะ remove path ที่
// ไม่มีจริง เงียบๆ ไม่ error แต่ไม่ได้ลบอะไรออกเลย)
// อ่านสดจากอุปกรณ์ (get_port_forward_information) เหมือนหน้า Static NAT - ไม่มี
// concept "ชื่อ" บนอุปกรณ์เลย ชื่อที่โชว์เป็นแค่ label ฝั่งเว็บเรา (เก็บผ่าน
// Device_Config_Object ตอนสร้างผ่านเว็บนี้) เลย cross-reference กับ DB แยกอีกที
// โดยจับคู่ protocol+local_ip+local_port+global_ip+global_port เป็น key รายการที่
// ไม่มีใน DB จะแสดงชื่อชั่วคราว import-portfwd-N โดยไม่ register ตอนอ่าน
function parsePortForwards(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperPortForwards(result);
    } catch {
      return null;
    }
  }
  try {
    const list =
      result?.payload?.data?.native?.ip?.nat?.inside?.source?.static?.[
        "nat-static-transport-list-port-fwd"
      ];
    return ensureArray(list).map((entry) => ({
      protocol: entry?.protocol || "",
      localIp: entry?.["local-ip"] || "",
      localPort: entry?.["local-port"] || "",
      globalIp: entry?.["global-ip"] || "",
      globalPort: entry?.["global-port"] || "",
    }));
  } catch {
    return null;
  }
}

function pfKey(row, isJuniper) {
  // Junos อนุญาตชื่อ rule เดียวกันในคนละ rule-set ได้ จึงต้องใช้ identity คู่
  // rule-set+rule ไม่เช่นนั้นเลือก/Edit แถวหนึ่งแล้วอาจไปจับอีก zone
  return isJuniper
    ? `${row.ruleSet}|${row.name}`
    : `${row.protocol}|${row.localIp}|${row.localPort}|${row.globalIp}|${row.globalPort}`;
}

export default function Pf({ devId, vendor }) {
  const isJuniper = vendor === "juniper";
  // dedupeInFlight: true - initial load, React StrictMode remount, ปุ่ม Refresh
  // และ device:state-changed event (จาก write อื่นของอุปกรณ์เดียวกันที่ล้มเหลว) ที่
  // ยิงมาซ้อนกันระหว่าง request เดิมยังไม่จบ ใช้ promise เดียวกัน (ดู inFlightRequests
  // ใน getDeviceInformation.js) ไม่ยิง NETCONF ซ้ำเข้า session เดิม
  const { data, loading, error, clearError, refetch } = getDeviceInformation(
    devId, "get_port_forward_information", { dedupeInFlight: true },
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
    getDeviceConfigObjects(devId, "port_forward")
      .then((objects) => {
        const map = {};
        for (const obj of objects) {
          const p = obj.cfg_params || {};
          if (p.local_ip && p.local_port && p.global_ip && p.global_port) {
            map[pfKey({
              protocol: p.protocol,
              localIp: p.local_ip,
              localPort: String(p.local_port),
              globalIp: p.global_ip,
              globalPort: String(p.global_port),
            }, false)] = obj.cfg_name;
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
  // ลบด้วย protocol+local_ip+local_port+global_ip+global_port (key จริงตาม YANG)
  async function handleConfirmDelete(row) {
    setDeleting(true);
    setDeleteError("");
    try {
      if (isJuniper) {
        // ใช้ rule-set name จริงที่อ่านมาจากอุปกรณ์ (row.ruleSet) ไม่ใช่เดาจาก
        // staticNatRuleSet(fromZone) - ดู comment ที่ parseJuniperPortForwards
        //
        // เจอบั๊กจริง (รอบ 4): ถ้า row นี้เป็น rule เดียวที่เหลือใน rule-set
        // ต้องลบทั้ง rule-set (+ pool) ไม่ใช่แค่ rule เดียว ไม่งั้นจะเหลือ shell
        // ว่างเปล่าที่ยังจอง context (from-zone) ไว้ถาวร (ดู isLastRuleInSet -
        // บั๊กเดียวกันเป๊ะกับฝั่ง static NAT)
        // ตรวจ Static NAT ก่อนเริ่มลบ และแนบ Proxy ARP เข้า delete RPC เดียวกัน
        // เฉพาะเมื่อยืนยันได้ว่าไม่มี rule อื่นแชร์ public IP นี้อยู่
        let proxyArpRemoval = {};
        try {
          const staticResult = await runDeviceCommand(devId, "get_static_nat_information", {});
          if (staticResult?.normalized) {
            const remainingPfRows = rows.filter((candidate) =>
              `${candidate.ruleSet}|${candidate.name}` !== `${row.ruleSet}|${row.name}`
            );
            proxyArpRemoval = orphanedProxyArpRemoval(
              row.globalIp,
              parseJuniperStaticNat(staticResult.result),
              remainingPfRows,
              data.result,
            );
          }
        } catch { /* ถ้าอ่าน cross-feature ไม่ได้ ให้ลบเฉพาะ NAT โดยไม่เสี่ยงลบ Proxy ARP */ }

        if (isLastRuleInSet(rows, row)) {
          await runDeviceCommand(devId, "remove_port_forward_ruleset", {
            rule_set: row.ruleSet,
            rule_name: row.name,
            ...(row.poolName ? { pool_name: row.poolName } : {}),
            ...proxyArpRemoval,
          });
        } else {
          await runDeviceCommand(devId, "remove_port_forward", {
            rule_set: row.ruleSet,
            rule_name: row.name,
            ...(row.poolName ? { pool_name: row.poolName } : {}),
            ...proxyArpRemoval,
          });
        }
      } else {
        await runDeviceCommand(devId, "remove_port_forward", {
          protocol: row.protocol,
          local_ip: row.localIp,
          local_port: row.localPort,
          global_ip: row.globalIp,
          global_port: row.globalPort,
        });
      }
      setShowDeleteConfirm(false);
      setSelectedKey(null);
      if (!isJuniper) setNameRevision((revision) => revision + 1);
      refetch();
    } catch (err) {
      setDeleteError(errorMessage(err, "Failed to delete Port Forwarding"));
    } finally {
      setDeleting(false);
    }
  }

  if (loading && !data) return <div className="center-loading">Loading Port Forwarding data...</div>;

  const rows = data?.normalized ? parsePortForwards(data.result) : null;
  const ruleSetContexts = isJuniper && data?.normalized
    ? parseJuniperDestinationRuleSets(data.result)
    : [];
  const selectedRow = rows?.find((row) => pfKey(row, isJuniper) === selectedKey) || null;
  const displayNameMap = !isJuniper && rows && nameMap !== null
    ? buildImportedNameMap(rows, nameMap, (row) => pfKey(row, false), "import-portfwd")
    : {};
  const selectedName = isJuniper
    ? selectedRow?.name
    : selectedRow ? displayNameMap[pfKey(selectedRow, false)] : undefined;

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {formMode ? (
        <PfFormModal
          devId={devId}
          vendor={vendor}
          mode={formMode}
          editTarget={formMode === "edit" && selectedRow ? { ...selectedRow, name: selectedName } : null}
          allRows={rows || []}
          ruleSetContexts={ruleSetContexts}
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
              featureName="Port Forwarding"
              selectedLabel={
                selectedRow
                  ? `${selectedRow.globalIp}:${selectedRow.globalPort} → ${selectedRow.localIp}:${selectedRow.localPort}`
                  : ""
              }
              canEdit={!!selectedKey && (isJuniper || nameMap !== null)}
              canDelete={!!selectedKey}
              showDeleteConfirm={showDeleteConfirm}
              deleting={deleting}
              deletingHint={vendor === "cisco" ? NAT_RECONNECT_HINT : ""}
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
            <div className="config-placeholder">No Port Forwarding configured</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Protocol</th>
                  <th>Local IP</th>
                  <th>Local Port</th>
                  <th>WAN IP</th>
                  <th>WAN Port</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => {
                  const key = pfKey(row, isJuniper);
                  return (
                    <tr
                      key={`${key}-${index}`}
                      className={`row-clickable ${key === selectedKey ? "row-selected" : ""}`}
                      onClick={() => setSelectedKey(key === selectedKey ? null : key)}
                    >
                      <td>{isJuniper ? row.name : nameMap === null ? "-" : displayNameMap[key]}</td>
                      <td>{(row.protocol || "-").toUpperCase()}</td>
                      <td>{row.localIp || "-"}</td>
                      <td>{row.localPort || "-"}</td>
                      <td>{row.globalIp || "-"}</td>
                      <td>{row.globalPort || "-"}</td>
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
