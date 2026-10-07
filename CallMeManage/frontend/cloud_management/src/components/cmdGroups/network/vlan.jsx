import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import VlanFormModal from "./vlanFormModal";
import Edit_Result from "../../commandResult/edit_command_result";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// อ่านสดจาก get_vlan_information - path ตรงกับที่ set_vlan เขียน
// (native/vlan/vlan-list) - "shutdown" เป็น empty leaf (มี key นี้โผล่มา = ปิด
// อยู่, ไม่มี = เปิดอยู่ ตรวจด้วย "in" เหมือนที่ nat.jsx เช็ค overload-new)
export function parseVlans(result) {
  if (result?.vendor === "juniper") {
    // Junos: vlans/vlan (key เป็น "name" ไม่ใช่ vlan-id โดยตรง ตรงกับที่ set_vlan
    // เขียน) อ่าน active/inactive metadata ที่ backend เก็บไว้จาก Junos XML
    try {
      const vlans = result?.payload?.data?.configuration?.vlans;
      const parentInactive = "inactive" in (vlans?.["@attributes"] || {});
      const rows = ensureArray(vlans?.vlan);
      return rows.map((row) => ({
        id: row?.["vlan-id"] ?? "",
        name: row?.name || "",
        state: "",
        enabled: !parentInactive && !("inactive" in (row?.["@attributes"] || {})),
      }));
    } catch {
      return null;
    }
  }
  if (result?.vendor === "huawei") {
    // VRP: vlan/vlans/vlan จาก huawei-vlan; VLAN ที่ปิดไม่มีสถานะแยกใน
    // payload นี้ จึงแสดงว่าเปิดอยู่ตามข้อมูลที่อุปกรณ์คืนมา.
    try {
      const rows = ensureArray(result?.payload?.data?.vlan?.vlans?.vlan);
      return rows.map((row) => ({
        id: row?.vlanId ?? "",
        name: row?.vlanName || row?.vlanDesc || "",
        state: "",
        enabled: true,
      }));
    } catch {
      return null;
    }
  }
  try {
    const rows = ensureArray(result?.payload?.data?.native?.vlan?.["vlan-list"]);
    return rows.map((row) => ({
      id: row?.id ?? "",
      name: row?.name || "",
      state: row?.state || "",
      enabled: !("shutdown" in (row || {})),
    }));
  } catch {
    return null;
  }
}

// Junos: interfaces/interface/unit/family/ethernet-switching (port-mode +
// vlan/members) - path ตรงกับที่ apply_switchport (ที่ apply_interface_to_vlan
// เรียกใช้ภายใน) เขียนตรงๆ ไม่มี read/write asymmetry แบบ Cisco ที่เจอ (ยังไม่เคย
// verify กับอุปกรณ์ Juniper จริง - เขียนตามโครงสร้างที่ apply_switchport เขียนเอง)
// members เป็นเลข VLAN ID ดิบ (junos-es-conf-interfaces.yang:15518 ยืนยันแล้ว)
function parseJuniperVlanMembership(switchportResult) {
  const membership = {};
  const interfaces = ensureArray(switchportResult?.payload?.data?.configuration?.interfaces?.interface);
  for (const iface of interfaces) {
    const ifaceName = iface?.name;
    if (!ifaceName) continue;
    for (const unit of ensureArray(iface.unit)) {
      const es = unit?.family?.["ethernet-switching"];
      if (!es) continue;
      const mode = es["port-mode"];
      const unitSuffix = unit?.name !== undefined && unit?.name !== "" ? `.${unit.name}` : "";
      const label = mode === "trunk" ? `${ifaceName}${unitSuffix} (trunk)` : `${ifaceName}${unitSuffix}`;
      for (const vlanId of ensureArray(es.vlan?.members)) {
        (membership[String(vlanId)] ||= []).push(label);
      }
    }
  }
  return membership;
}

// อ่าน get_switchport_information (subtree เดียวกับที่ interfaces.jsx ใช้ทำ
// ตาราง Layer 2/3) มาหาว่า interface ไหนเป็นสมาชิกของ VLAN ไหนบ้าง - **โครงสร้าง
// ตอนอ่านกลับมาไม่เหมือนตอน apply_interface_to_vlan เขียนเป๊ะ** (verify กับ
// อุปกรณ์จริงแล้ว 2026-07-24 ผ่าน get_switchport_information ตรงๆ): เขียนผ่าน
// switchport-wrapper/switchport/mode+access/vlan (ซ้อน 2 ชั้น) แต่ตอนอ่านกลับมา
// device คืนเป็น container เปล่าๆ ชื่อ "switchport" ตรงๆ (ไม่มี "-wrapper") ซ้อน
// access/vlan/vlan อีก 3 ชั้น (มี "vlan" ซ้อนกัน 2 รอบ) พร้อม container ซ้ำอีก
// ชุด "switchport-config" ที่มีข้อมูลเดียวกัน - อ่านจาก entry.switchport ก่อน
// (เจอจริงจากอุปกรณ์) fallback ไป switchport-config ถ้าไม่มี - ส่วน trunk มี
// ปรับ path เผื่อไว้เหมือนกัน (access เจอซ้อนเพิ่ม 1 ชั้น เดาว่า trunk อาจจะ
// เหมือนกัน) แต่ **trunk ยังไม่เคย verify กับอุปกรณ์จริง** (อุปกรณ์ที่มีอยู่ตอนนี้
// ยังไม่มี trunk port ให้เทียบ) คืน object { [vlanId]: string[] }
function parseHuaweiVlanMembership(switchportResult) {
  const membership = {};
  // get_switchport_information ของ Huawei ผ่าน normalizer แล้วจะเป็น array
  // [{ name, raw }] เหมือน Cisco; รองรับ payload ดิบไว้ด้วยเพื่อให้ fallback
  // แสดงผลได้เมื่อ backend ส่ง generic response จากข้อผิดพลาดเก่า.
  const interfaces = Array.isArray(switchportResult)
    ? switchportResult.map((row) => ({ ...row?.raw, ifName: row?.name || row?.raw?.ifName }))
    : ensureArray(switchportResult?.payload?.data?.ethernet?.ethernetIfs?.ethernetIf);
  for (const iface of interfaces) {
    const ifaceName = iface?.ifName;
    if (!ifaceName) continue;
    const attribute = iface?.l2Attribute || {};
    const info = ensureArray(attribute?.portActiveVlanInfos?.portActiveVlanInfo)[0] || {};
    const linkType = String(attribute?.linkType || "").toLowerCase();
    const values = linkType === "trunk" ? info?.tagVlanList : info?.unTagVlanList;
    for (const vlanId of String(values || "").split(",").map((value) => value.trim()).filter((value) => value && value !== "-")) {
      (membership[vlanId] ||= []).push(linkType === "trunk" ? `${ifaceName} (trunk)` : ifaceName);
    }
  }
  return membership;
}

// แปลงรายการ VLAN ที่อุปกรณ์คืนมาเป็นเลขทีละค่า รองรับทั้งจุลภาคและช่วง
// (เช่น "10,20" และ "10-20") คืน [] เมื่ออ่านไม่ได้ เพื่อไม่ให้ตารางล้ม
function expandVlanIds(value) {
  const text = value === undefined || value === null ? "" : String(value).trim();
  if (!text || text === "-") return [];
  const ids = new Set();
  for (const token of text.split(/[\s,]+/)) {
    const bounds = token.split("-");
    const start = Number(bounds[0]);
    const end = bounds.length === 2 ? Number(bounds[1]) : start;
    if (bounds.length > 2 || !Number.isInteger(start) || !Number.isInteger(end)) continue;
    const low = Math.min(start, end);
    const high = Math.max(start, end);
    if (low < 1 || high > 4094) continue;
    for (let vlan = low; vlan <= high; vlan += 1) ids.add(vlan);
  }
  return [...ids].sort((left, right) => left - right);
}

// Cisco: normalize_switchport_layer คืนแถว {name, layer, mode, helpers, raw} โดย
// raw คือ entry ดิบของ native/interface ต่อพอร์ต จึงอ่าน membership จากแถวเหล่านี้
// ได้เลย ไม่ต้องพึ่งรูป payload ดิบซึ่งไม่มีอยู่แล้วหลัง backend unify ผลลัพธ์
// (สาเหตุที่คอลัมน์ Members ของ Cisco ว่างมาตลอด)
//
// กฎการอ่านตรงกับที่ normalizer ใช้ตัดสิน mode:
//   mode/trunk            -> สมาชิกคือ VLAN ในรายการ allowed เท่านั้น
//                            native vlan นับด้วยเฉพาะเมื่อตั้งไว้จริง
//   access/vlan           -> สมาชิกของ VLAN นั้น
//   mode/access หรือว่าง  -> access VLAN 1 ตามค่าเริ่มต้นของอุปกรณ์
// นับเฉพาะพอร์ตที่สรุปแล้วว่าเป็น Layer 2 เพื่อไม่ให้พอร์ต Layer 3 ของ router
// ไปโผล่เป็นสมาชิก VLAN 1
function parseCiscoVlanMembership(rows) {
  const membership = {};
  const push = (vlanId, label) => {
    const id = String(vlanId);
    (membership[id] ||= []).push(label);
  };

  for (const row of rows || []) {
    if (row?.layer !== "Layer 2" || !row?.name) continue;
    const raw = row.raw || {};
    const swp = raw.switchport || raw["switchport-config"]?.switchport;
    const mode = swp?.mode;
    if (mode && typeof mode === "object" && "trunk" in mode) {
      const allowed =
        swp?.trunk?.allowed?.["vlan-v2"]?.["vlan-choices"]?.vlans ??
        swp?.trunk?.allowed?.vlan?.vlans ??
        swp?.trunk?.allowed?.vlan?.vlan;
      for (const vlanId of expandVlanIds(allowed)) push(vlanId, `${row.name} (trunk)`);
      const nativeVlan = swp?.trunk?.native?.vlan?.["vlan-id"] ?? swp?.trunk?.native?.vlan;
      if (nativeVlan !== undefined && nativeVlan !== null && nativeVlan !== "") {
        push(nativeVlan, `${row.name} (trunk native)`);
      }
      continue;
    }
    const accessVlan = swp?.access?.vlan?.vlan ?? swp?.access?.vlan;
    push(accessVlan === undefined || accessVlan === null || accessVlan === "" ? "1" : accessVlan, row.name);
  }
  return membership;
}

function parseVlanMembership(switchportResult) {
  if (Array.isArray(switchportResult) && switchportResult.some((row) => row?.raw?.l2Attribute || row?.raw?.l2Enable)) {
    try {
      return parseHuaweiVlanMembership(switchportResult);
    } catch {
      return {};
    }
  }
  if (switchportResult?.vendor === "juniper") {
    try {
      return parseJuniperVlanMembership(switchportResult);
    } catch {
      return {};
    }
  }
  if (switchportResult?.vendor === "huawei") {
    try {
      return parseHuaweiVlanMembership(switchportResult);
    } catch {
      return {};
    }
  }
  // Cisco มาถึงตรงนี้ในรูป array ของแถวที่ normalizer สร้างไว้แล้ว
  if (Array.isArray(switchportResult)) {
    try {
      return parseCiscoVlanMembership(switchportResult);
    } catch {
      return {};
    }
  }
  const membership = {};
  try {
    const ifaceRoot = switchportResult?.payload?.data?.native?.interface;
    if (!ifaceRoot || typeof ifaceRoot !== "object") return membership;
    for (const [type, value] of Object.entries(ifaceRoot)) {
      for (const entry of ensureArray(value)) {
        if (!entry?.name) continue;
        const ifaceName = `${type}${entry.name}`;
        const swp = entry?.switchport || entry?.["switchport-config"]?.switchport;
        if (!swp) continue;

        const accessVlan = swp.access?.vlan?.vlan ?? swp.access?.vlan;
        if (accessVlan) {
          (membership[String(accessVlan)] ||= []).push(ifaceName);
          continue;
        }

        const trunkVlans = swp.trunk?.allowed?.vlan?.vlans ?? swp.trunk?.allowed?.vlan?.vlan;
        if (trunkVlans) {
          for (const part of String(trunkVlans).split(",").map((s) => s.trim()).filter(Boolean)) {
            (membership[part] ||= []).push(`${ifaceName} (trunk)`);
          }
        }
      }
    }
  } catch {
    /* best-effort - ตารางยังโชว์ VLAN ได้ปกติแค่คอลัมน์ Interfaces ว่าง */
  }
  return membership;
}

export default function Vlan({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_vlan_information");
  const {
    data: switchportData,
    loading: switchportLoading,
    refetch: refetchSwitchport,
  } = getDeviceInformation(devId, "get_switchport_information");
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedId, setSelectedId] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const isJuniper = data?.result?.vendor === "juniper";
  const isHuawei = data?.result?.vendor === "huawei";

  function handleSaved() {
    setFormMode(null);
    setSelectedId(null);
    refetch();
    refetchSwitchport();
  }

  function handleRefresh() {
    refetch();
    refetchSwitchport();
  }

  async function handleConfirmDelete(vlan) {
    setDeleting(true);
    setDeleteError("");
    try {
      await runDeviceCommand(devId, "remove_vlan", isJuniper
        ? { vlan_name: vlan.name }
        : { vlan_id: Number(vlan.id) });
      setShowDeleteConfirm(false);
      setSelectedId(null);
      refetch();
      refetchSwitchport();
    } catch (err) {
      setDeleteError(err.detail || "Failed to delete VLAN");
    } finally {
      setDeleting(false);
    }
  }

  // รอทั้ง 2 query ให้เสร็จก่อนโชว์อะไรเลย (ไม่ใช่แค่ query แรก) - กันคอลัมน์
  // Interfaces (membership) โผล่ทีหลังตาราง VLAN เพราะ query คนละอันคนละเวลา resolve
  if ((loading && !data) || (switchportLoading && !switchportData)) {
    return <div className="center-loading">Fetching VLAN data...</div>;
  }

  const vlans = data?.normalized ? parseVlans(data.result) : null;
  const membership = switchportData?.normalized ? parseVlanMembership(switchportData.result) : {};

  // switchport ผูกกับ VLAN ID ไหนก็ได้โดยตรง (apply_interface_to_vlan ไม่บังคับ
  // ว่า VLAN นั้นต้องถูกสร้างผ่าน set_vlan ไว้ก่อน) - ถ้า VLAN ที่มี interface
  // เป็นสมาชิกไม่ได้อยู่ใน vlan-list (เช่น ยังไม่เคยสร้างผ่านหน้านี้ หรือสร้างผ่าน
  // ทางอื่นที่ไม่ได้ query กลับมาที่ vlan-list) จะไม่มีแถวให้โชว์เลย - เติมแถว
  // สังเคราะห์ให้ VLAN ID ที่เจอใน membership แต่ไม่มีใน vlan-list ด้วย กันตก
  // Huawei ไม่เติมแถวสังเคราะห์: `tagVlanList`/`unTagVlanList` ที่ใช้ทำ membership
  // เป็น operational state ของพอร์ต จึงคืน VLAN ทุกวงที่ trunk อนุญาตกลับมาด้วย
  // ทำให้ตารางมีแถวที่ไม่ได้อยู่ใน VLAN database จริง - ผู้ใช้ต้องการเห็นเฉพาะ
  // VLAN ที่ `get_vlan_information` อ่านได้จากอุปกรณ์เท่านั้น (Cisco/Juniper คงเดิม)
  const vlanIds = new Set((vlans || []).map((v) => String(v.id)));
  const extraVlans = isHuawei
    ? []
    : Object.keys(membership)
        .filter((id) => !vlanIds.has(id))
        // VLAN 1 มีอยู่จริงบนอุปกรณ์เสมอและเปิดใช้งานอยู่ แค่ IOS-XE ไม่เขียนลง
        // config จึงไม่ถูกส่งกลับมาใน VLAN database - แสดงชื่อ default กับสถานะ
        // Enabled ตามความจริง แต่ยังกด Edit/Delete ไม่ได้เพราะไม่มีอะไรให้ set_vlan
        // หรือ remove_vlan ทำกับ VLAN เริ่มต้นตัวนี้
        .map((id) => (id === "1"
          ? { id, name: "Default", enabled: true, readOnly: true }
          : { id, name: "", enabled: null }));
  const allVlans = vlans ? [...vlans, ...extraVlans].sort((a, b) => Number(a.id) - Number(b.id)) : vlans;
  // Edit/Delete ใช้ได้เฉพาะแถวที่มีอยู่จริงใน VLAN database (enabled !== null -
  // แถว "สังเคราะห์" ที่เจอแค่ใน membership แต่ไม่มีใน vlan-list ไม่มีอะไรให้
  // remove_vlan ลบเลย เพราะไม่เคยถูกสร้างผ่าน set_vlan มาก่อน)
  const selectedVlan = allVlans?.find(
    (vlan) => String(vlan.id) === selectedId && vlan.enabled !== null && !vlan.readOnly
  ) || null;

  return (
    <div className="command-configuration">

      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {formMode ? (
        <VlanFormModal
          devId={devId}
          vendor={data?.result?.vendor}
          mode={formMode}
          editTarget={formMode === "edit" ? selectedVlan : null}
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : (data && !data.normalized ? (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        ) : vlans === null ? (
          data && (
            <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
          )
        ) : (
          <>
            <div className="command-output-title">
              <Edit_Result
                featureName="VLAN"
                selectedLabel={selectedVlan ? `${selectedVlan.id}${selectedVlan.name ? ` (${selectedVlan.name})` : ""}` : ""}
                extraWarning={isJuniper
                  ? "Does not automatically remove or migrate interface memberships. If this VLAN is referenced, the device may reject commit."
                  : "Does not affect switchport memberships previously configured on interfaces."}
                canEdit={!!selectedVlan}
                canDelete={!!selectedVlan}
                showDeleteConfirm={showDeleteConfirm}
                deleting={deleting}
                deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
                onNew={() => setFormMode("create")}
                onEditClick={() => setFormMode("edit")}
                onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
                onCancelDelete={() => setShowDeleteConfirm(false)}
                onConfirmDelete={() => handleConfirmDelete(selectedVlan)}
                refreshing={loading || switchportLoading}
                onRefresh={handleRefresh}
              />
            </div>

            {allVlans.length === 0 ? (
              <div className="config-placeholder">No VLANs configured</div>
            ) : (
              <div className="security-table-container">
                <table className="security-data-table">
                  <thead>
                    <tr>
                      <th>No</th>
                      <th>VLAN ID</th>
                      <th>Name</th>
                      <th>Status</th>
                      <th>Members</th>
                    </tr>
                  </thead>
                  <tbody>
                    {allVlans.map((vlan, index) => {
                      const interfaces = membership[String(vlan.id)] || [];
                      const status =
                        vlan.enabled === null ? "Not in VLAN database" : vlan.enabled ? "Enabled" : "Shutdown";
                      const selectable = vlan.enabled !== null && !vlan.readOnly;
                      return (
                        <tr
                          key={`${vlan.id}-${index}`}
                          className={selectable ? `row-clickable ${String(vlan.id) === selectedId ? "row-selected" : ""}` : ""}
                          onClick={selectable ? () => setSelectedId(String(vlan.id) === selectedId ? null : String(vlan.id)) : undefined}
                        >
                          <td>{index + 1}</td>
                          <td>{vlan.id}</td>
                          <td>{vlan.name || "-"}</td>
                          <td>{status}</td>
                          <td>
                            {interfaces.length === 0 ? (
                              "-"
                            ) : (
                              <ul>
                                {interfaces.map((iface, ifaceIndex) => (
                                  <li key={ifaceIndex}>{iface}</li>
                                ))}
                              </ul>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )
      )}
    </div>
  );
}
