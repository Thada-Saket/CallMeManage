import DismissibleError from "../../DismissibleError";
import { useState, useEffect, Fragment } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import StatefulFormModal from "./statefulFormModal";
import Edit_Result from "../../commandResult/edit_command_result";
import JuniperPolicyTable from "./juniperPolicyTable";
import { parseCiscoFirewallPolicies } from "./ciscoZbfParser";
import {
  findPolicyByIdentity,
  formatPolicyLabel,
  getPolicyIdentityKey,
  buildMovePolicyParameters,
  describeMovePolicyError,
  groupPoliciesByZonePair,
  formatCiscoApplicationDisplay,
} from "./statefulUtils";

// จำนวนคอลัมน์จริงของตาราง Cisco (Policy Name, จากโซน, ไปโซน, Action, Services) - ใช้
// เป็น colSpan ของแถวหัวข้อกลุ่ม Zone ให้กินเต็มความกว้างเสมอ แม้จำนวนคอลัมน์จะเปลี่ยน
const CISCO_COLUMN_COUNT = 5;

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

const ACTION_LABEL = {
  inspect: "Inspect",
  pass: "Pass",
  drop: "Drop",
};

function renderCiscoServices(policy) {
  if (policy.applicationsKnown === false || policy.applicationMode === "unknown") {
    return "-";
  }
  const apps = (policy.applications || []).filter(
    (a) => a && String(a).trim() && String(a).trim().toLowerCase() !== "any"
  );
  if (apps.length === 0) {
    return "Any";
  }
  return (
    <ul>
      {apps.map((app, appIdx) => (
        <li key={`${app}-${appIdx}`}>{formatCiscoApplicationDisplay(app)}</li>
      ))}
    </ul>
  );
}

// Juniper rework (2026-07-28) - แยกออกจาก parseJuniperFirewallPolicies เดิม
// (ที่ใช้กับ get_firewall_information แบบ lossy action mapping) เพราะตอนนี้
// อ่านจาก get_security_policy_information โดยตรง (เฉพาะ policies ไม่มี zones
// ปนมา) และ action เป็น permit/deny ตรงตัว ไม่ต้อง reverse-map แบบเดา - เพิ่ม
// source/destination address + applications (Services column) ที่ของเดิมไม่มี
// เลย path ตรงกับที่ set_security_policy เขียน (policy_type grouping -
// source-address/destination-address/application เป็น leaf-list ธรรมดา ยืนยัน
// จริงผ่าน CLI 2026-07-28) - sourceAddress เปลี่ยนเป็น sourceAddresses (array
// เสมอ) 2026-07-29 เพราะ set_security_policy รองรับหลาย source-address แล้ว
// (กดบวกได้) - destinationAddress เปลี่ยนเป็น destinationAddresses (array เสมอ)
// เช่นกัน 2026-07-30 (user ขอให้ destination กดบวกได้หลายชุดเหมือน source) -
// ensureArray กัน object เดี่ยวกับ array ปนกันตามเดิม (Junos คืน string เดี่ยว
// ถ้ามีค่าเดียว, array ถ้ามีหลายค่า)
function parseJuniperSecurityPolicies(result) {
  const policyPairs = ensureArray(result?.payload?.data?.configuration?.security?.policies?.policy);
  const rows = [];
  for (const pair of policyPairs) {
    const fromZone = pair?.["from-zone-name"] || "";
    const toZone = pair?.["to-zone-name"] || "";
    const rules = ensureArray(pair?.policy);
    const totalInZone = rules.length;
    const pairOrderRevision = pair?.order_revision || pair?.orderRevision || "";
    rules.forEach((rule, zoneIndex) => {
      const then = rule?.then || {};
      const match = rule?.match || {};
      const sourceAddresses = ensureArray(match["source-address"]).filter(Boolean);
      const destinationAddresses = ensureArray(match["destination-address"]).filter(Boolean);
      const rawAction = rule?.rawAction || (
        "permit" in then ? "permit" :
        "deny" in then ? "deny" :
        "reject" in then ? "reject" : ""
      );
      const hasBrownfield = rule?.hasBrownfieldFields !== undefined
        ? rule.hasBrownfieldFields
        : (
            !!rule?.description ||
            !!rule?.["scheduler-name"] ||
            !!then?.count ||
            !!then?.log ||
            rawAction === "reject" ||
            (then?.permit && typeof then.permit === "object" && Object.keys(then.permit).length > 0)
          );
      const preservedFields = rule?.preservedFields || [];
      const unsupportedReasons = rule?.unsupportedReasons || (
        rawAction === "reject" ? ["Action reject is not supported by this form"] :
        rawAction === "" ? ["Unknown action is not supported by this form"] : []
      );
      const editable = rule?.editable !== undefined
        ? rule.editable
        : (rawAction === "permit" || rawAction === "deny");

      rows.push({
        name: rule?.name || "",
        fromZone,
        toZone,
        zoneIndex,
        zoneOrder: zoneIndex + 1,
        isFirstInZone: zoneIndex === 0,
        isLastInZone: zoneIndex === totalInZone - 1,
        totalInZone,
        action: rawAction,
        sourceAddresses: sourceAddresses.length ? sourceAddresses : ["any"],
        destinationAddresses: destinationAddresses.length ? destinationAddresses : ["any"],
        applications: ensureArray(match.application).filter((a) => a && a !== "any"),
        // Junos บังคับให้ทุก Policy มี match application - ถ้าไม่มีเลยแปลว่าอ่านไม่ครบ
        // ตาราง Services ต้องไม่เดาเป็น Any (ฟอร์ม Edit ยังใช้ applications เดิม)
        applicationsKnown: match.application !== undefined && match.application !== null,
        hasBrownfieldFields: hasBrownfield,
        preservedFields,
        unsupportedReasons,
        editable,
        revision: rule?.revision || "",
        orderRevision: rule?.order_revision || rule?.orderRevision || pairOrderRevision || "",
      });
    });
  }
  return rows;
}

// อ่าน Cisco ZBF (get_firewall_information) เดินตาม reference chain จริงทุกชั้น -
// ตรรกะทั้งหมดอยู่ใน ciscoZbfParser.js (pure module แยกไฟล์ ทดสอบได้โดยไม่ต้อง
// render React) ที่นี่แค่ import มาใช้

export default function Stateful({ devId, vendor }) {
  const isJuniper = vendor === "juniper";
  const { data, loading, error, clearError, refetch } = getDeviceInformation(
    devId,
    isJuniper ? "get_security_policy_information" : "get_firewall_information"
  );
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedKey, setSelectedKey] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [moving, setMoving] = useState(null); // { key, direction } | null
  const [actionError, setActionError] = useState("");

  function handleSaved() {
    setFormMode(null);
    setSelectedKey(null);
    setActionError("");
    refetch();
  }

  // ไม่ขยับแถวเองในหน้าเว็บ - สำเร็จแล้ว refetch ให้เห็นลำดับจริงจากอุปกรณ์เท่านั้น
  // ล้มเหลวแสดง error และ refetch เฉพาะกรณีลำดับบนอุปกรณ์อาจไม่ตรงกับที่เห็นอยู่
  async function handleMovePolicy(policy, direction) {
    if (!policy || moving) return;
    setMoving({ key: getPolicyIdentityKey(policy, true), direction });
    setActionError("");

    try {
      await runDeviceCommand(devId, "move_security_policy", buildMovePolicyParameters(policy, direction));
      refetch();
    } catch (err) {
      const { message, refetch: shouldRefetch } = describeMovePolicyError(err);
      setActionError(message);
      if (shouldRefetch) refetch();
    } finally {
      setMoving(null);
    }
  }

  // Juniper ลบ policy เดียวตาม identity ของ zone pair ส่วน Cisco ใช้คำสั่งรวม
  // เพื่อลบ ACL/class-map/policy-map/zone-pair พร้อมกันในประวัติหนึ่งแถว
  async function handleConfirmDelete(policy) {
    if (!policy) return;
    setDeleting(true);
    setDeleteError("");
    try {
      if (isJuniper) {
        await runDeviceCommand(devId, "remove_security_policy", {
          from_zone: policy.fromZone,
          to_zone: policy.toZone,
          policy_name: policy.name,
          expected_revision: policy.revision || undefined,
        });
      } else {
        await runDeviceCommand(devId, "remove_firewall_policy", {
          name: policy.name,
          expected_revision: policy.revision || undefined,
        });
      }
      setShowDeleteConfirm(false);
      setSelectedKey(null);
      refetch();
    } catch (err) {
      const msg =
        typeof err.detail === "object" && err.detail?.message
          ? err.detail.message
          : err.detail || "Failed to delete Firewall policy";
      setDeleteError(msg);
      if (
        err.status === 409 ||
        err.status === 404 ||
        (typeof err.detail === "object" && err.detail?.code === "POLICY_CONCURRENT_MODIFICATION") ||
        (typeof err.detail === "string" && err.detail.includes("POLICY_CONCURRENT_MODIFICATION"))
      ) {
        setShowDeleteConfirm(false);
        setActionError(msg);
        setSelectedKey(null);
        refetch();
      }
    } finally {
      setDeleting(false);
    }
  }

  let policies = null;
  let parseError = "";
  if (data?.normalized) {
    if (isJuniper) {
      policies = parseJuniperSecurityPolicies(data.result);
    } else {
      try {
        policies = parseCiscoFirewallPolicies(data.result, data.zbf_metadata);
      } catch (err) {
        parseError = err?.message || "Failed to read Cisco ZBF configuration";
      }
    }
  }
  const selectedPolicy = findPolicyByIdentity(policies, selectedKey, isJuniper);

  useEffect(() => {
    if (selectedKey && policies && !selectedPolicy) {
      setSelectedKey(null);
    }
  }, [selectedKey, policies, selectedPolicy]);

  const displayError = actionError || error || parseError;

  // Edit: ปิดปุ่มเมื่อ Reader ตัดสินว่าแก้ผ่านฟอร์มปัจจุบันไม่ปลอดภัย (editable===false)
  // - Read-only ยังคลิกดูแถวในตารางได้ตามปกติ แค่กด Edit ไม่ได้ - เหตุผลเต็มอยู่ใน
  // readOnlyReasons (แสดงเป็น title ของปุ่ม)
  // Delete: แยกจาก editable โดยเจตนา - remove_firewall_policy ยัง derive ชื่อ
  // object เป็น FW_<name> เหมือนเดิม (ยังไม่แก้ Writer ในงานนี้) จึงลบได้ปลอดภัย
  // เฉพาะ Policy ที่มีรูปแบบ object ตรงกับที่ระบบสร้างเอง (systemManagedShape) และ
  const canEdit =
    !!selectedPolicy &&
    (isJuniper ||
      (selectedPolicy.capabilities ? selectedPolicy.capabilities.can_edit !== false : selectedPolicy.chainComplete !== false));
  const editDisabledReason =
    !isJuniper && selectedPolicy && !canEdit
      ? selectedPolicy.blockingErrors?.join("; ") ||
        selectedPolicy.readOnlyReasons?.join("; ") ||
        "This policy cannot be edited (incomplete references)"
      : "";
  const ciscoCanDelete =
    !!selectedPolicy &&
    (selectedPolicy.capabilities ? selectedPolicy.capabilities.can_delete !== false : selectedPolicy.chainComplete !== false);
  const canDelete = !!selectedPolicy && (isJuniper || ciscoCanDelete);
  const deleteDisabledReason =
    !isJuniper && selectedPolicy && !ciscoCanDelete
      ? selectedPolicy.blockingErrors?.join("; ") ||
        "Cannot delete this policy automatically: incomplete reference chain"
      : "";

  if (loading && !data) return <div className="center-loading">Loading Firewall data...</div>;

  return (
    <div className="command-configuration">
      {displayError && (
        <DismissibleError
          message={displayError}
          onDismiss={actionError ? () => setActionError("") : error ? clearError : undefined}
        />
      )}

      {formMode ? (
        <StatefulFormModal
          devId={devId}
          vendor={vendor}
          mode={formMode}
          editTarget={formMode === "edit" ? selectedPolicy : null}
          // Cisco ZBF (2026-09): ต้องได้รายการ Zone Pair ปัจจุบันด้วยเพื่อกรอง From/To
          // Zone dropdown กันคู่ซ้ำ (ดู statefulUtils.js::getCiscoUsedZonePairs) - logic
          // ภายในฟอร์มแยก vendor ชัดเจน ไม่ใช้ identity rule ของ Juniper กับ Cisco
          existingPolicies={policies || []}
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : policies === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : (
        <>
          <div className="command-output-title">
            <Edit_Result
              featureName="Firewall Policy"
              selectedLabel={formatPolicyLabel(selectedPolicy, isJuniper)}
              extraWarning="Zones shared with other policies will not be deleted"
              canEdit={canEdit}
              editDisabledReason={editDisabledReason}
              canDelete={canDelete}
              deleteDisabledReason={deleteDisabledReason}
              showDeleteConfirm={showDeleteConfirm}
              deleting={deleting}
              deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
              onNew={() => setFormMode("create")}
              onEditClick={() => setFormMode("edit")}
              onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
              onCancelDelete={() => setShowDeleteConfirm(false)}
              onConfirmDelete={() => handleConfirmDelete(selectedPolicy)}
              refreshing={loading}
              onRefresh={() => {
                setActionError("");
                refetch();
              }}
            />
          </div>

          {policies.length === 0 ? (
            <div className="config-placeholder">No Firewall policies configured</div>
          ) : isJuniper ? (
            <JuniperPolicyTable
              policies={policies}
              selectedKey={selectedKey}
              moving={moving}
              refreshing={loading}
              onToggleSelect={setSelectedKey}
              onMove={handleMovePolicy}
            />
          ) : (
            <table className="data-table firewall-policy-table">
              <thead>
                <tr>
                  <th>Policy Name</th>
                  <th>From Zone</th>
                  <th>To Zone</th>
                  <th>Action</th>
                  <th style={{ width: "18%" }}>Services</th>
                </tr>
              </thead>
              <tbody>
                {groupPoliciesByZonePair(policies, false).map((group) => (
                  <Fragment key={`zone-header:${group.key}`}>
                    {/* แถวหัวข้อคู่ Zone - ไม่ clickable/selectable, ไม่ใช่ Policy, ไม่มี action
                        ใด ๆ ใช้ pattern เดียวกับ .table-section-header ของหน้า Interfaces */}
                    <tr className="table-section-header">
                      <td colSpan={CISCO_COLUMN_COUNT}>{group.title}</td>
                    </tr>
                    {group.rows.map((policy, index) => {
                      const policyKey = getPolicyIdentityKey(policy, false);
                      const isSelected = selectedKey === policyKey;
                      // action เป็น null เมื่อ Policy มีมากกว่า 1 class ที่ไม่ใช่
                      // class-default (กำกวม - ไม่เลือกอันแรกมาแทนเงียบๆ)
                      const actionText = policy.action === null ? "Multiple classes" : ACTION_LABEL[policy.action] || policy.action || "-";
                      return (
                        <tr
                          key={`zone-row:${policyKey}-${index}`}
                          className={`row-clickable ${isSelected ? "row-selected" : ""}`}
                          onClick={() => setSelectedKey(isSelected ? null : policyKey)}
                        >
                          <td>{policy.name || "-"}</td>
                          <td>{policy.source || "-"}</td>
                          <td>{policy.destination || "-"}</td>
                          <td>{actionText}</td>
                          <td className="cisco-policy-services">
                            {renderCiscoServices(policy)}
                          </td>
                        </tr>
                      );
                    })}
                  </Fragment>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
