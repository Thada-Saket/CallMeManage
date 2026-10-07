import { Fragment } from "react";
import { getPolicyIdentityKey, getApplicationDisplayItems, getAddressDisplayItems, groupPoliciesByZonePair } from "./statefulUtils";

const JUNIPER_ACTION_LABEL = {
  permit: "Permit",
  deny: "Deny",
  reject: "Reject",
};

// จำนวนคอลัมน์จริงของตารางนี้ (ลำดับ, Policy Name, Source Address, Destination
// Address, Policy Action, Services, Priority) - ใช้เป็น colSpan ของแถวหัวข้อกลุ่ม
// Zone ให้กินเต็มความกว้างเสมอ แม้จำนวนคอลัมน์จะเปลี่ยนในอนาคต
//
// คอลัมน์ From Zone/To Zone เดิมถูกแทนที่ด้วย Source/Destination Address (2026-09)
// เพราะข้อมูลที่มีประโยชน์กว่าสำหรับผู้ใช้เวลาดู Policy คู่ Zone เดียวกันหลายตัว -
// fromZone/toZone ของ policy ยังเก็บไว้ใน model เหมือนเดิมทุกประการ (ใช้ระบุตัวตน
// ร่วมกับชื่อ, จัดกลุ่มแถว, เลือกแถว, Edit/Delete, เลื่อนลำดับ) แค่ไม่ได้ขึ้นเป็น
// คอลัมน์แยกอีกต่อไป (ดูหัวข้อกลุ่ม [From Zone → To Zone] แทน)
const JUNIPER_COLUMN_COUNT = 7;

// ปุ่มในคอลัมน์ "จัดลำดับ" - แยกจากข้อมูล Policy ชัดเจน (คอลัมน์ขวาสุด sticky ให้เห็น
// เสมอแม้หน้าจอแคบจนตารางต้องเลื่อนแนวนอน) stopPropagation กันคลิกปุ่มแล้วไปเลือกแถว
function MoveButton({ policy, direction, disabled, busy, title, onMove }) {
  const label = direction === "up" ? "Up" : "Down";
  return (
    <button
      type="button"
      className={`juniper-policy-move-btn${busy ? " is-busy" : ""}`}
      aria-label={`Move Policy ${policy.name} ${label}`}
      aria-busy={busy || undefined}
      title={title}
      disabled={disabled}
      onClick={(event) => {
        event.stopPropagation();
        onMove(policy, direction);
      }}
    >
      {busy ? <span className="juniper-policy-move-spinner" aria-hidden="true" /> : direction === "up" ? "↑" : "↓"}
    </button>
  );
}

function moveTitle(policy, direction, blockedReason) {
  if (blockedReason) return blockedReason;
  if (direction === "up") {
    return policy.isFirstInZone
      ? `Already at the top of ${policy.fromZone} → ${policy.toZone}`
      : `Move ${policy.name} up 1 level (within ${policy.fromZone} → ${policy.toZone})`;
  }
  return policy.isLastInZone
    ? `Already at the bottom of ${policy.fromZone} → ${policy.toZone}`
    : `Move ${policy.name} down 1 level (within ${policy.fromZone} → ${policy.toZone})`;
}

// ตาราง Juniper Security Policy - แยกไฟล์จาก stateful.jsx เพราะ Cisco ใช้ตารางคนละแบบ
// (ไม่มีลำดับ/ปุ่มเลื่อน/Services) และทำให้ทดสอบ render ได้โดยไม่ต้องจำลอง hook
// moving = { key, direction } ของแถวที่กำลังเลื่อน | null
export default function JuniperPolicyTable({ policies, selectedKey, moving, refreshing, onToggleSelect, onMove }) {
  const busyAny = moving !== null && moving !== undefined;
  const groups = groupPoliciesByZonePair(policies, true);
  return (
    <div className="juniper-policy-table-wrap">
      <table className="data-table firewall-policy-table juniper-policy-table">
        <thead>
          <tr>
            <th className="juniper-policy-order-col">Order</th>
            <th>Policy Name</th>
            <th>Source Address</th>
            <th>Destination Address</th>
            <th>Policy Action</th>
            <th>Services</th>
            <th className="juniper-policy-move-col">Priority</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((group) => (
            <Fragment key={`zone-header:${group.key}`}>
              {/* แถวหัวข้อคู่ Zone - ไม่ clickable/selectable, ไม่ใช่ Policy, ไม่มี action ใด ๆ
                  ใช้ pattern เดียวกับ .table-section-header ของหน้า Interfaces */}
              <tr className="table-section-header">
                <td colSpan={JUNIPER_COLUMN_COUNT}>{group.title}</td>
              </tr>
              {group.rows.map((policy) => {
                const policyKey = getPolicyIdentityKey(policy, true);
                const isSelected = selectedKey === policyKey;
                const isMovingThis = busyAny && moving.key === policyKey;
                const actionLabel = JUNIPER_ACTION_LABEL[policy.action] || policy.action || "-";
                const services = getApplicationDisplayItems(policy.applications, policy.applicationsKnown !== false);
                // source_addresses/destination_addresses เป็น leaf-list ที่ Junos การันตีว่ามีเสมอ
                // (backend/parser fallback เป็น ["any"] เมื่อ config ไม่ได้ระบุ - ไม่มีสถานะ "อ่านไม่ได้"
                // แบบ applications) จึงไม่ต้องส่ง known flag
                const sourceAddresses = getAddressDisplayItems(policy.sourceAddresses);
                const destinationAddresses = getAddressDisplayItems(policy.destinationAddresses);
                const blockedReason = !policy.orderRevision
                  ? "No order data from device. Please click Refresh before moving."
                  : busyAny
                  ? "Moving Policy..."
                  : refreshing
                  ? "Loading latest order from device..."
                  : "";
                const locked = !!blockedReason;
                return (
                  <tr
                    key={`zone-row:${policyKey}`}
                    className={`row-clickable ${isSelected ? "row-selected" : ""}`}
                    onClick={() => onToggleSelect(isSelected ? null : policyKey)}
                  >
                    <td className="juniper-policy-order-col">{policy.zoneOrder}</td>
                    <td>
                      <span className="juniper-policy-name">
                        <span>{policy.name || "-"}</span>
                        {policy.hasBrownfieldFields && (
                          <span
                            className="badge badge-warning"
                            style={{ fontSize: "0.75rem", padding: "0.15rem 0.4rem", borderRadius: "4px", backgroundColor: "#fef3c7", color: "#92400e" }}
                            title={`This policy has additional configurations from the device${policy.preservedFields?.length ? ": " + policy.preservedFields.join(", ") : ""}`}
                          >
                            Brownfield
                          </span>
                        )}
                        {!policy.editable && (
                          <span
                            className="badge badge-danger"
                            style={{ fontSize: "0.75rem", padding: "0.15rem 0.4rem", borderRadius: "4px", backgroundColor: "#fee2e2", color: "#991b1b" }}
                            title={policy.unsupportedReasons?.join("; ") || "Cannot be edited via form"}
                          >
                            Unsupported
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="juniper-policy-addresses">
                      {sourceAddresses.length === 0 ? (
                        "-"
                      ) : (
                        <ul>
                          {sourceAddresses.map((address, index) => (
                            <li key={`${address}-${index}`}>{address}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td className="juniper-policy-addresses">
                      {destinationAddresses.length === 0 ? (
                        "-"
                      ) : (
                        <ul>
                          {destinationAddresses.map((address, index) => (
                            <li key={`${address}-${index}`}>{address}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "0.25rem" }}>
                        <span>{actionLabel}</span>
                        {policy.action === "reject" && (
                          <span style={{ fontSize: "0.75rem", color: "#b91c1c" }}>(Unsupported)</span>
                        )}
                      </span>
                    </td>
                    <td className="juniper-policy-services">
                      {services.length === 0 ? (
                        "-"
                      ) : (
                        <ul>
                          {services.map((service, index) => (
                            <li key={`${service}-${index}`}>{service}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td className="juniper-policy-move-col">
                      <div className="juniper-policy-move-group" role="group" aria-label={`Order Policy ${policy.name}`}>
                        {["up", "down"].map((direction) => (
                          <MoveButton
                            key={direction}
                            policy={policy}
                            direction={direction}
                            busy={isMovingThis && moving.direction === direction}
                            disabled={locked || (direction === "up" ? policy.isFirstInZone : policy.isLastInZone)}
                            title={moveTitle(policy, direction, blockedReason)}
                            onMove={onMove}
                          />
                        ))}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}
