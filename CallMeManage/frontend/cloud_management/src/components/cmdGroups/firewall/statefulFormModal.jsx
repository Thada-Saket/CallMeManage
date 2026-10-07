import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { parseJuniperAddressBookNames } from "../addresses/addressBookParser";
import { parseJuniperZoneNames, parseCiscoZoneNames } from "../../../utils/zoneParsers";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import IPv4Input from "../../common/IPv4Input";
import {
  getJuniperPolicyKey,
  JUNIPER_APPLICATIONS,
  CISCO_ZBF_APPLICATIONS,
  formatApplicationDisplay,
  formatCiscoApplicationDisplay,
  getCiscoUsedZonePairs,
  computeCiscoFromZoneOptions,
  computeCiscoToZoneOptions,
} from "./statefulUtils";
import CheckboxDropdown from "../../common/CheckboxDropdown";

// ข้อความแจ้งเมื่อฟิลด์ฝั่งตรงข้ามถูกล้างค่าเพราะ From/To ที่เพิ่งเปลี่ยนทำให้ค่าเดิมกลาย
// เป็นคู่ Zone ที่ใช้ไปแล้ว - ใช้ข้อความเดียวกันทั้งสองทิศทาง (From เปลี่ยนทำ To ค้าง / To
// เปลี่ยนทำ From ค้าง) ตาม requirement ข้อ E
const CISCO_ZONE_PAIR_CLEARED_HINT = "This Zone Pair is already in use by another Zone Pair. Please select a new Zone.";

// ตัวเลือก action ของ policy (Cisco เท่านั้น) - เก็บศัพท์ ZBF ไว้เป็น value แต่โชว์
// เป็นภาษาคนให้ผู้ใช้
const ACTIONS = [
  { value: "inspect", label: "Inspect" },
  { value: "pass", label: "Pass" },
  { value: "drop", label: "Drop" },
];

// ตัวสร้าง id ที่เสถียรกว่า array index ให้แถว IP/CIDR - กันปัญหา focus/state
// สลับกันตอนลบแถวกลางออก (React key ต้องไม่ผูกกับตำแหน่งในตอนนี้)
let scopeRowSeq = 0;
function makeScopeRow(value = "") {
  scopeRowSeq += 1;
  return { id: `scope-${scopeRowSeq}`, value };
}

// ================= Shared presentational components (Cisco + Juniper) =================

// From/To Zone dropdown ใช้ markup เดียวกันทั้งสอง vendor - Juniper ไม่เปิด
// checkStale (พฤติกรรมเดิมทุกประการ) ส่วน Cisco เปิดเพื่อกัน Save ทับ Zone ที่ไม่มี
// อยู่แล้วบนอุปกรณ์ (เช่น Zone ถูกลบไปหลังผู้ใช้เปิดฟอร์ม)
function ZoneSelectField({ id, label, value, onChange, options, placeholder, disabled, checkStale = false, staleHint }) {
  const isStale = checkStale && !!value && !options.includes(value);
  return (
    <div className="interface-configuration-form-field">
      <label className="data-label" htmlFor={id}>{label}</label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
        required
        aria-describedby={isStale ? `${id}-hint` : undefined}
        aria-invalid={isStale || undefined}
      >
        <option value="">{placeholder}</option>
        {options.map((zone) => (
          <option key={zone} value={zone}>
            {zone}
          </option>
        ))}
        {isStale && <option value={value}>{value} (no longer found on device)</option>}
      </select>
      {isStale && (
        <div id={`${id}-hint`} className="form-error" role="alert">
          {staleHint || `Zone "${value}" used by this Policy is no longer found on the device - cannot save until resolved`}
        </div>
      )}
    </div>
  );
}

// รายการ IP/CIDR แบบกดบวก/ลบได้หลายแถว (Cisco Source IP เท่านั้น - Juniper ใช้
// Address Book แบบ <select> แยกต่างหาก ไม่ใช้ component นี้) แถวแรกมีปุ่ม + เท่านั้น
// แถวที่เพิ่มมีปุ่ม − เท่านั้น (ห้ามมีทั้งคู่ในแถวเดียวกัน) ใช้ IPv4Input mode="cidr"
// ตรงๆ ไม่สร้าง regex validator ใหม่ - key ใช้ row.id ที่เสถียรกว่า index
function MultiCidrFields({ idPrefix, rows, onChangeAt, onAdd, onRemoveAt, disabled }) {
  return (
    <>
      {rows.map((row, index) => (
        <div className="interface-configuration-form-field-third" key={row.id}>
          <label className="data-label" htmlFor={`${idPrefix}-${row.id}`}>
            {index === 0 ? "IP/CIDR 1" : `IP/CIDR ${index + 1}`}
          </label>
          <IPv4Input
            id={`${idPrefix}-${row.id}`}
            mode="cidr"
            required
            disabled={disabled}
            value={row.value}
            onChange={(value) => onChangeAt(index, value)}
          />
          {index === 0 ? (
            <button
              type="button"
              className="mini-btn btn-ghost"
              onClick={onAdd}
              disabled={disabled}
              aria-label="Add IP/CIDR"
            >
              +
            </button>
          ) : (
            <button
              type="button"
              className="mini-btn btn-ghost"
              onClick={() => onRemoveAt(index)}
              disabled={disabled}
              aria-label={`Remove IP/CIDR row ${index + 1}`}
            >
              −
            </button>
          )}
        </div>
      ))}
    </>
  );
}

// dropdown checkbox เลือก Application/Services หลายค่า - markup เดียวกับที่
// Juniper ใช้อยู่แล้ว (details.zone-interface-picker) parameterize ด้วย catalog/
// format function ต่อ vendor เพื่อไม่ให้ปนกัน (Juniper "junos-*" กับ Cisco เป็นคนละ
// namespace) ค่า custom (Brownfield ที่ไม่อยู่ catalog) ยังแสดงเสมอ ไม่ทำให้หาย
function ApplicationCheckboxPicker({
  idPrefix, modeValue, onModeChange, catalog, selected, onToggle, formatLabel,
  disabled, customSuffix = "(custom)",
}) {
  const allOptions = Array.from(new Set([...catalog, ...selected])).filter((app) => app && app !== "any");
  return (
    <>
      <div className="interface-configuration-form-field">
        <label className="data-label">Services (Application)</label>
        <div
          className={`segmented-control${disabled ? " locked-choice" : ""}`}
          title={disabled ? "This value cannot be changed" : undefined}
        >
          <input
            type="radio"
            id={`${idPrefix}-app-any`}
            name={`${idPrefix}-application-mode`}
            value="any"
            checked={modeValue === "any"}
            onChange={() => onModeChange("any")}
            disabled={disabled}
          />
          <label htmlFor={`${idPrefix}-app-any`}>Any</label>
          <input
            type="radio"
            id={`${idPrefix}-app-specific`}
            name={`${idPrefix}-application-mode`}
            value="specific"
            checked={modeValue === "specific"}
            onChange={() => onModeChange("specific")}
            disabled={disabled}
          />
          <label htmlFor={`${idPrefix}-app-specific`}>Specific</label>
        </div>
      </div>

      {modeValue === "specific" && (
        <div className="interface-configuration-form-field">
          <label className="data-label" id={`${idPrefix}-app-label`}>Application</label>
          <CheckboxDropdown
            ariaLabel="Select Policy Services"
            disabled={disabled}
            title={disabled ? "Applications cannot be changed" : undefined}
            summary={<>
              <input
                type="text"
                readOnly
                tabIndex={-1}
                aria-label="Selected Services"
                placeholder="-- Select Applications --"
                value={selected.length > 0 ? selected.map(formatLabel).join(", ") : ""}
              />
            </>}
          >
            <div className="zone-interface-picker-options">
              {allOptions.map((app) => {
                const isCustom = !catalog.includes(app);
                const displayLabel = isCustom ? `${formatLabel(app)} ${customSuffix}` : formatLabel(app);
                return (
                  <label key={app} className="zone-interface-picker-option">
                    <input
                      type="checkbox"
                      checked={selected.includes(app)}
                      onChange={() => onToggle(app)}
                      disabled={disabled}
                      aria-label={displayLabel}
                    />
                    <span>{displayLabel}</span>
                  </label>
                );
              })}
            </div>
          </CheckboxDropdown>
        </div>
      )}
    </>
  );
}

function FormActions({ submitting, isEdit, submitDisabled, cancelDisabled, onCancel }) {
  return (
    <div className="interface-form-btn-container">
      <button type="submit" className="btn btn-primary" disabled={submitDisabled}>
        {submitting ? "Sending..." : isEdit ? "Save" : "OK"}
      </button>
      <button type="button" className="btn btn-ghost" onClick={onCancel} disabled={cancelDisabled}>
        Cancel
      </button>
    </div>
  );
}

// โหมด Edit: pre-fill จากค่าที่ ciscoZbfParser.js เดินตาม reference จริงจาก
// อุปกรณ์ (ไม่ใช่เดา) - sourceMode/applicationMode มีสถานะที่ 3 คือ "unknown"
// (แยกจาก "any" อย่างเคร่งครัด) เมื่อ Reader อ่าน chain ไม่ครบ/ไม่แน่ใจ เพื่อไม่ให้
// ฟอร์มแสดงเป็น Any ทั้งที่จริงอ่านไม่ได้ (ทั้งสองกรณีนี้ editable จะเป็น false
// จาก backend อยู่แล้ว ปุ่ม Save จึงถูกปิดเสมอ แต่การแสดงผลต้องซื่อสัตย์แยกกัน)
function buildInitialValuesCisco(editTarget) {
  if (!editTarget) {
    return {
      name: "", fromZone: "", toZone: "", action: "inspect",
      sourceMode: "any", sourceScopes: [makeScopeRow()],
      applicationMode: "any", applications: [],
      log: false,
    };
  }
  const chainKnown = editTarget.chainComplete === true;
  const scopes = editTarget.aclScopes || [];
  const sourceKnown = chainKnown && editTarget.aclReadable === true;
  const isAnySource = sourceKnown && scopes.length === 1 && scopes[0] === "any";
  const hasSpecificScopes = sourceKnown && scopes.length > 0 && !scopes.includes("any");
  const apps = editTarget.applications || [];
  const appsKnown = editTarget.applicationsKnown !== undefined
    ? editTarget.applicationsKnown === true
    : chainKnown;

  let applicationMode;
  if (!appsKnown || editTarget.applicationMode === "unknown") {
    applicationMode = "unknown";
  } else if (editTarget.applicationMode === "specific") {
    applicationMode = "specific";
  } else if (editTarget.applicationMode === "any") {
    applicationMode = "any";
  } else {
    applicationMode = apps.length > 0 ? "specific" : "any";
  }

  return {
    name: editTarget.name || editTarget.zonePairName || "",
    fromZone: editTarget.source || "",
    toZone: editTarget.destination || "",
    // ห้าม fallback เป็น "inspect" เมื่อ Reader ไม่รู้ action จริง (action:null จาก
    // ciscoZbfParser.js เมื่อมีหลาย class กำกวม) - เก็บเป็น "" แล้วแสดงข้อความ
    // "ไม่ทราบ" แทนใน UI (ดูจุดเรนเดอร์ Action ด้านล่าง)
    action: editTarget.action || "",
    sourceMode: !sourceKnown ? "unknown" : (isAnySource ? "any" : "specific"),
    sourceScopes: hasSpecificScopes ? scopes.map((s) => makeScopeRow(s)) : [makeScopeRow()],
    applicationMode,
    applications: appsKnown ? apps : [],
    log: !!editTarget.log,
  };
}

// โหมด Edit: pre-fill จาก editTarget = parseJuniperSecurityPolicies() 1 แถว
// (stateful.jsx) - name/fromZone/toZone ล็อกไว้เสมอตอน edit (เป็น identity รวม
// กันทั้ง 3 ค่าของ policy นี้ - เปลี่ยนอันไหนก็ตามจะกลายเป็น policy คนละตัว ทำ
// ให้ตัวเดิมค้างเป็น orphan) sourceAddresses/destinationAddresses/applications
// pre-fill ตรงจากของจริงที่อ่านมาได้เลย (ต่างจาก Cisco - query
// get_security_policy_information อ่านค่าจริงกลับมาครบทุก field ไม่ต้องเดา)
function buildInitialValuesJuniper(editTarget) {
  if (!editTarget) {
    return {
      name: "",
      fromZone: "",
      toZone: "",
      action: "permit",
      sourceMode: "any",
      sourceAddresses: [""],
      destinationMode: "any",
      destinationAddresses: [""],
      applicationMode: "any",
      applications: [],
    };
  }
  // sourceAddresses/destinationAddresses กดบวกได้หลายชุด (2026-07-29/07-30) -
  // editTarget.sourceAddresses/destinationAddresses เป็น array เสมอ
  // (parseJuniperSecurityPolicies) ["any"] = ไม่ได้เจาะจง
  const editSources = (editTarget.sourceAddresses || ["any"]).filter((a) => a && a !== "any");
  const hasSource = editSources.length > 0;
  const editDestinations = (editTarget.destinationAddresses || ["any"]).filter((a) => a && a !== "any");
  const hasDestination = editDestinations.length > 0;
  const editApps = (editTarget.applications || []).filter((a) => a && a !== "any");
  const hasApps = editApps.length > 0;
  return {
    name: editTarget.name || "",
    fromZone: editTarget.fromZone || "",
    toZone: editTarget.toZone || "",
    action: editTarget.action === "deny" ? "deny" : editTarget.action === "reject" ? "reject" : (editTarget.action || "permit"),
    sourceMode: hasSource ? "specific" : "any",
    sourceAddresses: hasSource ? editSources : [""],
    destinationMode: hasDestination ? "specific" : "any",
    destinationAddresses: hasDestination ? editDestinations : [""],
    applicationMode: hasApps ? "specific" : "any",
    applications: editApps,
  };
}

// Policy-Based Zone Firewall: ผู้ใช้กรอกแค่ "จากกลุ่มไหน (source zone) -> ไปไหน
// (destination zone) -> ทำอะไร (action)" ที่เหลือ (ACL, class-map, policy-map,
// zone-pair) backend ประกอบเองผ่าน create_firewall_policy ตัวเดียว - Zone/Interface
// ต้องเตรียมผ่านหน้า Zone Interfaces ก่อนเสมอ (2026-09, Writer v2) ฟอร์มนี้เลือก
// เฉพาะ Zone ที่มีอยู่จริง ไม่สร้าง Zone หรือผูก Interface ให้อีกต่อไป
export default function StatefulFormModal({
  devId,
  vendor,
  mode = "create",
  editTarget = null,
  existingPolicies = [],
  onClose,
  onSaved,
}) {
  const isJuniper = vendor === "juniper";
  const isEdit = mode === "edit" && !!editTarget;
  const [ciscoValues, setCiscoValues] = useState(buildInitialValuesCisco(isEdit ? editTarget : null));
  const [juniperValues, setJuniperValues] = useState(buildInitialValuesJuniper(isEdit ? editTarget : null));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [pendingReplaceTarget, setPendingReplaceTarget] = useState(null);
  // Edit ที่เปลี่ยน From/To Zone ถือเป็น "ย้าย Policy" ข้ามคู่ Zone (Juniper เท่านั้น
  // - identity ของ Junos policy คือ name+from-zone+to-zone รวมกัน) ต้องยืนยันก่อน
  // เสมอเพราะเป็นธุรกรรมที่ลบตำแหน่งเดิม+สร้างตำแหน่งใหม่พร้อมกัน (ดู
  // move_security_policy_zone) - Cisco ไม่มีแนวคิดนี้: identity ของ Zone Pair คือ
  // ชื่อ (id) เอง เปลี่ยน source/destination zone เป็นแค่แก้ field ธรรมดาใน object
  // เดิม (ดู build_cisco_zbf_edit_native_fragment - replace ทับ zone-pair ชื่อเดิม)
  const [pendingZoneMove, setPendingZoneMove] = useState(null); // { fromZone, toZone, newFromZone, newToZone } | null
  // Cisco เท่านั้น (2026-09): ข้อความแจ้งเมื่อเปลี่ยน From/To Zone แล้วทำให้ฝั่งตรงข้ามที่
  // เลือกไว้ก่อนหน้ากลายเป็นคู่ Zone ที่ใช้ไปแล้ว/From=To (ดู setCiscoFromZone/setCiscoToZone)
  const [ciscoZonePairHint, setCiscoZonePairHint] = useState("");

  // editable ตัดสินใจโดย ciscoZbfParser.js (เกณฑ์เข้มกว่าแค่ "ACL อ่านได้ไหม" -
  // ครอบคลุมชื่อ object ไม่ตรงรูปแบบที่ Writer เขียนได้/มีหลาย class/มี class-default
  // ไม่ตรงกับที่ Writer คาดหวัง/มี protocol-application นอก catalog/ใช้ object ร่วมกับ
  // Zone Pair อื่น ฯลฯ) - เพิ่มเงื่อนไข frontend เองอีกชั้น: ถ้า applications ที่อ่าน
  // มามีค่านอก CISCO_ZBF_APPLICATIONS (custom/unsupported) ต้องล็อกอ่านอย่างเดียว
  // ด้วยแม้ backend graph จะเห็นว่า topology ตรงรูปแบบก็ตาม เพราะ Writer จะปฏิเสธ
  // ตอน submit แน่นอน (validate_cisco_zbf_applications ตรวจกับ catalog เดียวกันนี้)
  const ciscoReadOnly =
    !isJuniper &&
    isEdit &&
    (editTarget?.capabilities
      ? editTarget.capabilities.can_edit === false
      : editTarget?.chainComplete === false);

  // ชื่อ Policy ล็อกเฉพาะตอน edit ตัวที่มีอยู่แล้วจริง (identity ต้องคงที่ตลอดการแก้
  // เปลี่ยนชื่อ = กลายเป็น policy คนละตัว ทำให้ตัวเดิมค้างเป็น orphan)
  const nameLocked = isEdit;

  const { data: zoneData, loading: zoneLoading, error: zoneLoadError } = getDeviceInformation(
    devId, "get_security_zone_information"
  );
  const juniperZoneNames = isJuniper && zoneData?.normalized ? parseJuniperZoneNames(zoneData.result) : null;
  const ciscoZoneNames = !isJuniper && zoneData?.normalized ? parseCiscoZoneNames(zoneData.result) : null;
  const zoneOptions = (isJuniper ? juniperZoneNames : ciscoZoneNames) || [];

  // Cisco fail-closed zone evaluation (2026-09):
  // ปิด Save เสมอจนกว่าจะได้ normalized response ที่ parse สำเร็จเป็น array
  const ciscoZoneReady =
    !isJuniper &&
    !zoneLoading &&
    !zoneLoadError &&
    Boolean(zoneData?.normalized) &&
    Array.isArray(ciscoZoneNames);

  const ciscoZoneLoadFailed =
    !isJuniper &&
    (Boolean(zoneLoadError) || (Boolean(zoneData) && (!zoneData.normalized || ciscoZoneNames === null)));

  const { data: addressBookData } = getDeviceInformation(devId, isJuniper ? "get_address_book_information" : null);
  const addressOptions = addressBookData?.normalized
    ? parseJuniperAddressBookNames(addressBookData.result)
    : [];

  // Cisco เท่านั้น: Zone เดิมของ Policy (Edit) ไม่อยู่ใน zone list ล่าสุดแล้ว - ต้อง
  // ปิด Save จนกว่าจะแก้ไข (Zone อาจถูกลบไปหลังผู้ใช้เปิดหน้านี้)
  const ciscoZoneStale = !isJuniper && ciscoZoneReady && (
    (Boolean(ciscoValues.fromZone) && !zoneOptions.includes(ciscoValues.fromZone)) ||
    (Boolean(ciscoValues.toZone) && !zoneOptions.includes(ciscoValues.toZone))
  );

  // Cisco เท่านั้น (2026-09): ป้องกันสร้าง Zone Pair ที่คู่ source/destination ซ้ำกับของ
  // เดิม - derive จาก policy.source/policy.destination ที่ Reader อ่านจากอุปกรณ์จริงเท่านั้น
  // (ไม่ derive จากชื่อ Policy) ไม่นับคู่เดิมของ Policy ที่กำลังแก้เป็น collision กับตัวเอง -
  // ต้องกรองซ้ำที่ backend เสมอด้วย (ดู vendor_translators/cisco_zbf.py::
  // check_cisco_zbf_new_zone_pair) เพราะ dropdown filter นี้ bypass ได้ถ้ายิง API ตรง
  const ciscoUsedZonePairs = !isJuniper
    ? getCiscoUsedZonePairs(existingPolicies, isEdit ? editTarget?.name : null)
    : [];
  const ciscoFromZoneOptions = !isJuniper
    ? computeCiscoFromZoneOptions(zoneOptions, ciscoValues.toZone, ciscoUsedZonePairs)
    : [];
  const ciscoToZoneOptions = !isJuniper
    ? computeCiscoToZoneOptions(zoneOptions, ciscoValues.fromZone, ciscoUsedZonePairs)
    : [];
  // New เท่านั้น: เลือกฝั่งหนึ่งแล้วไม่เหลือตัวเลือกให้อีกฝั่งเลย (ทุกคู่ที่เหลือถูกใช้ไปแล้ว
  // หรือเป็น Zone เดียวกัน) - ผู้ใช้อาจเลือก From ก่อนหรือ To ก่อนก็ได้ ต้องปิด Save และ
  // อธิบายเหตุผลทั้งสองทาง ไม่ปล่อยให้ dropdown ว่างเงียบๆ
  const ciscoNoToZoneAvailable = !isJuniper && !isEdit && !!ciscoValues.fromZone && ciscoToZoneOptions.length === 0;
  const ciscoNoFromZoneAvailable = !isJuniper && !isEdit && !!ciscoValues.toZone && ciscoFromZoneOptions.length === 0;
  const ciscoNoPairAvailable = ciscoNoToZoneAvailable || ciscoNoFromZoneAvailable;

  function setCiscoField(name, value) {
    setCiscoValues((prev) => ({ ...prev, [name]: value }));
  }

  function setJuniperField(name, value) {
    setJuniperValues((prev) => ({ ...prev, [name]: value }));
  }

  // log มีผลเฉพาะ action pass/drop (inspect ไม่มี log ใน YANG) - เปลี่ยน action
  // เป็น inspect ต้อง reset log เองฝั่ง frontend ด้วย ห้ามพึ่งแค่ backend เงียบๆ ทิ้ง
  // ให้ (create_firewall_policy ยังเมิน log ให้เหมือนเดิมเป็น safety net ชั้นที่ 2)
  function setCiscoAction(value) {
    setCiscoValues((prev) => ({
      ...prev,
      action: value,
      log: value === "pass" || value === "drop" ? prev.log : false,
    }));
  }

  // เปลี่ยน From Zone: ถ้า To Zone ที่เลือกไว้ก่อนหน้ากลายเป็นค่าที่ใช้ไม่ได้กับ From
  // Zone ใหม่ (Zone เดียวกัน หรือคู่นี้ถูก Zone Pair อื่นใช้ไปแล้ว) ต้องล้างค่า To Zone
  // ทันที ห้ามปล่อยค่า invalid ซ่อนอยู่ใน controlled select และห้าม auto-select แทน
  function setCiscoFromZone(value) {
    const nextToOptions = computeCiscoToZoneOptions(zoneOptions, value, ciscoUsedZonePairs);
    const toStillValid = !ciscoValues.toZone || nextToOptions.includes(ciscoValues.toZone);
    setCiscoZonePairHint(toStillValid ? "" : CISCO_ZONE_PAIR_CLEARED_HINT);
    setCiscoValues((prev) => ({ ...prev, fromZone: value, toZone: toStillValid ? prev.toZone : "" }));
  }

  // เปลี่ยน To Zone: กระจกของ setCiscoFromZone ข้างบน - ผู้ใช้อาจเลือก To ก่อน From หรือ
  // แก้ To ทีหลังตอน Edit
  function setCiscoToZone(value) {
    const nextFromOptions = computeCiscoFromZoneOptions(zoneOptions, value, ciscoUsedZonePairs);
    const fromStillValid = !ciscoValues.fromZone || nextFromOptions.includes(ciscoValues.fromZone);
    setCiscoZonePairHint(fromStillValid ? "" : CISCO_ZONE_PAIR_CLEARED_HINT);
    setCiscoValues((prev) => ({ ...prev, toZone: value, fromZone: fromStillValid ? prev.fromZone : "" }));
  }

  function handleApplicationModeChange(nextMode) {
    setJuniperValues((prev) => ({
      ...prev,
      applicationMode: nextMode,
      ...(nextMode === "any" ? { applications: [] } : {}),
    }));
  }

  function handleCiscoApplicationModeChange(nextMode) {
    setCiscoValues((prev) => ({
      ...prev,
      applicationMode: nextMode,
      ...(nextMode === "any" ? { applications: [] } : {}),
    }));
  }

  function toggleApplication(app) {
    setJuniperValues((prev) => ({
      ...prev,
      applications: prev.applications.includes(app)
        ? prev.applications.filter((a) => a !== app)
        : [...prev.applications, app],
    }));
  }

  function toggleCiscoApplication(app) {
    setCiscoValues((prev) => ({
      ...prev,
      applications: prev.applications.includes(app)
        ? prev.applications.filter((a) => a !== app)
        : [...prev.applications, app],
    }));
  }

  // Source Address กดบวกได้หลายชุด (pattern เดียวกับ From Zone ของ NAT
  // natFormModal.jsx - list ของ <select> พร้อมปุ่ม +/-)
  function setSourceAddressAt(index, value) {
    const next = [...juniperValues.sourceAddresses];
    next[index] = value;
    setJuniperField("sourceAddresses", next);
  }

  function addSourceAddress() {
    setJuniperField("sourceAddresses", [...juniperValues.sourceAddresses, ""]);
  }

  function removeSourceAddressAt(index) {
    if (juniperValues.sourceAddresses.length <= 1) return;
    setJuniperField("sourceAddresses", juniperValues.sourceAddresses.filter((_, i) => i !== index));
  }

  // Destination Address กดบวกได้หลายชุดเหมือน Source Address (2026-07-30 - user
  // ขอ) - pattern เดียวกันเป๊ะ
  function setDestinationAddressAt(index, value) {
    const next = [...juniperValues.destinationAddresses];
    next[index] = value;
    setJuniperField("destinationAddresses", next);
  }

  function addDestinationAddress() {
    setJuniperField("destinationAddresses", [...juniperValues.destinationAddresses, ""]);
  }

  function removeDestinationAddressAt(index) {
    if (juniperValues.destinationAddresses.length <= 1) return;
    setJuniperField("destinationAddresses", juniperValues.destinationAddresses.filter((_, i) => i !== index));
  }

  function setScopeAt(index, value) {
    const next = [...ciscoValues.sourceScopes];
    next[index] = { ...next[index], value };
    setCiscoField("sourceScopes", next);
  }

  function addScope() {
    setCiscoField("sourceScopes", [...ciscoValues.sourceScopes, makeScopeRow()]);
  }

  function removeScopeAt(index) {
    if (ciscoValues.sourceScopes.length <= 1) return;
    setCiscoField("sourceScopes", ciscoValues.sourceScopes.filter((_, i) => i !== index));
  }

  async function handleSubmitCisco(event) {
    event.preventDefault();
    setError("");

    if (ciscoReadOnly) {
      const firstBlocking = editTarget?.blockingErrors?.[0] || editTarget?.readOnlyReasons?.[0];
      return setError(
        firstBlocking
          ? `Cannot edit this Policy: ${firstBlocking}`
          : "This Policy is read-only; current form cannot safely edit it"
      );
    }
    if (isEdit && !editTarget?.revision) {
      return setError("No latest revision information from device for this Policy. Please refresh before saving.");
    }
    if (zoneLoading || (!zoneData && !zoneLoadError)) {
      return setError("Loading zone list from device. Please wait a moment and try again.");
    }
    if (ciscoZoneLoadFailed || !zoneData?.normalized || ciscoZoneNames === null) {
      return setError("Failed to load zone list from device. Please refresh before saving.");
    }
    if (!ciscoZoneReady) {
      return setError("Zone list is not ready. Please wait a moment and try again.");
    }
    if (zoneOptions.length === 0) {
      return setError("No zones found on this device. Please create zones in Zone Interfaces first.");
    }

    const name = ciscoValues.name.trim();
    const fromZone = ciscoValues.fromZone;
    const toZone = ciscoValues.toZone;
    if (!name) return setError("Please enter Policy name");
    if (!fromZone) return setError("Please select From Zone");
    if (!toZone) return setError("Please select To Zone");
    if (fromZone === toZone) {
      return setError("Source and destination zones cannot be the same");
    }
    if (!zoneOptions.includes(fromZone) || !zoneOptions.includes(toZone)) {
      return setError("Zone used by this Policy is no longer found on the device. Please refresh and select a new Zone.");
    }
    // Dropdown กรองคู่ซ้ำไว้แล้ว แต่ต้องตรวจซ้ำที่นี่ก่อนยิง API เสมอ (กัน state ค้าง/
    // ผู้ใช้ยิง submit handler ตรงๆ) - ต้องไม่เรียก validateDeviceCommand/runDeviceCommand
    // เลยถ้าพบคู่ซ้ำ (backend เป็นผู้ตัดสินสุดท้ายเสมอผ่าน running config สดอีกชั้นหนึ่ง)
    const duplicatePair = ciscoUsedZonePairs.find((pair) => pair.source === fromZone && pair.destination === toZone);
    if (duplicatePair) {
      return setError(
        `Zone Pair from "${fromZone}" to "${toZone}" already exists. Cannot create duplicate Zone Pair. ` +
          "Please add rules to existing Policy or select another Zone Pair."
      );
    }

    let sourceScopes = ["any"];
    if (ciscoValues.sourceMode === "unknown") {
      return setError("Cannot edit Source IP for this Policy (Reader could not completely parse device data)");
    }
    if (ciscoValues.sourceMode === "specific") {
      const trimmed = ciscoValues.sourceScopes.map((row) => row.value.trim());
      const allValid = trimmed.length > 0 && trimmed.every(
        (value) => value && validateIPv4Input(value, { mode: "cidr", required: true }).valid
      );
      if (!allValid) {
        return setError("Please fill in valid IP/CIDR for all fields (e.g. 192.168.1.0/24)");
      }
      sourceScopes = trimmed;
    }

    let applications = [];
    if (ciscoValues.applicationMode === "unknown") {
      return setError("Cannot edit Application for this Policy (Reader could not completely parse device data)");
    }
    if (ciscoValues.applicationMode === "specific") {
      if (ciscoValues.applications.length === 0) {
        return setError("Please select at least 1 Application");
      }
      applications = ciscoValues.applications;
    }

    const params = {
      name,
      source_zone: fromZone,
      destination_zone: toZone,
      action: ciscoValues.action,
      source_scopes: sourceScopes,
      applications,
      log: ciscoValues.action === "pass" || ciscoValues.action === "drop" ? ciscoValues.log : false,
      replace_name: isEdit ? editTarget.name : undefined,
      // (2026-09) revision ที่ backend คำนวณจริงตอนอ่านตาราง - device_router.py อ่าน
      // config สดอีกครั้งภายใน DeviceLock ก่อนเขียนเสมอ (ดู vendor_translators/
      // cisco_zbf.py::resolve_cisco_zbf_safe_edit) ไม่เชื่อค่านี้ตรงๆ แค่ใช้เทียบว่า
      // ตรงกับของสดไหม - New ไม่มี revision (editTarget เป็น null) เป็น undefined ปกติ
      expected_revision: isEdit ? editTarget.revision || undefined : undefined,
    };

    setSubmitting(true);
    try {
      await validateDeviceCommand(devId, "create_firewall_policy", params);
      await runDeviceCommand(devId, "create_firewall_policy", params);
      onSaved();
    } catch (err) {
      // (2026-09) err.detail อาจเป็น structured object {code,message,...} จาก
      // CiscoZbfError.to_dict() แล้ว (เช่น CISCO_ZBF_CONCURRENT_MODIFICATION/
      // CISCO_ZBF_SHARED_OBJECT/CISCO_ZBF_ZONE_NOT_FOUND/CISCO_ZBF_NAME_COLLISION)
      // - ต้องดึง .message ออกมา ห้าม setError(object) ตรงๆ เพราะ React render
      // {error} เป็น object ไม่ได้ ค่าที่ผู้ใช้กรอกในฟอร์มยังคงอยู่เหมือนเดิมเสมอ
      // (ไม่ reset/ไม่ปิด modal เมื่อ error) ให้ผู้ใช้กด Refresh เอง
      const msg =
        typeof err.detail === "object" && err.detail?.message
          ? err.detail.message
          : err.detail || (isEdit ? "Failed to edit Firewall policy" : "Failed to create Firewall policy");
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  }

  // Junos match เป็น leaf-list จึงใช้ replace ที่ policy ชั้นในเมื่อแก้ identity เดิม
  // รวมเป็น edit-config/commit เดียว โดยไม่ replace policy ชั้นนอกของ zone pair
  async function handleSubmitJuniper(event) {
    event.preventDefault();
    setError("");

    const name = juniperValues.name.trim();
    const fromZone = juniperValues.fromZone.trim();
    const toZone = juniperValues.toZone.trim();
    if (!name) return setError("Please enter Policy name");
    if (!fromZone) return setError("Please select From Zone");
    if (!toZone) return setError("Please select To Zone");

    let sourceAddresses = ["any"];
    if (juniperValues.sourceMode === "specific") {
      sourceAddresses = juniperValues.sourceAddresses.map((addr) => addr.trim()).filter(Boolean);
      if (sourceAddresses.length === 0) {
        return setError("Please select at least 1 Source Address");
      }
    }
    let destinationAddresses = ["any"];
    if (juniperValues.destinationMode === "specific") {
      destinationAddresses = juniperValues.destinationAddresses.map((addr) => addr.trim()).filter(Boolean);
      if (destinationAddresses.length === 0) {
        return setError("Please select at least 1 Destination Address");
      }
    }
    const applications = juniperValues.applicationMode === "specific" ? juniperValues.applications : [];
    if (juniperValues.applicationMode === "specific" && applications.length === 0) {
      return setError("Please check at least 1 Application");
    }

    // Edit ที่เปลี่ยน From/To Zone = ย้าย Policy ข้ามคู่ Zone (ธุรกรรมลบต้นทาง+สร้าง
    // ปลายทางพร้อมกัน) แยกเส้นทางออกจาก edit ธรรมดาโดยสิ้นเชิง เพราะ backend ต้องรู้
    // ว่ากำลังย้าย ไม่ใช่แก้ policy ที่ identity เดิม - ต้องยืนยันก่อนเสมอ (ไม่ใช่แค่
    // ตอนชนชื่อเหมือน create) เพราะ Policy ตำแหน่งเดิมจะถูกนำออกจริงหลังสำเร็จ
    const zoneChanged = isEdit && (fromZone !== editTarget.fromZone || toZone !== editTarget.toZone);
    if (zoneChanged) {
      setPendingZoneMove({
        fromZone: editTarget.fromZone,
        toZone: editTarget.toZone,
        newFromZone: fromZone,
        newToZone: toZone,
      });
      return;
    }

    // ตัดสินว่ากำลัง "แก้ policy เดิมในตำแหน่งเดิม" หรือ "สร้าง policy ใหม่ที่คู่ zone
    // นี้" - identity จริงของ Junos policy คือ (name, from-zone, to-zone) รวมกัน ไม่ใช่
    // แค่ name เฉยๆ (Junos ไม่มีข้อจำกัด 1 policy ต่อ 1 zone pair - ชื่อเดียวกันอยู่คนละ
    // zone pair ได้ปกติ เป็นคนละ entry กันจริง)
    //   - mode="edit" ตรงๆ (จากตาราง ไม่เปลี่ยน zone): identity ล็อกอยู่แล้วเสมอ = editTarget
    //   - mode="create" ที่พิมพ์ชื่อ+คู่ zone ชนกับ policy ที่มีอยู่แล้วบนอุปกรณ์:
    //     ต้องแสดง dialog เตือนและขอคำยืนยันก่อนแทนที่เสมอ (ป้องกันเขียนทับโดยไม่ตั้งใจ)
    const currentKey = getJuniperPolicyKey({ name, fromZone, toZone });
    const removalTarget = isEdit
      ? editTarget
      : existingPolicies.find((p) => getJuniperPolicyKey(p) === currentKey) || null;

    if (!isEdit && removalTarget) {
      setPendingReplaceTarget(removalTarget);
      return;
    }

    await executeSubmitJuniper(removalTarget, false);
  }

  async function executeSubmitJuniper(target, confirmedReplace = false) {
    const name = juniperValues.name.trim();
    const fromZone = juniperValues.fromZone.trim();
    const toZone = juniperValues.toZone.trim();

    let sourceAddresses = ["any"];
    if (juniperValues.sourceMode === "specific") {
      sourceAddresses = juniperValues.sourceAddresses.map((addr) => addr.trim()).filter(Boolean);
    }
    let destinationAddresses = ["any"];
    if (juniperValues.destinationMode === "specific") {
      destinationAddresses = juniperValues.destinationAddresses.map((addr) => addr.trim()).filter(Boolean);
    }
    const applications = juniperValues.applicationMode === "specific" ? juniperValues.applications : [];

    setSubmitting(true);
    try {
      await runDeviceCommand(devId, "set_security_policy", {
        from_zone: fromZone,
        to_zone: toZone,
        policy_name: name,
        action: juniperValues.action,
        source_addresses: sourceAddresses,
        destination_addresses: destinationAddresses,
        // `undefined` means "preserve the existing Brownfield field" to the
        // Juniper overlay writer.  Any is an explicit user choice, so send the
        // Junos leaf-list value instead; otherwise Specific -> Any appears to
        // save successfully while the old applications remain on the device.
        applications: applications.length > 0 ? applications : ["any"],
        replace_name: target ? target.name : undefined,
        confirm_replace_existing: (!isEdit && !!target) || confirmedReplace ? true : undefined,
        expected_revision: target?.revision || undefined,
      });
      setPendingReplaceTarget(null);
      onSaved();
    } catch (err) {
      const msg =
        typeof err.detail === "object" && err.detail?.message
          ? err.detail.message
          : err.detail || (target ? "Failed to edit Policy" : "Failed to create Policy");
      setError(msg);
      setPendingReplaceTarget(null);
    } finally {
      setSubmitting(false);
    }
  }

  // ย้าย Policy ข้ามคู่ Zone - ธุรกรรมเดียว (ลบต้นทาง+สร้างปลายทางใน edit-config/
  // commit เดียวกันฝั่ง backend) ห้ามยิงลบก่อนแล้วค่อยสร้างแยก 2 API call เพราะถ้าขั้น
  // สร้างล้มเหลว Policy จะหายไปเลย - เรียกจากปุ่ม "ยืนยันการย้าย" ใน modal เท่านั้น
  async function executeSubmitJuniperZoneMove() {
    const fromZone = juniperValues.fromZone.trim();
    const toZone = juniperValues.toZone.trim();

    let sourceAddresses = ["any"];
    if (juniperValues.sourceMode === "specific") {
      sourceAddresses = juniperValues.sourceAddresses.map((addr) => addr.trim()).filter(Boolean);
    }
    let destinationAddresses = ["any"];
    if (juniperValues.destinationMode === "specific") {
      destinationAddresses = juniperValues.destinationAddresses.map((addr) => addr.trim()).filter(Boolean);
    }
    const applications = juniperValues.applicationMode === "specific" ? juniperValues.applications : [];

    setSubmitting(true);
    try {
      await runDeviceCommand(devId, "move_security_policy_zone", {
        from_zone: editTarget.fromZone,
        to_zone: editTarget.toZone,
        policy_name: editTarget.name,
        new_from_zone: fromZone,
        new_to_zone: toZone,
        action: juniperValues.action,
        source_addresses: sourceAddresses,
        destination_addresses: destinationAddresses,
        // Keep the same explicit Any semantics when moving a Policy to a new
        // Zone pair.  The move builder also treats undefined as preserve.
        applications: applications.length > 0 ? applications : ["any"],
        expected_revision: editTarget.revision || undefined,
      });
      setPendingZoneMove(null);
      onSaved();
    } catch (err) {
      const msg =
        typeof err.detail === "object" && err.detail?.message
          ? err.detail.message
          : err.detail || "Failed to move Policy";
      setError(msg);
      setPendingZoneMove(null);
    } finally {
      setSubmitting(false);
    }
  }

  const handleSubmit = isJuniper ? handleSubmitJuniper : handleSubmitCisco;

  // log มีผลเฉพาะ pass/drop (inspect ไม่มี log) - ซ่อน toggle ไปเลยตอน inspect
  const logAvailable = !isJuniper && (ciscoValues.action === "pass" || ciscoValues.action === "drop");
  const ciscoActionKnown = !!ciscoValues.action && ACTIONS.some((a) => a.value === ciscoValues.action);
  const ciscoFieldsDisabled = submitting || ciscoReadOnly;
  const juniperFieldsDisabled = submitting || (isEdit && editTarget?.editable === false);
  const ciscoSubmitDisabled =
    submitting ||
    ciscoReadOnly ||
    !ciscoZoneReady ||
    zoneOptions.length === 0 ||
    ciscoZoneStale ||
    ciscoNoPairAvailable ||
    (isEdit && !editTarget?.revision);
  const policyEditLocked = isEdit && (isJuniper ? editTarget?.editable === false : ciscoReadOnly);
  const policyLockReasons = policyEditLocked
    ? (isJuniper ? editTarget?.unsupportedReasons : editTarget?.blockingErrors || editTarget?.readOnlyReasons) || []
    : [];

  return (
    <>
      <form className="interface-configuration-form" onSubmit={handleSubmit}>
        {isEdit && (
          <div className="command-output-title">
            Edit: {isJuniper ? editTarget.name : ciscoValues.name}
            {policyEditLocked && (
              <span
                className="locked-form-indicator"
                title={policyLockReasons.join("; ") || "This policy cannot be changed"}
                aria-label="This policy cannot be changed"
              >🔒</span>
            )}
          </div>
        )}
        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

        {!isJuniper && ciscoZoneLoadFailed && (
          <div className="form-error" role="alert">
            Failed to load zone list from device - cannot save until refreshed successfully
          </div>
        )}

        {!isJuniper && ciscoZoneReady && zoneOptions.length === 0 && (
          <div className="form-warning" style={{ backgroundColor: "#fef3c7", border: "1px solid #f59e0b", color: "#92400e", padding: "0.75rem", borderRadius: "6px", marginBottom: "1rem" }}>
            No zones exist on this device - please create zones in Zone Interfaces first
          </div>
        )}

        <div className="interface-configuration-form-field">
          <label className="data-label" htmlFor="fw-policy-name">
            Policy Name
          </label>
          <input
            id="fw-policy-name"
            type="text"
            placeholder={isJuniper ? "ALLOW-WEB" : "LAN_TO_WAN"}
            value={isJuniper ? juniperValues.name : ciscoValues.name}
            onChange={(event) => (isJuniper ? setJuniperField("name", event.target.value) : setCiscoField("name", event.target.value))}
            disabled={isJuniper ? nameLocked : isEdit}
            required
          />
        </div>

        <ZoneSelectField
          id="fw-from-zone"
          label={isJuniper ? `From Zone${isEdit ? " (changing will move Policy)" : ""}` : "From Zone"}
          value={isJuniper ? juniperValues.fromZone : ciscoValues.fromZone}
          onChange={(value) => (isJuniper ? setJuniperField("fromZone", value) : setCiscoFromZone(value))}
          options={isJuniper ? zoneOptions : ciscoFromZoneOptions}
          placeholder="-- Select Zone --"
          disabled={isJuniper ? (juniperFieldsDisabled || undefined) : ciscoFieldsDisabled || isEdit}
          checkStale={!isJuniper}
        />

        <ZoneSelectField
          id="fw-to-zone"
          label={isJuniper ? `To Zone${isEdit ? " (changing will move Policy)" : ""}` : "To Zone"}
          value={isJuniper ? juniperValues.toZone : ciscoValues.toZone}
          onChange={(value) => (isJuniper ? setJuniperField("toZone", value) : setCiscoToZone(value))}
          options={isJuniper ? zoneOptions : ciscoToZoneOptions}
          placeholder="-- Select Zone --"
          disabled={isJuniper ? (juniperFieldsDisabled || undefined) : ciscoFieldsDisabled || isEdit}
          checkStale={!isJuniper}
        />

        {!isJuniper && ciscoZonePairHint && (
          <div className="form-error" role="alert">
            {ciscoZonePairHint}
          </div>
        )}

        {!isJuniper && ciscoNoToZoneAvailable && (
          <div
            className="form-warning"
            style={{ backgroundColor: "#fef3c7", border: "1px solid #f59e0b", color: "#92400e", padding: "0.75rem", borderRadius: "6px", marginBottom: "1rem" }}
          >
            No available zones for To Zone (all remaining zones are already used in a Zone Pair with "
            {ciscoValues.fromZone}"). Please select another From Zone
          </div>
        )}

        {!isJuniper && ciscoNoFromZoneAvailable && (
          <div
            className="form-warning"
            style={{ backgroundColor: "#fef3c7", border: "1px solid #f59e0b", color: "#92400e", padding: "0.75rem", borderRadius: "6px", marginBottom: "1rem" }}
          >
            No available zones for From Zone (all remaining zones are already used in a Zone Pair to "
            {ciscoValues.toZone}"). Please select another To Zone
          </div>
        )}

        {isJuniper ? (
          <>
            <div className="interface-configuration-form-field">
              <label className="data-label">Policy Action</label>
              {isEdit && editTarget?.action && !["permit", "deny"].includes(editTarget.action) ? (
                <input type="text" value={editTarget.action} disabled readOnly title="This action cannot be changed in this form" />
              ) : (
                <select
                  value={juniperValues.action}
                  onChange={(event) => setJuniperField("action", event.target.value)}
                  disabled={juniperFieldsDisabled}
                >
                  <option value="permit">Permit</option>
                  <option value="deny">Deny</option>
                </select>
              )}
            </div>

            <div className="interface-configuration-form-field">
              <label className="data-label">Source Address</label>
              <div className={`segmented-control${juniperFieldsDisabled ? " locked-choice" : ""}`}>
                <input
                  type="radio"
                  id="fw-src-any"
                  name="fw-source-mode"
                  value="any"
                  checked={juniperValues.sourceMode === "any"}
                  onChange={(event) => setJuniperField("sourceMode", event.target.value)}
                  disabled={juniperFieldsDisabled}
                />
                <label htmlFor="fw-src-any">Any</label>
                <input
                  type="radio"
                  id="fw-src-specific"
                  name="fw-source-mode"
                  value="specific"
                  checked={juniperValues.sourceMode === "specific"}
                  onChange={(event) => setJuniperField("sourceMode", event.target.value)}
                  disabled={juniperFieldsDisabled}
                />
                <label htmlFor="fw-src-specific">Specific</label>
              </div>
            </div>

            {juniperValues.sourceMode === "specific" &&
              juniperValues.sourceAddresses.map((addr, index) => (
                <div className="interface-configuration-form-field-third" key={index}>
                  <label className="data-label">
                    {index === 0 ? "Source Address (Address Book)" : `Source Address ${index + 1}`}
                  </label>
                  <select value={addr} disabled={juniperFieldsDisabled} onChange={(event) => setSourceAddressAt(index, event.target.value)}>
                    <option value="">-- Select Address --</option>
                    {addressOptions.map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                  {index === juniperValues.sourceAddresses.length - 1 ? (
                    <button type="button" className="mini-btn btn-ghost" disabled={juniperFieldsDisabled} onClick={addSourceAddress}>
                      +
                    </button>
                  ) : (
                    <button type="button" className="mini-btn btn-ghost" disabled={juniperFieldsDisabled} onClick={() => removeSourceAddressAt(index)}>
                      -
                    </button>
                  )}
                </div>
              ))}

            <div className="interface-configuration-form-field">
              <label className="data-label">Destination Address</label>
              <div className={`segmented-control${juniperFieldsDisabled ? " locked-choice" : ""}`}>
                <input
                  type="radio"
                  id="fw-dst-any"
                  name="fw-destination-mode"
                  value="any"
                  checked={juniperValues.destinationMode === "any"}
                  onChange={(event) => setJuniperField("destinationMode", event.target.value)}
                  disabled={juniperFieldsDisabled}
                />
                <label htmlFor="fw-dst-any">Any</label>
                <input
                  type="radio"
                  id="fw-dst-specific"
                  name="fw-destination-mode"
                  value="specific"
                  checked={juniperValues.destinationMode === "specific"}
                  onChange={(event) => setJuniperField("destinationMode", event.target.value)}
                  disabled={juniperFieldsDisabled}
                />
                <label htmlFor="fw-dst-specific">Specific</label>
              </div>
            </div>

            {juniperValues.destinationMode === "specific" &&
              juniperValues.destinationAddresses.map((addr, index) => (
                <div className="interface-configuration-form-field-third" key={index}>
                  <label className="data-label">
                    {index === 0 ? "Destination Address (Address Book)" : `Destination Address ${index + 1}`}
                  </label>
                  <select value={addr} disabled={juniperFieldsDisabled} onChange={(event) => setDestinationAddressAt(index, event.target.value)}>
                    <option value="">-- Select Address --</option>
                    {addressOptions.map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                  {index === juniperValues.destinationAddresses.length - 1 ? (
                    <button type="button" className="mini-btn btn-ghost" disabled={juniperFieldsDisabled} onClick={addDestinationAddress}>
                      +
                    </button>
                  ) : (
                    <button
                      type="button"
                      className="mini-btn btn-ghost"
                      disabled={juniperFieldsDisabled}
                      onClick={() => removeDestinationAddressAt(index)}
                    >
                      -
                    </button>
                  )}
                </div>
              ))}

            <ApplicationCheckboxPicker
              idPrefix="fw-juniper"
              modeValue={juniperValues.applicationMode}
              onModeChange={handleApplicationModeChange}
              catalog={JUNIPER_APPLICATIONS}
              selected={juniperValues.applications}
              onToggle={toggleApplication}
              formatLabel={formatApplicationDisplay}
              disabled={juniperFieldsDisabled}
              customSuffix="(custom)"
            />
          </>
        ) : (
          <>
            <div className="interface-configuration-form-field">
              <label className="data-label" htmlFor="fw-cisco-action">Action</label>
              {isEdit && !ciscoActionKnown ? (
                <input id="fw-cisco-action" type="text" value="Unknown" disabled readOnly title="The device action could not be parsed safely" />
              ) : (
                <select
                  id="fw-cisco-action"
                  value={ciscoValues.action}
                  onChange={(event) => setCiscoAction(event.target.value)}
                  disabled={ciscoFieldsDisabled}
                >
                  {ACTIONS.map((action) => (
                    <option key={action.value} value={action.value}>
                      {action.label}
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div className="interface-configuration-form-field">
              <label className="data-label">Source IP/CIDR</label>
              {ciscoValues.sourceMode === "unknown" ? (
                <input type="text" value="Unknown" disabled readOnly title="The device source IP could not be parsed safely" />
              ) : (
                <div
                  className={`segmented-control${ciscoFieldsDisabled ? " locked-choice" : ""}`}
                  title={ciscoFieldsDisabled ? "Source IP/CIDR cannot be changed" : undefined}
                >
                  <input
                    type="radio"
                    id="fw-scope-any"
                    name="fw-scope-mode"
                    value="any"
                    checked={ciscoValues.sourceMode === "any"}
                    onChange={(event) => setCiscoField("sourceMode", event.target.value)}
                    disabled={ciscoFieldsDisabled}
                  />
                  <label htmlFor="fw-scope-any">Any</label>
                  <input
                    type="radio"
                    id="fw-scope-specific"
                    name="fw-scope-mode"
                    value="specific"
                    checked={ciscoValues.sourceMode === "specific"}
                    onChange={(event) => setCiscoField("sourceMode", event.target.value)}
                    disabled={ciscoFieldsDisabled}
                  />
                  <label htmlFor="fw-scope-specific">Specific</label>
                </div>
              )}
            </div>

            {ciscoValues.sourceMode === "specific" && (
              <MultiCidrFields
                idPrefix="fw-scope"
                rows={ciscoValues.sourceScopes}
                onChangeAt={setScopeAt}
                onAdd={addScope}
                onRemoveAt={removeScopeAt}
                disabled={ciscoFieldsDisabled}
              />
            )}

            {ciscoValues.applicationMode === "unknown" ? (
              <div className="interface-configuration-form-field">
                <label className="data-label">Services (Application)</label>
                <input type="text" value="Unknown" disabled readOnly title="The device application could not be parsed safely" />
              </div>
            ) : (
              <ApplicationCheckboxPicker
                idPrefix="fw-cisco"
                modeValue={ciscoValues.applicationMode}
                onModeChange={handleCiscoApplicationModeChange}
                catalog={CISCO_ZBF_APPLICATIONS}
                selected={ciscoValues.applications}
                onToggle={toggleCiscoApplication}
                formatLabel={formatCiscoApplicationDisplay}
                disabled={ciscoFieldsDisabled}
                customSuffix="(custom/unsupported)"
              />
            )}

            {logAvailable && (
              <div className="interface-configuration-form-field">
                <label className="data-label">Log</label>
                <div className="toggle-switch-container">
                  <input
                    type="checkbox"
                    id="fw-log-toggle"
                    checked={ciscoValues.log}
                    onChange={(event) => setCiscoField("log", event.target.checked)}
                    disabled={ciscoFieldsDisabled}
                  />
                  <label className="toggleSwitch" htmlFor="fw-log-toggle"></label>
                </div>
              </div>
            )}
          </>
        )}

        <FormActions
          submitting={submitting}
          isEdit={isEdit}
          submitDisabled={
            isJuniper
              ? submitting || !!pendingReplaceTarget || !!pendingZoneMove || (isEdit && editTarget?.editable === false)
              : ciscoSubmitDisabled
          }
          cancelDisabled={isJuniper ? submitting || !!pendingReplaceTarget || !!pendingZoneMove : submitting}
          onCancel={onClose}
        />
      </form>

      {isJuniper && pendingZoneMove && (
        <div className="modal-overlay" onClick={() => !submitting && setPendingZoneMove(null)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Confirm Firewall Policy Move</h2>
              <button
                type="button"
                className="modal-close"
                onClick={() => setPendingZoneMove(null)}
                aria-label="Close"
                disabled={submitting}
              >
                &times;
              </button>
            </div>
            <p>
              The system will move Policy ‘<strong>{editTarget?.name}</strong>’ from Zone Pair{" "}
              <strong>
                {pendingZoneMove.fromZone} → {pendingZoneMove.toZone}
              </strong>{" "}
              to Zone Pair{" "}
              <strong>
                {pendingZoneMove.newFromZone} → {pendingZoneMove.newToZone}
              </strong>.{" "}
              Upon completion, the policy at the original location will be removed. Do you want to confirm this move?
            </p>
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setPendingZoneMove(null)}
                disabled={submitting}
              >
                Back to Edit
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => executeSubmitJuniperZoneMove()}
                disabled={submitting}
              >
                {submitting ? "Moving..." : "Confirm Move"}
              </button>
            </div>
          </div>
        </div>
      )}

      {isJuniper && pendingReplaceTarget && (
        <div className="modal-overlay" onClick={() => !submitting && setPendingReplaceTarget(null)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h2>Confirm Firewall Policy Replacement</h2>
              <button
                type="button"
                className="modal-close"
                onClick={() => setPendingReplaceTarget(null)}
                aria-label="Close"
                disabled={submitting}
              >
                &times;
              </button>
            </div>
            <p>
              Policy ‘<strong>{pendingReplaceTarget.name}</strong>’ already exists in Zone Pair{" "}
              <strong>{pendingReplaceTarget.fromZone}</strong> → <strong>{pendingReplaceTarget.toZone}</strong>.{" "}
              If you proceed, the system will replace the existing Policy configuration with values from this form. Do you want to confirm replacing the existing Policy?
            </p>
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setPendingReplaceTarget(null)}
                disabled={submitting}
              >
                Back to Edit
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => executeSubmitJuniper(pendingReplaceTarget, true)}
                disabled={submitting}
              >
                {submitting ? "Replacing..." : "Confirm Replace"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
