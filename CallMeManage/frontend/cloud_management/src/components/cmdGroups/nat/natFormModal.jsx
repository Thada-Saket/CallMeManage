import DismissibleError from "../../DismissibleError";
import { NAT_RECONNECT_HINT } from "./natReconnectHint";
import { useEffect, useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import IPv4Input from "../../common/IPv4Input";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { splitInterfaceName } from "../../../utils/interfaceName";
import { parseJuniperZones } from "../network/zoneInterfaces";
import {
  ciscoNatInsideCandidates,
  defaultCiscoNatInsideNames,
  initialCiscoNatOutbound,
} from "./ciscoNatInterfaces";
import CheckboxDropdown from "../../common/CheckboxDropdown";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// (2026-09) err.detail ของ create_nat_policy/remove_nat_policy timeout เปลี่ยนเป็น
// {code, message} แทนสตริงเปล่า (ดู device_router.py's NETCONF_WRITE_OUTCOME_UNKNOWN)
// เรนเดอร์ object ตรงๆ ใน JSX จะ throw - ต้องดึง .message ออกมาก่อนเสมอ คำสั่งอื่นที่
// detail ยังเป็นสตริงปกติผ่านไม่เปลี่ยนพฤติกรรม
function errorMessage(err, fallback) {
  const detail = err?.detail;
  if (detail && typeof detail === "object") return detail.message || fallback;
  return detail || fallback;
}

function validateSpecificScopes(entries) {
  const scopes = [];
  for (const [index, entry] of entries.entries()) {
    if (!entry.trim()) continue;
    const result = validateIPv4Input(entry, { mode: "cidr" });
    if (!result.valid) {
      return { error: `IP/Prefix entry ${index + 1}: ${result.error}`, scopes: [] };
    }
    scopes.push(result.value);
  }
  return scopes.length > 0
    ? { error: "", scopes }
    : { error: "Please enter at least 1 IP/Prefix (e.g. 192.168.1.0/24)", scopes: [] };
}

// ชื่อ ACL/NAT rule คงที่ - user ไม่กรอกชื่อเองแล้ว (ตามที่ตกลง: ACL/overload
// เป็นเรื่องที่ backend จัดการเองทั้งหมด) NAT เป็นค่าเดียวทั้งอุปกรณ์อยู่แล้ว
// เลยใช้ชื่อคงที่ได้โดยไม่ชนกัน - ถ้าแก้ไข NAT ที่มีอยู่แล้ว (เช่น "HQ-NAT" ที่
// ตั้งมาก่อนหน้านี้ผ่าน CLI) ใช้ชื่อเดิมต่อเสมอ ไม่เปลี่ยนชื่อทิ้งของเดิม
const DEFAULT_NAT_NAME = "CLIENT_NAT";

// เจอบั๊กจริง (Juniper): edit-config ที่ถูกอุปกรณ์ปฏิเสธด้วย rpc-error ตอบกลับ
// เป็น HTTP 200 ปกติพร้อม {ok: false, errors: [...]} ไม่ใช่ exception -
// runDeviceCommand เลย resolve เฉยๆ ไม่ throw (pattern เดียวกับที่แก้ไปแล้วใน
// dhcpFormModal.jsx/zoneInterfacesFormModal.jsx/security_tunnel.jsx)
function assertCommandOk(response, fallbackMessage) {
  const result = response?.result;
  if (result && result.ok === false) {
    const message = (result.errors || []).map((e) => e.message).filter(Boolean).join("; ") || fallbackMessage;
    const err = new Error(message);
    err.detail = message;
    throw err;
  }
  return response;
}

function ZoneCheckboxPicker({ label, values, options, onToggle, disabled = false }) {
  const full = values.length >= 8;
  return (
    <div className="interface-configuration-form-field">
      <label className="data-label">{label}</label>
      <CheckboxDropdown
        ariaLabel={`Select ${label}`}
        disabled={disabled}
        title={disabled ? `${label} is fixed for this rule` : undefined}
        summary={<>
          <input
            type="text"
            readOnly
            tabIndex={-1}
            aria-label={`Selected ${label}`}
            placeholder="-- Select Zone --"
            value={values.join(", ")}
          />
        </>}
      >
        <div className="zone-interface-picker-options">
          {options.length === 0 && <div className="field-hint">No Security Zone found</div>}
          {options.map((zone) => {
            const checked = values.includes(zone);
            return (
              <label key={zone} className="zone-interface-picker-option">
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={disabled || (!checked && full)}
                  onChange={() => onToggle(zone)}
                />
                {zone}
              </label>
            );
          })}
        </div>
      </CheckboxDropdown>
      {full && <span className="field-hint">Up to 8 zones can be selected per Junos limit</span>}
    </div>
  );
}

// ========== Juniper: rewrite รอบนี้ - ทิ้ง create_nat_policy (เคย derive
// zone ปลายทางเองจาก via interface + สมมติ "trust" เป็น from-zone ตายตัว ไม่
// เคยทดสอบกับอุปกรณ์จริง และไม่ตรงกับวิธีที่ Junos SRX ใช้ zone-based NAT จริง)
// เปลี่ยนไปใช้ set_nat ตรงๆ ตาม syntax จริงที่ user ยืนยันมา:
//   set security nat source rule-set X from zone LAN
//   set security nat source rule-set X to zone WAN
//   set security nat source rule-set X rule Y match source-address ...
//   set security nat source rule-set X rule Y match destination-address 0.0.0.0/0
//   set security nat source rule-set X rule Y then source-nat interface|pool
// "via WAN interface" แบบ Cisco ตัดออก (ไม่ตรงกับวิธีของ Junos - NAT ผูกกับ
// zone ไม่ใช่ interface) แทนที่ด้วย From/To Zone แบบ multi-select ตาม YANG จริง
// (สูงสุดฝั่งละ 8) โดย Junos เลือก egress interface และ source IP จาก routing
// table เอง ไม่ต้องให้ผู้ใช้ระบุ IP ขาออก (rule_set == identity จริงบนอุปกรณ์
// ล็อกตอน edit เหมือน static NAT/
// port-forward ที่มีอยู่แล้ว - เปลี่ยนชื่อระหว่าง edit จะกลายเป็นสร้าง rule-set
// ใหม่ ตัวเดิมค้างเป็น orphan)
//
// เจอบั๊กจริง (2026-08-07): เดิม hardcode rule name เป็น "MATCH-ALL" คงที่ทุก
// policy - policy แรกสร้างผ่าน แต่ policy ที่ 2 เป็นต้นไป commit fail เสมอด้วย
// rpc-error "rule (MATCH-ALL) name check fail" - ยืนยันจากอุปกรณ์จริงแล้วว่า
// SRX นี้บังคับชื่อ rule ต้อง unique ข้าม rule-set ทั้งหมดภายใต้
// "security nat source" (ไม่ใช่แค่ unique ภายใน rule-set เดียวกันเหมือนที่คิด
// ไว้ตอนแรก) - แก้โดยใช้ rule_set name (ที่ unique อยู่แล้วเพราะเป็น identity
// หลักของ policy) เป็น rule name ไปด้วยเลย แทนค่าคงที่ตัวเดียวที่ชนกันเอง
function natRuleNameFor(ruleSetName) {
  return ruleSetName;
}

function buildInitialValues(mode, editTarget) {
  if (mode !== "edit" || !editTarget) {
    return {
      name: "",
      fromZones: [],
      toZones: [],
      scopeMode: "any",
      scopes: [""],
      translateMode: "interface",
      poolName: "",
    };
  }
  const sourceAddresses = editTarget.sourceAddresses || ["0.0.0.0/0"];
  const isAny = sourceAddresses.length === 1 && sourceAddresses[0] === "0.0.0.0/0";
  return {
    name: editTarget.name || "",
    fromZones: editTarget.fromZones && editTarget.fromZones.length ? editTarget.fromZones : [],
    toZones: editTarget.toZones && editTarget.toZones.length
      ? editTarget.toZones
      : editTarget.toZone ? [editTarget.toZone] : [],
    scopeMode: isAny ? "any" : "specific",
    scopes: isAny ? [""] : sourceAddresses,
    translateMode: editTarget.mode === "pool" ? "pool" : "interface",
    poolName: editTarget.mode === "pool" ? editTarget.target || "" : "",
  };
}

function JuniperNatForm({ devId, mode = "create", editTarget = null, allRows = [], onSaved, onClose }) {
  const isEdit = mode === "edit" && !!editTarget;
  const sharedRuleSet = isEdit && Number(editTarget?.ruleSetRuleCount) > 1;
  const [values, setValues] = useState(buildInitialValues(mode, editTarget));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const { data: zoneData } = getDeviceInformation(devId, "get_security_zone_information");
  const zones = zoneData?.normalized ? parseJuniperZones(zoneData.result) || [] : [];
  const zoneOptions = zones.map((zone) => zone.name).filter(Boolean);

  const { data: poolData, loading: poolLoading } = getDeviceInformation(
    devId,
    values.translateMode === "pool" && zoneData?.normalized ? "get_nat_pool_information" : null,
  );
  const poolOptions = poolData?.normalized
    ? ensureArray(poolData.result?.payload?.data?.configuration?.security?.nat?.source?.pool)
        .map((pool) => pool?.name)
        .filter(Boolean)
    : [];

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  function toggleZone(field, zone) {
    const current = values[field];
    setField(field, current.includes(zone) ? current.filter((value) => value !== zone) : [...current, zone]);
  }

  function setScopeAt(index, value) {
    const next = [...values.scopes];
    next[index] = value;
    setField("scopes", next);
  }

  function addScope() {
    setField("scopes", [...values.scopes, ""]);
  }

  function removeScopeAt(index) {
    if (values.scopes.length <= 1) return;
    setField("scopes", values.scopes.filter((_, i) => i !== index));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    const name = values.name.trim();
    if (!name) return setError("Please enter a Rule-set name");
    if (!isEdit && allRows.some((row) => row?.ruleSet === name || row?.name === name)) {
      return setError(`Name "${name}" already exists on the device`);
    }

    const fromZones = values.fromZones.map((z) => z.trim()).filter(Boolean);
    const toZones = values.toZones.map((z) => z.trim()).filter(Boolean);
    if (fromZones.length === 0) return setError("Please select at least 1 From Zone");
    if (toZones.length === 0) return setError("Please select at least 1 To Zone");
    if (values.translateMode === "pool" && !values.poolName) {
      return setError("Please select a NAT pool to use (create one in NAT Pool first if not present)");
    }

    let sourceAddresses = ["0.0.0.0/0"];
    if (values.scopeMode === "specific") {
      const checked = validateSpecificScopes(values.scopes);
      if (checked.error) return setError(checked.error);
      sourceAddresses = checked.scopes;
    }

    setSubmitting(true);
    try {
      // Edit ส่ง identity เดิมไปให้ translator ทำ nc:operation="replace" เฉพาะ
      // rule ที่เลือกใน candidate เดียว ไม่มีช่วงที่ remove สำเร็จแต่ set ใหม่ล้ม
      // และไม่แตะ sibling rules ใน brownfield rule-set เดียวกัน
      const params = {
        rule_set: isEdit ? editTarget.ruleSet : name,
        rule_name: natRuleNameFor(name),
        from_zones: fromZones,
        to_zones: toZones,
        source_addresses: sourceAddresses,
      };
      // (bug 97) เลือกทางแปลที่อยู่ให้ครบก่อน validate ทั้งตอนสร้างและแก้ไข
      // ต้องส่ง pool_name หรือ use_interface เพียงตัวเดียว ไม่ผูกกับ isEdit
      if (values.translateMode === "pool") params.pool_name = values.poolName;
      else params.use_interface = true;
      if (isEdit) {
        params.replace_rule_set = editTarget.ruleSet;
        params.replace_rule_name = editTarget.name;
      }
      await validateDeviceCommand(devId, "set_nat", params);
      assertCommandOk(
        await runDeviceCommand(devId, "set_nat", params),
        isEdit ? "Failed to edit NAT" : "Failed to create NAT"
      );
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit NAT" : "Failed to create NAT"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && <div className="command-output-title">Edit: {editTarget.name}</div>}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">NAT Rule Name</label>
        <input
          type="text"
          placeholder="SNAT-TO-INTERNET"
          value={values.name}
          onChange={(event) => setField("name", event.target.value)}
          disabled={isEdit}
          required
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Public IP Source</label>
        <div className="segmented-control">
          <input
            type="radio"
            id="mode-wanip"
            name="translate-mode"
            value="interface"
            checked={values.translateMode === "interface"}
            onChange={(event) => setField("translateMode", event.target.value)}
          />
          <label htmlFor="mode-wanip">WAN Interface</label>
          <input
            type="radio"
            id="mode-pool"
            name="translate-mode"
            value="pool"
            checked={values.translateMode === "pool"}
            onChange={(event) => setField("translateMode", event.target.value)}
          />
          <label htmlFor="mode-pool">IP Pool</label>
        </div>
      </div>

      {values.translateMode === "pool" && (
        <div className="interface-configuration-form-field">
          <label className="data-label">NAT Pool</label>
          {poolLoading ? (
            <select disabled value="">
              <option value="">Loading NAT pools...</option>
            </select>
          ) : (
            <select value={values.poolName} onChange={(event) => setField("poolName", event.target.value)}>
              <option value="" disabled>-- Select pool --</option>
              {poolOptions.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          )}
        </div>
      )}

      <div className="interface-configuration-form-field">
        <label className="data-label">Allow IP</label>
        <div className="segmented-control">
          <input
            type="radio"
            id="scope-any"
            name="scope-mode"
            value="any"
            checked={values.scopeMode === "any"}
            onChange={(event) => setField("scopeMode", event.target.value)}
          />
          <label htmlFor="scope-any">Any</label>
          <input
            type="radio"
            id="scope-specific"
            name="scope-mode"
            value="specific"
            checked={values.scopeMode === "specific"}
            onChange={(event) => setField("scopeMode", event.target.value)}
          />
          <label htmlFor="scope-specific">Specific</label>
        </div>
      </div>

      {values.scopeMode === "specific" &&
        values.scopes.map((scope, index) => (
          <div className="interface-configuration-form-field-third" key={index}>
            <label className="data-label">{index === 0 ? "IP/Prefix" : `IP/Prefix ${index + 1}`}</label>
            <IPv4Input
              mode="cidr"
              label={`Allow IP ${index + 1}`}
              value={scope}
              onChange={(value) => setScopeAt(index, value)}
            />
            {index === 0 && (
              <button type="button" className="mini-btn btn-ghost" onClick={addScope} aria-label="Add Allow IP">
                +
              </button>
            )}
            {index > 0 && (
              <button type="button" className="mini-btn btn-ghost" onClick={() => removeScopeAt(index)} aria-label={`Remove Allow IP ${index + 1}`}>
                -
              </button>
            )}
          </div>
        ))}


      <ZoneCheckboxPicker
        label="From Zone"
        values={values.fromZones}
        options={zoneOptions}
        onToggle={(zone) => toggleZone("fromZones", zone)}
        disabled={submitting || sharedRuleSet}
      />

      <ZoneCheckboxPicker
        label="To Zone"
        values={values.toZones}
        options={zoneOptions}
        onToggle={(zone) => toggleZone("toZones", zone)}
        disabled={submitting || sharedRuleSet}
      />

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Sending..." : isEdit ? "Save" : "OK"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}

// ========== Cisco: ฟอร์มใหม่ทั้งหมด ตามที่ตกลง 3 ข้อ ==========
// 1. เลือกขา Outbound (via) ก่อนเสมอ - ขาอื่นๆ (toggle list) ยังไม่โผล่จนกว่าจะเลือก
// 2. Source ผ่าน WAN IP (ของ via) หรือ NAT Pool
// 3. LAN Allow เลือก Any หรือ Specific ได้: Any เขียน ACL permit any ส่วน Specific
//    รับ IP/Prefix ได้หลายวงตามรูปแบบ Source IP ของ Juniper; toggle list ด้านล่างยัง
//    ใช้เลือกเฉพาะ interface ที่เป็น NAT inside (แก้ปัญหา Tunnel0 ที่ไม่ควรเป็น inside)
// ACL name/overload ไม่ให้กรอกเลย - backend คำนวณ/ตั้งชื่อคงที่เอง (DEFAULT_NAT_NAME
// หรือชื่อเดิมถ้าแก้ไข NAT ที่มีอยู่แล้ว)
function CiscoNatForm({
  devId,
  currentRule,
  insideNames,
  outsideName,
  outboundInterfaces,
  ifaceRows,
  aclScopes,
  onSaved,
}) {
  // NAT แบบ pool ไม่มีชื่อ interface อยู่ใน rule.target (ค่าตรงนั้นคือชื่อ pool)
  // จึงต้องเติมขาออกจาก interface ที่มี `ip nat outside` อยู่จริงแทน
  const [via, setVia] = useState(initialCiscoNatOutbound(currentRule, outsideName));
  const [translateMode, setTranslateMode] = useState(currentRule?.mode === "pool" ? "pool" : "interface");
  const [poolName, setPoolName] = useState(currentRule?.mode === "pool" ? currentRule.target : "");
  // ตอนแก้ไข NAT ที่มีอยู่แล้ว: pre-fill จากขาที่ "เป็น inside อยู่จริงตอนนี้"
  // (insideNames) ไม่ใช่ reset เป็น "ติ๊กหมด" ใหม่ - ต้องโชว์สถานะจริงให้ user
  // เห็นก่อนว่าอะไรเปิดอยู่ ตอนสร้างใหม่ (ไม่มี currentRule) ถึงจะ default ติ๊ก
  // ทุก interface ที่มี private IP จริง (ยกเว้น via) เหมือนพฤติกรรมเดิม;
  // IPv4 ช่วงอื่นยังเลือกได้แต่ไม่ถูกเลือกให้อัตโนมัติ.
  const defaultInsideSet = currentRule
    ? new Set((insideNames || []).filter((name) => name !== via))
    : new Set(defaultCiscoNatInsideNames(ifaceRows, via));
  const [insideSet, setInsideSet] = useState(defaultInsideSet);
  // ACL เดิมที่เป็น any ต้องกลับมาเป็น Any; ACL ที่มี CIDR ให้เปิด Specific เพื่อ
  // รักษาค่าจริงตอนแก้ไข โดยฟอร์มสร้างใหม่เริ่มจาก Any ตามค่าเริ่มต้นเดิม.
  const initialScopes = (aclScopes || []).filter(Boolean);
  const initialScopeMode = initialScopes.length > 0 && !initialScopes.includes("any") ? "specific" : "any";
  const [scopeMode, setScopeMode] = useState(initialScopeMode);
  const [scopeEntries, setScopeEntries] = useState(() => (
    initialScopeMode === "specific" ? initialScopes : [""]
  ));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // get_nat_dashboard อ่าน layer จริงมาใน request เดียวอยู่แล้ว ไม่ใช้
  // get_interface_list เพราะคำสั่งนั้นคืนเพียงชื่อและแยก Layer 2/3 ไม่ได้
  const interfaceOptions = outboundInterfaces || [];

  const { data: poolData, loading: poolLoading } = getDeviceInformation(
    devId,
    "get_nat_pool_information"
  );
  const poolOptions = poolData?.normalized
    ? ensureArray(poolData.result?.payload?.data?.native?.ip?.nat?.pool)
        .map((pool) => pool?.id)
        .filter(Boolean)
    : [];

  // via เปลี่ยน -> ปลดตัวเองออกจาก toggle list เสมอ (ขาเดียวกันเป็นทั้ง inside
  // และ outside พร้อมกันไม่ได้)
  useEffect(() => {
    if (!via) return;
    setInsideSet((prev) => {
      if (!prev.has(via)) return prev;
      const next = new Set(prev);
      next.delete(via);
      return next;
    });
  }, [via]);

  function toggleInside(name) {
    setInsideSet((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  // IOS-XE ไม่ได้บังคับว่า NAT inside ต้องเป็น RFC1918: ให้เลือก interface ที่มี
  // IPv4 ได้ทุกช่วง และคงขา brownfield ที่เป็น inside อยู่จริงแม้ telemetry IP อ่านไม่ได้.
  const toggleCandidates = ciscoNatInsideCandidates(ifaceRows, via, insideNames);
  const selectedInsideNames = toggleCandidates
    .filter((row) => insideSet.has(row.name))
    .map((row) => row.name);

  function selectScopeMode(mode) {
    setScopeMode(mode);
    // LAN Allow คือ ACL scope คนละส่วนกับบทบาท NAT inside ของ interface.
    // ห้าม reset insideSet เมื่อเลือก Any เพราะจะทำให้ public/tunnel/management
    // ที่เพิ่งเปิดให้เลือกถูกติ๊กทั้งหมดโดยไม่ได้ตั้งใจ.
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    if (!via) return setError("Please select an Outbound interface first");
    if (translateMode === "pool" && !poolName) {
      return setError("Please select a NAT pool to use (create one in NAT Pool first if not present)");
    }

    const includedRows = toggleCandidates.filter((row) => insideSet.has(row.name));
    if (includedRows.length === 0) {
      return setError("At least 1 interface must be enabled for NAT inside");
    }

    let scopes = ["any"];
    if (scopeMode === "specific") {
      const checked = validateSpecificScopes(scopeEntries);
      if (checked.error) return setError(checked.error);
      scopes = checked.scopes;
    }

    const { interfaceType: viaType, interfaceId: viaId } = splitInterfaceName(via);
    const name = currentRule?.name || DEFAULT_NAT_NAME;

    setSubmitting(true);
    try {
      // (ระลอก C3 / bug 65) ยุบทั้ง flow เหลือคำสั่งเดียว
      //
      // เดิม: teardownCurrentNat (สูงสุด 8 RPC) -> sleep 2.5 วินาที -> set_acl_rule ทีละวง
      // -> set_nat -> apply_nat_interface ทีละขา = 12 RPC ตอนสร้างใหม่ และ 20 RPC + หน่วง
      // 2.5 วินาที ตอนแก้ไข โดยมีช่วงที่ NAT บนอุปกรณ์ดับสนิทกลางทาง (ACL/nat rule ถูกลบ
      // และ inside-outside ถูกปลดหมดทุกขา แล้วค่อยทยอยสร้างกลับ) - ผู้ใช้จับได้จาก
      // Command History จริงว่าได้ 12-20 แถวต่อ 1 การกระทำ
      //
      // ตอนนี้ create_nat_policy ทำครบทั้ง ACL + nat rule + ip nat outside/inside +
      // ปลด nat ออกจากขาที่ไม่ได้ใช้แล้ว ในคำสั่งเดียวด้วย nc:operation="replace"
      // **1 action = 1 RPC = ประวัติ 1 แถว** และไม่ต้อง teardown เลย
      //
      // release_interfaces = ขาที่ "ตอนนี้" มี nat ติดอยู่จริงบนอุปกรณ์ (อ่านมาจาก
      // parseNatInterfaceState) ส่งไปทั้งชุดได้เลย เพราะ backend ข้ามขาที่ยังใช้อยู่
      // ในรอบนี้ให้เอง - ไม่ต้องคำนวณส่วนต่างฝั่งนี้
      const natPolicyParams = {
        name,
        via_type: viaType,
        via_id: viaId,
        translate_mode: translateMode,
        source_scopes: scopes,
        inside_interfaces: includedRows.map((row) => row.name),
        release_interfaces: [...(insideNames || []), outsideName].filter(Boolean),
      };
      if (translateMode === "pool") natPolicyParams.pool_name = poolName;

      await validateDeviceCommand(devId, "create_nat_policy", natPolicyParams);
      await runDeviceCommand(devId, "create_nat_policy", natPolicyParams);

      onSaved();
    } catch (err) {
      setError(errorMessage(err, "Failed to configure NAT"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Outbound Interface</label>
        <select
          value={via}
          onChange={(event) => setVia(event.target.value)}
          disabled={interfaceOptions.length === 0}
          required
        >
          <option value="" disabled>
            {interfaceOptions.length === 0 ? "No Layer 3 interface found" : "-- Select interface --"}
          </option>
          {interfaceOptions.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
      </div>

      {via && (
        <>
          <div className="interface-configuration-form-field">
            <label className="data-label">Public IP Source</label>
            <div className="segmented-control">
              <input
                type="radio"
                id="mode-wanip"
                name="translate-mode"
                value="interface"
                checked={translateMode === "interface"}
                onChange={(event) => setTranslateMode(event.target.value)}
              />
              <label htmlFor="mode-wanip">WAN Interface</label>
              <input
                type="radio"
                id="mode-pool"
                name="translate-mode"
                value="pool"
                checked={translateMode === "pool"}
                onChange={(event) => setTranslateMode(event.target.value)}
              />
              <label htmlFor="mode-pool">NAT Pool</label>
            </div>
          </div>

          {translateMode === "pool" && (
            <div className="interface-configuration-form-field">
              <label className="data-label">NAT Pool</label>
              {poolLoading ? (
                <select disabled value="">
                  <option value="">Loading NAT pools...</option>
                </select>
              ) : (
                <select value={poolName} onChange={(event) => setPoolName(event.target.value)}>
                  <option value="" disabled>-- Select pool --</option>
                  {poolOptions.map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
                </select>
              )}
            </div>
          )}

          <div className="interface-configuration-form-field">
            <label className="data-label">LAN Allow</label>
            <div className="segmented-control">
              <input
                type="radio"
                id="cisco-scope-any"
                name="cisco-scope-mode"
                value="any"
                checked={scopeMode === "any"}
                onChange={(event) => selectScopeMode(event.target.value)}
              />
              <label htmlFor="cisco-scope-any">Any</label>
              <input
                type="radio"
                id="cisco-scope-specific"
                name="cisco-scope-mode"
                value="specific"
                checked={scopeMode === "specific"}
                onChange={(event) => selectScopeMode(event.target.value)}
              />
              <label htmlFor="cisco-scope-specific">Specific</label>
            </div>
          </div>

          {scopeMode === "specific" && scopeEntries.map((scope, index) => (
            <div className="interface-configuration-form-field-third" key={index}>
              <label className="data-label">{index === 0 ? "IP/Prefix" : `IP/Prefix ${index + 1}`}</label>
              <IPv4Input
                mode="cidr"
                label={`LAN Allow ${index + 1}`}
                value={scope}
                onChange={(value) => setScopeEntries((previous) => previous.map((entry, entryIndex) => (
                  entryIndex === index ? value : entry
                )))}
              />
              {index === 0 && (
                <button type="button" className="mini-btn btn-ghost" onClick={() => setScopeEntries((previous) => [...previous, ""])} aria-label="Add LAN Allow">+</button>
              )}
              {index > 0 && (
                <button type="button" className="mini-btn btn-ghost" onClick={() => setScopeEntries((previous) => previous.filter((_, entryIndex) => entryIndex !== index))} aria-label={`Remove LAN Allow ${index + 1}`}>-</button>
              )}
            </div>
          ))}

          <div className="interface-configuration-form-field">
            <label className="data-label">NAT Inside Interface</label>
            <CheckboxDropdown ariaLabel="Select NAT Inside Interface" summary={<>
                <input
                  type="text"
                  readOnly
                  tabIndex={-1}
                  aria-label="Selected NAT Inside Interface"
                  placeholder="-- Select interface --"
                  value={selectedInsideNames.join(", ")}
                />
              </>}>
              <div className="zone-interface-picker-options">
                {toggleCandidates.length === 0 && (
                  <div className="field-hint">No other interface with an IPv4 address found besides Outbound interface</div>
                )}
                {toggleCandidates.map((row) => (
                  <label key={row.name} className="zone-interface-picker-option">
                    <input
                      type="checkbox"
                      checked={insideSet.has(row.name)}
                      disabled={submitting}
                      onChange={() => toggleInside(row.name)}
                    />
                    {row.name}{row.ipUnavailable ? " (configured; IP unavailable)" : ""}
                  </label>
                ))}
              </div>
            </CheckboxDropdown>
          </div>
        </>
      )}

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Sending..." : "Apply"}
        </button>
      </div>
      {submitting && <p className="nat-reconnect-hint" role="status">{NAT_RECONNECT_HINT}</p>}
    </form>
  );
}

export default function NatFormModal({
  devId,
  vendor,
  mode = "create",
  editTarget = null,
  allRows = [],
  currentRule = null,
  insideNames = [],
  outsideName = null,
  outboundInterfaces = [],
  ifaceRows = [],
  aclScopes = [],
  onSaved,
  onClose,
}) {
  if (vendor === "juniper") {
    return <JuniperNatForm devId={devId} mode={mode} editTarget={editTarget} allRows={allRows} onSaved={onSaved} onClose={onClose} />;
  }
  return (
    <CiscoNatForm
      devId={devId}
      currentRule={currentRule}
      insideNames={insideNames}
      outsideName={outsideName}
      outboundInterfaces={outboundInterfaces}
      ifaceRows={ifaceRows}
      aclScopes={aclScopes}
      onSaved={onSaved}
    />
  );
}
