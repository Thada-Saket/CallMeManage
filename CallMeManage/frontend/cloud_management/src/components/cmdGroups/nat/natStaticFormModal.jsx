import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import IPv4Input from "../../common/IPv4Input";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { splitInterfaceName } from "../../../utils/interfaceName";
import { resolveStaticNatRuleSet, isLastRuleInSet } from "./staticNatRuleSet";
import { cleanupOrphanedProxyArp } from "./proxyArpCleanup";
import { getWanZoneInterfaces } from "../../../utils/wanZoneInterfaces";
import { isJuniperSelectableInterfaceUnit } from "../../../utils/interfaceKind.js";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// (2026-09) err.detail ของ Cisco NAT family (Source/Static/Port Forward) timeout
// เปลี่ยนเป็น {code, message} แทนสตริงเปล่าสำหรับบาง error (ดู device_router.py's
// NETCONF_WRITE_OUTCOME_UNKNOWN/NETCONF_SESSION_RECOVERING) - เรนเดอร์ object ตรงๆ
// ใน JSX จะ throw ต้องดึง .message ออกมาก่อนเสมอ - Juniper/error อื่นที่ detail ยัง
// เป็นสตริงปกติผ่านไม่เปลี่ยนพฤติกรรม
function errorMessage(err, fallback) {
  const detail = err?.detail;
  if (detail && typeof detail === "object") return detail.message || fallback;
  return detail || fallback;
}

function parseZoneNames(result) {
  try {
    const zones = ensureArray(result?.payload?.data?.configuration?.security?.zones?.["security-zone"]);
    return zones.map((zone) => zone?.name).filter(Boolean);
  } catch {
    return [];
  }
}

// Static NAT ในฟอร์มนี้เป็นการแปลงแบบ 1:1 ระหว่าง host address สองฝั่งเท่านั้น
// Junos อ่านค่ากลับมาเป็น CIDR /32 จึงตัด suffix ออกก่อนนำมาใส่ IPv4 address
// input กลาง โดยตอนส่งค่ากลับ Junos ยอมรับ address เปล่าและตีความเป็น /32 เอง
function staticNatHostAddress(value) {
  return String(value || "").trim().split("/")[0];
}

// โหมด Edit: pre-fill จาก editTarget (แถวที่เลือกจาก natStatic.jsx -
// {name, fromZone, localIp, globalIp} - Juniper's name เป็น identity จริงบน
// อุปกรณ์ (rule_set == rule_name) ส่วน Cisco's name เป็นแค่ label จาก
// Device_Config_Object อาจเป็น "-" ถ้าหาไม่เจอ ไม่ต้อง pre-fill ค่านั้น)
function buildInitialValues(mode, editTarget, isJuniper) {
  if (mode !== "edit" || !editTarget) {
    return { name: "", fromZone: "", localIp: "", globalIp: "", wanInterface: "" };
  }
  return {
    name: isJuniper ? editTarget.name || "" : editTarget.name && editTarget.name !== "-" ? editTarget.name : "",
    fromZone: editTarget.fromZone || "",
    localIp: staticNatHostAddress(editTarget.localIp),
    globalIp: staticNatHostAddress(editTarget.globalIp),
    wanInterface: isJuniper ? editTarget.proxyArpInterface || "" : "",
  };
}

// ฟอร์ม Static NAT - Cisco: แค่ 3 ช่องตามที่ขอ (ชื่อ/Local IP/Public IP) - name
// ไม่มีที่เก็บบนอุปกรณ์จริง (set_static_nat รับไว้เฉยๆ ไม่ใส่ลง XML) ใช้เป็น
// label ฝั่งเว็บเราเท่านั้น local_ip+global_ip คือ key จริงบนอุปกรณ์
//
// Juniper: signature ต่างกันโดยพื้นฐาน (rule_set/rule_name/from_zone/
// destination_address/local_address) - name คือ identity ของ rule ภายใน
// rule-set ที่แชร์ตาม from-zone และแก้ชื่อด้วย Junos rename ใน rule-set เดิม
// ต้องมี From Zone (ฝั่งที่ traffic ขาเข้ามาจริง เช่น zone "WAN"/"untrust")
// เพิ่ม "WAN Interface" ให้เลือกเพื่อยิง
// set_nat_proxy_arp คู่กันเสมอ - **จำเป็นจริง** (ยืนยันจาก comment เดิมที่
// set_nat_proxy_arp: static NAT ไม่ทำงานเลยถ้าไม่มี proxy-arp แม้ policy/NAT
// rule จะถูกต้องครบก็ตาม เพราะ Junos ไม่ตอบ ARP แทน public IP เองอัตโนมัติ)
export default function NatStaticFormModal({ devId, vendor, mode = "create", editTarget = null, allRows = [], ruleSetContexts = [], onClose, onSaved }) {
  const isJuniper = vendor === "juniper";
  const isEdit = mode === "edit" && !!editTarget;
  const [values, setValues] = useState(buildInitialValues(mode, editTarget, isJuniper));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const { data: zoneData } = getDeviceInformation(devId, isJuniper ? "get_security_zone_information" : null);
  const zoneOptions = zoneData?.normalized ? parseZoneNames(zoneData.result) : [];

  const { data: ifBriefData, loading: ifBriefLoading } = getDeviceInformation(
    devId,
    isJuniper ? "get_ip_interface_brief" : null
  );
  const interfaceOptions = [...new Set([
    ...(ifBriefData?.normalized
      ? ifBriefData.result.map((row) => row.name).filter((name) => isJuniperSelectableInterfaceUnit(name))
      : []),
    ...(isJuniper && isJuniperSelectableInterfaceUnit(values.wanInterface) ? [values.wanInterface] : []),
  ])];

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  // user ขอ: ตอนสร้างใหม่ ให้ default "From Zone" เป็น "WAN" และ "WAN Interface"
  // (สำหรับ proxy-arp) เป็น interface ที่เป็นสมาชิกของ zone "WAN" ให้เองก่อนเลย
  // (เพราะ static NAT แทบทุกเคสจริงคือ WAN-facing) - ไม่ทับค่าที่ user เลือกเอง
  // แล้วหรือค่าที่ pre-fill มาตอน edit ตาม pattern เดียวกับ natFormModal.jsx's
  // JuniperNatForm "default To Zone = WAN"
  useEffect(() => {
    if (!isJuniper || isEdit) return;
    if (values.fromZone) return;
    if (zoneOptions.includes("WAN")) setField("fromZone", "WAN");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isJuniper, isEdit, zoneOptions.join(",")]);

  const wanZoneInterfaces = getWanZoneInterfaces({ vendor, zoneResult: zoneData });
  useEffect(() => {
    if (!isJuniper || values.wanInterface) return;
    const match = wanZoneInterfaces.find((name) => interfaceOptions.includes(name));
    if (match) setField("wanInterface", match);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isJuniper, values.wanInterface, wanZoneInterfaces.join(","), interfaceOptions.join(",")]);

  async function handleSubmitCisco(event) {
    event.preventDefault();
    setError("");

    if (!values.name.trim()) return setError("Please enter a name");
    const localIp = validateIPv4Input(values.localIp, { mode: "address" });
    const globalIp = validateIPv4Input(values.globalIp, { mode: "address" });
    if (!localIp.valid) return setError("Please enter a valid Local IP, e.g. 192.168.1.10");
    if (!globalIp.valid) return setError("Please enter a valid Public IP, e.g. 203.0.113.50");

    setSubmitting(true);
    try {
      // Cisco ไม่มีชื่อบนอุปกรณ์ ชื่ออยู่ใน Device_Config_Object เท่านั้น ส่วนคู่
      // local/global IP เป็น key จริง ส่ง key เดิมไปพร้อมคำสั่งเพื่อให้ backend
      // อัปเดตชื่อ record เดิม และรวม remove/create ใน RPC เดียวเมื่อ IP เปลี่ยน
      const staticNatParams = {
        name: values.name.trim(),
        local_ip: localIp.value,
        global_ip: globalIp.value,
        ...(isEdit ? {
          replace_local_ip: editTarget.localIp,
          replace_global_ip: editTarget.globalIp,
        } : {}),
      };
      await validateDeviceCommand(devId, "set_static_nat", staticNatParams);
      await runDeviceCommand(devId, "set_static_nat", staticNatParams);
      onSaved();
    } catch (err) {
      setError(errorMessage(err, isEdit ? "Failed to edit Static NAT" : "Failed to create Static NAT"));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSubmitJuniper(event) {
    event.preventDefault();
    setError("");

    const name = values.name.trim();
    if (!name) return setError("Please enter a name");
    if (!values.fromZone) return setError("Please select From Zone (the zone where inbound traffic arrives, e.g. WAN)");
    const localIp = validateIPv4Input(values.localIp, { mode: "address" });
    const globalIp = validateIPv4Input(values.globalIp, { mode: "address" });
    if (!localIp.valid) return setError("Please enter a valid Local IP, e.g. 192.168.1.10");
    if (!globalIp.valid) return setError("Please enter a valid Public IP, e.g. 203.0.113.50");
    if (!values.wanInterface) return setError("Please select WAN Interface (used to answer ARP for Public IP - always required)");

    const currentRuleSet = isEdit && editTarget.fromZone === values.fromZone
      ? editTarget.ruleSet
      : "";
    const targetRuleSet = resolveStaticNatRuleSet(
      ruleSetContexts.length ? ruleSetContexts : allRows,
      values.fromZone,
      currentRuleSet,
    );
    const targetContext = ruleSetContexts.find((context) => context.ruleSet === targetRuleSet);
    const keepsCurrentIdentity = isEdit
      && editTarget.ruleSet === targetRuleSet
      && editTarget.name === name;
    if (!keepsCurrentIdentity && targetContext?.ruleNames?.includes(name)) {
      return setError(`Name "${name}" already exists in zone ${values.fromZone}`);
    }

    setSubmitting(true);
    try {
      // (ปัญหาที่ 2 ขั้น B0) ตรวจค่าที่จะใช้สร้างใหม่ให้ผ่านก่อน "แล้วค่อยเริ่มลบ"
      // ไม่งั้นถ้าค่าผิด rule เดิมจะถูกลบไปแล้วโดยไม่มีอะไรมาแทน
      const { interfaceType, interfaceId } = splitInterfaceName(values.wanInterface);
      const junosStaticNatParams = {
        rule_set: targetRuleSet,
        rule_name: name,
        from_zone: values.fromZone,
        destination_address: globalIp.value,
        local_address: localIp.value,
        // Static NAT และ Proxy ARP ต้องอยู่ใน edit-config/candidate เดียวกัน
        // เพื่อไม่ให้เหลือ NAT ที่ใช้งานไม่ได้หากคำสั่ง Proxy ARP ล้มเหลว
        interface_type: interfaceType,
        interface_id: interfaceId,
        proxy_arp_address: globalIp.value,
        ...(isEdit ? {
          replace_rule_set: editTarget.ruleSet,
          replace_rule_name: editTarget.name,
          replace_whole_ruleset: isLastRuleInSet(allRows, editTarget),
        } : {}),
      };
      await validateDeviceCommand(devId, "set_static_nat", junosStaticNatParams);
      await runDeviceCommand(devId, "set_static_nat", junosStaticNatParams);
      // ถ้า user เปลี่ยน Public IP ระหว่าง edit, IP เดิมอาจกลายเป็น orphan ใน
      // proxy-arp - เช็คลบทิ้งถ้าไม่มี rule อื่นใช้อยู่แล้ว (best-effort)
      if (isEdit && editTarget.globalIp && staticNatHostAddress(editTarget.globalIp) !== globalIp.value) {
        // ต้องจบก่อน onSaved/refetch ไม่เช่นนั้นคำสั่งอ่านสอง flow จะแย่ง DeviceLock
        try { await cleanupOrphanedProxyArp(devId, editTarget.globalIp); } catch { /* best-effort */ }
      }
      onSaved();
    } catch (err) {
      setError(errorMessage(err, isEdit ? "Failed to edit Static NAT" : "Failed to create Static NAT"));
    } finally {
      setSubmitting(false);
    }
  }

  const handleSubmit = isJuniper ? handleSubmitJuniper : handleSubmitCisco;

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && (
        <div className="command-output-title">
          Edit: {editTarget.globalIp} → {editTarget.localIp}
        </div>
      )}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Name</label>
        <input
          type="text"
          placeholder="MAIL_SERVER"
          value={values.name}
          onChange={(event) => setField("name", event.target.value)}
          required
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Local IP</label>
        <IPv4Input
          id="static-nat-local-ip"
          mode="address"
          label="Static NAT Local IP"
          value={values.localIp}
          onChange={(value) => setField("localIp", value)}
          required
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Public IP</label>
        <IPv4Input
          id="static-nat-public-ip"
          mode="address"
          label="Static NAT Public IP"
          value={values.globalIp}
          onChange={(value) => setField("globalIp", value)}
          required
        />
      </div>

      {isJuniper && (
        <div className="interface-configuration-form-field">
          <label className="data-label">WAN Zone</label>
          <select
            value={values.fromZone}
            onChange={(event) => setField("fromZone", event.target.value)}
            required
          >
            <option value="">-- Select zone --</option>
            {zoneOptions.map((zone) => (
              <option key={zone} value={zone}>
                {zone}
              </option>
            ))}
          </select>
        </div>
      )}

      {isJuniper && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Proxy ARP Interface</label>
          <select
            value={values.wanInterface}
            onChange={(event) => setField("wanInterface", event.target.value)}
            disabled={ifBriefLoading}
            required
          >
            <option value="">-- Select interface --</option>
            {interfaceOptions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>
      )}

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
