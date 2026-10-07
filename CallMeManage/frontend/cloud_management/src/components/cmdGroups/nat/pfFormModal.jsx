import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { splitInterfaceName } from "../../../utils/interfaceName";
import { KNOWN_SERVICES } from "../../../utils/knownServices";
import { isLastRuleInSet, resolveDestinationNatRuleSet } from "./staticNatRuleSet";
import { cleanupOrphanedProxyArp } from "./proxyArpCleanup";
import { getWanZoneInterfaces } from "../../../utils/wanZoneInterfaces";
import { acceptsPortInput, DEFAULT_PORT_PROTOCOL, PORT_PROTOCOLS } from "../../../utils/portInput";
import IPv4Input from "../../common/IPv4Input";
import { isJuniperSelectableInterfaceUnit } from "../../../utils/interfaceKind.js";
import { classifyProxyArpForWanAddress } from "./proxyArpBindings.js";

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

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isValidIPv4(value) {
  const match = IPV4_RE.exec(value.trim());
  if (!match) return false;
  return match.slice(1).every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
}

// Juniper's destination_address/local_address รับ CIDR ตรงๆ และ round-trip
// กลับมาเป็น CIDR เสมอ (เช่น "203.0.113.150/32") - ดู comment เดียวกันที่
// natStaticFormModal.jsx (เจอ bug จริงตอนทดสอบ edit ผ่าน UI ที่นั่นมาก่อน)
function isValidIPv4OrCidr(value) {
  const trimmed = value.trim();
  const [ip, prefix] = trimmed.split("/");
  if (!isValidIPv4(ip)) return false;
  if (prefix === undefined) return true;
  const prefixNum = Number(prefix);
  return Number.isInteger(prefixNum) && prefixNum >= 0 && prefixNum <= 32;
}

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// (bug 83) ใช้ IP จากทุกแถวที่ normalizer คืนมา ตัด prefix เฉพาะรายการแนะนำ
// ไม่แปลง values.wanIp เพื่อรักษาค่าเดิม เช่น Juniper /32 และ IP ที่ route มาหา
function buildWanIpOptions(rows) {
  const byIp = new Map();
  for (const row of ensureArray(rows)) {
    for (const address of ensureArray(row?.ip)) {
      if (typeof address !== "string") continue;
      const ip = address.trim().split("/")[0];
      if (!isValidIPv4(ip) || ip === "0.0.0.0") continue;
      if (!byIp.has(ip)) byIp.set(ip, new Set());
      if (row?.name) byIp.get(ip).add(row.name);
    }
  }
  return [...byIp].map(([ip, names]) => ({ ip, label: names.size ? `${ip} (${[...names].join(", ")})` : ip }));
}

function parseZoneNames(result) {
  try {
    const zones = ensureArray(result?.payload?.data?.configuration?.security?.zones?.["security-zone"]);
    return zones.map((zone) => zone?.name).filter(Boolean);
  } catch {
    return [];
  }
}

// ช่อง port หนึ่งฝั่ง (local หรือ wan) - เลือกได้ว่าจะใช้ Service Port (dropdown
// จาก KNOWN_SERVICES) หรือ Custom - เหมือน pattern DHCP Server/Relay ใน
// InterfacesFormModal.jsx - `requireProtocol` (Cisco เท่านั้น): user ขอตัด
// ตัวเลือก TCP/UDP แยกที่ล่างสุดของฟอร์มทิ้ง ให้ derive protocol จาก port ที่
// กรอกตรงนี้แทนเลย - โหมด Service ได้ protocol จาก KNOWN_SERVICES ของ service
// นั้นอัตโนมัติอยู่แล้ว (เช่น HTTP = 80/tcp) โหมด Custom เลยต้องเปลี่ยนจากกรอก
// เลข port เดี่ยวๆ เป็นกรอกรวม "port/protocol" ในช่องเดียว (เช่น "8080/tcp")
// แทน - Juniper (`requireProtocol=false`) ไม่มี concept protocol เลย
// (destination NAT ทำงานทุก protocol อยู่แล้ว) เลยคงเป็นเลข port เดี่ยวๆ เหมือนเดิม
function PortField({ label, mode, onModeChange, service, onServiceChange, customPort, onCustomPortChange,
  protocol, onProtocolChange, requireProtocol = false }) {
  return (
    <>
      <div className="interface-configuration-form-field">
        <label className="data-label">{label}</label>
        <div className="segmented-control">
          <input
            type="radio"
            id={`${label}-service`}
            name={`${label}-mode`}
            value="service"
            checked={mode === "service"}
            onChange={(event) => onModeChange(event.target.value)}
          />
          <label htmlFor={`${label}-service`}>Service Port</label>
          <input
            type="radio"
            id={`${label}-custom`}
            name={`${label}-mode`}
            value="custom"
            checked={mode === "custom"}
            onChange={(event) => onModeChange(event.target.value)}
          />
          <label htmlFor={`${label}-custom`}>Custom</label>
        </div>
      </div>

      {mode === "service" ? (
        <div className="interface-configuration-form-field">
          <label className="data-label">Service</label>
          <select value={service} onChange={(event) => onServiceChange(event.target.value)}>
            {KNOWN_SERVICES.map((svc) => (
              <option key={svc.name} value={svc.name}>
                {svc.name} ({svc.port}/{svc.protocol})
              </option>
            ))}
          </select>
        </div>
      ) : (
        <>
          <div className="interface-configuration-form-field">
            <label className="data-label">{label.replace(" Type", "")}</label>
            <input
              type="text"
              inputMode="numeric"
              placeholder="8080"
              value={customPort}
              onChange={(event) => {
                if (acceptsPortInput(event.target.value)) onCustomPortChange(event.target.value);
              }}
            />
          </div>

          {/* protocol เป็นช่องแยก เฉพาะยี่ห้อที่ใช้จริง - เดิมให้พิมพ์รวมเป็น
              "8080/tcp" ในช่องเดียว ซึ่งผู้ใช้ลืมเติม "/tcp" ตลอดเพราะไม่มีอะไร
              บอกว่าต้องมี · Juniper ไม่มีช่องนี้เพราะ destination NAT ทำงานทุก
              protocol บน port นั้นอยู่แล้ว การให้เลือกจะเก็บค่าที่ไม่ได้ใช้ */}
          {requireProtocol && (
            <div className="interface-configuration-form-field">
              <label className="data-label">Protocol</label>
              <select value={protocol} onChange={(event) => onProtocolChange(event.target.value)}>
                {PORT_PROTOCOLS.map((name) => (
                  <option key={name} value={name}>{name.toUpperCase()}</option>
                ))}
              </select>
            </div>
          )}
        </>
      )}
    </>
  );
}

// โหมด Edit: pre-fill จาก editTarget (แถวที่เลือกจาก pf.jsx -
// {name, fromZone, protocol, localIp, localPort, globalIp, globalPort}) -
// ถ้าพอร์ตตรงกับ KNOWN_SERVICES ให้คืนไปที่โหมด Service Port และเลือก service
// จริง; ค่าที่ไม่รู้จักเท่านั้นจึงอยู่โหมด Custom. Cisco เทียบทั้ง port+protocol
// ส่วน Juniper ไม่มี protocol ใน destination NAT จึงเทียบด้วย port
// Junos round-trip ค่า pool address กลับมาเป็น CIDR เสมอ ("192.168.1.10/32")
// แต่ช่อง Local IP เป็น IPv4Input โหมด address ซึ่งถือว่าค่าที่มี "/" ติดมาเป็น
// รูปแบบผิด (ขึ้น error ทันทีที่ออกจากช่องทั้งที่ผู้ใช้ยังไม่ได้แก้อะไรเลย) -
// ตัดออกเฉพาะ /32 ซึ่งแปลว่า host เดียวและเป็นค่าเดียวที่ dest NAT pool ใช้จริง
// ส่วน prefix อื่นคงไว้ทั้งก้อนเพื่อไม่ให้เปลี่ยนความหมายของค่าที่ตั้งไว้เงียบ ๆ
function stripHostPrefix(value) {
  const text = String(value ?? "").trim();
  return text.endsWith("/32") ? text.slice(0, -3) : text;
}

function knownServiceForPort(port, protocol, isJuniper) {
  const number = Number(port);
  if (!Number.isInteger(number)) return null;
  return KNOWN_SERVICES.find((service) =>
    service.port === number && (isJuniper || service.protocol === protocol)
  ) || null;
}

function buildInitialValues(mode, editTarget, isJuniper) {
  if (mode !== "edit" || !editTarget) {
    return {
      name: "",
      fromZone: "",
      localIp: "",
      localMode: "service",
      localService: KNOWN_SERVICES[0].name,
      localPort: "",
      localProtocol: DEFAULT_PORT_PROTOCOL,
      wanIp: "",
      wanMode: "service",
      wanService: KNOWN_SERVICES[0].name,
      wanPort: "",
      wanProtocol: DEFAULT_PORT_PROTOCOL,
      wanInterface: "",
    };
  }
  // port กับ protocol เป็นคนละช่องแล้ว จึงเติมแยกกัน ไม่ต้องประกอบเป็น
  // "8080/tcp" ให้ผู้ใช้มานั่งแกะเองอีก
  const localPortValue = editTarget.localPort == null ? "" : String(editTarget.localPort);
  const wanPortValue = editTarget.globalPort == null ? "" : String(editTarget.globalPort);
  const protocolValue = PORT_PROTOCOLS.includes(editTarget.protocol) ? editTarget.protocol : DEFAULT_PORT_PROTOCOL;
  const localKnownService = knownServiceForPort(localPortValue, protocolValue, isJuniper);
  const wanKnownService = knownServiceForPort(wanPortValue, protocolValue, isJuniper);
  return {
    name: isJuniper ? editTarget.name || "" : editTarget.name && editTarget.name !== "-" ? editTarget.name : "",
    fromZone: editTarget.fromZone || "",
    localIp: stripHostPrefix(editTarget.localIp),
    localMode: localKnownService ? "service" : "custom",
    localService: localKnownService?.name || KNOWN_SERVICES[0].name,
    localPort: localPortValue,
    localProtocol: protocolValue,
    wanIp: editTarget.globalIp || "",
    wanMode: wanKnownService ? "service" : "custom",
    wanService: wanKnownService?.name || KNOWN_SERVICES[0].name,
    wanPort: wanPortValue,
    wanProtocol: protocolValue,
    wanInterface: isJuniper ? editTarget.proxyArpInterface || "" : "",
  };
}

// ฟอร์ม Port Forwarding - Cisco: name ไม่มีที่เก็บบนอุปกรณ์จริง (set_port_forward
// รับไว้เฉยๆ ไม่ใส่ลง XML) ใช้เป็น label ฝั่งเว็บเราเท่านั้น
//
// Juniper: เขียนลง security/nat/destination (pool-based - แยก container จาก
// static NAT โดยสิ้นเชิง ดู comment ยาวใน juniper_junos.py's set_port_forward
// อธิบายว่าทำไม 2026-07-30) - signature ต่างจาก Cisco คล้าย natStaticFormModal.jsx
// (rule_set/rule_name/from_zone เพิ่มมา, name เป็น identity จริงและแก้ไขได้แบบ
// remove/create ใน candidate เดียว รวมถึงย้าย from-zone ได้โดยย้าย rule-set)
// ไม่มี protocol ให้เลือก (destination NAT ทำงานทุก protocol บน port นั้นเลย
// ไม่แยก tcp/udp เหมือน static NAT) Public IP ที่ไม่ได้อยู่บนอุปกรณ์ต้องมี
// proxy-arp คู่กัน แต่ถ้าเลือก IP ของ interface เองต้องไม่สร้าง proxy-arp เพราะ
// Junos ตอบ ARP ให้ IP นั้นอยู่แล้วและจะ reject ช่วง Proxy ARP ที่ทับกัน
export default function PfFormModal({ devId, vendor, mode = "create", editTarget = null,
  allRows = [], ruleSetContexts = [], onClose, onSaved }) {
  const isJuniper = vendor === "juniper";
  const isEdit = mode === "edit" && !!editTarget;
  const [values, setValues] = useState(buildInitialValues(mode, editTarget, isJuniper));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [wanIpCustom, setWanIpCustom] = useState(false);

  const { data: zoneData } = getDeviceInformation(devId, isJuniper ? "get_security_zone_information" : null);
  const zoneOptions = zoneData?.normalized ? parseZoneNames(zoneData.result) : [];

  // (bug 83) Cisco อ่านเพิ่มหนึ่งครั้งตอนเปิดฟอร์ม ส่วน Juniper ใช้ข้อมูลเดิม
  // get_* ถูกยกเว้นจาก rate limit คำสั่งเขียน จึงไม่กินโควตาตอน Save
  const { data: ifBriefData, loading: ifBriefLoading, error: ifBriefError } = getDeviceInformation(
    devId,
    "get_ip_interface_brief"
  );
  const interfaceRows = ifBriefData?.normalized && Array.isArray(ifBriefData.result) ? ifBriefData.result : [];
  // Operational interface read อาจไม่คืน interface ที่ยังมี Proxy ARP config อยู่
  // ต้องเก็บค่าจริงจาก config ไว้ใน option เพื่อให้ Edit แสดงและส่งค่าตรงเดิม
  const interfaceOptions = [...new Set([
    ...interfaceRows.map((row) => row?.name).filter((name) => (
      !isJuniper || isJuniperSelectableInterfaceUnit(name)
    )),
    ...(isJuniper && isJuniperSelectableInterfaceUnit(values.wanInterface) ? [values.wanInterface] : []),
  ])];
  const wanIpOptions = buildWanIpOptions(ifBriefError ? [] : interfaceRows);
  // ค่าเดิมต้องอยู่ใน select แม้โหลดไม่เสร็จ/อ่านไม่ได้/ไม่มี IP นี้บน interface แล้ว
  const hasUnlistedWanIp = !!values.wanIp && !wanIpOptions.some((option) => option.ip === values.wanIp);
  const proxyArpMode = isJuniper
    ? classifyProxyArpForWanAddress(interfaceRows, values.wanIp)
    : "required";

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  // user ขอ: ตอนสร้างใหม่ ให้ default "From Zone" เป็น "WAN" และ "WAN Interface"
  // (สำหรับ proxy-arp เมื่อใช้ public IP อื่น) เป็น interface ที่เป็นสมาชิกของ
  // zone "WAN" ให้เองก่อนเลย; หากเลือก IP ที่ตั้งอยู่บนอุปกรณ์เอง field นี้จะ
  // ไม่ถูกส่งไปใน payload ตาม proxyArpMode ด้านล่าง
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

  function resolvePort(mode, service, customPort) {
    if (mode === "service") {
      const svc = KNOWN_SERVICES.find((entry) => entry.name === service);
      return svc ? svc.port : null;
    }
    const port = Number(customPort);
    return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
  }

  // Cisco เท่านั้น: user ขอตัดตัวเลือก TCP/UDP แยกทิ้ง ให้ derive protocol จาก
  // port ที่กรอกแทน - โหมด Service ได้ทั้ง port+protocol จาก KNOWN_SERVICES
  // ของ service ที่เลือกตรงๆ (เช่น เลือก "HTTP" = 80/tcp) โหมด Custom ต้อง
  // parse "port/protocol" จากช่องเดียว (เช่น "8080/tcp") - กรอกไม่ครบ (ไม่มี
  // "/protocol" ต่อท้าย, port หรือ protocol ไม่ถูกต้อง) คืน null ให้ caller ไม่
  // ส่งคำสั่งต่อ (ตามที่ user ขอ "ถ้ากรอกไม่ครบก็ไม่ให้ส่ง")
  function resolvePortAndProtocol(mode, service, customPort, customProtocol) {
    if (mode === "service") {
      const svc = KNOWN_SERVICES.find((entry) => entry.name === service);
      return svc ? { port: svc.port, protocol: svc.protocol } : null;
    }
    const port = Number(customPort);
    if (customPort === "" || !Number.isInteger(port) || port < 1 || port > 65535) return null;
    if (!PORT_PROTOCOLS.includes(customProtocol)) return null;
    return { port, protocol: customProtocol };
  }

  async function handleSubmitCisco(event) {
    event.preventDefault();
    setError("");

    if (!values.name.trim()) return setError("Please enter a name");
    if (!isValidIPv4(values.localIp)) return setError("Please enter a valid Local IP, e.g. 192.168.1.10");
    if (!isValidIPv4(values.wanIp)) return setError("Please enter a valid WAN IP, e.g. 203.0.113.50");

    const local = resolvePortAndProtocol(values.localMode, values.localService, values.localPort, values.localProtocol);
    if (!local) return setError("Please enter a valid Local Port (1-65535)");
    const wan = resolvePortAndProtocol(values.wanMode, values.wanService, values.wanPort, values.wanProtocol);
    if (!wan) return setError("Please enter a valid WAN Port (1-65535)");
    if (local.protocol !== wan.protocol) {
      return setError(`Local Port (${local.protocol}) and WAN Port (${wan.protocol}) must use the same protocol`);
    }

    setSubmitting(true);
    try {
      // แก้ไข entry ที่มีอยู่แล้ว: ลบตัวเดิมทิ้งก่อนเสมอด้วยค่าเดิมทั้ง 5 จาก
      // editTarget (protocol/local_ip/local_port/global_ip/global_port คือ key
      // จริงรวมกัน - เปลี่ยนค่าไหนก็ตามระหว่าง edit จะกลายเป็น entry ใหม่แทน)
      // (ปัญหาที่ 2 ขั้น B0) ตรวจค่าที่จะใช้สร้างใหม่ให้ผ่านก่อน "แล้วค่อยเริ่มลบ"
      // ไม่งั้นถ้าค่าผิด ของเดิมจะถูกลบไปแล้วโดยไม่มีอะไรมาแทน
      const pfParams = {
        name: values.name.trim(),
        protocol: wan.protocol,
        local_ip: values.localIp.trim(),
        local_port: local.port,
        global_ip: values.wanIp.trim(),
        global_port: wan.port,
        // key เดิมทำให้ translator ลบ/สร้างแบบ atomic; validate อยู่ก่อน write เสมอ
        ...(isEdit ? {
          replace_protocol: editTarget.protocol,
          replace_local_ip: editTarget.localIp,
          replace_local_port: editTarget.localPort,
          replace_global_ip: editTarget.globalIp,
          replace_global_port: editTarget.globalPort,
        } : {}),
      };
      await validateDeviceCommand(devId, "set_port_forward", pfParams);
      await runDeviceCommand(devId, "set_port_forward", pfParams);
      onSaved();
    } catch (err) {
      setError(errorMessage(err, isEdit ? "Failed to edit Port Forwarding" : "Failed to create Port Forwarding"));
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
    if (!isValidIPv4OrCidr(values.localIp)) return setError("Please enter a valid Local IP, e.g. 192.168.1.10 or 192.168.1.10/32");
    if (!isValidIPv4OrCidr(values.wanIp)) return setError("Please enter a valid WAN IP, e.g. 203.0.113.50 or 203.0.113.50/32");
    if (proxyArpMode === "overlap") {
      return setError("WAN IP range overlaps an IP configured on this device. Use the exact interface IP or a non-overlapping public IP range.");
    }
    if (proxyArpMode === "required" && !values.wanInterface) {
      return setError("Please select WAN Interface (used to answer ARP for the public IP)");
    }

    const localPort = resolvePort(values.localMode, values.localService, values.localPort);
    if (localPort === null) return setError("Invalid Local Port (1-65535)");
    const wanPort = resolvePort(values.wanMode, values.wanService, values.wanPort);
    if (wanPort === null) return setError("Invalid WAN Port (1-65535)");

    const currentRuleSet = isEdit && editTarget.fromZone === values.fromZone
      ? editTarget.ruleSet
      : "";
    const targetRuleSet = resolveDestinationNatRuleSet(
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
      const junosPfParams = {
        // ใช้ rule-set จริงของ brownfield config/zone เดิมก่อนเสมอ เพื่อไม่สร้าง
        // DNAT-<zone> ไปชน same-context constraint ของ Junos
        rule_set: targetRuleSet,
        rule_name: name,
        from_zone: values.fromZone,
        destination_address: values.wanIp.trim(),
        destination_port: wanPort,
        local_address: values.localIp.trim(),
        local_port: localPort,
        // รวม NAT, proxy-ARP และ remove เดิมใน edit-config เดียว
        ...(proxyArpMode === "required" ? (() => {
          const { interfaceType, interfaceId } = splitInterfaceName(values.wanInterface);
          return {
            interface_type: interfaceType,
            interface_id: interfaceId,
            proxy_arp_address: values.wanIp.trim(),
          };
        })() : {}),
        ...(isEdit ? {
          // pool เป็น flat object และไม่จำเป็นต้องชื่อ <rule>-POOL เสมอ
          // เก็บชื่อจริงเดิมไว้ทั้งขา set และ replace เพื่อไม่ทิ้ง orphan
          pool_name: editTarget.poolName || undefined,
          replace_pool_name: editTarget.poolName || undefined,
          replace_rule_set: editTarget.ruleSet,
          replace_rule_name: editTarget.name,
          replace_destination_ports: (
            Array.isArray(editTarget.globalPorts) && editTarget.globalPorts.length
              ? editTarget.globalPorts
              : [editTarget.globalPort]
          ).map(Number).filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535),
          replace_whole_ruleset: isLastRuleInSet(allRows, editTarget),
        } : {}),
      };
      await validateDeviceCommand(devId, "set_port_forward", junosPfParams);
      await runDeviceCommand(devId, "set_port_forward", junosPfParams);
      if (isEdit && editTarget.globalIp && editTarget.globalIp !== values.wanIp.trim()) {
        // ต้องจบก่อน onSaved/refetch ไม่เช่นนั้นคำสั่งอ่านสอง flow จะแย่ง DeviceLock
        try { await cleanupOrphanedProxyArp(devId, editTarget.globalIp); } catch { /* best-effort */ }
      }
      onSaved();
    } catch (err) {
      setError(errorMessage(err, isEdit ? "Failed to edit Port Forwarding" : "Failed to create Port Forwarding"));
    } finally {
      setSubmitting(false);
    }
  }

  const handleSubmit = isJuniper ? handleSubmitJuniper : handleSubmitCisco;

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && (
        <div className="command-output-title">
          Edit: {editTarget.globalIp}:{editTarget.globalPort} → {editTarget.localIp}:{editTarget.localPort}
        </div>
      )}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Name</label>
        <input
          type="text"
          placeholder="WEB_SERVER"
          value={values.name}
          onChange={(event) => setField("name", event.target.value)}
          required
        />
      </div>

      {/* ใช้ IPv4Input ชุดเดียวกับ Next Hop IP ของ StaticRouteFormModal - ช่องละ
          octet รับเฉพาะ 0-255 และตรวจรูปแบบให้เองตอนออกจากช่อง แทน input ข้อความ
          เปล่า ๆ ที่เดิมตรวจด้วย regex ตอนกด Apply อย่างเดียว

          Juniper round-trip ค่ากลับมาเป็น CIDR เสมอ - ตัด /32 ทิ้งตอน prefill
          (ดู stripHostPrefix) แล้วปล่อยให้อุปกรณ์เติมกลับให้เอง */}
      <div className="interface-configuration-form-field">
        <label className="data-label">Local IP</label>
        <IPv4Input
          id="pf-local-ip"
          label="Local IP"
          mode="address"
          value={values.localIp}
          onChange={(value) => setField("localIp", value)}
          required
        />
      </div>

      <PortField
        label="Local Port Type"
        mode={values.localMode}
        onModeChange={(value) => setField("localMode", value)}
        service={values.localService}
        onServiceChange={(value) => setField("localService", value)}
        customPort={values.localPort}
        onCustomPortChange={(value) => setField("localPort", value)}
        protocol={values.localProtocol}
        onProtocolChange={(value) => setField("localProtocol", value)}
        requireProtocol={!isJuniper}
      />

      <div className="interface-configuration-form-field">
        <label className="data-label">WAN IP</label>
        <select
          aria-label="WAN IP"
          value={wanIpCustom ? "__custom__" : values.wanIp}
          onChange={(event) => {
            const custom = event.target.value === "__custom__";
            setWanIpCustom(custom);
            if (!custom) setField("wanIp", event.target.value);
          }}
          required
        >
          <option value="">-- Select WAN IP --</option>
          {hasUnlistedWanIp && (
            <option value={values.wanIp}>{values.wanIp} (Current value — not in list)</option>
          )}
          {wanIpOptions.map((option) => (
            <option key={option.ip} value={option.ip}>{option.label}</option>
          ))}
          <option value="__custom__">Custom</option>
        </select>
        {wanIpCustom && (
          <input
            aria-label="Custom WAN IP"
            type="text"
            placeholder={isJuniper ? "203.0.113.50 or 203.0.113.50/32" : "203.0.113.50"}
            value={values.wanIp}
            onChange={(event) => setField("wanIp", event.target.value)}
            required
          />
        )}
      </div>

      <PortField
        label="WAN Port Type"
        mode={values.wanMode}
        onModeChange={(value) => setField("wanMode", value)}
        service={values.wanService}
        onServiceChange={(value) => setField("wanService", value)}
        customPort={values.wanPort}
        onCustomPortChange={(value) => setField("wanPort", value)}
        protocol={values.wanProtocol}
        onProtocolChange={(value) => setField("wanProtocol", value)}
        requireProtocol={!isJuniper}
      />

      {isJuniper && (
        <div className="interface-configuration-form-field">
          <label className="data-label">From Zone</label>
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
          {proxyArpMode === "not-required" ? (
            <span>Not required — this WAN IP is already configured on the device.</span>
          ) : (
            <>
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
              {proxyArpMode === "overlap" && (
                <small>This range overlaps an IP configured on the device and cannot be used for Proxy ARP.</small>
              )}
            </>
          )}
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
