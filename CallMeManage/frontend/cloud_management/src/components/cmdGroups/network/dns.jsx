import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { runDeviceCommand } from "../../../api/api_devices";
import { checkIPv4List } from "../../../utils/ipv4List";
import DnsForm from "./dnsFormModal";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// Juniper เท่านั้น: DNS Relay forwarders (system/services/dns/forwarders) -
// เดิมมี UI แยกให้เพิ่ม/ลบเองรวมกับ "DNS Server interface" (dns-proxy/interface)
// และ "DNS lookup ip" (dns-proxy/cache) แต่ user ขอตัดทั้ง 3 ส่วนนี้ออกจากหน้านี้
// ไปเลย: DNS Server interface ผูก/ปลดอัตโนมัติแล้วผ่าน dhcpDnsMode ตอน DHCP
// Server toggle (ดู InterfacesFormModal.jsx's dnsProxyBinding/
// remove_dns_server_interface - ทำเสร็จรอบก่อนหน้านี้แล้ว) ส่วน forwarders ตอนนี้
// sync อัตโนมัติจาก name-server ที่กรอกในฟอร์มนี้เองเลย (ดู handleApply) ไม่ต้อง
// มี UI ให้กรอกซ้ำอีกที่ - เหลือแค่ต้องอ่านค่า forwarders ปัจจุบันมาเทียบตอน sync
// เท่านั้น ไม่ต้อง parse dns-proxy/interface หรือ cache อีกต่อไป
function parseJuniperForwarders(result) {
  const dns = result?.payload?.data?.configuration?.system?.services?.dns || {};
  return ensureArray(dns.forwarders)
    .map((f) => (typeof f === "string" ? f : f?.name || ""))
    .filter(Boolean);
}

// แปลงผล get_dns_information (normalize_generic = JSON ที่ mirror โครงสร้าง tag
// ของ XML ที่ query มา) เป็นค่าเริ่มต้นของฟอร์ม - tag ที่อ่านตรงกับที่ query filter
// ถามไป เลยรู้รูปร่างแน่นอน ไม่ได้เดา field เฉพาะยี่ห้อ อ่านแบบ optional-chaining
// กันพังถ้าบาง tag ไม่มา (= ยังไม่ได้ตั้งค่า) - normalize_generic ใส่ "vendor" มา
// กับทุก reply ด้วยแล้ว เลยแยก path ตามยี่ห้อได้ตรงๆ ไม่ต้องเดา
function parseDnsResult(result) {
  if (result?.vendor === "juniper") {
    // Junos: system/domain-name (leaf เดี่ยว) + system/name-server (leaf-list
    // ของ container {name: ip} - set_dns_config เขียนแบบนี้) ตรงกับที่
    // get_dns_information query - Junos ไม่มี toggle "domain lookup"/"dns
    // server" แยกจริง (set_dns_config รับ 2 flag นี้ไว้เฉยๆ ไม่มีผลจริง ตามที่
    // เขียน comment ไว้ในนั้นแล้ว) เลยแสดงแบบ derived: lookup ถือว่าเปิดเสมอ,
    // dns server ถือว่าเปิดถ้ามี name-server ตั้งไว้อย่างน้อย 1 ตัว
    const system = result?.payload?.data?.configuration?.system || {};
    const domainName = typeof system["domain-name"] === "string" ? system["domain-name"] : "";
    let rawServers = system["name-server"];
    if (rawServers === undefined) rawServers = [];
    else if (!Array.isArray(rawServers)) rawServers = [rawServers];
    const nameServers = rawServers
      .map((entry) => (typeof entry === "string" ? entry : entry?.name || ""))
      .filter(Boolean);
    return { domainLookup: true, dnsServer: nameServers.length > 0, domainName, nameServers };
  }

  const ip = result?.payload?.data?.native?.ip || {};
  const domain = ip.domain || {};
  const nameServer = ip["name-server"] || {};

  // domain lookup: boolean leaf, default "true" ตั้งแต่ boot - ถ้า tag ไม่มา
  // (อุปกรณ์ไม่ส่งมาเพราะเป็นค่า default) ให้ถือเป็น true
  const lookupRaw = domain.lookup;
  const domainLookup = lookupRaw === undefined ? true : String(lookupRaw).toLowerCase() !== "false";

  // dns server: presence container - มี key (แม้ค่าเป็น "") = เปิด, ไม่มี = ปิด
  // (ตามที่คุยเรื่อง presence container: เช็คการมีอยู่ ไม่ใช่ค่าข้างใน)
  const dnsServer = ip.dns !== undefined && ip.dns.server !== undefined;

  const domainName = typeof domain.name === "string" ? domain.name : "";

  // name-server no-vrf: leaf-list - _element_to_json คืน string ถ้ามีตัวเดียว,
  // array ถ้าหลายตัว, undefined ถ้าไม่มี - normalize ให้เป็น array เสมอ
  let servers = nameServer["no-vrf"];
  if (servers === undefined) servers = [];
  else if (!Array.isArray(servers)) servers = [servers];

  return { domainLookup, dnsServer, domainName, nameServers: servers };
}

export default function Dns({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_dns_information");
  const [values, setValues] = useState(null);
  const [applying, setApplying] = useState(false);
  const [applyError, setApplyError] = useState("");
  const [dirty, setDirty] = useState(false);

  // ทุกครั้งที่ data มา (โหลดครั้งแรก / หลัง apply refetch / เปลี่ยนหน้ากลับมา
  // mount ใหม่) รีเซ็ตฟอร์มเป็นค่าสดจากอุปกรณ์ - ทำให้ "เปลี่ยนหน้าแล้วกลับเป็น
  // ค่าเริ่มต้น" ได้เองอัตโนมัติ (component unmount/remount -> data โหลดใหม่)
  useEffect(() => {
    if (data?.normalized) {
      setValues((current) => (
        current === null || !dirty ? parseDnsResult(data.result) : current
      ));
    }
  }, [data, dirty]);

  function setValue(name, value) {
    setDirty(true);
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  const isJuniper = data?.result?.vendor === "juniper";

  async function handleApply() {
    setApplyError("");
    // ตรวจซ้ำด้วย validator กลาง - ช่องว่างข้ามได้ แต่แถวที่กรอกไม่ครบ/ซ้ำต้องไม่ถูกส่ง
    const checked = checkIPv4List(values.nameServers, {
      label: (index) => (index === 0 ? "Primary DNS Server" : index === 1 ? "Secondary DNS Server" : `DNS Server ${index + 1}`),
      duplicateMessage: "DNS servers must be unique",
    });
    if (!checked.ok) {
      setApplyError(checked.error);
      return;
    }
    if (checked.values.length > 6) {
      setApplyError("A maximum of 6 DNS servers can be specified");
      return;
    }
    setApplying(true);
    try {
      const newNameServers = checked.values;
      await runDeviceCommand(devId, "set_dns_config", {
        domain_lookup: values.domainLookup,
        dns_server: values.dnsServer,
        domain_name: values.domainName.trim() || undefined,
        // ตัดช่องว่างออก ส่งเฉพาะ IP ที่กรอกจริง
        name_servers: newNameServers,
        // Juniper: ให้ backend รวม remove/set และ sync forwarders ใน
        // edit-config เดียว ใช้ snapshot จากอุปกรณ์ ไม่ใช่ค่าที่แก้ในฟอร์ม
        ...(isJuniper ? {
          previous_name_servers: parseDnsResult(data.result).nameServers,
          previous_forwarders: parseJuniperForwarders(data.result),
        } : {}),
      });

      await refetch(); // โหลดค่าสดกลับมา (useEffect ข้างบนจะรีเซ็ตฟอร์มให้เอง)
      setDirty(false);
    } catch (err) {
      setApplyError(err.detail || "Failed to configure DNS");
    } finally {
      setApplying(false);
    }
  }

  function handleRefresh() {
    setApplyError("");
    setDirty(false);
    refetch();
  }

  if (loading && !data) return <div className="center-loading">Fetching DNS data...</div>;
  if (error && !data) {
    return (
      <div className="command-configuration">
        <DismissibleError message={error} onDismiss={() => { clearError(); refetch(); }} />
        <button type="button" className="btn btn-ghost" onClick={refetch}>Retry</button>
      </div>
    );
  }

  // อุปกรณ์ยี่ห้ออื่นที่ get_dns_information ไม่รองรับ (normalized=false) หรือ
  // parse ไม่ได้ - โชว์ raw ไปก่อน ไม่ฝืน render ฟอร์มด้วยค่าที่เดาไม่ได้
  if (data && !data.normalized) {
    return (
      <div className="command-configuration">
        <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
      </div>
    );
  }

  if (!values) return null;

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}
      <DnsForm
        values={values}
        setValue={setValue}
        onApply={handleApply}
        applying={applying}
        error={applyError}
        onDismissError={() => setApplyError("")}
        loading={loading}
        onRefresh={handleRefresh}
        // Juniper ไม่มี toggle เปิด/ปิด DNS server จริง (resolver ทำงานอัตโนมัติ
        // เสมอทันทีที่ตั้ง name-server อย่างน้อย 1 ตัว - ดู comment ยาวใน
        // parseDnsResult/set_dns_config ด้านบน) ค่า dnsServer เดิมเป็นแค่ค่า
        // derived ไว้โชว์ ไม่เคยมีผลจริงกับอุปกรณ์ - ซ่อน toggle ทิ้งไปเลยกัน user
        // เข้าใจผิดว่าต้อง "เปิด" อะไรก่อนถึงจะใช้ DNS ได้ - Cisco ยังโชว์ปกติ
        // เพราะเป็น toggle จริง (presence container ip/dns/server)
        showDnsServerToggle={!isJuniper}
        showDomainLookupToggle={!isJuniper}
      />
    </div>
  );
}
