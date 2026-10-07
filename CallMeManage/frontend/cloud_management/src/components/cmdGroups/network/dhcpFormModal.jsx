import DismissibleError from "../../DismissibleError";
import { useEffect, useRef, useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import { computeDhcpExclusions, filterExplicitExclusions } from "../../../utils/dhcpRange";
import { normalizeSubnet } from "../../../utils/normalizeSubnet";
import { computeDhcpDefaults } from "../../../utils/dhcpDefaults";
import { hoursToLeaseMinutes, leaseHoursInput } from "../../../utils/dhcpLease";
import { validateDhcpNetwork, validateDhcpGateway } from "../../../utils/dhcpNetwork";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { checkIPv4List } from "../../../utils/ipv4List";
import IPv4Input from "../../common/IPv4Input";

const DEFAULT_VALUES = {
  name: "",
  network: "",
  startAddress: "",
  endAddress: "",
  gateway: "",
  dns: "",
  dnsServers: [""],
  dnsMode: "specific",
  gatewayMode: "specific",
  lease: "168", // ชั่วโมง (7 วัน)
};

// เจอบั๊กจริง (Juniper): edit-config ที่ถูกอุปกรณ์ปฏิเสธด้วย rpc-error (เช่น pool
// name ผิด syntax) ตอบกลับเป็น HTTP 200 ปกติพร้อม {ok: false, errors: [...]} ไม่
// ใช่ exception - runDeviceCommand เลย resolve เฉยๆ ไม่ throw ทำให้ฟอร์มเข้าใจว่า
// สำเร็จทั้งที่ pool ไม่ถูกสร้างเลยจริงๆ (ยืม pattern เดียวกับที่ใช้ใน
// security_tunnel.jsx/InterfacesFormModal.jsx มาแล้ว)
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

// Pre-fill one range; retain all original ranges/exclusions separately on edit.
function buildInitialValues(mode, editTarget) {
  if (mode !== "edit" || !editTarget) return DEFAULT_VALUES;

  let network = editTarget.network || "";
  // Cisco: parsePools คืน "10.0.0.0 255.255.255.0" (เว้นวรรค ไม่ใช่ CIDR) -
  // Juniper: parseJuniperPools คืน CIDR ตรงๆอยู่แล้ว
  if (network.includes(" ") && !network.includes("/")) {
    const [addr, mask] = network.split(" ");
    const subnet = normalizeSubnet(mask);
    if (subnet) network = `${addr}/${subnet.prefix}`;
  }

  const dnsFirst = (editTarget.dns || "").split(",")[0]?.trim() || "";
  const leaseHours = leaseHoursInput(editTarget);

  return {
    name: editTarget.name || "",
    network,
    startAddress: editTarget.startAddress || "",
    endAddress: editTarget.endAddress || "",
    gateway: editTarget.gateway || "",
    dns: dnsFirst,
    dnsServers: editTarget.dns ? editTarget.dns.split(",").map(item => item.trim()).filter(Boolean) : [""],
    dnsMode: editTarget.dns ? "specific" : "none",
    gatewayMode: editTarget.gateway ? "specific" : "none",
    lease: leaseHours,
  };
}

// ฟอร์มสร้าง/แก้ไข DHCP pool เดี่ยว - **ไม่มีช่องเลือก Interface อีกต่อไป**
// (2026-07-29 - user ขอแยกออก: เดิมฟอร์มนี้ผูก interface พร้อมกันในตัว ทำให้ดู
// เหมือน 1 pool ผูกกับ 1 interface เสมอ ทั้งที่ Junos ไม่มี mapping นี้จริง เลย
// แยกการจัดการ dhcp-local-server group's interface list ออกไปจากฟอร์มนี้ -
// ต่อมา 2026-08-02 user ขอตัด UI แยกส่วนนั้นออกทั้งหมดด้วย ให้หน้าตาเหมือน
// Cisco ที่ไม่มี concept นี้เลย เพราะการผูก/ปลด interface ทำอัตโนมัติผ่าน DHCP
// Server toggle ที่หน้า Interfaces แทน (ดู InterfacesFormModal.jsx)) ฟอร์มนี้
// เหลือแค่จัดการตัว pool ล้วนๆ (access/address-assignment/pool) ไม่แตะ
// system/services/dhcp-local-server เลย
// API uses whole minutes; hours are a presentation/input unit only.
// โหมด Edit: ช่องที่เป็น "key" จริงของแต่ละยี่ห้อต้อง freeze ไว้ห้ามแก้ (เปลี่ยนแล้ว
// จะกลายเป็นสร้าง pool ใหม่แทนที่จะแก้ตัวเดิม ตัวเดิมค้างเป็น orphan) - Cisco:
// "name" คือ key (pool list keyed ด้วย id), Juniper: "network" คือ key เหมือนเดิม
// (name เป็น key จริงแล้วก็จริง แต่ network ยังคง 1-pool-ต่อ-1-network อยู่ดี
// เปลี่ยน network กลางคันจะกลายเป็นคนละ pool ในทางปฏิบัติ)
export default function DhcpFormModal({ devId, vendor, mode = "create", editTarget = null, onClose, onSaved }) {
  const [values, setValues] = useState(buildInitialValues(mode, editTarget));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const isEdit = mode === "edit";
  const lockName = isEdit && vendor !== "juniper";
  const lockNetwork = isEdit && vendor === "juniper";
  const userEditedFields = useRef({ startAddress: false, endAddress: false, gateway: false });

  useEffect(() => {
    if (isEdit || !["cisco", "juniper"].includes(vendor)) return;
    const defaults = computeDhcpDefaults(values.network);
    // Clear stale automatic values when CIDR is incomplete or /31-/32.
    setValues((prev) => {
      const next = { ...prev };
      for (const [field, value] of Object.entries({
        startAddress: defaults?.start || "",
        endAddress: defaults?.end || "",
        gateway: defaults?.gateway || "",
      })) {
        if (!userEditedFields.current[field]) next[field] = value;
      }
      return next;
    });
  }, [values.network, isEdit, vendor]);

  function setField(name, value) {
    if (Object.hasOwn(userEditedFields.current, name)) userEditedFields.current[name] = true;
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    // IPv4Input ช่วย UX ระหว่างกรอก - ตรวจซ้ำตอน submit แล้วใช้เฉพาะค่า canonical ของ validator
    if (!values.name.trim()) return setError("Please enter Pool Name");
    const networkError = validateDhcpNetwork(values.network);
    if (networkError) return setError(networkError);
    const network = validateIPv4Input(values.network, { mode: "cidr", networkOnly: true }).value;

    let gateway = null;
    if (values.gatewayMode !== "none") {
      const checkedGateway = validateIPv4Input(values.gateway, { mode: "address", required: true });
      if (!checkedGateway.valid) return setError(`Gateway IP: ${checkedGateway.error}`);
      gateway = checkedGateway.value;
      const gatewayError = validateDhcpGateway(network, gateway);
      if (gatewayError) return setError(gatewayError);
    }

    const checkedStart = validateIPv4Input(values.startAddress, { mode: "address", required: false });
    if (!checkedStart.valid) return setError(`Start address: ${checkedStart.error}`);
    const checkedEnd = validateIPv4Input(values.endAddress, { mode: "address", required: false });
    if (!checkedEnd.valid) return setError(`End address: ${checkedEnd.error}`);
    const startAddress = checkedStart.value;
    const endAddress = checkedEnd.value;
    if (Boolean(startAddress) !== Boolean(endAddress)) {
      return setError("Please fill in both Start and End addresses, or leave both blank");
    }
    const exclude = computeDhcpExclusions(network, startAddress ? `${startAddress}-${endAddress}` : "");
    if (exclude === null) {
      return setError("Invalid Start or End address: out of network range or Start address is greater than End address");
    }

    let dns = [];
    if (values.dnsMode !== "none") {
      if (!values.dnsServers.length || values.dnsServers.some(item => !String(item).trim())) return setError("Please fill in all DNS IP fields");
      if (values.dnsServers.length > 3) return setError("A maximum of 3 DNS servers can be specified");
      const checkedDns = checkIPv4List(values.dnsServers, {
        label: (index) => `DNS IP ${index + 1}`,
        duplicateMessage: "DNS IP servers must be unique",
      });
      if (!checkedDns.ok) return setError(checkedDns.error);
      dns = checkedDns.values;
    }

    const params = {
      name: values.name.trim(),
      network,
      gateway,
      dns,
    };
    if (startAddress) {
      params.start_address = startAddress;
      params.end_address = endAddress;
    }
    if (isEdit) {
      if (editTarget.rangeDataValid === false) return setError("Incomplete original IP range data; pool update aborted to prevent data loss");
      const original = buildInitialValues(mode, editTarget);
      const rangeUnchanged = startAddress === original.startAddress && endAddress === original.endAddress && network === original.network;
      params.previous = {
        pool: editTarget.poolConfig || {name: editTarget.name, id: editTarget.name},
        exclude: editTarget.excludeRanges || [],
        ...(original.startAddress ? {start_address: original.startAddress} : {}),
        ...(original.endAddress ? {end_address: original.endAddress} : {}),
      };
      if (vendor === "juniper") {
        if (editTarget.excludeRanges?.length && network === original.network) params.exclude = editTarget.excludeRanges;
        if (editTarget.configuredRanges) {
          params.configured_ranges = rangeUnchanged ? editTarget.configuredRanges
            : startAddress ? [{name: "RANGE-1", low: startAddress, high: endAddress}] : [];
          params.configured_excluded_ranges = editTarget.excludedRangeEntries || [];
          delete params.start_address;
          delete params.end_address;
        }
      } else {
        const explicitExclusions = filterExplicitExclusions(
          editTarget.excludeRanges,
          original.network,
          original.startAddress,
          original.endAddress
        );
        if (explicitExclusions.length > 0 && network === original.network) {
          params.exclude = explicitExclusions;
        }
        if (rangeUnchanged) {
          delete params.start_address;
          delete params.end_address;
        }
      }
    }
    const lease = values.lease.trim();
    if (isEdit && editTarget.leaseInfinite && lease === "infinite" && vendor === "cisco") {
      params.lease_infinite = true;
    } else if (isEdit && vendor === "juniper" && editTarget.leaseSeconds > 0 && editTarget.leaseSeconds % 60 !== 0 && lease === leaseHoursInput(editTarget)) {
      // Preserve existing second-resolution leases exactly, even if hours repeat.
      params.lease_seconds = editTarget.leaseSeconds;
    } else if (lease) {
      const minutes = hoursToLeaseMinutes(lease);
      if (minutes === null) return setError("Lease time must be greater than 0 hours and convert cleanly to minutes, e.g. 0.5, 1.5, or 24");
      params.lease_minutes = minutes;
    }

    setSubmitting(true);
    try {
      // Validate locally, then update managed fields in one edit-config.
      await validateDeviceCommand(devId, "set_dhcp_pool", params);
      assertCommandOk(
        await runDeviceCommand(devId, "set_dhcp_pool", params),
        isEdit ? "Failed to update DHCP pool" : "Failed to create DHCP pool"
      );
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to update DHCP pool" : "Failed to create DHCP pool"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
      {isEdit && <div className="command-output-title">Edit: {editTarget?.name}</div>}
      <div className="interface-configuration-form-field">
        <label className="data-label">Pool Name</label>
        <input
          type="text"
          placeholder="LAN_POOL"
          value={values.name}
          onChange={(event) => setField("name", event.target.value)}
          disabled={lockName}
          required
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label" htmlFor="dhcp-pool-network">Network</label>
        <IPv4Input
          id="dhcp-pool-network"
          label="Network"
          mode="cidr"
          networkOnly
          required
          value={values.network}
          onChange={(value) => setField("network", value)}
          disabled={lockNetwork}
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label" htmlFor="dhcp-pool-start-address">Start address</label>
        <IPv4Input
          id="dhcp-pool-start-address"
          label="Start address"
          value={values.startAddress}
          onChange={(value) => setField("startAddress", value)}
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label" htmlFor="dhcp-pool-end-address">End address</label>
        <IPv4Input
          id="dhcp-pool-end-address"
          label="End address"
          value={values.endAddress}
          onChange={(value) => setField("endAddress", value)}
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Gateway</label>
        <div className="segmented-control">
          <input type="radio" id="pool-gw-specific" name="pool-gateway-mode" value="specific" checked={values.gatewayMode === "specific"} onChange={event => setField("gatewayMode", event.target.value)} />
          <label htmlFor="pool-gw-specific">Specific IP</label>
          <input type="radio" id="pool-gw-none" name="pool-gateway-mode" value="none" checked={values.gatewayMode === "none"} onChange={event => setField("gatewayMode", event.target.value)} />
          <label htmlFor="pool-gw-none">None</label>
        </div>
      </div>
      {values.gatewayMode === "specific" && <div className="interface-configuration-form-field">
        <label className="data-label" htmlFor="dhcp-pool-gateway">Gateway IP</label>
        <IPv4Input
          id="dhcp-pool-gateway"
          label="Gateway IP"
          required
          value={values.gateway}
          onChange={(value) => setField("gateway", value)}
        />
      </div>}

      <div className="interface-configuration-form-field">
        <label className="data-label">DNS</label>
        <div className="segmented-control">
          <input type="radio" id="pool-dns-specific" name="pool-dns-mode" value="specific" checked={values.dnsMode === "specific"} onChange={event => setField("dnsMode", event.target.value)} />
          <label htmlFor="pool-dns-specific">Specific IP</label>
          <input type="radio" id="pool-dns-none" name="pool-dns-mode" value="none" checked={values.dnsMode === "none"} onChange={event => setField("dnsMode", event.target.value)} />
          <label htmlFor="pool-dns-none">None</label>
        </div>
      </div>
      {values.dnsMode === "specific" && <div className="interface-configuration-form-field">
        <label className="data-label">DNS IP (Max 3)</label>
        <div>{values.dnsServers.map((dns, index) => <div className="interface-picker" key={`pool-dns-${index}`}>
          <IPv4Input label={`DNS IP ${index + 1}`} value={dns} required
            onChange={next => setValues(prev => ({...prev, dnsServers: prev.dnsServers.map((value, position) => position === index ? next : value)}))} />
          {index === 0 ? <button type="button" className="mini-btn btn-ghost" disabled={values.dnsServers.length >= 3} onClick={() => setValues(prev => ({...prev, dnsServers: prev.dnsServers.length < 3 ? [...prev.dnsServers, ""] : prev.dnsServers}))}>+</button>
            : <button type="button" className="mini-btn btn-ghost" onClick={() => setValues(prev => ({...prev, dnsServers: prev.dnsServers.filter((_, position) => position !== index)}))}>−</button>}
        </div>)}</div>
      </div>}

      <div className="interface-configuration-form-field">
        <label className="data-label">Lease time (hours)</label>
        <input
          type="text"
          value={values.lease}
          onChange={(event) => setField("lease", event.target.value)}
        />
      </div>

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
