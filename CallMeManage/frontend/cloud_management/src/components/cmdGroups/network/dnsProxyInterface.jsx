import { useState } from "react";
import DismissibleError from "../../DismissibleError";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { isJuniperSelectableInterfaceUnit } from "../../../utils/interfaceKind";
import { splitInterfaceName } from "../../../utils/interfaceName";

function ensureArray(value) {
  return value == null ? [] : Array.isArray(value) ? value : [value];
}

export function dnsProxyInterfaces(result) {
  const entries = result?.payload?.data?.configuration?.system?.services?.dns?.["dns-proxy"]?.interface;
  return ensureArray(entries)
    .map((entry) => typeof entry === "string" ? entry : entry?.name)
    .filter((name) => typeof name === "string" && name.length > 0);
}

function interfaceParameters(fullName) {
  if (typeof fullName !== "string") return null;
  const dot = fullName.lastIndexOf(".");
  if (dot < 1 || !/^\d+$/.test(fullName.slice(dot + 1))) return null;
  const parent = splitInterfaceName(fullName.slice(0, dot));
  if (!/^[A-Za-z]/.test(parent.interfaceType)) return null;
  return {
    interface_type: parent.interfaceType,
    interface_id: parent.interfaceId,
    unit: Number(fullName.slice(dot + 1)),
  };
}

function errorMessage(error) {
  return typeof error?.detail === "object"
    ? error.detail.message || "Failed to update DNS Proxy"
    : error?.detail || error?.message || "Failed to update DNS Proxy";
}

export default function DnsProxyInterface({ devId, result, loading, onRefresh }) {
  const [selected, setSelected] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const { data: interfaceData, loading: interfaceLoading, error: interfaceError,
    clearError: clearInterfaceError, refetch: refreshInterfaces } =
    getDeviceInformation(devId, "get_interface_list");

  const configured = dnsProxyInterfaces(result);
  const available = interfaceData?.normalized && Array.isArray(interfaceData.result)
    ? interfaceData.result.map((row) => row.name).filter(isJuniperSelectableInterfaceUnit)
      .filter((name) => !configured.includes(name))
    : [];

  async function apply(command, name) {
    const parameters = interfaceParameters(name);
    if (!parameters || (command === "set_dns_server_interface" && !isJuniperSelectableInterfaceUnit(name))) {
      setError(`Interface ${name} cannot be used for DNS Proxy`);
      return;
    }
    setBusy(name);
    setError("");
    try {
      // Re-read the device before a write so a stale tab cannot undo a newer change.
      const latest = await runDeviceCommand(devId, "get_dns_information", {});
      if (!latest?.normalized) throw new Error("Could not read current DNS Proxy configuration. Refresh and try again.");
      const fresh = dnsProxyInterfaces(latest.result);
      if (command === "set_dns_server_interface" && fresh.includes(name)) {
        throw new Error(`${name} is already enabled for DNS Proxy. Refresh to see the latest list.`);
      }
      if (command === "remove_dns_server_interface" && !fresh.includes(name)) {
        throw new Error(`${name} is no longer enabled for DNS Proxy. Refresh to see the latest list.`);
      }
      await runDeviceCommand(devId, command, parameters);
      if (command === "set_dns_server_interface") setSelected("");
      await onRefresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy("");
    }
  }

  async function refresh() {
    setError("");
    await Promise.all([onRefresh(), refreshInterfaces()]);
  }

  return (
    <div role="tabpanel" id="tabpanel-dns_proxy" aria-labelledby="tab-dns_proxy">
      <div className="command-output-title">DNS Proxy Interfaces</div>
      <p>Choose which interface accepts DNS requests. Interfaces using DHCP Server with Interface IP are also managed from Interfaces.</p>
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
      {interfaceError && <DismissibleError message={interfaceError} onDismiss={clearInterfaceError} />}
      <div className="interface-configuration-form">
        <div className="interface-configuration-form-field-third"
          style={{ width: "min(600px, 100%)", gridTemplateColumns: "110px minmax(0, 1fr) auto" }}>
          <label className="data-label" htmlFor="dns-proxy-interface">Interface</label>
          <select id="dns-proxy-interface" value={selected} disabled={!!busy || loading || interfaceLoading || !!interfaceError}
            onChange={(event) => setSelected(event.target.value)}>
            <option value="">-- Select Interface --</option>
            {available.map((name) => <option key={name} value={name}>{name}</option>)}
          </select>
          <button type="button" className="btn btn-primary" disabled={!selected || !!busy || loading || interfaceLoading}
            onClick={() => apply("set_dns_server_interface", selected)}>Add</button>
        </div>
      </div>
      {configured.length === 0 ? (
        <div className="config-placeholder">No DNS Proxy interface configured</div>
      ) : (
        <table className="data-table">
          <thead><tr><th>Interface</th><th>Action</th></tr></thead>
          <tbody>{configured.map((name) => (
            <tr key={name}>
              <td>{name}</td>
              <td><button type="button" className="btn btn-ghost" disabled={!!busy || loading || !interfaceParameters(name)}
                onClick={() => apply("remove_dns_server_interface", name)}>Remove</button></td>
            </tr>
          ))}</tbody>
        </table>
      )}
      <div className="interface-form-btn-container">
        <button type="button" className="btn btn-ghost" disabled={!!busy || loading || interfaceLoading} onClick={refresh}>
          {loading || interfaceLoading ? "Refreshing..." : "Refresh"}
        </button>
      </div>
    </div>
  );
}
