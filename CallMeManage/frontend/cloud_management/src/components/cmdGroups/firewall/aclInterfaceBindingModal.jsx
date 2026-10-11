import DismissibleError from "../../DismissibleError";
import { useState, useEffect } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import { getCliServerInfo } from "../../../api/api_cli";
import CheckboxDropdown from "../../common/CheckboxDropdown";

export default function AclInterfaceBindingModal({
  devId,
  aclName,
  allInterfaces = [],
  interfacesLoading = false,
  onClose,
  onSaved,
}) {
  const [inbound, setInbound] = useState(() =>
    allInterfaces
      .filter((i) => i.inboundAcl === aclName)
      .map((i) => i.interfaceName)
  );
  const [outbound, setOutbound] = useState(() =>
    allInterfaces
      .filter((i) => i.outboundAcl === aclName)
      .map((i) => i.interfaceName)
  );
  const [hasUserEdited, setHasUserEdited] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  // ปลายทางของท่อจัดการ (call-home) - ใช้บอกผู้ใช้ในคำเตือนว่าต้อง permit อะไร ถ้าดึงไม่ได้
  // ก็ยังเตือนได้แบบไม่มีเลข IP/port
  const [mgmtServer, setMgmtServer] = useState(null);

  useEffect(() => {
    let cancelled = false;
    getCliServerInfo()
      .then((info) => {
        if (!cancelled && info?.cloud_server_ip) {
          setMgmtServer({ ip: info.cloud_server_ip, port: info.cloud_server_port });
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!hasUserEdited && allInterfaces.length > 0) {
      setInbound(
        allInterfaces
          .filter((i) => i.inboundAcl === aclName)
          .map((i) => i.interfaceName)
      );
      setOutbound(
        allInterfaces
          .filter((i) => i.outboundAcl === aclName)
          .map((i) => i.interfaceName)
      );
    }
  }, [allInterfaces, aclName, hasUserEdited]);

  function toggleInbound(ifName) {
    setHasUserEdited(true);
    setInbound((prev) =>
      prev.includes(ifName) ? prev.filter((name) => name !== ifName) : [...prev, ifName]
    );
  }

  function toggleOutbound(ifName) {
    setHasUserEdited(true);
    setOutbound((prev) =>
      prev.includes(ifName) ? prev.filter((name) => name !== ifName) : [...prev, ifName]
    );
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await runDeviceCommand(devId, "replace_acl_interface_bindings", {
        acl_name: aclName,
        inbound_interfaces: inbound,
        outbound_interfaces: outbound,
      });
      onSaved();
    } catch (err) {
      setError(err.detail || err.message || "Failed to save ACL interface bindings");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      <div className="command-output-title">
        Apply to Interface: {aclName}
      </div>

      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">ACL Name</label>
        <input type="text" value={aclName} disabled readOnly />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Inbound Interfaces</label>
        <CheckboxDropdown ariaLabel="Select Inbound Interface" summary={<>
            <input
              type="text"
              readOnly
              tabIndex={-1}
              aria-label="Selected Inbound Interface"
              placeholder="-- Select Inbound Interfaces --"
              value={inbound.join(", ")}
            />
          </>}>
          <div className="zone-interface-picker-options">
            {interfacesLoading && <div className="field-hint">Loading interfaces...</div>}
            {!interfacesLoading && allInterfaces.length === 0 && (
              <div className="field-hint">No interfaces found on device</div>
            )}
            {allInterfaces.map((row) => {
              const checked = inbound.includes(row.interfaceName);
              const isUnrep = row.isRepresentable === false;
              const inUsedByOther = Boolean(row.inboundAcl && row.inboundAcl !== aclName);
              const locked = isUnrep || inUsedByOther;
              return (
                <label
                  key={`in-${row.interfaceName}`}
                  className="zone-interface-picker-option"
                  title={locked ? (isUnrep ? "Not supported for web editing" : `In use by ACL ${row.inboundAcl}`) : undefined}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={locked || interfacesLoading || submitting}
                    onChange={() => toggleInbound(row.interfaceName)}
                  />
                  {row.interfaceName}
                </label>
              );
            })}
          </div>
        </CheckboxDropdown>
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Outbound Interfaces</label>
        <CheckboxDropdown ariaLabel="Select Outbound Interface" summary={<>
            <input
              type="text"
              readOnly
              tabIndex={-1}
              aria-label="Selected Outbound Interface"
              placeholder="-- Select Outbound Interfaces --"
              value={outbound.join(", ")}
            />
          </>}>
          <div className="zone-interface-picker-options">
            {interfacesLoading && <div className="field-hint">Loading interfaces...</div>}
            {!interfacesLoading && allInterfaces.length === 0 && (
              <div className="field-hint">No interfaces found on device</div>
            )}
            {allInterfaces.map((row) => {
              const checked = outbound.includes(row.interfaceName);
              const isUnrep = row.isRepresentable === false;
              const outUsedByOther = Boolean(row.outboundAcl && row.outboundAcl !== aclName);
              const locked = isUnrep || outUsedByOther;
              return (
                <label
                  key={`out-${row.interfaceName}`}
                  className="zone-interface-picker-option"
                  title={locked ? (isUnrep ? "Not supported for web editing" : `In use by ACL ${row.outboundAcl}`) : undefined}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={locked || interfacesLoading || submitting}
                    onChange={() => toggleOutbound(row.interfaceName)}
                  />
                  {row.interfaceName}
                </label>
              );
            })}
          </div>
        </CheckboxDropdown>
      </div>

      {/* ACL เป็น stateless + implicit deny ท้ายสุด: ผูกขาเข้า (Inbound) บนขาที่ท่อจัดการ
          (call-home) วิ่งอยู่โดยไม่ permit traffic ที่ตอบกลับจาก server จัดการ = router ทิ้ง
          packet ของ session นั้น อุปกรณ์หลุดจากระบบจนต้องแก้ทาง console - ผู้ใช้เลือกให้
          "เตือน" ไม่ใช่ "ล็อก" (แบบเดียวกับการลบ zone ที่มีขาจัดการ) · ระบบบอกไม่ได้แน่ชัดว่า
          ขาไหนคือขาจัดการ (Cisco ไม่มี convention แบบ zone WAN ของ Juniper) จึงเตือนทุกครั้ง
          ที่มีขาเข้า พร้อมรายชื่อขาที่เลือกและปลายทางที่ต้อง permit */}
      {inbound.length > 0 && (
        <div className="acl-mgmt-warning" role="alert">
          <strong>Check the management connection before applying.</strong>{" "}
          This ACL will filter traffic coming in on {inbound.join(", ")}. If one of these interfaces carries this
          system&apos;s connection to the device, the ACL must permit traffic from the management server
          {mgmtServer
            ? <> (<code>{mgmtServer.ip}</code>{mgmtServer.port ? <>, TCP port <code>{mgmtServer.port}</code></> : null})</>
            : null}
          {" "}- otherwise the ACL&apos;s implicit deny drops it, the device goes offline here and must be fixed from the console.
        </div>
      )}

      <div className="interface-form-btn-container">
        <button
          type="submit"
          className="btn btn-primary"
          disabled={submitting || interfacesLoading}
        >
          {submitting ? "Saving..." : "Apply"}
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          onClick={onClose}
          disabled={submitting}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
