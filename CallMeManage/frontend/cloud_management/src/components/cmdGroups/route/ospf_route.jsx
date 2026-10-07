import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { ospfAreaToNumber } from "../../../utils/ospfArea";
import { parseJuniperOspf } from "./parseOspf";
import OspfRouteFormModal from "./OspfRouteFormModal";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function ipToInt(ip) {
  const parts = (ip || "").trim().split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function intToIp(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

function networkOf(ip, subnetDotted) {
  const ipInt = ipToInt(ip);
  const maskInt = ipToInt(subnetDotted);
  if (ipInt === null || maskInt === null) return null;
  return intToIp((ipInt & maskInt) >>> 0);
}

// ---------- Table 1: OSPF routes ทั้งหมด (get_routing_table, กรอง protocol=ospf) ----------
// path เดียวกับ static_route.jsx/rip_route.jsx แค่เปลี่ยนตัวกรอง protocol -
// **บั๊กเดียวกับที่เจอใน static_route.jsx/network_status.jsx**:
// get-route-information เป็น operational RPC ไม่มี ".data" คั่นกลาง แก้ตามกัน
function extractJuniperOspfRoutes(payload) {
  const tables = ensureArray(payload?.["route-information"]?.["route-table"]);
  const routes = [];
  for (const table of tables) {
    for (const rt of ensureArray(table?.rt)) {
      for (const entry of ensureArray(rt?.["rt-entry"])) {
        if ((entry?.["protocol-name"] || "").toLowerCase() !== "ospf") continue;
        const nh = ensureArray(entry?.nh)[0] || {};
        routes.push({
          prefix: rt?.["rt-destination"] || "",
          nextHop: nh?.to || "",
          iface: nh?.via || "",
          distance: entry?.preference || "",
          metric: entry?.metric || "",
        });
      }
    }
  }
  return routes;
}

function extractCiscoOspfRoutes(payload) {
  const routingState = payload?.data?.["routing-state"];
  const instances = ensureArray(routingState?.["routing-instance"]);
  const routes = [];
  for (const instance of instances) {
    const ribs = ensureArray(instance?.ribs?.rib);
    for (const rib of ribs) {
      const entries = ensureArray(rib?.routes?.route);
      for (const route of entries) {
        // Cisco ietf-routing เก็บ source-protocol เป็น identity-ref ที่มี prefix
        // โมดูลนำหน้า - ยืนยันจากอุปกรณ์จริง (HQ-R1, 2026-07-24): OSPF ตอบมาเป็น
        // "ospf:ospfv2" ไม่ใช่ "ospf" เฉยๆ (ต่างจาก "static" ที่ไม่มี prefix เพราะ
        // นิยามอยู่ใน ietf-routing เอง) เทียบแบบ "มีคำว่า ospf อยู่ใน string" กัน
        // เหนียวแทน exact match - เจอบั๊กนี้เพราะ exact match เดิมคืน [] ว่างเปล่า
        // เสมอทั้งที่อุปกรณ์มี OSPF route จริงอยู่
        if (!(route?.["source-protocol"] || "").toLowerCase().includes("ospf")) continue;
        const nextHop = route?.["next-hop"] || {};
        routes.push({
          prefix: route?.["destination-prefix"] || "",
          nextHop: nextHop?.["next-hop-address"] || "",
          iface: nextHop?.["outgoing-interface"] || "",
          distance: route?.["route-preference"] || "",
          metric: route?.["metric"] || "",
        });
      }
    }
  }
  return routes;
}

// ---------- Table 3: Interface และ IP ที่ตั้งไปใน OSPF ----------
// Cisco: ospf.networks เป็น network+wildcard+area (ไม่ใช่ชื่อ interface) - จับคู่
// กับ get_ip_interface_brief เอง (หา interface ที่ IP ตกอยู่ใน network นั้นจริง)
// แล้วเช็คว่าไม่ passive จาก active_interfaces ที่ normalize_ospf ให้มาแล้ว
// Juniper: area.interface เป็นชื่อ interface ตรงๆ อยู่แล้ว จับคู่ตรงชื่อได้เลย
function buildCiscoInterfaceRows(ospf, ifaceRows) {
  const activeSet = new Set(ensureArray(ospf.active_interfaces));
  return ensureArray(ospf.networks).map((net) => {
    const match = ifaceRows.find((row) => {
      if (!row.ip || row.ip === "-" || !row.subnet) return false;
      return networkOf(row.ip, row.subnet) === net.network;
    });
    const interfaceName = match?.name || "";
    return {
      area: net.area || "-",
      interface: interfaceName || "-",
      ip: match?.ip || "-",
      network: net.network || "-",
      passive: interfaceName ? !activeSet.has(interfaceName) : null,
    };
  });
}

function buildJuniperInterfaceRows(juniperOspf, ifaceRows) {
  const rows = [];
  for (const area of juniperOspf.areas) {
    // Junos เก็บ area เป็น dotted quad เสมอ แต่ระบบนี้ใช้เลขฐานสิบล้วนทุกยี่ห้อ
    // (ดู utils/ospfArea.js) ตารางจึงต้องแสดงเลขให้ตรงกับที่ฟอร์มให้กรอก ไม่งั้น
    // ผู้ใช้เห็น "0.0.0.0" ในตารางแต่ต้องพิมพ์ "0" ในฟอร์ม
    const areaLabel = ospfAreaToNumber(area.name) || area.name || "-";
    if (area.interfaces.length === 0) {
      rows.push({ area: areaLabel, interface: "-", ip: "-", network: "-", passive: null });
      continue;
    }
    for (const iface of area.interfaces) {
      const match = ifaceRows.find((row) => row.name === iface.name);
      const ip = match?.ip && match.ip !== "-" ? match.ip : "";
      const network = ip && match?.subnet ? networkOf(ip, match.subnet) : null;
      rows.push({
        area: areaLabel,
        interface: iface.name,
        ip: ip || "-",
        network: network || "-",
        passive: iface.passive,
      });
    }
  }
  return rows;
}

// ---------- Presentation ร่วม (เดิมทั้งหมด แค่รับข้อมูลที่ normalize แล้วเป็น
// prop แทนที่จะอ่านจาก hook ตรงๆ - แยก data-fetching ต่อยี่ห้อไว้ที่ wrapper
// ด้านล่าง (CiscoOspfPage ใช้ query เดียวรวม, JuniperOspfPage ใช้ 3 query แยก
// เหมือนเดิม เพราะ Junos operational RPC (get-route-information/get-interface-
// information) เป็นคนละ RPC verb กับ get-config เลยรวมเป็น request เดียวไม่ได้
// แบบ Cisco ที่ทุกอย่างผ่าน <get><filter type="subtree"> เหมือนกันหมด) ----------
function OspfPage({ devId, vendor, ospfResult, routesPayload, ifaceRows, busy, onRefresh, readError = "", onDismissReadError }) {
  const isJuniper = vendor === "juniper";
  const [formOpen, setFormOpen] = useState(false); // toggle "Enable OSPF" - ใช้ร่วมกันทั้ง 2 ยี่ห้อ
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  function handleSaved() {
    onRefresh();
  }

  // "รายละเอียดอื่นๆ" + "Interface และ IP ที่ตั้งไป" เป็นข้อมูลตัวเดียวกัน (OSPF
  // process เดียวทั้งอุปกรณ์) เลยไม่ต้องมี row-selection แบบตารางอื่น - Edit/Delete
  // ผูกกับ process ทั้งก้อนเสมอ - **บั๊กที่เจอจริง**: เดิมเรียก remove_ospf_process
  // แบบไม่แยก vendor เลยทั้งที่ปุ่ม Delete โผล่ให้ Juniper กดได้ด้วย (Juniper
  // โมเดล OSPF เป็นแบบ area/interface ไม่มี process-id ให้ลบทั้งก้อนแบบ Cisco -
  // remove_ospf_process ไม่มีอยู่ในไฟล์ juniper_junos.py เลยด้วยซ้ำ) กดแล้วโดน
  // "Feature is not supported by this translator" ทันที - เพิ่ม remove_ospf_routing
  // ให้ Juniper โดยเฉพาะแล้ว แยก branch ตรงนี้
  async function handleConfirmDelete() {
    setDeleting(true);
    setDeleteError("");
    try {
      if (isJuniper) {
        await runDeviceCommand(devId, "remove_ospf_routing", {});
      } else {
        await runDeviceCommand(devId, "remove_ospf_process", {
          process_id: Number(ospfResult.process_id),
        });
      }
      setShowDeleteConfirm(false);
      onRefresh();
    } catch (err) {
      setDeleteError(err.detail || "Failed to delete OSPF process");
    } finally {
      setDeleting(false);
    }
  }

  const routes = isJuniper ? extractJuniperOspfRoutes(routesPayload) : extractCiscoOspfRoutes(routesPayload);

  let detailRows = null; // [[label, value], ...]
  let interfaceRows = [];
  let hasConfig = false;
  // เจอบั๊กจริง (2026-07-30 - user รายงาน): ฟอร์ม Edit (dropdown Interface,
  // Area, toggle default-originate/redistribute static/rip) ว่างเปล่า/ไม่
  // pre-fill เลยทั้งที่อุปกรณ์มี OSPF ตั้งค่าอยู่จริง - สาเหตุคือส่ง `ospfResult`
  // (raw prop จาก get_ospf_information ตรงๆ shape `{vendor, payload:{data:
  // {configuration:{protocols:{ospf:{area,...}}}}}}`) เข้า `currentRule` ของ
  // OspfRouteFormModal ทั้งที่ `buildInitialValuesJuniper()` คาดหวัง shape ที่
  // parse แล้ว (`{areas:[...], defaultInformationOriginate, ...}` - ผลลัพธ์ของ
  // parseJuniperOspf()) - `currentRule.areas` บน raw shape เลยเป็น undefined
  // เสมอ ทุกอย่างเลย fallback เป็นค่าว่าง/false หมด (Cisco ไม่เจอบั๊กนี้เพราะ
  // get_ospf_dashboard คืน shape ที่ parse แล้วตรงๆ อยู่แล้ว ไม่ต้องแปลงซ้ำ) -
  // เก็บ juniperOspf ไว้ในตัวแปรนอก try เพื่อส่งเข้า currentRule แทน ospfResult
  let juniperOspfForForm = null;

  if (isJuniper) {
    try {
      const configuration = ospfResult?.payload?.data?.configuration;
      const juniperOspf = parseJuniperOspf(configuration?.protocols, configuration?.["routing-options"]);
      juniperOspfForForm = juniperOspf;
      // เดิม hasConfig = true เสมอไม่ว่า areas จะว่างหรือไม่ (parse ไม่ throw =
      // ถือว่า "มี config" เลย) ทำให้ toggle "Enable OSPF" เปิดค้างไว้ตั้งแต่ mount
      // แรกทั้งที่ยังไม่มี OSPF ตั้งค่าอยู่จริงเลย (areas ว่างเปล่า) - เจอบั๊กนี้
      // ตอนรวม UI เป็น toggle เดียวกับ Cisco (กดปิด toggle ครั้งแรกกลับเจอ modal
      // "ยืนยันการปิด OSPF" ทันทีทั้งที่ไม่เคยเปิดอะไรมาก่อนเลย) ต้องเช็คว่ามี
      // area จริงอย่างน้อย 1 อันก่อนถึงจะถือว่า "มี config"
      hasConfig = juniperOspf.areas.length > 0;
      detailRows = [
        ["Default-information originate", juniperOspf.defaultInformationOriginate ? "Enabled" : "Disabled"],
        ["Redistribute Static", juniperOspf.redistributeStatic ? "Enabled" : "Disabled"],
        ["Redistribute RIP", juniperOspf.redistributeRip ? "Enabled" : "Disabled"],
      ];
      interfaceRows = buildJuniperInterfaceRows(juniperOspf, ifaceRows);
    } catch {
      detailRows = null;
    }
  } else if (Array.isArray(ospfResult?.networks)) {
    const ospf = ospfResult;
    hasConfig = !!ospf.process_id;
    if (hasConfig) {
      detailRows = [
        ["Process ID", ospf.process_id],
        ["Router ID", ospf.router_id || "-"],
        ["Default-information originate", ospf.default_information_originate ? "Enabled" : "Disabled"],
        ["Passive-interface (default)", ospf.passive_interface_default ? "Enabled" : "Disabled"],
      ];
      interfaceRows = buildCiscoInterfaceRows(ospf, ifaceRows);
    } else {
      // ยังไม่มี OSPF process เลย (process_id เป็น null) - เป็น "ไม่มีข้อมูล" ที่
      // parse ได้ปกติ ไม่ใช่ parse ไม่ออก ต้องแยกจาก null (fallback raw JSON) ให้
      // detailRows เป็น [] เพื่อผ่านเงื่อนไข detailRows===null ไปเจอข้อความ
      // "ยังไม่มี OSPF process ตั้งค่าอยู่"
      detailRows = [];
    }
  }

  // sync toggle ให้ตรงกับสถานะจริงเสมอตอนโหลด/รีเฟรช (เหมือน nat.jsx) - เปิดฟอร์ม
  // ให้เองถ้ามี OSPF process อยู่แล้ว ไม่ต้องกดเปิดซ้ำ - ใช้ toggle เดียวกันทั้ง 2
  // ยี่ห้อแล้ว (เดิม Juniper ใช้ formMode/New-Edit-Delete แยกต่างหาก ตอนนี้รวมเป็น
  // UI เดียวกับ Cisco ตามที่ user ขอ)
  useEffect(() => {
    if (detailRows !== null) setFormOpen(hasConfig);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasConfig]);

  function handleToggleClick() {
    if (!formOpen) {
      // ปิด -> เปิด: แค่โชว์ฟอร์มให้กรอก ยังไม่ยิงอะไรจนกว่าจะกด Apply
      setFormOpen(true);
      return;
    }
    if (!hasConfig) {
      // ฟอร์มเปิดอยู่แต่ยังไม่เคย Apply จริง (ไม่มี OSPF process อยู่จริง) - กดปิด
      // ก็แค่ซ่อนฟอร์ม
      setFormOpen(false);
      return;
    }
    // มี OSPF process จริงอยู่ - กดปิด = ต้องการรื้อทิ้งจริง กระทบ routing ทันที
    // ต้องยืนยันก่อน
    setShowDeleteConfirm(true);
  }

  return (
    <div className="command-configuration">
      {readError && <DismissibleError message={readError} onDismiss={onDismissReadError} />}
      {detailRows === null ? (
        <pre>{JSON.stringify(ospfResult, null, 2)}</pre>
      ) : (
        <>
          <div className="interface-configuration-form">
            <div className="interface-configuration-form-field">
              <label className="data-label">Enable OSPF</label>
              <div className="toggle-switch-container">
                <input type="checkbox" id="ospf-enable-toggle" checked={formOpen} onChange={handleToggleClick} />
                <label className="toggleSwitch" htmlFor="ospf-enable-toggle"></label>
              </div>
            </div>
            {formOpen && (
              <OspfRouteFormModal
                devId={devId}
                vendor={vendor}
                currentRule={hasConfig ? (isJuniper ? juniperOspfForForm : ospfResult) : null}
                onSaved={handleSaved}
              />
            )}
          </div>

          {showDeleteConfirm && (
            <div className="modal-overlay" onClick={() => !deleting && setShowDeleteConfirm(false)}>
              <div className="modal-card" onClick={(event) => event.stopPropagation()}>
                <div className="modal-header">
                  <h2>Confirm Disabling OSPF</h2>
                  <button
                    type="button"
                    className="modal-close"
                    onClick={() => setShowDeleteConfirm(false)}
                    aria-label="Close"
                    disabled={deleting}
                  >
                    &times;
                  </button>
                </div>
                <p>
                  Are you sure you want to disable all OSPF{!isJuniper && ospfResult?.process_id ? <> process <strong>{ospfResult.process_id}</strong></> : ""} routing
                  (including all configured networks/areas)?
                </p>
                {deleteError && <DismissibleError message={deleteError} onDismiss={() => setDeleteError("")} />}
                <div className="modal-actions">
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => setShowDeleteConfirm(false)}
                    disabled={deleting}
                  >
                    Cancel
                  </button>
                  <button type="button" className="btn btn-primary" onClick={handleConfirmDelete} disabled={deleting}>
                    {deleting ? "Disabling..." : "Disable OSPF"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {!hasConfig ? null : (
            <>
              <div className="command-output-title">All OSPF Routes</div>
              {routes === null ? (
                <div className="config-placeholder">Failed to retrieve routing table or not supported on this vendor</div>
              ) : routes.length === 0 ? (
                <div className="config-placeholder">No routes learned via OSPF</div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Destination</th>
                      <th>Next Hop</th>
                      <th>Exit Interface</th>
                      <th>Distance</th>
                      <th>Metric</th>
                    </tr>
                  </thead>
                  <tbody>
                    {routes.map((route, index) => (
                      <tr key={`${route.prefix}-${index}`}>
                        <td>{route.prefix}</td>
                        <td>{route.nextHop || "-"}</td>
                        <td>{route.iface || "-"}</td>
                        <td>{route.distance || "-"}</td>
                        <td>{route.metric || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              <div className="command-output-title">Configured Interfaces and IPs</div>
              {interfaceRows.length === 0 ? (
                <div className="config-placeholder">No OSPF area/interfaces configured</div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Area</th>
                      <th>Interface</th>
                      <th>IP Address</th>
                      <th>Network</th>
                      <th>Passive</th>
                    </tr>
                  </thead>
                  <tbody>
                    {interfaceRows.map((row, index) => (
                      <tr key={`${row.area}-${row.interface}-${index}`}>
                        <td>{row.area}</td>
                        <td>{row.interface}</td>
                        <td>{row.ip}</td>
                        <td>{row.network}</td>
                        <td>{row.passive === null ? "-" : row.passive ? "Yes" : "No"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

// ---------- Cisco: 1 round-trip เดียว (get_ospf_dashboard รวม ospf/routes/
// interfaces) ----------
function CiscoOspfPage({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_ospf_dashboard");

  if (loading && !data) return <div className="center-loading">Loading OSPF data...</div>;
  if (error && !data) {
    return <DismissibleError message={error} onDismiss={() => { clearError(); refetch(); }} />;
  }
  if (!data?.normalized || !data.result?.ospf) {
    return (
      <div className="command-configuration">
        {data && <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>}
      </div>
    );
  }

  return (
    <OspfPage
      devId={devId}
      vendor="cisco"
      ospfResult={data.result.ospf}
      routesPayload={data.result.routes}
      ifaceRows={data.result.interfaces || []}
      busy={loading}
      onRefresh={refetch}
      readError={error}
      onDismissReadError={clearError}
    />
  );
}

// ---------- Juniper: คงเดิม 3 query แยก (Junos operational RPC คนละ verb กับ
// get-config เลยรวมเป็น request เดียวไม่ได้แบบ Cisco) ----------
function JuniperOspfPage({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_ospf_information");
  const {
    data: routeTableData,
    loading: routeTableLoading,
    refetch: refetchRouteTable,
  } = getDeviceInformation(devId, "get_routing_table");
  const {
    data: ifData,
    loading: ifLoading,
    refetch: refetchIf,
  } = getDeviceInformation(devId, "get_ip_interface_brief");

  function handleRefreshAll() {
    refetch();
    refetchRouteTable();
    refetchIf();
  }

  if (loading && !data) return <div className="center-loading">Loading OSPF data...</div>;
  if (error && !data) {
    return <DismissibleError message={error} onDismiss={() => { clearError(); refetch(); }} />;
  }
  if (!data?.normalized) {
    return (
      <div className="command-configuration">
        {data && <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>}
      </div>
    );
  }

  return (
    <OspfPage
      devId={devId}
      vendor="juniper"
      ospfResult={data.result}
      routesPayload={routeTableData?.normalized ? routeTableData.result?.payload : null}
      ifaceRows={ifData?.normalized ? ifData.result : []}
      busy={loading || routeTableLoading || ifLoading}
      onRefresh={handleRefreshAll}
      readError={error}
      onDismissReadError={clearError}
    />
  );
}

export default function OspfRoute({ devId, vendor }) {
  if (vendor === "juniper") return <JuniperOspfPage devId={devId} />;
  return <CiscoOspfPage devId={devId} />;
}
